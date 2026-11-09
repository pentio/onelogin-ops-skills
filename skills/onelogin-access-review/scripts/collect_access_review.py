#!/usr/bin/env python3
"""最小権限アクセスレビューに必要なOneLogin情報を読み取り専用で収集する。

このスクリプト自身はアクセス権が不要かどうかを判断しない。現在のユーザー、
アプリ、Role、Peer、利用履歴、変更Eventなどの事実情報を収集し、AIまたは
人間がレビューできるJSONとして出力する。

OAuthアクセストークン取得用POSTとOneLoginのGETエンドポイントだけを使用する。
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import stat
import tempfile
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable


USER_KEYS = (
    "id", "firstname", "lastname", "username", "email", "title", "department",
    "company", "group_id", "directory_id", "manager_user_id", "member_of",
    "role_ids", "status", "state", "created_at", "updated_at",
    "last_login",
)
USAGE_WINDOWS = (30, 90, 180, 365)
# 属性名が許可リストに含まれていても、これらの名前に該当する値は出力しない。
SENSITIVE_ATTRIBUTE_NAME = re.compile(
    r"password|passwd|passphrase|secret|token|api[_-]?key|private[_-]?key|credential|otp|pin",
    re.IGNORECASE,
)


class LocalSafetyError(RuntimeError):
    """安全上の前提が成立しない場合。"""


def secure_write_json(path_text: str, payload: dict[str, Any], *, overwrite: bool = False) -> Path:
    """0600で一時保存してからアトミックに配置し、意図しない上書きを防ぐ。"""
    path = Path(path_text).expanduser().absolute()
    if path.is_symlink():
        raise LocalSafetyError("出力先にシンボリックリンクは指定できません")
    if path.exists() and not overwrite:
        raise LocalSafetyError(f"出力先にファイルが存在します: {path}（上書きは--overwrite）")
    if not path.parent.is_dir():
        raise LocalSafetyError("出力先フォルダが存在しません")
    fd, tmp = tempfile.mkstemp(prefix=".access_review_", suffix=".tmp", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        if overwrite:
            os.replace(tmp, path)
        else:
            os.link(tmp, path)
            os.unlink(tmp)
        os.chmod(path, 0o600)
        return path
    except FileExistsError as e:
        raise LocalSafetyError("出力先がすでに存在します。上書きする場合は--overwriteを付けてください") from e
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_private_file(path_text: str, *, json_only: bool = False) -> Any:
    p = Path(path_text)
    if p.is_symlink() or not p.is_file():
        raise LocalSafetyError("指定した入力ファイルが安全な通常ファイルではありません")
    if stat.S_IMODE(p.stat().st_mode) & 0o077:
        raise LocalSafetyError(f"ファイルの権限を600に設定してください: {p}")
    if p.stat().st_size > (20 * 1024 * 1024 if json_only else 64 * 1024):
        raise LocalSafetyError("入力ファイルが想定サイズを超えています")
    data = p.read_text(encoding="utf-8-sig")
    if json_only:
        try:
            return json.loads(data)
        except ValueError as e:
            raise LocalSafetyError("JSONファイルの内容が正しくありません") from e
    return data


class CollectorError(RuntimeError):
    pass


def checked_records(rows, context):
    """一覧の形だけでなく、集計に必要なレコードIDを検証する。"""
    if (not isinstance(rows, list) or any(not isinstance(row, dict)
            or type(row.get("id")) is not int or row["id"] <= 0 for row in rows)):
        raise CollectorError(f"{context}: 必須idが欠損または不正です（0件とは扱いません）")
    return rows


def checked_event_types(rows):
    """イベントを分類するカタログの欠損・重複を正常な0件に変換しない。"""
    checked_records(rows, "Events Types")
    if not rows:
        raise CollectorError("Events Typesが空です（履歴を分類できないため収集を中断します）")
    event_types = {}
    for row in rows:
        if not isinstance(row.get("name"), str) or not row["name"].strip():
            raise CollectorError("Events Typesの名称が欠損または不正です（収集を中断します）")
        if row["id"] in event_types:
            raise CollectorError("Events TypesのIDが重複しています（収集を中断します）")
        event_types[row["id"]] = row
    return event_types


def checked_event(row, event_types=None):
    checked_records([row], "Event")
    if type(row.get("event_type_id")) is not int or parse_time(row.get("created_at")) is None:
        raise CollectorError("Eventの種別または日時が欠損・不正です（利用0件とは扱いません）")
    # 実イベントのevent_type_idがイベント種別カタログに未掲載のことがある。
    # カタログ不一致とEvent自体の形式異常は区別し、呼び出し元でcoverageをpartialにする。
    # 種別を推測して権限付与や利用履歴として分類してはならない。
    return row


def unlisted_event_types(events, event_types):
    """有効なEventのうち、カタログに未掲載の種別を件数・IDだけで集計する。"""
    counts = Counter()
    sample_event_ids = []
    for event in events:
        checked_event(event, event_types)
        if event["event_type_id"] not in event_types:
            counts[event["event_type_id"]] += 1
            if len(sample_event_ids) < 10:
                sample_event_ids.append(event["id"])
    return {"status": "partial" if counts else "complete",
            "unlisted_event_type_ids": sorted(counts),
            "unlisted_event_count": sum(counts.values()),
            "sample_event_ids": sample_event_ids,
            "reason": ("イベント種別一覧に未掲載の種別が含まれ、履歴の意味を確定できません"
                       if counts else None)}

USER_STATUS_NAMES = {
    0: "未アクティブ",
    1: "有効（Active）",
    2: "停止（Suspended）",
    3: "ロック（Locked）",
    4: "パスワード期限切れ",
    5: "パスワードリセット待ち",
    7: "パスワード設定待ち",
    8: "セキュリティ質問が必要",
}


def user_status_summary(user: dict[str, Any]) -> dict[str, Any]:
    raw = user.get("status")
    # 小数・bool等をintへ丸めず、整数コードまたはその正規の文字列表現だけ受け付ける。
    status = raw if type(raw) is int else None
    if isinstance(raw, str) and raw.strip() in {str(code) for code in USER_STATUS_NAMES}:
        status = int(raw.strip())
    if status not in USER_STATUS_NAMES:
        status = None
    return {
        "status": status,
        "status_name": USER_STATUS_NAMES.get(status, "不明") if status is not None else None,
        "active": (status == 1) if status is not None else None,
        "requires_user_review": (status != 1) if status is not None else None,
        "coverage": {"status": "complete" if status is not None else "unavailable", "reason": None if status is not None else "ユーザーステータスが欠損または不正です"},
    }


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_time(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def normalize_base_url(value: str) -> str:
    """サブドメイン・ホスト名・管理画面URLをHTTPSのテナントルートへ統一する。"""
    raw = (value or "").strip()
    if not raw:
        raise CollectorError("OneLoginテナントのサブドメインまたはURLが必要です")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urllib.parse.urlsplit(raw)
        if parsed.scheme.lower() not in ("http", "https"):
            raise CollectorError("OneLogin URLはhttpまたはhttpsだけを指定してください")
        if parsed.username or parsed.password or "@" in parsed.netloc:
            raise CollectorError("URLにユーザー名や認証情報を含めないでください")
        if parsed.port not in (None, 443):
            raise CollectorError("OneLoginテナントURLに標準外ポートを指定しないでください")
        host = (parsed.hostname or "").lower().rstrip(".")
    except (ValueError, AttributeError) as e:
        raise CollectorError("OneLoginテナントURLの形式が正しくありません") from e

    # URLのクエリやフラグメントに認証情報が含まれていれば破棄せず拒否する。
    for key, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
        if SENSITIVE_ATTRIBUTE_NAME.search(key) or key.lower() in ("code", "authorization"):
            raise CollectorError("認証情報を含むクエリ付きURLは指定できません")
    if parsed.fragment and SENSITIVE_ATTRIBUTE_NAME.search(parsed.fragment):
        raise CollectorError("認証情報を含むフラグメント付きURLは指定できません")

    if "." not in host:
        tenant = host
    elif host.endswith(".onelogin.com"):
        tenant = host[:-len(".onelogin.com")]
    else:
        raise CollectorError("OneLoginテナントはサブドメインまたは.onelogin.comドメインで指定してください")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", tenant):
        raise CollectorError("OneLoginサブドメインには英数字と内部のハイフンだけを指定してください")
    return "https://" + tenant + ".onelogin.com"


def safe_user(user: dict[str, Any], allowed_custom_attributes: Iterable[str] = ()) -> dict[str, Any]:
    """取得したユーザーから監査に必要な項目だけを選別する。"""
    out = {k: user.get(k) for k in USER_KEYS if k in user}
    source = user.get("custom_attributes")
    if not isinstance(source, dict):
        return out
    selected: dict[str, Any] = {}
    for attr in allowed_custom_attributes:
        if attr not in source:
            continue
        if SENSITIVE_ATTRIBUTE_NAME.search(str(attr)):
            selected[attr] = "[REDACTED]"
        else:
            val = source[attr]
            # Custom Attributeは文字列や単純値のみを許可。配列やオブジェクトは出力しない。
            if val is None or isinstance(val, (str, int, float, bool)):
                selected[attr] = val
    if selected:
        out["custom_attributes"] = selected
    return out

def display_name(user: dict[str, Any]) -> str:
    parts = [str(user.get("firstname") or "").strip(), str(user.get("lastname") or "").strip()]
    name = " ".join(x for x in parts if x).strip()
    return name or str(user.get("username") or user.get("email") or user.get("id") or "")


def event_user_key(event: dict[str, Any]) -> str | None:
    for key in ("user_id", "id"):
        if key in event and event.get(key) not in (None, ""):
            return f"id:{event.get(key)}"
    for key in ("email", "user_email"):
        if event.get(key):
            return "email:" + str(event[key]).strip().lower()
    if event.get("username"):
        return "username:" + str(event["username"]).strip().lower()
    if event.get("user_name"):
        return "name:" + str(event["user_name"]).strip().lower()
    return None


def event_app_key(event: dict[str, Any]) -> str | None:
    for key in ("app_id", "application_id"):
        if event.get(key) not in (None, ""):
            return f"id:{event.get(key)}"
    for key in ("app_name", "application_name", "app"):
        if event.get(key):
            return "name:" + str(event[key]).strip().lower()
    return None


def event_time(event: dict[str, Any]) -> datetime | None:
    for key in ("created_at", "timestamp", "time", "login_at", "event_time"):
        dt = parse_time(event.get(key))
        if dt:
            return dt
    return None


def load_usage_file(path: str) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        raise CollectorError(f"利用履歴ファイルが見つかりません: {path}")
    if p.suffix.lower() == ".csv":
        with p.open("r", encoding="utf-8-sig", newline="") as f:
            return [dict(row) for row in csv.DictReader(f)]
    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        if any(not isinstance(x, dict) for x in data):
            raise CollectorError("利用履歴JSONに不正なレコードが含まれています")
        return data
    if isinstance(data, dict):
        for key in ("events", "data", "login_history", "history"):
            if isinstance(data.get(key), list):
                if any(not isinstance(x, dict) for x in data[key]):
                    raise CollectorError("利用履歴JSONに不正なレコードが含まれています")
                return data[key]
    raise CollectorError("利用履歴JSONは配列、またはevents/data等の配列を含む必要があります")


def summarize_times(times: Iterable[datetime], now: datetime) -> dict[str, Any]:
    clean = sorted((t.astimezone(timezone.utc) for t in times if t is not None), reverse=True)
    counts = {}
    for days in USAGE_WINDOWS:
        cutoff = now - timedelta(days=days)
        counts[str(days)] = sum(1 for t in clean if t >= cutoff)
    return {
        "counts": counts,
        "last_observed_at": clean[0].isoformat().replace("+00:00", "Z") if clean else None,
        "total_in_window": len(clean),
    }


def role_assignment_for_app(app_id: int, roles: list[dict[str, Any]], *, roles_known: bool = True) -> dict[str, Any]:
    via = []
    for role in roles:
        role_app_ids = {int(a["id"]) for a in role.get("apps", []) if a.get("id") is not None}
        if int(app_id) in role_app_ids:
            via.append({"id": role.get("id"), "name": role.get("name")})
    return {
        "via_roles": via,
        "explained_by_current_role": bool(via) if roles_known else None,
        "unexplained_by_current_roles": (not bool(via)) if roles_known else None,
        "coverage": {"status": "complete" if roles_known else "unavailable", "reason": None if roles_known else "ユーザー詳細のrole_idsが取得できません"},
    }


def build_peer_cohorts(target: dict[str, Any], users: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates = [
        ("department+title", ("department", "title")),
        ("department", ("department",)),
        ("title", ("title",)),
        ("group", ("group_id",)),
        ("company", ("company",)),
        ("directory", ("directory_id",)),
    ]
    target_id = str(target.get("id"))
    cohorts = []
    seen_sets: set[tuple[str, ...]] = set()
    for key, fields in candidates:
        values = tuple(target.get(f) for f in fields)
        if any(v in (None, "") for v in values):
            continue
        members = []
        for u in users:
            if str(u.get("id")) == target_id:
                continue
            if all(u.get(f) == target.get(f) for f in fields):
                members.append(u)
        ids = tuple(sorted(str(u.get("id")) for u in members if u.get("id") is not None))
        if not ids or ids in seen_sets:
            continue
        seen_sets.add(ids)
        label = "; ".join(f"{f}={target.get(f)}" for f in fields)
        cohorts.append({
            "key": key,
            "label": label,
            "fields": list(fields),
            "size": len(members),
            "user_ids": [u.get("id") for u in members],
        })
    return cohorts


def peer_attribute_coverage(target, users, fields=("department", "title")):
    """比較に使う各属性の欠損を、同属性の該当者0名と区別する。"""
    peers = [u for u in users if u.get("id") != target.get("id")]
    details = {}
    for field in fields:
        missing = sum(u.get(field) in (None, "") for u in peers)
        target_known = target.get(field) not in (None, "")
        status = ("unavailable" if not target_known or not peers or missing == len(peers)
                  else "partial" if missing else "complete")
        details[field] = {"status": status, "target_available": target_known,
                          "peer_count": len(peers), "missing_peer_count": missing}
    statuses = [d["status"] for d in details.values()]
    status = ("complete" if all(s == "complete" for s in statuses)
              else "unavailable" if all(s == "unavailable" for s in statuses) else "partial")
    return {"status": status, "fields": details,
            "reason": None if status == "complete" else
                "比較対象がいないか、本人または比較対象の属性が欠損しています。同属性の該当者0名とは断定できません"}


def index_users(users: list[dict[str, Any]]) -> dict[str, int]:
    idx: dict[str, int] = {}
    for u in users:
        uid = u.get("id")
        if uid is None:
            continue
        idx[f"id:{uid}"] = int(uid)
        for field, prefix in (("email", "email"), ("username", "username")):
            if u.get(field):
                idx[f"{prefix}:{str(u[field]).strip().lower()}"] = int(uid)
        name = display_name(u).strip().lower()
        if name:
            idx[f"name:{name}"] = int(uid)
    return idx


@dataclass
class ApiClient:
    base_url: str
    client_id: str
    client_secret: str
    timeout: int = 30

    def __post_init__(self) -> None:
        self.base_url = normalize_base_url(self.base_url)
        self.access_token: str | None = None

    def authenticate(self) -> None:
        url = self.base_url + "/auth/oauth2/v2/token"
        credentials = f"{self.client_id}:{self.client_secret}".encode("utf-8")
        headers = {
            "Authorization": "Basic " + base64.b64encode(credentials).decode("ascii"),
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        body = json.dumps({"grant_type": "client_credentials"}).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        # 認証エンドポイントも一時的な通信不良に限り再試行する。401/403・TLS検証失敗は再試行しない。
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                break
            except urllib.error.HTTPError as e:
                if e.code in (429, 500, 502, 503, 504) and attempt < 2:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                raise CollectorError(f"OneLoginアクセストークン取得に失敗しました: HTTP {e.code}") from None
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                reason = e.reason if isinstance(e, urllib.error.URLError) else e
                if attempt < 2 and not isinstance(reason, (ssl.SSLError, PermissionError)):
                    time.sleep(0.5 * (attempt + 1))
                    continue
                raise CollectorError("OneLoginアクセストークンエンドポイントへの通信に失敗しました（再試行済み）。今回の実行でのエラーであり、APIが常に利用不可とは断定できません") from None
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not token:
            raise CollectorError("OneLoginのトークンレスポンスにaccess_tokenが含まれていません")
        self.access_token = str(token)

    def get(self, path: str, params: dict[str, Any] | None = None) -> tuple[Any, dict[str, str]]:
        if not self.access_token:
            self.authenticate()
        query = urllib.parse.urlencode(
            [(k, v) for k, value in (params or {}).items() for v in (value if isinstance(value, list) else [value]) if v is not None]
        )
        url = self.base_url + path + (("?" + query) if query else "")
        headers = {"Authorization": "bearer " + str(self.access_token), "Accept": "application/json"}
        req = urllib.request.Request(url, headers=headers, method="GET")
        # 一時的なレート制限/サーバー障害だけを有限回再試行する。秘密情報はログに出さない。
        for attempt in range(4):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    raw = resp.read().decode("utf-8")
                    try:
                        payload = json.loads(raw) if raw else None
                    except ValueError as e:
                        raise CollectorError(f"GET {path}: JSONレスポンスの形式が不正です") from e
                    return payload, {k.lower(): v for k, v in resp.headers.items()}
            except urllib.error.HTTPError as e:
                if e.code in (429, 500, 502, 503, 504) and attempt < 3:
                    retry_after = e.headers.get("Retry-After") if e.headers else None
                    try:
                        seconds = min(max(0.0, float(retry_after)), 10.0) if retry_after else float(2 ** attempt)
                    except (TypeError, ValueError):
                        seconds = float(2 ** attempt)
                    time.sleep(seconds)
                    continue
                raise CollectorError(f"GET {path} に失敗しました: HTTP {e.code}（再試行済み）") from None
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                reason = e.reason if isinstance(e, urllib.error.URLError) else e
                if attempt < 3 and not isinstance(reason, (ssl.SSLError, PermissionError)):
                    time.sleep(0.5 * (attempt + 1))
                    continue
                raise CollectorError(f"GET {path} の通信に失敗しました（再試行済み）。APIが常に利用不可とは断定できません") from None
        raise CollectorError(f"GET {path} を完了できませんでした")

    def list_page(self, path: str, params: dict[str, Any] | None = None, limit: int = 50) -> list[dict[str, Any]]:
        """異常な応答・欠落・不完全なページングを空の一覧と誤認しない。"""
        out: list[dict[str, Any]] = []
        page = 1
        while True:
            q = dict(params or {})
            q.update({"page": page, "limit": limit})
            payload, headers = self.get(path, q)
            if isinstance(payload, list):
                items = payload
            elif isinstance(payload, dict) and isinstance(payload.get("data"), list):
                items = payload["data"]
            else:
                raise CollectorError(f"{path}: 一覧APIのレスポンス形式が不正です（取得失敗を0件に変換しません）")
            checked_records(items, path)
            out.extend(items)
            if len(items) > limit:
                raise CollectorError(f"{path}: ページ内件数が上限を超えています")
            try:
                total_pages = int(headers["total-pages"]) if "total-pages" in headers else None
                total_count = int(headers["total-count"]) if "total-count" in headers else None
            except (ValueError, TypeError) as e:
                raise CollectorError(f"{path}: ページングヘッダーが不正です") from e
            if total_pages is not None:
                if page >= total_pages:
                    if total_count is not None and len(out) != total_count:
                        raise CollectorError(f"{path}: 全件数と収集件数が一致しません")
                    break
                if not items:
                    raise CollectorError(f"{path}: 続きのページがあるのに空のページが返りました")
            elif len(items) < limit:
                if total_count is not None and len(out) != total_count:
                    raise CollectorError(f"{path}: 全件数と収集件数が一致しません")
                break
            page += 1
            if page > 10000:
                raise CollectorError(f"{path}: ページングが安全上限を超えました")
        return out

    def list_events(self, params: dict[str, Any], max_pages: int = 100, *,
                    start_cursor: str | None = None, seen_cursors=None,
                    page_callback=None) -> tuple[list[dict[str, Any]], bool]:
        """v2 Eventsのcursorを厳密に検証。上限到達時のみpartial扱い。"""
        if max_pages <= 0:
            raise CollectorError("Eventsのページ数上限は正数で指定してください")
        out: list[dict[str, Any]] = []
        cursor: str | None = start_cursor
        seen: set[str] = set(seen_cursors or ())
        for page_no in range(max_pages):
            q = dict(params)
            q["limit"] = 100
            if cursor:
                q["after_cursor"] = cursor
            payload, _ = self.get("/api/2/events", q)
            if (not isinstance(payload, dict) or not isinstance(payload.get("data"), list)
                    or not isinstance(payload.get("pagination"), dict)):
                raise CollectorError("Eventsのレスポンスにdata/paginationがありません（0件とは扱いません）")
            items = payload["data"]
            pag = payload["pagination"]
            if any(not isinstance(x, dict) for x in items) or len(items) > 100:
                raise CollectorError("Eventsに不正な要素またはページ件数があります")
            for item in items:
                checked_event(item)
            if not isinstance(pag.get("has_more"), bool):
                raise CollectorError("Eventsのhas_moreが欠損または不正です")
            out.extend(items)
            if not pag["has_more"]:
                if page_callback:
                    page_callback(items, None, True, seen)
                return out, False
            next_cursor = pag.get("next_cursor")
            if not isinstance(next_cursor, str) or not next_cursor:
                raise CollectorError("Eventsに続きがあるのにnext_cursorがありません")
            if next_cursor in seen:
                raise CollectorError("Eventsのnext_cursorが繰り返されています")
            seen.add(next_cursor)
            cursor = next_cursor
            if page_callback:
                page_callback(items, cursor, False, seen)
        return out, True


def resolve_targets(identifiers: list[str], users: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {str(u.get("id")): u for u in users if u.get("id") is not None}
    targets = []
    for ident in identifiers:
        needle = ident.strip()
        matches = []
        if needle in by_id:
            matches = [by_id[needle]]
        else:
            n = needle.lower()
            for u in users:
                values = {
                    str(u.get("email") or "").lower(),
                    str(u.get("username") or "").lower(),
                    display_name(u).lower(),
                    (str(u.get("firstname") or "") + " " + str(u.get("lastname") or "")).strip().lower(),
                }
                if n in values:
                    matches.append(u)
        unique = {str(u.get("id")): u for u in matches if u.get("id") is not None}
        if len(unique) == 0:
            raise CollectorError(f"対象ユーザーが見つかりません: {ident}")
        if len(unique) > 1:
            raise CollectorError(f"対象ユーザーを一意に特定できません: {ident}")
        targets.append(next(iter(unique.values())))
    return targets


def normalize_external_usage(
    raw_events: list[dict[str, Any]],
    users: list[dict[str, Any]],
    apps: list[dict[str, Any]],
    *, return_report: bool = False,
):
    user_idx = index_users(users)
    app_idx: dict[str, int] = {}
    for app in apps:
        if app.get("id") is None:
            continue
        aid = int(app["id"])
        app_idx[f"id:{aid}"] = aid
        if app.get("name"):
            app_idx["name:" + str(app["name"]).strip().lower()] = aid

    normalized = []
    unmatched = 0
    for event in raw_events:
        dt = event_time(event)
        ukey = event_user_key(event)
        akey = event_app_key(event)
        uid = user_idx.get(ukey) if ukey else None
        aid = app_idx.get(akey) if akey else None
        if not dt or not ukey or not akey:
            raise CollectorError("外部利用履歴の日時・ユーザー・アプリ識別情報が欠損または不正です")
        if uid is None or aid is None:
            unmatched += 1
            continue
        normalized.append({"user_id": uid, "app_id": aid, "created_at": dt})
    return (normalized, unmatched) if return_report else normalized


def choose_change_events(events: list[dict[str, Any]], event_types: dict[int, dict[str, Any]], *, return_report=False):
    selected = []
    for e in events:
        etid = e.get("event_type_id")
        meta = event_types.get(int(etid)) if str(etid).isdigit() else None
        name = str((meta or {}).get("name") or "")
        desc = str((meta or {}).get("description") or "")
        text = (name + " " + desc).upper()
        if etid == 8:
            continue
        if (etid not in event_types or
                any(term in text for term in ("ROLE", "GROUP", "USER_UPDATED", "USER_CREATED", "USER_DEACTIVATED", "APP")) or any(
                    e.get(k) not in (None, "") for k in ("role_id", "group_id")
                )):
            selected.append({
                "id": e.get("id"),
                "event_type_id": etid,
                "event_type_name": name or None,
                "event_type_catalog_status": "unlisted" if etid not in event_types else "listed",
                "created_at": e.get("created_at"),
                "actor_system": e.get("actor_system"),
                "actor_user_id": e.get("actor_user_id"),
                "role_id": e.get("role_id"),
                "role_name": e.get("role_name") or e.get("role-name"),
                "group_id": e.get("group_id"),
                "group_name": e.get("group_name") or e.get("group-name"),
                "app_id": e.get("app_id"),
                "app_name": e.get("app_name") or e.get("app-name"),
                # 自由入力テキストは認証情報や個人情報を含む可能性があるため除外する。
            })
    return (selected[:100], len(selected)) if return_report else selected[:100]


def collect(args: argparse.Namespace, client: ApiClient) -> dict[str, Any]:
    now = utc_now()
    since = (now - timedelta(days=args.days)).isoformat().replace("+00:00", "Z")
    warnings: list[str] = []
    if args.days < max(USAGE_WINDOWS):
        warnings.append("指定取得期間より長い利用集計窓は部分取得です。未観測を0件と断定しないでください。")

    # APIレスポンス全体を分析対象として保持せず、必要な列だけに直ちに縮約する。
    all_users = [safe_user(u) for u in checked_records(client.list_page("/api/2/users", limit=50), "ユーザー一覧")]
    targets_brief = resolve_targets(args.user, all_users)

    groups = checked_records(client.list_page("/api/2/groups", limit=200), "グループ一覧")
    group_names = {int(g["id"]): g.get("name") for g in groups if g.get("id") is not None}

    type_payload, _ = client.get("/api/2/events/types")
    event_types = checked_event_types(type_payload)

    # 先に対象ユーザーの詳細を取得し、現在割り当てられているアプリを確認する。
    hydrated_targets: list[dict[str, Any]] = []
    all_target_apps: dict[int, dict[str, Any]] = {}
    for brief in targets_brief:
        uid = int(brief["id"])
        user, _ = client.get(f"/api/2/users/{uid}")
        if not isinstance(user, dict) or type(user.get("id")) is not int or user["id"] != uid:
            raise CollectorError(f"ユーザー {uid} の詳細情報が不正です")
        apps = [
            {"id": a.get("id"), "name": a.get("name")}
            for a in checked_records(client.list_page(f"/api/2/users/{uid}/apps", limit=200), "ユーザーの割当アプリ")
        ]
        for app in apps:
            if app.get("id") is not None:
                all_target_apps[int(app["id"])] = app
        hydrated_targets.append({
            "user": safe_user(user, getattr(args, "allow_custom_attribute", []) or []),
            "apps": apps,
        })

    external_usage = None
    external_usage_unmatched = 0
    usage_source = "onelogin_events"
    if args.usage_file:
        raw_usage = load_usage_file(args.usage_file)
        external_usage, external_usage_unmatched = normalize_external_usage(raw_usage, all_users, list(all_target_apps.values()), return_report=True)
        if external_usage_unmatched:
            warnings.append(f"外部利用履歴の{external_usage_unmatched}件は現在のテナントユーザー／対象アプリと対応せず、完全な利用0件の証拠にはできません。")
        usage_source = "supplied_file"
        if raw_usage and not external_usage:
            warnings.append("指定された利用履歴ファイルに、現在のテナントユーザー／アプリと一致するEventがありませんでした。")

    # Eventsのカタログ差異は処理を止めず、確認できたIDと件数をpartialとして保存する。
    # 各イベントのID・種別・日時の構造が不正な場合は従来どおり停止する。
    unlisted_event_rows = []

    # アプリごとに保有ユーザーとログインEventを一度取得してキャッシュする。
    app_holders: dict[int, set[int]] = {}
    app_login_times: dict[int, dict[int, list[datetime]]] = {}
    app_event_truncated: dict[int, bool] = {}
    for app_id in sorted(all_target_apps):
        holders = checked_records(client.list_page(f"/api/2/apps/{app_id}/users", limit=1000), "アプリ保有者")
        app_holders[app_id] = {int(u["id"]) for u in holders if u.get("id") is not None}
        by_user: dict[int, list[datetime]] = defaultdict(list)
        truncated = False
        if external_usage is not None:
            for e in external_usage:
                if int(e["app_id"]) == app_id:
                    if parse_time(since) <= e["created_at"] <= now:
                        by_user[int(e["user_id"])].append(e["created_at"])
        else:
            events, truncated = client.list_events(
                {"event_type_id": 8, "app_id": app_id, "since": since},
                max_pages=args.max_event_pages,
            )
            for e in events:
                checked_event(e, event_types)
                if e["event_type_id"] not in event_types:
                    unlisted_event_rows.append(e)
                uid = e.get("user_id")
                dt = parse_time(e.get("created_at"))
                if (type(uid) is not int or uid <= 0 or e["event_type_id"] != 8
                        or e.get("app_id", app_id) != app_id):
                    raise CollectorError("アプリのログインEventに必要なユーザーID・種別・アプリIDが不正です")
                if not parse_time(since) <= dt <= now:
                    raise CollectorError("ログインEventの日時が指定された取得期間外です")
                by_user[uid].append(dt)
        app_login_times[app_id] = dict(by_user)
        app_event_truncated[app_id] = truncated
        if truncated:
            warnings.append(f"アプリ {app_id} のログインEventは {args.max_event_pages * 100} 件で打ち切られました。")

    results = []
    for target in hydrated_targets:
        user = target["user"]
        uid = int(user["id"])
        roles_known = isinstance(user.get("role_ids"), list)
        if roles_known and any(type(r) is not int or r <= 0 for r in user["role_ids"]):
            raise CollectorError("ユーザーのrole_idsが不正です")
        role_ids = [int(r) for r in (user.get("role_ids") or []) if str(r).isdigit()]
        roles = []
        for rid in role_ids:
            role, _ = client.get(f"/api/2/roles/{rid}")
            if not isinstance(role, dict) or type(role.get("id")) is not int or role["id"] != rid:
                raise CollectorError(f"Role {rid} の取得データが不正です")
            role_apps = checked_records(client.list_page(f"/api/2/roles/{rid}/apps", limit=200), "Roleのアプリ一覧")
            roles.append({
                "id": rid,
                "name": role.get("name") if isinstance(role, dict) else None,
                "apps": [{"id": a.get("id"), "name": a.get("name")} for a in role_apps],
            })

        cohorts = build_peer_cohorts(user, all_users)
        peer_coverage = peer_attribute_coverage(user, all_users)
        cohort_coverages = {cohort["key"]: peer_attribute_coverage(user, all_users, cohort["fields"])
                            for cohort in cohorts}
        comparison_status = ("unavailable" if not cohorts
                             else "complete" if all(c["status"] == "complete" for c in cohort_coverages.values())
                             else "partial")
        if peer_coverage["status"] != "complete":
            warnings.append(f"ユーザー {uid} のPeer比較に必要な属性または比較対象が不足しています。比較不能を0名と扱わないでください。")
        if not cohorts:
            warnings.append(f"ユーザー {uid} の取得済み属性に一致するPeer比較対象がいません。Peerによる判断は保留してください。")
        elif comparison_status != "complete":
            warnings.append(f"ユーザー {uid} の一部のPeer集団は構成が未確定です。各集団の取得状態を確認してください。")

        user_events, user_events_truncated = client.list_events(
            {"user_id": uid, "since": since}, max_pages=args.max_event_pages
        )
        if user_events_truncated:
            warnings.append(f"ユーザー {uid} のEventは {args.max_event_pages * 100} 件で打ち切られました。")
        for e in user_events:
            checked_event(e, event_types)
            if e["event_type_id"] not in event_types:
                unlisted_event_rows.append(e)
        target_unlisted = unlisted_event_types(user_events, event_types)
        if target_unlisted["unlisted_event_count"]:
            warnings.append(f"ユーザー {uid} にイベント種別カタログ未掲載のEventが{target_unlisted['unlisted_event_count']}件あります。意味を推定せず変更履歴の判断は保留してください。")
        change_events, change_event_count = choose_change_events(user_events, event_types, return_report=True)
        changes_omitted = change_event_count > len(change_events)
        if changes_omitted:
            warnings.append(f"ユーザー {uid} の変更履歴は{change_event_count}件中{len(change_events)}件のみ出力しています。")

        app_rows = []
        for app in target["apps"]:
            if app.get("id") is None:
                continue
            aid = int(app["id"])
            holders = app_holders.get(aid, set())
            usage_by_user = app_login_times.get(aid, {})
            target_usage = summarize_times(usage_by_user.get(uid, []), now)
            target_usage["source"] = usage_source
            usage_incomplete = app_event_truncated.get(aid, False) or bool(external_usage_unmatched)
            if usage_incomplete:
                target_usage["counts_are_lower_bounds"] = True
                target_usage["complete_zero_observation"] = False
                target_usage["counts"] = {k: v if v else None for k, v in target_usage["counts"].items()}
                if target_usage["total_in_window"] == 0:
                    target_usage["total_in_window"] = None
            target_usage["window_coverage"] = {
                str(days): {"status": "partial" if usage_incomplete or days > args.days else "complete"}
                for days in USAGE_WINDOWS}
            for days in USAGE_WINDOWS:
                if days > args.days and target_usage["counts"][str(days)] == 0:
                    target_usage["counts"][str(days)] = None

            peer_stats = []
            for cohort in cohorts:
                peer_ids = {int(x) for x in cohort["user_ids"] if x is not None}
                holder_ids = peer_ids & holders
                active_ids = {pid for pid in peer_ids if usage_by_user.get(pid)}
                logins = sum(len(usage_by_user.get(pid, [])) for pid in peer_ids)
                size = len(peer_ids)
                membership = cohort_coverages[cohort["key"]]
                membership_complete = membership["status"] == "complete"
                peer_usage_incomplete = usage_incomplete or not membership_complete
                peer_stats.append({
                    "key": cohort["key"],
                    "label": cohort["label"],
                    "size": size,
                    "holders": len(holder_ids) if holder_ids or membership_complete else None,
                    "holder_rate": round(len(holder_ids) / size, 4) if size and membership_complete else None,
                    "users_with_observed_login": len(active_ids) if active_ids or not peer_usage_incomplete else None,
                    "observed_login_user_rate": round(len(active_ids) / size, 4) if size and membership_complete and not usage_incomplete else None,
                    "observed_logins": logins if logins or not peer_usage_incomplete else None,
                    "counts_are_lower_bounds": peer_usage_incomplete,
                    "analysis_window_days": args.days,
                    "coverage": {"membership": membership,
                                 "usage": {"status": "partial" if peer_usage_incomplete else "complete",
                                           "reason": "履歴または比較対象が部分取得のため未観測は0件ではありません" if peer_usage_incomplete else None}},
                })

            app_rows.append({
                "id": aid,
                "name": app.get("name"),
                "assignment": role_assignment_for_app(aid, roles, roles_known=roles_known),
                "usage": target_usage,
                "peer_cohorts": peer_stats,
                "coverage": {
                    "app_login_events_truncated": app_event_truncated.get(aid, False),
                    "usage_source": usage_source,
                    "app_holders": {"status": "complete", "reason": None},
                    "app_login_events": {"status": "partial" if usage_incomplete else "complete", "reason": "イベント上限または外部履歴の未対応行があるため、件数は観測下限値。0件は未確定" if usage_incomplete else None},
                },
            })

        results.append({
            "user": safe_user(user, getattr(args, "allow_custom_attribute", []) or []),
            "user_status": user_status_summary(user),
            "group": {
                "id": user.get("group_id"),
                "name": group_names.get(int(user["group_id"])) if user.get("group_id") is not None else None,
            },
            "roles": roles,
            "apps": app_rows,
            "change_events": change_events,
            "coverage": {
                "user_events_truncated": user_events_truncated,
                "peer_candidates": len(all_users) - 1,
                "peer_attributes": peer_coverage,
                "peer_comparison": {"status": comparison_status,
                                    "cohort_count": len(cohorts),
                                    "reason": ("取得できた属性に一致する比較対象がいません。属性の欠損状況も確認してください" if not cohorts
                                               else "比較対象の属性が欠損し、集団全体の構成は未確定です" if comparison_status != "complete" else None)},
                "roles": {"status": "complete" if roles_known else "unavailable", "reason": None if roles_known else "role_idsが取得できていません"},
                "user_events": {"status": "partial" if user_events_truncated else "complete", "reason": "イベント取得上限に達した" if user_events_truncated else None},
                "change_events": {"status": "partial" if user_events_truncated or changes_omitted or target_unlisted["unlisted_event_count"] else "complete",
                                  "reason": ("イベント種別未掲載のため変更内容の分類が未確定" if target_unlisted["unlisted_event_count"] else
                                             "API取得上限または出力件数上限あり" if user_events_truncated or changes_omitted else None),
                                  "unlisted_event_type_ids": target_unlisted["unlisted_event_type_ids"],
                                  "unlisted_event_count": target_unlisted["unlisted_event_count"],
                                  "observed_matching_count": change_event_count, "emitted_count": len(change_events)},
                "user_status": user_status_summary(user)["coverage"],
            },
        })

    # アプリ別とユーザー別Eventsには重複するイベントが含まれ得るためIDで重複排除する。
    unique_unlisted = {event["id"]: event for event in unlisted_event_rows}
    unlisted = unlisted_event_types(list(unique_unlisted.values()), event_types)
    if unlisted["unlisted_event_count"]:
        warnings.append("イベント種別一覧に未掲載のEventがあります。変更履歴を完全と断定しないでください。")
    if any(r["user_status"]["coverage"]["status"] != "complete" for r in results):
        warnings.append("一部ユーザーのstatusが不明です。正常なActiveと見なさないでください。")
    if any(r["coverage"]["roles"]["status"] != "complete" for r in results):
        warnings.append("一部ユーザーのrole_idsが取得できていません。割り当て経路の否定的判断は保留してください。")
    return {
        "schema_version": "1.2",
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "source": {
            "tenant": client.base_url,
            "credential_scope_expected": "Read All",
            "custom_attribute_allowlist": [a for a in (getattr(args, "allow_custom_attribute", []) or []) if not SENSITIVE_ATTRIBUTE_NAME.search(a)],
            "analysis_window_days": args.days,
            "usage_source": usage_source,
            "read_only": True,
            "collection_status": "partial" if warnings else "complete",
            "coverage": {"users": {"status": "complete", "reason": None}, "groups": {"status": "complete", "reason": None}, "event_types": unlisted},
            "warnings": sorted(set(warnings)),
        },
        "targets": results,
    }


def main(argv: list[str] | None = None) -> int:
    """レガシーCLIからSecretを引数・環境変数で受け取らない。"""
    print(
        "このCollectorは内部ライブラリです。AIのコード実行で "
        "python3 scripts/access_review.py --chat-request "
        "を実行してください。今回のチャットの入力をJSONで渡してください。",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
