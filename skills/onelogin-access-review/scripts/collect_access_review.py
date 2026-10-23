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
import sys
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
    "role_ids", "custom_attributes", "status", "state", "comment", "created_at", "updated_at",
    "last_login",
)
USAGE_WINDOWS = (30, 90, 180, 365)


class CollectorError(RuntimeError):
    pass

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
    try:
        status = int(raw) if raw is not None else None
    except (TypeError, ValueError):
        status = None
    return {
        "status": status,
        "status_name": USER_STATUS_NAMES.get(status, "不明") if status is not None else None,
        "active": status == 1,
        "requires_user_review": status is not None and status != 1,
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
    raw = (value or "").strip()
    if not raw:
        raise CollectorError("OneLoginのベースURLまたはサブドメインが必要です")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme.lower() != "https":
        raise CollectorError("OneLogin URLはhttpsを使用してください")
    if parsed.username or parsed.password:
        raise CollectorError("認証情報をURLへ埋め込まないでください")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host.endswith(".onelogin.com"):
        raise CollectorError("OneLoginホストは.onelogin.comで終わる必要があります")
    if parsed.path not in ("", "/") or parsed.params or parsed.query or parsed.fragment:
        raise CollectorError("テナントのルートURLだけを指定してください。例: https://example.onelogin.com")
    return f"https://{host}"


def safe_user(user: dict[str, Any]) -> dict[str, Any]:
    return {k: user.get(k) for k in USER_KEYS if k in user}


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
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ("events", "data", "login_history", "history"):
            if isinstance(data.get(key), list):
                return [x for x in data[key] if isinstance(x, dict)]
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


def role_assignment_for_app(app_id: int, roles: list[dict[str, Any]]) -> dict[str, Any]:
    via = []
    for role in roles:
        role_app_ids = {int(a["id"]) for a in role.get("apps", []) if a.get("id") is not None}
        if int(app_id) in role_app_ids:
            via.append({"id": role.get("id"), "name": role.get("name")})
    return {
        "via_roles": via,
        "explained_by_current_role": bool(via),
        "unexplained_by_current_roles": not bool(via),
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
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise CollectorError(f"OneLoginアクセストークン取得に失敗しました: HTTP {e.code}") from None
        except urllib.error.URLError as e:
            raise CollectorError(f"OneLoginアクセストークンエンドポイントへ接続できません: {e.reason}") from None
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
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
                payload = json.loads(raw) if raw else None
                return payload, {k.lower(): v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as e:
            raise CollectorError(f"GET {path} に失敗しました: HTTP {e.code}") from None
        except urllib.error.URLError as e:
            raise CollectorError(f"GET {path} に失敗しました: {e.reason}") from None

    def list_page(self, path: str, params: dict[str, Any] | None = None, limit: int = 50) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        page = 1
        while True:
            q = dict(params or {})
            q.update({"page": page, "limit": limit})
            payload, _ = self.get(path, q)
            if isinstance(payload, dict) and isinstance(payload.get("data"), list):
                items = payload["data"]
            elif isinstance(payload, list):
                items = payload
            else:
                items = []
            out.extend(x for x in items if isinstance(x, dict))
            if len(items) < limit:
                break
            page += 1
            if page > 10000:
                raise CollectorError(f"{path} のページングが安全上限を超えました")
        return out

    def list_events(self, params: dict[str, Any], max_pages: int = 100) -> tuple[list[dict[str, Any]], bool]:
        out: list[dict[str, Any]] = []
        cursor = None
        truncated = False
        for page_no in range(max_pages):
            q = dict(params)
            q["limit"] = 100
            if cursor:
                q["after_cursor"] = cursor
            payload, _ = self.get("/api/2/events", q)
            if not isinstance(payload, dict):
                break
            items = payload.get("data") if isinstance(payload.get("data"), list) else []
            out.extend(x for x in items if isinstance(x, dict))
            pagination = payload.get("pagination") if isinstance(payload.get("pagination"), dict) else {}
            if not pagination.get("has_more"):
                break
            cursor = pagination.get("next_cursor")
            if not cursor:
                break
            if page_no == max_pages - 1:
                truncated = True
        return out, truncated


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
) -> list[dict[str, Any]]:
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
    for event in raw_events:
        dt = event_time(event)
        ukey = event_user_key(event)
        akey = event_app_key(event)
        uid = user_idx.get(ukey) if ukey else None
        aid = app_idx.get(akey) if akey else None
        if not dt or uid is None or aid is None:
            continue
        normalized.append({"user_id": uid, "app_id": aid, "created_at": dt})
    return normalized


def choose_change_events(events: list[dict[str, Any]], event_types: dict[int, dict[str, Any]]) -> list[dict[str, Any]]:
    selected = []
    for e in events:
        etid = e.get("event_type_id")
        meta = event_types.get(int(etid)) if str(etid).isdigit() else None
        name = str((meta or {}).get("name") or "")
        desc = str((meta or {}).get("description") or "")
        text = (name + " " + desc).upper()
        if etid == 8:
            continue
        if any(term in text for term in ("ROLE", "GROUP", "USER_UPDATED", "USER_CREATED", "USER_DEACTIVATED", "APP")) or any(
            e.get(k) not in (None, "") for k in ("role_id", "group_id")
        ):
            selected.append({
                "id": e.get("id"),
                "event_type_id": etid,
                "event_type_name": name or None,
                "created_at": e.get("created_at"),
                "actor_system": e.get("actor_system"),
                "actor_user_id": e.get("actor_user_id"),
                "role_id": e.get("role_id"),
                "role_name": e.get("role_name") or e.get("role-name"),
                "group_id": e.get("group_id"),
                "group_name": e.get("group_name") or e.get("group-name"),
                "app_id": e.get("app_id"),
                "app_name": e.get("app_name") or e.get("app-name"),
                "custom_message": e.get("custom_message"),
            })
    return selected[:100]


def collect(args: argparse.Namespace, client: ApiClient) -> dict[str, Any]:
    now = utc_now()
    since = (now - timedelta(days=args.days)).isoformat().replace("+00:00", "Z")
    warnings: list[str] = []

    all_users = client.list_page("/api/2/users", limit=50)
    targets_brief = resolve_targets(args.user, all_users)

    groups = client.list_page("/api/2/groups", limit=200)
    group_names = {int(g["id"]): g.get("name") for g in groups if g.get("id") is not None}

    type_payload, _ = client.get("/api/2/events/types")
    event_types = {
        int(x["id"]): x for x in (type_payload if isinstance(type_payload, list) else [])
        if isinstance(x, dict) and x.get("id") is not None
    }

    # 先に対象ユーザーの詳細を取得し、現在割り当てられているアプリを確認する。
    hydrated_targets: list[dict[str, Any]] = []
    all_target_apps: dict[int, dict[str, Any]] = {}
    for brief in targets_brief:
        uid = int(brief["id"])
        user, _ = client.get(f"/api/2/users/{uid}")
        apps = client.list_page(f"/api/2/users/{uid}/apps", limit=200)
        for app in apps:
            if app.get("id") is not None:
                all_target_apps[int(app["id"])] = app
        hydrated_targets.append({"user": user if isinstance(user, dict) else brief, "apps": apps})

    external_usage = None
    usage_source = "onelogin_events"
    if args.usage_file:
        raw_usage = load_usage_file(args.usage_file)
        external_usage = normalize_external_usage(raw_usage, all_users, list(all_target_apps.values()))
        usage_source = "supplied_file"
        if not external_usage:
            warnings.append("指定された利用履歴ファイルに、現在のテナントユーザー／アプリと一致するEventがありませんでした。")

    # アプリごとに保有ユーザーとログインEventを一度取得してキャッシュする。
    app_holders: dict[int, set[int]] = {}
    app_login_times: dict[int, dict[int, list[datetime]]] = {}
    app_event_truncated: dict[int, bool] = {}
    for app_id in sorted(all_target_apps):
        holders = client.list_page(f"/api/2/apps/{app_id}/users", limit=1000)
        app_holders[app_id] = {int(u["id"]) for u in holders if u.get("id") is not None}
        by_user: dict[int, list[datetime]] = defaultdict(list)
        truncated = False
        if external_usage is not None:
            for e in external_usage:
                if int(e["app_id"]) == app_id:
                    by_user[int(e["user_id"])].append(e["created_at"])
        else:
            events, truncated = client.list_events(
                {"event_type_id": 8, "app_id": app_id, "since": since},
                max_pages=args.max_event_pages,
            )
            for e in events:
                uid = e.get("user_id")
                dt = parse_time(e.get("created_at"))
                if uid is not None and dt:
                    by_user[int(uid)].append(dt)
        app_login_times[app_id] = dict(by_user)
        app_event_truncated[app_id] = truncated
        if truncated:
            warnings.append(f"アプリ {app_id} のログインEventは {args.max_event_pages * 100} 件で打ち切られました。")

    results = []
    for target in hydrated_targets:
        user = target["user"]
        uid = int(user["id"])
        role_ids = [int(r) for r in (user.get("role_ids") or []) if str(r).isdigit()]
        roles = []
        for rid in role_ids:
            role, _ = client.get(f"/api/2/roles/{rid}")
            role_apps = client.list_page(f"/api/2/roles/{rid}/apps", limit=200)
            roles.append({
                "id": rid,
                "name": role.get("name") if isinstance(role, dict) else None,
                "apps": [{"id": a.get("id"), "name": a.get("name")} for a in role_apps],
            })

        cohorts = build_peer_cohorts(user, all_users)

        user_events, user_events_truncated = client.list_events(
            {"user_id": uid, "since": since}, max_pages=args.max_event_pages
        )
        if user_events_truncated:
            warnings.append(f"ユーザー {uid} のEventは {args.max_event_pages * 100} 件で打ち切られました。")
        change_events = choose_change_events(user_events, event_types)

        app_rows = []
        for app in target["apps"]:
            if app.get("id") is None:
                continue
            aid = int(app["id"])
            holders = app_holders.get(aid, set())
            usage_by_user = app_login_times.get(aid, {})
            target_usage = summarize_times(usage_by_user.get(uid, []), now)
            target_usage["source"] = usage_source

            peer_stats = []
            for cohort in cohorts:
                peer_ids = {int(x) for x in cohort["user_ids"] if x is not None}
                holder_ids = peer_ids & holders
                active_ids = {pid for pid in peer_ids if usage_by_user.get(pid)}
                logins = sum(len(usage_by_user.get(pid, [])) for pid in peer_ids)
                size = len(peer_ids)
                peer_stats.append({
                    "key": cohort["key"],
                    "label": cohort["label"],
                    "size": size,
                    "holders": len(holder_ids),
                    "holder_rate": round(len(holder_ids) / size, 4) if size else None,
                    "users_with_observed_login": len(active_ids),
                    "observed_login_user_rate": round(len(active_ids) / size, 4) if size else None,
                    "observed_logins": logins,
                })

            app_rows.append({
                "id": aid,
                "name": app.get("name"),
                "assignment": role_assignment_for_app(aid, roles),
                "usage": target_usage,
                "peer_cohorts": peer_stats,
                "coverage": {
                    "app_login_events_truncated": app_event_truncated.get(aid, False),
                    "usage_source": usage_source,
                },
            })

        results.append({
            "user": safe_user(user),
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
            },
        })

    return {
        "schema_version": "1.1",
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "source": {
            "tenant": client.base_url,
            "credential_scope_expected": "Read All",
            "analysis_window_days": args.days,
            "usage_source": usage_source,
            "read_only": True,
            "warnings": sorted(set(warnings)),
        },
        "targets": results,
    }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="最小権限アクセスレビューに必要なOneLogin情報を収集します")
    p.add_argument("--base-url", default=os.getenv("OL_BASE_URL"), help="OneLoginテナントURLまたはサブドメイン。環境変数: OL_BASE_URL")
    p.add_argument("--client-id", default=os.getenv("OL_CLIENT_ID"), help="API Client ID。環境変数: OL_CLIENT_ID")
    p.add_argument("--client-secret", default=os.getenv("OL_CLIENT_SECRET"), help="API Client Secret。環境変数: OL_CLIENT_SECRET")
    p.add_argument("--user", action="append", required=True, help="対象ユーザーのID／メールアドレス／ユーザー名／氏名。複数回指定可能")
    p.add_argument("--usage-file", help="OneLoginのアプリログインEventの代わりに利用するCSV/JSON形式の利用履歴（任意）")
    p.add_argument("--days", type=int, default=365, help="Event収集期間（日数）。既定値: 365")
    p.add_argument("--max-event-pages", type=int, default=100, help="1回のEvent照会で取得する最大ページ数（1ページ100件）")
    p.add_argument("--timeout", type=int, default=30, help="HTTPタイムアウト秒数")
    p.add_argument("--output", help="JSON出力先。未指定時は標準出力")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.base_url or not args.client_id or not args.client_secret:
        print("エラー: ベースURL、Client ID、Client Secretが必要です（引数またはOL_*環境変数で指定してください）。", file=sys.stderr)
        return 2
    if args.days <= 0 or args.max_event_pages <= 0:
        print("エラー: --days と --max-event-pages には正の値を指定してください。", file=sys.stderr)
        return 2
    try:
        client = ApiClient(args.base_url, args.client_id, args.client_secret, timeout=args.timeout)
        result = collect(args, client)
    except CollectorError as e:
        print(f"エラー: {e}", file=sys.stderr)
        return 1

    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
        print(args.output)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
