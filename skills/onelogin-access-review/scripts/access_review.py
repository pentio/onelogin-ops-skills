#!/usr/bin/env python3
"""4環境共通のOneLoginアクセスレビュー収集・コメント記録コマンド。

監査データの収集と、承認済みコメントの追記を分離する。
標準はチャット入力をAIがJSONリクエストとして渡す非対話実行。
"""
from __future__ import annotations

import argparse
import errno
import getpass
import hashlib
import json
import socket
import ssl
import time
import os
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from collect_access_review import ApiClient, CollectorError, SENSITIVE_ATTRIBUTE_NAME, collect, normalize_base_url, parse_time
from inventory_access_review import collect_inventory


from collect_access_review import LocalSafetyError, read_private_file, secure_write_json


def audit_context(args, base):
    """既存JSONを明示指定したときだけ監査IDを継続する。資格情報は継承しない。"""
    previous_path = args.continue_from
    if getattr(args, "resume_events", False):
        if not args.event_checkpoint:
            raise LocalSafetyError("--resume-eventsには--event-checkpointが必要です")
        previous_path = previous_path or args.event_checkpoint
    now = datetime.now(timezone.utc).isoformat()
    previous = None
    if previous_path:
        previous = read_private_file(previous_path, json_only=True)
        if (not isinstance(previous, dict) or not isinstance(previous.get("audit_id"), str)
                or not previous["audit_id"].strip()
                or not isinstance(previous.get("source"), dict) or previous["source"].get("tenant") != base
                or not (isinstance(previous.get("targets"), list)
                        or previous.get("mode") in ("inventory", "inventory_checkpoint"))):
            raise LocalSafetyError("継続元JSONの監査ID・テナント・形式を確認してください")
        if any(previous.get(k) is not None and parse_time(previous[k]) is None
               for k in ("audit_started_at", "generated_at")):
            raise LocalSafetyError("継続元JSONの監査日時が不正です")
    context = {"audit_id": previous["audit_id"] if previous else uuid.uuid4().hex,
               "audit_started_at": (previous.get("audit_started_at") or previous.get("generated_at") or now) if previous else now,
               "collection_id": uuid.uuid4().hex,
               "parent_collection_id": previous.get("collection_id") if previous else None,
               "audit_continued": previous is not None}
    args.audit_context = context
    return context, previous


def require_terminal() -> None:
    """getpassの平文フォールバックを防ぐ。"""
    if not (sys.stdin.isatty() and sys.stderr.isatty()):
        raise LocalSafetyError(
            "対話できるターミナルが必要です。AIが実行する非対話端末ではなく、"
            "利用者自身のターミナルから実行してください。"
        )


def normalize_and_confirm(tenant: str, *, confirmed_tenant: str | None = None) -> str:
    base = normalize_base_url(tenant)
    print(f"接続先のOneLoginテナント: {base}", file=sys.stderr)
    if confirmed_tenant is not None:
        if base != normalize_base_url(confirmed_tenant):
            raise LocalSafetyError("確認済みテナントと正規化後の接続先が一致しません")
        return base
    require_terminal()
    confirm = input("この接続先で続行しますか？ [y/N]: ").strip().lower()
    if confirm not in ("y", "yes"):
        raise LocalSafetyError("接続先が承認されなかったため処理を中止しました")
    return base


def _env_credentials(path_text: str) -> tuple[str, str]:
    path = Path(path_text)
    if path.is_symlink():
        raise LocalSafetyError(".envへのシンボリックリンクは許可しません")
    try:
        actual = path.resolve(strict=True)
        working = Path.cwd().resolve()
        if actual.parent != working or not actual.is_file():
            raise LocalSafetyError(".envは現在の作業ディレクトリ直下の通常ファイルにしてください")
        mode = stat.S_IMODE(actual.stat().st_mode)
        if mode != 0o600:
            raise LocalSafetyError(".envのファイル権限は600にしてください（chmod 600 .env）")
        if actual.stat().st_size > 4096:
            raise LocalSafetyError(".envのサイズが大きすぎます")
        values: dict[str, str] = {}
        for row in actual.read_text(encoding="utf-8").splitlines():
            s = row.strip()
            if not s or s.startswith("#"):
                continue
            key, sep, val = s.partition("=")
            if not sep or key.strip() not in ("OL_CLIENT_ID", "OL_CLIENT_SECRET"):
                raise LocalSafetyError(".envにはOL_CLIENT_IDとOL_CLIENT_SECRETだけを指定してください")
            key = key.strip()
            if key in values:
                raise LocalSafetyError(".envで同じ項目を重複して指定しないでください")
            val = val.strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
                val = val[1:-1]
            if not val:
                raise LocalSafetyError(f".envの{key}が空です")
            values[key] = val
        if "OL_CLIENT_ID" not in values or "OL_CLIENT_SECRET" not in values:
            raise LocalSafetyError(".envにClient IDとClient Secretの両方が必要です")
        return values["OL_CLIENT_ID"], values["OL_CLIENT_SECRET"]
    except OSError as e:
        raise LocalSafetyError(".envを安全に読み込めませんでした") from e


def obtain_credentials(args: argparse.Namespace) -> tuple[str, str]:
    """環境変数や過去実行時の資格情報を暗黙に再利用しない。"""
    if args.credential_mode == "chat":
        credentials = getattr(args, "chat_credentials", None)
        if (not isinstance(credentials, dict)
                or any(not isinstance(credentials.get(k), str) or not credentials[k].strip()
                       for k in ("client_id", "client_secret"))):
            raise LocalSafetyError("今回のチャットで入力されたClient IDとClient Secretが必要です")
        return credentials["client_id"].strip(), credentials["client_secret"]
    if args.credential_mode == "env-file":
        if not args.env_file:
            raise LocalSafetyError("env-fileモードには--env-fileが必要です")
        if not args.confirmed_tenant:
            raise LocalSafetyError("env-fileモードでは、利用者が承認した--confirmed-tenantが必要です")
        print("注意: .envには認証情報が平文で残ります。監査後に削除してください。", file=sys.stderr)
        return _env_credentials(args.env_file)
    if args.env_file:
        raise LocalSafetyError("標準モードでは--env-fileを使用できません")
    require_terminal()
    cid = getpass.getpass("Client ID（非表示）: ")
    secret = getpass.getpass("Client Secret（非表示）: ")
    if not cid.strip() or not secret:
        raise LocalSafetyError("Client IDとClient Secretは空欄にできません")
    return cid.strip(), secret


def connection_for(args):
    if args.credential_mode == "chat":
        base = normalize_base_url(args.tenant)
        approval = getattr(args, "connection_approval", None)
        if (not isinstance(approval, dict) or approval.get("approved") is not True
                or approval.get("tenant") != base):
            raise LocalSafetyError("正規化後の接続先をチャットで表示し、独立した確認を得てください")
        return normalize_and_confirm(args.tenant, confirmed_tenant=approval["tenant"])
    return normalize_and_confirm(args.tenant, confirmed_tenant=args.confirmed_tenant)


def chat_record_approval(args, base, user_id, approved):
    approval = getattr(args, "chat_approval", None)
    digest = hashlib.sha256(approved.encode("utf-8")).hexdigest()
    if (not isinstance(approval, dict) or approval.get("approved") is not True
            or approval.get("scope_confirmed") is not True
            or approval.get("tenant") != base or type(approval.get("user_id")) is not int
            or approval["user_id"] != user_id or approval.get("approved_comment_sha256") != digest):
        raise LocalSafetyError("対象・文面・スコープに結び付いたチャットでの最終承認が必要です")


def prepare_command(args):
    """認証情報やAPIを使わず、チャットで確認する接続先を返す。"""
    base = normalize_base_url(args.tenant)
    print(json.dumps({"status": "awaiting_connection_confirmation", "tenant": base,
                      "message": "この接続先でよいか、チャットで利用者に確認してください"}, ensure_ascii=False))
    return 0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """接続確認では転送先を追わず、確認済みOneLoginホストだけに通信する。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _probe_error_category(error: Exception) -> tuple[str, bool]:
    """原因を限定的に分類する。生のURLや例外文字列は表示しない。"""
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, (ssl.SSLCertVerificationError, ssl.CertificateError)):
        return "tls_certificate_error", False
    if isinstance(reason, ssl.SSLError):
        return "tls_error", False
    if isinstance(reason, socket.gaierror):
        return "dns_error", True
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return "timeout", True
    if isinstance(reason, PermissionError):
        return "execution_network_denied", False
    if isinstance(reason, OSError):
        if reason.errno in (errno.EACCES, errno.EPERM):
            return "execution_network_denied", False
        if reason.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN):
            return "network_unreachable", True
        if reason.errno in (errno.ECONNRESET, errno.ECONNREFUSED, errno.ETIMEDOUT):
            return "connection_error", True
    return "network_error", True


def probe_https(tenant: str, *, timeout: int = 5, attempts: int = 2, pause=None) -> dict[str, Any]:
    """認証情報を送らずトークンAPIへのHTTPS到達性を調べる。実際の認証可否は検証しない。"""
    if type(timeout) is not int or not (1 <= timeout <= 30):
        raise LocalSafetyError("接続確認の--timeoutは1～30秒で指定してください")
    if type(attempts) is not int or not (1 <= attempts <= 3):
        raise LocalSafetyError("接続確認の--attemptsは1～3回で指定してください")
    base = normalize_base_url(tenant)
    url = base + "/auth/oauth2/v2/token"
    opener = urllib.request.build_opener(_NoRedirect())
    sleep = time.sleep if pause is None else pause
    last: dict[str, Any] = {}
    for index in range(1, attempts + 1):
        req = urllib.request.Request(
            url, method="GET",
            headers={"Accept": "application/json", "User-Agent": "OneLoginAccessReviewProbe/1"},
        )
        try:
            with opener.open(req, timeout=timeout) as response:
                code = int(response.status)
        except urllib.error.HTTPError as exc:
            code = int(exc.code)
            exc.close()
        except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError) as exc:
            category, retryable = _probe_error_category(exc)
            last = {"status": "inconclusive", "failure_category": category}
            if retryable and index < attempts:
                sleep(0.5)
                continue
            break
        if 200 <= code < 500 and code != 407:
            return {
                "status": "reachable", "tenant": base, "endpoint": url,
                "http_status": code, "attempts": index,
                "meaning": "同一ホストのOAuthエンドポイントからHTTP応答を受信。API認証や権限の成否は未検証",
            }
        last = {"status": "inconclusive", "http_status": code,
                "failure_category": "proxy_auth_required" if code == 407 else
                "http_server_or_gateway_error" if 500 <= code < 600 else "unexpected_http_response"}
        if index < attempts and 500 <= code < 600:
            sleep(0.5)
            continue
        break
    return {
        **last, "tenant": base, "endpoint": url,
        "attempts": index,
        "meaning": "今回の到達性確認は成功していません。OneLogin APIの使用不可と断定せず、実行環境・経路を調査してください",
    }


def probe_command(args: argparse.Namespace) -> int:
    """接続承認後に実行する非認証の通信確認。Credentialの要求・送信は禁止。"""
    if getattr(args, "chat_credentials", None) is not None:
        raise LocalSafetyError("接続確認に認証情報を渡さないでください")
    if getattr(args, "credential_mode", "terminal") == "chat":
        base = normalize_base_url(args.tenant)
        approval = getattr(args, "connection_approval", None)
        if (not isinstance(approval, dict) or approval.get("approved") is not True
                or approval.get("tenant") != base):
            raise LocalSafetyError("接続確認前に正規化後のURLをチャットに表示して独立した承認を得てください")
    else:
        base = normalize_and_confirm(args.tenant)
    result = probe_https(base, timeout=args.timeout, attempts=args.attempts)
    print(json.dumps(result, ensure_ascii=False))
    # 到達性失敗は必ずJSONとして返す。API使用不可と扱うかは原因調査を経て判断する。
    return 0


def remember_output(args, path):
    outputs = getattr(args, "cleanup_files", None)
    if outputs is None:
        outputs = args.cleanup_files = []
    resolved = str(Path(path).absolute())
    if resolved not in outputs:
        outputs.append(resolved)


def report_cleanup(args):
    """保存したファイルだけを列挙し、ターミナルを使わない削除依頼を案内する。"""
    if args is None:
        return
    files = list(getattr(args, "cleanup_files", []))
    checkpoint = getattr(args, "event_checkpoint", None)
    if checkpoint and Path(checkpoint).is_file():
        resolved = str(Path(checkpoint).absolute())
        if resolved not in files:
            files.append(resolved)
    if not files:
        return
    print("\n保存ファイルと削除方法:")
    for path in files:
        print("- " + path)
    print("不要になったファイルは、このチャットでファイル名を指定して削除を依頼してください。利用者のターミナル操作は不要です。")
    print("保存が必要な受領ファイルと、再開予定のチェックポイントは保持してください。自動削除は行いません。")


def _display_field_name(value: str) -> str:
    """ユーザーへ表示するAPI由来の項目名から制御文字を除外する。"""
    return "".join(c if c.isprintable() else " " for c in value).strip()


def list_custom_fields(api: ApiClient) -> tuple[list[dict[str, Any]], str]:
    """認証後にフィールドの定義のみ取得。ユーザーデータは取得しない。"""
    payload, _ = api.get("/api/2/users/custom_attributes")
    if not isinstance(payload, list):
        raise CollectorError("カスタムユーザーフィールドの一覧が不正です。0件として処理せず監査を中断します")
    fields = []
    ids, shortnames = set(), set()
    for field in payload:
        if (not isinstance(field, dict) or type(field.get("id")) is not int or field["id"] <= 0
                or not isinstance(field.get("name"), str) or not field["name"].strip()
                or not isinstance(field.get("shortname"), str) or not field["shortname"].strip()):
            raise CollectorError("カスタムユーザーフィールドの定義が不正です。0件として処理しません")
        fid, name, shortname = field["id"], field["name"].strip(), field["shortname"].strip()
        if fid in ids or shortname.lower() in shortnames:
            raise CollectorError("カスタムユーザーフィールドのIDまたはShortnameが重複しています")
        ids.add(fid)
        shortnames.add(shortname.lower())
        sensitive = bool(SENSITIVE_ATTRIBUTE_NAME.search(name) or SENSITIVE_ATTRIBUTE_NAME.search(shortname))
        fields.append({"id": fid, "name": _display_field_name(name),
                       "shortname": shortname, "recommended_exclude": sensitive})
    fields.sort(key=lambda f: (f["id"], f["shortname"]))
    digest = hashlib.sha256(json.dumps(fields, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return fields, digest


def custom_fields_command(args: argparse.Namespace) -> int:
    """Credential入力直後に行う事前確認。フィールドの値は送信・保存しない。"""
    base = connection_for(args)
    cid, secret = obtain_credentials(args)
    api = ApiClient(base, cid, secret, timeout=args.timeout)
    fields, digest = list_custom_fields(api)
    print(json.dumps({"status": "awaiting_custom_field_confirmation" if fields else "no_custom_fields",
                      "tenant": base, "count": len(fields), "fields": fields,
                      "catalog_sha256": digest,
                      "message": ("表示名とShortnameを利用者へ提示し、利用しない項目を確認してください。"
                                  if fields else "カスタムユーザーフィールドは0件。確認は不要です。")}, ensure_ascii=False))
    return 0


def resolve_custom_field_consent(args: argparse.Namespace, api: ApiClient, base: str) -> dict[str, Any]:
    """監査の前に確認済みフィールド定義を再取得し、今回の同意と一致させる。"""
    fields, digest = list_custom_fields(api)
    if not fields:
        if getattr(args, "allow_custom_attribute", []) or getattr(args, "custom_fields_approval", None):
            raise LocalSafetyError("カスタムユーザーフィールドの構成が変わりました。項目一覧を再確認してください")
        args.allow_custom_attribute = []
        args.allowed_custom_fields = []
        return {"status": "no_custom_fields", "allowed": [], "excluded": [], "catalog_sha256": digest}
    field_by_shortname = {f["shortname"]: f for f in fields}
    recommended_exclude = {f["shortname"] for f in fields if f["recommended_exclude"]}
    if args.credential_mode == "chat":
        consent = getattr(args, "custom_fields_approval", None)
        if (not isinstance(consent, dict) or set(consent) != {"confirmed", "tenant", "catalog_sha256", "excluded_shortnames"}
                or consent.get("confirmed") is not True or consent.get("tenant") != base
                or consent.get("catalog_sha256") != digest
                or not isinstance(consent.get("excluded_shortnames"), list)
                or any(not isinstance(v, str) for v in consent["excluded_shortnames"])):
            raise LocalSafetyError("カスタムユーザーフィールドの一覧提示後に、今回のテナント・項目一覧に対する利用者の確認が必要です")
        excluded = set(consent["excluded_shortnames"])
    else:
        require_terminal()
        print("監査前のカスタムユーザーフィールド確認（値は表示しません）:", file=sys.stderr)
        for f in fields:
            label = " [機密の可能性: 自動除外]" if f["recommended_exclude"] else ""
            print(f"- {_display_field_name(f['name'])} ({f['shortname']}){label}", file=sys.stderr)
        raw = input("利用しないShortnameをカンマ区切りで入力（なしの場合はEnter）: ").strip()
        excluded = {v.strip() for v in raw.split(",") if v.strip()}
        if input("上記の除外設定で監査を進めますか？ [y/N]: ").strip().lower() not in ("y", "yes"):
            raise LocalSafetyError("カスタムユーザーフィールドの利用確認が承認されませんでした")
    if not excluded <= set(field_by_shortname):
        raise LocalSafetyError("指定した除外Shortnameが現在のカスタムユーザーフィールド一覧にありません")
    excluded |= recommended_exclude
    allowed = sorted(set(field_by_shortname) - excluded)
    user_specified = set(getattr(args, "allow_custom_attribute", []) or [])
    if user_specified and not user_specified <= set(allowed):
        raise LocalSafetyError("指定されたカスタム属性に未許可または機密属性が含まれます")
    if user_specified:
        # --allow-custom-attribute は、承認された範囲をさらに絞る目的で維持する。
        allowed = sorted(user_specified)
    args.allow_custom_attribute = allowed
    args.allowed_custom_fields = allowed
    return {"status": "confirmed", "allowed": allowed, "excluded": sorted(set(field_by_shortname) - set(allowed)), "catalog_sha256": digest}


def collect_command(args: argparse.Namespace) -> int:
    base = connection_for(args)
    if args.credential_mode == "terminal" and args.confirmed_tenant:
        raise LocalSafetyError("標準モードでは--confirmed-tenantを指定できません。接続先を対話確認してください")
    context, previous = audit_context(args, base)
    if not args.user and previous and isinstance(previous.get("targets"), list):
        if any(not isinstance(t, dict) or not isinstance(t.get("user"), dict)
               or type(t["user"].get("id")) is not int for t in previous["targets"]):
            raise LocalSafetyError("継続元の対象ユーザーIDが不正です。対象を明示してください")
        args.user = [str(t["user"]["id"]) for t in previous["targets"]
                     if isinstance(t, dict) and isinstance(t.get("user"), dict)
                     and type(t["user"].get("id")) is int]
    if not args.user:
        raise LocalSafetyError("収集するユーザーを少なくとも1名指定してください")
    if args.days <= 0 or args.max_event_pages <= 0:
        raise LocalSafetyError("期間と最大ページ数は正数で指定してください")
    # 認証情報の入力は、テナントの正規化と承認が終わってから実施する。
    cid, secret = obtain_credentials(args)
    api = ApiClient(base, cid, secret, timeout=args.timeout)
    collect_args = argparse.Namespace(
        user=args.user, days=args.days, max_event_pages=args.max_event_pages,
        usage_file=args.usage_file, allow_custom_attribute=args.allow_custom_attribute,
    )
    field_consent = resolve_custom_field_consent(args, api, base)
    collect_args.allow_custom_attribute = args.allow_custom_attribute
    result = collect(collect_args, api)
    result["source"]["custom_fields_consent"] = field_consent
    result.update(context)
    result["source"]["credential_entry_mode"] = args.credential_mode
    result["source"]["collection_environment"] = "ai-execution" if args.credential_mode == "chat" else "local-terminal"
    result["source"]["scope_verification"] = "APIの成否に基づく。Credentialの表示スコープはAPIトークンレスポンスから証明できない"
    dest = secure_write_json(args.output, result, overwrite=args.overwrite)
    remember_output(args, dest)
    print(f"収集完了: {dest}（ファイル権限600）")
    print(f"監査ID: {result['audit_id']} / 調査対象: {len(result['targets'])} 名")
    print("収集JSONを分析します。認証情報は結果ファイルへ保存しません。")
    if args.credential_mode == "env-file":
        print("注意: 作業が終わったら .env を削除してください。")
    return 0


def inventory_command(args: argparse.Namespace) -> int:
    """対象ユーザーを指定せず全テナントの確認候補を抽出する。"""
    base = connection_for(args)
    if args.credential_mode == "terminal" and args.confirmed_tenant:
        raise LocalSafetyError("標準モードでは--confirmed-tenantを指定できません")
    if args.days <= 0 or args.max_event_pages <= 0:
        raise LocalSafetyError("期間と最大ページ数は正数で指定してください")
    context, _ = audit_context(args, base)
    if args.lifecycle_file and not args.hr_data_approved:
        raise LocalSafetyError("人事情報の利用には明示承認と--hr-data-approvedが必要です")
    cid, secret = obtain_credentials(args)
    api = ApiClient(base, cid, secret, timeout=args.timeout)
    field_consent = resolve_custom_field_consent(args, api, base)
    result = collect_inventory(args, api)
    result["source"]["custom_fields_consent"] = field_consent
    result.update(context)
    result["source"]["credential_entry_mode"] = args.credential_mode
    result["source"]["collection_environment"] = "ai-execution" if args.credential_mode == "chat" else "local-terminal"
    dest = secure_write_json(args.output, result, overwrite=args.overwrite)
    remember_output(args, dest)
    print(f"全体棚卸し完了: {dest}（権限600）")
    print(f"監査ID: {result['audit_id']} / スキャン: {result['summary']['users_scanned']}名 / 候補: {result['summary']['candidates']}名")
    if result['source']['collection_status'] != 'complete':
        print("注意: 一部の情報は未取得です。0件・異常なしと解釈しないでください")
    print("詳細に調査するユーザーを選択してください。ユーザー名・メール・IDで指定できます。")
    return 0


def _find_audit_target(audit: dict[str, Any], tenant: str, user_identifier: str) -> dict[str, Any]:
    if audit.get("source", {}).get("tenant") != tenant:
        raise LocalSafetyError("監査データに記録されたテナントと接続先が一致しません")
    key = user_identifier.strip().lower()
    matched = []
    for target in audit.get("targets", []):
        user = target.get("user", {})
        identifiers = {str(user.get("id", "")).lower(), str(user.get("email") or "").lower(),
                       str(user.get("username") or "").lower()}
        if key in identifiers:
            matched.append(user)
    if len(matched) != 1:
        raise LocalSafetyError("監査データ内の対象ユーザーと--userを一意に対応させられません")
    return matched[0]


def _api_update_comment(api: ApiClient, user_id: int, comment: str) -> None:
    if not api.access_token:
        api.authenticate()
    path = f"/api/2/users/{user_id}?mappings=disabled"
    req = urllib.request.Request(
        api.base_url + path,
        data=json.dumps({"comment": comment}, ensure_ascii=False).encode("utf-8"),
        headers={"Authorization": "bearer " + str(api.access_token),
                 "Content-Type": "application/json", "Accept": "application/json"},
        method="PUT",
    )
    try:
        with urllib.request.urlopen(req, timeout=api.timeout) as response:
            if response.status != 200:
                raise LocalSafetyError(f"コメント更新APIがHTTP {response.status}を返しました")
    except urllib.error.HTTPError as e:
        raise LocalSafetyError(f"コメント更新APIが拒否しました（HTTP {e.code}）。Credentialの権限も確認してください") from None
    except urllib.error.URLError as e:
        raise LocalSafetyError("コメント更新APIへの接続に失敗しました") from e


def record_command(args: argparse.Namespace) -> int:
    if not args.confirmed_scope_in_admin:
        raise LocalSafetyError(
            "書き込み用CredentialのManage usersまたはManage AllをOneLogin管理画面で確認し、"
            "--confirmed-scope-in-adminを指定してください"
        )
    if args.credential_mode != "chat":
        require_terminal()
    base = connection_for(args)
    audit = read_private_file(args.audit_data, json_only=True)
    if not isinstance(audit, dict) or not audit.get("audit_id"):
        raise LocalSafetyError("監査IDを持つ収集JSONだけを使用してください")
    expected = _find_audit_target(audit, base, args.user[0])
    user_id = expected.get("id")
    if not isinstance(user_id, int):
        raise LocalSafetyError("監査データに整数のユーザーIDがありません")
    approved = read_private_file(args.approved_comment).strip()
    if not approved:
        raise LocalSafetyError("承認済みコメントのファイルが空です")
    print(
        "OneLogin管理画面の Developers > API Credentials で、今回入力するClient IDの"
        "スコープがManage usersまたはManage Allであることを確認してください。\n"
        "注: 標準のOAuthトークン応答にはスコープ情報がないため、ツール単体では事前にAPI検証できません。"
    )
    if args.credential_mode == "chat":
        chat_record_approval(args, base, user_id, approved)
    elif input("管理画面で確認済みなら 'SCOPE VERIFIED' と入力: ").strip() != "SCOPE VERIFIED":
        raise LocalSafetyError("Credentialのスコープ確認が完了していません")
    # OneLoginを変更する前に、今回の受領ファイルを排他的に作成する。
    # 既存ファイルの衝突や保存先の問題を、書き込み後に初めて発見しない。
    receipt = {
        "audit_id": audit["audit_id"], "collection_id": audit.get("collection_id"), "tenant": base, "user_id": user_id,
        "email": expected.get("email"), "status": "not_written",
        "write_attempted": False, "api_update_acknowledged": False,
        "approved_comment_sha256": hashlib.sha256(approved.encode("utf-8")).hexdigest(),
        "scope_check": "operator_confirmed_in_admin_not_api_verified",
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    receipt_path = secure_write_json(args.receipt, receipt, overwrite=args.overwrite)
    remember_output(args, receipt_path)
    print(f"受領ファイル: {receipt_path}（権限600。処理結果はこのファイルで確認してください）")
    def save_receipt(status):
        receipt["status"] = status
        receipt["checked_at"] = datetime.now(timezone.utc).isoformat()
        secure_write_json(str(receipt_path), receipt, overwrite=True)
    phase = "before_update"
    try:
        cid, secret = obtain_credentials(args)
        api = ApiClient(base, cid, secret, timeout=args.timeout)
        live, _ = api.get(f"/api/2/users/{user_id}")
        if not isinstance(live, dict) or live.get("id") != user_id:
            raise LocalSafetyError("直前確認の対象ユーザーIDが一致しません")
        if str(live.get("email") or "").lower() != str(expected.get("email") or "").lower():
            raise LocalSafetyError("対象ユーザーのメールアドレスが監査時から変化しています")
        if "comment" not in live or (live["comment"] is not None and not isinstance(live["comment"], str)):
            raise LocalSafetyError("既存コメントの取得が不完全です。空欄とみなして更新することはできません")
        old_comment = str(live.get("comment") or "")
        outcome = "already_present" if approved in old_comment else "not_written"
        if outcome != "already_present":
            appended = old_comment.rstrip() + ("\n\n" if old_comment.strip() else "") + approved
            print("\n--- 今回追記する承認済みコメント ---\n" + approved + "\n--- ここまで ---")
            print(f"テナント: {base} / 対象ユーザーID: {user_id} / メール: {expected.get('email')}")
            print("既存コメントは保持します。User Mappingは無効で更新します。")
            if args.credential_mode == "chat":
                chat_record_approval(args, base, user_id, approved)
            elif input(f"書き込む場合は 'UPDATE {user_id}' と入力: ").strip() != f"UPDATE {user_id}":
                raise LocalSafetyError("最終承認が得られなかったため、書き込みませんでした")
            # PUTの前に保存する。通信が途中で切れた場合も『未更新』と断定しない。
            receipt["write_attempted"] = True
            save_receipt("update_outcome_unknown")
            phase = "update"
            _api_update_comment(api, user_id, appended)
            phase = "verification"
            receipt["api_update_acknowledged"] = True
            save_receipt("written_verification_pending")
            after, _ = api.get(f"/api/2/users/{user_id}")
            if (not isinstance(after, dict) or after.get("id") != user_id
                    or str(after.get("email") or "").lower() != str(expected.get("email") or "").lower()
                    or str(after.get("comment") or "") != appended):
                outcome = "verification_failed"
            else:
                outcome = "written_and_verified"
        save_receipt(outcome)
    except (CollectorError, LocalSafetyError, OSError, ValueError, EOFError, KeyboardInterrupt):
        # 例外本文やAPIレスポンスは保存せず、秘密情報を受領ファイルに混入させない。
        if phase == "before_update":
            receipt["write_attempted"] = False
        outcome = {"before_update": "not_written", "update": "update_outcome_unknown",
                   "verification": "verification_unavailable"}[phase]
        save_receipt(outcome)
        raise
    print(f"結果: {outcome} / 受領ファイル: {receipt_path}（権限600）")
    return 0 if outcome in ("written_and_verified", "already_present") else 1


class SafeArgumentParser(argparse.ArgumentParser):
    """不正な引数に秘密情報が含まれていてもエラーへ転記しない。"""
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, "エラー: 引数が正しくありません。--helpをご確認ください。認証情報を引数に含めないでください。\n")


def build_parser() -> argparse.ArgumentParser:
    p = SafeArgumentParser(description="OneLogin連携アプリのアクセス権監査（4環境共通）")
    sub = p.add_subparsers(dest="operation", required=True)
    def shared(cmd: argparse.ArgumentParser, *, include_user: bool = True) -> None:
        cmd.add_argument("--tenant", required=True, help="サブドメイン・ホスト名・テナントURL")
        if include_user:
            cmd.add_argument("--user", action="append", help="対象ユーザーID・メールアドレス等（collect/recordで必須）")
        cmd.add_argument("--timeout", type=int, default=30, help="API接続のタイムアウト秒数")
        cmd.add_argument("--credential-mode", choices=("terminal", "env-file", "chat"), default="terminal",
                         help="chat/terminal/env-fileから実行環境に合った入力方式を明示して選択")
        cmd.add_argument("--env-file", help="env-fileモードのときだけ作業ディレクトリ直下の.envを指定")
        cmd.add_argument("--confirmed-tenant", help="env-fileモード時に利用者が事前承認した接続先URL")
        cmd.add_argument("--overwrite", action="store_true", help="既存の出力ファイルを明示的に上書き")
    prep = sub.add_parser("prepare", help="接続先確認用のURLを生成する（API通信なし）")
    shared(prep, include_user=False)
    prep.set_defaults(handler=prepare_command, user=None)
    probe = sub.add_parser("probe", help="認証情報なしでOAuthエンドポイントのHTTPS到達性を実測する")
    probe.add_argument("--tenant", required=True, help="確認済みOneLoginサブドメインまたはURL")
    probe.add_argument("--timeout", type=int, default=5, help="1回の接続タイムアウト秒数（1～30）")
    probe.add_argument("--attempts", type=int, default=2, help="最大試行回数（1～3、既定2）")
    probe.set_defaults(handler=probe_command)
    fields_cmd = sub.add_parser("custom-fields", help="認証情報入力後にカスタムユーザーフィールドの定義だけを取得")
    shared(fields_cmd, include_user=False)
    fields_cmd.set_defaults(handler=custom_fields_command, user=None)
    cc = sub.add_parser("collect", help="監査データを安全に収集する（GETのみ）")
    shared(cc)
    cc.add_argument("--days", type=int, default=365)
    cc.add_argument("--continue-from", help="同じ監査を続けるときだけ、既存の監査JSON（600）を指定")
    cc.add_argument("--max-event-pages", type=int, default=100)
    cc.add_argument("--usage-file", help="外部ログイン履歴のCSV/JSON")
    cc.add_argument("--allow-custom-attribute", action="append", default=[], metavar="ATTRIBUTE",
                    help="出力を明示的に許可するカスタム属性名。複数回指定できる")
    cc.add_argument("--output", default="access_review_data.json", help="収集JSONの保存先（600）")
    cc.set_defaults(handler=collect_command)
    inv = sub.add_parser("inventory", help="ユーザー指定なしでテナント全体の確認候補を抽出（AIはここでは判定しない）")
    shared(inv, include_user=False)
    inv.add_argument("--inventory-depth", choices=("basic", "extended"), default="basic",
                     help="basic:候補一次抽出のみ（Role/Events取得なし）、extended:従来の詳細な候補抽出")
    inv.add_argument("--days", type=int, default=365, help="extendedモードのイベント取得期間（日数）")
    inv.add_argument("--continue-from", help="既存の棚卸し/監査JSONを指定し同じ監査IDを引き継ぐ")
    inv.add_argument("--inventory-policy", help="保持パターン・集中付与・状態遷移の組織設定JSON（600）")
    inv.add_argument("--event-checkpoint", help="最小化したEventsの再開用ファイル（600）。AIには渡さない")
    inv.add_argument("--resume-events", action="store_true", help="保存済みカーソルからEvents収集を再開")
    inv.add_argument("--lifecycle-file", help="承認済みの入社/異動/退職イベントJSON（600）")
    inv.add_argument("--lifecycle-kind", choices=("joiner", "mover", "leaver"), help="人事イベントの種類で絞り込む")
    inv.add_argument("--hr-data-approved", action="store_true", help="対象の人事情報の利用が明示的に承認された場合のみ指定")
    inv.add_argument("--max-event-pages", type=int, default=100, help="Eventsの最大ページ数。上限到達時はpartialと明示")
    inv.add_argument("--app", action="append", help="特定アプリ名またはアプリIDに絞り込む（複数可）")
    inv.add_argument("--department", help="部署で絞り込む（必要に応じ個別APIで属性補完）")
    inv.add_argument("--manager", help="上長ユーザーIDで絞り込む（必要に応じ個別APIで属性補完）")
    inv.add_argument("--max-attribute-users", type=int, default=200, metavar="N",
                     help="一覧APIで属性不足時に個別取得するユーザーの上限（既定200）。超過時は比較未実施/部分実施")
    inv.add_argument("--min-peer-users", type=int, default=10, metavar="N",
                     help="本人以外の最小同属性比較人数（既定10）")
    inv.add_argument("--max-peer-app-rate", type=float, default=0.10, metavar="RATE",
                     help="同属性比較で候補にするアプリ保有率の上限（0-1、既定0.10）")
    inv.add_argument("--peer-custom-department", metavar="SHORTNAME",
                     help="承認済みカスタム属性を部署の代替として指定。未指定時は名称が明確な候補のみ自動選択")
    inv.add_argument("--peer-custom-title", metavar="SHORTNAME",
                     help="承認済みカスタム属性を職種の代替として指定。未指定時は名称が明確な候補のみ自動選択")
    inv.add_argument("--peer-group-fallback", action="store_true",
                     help="Groupの意味が業務上確認できた場合だけ、部署・職種に代えて比較に利用")
    inv.add_argument("--high-impact-app", action="append", help="重要アプリとして重点確認するアプリ名/ID")
    inv.add_argument("--privileged-group", action="append", help="重要グループとして重点確認するグループID")
    inv.add_argument("--output", default="access_review_inventory.json", help="候補要約JSONの保存先（600）")
    inv.set_defaults(handler=inventory_command, user=None)
    rec = sub.add_parser("record", help="承認済みの監査結果をユーザーcommentに追記")
    shared(rec)
    rec.add_argument("--audit-data", required=True, help="collectで出力した監査JSON（600）")
    rec.add_argument("--approved-comment", required=True, help="事前に文面承認を得たテキスト（600）")
    rec.add_argument("--confirmed-scope-in-admin", action="store_true",
                     help="OneLogin管理画面でManage users/Manage Allを確認済みの場合のみ指定")
    rec.add_argument("--receipt", default="access_review_comment_receipt.json", help="結果ファイル（600）")
    rec.set_defaults(handler=record_command)
    return p


def main(argv: list[str] | None = None, *, chat_request=None) -> int:
    # stdout/stderrに秘密情報を出さない。既存の環境変数は資格情報として使用しない。
    os.umask(0o077)
    args = None
    try:
        command = sys.argv[1:] if argv is None else argv
        if chat_request is None and command == ["--chat-request"]:
            try:
                chat_request = json.load(sys.stdin)
            except (ValueError, OSError):
                raise LocalSafetyError("チャット実行リクエストのJSON形式が不正です") from None
        if chat_request is not None:
            if (not isinstance(chat_request, dict)
                    or set(chat_request) - {"operation", "arguments", "credentials", "record_approval", "connection_approval", "custom_fields_approval"}
                    or chat_request.get("operation") not in ("prepare", "probe", "custom-fields", "inventory", "collect", "record")
                    or not isinstance(chat_request.get("arguments"), list)
                    or any(not isinstance(x, str) for x in chat_request["arguments"])):
                raise LocalSafetyError("チャット実行リクエストの項目が不正です")
            args = build_parser().parse_args([chat_request["operation"], *chat_request["arguments"]])
            args.credential_mode = "chat"
            if getattr(args, "env_file", None) or getattr(args, "confirmed_tenant", None):
                raise LocalSafetyError("チャット実行では認証ファイルや別の接続先確認値を指定しません")
            args.chat_credentials = chat_request.get("credentials")
            args.chat_approval = chat_request.get("record_approval")
            args.connection_approval = chat_request.get("connection_approval")
            args.custom_fields_approval = chat_request.get("custom_fields_approval")
        else:
            args = build_parser().parse_args(command)
        if args.operation == "inventory" and args.user:
            raise LocalSafetyError("inventoryでは--userを指定しません。個別調査はcollectを使用してください")
        if args.operation == "record" and (not args.user or len(args.user) != 1):
            raise LocalSafetyError("recordは対象ユーザーを1名だけ指定してください")
        if args.operation == "record" and args.credential_mode not in ("terminal", "chat"):
            raise LocalSafetyError("コメント記録はチャット承認付き実行または本人の対話実行で行ってください")
        return args.handler(args)
    except (LocalSafetyError, CollectorError) as e:
        print(f"エラー: {e}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as e:
        print("エラー: 安全に処理を完了できませんでした。入力ファイルとネットワークの状態を確認してください。", file=sys.stderr)
        return 2
    finally:
        report_cleanup(args)


if __name__ == "__main__":
    raise SystemExit(main())
