"""OneLogin全体棚卸し・組織設定・Events再開の共通実装。"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from collect_access_review import CollectorError, SENSITIVE_ATTRIBUTE_NAME, parse_time
from collect_access_review import read_private_file
from pathlib import Path
from collect_access_review import CollectorError, parse_time
from collect_access_review import read_private_file, secure_write_json
from collections import Counter, defaultdict
from statistics import median
from typing import Any
from collect_access_review import (
    CollectorError, SENSITIVE_ATTRIBUTE_NAME, parse_time, safe_user,
    user_status_summary, utc_now, checked_event_types, checked_event, unlisted_event_types,
)


DEFAULT_POLICY = {"grant_burst_hours": 24, "grant_burst_minimum": 3,
                  "reactivation_min_inactive_days": 30, "known_patterns": [],
                  "event_type_states": {}}


def validate_policy(value):
    if not isinstance(value, dict) or set(value) - set(DEFAULT_POLICY):
        raise CollectorError("棚卸し設定の項目が不正です")
    policy = DEFAULT_POLICY | value
    for key in ("grant_burst_hours", "grant_burst_minimum", "reactivation_min_inactive_days"):
        if type(policy[key]) is not int or policy[key] <= 0:
            raise CollectorError("棚卸し設定の期間・件数は正の整数で指定してください")
    if policy["grant_burst_minimum"] < 2:
        raise CollectorError("集中付与の最小件数は2以上にしてください")
    patterns = policy["known_patterns"]
    if not isinstance(patterns, list):
        raise CollectorError("known_patternsは配列で指定してください")
    for pattern in patterns:
        if (not isinstance(pattern, dict) or set(pattern) - {"name", "group_ids", "attributes"}
                or not isinstance(pattern.get("name"), str) or not pattern["name"].strip()
                or not (pattern.get("group_ids") or pattern.get("attributes"))):
            raise CollectorError("既知パターンには名前とグループIDまたはカスタム属性条件が必要です")
        if (not isinstance(pattern.get("group_ids", []), list)
                or any(type(i) is not int or i <= 0 for i in pattern.get("group_ids", []))):
            raise CollectorError("既知パターンのgroup_idsは正の整数の配列にしてください")
        attrs = pattern.get("attributes", {})
        if (not isinstance(attrs, dict) or any(not isinstance(k, str) or SENSITIVE_ATTRIBUTE_NAME.search(k)
                or not isinstance(v, (str, int, bool)) for k, v in attrs.items())):
            raise CollectorError("既知パターンの属性条件に機密属性や複雑な値は指定できません")
    transitions = policy["event_type_states"]
    if not isinstance(transitions, dict):
        raise CollectorError("event_type_statesはイベント種別IDをキーにしたオブジェクトにしてください")
    for key, target in transitions.items():
        if (not str(key).isdigit() or not isinstance(target, dict) or not target
                or set(target) - {"status", "state"}):
            raise CollectorError("状態遷移設定にはイベント種別IDとstatus/stateだけを指定してください")
        for axis, value in target.items():
            if type(value) is not int or value not in ({0, 1, 2, 3, 4, 5, 7, 8} if axis == "status" else {0, 1, 2, 3}):
                raise CollectorError("状態遷移設定のstatus/stateが不正です")
    return policy


def load_policy(path=None):
    return validate_policy(read_private_file(path, json_only=True) if path else {})


def known_pattern_names(user, policy):
    result = []
    attrs = user.get("custom_attributes") or {}
    for p in policy["known_patterns"]:
        group_match = not p.get("group_ids") or user.get("group_id") in p["group_ids"]
        attr_match = all(k in attrs and attrs[k] == v for k, v in p.get("attributes", {}).items())
        if group_match and attr_match:
            result.append(p["name"])
    return result


def event_name(event, event_types):
    return str((event_types.get(event.get("event_type_id")) or {}).get("name") or "").lower()


def is_activation(event, event_types):
    name = event_name(event, event_types)
    return not any(x in name for x in ("failed", "失敗", "deactivat")) and any(
        x in name for x in ("reactivat", "re-enabl", "再有効", "再開"))


def historical_findings(events, event_types, policy, is_grant):
    """現在の状態を過去へ投影しない。状態の対応は管理者が確認した設定に限定。"""
    grouped = defaultdict(list)
    for event in events:
        dt = parse_time(event.get("created_at"))
        if dt is None:
            raise CollectorError("棚卸しイベントの日時が欠損または不正です")
        grouped[dt].append(event)
    status = state = None
    # statusとstateのどちらかで停止している連続期間を追跡する。
    # 軸ごとの開始日では、片方を復旧した時点で重なった停止期間を失う。
    inactive_since = None
    def inactive(status, state):
        if (status is not None and status != 1) or state == 3:
            return True
        if status == 1 and state is not None and state != 3:
            return False
        return None
    findings = {"grants": [], "unknown_grants": [], "reactivations": [], "unknown_activations": []}
    transitions = policy["event_type_states"]
    for dt, batch in sorted(grouped.items()):
        changes = [e for e in batch if str(e.get("event_type_id")) in transitions]
        # 同時刻の変更と付与の順番は分からないため、付与時点を確定しない。
        unknown_change = any(
            "user" in event_name(e, event_types) and any(t in event_name(e, event_types)
                for t in ("updat", "status", "state", "activat", "suspend", "password", "lock", "licens"))
            and str(e.get("event_type_id")) not in transitions for e in batch)
        uncertain = bool(changes) or unknown_change
        for event in batch:
            if is_grant(event, event_types):
                evidence = {"event_id": event.get("id"), "created_at": dt.isoformat(),
                            "status_at_grant": status, "state_at_grant": state}
                if not uncertain and ((status is not None and status != 1) or state == 3):
                    findings["grants"].append(evidence)
                elif uncertain or status is None or state is None:
                    findings["unknown_grants"].append(evidence)
        if len(changes) > 1 or unknown_change:
            # 同時刻の複数遷移は順序不明。後続の状態も推定しない。
            status = state = None
            inactive_since = None
            for e in changes:
                change = transitions[str(e["event_type_id"])]
                restoring = change.get("status") == 1 or ("state" in change and change["state"] != 3)
                if is_activation(e, event_types) or restoring:
                    findings["unknown_activations"].append({"event_id": e.get("id"), "created_at": dt.isoformat()})
        elif changes:
            change = transitions[str(changes[0]["event_type_id"])]
            was_inactive = inactive(status, state)
            for axis in change:
                if axis == "status": status = change[axis]
                else: state = change[axis]
            now_inactive = inactive(status, state)
            restored = now_inactive is False and was_inactive is True and inactive_since is not None
            if restored:
                duration = (dt - inactive_since).total_seconds() / 86400
                if duration >= policy["reactivation_min_inactive_days"]:
                    findings["reactivations"].append({"event_id": changes[0].get("id"),
                        "created_at": dt.isoformat(), "observed_inactive_days": round(duration, 2)})
            elif is_activation(changes[0], event_types) or (now_inactive is None and
                    (change.get("status") == 1 or ("state" in change and change["state"] != 3))):
                findings["unknown_activations"].append({"event_id": changes[0].get("id"), "created_at": dt.isoformat()})
            if now_inactive is True:
                if was_inactive is not True or inactive_since is None:
                    inactive_since = dt
            else:
                inactive_since = None
        for e in batch:
            if is_activation(e, event_types) and e not in changes:
                findings["unknown_activations"].append({"event_id": e.get("id"), "created_at": dt.isoformat()})
    return findings


def grant_burst(events, policy):
    times = sorted(parse_time(e["created_at"]) for e in events)
    left = best = 0
    interval = timedelta(hours=policy["grant_burst_hours"])
    for right, dt in enumerate(times):
        while dt - times[left] > interval:
            left += 1
        best = max(best, right - left + 1)
    return best if best >= policy["grant_burst_minimum"] else 0


def load_lifecycle(path, *, approved, kind, since, until):
    if not path:
        if kind: raise CollectorError("人事イベントの絞り込みには--lifecycle-fileが必要です")
        return {}
    if not approved:
        raise CollectorError("人事情報の利用には明示承認と--hr-data-approvedが必要です")
    payload = read_private_file(path, json_only=True)
    if not isinstance(payload, dict) or set(payload) != {"events"} or not isinstance(payload["events"], list):
        raise CollectorError("人事イベントJSONにはevents配列だけを指定してください")
    selected = defaultdict(set)
    for row in payload["events"]:
        if (not isinstance(row, dict) or set(row) != {"user_id", "kind", "occurred_at"}
                or type(row["user_id"]) is not int or row["user_id"] <= 0
                or row["kind"] not in ("joiner", "mover", "leaver")):
            raise CollectorError("人事イベントにはuser_id、kind、occurred_atだけを指定してください")
        dt = parse_time(row["occurred_at"])
        if dt is None: raise CollectorError("人事イベントの日時が不正です")
        if since <= dt <= until and (not kind or row["kind"] == kind):
            selected[row["user_id"]].add(row["kind"])
    return dict(selected)


def minimized_event(row):
    if (not isinstance(row, dict) or type(row.get("id")) is not int
            or type(row.get("event_type_id")) is not int or parse_time(row.get("created_at")) is None):
        raise CollectorError("棚卸しイベントのID・種別・日時が欠損または不正です")
    out = {k: row[k] for k in ("id", "event_type_id", "created_at")}
    for key in ("user_id", "app_id", "role_id", "group_id"):
        if row.get(key) is not None:
            if type(row[key]) is not int:
                raise CollectorError("棚卸しイベントの関連IDが不正です")
            out[key] = row[key]
    return out


def fetch_events(args, client, *, since, until):
    path = getattr(args, "event_checkpoint", None)
    resume = getattr(args, "resume_events", False)
    if not path:
        if resume: raise CollectorError("Eventsの再開には--event-checkpointが必要です")
        events, partial = client.list_events({"since": since, "until": until}, max_pages=args.max_event_pages)
        unique = {}
        for e in events:
            clean = minimized_event(e)
            if clean["id"] in unique and unique[clean["id"]] != clean:
                raise CollectorError("同じイベントIDの内容が変化しました")
            unique[clean["id"]] = clean
        return list(unique.values()), partial, since, until
    if resume:
        state = read_private_file(path, json_only=True)
        if (not isinstance(state, dict) or state.get("mode") != "inventory_checkpoint"
                or state.get("audit_id") != args.audit_context["audit_id"]
                or not isinstance(state.get("source"), dict) or state["source"].get("tenant") != client.base_url
                or state.get("days") != args.days):
            raise CollectorError("チェックポイントの監査ID・テナント・期間が一致しません")
        since, until = state.get("since"), state.get("until")
        if (parse_time(since) is None or parse_time(until) is None or parse_time(since) > parse_time(until)
                or type(state.get("complete")) is not bool or not isinstance(state.get("events"), list)
                or not isinstance(state.get("seen_cursors"), list)
                or any(not isinstance(c, str) or not c for c in state["seen_cursors"])
                or (not state["complete"] and state.get("next_cursor") is not None
                    and (not isinstance(state["next_cursor"], str) or not state["next_cursor"]))):
            raise CollectorError("チェックポイントの日時・ページ情報が不正です")
        # 保存済みイベントにも同じ検証を適用する。
        state["events"] = [minimized_event(e) for e in state["events"]]
        state.update(args.audit_context)
        secure_write_json(path, state, overwrite=True)
        if state["complete"]:
            return state["events"], False, since, until
    else:
        if Path(path).exists() or Path(path).is_symlink():
            raise CollectorError("チェックポイントが存在します。再開するか、新しい保存先を指定してください")
        state = {"mode": "inventory_checkpoint", **args.audit_context,
                 "source": {"tenant": client.base_url}, "days": args.days,
                 "since": since, "until": until, "complete": False,
                 "next_cursor": None, "seen_cursors": [], "events": []}
        secure_write_json(path, state)
    by_id = {e["id"]: e for e in state["events"]}
    def save_page(items, cursor, complete, seen):
        for item in items:
            clean = minimized_event(item)
            if clean["id"] in by_id and by_id[clean["id"]] != clean:
                raise CollectorError("同じイベントIDの内容が変化しました")
            by_id[clean["id"]] = clean
        state.update(events=list(by_id.values()), next_cursor=cursor, complete=complete, seen_cursors=sorted(seen))
        secure_write_json(path, state, overwrite=True)
    _, partial = client.list_events({"since": since, "until": until}, max_pages=args.max_event_pages,
        start_cursor=state["next_cursor"], seen_cursors=state["seen_cursors"], page_callback=save_page)
    return list(by_id.values()), partial, since, until


def checked_id(obj: dict[str, Any], context: str) -> int:
    try:
        return int(obj["id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CollectorError(f"{context}: 必須idが欠損または不正です") from exc


def event_is_grant(event: dict[str, Any], event_types: dict[int, dict[str, Any]]) -> bool:
    """イベント種別名から確実に読み取れる『付与』だけ。APIイベントの存在だけで推定しない。"""
    try:
        meta = event_types.get(int(event.get("event_type_id"))) or {}
    except (ValueError, TypeError):
        return False
    name = str(meta.get("name") or "").lower()
    positive = ("added", "assigned", "granted", "付与", "割当", "追加")
    negative = ("removed", "unassigned", "revoked", "削除", "解除", "failed", "失敗")
    entity = ("role", "application", "app", "group", "ロール", "アプリ", "グループ")
    return any(x in name for x in positive) and any(x in name for x in entity) and not any(x in name for x in negative)


def event_is_activation(event: dict[str, Any], event_types: dict[int, dict[str, Any]]) -> bool:
    try:
        name = str((event_types.get(int(event.get("event_type_id"))) or {}).get("name") or "").lower()
    except (ValueError, TypeError):
        return False
    return ("reactivat" in name or "re-enabl" in name or "再有効" in name or "再開" in name)


def bucket(priority: int) -> str:
    return "高" if priority >= 6 else "中" if priority >= 3 else "低"


def build_candidates(users: list[dict[str, Any]], apps: list[dict[str, Any]],
                     user_apps: dict[int, set[int]], user_roles: dict[int, set[int]],
                     role_apps: dict[int, set[int]], events: list[dict[str, Any]],
                     event_types: dict[int, dict[str, Any]], *, events_complete: bool,
                     high_impact_app_ids: set[int] | None = None,
                     privileged_group_ids: set[int] | None = None,
                     days: int = 365, now=None, scope_filter=None, policy=None, lifecycle=None) -> list[dict[str, Any]]:
    now = now or utc_now()
    policy = policy or load_policy()
    lifecycle = lifecycle or {}
    high_impact = high_impact_app_ids or set()
    privileged_groups = privileged_group_ids or set()
    user_by_id = {checked_id(u, "ユーザー"): u for u in users}
    recent_grants = defaultdict(list)
    user_events = defaultdict(list)
    for ev in events:
        uid = ev.get("user_id")
        if uid is None:
            continue
        try:
            uid = int(uid)
        except (TypeError, ValueError):
            continue
        dt = parse_time(ev.get("created_at"))
        if dt is None:
            raise CollectorError("棚卸しイベントの日時が欠損または不正です")
        if not now - timedelta(days=days) <= dt <= now:
            continue
        user_events[uid].append(ev)
        if event_is_grant(ev, event_types):
            recent_grants[uid].append(ev)
    cohorts = defaultdict(list)
    for uid, u in user_by_id.items():
        if u.get("department"):
            cohorts[str(u["department"])].append(uid)
    results = []
    for uid, user in user_by_id.items():
        if scope_filter and not scope_filter(uid, user, user_apps.get(uid, set())):
            continue
        held = user_apps.get(uid, set())
        roles = user_roles.get(uid, set())
        flags: list[dict[str, Any]] = []
        known_patterns = known_pattern_names(user, policy)
        known_dormant = bool(known_patterns) and (user_status_summary(user)["active"] is False or str(user.get("state")) == "3")
        suppressed = []
        def add(code, description, weight, evidence_status="complete", evidence=None):
            if known_dormant and code in {"never_logged_in", "long_no_login", "unexplained_assignment", "no_role_explanation", "role_department_outlier", "high_impact_app", "privileged_group"}:
                suppressed.append(code)
                return
            flags.append({"code": code, "reason": description, "priority_points": weight,
                          "evidence_status": evidence_status,
                          **({"evidence_sample": evidence[:10], "evidence_count": len(evidence)} if evidence else {})})
        state = user.get("state")
        status = user_status_summary(user)
        login = parse_time(user.get("last_login"))
        # 停止/Unlicensedと現在割当が存在することだけでは警告しない。
        if held and user.get("last_login", "missing") is None:
            add("never_logged_in", "OneLoginの最終ログイン記録がないがアプリ割り当てがある", 2)
        elif held and login and login < now - timedelta(days=180):
            add("long_no_login", "OneLoginの最終ログインから180日以上経過している", 2)
        if held and user.get("last_login", "missing") == "missing":
            # 未取得を未利用と解釈しない。
            pass
        if held and roles:
            explained = set().union(*(role_apps.get(rid, set()) for rid in roles))
            unmatched = held - explained
            if unmatched:
                add("unexplained_assignment", f"現在のRoleから説明できない割当が{len(unmatched)}件ある（直接付与とは断定しない）", 2)
        elif held and not roles:
            # APIによりRole割り当てが存在しないことが確認できている場合だけ。
            if uid in user_roles:
                add("no_role_explanation", "Roleで説明できないアプリ割り当てがある（直接付与とは断定しない）", 2)
        g = recent_grants.get(uid, [])
        history = historical_findings(user_events.get(uid, []), event_types, policy, event_is_grant)
        ev_coverage = "complete" if events_complete else "partial"
        if history["grants"]:
            add("grant_while_nonactive", "設定した状態遷移に基づき、非ActiveまたはUnlicensed中の付与を観測", 4,
                ev_coverage, history["grants"])
        if (status["active"] is False or str(state) == "3") and history["unknown_grants"]:
            add("grant_while_nonactive_candidate", "現在停止等のユーザーに付与イベントがあるが、付与当時の状態は未確認", 2,
                "partial", history["unknown_grants"])
        burst = grant_burst(g, policy)
        if burst:
            add("grant_burst", f"{policy['grant_burst_hours']}時間以内に権限付与イベントを最大{burst}件観測", 2, ev_coverage)
        if history["reactivations"]:
            add("reactivation_after_long_inactivity", "設定した状態遷移に基づき、長期非Active/Unlicensed後のActive化を観測", 4,
                ev_coverage, history["reactivations"])
        if history["unknown_activations"]:
            add("reactivation_event_candidate", "再有効化イベントを観測したが、直前状態または停止期間は未確認", 2,
                "partial", history["unknown_activations"])
        if uid in lifecycle:
            add("lifecycle_scope", "承認済み人事イベントで選択された対象（権限の異常を意味しない）: " + ",".join(sorted(lifecycle[uid])), 1)
        if high_impact & held:
            add("high_impact_app", "指定された重要アプリの割り当てがある", 2)
        try:
            gid = int(user.get("group_id")) if user.get("group_id") is not None else None
        except (TypeError, ValueError):
            gid = None
        if gid in privileged_groups:
            add("privileged_group", "指定された重要グループのメンバー", 2)
        dept = user.get("department")
        peers = [v for v in cohorts.get(str(dept), []) if v != uid] if dept else []
        if len(peers) >= 3:
            peer_roles = Counter(r for v in peers for r in user_roles.get(v, set()))
            unusual = [r for r in roles if peer_roles.get(r, 0) == 0]
            if unusual:
                add("role_department_outlier", f"同じ部署の比較対象{len(peers)}名が保有していないRoleを{len(unusual)}件保有", 2)
        if known_dormant and ({"high_impact_app", "privileged_group"} & set(suppressed)):
            add("known_pattern_privileged_reference", "運用上の既知パターンに該当。重要アプリ/グループは参考確認", 1)
        if not flags:
            continue
        score = sum(x["priority_points"] for x in flags)
        out_user = safe_user(user)
        # AIへ渡すのは優先確認候補の最小限だけ。機密属性・コメント・生イベントは出力しない。
        results.append({"user": {k: out_user.get(k) for k in ("id", "email", "firstname", "lastname", "department", "title", "status", "state") if k in out_user},
                        "priority": bucket(score), "priority_points": score,
                        "flags": flags, "known_patterns": known_patterns, "suppressed_static_flags": suppressed, "assigned_app_count": len(held),
                        "role_count": len(roles), "status": status["status_name"],
                        "app_id_sample": sorted(held)[:10],
                        "coverage": {"status": "partial" if not events_complete else "complete",
                                     "reason": "履歴の取得またはユーザーへの対応付けが不完全なため、未検出を正常とは扱えません" if not events_complete else None,
                                     "user_status": status["coverage"]}})
    return sorted(results, key=lambda r: (-r["priority_points"], r["user"]["id"]))




# 一次棚卸しの属性比較は、Role/Eventsを取得せず、割当データと属性だけで行う。
# 名称から業務上の意味が比較的明確なShortnameのみ、自動で部署/職種の代替候補とする。
PEER_DEPARTMENT_ALIASES = ("department", "google_department", "dept", "org_department", "custom_department")
PEER_TITLE_ALIASES = ("job_title", "jobtitle", "title", "job_position")
PEER_LIST_FIELDS = (
    "id", "department", "title", "group_id", "manager_user_id", "custom_attributes",
)


def _peer_text(value):
    if value is None or isinstance(value, (dict, list, tuple, set, bool)):
        return None
    text = str(value).strip()
    return text if text else None


def _peer_alias(allowed, names, explicit=None):
    if explicit:
        if explicit not in allowed or SENSITIVE_ATTRIBUTE_NAME.search(explicit):
            raise CollectorError("比較に指定されたカスタム属性が利用承認範囲にありません")
        return explicit
    choices = {a.casefold().replace("-", "_"): a for a in sorted(allowed)}
    for name in names:
        if name in choices:
            return choices[name]
    return None


def _safe_merge_attribute_fields(existing, incoming, allowed_custom):
    """APIの追加応答は最小限の許可属性だけに縮約し、取得済みのログイン情報などを失わない。"""
    clean = safe_user(incoming, allowed_custom)
    for key in ("department", "title", "group_id", "manager_user_id"):
        if key in clean and (key not in existing or not _peer_text(existing.get(key))):
            existing[key] = clean[key]
    if clean.get("custom_attributes"):
        attrs = existing.setdefault("custom_attributes", {})
        for key, value in clean["custom_attributes"].items():
            if key not in attrs or not _peer_text(attrs[key]):
                attrs[key] = value


def enrich_inventory_users(args, client, raw_users, allowed_custom, peer_custom_keys):
    """最初は一覧のfields指定、足りなければ件数上限を守って個別GET。

    個別GETが必要な人数が上限を超える場合はバイアスのある部分標本を作らず、
    比較を未実施とする。取得エラーは欠損と区別する。
    """
    by_id = {checked_id(row, "ユーザー"): safe_user(row, allowed_custom) for row in raw_users}
    if len(by_id) != len(raw_users):
        raise CollectorError("ユーザー一覧に重複したIDがあります")
    details = {"list_fields_attempted": False, "list_fields_used": False,
               "individual_requests": 0, "individual_failed": 0,
               "enrichment_limit": args.max_attribute_users, "warnings": []}
    def needs_detail(u):
        # None/空文字は「値なし」、キーそのものの欠落は「一覧で未取得」と区別する。
        if "department" not in u or "title" not in u:
            return True
        if getattr(args, "manager", None) and "manager_user_id" not in u:
            return True
        attrs = u.get("custom_attributes") or {}
        for standard, shortname in peer_custom_keys.items():
            if (shortname and not _peer_text(u.get(standard))
                    and shortname not in attrs):
                return True
        return False
    missing = {uid for uid, u in by_id.items() if needs_detail(u)}
    if missing:
        details["list_fields_attempted"] = True
        try:
            # 一覧はフィールド絞り込みが可能。既存のユーザー属性は失わないようIDでマージする。
            # カスタム属性は承認済みの項目だけを保持する。
            fields = ",".join(v for v in PEER_LIST_FIELDS
                              if v != "custom_attributes" or any(peer_custom_keys.values()))
            rows = client.list_page("/api/2/users", params={"fields": fields}, limit=50)
            ids = {checked_id(row, "属性付きユーザー一覧") for row in rows}
            if ids != set(by_id) or len(rows) != len(by_id):
                details["warnings"].append("属性付きユーザー一覧のIDが一致せず、個別取得に切り替えました")
            else:
                for row in rows:
                    _safe_merge_attribute_fields(by_id[row["id"]], row, allowed_custom)
                details["list_fields_used"] = True
        except CollectorError as exc:
            if "HTTP 401" in str(exc) or "HTTP 403" in str(exc):
                raise
            details["warnings"].append("一覧の属性指定を利用できなかったため、必要な範囲で個別取得を試みました")
    missing = [uid for uid in sorted(by_id) if needs_detail(by_id[uid])]
    # 一覧が属性キーを返しても全員nullなら、個別APIでは値がある可能性を排除できない。
    # 上限内でのみ詳細取得して確認する。比較しないまま正常完了と見なさない。
    all_profiles_blank = not any(
        _peer_text(u.get("department")) or _peer_text(u.get("title"))
        or any(_peer_text((u.get("custom_attributes") or {}).get(a))
               for a in peer_custom_keys.values() if a)
        for u in by_id.values()
    )
    if all_profiles_blank:
        missing = sorted(by_id)
    if len(missing) > args.max_attribute_users:
        details["limited"] = True
        details["warnings"].append(
            f"属性補完が必要な{len(missing)}名は個別取得上限{args.max_attribute_users}名を超えるため、属性比較は一部または未実施です")
    else:
        details["limited"] = False
        for uid in missing:
            details["individual_requests"] += 1
            try:
                payload, _ = client.get(f"/api/2/users/{uid}")
                if not isinstance(payload, dict) or type(payload.get("id")) is not int or payload["id"] != uid:
                    raise CollectorError("個別ユーザー取得のIDが不正です")
                _safe_merge_attribute_fields(by_id[uid], payload, allowed_custom)
            except CollectorError as exc:
                if "HTTP 401" in str(exc) or "HTTP 403" in str(exc):
                    raise
                details["individual_failed"] += 1
                if "HTTP 429" in str(exc):
                    details["warnings"].append("APIレート制限により個別属性取得を中断しました")
                    break
        if details["individual_failed"]:
            details["warnings"].append(f"{details['individual_failed']}名の属性補完に失敗しました。比較率は部分的です")
    return list(by_id.values()), details


def _peer_profiles(users, department_custom, title_custom):
    profiles = {}
    for user in users:
        dep = _peer_text(user.get("department"))
        title = _peer_text(user.get("title"))
        attrs = user.get("custom_attributes") or {}
        dep_origin = "department" if dep else None
        title_origin = "title" if title else None
        if not dep and department_custom:
            dep = _peer_text(attrs.get(department_custom))
            if dep:
                dep_origin = "custom:" + department_custom
        if not title and title_custom:
            title = _peer_text(attrs.get(title_custom))
            if title:
                title_origin = "custom:" + title_custom
        group = _peer_text(user.get("group_id"))
        profiles[user["id"]] = {"department": dep.casefold() if dep else None,
                                "title": title.casefold() if title else None,
                                "group_id": group, "department_source": dep_origin,
                                "title_source": title_origin}
    return profiles


def _peer_cohort_lookup(profiles, *, group_fallback):
    cohorts = defaultdict(set)
    for uid, p in profiles.items():
        dep, title = p["department"], p["title"]
        if dep and title:
            cohorts[("department+title", dep, title)].add(uid)
        if dep:
            cohorts[("department", dep)].add(uid)
        if title:
            cohorts[("title", title)].add(uid)
        if group_fallback and p["group_id"]:
            cohorts[("group_id", p["group_id"])].add(uid)
    return cohorts


def _peer_cohort_for(uid, profiles, cohorts, min_peers):
    p = profiles[uid]
    dep, title, group = p["department"], p["title"], p["group_id"]
    order = []
    if dep and title:
        order.append(("department+title", dep, title))
    if dep:
        order.append(("department", dep))
    if title:
        order.append(("title", title))
    if group:
        order.append(("group_id", group))
    for key in order:
        # Group比較はオプトイン時にしかcohortsに存在しない。
        members = cohorts.get(key, set())
        if len(members) - 1 >= min_peers:
            return key, members
    return None, set()


def collect_lightweight_inventory(args, client) -> dict[str, Any]:
    """一次棚卸し。部署・職種などのアプリ保有率を主軸に外れ値を候補化する。"""
    now = utc_now()
    policy = load_policy(getattr(args, "inventory_policy", None))
    if (policy["event_type_states"] or getattr(args, "event_checkpoint", None)
            or getattr(args, "resume_events", False)
            or getattr(args, "lifecycle_file", None)
            or getattr(args, "lifecycle_kind", None)):
        raise CollectorError("状態遷移・Events再開・人事イベントの条件を使う場合は--inventory-depth extendedを指定してください")
    if (args.min_peer_users < 3 or args.max_peer_app_rate < 0 or args.max_peer_app_rate > 1
            or args.max_attribute_users < 0):
        raise CollectorError("比較人数・保有率・属性取得の上限値が不正です")
    raw_users = client.list_page("/api/2/users", limit=50)
    allowed_custom = set(getattr(args, "allowed_custom_fields", []) or [])
    referenced_custom = {str(k) for pattern in policy["known_patterns"] for k in pattern.get("attributes", {})}
    if referenced_custom - allowed_custom:
        raise CollectorError("棚卸しポリシーが除外・未承認のカスタム属性を参照しています")
    department_custom = _peer_alias(allowed_custom, PEER_DEPARTMENT_ALIASES,
                                    getattr(args, "peer_custom_department", None))
    title_custom = _peer_alias(allowed_custom, PEER_TITLE_ALIASES,
                               getattr(args, "peer_custom_title", None))
    peer_custom_keys = {"department": department_custom, "title": title_custom}
    users, attr_collection = enrich_inventory_users(args, client, raw_users, allowed_custom, peer_custom_keys)

    apps = client.list_page("/api/2/apps", limit=1000)
    app_by_id = {checked_id(a, "アプリ"): a for a in apps}
    app_by_name = {str(a.get("name") or "").casefold(): checked_id(a, "アプリ") for a in apps}
    def resolve_app_ids(names, kind):
        ids = set()
        for n in names or []:
            aid = int(n) if str(n).isdigit() else app_by_name.get(str(n).casefold())
            if aid not in app_by_id:
                raise CollectorError(f"{kind}がテナントのアプリ一覧に見つかりません: {n}")
            ids.add(aid)
        return ids
    selected = resolve_app_ids(getattr(args, "app", None), "対象アプリ")
    high_impact = resolve_app_ids(getattr(args, "high_impact_app", None), "重要アプリ")
    privileged_groups = set()
    for raw in getattr(args, "privileged_group", None) or []:
        if not str(raw).isdigit():
            raise CollectorError("--privileged-groupはOneLoginグループIDを指定してください")
        privileged_groups.add(int(raw))

    profiles = _peer_profiles(users, department_custom, title_custom)
    by_id = {u["id"]: u for u in users}
    if args.department and any(not profiles[u["id"]]["department"] for u in users):
        raise CollectorError("部署が未取得のユーザーがいます。完全な部署絞り込みとして扱えません")
    if args.manager and any("manager_user_id" not in u for u in users):
        raise CollectorError("上長が未取得のユーザーがいます。完全な上長絞り込みとして扱えません")

    # アプリ指定時は対象アプリだけを照会する。Role/Eventsは収集しない。
    scanned_app_ids = sorted(selected if selected else app_by_id)
    user_apps = defaultdict(set)
    for aid in scanned_app_ids:
        for app_user in client.list_page(f"/api/2/apps/{aid}/users", limit=1000):
            if app_user.get("assigned") is False:
                continue
            user_apps[checked_id(app_user, f"アプリ{aid}の利用者")].add(aid)
    unmatched_app_users = set(user_apps) - set(by_id)

    cohort_lookup = _peer_cohort_lookup(profiles, group_fallback=args.peer_group_fallback)
    cohort_app_counts = {}
    for key, members in cohort_lookup.items():
        cohort_app_counts[key] = Counter(aid for uid in members for aid in user_apps.get(uid, set()))
    peer_eligible = {uid: _peer_cohort_for(uid, profiles, cohort_lookup, args.min_peer_users)
                     for uid in by_id}
    # 属性が個別取得上限により補完されなかった場合やAPI取得失敗時は、既知分のみの参考値とする。
    missing_attribute_data = attr_collection["limited"] or attr_collection["individual_failed"] > 0
    candidates = []
    attribute_candidates = 0
    comparisons_possible = 0
    candidate_reason_users = defaultdict(set)
    for uid, user in by_id.items():
        held = user_apps.get(uid, set())
        if selected and not selected.intersection(held):
            continue
        if args.department and profiles[uid]["department"] != str(args.department).strip().casefold():
            continue
        if args.manager and str(user.get("manager_user_id")) != str(args.manager):
            continue
        try:
            group_id = int(user.get("group_id")) if user.get("group_id") is not None else None
        except (ValueError, TypeError):
            group_id = None
        if not held and not (privileged_groups and group_id in privileged_groups):
            continue
        patterns = known_pattern_names(user, policy)
        state = user_status_summary(user)
        dormant = bool(patterns) and (state["active"] is False or user.get("state") == 3)
        flags, suppressed = [], []
        def add(code, reason, weight, *, evidence="complete"):
            if dormant and code in {"never_logged_in", "long_no_login", "peer_app_outlier",
                                    "peer_app_count_outlier", "high_impact_app", "privileged_group"}:
                suppressed.append(code)
                return
            flags.append({"code": code, "reason": reason, "priority_points": weight,
                          "evidence_status": evidence})
            candidate_reason_users[code].add(uid)
        key, members = peer_eligible[uid]
        if key and held:
            comparisons_possible += 1
            denom = len(members) - 1
            app_counter = cohort_app_counts[key]
            outlier_apps = [(aid, (app_counter[aid] - 1) / denom) for aid in held
                            if (app_counter[aid] - 1) / denom <= args.max_peer_app_rate]
            if outlier_apps:
                # 属性補完に失敗した場合は参考候補に留める。
                top = sorted(outlier_apps, key=lambda x: (x[1], x[0]))[:3]
                sample = "、".join(str(app_by_id[aid].get("name") or aid) for aid, _ in top)
                sample += "ほか" if len(outlier_apps) > 3 else ""
                comparison_label = {"department+title": "部署・職種", "department": "部署",
                                    "title": "職種", "group_id": "Group"}[key[0]]
                note = f"{comparison_label}の他{denom}名との比較で、保有率{args.max_peer_app_rate * 100:g}%以下のアプリが{len(outlier_apps)}件（{sample}）"
                if key[0] == "group_id":
                    note += "。Groupの業務上の同質性は要確認"
                add("peer_app_outlier", note, 1 if missing_attribute_data else 4,
                    evidence="partial" if missing_attribute_data else "complete")
            # アプリを絞っている場合は、全アプリ数による偏りは計算できない。
            peer_counts = [len(user_apps.get(peer, set())) for peer in members if peer != uid]
            center = median(peer_counts)
            if not selected and len(held) >= max(center + 5, center * 2 + 1):
                add("peer_app_count_outlier",
                    f"同属性の他{denom}名の割当アプリ数の中央値{center:g}件に対し、本人は{len(held)}件",
                    1 if missing_attribute_data else 3,
                    evidence="partial" if missing_attribute_data else "complete")
        if held and "last_login" in user:
            if user["last_login"] is None:
                add("never_logged_in", "OneLoginの最終ログイン記録がない", 1)
            else:
                dt = parse_time(user["last_login"])
                if dt is not None and dt < now - timedelta(days=180):
                    add("long_no_login", "OneLoginの最終ログインから180日以上経過", 1)
        if high_impact & held:
            add("high_impact_app", "指定された重要アプリの割り当てがある", 1)
        if privileged_groups and group_id in privileged_groups:
            add("privileged_group", "指定された重要グループに所属している", 1)
        if not flags:
            continue
        if any(f["code"] in ("peer_app_outlier", "peer_app_count_outlier") for f in flags):
            attribute_candidates += 1
        points = sum(flag["priority_points"] for flag in flags)
        entry = safe_user(user)
        candidates.append({"user": {field: entry[field] for field in
                                    ("id", "email", "firstname", "lastname", "department", "title", "status", "state")
                                    if field in entry},
                           "priority": bucket(points), "priority_points": points,
                           "flags": flags, "known_patterns": patterns,
                           "suppressed_static_flags": suppressed,
                           "assigned_app_count": len(held),
                           "app_id_sample": sorted(held)[:10],
                           "status": state["status_name"],
                           "peer_comparison": {"basis": key[0] if key else None,
                                               "comparison_users": len(members) - 1 if key else 0,
                                               "status": "partial" if key and missing_attribute_data
                                               else "complete" if key else "unavailable"},
                           "coverage": {"status": "partial", "reason": "Role・Events・アプリ利用履歴は未収集",
                                        "user_status": state["coverage"]}})
    candidates.sort(key=lambda c: (-c["priority_points"], c["user"]["id"]))
    status_missing = sum(user_status_summary(u)["active"] is None for u in users)
    login_missing = sum("last_login" not in u or (u["last_login"] is not None and parse_time(u["last_login"]) is None) for u in users)
    population_with_app = {uid for uid in by_id if user_apps.get(uid)}
    cohort_comparable = sum(bool(peer_eligible[uid][0]) for uid in population_with_app)
    attributes_assessed = sum(1 for uid in population_with_app if peer_eligible[uid][0])
    coverage_status = ("unavailable" if not attributes_assessed else
                       "partial" if missing_attribute_data or attributes_assessed < len(population_with_app)
                       else "complete")
    coverage_reason = ("一部属性の追加取得が完了していません" if missing_attribute_data else
                       f"アプリ割当ユーザー{len(population_with_app)}名中{attributes_assessed}名のみ有効な同属性比較集団があります"
                       if attributes_assessed < len(population_with_app) else None)
    warnings = ["一次抽出のみ。Role・Events・アプリ別利用履歴は未取得で、候補外も問題なしを保証しません"]
    if selected:
        warnings.append("アプリ指定のため割り当て照会は対象アプリのみです")
    if unmatched_app_users:
        warnings.append(f"{len(unmatched_app_users)}名の割り当てユーザーをユーザー一覧に対応付けられません")
    if status_missing:
        warnings.append(f"{status_missing}名のユーザー状態を確認できません")
    if login_missing:
        warnings.append(f"{login_missing}名のlast_loginが未取得または不正です")
    if coverage_status != "complete":
        warnings.append("属性比較が未実施または一部のみです。外れ値0件とは断定できません")
    warnings.extend(attr_collection["warnings"])
    attribute_sources = {"department": department_custom, "title": title_custom}
    return {"schema_version": "2.2", "mode": "inventory", "generated_at": now.isoformat(),
            "source": {"tenant": client.base_url, "read_only": True, "credential_scope_expected": "Read All",
                       "inventory_depth": "basic", "collection_status": "partial",
                       "coverage": {"users": {"status": "complete"},
                                    "apps": {"status": "complete" if not selected else "partial", "apps_assessed": len(scanned_app_ids)},
                                    "app_assignments": {"status": "complete" if not selected and not unmatched_app_users else "partial",
                                                        "apps_queried": len(scanned_app_ids),
                                                        "unmatched_user_count": len(unmatched_app_users)},
                                    "peer_comparison": {"status": coverage_status, "reason": coverage_reason,
                                                        "users_with_assignments": len(population_with_app),
                                                        "comparable_users": attributes_assessed,
                                                        "minimum_peers": args.min_peer_users,
                                                        "max_peer_app_rate": args.max_peer_app_rate,
                                                        "department_present": sum(bool(p["department"]) for p in profiles.values()),
                                                        "title_present": sum(bool(p["title"]) for p in profiles.values()),
                                                        "group_fallback_enabled": args.peer_group_fallback,
                                                        "custom_attribute_sources": attribute_sources,
                                                        "attribute_api": attr_collection},
                                    "roles": {"status": "unavailable", "reason": "軽量モードで未取得"},
                                    "events": {"status": "unavailable", "reason": "軽量モードで未取得"},
                                    "usage_history": {"status": "unavailable", "reason": "軽量モードで未取得"},
                                    "user_status": {"status": "partial" if status_missing else "complete", "missing_count": status_missing},
                                    "last_login": {"status": "partial" if login_missing else "complete", "missing_count": login_missing}},
                       "scope": {"apps": args.app or [], "department": args.department, "manager": args.manager},
                       "candidate_detection_basis": ["last_login", "app_assignments", "peer_app_outlier",
                                                     "peer_app_count_outlier", "explicit_high_impact_settings"],
                       "warnings": warnings},
            "summary": {"users_scanned": len(users), "apps_scanned": len(scanned_app_ids),
                        "apps_in_tenant": len(apps), "app_user_queries": len(scanned_app_ids),
                        "observed_app_user_assignments": sum(len(ids) for uid, ids in user_apps.items() if uid in by_id),
                        "roles_scanned": None, "events_observed": None,
                        "candidates": len(candidates), "attribute_candidates": attribute_candidates,
                        "login_candidates": len(candidate_reason_users["never_logged_in"] | candidate_reason_users["long_no_login"]),
                        "comparison_possible_users": comparisons_possible,
                        "unflagged_users_not_verified_normal": max(0, len(users) - len(candidates))},
            "candidates": candidates}

def collect_inventory(args, client) -> dict[str, Any]:
    if getattr(args, "inventory_depth", "basic") == "basic":
        return collect_lightweight_inventory(args, client)
    now = utc_now()
    policy = load_policy(getattr(args, "inventory_policy", None))
    # User Listに存在しないdepartment/role_idsは未取得扱い。追加の個別APIを大量には呼ばない。
    raw_users = client.list_page("/api/2/users", limit=50)
    # 利用者が承認したShortnameだけを候補判定へ渡す。除外属性は内部判定にも使わない。
    allowed_custom = set(getattr(args, "allowed_custom_fields", []) or [])
    users = [safe_user(u, allowed_custom) for u in raw_users]
    referenced_custom = {str(name) for pattern in policy["known_patterns"] for name in pattern.get("attributes", {})}
    if referenced_custom - allowed_custom:
        raise CollectorError("棚卸しポリシーが除外・未承認のカスタム属性を参照しています。設定を変更してください")
    apps = [{"id": a.get("id"), "name": a.get("name")} for a in client.list_page("/api/2/apps", limit=1000)]
    roles = [{"id": r.get("id"), "name": r.get("name")} for r in client.list_page("/api/2/roles", limit=650)]
    # 全ユーザー×アプリの照会は避け、アプリ/Roleごとの一覧で割当を反転インデックス化。
    user_apps: dict[int, set[int]] = defaultdict(set)
    for a in apps:
        aid = checked_id(a, "アプリ")
        for u in client.list_page(f"/api/2/apps/{aid}/users", limit=1000):
            user_apps[checked_id(u, f"アプリ{aid}の利用者")].add(aid)
    user_roles: dict[int, set[int]] = defaultdict(set)
    role_apps: dict[int, set[int]] = {}
    for r in roles:
        rid = checked_id(r, "Role")
        assigned_users = client.list_page(f"/api/2/roles/{rid}/users", limit=650)
        for u in assigned_users:
            if u.get("assigned") is False:
                continue
            user_roles[checked_id(u, f"Role{rid}のユーザー")].add(rid)
        role_apps[rid] = {checked_id(a, f"Role{rid}のアプリ") for a in client.list_page(f"/api/2/roles/{rid}/apps", limit=200)}
    # 調査対象にRoleのないユーザーも確実に空集合として初期化。
    for u in users:
        user_roles.setdefault(checked_id(u, "ユーザー"), set())
    type_payload, _ = client.get("/api/2/events/types")
    event_types = checked_event_types(type_payload)
    if any(int(key) not in event_types for key in policy["event_type_states"]):
        raise CollectorError("状態遷移設定のイベント種別IDがテナントのカタログにありません")
    since = (now - timedelta(days=args.days)).isoformat().replace("+00:00", "Z")
    events, truncated, since, until = fetch_events(args, client, since=since, until=now.isoformat())
    for event in events:
        checked_event(event, event_types)
    unlisted = unlisted_event_types(events, event_types)
    event_until = parse_time(until)
    known_user_ids = {checked_id(u, "ユーザー") for u in users}
    # テナント全体のイベントにはユーザーを持たない種別もある。
    # 監査に必要な付与・ログイン・状態変更だけ、帰属不能を取得制約とする。
    unattributed_events = [e for e in events
        if (event_is_grant(e, event_types) or event_is_activation(e, event_types)
            or e.get("event_type_id") == 8 or str(e.get("event_type_id")) in policy["event_type_states"])
        and (type(e.get("user_id")) is not int or e["user_id"] not in known_user_ids)]
    events_incomplete = truncated or bool(unattributed_events) or bool(unlisted["unlisted_event_count"])
    event_reasons = (["指定ページ数で取得を打ち切り"] if truncated else []) + (
        [f"監査対象の履歴{len(unattributed_events)}件を現在のユーザーへ対応付けられません"] if unattributed_events else []) + (
        [f"イベント種別カタログに未掲載の履歴が{unlisted['unlisted_event_count']}件あります"] if unlisted["unlisted_event_count"] else [])
    lifecycle = load_lifecycle(getattr(args, "lifecycle_file", None), approved=getattr(args, "hr_data_approved", False),
        kind=getattr(args, "lifecycle_kind", None), since=parse_time(since), until=event_until)
    app_ids_by_name = {str(a.get("name") or "").lower(): checked_id(a, "アプリ") for a in apps}
    known_app_ids = {checked_id(a, "アプリ") for a in apps}
    selected_ids = set()
    for name in args.app or []:
        if str(name).isdigit():
            if int(name) not in known_app_ids:
                raise CollectorError("対象アプリIDがテナントの一覧に存在しません")
            selected_ids.add(int(name))
        elif name.lower() in app_ids_by_name:
            selected_ids.add(app_ids_by_name[name.lower()])
        else:
            raise CollectorError(f"対象アプリが見つかりません: {name}")
    high_impact = set()
    for name in args.high_impact_app or []:
        if str(name).isdigit():
            if int(name) not in known_app_ids:
                raise CollectorError("重要アプリIDがテナントの一覧に存在しません")
            high_impact.add(int(name))
        elif name.lower() in app_ids_by_name:
            high_impact.add(app_ids_by_name[name.lower()])
        else:
            raise CollectorError(f"重要アプリが見つかりません: {name}")
    privileged_groups = set()
    for raw in args.privileged_group or []:
        if not str(raw).isdigit():
            raise CollectorError("--privileged-groupはOneLoginグループIDを指定してください")
        privileged_groups.add(int(raw))
    def scope_filter(uid, u, held):
        if getattr(args, "lifecycle_file", None) and uid not in lifecycle:
            return False
        if selected_ids and not selected_ids.intersection(held):
            return False
        if args.department and str(u.get("department") or "") != args.department:
            return False
        if args.manager and str(u.get("manager_user_id") or "") != args.manager:
            return False
        return True
    if args.department and any(u.get("department") is None for u in users):
        raise CollectorError("一部または全ユーザーの部署が不明です。完全な部署絞り込みとして0件とは扱いません")
    if args.manager and any("manager_user_id" not in u for u in users):
        raise CollectorError("一部または全ユーザーの上長が未取得です。完全な上長絞り込みとして0件とは扱いません")
    user_status_missing = sum(1 for u in users if user_status_summary(u)["active"] is None)
    user_state_missing = sum(1 for u in users if type(u.get("state")) is not int or u["state"] not in (0, 1, 2, 3))
    user_last_login_missing = sum(1 for u in users if "last_login" not in u
        or (u["last_login"] is not None and parse_time(u["last_login"]) is None))
    department_missing = sum(1 for u in users if u.get("department") is None)
    candidates = build_candidates(users, apps, user_apps, user_roles, role_apps, events, event_types,
                                  events_complete=not events_incomplete, high_impact_app_ids=high_impact,
                                  privileged_group_ids=privileged_groups,
                                  days=args.days, now=event_until, scope_filter=scope_filter, policy=policy, lifecycle=lifecycle)
    # 未監査=正常を意味しない。候補のみAIへ渡す。全体件数を付す。
    return {"schema_version": "2.1", "mode": "inventory", "generated_at": now.isoformat(),
            "source": {"tenant": client.base_url, "read_only": True, "credential_scope_expected": "Read All",
                       "analysis_window_days": args.days, "events_since": since, "events_until": until,
                       "rules": {k: policy[k] for k in ("grant_burst_hours", "grant_burst_minimum", "reactivation_min_inactive_days")},
                       "historical_state_basis": "configured_event_type_states" if policy["event_type_states"] else "unavailable",
                       "scope": {"apps": args.app or [], "department": args.department, "manager": args.manager,
                                 "lifecycle_kind": getattr(args, "lifecycle_kind", None)},
                       "collection_status": "partial" if events_incomplete or user_status_missing or user_state_missing or user_last_login_missing or department_missing else "complete",
                       "coverage": {"users": {"status": "complete", "reason": None},
                                    "apps": {"status": "complete", "reason": None},
                                    "roles": {"status": "complete", "reason": None},
                                    "events": {"status": "partial" if events_incomplete else "complete", "reason": " / ".join(event_reasons) or None,
                                               "unattributed_event_count": len(unattributed_events)},
                                    "event_types": unlisted,
                                    "department": {"status": "complete" if all(u.get("department") is not None for u in users) else "partial" if any(u.get("department") is not None for u in users) else "unavailable", "reason": "一部または全ユーザーの部署が取得できません" if not all(u.get("department") is not None for u in users) else None},
                                    "user_status": {"status": "partial" if user_status_missing else "complete", "reason": f"{user_status_missing}名のstatusが不明" if user_status_missing else None},
                                    "user_state": {"status": "partial" if user_state_missing else "complete", "reason": f"{user_state_missing}名のstateが不明" if user_state_missing else None},
                                    "last_login": {"status": "partial" if user_last_login_missing else "complete", "reason": f"{user_last_login_missing}名はlast_login項目が欠損" if user_last_login_missing else None}},
                       "warnings": (["イベント取得が途中で打ち切られました。付与・利用履歴について未検出を正常と見なさないでください"] if truncated else [])
                                  + ([f"{len(unattributed_events)}件の監査対象履歴をユーザーへ対応付けられません。未検出を正常と扱わないでください"] if unattributed_events else [])
                                  + ([f"{user_status_missing}名のstatusが不明です"] if user_status_missing else [])
                                  + ([f"{user_state_missing}名のstateが不明です"] if user_state_missing else [])
                                  + ([f"{department_missing}名の部署が不明です"] if department_missing else [])
                                  + ([f"{user_last_login_missing}名のlast_loginが欠損しています"] if user_last_login_missing else [])
                                  + ([f"未掲載のイベント種別ID: {', '.join(map(str, unlisted['unlisted_event_type_ids']))}。該当する変更履歴の解釈は未確定です"] if unlisted["unlisted_event_count"] else [])},
            "summary": {"users_scanned": len(users), "apps_scanned": len(apps), "roles_scanned": len(roles),
                        "events_observed": len(events), "unattributed_event_count": len(unattributed_events),
                        "unlisted_event_count": unlisted["unlisted_event_count"], "candidates": len(candidates),
                        "known_pattern_users": sum(bool(known_pattern_names(u, policy)) for u in users),
                        "lifecycle_selected_users": len(lifecycle),
                        "unflagged_users_not_verified_normal": max(0,len(users) - len(candidates))},
            "candidates": candidates}
