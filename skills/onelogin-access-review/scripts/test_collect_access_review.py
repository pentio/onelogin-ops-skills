#!/usr/bin/env python3
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import collect_access_review as c


class 収集処理ユーティリティテスト(unittest.TestCase):
    def test_ベースURL正規化(self):
        self.assertEqual(c.normalize_base_url("example.onelogin.com"), "https://example.onelogin.com")
        self.assertEqual(c.normalize_base_url("https://EXAMPLE.onelogin.com/"), "https://example.onelogin.com")
        with self.assertRaises(c.CollectorError):
            c.normalize_base_url("http://example.onelogin.com")
        with self.assertRaises(c.CollectorError):
            c.normalize_base_url("https://example.com")

    def test_Peer候補は具体的属性を優先(self):
        target = {"id": 1, "department": "営業", "title": "SE", "group_id": 9, "company": "A"}
        users = [
            target,
            {"id": 2, "department": "営業", "title": "SE", "group_id": 9, "company": "A"},
            {"id": 3, "department": "営業", "title": "AE", "group_id": 9, "company": "A"},
            {"id": 4, "department": "開発", "title": "SE", "group_id": 8, "company": "A"},
        ]
        cohorts = c.build_peer_cohorts(target, users)
        by_key = {x["key"]: x for x in cohorts}
        self.assertEqual(by_key["department+title"]["size"], 1)
        self.assertEqual(by_key["department"]["size"], 2)
        self.assertEqual(by_key["title"]["size"], 2)

    def test_利用期間集計は累積(self):
        now = datetime(2026, 10, 13, tzinfo=timezone.utc)
        times = [
            datetime(2026, 10, 12, tzinfo=timezone.utc),
            datetime(2026, 9, 1, tzinfo=timezone.utc),
            datetime(2026, 6, 1, tzinfo=timezone.utc),
            datetime(2026, 1, 1, tzinfo=timezone.utc),
        ]
        out = c.summarize_times(times, now)
        self.assertEqual(out["counts"]["30"], 1)
        self.assertEqual(out["counts"]["90"], 2)
        self.assertEqual(out["counts"]["180"], 3)
        self.assertEqual(out["counts"]["365"], 4)

    def test_Roleで説明できない割当を直接割当と断定しない(self):
        roles = [
            {"id": 10, "name": "開発Role", "apps": [{"id": 100, "name": "GitHub"}]},
        ]
        explained = c.role_assignment_for_app(100, roles)
        unexplained = c.role_assignment_for_app(200, roles)
        self.assertTrue(explained["explained_by_current_role"])
        self.assertFalse(explained["unexplained_by_current_roles"])
        self.assertFalse(unexplained["explained_by_current_role"])
        self.assertTrue(unexplained["unexplained_by_current_roles"])
        self.assertNotIn("direct", unexplained)

    def test_非Activeステータスを要確認とする(self):
        self.assertEqual(c.user_status_summary({"status": 1})["status_name"], "有効（Active）")
        self.assertFalse(c.user_status_summary({"status": 1})["requires_user_review"])
        suspended = c.user_status_summary({"status": 2})
        self.assertEqual(suspended["status_name"], "停止（Suspended）")
        self.assertTrue(suspended["requires_user_review"])

    def test_外部利用履歴JSONを正規化(self):
        users = [{"id": 1, "email": "u@example.com", "username": "u", "firstname": "U", "lastname": "Test"}]
        apps = [{"id": 50, "name": "テストアプリ"}]
        payload = {"events": [{"user_email": "u@example.com", "app_name": "テストアプリ", "created_at": "2026-10-01T00:00:00Z"}]}
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "usage.json"
            p.write_text(json.dumps(payload), encoding="utf-8")
            raw = c.load_usage_file(str(p))
            normalized = c.normalize_external_usage(raw, users, apps)
        self.assertEqual(len(normalized), 1)
        self.assertEqual(normalized[0]["user_id"], 1)
        self.assertEqual(normalized[0]["app_id"], 50)


if __name__ == "__main__":
    unittest.main(verbosity=2)
