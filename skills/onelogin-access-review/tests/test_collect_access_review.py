#!/usr/bin/env python3
"""collect_access_review の純粋関数と、安全性に関わる入出力のテスト。

標準ライブラリだけで動く。OneLoginへは通信しない。
"""
import json
import os
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import collect_access_review as c  # noqa: E402


class 収集処理ユーティリティテスト(unittest.TestCase):
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


class テナントURL正規化テスト(unittest.TestCase):
    """認証情報の送信先になるため、*.onelogin.com の単一サブドメイン以外は受け付けない。"""

    def test_受け付ける形式はすべてHTTPSのテナントルートになる(self):
        for value in (
            "example",
            "example.onelogin.com",
            "https://EXAMPLE.onelogin.com/",
            "https://example.onelogin.com/admin",
            # HTTPは拒否せずHTTPSへ正規化する。この関数の戻り値がHTTPになることはない。
            "http://example.onelogin.com",
        ):
            with self.subTest(value=value):
                self.assertEqual(c.normalize_base_url(value), "https://example.onelogin.com")

    def test_別ドメインや紛らわしい形式は拒否する(self):
        for value in (
            "",
            "https://example.com",
            "example.evil.com",
            "https://example.onelogin.com.evil.com",
            "example.onelogin.co.jp",
            "a.b.onelogin.com",
            "onelogin.com",
            "ftp://example.onelogin.com",
            "example.onelogin.com:8443",
            "https://user:pw@example.onelogin.com",
            "https://example.onelogin.com/?client_secret=abc",
            "https://example.onelogin.com/?code=abc",
            "-example",
        ):
            with self.subTest(value=value):
                with self.assertRaises(c.CollectorError):
                    c.normalize_base_url(value)


class ユーザー情報の最小化テスト(unittest.TestCase):
    def test_commentと未許可のカスタム属性は出力しない(self):
        user = {
            "id": 1, "email": "u@example.com", "comment": "既存の管理メモ",
            "custom_attributes": {"employee_no": "A001", "memo": "メモ"},
        }
        out = c.safe_user(user)
        self.assertEqual(out["id"], 1)
        self.assertNotIn("comment", out)
        self.assertNotIn("custom_attributes", out)

    def test_許可した属性だけを出し_機微な名前は値を伏せる(self):
        user = {"id": 1, "custom_attributes": {
            "employee_no": "A001", "api_key": "k-123", "tags": ["a", "b"], "memo": "x",
        }}
        out = c.safe_user(user, ["employee_no", "api_key", "tags"])
        self.assertEqual(out["custom_attributes"]["employee_no"], "A001")
        self.assertEqual(out["custom_attributes"]["api_key"], "[REDACTED]")
        self.assertNotIn("tags", out["custom_attributes"])  # 配列は出力しない
        self.assertNotIn("memo", out["custom_attributes"])  # 許可していない


class ローカルファイル安全性テスト(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.dir = Path(self._td.name)

    def test_出力ファイルは権限600で作られる(self):
        out = c.secure_write_json(str(self.dir / "out.json"), {"a": 1})
        self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o600)
        self.assertEqual(json.loads(out.read_text(encoding="utf-8")), {"a": 1})

    def test_既存ファイルは明示しない限り上書きしない(self):
        target = self.dir / "out.json"
        c.secure_write_json(str(target), {"v": 1})
        with self.assertRaises(c.LocalSafetyError):
            c.secure_write_json(str(target), {"v": 2})
        c.secure_write_json(str(target), {"v": 2}, overwrite=True)
        self.assertEqual(json.loads(target.read_text(encoding="utf-8")), {"v": 2})

    def test_シンボリックリンクと存在しないフォルダへは出力しない(self):
        real = self.dir / "real.json"
        real.write_text("{}", encoding="utf-8")
        link = self.dir / "link.json"
        link.symlink_to(real)
        with self.assertRaises(c.LocalSafetyError):
            c.secure_write_json(str(link), {"a": 1}, overwrite=True)
        with self.assertRaises(c.LocalSafetyError):
            c.secure_write_json(str(self.dir / "no_such_dir" / "out.json"), {"a": 1})

    def test_権限が広いファイルは入力として読まない(self):
        p = self.dir / "in.json"
        p.write_text('{"ok": true}', encoding="utf-8")
        os.chmod(p, 0o644)
        with self.assertRaises(c.LocalSafetyError):
            c.read_private_file(str(p), json_only=True)
        os.chmod(p, 0o600)
        self.assertEqual(c.read_private_file(str(p), json_only=True), {"ok": True})

    def test_シンボリックリンクは入力として読まない(self):
        real = self.dir / "real.json"
        real.write_text("{}", encoding="utf-8")
        os.chmod(real, 0o600)
        link = self.dir / "link.json"
        link.symlink_to(real)
        with self.assertRaises(c.LocalSafetyError):
            c.read_private_file(str(link), json_only=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
