#!/usr/bin/env python3
"""access_review の認証情報の取り扱いと、書き込み承認の検証テスト。

標準ライブラリだけで動く。OneLoginへは通信しない。
"""
import contextlib
import hashlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import access_review as ar  # noqa: E402
import collect_access_review as c  # noqa: E402


class _EnvFileBase(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.dir = Path(self._td.name).resolve()
        self._cwd = os.getcwd()
        os.chdir(self.dir)
        self.addCleanup(os.chdir, self._cwd)

    def write_env(self, text, mode=0o600, name=".env"):
        p = self.dir / name
        p.write_text(text, encoding="utf-8")
        os.chmod(p, mode)
        return p


class envファイルの読み込みテスト(_EnvFileBase):
    def test_正しい形式なら読める(self):
        self.write_env('OL_CLIENT_ID="id-1"\nOL_CLIENT_SECRET=secret-1\n')
        self.assertEqual(ar._env_credentials(".env"), ("id-1", "secret-1"))

    def test_権限が600でなければ拒否する(self):
        self.write_env("OL_CLIENT_ID=a\nOL_CLIENT_SECRET=b\n", mode=0o644)
        with self.assertRaises(c.LocalSafetyError):
            ar._env_credentials(".env")

    def test_指定外の項目_重複_欠落_空値は拒否する(self):
        cases = {
            "指定外の項目": "OL_CLIENT_ID=a\nOL_CLIENT_SECRET=b\nOTHER=c\n",
            "重複": "OL_CLIENT_ID=a\nOL_CLIENT_ID=a2\nOL_CLIENT_SECRET=b\n",
            "SECRETの欠落": "OL_CLIENT_ID=a\n",
            "空値": "OL_CLIENT_ID=\nOL_CLIENT_SECRET=b\n",
        }
        for label, text in cases.items():
            with self.subTest(label):
                self.write_env(text)
                with self.assertRaises(c.LocalSafetyError):
                    ar._env_credentials(".env")

    def test_シンボリックリンクと作業ディレクトリ外は拒否する(self):
        real = self.write_env("OL_CLIENT_ID=a\nOL_CLIENT_SECRET=b\n", name="real.env")
        (self.dir / "link.env").symlink_to(real)
        with self.assertRaises(c.LocalSafetyError):
            ar._env_credentials("link.env")
        sub = self.dir / "sub"
        sub.mkdir()
        inner = sub / ".env"
        inner.write_text("OL_CLIENT_ID=a\nOL_CLIENT_SECRET=b\n", encoding="utf-8")
        os.chmod(inner, 0o600)
        with self.assertRaises(c.LocalSafetyError):
            ar._env_credentials("sub/.env")


class 認証情報の取得テスト(unittest.TestCase):
    def test_チャット方式は今回入力された値だけを使う(self):
        args = SimpleNamespace(credential_mode="chat", chat_credentials={"client_id": " id ", "client_secret": "sec"})
        self.assertEqual(ar.obtain_credentials(args), ("id", "sec"))
        for bad in (None, {}, {"client_id": "id"}, {"client_id": "id", "client_secret": "  "}):
            with self.subTest(bad=bad):
                with self.assertRaises(c.LocalSafetyError):
                    ar.obtain_credentials(SimpleNamespace(credential_mode="chat", chat_credentials=bad))

    def test_標準方式は対話端末がなければ拒否する(self):
        args = SimpleNamespace(credential_mode="terminal", env_file=None)
        original = sys.stdin
        sys.stdin = io.StringIO("")  # isatty() は False
        try:
            with self.assertRaises(c.LocalSafetyError):
                ar.obtain_credentials(args)
        finally:
            sys.stdin = original

    def test_標準方式では_env_fileを使えない(self):
        args = SimpleNamespace(credential_mode="terminal", env_file=".env")
        with self.assertRaises(c.LocalSafetyError):
            ar.obtain_credentials(args)


class 接続先の確認テスト(unittest.TestCase):
    def test_確認済みの接続先と一致しなければ拒否する(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(
                ar.normalize_and_confirm("example", confirmed_tenant="example.onelogin.com"),
                "https://example.onelogin.com",
            )
            with self.assertRaises(c.LocalSafetyError):
                ar.normalize_and_confirm("example", confirmed_tenant="other.onelogin.com")


class コメント記録の承認テスト(unittest.TestCase):
    BASE = "https://example.onelogin.com"
    COMMENT = "2026-10 アクセス権監査: 〇〇アプリの割当を確認済み"

    def approval(self, **override):
        data = {
            "approved": True, "scope_confirmed": True, "tenant": self.BASE, "user_id": 42,
            "approved_comment_sha256": hashlib.sha256(self.COMMENT.encode("utf-8")).hexdigest(),
        }
        data.update(override)
        return SimpleNamespace(chat_approval=data)

    def check(self, args):
        ar.chat_record_approval(args, self.BASE, 42, self.COMMENT)

    def test_対象_文面_スコープに結び付いた承認だけを受け付ける(self):
        self.check(self.approval())

    def test_承認が欠けている_または結び付きが違えば拒否する(self):
        bad_cases = {
            "未承認": self.approval(approved=False),
            "スコープ未確認": self.approval(scope_confirmed=False),
            "別テナント": self.approval(tenant="https://other.onelogin.com"),
            "別ユーザー": self.approval(user_id=43),
            "ユーザーIDが文字列": self.approval(user_id="42"),
            "ユーザーIDが真偽値": self.approval(user_id=True),
            "文面が違う": self.approval(approved_comment_sha256=hashlib.sha256(b"other").hexdigest()),
        }
        for label, args in bad_cases.items():
            with self.subTest(label):
                with self.assertRaises(c.LocalSafetyError):
                    self.check(args)
        with self.assertRaises(c.LocalSafetyError):
            self.check(SimpleNamespace())  # 承認情報そのものが無い


if __name__ == "__main__":
    unittest.main(verbosity=2)
