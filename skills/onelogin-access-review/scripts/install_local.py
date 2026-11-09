#!/usr/bin/env python3
"""対応するローカルSkillディレクトリへ新規登録する。

利用者自身のPCで実行する。既存Skillは削除・上書きしない。
"""
from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path

SKILL_ID = "onelogin-access-review"


def destinations(home: Path, target: str) -> list[Path]:
    mapping = {
        "claude": home / ".claude" / "skills" / SKILL_ID,
        "codex": home / ".agents" / "skills" / SKILL_ID,
        "chatgpt": home / ".agents" / "skills" / SKILL_ID,
    }
    if target == "both":
        return [mapping["claude"], mapping["codex"]]
    return [mapping[target]]


def install(source: Path, dest: Path) -> None:
    if not (source / "SKILL.md").is_file():
        raise RuntimeError("SKILL.mdが見つかりません")
    if dest.exists() or dest.is_symlink():
        raise RuntimeError(f"既にSkillが存在します。上書きしません: {dest}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copytree(
            source,
            dest,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".env", "*.tmp"),
            symlinks=False,
        )
        if not (dest / "SKILL.md").is_file():
            raise RuntimeError("Skillコピー後の検証に失敗しました")
    except Exception:
        if dest.is_dir():
            shutil.rmtree(dest)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="対応するローカルSkillディレクトリへスキルを新規登録する")
    parser.add_argument("--target", required=True, choices=("chatgpt", "claude", "codex", "both"))
    args = parser.parse_args()
    skill_dir = Path(__file__).resolve().parent.parent
    targets = destinations(Path.home(), args.target)
    if any(p.exists() or p.is_symlink() for p in targets):
        for path in targets:
            if path.exists() or path.is_symlink():
                print(f"すでに存在するため処理を中止しました: {path}")
        return 2
    try:
        for path in targets:
            install(skill_dir, path)
            print(f"新規登録しました: {path}")
    except Exception as exc:
        print(f"インストールに失敗しました: {exc}")
        return 1
    print("利用するアプリでSkill一覧を再読み込みし、登録されたSkillを確認してください。登録だけではAPIへの通信許可は付与されません。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
