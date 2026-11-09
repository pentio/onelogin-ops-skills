#!/usr/bin/env python3
"""skills/*/SKILL.md が Agent Skills の仕様（https://agentskills.io/specification）に沿っているか検証する。

標準ライブラリだけで動く。仕様に反する項目があればエラー終了する。
推奨値（500行以内など）を超える場合は警告だけを出す。
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

NAME_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
MAX_NAME = 64
MAX_DESCRIPTION = 1024
MAX_COMPATIBILITY = 500
RECOMMENDED_MAX_LINES = 500
ALLOWED_KEYS = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}


def parse_frontmatter(text: str) -> dict[str, str]:
    m = re.match(r"---\n(.*?)\n---\n", text, re.S)
    if not m:
        raise ValueError("先頭にYAMLのfrontmatter（--- で囲まれた領域）がありません")
    fields: dict[str, str] = {}
    key = None
    for line in m.group(1).splitlines():
        top = re.match(r"([A-Za-z][A-Za-z0-9_-]*):\s*(.*)$", line)
        if top and not line.startswith((" ", "\t")):
            key = top.group(1)
            fields[key] = top.group(2).strip()
        elif key is not None and line.strip():
            fields[key] += " " + line.strip()  # 複数行の値は連結して長さだけを見る
    return fields


def validate(skill_dir: Path) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    path = skill_dir / "SKILL.md"
    if not path.is_file():
        return [f"{skill_dir}: SKILL.md がありません"], warnings
    text = path.read_text(encoding="utf-8")
    try:
        fm = parse_frontmatter(text)
    except ValueError as e:
        return [f"{path}: {e}"], warnings

    unknown = set(fm) - ALLOWED_KEYS
    if unknown:
        errors.append(f"{path}: 仕様にないfrontmatterの項目があります: {sorted(unknown)}")
    name = fm.get("name", "")
    if not name:
        errors.append(f"{path}: name は必須です")
    else:
        if len(name) > MAX_NAME or not NAME_RE.fullmatch(name):
            errors.append(f"{path}: name は英小文字・数字・ハイフンだけで{MAX_NAME}文字以内にしてください（先頭末尾と連続のハイフン不可）: {name!r}")
        if name != skill_dir.name:
            errors.append(f"{path}: name ({name!r}) は親ディレクトリ名 ({skill_dir.name!r}) と一致させてください")
    description = fm.get("description", "")
    if not description:
        errors.append(f"{path}: description は必須です")
    elif len(description) > MAX_DESCRIPTION:
        errors.append(f"{path}: description は{MAX_DESCRIPTION}文字以内にしてください（現在 {len(description)} 文字）")
    if len(fm.get("compatibility", "")) > MAX_COMPATIBILITY:
        errors.append(f"{path}: compatibility は{MAX_COMPATIBILITY}文字以内にしてください")

    lines = text.count("\n")
    if lines > RECOMMENDED_MAX_LINES:
        warnings.append(f"{path}: SKILL.md が{lines}行あります。{RECOMMENDED_MAX_LINES}行以内を推奨します（詳細は references/ へ）")
    size_kb = len(text.encode("utf-8")) / 1024
    if size_kb > 20:
        warnings.append(f"{path}: SKILL.md が{size_kb:.0f}KBあります。起動時に全文が読み込まれるため、詳細は references/ へ分けることを推奨します")
    return errors, warnings


def main() -> int:
    root = Path(__file__).resolve().parents[2] / "skills"
    skill_dirs = sorted(p for p in root.iterdir() if p.is_dir())
    if not skill_dirs:
        print("skills/ 配下にSkillがありません")
        return 1
    failed = False
    for d in skill_dirs:
        errors, warnings = validate(d)
        for w in warnings:
            print(f"::warning::{w}")
        for e in errors:
            print(f"::error::{e}")
            failed = True
        if not errors:
            print(f"OK: {d.name}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
