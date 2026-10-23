# onelogin-ops-skills

OneLoginをご利用のお客様向けに、OneLoginの運用・監査に役立つ生成AI向けSkillを公開しています。

## 収録Skill

| Skill | 概要 |
|---|---|
| [onelogin-access-review](skills/onelogin-access-review/) | ユーザーに割り当てられたアプリが最小権限の原則に沿っているかを、Role・同属性ユーザーとの比較・利用履歴・変更履歴などから監査する |

## 構成

```text
skills/
└── <skill名>/
    ├── SKILL.md        # Skill本体（名前・説明・手順）
    ├── references/     # 必要なときだけ参照する補足資料
    ├── scripts/        # Skillから実行するスクリプト
    └── assets/         # アイコンなど
```

各Skillは `skills/<skill名>/SKILL.md` を起点とします。

## 利用方法

1. このリポジトリをダウンロードまたはクローンします。
2. 利用したいSkillのディレクトリ（例：`skills/onelogin-access-review/`）を、お使いのAIツールのSkill読み込み先に配置します。Skill（`SKILL.md` 形式）に対応したAIツールで利用できます。
3. Skillの案内に従い、OneLoginテナントとAPI Credentialを実行のたびに入力します。

### 動作要件

- Python 3（同梱スクリプトは標準ライブラリのみを使用）
- OneLogin API Credential（`onelogin-access-review` の通常の監査では **Read All** スコープ）

## セキュリティ

- 同梱スクリプトは、明記している場合を除き読み取り専用です。
- API CredentialやアクセストークンをSkillやリポジトリに保存しないでください。
- 監査結果（`access_review_data.json` やCSV）には利用者の情報が含まれます。コミットしたり、公開の場所に置いたりしないでください。
- 脆弱性の報告方法は [SECURITY.md](SECURITY.md) を参照してください。

## 開発

```bash
cd skills/onelogin-access-review/scripts
python3 -m unittest -v
```

テストやサンプルには架空の値（`example.com` など）だけを使用してください。

## 免責事項

本リポジトリはOne Identity LLCが公式に提供するものではなく、同社の保証やサポートの対象外です。OneLoginはOne Identity LLCまたはその関連会社の商標です。

Skillの出力は確認を支援するための情報であり、アクセス権の削除などの判断は必ず人が行ってください。
