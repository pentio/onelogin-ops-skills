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
    ├── README.md            # skillの説明
    └── {skill名}.zip        # skill本体
```

各Skillは `skills/<skill名>/<skill名>.zip` を起点とします。

## 利用方法

1. 利用したいSkillのZIPをクリックし、［Download raw file］よりダウンロードします。
2. チャットで登録済みのSkillを選択し、監査を依頼します。
3. 以降の操作は、各SkillのREADMEとZIP内の `references/usage-guide.md` を参照してください。

### 動作要件

- Skillを実行する環境でPython 3.10以上のコード実行、同梱ファイルへのアクセス、OneLogin APIへのHTTPS通信が可能であること（同梱スクリプトは標準ライブラリのみを使用）
- OneLogin API Credential（必要なスコープは各skillによって異なる）

## セキュリティ

- 同梱スクリプトは、明記している場合を除き読み取り専用です。
- API CredentialやアクセストークンをSkillやリポジトリに保存しないでください。
- 脆弱性の報告方法は [SECURITY.md](SECURITY.md) を参照してください。



## 免責事項

本リポジトリはOne Identity LLCが公式に提供するものではなく、同社ならびにペンティオ株式会社の保証やサポートの対象外です。OneLoginはOne Identity LLCまたはその関連会社の商標です。

Skillの出力は確認を支援するための情報であり、アクセス権の削除などの判断は必ず人が行ってください。
