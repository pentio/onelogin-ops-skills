# obot-integration-skills
生成AI向けSkill集。Obotと連携して配布・利用する

## 構成

各Skillは `skills/<skill名>/` に配置し、直下に `SKILL.md` を置く。

| Skill | 概要 |
|---|---|
| [onelogin-access-review](skills/onelogin-access-review/) | OneLoginのアプリ割り当てを最小権限の観点から監査する |

## 注意

- APIキー・パスワードなどの認証情報や顧客情報をコミットしない。例やテストには架空の値を使う。
