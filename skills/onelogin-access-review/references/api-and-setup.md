# OneLogin API・実行設定

OneLoginから実データを取得するとき、Credentialのスコープ、エンドポイント、HR情報源の扱い、ユーザーコメントへの共有方法を確認するときだけ参照する。

## 監査用Credential

OneLoginテナント、Client ID、Client Secretは、**Skillを実行するたびにユーザーから入力してもらう。** 過去チャット、別チャット、Memory、以前のSkill実行、保存済み設定や環境変数から自動的に再利用しない。

通常の監査では **Read All** スコープを持つOneLogin API Credentialを使用する。

同梱のCollectorは読み取り専用で、アクセストークン取得用のPOSTと情報取得用のGETだけを使用する。

OAuth 2.0 Client Credentialsでアクセストークンを取得する。

- `POST https://<subdomain>.onelogin.com/auth/oauth2/v2/token`
- Client ID / Client Secretで認証する。
- `grant_type=client_credentials`

Client Secret、アクセストークン、Authorizationヘッダーをユーザー向け出力へ表示・保存しない。Client IDやClient Secretを次回実行用にMemoryや永続設定へ保存しない。

## Collectorで利用する主なエンドポイント

- ユーザー
  - `GET /api/2/users`
  - `GET /api/2/users/:id`
  - `GET /api/2/users/:id/apps`
- Role
  - `GET /api/2/roles/:id`
  - `GET /api/2/roles/:id/apps`
- Group
  - `GET /api/2/groups`
- アプリ
  - `GET /api/2/apps/:app_id/users`
- Event
  - `GET /api/2/events/types`
  - `GET /api/2/events`

## OneLoginユーザーステータス

ユーザーの `status` フィールドはログイン状態を表す。主な値は次のとおり。

- `0`: 未アクティブ
- `1`: Active
- `2`: Suspended
- `3`: Locked
- `4`: パスワード期限切れ
- `5`: パスワードリセット待ち
- `7`: パスワード設定待ち
- `8`: セキュリティ質問が必要

Active以外の状態は、ユーザー単位の確認材料として扱う。非Activeであることだけを理由に個別アプリを削除対象と判断しない。

## Read Allで収集する情報

Collectorでは主に次の情報を取得する。

- 現在のユーザー属性とステータス。
- 現在対象ユーザーへ割り当てられているアプリ。
- 現在のRole IDと各Roleに含まれるアプリ。
- 取得できる範囲でのGroup情報とPeer比較用属性。
- Peerの現在のアプリ保有状況。
- OneLoginのアプリログインEventと、関連する変更Event。

現在のRoleによって現在のアプリ割り当てが説明できるかは判定できる。

ただし、現在のRoleで説明できないという理由だけで、そのアプリが確実にUsers > Applicationsから直接割り当てられたとは断定しない。

## 利用履歴の制約

OneLoginのEvent Type 8はIdP側で観測されたアプリログインであり、アプリの完全な利用履歴ではない。

既存のSPセッション、デスクトップクライアント、APIなどを利用している場合、新しいOneLoginアプリログインEventが発生しなくてもアプリを利用している可能性がある。

OneLogin上のアプリログインEventが0件または欠落していることは、補助的な根拠としてのみ扱う。

## ユーザー提供の利用履歴

ユーザーが合成データや外部システムから取得した利用履歴を明示的に提供した場合は、`--usage-file` で指定する。

対応形式:

- Eventの配列を持つJSON。
- `events`、`data`、`login_history`、`history` のいずれかに配列を持つJSON。
- CSV。

利用できる主なフィールド:

- ユーザー: `user_id`, `email`, `user_email`, `username`, `user_name`
- アプリ: `app_id`, `app_name`, `application_id`, `application_name`
- 時刻: `created_at`, `timestamp`, `time`, `login_at`, `event_time`

ユーザー提供の利用履歴とOneLoginのアプリログインEventを無断で混在させない。

## HR情報源

HR情報は、現在のセッションで利用可能なConnector、MCP、Plugin、アップロードファイル、その他の情報源から取得できる場合がある。

HRデータを取得する前に、必ず次の手順を守る。

1. 必要であれば、利用可能なツールや情報源の種類・メタデータだけを確認する。
2. HR情報をアクセスレビューに利用してよいか、ユーザーへ明示的に確認する。
3. 許可されるまでHRレコードを検索・閲覧・取得・照会しない。
4. 許可後は、通常は在籍状態、Department、Title、入退社日、異動日など、アクセスレビューに必要な最小限の情報だけを取得する。

許可されない場合はHR情報を使用せず監査を続行する。

休職中、退職済み、退職・退任予定など通常以外の在籍状態は、**ユーザー単位の要確認**として扱う。休職理由など、アクセスレビューに不要な詳細は取得・表示しない。

## コメント共有用Credential

OneLoginユーザーの `comment` を更新するには、**Manage users** または **Manage All** スコープを持つCredentialが必要である。最小権限の観点から **Manage users** を優先する。

Read All Credentialでコメントを書き込めるとは想定しない。

アクセストークンのレスポンスだけでは、元のAPI Credentialに設定された管理スコープを確定できない。書き込み前に、信頼できる設定情報または管理者が明示した情報から、使用予定Credentialのスコープを確認する。確認できない場合は書き込まない。

## 監査結果を `comment` へ記録する場合

使用する更新方法:

- `PUT /api/2/users/:id?mappings=disabled`
- `Content-Type: application/json`
- Bodyには `comment` フィールドだけを含める。

`mappings=disabled` を使い、コメント更新を理由にUser Mappingを実行しない。

書き込み前に必ず次を行う。

1. コメント共有についてユーザーの明示的な承認を得る。
2. 対象ユーザーごとの実際の書き込み予定文を提示し、その文面について承認を得る。
3. **Manage users** または **Manage All** スコープを確認する。
4. 現在のコメントを取得する。
5. ユーザーが明示的に置換を希望しない限り、既存コメントを保持したうえで追記する。
6. HRの詳細情報は、その具体的な文面についてユーザーが明示的に承認しない限り記載しない。

中立的な記載例:

```text
[アクセスレビュー YYYY-MM-DD]
確認推奨度: 高
理由: HR情報とOneLoginアカウント状態の整合性について確認が必要です。
```

## Collectorの実行方法

認証情報がシェル履歴に残らないよう、環境変数の利用を推奨する。

```bash
export OL_BASE_URL="https://example.onelogin.com"
export OL_CLIENT_ID="..."
export OL_CLIENT_SECRET="..."

python3 scripts/collect_access_review.py \
  --user user@example.com \
  --user another.user@example.com \
  --output access_review_data.json
```

ユーザー提供の利用履歴を使う場合:

```bash
python3 scripts/collect_access_review.py \
  --user user@example.com \
  --usage-file login_history.csv \
  --output access_review_data.json
```

同梱スクリプトは情報収集専用とする。HR情報へのアクセスとOneLoginコメントへの書き込みは、`SKILL.md` に定義した承認フローを通した場合だけ行う。

## 外部通信できない実行環境

Skillの実行環境から外部HTTPS通信ができない場合は、信頼できる端末またはネットワーク通信可能な環境でCollectorを実行し、生成された `access_review_data.json` をAIへ渡して分析する。
