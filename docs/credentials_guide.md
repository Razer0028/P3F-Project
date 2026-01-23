# 認証情報・ドメイン準備ガイド（日本語）

本ドキュメントは、Cloudflare と AWS の認証情報、ドメイン準備の手順をまとめたものです。

## 1. ドメイン準備（レジストラ → Cloudflare）
1) ドメインを購入します（任意のレジストラで OK）。
2) Cloudflare ダッシュボードで「Web サイトを追加」からドメインを登録します。
3) 付与された Cloudflare のネームサーバーを、レジストラ側へ設定します。
4) 反映後にステータスが「有効」になったことを確認します。

確認例:
```
dig NS YOUR_DOMAIN +short
```

## 2. Cloudflare API トークンの作成
Terraform で Cloudflare の Zone/DNS/Tunnel を作成・更新するためのトークンです。

1) Cloudflare → 右上ユーザーアイコン → 「マイプロフィール」→ 「API トークン」
2) 「トークンを作成」
3) 例: 「Edit zone DNS」テンプレートをベースに作成
4) 必要に応じて権限を追加
   - Zone: DNS:Edit
   - Zone: Zone:Read
   - Account: Cloudflare Tunnel:Edit（トンネルを Terraform で作る場合）
5) 対象ゾーンを対象ドメインのみに限定
6) 作成後、トークンを控えます（表示は一度だけ）

保存方法（例）:
```
export CLOUDFLARE_API_TOKEN="YOUR_TOKEN"
```

## 3. AWS IAM ユーザーとアクセスキーの作成
Terraform で EC2 を作成するための IAM ユーザーを用意します。

1) AWS Console → IAM → Users → Create user
2) 「アクセスキー - プログラムによるアクセス」を有効化
3) 権限は最小権限ポリシーを付与
   - 例: `docs/iam_terraform_policy.json`
4) アクセスキーを作成し、CSV をダウンロード

ポータル使用時:
- AWS のアクセスキー CSV をアップロードします。

CLI で使う場合:
```
aws configure
```

## 4. よくある注意点
- トークン/アクセスキーは漏洩させないでください。
- DNS の反映には数分〜数時間かかる場合があります。
- Terraform で Zone を作成した場合は、必ずネームサーバー変更を行ってください。
