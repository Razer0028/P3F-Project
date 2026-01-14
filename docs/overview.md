# edge-stack 概要

## 目的
自宅のオンプレサーバーにゲームサーバー/WEBサイトを置き、
外部公開は VPS を経由、障害時は EC2 に切り替える構成を
IaC で再現可能にすることが目的です。

## トポロジー（標準構成）
- オンプレ（Debian 12）
  - ゲームサーバー（Minecraft/Valheim/7DTD 等）
  - Webサイト（Apache または Webコンテナ）
  - 監視・管理ポータル
- VPS（エッジ）
  - WireGuard 中継
  - ポートフォワード管理（portctl）
  - Suricata (IDS/IPS)
  - FRR/BFD（フェイルオーバー監視）
  - Cloudflared（Web公開経路のトンネル）
- EC2（代替経路）
  - WireGuard 中継
  - Suricata (IDS/IPS)
  - Cloudflared（必要に応じて）
- NAS（Synology DS223j）
  - バックアップ保存先

## 主要な通信フロー
- Web公開
  - Cloudflare (DNS/WAF/Access) -> VPS またはオンプレ/EC2 の cloudflared
  - Webトラフィックは HTTP/HTTPS 経由
- ゲームポート
  - 外部 -> VPS (TCP/UDP) -> WireGuard -> オンプレ
  - 代替として EC2 -> WireGuard -> オンプレ

## セキュリティ層
- Cloudflare（HTTP/HTTPS の WAF/アクセスポリシー）
- WireGuard による IP 秘匿・トンネル化
- Suricata (IDS/IPS) による検知/遮断
- UFW によるアクセス制御

## フェイルオーバー
- VPS の疎通監視: FRR/BFD
- 切替制御: failover_core
- WireGuard の切替と Cloudflare DNS 更新を自動化

## IaC 構成
- Ansible
  - on-prem/vps/ec2 それぞれの役割をロール化
  - 秘密情報は Ansible Vault で管理
- Terraform
  - EC2/VPC/SG/KeyPair/EIP を作成
  - カスタム VPC か自動 VPC を選択可能

## 構成モード
- 1台構成（オンプレのみ）
  - 最小構成。外部公開や防御層は含まない
- 2台構成（オンプレ + VPS）
  - VPS を入口にして WireGuard + 防御層を有効化
- 3台構成（オンプレ + VPS + EC2）
  - フェイルオーバーを含むフル構成

## 注意点
- Cloudflare の設定（DNS/Access/LB）は外部サービスのため IaC で完全自動化しにくい箇所があります。
- VPS 初期構築（アカウント作成/OSセットアップ）は手動前提です。
- AllowedIPs を 0.0.0.0/0 にする場合、Endpoint への経路は PostUp/PostDown で LAN 側に固定してください。
- WireGuard のサンプル IP は `10.100.0.0/24` を想定しています。環境に合わせて置換してください。
- 管理者画面は必須で、許可CIDRが空の場合はアクセス不可です。
