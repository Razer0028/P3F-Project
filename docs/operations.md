# 運用ガイド

## 管理者ポータル（web_portal）
- 管理画面: `http://<onprem_ip>/admin/`（Apache の digest 認証）
- 認証/アクセス制御:
  - `web_portal_admin_enable: true` を有効化
  - `web_portal_admin_user` / `web_portal_admin_password` を Vault に保存
  - `web_portal_admin_allow_cidrs` / `web_portal_admin_deny_cidrs` で許可・拒否を制御
  - allow を空にすると `/admin` は拒否されます（安全側）
- 管理対象の定義:
  - `/opt/serveradmin/config/portal_services.json` で「どのサービスを管理/公開するか」を決定
  - `enabled`, `monitor_containers`, `services`（hostport/howto/compose_dir 等）を編集
- 実行基盤:
  - `sudo /opt/serveradmin/bin/docker_manage.sh` でコンテナ操作（status/start/stop/build/deploy/purge）
  - `sudo /opt/serveradmin/bin/game_admin.sh` でゲーム設定/コマンド
  - `player_monitor.py` が `/opt/serveradmin/status/current_players.json` を更新（状態/人数）
- 参照/反映先:
  - Web ポータルは `/opt/serveradmin` をマウントして状態/設定を参照します

## portctl（VPS ポートフォワード管理）
- Web UI: `http://<wg_vps_ip>:9000/`（WG 経由）
- Local: `http://127.0.0.1:9000/`（VPS 内）
- 設定:
  - 既定転送先: `/etc/portctl/config.json` の `default_dest_ip`
  - 外向き IF: 同ファイルの `public_interface` で上書き可能
  - 既定転送先は WG のオンプレIPに合わせる（例: `10.100.0.2`）
- ルール本体: `/opt/portctl/rules.json`
- ポイント:
  - `default_dest_ip` が空の場合は、ルール側に `dest_ip` が必要
  - 既定では WG 経由の転送を想定（`portctl_wg_interface`）

## WireGuard 切替
- 同時に wg0/wg1 を有効にしない
- `systemctl stop wg-quick@wg0` / `systemctl start wg-quick@wg1`
- AllowedIPs を `0.0.0.0/0` にする場合、切替後に通信できることを確認する

## フェイルオーバー
- 役割:
  - オンプレ側の `failover_core` が DNS と wg0/wg1 を制御
  - VPS 障害時は EC2 に切替、復旧時は VPS へ戻す
- 仕組み:
  - FRR/BFD の down を監視トリガーにする
  - WireGuard を wg0/wg1 で切替
  - Cloudflare DNS を更新（`failover_cf_token/zone_id/record_id`）
  - VPS ヘルスチェック（既定: TCP 18080）で復旧判定
- 主要変数（Vault 推奨）:
  - `failover_instance_id` / `failover_ec2_ip`
  - `failover_cf_token` / `failover_cf_zone_id` / `failover_cf_record_id`
  - `failover_dns_record_name` / `failover_vps_ip`
  - `failover_wg0_bfd_peer`（BFD の対向IP）
- 制御:
  - 自動切替を止めたい場合は `failover_auto_failback: "no"`
  - 手動フェイルバックは `failover_failback_request_file` を作成

## Cloudflared
- `cloudflared` は VPS/EC2 で個別トンネルに分ける
- tunnel ID と credentials は Vault で管理

## バックアップ
- `backup_full_enabled` / `backup_games_enabled` で制御
- NAS パスは `nas_mount` / `backup_root` で指定

## 検証
- `make validate` で主要サービスの稼働確認
- 失敗時は `systemctl status` と `journalctl -u <service>` で確認
