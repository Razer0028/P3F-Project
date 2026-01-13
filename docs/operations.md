# 運用ガイド

## portctl（VPS ポートフォワード管理）
- Web UI: `http://<wg_vps_ip>:9000/`（WG 経由）
- Local: `http://127.0.0.1:9000/`（VPS 内）
- 設定:
  - 既定転送先: `/etc/portctl/config.json` の `default_dest_ip`
  - 外向き IF: 同ファイルの `public_interface` で上書き可能
  - 既定転送先は WG のオンプレIPに合わせる（例: `10.100.0.2`）

## WireGuard 切替
- 同時に wg0/wg1 を有効にしない
- `systemctl stop wg-quick@wg0` / `systemctl start wg-quick@wg1`

## フェイルオーバー
- failover_core が DNS と wg0/wg1 を制御
- 自動切替を止めたい場合は `failover_auto_failback` を `no` に設定

## Cloudflared
- `cloudflared` は VPS/EC2 で個別トンネルに分ける
- tunnel ID と credentials は Vault で管理

## バックアップ
- `backup_full_enabled` / `backup_games_enabled` で制御
- NAS パスは `nas_mount` / `backup_root` で指定

## 検証
- `make validate` で主要サービスの稼働確認
- 失敗時は `systemctl status` と `journalctl -u <service>` で確認
