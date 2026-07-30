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
- Terraform は `make tf-validate` / `make tf-cf-validate` で構文と参照を確認

## Cloudflare プロバイダ v4 → v5 の移行

`terraform-cloudflare/` は cloudflare プロバイダ `~> 5.22` に移行済みです。
v5 は破壊的変更が多く、v4 で作成した state をそのまま使うことはできません。
実際に対応した内容と、既存環境で必要な移行作業を以下にまとめます。

### 1. `cloudflare_record` → `cloudflare_dns_record`

v5 で `cloudflare_record` リソースは**削除**され、`cloudflare_dns_record` に改名されました。
既存の state は `terraform state mv` でアドレスを移行する必要があります。

```
terraform state mv 'cloudflare_record.failover[0]' 'cloudflare_dns_record.failover[0]'
terraform state mv 'cloudflare_record.vps_tunnel[0]' 'cloudflare_dns_record.vps_tunnel[0]'
terraform state mv 'cloudflare_record.ec2_tunnel[0]' 'cloudflare_dns_record.ec2_tunnel[0]'
```

### 2. `allow_overwrite` の廃止

`allow_overwrite` 属性は廃止されました。既存の DNS レコードを Terraform 管理に引き継ぐ場合は、
`terraform import` で取り込んでください。

### 3. `cloudflare_zone` の属性変更

- `account_id` → `account = { id = ... }`
- `zone` → `name`
- `plan` 属性は削除されたため、**Terraform ではプランを設定できません**。
  プランの変更は Cloudflare のダッシュボード、または `cloudflare_zone_subscription` で行ってください。
- `cf_zone_plan` 変数は既存 tfvars との互換のため残していますが、**未使用**です。

### 4. 既存ゾーン参照は `filter` 形式へ

`data "cloudflare_zone"` は `filter = { name = ..., account = { id = ... } }` の形式になり、
ゾーン ID は `.id` から取得します。

```
data "cloudflare_zone" "main" {
  count = var.cf_zone_mode == "existing" ? 1 : 0
  filter = {
    name    = var.cf_zone_name
    account = { id = var.cf_account_id }
  }
}
```

### 5. トンネルの `secret` → `tunnel_secret`

Cloudflare Tunnel リソース（`cloudflare_zero_trust_tunnel_cloudflared`）の `secret` 属性は
`tunnel_secret` に改名されました。

### 動作確認の状況

- `terraform validate` は `terraform/` と `terraform-cloudflare/` の両ディレクトリで成功を確認済みです。
- `terraform plan` / `terraform apply` は認証情報が必要なため**未実行**です。
  実環境へ適用する前に、必ず `plan` の差分を確認してください。

### プロバイダのバージョン

- `terraform-cloudflare/`: cloudflare `~> 5.22`、random `~> 3.9`
- `terraform/`: aws `~> 6.0`、external `~> 2.4`、random `~> 3.9`
  - `random` はこれまで未宣言でした（暗黙依存に頼っていたバグ）。明示宣言に修正済みです。

## AWS セキュリティグループの非推奨リソース（据え置き）

`aws_security_group_rule` は AWS プロバイダで非推奨です
（後継は `aws_vpc_security_group_ingress_rule` / `aws_vpc_security_group_egress_rule`）。

ただし移行するとリソースアドレスが変わるため state 移行とルールの一時的な再作成が必要で、
稼働中のゲームサーバーのポートが一瞬閉じます。そのため**今回は意図的に据え置いています**。

将来移行する場合の手順:

1. 計画停止の時間帯に実施する（ポートが一瞬閉じるため）。
2. 既存ルールを state から外し、新リソースとして取り込む。

```
terraform state rm 'aws_security_group_rule.ssh'
terraform import 'aws_vpc_security_group_ingress_rule.ssh' <security_group_rule_id>
```

3. `terraform plan` で差分が消えたことを確認する。

移行のタイミングを取れない場合は、現行の `aws_security_group_rule` のまま運用して問題ありません。

## 修正済みの既知の問題

過去に存在した以下の不具合は修正済みです。古いバージョンを運用している場合は更新してください。

### portctl agent の任意コマンド実行（重要）

`portctl` の agent は root 権限で動作しますが、UFW コマンドを
`subprocess.run(..., shell=True)` で実行しており、拒否文字リストに単独の `&` が
含まれていませんでした。そのため、ポート転送の Web UI から任意コマンドを root 権限で
実行できる状態でした。

修正内容:
- `shell=False`（配列渡し）に変更し、シェルのメタ文字が解釈されないようにした。
- ルール文字列に許可文字のホワイトリスト検証を追加した。

### 公開ポータルの CSRF と XSS

- 公開ポータル（`server_portal.php`）のホワイトリスト申請とフィードバック送信に
  CSRF トークンがありませんでした。トークン検証を追加して修正済みです。
- `hostport` / コンテナ名を JS の文字列リテラルへ `htmlspecialchars` で埋めており、
  XSS が発生していました。修正済みです。

### 管理画面の Docker 操作が失敗する不具合

- `docker_action.php` が `deploy` / `purge` を許可アクションに含めていなかったため、
  「展開+ビルド」とカタログの「削除」が常に失敗していました。許可アクションに追加して修正済みです。
- 実行結果を `$_SESSION['docker_result']` に書き込む一方で、管理画面は
  `$_SESSION['flash']` を読んでいたため結果が表示されませんでした。参照先を統一して修正済みです。

## ポータルの言語

- `portal/` のセットアップポータルは既定言語が日本語です（英語にも切り替えできます）。
- 管理画面、公開ポータル、portctl の Web UI も日本語化済みです。

## 残っている課題（手作業が必要）

### 同梱の Suricata 設定が 6.0 世代

`ansible/roles/suricata/files/suricata.yaml` は Suricata 6.0 時代の設定ファイルです。
Debian 13 が提供する Suricata 7.x / 8.x では `detect-engine` / `stream` / `app-layer` /
`eve-log` 配下に廃止・改名されたキーが含まれるため、そのまま読み込ませると起動に失敗します。

現状の影響範囲は限定的です。`suricata` ロールがこのファイルを配置するのは
`/etc/suricata/suricata.yaml` が存在しないときだけで、通常は apt でパッケージを
導入した時点で作成されるため、このタスクは実行されません。
ただしパッケージ導入をスキップした環境では古い設定が配置されます。

作り直す手順:

1. 対象ホストに Suricata を導入し、パッケージ同梱の既定値を取得する。

   ```
   sudo apt-get install -y suricata
   sudo cp /etc/suricata/suricata.yaml /tmp/suricata.yaml.new
   ```

2. 現行ファイルとの差分を確認し、このプロジェクト固有の変更のみを新しい既定値へ移す。

   ```
   diff -u ansible/roles/suricata/files/suricata.yaml /tmp/suricata.yaml.new
   ```

3. `ansible/roles/suricata/files/suricata.yaml` を置き換え、
   `suricata -T -c /etc/suricata/suricata.yaml` で設定テストを通す。

なお、ホスト固有の設定を Vault で渡す場合は `suricata_yaml_manage: true` と
`suricata_yaml_content` を使う経路が用意されており、こちらは同梱ファイルを経由しません。

### `/etc/default/suricata` のレガシーな設定項目

`ansible/roles/suricata/templates/suricata_default.j2` は `RUN=` / `LISTENMODE=` /
`NFQUEUE=` / `TCMALLOC=` といった sysvinit 時代のキーを書き出します。
systemd 管理下ではこれらは無視されるため、監視インターフェースを変えたい場合は
`suricata@<インターフェース>` テンプレートユニット、または
`/etc/systemd/system/suricata.service.d/override.conf` のドロップインで
`ExecStart` に `--af-packet=<インターフェース>` を渡す方式へ移行してください。

### 公開ポータルのトースト表示位置

`server_portal.php` のフラッシュメッセージ（CSRF エラーやフィードバック送信エラー）は
Minecraft 用カードの内側で描画されています。Minecraft を無効化した構成では
カード自体が出力されないため、メッセージが表示されません。
セキュリティチェック自体は正しく機能しますが、表示位置をページ全体の階層へ
移す修正が別途必要です。
