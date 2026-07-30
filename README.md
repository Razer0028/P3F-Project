# P3F-Project（エッジスタック IaC）

オンプレ + VPS + EC2 のフェイルオーバー構成を管理する IaC ワークスペースです。

## このリポジトリの対象範囲

- オンプレ（Debian 13 / trixie）: Docker ワークロード、Apache、failover_core、バックアップ。
- VPS エッジ: WireGuard、FRR/BFD、Suricata（カスタムルール + DDoS 通知）、Cloudflared トンネル。
- EC2 エッジ: WireGuard、Suricata（FRR なし）。
- failover_core による Cloudflare DNS の更新。
- NAS へのシステム全体およびゲームデータのバックアップ。

## 必要なもの

- ansible-core 2.17 以上、Python3、ssh-agent。
  - 2.14 / 2.15 / 2.16 は EOL のためサポート対象外です。
- Ansible コレクション（後述の「Ansible コレクション」を参照）。`make deps` で導入します。
- Terraform 1.9 以上（EC2 のプロビジョニングに使用、任意）。
  - `required_version` を 1.9.0 に引き上げています。
- オンプレ / VPS / EC2 用の SSH 鍵（ポータルホストの ~/.ssh 配下、通常は /root/.ssh に配置）。

## Ansible コレクション

必要なコレクションは `ansible/requirements.yml` に定義しています。

| コレクション | バージョン |
| --- | --- |
| `ansible.posix` | >=1.5.0 |
| `community.general` | >=8.0.0 |
| `community.docker` | >=3.4.0 |

導入コマンド:

  make deps

これは以下と同じです。

  ansible-galaxy collection install -r ansible/requirements.yml

注意: `ansible` バンドル版を入れている場合はこれらのコレクションが同梱されているため
気づきにくいですが、`ansible-core` のみを入れた環境ではコレクションが無いと
`base` / `failover_core` ロールが失敗します。デプロイ前に `make deps` を実行してください。

## ドキュメント

- `docs/quickstart.md`: クイックスタート手順
- `docs/overview.md`: 構成概要/通信フロー
- `docs/credentials_guide.md`: Cloudflare/AWS 認証情報とドメイン準備
- `docs/operations.md`: 管理者ポータル/portctl/フェイルオーバー運用、移行手順、修正済みの既知の問題
- `docs/cloudflared_setup.md`: Cloudflared トンネルのセットアップ

## 公開時の注意

- 秘密情報はローカルに留めてください。`~/.config/edge-stack/ansible/host_vars/*.yml` と
  `~/.config/edge-stack/ansible/hosts.ini` はコミットしないでください。
- 出発点としてサンプルファイルを利用してください。
  - `ansible/inventory/hosts.ini.example`
  - `ansible/host_vars/onprem-1.yml.example`
  - `ansible/host_vars/vps-1.yml.example`
  - `ansible/host_vars/ec2-1.yml.example`
- Cloudflared トンネルの設定手順は `docs/cloudflared_setup.md` にあります。

## デプロイ前に用意する情報

- ホスト: オンプレ/VPS/EC2 の IP、SSH ユーザー、SSH 鍵名（鍵ファイルは ~/.ssh、通常は /root/.ssh に配置）。
- Cloudflare: アカウント ID、ゾーン名（YOUR_DOMAIN）、API トークン（環境変数で渡す）。
- Terraform（EC2）: aws_region、instance_type、key_name、allowed_ssh_cidrs、instance_name。
  - AMI: `ami_mode=manual` なら `ami_id`、`ami_mode=auto` なら `ami_owners` + `ami_name_filter`。
- フェイルオーバー: failover_ec2_ip、failover_vps_ip、failover_dns_record_name。
- 通知（任意）: Discord Webhook（DDoS 通知とポータル通知で共用）。
- WireGuard のサンプルは `10.100.0.0/24` を前提にしています（環境に合わせて置換してください）。
- 管理者用の許可 CIDR には WG/LAN を含めてください。リストが空の場合は管理画面へアクセスできません。
- LAN の CIDR は、状態確認時にポータルホスト側で自動検出されます。
- BFD は wg0 上で UDP 3784/3785 を使用します。VPS 側で許可してください。
- フェイルバックのヘルスチェックは VPS の TCP 18080 を使用します。許可する（またはオンプレ IP に限定する）必要があります。

## Vault で管理する秘密情報（host_vars/*.yml）

- WireGuard の秘密鍵/設定。
- Cloudflared の設定 + credentials JSON。
- フェイルオーバー用の Cloudflare トークン / ゾーン ID / レコード ID。
- Suricata のルール（カスタムする場合）。
- DDoS 通知（VPS のみ）: 通知先（共用の Discord Webhook を使用）。
- 管理者ポータルの認証情報（必須）。
- フェイルオーバー用の AWS 認証情報は既定でプロファイル default を使用します。Terraform/管理用の
  認証情報と分けたい場合は、failover_aws_profile に専用の名前（例: failover）を設定してください。

## 公開リリース前チェックリスト

- `~/.config/edge-stack/ansible/host_vars/*.yml` と `~/.config/edge-stack/ansible/hosts.ini` を git 管理外にする。
- `~/.config/edge-stack/terraform/terraform.tfvars` と
  `~/.config/edge-stack/terraform-cloudflare/terraform.tfvars` を git 管理外にする。
- デプロイ前にプレースホルダ（YOUR_*）を実際の値に置き換える。
- ポータルの出力に実 IP や秘密情報が表示されていないか確認する。

## WireGuard ヘルパー（任意）

鍵と Vault にそのまま貼れるスニペットを生成します。

  ./scripts/wireguard_wizard.sh

## AWS IAM ポリシー（Terraform 用）

Terraform が state を更新するには、追加の EC2 読み取り権限が必要です。
`docs/iam_terraform_policy.json` のようなポリシーを使うか、AmazonEC2ReadOnlyAccess に
作成/削除用の EC2 書き込みポリシーを併せてアタッチしてください。

## クイックスタート（Ansible）

0) 必要な Ansible コレクションを導入します（`ansible-core` のみの環境では必須）。

  make deps

1) 対話的なセットアップでインベントリと基本変数を生成します。

  ./setup.sh

2) ローカルに Vault パスワードファイルを作成します（コミットしないこと）。

  mkdir -p ~/.config/edge-stack
  chmod 700 ~/.config/edge-stack
  printf "%s\n" "YOUR_VAULT_PASSWORD" > ~/.config/edge-stack/vault_pass
  chmod 600 ~/.config/edge-stack/vault_pass

3) SSH ホスト鍵を登録します（**必須**）。

  `ansible.cfg` は `host_key_checking = True` です。初回接続の前に、対象ホストを
  `~/.ssh/known_hosts` へ登録しておく必要があります。登録せずに実行すると接続に失敗します。

  ssh-keyscan -H <onprem_ip> >> ~/.ssh/known_hosts
  ssh-keyscan -H <vps_ip> >> ~/.ssh/known_hosts
  ssh-keyscan -H <ec2_ip> >> ~/.ssh/known_hosts

  既存環境で急ぎ動かしたい場合の一時的な回避策として、実行時に
  `ANSIBLE_HOST_KEY_CHECKING=False` を付けることもできます（中間者攻撃を防げないため非推奨）。

4) ホストごとの Ansible Vault ファイルに秘密情報を記入します。

  ansible-vault edit ~/.config/edge-stack/ansible/host_vars/onprem-1.yml
  ansible-vault edit ~/.config/edge-stack/ansible/host_vars/vps-1.yml
  ansible-vault edit ~/.config/edge-stack/ansible/host_vars/ec2-1.yml

5) タグを使って安全に適用します（例）。

  ANSIBLE_CONFIG=./ansible.cfg ansible-playbook -i ~/.config/edge-stack/ansible/hosts.ini ansible/site.yml -l vps --tags base
  ANSIBLE_CONFIG=./ansible.cfg ansible-playbook -i ~/.config/edge-stack/ansible/hosts.ini ansible/site.yml -l vps --tags cloudflared \
    -e cloudflared_allow_overwrite=true -e cloudflared_restart_on_change=true -e cloudflared_manage_service=true

6) 検証します。

  make validate

補足:
- 正式なプレイブックは `ansible/site.yml` です（接続待ちの `pre_tasks` を含みます）。
  ルートの `site.yml` は互換用のラッパーで、`- import_playbook: ansible/site.yml` のみを行います。
  以前はルート側にも同じ内容が二重管理されており、片方だけ更新される事故の原因になっていました。
- Vault パスワードファイル: `~/.config/edge-stack/vault_pass`（または `ANSIBLE_VAULT_PASSWORD_FILE` で指定）。
- WireGuard の wg0/wg1 を同時に有効にしないでください。failover_core のスクリプトがこれを強制します。
- 認証情報ガイド: `docs/credentials_guide.md`

## SSH ホスト鍵チェックについて（破壊的変更）

以前のルートの `ansible.cfg` は `host_key_checking = False` かつ
`ssh_args = -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null` となっており、
README の記述（有効）と矛盾していました。現在は `ansible/ansible.cfg` と揃えて
**`host_key_checking = True`** にし、危険な `ssh_args` を削除しています。

そのため、初回接続の前に `ssh-keyscan` で `~/.ssh/known_hosts` へ登録する手順が**必須**になりました。
既存環境をそのまま動かしていた場合、この変更によって接続が失敗するようになります。
一時的な回避策としては `ANSIBLE_HOST_KEY_CHECKING=False` を実行時に付与できますが、
恒久対応としては `ssh-keyscan` による登録を行ってください。

## ワンコマンドのワークフロー

- 全体デプロイ（Terraform + 全ホストの Ansible）:
  make deploy

- Terraform が作成した EC2 リソースの削除:
  make destroy

- 対象を絞ったデプロイ:
  make deploy-onprem
  make deploy-vps
  make deploy-ec2

## 必要なホスト変数（例）

これらは ~/.config/edge-stack/ansible/host_vars/*.yml に置き、Ansible Vault で暗号化します。

- WireGuard（オンプレ、VPS、EC2）
  - wireguard_raw_configs または wireguard_configs
  - wireguard_primary（任意）

- FRR（VPS + BFD 用にオンプレ）
  - `frr_generate_config: true` と `frr_bfd_peers` / `frr_bfd_interface` を使う、または
  - `frr_config_content` と `frr_daemons_content` を手動で指定する。

- Suricata（VPS、EC2）
  - suricata_custom_rules_content
  - suricata_custom_rules_path

- Cloudflared（VPS）
  - cloudflared_config_content
  - cloudflared_credentials_path
  - cloudflared_credentials_content

- failover_core（オンプレ）
  - failover_instance_id
  - failover_region
  - failover_ec2_ip
  - failover_cf_token
  - failover_cf_zone_id
  - failover_cf_record_id
  - failover_dns_record_name
  - failover_vps_ip
  - failover_auto_failback（"yes" または "no"）
  - failover_failback_request_file
  - failover_core_state（started/stopped）
  - failover_core_enable（true/false）

## failover_core の挙動

- 自動フェイルバックは failover_auto_failback で制御します。
- 手動フェイルバックは failover_failback_request_file を使います。このファイルを作成すると
  フェイルバックを要求します。
- フェイルオーバーは BFD の down で発動し、フェイルバックは VPS のヘルスチェック
  エンドポイント（ポート 18080）で判定します。
- 起動時、スクリプトは wg0/wg1 の状態を整合させ、起動時強制が有効な場合は VPS 側へ経路を向けます。

## バックアップ

- システム全体のバックアップは任意です（backup_full_enabled）。
- ゲームデータのバックアップは既定で 1 時間ごとに実行されます（backup_games_cron）。
- バックアップ先のパスは ~/.config/edge-stack/ansible/group_vars/all.yml で調整します。

## コンテナ関連の変更

- Web ポータルのコンテナは `debian:trixie-slim` ベースになりました。
- プレイヤー監視（player-monitor）のコンテナは `python:3.13-slim` ベースになりました。
- `docker-compose`（v1, Python 版）は Debian 13 で削除されたため `docker-compose-v2` に変更しました。
  `docker_packages` の既定も `docker.io` / `docker-compose-v2` / `docker-buildx` になっています。

## Terraform（EC2 スケルトン）

terraform/ ディレクトリには最小構成の EC2 スタックがあり、VPC（自動またはカスタム CIDR）、
IGW + ルートテーブル付きのパブリックサブネット、セキュリティグループ、任意の EIP、
公開鍵から作る任意の KeyPair を作成します。

  cd terraform
  terraform init
  terraform plan -var-file=~/.config/edge-stack/terraform/terraform.tfvars
  terraform apply -var-file=~/.config/edge-stack/terraform/terraform.tfvars

宣言しているプロバイダのバージョン:
- `terraform/`: aws `~> 6.0`、external `~> 2.4`、random `~> 3.9`
  - `random` はこれまで未宣言でした（暗黙依存に頼っていたバグ）。明示宣言するよう修正しています。
- `terraform-cloudflare/`: cloudflare `~> 5.22`、random `~> 3.9`
  - Cloudflare プロバイダ v4 から v5 へ移行済みです。既存の state からの移行手順は
    `docs/operations.md` を参照してください。

補足:
- `~/.config/edge-stack/terraform/terraform.tfvars` はローカル専用で、コミットしないでください。
- EC2 インスタンスがトラフィックを転送する必要がある場合は `source_dest_check = false` を設定してください。

VPS のプロビジョニングは設計上手動です。設定は Ansible で行ってください。

## よく使うコマンド

- make deps
- make bootstrap
- make validate
- make tf-init
- make tf-validate
- make tf-plan
- make tf-apply
- make tf-destroy
- make tf-cf-init
- make tf-cf-validate
- make tf-cf-plan
- make tf-cf-apply
- make tf-cf-destroy

## ローカルセットアップポータル

任意で使えるローカル/LAN 向けのポータルがあり、インベントリファイルの生成、許可された
タスクの実行、SSH 鍵のアップロードが行えます。ターミナルに表示されるトークンを使って
動作します（アップロードとタスク実行に必須）。

  make portal

LAN からアクセスする場合（0.0.0.0 でバインド）:

  make portal-lan

ポータルの操作はホワイトリスト方式です（Terraform/Ansible/Validate）。破壊的な操作には
確認ワードの入力が必要です。セットアップ後にポータルが不要であれば `portal/` を削除してください。

セットアップポータルの既定言語は日本語です（英語にも切り替えできます）。管理画面、公開ポータル、
portctl の Web UI も日本語化されています。
