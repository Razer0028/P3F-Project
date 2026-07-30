# Cloudflared セットアップ（公開用ガイド）

このプロジェクトでは cloudflared を VPS と EC2 で動かすことを前提としています。
秘密情報は必ず Ansible Vault に保存してください（コミットしないこと）。

## 1) トンネルを作成する

Cloudflare でトンネルを作成し、credentials JSON をダウンロードします。

必要になるもの:
- Tunnel ID
- credentials JSON ファイル
- ingress 用のホスト名（1 つ以上）

なお、`terraform-cloudflare/` を使えばトンネルと DNS レコードを Terraform で作成できます
（cloudflare プロバイダ `~> 5.22`）。その場合、トンネルリソースの秘密値は
`tunnel_secret` 属性で指定します（v4 の `secret` から改名されました）。

## 2) Vault のエントリを準備する

以下の値をホストごとの Vault ファイルに保存します。

- cloudflared_config_content
- cloudflared_credentials_path
- cloudflared_credentials_content

設定内容の例:

  tunnel: <TUNNEL_ID>
  credentials-file: /etc/cloudflared/<TUNNEL_ID>.json
  ingress:
    - hostname: YOUR_DOMAIN
      service: http://127.0.0.1:8080
    - service: http_status:404

credentials の内容の例（生の JSON）:

  {"AccountTag":"...","TunnelSecret":"...","TunnelID":"..."}

## 3) Ansible で反映する

正式なプレイブックは `ansible/site.yml` です。

  ANSIBLE_CONFIG=./ansible.cfg ansible-playbook -i ~/.config/edge-stack/ansible/hosts.ini \
    ansible/site.yml -l vps --tags cloudflared

  ANSIBLE_CONFIG=./ansible.cfg ansible-playbook -i ~/.config/edge-stack/ansible/hosts.ini \
    ansible/site.yml -l ec2 --tags cloudflared

補足: `host_key_checking = True` のため、初回接続の前に対象ホストを `ssh-keyscan` で
`~/.ssh/known_hosts` へ登録しておく必要があります。

## 注意点

- パッケージのインストールに失敗する場合は、cloudflared を手動でインストールし、
  ~/.config/edge-stack/ansible/group_vars/all.yml で
  cloudflared_install_if_missing=false を設定してください。
