# クイックスタート

## 前提
- VPS/EC2 のアカウント作成と OS セットアップが完了している
- オンプレは Debian 13（trixie）を前提としている
- Cloudflare アカウントと管理対象ドメインがある
- SSH 鍵が準備済み（鍵名は ~/.ssh、通常は /root/.ssh に配置）
- ansible-core 2.17 以上（2.14 / 2.15 / 2.16 は EOL）
- Terraform を使う場合は 1.9 以上

## 0. Ansible コレクションの導入
必要なコレクションは `ansible/requirements.yml` に定義しています
（`ansible.posix` >=1.5.0 / `community.general` >=8.0.0 / `community.docker` >=3.4.0）。

```
make deps
```

上記は `ansible-galaxy collection install -r ansible/requirements.yml` と同じです。

補足: `ansible` バンドル版を入れている場合は同梱されているため気づきにくいですが、
`ansible-core` のみを入れた環境ではコレクションが無いと `base` / `failover_core` ロールが
失敗します。デプロイ前に必ず実行してください。

## 1. ブートストラップ
最小のファイルを生成します。

```
./scripts/bootstrap.sh
```

これで以下が作成されます（未作成の場合のみ）。
- `~/.config/edge-stack/ansible/hosts.ini`
- `~/.config/edge-stack/terraform/terraform.tfvars`
- `~/.config/edge-stack/ansible/host_vars/*`（Vault パスワードがある場合）

## 1.5 認証情報とドメインの準備
Cloudflare のトークン作成、AWS IAM ユーザー/アクセスキー作成、ドメインの準備は
下記のガイドにまとめています。

```
docs/credentials_guide.md
```

## 2. Vault パスワード
Vault を使うためのパスワードファイルを作成します。

```
mkdir -p ~/.config/edge-stack
chmod 700 ~/.config/edge-stack
printf "%s\n" "YOUR_VAULT_PASSWORD" > ~/.config/edge-stack/vault_pass
chmod 600 ~/.config/edge-stack/vault_pass
```

補足: 既定パス以外を使う場合は `ANSIBLE_VAULT_PASSWORD_FILE` で上書きできます。

## 3. 秘密情報の入力
各ホストの Vault ファイルへ設定を記入します。

```
ansible-vault edit ~/.config/edge-stack/ansible/host_vars/onprem-1.yml
ansible-vault edit ~/.config/edge-stack/ansible/host_vars/vps-1.yml
ansible-vault edit ~/.config/edge-stack/ansible/host_vars/ec2-1.yml
```

### WireGuard 鍵の生成（任意）
簡易ヘルパーで鍵と設定スニペットを生成できます。

```
./scripts/wireguard_wizard.sh
```

補足: 例のアドレスは `10.100.0.0/24` を前提にしています。環境に合わせて編集してください。

## 3.5 SSH ホスト鍵の登録（必須）
`ansible.cfg` は `host_key_checking = True` です。初回接続の前に、対象ホストを
`~/.ssh/known_hosts` へ登録しておく必要があります。登録せずに実行すると接続に失敗します。

```
ssh-keyscan -H <onprem_ip> >> ~/.ssh/known_hosts
ssh-keyscan -H <vps_ip> >> ~/.ssh/known_hosts
ssh-keyscan -H <ec2_ip> >> ~/.ssh/known_hosts
```

補足: 既存環境で急ぎ動かしたい場合の一時的な回避策として、実行時に
`ANSIBLE_HOST_KEY_CHECKING=False` を付けることもできます（中間者攻撃を防げないため非推奨）。

## 4. 反映（Ansible）
最初は base を適用し、その後必要なロールを適用します。
正式なプレイブックは `ansible/site.yml` です（接続待ちの `pre_tasks` を含みます）。
ルートの `site.yml` は `ansible/site.yml` を読み込むだけの互換用ラッパーです。

```
ANSIBLE_CONFIG=./ansible.cfg ansible-playbook -i ~/.config/edge-stack/ansible/hosts.ini ansible/site.yml --tags base
ANSIBLE_CONFIG=./ansible.cfg ansible-playbook -i ~/.config/edge-stack/ansible/hosts.ini ansible/site.yml -l vps
ANSIBLE_CONFIG=./ansible.cfg ansible-playbook -i ~/.config/edge-stack/ansible/hosts.ini ansible/site.yml -l ec2
ANSIBLE_CONFIG=./ansible.cfg ansible-playbook -i ~/.config/edge-stack/ansible/hosts.ini ansible/site.yml -l onprem
```

## 5. Terraform（EC2 を IaC 化する場合）
Terraform 1.9 以上が必要です（`required_version` は 1.9.0 に設定しています）。

```
cd terraform
terraform init
terraform plan -var-file=~/.config/edge-stack/terraform/terraform.tfvars
terraform apply -input=false -auto-approve -var-file=~/.config/edge-stack/terraform/terraform.tfvars
```

`terraform-cloudflare/` は cloudflare プロバイダ `~> 5.22` を前提としています。
v4 から移行する場合は state の移行が必要です。手順は `docs/operations.md` の
「Cloudflare プロバイダ v4 → v5 の移行」を参照してください。

## 6. 動作確認

```
make validate
```

## ポータルを使う場合
ローカルポータルから生成/保存/実行を行えます。

```
make portal
```

ブラウザで `http://127.0.0.1:8000` を開き、
「ガイド付き」または「カスタム」から実行してください。
