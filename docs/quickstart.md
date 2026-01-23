# クイックスタート

## 前提
- VPS/EC2 のアカウント作成と OS セットアップが完了している
- Cloudflare アカウントと管理対象ドメインがある
- SSH 鍵が準備済み（鍵名は ~/.ssh、通常は /root/.ssh に配置）

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

## 4. 反映（Ansible）
最初は base を適用し、その後必要なロールを適用します。

```
ANSIBLE_CONFIG=./ansible.cfg ansible-playbook -i ~/.config/edge-stack/ansible/hosts.ini ansible/site.yml --tags base
ANSIBLE_CONFIG=./ansible.cfg ansible-playbook -i ~/.config/edge-stack/ansible/hosts.ini ansible/site.yml -l vps
ANSIBLE_CONFIG=./ansible.cfg ansible-playbook -i ~/.config/edge-stack/ansible/hosts.ini ansible/site.yml -l ec2
ANSIBLE_CONFIG=./ansible.cfg ansible-playbook -i ~/.config/edge-stack/ansible/hosts.ini ansible/site.yml -l onprem
```

## 5. Terraform（EC2 を IaC 化する場合）

```
cd terraform
terraform init
terraform plan -var-file=~/.config/edge-stack/terraform/terraform.tfvars
terraform apply -input=false -auto-approve -var-file=~/.config/edge-stack/terraform/terraform.tfvars
```

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
