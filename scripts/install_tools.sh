#!/usr/bin/env bash
set -euo pipefail

if ! command -v apt-get >/dev/null 2>&1; then
  echo "apt-get が利用できません。ツールを手動でインストールしてください。" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

check_nameserver() {
  if ! grep -qE '^\s*nameserver\s+' /etc/resolv.conf 2>/dev/null; then
    echo "/etc/resolv.conf に nameserver の設定が見つかりません。" >&2
    return 1
  fi
  return 0
}

check_dns() {
  local host="$1"
  if ! getent ahosts "$host" >/dev/null 2>&1; then
    echo "${host} の DNS 名前解決に失敗しました。" >&2
    return 1
  fi
  return 0
}

ensure_fallback_dns() {
  local head_dir="/etc/resolvconf/resolv.conf.d"
  local head_file="${head_dir}/head"
  if [ ! -d "${head_dir}" ]; then
    mkdir -p "${head_dir}"
  fi
  if ! grep -qE '^\s*nameserver\s+' "${head_file}" 2>/dev/null; then
    printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" >> "${head_file}"
  fi
  if command -v resolvconf >/dev/null 2>&1; then
    resolvconf -u || true
  fi
}

ensure_dns_or_exit() {
  local host="$1"
  if check_nameserver && check_dns "${host}"; then
    return 0
  fi
  echo "フォールバック DNS を適用します..." >&2
  ensure_fallback_dns
  if check_nameserver && check_dns "${host}"; then
    return 0
  fi
  echo "${host} の DNS 名前解決に失敗しています。/etc/resolv.conf またはネットワーク設定を修正して再実行してください。" >&2
  exit 1
}

ensure_dns_or_exit "deb.debian.org"

required_packages=(
  ansible
  openssh-client
  python3
  python3-venv
  python3-pip
  wireguard
  wireguard-tools
  resolvconf
  curl
  gnupg
  lsb-release
  ca-certificates
)

apt-get update -y
apt-get install -y "${required_packages[@]}"

# Ansible コレクションの導入。
# ansible（バンドル版）には同梱されているが、ansible-core だけの環境では別途必要になる。
# requirements.yml が無い場合や取得に失敗した場合でも、ここでは処理を止めない。
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ansible_requirements="${repo_root}/ansible/requirements.yml"
if [ ! -f "${ansible_requirements}" ]; then
  echo "${ansible_requirements} が見つからないため、Ansible コレクションの導入をスキップします。" >&2
elif ! command -v ansible-galaxy >/dev/null 2>&1; then
  echo "ansible-galaxy が見つからないため、Ansible コレクションの導入をスキップします。" >&2
else
  echo "Ansible コレクションをインストールします: ${ansible_requirements}"
  if ! ansible-galaxy collection install -r "${ansible_requirements}"; then
    echo "Ansible コレクションのインストールに失敗しました。ネットワークを確認し、'ansible-galaxy collection install -r ansible/requirements.yml' を手動で実行してください。" >&2
  fi
fi

if ! command -v terraform >/dev/null 2>&1; then
  ensure_dns_or_exit "apt.releases.hashicorp.com"
  echo "Terraform が見つかりません。HashiCorp のリポジトリを追加します..."
  install -m 0755 -d /usr/share/keyrings
  tmp_key=$(mktemp)
  curl_opts=(--fail --silent --show-error --location --retry 3 --retry-connrefused --connect-timeout 5 --max-time 20)
  if ! curl "${curl_opts[@]}" https://apt.releases.hashicorp.com/gpg -o "${tmp_key}"; then
    echo "HashiCorp の GPG 鍵の取得に失敗しました（ネットワーク/DNS）。ネットワークを修正して再実行してください。" >&2
    rm -f "${tmp_key}"
    exit 1
  fi
  gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg "${tmp_key}"
  rm -f "${tmp_key}"
  chmod 0644 /usr/share/keyrings/hashicorp-archive-keyring.gpg
  release=$(lsb_release -cs)
  echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com ${release} main" > /etc/apt/sources.list.d/hashicorp.list
  apt-get update -y
  apt-get install -y terraform
else
  echo "Terraform は既にインストールされています。"
fi

echo "ツールのインストールが完了しました。"
