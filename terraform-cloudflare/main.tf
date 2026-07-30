# Cloudflare プロバイダ v5 系を前提とした構成。
# 認証は環境変数 CLOUDFLARE_API_TOKEN から読み込む（tfvars に書かない）。
provider "cloudflare" {}

locals {
  zone_id           = var.cf_zone_mode == "create" ? cloudflare_zone.main[0].id : data.cloudflare_zone.main[0].id
  zone_name         = var.cf_zone_mode == "create" ? cloudflare_zone.main[0].name : data.cloudflare_zone.main[0].name
  zone_name_servers = var.cf_zone_mode == "create" ? cloudflare_zone.main[0].name_servers : data.cloudflare_zone.main[0].name_servers

  vps_tunnel_enabled = var.cf_manage_tunnels && length(trimspace(var.cf_vps_hostname)) > 0
  ec2_tunnel_enabled = var.cf_manage_tunnels && length(trimspace(var.cf_ec2_hostname)) > 0

  vps_tunnel_target = local.vps_tunnel_enabled ? "${cloudflare_zero_trust_tunnel_cloudflared.vps[0].id}.cfargotunnel.com" : ""
  ec2_tunnel_target = local.ec2_tunnel_enabled ? "${cloudflare_zero_trust_tunnel_cloudflared.ec2[0].id}.cfargotunnel.com" : ""

  # cloudflared に渡す credentials JSON。TunnelSecret は base64 のまま保持する。
  vps_tunnel_credentials = local.vps_tunnel_enabled ? jsonencode({
    AccountTag   = var.cf_account_id
    TunnelID     = cloudflare_zero_trust_tunnel_cloudflared.vps[0].id
    TunnelSecret = base64encode(random_password.vps_tunnel_secret[0].result)
  }) : ""
  ec2_tunnel_credentials = local.ec2_tunnel_enabled ? jsonencode({
    AccountTag   = var.cf_account_id
    TunnelID     = cloudflare_zero_trust_tunnel_cloudflared.ec2[0].id
    TunnelSecret = base64encode(random_password.ec2_tunnel_secret[0].result)
  }) : ""
}

# ゾーンを新規作成する場合。
# v5 では account_id が account = { id = ... } に、zone が name に変わった。
resource "cloudflare_zone" "main" {
  count   = var.cf_zone_mode == "create" ? 1 : 0
  account = { id = var.cf_account_id }
  name    = var.cf_zone_name
  type    = var.cf_zone_type
}

# 既存ゾーンを参照する場合。v5 では filter で検索する。
data "cloudflare_zone" "main" {
  count = var.cf_zone_mode == "existing" ? 1 : 0
  filter = {
    name    = var.cf_zone_name
    account = { id = var.cf_account_id }
  }
}

# フェイルオーバー用 A レコード。
# 実際の向き先は failover_core が API で書き換えるため content の差分は無視する。
resource "cloudflare_dns_record" "failover" {
  count   = var.cf_manage_failover_record ? 1 : 0
  zone_id = local.zone_id
  name    = var.cf_failover_record_name
  type    = "A"
  content = var.cf_failover_record_value
  ttl     = var.cf_failover_record_ttl
  proxied = var.cf_failover_record_proxied

  lifecycle {
    ignore_changes = [content]
  }
}

resource "random_password" "vps_tunnel_secret" {
  count   = local.vps_tunnel_enabled ? 1 : 0
  length  = 32
  special = false
}

resource "random_password" "ec2_tunnel_secret" {
  count   = local.ec2_tunnel_enabled ? 1 : 0
  length  = 32
  special = false
}

# v5 では secret 属性が tunnel_secret に改名された。
resource "cloudflare_zero_trust_tunnel_cloudflared" "vps" {
  count         = local.vps_tunnel_enabled ? 1 : 0
  account_id    = var.cf_account_id
  name          = var.cf_vps_tunnel_name
  tunnel_secret = base64encode(random_password.vps_tunnel_secret[0].result)
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "ec2" {
  count         = local.ec2_tunnel_enabled ? 1 : 0
  account_id    = var.cf_account_id
  name          = var.cf_ec2_tunnel_name
  tunnel_secret = base64encode(random_password.ec2_tunnel_secret[0].result)
}

resource "cloudflare_dns_record" "vps_tunnel" {
  count   = local.vps_tunnel_enabled ? 1 : 0
  zone_id = local.zone_id
  name    = var.cf_vps_hostname
  type    = "CNAME"
  content = local.vps_tunnel_target
  ttl     = var.cf_tunnel_ttl
  proxied = var.cf_tunnel_proxied
}

resource "cloudflare_dns_record" "ec2_tunnel" {
  count   = local.ec2_tunnel_enabled ? 1 : 0
  zone_id = local.zone_id
  name    = var.cf_ec2_hostname
  type    = "CNAME"
  content = local.ec2_tunnel_target
  ttl     = var.cf_tunnel_ttl
  proxied = var.cf_tunnel_proxied
}
