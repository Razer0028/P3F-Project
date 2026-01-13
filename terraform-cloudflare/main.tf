provider "cloudflare" {}

locals {
  zone_id           = var.cf_zone_mode == "create" ? cloudflare_zone.main[0].id : data.cloudflare_zone.main[0].id
  zone_name         = var.cf_zone_mode == "create" ? cloudflare_zone.main[0].zone : data.cloudflare_zone.main[0].name
  zone_name_servers = var.cf_zone_mode == "create" ? cloudflare_zone.main[0].name_servers : data.cloudflare_zone.main[0].name_servers

  vps_tunnel_enabled = var.cf_manage_tunnels && length(trimspace(var.cf_vps_hostname)) > 0
  ec2_tunnel_enabled = var.cf_manage_tunnels && length(trimspace(var.cf_ec2_hostname)) > 0

  vps_tunnel_target = local.vps_tunnel_enabled ? "${cloudflare_zero_trust_tunnel_cloudflared.vps[0].id}.cfargotunnel.com" : ""
  ec2_tunnel_target = local.ec2_tunnel_enabled ? "${cloudflare_zero_trust_tunnel_cloudflared.ec2[0].id}.cfargotunnel.com" : ""

  vps_tunnel_credentials = local.vps_tunnel_enabled ? jsonencode({
    AccountTag   = var.cf_account_id
    TunnelID     = cloudflare_zero_trust_tunnel_cloudflared.vps[0].id
    TunnelSecret = cloudflare_zero_trust_tunnel_cloudflared.vps[0].secret
  }) : ""
  ec2_tunnel_credentials = local.ec2_tunnel_enabled ? jsonencode({
    AccountTag   = var.cf_account_id
    TunnelID     = cloudflare_zero_trust_tunnel_cloudflared.ec2[0].id
    TunnelSecret = cloudflare_zero_trust_tunnel_cloudflared.ec2[0].secret
  }) : ""
}

resource "cloudflare_zone" "main" {
  count      = var.cf_zone_mode == "create" ? 1 : 0
  account_id = var.cf_account_id
  zone       = var.cf_zone_name
  plan       = var.cf_zone_plan
  type       = var.cf_zone_type
}

data "cloudflare_zone" "main" {
  count      = var.cf_zone_mode == "existing" ? 1 : 0
  account_id = var.cf_account_id
  name       = var.cf_zone_name
}

resource "cloudflare_record" "failover" {
  count           = var.cf_manage_failover_record ? 1 : 0
  zone_id         = local.zone_id
  name            = var.cf_failover_record_name
  type            = "A"
  content         = var.cf_failover_record_value
  ttl             = var.cf_failover_record_ttl
  proxied         = var.cf_failover_record_proxied
  allow_overwrite = true

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

resource "cloudflare_zero_trust_tunnel_cloudflared" "vps" {
  count      = local.vps_tunnel_enabled ? 1 : 0
  account_id = var.cf_account_id
  name       = var.cf_vps_tunnel_name
  secret     = base64encode(random_password.vps_tunnel_secret[0].result)

  lifecycle {
    ignore_changes = [secret]
  }
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "ec2" {
  count      = local.ec2_tunnel_enabled ? 1 : 0
  account_id = var.cf_account_id
  name       = var.cf_ec2_tunnel_name
  secret     = base64encode(random_password.ec2_tunnel_secret[0].result)

  lifecycle {
    ignore_changes = [secret]
  }
}

resource "cloudflare_record" "vps_tunnel" {
  count           = local.vps_tunnel_enabled ? 1 : 0
  zone_id         = local.zone_id
  name            = var.cf_vps_hostname
  type            = "CNAME"
  content         = local.vps_tunnel_target
  ttl             = var.cf_tunnel_ttl
  proxied         = var.cf_tunnel_proxied
  allow_overwrite = true
}

resource "cloudflare_record" "ec2_tunnel" {
  count           = local.ec2_tunnel_enabled ? 1 : 0
  zone_id         = local.zone_id
  name            = var.cf_ec2_hostname
  type            = "CNAME"
  content         = local.ec2_tunnel_target
  ttl             = var.cf_tunnel_ttl
  proxied         = var.cf_tunnel_proxied
  allow_overwrite = true
}
