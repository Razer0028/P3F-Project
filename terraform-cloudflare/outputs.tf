output "zone_id" {
  description = "ゾーン ID"
  value       = local.zone_id
}

output "zone_name" {
  description = "ゾーン名（ドメイン）"
  value       = local.zone_name
}

output "zone_name_servers" {
  description = "Cloudflare から割り当てられたネームサーバー"
  value       = local.zone_name_servers
}

output "failover_record_id" {
  description = "フェイルオーバー A レコードの ID"
  value       = var.cf_manage_failover_record ? cloudflare_dns_record.failover[0].id : null
}

output "failover_record_name" {
  description = "フェイルオーバー A レコード名"
  value       = var.cf_manage_failover_record ? cloudflare_dns_record.failover[0].name : null
}

output "failover_record_value" {
  description = "フェイルオーバー A レコードの現在値"
  value       = var.cf_manage_failover_record ? cloudflare_dns_record.failover[0].content : null
}

output "vps_tunnel_id" {
  description = "VPS 側トンネル ID"
  value       = local.vps_tunnel_enabled ? cloudflare_zero_trust_tunnel_cloudflared.vps[0].id : null
}

output "vps_tunnel_target" {
  description = "VPS 側トンネルの CNAME 先"
  value       = local.vps_tunnel_enabled ? local.vps_tunnel_target : null
}

output "vps_tunnel_credentials_json" {
  description = "cloudflared に配置する credentials JSON（VPS）"
  value       = local.vps_tunnel_credentials
  sensitive   = true
}

output "ec2_tunnel_id" {
  description = "EC2 側トンネル ID"
  value       = local.ec2_tunnel_enabled ? cloudflare_zero_trust_tunnel_cloudflared.ec2[0].id : null
}

output "ec2_tunnel_target" {
  description = "EC2 側トンネルの CNAME 先"
  value       = local.ec2_tunnel_enabled ? local.ec2_tunnel_target : null
}

output "ec2_tunnel_credentials_json" {
  description = "cloudflared に配置する credentials JSON（EC2）"
  value       = local.ec2_tunnel_credentials
  sensitive   = true
}
