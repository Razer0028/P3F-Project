output "zone_id" {
  value = local.zone_id
}

output "zone_name" {
  value = local.zone_name
}

output "zone_name_servers" {
  value = local.zone_name_servers
}

output "failover_record_id" {
  value = var.cf_manage_failover_record ? cloudflare_record.failover[0].id : null
}

output "failover_record_name" {
  value = var.cf_manage_failover_record ? cloudflare_record.failover[0].name : null
}

output "failover_record_value" {
  value = var.cf_manage_failover_record ? cloudflare_record.failover[0].content : null
}

output "vps_tunnel_id" {
  value = local.vps_tunnel_enabled ? cloudflare_zero_trust_tunnel_cloudflared.vps[0].id : null
}

output "vps_tunnel_target" {
  value = local.vps_tunnel_enabled ? local.vps_tunnel_target : null
}

output "vps_tunnel_credentials_json" {
  value     = local.vps_tunnel_credentials
  sensitive = true
}

output "ec2_tunnel_id" {
  value = local.ec2_tunnel_enabled ? cloudflare_zero_trust_tunnel_cloudflared.ec2[0].id : null
}

output "ec2_tunnel_target" {
  value = local.ec2_tunnel_enabled ? local.ec2_tunnel_target : null
}

output "ec2_tunnel_credentials_json" {
  value     = local.ec2_tunnel_credentials
  sensitive = true
}
