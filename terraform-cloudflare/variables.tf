variable "cf_account_id" {
  type        = string
  description = "Cloudflare アカウント ID"
}

variable "cf_zone_name" {
  type        = string
  description = "ゾーン名（例: example.com）"
  validation {
    condition     = length(trimspace(var.cf_zone_name)) > 0
    error_message = "cf_zone_name を指定してください。"
  }
}

variable "cf_zone_mode" {
  type        = string
  description = "ゾーンの扱い（create=新規作成 / existing=既存を参照）"
  default     = "existing"
  validation {
    condition     = contains(["create", "existing"], var.cf_zone_mode)
    error_message = "cf_zone_mode は create または existing を指定してください。"
  }
}

# 互換性のために残している変数。Cloudflare プロバイダ v5 では cloudflare_zone から
# plan 属性が削除されたため、Terraform ではプランを設定しない。
# プラン変更は Cloudflare ダッシュボード、または cloudflare_zone_subscription リソースで行う。
variable "cf_zone_plan" {
  type        = string
  description = "【未使用】プロバイダ v5 で廃止。既存 tfvars との互換のために残置"
  default     = "free"
}

variable "cf_zone_type" {
  type        = string
  description = "ゾーン種別（full / partial）"
  default     = "full"
}

variable "cf_manage_failover_record" {
  type        = bool
  description = "フェイルオーバー用 A レコードを Terraform で管理するか"
  default     = false
}

variable "cf_failover_record_name" {
  type        = string
  description = "フェイルオーバー用レコード名（FQDN）"
  default     = ""
  validation {
    condition     = !var.cf_manage_failover_record || length(trimspace(var.cf_failover_record_name)) > 0
    error_message = "cf_manage_failover_record が true の場合は cf_failover_record_name を指定してください。"
  }
}

variable "cf_failover_record_value" {
  type        = string
  description = "フェイルオーバー用レコードの初期 IP"
  default     = ""
  validation {
    condition     = !var.cf_manage_failover_record || length(trimspace(var.cf_failover_record_value)) > 0
    error_message = "cf_manage_failover_record が true の場合は cf_failover_record_value を指定してください。"
  }
}

variable "cf_failover_record_proxied" {
  type        = bool
  description = "フェイルオーバー用レコードを Cloudflare プロキシ経由にするか"
  default     = false
}

variable "cf_failover_record_ttl" {
  type        = number
  description = "フェイルオーバー用レコードの TTL（1=自動）"
  default     = 1
  validation {
    condition     = var.cf_failover_record_ttl == 1 || (var.cf_failover_record_ttl >= 30 && var.cf_failover_record_ttl <= 86400)
    error_message = "cf_failover_record_ttl は 1（自動）または 30〜86400 の範囲で指定してください。"
  }
}

variable "cf_manage_tunnels" {
  type        = bool
  description = "Cloudflare Tunnel を Terraform で管理するか"
  default     = false
  validation {
    condition     = !var.cf_manage_tunnels || length(trimspace(var.cf_vps_hostname)) > 0 || length(trimspace(var.cf_ec2_hostname)) > 0
    error_message = "cf_manage_tunnels が true の場合は cf_vps_hostname か cf_ec2_hostname のどちらかを指定してください。"
  }
}

variable "cf_vps_tunnel_name" {
  type        = string
  description = "VPS 側のトンネル名"
  default     = ""
  validation {
    condition     = !var.cf_manage_tunnels || length(trimspace(var.cf_vps_hostname)) == 0 || length(trimspace(var.cf_vps_tunnel_name)) > 0
    error_message = "cf_manage_tunnels が true かつ cf_vps_hostname を指定した場合は cf_vps_tunnel_name も指定してください。"
  }
}

variable "cf_ec2_tunnel_name" {
  type        = string
  description = "EC2 側のトンネル名"
  default     = ""
  validation {
    condition     = !var.cf_manage_tunnels || length(trimspace(var.cf_ec2_hostname)) == 0 || length(trimspace(var.cf_ec2_tunnel_name)) > 0
    error_message = "cf_manage_tunnels が true かつ cf_ec2_hostname を指定した場合は cf_ec2_tunnel_name も指定してください。"
  }
}

variable "cf_vps_hostname" {
  type        = string
  description = "VPS 側トンネルの公開ホスト名（FQDN）"
  default     = ""
}

variable "cf_ec2_hostname" {
  type        = string
  description = "EC2 側トンネルの公開ホスト名（FQDN）"
  default     = ""
}

variable "cf_tunnel_proxied" {
  type        = bool
  description = "トンネル用 DNS レコードを Cloudflare プロキシ経由にするか"
  default     = true
}

variable "cf_tunnel_ttl" {
  type        = number
  description = "トンネル用レコードの TTL（1=自動）"
  default     = 1
  validation {
    condition     = var.cf_tunnel_ttl == 1 || (var.cf_tunnel_ttl >= 30 && var.cf_tunnel_ttl <= 86400)
    error_message = "cf_tunnel_ttl は 1（自動）または 30〜86400 の範囲で指定してください。"
  }
}
