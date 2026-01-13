variable "cf_account_id" {
  type        = string
  description = "Cloudflare account ID"
}

variable "cf_zone_name" {
  type        = string
  description = "Zone name (YOUR_DOMAIN)"
  validation {
    condition     = length(trimspace(var.cf_zone_name)) > 0
    error_message = "cf_zone_name must be set."
  }
}

variable "cf_zone_mode" {
  type        = string
  description = "Zone mode (create or existing)"
  default     = "create"
  validation {
    condition     = contains(["create", "existing"], var.cf_zone_mode)
    error_message = "cf_zone_mode must be create or existing."
  }
}

variable "cf_zone_plan" {
  type        = string
  description = "Cloudflare plan (free/pro/etc)"
  default     = "free"
}

variable "cf_zone_type" {
  type        = string
  description = "Zone type (full/partial)"
  default     = "full"
}

variable "cf_manage_failover_record" {
  type        = bool
  description = "Manage the failover A record"
  default     = false
}

variable "cf_failover_record_name" {
  type        = string
  description = "Failover record name (FQDN)"
  default     = ""
  validation {
    condition     = !var.cf_manage_failover_record || length(trimspace(var.cf_failover_record_name)) > 0
    error_message = "cf_failover_record_name must be set when cf_manage_failover_record is true."
  }
}

variable "cf_failover_record_value" {
  type        = string
  description = "Initial IP for failover record"
  default     = ""
  validation {
    condition     = !var.cf_manage_failover_record || length(trimspace(var.cf_failover_record_value)) > 0
    error_message = "cf_failover_record_value must be set when cf_manage_failover_record is true."
  }
}

variable "cf_failover_record_proxied" {
  type        = bool
  description = "Proxy the failover record"
  default     = false
}

variable "cf_failover_record_ttl" {
  type        = number
  description = "TTL for failover record (1=auto)"
  default     = 1
}

variable "cf_manage_tunnels" {
  type        = bool
  description = "Manage Cloudflare tunnels"
  default     = false
  validation {
    condition     = !var.cf_manage_tunnels || length(trimspace(var.cf_vps_hostname)) > 0 || length(trimspace(var.cf_ec2_hostname)) > 0
    error_message = "Set cf_vps_hostname or cf_ec2_hostname when cf_manage_tunnels is true."
  }
}

variable "cf_vps_tunnel_name" {
  type        = string
  description = "Tunnel name for VPS"
  default     = ""
  validation {
    condition     = !var.cf_manage_tunnels || length(trimspace(var.cf_vps_hostname)) == 0 || length(trimspace(var.cf_vps_tunnel_name)) > 0
    error_message = "Set cf_vps_tunnel_name when cf_manage_tunnels is true and cf_vps_hostname is set."
  }
}

variable "cf_ec2_tunnel_name" {
  type        = string
  description = "Tunnel name for EC2"
  default     = ""
  validation {
    condition     = !var.cf_manage_tunnels || length(trimspace(var.cf_ec2_hostname)) == 0 || length(trimspace(var.cf_ec2_tunnel_name)) > 0
    error_message = "Set cf_ec2_tunnel_name when cf_manage_tunnels is true and cf_ec2_hostname is set."
  }
}

variable "cf_vps_hostname" {
  type        = string
  description = "VPS tunnel hostname (FQDN)"
  default     = ""
}

variable "cf_ec2_hostname" {
  type        = string
  description = "EC2 tunnel hostname (FQDN)"
  default     = ""
}

variable "cf_tunnel_proxied" {
  type        = bool
  description = "Proxy tunnel DNS records"
  default     = true
}

variable "cf_tunnel_ttl" {
  type        = number
  description = "TTL for tunnel records (1=auto)"
  default     = 1
}
