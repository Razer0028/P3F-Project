variable "aws_region" {
  type        = string
  description = "AWS region"
  default     = "ap-northeast-1"
}

variable "aws_profile" {
  type        = string
  description = "AWS profile name (optional)"
  default     = ""
}

variable "ami_mode" {
  type        = string
  description = "AMI selection mode (manual or auto)"
  default     = "manual"
  validation {
    condition     = contains(["manual", "auto"], var.ami_mode)
    error_message = "ami_mode must be manual or auto."
  }
}

variable "ami_id" {
  type        = string
  description = "AMI ID for EC2 (manual mode)"
  default     = ""
  validation {
    condition     = var.ami_mode != "manual" || length(trimspace(var.ami_id)) > 0
    error_message = "Set ami_id when ami_mode=manual."
  }
}

variable "ami_owners" {
  type        = list(string)
  description = "AMI owners for auto mode"
  default     = []
  validation {
    condition     = var.ami_mode != "auto" || length(var.ami_owners) > 0
    error_message = "Set ami_owners when ami_mode=auto."
  }
}

variable "ami_name_filter" {
  type        = string
  description = "AMI name filter for auto mode"
  default     = ""
  validation {
    condition     = var.ami_mode != "auto" || length(trimspace(var.ami_name_filter)) > 0
    error_message = "Set ami_name_filter when ami_mode=auto."
  }
}

variable "ami_architecture" {
  type        = string
  description = "AMI architecture filter for auto mode"
  default     = "arm64"
}

variable "ami_virtualization_type" {
  type        = string
  description = "AMI virtualization type for auto mode"
  default     = "hvm"
}

variable "ami_root_device_type" {
  type        = string
  description = "AMI root device type for auto mode"
  default     = "ebs"
}

variable "vpc_mode" {
  type        = string
  description = "VPC configuration mode (auto or custom)"
  default     = "auto"
  validation {
    condition     = contains(["auto", "custom"], var.vpc_mode)
    error_message = "vpc_mode must be auto or custom."
  }
}

variable "vpc_cidr" {
  type        = string
  description = "VPC CIDR (required if vpc_mode=custom)"
  default     = ""
  validation {
    condition     = var.vpc_mode != "custom" || length(trimspace(var.vpc_cidr)) > 0
    error_message = "Set vpc_cidr when vpc_mode=custom."
  }
}

variable "public_subnet_cidr" {
  type        = string
  description = "Public subnet CIDR (required if vpc_mode=custom)"
  default     = ""
  validation {
    condition     = var.vpc_mode != "custom" || length(trimspace(var.public_subnet_cidr)) > 0
    error_message = "Set public_subnet_cidr when vpc_mode=custom."
  }
}

variable "public_subnet_az" {
  type        = string
  description = "Availability zone for public subnet (optional)"
  default     = ""
}

variable "instance_type" {
  type        = string
  description = "EC2 instance type"
  default     = "t4g.medium"
}

variable "key_name" {
  type        = string
  description = "EC2 key pair name"
}

variable "key_pair_mode" {
  type        = string
  description = "Key pair mode (existing or create)"
  default     = "existing"
  validation {
    condition     = contains(["existing", "create"], var.key_pair_mode)
    error_message = "key_pair_mode must be existing or create."
  }
}

variable "key_pair_public_key" {
  type        = string
  description = "Public key material when creating a KeyPair"
  default     = ""
  validation {
    condition     = var.key_pair_mode != "create" || length(trimspace(var.key_pair_public_key)) > 0
    error_message = "Set key_pair_public_key when key_pair_mode=create."
  }
}

variable "source_dest_check" {
  type        = bool
  description = "Enable EC2 source/destination check (disable for routing)"
  default     = false
}

variable "instance_name" {
  type        = string
  description = "Instance name tag"
  default     = "ec2-edge"
}

variable "associate_eip" {
  type        = bool
  description = "Attach Elastic IP"
  default     = true
}

variable "allowed_ssh_cidrs" {
  type        = list(string)
  description = "CIDR blocks allowed for SSH"
  validation {
    condition     = length(var.allowed_ssh_cidrs) > 0
    error_message = "Set allowed_ssh_cidrs to your admin IP range."
  }
}

variable "allowed_udp_ports" {
  type        = list(number)
  description = "Allowed UDP ports"
  default     = [51820]
}

variable "allowed_tcp_ports" {
  type        = list(number)
  description = "Allowed TCP ports"
  default     = [22]
}

variable "tags" {
  type        = map(string)
  description = "Extra tags for resources"
  default     = {}
}

variable "create_failover_iam" {
  type        = bool
  description = "Create IAM user + access key for failover EC2 start/stop"
  default     = true
}

variable "failover_iam_user_name" {
  type        = string
  description = "IAM user name for failover operations"
  default     = "edge-failover"
}

variable "failover_iam_policy_name" {
  type        = string
  description = "IAM policy name for failover operations"
  default     = "edge-failover-policy"
}
