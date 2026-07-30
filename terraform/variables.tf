variable "aws_region" {
  type        = string
  description = "AWS リージョン"
  default     = "ap-northeast-1"
}

variable "aws_profile" {
  type        = string
  description = "使用する AWS プロファイル名（任意）"
  default     = ""
}

variable "ami_mode" {
  type        = string
  description = "AMI の選び方（manual=IDを直接指定 / auto=条件検索）"
  default     = "manual"
  validation {
    condition     = contains(["manual", "auto"], var.ami_mode)
    error_message = "ami_mode は manual または auto を指定してください。"
  }
}

variable "ami_id" {
  type        = string
  description = "EC2 に使う AMI ID（ami_mode=manual のとき必須）"
  default     = ""
  validation {
    condition     = var.ami_mode != "manual" || length(trimspace(var.ami_id)) > 0
    error_message = "ami_mode=manual の場合は ami_id を指定してください。"
  }
}

variable "ami_owners" {
  type        = list(string)
  description = "AMI 検索時の所有者アカウント（ami_mode=auto のとき必須）"
  default     = []
  validation {
    condition     = var.ami_mode != "auto" || length(var.ami_owners) > 0
    error_message = "ami_mode=auto の場合は ami_owners を指定してください。"
  }
}

variable "ami_name_filter" {
  type        = string
  description = "AMI 検索時の名前フィルタ（ami_mode=auto のとき必須）"
  default     = ""
  validation {
    condition     = var.ami_mode != "auto" || length(trimspace(var.ami_name_filter)) > 0
    error_message = "ami_mode=auto の場合は ami_name_filter を指定してください。"
  }
}

variable "ami_architecture" {
  type        = string
  description = "AMI 検索時のアーキテクチャ（auto 用）"
  default     = "arm64"
}

variable "ami_virtualization_type" {
  type        = string
  description = "AMI 検索時の仮想化方式（auto 用）"
  default     = "hvm"
}

variable "ami_root_device_type" {
  type        = string
  description = "AMI 検索時のルートデバイス種別（auto 用）"
  default     = "ebs"
}

variable "vpc_mode" {
  type        = string
  description = "VPC の CIDR 設定方法（auto=既定値 / custom=手動指定）"
  default     = "auto"
  validation {
    condition     = contains(["auto", "custom"], var.vpc_mode)
    error_message = "vpc_mode は auto または custom を指定してください。"
  }
}

variable "vpc_cidr" {
  type        = string
  description = "VPC の CIDR（vpc_mode=custom のとき必須）"
  default     = ""
  validation {
    condition     = var.vpc_mode != "custom" || length(trimspace(var.vpc_cidr)) > 0
    error_message = "vpc_mode=custom の場合は vpc_cidr を指定してください。"
  }
}

variable "public_subnet_cidr" {
  type        = string
  description = "パブリックサブネットの CIDR（vpc_mode=custom のとき必須）"
  default     = ""
  validation {
    condition     = var.vpc_mode != "custom" || length(trimspace(var.public_subnet_cidr)) > 0
    error_message = "vpc_mode=custom の場合は public_subnet_cidr を指定してください。"
  }
}

variable "public_subnet_az" {
  type        = string
  description = "パブリックサブネットのアベイラビリティゾーン（任意。未指定なら先頭のAZ）"
  default     = ""
}

variable "instance_type" {
  type        = string
  description = "EC2 インスタンスタイプ"
  default     = "t4g.medium"
}

variable "key_name" {
  type        = string
  description = "EC2 キーペア名"
}

variable "key_pair_mode" {
  type        = string
  description = "キーペアの扱い（existing=既存を使う / create=新規作成 / auto=無ければ作成）"
  default     = "existing"
  validation {
    condition     = contains(["existing", "create", "auto"], var.key_pair_mode)
    error_message = "key_pair_mode は existing / create / auto のいずれかを指定してください。"
  }
}

variable "key_pair_public_key" {
  type        = string
  description = "キーペア作成時に登録する公開鍵の内容"
  default     = ""
  validation {
    condition     = !(var.key_pair_mode == "create" || var.key_pair_mode == "auto") || length(trimspace(var.key_pair_public_key)) > 0
    error_message = "key_pair_mode が create または auto の場合は key_pair_public_key を指定してください。"
  }
}

variable "source_dest_check" {
  type        = bool
  description = "EC2 の送信元/宛先チェック（ルーティングさせる場合は false）"
  default     = false
}

variable "instance_name" {
  type        = string
  description = "インスタンスの Name タグ"
  default     = "ec2-edge"
}

variable "associate_eip" {
  type        = bool
  description = "Elastic IP を割り当てるか"
  default     = true
}

variable "allowed_ssh_cidrs" {
  type        = list(string)
  description = "SSH を許可する CIDR（管理元 IP に絞ることを推奨）"
  default     = ["0.0.0.0/0"]
  validation {
    condition     = length(var.allowed_ssh_cidrs) > 0
    error_message = "allowed_ssh_cidrs に管理元の IP レンジを指定してください。"
  }
}

variable "allowed_udp_ports" {
  type        = list(number)
  description = "許可する UDP ポート"
  default     = [51820]
}

variable "allowed_tcp_ports" {
  type        = list(number)
  description = "許可する TCP ポート"
  default     = [22]
}

variable "tags" {
  type        = map(string)
  description = "全リソースに付与する追加タグ"
  default     = {}
}

variable "create_failover_iam" {
  type        = bool
  description = "フェイルオーバー用（EC2 起動/停止）の IAM ユーザーとアクセスキーを作成するか"
  default     = true
}

variable "failover_iam_user_name" {
  type        = string
  description = "フェイルオーバー用 IAM ユーザー名"
  default     = "edge-failover"
}

variable "failover_iam_policy_name" {
  type        = string
  description = "フェイルオーバー用 IAM ポリシー名"
  default     = "edge-failover-policy"
}

variable "failover_access_key_id" {
  type        = string
  description = "既存のアクセスキー ID を使う場合に指定（任意）"
  default     = ""
  validation {
    condition     = (length(trimspace(var.failover_access_key_id)) == 0) == (length(trimspace(var.failover_secret_access_key)) == 0)
    error_message = "failover_access_key_id と failover_secret_access_key は両方指定するか、両方空にしてください。"
  }
}

variable "failover_secret_access_key" {
  type        = string
  description = "既存のシークレットアクセスキーを使う場合に指定（任意）"
  default     = ""
  sensitive   = true
}
