terraform {
  required_version = ">= 1.9.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2.4"
    }
    # random_id（KeyPair 名の重複回避）で使用。v5 以前は暗黙依存だったが明示宣言する。
    random = {
      source  = "hashicorp/random"
      version = "~> 3.9"
    }
  }
}
