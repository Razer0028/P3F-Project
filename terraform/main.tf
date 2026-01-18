provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile != "" ? var.aws_profile : null
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "selected" {
  count       = var.ami_mode == "auto" ? 1 : 0
  most_recent = true
  owners      = var.ami_owners

  filter {
    name   = "name"
    values = [var.ami_name_filter]
  }

  filter {
    name   = "architecture"
    values = [var.ami_architecture]
  }

  filter {
    name   = "virtualization-type"
    values = [var.ami_virtualization_type]
  }

  filter {
    name   = "root-device-type"
    values = [var.ami_root_device_type]
  }
}

data "external" "key_pair_lookup" {
  count   = var.key_pair_mode == "auto" ? 1 : 0
  program = ["python3", "${path.module}/scripts/aws_lookup.py"]
  query = {
    kind    = "key_pair"
    name    = var.key_name
    region  = var.aws_region
    profile = var.aws_profile
  }
}

data "external" "failover_user_lookup" {
  count   = var.create_failover_iam ? 1 : 0
  program = ["python3", "${path.module}/scripts/aws_lookup.py"]
  query = {
    kind    = "iam_user"
    name    = var.failover_iam_user_name
    region  = var.aws_region
    profile = var.aws_profile
  }
}

data "external" "failover_policy_lookup" {
  count   = var.create_failover_iam ? 1 : 0
  program = ["python3", "${path.module}/scripts/aws_lookup.py"]
  query = {
    kind    = "iam_policy"
    name    = var.failover_iam_policy_name
    region  = var.aws_region
    profile = var.aws_profile
  }
}

data "external" "failover_access_keys_lookup" {
  count   = var.create_failover_iam ? 1 : 0
  program = ["python3", "${path.module}/scripts/aws_lookup.py"]
  query = {
    kind    = "iam_access_keys"
    name    = var.failover_iam_user_name
    region  = var.aws_region
    profile = var.aws_profile
  }
}

resource "random_id" "key_pair_suffix" {
  count       = var.key_pair_mode == "auto" ? 1 : 0
  byte_length = 3
  keepers = {
    key_name   = var.key_name
    public_key = var.key_pair_public_key
  }
}

locals {
  auto_vpc_cidr           = "10.20.0.0/16"
  auto_public_subnet_cidr = "10.20.10.0/24"

  vpc_cidr           = var.vpc_mode == "custom" && var.vpc_cidr != "" ? var.vpc_cidr : local.auto_vpc_cidr
  public_subnet_cidr = var.vpc_mode == "custom" && var.public_subnet_cidr != "" ? var.public_subnet_cidr : local.auto_public_subnet_cidr
  public_subnet_az   = var.public_subnet_az != "" ? var.public_subnet_az : data.aws_availability_zones.available.names[0]
  resolved_ami_id    = var.ami_mode == "auto" ? data.aws_ami.selected[0].id : var.ami_id

  key_pair_exists = (
    var.key_pair_mode == "auto"
    ? try(data.external.key_pair_lookup[0].result.exists, "false") == "true"
    : false
  )
  key_pair_auto_suffix = (
    var.key_pair_mode == "auto" && local.key_pair_exists
    ? "-${random_id.key_pair_suffix[0].hex}"
    : ""
  )
  key_pair_auto_name = var.key_pair_mode == "auto" ? "${var.key_name}${local.key_pair_auto_suffix}" : var.key_name
  key_pair_create    = var.key_pair_mode == "create" || var.key_pair_mode == "auto"
  key_pair_name      = local.key_pair_create ? aws_key_pair.edge[0].key_name : var.key_name

  failover_user_exists = (
    var.create_failover_iam
    ? try(data.external.failover_user_lookup[0].result.exists, "false") == "true"
    : false
  )
  create_failover_user = var.create_failover_iam && !local.failover_user_exists
  failover_user_name = (
    var.create_failover_iam
    ? (local.create_failover_user ? aws_iam_user.failover[0].name : var.failover_iam_user_name)
    : ""
  )

  failover_policy_existing_arn = var.create_failover_iam ? try(data.external.failover_policy_lookup[0].result.arn, "") : ""
  failover_policy_exists       = var.create_failover_iam && local.failover_policy_existing_arn != ""
  create_failover_policy       = var.create_failover_iam && !local.failover_policy_exists
  failover_policy_arn = (
    var.create_failover_iam
    ? (local.create_failover_policy ? aws_iam_policy.failover[0].arn : local.failover_policy_existing_arn)
    : ""
  )

  failover_access_key_provided = length(trimspace(var.failover_access_key_id)) > 0 || length(trimspace(var.failover_secret_access_key)) > 0
  failover_access_keys_count = (
    var.create_failover_iam
    ? try(tonumber(data.external.failover_access_keys_lookup[0].result.count), 0)
    : 0
  )
  failover_access_keys_exist  = var.create_failover_iam && local.failover_access_keys_count > 0
  failover_access_key_create  = var.create_failover_iam && !local.failover_access_key_provided && !local.failover_access_keys_exist
  failover_access_key_id_value = (
    local.failover_access_key_provided
    ? var.failover_access_key_id
    : (var.create_failover_iam ? try(aws_iam_access_key.failover[0].id, "") : "")
  )
  failover_secret_access_key_value = (
    local.failover_access_key_provided
    ? var.failover_secret_access_key
    : (var.create_failover_iam ? try(aws_iam_access_key.failover[0].secret, "") : "")
  )
}

resource "aws_vpc" "edge" {
  cidr_block           = local.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(var.tags, {
    Name = "${var.instance_name}-vpc"
  })
}

resource "aws_internet_gateway" "edge" {
  vpc_id = aws_vpc.edge.id

  tags = merge(var.tags, {
    Name = "${var.instance_name}-igw"
  })
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.edge.id
  cidr_block              = local.public_subnet_cidr
  availability_zone       = local.public_subnet_az
  map_public_ip_on_launch = true

  tags = merge(var.tags, {
    Name = "${var.instance_name}-public"
  })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.edge.id

  tags = merge(var.tags, {
    Name = "${var.instance_name}-public-rt"
  })
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.edge.id
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "edge" {
  name        = "${var.instance_name}-sg"
  description = "Security group for edge node"
  vpc_id      = aws_vpc.edge.id

  tags = merge(var.tags, {
    Name = "${var.instance_name}-sg"
  })
}

resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  security_group_id = aws_security_group.edge.id
  protocol          = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_blocks       = var.allowed_ssh_cidrs
  description       = "SSH"
}

resource "aws_security_group_rule" "udp" {
  for_each          = { for p in var.allowed_udp_ports : tostring(p) => p }
  type              = "ingress"
  security_group_id = aws_security_group.edge.id
  protocol          = "udp"
  from_port         = each.value
  to_port           = each.value
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "UDP ${each.value}"
}

resource "aws_security_group_rule" "tcp" {
  for_each          = { for p in var.allowed_tcp_ports : tostring(p) => p if p != 22 }
  type              = "ingress"
  security_group_id = aws_security_group.edge.id
  protocol          = "tcp"
  from_port         = each.value
  to_port           = each.value
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "TCP ${each.value}"
}

resource "aws_security_group_rule" "egress_all" {
  type              = "egress"
  security_group_id = aws_security_group.edge.id
  protocol          = "-1"
  from_port         = 0
  to_port           = 0
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "Allow all egress"
}

resource "aws_key_pair" "edge" {
  count      = local.key_pair_create ? 1 : 0
  key_name   = var.key_pair_mode == "auto" ? local.key_pair_auto_name : var.key_name
  public_key = var.key_pair_public_key

  tags = merge(var.tags, {
    Name = "${var.instance_name}-key"
  })

  lifecycle {
    precondition {
      condition     = length(trimspace(var.key_pair_public_key)) > 0
      error_message = "Set key_pair_public_key when key_pair_mode=create or auto."
    }
  }
}

resource "aws_instance" "edge" {
  ami                         = local.resolved_ami_id
  instance_type               = var.instance_type
  key_name                    = local.key_pair_name
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.edge.id]
  associate_public_ip_address = true
  source_dest_check           = var.source_dest_check

  tags = merge(var.tags, {
    Name = var.instance_name
  })
}

resource "aws_eip" "edge" {
  count    = var.associate_eip ? 1 : 0
  instance = aws_instance.edge.id
  domain   = "vpc"

  tags = merge(var.tags, {
    Name = "${var.instance_name}-eip"
  })
}

data "aws_iam_policy_document" "failover" {
  count = local.create_failover_policy ? 1 : 0

  statement {
    actions   = [
      "ec2:DescribeInstances",
      "ec2:DescribeInstanceStatus",
    ]
    resources = ["*"]
  }

  statement {
    actions = [
      "ec2:StartInstances",
      "ec2:StopInstances",
    ]
    resources = [aws_instance.edge.arn]
  }
}

resource "aws_iam_user" "failover" {
  count = local.create_failover_user ? 1 : 0
  name  = var.failover_iam_user_name

  tags = merge(var.tags, {
    Name = "${var.instance_name}-failover-user"
  })
}

resource "aws_iam_policy" "failover" {
  count  = local.create_failover_policy ? 1 : 0
  name   = var.failover_iam_policy_name
  policy = data.aws_iam_policy_document.failover[0].json
}

resource "aws_iam_user_policy_attachment" "failover" {
  count      = var.create_failover_iam ? 1 : 0
  user       = local.failover_user_name
  policy_arn = local.failover_policy_arn

  lifecycle {
    precondition {
      condition     = local.failover_user_name != "" && local.failover_policy_arn != ""
      error_message = "Failed to resolve failover IAM user or policy."
    }
  }
}

resource "aws_iam_access_key" "failover" {
  count = local.failover_access_key_create ? 1 : 0
  user  = local.failover_user_name

  lifecycle {
    precondition {
      condition     = local.failover_user_name != ""
      error_message = "Failed to resolve failover IAM user."
    }
  }
}
