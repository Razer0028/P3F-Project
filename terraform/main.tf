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

locals {
  auto_vpc_cidr           = "10.20.0.0/16"
  auto_public_subnet_cidr = "10.20.10.0/24"

  vpc_cidr           = var.vpc_mode == "custom" && var.vpc_cidr != "" ? var.vpc_cidr : local.auto_vpc_cidr
  public_subnet_cidr = var.vpc_mode == "custom" && var.public_subnet_cidr != "" ? var.public_subnet_cidr : local.auto_public_subnet_cidr
  public_subnet_az   = var.public_subnet_az != "" ? var.public_subnet_az : data.aws_availability_zones.available.names[0]
  resolved_ami_id    = var.ami_mode == "auto" ? data.aws_ami.selected[0].id : var.ami_id
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
  count      = var.key_pair_mode == "create" ? 1 : 0
  key_name   = var.key_name
  public_key = var.key_pair_public_key

  tags = merge(var.tags, {
    Name = "${var.instance_name}-key"
  })
}

resource "aws_instance" "edge" {
  ami                         = local.resolved_ami_id
  instance_type               = var.instance_type
  key_name                    = var.key_pair_mode == "create" ? aws_key_pair.edge[0].key_name : var.key_name
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
  count = var.create_failover_iam ? 1 : 0

  statement {
    actions   = ["ec2:DescribeInstances, ec2:DescribeInstanceStatus"]
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
  count = var.create_failover_iam ? 1 : 0
  name  = var.failover_iam_user_name

  tags = merge(var.tags, {
    Name = "${var.instance_name}-failover-user"
  })
}

resource "aws_iam_policy" "failover" {
  count  = var.create_failover_iam ? 1 : 0
  name   = var.failover_iam_policy_name
  policy = data.aws_iam_policy_document.failover[0].json
}

resource "aws_iam_user_policy_attachment" "failover" {
  count      = var.create_failover_iam ? 1 : 0
  user       = aws_iam_user.failover[0].name
  policy_arn = aws_iam_policy.failover[0].arn
}

resource "aws_iam_access_key" "failover" {
  count = var.create_failover_iam ? 1 : 0
  user  = aws_iam_user.failover[0].name
}
