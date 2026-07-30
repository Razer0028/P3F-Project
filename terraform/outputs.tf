output "instance_id" {
  description = "EC2 インスタンス ID"
  value       = aws_instance.edge.id
}

output "public_ip" {
  description = "接続に使うグローバル IP（EIP があれば EIP）"
  value       = var.associate_eip ? aws_eip.edge[0].public_ip : aws_instance.edge.public_ip
}

output "public_dns" {
  description = "EC2 のパブリック DNS 名"
  value       = aws_instance.edge.public_dns
}

output "security_group_id" {
  description = "セキュリティグループ ID"
  value       = aws_security_group.edge.id
}

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.edge.id
}

output "public_subnet_id" {
  description = "パブリックサブネット ID"
  value       = aws_subnet.public.id
}

output "public_subnet_az" {
  description = "パブリックサブネットのアベイラビリティゾーン"
  value       = aws_subnet.public.availability_zone
}

output "internet_gateway_id" {
  description = "インターネットゲートウェイ ID"
  value       = aws_internet_gateway.edge.id
}

output "route_table_id" {
  description = "ルートテーブル ID"
  value       = aws_route_table.public.id
}

output "key_pair_name" {
  description = "実際に使用されたキーペア名"
  value       = local.key_pair_name
}

output "elastic_ip" {
  description = "割り当てた Elastic IP（未使用なら null）"
  value       = var.associate_eip ? aws_eip.edge[0].public_ip : null
}

output "failover_iam_user_name" {
  description = "フェイルオーバー用 IAM ユーザー名"
  value       = var.create_failover_iam ? local.failover_user_name : ""
}

output "failover_access_key_id" {
  description = "フェイルオーバー用アクセスキー ID"
  value       = local.failover_access_key_id_value
  sensitive   = true
}

output "failover_secret_access_key" {
  description = "フェイルオーバー用シークレットアクセスキー"
  value       = local.failover_secret_access_key_value
  sensitive   = true
}
