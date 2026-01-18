output "instance_id" {
  value = aws_instance.edge.id
}

output "public_ip" {
  value = var.associate_eip ? aws_eip.edge[0].public_ip : aws_instance.edge.public_ip
}

output "public_dns" {
  value = aws_instance.edge.public_dns
}

output "security_group_id" {
  value = aws_security_group.edge.id
}

output "vpc_id" {
  value = aws_vpc.edge.id
}

output "public_subnet_id" {
  value = aws_subnet.public.id
}

output "public_subnet_az" {
  value = aws_subnet.public.availability_zone
}

output "internet_gateway_id" {
  value = aws_internet_gateway.edge.id
}

output "route_table_id" {
  value = aws_route_table.public.id
}

output "key_pair_name" {
  value = local.key_pair_name
}

output "elastic_ip" {
  value = var.associate_eip ? aws_eip.edge[0].public_ip : null
}

output "failover_iam_user_name" {
  value = var.create_failover_iam ? local.failover_user_name : ""
}

output "failover_access_key_id" {
  value     = local.failover_access_key_id_value
  sensitive = true
}

output "failover_secret_access_key" {
  value     = local.failover_secret_access_key_value
  sensitive = true
}
