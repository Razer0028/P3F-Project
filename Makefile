SHELL := /bin/bash
PROJECT_SLUG ?= edge-stack
CONFIG_DIR ?= $(HOME)/.config/$(PROJECT_SLUG)
ANSIBLE := ANSIBLE_CONFIG=./ansible.cfg ansible-playbook -i $(CONFIG_DIR)/ansible/hosts.ini ansible/site.yml
TF_DIR := terraform
TF_CF_DIR := terraform-cloudflare
TF_VARS := $(CONFIG_DIR)/terraform/terraform.tfvars
TF_CF_VARS := $(CONFIG_DIR)/terraform-cloudflare/terraform.tfvars

bootstrap:
	$(ANSIBLE)

validate:
	./scripts/validate.sh

tf-init:
	cd $(TF_DIR) && terraform init

tf-validate:
	cd $(TF_DIR) && terraform validate

tf-plan:
	cd $(TF_DIR) && terraform plan -var-file=$(TF_VARS)

tf-apply:
	cd $(TF_DIR) && terraform apply -auto-approve -input=false -var-file=$(TF_VARS)

tf-destroy:
	cd $(TF_DIR) && terraform destroy -auto-approve -input=false -var-file=$(TF_VARS)

tf-cf-init:
	cd $(TF_CF_DIR) && terraform init

tf-cf-validate:
	cd $(TF_CF_DIR) && terraform validate

tf-cf-plan:
	cd $(TF_CF_DIR) && terraform plan -var-file=$(TF_CF_VARS)

tf-cf-apply:
	cd $(TF_CF_DIR) && terraform apply -auto-approve -input=false -var-file=$(TF_CF_VARS)

tf-cf-destroy:
	cd $(TF_CF_DIR) && terraform destroy -auto-approve -input=false -var-file=$(TF_CF_VARS)

deploy:
	$(MAKE) tf-apply
	$(MAKE) bootstrap

destroy:
	$(MAKE) tf-destroy

deploy-onprem:
	$(ANSIBLE) -l onprem

deploy-vps:
	$(ANSIBLE) -l vps

deploy-ec2:
	$(ANSIBLE) -l ec2

portal:
	@token=$$(openssl rand -hex 8); \
	echo "Upload token: $$token"; \
	echo "Open http://127.0.0.1:8000 in your browser"; \
	PORTAL_UPLOAD_TOKEN=$$token python3 portal/server.py --bind 127.0.0.1 --port 8000

portal-lan:
	@token=$$(openssl rand -hex 8); \
	echo "Upload token: $$token"; \
	echo "Open http://<server-lan-ip>:8000 in your browser"; \
	PORTAL_UPLOAD_TOKEN=$$token python3 portal/server.py --bind 0.0.0.0 --port 8000
