# Cloudflared setup (public guide)

This project expects cloudflared to run on VPS and EC2. Secrets must be stored
in Ansible Vault (do not commit).

## 1) Create a tunnel

Create a tunnel in Cloudflare and download the credentials JSON.

You will need:
- Tunnel ID
- credentials JSON file
- One or more hostnames for ingress

## 2) Prepare Vault entries

Store these values in the host Vault files:

- cloudflared_config_content
- cloudflared_credentials_path
- cloudflared_credentials_content

Example config content:

  tunnel: <TUNNEL_ID>
  credentials-file: /etc/cloudflared/<TUNNEL_ID>.json
  ingress:
    - hostname: YOUR_DOMAIN
      service: http://127.0.0.1:8080
    - service: http_status:404

Example credentials content (raw JSON):

  {"AccountTag":"...","TunnelSecret":"...","TunnelID":"..."}

## 3) Apply via Ansible

  ANSIBLE_CONFIG=./ansible.cfg ansible-playbook -i ~/.config/edge-stack/ansible/hosts.ini \
    ansible/site.yml -l vps --tags cloudflared

  ANSIBLE_CONFIG=./ansible.cfg ansible-playbook -i ~/.config/edge-stack/ansible/hosts.ini \
    ansible/site.yml -l ec2 --tags cloudflared

## Notes

- If the package install fails, install cloudflared manually and set
  cloudflared_install_if_missing=false in ~/.config/edge-stack/ansible/group_vars/all.yml.
