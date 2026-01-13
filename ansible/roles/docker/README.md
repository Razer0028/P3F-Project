# docker

Installs Docker when missing, optionally manages `daemon.json`, and ensures the service is running.

## Variables

- `docker_manage` (default: false)
- `docker_install_if_missing` (default: true)
- `docker_manage_service` (default: true)
- `docker_users` (default: [])
- `docker_manage_daemon_config` (default: false)
- `docker_daemon_config` (default: {})

## Notes

If Docker is already present, install is skipped by default.
