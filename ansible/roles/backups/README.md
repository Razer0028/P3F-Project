# backups

Manages NAS backup scripts and the hourly game backup cron.

Variables:
- backups_manage: true/false
- backup_full_enabled: true/false
- backup_games_enabled: true/false
- backup_games_cron: "0 * * * *"
- nas_mount: "/mnt/nas"
- backup_root: "/mnt/nas/backup"
- backup_games_root: "/mnt/nas/backup_games"
