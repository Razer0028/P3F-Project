FROM python:3.11-slim

# 必須パッケージ
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg \
        logrotate cron \
    && rm -rf /var/lib/apt/lists/*

# ===== Docker CLI のインストール =====
RUN install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    chmod a+r /etc/apt/keyrings/docker.gpg && \
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
      https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
      | tee /etc/apt/sources.list.d/docker.list > /dev/null

RUN apt-get update && \
    apt-get install -y docker-ce-cli && \
    rm -rf /var/lib/apt/lists/*

ARG MONITOR_USER=edge
ARG MONITOR_UID=1000
ARG MONITOR_GID=1000
ENV MONITOR_USER=${MONITOR_USER}

# ===== ユーザー作成 =====
RUN set -eux; if ! getent group "${MONITOR_GID}" >/dev/null; then groupadd -g "${MONITOR_GID}" "${MONITOR_USER}"; fi; \
    if ! id -u "${MONITOR_USER}" >/dev/null 2>&1; then useradd -m -u "${MONITOR_UID}" -g "${MONITOR_GID}" "${MONITOR_USER}"; fi; \
    if ! getent group www-data >/dev/null; then groupadd -g 33 www-data; fi; \
    if [ "${MONITOR_USER}" != "root" ]; then usermod -aG www-data "${MONITOR_USER}" || true; fi; \
    mkdir -p /opt/serveradmin; \
    chown -R "${MONITOR_UID}:${MONITOR_GID}" /opt/serveradmin

WORKDIR /opt/serveradmin

# ===== logrotate設定を追加 =====
COPY player_monitor.logrotate /etc/logrotate.d/player_monitor

# ===== cron + モニタープログラム起動 =====
COPY start.sh /start.sh
RUN chmod +x /start.sh

CMD ["/start.sh"]
