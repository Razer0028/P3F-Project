# Debian 13 (trixie) ベース。PHP は trixie の 8.4 系が入る。
FROM debian:trixie-slim

# ロケール（管理画面が日本語のため ja_JP.UTF-8 を生成する）
RUN apt-get update \
 && apt-get install -y locales \
 && sed -i 's/# ja_JP.UTF-8 UTF-8/ja_JP.UTF-8 UTF-8/' /etc/locale.gen \
 && locale-gen \
 && rm -rf /var/lib/apt/lists/*
ENV LANG=ja_JP.UTF-8
ENV LC_ALL=ja_JP.UTF-8

# Docker CLI + Apache + PHP
# ディストリのコードネームはベースイメージから取得する（bookworm 決め打ちを廃止）。
RUN set -eux; \
    apt-get update; \
    apt-get install -y ca-certificates curl gnupg sudo; \
    install -m 0755 -d /etc/apt/keyrings; \
    curl -fsSL https://download.docker.com/linux/debian/gpg \
      | gpg --dearmor -o /etc/apt/keyrings/docker.gpg; \
    chmod a+r /etc/apt/keyrings/docker.gpg; \
    codename="$(. /etc/os-release && echo "$VERSION_CODENAME")"; \
    printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian %s stable\n' \
      "$(dpkg --print-architecture)" "$codename" \
      > /etc/apt/sources.list.d/docker.list; \
    apt-get update; \
    apt-get install -y \
      docker-ce-cli docker-compose-plugin \
      apache2 libapache2-mod-php \
      php php-cli php-curl php-mbstring php-xml php-zip php-gd \
      unzip git composer apache2-utils python3; \
    rm -rf /var/lib/apt/lists/*
# 注: php-json は PHP 8.0 以降コアに統合され、trixie にパッケージが存在しないため削除した。

# ---- docker.sock の権限 ----
# ホストの docker グループ GID を DOCKER_GID で渡す（既定 125 はあくまで目安）。
# 同じ GID のグループが既にある場合は新規作成せず、そのグループへ www-data を追加する。
ARG DOCKER_GID=125
RUN set -eux; \
    if getent group "${DOCKER_GID}" >/dev/null; then \
      grp="$(getent group "${DOCKER_GID}" | cut -d: -f1)"; \
    else \
      groupadd -g "${DOCKER_GID}" docker; \
      grp=docker; \
    fi; \
    usermod -aG "$grp" www-data

# ---- sudoers ----
COPY ./sudoers_www /etc/sudoers.d/www-data-docker
RUN chmod 440 /etc/sudoers.d/www-data-docker \
 && chown root:root /etc/sudoers.d/www-data-docker

# Apache 設定
RUN a2enmod rewrite auth_digest
COPY ./apache/000-default.conf /etc/apache2/sites-available/000-default.conf

# =====================================================================
# Apache の access.log / error.log を Docker の STDOUT/STDERR へ流す
# =====================================================================
RUN ln -sf /proc/self/fd/1 /var/log/apache2/access.log \
 && ln -sf /proc/self/fd/2 /var/log/apache2/error.log

WORKDIR /var/www/html/public
RUN composer install --no-dev --no-interaction || true

CMD ["/usr/sbin/apachectl", "-D", "FOREGROUND"]
