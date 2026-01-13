FROM debian:bookworm-slim

# Locale
RUN apt-get update && apt-get install -y locales \
  && sed -i 's/# ja_JP.UTF-8 UTF-8/ja_JP.UTF-8 UTF-8/' /etc/locale.gen \
  && locale-gen
ENV LANG=ja_JP.UTF-8
ENV LC_ALL=ja_JP.UTF-8

# Install Docker CLI + Apache + PHP
RUN apt-get update \
 && apt-get install -y ca-certificates curl gnupg sudo \
 && install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://download.docker.com/linux/debian/gpg \
      | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
      https://download.docker.com/linux/debian bookworm stable" \
      > /etc/apt/sources.list.d/docker.list \
 && apt-get update \
 && apt-get install -y docker-ce-cli apache2 libapache2-mod-php \
    php php-cli php-curl php-mbstring php-xml php-json php-zip php-gd \
    unzip git composer apache2-utils python3

# ---- docker.sock permissions ----
ARG DOCKER_GID=125
RUN groupadd -g ${DOCKER_GID} docker || true \
 && usermod -aG docker www-data

# ---- sudoers ----
COPY ./sudoers_www /etc/sudoers.d/www-data-docker
RUN chmod 440 /etc/sudoers.d/www-data-docker \
 && chown root:root /etc/sudoers.d/www-data-docker

# Apache config
RUN a2enmod rewrite auth_digest
COPY ./apache/000-default.conf /etc/apache2/sites-available/000-default.conf

# =====================================================================
# ★ 追加：Apache の access.log / error.log を Docker STDOUT/STDERR へ
# =====================================================================
RUN ln -sf /proc/self/fd/1 /var/log/apache2/access.log \
 && ln -sf /proc/self/fd/2 /var/log/apache2/error.log

WORKDIR /var/www/html/public
RUN composer install --no-dev --no-interaction || true

CMD ["/usr/sbin/apachectl", "-D", "FOREGROUND"]
