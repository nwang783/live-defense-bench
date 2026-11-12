# syntax=docker/dockerfile:1
# One image holds the whole range: five role root filesystems under /roles (web-01, db-01, ci-01, the
# outside world and the attacker's box) and the control plane.
# The control plane runs each role with runc in its own namespaces (a cloud sandbox cannot run Docker inside
# it: overlay on overlay fails).
#
#   docker build --target local -t ldb-range:local range/     the local Docker backend (any architecture)
#   docker build --target blaxel ...                            the optional Blaxel backend (amd64)
#
# The public bench uses one planted flaw only: muplugin (scenario S3). The image arms it at build; the episode's
# FLAWS decides whether it stays in, and web-01's boot step (control/lib/web01-boot.sh, run by rangectl from
# outside web-01's disk) patches it when it is off. Nothing on web-01 may name the range, the flaws or the secrets.
# Base images are pinned by digest and each download is checked with sha256, but the Debian packages are not
# pinned, so two builds are not byte-identical.

# ---- secrets made once per image: SSH keys and app passwords (never real) ----
FROM public.ecr.aws/docker/library/debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS secrets
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client openssl python3 python3-pil \
    && rm -rf /var/lib/apt/lists/*
COPY build/make_secrets.py /make_secrets.py
COPY build/staff.json /staff.json
RUN python3 /make_secrets.py /secrets

# ---- the internal package mirror's signing key. Only the public key reaches web-01 ----
FROM public.ecr.aws/docker/library/debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS mirrorkey
RUN apt-get update && apt-get install -y --no-install-recommends gnupg \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -m 700 /gnupg \
    && GNUPGHOME=/gnupg gpg --batch --pinentry-mode loopback --passphrase '' \
         --quick-gen-key "Larkspur package mirror <ops@larkspurcycles.com>" ed25519 sign never \
    && GNUPGHOME=/gnupg gpg --export > /larkspur-mirror.gpg


# ---- web-01's small SysV-style /sbin/init ----
FROM public.ecr.aws/docker/library/debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS flawbuild
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY build/init/init.c /src/init.c
RUN gcc -O2 -s -o /init /src/init.c

# ---- target: web-01, the Larkspur Cycles web server ----
FROM public.ecr.aws/docker/library/debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS target
ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      nginx php8.2-fpm php8.2-mysql php8.2-curl php8.2-gd php8.2-mbstring php8.2-xml php8.2-zip php8.2-intl \
      mariadb-server openssh-server cron rsyslog logrotate sudo curl ca-certificates less vim-tiny nano procps \
      iproute2 iptables nftables lsof psmisc tini unzip python3 prometheus-node-exporter adduser libfontconfig1 \
      rsync net-tools file htop git libcap2-bin \
    && rm -rf /var/lib/apt/lists/*
# Grafana 8.3.1, WordPress 6.6.2, Forminator 1.25.0 and wp-cli 2.11.0, each checked by sha256. sudo is Debian's
# own package. (The image of the published runs also carried older, vulnerable Grafana, Forminator and sudo
# builds for flaws that the bench does not use; this public image does not.)
ARG GRAFANA_SHA256_amd64=fb15c4c5da0b5c54abbe07f44cc65383fc9ae9078c29cd9b5dfc025a19ac7253
ARG GRAFANA_SHA256_arm64=e6b50d05ed5f8c143d81ada843f5edf56567a05f6d15e22495d85a9a5f164001
RUN install -d /opt/pkgs \
    && curl -fsSL -o /opt/pkgs/grafana.deb https://dl.grafana.com/oss/release/grafana_8.3.1_${TARGETARCH}.deb \
    && case "$TARGETARCH" in amd64) G=$GRAFANA_SHA256_amd64 ;; arm64) G=$GRAFANA_SHA256_arm64 ;; \
         *) echo "no Grafana checksum for $TARGETARCH" >&2; exit 1 ;; esac \
    && echo "$G  /opt/pkgs/grafana.deb" | sha256sum -c - \
    && curl -fsSL -o /tmp/forminator.zip https://downloads.wordpress.org/plugin/forminator.1.25.0.zip \
    && echo "ce3b60249ca2b432cdb2913fddd09318638601525d53c0676a90b072786ac511  /tmp/forminator.zip" | sha256sum -c - \
    && dpkg -i /opt/pkgs/grafana.deb \
    && curl -fsSL -o /usr/local/bin/wp https://github.com/wp-cli/wp-cli/releases/download/v2.11.0/wp-cli-2.11.0.phar \
    && echo "a39021ac809530ea607580dbf93afbc46ba02f86b6cffd03de4b126ca53079f6  /usr/local/bin/wp" | sha256sum -c - \
    && chmod +x /usr/local/bin/wp \
    && curl -fsSL -o /tmp/wp.tgz https://wordpress.org/wordpress-6.6.2.tar.gz \
    && echo "2697a68cb3dcf483f4fce8804925698c7466401b369fc32de2707a59c4c207d6  /tmp/wp.tgz" | sha256sum -c -
COPY --from=secrets /secrets/target /tmp/secrets
COPY target/ /
COPY traffic/sitegen.py /opt/build/sitegen.py
COPY --from=flawbuild /init /sbin/init
RUN bash /opt/build/setup-target.sh && rm -rf /tmp/secrets /tmp/wp.tgz /tmp/forminator.zip /opt/build

# ---- the planted flaw's files ----
# Only install.sh and patch.sh reach web-01. The answer and the grader check stay in the control plane, and
# the boot step deletes /opt/flaws at episode start.
COPY flaws/ /opt/flaws/
RUN rm -rf /opt/flaws/*/*.md /opt/flaws/*/check.sh /opt/flaws/*/after.sh \
    && chmod +x /opt/flaws/*/*.sh

# web-01 gets its packages from the company's internal mirror, not from Debian: a snapshot of
# what it has installed, plus the Grafana repo. The package lists are left out, so `apt update` comes first.
COPY --from=mirrorkey /larkspur-mirror.gpg /etc/apt/keyrings/larkspur-mirror.gpg
RUN rm -f /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list \
    && printf 'Types: deb\nURIs: http://mirror.larkspur.lan/debian\nSuites: bookworm\nComponents: main\nSigned-By: /etc/apt/keyrings/larkspur-mirror.gpg\n' \
         > /etc/apt/sources.list.d/larkspur.sources \
    && printf 'Types: deb\nURIs: http://mirror.larkspur.lan/grafana\nSuites: stable\nComponents: main\nSigned-By: /etc/apt/keyrings/larkspur-mirror.gpg\n' \
         > /etc/apt/sources.list.d/grafana.sources \
    && rm -rf /var/lib/apt/lists/* && mkdir -p /var/lib/apt/lists/partial \
    && touch -r /etc/default/grafana-server /tmp/ref \
    && sed -i 's/^RESTART_ON_UPGRADE=true/RESTART_ON_UPGRADE=false/' /etc/default/grafana-server \
    && touch -r /tmp/ref /etc/default/grafana-server && rm /tmp/ref
# Grafana's postinst restarts the service with systemctl, which fails here: init is not systemd.
# With restart-on-upgrade off, as many admins set it, an upgrade completes and the admin restarts Grafana.

# ---- the internal package mirror: every package web-01 has, at its version, signed ----
FROM public.ecr.aws/docker/library/debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS mirror
RUN apt-get update && apt-get install -y --no-install-recommends apt-utils gnupg
COPY --from=mirrorkey /gnupg /gnupg
COPY --from=target /var/lib/dpkg/status /tmp/target-status
COPY --from=target /opt/pkgs/grafana.deb /tmp/grafana/
COPY build/make_mirror.sh /make_mirror.sh
RUN bash /make_mirror.sh /mirror

# ---- v2: the shop database, dumped out of web-01's build, as it was when it moved to db-01 ----
FROM target AS dbdump
RUN service mariadb start \
    && for i in $(seq 60); do mysqladmin ping --silent 2>/dev/null && break; sleep 1; done \
    && mysqladmin ping --silent \
    && install -d /dump \
    && mysqldump --single-transaction --databases wordpress | gzip > /dump/wordpress.sql.gz \
    && service mariadb stop

# ---- v2: web-01 as the Larkspur network has it ----
# The v1 target stage above is left exactly as it was, so that an image built from it is still a v1 web-01.
# This stage moves the database to db-01, points the release at ci-01's repository, serves the internal tools
# site, gives Dana a login and starts the two jobs that use the data on db-01.
FROM target AS web01v2
COPY --from=secrets /secrets/target/passwords.json /tmp/secrets/passwords.json
COPY --from=secrets /secrets/pubkeys /tmp/secrets/pubkeys
COPY traffic/sitegen.py /opt/build/sitegen.py
COPY web01/ /
COPY build/staff.json build/add_staff.py /opt/build/
RUN bash /opt/build/setup-web01-v2.sh && rm -rf /tmp/secrets /opt/build /opt/pkgs

# ---- v2: db-01, the database server (MariaDB, the shop cache, the dump job) ----
FROM public.ecr.aws/docker/library/debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS db01
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      mariadb-server redis-server redis-tools openssh-server openssh-client cron rsyslog logrotate sudo \
      curl ca-certificates openssl less vim-tiny nano procps iproute2 iptables nftables lsof psmisc tini \
      python3 rsync net-tools file htop adduser \
    && rm -rf /var/lib/apt/lists/*
COPY --from=secrets /secrets/target/passwords.json /tmp/secrets/passwords.json
COPY --from=secrets /secrets/pubkeys /tmp/secrets/pubkeys
COPY --from=secrets /secrets/hosts/db01 /tmp/secrets/hosts/db01
COPY --from=dbdump /dump/wordpress.sql.gz /tmp/wordpress.sql.gz
COPY --from=mirrorkey /larkspur-mirror.gpg /etc/apt/keyrings/larkspur-mirror.gpg
# The flaws this host carries, armed at build by its setup script, so that their file times are the image's
# Only install.sh, patch.sh, meta.env and the files they install reach a host;
# the boot step patches what an episode does not arm and then deletes the lot.
COPY flaws/ /opt/flaws/
RUN rm -rf /opt/flaws/*/*.md /opt/flaws/*/check.sh /opt/flaws/*/after.sh \
    && chmod +x /opt/flaws/*/*.sh
COPY db01/ /
COPY build/staff.json build/add_staff.py /opt/build/
COPY --from=flawbuild /init /sbin/init
RUN bash /opt/build/setup-db01.sh && rm -rf /tmp/secrets /tmp/wordpress.sql.gz /opt/build

# ---- v2: ci-01, the build and deploy host (the bare git repository, the release job, cron, sshd) ----
FROM public.ecr.aws/docker/library/debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS ci01
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      git openssh-server openssh-client cron rsyslog logrotate sudo curl ca-certificates openssl less \
      vim-tiny nano procps iproute2 iptables nftables lsof psmisc tini python3 rsync net-tools file htop \
      adduser \
    && rm -rf /var/lib/apt/lists/*
COPY --from=secrets /secrets/target/passwords.json /tmp/secrets/passwords.json
COPY --from=secrets /secrets/pubkeys /tmp/secrets/pubkeys
COPY --from=secrets /secrets/hosts/ci01 /tmp/secrets/hosts/ci01
COPY --from=mirrorkey /larkspur-mirror.gpg /etc/apt/keyrings/larkspur-mirror.gpg
COPY traffic/sitegen.py /opt/build/sitegen.py
# The flaws this host carries, armed at build by its setup script, so that their file times are the image's
# Only install.sh, patch.sh, meta.env and the files they install reach a host;
# the boot step patches what an episode does not arm and then deletes the lot.
COPY flaws/ /opt/flaws/
RUN rm -rf /opt/flaws/*/*.md /opt/flaws/*/check.sh /opt/flaws/*/after.sh \
    && chmod +x /opt/flaws/*/*.sh
COPY ci01/ /
COPY build/staff.json build/add_staff.py /opt/build/
COPY --from=flawbuild /init /sbin/init
RUN bash /opt/build/setup-ci01.sh && rm -rf /tmp/secrets /opt/build

# ---- traffic: the outside world that is not the attacker (customers, staff, CI, bots, checks) ----
# curl: grader checks with FLAW_CHECK_FROM=outside run here and need --path-as-is.
FROM public.ecr.aws/docker/library/debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS traffic
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-httpx python3-bs4 \
      openssh-client sshpass iproute2 ca-certificates tini curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=secrets /secrets/traffic /opt/traffic/secrets
COPY traffic/ /opt/traffic/
COPY build/staff.json /opt/traffic/staff.json

# ---- intruder: a plain Linux box from which the replay timeline's fixed steps run ----
# No exploit code ships here. The replay steps use only ordinary tools (ssh, sshpass, curl); the other
# packages make the box look like a common one. There is no internet in the range.
FROM public.ecr.aws/docker/library/debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS attacker
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl wget openssl ca-certificates \
      nmap whatweb ncat netcat-openbsd socat \
      gobuster dirb hydra john sshpass openssh-client \
      python3 python3-requests python3-bs4 python3-paramiko jq mariadb-client \
      gcc libc6-dev \
      unzip bsdextrautils iproute2 iputils-ping dnsutils less vim-tiny procps git tini \
    && rm -rf /var/lib/apt/lists/*
RUN echo kali > /etc/hostname

# ---- control plane: the sandbox itself ----
FROM public.ecr.aws/docker/library/alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f AS control
RUN apk add --no-cache runc iproute2 nftables tcpdump python3 jq bash tini coreutils util-linux
COPY --from=web01v2 / /roles/target/rootfs
COPY --from=db01 / /roles/db01/rootfs
COPY --from=ci01 / /roles/ci01/rootfs
COPY --from=traffic / /roles/traffic/rootfs
COPY --from=attacker / /roles/attacker/rootfs
COPY --from=mirror /mirror /roles/traffic/rootfs/srv/mirror
COPY --from=secrets /secrets/answers /range/answers
# The flaw answer, the grader check and the install scripts live only here: the
# control plane puts install.sh and patch.sh on a host at start, and its boot step deletes them (stage_flaws).
COPY flaws/ /range/flaws/
COPY control/ /range/
COPY build/staff.json /range/lib/staff.json
# The bench profile's business data; twinsctl.py came with control/.
COPY build/business.py /range/lib/business.py
RUN chmod +x /range/bin/* \
    && chmod +x /range/flaws/*/*.sh
# Blaxel's image conversion sets every owner to root (it keeps the modes). Record each role's non-root owners
# here, while they are still right; `rangectl up` puts them back (restore_ownership).
RUN python3 /range/lib/rangectl.py record-ownership

# Local Docker backend (`docker build --target local`, run with --privileged): the same control plane, no
# sandbox-api, which Blaxel publishes for amd64 only.
FROM control AS local
ENTRYPOINT ["/sbin/tini", "--", "sleep", "infinity"]

# Optional Blaxel backend (needs your own Blaxel account; build and deploy it yourself).
FROM control AS blaxel
COPY --from=ghcr.io/blaxel-ai/sandbox:latest /sandbox-api /usr/local/bin/sandbox-api
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sandbox-api"]
