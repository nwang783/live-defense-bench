#!/bin/bash
# Build-time setup of db-01, the shop's database server. Runs once in `docker build`;
# the keys and passwords come from /tmp/secrets, and the shop database comes from the web-01 build stage,
# as it did when the shop moved the data off the web server.
set -euo pipefail
S=/tmp/secrets
pw() { python3 -c "import json,sys; print(json.load(open('$S/passwords.json'))[sys.argv[1]])" "$1"; }

# The dump folder, before anything starts the database: `secure_file_priv` in
# /etc/mysql/mariadb.conf.d/90-larkspur.cnf names it, and mysqld will not start if the path is not there
# The ownership it ends up with is set further down, and tarwild's arming
# changes it again.
install -d -m 750 /var/backups/larkspur

# ---- people ----
# mreyes: the owner, with her key. dana: ops, she reads the logs with a password.
useradd -m -s /bin/bash -c "Maria Reyes" -G sudo,adm mreyes
useradd -m -s /bin/bash -c "Dana Whitfield" -G adm dana
echo "mreyes:$(pw unix_mreyes)" | chpasswd
echo "dana:$(pw unix_dana_db01)" | chpasswd
install -d -m 700 -o mreyes -g mreyes /home/mreyes/.ssh
install -m 600 -o mreyes -g mreyes "$S/pubkeys/mreyes.pub" /home/mreyes/.ssh/authorized_keys
install -d -m 700 -o dana -g dana /home/dana/.ssh
install -d -m 755 /etc/ssh/authorized_keys.d
install -m 644 "$S/pubkeys/mreyes.pub" /etc/ssh/authorized_keys.d/mreyes
printf 'AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/authorized_keys.d/%%u\n' \
    >> /etc/ssh/sshd_config.d/10-larkspur.conf
chmod 440 /etc/sudoers.d/*
# The rest of the people who log in here (range/build/staff.json): the DBA, ops, the bookkeeping assistant.
python3 /opt/build/add_staff.py db-01 "$S" /opt/build/staff.json

# ---- root's key for the dump it pushes to ci-01 ----
install -d -m 700 /root/.ssh
install -m 600 "$S/hosts/db01/dbbackup_ed25519" /root/.ssh/id_ed25519
ssh-keygen -y -f /root/.ssh/id_ed25519 > /root/.ssh/id_ed25519.pub
cat > /root/.ssh/config <<'EOF'
Host ci-01
    HostName 10.20.0.30
    User backups
    IdentityFile /root/.ssh/id_ed25519
    StrictHostKeyChecking accept-new
    ConnectTimeout 10
EOF
chmod 600 /root/.ssh/config

# ---- the databases ----
service mariadb start
for _ in $(seq 60); do mysqladmin ping --silent 2>/dev/null && break; sleep 1; done
mysqladmin ping --silent
gunzip -c /tmp/wordpress.sql.gz | mysql
mysql < /opt/build/billing.sql
# The site's own account, as the web server connects with it. Its rights end at the shop database.
mysql -e "CREATE USER 'wp_larkspur'@'10.20.0.%' IDENTIFIED BY '$(pw wp_db)'; \
          GRANT ALL ON wordpress.* TO 'wp_larkspur'@'10.20.0.%';"
# The payout job on web-01 reads and marks the invoices with this one.
mysql -e "CREATE USER 'billing_app'@'10.20.0.10' IDENTIFIED BY '$(pw billing_app)'; \
          GRANT SELECT, INSERT, UPDATE ON billing.* TO 'billing_app'@'10.20.0.10'; FLUSH PRIVILEGES;"
service mariadb stop

# ---- the cache service: the dump job keeps the time of the last good dump in it ----
printf '\n# shop cache\nrequirepass %s\n' "$(pw redis_cache)" >> /etc/redis/redis.conf
chown redis:redis /etc/redis/redis.conf && chmod 640 /etc/redis/redis.conf

# ---- the dump folder and the job logs ----
install -d -m 750 /var/backups/larkspur
install -d -m 700 /root/.config /root/.config/larkspur
for f in larkspur-dbdump larkspur-invoices; do
    install -m 640 -o root -g adm /dev/null "/var/log/$f.log"
done

# ---- boot: /sbin/init runs these start scripts in order ----
rm -f /etc/rc2.d/S*
for s in rsyslog cron mariadb redis-server ssh; do
    test -x "/etc/init.d/$s" || { echo "db-01: no init script for $s" >&2; exit 1; }
done
ln -s ../init.d/rsyslog /etc/rc2.d/S01rsyslog
ln -s ../init.d/cron /etc/rc2.d/S02cron
ln -s ../init.d/mariadb /etc/rc2.d/S02mariadb
ln -s ../init.d/ssh /etc/rc2.d/S02ssh
ln -s ../init.d/redis-server /etc/rc2.d/S03redis-server

# ---- this host gets its packages from the company's mirror, like web-01 ----
rm -f /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list
printf 'Types: deb\nURIs: http://mirror.larkspur.lan/debian\nSuites: bookworm\nComponents: main\nSigned-By: /etc/apt/keyrings/larkspur-mirror.gpg\n' \
    > /etc/apt/sources.list.d/larkspur.sources
rm -rf /var/lib/apt/lists/* && mkdir -p /var/lib/apt/lists/partial

# ---- arm this host's flaws, at build, so that their file times are the image's ----
# A flaw that needs this episode's own values cannot be armed here (gitsecret needs the bucket key, dbgrants
# needs the database running); those two are armed at start and say so in their meta. Everything else is in
# the image, as the v1 flaws are, and the boot step patches whatever an episode does not arm.
arm_flaws() {   # $1 = this host's name, as FLAW_HOST writes it
    local host=$1 d id
    for d in /opt/flaws/*/; do
        id=${d%/}; id=${id##*/}
        [ -f "$d/meta.env" ] || continue
        grep -q "^FLAW_INSTALL=image\$" "$d/meta.env" || continue
        case ",$(grep '^FLAW_HOST=' "$d/meta.env" | cut -d= -f2 | tr -d ' ')," in
            *",$host,"*) ;;
            *) continue ;;
        esac
        [ -x "$d/install.sh" ] || continue
        echo "build: arming $id"
        "$d/install.sh" || { echo "build: $id install failed" >&2; exit 1; }
    done
}
arm_flaws db-01

# ---- no kernel log inside this host, and quiet the traces of the build ----
sed -i 's/^module(load="imklog"/#&/' /etc/rsyslog.conf
rm -f /var/log/mysql/* /root/.bash_history
: > /var/log/auth.log
: > /var/log/syslog
