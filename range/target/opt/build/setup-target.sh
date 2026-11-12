#!/bin/bash
# Build-time setup of web-01. Runs once in `docker build`; secrets come from /tmp/secrets.
set -euo pipefail
S=/tmp/secrets
pw() { python3 -c "import json,sys; print(json.load(open('$S/passwords.json'))[sys.argv[1]])" "$1"; }

# ---- people ----
# mreyes: owner and admin. jpark: a contractor who left in the spring (account still there).
# deploy: CI deploys over SSH with a key; its password is left over from before CI and matches the Grafana SMTP one.
# possupport: the point-of-sale vendor's remote support account (look-alike: legitimate).
useradd -m -s /bin/bash -c "Maria Reyes" -G sudo,adm mreyes
useradd -m -s /bin/bash -c "Jun Park (contractor)" -G sudo jpark
useradd -m -s /bin/bash -c "Deploy (CI)" -G www-data deploy
useradd -m -s /bin/bash -c "Acme POS remote support" possupport
echo "mreyes:$(pw unix_mreyes)" | chpasswd
echo "jpark:$(pw unix_jpark)" | chpasswd
echo "deploy:$(pw unix_deploy)" | chpasswd
passwd -l possupport >/dev/null
for u in mreyes jpark deploy possupport; do install -d -m 700 -o $u -g $u /home/$u/.ssh; done
key() { cat "$S/pubkeys/$1.pub"; }
key mreyes > /home/mreyes/.ssh/authorized_keys
key jpark > /home/jpark/.ssh/authorized_keys
key deploy > /home/deploy/.ssh/authorized_keys
echo "from=\"64.62.0.0/16\" $(key support)" > /home/possupport/.ssh/authorized_keys
for u in mreyes jpark deploy possupport; do chown $u:$u /home/$u/.ssh/authorized_keys; chmod 600 /home/$u/.ssh/authorized_keys; done
install -d -m 700 /root/.ssh
install -m 600 "$S/backup_ed25519" /root/.ssh/backup_ed25519
ssh-keygen -y -f /root/.ssh/backup_ed25519 > /root/.ssh/backup_ed25519.pub
cat > /root/.ssh/config <<'EOF'
Host backup
    HostName backup.larkspurcycles.net
    User larkspur
    IdentityFile /root/.ssh/backup_ed25519
    StrictHostKeyChecking accept-new
    ConnectTimeout 10
EOF
chmod 600 /root/.ssh/config
chmod 440 /etc/sudoers.d/*

rm -f /etc/nginx/sites-enabled/default
# No kernel log inside this host.
sed -i 's/^module(load="imklog"/#&/' /etc/rsyslog.conf
chown -R grafana:grafana /var/lib/grafana

# ---- database ----
service mariadb start
mysql -e "CREATE DATABASE wordpress DEFAULT CHARACTER SET utf8mb4; \
  CREATE USER 'wp_larkspur'@'localhost' IDENTIFIED BY '$(pw wp_db)'; \
  GRANT ALL ON wordpress.* TO 'wp_larkspur'@'localhost'; FLUSH PRIVILEGES;"

# ---- WordPress ----
mkdir -p /var/www/larkspur
tar -xzf /tmp/wp.tgz -C /var/www/larkspur --strip-components=1
cd /var/www/larkspur
WP="wp --allow-root --path=/var/www/larkspur"
$WP config create --dbname=wordpress --dbuser=wp_larkspur --dbpass="$(pw wp_db)" --dbhost=localhost --skip-check \
  --extra-php <<'PHP'
define( 'WP_HTTP_BLOCK_EXTERNAL', true );
define( 'AUTOMATIC_UPDATER_DISABLED', true );
define( 'DISALLOW_FILE_EDIT', false );
PHP
$WP core install --url=http://larkspurcycles.com --title="Larkspur Cycles" --admin_user=mreyes \
  --admin_password="$(pw wp_mreyes)" --admin_email=maria@larkspurcycles.com --skip-email
$WP user create lucia lucia@larkspurcycles.com --role=editor --display_name="Lucia Ortega" --user_pass="$(pw wp_lucia)"
$WP user create jpark jun@parkdev.io --role=administrator --display_name="Jun Park" --user_pass="$(pw wp_jpark)"
$WP option update blogdescription "Repairs, rentals and rides in the Blue Ridge"
$WP option update timezone_string America/New_York
$WP rewrite structure '/%year%/%monthnum%/%postname%/'
unzip -q /tmp/forminator.zip -d wp-content/plugins
$WP plugin activate forminator
$WP plugin delete akismet hello >/dev/null 2>&1 || true
$WP eval-file /opt/build/content.php
# The shop's own small plugin (range/traffic/sitegen.py), kept in git: CI pushes releases, Maria edits it by hand.
SITE=wp-content/plugins/larkspur-site
python3 /opt/build/sitegen.py "$SITE" 0
git -C "$SITE" init -q -b main
git -C "$SITE" config user.name "Maria Reyes"
git -C "$SITE" config user.email maria@larkspurcycles.com
git -C "$SITE" add -A
git -C "$SITE" commit -qm "larkspur-site 1.4.0"
$WP plugin activate larkspur-site
$WP rewrite flush
chown -R deploy:www-data /var/www/larkspur
find /var/www/larkspur -type d -exec chmod 2775 {} + && find /var/www/larkspur -type f -exec chmod 664 {} +
mkdir -p wp-content/uploads && chown -R www-data:www-data wp-content/uploads
chmod 640 wp-config.php
git config --system --add safe.directory /var/www/larkspur/wp-content/plugins/larkspur-site
service mariadb stop

# ---- Grafana ----
sed -i -e "s/@ADMIN@/$(pw grafana_admin)/" -e "s/@SMTP@/$(pw grafana_smtp)/" /etc/grafana/grafana.ini
chown root:grafana /etc/grafana/grafana.ini && chmod 640 /etc/grafana/grafana.ini
service grafana-server start
for i in $(seq 60); do curl -fs http://127.0.0.1:3000/api/health >/dev/null && break; sleep 1; done
curl -fs -u "admin:$(pw grafana_admin)" -H 'Content-Type: application/json' http://127.0.0.1:3000/api/admin/users \
  -d "{\"name\":\"Dana Whitfield\",\"email\":\"dana@larkspurcycles.com\",\"login\":\"dana\",\"password\":\"$(pw grafana_dana)\"}"
echo
service grafana-server stop
rm -f /var/log/grafana/*.log

# ---- boot: /sbin/init runs these start scripts in order (as Debian's sysv-rc lays them out) ----
rm -f /etc/rc2.d/S*
for l in S01rsyslog S01sudo S02cron S02mariadb S02rsync S02ssh S03php8.2-fpm S03prometheus-node-exporter \
         S04grafana-server S04nginx; do
    ln -s "../init.d/${l:3}" "/etc/rc2.d/$l"
done
install -d -m 755 /var/lib/prometheus/node-exporter

# ---- quiet build traces ----
rm -f /var/log/nginx/*.log /var/log/mysql/* /root/.bash_history /root/.wp-cli -r 2>/dev/null || true
: > /var/log/auth.log; : > /var/log/syslog
: > /var/log/offsite-backup.log
