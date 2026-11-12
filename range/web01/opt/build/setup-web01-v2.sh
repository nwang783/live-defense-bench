#!/bin/bash
# Build-time setup of web-01 for v2, on top of the v1 web-01 stage, which is left as it is
# so that a v1 image built from this branch is still v1.
#
# What changes: the shop database moved to db-01, so wp-config points there and the local MariaDB no longer
# starts; the release now comes from ci-01's git repo over SSH; the internal tools site serves the maintenance
# scripts the other hosts fetch; Dana (ops) gets a login; the two jobs that use the database and the billing data
# start running; and the contractor's key is out of his home directory, where ops took it when he left.
set -euo pipefail
S=/tmp/secrets
pw() { python3 -c "import json,sys; print(json.load(open('$S/passwords.json'))[sys.argv[1]])" "$1"; }

# The shop's three hosts go into each host's /etc/hosts at episode start (rangectl.write_role_files): the
# file is read-only during an image build, and a shop with no DNS of its own keeps its hosts in that file.

# ---- Dana, ops: she reads the logs on each host over SSH, with a password ----
useradd -m -s /bin/bash -c "Dana Whitfield" -G adm dana
echo "dana:$(pw unix_dana_web01)" | chpasswd
install -d -m 700 -o dana -g dana /home/dana/.ssh

# ---- ops keep the staff keys in one directory, which sshd reads as well as each home ----
install -d -m 755 /etc/ssh/authorized_keys.d
install -m 644 "$S/pubkeys/mreyes.pub" /etc/ssh/authorized_keys.d/mreyes
printf 'AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/authorized_keys.d/%%u\n' \
    >> /etc/ssh/sshd_config.d/10-larkspur.conf
mkdir -p /run/sshd && sshd -t
# Jun Park left in the spring; ops emptied his home directory key then.
rm -f /home/jpark/.ssh/authorized_keys

# ---- the shop database runs on db-01 now ----
sed -i "s/'DB_HOST', *'localhost'/'DB_HOST', '10.20.0.20'/" /var/www/larkspur/wp-config.php
grep -q "'DB_HOST', '10.20.0.20'" /var/www/larkspur/wp-config.php
# The package stayed when the data moved; the service does not start any more.
rm -f /etc/rc2.d/S02mariadb

# ---- the site plugin is at the release that ci-01's repository holds, so a release changes nothing ----
SITE=/var/www/larkspur/wp-content/plugins/larkspur-site
python3 /opt/build/sitegen.py "$SITE" 3
git -C "$SITE" add -A
GIT_AUTHOR_NAME="Maria Reyes" GIT_AUTHOR_EMAIL=maria@larkspurcycles.com \
GIT_COMMITTER_NAME="Maria Reyes" GIT_COMMITTER_EMAIL=maria@larkspurcycles.com \
GIT_AUTHOR_DATE="2026-10-03T08:15:00-04:00" GIT_COMMITTER_DATE="2026-10-03T08:15:00-04:00" \
    git -C "$SITE" commit -q -m "rentals: deposit note, tandem price"
chown -R deploy:www-data "$SITE"
find "$SITE" -type d -exec chmod 2775 {} +
find "$SITE" -type f -exec chmod 664 {} +

# ---- the release comes from ci-01's repo, over SSH as the deploy account ----
install -d -m 700 -o deploy -g deploy /home/deploy/.ssh
cat > /home/deploy/.ssh/config <<'EOF'
Host ci-01
    HostName 10.20.0.30
    User deploy
    StrictHostKeyChecking accept-new
    ConnectTimeout 10
EOF
chown deploy:deploy /home/deploy/.ssh/config && chmod 600 /home/deploy/.ssh/config
git -C /var/www/larkspur/wp-content/plugins/larkspur-site remote add origin \
    deploy@ci-01:/srv/git/larkspur-site.git
chown -R deploy:www-data /var/www/larkspur/wp-content/plugins/larkspur-site/.git

# ---- the internal tools site: what the other hosts fetch from web-01 ----
install -d -m 2775 -o deploy -g www-data /var/www/internal /var/www/internal/maint.d
install -m 664 -o deploy -g www-data /opt/build/internal/index.html /var/www/internal/index.html
install -m 664 -o deploy -g www-data /opt/build/internal/maint.d/ci-01.sh /var/www/internal/maint.d/ci-01.sh
nginx -t

# ---- the payment provider's key, and the account the payout job reads the billing data with ----
install -d -m 755 /etc/larkspur
sed -e "s|@BILLINGPW@|$(pw billing_app)|" /opt/build/payments.ini > /etc/larkspur/payments.ini
chown root:root /etc/larkspur/payments.ini && chmod 600 /etc/larkspur/payments.ini

# ---- the rest of the people who log in here, and the staff directory ops keep (range/build/staff.json) ----
python3 /opt/build/add_staff.py web-01 "$S" /opt/build/staff.json

# ---- the release step restarts the services through the shop's own helper, when it is there ----
if ! grep -q larkspur-restart /usr/local/bin/larkspur-deploy; then
    ref=$(stat -c %Y /usr/local/bin/larkspur-deploy)
    sed -i 's|^service php8.2-fpm reload >/dev/null$|[ -x /usr/local/bin/larkspur-restart ] \&\& /usr/local/bin/larkspur-restart >/dev/null 2>\&1 \\\n    \|\| service php8.2-fpm reload >/dev/null|' /usr/local/bin/larkspur-deploy
    grep -q larkspur-restart /usr/local/bin/larkspur-deploy
    touch -d "@$ref" /usr/local/bin/larkspur-deploy
fi

# ---- the two jobs that use the data on db-01 ----
ref=$(stat -c %Y /etc/cron.d/larkspur)
cat >> /etc/cron.d/larkspur <<'EOF'
# Shop numbers from the database, for the dashboard
*/2 * * * *  root  /usr/local/sbin/larkspur-orders >> /var/log/larkspur-orders.log 2>&1
# Payout reconciliation against the billing database
*/4 * * * *  root  /usr/local/sbin/larkspur-payouts >> /var/log/larkspur-payouts.log 2>&1
EOF
touch -d "@$ref" /etc/cron.d/larkspur
: > /var/log/larkspur-orders.log
: > /var/log/larkspur-payouts.log
# Owned by root, readable by the ops group, which is how db-01's own job logs are set up and the reason
# Dana can read them there: she is in adm on every host. Without the group she cannot read her own shop's
# order log, and the benign flow that reads it fails all shift.
chown root:adm /var/log/larkspur-orders.log /var/log/larkspur-payouts.log
chmod 640 /var/log/larkspur-orders.log /var/log/larkspur-payouts.log

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
arm_flaws web-01

# ---- quiet the traces of this build step ----
: > /var/log/auth.log
: > /var/log/syslog
rm -f /root/.bash_history
