#!/bin/bash
# Build-time setup of ci-01, the shop's build and deploy host. Runs once in
# `docker build`; the keys and passwords come from /tmp/secrets.
set -euo pipefail
S=/tmp/secrets
pw() { python3 -c "import json,sys; print(json.load(open('$S/passwords.json'))[sys.argv[1]])" "$1"; }

# ---- people ----
# deploy: the account the release job runs as, with the key web-01 accepts. mreyes: the owner.
# dana: ops, with a password. jpark: the contractor who left in the spring; the account is still here.
# backups: where db-01 drops the database archives (the name `backup` is Debian's own system account).
useradd -m -s /bin/bash -c "Larkspur CI" deploy
useradd -m -s /bin/bash -c "Maria Reyes" -G sudo,adm mreyes
useradd -m -s /bin/bash -c "Dana Whitfield" -G adm dana
useradd -m -s /bin/bash -c "Jun Park (contractor)" jpark
# A plain shell, because db-01 pushes the archives here with rsync over SSH, which needs one.
useradd -d /srv/backups -s /bin/bash -c "Database archives from db-01" backups
passwd -l deploy >/dev/null
passwd -l backups >/dev/null
echo "mreyes:$(pw unix_mreyes)" | chpasswd
echo "jpark:$(pw unix_jpark)" | chpasswd
echo "dana:$(pw unix_dana_ci01)" | chpasswd
install -d -m 700 -o mreyes -g mreyes /home/mreyes/.ssh
install -m 600 -o mreyes -g mreyes "$S/pubkeys/mreyes.pub" /home/mreyes/.ssh/authorized_keys
install -d -m 700 -o dana -g dana /home/dana/.ssh
install -d -m 700 -o jpark -g jpark /home/jpark/.ssh
install -d -m 755 /etc/ssh/authorized_keys.d
install -m 644 "$S/pubkeys/mreyes.pub" /etc/ssh/authorized_keys.d/mreyes
printf 'AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/authorized_keys.d/%%u\n' \
    >> /etc/ssh/sshd_config.d/10-larkspur.conf
chmod 440 /etc/sudoers.d/*

# ---- the key the release job logs in to web-01 with ----
install -d -m 700 -o deploy -g deploy /home/deploy/.ssh
install -m 600 -o deploy -g deploy "$S/hosts/ci01/deploy_ed25519" /home/deploy/.ssh/id_ed25519
ssh-keygen -y -f /home/deploy/.ssh/id_ed25519 > /home/deploy/.ssh/id_ed25519.pub
chown deploy:deploy /home/deploy/.ssh/id_ed25519.pub
cat > /home/deploy/.ssh/config <<'EOF'
Host web-01
    HostName 10.20.0.10
    User deploy
    IdentityFile /home/deploy/.ssh/id_ed25519
    StrictHostKeyChecking accept-new
    ConnectTimeout 10
EOF
chown deploy:deploy /home/deploy/.ssh/config && chmod 600 /home/deploy/.ssh/config
# The repository here is what web-01 pulls from during a release, so its own key is listed as well.
install -m 600 -o deploy -g deploy "$S/pubkeys/deploy.pub" /home/deploy/.ssh/authorized_keys

# ---- where db-01 drops the database archives ----
install -d -m 750 -o backups -g backups /srv/backups /srv/backups/larkspur
install -d -m 700 -o backups -g backups /srv/backups/.ssh
install -m 600 -o backups -g backups "$S/pubkeys/dbbackup.pub" /srv/backups/.ssh/authorized_keys

# ---- the site plugin's repository, with the history it really has ----
install -d -m 755 -o deploy -g deploy /srv/git /srv/artifacts
WORK=$(mktemp -d)
export GIT_AUTHOR_NAME="Maria Reyes" GIT_AUTHOR_EMAIL=maria@larkspurcycles.com
export GIT_COMMITTER_NAME="Maria Reyes" GIT_COMMITTER_EMAIL=maria@larkspurcycles.com
git init -q -b main "$WORK/larkspur-site"
commit() {   # $1 = date, $2 = message, $3 = author name, $4 = author email
    GIT_AUTHOR_NAME="$3" GIT_AUTHOR_EMAIL="$4" GIT_COMMITTER_NAME="$3" GIT_COMMITTER_EMAIL="$4" \
    GIT_AUTHOR_DATE="$1" GIT_COMMITTER_DATE="$1" \
        git -C "$WORK/larkspur-site" commit -q -m "$2"
}
# What a release is: the plugin's own files. The folder with the deploy scripts and this file stay in the
# repository and out of `git archive`, so a release carries neither.
printf 'deploy/ export-ignore\n.gitattributes export-ignore\n' > "$WORK/larkspur-site/.gitattributes"
for n in 0 1 2 3; do
    python3 /opt/build/sitegen.py "$WORK/larkspur-site" "$n"
    git -C "$WORK/larkspur-site" add -A
    case "$n" in
        0) commit "2026-06-11T09:24:00-04:00" "larkspur-site 1.4.0" "Maria Reyes" maria@larkspurcycles.com ;;
        1) commit "2026-07-29T16:02:00-04:00" "rentals: summer prices, e-bike row" "Maria Reyes" maria@larkspurcycles.com ;;
        2) commit "2026-09-08T11:41:00-04:00" "hours: fall hours, Sunday closed" "Larkspur CI" ci@larkspurcycles.com ;;
        3) commit "2026-10-03T08:15:00-04:00" "rentals: deposit note, tandem price" "Maria Reyes" maria@larkspurcycles.com ;;
    esac
done
git clone -q --bare "$WORK/larkspur-site" /srv/git/larkspur-site.git
rm -rf "$WORK"
cd /srv/git/larkspur-site.git
git symbolic-ref HEAD refs/heads/main
printf 'Larkspur Cycles site plugin\n' > description
git config remote.github.url 'https://larkspur-ci:@DEPLOYTOKEN@@github.com/larkspur-cycles/larkspur-site.git'
git config remote.github.fetch '+refs/heads/*:refs/remotes/github/*'
git config receive.denyNonFastForwards true
chown -R deploy:deploy /srv/git/larkspur-site.git
cd /

# ---- the rest of the people who log in here (range/build/staff.json) ----
# The developers push their work branches to the repository here, so it is shared with their group; the release
# job still takes only main.
python3 /opt/build/add_staff.py ci-01 "$S" /opt/build/staff.json
git --git-dir=/srv/git/larkspur-site.git config core.sharedRepository group
chgrp -R developers /srv/git/larkspur-site.git
chmod -R g+rwX /srv/git/larkspur-site.git
find /srv/git/larkspur-site.git -type d -exec chmod g+s {} +
usermod -aG developers deploy
# The repository belongs to deploy; the people who read it from their own accounts are told it is the shop's.
git config --system --add safe.directory /srv/git/larkspur-site.git

# ---- the offsite bucket's keys ----
install -d -m 755 /etc/larkspur
install -m 640 -o root -g root /opt/build/backup.env /etc/larkspur/backup.env

# ---- the job logs: the release job runs as deploy, so it writes its own ----
install -m 640 -o deploy -g adm /dev/null /var/log/larkspur-release.log
for f in larkspur-maint larkspur-offsite; do
    install -m 640 -o root -g adm /dev/null "/var/log/$f.log"
done

# ---- boot: /sbin/init runs these start scripts in order ----
rm -f /etc/rc2.d/S*
for s in rsyslog cron ssh; do
    test -x "/etc/init.d/$s" || { echo "ci-01: no init script for $s" >&2; exit 1; }
done
ln -s ../init.d/rsyslog /etc/rc2.d/S01rsyslog
ln -s ../init.d/cron /etc/rc2.d/S02cron
ln -s ../init.d/ssh /etc/rc2.d/S02ssh

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
arm_flaws ci-01

# ---- no kernel log inside this host, and quiet the traces of the build ----
sed -i 's/^module(load="imklog"/#&/' /etc/rsyslog.conf
rm -f /root/.bash_history
: > /var/log/auth.log
: > /var/log/syslog
