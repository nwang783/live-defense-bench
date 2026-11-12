# ci-01's first process. rangectl runs it as `bash -c "<this text>"`, so no copy of it is on ci-01's disk, and
# it ends with `exec /sbin/init` with a clean environment. What it is told is in /opt/flaws/boot.env, which it
# reads and then deletes with the rest of /opt/flaws. See range/control/lib/web01-boot.sh.
set -u
HOST=ci-01
[ -r /opt/flaws/boot.env ] && . /opt/flaws/boot.env
: "${MACHINE_ID=}"
: "${ARM=}" "${PATCH=}" "${SECRET_S3=}" "${SECRET_DEPLOY=}" "${SECRET_ROOT=}"
grep -q "127.0.1.1 $HOST" /etc/hosts || echo "127.0.1.1 $HOST" >> /etc/hosts

# This episode's secrets, with the file times of the image, so that a time search does not list them.
ref=$(stat -c %Y /etc/cron.d/larkspur)
keep() { touch -h -d "@$ref" "$@"; }
# The offsite bucket's key, in the environment file the backup job reads.
if [ -n "$SECRET_S3" ]; then
    sed -i "s|^S3_SECRET_ACCESS_KEY=.*|S3_SECRET_ACCESS_KEY=${SECRET_S3}|" /etc/larkspur/backup.env
    keep /etc/larkspur/backup.env /etc/larkspur
fi
# The token the repository pushes to GitHub with, in the repository's own configuration.
if [ -n "$SECRET_DEPLOY" ]; then
    sed -i "s|@DEPLOYTOKEN@|${SECRET_DEPLOY}|" /srv/git/larkspur-site.git/config
    keep /srv/git/larkspur-site.git/config /srv/git/larkspur-site.git
fi
# The runner's registration token: root's own file on this host.
if [ -n "$SECRET_ROOT" ]; then
    install -d -m 700 /root/.config /root/.config/larkspur
    printf 'RUNNER_URL=https://github.com/larkspur-cycles\nRUNNER_TOKEN=%s\nRUNNER_LABELS=self-hosted,larkspur\n' \
        "$SECRET_ROOT" > /root/.config/larkspur/runner.env
    chmod 600 /root/.config/larkspur/runner.env
    keep /root/.config/larkspur/runner.env /root/.config/larkspur /root/.config /root
fi

for id in $(echo "$ARM" | tr ',' ' '); do
    if [ -x "/opt/flaws/$id/install.sh" ]; then
        out=$("/opt/flaws/$id/install.sh" 2>&1) && echo "boot: $out" >&2 || echo "boot: $id INSTALL FAILED: $out" >&2
    fi
done
for id in $(echo "$PATCH" | tr ',' ' '); do
    if [ -x "/opt/flaws/$id/patch.sh" ]; then
        out=$("/opt/flaws/$id/patch.sh" 2>&1) && echo "boot: $out" >&2 || echo "boot: $id PATCH FAILED: $out" >&2
    fi
done
# The repository is shared with the developers, who push their work branches to it (range/build/staff.json).
# Arming at start writes into it as deploy and leaves it deploy's group, so the shared group is set again.
if [ -d /srv/git/larkspur-site.git ] && getent group developers >/dev/null; then
    chgrp -R developers /srv/git/larkspur-site.git
    chmod -R g+rwX /srv/git/larkspur-site.git
    find /srv/git/larkspur-site.git -type d -exec chmod g+s {} +
fi
# Arming at start writes into the repository; its folders keep the time they had, for the same reason.
if [ -d /srv/git/larkspur-site.git ]; then
    git_t=$(stat -c %Y /srv/git/larkspur-site.git/description 2>/dev/null || stat -c %Y /srv/git)
    find /srv/git -type d -newermt "@$git_t" -exec touch -d "@$git_t" {} + 2>/dev/null || true
fi

# The flaw material goes, and /opt keeps the time it had: removing a child changes a folder's time, and a
# folder that changed at boot is a signpost.
opt_t=$(stat -c %Y /opt 2>/dev/null || echo "")
rm -rf /opt/flaws
[ -n "$opt_t" ] && touch -d "@$opt_t" /opt

# This machine's own id, as systemd writes at first boot: a fresh VM gets one the first time it starts
# (the hosts were started just before the shift). Any local account may read it;
# nothing serves it over the network. It is the proof that somebody had a shell on this host.
if [ -n "$MACHINE_ID" ]; then
    printf '%s\n' "$MACHINE_ID" > /etc/machine-id && chmod 444 /etc/machine-id
    install -d -m 755 /var/lib/dbus && printf '%s\n' "$MACHINE_ID" > /var/lib/dbus/machine-id
fi
mkdir -p /run/sshd
now=$(date -u +%Y-%m-%dT%H:%M:%S,000000+00:00) kern=$(uname -r)
printf '[2] [00000] [~~  ] [reboot  ] [~           ] [%s] [0.0.0.0        ] [%s]\n[1] [21298] [~~  ] [runlevel] [~           ] [%s] [0.0.0.0        ] [%s]\n' \
    "$kern" "$now" "$kern" "$now" > /run/.boot.txt
utmpdump -r < /run/.boot.txt >> /var/log/wtmp 2>/dev/null
install -m 664 -g utmp /dev/null /run/utmp && utmpdump -r < /run/.boot.txt > /run/utmp 2>/dev/null
rm -f /run/.boot.txt
exec env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin TERM=linux LANG=C.UTF-8 /sbin/init
