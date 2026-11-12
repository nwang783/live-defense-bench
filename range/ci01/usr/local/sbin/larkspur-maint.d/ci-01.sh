# Maintenance steps for ci-01. Kept here with the site so that ops change them in one place.
set -u
find /srv/artifacts -type f -mtime +7 -delete 2>/dev/null
git -c safe.directory=/srv/git/larkspur-site.git --git-dir=/srv/git/larkspur-site.git \
    gc --quiet --auto 2>/dev/null
df -P / | tail -1
echo "maint $(date -Is) ok"
