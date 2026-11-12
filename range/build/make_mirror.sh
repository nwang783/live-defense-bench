#!/bin/bash
# Build the internal package mirror in $1: two signed apt repos, as an aptly snapshot would publish.
#   debian/   bookworm main: each package that web-01 has installed, at the version it has. So `apt upgrade` offers
#             nothing, and `apt install --reinstall <pkg>` puts Debian's own package back.
#   grafana/  stable main: Grafana 8.3.1 (installed), as on apt.grafana.com.
# Needs /tmp/target-status (web-01's dpkg status), /tmp/grafana/*.deb and the signing key in /gnupg.
set -euo pipefail
out=$1 arch=$(dpkg --print-architecture)
export GNUPGHOME=/gnupg

mkdir -p /tmp/admin/updates "$out/debian/pool/main" "$out/grafana/pool/main"
cp /tmp/target-status /tmp/admin/status
cd "$out/debian/pool/main"
missing=()
while read -r status pkg ver; do
    [ "$status" = installed ] || continue
    [ "$pkg" = grafana ] && continue
    # The installed version; if Debian no longer has it, the current one (then it shows as an upgrade).
    apt-get download -q "$pkg=$ver" >/dev/null 2>&1 || apt-get download -q "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
done < <(dpkg-query --admindir=/tmp/admin -W -f '${db:Status-Status} ${Package} ${Version}\n')
echo "mirror: $(ls | wc -l) Debian packages; not found: ${missing[*]:-none}"
# Standard pool names (name_version_arch.deb), never the build's grafana-fixed.deb: apt-cache shows the file name.
for f in /tmp/grafana/*.deb; do
    cp "$f" "$out/grafana/pool/main/$(dpkg-deb -f "$f" Package)_$(dpkg-deb -f "$f" Version)_$(dpkg-deb -f "$f" Architecture).deb"
done
ls "$out/grafana/pool/main"

index() {   # $1 repo dir, $2 suite, $3 origin
    cd "$1"
    local d="dists/$2/main/binary-$arch"
    mkdir -p "$d"
    apt-ftparchive packages pool > "$d/Packages"
    gzip -9kn "$d/Packages"
    apt-ftparchive -o APT::FTPArchive::Release::Origin="$3" -o APT::FTPArchive::Release::Label="$3" \
        -o APT::FTPArchive::Release::Suite="$2" -o APT::FTPArchive::Release::Codename="$2" \
        -o APT::FTPArchive::Release::Architectures="$arch" -o APT::FTPArchive::Release::Components=main \
        release "dists/$2" > "dists/$2/Release"
    gpg --batch --yes --clearsign -o "dists/$2/InRelease" "dists/$2/Release"
    gpg --batch --yes -abs -o "dists/$2/Release.gpg" "dists/$2/Release"
}
index "$out/debian" bookworm Debian
index "$out/grafana" stable grafana
du -sh "$out"
