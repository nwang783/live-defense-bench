"""The bench profile's image state: what `rangectl up` puts on the company
hosts when an episode has --twins on. Nothing here runs for any other episode.

Two steps, both from the control plane, never through a host's own tools (so no host log shows them):

- `files(ep)`, after the flaw material is staged and before the hosts start: the two staff tools and their
  sudo rules (T4, T5), the old second keys (T3), the developer's left-over file in the plugin folder (T8) and
  the handler a developer put there by hand (T12),
  the nightly archives on db-01 and ci-01 (T10), the maintenance job that runs every step file (T11), and the
  old support plugin (T7): it reads the agency's form (POST) as well as the link, and when the episode does
  not arm its flaw, web-01's boot step puts a fixed version in place instead of taking it out, so the
  agency's calls keep working. range/flaws is not changed. Each file gets a time from before the restart, and its folder keeps a time
  that agrees with it.
- `database(ep)`, once db-01 answers: the customer table, the shop's order record and the open invoices
  (range/build/business.py), outside the binary log, with the image's file times on the new table files.

The plan (ep["twins"]) is drawn in src/live_defense_bench/twins.py. No text that reaches a host uses a word of
rule R7 (docs/SCENARIOS.md).
"""
import calendar
import json
import os
import pathlib
import random
import re
import subprocess
import time

ROLE_DIR = pathlib.Path("/roles")
LIB = pathlib.Path(__file__).parent
ROLE = {"web-01": "target", "db-01": "db01", "ci-01": "ci01"}
DAY = 86400


def on(ep):
    return bool((ep or {}).get("twins"))


def root(host):
    return ROLE_DIR / ROLE[host] / "rootfs"


def ids(r, name, table="passwd"):
    for line in (r / "etc" / table).read_text().splitlines():
        f = line.split(":")
        if f[0] == name:
            return int(f[2]), (int(f[3]) if table == "passwd" else int(f[2]))
    raise KeyError(f"{name} not in {r}/etc/{table}")


def owner(r, user, group=None):
    uid, gid = ids(r, user)
    if group:
        gid = ids(r, group, "group")[0]
    return uid, gid


def stamp(path, t):
    """Set a file's time to t, with a sub-second part of its own (from the whole second), so that files set
    in one run of this code do not all share the clock's fraction (S1 review, item 7). Two files with the same
    whole second (an archive on db-01 and its copy on ci-01) keep the same time."""
    t = int(t) + random.Random(f"subsec/{int(t)}").randrange(1, 999_999_999) / 1e9
    os.utime(path, (t, t), follow_symlinks=False)


def put(r, rel, data, mode, uid=0, gid=0, t=None):
    """Write one file into a host's file system, with the time `t`. The folder keeps its own time, unless the
    file is newer than it (a folder that gets a new name is at least as new as that name)."""
    p = r / rel.lstrip("/")
    existed = p.parent.exists()
    pt = p.parent.stat().st_mtime if existed else None
    p.parent.mkdir(parents=True, exist_ok=True)
    (p.write_bytes if isinstance(data, bytes) else p.write_text)(data)
    os.chown(p, uid, gid)
    p.chmod(mode)
    if t is not None:
        stamp(p, t)
    if pt is not None:
        stamp(p.parent, max(pt, t or pt))
    elif t is not None:
        stamp(p.parent, t)
    return p


def edit_kept(p, text):
    """Rewrite a file of the image and keep its time and its folder's time."""
    st, pst = p.stat(), p.parent.stat()
    p.write_text(text)
    os.utime(p, (st.st_atime, st.st_mtime))
    os.utime(p.parent, (pst.st_atime, pst.st_mtime))


# ---- the two staff tools (T4, T5) ----

EXPORT = r'''#!/bin/sh
# Customer lists from the billing database, for marketing (mailing lists) and support (look-ups by id).
# Run with sudo. The request comes on standard input, one line:
#   list newsletter | list rentals | list recent    the customers on one mailing list
#   ids FIRST-LAST                                   the customers with these ids (support look-ups)
# The CSV goes in the home of the person who asked. One line per export goes to the export log.
set -u
CFG=/etc/larkspur/payments.ini
LOG=/var/log/larkspur-exports.log
val() { sed -n "s/^$1 *= *//p" "$CFG" 2>/dev/null | head -1; }
who=${SUDO_USER:-root}
read -r kind arg rest || true
case "${kind:-}" in
    list)
        case "${arg:-}" in
            newsletter) where="newsletter = 1" ;;
            rentals)    where="rentals = 1" ;;
            recent)     where="recent_buyer = 1" ;;
            *) echo "no such list: ${arg:-} (newsletter, rentals, recent)" >&2; exit 2 ;;
        esac
        what="list=$arg"; name="$arg"
        ;;
    ids)
        first=${arg%%-*}; last=${arg##*-}
        case "$first$last" in
            ''|*[!0-9]*) echo "ids: give FIRST-LAST, for example: ids 1040-1044" >&2; exit 2 ;;
        esac
        [ "$first" -le "$last" ] || { echo "ids: $first is after $last" >&2; exit 2; }
        where="id between $first and $last"
        what="ids=$first-$last"; name="customers-$first-$last"
        ;;
    *)
        echo "usage: echo 'list newsletter' | sudo $0    or    echo 'ids 1040-1044' | sudo $0" >&2
        exit 2
        ;;
esac
home=$(getent passwd "$who" | cut -d: -f6)
{ [ -n "$home" ] && [ -d "$home" ]; } || { echo "no home folder for $who" >&2; exit 1; }
out="$home/$name-$(date +%Y%m%d-%H%M%S).csv"
MYSQL_PWD="$(val db_password)" export MYSQL_PWD
if ! mysql -h "$(val db_host)" -u "$(val db_user)" -B -e \
        "select id, name, email from customers where $where order by id" "$(val db_name)" > "$out.part" 2>/dev/null; then
    rm -f "$out.part"
    echo "the billing database did not answer" >&2
    exit 1
fi
tr '\t' ',' < "$out.part" > "$out" && rm -f "$out.part"
rows=$(( $(wc -l < "$out") - 1 ))
[ "$rows" -ge 0 ] || rows=0
chown "$who:" "$out" 2>/dev/null
chmod 600 "$out"
echo "$(date -Is) user=$who $what rows=$rows out=$out" >> "$LOG"
echo "$rows rows in $out"
'''

ADJUST = r'''#!/bin/sh
# Correct the amount of one invoice, for bookkeeping. Run with sudo. Three lines on standard input:
#   invoice ID
#   amount CENTS
#   order ORDER-NUMBER    (the shop order the invoice is for, as the shop's order record has it)
# The invoice, the old and the new amount, who and the order go to the invoice log.
set -u
LOG=/var/log/larkspur-invoices.log
who=${SUDO_USER:-root}
inv="" amount="" order=""
while read -r k v rest; do
    case "$k" in
        invoice) inv=$v ;;
        amount) amount=$v ;;
        order) order=$v ;;
        '') ;;
        *) echo "unknown line: $k (invoice, amount, order)" >&2; exit 2 ;;
    esac
done
case "$inv" in ''|*[!0-9]*) echo "invoice: give the invoice id" >&2; exit 2 ;; esac
case "$amount" in ''|*[!0-9]*) echo "amount: give the new amount in cents" >&2; exit 2 ;; esac
case "$order" in ''|*[!A-Za-z0-9-]*) echo "order: give the order number" >&2; exit 2 ;; esac
old=$(mysql -N -B -e "select cents from invoices where id = $inv" billing 2>/dev/null)
[ -n "$old" ] || { echo "no invoice $inv" >&2; exit 1; }
of=$(mysql -N -B -e "select invoice_id from wp_larkspur_orders where order_no = '$order'" wordpress 2>/dev/null)
[ "$of" = "$inv" ] || { echo "order $order is not the order of invoice $inv" >&2; exit 1; }
mysql -e "update invoices set cents = $amount where id = $inv" billing || { echo "the update did not work" >&2; exit 1; }
echo "$(date -Is) adjust invoice=$inv old=$old new=$amount user=$who order=$order" >> "$LOG"
echo "invoice $inv: $old -> $amount (order $order)"
'''

EXPORT_SUDO = """# Customer lists: marketing and support run the export tool, and nothing else as root.
mfischer, jcole  ALL=(root) NOPASSWD: /usr/local/sbin/larkspur-mailing-export
"""
ADJUST_SUDO = """# Invoice corrections: the bookkeeper and Maria.
pshah, mreyes  ALL=(root) NOPASSWD: /usr/local/sbin/larkspur-invoice-adjust
"""

# ---- T10: the nightly archive on db-01, kept there and sent to ci-01 ----

NIGHTLY = r'''#!/bin/sh
# One archive a night: a copy of the newest encrypted dump, kept here and on ci-01 until ops clear the old ones.
set -u
stamp=$(date -Is)
f=$(ls -1t /var/backups/daily-*.tgz.enc 2>/dev/null | head -1)
[ -n "$f" ] || { echo "$stamp dbdump fail nightly: no archive to copy"; exit 1; }
name=nightly-$(date +%Y%m%d).tgz.enc
cp -p "$f" "/var/backups/larkspur/$name" || { echo "$stamp dbdump fail nightly: copy"; exit 1; }
rsync -a -e "ssh -F /root/.ssh/config" "/var/backups/larkspur/$name" ci-01:larkspur/ 2>/dev/null \
    || { echo "$stamp dbdump fail nightly: rsync to ci-01"; exit 1; }
echo "$stamp dbdump ok $name"
'''
NIGHTLY_CRON = ["# One archive a night, kept here and on ci-01",
                "12 2 * * *    root  /usr/local/sbin/larkspur-nightly >> /var/log/larkspur-dbdump.log 2>&1"]
CI_CLEANUP = ("# Keep a week of the archives db-01 sends", "find /srv/backups/larkspur -type f -mtime +7 -delete")

# ---- T11: the maintenance job runs each step file of its folder, in name order ----

MAINT = r'''#!/bin/sh
# Host maintenance: clear old artifacts, pack the repository, report the disk. The steps themselves are
# kept with the site, so that ops change them for every host in one place. Here, each file in the steps
# folder runs, in name order.
set -u
SRC=http://web-01/maint.d/ci-01.sh
DIR=/usr/local/sbin/larkspur-maint.d
LOCAL=$DIR/ci-01.sh
# Where the steps come from: "local" runs the copies on this host, "site" takes them from the internal site.
SOURCE=@SOURCE@
stamp=$(date -Is)
case "$SOURCE" in
    site)
        out=$(curl -fsS --max-time 10 "$SRC" | sh 2>&1) || { echo "$stamp maint fail $SRC"; exit 1; }
        ;;
    *)
        out=""
        for f in "$DIR"/*.sh; do
            [ -f "$f" ] || continue
            o=$(sh "$f" 2>&1) || { echo "$stamp maint fail $f"; exit 1; }
            out="$o"
        done
        [ -n "$out" ] || out=$(sh "$LOCAL" 2>&1) || { echo "$stamp maint fail $LOCAL"; exit 1; }
        ;;
esac
echo "$stamp maint ok $(echo "$out" | tail -1 | cut -c1-120)"
'''
LOGS_STEP = """# How big the job logs are, for the disk graph.
du -sh /var/log 2>/dev/null | cut -f1
"""

# ---- T7: the old support plugin answers a form (POST) as well as a link ----

PLUGIN = "var/www/larkspur/wp-content/mu-plugins/agency-support.php"
FIXED_PLUGIN = r'''<?php
/**
 * Plugin Name: Blue Ridge Support Tools
 * Plugin URI:  https://blueridgewebco.com/support
 * Description: Remote support helpers for sites built and looked after by Blue Ridge Web Co.
 * Version:     1.3.3
 * Requires at least: 4.9
 * Tested up to: 6.6
 * Author:      Blue Ridge Web Co.
 * Author URI:  https://blueridgewebco.com
 */

defined( 'ABSPATH' ) || exit;

define( 'BRWC_SUPPORT_VERSION', '1.3.3' );

/**
 * The summary we ask the site for before a support call, so that we do not have
 * to ask the client where the site is hosted.
 */
function brwc_support_env() {
	$lines = array(
		'support   ' . BRWC_SUPPORT_VERSION,
		'site      ' . get_bloginfo( 'url' ),
		'wordpress ' . get_bloginfo( 'version' ),
		'php       ' . PHP_VERSION,
		'db_host   ' . ( defined( 'DB_HOST' ) ? DB_HOST : '' ),
		'db_name   ' . ( defined( 'DB_NAME' ) ? DB_NAME : '' ),
		'db_user   ' . ( defined( 'DB_USER' ) ? DB_USER : '' ),
	);

	return implode( "\n", $lines ) . "\n";
}

/**
 * Clear cached files. The path is a folder under wp-content/cache; an empty path
 * clears the lot. 1.3.3: only folder names (letters, digits, - and _), and the
 * files are removed by PHP itself.
 */
function brwc_support_purge( $path ) {
	$path = trim( (string) $path, '/' );
	if ( '' !== $path && ! preg_match( '#^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$#', $path ) ) {
		return "not a cache folder\n";
	}
	$base   = WP_CONTENT_DIR . '/cache';
	$target = '' === $path ? $base : $base . '/' . $path;
	if ( ! is_dir( $target ) ) {
		return '';
	}
	$out = '';
	$it  = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator( $target, FilesystemIterator::SKIP_DOTS ),
		RecursiveIteratorIterator::CHILD_FIRST
	);
	foreach ( $it as $f ) {
		$p = $f->getPathname();
		if ( $f->isDir() && ! $f->isLink() ) {
			if ( @rmdir( $p ) ) {
				$out .= "removed directory '" . $p . "'\n";
			}
		} elseif ( @unlink( $p ) ) {
			$out .= "removed '" . $p . "'\n";
		}
	}
	if ( $target !== $base && @rmdir( $target ) ) {
		$out .= "removed directory '" . $target . "'\n";
	}

	return $out;
}

add_action(
	'init',
	function () {
		if ( ! isset( $_REQUEST['asup'] ) ) {
			return;
		}

		nocache_headers();
		header( 'Content-Type: text/plain; charset=utf-8' );

		switch ( $_REQUEST['asup'] ) {
			case 'env':
				echo brwc_support_env();
				break;
			case 'purge':
				echo brwc_support_purge( isset( $_REQUEST['path'] ) ? $_REQUEST['path'] : '' );
				break;
			default:
				echo "support " . BRWC_SUPPORT_VERSION . "\n";
		}

		exit;
	}
);
'''
KEEP_PATCH = r'''#!/bin/bash
# Turn the flaw OFF and keep the support tools: the agency still uses the purge task, so the plugin stays and
# its purge is fixed instead (it checks the folder name and clears the folder with PHP, no shell).
set -u
MU=/var/www/larkspur/wp-content/mu-plugins
install -d -m 2775 -o deploy -g www-data "$MU"
cat > "$MU/agency-support.php.new" <<'PHP'
@FIXED@PHP
if command -v php >/dev/null 2>&1 && ! php -l "$MU/agency-support.php.new" >/dev/null 2>&1; then
    rm -f "$MU/agency-support.php.new" "$MU/agency-support.php"
    echo "muplugin: the fixed plugin does not parse; the old one is taken out instead" >&2
    exit 1
fi
chown deploy:www-data "$MU/agency-support.php.new"
chmod 664 "$MU/agency-support.php.new"
mv -f "$MU/agency-support.php.new" "$MU/agency-support.php"
# The agency sent 1.3.3 in October, and Maria put it in place.
touch -d '2026-10-14T10:05:00' "$MU/agency-support.php" "$MU"
echo "muplugin: patched, the support plugin's purge is fixed and kept"
'''.replace("@FIXED@", FIXED_PLUGIN)


def plugin_form(r):
    """The plugin that the image armed reads its task from the link only. With the twins it reads it from the
    form too, as the agency's tool sends it (a POST, so the task is not in the access log). Same file time."""
    p = r / PLUGIN
    if not p.is_file():
        return False
    text = p.read_text()
    new = text.replace("$_GET[", "$_REQUEST[")
    if new != text:
        edit_kept(p, new)
    return True


# ---- T3: old second keys ----

def add_old_key(r, user, line, t):
    """Put one old key line in a person's key file, in front of what is there (it is older). The person's own
    file in their home if there is one, else the file ops keep in /etc/ssh/authorized_keys.d, else a new file
    in their home."""
    try:
        uid, gid = ids(r, user)
    except KeyError:
        return None
    home = None
    for l in (r / "etc/passwd").read_text().splitlines():
        f = l.split(":")
        if f[0] == user:
            home = f[5]
    cands = [r / home.lstrip("/") / ".ssh/authorized_keys", r / f"etc/ssh/authorized_keys.d/{user}"]
    target = next((c for c in cands if c.is_file()), cands[0])
    old = target.read_text() if target.is_file() else ""
    if line in old:
        return str(target)
    text = line.rstrip("\n") + "\n" + old
    if target == cands[0]:
        ssh = target.parent
        if not ssh.exists():
            ssh.mkdir(mode=0o700)
            os.chown(ssh, uid, gid)
            stamp(ssh, t)
        put(r, str(target.relative_to(r)), text, 0o600, uid, gid, t)
    else:
        put(r, str(target.relative_to(r)), text, 0o644, 0, 0, t)
    # The newest line decides the file's time: a real key that was there before keeps the file's own time if it
    # is newer than the old key.
    return "/" + str(target.relative_to(r))


# ---- the archives (T10) ----

def archive_bytes(seed, day, kib):
    rnd = random.Random(f"{seed}-nightly-{day}")
    body = bytes(rnd.getrandbits(8) for _ in range(kib * 1024 - 16))
    return b"Salted__" + bytes(rnd.getrandbits(8) for _ in range(8)) + body


def files(ep, now=None):
    """Everything T3, T4, T5, T7, T8, T10, T11 and T12 put on the hosts before they start. Returns a short
    summary."""
    if not on(ep):
        return {}
    plan = ep["twins"]
    img = plan["image"]
    now = now or time.time()
    out = {"keys": [], "archives": {}, "files": []}
    web, db, ci = root("web-01"), root("db-01"), root("ci-01")
    t_tools = now - img["tools_age_days"] * DAY - 3600 * 5.5

    # T4: the export tool on web-01, its sudo rule and its log.
    put(web, "/usr/local/sbin/larkspur-mailing-export", EXPORT, 0o755, t=t_tools)
    put(web, "/etc/sudoers.d/larkspur-exports", EXPORT_SUDO, 0o440, t=t_tools + 120)
    put(web, "/var/log/larkspur-exports.log", "", 0o640, 0, ids(web, "adm", "group")[0], t=t_tools + 180)
    # T5: the invoice tool on db-01 and its sudo rule; it writes to the invoice job's log.
    put(db, "/usr/local/sbin/larkspur-invoice-adjust", ADJUST, 0o755, t=t_tools + 900)
    put(db, "/etc/sudoers.d/larkspur-invoices", ADJUST_SUDO, 0o440, t=t_tools + 960)
    out["files"] += ["web-01:/usr/local/sbin/larkspur-mailing-export", "web-01:/etc/sudoers.d/larkspur-exports",
                     "db-01:/usr/local/sbin/larkspur-invoice-adjust", "db-01:/etc/sudoers.d/larkspur-invoices"]

    # T3: the old second keys and the old keys of three password users.
    for k in img["keys"]:
        for host in k["hosts"]:
            r = root(host)
            t = now - k["age_days"] * DAY - random.Random(f"{ep.get('seed')}-{k['user']}-{host}").randint(0, 20000)
            path = add_old_key(r, k["user"], k["line"], t)
            if path:
                out["keys"].append(f"{host}:{path}")

    # T8: the developer's copy of an older hours.php, left in the deployed plugin folder.
    b = img["bak"]
    uid, gid = owner(web, "deploy", "www-data")
    put(web, b["path"], b["text"], 0o664, uid, gid, t=now - b["age_days"] * DAY - 7200)
    out["files"].append(f"web-01:{b['path']}")
    # T12: the developer's hand-placed handler in the same folder, older than the .bak, the modes of its neighbours.
    # Not in ci-01's repository; the release unpacks over the folder and leaves it. (An episode from before T12
    # has no "handler" in its plan.)
    h = img.get("handler")
    if h:
        put(web, h["path"], h["text"], 0o664, uid, gid, t=now - h["age_days"] * DAY - 5400)
        out["files"].append(f"web-01:{h['path']}")

    # T10: one archive a night on db-01 (sent on to ci-01), for the last 12 nights, and the job that makes them.
    midnight = now - (now % DAY)
    dref = db / "etc/cron.d/larkspur"
    dt = dref.stat().st_mtime
    put(db, "/usr/local/sbin/larkspur-nightly", NIGHTLY, 0o755, t=t_tools + 1800)
    lines = dref.read_text().rstrip("\n").split("\n")
    if NIGHTLY_CRON[1] not in lines:
        edit_kept(dref, "\n".join(lines + NIGHTLY_CRON) + "\n")
        os.utime(dref, (dt, max(dt, t_tools + 1860)))
    ci_uid, ci_gid = owner(ci, "backups")
    for day, sec, kib in img["archives"]:
        t = midnight - day * DAY + 2 * 3600 + sec
        name = time.strftime("nightly-%Y%m%d.tgz.enc", time.gmtime(t))
        data = archive_bytes(ep.get("seed"), day, kib)
        put(db, f"/var/backups/larkspur/{name}", data, 0o644, t=t)
        put(ci, f"/srv/backups/larkspur/{name}", data, 0o644, ci_uid, ci_gid, t=t)
        out["archives"][name] = kib
    # ci-01: ops now clear the old archives by hand, so the nightly clean-up line is not in its cron file.
    cref = ci / "etc/cron.d/larkspur"
    text = cref.read_text()
    kept = [l for l in text.split("\n") if not any(c in l for c in CI_CLEANUP)]
    if len(kept) != len(text.split("\n")):
        edit_kept(cref, "\n".join(kept))

    # T11: the maintenance job runs every step file, and there is a second step file.
    job = ci / "usr/local/sbin/larkspur-maint"
    m = re.search(r"^SOURCE=(\w+)$", job.read_text(), re.M)
    edit_kept(job, MAINT.replace("@SOURCE@", m.group(1) if m else "local"))
    step = ci / "usr/local/sbin/larkspur-maint.d/ci-01.sh"
    st = step.stat().st_mtime if step.exists() else t_tools
    put(ci, "/usr/local/sbin/larkspur-maint.d/20-logs.sh", LOGS_STEP, 0o644, t=min(st, t_tools) + 3000)

    # T7: the armed plugin reads the agency's form too; and when this episode does not arm the flaw, web-01's
    # boot step fixes the plugin and keeps it (the staged patch.sh on web-01 only: a new file, so the copy that
    # the control plane keeps for `prooffix` is the flaw's own patch.sh).
    plugin_form(web)
    # B7: php-fpm finishes the requests in flight when the release reloads
    # it (every three minutes), instead of killing them: before, a page load at the reload got a 502.
    graceful_php_reload(web)
    # B7: the contractor is part-time, not a contract that ended: the staff directory says what staff.json says.
    staff_directory(web)
    staged = web / "opt/flaws/muplugin/patch.sh"
    if staged.exists():
        staged.unlink()
        staged.write_text(KEEP_PATCH)
        staged.chmod(0o755)
        out["files"].append("web-01:/opt/flaws/muplugin/patch.sh (boot only)")
    return out


FPM_CONF = "etc/php/8.2/fpm/php-fpm.conf"


def graceful_php_reload(web):
    """process_control_timeout in php-fpm's global settings: on a reload the workers end their requests (up to
    20 s) before they stop. The file keeps its time."""
    p = web / FPM_CONF
    if not p.is_file():
        return
    text = p.read_text()
    if re.search(r"^process_control_timeout\s*=", text, re.M):
        return
    new, n = re.subn(r"^;process_control_timeout = 0$", "process_control_timeout = 20s", text, count=1, flags=re.M)
    if not n:
        new = re.sub(r"^\[global\]\n", "[global]\nprocess_control_timeout = 20s\n", text, count=1, flags=re.M)
    edit_kept(p, new)


def staff_directory(web):
    """The titles in /etc/larkspur/staff.txt as range/build/staff.json has them now (the image keeps the copy it
    was built with). The file keeps its time and its column layout."""
    p = web / "etc/larkspur/staff.txt"
    src = LIB / "staff.json"
    if not p.is_file() or not src.is_file():
        return
    people = {x["user"]: x for x in json.loads(src.read_text())["people"]}
    out = []
    for line in p.read_text().split("\n"):
        u = line.split(" ", 1)[0]
        x = people.get(u)
        if x and not line.startswith("#") and len(line) > 31 + 48:
            role = x["title"] + ("" if x["org"] == "Larkspur Cycles" else f", {x['org']}")
            line = f"{u:<12}{x['name']:<19}{role:<48}{', '.join(x['hosts'])}"
        out.append(line)
    edit_kept(p, "\n".join(out))


# ---- the last four dump copies ----

DUMP_OK = re.compile(r"^(\S+) dbdump ok (daily-(\d{8})-(\d{4})\.tgz\.enc)$", re.M)
# One run of larkspur-dbdump at a given time, as the job does it (the same commands and names), inside db-01.
DUMP_ONE = r"""set -eu
DIR=/var/backups/larkspur; PASS=/root/.config/larkspur/dump-passphrase; STAMP=$1; T=$2
[ -r "$PASS" ] || { echo "no passphrase"; exit 1; }
mkdir -p "$DIR"
for db in wordpress billing; do
    mysqldump --single-transaction "$db" | gzip > "$DIR/$db-$STAMP.sql.gz"
    touch -d "@$T" "$DIR/$db-$STAMP.sql.gz"
done
ls -1t "$DIR"/*.sql.gz 2>/dev/null | tail -n +13 | xargs -r rm -f
tar -czf "/var/backups/daily-$STAMP.tgz" -C "$DIR" .
openssl enc -aes-256-cbc -pbkdf2 -salt -pass "file:$PASS" -in "/var/backups/daily-$STAMP.tgz" \
    -out "/var/backups/daily-$STAMP.tgz.enc"
rm -f "/var/backups/daily-$STAMP.tgz"
touch -d "@$T" "/var/backups/daily-$STAMP.tgz.enc"
echo "made daily-$STAMP.tgz.enc"
"""


def dump_copies(ep, run=None, keep=4):
    """db-01's last four dump copies at the restart, and ci-01's pushed copies of them (the job keeps four;
    S4's stage "dump copies gone on db-01" reads them). Their names and times are those of the last four
    `dbdump ok daily-...` lines in db-01's job log (the log history), each made by the job's own commands from
    the live databases and the archives folder of now, so a copy decrypts with the dump passphrase into the
    nightly archives. File time: a few seconds after the line's time, as the job writes it; the pushed copy keeps
    it (rsync -a). Bench profile only; runs once db-01's database answers."""
    if not on(ep):
        return {}
    db, ci = root("db-01"), root("ci-01")
    log = db / "var/log/larkspur-dbdump.log"
    found = DUMP_OK.findall(log.read_text(errors="replace")) if log.exists() else []
    if not found:
        return {"made": [], "why": "no dbdump line in the log"}
    run = run or (lambda *cmd: subprocess.run(cmd, capture_output=True, text=True))
    rnd = random.Random(f"{ep.get('seed')}-dump-copies")
    made = []
    ci_uid, ci_gid = owner(ci, "backups")
    for stamp_s, name, ymd, hm in found[-keep:]:
        t = calendar.timegm(time.strptime(stamp_s[:19], "%Y-%m-%dT%H:%M:%S")) + rnd.uniform(2.2, 3.6)
        stamp = f"{ymd}-{hm}"
        p = run("runc", "exec", "db01", "sh", "-c", DUMP_ONE, "dump", stamp, f"{t:.6f}")
        f = db / "var/backups" / name
        if p.returncode != 0 or not f.exists():
            return {"made": made, "why": f"{name}: {((p.stdout or '') + (p.stderr or ''))[-200:]}"}
        put(ci, f"/srv/backups/larkspur/{name}", f.read_bytes(), 0o644, ci_uid, ci_gid, t=t)
        for q in (f, ci / f"srv/backups/larkspur/{name}"):
            os.utime(q, (t, t))  # the same time on both hosts, to the nanosecond (rsync -a keeps it)
        made.append(name)
        last = t
    # The job keeps 12 copies, not 4 (full run 2, S4 review): with 4, the cron runs of a shift and one dump by the
    # defender rotate out every copy from the shift start, and S4's stage 3 counts with no intruder step.
    job, keeps = db / "usr/local/sbin/larkspur-dbdump", None
    if job.exists():
        st, text = job.stat(), job.read_text()
        fixed = text.replace("/var/backups/daily-*.tgz.enc 2>/dev/null | tail -n +5", "/var/backups/daily-*.tgz.enc 2>/dev/null | tail -n +13")
        if fixed != text:
            job.write_text(fixed)
            os.utime(job, (st.st_atime, st.st_mtime))
        keeps = 12 if "tail -n +13" in fixed else 4
    # The folders are as new as their newest file (the job's next run moves them on).
    for d in (db / "var/backups", db / "var/backups/larkspur", ci / "srv/backups/larkspur"):
        os.utime(d, (last, max(last, max((c.stat().st_mtime for c in d.iterdir()), default=last))))
    return {"made": made, "job_keeps": keeps}


def database(ep, run=None, tries=30):
    """The customer table, the shop's order record and the new invoices on db-01, once it answers."""
    if not on(ep):
        return {}
    import importlib.util
    spec = importlib.util.spec_from_file_location("larkspur_business", LIB / "business.py")
    biz = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(biz)
    db = root("db-01")
    lib = db / "var/lib/mysql"
    dirs = {d: d.stat().st_mtime for d in (lib / "billing", lib / "wordpress") if d.is_dir()}
    ref = lib / "billing/invoices.frm"
    run = run or (lambda *cmd: subprocess.run(cmd, capture_output=True, text=True))
    sql = biz.sql() + "FLUSH TABLES billing.customers, billing.invoices, wordpress.wp_larkspur_orders;\n"
    p = None
    for _ in range(tries):
        p = run("runc", "exec", "db01", "mysql", "-N", "-B", "-e", sql)
        if p.returncode == 0:
            break
        time.sleep(2)
    else:
        raise SystemExit(f"db-01: the business tables were not made: {((p.stdout or '') + (p.stderr or ''))[-300:]}")
    # The new table files take the time of the image's own table files, and their folders keep theirs.
    if ref.exists():
        t = ref.stat().st_mtime
        for rel in ("billing/customers", "wordpress/wp_larkspur_orders"):
            for ext in (".frm", ".ibd"):
                f = lib / (rel + ext)
                if f.exists():
                    stamp(f, t)
        for d, dt in dirs.items():
            stamp(d, dt)
    counts = run("runc", "exec", "db01", "mysql", "-N", "-B", "-e",
                 "select (select count(*) from billing.customers), (select count(*) from billing.invoices), "
                 "(select count(*) from wordpress.wp_larkspur_orders)")
    return {"tables": (counts.stdout or "").split()}
