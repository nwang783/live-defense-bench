"""The bench profile's log history: about two weeks of back-dated, ordinary log
lines on the three company hosts, written as files by the control plane before the hosts start. Nothing here runs
for an episode without the bench profile (ep["twins"]).

The story the files tell (and the defender's handover note says): the hosting provider moved the three servers to
new VMs today and restored the last two weeks of their logs with them. So the logs go back about 14 days, stop a
few minutes before the restart, and the live shift appends to the same current files.

Two parts:
- `generate(ep, facts, end)`: pure. From the episode (its seed, people, addresses, twin plan) and a few facts read
  from the image (accounts, key fingerprints, cron lines, the release's commit), every history file of each host:
  {host: {path: File}}. Deterministic: a random stream of its own (f"history/{seed}"), so that no earlier draw of
  the episode changes.
- `write(ep)`: reads the facts from /roles/<role>/rootfs, calls generate and writes the files with the owners,
  modes and times that logrotate and the daemons give them.

What is generated per host (formats copied from what the live hosts write):
- /var/log/auth.log (+ .1, .2.gz ...: weekly, Sunday 06:25, as Debian's rsyslog logrotate block): sshd sessions of
  each person from their usual address(es) on their working days, service logins (the release from ci-01, the
  archive copies from db-01, the old scripts' deploy password logins), sudo lines, cron's PAM lines, and internet
  SSH guessing on web-01;
- /var/log/syslog (same rotation): cron's CMD lines, the release's own lines, rsyslog's HUP at each rotation and
  its exit at the move;
- web-01 /var/log/nginx/larkspur.access.log (+ .1, .2.gz ... .14.gz: daily 06:25): visitors, crawlers, the uptime
  monitor, scanners, the editor's and Maria's wp-admin work, the agency's support calls (T7), the hand-placed
  handler's POSTs (T12), the payment partner;
- the job logs (not rotated on these hosts): each cron job's own line at each run;
- the business logs: the customer exports (T4's habit), the invoice corrections (T5's habit, each to the order
  total that the shop database still has), the archive clean-ups (T10's habit);
- /var/log/wtmp (`last`), /var/log/btmp (+ .1, monthly), /var/log/lastlog, /var/lib/logrotate/status.

Rules (tested in tests/v2_history.py): an intruder address never appears; an address that the twins present as new
today (T1) never appears; each person's usual address is there on most of their working days; nothing uses an old
second key (T3), the planted extra key or the planted extra PHP file; no word of rule R7.
"""
import base64
import calendar
import gzip
import hashlib
import json
import os
import pathlib
import random
import re
import struct
import time

DAY = 86400
HISTORY_DAYS = 14
ROLE = {"web-01": "target", "db-01": "db01", "ci-01": "ci01"}
OFFICE = {"web-01": "10.20.0.10", "db-01": "10.20.0.20", "ci-01": "10.20.0.30"}
ROLE_DIR = pathlib.Path("/roles")
SITE = "larkspurcycles.com"
RSYSLOG_VERSION = "8.2302.0"
TARGET_TAG = "history"


class File:
    """One file to write: its bytes, mode, owner and group names, and its time."""
    __slots__ = ("data", "mode", "user", "group", "mtime")

    def __init__(self, data, mode, user, group, mtime):
        self.data, self.mode, self.user, self.group, self.mtime = data, mode, user, group, mtime


def on(ep):
    return bool((ep or {}).get("twins"))


# ---- small helpers ----

_DAYS = {}


def _day(t, fmt):
    k = (int(t) // DAY, fmt)
    v = _DAYS.get(k)
    if v is None:
        v = _DAYS[k] = time.strftime(fmt, time.gmtime(k[0] * DAY))
    return v


def _hms(t):
    s = int(t) % DAY
    return "%02d:%02d:%02d" % (s // 3600, s // 60 % 60, s % 60)


def iso(t):
    """rsyslog's RSYSLOG_FileFormat time, as the hosts write it."""
    return "%sT%s.%06d+00:00" % (_day(t, "%Y-%m-%d"), _hms(t), int((t % 1) * 1e6))


def iso_s(t):
    """`date -Is` on the hosts (UTC)."""
    return "%sT%s+00:00" % (_day(t, "%Y-%m-%d"), _hms(t))


def clf(t):
    return "%s:%s +0000" % (_day(t, "%d/%b/%Y"), _hms(t))


def fingerprint(blob):
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def key_blob(line):
    """The public key blob of an authorized_keys line (with or without options), or None."""
    parts = line.split()
    for i, p in enumerate(parts):
        if p.startswith(("ssh-", "ecdsa-", "sk-")) and i + 1 < len(parts):
            try:
                return base64.b64decode(parts[i + 1])
            except ValueError:
                return None
    return None


def private_key_blob(text):
    """The public key blob inside an unencrypted openssh-key-v1 private key."""
    body = "".join(l for l in text.splitlines() if l and not l.startswith("-----"))
    raw = base64.b64decode(body)
    if not raw.startswith(b"openssh-key-v1\0"):
        return None
    off = len(b"openssh-key-v1\0")

    def string(o):
        n = struct.unpack(">I", raw[o:o + 4])[0]
        return raw[o + 4:o + 4 + n], o + 4 + n
    _, off = string(off)  # cipher
    _, off = string(off)  # kdf
    _, off = string(off)  # kdf options
    off += 4  # number of keys
    blob, _ = string(off)
    return blob


def key_type(blob):
    n = struct.unpack(">I", blob[:4])[0]
    name = blob[4:4 + n].decode()
    return {"ssh-ed25519": "ED25519", "ssh-rsa": "RSA"}.get(name, name.upper())


# ---- cron lines ----

def _field(spec, lo, hi):
    out = set()
    for part in spec.split(","):
        step = 1
        if "/" in part:
            part, s = part.split("/", 1)
            step = int(s)
        if part == "*":
            a, b = lo, hi
        elif "-" in part:
            a, b = (int(x) for x in part.split("-", 1))
        else:
            a = b = int(part)
        out.update(range(a, b + 1, step))
    return out


def parse_cron(text):
    """[(minutes, hours, doms, months, dows, dom_any, dow_any, user, command)] of a system crontab's job lines.
    `command` keeps what cron logs: the command field with one separating blank removed."""
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or re.match(r"^[A-Za-z_]+=", s):
            continue
        m = re.match(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(\s.*)$", line)
        if not m:
            continue
        mi, ho, dom, mon, dow, user, cmd = m.groups()
        try:
            out.append((_field(mi, 0, 59), _field(ho, 0, 23), _field(dom, 1, 31), _field(mon, 1, 12),
                        {d % 7 for d in _field(dow, 0, 7)}, dom == "*", dow == "*", user, cmd[1:]))
        except ValueError:
            continue
    return out


def cron_runs(jobs, start, end):
    """[(t, job)] of every run between start and end, in time order (t: the minute, UTC)."""
    runs = []
    t = int(start // 60 * 60 + 60)
    while t < end:
        g = time.gmtime(t)
        dow = (g.tm_wday + 1) % 7
        for j in jobs:
            mi, ho, dom, mon, dows, dom_any, dow_any = j[:7]
            if g.tm_min in mi and g.tm_hour in ho and g.tm_mon in mon:
                day_ok = (g.tm_mday in dom) if dow_any else (dow in dows) if dom_any else \
                    (g.tm_mday in dom or dow in dows)
                if day_ok:
                    runs.append((t, j))
        t += 60
    return runs


# ---- utmp records (wtmp, btmp) and lastlog ----

def utmp_record(arch, typ, pid, line, uid_, user, host, t, addr=None):
    """One struct utmp as glibc writes it: 384 bytes on x86_64 (32-bit times), 400 on aarch64."""
    ip = bytes(16)
    if addr and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", addr):
        ip = bytes(int(x) for x in addr.split(".")) + bytes(12)
    sec, usec = int(t), int((t % 1) * 1e6)
    enc = lambda s, n: s.encode()[:n].ljust(n, b"\0")  # noqa: E731
    head = struct.pack("<hxxi32s4s32s256shh", typ, pid, enc(line, 32), enc(uid_, 4), enc(user, 32), enc(host, 256),
                       0, 0)
    if arch == "aarch64":
        return head + struct.pack("<qqq16s20s4x", 0, sec, usec, ip, bytes(20))
    return head + struct.pack("<iii16s20s", 0, sec, usec, ip, bytes(20))


def lastlog_bytes(arch, entries):
    """/var/log/lastlog: one record per uid (time, line, host), sparse."""
    size = 296 if arch == "aarch64" else 292
    if not entries:
        return b""
    buf = bytearray(size * (max(entries) + 1))
    for uid, (t, line, host) in entries.items():
        tf = struct.pack("<q", int(t)) if size == 296 else struct.pack("<i", int(t))
        rec = tf + line.encode()[:32].ljust(32, b"\0") + host.encode()[:256].ljust(256, b"\0")
        buf[uid * size:uid * size + size] = rec
    return bytes(buf)


# ---- the content of the work: what the people run, as sudo logs it ----

SUDO_CMDS = {
    ("ops2", "web-01"): ["/usr/bin/tail -n 20 /var/log/auth.log", "/usr/sbin/service nginx status",
                         "/usr/sbin/service php8.2-fpm status", "/usr/bin/tail -n 20 /var/log/nginx/larkspur.error.log",
                         "/usr/bin/du -sh /var/www/larkspur/wp-content/uploads"],
    ("ops2", "db-01"): ["/usr/sbin/service mariadb status", "/usr/sbin/service redis-server status",
                        "/usr/bin/ls -lh /var/backups/larkspur", "/usr/bin/ls -l /var/backups/larkspur"],
    ("ops2", "ci-01"): ["/usr/bin/tail -n 10 /var/log/larkspur-release.log", "/usr/bin/tail -n 5 /var/log/larkspur-maint.log",
                        "/usr/bin/ls -lt /srv/backups/larkspur", "/usr/sbin/service cron status"],
    ("dba", "db-01"): ["/usr/bin/mysql -e 'show processlist'", "/usr/bin/mysqladmin status",
                       "/usr/bin/mysql -N -e 'select table_schema, round(sum(data_length+index_length)/1048576,1) "
                       "from information_schema.tables group by table_schema'",
                       "/usr/bin/ls -lh /var/backups/larkspur"],
    ("owner", "db-01"): ["/usr/bin/ls -lt /var/backups/larkspur"],
    ("owner", "web-01"): ["/usr/bin/tail -n 30 /var/log/nginx/larkspur.error.log", "/usr/sbin/service nginx status",
                          "/usr/sbin/service php8.2-fpm status", "/usr/bin/tail -n 5 /var/log/offsite-backup.log"],
}
DEV_SUDO = [("www-data", "/usr/local/bin/wp --path=/var/www/larkspur cache flush"),
            ("www-data", "/usr/local/bin/wp --path=/var/www/larkspur transient delete --expired"),
            ("www-data", "/usr/local/bin/wp --path=/var/www/larkspur plugin list"),
            ("root", "/usr/bin/tail -n 20 /var/log/nginx/larkspur.error.log"),
            ("root", "/usr/bin/tail -n 15 /var/log/nginx/larkspur.access.log"),
            ("deploy", "/usr/bin/cp /tmp/rentals.php inc/rentals.php"),
            ("deploy", "/usr/bin/cp /tmp/site.css assets/site.css")]
PLUGIN_DIR = "/var/www/larkspur/wp-content/plugins/larkspur-site"
# What a person types in a terminal besides sudo, by the kind of work (the live shift's driver has the same
# kinds of looks, range/traffic/driver.py WORK), for each person's ~/.bash_history.
LOOKS = {
    "ops2": ["uptime", "df -h / | tail -1", "w", "free -m", "ps aux --sort=-%cpu | head -8", "tail -n 5 /var/log/larkspur-orders.log",
             "tail -n 5 /var/log/larkspur-dbdump.log", "ls -lt /srv/backups/larkspur | head -5"],
    "dba": ["free -m | head -2", "df -h / | tail -1", "tail -n 10 /var/log/larkspur-dbdump.log", "uptime",
            "tail -n 10 /var/log/larkspur-offsite.log"],
    "dev": [f"cd {'/var/www/larkspur/wp-content/plugins/larkspur-site'}", "git status --short", "git log --oneline -5",
            "tail -n 30 /var/log/nginx/larkspur.error.log", "php -v", "ls -la inc", "grep -n Version larkspur-site.php"],
    "marketing": ["tail -n 20 /var/log/nginx/larkspur.access.log", "grep -c utm_ /var/log/nginx/larkspur.access.log",
                  "ls -lt ~ | head", "head -n 5 ~/newsletter-*.csv"],
    "support": ["tail -n 10 /var/log/larkspur-orders.log", "ls -lt ~ | head", "cat ~/support-log.txt | tail -3"],
    "owner": ["uptime", "tail -n 5 /var/log/larkspur-invoices.log", "tail -n 5 /var/log/larkspur-dbdump.log",
              "df -h /", "ls -lt /var/backups/larkspur | head -4"],
    "books": ["tail -n 10 /var/log/larkspur-invoices.log", "date", "ls -lt ~ | head"],
}
EXPORT = "/usr/local/sbin/larkspur-mailing-export"
ADJUST = "/usr/local/sbin/larkspur-invoice-adjust"
ARCHIVE_DIRS = {"db-01": "/var/backups/larkspur", "ci-01": "/srv/backups/larkspur"}
# Sessions per working day on each host, by the kind of work (the live shift is a busy afternoon; a normal day
# has a few visits per person).
PER_DAY = {"ops": 3.0, "ops2": 4.0, "dev": 3.0, "frontend": 2.5, "support": 3.0, "editor": 2.0, "shop": 2.5,
           "marketing": 2.5, "owner": 2.5, "dba": 3.0, "books": 2.5, "once": 0.5}
TTY_SHARE = {"ops2": 0.3, "dba": 0.3, "dev": 0.25, "marketing": 0.2, "support": 0.15, "owner": 0.2}
# Which days each kind of person works (0 = Monday): most people Monday to Friday; the shop manager Tuesday to
# Saturday; ops on call every day; the bookkeeper four days.
WEEKDAYS = {"shop": {1, 2, 3, 4, 5}, "books": {0, 1, 2, 3}, "ops2": {0, 1, 2, 3, 4, 5, 6}}
# How often a person's session comes from their known second address (a phone, a second home), as in the live
# shift (range/traffic/driver.py: Maria 25 %, Lucia 20 %, the others 8 %), on the days they use it.
ALT_SHARE = {"mreyes": 0.25, "lucia": 0.2}
PART_TIME = {"tbrooks": 0.75, "agarcia": 0.8, "wlin": 0.75, "rnakamura": 0.65}
SSH_USERS = ["root"] * 6 + ["admin", "ubuntu", "test", "user", "oracle", "postgres", "git", "ftpuser", "pi", "guest",
                            "support", "dev", "www", "mysql", "deploy", "deploy", "jenkins", "ansible", "debian",
                            "hadoop", "nagios", "minecraft", "steam", "larkspur", "maria", "mreyes", "jpark", "backup",
                            "web", "wordpress", "ec2-user", "centos", "user1", "test1", "odoo", "sol", "vagrant", "tomcat"]


class Host:
    """The lines and records of one host's history, in no order; sorted when written."""

    def __init__(self, name, facts, rnd, start):
        self.name, self.facts, self.rnd, self.start = name, facts, rnd, start
        self.auth, self.syslog, self.access = [], [], []
        self.jobs = {}
        self.job_owner = {}  # log path -> the account its cron job runs as
        self.wtmp, self.btmp = [], []
        self.lastlog = {}
        self.extra = {}
        self.ptys = []  # (start, end) of each tty in use
        self.typed = {}  # user -> [(t, command)]: what the person typed in a terminal, for ~/.bash_history
        self.rate = {"web-01": 0.55, "db-01": 0.22, "ci-01": 0.3}[name]
        self.phase = rnd.randint(0, 30000)

    def pid(self, t):
        """A pid for a process started at t: the old VM's counter, about `rate` new processes a second, wrapping
        at 32768 as the kernel's default pid_max does."""
        n = int((t - self.start) * self.rate) + self.phase + self.rnd.randint(0, 3)
        return 300 + n % 32400

    def a(self, t, prog, msg):
        self.auth.append((t, f"{prog}: {msg}"))

    def s(self, t, prog, msg):
        self.syslog.append((t, f"{prog}: {msg}"))

    def job(self, path, t, text):
        self.jobs.setdefault(path, []).append((t, text))

    def pty(self, t0, t1):
        n = 0
        used = {k for a, b, k in self.ptys if a < t1 and b > t0}
        while n in used:
            n += 1
        self.ptys.append((t0, t1, n))
        return n


def typed(h, user, t, cmds):
    """Lines that `user` typed in a terminal session on host `h` that started at t (for ~/.bash_history)."""
    for i, c in enumerate(cmds):
        h.typed.setdefault(user, []).append((t + i, c))


def as_typed(runas, cmd):
    """A sudo command as the person types it (`sudo tail ...`, not /usr/bin/tail)."""
    c = re.sub(r"^/usr/(?:s?bin|local/bin)/", "", cmd)
    return f"sudo -u {runas} {c}" if runas not in ("root", None) else f"sudo {c}"


def port(rnd):
    return rnd.randint(32768, 60999)


def sudo_lines(h, t, user, uid, tty, pwd, runas, runuid, cmd):
    who = f"{user:>8}"
    tt = f"TTY=pts/{tty} ; " if tty is not None else ""
    h.a(t, "sudo", f"{who} : {tt}PWD={pwd} ; USER={runas} ; COMMAND={cmd}")
    h.a(t + 0.0001, "sudo", "pam_limits(sudo:session): Could not set limit for 'core' to soft=0, hard=-1: Operation "
                            f"not permitted; uid={uid},euid=0")
    by = f"{user}(uid={uid})" if tty is not None else f"(uid={uid})"
    h.a(t + 0.0002, "sudo", f"pam_unix(sudo:session): session opened for user {runas}(uid={runuid}) by {by}")
    return t + 0.0002


def session(h, t0, user, ip, auth, dur, rnd, work=(), tty=False, jump=False, close_line=None, forward=False):
    """One SSH login, as sshd (LogLevel VERBOSE) and PAM write it on these hosts. `work`: [(offset, runas, cmd,
    pwd)] sudo commands inside the session. Returns the session's end time."""
    f = h.facts
    uid = f["uids"].get(user)
    if uid is None:
        return t0
    p = h.pid(t0)
    c = p + 6
    pt = port(rnd)
    local = f["public_ip"] if (h.name == "web-01" and not ip.startswith("10.20.0.")) else OFFICE[h.name]
    sp = f"sshd[{p}]"
    h.a(t0, sp, f'Connection from {ip} port {pt} on {local} port 22 rdomain ""')
    t = t0 + rnd.uniform(0.09, 0.2)
    if auth == "key":
        k = f["keys"].get(user)
        if not k:
            return t0
        found = f"{k['type']} {k['fp']} found at {k['file']}:{k['line']}"
        h.a(t, sp, f"Accepted key {found}")
        h.a(t + 0.008, sp, f"Postponed publickey for {user} from {ip} port {pt} ssh2 [preauth]")
        h.a(t + 0.0081, sp, f"Accepted key {found}")
        t += 0.016
        h.a(t, sp, f"Accepted publickey for {user} from {ip} port {pt} ssh2: {k['type']} {k['fp']}")
    else:
        h.a(t, sp, f"Accepted password for {user} from {ip} port {pt} ssh2")
    t += 0.002
    h.a(t, sp, f"pam_unix(sshd:session): session opened for user {user}(uid={uid}) by (uid=0)")
    h.a(t + 0.004, sp, "pam_env(sshd:session): deprecated reading of user environment enabled")
    h.a(t + 0.00405, sp, "pam_env(sshd:session): Unable to open env file: /etc/default/locale: No such file or directory")
    h.a(t + 0.0045, sp, f"User child is on pid {c}")
    t += 0.045
    end = t + dur
    n = None
    if tty:
        n = h.pty(t0, end)
        h.a(t, f"sshd[{c}]", f"Starting session: shell on pts/{n} for {user} from {ip} port {pt} id 0")
        h.wtmp.append((t, 7, p, f"pts/{n}", user, ip))
        h.wtmp.append((end + 0.002, 8, p, f"pts/{n}", "", ""))
        h.lastlog[uid] = max(h.lastlog.get(uid, (0, "", "")), (t, f"pts/{n}", ip))
    elif not forward and rnd.random() < 0.92:
        # (A jump's outer session only forwards the connection (ssh -W): sshd logs no session start for it.)
        h.a(t, f"sshd[{c}]", f"Starting session: command for {user} from {ip} port {pt} id 0")
    for i, w in enumerate(work):
        off, runas, cmd, pwd = w[:4]
        st = t + min(off, max(0.05, dur - 0.2)) + i * 0.0031
        ru = 0 if runas == "root" else f["uids"].get(runas, 33 if runas == "www-data" else 0)
        e = sudo_lines(h, st, user, uid, n, pwd, runas, ru, cmd)
        held = w[4] if len(w) > 4 else rnd.uniform(0.003, 0.4)
        h.a(min(e + held, end - 0.0005 - (len(work) - i) * 0.00007), "sudo", f"pam_unix(sudo:session): session closed for user {runas}")
    cs = f"sshd[{c}]"
    if jump:
        h.a(end, cs, f"Connection closed by {ip} port {pt}")
        h.a(end + 0.00002, cs, f"Close session: user {user} from {ip} port {pt} id 0")
        h.a(end + 0.00004, cs, f"Transferred: sent {rnd.randint(3600, 16000)}, received {rnd.randint(3400, 5200)} bytes")
        h.a(end + 0.00005, cs, f"Closing connection to {ip} port {pt}")
    else:
        if tty or (not forward and (close_line if close_line is not None else rnd.random() < 0.2)):
            h.a(end, cs, f"Close session: user {user} from {ip} port {pt} id 0")
        h.a(end + 0.0001, cs, f"Received disconnect from {ip} port {pt}:11: disconnected by user")
        h.a(end + 0.0002, cs, f"Disconnected from user {user} {ip} port {pt}")
    h.a(end + 0.0005, sp, f"pam_unix(sshd:session): session closed for user {user}")
    return end + 0.001


def failed_password(h, t0, user, ip, rnd, valid=True):
    """A password that the server refused: a person's typo, or a guess from the internet. Returns the end."""
    p = h.pid(t0)
    pt = port(rnd)
    sp = f"sshd[{p}]"
    h.a(t0, sp, f'Connection from {ip} port {pt} on {h.facts["public_ip"] if h.name == "web-01" else OFFICE[h.name]} '
                'port 22 rdomain ""')
    t = t0 + rnd.uniform(0.09, 0.19)
    if valid:
        h.a(t, sp, "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= "
                   f"rhost={ip}  user={user}")
        t += rnd.uniform(1.8, 2.6)
        h.a(t, sp, f"Failed password for {user} from {ip} port {pt} ssh2")
        h.btmp.append((int(t), 6, p, "ssh:notty", user, ip))
        t += rnd.uniform(0.4, 2.2)
        h.a(t, sp, f"Connection closed by authenticating user {user} {ip} port {pt} [preauth]")
    else:
        h.a(t, sp, f"Invalid user {user} from {ip} port {pt}")
        h.btmp.append((int(t), 6, p, "ssh:notty", user, ip))
        h.a(t + 0.009, sp, "pam_unix(sshd:auth): check pass; user unknown")
        h.a(t + 0.0091, sp, "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= "
                            f"rhost={ip} ")
        t += rnd.uniform(1.4, 2.6)
        h.a(t, sp, f"Failed password for invalid user {user} from {ip} port {pt} ssh2")
        h.btmp.append((int(t), 6, p, "ssh:notty", user, ip))
        t += rnd.uniform(0.07, 1.0)
        h.a(t, sp, f"Connection closed by invalid user {user} {ip} port {pt} [preauth]")
    return t


# ---- the plan: who, which days, from where ----

def eastern_weekday(t):
    off = 4 * 3600 if t < calendar.timegm((2026, 11, 1, 6, 0, 0)) else 5 * 3600
    return time.gmtime(t - off).tm_wday


def forbidden_addresses(ep):
    """Every address that must not be in the history: the intruder's (all of them) and the twins' new ones."""
    out = set(ep.get("attacker_ips") or [])
    for pool in (ep.get("attacker_pools") or {}).values():
        out.update(pool)
    if ep.get("wave2_ip"):
        out.add(ep["wave2_ip"])
    out.update(((ep.get("replay") or {}).get("truth") or {}).get("intruder", {}).get("addresses") or [])
    out.update((ep.get("ips") or {}).get("new_address") or [])
    for e in (ep.get("twins") or {}).get("events") or []:
        if e.get("twin") == "T1" and e.get("ip"):
            out.add(e["ip"])
    return {a for a in out if isinstance(a, str) and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", a)}


def _usual(ep, user):
    p = (ep.get("people") or {}).get(user) or {}
    return p.get("ip"), list(p.get("alt") or [])


def generate(ep, facts, end, roster=None):
    """{host: {path: File}}: the history of each company host, from `end - ~14 days` to `end` (the move)."""
    rnd = random.Random(f"history/{ep['seed']}")
    forbidden = forbidden_addresses(ep)
    start = (int(end) // DAY - HISTORY_DAYS) * DAY
    shift_tod = (end + 300) % DAY
    hosts = {h: Host(h, facts["hosts"][h], random.Random(f"history/{ep['seed']}/{h}"), start)
             for h in facts["hosts"]}
    people = ep.get("people") or {}
    ips = ep.get("ips") or {}
    plan = ep.get("twins") or {}
    days = [start + d * DAY for d in range(HISTORY_DAYS + 1)]

    def ok(a):
        return a and a not in forbidden

    # Each person's busy times: one place at a time (T2 holds in the history too).
    busy = {}

    def free(user, t0, t1, ip):
        for a, b, where in busy.get(user, []):
            if a < t1 + 5 and b > t0 - 5 and where != ip:
                return False
        return True

    def hold(user, t0, t1, ip):
        busy.setdefault(user, []).append((t0, t1, ip))

    # The window in which each person works on a day: around the time of day of today's shift, so that the shift
    # is an ordinary working time for the people in it (see the notes for this shortcut).
    windows = {}
    for u in sorted(people):
        before = rnd.uniform(2.0, 6.0) * 3600
        windows[u] = (before, rnd.uniform(6.5, 9.5) * 3600)

    def worked_days(u, work):
        wd = WEEKDAYS.get(work, {0, 1, 2, 3, 4})
        out = []
        absent = set(rnd.sample(range(len(days)), rnd.choice([0, 1, 1, 2])))
        for i, d in enumerate(days):
            anchor = d + shift_tod
            if anchor - windows[u][0] > end:
                continue
            wday = eastern_weekday(anchor)
            if work == "once":
                continue
            if wday not in wd and not (u == "mreyes" and wday == 5 and rnd.random() < 0.6) \
                    and not (u == "lucia" and wday >= 5 and rnd.random() < 0.5):
                continue
            if i in absent and work != "ops2":
                continue
            if rnd.random() > PART_TIME.get(u, 1.0):
                continue
            out.append(d)
        if work == "once":
            # The part-time contractor (Kevin Owens, staff.json: "Developer (contractor, part-time)"): one login on
            # some days, spread over the two weeks, the last ones too; a weekday each.
            wk = [d for d in days if eastern_weekday(d + shift_tod) < 5 and d + shift_tod - windows[u][0] <= end]
            out = sorted(rnd.sample(wk, min(len(wk), rnd.randint(3, 5))))
        return out

    def when(u, d, dur):
        before, length = windows[u]
        lo = d + shift_tod - before + rnd.uniform(-1800, 1800)
        t = lo + rnd.uniform(0, length)
        return t if t + dur < end - 120 else None

    sessions = []  # (t, user, host, ip, auth, dur, work, tty, jump)
    for u in sorted(people):
        p = people[u]
        r = (roster or {}).get(u, {})
        work = p.get("work") or r.get("work") or "ops"
        home, alt = p.get("ip"), [a for a in (p.get("alt") or []) if ok(a)]
        if not ok(home):
            continue
        for d in worked_days(u, work):
            phone_day = alt and rnd.random() < min(1.0, 3 * ALT_SHARE.get(u, 0.08))
            for host in p.get("hosts") or []:
                if host not in hosts:
                    continue
                lam = PER_DAY.get(work, 2.5) * (0.5 if eastern_weekday(d + shift_tod) >= 5 else 1.0)
                n = max(1 if host == p["hosts"][0] or rnd.random() < 0.6 else 0, _poisson(rnd, lam))
                for _ in range(n):
                    tty = rnd.random() < TTY_SHARE.get(work, 0.0)
                    dur = rnd.uniform(150, 900) if tty else rnd.uniform(0.3, 25)
                    t = when(u, d, dur)
                    if t is None:
                        continue
                    ip = home
                    jump = False
                    if host == "web-01" and phone_day and rnd.random() < 0.5:
                        ip = rnd.choice(alt)
                    elif host != "web-01" and u in (plan.get("jumpers") or {}) and \
                            host in plan["jumpers"][u] and rnd.random() < float(plan.get("jump_share", 0.25)):
                        jump = True
                    if not free(u, t, t + dur, ip):
                        continue
                    hold(u, t, t + dur, ip)
                    sessions.append((t, u, host, ip, p.get("auth", "key"), dur, work, tty, jump))

    # ---- people's sessions, with their sudo work and typos ----
    for t, u, host, ip, auth, dur, work, tty, jump in sorted(sessions):
        h = hosts[host]
        hr = h.rnd
        cmds = []
        pwd = f"/home/{u}"
        pool = SUDO_CMDS.get((work, host))
        if u == "mreyes" and host == "web-01" and tty:
            pwd = PLUGIN_DIR
            for k in range(hr.randint(1, 3)):
                runas, cmd = hr.choice(DEV_SUDO)
                cmds.append((hr.uniform(5, max(6, dur - 5)), runas, cmd, pwd))
        elif pool and hr.random() < (0.85 if work in ("ops2", "dba") else 0.5):
            for k in range(hr.randint(1, 3 if work in ("ops2", "dba") else 1)):
                cmds.append((hr.uniform(0.05, max(0.1, dur * 0.8)), "root", hr.choice(pool), pwd))
        cmds.sort()
        if tty:
            looks = LOOKS.get(work) or []
            lines = hr.sample(looks, min(len(looks), hr.randint(1, 3))) + [as_typed(c[1], c[2]) for c in cmds]
            if u == "mreyes" and host == "web-01" and lines:
                lines.insert(0, f"cd {PLUGIN_DIR}")
            typed(h, u, t, lines + ["exit"])
        if auth == "password" and hr.random() < 0.06:
            failed_password(h, t - hr.uniform(3, 9), u, ip, hr)
        if jump:
            w = hosts.get("web-01")
            if w is not None:
                session(w, t - 0.3, u, ip, "key", dur + 0.4, w.rnd, forward=True)
            session(h, t, u, OFFICE["web-01"], auth, dur, hr, cmds, tty=False, jump=True)
        else:
            session(h, t, u, ip, auth, dur, hr, cmds, tty=tty)

    # ---- the business habits ----
    _exports(ep, hosts, people, days, end, rnd, ok, free, hold, shift_tod)
    _corrections(ep, hosts, people, start, end, rnd, ok, free, hold, shift_tod)
    _cleanups(ep, hosts, people, end, rnd, ok, free, hold, shift_tod, facts)
    _deploy_passwords(ep, hosts, start, end, rnd, ok, free, hold)
    # ---- the jobs, and what they do on the other hosts ----
    for name, h in hosts.items():
        _crons(ep, h, hosts, start, end, facts)
    # ---- the internet ----
    if "web-01" in hosts:
        planted = _planted_requesters(ep, forbidden)
        used = {a for _, addrs in planted for a in addrs}
        _ssh_noise(ep, hosts["web-01"], start, end, rnd, forbidden | used)
        _web(ep, hosts["web-01"], start, end, rnd, lambda a: ok(a) and a not in used, people, facts, shift_tod)
        _planted_requests(ep, hosts["web-01"], planted, days, end, shift_tod)
    return render(ep, hosts, start, end, facts, forbidden)


def _poisson(rnd, lam):
    n, p, L = 0, 1.0, pow(2.718281828, -lam)
    while True:
        p *= rnd.random()
        if p <= L:
            return n
        n += 1


def _tty_work(h, t, user, ip, auth, dur, cmds, rnd):
    return session(h, t, user, ip, auth, dur, rnd, cmds, tty=True)


def _exports(ep, hosts, people, days, end, rnd, ok, free, hold, tod):
    """T4's habit: marketing exports a mailing list on most of her days; support looks up a few customers."""
    h = hosts.get("web-01")
    if h is None:
        return
    lists = {"newsletter": 41, "rentals": 33, "recent": 52}
    pick = ["newsletter", "newsletter", "newsletter", "rentals", "recent"]
    for u in ("mfischer", "jcole"):
        p = people.get(u)
        if not p or not ok(p.get("ip")):
            continue
        for d in days:
            if eastern_weekday(d + tod) >= 5:
                continue
            n = (1 if rnd.random() < 0.6 else 0) + (1 if rnd.random() < 0.15 else 0) if u == "mfischer" \
                else rnd.randint(0, 3)
            for _ in range(n):
                t = d + tod + rnd.uniform(-4, 4) * 3600
                dur = rnd.uniform(70, 220)
                if t + dur > end - 300 or not free(u, t, t + dur, p["ip"]):
                    continue
                hold(u, t, t + dur, p["ip"])
                at = rnd.uniform(8, 35)
                end_t = _tty_work(h, t, u, p["ip"], p.get("auth", "password"), dur, [(at, "root", EXPORT, f"/home/{u}")], h.rnd)
                del end_t
                st = t + 0.25 + at + 0.3
                if u == "mfischer":
                    lst = rnd.choice(pick)
                    what, rows, name = f"list={lst}", lists[lst], lst
                else:
                    first = rnd.randint(1001, 1240)
                    last = min(first + rnd.randint(0, 4), 1240)
                    what, rows, name = f"ids={first}-{last}", last - first + 1, f"customers-{first}-{last}"
                out = f"/home/{u}/{name}-{time.strftime('%Y%m%d-%H%M%S', time.gmtime(st))}.csv"
                ask = f"list {lst}" if u == "mfischer" else f"ids {first}-{last}"
                typed(h, u, t, [f'echo "{ask}" | sudo -n {EXPORT}', f'head -n 5 "$(ls -t ~/{name}-*.csv | head -1)"',
                                "exit"])
                h.job("/var/log/larkspur-exports.log", st, f"{iso_s(st)} user={u} {what} rows={rows} out={out}")


def _corrections(ep, hosts, people, start, end, rnd, ok, free, hold, tod):
    """T5's habit: the bookkeeper and Maria correct an invoice to its order total, a few times a week. Only
    invoices that already agree with their order today (so the shop database still says the correction was
    right); the ones that wait for a correction are today's work."""
    h = hosts.get("db-01")
    if h is None:
        return
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("larkspur_business", BUSINESS)
        biz = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(biz)
        invs = biz.invoices()
    except Exception:  # noqa: BLE001 -- no business data: no corrections
        return
    cands = [i for i in invs if not i["image"] and i["cents"] == i["order_cents"] and i["issued_days"]
             and i["issued_days"] >= 2]
    rnd.shuffle(cands)
    for k, inv in enumerate(cands[:rnd.randint(4, 6)]):
        u = "pshah" if k % 3 != 2 else "mreyes"
        p = people.get(u)
        if not p or not ok(p.get("ip")):
            continue
        issued = end - inv["issued_days"] * DAY
        last = end - (inv["paid_days"] * DAY if inv["paid_days"] else 3600 * 6)
        lo = max(issued + 3 * 3600, start + 3600)
        if last - lo < 3600:
            continue
        for _ in range(10):
            d = lo + rnd.uniform(0, last - lo)
            t = d - (d % DAY) + tod + rnd.uniform(-3, 3) * 3600
            if lo < t < last and eastern_weekday(t) < 5 and free(u, t - 25, t + 45, p["ip"]):
                break
        else:
            continue
        hold(u, t - 25, t + 45, p["ip"])
        old = inv["order_cents"] + rnd.choice([-12000, -8500, -6000, -3500, 2500, 4000, 7500])
        # By hand, in a terminal: the sudo line has TTY=pts/N, as the live shift's corrections have.
        at = rnd.uniform(6, 20)
        session(h, t - at, u, p["ip"], p.get("auth", "password"), at + rnd.uniform(8, 40), h.rnd,
                [(at - 0.2, "root", ADJUST, f"/home/{u}")], tty=True)
        typed(h, u, t - at, ["tail -n 5 /var/log/larkspur-invoices.log",
                             f"printf 'invoice {inv['id']}\\namount {inv['order_cents']}\\norder {inv['order_no']}\\n' "
                             f"| sudo -n {ADJUST}", "exit"])
        h.job("/var/log/larkspur-invoices.log", t + 0.3, f"{iso_s(t + 0.3)} adjust invoice={inv['id']} old={old} "
              f"new={inv['order_cents']} user={u} order={inv['order_no']}")


def _cleanups(ep, hosts, people, end, rnd, ok, free, hold, tod, facts):
    """T10's habit: operations clears the archives older than a week by hand, every few days, on db-01 and on ci-01.
    The last clean-up on each host falls in the one day that agrees with the image's archives (1 to 12 nights old,
    nothing older): after the 13th night became 8 days old and before the 12th did."""
    p = people.get("nvega")
    if not p or not ok(p.get("ip")):
        return
    midnight = end - end % DAY
    for host, d in ARCHIVE_DIRS.items():
        h = hosts.get(host)
        if h is None:
            continue
        lo = midnight - 5 * DAY + 2 * 3600 + 600
        hi = midnight - 4 * DAY + 2 * 3600
        times = []
        for _ in range(30):
            t = lo + rnd.uniform(0, hi - lo)
            if free("nvega", t, t + 90, p["ip"]):
                times.append(t)
                break
        t = times[0] if times else None
        while t is not None:
            if t > end - 14 * DAY + 3600:
                hold("nvega", t, t + 90, p["ip"])
                # By hand, in a terminal, as the live shift's clean-up.
                a = rnd.uniform(6, 15)
                session(h, t, "nvega", p["ip"], "key", a + rnd.uniform(20, 60), h.rnd,
                        [(a, "root", f"/usr/bin/ls -l {d}", "/home/nvega"),
                         (a + 3, "root", f"/usr/bin/find {d} -type f -mtime +7 -delete", "/home/nvega"),
                         (a + 8, "root", f"/usr/bin/ls -l {d}", "/home/nvega")], tty=True)
                typed(h, "nvega", t, ["df -h / | tail -1", f"sudo -n ls -l {d}",
                                      f"sudo -n find {d} -type f -mtime +7 -delete", f"sudo -n ls -l {d}", "exit"])
            t -= rnd.uniform(3, 5) * DAY
            if t < end - 14 * DAY:
                break


def _deploy_passwords(ep, hosts, start, end, rnd, ok, free, hold):
    """T6's habit: the old monitoring box logs in to deploy with the password a few times a day; Maria now and then,
    from one of her own addresses."""
    h = hosts.get("web-01")
    if h is None:
        return
    legacy = (ep.get("ips") or {}).get("legacy")
    t = start + rnd.uniform(600, 5400)
    while legacy and ok(legacy) and t < end - 300:
        session(h, t, "deploy", legacy, "password", rnd.uniform(0.2, 1.0), h.rnd)
        t += rnd.uniform(2, 7) * 3600
    maria = [a for a in [(ep.get("people") or {}).get("mreyes", {}).get("ip")] +
             list((ep.get("people") or {}).get("mreyes", {}).get("alt") or []) if ok(a)]
    t = start + rnd.uniform(DAY, 2 * DAY)
    while maria and t < end - 600:
        ip = maria[0] if rnd.random() < 0.6 else rnd.choice(maria)
        if free("mreyes", t, t + 8, ip):
            hold("mreyes", t, t + 8, ip)
            session(h, t, "deploy", ip, "password", rnd.uniform(1, 6), h.rnd)
        t += rnd.uniform(1.5, 4.5) * DAY


# business.py sits beside this file in the sandbox (/range/lib) and in range/build in the repository.
_HERE = pathlib.Path(__file__).resolve()
BUSINESS = next((p for p in (_HERE.with_name("business.py"), _HERE.parent.parent.parent / "build/business.py")
                 if p.exists()), _HERE.with_name("business.py"))


# ---- the jobs ----

def _business_counts(end):
    """(open invoices, paid in the last 7 days) as a function of days before `end`, relative to today's values
    (11 open, 9 paid this week once the first runs of the day settled), from the business data."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("larkspur_business", BUSINESS)
        biz = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(biz)
        invs = [i for i in biz.invoices() if not i["image"]]
    except Exception:  # noqa: BLE001
        invs = []

    def open_at(x):
        return sum(1 for i in invs if i["issued_days"] > x and (i["paid_days"] is None or i["paid_days"] < x))

    def paid_week(x):
        return sum(1 for i in invs if i["paid_days"] is not None and x <= i["paid_days"] < x + 7)
    o0, p0 = open_at(0), paid_week(0)
    return (lambda t: max(0, 11 + open_at(int((end - t) // DAY)) - o0),
            lambda t: max(0, 9 + paid_week(int((end - t) // DAY)) - p0))


def _crons(ep, h, hosts, start, end, facts):
    """Every cron run of the host's own crontabs: cron's PAM lines (auth.log), its CMD line (syslog), the job's
    own log line, and what the job does on another host (the release logs in to web-01, the dump job's copy logs
    in to ci-01)."""
    f = h.facts
    rnd = h.rnd
    open_inv, paid_week = _business_counts(end)
    sha = facts.get("release") or "0000000"
    s3 = facts.get("s3_endpoint") or "https://s3.eu-central-1.wasabisys.com"
    runs = cron_runs(f["crons"], start, end - 5)
    by_minute = {}
    for t, j in runs:
        by_minute.setdefault(t, []).append(j)
    last_dump = None
    for t in sorted(by_minute):
        jobs = by_minute[t]
        d0 = t + rnd.uniform(1.0, 1.6)
        p = h.pid(t)
        k = len(jobs)
        for i, j in enumerate(jobs):
            user, cmd = j[7], j[8]
            uid = f["uids"].get(user, 0)
            cp = f"CRON[{p + i}]"
            a = d0 + i * 0.00002
            h.a(a, cp, "pam_env(cron:session): Unable to open env file: /etc/default/locale: No such file or directory")
            h.a(a + 0.0002, cp, f"pam_unix(cron:session): session opened for user {user}(uid={uid}) by (uid=0)")
            h.s(a + 0.0005, f"CRON[{p + k + i}]", f"({user}) CMD ({cmd})")
            st = int(d0)
            dur = rnd.uniform(0.02, 0.4)
            m = re.search(r">>\s*(/var/log/\S+)", cmd)
            log = m.group(1) if m else None
            line = None
            # The job is its program (the first word of the command), not the log it writes to.
            words = cmd.split()
            prog = words[0].rsplit("/", 1)[-1] if words else ""
            if prog == "larkspur-release":
                dur = rnd.uniform(1.9, 2.4)
                line = f"{iso_s(st)} release ok {sha}"
                w = hosts.get("web-01")
                if w is not None and "deploy" in w.facts["keys"]:
                    _release(w, d0 + rnd.uniform(1.0, 1.15), sha)
            elif prog == "larkspur-maint":
                line = f"{iso_s(st)} maint ok maint {iso_s(st + (1 if rnd.random() < 0.2 else 0))} ok"
            elif prog == "larkspur-offsite-copy":
                line = f"{iso_s(st)} offsite-copy ok {last_dump or 'none'}"
            elif prog == "larkspur-offsite":
                n = 12 + (1 if (t % DAY) < 4 * 3600 + 720 and (t % DAY) > 2 * 3600 + 720 else 0)
                dur = rnd.uniform(15.1, 16.2)
                line = f"{iso_s(st + int(dur))} offsite FAILED no route to {s3} ({n} archive(s) waiting)"
            elif prog == "larkspur-dbdump":
                dur = rnd.uniform(2.2, 3.6)
                name = time.strftime("daily-%Y%m%d-%H%M.tgz.enc", time.gmtime(t))
                line = f"{iso_s(st)} dbdump ok {name}"
                c = hosts.get("ci-01")
                if c is not None:
                    session(c, d0 + dur - 0.3, "backups", OFFICE["db-01"], "key", rnd.uniform(0.03, 0.06), c.rnd)
                last_dump = name
            elif prog == "larkspur-nightly":
                dur = rnd.uniform(0.3, 0.8)
                line = f"{iso_s(st)} dbdump ok {time.strftime('nightly-%Y%m%d.tgz.enc', time.gmtime(t))}"
                c = hosts.get("ci-01")
                if c is not None:
                    session(c, d0 + 0.2, "backups", OFFICE["db-01"], "key", rnd.uniform(0.05, 0.2), c.rnd)
            elif prog == "larkspur-invoices":
                line = f"{iso_s(st)} invoices ok {open_inv(t)} open"
            elif prog == "larkspur-settle" and "--batch" in cmd:
                day = time.strftime("%Y%m%d", time.gmtime(t))
                line = f"{iso_s(st)} settle ok batch {day}: {paid_week(t)} payouts sent"
                h.extra[f"/var/lib/larkspur/settle-batch.{day}"] = (iso_s(st + 1) + "\n", st + 1)
            elif prog == "larkspur-settle":
                line = f"{iso_s(st)} settle ok {paid_week(t)} paid this week"
            elif prog == "larkspur-orders":
                line = f"{iso_s(st)} orders ok 6 published 0 pending"
            elif prog == "larkspur-payouts":
                line = f"{iso_s(st)} payouts ok {open_inv(t)} open invoices"
            elif prog == "larkspur-report":
                line = f"{iso_s(st)} report ok 14 0"
            elif prog == "stock-sync":
                line = time.strftime("%Y-%m-%dT%H:%M:%S+0000", time.gmtime(st)) + " stock ok 6 models"
            elif prog == "offsite-backup":
                dur = rnd.uniform(9.5, 10.5)
                line = f"{iso_s(st + 10)} offsite FAILED (exit 255)"
            if line and log:
                h.job(log, st, line)
                # A job that runs as another account writes its own log (B10: the stock job runs as deploy).
                h.job_owner.setdefault(log, user)
            h.a(a + dur, cp, f"pam_unix(cron:session): session closed for user {user}")


def _release(w, t, sha):
    """The release on web-01: ci-01's deploy key, the deploy step with sudo, the cache flush."""
    rnd = w.rnd
    uid = w.facts["uids"].get("deploy", 1002)
    dur = rnd.uniform(0.8, 1.1)
    end = session(w, t, "deploy", OFFICE["ci-01"], "key", dur, rnd,
                  [(0.01, "root", f"/usr/local/bin/larkspur-deploy {sha}", "/home/deploy", dur - 0.012)],
                  close_line=True)
    # Inside the deploy step: root runs the cache flush as www-data, twice.
    a = t + 0.5 + rnd.uniform(0, 0.05)
    for _ in range(2):
        e = sudo_lines(w, a, "root", 0, None, "/var/www/larkspur", "www-data", 33,
                       "/usr/local/bin/wp --path=/var/www/larkspur cache flush")
        a = e + rnd.uniform(0.22, 0.3)
        w.a(a, "sudo", "pam_unix(sudo:session): session closed for user www-data")
        a += 0.002
    w.s(end - 0.006, "larkspur-restart", "restart manual done")
    w.s(end - 0.005, "larkspur-deploy", f"release {sha} done")
    del uid


# ---- the internet ----

def _noise_pool(ep, rnd, forbidden):
    ips = ep.get("ips") or {}
    pool = [a for a in list(ips.get("ssh_noise") or []) + list(ips.get("scanners_more") or []) if a not in forbidden]
    taken = {a for v in ips.values() for a in (v if isinstance(v, list) else [v]) if isinstance(a, str)}
    for p in (ep.get("people") or {}).values():
        taken.update([p.get("ip")] + list(p.get("alt") or []))
    near = {".".join(a.split(".")[:2]) for a in forbidden}
    blocks = sorted({".".join(a.split(".")[:2]) for a in (ips.get("ssh_noise") or [])[:30]} - near)
    extra = []
    while blocks and len(extra) < 140:
        a = f"{rnd.choice(blocks)}.{rnd.randint(1, 254)}.{rnd.randint(2, 254)}"
        if a not in taken and a not in forbidden and a not in extra:
            extra.append(a)
    return pool, extra


def _ssh_noise(ep, h, start, end, rnd, forbidden):
    """Internet password guessing on web-01: a few hundred to a few thousand tries a day, in bursts of 1 to 5 from
    one source, from the episode's own noise sources and more from the same blocks."""
    pool, extra = _noise_pool(ep, rnd, forbidden)
    if not pool:
        return
    t = start + rnd.uniform(0, 300)
    day_rate = {}
    while t < end - 60:
        d = int(t // DAY)
        if d not in day_rate:
            day_rate[d] = rnd.uniform(300, 1000)
        src = rnd.choice(extra) if extra and rnd.random() < 0.6 else rnd.choice(pool)
        for _ in range(rnd.randint(1, 5)):
            user = rnd.choice(SSH_USERS)
            valid = user in h.facts["uids"]
            t = failed_password(h, t, user, src, h.rnd, valid=valid) + rnd.uniform(2, 30)
            if t > end - 60:
                break
        t += rnd.expovariate(day_rate[d] / 3.0 / DAY)


# ---- web-01's access log ----

PAGES = [("/", 13560), ("/rentals/", 13424), ("/contact/", 13416), ("/about/", 13459), ("/repairs/", 13542),
         ("/share-your-ride/", 21558), ("/feed/", 7791), ("/category/rides/", 15334), ("/category/news/", 15119),
         ("/category/workshop/", 15272), ("/author/mreyes/", 15302), ("/author/lucia/", 15789),
         ("/2026/10/brake-pads-for-wet-weather/", 16582), ("/2026/10/ride-report-max-patch-in-the-fog/", 16625),
         ("/2026/10/holiday-gift-cards-are-here/", 16467), ("/2026/09/why-your-tubeless-tire-keeps-going-flat/", 16685),
         ("/2026/09/fall-rental-hours/", 16546),
         ("/2026/08/saturday-shop-ride-new-route-along-the-french-broad/", 16682)]
POSTS = [p for p in PAGES if p[0].startswith("/2026/")]
# What a visitor reaches from the home page's menu (the driver's browse()).
MENU = [p for p in PAGES if p[0] in ("/", "/rentals/", "/contact/", "/about/", "/repairs/", "/share-your-ride/")]
DESKTOP = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
]
MOBILE = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 16; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-A536U) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/24.0 Chrome/117.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 16_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
]
# The driver's own browser list (range/traffic/driver.py BROWSERS), which T12's requests use by index.
BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 16; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
]
CRAWL = {"66.249": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
         "157.55": "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"}
SITEMAPS = [("/wp-sitemap-posts-post-1.xml", 1003), ("/wp-sitemap-posts-page-1.xml", 803),
            ("/wp-sitemap-taxonomies-category-1.xml", 396), ("/wp-sitemap-users-1.xml", 328)]
FETCHERS = [("Feedly/1.0 (+http://www.feedly.com/fetcher.html; 3 subscribers; like FeedFetcher-Google)", "/feed/"),
            ("facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", "post"),
            ("Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)", "post"),
            ("NetNewsWire (RSS Reader; https://netnewswire.com/)", "/feed/"),
            ("Mozilla/5.0 (compatible; Pinterestbot/1.0; +http://www.pinterest.com/bot.html)", "post"),
            ("-", "/"), ("curl/7.88.1", "/"), ("Wget/1.21.3", "/feed/"), ("python-requests/2.31.0", "/rentals/")]
SCAN = [("/.env", 404, 13668), ("/wp-config.php.bak", 404, 13668), ("/.git/config", 403, 125),
        ("/phpmyadmin/", 404, 13668), ("/wp-login.php", 200, 1807), ("/admin/config.php", 404, 125),
        ("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", 404, 125), ("/.aws/credentials", 404, 13668),
        ("/server-status", 404, 13668), ("/api/v1/pods", 404, 13668), ("/actuator/env", 404, 13668),
        ("/.DS_Store", 404, 13668), ("/?author=1", 301, 5), ("/wp-content/plugins/forminator/readme.txt", 200, 97929),
        ("/wp-content/plugins/contact-form-7/readme.txt", 404, 13668),
        ("/wp-content/plugins/woocommerce/readme.txt", 404, 13668), ("/wp-content/debug.log", 404, 13668),
        ("/wp-config.php~", 404, 13668), ("/wp-content/uploads/", 403, 125), ("/wp-includes/wlwmanifest.xml", 404, 13668),
        ("/readme.html", 200, 3265), ("/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php", 404, 125),
        ("/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php", 400, 11)]
SCAN_UAS = ["curl/8.5.0", "Go-http-client/1.1", "python-requests/2.32.3", "Mozilla/5.0 zgrab/0.x", "-",
            "Mozilla/5.0 (compatible; Nuclei - Open-source project (github.com/projectdiscovery/nuclei))",
            "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)",
            "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"]
AGENCY_UA = "SwitchbackSupport/2.3 (+https://switchbackdigital.com/support)"
PARTNER_UA = "LarkspurPay-Webhook/1.1 (+https://larkspurpay.example/webhooks)"
REF = f"http://{SITE}/"


def _diurnal(t):
    """How busy the shop's site is at t, 0.2 at night to 1 in the afternoon (US Eastern)."""
    hour = ((t - (4 if t < calendar.timegm((2026, 11, 1, 6, 0, 0)) else 5) * 3600) % DAY) / 3600
    return 0.2 + 0.8 * max(0.0, min(1.0, (hour - 6) / 5)) * max(0.0, min(1.0, (23 - hour) / 4))


def _web(ep, h, start, end, rnd, ok, people, facts, tod):
    ips = ep.get("ips") or {}
    plan = ep.get("twins") or {}
    out = h.access
    r = random.Random(f"history/{ep['seed']}/web")

    def req(t, ip, method, path, status, size, ref="-", ua="-"):
        out.append((t, f'{ip} - - [{clf(t)}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"'))

    last_cron = [0.0]

    def cron_hit(t):
        if t - last_cron[0] > 60 and r.random() < 0.7:
            last_cron[0] = t
            tt = t + r.uniform(0.01, 0.2)
            req(tt, "127.0.0.1", "POST", f"/wp-cron.php?doing_wp_cron={tt:.22f}", 200, 31, "-",
                f"WordPress/6.6.2; http://{SITE}")

    def jitter(size):  # the pages' sizes are the same each time, as the live log has them
        return size

    visitors = [a for a in (ips.get("visitors") or []) + (ips.get("carrier") or []) + (ips.get("office_nat") or [])
                + (ips.get("customers") or []) if ok(a)]
    # the uptime monitor, once a minute
    mon = ips.get("monitor")
    if ok(mon):
        t = start + r.uniform(0, 60)
        while t < end - 5:
            req(t, mon, "GET", "/", 200, 13560, "-", "UptimeRobot/2.0")
            t += r.uniform(55, 65)
    # visitors: a page and one to three more from it
    t = start
    while t < end - 60 and visitors:
        t += r.expovariate(_diurnal(t) * 700 / DAY)
        ip = r.choice(visitors)
        ua = (DESKTOP[sum(ip.encode()) % len(DESKTOP)] if r.random() < 0.6 else r.choice(MOBILE))
        tt = t
        req(tt, ip, "GET", "/", 200, 13560, "-", ua)
        cron_hit(tt)
        for _ in range(r.randint(1, 3)):
            tt += r.uniform(2, 25)
            path, size = r.choice(MENU)
            if path == "/share-your-ride/":
                size = r.choice([21556, 21557, 21558, 21559, 21564, 21565, 19575, 19576])
            req(tt, ip, "GET", path, 200, jitter(size), REF, ua)
            if path == "/share-your-ride/" and r.random() < 0.08:
                tt += r.uniform(30, 90)
                req(tt, ip, "POST", "/wp-admin/admin-ajax.php", 200, r.randint(205, 225), f"{REF}share-your-ride/", ua)
    # crawlers
    for ip in ips.get("crawlers") or []:
        if not ok(ip):
            continue
        ua = CRAWL.get(".".join(ip.split(".")[:2]), CRAWL["66.249"])
        t = start + r.uniform(0, 1800)
        while t < end - 60:
            req(t, ip, "GET", "/robots.txt", 200, 129, "-", ua)
            req(t + 0.1, ip, "GET", "/wp-sitemap.xml", 200, 559, "-", ua)
            sm, sz = r.choice(SITEMAPS)
            req(t + 0.2, ip, "GET", sm, 200, sz, "-", ua)
            for k, (path, size) in enumerate(r.sample(PAGES, 3)):
                req(t + 0.4 + k * 0.3, ip, "GET", path, 200, jitter(size), "-", ua)
            t += r.uniform(1800, 5400)
    # feed readers and link previews
    bots = [a for a in ips.get("bots") or [] if ok(a)]
    t = start
    while bots and t < end - 60:
        t += r.expovariate(40 / DAY)
        ua, what = r.choice(FETCHERS)
        ip = r.choice(bots)
        if what == "post":
            req(t, ip, "GET", "/wp-sitemap-posts-post-1.xml", 200, 1003, "-", ua)
            path, size = r.choice(POSTS)
            req(t + 0.2, ip, "GET", path, 200, jitter(size), "-", ua)
        else:
            req(t, ip, "GET", what, 200, dict(PAGES).get(what, 13560), "-", ua)
    # scanners
    scan = [a for a in (ips.get("scanners") or []) + (ips.get("scanners_more") or []) + (ips.get("ssh_noise") or [])[:10]
            if ok(a)]
    t = start
    while scan and t < end - 60:
        t += r.expovariate(70 / DAY)
        ip, ua = r.choice(scan), r.choice(SCAN_UAS)
        if r.random() < 0.05:  # a TLS hello on port 80, as mass scanners send
            out.append((t, f'{ip} - - [{clf(t)}] "\\x16\\x03\\x01\\x00\\x05\\x01\\x00\\x00\\x01\\x00" 400 157 "-" "-"'))
            continue
        for k, (path, st, size) in enumerate(r.sample(SCAN, r.randint(1, 5))):
            req(t + k * 0.05, ip, "GET", path, st, size, "-", ua)
    # the payment partner checks the shop before its batches
    partner = [a for a in ips.get("partner") or [] if ok(a)]
    t = start
    while partner and t < end - 60:
        t += r.uniform(1200, 3000)
        req(t, partner[0], "GET", "/", 200, 13560, "-", PARTNER_UA)
        req(t + 0.1, partner[0], "GET", "/rentals/", 200, 13424, "-", PARTNER_UA)
    days = [start + d * DAY for d in range(HISTORY_DAYS + 1)]
    # the editor and Maria in the WordPress admin, from their own addresses
    for u, flow in (("lucia", "editor"), ("mreyes", "admin")):
        p = people.get(u)
        if not p or not ok(p.get("ip")):
            continue
        alt = [a for a in (p.get("alt") or []) if ok(a)]
        for d in days:
            if eastern_weekday(d + tod) >= 5 and r.random() < 0.6:
                continue
            for _ in range(r.randint(1, 3) if flow == "editor" else r.randint(0, 2)):
                t = d + tod + r.uniform(-5, 3) * 3600
                if t > end - 300:
                    continue
                ip = r.choice(alt) if alt and r.random() < 0.2 else p["ip"]
                ua = (BROWSERS[1] if ip == p["ip"] else MOBILE[3]) if flow == "editor" else BROWSERS[2]
                req(t, ip, "GET", "/wp-login.php", 200, 1807, "-", ua)
                req(t + 0.1, ip, "POST", "/wp-login.php", 302, 5, "-", ua)
                if flow == "editor":
                    req(t + 0.2, ip, "GET", "/wp-admin/", 200, 13400 + r.randint(-20, 60), "-", ua)
                    req(t + 0.3, ip, "GET", "/wp-admin/edit.php?post_status=pending&post_type=post", 200,
                        10541 + r.randint(0, 16), "-", ua)
                    req(t + 0.4, ip, "GET", "/wp-admin/admin-ajax.php?action=rest-nonce", 200, 41, "-", ua)
                    req(t + 0.5, ip, "GET", "/wp-json/wp/v2/posts?status=pending&orderby=date&order=asc", 200, 12,
                        "-", ua)
                else:
                    req(t + 0.2, ip, "GET", "/wp-admin/", 200, 108500 + r.randint(0, 20), "-", ua)
                    req(t + 0.3, ip, "GET", "/wp-admin/plugins.php", 200, 15499 + r.randint(0, 3), "-", ua)
                    req(t + 0.4, ip, "GET", "/wp-admin/edit.php", 200, 18794 + r.randint(0, 40), "-", ua)
    # T7's habit: the agency's support calls, on working days, from the agency's office
    agency = [a for a in ips.get("agency") or [] if ok(a)]
    for d in days:
        if not agency or eastern_weekday(d + tod) >= 5:
            continue
        for _ in range(r.randint(0, 4)):
            t = d + tod + r.uniform(-5, 4) * 3600
            if t < end - 300:
                req(t, agency[0], "POST", "/", 200, 5, "-", AGENCY_UA)
    # T12's habit: the booking box on the rentals page posts to the hand-placed handler (never to the spare name)
    hd = plan.get("handlers") or {}
    used = hd.get("used")
    if used:
        path = used[len("/var/www/larkspur"):] if used.startswith("/var/www/larkspur") else used
        browsers = [a for a in (ips.get("customers") or []) + (ips.get("visitors") or []) if ok(a)]
        for d in days:
            for _ in range(r.randint(2, 7)):
                t = d + tod + r.uniform(-8, 6) * 3600
                if t > end - 300 or not browsers:
                    continue
                ip, ua = r.choice(browsers), r.choice(BROWSERS)
                req(t, ip, "GET", "/rentals/", 200, 13424, "-", ua)
                # The handler's JSON: "Closed Mondays." for a Monday, else the bikes of that size (about 200 to 650 bytes).
                size = r.randint(88, 92) if r.random() < 0.15 else r.randint(200, 650)
                req(t + r.uniform(4, 40), ip, "POST", path, 200, size, f"{REF}rentals/", ua)


# ---- a scenario's planted file that the intruder used before today ----

# The user agents of the earlier uses: desktop browsers (the intruder's own tooling sends one of these).
PLANTED_UAS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
]


MORE_CONSUMER = ("67.161", "69.181", "71.233", "76.18", "97.84", "98.97", "24.5", "68.48", "73.229", "75.68",
                 "107.115", "174.240", "166.170", "172.32", "99.203", "47.14", "70.120", "104.172")


def _planted_requesters(ep, forbidden):
    """[(planted file, [2 or 3 addresses])] for each of the replay's planted files with `history_requests`
    (range/scenarios/*/scenario.json): consumer and mobile addresses that the episode uses for nothing else, that
    are not today's intruder addresses and not in their /16 blocks. From a stream of their own."""
    pls = [pl for pl in ((ep.get("replay") or {}).get("setup") or {}).get("planted") or []
           if pl.get("kind") == "file" and pl.get("history_requests") and pl.get("host") == "web-01"]
    if not pls:
        return []
    ips = ep.get("ips") or {}
    taken = {a for v in ips.values() for a in (v if isinstance(v, list) else [v]) if isinstance(a, str)}
    for p in (ep.get("people") or {}).values():
        taken.update([p.get("ip")] + list(p.get("alt") or []))
    taken |= set(forbidden) | {ep.get("target_ip")}
    near = {".".join(a.split(".")[:2]) for a in forbidden}
    staff16 = {".".join(a.split(".")[:2]) for p in (ep.get("people") or {}).values()
               for a in [p.get("ip")] + list(p.get("alt") or []) if a}
    # Consumer and mobile blocks, as the episode's own visitors and phones have them.
    homes = list(ips.get("carrier") or []) + list(ips.get("visitors") or [])[18:]
    blocks = sorted({".".join(a.split(".")[:2]) for a in homes} - near - staff16)
    if not blocks:
        # Since the staff homes are drawn from home ISP blocks (shakedown review 3, item 1), the staff and the
        # intruder can take every block of the visitors and phones: then other consumer ISP blocks (the same
        # as episode.PROXY's own extra blocks).
        blocks = sorted(set(MORE_CONSUMER) - near - staff16)
    rnd = random.Random(f"history/{ep['seed']}/planted")
    out = []
    for pl in pls:
        addrs = []
        while blocks and len(addrs) < rnd.choice([2, 3]):
            a = f"{rnd.choice(blocks)}.{rnd.randint(1, 254)}.{rnd.randint(2, 254)}"
            if a not in taken:
                taken.add(a)
                addrs.append(a)
        out.append((pl, addrs))
    return out


def planted_requester_addresses(ep):
    """{planted file's path: [its 2 or 3 earlier requesters]}: the addresses that only the history has (POSTs to a
    replay's planted file before today). The grader holds them neutral in the report (a defender who names one
    read the logs right; truth.json does not know them). Pure: from the episode alone, as generate draws them."""
    if not on(ep):
        return {}
    return {pl["path"]: list(addrs) for pl, addrs in _planted_requesters(ep, forbidden_addresses(ep)) if addrs}


def php_json(obj):
    """PHP's json_encode of a value made of dicts, lists, strings and numbers (no spaces; '/' as '\\/')."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True).replace("/", "\\/")


def chunked(n):
    """nginx's $body_bytes_sent for a PHP answer of n bytes to an HTTP/1.1 client: PHP sends no length, so nginx
    sends one chunk ("<hex n>\\r\\n", the data, "\\r\\n") and the last chunk ("0\\r\\n\\r\\n"), and counts them."""
    return n + len(f"{n:x}") + 2 + 2 + 5


def answer_sizes(text, wp_defines, r):
    """(a function giving one ordinary answer's size, the larger answer's size), from the planted file's own PHP
    when it is a quote handler of the kind S3 plants (see the S3 notes):
    the quote's JSON for a bike and a number of days, and the settings answer (the DB_ defines of web-01's
    wp-config.php, in their order, and the rates). None for a file of another kind (the earlier ranges)."""
    m = re.search(r"\$rates\s*=\s*array\((.*?)\);", text or "", re.S)
    note = re.search(r"'note'\s*=>\s*'([^']*)'", text or "")
    if not m or not note:
        return None, None
    rates = {k: int(v) for k, v in re.findall(r"'([a-z]+)'\s*=>\s*(\d+)", m.group(1))}
    if not rates:
        return None, None

    def quote():
        bike = r.choice(sorted(rates))
        days = r.choice([1, 1, 2, 2, 3, 4, 5, 7])
        paid = days - 2 * (days // 7) if days >= 7 else days
        return chunked(len(php_json({"ok": True, "bike": bike, "days": days, "per_day": rates[bike],
                                     "total": rates[bike] * paid, "note": note.group(1)})))
    big = None
    if wp_defines and "wp-config.php" in text and "'site'" in text:
        big = chunked(len(php_json({"ok": True, "site": dict(wp_defines), "rates": rates})))
    return quote, big


def _planted_requests(ep, h, planted, days, end, tod):
    """POSTs to the planted file's URL on some of the days, at ordinary hours: mostly the file's ordinary answer,
    once or twice a larger one. The sizes are the ones the real file gives (answer_sizes); for a file whose
    answers this cannot work out, 110 to 130 and 190 to 260 bytes as before."""
    for pl, addrs in planted:
        if not addrs:
            continue
        r = random.Random(f"history/{ep['seed']}/planted/{pl['path']}")
        path = pl["path"][len("/var/www/larkspur"):] if pl["path"].startswith("/var/www/larkspur") else pl["path"]
        lo, hi = (pl["history_requests"].get("per_week") or [1, 3])[:2]
        ua = {a: r.choice(PLANTED_UAS) for a in addrs}
        times = []
        for w in range(0, HISTORY_DAYS, 7):
            week = days[w:w + 7]
            for _ in range(r.randint(int(lo), int(hi))):
                t = r.choice(week) + tod + r.uniform(-6, 4) * 3600
                if t < end - 1800:
                    times.append(t)
        times.sort()
        big = set(r.sample(range(len(times)), min(len(times), r.randint(1, 2)))) if times else set()
        quote, big_size = answer_sizes(pl.get("text"), h.facts.get("wp_defines"),
                                       random.Random(f"history/{ep['seed']}/planted/{pl['path']}/sizes"))
        for k, t in enumerate(times):
            a = addrs[k % len(addrs)] if r.random() < 0.5 else r.choice(addrs)
            size = r.randint(190, 260) if k in big else r.randint(110, 130)
            if k in big and big_size:
                size = big_size
            elif k not in big and quote:
                size = quote()
            h.access.append((t, f'{a} - - [{clf(t)}] "POST {path} HTTP/1.1" 200 {size} "-" "{ua[a]}"'))


# ---- the files ----

def _weekly(start, end):
    """The times of logrotate's weekly runs (cron.daily, 06:25 on Sundays, UTC on these hosts)."""
    out = []
    d = start - start % DAY
    while d < end:
        if time.gmtime(d).tm_wday == 6 and start < d + 6 * 3600 + 25 * 60 < end:
            out.append(d + 6 * 3600 + 25 * 60 + 1.4)
        d += DAY
    return out


def _daily(start, end):
    d = start - start % DAY
    out = []
    while d < end:
        t = d + 6 * 3600 + 25 * 60 + 1.4
        if start < t < end:
            out.append(t)
        d += DAY
    return out


def _monthly(start, end):
    return [t for t in _daily(start, end) if time.gmtime(t).tm_mday == 1]


def _before(lines, end):
    return [x for x in lines if x[0] < end]


def _text(lines, host=None):
    if host:
        return "".join(f"{iso(t)} {host} {m}\n" for t, m in lines).encode()
    return "".join(m + "\n" for t, m in lines).encode()


def _rotated(base, lines, cuts, keep, owner, host=None, compress=True):
    """{path: File} of a log and its rotations at `cuts` (logrotate with delaycompress: .1 plain, .2.gz on)."""
    lines.sort(key=lambda x: x[0])
    bounds = sorted(cuts)
    parts = []
    i = 0
    for b in bounds + [None]:
        j = i
        while j < len(lines) and (b is None or lines[j][0] < b):
            j += 1
        parts.append(lines[i:j])
        i = j
    out = {}
    mode, user, group = owner
    parts = parts[::-1]  # newest first: the current file, then .1, .2 ...
    for n, part in enumerate(parts):
        if n > keep:
            break
        if n and not part:
            continue
        data = _text(part, host)
        mt = part[-1][0] if part else (bounds[-1] if bounds else 0)
        if n == 0:
            out[base] = File(data, mode, user, group, mt)
        elif n == 1 or not compress:
            out[f"{base}.{n}"] = File(data, mode, user, group, mt)
        else:
            out[f"{base}.{n}.gz"] = File(gzip.compress(data, 6, mtime=0), mode, user, group, mt)
    return out


def render(ep, hosts, start, end, facts, forbidden):
    arch = facts.get("arch", "x86_64")
    kernel = facts.get("kernel", "6.1.0")
    weekly, daily, monthly = _weekly(start, end), _daily(start, end), _monthly(start, end)
    out = {}
    for name, h in hosts.items():
        f = h.facts
        files = {}
        rpid = f.get("rsyslog_pid") or 400 + h.rnd.randint(0, 300)
        origin = (f'[origin software="rsyslogd" swVersion="{RSYSLOG_VERSION}" x-pid="{rpid}" '
                  f'x-info="https://www.rsyslog.com"]')
        for t in weekly:
            h.s(t + 0.3, "rsyslogd", f"{origin} rsyslogd was HUPed")
        h.s(end + 0.5, "rsyslogd", f"{origin} exiting on signal 15.")
        own = f.get("owners", {})
        h.auth, h.syslog, h.access = _before(h.auth, end), _before(h.syslog, end + 1), _before(h.access, end)
        h.jobs = {k: _before(v, end) for k, v in h.jobs.items()}
        h.wtmp, h.btmp = _before(h.wtmp, end), _before(h.btmp, end)
        files.update(_rotated("/var/log/auth.log", h.auth, weekly, 4, own.get("/var/log/auth.log", (0o644, "root", "root")),
                              name))
        files.update(_rotated("/var/log/syslog", h.syslog, [t + 0.31 for t in weekly], 4,
                              own.get("/var/log/syslog", (0o644, "root", "root")), name))
        # rsyslog's other rules on these hosts: cron.* to cron.log, user.* (the release's `logger` lines) to
        # user.log, both also in syslog; files that rsyslog makes itself are root:adm 0640.
        cron = [x for x in h.syslog if x[1].startswith("CRON[")]
        user = [x for x in h.syslog if x[1].startswith(("larkspur-deploy:", "larkspur-restart:"))]
        files.update(_rotated("/var/log/cron.log", cron, [t + 0.31 for t in weekly], 4, (0o640, "root", "adm"), name))
        if user:
            files.update(_rotated("/var/log/user.log", user, [t + 0.31 for t in weekly], 4, (0o640, "root", "adm"),
                                  name))
        if h.access:
            files.update(_rotated("/var/log/nginx/larkspur.access.log", h.access, daily, 14,
                                  (0o640, "www-data", "adm")))
        for path, lines in h.jobs.items():
            lines.sort(key=lambda x: x[0])
            m, u, g = own.get(path, (0o640, h.job_owner.get(path, "root"), "adm"))
            files[path] = File(_text(lines), m, u, g, lines[-1][0])
        # wtmp: the sessions with a terminal, then the old VMs' shutdown at the move
        recs = sorted(h.wtmp)
        data = b"".join(utmp_record(arch, typ, pid, line, line[-4:] if typ == 7 else "", user, host, t, host or None)
                        for t, typ, pid, line, user, host in recs)
        data += utmp_record(arch, 1, 12848, "~", "~~", "runlevel", kernel, end + 1.0)
        data += utmp_record(arch, 1, 0, "~", "~~", "shutdown", kernel, end + 1.2)
        files["/var/log/wtmp"] = File(data, 0o664, "root", "utmp", end + 1.2)
        # btmp: monthly, no compression
        bt = sorted(h.btmp)
        cut = monthly[-1] if monthly else None
        newer = [r for r in bt if cut is None or r[0] >= cut]
        older = [r for r in bt if cut is not None and r[0] < cut]
        pack = lambda rs: b"".join(utmp_record(arch, 6, pid, line, "", user, host, t, host)  # noqa: E731
                                   for t, typ, pid, line, user, host in rs)
        files["/var/log/btmp"] = File(pack(newer), 0o660, "root", "utmp", newer[-1][0] if newer else end)
        if older:
            files["/var/log/btmp.1"] = File(pack(older), 0o660, "root", "utmp", older[-1][0])
        files["/var/log/lastlog"] = File(lastlog_bytes(arch, h.lastlog), 0o664, "root", "utmp",
                                         max([v[0] for v in h.lastlog.values()] or [end]))
        # logrotate's own record of what it rotated, and when
        st = ["logrotate state -- version 2"]

        def stamp(t):
            g = time.gmtime(t)
            return f"{g.tm_year}-{g.tm_mon}-{g.tm_mday}-{g.tm_hour}:{g.tm_min}:{g.tm_sec}"
        last_w = weekly[-1] if weekly else start
        rsys = ("/var/log/syslog", "/var/log/auth.log", "/var/log/cron.log") + (("/var/log/user.log",) if user else ())
        for p in rsys:
            st.append(f'"{p}" {stamp(last_w)}')
        if h.access:
            st.append(f'"/var/log/nginx/larkspur.access.log" {stamp(daily[-1] if daily else start)}')
        st.append(f'"/var/log/btmp" {stamp(cut or start)}')
        st.append(f'"/var/log/wtmp" {stamp(cut or start)}')
        files["/var/lib/logrotate/status"] = File(("\n".join(st) + "\n").encode(), 0o644, "root", "root",
                                                  daily[-1] if daily else start)
        for path, (text, t) in h.extra.items():
            files[path] = File(text.encode(), 0o644, "root", "root", t)
        files.update(bash_histories(ep, h, end))
        out[name] = files
    return out


def bash_histories(ep, h, end):
    """Each person's ~/.bash_history on host `h`: what they typed in their terminal sessions of the last few
    days (some lines, not all 14 days: each person's file starts 2 to 8 days back), owner the person, 0600, the
    file time that of the last session. Bash writes the history at the end of a session, so a session's lines
    are there only when it ended before the move."""
    out = {}
    people = ep.get("people") or {}
    for u, lines in sorted(h.typed.items()):
        if u not in people:
            continue
        r = random.Random(f"history/{ep['seed']}/{h.name}/bash/{u}")
        since = end - r.uniform(2, 8) * DAY
        keep = [(t, c) for t, c in sorted(lines) if since <= t < end - 60]
        if not keep:
            continue
        out[f"/home/{u}/.bash_history"] = File(("\n".join(c for _, c in keep) + "\n").encode(), 0o600, u, u,
                                                min(end - 1, keep[-1][0] + r.uniform(30, 600)))
    return out


# ---- the facts, read from the image (the control plane, before the hosts start) ----

def _passwd(r):
    out = {}
    for line in (r / "etc/passwd").read_text(errors="replace").splitlines():
        f = line.split(":")
        if len(f) >= 7:
            out[f[0]] = (int(f[2]), int(f[3]), f[5])
    return out


def _group_id(r, name):
    for line in (r / "etc/group").read_text(errors="replace").splitlines():
        f = line.split(":")
        if f[0] == name:
            return int(f[2])
    return 0


def _find_key(r, user, home, blob):
    """(file, line number, type, fingerprint) of the authorized_keys line with this key, as sshd reports it."""
    for cand in (f"{home}/.ssh/authorized_keys", f"/etc/ssh/authorized_keys.d/{user}"):
        p = r / cand.lstrip("/")
        if not p.is_file():
            continue
        for n, line in enumerate(p.read_text(errors="replace").splitlines(), start=1):
            b = key_blob(line)
            if b and (blob is None or b == blob):
                return {"file": cand, "line": n, "type": key_type(b), "fp": fingerprint(b)}
    return None


def collect_facts(ep, root=ROLE_DIR):
    """What generate() needs from the image: accounts, key fingerprints, cron lines, the release's commit."""
    import platform
    facts = {"hosts": {}, "arch": platform.machine(), "kernel": os.uname().release}
    keys_dir = root / "traffic/rootfs/opt/traffic/secrets/keys"
    people = ep.get("people") or {}
    for host, role in ROLE.items():
        r = root / role / "rootfs"
        if not (r / "etc/passwd").exists():
            continue
        pw = _passwd(r)
        keys = {}
        for u, p in people.items():
            if host not in (p.get("hosts") or []) or p.get("auth") != "key" or u not in pw:
                continue
            kf = keys_dir / u
            blob = private_key_blob(kf.read_text()) if kf.is_file() else None
            k = _find_key(r, u, pw[u][2], blob) if blob else None
            if k:
                keys[u] = k
        if host == "web-01":
            pub = root / "ci01/rootfs/home/deploy/.ssh/id_ed25519.pub"
            if pub.is_file() and "deploy" in pw:
                k = _find_key(r, "deploy", pw["deploy"][2], key_blob(pub.read_text()))
                if k:
                    keys["deploy"] = k
        if host == "ci-01":
            pub = root / "db01/rootfs/root/.ssh/id_ed25519.pub"
            if pub.is_file() and "backups" in pw:
                k = _find_key(r, "backups", pw["backups"][2], key_blob(pub.read_text()))
                if k:
                    keys["backups"] = k
        crons = []
        for cf in [r / "etc/crontab"] + sorted((r / "etc/cron.d").glob("*")):
            if cf.is_file():
                crons += parse_cron(cf.read_text(errors="replace"))
        owners = {}
        for rel in ("/var/log/auth.log", "/var/log/syslog", "/var/log/larkspur-release.log",
                    "/var/log/larkspur-exports.log"):
            p = r / rel.lstrip("/")
            if p.exists():
                st = p.stat()
                inv = {v[0]: k for k, v in pw.items()}
                owners[rel] = (st.st_mode & 0o777, inv.get(st.st_uid, "root"),
                               {_group_id(r, g): g for g in ("root", "adm")}.get(st.st_gid, "root"))
        facts["hosts"][host] = {"uids": {k: v[0] for k, v in pw.items()}, "keys": keys, "crons": crons,
                                "public_ip": ep.get("target_ip", "0.0.0.0"), "owners": owners}
        wpc = r / "var/www/larkspur/wp-config.php"
        if host == "web-01" and wpc.is_file():
            # The DB_ defines in their order, as a planted file that reads wp-config.php answers with them (only
            # their sizes go into the history; the values stay in this process).
            facts["hosts"][host]["wp_defines"] = re.findall(r"define\(\s*'(DB_[A-Z]+)'\s*,\s*'([^']*)'",
                                                            wpc.read_text(errors="replace"))
    git = root / "ci01/rootfs/srv/git/larkspur-site.git"
    ref = git / "refs/heads/main"
    if ref.is_file():
        facts["release"] = ref.read_text().strip()[:7]
    elif (git / "packed-refs").is_file():
        m = re.search(r"^([0-9a-f]{40}) refs/heads/main$", (git / "packed-refs").read_text(), re.M)
        if m:
            facts["release"] = m.group(1)[:7]
    env = root / "ci01/rootfs/etc/larkspur/backup.env"
    if env.is_file():
        m = re.search(r"^S3_ENDPOINT=(\S+)", env.read_text(), re.M)
        if m:
            facts["s3_endpoint"] = m.group(1)
    return facts


def move_time(now=None):
    """When the old VMs stopped: a few minutes before this sandbox's kernel started (the restart of the handover
    note), or before now when the kernel is older than the episode (the local backend's shared VM)."""
    now = now or time.time()
    bt = now
    try:
        for line in open("/proc/stat"):
            if line.startswith("btime"):
                bt = int(line.split()[1])
    except OSError:
        pass
    ref = bt if now - 6 * 3600 < bt <= now else now
    seed = int(ref) % 997
    return ref - 90 - seed % 150


def write(ep, root=ROLE_DIR, now=None):
    """Write each host's history files. Returns a short summary (file counts, bytes, seconds)."""
    if not on(ep):
        return {}
    t0 = time.time()
    facts = collect_facts(ep, root)
    end = move_time(now)
    out = generate(ep, facts, end)
    summary = {"end": round(end, 1), "files": 0, "bytes": 0,
               "planted_requesters": planted_requester_addresses(ep)}
    for host, files in out.items():
        r = root / ROLE[host] / "rootfs"
        pw = _passwd(r)
        for path, f in files.items():
            p = r / path.lstrip("/")
            fresh = not p.parent.exists()
            p.parent.mkdir(parents=True, exist_ok=True)
            pt = f.mtime if fresh else p.parent.stat().st_mtime
            p.write_bytes(f.data)
            uid = pw.get(f.user, (0,))[0]
            gid = _group_id(r, f.group)
            os.chown(p, uid, gid)
            p.chmod(f.mode)
            os.utime(p, (f.mtime, f.mtime))
            # A folder that gets a new name is at least as new as that name.
            os.utime(p.parent, (max(pt, f.mtime), max(pt, f.mtime)))
            summary["files"] += 1
            summary["bytes"] += len(f.data)
    summary["seconds"] = round(time.time() - t0, 2)
    return summary
