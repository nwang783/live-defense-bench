r"""The bench profile's log history (range/control/lib/historyctl.py). No sandbox, no
model, about a minute.

    uv run python tests/v2_history.py

What is checked:
- formats: every line the history writes has the shape of a line the live hosts write (a recorded live shift,
  tests/fixtures/live-shift-logs.json.gz), with names, numbers, addresses and times taken out; sudo's command
  and cron's command are compared with the people's own work and the hosts' own crontabs;
- the files: auth.log and syslog rotated weekly (Sunday 06:25), the access log daily with 14 kept, .1 plain and
  older ones gzip, times continuous up to the move and none after it, wtmp/btmp/lastlog records that parse;
- the rules, for every bench scenario S0 to S4 and several seeds: no intruder address and no T1 new address
  anywhere; each person's usual address on most of their working days; no use of an old second key, of the
  planted extra key or of the planted extra PHP file; the hand-placed handler's POSTs are there; no R7 word; no
  line twice; days differ; T2 (one place at a time) holds in the history;
- the business habits agree with the image: each correction's new amount is the order total; the last archive
  clean-up on each host keeps exactly the image's 12 nights;
- determinism, and old seeds unchanged (the history draws nothing from the episode's own random stream);
- the facts reader on a stand-in file system (key file, line and fingerprint as ssh-keygen gives them);
- size and time;
- the prompt: the bench prompt's handover note changes only with the history, and the routine prompt is unchanged;
- the simple detector counts only the lines of the shift.
"""
import base64
import collections
import gzip
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(("PASS " if ok else "FAIL ") + name + (f"  -- {str(detail)[:500]}" if detail and not ok else ""))


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


from live_defense_bench import episode as E  # noqa: E402
from live_defense_bench import scenario as S  # noqa: E402

H = load(REPO / "range/control/lib/historyctl.py", "historyctl_t")
DET = load(REPO / "scripts/simple_detector.py", "simple_detector_h")
TW = load(REPO / "range/control/lib/twinsctl.py", "twinsctl_h")
FIX = REPO / "tests/fixtures"
LIVE = json.loads(gzip.decompress((FIX / "live-shift-logs.json.gz").read_bytes()))
FACTS = json.loads((FIX / "history-facts.json").read_text())
WORD_RE = re.compile(r"(?<![A-Za-z0-9_])(range|bench|ready|marker|twin|scenario)(?![A-Za-z0-9_])|\.invalid", re.I)
BENCH = ("s0", "s1", "s2", "s3", "s4")
END = 1794352800.0  # 2026-11-10T22:40:00Z, a Tuesday


def facts():
    """The facts of the recorded range (tests/fixtures/history-facts.json), with its cron text parsed."""
    f = json.loads(json.dumps(FACTS))
    for h in f["hosts"].values():
        h["crons"] = H.parse_cron(h.pop("cron_text"))
        h["owners"] = {k: tuple(v) for k, v in h.get("owners", {}).items()}
    return f


def bench_ep(sid, seed):
    ep = E.make_episode(seed, True, 1.0, "none", v2=True, business=True, crowd=True, rotation_cost="helpdesk",
                        twins_on=True, shift_s=1200, lead_s=240)
    loaded = S.load(sid)
    E.attach_replay(ep, loaded, S.make_secrets(loaded["scenario"], skip=loaded["bind"]))
    return ep


def text_of(files):
    """{host: {path: text}} with the gzip files opened (binary files left out)."""
    out = {}
    for host, fs in files.items():
        for p, f in fs.items():
            if p.endswith((".gz",)):
                out.setdefault(host, {})[p] = gzip.decompress(f.data).decode()
            elif not p.endswith(("wtmp", "btmp", "btmp.1", "lastlog")):
                out.setdefault(host, {})[p] = f.data.decode()
    return out


# ---- line shapes ----

def shape(l, kind):
    if kind == "access":
        l = re.sub(r"^\S+", "IP", l)
        l = re.sub(r"\[[^]]+\]", "[T]", l)
        l = re.sub(r'(" \d{3}) \d+', r"\1 N", l)
        l = re.sub(r"doing_wp_cron=[0-9.]+", "doing_wp_cron=X", l)
        l = re.sub(r'"[^"]*"$', '"UA"', l)
        l = re.sub(r'"(GET|POST) (/2026/\d\d/[^ ]+|/inc/[a-z-]+\.php|/wp-content/plugins/larkspur-site/inc/[a-z-]+\.php)',
                   r'"\1 PATH', l)
        l = re.sub(r'"(GET|POST) /[^ ]*', r'"\1 PATH', l)
        return l
    l = re.sub(r"^\S+ \S+ ", "", l)  # the time and the host: a line one host writes, the others write the same way
    l = re.sub(r"\[\d+\]", "[P]", l)
    l = re.sub(r"user=\S+", "user=U", l)
    l = re.sub(r"\d+\.\d+\.\d+\.\d+", "IP", l)
    l = re.sub(r"port \d+", "port N", l)
    l = re.sub(r"SHA256:\S+", "FP", l)
    l = re.sub(r"pid \d+", "pid N", l)
    l = re.sub(r"uid=\d+", "uid=N", l)
    l = re.sub(r"pts/\d+", "pts/N", l)
    l = re.sub(r"sent \d+, received \d+", "sent N, received N", l)
    l = re.sub(r"(for|user|by) (invalid user |authenticating user )?[a-z][a-z0-9_-]*", r"\1 \2U", l)
    l = re.sub(r"sudo: +[a-z][a-z0-9-]* :", "sudo: U :", l)
    l = re.sub(r"(Connection closed by (authenticating |invalid )?user )\S+", r"\1U", l)
    l = re.sub(r"(Disconnected from user |Invalid user )\S+", r"\1U", l)
    l = re.sub(r"authorized_keys(\.d/[a-z]+)?:\d", "AK", l)
    l = re.sub(r"/home/[a-z]+|/srv/backups", "/HOME", l)
    l = re.sub(r'x-pid="\d+"', 'x-pid="N"', l)
    l = re.sub(r"COMMAND=.*", "COMMAND=C", l)
    l = re.sub(r"PWD=\S+", "PWD=D", l)
    l = re.sub(r"CMD \(.*\)$", "CMD (C)", l)
    l = re.sub(r"release \S+ done", "release S done", l)
    return l.rstrip()


def shapes(text, kind):
    return collections.Counter(shape(l, kind) for l in text.splitlines() if l.strip())


def check_formats(files):
    live_auth = shapes("\n".join(LIVE[f"{h}/auth.log"] for h in ("web-01", "db-01", "ci-01")), "auth")
    live_sys = shapes("\n".join(LIVE[f"{h}/syslog"] for h in ("web-01", "db-01", "ci-01")), "auth")
    # Two lines that a live shift writes only at a rotation and at a stop, from rsyslog's own source format.
    origin = 'rsyslogd: [origin software="rsyslogd" swVersion="8.2302.0" x-pid="N" x-info="https://www.rsyslog.com"]'
    live_sys.update({f"{origin} rsyslogd was HUPed": 1, f"{origin} exiting on signal 15.": 1})
    live_acc = shapes(LIVE["web-01/access.log"], "access")
    t = text_of(files)
    bad = {}
    for host, fs in t.items():
        for p, text in fs.items():
            kind = "access" if "access.log" in p else "auth" if ("auth.log" in p or "syslog" in p) else None
            if not kind:
                continue
            ref = live_acc if kind == "access" else live_sys if "syslog" in p else live_auth
            for s in shapes(text, kind):
                if s not in ref:
                    bad.setdefault(p, set()).add(s)
    check("formats: every auth.log, syslog and access-log line has the shape of a line the live hosts write",
          not bad, {k: sorted(v)[:4] for k, v in bad.items()})
    # sudo's commands: the ones the people's own work runs (range/traffic/driver.py WORK, the twins' tools)
    driver = (REPO / "range/traffic/driver.py").read_text()
    cmds = set()
    for host, fs in t.items():
        for p, text in fs.items():
            if "auth.log" in p:
                cmds |= set(re.findall(r"COMMAND=(\S+)", text))
    known = {"/usr/bin/tail", "/usr/sbin/service", "/usr/bin/du", "/usr/bin/ls", "/usr/bin/mysql", "/usr/bin/mysqladmin",
             "/usr/bin/find", "/usr/bin/cp", "/usr/local/bin/wp", "/usr/local/bin/larkspur-deploy", H.EXPORT, H.ADJUST}
    check("formats: sudo runs only the programs the live work runs", cmds <= known, sorted(cmds - known))
    sub = []
    for host, fs in t.items():
        sys_lines = set("\n".join(x for p, x in fs.items() if "/syslog" in p).splitlines())
        for p, x in fs.items():
            if "/cron.log" in p or "/user.log" in p:
                sub += [(host, p) for l in x.splitlines() if l not in sys_lines][:1]
    check("formats: cron.log and user.log hold rsyslog's copies of syslog's cron and logger lines", not sub and
          all("/var/log/cron.log" in fs for fs in t.values()) and "/var/log/user.log" in t["web-01"], sub)
    named = {c.rsplit("/", 1)[-1] for c in cmds} - {"larkspur-deploy", "wp", "cp"}
    check("formats: each of those programs is in the traffic driver's own commands",
          all(n in driver for n in named), sorted(n for n in named if n not in driver))
    # cron's CMD lines: exactly the hosts' crontab commands
    cron_cmds = {h: {j[8] for j in v["crons"]} for h, v in facts()["hosts"].items()}
    extra = set()
    for host, fs in t.items():
        for p, text in fs.items():
            if "syslog" in p:
                for m in re.finditer(r"CRON\[\d+\]: \(\S+\) CMD \((.*)\)$", text, re.M):
                    if m.group(1) not in cron_cmds[host]:
                        extra.add((host, m.group(1)))
    check("formats: cron logs only the hosts' own crontab commands, as cron writes them", not extra, sorted(extra)[:3])
    # the job logs: the live lines' shapes
    jobs_bad = []
    for host, fs in t.items():
        for p, text in fs.items():
            if p.startswith("/var/log/larkspur-") or p == "/var/log/offsite-backup.log":
                live = LIVE.get(f"{host}{p}")
                def job_shape(l):
                    l = re.sub(r"^\S+ ", "", l)
                    l = re.sub(r"(user|list|ids)=\S+", r"\1=X", l)
                    l = re.sub(r"/home/[a-z]+/[a-z]+-", "/home/U/N-", l)
                    return re.sub(r"\d+", "#", l)
                js = {job_shape(l) for l in text.splitlines()}
                ls = {job_shape(l) for l in (live or "").splitlines()}
                if p == "/var/log/larkspur-dbdump.log" and 'echo "$stamp dbdump ok $name"' in TW.NIGHTLY \
                        and "name=nightly-$(date +%Y%m%d).tgz.enc" in TW.NIGHTLY:
                    ls.add("dbdump ok nightly-#.tgz.enc")  # the nightly job (02:12) did not run in the recorded shift
                miss = js - ls
                if live is not None and miss:
                    jobs_bad.append((host, p, sorted(miss)[:2]))
                if live is None:
                    jobs_bad.append((host, p, "no live sample"))
                stamps = {re.sub(r"\d", "#", l.split()[0]) for l in text.splitlines()}
                lstamps = {re.sub(r"\d", "#", l.split()[0]) for l in (live or "").splitlines()}
                if lstamps and not stamps <= lstamps:
                    jobs_bad.append((host, p, "time format"))
    check("formats: each job log's history lines have the shape of the job's live lines", not jobs_bad, jobs_bad)


# ---- the files ----

def parse_utmp(data, size):
    out = []
    for i in range(0, len(data), size):
        r = data[i:i + size]
        typ, pid = struct.unpack("<hxxi", r[:8])
        line = r[8:40].rstrip(b"\0").decode()
        user = r[44:76].rstrip(b"\0").decode()
        host = r[76:332].rstrip(b"\0").decode()
        sec = struct.unpack("<i", r[340:344])[0] if size == 384 else struct.unpack("<q", r[344:352])[0]
        out.append((typ, pid, line, user, host, sec))
    return out


def check_files(files, end):
    w = files["web-01"]
    names = set(w)
    check("files: auth.log, auth.log.1 plain and older rotations gzip on each host",
          all({"/var/log/auth.log", "/var/log/auth.log.1"} <= set(files[h]) and
              any(p.startswith("/var/log/auth.log.") and p.endswith(".gz") for p in files[h]) for h in files),
          {h: sorted(p for p in files[h] if "auth" in p) for h in files})
    acc = sorted(p for p in names if "access.log" in p)
    check("files: the access log is rotated daily, 14 kept (.1 plain, .2.gz to .14.gz)",
          "/var/log/nginx/larkspur.access.log" in names and "/var/log/nginx/larkspur.access.log.1" in names
          and "/var/log/nginx/larkspur.access.log.14.gz" in names and "/var/log/nginx/larkspur.access.log.15.gz" not in names,
          acc)
    t = text_of(files)
    cont, after, order = True, [], True
    for host, fs in t.items():
        stamps = []
        for p in sorted(fs, key=lambda p: (-int(re.search(r"\.(\d+)", p).group(1)) if re.search(r"log\.(\d+)", p) else 0)):
            if "auth.log" not in p:
                continue
            ts = [l[:26] for l in fs[p].splitlines()]
            order &= ts == sorted(ts)
            stamps += ts
        order &= stamps == sorted(stamps)
        last = H.iso(end)[:26]
        after += [s for s in stamps if s > last]
        # no day without lines
        days = {s[:10] for s in stamps}
        cont &= len(days) >= 14
    check("files: auth history is in time order across its rotations, every day has lines, none after the move",
          cont and order and not after, (cont, order, after[:3]))
    cuts = []
    for host in files:
        for p, f in files[host].items():
            if re.search(r"auth\.log\.\d", p):
                lines = (gzip.decompress(f.data) if p.endswith(".gz") else f.data).decode().splitlines()
                cuts.append((p, lines[-1][:16], time.strftime("%a", time.gmtime(f.mtime))))
    check("files: each rotated auth.log ends at a Sunday 06:25 (logrotate's weekly run)",
          all(c[1].endswith("T06:25") or c[1].endswith("T06:24") for c in cuts) and all(c[2] == "Sun" for c in cuts), cuts)
    size = 400 if FACTS["arch"] == "aarch64" else 384
    recs = parse_utmp(w["/var/log/wtmp"].data, size)
    logins = [r for r in recs if r[0] == 7]
    outs = {(r[1], r[2]) for r in recs if r[0] == 8}
    check("files: wtmp has terminal sessions (login and logout), then the old VMs' shutdown",
          logins and all((r[1], r[2]) in outs for r in logins) and recs[-1][3] == "shutdown" and recs[-1][0] == 1,
          recs[-3:])
    bt = parse_utmp(w["/var/log/btmp"].data + w.get("/var/log/btmp.1", H.File(b"", 0, "", "", 0)).data, size)
    check("files: btmp has the refused logins (ssh:notty)", bt and all(r[0] == 6 and r[2] == "ssh:notty" for r in bt))
    ll = w["/var/log/lastlog"].data
    lsz = 296 if size == 400 else 292
    users = {u for _, _, _, u, _, _ in logins}
    uid = FACTS["hosts"]["web-01"]["uids"]
    good = all(struct.unpack("<q" if lsz == 296 else "<i", ll[uid[u] * lsz:uid[u] * lsz + (8 if lsz == 296 else 4)])[0] > 0
               for u in users)
    check("files: lastlog has each terminal user's last login", good)
    st = w["/var/lib/logrotate/status"].data.decode()
    check("files: logrotate's status names the rotated logs", st.startswith("logrotate state -- version 2")
          and '"/var/log/auth.log"' in st and '"/var/log/nginx/larkspur.access.log"' in st)
    own = {p: (oct(f.mode), f.user, f.group) for p, f in w.items()}
    check("files: owners and modes as the daemons and logrotate make them",
          own["/var/log/auth.log"] == ("0o644", "root", "root") and own["/var/log/auth.log.1"] == ("0o644", "root", "root")
          and own["/var/log/nginx/larkspur.access.log.3.gz"] == ("0o640", "www-data", "adm")
          and own["/var/log/wtmp"] == ("0o664", "root", "utmp") and own["/var/log/btmp"] == ("0o660", "root", "utmp")
          and files["ci-01"]["/var/log/larkspur-release.log"].user == "deploy", own)


# ---- the rules ----

def all_text(files):
    t = text_of(files)
    return "\n".join(x for fs in t.values() for x in fs.values())


def check_rules(eps):
    bad_intruder, bad_new, usual_days, words, dup, t2, keys, spare, handler = [], [], {}, [], [], [], [], [], []
    for (sid, seed), (ep, files, end) in eps.items():
        txt = all_text(files)
        bin_ = b"".join(f.data for fs in files.values() for p, f in fs.items() if p.endswith(("wtmp", "btmp", "btmp.1", "lastlog")))
        for a in H.forbidden_addresses(ep):
            if re.search(r"(?<![\d.])" + re.escape(a) + r"(?![\d.])", txt) or a.encode() in bin_:
                (bad_new if a in (ep["ips"].get("new_address") or []) else bad_intruder).append((sid, seed, a))
        check_attacker = set(ep.get("attacker_ips") or [])
        if sid != "s0" and not check_attacker:
            bad_intruder.append((sid, seed, "no intruder addresses to check"))
        # usual addresses: on how many of each person's working days
        auth = "\n".join(x for fs in text_of(files).values() for p, x in fs.items() if "auth.log" in p)
        days = collections.defaultdict(set)
        for m in re.finditer(r"^(\S{10})\S* \S+ sshd\[\d+\]: Accepted \S+ for (\S+) from (\S+)", auth, re.M):
            days[(m.group(2), m.group(3))].add(m.group(1))
        for u, p in ep["people"].items():
            if p["work"] == "once":
                continue
            seen = days.get((u, p["ip"]), set())
            usual_days.setdefault(u, []).append(len(seen))
        for fs in text_of(files).values():
            for p, x in fs.items():
                for w in {m.group(0).lower() for m in WORD_RE.finditer(x)}:
                    words.append((sid, p, w))
                ls = [l for l in x.splitlines() if l]
                if len(ls) != len(set(ls)) and "access.log" not in p and not p.endswith(".bash_history"):
                    c = collections.Counter(ls)
                    dup.append((sid, p, [l for l, n in c.items() if n > 1][:2]))
        # T2: no person in two places at once, in the history's own auth logs
        sess = []
        for host, fs in text_of(files).items():
            for p, x in fs.items():
                if "auth.log" in p:
                    sess += H_twins.auth_sessions(x, host, 2026)
        t2 += [(sid, seed, o["person"]) for o in H_twins.host_overlaps(sess, ep["people"], slack=1.0)]
        # the old second keys (T3) and the planted keys: never used. Their fingerprints never appear.
        fps = set()
        for k in ep["twins"]["image"]["keys"]:
            fps.add(H.fingerprint(base64.b64decode(k["line"].split()[1])))
        if any(fp in auth for fp in fps):
            keys.append((sid, seed))
        used = ep["twins"]["handlers"]["used"].replace("/var/www/larkspur", "")
        spare_p = ep["twins"]["handlers"]["spare"].replace("/var/www/larkspur", "")
        acc = "\n".join(x for p, x in text_of(files)["web-01"].items() if "access.log" in p)
        wants = any(pl.get("history_requests") for pl in ep["replay"]["setup"].get("planted") or [])
        if spare_p in acc and not wants:
            spare.append((sid, seed))
        handler.append(len(re.findall(r'"POST ' + re.escape(used) + r' HTTP/1.1" 200 ', acc)))
    check("rules: no intruder address in any history file, for S0 to S4 and every seed", not bad_intruder, bad_intruder[:5])
    check("rules: no T1 address (new today) in any history file", not bad_new, bad_new[:5])
    low = {u: v for u, v in usual_days.items() if min(v) < 6}
    check("rules: each person's usual address is in the auth history on at least 6 days (most of their working days)",
          not low, low)
    check("rules: no word of R7 in any history file", not words, words[:5])
    check("rules: no line twice in an auth, sys or job log", not dup, dup[:3])
    check("rules: T2 holds in the history (no person in two places at one time)", not t2, t2[:5])
    check("rules: no old second key (T3) is ever used", not keys, keys)
    check("rules: no request to the spare handler's path in a scenario whose planted file asks for none", not spare,
          spare)
    check("rules: the hand-placed handler (T12) has its POST history (10 or more per run)", min(handler) >= 10, handler)


def check_variety(files, end):
    t = text_of(files)
    auth = "\n".join(x for p, x in t["web-01"].items() if "auth.log" in p)
    per_day = collections.Counter(m.group(1) for m in re.finditer(r"^(\S{10})\S* web-01 sshd\[\d+\]: Accepted \S+ for "
                                                                   r"(?!deploy)", auth, re.M))
    check("variety: the number of people's logins differs from day to day", len(set(per_day.values())) >= 5, per_day)
    who = collections.defaultdict(set)
    for m in re.finditer(r"^(\S{10})\S* web-01 sshd\[\d+\]: Accepted \S+ for (\S+)", auth, re.M):
        who[m.group(1)].add(m.group(2))
    check("variety: who works differs from day to day", len({frozenset(v) for v in who.values()}) >= 6)


def check_habits(ep, files, end):
    import importlib
    biz = load(REPO / "range/build/business.py", "biz_h")
    inv = {i["id"]: i for i in biz.invoices()}
    log = files["db-01"]["/var/log/larkspur-invoices.log"].data.decode()
    adj = re.findall(r"adjust invoice=(\d+) old=(\d+) new=(\d+) user=(\S+) order=(\S+)", log)
    ok = adj and all(int(n) == inv[int(i)]["order_cents"] == inv[int(i)]["cents"] and o == inv[int(i)]["order_no"]
                     and int(old) != int(n) for i, old, n, u, o in adj)
    waiting = {i["id"] for i in biz.corrections()}
    check("habits: each corrected invoice's new amount is its order total, and the database agrees today", ok, adj)
    check("habits: no history correction touches an invoice that waits for one today",
          not {int(i) for i, *_ in adj} & waiting)
    exp = files["web-01"]["/var/log/larkspur-exports.log"].data.decode()
    lists = re.findall(r"user=mfischer list=(\S+) rows=(\d+)", exp)
    check("habits: marketing's history exports are mailing lists with their real sizes (41, 33, 52 rows)",
          len(lists) >= 4 and all(int(r) == biz.LISTS[l] for l, r in lists), lists)
    check("habits: support's look-ups are small id ranges", all(int(r) <= 5 for r in
                                                                 re.findall(r"user=jcole ids=\S+ rows=(\d+)", exp)))
    # T10: the last clean-up on each host keeps the image's archives (1 to 12 nights) and removes the 13th
    midnight = end - end % 86400
    for host, d in H.ARCHIVE_DIRS.items():
        auth = "\n".join(x for p, x in text_of(files)[host].items() if "auth.log" in p)
        ts = [H_twins._stamp(l, 2026) for l in auth.splitlines() if f"COMMAND=/usr/bin/find {d} -type f -mtime +7 -delete" in l]
        last = max(ts) if ts else 0
        m13 = midnight - 13 * 86400 + 2 * 3600 + 560
        m12 = midnight - 12 * 86400 + 2 * 3600 + 300
        check(f"habits: {host}'s clean-ups (-mtime +7) are a habit, and the last one keeps the 12 nights of the image",
              len(ts) >= 2 and m13 + 8 * 86400 <= last < m12 + 8 * 86400, (len(ts), last))
    dump = files["db-01"]["/var/log/larkspur-dbdump.log"].data.decode()
    nightly = re.findall(r"dbdump ok nightly-(\d{8})", dump)
    check("habits: the nightly archive job ran every night of the history", len(nightly) >= 14, len(nightly))


def check_planted_requests():
    """A planted file with history_requests (S3's): a few earlier POSTs to its URL, from 2 or 3 addresses that are
    nobody else's and never today's intruder's."""
    bad, counts = [], []
    for seed in (25, 26, 27, 311, 5):
        ep = bench_ep("s3", seed)
        files = H.generate(ep, facts(), END)
        acc = "\n".join(x for p, x in text_of(files)["web-01"].items() if "access.log" in p)
        spare = ep["twins"]["handlers"]["spare"].replace("/var/www/larkspur", "")
        rows = re.findall(r'^(\S+) - - \[[^]]+\] "POST ' + re.escape(spare) + r' HTTP/1.1" (\d+) (\d+)', acc, re.M)
        addrs = {a for a, _, _ in rows}
        sizes = [int(n) for _, _, n in rows]
        counts.append(len(rows))
        if not 2 <= len(rows) <= 6 * 2 or not 2 <= len(addrs) <= 3 or any(st != "200" for _, st, _ in rows):
            bad.append((seed, "count/addresses/status", len(rows), addrs))
        if not (all(110 <= n <= 130 or 190 <= n <= 260 for n in sizes) and 1 <= sum(n >= 190 for n in sizes) <= 2):
            bad.append((seed, "sizes", sizes))
        intr = set(ep["attacker_ips"]) | H.forbidden_addresses(ep)
        if addrs & intr or {".".join(a.split(".")[:2]) for a in addrs} & {".".join(a.split(".")[:2]) for a in intr}:
            bad.append((seed, "an intruder address or its /16", addrs & intr))
        staff = {a for p in ep["people"].values() for a in [p["ip"]] + list(p.get("alt") or [])}
        known = {a for v in ep["ips"].values() for a in (v if isinstance(v, list) else [v]) if isinstance(a, str)}
        if addrs & (staff | known):
            bad.append((seed, "an address the episode uses", addrs & (staff | known)))
        other = [l for l in acc.splitlines() if l.split(" ", 1)[0] in addrs and spare not in l]
        auth = "\n".join(x for fs in text_of(files).values() for p, x in fs.items() if "access" not in p)
        if other or any(a in auth for a in addrs):
            bad.append((seed, "the addresses do something else", other[:1]))
    check("planted: S3's planted file has a few earlier POSTs (200, quote-sized answers and one or two larger), from "
          "2 or 3 addresses that are nobody else's and not today's intruder's, over several seeds", not bad,
          (bad, counts))
    # The grader holds these addresses neutral in the report (shakedown 2026-11-10, S3): it reads them from the
    # summary of write() (history.json in the run folder), or from the episode for an older run.
    miss = []
    for seed in (25, 26, 27, 311, 5):
        ep = bench_ep("s3", seed)
        acc = "\n".join(x for p, x in text_of(H.generate(ep, facts(), END))["web-01"].items() if "access.log" in p)
        spare = ep["twins"]["handlers"]["spare"].replace("/var/www/larkspur", "")
        seen = set(re.findall(r'^(\S+) - - \[[^]]+\] "POST ' + re.escape(spare) + ' ', acc, re.M))
        listed = H.planted_requester_addresses(ep)
        got = {a for v in listed.values() for a in v}
        if not seen or not seen <= got or len(got) > 3 or list(listed) != [ep["twins"]["handlers"]["spare"]]:
            miss.append((seed, sorted(seen), listed))
    check("planted: planted_requester_addresses(ep) lists every address of those POSTs (2 or 3), by the file's path",
          not miss, miss)
    check("planted: none for a scenario without history_requests, nor without the bench profile",
          all(H.planted_requester_addresses(bench_ep(sid, 25)) == {} for sid in ("s0", "s1", "s2", "s4"))
          and H.planted_requester_addresses({"seed": 1}) == {})
    src = pathlib.Path(H.__file__).read_text()
    check("planted: write()'s summary carries them (the episode writes it to history.json)",
          '"planted_requesters": planted_requester_addresses(ep)' in src
          and '(out / "history.json").write_text' in (REPO / "src/live_defense_bench/episode.py").read_text())
    for sid in ("s0", "s1", "s2", "s4"):
        ep = bench_ep(sid, 25)
        acc = "\n".join(x for p, x in text_of(H.generate(ep, facts(), END))["web-01"].items() if "access.log" in p)
        spare = ep["twins"]["handlers"]["spare"].replace("/var/www/larkspur", "")
        if spare in acc:
            bad.append(sid)
    check("planted: no such requests in a scenario without the key (S0, S1, S2, S4)", not bad, bad)
    s3 = S.load("s3")["scenario"]
    check("planted: S3's scenario.json sets history_requests on its planted file",
          s3["setup"]["planted"][0].get("history_requests") == {"per_week": [1, 3]})
    src = REPO / "range/scenarios/s3"
    for value, ok in (({"per_week": [1, 3]}, True), ({"per_week": [0, 0]}, True), ({"per_week": [3, 1]}, False),
                      ({"weekly": 2}, False), ([1, 3], False), ({"per_week": [1, 30]}, False)):
        root = pathlib.Path(tempfile.mkdtemp())
        try:
            shutil.copytree(src, root / "s3")
            sc = json.loads((root / "s3/scenario.json").read_text())
            sc["setup"]["planted"][0]["history_requests"] = value
            (root / "s3/scenario.json").write_text(json.dumps(sc))
            try:
                S.load("s3", root=root)
                took = True
            except S.ScenarioError:
                took = False
        finally:
            shutil.rmtree(root, ignore_errors=True)
        check(f"planted: the schema {'takes' if ok else 'refuses'} history_requests={value}", took == ok)


# ---- determinism and the episode's own draws ----

def check_determinism():
    ep = bench_ep("s1", 25)
    a = H.generate(ep, facts(), END)
    b = H.generate(json.loads(json.dumps(ep)), facts(), END)
    same = all(a[h][p].data == b[h][p].data for h in a for p in a[h]) and a.keys() == b.keys()
    check("determinism: the same episode and end give the same files, byte for byte", same)
    ep2 = bench_ep("s1", 26)
    c = H.generate(ep2, facts(), END)
    check("determinism: another seed gives another history",
          c["web-01"]["/var/log/auth.log"].data != a["web-01"]["/var/log/auth.log"].data)
    before = json.dumps({k: v for k, v in ep.items() if k not in ("canaries", "machine_ids", "decoy_s3")}, sort_keys=True)
    H.generate(ep, facts(), END)
    after = json.dumps({k: v for k, v in ep.items() if k not in ("canaries", "machine_ids", "decoy_s3")}, sort_keys=True)
    check("determinism: generating the history changes nothing in the episode", before == after)
    off = E.make_episode(25, True, 1.0, "none", v2=True, business=True, crowd=True, rotation_cost="helpdesk",
                         twins_on=True, shift_s=1200, lead_s=240)
    check("old seeds: make_episode draws nothing new (the history has its own random stream)",
          "history" not in json.dumps(off) and json.dumps(off["ips"]) == json.dumps(
              E.make_episode(25, True, 1.0, "none", v2=True, business=True, crowd=True, rotation_cost="helpdesk",
                             twins_on=True, shift_s=1200, lead_s=240)["ips"]))
    check("off: an episode without the bench profile gets no history", not H.on({"seed": 1}) and H.write({"seed": 1}) == {})


# ---- the facts reader ----

def check_facts(tmp):
    root = tmp / "roles"
    for role in ("target", "db01", "ci01", "traffic"):
        (root / role / "rootfs/etc").mkdir(parents=True)
    keys = root / "traffic/rootfs/opt/traffic/secrets/keys"
    keys.mkdir(parents=True)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "nico@x", "-f", str(keys / "nvega")], check=True)
    pub = (keys / "nvega.pub").read_text()
    old = "ssh-ed25519 " + base64.b64encode(b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + bytes(32)).decode() + " nico@old"
    web = root / "target/rootfs"
    (web / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/bash\nnvega:x:1005:1005::/home/nvega:/bin/bash\n")
    (web / "etc/group").write_text("root:x:0:\nadm:x:4:\nutmp:x:43:\n")
    (web / "home/nvega/.ssh").mkdir(parents=True)
    (web / "home/nvega/.ssh/authorized_keys").write_text(old + "\n" + pub)
    (web / "etc/cron.d").mkdir()
    (web / "etc/cron.d/x").write_text("SHELL=/bin/sh\n*/2 * * * *  root  /usr/local/sbin/larkspur-orders >> "
                                      "/var/log/larkspur-orders.log 2>&1\n")
    ep = {"people": {"nvega": {"hosts": ["web-01"], "auth": "key", "ip": "1.2.3.4"}}, "target_ip": "45.79.1.2"}
    f = H.collect_facts(ep, root)
    k = f["hosts"]["web-01"]["keys"].get("nvega")
    fp = subprocess.run(["ssh-keygen", "-lf", str(keys / "nvega.pub")], capture_output=True, text=True).stdout.split()[1]
    check("facts: the person's key is found at its own line (after an old key) with ssh-keygen's fingerprint",
          k == {"file": "/home/nvega/.ssh/authorized_keys", "line": 2, "type": "ED25519", "fp": fp}, (k, fp))
    j = f["hosts"]["web-01"]["crons"]
    check("facts: the crontab's job and its command as cron logs it", len(j) == 1 and j[0][7] == "root"
          and j[0][8] == " /usr/local/sbin/larkspur-orders >> /var/log/larkspur-orders.log 2>&1" and 0 in j[0][0]
          and 1 not in j[0][0])
    runs = H.cron_runs(H.parse_cron("17 * * * * root a\n25 6 * * 7 root b\n52 6 1 * * root c\n"),
                       END - 10 * 86400, END)
    names = collections.Counter(j[8] for _, j in runs)
    check("facts: cron's schedule (hourly, Sundays, the 1st of the month)", names == {"a": 240, "b": 2, "c": 1}, names)


# ---- size, time, prompt, detector ----

def check_size_time():
    ep = bench_ep("s4", 27)
    t0 = time.time()
    out = H.generate(ep, facts(), END)
    dt = time.time() - t0
    total = sum(len(f.data) for fs in out.values() for f in fs.values())
    check(f"size: the history is tens of MB at most ({total / 1e6:.1f} MB)", total < 70e6, total)
    check(f"time: generating it takes a few seconds ({dt:.1f} s here)", dt < 8, dt)


def check_prompt():
    routine = (REPO / "src/live_defense_bench/prompts/defender-routine-v2.md").read_text()
    a, b = E.bench_prompt(routine), E.bench_prompt(routine, history=True)
    check("prompt: with the history, the handover note says the last two weeks of logs were restored",
          "last two weeks of their logs were restored" in b and "the older ones stayed with the" not in b)
    check("prompt: without it, the bench prompt is what it was; the routine prompt file is unchanged",
          "the older ones stayed with the" in a and "the older ones stayed with the" in routine
          and a.replace("The logs on them begin then; the older ones stayed with the\nold VMs.", "") ==
          b.replace("The last two weeks of their logs were restored with them:\nthe logs on each server go back about "
                    "14 days, with a short gap at the restart.", ""))
    ep_src = (REPO / "src/live_defense_bench/episode.py").read_text()
    check("prompt: the episode asks for the history's note only with the bench profile",
          any("bench_prompt(defender_system" in l and 'history=bool(ep.get("twins"))' in l for l in ep_src.splitlines()))


def check_detector(tmp):
    """The host script on a stand-in host: the history's lines (before the boot time) are not counted."""
    root = tmp / "det"
    (root / "var/log/nginx").mkdir(parents=True)
    bt = int(time.time()) - 600
    old, new = H.iso(bt - 3600), H.iso(bt + 60)
    auth = (f"{old} web-01 sshd[1]: Accepted password for lucia from 9.9.9.9 port 1 ssh2\n"
            f"{old} web-01 sudo:    nvega : PWD=/x ; USER=root ; COMMAND=/usr/bin/oldtool --flag\n"
            f"{new} web-01 sshd[2]: Accepted password for lucia from 8.8.8.8 port 2 ssh2\n")
    (root / "var/log/auth.log").write_text(auth)
    acc = (f'1.1.1.1 - - [{H.clf(bt - 3600)}] "POST /old.php HTTP/1.1" 200 5 "-" "-"\n'
           f'1.1.1.1 - - [{H.clf(bt + 60)}] "POST /new.php HTTP/1.1" 200 5 "-" "-"\n')
    (root / "var/log/nginx/larkspur.access.log").write_text(acc)
    script = DET.HOST_SCRIPT.replace('"/var/log/', f'"{root}/var/log/').replace(
        'bt = 0\nfor l in open("/proc/stat"):\n    if l.startswith("btime"):\n        bt = int(l.split()[1])',
        f"bt = {bt}")
    script = script.replace('walk("/")', "pass").replace('for top in TOPS:', "for top in []:")
    script = script.replace('open("/etc/passwd")', "iter([])")
    p = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, env={**os.environ, "H": "web-01"})
    try:
        vals = DET.parse(p.stdout)
    except ValueError:
        vals = {}
    check("detector: the auth and access checks count only the shift's lines (not the history before the boot)",
          vals.get("rare_login_pairs") == 1 and vals.get("sudo_programs") == [] and vals.get("post_paths") == ["/new.php"],
          (vals, p.stderr[-300:]))


H_twins = load(REPO / "src/live_defense_bench/twins.py", "twins_h")


def main():
    tmp = pathlib.Path(tempfile.mkdtemp())
    try:
        eps = {}
        for sid in BENCH:
            for seed in ((25, 26, 27) if sid in ("s1", "s4") else (25,)):
                ep = bench_ep(sid, seed)
                eps[(sid, seed)] = (ep, H.generate(ep, facts(), END), END)
        ep, files, end = eps[("s0", 25)]
        check_formats(files)
        check_files(files, end)
        check_rules(eps)
        check_variety(files, end)
        check_habits(ep, files, end)
        check_planted_requests()
        check_determinism()
        check_facts(tmp)
        check_size_time()
        check_prompt()
        check_detector(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
