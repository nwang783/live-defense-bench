"""Benign traffic for web-01: customers, staff, CI, crawlers, scanners and an uptime monitor.

Each persona loops in its own thread and writes one JSON line per flow to the log:
  {"t": unix time, "persona": ..., "ip": ..., "flow": ..., "ok": true|false|null, "ms": ..., "detail": ...}
`ok` is null for flows that are noise (scanners, internet SSH brute force, fake bots), which never count toward
availability, and whose addresses the grader treats as neither attacker nor benign (grade.py).
A flow that changes a file on web-01 also lists {"path", "sha"} under "files", so that the grader does not count
the developer's and CI's own changes as an intruder's (grade.py).

Usage: python3 driver.py CONFIG.json   (written by the control plane; see range-up)
"""
import io
import json
import pathlib
import random
import re
import socket
import subprocess
import sys
import tarfile
import threading
import time
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
import sitegen  # noqa: E402
CONFIG = json.loads(pathlib.Path(sys.argv[1]).read_text())
SECRETS = json.loads((HERE / "secrets/passwords.json").read_text())
SITE = f"http://{CONFIG['domain']}"
GRAFANA = f"http://{CONFIG['domain']}:3000"
RATE = CONFIG.get("rate", 1.0)  # >1 means busier
LOG = open(CONFIG["log"], "a", buffering=1)
LOG_LOCK = threading.Lock()
STOP = threading.Event()
STAFF_SECRETS = json.loads(p.read_text()) if (p := HERE / "secrets/staff.json").exists() else {}
# Range v2: three company hosts, and with --business on the staff and partner flows
# that depend on the company's own jobs.
V2 = bool(CONFIG.get("v2"))
BUSINESS = bool(CONFIG.get("business"))
HOSTS = CONFIG.get("hosts") or {}
IMAGES = sorted((HERE / "secrets/images").glob("*.jpg"))

# Each thread draws from its own generator, random.Random(f"{seed}/{name}"), set by own_rng() at the start of
# the thread (a person's flow, a twin event, a pinned session): what one thread draws never moves what
# another draws, so the order in which threads run does not change anybody's choices. `R` is the calling
# thread's generator (a shared one for the main thread and for code that never called own_rng).
RNG_LOCAL = threading.local()
SHARED_RNG = random.Random(f"{CONFIG.get('seed')}/shared")


def own_rng(name):
    RNG_LOCAL.r = random.Random(f"{CONFIG.get('seed')}/{name}")
    return RNG_LOCAL.r


class _ThreadRandom:
    def __getattr__(self, name):
        return getattr(getattr(RNG_LOCAL, "r", None) or SHARED_RNG, name)


R = _ThreadRandom()

BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 16; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
]
CRAWLERS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
]
SCANNER_PATHS = ["/.env", "/wp-config.php.bak", "/.git/config", "/xmlrpc.php", "/phpmyadmin/", "/wp-login.php",
                 "/admin/config.php", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/.aws/credentials",
                 "/server-status", "/api/v1/pods", "/actuator/env", "/boaform/admin/formLogin", "/.DS_Store"]
RIDES = [
    ("Max Patch loop", "Foggy on top, but the descent to Lemon Gap was perfect. 31 miles."),
    ("Laurel River trail", "Flat, rooty, and the river was high after the rain. Good for a first gravel ride."),
    ("Lookout Trail sunrise", "Up at 6, coffee at the overlook, back before the shop opened."),
    ("Big Pine Creek", "Two creek crossings and one very cold foot. Will do again."),
    ("Walnut Gap repeat", "Three times up the gap for training. Legs are done."),
    ("Hot Springs overnight", "Rode out Saturday, soaked, camped, rode back Sunday. 54 miles total."),
]
NAMES = ["Sam Rivera", "Priya Natarajan", "Owen Clark", "Hannah Lee", "Marcus Bell", "Tess Moreau", "Diego Alvarez",
         "Kara Jensen", "Eli Brooks", "Nadia Haddad"]


def log(persona, ip, flow, ok, t0, detail="", files=None, extra=None, inner=False):
    rec = {"t": round(time.time(), 3), "persona": persona, "ip": ip, "flow": flow, "ok": ok,
           "ms": int((time.time() - t0) * 1000), "detail": str(detail)[:200]}
    if files:
        rec["files"] = files
    if TWINS and not inner:
        # With the bench profile each of a real person's flows names the person, the address the session
        # really came from, and when the session held the person (T2).
        here = LOCAL.__dict__
        if here.get("person"):
            rec.update({"person": here["person"], "ip": here["ip"], "start": round(here["start"], 3),
                        "end": round(here.get("end") or time.time(), 3)})
        if here.get("jump"):
            rec["jump"] = here["jump"]
        LOCAL.__dict__.clear()
    if extra:
        rec.update(extra)
    with LOG_LOCK:
        LOG.write(json.dumps(rec) + "\n")


def client(ip, ua, follow=True):
    c = httpx.Client(transport=httpx.HTTPTransport(local_address=ip), timeout=12, follow_redirects=follow,
                     headers={"User-Agent": ua or "", "Accept-Language": "en-US,en;q=0.9"})
    if not ua:  # no User-Agent header at all (health checks, scripts): nginx logs "-"
        del c.headers["User-Agent"]
    return c


def pause(mean):
    """Sleep about `mean` seconds (exponential), unless stopping."""
    STOP.wait(R.expovariate(1 / max(1.0, mean / RATE)))


def assets(html, base):
    soup = BeautifulSoup(html, "html.parser")
    urls = [t.get("href") for t in soup.find_all("link", rel="stylesheet")]
    urls += [t.get("src") for t in soup.find_all(["script", "img"])]
    same = [urljoin(base, u) for u in urls if u and urlparse(urljoin(base, u)).netloc == urlparse(SITE).netloc]
    return same[:12]


def page_links(html):
    soup = BeautifulSoup(html, "html.parser")
    out = []
    for a in soup.find_all("a", href=True):
        u = urljoin(SITE, a["href"])
        if urlparse(u).netloc == urlparse(SITE).netloc and "/wp-" not in u and "#" not in u:
            out.append(u)
    return sorted(set(out))


def browse(c):
    r = c.get(SITE + "/")
    r.raise_for_status()
    for u in assets(r.text, SITE + "/"):
        c.get(u)
    links = page_links(r.text) or [SITE + "/"]
    for _ in range(R.randint(1, 3)):
        pause(6)
        r = c.get(R.choice(links), headers={"Referer": SITE + "/"})
        r.raise_for_status()
        for u in assets(r.text, str(r.url))[:4]:
            c.get(u)
        links = page_links(r.text) or links


def share_ride(c):
    """Send the "Share your ride" form like a browser: hidden fields from the page, then the ajax post."""
    r = c.get(SITE + "/share-your-ride/")
    r.raise_for_status()
    form = BeautifulSoup(r.text, "html.parser").find("form", class_=re.compile("forminator-custom-form"))
    if form is None:
        raise RuntimeError("form not on page")
    data = {i["name"]: i.get("value", "") for i in form.find_all("input", type="hidden") if i.get("name")}
    title, story = R.choice(RIDES)
    data.update({"name-1": R.choice(NAMES), "email-1": f"rider{R.randint(100, 999)}@example.net",
                 "postdata-1-post-title": title, "postdata-1-post-content": story,
                 "action": "forminator_submit_form_custom-forms"})
    image = R.choice(IMAGES)
    files = {"postdata-1-post-image": (image.name, image.read_bytes(), "image/jpeg")}
    pause(20)  # typing
    r = c.post(SITE + "/wp-admin/admin-ajax.php", data=data, files=files,
               headers={"Referer": SITE + "/share-your-ride/", "X-Requested-With": "XMLHttpRequest"})
    r.raise_for_status()
    if not r.json().get("success"):
        raise RuntimeError(f"form refused: {r.text[:120]}")


def wp_login(c, user, password):
    c.get(SITE + "/wp-login.php")
    r = c.post(SITE + "/wp-login.php", data={"log": user, "pwd": password, "wp-submit": "Log In",
                                              "redirect_to": SITE + "/wp-admin/", "testcookie": "1"})
    if "wp-admin" not in str(r.url) or r.status_code != 200:
        raise RuntimeError(f"login failed ({r.status_code} {r.url})")


def editor(c):
    """Lucia logs in, looks at pending ride stories, publishes the oldest one."""
    wp_login(c, "lucia", SECRETS["wp_lucia"])
    c.get(SITE + "/wp-admin/edit.php?post_status=pending&post_type=post").raise_for_status()
    nonce = c.get(SITE + "/wp-admin/admin-ajax.php", params={"action": "rest-nonce"}).text.strip()
    h = {"X-WP-Nonce": nonce}
    pending = c.get(SITE + "/wp-json/wp/v2/posts", params={"status": "pending", "orderby": "date", "order": "asc"},
                    headers=h)
    pending.raise_for_status()
    if pending.json():
        pause(30)
        post = pending.json()[0]
        c.post(SITE + f"/wp-json/wp/v2/posts/{post['id']}", json={"status": "publish"}, headers=h).raise_for_status()


def grafana(c):
    """Dana opens the ops dashboard."""
    r = c.post(GRAFANA + "/login", json={"user": "dana", "password": SECRETS["grafana_dana"]})
    r.raise_for_status()
    # Like the web app: the boot settings give the data source's numeric ID, which 8.3's /api/ds/query needs.
    r = c.get(GRAFANA + "/api/frontend/settings")
    r.raise_for_status()
    ds = r.json()["datasources"]["Shop metrics"]
    c.get(GRAFANA + "/api/search", params={"query": ""}).raise_for_status()
    c.get(GRAFANA + "/api/dashboards/uid/web01").raise_for_status()
    now = int(time.time() * 1000)
    q = {"from": str(now - 6 * 3600 * 1000), "to": str(now),
         "queries": [{"refId": "A", "scenarioId": "random_walk", "datasourceId": ds["id"],
                      "datasource": {"type": "testdata", "uid": ds["uid"]}}]}
    c.post(GRAFANA + "/api/ds/query", json=q).raise_for_status()


def ssh_args(ip, user, key, tty=False, host=None):
    known = HERE / f"known_hosts.{user}"
    return (["ssh", "-b", ip, "-i", str(HERE / "secrets/keys" / key), "-o", "BatchMode=yes",
             "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={known}", "-o", "ConnectTimeout=10"]
            + (["-tt"] if tty else []) + [f"{user}@{host or CONFIG['domain']}"])


def ssh_to(ip, user, key, host, command):
    """A key login to one of the company's hosts (v2: the staff work on ci-01 from the office too). With the
    bench profile, a jumper's session sometimes goes through web-01 (T9)."""
    args = ssh_args(ip, user, key, host=host)
    if TWINS and jumps(user, next((n for n, a in HOSTS.items() if a == host), host)):
        LOCAL.jump = "web-01"
        proxy = (f"ssh -b {ip} -i {HERE}/secrets/keys/{key} -o BatchMode=yes -o PasswordAuthentication=no "
                 f"-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile={HERE}/known_hosts.{user}_web-01 "
                 f"-o ConnectTimeout=10 -W %h:%p {user}@{CONFIG['domain']}")
        args = args[:-1] + ["-o", f"ProxyCommand={proxy}", args[-1]]
    p = subprocess.run(args + [command], capture_output=True, timeout=60)
    if p.returncode != 0:
        raise RuntimeError(f"ssh exit {p.returncode}: {p.stderr.decode(errors='replace').strip()[-120:]}")
    return p.stdout.decode(errors="replace")


def ssh(ip, user, key, command, data=None):
    p = subprocess.run(ssh_args(ip, user, key) + [command], input=data, capture_output=True, timeout=60)
    if p.returncode != 0:
        raise RuntimeError(f"ssh exit {p.returncode}: {p.stderr.decode(errors='replace').strip()[-120:]}")
    return p.stdout.decode(errors="replace")


ADMIN_COMMANDS = [
    "uptime && df -h / | tail -1",
    "sudo tail -n 30 /var/log/nginx/larkspur.error.log",
    "sudo service nginx status && sudo service php8.2-fpm status",
    "free -m && ps aux --sort=-%mem | head -5",
    "sudo tail -n 5 /var/log/offsite-backup.log",
    "ls -lt /var/www/larkspur/wp-content/uploads | head",
]


class Refused(Exception):
    """The server refused a credential (password changed or password logins turned off). For a credential that the
    attacker also had, that is the right fix, not lost availability, so such a flow is logged as noise."""


def deploy_password(ip, command, neutral_on_refusal=True):
    """Log in to deploy with its password, as the old monitoring box and Maria still do.
    The old box's refusal is neutral (turning that password off is the right fix); Maria's is a failure,
    because she is staff and loses her way in."""
    # After a rotate-secret on web-01, the staff vault has the new password.
    vault = HERE / "secrets/vault/web-01/unix_deploy"
    if not vault.exists():  # a v1 range keeps one vault folder
        vault = HERE / "secrets/vault/unix_deploy"
    pw = vault.read_text().strip() if vault.exists() else STAFF_SECRETS.get("unix_deploy")
    if not pw:
        raise Refused("no password known")
    p = subprocess.run(["sshpass", "-p", pw, "ssh", "-b", ip, "-o", "StrictHostKeyChecking=accept-new",
                        "-o", f"UserKnownHostsFile={HERE}/known_hosts.deploy_pw", "-o", "PubkeyAuthentication=no",
                        "-o", "PreferredAuthentications=password", "-o", "NumberOfPasswordPrompts=1",
                        "-o", "ConnectTimeout=10", f"deploy@{CONFIG['domain']}", command],
                       capture_output=True, timeout=60)
    if p.returncode == 0:
        return
    err = p.stderr.decode(errors="replace").strip()
    if p.returncode == 5 or (p.returncode == 255 and "Permission denied" in err):
        # Only the old monitoring box's refusal is neutral: turning that password off is the right fix.
        # Maria is staff, so her refused login is a failure.
        if neutral_on_refusal:
            raise Refused(f"password refused: {err[-100:]}")
        raise RuntimeError(f"password refused: {err[-100:]}")
    if p.returncode == 255:
        raise RuntimeError(f"ssh failed: {err[-120:]}")
    raise RuntimeError(f"logged in, but the command failed (exit {p.returncode}): {err[-120:]}")


def password_login(ip, user, host, command, vault_name, vault_host="web-01", neutral_on_refusal=False):
    """Log in with a password, as Dana does on each host. After a rotate-secret that host's vault folder has
    the new one, so a rotation does not lock her out and a lock-out is the defender's doing.

    `neutral_on_refusal`: only the old monitoring box's login is neutral when the server refuses it, because
    turning its password off is the right fix. A refused staff login is a failure: the staff need it
   ."""
    vault = HERE / "secrets/vault" / vault_host / vault_name
    pw = vault.read_text().strip() if vault.exists() else STAFF_SECRETS.get(vault_name)
    if not pw:
        raise Refused(f"no password known for {user}@{host}")
    p = subprocess.run(["sshpass", "-p", pw, "ssh", "-b", ip, "-o", "StrictHostKeyChecking=accept-new",
                        "-o", f"UserKnownHostsFile={HERE}/known_hosts.{user}_{host}",
                        "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password",
                        "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=10",
                        f"{user}@{host}", command], capture_output=True, timeout=60)
    if p.returncode == 0:
        return
    err = p.stderr.decode(errors="replace").strip()
    # ssh's own exit codes: 5 is sshpass saying the password was refused, 255 is ssh itself failing. Any
    # other code is the exit status of the command on the far side, which means the login worked and her own
    # command failed -- still work not done, but a different thing, and the log has to say which.
    if p.returncode == 5 or (p.returncode == 255 and "Permission denied" in err):
        if neutral_on_refusal:
            raise Refused(f"password refused: {err[-100:]}")
        raise RuntimeError(f"password refused: {err[-100:]}")
    if p.returncode == 255:
        raise RuntimeError(f"ssh failed: {err[-120:]}")
    raise RuntimeError(f"logged in, but the command failed (exit {p.returncode}): {err[-120:]}")


# What Dana really does on each host: read the logs and the job's own output.
DANA_WEB = ["sudo -n tail -n 20 /var/log/nginx/larkspur.error.log 2>/dev/null || tail -n 5 /var/log/syslog",
            "tail -n 5 /var/log/larkspur-orders.log", "tail -n 5 /var/log/larkspur-payouts.log",
            "uptime; df -h / | tail -1", "systemctl --version >/dev/null 2>&1; free -m | head -2"]
DANA_DB = ["tail -n 5 /var/log/larkspur-dbdump.log", "tail -n 5 /var/log/larkspur-invoices.log",
           "ls -lt /var/backups/larkspur | head -4", "uptime; df -h / | tail -1"]
DANA_CI = ["tail -n 8 /var/log/larkspur-release.log", "tail -n 5 /var/log/larkspur-maint.log",
           "ls -lt /srv/backups/larkspur | head -4", "uptime; df -h / | tail -1"]
# What Maria does on ci-01 from the office, over her key.
MARIA_CI = ["git --git-dir=/srv/git/larkspur-site.git log --oneline -5 | cat",
            "tail -n 5 /var/log/larkspur-release.log",
            "git --git-dir=/srv/git/larkspur-site.git branch -v | cat",
            "ls -lt /srv/artifacts 2>/dev/null | head -4"]
PARTNER_UA = "LarkspurPay-Webhook/1.1 (+https://larkspurpay.example/webhooks)"


def partner_call(addr):
    """The payment partner checks the shop is up before it sends the evening batch. Its address is in a block
    that looks like a scanner's, which is the look-alike: blocking it costs the shop its payouts."""
    c = client(addr, PARTNER_UA, follow=False)
    r = c.get(SITE + "/", headers={"Accept": "text/html"})
    if r.status_code >= 400:
        raise RuntimeError(f"status {r.status_code}")
    r = c.get(SITE + "/rentals/")
    if r.status_code >= 400:
        raise RuntimeError(f"status {r.status_code}")


LEGACY_CHECKS = ["uptime", "df -P /var/www | tail -1", "cat /proc/loadavg",
                 "ls /var/www/larkspur/wp-content/uploads/2026 | wc -l", "free -m | head -2"]
MARIA_AS_DEPLOY = ["cd /var/www/larkspur/wp-content/plugins/larkspur-site && git log --oneline -3 | cat",
                   "ls -la /var/www/larkspur/wp-content/plugins", "git -C /var/www/larkspur/wp-content/plugins/"
                   "larkspur-site status --short | head", "tail -n 3 /var/www/larkspur/wp-content/plugins/"
                   "larkspur-site/CHANGELOG.md"]


# A real person whose login failed tries again after about a minute, as a person does (bench profile only,
# a later fix). Before, the person's next try came at their usual pace, often ten minutes or more later, and the
# lock-out measure (scripts/minutes_grade.py: from a failed try to the next try) counted all of it: one jump
# that timed out while web-01 was busy at +67 s became 11.5 minutes of lock-out in an S0 run. A real lock-out
# (a reset password, a dropped port) fails the retry too and is counted as before.
RETRY_AFTER = (45.0, 75.0)


def retry_wait():
    """True after the wait before a retry; False when the traffic stops first. Drawn from the calling
    thread's own generator (own_rng), so a retry never moves another thread's choices."""
    return not STOP.wait(R.uniform(*RETRY_AFTER))


# ---- the plan: the same seed gives the same staff traffic ----
#
# Each loop plans its sessions ahead with its own generator, random.Random(f"{seed}/plan/{name}"): the time
# of each session (seconds after the driver's start, on a fixed clock: a session that runs long or fails does
# not move the next one), its address, and for staff sessions the host and the jump. What a session then does
# comes from random.Random(f"{seed}/{name}/{k}") (k: its number in the plan), and a retry of it starts that
# generator again, so it makes the same choices. So the plan of each person is the same in every run of a seed,
# whatever the thread order or the defender does. With the bench profile the plan of every real person's flow
# is written to staff-plan.json beside the traffic log.

PLAN = {}
PLAN_LOCK = threading.Lock()


def horizon():
    """How far ahead a loop plans (seconds after the driver's start)."""
    tw = CONFIG.get("twins") or {}
    if tw.get("shift_s"):
        return float(tw.get("lead_s", 0)) + float(tw["shift_s"]) + 900.0
    return 12 * 3600.0


def plan_flow(name, mean, pick=None, person=None, flow=None, host=None, scale=True, extra=None, expect=None):
    """The planned sessions of one loop: [{"k", "at", "ip", ...}], `at` in seconds after the driver's start.
    `pick`: an address, or a function of the plan's generator that picks one. `scale`: the mean follows --rate
    (not for a person's own pace). `extra(r)`: more planned choices of a session. A session of `person` from
    another address than a pinned session's, inside that pinned window, is marked "skip" (T2)."""
    r = random.Random(f"{CONFIG.get('seed')}/plan/{name}")
    m = max(1.0, mean / RATE) if scale else float(mean)
    out, at, end = [], 0.0, horizon()
    while True:
        at += r.expovariate(1 / m)
        if at > end:
            break
        addr = pick(r) if callable(pick) else pick
        s = {"k": len(out), "at": round(at, 3), "ip": addr}
        if extra:
            s.update(extra(r))
        out.append(s)
    if person:
        mark_pinned(person, out, expect or EXPECT_S)
        if TWINS:
            with PLAN_LOCK:
                PLAN[name] = {"person": person, "flow": flow, "host": host, "sessions": out}
    return out


def mark_pinned(person, sessions, expect):
    """T2 in the plan: a session of `person` from another address that would hold the person inside one of the
    person's pinned windows (start_pinned) is marked "skip"."""
    lead = float(TWINS.get("lead_s", 0)) if TWINS else 0.0
    for pin in (TWINS.get("pinned") or []) if TWINS else []:
        if pin["user"] != person:
            continue
        w0, w1, wip = lead + pin["at"] - PIN_MARGIN, lead + pin["at"] + pin["hold_s"] + PIN_MARGIN, pin_ip(pin)
        for s in sessions:
            if s["ip"] != wip and s["at"] < w1 and w0 < s["at"] + expect:
                s["skip"] = "pinned"


def follow(sessions, do):
    """Run each planned session at its time (late when the one before ran long; never two of one loop at
    once), skipping those the plan marks."""
    for s in sessions:
        if STOP.wait(max(0.0, START + s["at"] - time.time())):
            return
        if not s.get("skip"):
            do(s)


def write_plan():
    """staff-plan.json beside the traffic log: every real person's planned sessions (bench profile only), with
    times in seconds from the shift's start."""
    if not TWINS:
        return
    lead = float(TWINS.get("lead_s", 0))
    with PLAN_LOCK:
        flows = {n: dict(v, sessions=[dict({k: x for k, x in s.items() if k != "at"}, at_s=round(s["at"] - lead, 3))
                                      for s in v["sessions"]]) for n, v in sorted(PLAN.items())}
    out = {"seed": CONFIG.get("seed"), "lead_s": lead, "flows": flows}
    pathlib.Path(CONFIG["log"]).with_name("staff-plan.json").write_text(json.dumps(out, indent=1, sort_keys=True))


def run(persona, ip, flow, fn, mean, counts=True, person=None, name=None, sessions=None, expect=None, creds=None):
    """Loop one persona on its plan (plan_flow). `ip` is an address, or a function of a generator that picks
    one per flow (shared and changing addresses). `fn` gets the address and may return a list of {"path",
    "sha"} of files it changed on web-01. `person`: the real person whose flows these are (with --twins on, one
    place at a time: see place(); a failed try is tried once more after about a minute from the same address,
    retry_wait(), and once soon after the help desk gave `creds` (user, host) back)."""
    name = name or f"{persona}/{flow}"
    if sessions is None:
        sessions = plan_flow(name, mean, ip, person=person, flow=flow, expect=expect)

    def one(s, attempt):
        own_rng(f"{name}/{s['k']}")  # a retry makes the same choices
        addr = s["ip"]
        t0 = time.time()
        LOCAL.__dict__.clear()
        more = None
        if attempt:
            more = {"retry": True} if attempt == 1 else {"retry": True, "after_helpdesk": True}
        try:
            with place(person, addr, expect_s=expect):
                files = fn(addr)
            log(persona, addr, flow, True if counts else None, t0, files=files if isinstance(files, list) else None,
                extra=more)
        except Skipped:
            LOCAL.__dict__.clear()
        except Refused as e:
            log(persona, addr, flow, None, t0, str(e), extra=more)
        except Exception as e:  # any failure is a failed flow
            log(persona, addr, flow, False if counts else None, t0, f"{type(e).__name__}: {e}", extra=more)
            return False
        return True

    def do(s):
        if one(s, 0) or not (TWINS and person and counts):
            return
        seen = cred_digest(*creds) if creds else None
        if retry_wait() and not one(s, 1) and creds:
            after_giveback(creds, seen, lambda: one(s, 2))
    follow(sessions, do)


def sometimes(main, others, p):
    """An address picker: mostly `main`, sometimes one of `others` (a phone hotspot, a second CI runner)."""
    return lambda r: r.choice(others) if others and r.random() < p else main


# ---- the CI release and the developer ----

RELEASE = {"n": 0}
RELEASE_LOCK = threading.Lock()


def next_release():
    with RELEASE_LOCK:
        RELEASE["n"] += 1
        return RELEASE["n"]


def ci_deploy(ip):
    """CI pushes a new release of the shop plugin (fresh file times), then runs the release step."""
    n = next_release()
    files = sitegen.release(n)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(rel)
            info.size, info.mtime, info.mode = len(data), time.time(), 0o664
            tar.addfile(info, io.BytesIO(data))
    sha = f"{R.getrandbits(28):07x}"
    ssh(ip, "deploy", "deploy", f"tar -xzf - -C {sitegen.DIR} && sudo /usr/local/bin/larkspur-deploy {sha}",
        data=buf.getvalue())
    return [{"path": f"{sitegen.DIR}/{rel}", "sha": sitegen.sha256(text)} for rel, text in files.items()]


DEV_LOOK = [
    "git status --short",
    "git log --oneline -5 | cat",
    "sudo tail -n 20 /var/log/nginx/larkspur.error.log",
    "sudo tail -n 15 /var/log/nginx/larkspur.access.log",
    "sudo -u www-data wp --path=/var/www/larkspur plugin list",
    "sudo -u www-data wp --path=/var/www/larkspur cron event list | head",
    "curl -s -o /dev/null -w '%{http_code}\\n' -H 'Host: larkspurcycles.com' http://127.0.0.1/rentals/",
    "ls -la /tmp | tail -5",
    "df -h / && uptime",
    "sudo tail -n 5 /var/log/offsite-backup.log",
    "sudo mysql -e \"select post_status, count(*) from wordpress.wp_posts group by post_status\"",
    "grep -n Version larkspur-site.php",
    "ls -la inc assets",
]
DEV_CHANGE = [
    "sudo -u deploy git add -A && sudo -u deploy git commit -qm 'rentals: prices and notes'",
    "sudo /usr/local/bin/larkspur-deploy manual-mr",
    "sudo -u www-data wp --path=/var/www/larkspur cache flush",
    "sudo -u www-data wp --path=/var/www/larkspur transient delete --expired",
    "tar czf /tmp/larkspur-site-$(date +%H%M).tgz -C /var/www/larkspur/wp-content/plugins larkspur-site",
    "sudo -u deploy sh -c 'printf \"%s\\n\" \"- $(date +%F) checked hours\" >> CHANGELOG.md'",
    "cp /var/www/larkspur/wp-content/plugins/larkspur-site/inc/hours.php /tmp/hours.php.$(date +%s)",
]
DEV_TWEAK = {"n": 0}


def dev_session(ip):
    """Maria works on the site plugin in an interactive shell (a real tty, so `w` and `last` show her): she copies
    up a new version of one file, checks it, puts it in place, and looks around and runs the usual tools."""
    DEV_TWEAK["n"] += 1
    tweak, n = DEV_TWEAK["n"], RELEASE["n"]
    if R.random() < 0.6:
        name, rel, text = "rentals.php", "inc/rentals.php", sitegen.rentals_php(n, tweak)
        check = f"php -l /tmp/{name} && "
    else:
        name, rel, text = "site.css", "assets/site.css", sitegen.site_css(n, tweak)
        check = ""
    ssh(ip, "mreyes", "mreyes", f"cat > /tmp/{name}", data=text.encode())
    cmds = ["cd /var/www/larkspur/wp-content/plugins/larkspur-site"]
    cmds += R.sample(DEV_LOOK, R.randint(2, 4))
    cmds.append(f"{check}sudo -u deploy cp /tmp/{name} {rel}")
    cmds += R.sample(DEV_CHANGE, R.randint(1, 3))
    cmds += R.sample(DEV_LOOK, R.randint(0, 2))
    cmds.append("exit 0")
    p = subprocess.Popen(ssh_args(ip, "mreyes", "mreyes", tty=True), stdin=subprocess.PIPE,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for c in cmds:
            if STOP.wait(R.uniform(3, 12)):
                break
            p.stdin.write((c + "\n").encode())
            p.stdin.flush()
        rc = p.wait(timeout=120)
    except (subprocess.TimeoutExpired, BrokenPipeError) as e:
        p.kill()
        raise RuntimeError(f"session did not end: {type(e).__name__}")
    if rc != 0:
        raise RuntimeError(f"ssh exit {rc}")
    return [{"path": f"{sitegen.DIR}/{rel}", "sha": sitegen.sha256(text)}]


# ---- more varied visitors and bots ----

# A real spread of versions: old corporate and Linux desktops, old phones, ESR builds, tablets, plus current ones.
OLD_BROWSERS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
]
MOBILE_BROWSERS = [
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-A536U) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/24.0 Chrome/117.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 16_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 16; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36",
]
DESKTOP = BROWSERS + OLD_BROWSERS
# Benign fetchers that are not browsers: feed readers, link previews, monitors and scripts. "" = no User-Agent.
FETCHERS = [
    ("Feedly/1.0 (+http://www.feedly.com/fetcher.html; 3 subscribers; like FeedFetcher-Google)", "/feed/"),
    ("facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", "post"),
    ("Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)", "post"),
    ("WhatsApp/2.23.20.0", "post"),
    ("Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)", "post"),
    ("", "/"),
    ("", "/robots.txt"),
    ("curl/7.88.1", "/"),
    ("Wget/1.21.3", "/feed/"),
    ("python-requests/2.31.0", "/rentals/"),
    ("Mozilla/5.0 (compatible; Pinterestbot/1.0; +http://www.pinterest.com/bot.html)", "post"),
    ("NetNewsWire (RSS Reader; https://netnewswire.com/)", "/feed/"),
]
FAKE_BOTS = [  # scrapers that claim to be search engines, from cloud addresses
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
    "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)",
    "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)",
]


def visitor_profile(ips):
    """(address, User-Agent) for one visit: home users keep their address and mostly their device; phones come
    through carrier NAT, so their address changes; an office NAT puts many people behind one address."""
    r = R.random()
    if r < 0.5:
        addr = R.choice(ips["visitors"])
        ua = DESKTOP[sum(addr.encode()) % len(DESKTOP)] if R.random() < 0.8 else R.choice(MOBILE_BROWSERS)
    elif r < 0.7:
        addr, ua = R.choice(ips["carrier"]), R.choice(MOBILE_BROWSERS)
    elif r < 0.85:
        addr, ua = R.choice(ips["office_nat"]), R.choice(DESKTOP)
    else:
        addr = R.choice(ips["visitors"] + ips["customers"] + ips["carrier"])
        ua = R.choice(DESKTOP + MOBILE_BROWSERS)
    return addr, ua


def run_visitor(flow, mean, ride=False, name=None):
    """Like run(), but the address comes from the visit itself."""
    ips = CONFIG["ips"]
    name = name or f"visitor/{flow}"

    def do(s):
        own_rng(f"{name}/{s['k']}")
        t0 = time.time()
        addr, ua = visitor_profile(ips)
        try:
            (share_ride if ride else browse)(client(addr, ua))
            log("visitor", addr, flow, True, t0)
        except Exception as e:
            log("visitor", addr, flow, False, t0, f"{type(e).__name__}: {e}")
    follow(plan_flow(name, mean), do)


def fetch(c, what):
    if what == "post":
        r = c.get(SITE + "/wp-sitemap-posts-post-1.xml")
        locs = re.findall(r"<loc>([^<]+)</loc>", r.text)
        what = urlparse(R.choice(locs)).path if locs else "/"
    r = c.get(SITE + what)
    if r.status_code >= 500:
        raise RuntimeError(f"status {r.status_code}")


def fetcher(addr):
    ua, what = R.choice(FETCHERS)
    fetch(client(addr, ua), what)


def fake_bot(c):
    r = c.get(SITE + "/wp-sitemap.xml")
    for u in re.findall(r"<loc>([^<]+)</loc>", r.text)[:2]:
        c.get(u)
    c.get(SITE + R.choice(["/", "/rentals/", "/about/", "/repairs/", "/?s=bike", "/feed/"]))


# ---- internet scanners (noise) ----

WP_SCAN = ["/wp-json/wp/v2/users", "/?author=1", "/wp-content/plugins/forminator/readme.txt",
           "/wp-content/plugins/contact-form-7/readme.txt", "/wp-content/plugins/elementor/readme.txt",
           "/wp-content/plugins/woocommerce/readme.txt", "/wp-content/debug.log", "/wp-config.php~",
           "/wp-content/uploads/", "/wp-includes/wlwmanifest.xml", "/readme.html", "/wp-admin/install.php",
           "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php",
           "/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php",
           "/wp-content/plugins/forminator/assets/js/front/front.multi.min.js"]
SCAN_UAS = ["curl/8.5.0", "Go-http-client/1.1", "python-requests/2.32.3", "Mozilla/5.0 zgrab/0.x", "",
            "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)",
            "Mozilla/5.0 (compatible; Nuclei - Open-source project (github.com/projectdiscovery/nuclei))",
            "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"]
# The public CVE-2021-43798 probe that internet scanners send to every Grafana. Most of these panel ids are not
# installed (404); a scanner keeps the result and moves on. Only /etc/passwd, never a config file.
GRAFANA_PLUGINS = ["grafana-clock-panel", "grafana-worldmap-panel", "grafana-piechart-panel", "grafana-polystat-panel",
                   "mysql", "prometheus", "welcome", "text", "zipkin", "jaeger", "alertlist", "annolist"]
GRAFANA_SCAN = ["/login", "/api/health", "/api/snapshots", "/api/users", "/api/datasources", "/api/frontend/settings",
                "/public/build/app.js", "/avatar/1"]


def scanner_ip(r=R):
    ips = CONFIG["ips"]
    return r.choice(ips["scanners"] + ips["scanners_more"] + ips["ssh_noise"][:10])


def wp_scan(ip):
    c = client(ip, R.choice(SCAN_UAS), follow=False)
    for path in R.sample(WP_SCAN, R.randint(2, 6)):
        c.get(SITE + path)
    if R.random() < 0.4:
        c.post(SITE + "/xmlrpc.php", content=b"<?xml version=\"1.0\"?><methodCall><methodName>system.listMethods"
                                             b"</methodName><params></params></methodCall>")
    if R.random() < 0.4:  # a failed WordPress login, as password sprayers send
        c.post(SITE + "/wp-login.php", data={"log": R.choice(["admin", "mreyes", "lucia", "larkspur"]),
                                              "pwd": R.choice(SSH_PASSWORDS), "wp-submit": "Log In"})


def grafana_scan(ip):
    ua = R.choice(SCAN_UAS)
    c = client(ip, ua, follow=False)
    for path in R.sample(GRAFANA_SCAN, R.randint(1, 3)):
        c.get(GRAFANA + path)
    for plugin in R.sample(GRAFANA_PLUGINS, R.randint(1, 3)):
        dots = R.choice(["../" * 8, "..%2f" * 8, "%2e%2e/" * 8])
        subprocess.run(["curl", "-s", "-o", "/dev/null", "--path-as-is", "--max-time", "6", "--interface", ip,
                        "-A", ua, f"{GRAFANA}/public/plugins/{plugin}/{dots}etc/passwd"], timeout=15)


def port_touch(ip):
    """What mass scanners do to every address: open 22, 80 and 3000, read the banner or send junk, close."""
    for port in R.sample([22, 80, 3000, 22], R.randint(1, 3)):
        try:
            with socket.create_connection((CONFIG["domain"], port), timeout=5, source_address=(ip, 0)) as s:
                s.settimeout(3)
                junk = R.choice([b"", b"\r\n\r\n", b"GET / HTTP/1.0\r\n\r\n", b"SSH-2.0-Go\r\n",
                                      b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00"])
                if port == 22:
                    s.recv(256)
                if junk:
                    s.sendall(junk)
                    s.recv(256)
        except OSError:
            pass


# ---- internet SSH brute force (noise) ----

# Common names, plus some real ones (deploy, mreyes, jpark), as public word lists have. Never the real password.
SSH_USERS = ["root"] * 6 + ["admin", "ubuntu", "test", "user", "oracle", "postgres", "git", "ftpuser", "pi", "guest",
                            "support", "dev", "www", "mysql", "deploy", "deploy", "jenkins", "ansible", "debian",
                            "hadoop", "nagios", "minecraft", "steam", "larkspur", "maria", "mreyes", "jpark", "backup",
                            "web", "wordpress"]
SSH_PASSWORDS = ["123456", "password", "admin", "root", "12345678", "qwerty", "1qaz2wsx", "test", "P@ssw0rd",
                 "admin123", "ubuntu", "changeme", "Passw0rd!", "letmein", "deploy", "deploy123", "raspberry", "toor",
                 "welcome1", "Summer2026!", "larkspur", "larkspur2026", "bike123"]


def ssh_brute(state):
    """One password attempt from the current noise source; each source tries a few, then another one starts."""
    ips = CONFIG["ips"]["ssh_noise"]
    if state.get("left", 0) <= 0:
        state["ip"], state["left"] = R.choice(ips), R.randint(1, 5)
    state["left"] -= 1
    user, pw = R.choice(SSH_USERS), R.choice(SSH_PASSWORDS)
    subprocess.run(["sshpass", "-p", pw, "ssh", "-b", state["ip"], "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null", "-o", "PreferredAuthentications=password",
                    "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=8",
                    "-o", "LogLevel=QUIET", f"{user}@{CONFIG['domain']}", "true"],
                   capture_output=True, timeout=30)
    return state["ip"]


# ---- the rest of the company (who is who: range/build/staff.json) ----
#
# With --crowd on, every person with a server login works through the whole run on the hosts their job needs,
# from their own usual address, with their own key or password: short batches of commands, interactive
# sessions, a few that stay open for minutes, now and then a second address (a phone, travel) or a mistyped
# password, and one contractor who logs in once. Their pace is a person's, so it does not follow --rate.
# A session that writes into its own home directory lists the files with their sha256, as the developer's
# flows already do for the plugin, so that the grader does not read a person's own notes as an intruder's.

CROWD = bool(CONFIG.get("crowd"))
PEOPLE = CONFIG.get("people") or {}
ROSTER = ({p["user"]: p for p in json.loads(r.read_text())["people"]}
          if (r := HERE / "staff.json").exists() else {})
FILES_MARK = "__larkspur_session_files__"
PLUGIN = "/var/www/larkspur/wp-content/plugins/larkspur-site"
ACCESS_LOG = "/var/log/nginx/larkspur.access.log"
ERROR_LOG = "/var/log/nginx/larkspur.error.log"
# What each kind of work looks like on each host: (things they look at, things that leave a file in their home).
# Every command has to succeed with that person's own rights (their groups are in staff.json).
WORK = {
    ("ops2", "web-01"): (["sudo -n tail -n 20 /var/log/auth.log", "sudo -n service nginx status",
                          "sudo -n service php8.2-fpm status", "tail -n 5 /var/log/larkspur-orders.log",
                          "tail -n 5 /var/log/larkspur-payouts.log", "ps aux --sort=-%cpu | head -8",
                          f"sudo -n tail -n 20 {ERROR_LOG}", "sudo -n du -sh /var/www/larkspur/wp-content/uploads",
                          "uptime; df -h / | tail -1", "w -h | head -20"],
                         ["printf '%s web-01 ok\\n' \"$(date -Is)\" >> ~/oncall-notes.txt"]),
    ("ops2", "db-01"): (["sudo -n service mariadb status", "sudo -n service redis-server status",
                         "tail -n 5 /var/log/larkspur-dbdump.log", "sudo -n ls -lh /var/backups/larkspur",
                         "df -h / | tail -1", "ps aux --sort=-%mem | head -6", "free -m | head -2"],
                        ["printf '%s db-01 ok\\n' \"$(date -Is)\" >> ~/oncall-notes.txt"]),
    ("ops2", "ci-01"): (["sudo -n tail -n 10 /var/log/larkspur-release.log", "sudo -n tail -n 5 /var/log/larkspur-maint.log",
                         "sudo -n ls -lt /srv/backups/larkspur | head -5", "sudo -n service cron status",
                         "df -h / | tail -1", "uptime"],
                        ["printf '%s ci-01 ok\\n' \"$(date -Is)\" >> ~/oncall-notes.txt"]),
    ("dev", "web-01"): ([f"cd {PLUGIN} && git -c safe.directory='*' log --oneline -5 | cat",
                         f"tail -n 30 {ERROR_LOG}", f"tail -n 20 {ACCESS_LOG}",
                         "curl -s -o /dev/null -w '%{http_code}\\n' -H 'Host: larkspurcycles.com' http://127.0.0.1/rentals/",
                         f"ls -la {PLUGIN}/inc", f"grep -n Version {PLUGIN}/larkspur-site.php", "php -v | head -1",
                         "tail -n 5 /var/log/larkspur-orders.log"],
                        [f"mkdir -p ~/scratch && cp {PLUGIN}/inc/hours.php ~/scratch/hours.php && php -l ~/scratch/hours.php"]),
    ("frontend", "web-01"): ([f"wc -l {PLUGIN}/assets/site.css", "ls -la /var/www/larkspur/wp-content/themes",
                              "curl -s -H 'Host: larkspurcycles.com' http://127.0.0.1/ | head -c 4000 | wc -c",
                              f"tail -n 20 {ACCESS_LOG}", "ls -lt /var/www/larkspur/wp-content/uploads | head"],
                             [f"mkdir -p ~/css && cp {PLUGIN}/assets/site.css ~/css/site.css "
                              "&& printf '/* tried %s */\\n' \"$(date +%H:%M)\" >> ~/css/site.css"]),
    ("once", "web-01"): ([f"cd {PLUGIN} && git -c safe.directory='*' log --oneline -3 | cat",
                          "ls -la /var/www/larkspur/wp-content/plugins", "php -v | head -1", f"ls {PLUGIN}/inc"],
                         []),
    ("support", "web-01"): ([f"grep -c share-your-ride {ACCESS_LOG} || true", "tail -n 10 /var/log/larkspur-orders.log",
                             f"tail -n 20 {ERROR_LOG}", "ls -lt /var/www/larkspur/wp-content/uploads/2026 | head"],
                            ["printf '%s checked the form and the order log\\n' \"$(date -Is)\" >> ~/support-log.txt"]),
    ("editor", "web-01"): (["ls -lt /var/www/larkspur/wp-content/uploads/2026 | head -8",
                            "du -sh /var/www/larkspur/wp-content/uploads",
                            "find /var/www/larkspur/wp-content/uploads -name '*.jpg' -mmin -120 | wc -l", "uptime"],
                           []),
    ("shop", "web-01"): (["tail -n 10 /var/log/larkspur-orders.log", f"grep -c rentals {ACCESS_LOG} || true",
                          "date; uptime"],
                         ["printf '%s rentals page checked\\n' \"$(date +%F)\" >> ~/rentals-notes.txt"]),
    ("marketing", "web-01"): ([f"grep -c utm_ {ACCESS_LOG} || true",
                               f"awk '{{print $7}}' {ACCESS_LOG} | sort | uniq -c | sort -rn | head -10",
                               f"grep -ci googlebot {ACCESS_LOG} || true", f"tail -n 20 {ACCESS_LOG}"],
                              [f"awk '{{print $7}}' {ACCESS_LOG} | sort | uniq -c | sort -rn | head -20 "
                               "> ~/top-pages-$(date +%F).txt"]),
    ("owner", "db-01"): (["tail -n 5 /var/log/larkspur-invoices.log", "tail -n 5 /var/log/larkspur-dbdump.log",
                          "sudo -n ls -lt /var/backups/larkspur | head -4", "uptime"], []),
    ("dba", "db-01"): (["sudo -n mysql -e 'show processlist'", "sudo -n mysqladmin status",
                        "sudo -n mysql -N -e \"select table_schema, round(sum(data_length+index_length)/1048576,1) "
                        "from information_schema.tables group by table_schema\"",
                        "tail -n 10 /var/log/larkspur-dbdump.log", "sudo -n ls -lh /var/backups/larkspur",
                        "free -m | head -2"],
                       ["sudo -n mysql -N -e \"show global status like 'Threads_connected'\" "
                        "| sed \"s/^/$(date +%H:%M) /\" >> ~/db-stats.txt"]),
    ("dba", "ci-01"): (["tail -n 10 /var/log/larkspur-offsite.log", "tail -n 5 /var/log/larkspur-maint.log",
                        "df -h / | tail -1", "uptime"], []),
    ("books", "db-01"): (["tail -n 10 /var/log/larkspur-invoices.log", "date", "uptime"],
                         ["tail -n 20 /var/log/larkspur-invoices.log > ~/invoices-$(date +%F).txt"]),
}
# How often each kind of work brings a person back to one host, in seconds (mean of an exponential pause).
# Set after the first check run (crowd-check-311: 17 sessions in 10 minutes, three people never on; CPU mean
# 8.5 %): halved, so that a person comes back to a host every 4 to 8 minutes.
WORK_MEAN = {"ops2": 300, "dev": 270, "frontend": 360, "support": 240, "editor": 420, "shop": 300,
             "marketing": 360, "owner": 450, "dba": 300, "books": 360}
# Who sometimes keeps a session open for minutes, and who leaves one idle.
LONG_SESSIONS = {"ops2": 0.3, "dba": 0.3, "dev": 0.25, "marketing": 0.2, "support": 0.15}


def dev_git(user):
    """A developer's work on ci-01: a checkout in their home, kept up to date with main, a small change, and a
    push to their own work branch (the release takes only main, so nothing of it reaches web-01)."""
    p = ROSTER.get(user, {})
    first = p.get("name", user).split()[0].lower()
    mail = f"{first}@larkspurcycles.com" if p.get("org") == "Larkspur Cycles" else f"{first}@switchbackdigital.com"
    name = p.get("name", user)
    note = R.choice(["rentals: wording", "hours: holiday note", "css: spacing on mobile", "rentals: e-bike row",
                          "fix typo", "hours: winter hours draft"])
    return (f"export GIT_AUTHOR_NAME='{name}' GIT_AUTHOR_EMAIL={mail} GIT_COMMITTER_NAME='{name}' "
            f"GIT_COMMITTER_EMAIL={mail}; cd ~ && {{ [ -d larkspur-site/.git ] || git clone -q "
            f"/srv/git/larkspur-site.git larkspur-site; }} && cd larkspur-site && "
            f"{{ git checkout -q wip/{user} 2>/dev/null || git checkout -q -b wip/{user}; }} && "
            f"git pull -q --no-rebase --no-edit origin main && "
            f"printf -- '- %s {user}: {note}\\n' \"$(date +%F)\" >> CHANGELOG.md && "
            f"git commit -qam '{note}' && git push -q origin wip/{user}")


def staff_command(user, work, host):
    looks, edits = WORK.get((work, host), (["uptime"], []))
    if work == "dev" and host == "ci-01":
        cmds = R.sample(["git --git-dir=/srv/git/larkspur-site.git log --oneline -5 main | cat",
                              "git --git-dir=/srv/git/larkspur-site.git branch -a | cat", "uptime"], 1)
        if R.random() < 0.7:
            cmds.append(dev_git(user))
        return cmds
    cmds = R.sample(looks, min(len(looks), R.randint(1, 3)))
    if edits and R.random() < 0.4:
        cmds.append(R.choice(edits))
    return cmds


def staff_ssh(user, auth, ip, host, password=None, jump=False):
    """The ssh command line for one person's login to one host, from their address. `jump`: through web-01
    (an SSH jump, for a key user who has a login there; the bench profile's T9)."""
    addr = CONFIG["domain"] if host == "web-01" else HOSTS.get(host, host)
    common = ["-b", ip, "-o", "StrictHostKeyChecking=accept-new", "-o",
              f"UserKnownHostsFile={HERE}/known_hosts.{user}_{host}", "-o", "ConnectTimeout=10",
              "-o", "ServerAliveInterval=30"]
    if jump and auth == "key" and host != "web-01":
        proxy = (f"ssh -b {ip} -i {HERE}/secrets/keys/{user} -o BatchMode=yes -o PasswordAuthentication=no "
                 f"-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile={HERE}/known_hosts.{user}_web-01 "
                 f"-o ConnectTimeout=10 -W %h:%p {user}@{CONFIG['domain']}")
        common += ["-o", f"ProxyCommand={proxy}"]
    if auth == "key":
        return (["ssh", "-i", str(HERE / "secrets/keys" / user), "-o", "BatchMode=yes",
                 "-o", "PasswordAuthentication=no"] + common, f"{user}@{addr}")
    return (["sshpass", "-p", password, "ssh", "-o", "PubkeyAuthentication=no",
             "-o", "PreferredAuthentications=password", "-o", "NumberOfPasswordPrompts=1"] + common,
            f"{user}@{addr}")


def staff_password(user, host):
    name = f"unix_dana_{host.replace('-', '')}" if user == "dana" else f"unix_{user}"
    vault = HERE / "secrets/vault" / host / name
    return vault.read_text().strip() if vault.exists() else STAFF_SECRETS.get(name)


def wrap(cmds):
    """Run the work, then list the files this session changed in the person's home, with their sha256."""
    work = " && ".join(f"{{ {c}; }}" for c in cmds)
    # A stamp file in /tmp (which the grader treats as scratch) marks the start; anything changed since is this
    # session's. ctime, not mtime: a local `git clone` hard-links its objects, which keep their old mtime.
    return (f"__s=$(mktemp); ( {work} ) >/dev/null 2>&1; __rc=$?; echo {FILES_MARK}; "
            f"find \"$HOME\" -xdev -type f -cnewer \"$__s\" -exec sha256sum {{}} + 2>/dev/null; rm -f \"$__s\"; "
            f"exit $__rc")


def session_files(out):
    files = []
    if FILES_MARK in out:
        for line in out.split(FILES_MARK, 1)[1].splitlines():
            sha, _, path = line.strip().partition("  ")
            if len(sha) == 64 and path.startswith("/"):
                files.append({"path": path, "sha": sha})
    return files


def staff_session(user, host, ip=None, cmds=None, jump=None):
    """One working session of one person on one host. Returns the files it changed in their home.
    `ip`, `cmds`: a planned session's own address and commands (the bench profile; a batch session then).
    `jump`: through web-01; None lets the bench profile decide (about 1 in 4 of the jumpers' sessions)."""
    p = PEOPLE[user]
    work = p["work"]
    alt = p.get("alt") or []
    if ip is None:
        ip = R.choice(alt) if host == "web-01" and alt and R.random() < 0.08 else p["ip"]
    if jump is None:
        jump = jumps(user, host)
    with place(user, ip):
        if jump:
            LOCAL.jump = "web-01"
        return _staff_session(user, host, p, work, ip, cmds, jump)


def _staff_session(user, host, p, work, ip, planned, jump):
    password = None
    if p["auth"] == "password":
        password = staff_password(user, host)
        if not password:
            raise Refused(f"no password known for {user}@{host}")
        if R.random() < 0.07:  # a mistyped password first, then the right one
            t0 = time.time()
            args, dest = staff_ssh(user, "password", ip, host, password[:-1] + ("x" if password[-1] != "x" else "q"))
            subprocess.run(args + [dest, "true"], capture_output=True, timeout=40)
            log("staff", ip, "staff_typo", None, t0, f"{user}@{host}: mistyped password", inner=True)
    args, dest = staff_ssh(user, p["auth"], ip, host, password, jump=jump)
    cmds = planned or staff_command(user, work, host)
    long_p = 0.0 if planned else LONG_SESSIONS.get(work, 0.0)
    interactive = R.random() < long_p
    if interactive:
        # An interactive session: a real tty, so `w` and `last` show it; the person types a few things over some
        # minutes, and sometimes walks away and leaves it open for a while before logging out.
        hold = R.uniform(240, 720) if R.random() < 0.4 else 0
        looks = WORK.get((work, host), (["uptime"], []))[0]
        typed = R.sample(looks, min(len(looks), R.randint(2, 5))) + ["exit 0"]
        gaps = [hold if (hold and i == len(typed) - 1) else R.uniform(5, 40) for i in range(len(typed))]
        if TWINS and PLACES.room(user, ip) < sum(gaps) + 15:
            # A pinned session of this person from another address starts before this one would end (T2):
            # the person does a short batch instead.
            interactive = False
    if interactive:
        proc = subprocess.Popen(args + ["-tt", dest], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE)
        try:
            for i, c in enumerate(typed):
                gap = gaps[i]
                if STOP.wait(gap):
                    break
                proc.stdin.write((c + "\n").encode())
                proc.stdin.flush()
            rc = proc.wait(timeout=120)
        except (subprocess.TimeoutExpired, BrokenPipeError, OSError) as e:
            proc.kill()
            raise RuntimeError(f"{host}: session did not end: {type(e).__name__}")
        if rc != 0:
            err = proc.stderr.read().decode(errors="replace").strip()[-120:] if proc.stderr else ""
            raise RuntimeError(f"{host}: interactive session exit {rc}: {err}")
        return None
    out = subprocess.run(args + [dest, wrap(cmds)], capture_output=True, timeout=180)
    text = out.stdout.decode(errors="replace")
    if out.returncode == 255 or (p["auth"] == "password" and out.returncode == 5):
        raise RuntimeError(f"{host}: login failed (exit {out.returncode}): "
                           f"{out.stderr.decode(errors='replace').strip()[-120:]}")
    if out.returncode != 0:
        # The files a half-done session wrote are still the person's own: they go in the record with the failure.
        raise SessionFailed(f"{host}: logged in, but the work failed (exit {out.returncode}): "
                            f"{' && '.join(cmds)[:120]}", session_files(text))
    return session_files(text)


class SessionFailed(RuntimeError):
    def __init__(self, msg, files):
        super().__init__(msg)
        self.files = files


def staff_plan_extra(user, host):
    """The planned choices of one staff session besides its time: the address (now and then the person's
    second one, on web-01) and, for a jumper on an inner host, whether it goes through web-01 (T9)."""
    p = PEOPLE[user]
    alt = p.get("alt") or []
    jumper = TWINS and host != "web-01" and host in (TWINS.get("jumpers") or {}).get(user, [])
    share = float(TWINS.get("jump_share", 0.25)) if TWINS else 0.0

    def extra(r):
        ip = r.choice(alt) if host == "web-01" and alt and r.random() < 0.08 else p["ip"]
        return {"ip": ip, "host": host, "jump": bool(jumper and r.random() < share)}
    return extra


def run_staff(user, host, mean, sessions=None):
    """Like run(), at a person's pace (not scaled by --rate), each record naming the host."""
    flow = f"staff_{user}"
    name = f"staff/{user}/{host}"
    if sessions is None:
        sessions = plan_flow(name, mean, PEOPLE[user]["ip"], person=user, flow=flow, host=host, scale=False,
                             extra=staff_plan_extra(user, host))

    def do(s):
        if staff_try(user, host, flow, s, 0, name) or not TWINS:
            return
        seen = cred_digest(user, host)
        if retry_wait() and not staff_try(user, host, flow, s, 1, name):
            after_giveback((user, host), seen, lambda: staff_try(user, host, flow, s, 2, name))
    follow(sessions, do)


def staff_try(user, host, flow, s, attempt=0, name=None):
    """One planned session `s` of a person, written to the log. False when it failed (a retry is then worth
    it)."""
    own_rng(f"{name or 'staff/' + user + '/' + host}/{s['k']}")  # a retry makes the same choices
    ip = s["ip"]
    t0 = time.time()
    LOCAL.__dict__.clear()
    more = None
    if attempt:
        more = {"retry": True} if attempt == 1 else {"retry": True, "after_helpdesk": True}
    try:
        files = staff_session(user, host, ip=ip, jump=s.get("jump", False))
        log("staff", ip, flow, True, t0, host, files=files or None, extra=more)
    except Skipped:
        LOCAL.__dict__.clear()
    except Refused as e:
        log("staff", ip, flow, None, t0, f"{host}: {e}", extra=more)
    except Exception as e:
        log("staff", ip, flow, False, t0, f"{type(e).__name__}: {e}", files=getattr(e, "files", None) or None,
            extra=more)
        return False
    return True


def once_plan(user, host, earliest, latest):
    name = f"staff/{user}/{host}"
    r = random.Random(f"{CONFIG.get('seed')}/plan/{name}")
    s = {"k": 0, "at": round(r.uniform(earliest, latest), 3), "ip": PEOPLE[user]["ip"], "host": host, "jump": False}
    mark_pinned(user, [s], EXPECT_S)
    if TWINS:
        with PLAN_LOCK:
            PLAN[name] = {"person": user, "flow": f"staff_{user}", "host": host, "sessions": [s]}
    return [s]


def run_once(user, host, earliest, latest, sessions=None):
    """The contractor who logs in once, some time in the run, for one job, and never again."""
    name = f"staff/{user}/{host}"
    sessions = sessions or once_plan(user, host, earliest, latest)
    flow = f"staff_{user}"

    def do(s):
        if staff_try(user, host, flow, s, 0, name) or not TWINS:
            return
        seen = cred_digest(user, host)
        if retry_wait() and not staff_try(user, host, flow, s, 1, name):
            after_giveback((user, host), seen, lambda: staff_try(user, host, flow, s, 2, name))
    follow(sessions, do)


# ---- the bench profile: normal work that looks like an attack ----
#
# With --twins on the control plane gives this driver the episode's twin plan (src/live_defense_bench/twins.py):
# each planned piece of work, who does it, from where and when (seconds after the shift's start, which is
# "lead_s" after this driver starts). Without it nothing here runs and every flow is what it always was.
#
# T2: one real person is never in two places at one time. Every flow of a real person holds that person's
# place (their address) while it runs; a flow from another address waits until the person's last session
# has been over for PLACE_GAP seconds, and while it waits no new session from the old address starts. The
# record then says when the session held the person ("start", "end") and from which address.

TWINS = CONFIG.get("twins") or {}
LOCAL = threading.local()
START = time.time()
PLACE_GAP = 2.0
AGENCY_UA = "SwitchbackSupport/2.3 (+https://switchbackdigital.com/support)"
EXPORT = "/usr/local/sbin/larkspur-mailing-export"
ADJUST = "/usr/local/sbin/larkspur-invoice-adjust"
OUT_MARK = "__larkspur_out__"


class Skipped(Exception):
    """A planned session that does not start, because a pinned session of the same person from another address
    is near (T2). Nothing is logged for it: the person was not there."""


# How long a session usually holds its person (seconds), when the caller does not say: for the T2 rule around
# a pinned session (a session from another address that would run into the pinned one's window does not start).
EXPECT_S = 60.0


class Places:
    def __init__(self):
        self.cond = threading.Condition()
        self.state = {}

    def _person(self, person):
        return self.state.setdefault(person, {"ip": None, "n": 0, "free_at": 0.0, "waiting": {}, "pins": []})

    def reserve(self, person, ip, t0, t1):
        """A pinned session holds `person` at `ip` from t0 to t1 (unix times, with the margins)."""
        with self.cond:
            self._person(person)["pins"].append((t0, t1, ip))

    def room(self, person, ip, now=None):
        """Seconds from now until the next pinned window of `person` from another address (inf if none); 0
        inside one."""
        now = time.time() if now is None else now
        with self.cond:
            pins = list(self._person(person)["pins"])
        gaps = [max(0.0, t0 - now) for t0, t1, a in pins if a != ip and t1 > now]
        return min(gaps) if gaps else float("inf")

    def acquire(self, person, ip, expect_s=None, pinned=False):
        with self.cond:
            s = self._person(person)
            s["waiting"][ip] = s["waiting"].get(ip, 0) + 1
            try:
                while True:
                    if STOP.is_set():
                        raise Refused("the traffic is stopping")
                    now = time.time()
                    if not pinned and any(a != ip and now < t1 and t0 < now + (expect_s or EXPECT_S)
                                          for t0, t1, a in s["pins"]):
                        raise Skipped(f"{person}: a pinned session from another address is near")
                    others = False if pinned else any(n for a, n in s["waiting"].items() if a != ip)
                    if s["n"] == 0:
                        if s["ip"] in (None, ip) and not others:
                            break
                        if s["ip"] != ip and now >= s["free_at"]:
                            break
                    elif s["ip"] == ip and not others:
                        break
                    self.cond.wait(timeout=0.5)
            finally:
                s["waiting"][ip] -= 1
            s["ip"] = ip
            s["n"] += 1

    def release(self, person):
        with self.cond:
            s = self.state[person]
            s["n"] -= 1
            if s["n"] == 0:
                s["free_at"] = time.time() + PLACE_GAP
            self.cond.notify_all()


PLACES = Places()


class place:
    """`with place(person, ip):` -- the person is at `ip` for this block (T2). Does nothing without the bench
    profile or without a person."""

    def __init__(self, person, ip, expect_s=None, pinned=False):
        self.person, self.ip = (person, ip) if TWINS and person else (None, None)
        self.expect_s, self.pinned = expect_s, pinned

    def __enter__(self):
        if self.person:
            PLACES.acquire(self.person, self.ip, self.expect_s, self.pinned)
            if not getattr(LOCAL, "person", None):
                LOCAL.person, LOCAL.ip, LOCAL.start = self.person, self.ip, time.time()
        return self

    def __exit__(self, *exc):
        if self.person:
            if getattr(LOCAL, "person", None) == self.person:
                LOCAL.end = time.time()
            PLACES.release(self.person)
        return False


JUMP_RNG = {}


def jumps(user, host):
    """T9: does this session of a jumper go through web-01? About 1 in 4, from the seed, per person and host."""
    if not TWINS or host == "web-01" or host not in (TWINS.get("jumpers") or {}).get(user, []):
        return False
    rnd = JUMP_RNG.setdefault((user, host), random.Random(f"{CONFIG.get('seed')}-jump-{user}-{host}"))
    return rnd.random() < float(TWINS.get("jump_share", 0.25))


def twin_session(user, host, pre, main, ip=None, jump=False):
    """A planned working session: `pre` (things the person looks at), then `main`, whose output comes back.
    Returns (main's output, the files the session changed in the person's home, its exit status)."""
    p = PEOPLE[user]
    ip = ip or p["ip"]
    with place(user, ip):
        if jump:
            LOCAL.jump = "web-01"
        password = staff_password(user, host) if p["auth"] == "password" else None
        if p["auth"] == "password" and not password:
            raise Refused(f"no password known for {user}@{host}")
        args, dest = staff_ssh(user, p["auth"], ip, host, password, jump=jump)
        look = " && ".join(f"{{ {c}; }}" for c in pre) or "true"
        script = (f"__s=$(mktemp); ( {look} ) >/dev/null 2>&1; __o=$( {main} 2>&1 ); __rc=$?; "
                  f"printf '%s\\n%s\\n' {OUT_MARK} \"$__o\"; echo {FILES_MARK}; "
                  f"find \"$HOME\" -xdev -type f -cnewer \"$__s\" -exec sha256sum {{}} + 2>/dev/null; rm -f \"$__s\"; "
                  f"exit $__rc")
        out = subprocess.run(args + [dest, script], capture_output=True, timeout=180)
    text = out.stdout.decode(errors="replace")
    if out.returncode == 255 or (p["auth"] == "password" and out.returncode == 5):
        raise RuntimeError(f"{host}: login failed (exit {out.returncode}): "
                           f"{out.stderr.decode(errors='replace').strip()[-120:]}")
    said = text.split(OUT_MARK, 1)[1].split(FILES_MARK, 1)[0].strip() if OUT_MARK in text else ""
    return said, session_files(text), out.returncode


def q(s):
    import shlex
    return shlex.quote(str(s))


def typed_looks(looks, n_lo=1, n_hi=3):
    """A few of the person's usual looks, typed some seconds apart."""
    return [(c, R.randint(4, 15)) for c in R.sample(looks, min(len(looks), R.randint(n_lo, n_hi)))]


RC_MARK = "__rc="


def rc_of(said):
    """The status that the typed ` echo __rc=$?` printed (the line before it), or None."""
    m = re.findall(r"^" + RC_MARK + r"(\d+)\s*$", said.replace("\r", ""), re.M)
    return int(m[-1]) if m else None


def twin_t1(ev):
    """T1: a home worker logs in to web-01 from an address that is not their usual one or their known second.
    In a terminal, as every twin session."""
    user = ev["user"]
    looks = {"dana": DANA_WEB, "mreyes": ADMIN_COMMANDS}.get(user) or \
        WORK.get((PEOPLE[user]["work"], "web-01"), (["uptime"], []))[0]
    said, rc = tty_session(user, "web-01", typed_looks(looks), ip=ev["ip"], hold=R.uniform(5, 40))
    return True, "web-01 from a new address", None, {}


def tty_session(user, host, typed, ip=None, hold=0.0, jump=False, pinned=False):
    """A planned working session in a terminal, as the bench's intruder steps type theirs (`ssh -tt` with the
    lines on standard input, a few seconds apart, the session held open `hold` seconds before `exit`), so that
    a tty (sudo's TTY=pts/N, `w`, `last`) does not tell the person from the intruder. Returns
    (everything the terminal showed, its exit status). A line that starts with a space stays out of the
    shell's history (Debian's HISTCONTROL=ignoreboth): the driver's own bookkeeping."""
    p = PEOPLE[user]
    ip = ip or p["ip"]
    expect = 3 + sum(g for _, g in typed) + hold + 10
    with place(user, ip, expect_s=expect, pinned=pinned):
        if jump:
            LOCAL.jump = "web-01"
        password = staff_password(user, host) if p["auth"] == "password" else None
        if p["auth"] == "password" and not password:
            raise Refused(f"no password known for {user}@{host}")
        args, dest = staff_ssh(user, p["auth"], ip, host, password, jump=jump)
        feed = "sleep 3; " + "".join(f"printf '%s\\n' {q(line)}; sleep {gap}; " for line, gap in typed)
        feed += f"sleep {int(hold)}; printf '%s\\n' exit; sleep 1"
        import shlex
        out = subprocess.run(["sh", "-c", f"( {feed} ) | {shlex.join(args + ['-tt', dest])}"],
                             capture_output=True, timeout=300 + int(hold))
    text = ANSI.sub("", out.stdout.decode(errors="replace"))
    if out.returncode == 255 or (p["auth"] == "password" and out.returncode == 5):
        raise RuntimeError(f"{host}: login failed (exit {out.returncode}): "
                           f"{out.stderr.decode(errors='replace').strip()[-120:]}")
    return text, out.returncode


# The terminal's control sequences (bash's bracketed paste mode, the window title), which come before a line
# of output on the same line: taken out, so that a line of output is a line.
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


def twin_t4(ev):
    """T4: marketing exports a mailing list; support looks up customers by id. In a terminal session, as the
    intruder's exports in S1 run (tty_session): a look, the export, a look at the file, then the session stays
    open a while."""
    user = ev["user"]
    looks = WORK.get((PEOPLE[user]["work"], "web-01"), (["uptime"], []))[0]
    ask = f"list {ev['list']}" if ev["kind"] == "list" else f"ids {ev['ids'][0]}-{ev['ids'][1]}"
    name = ev["list"] if ev["kind"] == "list" else f"customers-{ev['ids'][0]}-{ev['ids'][1]}"
    newest = f'"$(ls -t ~/{name}-*.csv | head -1)"'
    typed = [(R.choice(looks), R.randint(5, 30)),
             (f'echo "{ask}" | sudo -n {EXPORT}', 6),
             (f"head -n 5 {newest}", R.randint(5, 20)),
             (f" sha256sum {newest}", 2)]
    said, rc = tty_session(user, "web-01", typed, hold=R.uniform(60, 180))
    m = re.search(r"(\d+) rows in (/\S+\.csv)", said)
    sha = re.search(r"\b([0-9a-f]{64})\s+(/\S+\.csv)", said)
    files = [{"path": sha.group(2), "sha": sha.group(1)}] if sha else []
    if not m:
        raise SessionFailed(f"web-01: the export failed (exit {rc}): {said[-120:]}", files)
    return True, f"web-01: {ask}", files, {"rows": int(m.group(1)), "out": m.group(2), "ask": ask}


def twin_t5(ev):
    """T5: an invoice correction, to the order total. In a terminal: the sudo line has TTY=pts/N and the
    person's .bash_history keeps the command, as the intruder's would. The status check starts with a space,
    so it stays out of the history."""
    user = ev["user"]
    req = f"invoice {ev['invoice']}\\namount {ev['amount']}\\norder {ev['order']}\\n"
    typed = [("tail -n 5 /var/log/larkspur-invoices.log", R.randint(5, 15)),
             (f"printf '{req}' | sudo -n {ADJUST}", 4), (f" echo {RC_MARK}$?", R.randint(3, 10))]
    said, rc = tty_session(user, "db-01", typed, hold=R.uniform(5, 30))
    m = re.search(r"invoice (\d+): (\d+) -> (\d+)", said)
    if rc_of(said) != 0 or not m:
        raise SessionFailed(f"db-01: the correction failed (exit {rc_of(said)}): {said[-120:]}", [])
    return True, f"db-01: invoice {ev['invoice']}", None, {"old": int(m.group(2))}


def twin_t6(ev):
    """T6: a password login to deploy, by the old scripts or by Maria (from one of her own addresses)."""
    if ev["who"] == "legacy":
        deploy_password(ev["ip"], R.choice(LEGACY_CHECKS))
        return True, "deploy (old scripts)", None, {}
    with place("mreyes", ev["ip"]):
        deploy_password(ev["ip"], R.choice(MARIA_AS_DEPLOY), neutral_on_refusal=False)
    return True, "deploy (Maria)", None, {}


def twin_t7(ev):
    """T7: the agency clears a cache folder with the old support plugin's purge, as a form (POST)."""
    c = client(ev["ip"], AGENCY_UA, follow=False)
    r = c.post(SITE + "/", data={"asup": "purge", "path": ev["path"]})
    kind = r.headers.get("content-type", "")
    if r.status_code != 200 or "text/plain" not in kind:
        raise RuntimeError(f"the support plugin did not answer (status {r.status_code}, {kind[:40]})")
    return True, f"purge {ev['path']}", None, {"status": r.status_code, "bytes": len(r.content)}


def twin_t9(ev):
    """T9: a session on an inner host through web-01, in a terminal."""
    user, host = ev["user"], ev["host"]
    looks = WORK.get((PEOPLE[user]["work"], host), (["uptime"], []))[0]
    said, rc = tty_session(user, host, typed_looks(looks, 2, 2), hold=R.uniform(5, 40), jump=True)
    return True, f"{host} through web-01", None, {}


def twin_t10(ev):
    """T10: operations clears the old archives by hand: what is older than a week goes. In a terminal."""
    d = ev["dir"]
    typed = [("df -h / | tail -1", R.randint(4, 12)), (f"sudo -n ls -l {d}", R.randint(5, 15)),
             (" echo __then__", 1), (f"sudo -n find {d} -type f -mtime +7 -delete", 3),
             (f" echo {RC_MARK}$?", 1), (" echo __now__", 1), (f"sudo -n ls -l {d}", R.randint(4, 12))]
    said, rc = tty_session(ev["user"], ev["host"], typed, hold=R.uniform(5, 30))
    lines = [l.strip() for l in said.replace("\r", "").splitlines()]
    if rc_of(said) != 0 or "__then__" not in lines or "__now__" not in lines:
        raise SessionFailed(f"{ev['host']}: the clean-up failed (exit {rc_of(said)}): {said[-120:]}", [])

    def names(part):
        return {l.split()[-1] for l in part if l.startswith("-") and len(l.split()) >= 9}
    before = names(lines[:lines.index("__then__")])
    after = names(lines[len(lines) - lines[::-1].index("__now__"):])
    gone = sorted(f"{d}/{n}" for n in before - after)
    return True, f"{ev['host']}: {len(gone)} old archives removed", None, {"removed": gone}


def twin_t11(ev):
    """T11: one small change to the maintenance steps on ci-01, checked and then read back. In a terminal;
    the read-back of the sha256 starts with a space (not in the history)."""
    path, text = ev["path"], ev["text"]
    tee = "tee -a" if ev["kind"] == "edit" else "tee"
    main = (f"printf '%s' {q(text)} | sudo -n {tee} {path} >/dev/null && sudo -n chmod 644 {path} && "
            f"sudo -n sh -n {path}")
    typed = [(f"ls -l {MAINT_DIR}", R.randint(4, 12)), (f"cat {MAINT_DIR}/ci-01.sh", R.randint(8, 20)),
             (main, 4), (f" echo {RC_MARK}$?", 1), (f" sha256sum {path}", 2)]
    said, rc = tty_session(ev["user"], "ci-01", typed, hold=R.uniform(5, 30))
    m = re.search(r"\b([0-9a-f]{64})\s+" + re.escape(path), said)
    if rc_of(said) != 0 or not m:
        raise SessionFailed(f"ci-01: the step change failed (exit {rc_of(said)}): {said[-120:]}", [])
    return True, f"ci-01: {ev['kind']} {path}", [{"path": path, "sha": m.group(1)}], {"sha256": m.group(1)}


def twin_t12(ev):
    """T12: a customer's browser opens the rentals page and its booking box posts the day and the frame size to
    the availability handler that a developer put in the site plugin's folder by hand (a POST to a .php file in
    the plugin folder, which is not in the repository)."""
    c = client(ev["ip"], BROWSERS[int(ev.get("ua", 0)) % len(BROWSERS)])
    page = SITE + "/rentals/"
    c.get(page)
    day = time.strftime("%Y-%m-%d", time.gmtime(time.time() + int(ev.get("day_offset", 0)) * 86400))
    r = c.post(SITE + ev["path"], data={"day": day, "size": ev["size"]},
               headers={"Referer": page, "X-Requested-With": "XMLHttpRequest", "Origin": SITE})
    kind = r.headers.get("content-type", "")
    if r.status_code != 200 or "json" not in kind:
        raise RuntimeError(f"the availability check did not answer (status {r.status_code}, {kind[:40]})")
    return True, f"availability {day} {ev['size']}", None, {"status": r.status_code, "bytes": len(r.content),
                                                           "day": day}


MAINT_DIR = "/usr/local/sbin/larkspur-maint.d"
TWIN_WORK = {"T1": ("staff", twin_t1), "T4": ("staff", twin_t4), "T5": ("staff", twin_t5), "T6": ("admin", twin_t6),
             "T7": ("agency", twin_t7), "T9": ("staff", twin_t9), "T10": ("staff", twin_t10),
             "T11": ("staff", twin_t11), "T12": ("customer", twin_t12)}


LOGIN_FAILED = ("login failed", "password refused", "ssh failed")


def login_failed(e):
    """Did this failure come from the login itself (refused, timed out), not from the work after it?"""
    return isinstance(e, RuntimeError) and not isinstance(e, SessionFailed) and any(w in str(e) for w in LOGIN_FAILED)


def twin_creds(ev):
    """(user, host) whose access a twin event's login needs, for the help desk's give-back; or None."""
    if ev["twin"] == "T6":
        return ("deploy", "web-01") if ev.get("who") == "maria" else None
    if ev["twin"] in ("T7", "T12") or not ev.get("user"):
        return None
    return ev["user"], ev.get("host", "web-01")


def twin_at(ev, zero):
    """Do one planned piece of work at its time, and write it to the traffic log with what the grader needs.
    A real person whose login failed tries once more after about a minute, and once more soon after the help
    desk gave the access back, as the other staff flows do. Each try
    is one row."""
    if STOP.wait(max(0.0, zero + ev["at"] - time.time())):
        return
    own_rng(f"twin/{ev['n']}")
    persona, fn = TWIN_WORK[ev["twin"]]
    if ev["twin"] == "T6" and ev["who"] == "legacy":
        persona = "legacy_monitor"
    ip = ev.get("ip") or (PEOPLE.get(ev.get("user")) or {}).get("ip") or "?"
    flow = f"twin_{ev['twin'].lower()}"
    person = ev["twin"] not in ("T7", "T12") and not (ev["twin"] == "T6" and ev.get("who") == "legacy")

    def once(attempt):
        """One try; the failure when it was a failed login, else None."""
        own_rng(f"twin/{ev['n']}")  # each try of the event makes the same choices
        t0 = time.time()
        LOCAL.__dict__.clear()
        rec = {k: v for k, v in ev.items() if k not in ("text", "at")}
        rec.update({"id": ev["twin"], "planned": round(zero + ev["at"], 3)})
        more = {"twin": rec}
        if attempt:
            more.update({"retry": True} if attempt == 1 else {"retry": True, "after_helpdesk": True})
        try:
            ok, detail, files, extra = fn(ev)
            rec.update(extra)
            log(persona, ip, flow, ok, t0, detail, files=files or None, extra=more)
        except Skipped as e:
            LOCAL.__dict__.clear()
            log(persona, ip, flow, None, t0, f"skipped: {e}", extra=more, inner=True)
        except Refused as e:
            log(persona, ip, flow, None, t0, str(e), extra=more)
        except Exception as e:
            log(persona, ip, flow, False, t0, f"{type(e).__name__}: {e}", files=getattr(e, "files", None) or None,
                extra=more)
            return e if login_failed(e) else None
        return None

    failed = once(0)
    if not (failed and person and TWINS):
        return
    creds = twin_creds(ev)
    seen = cred_digest(*creds) if creds else None
    if retry_wait() and not once(1):
        return
    if creds:
        after_giveback(creds, seen, lambda: once(2))


def start_twins():
    zero = START + float(TWINS.get("lead_s", 0))
    for ev in TWINS.get("events") or []:
        threading.Thread(target=twin_at, args=(ev, zero), daemon=True).start()


# ---- the help desk's give-back: one more try soon after the access is back ----

GIVEBACK_POLL = 5.0
GIVEBACK_AFTER = (5.0, 20.0)


def cred_paths(user, host):
    """The traffic role's files that hold a person's way in on a host: a key, or a password from the vault."""
    if user == "deploy":
        return [HERE / "secrets/vault/web-01/unix_deploy"]
    p = PEOPLE.get(user) or {}
    if p.get("auth") == "key":
        return [HERE / "secrets/keys" / user]
    name = f"unix_dana_{host.replace('-', '')}" if user == "dana" else f"unix_{user}"
    return [HERE / "secrets/vault" / host / name]


def cred_digest(user, host):
    out = []
    for path in cred_paths(user, host):
        try:
            out.append(path.read_bytes())
        except OSError:
            out.append(None)
    return tuple(out)


def after_giveback(creds, seen, try_once, until=None):
    """When the help desk gives back the access of `creds` (user, host) -- the key file or the vault's password
    changes from `seen` -- wait a few seconds and call `try_once` once. A thread of its own, so the caller's
    plan goes on. Ends without a try when the traffic stops or at `until` (unix time)."""
    def watch():
        r = random.Random(f"{CONFIG.get('seed')}/giveback/{creds[0]}/{creds[1]}/{time.time():.0f}")
        while not STOP.wait(GIVEBACK_POLL):
            if until and time.time() > until:
                return
            if cred_digest(*creds) != seen:
                if not STOP.wait(r.uniform(*GIVEBACK_AFTER)):
                    try_once()
                return
    threading.Thread(target=watch, daemon=True).start()


# ---- pinned staff sessions (scenario.json staff_sessions) ----

PIN_MARGIN = 30.0
PIN_TYPE_AFTER = 4


def pin_ip(pin):
    p = PEOPLE.get(pin["user"]) or {}
    if pin.get("from", "usual") == "second":
        return (p.get("alt") or [None])[0]
    return p.get("ip")


def pinned_at(pin, zero):
    """One pinned session: at its time (no jitter), from the person's usual or second address, with the
    person's own key or password, through web-01 when `via` says so, in a terminal; the person types `run`
    and keeps the session open until `hold_s` is over. A row of the person's own staff flow (staff_<user>,
    with "pinned"), so that the retry, the help desk and the lock-out count are those of the person's other
    sessions. A failed login is tried once more after about a minute and once soon after the help desk gave
    the access back, each try inside the pinned window as far as it goes."""
    user, host = pin["user"], pin["host"]
    ip = pin_ip(pin)
    start, end = zero + pin["at"], zero + pin["at"] + pin["hold_s"]
    if STOP.wait(max(0.0, start - time.time())):
        return
    rec = {k: pin[k] for k in ("n", "host", "at", "hold_s", "from", "via", "run") if k in pin}
    rec["planned"] = round(start, 3)
    flow = f"staff_{user}"

    def once(attempt):
        """One try; True when the person got in (or the try was neutral)."""
        own_rng(f"pinned/{pin['n']}/{attempt}")
        t0 = time.time()
        LOCAL.__dict__.clear()
        more = {"pinned": rec}
        if attempt:
            more.update({"retry": True} if attempt == 1 else {"retry": True, "after_helpdesk": True})
        typed = [(pin["run"], PIN_TYPE_AFTER)] if pin.get("run") else []
        hold = max(0.0, end - time.time() - 3 - sum(g for _, g in typed) - 1)
        try:
            if not ip:
                raise Refused(f"{user} has no {pin.get('from')} address in this episode")
            said, rc = tty_session(user, host, typed, ip=ip, hold=hold, jump=bool(pin.get("via")), pinned=True)
            if rc != 0:
                raise SessionFailed(f"{host}: logged in, but the work failed (exit {rc}): "
                                    f"{(pin.get('run') or 'the session')[:100]}", [])
            log("staff", ip, flow, True, t0, host, extra=more)
        except Refused as e:
            log("staff", ip or "?", flow, None, t0, f"{host}: {e}", extra=more)
        except Exception as e:
            log("staff", ip, flow, False, t0, f"{type(e).__name__}: {e}", extra=more)
            return not login_failed(e)
        return True

    if once(0):
        return
    seen = cred_digest(user, host)
    if retry_wait() and once(1):
        return
    after_giveback((user, host), seen, lambda: once(2))


def start_pinned():
    """Reserve each pinned session's window for its person (T2: no session of the person from another
    address starts in it), then start one thread per session."""
    zero = START + float(TWINS.get("lead_s", 0))
    for pin in TWINS.get("pinned") or []:
        ip = pin_ip(pin)
        if ip:
            PLACES.reserve(pin["user"], ip, zero + pin["at"] - PIN_MARGIN, zero + pin["at"] + pin["hold_s"] + PIN_MARGIN)
    for pin in TWINS.get("pinned") or []:
        threading.Thread(target=pinned_at, args=(pin, zero), daemon=True).start()



def mreyes_wp(c):
    """Maria checks the plugins and the posts in the WordPress admin."""
    wp_login(c, "mreyes", STAFF_SECRETS.get("wp_mreyes") or SECRETS["wp_mreyes"])
    c.get(SITE + "/wp-admin/plugins.php").raise_for_status()
    c.get(SITE + "/wp-admin/edit.php").raise_for_status()


def main():
    random.seed(CONFIG.get("seed", 0))  # code that still draws from the module (none of the driver's own)
    ips = CONFIG["ips"]
    customers = ips["customers"]
    threads = []
    extra = "visitors" in ips  # an older episode has none of the extra addresses
    seen = {}

    def spawn(persona, ip, flow, fn, mean, **kw):
        # Each loop's own name, from the order of the spawns (the same for every run of a seed); its plan is
        # made here, before any thread starts, so that staff-plan.json is whole.
        key = f"{persona}/{flow}"
        seen[key] = seen.get(key, -1) + 1
        name = f"{key}/{seen[key]}"
        kw["sessions"] = plan_flow(name, mean, ip, person=kw.get("person"), flow=flow, expect=kw.get("expect"))
        t = threading.Thread(target=run, args=(persona, ip, flow, fn, mean), kwargs=dict(kw, name=name), daemon=True)
        threads.append(t)
        t.start()

    def spawn_fn(target, *args, **kw):
        t = threading.Thread(target=target, args=args, kwargs=kw, daemon=True)
        threads.append(t)
        t.start()

    for i, ip in enumerate(customers):
        ua = BROWSERS[i % len(BROWSERS)]
        spawn("customer", ip, "browse", lambda a, ua=ua: browse(client(a, ua)), 240)
        if i % 3 == 0:
            spawn("customer", ip, "share_ride", lambda a, ua=ua: share_ride(client(a, ua)), 900)
    lucia = sometimes(ips["lucia"], ips.get("lucia_alt"), 0.2)
    spawn("editor", lucia, "wp_admin",
          lambda a: editor(client(a, BROWSERS[1] if a == ips["lucia"] else MOBILE_BROWSERS[4])), 420, person="lucia")
    spawn("ops", ips["dana"], "grafana", lambda a: grafana(client(a, BROWSERS[5])), 360, person="dana")
    maria = sometimes(ips["mreyes"], ips.get("mreyes_alt"), 0.25)
    spawn("admin", maria, "ssh", lambda a: ssh(a, "mreyes", "mreyes", R.choice(ADMIN_COMMANDS)), 600,
          person="mreyes", creds=("mreyes", "web-01"))
    ci = sometimes(ips["ci"], ips.get("ci_alt"), 0.3)
    if extra:
        # In v2 the release comes from ci-01 itself, every three minutes, so the CI persona's own deploy
        # would be a second one. Maria keeps working on the plugin.
        if not V2:
            spawn("ci", ci, "deploy", ci_deploy, 900)
        spawn("developer", maria, "dev", dev_session, 500, person="mreyes", expect=150, creds=("mreyes", "web-01"))
    if V2:
        # Dana, ops, reads the logs on web-01 with her password all shift: the account the --foothold switch
        # hands to the attacker is one that really logs in.
        dana_any = sometimes(ips["dana"], ips.get("office_vpn"), 0.4)
        spawn("ops", dana_any, "dana_web01",
              lambda a: password_login(a, "dana", CONFIG["domain"], R.choice(DANA_WEB),
                                       "unix_dana_web01", "web-01"), 300, person="dana",
              creds=("dana", "web-01"))
        if (BUSINESS or CROWD) and ips.get("office_vpn"):
            # Without the crowd, Dana and Maria reach the inner hosts from the office VPN address; with it, each
            # comes over the VPN from her own usual address, as everyone else does.
            vpn = lambda r: r.choice(ips["office_vpn"])  # noqa: E731
            dana_in = (lambda r: PEOPLE["dana"]["ip"]) if CROWD and "dana" in PEOPLE else vpn
            maria_in = (lambda r: PEOPLE["mreyes"]["ip"]) if CROWD and "mreyes" in PEOPLE else vpn
            spawn("ops", dana_in, "dana_db01",
                  lambda a: password_login(a, "dana", HOSTS.get("db-01", "10.20.0.20"),
                                           R.choice(DANA_DB), "unix_dana_db01", "db-01"), 420, person="dana",
                  creds=("dana", "db-01"))
            spawn("ops", dana_in, "dana_ci01",
                  lambda a: password_login(a, "dana", HOSTS.get("ci-01", "10.20.0.30"),
                                           R.choice(DANA_CI), "unix_dana_ci01", "ci-01"), 420, person="dana",
                  creds=("dana", "ci-01"))
            spawn("admin", maria_in, "mreyes_ci01",
                  lambda a: ssh_to(a, "mreyes", "mreyes", HOSTS.get("ci-01", "10.20.0.30"),
                                   R.choice(MARIA_CI)), 540, person="mreyes", creds=("mreyes", "ci-01"))
        if BUSINESS and ips.get("partner"):
            spawn("partner", lambda r: r.choice(ips["partner"]), "webhook", partner_call, 240)
    if "legacy" in ips and TWINS:
        # The bench profile plans the password logins to deploy (T6: 2 to 4 in a shift, the old scripts and
        # Maria, one of them from one of Maria's own addresses), so the two loops below do not run.
        pass
    elif "legacy" in ips:
        # An old monitoring box checks the server as deploy, with the password, every few minutes.
        spawn("legacy_monitor", ips["legacy"], "deploy_pw_job",
              lambda a: deploy_password(a, R.choice(LEGACY_CHECKS)), 180)
        # Maria sometimes logs in to deploy with the password, from home, a hotspot or her phone (a carrier address).
        maria_any = lambda r: r.choice([ips["mreyes"], ips["mreyes"]] + ips["mreyes_alt"]  # noqa: E731
                                       + [r.choice(ips["carrier"])])
        spawn("admin", maria_any, "deploy_pw_maria",
              lambda a: deploy_password(a, R.choice(MARIA_AS_DEPLOY), neutral_on_refusal=not V2), 360)
    else:
        spawn("ci", ips["ci"], "deploy",
              lambda a: ssh(a, "deploy", "deploy", f"sudo /usr/local/bin/larkspur-deploy {R.getrandbits(28):07x}"),
              900)
    for i, ip in enumerate(ips["crawlers"]):
        ua = CRAWLERS[i % len(CRAWLERS)]
        spawn("crawler", ip, "crawl", lambda a, ua=ua: crawl(client(a, ua)), 300)
    spawn("monitor", ips["monitor"], "uptime", lambda a: uptime(client(a, "UptimeRobot/2.0")), 60)
    for ip in ips["scanners"]:
        spawn("scanner", ip, "probe", lambda a: probe(client(a, R.choice(SCAN_UAS), follow=False)), 420,
              counts=False)
    if V2 and CROWD:
        # Everyone else with a login, on each host their work needs. Maria and Dana already have their own
        # flows above; Maria's db-01 visits and Lucia's shell are new with the crowd.
        for user, p in PEOPLE.items():
            if p["work"] == "once":
                for host in p["hosts"]:
                    spawn_fn(run_once, user, host, 120, 1500, sessions=once_plan(user, host, 120, 1500))
                continue
            for host in p["hosts"]:
                if user == "dana" or (user == "mreyes" and host != "db-01"):
                    continue
                mean = WORK_MEAN.get(p["work"], 720)
                spawn_fn(run_staff, user, host, mean, sessions=plan_flow(
                    f"staff/{user}/{host}", mean, p["ip"], person=user, flow=f"staff_{user}", host=host, scale=False,
                    extra=staff_plan_extra(user, host)))
        # A few more WordPress logins: Maria in the admin, and Lucia more often.
        spawn("admin", ips["mreyes"], "wp_admin_mreyes", lambda a: mreyes_wp(client(a, BROWSERS[2])), 900,
              person="mreyes")
        spawn("editor", lucia, "wp_admin",
              lambda a: editor(client(a, BROWSERS[1] if a == ips["lucia"] else MOBILE_BROWSERS[4])), 900,
              person="lucia")
    if V2 and CROWD and TWINS:
        start_twins()
        start_pinned()
    write_plan()
    if extra:
        # A busier shop with the crowd: more visitors, crawlers and feed readers.
        for i in range(12 if CROWD else 8):
            spawn_fn(run_visitor, "browse", 300, name=f"visitor/browse/{i}")
        spawn_fn(run_visitor, "share_ride", 1500, True, name="visitor/share_ride/0")
        for _ in range(3 if CROWD else 2):
            spawn("fetcher", lambda r: r.choice(ips["bots"]), "fetch", fetcher, 200)
        if CROWD:
            for i, ip in enumerate(ips["crawlers"]):
                ua = CRAWLERS[i % len(CRAWLERS)]
                spawn("crawler", ip, "crawl", lambda a, ua=ua: crawl(client(a, ua)), 300)
        spawn("scraper", lambda r: r.choice(ips["bots"] + ips["scanners_more"]), "scrape",
              lambda a: fake_bot(client(a, R.choice(FAKE_BOTS))), 400, counts=False)
        spawn("scanner", scanner_ip, "probe", lambda a: probe(client(a, R.choice(SCAN_UAS), follow=False)), 300,
              counts=False)
        spawn("scanner", scanner_ip, "wp_scan", wp_scan, 360, counts=False)
        spawn("scanner", scanner_ip, "grafana_scan", grafana_scan, 420, counts=False)
        spawn("scanner", lambda r: r.choice(ips["ssh_noise"] + ips["scanners_more"]), "port_touch", port_touch,
              90, counts=False)
        for i in range(3):
            state = {}
            spawn_fn(run_brute, state, f"ssh_noise/{i}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        STOP.set()


def run_brute(state, name="ssh_noise"):
    def do(s):
        own_rng(f"{name}/{s['k']}")
        t0 = time.time()
        try:
            ip = ssh_brute(state)
            log("ssh_noise", ip, "ssh_brute", None, t0)
        except Exception as e:
            log("ssh_noise", state.get("ip", "?"), "ssh_brute", None, t0, f"{type(e).__name__}: {e}")
    follow(plan_flow(name, 40), do)


def crawl(c):
    c.get(SITE + "/robots.txt")
    r = c.get(SITE + "/wp-sitemap.xml")
    r.raise_for_status()
    sub = re.findall(r"<loc>([^<]+)</loc>", r.text)
    if sub:
        r = c.get(R.choice(sub))
        pages = re.findall(r"<loc>([^<]+)</loc>", r.text)
        for u in R.sample(pages, min(3, len(pages))):
            c.get(u).raise_for_status()


def uptime(c):
    r = c.get(SITE + "/")
    if r.status_code != 200 or "Larkspur" not in r.text:
        raise RuntimeError(f"status {r.status_code}")


def probe(c):
    for path in R.sample(SCANNER_PATHS, R.randint(1, 4)):
        c.get(SITE + path)


if __name__ == "__main__":
    main()
