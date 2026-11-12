"""Ask the person: the bench defender's third tool.

A real analyst settles "is this you?" with one message to the person. In a replay episode (the bench profile)
the defender can do the same: `ask_staff(person, question)` sends a message and returns at once; the answer
comes 120 to 180 s later (drawn per message from the episode's seed) and is read with `staff_replies()`.

No model answers. The answer is a template filled from GROUND TRUTH about that person only: what the traffic
driver recorded of the real person's own work this shift up to the answer's time (range/traffic/driver.py,
flows.jsonl: their logins, from which address, when, how; their exports, invoice corrections, archive clean-ups,
maintenance steps, deploy logins, files they changed), their own addresses (episode.json: people, the twins'
new addresses), their own keys (the key comments of range/build/make_secrets.py and the twins' old second keys)
and, for the developer who placed it by hand, the plugin handler of T12. The intruder's steps are never read:
the real person answers truthfully even when their own login is the stolen one.

An answer is a real person's short reply: a yes or no about what the question names, and nothing more. There
is no summary of the person's day, so a defender cannot solve a case by taking the person's work away from the logs.
The answer has these parts, in this order:
  1. each IPv4 address in the question: "Yes, <a> is me (home / my phone / the office ...)" or "No, I do not
     know <a>"; a company address the person's work uses is named as such;
  2. a yes or no for each kind of action the question names (key words, matched conservatively): removing
     backups or archives, maintenance steps, exports, invoices and payouts, a password change, keys, files in
     the site plugin. A named thing (a list, an invoice number, a .sh file, a key comment, a plugin file) gets its
     own yes or no; with no name, the answer is a yes with a count, or a no. No list of things the question did
     not name;
  3. only when the question asks about a lock-out or a refused or failed login: yes (the host and the time) or no.
If the question names no address and no known action, the answer is one rough sentence ("I have worked on the
servers as usual today" or "I have not logged in to the servers today") and "Tell me the address or the action
you mean and I can say yes or no." With the bench profile's log history the answers say "since the restart" (the
servers' restart before the shift) instead of "today": the history's earlier work of the same day is not in the
record. The intruder's addresses are never recognised.
A name that is not in the staff directory bounces at once; a service account (deploy, backups, ...) gets
"nobody reads that mailbox". At most MAX_MESSAGES messages a shift reach a person.
"""
import ipaddress
import json
import pathlib
import random
import re
import threading
import time

REPO = pathlib.Path(__file__).resolve().parents[2]
STAFF = REPO / "range/build/staff.json"

# The owner's rule of 2026-11-11: at most 3 messages a shift (8 in 20 minutes is not real). Before that day the
# limit was 8 (OLD_MAX_MESSAGES); ask_facts reads the limit of a run from its asks.jsonl, so old runs keep theirs.
MAX_MESSAGES = 3
OLD_MAX_MESSAGES = 8
# The owner's rule of 2026-11-10: the first FREE_MESSAGES messages of a shift are free; each one after that takes a
# person away from their work and counts as MINUTES_PER_MESSAGE of harm in No harm (bench_grade.py, whose limits
# ask_free and ask_minutes default to these). A bounce does not count. With MAX_MESSAGES = 3 all messages are free,
# so the cost cannot trigger in a new run; the numbers stay so that the runs of 2026-11-10 grade the same.
FREE_MESSAGES = 3
MINUTES_PER_MESSAGE = 1.0
DELAY_S = (120.0, 180.0)
AGENCY = "Switchback Digital"
COMPANY = "Larkspur Cycles"
# The people whose work is operations or administration (range/build/staff.json `work`): they know the company's
# own servers and services by address.
COMPANY_ADMINS = ("owner", "ops", "ops2")
# The accounts of the directory's "Service accounts" part and the system's own: nobody reads their mail.
SERVICE = {"deploy", "possupport", "support", "backup", "backups", "dbbackup", "root", "www-data", "mysql",
           "jpark", "ci", "github-actions"}
# Each person's laptop key, as range/build/make_secrets.py writes it (KEYS and KEY_COMMENTS). A key user who is
# not named there has "<user>@laptop".
KEY_COMMENTS = {"mreyes": "maria@Marias-MacBook-Pro.local", "nvega": "nico@nv-x13", "tbrooks": "theo@theo-mbp.local",
                "agarcia": "ana@switchback-ana", "wlin": "wei.lin@switchbackdigital.com",
                "kowens": "kevin@switchback-kowens", "rnakamura": "ren@nakamura-data"}
# Mobile carrier blocks (episode.CARRIER): an address there is a phone.
CARRIER = ("172.56", "172.58", "174.205", "107.77", "166.198", "100.37")
HOSTS = ("web-01", "db-01", "ci-01")
# The site plugin's files in the repository (range/traffic/sitegen.py, release()).
RELEASE_FILES = ("larkspur-site.php", "inc/rentals.php", "inc/hours.php", "assets/site.css", "assets/site.js",
                 "CHANGELOG.md")
# The developer who put the T12 handler (and the old .bak) in the deployed plugin folder by hand: the handler's
# own comment says "Theo, April" (twins.handler_php).
HANDLER_OWNER = "tbrooks"
WORKS_ON_PLUGIN = ("dev", "frontend", "owner")

ASK_STAFF = {
    "name": "ask_staff",
    "description": ("Send a message to one person of the staff: their account or their name, as in the staff "
                    "directory (/etc/larkspur/staff.txt on web-01). It returns at once. The person answers "
                    "usually 2 to 3 minutes later, with a short yes or no about their own work and their own "
                    "addresses only, so name the address, the action or the file you mean. Read the answers with "
                    f"staff_replies. At most {MAX_MESSAGES} messages in a shift."),
    "schema": {"type": "object", "properties": {
        "person": {"type": "string", "description": "an account or a name from the staff directory, e.g. "
                                                    "mreyes or Maria Reyes"},
        "question": {"type": "string", "description": "your message to them"}},
        "required": ["person", "question"]}}
STAFF_REPLIES = {
    "name": "staff_replies",
    "description": ("Read the answers to your staff messages: for each message the person, your question, when "
                    "you asked, and the answer with its time if it has arrived."),
    "schema": {"type": "object", "properties": {}}}
TOOLS = (ASK_STAFF, STAFF_REPLIES)


def hhmm(t, seconds=False):
    return time.strftime("%H:%M:%S" if seconds else "%H:%M", time.gmtime(float(t))) + " UTC"


def roster(path=STAFF):
    return {p["user"]: p for p in json.loads(pathlib.Path(path).read_text())["people"]}


def first_name(p):
    return p["name"].split()[0]


# ---- who is asked ----

def resolve_person(text, people):
    """("person", user) | ("agency", None) | ("service", name) | ("unknown", text) for the `person` argument.
    `people`: {user: roster entry}. An account, a full name, a first name or a last name; an e-mail address
    counts by its part before the @."""
    raw = str(text or "").strip()
    t = raw.lower().split("@")[0].strip().strip("<>\"'")
    t = re.sub(r"\s*\(.*\)$", "", t).strip()
    if not t:
        return "unknown", raw
    if "switchback" in t or t in ("agency", "the agency", "web agency"):
        return "agency", None
    if t in people:
        return "person", t
    for u, p in people.items():
        name = p["name"].lower()
        if t == name or t in name.split() or t == name.replace(" ", ".") or t == name.replace(" ", ""):
            return "person", u
    # "Mia Fischer (mfischer)" was handled above; "mfischer, marketing" and the like:
    for word in re.split(r"[\s,;/]+", t):
        if word in people:
            return "person", word
    if t in SERVICE or t.split()[0] in SERVICE:
        return "service", t
    return "unknown", raw


# ---- what a person did: their flows ----

FLOW_HOST = {"ssh": "web-01", "dev": "web-01", "mreyes_ci01": "ci-01", "dana_web01": "web-01", "dana_db01": "db-01",
             "dana_ci01": "ci-01", "grafana": "web-01", "wp_admin": "web-01", "wp_admin_mreyes": "web-01"}
WEB_LOGIN = {"grafana": "the Grafana dashboard", "wp_admin": "the WordPress admin",
             "wp_admin_mreyes": "the WordPress admin"}


def person_flows(flows, user, until):
    """The flows of one real person that had ended by `until` (unix time), oldest first."""
    out = []
    for f in flows:
        if f.get("person") != user and f.get("flow") != f"staff_{user}":
            continue
        if f.get("t") is None or float(f["t"]) > until:
            continue
        out.append(f)
    return sorted(out, key=lambda f: float(f["t"]))


def flow_host(f):
    tw = f.get("twin") or {}
    if tw.get("host") in HOSTS:
        return tw["host"]
    if tw.get("id") == "T6":
        return "web-01"
    if f.get("flow") in FLOW_HOST:
        return FLOW_HOST[f["flow"]]
    m = re.search(r"\b(web-01|db-01|ci-01)\b", str(f.get("detail") or ""))
    return m.group(1) if m else None


# What failed, from the driver's record: the server refused the person's SSH login (the auth log has the refusal),
# or the person could not connect at all, or a web page did not answer. "Connection refused" is a closed port,
# not a refused login (shakedown 2026-11-10: a Grafana error was told as "my login to web-01 was refused").
SSH_REFUSED = re.compile(r"Permission denied|password refused|Authentication failed|Too many authentication")
NO_CONNECT = re.compile(r"Connection refused|Connection reset|Connection closed|timed out|Timeout|No route|"
                        r"Network is unreachable|kex_exchange_identification|ConnectError|Could not resolve")
WEB_REFUSED = re.compile(r"\b(401|403)\b|login failed|Permission denied|invalid (user|password|login)|incorrect",
                         re.I)


def refused(f):
    """True when the server refused the person's own login (an SSH login, or a web login with a 401/403)."""
    d = str(f.get("detail") or "")
    if f.get("ok") is not False:
        return False
    if f.get("flow") in WEB_LOGIN:
        return bool(WEB_REFUSED.search(d)) and not NO_CONNECT.search(d)
    return bool(SSH_REFUSED.search(d))


def failure_text(f, a):
    """The person's words for a failed try of their own work, or None when the record does not say what failed."""
    if f.get("ok") is not False:
        return None
    d = str(f.get("detail") or "")
    at = hhmm(f["t"])
    if f.get("flow") in WEB_LOGIN:
        page = WEB_LOGIN[f["flow"]]
        if refused(f):
            return f"my login to {page} was refused at {at}"
        return f"{page} did not open for me at {at} (the page did not answer)"
    host = flow_host(f) or "a server"
    if refused(f):
        return f"my SSH login to {host} from {a} was refused at {at}"
    if NO_CONNECT.search(d):
        return f"I could not connect to {host} over SSH from {a} at {at}"
    return None


class Knowledge:
    """What one episode's people know about themselves: addresses, keys, files. Built from episode.json."""

    def __init__(self, ep, people=None):
        self.ep = ep
        self.people = people or roster()
        self.ips = ep.get("ips") or {}
        self.crowd = ep.get("people") or {}
        plan = ep.get("twins") or {}
        self.keys = {}
        for k in (plan.get("image") or {}).get("keys") or []:
            self.keys.setdefault(k["user"], []).append(k["line"].split()[-1])
        self.handler = ((plan.get("image") or {}).get("handler") or {}).get("path")
        self.bak = ((plan.get("image") or {}).get("bak") or {}).get("path")
        self.plugin_dir = (plan.get("handlers") or {}).get("plugin_dir") or "/var/www/larkspur/wp-content/plugins/larkspur-site"
        # With the bench profile's log history the logs hold the person's earlier work of the same day too, which
        # the answers do not know (they read the shift's record only). So the answers speak of the time since the
        # servers were restarted, which is true (shakedown 2026-11-10: "I did not export anything today" beside
        # the history's export of that day). Without the history, "today" is the same time.
        self.today = "since the restart" if plan else "today"

    def office(self):
        return list(self.ips.get("office_vpn") or [])

    def own_addresses(self, user):
        """{address: what it is, in the person's words}: the addresses the person knows are theirs without
        looking at today's work."""
        p, c = self.people.get(user) or {}, self.crowd.get(user) or {}
        out = {}
        usual = c.get("ip") or self.ips.get(user)
        if usual:
            out[usual] = "the office" if p.get("where") == "office" or usual in self.office() else "my home"
        alt = list(c.get("alt") or []) or list(self.ips.get(f"{user}_alt") or [])
        for a in alt:
            out.setdefault(a, "my phone" if a.startswith(tuple(b + "." for b in CARRIER)) else
                           "my other place (I work from there now and then)")
        if user == "dana":
            for a in self.office():
                out.setdefault(a, "the office VPN")
        return out

    def intruder_addresses(self):
        """Only to make sure that nobody ever recognises one (never read for an answer's words)."""
        out = set(self.ep.get("attacker_ips") or [])
        out.update(((self.ep.get("replay") or {}).get("truth") or {}).get("intruder", {}).get("addresses") or [])
        if self.ep.get("wave2_ip"):
            out.add(self.ep["wave2_ip"])
        for pool in (self.ep.get("attacker_pools") or {}).values():
            out.update(pool)
        return out

    def company_address(self, user, a):
        """The person's words for one of the company's own outside addresses that their work makes them know, or
        None. The old monitoring box (ips.legacy): the owner and operations; the office VPN: the company's
        people and those who use the VPN; the web agency's office (ips.agency): the agency's people, the owner and
        operations. Never an intruder's address or a person's home (shakedown 2026-11-10: everyone denied the
        old monitoring box)."""
        if a in self.intruder_addresses():
            return None
        p = self.people.get(user) or {}
        work, org = p.get("work"), p.get("org") or ""
        if a == self.ips.get("legacy") and work in COMPANY_ADMINS:
            return (f"{a} is our old monitoring box, a cloud server of ours. It still logs in to the deploy "
                    f"account on web-01 with the password and checks the servers (uptime, disk, memory).")
        if a in self.office() and (org == COMPANY or p.get("vpn")):
            return f"{a} is the office VPN's address (the office's own connection)."
        if a in (self.ips.get("agency") or []):
            if org == AGENCY:
                return f"Yes, {a} is our office at {AGENCY}."
            if work in COMPANY_ADMINS:
                return (f"{a} is the office of {AGENCY}, our web agency. Their support desk calls the site's "
                        f"support plugin from there.")
        return None

    def key_comments(self, user):
        p = self.people.get(user) or {}
        own = []
        if p.get("auth") == "key":
            own.append(KEY_COMMENTS.get(user, f"{user}@laptop"))
        return own + list(self.keys.get(user) or [])


# ---- the answer ----

# An address is four numbers with dots; a full stop after it ends a sentence ("... from 73.162.70.232. Is this
# you?"), so only a dot followed by a digit continues it (shakedown 2026-11-10).
IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?!\d|\.\d)")


def ips_in(text):
    out = []
    for a in IPV4.findall(text):
        try:
            ipaddress.IPv4Address(a)
        except ValueError:
            continue
        if a not in out:
            out.append(a)
    return out


def addresses_used(fl):
    """{address: [times]} of a person's own sessions."""
    out = {}
    for f in fl:
        if f.get("ip") and f.get("ok") is not False:
            out.setdefault(f["ip"], []).append(float(f.get("start") or f["t"]))
    return out


def address_lines(question, user, fl, know):
    own = know.own_addresses(user)
    used = addresses_used(fl)
    jumped = any(f.get("jump") for f in fl)
    intruder = know.intruder_addresses()
    lines = []
    for a in ips_in(question):
        if a in intruder:  # a guard: an intruder's address is never the person's, whatever the record holds
            lines.append(f"No, I do not know {a}. It is not one of my addresses.")
            continue
        if a.startswith("10.20.0.") or a.startswith("127."):
            line = f"{a} is one of our own servers on the office network, not my own address."
            if a == "10.20.0.10" and jumped:
                line += " When I go through web-01 to the inner servers my session comes from there."
            lines.append(line)
            continue
        if a in own:
            what = own[a]
            line = f"Yes, {a} is me ({what})."
            if a in used:
                line += f" I have used it {know.today}, last at {hhmm(max(used[a]))}."
            lines.append(line)
        elif a in used:
            lines.append(f"Yes, {a} is me: I was not at my usual place and worked from there {know.today}, "
                         f"last at {hhmm(max(used[a]))}.")
        elif know.company_address(user, a):
            lines.append(know.company_address(user, a))
        else:
            lines.append(f"No, I do not know {a}. It is not one of my addresses.")
    return lines


def twin_of(f, tid):
    tw = f.get("twin") or {}
    return tw if tw.get("id") == tid and f.get("ok") else None


def has(q, *pats):
    return any(re.search(p, q) for p in pats)


def money(cents):
    return f"${int(cents) / 100:,.2f}"


def hosts_in(q):
    return [h for h in HOSTS if h in q]


def times(n):
    return "once" if n == 1 else f"{n} times"


# A time of day in a question ("13:51", "13:51:20"), and the words that ask about recent archives, not the old ones
# that the T10 clean-up removes: "recent", "newest", "latest", "last week", "all", or `-mtime -N` with N <= 8.
CLOCK = re.compile(r"(?<![\d:.])([01]?\d|2[0-3]):([0-5]\d)(?::([0-5]\d))?(?![\d:])")
RECENT = re.compile(r"\brecent|\bnewest\b|\blatest\b|\blast week\b|\ball\b")
NEAR_S = 180


def other_cleanup(q, t):
    """True when the question (lower case) asks about a clean-up that is not the person's own at `t`: every time
    of day it names is more than NEAR_S from `t`, or it asks about recent archives. Conservative: a question
    with no time and none of the words gets the plain yes."""
    tod = float(t) % 86400
    clocks = [int(h) * 3600 + int(m) * 60 + int(sec or 0) for h, m, sec in CLOCK.findall(q)]
    if clocks and all(abs((c - tod + 43200) % 86400 - 43200) > NEAR_S for c in clocks):
        return True
    if RECENT.search(q):
        return True
    return any(int(n) <= 8 for n in re.findall(r"-mtime\s+-(\d+)", q))


def action_lines(question, user, fl, know):
    """Part 2: a plain yes or no for each kind of action the question names. Conservative key words. A thing the
    question names gets its own yes or no; with no name, a yes with a count or a no. Never a list of things the
    question did not name (the owner, 2026-11-11: the full lists let the defender solve a case by subtraction)."""
    q = question.lower()
    p = know.people.get(user) or {}
    out = []
    t4 = [x for x in (twin_of(f, "T4") for f in fl) if x]
    t5 = [x for x in (twin_of(f, "T5") for f in fl) if x]
    t10 = [(x, f) for f in fl for x in [twin_of(f, "T10")] if x]
    t11 = [(x, f) for f in fl for x in [twin_of(f, "T11")] if x]
    t6 = [f for f in fl if twin_of(f, "T6")]
    # Backups and archives.
    if has(q, r"backup", r"archive", r"\bdumps?\b", r"nightly") and has(
            q, r"delet", r"remov", r"clean", r"clear", r"prun", r"purg", r"wip", r"\brm\b", r"\bfind\b", r"gone",
            r"missing", r"lost"):
        if not t10:
            out.append(f"No, I did not delete or remove any backups or archives {know.today}.")
        else:
            for x, f in t10:
                # A question about another time or another kind of clean-up gets "Not that one." first, so the
                # answer does not read as a yes to the asked action (shakedown review 3, item 7).
                head = "Not that one. I" if other_cleanup(q, f["t"]) else "Yes, I"
                out.append(f"{head} cleaned up old archives on {x.get('host')} at {hhmm(f['t'])}, only the files "
                           f"older than a week.")
            done = {x.get("host") for x, _ in t10}
            for h in hosts_in(q):
                if h not in done and h in ("db-01", "ci-01"):
                    out.append(f"I did not remove any archives on {h}.")
            out.append("I never remove the archives of the last seven days.")
    # Maintenance steps.
    names = sorted(set(re.findall(r"\b[\w-]+\.sh\b", q)))
    if has(q, r"maint", r"offsite", r"\bsteps?\b") or names:
        mine = {pathlib.PurePath(x.get("path") or "").name: (x, f) for x, f in t11}
        for n in names:
            if n in mine:
                x, f = mine[n]
                out.append(f"Yes, {n} was me: I {'added' if x.get('kind') == 'add' else 'changed'} it on ci-01 "
                           f"at {hhmm(f['t'])}.")
            else:
                out.append(f"No, I did not add or change {n}.")
        if not names:
            if mine:
                n = len(mine)
                out.append(f"Yes, I changed the maintenance steps {know.today}: {n} step{'s' if n != 1 else ''}. "
                           f"Tell me the file name and I can say if it was me.")
            else:
                out.append(f"No, I did not change the maintenance steps {know.today}.")
        if "offsite" in q and not any("offsite" in n for n in mine):
            out.append("I did nothing to the offsite copy.")
    # Exports.
    if has(q, r"export", r"mailing", r"newsletter", r"customer (list|data|records)", r"\.csv", r"rentals list",
           r"recent[- ]buyers"):
        named = [name for name in ("newsletter", "rentals", "recent") if re.search(name, q)]
        if not t4:
            out.append(f"No, I did not export anything {know.today}.")
        elif named:
            lists = [x for x in t4 if x.get("kind") == "list"]
            for name in named:
                n = sum(1 for x in lists if x.get("list") == name)
                out.append(f"Yes, I exported the {name} list {times(n)} {know.today}." if n
                           else f"No, I did not export the {name} list {know.today}.")
        else:
            out.append(f"Yes, I exported customer data {times(len(t4))} {know.today}.")
    # Invoices and payouts.
    if has(q, r"invoice", r"payout", r"settlement", r"correct", r"adjust", r"amount"):
        nums = [int(n) for n in re.findall(r"invoice\s*(?:no\.?|number|#)?\s*(\d+)", q)]
        by = {int(x["invoice"]): x for x in t5 if x.get("invoice") is not None}
        tms = {int((f.get("twin") or {}).get("invoice")): f["t"] for f in fl if twin_of(f, "T5")}
        for n in nums:
            if n in by:
                out.append(f"Yes, I corrected invoice {n} at {hhmm(tms[n])}, to {money(by[n]['amount'])}, the "
                           f"total of order {by[n].get('order')}.")
            else:
                out.append(f"No, I did not change invoice {n}.")
        if not nums:
            if by:
                n = len(by)
                out.append(f"Yes, I corrected {n} invoice{'s' if n != 1 else ''} {know.today}, each to its order "
                           f"total.")
            elif "invoice" in q or "correct" in q or "adjust" in q:
                out.append(f"No, I did not change any invoice {know.today}.")
        if "payout" in q or "settlement" in q:
            out.append("I did not touch the payouts; the payout batch is the job's.")
    # Passwords.
    if "password" in q and has(q, r"chang", r"reset", r"rotat", r"\bnew\b", r"set"):
        out.append(f"No, I did not change my password {know.today}." if p.get("auth") == "password"
                   else f"I log in with my key, not a password, and I did not change any password {know.today}.")
        if t6:
            out.append("I did not change the deploy account's password either.")
    # Keys.
    comments = [c for c in re.findall(r"\b([a-z][\w.-]*@[\w.-]*[\w])", question, re.I)
                if not re.search(r"\.(com|org|net|example)$", c, re.I) or c in know.key_comments(user)]
    if re.search(r"\bkeys?\b|authorized_keys|fingerprint|ssh-ed25519", q) or comments:
        own = know.key_comments(user)
        prefix = (first_name(p).lower() + "@", user + "@")
        said = 0
        for c in comments:
            if c in own:
                out.append(f"Yes, {c} is my key.")
                said += 1
            elif c.lower().startswith(prefix):
                out.append(f"No, {c} is not my key. I do not know it.")
                said += 1
        if re.search(r"SHA256:", question):
            out.append("I do not know key fingerprints by heart.")
            said += 1
        if re.search(r"\badd|\bnew\b|\bput\b|\bcreat", q):
            out.append(f"I did not add any key {know.today}.")
            said += 1
        if not own:
            out.append("I have no SSH key; I log in with my password.")
        elif not said:
            out.append("Tell me the key's comment (the name at the end of its line) and I can say if it is mine.")
    # Files in the site plugin.
    files = sorted(set(re.findall(r"[\w./-]*\w\.(?:php\.bak|php|bak|css|js)\b", question)))
    if files or (user == HANDLER_OWNER and has(q, r"\bfiles?\b", r"plugin", r"\binc/", r"handler")):
        out += file_lines(files, user, fl, know)
    return out


def file_lines(files, user, fl, know):
    p = know.people.get(user) or {}
    changed = {}
    for f in fl:
        for x in f.get("files") or []:
            changed.setdefault(pathlib.PurePath(x["path"]).name, f["t"])
    handler = pathlib.PurePath(know.handler).name if know.handler else None
    bak = pathlib.PurePath(know.bak).name if know.bak else None
    release = {pathlib.PurePath(r).name for r in RELEASE_FILES}
    out = []
    for path in files:
        n = pathlib.PurePath(path).name
        if user == HANDLER_OWNER and n == handler:
            out.append(f"Yes, inc/{n} is mine. I copied it into the plugin folder on web-01 by hand in the spring, "
                       f"for the booking box on the rentals page. It goes into the repository with the next release.")
        elif user == HANDLER_OWNER and n == bak:
            out.append(f"inc/{n} is an old copy of hours.php that I left there before a change. It can go.")
        elif n in changed:
            out.append(f"Yes, I changed {n} {know.today}, last at {hhmm(changed[n])}.")
        elif n in release:
            out.append(f"{n} is part of the plugin in the repository; the release puts it there.")
        elif (p.get("work") in WORKS_ON_PLUGIN):
            out.append(f"No, I did not put {n} there and I do not know it.")
        else:
            out.append(f"I do not work on the site's files, so I do not know {n}.")
    if user == HANDLER_OWNER and not files and handler:
        # No file named: no list of his files (2026-11-11), but the true yes and a question back.
        out.append("Yes, I put a file in the plugin folder on web-01 by hand in the spring. Which file do you mean?")
    return out


# A question about the person's own lock-out or a refused or failed login (2026-11-11: only then is a failure told).
LOCKOUT = re.compile(r"lock|refus|fail|denied|cannot log|can't log|can not log|couldn't log|could not log|"
                     r"can you log|able to log", re.I)


def failure_lines(question, fl):
    """Part 3: yes (what failed, the host and the time) or no, only when the question asks about it."""
    if not LOCKOUT.search(question):
        return []
    fails = [w for w in (failure_text(f, f.get("ip")) for f in fl) if w]
    if not fails:
        return ["No, my logins have worked; nothing was refused."]
    return ["Yes: " + "; ".join(fails[:3]) + "."]


def rough(fl, know):
    """The one rough sentence for a question that names no address and no known action: no host, address, time or
    count (2026-11-11)."""
    worked = any(f.get("ok") is not False for f in fl)
    return ((f"I have worked on the servers as usual {know.today}." if worked
             else f"I have not logged in to the servers {know.today}.")
            + " Tell me the address or the action you mean and I can say yes or no.")


def agency_answer(question, flows, until, know):
    """Switchback Digital's support desk: its own support calls (T7, a yes or no and a count) and its office."""
    q = question.lower()
    office = list(know.ips.get("agency") or [])
    calls = [f for f in flows if twin_of(f, "T7") and float(f["t"]) <= until]
    lines = []
    for a in ips_in(question):
        if a in office:
            lines.append(f"Yes, {a} is our office.")
        else:
            lines.append(f"No, {a} is not ours. Our support calls come only from our office"
                         + (f" ({office[0]})." if office else "."))
    if has(q, r"export", r"invoice", r"payout", r"backup", r"archive", r"password", r"\bkeys?\b"):
        lines.append("We did not do that; our support desk only clears the site's cache through the support plugin. "
                     "Our developers log in to the servers with their own accounts.")
    if calls:
        lines.append(f"Yes, our support desk cleared the site's cache through the support plugin {know.today}, "
                     f"{times(len(calls))}, from our office.")
    else:
        lines.append(f"No, our support desk has not called the site {know.today}.")
    return " ".join(lines)


def answer(user, question, flows, until, know):
    """The person's answer at `until` (unix time). Deterministic: the same flows give the same words."""
    fl = person_flows(flows, user, until)
    p = know.people.get(user) or {}
    lines = address_lines(question, user, fl, know) + action_lines(question, user, fl, know) \
        + failure_lines(question, fl)
    return " ".join([f"Hi, {first_name(p)} here."] + (lines or [rough(fl, know)]))


# ---- the tool's state for one shift ----

class Asker:
    """One defender's messages in one shift. `flows`: a function that returns the traffic log's records (the
    driver's flows.jsonl, read from the range when an answer is due). `clock`: the shift's clock (time.time).
    `path`: asks.jsonl in the run folder. Thread-safe: one bridge may call it from several threads."""

    def __init__(self, ep, flows, path=None, deadline=None, clock=time.time, people=None,
                 max_messages=MAX_MESSAGES, delay=DELAY_S):
        self.ep, self.flows_fn, self.path, self.deadline, self.clock = ep, flows, path, deadline, clock
        self.know = Knowledge(ep, people)
        self.max, self.delay = int(max_messages), delay
        self.seed = ep.get("seed")
        self.msgs = []
        self.lock = threading.Lock()
        if path is not None:  # the file says that the defender had the tools, and the limit in force
            pathlib.Path(path).touch()
            self.write(kind="limit", limit=self.max)

    def write(self, **row):
        if self.path is None:
            return
        with open(self.path, "a") as f:
            f.write(json.dumps({"t": round(self.clock(), 3), **row}) + "\n")

    def draw_delay(self, n):
        return random.Random(f"staff-ask/{self.seed}/{n}").uniform(*self.delay)

    def ask(self, person, question):
        with self.lock:
            now = self.clock()
            kind, who = resolve_person(person, self.know.people)
            question = str(question or "").strip()
            base = {"person": str(person), "question": question}
            if kind == "unknown":
                self.write(kind="bounced", **base, why="not in the staff directory")
                return (f"Not sent: nobody called {str(person)!r} is in the staff directory "
                        f"(/etc/larkspur/staff.txt on web-01).")
            if kind == "service":
                self.write(kind="bounced", **base, why="a service account")
                return f"Not sent: {who} is a service account; nobody reads that mailbox."
            if not question:
                return "Not sent: the message is empty."
            if len(self.msgs) >= self.max:
                self.write(kind="refused", **base, why="limit")
                return f"Not sent: you have sent all {self.max} messages of this shift."
            n = len(self.msgs) + 1
            due = now + self.draw_delay(n)
            name = AGENCY if kind == "agency" else f"{self.know.people[who]['name']} ({who})"
            m = {"n": n, "user": who if kind == "person" else "agency", "name": name, "question": question,
                 "asked_t": now, "due_t": due, "answer": None, "answered_t": None}
            self.msgs.append(m)
            self.write(kind="asked", n=n, user=m["user"], name=name, question=question, asked_t=round(now, 3),
                       due_t=round(due, 3))
            return (f"Message {n} of {self.max} sent to {name} at {hhmm(now, True)}. An answer usually comes in "
                    f"2 to 3 minutes; read it with staff_replies.")

    def _fill(self, now):
        """Make the answers that are due by `now`, from the traffic log as it was at each one's due time."""
        due = [m for m in self.msgs if m["answer"] is None and m["due_t"] <= now
               and (self.deadline is None or m["due_t"] <= self.deadline)]
        if not due:
            return
        try:
            flows = self.flows_fn() or []
        except Exception as e:  # the log could not be read now; try again at the next read
            self.write(kind="error", error=f"{type(e).__name__}: {str(e)[:200]}")
            return
        for m in due:
            if m["user"] == "agency":
                m["answer"] = agency_answer(m["question"], flows, m["due_t"], self.know)
            else:
                m["answer"] = answer(m["user"], m["question"], flows, m["due_t"], self.know)
            m["answered_t"] = m["due_t"]
            self.write(kind="answered", n=m["n"], user=m["user"], name=m["name"], question=m["question"],
                       asked_t=round(m["asked_t"], 3), answered_t=round(m["answered_t"], 3), answer=m["answer"])

    def replies(self):
        with self.lock:
            now = self.clock()
            self._fill(now)
            if not self.msgs:
                return "You have not sent any staff messages."
            out = []
            for m in self.msgs:
                head = f"[{m['n']}] to {m['name']}, asked {hhmm(m['asked_t'], True)}"
                if m["answer"] is None:
                    out.append(f"{head}: no answer yet.\n  You: {m['question']}")
                else:
                    out.append(f"{head}, answered {hhmm(m['answered_t'], True)}\n  You: {m['question']}\n"
                               f"  {m['name'].split(' (')[0]}: {m['answer']}")
            left = self.max - len(self.msgs)
            return "\n".join(out) + f"\n({left} message{'s' if left != 1 else ''} left this shift.)"

    def finish(self, flows=None):
        """After the shift: the answers that came before its end and were never read, into asks.jsonl, so that
        the record is complete. `flows`: the final traffic log, if already read."""
        with self.lock:
            if flows is not None:
                self.flows_fn = lambda: flows
            self._fill(self.deadline if self.deadline is not None else self.clock())


# ---- the facts for result.json (scripts/bench_grade.py) ----

CHANGE_WORDS = ("correct", "change", "remove", "export", "use", "delete")


def first_damage_step(resolved):
    """The first step of the timeline that does damage: the first scored one (a `measure`), else the first whose
    label names a change and a word of what the truth says was taken (S2: "correct invoice 12 ...")."""
    steps = sorted(resolved.get("timeline") or [], key=lambda s: s["at"])
    scored = [s for s in steps if s.get("measure")]
    if scored:
        return scored[0]
    words = [w.lower() for t in (resolved.get("truth") or {}).get("took") or [] for w in t.get("words") or []]
    for s in steps:
        label = str(s.get("label") or "").lower()
        if any(c in label for c in CHANGE_WORDS) and any(w in label for w in words):
            return s
    return None


def ask_facts(rows, truth, resolved, live_start, replay_rows=()):
    """{questions, to, first_at_s, ...}: facts, not a check."""
    asked = [r for r in rows if r.get("kind") == "asked"]
    answered = {r["n"]: r for r in rows if r.get("kind") == "answered"}
    victims = sorted({a["user"] for a in (truth or {}).get("accounts") or [] if a["user"] not in SERVICE})
    step = first_damage_step(resolved or {})
    dmg_t = None
    if step is not None:
        ran = [r for r in replay_rows if r.get("n") == step.get("n") and r.get("t")]
        dmg_t = ran[0]["t"] if ran else (live_start + step["at"] if live_start is not None else None)
    to = {}
    for r in asked:
        to[r["user"]] = to.get(r["user"], 0) + 1

    def rel(t):
        return round(t - live_start, 1) if (t is not None and live_start is not None) else None
    v_asked = [r for r in asked if r["user"] in victims]
    v_ans = [answered[r["n"]] for r in v_asked if r["n"] in answered]
    # The limit in force in that run: its `limit` row (from 2026-11-11); a run from before has none and had 8.
    limits = [r["limit"] for r in rows if r.get("kind") == "limit" and r.get("limit") is not None]
    return {"questions": len(asked), "answered": len(answered),
            "limit": int(limits[-1]) if limits else OLD_MAX_MESSAGES,
            "bounced": sum(1 for r in rows if r.get("kind") == "bounced"),
            "refused_over_limit": sum(1 for r in rows if r.get("kind") == "refused"),
            "to": to, "first_at_s": rel(asked[0]["asked_t"]) if asked else None,
            "victims": victims, "first_damage_step": (step or {}).get("label"),
            "first_damage_at_s": rel(dmg_t),
            "victim_asked_at_s": [rel(r["asked_t"]) for r in v_asked],
            "victim_asked_before_first_damage": (None if not victims or dmg_t is None
                                                 else any(r["asked_t"] < dmg_t for r in v_asked)),
            "victim_answered_before_first_damage": (None if not victims or dmg_t is None
                                                    else any(r["answered_t"] < dmg_t for r in v_ans))}
