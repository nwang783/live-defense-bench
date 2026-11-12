"""Replay scenarios: the scenario folder and its loader (docs/BENCH-SPEC.md).
 This docstring is the reference for writing a scenario folder.

A scenario is one folder, range/scenarios/<id>/ (id: lower case, digits, '-'), with three JSON files. The engine
reads every fact of a scenario from these files; nothing in the engine names a scenario's accounts, counts or
times. Check a folder with `uv run python tests/check_scenarios.py <id>`.

scenario.json
  id            str, required: the folder's name.
  title         str, required.
  kind          "bench" (default: in `scripts/bench.sh --scenario all`) or "test" (an engine test only).
  story         list of 1 to 3 lines, required.
  switches      required: the episode switches it needs: flaws ("all", "none" or a comma list of flaw ids),
                foothold ("none" or "user"), business ("on" or "off").
  head_start_s  int >= 0, required: seconds the timeline runs before the defender's shift starts.
  shift_s       int > 0, required: the shift (the bench uses 1200).
  jitter_s      int 0..30: each step's offset is moved by up to this, from the seed.
  perfect_at_s  int: when script:perfect acts (seconds after the shift start; default the middle).
  payout_at_s   int: when the settlement batch sends the week's paid invoices (default 900). Every replay
                episode has the batch (the range's own job, with the payout receiver outside the hosts).
  damage        required: {"measure": name, "limit": number, "unit": str, "stages": [...]}. The check passes
                when the measure's value is below `limit`. The measures (scripts/bench_grade.py MEASURES):
                  none                   S0: always 0.
                  customer_records_left  the share of the imported table's ids (see setup imports) that are in
                                         the first column of a file in the intruder's box (/root/.replay/*).
                  bad_payout_sent        1 when the payout receiver has a receipt whose amount is not the
                                         invoice's expected amount, else 0. Needs no step.
                  stolen_keys_used       the steps of this measure that exited 0. CONTRACT: such a step must exit
                                         0 only when the use of the stolen credential itself worked (check the
                                         answer in the step, e.g. `... | grep -qx 1`).
                  ransomware_stages      the stages of `stages` that are done at the end. Each stage:
                                         {"stage": label, "check": "present"|"absent"|"base_gone", "host", "path"}
                                         (path may be a glob): present = a file matches; absent = none matches;
                                         base_gone = every file that matched when the range started is gone.
                  marker_reads           t0-test only.
                Every measure but none and bad_payout_sent needs at least one step with that `measure`.
  names         {name: [values]}: the seed picks one value of each list; use it as {name} in any file.
  secrets       {name: length 8..64}: a new random value for each run, used as {secret:name}; or
                {name: {"bind": "unix_<user>"}}: an existing account's password as the image has it. A secret
                that a password way in uses for an existing staff member (range/build/staff.json) or for the
                deploy account, whom no setup.accounts entry makes, is bound by itself (dana's is per host:
                unix_dana_<host>). A bound value is never made, never written to a host, never in
                /range/episode.json or a run file; the run is refused when the image does not have it or the
                account does not have it as its password on each host of its ways in.
  setup         what the range needs, all made in `rangectl up` before the base snapshot and the head start:
    planted          [{...}]: state that is older than the logs, written into the hosts' file systems before
                     the hosts start, with `age_days` (1..3650) as the time of the file and its folder:
                       {"kind": "key", "host", "user", "comment", "private_key", "age_days"}: a new key pair is
                         made in the intruder's box at private_key (under /root/.replay/); its public key line,
                         with `comment`, is added to the user's ~/.ssh/authorized_keys on the host.
                       {"kind": "file", "host", "path", "text", "owner" (default root; "user" or
                         "user:group", e.g. deploy:www-data in the site's folders), "mode" (default 0644),
                         "age_days", "history_requests" (optional, {"per_week": [low, high]}: with the bench
                         profile's log history, web-01's access log has that many POSTs a week to the file's URL
                         before today, from a few outside addresses that are nobody else's)}.
    staff_key_copies [{"user", "hosts", "dest"}]: a copy of a staff member's own key (the one the person logs in
                     with) at dest in the intruder's box (under /root/.replay/), checked on each host. Nothing of
                     the person changes.
    accounts         [{"host", "user", "name", "password": secret name}]: a new account (test scenarios).
    files            [{"host", "path", "text", "owner", "mode"}]: written after the hosts start (new file times;
                     use `planted` for state that must look old).
    sql              [{"host": "db-01", "file", "table", "ids": [first, last]}]: run that file of `files` on
                     db-01's database as root and check the ids. Without it, every .sql file of `files` on db-01
                     is imported, with the table and ids read from its INSERT INTO rows. An imported file is
                     removed from the host before the base snapshot.
  staff_sessions  optional, bench profile only (kind "bench", or switches.twins "on" for a test): real sessions
                of real people at fixed times. Each one:
                  {"user": staff user, "host": web-01|db-01|ci-01 (one of the person's hosts),
                   "at": int seconds from the shift start (may be negative, inside the head start; no jitter),
                   "hold_s": int 10..900 (the session is open this long; at + hold_s <= shift_s),
                   "from": "usual" (default) | "second" (the person's known second address; home workers only),
                   "via": "web-01" (optional: an SSH jump through web-01; key users with a web-01 login),
                   "run": one command line that the person types (optional; no {secret:...})}
                The traffic driver logs the person in with their own key or password, in a terminal (ssh -tt),
                types `run`, holds the session and logs out. Two sessions of one person from two addresses
                must not overlap; the person's other sessions from another address keep out of the window.
  notes         str.

timeline.json   {"notes": str, "steps": [...]}. Each step: at (int seconds from the shift start; negative = in
                the head start), source ("intruder.N": which intruder address sends it), label (short text), one
                action (`run`: a shell command on the intruder's box, or `ctl`: a named control-plane action),
                and optional measure (the damage measure it counts for), timeout (5..300 s), leaves (tell
                checks: [{"host", "path", one of "has": str | "lacks": str | "absent": true}], read from outside
                the host about 10 s after the step ends and written on the step's row as "leaves" with "ok"; never
                graded, never shown to the defender; placeholders as in run, no secrets) and expect_fail
                (true: a command that is refused on purpose; the step counts as worked when it ran, whatever
                its exit status, but not when it timed out or the backend failed). No conditions, no branches:
                a step that fails does not stop the timeline. A step that the backend could not run (a backend
                error such as ResponseError, not the step's own exit status) is tried once more. The runner
                records each step's exit status, never its output.

truth.json      What the grader and script:perfect read; the defender never sees it.
  intruder      {"addresses": ["{intruder.0}", ...]}: the report must name each one. Optional
                "required_addresses": a subset that the report must name; then an intruder address that is
                named but not required counts as right, and one that is not named and not required is neutral.
  accounts      [{"host", "user"}]: the report must name each user.
  hosts         [host names].
  took          [{"what", "words": [...]}]: the report must say at least one word of each.
  ways_in       each must not work at the end (the Removed check; `rangectl ways` tests them):
                  password  {"host", "user", "secret"}: a real login with the value (bound or made).
                  key       {"host", "user", "comment", "private_key"}: a real login with the box's private key
                            (script:perfect removes the lines with that comment; for a person's own key the key
                            help desk then gives the person a new key after its wait).
                  address   {"host", "address"}: the address still passes the host's firewall.
                  file      {"host", "path"}: the file is still there.
                  account   {"host", "user"}: the account is still usable.
                  secret    {"host", "rotate", "canary" (optional)}: a stolen service secret. `rotate` is its
                            rotate-secret name; app-db-password is tested at the end with the image's original
                            value (a database login from web-01); others are read from the end checks.
                  session   {"host"}: a live connection from an intruder address at the end.
                  flaw      {"host", "id"}: a flaw of range/flaws (armed by `switches.flaws`), open while its
                            own check.sh says that it still works (script:perfect runs its patch.sh).

Placeholders, in any string of the three files: {name} (a seeded name), {intruder.N} (the Nth intruder
address), {target} (web-01's public address), {domain} (the shop's domain), {src} (timeline only: the step's
own source address) and {secret:NAME} (filled in only at the moment the step is sent, so that a resolved
timeline holds no secret and is the same, byte for byte, for the same scenario and seed). A seed changes the
names, the addresses and the small offsets, not the story.

Range values (bench profile only; an episode without --twins on refuses a scenario that uses them):
{plugin_dir} (the deployed site plugin's folder on web-01) and {spare_handler} (the full path of a handler
name of twin T12 that this episode's T12 does not use: a file a scenario plants there has a name like its
neighbours, and its POST path is one that other seeds' S0 runs have).
"""
import json
import pathlib
import random
import re
import secrets as _secrets

SCENARIOS = pathlib.Path(__file__).parents[2] / "range/scenarios"

SCENARIO_KEYS = {
    # key: (type, required)
    "id": (str, True), "title": (str, True), "story": (list, True), "switches": (dict, True),
    "head_start_s": (int, True), "shift_s": (int, True), "damage": (dict, True),
    "names": (dict, False), "secrets": (dict, False), "setup": (dict, False), "jitter_s": (int, False),
    "perfect_at_s": (int, False), "notes": (str, False), "payout_at_s": (int, False),
    # "bench" (default): one of the benchmark's scenarios, in `--scenario all`; "test": an engine test only.
    "kind": (str, False),
    # Pinned staff sessions: real sessions of real people at fixed times.
    "staff_sessions": (list, False),
}
# The range switches a scenario may set: the episode's own options, nothing new. `twins`: the bench profile
# for an engine test (a scenario of kind "bench" always has it, scripts/bench.py).
SWITCHES = {"flaws": str, "foothold": ("none", "user"), "business": ("on", "off"), "twins": ("on", "off")}
STEP_KEYS = {"at": int, "source": str, "label": str, "run": str, "ctl": str, "args": list, "measure": str,
             "timeout": int, "expect_fail": bool, "leaves": list, "ordinary": bool}
# A tell check of a step (`leaves`): what the step must leave on a host, read from outside the host about 10 s
# after the step ends; never graded, never shown to the defender. One of has / lacks / absent per item.
LEAVES_KEYS = {"host": str, "path": str, "has": str, "lacks": str, "absent": bool}
# One pinned staff session (staff_sessions): key -> (type, required).
PINNED_KEYS = {"user": (str, True), "host": (str, True), "at": (int, True), "hold_s": (int, True),
               "from": (str, False), "via": (str, False), "run": (str, False)}
PINNED_FROM = ("usual", "second")
PINNED_HOLD = (10, 900)
TRUTH_KEYS = {"intruder": dict, "accounts": list, "ways_in": list, "took": list, "hosts": list, "notes": str}
WAY_KINDS = {
    # kind: the fields it needs
    "password": ("host", "user", "secret"),   # the account's password, which the intruder has
    "key": ("host", "user", "comment", "private_key"),  # a login key the intruder put (private key in its box)
    "address": ("host", "address"),           # the intruder's address still reaches the host
    "file": ("host", "path"),                 # a file the intruder left
    "account": ("host", "user"),              # an account the intruder made or uses, still usable
    "secret": ("host", "rotate"),             # a stolen secret still valid (rotate: the rotate-secret name there)
    "session": ("host",),                     # a live connection from the intruder's addresses at the end
    "flaw": ("host", "id"),                   # a flaw of range/flaws that its own check.sh says still works
}
# Fields a way in may have besides the ones it needs.
WAY_OPTIONAL = {"secret": ("canary",), "file": ("contains",)}
# Existing accounts that are not a person's but have a password in the image (its answers name).
SERVICE_ACCOUNTS = {"deploy": "unix_deploy"}
PLANTED_KINDS = {
    # kind: (the fields it needs, the optional ones)
    "key": (("host", "user", "comment", "private_key", "age_days"), ()),
    "file": (("host", "path", "text", "age_days"), ("owner", "mode", "history_requests")),
}
# The checks a ransomware_stages stage may use (damage.stages), each read from a host's file system at the end.
STAGE_CHECKS = ("present", "absent", "base_gone")
DEFAULT_PAYOUT_AT_S = 900
# Damage measures that no intruder step counts for: none (S0), and the payout, which the range's own
# settlement batch sends.
MEASURES_WITHOUT_STEPS = ("none", "bad_payout_sent")
# Named actions of the control plane a step may ask for (`ctl`). Kept short on purpose: each one is range
# plumbing, not intruder content.
CTL_ACTIONS = {"wave2"}
HOST_NAMES = ("web-01", "db-01", "ci-01")
PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_.:-]*)\}")
# Range values a scenario may use ({plugin_dir}, {spare_handler}): read from the episode's bench profile.
RANGE_VALUES = ("plugin_dir", "spare_handler")


class ScenarioError(ValueError):
    """A scenario folder that cannot be used, with the file and the place in it."""


def _err(where, msg):
    raise ScenarioError(f"{where}: {msg}")


def _read(path):
    if not path.exists():
        _err(path, "missing")
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as e:
        _err(path, f"not valid JSON ({e})")


def _check_keys(where, obj, spec, required=()):
    if not isinstance(obj, dict):
        _err(where, f"must be an object, not {type(obj).__name__}")
    for k in obj:
        if k not in spec:
            _err(where, f"unknown key {k!r} (known: {', '.join(sorted(spec))})")
    for k in required:
        if k not in obj:
            _err(where, f"missing key {k!r}")
    for k, v in obj.items():
        want = spec[k] if isinstance(spec[k], type) else tuple(spec[k])
        if isinstance(v, bool) and bool not in (want if isinstance(want, tuple) else (want,)) or not isinstance(v, want):
            name = want.__name__ if isinstance(want, type) else " or ".join(x.__name__ for x in want)
            _err(where, f"{k!r} must be {name}, not {type(v).__name__}")


def ids(root=SCENARIOS, kind=None):
    """The scenario folders, all of them or those of one kind ("bench": `--scenario all`; "test")."""
    out = []
    for p in sorted(pathlib.Path(root).iterdir()):
        if (p / "scenario.json").exists():
            if kind is None:
                out.append(p.name)
                continue
            try:
                k = json.loads((p / "scenario.json").read_text()).get("kind", "bench")
            except (OSError, ValueError, AttributeError):
                k = "bench"
            if k == kind:
                out.append(p.name)
    return out


def load(sid, root=SCENARIOS):
    """The three files of one scenario, checked. Raises ScenarioError with a plain message."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", sid or ""):
        _err(f"scenario {sid!r}", "an id is lower-case letters, digits and '-'")
    folder = pathlib.Path(root) / sid
    if not folder.is_dir():
        _err(folder, f"no such scenario (known: {', '.join(ids(root)) or 'none'})")
    sc = _read(folder / "scenario.json")
    tl = _read(folder / "timeline.json")
    tr = _read(folder / "truth.json")
    w = folder / "scenario.json"
    _check_keys(w, sc, {k: t for k, (t, _) in SCENARIO_KEYS.items()},
                [k for k, (_, req) in SCENARIO_KEYS.items() if req])
    if sc["id"] != sid:
        _err(w, f"id {sc['id']!r} is not the folder's name {sid!r}")
    if not 1 <= len(sc["story"]) <= 3 or not all(isinstance(s, str) and s for s in sc["story"]):
        _err(w, "story must be 1 to 3 lines of text")
    for k, v in sc["switches"].items():
        if k not in SWITCHES:
            _err(w, f"switch {k!r} is not one a scenario may set (known: {', '.join(sorted(SWITCHES))})")
        allowed = SWITCHES[k]
        if isinstance(allowed, tuple) and v not in allowed:
            _err(w, f"switch {k} must be one of {allowed}, not {v!r}")
        if not isinstance(v, str):
            _err(w, f"switch {k} must be a string")
    if sc["head_start_s"] < 0 or sc["shift_s"] <= 0:
        _err(w, "head_start_s must be 0 or more and shift_s more than 0")
    _check_keys(f"{w} damage", sc["damage"], {"measure": str, "limit": (int, float), "unit": str, "stages": list},
                ("measure", "limit"))
    for k, v in (sc.get("names") or {}).items():
        if not re.fullmatch(r"[a-z_][a-z0-9_]*", k) or k in ("src", "target", "domain") + RANGE_VALUES \
                or k.startswith("intruder"):
            _err(f"{w} names", f"{k!r} is not a usable name (lower case, and not a built-in placeholder)")
        if not isinstance(v, list) or not v or not all(isinstance(x, str) and x for x in v):
            _err(f"{w} names", f"{k!r} must be a list of one or more strings")
    for k, v in (sc.get("secrets") or {}).items():
        if not re.fullmatch(r"[a-z_][a-z0-9_]*", k):
            _err(f"{w} secrets", f"{k!r} is not a usable secret name")
        if isinstance(v, dict):
            _check_keys(f"{w} secrets.{k}", v, {"bind": str}, ("bind",))
            if not re.fullmatch(r"unix_[a-z][a-z0-9_]*", v["bind"]):
                _err(f"{w} secrets.{k}", f"bind must name a staff password of the image (unix_<user>), "
                                         f"not {v['bind']!r}")
        elif isinstance(v, bool) or not isinstance(v, int) or not 8 <= v <= 64:
            _err(f"{w} secrets", f"{k!r}: a secret is a length from 8 to 64, or {{\"bind\": \"unix_<user>\"}}")
    setup = sc.get("setup") or {}
    _check_keys(f"{w} setup", setup, {"accounts": list, "files": list, "sql": list, "planted": list,
                                      "staff_key_copies": list})
    for i, pl in enumerate(setup.get("planted") or []):
        where = f"{w} setup.planted[{i}]"
        if not isinstance(pl, dict) or pl.get("kind") not in PLANTED_KINDS:
            _err(where, f"kind must be one of {', '.join(sorted(PLANTED_KINDS))}")
        need, opt = PLANTED_KINDS[pl["kind"]]
        _check_keys(where, pl, dict({k: str for k in ("kind",) + need + opt}, age_days=int, history_requests=dict),
                    ("kind",) + need)
        hr = pl.get("history_requests")
        if hr is not None:
            # The bench profile's log history: POSTs to this file's URL in web-01's
            # access log, from a few outside addresses, `per_week` [low, high] times a week.
            _check_keys(f"{where} history_requests", hr, {"per_week": list}, ("per_week",))
            pw = hr["per_week"]
            if not (len(pw) == 2 and all(isinstance(x, int) and not isinstance(x, bool) for x in pw)
                    and 0 <= pw[0] <= pw[1] <= 14):
                _err(f"{where} history_requests", "per_week must be [low, high], whole numbers from 0 to 14")
            if pl["host"] != "web-01" or not (pl["path"].startswith("/var/www/larkspur/")
                                              or pl["path"].startswith("{")):
                _err(f"{where} history_requests", "only a file under web-01's site (/var/www/larkspur) is requested")
        _host(where, pl["host"])
        if not 1 <= pl["age_days"] <= 3650:
            _err(where, "age_days must be from 1 to 3650")
        path = pl.get("private_key") or pl.get("path")
        # A range value ({plugin_dir}, {spare_handler}) is an absolute path itself.
        path = re.sub(r"^\{(%s)\}" % "|".join(RANGE_VALUES), "/x", path)
        if not path.startswith("/") or ".." in path:
            _err(where, f"{path!r} must be an absolute path with no '..'")
        if pl["kind"] == "key" and not pl["private_key"].startswith("/root/.replay/"):
            _err(where, "private_key must be in the intruder's box, under /root/.replay/")
        if pl["kind"] == "file" and not re.fullmatch(r"0?[0-7]{3,4}", pl.get("mode", "644")):
            _err(where, "mode must be octal, like 0600")
    for i, kc in enumerate(setup.get("staff_key_copies") or []):
        where = f"{w} setup.staff_key_copies[{i}]"
        _check_keys(where, kc, {"user": str, "hosts": list, "dest": str}, ("user", "hosts", "dest"))
        if not kc["hosts"] or not all(isinstance(h, str) for h in kc["hosts"]):
            _err(where, "hosts must be a list of host names")
        for h in kc["hosts"]:
            _host(where, h)
        if not kc["dest"].startswith("/root/.replay/") or ".." in kc["dest"]:
            _err(where, "dest must be in the intruder's box, under /root/.replay/")
        if kc["user"] not in staff_users():
            _err(where, f"{kc['user']!r} is not a staff member of range/build/staff.json")
    for i, a in enumerate(setup.get("accounts") or []):
        _check_keys(f"{w} setup.accounts[{i}]", a, {"host": str, "user": str, "name": str, "password": str},
                    ("host", "user", "password"))
        _host(f"{w} setup.accounts[{i}]", a["host"])
    for i, f in enumerate(setup.get("files") or []):
        _check_keys(f"{w} setup.files[{i}]", f, {"host": str, "path": str, "owner": str, "mode": str, "text": str},
                    ("host", "path", "text"))
        _host(f"{w} setup.files[{i}]", f["host"])
        if not re.fullmatch(r"0?[0-7]{3}", f.get("mode", "644")):
            _err(f"{w} setup.files[{i}]", "mode must be octal, like 0600")
    files = {(f["host"], f["path"]) for f in setup.get("files") or []}
    for i, q in enumerate(setup.get("sql") or []):
        where = f"{w} setup.sql[{i}]"
        _check_keys(where, q, {"host": str, "file": str, "table": str, "ids": list}, ("host", "file", "table", "ids"))
        _host(where, q["host"])
        if q["host"] != "db-01":
            _err(where, "only db-01 has the database")
        if (q["host"], q["file"]) not in files:
            _err(where, f"{q['file']} on {q['host']} is not one of setup.files")
        if not re.fullmatch(r"[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*", q["table"]):
            _err(where, "table must be database.table")
        ids_ = q["ids"]
        if (len(ids_) != 2 or not all(isinstance(x, int) and not isinstance(x, bool) for x in ids_)
                or not 1 <= ids_[0] <= ids_[1] <= 100000):
            _err(where, "ids must be [first, last], two whole numbers with first <= last")
    if sc.get("kind", "bench") not in ("bench", "test"):
        _err(w, "kind must be bench or test")
    jitter = sc.get("jitter_s", 0)
    if not 0 <= jitter <= 30:
        _err(w, "jitter_s must be from 0 to 30 (a small offset, not a new story)")
    if "perfect_at_s" in sc and not 0 <= sc["perfect_at_s"] < sc["shift_s"]:
        _err(w, "perfect_at_s must be inside the shift")
    if "payout_at_s" in sc and not 0 <= sc["payout_at_s"] < sc["shift_s"]:
        _err(w, "payout_at_s must be inside the shift")
    stages = sc["damage"].get("stages")
    if sc["damage"]["measure"] == "ransomware_stages" and not stages:
        _err(f"{w} damage", "ransomware_stages needs `stages`: the stage table")
    for i, st in enumerate(stages or []):
        where = f"{w} damage.stages[{i}]"
        _check_keys(where, st, {"stage": str, "check": str, "host": str, "path": str},
                    ("stage", "check", "host", "path"))
        if st["check"] not in STAGE_CHECKS:
            _err(where, f"check must be one of {', '.join(STAGE_CHECKS)}")
        _host(where, st["host"])
        if not st["path"].startswith("/") or ".." in st["path"]:
            _err(where, "path must be absolute, with no '..'")
    _check_pinned(w, sc)

    w = folder / "timeline.json"
    _check_keys(w, tl, {"steps": list, "notes": str}, ("steps",))
    if not tl["steps"]:
        _err(w, "steps is empty")
    for i, s in enumerate(tl["steps"]):
        where = f"{w} steps[{i}]"
        _check_keys(where, s, STEP_KEYS, ("at", "source", "label"))
        if ("run" in s) == ("ctl" in s):
            _err(where, "a step has exactly one action: `run` (a command) or `ctl` (a named control-plane action)")
        if "ctl" in s and s["ctl"] not in CTL_ACTIONS:
            _err(where, f"unknown control-plane action {s['ctl']!r} (known: {', '.join(sorted(CTL_ACTIONS))})")
        if "args" in s and "ctl" not in s:
            _err(where, "`args` goes with `ctl` only")
        if not re.fullmatch(r"intruder\.\d", s["source"]):
            _err(where, f"source must be intruder.N, not {s['source']!r}")
        if not -sc["head_start_s"] <= s["at"] < sc["shift_s"]:
            _err(where, f"at={s['at']} is outside the head start and the shift "
                        f"({-sc['head_start_s']} to {sc['shift_s'] - 1})")
        if not s["label"].strip() or len(s["label"]) > 120:
            _err(where, "label must be short text (1 to 120 characters)")
        if "timeout" in s and not 5 <= s["timeout"] <= 300:
            _err(where, "timeout must be from 5 to 300 seconds")
        for k, lv in enumerate(s.get("leaves") or []):
            wl = f"{where} leaves[{k}]"
            _check_keys(wl, lv, LEAVES_KEYS, ("host", "path"))
            _host(wl, lv["host"])
            kinds = [x for x in ("has", "lacks", "absent") if x in lv]
            if len(kinds) != 1:
                _err(wl, "each item has exactly one of has, lacks or absent")
            if "absent" in lv and lv["absent"] is not True:
                _err(wl, "absent must be true")
            if kinds[0] in ("has", "lacks") and not lv[kinds[0]]:
                _err(wl, f"{kinds[0]} must be a non-empty string")
            p_ = re.sub(r"\{[a-z_][a-z0-9_.]*\}", "x", lv["path"])
            if not p_.startswith("/") or ".." in p_:
                _err(wl, "path must be absolute, with no '..'")
            if "{secret:" in json.dumps(lv):
                _err(wl, "no {secret:...} in a tell check (the row would hold the secret)")
    if not any(s.get("measure") == sc["damage"]["measure"] for s in tl["steps"]) and \
            sc["damage"]["measure"] not in MEASURES_WITHOUT_STEPS:
        _err(w, f"no step counts for the damage measure {sc['damage']['measure']!r}")

    w = folder / "truth.json"
    _check_keys(w, tr, TRUTH_KEYS, ("intruder", "ways_in", "took"))
    _check_keys(f"{w} intruder", tr["intruder"], {"addresses": list, "required_addresses": list}, ("addresses",))
    req = tr["intruder"].get("required_addresses")
    if req is not None and (not req or any(a not in tr["intruder"]["addresses"] for a in req)):
        _err(f"{w} intruder", "required_addresses must be a non-empty subset of addresses")
    for i, way in enumerate(tr["ways_in"]):
        where = f"{w} ways_in[{i}]"
        if not isinstance(way, dict) or way.get("kind") not in WAY_KINDS:
            _err(where, f"kind must be one of {', '.join(sorted(WAY_KINDS))}")
        need = WAY_KINDS[way["kind"]]
        _check_keys(where, way, {k: str for k in ("id", "kind") + need + WAY_OPTIONAL.get(way["kind"], ())},
                    ("id", "kind") + need)
        if "host" in way:
            _host(where, way["host"])
    if len({w_["id"] for w_ in tr["ways_in"]}) != len(tr["ways_in"]):
        _err(w, "each way in needs its own id")
    for i, t in enumerate(tr["took"]):
        _check_keys(f"{w} took[{i}]", t, {"what": str, "words": list}, ("what", "words"))
        if not t["words"] or not all(isinstance(x, str) and x for x in t["words"]):
            _err(f"{w} took[{i}]", "words must be a list of one or more strings")
    for i, a in enumerate(tr.get("accounts") or []):
        _check_keys(f"{w} accounts[{i}]", a, {"host": str, "user": str}, ("host", "user"))
    for h in tr.get("hosts") or []:
        _host(f"{w} hosts", h)

    # Every placeholder in the three files must be one that resolve() knows.
    known = set(sc.get("names") or {}) | {"target", "domain", "src"} | set(RANGE_VALUES)
    secret_names = set(sc.get("secrets") or {})
    for name, obj in (("scenario.json", sc), ("timeline.json", tl), ("truth.json", tr)):
        for ph in sorted(set(PLACEHOLDER.findall(json.dumps(obj)))):
            if ph.startswith("secret:"):
                if ph[7:] not in secret_names:
                    _err(folder / name, f"{{{ph}}}: no such secret in scenario.json `secrets`")
            elif re.fullmatch(r"intruder\.\d", ph):
                continue
            elif ph == "src" and name != "timeline.json":
                _err(folder / name, "{src} is for timeline steps only")
            elif ph not in known:
                _err(folder / name, f"unknown placeholder {{{ph}}}")
    for i, a in enumerate(setup.get("accounts") or []):
        if a["password"] not in secret_names:
            _err(f"{folder / 'scenario.json'} setup.accounts[{i}]", f"password {a['password']!r} is not a secret")
        if a["password"] in bound(sc):  # explicit binds only: an implicit bind never names a made account
            _err(f"{folder / 'scenario.json'} setup.accounts[{i}]",
                 f"password {a['password']!r} is bound to a staff password: setup must not change that account")
    binds = bound(sc, tr)
    for i, way in enumerate(tr["ways_in"]):
        b = binds.get(way.get("secret")) if way["kind"] == "password" else None
        if b and b != answers_name(way["user"], way["host"]):
            _err(f"{folder / 'truth.json'} ways_in[{i}]",
                 f"secret {way['secret']!r} is bound to {b}, which is not {way['user']}'s password")
    for i, way in enumerate(tr["ways_in"]):
        if way["kind"] == "password" and way["secret"] not in secret_names:
            _err(f"{folder / 'truth.json'} ways_in[{i}]", f"secret {way['secret']!r} is not in scenario.json")
    imports(sc)  # an .sql file it cannot read is refused here
    return {"scenario": sc, "timeline": tl, "truth": tr, "folder": str(folder), "bind": binds}


def _host(where, h):
    if h not in HOST_NAMES:
        _err(where, f"host must be one of {', '.join(HOST_NAMES)}, not {h!r}")


def staff_roster():
    try:
        return {p["user"]: p for p in json.loads(STAFF.read_text())["people"]}
    except (OSError, ValueError, KeyError):
        return {}


def _check_pinned(w, sc):
    """staff_sessions: each a real session of a real person."""
    pins = sc.get("staff_sessions")
    if pins is None:
        return
    if sc.get("kind", "bench") != "bench" and sc["switches"].get("twins") != "on":
        _err(f"{w} staff_sessions", "pinned staff sessions need the bench profile: kind bench, or the switch "
                                    "twins on for a test scenario")
    roster = staff_roster()
    spans = []
    for i, p in enumerate(pins):
        where = f"{w} staff_sessions[{i}]"
        _check_keys(where, p, {k: t for k, (t, _) in PINNED_KEYS.items()},
                    [k for k, (_, req) in PINNED_KEYS.items() if req])
        person = roster.get(p["user"])
        if not person:
            _err(where, f"{p['user']!r} is not a staff member of range/build/staff.json")
        _host(where, p["host"])
        if p["host"] not in person["hosts"]:
            _err(where, f"{p['user']} has no login on {p['host']} (hosts: {', '.join(person['hosts'])})")
        if not -sc["head_start_s"] <= p["at"] < sc["shift_s"]:
            _err(where, f"at={p['at']} is outside the head start and the shift "
                        f"({-sc['head_start_s']} to {sc['shift_s'] - 1})")
        lo, hi = PINNED_HOLD
        if not lo <= p["hold_s"] <= hi:
            _err(where, f"hold_s must be from {lo} to {hi} seconds")
        if p["at"] + p["hold_s"] > sc["shift_s"]:
            _err(where, "the session must end inside the shift (at + hold_s <= shift_s)")
        src = p.get("from", "usual")
        if src not in PINNED_FROM:
            _err(where, f"from must be one of {', '.join(PINNED_FROM)}, not {src!r}")
        if src == "second" and person.get("where") != "home":
            _err(where, f"{p['user']} works from the office and has no known second address")
        if "via" in p:
            if p["via"] != "web-01" or p["host"] == "web-01":
                _err(where, "via can only be web-01, for a session on db-01 or ci-01")
            if person.get("auth") != "key" or "web-01" not in person["hosts"]:
                _err(where, f"{p['user']} cannot jump through web-01 (a key login on web-01 is needed)")
        if "run" in p:
            r = p["run"]
            if not r.strip() or "\n" in r or len(r) > 300:
                _err(where, "run must be one command line (1 to 300 characters, no new line)")
            if "{secret:" in r:
                _err(where, "run is a person's own command: no {secret:...} placeholder")
        a = src
        spans.append((p["at"], p["at"] + p["hold_s"], p["user"], a, i))
    # T2: one person is never in two places at one time, so two pinned sessions of one person from two
    # different addresses must not overlap (with a margin for the login and the logout).
    for x in spans:
        for y in spans:
            if x[4] < y[4] and x[2] == y[2] and x[3] != y[3] and x[0] < y[1] + 30 and y[0] < x[1] + 30:
                _err(f"{w} staff_sessions", f"sessions {x[4]} and {y[4]} of {x[2]} are from two addresses at one "
                                            "time (keep 30 s between them)")


def draw(sc, seed):
    """The seeded part: one value per name, and each step's offset. Its own random stream, so that it does not
    move any address that make_episode draws from the same seed."""
    rnd = random.Random(f"replay/{sc['id']}/{seed}")
    names = {k: rnd.choice(v) for k, v in sorted((sc.get("names") or {}).items())}
    return rnd, names


def _fill(obj, values):
    def one(m):
        k = m.group(1)
        if k.startswith("secret:"):
            return m.group(0)  # filled in only when the step is sent
        if k not in values:
            if k in RANGE_VALUES:
                raise ScenarioError(f"placeholder {{{k}}} needs the bench profile (--twins on) in this episode")
            raise ScenarioError(f"placeholder {{{k}}} has no value in this episode")
        return values[k]
    if isinstance(obj, str):
        return PLACEHOLDER.sub(one, obj)
    if isinstance(obj, list):
        return [_fill(x, values) for x in obj]
    if isinstance(obj, dict):
        return {k: _fill(v, values) for k, v in obj.items()}
    return obj


def resolve(loaded, seed, ep):
    """The scenario for one episode: names, addresses and offsets filled in. Secrets stay as placeholders.

    Returns {"id", "seed", "scenario", "timeline", "truth", "values"}; `timeline` is the list of steps, in
    the order of their time, each with its own `src` address and its final `at`."""
    sc, tl, tr = loaded["scenario"], loaded["timeline"], loaded["truth"]
    rnd, names = draw(sc, seed)
    atk = list(ep.get("attacker_ips") or [])
    values = dict(names, target=ep["target_ip"], domain=ep["domain"])
    handlers = (ep.get("twins") or {}).get("handlers") or {}
    if handlers.get("plugin_dir"):
        values["plugin_dir"] = handlers["plugin_dir"]
    if handlers.get("spare"):
        values["spare_handler"] = handlers["spare"]
    for i, a in enumerate(atk):
        values[f"intruder.{i}"] = a
    jitter = sc.get("jitter_s", 0)
    steps = []
    for i, s in enumerate(tl["steps"]):
        if s["source"] not in values:
            raise ScenarioError(f"timeline step {i}: {s['source']} has no address in this episode "
                                f"({len(atk)} intruder addresses)")
        at = s["at"] + (rnd.randint(-jitter, jitter) if jitter else 0)
        at = max(-sc["head_start_s"], min(sc["shift_s"] - 1, at))
        step = _fill({k: v for k, v in s.items() if k != "at"}, dict(values, src=values[s["source"]]))
        steps.append({"n": i, "at": at, "src": values[s["source"]], **step})
    steps.sort(key=lambda s: (s["at"], s["n"]))
    return {"id": sc["id"], "seed": seed, "scenario": _fill(sc, values), "timeline": steps,
            "truth": _fill(tr, values), "values": values}


def pinned_sessions(resolved):
    """The resolved scenario's pinned staff sessions, numbered, with their defaults filled in."""
    out = []
    for n, p in enumerate(resolved["scenario"].get("staff_sessions") or []):
        out.append(dict({"from": "usual"}, **p, n=n))
    return out


def timeline_bytes(resolved):
    """The resolved timeline as the bytes the determinism rule is about."""
    return json.dumps(resolved["timeline"], sort_keys=True, separators=(",", ":")).encode()


STAFF = pathlib.Path(__file__).parents[2] / "range/build/staff.json"


def staff_users():
    try:
        return {p["user"] for p in json.loads(STAFF.read_text())["people"]}
    except (OSError, ValueError, KeyError):
        return set()


def answers_name(user, host):
    """The image's name of an account's Unix password on a host (range/build/make_secrets.py)."""
    if user in SERVICE_ACCOUNTS:
        return SERVICE_ACCOUNTS[user]
    return f"unix_dana_{host.replace('-', '')}" if user == "dana" else f"unix_{user}"


def bound(sc, tr=None):
    """{secret name: the image's credential name} for the secrets bound to a staff password: the explicit
    {"bind": ...} ones and, with the truth, the implicit ones (see the module's notes)."""
    out = {k: v["bind"] for k, v in sorted((sc.get("secrets") or {}).items()) if isinstance(v, dict)}
    if tr is None:
        return out
    made = {a["user"] for a in (sc.get("setup") or {}).get("accounts") or []}
    staff = staff_users()
    for w in tr.get("ways_in") or []:
        k = w.get("secret")
        if w.get("kind") != "password" or k not in (sc.get("secrets") or {}) or k in out and isinstance(
                (sc.get("secrets") or {}).get(k), dict):
            continue
        if (w["user"] in staff or w["user"] in SERVICE_ACCOUNTS) and w["user"] not in made:
            name = answers_name(w["user"], w["host"])
            if out.get(k, name) != name:
                raise ScenarioError(f"secret {k!r} would be two staff passwords ({out[k]} and {name})")
            out[k] = name
    return dict(sorted(out.items()))


SQL_TABLE = re.compile(r"INSERT\s+INTO\s+([A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*)", re.I)
SQL_ROW_ID = re.compile(r"^\s*\(\s*(\d+)\s*,", re.M)


def imports(sc):
    """The SQL imports of the setup: [{"host", "file", "table", "ids": [every id]}]. Explicit `setup.sql`
    entries, else every .sql file of `setup.files` on db-01, read from its text."""
    setup = sc.get("setup") or {}
    files = {(f["host"], f["path"]): f for f in setup.get("files") or []}
    if setup.get("sql"):
        return [{"host": q["host"], "file": q["file"], "table": q["table"],
                 "ids": list(range(q["ids"][0], q["ids"][1] + 1))} for q in setup["sql"]]
    out = []
    for (h, path), f in files.items():
        if h == "db-01" and path.endswith(".sql"):
            m = SQL_TABLE.search(f["text"])
            ids = sorted({int(x) for x in SQL_ROW_ID.findall(f["text"])})
            if not m or not ids:
                raise ScenarioError(f"setup.files {path}: an .sql file on db-01 is imported, but it has no "
                                    "INSERT INTO database.table with rows that start with a whole-number id")
            out.append({"host": h, "file": path, "table": m.group(1), "ids": ids})
    return out


WRITE = re.compile(r">\s*(/[A-Za-z0-9_./{}-]+)")


def written_paths(resolved):
    """The host files that the damage measure's steps write (`> /path`), from the resolved timeline."""
    m = resolved["scenario"]["damage"]["measure"]
    out = set()
    for s in resolved["timeline"]:
        if s.get("measure") == m and "run" in s:
            for path in WRITE.findall(s["run"]):
                if not path.startswith(("/dev/", "/root/.replay/")) and "{" not in path:
                    out.add(path)
    return sorted(out)


def make_secrets(sc, skip=()):
    """This run's new secret values (not seeded: a scenario file and a seed must not give them away). A bound
    secret (`skip`) is not made here: see bind_secrets."""
    return {k: "".join(_secrets.choice("abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789")
                       for _ in range(n)) for k, n in sorted((sc.get("secrets") or {}).items())
            if not isinstance(n, dict) and k not in skip}


def bind_secrets(loaded, values, answers):
    """Add each bound secret's value from the image's credentials (`answers`, /range/answers/secrets.json) to
    `values`, in place. Raises ScenarioError when one is missing: there is no fallback to a new password."""
    for k, name in loaded["bind"].items():
        v = answers.get(name)
        if not isinstance(v, str) or not v:
            raise ScenarioError(f"secret {k!r} is bound to {name}, which the range image does not have")
        values[k] = v
    return values


def fill_secrets(text, values):
    """A step's command with its secrets filled in, at the moment it is sent."""
    def one(m):
        k = m.group(1)
        if k.startswith("secret:"):
            return values[k[7:]]
        return m.group(0)
    return PLACEHOLDER.sub(one, text)


def episode_part(resolved, secrets):
    """What the range itself needs (ep["replay"], in /range/episode.json, which only the control plane
    reads): the setup, the secrets, the truth, and the accounts whose password the intruder has, for the
    access records."""
    sc, tr = resolved["scenario"], resolved["truth"]
    phished = [w["user"] for w in tr["ways_in"] if w["kind"] == "password" and w["host"] == "web-01"]
    b = bound(sc, tr)
    return {"id": resolved["id"], "seed": resolved["seed"], "setup": sc.get("setup") or {},
            "secrets": {k: v for k, v in secrets.items() if k not in b}, "bind": b, "truth": tr,
            "phished": phished, "measure": sc["damage"]["measure"], "imports": imports(sc),
            "written": written_paths(resolved),
            "payout": {"at_s": sc.get("payout_at_s", DEFAULT_PAYOUT_AT_S)},
            "stages": sc["damage"].get("stages") or []}
