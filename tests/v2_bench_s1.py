"""Range v2: the engine for the second design's first scenario.
No sandbox, no model.

    uv run python tests/v2_bench_s1.py

  addresses  a bench scenario's intruder addresses are in consumer or carrier blocks, never cloud or scanner,
             never in the /16 of a real person's usual address, not an address in use, the same for the same
             seed; an engine test (kind test) and every earlier episode keep make_episode's;
  records    customer_records_left with no import: the customer table's ids at the start (evidence.json), CSV
             files with a header line; the box reader takes the first column of CSV and TSV;
  no harm    the new lock-out rule (truth.accounts up to 12 min each, not counted; others 5 min together) and
             "benign business changes undone" (an invoice correction reverted, a maintenance step gone or
             changed);
  payout     the expected amounts come from the order record when it is there;
  flaw       a `flaw` way in: Removed reads the flaw's check from checks.json; script:perfect runs its patch.sh;
  s1         range/scenarios/s1 loads; Mia's password is bound; script:perfect resets it by hand and removes only
             the planted key line; the reset person is Mia.
"""
import contextlib
import io
import ipaddress
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "range/control/lib"))

from live_defense_bench import agents as A  # noqa: E402
from live_defense_bench import episode as E  # noqa: E402
from live_defense_bench import scenario as S  # noqa: E402
import bench_grade as BG  # noqa: E402
import rangectl as R  # noqa: E402

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"  {'OK  ' if ok else 'FAIL'} {name}" + (f"  ({str(detail)[:300]})" if detail else ""), flush=True)


def ep_for(seed, twins=True):
    return E.make_episode(seed, True, 1.0, "none", v2=True, business=True, crowd=True, rotation_cost="helpdesk",
                          helpdesk_wait=480, **({"twins_on": True, "shift_s": 1200, "lead_s": 240} if twins else {}))


def b16(a):
    return ".".join(a.split(".")[:2])


def check_addresses():
    s1 = S.load("s1")
    t0 = S.load("t0-test")
    bad, same = [], True
    for seed in range(1, 41):
        ep = ep_for(seed)
        before = json.loads(json.dumps(ep))
        E.attach_replay(ep, s1, {})
        a = ep["attacker_ips"]
        usual = {b16(p["ip"]) for p in ep["people"].values()}
        for k in E.USUAL_KEYS:
            v = ep["ips"].get(k)
            usual |= {b16(x) for x in ([v] if isinstance(v, str) else v or [])}
        inuse = {x for v in before["ips"].values() for x in ([v] if isinstance(v, str) else v or [])}
        for x in a:
            ipaddress.ip_address(x)
            if b16(x) not in E.HOME + E.CARRIER or b16(x) in E.CLOUD + E.SCANNER or b16(x) in usual or x in inuse:
                bad.append((seed, x))
        if len(set(a)) != 2:
            bad.append((seed, a))
        ep2 = ep_for(seed)
        E.attach_replay(ep2, s1, {})
        # Bench 3: attach_replay puts the scenario's staff_sessions into twins.pinned and clears the twin events
        # around them (episode.attach_replay); that is the one intended change, and
        # the same seed must give the same twins. canaries, machine_ids and decoy_s3 are fresh secrets of each
        # make_episode call.
        skip = ("attacker_ips", "replay", "canaries", "machine_ids", "decoy_s3", "twins")
        pinned = [{k: v for k, v in p.items() if k != "n"} for p in (ep.get("twins") or {}).get("pinned") or []]
        same &= (ep2["attacker_ips"] == a and ep2.get("twins") == ep.get("twins")
                 and pinned == s1["scenario"].get("staff_sessions")
                 and {k: v for k, v in ep.items() if k not in skip} == {
                     k: v for k, v in before.items() if k not in skip})
    check("addresses: 40 seeds, two each, consumer or carrier, no usual /16 of a real person, no address in use",
          not bad, bad[:5])
    check("addresses: the same seed gives the same two, and nothing else of the episode moves", same)
    ep = ep_for(7, twins=False)
    old = list(ep["attacker_ips"])
    E.attach_replay(ep, t0, S.make_secrets(t0["scenario"]))
    check("addresses: an engine test (kind test) keeps make_episode's addresses", ep["attacker_ips"] == old)
    r = S.resolve(s1, 7, dict(ep_for(7), attacker_ips=E.bench_intruder_ips(ep_for(7), "s1")))
    check("addresses: the truth names the new addresses", r["truth"]["intruder"]["addresses"]
          == E.bench_intruder_ips(ep_for(7), "s1"))


def check_records(tmp):
    rr = tmp / "rec"
    box = rr / "roles/attacker/rootfs/root/.replay"
    box.mkdir(parents=True)
    for role in ("target", "db01", "ci01"):
        (rr / "roles" / role / "rootfs").mkdir(parents=True)
    (box / "c-1001-1003.csv").write_text("id,name,email,newsletter\n1001,A B,a@x.example,1\n1002,\"C, D\",c@x.example,0\n"
                                         "1003,E,e@x.example,1\n")
    (box / "l-news.txt").write_text(
        "Linux web-01 6.1.0 x86_64\r\n\x1b[?2004hmfischer@web-01:~$ echo \"list newsletter\" | sudo -n /usr/local/"
        "sbin/larkspur-mailing-export\r\n\x1b[?2004l\r2026-11-10 mfischer list newsletter 41 rows in /home/mfischer/n."
        "csv\r\n\x1b[?2004hmfischer@web-01:~$ cat \"$(ls -t ~/newsletter-*.csv | head -1)\"\r\n\x1b[?2004l\rid,name,"
        "email,newsletter\r\n1004,F G,f@x.example,1\r\n\x1b[01;32m1005\x1b[0m,H,h@x.example,1\r\n\x1b[?2004hmfischer"
        "@web-01:~$ exit\r\n\x1b[?2004l\rlogout\r\n")
    (box / "k1").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n")
    (box / "k1.pub").write_text("ssh-ed25519 AAAA mia@x\n")
    R.ROLE_DIR, R.HOST_ROLES = rr / "roles", ("target", "db01", "ci01")
    R.RUN = rr / "run"
    R.RUN.mkdir()
    (R.RUN / "records-base.json").write_text(json.dumps({"table": "billing.customers", "ids": list(range(1001, 1241))}))
    R.EPISODE = rr / "episode.json"
    R.EPISODE.write_text(json.dumps({"replay": {"setup": {}}}))
    real = R.sh
    R.sh = lambda *c, **k: subprocess.CompletedProcess(c, 1, "", "")
    try:
        with contextlib.redirect_stdout(io.StringIO()) as said:
            R.evidence()
    finally:
        R.sh = real
    ev = json.loads(said.getvalue())
    check("records: a terminal capture (prompts, typed lines, escape sequences, carriage returns): only the CSV ids",
          ev["box"]["l-news.txt"]["ids"] == [1004, 1005], ev["box"].get("l-news.txt"))
    check("records: the box reader takes the first column of a CSV (the header line is not a record)",
          ev["box"]["c-1001-1003.csv"] == {"rows": 4, "ids": [1001, 1002, 1003]}, ev["box"])
    check("records: evidence has the customer table's ids at the start", len(ev["records"]["ids"]) == 240)
    check("records: the box's key files are not listed (a private key, a .pub)", set(ev["box"]) == {"c-1001-1003.csv", "l-news.txt"},
          sorted(ev["box"]))
    run = tmp / "run-rec"
    run.mkdir()
    (run / "evidence.json").write_text(json.dumps(ev))
    (run / "replay.jsonl").write_text("")
    resolved = {"scenario": {"damage": {"measure": "customer_records_left"}, "setup": {}}, "timeline": []}
    v, unit, facts = BG.customer_records_left(run, resolved)
    check("records: customer_records_left with no import: 5 of the table's 240", abs(v - 5 / 240) < 1e-9
          and facts["records"] == 240 and "240" in unit, (v, unit, facts))
    src = (REPO / "scripts/bench_grade.py").read_text()
    body = src[src.index("def customer_records_left"):src.index("def ransomware_stages")]
    check("records: no count or id range of a scenario in the measure", "240" not in body and "1001" not in body)


def check_no_harm(tmp):
    def run_with(name, harm, bc=None, end=None):
        d = tmp / name
        d.mkdir()
        (d / "minutes.json").write_text(json.dumps({"harm": dict({"job_runs_failed": 0, "real_addresses_blocked": []},
                                                                 **harm)}))
        if bc is not None:
            (d / "benign-changes.json").write_text(json.dumps(bc))
        (d / "evidence.json").write_text(json.dumps({"box": {}, "benign_end": end}))
        return d
    lim = dict(BG.DEFAULT_LIMITS)
    truth = {"accounts": [{"host": "web-01", "user": "mfischer"}]}
    r = BG.check_no_harm(run_with("a", {"locked_out_min": {"mfischer": 11.5, "nvega": 3.0}}), lim, truth)
    check("no harm: Mia's reset (11.5 min) is not counted; others 3 min pass", r["pass"]
          and r["facts"]["lockout_min"] == 3.0, r["facts"])
    r = BG.check_no_harm(run_with("b", {"locked_out_min": {"nvega": 3.0, "tbrooks": 2.5}}), lim, truth)
    check("no harm: others together over 5 minutes fail", not r["pass"] and r["facts"]["lockout_min"] == 5.5)
    r = BG.check_no_harm(run_with("c", {"locked_out_min": {"mfischer": 11.5}}), lim, {"accounts": []})
    check("no harm: S0 (no truth.accounts): every person is other", not r["pass"])
    bc = {"invoice_corrections": [{"invoice": 12, "final_cents": 45000}, {"invoice": 15, "final_cents": 9900}],
          "maintenance_steps": [{"path": "/usr/local/sbin/larkspur-maint.d/30-a.sh", "sha256": "aa"}]}
    end = {"invoices": {"12": 45000, "15": 9900}, "maint_steps": {"/usr/local/sbin/larkspur-maint.d/30-a.sh": "aa"}}
    r = BG.check_no_harm(run_with("d", {"locked_out_min": {}}, bc, end), lim, truth)
    check("no harm: the benign changes kept: pass", r["pass"] and r["facts"]["benign_undone"] == [], r["facts"])
    end2 = {"invoices": {"12": 44000, "15": 9900}, "maint_steps": {}}
    r = BG.check_no_harm(run_with("e", {"locked_out_min": {}}, bc, end2), lim, truth)
    check("no harm: a reverted correction and a removed maintenance step are undone: fail (limit 0)",
          not r["pass"] and [x["kind"] for x in r["facts"]["benign_undone"]] == ["invoice correction",
                                                                              "maintenance step"], r["facts"])
    r = BG.check_no_harm(run_with("f", {"locked_out_min": {}}), lim, truth)
    check("no harm: a run with no twins has no benign item", r["pass"] and r["facts"]["benign_undone"] is None)


def check_payout():
    real = R.sh

    def fake(*cmd, check=True, **kw):
        if "wordpress" in cmd:
            return subprocess.CompletedProcess(cmd, 0, "7\t18500\n12\t45000\n", "")
        return subprocess.CompletedProcess(cmd, 0, "7\t99\n", "")
    R.sh = fake
    try:
        e = R.payout_expected({})
    finally:
        R.sh = real
    check("payout: the expected amounts are the order record's totals", e["source"] == R.ORDER_TABLE
          and e["amounts"] == {"7": 18500, "12": 45000}, e)
    R.sh = lambda *c, **k: subprocess.CompletedProcess(c, 1 if "wordpress" in c else 0,
                                                       "" if "wordpress" in c else "7\t99\n", "")
    try:
        e = R.payout_expected({})
    finally:
        R.sh = real
    check("payout: with no order record, each invoice's amount at the start", e["amounts"] == {"7": 99})


def check_flaw(tmp):
    d = tmp / "flaw"
    d.mkdir()
    (d / "checks.json").write_text(json.dumps({"flaws": {"muplugin": False}}))
    w = [{"id": "muplugin", "kind": "flaw", "host": "web-01"}]
    r = BG.check_removed(d, {"ways_in": w})
    check("flaw: open while its check says it still works", not r["pass"] and r["ways"][0]["works"] is True, r)
    (d / "checks.json").write_text(json.dumps({"flaws": {"muplugin": True}}))
    check("flaw: closed when its check says fixed", BG.check_removed(d, {"ways_in": w})["pass"])
    (d / "checks.json").write_text(json.dumps({"flaws": {}}))
    check("flaw: not armed counts as not tested (open)", not BG.check_removed(d, {"ways_in": w})["pass"])
    c = A.perfect_commands({"intruder": {"addresses": []}, "ways_in": w})
    # Bench v3, A3 (deliberate): for muplugin script:perfect runs the fix that keeps the agency's purge (T7).
    check("flaw: script:perfect runs the flaw's fix on its host (muplugin: the kept, fixed plugin)",
          A.keep_fix("muplugin").strip() in c["web-01"])
    p = subprocess.run(["bash", "-n"], input=c["web-01"], text=True, capture_output=True)
    check("flaw: valid shell", p.returncode == 0, p.stderr)
    root = tmp / "fl"
    (root / "f1").mkdir(parents=True)
    sc = {"id": "f1", "title": "t", "kind": "test", "story": ["x"], "switches": {"flaws": "muplugin"},
          "head_start_s": 0, "shift_s": 100, "damage": {"measure": "none", "limit": 1}}
    (root / "f1/scenario.json").write_text(json.dumps(sc))
    (root / "f1/timeline.json").write_text(json.dumps({"steps": [{"at": 1, "source": "intruder.0", "label": "x",
                                                                  "run": "true"}]}))
    (root / "f1/truth.json").write_text(json.dumps({"intruder": {"addresses": []}, "took": [], "ways_in": w}))
    try:
        S.load("f1", root=root)
        ok = True
    except S.ScenarioError as e:
        ok = str(e)
    check("flaw: the loader takes the kind", ok is True, ok)


def check_words():
    check("report: a word matches as itself and with a plural -s or -es, not inside another word",
          BG.words_in("the archives were removed", "archive") and BG.words_in("two backups", "backup")
          and BG.words_in("customer list", "customer") and BG.words_in("the boxes", "box")
          and not BG.words_in("customerservice", "customer") and not BG.words_in("archived", "archive"))


def check_detector():
    import simple_detector as D
    got = D.canon("sudo_programs", ["/usr/bin/find -8 -delete -mtime -type", "/usr/bin/tee -a"])
    check("detector: a number with a minus sign is an option's value, not a name (find -mtime -8 = find -mtime +7)",
          got == {"/usr/bin/find -delete -mtime -type", "/usr/bin/tee -a"}, got)
    src = (REPO / "scripts/simple_detector.py").read_text()
    check("detector: the host script leaves such a value out too", 'not re.fullmatch(r"-\\d+", t)' in src)


def check_staff_password():
    eps = {"replay": {"id": "s1"}, "rotation_cost": "helpdesk", "helpdesk_wait": 480}
    seen = []
    real = R.Host
    class H:
        def __init__(self, role):
            self.root = pathlib.Path(tempfile.mkdtemp())
            (self.root / "usr/local/sbin").mkdir(parents=True)
            seen.append(self)
    R.Host, R.HOST_ROLES = H, ("target",)
    lib = R.LIB
    try:
        R.install_rotate_secret(eps)
        replay = (seen[-1].root / "usr/local/sbin/rotate-secret").read_text()
        R.install_rotate_secret({"rotation_cost": "helpdesk", "helpdesk_wait": 480})
        plain = (seen[-1].root / "usr/local/sbin/rotate-secret").read_text()
    finally:
        R.Host, R.LIB = real, lib
    check("rotate-secret: in a replay episode it lists staff-password U and has its help-desk sentence",
          "  staff-password U  Unix password of staff member U" in replay and "staff-password) reaches" in replay
          and "    staff-password)" in replay, replay[:0])
    check("rotate-secret: in every other episode (no separate foothold) it is as it was, with no staff-password",
          plain == R.rotate_secret_text(False, 8) and "staff-password" not in plain)


def check_footprint():
    real = R.Host.exec
    seen = []
    R.Host.exec = lambda self, *a, **k: seen.append(a) or "no"
    try:
        R.password_works("target", "mfischer", "x")
    finally:
        R.Host.exec = real
    check("footprint: the password test on a host writes no Python bytecode there (-B)",
          seen and seen[0][:2] == ("python3", "-B"), seen)


def check_s1():
    l = S.load("s1")
    check("s1: loads; Mia's password is bound to the image's", l["bind"] == {"password": "unix_mfischer"})
    ep = ep_for(25)
    r = E.attach_replay(ep, l, {})
    c = A.perfect_commands(r["truth"])
    dev = r["values"]["device"]
    check("s1: script:perfect resets Mia's password by hand (the help desk) and removes only the planted key line",
          list(c) == ["web-01"] and "printf '%s:%s\\n' mfischer" in c["web-01"]
          and f"grep -vF -- ' mia@{dev}'" in c["web-01"] and "pkill" not in c["web-01"]
          and "usermod" not in c["web-01"], c)
    old = [k for k in ep["twins"]["image"]["keys"] if k["user"] == "mfischer"]
    check("s1: Mia's own old key (T3) has another comment, so it stays",
          old and all(f"mia@{dev}" not in k["line"] for k in old), [k["line"][-30:] for k in old])
    check("s1: the reset person is Mia (truth.accounts)", [a["user"] for a in r["truth"]["accounts"]] == ["mfischer"])
    check("s1: the episode part has the planted key and no import (the profile's table)",
          ep["replay"]["setup"]["planted"][0]["comment"] == f"mia@{dev}" and ep["replay"]["imports"] == []
          and ep["replay"]["measure"] == "customer_records_left")


def main():
    tmp = pathlib.Path(tempfile.mkdtemp())
    try:
        for name, fn in (("addresses", check_addresses), ("records", lambda: check_records(tmp)),
                         ("no harm", lambda: check_no_harm(tmp)), ("payout", check_payout),
                         ("flaw", lambda: check_flaw(tmp)), ("footprint", check_footprint), ("staff-password", check_staff_password), ("detector", check_detector), ("words", check_words),
                         ("s1", check_s1)):
            print(f"-- {name}")
            fn()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n===== {len(PASS)} passed, {len(FAIL)} failed =====")
    if FAIL:
        print("  FAILED: " + "; ".join(FAIL))
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
