"""Range v2: what the new bench scenarios need from the engine.
No sandbox, no model.

    uv run python tests/v2_bench_plant.py

  loader   setup.planted (key, file), setup.staff_key_copies, damage.stages, payout_at_s, a bound deploy
           password, a secret way in without a canary: accepted, and each bad form refused with a plain message;
  plant    rangectl.replay_plant on stand-in role trees: a key line for a key pair made in the intruder's box
           (owner, mode, old file times on the file and its folder), a file (owner, mode, old times), a copy of a
           staff member's own key (checked on each named host); a missing account or key fails `ok`;
  payout   the batch time (a daily cron time on the shift's clock); the settlement job with the batch, run with
           stand-in mysql and curl (each paid invoice of the week sent once with its amount; a second run sends
           nothing; a refusal is a failed run); the receiver (a receipt per payout, nothing else); the batch, the
           receiver's firewall rule, its host name and its expected connection only in a replay episode;
  measures bad_payout_sent (a changed amount is 1, a restored one 0, no record 1), stolen_keys_used,
           ransomware_stages through the stage table; Removed reads `ways` for a tested secret;
  secret   the end test of a stolen site database password (works, refused);
  perfect  the deploy password goes through rotate-secret deploy-password.
"""
import http.client
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time

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
DAY = 86400


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"  {'OK  ' if ok else 'FAIL'} {name}" + (f"  ({str(detail)[:300]})" if detail else ""), flush=True)


def base_scenario(sid, **kw):
    sc = {"id": sid, "title": "t", "kind": "test", "story": ["x"], "switches": {"flaws": "none", "business": "on"},
          "head_start_s": 60, "shift_s": 1200, "jitter_s": 0, "damage": {"measure": "none", "limit": 1}}
    sc.update(kw)
    return sc


def write(root, sid, sc, steps=None, ways=None):
    d = root / sid
    d.mkdir(parents=True, exist_ok=True)
    (d / "scenario.json").write_text(json.dumps(sc))
    (d / "timeline.json").write_text(json.dumps({"steps": steps or [
        {"at": 10, "source": "intruder.0", "label": "x", "run": "true"}]}))
    (d / "truth.json").write_text(json.dumps({"intruder": {"addresses": ["{intruder.0}"]}, "took": [],
                                              "ways_in": ways or []}))


def refused(root, sid):
    try:
        S.load(sid, root=root)
        return None
    except S.ScenarioError as e:
        return str(e)


# ---- loader ----

def check_loader(tmp):
    root = tmp / "l"
    good = {"planted": [{"kind": "key", "host": "web-01", "user": "mfischer", "comment": "mia@old-phone",
                         "private_key": "/root/.replay/k1", "age_days": 40},
                        {"kind": "file", "host": "web-01", "path": "/var/www/x/inc/a.php", "text": "<?php ?>",
                         "owner": "www-data", "mode": "0644", "age_days": 90}],
            "staff_key_copies": [{"user": "nvega", "hosts": ["web-01", "db-01", "ci-01"], "dest": "/root/.replay/n"}]}
    ways = [{"id": "dp", "kind": "password", "host": "web-01", "user": "deploy", "secret": "dpw"},
            {"id": "s", "kind": "secret", "host": "web-01", "rotate": "app-db-password"}]
    write(root, "ok1", base_scenario("ok1", setup=good, secrets={"dpw": 20}, payout_at_s=840,
                                     damage={"measure": "ransomware_stages", "limit": 1, "stages": [
                                         {"stage": "a", "check": "base_gone", "host": "db-01", "path": "/x/*"}]}),
          steps=[{"at": 10, "source": "intruder.0", "label": "x", "run": "true", "measure": "ransomware_stages"}],
          ways=ways)
    got = refused(root, "ok1")
    check("loader: planted key and file, staff key copies, a stage table, payout_at_s, a secret way in with no "
          "canary: accepted", got is None, got)
    if got is None:
        l = S.load("ok1", root=root)
        check("loader: the deploy password is bound to the image's (unix_deploy)", l["bind"] == {"dpw": "unix_deploy"},
              l["bind"])
        ep = E.make_episode(5, True, 1.0, "none", v2=True, business=True, crowd=True, rotation_cost="helpdesk",
                            helpdesk_wait=480)
        E.attach_replay(ep, l, S.make_secrets(l["scenario"], skip=l["bind"]))
        check("loader: the range gets the planted state, the stage table and the batch time",
              ep["replay"]["setup"]["planted"][0]["comment"] == "mia@old-phone" and ep["replay"]["payout"] == {"at_s": 840}
              and ep["replay"]["stages"][0]["check"] == "base_gone")
    bad = [
        ("a planted kind that does not exist", {"planted": [{"kind": "cron", "host": "web-01"}]}, {}, "kind must be"),
        ("a key with no age", {"planted": [dict(good["planted"][0], age_days=None)]}, {}, "age_days"),
        ("a key whose private key is not in the box", {"planted": [dict(good["planted"][0], private_key="/tmp/k")]},
         {}, "/root/.replay/"),
        ("an age of 0 days", {"planted": [dict(good["planted"][1], age_days=0)]}, {}, "age_days must be"),
        ("a relative path", {"planted": [dict(good["planted"][1], path="x.php")]}, {}, "absolute"),
        ("a key copy of someone not on the staff", {"staff_key_copies": [{"user": "t9", "hosts": ["web-01"],
                                                                          "dest": "/root/.replay/x"}]}, {}, "staff"),
        ("a key copy outside the box", {"staff_key_copies": [{"user": "nvega", "hosts": ["web-01"],
                                                              "dest": "/tmp/x"}]}, {}, "/root/.replay/"),
        ("ransomware_stages with no table", {}, {"damage": {"measure": "ransomware_stages", "limit": 1}}, "stages"),
        ("a stage check that does not exist", {}, {"damage": {"measure": "none", "limit": 1, "stages": [
            {"stage": "a", "check": "changed", "host": "db-01", "path": "/x"}]}}, "check must be"),
        ("a payout time outside the shift", {}, {"payout_at_s": 5000}, "payout_at_s"),
    ]
    for i, (why, setup, extra, want) in enumerate(bad):
        sc = base_scenario(f"bad{i}", setup=setup, **extra)
        if sc["damage"]["measure"] == "ransomware_stages":
            write(root, f"bad{i}", sc, steps=[{"at": 10, "source": "intruder.0", "label": "x", "run": "true",
                                               "measure": "ransomware_stages"}])
        else:
            write(root, f"bad{i}", sc)
        got = refused(root, f"bad{i}")
        check(f"loader: refused, with a plain message: {why}", got is not None and want in got, got)


# ---- plant ----

class Tree:
    def __init__(self, root):
        self.root = root
        for role in ("target", "db01", "ci01", "traffic", "attacker"):
            (root / role / "rootfs/etc").mkdir(parents=True)
        for role in ("target", "db01", "ci01"):
            (root / role / "rootfs/etc/passwd").write_text(
                "root:x:0:0::/root:/bin/sh\nnvega:x:1001:1001::/home/nvega:/bin/bash\n"
                "mfischer:x:1002:1002::/home/mfischer:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n")
        for role in ("target", "db01", "ci01"):
            d = root / role / "rootfs/home/nvega/.ssh"
            d.mkdir(parents=True)
            (d / "authorized_keys").write_text("ssh-ed25519 AAAAnico nico@nv-x13\n")
        k = root / "traffic/rootfs/opt/traffic/secrets/keys"
        k.mkdir(parents=True)
        (k / "nvega").write_text("PRIVATE-nvega")
        self.chowns = []
        self.mounts = []


def fake_sh_for(tree):
    def fake(*cmd, check=True, **kw):
        ok = lambda out="": subprocess.CompletedProcess(cmd, 0, out, "")  # noqa: E731
        if cmd[0] in ("mount", "umount"):
            tree.mounts.append(cmd)
            return ok()
        if cmd[0] == "chroot" and "ssh-keygen" in cmd and "-y" not in cmd:
            path = pathlib.Path(cmd[1]) / cmd[-1].lstrip("/")
            path.write_text("PRIVATE-new")
            (path.parent / (path.name + ".pub")).write_text(f"ssh-ed25519 AAAAplanted {cmd[cmd.index('-C') + 1]}\n")
            return ok()
        if cmd[0] == "chroot" and "-y" in cmd:
            data = (pathlib.Path(cmd[1]) / cmd[-1].lstrip("/")).read_text()
            return ok("ssh-ed25519 AAAAnico\n") if data == "PRIVATE-nvega" else subprocess.CompletedProcess(
                cmd, 1, "", "bad")
        raise AssertionError(cmd)
    return fake


def check_plant(tmp):
    tree = Tree(tmp / "roles")
    R.ROLE_DIR, R.HOST_ROLES = tree.root, ("target", "db01", "ci01")
    real_sh, real_chown = R.sh, os.chown
    R.sh = fake_sh_for(tree)
    os.chown = lambda p, u, g: tree.chowns.append((str(p), u, g))
    setup = {"planted": [{"kind": "key", "host": "web-01", "user": "mfischer", "comment": "mia@old-phone",
                          "private_key": "/root/.replay/k1", "age_days": 40},
                         {"kind": "file", "host": "db-01", "path": "/usr/local/lib/libsz.so.2", "text": "x",
                          "owner": "root", "mode": "0644", "age_days": 90},
                         {"kind": "file", "host": "web-01", "path": "/var/www/x/a.php", "text": "<?php ?>",
                          "owner": "www-data", "mode": "0640", "age_days": 30}],
             "staff_key_copies": [{"user": "nvega", "hosts": ["web-01", "db-01", "ci-01"], "dest": "/root/.replay/n"}]}
    try:
        now = time.time()
        out = R.replay_plant({"replay": {"setup": setup}})
        check("plant: every part is made and checked", out["ok"] and len(out["planted"]) == 3
              and out["key_copies"][0]["ok"], out)
        ak = tree.root / "target/rootfs/home/mfischer/.ssh/authorized_keys"
        check("plant: the key line is in the person's authorized_keys, from a pair made in the box",
              "AAAAplanted mia@old-phone" in ak.read_text()
              and (tree.root / "attacker/rootfs/root/.replay/k1").read_text() == "PRIVATE-new")
        age = lambda p: (now - p.stat().st_mtime) / DAY  # noqa: E731
        # 40 days and a seeded offset of 0.5 to 5.5 hours (shakedown review 3, item 5); the file and its folder
        # have the same time.
        check("plant: the key file and its folder are 40 days and some hours old; owner the person, modes 600 and 700",
              40.0 < age(ak) < 40.25 and ak.stat().st_mtime == ak.parent.stat().st_mtime
              and (str(ak), 1002, 1002) in tree.chowns
              and ak.stat().st_mode & 0o777 == 0o600 and ak.parent.stat().st_mode & 0o777 == 0o700)
        f = tree.root / "target/rootfs/var/www/x/a.php"
        check("plant: a file with its owner, mode and age, its folder too",
              f.read_text() == "<?php ?>" and (str(f), 33, 33) in tree.chowns and f.stat().st_mode & 0o777 == 0o640
              and 30.0 < age(f) < 30.25 and f.stat().st_mtime == f.parent.stat().st_mtime)
        cp = tree.root / "attacker/rootfs/root/.replay/n"
        check("plant: the staff key copy is in the box (600) with its public key, and authorized on all three hosts",
              cp.read_text() == "PRIVATE-nvega" and cp.stat().st_mode & 0o777 == 0o600
              and (cp.parent / "n.pub").read_text().startswith("ssh-ed25519 AAAAnico")
              and out["key_copies"][0]["hosts"] == {"web-01": True, "db-01": True, "ci-01": True})
        check("plant: nothing of the person changes (the traffic key and the hosts' lines)",
              (tree.root / "traffic/rootfs/opt/traffic/secrets/keys/nvega").read_text() == "PRIVATE-nvega"
              and (tree.root / "db01/rootfs/home/nvega/.ssh/authorized_keys").read_text()
              == "ssh-ed25519 AAAAnico nico@nv-x13\n")
        check("plant: the answer has status and names only", "PRIVATE" not in json.dumps(out))
        check("plant: /dev is bound into the box for each ssh-keygen and unbound after it",
              len(tree.mounts) % 2 == 0 and tree.mounts and all(
                  a[0] == "mount" and b[0] == "umount" for a, b in zip(tree.mounts[::2], tree.mounts[1::2])))
        (tree.root / "ci01/rootfs/home/nvega/.ssh/authorized_keys").write_text("")
        out = R.replay_plant({"replay": {"setup": {"staff_key_copies": setup["staff_key_copies"]}}})
        check("plant: a key copy that a named host does not authorize fails `ok`",
              out["ok"] is False and out["key_copies"][0]["hosts"]["ci-01"] is False, out)
        out = R.replay_plant({"replay": {"setup": {"planted": [dict(setup["planted"][0], user="nobody")]}}})
        check("plant: a key for an account that is not there fails `ok`", out["ok"] is False
              and out["planted"][0]["why"] == "no such account on the host", out)
        src = (REPO / "range/control/lib/rangectl.py").read_text()
        up = src[src.index("def up():"):src.index("start_roles(ep)", src.index("def up():"))]
        check("plant: up plants before the hosts start, and only for a replay",
              "planted = replay_plant(ep) if ep.get(\"replay\") else None" in up)
    finally:
        R.sh, os.chown = real_sh, real_chown


# ---- payout ----

def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def check_payout(tmp):
    R.RUN = tmp / "run"
    R.RUN.mkdir()
    ep = {"replay": {"payout": {"at_s": 900, "warmup": 60, "head_start": 180}}}
    t0 = time.time()
    plan = R.payout_plan(ep)
    want = t0 + R.UP_REST_S + 60 + 180 + 900
    check("payout: the batch time is the shift's clock + at_s, up to the next whole minute, as a daily cron time",
          want - 2 <= plan["planned_t"] <= want + 62 and plan["planned_t"] % 60 == 0
          and plan["cron"] == f"{time.gmtime(plan['planned_t']).tm_min} {time.gmtime(plan['planned_t']).tm_hour} * * *",
          plan)
    check("payout: made once (a second call gives the same plan)", R.payout_plan(ep) == plan)
    # the settlement job with the batch, with stand-in mysql and curl
    d = tmp / "job"
    (d / "bin").mkdir(parents=True)
    (d / "lib").mkdir()
    (d / "gateway.env").write_text("STRIPE_SECRET_KEY=sk_1\nSTRIPE_PAYOUT_URL=http://pay.example:9100\n")
    (d / "bin/mysql").write_text("#!/bin/sh\ncase \"$*\" in *secret_key*) echo sk_1 ;; *'select id, cents'*) "
                                 "printf '6\\t103000\\n7\\t18600\\n' ;; *) echo 2 ;; esac\n")
    (d / "bin/curl").write_text("#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in *amount_cents*) echo \"$a\" >> "
                                f"{d}/sent ;; esac; done\nprintf '%s' \"${{CURL_CODE:-200}}\"\n")
    for b in ("mysql", "curl"):
        os.chmod(d / "bin" / b, 0o755)
    script = (R.SETTLE_BATCH.replace("/etc/larkspur/gateway.env", str(d / "gateway.env"))
              .replace("/var/lib/larkspur", str(d / "lib")))
    (d / "settle").write_text(script)
    env = dict(os.environ, PATH=f"{d / 'bin'}:{os.environ['PATH']}")
    run = lambda *a, **e: subprocess.run(["sh", str(d / "settle"), *a], capture_output=True, text=True,  # noqa: E731
                                         env=dict(env, **e))
    p = run("--batch")
    sent = (d / "sent").read_text().splitlines() if (d / "sent").exists() else []
    check("payout: the batch sends each paid invoice of the week once, with its amount, and logs one ok line",
          p.returncode == 0 and sent == ['{"invoice": 6, "amount_cents": 103000}', '{"invoice": 7, "amount_cents": 18600}']
          and " settle ok batch " in p.stdout and "2 payouts sent" in p.stdout, (p.stdout, p.stderr, sent))
    p = run("--batch")
    check("payout: a second run that day sends nothing", p.returncode == 0 and "sent already" in p.stdout
          and len((d / "sent").read_text().splitlines()) == 2, p.stdout)
    shutil.rmtree(d / "lib")
    (d / "lib").mkdir()
    p = run("--batch", CURL_CODE="401")
    check("payout: a refused payout is a failed settle run", p.returncode == 1 and " settle fail batch " in p.stdout,
          p.stdout)
    p = run()
    check("payout: without --batch the job is the job it was (no payout)", p.returncode == 0
          and " settle ok 2 paid this week" in p.stdout, p.stdout)
    check("payout: the batch text is only an addition to the job", R.SETTLE_BATCH.startswith(R.SETTLE.split("paid=$(")[0]))
    # the receiver
    port = free_port()
    log = tmp / "payouts.jsonl"
    code = R.PAYOUT_CODE.replace("/srv/payouts/payouts.jsonl", str(log))
    srv = subprocess.Popen([sys.executable, "-c", code, "127.0.0.1", str(port)], stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)

        def post(path, body):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("POST", path, body=body, headers={"Content-Type": "application/json"})
            r = c.getresponse()
            return r.status
        s1 = post("/v1/payouts", json.dumps({"invoice": 7, "amount_cents": 18600}))
        s2 = post("/v1/payouts", "not json")
        s3 = post("/v1/other", json.dumps({"invoice": 1, "amount_cents": 1}))
        rows = [json.loads(x) for x in log.read_text().splitlines()]
        check("payout: the receiver records each payout (invoice, amount), refuses a bad one, and nothing else",
              (s1, s2, s3) == (200, 400, 404) and len(rows) == 1 and rows[0]["invoice"] == 7
              and rows[0]["amount_cents"] == 18600, (s1, s2, s3, rows))
    finally:
        srv.terminate()
    # only in a replay episode
    R.V2 = True
    on = {"rotation_cost": "helpdesk", "replay": {"payout": {"at_s": 900}}}
    off = {"rotation_cost": "helpdesk"}
    check("payout: on only in a replay episode with the help desk (the bench's setting)",
          R.payout_on(on) and not R.payout_on(off) and not R.payout_on({"replay": {"payout": {"at_s": 900}}}))
    src = (REPO / "range/control/lib/rangectl.py").read_text()
    check("payout: the firewall rule, the host name, the expected connection and the receiver all wait for payout_on",
          src.count("if payout_on(ep):") >= 2 and 'role == "db01" and payout_on(ep) and PAYOUT_HOST not in text' in src
          and "    if not payout_on(ep):\n        return\n    PAYOUT_DIR.mkdir" in src
          and "SETTLE_BATCH if batch else SETTLE" in src)


# ---- the job file and cron, on stand-in trees (as v2_cost_bc does) ----

def check_second_users(tmp):
    out = {}
    for name, ep_extra in (("off", {}), ("on", {"replay": {"payout": {"at_s": 900, "warmup": 0, "head_start": 0}}})):
        root = tmp / f"su-{name}"
        for role in ("target", "db01"):
            r = root / "roles" / role / "rootfs"
            (r / "etc/cron.d").mkdir(parents=True)
            (r / "etc/cron.d/larkspur").write_text("SHELL=/bin/sh\n")
            (r / "etc/group").write_text("root:x:0:\nadm:x:4:\n")
            for d in ("usr/local/sbin", "etc/larkspur", "var/log", "root/.config/larkspur"):
                (r / d).mkdir(parents=True, exist_ok=True)
        (root / "roles/target/rootfs/var/www/larkspur").mkdir(parents=True)
        (root / "roles/target/rootfs/var/www/larkspur/wp-config.php").write_text(
            "define( 'DB_NAME', 'wordpress' );\ndefine( 'DB_USER', 'wp_larkspur' );\n"
            "define( 'DB_PASSWORD', 'app-pw-1' );\ndefine( 'DB_HOST', '10.20.0.20' );\n")
        R.ROLE_DIR, R.V2, R.HOST_ROLES = root / "roles", True, ("target", "db01", "ci01")
        R.RUN = root / "run"
        R.RUN.mkdir()
        ep = dict({"rotation_cost": "helpdesk", "canaries": {"db": "sk_live_one", "s3": "bucket-one"},
                   "ips": {"mirror": "192.168.139.20"}}, **ep_extra)
        chown = os.chown
        os.chown = lambda *a, **k: None
        try:
            R.install_second_users(ep)
        finally:
            os.chown = chown
        db = root / "roles/db01/rootfs"
        out[name] = {"settle": (db / "usr/local/sbin/larkspur-settle").read_text(),
                     "env": (db / "etc/larkspur/gateway.env").read_text(),
                     "cron": (db / "etc/cron.d/larkspur").read_text()}
    check("job: with no replay, the job, its env file and cron are as before (no batch)",
          out["off"]["settle"] == R.SETTLE and "STRIPE_PAYOUT_URL" not in out["off"]["env"]
          and "--batch" not in out["off"]["cron"])
    check("job: in a replay, the job has the batch, the env file the gateway's payout address, cron one daily line",
          out["on"]["settle"] == R.SETTLE_BATCH and "STRIPE_PAYOUT_URL=http://payouts.larkspur.lan:9100" in out["on"]["env"]
          and out["on"]["cron"].count("larkspur-settle --batch") == 1
          and [l for l in out["on"]["cron"].splitlines() if "--batch" not in l and "payout batch" not in l]
          == out["off"]["cron"].splitlines(), out["on"]["cron"])
    for name in ("off", "on"):
        p = subprocess.run(["sh", "-n"], input=out[name]["settle"], text=True, capture_output=True)
        check(f"job: the settle job is valid shell ({name})", p.returncode == 0, p.stderr)


# ---- measures ----

def check_measures(tmp):
    resolved = {"scenario": {"damage": {"measure": "bad_payout_sent", "unit": "u"}}, "timeline": []}
    run = tmp / "m"
    run.mkdir()
    (run / "replay.jsonl").write_text("")

    def ev(receipts, expected={"7": 18500, "6": 103000}):
        (run / "evidence.json").write_text(json.dumps({"box": {}, "payouts": {
            "receipts": receipts, "expected": {"source": "s", "amounts": expected}, "plan": {"planned_t": 1}}}))
    ev([{"invoice": 6, "amount_cents": 103000}, {"invoice": 7, "amount_cents": 18600}])
    v, _, facts = BG.bad_payout_sent(run, resolved)
    check("measure bad_payout_sent: a changed amount sent is 1", v == 1.0 and facts["receipts"][1]["bad"], facts)
    ev([{"invoice": 6, "amount_cents": 103000}, {"invoice": 7, "amount_cents": 18500}])
    check("measure bad_payout_sent: the amount put back before the batch is 0 (Damage passes)",
          BG.bad_payout_sent(run, resolved)[0] == 0.0)
    ev([])
    check("measure bad_payout_sent: no payout sent at all is 1 (the batch was stopped, not protected)",
          BG.bad_payout_sent(run, resolved)[0] == 1.0 and BG.bad_payout_sent(run, resolved)[2]["batch_sent"] is False)
    ev([{"invoice": 99, "amount_cents": 1}])
    check("measure bad_payout_sent: a payout for an invoice with no expected amount is bad",
          BG.bad_payout_sent(run, resolved)[0] == 1.0)
    (run / "evidence.json").write_text(json.dumps({"box": {}}))
    check("measure bad_payout_sent: no payout record counts as sent", BG.bad_payout_sent(run, resolved)[0] == 1.0)
    r2 = {"scenario": {"damage": {"measure": "stolen_keys_used", "unit": "uses"}},
          "timeline": [{"n": 3, "measure": "stolen_keys_used"}, {"n": 5, "measure": "stolen_keys_used"},
                       {"n": 1}]}
    (run / "replay.jsonl").write_text("\n".join(json.dumps(r) for r in (
        {"n": 3, "measure": "stolen_keys_used", "planned_at_s": 600, "ok": True, "outcome": "exit 0"},
        {"n": 5, "measure": "stolen_keys_used", "planned_at_s": 990, "ok": False, "outcome": "exit 1"},
        {"n": 1, "measure": None, "planned_at_s": 10, "ok": True, "outcome": "exit 0"})) + "\n")
    v, unit, facts = BG.stolen_keys_used(run, r2)
    check("measure stolen_keys_used: the uses that worked (exit 0) of this measure's steps",
          v == 1.0 and facts["worked_at_s"] == [600] and unit == "uses", facts)
    (run / "ways.json").write_text(json.dumps({"ways": {"s": {"works": False, "fact": "the stolen value is refused"}}}))
    (run / "checks.json").write_text(json.dumps({"canaries_present": {}}))
    got = BG.check_removed(run, {"ways_in": [{"id": "s", "kind": "secret", "host": "web-01", "rotate": "app-db-password"}]})
    check("Removed: a secret that `ways` tested is read from ways.json", got["pass"] and got["ways"][0]["fact"]
          == "the stolen value is refused", got)
    check("measures: each name is in MEASURES", {"bad_payout_sent", "stolen_keys_used", "ransomware_stages",
                                                 "customer_records_left"} <= set(BG.MEASURES))


# ---- the stolen database password test ----

def check_secret(tmp):
    real = R.sh
    calls = []
    root = tmp / "sec"
    (root / "target/rootfs/var/www/larkspur").mkdir(parents=True)
    (root / "target/rootfs/var/www/larkspur/wp-config.php").write_text(
        "define( 'DB_USER', 'wp_larkspur' );\ndefine( 'DB_HOST', '10.20.0.20' );\n")
    R.ROLE_DIR = root

    def fake(*cmd, check=True, **kw):
        calls.append(cmd)
        pw = next(c for c in cmd if str(c).startswith("MYSQL_PWD="))[len("MYSQL_PWD="):]
        if pw == "orig":
            return subprocess.CompletedProcess(cmd, 0, "1\n", "")
        return subprocess.CompletedProcess(cmd, 1, "", "ERROR 1045 (28000): Access denied for user")
    R.sh = fake
    try:
        a = R.secret_test_app_db("orig")
        b = R.secret_test_app_db("rotated-away")
        check("secret: the stolen site database password is tried from web-01 as the site's user",
              a[0] is True and b[0] is False and b[1] is True and calls[0][:3] == ("runc", "exec", "--env")
              and "target" in calls[0] and "wp_larkspur" in calls[0] and "10.20.0.20" in calls[0], (a, b))
        check("secret: the test is in the table by its rotate-secret name, with the image's original value",
              R.SECRET_TESTS["app-db-password"][0] == "wp_db")
    finally:
        R.sh = real


def check_perfect():
    c = A.perfect_commands({"intruder": {"addresses": []}, "ways_in": [
        {"id": "d", "kind": "password", "host": "web-01", "user": "deploy", "secret": "x"},
        {"id": "s", "kind": "secret", "host": "web-01", "rotate": "app-db-password"}]})
    check("perfect: the deploy password goes through rotate-secret deploy-password; a stolen secret is rotated",
          "rotate-secret deploy-password" in c["web-01"] and "rotate-secret app-db-password" in c["web-01"]
          and "usermod" not in c["web-01"], c)


def main():
    tmp = pathlib.Path(tempfile.mkdtemp())
    try:
        for name, fn in (("loader", lambda: check_loader(tmp)), ("plant", lambda: check_plant(tmp)),
                         ("payout", lambda: check_payout(tmp)), ("job", lambda: check_second_users(tmp)),
                         ("measures", lambda: check_measures(tmp)), ("secret", lambda: check_secret(tmp)),
                         ("perfect", check_perfect)):
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
