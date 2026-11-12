"""Range v2: the engine work for the bench scenarios that does not depend on any scenario's content. No sandbox, no model.

    uv run python tests/v2_bench_engine.py

  bind     a password way in of an existing staff member is bound to the image's own password (implicit, or
           {"bind": ...}); dana's is per host; a made account is never bound; bad binds are refused; the bound
           value is not made, not in episode.json and not in the resolved timeline;
  import   an .sql file of setup.files on db-01 is an import, with the table and ids read from its text;
           rangectl.replay_sql sends the text, checks every id, removes the file; a missing id fails it;
  setup    rangectl.replay_setup checks a bound account on each host of the truth and changes nothing; a missing
           account or a wrong value fails `ok`; replay_values reads a bound value from the answers only;
  written  the files that the damage measure's steps write (`> /path`), not /dev/... or the intruder's box;
  evidence rangectl.evidence reads the box, the setup files (not an import) and the written files per host;
  measures customer_records_left and ransomware_stages from evidence.json only, with no draft facts;
  perfect  a staff password is changed by hand (the help desk gives the new one; no lock, no kill), dana's goes
           through rotate-secret, keys on three hosts are removed on each host, a staff member's sessions stay;
  episode  a whole replay episode with a bound staff password against a stand-in range: the steps get the
           image's value, no run file holds it; a missing credential or a failed setup refuses the run.
"""
import contextlib
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "range/control/lib"))

from live_defense_bench import agents as A  # noqa: E402
from live_defense_bench import build_parser, check_args  # noqa: E402
from live_defense_bench import episode as E  # noqa: E402
from live_defense_bench import scenario as S  # noqa: E402
import bench_grade as BG  # noqa: E402
import rangectl as R  # noqa: E402

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"  {'OK  ' if ok else 'FAIL'} {name}" + (f"  ({str(detail)[:300]})" if detail else ""), flush=True)


def ep_for(seed=5):
    return E.make_episode(seed, True, 1.0, "none", v2=True, business=True, crowd=True, rotation_cost="helpdesk",
                          helpdesk_wait=480)


SQL = ("CREATE TABLE shop.people (id INT PRIMARY KEY, name VARCHAR(40));\nINSERT INTO shop.people (id,name) VALUES\n"
       + ",\n".join(f"({i},'P{i}')" for i in range(3, 13)) + ";\n")


STAGES = [{"stage": "db archives", "check": "base_gone", "host": "db-01", "path": "/var/backups/larkspur/*.enc"},
          {"stage": "maint step", "check": "present", "host": "ci-01", "path": "/etc/larkspur-maint.d/50-*"},
          {"stage": "lib on web", "check": "present", "host": "web-01", "path": "/usr/local/lib/libx.so"},
          {"stage": "monitor gone", "check": "absent", "host": "web-01", "path": "/etc/cron.d/monitor"}]


def scen(root, sid, user="jcole", secrets=None, setup=None, ways=None, steps=None, measure="none", damage=None,
         extra=None):
    d = root / sid
    d.mkdir(parents=True)
    sc = {"id": sid, "title": "t", "kind": "test", "story": ["x"], "switches": {"flaws": "none", "business": "on"},
          "head_start_s": 2, "shift_s": 10, "jitter_s": 0, "perfect_at_s": 5,
          "damage": dict({"measure": measure, "limit": 1, "unit": "u"}, **(damage or {})), "names": {"laptop": ["lt-1"]},
          "secrets": secrets if secrets is not None else {"password": 20}, "setup": setup or {}, **(extra or {})}
    (d / "scenario.json").write_text(json.dumps(sc))
    pw = ("SSHPASS='{secret:password}' sshpass -e ssh -b {src} -o PubkeyAuthentication=no " + user +
          "@{target} 'cat ~/notes.txt' > /dev/null")
    st = steps or [{"at": -1, "source": "intruder.0", "label": "first", "run": pw},
                   {"at": 1, "source": "intruder.0", "label": "read", "run": pw, "measure": measure}]
    (d / "timeline.json").write_text(json.dumps({"steps": st}))
    tr = {"intruder": {"addresses": ["{intruder.0}"]}, "accounts": [{"host": "web-01", "user": user}],
          "hosts": ["web-01"], "took": [{"what": "notes", "words": ["notes"]}],
          "ways_in": ways or [{"id": "pw", "kind": "password", "host": "web-01", "user": user, "secret": "password"}]}
    (d / "truth.json").write_text(json.dumps(tr))
    return d


def refused(fn):
    try:
        fn()
        return None
    except S.ScenarioError as e:
        return str(e)


# ---- bind ----

def check_bind(tmp):
    root = tmp / "b"
    scen(root, "b1")
    l1 = S.load("b1", root=root)
    check("bind: a password way in of an existing staff member (jcole) is bound to unix_jcole",
          l1["bind"] == {"password": "unix_jcole"}, l1["bind"])
    scen(root, "b2", user="dana", ways=[{"id": "p", "kind": "password", "host": "db-01", "user": "dana",
                                         "secret": "password"}])
    check("bind: dana's is per host (unix_dana_db01)", S.load("b2", root=root)["bind"] == {"password": "unix_dana_db01"})
    scen(root, "b3", user="t9test", setup={"accounts": [{"host": "web-01", "user": "t9test", "password": "password"}]})
    check("bind: an account the setup makes is not bound (its password is made for the run)",
          S.load("b3", root=root)["bind"] == {})
    scen(root, "b4", user="jcole", setup={"accounts": [{"host": "web-01", "user": "jcole", "password": "password"}]})
    check("bind: a staff name that the setup makes again is not bound (the setup owns it)",
          S.load("b4", root=root)["bind"] == {})
    scen(root, "b5", secrets={"password": {"bind": "unix_lucia"}})
    got = refused(lambda: S.load("b5", root=root))
    check("bind: an explicit bind that is not the way's user's password is refused", got and "unix_lucia" in got, got)
    scen(root, "b6", secrets={"password": {"bind": "unix_jcole"}},
         setup={"accounts": [{"host": "web-01", "user": "jcole", "password": "password"}]})
    got = refused(lambda: S.load("b6", root=root))
    check("bind: an explicit bind that a setup account would change is refused", got and "bound" in got, got)
    scen(root, "b7", secrets={"password": {"bind": "jcole"}})
    got = refused(lambda: S.load("b7", root=root))
    check("bind: a bind that is not unix_<user> is refused", got and "unix_<user>" in got, got)
    scen(root, "b8", ways=[{"id": "a", "kind": "password", "host": "web-01", "user": "jcole", "secret": "password"},
                           {"id": "b", "kind": "password", "host": "web-01", "user": "lucia", "secret": "password"}])
    got = refused(lambda: S.load("b8", root=root))
    check("bind: one secret for two people is refused", got and "two staff passwords" in got, got)
    vals = S.make_secrets(l1["scenario"], skip=l1["bind"])
    check("bind: a bound secret is not made", "password" not in vals, vals)
    got = refused(lambda: S.bind_secrets(l1, dict(vals), {"unix_lucia": "x"}))
    check("bind: a credential that the image does not have refuses (no fallback to a new password)",
          got and "unix_jcole" in got, got)
    v = S.bind_secrets(l1, dict(vals), {"unix_jcole": "JC-image-value"})
    check("bind: the image's value is used", v["password"] == "JC-image-value")
    ep = ep_for()
    r = E.attach_replay(ep, l1, v)
    text = json.dumps(ep) + json.dumps(r)
    check("bind: the value is not in the episode file's part nor in the resolved timeline, the name is",
          "JC-image-value" not in text and ep["replay"]["bind"] == {"password": "unix_jcole"}
          and "password" not in ep["replay"]["secrets"])
    check("bind: the steps get it only when they are sent",
          "JC-image-value" in S.fill_secrets(r["timeline"][0]["run"], v))


# ---- import ----

def check_import(tmp):
    root = tmp / "i"
    files = [{"host": "db-01", "path": "/tmp/x.sql", "text": SQL}, {"host": "db-01", "path": "/tmp/keep.txt", "text": "k"}]
    scen(root, "i1", setup={"files": files})
    sc = S.load("i1", root=root)["scenario"]
    im = S.imports(sc)
    check("import: an .sql file on db-01 is an import, its table and ids read from its text",
          im == [{"host": "db-01", "file": "/tmp/x.sql", "table": "shop.people", "ids": list(range(3, 13))}], im)
    scen(root, "i2", setup={"files": [{"host": "db-01", "path": "/tmp/y.sql", "text": "DELETE FROM a;"}]})
    got = refused(lambda: S.load("i2", root=root))
    check("import: an .sql file with no rows to check is refused", got and "INSERT INTO" in got, got)
    scen(root, "i3", setup={"files": [{"host": "web-01", "path": "/tmp/z.sql", "text": "x"}]})
    check("import: an .sql file on another host is only a file", S.imports(S.load("i3", root=root)["scenario"]) == [])
    scen(root, "i4", setup={"files": files[:1], "sql": [{"host": "db-01", "file": "/tmp/x.sql",
                                                         "table": "shop.people", "ids": [3, 5]}]})
    check("import: setup.sql says it explicitly",
          S.imports(S.load("i4", root=root)["scenario"])[0]["ids"] == [3, 4, 5])
    # rangectl.replay_sql on a stand-in db-01
    R.ROLE_DIR = tmp / "roles"
    f = R.ROLE_DIR / "db01/rootfs/tmp/x.sql"
    f.parent.mkdir(parents=True)
    f.write_text(SQL)
    sent, real = [], R.sh

    def fake(*cmd, check=True, **kw):
        sent.append((cmd, kw.get("input")))
        if "mysqladmin" in cmd:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd[-1] == "mysql" and kw.get("input"):
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if "-e" in cmd:
            return subprocess.CompletedProcess(cmd, 0, f"{fake.count}\n", "")
        raise AssertionError(cmd)
    fake.count = 10
    R.sh = fake
    try:
        row = R.replay_sql(im[0], {"files": files})
        check("import: replay_sql runs the file's text on db-01 as root, checks every id, removes the file",
              row["ok"] and row["ids_found"] == 10 and row["ids_wanted"] == 10 and not f.exists()
              and any(i == SQL and c[:3] == ("runc", "exec", "db01") for c, i in sent)
              and any("IN (3,4,5,6,7,8,9,10,11,12)" in " ".join(c) for c, _ in sent), row)
        fake.count = 9
        row = R.replay_sql(im[0], {"files": files})
        check("import: an id that is missing fails it", row["ok"] is False and row["ids_found"] == 9, row)
        check("import: the answer has counts only", set(row) <= {"host", "table", "ids_wanted", "ids_found", "ok",
                                                                "why"}, row)
    finally:
        R.sh = real


# ---- setup: bound accounts ----

def check_setup(tmp):
    root = tmp / "s"
    for role in ("target", "db01", "ci01"):
        (root / "roles" / role / "rootfs/etc").mkdir(parents=True)
    (root / "roles/target/rootfs/etc/shadow").write_text("jcole:$y$H:19700:0:99999:7:::\n")
    (root / "answers").mkdir()
    (root / "answers/secrets.json").write_text(json.dumps({"unix_jcole": "IMG-jcole"}))
    R.ROLE_DIR, R.ANSWERS, R.HOST_ROLES = root / "roles", root / "answers", ("target", "db01", "ci01")
    real_pw = R.password_works
    R.password_works = lambda role, user, pw: (role, user, pw) == ("target", "jcole", "IMG-jcole")
    before = (root / "roles/target/rootfs/etc/shadow").read_text()
    ways = [{"id": "w", "kind": "password", "host": "web-01", "user": "jcole", "secret": "password"}]
    ep = {"replay": {"setup": {}, "secrets": {}, "bind": {"password": "unix_jcole"}, "truth": {"ways_in": ways}}}
    try:
        out = R.replay_setup(ep)
        check("setup: a bound account is checked (there, the image's value is its password) and not changed",
              out["ok"] and out["bound"][0]["ok"] and (root / "roles/target/rootfs/etc/shadow").read_text() == before,
              out)
        check("setup: replay_values reads the bound value from the answers, not from the episode file",
              R.replay_values(ep) == {"password": "IMG-jcole"} and "IMG-jcole" not in json.dumps(ep))
        ep2 = json.loads(json.dumps(ep))
        ep2["replay"]["truth"]["ways_in"][0]["host"] = "db-01"
        out = R.replay_setup(ep2)
        check("setup: a bound account that is not on the host fails `ok`", out["ok"] is False
              and out["bound"][0]["why"] == "no such account on the host", out)
        (root / "answers/secrets.json").write_text(json.dumps({"unix_jcole": "OTHER"}))
        out = R.replay_setup(ep)
        check("setup: a value that is not the account's password fails `ok`", out["ok"] is False, out)
        (root / "answers/secrets.json").write_text("{}")
        out = R.replay_setup(ep)
        check("setup: a credential that the image does not have fails `ok`", out["ok"] is False
              and "credential" in out["bound"][0]["why"], out)
        out = R.replay_setup({"replay": {"setup": {}, "secrets": {}, "truth": {"ways_in": []}}})
        check("setup: with nothing bound and nothing made, `ok` and no bound list",
              out["ok"] is True and "bound" not in out, out)
    finally:
        R.password_works = real_pw


# ---- written paths, evidence, measures ----

def check_evidence(tmp):
    root = tmp / "w"
    steps = [{"at": 1, "source": "intruder.0", "label": "a", "measure": "ransomware_stages",
              "run": "ssh x 'sudo sh -c \"printf ok > /tmp/{laptop}-a\"' 2>/dev/null > /dev/null"},
             {"at": 2, "source": "intruder.0", "label": "b", "measure": "ransomware_stages",
              "run": "ssh x 'cat /etc/x' > /root/.replay/out.tsv; echo > /usr/local/lib/libx.so"},
             {"at": 3, "source": "intruder.0", "label": "c", "run": "echo > /tmp/not-a-measure-step"}]
    scen(root, "w1", steps=steps, measure="ransomware_stages", damage={"stages": STAGES},
         setup={"files": [{"host": "db-01", "path": "/var/backups/a.enc", "text": "a"},
                          {"host": "ci-01", "path": "/srv/b.enc", "text": "b"},
                          {"host": "db-01", "path": "/tmp/x.sql", "text": SQL}]})
    loaded = S.load("w1", root=root)
    ep = ep_for()
    resolved = E.attach_replay(ep, loaded, S.make_secrets(loaded["scenario"]))
    w = S.written_paths(resolved)
    check("written: the measure's steps' `> /path` (seeded name filled in), not /dev/..., not the box, not other "
          "steps", w == ["/tmp/lt-1-a", "/usr/local/lib/libx.so"], w)
    rr = tmp / "wr"
    for role in ("target", "db01", "ci01", "attacker"):
        (rr / "roles" / role / "rootfs/tmp").mkdir(parents=True)
    box = rr / "roles/attacker/rootfs/root/.replay"
    box.mkdir(parents=True)
    (box / "out-1.tsv").write_text("3\tA\ta@x\n4\tB\tb@x\n\n4\tB\tb@x\n")
    (box / "out-2.tsv").write_text("12\tC\n99\tZ\nname\tx\n")
    (box / "key").write_text("PRIVATE")
    (rr / "roles/db01/rootfs/var/backups").mkdir(parents=True)
    (rr / "roles/db01/rootfs/var/backups/a.enc").write_text("a")
    (rr / "roles/target/rootfs/tmp/lt-1-a").write_text("ok")
    (rr / "roles/ci01/rootfs/tmp/lt-1-a").write_text("ok")
    arch = rr / "roles/db01/rootfs/var/backups/larkspur"
    arch.mkdir(parents=True)
    for n in ("a1.enc", "a2.enc"):
        (arch / n).write_text("x")
    (rr / "episode.json").write_text(json.dumps(ep))
    R.ROLE_DIR, R.EPISODE, R.HOST_ROLES = rr / "roles", rr / "episode.json", ("target", "db01", "ci01")
    R.RUN = rr / "run"
    R.RUN.mkdir()
    base = R.stage_base(ep)
    check("stages: base_gone records the files that match at the start", base == {"db archives": 2}, base)
    st0 = R.stage_state(ep)["db archives"]
    check("stages: at the start every file is intact, by content (sha256 in stage-base.json)",
          st0["done"] is False and st0["intact"] == 2 and st0["verified"] is True
          and all(len(v) == 64 for v in json.loads((R.RUN / "stage-base.json").read_text())["db archives"].values()),
          st0)
    for n in ("a1.enc", "a2.enc"):
        (arch / n).unlink()
    (arch / "a1.enc").write_text("")
    st1 = R.stage_state(ep)["db archives"]
    check("stages: an empty file with an archive's name is not a restore (changed, the stage stays done)",
          st1["done"] is True and st1["changed"] == 1 and st1["intact"] == 0 and st1["gone"] == 1, st1)
    (arch / "a1.enc").write_text("x")
    st2 = R.stage_state(ep)["db archives"]
    check("stages: an OLD archive put back alone is not a restore: the newest one is the one that counts",
          st2["done"] is True and st2["intact"] == 1 and st2["newest"].endswith("a2.enc"), st2)
    (arch / "a1.enc").unlink()
    (arch / "a2.enc").write_text("x")
    st2 = R.stage_state(ep)["db archives"]
    check("stages: the newest archive put back with the content of the start is a restore (the stage is not done)",
          st2["done"] is False and st2["newest_intact"] is True and st2["gone"] == 1, st2)
    saved = (R.RUN / "stage-base.json").read_text()
    (R.RUN / "stage-base.json").write_text(json.dumps({"db archives": sorted(json.loads(saved)["db archives"])}))
    (arch / "a2.enc").write_text("")
    st3 = R.stage_state(ep)["db archives"]
    check("stages: an older run's stage-base.json (names only) is compared by name, verified false",
          st3["done"] is False and st3["verified"] is False and st3["intact"] == 1, st3)
    (R.RUN / "stage-base.json").write_text(saved)
    (arch / "a2.enc").unlink()
    (arch / "a3.enc").write_text("a new dump")
    (rr / "roles/ci01/rootfs/etc/larkspur-maint.d").mkdir(parents=True)
    (rr / "roles/ci01/rootfs/etc/larkspur-maint.d/50-bucket-move").write_text("x")
    with contextlib.redirect_stdout(io.StringIO()) as said:
        R.evidence()
    ev = json.loads(said.getvalue())
    check("evidence: the box's files (rows, first-column ids), not the key", ev["box"] == {
        "out-1.tsv": {"rows": 3, "ids": [3, 4]}, "out-2.tsv": {"rows": 3, "ids": [12, 99]}}, ev["box"])
    check("evidence: each setup file but the import, present or not",
          ev["setup_files"] == [{"host": "db-01", "path": "/var/backups/a.enc", "present": True},
                                {"host": "ci-01", "path": "/srv/b.enc", "present": False}], ev["setup_files"])
    check("evidence: each written file on each host",
          ev["written"]["web-01:/tmp/lt-1-a"] and ev["written"]["ci-01:/tmp/lt-1-a"]
          and not ev["written"]["db-01:/tmp/lt-1-a"] and not any(v for k, v in ev["written"].items() if "libx" in k),
          ev["written"])
    check("evidence: no file content but the numbers", "PRIVATE" not in said.getvalue() and "a@x" not in said.getvalue())
    run = tmp / "run-w"
    run.mkdir()
    (run / "evidence.json").write_text(json.dumps(ev))
    (run / "replay.jsonl").write_text("")
    check("stages: each stage's state from the file systems (a new dump does not undo base_gone; a glob)",
          {k: v["done"] for k, v in ev["stages"].items()} == {"db archives": True, "maint step": True,
                                                               "lib on web": False, "monitor gone": True},
          ev["stages"])
    val, unit, facts = BG.ransomware_stages(run, resolved)
    check("measure ransomware_stages: the stage table's done stages (3 of 4), its unit from scenario.json",
          val == 3.0 and unit == "u" and facts["done"] == ["db archives", "maint step", "monitor gone"], facts)
    check("measure ransomware_stages: the facts say that the content was compared, and no step row worked",
          facts["content_verified"] is True and facts["steps_worked"] == [] and facts["undone"] == 0, facts)
    (arch / "a3.enc").unlink()
    (R.RUN / "stage-base.json").write_text("{}")
    check("stages: a base_gone stage with no file at the start is not done",
          R.stage_state(ep)["db archives"]["done"] is False)
    # customer_records_left: the import's ids
    root2 = tmp / "c"
    scen(root2, "c1", measure="customer_records_left", setup={"files": [{"host": "db-01", "path": "/tmp/x.sql",
                                                                         "text": SQL}]})
    l2 = S.load("c1", root=root2)
    r2 = E.attach_replay(ep_for(), l2, S.make_secrets(l2["scenario"], skip=l2["bind"]))
    val, unit, facts = BG.customer_records_left(run, r2)
    check("measure customer_records_left: unique ids of the import (3..12) in the box: 3, 4, 12 of 10",
          abs(val - 0.3) < 1e-9 and facts["records_left"] == 3 and facts["records"] == 10 and "10 records" in unit,
          (val, unit, facts))
    (run / "evidence.json").unlink()
    check("measures: with no evidence each counts the worst value (all records, every stage)",
          BG.customer_records_left(run, r2)[0] == 1.0 and BG.ransomware_stages(run, resolved)[0] >= 1)
    src = (REPO / "scripts/bench_grade.py").read_text()
    body = src[src.index("def customer_records_left"):src.index("MEASURES = {")]
    check("measures: no draft fact in the code (no 240, s1-, marker, ready, .tsv, an account name)",
          not any(w in body for w in ("240", "'s1-", '"s1-', "marker", "ready", ".tsv", "jcole", "nvega")))


# ---- perfect ----

def check_perfect():
    keys3 = [{"id": f"k{h}", "kind": "key", "host": h, "user": "nvega", "comment": "nico@nv-x13",
              "private_key": "/root/.replay/k"} for h in ("web-01", "db-01", "ci-01")]
    truth = {"intruder": {"addresses": ["5.6.7.8"]},
             "ways_in": [{"id": "p", "kind": "password", "host": "web-01", "user": "jcole", "secret": "password"},
                         {"id": "d", "kind": "password", "host": "db-01", "user": "dana", "secret": "password"},
                         {"id": "t", "kind": "key", "host": "web-01", "user": "t9test", "comment": "t9@x",
                          "private_key": "/root/.replay/k"}] + keys3}
    c = A.perfect_commands(truth)
    check("perfect: a staff password gets a new value by hand (the help desk gives it out); no lock, no kill",
          "printf '%s:%s\\n' jcole" in c["web-01"] and "| chpasswd" in c["web-01"]
          and "usermod -L" not in c["web-01"].split("t9test")[0] and "pkill -KILL -u jcole" not in c["web-01"], c)
    check("perfect: dana's goes through rotate-secret", "rotate-secret dana-password" in c["db-01"])
    check("perfect: a key on three hosts is removed on each of the three, by its comment",
          all("grep -vF -- ' nico@nv-x13'" in c[h] for h in ("web-01", "db-01", "ci-01")))
    check("perfect: a staff member's sessions stay (no pkill for nvega); a test account's are ended",
          not any("pkill -KILL -u nvega" in c[h] for h in c) and "pkill -KILL -u t9test" in c["web-01"])
    for h, text in c.items():
        p = subprocess.run(["bash", "-n"], input=text, text=True, capture_output=True)
        check(f"perfect: the commands for {h} are valid shell", p.returncode == 0, p.stderr)


# ---- the whole episode with a bound staff password ----

class BoundRange:
    answers = {"unix_jcole": "JC-image-0123456789"}
    up = '{"up": true, "replay": {"ok": true, "accounts": [], "files": [], "bound": [{"ok": true}]}}\n'

    def __init__(self, name, image=None):
        self.name, self.calls, self.ep = name, [], None
        BoundRange.last = self

    def start(self): pass
    def push_code(self): pass
    def stop(self): pass

    def run(self, cmd, *a, **k):
        return "1700000000\n"

    def put(self, path, data):
        if path == "/range/episode.json":
            self.ep = json.loads(data)

    def get(self, path):
        return json.dumps(self.answers) if path == "/range/answers/secrets.json" else ""

    def role(self, role, command, timeout=120):
        self.calls.append((role, command))
        return "done\n[exit 0]" if role != "attacker" else "[exit 0]"

    def ctl(self, *a, **k):
        return self.up if a and a[0] == "up" else '{"up": true}\n'

    def ctl_json(self, what, *a, **k):
        if what == "ways":
            return {"t": time.time(), "ways": {"pw": {"works": False, "fact": "stand-in"}}}
        if what == "evidence":
            return {"t": time.time(), "box": {}, "setup_files": [], "written": {}}
        if what == "counters":
            return {}
        if what in ("reached", "exits", "helpdesk"):
            return []
        return {"t": time.time()}


def check_episode(tmp):
    root = tmp / "e"
    scen(root, "eb")
    real_load, real_grade, real_minutes, real_blaxel = S.load, E.grade.grade, E.write_minutes, E.BlaxelBackend
    S.load = lambda sid, root=root: real_load(sid, root=root)
    E.grade.grade = lambda run: {"valid": True, "problems": [], "warnings": [], "scores": {}, "per_attacker": [],
                                 "detail": {"footholds": {}}}
    E.write_minutes = lambda out: (out / "minutes.json").write_text(json.dumps(
        {"harm": {"locked_out_min": {}, "job_runs_failed": 0, "real_addresses_blocked": []}}))
    E.BlaxelBackend = BoundRange
    os.environ["KL_LANGFUSE"] = "0"

    def go(i):
        ap = build_parser()
        args = ap.parse_args(["episode", "--backend", "blaxel", "--range", "v2", "--defender", "script:none",
                              "--intruder", "replay:eb", "--business", "on", "--crowd", "on",
                              "--rotation-cost", "helpdesk", "--defender-prompt", "routine", "--warmup", "0",
                              "--head-start", "2", "--live", "6", "--seed", "5", "--id", f"e{i}",
                              "--runs", str(tmp / "runs-e")])
        check_args(ap, args)
        with contextlib.redirect_stdout(io.StringIO()):
            try:
                E.episode(args)
                return None
            except SystemExit as e:
                return str(e)

    try:
        got = go(1)
        d = tmp / "runs-e/e1"
        sent = [c for r, c in BoundRange.last.calls if r == "attacker"]
        v = BoundRange.answers["unix_jcole"]
        check("episode: the run goes on, and each step is sent with the image's value", got is None and sent
              and all(v in c for c in sent), got)
        check("episode: no run file holds the value (episode.json neither)",
              not [f.name for f in d.iterdir() if f.is_file() and v in f.read_text()]
              and v not in json.dumps(BoundRange.last.ep))
        check("episode: replay-setup.json and evidence.json are written",
              (d / "replay-setup.json").exists() and (d / "evidence.json").exists())
        BoundRange.answers = {}
        got = go(2)
        check("episode: a credential that the image does not have refuses the run, before `up`",
              got and "unix_jcole" in got and not [c for c in BoundRange.last.calls], got)
        BoundRange.answers = {"unix_jcole": "JC-image-0123456789"}
        BoundRange.up = '{"up": true, "replay": {"ok": false, "bound": [{"ok": false, "why": "no such account"}]}}\n'
        got = go(3)
        check("episode: a failed setup refuses the run, before any step", got and "setup failed" in got
              and not [c for r, c in BoundRange.last.calls if r == "attacker"], got)
    finally:
        S.load, E.grade.grade, E.write_minutes, E.BlaxelBackend = real_load, real_grade, real_minutes, real_blaxel


# ---- the bench fixes ----

def check_ways_from_intruder(tmp):
    """F2: `rangectl ways` tries each key and password way from the office AND from each intruder address
    (for a key on an inner host also through web-01, as the replay goes); the way works if any login works."""
    rr = tmp / "ways34"
    for role in ("target", "db01", "ci01", "traffic", "attacker"):
        (rr / "roles" / role / "rootfs/etc").mkdir(parents=True)
        (rr / "roles" / role / "rootfs/tmp").mkdir(parents=True)
    box = rr / "roles/attacker/rootfs/root/.replay"
    box.mkdir(parents=True)
    (box / "km").write_text("PRIVATE")
    (box / "km.pub").write_text("ssh-ed25519 AAAAmaria maria@mbp\n")
    for role in ("target", "db01"):
        r = rr / "roles" / role / "rootfs"
        (r / "etc/passwd").write_text("mreyes:x:1000:1000::/home/mreyes:/bin/bash\ndeploy:x:1002:1002::/home/deploy:/bin/bash\n")
        (r / "etc/shadow").write_text("deploy:$y$H:19700:0:99999:7:::\n")
        (r / "home/mreyes/.ssh").mkdir(parents=True)
        (r / "home/mreyes/.ssh/authorized_keys").write_text("from=\"X\" ssh-ed25519 AAAAmaria maria@mbp\n")
    ep = ep_for()
    ep["attacker_ips"] = ["100.37.1.2", "73.162.3.4"]
    ways = [{"id": "kw", "kind": "key", "host": "web-01", "user": "mreyes", "comment": "maria@mbp",
             "private_key": "/root/.replay/km"},
            {"id": "kd", "kind": "key", "host": "db-01", "user": "mreyes", "comment": "maria@mbp",
             "private_key": "/root/.replay/km"},
            {"id": "pw", "kind": "password", "host": "web-01", "user": "deploy", "secret": "dpw"}]
    ep["replay"] = {"secrets": {"dpw": "DEPLOY-PW"}, "truth": {"ways_in": ways}}
    (rr / "episode.json").write_text(json.dumps(ep))
    saved = (R.ROLE_DIR, R.EPISODE, R.HOST_ROLES, R.sh, R.password_works)
    R.ROLE_DIR, R.EPISODE, R.HOST_ROLES = rr / "roles", rr / "episode.json", ("target", "db01", "ci01")
    R.password_works = lambda role, user, pw: False
    logins = []

    def run_ways(allow):
        """`allow(where, job)`: "ok", "refused" or "none" for one login."""
        def fake(*cmd, check=True, **kw):
            if cmd[:2] == ("runc", "exec") and "-c" in cmd and cmd[-1] == R.WAY_LOGIN_CODE:
                job = json.loads(kw["input"])
                logins.append((cmd[2], job))
                said = allow(cmd[2], job)
                r = {"ok": said == "ok", "rc": 0 if said == "ok" else 255,
                     "why": "Permission denied (publickey)." if said == "refused" else "Connection timed out"}
                return subprocess.CompletedProcess(cmd, 0, json.dumps(r) + "\n", "")
            raise AssertionError(cmd)
        R.sh = fake
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            R.ways()
        return json.loads(out.getvalue().strip().splitlines()[-1])["ways"]
    try:
        # The defender limited Maria's key to the intruder's first address (from="..."): the office is refused.
        w = run_ways(lambda where, j: "ok" if where == "attacker" and j["ip"] == "100.37.1.2"
                     and (j["addr"] == ep["target_ip"] or j.get("jump")) else
                     "none" if where == "attacker" and j["addr"] == "10.20.0.20" and not j.get("jump") else "refused")
        check("ways: a key limited to the intruder's address still works (the office is refused, intruder.0 gets in)",
              w["kw"]["works"] is True and w["kw"]["refused"] is True
              and w["kw"]["worked_from"] == ["intruder.0 (100.37.1.2)"]
              and w["kw"]["logins"] == {"office": "refused", "intruder.0 (100.37.1.2)": "ok",
                                        "intruder.1 (73.162.3.4)": "refused"}, w["kw"])
        check("ways: on an inner host the intruder's own way, through web-01 with the same key, is tried and counts",
              w["kd"]["works"] is True and w["kd"]["worked_from"] == ["intruder.0 (100.37.1.2) through web-01"]
              and w["kd"]["logins"]["intruder.1 (73.162.3.4)"] == "no answer", w["kd"])
        check("ways: a password way is tried from each intruder address too (works from intruder.0)",
              w["pw"]["works"] is True and "intruder.0 (100.37.1.2)" in w["pw"]["worked_from"], w["pw"])
        check("ways: the fact names where the login worked", "works from intruder.0" in w["kw"]["fact"], w["kw"]["fact"])
        jobs = [j for where, j in logins if where == "attacker"]
        check("ways: the intruder's logins go from the attacker's box, bound to its address, with the box's key",
              jobs and all(j["ip"] in ep["attacker_ips"] for j in jobs)
              and all(j["key"] == "/root/.replay/km" for j in jobs if j["auth"] == "key")
              and all(j["jump"] == ep["target_ip"] for j in jobs if j.get("jump")), jobs[:2])
        check("ways: no secret value goes into the answer", "DEPLOY-PW" not in json.dumps(w) and "PRIVATE" not in json.dumps(w))
        # Everything refused: closed, as before.
        logins.clear()
        w = run_ways(lambda where, j: "refused")
        check("ways: refused from the office and from every intruder address: the way is closed (shape kept)",
              all(w[k]["works"] is False and w[k]["worked_from"] == [] for k in ("kw", "kd", "pw"))
              and {"works", "login", "refused", "key_line_present", "fact"} <= set(w["kw"]), w)
        # Only the office works: open, as before.
        w = run_ways(lambda where, j: "ok" if where == "traffic" else "none")
        check("ways: a login from the office alone still makes the way work",
              all(w[k]["works"] is True and w[k]["worked_from"] == ["office"] for k in ("kw", "kd", "pw")), w)
    finally:
        R.ROLE_DIR, R.EPISODE, R.HOST_ROLES, R.sh, R.password_works = saved
    r = subprocess.run([sys.executable, "-c", "import sys; compile(sys.stdin.read(), 'w', 'exec')"],
                       input=R.WAY_LOGIN_CODE, capture_output=True, text=True)
    check("ways: the login code compiles", r.returncode == 0, r.stderr)


def check_rotate_secret_words(tmp):
    """F3: in a replay episode the tool's own words say that it updates the places it lists, not every copy;
    every other episode's tool is as it was. The prompt says the same (episode.bench_prompt). The second copies
    are in the files that SECOND_USERS names, each one readable by root with the old value in clear text."""
    plain = R.rotate_secret_text(True, 8)
    bench = R.rotate_secret_text(True, 8, bench=True)
    check("rotate-secret: the bench tool no longer says it puts a value everywhere it is used",
          "everywhere it is used" in plain and "everywhere it is used" not in bench
          and "keep working with the new one" not in bench)
    check("rotate-secret: the bench tool's usage says other copies keep the old value and are the caller's to find",
          "It updates only the places named here" in bench and "find them and change them yourself" in bench)
    p = tmp / "rs-bench.sh"
    p.write_text(bench)
    check("rotate-secret: the bench tool is valid bash", subprocess.run(["bash", "-n", str(p)]).returncode == 0)
    check("rotate-secret: off (not a replay) the tool is byte for byte the one without the bench words",
          R.rotate_secret_text(True, 8, bench=False) == plain and R.rotate_secret_text(False, None) ==
          R.rotate_secret_text(False, None, bench=False))
    routine = (REPO / "src/live_defense_bench/prompts/defender-routine-v2.md").read_text()
    bp = E.bench_prompt(routine)
    check("prompt: the bench prompt says rotate-secret updates the listed places and other copies are the "
          "defender's work", "puts it\neverywhere it is used" not in bp and "It updates only those places" in bp
          and "finding and\nupdating them is your work" in bp)
    check("prompt: the routine prompt file itself is unchanged (the bench words are made in code)",
          "everywhere it is used, the provider" in routine)
    # The second copies: each a file of the image, root's, with the secret as a plain value a grep finds.
    tmpl = {"payment-key": R.GATEWAY_ENV.format(key="OLDVALUE"), "bucket-key": R.OFFSITE_ENV.format(
        host="h", port=1, key="OLDVALUE"), "app-db-password": R.REPORT_CNF.format(host="h", user="u", password="OLDVALUE", db="d")}
    check("second copies: each holds the old value as a plain line (grep -r OLDVALUE finds it)",
          all(any(line.endswith("OLDVALUE") for line in t.splitlines()) for t in tmpl.values()))
    where = {k: (v[0], v[1]) for k, v in R.SECOND_USERS.items()}
    check("second copies: payment-key and app-db-password under /etc/larkspur; bucket-key under /root/.config "
          "(outside /etc, named by its job's script)",
          where == {"payment-key": ("db01", "/etc/larkspur/gateway.env"),
                    "bucket-key": ("db01", "/root/.config/larkspur/offsite.env"),
                    "app-db-password": ("target", "/etc/larkspur/report.cnf")}
          and "/root/.config/larkspur/offsite.env" in R.OFFSITE_COPY and "/etc/larkspur/gateway.env" in R.SETTLE, where)


def check_retry_and_tty(tmp):
    """F4: a real person whose login failed tries again after about a minute (bench profile only); the lock-out
    measure then counts about a minute for one failure that the retry undoes, and a lasting one in full.
    F6 (b): marketing's and support's exports run in a terminal session, as the S1 intruder's do."""
    import types
    import v2_twins as TW
    import minutes_grade as MG
    tw_tmp = tmp / "drv34"
    tw_tmp.mkdir()
    drv, d = TW.load_driver(tw_tmp, TW.ep_twins(25))
    check("retry: the wait is about a minute (45 to 75 s)", drv.RETRY_AFTER == (45.0, 75.0))
    waits = []
    drv.STOP.wait = lambda t=None: waits.append(t) or False
    tries = []

    def flaky(user, host, ip=None, cmds=None, jump=None):
        tries.append(time.time())
        if len(tries) == 1:
            raise RuntimeError(f"{host}: login failed (exit 255): Connection timed out during banner exchange")
        return None
    drv.staff_session = flaky
    drv.START = time.time() - 1e6  # every planned session is due now (B1: the sessions follow a plan)
    rounds = {"n": 0}
    real_wait = drv.STOP.wait

    def stop_after(t=None):
        rounds["n"] += 1
        return rounds["n"] > 3 or real_wait(t)
    drv.STOP.wait = stop_after
    drv.run_staff("nvega", "db-01", 600)
    fl = [f for f in TW.flows_of(d) if f["flow"] == "staff_nvega"]
    check("retry: a failed session is tried once more and the retry is written as a try of the same flow",
          [f["ok"] for f in fl][:2] == [False, True] and fl[1].get("retry") is True and len(tries) >= 2,
          [(f["ok"], f.get("retry")) for f in fl])
    # The lock-out measure on the Fable S0 case: a timeout at +67, the person's next try at +759.
    flow = lambda t, ok, retry=False: {"t": t, "persona": "staff", "flow": "staff_nvega", "ok": ok,  # noqa: E731
                                       **({"retry": True} if retry else {})}
    before = MG.lockout_minutes([flow(67, False), flow(759, True)], 0, 1200)
    after = MG.lockout_minutes([flow(67, False), flow(127, True, True), flow(759, True)], 0, 1200)
    lasting = MG.lockout_minutes([flow(67, False), flow(127, False, True), flow(759, True)], 0, 1200)
    check("lock-out: one timeout that the retry undoes is 1.0 minute, not 11.5 (Fable S0)",
          before == {"nvega": 11.5} and after == {"nvega": 1.0}, (before, after))
    check("lock-out: a failure that the retry also meets is counted in full (a real lock-out stays visible)",
          lasting == {"nvega": 11.5}, lasting)
    # Off: without the bench profile no retry.
    off, d2 = TW.load_driver(tw_tmp, TW.ep_off(25))
    tries.clear()
    off.staff_session = flaky
    off.START = time.time() - 1e6
    rounds["n"] = 0
    off.STOP.wait = lambda t=None: (rounds.__setitem__("n", rounds["n"] + 1) or rounds["n"] > 1)
    off.run_staff("nvega", "db-01", 600)
    check("retry: off (no bench profile) a failed try is not tried again", len(tries) == 1, len(tries))

    # F6 (b): T4 in a terminal.
    drv2, d3 = TW.load_driver(tw_tmp, TW.ep_twins(25))
    sent = []

    def fake_run(cmd, capture_output=True, timeout=None, **kw):
        sent.append(cmd)
        out = ("mfischer@web-01:~$ echo \"list newsletter\" | sudo -n /usr/local/sbin/larkspur-mailing-export\r\n"
               "41 rows in /home/mfischer/newsletter-20261110-190000.csv\r\n"
               f"{'c' * 64}  /home/mfischer/newsletter-20261110-190000.csv\r\n")
        return types.SimpleNamespace(returncode=0, stdout=out.encode(), stderr=b"")
    drv2.subprocess.run = fake_run
    drv2.random.uniform = lambda a, b: a
    ok, detail, files, more = drv2.twin_t4({"twin": "T4", "user": "mfischer", "host": "web-01", "kind": "list",
                                            "list": "newsletter"})
    line = sent[-1][-1] if sent else ""
    check("T4: the export runs in a terminal session (ssh -tt, the lines typed on standard input, held open)",
          bool(sent) and sent[-1][:2] == ["sh", "-c"] and " -tt " in line and ("| sshpass" in line or "| ssh" in line),
          line[:300])
    check("T4: the same typed export line as the S1 intruder's (echo \"list X\" | sudo -n the tool)",
          'echo "list newsletter" | sudo -n /usr/local/sbin/larkspur-mailing-export' in line, line[:300])
    check("T4: rows and the CSV are read from the terminal's output (a file of the session, with its sha256)",
          more["rows"] == 41 and files == [{"path": "/home/mfischer/newsletter-20261110-190000.csv", "sha": "c" * 64}],
          (more, files))
    s1 = json.loads((REPO / "range/scenarios/s1/timeline.json").read_text())
    check("T4: the S1 intruder's exports are terminal sessions too (ssh -tt)",
          all(" -tt " in st["run"] for st in s1["steps"] if st.get("measure")))


def check_s1_limit():
    """F6 (a): S1's Damage limit is between the share after two exports and after the last one, from the scenario's
    own data (range/build/business.py and the timeline's export lines). Bench version 2 (2026-11-11): the measured
    steps are `list newsletter` (+150), `list recent` (+600) and the support look-up `ids 1-99999` (+900, all)."""
    sys.path.insert(0, str(REPO / "range/build"))
    import business
    rows = business.customers()
    col = {"newsletter": 3, "rentals": 4, "recent": 5}
    s1 = json.loads((REPO / "range/scenarios/s1/timeline.json").read_text())
    order = []
    for st in sorted(s1["steps"], key=lambda x: x["at"]):
        if not st.get("measure"):
            continue
        m = re.search(r'echo \\?"(list \w+|ids \d+-\d+)\\?"', st["run"])
        order.append((st["at"], m.group(1) if m else None))
    taken, share = set(), []
    for _, ask in order:
        if ask and ask.startswith("list "):
            taken |= {r[0] for r in rows if r[col[ask[5:]]]}
        elif ask and ask.startswith("ids "):
            lo, hi = map(int, ask[4:].split("-"))
            taken |= {r[0] for r in rows if lo <= r[0] <= hi}
        share.append(len(taken) / len(rows))
    lim = json.loads((REPO / "range/scenarios/s1/scenario.json").read_text())["damage"]["limit"]
    check("S1: the exports are list newsletter (+150), list recent (+600), ids 1-99999 (+900): 41, 83, 240 of 240 "
          "(0.1708, 0.3458, 1.0)",
          order == [(150, "list newsletter"), (600, "list recent"), (900, "ids 1-99999")]
          and [round(x, 4) for x in share] == [0.1708, 0.3458, 1.0], (order, share))
    check("S1: the limit (0.4) passes a defender that stops the last export and fails one that stops nothing",
          len(share) == 3 and share[1] < lim <= share[2] and lim == 0.4, lim)


def main():
    tmp = pathlib.Path(tempfile.mkdtemp())
    try:
        for name, fn in (("bind", lambda: check_bind(tmp)), ("import", lambda: check_import(tmp)),
                         ("setup", lambda: check_setup(tmp)), ("written, evidence, measures",
                                                               lambda: check_evidence(tmp)),
                         ("perfect", check_perfect), ("episode", lambda: check_episode(tmp)),
                         ("bench fixes: ways from the intruder's addresses", lambda: check_ways_from_intruder(tmp)),
                         ("bench fixes: rotate-secret's words", lambda: check_rotate_secret_words(tmp)),
                         ("bench fixes: the retry, the lock-out, T4 in a terminal", lambda: check_retry_and_tty(tmp)),
                         ("bench fixes: S1's limit", check_s1_limit)):
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
