"""Build-time: give one host the accounts of the people who log in to it (range/build/staff.json).

Usage: python3 add_staff.py HOST SECRETS_DIR ROSTER   (HOST is web-01, db-01 or ci-01)

Runs in `docker build`, inside the host's own stage, after the host's own setup has made the accounts it always
had (mreyes, dana, deploy, ...). For those ("existing" in the roster) it only adds the group memberships the
roster gives them. For everyone else on this host: the account, a password, the key in the home directory (where
a person's own key lives; /etc/ssh/authorized_keys.d is left as ops have it), and the groups. On web-01 it also
writes the staff directory a new engineer is pointed at, /etc/larkspur/staff.txt: names, roles, accounts and
the hosts each one uses -- never an address.
"""
import json
import pathlib
import subprocess
import sys

host, secrets_dir, roster = sys.argv[1], pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
people = json.loads(roster.read_text())["people"]
passwords = json.loads((secrets_dir / "passwords.json").read_text())


def run(*cmd, data=None):
    subprocess.run(cmd, check=True, input=data, text=True)


def have_group(g):
    return subprocess.run(["getent", "group", g], capture_output=True).returncode == 0


def have_user(u):
    return subprocess.run(["getent", "passwd", u], capture_output=True).returncode == 0


for p in people:
    if host not in p["hosts"]:
        continue
    user = p["user"]
    groups = p.get("groups", {}).get(host, [])
    for g in groups:
        if not have_group(g):
            run("groupadd", g)
    if p.get("existing"):
        if not have_user(user):
            raise SystemExit(f"{host}: {user} is marked existing but the host's setup did not make it")
        for g in groups:
            run("usermod", "-aG", g, user)
        continue
    comment = f"{p['name']}" + ("" if p["org"] == "Larkspur Cycles" else f" ({p['org']})")
    run("useradd", "-m", "-s", "/bin/bash", "-c", comment, *(["-G", ",".join(groups)] if groups else []), user)
    run("chpasswd", data=f"{user}:{passwords['unix_' + user]}\n")
    ssh = pathlib.Path(f"/home/{user}/.ssh")
    run("install", "-d", "-m", "700", "-o", user, "-g", user, str(ssh))
    if p["auth"] == "key":
        key = (secrets_dir / "pubkeys" / f"{user}.pub").read_text()
        (ssh / "authorized_keys").write_text(key)
        run("chown", f"{user}:{user}", str(ssh / "authorized_keys"))
        run("chmod", "600", str(ssh / "authorized_keys"))

if host == "web-01":
    lines = ["# Larkspur Cycles -- who has a login on the servers",
             "# Kept by ops. Ask Maria before adding anyone; tell ops when someone leaves.",
             "#",
             "# account     name               role                                            servers"]
    for p in people:
        role = p["title"] + ("" if p["org"] == "Larkspur Cycles" else f", {p['org']}")
        lines.append(f"{p['user']:<12}{p['name']:<19}{role:<48}{', '.join(p['hosts'])}")
    lines += ["",
              "# Service accounts",
              "deploy      the release: ci-01 puts each release on web-01 as deploy, with its key",
              "possupport  Acme POS remote support (the till vendor), key only, from the vendor's network",
              ""]
    d = pathlib.Path("/etc/larkspur")
    d.mkdir(mode=0o755, exist_ok=True)
    (d / "staff.txt").write_text("\n".join(lines))
    (d / "staff.txt").chmod(0o644)
