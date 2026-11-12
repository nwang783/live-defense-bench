"""Where a range runs. Both backends run the same image and the same control plane (`/range/bin/rangectl`);
only the transport differs.

  LocalBackend   one privileged Docker container (`docker build --target local -t kl-range:dev range/`)
  BlaxelBackend  one Blaxel sandbox from the template that `bl deploy` makes from range/
"""
import hashlib
import json
import os
import re
import shlex
import subprocess
import time
import uuid

OUTPUT_LIMIT = 16_000


def clip(text, limit=OUTPUT_LIMIT):
    if len(text) <= limit:
        return text
    half = limit // 2
    return f"{text[:half]}\n[... {len(text) - limit} characters cut ...]\n{text[-half:]}"


# What each rangectl command's answer looks like: its shape, and a key it always holds. A reply that does not
# match is not the answer. A 380 KB state object can come back from the sandbox's log broken across lines, and
# a line of it parses on its own -- the `suid` array, or any of the objects nested inside it. e1d-opus-311 was
# graded against that `suid` array and the grader raised, so the shape is checked here, where the answer is
# read, and not in the grader. A command that is not listed may answer any object or list.
ANSWER = {"state": (dict, "t"), "checks": (dict, "flaws"), "progress": (dict, "t"), "mem": (dict, "roles"),
          "wave2": (dict, "wave2_ip"), "reset-evidence": (dict, "reset"),
          # Maps keyed by address, host pair, job or flaw id: there is no key that is always in them.
          "counters": (dict, None), "pivots": (dict, None), "jobs": (dict, None), "flawcheck": (dict, None),
          # The only answer that is a list: the sampler's sightings, in the order it saw them.
          "reached": (list, None),
          # one access record, and the exit switches and help-desk records.
          "access": (dict, "t"), "exits": (list, None), "helpdesk": (list, None),
          # whether each way in of a replay's truth still works at the end.
          "ways": (dict, "ways"), "evidence": (dict, "box")}


def last_json(text, want=(dict, list), key=None):
    """The JSON value that a rangectl command answered with, or None if its output holds none of the shape
    `want` (holding `key`, if one is given).

    rangectl prints its answer as the last line of its output, so the lines are read from the end: a whole
    line first, and then a line whose JSON is followed by rubbish, because that is how a lost shift came back
    ("Extra data": a whole object, and then something else on the same line). Rubbish *before* the JSON on a
    line is not read at all -- a line out of the middle of a broken answer starts that way, and the answer is
    better asked for again than guessed at."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for lenient in (False, True):
        for line in reversed(lines):
            try:
                value = json.JSONDecoder().raw_decode(line)[0] if lenient else json.loads(line)
            except ValueError:
                continue
            if isinstance(value, want) and (key is None or (isinstance(value, dict) and key in value)):
                return value
    return None


class CutOutput(ValueError):
    """A command's output came back shorter than, or different from, what the sandbox wrote. Raised instead of
    handing on a partial answer as if it were the whole one."""


# The line run_to_file's wrapper prints after the command: its exit code, and the size and SHA-256 of the file
# that holds its output, as the sandbox counted them.
FILE_MARK = re.compile(r"\[file (\d+)\s+(\d+)\s+([0-9a-f]{64})\]")


def role_command(role, command, timeout):
    """The command line, in the control plane, that runs `command` as root in a role's own namespaces."""
    return (f"timeout -k 5 {int(timeout)} runc exec {role} bash -c {shlex.quote(command)} 2>&1; "
            f"echo \"[exit $?]\"")


class Backend:
    def start(self): ...
    def stop(self): ...
    def run(self, command, timeout=120) -> str: ...
    def put(self, path, text): ...
    def get(self, path) -> str: ...
    def get_bytes(self, path) -> bytes: ...

    def run_to_file(self, command, timeout=120):
        """`command`'s output (stdout and stderr), read from a file in the sandbox and not from the process
        log. Blaxel's process log keeps only the last 4 MiB of a command's output and puts a "[... truncated"
        line where the rest was (an early test: two shifts lost their end state that
        way, a single line of JSON over 4 MiB with its start gone. Here the
        sandbox counts the bytes and hashes them, and the read must match both, or CutOutput is raised.

        A command that runs out of time ends as `run` does, with "[timed out]", after what it had written."""
        path = f"/range/run/out-{uuid.uuid4().hex[:12]}.txt"
        q = shlex.quote(path)
        said = self.run(f"( {command} ) > {q} 2>&1; rc=$?; n=$(wc -c < {q} | tr -d ' '); "
                        f"h=$(sha256sum {q} | cut -d' ' -f1); echo \"[file $rc $n $h]\"", timeout=timeout)
        try:
            marks = FILE_MARK.findall(said)
            if not marks:
                if said.rstrip().endswith("[timed out]"):
                    try:
                        part = self.get_bytes(path).decode(errors="replace")
                    except Exception:
                        part = ""
                    return part + "\n[timed out]"
                raise CutOutput(f"no size line after the command (the wrapper did not finish): {said[-300:]!r}")
            _rc, size, digest = marks[-1]
            data = b""
            for _ in range(2):  # one read again if the first is short: reading changes nothing
                data = self.get_bytes(path)
                if len(data) == int(size) and hashlib.sha256(data).hexdigest() == digest:
                    return data.decode(errors="replace")
            raise CutOutput(f"read {len(data)} bytes (sha256 {hashlib.sha256(data).hexdigest()[:12]}) of a "
                            f"{size}-byte output (sha256 {digest[:12]}) from {path}")
        finally:
            try:
                self.run(f"rm -f {q}", timeout=30)
            except Exception:
                pass

    # Range code that this checkout sends into a fresh sandbox before `up`, so that a change to the traffic or the
    # control plane needs no image build. None of it goes to web-01 or the attacker.
    CODE = {"range/traffic/driver.py": "/roles/traffic/rootfs/opt/traffic/driver.py",
            "range/traffic/sitegen.py": "/roles/traffic/rootfs/opt/traffic/sitegen.py",
            "range/control/lib/rangectl.py": "/range/lib/rangectl.py",
            "range/control/lib/web01-boot.sh": "/range/lib/web01-boot.sh",
            "range/control/lib/db01-boot.sh": "/range/lib/db01-boot.sh",
            "range/control/lib/ci01-boot.sh": "/range/lib/ci01-boot.sh",
            "range/control/lib/rotate-secret": "/range/lib/rotate-secret",
            # The defender's scratch pad (--notes on).
            "range/control/lib/note": "/range/lib/note",
            # Who logs in where: the traffic and the control plane read it at run
            # time; the accounts on the hosts come from the copy the image was built with.
            "range/build/staff.json": "/roles/traffic/rootfs/opt/traffic/staff.json"}
    CODE_EXTRA = {"range/build/staff.json": "/range/lib/staff.json",
                  # The bench profile: its image state and its business data.
                  "range/control/lib/twinsctl.py": "/range/lib/twinsctl.py",
                  # Its two weeks of log history.
                  "range/control/lib/historyctl.py": "/range/lib/historyctl.py",
                  "range/build/business.py": "/range/lib/business.py"}

    def push_code(self):
        """Send this checkout's range code into a fresh sandbox before `up`. The flaw directories go as one
        JSON file, which `rangectl up` unpacks into /range/flaws, so that a change to a flaw's install, patch
        or check script needs no image build either."""
        import json
        import pathlib
        repo = pathlib.Path(__file__).parents[2]
        if os.environ.get("KL_PUSH_CODE", "1") == "0":
            return
        for src, dst in list(self.CODE.items()) + list(self.CODE_EXTRA.items()):
            self.put(dst, (repo / src).read_text())
        if os.environ.get("KL_PUSH_FLAWS", "1") == "0":
            return
        flaws = {}
        for p in sorted((repo / "range/flaws").glob("*/*")):
            if p.is_file() and p.name != "NEEDS.md":
                try:
                    flaws[f"{p.parent.name}/{p.name}"] = p.read_text()
                except UnicodeDecodeError:  # nothing binary belongs in a flaw directory
                    continue
        self.put("/range/flaws-push.json", json.dumps(flaws))

    def ctl(self, *args, timeout=300):
        # Through a file, not the process log: a state answer can be over the 4 MiB the log keeps (run_to_file).
        out = self.run_to_file("/range/bin/rangectl " + " ".join(shlex.quote(a) for a in args) + " 2>/range/run/ctl.err; "
                       "rc=$?; [ $rc = 0 ] || { cat /range/run/ctl.err >&2; echo \"[rangectl exit $rc]\"; }",
                       timeout=timeout)
        if "[rangectl exit" in out:
            raise RuntimeError(f"rangectl {args[0]} failed: {out[-2000:]}")
        return out

    def ctl_json(self, *args, timeout=300, tries=3, want=None):
        """A rangectl command whose answer is JSON of a known shape (ANSWER). Asked again, up to `tries`
        times, when what comes back is not of that shape: every command that goes through here only reads the
        range, so asking twice changes nothing.

        Three shifts died in this one line. Two in runs/v2-e1c: one in the end snapshot, after its whole live
        phase, with "Extra data", and one at warm-up with "Expecting value" -- the sandbox had handed back the
        last line with something else stuck to it. Then e1d-opus-311, whose state reply came back broken
        across lines: a line of it parsed as a list, which is why the shape is checked here and not in the
        grader.

        `want`: (shape, key) for a command ANSWER does not list, or to ask for something else."""
        want, key = want or ANSWER.get(args[0], ((dict, list), None))
        shape = ("object" if want is dict else "list" if want is list else "object or list")
        shape += f' with a "{key}" in it' if key else ""
        out = ""
        for attempt in range(max(1, tries)):
            try:
                out = self.ctl(*args, timeout=timeout)
            except CutOutput as e:  # the answer was there, the read of it was not whole: ask again
                out = f"[cut] {e}"
                print(f"rangectl {args[0]}: {out} (try {attempt + 1} of {max(1, tries)})", flush=True)
                continue
            value = last_json(out, want, key)
            if value is not None:
                return value
            # A command that ran out of time did not answer badly, it did not finish: asking again would cost
            # another `timeout`, and at the end of a shift that is 15 minutes each.
            if out.rstrip().endswith("[timed out]"):
                raise ValueError(f"rangectl {args[0]} timed out after {timeout} s: {out.strip()[-300:]}")
            print(f"rangectl {args[0]}: the answer is not a JSON {shape} "
                  f"(try {attempt + 1} of {max(1, tries)}): {out.strip()[-300:]!r}", flush=True)
        raise ValueError(f"rangectl {args[0]} did not answer a JSON {shape} in {max(1, tries)} tries: "
                         f"{out.strip()[-500:]}")

    def role(self, role, command, timeout=120):
        return clip(self.run(role_command(role, command, timeout), timeout=timeout + 15))


class LocalBackend(Backend):
    def __init__(self, name, image=None):
        # The image that `docker build --target local -t ldb-range:local range/` makes (README, quick start).
        image = image or os.environ.get("KL_RANGE_IMAGE_V2") or os.environ.get("KL_RANGE_IMAGE") or "ldb-range:local"
        self.name, self.image = name, image

    def start(self):
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)
        subprocess.run(["docker", "run", "-d", "--privileged", "--cgroupns=host", "--name", self.name, self.image],
                       check=True, capture_output=True)
        self.run("mkdir -p /range/run")

    def stop(self):
        # Roles' cgroups live in the Docker VM's tree (--cgroupns=host): remove them before the container.
        subprocess.run(["docker", "exec", self.name, "/range/bin/rangectl", "down"], capture_output=True, timeout=60)
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)

    def run(self, command, timeout=120):
        try:
            p = subprocess.run(["docker", "exec", self.name, "sh", "-c", command], capture_output=True, text=True,
                               timeout=timeout)
            return p.stdout + p.stderr
        except subprocess.TimeoutExpired as e:
            return (e.stdout or b"").decode(errors="replace") + "\n[timed out]"

    def put(self, path, text):
        subprocess.run(["docker", "exec", "-i", self.name, "sh", "-c", f"cat > {shlex.quote(path)}"], input=text,
                       text=True, check=True)

    def get(self, path):
        return subprocess.run(["docker", "exec", self.name, "cat", path], capture_output=True, text=True).stdout

    def get_bytes(self, path):
        return subprocess.run(["docker", "exec", self.name, "cat", path], capture_output=True).stdout


class BlaxelBackend(Backend):
    """Optional. Needs your own Blaxel account (BL_WORKSPACE, BL_API_KEY in .env) and your own build of the range
    image on it (range/blaxel.toml); pass that image with --image or KL_BLAXEL_IMAGE_V2."""

    TTL_MINUTES = 180

    def __init__(self, name, image=None, memory=4096, region="us-was-1"):
        image = image or os.environ.get("KL_BLAXEL_IMAGE_V2") or os.environ.get("KL_BLAXEL_IMAGE")
        if not image:
            raise ValueError("--backend blaxel needs your own range image: pass --image or set KL_BLAXEL_IMAGE_V2 "
                             "(see the README, 'Blaxel backend')")
        self.name, self.image, self.memory, self.region = name, image, memory, region
        self.box = None

    def start(self):
        from blaxel.core import SyncSandboxInstance
        t0 = time.time()
        config = {"name": self.name, "image": self.image, "memory": self.memory, "ttl": f"{self.TTL_MINUTES}m",
                  "region": self.region}
        # A create can end in the gateway's 504 (smoke-haiku-monitor). create_if_not_exists returns the sandbox
        # that the failed request may have made, so a retry never makes a second one.
        for attempt in range(4):
            try:
                self.box = SyncSandboxInstance.create_if_not_exists(config)
                break
            except Exception:
                if attempt == 3:
                    raise
                time.sleep(15 * (attempt + 1))
        # An idle sandbox goes to standby, and Blaxel saves a snapshot of it then. A keepAlive process keeps it
        # awake until the TTL (as platform/api/app/triage/sandbox.py does).
        try:
            self.box.process.exec({"name": "keep-alive", "command": f"sleep {self.TTL_MINUTES * 60}",
                                   "keep_alive": True, "timeout": self.TTL_MINUTES * 60,
                                   "wait_for_completion": False})
        except Exception:
            SyncSandboxInstance.delete(self.name)
            raise
        self.run("mkdir -p /range/run")
        return time.time() - t0

    def stop(self):
        from blaxel.core import SyncSandboxInstance
        SyncSandboxInstance.delete(self.name)

    def run(self, command, timeout=120):
        # Start the command, then poll for it: holding one HTTP request open for a long command ends in the
        # gateway's 504, which ended the agent (haiku-1). wait() polls with short requests and never stops it.
        name, t0 = "c" + uuid.uuid4().hex[:12], time.time()
        # Just after create, Blaxel can answer WORKLOAD_UNAVAILABLE (told-sonnet-202). It says the request did not
        # reach the sandbox, so a replay is safe; it asks for backoff up to about 60 s.
        delay = 0.5
        while True:
            try:
                self.box.process.exec({"name": name, "command": command, "wait_for_completion": False,
                                       "timeout": int(timeout)})
                break
            except Exception as e:
                if "WORKLOAD_UNAVAILABLE" not in str(e) or time.time() - t0 > 90:
                    raise
                time.sleep(delay)
                delay = min(delay * 2, 30)
        try:
            r = self.box.process.wait(name, max_wait=(int(timeout) + 15) * 1000, interval=500)
        except TimeoutError:
            try:
                self.box.process.kill(name)
            except Exception:
                pass
            return "\n[timed out]"  # as LocalBackend
        # r.logs stops at 64 KB, and this read at the last 4 MiB, with a "[... truncated" line where the start was:
        # an answer that can be that large goes through run_to_file (rangectl's always do).
        out = self.box.process.logs(name, "all")
        if r.status != "completed" and time.time() - t0 >= timeout:  # Blaxel's own limit stopped it
            out += "\n[timed out]"
        return out

    def put(self, path, text):
        self.box.fs.write(path, text)

    def get(self, path):
        return self.box.fs.read(path)

    def get_bytes(self, path):
        # One request: read whole and checked up to 16 MB (scripts/blaxel_large_output.py --fixed); an end
        # state is about 0.4-5 MB. run_to_file checks the size and hash, so a short read is never silent.
        return self.box.fs.read_binary(path)
