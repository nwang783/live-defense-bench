"""Run the range's rotate-secret tool on this machine with stand-in system tools (no sandbox). Used by the tests."""
import subprocess

FAKES = {
    "id": '#!/bin/sh\nif [ "$1" = -u ] && [ -n "$2" ]; then case "$2" in lucia|dana|deploy) echo 1001;; *) exit 1;; esac; else echo 0; fi\n',
    "chpasswd": '#!/bin/sh\ncat >> "$FAKEROOT/chpasswd.log"\n',
    "passwd": "#!/bin/sh\necho \"$2 P 2024-01-01 0 99999 7 -1\"\n",
    "logger": "#!/bin/sh\n:\n",
    "hostname": "#!/bin/sh\necho web-01\n",
    "service": "#!/bin/sh\n:\n",
}


def run_tool(tmp, text, *args):
    root = tmp / f"tool{len(list(tmp.glob('tool*')))}"
    (root / "bin").mkdir(parents=True)
    (root / "vault").mkdir()
    for name, body in FAKES.items():
        (root / "bin" / name).write_text(body)
        (root / "bin" / name).chmod(0o755)
    tool = root / "rotate-secret"
    tool.write_text(text.replace("VAULT=/var/lib/larkspur/vault", f"VAULT={root}/vault"))
    p = subprocess.run(["bash", str(tool), *args], capture_output=True, text=True,
                       env={"PATH": f"{root}/bin:/usr/bin:/bin", "FAKEROOT": str(root)})
    return p, root
