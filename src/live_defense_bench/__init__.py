"""Live Defense Bench: run episodes and grade them."""
import argparse
from pathlib import Path

from dotenv import load_dotenv

REPO = Path(__file__).resolve().parents[2]


def build_parser() -> argparse.ArgumentParser:
    """The command line itself. Separate from main() so that a test can build the same arguments an episode
    gets, instead of a hand-written copy of them that drifts."""
    ap = argparse.ArgumentParser(prog="live-defense-bench")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("episode", help="run one episode")
    # docker is the bench's name for local: the same LocalBackend.
    e.add_argument("--backend", choices=["local", "docker", "blaxel"], default="local")
    e.add_argument("--defender", default="scripted:do-nothing",
                   help="script:<none|blunt|perfect> (the bench's calibration defenders) | anthropic:<model> | "
                        "openai:<model>[@<base_url>][#<key env>] | meta:<model> | codex:<model> (e.g. codex:gpt-6-sol: "
                        "through the Codex CLI on your ChatGPT login, its only tools the "
                        "defender's own shell and report) | claude-code:<model> (e.g. "
                        "claude-code:claude-opus-5-5: through Claude Code, `claude -p`, on your Claude "
                        "subscription login, its only tools the defender's own shell and report)")
    # Options of an older research mode that is not part of the bench. They are kept so that the episode code
    # stays as it was tested, but they are hidden from --help and not documented.
    e.add_argument("--attacker", help=argparse.SUPPRESS)
    e.add_argument("--quiet-attacker", help=argparse.SUPPRESS)
    e.add_argument("--attacker-effort", choices=["low", "medium", "high", "xhigh", "max"], help=argparse.SUPPRESS)
    e.add_argument("--defender-effort", choices=["low", "medium", "high", "xhigh", "max"], default="high",
                   help="effort for an anthropic:, codex: or claude-code: defender")
    e.add_argument("--attacker-prompt", help=argparse.SUPPRESS)
    e.add_argument("--attackers", type=int, default=1, help=argparse.SUPPRESS)
    e.add_argument("--attacker-shell-cap", type=int, default=30, help=argparse.SUPPRESS)
    e.add_argument("--attacker-style", choices=["loud", "stealth"], default="loud", help=argparse.SUPPRESS)
    e.add_argument("--attacker-quiet-prompt", choices=["v2", "v3", "v4", "v5"], default="v2", help=argparse.SUPPRESS)
    e.add_argument("--attacker-guide", choices=["on", "off"], default="off", help=argparse.SUPPRESS)
    e.add_argument("--flaws", help="all | none | comma list of flaw ids (default: all with an attacker or stand-in, "
                                   "none on a quiet episode)")
    e.add_argument("--standin", action="store_true", help=argparse.SUPPRESS)
    # Unset by default, so every earlier episode runs as it did.
    e.add_argument("--intruder",
                   help="replay:<id>: the intruder is the fixed timeline of range/scenarios/<id>/, played from "
                        "the attacker role with no model (docs/BENCH-SPEC.md). Not with --attacker or --standin")
    e.add_argument("--script-at", type=int,
                   help="seconds after the shift start when --defender script:perfect acts (default: the "
                        "scenario's perfect_at_s, else the middle of the shift)")
    e.add_argument("--warmup", type=int, default=60,
                   help="seconds of benign traffic before the attacker starts (the availability baseline)")
    e.add_argument("--head-start", type=int, default=0, help="seconds the attacker works before the defender starts")
    e.add_argument("--defender-prompt", choices=["told", "monitor", "wave", "audit", "routine"], default="told",
                   help="told: an attack may be happening now; monitor: routine watch, maybe no attack; "
                        "wave: told, plus watch the whole shift, close the holes, rotate-secret; "
                        "audit: wave, plus review the whole server for other weaknesses; "
                        "routine (v2 only): the security engineer's normal shift -- audit the three servers, act "
                        "on what is found, keep the business running -- with no word of an attack "
                        "")
    # Range v2. The network is always on in v2; these are the two switches, and each
    # changes one thing from the base.
    e.add_argument("--business", choices=["on", "off"], default="off",
                   help="on: staff and partner traffic that depends on the company's jobs, and the jobs are "
                        "scored (deploys, the shop database, the dumps, the payout check)")
    # Off by default, so every earlier run replays with the traffic it had.
    e.add_argument("--crowd", choices=["on", "off"], default="off",
                   help="on (v2): the company's 13 people with server logins work all run, each from a usual "
                        "address of their own, with the normal noise (second addresses, mistyped passwords, a "
                        "one-time contractor, sessions left open), and more visitors, crawlers and WordPress "
                        "logins")
    e.add_argument("--foothold", choices=["none", "user"], default="none",
                   help="user: the attacker starts with a staff SSH password on web-01 (a phished login)")
    # shared by default, so every earlier run replays as it was.
    e.add_argument("--quiet-foothold", choices=["shared", "separate"], default="shared", help=argparse.SUPPRESS)
    # off and 1 by default, so every earlier run replays as it was.
    e.add_argument("--rotation-cost", choices=["off", "helpdesk"], default="off",
                   help="helpdesk (v2): a person's password that rotate-secret or the defender changes reaches "
                        "the person only through the help desk, after --helpdesk-wait seconds; and the payment "
                        "key, the bucket key and the site's database password each have a second real user that "
                        "rotate-secret does not update")
    e.add_argument("--helpdesk-wait", type=int, default=480,
                   help="seconds the help desk takes to give a person a new password (with --rotation-cost helpdesk)")
    e.add_argument("--attacker-pool", type=int, default=1, help=argparse.SUPPRESS)
    # off by default, so every earlier run replays as it was; when not given
    # neither switch is in args.json at all (every reader takes "off" for a missing one).
    e.add_argument("--twins", choices=["on", "off"], default=argparse.SUPPRESS,
                   help="on (v2, with --crowd on): the bench profile -- normal work that looks like an attack "
                        "(new addresses, old second keys, customer exports, invoice corrections, deploy logins, "
                        "the agency's support calls, a left-over file, jumps through web-01, archive clean-up, "
                        "maintenance steps), drawn from the seed; benign-changes.json at the end")
    # On for a replay with the routine prompt; when not given it is not in args.json.
    e.add_argument("--ask-staff", choices=["on", "off"], default=argparse.SUPPRESS,
                   help="off: a replay's defender gets no ask_staff and staff_replies tools and no sentences about "
                        "them in its prompt (default on; every other episode never has them)")
    # the defender's scratch pad. Off when not given (every earlier episode); scripts/bench.py sets it.
    e.add_argument("--notes", choices=["on", "off"], default=argparse.SUPPRESS,
                   help="on (v2): a `note \"text\"` command on each company host and one paragraph about it in the "
                        "routine prompt; the notes go to notes.jsonl and count for nothing")
    e.add_argument("--detector", choices=["on", "off"], default=argparse.SUPPRESS,
                   help="on: scripts/simple_detector.py runs through the defender's own root shell at +3, +10 "
                        "and +18 minutes of the shift, into detector.json (no model)")
    e.add_argument("--range", choices=["auto", "v1", "v2"], default="auto",
                   help="which range the image is; auto asks the image (a v2 image carries db-01 and ci-01)")
    e.add_argument("--image", help="the sandbox image. Without it: KL_BLAXEL_IMAGE_V2 when --range is v2, "
                                   "else KL_BLAXEL_IMAGE (blaxel) or KL_RANGE_IMAGE (local)")
    e.add_argument("--quiet", action="store_true", help=argparse.SUPPRESS)
    e.add_argument("--wave2-at", type=int, default=0, help=argparse.SUPPRESS)
    e.add_argument("--live", type=int, default=1800)
    e.add_argument("--rate", type=float, default=1.0, help="benign traffic rate (>1 is busier)")
    e.add_argument("--seed", type=int)
    e.add_argument("--id")
    e.add_argument("--runs", default="runs")
    e.add_argument("--keep", action="store_true", help="keep the range running afterwards")
    tr = sub.add_parser("trace", help="send a finished episode to your own Langfuse project (optional; needs "
                                      "LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY and LANGFUSE_HOST)")
    tr.add_argument("run_dir")
    return ap


def check_args(ap, args) -> None:
    """The combinations an episode cannot run, refused before anything is created."""
    if args.cmd != "episode":
        return
    if args.attacker and args.standin:
        ap.error("--attacker and --standin are exclusive")
    check_replay_args(ap, args)
    if args.attackers < 1:
        ap.error("--attackers must be at least 1")
    if str(getattr(args, "defender", "")).startswith("codex:") and not args.defender.partition(":")[2]:
        ap.error("--defender codex: needs a model (codex:gpt-6-sol)")
    if str(getattr(args, "defender", "")).startswith("claude-code:") and not args.defender.partition(":")[2]:
        ap.error("--defender claude-code: needs a model (claude-code:claude-opus-5-5)")
    if args.attacker_pool < 1:
        ap.error("--attacker-pool must be at least 1")
    if args.helpdesk_wait < 0:
        ap.error("--helpdesk-wait must be 0 or more")
    if getattr(args, "twins", "off") == "on":
        if getattr(args, "crowd", "off") != "on":
            ap.error("--twins on needs --crowd on (the normal work is the staff's)")
        if getattr(args, "range", "auto") == "v1":
            ap.error("--twins is for a v2 range")
    if getattr(args, "range", "auto") == "v1" and (args.rotation_cost != "off" or args.attacker_pool > 1):
        ap.error("--rotation-cost and --attacker-pool are for a v2 range")
    # Two shapes of a second attacker that would be impossible to tell apart in the transcripts and in the
    # scores: pick one.
    if args.attackers > 1 and args.wave2_at:
        ap.error("--attackers > 1 and --wave2-at are exclusive: attackers start together, a wave starts later")
    # Stealth is a decoy plus a quiet operator: exactly two attackers, and no second wave.
    if getattr(args, "attacker_style", "loud") == "stealth" and args.attackers != 2:
        ap.error("--attacker-style stealth needs --attackers 2 (operator 1 the decoy, operator 2 the quiet one)")
    # A model of its own for the quiet operator: there must be a quiet
    # operator to give it to, and a decoy model for operator 1 to stay on.
    if getattr(args, "quiet_attacker", None):
        if getattr(args, "attacker_style", "loud") != "stealth":
            ap.error("--quiet-attacker needs --attacker-style stealth (it is the quiet operator's model)")
        if not args.attacker:
            ap.error("--quiet-attacker needs --attacker as well (the decoy's model)")
        if args.quiet_attacker.partition(":")[0] not in ("anthropic", "openai", "scripted", "codex"):
            ap.error("--quiet-attacker takes the same forms as --attacker "
                     "(anthropic:<model> | openai:<model>[@<base_url>][#<key env>]) or codex:<model>")
        if args.quiet_attacker.startswith("codex:") and not args.quiet_attacker.partition(":")[2]:
            ap.error("--quiet-attacker codex: needs a model (codex:gpt-6-sol)")
    # A separate phished account for the quiet operator: there must be a
    # quiet operator, a phished login to give it, and the crowd, in which the account's owner really logs in.
    if getattr(args, "quiet_foothold", "shared") == "separate":
        if getattr(args, "attacker_style", "loud") != "stealth":
            ap.error("--quiet-foothold separate needs --attacker-style stealth (it is the quiet operator's login)")
        if getattr(args, "foothold", "none") != "user":
            ap.error("--quiet-foothold separate needs --foothold user")
        if getattr(args, "crowd", "off") != "on":
            ap.error("--quiet-foothold separate needs --crowd on (the account's owner logs in with the crowd)")
        if getattr(args, "range", "auto") == "v1":
            ap.error("--quiet-foothold separate is for a v2 range")


def check_replay_args(ap, args) -> None:
    """--intruder and --defender script:<name>."""
    spec = str(getattr(args, "defender", "") or "")
    if spec.startswith("script:"):
        from .agents import SCRIPTS
        if spec.partition(":")[2] not in SCRIPTS:
            ap.error(f"--defender script: takes one of {', '.join(SCRIPTS)}")
        if spec == "script:perfect" and not getattr(args, "intruder", None):
            ap.error("--defender script:perfect needs --intruder replay:<id> (it reads the scenario's truth)")
    intruder = getattr(args, "intruder", None)
    if not intruder:
        return
    if not intruder.startswith("replay:") or not intruder.partition(":")[2]:
        ap.error("--intruder takes replay:<id> (a folder of range/scenarios)")
    if args.attacker or args.standin:
        ap.error("--intruder replay: is the whole intruder: not with --attacker or --standin")
    if args.attackers != 1 or args.wave2_at:
        ap.error("--intruder replay: has one timeline: not with --attackers or --wave2-at")
    if args.attacker_pool != 1:
        ap.error("--attacker-pool stays 1 in replay")
    if getattr(args, "range", "auto") == "v1":
        ap.error("--intruder replay: is for a v2 range")
    from .scenario import ScenarioError, load
    try:
        sc = load(intruder.partition(":")[2])["scenario"]
    except ScenarioError as e:
        ap.error(f"--intruder {intruder}: {e}")
    for k, want in sc["switches"].items():
        have = getattr(args, k, None)
        if k == "twins" and have is None:
            # An engine test that needs the bench profile (pinned staff sessions) turns it on itself.
            if want == "on" and getattr(args, "crowd", "off") != "on":
                ap.error(f"--intruder {intruder}: the scenario's switch twins on needs --crowd on")
            args.twins = have = want
        if k != "flaws" and have != want:
            ap.error(f"--intruder {intruder}: the scenario needs --{k} {want} (this run has {have})")


def main() -> None:
    # Keys and settings: the .env file at the repository root (see .env.example), then the environment.
    load_dotenv(REPO / ".env")
    ap = build_parser()
    args = ap.parse_args()
    check_args(ap, args)
    if args.cmd == "trace":
        from .trace import export
        print(export(args.run_dir) or "no Langfuse keys")
        return
    if args.cmd == "episode":
        from .episode import episode
        episode(args)
