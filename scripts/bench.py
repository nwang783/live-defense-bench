#!/usr/bin/env python3
"""The Live Defense Bench, one command (docs/BENCH-SPEC.md).

  scripts/bench.sh --scenario <id|all> --defender <model or script:name> --backend <blaxel|docker> --seed N

For each scenario (`all`: every scenario of kind "bench", not the engine tests such as t0-test) it runs one
replay episode with the spec's fixed settings and prints the four checks. The run folder holds result.json
beside every file an episode always writes. A second command makes one table from many run folders:

  scripts/bench.sh --table runs/bench

Fixed settings (docs/BENCH-SPEC.md, "Fixed settings"): a v2 range, --rotation-cost helpdesk, --crowd on,
--defender-prompt routine, --business on (the jobs scored), --attacker-pool 1, a 60 s warm-up, and for every
scenario of kind "bench" the bench profile, --twins on, and the defender's
scratch pad, --notes on (`--notes off` tags the run -nonote). The head
start, the shift and the range switches (flaws, foothold) come from the scenario's own scenario.json.

The defender: a model as the episode takes it (anthropic:<model>, codex:<model>, claude-code:<model>, openai:...) or one of the
scripted calibration defenders, script:none, script:blunt or script:perfect. `--backend docker` is the local
backend (one privileged Docker container; image KL_RANGE_IMAGE_V2 or --image).

The range image: --image, else KL_RANGE_IMAGE_V2 (docker; default ldb-range:local) or KL_BLAXEL_IMAGE_V2 (blaxel,
your own build; there is no default).
"""
import argparse
import json
import pathlib
import sys
import time

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from live_defense_bench import build_parser, check_args, scenario  # noqa: E402


SANDBOX_NAME_MAX = 49  # Blaxel: lowercase letters, digits and hyphens, at most 49 characters


def run_id_for(sid, defender, seed, stamp=None):
    """The run id: scenario, defender, seed, time. A claude-code: defender is written cc- (claude-code:claude-
    sonnet-5-5 in full would make a sandbox name of 51 characters)."""
    spec = "cc:" + defender.partition(":")[2] if defender.startswith("claude-code:") else defender
    who = spec.replace(":", "-").replace("/", "-").replace("@", "-").replace(".", "-")[:40]
    return f"{sid}-{who}-s{seed}-{stamp or time.strftime('%m%d-%H%M%S')}"


def episode_argv(sid, a, run_id):
    """The episode's command line for one scenario: the fixed settings, then the scenario's own."""
    sc = scenario.load(sid)["scenario"]
    sw = sc["switches"]
    argv = ["episode", "--backend", a.backend, "--defender", a.defender, "--intruder", f"replay:{sid}",
            "--range", "v2", "--seed", str(a.seed), "--live", str(sc["shift_s"]),
            "--head-start", str(sc["head_start_s"]), "--warmup", str(a.warmup),
            "--flaws", sw.get("flaws", "none"), "--foothold", sw.get("foothold", "none"),
            "--business", "on", "--crowd", "on", "--rotation-cost", "helpdesk",
            "--defender-prompt", "routine", "--attacker-pool", "1",
            "--runs", a.runs, "--id", run_id]
    # The bench profile: the normal work that looks like an attack is in
    # every bench scenario, S0 too. An engine test (t0-test) keeps the traffic it was calibrated with.
    if sc.get("kind") == "bench":
        argv += ["--twins", "on"]
    if getattr(a, "detector", False):
        argv += ["--detector", "on"]
    image = a.image
    if image:
        argv += ["--image", image]
    if a.keep:
        argv.append("--keep")
    if a.script_at is not None:
        argv += ["--script-at", str(a.script_at)]
    if a.defender_effort:
        argv += ["--defender-effort", a.defender_effort]
    # The defender's scratch pad: on, the bench's fixed setting.
    argv += ["--notes", getattr(a, "notes", "on")]
    if getattr(a, "ask_staff", "off") != "on":
        argv += ["--ask-staff", "off"]
    return argv


def main(argv=None):
    ap = argparse.ArgumentParser(prog="bench.sh")
    ap.add_argument("--scenario", required=True, help="a scenario id (range/scenarios/<id>) or all")
    ap.add_argument("--defender", required=True,
                    help="anthropic:<model> | codex:<model> | claude-code:<model> | meta:<model> | openai:<model>... | "
                         "script:<none|blunt|perfect>")
    ap.add_argument("--backend", choices=["blaxel", "docker"], required=True)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--runs", default="runs/bench", help="where the run folders go (default runs/bench)")
    ap.add_argument("--image", help="the range image (default: KL_RANGE_IMAGE_V2 or ldb-range:local on docker; "
                                       "KL_BLAXEL_IMAGE_V2 on blaxel)")
    ap.add_argument("--warmup", type=int, default=60)
    ap.add_argument("--script-at", type=int, help="when script:perfect acts (s after the shift start)")
    ap.add_argument("--defender-effort", choices=["low", "medium", "high", "xhigh", "max"])
    ap.add_argument("--keep", action="store_true", help="keep the range running afterwards")
    ap.add_argument("--detector", action="store_true",
                    help="run scripts/simple_detector.py at +3, +10 and +18 minutes (detector.json)")
    ap.add_argument("--ask-staff", choices=["on", "off"], default="off",
                    help="on: the defender can message the staff. The bench's fixed "
                         "setting is off (decision of 2026-11-11)")
    ap.add_argument("--notes", choices=["on", "off"], default="on",
                    help="the defender's scratch pad, `note \"text\"` on each host. The bench's fixed "
                         "setting is on; a run with it off gets the tag -nonote")
    ap.add_argument("--dry-run", action="store_true", help="print each episode's command line and stop")
    a = ap.parse_args(argv)

    ids = scenario.ids(kind="bench") if a.scenario == "all" else [a.scenario]
    if not ids:
        raise SystemExit("--scenario all: no scenario of kind bench in range/scenarios yet")
    from dotenv import load_dotenv
    load_dotenv(REPO / ".env")
    parser = build_parser()
    plans = []
    for sid in ids:
        try:
            scenario.load(sid)
        except scenario.ScenarioError as e:
            raise SystemExit(f"scenario {sid}: {e}")
        run_id = run_id_for(sid, a.defender, a.seed)
        # The run id is also the sandbox's name: two runs that differ only in a switch must not share it
        # (2026-11-10: an ask-on and an ask-off run started in the same second and both used one sandbox).
        # Since 2026-11-11 the bench runs with the staff messages off (a decision of the bench's authors); a run with them on
        # is the one that gets the tag.
        if getattr(a, "ask_staff", "off") == "on":
            head, _, stamp = run_id.rpartition("-s%d-" % a.seed)
            run_id = f"{head}-ask-s{a.seed}-{stamp}"
        if getattr(a, "notes", "on") == "off":  # the run without the scratch pad gets the tag
            head, _, stamp = run_id.rpartition("-s%d-" % a.seed)
            run_id = f"{head}-nonote-s{a.seed}-{stamp}"
        # A Blaxel sandbox is named kl-<run id>, and Blaxel takes at most 49 characters.
        if a.backend == "blaxel" and len("kl-" + run_id) > SANDBOX_NAME_MAX:
            raise SystemExit(f"the sandbox name kl-{run_id} is longer than {SANDBOX_NAME_MAX} characters")
        args = parser.parse_args(episode_argv(sid, a, run_id))
        check_args(parser, args)
        plans.append((sid, args))
    if a.dry_run:
        for sid, args in plans:
            print(" ".join(episode_argv(sid, a, args.id)))
        return
    from live_defense_bench.episode import bench_grader, episode
    grader = bench_grader()
    lines = []
    for sid, args in plans:
        print(f"== {sid}: {' '.join(episode_argv(sid, a, args.id)[1:])}", flush=True)
        try:
            episode(args)
        except Exception as e:  # one scenario's failure must not cost the others
            lines.append(f"{sid}: the episode failed: {type(e).__name__}: {str(e)[:300]}")
            print(lines[-1], flush=True)
            continue
        run = pathlib.Path(args.runs) / args.id
        res = (json.loads((run / "result.json").read_text()) if (run / "result.json").exists()
               else grader.write_result(run))
        lines.append(grader.line(res))
    print("\n== the four checks")
    for l in lines:
        print(l)
    print(f"\nrun folders under {a.runs}; one table: scripts/bench.sh --table {a.runs}")


if __name__ == "__main__":
    main()
