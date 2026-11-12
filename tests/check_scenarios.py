#!/usr/bin/env python3
"""Check the scenario folders as the engine reads them. No sandbox, no model.

  uv run python tests/check_scenarios.py [ID ...]      (default: every folder in range/scenarios)

For each scenario: the loader's checks; the same timeline byte for byte for the same seed (1 and 25); the
shell syntax of each step (`bash -n`, secrets filled with a dummy value); the damage measure is one that
scripts/bench_grade.py has; and what the engine reads from the files: the bound staff passwords, the SQL
imports (table and number of ids), the files the measure's steps write, the ways in and the script:perfect
commands' hosts. Exit status 1 when a scenario fails a check.
"""
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts"))

from live_defense_bench import agents, scenario  # noqa: E402
from live_defense_bench.episode import make_episode  # noqa: E402
import bench_grade  # noqa: E402


def one(sid):
    bad = []
    try:
        loaded = scenario.load(sid)
    except scenario.ScenarioError as e:
        return [f"loader: {e}"], {}
    sc = loaded["scenario"]
    flaws = sc["switches"].get("flaws", "none")
    flaws = flaws if flaws in ("all", "none") else sorted(flaws.split(","))
    facts = {"kind": sc.get("kind", "bench"), "measure": sc["damage"]["measure"], "limit": sc["damage"]["limit"],
             "bound": loaded["bind"]}
    if sc["damage"]["measure"] not in bench_grade.MEASURES:
        bad.append(f"no measure {sc['damage']['measure']!r} in bench_grade.py yet")
    res = {}
    for seed in (1, 25):
        # A bench scenario runs with the bench profile (scripts/bench.py), so its range values ({plugin_dir},
        # {spare_handler}) have a value; an engine test runs without it.
        ep = make_episode(seed, True, 1.0, flaws, v2=True, business=True, crowd=True, rotation_cost="helpdesk",
                          helpdesk_wait=480, twins_on=sc.get("kind", "bench") == "bench", shift_s=sc["shift_s"],
                          lead_s=60 + sc["head_start_s"])
        a = scenario.timeline_bytes(scenario.resolve(loaded, seed, ep))
        b = scenario.timeline_bytes(scenario.resolve(loaded, seed, ep))
        if a != b:
            bad.append(f"seed {seed}: the timeline is not the same twice")
        res[seed] = scenario.resolve(loaded, seed, ep)
    r = res[25]
    dummy = {k: "x" * 12 for k in (sc.get("secrets") or {})}
    for s in r["timeline"]:
        if "run" not in s:
            continue
        p = subprocess.run(["bash", "-n"], input=scenario.fill_secrets(s["run"], dummy), text=True,
                           capture_output=True)
        if p.returncode:
            bad.append(f"step {s['n']} ({s['label']}): bash -n: {p.stderr.strip()[:200]}")
    try:
        facts["imports"] = [f"{q['host']} {q['table']}: {len(q['ids'])} ids" for q in scenario.imports(sc)]
    except scenario.ScenarioError as e:
        bad.append(str(e))
    facts["written"] = scenario.written_paths(r)
    facts["steps"] = len(r["timeline"])
    facts["ways_in"] = [f"{w['id']} ({w['kind']}{', ' + w['host'] if w.get('host') else ''})"
                        for w in r["truth"]["ways_in"]]
    facts["perfect_hosts"] = sorted(agents.perfect_commands(r["truth"]))
    return bad, facts


def main(argv):
    ids = argv or scenario.ids()
    failed = 0
    for sid in ids:
        bad, facts = one(sid)
        print(f"== {sid}: {'OK' if not bad else 'FAIL'}")
        for k, v in facts.items():
            print(f"   {k}: {v}")
        for b in bad:
            print(f"   FAIL {b}")
        failed += bool(bad)
    print(f"\n{len(ids) - failed} of {len(ids)} scenarios pass the checks")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
