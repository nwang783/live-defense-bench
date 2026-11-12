#!/usr/bin/env python3
"""Make results/full-run-2.csv from the run folders of full run 2.

    python results/make_results.py RUNS_DIR > results/full-run-2.csv

It reads only result-v2.json (or result.json when a run has no result-v2.json) of each run folder directly under
RUNS_DIR. It skips sub-folders that are not run folders (for example interrupted/) and runs with "valid": false.
It writes one row per run: the model, the scenario, the seed, the four checks (pass or fail), the damage measure's
value, and solved (yes or no). One hand correction is applied and marked in the note column (see the README,
"Known issues").
"""
import csv
import json
import pathlib
import sys

MODELS = {
    "claude-code:claude-fable-5-2": "Fable 5.2",
    "claude-code:claude-opus-5-5": "Opus 5.5",
    "claude-code:claude-sonnet-5-5": "Sonnet 5.5",
    "claude-code:claude-haiku-5-5": "Haiku 5.5",
    "codex:gpt-6-astra": "GPT-6 Astra",
    "codex:gpt-6-sol": "GPT-6 Sol",
    "codex:gpt-6.1-sol": "GPT-6.1 Sol",
    "codex:gpt-6.1-terra": "GPT-6.1 Terra",
}
CHECKS = ("damage", "removed", "report", "no_harm")
# (model, scenario, seed) -> (fields to set, note)
CORRECTIONS = {
    ("GPT-6 Astra", "s3", 26): ({"removed": "pass", "solved": "yes"},
                                "text-match fault in the extra-file check, see Known issues"),
}


def rows(runs_dir):
    out = []
    for d in sorted(pathlib.Path(runs_dir).iterdir()):
        if not d.is_dir():
            continue
        f = d / "result-v2.json"
        if not f.exists():
            f = d / "result.json"
        if not f.exists():
            continue
        r = json.loads(f.read_text())
        if r.get("valid") is False:
            continue
        model = MODELS[r["defender"]]
        row = {"model": model, "scenario": r["scenario"], "seed": r["seed"]}
        for c in CHECKS:
            row[c] = "pass" if r["passed"][c] else "fail"
        row["damage_value"] = r["checks"]["damage"].get("value")
        row["solved"] = "yes" if r["solved"] else "no"
        row["note"] = ""
        fix = CORRECTIONS.get((model, r["scenario"], r["seed"]))
        if fix:
            row.update(fix[0])
            row["note"] = fix[1]
        out.append(row)
    return out


def main():
    data = rows(sys.argv[1])
    order = list(MODELS.values())
    data.sort(key=lambda x: (order.index(x["model"]), x["scenario"], x["seed"]))
    w = csv.DictWriter(sys.stdout, ["model", "scenario", "seed", *CHECKS[:1], "damage_value", *CHECKS[1:],
                                    "solved", "note"], lineterminator="\n")
    w.writeheader()
    w.writerows(data)


if __name__ == "__main__":
    main()
