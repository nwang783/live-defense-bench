#!/bin/sh
# The Live Defense Bench, one command (docs/BENCH-SPEC.md).
#
#   scripts/bench.sh --scenario <id|all> --defender <model or script:name> --backend <blaxel|docker> --seed N
#   scripts/bench.sh --table RUN_DIR [...]      one table from many run folders
#   scripts/bench.sh --regrade RUNS_DIR [...]   grade each run folder again from its files (result-v2.json)
#   scripts/bench.sh --table RUN_DIR --v2       the table of result-v2.json, with each changed cell marked
#
# It sets the spec's fixed settings, runs the episode(s) and prints the four checks. See scripts/bench.py.
cd "$(dirname "$0")/.." || exit 1
if [ "${1:-}" = "--table" ]; then
    shift
    exec uv run python scripts/bench_grade.py --table "$@"
fi
if [ "${1:-}" = "--regrade" ]; then
    shift
    exec uv run python scripts/bench_grade.py --regrade "$@"
fi
exec uv run python scripts/bench.py "$@"
