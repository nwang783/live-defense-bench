#!/bin/sh
# Run every offline test: no sandbox, no Docker, no model, no network. About 6 minutes.
#   tests/run_all.sh
cd "$(dirname "$0")/.." || exit 1
fail=0
for t in tests/check_scenarios.py tests/v2_*.py; do
    printf '%s: ' "$t"
    out=$(uv run python "$t" 2>&1)
    rc=$?
    echo "$out" | tail -1
    [ $rc -eq 0 ] || { fail=1; echo "  FAILED (exit $rc)"; }
done
exit $fail
