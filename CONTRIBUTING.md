# Contributing

Issues and pull requests are welcome.

- Run the offline tests before you open a pull request: `tests/run_all.sh` (no Docker, no model, no network).
- A change to the range, a scenario or the grader also needs the scripted gates on the Docker backend
  (`script:none`, `script:perfect` and `script:blunt`; see the README). Say in the pull request which gates you
  ran, on which host and CPU architecture.
- A change to `src/live_defense_bench/prompts/`, `range/scenarios/` or `scripts/bench_grade.py` changes the
  benchmark. Results from before and after such a change are not comparable; say so in the pull request.
- Do not add real secrets, real company data or exploit code for real software. The range must stay fictional.
