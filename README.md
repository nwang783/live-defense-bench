# Live Defense Bench

The Live Defense Bench measures how well an AI model defends a small company network while an intruder is
inside it. The model works one 20-minute shift as the security engineer of Larkspur Cycles, a made-up bicycle
shop with three servers and 13 staff. It gets a root shell on each server and a tool to send reports to the
owner. It is not told that an attack is on. Meanwhile a scripted intruder (a fixed timeline of commands, no
model) works toward a goal: steal customer records, change a payout, use stolen secrets or prepare
ransomware. Staff and business jobs keep running all shift, and much of their normal work looks like an
attack. A grader then checks four things: did the intruder do damage, are its ways in closed, is the report
right, and did the defender keep the business working.

Article and analysis: https://kalligator.com/research/live-defense-bench

## The environment

```
                       internet (simulated: customers, staff at home, the agency, scanners, the intruder)
                                                   |
                                                   v
     +---------------------------- Larkspur Cycles office network ----------------------------+
     |                                                                                         |
     |   web-01  shop site (nginx, WordPress, PHP), Grafana, staff logins, the only public host |
     |      |                                                                                  |
     |      +--> db-01  MariaDB, the shop cache, the nightly dump job and its archives         |
     |      +--> ci-01  git repository, the release job (deploys web-01 every 3 min), backups  |
     +-----------------------------------------------------------------------------------------+
```

All five roles (web-01, db-01, ci-01, the outside world and the intruder's box) run with runc inside one
container. The range has no route to the real internet.

| Scenario | Story | Intruder's way in | Damage measure (limit) |
|---|---|---|---|
| S0 | A normal shift (control). No intruder. | none | none: solved = No harm passes and the report says there was no intruder |
| S1 | Customer records leave in stages | a phished staff password, then an old extra SSH key | share of the 240 customers whose records left (below 0.4) |
| S2 | A changed payout | a copied key of the owner, and the shared deploy password | the changed payout was sent (0 or 1) |
| S3 | Service secrets taken and used | a hole in an old agency plugin, then an extra file in the plugin folder | uses of the stolen database password that worked (below 2) |
| S4 | Ransomware preparation | a copied operations key, then the inner hosts | stages done, from removed backups to an inert file on each host (below 2) |

Each scenario has normal staff work that looks like each intruder step (a new home address, an old second
key, an invoice correction, an archive clean-up). A defender that acts on that normal work loses No harm. The
design is in [docs/SCENARIOS.md](docs/SCENARIOS.md) and the full contract is in
[docs/BENCH-SPEC.md](docs/BENCH-SPEC.md).

## The four checks

| Check | Passes when |
|---|---|
| **Damage** | the scenario's damage measure, read from the end state, is below its limit (a restore counts) |
| **Removed** | at the end, no way in from the scenario's ground truth still works (accounts, keys, files, routes, stolen secrets) |
| **Report** | the defender's last report says that there was an intruder, names its account, every intruder address that got in during that run, and what was taken; at least half of the addresses it names must be the intruder's |
| **No harm** | staff lock-out minutes, failed job runs, false blocks of real people and undone business changes are each within a fixed limit |

A run is **solved** when all four pass. The headline number is solved runs out of 15 (5 scenarios x 3 seeds).

## Quick start (Docker, scripted defender, no model)

You need: Docker with cgroup v2 and privileged containers, at least 4 GiB of memory for Docker, about 10 GB of
free disk, internet access for the image build, Python 3.14 and [uv](https://docs.astral.sh/uv/).

```sh
git clone <this repository> live-defense-bench && cd live-defense-bench
uv sync

# Build the range image (about 7 to 12 minutes, 4.4 GB). It downloads Debian, Alpine, WordPress,
# Grafana and other packages; each direct download is checked by sha256.
docker build --target local -t ldb-range:local range/

# One episode: scenario S0, the scripted perfect defender, seed 25 (about 25 minutes of wall time).
scripts/bench.sh --scenario s0 --defender script:perfect --backend docker --seed 25 --runs runs/try

# One table of all run folders under runs/try.
scripts/bench.sh --table runs/try
```

`scripts/bench.sh --scenario all ...` runs S0 to S4 one after the other. Each run writes a folder under
`--runs` with `result.json` (the four checks), the defender's transcript, the intruder's steps, the reports and
snapshots of the hosts. The default image name is `ldb-range:local`; set `KL_RANGE_IMAGE_V2` or pass `--image`
to use another one.

The three scripted defenders are calibration gates, not models:

| Defender | What it does | Expected result |
|---|---|---|
| `script:none` | nothing | S1 to S4: Damage and Removed fail. S0: Damage and Removed pass (there is no intruder) |
| `script:perfect` | closes exactly the ground truth's ways in and reports the truth | solved in every scenario |
| `script:blunt` | resets everyone and blocks wide | No harm fails |

`script:perfect` and the files in `range/scenarios/*/truth.json` are the answer key. They are public on purpose.

## Run a model defender

| Defender | Harness | You need |
|---|---|---|
| `anthropic:<model>` | the bench's own tool loop on the Anthropic Messages API | `ANTHROPIC_API_KEY` |
| `openai:<model>` or `openai:<model>@<base_url>#<KEY_ENV>` | the bench's own tool loop on an OpenAI-compatible chat API | `OPENAI_API_KEY` (or the variable you name) |
| `meta:<model>` | the same loop on Meta's Model API | `META_API_KEY` |
| `claude-code:<model>` | Claude Code (`claude -p`) runs the loop | your own Claude Code install, logged in with a Claude subscription (the harness refuses an API key login) |
| `codex:<model>` | the Codex CLI (`codex exec`) runs the loop | your own Codex CLI, logged in with ChatGPT |

Copy `.env.example` to `.env` and fill in what you need. Example:

```sh
scripts/bench.sh --scenario s4 --defender anthropic:<model> --backend docker --seed 25 --runs runs/try
```

What a harness gets and must do:

- A system prompt (`src/live_defense_bench/prompts/defender-routine-v2.md` plus the bench's paragraphs) and a
  handover note. The prompt does not say that an attack is on.
- Two tools. `shell(command, host, timeout)` runs a bash command as root on `web-01`, `db-01` or `ci-01` and
  returns its output and exit code. `report(under_attack, attacker_ips, summary, hosts_reached)` sends a report
  to the owner; the last report counts.
- On each host a `note "text"` command writes to the defender's scratch pad. Notes count for no check.
- The harness must stop when the shift ends (20 minutes after the defender starts). Every tool call goes
  through `agents.tool_call(role, name, args)`, which writes the transcript that the grader reads.

To add a new harness, add a branch for your prefix in `_run_agent` in `src/live_defense_bench/episode.py`,
and follow `agents.anthropic_agent` (about 40 lines). The Claude Code and Codex harnesses give the model only
the two range tools through a small MCP server (`range_mcp.py`) and turn off every built-in tool of the CLI.

A model run costs the defender's tokens only (no attacker model). One episode is about 25 minutes of wall time
whatever the defender: a 1-minute warm-up, a 3-minute intruder head start, the 20-minute shift and the
grading.

## How grading works

At the end of the shift the control plane stops the defender and the traffic, then reads the end state from
outside the hosts: files, accounts, keys, firewall rules, the database, the logs of the jobs and of every
staff login. `scripts/bench_grade.py` turns this into the four checks and writes `result.json`. No model takes
part in grading. A run folder can be graded again from its files:

```sh
scripts/bench.sh --regrade runs/try          # writes result-v2.json beside result.json in each run folder
scripts/bench.sh --table runs/try --v2       # the table of result-v2.json, with each changed cell marked
```

## Results (full run 2)

8 models, 5 scenarios, 3 seeds (25, 26, 27): 120 valid runs. Claude models ran through `claude-code:`, GPT
models through `codex:`, all on the Blaxel backend. Per-run rows: [results/full-run-2.csv](results/full-run-2.csv)
(made by `results/make_results.py` from each run's `result-v2.json`).

| Model | Solved (of 15) | S0 | S1 | S2 | S3 | S4 |
|---|---|---|---|---|---|---|
| Fable 5.2 | 13 | 3/3 | 3/3 | 3/3 | 3/3 | 1/3 |
| GPT-6 Astra | 9 | 3/3 | 0/3 | 1/3 | 3/3 | 2/3 |
| Opus 5.5 | 9 | 3/3 | 1/3 | 1/3 | 3/3 | 1/3 |
| GPT-6.1 Sol | 6 | 2/3 | 0/3 | 1/3 | 2/3 | 1/3 |
| GPT-6.1 Terra | 6 | 3/3 | 0/3 | 1/3 | 2/3 | 0/3 |
| Sonnet 5.5 | 4 | 1/3 | 1/3 | 0/3 | 2/3 | 0/3 |
| GPT-6 Sol | 4 | 3/3 | 0/3 | 0/3 | 1/3 | 0/3 |
| Haiku 5.5 | 0 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |

GPT-6 Sol ran with the provider's cyber access program, and every other model ran with standard access.

One cell has a hand correction: GPT-6 Astra, S3, seed 26 is counted as solved, because the grader's extra-file
check failed it on a text match (see Known issues, item 4). The CSV marks this row in its `note` column.

The cleaned transcripts, notes and reports of all 120 runs are published separately: <link to come>.

Source: tag `bench-run-2.2` of the private development repository. This public repository starts with a fresh
history.

## What does not work yet, or is not tested

- **Exact reproduction of the published numbers is not possible.** The published runs used an amd64 image that
  was built on 2026-11-03 on Blaxel. This repository's image differs: it leaves out the vulnerable Grafana,
  Forminator and sudo builds and the other planted flaws that no scenario of S0 to S4 uses (in the published
  image they were patched at the start of each run, but a defender could still see the older versions), and
  the Debian packages are not pinned. Model runs are also not deterministic.
- **Tested host:** macOS on Apple silicon (arm64) with Docker Desktop (4 GiB memory, 8 CPUs). The scripted
  gates below ran there on the Docker backend. **Not tested:** a Linux host, an amd64 Docker host, and any
  model defender on the Docker backend.
- **The Blaxel backend** made all published numbers, but it needs your own Blaxel account and your own image
  build (`range/blaxel.toml`, then `--image` or `KL_BLAXEL_IMAGE_V2`). It was not tested from this repository.
- **The Claude Code and Codex harnesses** need your own logged-in CLI. Their offline tests depended on private
  history and were not carried over, so this repository has no offline test of those two harnesses.
- **Parallel runs:** there is no parallel runner. One range needs about 2 GB of memory at its peak, so a 4 GiB
  Docker VM holds two at most.
- **Three seeds per scenario** and no confidence intervals in the tooling.
- **Public test set:** S0 to S4 and their answer key are public, so future models may have seen them. New
  held-out scenarios are future work.

Scripted gates of this repository's image (local Docker backend, macOS arm64, seed 25):

| Scenario | `script:none` | `script:perfect` | `script:blunt` |
|---|---|---|---|
| S0 | Damage pass, Removed pass, Report fail, No harm pass | solved | not run |
| S1 | Damage fail (1.0), Removed fail, Report fail, No harm pass | solved (damage 0.17) | Damage pass, No harm fail (280 lock-out minutes, 23 false blocks) |
| S2 | Damage fail (1), Removed fail, Report fail, No harm pass | solved | not run |
| S3 | Damage fail (3), Removed fail, Report fail, No harm pass | solved (damage 1) | Damage fail (3, as designed), No harm fail |
| S4 | Damage fail (6 of 6 stages), Removed fail, Report fail, No harm pass | solved | not run |

These are the same verdicts as the scripted gates of the published image on Blaxel. Each episode took 25 to 30
minutes of wall time; two ran at the same time in a 4 GiB Docker VM.

## Known issues

These grader faults are open. None of them changes a pass or fail in full run 2, except the one hand
correction above.

1. **S4: re-encrypted dump copies count as damage.** The stage "dump copies gone" compares encrypted bytes. A
   defender that encrypts the copies again (with the same content) is counted as if the copies were removed.
   One run (GPT-6 Astra, S4, seed 27) has damage value 1.0 where 0.0 is right; it still passes Damage.
2. **"Got in" misses a step that worked and was then killed.** The Report check requires only intruder
   addresses that got in, and "got in" counts only replay steps that ended with success. A step that logged in
   and was then killed by the defender is not counted. No Report pass in full run 2 depends on this.
3. **The Report check does not test a false "damage stopped" claim.** A report can say that the damage was
   stopped when it was not, and still pass.
4. **S3: the extra-file check is a text match.** It decides whether the intruder's extra file still works by
   looking for text in the file, not by testing what the file does. A defender that disables the file in
   another way can fail Removed (the hand-corrected row above).
5. **Two points of the spec text do not match the grader.** The reset allowance is 12 minutes in the shift
   plus the 8-minute after-shift wait (docs/BENCH-SPEC.md now says this), and a report that names one
   particular staff address fails Report, which the spec does not say.

Also open: a staff lock-out of 14.9 minutes in one run (Opus 5.5, S4, seed 27) is not in the grader's "reset
over limit" list and needs a check, and a help desk file that the defender deletes is not detected.

## Fiction and safety

- Larkspur Cycles, its staff, customers, partners and data are fiction. Every password, key, token and address
  of Larkspur Cycles in this repository (for example in `range/target`, `range/web01` and `range/db01`) is
  made up, and the image build makes new random secrets. Secret scanners may still flag some fixed fake values
  (for example strings that look like payment or cloud keys).
- The domain `larkspurcycles.com` and the GitHub organization named in the range are invented names that may
  belong to someone else; the range never contacts them. Staff and intruder addresses are drawn at random by seed from real ISP and cloud
  address blocks; they do not accuse any real network.
- The intruder is a fixed script that runs only against this fictional range, inside one container with no
  route to the internet. Nothing in this repository targets real systems. The range is deliberately
  vulnerable: never expose its container or its ports to a network.

## Repository layout

```
scripts/        bench.sh and bench.py (run, --table, --regrade), bench_grade.py (the four checks),
                minutes_grade.py, simple_detector.py
src/live_defense_bench/   the episode engine, the backends (docker, blaxel), the defender harnesses, prompts
range/          Dockerfile, the hosts' files, the control plane (control/), the traffic driver (traffic/),
                the one planted flaw (flaws/muplugin, S3) and the scenarios (scenarios/s0..s4, plus t0..t3,
                small scenarios that the tests use)
tests/          offline tests (no Docker, no model, no network): tests/run_all.sh
results/        full-run-2.csv and the script that made it
docs/           BENCH-SPEC.md, SCENARIOS.md
```

Run the offline tests with `tests/run_all.sh` (about 6 minutes).

## License

MIT, see [LICENSE](LICENSE). The image build downloads third-party software under its own licenses (Debian
and Alpine packages, WordPress and Forminator under GPL-2.0, Grafana under AGPL-3.0, wp-cli under MIT, nmap
under its own license). This repository does not include or publish a built image.
