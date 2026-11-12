"""Langfuse export: one trace per agent per episode, from the episode's own transcripts (runs/<id>/*.jsonl).

  trace       live-defense-bench/<attacker|defender>; session = <batch>/<episode>, so both agents sit side by side
  generation  each model call: model, token usage, the tool results it was given, its output
  span        each shell command: the command, its output
  event       each defender report, and control-plane steps (scripted proofs)
  score       the episode scores, on the defender's trace

Ids come from the run id and the role, so a second export of a run replaces its traces instead of adding more.
Sent: prompts, transcripts and scores. Never sent: answers, checks, state snapshots.
Keys: LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY, LANGFUSE_HOST in the environment (or .env). Off by default: an
episode exports only with KL_LANGFUSE=1.
"""
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx

PROMPTS = Path(__file__).parent / "prompts"
BATCH_BYTES = 3_000_000


def settings():
    env = {k: os.environ.get(k) for k in ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "LANGFUSE_HOST")}
    if not all(env.values()):
        return None
    host = env["LANGFUSE_HOST"].rstrip("/")
    return {**env, "LANGFUSE_HOST": host if host.startswith("http") else "https://" + host}


def ts(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat().replace("+00:00", "Z")


def uid(*parts):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "live-defense-bench/" + "/".join(parts)))


def load_jsonl(p):
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.exists() else []


def usage(u):
    if not u:
        return None
    i = u.get("input_tokens", u.get("prompt_tokens"))
    o = u.get("output_tokens", u.get("completion_tokens"))
    return {"input": i, "output": o, "unit": "TOKENS"} if i is not None or o is not None else None


def events(run_id, role, spec, system, task, records, start, end, meta, scores):
    """Ingestion events for one agent's trace."""
    tid = uid(run_id, role)
    model = spec.split(":", 1)[-1].split("@")[0] if ":" in spec else spec
    out = [{"type": "trace-create", "body": {
        "id": tid, "timestamp": ts(start), "name": f"live-defense-bench/{role}", "sessionId": run_id,
        "tags": ["live-defense-bench", role, spec.split(":")[0]], "input": {"system": system, "task": task},
        "output": {"scores": scores} if scores else None, "metadata": {**meta, "role": role, "agent": spec}}}]
    last, pending, n = start, [], 0
    for i, r in enumerate(records):
        n += 1
        k, t = r.get("kind"), r.get("t", last)
        oid = uid(run_id, role, str(i))
        if k == "model":
            out.append({"type": "generation-create", "body": {
                "id": oid, "traceId": tid, "name": "model", "startTime": ts(last), "endTime": ts(t), "model": model,
                "input": pending or task, "output": r.get("content"), "usage": usage(r.get("usage")),
                "metadata": {"stop": r.get("stop")}}})
            pending = []
        elif k == "shell":
            nxt = records[i + 1] if i + 1 < len(records) and records[i + 1].get("kind") == "output" else {}
            output = nxt.get("output")
            out.append({"type": "span-create", "body": {
                "id": oid, "traceId": tid, "name": "shell", "startTime": ts(t), "endTime": ts(nxt.get("t", t)),
                "input": {"command": r.get("command"), "timeout": r.get("timeout")}, "output": output}})
            pending.append({"command": r.get("command"), "output": output})
        elif k == "output":
            pass  # with its shell span
        elif k == "report":
            body = {key: r.get(key) for key in ("under_attack", "attacker_ips", "summary")}
            out.append({"type": "event-create", "body": {"id": oid, "traceId": tid, "name": "report",
                                                         "startTime": ts(t), "input": body}})
            pending.append({"report": body})
        else:
            out.append({"type": "event-create", "body": {"id": oid, "traceId": tid, "name": k or "note",
                                                         "startTime": ts(t), "output": r.get("output")}})
        last = t
    for name, value in (scores or {}).items():
        if value is not None and role == "defender":
            out.append({"type": "score-create", "body": {"id": uid(run_id, role, "score", name), "traceId": tid,
                                                         "name": name, "value": float(value), "dataType": "NUMERIC"}})
    stamp = ts(end)
    return [{"id": uid(run_id, role, "event", str(j)), "timestamp": stamp, **e} for j, e in enumerate(out)], tid, n


def export(run_dir):
    """Send one episode's traces. Returns {role: trace url}, or None without keys."""
    cfg = settings()
    if cfg is None:
        return None
    d = Path(run_dir)
    run_id = f"{d.resolve().parent.name}/{d.name}"  # runs/<batch>/<episode>: episode ids repeat across batches
    ep = json.loads((d / "episode.json").read_text())
    tl = json.loads((d / "timeline.json").read_text()) if (d / "timeline.json").exists() else {}
    args = json.loads((d / "args.json").read_text()) if (d / "args.json").exists() else {}
    scores = json.loads((d / "scores.json").read_text())["scores"] if (d / "scores.json").exists() else None
    meta = {"episode": run_id, "defender_prompt": args.get("defender_prompt", "told"), "domain": ep.get("domain"), "flaws": ep.get("flaws"), "seed": ep.get("seed"),
            "attacker_ips": ep.get("attacker_ips"), "target_ip": ep.get("target_ip"), "timeline": tl}
    end = tl.get("checked") or tl.get("live_end") or 0
    batch, urls = [], {}
    atk_task = f"Target: web-01 at {ep.get('target_ip')} ({ep.get('domain')})."
    atk_spec = args.get("attacker") or ("standin" if args.get("standin") else None)
    agents = []
    # One trace per attacker transcript: each operator of --attackers N has its own, as the second wave does
    # Without this, half of a two-operator shift would be missing here.
    for path in sorted(d.glob("attacker*.jsonl"), key=lambda p: (p.name != "attacker.jsonl", p.name)):
        role = path.stem
        prompt = d / f"{role}_prompt.md"
        if not prompt.exists():
            prompt = d / "attacker_prompt.md"
        start = tl.get("wave2_start") if role.endswith("wave2") else tl.get("attack_start")
        agents.append((role, atk_spec, prompt.read_text() if prompt.exists() else None, atk_task, start))
    agents += [("defender", args.get("defender", "unknown"),
               (d / "defender_prompt.md" if (d / "defender_prompt.md").exists() else PROMPTS / "defender.md").read_text(),
                "Start now.",
                tl.get("live_start"))]
    for role, spec, system, task, start in agents:
        records = load_jsonl(d / f"{role}.jsonl")
        if not records or not spec or start is None:
            continue
        evs, tid, _ = events(run_id, role, spec, system, task, records, start, end or records[-1]["t"], meta, scores)
        batch += evs
        urls[role] = f"{cfg['LANGFUSE_HOST']}/trace/{tid}"
    auth = (cfg["LANGFUSE_PUBLIC_KEY"], cfg["LANGFUSE_SECRET_KEY"])
    chunk, size = [], 0
    with httpx.Client(timeout=60) as client:
        for e in batch + [None]:
            line = len(json.dumps(e)) if e else 0
            if chunk and (e is None or size + line > BATCH_BYTES):
                r = client.post(f"{cfg['LANGFUSE_HOST']}/api/public/ingestion", auth=auth, json={"batch": chunk})
                r.raise_for_status()
                errors = r.json().get("errors") or []
                if errors:
                    raise RuntimeError(f"Langfuse rejected {len(errors)} events: {json.dumps(errors[:3])[:600]}")
                chunk, size = [], 0
            if e:
                chunk.append(e)
                size += line
    return urls
