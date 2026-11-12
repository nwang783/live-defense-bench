"""The defender on Claude Code, headless (`claude -p`), on the user's Claude subscription login.

`--defender claude-code:<model>` (e.g. `claude-code:claude-opus-5-5`) runs the defender the way codex_agent runs
`codex:<model>`: Claude Code runs the model loop, and the model's only tools are the defender's own, `shell` (with
its `host`) and `report`, served by the same bridge (codex_agent.Bridge) and the same stdio MCP server
(range_mcp.py). Every call goes through `agents.tool_call(role, ...)`: the same Role, shell cap, deadline and
transcript rows (shell, output, report) as the anthropic defender.

  - The subscription only. The child process gets a small environment built from an allow list (HOME, USER,
    LOGNAME, LANG, TMPDIR, CLAUDE_CONFIG_DIR and a fixed PATH), so no ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN, ANTHROPIC_BASE_URL
    or other provider key or base URL that the bench loads from .env can reach it. Before the first turn
    `claude auth status --json` is run with that same environment, and the run stops with an error row unless
    it says `authMethod: claude.ai`, first party, with no API key source. Claude Code's own `init` event must
    then say `apiKeySource: none`. Both are recorded (`auth_mode`).
  - Only the bench tools. `--tools ""` takes every built-in tool away (Bash, Read, Edit, Write, WebFetch,
    WebSearch, Agent, ...); `--strict-mcp-config --mcp-config <file>` loads the range server and no other;
    `--setting-sources ""` reads no user, project or local settings (so no hooks, no permissions, no MCP servers
    of the user's); `--disable-slash-commands` turns skills and commands off; CLAUDE.md files, auto-memory,
    the advisor tool, background tasks, cron, workflows and non-essential traffic are off by environment
    (ENV_SET). `--permission-mode dontAsk` with `--allowedTools` naming the two range tools denies anything
    else without asking. The working folder is an empty temporary one. The tools that Claude Code really
    offered are read from its `init` event and from the request shape in its session file; any tool that is
    not the range's, or a tool_use of one, stops the run with an error row.
  - The system prompt is the bench's, by `--system-prompt-file` (REPLACE, not append). Claude Code still puts
    one line of its own before it ("You are a Claude agent, built on Anthropic's Claude Agent SDK.") and adds
    context messages of its own (environment, date, model, the account's email); the session file's copy of
    the system prompt is compared with ours and recorded.
  - Compaction is Claude Code's own and stays on; each `compact_boundary` event is a `compaction` row.
  - A turn that ends is an end_turn: the harness waits IDLE_SECONDS and sends the same nudge, with
    `--resume <session id>`. A refusal, a usage limit, a login error or a model that is not available stops the
    defender with an `error` (or `refusal`) row and an `early_stop` row; episode.py then marks the run INVALID.
    A rate limit or a server error is waited out with call_model's ladder. At the end of the shift Claude Code
    is killed.
  - Tokens: one `model` row per API message with its usage, as an anthropic call reports it. The subscription
    costs nothing per token; Claude Code's own API-equivalent price is kept in `cc_result` rows.
"""
import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

from . import agents
from .codex_agent import Bridge, REFUSAL_TEXT, POLICY_WORDS

SHIM = pathlib.Path(__file__).with_name("range_mcp.py")
MCP_NAME = "range"
PREFIX = f"mcp__{MCP_NAME}__"
CLAUDE_DIRS = ("/opt/homebrew/bin", os.path.expanduser("~/.local/bin"), "/usr/local/bin")
SYSTEM_MODE = "replace"  # --system-prompt-file, not --append-system-prompt
# The only variables the child gets from the bench's environment. Everything else (API keys, base URLs,
# Bedrock/Vertex/Foundry switches, the parent Claude Code's own CLAUDE_CODE_* variables) is left behind.
# CLAUDE_CONFIG_DIR is kept when it is set: it is where the subscription login and the session files are.
ENV_KEEP = ("HOME", "USER", "LOGNAME", "LANG", "TMPDIR", "CLAUDE_CONFIG_DIR")
# Claude Code switches, set in the child's environment. Each name is checked against the installed binary by
# the no-model test (tests/v2_claude_code_defender.py).
ENV_SET = {
    "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",          # no auto-memory folder read or written
    "CLAUDE_CODE_DISABLE_CLAUDE_MDS": "1",           # no CLAUDE.md of the user's or of any folder
    "CLAUDE_CODE_DISABLE_ADVISOR_TOOL": "1",         # no second model behind an advisor tool
    "CLAUDE_CODE_DISABLE_BACKGROUND_TASKS": "1",
    "CLAUDE_CODE_DISABLE_CRON": "1",
    "CLAUDE_CODE_DISABLE_WORKFLOWS": "1",
    "CLAUDE_CODE_DISABLE_BUNDLED_SKILLS": "1",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    # The model stays the one asked for: no fallback to another model on a refusal or a model-access error.
    "CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK": "1",
    "CLAUDE_CODE_DISABLE_REFUSAL_RETRY": "1",
    "CLAUDE_CODE_DISABLE_MODEL_ACCESS_FALLBACK": "1",
    "DISABLE_AUTOUPDATER": "1",
    "MCP_TIMEOUT": "60000",                          # the range server's start-up, in ms
}
# Variables that would make Claude Code bill something other than the subscription. None can be in the child's
# environment (it is built from ENV_KEEP); child_env() checks it anyway.
PROVIDER_VARS = re.compile(r"^(ANTHROPIC_|CLAUDE_CODE_USE_|CLAUDE_CODE_OAUTH|AWS_|GOOGLE_|VERTEX|BEDROCK|"
                           r"OPENAI_|AZURE_|CLOUD_ML_)")
# A failed turn that would fail the same way for the rest of the shift: stop, and say why.
FATAL = (("usage_limit", ("usage limit", "hit your limit", "limit reached", "limit will reset", "resets at",
                          "out of extra usage", "weekly limit", "5-hour limit")),
         ("auth", ("authentication", "unauthorized", "invalid api key", "/login", "not logged in", "oauth",
                   "401", "403", "permission_error", "billing")),
         ("model_unavailable", ("model_not_found", "issue with the selected model", "not_found_error",
                                "may not exist", "404", "invalid model")))
EARLY = 30  # a defender that stops with more than this many seconds of the shift left stopped early


def claude_bin():
    # KL_CLAUDE_BIN: a kept copy of the binary. The installed one is replaced in place when Claude Code updates
    # itself from another session, and for a moment there is no file (2026-11-11: two runs stopped on it).
    kept = os.environ.get("KL_CLAUDE_BIN")
    if kept and pathlib.Path(kept).exists():
        return kept
    for d in CLAUDE_DIRS:
        p = pathlib.Path(d) / "claude"
        if p.exists():
            return str(p)
    found = shutil.which("claude")
    if not found:
        raise FileNotFoundError("no claude (Claude Code) on this machine")
    return found


def child_env(cap, environ=None):
    """The child's whole environment: the allow list, a fixed PATH, ENV_SET and the MCP tool timeout."""
    environ = os.environ if environ is None else environ
    env = {k: environ[k] for k in ENV_KEEP if k in environ}
    env["PATH"] = os.pathsep.join([*CLAUDE_DIRS, "/usr/bin", "/bin", "/usr/sbin", "/sbin"])
    env.update(ENV_SET)
    env["MCP_TOOL_TIMEOUT"] = str((int(cap) + 60) * 1000)
    bad = [k for k in env if PROVIDER_VARS.match(k)]
    if bad:
        raise RuntimeError(f"provider variables in the claude child's environment: {bad}")
    return env


def mcp_config(path, bridge_env):
    """The one MCP server Claude Code loads: range_mcp.py, run with `python -I`. The bridge's secret is in this
    file (mode 600), not on any command line."""
    cfg = {"mcpServers": {MCP_NAME: {"type": "stdio", "command": sys.executable, "args": ["-I", str(SHIM)],
                                     "env": {"KL_RANGE_BRIDGE": bridge_env}}}}
    p = pathlib.Path(path)
    p.write_text(json.dumps(cfg))
    p.chmod(0o600)
    return p


def claude_argv(binary, model, system_file, mcp_file, tool_names, effort=None, resume=None):
    """The whole `claude -p` command line, the same for a new session and a resumed one. The prompt goes in on
    stdin (several flags take a list of values and would swallow a prompt put after them)."""
    # --include-partial-messages: the API's own message_start / message_delta events, the only place in the
    # stream with each message's final output tokens and stop reason (an `assistant` event carries the usage of
    # message_start: 25 output tokens where the message had 77, in an early smoke test).
    argv = [binary, "-p", "--output-format", "stream-json", "--verbose", "--include-partial-messages",
            "--model", model,  # passed through unchanged
            "--system-prompt-file", str(system_file),
            "--tools", "",
            "--strict-mcp-config", "--mcp-config", str(mcp_file),
            "--allowedTools", ",".join(PREFIX + n for n in tool_names),
            "--permission-mode", "dontAsk",
            "--setting-sources", "",
            "--disable-slash-commands",
            "--no-chrome"]
    if effort:
        argv += ["--effort", effort]
    if resume:
        argv += ["--resume", resume]
    return argv


def auth_status(binary, env):
    """`claude auth status --json` in the child's own environment, without any token, email or org in it."""
    try:
        p = subprocess.run([binary, "auth", "status", "--json"], env=env, capture_output=True, text=True,
                           timeout=60, cwd=env.get("TMPDIR") or "/tmp")
        d = json.loads(p.stdout)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {str(e)[:200]}"}
    return {k: d.get(k) for k in ("loggedIn", "authMethod", "apiProvider", "apiKeySource", "subscriptionType")}


def subscription_ok(status):
    """Is Claude Code going to use the claude.ai subscription login, and not bill any API key?"""
    return (bool(status.get("loggedIn")) and status.get("authMethod") == "claude.ai"
            and status.get("apiProvider") == "firstParty" and not status.get("apiKeySource"))


# A tool that runs nothing: Claude Code's placeholder that keeps deferred tool loading on ("Reserved placeholder
# that keeps deferred tool loading active; never call this tool"), sent with every request on 2.1.322. A call
# of it would still be a tool_use that is not the range's, which stops the run.
HARMLESS = ("DeferredToolPlaceholder",)


def tools_ok(names):
    bad = [n for n in names or [] if not str(n).startswith(PREFIX) and n not in HARMLESS]
    return not bad, bad


def session_file(session_id):
    home = pathlib.Path(os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude"))
    found = sorted((home / "projects").glob(f"*/{session_id}.jsonl"))
    return found[-1] if found else None


def session_facts(path, system):
    """What Claude Code itself recorded in its session file: the system prompt it sent (the snapshot) and the
    tools and system blocks of each request shape. Read, not assumed from the flags."""
    facts = {"session_file": str(path) if path else None, "system_blocks": None, "system_prefix": None,
             "instructions_match": None, "instructions_sha256": None, "request_tools": []}
    if not path or not pathlib.Path(path).exists():
        return facts
    for line in pathlib.Path(path).read_text().splitlines():
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if r.get("type") == "attachment" and (r.get("attachment") or {}).get("type") == "prompt_snapshot":
            sp = r["attachment"].get("systemPrompt") or []
            text = "".join(sp) if isinstance(sp, list) else str(sp)
            facts["instructions_sha256"] = hashlib.sha256(text.encode()).hexdigest()
            facts["instructions_match"] = text.rstrip() == system.rstrip()
        elif r.get("type") == "api-request-shape":
            shape = r.get("shape") or {}
            blocks = [b.get("text") if isinstance(b, dict) else str(b) for b in shape.get("system") or []]
            facts["system_blocks"] = len(blocks)
            # Every block before ours is Claude Code's own (one identity line on 2.1.322).
            facts["system_prefix"] = [b for b in blocks if (b or "").rstrip() != system.rstrip()]
            for t in shape.get("tools") or []:
                n = t.get("name") if isinstance(t, dict) else str(t)
                if n and n not in facts["request_tools"]:
                    facts["request_tools"].append(n)
    return facts


def usage_row(u):
    """One API message's usage in the shape an anthropic call reports it (what run_metrics reads)."""
    u = u or {}
    return {"input_tokens": int(u.get("input_tokens") or 0), "output_tokens": int(u.get("output_tokens") or 0),
            "cache_read_input_tokens": int(u.get("cache_read_input_tokens") or 0),
            "cache_creation_input_tokens": int(u.get("cache_creation_input_tokens") or 0)}


def classify(msg):
    """'usage_limit' | 'auth' | 'model_unavailable' | 'refusal' | 'transient' | 'other' for a failed turn."""
    low = (msg or "").lower()
    for kind, words in FATAL:
        if any(w in low for w in words):
            return kind
    if any(w in low for w in POLICY_WORDS):
        return "refusal"
    if agents.transient_error(TurnError(msg)):
        return "transient"
    return "other"


class TurnError(Exception):
    """A failed turn, carrying Claude Code's message so that agents.transient_error can read it."""


def claude_code_agent(role, model, system, task, effort=None, binary=None):
    """The defender's whole shift. Any way out with time left writes an `early_stop` row (episode.py makes
    the run INVALID from it)."""
    why = {"reason": None}
    try:
        _run(role, model, system, task, effort, binary, why)
    except Exception as e:  # a crash of the harness is an early stop too, never a quiet shift
        why["reason"] = why["reason"] or f"harness: {type(e).__name__}: {str(e)[:300]}"
        role.transcript.write(kind="error", error=f"claude-code harness: {type(e).__name__}: {str(e)[:500]}")
    finally:
        left = role.left()
        if left > EARLY:
            role.transcript.write(kind="early_stop", seconds_left=round(left, 1),
                                  error=why["reason"] or "claude-code stopped before the end of the shift",
                                  output=f"the defender stopped with {int(left)} s of the shift left: "
                                         f"{why['reason'] or 'no reason given'}")


def _run(role, model, system, task, effort, binary, why):
    binary = binary or claude_bin()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="kl-cc-"))
    ws = tmp / "ws"  # an empty folder, Claude Code's working folder: nothing of the harness's is in it
    ws.mkdir()
    system_file = tmp / "system.md"
    system_file.write_text(system)
    bridge = Bridge(role)
    env = child_env(role.shell_cap)
    try:
        status = auth_status(binary, env)
        role.transcript.write(kind="claude_code_auth", auth_mode=status.get("authMethod"), **status)
        if not subscription_ok(status):
            why["reason"] = f"claude-code is not on the subscription login: {status}"
            role.transcript.write(kind="error", error=f"claude-code would not use the claude.ai subscription "
                                                      f"(auth status {status}); nothing was run")
            return
        mcp_file = mcp_config(tmp / "mcp.json", f"{bridge.url} {bridge.secret}")
        session_id, prompt, attempt, facts_seen = None, task, 0, None
        while role.left() > 5:
            argv = claude_argv(binary, model, system_file, mcp_file, bridge.names, effort, resume=session_id)
            res = run_turn(role, argv, ws, env, prompt, status)
            session_id = res["session_id"] or session_id
            if res.get("init"):
                facts = {**res["init"], **session_facts(session_file(session_id), system),
                         "argv": argv[1:], "system_prompt_mode": SYSTEM_MODE, "effort": effort,
                         "auth_mode": status.get("authMethod"), "subscription": status.get("subscriptionType")}
                ok1, bad1 = tools_ok(facts.get("tools"))
                ok2, bad2 = tools_ok(facts.get("request_tools"))
                facts["tools_only_range"] = ok1 and ok2
                if facts != facts_seen:
                    role.transcript.write(kind="claude_code_session", **facts)
                    facts_seen = facts
                if not facts["tools_only_range"]:
                    why["reason"] = f"claude-code offered tools other than the range's: {bad1 + bad2}"
                    role.transcript.write(kind="error", error=why["reason"])
                    return
            if res["status"] == "deadline":
                return
            if res["status"] in ("local_action", "bad_init"):
                why["reason"] = res["error"]
                return
            if res["status"] == "refusal":
                why["reason"] = f"refusal: {(res['error'] or '')[:300]}"
                role.transcript.write(kind="refusal", output=json.dumps(
                    {"source": "claude-code", "error": res["error"], "details": res.get("details")}))
                return
            if res["status"] == "failed":
                msg = res["error"] or "claude-code exited without finishing the turn"
                kind = classify(msg)
                if kind == "refusal":
                    why["reason"] = f"refusal: {msg[:300]}"
                    role.transcript.write(kind="refusal", output=json.dumps({"source": "claude-code", "error": msg}))
                    return
                if kind != "transient":
                    why["reason"] = f"{kind}: {msg[:300]}"
                    role.transcript.write(kind="error", error=f"claude-code ({kind}): {msg[:500]}")
                    return
                attempt += 1
                wait = agents.retry_wait(attempt, role.left())
                role.transcript.write(
                    kind="retry", attempt=attempt, error=f"TurnError: {msg[:200]}", wait=round(wait, 1) if wait else 0,
                    output=(f"TurnError: {msg[:200]}; sending the same turn again in {wait:.0f} s" if wait else
                            f"TurnError: {msg[:200]}; the shift ends before another try is worth taking"))
                if wait is None:
                    return
                time.sleep(wait)
                continue  # the same prompt again, on the same session if there is one
            attempt = 0
            # A completed turn: the model's last answer had no tool call, which is an end_turn for any operator.
            if res["calls"] == 0 and res["last_text"] and REFUSAL_TEXT.search(res["last_text"]):
                why["reason"] = "refusal: the answer declined the work"
                role.transcript.write(kind="refusal", output=json.dumps(
                    {"source": "answer", "text": res["last_text"][:2000]}))
                return
            agents.idle(role)
            prompt = agents.nudge(role)
    finally:
        bridge.stop()
        shutil.rmtree(tmp, ignore_errors=True)


def run_turn(role, argv, ws, env, prompt, status=None):
    """One `claude -p` (or `--resume`) to its end, its events written to the transcript as they come.
    Returns {status: completed|failed|refusal|deadline|local_action|bad_init, session_id, calls, last_text,
    error, init}."""
    res = {"status": "failed", "session_id": None, "calls": 0, "last_text": "", "error": None, "init": None}
    err = tempfile.TemporaryFile()
    proc = subprocess.Popen(argv, cwd=ws, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=err, text=True, start_new_session=True)
    try:
        proc.stdin.write(prompt)
        proc.stdin.close()
    except BrokenPipeError:
        pass
    stopped = threading.Event()

    def kill():
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                time.sleep(3)
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def watchdog():
        while proc.poll() is None:
            if role.left() <= 5:
                stopped.set()
                kill()
                return
            time.sleep(0.5)

    threading.Thread(target=watchdog, daemon=True).start()
    pending = {}  # the API message whose usage is not written yet: {id, usage, stop}
    limits = {}

    def flush():
        if pending.get("id"):
            # The stream may carry no stop_reason; a message with a tool call is a tool_use, any other an end_turn.
            stop = pending.get("stop") or ("tool_use" if pending.get("tool") else "end_turn")
            role.transcript.write(kind="model", content=[], usage=usage_row(pending.get("usage")), stop=stop,
                                  message_id=pending["id"])
        pending.clear()

    try:
        for line in proc.stdout:
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            t = ev.get("type")
            if t == "system":
                sub = ev.get("subtype")
                if sub == "init":
                    res["session_id"] = ev.get("session_id") or res["session_id"]
                    res["init"] = {"session_id": ev.get("session_id"), "cli_version": ev.get("claude_code_version"),
                                   "model": ev.get("model"), "tools": ev.get("tools"),
                                   "mcp_servers": ev.get("mcp_servers"), "permission_mode": ev.get("permissionMode"),
                                   "api_key_source": ev.get("apiKeySource"), "plugins": [
                                       p.get("name") if isinstance(p, dict) else p for p in ev.get("plugins") or []],
                                   "skills": ev.get("skills"), "slash_commands": ev.get("slash_commands"),
                                   "memory_paths": ev.get("memory_paths")}
                    servers = {s.get("name"): s.get("status") for s in ev.get("mcp_servers") or []
                               if isinstance(s, dict)}
                    bad = None
                    if ev.get("apiKeySource") not in (None, "none"):
                        bad = f"claude-code would bill an API key ({ev.get('apiKeySource')}), not the subscription"
                    elif (status or {}).get("authMethod") not in (None, "claude.ai"):
                        bad = f"claude-code is logged in by {status.get('authMethod')}, not the subscription"
                    elif not tools_ok(ev.get("tools"))[0]:
                        bad = f"claude-code offered tools other than the range's: {tools_ok(ev.get('tools'))[1]}"
                    elif servers != {MCP_NAME: "connected"}:
                        bad = f"the range MCP server is not the only one connected: {servers}"
                    elif ev.get("memory_paths"):
                        bad = f"claude-code auto-memory is on: {ev.get('memory_paths')}"
                    if bad:
                        role.transcript.write(kind="error", error=bad)
                        res.update(status="bad_init", error=bad)
                        kill()
                        break
                elif sub == "thinking_tokens" or (sub == "status" and "compact" not in str(ev.get("status"))):
                    pass  # "requesting" before each call, and the running estimate while the model thinks  # a running estimate while the model thinks; the message's own usage has the count
                elif sub == "compact_boundary":
                    role.transcript.write(kind="compaction", metadata=ev.get("compact_metadata"),
                                          output=f"claude-code compacted the conversation: "
                                                 f"{json.dumps(ev.get('compact_metadata'))[:300]}")
                elif sub == "api_retry":
                    role.transcript.write(kind="retry", source="claude-code", attempt=ev.get("attempt"),
                                          error=str(ev.get("error") or ev.get("error_status")),
                                          wait=round((ev.get("retry_delay_ms") or 0) / 1000, 1),
                                          output=f"claude-code retries the API call ({ev.get('error_status')} "
                                                 f"{ev.get('error')}), attempt {ev.get('attempt')}")
                else:
                    role.transcript.write(kind="cc_system", subtype=sub,
                                          output=json.dumps({k: v for k, v in ev.items()
                                                             if k not in ("type", "uuid", "session_id")})[:1000])
            elif t == "stream_event":
                e = ev.get("event") or {}
                if ev.get("parent_tool_use_id"):
                    continue
                res["partial"] = True
                if e.get("type") == "message_start":
                    flush()
                    m = e.get("message") or {}
                    pending.update(id=m.get("id"), usage=dict(m.get("usage") or {}))
                elif e.get("type") == "message_delta":
                    pending.setdefault("usage", {}).update({k: v for k, v in (e.get("usage") or {}).items()
                                                            if v is not None})
                    stop = (e.get("delta") or {}).get("stop_reason")
                    if stop:
                        pending["stop"] = stop
                    if stop == "refusal":
                        res["status"], res["error"] = "refusal", "the model's answer stopped with stop_reason refusal"
                        res["details"] = (e.get("delta") or {}).get("stop_details")
                elif e.get("type") == "message_stop":
                    flush()
            elif t == "rate_limit_event":
                info = ev.get("rate_limit_info") or {}
                key = (info.get("status"), info.get("rateLimitType"))
                if limits.get("last") != key:
                    limits["last"] = key
                    role.transcript.write(kind="cc_rate_limit", info=info,
                                          output=f"subscription limit {info.get('rateLimitType')}: "
                                                 f"{info.get('status')}")
            elif t == "assistant":
                msg = ev.get("message") or {}
                if ev.get("parent_tool_use_id"):
                    continue  # a sub-agent's message; there are none with --tools "" (an Agent tool is needed)
                if not res.get("partial"):
                    # No partial events (an older CLI): the usage this event carries is all there is.
                    if msg.get("id") != pending.get("id"):
                        flush()
                        pending["id"] = msg.get("id")
                    pending["usage"] = msg.get("usage") or pending.get("usage")
                    pending["stop"] = msg.get("stop_reason") or pending.get("stop")
                if ev.get("error"):
                    text = " ".join(b.get("text", "") for b in msg.get("content") or [] if isinstance(b, dict))
                    res["error"] = f"{ev.get('error')} (status {ev.get('api_error_status')}): {text}".strip()
                    role.transcript.write(kind="cc_api_error", error=res["error"][:1000], output=res["error"][:1000])
                    if pending.get("id") == msg.get("id"):
                        pending.clear()  # a synthetic message: no tokens were spent on it
                    continue
                for b in msg.get("content") or []:
                    bt = b.get("type")
                    if bt == "tool_use":
                        name = b.get("name") or ""
                        if not name.startswith(PREFIX):
                            res["error"] = f"claude-code used a tool of its own ({name}); stopped"
                            role.transcript.write(kind="error", error=res["error"], item=b)
                            res["status"] = "local_action"
                            kill()
                            break
                        res["calls"] += 1
                        pending["tool"] = True
                        # Before the bridge's own `shell` row, as a model's tool_use comes before its command.
                        role.transcript.write(kind="model", content=[{
                            "type": "tool_use", "id": b.get("id"), "server": MCP_NAME, "name": name[len(PREFIX):],
                            "input": b.get("input")}], usage=None)
                    elif bt == "text":
                        res["last_text"] = b.get("text") or ""
                        role.transcript.write(kind="model", content=[{"type": "text", "text": res["last_text"]}],
                                              usage=None)
                    elif bt == "thinking":
                        role.transcript.write(kind="model", content=[{"type": "thinking",
                                                                      "thinking": b.get("thinking")}], usage=None)
                if res["status"] == "local_action":
                    break
                if msg.get("stop_reason") == "refusal":
                    res["status"], res["error"] = "refusal", "the model's answer stopped with stop_reason refusal"
                    res["details"] = msg.get("stop_details")
            elif t == "user":
                for b in (ev.get("message") or {}).get("content") or []:
                    if isinstance(b, dict) and b.get("type") == "tool_result" and b.get("is_error"):
                        c = b.get("content")
                        role.transcript.write(kind="tool_error", output=(c if isinstance(c, str) else json.dumps(c))[:2000])
            elif t == "result":
                flush()
                role.transcript.write(
                    kind="cc_result", subtype=ev.get("subtype"), is_error=ev.get("is_error"),
                    terminal_reason=ev.get("terminal_reason"), num_turns=ev.get("num_turns"),
                    duration_ms=ev.get("duration_ms"), api_equivalent_usd=ev.get("total_cost_usd"),
                    safety_stops=ev.get("safety_stops"), api_error_status=ev.get("api_error_status"),
                    permission_denials=ev.get("permission_denials"), cc_usage=ev.get("usage"),
                    output=f"claude-code turn ended: {ev.get('subtype')} ({ev.get('terminal_reason')})")
                if res["status"] == "refusal":
                    pass
                elif ev.get("safety_stops"):
                    res["status"] = "refusal"
                    res["error"] = res["error"] or f"claude-code safety stop ({ev.get('safety_stops')})"
                elif ev.get("is_error") or ev.get("subtype") != "success":
                    res["status"] = "failed"
                    res["error"] = res["error"] or str(ev.get("result") or ev.get("errors") or ev.get("subtype"))
                else:
                    res["status"] = "completed"
    finally:
        flush()
        if proc.poll() is None and res["status"] in ("local_action", "bad_init"):
            kill()
        proc.wait()
        err.seek(0)
        tail = err.read().decode(errors="replace")[-2000:]
        err.close()
    if stopped.is_set():
        role.transcript.write(kind="idle", output="the shift is over; claude-code stopped")
        res["status"] = "deadline"
    elif res["status"] == "failed" and not res["error"]:
        res["error"] = f"claude-code exited {proc.returncode}: {tail.strip()[-500:]}"
    return res
