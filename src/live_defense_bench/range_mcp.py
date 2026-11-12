"""The range's shell as an MCP server, for an operator whose loop is Codex's.

Codex starts this file as a stdio MCP server; it is the only tool Codex is given. It holds no shell of its own
and runs nothing: every `tools/call` is posted to the harness's bridge (codex_agent.Bridge) on 127.0.0.1,
which runs it through the operator's `Role` -- the same `tool_call` path, shell cap, transcript and deadline
as every other operator -- on the attacker box in the sandbox. The tool list is the bridge's, so the tools
are exactly the harness's.

It is run as `python -I range_mcp.py` and imports nothing from the package, so nothing in the working folder
is loaded. The bridge's address and a per-run secret come in KL_RANGE_BRIDGE ("http://127.0.0.1:PORT SECRET").
"""
import json
import os
import sys
import urllib.request

PROTOCOL = "2025-06-18"


def bridge(path, body=None):
    url, _, secret = os.environ.get("KL_RANGE_BRIDGE", "").partition(" ")
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url + path, data=data, method="GET" if body is None else "POST",
                                 headers={"X-Range-Secret": secret, "Content-Type": "application/json"})
    # No timeout of ours: the bridge's Role caps the command, and Codex's tool_timeout_sec caps the call.
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode())


def answer(msg):
    method, mid = msg.get("method"), msg.get("id")
    if mid is None:  # a notification (initialized, cancelled, ...): nothing to say back
        return None
    if method == "initialize":
        want = (msg.get("params") or {}).get("protocolVersion") or PROTOCOL
        return {"protocolVersion": want, "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "range", "version": "1"}}
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": bridge("/tools")["tools"]}
    if method == "tools/call":
        p = msg.get("params") or {}
        try:
            r = bridge("/call", {"name": p.get("name"), "arguments": p.get("arguments") or {}})
            return {"content": [{"type": "text", "text": r["text"]}], "isError": False}
        except Exception as e:  # the bridge is gone (the shift ended): say so, as a tool error
            return {"content": [{"type": "text", "text": f"[tool error: {type(e).__name__}: {e}]"}],
                    "isError": True}
    raise LookupError(method)


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            result = answer(msg)
            if result is None:
                continue
            out = {"jsonrpc": "2.0", "id": msg["id"], "result": result}
        except LookupError as e:
            out = {"jsonrpc": "2.0", "id": msg.get("id"), "error": {"code": -32601, "message": f"no method {e}"}}
        except Exception as e:
            out = {"jsonrpc": "2.0", "id": msg.get("id"), "error": {"code": -32603, "message": str(e)[:300]}}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
