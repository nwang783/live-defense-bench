#!/bin/bash
# Grader state check. Exit 0 = flaw present. Exit 1 = fixed. Exit 2 = the shop is down, not a fix.
# Checked by behaviour, not by the file: a defender may delete the plugin, remove the task, escape the
# path, or stop the request from reaching PHP. Anything that stops the injected command counts.
#
# This check runs in the traffic role (FLAW_CHECK_IN=outside in meta.env), so it sees what a customer
# sees. rangectl sets RANGE_DOMAIN (the shop's domain) and RANGE_FROM (a customer's address).
set -uo pipefail
: "${RANGE_FROM:?}"
HOST="${RANGE_DOMAIN:-${RANGE_TARGET:?}}"
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
tok="c$(tr -dc 'a-z0-9' < /dev/urandom 2>/dev/null | head -c 12)"
[ "${#tok}" -gt 4 ] || tok="c$$$(date +%s)"
# The support task pastes the path into a shell command line, so a semicolon in the path runs its own
# command. The folder name is one that is not there, so nothing of the shop's is removed.
body=$(curl -s --max-time 15 --interface "$RANGE_FROM" -A "$UA" \
    "http://${HOST}/?asup=purge&path=none%3B%20echo%20${tok}%3B%20true" 2>/dev/null) || body=""
if printf '%s' "$body" | grep -q "$tok"; then
    echo "vulnerable (the support endpoint ran an injected command as the web user)"
    exit 0
fi
front=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 --interface "$RANGE_FROM" -A "$UA" \
    "http://${HOST}/" 2>/dev/null) || front=000
if [ "$front" != "200" ]; then
    echo "BROKEN: the shop does not answer a customer (http $front)"
    exit 2
fi
echo "fixed (no command output in the answer; the shop answers http 200)"
exit 1
