#!/usr/bin/env python3
"""PreToolUse guard: stop personal identifiers leaving the machine via tool calls.

Background: sites can ask agents to "identify their users" (e.g. a User-Agent or
From: header with a contact email, as SEC EDGAR requires). An agent that has the
user's email in context may comply and send it. This hook forces a permission
prompt when an outbound tool call carries a protected term.

Protected terms: ~/.claude/hooks/pii_terms.txt (one per line, # comments)
plus `git config user.email`. Each term is also matched URL-encoded and base64'd.
"""
import base64
import json
import os
import re
import subprocess
import sys
import urllib.parse

TERMS_FILE = os.path.expanduser("~/.claude/hooks/pii_terms.txt")

# Something in the command/script that can talk to the network.
NET = re.compile(
    r"\b(curl|wget|http|https|httpie|xh|nc|ncat|socat|telnet|ssh|scp|rsync|ftp|"
    r"requests|urllib|httpx|aiohttp|urlopen|fetch\(|axios|Invoke-WebRequest|"
    r"Invoke-RestMethod|gh\s+api|sendmail|mail\s)",
    re.I,
)
# Identity-style headers carrying an email, regardless of whose it is.
ID_HEADER = re.compile(
    r"((User-Agent|From|X-Contact|X-Email|X-User)[\"']?\s*[:=]|(^|\s)(-A|--user-agent|-U)\s)"
    r"[^\n]{0,200}?"
    r"[\w.+-]+(@|%40)[\w-]+\.[\w.-]+",
    re.I,
)
SCRIPT_EXT = (".py", ".sh", ".bash", ".js", ".mjs", ".ts", ".rb", ".pl", ".ps1", ".php", ".go")


def load_terms():
    terms = set()
    try:
        with open(TERMS_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    terms.add(line)
    except OSError:
        pass
    try:
        email = subprocess.run(
            ["git", "config", "--global", "user.email"],
            capture_output=True, text=True, timeout=2,
        ).stdout.strip()
        if email:
            terms.add(email)
    except Exception:
        pass
    return terms


def variants(term):
    yield term
    yield urllib.parse.quote(term, safe="")
    yield urllib.parse.quote_plus(term)
    b = base64.b64encode(term.encode()).decode().rstrip("=")
    if len(b) > 8:
        yield b[:-2]  # tolerate different padding / trailing bytes


def find_terms(text, terms):
    low = text.lower()
    return sorted({t for t in terms for v in variants(t) if v.lower() in low})


def outbound_text(tool, inp):
    """Return the text that would leave the machine, or None if not outbound."""
    if tool in ("WebFetch", "WebSearch"):
        return json.dumps(inp, ensure_ascii=False)
    if tool == "Bash":
        cmd = inp.get("command", "")
        return cmd if NET.search(cmd) else None
    if tool in ("Write", "Edit"):
        path = inp.get("file_path", "")
        body = inp.get("content") or inp.get("new_string") or ""
        if path.endswith(SCRIPT_EXT) and NET.search(body):
            return body
    return None


def main():
    data = json.load(sys.stdin)
    tool = data.get("tool_name", "")
    text = outbound_text(tool, data.get("tool_input") or {})
    if text is None:
        return

    reasons = []
    hits = find_terms(text, load_terms())
    if hits:
        reasons.append("contains protected identifier(s): " + ", ".join(hits))
    if ID_HEADER.search(text):
        reasons.append("sets an identity header (User-Agent/From/...) containing an email")
    if not reasons:
        return

    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": (
                f"PII egress guard: {tool} call " + "; ".join(reasons)
                + ". Approve only if you intend to share this with the remote site."
            ),
        }
    }))


if __name__ == "__main__":
    main()
