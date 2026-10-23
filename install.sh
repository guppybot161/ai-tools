#!/usr/bin/env bash
set -e

AI_TOOLS="$(cd "$(dirname "$0")" && pwd)"
HOOKS=~/.claude/hooks

mkdir -p "$HOOKS"

# pii-egress-guard — symlink script, seed private terms file once
ln -sfn "$AI_TOOLS/hooks/pii-egress-guard/pii_egress_guard.py" "$HOOKS/pii_egress_guard.py"
echo "pii-egress-guard: symlinked $HOOKS/pii_egress_guard.py"
if [ ! -f "$HOOKS/pii_terms.txt" ]; then
  install -m 600 "$AI_TOOLS/hooks/pii-egress-guard/pii_terms.example.txt" "$HOOKS/pii_terms.txt"
  echo "pii-egress-guard: created $HOOKS/pii_terms.txt — edit it to list your identifiers"
fi

# settings.json is machine-specific and not managed here
if ! grep -q pii_egress_guard ~/.claude/settings.json 2>/dev/null; then
  cat <<'EOF'

pii-egress-guard: not registered yet. Add to "hooks" in ~/.claude/settings.json:

    "PreToolUse": [
      {
        "matcher": "Bash|WebFetch|WebSearch|Write|Edit",
        "hooks": [
          { "type": "command", "command": "python3 -I ~/.claude/hooks/pii_egress_guard.py", "timeout": 10 }
        ]
      }
    ]

Then open /hooks once (or restart Claude Code) to load it.
EOF
fi
