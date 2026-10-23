# ai-tools

Hooks and skills for Claude Code and other AI tools.

## Quick Start

```bash
git clone https://github.com/guppybot161/ai-tools ~/pyprojects/ai-tools
~/pyprojects/ai-tools/install.sh
```

`install.sh` symlinks each tool into place, so edits in the repo take effect immediately. It never touches `~/.claude/settings.json`. Registering a hook is a manual step, and the script prints the snippet to use.

## Tools

| Tool | Type | What it does |
|---|---|---|
| [pii-egress-guard](hooks/pii-egress-guard/) | PreToolUse hook | Prompts before Bash/WebFetch/WebSearch/Write/Edit calls send your email or other identifiers off the machine |
