# pii-egress-guard

A Claude Code `PreToolUse` hook that makes Claude ask you first before a tool call sends your personal identifiers (email etc.) off the machine.

## The threat

Some websites ask automated clients to identify themselves. SEC EDGAR, for example, requires a contact email in the `User-Agent`. An agent that has your email in its context (Claude Code injects it) may politely comply and send it in a `curl` header, a URL parameter or a search query. Nobody attacks you here: the agent is just being helpful to the website. This hook catches that kind of *accidental compliance*.

## How a hook runs

```
Claude wants to call a tool
  → tool name matches "Bash|WebFetch|WebSearch|Write|Edit"?
  → Claude Code runs: python3 -I ~/.claude/hooks/pii_egress_guard.py
       stdin  ← {"tool_name": "Bash", "tool_input": {"command": "..."}, ...}
       stdout → nothing                       = no opinion, normal flow
              → {"permissionDecision": "ask"} = you get a prompt, even in auto mode
```

- The **matcher** is a regex over tool names and only decides whether the script runs. Everything else is up to the script.
- **`python3 -I`** runs Python in isolated mode. The hook runs in whatever directory you're working in, and without `-I` a stray `json.py` there would be imported in place of the real library.
- The hook answers **`ask`, not `deny`**. Some sharing is legitimate (SEC EDGAR), and a hard deny would push the model to find a workaround. `ask` puts you in charge and shows the reason.

## What it detects

**Step 1: is this call outbound?** If not, the hook stays silent.

| Tool | Treated as outbound when… |
|---|---|
| `WebFetch`, `WebSearch` | always (the whole input is scanned) |
| `Bash` | the command matches `NET`: curl, wget, ssh, `requests`, `urllib`, `gh api`, … |
| `Write`, `Edit` | the file is a script (`.py`, `.sh`, `.js`, …) **and** its content matches `NET`. This catches "write a script with the header, then run it" |

So `git log --author=you@mail.com` passes silently: your email is in it, but nothing sends it anywhere.

**Step 2: scan the outbound text** for either of two signals:

1. **Protected terms**: each line of `~/.claude/hooks/pii_terms.txt` plus `git config --global user.email`. Each term is also matched URL-encoded (`%40`) and base64-encoded.
2. **Identity headers carrying *any* email**, even one you haven't listed:

   | Regex part | Matches |
   |---|---|
   | `(User-Agent\|From\|X-Contact\|…)["']?\s*[:=]` | a header name; the optional quote covers Python dicts (`{"User-Agent": …}`) |
   | `\|(^\|\s)(-A\|--user-agent\|-U)\s` | curl/wget User-Agent flags |
   | `[^\n]{0,200}?` | up to 200 characters on the same line (lazy) |
   | `[\w.+-]+(@\|%40)[\w-]+\.[\w.-]+` | something email-shaped, including URL-encoded |

## Install

```bash
./install.sh   # from the repo root
```

The script symlinks the hook into `~/.claude/hooks/` and creates `~/.claude/hooks/pii_terms.txt` (mode 600) from the example if it doesn't exist yet. It does **not** edit `settings.json`; it prints the snippet to add. Then open `/hooks` once or restart Claude Code.

Your terms file stays local and is git-ignored, so the script itself contains no personal data.

## Tests

```bash
python3 -m unittest discover -s hooks/pii-egress-guard/tests
```

The tests run the hook as a subprocess with `HOME` set to a temp dir, using a fake terms file. Real identifiers are never involved.

## Limitations

- **Fails open.** If the script crashes, Claude Code's default `onFailure: "continue"` lets the call go ahead. Add `"onFailure": "block"` to the hook entry if you prefer to fail closed; the cost is that a broken hook blocks all five tools.
- **Matches strings, doesn't track data.** It misses `$EMAIL`, `$(git config user.email)`, emails assembled from pieces, and scripts that were already on disk. For real enforcement, restrict network egress (sandbox `network.allowedDomains` or a proxy).
- **Base64 is partial.** The encoded email only appears verbatim inside a larger base64 blob when it starts at a byte offset divisible by 3. Embedded in a bigger encoded payload, it's missed about two times in three.
- **MCP tools aren't covered.** Adding `|mcp__.*` to the matcher is easy, but noisy given the varied input shapes.
