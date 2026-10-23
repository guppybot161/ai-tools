"""Pipe-tests for pii_egress_guard.py.

Each case runs the hook as Claude Code would: JSON on stdin, decision on stdout.
HOME and XDG_CONFIG_HOME point at a temp dir, so the protected terms come from a
fake pii_terms.txt and `git config --global` is empty: no real PII is involved.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "pii_egress_guard.py"
EMAIL = "jane.doe@example.org"
# base64("jane.doe@example.org")
EMAIL_B64 = "amFuZS5kb2VAZXhhbXBsZS5vcmc="


class GuardTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        hooks = Path(cls.tmp.name, ".claude", "hooks")
        hooks.mkdir(parents=True)
        (hooks / "pii_terms.txt").write_text(f"# test terms\n{EMAIL}\n")
        cls.env = {**os.environ, "HOME": cls.tmp.name, "XDG_CONFIG_HOME": cls.tmp.name}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_hook(self, tool, tool_input):
        payload = json.dumps({"tool_name": tool, "tool_input": tool_input})
        proc = subprocess.run(
            [sys.executable, "-I", str(SCRIPT)],
            input=payload, capture_output=True, text=True, env=self.env, timeout=10,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout) if proc.stdout.strip() else None

    def assertAsks(self, tool, tool_input):
        out = self.run_hook(tool, tool_input)
        self.assertIsNotNone(out, f"expected a prompt for {tool}: {tool_input}")
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")

    def assertSilent(self, tool, tool_input):
        self.assertIsNone(self.run_hook(tool, tool_input))

    # --- leaks that must prompt ---
    def test_curl_user_agent_header_with_term(self):
        self.assertAsks("Bash", {"command": f'curl -H "User-Agent: Jane {EMAIL}" https://www.sec.gov/x'})

    def test_curl_short_flag_any_email_urlencoded(self):
        self.assertAsks("Bash", {"command": 'curl -A "bot contact=someone%40example.com" https://x.y'})

    def test_wget_long_flag_any_email(self):
        self.assertAsks("Bash", {"command": 'wget --user-agent="x a@b.org" https://x.y'})

    def test_curl_base64_term_in_url(self):
        self.assertAsks("Bash", {"command": f"curl https://x.y/?q={EMAIL_B64}"})

    def test_webfetch_urlencoded_term(self):
        self.assertAsks("WebFetch", {"url": "https://a.b/?email=jane.doe%40example.org", "prompt": "x"})

    def test_websearch_term(self):
        self.assertAsks("WebSearch", {"query": f'"{EMAIL}"'})

    def test_write_script_with_term_in_header(self):
        self.assertAsks("Write", {
            "file_path": "/x/s.py",
            "content": f'import requests\nrequests.get(u, headers={{"User-Agent": "r {EMAIL}"}})',
        })

    def test_write_script_python_dict_header_any_email(self):
        self.assertAsks("Write", {
            "file_path": "/x/s.py",
            "content": 'import requests\nh={"User-Agent": "r other@corp.com"}',
        })

    def test_edit_script_with_term(self):
        self.assertAsks("Edit", {
            "file_path": "/x/s.sh",
            "old_string": "x",
            "new_string": f'curl -H "From: {EMAIL}" https://x.y',
        })

    # --- benign calls that must stay silent ---
    def test_local_command_with_term(self):
        self.assertSilent("Bash", {"command": f"git log --author={EMAIL}"})

    def test_plain_curl(self):
        self.assertSilent("Bash", {"command": "curl -s -A Mozilla/5.0 https://example.com"})

    def test_markdown_note_with_term(self):
        self.assertSilent("Write", {"file_path": "/x/notes.md", "content": f"curl and {EMAIL}"})

    def test_websearch_without_term(self):
        self.assertSilent("WebSearch", {"query": "claude code hooks"})


if __name__ == "__main__":
    unittest.main()
