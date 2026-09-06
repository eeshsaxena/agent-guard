# agent-guard / sneakoscope handoff

**What it is:** see what your AI coding agent touches, and fence it in. A pre-tool-call
hook that logs every action to a live dashboard and blocks file access outside folders
you allow, plus Bash-command inspection and a real OS-sandbox launcher.

- **Repo:** `github.com/eeshsaxena/agent-guard` (PUBLIC). **PyPI name: `sneakoscope`**
  (import + CLI stay `agentguard`). Local: `Downloads/agent-guard`.
- **Current: v0.4.0** on `main`. **PyPI has 0.1.0**, newer versions NOT published yet
  (your local `twine` step; CI publish is billing-blocked).
- **LIVE:** the Claude Code `PreToolUse` hook is active in `~/.claude/settings.json`
  (runs the top-level `guard.py` shim). Every change is verified to keep that
  byte-identical: benign -> exit 0, outside-root/exfil -> exit 2, malformed -> exit 0.

## Shipped (verified: ruff clean, 120 tests; live-hook smoke re-run each release)
- **Folder fence:** blocks Read/Write/Edit/etc. outside `allowed_roots` (exit 2).
- **Bash inspection** (`bashinspect.py`): flags credential reads / network egress /
  destructive ops / outside-root access; blocks the credential-exfil case. Config:
  `inspect_bash`, `bash_enforce`.
- **`agentguard run -- <cmd>`** (`sandbox.py`): real OS filesystem sandbox: bwrap/
  firejail (Linux), sandbox-exec (macOS); Windows honestly refuses (use Docker/WSL2).
- **Tamper-evident audit log** (`integrity.py`): SHA-256 hash chain per entry;
  `agentguard verify-log` reports INTACT or the first broken line (CI-usable).
- **Real-time block alerts** (`alerts.py`): best-effort desktop notification on block
  (Windows/macOS/Linux), config `alerts` (default true), fail-safe.
- **Multi-agent adapters** (`core.py` + `adapters.py`): agent-agnostic `decide()` core;
  adapters for `claude-code` (default), `gemini-cli`, `cursor`, and `generic` (BYO
  schema `{tool,paths,command,url,cwd}`). `agentguard hook --agent <name>`. Codex/
  opencode/Cline/aider documented honestly as having no usable blocking hook, use
  `generic` + `run`. Hooks are advisory; `run` is the only hard fence.
- **Dashboard**, `install`/`uninstall`/`status`/`harden` commands. Stdlib only.

## Remaining (your call)
- Publish new versions to PyPI (local twine; `sneakoscope` 0.1.0 live, 0.4.0 not).
- Alerts were unit-tested + wiring-verified but not visually popped on Windows.
- OS sandbox arg/profile construction is unit-tested with mocks, not run against real
  bwrap/sandbox-exec (none on this Windows host).
- Commits omit the Co-Authored-By AI trailer, per your OSS preference.
