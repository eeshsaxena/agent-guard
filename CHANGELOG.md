# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.4.1]

An honesty-and-correctness patch. No behavior change to the live Claude Code hook
(the smoke still reads benign-inside-root as allow, an outside-root read and a
credential-exfil Bash command as block, and malformed input as allow).

### Documentation

- Corrected the tamper-evident audit log claims. The log is a **keyless** SHA-256
  hash chain: it is tamper-*evident* (it detects accidental or naive edits, drops,
  inserts, and reorders of interior entries by recomputing the chain from the
  file), not tamper-*proof*. Stated the real limits plainly: the chain has no
  unforgeable anchor, so anyone who can run code, including the audited agent
  (the log lives under `~/.agentguard/`, outside the default fenced roots, and
  Bash is not path-fenced), can recompute a fully valid chain over doctored
  entries; and a tail-drop of the most recent entries is not detected. Removed the
  "adds nothing you have to trust" framing, and noted that real tamper-resistance
  would need an HMAC keyed outside the log (a possible future direction, not
  implemented here).
- Reframed the Bash credential-exfil block as a tripwire for the naive, literal
  "read a credential file and pipe it to a remote net tool" pattern, not a
  boundary. Called out what it does not catch: `/dev/tcp` redirection,
  interpreter-based exfil (`python -c ...`, `node -e ...`), base64-decoded or
  otherwise obfuscated commands, and DNS exfil; and that credential files such as
  `~/.docker/config.json` and `~/.kube/config` are not recognized.
- Added a Fence scope section: the path fence covers only a fixed set of file
  tools (`Read`/`Write`/`Edit`/`MultiEdit`/`NotebookEdit`/`Grep`/`Glob`); Bash and
  any new or renamed file tool are not path-fenced; and the `~/.agentguard`
  config+log directory sits outside the default roots, so a capable agent could
  disable the fence by editing the config. Recommended placing and protecting that
  directory accordingly.

### Fixed

- **Large log entries no longer cause a false `verify-log` BROKEN.** `_last_hash`
  read only the final 64 KB of the log to find the previous entry's hash, so a
  single entry larger than 64 KB made the next entry chain onto GENESIS and
  `verify-log` falsely reported tampering. It now reads the last complete line
  regardless of size, walking backward in chunks so the common small-entry case
  still only touches the tail.
- **Relative target paths now resolve against the event's `cwd`.** `_inside_any`
  resolved a relative path against the hook process's own working directory,
  ignoring the `cwd` the adapter captured, which could fence a relative path
  against the wrong directory. Relative paths now resolve against `event.cwd` when
  present, before `.resolve()`. Claude Code is unaffected, since its file tools
  always pass absolute paths.

## [0.4.0]

- Prior release: folder fence, Bash inspection, `agentguard run` OS sandbox,
  keyless hash-chained audit log with `verify-log`, desktop block alerts,
  multi-agent adapters (claude-code, gemini-cli, cursor, generic), and the live
  dashboard. See the git history for details.
