"""The agent-agnostic guard core.

An adapter turns some agent's pre-tool-call event into a normalized `Event`
(tool label, target paths, shell command, url, cwd). This module holds the parts
that don't care which agent asked: `decide` turns an Event plus config into an
allow/block `Decision`, `build_log_entry` renders the audit record, and
`run_adapter` wires parse -> decide -> log -> emit together.

The decision logic here is exactly what the Claude Code hook used to run inline;
it was lifted out unchanged so every agent shares one policy. Everything fails
OPEN: a parse error allows the call, and inspection/path checks never raise.
"""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import alerts, bashinspect, config, integrity

# Exit codes an adapter's emit returns: 2 blocks the call, 0 allows it.
ALLOW = 0
BLOCK = 2

# Claude Code's file tools and the keys they carry a path under. Kept here
# because the claude-code adapter is the reference; other adapters bring their
# own vocabulary.
ENFORCED = {"Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Grep", "Glob"}
PATH_KEYS = ("file_path", "notebook_path", "path")


@dataclass
class Event:
    """A pre-tool-call reduced to what the policy needs, regardless of agent.

    `tool` is a display label (recorded in the log). `paths` are file targets to
    fence, `command` a shell command to inspect, `url` a fetch target to record.
    This is also the stable schema the `generic` adapter accepts on stdin.
    """
    tool: str = ""
    paths: list[str] = field(default_factory=list)
    command: str | None = None
    url: str | None = None
    cwd: str | None = None


@dataclass
class Decision:
    blocked: bool
    bash_blocked: bool
    findings: list
    outside: list[str]


def _inside_any(path: str, roots: list[Path], cwd: str | None = None) -> bool:
    try:
        p = Path(os.path.expandvars(os.path.expanduser(path)))
        # A relative path is resolved against the cwd the adapter captured, not
        # the hook process's own cwd. Claude Code always passes absolute paths,
        # so this only matters for agents/wrappers that send relative ones.
        if not p.is_absolute() and cwd:
            p = Path(cwd) / p
        p = p.resolve()
    except Exception:
        return True  # unresolvable -> do not block
    for r in roots:
        try:
            p.relative_to(r)
            return True
        except ValueError:
            continue
    return False


def decide(event: Event, cfg) -> Decision:
    """Apply the folder fence and Bash inspection to a normalized event.

    Paths only reach here for file tools (the adapter decides that), so the fence
    naturally skips shell/web calls. A command is inspected only when it is a
    string. Nothing here raises: inspection and path resolution fail open.
    """
    outside = [p for p in event.paths if cfg.roots and not _inside_any(p, cfg.roots, event.cwd)]
    file_block = bool(outside) and cfg.enforce

    findings = []
    if cfg.inspect_bash and isinstance(event.command, str):
        findings = bashinspect.inspect(event.command, cfg.roots)
    bash_blocked = cfg.bash_enforce and any(f.severity == bashinspect.BLOCK for f in findings)

    return Decision(
        blocked=file_block or bash_blocked,
        bash_blocked=bash_blocked,
        findings=findings,
        outside=outside,
    )


def build_log_entry(event: Event, decision: Decision) -> dict:
    return {
        "ts": time.time(),
        "tool": event.tool,
        "paths": event.paths,
        "command": event.command,
        "url": event.url,
        "outside": decision.outside,
        "suspicious": bool(decision.findings),
        "findings": [f.as_dict() for f in decision.findings],
        "blocked": decision.blocked,
        "cwd": event.cwd,
    }


def _last_complete_line(fh) -> str:
    """The final non-blank, newline-complete line of an open binary log.

    Walks backward in chunks, so the common case (a small last entry) reads only
    the tail, but a single entry larger than one chunk is still read in full
    rather than truncated. Only lines whose left boundary is inside the buffer
    (or the very first line, once the file start is reached) are ever returned,
    so a partial line is never mistaken for a complete one.
    """
    step = 65536
    fh.seek(0, os.SEEK_END)
    pos = fh.tell()
    buf = b""
    while pos > 0:
        read = min(step, pos)
        pos -= read
        fh.seek(pos)
        buf = fh.read(read) + buf
        stripped = buf.rstrip(b"\r\n \t")  # drop any trailing blank lines
        nl = stripped.rfind(b"\n")
        if nl != -1:
            # Everything after this newline is a complete final line (buf runs to
            # EOF), and it is non-blank because we just stripped trailing space.
            return stripped[nl + 1:].decode("utf-8", "ignore")
        # No in-buffer left boundary yet: keep reading backward.
    # Reached the start of the file; the first line in buf is now complete.
    for line in reversed(buf.split(b"\n")):
        if line.strip():
            return line.decode("utf-8", "ignore")
    return ""


def _last_hash(log_path: Path) -> str:
    """Hash of the most recent entry, for chaining the next one onto it.

    Reads the last complete line of the log regardless of its size, so a single
    entry larger than the read window still chains correctly instead of tripping
    a false tamper alarm. A missing file, a legacy line with no hash, or any
    error yields GENESIS: the chain just (re)starts here rather than the hook
    failing.
    """
    try:
        with log_path.open("rb") as fh:
            line = _last_complete_line(fh)
        if line:
            obj = json.loads(line)
            h = obj.get("hash") if isinstance(obj, dict) else None
            return h if isinstance(h, str) else integrity.GENESIS
    except Exception:
        pass
    return integrity.GENESIS


def append_log(log_path: Path, entry: dict) -> None:
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            entry = integrity.chain_entry(entry, _last_hash(log_path))
        except Exception:
            pass  # never let hashing drop the audit record; write it unchained
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def alert(cfg, tool: str, bash_blocked: bool, findings: list, outside: list) -> None:
    """Pop a best-effort desktop notification for a block. Fail-safe: swallows
    everything so a notifier problem can never delay or crash the hook."""
    if not cfg.alerts:
        return
    try:
        if bash_blocked:
            detail = "; ".join(f.detail for f in findings if f.severity == bashinspect.BLOCK)
            message = f"Blocked Bash: {detail}" if detail else "Blocked a Bash command"
        else:
            message = f"Blocked {tool}: path outside allowed folders -> {', '.join(outside)}"
        alerts.notify("agent-guard blocked a tool call", message[:200], enabled=cfg.alerts)
    except Exception:
        pass


def block_reason(event: Event, decision: Decision) -> str:
    """The one-line reason shown when a call is blocked. Shared by the adapters
    that report on stderr; Bash exfil and path-fence get their own wording."""
    if decision.bash_blocked:
        reasons = "; ".join(f.detail for f in decision.findings if f.severity == bashinspect.BLOCK)
        return (
            f"agent-guard blocked {event.tool}: {reasons}. "
            f'Set "bash_enforce": false in {config.config_path()} to allow.'
        )
    return (
        f"agent-guard blocked {event.tool}: path outside allowed folders -> {decision.outside}. "
        f"Add the folder to {config.config_path()} (allowed_roots) if intended."
    )


def run_adapter(adapter, stdin_text: str) -> int:
    """Parse -> decide -> log -> emit, for any adapter.

    A parse failure returns ALLOW without touching config or the log, so garbage
    on stdin can never brick or even record against the agent. Otherwise the call
    is logged and the adapter emits its verdict (exit code, and any message).
    """
    try:
        event = adapter.parse(stdin_text)
    except Exception:
        return ALLOW  # fail open: malformed event, allow and don't log
    cfg = config.load()
    decision = decide(event, cfg)
    append_log(cfg.log_path, build_log_entry(event, decision))
    return adapter.emit(event, decision, cfg)


def emit_stderr(event: Event, decision: Decision, cfg) -> int:
    """Emit a verdict the Claude Code / Gemini CLI way: exit 2 with the reason on
    stderr, exit 0 (silently) to allow. Used by every stdin+exit-code adapter."""
    if not decision.blocked:
        return ALLOW
    alert(cfg, event.tool, decision.bash_blocked, decision.findings, decision.outside)
    print(block_reason(event, decision), file=sys.stderr)
    return BLOCK
