"""The PreToolUse guard: log every tool call, block file access outside allowed roots.

Reads the tool JSON on stdin. Exit 2 blocks the call (reason on stderr shown to
Claude); exit 0 allows it. Fails OPEN on any internal error so a bug here can
never brick the agent.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from . import bashinspect, config

# Tools whose paths we enforce (they read or write file contents).
ENFORCED = {"Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Grep", "Glob"}
PATH_KEYS = ("file_path", "notebook_path", "path")


def _target_paths(tool: str, tool_input: dict) -> list[str]:
    return [tool_input[k] for k in PATH_KEYS if isinstance(tool_input.get(k), str)]


def _inside_any(path: str, roots: list[Path]) -> bool:
    try:
        p = Path(os.path.expandvars(os.path.expanduser(path))).resolve()
    except Exception:
        return True  # unresolvable -> do not block
    for r in roots:
        try:
            p.relative_to(r)
            return True
        except ValueError:
            continue
    return False


def _append_log(log_path: Path, entry: dict) -> None:
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def run(stdin_text: str) -> int:
    try:
        data = json.loads(stdin_text or "{}")
    except Exception:
        return 0

    tool = data.get("tool_name", "")
    tool_input = data.get("tool_input") or {}
    cfg = config.load()

    paths = _target_paths(tool, tool_input) if tool in ENFORCED else []
    outside = [p for p in paths if cfg.roots and not _inside_any(p, cfg.roots)]
    blocked = bool(outside) and cfg.enforce and tool in ENFORCED

    findings = []
    if tool == "Bash" and cfg.inspect_bash:
        command = tool_input.get("command")
        if isinstance(command, str):
            findings = bashinspect.inspect(command, cfg.roots)
    bash_blocked = cfg.bash_enforce and any(f.severity == bashinspect.BLOCK for f in findings)
    blocked = blocked or bash_blocked

    _append_log(cfg.log_path, {
        "ts": time.time(),
        "tool": tool,
        "paths": paths,
        "command": tool_input.get("command") if tool == "Bash" else None,
        "url": tool_input.get("url") if tool == "WebFetch" else None,
        "outside": outside,
        "suspicious": bool(findings),
        "findings": [f.as_dict() for f in findings],
        "blocked": blocked,
        "cwd": data.get("cwd"),
    })

    if blocked:
        if bash_blocked:
            reasons = "; ".join(f.detail for f in findings if f.severity == bashinspect.BLOCK)
            print(
                f"agent-guard blocked Bash: {reasons}. "
                f'Set "bash_enforce": false in {config.config_path()} to allow.',
                file=sys.stderr,
            )
        else:
            print(
                f"agent-guard blocked {tool}: path outside allowed folders -> {outside}. "
                f"Add the folder to {config.config_path()} (allowed_roots) if intended.",
                file=sys.stderr,
            )
        return 2
    return 0


def main() -> int:
    return run(sys.stdin.read())


if __name__ == "__main__":
    raise SystemExit(main())
