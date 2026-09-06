"""The Claude Code PreToolUse guard: the entry point Claude Code invokes.

Reads the tool JSON on stdin. Exit 2 blocks the call (reason on stderr shown to
Claude); exit 0 allows it. Fails OPEN on any internal error so a bug here can
never brick the agent.

The decision logic now lives in `core`, shared across agents; this module is the
`claude-code` adapter's entry point and keeps the same stdin schema, exit codes,
and fail-open behavior it always had. See `adapters` for the other agents.
"""
from __future__ import annotations

import sys

from . import adapters, core

# Re-exported for back-compat with anything importing them from here.
ENFORCED = core.ENFORCED
PATH_KEYS = core.PATH_KEYS


def run(stdin_text: str) -> int:
    return core.run_adapter(adapters.ClaudeCodeAdapter(), stdin_text)


def main() -> int:
    return run(sys.stdin.read())


if __name__ == "__main__":
    raise SystemExit(main())
