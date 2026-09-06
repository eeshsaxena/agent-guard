"""agent-guard: see what your AI coding agent touches, and fence it in.

A PreToolUse hook for Claude Code that logs every tool call and blocks file
access outside folders you allow, plus a local live dashboard. Stdlib only.
"""
from __future__ import annotations

from . import adapters, alerts, bashinspect, config, core, dashboard, guard, integrity, sandbox

__all__ = [
    "adapters", "alerts", "bashinspect", "config", "core", "dashboard",
    "guard", "integrity", "sandbox", "__version__",
]
__version__ = "0.4.1"
