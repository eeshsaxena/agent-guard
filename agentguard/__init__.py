"""agent-guard: see what your AI coding agent touches, and fence it in.

A PreToolUse hook for Claude Code that logs every tool call and blocks file
access outside folders you allow, plus a local live dashboard. Stdlib only.
"""
from __future__ import annotations

from . import bashinspect, config, dashboard, guard, sandbox

__all__ = ["bashinspect", "config", "dashboard", "guard", "sandbox", "__version__"]
__version__ = "0.2.0"
