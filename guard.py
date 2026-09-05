#!/usr/bin/env python3
"""Compatibility shim so an existing hook pointing at this path keeps working.

The real guard lives in the `agentguard` package next to this file. We add the
repo root to sys.path so `import agentguard` works without a pip install, then
delegate. New installs should use the console script instead: `agentguard hook`.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agentguard.guard import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
