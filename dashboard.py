#!/usr/bin/env python3
"""Compatibility shim: `python dashboard.py` still opens the dashboard.

Prefer the console script: `agentguard dashboard`.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agentguard.dashboard import serve  # noqa: E402

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8799
    try:
        serve(port)
    except KeyboardInterrupt:
        print("\nstopped.")
