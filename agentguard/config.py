"""Configuration loading for agent-guard.

Resolution order for the config file:
1. $AGENTGUARD_CONFIG
2. a config.json next to the project (back-compat with the original layout)
3. ~/.agentguard/config.json  (what `agentguard install` writes)
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent


def config_path() -> Path:
    env = os.environ.get("AGENTGUARD_CONFIG")
    if env:
        return Path(env)
    local = _REPO_ROOT / "config.json"
    if local.exists():
        return local
    return Path.home() / ".agentguard" / "config.json"


def default_roots() -> list[str]:
    home = Path.home()
    return [str(home / "Downloads"), str(home / ".claude")]


@dataclass
class Config:
    roots: list[Path]
    log_path: Path
    enforce: bool


def load() -> Config:
    path = config_path()
    try:
        cfg = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        cfg = {}
    roots = []
    for r in cfg.get("allowed_roots", default_roots()):
        try:
            roots.append(Path(os.path.expandvars(os.path.expanduser(r))).resolve())
        except Exception:
            pass
    log_path = Path(os.path.expandvars(os.path.expanduser(
        cfg.get("log_path", str(path.parent / "access-log.jsonl"))
    )))
    return Config(roots=roots, log_path=log_path, enforce=bool(cfg.get("enforce", True)))
