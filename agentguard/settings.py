"""Read/merge Claude Code's settings.json for the install/uninstall/harden commands.

All edits are merge-in-place: we read the file, change only what we own, and
write it back. Existing hooks, env, permissions, and everything else are kept.
"""
from __future__ import annotations

import json
from pathlib import Path

# Marker that identifies the PreToolUse hook entry that belongs to agent-guard,
# so uninstall can find and remove exactly it (and install can dedup).
HOOK_TAG = "agentguard"

# Read-deny rules `harden` adds. These complement the folder fence by keeping
# tools away from credentials wherever they live on disk.
HARDEN_DENY = [
    "Read(**/.ssh/**)",
    "Read(**/.aws/**)",
    "Read(**/.gnupg/**)",
    "Read(**/.config/gcloud/**)",
    "Read(**/.netrc)",
    "Read(**/.env)",
    "Read(**/.env.*)",
    "Read(**/id_rsa)",
    "Read(**/id_ed25519)",
    "Read(**/*.pem)",
    "Read(**/AppData/**/Login Data)",
    "Read(**/Library/Keychains/**)",
]


def settings_path() -> Path:
    return Path.home() / ".claude" / "settings.json"


def load(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except ValueError as exc:
        raise SystemExit(f"error: {path} is not valid JSON ({exc}); fix it before running this.") from exc


def save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _is_agentguard_hook(block: dict) -> bool:
    for h in block.get("hooks", []):
        blob = (h.get("command", "") + " " + " ".join(h.get("args", []) or [])).lower()
        if HOOK_TAG in blob or "guard.py" in blob:
            return True
    return False


def find_hook(data: dict) -> bool:
    return any(_is_agentguard_hook(b) for b in data.get("hooks", {}).get("PreToolUse", []))


def add_hook(data: dict, command: str, args: list[str], timeout: int = 10) -> dict:
    """Install (or replace) agent-guard's PreToolUse hook, leaving others intact."""
    hooks = data.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])
    pre = [b for b in pre if not _is_agentguard_hook(b)]
    pre.append({"hooks": [{"type": "command", "command": command, "args": args, "timeout": timeout}]})
    hooks["PreToolUse"] = pre
    return data


def remove_hook(data: dict) -> int:
    pre = data.get("hooks", {}).get("PreToolUse")
    if not pre:
        return 0
    kept = [b for b in pre if not _is_agentguard_hook(b)]
    removed = len(pre) - len(kept)
    data["hooks"]["PreToolUse"] = kept
    return removed


def add_deny(data: dict, rules: list[str]) -> list[str]:
    perms = data.setdefault("permissions", {})
    deny = perms.setdefault("deny", [])
    added = [r for r in rules if r not in deny]
    deny.extend(added)
    return added
