
from agentguard import settings


def test_add_hook_preserves_existing_hooks_and_keys():
    data = {
        "model": "x",
        "hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "other-tool"}]}]},
    }
    settings.add_hook(data, "agentguard", ["hook"])
    pre = data["hooks"]["PreToolUse"]
    assert len(pre) == 2                      # existing kept + ours added
    assert data["model"] == "x"               # unrelated keys untouched
    assert settings.find_hook(data) is True


def test_add_hook_is_idempotent():
    data = {}
    settings.add_hook(data, "agentguard", ["hook"])
    settings.add_hook(data, "agentguard", ["hook"])
    ours = [b for b in data["hooks"]["PreToolUse"] if settings._is_agentguard_hook(b)]
    assert len(ours) == 1                      # replaced, not duplicated


def test_remove_hook_only_removes_ours():
    data = {"hooks": {"PreToolUse": [
        {"hooks": [{"type": "command", "command": "other-tool"}]},
        {"hooks": [{"type": "command", "command": "agentguard", "args": ["hook"]}]},
    ]}}
    removed = settings.remove_hook(data)
    assert removed == 1
    assert len(data["hooks"]["PreToolUse"]) == 1
    assert settings.find_hook(data) is False


def test_detects_legacy_guardpy_hook():
    data = {"hooks": {"PreToolUse": [
        {"hooks": [{"type": "command", "command": "python", "args": ["C:/x/guard.py"]}]},
    ]}}
    assert settings.find_hook(data) is True


def test_add_deny_dedups():
    data = {"permissions": {"deny": ["Read(**/.ssh/**)"]}}
    added = settings.add_deny(data, settings.HARDEN_DENY)
    assert "Read(**/.ssh/**)" not in added          # already present
    assert "Read(**/.aws/**)" in added
    assert data["permissions"]["deny"].count("Read(**/.ssh/**)") == 1


def test_load_save_roundtrip(tmp_path):
    p = tmp_path / "settings.json"
    settings.save(p, {"a": 1})
    assert settings.load(p) == {"a": 1}


def test_load_missing_file_returns_empty(tmp_path):
    assert settings.load(tmp_path / "nope.json") == {}
