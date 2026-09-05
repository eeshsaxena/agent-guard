import json

import pytest


@pytest.fixture
def ag_config(tmp_path, monkeypatch):
    """Isolate agent-guard onto a temp config + log so tests never touch real state."""
    log = tmp_path / "access-log.jsonl"
    cfg = tmp_path / "config.json"

    def write(enforce=True, roots=None):
        roots = roots if roots is not None else [str(tmp_path / "project")]
        cfg.write_text(json.dumps({
            "enforce": enforce,
            "allowed_roots": roots,
            "log_path": str(log),
        }), encoding="utf-8")
        return cfg

    write()  # sensible default; tests can rewrite
    monkeypatch.setenv("AGENTGUARD_CONFIG", str(cfg))
    (tmp_path / "project").mkdir()
    return type("C", (), {"cfg": cfg, "log": log, "tmp": tmp_path, "write": staticmethod(write)})
