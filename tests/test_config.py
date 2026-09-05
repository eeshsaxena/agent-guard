
from agentguard import config


def test_env_var_takes_precedence(tmp_path, monkeypatch):
    p = tmp_path / "custom.json"
    p.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("AGENTGUARD_CONFIG", str(p))
    assert config.config_path() == p


def test_load_expands_and_resolves_roots(ag_config):
    ag_config.write(roots=[str(ag_config.tmp / "project")])
    cfg = config.load()
    assert cfg.enforce is True
    assert any(r.name == "project" for r in cfg.roots)


def test_load_defaults_when_file_missing(tmp_path, monkeypatch):
    missing = tmp_path / "nope.json"
    monkeypatch.setenv("AGENTGUARD_CONFIG", str(missing))
    cfg = config.load()
    assert cfg.enforce is True          # default
    assert len(cfg.roots) >= 1          # default roots
    assert cfg.log_path.name == "access-log.jsonl"


def test_enforce_false_is_read(ag_config):
    ag_config.write(enforce=False)
    assert config.load().enforce is False


def test_bad_json_falls_back_to_defaults(tmp_path, monkeypatch):
    p = tmp_path / "broken.json"
    p.write_text("{ not json", encoding="utf-8")
    monkeypatch.setenv("AGENTGUARD_CONFIG", str(p))
    cfg = config.load()  # must not raise
    assert cfg.enforce is True
