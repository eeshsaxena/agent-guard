import json

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


def test_repo_local_config_used_when_no_env(tmp_path, monkeypatch):
    # Resolution order tier 2: a config.json next to the package, no env override.
    monkeypatch.delenv("AGENTGUARD_CONFIG", raising=False)
    monkeypatch.setattr(config, "_REPO_ROOT", tmp_path)
    local = tmp_path / "config.json"
    local.write_text("{}", encoding="utf-8")
    assert config.config_path() == local


def test_home_config_is_the_final_fallback(tmp_path, monkeypatch):
    # Resolution order tier 3: no env, no repo-local -> ~/.agentguard/config.json.
    monkeypatch.delenv("AGENTGUARD_CONFIG", raising=False)
    repo = tmp_path / "repo"
    repo.mkdir()
    home = tmp_path / "home"
    monkeypatch.setattr(config, "_REPO_ROOT", repo)
    monkeypatch.setattr(config.Path, "home", lambda: home)
    assert config.config_path() == home / ".agentguard" / "config.json"


def test_new_toggle_keys_are_read(tmp_path, monkeypatch):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"inspect_bash": False, "bash_enforce": False, "alerts": False}), encoding="utf-8")
    monkeypatch.setenv("AGENTGUARD_CONFIG", str(p))
    cfg = config.load()
    assert cfg.inspect_bash is False
    assert cfg.bash_enforce is False
    assert cfg.alerts is False
