import json

from agentguard import cli, config, settings


def test_hook_subcommand_reads_stdin(ag_config, monkeypatch, capsys):
    import io
    outside = str(ag_config.tmp / "elsewhere" / "x.txt")
    monkeypatch.setattr("sys.stdin", io.StringIO(
        json.dumps({"tool_name": "Read", "tool_input": {"file_path": outside}})
    ))
    assert cli.main(["hook"]) == 2          # blocked -> exit 2


def test_status_runs(ag_config, capsys):
    assert cli.main(["status"]) == 0
    out = capsys.readouterr().out
    assert "allowed roots" in out
    assert "enforce" in out


def test_harden_dryrun_prints_rules_without_writing(tmp_path, monkeypatch, capsys):
    s = tmp_path / "settings.json"
    monkeypatch.setattr(settings, "settings_path", lambda: s)
    assert cli.main(["harden"]) == 0
    out = capsys.readouterr().out
    assert "Read(**/.ssh/**)" in out
    assert not s.exists()                    # dry-run wrote nothing


def test_harden_apply_writes_rules(tmp_path, monkeypatch):
    s = tmp_path / "settings.json"
    monkeypatch.setattr(settings, "settings_path", lambda: s)
    assert cli.main(["harden", "--apply"]) == 0
    data = json.loads(s.read_text(encoding="utf-8"))
    assert "Read(**/.ssh/**)" in data["permissions"]["deny"]


def test_install_uninstall_roundtrip(tmp_path, monkeypatch):
    s = tmp_path / ".claude" / "settings.json"
    c = tmp_path / ".agentguard" / "config.json"
    s.parent.mkdir(parents=True)
    s.write_text(json.dumps({"model": "keep-me"}), encoding="utf-8")
    monkeypatch.setattr(settings, "settings_path", lambda: s)
    monkeypatch.setattr(config, "config_path", lambda: c)

    assert cli.main(["install"]) == 0
    data = json.loads(s.read_text(encoding="utf-8"))
    assert settings.find_hook(data) is True
    assert data["model"] == "keep-me"        # existing settings preserved
    assert c.exists()                        # default config created

    assert cli.main(["uninstall"]) == 0
    assert settings.find_hook(json.loads(s.read_text(encoding="utf-8"))) is False
