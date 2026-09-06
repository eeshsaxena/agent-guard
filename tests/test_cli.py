import json

from agentguard import cli, config, guard, sandbox, settings


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


def test_run_requires_a_command(ag_config, capsys):
    assert cli.main(["run"]) == 2
    assert "usage" in capsys.readouterr().err


def test_run_reports_when_sandbox_unavailable(ag_config, monkeypatch, capsys):
    monkeypatch.setattr(sandbox, "build_sandbox_command", lambda cmd, roots: (None, "no sandbox here"))
    assert cli.main(["run", "--", "ls"]) == 1
    assert "no sandbox here" in capsys.readouterr().err


def test_run_invokes_wrapped_command(ag_config, monkeypatch):
    seen = {}

    def fake_call(argv):
        seen["argv"] = argv
        return 0

    monkeypatch.setattr(sandbox, "build_sandbox_command", lambda cmd, roots: (["bwrap", "--", *cmd], ""))
    monkeypatch.setattr(cli.subprocess, "call", fake_call)
    assert cli.main(["run", "--", "echo", "hi"]) == 0
    assert seen["argv"] == ["bwrap", "--", "echo", "hi"]


def _log_some(ag_config, n=3):
    inside = str(ag_config.tmp / "project" / "a.txt")
    for _ in range(n):
        guard.run(json.dumps({"tool_name": "Read", "tool_input": {"file_path": inside}}))


def test_verify_log_intact(ag_config, capsys):
    _log_some(ag_config)
    assert cli.main(["verify-log"]) == 0
    assert "INTACT" in capsys.readouterr().out


def test_verify_log_detects_in_place_edit(ag_config, capsys):
    _log_some(ag_config)
    lines = ag_config.log.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[1])
    entry["tool"] = "Bash"                    # edit content, keep the stored hash
    lines[1] = json.dumps(entry)
    ag_config.log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert cli.main(["verify-log"]) == 1
    assert "BROKEN" in capsys.readouterr().out


def test_verify_log_detects_deleted_line(ag_config, capsys):
    _log_some(ag_config, n=4)
    lines = ag_config.log.read_text(encoding="utf-8").splitlines()
    del lines[1]
    ag_config.log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert cli.main(["verify-log"]) == 1


def test_verify_log_tolerates_corrupt_legacy_line(ag_config, capsys):
    # A malformed line before any hashed entry is legacy noise, not tampering.
    ag_config.log.write_text('{"tool":"Read"}\nnot json at all\n', encoding="utf-8")
    assert cli.main(["verify-log"]) == 0
    out = capsys.readouterr().out
    assert "INTACT" in out and "unreadable" in out


def test_verify_log_detects_corruption_after_chain_starts(ag_config, capsys):
    _log_some(ag_config)                          # hashed entries
    with ag_config.log.open("a", encoding="utf-8") as fh:
        fh.write("}corrupt truncated line\n")     # break after the chain started
    assert cli.main(["verify-log"]) == 1
    assert "BROKEN" in capsys.readouterr().out


def test_verify_log_no_file_is_ok(ag_config, capsys):
    assert not ag_config.log.exists()
    assert cli.main(["verify-log"]) == 0
    assert "nothing to verify" in capsys.readouterr().out


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
