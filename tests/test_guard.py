import json

from agentguard import guard


def _read_log(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _payload(tool, **tool_input):
    return json.dumps({"tool_name": tool, "tool_input": tool_input, "cwd": "x"})


def test_allows_path_inside_root(ag_config):
    inside = str(ag_config.tmp / "project" / "a.txt")
    assert guard.run(_payload("Read", file_path=inside)) == 0
    log = _read_log(ag_config.log)
    assert log[-1]["blocked"] is False
    assert log[-1]["outside"] == []


def test_blocks_path_outside_root_when_enforcing(ag_config):
    outside = str(ag_config.tmp / "elsewhere" / "secret.txt")
    assert guard.run(_payload("Read", file_path=outside)) == 2
    log = _read_log(ag_config.log)
    assert log[-1]["blocked"] is True
    assert log[-1]["outside"] == [outside]


def test_log_only_mode_never_blocks(ag_config):
    ag_config.write(enforce=False)
    outside = str(ag_config.tmp / "elsewhere" / "secret.txt")
    assert guard.run(_payload("Read", file_path=outside)) == 0
    log = _read_log(ag_config.log)
    assert log[-1]["blocked"] is False
    assert log[-1]["outside"] == [outside]  # still recorded


def test_write_and_multiedit_are_enforced(ag_config):
    outside = str(ag_config.tmp / "elsewhere" / "x.txt")
    assert guard.run(_payload("Write", file_path=outside)) == 2
    assert guard.run(_payload("MultiEdit", file_path=outside)) == 2


def test_bash_is_logged_but_not_path_blocked(ag_config):
    assert guard.run(_payload("Bash", command="rm -rf /elsewhere")) == 0
    log = _read_log(ag_config.log)
    assert log[-1]["tool"] == "Bash"
    assert log[-1]["command"] == "rm -rf /elsewhere"
    assert log[-1]["blocked"] is False


def test_webfetch_url_is_recorded(ag_config):
    assert guard.run(_payload("WebFetch", url="https://example.com")) == 0
    assert _read_log(ag_config.log)[-1]["url"] == "https://example.com"


def test_fails_open_on_garbage_stdin(ag_config):
    assert guard.run("not json at all {{{") == 0


def test_no_roots_configured_blocks_nothing(ag_config):
    ag_config.write(roots=[])
    outside = str(ag_config.tmp / "elsewhere" / "x.txt")
    assert guard.run(_payload("Read", file_path=outside)) == 0


def test_notebook_path_key_is_checked(ag_config):
    outside = str(ag_config.tmp / "elsewhere" / "nb.ipynb")
    assert guard.run(_payload("NotebookEdit", notebook_path=outside)) == 2
