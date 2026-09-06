from agentguard import alerts


def test_windows_command_uses_powershell_notifyicon():
    argv = alerts.build_alert_command("Windows", "title", "hello")
    assert argv[0] == "powershell"
    script = argv[-1]
    assert "NotifyIcon" in script
    assert "ShowBalloonTip" in script
    assert "'title'" in script and "'hello'" in script


def test_windows_command_escapes_single_quotes():
    argv = alerts.build_alert_command("Windows", "it's", "a'b")
    script = argv[-1]
    assert "'it''s'" in script
    assert "'a''b'" in script


def test_macos_command_uses_osascript():
    argv = alerts.build_alert_command("Darwin", "title", "hello")
    assert argv[0] == "osascript"
    assert argv[1] == "-e"
    assert 'display notification "hello" with title "title"' == argv[2]


def test_macos_command_escapes_quotes_and_backslashes():
    argv = alerts.build_alert_command("Darwin", 'a"b', "c\\d")
    assert '\\"' in argv[2]
    assert "c\\\\d" in argv[2]


def test_linux_command_uses_notify_send():
    argv = alerts.build_alert_command("Linux", "title", "hello")
    assert argv[0] == "notify-send"
    assert argv[-2:] == ["title", "hello"]


def test_unknown_platform_returns_none():
    assert alerts.build_alert_command("Plan9", "t", "m") is None


def test_notify_dispatches_via_injected_runner():
    seen = {}
    ok = alerts.notify("t", "m", system="Linux", runner=lambda argv: seen.setdefault("argv", argv))
    assert ok is True
    assert seen["argv"][0] == "notify-send"


def test_notify_noops_when_disabled():
    called = []
    ok = alerts.notify("t", "m", enabled=False, system="Linux", runner=lambda argv: called.append(argv))
    assert ok is False
    assert called == []  # runner never invoked


def test_notify_returns_false_on_unsupported_platform():
    called = []
    ok = alerts.notify("t", "m", system="Plan9", runner=lambda argv: called.append(argv))
    assert ok is False
    assert called == []


def test_notify_swallows_runner_errors():
    def boom(argv):
        raise RuntimeError("no display")

    # A failing notifier must never propagate out of notify().
    assert alerts.notify("t", "m", system="Linux", runner=boom) is False
