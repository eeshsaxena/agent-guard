"""Best-effort OS desktop notifications, fired when the guard blocks a call.

A blocked tool call is the moment you most want to see, so we pop a native
notification the instant it happens: PowerShell balloon on Windows, `osascript`
on macOS, `notify-send` on Linux.

Two rules, both non-negotiable so the notifier can never hurt the hook:
- non-blocking: the command is spawned and never waited on;
- fail-safe: any error (missing tool, bad platform, spawn failure) is swallowed.

`build_alert_command` is a pure function so the per-OS wiring is unit-testable
without ever popping a real notification; `notify` takes an injectable runner for
the same reason.
"""
from __future__ import annotations

import platform
import subprocess


def build_alert_command(system: str, title: str, message: str) -> list[str] | None:
    """Construct the per-OS notification command. Pure: launches nothing here.

    Returns None on a platform we don't have a notifier for.
    """
    if system == "Windows":
        return ["powershell", "-NoProfile", "-NonInteractive", "-Command", _windows_script(title, message)]
    if system == "Darwin":
        script = f"display notification {_osa_quote(message)} with title {_osa_quote(title)}"
        return ["osascript", "-e", script]
    if system == "Linux":
        return ["notify-send", "-u", "critical", title, message]
    return None


def notify(title: str, message: str, *, enabled: bool = True, system: str | None = None, runner=None) -> bool:
    """Fire a desktop notification, best effort.

    Returns True when a command was dispatched, False when disabled or the
    platform is unsupported. Never raises and never blocks.
    """
    if not enabled:
        return False
    try:
        argv = build_alert_command(system or platform.system(), title, message)
        if argv is None:
            return False
        (runner or _spawn)(argv)
        return True
    except Exception:
        return False


def _windows_script(title: str, message: str) -> str:
    """A one-line PowerShell balloon via System.Windows.Forms NotifyIcon.

    The tray icon has to outlive the balloon for it to render, hence the brief
    sleep; the process is detached, so this never delays the hook.
    """
    return (
        "Add-Type -AssemblyName System.Windows.Forms,System.Drawing;"
        "$n=New-Object System.Windows.Forms.NotifyIcon;"
        "$n.Icon=[System.Drawing.SystemIcons]::Warning;$n.Visible=$true;"
        f"$n.ShowBalloonTip(8000,{_ps_quote(title)},{_ps_quote(message)},"
        "[System.Windows.Forms.ToolTipIcon]::Warning);"
        "Start-Sleep -Milliseconds 6000;$n.Dispose()"
    )


def _ps_quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def _osa_quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _spawn(argv: list[str]) -> None:
    """Launch the notifier detached and swallow every error.

    We never wait on it; on Windows we also detach and hide the console so no
    window flashes.
    """
    kwargs: dict = {
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "stdin": subprocess.DEVNULL,
    }
    flags = 0
    for name in ("CREATE_NO_WINDOW", "DETACHED_PROCESS"):
        flags |= getattr(subprocess, name, 0)
    if flags:
        kwargs["creationflags"] = flags
    try:
        subprocess.Popen(argv, **kwargs)
    except Exception:
        pass
