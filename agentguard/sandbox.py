"""OS-level filesystem sandbox for `agentguard run`.

The PreToolUse hook is advisory: it sees a call and can refuse it, but nothing
stops a subprocess from touching the disk directly. `run` launches a command
inside a real OS fence that confines reads/writes to the allowed roots.

Support is honest and per-platform:
- Linux : bubblewrap (`bwrap`), falling back to `firejail`.
- macOS : `sandbox-exec` with a generated seatbelt profile.
- Windows: no clean native equivalent; we say so and refuse rather than pretend.

The command builders are pure functions so they can be unit-tested without the
real sandbox binaries; `build_sandbox_command` takes injectable `system`/`which`
for the same reason.
"""
from __future__ import annotations

import platform
import shutil

# Read-only system locations a program needs just to launch; user data stays
# fenced to the roots.
_LINUX_RO_BASE = ("/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/etc")

_WINDOWS_MESSAGE = (
    "agentguard run: OS-level filesystem sandboxing is not available on Windows.\n"
    "There is no clean native equivalent to bubblewrap or sandbox-exec here, and\n"
    "faking one would be dishonest. For a real fence, run the agent inside a\n"
    "container (Docker) or WSL2. The PreToolUse hook (agentguard install) still\n"
    "gives you advisory logging and blocking in the meantime."
)


def build_sandbox_command(command, roots, system=None, which=None):
    """Return (argv, message). argv is the wrapped command to exec, or None with
    a message to print when sandboxing is unavailable on this platform."""
    system = system or platform.system()
    which = which or shutil.which

    if system == "Windows":
        return None, _WINDOWS_MESSAGE
    if system == "Linux":
        if which("bwrap"):
            return linux_bwrap_args(command, roots), ""
        if which("firejail"):
            return linux_firejail_args(command, roots), ""
        return None, _no_tool_message("Linux", "bwrap (bubblewrap) or firejail")
    if system == "Darwin":
        if which("sandbox-exec"):
            return macos_sandbox_exec_args(command, roots), ""
        return None, _no_tool_message("macOS", "sandbox-exec")
    return None, f"agentguard run: no OS sandbox support known for {system!r}."


def linux_bwrap_args(command, roots) -> list[str]:
    argv = ["bwrap"]
    for base in _LINUX_RO_BASE:
        argv += ["--ro-bind-try", base, base]
    argv += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    for root in roots:
        argv += ["--bind", root, root]
    if roots:
        argv += ["--chdir", roots[0]]
    argv += ["--unshare-user", "--die-with-parent", "--"]
    return argv + list(command)


def linux_firejail_args(command, roots) -> list[str]:
    argv = ["firejail", "--quiet", "--noprofile", "--private-tmp"]
    for root in roots:
        argv.append(f"--whitelist={root}")
    argv.append("--")
    return argv + list(command)


def macos_sandbox_exec_args(command, roots) -> list[str]:
    return ["sandbox-exec", "-p", macos_profile(roots), *command]


def macos_profile(roots) -> str:
    """A seatbelt profile: deny by default, allow the reads a program needs to
    run, and grant read+write only inside the allowed roots."""
    lines = [
        "(version 1)",
        "(deny default)",
        "(allow process-exec)",
        "(allow process-fork)",
        "(allow sysctl-read)",
        "(allow mach-lookup)",
        "(allow file-read-metadata)",
        "(allow file-read*",
        '    (subpath "/usr")',
        '    (subpath "/bin")',
        '    (subpath "/sbin")',
        '    (subpath "/System")',
        '    (subpath "/Library")',
        '    (subpath "/dev"))',
    ]
    if roots:
        lines.append("(allow file-read* file-write*")
        lines += [f'    (subpath "{_sb_escape(r)}")' for r in roots]
        lines[-1] = lines[-1] + ")"
    lines += [
        "(allow file-write*",
        '    (subpath "/private/tmp")',
        '    (subpath "/private/var/tmp")',
        '    (literal "/dev/null"))',
    ]
    return "\n".join(lines) + "\n"


def _sb_escape(path: str) -> str:
    return path.replace("\\", "\\\\").replace('"', '\\"')


def _no_tool_message(os_name: str, tool: str) -> str:
    return (
        f"agentguard run: no supported sandbox tool found on {os_name} (looked for {tool}).\n"
        f"Install one and re-run. Refusing to run the command unsandboxed."
    )
