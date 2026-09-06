"""The `agentguard` command.

    agentguard hook [--agent NAME]  # run the pre-tool-call guard (default agent: claude-code)
    agentguard run -- <command>     # run a command inside an OS filesystem sandbox
    agentguard dashboard [--port]   # open the live activity dashboard
    agentguard verify-log           # check the audit log's hash chain for tampering
    agentguard install              # add the PreToolUse hook to ~/.claude/settings.json
    agentguard uninstall            # remove it again
    agentguard status               # show config, whether the hook is installed, recent counts
    agentguard harden [--apply]     # add credential read-deny rules (dry-run without --apply)

`hook` is what Claude Code invokes on every tool call; the rest are for you.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

from . import __version__, adapters, config, core, dashboard, integrity, sandbox, settings


def _fix_stdout_encoding() -> None:
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        try:
            reconfigure(encoding="utf-8")
        except Exception:
            pass


def cmd_hook(args) -> int:
    adapter = adapters.get_adapter(args.agent)
    if adapter is None:
        print(
            f"agentguard hook: unknown agent {args.agent!r}. Available: {', '.join(adapters.available())}.",
            file=sys.stderr,
        )
        return 2
    return core.run_adapter(adapter, sys.stdin.read())


def cmd_run(args) -> int:
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("usage: agentguard run -- <command> [args...]", file=sys.stderr)
        return 2
    roots = [str(r) for r in config.load().roots]
    argv, message = sandbox.build_sandbox_command(command, roots)
    if argv is None:
        print(message, file=sys.stderr)
        return 1
    print(
        f"agent-guard: sandboxing with {argv[0]}; writable roots: {', '.join(roots) or '(none configured)'}",
        file=sys.stderr,
    )
    try:
        return subprocess.call(argv)
    except FileNotFoundError:
        print(f"agent-guard run: could not launch {argv[0]}.", file=sys.stderr)
        return 1


def cmd_dashboard(args) -> int:
    try:
        dashboard.serve(args.port)
    except KeyboardInterrupt:
        print("\nstopped.")
    return 0


def cmd_verify_log(args) -> int:
    log_path = config.load().log_path
    if not log_path.exists():
        print(f"verify-log: no log at {log_path} (nothing to verify).")
        return 0
    entries, lineno, unreadable = [], [], 0
    for i, line in enumerate(log_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except ValueError:
            entries.append(None)  # keep the position; the chain decides if it matters
            unreadable += 1
        lineno.append(i)
    ok, idx, detail = integrity.verify_chain(entries)
    if not ok:
        print(f"verify-log: BROKEN at line {lineno[idx]} (entry {idx}): {detail}.")
        print("The audit log has been edited, reordered, or truncated since it was written.")
        return 1
    hashed = sum(1 for e in entries if isinstance(e, dict) and e.get("hash"))
    note = f", {unreadable} unreadable legacy line(s) skipped" if unreadable else ""
    if hashed == 0:
        print(f"verify-log: INTACT. {len(entries)} entries, none hashed yet (pre-hash log{note}) - {log_path}")
    else:
        print(f"verify-log: INTACT. {hashed} hashed of {len(entries)} entries verified{note} - {log_path}")
    return 0


def _hook_invocation() -> tuple[str, list[str]]:
    """How Claude Code should call the guard.

    Prefer the installed console script (`agentguard hook`); fall back to running
    the top-level shim with the current interpreter if the script isn't resolvable.
    """
    from shutil import which
    exe = which("agentguard")
    if exe:
        return "agentguard", ["hook"]
    shim = Path(__file__).resolve().parent.parent / "guard.py"
    return sys.executable, [str(shim)]


def cmd_install(args) -> int:
    path = settings.settings_path()
    data = settings.load(path)
    command, hook_args = _hook_invocation()
    settings.add_hook(data, command, hook_args)
    settings.save(path, data)
    # Make sure a config exists so the guard has roots to enforce.
    cfg_path = config.config_path()
    if not cfg_path.exists():
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text(json.dumps({
            "enforce": True,
            "allowed_roots": config.default_roots(),
            "log_path": str(cfg_path.parent / "access-log.jsonl"),
            "inspect_bash": True,
            "bash_enforce": True,
            "alerts": True,
        }, indent=2), encoding="utf-8")
        print(f"wrote default config: {cfg_path}")
    print(f"installed PreToolUse hook in {path}")
    print(f"  runs: {command} {' '.join(hook_args)}")
    print("Open a NEW Claude Code session (or run /hooks) for it to take effect.")
    return 0


def cmd_uninstall(args) -> int:
    path = settings.settings_path()
    data = settings.load(path)
    n = settings.remove_hook(data)
    settings.save(path, data)
    print(f"removed {n} agent-guard hook entr{'y' if n == 1 else 'ies'} from {path}")
    return 0


def cmd_status(args) -> int:
    cfg = config.load()
    path = settings.settings_path()
    installed = settings.find_hook(settings.load(path))
    print(f"agent-guard {__version__}")
    print(f"config     : {config.config_path()}")
    print(f"enforce    : {cfg.enforce}  ({'BLOCKING' if cfg.enforce else 'log-only'})")
    print(f"alerts     : {cfg.alerts}")
    print(f"log        : {cfg.log_path}")
    print("allowed roots:")
    for r in cfg.roots:
        print(f"  - {r}")
    print(f"hook       : {'installed' if installed else 'NOT installed'} ({path})")
    entries = dashboard.read_log(cfg.log_path)
    if entries:
        kinds = Counter(e.get("tool", "?") for e in entries)
        blocked = sum(1 for e in entries if e.get("blocked"))
        print(f"recent     : {len(entries)} calls  {dict(kinds)}  blocked={blocked}")
    return 0


def cmd_harden(args) -> int:
    path = settings.settings_path()
    data = settings.load(path)
    if not args.apply:
        print("harden (dry-run) would add these read-deny rules to permissions.deny:")
        for r in settings.HARDEN_DENY:
            print(f"  {r}")
        print("\nThese keep tools away from credentials wherever they live, alongside")
        print("the folder fence. Re-run with --apply to write them to settings.json.")
        return 0
    added = settings.add_deny(data, settings.HARDEN_DENY)
    settings.save(path, data)
    print(f"added {len(added)} deny rule(s) to {path}")
    for r in added:
        print(f"  + {r}")
    if not added:
        print("  (all rules were already present)")
    return 0


def main(argv=None) -> int:
    _fix_stdout_encoding()
    ap = argparse.ArgumentParser(prog="agentguard", description="See what your AI agent touches, and fence it in.")
    ap.add_argument("--version", action="version", version=f"agent-guard {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("hook", help="run the pre-tool-call guard (reads the tool event on stdin)")
    p.add_argument(
        "--agent", default=adapters.DEFAULT,
        help=f"which agent's event format to parse (default: {adapters.DEFAULT}; also: {', '.join(adapters.available())})",
    )
    p.set_defaults(func=cmd_hook)

    p = sub.add_parser("run", help="run a command inside an OS filesystem sandbox (allowed_roots only)")
    p.add_argument("command", nargs=argparse.REMAINDER, help="-- <command> [args...]")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("dashboard", help="serve the live activity dashboard")
    p.add_argument("--port", type=int, default=dashboard.DEFAULT_PORT)
    p.set_defaults(func=cmd_dashboard)

    sub.add_parser(
        "verify-log", help="recompute the audit-log hash chain and report tampering (exit 1 if broken)"
    ).set_defaults(func=cmd_verify_log)

    sub.add_parser("install", help="add the PreToolUse hook to ~/.claude/settings.json").set_defaults(func=cmd_install)
    sub.add_parser("uninstall", help="remove the PreToolUse hook").set_defaults(func=cmd_uninstall)
    sub.add_parser("status", help="show config, hook state, and recent activity").set_defaults(func=cmd_status)

    p = sub.add_parser("harden", help="add credential read-deny rules (dry-run without --apply)")
    p.add_argument("--apply", action="store_true", help="write the rules (default is dry-run)")
    p.set_defaults(func=cmd_harden)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
