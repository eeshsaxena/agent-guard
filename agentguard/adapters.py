"""Per-agent adapters: parse an agent's pre-tool-call event into a normalized
`core.Event`, and emit the guard's verdict the way that agent expects.

The shared policy lives in `core`; an adapter only knows its agent's wire format:
which tool names touch files, where the path/command/url live in the payload, and
how a block is signalled back (exit code, or a JSON verdict on stdout).

Supported today:
- claude-code : Claude Code PreToolUse. {tool_name, tool_input, cwd} on stdin,
                exit 2 blocks, stderr is the reason. The reference adapter.
- gemini-cli  : Gemini CLI BeforeTool. Same stdin shape and exit-2 contract as
                Claude Code, different tool vocabulary.
- cursor      : Cursor beforeShellExecution / beforeReadFile. Blocks by printing
                a {"permission": "deny"} verdict on stdout.
- generic     : a stable {tool, paths, command, url, cwd} schema so any agent or
                wrapper can integrate by piping that shape; exit 2 blocks.
"""
from __future__ import annotations

import json

from . import core


class _StdinExitAdapter:
    """Base for agents whose hook reads a tool event on stdin and blocks with
    exit 2 + a stderr reason. Subclasses set the tool vocabulary; `_normalize`
    turns {tool_name, tool_input} into the normalized fields."""

    name = ""
    file_tools: set = set()
    path_keys: tuple = ()
    list_path_keys: tuple = ()
    shell_tools: set = set()
    web_tools: set = set()

    def parse(self, stdin_text: str) -> core.Event:
        data = json.loads(stdin_text or "{}")
        tool = data.get("tool_name", "")
        tool_input = data.get("tool_input") or {}
        paths, command, url = self._normalize(tool, tool_input)
        return core.Event(tool=tool, paths=paths, command=command, url=url, cwd=data.get("cwd"))

    def _normalize(self, tool: str, tool_input: dict):
        paths: list[str] = []
        if tool in self.file_tools:
            for k in self.path_keys:
                v = tool_input.get(k)
                if isinstance(v, str):
                    paths.append(v)
            for k in self.list_path_keys:
                v = tool_input.get(k)
                if isinstance(v, list):
                    paths.extend(x for x in v if isinstance(x, str))
        command = tool_input.get("command") if tool in self.shell_tools else None
        url = tool_input.get("url") if tool in self.web_tools else None
        return paths, command, url

    def emit(self, event: core.Event, decision: core.Decision, cfg) -> int:
        return core.emit_stderr(event, decision, cfg)


class ClaudeCodeAdapter(_StdinExitAdapter):
    """Claude Code PreToolUse. This is the live hook path; its parse and emit are
    the original inline behavior, unchanged."""

    name = "claude-code"
    file_tools = core.ENFORCED
    path_keys = core.PATH_KEYS
    shell_tools = {"Bash"}
    web_tools = {"WebFetch"}


class GeminiCliAdapter(_StdinExitAdapter):
    """Gemini CLI BeforeTool hook.

    Same stdin shape ({tool_name, tool_input, cwd}) and exit-2/stderr block
    contract as Claude Code, so it reuses the base; only the built-in tool names
    and argument keys differ. Path keys are kept broad (file_path/absolute_path/
    path/dir_path) so a renamed argument still gets fenced rather than silently
    skipped.
    """

    name = "gemini-cli"
    file_tools = {
        "read_file", "write_file", "replace", "read_many_files",
        "glob", "grep_search", "search_file_content", "list_directory",
    }
    path_keys = ("file_path", "absolute_path", "path", "dir_path")
    list_path_keys = ("paths", "file_paths")
    shell_tools = {"run_shell_command"}
    web_tools = {"web_fetch"}


class GenericAdapter(_StdinExitAdapter):
    """Bring-your-own-agent: read the normalized schema straight off stdin.

        {"tool": "...", "paths": ["..."], "command": "...", "url": "...", "cwd": "..."}

    Every field is optional. Any agent or wrapper that can shell out and pipe this
    shape gets the same fence and Bash inspection; exit 2 blocks, stderr is why.
    """

    name = "generic"

    def parse(self, stdin_text: str) -> core.Event:
        data = json.loads(stdin_text or "{}")
        if not isinstance(data, dict):
            return core.Event()
        raw_paths = data.get("paths") or []
        paths = [p for p in raw_paths if isinstance(p, str)] if isinstance(raw_paths, list) else []
        command = data.get("command") if isinstance(data.get("command"), str) else None
        url = data.get("url") if isinstance(data.get("url"), str) else None
        tool = data.get("tool")
        if not isinstance(tool, str) or not tool:
            tool = _infer_label(paths, command, url)
        return core.Event(tool=tool, paths=paths, command=command, url=url, cwd=data.get("cwd"))


class CursorAdapter:
    """Cursor agent hooks (beforeShellExecution, beforeReadFile).

    Cursor picks the hook by `hook_event_name` and passes the command or file_path
    at the top level of the payload (not under a tool_input object). Unlike the
    exit-code agents, it expects a JSON verdict on stdout:

        {"permission": "allow" | "deny", "agent_message": "...", "user_message": "..."}

    We print that verdict and also return exit 2 on a block, which Cursor honors as
    a fallback.
    """

    name = "cursor"
    _SHELL_EVENTS = {"beforeShellExecution"}
    _READ_EVENTS = {"beforeReadFile"}

    def parse(self, stdin_text: str) -> core.Event:
        data = json.loads(stdin_text or "{}")
        if not isinstance(data, dict):
            return core.Event()
        ev = data.get("hook_event_name", "")
        command = data.get("command") if ev in self._SHELL_EVENTS and isinstance(data.get("command"), str) else None
        paths = []
        if ev in self._READ_EVENTS and isinstance(data.get("file_path"), str):
            paths = [data["file_path"]]
        return core.Event(tool=ev or "cursor", paths=paths, command=command, url=None, cwd=data.get("cwd"))

    def emit(self, event: core.Event, decision: core.Decision, cfg) -> int:
        if not decision.blocked:
            print(json.dumps({"permission": "allow"}))
            return core.ALLOW
        core.alert(cfg, event.tool, decision.bash_blocked, decision.findings, decision.outside)
        reason = core.block_reason(event, decision)
        print(json.dumps({"permission": "deny", "agent_message": reason, "user_message": reason}))
        return core.BLOCK


def _infer_label(paths, command, url) -> str:
    if command:
        return "shell"
    if paths:
        return "file"
    if url:
        return "web"
    return "tool"


_ADAPTERS = {
    a.name: a
    for a in (ClaudeCodeAdapter, GeminiCliAdapter, CursorAdapter, GenericAdapter)
}

DEFAULT = ClaudeCodeAdapter.name


def available() -> list[str]:
    return list(_ADAPTERS)


def get_adapter(name: str):
    cls = _ADAPTERS.get(name)
    return cls() if cls else None
