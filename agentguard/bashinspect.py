"""Inspect Bash commands for risky operations the folder fence can't see.

The path fence only covers the file tools; a shell command can read a secret or
pipe it off the box without ever naming a path the guard checks. This module
looks at the command string and returns findings.

Policy (deliberately low false-positive):
- FLAG (log as suspicious, still allow) the broad signals: reads of credential
  files, network commands to a remote host, destructive ops or plain file
  access on absolute paths outside the allowed roots.
- BLOCK (severity "block") only the unambiguous case: credential material read
  AND handed to a network command with a remote destination in the same command.

Whether a "block" finding actually stops the call is the caller's decision
(config `bash_enforce`). Everything here fails OPEN: any parse error yields no
findings so a quirk in a command can never brick the agent.
"""
from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

FLAG = "flag"
BLOCK = "block"

# Credential/secret material. Matched per token, on both the whole (lowercased)
# token and its basename, so a quoted commit message that merely mentions ".env"
# is not treated as a file.
_CRED_DIR_PARTS = ("/.ssh/", "/.aws/", "/.gnupg/", "/.config/gcloud/", "/library/keychains/")
_CRED_NAMES = {"id_rsa", "id_ed25519", "id_dsa", "id_ecdsa", ".netrc", "login data"}
_CRED_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".keystore")

# Commands that move data off the machine.
_NET_CMDS = {"curl", "wget", "nc", "ncat", "netcat", "scp", "sftp", "rsync", "ftp", "telnet"}
# Destructive verbs; only interesting when they touch a path outside the roots.
_DESTRUCTIVE = {"rm", "dd", "mkfs", "shred", "srm"}
# Commands that read/copy file contents; used to catch outside-root access.
_READ_CMDS = {"cat", "less", "more", "head", "tail", "cp", "mv", "tee", "install"}
# Leading tokens that wrap the real command.
_PREFIXES = {"sudo", "doas", "env", "nohup", "time", "command", "exec", "nice", "stdbuf", "setsid"}

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "::"}
_HOSTISH = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)(?::\d+)?$")
_ASSIGNMENT = re.compile(r"^\w+=")


@dataclass
class Finding:
    severity: str
    category: str
    detail: str

    def as_dict(self) -> dict:
        return {"severity": self.severity, "category": self.category, "detail": self.detail}


def inspect(command: str, roots: list[Path]) -> list[Finding]:
    try:
        return _inspect(command, roots)
    except Exception:
        return []  # fail open: never let inspection crash the hook


def _inspect(command: str, roots: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    creds: list[str] = []
    net_cmds: list[str] = []
    egress: list[str] = []

    for segment in _split_segments(command):
        tokens = _tokenize(segment)
        if not tokens:
            continue
        verb = _command_verb(tokens)

        seg_creds = [_strip_quotes(t) for t in tokens if _is_credential(t)]
        creds.extend(seg_creds)

        if verb in _NET_CMDS:
            net_cmds.append(verb)
            egress.extend(_egress_hosts(tokens))

        if verb in _DESTRUCTIVE or verb.startswith("mkfs"):
            for path in _outside_paths(tokens, roots):
                findings.append(Finding(FLAG, "destructive", f"'{verb}' targets path outside allowed roots: {path}"))

        elif verb in _READ_CMDS or _has_redirect(segment):
            for path in _outside_paths(tokens, roots):
                if not _is_credential(path):
                    findings.append(Finding(FLAG, "outside-access", f"file access outside allowed roots: {path}"))

    for cred in _dedup(creds):
        findings.append(Finding(FLAG, "credential-read", f"reads credential/secret file: {cred}"))

    if creds and net_cmds and egress:
        findings.append(Finding(
            BLOCK, "credential-exfil",
            f"reads credential material ({creds[0]}) and sends it to {egress[0]} via {net_cmds[0]}",
        ))
    elif creds and net_cmds:
        findings.append(Finding(
            FLAG, "network-egress",
            f"network command '{net_cmds[0]}' used alongside credential access",
        ))
    elif net_cmds and egress:
        findings.append(Finding(FLAG, "network-egress", f"'{net_cmds[0]}' to remote host {egress[0]}"))

    return _dedup_findings(findings)


def _split_segments(command: str) -> list[str]:
    """Split on shell control operators (| ; &) while respecting quotes, so each
    verb is matched against its own arguments rather than the whole line."""
    segments, buf, quote = [], [], ""
    for ch in command:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
            buf.append(ch)
        elif ch in "|;&":
            segments.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    segments.append("".join(buf))
    return [s.strip() for s in segments if s.strip()]


def _tokenize(segment: str) -> list[str]:
    # posix=False keeps backslashes intact (Windows paths) and never crashes the
    # caller; fall back to a plain split on unbalanced quotes.
    try:
        return shlex.split(segment, posix=False)
    except ValueError:
        return segment.split()


def _command_verb(tokens: list[str]) -> str:
    for tok in tokens:
        cand = _strip_quotes(tok)
        if _ASSIGNMENT.match(cand) or cand.startswith("-"):
            continue
        base = os.path.basename(cand).lower()
        if base in _PREFIXES:
            continue
        return base
    return ""


def _strip_quotes(token: str) -> str:
    return token.strip("'\"")


def _is_credential(token: str) -> bool:
    low = _strip_quotes(token).lower()
    if any(part in low for part in _CRED_DIR_PARTS):
        return True
    name = os.path.basename(low.lstrip("@<>"))
    if name in _CRED_NAMES:
        return True
    if name == ".env" or name.startswith(".env.") or name.endswith(".env"):
        return True
    return name.endswith(_CRED_SUFFIXES)


def _egress_hosts(tokens: list[str]) -> list[str]:
    hosts = []
    for tok in tokens:
        host = _host_of(_strip_quotes(tok))
        if host and _is_remote_host(host):
            hosts.append(host)
    return hosts


def _host_of(token: str) -> str:
    if token.startswith("-"):
        return ""
    if "://" in token:
        return urlparse(token).hostname or ""
    if "@" in token:
        host = token.split("@", 1)[1].split(":", 1)[0]
        return host if _HOSTISH.match(host) else ""
    if "/" in token or "\\" in token:
        return ""
    return token.split(":", 1)[0] if _HOSTISH.match(token) else ""


def _is_remote_host(host: str) -> bool:
    h = (host or "").strip().lower().strip("[]")
    if not h or h in _LOCAL_HOSTS or h.startswith("127."):
        return False
    return not h.endswith((".local", ".localhost"))


def _has_redirect(segment: str) -> bool:
    return ">" in segment or "<" in segment


def _outside_paths(tokens: list[str], roots: list[Path]) -> list[str]:
    if not roots:
        return []
    out = []
    for tok in tokens:
        cand = _abs_candidate(_strip_quotes(tok))
        if cand and _is_outside(cand, roots):
            out.append(cand)
    return _dedup(out)


def _abs_candidate(token: str) -> str:
    cand = token.lstrip("<>")
    if not cand or cand.startswith(("-", "&")):
        return ""
    if cand.startswith(("~", "$")):
        cand = os.path.expandvars(os.path.expanduser(cand))
    if cand.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", cand):
        return cand
    return ""


def _is_outside(path: str, roots: list[Path]) -> bool:
    try:
        p = Path(os.path.expandvars(os.path.expanduser(path))).resolve()
    except Exception:
        return False
    for r in roots:
        try:
            p.relative_to(r)
            return False
        except ValueError:
            continue
    return True


def _dedup(items: list[str]) -> list[str]:
    seen, out = set(), []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


def _dedup_findings(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        key = (f.severity, f.category, f.detail)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
