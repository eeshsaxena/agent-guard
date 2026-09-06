"""Live activity dashboard: filters, per-folder grouping, a timeline, alerts.

Reads the audit log written by the guard and serves an auto-refreshing local page.
Nothing leaves your machine.
"""
from __future__ import annotations

import datetime as dt
import html
import http.server
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import config

MAX_ROWS = 800
DEFAULT_PORT = 8799


def read_log(log_path: Path) -> list[dict]:
    if not log_path.exists():
        return []
    import json
    out = []
    for line in log_path.read_text(encoding="utf-8").splitlines()[-MAX_ROWS:]:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def _target(e: dict) -> str:
    if e.get("paths"):
        return " , ".join(e["paths"])
    return e.get("command") or e.get("url") or ""


def _timeline(entries: list[dict], minutes: int = 20) -> str:
    now = dt.datetime.now()
    buckets = [0] * minutes
    for e in entries:
        ts = e.get("ts")
        if not ts:
            continue
        age = (now - dt.datetime.fromtimestamp(ts)).total_seconds() / 60
        if 0 <= age < minutes:
            buckets[minutes - 1 - int(age)] += 1
    peak = max(buckets) or 1
    bars = "".join(
        f'<div class="bar" title="{c}"><div class="fill" style="height:{max(2, int(c / peak * 60))}px"></div></div>'
        for c in buckets
    )
    return f'<div class="timeline">{bars}</div><div class=muted style="font-size:11px">last {minutes} min</div>'


def render(entries: list[dict], flt: str = "all") -> str:
    kinds = Counter(e.get("tool", "?") for e in entries)
    blocked = [e for e in entries if e.get("blocked")]
    outside = [e for e in entries if e.get("outside")]

    folders: Counter = Counter()
    for e in entries:
        for p in e.get("paths", []):
            folders[str(Path(p).parent)] += 1

    def tile(label, value, cls=""):
        return f'<div class="tile {cls}"><div class="v">{value}</div><div class="l">{html.escape(label)}</div></div>'

    tiles = "".join([
        tile("total", len(entries)),
        tile("reads", kinds.get("Read", 0)),
        tile("writes/edits", kinds.get("Write", 0) + kinds.get("Edit", 0) + kinds.get("MultiEdit", 0)),
        tile("shell", kinds.get("Bash", 0)),
        tile("web", kinds.get("WebFetch", 0) + kinds.get("WebSearch", 0)),
        tile("outside", len(outside), "warn" if outside else ""),
        tile("BLOCKED", len(blocked), "bad" if blocked else ""),
    ])

    shown = entries
    if flt == "blocked":
        shown = blocked
    elif flt == "outside":
        shown = outside

    def link(name, val):
        cur = "on" if flt == val else ""
        return f'<a class="flt {cur}" href="/?filter={val}">{name}</a>'

    filters = link("all", "all") + link("outside", "outside") + link("blocked", "blocked")

    top_folders = "".join(
        f"<tr><td class=t>{html.escape(f)}</td><td class=n>{c}</td></tr>"
        for f, c in folders.most_common(8)
    ) or "<tr><td class=muted colspan=2>no file access yet</td></tr>"

    rows = []
    for e in reversed(shown):
        ts = e.get("ts", 0)
        when = dt.datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "?"
        status, scls = ("allowed", "ok")
        if e.get("blocked"):
            status, scls = ("BLOCKED", "bad")
        elif e.get("outside"):
            status, scls = ("outside", "warn")
        rows.append(
            f"<tr class={scls}><td>{when}</td><td>{html.escape(e.get('tool',''))}</td>"
            f"<td class=t>{html.escape(_target(e)[:150])}</td><td>{status}</td></tr>"
        )
    body = "".join(rows) or "<tr><td colspan=4 class=muted>nothing matches this filter yet</td></tr>"

    alert = ""
    if blocked:
        last = blocked[-1]
        alert = f'<div class="alert"><b>{len(blocked)} blocked attempt(s).</b> Latest: {html.escape(_target(last)[:120])}</div>'

    return f"""<!doctype html><html><head><meta charset=utf-8><meta http-equiv="refresh" content="2">
<title>agent-guard</title><style>
body{{margin:0;background:#0b0f0d;color:#e6e6e6;font:14px system-ui,Segoe UI,sans-serif;padding:20px}}
h1{{font-size:18px;margin:0 0 2px}}.sub{{color:#8a8f8c;font-size:12px;margin-bottom:16px}}
.alert{{background:#1a0d0d;border:1px solid #e0483d66;color:#ff8079;padding:10px 14px;border-radius:8px;margin-bottom:16px}}
.tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin-bottom:16px}}
.tile{{background:#121815;border:1px solid #1f2a24;border-radius:10px;padding:12px}}
.tile .v{{font-size:22px;font-weight:700}}.tile .l{{color:#8a8f8c;font-size:11px;text-transform:uppercase;margin-top:3px}}
.tile.warn{{border-color:#e0a52d66}}.tile.warn .v{{color:#f0b429}}.tile.bad{{border-color:#e0483d66}}.tile.bad .v{{color:#ff6b5e}}
.two{{display:grid;grid-template-columns:2fr 1fr;gap:16px;align-items:start}}@media(max-width:800px){{.two{{grid-template-columns:1fr}}}}
.card{{background:#0f1512;border:1px solid #1f2a24;border-radius:10px;padding:14px;margin-bottom:16px}}
.card h2{{font-size:11px;text-transform:uppercase;color:#8a8f8c;margin:0 0 10px}}
.timeline{{display:flex;align-items:flex-end;gap:2px;height:64px}}.bar{{flex:1;display:flex;align-items:flex-end}}.fill{{width:100%;background:#08d46e;border-radius:2px 2px 0 0}}
.flt{{color:#8a8f8c;text-decoration:none;margin-right:12px;font-size:12px;padding-bottom:2px}}.flt.on{{color:#4dfea0;border-bottom:2px solid #08d46e}}
table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{text-align:left;padding:5px 8px;border-bottom:1px solid #18201b;vertical-align:top}}
th{{color:#8a8f8c;font-size:11px;text-transform:uppercase}}.t{{font-family:ui-monospace,Consolas,monospace;color:#b9c2bd;word-break:break-all}}.n{{text-align:right}}
tr.bad td{{color:#ff8079}}tr.warn td{{color:#f0b429}}.muted{{color:#6b716d}}.scroll{{max-height:460px;overflow:auto}}
</style></head><body>
<h1>agent-guard &middot; live activity</h1><div class=sub>auto-refresh 2s &middot; blocked=red, outside=orange</div>
{alert}
<div class=tiles>{tiles}</div>
<div class=two>
  <div class=card><h2>activity ({html.escape(flt)}) &nbsp; {filters}</h2><div class=scroll><table>
    <tr><th>time</th><th>tool</th><th>target</th><th>status</th></tr>{body}</table></div></div>
  <div>
    <div class=card><h2>timeline</h2>{_timeline(entries)}</div>
    <div class=card><h2>top folders touched</h2><table>{top_folders}</table></div>
  </div>
</div></body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    log_path: Path = None  # set by serve()

    def log_message(self, *a):
        pass

    def do_GET(self):
        flt = (parse_qs(urlparse(self.path).query).get("filter", ["all"])[0])
        page = render(read_log(self.log_path), flt).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)


def serve(port: int = DEFAULT_PORT) -> None:
    Handler.log_path = config.load().log_path
    print(f"agent-guard dashboard on http://127.0.0.1:{port}  (Ctrl+C to stop)")
    http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()
