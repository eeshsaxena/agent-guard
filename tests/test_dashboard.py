import json
import time

from agentguard import dashboard, integrity


def _write_log(path, entries):
    path.write_text("\n".join(json.dumps(e) for e in entries), encoding="utf-8")


def test_read_log_tolerates_bad_lines(tmp_path):
    p = tmp_path / "log.jsonl"
    p.write_text('{"tool":"Read"}\nGARBAGE\n{"tool":"Write"}\n', encoding="utf-8")
    entries = dashboard.read_log(p)
    assert [e["tool"] for e in entries] == ["Read", "Write"]


def test_read_log_missing_file(tmp_path):
    assert dashboard.read_log(tmp_path / "nope.jsonl") == []


def test_render_has_tiles_and_counts():
    now = time.time()
    entries = [
        {"ts": now, "tool": "Read", "paths": ["/a/b.txt"], "outside": [], "blocked": False},
        {"ts": now, "tool": "Write", "paths": ["/a/c.txt"], "outside": [], "blocked": False},
    ]
    html = dashboard.render(entries)
    assert "agent-guard" in html
    assert "reads" in html and "writes/edits" in html


def test_render_shows_blocked_alert():
    now = time.time()
    entries = [{"ts": now, "tool": "Read", "paths": ["/etc/shadow"], "outside": ["/etc/shadow"], "blocked": True}]
    html = dashboard.render(entries)
    assert "blocked attempt" in html
    assert "/etc/shadow" in html


def test_render_filter_blocked_only():
    now = time.time()
    entries = [
        {"ts": now, "tool": "Read", "paths": ["/ok.txt"], "outside": [], "blocked": False},
        {"ts": now, "tool": "Read", "paths": ["/bad.txt"], "outside": ["/bad.txt"], "blocked": True},
    ]
    html = dashboard.render(entries, flt="blocked")
    assert "/bad.txt" in html
    assert "/ok.txt" not in html


def test_render_empty_is_valid():
    html = dashboard.render([])
    assert "<html>" in html
    assert "no file access yet" in html


def test_reads_and_renders_hash_chained_entries(tmp_path):
    now = time.time()
    prev = integrity.GENESIS
    lines = []
    for i in range(3):
        e = integrity.chain_entry(
            {"ts": now, "tool": "Read", "paths": [f"/proj/{i}.txt"], "outside": [], "blocked": False}, prev
        )
        prev = e["hash"]
        lines.append(json.dumps(e))
    p = tmp_path / "log.jsonl"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    entries = dashboard.read_log(p)
    assert len(entries) == 3
    assert entries[0]["hash"]                     # new fields carried through
    html = dashboard.render(entries)              # and render still works on them
    assert "/proj" in html


def test_top_folders_groups_by_parent():
    now = time.time()
    entries = [
        {"ts": now, "tool": "Read", "paths": ["/proj/a.txt"], "outside": [], "blocked": False},
        {"ts": now, "tool": "Read", "paths": ["/proj/b.txt"], "outside": [], "blocked": False},
    ]
    html = dashboard.render(entries)
    assert "/proj" in html
