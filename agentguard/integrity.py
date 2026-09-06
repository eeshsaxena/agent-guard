"""Tamper-evident audit log: a sha256 hash chain over the JSONL entries.

Each appended entry carries `prev_hash` (the previous entry's hash, or GENESIS
for the first) and `hash` = sha256 over the entry's content plus prev_hash.
Editing, inserting, deleting, or reordering any past entry breaks the recomputed
chain, so after-the-fact tampering is detectable.

Pure functions, no I/O: the guard calls `chain_entry` when appending a line and
`verify_chain` walks a whole log. Logs written before hashing existed have no
`hash` field; they're treated as a legacy prefix and skipped, not flagged.
"""
from __future__ import annotations

import hashlib
import json

# prev_hash of the first entry in a chain.
GENESIS = "0" * 64

# Fields the chain adds itself; excluded when hashing an entry's content so the
# hash can commit to prev_hash without trying to cover itself.
_CHAIN_KEYS = ("hash", "prev_hash")


def content_hash(entry: dict, prev_hash: str) -> str:
    """sha256 over a canonical serialization of the entry's content and prev_hash.

    Key order is normalized so the digest is stable regardless of how the dict
    was built or how JSON stored it on disk.
    """
    content = {k: v for k, v in entry.items() if k not in _CHAIN_KEYS}
    payload = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((payload + "\n" + prev_hash).encode("utf-8")).hexdigest()


def chain_entry(entry: dict, prev_hash: str) -> dict:
    """Return a copy of `entry` with `prev_hash` and `hash` set, linking it in."""
    linked = dict(entry)
    linked["prev_hash"] = prev_hash
    linked["hash"] = content_hash(entry, prev_hash)
    return linked


def verify_chain(entries: list[dict]) -> tuple[bool, int | None, str]:
    """Recompute the hash chain over `entries` in file order.

    Returns (ok, break_index, detail). Entries with no hash (legacy lines, or
    unreadable ones passed in as non-dicts) are skipped until the chain begins at
    the first hashed entry; from there every entry must carry the expected
    prev_hash and a matching hash. `break_index` is the 0-based index of the
    first entry that fails, or None when the chain is intact.
    """
    prev: str | None = None  # None until the first hashed entry starts the chain
    for i, entry in enumerate(entries):
        stored = entry.get("hash") if isinstance(entry, dict) else None
        if stored is None:
            if prev is not None:
                # The chain was underway and this entry lost its hash (dropped,
                # corrupted, or truncated): a break, not a legacy prefix.
                return False, i, "entry is unreadable or unhashed after the chain started"
            continue  # a legacy or unreadable line before the chain begins
        expected_prev = GENESIS if prev is None else prev
        if entry.get("prev_hash") != expected_prev:
            return False, i, "prev_hash does not point at the previous entry (inserted, deleted, or reordered)"
        if content_hash(entry, expected_prev) != stored:
            return False, i, "hash does not match entry content (edited in place)"
        prev = stored
    return True, None, "chain intact"
