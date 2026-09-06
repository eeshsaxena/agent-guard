from agentguard import integrity


def _chain(entries):
    """Link a list of plain entries into a hash chain, as the guard would."""
    out, prev = [], integrity.GENESIS
    for e in entries:
        linked = integrity.chain_entry(e, prev)
        out.append(linked)
        prev = linked["hash"]
    return out


def test_first_entry_links_to_genesis():
    linked = integrity.chain_entry({"tool": "Read"}, integrity.GENESIS)
    assert linked["prev_hash"] == integrity.GENESIS
    assert len(linked["hash"]) == 64
    assert linked["tool"] == "Read"  # original fields preserved


def test_hash_is_deterministic_regardless_of_key_order():
    a = integrity.content_hash({"tool": "Read", "ts": 1.0}, integrity.GENESIS)
    b = integrity.content_hash({"ts": 1.0, "tool": "Read"}, integrity.GENESIS)
    assert a == b


def test_chain_entry_does_not_mutate_input():
    entry = {"tool": "Write"}
    integrity.chain_entry(entry, integrity.GENESIS)
    assert entry == {"tool": "Write"}


def test_intact_chain_verifies():
    chain = _chain([{"tool": "Read", "n": i} for i in range(5)])
    ok, idx, _ = integrity.verify_chain(chain)
    assert ok is True
    assert idx is None


def test_edited_content_breaks_chain():
    chain = _chain([{"tool": "Read", "n": i} for i in range(5)])
    chain[2]["tool"] = "Bash"  # tamper in place, leave hash untouched
    ok, idx, detail = integrity.verify_chain(chain)
    assert ok is False
    assert idx == 2
    assert "content" in detail


def test_deleted_entry_breaks_chain():
    chain = _chain([{"tool": "Read", "n": i} for i in range(5)])
    del chain[2]  # the next entry's prev_hash now dangles
    ok, idx, _ = integrity.verify_chain(chain)
    assert ok is False
    assert idx == 2


def test_inserted_entry_breaks_chain():
    chain = _chain([{"tool": "Read", "n": i} for i in range(5)])
    forged = integrity.chain_entry({"tool": "Read", "n": 99}, chain[1]["hash"])
    chain.insert(2, forged)  # forged links to [1], but [3] still expects old [2]
    ok, idx, _ = integrity.verify_chain(chain)
    assert ok is False
    assert idx == 3


def test_reordered_entries_break_chain():
    chain = _chain([{"tool": "Read", "n": i} for i in range(5)])
    chain[1], chain[2] = chain[2], chain[1]
    ok, idx, _ = integrity.verify_chain(chain)
    assert ok is False


def test_legacy_prefix_is_skipped_then_chain_verifies():
    # Old unhashed lines followed by a fresh hashed segment: valid, not a break.
    legacy = [{"tool": "Read"}, {"tool": "Write"}]
    chain = _chain([{"tool": "Bash", "n": i} for i in range(3)])
    ok, idx, _ = integrity.verify_chain(legacy + chain)
    assert ok is True
    assert idx is None


def test_all_legacy_log_is_vacuously_intact():
    ok, idx, _ = integrity.verify_chain([{"tool": "Read"}, {"tool": "Write"}])
    assert ok is True
    assert idx is None


def test_dropped_hash_mid_chain_breaks():
    chain = _chain([{"tool": "Read", "n": i} for i in range(4)])
    del chain[2]["hash"]
    del chain[2]["prev_hash"]
    ok, idx, _ = integrity.verify_chain(chain)
    assert ok is False
    assert idx == 2


def test_unreadable_line_in_legacy_prefix_is_skipped():
    chain = _chain([{"tool": "Read", "n": i} for i in range(2)])
    ok, idx, _ = integrity.verify_chain([None, {"tool": "old"}] + chain)
    assert ok is True
    assert idx is None


def test_unreadable_line_after_chain_starts_breaks():
    chain = _chain([{"tool": "Read", "n": i} for i in range(2)])
    ok, idx, _ = integrity.verify_chain(chain + [None])
    assert ok is False
    assert idx == 2


def test_empty_log_is_intact():
    ok, idx, _ = integrity.verify_chain([])
    assert ok is True
    assert idx is None
