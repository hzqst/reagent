"""Proposal replacement normalizes addresses and prevents lost concurrent updates."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from threading import Barrier

from re_agent.core import symbols
from re_agent.core.models import SymbolProposal
from re_agent.core.symbols import load_symbols, record_symbol


def test_record_symbol_normalizes_address_and_replaces_entire_proposal(tmp_path):
    path = tmp_path / "symbols.json"
    record_symbol(path, "0x1000", SymbolProposal(name="old", comment="old", checker_ok=True))
    record_symbol(path, "0x2000", SymbolProposal(name="other"))
    new = SymbolProposal(name="new", comment="new", checker_ok=False)
    record_symbol(path, "00001000", new)
    rows = load_symbols(path)
    assert len(rows) == 2
    assert {"address": "00001000", **asdict(new)} == rows[1]
    assert rows[0]["name"] == "other"


def test_concurrent_records_preserve_other_addresses(monkeypatch, tmp_path):
    path = tmp_path / "symbols.json"
    workers = 6
    start = Barrier(workers)
    original = symbols.load_symbols

    def slow_read(path):
        rows = original(path)
        # Widen the read/write window: atomic replacement alone loses updates.
        time.sleep(0.02)
        return rows

    monkeypatch.setattr(symbols, "load_symbols", slow_read)

    def write(index):
        start.wait(timeout=10)
        record_symbol(path, hex(index), SymbolProposal(name=f"function_{index}"))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(write, range(workers)))
    assert {f"function_{index}" for index in range(workers)} == {row["name"] for row in load_symbols(path)}
