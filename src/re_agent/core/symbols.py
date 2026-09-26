"""Accumulated symbol proposals produced by reversal runs.

Proposals are collected into a single JSON artifact next to the other run
outputs (``report_dir/symbols.json``) rather than written back to the analysis
database directly.  Applying them is a separate, explicitly-requested step.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from re_agent.core.models import SymbolProposal
from re_agent.utils.address import address_key
from re_agent.utils.storage import atomic_json, file_lock

SCHEMA_VERSION = 1
SYMBOLS_FILENAME = "symbols.json"


def symbols_path(report_dir: Path) -> Path:
    """Return the artifact path for a run's symbol proposals."""
    return report_dir / SYMBOLS_FILENAME


def load_symbols(path: Path) -> list[dict[str, Any]]:
    """Read accumulated entries; a missing or malformed file yields ``[]``."""
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    entries = payload.get("symbols") if isinstance(payload, dict) else None
    if not isinstance(entries, list):
        return []
    return [entry for entry in entries if isinstance(entry, dict)]


def record_symbol(path: Path, address: str, symbol: SymbolProposal) -> None:
    """Insert or replace the entry for *address*, preserving the others."""
    key = address_key(address)
    with file_lock(path):
        entries = [entry for entry in load_symbols(path) if address_key(str(entry.get("address", ""))) != key]
        entries.append({"address": address, **asdict(symbol)})
        atomic_json(path, {"schema_version": SCHEMA_VERSION, "symbols": entries})
