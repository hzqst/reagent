"""Apply accumulated symbol proposals to a running IDA database.

Nothing is written unless ``--write`` is given, and struct changes need the
extra ``--allow-struct-changes`` gate because they modify a shared type.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from re_agent.backend.ida_write import (
    IdaWriteClient,
    address_key,
    apply_member_change,
    is_unnamed,
)
from re_agent.config.loader import load_config
from re_agent.config.schema import ReAgentConfig
from re_agent.core.models import StructChange, SymbolProposal
from re_agent.core.symbols import load_symbols, symbols_path

WRITE_BACKENDS = frozenset({"ida-mcp", "ida"})


@dataclass
class _Entry:
    """One proposal paired with the decision made about it."""

    address: str
    proposal: SymbolProposal
    current_name: str = ""
    action: str = "apply"
    notes: list[str] = field(default_factory=list)
    struct_reports: list[dict[str, object]] = field(default_factory=list)


def cmd_annotate(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config))
    backend_type = config.backend.type.lower().replace("_", "-")
    if backend_type not in WRITE_BACKENDS:
        raise ValueError(
            "annotate writes to an IDA database, so it needs "
            f"backend.type 'ida-mcp'; configured type is {config.backend.type!r}"
        )

    entries = _load_entries(args, config)
    if not entries:
        print("No symbol proposals to apply.", file=sys.stderr)
        return 0

    client = IdaWriteClient(config.backend.url, config.backend.timeout_s)
    names = client.function_names([entry.address for entry in entries])

    _decide(entries, names, only_unnamed=args.only_unnamed, include_flagged=args.include_flagged)

    # Comments go first: a proposal may be addressed by a symbol name, and
    # renaming replaces that name, leaving the old one unresolvable.
    if args.write:
        for entry in entries:
            if entry.action == "apply" and entry.proposal.comment:
                client.append_function_comment(entry.address, _comment_text(entry.proposal))

    renames = [(e.address, e.proposal.name) for e in entries if e.action == "apply"]
    results = client.rename_functions(
        renames, dry_run=not args.write, allow_overwrite=False
    )
    for entry, result in zip([e for e in entries if e.action == "apply"], results, strict=False):
        if isinstance(result, dict) and result.get("error"):
            entry.action = "error"
            entry.notes.append(str(result["error"]))

    if args.write:
        if args.allow_struct_changes:
            for entry in entries:
                if entry.action == "apply":
                    entry.struct_reports = _apply_struct_changes(client, entry)
        if args.save:
            client.save()

    _report(entries, write=args.write, saved=args.save)
    return 0 if all(e.action in {"apply", "skip-named", "skip-flagged"} for e in entries) else 1


# -- collecting proposals -----------------------------------------------------


def _load_entries(args: argparse.Namespace, config: ReAgentConfig) -> list[_Entry]:
    if args.from_hooks:
        return _hook_entries(args.from_hooks, config)

    path = Path(args.symbols) if args.symbols else symbols_path(Path(config.output.report_dir))
    if not path.exists():
        raise ValueError(
            f"No symbol proposals at {path}. Run `re-agent reverse` first, "
            "or pass --symbols / --from-hooks."
        )
    entries: list[_Entry] = []
    for raw in load_symbols(path):
        address = str(raw.get("address") or "").strip()
        proposal = SymbolProposal.from_dict(raw)
        if address and proposal is not None:
            entries.append(_Entry(address=address, proposal=proposal))
    return entries


def _hook_entries(paths: list[str], config: ReAgentConfig) -> list[_Entry]:
    """Build proposals from header annotations found under *paths*.

    Unlike ``SourceIndexer``, the class name is taken from the file name: the
    upstream trees carry no ``class_macro``-style marker, so the indexer's
    per-file scan would leave every entry class-less.

    Deliberately conservative.  Such trees are often duplicated copies, so an
    address can appear in several files; an entry is dropped when the sources
    disagree about its name, when the header's own name is a placeholder, or
    when two addresses would claim the same name and collide on rename.
    """
    patterns = [re.compile(pattern) for pattern in config.project_profile.hook_patterns]
    if not patterns:
        raise ValueError("--from-hooks needs project_profile.hook_patterns to be configured")

    extensions = config.project_profile.source_extensions or [".h"]
    # address -> {proposed name: address as spelled in the header}
    candidates: dict[str, dict[str, str]] = {}
    placeholders = 0
    for raw in paths:
        root = Path(raw)
        if not root.is_dir():
            raise ValueError(f"--from-hooks path is not a directory: {root}")
        for source in sorted(p for ext in extensions for p in root.rglob(f"*{ext}")):
            text = source.read_text(encoding="utf-8", errors="ignore")
            class_name = source.stem
            for pattern in patterns:
                for match in pattern.finditer(text):
                    if match.lastindex is None or match.lastindex < 2:
                        continue
                    function = match.group(1).strip()
                    address = match.group(2).strip()
                    if not function or not address:
                        continue
                    if is_unnamed(function):
                        placeholders += 1
                        continue
                    name = f"{class_name}::{function}" if class_name else function
                    candidates.setdefault(address_key(address), {})[name] = address

    unambiguous = {key: names for key, names in candidates.items() if len(names) == 1}
    claimed = Counter(name for names in unambiguous.values() for name in names)

    entries: list[_Entry] = []
    conflicting = len(candidates) - len(unambiguous)
    colliding = 0
    for _, names in sorted(unambiguous.items()):
        name, address = next(iter(names.items()))
        if claimed[name] > 1:
            colliding += 1
            continue
        entries.append(
            _Entry(
                address=address,
                proposal=SymbolProposal(
                    name=name,
                    comment="Named from an upstream header annotation.",
                    confidence="verified",
                    evidence=[f"header annotation for {address}"],
                ),
            )
        )

    skipped = conflicting + colliding + placeholders
    if skipped:
        print(
            f"[annotate] --from-hooks dropped {skipped} ambiguous entries "
            f"({conflicting} named differently across sources, "
            f"{colliding} sharing a name with another address, "
            f"{placeholders} placeholder-named in the header)",
            file=sys.stderr,
        )
    return entries


# -- decisions ----------------------------------------------------------------


def _decide(
    entries: list[_Entry],
    names: dict[str, str],
    *,
    only_unnamed: bool,
    include_flagged: bool,
) -> None:
    for entry in entries:
        # Derived from scratch so the decision never inherits a previous pass.
        entry.action = "apply"
        entry.notes = []
        entry.current_name = names.get(address_key(entry.address), "")
        if not entry.proposal.checker_ok and not include_flagged:
            entry.action = "skip-flagged"
            entry.notes.extend(entry.proposal.checker_notes)
            continue
        if only_unnamed and entry.current_name and not is_unnamed(entry.current_name):
            entry.action = "skip-named"
            entry.notes.append(f"already named {entry.current_name!r}")


def _comment_text(proposal: SymbolProposal) -> str:
    lines = [proposal.comment]
    if proposal.evidence:
        lines.append("Evidence: " + "; ".join(proposal.evidence))
    lines.append(f"Naming confidence: {proposal.confidence}")
    return "\n".join(line for line in lines if line)


# -- struct changes -----------------------------------------------------------


def _apply_struct_changes(client: IdaWriteClient, entry: _Entry) -> list[dict[str, object]]:
    """Apply each struct change, reverting when the result misses its target."""
    reports: list[dict[str, object]] = []
    for change in entry.proposal.struct_changes:
        report: dict[str, object] = {
            "struct": change.struct_name,
            "member": change.member,
            "operation": change.operation,
            "status": "pending",
        }
        try:
            original = client.read_declaration(change.struct_name)
            before = client.struct_layout(change.struct_name)
            patched, diff = apply_member_change(original, change)
            report["diff"] = diff
            client.declare_type(patched)
            after = client.struct_layout(change.struct_name)
            report["layout_before"] = before
            report["layout_after"] = after

            problem = _layout_problem(change, before, after)
            if problem is None:
                report["status"] = "applied"
            else:
                # Undo rather than leave a shared type in a worse state.
                client.declare_type(original)
                report["status"] = "reverted"
                report["reason"] = problem
        except (RuntimeError, ValueError, OSError) as exc:
            report["status"] = "failed"
            report["reason"] = str(exc)
        reports.append(report)
    return reports


def _layout_problem(
    change: StructChange,
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
) -> str | None:
    """Return why the change should be reverted, or ``None`` when it is sound.

    Changing a struct's total size shifts every following consumer, so it is
    rejected outright.  A ``move`` must also land at the offset it asked for.
    """
    if before and after and before.get("size") != after.get("size"):
        return (
            f"struct size changed from {before.get('size')} to {after.get('size')}; "
            "rejected because it shifts every following consumer"
        )
    if change.operation == "move" and change.offset:
        landed = (after or {}).get("members", {}).get(change.member)
        if not landed or not _same_offset(str(landed), change.offset):
            return f"{change.member} landed at {landed}, not {change.offset}"
    return None


def _same_offset(actual: str, expected: str) -> bool:
    with contextlib.suppress(ValueError):
        return int(actual, 16) == int(expected, 16)
    return actual.strip().lower() == expected.strip().lower()


# -- reporting ----------------------------------------------------------------


def _report(entries: list[_Entry], *, write: bool, saved: bool) -> None:
    payload = {
        "mode": "write" if write else "dry-run",
        "saved": saved,
        "undo": [
            {"address": entry.address, "current_name": entry.current_name, "new_name": entry.proposal.name}
            for entry in entries
            if entry.action == "apply"
        ],
        "entries": [
            {
                "address": entry.address,
                "name": entry.proposal.name,
                "confidence": entry.proposal.confidence,
                "action": entry.action,
                "notes": entry.notes,
                "struct_changes": entry.struct_reports,
            }
            for entry in entries
        ],
    }
    print(json.dumps(payload, indent=2))

    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry.action] = counts.get(entry.action, 0) + 1
    summary = ", ".join(f"{action}={count}" for action, count in sorted(counts.items()))
    mode = "applied" if write else "would apply"
    print(f"[annotate] {mode}: {summary}", file=sys.stderr)
    if not write:
        print("[annotate] dry run; re-run with --write to apply", file=sys.stderr)
