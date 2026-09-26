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
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from re_agent.backend.ida_comments import managed_comment
from re_agent.backend.ida_prototype import PrototypeOperationError
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
from re_agent.utils.address import checked_address

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
    prototype_report: dict[str, Any] = field(default_factory=dict)
    prototype_plan: dict[str, Any] = field(default_factory=dict)
    name_status: str = "pending"
    comment_status: str = "pending"
    comment_report: dict[str, Any] = field(default_factory=dict)


def cmd_annotate(args: argparse.Namespace) -> int:
    inferred = getattr(args, "allow_inferred_prototypes", False)
    corrections = getattr(args, "allow_abi_type_corrections", False)
    if (inferred or corrections) and (not args.allow_prototype_changes or not args.address):
        raise ValueError("Extended prototype flags require --allow-prototype-changes and --address")
    if args.allow_prototype_changes and args.allow_struct_changes:
        raise ValueError("Apply prototype and shared struct changes in separate invocations, with fresh proposals")
    if args.comments_only and (args.only_unnamed or args.allow_prototype_changes or args.allow_struct_changes):
        raise ValueError("--comments-only cannot be combined with --only-unnamed or type-change flags")
    if args.replace_function_comment and not args.address:
        raise ValueError("--replace-function-comment requires --address to bound whole-comment replacement")
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
    for entry in entries:
        entry.name_status = "disabled" if args.comments_only else entry.action if entry.action != "apply" else "pending"
        _plan_comment(client, entry, replace=args.replace_function_comment)
        if args.comments_only:
            if entry.proposal.prototype:
                entry.prototype_report = {"status": "disabled", "reason": "--comments-only"}
        else:
            _plan_prototype(client, entry, allowed=args.allow_prototype_changes,
                            inferred=inferred, corrections=corrections)

    if args.write:
        for entry in entries:
            if entry.comment_status == "would-apply":
                _apply_comment(client, entry)

    rename_entries = [] if args.comments_only else [e for e in entries if e.action == "apply"]
    renames = [(e.address, e.proposal.name) for e in rename_entries]
    try:
        results = client.rename_functions(renames, dry_run=not args.write, allow_overwrite=False) if renames else []
    except (RuntimeError, OSError, ValueError) as exc:
        results = [{"error": str(exc)} for _ in renames]
    for index, entry in enumerate(rename_entries):
        result = results[index] if index < len(results) else {"error": "IDA returned no rename result"}
        if result.get("error") or result.get("ok") is False:
            entry.action = "error"
            entry.name_status = "failed"
            entry.notes.append(str(result.get("error") or "IDA rejected the rename"))
        else:
            entry.name_status = "applied" if args.write else "would-apply"

    saved = False
    save_error = ""
    if args.write:
        recovery_failed = False
        for entry in entries:
            if entry.prototype_report.get("status") == "would-apply":
                if recovery_failed:
                    entry.prototype_report.update(status="not-attempted", reason="An earlier type recovery failed")
                    continue
                # Address and original type were fixed before renaming.
                _apply_prototype(client, entry)
                recovery_failed = entry.prototype_report.get("status") == "recovery-failed"
        if args.allow_struct_changes:
            for entry in entries:
                if entry.action == "apply":
                    entry.struct_reports = _apply_struct_changes(client, entry)
        if args.save:
            if any(e.prototype_report.get("status") == "recovery-failed" for e in entries):
                save_error = "Save suppressed: a function type could not be restored"
            elif any(e.comment_status == "failed" for e in entries):
                save_error = "Save suppressed: a function comment write could not be confirmed; inspect the IDB"
            else:
                try:
                    client.save()
                    saved = True
                except (RuntimeError, OSError, ValueError) as exc:
                    save_error = str(exc)

    _report(entries, write=args.write, saved=saved, save_error=save_error)
    failed = any(
        e.action not in {"apply", "skip-named", "skip-flagged"}
        or e.comment_status in {"failed", "conflict", "rejected"}
        or e.prototype_report.get("status") in {
            "invalid-prototype", "rejected", "reverted", "recovery-failed", "unsupported-change", "stale",
        }
        for e in entries
    )
    return 1 if failed or save_error else 0


def _plan_comment(client: IdaWriteClient, entry: _Entry, *, replace: bool) -> None:
    entry.comment_status = entry.action if entry.action != "apply" else "absent"
    if entry.action != "apply" or not entry.proposal.comment.strip():
        return
    report = entry.comment_report
    try:
        snapshot = client.comment_operation("read", entry.address)
        report.update(address=snapshot["address"], current=snapshot["comment"])
        proposed = managed_comment(snapshot["comment"], _comment_text(entry.proposal), replace=replace)
        report["proposed"] = proposed
        entry.comment_status = "unchanged" if proposed == snapshot["comment"] else "would-apply"
    except ValueError as exc:
        entry.comment_status = "conflict"
        report["reason"] = str(exc)
    except (RuntimeError, OSError, KeyError) as exc:
        entry.comment_status = "rejected"
        report["reason"] = str(exc)


def _apply_comment(client: IdaWriteClient, entry: _Entry) -> None:
    report = entry.comment_report
    try:
        client.comment_operation(
            "apply", report["address"], expected=report["current"], proposed=report["proposed"],
        )
        # A separate read verifies the stored slot, not the helper's write response.
        after = client.comment_operation("read", report["address"])
        report["after"] = after["comment"]
        if after["comment"] != report["proposed"]:
            raise RuntimeError("Independent function comment readback mismatch")
        entry.comment_status = "applied"
    except (RuntimeError, OSError, ValueError, KeyError) as exc:
        # Never retry an ambiguous write or overwrite a subsequent human edit.
        entry.comment_status = "failed"
        report["reason"] = str(exc)


def _plan_prototype(
    client: IdaWriteClient, entry: _Entry, *, allowed: bool, inferred: bool = False, corrections: bool = False,
) -> None:
    prototype = entry.proposal.prototype
    if prototype is None:
        return
    report = entry.prototype_report
    report.update(proposed=prototype.declaration, current=None, status="pending",
                  confidence=prototype.confidence, evidence_kind=prototype.evidence_kind,
                  review_status=prototype.review_status, review_notes=prototype.review_notes,
                  evidence_details=prototype.evidence_details, abi_evidence=prototype.abi_evidence)
    if entry.action != "apply":
        report.update(status=entry.action)
        return
    if prototype.validation_error:
        report.update(status="invalid-prototype", reason=prototype.validation_error)
        return
    try:
        state = client.prototype_operation("read", entry.address)["current"]
        report.update(current=state["declaration"], address=state["address"], source=state["source"])
        if not allowed:
            report.update(status="disabled", reason="Requires --allow-prototype-changes")
            return
        if prototype.review_status == "disputed" or not entry.proposal.checker_ok:
            report.update(status="disputed", reason="Prototype or symbol has unresolved disputes")
            return
        if prototype.review_status != "approved":
            report.update(status="unreviewed", reason="Prototype needs independent approval")
            return
        if not prototype.evidence:
            report.update(status="insufficient-evidence", reason="Missing prototype evidence")
            return
        if not prototype.expected_current:
            raise ValueError("Missing original function type snapshot; regenerate the proposal")
        # Read-only classification includes supported corrections even without authorization.
        # Authorization is checked below and is passed independently to the write helper.
        plan = client.prototype_operation(
            "plan", state["address"], declaration=prototype.declaration,
            expected_current=prototype.expected_current, required_types=prototype.required_types,
            allow_abi_type_corrections=True,
        )
        differences = plan.get("differences", [])
        requires_corrections = plan.get("requires_abi_corrections", False)
        report.update(current=plan["current"]["declaration"], proposed=plan["proposed"],
                      differences=differences, abi_check=plan.get("abi_check", "compatible"))
        if prototype.confidence != "verified" or requires_corrections:
            required = {"header", "version", "address_binding"}
            missing = sorted(key for key in required if not prototype.evidence_details.get(key, "").strip())
            positions = ["calling_convention", *[item["position"] for item in differences]]
            missing += [key for key in positions if not prototype.abi_evidence.get(key, "").strip()]
            if not prototype.evidence_kind or missing:
                report.update(status="insufficient-evidence",
                              reason="Regenerate and review structured header/version/binding and ABI evidence",
                              missing_evidence=missing + ([] if prototype.evidence_kind else ["evidence_kind"]))
                return
        needed = []
        if prototype.confidence != "verified" and not inferred:
            needed.append("--allow-inferred-prototypes")
        if requires_corrections and not corrections:
            needed.append("--allow-abi-type-corrections")
        if needed:
            report.update(status="needs-opt-in", required_flags=needed,
                          reason="Review evidence and type differences; opt in with --address")
            return
        plan["allow_abi_type_corrections"] = corrections
        entry.prototype_plan = plan
        report.update(status="unchanged" if plan["unchanged"] else "would-apply")
    except (RuntimeError, OSError, ValueError, KeyError) as exc:
        report.update(status=exc.code if isinstance(exc, PrototypeOperationError) else "rejected", reason=str(exc))


def _apply_prototype(client: IdaWriteClient, entry: _Entry) -> None:
    plan = entry.prototype_plan
    original = plan["current"]
    address = original["address"]
    report = entry.prototype_report
    verifying = False
    try:
        client.prototype_operation(
            "apply", address, original=original, declaration=plan["proposed"], proposed_key=plan["proposed_key"],
            allow_abi_type_corrections=plan.get("allow_abi_type_corrections", False),
        )
        verifying = True
        verified = client.prototype_operation("verify", address, proposed_key=plan["proposed_key"])
        report.update(status="applied", after=verified["current"]["declaration"], verified=True)
    except (RuntimeError, OSError, ValueError, KeyError) as exc:
        report.update(reason=str(exc), verified=False)
        if isinstance(exc, PrototypeOperationError) and not exc.write_attempted and not verifying:
            report.update(status="rejected")
            return
        # An HTTP error can arrive after IDA applied the type. Never retry the
        # write blindly; recovery reads the actual state and guards restoration.
        try:
            client.prototype_operation(
                "restore", address, original=original, proposed_key=plan["proposed_key"],
            )
            report.update(status="reverted")
        except (RuntimeError, OSError, ValueError, KeyError) as recovery:
            report.update(status="recovery-failed", recovery_error=str(recovery))


# -- collecting proposals -----------------------------------------------------


def _load_entries(args: argparse.Namespace, config: ReAgentConfig) -> list[_Entry]:
    if args.from_hooks:
        rows = [{"address": entry.address, **asdict(entry.proposal)}
                for entry in _hook_entries(args.from_hooks, config)]
    else:
        path = Path(args.symbols) if args.symbols else symbols_path(Path(config.output.report_dir))
        if not path.exists():
            raise ValueError(
                f"No symbol proposals at {path}. Run `re-agent reverse` first, "
                "or pass --symbols / --from-hooks."
            )
        rows = load_symbols(path)
    entries: list[_Entry] = []
    for raw in _select_rows(rows, args.address):
        address = str(raw.get("address") or "").strip()
        proposal = SymbolProposal.from_dict(raw)
        if not address or proposal is None:
            raise ValueError(f"Invalid symbol proposal at {address!r}")
        entries.append(_Entry(address=address, proposal=proposal))
    return entries


def _select_rows(rows: list[dict[str, Any]], addresses: list[str] | None) -> list[dict[str, Any]]:
    """Scope first, then reject conflicts before any backend access or mutation."""
    requested = {address_key(checked_address(address)) for address in addresses or []}
    selected: dict[str, dict[str, Any]] = {}
    for raw in rows:
        key = address_key(str(raw.get("address") or ""))
        if requested and key not in requested:
            continue
        normalized = {**raw, "address": key}
        if key in selected and {**selected[key], "address": key} != normalized:
            raise ValueError(
                f"Conflicting symbol proposals for address {key}; regenerate or resolve the selected entries"
            )
        selected[key] = raw
    missing = requested - selected.keys()
    if missing:
        raise ValueError("No symbol proposal for requested address(es): " + ", ".join(sorted(missing)))
    return list(selected.values())


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


def _report(entries: list[_Entry], *, write: bool, saved: bool, save_error: str = "") -> None:
    payload = {
        "mode": "write" if write else "dry-run",
        "saved": saved,
        "save_error": save_error or None,
        "undo": [
            {"address": entry.address, "current_name": entry.current_name, "new_name": entry.proposal.name}
            for entry in entries
            if entry.name_status in {"applied", "would-apply"}
        ],
        "entries": [
            {
                "address": entry.address,
                "name": entry.proposal.name,
                "confidence": entry.proposal.confidence,
                "action": entry.action,
                "notes": entry.notes,
                "struct_changes": entry.struct_reports,
                "prototype": entry.prototype_report or None,
                "name_status": entry.name_status,
                "comment_status": entry.comment_status,
                "comment": entry.comment_report or None,
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
