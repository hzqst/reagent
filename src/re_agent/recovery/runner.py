"""Bounded interactive recovery with durable tool events and independent readback."""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from re_agent.config.schema import RecoveryConfig
from re_agent.llm.protocol import LLMProvider, Message
from re_agent.recovery import files
from re_agent.recovery.ida import READ_TOOLS, WRITE_TOOLS, IdaRecoveryClient, tool_error
from re_agent.utils.storage import atomic_json, file_lock
from re_agent.utils.templates import render_template

PROMPT = Path(__file__).parents[1] / "agents" / "prompts" / "recovery_system.md"
_log = logging.getLogger(__name__)


def _parse_response(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```json") and text.endswith("```"):
        text = text[7:-3].strip()
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        # Some CLI models prefix a valid action with a short explanation. Accept
        # one trailing object, but never silently choose between several actions.
        start = text.find("{")
        if start < 0:
            raise ValueError("Return one JSON object with action tool or finish") from None
        value, end = json.JSONDecoder().raw_decode(text[start:])
        if text[start + end:].strip() not in {"", "```"}:
            raise ValueError("Return only one action per turn") from None
    if not isinstance(value, dict):
        raise ValueError("Return one JSON object with action tool or finish")
    return value


def _bounded(value: Any, limit: int) -> str:
    text = json.dumps(value, ensure_ascii=False)
    if len(text) <= limit:
        return text
    return text[:limit] + "\n[TRUNCATED: full result is in the journal; request smaller queries before concluding.]"


def run_recovery(
    provider: LLMProvider,
    client: IdaRecoveryClient,
    addresses: list[str],
    settings: RecoveryConfig,
    report_path: Path,
    *,
    write: bool = False,
    save: bool = False,
    evidence: str = "",
    evidence_files: list[Path] | None = None,
    objective: str = "Recover evidence-supported class pointers, vtable pointers and virtual calls.",
) -> dict[str, Any]:
    """Run a backend-specific agent without constructing symbol proposals.

    The journal is written before dispatch, including before potentially partial
    writes. Arbitrary IDAPython is trusted in write mode; backups are recovery
    points, not a claim that remote operations are transactional.
    """
    if save and not write:
        raise ValueError("--save requires --write")
    if not addresses:
        raise ValueError("Recovery requires at least one target address")
    report: dict[str, Any] = {
        "status": "running", "mode": "write" if write else "preview", "addresses": addresses,
        "objective": objective, "write_attempted": False, "saved": False, "backup_path": None,
        "events": [], "checks": [], "unresolved": [],
    }
    # Unique run files are the default; locking also protects an explicit --output.
    with file_lock(report_path):
        atomic_json(report_path, report)
        try:
            _run(provider, client, addresses, settings, report_path, report, write, save, evidence,
                 evidence_files or [])
        except (RuntimeError, OSError, ValueError, KeyError, TypeError) as exc:
            report.update(status="failed", error=str(exc))
        except KeyboardInterrupt:
            report.update(status="interrupted", error="Interrupted; inspect the journal and backup before resuming")
        finally:
            atomic_json(report_path, report)
    return report


def _file_roots_and_catalog(
    settings: RecoveryConfig, evidence_files: list[Path], catalog: list[dict[str, Any]],
) -> tuple[list[Path], list[dict[str, Any]]]:
    """Resolve the readable roots and, if any, add the read/grep/glob tools.

    Roots come from two places: ``recovery.file_roots`` (operator-selected
    reference trees) and the parent directories of ``evidence_files``. Because
    ``--evidence`` names files rather than injecting their content, the agent
    must be able to read them; deriving a root from each evidence file's
    directory is what makes that automatic. A configured root that does not
    exist is a hard error: silently dropping it would leave the agent believing
    it has access it does not.
    """
    roots: list[Path] = []
    for raw in settings.file_roots:
        path = Path(raw).expanduser().resolve()
        if not path.is_dir():
            raise ValueError(f"recovery.file_roots entry is not a directory: {raw!r}")
        roots.append(path)
    for evidence in evidence_files:
        if evidence.is_file():
            roots.append(evidence.resolve().parent)
    # A specific root makes a broader root's files reachable anyway; keep the
    # most specific, deduplicating while preserving order.
    ordered: list[Path] = []
    for root in roots:
        if root not in ordered:
            ordered.append(root)
    if not ordered:
        return [], catalog
    return ordered, [*catalog, *files.FILE_TOOL_DEFS]


def _run(
    provider: LLMProvider, client: IdaRecoveryClient, addresses: list[str], settings: RecoveryConfig,
    report_path: Path, report: dict[str, Any], write: bool, save: bool, evidence: str,
    evidence_files: list[Path],
) -> None:
    health = client.health()
    report["database"] = health
    report["before"] = client.snapshot(addresses)
    allowed = READ_TOOLS | WRITE_TOOLS if write else READ_TOOLS
    catalog = [t for t in client.tools() if t.get("name") in allowed]
    file_roots, catalog = _file_roots_and_catalog(settings, evidence_files, catalog)
    tool_names = {t["name"] for t in catalog}
    system = render_template(PROMPT)
    initial = {
        "mode": report["mode"], "write_addresses": addresses, "objective": report["objective"],
        "database": health, "initial_state": report["before"], "evidence": evidence,
        "tools": catalog, "max_steps": settings.max_steps,
    }
    if evidence_files:
        # Content is not inlined; point the agent at the files and let it read
        # them with the file tools (their directories are readable roots).
        initial["evidence_files"] = [str(path) for path in evidence_files]
    if file_roots:
        initial["file_roots"] = files.tree(file_roots)
    # A served file call does not spend a step, so consulting reference source
    # costs no IDA evidence slot.  ``None`` keeps the historical shared budget,
    # where a file call spends a step like any other turn.
    file_budget = settings.max_file_calls
    file_used = 0
    steps_used = 0
    # Every turn charges a step up front -- refusals and malformed responses
    # included, exactly as the previous ``range(max_steps)`` loop did -- and a
    # served file call refunds it against the file budget instead.  One counter
    # therefore always advances, so a model that keeps asking past its budgets
    # cannot lengthen the run.
    max_rounds = settings.max_steps + (file_budget or 0)
    # Native conversation state avoids replaying the growing catalog/transcript
    # on CLI providers. API providers use the same Message contract as reverse.
    conversation = provider.new_conversation(system) if provider.supports_conversations else None
    history = [Message(role="system", content=system)]
    message = json.dumps(initial, ensure_ascii=False)
    atomic_json(report_path, report)
    rounds = 0
    # The run is extended past ``max_steps`` only by a turn that was actually
    # served from the file budget.  Otherwise an unused file budget would keep
    # the loop alive while a model spent the extra turns on refusals.
    served_file_call = False
    while rounds < max_rounds and (steps_used < settings.max_steps or served_file_call):
        served_file_call = False
        rounds += 1
        steps_used += 1
        atomic_json(report_path, report)
        _log.info("Recovery step %d/%d (%s)", steps_used, settings.max_steps, report["mode"])
        history.append(Message(role="user", content=message))
        response = provider.resume(conversation, message) if conversation is not None else provider.send(history)
        history.append(Message(role="assistant", content=response))
        # The turn index, independent of which budget the turn ends up on.
        event: dict[str, Any] = {"step": rounds, "response": response, "status": "pending"}
        report["events"].append(event)
        atomic_json(report_path, report)
        try:
            action = _parse_response(response)
            if action.get("action") == "finish":
                _finish(client, addresses, report, action, write, save)
                event["status"] = "finished"
                return
            if action.get("action") != "tool":
                raise ValueError("Expected action tool or finish")
            name, arguments = action.get("name"), action.get("arguments")
            if not isinstance(name, str) or not isinstance(arguments, dict):
                raise ValueError("Tool requests need a string name and object arguments")
            if name not in tool_names:
                event.update(status="denied", error=f"Tool {name!r} is unavailable in {report['mode']} mode")
                message = json.dumps({"error": event["error"]})
                continue
            if name == "recovery_set_local_type":
                if arguments.get("address") not in addresses:
                    raise ValueError("Local type writes require an explicitly selected function address")
                client.validate_local(arguments)
            if name == "declare_type":
                # The IDA-MCP server comma-splits a *string* decls into several
                # declarations, which shreds any declaration containing a comma
                # (two-parameter function members, multi-member structs) and
                # fails with a misleading "Missing brace". Wrap it as a single
                # list element so it is parsed whole.
                decls = arguments.get("decls")
                if isinstance(decls, str):
                    arguments = {**arguments, "decls": [decls]}
            if name == "set_type":
                edits = arguments.get("edits", [])
                for edit in edits if isinstance(edits, list) else [edits]:
                    if isinstance(edit, dict) and isinstance(edit.get("signature"), str) and re.search(
                        r"\b__(?:cdecl|stdcall|fastcall|thiscall)\s*\(", edit["signature"],
                    ):
                        raise ValueError(
                            "Include the function name in signatures, e.g. int __fastcall dispatch(C *obj)"
                        )
            if name == "py_eval":
                code = arguments.get("code")
                if not isinstance(code, str):
                    raise ValueError("py_eval.code must be a string")
                # Catch syntax errors locally, without executing model code or
                # sending a potentially mutating request to IDA.
                try:
                    compile(code, "<recovery-py-eval>", "exec")
                except SyntaxError as exc:
                    raise ValueError(f"Invalid IDAPython syntax: {exc}") from exc
        except (ValueError, TypeError) as exc:
            event.update(status="invalid", error=str(exc))
            message = json.dumps({"error": str(exc), "instruction": "Return a valid tool request or finish object"})
            continue
        if name in files.FILE_TOOL_NAMES and file_budget is not None and file_used < file_budget:
            # Served from the file budget: this turn refunds the step charged
            # above and extends the run by one turn.
            served_file_call = True
        event.update(tool=name, arguments=arguments)
        mutating = name in WRITE_TOOLS
        if mutating:
            _same_database(client, health)
            if report["backup_path"] is None:
                report["backup_path"] = client.backup(health)
                _same_database(client, health)
            report["write_attempted"] = True
        atomic_json(report_path, report)
        try:
            result = (files.dispatch(file_roots, name, arguments)
                      if name in files.FILE_TOOL_NAMES else client.call(name, arguments))
            event["result"] = result
            error = tool_error(result)
            if error:
                raise RuntimeError(error)
            event["status"] = "ok"
            if served_file_call:
                file_used += 1
                steps_used -= 1
            message = _bounded({"tool": name, "result": result}, settings.max_result_chars)
        except (RuntimeError, OSError, ValueError) as exc:
            event.update(status="failed", error=str(exc))
            if mutating:
                # HTTP errors can arrive after a partial application. Do not
                # retry, continue writing or save an uncertain database.
                raise RuntimeError(f"Write outcome uncertain for {name}: {exc}; inspect backup and journal") from exc
            message = json.dumps({"tool": name, "error": str(exc)})
        atomic_json(report_path, report)
    report.update(status="budget-exhausted", error="Recovery step budget exhausted; no automatic save")


def _same_database(client: IdaRecoveryClient, original: dict[str, Any]) -> None:
    current = client.health()
    if any(current.get(key) != original.get(key) for key in ("idb_path", "module", "imagebase")):
        raise RuntimeError("Active IDA database changed during recovery")


def _finish(
    client: IdaRecoveryClient, addresses: list[str], report: dict[str, Any], action: dict[str, Any],
    write: bool, save: bool,
) -> None:
    checks, unresolved = action.get("checks"), action.get("unresolved")
    if not isinstance(action.get("summary"), str):
        raise ValueError("finish.summary must be a string")
    if not isinstance(checks, list) or not all(isinstance(check, dict) for check in checks):
        raise ValueError("finish.checks must be a list of verification objects")
    if not isinstance(unresolved, list) or not all(isinstance(item, str) for item in unresolved):
        raise ValueError("finish.unresolved must be a list of strings")
    report.update(summary=action["summary"], unresolved=unresolved)
    if not write:
        report["status"] = "planned"
        return
    _same_database(client, report["database"])
    types = sorted({c["name"] for c in checks if c.get("kind") in {"type", "member"}
                    and isinstance(c.get("name"), str)})
    report["after"] = client.snapshot(addresses, types)
    report["checks"] = client.verify(checks, report["after"])
    # At least one target-variable/prototype assertion is necessary: merely
    # creating a type does not demonstrate recovery in a target function.
    applied_check = any(c.get("kind") in {"local", "prototype"} and c.get("address") in addresses for c in checks)
    verified = (bool(checks) and applied_check and len(checks) == len(report["checks"])
                and all(c.get("ok") is True for c in report["checks"]))
    report["status"] = "verified" if verified and not unresolved else "incomplete"
    if save and report["status"] == "verified":
        _same_database(client, report["database"])
        client.save()
        report["saved"] = True
