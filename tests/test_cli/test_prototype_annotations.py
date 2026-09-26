"""Exercise dry-run, write and failure recovery without a live IDB."""
from __future__ import annotations

import argparse
import copy
import json
from dataclasses import asdict

import pytest

from re_agent.agents.loop import run_fix_loop
from re_agent.backend.ida_prototype import PrototypeOperationError
from re_agent.cli.cmd_annotate import cmd_annotate
from re_agent.config.schema import ReAgentConfig
from re_agent.core.models import FunctionPrototypeProposal, FunctionTarget, SymbolProposal
from re_agent.core.symbols import record_symbol
from tests.test_agents.test_loop import MockLLM
from tests.test_agents.test_symbol_proposal import NEW as REVIEWED_DECLARATION
from tests.test_agents.test_symbol_proposal import PrototypeBackend, prototype_response

OLD = "void *__thiscall(void *this)"
NEW = "void *__thiscall(FileClass *this)"


class FakeClient:
    def __init__(self):
        self.calls = []
        self.original = {"address": "0x4a3890", "declaration": OLD, "source": "database",
                         "explicit": True, "serialized": ["old", "names", ""], "type_key": "old"}
        self.current = copy.deepcopy(self.original)
        self.fail = {}
        self.saved = False
        self.comment = ""
        self.corrections = False
        self.parameters = []

    def function_names(self, addresses):
        return {"4a3890": "FileClass_ReadWholeFile", "old_name": "FileClass_ReadWholeFile"}

    def comment_operation(self, mode, address, **parameters):
        self.calls.append(("comment-" + mode, address))
        if mode == "apply":
            self.comment = parameters["proposed"]
        return {"ok": True, "address": "0x4a3890", "comment": self.comment}

    def rename_functions(self, renames, *, dry_run, allow_overwrite):
        self.calls.append(("rename-dry" if dry_run else "rename", renames))
        return [{"ok": True} for _ in renames]

    def prototype_operation(self, mode, address, **kwargs):
        self.calls.append((mode, address))
        self.parameters.append((mode, kwargs))
        resolved = "0x4a3890" if address == "old_name" else address.lower()
        snapshot = {**copy.deepcopy(self.current), "address": resolved}
        # A timeout after application models an ambiguous transport failure.
        if mode == "apply" and not isinstance(self.fail.get(mode), PrototypeOperationError):
            self.current.update(declaration=NEW, type_key="new", serialized=["new", "names", ""])
        if mode in self.fail:
            raise self.fail[mode]
        if mode == "read":
            return {"ok": True, "current": snapshot}
        if mode == "plan":
            return {"ok": True, "current": snapshot, "proposed": NEW,
                    "requires_abi_corrections": self.corrections,
                    "differences": [{"position": "return", "before": "int", "after": "FileClass *"}]
                    if self.corrections else [{"position": "arg:0", "before": "void *", "after": "FileClass *"}],
                    "proposed_key": "new", "unchanged": self.current["type_key"] == "new"}
        if mode == "verify":
            return {"ok": True, "current": copy.deepcopy(self.current), "decompiled": "code"}
        if mode == "restore":
            self.current = copy.deepcopy(self.original)
        return {"ok": True}

    def save(self):
        self.calls.append(("save", None))
        if "save" in self.fail:
            raise self.fail["save"]
        self.saved = True
        return {"ok": True}


@pytest.fixture
def annotate(monkeypatch, tmp_path, capsys):
    client = FakeClient()
    config = ReAgentConfig()
    config.backend.type = "ida-mcp"
    monkeypatch.setattr("re_agent.cli.cmd_annotate.load_config", lambda _: config)
    monkeypatch.setattr("re_agent.cli.cmd_annotate.IdaWriteClient", lambda *args: client)
    prototype = FunctionPrototypeProposal(
        declaration=NEW, expected_current=OLD, required_types=["FileClass"],
        confidence="verified", evidence=["header:12, address 0x4A3890; ECX this"], review_status="approved",
    )

    def run(*, raw=None, address="0x4A3890", selected=None, **options):
        path = tmp_path / "symbols.json"
        if raw is None:
            record_symbol(path, address, SymbolProposal(name="FileClass::ReadWholeFile", comment="Read file",
                                                        prototype=prototype))
        else:
            rows = raw if isinstance(raw, list) else [{"address": address, **raw}]
            path.write_text(json.dumps({"schema_version": 1, "symbols": rows}))
        args = dict(config="unused.yaml", symbols=str(path), from_hooks=None, only_unnamed=False,
                    include_flagged=False, allow_struct_changes=False, allow_prototype_changes=True,
                    write=False, save=False, address=selected, comments_only=False, replace_function_comment=False)
        args.update(options)
        code = cmd_annotate(argparse.Namespace(**args))
        report = json.loads(capsys.readouterr().out)
        return code, report

    return client, prototype, run


def test_dry_run_reports_both_types_without_writes_or_save(annotate):
    client, _, run = annotate
    code, report = run(save=True)
    assert code == 0
    assert report["saved"] is False
    assert report["entries"][0]["prototype"]["current"] == OLD
    assert report["entries"][0]["prototype"]["proposed"] == NEW
    assert report["entries"][0]["prototype"]["status"] == "would-apply"
    assert {mode for mode, _ in client.calls} == {"read", "plan", "rename-dry", "comment-read"}
    assert client.original == client.current


def test_write_pins_address_before_rename_then_verifies_and_saves(annotate):
    client, _, run = annotate
    code, report = run(address="old_name", write=True, save=True)
    assert code == 0
    assert report["saved"] is True
    assert report["entries"][0]["prototype"]["verified"] is True
    assert client.calls[-3:] == [("apply", "0x4a3890"), ("verify", "0x4a3890"), ("save", None)]
    assert client.current["declaration"] == NEW


def test_second_application_is_unchanged(annotate):
    client, _, run = annotate
    run(write=True)
    client.calls.clear()
    code, report = run(write=True)
    assert code == 0
    assert report["entries"][0]["prototype"]["status"] == "unchanged"
    assert "apply" not in [mode for mode, _ in client.calls]


@pytest.mark.parametrize("status", ["unreviewed", "disputed"])
def test_include_flagged_cannot_bypass_prototype_review(annotate, status):
    client, prototype, run = annotate
    prototype.review_status = status
    code, report = run(write=True, include_flagged=True)
    assert code == 0
    assert report["entries"][0]["prototype"]["status"] == status
    assert "apply" not in [mode for mode, _ in client.calls]


@pytest.mark.parametrize("field,value", [("confidence", "inferred"), ("evidence", [])])
def test_unverified_type_is_skipped(annotate, field, value):
    client, prototype, run = annotate
    setattr(prototype, field, value)
    code, report = run(write=True)
    assert code == 0
    assert report["entries"][0]["prototype"]["status"] == "insufficient-evidence"
    assert client.original == client.current


def test_flag_is_required(annotate):
    client, _, run = annotate
    code, report = run(write=True, allow_prototype_changes=False)
    assert code == 0
    assert report["entries"][0]["prototype"]["status"] == "disabled"
    assert "apply" not in [mode for mode, _ in client.calls]


def test_only_unnamed_skips_entire_entry(annotate):
    client, _, run = annotate
    code, report = run(write=True, only_unnamed=True)
    assert code == 0
    assert report["entries"][0]["prototype"]["status"] == "skip-named"
    assert all(mode not in {"read", "plan", "apply", "comment"} for mode, _ in client.calls)


def test_invalid_type_does_not_disappear(annotate):
    client, _, run = annotate
    code, report = run(raw={"name": "f", "prototype": "bad"}, write=True)
    assert code == 1
    assert report["entries"][0]["prototype"]["status"] == "invalid-prototype"
    assert client.original == client.current


def test_legacy_file_does_not_call_type_tools(annotate):
    client, _, run = annotate
    code, report = run(raw={"name": "f", "comment": "hello"}, write=True, save=True)
    assert code == 0
    assert report["entries"][0]["prototype"] is None
    assert [mode for mode, _ in client.calls] == ["comment-read", "comment-apply", "comment-read", "rename", "save"]


@pytest.mark.parametrize("mode", ["plan", "apply", "verify", "save"])
def test_failures_produce_nonzero_exit_and_honest_report(annotate, mode):
    client, _, run = annotate
    client.fail[mode] = RuntimeError("simulated failure")
    code, report = run(write=True, save=True)
    assert code == 1
    if mode == "save":
        assert report["saved"] is False
        assert report["save_error"]
    else:
        status = "rejected" if mode == "plan" else "reverted"
        assert report["entries"][0]["prototype"]["status"] == status
        assert client.current == client.original
        calls = [operation for operation, _ in client.calls if operation in {"apply", "verify", "restore"}]
        expected = [] if mode == "plan" else ["apply", "restore"] if mode == "apply" else ["apply", "verify", "restore"]
        assert expected == calls


def test_prewrite_rejection_does_not_restore_someone_elses_edit(annotate):
    client, _, run = annotate
    client.fail["apply"] = PrototypeOperationError("stale", write_attempted=False)
    code, report = run(write=True)
    assert code == 1
    assert report["entries"][0]["prototype"]["status"] == "rejected"
    assert "restore" not in [mode for mode, _ in client.calls]


def test_failed_recovery_suppresses_save(annotate):
    client, _, run = annotate
    client.fail.update(verify=RuntimeError("mismatch"), restore=RuntimeError("disconnected"))
    code, report = run(write=True, save=True)
    assert code == 1
    assert report["saved"] is False
    assert report["entries"][0]["prototype"]["status"] == "recovery-failed"
    assert "save" not in [mode for mode, _ in client.calls]


def test_failed_recovery_stops_remaining_prototypes(annotate):
    client, prototype, run = annotate
    client.fail.update(verify=RuntimeError("mismatch"), restore=RuntimeError("disconnected"))
    code, report = run(raw=[
        {"address": "0x4A3890", "name": "f", "prototype": asdict(prototype)},
        {"address": "0x4A3900", "name": "g", "prototype": asdict(prototype)},
    ], write=True, save=True)
    assert code == 1
    assert report["entries"][1]["prototype"]["status"] == "not-attempted"
    assert [address for mode, address in client.calls if mode == "apply"] == ["0x4a3890"]
    assert client.saved is False


def test_shared_type_changes_require_separate_invocation(annotate):
    client, _, run = annotate
    with pytest.raises(ValueError, match="separate invocations"):
        run(write=True, allow_struct_changes=True)
    assert client.calls == []


def test_missing_snapshot_rejected(annotate):
    client, prototype, run = annotate
    prototype.expected_current = ""
    code, report = run(write=True)
    assert code == 1
    assert report["entries"][0]["prototype"]["status"] == "rejected"
    assert client.current == client.original


def test_symbol_dispute_blocks_type_even_with_include_flagged(annotate):
    client, prototype, run = annotate
    code, report = run(raw={"name": "f", "checker_ok": False, "prototype": asdict(prototype)},
                       write=True, include_flagged=True)
    assert code == 0
    assert report["entries"][0]["prototype"]["status"] == "disputed"
    assert client.current == client.original


def test_reverse_to_artifact_to_annotate(annotate):
    client, _, run = annotate
    result = run_fix_loop(
        FunctionTarget("0x4A3890", "FileClass", "f"), PrototypeBackend(),
        MockLLM([prototype_response()]), MockLLM([json.dumps({"verdict": "PASS", "prototype_review": {
            "status": "approved", "declaration": REVIEWED_DECLARATION, "notes": ["header and binary agree"],
        }})]), max_rounds=1, investigation_enabled=False, objective_verifier_enabled=False,
    )
    code, report = run(raw=asdict(result.symbol), write=True, save=True)
    assert code == 0
    assert report["entries"][0]["prototype"]["status"] == "applied"
    assert client.saved
    assert client.current["declaration"] == NEW


def test_inferred_requires_structured_evidence(annotate):
    client, prototype, run = annotate
    prototype.confidence = "inferred"
    _, report = run(write=True)
    assert report["entries"][0]["prototype"]["status"] == "insufficient-evidence"
    assert client.original == client.current


def test_disputed_is_distinct_from_unreviewed(annotate):
    _, prototype, run = annotate
    prototype.review_status = "disputed"
    _, report = run()
    assert report["entries"][0]["prototype"]["status"] == "disputed"


def structured(prototype):
    prototype.confidence = "inferred"
    prototype.evidence_kind = "signature-bound"
    prototype.evidence_details = {"header": "header.h:17-24", "version": "matched build",
                                  "address_binding": "member offsets and branches match"}
    prototype.abi_evidence = {"calling_convention": "ECX this; callee pops 8",
                              "arg:0": "ECX accesses class fields", "return": "all returns carry this in EAX"}


@pytest.mark.parametrize("corrections", [False, True])
def test_preflight_distinguishes_missing_opt_ins(annotate, corrections):
    client, prototype, run = annotate
    structured(prototype)
    client.corrections = corrections
    _, report = run(write=True)
    result = report["entries"][0]["prototype"]
    assert result["status"] == "needs-opt-in"
    expected = ["--allow-inferred-prototypes"]
    if corrections:
        expected.append("--allow-abi-type-corrections")
    assert expected == result["required_flags"]
    assert client.original == client.current
    assert "plan" in [mode for mode, _ in client.calls]


def test_opted_in_write_passes_correction_policy_and_verifies(annotate):
    client, prototype, run = annotate
    structured(prototype)
    client.corrections = True
    code, report = run(selected=["0x4A3890"], allow_inferred_prototypes=True,
                       allow_abi_type_corrections=True, write=True, save=True)
    assert code == 0
    assert report["entries"][0]["prototype"]["status"] == "applied"
    assert True is report["saved"]
    assert True is next(p for mode, p in client.parameters if mode == "apply")["allow_abi_type_corrections"]


@pytest.mark.parametrize("missing", ["header", "version", "address_binding", "return", "calling_convention"])
def test_opt_in_does_not_override_missing_evidence(annotate, missing):
    client, prototype, run = annotate
    structured(prototype)
    client.corrections = True
    prototype.evidence_details.pop(missing, None)
    prototype.abi_evidence.pop(missing, None)
    _, report = run(selected=["0x4A3890"], allow_inferred_prototypes=True,
                    allow_abi_type_corrections=True, write=True)
    assert report["entries"][0]["prototype"]["status"] == "insufficient-evidence"
    assert client.original == client.current


@pytest.mark.parametrize("flag", ["allow_inferred_prototypes", "allow_abi_type_corrections"])
def test_extended_flags_require_scope_and_base_permission(annotate, flag):
    client, _, run = annotate
    with pytest.raises(ValueError, match="require"):
        run(**{flag: True})
    with pytest.raises(ValueError, match="require"):
        run(selected=["0x4A3890"], allow_prototype_changes=False, **{flag: True})
    assert client.calls == []


def test_unsupported_change_is_not_reported_as_missing_permission(annotate):
    client, prototype, run = annotate
    structured(prototype)
    client.fail["plan"] = PrototypeOperationError("ABI mismatch", write_attempted=False, code="unsupported-change")
    code, report = run()
    assert code == 1
    assert report["entries"][0]["prototype"]["status"] == "unsupported-change"


@pytest.mark.parametrize("inferred,corrections,missing", [
    (True, False, "--allow-abi-type-corrections"),
    (False, True, "--allow-inferred-prototypes"),
])
def test_each_authorization_is_independent(annotate, inferred, corrections, missing):
    client, prototype, run = annotate
    structured(prototype)
    client.corrections = True
    _, report = run(selected=["0x4A3890"], allow_inferred_prototypes=inferred,
                    allow_abi_type_corrections=corrections, write=True)
    assert report["entries"][0]["prototype"]["required_flags"] == [missing]
    assert client.current == client.original


def test_verified_correction_still_needs_structured_evidence_and_opt_in(annotate):
    client, prototype, run = annotate
    client.corrections = True
    _, report = run()
    assert report["entries"][0]["prototype"]["status"] == "insufficient-evidence"
    structured(prototype)
    prototype.confidence = "verified"
    prototype.evidence_kind = "address-bound"
    _, report = run()
    assert report["entries"][0]["prototype"]["required_flags"] == ["--allow-abi-type-corrections"]


@pytest.mark.parametrize("review", ["unreviewed", "disputed"])
def test_all_opt_ins_cannot_bypass_review(annotate, review):
    client, prototype, run = annotate
    structured(prototype)
    prototype.review_status = review
    _, report = run(selected=["0x4A3890"], allow_inferred_prototypes=True,
                    allow_abi_type_corrections=True, include_flagged=True, write=True)
    assert review == report["entries"][0]["prototype"]["status"]
    assert client.current == client.original
