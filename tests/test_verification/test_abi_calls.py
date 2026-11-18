"""PIC/lifetime lowering must not reject source-level C++ call structure."""
from __future__ import annotations

import json

import pytest

from re_agent.agents.loop import run_fix_loop
from re_agent.backend.stub import StubBackend
from re_agent.config.schema import ParityConfig, ProjectProfile
from re_agent.core.models import AnalysisArtifact, AsmResult, DecompileResult, FunctionTarget, HookEntry, Verdict
from re_agent.parity.engine import fetch_ghidra_data, score_single
from re_agent.parity.signals import check_call_count_mismatch, check_low_call_count
from re_agent.parity.source_indexer import SourceIndexer
from re_agent.utils.text import count_calls
from re_agent.verification.objective import verify_candidate
from tests.test_agents.test_loop import MockLLM

TARGET = FunctionTarget("0x91b0", "CBaseFileSystem", "Close")
CANDIDATE = """void CBaseFileSystem::Close(Handle *handle) {
    Trace_FClose(handle);
    delete handle->data;
    if (bad) Warning(1);
    delete handle;
    if (other) Warning(2);
}"""
DECOMPILE = CANDIDATE.replace("delete handle->data;", "operator delete(handle->data, 4u);").replace(
    "delete handle;", "operator delete(handle, 4u);",
)
CALLS = [
    "__x86.get_pc_thunk.bx", "CBaseFileSystem::Trace_FClose", "operator delete(void*,uint)",
    "CBaseFileSystem::Warning", "operator delete(void*,uint)", "CBaseFileSystem::Warning",
]


class _ABIBackend(StubBackend):
    def __init__(self, calls: list[str] | None = None, decompiled: str = DECOMPILE,
                 pcode: list[dict[str, object]] | None = None, callees: int | None = 5) -> None:
        super().__init__()
        self.calls = CALLS if calls is None else calls
        self.decompiled = decompiled
        self.pcode = pcode
        self.callees = callees
        self.capabilities.has_pcode = pcode is not None

    def decompile(self, target: str) -> DecompileResult:
        return DecompileResult(target, "CBaseFileSystem::Close", "", self.decompiled, self.decompiled,
                               callees=self.callees)

    def get_asm(self, target: str) -> AsmResult:
        instructions = "\n".join(f"{0x91bb + i * 4:x} call {call}" for i, call in enumerate(self.calls))
        return AsmResult(target, instructions, 61, len(self.calls), False)

    def get_pcode(self, target: str) -> AnalysisArtifact | None:
        return AnalysisArtifact("pcode", target, json.dumps({"data": self.pcode})) if self.pcode is not None else None


@pytest.mark.parametrize("has_asm", [True, False])
def test_close_lifetime_expansion_is_unknown_with_auditable_raw_counts(has_asm: bool) -> None:
    backend = _ABIBackend()
    backend.capabilities.has_asm = has_asm
    result = verify_candidate(CANDIDATE, TARGET, backend)
    assert result.verdict == Verdict.UNKNOWN
    if has_asm:
        assert any("raw 6 calls; PIC 1; lifetime 2; ordinary 3" in f for f in result.findings)
        assert any("91bb" in f and "exact PIC" in f for f in result.findings)
    assert any("operator delete" in f and "lifetime" in f for f in result.findings)
    assert count_calls(CANDIDATE.partition("{")[2])[0] == 3


@pytest.mark.parametrize("missing", ["Trace_FClose(handle);", "Warning(1);", "Warning(2);"])
def test_lifetime_uncertainty_does_not_hide_a_missing_business_occurrence(missing: str) -> None:
    result = verify_candidate(CANDIDATE.replace(missing, ";"), TARGET, _ABIBackend())
    assert result.verdict == Verdict.FAIL
    assert any("Named calls missing" in f and missing.split("(")[0] in f for f in result.findings)


def test_delete_keyword_or_comment_cannot_prove_lifetime_equivalence() -> None:
    candidate = CANDIDATE.replace("delete handle->data;", "/* delete handle->data; */")
    result = verify_candidate(candidate, TARGET, _ABIBackend())
    assert result.verdict == Verdict.UNKNOWN


def test_guard_removal_without_independent_evidence_is_inconclusive() -> None:
    candidate = CANDIDATE.replace("if (bad) ", "").replace("if (other) ", "")
    result = verify_candidate(candidate, TARGET, _ABIBackend())
    assert result.verdict == Verdict.UNKNOWN
    assert any("Control-flow mismatch" in f for f in result.findings)


def test_only_pic_thunks_can_be_removed_without_lifetime_uncertainty() -> None:
    backend = _ABIBackend(["__i686.get_pc_thunk.bx"] * 6, "void Close() {}", callees=None)
    result = verify_candidate("void Close() {}", TARGET, backend)
    assert result.verdict == Verdict.PASS
    assert any("PIC 6" in f for f in result.findings)
    assert not any("ASM call mismatch" in f for f in result.findings)


def test_unnamed_decompiler_targets_do_not_become_missing_business_anchors() -> None:
    backend = _ABIBackend(["sub_1234"] * 6, "void Close() {" + "sub_1234();" * 6 + "}")
    result = verify_candidate("void Close() {}", TARGET, backend)
    assert result.verdict == Verdict.UNKNOWN
    assert not any("Named calls missing" in f for f in result.findings)


def test_aggregate_callee_count_without_targets_is_not_a_hard_failure() -> None:
    backend = _ABIBackend([], "unavailable")
    result = verify_candidate("void Close() {}", TARGET, backend)
    assert result.verdict == Verdict.UNKNOWN
    assert any("callee totals" in f for f in result.findings)


@pytest.mark.parametrize("named", [False, True])
def test_pcode_uses_the_same_classification_or_reports_missing_targets(named: bool) -> None:
    operations = [{"opcode": "CALL", **({"target": call} if named else {"inputs": ["ram:0x100"]})}
                  for call in CALLS]
    result = verify_candidate(CANDIDATE, TARGET, _ABIBackend(pcode=operations))
    assert result.verdict == Verdict.UNKNOWN
    assert any("P-code call comparison is inconclusive" in f for f in result.findings)
    assert not any("P-code call mismatch" in f for f in result.findings)


def test_named_pcode_deficit_still_fails() -> None:
    backend = _ABIBackend([], "void Close() {}", [{"opcode": "CALL", "target": "notify"}] * 6)
    result = verify_candidate("void Close() {}", TARGET, backend)
    assert result.verdict == Verdict.FAIL
    assert any("P-code call mismatch" in f for f in result.findings)


def test_unknown_objective_allows_checker_pass_without_another_round() -> None:
    result = run_fix_loop(
        TARGET, _ABIBackend(), MockLLM([f"```cpp\n{CANDIDATE}\n```"]),
        MockLLM([json.dumps({"verdict": "PASS", "summary": "Matches", "issues": []})]),
        max_rounds=2, investigation_enabled=False,
    )
    assert result.success
    assert result.rounds_used == 1
    assert result.objective_verdict is not None
    assert result.objective_verdict.verdict == Verdict.UNKNOWN


def test_parity_preserves_raw_counts_and_uses_the_shared_classification(tmp_path) -> None:
    backend = _ABIBackend()
    data = fetch_ghidra_data(TARGET.address, backend)
    source = SourceIndexer(tmp_path, ProjectProfile()).analyze_body(
        "candidate.cpp", 1, CANDIDATE[CANDIDATE.index("{"):],
    )
    finding = check_call_count_mismatch(source, data, call_count_warn_diff=0)
    assert data.asm_call_count == 6
    assert data.callees == 5
    assert finding is not None and finding.level == "info"
    assert "PIC 1; lifetime 2; ordinary 3" in finding.reason
    hook = HookEntry("CBaseFileSystem", "Close", TARGET.address, True, False, False)
    _, findings = score_single(hook, source, data, ParityConfig(call_count_warn_diff=0))
    assert not any(f.level in {"yellow", "red"} for f in findings)


def test_lifetime_only_decompile_does_not_emit_a_blocking_low_call_warning(tmp_path) -> None:
    backend = _ABIBackend([], "void Close() {" + "operator delete(p);" * 6 + "}")
    data = fetch_ghidra_data(TARGET.address, backend)
    data.callees = 6
    source = SourceIndexer(tmp_path, ProjectProfile()).analyze_body("candidate.cpp", 1, "{ delete p; }")
    finding = check_low_call_count(source, data)
    assert finding is not None and finding.level == "info"


def test_low_call_warning_ignores_braces_and_calls_in_backend_comments(tmp_path) -> None:
    backend = _ABIBackend([], "/* { " + "fake();" * 6 + " */ void Close() {}", callees=0)
    data = fetch_ghidra_data(TARGET.address, backend)
    source = SourceIndexer(tmp_path, ProjectProfile()).analyze_body("candidate.cpp", 1, "{}")
    assert check_low_call_count(source, data) is None


def test_parity_retains_a_comparable_business_call_deficit(tmp_path) -> None:
    backend = _ABIBackend(["operator delete(void *)"] * 2 + ["notify"] * 6,
                          "void Close() {" + "notify();" * 6 + "}")
    data = fetch_ghidra_data(TARGET.address, backend)
    source = SourceIndexer(tmp_path, ProjectProfile()).analyze_body("candidate.cpp", 1, "{ delete handle; }")
    for finding in (check_low_call_count(source, data), check_call_count_mismatch(source, data)):
        assert finding is not None and finding.level == "yellow"
