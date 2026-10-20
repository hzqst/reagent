"""Regression tests for conservative structural evidence handling."""
from __future__ import annotations

import json

import pytest

from re_agent.backend.ida_mcp import IdaMcpBackend
from re_agent.backend.protocol import BackendCapabilities
from re_agent.core.models import AnalysisArtifact, DecompileResult, FunctionTarget, Verdict
from re_agent.verification.objective import verify_candidate
from tests.test_backend.test_ida_mcp import _backend, _ok, _plain_decompile, _repeated_calls_backend


@pytest.mark.parametrize("source_calls, expected", [(6, Verdict.PASS), (0, Verdict.FAIL)])
def test_ida_repeated_call_sites_detect_missing_candidate_calls(monkeypatch, source_calls, expected):
    backend = _repeated_calls_backend(monkeypatch)

    result = verify_candidate(
        "void f() { " + "NormalizeFrustumPlane(); " * source_calls + "}",
        FunctionTarget("0x10001100", "", "f"),
        backend,
    )

    assert expected == result.verdict
    if expected == Verdict.FAIL:
        assert "ASM call mismatch: disassembly has 6 calls, candidate has 0" in result.findings


class _ErrorIRBackend:
    capabilities = BackendCapabilities(has_pcode=True, has_cfg=True)

    def decompile(self, target: str) -> DecompileResult:
        return DecompileResult(
            address=target,
            name="f",
            signature="void f()",
            decompiled="void f() {}",
            raw_output="void f() {}",
        )

    def get_pcode(self, target: str) -> AnalysisArtifact:
        payload = {"data": [{"error": "HighFunction unavailable"}]}
        return AnalysisArtifact("pcode", target, json.dumps(payload))

    def get_cfg(self, target: str) -> AnalysisArtifact:
        payload = {"data": [{"error": "CFG unavailable"}]}
        return AnalysisArtifact("cfg", target, json.dumps(payload))


def test_ir_error_objects_are_not_counted_as_successful_checks() -> None:
    verdict = verify_candidate(
        "void f() {}",
        FunctionTarget("0x100", "", "f"),
        _ErrorIRBackend(),  # type: ignore[arg-type]
    )
    assert verdict.verdict == Verdict.UNKNOWN


class _CFGBackend:
    capabilities = BackendCapabilities(has_cfg=True)

    def __init__(self, source: str, blocks: list[dict]) -> None:
        self.source = source
        self.blocks = blocks

    def decompile(self, target: str) -> DecompileResult:
        return DecompileResult(address=target, name="f", signature="int f(int x)",
                               decompiled=self.source, raw_output=self.source)

    def get_cfg(self, target: str) -> AnalysisArtifact:
        return AnalysisArtifact("cfg", target, json.dumps({"data": self.blocks}))


EARLY_RETURN_SOURCE = "int f(int x) { if (x == 0) return 10; if (x == 1) return 20; if (x == 2) return 30; return 0; }"
EARLY_RETURN_CFG = [
    {"index": 0, "out": [1, 2]}, {"index": 1, "out": []},
    {"index": 2, "out": [3, 4]}, {"index": 3, "out": []},
    {"index": 4, "out": [5, 6]}, {"index": 5, "out": []}, {"index": 6, "out": []},
]


@pytest.mark.parametrize("source", [
    EARLY_RETURN_SOURCE,
    "int f(int x) { return x == 0 ? 10 : x == 1 ? 20 : x == 2 ? 30 : 0; }",
    "int f(int x) { switch (x) { case 0: return 10; case 1: return 20; case 2: return 30; default: return 0; } }",
    "int f(int x) { return x > 0 && x < 10 && x != 5; }",
])
def test_cfg_does_not_estimate_block_count_from_source_keywords(source: str) -> None:
    result = verify_candidate(source, FunctionTarget("100", "", "f"),
                              _CFGBackend(source, EARLY_RETURN_CFG))  # type: ignore[arg-type]
    assert result.verdict == Verdict.PASS


def test_cfg_still_rejects_removed_branching_without_decompiler_support() -> None:
    # The CFG can catch a trivial replacement even if the decompiler omits flow.
    result = verify_candidate("int f(int x) { return x; }", FunctionTarget("100", "", "f"),
                              _CFGBackend("unavailable", EARLY_RETURN_CFG))  # type: ignore[arg-type]
    assert result.verdict == Verdict.FAIL
    assert any("CFG mismatch" in finding for finding in result.findings)


def test_removed_branches_still_fail_decompile_check() -> None:
    result = verify_candidate("int f(int x) { return 0; }", FunctionTarget("100", "", "f"),
                              _CFGBackend(EARLY_RETURN_SOURCE, EARLY_RETURN_CFG))  # type: ignore[arg-type]
    assert result.verdict == Verdict.FAIL
    assert any("Control-flow mismatch" in finding for finding in result.findings)


def test_linear_cfg_blocks_do_not_imply_branching() -> None:
    blocks = [{"index": i, "out": [i + 1] if i < 7 else []} for i in range(8)]
    result = verify_candidate("int f(int x) { return x; }", FunctionTarget("100", "", "f"),
                              _CFGBackend("int f(int x) { return x; }", blocks))  # type: ignore[arg-type]
    assert result.verdict == Verdict.PASS


# Representative Hex-Rays output: the three occurrences of "for" are part
# of a demangled static guard name, not loops. There are two decisions.
STATIC_GUARD_SOURCE = """int f() {
    if ((_BYTE)`guard variable for'Dialog::map
        || !acquire(&`guard variable for'Dialog::map)) return map;
    map = initialize("Dialog");
    release(&`guard variable for'Dialog::map);
    return map;
}"""
STATIC_GUARD_CANDIDATES = [
    "int f() { if (guard || !acquire(&guard)) return map; "
    'map = initialize("Dialog"); release(&guard); return map; }',
    "int f() { if (guard) return map; if (!acquire(&guard)) return map; "
    'map = initialize("Dialog"); release(&guard); return map; }',
    "int f() { if (!guard) { if (acquire(&guard)) { "
    'map = initialize("Dialog"); release(&guard); } } return map; }',
]


@pytest.mark.parametrize("candidate", STATIC_GUARD_CANDIDATES)
def test_ida_static_guard_accepts_short_circuit_and_separate_ifs(monkeypatch, candidate: str) -> None:
    _backend(monkeypatch, _plain_decompile(STATIC_GUARD_SOURCE))
    result = verify_candidate(candidate, FunctionTarget("0x1", "", "f"), IdaMcpBackend(),
                              control_flow_tolerance=1)
    assert result.verdict == Verdict.PASS
    assert result.findings == []


def test_ida_static_guard_still_rejects_removed_decisions(monkeypatch) -> None:
    _backend(monkeypatch, _plain_decompile(STATIC_GUARD_SOURCE))
    result = verify_candidate("int f() { return map; }", FunctionTarget("0x1", "", "f"), IdaMcpBackend())
    assert result.verdict == Verdict.FAIL
    assert "Control-flow mismatch: decompile has 2 branches/loops, candidate has 0" in result.findings


def test_objective_ignores_json_metadata_when_counting_decompiled_code(monkeypatch) -> None:
    source = "int f() { if (a) return 1; if (b) return 2; return 0; }"
    responses = _plain_decompile(source)
    responses["decompile"] = _ok({
        "code": source,
        "refs": [{"name": "for while if switch", "string": "if && || ?"}],
    })
    _backend(monkeypatch, responses)
    result = verify_candidate(source, FunctionTarget("0x1", "", "f"), IdaMcpBackend())
    assert result.verdict == Verdict.PASS


def test_ida_json_envelope_does_not_hide_constant_return_mismatch(monkeypatch) -> None:
    _backend(monkeypatch, _plain_decompile("int f() { return 1; }"))
    result = verify_candidate("int f() { return 2; }", FunctionTarget("0x1", "", "f"), IdaMcpBackend())
    assert result.verdict == Verdict.FAIL
    assert "Constant return value differs from decompiled evidence" in result.findings


@pytest.mark.parametrize("candidate", [
    'int f(int x) { const char *text = "if for while && || ?"; return x; }',
    "int f(int x) { const char *text = R\"(if for while && || ?)\"; return x; }",
])
def test_literals_cannot_hide_removed_cfg_branching(candidate: str) -> None:
    result = verify_candidate(candidate, FunctionTarget("100", "", "f"),
                              _CFGBackend("unavailable", EARLY_RETURN_CFG))  # type: ignore[arg-type]
    assert result.verdict == Verdict.FAIL
    assert any("CFG mismatch" in finding for finding in result.findings)


def test_call_names_in_literals_cannot_hide_removed_calls(monkeypatch) -> None:
    backend = _repeated_calls_backend(monkeypatch)
    source = 'void f() { print("' + "NormalizeFrustumPlane(); " * 6 + '"); }'
    result = verify_candidate(source, FunctionTarget("0x10001100", "", "f"), backend)
    assert result.verdict == Verdict.FAIL
    assert "ASM call mismatch: disassembly has 6 calls, candidate has 1" in result.findings


@pytest.mark.parametrize("decompiled, candidate", [
    ("int f() { if (a) return 1; if (b) return 1; if (c) return 1; return 0; }",
     "int f() { if (a || b || c) return 1; return 0; }"),
    ("int f() { if (a) { if (b) { if (c) return 1; } } return 0; }",
     "int f() { if (a && b && c) return 1; return 0; }"),
    ("int f() { if (a) return 1; if (b) return 2; if (c) return 3; return 0; }",
     "int f() { return a ? 1 : b ? 2 : c ? 3 : 0; }"),
])
@pytest.mark.parametrize("swap", [False, True])
def test_equivalent_decision_counts_are_symmetric(monkeypatch, decompiled: str, candidate: str, swap: bool) -> None:
    if swap:
        decompiled, candidate = candidate, decompiled
    _backend(monkeypatch, _plain_decompile(decompiled))
    result = verify_candidate(candidate, FunctionTarget("0x1", "", "f"), IdaMcpBackend(),
                              control_flow_tolerance=1)
    assert result.verdict == Verdict.PASS


def test_literal_comment_markers_do_not_hide_real_source_branches(monkeypatch) -> None:
    source = 'int f() { print("http://host"); if (a) return 1; if (b) return 2; return 0; }'
    _backend(monkeypatch, _plain_decompile(source))
    result = verify_candidate(source, FunctionTarget("0x1", "", "f"), IdaMcpBackend(),
                              control_flow_tolerance=1)
    assert result.verdict == Verdict.PASS
