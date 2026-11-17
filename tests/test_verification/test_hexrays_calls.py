"""Hex-Rays expression wrappers must not masquerade as business calls."""
from __future__ import annotations

import pytest

from re_agent.backend.stub import StubBackend
from re_agent.config.schema import ProjectProfile
from re_agent.core.models import AsmResult, DecompileResult, FunctionTarget, Verdict
from re_agent.parity.engine import fetch_ghidra_data
from re_agent.parity.signals import check_low_call_count
from re_agent.parity.source_indexer import SourceIndexer
from re_agent.verification.inline_library import named_calls
from re_agent.verification.objective import verify_candidate

TARGET = FunctionTarget("0x1508c0", "", "CL_Parse_CDTrack")
DECOMPILE = '''void CL_Parse_CDTrack() {
    LODWORD(track[28]) = MSG_ReadByte();
    LODWORD(track[29]) = MSG_ReadByte();
    if (!COM_CheckParm("-nocdaudio")) queued = LODWORD(track[28]);
}'''
CANDIDATE = '''void CL_Parse_CDTrack() {
    track[28] = MSG_ReadByte();
    track[29] = MSG_ReadByte();
    if (!COM_CheckParm("-nocdaudio")) queued = track[28];
}'''


class _HexRaysBackend(StubBackend):
    def __init__(self, *, has_asm: bool = True, decompiled: str = DECOMPILE) -> None:
        super().__init__()
        self.capabilities.has_asm = has_asm
        self.decompiled = decompiled

    def decompile(self, target: str) -> DecompileResult:
        return DecompileResult(target, TARGET.function_name, "", self.decompiled, self.decompiled)

    def get_asm(self, target: str) -> AsmResult:
        return AsmResult(target, """1508c2 call __x86.get_pc_thunk.bx
1508d0 call MSG_ReadByte
1508e1 call MSG_ReadByte
1508f5 call COM_CheckParm""", 20, 4, False)


@pytest.mark.parametrize("has_asm", [False, True])
@pytest.mark.parametrize("macro", ["LODWORD", "HIDWORD", "LOWORD", "LOBYTE", "SHIBYTE", "BYTE1", "COERCE_FLOAT"])
def test_complete_cdtrack_candidate_passes_with_auditable_normalization(has_asm: bool, macro: str) -> None:
    backend = _HexRaysBackend(has_asm=has_asm, decompiled=DECOMPILE.replace("LODWORD", macro))
    result = verify_candidate(CANDIDATE, TARGET, backend)
    assert result.verdict == Verdict.PASS
    assert any("raw 6" in note and "ordinary 3" in note for note in result.findings)
    assert sum(macro in note and "decompiler_expr" in note for note in result.findings) == 3
    assert DECOMPILE.replace("LODWORD", macro) == backend.decompiled


@pytest.mark.parametrize("has_asm", [False, True])
@pytest.mark.parametrize("expression", ["MSG_ReadByte()", 'COM_CheckParm("-nocdaudio")'])
def test_normalization_cannot_hide_a_single_missing_business_occurrence(has_asm: bool, expression: str) -> None:
    candidate = CANDIDATE.replace(expression, "0", 1)
    missing = expression.split("(")[0]
    result = verify_candidate(candidate, TARGET, _HexRaysBackend(has_asm=has_asm))
    assert result.verdict == Verdict.FAIL
    assert any("Named calls missing" in note and f"{missing} (1 occurrence(s))" in note for note in result.findings)


def test_nested_real_call_still_provides_a_call_lower_bound() -> None:
    backend = _HexRaysBackend(has_asm=False, decompiled="void f() { LODWORD(real_call()); }")
    result = verify_candidate("void f() {}", FunctionTarget("0x1", "", "f"), backend, call_count_tolerance=1)
    assert result.verdict == Verdict.FAIL
    assert any("Decompiled call mismatch" in note for note in result.findings)
    assert any("real_call (1 occurrence(s))" in note for note in result.findings)


@pytest.mark.parametrize("call", ["LODWORD", "Business::LODWORD", "object.LODWORD"])
def test_real_source_functions_with_macro_names_are_counted(call: str) -> None:
    backend = _HexRaysBackend(has_asm=False, decompiled="void f() { real_call(); real_call(); real_call(); }")
    candidate = "void f() { " + f"{call}();" * 3 + " }"
    result = verify_candidate(candidate, FunctionTarget("0x1", "", "f"), backend, call_count_tolerance=1)
    assert result.verdict == Verdict.PASS


@pytest.mark.parametrize("call", ["LODWORD", "BYTE1", "COERCE_FLOAT"])
def test_source_macro_names_remain_named_call_anchors(call: str) -> None:
    assert {call: 1} == named_calls(f"{call}(x);", decompiled=False)
    assert named_calls(f"{call}(x);") == {}
    assert {call: 1} == named_calls(f"object.{call}(x);")


def test_normalized_check_can_match_a_real_source_function_named_like_a_macro() -> None:
    backend = _HexRaysBackend(has_asm=False, decompiled="void f() { LOBYTE(x) = object.BYTE1(); }")
    result = verify_candidate("void f() { x = BYTE1(); }", FunctionTarget("0x1", "", "f"), backend)
    assert result.verdict == Verdict.PASS


def test_unknown_machine_evidence_remains_unknown_after_macro_normalization() -> None:
    backend = _HexRaysBackend(has_asm=False, decompiled="void f() { LODWORD(sub_1234()); }")
    result = verify_candidate("void f() {}", FunctionTarget("0x1", "", "f"), backend)
    assert result.verdict == Verdict.UNKNOWN
    assert any("unresolved" in note and "sub_1234" in note for note in result.findings)


def test_parity_low_call_signal_uses_decompiler_normalization(tmp_path) -> None:
    backend = _HexRaysBackend(has_asm=False, decompiled="void f() {" + "LOBYTE(x) = 1;" * 6 + "}")
    data = fetch_ghidra_data(TARGET.address, backend)
    source = SourceIndexer(tmp_path, ProjectProfile()).analyze_body("candidate.cpp", 1, "{ x = 1; }")
    assert check_low_call_count(source, data) is None
