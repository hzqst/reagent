"""Hex-Rays expression wrappers must not masquerade as business calls."""
from __future__ import annotations

from pathlib import Path

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


# Issue #29's six intrinsic names and exact occurrence counts. Business calls
# are synthetic; one nested Read must survive masking the intrinsic around it.
SIMD_COUNTS = (
    ("_mm_add_epi64", 5), ("_mm_cvtsi128_si32", 3), ("_mm_cvtsi32_si128", 2),
    ("_mm_loadl_epi64", 7), ("_mm_srli_epi64", 2), ("_mm_unpacklo_epi32", 1),
)
SIMD_BODY = "".join(f"{name}(value);\n" * count for name, count in SIMD_COUNTS).replace(
    "_mm_cvtsi32_si128(value)", "_mm_cvtsi32_si128(Read())", 1,
)
SIMD_DECOMPILE = "void f() { Read(); Read(); Emit();\n" + SIMD_BODY + "}"
SIMD_CANDIDATE = "void f() { Read(); Read(); Emit(); value = Read(); }"
SIMD_TARGET = FunctionTarget("0xc020", "", "f")


class _SimdBackend(_HexRaysBackend):
    def __init__(self, *, has_asm: bool = True, decompiled: str = SIMD_DECOMPILE) -> None:
        super().__init__(has_asm=has_asm, decompiled=decompiled)

    def get_asm(self, target: str) -> AsmResult:
        return AsmResult(target, """c020 call __x86.get_pc_thunk.bx
c030 call Read
c040 call Read
c050 call Emit
c060 call Read
c070 paddq xmm0, xmm1
c080 movq xmm0, [eax]""", 30, 5, False)


@pytest.mark.parametrize("has_asm", [False, True])
def test_issue29_intrinsics_do_not_reject_scalar_candidate(has_asm: bool) -> None:
    backend = _SimdBackend(has_asm=has_asm)
    result = verify_candidate(SIMD_CANDIDATE, SIMD_TARGET, backend)
    assert result.verdict == Verdict.PASS
    assert any("raw 24" in note and "ordinary 4" in note for note in result.findings)
    assert sum("decompiler_expr" in note for note in result.findings) == 20
    for name, count in SIMD_COUNTS:
        assert sum(f": {name} [decompiler_expr]" in note for note in result.findings) == count
    assert backend.decompiled == SIMD_DECOMPILE


@pytest.mark.parametrize("has_asm", [False, True])
@pytest.mark.parametrize("call", ["Read()", "Emit()"])
def test_intrinsic_normalization_preserves_missing_business_occurrences(has_asm: bool, call: str) -> None:
    result = verify_candidate(SIMD_CANDIDATE.replace(call, "0", 1), SIMD_TARGET, _SimdBackend(has_asm=has_asm))
    assert result.verdict == Verdict.FAIL
    assert any(
        "Named calls missing" in note and f"{call[:-2]} (1 occurrence(s))" in note for note in result.findings
    )


@pytest.mark.parametrize("intrinsic", [
    "_mm_add_epi64", "_mm256_add_epi64", "_mm512_add_epi64", "__builtin_ia32_paddq128", "_cvtss_sh", "_cvtsh_ss",
])
def test_intrinsic_only_difference_passes_and_parity_does_not_warn(intrinsic: str, tmp_path: Path) -> None:
    backend = _SimdBackend(has_asm=False, decompiled="void f() {" + f"{intrinsic}(x);" * 6 + "}")
    result = verify_candidate("void f() { x = 1; }", SIMD_TARGET, backend)
    assert result.verdict == Verdict.PASS
    assert any("ordinary 0" in note and "decompiler expressions 6" in note for note in result.findings)
    assert named_calls(f"{intrinsic}(real_call());") == {"real_call": 1}
    data = fetch_ghidra_data(SIMD_TARGET.address, backend)
    source = SourceIndexer(tmp_path, ProjectProfile()).analyze_body("candidate.cpp", 1, "{ x = 1; }")
    assert check_low_call_count(source, data) is None


@pytest.mark.parametrize("call", ["_mm_add_epi64", "_mm256_add_epi64", "_mm512_add_epi64", "_cvtss_sh", "_cvtsh_ss"])
def test_intrinsic_named_source_and_member_calls_remain_anchors(call: str) -> None:
    assert named_calls(f"{call}(x);", decompiled=False) == {call: 1}
    assert named_calls(f"object.{call}(x);") == {call: 1}
    backend = _SimdBackend(has_asm=False, decompiled=f"void f() {{ _mm_loadl_epi64(x); object.{call}(x); }}")
    assert verify_candidate("void f() {}", SIMD_TARGET, backend).verdict == Verdict.FAIL


def test_intrinsic_nested_business_call_still_sets_lower_bound() -> None:
    backend = _SimdBackend(has_asm=False, decompiled="void f() { _mm_cvtsi32_si128(Read()); }")
    result = verify_candidate("void f() {}", SIMD_TARGET, backend, call_count_tolerance=1)
    assert result.verdict == Verdict.FAIL
    assert any("Decompiled call mismatch" in note for note in result.findings)
    assert any("Read (1 occurrence(s))" in note for note in result.findings)


def test_intrinsic_normalization_keeps_independent_evidence_gaps_unknown() -> None:
    backend = _SimdBackend(has_asm=False, decompiled="void f() { _mm_cvtsi32_si128(sub_1234()); }")
    result = verify_candidate("void f() {}", SIMD_TARGET, backend)
    assert result.verdict == Verdict.UNKNOWN
    assert any("unresolved" in note and "sub_1234" in note for note in result.findings)


def test_unused_intrinsic_results_leave_only_lexical_flow_uncertainty() -> None:
    backend = _SimdBackend(
        has_asm=False, decompiled="void f() { if (x) _mm_add_epi64(x); if (y) _mm_loadl_epi64(y); }",
    )
    result = verify_candidate("void f() {}", SIMD_TARGET, backend)
    assert result.verdict == Verdict.UNKNOWN
    assert any("Control-flow mismatch" in note for note in result.findings)
