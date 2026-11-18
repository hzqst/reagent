"""Call classification must use exact targets and retain occurrence counts."""
from __future__ import annotations

import pytest

from re_agent.utils.call_evidence import (
    asm_call_evidence,
    code_call_evidence,
    mask_nonordinary_calls,
    pcode_call_evidence,
)


@pytest.mark.parametrize("target", [
    "__x86.get_pc_thunk.bx", "__i686.get_pc_thunk.cx", "__x86.get_pc_thunk.ax@plt",
    "0x91bb <__x86.get_pc_thunk.bx>",
])
def test_exact_pic_targets(target: str) -> None:
    calls = asm_call_evidence(f"0x91bb: CALL {target}", 1)
    assert calls.count("pic") == 1
    assert calls.comparable
    assert calls.sites[0].location == "0x91bb"


@pytest.mark.parametrize("target", [
    "operator delete(void*,uint)", "operator delete[](void *)", "operator new(unsigned int)",
    "std::operator new[](unsigned long)", "_ZdlPv", "_ZdlPvj", "_ZdlPvm@plt", "_ZdaPvj",
    "_Znwj", "_Znwm", "_ZnamRKSt9nothrow_t", "_ZnwmSt11align_val_t",
    "_ZdlPvmSt11align_val_t",
])
def test_allocation_variants_are_uncertain_lifetime_evidence(target: str) -> None:
    calls = asm_call_evidence(f"100 call {target}", 1)
    assert calls.count("lifetime") == 1
    assert not calls.comparable


@pytest.mark.parametrize("instruction", [
    "100 call notify ; __x86.get_pc_thunk.bx",
    "100 call Business::get_pc_thunk()",
    "100 call __x86.get_pc_thunk.bxBusiness",
    "100 call _ZdlPvBusiness",
    "100 call _ZdlSomething",
    "100 call __cxa_throw", "100 call __cxa_guard_acquire", "100 call _Unwind_Resume",
])
def test_business_and_runtime_symbols_are_not_exempt(instruction: str) -> None:
    calls = asm_call_evidence(instruction, 1)
    assert calls.count("ordinary") == 1


@pytest.mark.parametrize("target", [
    "eax", "[eax] ; operator delete(void *)", "dword ptr [ebx+_GLOBAL_OFFSET_TABLE_]",
    "ds:callback", "0x1234", "sub_1234", "FUN_00001234", "unk_D8C44C",
])
def test_indirect_or_unnamed_targets_are_unresolved(target: str) -> None:
    calls = asm_call_evidence(f"100 call {target}", 1)
    assert calls.count("unresolved") == 1
    assert not calls.comparable


def test_noncall_instructions_and_comments_cannot_inflate_sites() -> None:
    calls = asm_call_evidence("100 mov eax, call_counter ; call foo\n; call operator delete\n101 jmp foo", 0)
    assert calls.comparable
    assert calls.raw_count == 0


def test_hex_rays_data_labels_require_an_exact_bare_backend_name() -> None:
    code = "unk_ABCD(); unk_ABCD_handler(); api.unk_ABCD();"
    assert code_call_evidence(code).count("ordinary") == 3
    calls = code_call_evidence(code, decompiled=True)
    assert [site.kind for site in calls.sites] == ["unresolved", "ordinary", "ordinary"]


def test_partial_parsing_does_not_rewrite_the_raw_total() -> None:
    calls = asm_call_evidence("100 call foo", 6)
    assert calls.raw_count == 6
    assert calls.count("ordinary") == 1
    assert not calls.complete


def test_code_calls_keep_repeated_occurrences_and_mask_only_abi_names() -> None:
    code = """{
        __x86.get_pc_thunk.bx();
        Trace_FClose(handle);
        operator delete(handle, get_size());
        if (bad) Warning(1); else Warning(2);
        _ZdlPv(handle);
        // __i686.get_pc_thunk.ax(); Warning(3);
        const char *text = "Warning(4); operator delete(handle);";
    }"""
    calls = code_call_evidence(code)
    assert calls.count("ordinary") == 4
    assert calls.count("pic") == 1
    assert calls.count("lifetime") == 2
    remaining = mask_nonordinary_calls(code)
    assert len(remaining) == len(code)
    assert "get_size()" in remaining
    assert code_call_evidence(remaining).raw_count == 4


def test_unresolved_pcode_and_callind_do_not_claim_named_call_evidence() -> None:
    calls = pcode_call_evidence([
        {"opcode": "CALL", "target": "__x86.get_pc_thunk.bx", "address": "0x91bb"},
        {"opcode": "CALL", "target": "_ZdlPvj"},
        {"opcode": "CALL", "inputs": ["ram:0x9219"]},
        {"opcode": "CALLIND", "target": "operator delete(void *)"},
        {"opcode": "RETURN"},
    ])
    assert calls.raw_count == 4
    assert calls.count("pic") == 1
    assert calls.count("lifetime") == 1
    assert calls.count("unresolved") == 2


@pytest.mark.parametrize("macro", [
    "LOBYTE", "LOWORD", "LODWORD", "HIBYTE", "HIWORD", "HIDWORD",
    "SLOBYTE", "SLOWORD", "SLODWORD", "SHIBYTE", "SHIWORD", "SHIDWORD",
    "BYTE1", "BYTE15", "WORD1", "WORD7", "DWORD1", "DWORD3",
    "SBYTE1", "SBYTE15", "SWORD1", "SWORD7", "SDWORD1", "SDWORD3",
    "BYTEn", "WORDn", "DWORDn", "SBYTEn", "SWORDn", "SDWORDn",
    "COERCE_FLOAT", "COERCE_DOUBLE", "COERCE_LONG_DOUBLE", "COERCE_UNSIGNED_INT", "COERCE_UNSIGNED_INT64",
    "_mm_add_epi64", "_mm_cvtsi128_si32", "_mm_cvtsi32_si128", "_mm_loadl_epi64", "_mm_srli_epi64",
    "_mm_unpacklo_epi32", "_mm256_add_epi64", "_mm512_add_epi64", "__builtin_ia32_paddq128",
    "_cvtss_sh", "_cvtsh_ss",
])
def test_decompiler_expression_wrappers_keep_nested_calls_and_raw_evidence(macro: str) -> None:
    code = f"{macro}(real_call())"
    calls = code_call_evidence(code, decompiled=True)
    assert calls.raw_count == 2
    assert calls.count("ordinary") == 1
    assert calls.count("decompiler_expr") == 1
    assert calls.complete and calls.comparable
    assert [macro, "real_call"] == [site.target for site in calls.sites]
    assert "Hex-Rays" in calls.sites[0].reason
    assert code_call_evidence(code).count("ordinary") == 2
    assert asm_call_evidence(f"100 call {macro}", 1).count("ordinary") == 1
    assert pcode_call_evidence([{"opcode": "CALL", "target": macro}]).count("ordinary") == 1


def test_cdtrack_decompiler_calls_preserve_occurrences_and_diagnostics() -> None:
    code = '''LODWORD(track[28]) = MSG_ReadByte();
LODWORD(track[29]) = MSG_ReadByte();
if (!COM_CheckParm("-nocdaudio")) queued = LODWORD(track[28]);'''
    calls = code_call_evidence(code, decompiled=True)
    assert calls.raw_count == 6
    assert calls.count("ordinary") == 3
    assert calls.count("decompiler_expr") == 3
    assert calls.complete and calls.comparable
    assert [
        site.target for site in calls.sites if site.kind == "ordinary"
    ] == ["MSG_ReadByte", "MSG_ReadByte", "COM_CheckParm"]
    assert any("raw 6" in note and "ordinary 3" in note for note in calls.diagnostics("Decompile"))
    assert sum("LODWORD" in note and "text offset" in note for note in calls.diagnostics("Decompile")) == 3


@pytest.mark.parametrize("wrapper", ["LODWORD", "_mm_add_epi64", "__builtin_ia32_paddq128", "_cvtss_sh"])
def test_mask_decompiler_wrappers_preserves_nested_calls_offsets_and_newlines(wrapper: str) -> None:
    code = f"{wrapper}\n(\nHIDWORD(real_call())); BYTEn(other_call(), index_call());"
    remaining = mask_nonordinary_calls(code, decompiled=True)
    assert len(code) == len(remaining)
    assert code.index("\n") == remaining.index("\n")
    assert code.index("real_call") == remaining.index("real_call")
    assert [
        site.target for site in code_call_evidence(remaining).sites
    ] == ["real_call", "other_call", "index_call"]
    assert code == mask_nonordinary_calls(code)


@pytest.mark.parametrize("expression", [
    "Business::LODWORD(x)", "::LODWORD(x)", "object.LODWORD(x)", "object -> LODWORD(x)",
    "object. /* member */ BYTE1(x)", "Business::BYTE1(x)", "Business::COERCE_FLOAT(x)",
    "LODWORDHelper(x)", "BYTE1Helper(x)", "BYTE16(x)", "WORD8(x)", "DWORD4(x)",
    "COERCE_CUSTOM(x)", "__ROL4__(x, 1)", "__OFADD__(x, y)", "is_mul_ok(x, y)",
    "Business::_mm_add_epi64(x)", "::_mm_add_epi64(x)", "object._mm_add_epi64(x)",
    "object -> _mm_add_epi64(x)", "object. /* member */ _mm_add_epi64(x)",
    "Business::__builtin_ia32_paddq128(x)", "object._cvtss_sh(x)", "Business::_cvtsh_ss(x)",
    "_mmHelper(x)", "_mm256Helper(x)", "_mm512Helper(x)", "_mm1024_add_epi64(x)",
    "__builtin_ia32Helper(x)", "_cvtss_shHelper(x)", "_cvt_custom(x)",
])
def test_macro_lookalikes_and_other_helpers_are_retained(expression: str) -> None:
    calls = code_call_evidence(expression, decompiled=True)
    assert calls.count("ordinary") == 1
    assert calls.count("decompiler_expr") == 0


def test_comments_and_literals_cannot_supply_decompiler_expressions() -> None:
    code = '''// LODWORD(fake());
const char *text = "COERCE_FLOAT(fake())";
// _mm_add_epi64(fake());
const char *simd = "__builtin_ia32_paddq128(fake())";
real_call();'''
    calls = code_call_evidence(code, decompiled=True)
    assert calls.raw_count == 1
    assert calls.sites[0].target == "real_call"
