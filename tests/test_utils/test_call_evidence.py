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
    "ds:callback", "0x1234", "sub_1234", "FUN_00001234",
])
def test_indirect_or_unnamed_targets_are_unresolved(target: str) -> None:
    calls = asm_call_evidence(f"100 call {target}", 1)
    assert calls.count("unresolved") == 1
    assert not calls.comparable


def test_noncall_instructions_and_comments_cannot_inflate_sites() -> None:
    calls = asm_call_evidence("100 mov eax, call_counter ; call foo\n; call operator delete\n101 jmp foo", 0)
    assert calls.comparable
    assert calls.raw_count == 0


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
