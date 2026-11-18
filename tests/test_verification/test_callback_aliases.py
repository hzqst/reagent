"""Callback spellings and machine call identities are separate evidence."""
from __future__ import annotations

import json

import pytest

from re_agent.backend.stub import StubBackend
from re_agent.core.models import AnalysisArtifact, AsmResult, DecompileResult, FunctionTarget, Verdict
from re_agent.verification.objective import verify_candidate

TARGET = FunctionTarget("100", "", "f")


class CallbackBackend(StubBackend):
    def __init__(self, body: str, instructions: str = "", operations: tuple[dict[str, str], ...] = ()) -> None:
        super().__init__()
        self.capabilities.has_asm = bool(instructions)
        self.capabilities.has_pcode = bool(operations)
        self.code = "void f() {\n" + body + "\n}"
        self.instructions = instructions
        self.operations = operations

    def decompile(self, target: str) -> DecompileResult:
        return DecompileResult(target, "f", "void f()", self.code, self.code)

    def get_asm(self, target: str) -> AsmResult:
        count = len(self.instructions.splitlines())
        return AsmResult(target, self.instructions, count, count, False)

    def get_pcode(self, target: str) -> AnalysisArtifact:
        return AnalysisArtifact("pcode", target, json.dumps({"data": self.operations}))


def test_unmapped_typed_callbacks_keep_raw_names() -> None:
    backend = CallbackBackend('gEntityInterface(); unk_D8C44C(&move); sub_A3C88("message");')
    result = verify_candidate('void f() { api.pfnGameInit(); api.pfnPM_Init(&move); Con_DPrintf("message"); }',
                              TARGET, backend)
    assert result.verdict == Verdict.UNKNOWN
    for name in ("gEntityInterface", "unk_D8C44C", "sub_A3C88"):
        assert any(name in note and "text offset" in note for note in result.findings)
    assert any("raw 3 calls" in note for note in result.findings)


@pytest.mark.parametrize("member", ["api.pfnInit", "api->pfnInit"])
def test_bare_alias_alone_is_inconclusive(member: str) -> None:
    result = verify_candidate(f"void f() {{ {member}(); }}", TARGET, CallbackBackend("callback_table();"))
    assert result.verdict == Verdict.UNKNOWN
    assert any("callback_table" in note for note in result.findings)


def test_data_labels_do_not_inflate_direct_call_lower_bound() -> None:
    backend = CallbackBackend("unk_A1(); unk_A2(); unk_A3(); unk_A4();")
    result = verify_candidate("void f() { api->init(); }", TARGET, backend)
    assert result.verdict == Verdict.UNKNOWN
    assert any("ordinary 0; unresolved 4" in note for note in result.findings)


@pytest.mark.parametrize("machine", ["ASM", "P-code", "both"])
@pytest.mark.parametrize("keep_notify", [True, False])
def test_indirect_slot_and_direct_call_are_checked_independently(machine: str, keep_notify: bool) -> None:
    asm = "cd211 call [edi+8Ch]\ncd220 call notify" if machine != "P-code" else ""
    ops = ({"opcode": "CALLIND", "address": "0xcd211"}, {"opcode": "CALL", "target": "notify"})
    backend = CallbackBackend("table(); /*0xcd211*/\nnotify();", asm, ops if machine != "ASM" else ())
    candidate = "void f() { api.pfnInit(); " + ("notify();" if keep_notify else "other(); /* notify(); */") + "}"
    result = verify_candidate(candidate, TARGET, backend)
    assert result.verdict == (Verdict.UNKNOWN if keep_notify else Verdict.FAIL)
    assert any("table" in note and "0xcd211" in note and "unresolved" in note for note in result.findings)
    if not keep_notify:
        assert any("notify (1 occurrence(s))" in note for note in result.findings)


def test_candidate_address_cannot_bind_backend_call() -> None:
    backend = CallbackBackend("notify();", "cd211 call [edi+8Ch]\ncd220 call notify")
    result = verify_candidate("void f() { api.pfnInit(); /*0xcd211*/ }", TARGET, backend)
    assert result.verdict == Verdict.FAIL
    assert any("notify (1 occurrence(s))" in note for note in result.findings)


@pytest.mark.parametrize("body", ["outer(notify()); /*0xcd211*/", "notify(); /*0xcd212*/"])
def test_ambiguous_or_unrelated_address_does_not_hide_direct_call(body: str) -> None:
    backend = CallbackBackend(body, "cd211 call [edi+8Ch]\ncd220 call notify")
    result = verify_candidate("void f() { api.pfnInit(); }", TARGET, backend)
    assert result.verdict == Verdict.FAIL
    assert any("notify (1 occurrence(s))" in note for note in result.findings)


def test_same_spelling_can_be_an_indirect_slot_and_a_direct_target() -> None:
    backend = CallbackBackend("notify(); /*0xcd211*/\nnotify();", "cd211 call eax\ncd220 call notify")
    result = verify_candidate("void f() { api.pfnInit(); notify(); }", TARGET, backend)
    assert result.verdict == Verdict.UNKNOWN
    assert any("cd211" in note and "eax" in note for note in result.findings)


def test_conflicting_ir_does_not_erase_a_direct_call_at_the_same_address() -> None:
    backend = CallbackBackend("notify(); /*0xcd211*/", "cd211 call notify",
                              ({"opcode": "CALLIND", "address": "0xcd211"},))
    result = verify_candidate("void f() { api.pfnInit(); }", TARGET, backend)
    assert result.verdict == Verdict.FAIL
    assert any("notify (1 occurrence(s))" in note for note in result.findings)


def test_an_unrelated_qualified_symbol_does_not_confirm_a_bare_alias() -> None:
    backend = CallbackBackend("callback();", "cd211 call [edi]\ncd220 call Other::callback()")
    result = verify_candidate("void f() { api.pfnInit(); Other::callback(); }", TARGET, backend)
    assert result.verdict == Verdict.UNKNOWN
    assert any("Unresolved call identity: callback" in note for note in result.findings)
