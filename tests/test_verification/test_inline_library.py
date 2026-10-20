"""Compiler expansion never waives independent business-logic contradictions."""
from __future__ import annotations

import json

import pytest

from re_agent.backend.protocol import BackendCapabilities
from re_agent.core.models import AnalysisArtifact, AsmResult, DecompileResult, FunctionTarget, Verdict
from re_agent.verification.inline_library import mask_regions, mechanical_call, vector_regions
from re_agent.verification.objective import verify_candidate

EXPANSION = """
    if (values._M_impl._M_finish == values._M_impl._M_end_of_storage) /*0x101c27*/ {
        std::vector<int>::_M_insert_aux(&values, values._M_impl._M_finish, &value); /*0x1024de*/
        if (values._M_impl._M_start) { memmove(dst, src, size); }
    } else {
        if (values._M_impl._M_finish) { *values._M_impl._M_finish = value; }
        values._M_impl._M_finish = values._M_impl._M_finish + 1;
    }
"""
BUSINESS = "if (enabled) notify(); if (ready) notify();"
TARGET = FunctionTarget("0x100", "", "f")


class _InlineBackend:
    capabilities = BackendCapabilities(has_asm=True, has_cfg=True)

    def __init__(self, body: str = BUSINESS + EXPANSION, calls: list[str] | None = None) -> None:
        self.body = body
        self.calls = calls if calls is not None else ["memmove"] * 6 + ["notify"] * 2

    def decompile(self, target: str) -> DecompileResult:
        code = "void f() {" + self.body + "}"
        return DecompileResult(target, "f", "void f()", code, code)

    def get_asm(self, target: str) -> AsmResult:
        instructions = "\n".join(f"{0x100 + i:x} call {call}" for i, call in enumerate(self.calls))
        return AsmResult(target, instructions, len(self.calls), len(self.calls), False)

    def get_cfg(self, target: str) -> AnalysisArtifact:
        return AnalysisArtifact("cfg", target, json.dumps({"data": [
            {"index": 0, "out": [1, 2]}, {"index": 1, "out": [3, 4]},
        ]}))


def test_container_abstraction_keeps_raw_counts_and_bounded_address_evidence():
    backend = _InlineBackend()
    verdict = verify_candidate("void f() {" + BUSINESS + "values.push_back(value);}", TARGET,
                               backend)  # type: ignore[arg-type]
    assert verdict.verdict == Verdict.UNKNOWN
    assert any("ASM call mismatch: disassembly has 8 calls, candidate has 3" in f for f in verdict.findings)
    assert any("0x101c27" in f and "0x1024de" in f for f in verdict.findings)
    assert any("Control-flow mismatch" in f for f in verdict.findings)


def test_removed_business_branches_remain_fail_even_if_calls_are_retained():
    verdict = verify_candidate("void f() {notify(); notify(); values.push_back(value);}", TARGET,
                               _InlineBackend())  # type: ignore[arg-type]
    assert verdict.verdict == Verdict.FAIL
    assert any("Control-flow mismatch" in f for f in verdict.findings)


def test_missing_business_call_dominates_unknown_counts():
    verdict = verify_candidate("void f() {if (enabled) values.push_back(value);}", TARGET,
                               _InlineBackend())  # type: ignore[arg-type]
    assert verdict.verdict == Verdict.FAIL
    assert any("Named calls missing" in f and "notify" in f for f in verdict.findings)


def test_pure_library_cfg_branching_is_unknown_for_branchless_container_source():
    verdict = verify_candidate("void f() {values.push_back(value);}", TARGET,
                               _InlineBackend(EXPANSION, ["memmove"] * 6))  # type: ignore[arg-type]
    assert verdict.verdict == Verdict.UNKNOWN
    assert any("CFG mismatch" in f for f in verdict.findings)


def test_nonlibrary_call_deficit_still_fails_with_vector_evidence():
    verdict = verify_candidate("void f() {" + BUSINESS + "values.push_back(value);}", TARGET,
                               _InlineBackend(calls=["notify"] * 9))  # type: ignore[arg-type]
    assert verdict.verdict == Verdict.FAIL
    assert any("ASM call mismatch" in f for f in verdict.findings)


@pytest.mark.parametrize("candidate", [
    "void f() {}",
    "void f() { /* values.push_back(value); 0x101c27..0x1024de */ }",
    "void f() { const char *claim = \"values.push_back(value);\"; }",
])
def test_candidate_claims_cannot_request_an_exception(candidate):
    verdict = verify_candidate(candidate, TARGET, _InlineBackend())  # type: ignore[arg-type]
    assert verdict.verdict == Verdict.FAIL


def test_generic_memmove_does_not_authorize_vector_normalization():
    backend = _InlineBackend("if (enabled) memmove(dst, src, size); if (ready) memmove(dst, src, size);")
    verdict = verify_candidate("void f() {values.push_back(value);}", TARGET,
                               backend)  # type: ignore[arg-type]
    assert verdict.verdict == Verdict.FAIL


@pytest.mark.parametrize("addition", [
    "business();", "if (permission) business();", "state.enabled = 1;", "return;", "goto elsewhere;",
    "(*callback)();", "*health = 0;", "*v123 = 0;", "global_state = 0;", "counter[0] = 1;",
    "Business::memmove();",
])
def test_library_region_does_not_swallow_business_effects_or_external_edges(addition):
    code = "void f() { if (values._M_impl._M_finish) { memmove(dst, src, size); " + addition + " } }"
    assert vector_regions(code) == []


def test_normalization_keeps_surrounding_business_control_flow():
    code = "void f() {" + BUSINESS + EXPANSION + "}"
    regions = vector_regions(code)
    assert len(regions) == 1
    assert BUSINESS in mask_regions(code, regions)
    assert "_M_impl" not in mask_regions(code, regions)


def test_removing_one_repeated_business_call_still_fails():
    candidate = "void f() { if (enabled) notify(); if (ready) {} values.push_back(value); }"
    verdict = verify_candidate(candidate, TARGET, _InlineBackend())  # type: ignore[arg-type]
    assert verdict.verdict == Verdict.FAIL
    assert any("Named calls missing" in f and "notify" in f for f in verdict.findings)


def test_implicit_destructor_does_not_count_as_a_missing_constructor():
    backend = _InlineBackend(EXPANSION + "Item::Item(item); Item::~Item(item);", ["memmove"] * 6)
    verdict = verify_candidate("void f() {values.push_back(value); Item *item = new Item(); delete item;}",
                               TARGET, backend)  # type: ignore[arg-type]
    assert verdict.verdict == Verdict.UNKNOWN


@pytest.mark.parametrize("instruction, expected", [
    ("100 call memmove", True), ("100 call std::__throw_bad_alloc(void)", True),
    ("100 call operator delete(void *)", True), ("100 call _ZdlPv", True),
    ("100 call Business::memmoveRecords()", False), ("100 call notify ; memmove", False),
    ("100 call [eax] ; operator delete", False), ("100 mov eax, memmove", False),
    ("100 CALL memmove", True), ("100 call MEMMOVE", False),
])
def test_lowering_call_matching_requires_a_direct_known_target(instruction, expected):
    assert mechanical_call(instruction) == expected
