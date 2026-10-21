"""Sort normalization is bounded evidence, never permission to omit business logic."""
from __future__ import annotations

from collections import Counter

import pytest

from re_agent.core.models import Verdict
from re_agent.verification.inline_library import (
    has_sort_abstraction,
    has_sort_expansion,
    mask_regions,
    mechanical_call,
    named_calls,
    sort_regions,
)
from re_agent.verification.objective import verify_candidate
from tests.test_verification.test_inline_library import BUSINESS, EXPANSION, TARGET, _InlineBackend

SORT = """
    if (__first != __last) { /*0x1100*/
        _BitScanReverse(&v9, __last - __first);
        std::__introsort_loop<__gnu_cxx::__normal_iterator<int *,std::vector<int>>,int>(
            __first, __last, 2*(31 - (v9 ^ 0x1F))); /*0x1110*/
        if (__last - __first > 16) {
            std::__insertion_sort<int *>(__first, __first + 16);
        } else {
            std::__final_insertion_sort<int *>(__first, __last);
        }
    }
"""
SORT_CALLS = ["_ZSt16__introsort_loopIPiiEvT_S1_T0_"] * 6
SOURCE_SORT = "std::sort(values.begin(), values.end());"


@pytest.mark.parametrize("expression", [
    "BYTE1(x) = 0", "BYTE2(x)", "BYTE4(x)", "WORD1(x)", "DWORD1(x)",
    "HIBYTE(x)", "LOBYTE(x)", "SHIBYTE(x)", "SLODWORD(x)", "SHIDWORD(x)",
    "BYTEn(x, n)", "_BitScanReverse(&v9, size)", "_BitScanForward(&v9, size)",
    "_BitScanReverse64(&v9, size)", "__builtin_clz(size)",
])
def test_hex_rays_expressions_are_not_named_calls(expression: str) -> None:
    assert named_calls(expression + "; strcasecmp(a, b);") == Counter({"strcasecmp": 1})


@pytest.mark.parametrize("call, anchor", [
    ("BYTE1Helper(x)", "BYTE1Helper"), ("_BitScanReverseHelper(x)", "_BitScanReverseHelper"),
    ("Business::BYTE1(x)", "BYTE1"), ("Business::_BitScanReverse(x)", "_BitScanReverse"),
    ("object.BYTE1(x)", "BYTE1"), ("object->_BitScanReverse(x)", "_BitScanReverse"),
])
def test_similar_business_names_are_still_anchors(call: str, anchor: str) -> None:
    assert named_calls(call) == Counter({anchor: 1})


def test_pseudo_calls_no_longer_turn_vector_uncertainty_into_failure() -> None:
    backend = _InlineBackend(EXPANSION + "BYTE1(v8) = 0; _BitScanReverse(&v9, size);", ["memmove"] * 6)
    result = verify_candidate("void f() {values.push_back(value);}", TARGET,
                              backend)  # type: ignore[arg-type]
    assert result.verdict == Verdict.UNKNOWN
    assert not any("Named calls missing" in finding for finding in result.findings)


def test_sort_regions_preserve_offsets_addresses_and_business_branches() -> None:
    code = "void f() {" + BUSINESS + SORT + "if (saved) flush();}"
    regions = sort_regions(code)
    assert len(regions) == 1
    assert regions[0].kind == "std::sort helper"
    assert regions[0].addresses == {0x1100, 0x1110}
    residual = mask_regions(code, regions)
    assert len(residual) == len(code)
    assert BUSINESS in residual and "if (saved) flush();" in residual
    assert "__introsort_loop" not in residual


def test_sort_without_vector_storage_can_explain_library_counts() -> None:
    backend = _InlineBackend(BUSINESS + SORT, SORT_CALLS + ["notify"] * 2)
    result = verify_candidate("void f() {" + BUSINESS + SOURCE_SORT + "}", TARGET,
                              backend)  # type: ignore[arg-type]
    assert result.verdict == Verdict.UNKNOWN
    assert any("std::sort helper region" in finding for finding in result.findings)
    assert any("6 direct lowering/library calls" in finding for finding in result.findings)
    assert not any("Named calls missing" in finding for finding in result.findings)


def test_plain_sort_helpers_are_not_reported_as_missing_source_calls() -> None:
    backend = _InlineBackend(SORT.replace("<int *>", ""), SORT_CALLS)
    result = verify_candidate("void f() {" + SOURCE_SORT + "}", TARGET,
                              backend)  # type: ignore[arg-type]
    assert result.verdict == Verdict.UNKNOWN
    assert not any("Named calls missing" in finding for finding in result.findings)


@pytest.mark.parametrize("addition", [
    "business();", "if (permission) business();", "state.enabled = 1;", "return;",
    "goto outside;", "inside: v9 = 0;", "(*callback)();", "*health = 0;", "*v123 = 0;",
    "global_state = 0;", "counter[0] = 1;", "Business::__insertion_sort();",
    "if (v9) notify();", "v9 = *v123;", "*(v123) = 0;", "*((int *)v123) = 0;",
    "v9 = new int;", "delete v9;",
])
def test_sort_region_does_not_swallow_business_effects_or_pointer_accesses(addition: str) -> None:
    code = "void f() {if (__first != __last) {std::__introsort_loop<int *>(__first, __last, 2);"
    code += addition + "}}"
    assert sort_regions(code) == []


def test_cross_region_sort_jumps_remain_unknown_and_visible() -> None:
    body = SORT.replace("/*0x1110*/", "goto after_sort; /*0x1110*/")
    body += "after_sort: if (enabled) notify();"
    backend = _InlineBackend(body, SORT_CALLS + ["notify"])
    result = verify_candidate("void f() {" + SOURCE_SORT + "if (enabled) notify();}", TARGET,
                              backend)  # type: ignore[arg-type]
    assert result.verdict == Verdict.UNKNOWN
    assert any("Unresolved std::sort expansion" in finding for finding in result.findings)
    residual = mask_regions(body, sort_regions(body))
    assert "goto after_sort;" in residual
    assert "after_sort: if (enabled) notify();" in residual


def test_sort_normalization_still_rejects_removed_business_branches() -> None:
    backend = _InlineBackend(BUSINESS + SORT, SORT_CALLS + ["notify"] * 2)
    result = verify_candidate("void f() {notify(); notify();" + SOURCE_SORT + "}", TARGET,
                              backend)  # type: ignore[arg-type]
    assert result.verdict == Verdict.FAIL
    assert any("Control-flow mismatch" in finding for finding in result.findings)


def test_sort_uncertainty_still_rejects_one_missing_repeated_business_call() -> None:
    body = SORT + "if (v9) {strcasecmp(a, b); strcasecmp(c, d); strcasecmp(e, f);}"
    backend = _InlineBackend(body, SORT_CALLS + ["strcasecmp"] * 3)
    candidate = "void f() {" + SOURCE_SORT + "if (v9) {strcasecmp(a, b); strcasecmp(c, d);}}"
    result = verify_candidate(candidate, TARGET, backend)  # type: ignore[arg-type]
    assert result.verdict == Verdict.FAIL
    assert any("Named calls missing" in finding and "strcasecmp" in finding for finding in result.findings)


@pytest.mark.parametrize("claim", [
    "", "/* std::sort(values.begin(), values.end()); */",
    'const char *claim = "std::sort(values.begin(), values.end());";',
    "Business::sort(values);", "std::stable_sort(values.begin(), values.end());",
])
def test_sort_claims_cannot_enable_normalization(claim: str) -> None:
    backend = _InlineBackend(BUSINESS + SORT, SORT_CALLS + ["notify"] * 2)
    result = verify_candidate("void f() {" + BUSINESS + claim + "}", TARGET,
                              backend)  # type: ignore[arg-type]
    assert result.verdict == Verdict.FAIL


def test_vector_uncertainty_cannot_cover_a_removed_sort() -> None:
    # Leave unrelated storage visible so the vector fallback is incomplete.
    backend = _InlineBackend(EXPANSION + "v1 = values._M_impl._M_start;" + SORT,
                             ["memmove"] * 6 + SORT_CALLS)
    result = verify_candidate("void f() {values.push_back(value);}", TARGET,
                              backend)  # type: ignore[arg-type]
    assert result.verdict == Verdict.FAIL
    assert any("Control-flow mismatch" in finding for finding in result.findings)


def test_sort_has_to_be_present_in_both_backend_and_candidate_code() -> None:
    assert has_sort_abstraction("std::sort<int *>(first, last);")
    assert not has_sort_abstraction("/* std::sort(first, last); */")
    assert has_sort_expansion(SORT)
    assert not has_sort_expansion('const char *s = "std::__introsort_loop(first, last, 2)";')
    backend = _InlineBackend(BUSINESS, ["notify"] * 2)
    result = verify_candidate("void f() {" + SOURCE_SORT + "}", TARGET,
                              backend)  # type: ignore[arg-type]
    assert result.verdict == Verdict.FAIL


@pytest.mark.parametrize("instruction, expected", [
    ("100 call std::__introsort_loop<int *>(first, last, depth)", True),
    ("100 CALL std::__insertion_sort<int *>(first, last)", True),
    ("100 call _ZSt16__introsort_loopIPiiEvT_S1_T0_", True),
    ("100 call _ZSt16__insertion_sortIPiEvT_S1_", True),
    ("100 call Business::__introsort_loop()", False),
    ("100 call std::__introsort_loopBusiness()", False),
    ("100 call compare ; std::__introsort_loop<int *>", False),
    ("100 call [eax] ; std::__introsort_loop<int *>", False),
    ("100 mov eax, std::__introsort_loop<int *>", False),
])
def test_sort_lowering_requires_explicit_opt_in_and_an_exact_direct_target(instruction: str, expected: bool) -> None:
    assert mechanical_call(instruction, include_sort=True) == expected
    assert not mechanical_call(instruction)
