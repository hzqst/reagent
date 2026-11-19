"""Objective verdicts for recovered source helpers and inlined pseudocode."""
from __future__ import annotations

import pytest

from re_agent.backend.protocol import BackendCapabilities
from re_agent.core.models import DecompileResult, FunctionTarget, Verdict
from re_agent.verification.objective import verify_candidate


class Backend:
    capabilities = BackendCapabilities()

    def __init__(self, body: str) -> None:
        self.text = "void f(int *p) {" + body + "}"

    def decompile(self, address: str) -> DecompileResult:
        return DecompileResult(address, "f", "void f(int *p)", self.text, raw_output=self.text)


PAIR = "first(p); second(p);"
HELPER = "void helper(int *p) {" + PAIR + "}"
CALL = "helper(p);"


def verify(definitions: str, calls: str, decompiled: str):
    return verify_candidate(definitions + "void f(int *p) {" + calls + "}", FunctionTarget("100", "", "f"),
                            Backend(decompiled))  # type: ignore[arg-type]


@pytest.mark.parametrize("body", [PAIR * 3, PAIR + CALL + PAIR])
def test_separately_matched_helper_sites(body):
    result = verify(HELPER, CALL * 3, body)
    assert result.verdict == Verdict.UNKNOWN
    assert any("helper" in message and "candidate has 3 calls" in message for message in result.findings)


def test_missing_call_outside_helper_still_fails():
    result = verify(HELPER, CALL * 3, PAIR + "audit(p);" + PAIR * 2)
    assert result.verdict == Verdict.FAIL
    assert any("audit (1 occurrence(s))" in message for message in result.findings)


@pytest.mark.parametrize(("definitions", "calls", "body"), [
    (HELPER, "", PAIR * 3),
    ("void helper(int *p);", CALL * 3, PAIR * 3),
    (HELPER + "void helper(double *p) {}", CALL * 3, PAIR * 3),
    ("void helper(int *p) {if (*p) first(p); else second(p);}", CALL * 3, PAIR * 3),
    (HELPER, CALL * 3, "second(p); first(p);" * 3),
    (HELPER, "auto helper = other;" + CALL * 3, PAIR * 3),
])
def test_unmatched_helpers_cannot_cover_deficit(definitions, calls, body):
    assert verify(definitions, calls, body).verdict == Verdict.FAIL


def test_member_alias_uncertainty_receives_no_free_helper_credit():
    result = verify(HELPER, "obj.helper(p);" * 3, PAIR * 3)
    assert all("possible inline expansion" not in message for message in result.findings)


def test_target_name_can_be_a_substring_of_the_helper_name():
    result = verify(HELPER.replace("helper", "first_pair"), "first_pair(p);" * 3, PAIR * 3)
    assert result.verdict == Verdict.UNKNOWN
    assert any("first_pair x3" in msg for msg in result.findings)


def test_save_directory_call_shape_with_nested_source_calls():
    helper = """char *Host_SaveGameDirectory() {
        static char dir[260]; Q_memset(dir, 0, 260); std::strcpy(dir, "SAVE/"); return dir;
    }"""
    source = "snprintf(buf, n, fmt, Host_SaveGameDirectory());" * 3 + "other();" * 13
    binary = ('Q_memset(dir, 0, 260); strcpy(dir, "SAVE/"); snprintf(buf, n, fmt, dir);' * 3
              + "other();" * 13)
    result = verify(helper, source, binary)
    assert result.verdict == Verdict.UNKNOWN
    assert any("22 ordinary call sites" in msg and "19 calls" in msg and "Host_SaveGameDirectory x3" in msg
               for msg in result.findings)
