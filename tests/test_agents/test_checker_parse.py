"""Checker verdict parsing, including prose-wrapped and fenced JSON replies."""
from __future__ import annotations

import json

import pytest

from re_agent.agents.checker import CheckerAgent
from re_agent.core.models import Verdict

_VERDICT_JSON = json.dumps({"verdict": "PASS", "summary": "matches", "issues": [], "symbol_issues": []})


def test_parses_prose_then_fenced_json():
    response = (
        "All evidence is now in hand. Cross-checking against the disassembly:\n\n"
        f"```json\n{_VERDICT_JSON}\n```\n"
    )

    verdict = CheckerAgent._parse_verdict(response)

    assert verdict.verdict == Verdict.PASS
    assert verdict.summary == "matches"


def test_parses_prose_then_bare_json():
    response = f"Checking branch by branch.\n\n{_VERDICT_JSON}"

    assert CheckerAgent._parse_verdict(response).verdict == Verdict.PASS


def test_parses_fenced_json_followed_by_prose():
    response = f"```json\n{_VERDICT_JSON}\n```\nThat concludes the review."

    assert CheckerAgent._parse_verdict(response).verdict == Verdict.PASS


def test_ignores_unrelated_json_without_verdict():
    response = 'For reference the entry looks like {"a": 1}.\n```json\n' + _VERDICT_JSON + "\n```"

    assert CheckerAgent._parse_verdict(response).verdict == Verdict.PASS


def test_last_verdict_wins():
    response = (
        'earlier guess:\n```json\n{"verdict": "FAIL", "summary": "wrong"}\n```\n'
        'final:\n```json\n{"verdict": "PASS", "summary": "right"}\n```'
    )

    verdict = CheckerAgent._parse_verdict(response)

    assert verdict.verdict == Verdict.PASS
    assert verdict.summary == "right"


def test_braces_inside_strings_do_not_break_scanning():
    response = 'the log printed "}"\n' + json.dumps({"verdict": "FAIL", "summary": "keep { and } literal"})

    verdict = CheckerAgent._parse_verdict(response)

    assert verdict.verdict == Verdict.FAIL
    assert verdict.summary == "keep { and } literal"


def test_text_format_still_parses():
    response = "VERDICT: PASS\nSUMMARY: looks right\nISSUES:\n- none\n"

    verdict = CheckerAgent._parse_verdict(response)

    assert verdict.verdict == Verdict.PASS
    assert verdict.summary == "looks right"
    assert verdict.issues == []


@pytest.mark.parametrize("raw_verdict, expected", [
    ("PASS", Verdict.PASS),
    (" pass \t", Verdict.PASS),
    ("Correct", Verdict.PASS),
    ("OK", Verdict.PASS),
    ("good", Verdict.PASS),
    (" verified ", Verdict.PASS),
    ("FAIL", Verdict.FAIL),
    (" fail \t", Verdict.FAIL),
    ("Incorrect", Verdict.FAIL),
    ("wrong", Verdict.FAIL),
])
@pytest.mark.parametrize("format_", ["json", "text"])
def test_normalizes_verdict_aliases(raw_verdict: str, expected: Verdict, format_: str) -> None:
    if format_ == "json":
        response = json.dumps({"verdict": raw_verdict, "summary": "reviewed", "issues": ["detail"]})
    else:
        response = f"VERDICT: {raw_verdict}\nSUMMARY: reviewed\nISSUES:\n- detail\n"

    verdict = CheckerAgent._parse_verdict(response)

    assert expected == verdict.verdict
    assert verdict.summary == "reviewed"
    assert verdict.issues == ["detail"]


@pytest.mark.parametrize("raw_verdict", [
    "maybe", "UNKNOWN", "PASS or FAIL", "not correct", "", "PASSENGER", "FAILING",
    None, True, False, 1, ["PASS"], {"value": "PASS"},
])
def test_invalid_json_verdict_reports_protocol_error(raw_verdict: object) -> None:
    response = json.dumps({"verdict": raw_verdict, "issues": []})

    with pytest.raises(ValueError) as exc:
        CheckerAgent._parse_verdict(response)

    assert f"Checker protocol error: expected PASS/FAIL, got {raw_verdict!r}" == str(exc.value)


@pytest.mark.parametrize("raw_verdict", ["maybe", "UNKNOWN", "PASS or FAIL", "PASSENGER", "FAILING", ""])
def test_invalid_text_verdict_reports_complete_value(raw_verdict: str) -> None:
    response = f"VERDICT: {raw_verdict}\nSUMMARY: reviewed\n"

    with pytest.raises(ValueError) as exc:
        CheckerAgent._parse_verdict(response)

    assert f"Checker protocol error: expected PASS/FAIL, got {raw_verdict!r}" == str(exc.value)


@pytest.mark.parametrize("response", ["", "no structured verdict here", "{}", '{"issues": []}'])
def test_missing_verdict_reports_protocol_error(response: str) -> None:
    with pytest.raises(ValueError, match="expected PASS/FAIL, got .*missing verdict"):
        CheckerAgent._parse_verdict(response)


def test_invalid_final_verdict_does_not_fall_back_to_earlier_pass() -> None:
    response = '{"verdict": "PASS"}\nFinal review:\n{"verdict": "maybe"}'

    with pytest.raises(ValueError, match="expected PASS/FAIL, got 'maybe'"):
        CheckerAgent._parse_verdict(response)
