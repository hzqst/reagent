"""Checker verdict parsing, including prose-wrapped and fenced JSON replies."""
from __future__ import annotations

import json

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


def test_unparseable_response_is_unknown():
    assert CheckerAgent._parse_verdict("no structured verdict here").verdict == Verdict.UNKNOWN
