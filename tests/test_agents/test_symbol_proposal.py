"""Symbol proposal parsing from reverser and checker responses."""
from __future__ import annotations

import json

from re_agent.agents.checker import CheckerAgent
from re_agent.agents.reverser import ReverserAgent


def _response_with_symbol(symbol_json: str, *, whole: bool = False) -> str:
    if whole:
        return symbol_json
    return (
        "```cpp\nvoid f() {}\n```\n\n"
        "REVERSED_FUNCTION: TechnoClass::sub_70E000 (0x70E000)\n\n"
        "```json\n" + symbol_json + "\n```\n"
    )


def test_parses_fenced_json_block():
    symbol_json = (
        '{"symbol": {"name": "TechnoClass::Decay_70E000", "comment": "cooldown",'
        ' "confidence": "verified", "evidence": ["0x70DF6E"],'
        ' "struct_changes": [{"struct": "TechnoClass", "member": "Audio4",'
        ' "operation": "move", "offset": "0x4A4", "type": "AudioController"}]}}'
    )
    symbol = ReverserAgent._extract_symbol(_response_with_symbol(symbol_json))

    assert symbol is not None
    assert symbol.name == "TechnoClass::Decay_70E000"
    assert symbol.comment == "cooldown"
    assert symbol.confidence == "verified"
    assert symbol.evidence == ["0x70DF6E"]
    assert len(symbol.struct_changes) == 1
    change = symbol.struct_changes[0]
    assert (change.struct_name, change.member, change.operation) == ("TechnoClass", "Audio4", "move")
    assert change.offset == "0x4A4"
    assert change.type_str == "AudioController"


def test_parses_whole_response_json():
    response = '{"code": "void f() {}", "reversed_function": "A::b", "symbol": {"name": "A::B"}}'
    symbol = ReverserAgent._extract_symbol(_response_with_symbol(response, whole=True))

    assert symbol is not None and symbol.name == "A::B"


def test_json_block_does_not_leak_into_code():
    """The code extractor must ignore the ```json block."""
    response = "```cpp\nvoid f() {}\n```\n```json\n{\"symbol\": {\"name\": \"N\"}}\n```\n"

    assert ReverserAgent._extract_code(response) == "void f() {}"


def test_absent_symbol_returns_none():
    assert ReverserAgent._extract_symbol("```cpp\nvoid f() {}\n```") is None
    assert ReverserAgent._extract_symbol('{"symbol": {}}') is None


def test_evidence_request_is_not_a_proposal():
    assert ReverserAgent._extract_symbol('{"actions":[{"tool":"decompile","target":"0x1"}]}') is None


def test_unrecognised_confidence_stays_conservative():
    symbol = ReverserAgent._extract_symbol('{"symbol": {"name": "N", "confidence": "high"}}')

    assert symbol is not None and symbol.confidence == "inferred"


def test_malformed_struct_changes_are_dropped():
    symbol = ReverserAgent._extract_symbol(
        '{"symbol": {"name": "N", "struct_changes": [{"struct": "T"}, "junk",'
        ' {"struct": "T", "member": "m", "operation": "teleport"}]}}'
    )

    assert symbol is not None and symbol.struct_changes == []


def test_checker_parses_symbol_issues():
    response = json.dumps(
        {
            "verdict": "PASS",
            "summary": "ok",
            "issues": [],
            "fix_instructions": [],
            "symbol_issues": ["name contradicts offset 0x4A4"],
        }
    )
    verdict = CheckerAgent._parse_verdict(response)

    assert verdict.symbol_issues == ["name contradicts offset 0x4A4"]


def test_checker_defaults_symbol_issues_to_empty():
    verdict = CheckerAgent._parse_verdict('{"verdict": "PASS", "summary": "ok"}')

    assert verdict.symbol_issues == []
