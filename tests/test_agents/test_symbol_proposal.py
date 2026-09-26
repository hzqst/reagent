"""Symbol proposal parsing from reverser and checker responses."""
from __future__ import annotations

import json
from dataclasses import replace

import pytest

from re_agent.agents.checker import CheckerAgent
from re_agent.agents.loop import run_fix_loop
from re_agent.agents.reverser import ReverserAgent
from re_agent.backend.stub import StubBackend
from re_agent.config.schema import ProjectProfile
from re_agent.core.models import FunctionTarget
from tests.test_agents.test_loop import MockLLM
from tests.test_agents.test_source_context import RecordingLLM


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


OLD = "void *__thiscall(void *this)"
NEW = "void *__thiscall f(FileClass *this);"


class PrototypeBackend(StubBackend):
    def decompile(self, target):
        return replace(super().decompile(target), signature=OLD, signature_source="database")


def prototype_response():
    return json.dumps({"code": "void f() {}", "symbol": {"name": "f", "prototype": {
        "declaration": NEW, "expected_current": "invented by reverser",
        "confidence": "verified", "evidence": ["header:12; matching address"],
        "review_status": "approved",
    }}})


@pytest.mark.parametrize("review", [None, {}, {"status": "approved"},
    {"status": ["approved"], "declaration": NEW},
    {"status": "approved", "declaration": NEW, "notes": "not a list"},
    {"status": "approved", "declaration": "different"},
])
def test_missing_malformed_or_unbound_review_never_approves(review):
    result = run_fix_loop(
        FunctionTarget("0x4A3890", "FileClass", "f"), PrototypeBackend(),
        MockLLM([prototype_response()]), MockLLM([json.dumps({"verdict": "PASS", "prototype_review": review})]),
        max_rounds=1, investigation_enabled=False, objective_verifier_enabled=False,
    )
    assert result.symbol.prototype.review_status == "unreviewed"
    assert result.symbol.prototype.expected_current == OLD


def test_bound_independent_review_approves_final_prototype():
    result = run_fix_loop(
        FunctionTarget("0x4A3890", "FileClass", "f"), PrototypeBackend(),
        MockLLM([prototype_response()]), MockLLM([json.dumps({"verdict": "PASS", "prototype_review": {
            "status": "approved", "declaration": NEW, "notes": ["Matches header and ABI"],
        }})]), max_rounds=1, investigation_enabled=False, objective_verifier_enabled=False,
    )
    assert result.symbol.prototype.review_status == "approved"
    assert result.symbol.prototype.expected_current == OLD
    assert result.symbol.prototype.review_notes == ["Matches header and ABI"]


def test_fix_round_does_not_inherit_prototype_approval():
    result = run_fix_loop(
        FunctionTarget("0x4A3890", "FileClass", "f"), PrototypeBackend(),
        MockLLM([prototype_response(), prototype_response()]), MockLLM([
            json.dumps({"verdict": "FAIL", "issues": ["fix code"], "prototype_review": {
                "status": "approved", "declaration": NEW, "notes": [],
            }}),
            json.dumps({"verdict": "PASS"}),
        ]), max_rounds=2, investigation_enabled=False, objective_verifier_enabled=False,
    )
    assert result.rounds_used == 2
    assert result.symbol.prototype.review_status == "unreviewed"
    assert result.symbol.prototype.expected_current == OLD


def test_checker_receives_actual_source_evidence(tmp_path):
    header = tmp_path / "FileClass.h"
    header.write_text("class FileClass { public: void *f(); }; // function address 0x4A3890\n")
    checker = RecordingLLM('{"verdict":"PASS"}')
    run_fix_loop(
        FunctionTarget("0x4A3890", "FileClass", "f"), PrototypeBackend(),
        MockLLM([prototype_response()]), checker, max_rounds=1,
        source_root=tmp_path, project_profile=ProjectProfile(source_root=str(tmp_path), hooks_csv=None),
        investigation_enabled=False, objective_verifier_enabled=False,
    )
    assert str(header) in checker.messages[-1].content
    assert "void *f();" in checker.messages[-1].content
