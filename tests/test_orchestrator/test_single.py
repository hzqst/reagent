"""Tests for single function orchestrator."""
from __future__ import annotations

import logging
from pathlib import Path

import pytest

from re_agent.backend.stub import StubBackend
from re_agent.config.schema import ReAgentConfig
from re_agent.core.models import FunctionTarget, ParityStatus, SymbolProposal, Verdict
from re_agent.core.symbols import record_symbol, symbols_path
from re_agent.llm.protocol import Message
from re_agent.orchestrator.single import reverse_single


class _LLM:
    def __init__(self, response: str) -> None:
        self.response = response

    def send(self, messages: list[Message], **kwargs: object) -> str:
        return self.response

    @property
    def supports_conversations(self) -> bool:
        return False

    def new_conversation(self, system: str) -> str:
        return ""

    def resume(self, conversation_id: str, message: str) -> str:
        return self.response


def test_dry_run_smoke() -> None:
    """Smoke test that config + target creation works."""
    config = ReAgentConfig.create_default()
    target = FunctionTarget(
        address="0x6F86A0",
        class_name="CTrain",
        function_name="ProcessControl",
    )
    assert target.address == "0x6F86A0"
    assert config.orchestrator.max_review_rounds == 4


def test_checker_protocol_error_is_reported_to_caller(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    config = ReAgentConfig.create_default()
    config.project_profile.source_root = str(tmp_path / "source")
    config.output.report_dir = str(tmp_path / "reports")
    config.output.log_dir = str(tmp_path / "logs")
    config.orchestrator.investigation_enabled = False

    result = reverse_single(
        FunctionTarget("0x100", "CTest", "Foo"),
        config,
        StubBackend(),
        _LLM("```cpp\nvoid CTest::Foo() {}\n```"),
        checker_llm=_LLM('{"verdict": "maybe", "issues": []}'),
    )

    assert not result.success
    assert result.error == "Checker protocol error: expected PASS/FAIL, got 'maybe'"
    assert result.checker_verdict is None
    assert "No symbol proposal" not in caplog.text


def test_candidate_parity_is_blocking_and_uses_generated_body(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "CTest.cpp").write_text(
        "void CTest::Foo() { ExistingImplementation(); }\n",
        encoding="utf-8",
    )
    config = ReAgentConfig.create_default()
    config.project_profile.source_root = str(source_root)
    config.output.report_dir = str(tmp_path / "reports")
    config.output.log_dir = str(tmp_path / "logs")
    config.output.session_file = str(tmp_path / "session.json")
    config.orchestrator.max_review_rounds = 1
    config.orchestrator.investigation_enabled = False

    reverser = _LLM(
        "```cpp\nvoid CTest::Foo() { NOTSA_UNREACHABLE(); }\n```\n"
        "REVERSED_FUNCTION: CTest::Foo (0x100)"
    )
    checker = _LLM(
        "VERDICT: PASS\nSUMMARY: Looks right\nISSUES:\n- none\n"
        "FIX_INSTRUCTIONS:\n- none"
    )
    result = reverse_single(
        FunctionTarget("0x100", "CTest", "Foo"),
        config,
        StubBackend(),
        reverser,
        checker_llm=checker,
    )

    assert result.parity_status == ParityStatus.RED
    assert result.validation_verdict is not None
    assert result.validation_verdict.verdict == Verdict.UNKNOWN
    assert result.success is False


def test_unknown_validation_blocks_acceptance_by_default(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "CTest.cpp").write_text(
        "void CTest::Foo() { ExistingImplementation(); }\n",
        encoding="utf-8",
    )
    config = ReAgentConfig.create_default()
    config.project_profile.source_root = str(source_root)
    config.output.report_dir = str(tmp_path / "reports")
    config.output.log_dir = str(tmp_path / "logs")
    config.orchestrator.max_review_rounds = 1
    config.orchestrator.investigation_enabled = False
    config.parity.enabled = False

    result = reverse_single(
        FunctionTarget("0x100", "CTest", "Foo"),
        config,
        StubBackend(),
        _LLM("```cpp\nvoid CTest::Foo() { NewImplementation(); }\n```"),
        checker_llm=_LLM(
            "VERDICT: PASS\nSUMMARY: Looks right\nISSUES:\n- none\n"
            "FIX_INSTRUCTIONS:\n- none"
        ),
    )

    assert result.validation_verdict is not None
    assert result.validation_verdict.verdict == Verdict.UNKNOWN
    assert result.success is False
    assert "No symbol proposal for 0x100" in caplog.text


def test_candidate_with_leading_types_succeeds_when_checker_passes(tmp_path: Path) -> None:
    """Regression for #13: a PASS candidate with leading types is not rejected."""
    config = ReAgentConfig.create_default()
    config.project_profile.source_root = str(tmp_path / "empty")
    config.output.report_dir = str(tmp_path / "reports")
    config.output.log_dir = str(tmp_path / "logs")
    config.orchestrator.max_review_rounds = 1
    config.orchestrator.investigation_enabled = False
    config.orchestrator.objective_verifier_enabled = False
    config.parity.enabled = False
    config.validation.enabled = False

    code = (
        "```cpp\n"
        "struct M { float row[3][4]; };\n"
        "M *__stdcall C::F(void *this_, M *sret) { return sret; }\n"
        "```\n"
        "REVERSED_FUNCTION: C::F (0x100)"
    )
    result = reverse_single(
        FunctionTarget("0x100", "C", "F"),
        config,
        StubBackend(),
        _LLM(code),
        checker_llm=_LLM(
            "VERDICT: PASS\nSUMMARY: Looks right\nISSUES:\n- none\n"
            "FIX_INSTRUCTIONS:\n- none"
        ),
    )

    assert result.success is True
    assert result.validation_verdict is not None
    assert result.validation_verdict.overlay_file is not None
    assert Path(result.validation_verdict.overlay_file).exists()


@pytest.mark.parametrize("with_symbol, existing_symbol", [(False, False), (False, True), (True, False)])
def test_explicitly_disabled_validation_does_not_block(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    with_symbol: bool,
    existing_symbol: bool,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "CTest.cpp").write_text("void CTest::Foo() {}\n", encoding="utf-8")
    config = ReAgentConfig.create_default()
    config.project_profile.source_root = str(source_root)
    config.output.report_dir = str(tmp_path / "reports")
    config.output.log_dir = str(tmp_path / "logs")
    config.orchestrator.max_review_rounds = 1
    config.orchestrator.investigation_enabled = False
    config.orchestrator.objective_verifier_enabled = False
    config.parity.enabled = False
    config.validation.enabled = False

    proposal_path = symbols_path(Path(config.output.report_dir))
    old_proposals = b""
    if existing_symbol:
        record_symbol(proposal_path, "0x100", SymbolProposal(name="CTest::PreviousName"))
        old_proposals = proposal_path.read_bytes()
    response = "```cpp\nvoid CTest::Foo() {}\n```"
    if with_symbol:
        response += '\n```json\n{"symbol": {"name": "CTest::Foo"}}\n```'

    result = reverse_single(
        FunctionTarget("0x100", "CTest", "Foo"),
        config,
        StubBackend(),
        _LLM(response),
        checker_llm=_LLM(
            "VERDICT: PASS\nSUMMARY: Looks right\nISSUES:\n- none\n"
            "FIX_INSTRUCTIONS:\n- none"
        ),
    )

    assert result.validation_verdict is not None
    assert result.validation_verdict.verdict == Verdict.UNKNOWN
    assert result.success is True
    warnings = [record for record in caplog.records if "No symbol proposal" in record.getMessage()]
    if with_symbol:
        assert warnings == []
        assert result.symbol is not None
        assert result.symbol.name == "CTest::Foo"
    else:
        assert result.symbol is None
        assert len(warnings) == 1
        assert warnings[0].levelno == logging.WARNING
        message = warnings[0].getMessage()
        assert "0x100" in message
        assert str(proposal_path) in message
        assert "not updated for this function" in message
        assert "reverser response" in message
        assert "annotate" in message
        if existing_symbol:
            assert old_proposals == proposal_path.read_bytes()
        else:
            assert not proposal_path.exists()
