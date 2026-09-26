"""Tests for the subscription-backed Claude Code CLI provider."""
from __future__ import annotations

import json
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from re_agent.llm.claude_cli import ClaudeCLIProvider
from re_agent.llm.protocol import Message


def _completed(session_id: str = "session-1") -> CompletedProcess[str]:
    payload = {
        "result": "generated code",
        "session_id": session_id,
        "total_cost_usd": 0.12,
        "duration_ms": 42,
        "usage": {"input_tokens": 10, "output_tokens": 4},
    }
    return CompletedProcess(["claude"], 0, stdout=json.dumps(payload), stderr="")


def test_claude_cli_send_parses_result_and_usage() -> None:
    provider = ClaudeCLIProvider(model="sonnet", max_budget_usd=1.5, effort="high")
    with patch("re_agent.llm.claude_cli.subprocess.run", return_value=_completed()) as run:
        result = provider.send([
            Message(role="system", content="system"),
            Message(role="user", content="reverse this"),
        ])

    assert result == "generated code"
    assert provider.last_metadata.cost_usd == 0.12
    command = run.call_args.args[0]
    assert "--tools" in command
    assert "--bare" not in command
    assert "--max-budget-usd" in command
    assert "--system-prompt" in command


def test_claude_cli_uses_real_session_resume() -> None:
    provider = ClaudeCLIProvider()
    conversation_id = provider.new_conversation("system")
    with patch("re_agent.llm.claude_cli.subprocess.run", return_value=_completed()) as run:
        provider.resume(conversation_id, "first")
        first = run.call_args.args[0]
        provider.resume(conversation_id, "second")
        second = run.call_args.args[0]

    assert "--session-id" in first
    assert "--resume" in second


def test_claude_cli_surfaces_structured_error() -> None:
    payload = json.dumps({"is_error": True, "result": "Not logged in", "session_id": "s"})
    completed = CompletedProcess(["claude"], 1, stdout=payload, stderr="")
    provider = ClaudeCLIProvider()
    with (
        patch("re_agent.llm.claude_cli.subprocess.run", return_value=completed),
        pytest.raises(RuntimeError, match="Not logged in"),
    ):
        provider.send([Message(role="user", content="hello")])


def test_runner_prompt_file_appends_and_excludes_memory(tmp_path: Path) -> None:
    runner_prompt = tmp_path / "SKILL_RUNNER.md"
    runner_prompt.write_text("runner conventions", encoding="utf-8")
    provider = ClaudeCLIProvider(runner_prompt_file=str(runner_prompt))
    with patch("re_agent.llm.claude_cli.subprocess.run", return_value=_completed()) as run:
        provider.send([
            Message(role="system", content="system"),
            Message(role="user", content="reverse this"),
        ])

    command = run.call_args.args[0]
    assert command[command.index("--append-system-prompt-file") + 1] == str(runner_prompt)
    settings = json.loads(command[command.index("--settings") + 1])
    assert settings["claudeMdExcludes"] == [".claude/CLAUDE.md", "CLAUDE.md", "AGENTS.md"]


def test_runner_prompt_file_is_absent_by_default() -> None:
    provider = ClaudeCLIProvider()
    with patch("re_agent.llm.claude_cli.subprocess.run", return_value=_completed()) as run:
        provider.send([Message(role="user", content="reverse this")])

    command = run.call_args.args[0]
    assert "--append-system-prompt-file" not in command
    assert "--settings" not in command


def test_runner_prompt_file_not_reappended_on_resume(tmp_path: Path) -> None:
    runner_prompt = tmp_path / "SKILL_RUNNER.md"
    runner_prompt.write_text("runner conventions", encoding="utf-8")
    provider = ClaudeCLIProvider(runner_prompt_file=str(runner_prompt))
    conversation_id = provider.new_conversation("system")
    with patch("re_agent.llm.claude_cli.subprocess.run", return_value=_completed()) as run:
        provider.resume(conversation_id, "first")
        first = run.call_args.args[0]
        provider.resume(conversation_id, "second")
        second = run.call_args.args[0]

    # The opening turn carries the runner prompt; the session keeps it, but the
    # memory exclusion has to be re-applied because each turn is a new process.
    assert "--append-system-prompt-file" in first
    assert "--append-system-prompt-file" not in second
    assert "--settings" in first
    assert "--settings" in second
