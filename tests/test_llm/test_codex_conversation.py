"""Regression tests for Codex conversation recovery."""
from __future__ import annotations

import pytest

from re_agent.llm.codex_cli import CodexCLIProvider


def _record(provider, monkeypatch, responses):
    """Capture invocations; ``responses`` yields (text, thread_id) per call."""
    calls: list[tuple[list[str], str]] = []
    pending = list(responses)

    def invoke(args, prompt):
        calls.append((list(args), prompt))
        result = pending.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(provider, "_invoke", invoke)
    return calls


def test_resume_reuses_codex_session(monkeypatch):
    provider = CodexCLIProvider()
    conversation = provider.new_conversation("system")
    calls = _record(provider, monkeypatch, [("answer", "thread-1"), ("next answer", "thread-1")])

    assert provider.resume(conversation, "request") == "answer"
    opening_args, opening_prompt = calls[0]
    assert opening_args[1] == "exec"
    assert "resume" not in opening_args
    assert opening_prompt == "[SYSTEM]\nsystem\n\n[USER]\nrequest"

    assert provider.resume(conversation, "next") == "next answer"
    follow_args, follow_prompt = calls[1]
    assert follow_args[1:4] == ["exec", "resume", "thread-1"]
    assert follow_prompt == "next"


def test_resume_args_keep_read_only_sandbox(monkeypatch):
    provider = CodexCLIProvider()
    conversation = provider.new_conversation("system")
    calls = _record(provider, monkeypatch, [("answer", "thread-1"), ("more", "thread-1")])
    provider.resume(conversation, "request")
    provider.resume(conversation, "next")

    opening_args = calls[0][0]
    assert "-s" in opening_args
    assert opening_args[opening_args.index("-s") + 1] == "read-only"

    follow_args = calls[1][0]
    assert "sandbox_mode=read-only" in follow_args
    assert "--skip-git-repo-check" in follow_args


def test_failed_turn_does_not_duplicate_prompt_on_retry(monkeypatch):
    provider = CodexCLIProvider()
    conversation = provider.new_conversation("system")
    calls = _record(
        provider,
        monkeypatch,
        [RuntimeError("CLI unavailable"), ("answer", "thread-1"), ("next", "thread-1")],
    )

    with pytest.raises(RuntimeError, match="CLI unavailable"):
        provider.resume(conversation, "request")
    assert provider.resume(conversation, "request") == "answer"

    # The failed turn recorded no session, so the retry replays the same prompt.
    assert calls[0] == calls[1]

    provider.resume(conversation, "next")
    assert calls[2][1] == "next"


def test_missing_thread_id_replays_transcript(monkeypatch):
    provider = CodexCLIProvider()
    conversation = provider.new_conversation("system")
    calls = _record(provider, monkeypatch, [("answer", None), ("next answer", None)])

    provider.resume(conversation, "one")
    provider.resume(conversation, "two")

    assert calls[1][1] == "[SYSTEM]\nsystem\n\n[USER]\none\n\n[ASSISTANT]\nanswer\n\n[USER]\ntwo"


def test_unknown_conversation_id_raises():
    with pytest.raises(KeyError, match="Unknown conversation ID"):
        CodexCLIProvider().resume("missing", "request")


@pytest.mark.parametrize(
    "stdout",
    [
        '{"type":"thread.started","thread_id":"abc-123"}\n{"type":"turn.completed"}\n',
        'warning: config drift\n{"type":"thread.started","thread_id":"abc-123"}\n',
        '{"type":"turn.started"}\n{"type":"thread.started","thread_id":"abc-123"}\n',
    ],
)
def test_extract_thread_id(stdout):
    from re_agent.llm.codex_cli import _extract_thread_id

    assert _extract_thread_id(stdout) == "abc-123"


@pytest.mark.parametrize(
    "stdout",
    ["", "diagnostic ✓", '{"type":"turn.completed"}\n', '{"type":"thread.started"}\n'],
)
def test_extract_thread_id_absent(stdout):
    from re_agent.llm.codex_cli import _extract_thread_id

    assert _extract_thread_id(stdout) is None
