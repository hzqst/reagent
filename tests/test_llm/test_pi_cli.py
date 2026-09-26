"""Pi transport regression tests; no account or model calls required."""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

from re_agent.llm.pi_cli import PiCLIProvider
from re_agent.llm.protocol import Message

# Pi session IDs must start and end with an alphanumeric character.
_SESSION_ID = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")


def test_large_unicode_prompt_uses_utf8_stdin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = tmp_path / "fake_pi.py"
    fake.write_text(
        "import sys\n"
        "prompt = sys.stdin.buffer.read().decode('utf-8')\n"
        "sys.stdout.buffer.write(prompt.encode('utf-8'))\n",
        encoding="utf-8",
    )
    run = subprocess.run
    captured: dict[str, object] = {}

    def invoke(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return run([sys.executable, str(fake), *args[1:]], **kwargs)

    monkeypatch.setattr("re_agent.llm.pi_cli.subprocess.run", invoke)
    content = "日本語 evidence & | > \" ' " * 5000
    expected = "[USER]\n" + content.strip()
    result = PiCLIProvider().send(
        [Message(role="system", content="be careful"), Message(role="user", content=content)]
    )

    args = captured["args"]
    assert isinstance(args, list)
    assert args[0] == "pi"
    assert "--print" in args
    assert "--no-session" in args
    assert "--session-id" not in args
    # A bare token right after --print would be consumed as the prompt; it must be a flag.
    assert args[args.index("--print") + 1].startswith("-")
    assert args[args.index("--append-system-prompt") + 1] == "be careful"
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["encoding"] == "utf-8"
    assert kwargs["input"] == expected
    assert result == expected


def test_resume_reuses_one_pi_session(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[list[str], str]] = []

    def invoke(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        prompt = kwargs["input"]
        assert isinstance(prompt, str)
        calls.append((list(args), prompt))
        return subprocess.CompletedProcess(args, 0, "answer\n")

    monkeypatch.setattr("re_agent.llm.pi_cli.subprocess.run", invoke)
    provider = PiCLIProvider()
    conversation = provider.new_conversation("system prompt")
    assert _SESSION_ID.match(conversation)

    assert provider.resume(conversation, "first") == "answer\n"
    assert provider.resume(conversation, "second") == "answer\n"

    first_args, first_prompt = calls[0]
    second_args, second_prompt = calls[1]
    assert first_args[first_args.index("--session-id") + 1] == conversation
    assert second_args[second_args.index("--session-id") + 1] == conversation
    assert "--no-session" not in first_args
    assert first_prompt == "first"
    assert second_prompt == "second"
    # Pi rebuilds the system prompt per process, so it must be re-appended each turn.
    assert first_args[first_args.index("--append-system-prompt") + 1] == "system prompt"
    assert second_args[second_args.index("--append-system-prompt") + 1] == "system prompt"


def test_model_and_thinking_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def invoke(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(list(args))
        return subprocess.CompletedProcess(args, 0, "ok")

    monkeypatch.setattr("re_agent.llm.pi_cli.subprocess.run", invoke)

    PiCLIProvider().send([Message(role="user", content="x")])
    assert "--model" not in calls[0]
    assert "--thinking" not in calls[0]

    PiCLIProvider(model="sonnet:high", effort="high").send([Message(role="user", content="x")])
    assert calls[1][calls[1].index("--model") + 1] == "sonnet:high"
    assert calls[1][calls[1].index("--thinking") + 1] == "high"


@pytest.mark.parametrize("failure", ["timeout", "missing", "exit"])
def test_cli_failures_preserve_diagnostics(monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    def invoke(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if failure == "timeout":
            raise subprocess.TimeoutExpired(args, 7)
        if failure == "missing":
            raise FileNotFoundError("not installed")
        return subprocess.CompletedProcess(args, 1, "", "selected model requires authentication 診断")

    monkeypatch.setattr("re_agent.llm.pi_cli.subprocess.run", invoke)
    match = {"timeout": "timed out after 7s", "missing": "CLI not found", "exit": "exit code 1"}
    with pytest.raises(RuntimeError, match=match[failure]) as excinfo:
        PiCLIProvider(timeout_s=7).send([Message(role="user", content="test")])
    if failure == "exit":
        assert "診断" in str(excinfo.value)


def test_unknown_conversation_id_raises() -> None:
    with pytest.raises(KeyError, match="Unknown conversation ID"):
        PiCLIProvider().resume("missing", "request")
