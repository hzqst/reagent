"""Codex transport regression tests; no account or model calls required."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from re_agent.config.schema import LLMConfig
from re_agent.llm.codex_cli import CodexCLIProvider
from re_agent.llm.protocol import Message
from re_agent.llm.registry import create_provider


def test_large_unicode_prompt_uses_utf8_stdin(tmp_path, monkeypatch):
    fake = tmp_path / "fake_codex.py"
    fake.write_text(
        "import pathlib, sys\n"
        "assert sys.argv[-1] == '-'\n"
        "prompt = sys.stdin.buffer.read().decode('utf-8')\n"
        "out = sys.argv[sys.argv.index('--output-last-message') + 1]\n"
        "pathlib.Path(out).write_bytes(prompt.encode('utf-8'))\n"
        "sys.stdout.buffer.write('\u8a3a\u65ad \u2713'.encode('utf-8'))\n",
        encoding="utf-8",
    )
    run = subprocess.run
    output_paths = []

    def invoke(args, **kwargs):
        assert sum(len(arg) for arg in args) < 4096
        assert kwargs.get("encoding") == "utf-8"
        assert kwargs.get("input") == expected
        output_paths.append(Path(args[args.index('--output-last-message') + 1]))
        return run([sys.executable, str(fake), *args[1:]], **kwargs)

    monkeypatch.setattr("re_agent.llm.codex_cli.subprocess.run", invoke)
    content = "\u65e5\u672c\u8a9e evidence & | > \" ' " * 5000
    expected = "[USER]\n" + content.strip()
    assert CodexCLIProvider().send([Message(role="user", content=content)]) == expected
    assert all(not path.exists() for path in output_paths)


@pytest.mark.parametrize("failure", ["model", "timeout", "missing"])
def test_cli_failures_preserve_diagnostics_and_clean_output(monkeypatch, failure):
    output_paths = []

    def invoke(args, **kwargs):
        output_paths.append(Path(args[args.index('--output-last-message') + 1]))
        if failure == "timeout":
            raise subprocess.TimeoutExpired(args, 7)
        if failure == "missing":
            raise FileNotFoundError("not installed")
        return subprocess.CompletedProcess(
            args, 1, "The selected model requires a newer version of Codex. \u8a3a\u65ad"
        )

    monkeypatch.setattr("re_agent.llm.codex_cli.subprocess.run", invoke)
    match = {"model": "requires a newer version", "timeout": "timed out after 7s", "missing": "CLI not found"}
    with pytest.raises(RuntimeError, match=match[failure]):
        CodexCLIProvider(timeout_s=7).send([Message(role="user", content="test")])
    assert all(not path.exists() for path in output_paths)


def _write_output(args, text="ok"):
    Path(args[args.index("--output-last-message") + 1]).write_text(text, encoding="utf-8")


def test_runner_prompt_file_suppresses_project_doc(tmp_path, monkeypatch):
    runner_prompt = tmp_path / "SKILL_RUNNER.md"
    runner_prompt.write_text('line one\nline two "quoted"', encoding="utf-8")
    calls = []

    def invoke(args, **kwargs):
        calls.append(list(args))
        _write_output(args)
        return subprocess.CompletedProcess(args, 0, "")

    monkeypatch.setattr("re_agent.llm.codex_cli.subprocess.run", invoke)
    CodexCLIProvider(runner_prompt_file=str(runner_prompt)).send(
        [Message(role="user", content="x")]
    )

    args = calls[0]
    assert args[1:4] == ["-c", 'project_doc_fallback_filenames=["REAGENT_RUNNER.md"]', "exec"]
    assert "project_doc_max_bytes=0" in args
    instruction_args = [arg for arg in args if arg.startswith("developer_instructions=")]
    assert len(instruction_args) == 1
    # The value travels as one argv element and must not contain a literal
    # newline, which TOML would reject inside an unquoted value.
    assert "\n" not in instruction_args[0]
    assert json.loads(instruction_args[0].split("=", 1)[1]) == runner_prompt.read_text(
        encoding="utf-8"
    )


def test_runner_prompt_file_applies_to_thread_resume(tmp_path, monkeypatch):
    runner_prompt = tmp_path / "SKILL_RUNNER.md"
    runner_prompt.write_text("runner conventions", encoding="utf-8")
    calls = []

    def invoke(args, **kwargs):
        calls.append(list(args))
        _write_output(args)
        return subprocess.CompletedProcess(
            args, 0, '{"type":"thread.started","thread_id":"thread-1"}\n'
        )

    monkeypatch.setattr("re_agent.llm.codex_cli.subprocess.run", invoke)
    provider = CodexCLIProvider(runner_prompt_file=str(runner_prompt))
    conversation_id = provider.new_conversation("system")
    provider.resume(conversation_id, "first")
    provider.resume(conversation_id, "second")

    assert "resume" in calls[1]
    for args in calls:
        assert args[1:4] == ["-c", 'project_doc_fallback_filenames=["REAGENT_RUNNER.md"]', "exec"]
        assert "project_doc_max_bytes=0" in args
        instruction_args = [arg for arg in args if arg.startswith("developer_instructions=")]
        assert json.loads(instruction_args[0].split("=", 1)[1]) == "runner conventions"


def test_runner_prompt_file_is_absent_by_default(monkeypatch):
    calls = []

    def invoke(args, **kwargs):
        calls.append(list(args))
        _write_output(args)
        return subprocess.CompletedProcess(args, 0, "")

    monkeypatch.setattr("re_agent.llm.codex_cli.subprocess.run", invoke)
    CodexCLIProvider().send([Message(role="user", content="x")])

    assert calls[0][1:4] == ["-c", 'project_doc_fallback_filenames=["REAGENT_RUNNER.md"]', "exec"]
    assert "project_doc_max_bytes=0" not in calls[0]
    assert not [arg for arg in calls[0] if arg.startswith("developer_instructions=")]


def test_effort_overrides_model_reasoning_effort(monkeypatch):
    calls = []

    def invoke(args, **kwargs):
        calls.append(list(args))
        _write_output(args)
        return subprocess.CompletedProcess(args, 0, '{"type":"thread.started","thread_id":"t1"}\n')

    monkeypatch.setattr("re_agent.llm.codex_cli.subprocess.run", invoke)
    provider = CodexCLIProvider(effort="xhigh")
    conversation_id = provider.new_conversation("system")
    provider.resume(conversation_id, "first")
    provider.resume(conversation_id, "second")

    # Effort rides on both the opening exec turn and the resume turn; an empty
    # value must leave Codex's configured default untouched.
    for args in calls:
        value = args[args.index("model_reasoning_effort=\"xhigh\"") - 1]
        assert value == "-c"


def test_effort_is_absent_by_default(monkeypatch):
    calls = []

    def invoke(args, **kwargs):
        calls.append(list(args))
        _write_output(args)
        return subprocess.CompletedProcess(args, 0, "")

    monkeypatch.setattr("re_agent.llm.codex_cli.subprocess.run", invoke)
    CodexCLIProvider().send([Message(role="user", content="x")])

    assert not [arg for arg in calls[0] if arg.startswith("model_reasoning_effort=")]


def test_registry_passes_effort_to_codex(monkeypatch):
    calls = []

    def invoke(args, **kwargs):
        calls.append(list(args))
        _write_output(args)
        return subprocess.CompletedProcess(args, 0, "")

    monkeypatch.setattr("re_agent.llm.codex_cli.subprocess.run", invoke)
    provider = create_provider(LLMConfig(provider="codex", model="gpt-5.4", effort="high"))
    provider.send([Message(role="user", content="x")])

    assert 'model_reasoning_effort="high"' in calls[0]
