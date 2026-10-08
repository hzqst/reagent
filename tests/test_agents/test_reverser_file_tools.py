"""Opt-in host-side file tools for the reverser: confinement and budget."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from re_agent.agents.reverser import ReverserAgent
from re_agent.backend.stub import StubBackend
from re_agent.core.models import FunctionTarget
from re_agent.llm.protocol import Message
from re_agent.recovery import files


class _ScriptedLLM:
    """Replays a fixed list of responses, repeating the last one when exhausted."""

    def __init__(self, responses: list[str]) -> None:
        self._responses = list(responses)
        self.calls = 0
        self.messages: list[str] = []

    def _next(self, prompt: str) -> str:
        self.calls += 1
        self.messages.append(prompt)
        return self._responses[min(self.calls - 1, len(self._responses) - 1)]

    def send(self, messages: list[Message], **kwargs: Any) -> str:
        return self._next(messages[-1].content)

    @property
    def supports_conversations(self) -> bool:
        return False

    def new_conversation(self, system: str) -> str:
        return ""

    def resume(self, conversation_id: str, message: str) -> str:
        return self._next(message)


def _root(tmp_path: Path) -> Path:
    refs = tmp_path / "refs"
    refs.mkdir()
    (refs / "a.h").write_text("struct A { int x; };\n// needle\n", encoding="utf-8")
    (refs / "sub").mkdir()
    (refs / "sub" / "b.cpp").write_text("void A::Tick() {}\n// needle\n", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("do not read me\n", encoding="utf-8")
    return refs.resolve()


def test_no_file_tools_are_advertised_without_roots() -> None:
    """Unconfigured must stay byte-for-byte the old prompt."""
    reverser = ReverserAgent(_ScriptedLLM([]), StubBackend(), max_file_calls=5)

    prompt = reverser._system_prompt()

    for tool in ("`read`", "`grep`", "`glob`"):
        assert tool not in prompt
    assert reverser._file_tool_names() == []


def test_no_file_tools_when_the_budget_is_zero(tmp_path: Path) -> None:
    """Roots alone are not enough; a zero budget withdraws the tools too."""
    reverser = ReverserAgent(_ScriptedLLM([]), StubBackend(), file_roots=[_root(tmp_path)], max_file_calls=0)

    assert reverser._file_tool_names() == []
    assert "`grep`" not in reverser._system_prompt()


def test_file_tools_withdrawn_when_the_loop_is_disabled(tmp_path: Path) -> None:
    """``investigation_enabled`` is the master switch for the request loop."""
    reverser = ReverserAgent(
        _ScriptedLLM([]),
        StubBackend(),
        file_roots=[_root(tmp_path)],
        max_file_calls=3,
        investigation_enabled=False,
    )

    assert reverser._file_tool_names() == []


def test_configured_roots_advertise_the_tools(tmp_path: Path) -> None:
    root = _root(tmp_path)
    reverser = ReverserAgent(_ScriptedLLM([]), StubBackend(), file_roots=[root], max_file_calls=3)

    prompt = reverser._system_prompt()

    assert reverser._file_tool_names() == ["glob", "grep", "read"]
    for tool in ("`read`", "`grep`", "`glob`"):
        assert tool in prompt
    assert str(root) in prompt
    # The object-shaped argument contract has to be spelled out; the existing
    # example only shows the plain-address backend tools.
    assert '"arguments"' in prompt


def test_grep_request_is_dispatched_host_side(tmp_path: Path) -> None:
    root = _root(tmp_path)
    llm = _ScriptedLLM(
        [
            '{"actions":[{"tool":"grep","arguments":{"pattern":"needle","include":"*.cpp"}}]}',
            "```cpp\nvoid A::Tick() {}\n```",
        ]
    )
    reverser = ReverserAgent(llm, StubBackend(), file_roots=[root], max_file_calls=3)

    code, _ = reverser.reverse(FunctionTarget("0x100", "A", "Tick"))

    assert "void A::Tick" in code
    assert "b.cpp" in llm.messages[-1]
    assert "a.h" not in llm.messages[-1]  # the include glob kept the .h out
    assert "1 of 3" in llm.messages[-1]


def test_read_request_pages_a_file(tmp_path: Path) -> None:
    root = _root(tmp_path)
    llm = _ScriptedLLM(
        [
            '{"actions":[{"tool":"read","arguments":{"path":"a.h","offset":0,"limit":1}}]}',
            "```cpp\nstruct A {};\n```",
        ]
    )
    reverser = ReverserAgent(llm, StubBackend(), file_roots=[root], max_file_calls=3)

    reverser.reverse(FunctionTarget("0x100", "A", "Tick"))

    assert "struct A { int x; };" in llm.messages[-1]
    assert "total_lines" in llm.messages[-1]


def test_path_outside_every_root_is_reported_and_not_charged(tmp_path: Path) -> None:
    """A refused request is not evidence, so it must not cost a file slot."""
    root = _root(tmp_path)
    llm = _ScriptedLLM(
        [
            '{"actions":[{"tool":"read","arguments":{"path":"../secret.txt"}}]}',
            "```cpp\nvoid A::Tick() {}\n```",
        ]
    )
    reverser = ReverserAgent(llm, StubBackend(), file_roots=[root], max_file_calls=1)

    code, _ = reverser.reverse(FunctionTarget("0x100", "A", "Tick"))

    assert "void A::Tick" in code
    assert "not found under any reference root" in llm.messages[-1]
    # The budget was 1, the only request was refused, so a correction round fit.
    assert "0 of 1" in llm.messages[-1]


def test_file_calls_do_not_consume_the_investigation_budget(tmp_path: Path) -> None:
    """Source lookup must never crowd out binary evidence."""
    root = _root(tmp_path)
    llm = _ScriptedLLM(
        [
            '{"actions":[{"tool":"grep","arguments":{"pattern":"needle"}}]}',
            "```cpp\nvoid A::Tick() {}\n```",
        ]
    )
    reverser = ReverserAgent(llm, StubBackend(), max_investigations=1, file_roots=[root], max_file_calls=3)

    reverser.reverse(FunctionTarget("0x100", "A", "Tick"))

    assert "Evidence requests used: 0 of 1" in llm.messages[-1]
    assert "File requests used: 1 of 3" in llm.messages[-1]


def test_file_budget_works_with_no_investigation_budget(tmp_path: Path) -> None:
    root = _root(tmp_path)
    llm = _ScriptedLLM(
        [
            '{"actions":[{"tool":"glob","arguments":{"pattern":"**/*.cpp"}}]}',
            "```cpp\nvoid A::Tick() {}\n```",
        ]
    )
    reverser = ReverserAgent(llm, StubBackend(), max_investigations=0, file_roots=[root], max_file_calls=2)

    code, _ = reverser.reverse(FunctionTarget("0x100", "A", "Tick"))

    assert "void A::Tick" in code
    assert "b.cpp" in llm.messages[-1]


def test_spent_file_budget_ends_the_loop(tmp_path: Path) -> None:
    root = _root(tmp_path)
    llm = _ScriptedLLM(['{"actions":[{"tool":"glob","arguments":{"pattern":"**/*.h"}}]}'])
    reverser = ReverserAgent(llm, StubBackend(), max_investigations=0, file_roots=[root], max_file_calls=1)

    with pytest.raises(RuntimeError, match="budget exhausted"):
        reverser.reverse(FunctionTarget("0x100", "A", "Tick"))


def test_spent_investigation_budget_still_serves_files(tmp_path: Path) -> None:
    """The loop must not end while file budget remains, even at the old cap."""
    root = _root(tmp_path)
    llm = _ScriptedLLM(
        [
            '{"actions":[{"tool":"decompile","target":"0x200"}]}',
            '{"actions":[{"tool":"grep","arguments":{"pattern":"needle"}}]}',
            "```cpp\nvoid A::Tick() {}\n```",
        ]
    )
    reverser = ReverserAgent(llm, StubBackend(), max_investigations=1, file_roots=[root], max_file_calls=2)

    code, _ = reverser.reverse(FunctionTarget("0x100", "A", "Tick"))

    assert "void A::Tick" in code
    # The decompile spent the whole investigation budget, yet the round still
    # went out for the following file request -- that is the whole point.
    assert "Evidence requests used: 1 of 1" in llm.messages[-1]
    assert "File requests used: 1 of 2" in llm.messages[-1]


def test_unknown_file_argument_path_is_reported(tmp_path: Path) -> None:
    """A malformed request is answered, not crashed on, and stays uncharged."""
    root = _root(tmp_path)
    llm = _ScriptedLLM(
        [
            '{"actions":[{"tool":"read","arguments":{}}]}',
            "```cpp\nvoid A::Tick() {}\n```",
        ]
    )
    reverser = ReverserAgent(llm, StubBackend(), file_roots=[root], max_file_calls=1)

    code, _ = reverser.reverse(FunctionTarget("0x100", "A", "Tick"))

    assert "void A::Tick" in code
    assert "path must be a non-empty string" in llm.messages[-1]


def test_resolve_roots_rejects_a_missing_directory(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a directory"):
        files.resolve_roots([str(tmp_path / "nope")])


def test_resolve_roots_is_relative_to_the_base(tmp_path: Path) -> None:
    (tmp_path / "source").mkdir()

    assert files.resolve_roots(["source"], base=tmp_path) == [(tmp_path / "source").resolve()]


def test_resolve_roots_deduplicates_preserving_order(tmp_path: Path) -> None:
    (tmp_path / "source").mkdir()

    resolved = files.resolve_roots(["source", "source"], base=tmp_path)

    assert resolved == [(tmp_path / "source").resolve()]
