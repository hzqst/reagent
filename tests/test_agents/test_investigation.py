"""Tests for model-requested read-only RE investigations."""
from __future__ import annotations

from typing import Any

import pytest

from re_agent.agents.reverser import ReverserAgent
from re_agent.backend.stub import StubBackend
from re_agent.core.models import FunctionTarget
from re_agent.llm.protocol import Message


class _ActionLLM:
    def __init__(self) -> None:
        self.calls = 0
        self.last_messages: list[Message] = []

    def send(self, messages: list[Message], **kwargs: object) -> str:
        self.calls += 1
        self.last_messages = list(messages)
        if self.calls == 1:
            return '{"actions":[{"tool":"decompile","target":"0x200"}]}'
        return "```cpp\nvoid CTest::Foo() { ResolvedCall(); }\n```"

    @property
    def supports_conversations(self) -> bool:
        return False

    def new_conversation(self, system: str) -> str:
        return ""

    def resume(self, conversation_id: str, message: str) -> str:
        return ""


def test_reverser_executes_bounded_read_only_action() -> None:
    llm = _ActionLLM()
    reverser = ReverserAgent(
        llm,
        StubBackend(),
        investigation_enabled=True,
        max_investigations=2,
    )
    code, _ = reverser.reverse(FunctionTarget("0x100", "CTest", "Foo"))
    assert llm.calls == 2
    assert "ResolvedCall" in code
    assert "TOOL decompile(0x200)" in llm.last_messages[-1].content


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


def test_system_prompt_offers_only_tools_the_backend_implements() -> None:
    """The prompt must not invite a request the backend can only answer with an error.

    Regression: the tool list was hardcoded, so a backend without P-code or
    vtable support was still asked for both, and each refusal still consumed a
    slot of the investigation budget.
    """
    prompt = ReverserAgent(_ScriptedLLM([]), StubBackend())._system_prompt()

    assert "`decompile`" in prompt and "`context`" in prompt
    for unsupported in ("`pcode`", "`vtable`", "`cfg`", "`global`", "`strings`"):
        assert unsupported not in prompt


def test_unsupported_tool_does_not_consume_budget() -> None:
    """A refused request is not evidence, so it must not cost the model a slot."""
    llm = _ScriptedLLM(
        [
            '{"actions":[{"tool":"pcode","target":"0x200"}]}',
            "```cpp\nvoid CTest::Foo() { ResolvedCall(); }\n```",
        ]
    )
    reverser = ReverserAgent(llm, StubBackend(), max_investigations=1)

    code, _ = reverser.reverse(FunctionTarget("0x100", "CTest", "Foo"))

    # The budget is 1 and the only request was refused, so a correction round
    # still fits; charging it would have ended the run with no candidate.
    assert llm.calls == 2
    assert "ResolvedCall" in code
    assert "unavailable on this backend" in llm.messages[-1]


def test_repeated_unsupported_requests_stay_bounded() -> None:
    """Rounds are capped independently, so uncharged requests cannot loop forever."""
    llm = _ScriptedLLM(['{"actions":[{"tool":"pcode","target":"0x200"}]}'])
    reverser = ReverserAgent(llm, StubBackend(), max_investigations=1)

    with pytest.raises(RuntimeError, match="budget exhausted"):
        reverser.reverse(FunctionTarget("0x100", "CTest", "Foo"))

    assert llm.calls == 2


def test_spent_budget_does_not_spend_another_model_call() -> None:
    """Regression: the loop resumed once more after the budget ran out.

    That reply could only be another evidence request, and it was discarded --
    a full model call whose result was never used.
    """
    llm = _ScriptedLLM(
        ['{"actions":[{"tool":"decompile","target":"0x200"},{"tool":"decompile","target":"0x201"}]}']
    )
    reverser = ReverserAgent(llm, StubBackend(), max_investigations=2)

    with pytest.raises(RuntimeError, match="budget exhausted"):
        reverser.reverse(FunctionTarget("0x100", "CTest", "Foo"))

    assert llm.calls == 1


def test_tool_message_states_the_remaining_budget() -> None:
    """The model gets an explicit cost signal instead of a bare 'remaining budget'."""
    llm = _ScriptedLLM(
        [
            '{"actions":[{"tool":"decompile","target":"0x200"}]}',
            "```cpp\nvoid CTest::Foo() { ResolvedCall(); }\n```",
        ]
    )
    reverser = ReverserAgent(llm, StubBackend(), max_investigations=3)

    reverser.reverse(FunctionTarget("0x100", "CTest", "Foo"))

    assert "1 of 3" in llm.messages[-1]
    assert "2 remaining" in llm.messages[-1]
