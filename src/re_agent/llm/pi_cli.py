"""Pi coding agent CLI provider using an existing Pi login and configuration."""
from __future__ import annotations

import subprocess
import uuid
from dataclasses import dataclass
from typing import Any

from re_agent.llm.protocol import Message


@dataclass
class _Conversation:
    """A conversation backed by a Pi-native session.

    Attributes:
        system: System-level instruction. Pi rebuilds the system prompt from CLI
            flags on every process start, so it is re-appended on each turn
            instead of being stored in the session.
    """

    system: str


class PiCLIProvider:
    """LLM provider backed by the local ``pi --print`` coding agent CLI."""

    def __init__(
        self,
        model: str = "",
        timeout_s: int = 1800,
        pi_bin: str = "pi",
        effort: str | None = None,
    ) -> None:
        self._model = model
        self._timeout_s = timeout_s
        self._pi_bin = pi_bin
        self._effort = effort
        self._conversations: dict[str, _Conversation] = {}

    def send(self, messages: list[Message], **kwargs: Any) -> str:
        system = "\n\n".join(m.content for m in messages if m.role == "system")
        prompt = self._render_messages([m for m in messages if m.role != "system"])
        return self._run(prompt, system=system or None, model=kwargs.get("model"), session_id=None)

    @property
    def supports_conversations(self) -> bool:
        return True

    def new_conversation(self, system: str) -> str:
        # Reuse the conversation ID as the Pi session ID: ``--session-id`` opens it
        # if it exists and creates it otherwise, so every turn resumes the same one.
        conversation_id = uuid.uuid4().hex
        self._conversations[conversation_id] = _Conversation(system=system)
        return conversation_id

    def resume(self, conversation_id: str, message: str) -> str:
        conversation = self._conversations.get(conversation_id)
        if conversation is None:
            raise KeyError(f"Unknown conversation ID: {conversation_id}")
        return self._run(
            message, system=conversation.system, model=None, session_id=conversation_id
        )

    def _run(
        self,
        prompt: str,
        *,
        system: str | None,
        model: Any,
        session_id: str | None,
    ) -> str:
        # Every flag starts with ``-`` because a bare token right after ``--print``
        # is consumed as the prompt; the prompt itself travels over stdin instead.
        cmd = [self._pi_bin, "--print"]
        cmd.extend(["--session-id", session_id] if session_id is not None else ["--no-session"])
        selected_model = str(model or self._model)
        if selected_model:
            cmd.extend(["--model", selected_model])
        if self._effort is not None:
            cmd.extend(["--thinking", self._effort])
        if system:
            # Append rather than replace Pi's default prompt so the enabled tools
            # keep their usage guidance.
            cmd.extend(["--append-system-prompt", system])

        try:
            proc = subprocess.run(
                cmd,
                input=prompt,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=self._timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"pi CLI timed out after {self._timeout_s}s") from exc
        except FileNotFoundError as exc:
            raise RuntimeError(f"Pi CLI not found: {self._pi_bin}") from exc

        if proc.returncode != 0:
            detail = proc.stderr.strip() or proc.stdout.strip()
            raise RuntimeError(f"pi CLI failed with exit code {proc.returncode}\n{detail}")
        return proc.stdout

    @staticmethod
    def _render_messages(messages: list[Message]) -> str:
        return "\n\n".join(f"[{m.role.upper()}]\n{m.content.strip()}" for m in messages).strip()
