"""Codex CLI-backed LLM provider using ChatGPT login credentials."""
from __future__ import annotations

import json
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from re_agent.llm.protocol import Message

SANDBOX_MODE = "read-only"


@dataclass
class _Conversation:
    """A conversation backed by a Codex-native session.

    Attributes:
        system: System-level instruction, sent with the opening turn.
        thread_id: Codex thread id, once the opening turn has recorded one.
        history: Committed turns, replayed only if no thread id is available.
    """

    system: str
    thread_id: str | None = None
    history: list[Message] = field(default_factory=list)


class CodexCLIProvider:
    """LLM provider backed by the local ``codex exec`` CLI."""

    def __init__(
        self,
        model: str = "gpt-5.4",
        timeout_s: int = 1800,
        codex_bin: str = "codex",
        runner_prompt_file: str | None = None,
    ) -> None:
        self._model = model
        self._timeout_s = timeout_s
        self._codex_bin = codex_bin
        # Read once: the config loader already refuses a missing file, and the
        # contents become an argv element on every invocation.
        self._runner_prompt = (
            Path(runner_prompt_file).read_text(encoding="utf-8")
            if runner_prompt_file is not None
            else None
        )
        self._conversations: dict[str, _Conversation] = {}

    def send(self, messages: list[Message], **kwargs: Any) -> str:
        response_text, _ = self._invoke(self._exec_args(kwargs.get("model")), self._render_messages(messages))
        return response_text

    @property
    def supports_conversations(self) -> bool:
        return True

    def new_conversation(self, system: str) -> str:
        cid = uuid.uuid4().hex
        self._conversations[cid] = _Conversation(system=system)
        return cid

    def resume(self, conversation_id: str, message: str) -> str:
        conversation = self._conversations.get(conversation_id)
        if conversation is None:
            raise KeyError(f"Unknown conversation ID: {conversation_id}")

        if conversation.thread_id is not None:
            args = self._resume_args(conversation.thread_id, self._model)
            prompt = message
        else:
            # Opening turn, or a replay when the CLI reported no thread id.
            args = self._exec_args(self._model)
            prompt = self._render_messages(
                [
                    Message(role="system", content=conversation.system),
                    *conversation.history,
                    Message(role="user", content=message),
                ]
            )

        response_text, thread_id = self._invoke(args, prompt)
        if conversation.thread_id is None and thread_id is not None:
            conversation.thread_id = thread_id
        conversation.history.extend(
            [
                Message(role="user", content=message),
                Message(role="assistant", content=response_text),
            ]
        )
        return response_text

    def _exec_args(self, model: Any) -> list[str]:
        return [
            self._codex_bin,
            "exec",
            "-s",
            SANDBOX_MODE,
            "--color",
            "never",
            "--skip-git-repo-check",
            "--json",
            "-m",
            str(model or self._model),
            *self._prompt_isolation_args(),
        ]

    def _resume_args(self, thread_id: str, model: Any) -> list[str]:
        # ``codex exec resume`` rejects ``-s`` and ``--color``; the read-only
        # policy is re-asserted through a config override instead.
        return [
            self._codex_bin,
            "exec",
            "resume",
            thread_id,
            "-c",
            f"sandbox_mode={SANDBOX_MODE}",
            "--skip-git-repo-check",
            "--json",
            "-m",
            str(model or self._model),
            *self._prompt_isolation_args(),
        ]

    def _prompt_isolation_args(self) -> list[str]:
        """Suppress codex's project prompt and use the runner prompt instead.

        ``project_doc_max_bytes=0`` is the only override that stops codex from
        reading the project ``AGENTS.md``.  ``project_doc_fallback_filenames``
        cannot do it: codex consults that list only in a directory where
        ``AGENTS.md`` is missing, and only for bare filenames — it adds a
        document rather than replacing one (measured on codex-cli 0.157.1).
        ``developer_instructions`` replaces codex's base instructions; the JSON
        encoding keeps the multi-line file contents a single TOML-parseable
        argv element.
        """
        if self._runner_prompt is None:
            return []
        return [
            "-c",
            "project_doc_max_bytes=0",
            "-c",
            f"developer_instructions={json.dumps(self._runner_prompt)}",
        ]

    def _invoke(self, args: list[str], prompt: str) -> tuple[str, str | None]:
        """Run a Codex invocation, returning its last message and thread id."""
        with tempfile.NamedTemporaryFile("r+", encoding="utf-8", delete=False) as tmp:
            out_path = Path(tmp.name)

        try:
            proc = subprocess.run(
                [*args, "--output-last-message", str(out_path), "-"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                input=prompt,
                text=True,
                encoding="utf-8",
                timeout=self._timeout_s,
                check=False,
            )
            if proc.returncode != 0:
                raise RuntimeError(
                    f"codex exec failed with exit code {proc.returncode}\n{proc.stdout}"
                )
            return out_path.read_text(encoding="utf-8"), _extract_thread_id(proc.stdout)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"codex exec timed out after {self._timeout_s}s") from exc
        except FileNotFoundError as exc:
            raise RuntimeError(f"codex CLI not found: {self._codex_bin}") from exc
        finally:
            out_path.unlink(missing_ok=True)

    @staticmethod
    def _render_messages(messages: list[Message]) -> str:
        parts: list[str] = []
        for msg in messages:
            role = msg.role.upper()
            parts.append(f"[{role}]\n{msg.content.strip()}")
        return "\n\n".join(parts).strip()


def _extract_thread_id(stdout: str) -> str | None:
    """Return the thread id from the JSONL event stream, if present."""
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and event.get("type") == "thread.started":
            thread_id = event.get("thread_id")
            if isinstance(thread_id, str) and thread_id:
                return thread_id
    return None
