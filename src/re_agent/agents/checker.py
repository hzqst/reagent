"""Checker agent — verifies reversed code against Ghidra decompilation."""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any

from re_agent.backend.protocol import REBackend
from re_agent.backend.stages import backend_task
from re_agent.core.models import CheckerVerdict, FunctionTarget, SymbolProposal, Verdict
from re_agent.llm.protocol import LLMProvider, Message
from re_agent.utils.templates import render_template

PROMPTS_DIR = Path(__file__).parent / "prompts"
VERDICT_RE = re.compile(r"^[ \t]*VERDICT:[ \t]*([^\r\n]*)", re.I | re.MULTILINE)
SUMMARY_RE = re.compile(r"SUMMARY:\s*(.+)")
ISSUES_RE = re.compile(r"ISSUES:\s*\n((?:\s*-\s*.+\n?)+)", re.I)
FIX_RE = re.compile(r"FIX_INSTRUCTIONS:\s*\n((?:\s*-\s*.+\n?)+)", re.I)
SYMBOL_ISSUES_RE = re.compile(r"SYMBOL_ISSUES:\s*\n((?:\s*-\s*.+\n?)+)", re.I)
FENCE_RE = re.compile(r"```[ \t]*(?:json)?[ \t]*\r?\n(.*?)```", re.DOTALL | re.IGNORECASE)
_VERDICT_ALIASES = {
    "PASS": Verdict.PASS,
    "CORRECT": Verdict.PASS,
    "OK": Verdict.PASS,
    "GOOD": Verdict.PASS,
    "VERIFIED": Verdict.PASS,
    # pi/glm-5.3 对「代码正确」常用的措辞；漏掉它会把整个函数判为协议错误并丢弃候选。
    "ACCEPT": Verdict.PASS,
    "ACCEPTED": Verdict.PASS,
    "APPROVED": Verdict.PASS,
    "FAIL": Verdict.FAIL,
    "INCORRECT": Verdict.FAIL,
    "WRONG": Verdict.FAIL,
}


def _normalize_verdict(raw_verdict: object) -> Verdict:
    """Accept known verdict synonyms and reject protocol errors explicitly."""
    if isinstance(raw_verdict, str):
        verdict = _VERDICT_ALIASES.get(raw_verdict.strip().upper())
        if verdict is not None:
            return verdict
    raise ValueError(f"Checker protocol error: expected PASS/FAIL, got {raw_verdict!r}")


def _loads_dict(text: str) -> dict[str, Any] | None:
    """Parse ``text`` as a JSON object, or return ``None``."""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _strip_fence(text: str) -> str:
    """Unwrap ``text`` when it is a single fenced code block and nothing else."""
    if text.startswith("```") and text.endswith("```"):
        body = text[3:-3]
        newline = body.find("\n")
        if newline != -1:
            body = body[newline + 1 :]
        return body.strip()
    return text


def _balanced_objects(text: str) -> list[str]:
    """Return the top-level ``{...}`` regions of ``text``, ignoring braces in strings."""
    objects: list[str] = []
    depth = 0
    start = -1
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}" and depth:
            depth -= 1
            if depth == 0:
                objects.append(text[start : index + 1])
    return objects


def _extract_json_object(response: str) -> dict[str, Any] | None:
    """Find the verdict JSON, tolerating prose, fences, and stray braces.

    Models commonly narrate their reasoning before emitting the result. Only the
    exact whole-response object keeps its old lenient behaviour; every embedded
    candidate must carry a ``verdict`` key, so an unrelated example object in the
    prose cannot be mistaken for the decision. Candidates are searched from the
    end so the final answer wins.
    """
    text = response.strip()
    direct = _loads_dict(_strip_fence(text))
    if direct is not None:
        return direct

    candidates = [match.group(1).strip() for match in FENCE_RE.finditer(text)]
    candidates.extend(_balanced_objects(text))
    for candidate in reversed(candidates):
        payload = _loads_dict(candidate)
        if payload is not None and "verdict" in payload:
            return payload
    return None


def _render_symbol(symbol: SymbolProposal | None) -> str:
    """Render a proposal as prompt text, or a placeholder when absent."""
    if symbol is None:
        return "(none proposed)"
    lines = [f"name: {symbol.name}", f"confidence: {symbol.confidence}"]
    if symbol.comment:
        lines.append(f"comment: {symbol.comment}")
    if symbol.evidence:
        lines.append("evidence: " + "; ".join(symbol.evidence))
    if symbol.prototype is not None:
        lines.append("prototype: " + json.dumps(asdict(symbol.prototype)))
    for change in symbol.struct_changes:
        lines.append(
            f"struct_change: {change.struct_name}.{change.member} {change.operation} "
            f"offset={change.offset or '?'} type={change.type_str or '?'}"
        )
    return "\n".join(lines)


class CheckerAgent:
    """Verifies reversed code against Ghidra decompilation."""

    def __init__(self, llm: LLMProvider, backend: REBackend) -> None:
        self.llm = llm
        self.backend = backend
        self._conversation_id: str | None = None
        self.last_prompt: str = ""
        self.last_response: str = ""

    @backend_task("checker")
    def check(
        self,
        code: str,
        target: FunctionTarget,
        symbol: SymbolProposal | None = None,
        *,
        source_context: str = "",
    ) -> CheckerVerdict:
        """Check reversed code against decompilation. Returns CheckerVerdict.

        Args:
            code: The reversed candidate.
            target: The function being reversed.
            symbol: Optional proposed symbol, validated alongside the code.
            source_context: Harness-collected header/source evidence, not model claims.

        Raises:
            ValueError: The response lacks a recognized PASS/FAIL verdict.
        """
        decompile_result = self.backend.decompile(target.address)
        decompiled = decompile_result.raw_output

        system_prompt = render_template(PROMPTS_DIR / "checker_system.md")
        task_prompt = render_template(
            PROMPTS_DIR / "checker_task.md",
            class_name=target.class_name,
            function_name=target.function_name,
            address=target.address,
            reversed_code=code,
            decompiled=decompiled,
            proposed_symbol=_render_symbol(symbol),
            source_context=source_context or "Unavailable; do not approve unsupported header claims.",
        )

        from re_agent.agents.reverser import ReverserAgent

        evidence = ReverserAgent(self.llm, self.backend, max_investigations=4)._build_investigation_context(target)
        if evidence:
            task_prompt += "\n\nIndependent binary evidence (resolve conflicts explicitly):\n" + evidence
        try:
            struct = self.backend.get_struct(target.class_name) if target.class_name else None
        except (RuntimeError, OSError, ValueError):
            struct = None
        if struct:
            task_prompt += "\n\nType layout: " + repr(struct)
        # Preload the function's own disassembly so the checker can verify offsets,
        # immediates, and the call sequence against machine ground truth instead of
        # rejecting an otherwise-correct candidate for lack of raw evidence.
        try:
            asm = self.backend.get_asm(target.address) if self.backend.capabilities.has_asm else None
        except (RuntimeError, OSError, ValueError, NotImplementedError):
            asm = None
        if asm is not None and asm.instructions:
            task_prompt += (
                "\n\nOriginal disassembly (machine ground truth for offsets, immediates, "
                "and call sequence):\n" + asm.instructions
            )
        self.last_prompt = task_prompt

        if self._conversation_id is None and self.llm.supports_conversations:
            self._conversation_id = self.llm.new_conversation(system_prompt)

        if self._conversation_id:
            response = self.llm.resume(self._conversation_id, task_prompt)
        else:
            messages = [
                Message(role="system", content=system_prompt),
                Message(role="user", content=task_prompt),
            ]
            response = self.llm.send(messages)

        self.last_response = response
        return self._parse_verdict(response)

    @staticmethod
    def _parse_verdict(response: str) -> CheckerVerdict:
        json_verdict = CheckerAgent._parse_json_verdict(response)
        if json_verdict is not None:
            return json_verdict

        verdict_match = VERDICT_RE.search(response)
        verdict = _normalize_verdict(verdict_match.group(1) if verdict_match else "<missing verdict>")

        summary_match = SUMMARY_RE.search(response)
        summary = summary_match.group(1).strip() if summary_match else ""

        issues: list[str] = []
        issues_match = ISSUES_RE.search(response)
        if issues_match:
            for line in issues_match.group(1).strip().splitlines():
                item = line.strip().lstrip("- ").strip()
                if item and item.lower() != "none":
                    issues.append(item)

        fix_instructions: list[str] = []
        fix_match = FIX_RE.search(response)
        if fix_match:
            for line in fix_match.group(1).strip().splitlines():
                item = line.strip().lstrip("- ").strip()
                if item and item.lower() != "none":
                    fix_instructions.append(item)

        symbol_issues: list[str] = []
        symbol_match = SYMBOL_ISSUES_RE.search(response)
        if symbol_match:
            for line in symbol_match.group(1).strip().splitlines():
                item = line.strip().lstrip("- ").strip()
                if item and item.lower() != "none":
                    symbol_issues.append(item)

        return CheckerVerdict(
            verdict=verdict,
            summary=summary,
            issues=issues,
            fix_instructions=fix_instructions,
            symbol_issues=symbol_issues,
        )

    @staticmethod
    def _parse_json_verdict(response: str) -> CheckerVerdict | None:
        payload = _extract_json_object(response)
        if payload is None:
            return None
        verdict = _normalize_verdict(payload.get("verdict", "<missing verdict>"))
        issues = payload.get("issues", [])
        fixes = payload.get("fix_instructions", [])
        symbol_issues = payload.get("symbol_issues", [])
        review = payload.get("prototype_review")
        review = review if isinstance(review, dict) else {}
        status = review.get("status", "unreviewed")
        declaration = review.get("declaration", "")
        notes = review.get("notes", [])
        valid_review = (
            isinstance(status, str) and isinstance(declaration, str) and bool(declaration.strip())
            and isinstance(notes, list) and all(isinstance(note, str) for note in notes)
        )
        return CheckerVerdict(
            verdict=verdict,
            summary=str(payload.get("summary", "")),
            issues=[str(item) for item in issues] if isinstance(issues, list) else [],
            fix_instructions=[str(item) for item in fixes] if isinstance(fixes, list) else [],
            symbol_issues=(
                [str(item) for item in symbol_issues] if isinstance(symbol_issues, list) else []
            ),
            prototype_review=status if valid_review and status in {"approved", "disputed"} else "unreviewed",
            prototype_declaration=declaration if isinstance(declaration, str) else "",
            prototype_notes=notes if valid_review else [],
        )
