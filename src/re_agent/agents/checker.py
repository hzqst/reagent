"""Checker agent — verifies reversed code against Ghidra decompilation."""

from __future__ import annotations

import json
import re
from pathlib import Path

from re_agent.backend.protocol import REBackend
from re_agent.core.models import CheckerVerdict, FunctionTarget, SymbolProposal, Verdict
from re_agent.llm.protocol import LLMProvider, Message
from re_agent.utils.templates import render_template

PROMPTS_DIR = Path(__file__).parent / "prompts"
VERDICT_RE = re.compile(r"VERDICT:\s*(PASS|FAIL)", re.I)
SUMMARY_RE = re.compile(r"SUMMARY:\s*(.+)")
ISSUES_RE = re.compile(r"ISSUES:\s*\n((?:\s*-\s*.+\n?)+)", re.I)
FIX_RE = re.compile(r"FIX_INSTRUCTIONS:\s*\n((?:\s*-\s*.+\n?)+)", re.I)
SYMBOL_ISSUES_RE = re.compile(r"SYMBOL_ISSUES:\s*\n((?:\s*-\s*.+\n?)+)", re.I)


def _render_symbol(symbol: SymbolProposal | None) -> str:
    """Render a proposal as prompt text, or a placeholder when absent."""
    if symbol is None:
        return "(none proposed)"
    lines = [f"name: {symbol.name}", f"confidence: {symbol.confidence}"]
    if symbol.comment:
        lines.append(f"comment: {symbol.comment}")
    if symbol.evidence:
        lines.append("evidence: " + "; ".join(symbol.evidence))
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

    def check(
        self,
        code: str,
        target: FunctionTarget,
        symbol: SymbolProposal | None = None,
    ) -> CheckerVerdict:
        """Check reversed code against decompilation. Returns CheckerVerdict.

        Args:
            code: The reversed candidate.
            target: The function being reversed.
            symbol: Optional proposed symbol, validated alongside the code.
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
        if verdict_match:
            verdict_str = verdict_match.group(1).upper()
            verdict = Verdict.PASS if verdict_str == "PASS" else Verdict.FAIL
        else:
            verdict = Verdict.UNKNOWN

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
        text = response.strip()
        if text.startswith("```json") and text.endswith("```"):
            text = text[7:-3].strip()
        if not text.startswith("{"):
            return None
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        raw_verdict = str(payload.get("verdict", "UNKNOWN")).upper()
        verdict = {
            "PASS": Verdict.PASS,
            "FAIL": Verdict.FAIL,
        }.get(raw_verdict, Verdict.UNKNOWN)
        issues = payload.get("issues", [])
        fixes = payload.get("fix_instructions", [])
        symbol_issues = payload.get("symbol_issues", [])
        return CheckerVerdict(
            verdict=verdict,
            summary=str(payload.get("summary", "")),
            issues=[str(item) for item in issues] if isinstance(issues, list) else [],
            fix_instructions=[str(item) for item in fixes] if isinstance(fixes, list) else [],
            symbol_issues=(
                [str(item) for item in symbol_issues] if isinstance(symbol_issues, list) else []
            ),
        )
