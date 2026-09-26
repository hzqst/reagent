"""Core data models for re-agent."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

# ---------------------------------------------------------------------------
# Target identification
# ---------------------------------------------------------------------------


@dataclass
class FunctionTarget:
    """Identifies a single function to reverse."""

    address: str
    class_name: str
    function_name: str
    caller_count: int = 0


# ---------------------------------------------------------------------------
# Verdict / status enums
# ---------------------------------------------------------------------------


class Verdict(Enum):
    """Checker verdict for a reversal attempt."""

    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class ParityStatus(Enum):
    """Static parity triage status."""

    GREEN = "green"
    YELLOW = "yellow"
    RED = "red"


# ---------------------------------------------------------------------------
# Checker results
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A single parity finding."""

    level: str  # "red", "yellow", or "info"
    reason: str


@dataclass
class CheckerVerdict:
    """Structured result from the checker agent."""

    verdict: Verdict
    summary: str
    issues: list[str] = field(default_factory=list)
    fix_instructions: list[str] = field(default_factory=list)
    symbol_issues: list[str] = field(default_factory=list)
    prototype_review: str = "unreviewed"
    prototype_declaration: str = ""
    prototype_notes: list[str] = field(default_factory=list)


@dataclass
class ObjectiveVerdict:
    """Structured result from conservative non-LLM verification."""

    verdict: Verdict
    summary: str
    findings: list[str] = field(default_factory=list)


@dataclass
class ValidationVerdict:
    """Result of configured candidate build and test gates."""

    verdict: Verdict
    summary: str
    findings: list[str] = field(default_factory=list)
    overlay_file: str | None = None
    checks: list[dict[str, str]] = field(default_factory=list)


def _string_list(value: object) -> list[str]:
    """Coerce a field into a list of non-empty strings."""
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _confidence(value: object) -> str:
    """Normalise a confidence marker; anything unrecognised stays conservative."""
    return "verified" if str(value or "").strip().lower() == "verified" else "inferred"


STRUCT_OPERATIONS = frozenset({"move", "rename", "retype"})


@dataclass
class StructChange:
    """A proposed correction to a struct member in the analysis database."""

    struct_name: str
    member: str
    operation: str  # "move", "rename", or "retype"
    offset: str = ""
    type_str: str = ""
    confidence: str = "inferred"
    evidence: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: object) -> StructChange | None:
        """Parse one proposal, or ``None`` when it is malformed."""
        if not isinstance(data, dict):
            return None
        struct_name = str(data.get("struct") or data.get("struct_name") or "").strip()
        member = str(data.get("member") or "").strip()
        operation = str(data.get("operation") or "").strip().lower()
        if not struct_name or not member or operation not in STRUCT_OPERATIONS:
            return None
        return cls(
            struct_name=struct_name,
            member=member,
            operation=operation,
            offset=str(data.get("offset") or "").strip(),
            type_str=str(data.get("type") or data.get("type_str") or "").strip(),
            confidence=_confidence(data.get("confidence")),
            evidence=_string_list(data.get("evidence")),
        )


@dataclass
class FunctionPrototypeProposal:
    """An independently reviewed, optional function type refinement.

    Malformed proposals remain visible through ``validation_error`` rather
    than disappearing as if no type change had been requested.
    """

    declaration: str = ""
    expected_current: str = ""
    required_types: list[str] = field(default_factory=list)
    confidence: str = "inferred"
    evidence: list[str] = field(default_factory=list)
    review_status: str = "unreviewed"
    review_notes: list[str] = field(default_factory=list)
    validation_error: str = ""

    @classmethod
    def from_dict(cls, data: object) -> FunctionPrototypeProposal:
        if not isinstance(data, dict):
            return cls(validation_error="prototype must be an object")
        for key in ("declaration", "expected_current", "confidence", "review_status", "validation_error"):
            if key in data and not isinstance(data[key], str):
                return cls(validation_error=f"prototype.{key} must be a string")
        for key in ("required_types", "evidence", "review_notes"):
            if key in data and (
                not isinstance(data[key], list)
                or any(not isinstance(item, str) or not item.strip() for item in data[key])
            ):
                return cls(validation_error=f"prototype.{key} must be a list of non-empty strings")
        declaration = str(data.get("declaration", "")).strip()
        status = data.get("review_status", "unreviewed")
        return cls(
            declaration=declaration,
            expected_current=str(data.get("expected_current", "")).strip(),
            required_types=_string_list(data.get("required_types")),
            confidence=_confidence(data.get("confidence")),
            evidence=_string_list(data.get("evidence")),
            review_status=status if status in {"approved", "disputed"} else "unreviewed",
            review_notes=_string_list(data.get("review_notes")),
            validation_error=str(data.get("validation_error") or ("" if declaration else "Missing declaration")),
        )


@dataclass
class SymbolProposal:
    """A proposed name and comment for a function in the analysis database.

    ``confidence`` is ``"verified"`` when the name comes from a deterministic
    source (a header annotation) and ``"inferred"`` when a model proposed it.
    """

    name: str
    comment: str = ""
    confidence: str = "inferred"
    evidence: list[str] = field(default_factory=list)
    struct_changes: list[StructChange] = field(default_factory=list)
    checker_ok: bool = True
    checker_notes: list[str] = field(default_factory=list)
    prototype: FunctionPrototypeProposal | None = None

    @classmethod
    def from_dict(cls, data: object) -> SymbolProposal | None:
        """Parse a proposal, or ``None`` when it carries no usable name."""
        if not isinstance(data, dict):
            return None
        name = str(data.get("name") or "").strip()
        if not name:
            return None
        raw_changes = data.get("struct_changes")
        changes = [_c for _c in (
            StructChange.from_dict(item) for item in (raw_changes if isinstance(raw_changes, list) else [])
        ) if _c is not None]
        return cls(
            name=name,
            comment=str(data.get("comment") or "").strip(),
            confidence=_confidence(data.get("confidence")),
            evidence=_string_list(data.get("evidence")),
            struct_changes=changes,
            checker_ok=bool(data.get("checker_ok", True)),
            checker_notes=_string_list(data.get("checker_notes")),
            prototype=(
                FunctionPrototypeProposal.from_dict(data["prototype"])
                if data.get("prototype") is not None else None
            ),
        )


@dataclass
class ReversalResult:
    """Complete result of reversing one function."""

    target: FunctionTarget
    code: str
    checker_verdict: CheckerVerdict | None = None
    objective_verdict: ObjectiveVerdict | None = None
    parity_status: ParityStatus | None = None
    parity_findings: list[Finding] = field(default_factory=list)
    rounds_used: int = 0
    success: bool = False
    validation_verdict: ValidationVerdict | None = None
    run_id: str = ""
    error: str | None = None
    symbol: SymbolProposal | None = None


# ---------------------------------------------------------------------------
# Ghidra / decompiler data
# ---------------------------------------------------------------------------


@dataclass
class DecompileResult:
    """Parsed output from a decompiler invocation."""

    address: str
    name: str
    signature: str
    decompiled: str
    raw_output: str
    callers: int | None = None
    callees: int | None = None
    signature_source: str = ""


@dataclass
class XRef:
    """A single cross-reference entry."""

    address: str
    name: str
    ref_type: str


@dataclass
class FunctionEntry:
    """A function entry from the decompiler's function list."""

    address: str
    name: str
    class_name: str = ""
    caller_count: int = 0


@dataclass
class StructField:
    """A single field within a struct definition."""

    name: str
    offset: int
    type_str: str
    size: int


@dataclass
class StructDef:
    """A struct/class definition from the decompiler."""

    name: str
    size: int
    fields: list[StructField] = field(default_factory=list)


@dataclass
class EnumValue:
    """A single value within an enum definition."""

    name: str
    value: int


@dataclass
class EnumDef:
    """An enum definition from the decompiler."""

    name: str
    values: list[EnumValue] = field(default_factory=list)


@dataclass
class AsmResult:
    """Parsed assembly listing for a function."""

    address: str
    instructions: str
    instruction_count: int
    call_count: int
    has_fp_sensitive: bool


@dataclass
class AnalysisArtifact:
    """Machine-readable or textual evidence returned by an RE backend."""

    kind: str
    target: str
    content: str


# ---------------------------------------------------------------------------
# Source analysis data
# ---------------------------------------------------------------------------


@dataclass
class SourceMatch:
    """Parsed source function body with analysis metrics."""

    path: str
    line: int
    body: str
    body_no_comments: str
    body_lines: int
    call_count: int
    plugin_call_count: int
    non_plugin_call_count: int
    control_flow_count: int
    has_stub_marker: bool
    has_fp_token: bool
    is_inline_internal_forwarder: bool
    body_start: int = 0
    body_end: int = 0


@dataclass
class GhidraData:
    """Aggregated Ghidra analysis data for a function."""

    decompile_ok: bool = False
    decompile_error: str | None = None
    callers: int | None = None
    callees: int | None = None
    param_offsets: int = 0
    decompile_has_nan: bool = False
    asm_ok: bool = False
    asm_error: str | None = None
    asm_instruction_count: int = 0
    asm_call_count: int = 0
    asm_has_fp_sensitive: bool = False
    refs_call_count: int = 0
    refs_global_rw_count: int = 0
    used_containing_fallback: bool = False
    resolved_address: str | None = None


# ---------------------------------------------------------------------------
# Hook registry
# ---------------------------------------------------------------------------


@dataclass
class HookEntry:
    """A single hook from the hooks CSV registry."""

    class_path: str
    fn_name: str
    address: str
    reversed: bool
    locked: bool
    is_virtual: bool

    @property
    def class_name(self) -> str:
        """Extract the class name from the class path."""
        return self.class_path.split("/")[-1]

    @property
    def symbol(self) -> str:
        """Return the fully-qualified symbol name."""
        return f"{self.class_name}::{self.fn_name}"


# ---------------------------------------------------------------------------
# Semantic parity rules
# ---------------------------------------------------------------------------


@dataclass
class SemanticRule:
    """A semantic parity rule loaded from a JSON rules file."""

    id: str
    reason: str
    severity: str  # "red", "yellow", or "info"
    addresses: list[str] = field(default_factory=list)
    symbols: list[str] = field(default_factory=list)
    source_all_of: list[str] = field(default_factory=list)
    source_any_of: list[str] = field(default_factory=list)
    source_none_of: list[str] = field(default_factory=list)


@dataclass
class ManualCheckEntry:
    """A manually-verified parity check entry."""

    line: int
    note: str


@dataclass(frozen=True)
class EvidenceGap:
    """An observed limitation, not a guessed dependency or recovered fact."""

    function: str
    reason: str
    origin: str
    kind: str = "unavailable"
    site: str | None = None

    @classmethod
    def from_dict(cls, value: object) -> EvidenceGap:
        if not isinstance(value, dict):
            raise ValueError("Evidence gap must be an object")
        required = ("function", "reason", "origin", "kind")
        if any(not isinstance(value.get(key), str) or not value[key].strip() for key in required):
            raise ValueError("Evidence gap requires function, reason, origin, and kind strings")
        if value["kind"] not in {"unavailable", "unsupported", "query_failed", "unresolved_call", "limit"}:
            raise ValueError("Unknown evidence gap kind")
        from re_agent.utils.address import checked_address

        return cls(checked_address(value["function"]), value["reason"], value["origin"], value["kind"],
                   checked_address(value["site"]) if value.get("site") is not None else None)
