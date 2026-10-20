"""Text analysis utilities for C++ source and assembly."""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

COMMENT_BLOCK_RE: re.Pattern[str] = re.compile(r"/\*.*?\*/", re.S)
COMMENT_LINE_RE: re.Pattern[str] = re.compile(r"//.*")
TOKEN_CALL_RE: re.Pattern[str] = re.compile(r"\b([A-Za-z_][A-Za-z0-9_:]*)\s*\(")
CONTROL_FLOW_RE: re.Pattern[str] = re.compile(r"\b(if|for|while|switch|do|goto)\b")
CONDITIONAL_RE: re.Pattern[str] = re.compile(r"&&|\|\||\?")
# Match complete tokens in source order: a quote inside a comment or an IDA
# name must not start a C++ literal. Preserve numbers so digit separators in
# e.g. 1'000 are not mistaken for opening character quotes.
_NON_CODE_RE: re.Pattern[str] = re.compile(
    r"(?P<number>\b[0-9][\w.']*)"
    r'|(?:u8|u|U|L)?R"(?P<delimiter>[^\s()\\]{0,16})\(.*?\)(?P=delimiter)"'
    r'|"(?:\\.|[^"\\])*"'
    r"|`[^`'\r\n]*'"
    r"|'(?:\\.|[^'\\\r\n])*'"
    r"|//(?:\\\r?\n|[^\n])*|/\*.*?(?:\*/|$)",
    re.S,
)
ASM_LINE_RE: re.Pattern[str] = re.compile(r"^[0-9a-fA-F]{8}\s+([A-Z]+)")

# ---------------------------------------------------------------------------
# Token sets
# ---------------------------------------------------------------------------

CPP_KEYWORDS: set[str] = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "alignof",
    "decltype",
    "static_cast",
    "reinterpret_cast",
    "const_cast",
    "dynamic_cast",
    "catch",
    "new",
    "delete",
}

FP_SOURCE_TOKENS: tuple[str, ...] = (
    "std::sin",
    "std::cos",
    "std::tan",
    "std::sqrt",
    "std::pow",
    "std::asin",
    "std::acos",
    "std::atan",
    "std::atan2",
    "std::fabs",
    "std::abs",
    "std::ceil",
    "std::floor",
    "std::isnan",
    "std::isfinite",
    "std::copysign",
    "sin(",
    "cos(",
    "sqrt(",
    "atan2(",
    "fabs(",
)

FP_ASM_PREFIXES: tuple[str, ...] = (
    "FCOM",
    "FUCOM",
    "FSIN",
    "FCOS",
    "FPTAN",
    "FPATAN",
    "FSQRT",
    "FDIV",
    "FMUL",
    "FADD",
    "FSUB",
    "FABS",
    "FRNDINT",
    "FNSTSW",
)


# ---------------------------------------------------------------------------
# Functions
# ---------------------------------------------------------------------------

def strip_comments(text: str) -> str:
    """Remove both block (``/* ... */``) and line (``// ...``) comments from C++ source."""
    return COMMENT_LINE_RE.sub("", COMMENT_BLOCK_RE.sub("", text))


def mask_non_code(text: str) -> str:
    """Blank comments, literals and IDA quoted names, preserving offsets.

    Hex-Rays prints names such as `` `guard variable for'Dialog::map``.
    The quoted prefix is an identifier, not a loop or a character literal.
    Recognize it before C++ quotes so it cannot hide subsequent real code.
    """
    def mask(match: re.Match[str]) -> str:
        token = match.group(0)
        return token if match.group("number") is not None else re.sub(r"[^\n]", " ", token)

    return _NON_CODE_RE.sub(mask, text)


def count_calls(
    body_no_comments: str,
    stub_call_prefix: str = "plugin::Call",
) -> tuple[int, int, int]:
    """Count function calls in comment-stripped C++ source.

    Args:
        body_no_comments: Source text with comments already removed.
        stub_call_prefix: Prefix used to identify stub/plugin calls.

    Returns:
        A tuple of ``(total_calls, plugin_calls, non_plugin_calls)``.
    """
    total = 0
    plugin = 0
    non_plugin = 0
    for m in TOKEN_CALL_RE.finditer(body_no_comments):
        tok = m.group(1)
        if tok in CPP_KEYWORDS:
            continue
        if tok.endswith("::operator") or tok == "operator":
            continue
        total += 1
        if tok.startswith(stub_call_prefix):
            plugin += 1
        else:
            non_plugin += 1
    return total, plugin, non_plugin


def count_control_flow(body: str) -> int:
    """Estimate control flow from code keywords and conditional operators.

    Each ``&&`` / ``||`` adds one potential decision, so two nested ``if``
    statements and ``if (a && b)`` have the same count. Count ternary decisions
    too. This is a structural heuristic, not a CFG or an equivalence proof.
    """
    code = mask_non_code(body)
    return len(CONTROL_FLOW_RE.findall(code)) + len(CONDITIONAL_RE.findall(code))


def has_fp_token(text: str) -> bool:
    """Check whether the text contains any floating-point math tokens."""
    return any(tok in text for tok in FP_SOURCE_TOKENS)


def parse_asm_line_op(line: str) -> str | None:
    """Extract the opcode from an assembly listing line.

    Expects the format ``XXXXXXXX  OPCODE ...`` where ``XXXXXXXX`` is an
    8-digit hex address.

    Returns:
        The opcode string if matched, otherwise ``None``.
    """
    m = ASM_LINE_RE.match(line)
    if m:
        return m.group(1)
    return None


def has_fp_asm(instructions: str) -> bool:
    """Check whether assembly instructions contain floating-point sensitive opcodes."""
    for line in instructions.splitlines():
        op = parse_asm_line_op(line)
        if op is not None and op.startswith(FP_ASM_PREFIXES):
            return True
    return False
