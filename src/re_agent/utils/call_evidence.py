"""Call-site evidence shared by structural verification and parity.

Raw totals remain intact. Exact PIC thunks and known expression wrappers in
decompiler text do not establish source calls; allocation/deallocation and
unresolved targets prevent treating an aggregate machine count as a source count.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from re_agent.utils.text import CPP_KEYWORDS, TOKEN_CALL_RE, mask_non_code

CallKind = Literal["ordinary", "pic", "lifetime", "unresolved", "decompiler_expr"]

# Hex-Rays partial-access macros from defs.h. Numbered aliases cover parts of
# up to 128-bit values; do not exempt arbitrary names sharing these prefixes.
# https://hex-rays.com/blog/igors-tip-of-the-week-67-decompiler-helpers
_HEX_RAYS_ACCESS = re.compile(
    r"S?(?:(?:HI|LO)(?:BYTE|WORD|DWORD)|BYTE(?:[1-9]|1[0-5])|WORD[1-7]|DWORD[1-3]|(?:BYTE|WORD|DWORD)n)"
)
_HEX_RAYS_COERCIONS = frozenset({
    "COERCE_FLOAT", "COERCE_DOUBLE", "COERCE_LONG_DOUBLE", "COERCE_UNSIGNED_INT", "COERCE_UNSIGNED_INT64",
})

_PIC = re.compile(r"__(?:x86|i686)\.get_pc_thunk\.(?:ax|bx|cx|dx|si|di|bp)")
_ALLOCATION = re.compile(
    r"(?:std::)?operator\s+(?:new|delete)(?:\[\])?"
    r"|_Z(?:nw|na)[jm](?:Pv|RKSt9nothrow_t|St11align_val_t(?:RKSt9nothrow_t)?)?"
    r"|_Z(?:dl|da)Pv(?:[jm](?:St11align_val_t)?|St11align_val_t|RKSt9nothrow_t|S_)?"
)
_SPECIAL_CODE_CALL = re.compile(
    r"(?<![\w:.>])(?P<target>__(?:x86|i686)\.get_pc_thunk\.\w+|"
    r"(?:std::)?operator\s+(?:new|delete)(?:\[\])?)\s*\("
)
_ASM_CALL = re.compile(
    r"^[ \t]*(?:(?P<address>(?:0x)?[0-9a-f]+):?[ \t]+)?call(?:q|l)?\s+(?P<target>.*)$",
    re.IGNORECASE,
)
_REGISTER = re.compile(r"(?:[re]?(?:ax|bx|cx|dx|si|di|bp|sp)|r\d+[bwd]?|[wx]\d+|lr)", re.IGNORECASE)
_UNRESOLVED_NAME = re.compile(r"(?:sub_|FUN_|thunk_FUN_)[0-9a-fA-F]+")


@dataclass(frozen=True)
class CallSite:
    """One observed call, including its origin and classification reason."""

    location: str
    target: str
    kind: CallKind
    reason: str
    start: int = 0
    end: int = 0


@dataclass(frozen=True)
class CallEvidence:
    """Observed sites and the independent raw total, when available."""

    sites: tuple[CallSite, ...]
    raw_count: int

    def count(self, kind: CallKind) -> int:
        return sum(site.kind == kind for site in self.sites)

    @property
    def complete(self) -> bool:
        return len(self.sites) == self.raw_count

    @property
    def comparable(self) -> bool:
        return self.complete and not self.count("lifetime") and not self.count("unresolved")

    def describe(self) -> str:
        return (
            f"raw {self.raw_count} calls; PIC {self.count('pic')}; lifetime {self.count('lifetime')}; "
            f"ordinary {self.count('ordinary')}; unresolved {self.count('unresolved')}; "
            f"decompiler expressions {self.count('decompiler_expr')}; parsed {len(self.sites)} sites"
        )

    def diagnostics(self, origin: str) -> list[str]:
        return [f"{origin}: {self.describe()}", *(
            f"{origin} call at {site.location}: {site.target or '<unknown>'} [{site.kind}]: {site.reason}"
            for site in self.sites if site.kind != "ordinary"
        )]


def is_hexrays_expression(target: str) -> bool:
    """Recognize exact access/coercion spellings, without classifying real targets."""
    return _HEX_RAYS_ACCESS.fullmatch(target) is not None or target in _HEX_RAYS_COERCIONS


def classify_target(target: str) -> tuple[CallKind, str]:
    """Classify a resolved target, never symbol-like text in a comment."""
    name = target.strip()
    # objdump-style direct operands may carry both an address and a symbol.
    annotated = re.fullmatch(r"(?:0x)?[0-9a-fA-F]+\s+<([^<>]+)>", name)
    if annotated:
        name = annotated[1]
    name = re.sub(r"@(?:plt|GLIBCXX_[\w.]+|CXXABI_[\w.]+)$", "", name)
    if _PIC.fullmatch(name):
        return "pic", "exact PIC register-setup thunk"
    symbol = name.split("(", 1)[0].strip()
    if _ALLOCATION.fullmatch(symbol):
        return "lifetime", "allocation/deallocation lowering has no fixed source-call multiplicity"
    if (not re.fullmatch(r"[A-Za-z_$][\w:$@.~]*(?:\([^;\n]*\))?", name)
            or _REGISTER.fullmatch(name) or _UNRESOLVED_NAME.fullmatch(name)
            or re.match(r"(?:cs|ds|es|ss|fs|gs):", name, re.IGNORECASE)
            or name == "_GLOBAL_OFFSET_TABLE_"):
        return "unresolved", "indirect or unresolved target cannot be classified as a source call"
    return "ordinary", "direct named call retained"


def code_call_evidence(code: str, *, decompiled: bool = False) -> CallEvidence:
    """Read lexical occurrences; normalize known wrappers only in decompiler text.

    Wrappers retain their raw sites and offsets. Scanning continues through
    their arguments, preserving nested business calls and repeated occurrences.
    """
    masked = mask_non_code(code)
    sites: list[CallSite] = []
    for match in _SPECIAL_CODE_CALL.finditer(masked):
        target = match["target"]
        kind, reason = classify_target(target)
        sites.append(CallSite(f"text offset {match.start()}", target, kind, reason, match.start(), match.end()))
    for site in sites:
        masked = masked[:site.start] + " " * (site.end - site.start) + masked[site.end:]
    for match in TOKEN_CALL_RE.finditer(masked):
        target = match[1]
        if target in CPP_KEYWORDS or target == "operator" or target.endswith("::operator"):
            continue
        kind, reason = classify_target(target)
        if (decompiled and is_hexrays_expression(target)
                and not re.search(r"(?:\.|->|::)\s*$", masked[:match.start()])):
            kind, reason = "decompiler_expr", "known Hex-Rays access/coercion expression, not a machine call"
        sites.append(CallSite(f"text offset {match.start()}", target, kind, reason, match.start(), match.end()))
    return CallEvidence(tuple(sorted(sites, key=lambda site: site.start)), len(sites))


def mask_nonordinary_calls(code: str, *, decompiled: bool = False) -> str:
    """Hide non-call/ABI/unknown names, preserving arguments and text offsets."""
    masked = mask_non_code(code)
    for site in code_call_evidence(code, decompiled=decompiled).sites:
        if site.kind != "ordinary":
            masked = masked[:site.start] + re.sub(r"[^\n]", " ", masked[site.start:site.end]) + masked[site.end:]
    return masked


def asm_call_evidence(instructions: str, raw_count: int) -> CallEvidence:
    """Read actual call mnemonics; comments and GOT operands grant no exemption."""
    sites: list[CallSite] = []
    for index, line in enumerate(instructions.splitlines()):
        match = _ASM_CALL.fullmatch(line.split(";", 1)[0].strip())
        if match is None:
            continue
        target = re.sub(r"^(?:(?:near|far|byte|word|dword|qword)\s+ptr\s+)", "", match["target"],
                        flags=re.IGNORECASE).strip()
        kind, reason = classify_target(target)
        sites.append(CallSite(match["address"] or f"line {index + 1}", target, kind, reason))
    return CallEvidence(tuple(sites), raw_count)


def pcode_call_evidence(operations: list[dict[str, object]]) -> CallEvidence:
    """Unresolved IR addresses are evidence gaps, never presumed business calls."""
    sites: list[CallSite] = []
    for index, operation in enumerate(operations):
        opcode = str(operation.get("opcode", "")).upper()
        if opcode not in {"CALL", "CALLIND"}:
            continue
        target = operation.get("target")
        target = target if isinstance(target, str) else ""
        kind, reason = classify_target(target) if opcode == "CALL" else ("unresolved", "indirect P-code call")
        sites.append(CallSite(str(operation.get("address", f"operation {index}")), target, kind, reason))
    return CallEvidence(tuple(sites), len(sites))
