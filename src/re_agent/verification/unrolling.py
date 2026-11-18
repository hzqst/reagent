"""Fixed-trip loop unrolling evidence, never a general tolerance increase.

A compiler may fully unroll a loop whose bound is a source constant and expand
its tail zero padding into stores. Source call sites and keywords then no longer
predict machine counts. A loop only explains extra sites when the backend's
per-callee count equals the trip count exactly; a wrong bound, a removed call
or an unrelated deficit stays visible to the structural checks.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

from re_agent.utils.call_evidence import CallEvidence, code_call_evidence
from re_agent.utils.text import count_control_flow, mask_non_code

_INTEGER = r"(?:0[xX][0-9a-fA-F]+|[0-9]+)[uUlL]*"
_LOOP = re.compile(r"\b(for|while)\s*\(")
_NESTED_LOOP = re.compile(r"\b(?:for|while|do)\b")
_EXIT = re.compile(r"\b(?:break|continue|return)\b")
_CONDITION = re.compile(rf"^\s*([A-Za-z_]\w*)\s*(<=|<|!=)\s*([A-Za-z_]\w*|{_INTEGER})\s*$")
_REVERSED_CONDITION = re.compile(rf"^\s*([A-Za-z_]\w*|{_INTEGER})\s*(>=|>)\s*([A-Za-z_]\w*)\s*$")
_ZERO = r"0(?:[uU]?(?:i64|[lL]{1,2})?)?"
_CHAR_ZERO = re.compile(r"(?:u8|u|U|L)?'\\0'")
# Backend stores must write through a dereference or an index: a zeroed local
# variable or struct field is not expanded padding.
_BACKEND_ZERO_STORE = re.compile(
    rf"(?:^|[;{{}}:)]|\belse\b)\s*(?:\*[^;={{}}]+?|[A-Za-z_][\w.>-]*\s*\[[^;={{}}]+\])\s*=\s*{_ZERO}\s*;", re.M,
)
_BACKEND_MEMSET = re.compile(rf"\bmemset\s*\([^;]*?,\s*{_ZERO}\s*,")
# Source fill may also use member stores or library fills.
_SOURCE_ZERO_WRITE = re.compile(
    rf"(?:\]|\*\s*[A-Za-z_(][^;={{}}]*?|(?:->|\.)\s*[A-Za-z_]\w*)\s*=\s*(?:{_ZERO}|nullptr|NULL)\s*;"
    r"|\b(?:memset|bzero|std::fill(?:_n)?|fill(?:_n)?)\s*\("
)
_MIN_ZERO_STORES = 2


@dataclass(frozen=True)
class FixedTripLoop:
    """A non-nested source loop whose maximum trip count is a constant."""

    start: int
    end: int
    trips: int
    calls: Counter[str]
    body_flow: int
    zero_fill: bool


def callee_key(target: str) -> str:
    """Compare source, decompiler and ASM names: ``std::tolower`` = ``_tolower@plt``."""
    annotated = re.search(r"<([^<>]+)>", target)
    name = annotated[1] if annotated else target
    name = re.sub(r"@.*$", "", name.split("(", 1)[0].strip()).split("::")[-1]
    return re.sub(r"^(?:j_|[._])+", "", name)


def call_counter(evidence: CallEvidence) -> Counter[str]:
    return Counter(callee_key(site.target) for site in evidence.sites if site.kind == "ordinary")


def _integer(text: str) -> int:
    digits = text.rstrip("uUlL")
    return int(digits, 16) if digits.lower().startswith("0x") else int(digits, 10)


def _constant(token: str, code: str) -> int | None:
    if re.fullmatch(_INTEGER, token):
        return _integer(token)
    match = re.search(
        rf"\b(?:constexpr|const)\b[\w\s:]*?\b{re.escape(token)}\s*(?:=\s*|\{{\s*)({_INTEGER})\s*\}}?\s*;", code,
    )
    return _integer(match[1]) if match else None


def _closing(code: str, opening: int, pair: str) -> int | None:
    depth = 0
    for index in range(opening, len(code)):
        if code[index] == pair[0]:
            depth += 1
        elif code[index] == pair[1]:
            depth -= 1
            if depth == 0:
                return index
    return None


def _statement_end(code: str, start: int) -> int | None:
    """End of a braced block or of a single statement, skipping parenthesized headers."""
    depth = 0
    for index in range(start, len(code)):
        char = code[index]
        if char == "{" and depth == 0:
            return _closing(code, index, "{}")
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == ";" and depth == 0:
            return index
    return None


def _trips(keyword: str, header: str, code: str) -> int | None:
    parts = header.split(";")
    if keyword == "for" and len(parts) != 3:
        return None
    condition = parts[1] if keyword == "for" else header
    match = _CONDITION.fullmatch(condition)
    if match:
        variable, operator, bound_token = match.groups()
    else:
        reversed_match = _REVERSED_CONDITION.fullmatch(condition)
        if reversed_match is None:
            return None
        bound_token, operator, variable = reversed_match.groups()
        operator = {">": "<", ">=": "<="}[operator]
    bound = _constant(bound_token, code)
    if bound is None:
        return None
    # An empty initializer continues from earlier code; the bound is then the
    # maximum trip count. Any other initializer must assign a constant.
    initial = 0
    if keyword == "for" and parts[0].strip():
        init = re.fullmatch(rf"\s*(?:[\w:]+\s+)*{re.escape(variable)}\s*=\s*(\S+)\s*", parts[0])
        value = _constant(init[1], code) if init else None
        if value is None:
            return None
        initial = value
    trips = bound - initial + (operator == "<=")
    return trips if trips > 1 else None


def fixed_trip_loops(source_body: str) -> list[FixedTripLoop]:
    """Read candidate loops; nested loops multiply counts and are not explained."""
    code = mask_non_code(source_body)
    spans: list[tuple[int, int, int, int]] = []
    for match in _LOOP.finditer(code):
        header_end = _closing(code, match.end() - 1, "()")
        if header_end is None:
            continue
        body_start = header_end + 1
        while body_start < len(code) and code[body_start].isspace():
            body_start += 1
        body_end = _statement_end(code, body_start)
        if body_end is None or body_end == body_start:
            # ``do { } while (...);`` has its body before the header.
            continue
        trips = _trips(match[1], code[match.end():header_end], code)
        if trips is not None:
            spans.append((match.start(), body_start, body_end + 1, trips))
    loops: list[FixedTripLoop] = []
    for start, body_start, end, trips in spans:
        body = code[body_start:end]
        nested = _NESTED_LOOP.search(body) or any(
            other_start < start and end <= other_end for other_start, _, other_end, _ in spans
        )
        if nested:
            continue
        calls = Counter(
            callee_key(site.target) for site in code_call_evidence(body).sites if site.kind == "ordinary"
        )
        # Each source exit may become one ``goto`` per unrolled iteration.
        body_flow = count_control_flow(body) + len(_EXIT.findall(body))
        loops.append(FixedTripLoop(start, end, trips, calls, body_flow,
                                   has_zero_write(source_body[body_start:end])))
    return loops


def unrolled_call_credit(loops: list[FixedTripLoop], source: Counter[str], binary: Counter[str]) -> Counter[str]:
    """Extra backend sites per callee, only where unrolling explains them exactly."""
    extra: Counter[str] = Counter()
    for loop in loops:
        for name, sites in loop.calls.items():
            extra[name] += (loop.trips - 1) * sites
    return Counter({
        name: count for name, count in extra.items()
        if count > 0 and binary[name] == source[name] + count
    })


def unrolled_flow_budget(loops: list[FixedTripLoop], credited: Counter[str], zero_fill: bool) -> int:
    """Upper bound on branches that unrolling may add over the candidate's count.

    The loop test itself disappears when fully unrolled, so only branches in
    the body repeat. A tail fill after an early exit may expand into one
    alignment/length test per possible start, so it adds at most its trips.
    """
    budget = 0
    for loop in loops:
        if loop.calls and all(name in credited for name in loop.calls):
            budget += loop.trips * loop.body_flow
        elif zero_fill and loop.zero_fill and not loop.calls:
            budget += loop.trips
    return budget


def has_zero_fill_expansion(decompiled: str) -> bool:
    code = mask_non_code(decompiled)
    return len(_BACKEND_ZERO_STORE.findall(code)) >= _MIN_ZERO_STORES or bool(_BACKEND_MEMSET.search(code))


def has_zero_write(source: str) -> bool:
    # Keep NUL character literals visible as zero before literals are masked.
    return bool(_SOURCE_ZERO_WRITE.search(mask_non_code(_CHAR_ZERO.sub("0", source))))
