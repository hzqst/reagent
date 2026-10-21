"""Conservative regions of decompiled library implementation, not source text rules.

Only self-contained control statements with vector metadata or sort helpers
and known local operations qualify. Unknown calls, indirect
calls, unrelated member accesses and exits keep the statement visible. These
regions explain compiler expansion; they do not prove source equivalence.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

from re_agent.utils.text import CPP_KEYWORDS, TOKEN_CALL_RE, mask_non_code

_STORAGE = re.compile(
    r"\b(?:[A-Za-z_]\w*(?:->|\.))*[A-Za-z_]\w*"
    r"\._M_impl\._M_(?:start|finish|end_of_storage)\b"
)
_LIBRARY_CALLS = frozenset({"memmove", "memcpy", "memset", "__throw_bad_alloc", "_M_insert_aux"})
_ADDRESS = re.compile(r"/\*\s*(0x[0-9a-fA-F]+)\s*\*/")
_TYPE_WORDS = frozenset({"void", "char", "short", "int", "long", "float", "double", "bool", "signed", "unsigned"})
# These are expressions emitted by Hex-Rays, not arbitrary functions sharing
# a prefix. In particular, BYTE1Helper and Business::BYTE1 remain call anchors.
_HEX_RAYS_SLICE = re.compile(
    r"(?:S?(?:BYTE|WORD|DWORD)\d+|S?(?:HI|LO)(?:BYTE|WORD|DWORD)|(?:BYTE|WORD|DWORD)n)"
)
_BIT_INTRINSICS = frozenset({"_BitScanReverse", "_BitScanForward", "_BitScanReverse64", "_BitScanForward64"})
_SORT_HELPERS = (
    "__introsort_loop", "__insertion_sort", "__final_insertion_sort",
    "__unguarded_insertion_sort", "__unguarded_linear_insert", "__lg",
)
_SORT_NAMES = frozenset("std::" + helper for helper in _SORT_HELPERS)
_SORT_CALL = re.compile(r"(?<![\w:.>])std::(" + "|".join(_SORT_HELPERS) + r")\s*\(")


def _mask_template_arguments(code: str) -> str:
    """Expose qualified template calls without losing backend text offsets.

    This is deliberately limited to qualified names; a local comparison such
    as ``a < b`` must not hide the subsequent code as a template argument.
    Unbalanced or expression-like arguments are left untouched.
    """
    for match in reversed(list(re.finditer(r"\b\w+(?:::\w+)+\s*<", code))):
        opening = match.end() - 1
        depth = 1
        end = opening + 1
        while end < len(code) and depth:
            char = code[end]
            if char in ";{}()=":
                break
            if char == "<":
                depth += 1
            elif char == ">":
                depth -= 1
            end += 1
        if depth == 0:
            code = code[:opening] + re.sub(r"[^\n]", " ", code[opening:end]) + code[end:]
    return code


def _pseudo_call(name: str) -> bool:
    return name in _BIT_INTRINSICS or _HEX_RAYS_SLICE.fullmatch(name) is not None


@dataclass(frozen=True)
class InlineRegion:
    """A bounded statement read from the backend decompiler, never a candidate comment."""

    start: int
    end: int
    addresses: frozenset[int]
    kind: str = "vector storage"


def vector_regions(decompiled: str) -> list[InlineRegion]:
    """Select maximal nonoverlapping, library-only vector control statements."""
    code = mask_non_code(decompiled)
    # Only compiler-generated temporaries and proven storage aliases may be
    # assigned inside a region. A scalar/global/pointer write next to memmove
    # must not disappear merely because it has no member-access syntax.
    aliases: set[str] = set()
    assignments = list(re.finditer(r"(?<![\w.>])([A-Za-z_]\w*)\s*=(?!=)\s*([^;{}]+);", code))
    for _ in range(len(assignments) + 1):
        previous = set(aliases)
        for assignment in assignments:
            rhs = assignment[2]
            if (not TOKEN_CALL_RE.search(rhs) and
                    (_STORAGE.search(rhs) or any(re.search(r"\b" + re.escape(alias) + r"\b", rhs)
                                                for alias in aliases))):
                aliases.add(assignment[1])
        if aliases == previous:
            break
    regions: list[InlineRegion] = []
    for start, end in _control_statements(code):
        if regions and start < regions[-1].end:
            continue
        fragment = code[start:end]
        storage = list(_STORAGE.finditer(fragment))
        if not storage or re.search(r"\b(?:return|break|continue|throw)\b|\)\s*\(", fragment):
            continue
        calls = {call[1].split("::")[-1] for call in TOKEN_CALL_RE.finditer(fragment)
                 if call[1] not in CPP_KEYWORDS and call[1] not in {"operator", "std::operator"}}
        qualified_business_calls = any(
            "::" in call[1] and not call[1].startswith("std::")
            for call in TOKEN_CALL_RE.finditer(fragment)
        )
        if not calls <= _LIBRARY_CALLS or qualified_business_calls:
            continue
        # A region must do actual storage work, not just test size/empty in
        # a business condition. Disallow unrelated object fields, including
        # writes to scalar business state hidden alongside allocator work.
        if (not calls and not re.search(r"\boperator\s+(?:new|delete)\b", fragment)
                and not re.search(r"\._M_(?:start|finish|end_of_storage)\s*=", fragment)):
            continue
        roots = {item[0].split("._M_impl")[0] for item in storage}
        remainder = _STORAGE.sub("storage", fragment)
        for root in sorted(roots, key=len, reverse=True):
            remainder = re.sub(re.escape(root) + r"\b", "vector", remainder)
        if re.search(r"->|(?<!\d)\.(?!\d)", remainder):
            continue
        # After replacing storage expressions, any remaining assignment must
        # target a compiler temporary or a storage-derived pointer. The
        # lightweight recognizer refuses casts/complex lvalues rather than
        # guessing their effect.
        writes = re.findall(r"(?:^|[;{}])\s*([^;{}=]+?)\s*=(?!=)", remainder)
        storage_targets = "|".join(["storage", *(re.escape(alias) for alias in sorted(aliases))])
        safe_write = re.compile(r"\s*(?:(?:" + storage_targets + r"|v\d+)|\*\s*(?:" +
                                storage_targets + r"))\s*")
        if any(safe_write.fullmatch(lhs) is None for lhs in writes):
            continue
        # External labels may encode shared library cold paths, but crossing
        # their boundaries cannot be normalized without CFG evidence.
        labels = set(re.findall(r"\b([A-Za-z_]\w*)\s*:(?!:)", fragment))
        jumps = set(re.findall(r"\bgoto\s+([A-Za-z_]\w*)", fragment))
        if not jumps <= labels:
            continue
        addresses = frozenset(int(item[1], 16) for item in _ADDRESS.finditer(decompiled[start:end]))
        regions.append(InlineRegion(start, end, addresses))
    return regions


def _control_statements(code: str) -> list[tuple[int, int]]:
    """Read complete control statements, refusing malformed delimiter pairs."""
    pairs: dict[int, int] = {}
    stack: list[int] = []
    for index, char in enumerate(code):
        if char in "({":
            stack.append(index)
        elif char in ")}":
            if not stack or code[stack[-1]] != ("(" if char == ")" else "{"):
                return []
            pairs[stack.pop()] = index
    if stack:
        return []

    def skip(index: int) -> int:
        while index < len(code) and code[index].isspace():
            index += 1
        return index

    def statement(index: int) -> int | None:
        index = skip(index)
        if index >= len(code):
            return None
        if code[index] == "{":
            return pairs.get(index, -1) + 1 or None
        keyword = re.match(r"(if|while|for)\b", code[index:])
        if keyword:
            opening = skip(index + keyword.end())
            if code[opening:opening + 1] != "(" or opening not in pairs:
                return None
            end = statement(pairs[opening] + 1)
            if end is not None and keyword[1] == "if":
                following = skip(end)
                if re.match(r"else\b", code[following:]):
                    return statement(following + 4)
            return end
        semicolon = code.find(";", index)
        return semicolon + 1 if semicolon >= 0 and "{" not in code[index:semicolon] else None

    statements: list[tuple[int, int]] = []
    for match in re.finditer(r"\b(?:if|while|for)\b", code):
        end = statement(match.start())
        if end is not None:
            statements.append((match.start(), end))
    return statements


def has_sort_expansion(decompiled: str) -> bool:
    """Require actual std::sort implementation calls in backend evidence."""
    code = _mask_template_arguments(mask_non_code(decompiled))
    return any(call[1] in {"__introsort_loop", "__final_insertion_sort"}
               for call in _SORT_CALL.finditer(code))


def has_sort_abstraction(source_body: str) -> bool:
    """Comments, literals and similarly named business methods cannot opt in."""
    code = _mask_template_arguments(mask_non_code(source_body))
    return bool(re.search(r"(?<![\w:.>])std::sort\s*\(", code))


def unresolved_sort_flow(decompiled: str) -> bool:
    """Remaining helper calls do not establish a safe region boundary."""
    return bool(_SORT_CALL.search(_mask_template_arguments(mask_non_code(decompiled))))


def sort_regions(decompiled: str) -> list[InlineRegion]:
    """Fold closed helper-only statements, never arbitrary insertion loops.

    Pointer stores require iterator dataflow/CFG proof which this recognizer
    does not have. Mixed business code and cross-region jumps remain visible;
    their compiler expansion is reported as unresolved instead of erased.
    """
    code = _mask_template_arguments(mask_non_code(decompiled))
    regions: list[InlineRegion] = []
    allowed_words = _TYPE_WORDS | CPP_KEYWORDS | {"else", "true", "false", "__first", "__last", "__depth_limit"}
    for start, end in _control_statements(code):
        if regions and start < regions[-1].end:
            continue
        fragment = code[start:end]
        if not _SORT_CALL.search(fragment):
            continue
        # No memory/member/array accesses or labels: even a compiler temporary
        # may point to business state rather than the sorted range.
        if re.search(r"->|\.|\[|\]|\b(?:goto|return|throw|new|delete)\b|\)\s*\(", fragment):
            continue
        calls = list(TOKEN_CALL_RE.finditer(fragment))
        if any(call[1] not in allowed_words and not _pseudo_call(call[1])
               and _SORT_CALL.fullmatch(call[0]) is None for call in calls):
            continue
        # With dereferences forbidden, '*' is only allowed in arithmetic or
        # a simple primitive cast. Stores and loads through temporaries stay
        # outside the bounded normalization, as do unknown scalar identifiers.
        remainder = _SORT_CALL.sub("(", fragment)
        remainder = re.sub(r"\b(?:" + "|".join(_BIT_INTRINSICS) + r")\s*\(", "(", remainder)
        remainder = re.sub(r"\(\s*(?:(?:unsigned|signed|long|short)\s+)*(?:char|int|void)\s*\*\s*\)",
                           "", remainder)
        if re.search(r"(?<![\w)])\*|:(?!:)", remainder):
            continue
        words = re.findall(r"\b[A-Za-z_]\w*\b", remainder)
        if any(word not in allowed_words and re.fullmatch(r"v\d+", word) is None for word in words):
            continue
        addresses = frozenset(int(item[1], 16) for item in _ADDRESS.finditer(decompiled[start:end]))
        regions.append(InlineRegion(start, end, addresses, "std::sort helper"))
    return regions


def has_vector_expansion(decompiled: str) -> bool:
    """Require both vector storage fields and implementation work in backend code."""
    code = mask_non_code(decompiled)
    return bool(_STORAGE.search(code) and re.search(
        r"\b_M_insert_aux\s*\(|\bmemmove\s*\(|\boperator\s+(?:new|delete)\b", code,
    ))


def has_container_abstraction(source_body: str) -> bool:
    """A real source operation is needed before declaring counts incomparable."""
    code = mask_non_code(source_body)
    return bool(re.search(
        r"(?:\.|->)\s*(?:push_back|emplace_back|clear|assign|insert|resize|reserve)\s*\(|"
        r"\bstd::vector\s*<", code,
    ))


def unresolved_vector_flow(decompiled: str) -> bool:
    """Storage still present outside bounded regions means counts are not comparable.

    This intentionally refuses to infer the size of a cold path from symbol
    names. Business-call and constant checks remain independent of this gap.
    """
    return bool(_STORAGE.search(mask_non_code(decompiled)))


def named_calls(code: str) -> Counter[str]:
    """Direct named call anchors; omit compiler temporaries, casts and library internals."""
    code = mask_non_code(code)
    return Counter(
        call[1].split("::")[-1]
        for call in TOKEN_CALL_RE.finditer(code)
        if call[1] not in CPP_KEYWORDS and call[1].split("::")[-1] not in _LIBRARY_CALLS
        and code[max(0, call.start() - 1):call.start()] != "~"
        and call[1] not in _TYPE_WORDS and not call[1].endswith(":")
        and not (_pseudo_call(call[1]) and not re.search(r"(?:\.|->)\s*$", code[:call.start()]))
        and call[1] not in _SORT_NAMES
        and not call[1].startswith("__")
        and not call[1].split("::")[-1].startswith(("_M_", "_Z"))
        and not re.fullmatch(r"(?:v\d+|operator|[A-Z_]+)", call[1])
    )


def mask_regions(decompiled: str, regions: list[InlineRegion]) -> str:
    """Keep offsets and all code outside identified implementation statements."""
    code = mask_non_code(decompiled)
    for region in regions:
        code = code[:region.start] + re.sub(r"[^\n]", " ", code[region.start:region.end]) + code[region.end:]
    return code


def mechanical_call(line: str, *, include_sort: bool = False) -> bool:
    """Known direct lowering/library calls only; never match arbitrary substrings."""
    instruction = line.split(";", 1)[0]
    if include_sort and re.match(
        r"\s*(?:(?:0x)?[0-9a-fA-F]+:?\s+)?(?i:call)\s+"
        r"(?:std::(?:" + "|".join(_SORT_HELPERS) + r")(?:<[^;\n]*>)?|"
        r"_ZSt(?:16__introsort_loop|16__insertion_sort|22__final_insertion_sort|"
        r"26__unguarded_insertion_sort|25__unguarded_linear_insert|4__lg)I\w+)"
        r"(?:\s*\(|\s*$)", instruction,
    ):
        return True
    return bool(re.match(
        r"\s*(?:(?:0x)?[0-9a-fA-F]+:?\s+)?(?i:call)\s+(?:(?i:[a-z]+ ptr)\s+)?"
        r"(?:_?(?:memmove|memcpy|memset)(?:@\w+)?|(?:std::)?__throw_bad_alloc|"
        r"(?:std::)?operator (?:new|delete)(?:\[\])?|"
        r"_Z(?:nw|na|dl|da)\w*|std::vector<[^;\n]*>::_M_insert_aux)"
        r"(?:\s*\(|\s*$)", instruction,
    ))
