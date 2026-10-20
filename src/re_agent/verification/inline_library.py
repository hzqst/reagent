"""Conservative regions of decompiled vector implementation, not source text rules.

Only self-contained control statements containing vector storage metadata,
library calls and local/pointer operations qualify. Unknown calls, indirect
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


@dataclass(frozen=True)
class InlineRegion:
    """A bounded statement read from the backend decompiler, never a candidate comment."""

    start: int
    end: int
    addresses: frozenset[int]


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

    regions: list[InlineRegion] = []
    for match in re.finditer(r"\b(?:if|while|for)\b", code):
        if regions and match.start() < regions[-1].end:
            continue
        end = statement(match.start())
        if end is None:
            continue
        fragment = code[match.start():end]
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
        addresses = frozenset(int(item[1], 16) for item in _ADDRESS.finditer(decompiled[match.start():end]))
        regions.append(InlineRegion(match.start(), end, addresses))
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
    type_words = {"void", "char", "short", "int", "long", "float", "double", "bool", "signed", "unsigned"}
    code = mask_non_code(code)
    return Counter(
        call[1].split("::")[-1]
        for call in TOKEN_CALL_RE.finditer(code)
        if call[1] not in CPP_KEYWORDS and call[1].split("::")[-1] not in _LIBRARY_CALLS
        and code[max(0, call.start() - 1):call.start()] != "~"
        and call[1] not in type_words and not call[1].endswith(":")
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


def mechanical_call(line: str) -> bool:
    """Known direct lowering/library calls only; never match arbitrary substrings."""
    instruction = line.split(";", 1)[0]
    return bool(re.match(
        r"\s*(?:(?:0x)?[0-9a-fA-F]+:?\s+)?(?i:call)\s+(?:(?i:[a-z]+ ptr)\s+)?"
        r"(?:_?(?:memmove|memcpy|memset)(?:@\w+)?|(?:std::)?__throw_bad_alloc|"
        r"(?:std::)?operator (?:new|delete)(?:\[\])?|"
        r"_Z(?:nw|na|dl|da)\w*|std::vector<[^;\n]*>::_M_insert_aux)"
        r"(?:\s*\(|\s*$)", instruction,
    ))
