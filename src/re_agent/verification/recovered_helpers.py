"""Match direct calls to candidate-local helpers against ordered pseudocode sites."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from re_agent.parity.source_indexer import SourceIndexer
from re_agent.utils.call_evidence import CallEvidence, CallSite, code_call_evidence

# Only model unconditional calls. A final return may return the computed value.
_CONTROL = re.compile(r"[{}?:#]|&&|\|\||\b(?:if|else|switch|for|while|do|goto|throw|try|sizeof|decltype|noexcept)\b")
_SIMPLE_HEAD = re.compile(r"(?:[\w\s*&]+?[\s*&])(?P<name>[A-Za-z_]\w*)\s*\([^()]*\)\s*$")


def helper_sequences(masked: str, definitions: list[tuple[int, int]], target: tuple[int, int]) -> dict[str, list[str]]:
    """Collect straight-line bodies for unambiguous free-function definitions."""
    if re.search(r"^\s*#\s*(?:if|define)", masked, re.MULTILINE):
        return {}
    sequences: dict[str, list[str]] = {}
    # Exclude prototypes, overloads and other competing declarations.
    declarations = list(masked)
    for start, end in definitions:
        declarations[start:end + 1] = " " * (end + 1 - start)
    heads = "".join(declarations)
    for start, end in definitions:
        if (start, end) == target:
            continue
        head_start = max(masked.rfind(";", 0, start), masked.rfind("}", 0, start)) + 1
        head = _SIMPLE_HEAD.fullmatch(masked[head_start:start].strip())
        if not head:
            continue
        name = head["name"]
        if len(re.findall(rf"\b{re.escape(name)}\b", heads)) != 1:
            continue
        body = masked[start + 1:end]
        if _CONTROL.search(body.replace("::", "")) or re.search(r"\breturn\b[^;]*;\s*\S", body):
            continue
        sites = code_call_evidence(body).sites
        if len(sites) >= 2 and all(site.kind == "ordinary" for site in sites):
            sequences[name] = [_name(body, site) for site in _ordered(sites, body)]
    return sequences


def _ordered(sites: tuple[CallSite, ...], text: str) -> list[CallSite]:
    # Calls in argument expressions precede their enclosing call.
    def position(site: CallSite) -> int:
        if text[site.end - 1:site.end] == "(":
            return SourceIndexer._find_matching_paren(text, site.end - 1) or site.start
        return site.start

    return sorted(sites, key=position)


def _name(text: str, site: CallSite) -> str:
    prefix = text[:site.start].rstrip()
    if prefix.endswith((".", "->", "::")):
        receiver = re.search(r"([\w:]+)\s*(->|\.|::)$", prefix)
        return ("".join(receiver.groups()) if receiver else "<member>") + site.target
    # C library calls commonly lose their std:: qualifier in pseudocode.
    if site.target in {"std::strcpy", "std::memset", "std::memcpy", "std::memmove", "std::strlen",
                       "std::snprintf", "std::strncat"}:
        return site.target.removeprefix("std::")
    return site.target


@dataclass
class HelperMatches:
    source: list[CallSite] = field(default_factory=list)
    decompiled: list[CallSite] = field(default_factory=list)

    @property
    def extra_sites(self) -> int:
        return len(self.decompiled) - len(self.source)

    def describe(self) -> str:
        return ", ".join(f"{name} x{count}" for name, count in Counter(s.target for s in self.source).items())


def match_helpers(
    sequences: dict[str, list[str]], source: str, calls: CallEvidence, body: str, evidence: CallEvidence,
) -> HelperMatches:
    matches = HelperMatches()
    if not sequences or not any(site.target in sequences for site in calls.sites):
        return matches
    sites = _ordered(tuple(s for s in evidence.sites if s.kind != "decompiler_expr"), body)
    names = [_name(body, s) if s.kind == "ordinary" else "" for s in sites]
    # A local declaration or rebinding makes a same-spelled call ambiguous.
    candidates = {name: seq for name, seq in sequences.items()
                  if len(re.findall(rf"\b{re.escape(name)}\b", source)) == sum(s.target == name for s in calls.sites)}
    cursor = 0
    for site in _ordered(calls.sites, source):
        name = _name(source, site)
        sequence = candidates.get(site.target) if site.kind == "ordinary" and name == site.target else None
        for i in range(cursor, len(sites)):
            if name == names[i]:
                cursor = i + 1
                break
            if sequence and names[i:i + len(sequence)] == sequence:
                region = sites[i:i + len(sequence)]
                if any(_CONTROL.search(body[left.end:right.start].replace("::", ""))
                       for left, right in zip(region, region[1:], strict=False)):
                    continue
                matches.source.append(site)
                matches.decompiled.extend(region)
                cursor = i + len(sequence)
                break
        else:
            # No consistent placement with respect to the other source calls.
            return HelperMatches()
    return matches


def mask_matched_sites(text: str, sites: list[CallSite]) -> str:
    chars = list(text)
    for site in sites:
        chars[site.start:site.end] = " " * (site.end - site.start)
    return "".join(chars)
