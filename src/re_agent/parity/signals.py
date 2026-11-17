"""Individual parity heuristic signals — each returns a Finding or None."""
from __future__ import annotations

from collections.abc import Callable

from re_agent.core.models import Finding, GhidraData, SourceMatch
from re_agent.utils.call_evidence import asm_call_evidence, code_call_evidence
from re_agent.utils.text import mask_non_code

SignalFn = Callable[..., Finding | None]


def check_missing_source(source: SourceMatch | None, **_kw: object) -> Finding | None:
    if source is None:
        return Finding(level="red", reason="Source function body not found")
    return None


def check_stub_markers(
    source: SourceMatch | None,
    stub_markers: tuple[str, ...] = ("NOTSA_UNREACHABLE",),
    **_kw: object,
) -> Finding | None:
    if source is not None and source.has_stub_marker:
        return Finding(level="red", reason=f"Source contains stub marker ({', '.join(stub_markers)})")
    return None


def check_trivial_stub(source: SourceMatch | None, **_kw: object) -> Finding | None:
    if source is None or source.plugin_call_count == 0:
        return None
    likely_trivial = (
        source.body_lines <= 14
        and source.non_plugin_call_count <= 1
        and source.control_flow_count == 0
    )
    if likely_trivial:
        return Finding(level="red", reason="Source appears to be a trivial plugin::Call* stub")
    return None


def check_large_asm_tiny_source(
    source: SourceMatch | None,
    ghidra: GhidraData | None = None,
    inline_skip: bool = False,
    **_kw: object,
) -> Finding | None:
    if source is None or ghidra is None or not ghidra.asm_ok or inline_skip:
        return None
    if ghidra.asm_instruction_count >= 80 and source.body_lines <= 12:
        return Finding(level="red", reason="Large ASM body but tiny source body, likely mismatch/stub")
    return None


def check_plugin_call_heavy(source: SourceMatch | None, **_kw: object) -> Finding | None:
    if source is None or source.plugin_call_count == 0:
        return None
    plugin_heavy = source.plugin_call_count >= max(2, source.non_plugin_call_count)
    trivial = (
        source.body_lines <= 14
        and source.non_plugin_call_count <= 1
        and source.control_flow_count == 0
    )
    if plugin_heavy and not trivial:
        return Finding(
            level="yellow",
            reason=(
                f"Source relies heavily on plugin::Call* "
                f"({source.plugin_call_count} plugin vs {source.non_plugin_call_count} non-plugin calls)"
            ),
        )
    return None


def check_short_body(source: SourceMatch | None, inline_skip: bool = False, **_kw: object) -> Finding | None:
    if source is None or inline_skip:
        return None
    if source.body_lines < 6:
        return Finding(level="yellow", reason=f"Very short body ({source.body_lines} lines), inspect manually")
    return None


def check_low_call_count(
    source: SourceMatch | None,
    ghidra: GhidraData | None = None,
    inline_skip: bool = False,
    **_kw: object,
) -> Finding | None:
    if source is None or ghidra is None or not ghidra.decompile_ok or inline_skip:
        return None
    source_calls = code_call_evidence(source.body_no_comments).count("ordinary")
    if ghidra.decompiled is not None:
        # Exclude the function declaration, which is not a call occurrence.
        body = mask_non_code(ghidra.decompiled).partition("{")[2]
        calls = code_call_evidence(body)
        if calls.count("ordinary") >= 6 and source_calls <= 1:
            return Finding(
                level="yellow",
                reason=f"Source call count is very low ({source_calls}) vs decompiled ordinary calls "
                       f"({calls.count('ordinary')}); {calls.describe()}",
            )
    if ghidra.callees is not None and ghidra.callees >= 6 and source_calls <= 1:
        return Finding(
            level="info",
            reason=f"Backend reports {ghidra.callees} callees vs {source_calls} source calls; "
                   "callee totals and source call sites are not directly comparable",
        )
    return None


def check_fp_sensitivity(
    source: SourceMatch | None,
    ghidra: GhidraData | None = None,
    inline_skip: bool = False,
    **_kw: object,
) -> Finding | None:
    if source is None or ghidra is None or not ghidra.asm_ok or inline_skip:
        return None
    if ghidra.asm_has_fp_sensitive and not source.has_fp_token:
        return Finding(
            level="yellow",
            reason="ASM contains floating-point sensitive ops but source has no obvious math tokens",
        )
    return None


def check_call_count_mismatch(
    source: SourceMatch | None,
    ghidra: GhidraData | None = None,
    inline_skip: bool = False,
    call_count_warn_diff: int = 3,
    **_kw: object,
) -> Finding | None:
    if source is None or ghidra is None or not ghidra.asm_ok or inline_skip:
        return None
    source_calls = code_call_evidence(source.body_no_comments).count("ordinary")
    if ghidra.asm_instructions is None:
        if abs(ghidra.asm_call_count - source_calls) > call_count_warn_diff:
            return Finding(level="info", reason="Raw ASM call total has no call-site details for comparison")
        return None
    calls = asm_call_evidence(ghidra.asm_instructions, ghidra.asm_call_count)
    call_diff = abs(calls.count("ordinary") - source_calls)
    definite_deficit = calls.complete and calls.count("ordinary") - source_calls > call_count_warn_diff
    if not calls.comparable and not definite_deficit:
        return Finding(level="info", reason=f"Call count comparison is inconclusive: {calls.describe()}")
    if call_diff > call_count_warn_diff:
        return Finding(
            level="yellow",
            reason=(
                f"Call count mismatch: vanilla has {ghidra.asm_call_count} calls, "
                f"source has {source_calls} ordinary calls (normalized diff: {call_diff}); {calls.describe()}"
            ),
        )
    return None


def check_nan_logic(
    source: SourceMatch | None,
    ghidra: GhidraData | None = None,
    **_kw: object,
) -> Finding | None:
    if source is None or ghidra is None or not ghidra.decompile_ok:
        return None
    if ghidra.decompile_has_nan and "isnan" not in source.body_no_comments and "NAN(" not in source.body_no_comments:
        return Finding(
            level="yellow",
            reason="Decompile includes NAN-sensitive logic; verify NaN behavior manually",
        )
    return None


def check_inline_wrapper(source: SourceMatch | None, **_kw: object) -> Finding | None:
    if source is not None and source.is_inline_internal_forwarder:
        return Finding(level="info", reason="Source is an inline forwarding wrapper to internal I_* implementation")
    return None


ALL_SIGNALS: list[SignalFn] = [
    check_missing_source,
    check_stub_markers,
    check_trivial_stub,
    check_large_asm_tiny_source,
    check_plugin_call_heavy,
    check_short_body,
    check_low_call_count,
    check_fp_sensitivity,
    check_call_count_mismatch,
    check_nan_logic,
    check_inline_wrapper,
]
