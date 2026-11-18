"""Fixed-trip unrolling explains exact compiler expansion, never a missing effect."""
from __future__ import annotations

from collections import Counter

import pytest

from re_agent.backend.stub import StubBackend
from re_agent.core.models import AsmResult, DecompileResult, FunctionTarget, Verdict
from re_agent.utils.call_evidence import code_call_evidence
from re_agent.utils.text import count_calls
from re_agent.verification.inline_library import named_calls
from re_agent.verification.objective import verify_candidate
from re_agent.verification.unrolling import (
    callee_key,
    fixed_trip_loops,
    has_zero_fill_expansion,
    has_zero_write,
    unrolled_call_credit,
)

TARGET = FunctionTarget("0x129510", "", "W_CleanupName")
NAME_LENGTH = 16
# Issue #31 round 1: readable bounded conversion with early NUL exit and tail fill.
CANDIDATE = """void __attribute__((cdecl)) W_CleanupName(char* in, char* out)
{
    constexpr int kNameLength = 16;
    int i = 0;
    for (; i < kNameLength; ++i)
    {
        const int c = static_cast<signed char>(in[i]);
        if (c == 0)
            break;
        out[i] = static_cast<char>((::tolower)(c));
    }
    for (; i < kNameLength; ++i)
        out[i] = '\\0';
}"""
_STEPS = "".join(
    f"  v{k} = in[{k}];\n  if ( !(_BYTE)v{k} )\n    goto LABEL_PAD;\n  out[{k}] = tolower(v{k});\n"
    for k in range(NAME_LENGTH)
)
# Hex-Rays shape: sixteen guarded steps, then alignment-sensitive tail stores.
DECOMPILE = (
    "void __cdecl W_CleanupName(char *in, char *out)\n{\n"
    + _STEPS
    + "  return;\nLABEL_PAD:\n"
    + "  if ( ((unsigned __int8)v20 & 1) != 0 )\n    *v20++ = 0;\n"
    + "  if ( ((unsigned __int8)v20 & 2) != 0 )\n  {\n    *(_WORD *)v20 = 0;\n    v20 += 2;\n  }\n"
    + "  if ( v21 >= 4 )\n    *(_DWORD *)v20 = 0;\n"
    + "}"
)
ASM_CALLS = ["__x86.get_pc_thunk.bx", *["_tolower"] * NAME_LENGTH]


class _UnrolledBackend(StubBackend):
    def __init__(self, decompiled: str = DECOMPILE, calls: list[str] | None = None) -> None:
        super().__init__()
        self.decompiled = decompiled
        self.calls = ASM_CALLS if calls is None else calls

    def decompile(self, target: str) -> DecompileResult:
        return DecompileResult(target, TARGET.class_name, "", self.decompiled, self.decompiled)

    def get_asm(self, target: str) -> AsmResult:
        instructions = "\n".join(f"{0x129520 + i * 8:x} call {call}" for i, call in enumerate(self.calls))
        return AsmResult(target, instructions, 200, len(self.calls), False)


def _verify(candidate: str, backend: StubBackend | None = None) -> tuple[Verdict, list[str]]:
    result = verify_candidate(candidate, TARGET, backend or _UnrolledBackend())
    return result.verdict, result.findings


@pytest.mark.parametrize("call", ["tolower(c)", "::tolower(c)", "(::tolower)(c)", "(tolower)(c)", "(std::tolower)(c)"])
def test_parenthesized_and_qualified_callees_count_as_calls(call: str) -> None:
    body = f"{{ out[i] = {call}; }}"

    assert code_call_evidence(body).count("ordinary") == 1
    assert Counter({"tolower": 1}) == named_calls(body, decompiled=False)
    assert count_calls(body) == (1, 0, 1)


@pytest.mark.parametrize("expression", [
    "(int)(x)", "(size_t)(n)", "(std::uint8_t)(v)", "(DWORD)(v)", "(_BYTE)(v)", "(__int8)(v)", "f(g)(x)", "a[i](x)",
])
def test_casts_and_argument_parentheses_are_not_parenthesized_callees(expression: str) -> None:
    names = {site.target for site in code_call_evidence(f"{{ y = {expression}; }}").sites}

    assert "g" not in names and "i" not in names
    assert not names & {"int", "size_t", "std::uint8_t", "DWORD", "_BYTE", "__int8"}


def test_condition_parentheses_are_not_a_callee() -> None:
    sites = code_call_evidence("{ if (flag) (f)(x); while (ok) (g)(y); }").sites

    assert [site.target for site in sites] == ["f", "g"]


def test_fixed_trip_loops_resolve_constant_bounds_and_tail_fill() -> None:
    loops = fixed_trip_loops(CANDIDATE)

    assert [loop.trips for loop in loops] == [NAME_LENGTH, NAME_LENGTH]
    assert Counter({"tolower": 1}) == loops[0].calls
    assert [loop.zero_fill for loop in loops] == [False, True]
    # ``if`` plus ``break`` may each repeat per unrolled step.
    assert loops[0].body_flow == 2


@pytest.mark.parametrize("header, trips", [
    ("for (int i = 0; i < 16; ++i)", 16),
    ("for (int i = 2; i < 16; ++i)", 14),
    ("for (int i = 0; i <= 0x0F; i++)", 16),
    ("for (unsigned i = 0; 16u > i; ++i)", 16),
    ("for (int i = 0; i < n; ++i)", None),
    ("for (int i = start; i < 16; ++i)", None),
    ("while (*p)", None),
])
def test_only_constant_bounds_define_a_trip_count(header: str, trips: int | None) -> None:
    loops = fixed_trip_loops(f"{{ {header} {{ f(i); }} }}")

    assert trips == (loops[0].trips if loops else None)


def test_nested_and_do_while_loops_are_not_explained() -> None:
    assert fixed_trip_loops("{ for (int i = 0; i < 4; ++i) for (int j = 0; j < 4; ++j) f(i, j); }") == []
    assert fixed_trip_loops("{ int i = 0; do { f(i); } while (++i < 16); }") == []


def test_credit_requires_exact_per_callee_backend_count() -> None:
    loops = fixed_trip_loops(CANDIDATE)
    source = Counter({"tolower": 1})

    assert Counter({"tolower": 15}) == unrolled_call_credit(loops, source, Counter({"tolower": 16}))
    assert Counter() == unrolled_call_credit(loops, source, Counter({"tolower": 15}))
    assert Counter() == unrolled_call_credit(loops, source, Counter({"tolower": 32}))
    assert Counter() == unrolled_call_credit(loops, source, Counter({"toupper": 16}))


@pytest.mark.parametrize("target, key", [
    ("_tolower", "tolower"), ("tolower@plt", "tolower"), ("0x8049000 <tolower@plt>", "tolower"),
    ("std::tolower", "tolower"), ("j_tolower", "tolower"), (".tolower", "tolower"),
])
def test_callee_keys_compare_source_decompile_and_asm_names(target: str, key: str) -> None:
    assert key == callee_key(target)


def test_zero_fill_evidence_requires_memory_stores() -> None:
    assert has_zero_fill_expansion(DECOMPILE)
    assert has_zero_fill_expansion("{ memset(out + i, 0, 16 - i); }")
    assert not has_zero_fill_expansion("{ v1 = 0; v2 = 0; result = 0; }")
    assert has_zero_write("{ out[i] = '\\0'; }")
    assert has_zero_write("{ std::fill(out + i, out + 16, 0); }")
    assert not has_zero_write("{ int i = 0; out[i] = c; }")
    assert not has_zero_write("{ out[i] = c; /* out[i] = 0; */ }")


def test_readable_unrolled_reconstruction_is_unknown_with_raw_counts() -> None:
    verdict, findings = _verify(CANDIDATE)

    assert verdict == Verdict.UNKNOWN
    text = "\n".join(findings)
    assert "decompiled body has 16 ordinary call sites" in text
    assert "ASM call mismatch: disassembly has 17 calls, candidate has 1" in text
    assert "15 extra call sites match fixed-trip loop unrolling" in text
    assert "tolower (1 source site(s) + 15 unrolled)" in text
    assert "fixed-trip loop unrolling and tail zero fill account for up to" in text


def test_compiler_style_expanded_reconstruction_still_passes() -> None:
    steps = "".join(
        f"    if (!in[{k}]) goto pad;\n    out[{k}] = tolower(in[{k}]);\n" for k in range(NAME_LENGTH)
    )
    padding = DECOMPILE[DECOMPILE.index("  return;"):]
    candidate = "void W_CleanupName(char* in, char* out)\n{\n" + steps + padding.replace("LABEL_PAD", "pad")

    assert _verify(candidate)[0] == Verdict.PASS


@pytest.mark.parametrize("candidate, expected", [
    # Removed conversion: no source loop names tolower.
    (CANDIDATE.replace("(::tolower)(c)", "c"), "Decompiled call mismatch"),
    # Wrong bound: 8 x 1 cannot explain 16 backend sites.
    (CANDIDATE.replace("kNameLength = 16", "kNameLength = 8"), "Decompiled call mismatch"),
    # Wrong bound in the other direction.
    (CANDIDATE.replace("kNameLength = 16", "kNameLength = 32"), "Decompiled call mismatch"),
    # Missing tail padding.
    (CANDIDATE.replace("    for (; i < kNameLength; ++i)\n        out[i] = '\\0';\n", ""), "Zero-fill mismatch"),
])
def test_unrolling_does_not_hide_semantic_omissions(candidate: str, expected: str) -> None:
    verdict, findings = _verify(candidate)

    assert verdict == Verdict.FAIL
    assert any(finding.startswith(expected) for finding in findings), findings


def test_removed_early_exit_leaves_unexplained_flow() -> None:
    candidate = CANDIDATE.replace("        if (c == 0)\n            break;\n", "")
    verdict, findings = _verify(candidate)

    assert verdict == Verdict.UNKNOWN
    assert any("restructuring" in finding for finding in findings)


def test_unrolling_does_not_hide_a_deleted_independent_side_effect() -> None:
    decompiled = DECOMPILE.replace("  return;\n", "  Con_DPrintf(out);\n  Con_DPrintf(in);\n  return;\n", 1)
    backend = _UnrolledBackend(decompiled, [*ASM_CALLS, "Con_DPrintf", "Con_DPrintf"])

    verdict, findings = _verify(CANDIDATE, backend)

    assert verdict == Verdict.FAIL
    assert "Named calls missing outside library normalization: Con_DPrintf (2 occurrence(s))" in findings


def test_one_unexplained_step_is_not_hidden_by_unrolling() -> None:
    # 15 backend sites cannot be the 16-step source loop; the other call stays a deficit.
    decompiled = DECOMPILE.replace("out[1] = tolower(v1);", "out[1] = Con_DPrintf(v1);")
    backend = _UnrolledBackend(decompiled, ["__x86.get_pc_thunk.bx", *["_tolower"] * 15, "Con_DPrintf"])

    assert _verify(CANDIDATE, backend)[0] == Verdict.FAIL
