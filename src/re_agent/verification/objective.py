"""Conservative structural verification that does not rely on an LLM."""

from __future__ import annotations

import json
import re
from collections import Counter

from re_agent.backend.protocol import REBackend
from re_agent.backend.stages import backend_task
from re_agent.core.models import FunctionTarget, ObjectiveVerdict, Verdict
from re_agent.utils.call_evidence import (
    CallEvidence,
    asm_call_evidence,
    bind_indirect_sites,
    code_call_evidence,
    mask_nonordinary_calls,
    pcode_call_evidence,
)
from re_agent.utils.text import count_control_flow, mask_non_code
from re_agent.verification.inline_library import (
    has_container_abstraction,
    has_sort_abstraction,
    has_sort_expansion,
    has_vector_expansion,
    mask_regions,
    mechanical_call,
    named_calls,
    sort_regions,
    unresolved_sort_flow,
    unresolved_vector_flow,
    vector_regions,
)
from re_agent.verification.recovered_helpers import helper_sequences, mask_matched_sites, match_helpers
from re_agent.verification.unrolling import (
    call_counter,
    callee_key,
    fixed_trip_loops,
    has_zero_fill_expansion,
    has_zero_write,
    unrolled_call_credit,
    unrolled_flow_budget,
)


@backend_task("objective")
def verify_candidate(
    code: str,
    target: FunctionTarget,
    backend: REBackend,
    call_count_tolerance: int = 3,
    control_flow_tolerance: int = 2,
) -> ObjectiveVerdict:
    """Return FAIL only on strong structural mismatches, else PASS/UNKNOWN."""
    if not code.strip():
        return ObjectiveVerdict(
            verdict=Verdict.FAIL,
            summary="No candidate code produced",
            findings=["Candidate code is empty"],
        )

    raw_source_body, helpers = _candidate_functions(code, target)
    source_body = mask_non_code(raw_source_body)
    source_calls = code_call_evidence(source_body)
    source_call_count = source_calls.count("ordinary")
    source_flow_count = count_control_flow(source_body)
    # Fixed-trip loops can explain exact per-callee unrolling, never a deficit.
    loops = fixed_trip_loops(raw_source_body)
    source_callees = call_counter(source_calls)
    machine_calls: list[CallEvidence] = []

    findings: list[str] = []
    uncertainties: list[str] = []
    call_notes: list[str] = []
    unrolling_notes: list[str] = []
    checks_run = 0

    def unrolled_credit(evidence: CallEvidence, origin: str) -> Counter[str]:
        credit = unrolled_call_credit(loops, source_callees, call_counter(evidence))
        if credit:
            unrolling_notes.append(f"{origin}: fixed-trip loop unrolling matches " + ", ".join(
                f"{name} ({source_callees[name]} source site(s) + {extra} unrolled)"
                for name, extra in sorted(credit.items())
            ))
        return credit

    def check_calls(evidence: CallEvidence, origin: str, message: str, *, lowering: int = 0,
                    library_expansion: bool = False, uncertain_aliases: int = 0,
                    source_count: int = source_call_count) -> None:
        if evidence.count("pic") or evidence.count("decompiler_expr") or not evidence.comparable:
            call_notes.extend(evidence.diagnostics(origin))
        if not evidence.comparable:
            uncertainties.append(f"{origin} call comparison is inconclusive: {evidence.describe()}")
        # Direct retained calls provide a lower bound. Unknown/implicit calls
        # cannot increase the source's budget or hide an independent deficit.
        deficit = evidence.count("ordinary") - uncertain_aliases - source_count
        if evidence.complete and deficit >= call_count_tolerance and deficit > 0:
            unrolled = sum(unrolled_credit(evidence, origin).values())
            if unrolled and deficit - unrolled < call_count_tolerance:
                uncertainties.append(f"{message}; {unrolled} extra call sites match fixed-trip loop unrolling")
            elif library_expansion and deficit - lowering < call_count_tolerance:
                uncertainties.append(
                    f"{message}; {lowering} direct lowering/library calls make totals incomparable"
                )
            elif library_expansion and origin == "Decompile":
                uncertainties.append(message)
            else:
                findings.append(message)

    try:
        decompile = backend.decompile(target.address)
    except Exception as exc:
        return ObjectiveVerdict(
            verdict=Verdict.UNKNOWN,
            summary="Objective verifier could not read decompile output",
            findings=[str(exc)],
        )

    # raw_output may be a JSON envelope, with escaped code and ref metadata.
    # Mask before slicing so braces in literals cannot select a false body.
    masked_decompile = mask_non_code(decompile.decompiled)
    decompile_body = _extract_body(masked_decompile)
    decompile_calls = code_call_evidence(decompile_body, decompiled=True)
    # Read only backend evidence here. Candidate address comments and checker
    # verdicts never authorize an exception to the independent verifier.
    vector_expanded = has_vector_expansion(decompile.decompiled) and has_container_abstraction(source_body)
    sort_expanded = has_sort_expansion(decompile.decompiled) and has_sort_abstraction(source_body)
    expanded = vector_expanded or sort_expanded
    regions = vector_regions(decompile.decompiled) if vector_expanded else []
    if sort_expanded:
        regions.extend(sort_regions(decompile.decompiled))
    residual = _extract_body(mask_regions(decompile.decompiled, regions))
    unresolved_sort = unresolved_sort_flow(residual)
    # Unmatched algorithm expansion must not borrow the vector fallback. A
    # candidate without sort still has to account for its remaining flow.
    incomplete_expansion = (
        vector_expanded and unresolved_vector_flow(residual) and not unresolved_sort
        or sort_expanded and unresolved_sort
    )
    region_notes = [
        f"{region.kind} region at text offsets {region.start}:{region.end}; "
        f"IDA statement addresses: {', '.join(hex(ea) for ea in sorted(region.addresses)) or 'unavailable'}"
        for region in regions
    ]
    if sort_expanded and unresolved_sort:
        region_notes.append("Unresolved std::sort expansion remains visible; helper names do not prove CFG boundaries")
    constant_return = re.compile(r"\{\s*return\s+(-?(?:0x[0-9a-fA-F]+|[0-9]+))\s*;\s*\}")
    expected_constant = constant_return.fullmatch(decompile_body.strip())
    actual_constant = constant_return.fullmatch(source_body.strip())
    if expected_constant and actual_constant:
        checks_run += 1

        def integer(text: str) -> int:
            return int(text, 16) if "0x" in text.lower() else int(text, 10)

        if integer(expected_constant.group(1)) != integer(actual_constant.group(1)):
            findings.append("Constant return value differs from decompiled evidence")
    decompile_flow_count = count_control_flow(decompile_body)
    zero_fill_expanded = has_zero_fill_expansion(decompile_body)
    if decompile.callees is not None:
        checks_run += 1
        if decompile.callees - source_call_count >= call_count_tolerance and decompile.callees > source_call_count:
            # This is a backend's callee-list cardinality, not a call-site
            # count. Without individual targets it cannot establish a FAIL.
            uncertainties.append(
                f"Backend reports {decompile.callees} callees, candidate has {source_call_count} calls; "
                "callee totals and source call sites are not directly comparable"
            )

    if backend.capabilities.has_asm:
        try:
            asm = backend.get_asm(target.address)
        except Exception:
            asm = None
        if asm is not None:
            checks_run += 1
            asm_calls = asm_call_evidence(asm.instructions, asm.call_count)
            machine_calls.append(asm_calls)
            mechanical = sum(
                site.kind == "ordinary" and mechanical_call(f"call {site.target}", include_sort=sort_expanded)
                for site in asm_calls.sites
            ) if expanded else 0
            check_calls(
                asm_calls, "ASM",
                f"ASM call mismatch: disassembly has {asm.call_count} calls, candidate has {source_call_count}",
                lowering=mechanical, library_expansion=expanded,
            )

    if getattr(backend.capabilities, "has_cfg", False):
        cfg = _read_ir_artifact(backend, "get_cfg", target.address)
        if isinstance(cfg, list):
            cfg = [item for item in cfg if isinstance(item, dict) and "index" in item]
        if isinstance(cfg, list) and cfg:
            checks_run += 1
            # Source keywords do not predict machine basic-block counts: early
            # returns, short-circuit conditions and switches all change topology.
            # Only use CFG topology to flag wholesale removal of branching.
            branching_blocks = sum(
                isinstance(block.get("out"), list) and len(set(block["out"])) > 1
                for block in cfg
                if isinstance(block.get("out"), list)
                and all(isinstance(edge, int) for edge in block["out"])
            )
            source_has_branching = source_flow_count > 0 or bool(re.search(r"\?|&&|\|\|", source_body))
            if branching_blocks >= control_flow_tolerance and branching_blocks > 0 and not source_has_branching:
                message = (
                    f"CFG mismatch: binary has {branching_blocks} branching blocks, "
                    "candidate has no explicit control flow or conditional expressions"
                )
                if expanded and (incomplete_expansion or count_control_flow(residual) == 0):
                    uncertainties.append(message + "; branching may belong to inline library implementation")
                else:
                    findings.append(message)

    if getattr(backend.capabilities, "has_pcode", False):
        pcode = _read_ir_artifact(backend, "get_pcode", target.address)
        if isinstance(pcode, list):
            pcode = [item for item in pcode if isinstance(item, dict) and item.get("opcode")]
        if isinstance(pcode, list) and pcode:
            checks_run += 1
            opcodes = [str(item.get("opcode", "")).upper() for item in pcode if isinstance(item, dict)]
            ir_calls = pcode_call_evidence(pcode)
            machine_calls.append(ir_calls)
            check_calls(
                ir_calls, "P-code",
                f"P-code call mismatch: normalized IR has {ir_calls.raw_count} calls, "
                f"candidate has {source_call_count}",
                lowering=ir_calls.count("ordinary") if expanded else 0, library_expansion=expanded,
            )
            ir_returns = sum(op == "RETURN" for op in opcodes)
            source_returns = source_body.count("return")
            if ir_returns >= 2 and source_returns == 0:
                findings.append(
                    f"P-code return mismatch: normalized IR has {ir_returns} returns, candidate has no explicit return"
                )

    # A bare name in pseudocode can denote a callback-table slot. A new
    # member spelling makes identity uncertain, but cannot establish a mapping.
    machine_callees: Counter[str] = Counter()
    for evidence in machine_calls:
        # A scoped C++ method with the same basename cannot establish the
        # identity of a bare data object. Preserve scope and leading underscores.
        direct_names: Counter[str] = Counter()
        for site in evidence.sites:
            if site.kind == "ordinary":
                annotated = re.fullmatch(r"(?:0x)?[\da-fA-F]+\s+<([^<>]+)>", site.target)
                symbol = annotated[1] if annotated else site.target
                direct_names[symbol.partition("(")[0].removesuffix("@plt")] += 1
        machine_callees |= direct_names
    # Comment masking preserves offsets. Only the backend's original text can
    # supply the statement addresses corresponding to its machine evidence.
    body_start = masked_decompile.find(decompile_body)
    raw_body = decompile.decompiled[body_start:body_start + len(decompile_body)]
    decompile_calls = bind_indirect_sites(raw_body, decompile_calls, machine_calls)
    recovered = match_helpers(helpers, source_body, source_calls, decompile_body, decompile_calls)
    matched = set(recovered.decompiled)
    remaining = CallEvidence(tuple(s for s in decompile_calls.sites if s not in matched),
                             decompile_calls.raw_count - len(matched))
    decompile_unrolled = unrolled_call_credit(loops, source_callees, call_counter(remaining))
    member_sites = Counter(
        site.target for site in source_calls.sites
        if site.kind == "ordinary" and source_body[:site.start].rstrip().endswith((".", "->"))
    )
    decompiled_names = Counter(site.target for site in decompile_calls.sites if site.kind == "ordinary")
    new_members = member_sites - decompiled_names
    possible_aliases: Counter[str] = Counter()
    if new_members:
        source_names = Counter(site.target for site in source_calls.sites if site.kind == "ordinary")
        bare_names = Counter(
            site.target for site in remaining.sites if site.kind == "ordinary"
            and re.fullmatch(r"\w+", site.target) and not decompile_body[:site.start].rstrip().endswith((".", "->"))
        )
        for name, occurrences in bare_names.items():
            unmatched = occurrences - max(source_names[name], machine_callees[name])
            if unmatched > 0:
                possible_aliases[name] = min(unmatched, new_members.total())
                locations = ", ".join(site.location for site in decompile_calls.sites if site.target == name)
                uncertainties.append(f"Unresolved call identity: {name} at {locations}; "
                                     f"no verified mapping to candidate member calls ({decompile_calls.raw_count} "
                                     f"raw decompile sites, {source_calls.raw_count} raw candidate sites)")

    if "{" in decompile_body and decompile_calls.raw_count:
        checks_run += 1
        message = (
            f"Decompiled call mismatch: decompiled body has {decompile_calls.count('ordinary')} ordinary call sites "
            f"(raw lexical sites {decompile_calls.raw_count}), candidate has {source_call_count} calls"
        )
        if recovered.extra_sites:
            uncertainties.append(f"{message}; possible inline expansion of {recovered.describe()} "
                                 f"accounts for {recovered.extra_sites} extra sites")
        check_calls(
            remaining, "Decompile", message, source_count=source_call_count - len(recovered.source),
            library_expansion=expanded,
            uncertain_aliases=min(possible_aliases.total(), new_members.total()),
        )

    if decompile_flow_count >= 2:
        checks_run += 1
        flow_diff = decompile_flow_count - source_flow_count
        if flow_diff >= control_flow_tolerance and source_flow_count < decompile_flow_count:
            message = (
                f"Control-flow mismatch: decompile has {decompile_flow_count} lexical control-flow tokens, "
                f"candidate has {source_flow_count}"
            )
            residual_count = count_control_flow(residual)
            flow_budget = unrolled_flow_budget(loops, decompile_unrolled, zero_fill_expanded)
            if flow_budget and flow_diff - flow_budget < control_flow_tolerance:
                uncertainties.append(f"{message}; fixed-trip loop unrolling and tail zero fill account for up to "
                                     f"{flow_budget} branches")
            elif expanded and (incomplete_expansion or residual_count - source_flow_count < control_flow_tolerance):
                uncertainties.append(f"{message}; bounded normalization leaves {residual_count}; "
                                     "remaining compiler expansion is not a comparable source count")
            else:
                uncertainties.append(f"{message}; equivalent control-flow restructuring can change lexical counts")

    if unrolling_notes and zero_fill_expanded and not has_zero_write(raw_source_body):
        findings.append("Zero-fill mismatch: decompiled body stores expanded zero padding, "
                        "candidate writes no zero padding")

    if uncertainties or call_notes or new_members:
        binary_text = mask_nonordinary_calls(decompile_body, evidence=decompile_calls)
        source_text = mask_nonordinary_calls(source_body)
        missing_calls = named_calls(mask_matched_sites(binary_text, recovered.decompiled)) - named_calls(
            mask_matched_sites(source_text, recovered.source), decompiled=False)
        for name in list(missing_calls):
            # Exactly matched unrolled steps are not missing source calls.
            missing_calls[name] -= decompile_unrolled[callee_key(name)]
        missing_calls -= possible_aliases
        if missing_calls:
            findings.append("Named calls missing outside library normalization: " + ", ".join(
                f"{name} ({count} occurrence(s))" for name, count in sorted(missing_calls.items())
            ))

    if findings:
        return ObjectiveVerdict(
            verdict=Verdict.FAIL,
            summary="Objective verifier found structural mismatches",
            findings=[*findings, *uncertainties, *call_notes, *unrolling_notes,
                      *(region_notes if uncertainties else [])],
        )
    if uncertainties:
        return ObjectiveVerdict(
            verdict=Verdict.UNKNOWN,
            summary="Structural comparison is inconclusive",
            findings=[*uncertainties, *call_notes, *unrolling_notes, *region_notes],
        )
    if checks_run == 0:
        return ObjectiveVerdict(
            verdict=Verdict.UNKNOWN,
            summary="Objective verifier had insufficient structural data",
            findings=[],
        )
    return ObjectiveVerdict(
        verdict=Verdict.PASS,
        summary="No structural mismatches found",
        findings=call_notes,
    )


def _candidate_functions(code: str, target: FunctionTarget) -> tuple[str, dict[str, list[str]]]:
    """Return the target top-level function body, ignoring leading declarations.

    Unlike the decompiler output (which ``_extract_body`` handles), a candidate
    may legitimately define helper structs before the function.  Counting calls
    and control flow over the whole file would inflate the candidate's counts
    and hide genuine shortfalls, so the candidate side uses the same locator as
    the candidate overlay.  When the candidate also defines a helper function,
    the locator selects the definition naming *target*; falling back to the
    first definition would score the helper's calls instead of the function's.
    """
    from re_agent.parity.source_indexer import SourceIndexer
    from re_agent.verification.candidate import _select_target_definition

    definitions, _ = SourceIndexer._locate_function_definitions(code)
    if not definitions:
        return code, {}
    selected = _select_target_definition(code, definitions, target) if len(definitions) > 1 else None
    open_brace, close_brace = selected if selected is not None else definitions[0]
    helpers = helper_sequences(mask_non_code(code), definitions, selected) if selected else {}
    return code[open_brace : close_brace + 1], helpers


def _extract_body(text: str) -> str:
    open_brace = text.find("{")
    close_brace = text.rfind("}")
    if open_brace == -1 or close_brace == -1 or close_brace <= open_brace:
        return text
    return text[open_brace : close_brace + 1]


def _read_ir_artifact(backend: REBackend, method_name: str, target: str) -> object | None:
    method = getattr(backend, method_name, None)
    if not callable(method):
        return None
    try:
        artifact = method(target)
        if artifact is None:
            return None
        payload = json.loads(artifact.content)
    except (AttributeError, json.JSONDecodeError, OSError, RuntimeError, TypeError, ValueError):
        return None
    if isinstance(payload, dict):
        data = payload.get("data")
        if isinstance(data, list) and any(isinstance(item, dict) and "error" in item for item in data):
            return None
        return data
    return None
