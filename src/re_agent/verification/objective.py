"""Conservative structural verification that does not rely on an LLM."""

from __future__ import annotations

import json
import re

from re_agent.backend.protocol import REBackend
from re_agent.backend.stages import backend_task
from re_agent.core.models import FunctionTarget, ObjectiveVerdict, Verdict
from re_agent.utils.call_evidence import (
    CallEvidence,
    asm_call_evidence,
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

    source_body = mask_non_code(_extract_candidate_body(code, target))
    source_call_count = code_call_evidence(source_body).count("ordinary")
    source_flow_count = count_control_flow(source_body)

    findings: list[str] = []
    uncertainties: list[str] = []
    call_notes: list[str] = []
    checks_run = 0

    def check_calls(evidence: CallEvidence, origin: str, message: str, *, lowering: int = 0,
                    library_expansion: bool = False) -> None:
        if evidence.count("pic") or evidence.count("decompiler_expr") or not evidence.comparable:
            call_notes.extend(evidence.diagnostics(origin))
        if not evidence.comparable:
            uncertainties.append(f"{origin} call comparison is inconclusive: {evidence.describe()}")
        # Direct retained calls provide a lower bound. Unknown/implicit calls
        # cannot increase the source's budget or hide an independent deficit.
        deficit = evidence.count("ordinary") - source_call_count
        if evidence.complete and deficit >= call_count_tolerance and deficit > 0:
            if library_expansion and deficit - lowering < call_count_tolerance:
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
    decompile_body = _extract_body(mask_non_code(decompile.decompiled))
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
    if "{" in decompile_body and decompile_calls.raw_count:
        checks_run += 1
        check_calls(
            decompile_calls, "Decompile",
            f"Decompiled call mismatch: decompiled body has {decompile_calls.count('ordinary')} ordinary call sites "
            f"(raw lexical sites {decompile_calls.raw_count}), "
            f"candidate has {source_call_count} calls",
            library_expansion=expanded,
        )
    if decompile.callees is not None:
        checks_run += 1
        if decompile.callees - source_call_count >= call_count_tolerance and decompile.callees > source_call_count:
            # This is a backend's callee-list cardinality, not a call-site
            # count. Without individual targets it cannot establish a FAIL.
            uncertainties.append(
                f"Backend reports {decompile.callees} callees, candidate has {source_call_count} calls; "
                "callee totals and source call sites are not directly comparable"
            )

    if decompile_flow_count >= 2:
        checks_run += 1
        flow_diff = decompile_flow_count - source_flow_count
        if flow_diff >= control_flow_tolerance and source_flow_count < decompile_flow_count:
            message = (
                f"Control-flow mismatch: decompile has {decompile_flow_count} branches/loops, "
                f"candidate has {source_flow_count}"
            )
            residual_count = count_control_flow(residual)
            if expanded and (incomplete_expansion or residual_count - source_flow_count < control_flow_tolerance):
                uncertainties.append(f"{message}; bounded normalization leaves {residual_count}; "
                                     "remaining compiler expansion is not a comparable source count")
            else:
                findings.append(message)

    if backend.capabilities.has_asm:
        try:
            asm = backend.get_asm(target.address)
        except Exception:
            asm = None
        if asm is not None:
            checks_run += 1
            asm_calls = asm_call_evidence(asm.instructions, asm.call_count)
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

    if uncertainties or call_notes:
        missing_calls = named_calls(mask_nonordinary_calls(decompile_body, decompiled=True)) - named_calls(
            mask_nonordinary_calls(source_body), decompiled=False,
        )
        if missing_calls:
            findings.append("Named calls missing outside library normalization: " + ", ".join(
                f"{name} ({count} occurrence(s))" for name, count in sorted(missing_calls.items())
            ))

    if findings:
        return ObjectiveVerdict(
            verdict=Verdict.FAIL,
            summary="Objective verifier found structural mismatches",
            findings=[*findings, *uncertainties, *call_notes, *(region_notes if uncertainties else [])],
        )
    if uncertainties:
        return ObjectiveVerdict(
            verdict=Verdict.UNKNOWN,
            summary="Call evidence or compiler expansion prevents independent structural comparison",
            findings=[*uncertainties, *call_notes, *region_notes],
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


def _extract_candidate_body(code: str, target: FunctionTarget | None = None) -> str:
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
        return code
    selected = _select_target_definition(code, definitions, target) if len(definitions) > 1 else None
    open_brace, close_brace = selected if selected is not None else definitions[0]
    return code[open_brace : close_brace + 1]


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
