"""Read-only physical operand evidence, independent of IDA register aliases."""
from __future__ import annotations

import inspect
import json
from typing import Any

ASSEMBLY_MARKER = "__RE_AGENT_ASSEMBLY__"


def assembly_script(addresses: list[str]) -> str:
    """Batch-decode only the instruction addresses supplied by disasm."""
    return (
        "from __future__ import annotations\nimport json\n"
        + inspect.getsource(_ida_assembly)
        + f"\nprint({ASSEMBLY_MARKER!r} + json.dumps(_ida_assembly({addresses!r})))\n"
    )


def assembly_result(payload: Any, addresses: list[str]) -> dict[str, str]:
    """Require a complete, address-bound result; never mix partial evidence."""
    if not isinstance(payload, dict) or payload.get("stderr"):
        raise RuntimeError("IDA physical operand decoder failed")
    lines = [line[len(ASSEMBLY_MARKER):] for line in str(payload.get("stdout", "")).splitlines()
             if line.startswith(ASSEMBLY_MARKER)]
    if len(lines) != 1:
        raise RuntimeError("IDA physical operand decoder returned no unique result")
    result = json.loads(lines[0])
    if not isinstance(result, dict) or result.get("ok") is not True:
        raise RuntimeError(f"IDA physical operand decoder failed: {result}")
    rows = result.get("instructions")
    if (not isinstance(rows, dict) or set(rows) != set(addresses)
            or any(not isinstance(value, str) or not value.strip() for value in rows.values())):
        raise RuntimeError("IDA physical operand decoder returned incomplete instructions")
    return rows


def _ida_assembly(addresses: list[str]) -> dict[str, Any]:
    """Self-contained IDAPython; preserve prefixes and non-register operands."""
    import importlib

    ua = importlib.import_module("ida_ua")
    ip = importlib.import_module("ida_idp")
    lines = importlib.import_module("ida_lines")
    dc = importlib.import_module("idc")
    result: dict[str, str] = {}
    try:
        for address in addresses:
            ea = int(address, 16)
            insn = ua.insn_t()
            if not ua.decode_insn(insn, ea):
                raise ValueError("Cannot decode " + address)
            text = lines.tag_remove(lines.generate_disasm_line(ea, 0) or "")
            aliases: list[str] = []
            replacements: list[tuple[int, int, str]] = []
            cursor = len(dc.print_insn_mnem(ea))
            for operand in insn.ops:
                if operand.type == ua.o_void:
                    break
                printed = dc.print_operand(ea, operand.n)
                if not printed:
                    continue  # implicit operand
                position = text.find(printed, cursor)
                if position < 0:
                    raise ValueError("Cannot locate operand at " + address)
                cursor = position + len(printed)
                if operand.type != ua.o_reg:
                    continue
                register = ip.get_reg_name(operand.reg, ua.get_dtype_size(operand.dtype))
                if not register:
                    raise ValueError("Cannot decode register at " + address)
                if printed != register:
                    replacements.append((position, cursor, register))
                    aliases.append(f"operand {operand.n}: {printed}={register}")
            for start, end, register in reversed(replacements):
                text = text[:start] + register + text[end:]
            if aliases:
                text += " ; IDA aliases: " + ", ".join(aliases)
            result[address] = text
        return {"ok": True, "instructions": result}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
