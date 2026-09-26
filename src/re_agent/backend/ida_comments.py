"""Managed function comments and fixed, guarded IDAPython operations."""
from __future__ import annotations

import inspect
import json
import re
from typing import Any

BEGIN = "[re-agent:begin]"
END = "[re-agent:end]"
COMMENT_MARKER = "__RE_AGENT_COMMENT__"


def managed_comment(current: str, body: str, *, replace: bool = False) -> str:
    """Replace our single delimited block, preserving all outside text exactly."""
    if BEGIN in body or END in body or "\x00" in body:
        raise ValueError("Proposal comment contains reserved markers or a NUL character")
    block = f"{BEGIN}\n{body}\n{END}"
    if replace or not current:
        return block
    pattern = re.compile(r"^" + re.escape(BEGIN) + r"\n.*?\n" + re.escape(END) + r"(?=\n|$)", re.M | re.S)
    match = pattern.search(current)
    if current.count(BEGIN) != 1 or current.count(END) != 1 or match is None:
        raise ValueError(
            "Existing function comment has no unique valid re-agent block; "
            "preview --replace-function-comment with --address to replace the whole comment"
        )
    return current[:match.start()] + block + current[match.end():]


def comment_script(request: dict[str, Any]) -> str:
    """Encode proposal text as JSON data, never executable Python."""
    return (
        "from __future__ import annotations\nimport json\n"
        + inspect.getsource(_ida_comment)
        + f"\nprint({COMMENT_MARKER!r} + json.dumps(_ida_comment(json.loads({json.dumps(request)!r}))))\n"
    )


def comment_result(payload: Any) -> dict[str, Any]:
    """Require one explicit successful result, including a complete snapshot."""
    if not isinstance(payload, dict) or payload.get("stderr"):
        raise RuntimeError(f"IDA comment helper failed: {payload}")
    lines = [line[len(COMMENT_MARKER):] for line in str(payload.get("stdout", "")).splitlines()
             if line.startswith(COMMENT_MARKER)]
    if len(lines) != 1:
        raise RuntimeError("IDA comment helper returned no unique result")
    try:
        result = json.loads(lines[0])
    except ValueError as exc:
        raise RuntimeError("IDA comment helper returned invalid JSON") from exc
    if (not isinstance(result, dict) or result.get("ok") is not True or result.get("error")
            or not isinstance(result.get("comment"), str) or not isinstance(result.get("address"), str)):
        raise RuntimeError(f"IDA comment operation failed: {result}")
    return result


def _ida_comment(request: dict[str, Any]) -> dict[str, Any]:
    """Self-contained helper: touch only the non-repeatable function comment."""
    import importlib

    funcs = importlib.import_module("ida_funcs")
    api = importlib.import_module("idaapi")
    names = importlib.import_module("ida_name")
    try:
        address = request["address"]
        try:
            ea = int(address, 16)
        except ValueError:
            ea = names.get_name_ea(api.BADADDR, address)
        function = funcs.get_func(ea)
        if function is None or function.start_ea != ea:
            raise ValueError("Target must resolve to an exact function entry")
        current = funcs.get_func_cmt(function, False) or ""
        if request["mode"] == "apply":
            if current != request["expected"]:
                raise ValueError("Function comment changed since preflight; regenerate the plan")
            proposed = request["proposed"]
            if not isinstance(proposed, str) or "\x00" in proposed:
                raise ValueError("Invalid proposed comment")
            if current != proposed:
                if not funcs.set_func_cmt(function, proposed, False):
                    raise RuntimeError("IDA rejected the function comment")
                current = funcs.get_func_cmt(function, False) or ""
                if current != proposed:
                    raise RuntimeError("Function comment readback mismatch")
        elif request["mode"] != "read":
            raise ValueError("Unknown comment operation")
        return {"ok": True, "address": hex(ea), "comment": current}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
