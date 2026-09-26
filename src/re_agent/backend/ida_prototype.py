"""Fixed IDAPython operations for guarded function prototype refinements.

Only JSON data crosses into the helper. It runs inside IDA, never locally, and
uses IDA's type parser and ABI layout rather than parsing C types in the CLI.
"""
from __future__ import annotations

import inspect
import json
from typing import Any

PROTOTYPE_MARKER = "__RE_AGENT_PROTOTYPE__"


class PrototypeOperationError(RuntimeError):
    """A helper failure with an explicit indication of possible mutation."""

    def __init__(self, message: str, *, write_attempted: bool, code: str = "rejected") -> None:
        super().__init__(message)
        self.write_attempted = write_attempted
        self.code = code


def prototype_script(request: dict[str, Any]) -> str:
    """Encode data as a Python string literal, never executable source."""
    return (
        "from __future__ import annotations\nimport json\n"
        + inspect.getsource(_ida_prototype)
        + f"\nprint({PROTOTYPE_MARKER!r} + json.dumps(_ida_prototype(json.loads({json.dumps(request)!r}))))\n"
    )


def prototype_result(payload: Any) -> dict[str, Any]:
    """Reject empty, malformed and error responses (including py_eval stderr)."""
    if not isinstance(payload, dict) or payload.get("stderr"):
        raise RuntimeError(f"IDA prototype helper failed: {payload}")
    stdout = str(payload.get("stdout", ""))
    lines = [line[len(PROTOTYPE_MARKER):] for line in stdout.splitlines() if line.startswith(PROTOTYPE_MARKER)]
    if len(lines) != 1:
        raise RuntimeError("IDA prototype helper returned no unique result")
    try:
        result = json.loads(lines[0])
    except ValueError as exc:
        raise RuntimeError("IDA prototype helper returned invalid JSON") from exc
    if not isinstance(result, dict) or result.get("error") or result.get("ok") is not True:
        raise PrototypeOperationError(
            f"IDA prototype operation failed: {result}",
            write_attempted=not isinstance(result, dict) or result.get("write_attempted") is not False,
            code=str(result.get("code", "rejected")) if isinstance(result, dict) else "rejected",
        )
    return result


def _ida_prototype(request: dict[str, Any]) -> dict[str, Any]:
    """Self-contained helper, executed under py_eval in the IDA process."""
    import importlib
    import re

    ti = importlib.import_module("ida_typeinf")
    na = importlib.import_module("ida_nalt")
    funcs = importlib.import_module("ida_funcs")
    api = importlib.import_module("idaapi")
    hx = importlib.import_module("ida_hexrays")

    class UnsupportedChange(ValueError):
        pass

    class StaleProposal(ValueError):
        pass

    def serial(tif: Any) -> list[str]:
        return [part.hex() if part else "" for part in tif.serialize()]

    def decompile(ea: int, *, fresh: bool = False) -> tuple[Any, str]:
        if fresh:
            hx.mark_cfunc_dirty(ea, False)
        cf = hx.decompile(ea)
        tif = ti.tinfo_t()
        if cf is None or not cf.get_func_type(tif) or not tif.is_func():
            raise ValueError("Cannot independently read the decompiled function type")
        return tif, str(cf)

    def snapshot(ea: int) -> tuple[Any, dict[str, Any]]:
        tif = ti.tinfo_t()
        explicit = bool(na.get_tinfo(tif, ea))
        if not explicit:
            tif, _ = decompile(ea)
        if not tif.is_func():
            raise ValueError("Target has no usable function type")
        return tif, {
            "address": hex(ea), "declaration": str(tif), "explicit": explicit,
            "serialized": serial(tif), "type_key": serial(tif)[0],
            "source": "database" if explicit else "decompiler",
        }

    def existing_type(name: str) -> Any:
        tif = ti.tinfo_t()
        if not tif.get_named_type(None, name):
            raise ValueError("Missing referenced type: " + name)
        return tif

    def parse(text: str) -> Any:
        # Deliberately narrow grammar: one plain function declaration. Checking
        # named types BEFORE parsing prevents implicit forward declarations or
        # imports. No struct definitions, attributes, arrays or nested declarators.
        text = text.strip().removesuffix(";").strip()
        match = re.fullmatch(
            r"(.+?)\s*(__cdecl|__stdcall|__fastcall|__thiscall)\s*"
            r"(?:[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)?\s*\(([^()]*)\)", text,
        )
        if match is None:
            raise ValueError("Unsupported declaration: require one plain prototype with an explicit calling convention")
        type_pattern = (
            r"(?:(?:const|volatile)\s+)*"
            r"(?:unsigned\s+long\s+long|signed\s+long\s+long|long\s+long|"
            r"(?:unsigned|signed)\s+(?:char|short|int|long|__int64)|"
            r"[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)"
            r"(?:\s*\*\s*(?:(?:const|volatile)\s*)*)?"
        )
        builtins = {"void", "bool", "char", "short", "int", "long", "float", "double",
                    "signed", "unsigned", "__int8", "__int16", "__int32", "__int64"}
        parts = [match[1], *([] if match[3].strip() in {"", "void"} else match[3].split(","))]
        for index, part in enumerate(parts):
            pattern = "(" + type_pattern + ")" + (r"(?:\s*([A-Za-z_]\w*))?" if index else "")
            item = re.fullmatch(pattern, part.strip())
            if item is None:
                raise ValueError("Unsupported parameter/return declaration: " + part)
            base = re.sub(r"\b(const|volatile)\b|\*", "", item[1]).strip()
            if not all(token in builtins for token in base.split()):
                existing_type(base)
        tif = ti.tinfo_t()
        # IDA's printer omits the function name, but parse_decl needs one.
        normalized = f"{match[1]} {match[2]} __re_agent_target({match[3]});"
        parsed = ti.parse_decl(tif, None, normalized, ti.PT_SIL | ti.PT_TYP)
        if parsed is None or not tif.is_func():
            raise ValueError("Invalid function declaration")
        return tif

    def location(loc: Any) -> tuple[Any, ...]:
        if loc.is_reg1():
            return ("register", loc.reg1(), loc.regoff())
        if loc.is_stkoff():
            return ("stack", loc.stkoff())
        if loc.is_badloc():
            return ("none",)
        raise UnsupportedChange("Unsupported ABI argument location")

    def refinement(before: Any, after: Any) -> tuple[list[dict[str, str]], bool]:
        old, new = ti.func_type_data_t(), ti.func_type_data_t()
        if not before.get_func_details(old) or not after.get_func_details(new):
            raise UnsupportedChange("Cannot calculate function ABI")
        old_cc = old.get_cc() if hasattr(old, "get_cc") else old.cc
        new_cc = new.get_cc() if hasattr(new, "get_cc") else new.cc
        allowed = {ti.CM_CC_CDECL, ti.CM_CC_STDCALL, ti.CM_CC_FASTCALL, ti.CM_CC_THISCALL}
        if old_cc not in allowed or old_cc != new_cc:
            raise UnsupportedChange("Calling convention changes or special conventions are unsupported")
        if old.flags != new.flags or len(old) != len(new):
            raise UnsupportedChange("Function flags and argument count must be preserved")
        if location(old.retloc) != location(new.retloc) or old.stkargs != new.stkargs:
            raise UnsupportedChange("Return/stack ABI layout changed")
        differences: list[dict[str, str]] = []
        corrections = False

        def complete_class(tif: Any) -> bool:
            name = tif.get_type_name()
            return bool(tif.is_udt() and not tif.is_union() and name
                        and existing_type(name).is_udt() and tif.get_size() != api.BADSIZE)

        def data_pointer(tif: Any) -> bool:
            if not tif.is_ptr() or tif.is_const() or tif.is_volatile():
                return False
            obj = tif.get_pointed_object()
            return bool(not obj.is_const() and not obj.is_volatile()
                        and (obj.is_void() or complete_class(obj)))

        def compare(a: Any, b: Any, position: str) -> None:
            nonlocal corrections
            if a.equals_to(b):
                return
            difference = {"position": position, "before": str(a), "after": str(b)}
            differences.append(difference)
            same_width = a.get_size() == b.get_size() and a.get_size() not in {0, api.BADSIZE}
            if position != "return" and a.is_ptr() and b.is_ptr() and same_width:
                pa, pb = a.get_pointed_object(), b.get_pointed_object()
                if (pa.is_void() and complete_class(pb) and a.is_const() == b.is_const()
                        and a.is_volatile() == b.is_volatile() and pa.is_const() == pb.is_const()
                        and pa.is_volatile() == pb.is_volatile()):
                    difference["kind"] = "refinement"
                    return
            integer_change = a.is_integral() and (
                b.is_integral() or data_pointer(b)
            )
            # bool/enums, qualifiers, floats and arbitrary pointer casts are not corrections.
            if (same_width and integer_change and not a.is_bool() and not b.is_bool()
                    and not a.is_enum() and not b.is_enum()
                    and not a.is_const() and not a.is_volatile()
                    and not b.is_const() and not b.is_volatile()):
                difference["kind"] = "abi-type-correction"
                corrections = True
                return
            raise UnsupportedChange("Only qualifier-preserving void pointer refinements and "
                                    "same-width integer to integer/data-pointer corrections are supported: " + position)

        compare(old.rettype, new.rettype, "return")
        for index, (previous, proposed) in enumerate(zip(old, new, strict=True)):
            if previous.flags != proposed.flags or location(previous.argloc) != location(proposed.argloc):
                raise UnsupportedChange("Argument flags or ABI location changed")
            compare(previous.type, proposed.type, f"arg:{index}")
        if corrections and request.get("allow_abi_type_corrections") is not True:
            raise UnsupportedChange("Return type or argument correction requires --allow-abi-type-corrections")
        return differences, corrections

    write_attempted = False
    try:
        target = str(request["address"])
        try:
            ea = int(target, 16)
        except ValueError:
            ea = api.get_name_ea(api.BADADDR, target)
        fn = funcs.get_func(ea)
        if fn is None or fn.start_ea != ea:
            raise ValueError("Prototype target must resolve to an exact function entry")
        current, state = snapshot(ea)
        mode = request["mode"]
        if mode == "read":
            return {"ok": True, "current": state}
        if mode == "plan":
            for name in request.get("required_types", []):
                existing_type(name)
            expected = parse(request["expected_current"])
            proposed = parse(request["declaration"])
            differences, corrections = refinement(expected, proposed)
            unchanged = current.equals_to(proposed)
            if not unchanged and not current.equals_to(expected):
                raise StaleProposal("Stale prototype proposal: current type differs from expected_current")
            return {"ok": True, "current": state, "proposed": str(proposed),
                    "proposed_key": serial(proposed)[0], "unchanged": unchanged,
                    "differences": differences, "requires_abi_corrections": corrections, "abi_check": "compatible"}
        if mode == "apply":
            original = request["original"]
            if state["serialized"] != original["serialized"] or state["explicit"] != original["explicit"]:
                raise StaleProposal("Stale prototype: changed after preflight")
            proposed = parse(request["declaration"])
            refinement(current, proposed)
            if serial(proposed)[0] != request["proposed_key"]:
                raise ValueError("Proposed type changed after preflight")
            write_attempted = True
            if not ti.apply_tinfo(ea, proposed, ti.TINFO_DEFINITE):
                raise ValueError("IDA rejected function type application")
            return {"ok": True}
        if mode == "verify":
            actual, code = decompile(ea, fresh=True)
            if state["type_key"] != request["proposed_key"] or serial(actual)[0] != request["proposed_key"]:
                raise ValueError("Independent prototype/decompilation readback mismatch")
            return {"ok": True, "current": state, "decompiled": code}
        if mode == "restore":
            original = request["original"]
            if state["serialized"] == original["serialized"] and state["explicit"] == original["explicit"]:
                return {"ok": True, "current": state}
            if state["type_key"] != request["proposed_key"]:
                raise ValueError("Refusing to overwrite an unexpected type during recovery")
            write_attempted = True
            if original["explicit"]:
                tif = ti.tinfo_t()
                parts = [bytes.fromhex(part) for part in original["serialized"]]
                if not tif.deserialize(None, *parts) or not ti.apply_tinfo(ea, tif, ti.TINFO_DEFINITE):
                    raise ValueError("Could not restore original explicit type")
            else:
                na.del_tinfo(ea)
            hx.mark_cfunc_dirty(ea, False)
            _, restored = snapshot(ea)
            if restored["serialized"] != original["serialized"] or restored["explicit"] != original["explicit"]:
                raise ValueError("Original type state was not restored")
            return {"ok": True, "current": restored}
        raise ValueError("Unknown prototype operation")
    except Exception as exc:
        return {"ok": False, "error": str(exc), "write_attempted": write_attempted,
                "code": "unsupported-change" if isinstance(exc, UnsupportedChange) else
                        "stale" if isinstance(exc, StaleProposal) else "rejected"}
