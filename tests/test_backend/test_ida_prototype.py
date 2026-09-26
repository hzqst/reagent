"""Execute the IDA helper against a small type API double, including recovery."""
from __future__ import annotations

import copy
import json
import sys
from types import SimpleNamespace

import pytest

from re_agent.backend.ida_prototype import _ida_prototype, prototype_result, prototype_script


class Type:
    def __init__(self, name="", *, pointee=None, args=None, result=None, cc=128, flags=0, const=False):
        self.name, self.pointee, self.args, self.result = name, pointee, args, result
        self.cc, self.flags, self.const = cc, flags, const

    def __str__(self):
        return self.name

    def equals_to(self, other):
        return self.name == other.name

    def is_func(self):
        return self.args is not None

    def is_ptr(self):
        return self.pointee is not None

    def is_void(self):
        return self.name == "void"

    def is_udt(self):
        return self.name == "FileClass"

    def is_union(self):
        return False

    def is_const(self):
        return self.const

    def is_volatile(self):
        return False

    def get_size(self):
        return 4

    def get_pointed_object(self):
        return self.pointee

    def get_type_name(self):
        return self.name

    def get_named_type(self, til, name):
        if name != "FileClass":
            return False
        self.name = name
        return True

    def serialize(self):
        return self.name.encode(), b"this", None

    def deserialize(self, til, *parts):
        value = FUNCTIONS.get(parts[0].decode())
        if value is None:
            return False
        self.__dict__.update(copy.deepcopy(value.__dict__))
        return True

    def get_func_details(self, details):
        details.extend(self.args)
        details.cc, details.flags, details.rettype = self.cc, self.flags, self.result
        details.retloc, details.stkargs = loc("eax"), 0
        return True


class Details(list):
    def get_cc(self):
        return self.cc


def loc(register):
    return SimpleNamespace(is_reg1=lambda: True, reg1=lambda: register, regoff=lambda: 0)


def arg(tif, *, register="ecx", flags=0):
    return SimpleNamespace(type=tif, flags=flags, argloc=loc(register))


VOID_PTR = Type("void *", pointee=Type("void"))
CLASS_PTR = Type("FileClass *", pointee=Type("FileClass"))
OLD = "void *__thiscall(void *this)"
NEW = "void *__thiscall(FileClass *this)"
FUNCTIONS = {
    OLD: Type(OLD, args=[arg(VOID_PTR)], result=VOID_PTR),
    NEW: Type(NEW, args=[arg(CLASS_PTR)], result=VOID_PTR),
}


@pytest.fixture
def ida(monkeypatch):
    state = SimpleNamespace(current=copy.deepcopy(FUNCTIONS[OLD]), explicit=True, writes=[],
                            apply_ok=True, verify_bad=False, restore_ok=True, parsed=[])
    registry = copy.deepcopy(FUNCTIONS)

    def populate(out, value):
        out.__dict__.update(copy.deepcopy(value.__dict__))
        return True

    def parse(out, til, text, flags):
        state.parsed.append(text)
        canonical = text.replace(" __re_agent_target", "").replace("* __", "*__").removesuffix(";")
        if canonical not in registry:
            return None
        populate(out, registry[canonical])
        return ""  # IDA returns an empty string for successful type parsing.

    def apply(ea, tif, flags):
        state.writes.append(("apply", ea, str(tif)))
        if not state.apply_ok:
            return False
        state.current = copy.deepcopy(tif)
        state.explicit = True
        return True

    def remove(ea):
        state.writes.append(("delete", ea))
        state.explicit = False
        state.current = copy.deepcopy(registry[OLD])

    def decompile(ea):
        value = registry[OLD] if state.verify_bad else state.current
        return SimpleNamespace(get_func_type=lambda out: populate(out, value))

    modules = {
        "ida_typeinf": SimpleNamespace(tinfo_t=Type, func_type_data_t=Details, parse_decl=parse,
            PT_SIL=1, PT_TYP=4, TINFO_DEFINITE=1, CM_CC_CDECL=48, CM_CC_STDCALL=80,
            CM_CC_FASTCALL=112, CM_CC_THISCALL=128, apply_tinfo=apply),
        "ida_nalt": SimpleNamespace(get_tinfo=lambda out, ea: state.explicit and populate(out, state.current),
                                    del_tinfo=remove),
        "idaapi": SimpleNamespace(BADADDR=-1, BADSIZE=-1, get_name_ea=lambda bad, name: 0x4A3890),
        "ida_funcs": SimpleNamespace(get_func=lambda ea: SimpleNamespace(start_ea=0x4A3890)),
        "ida_hexrays": SimpleNamespace(decompile=decompile, mark_cfunc_dirty=lambda *args: None),
    }
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)
    return state, registry


def plan(**kwargs):
    return _ida_prototype({"mode": "plan", "address": "0x4A3890", "expected_current": OLD,
                           "declaration": NEW, "required_types": ["FileClass"], **kwargs})


def test_preflight_does_not_write_and_normalizes_nameless_types(ida):
    state, _ = ida
    result = plan()
    assert result["ok"] is True
    assert result["unchanged"] is False
    assert state.writes == []


@pytest.mark.parametrize("change,reason", [
    ("return", "Return type"), ("cc", "Calling convention"), ("count", "argument count"),
    ("flags", "function flags"), ("argflags", "Argument flags"), ("argloc", "ABI location"),
    ("scalar", "void pointer"), ("qualifier", "qualifier-preserving"),
])
def test_rejects_abi_and_unsupported_type_changes(ida, change, reason):
    state, registry = ida
    proposed = registry[NEW]
    if change == "return":
        proposed.result = Type("int")
    elif change == "cc":
        proposed.cc = 48
    elif change == "count":
        proposed.args.append(arg(VOID_PTR))
    elif change == "flags":
        proposed.flags = 8
    elif change == "argflags":
        proposed.args[0].flags = 1
    elif change == "argloc":
        proposed.args[0].argloc = loc("edx")
    elif change == "scalar":
        proposed.args[0].type = Type("int")
    else:
        proposed.args[0].type.const = True
    result = plan()
    assert result["ok"] is False
    assert reason in result["error"]
    assert state.writes == []


@pytest.mark.parametrize("declaration", [
    "void *__thiscall f(MissingType *this);",
    "void *__thiscall f(FileClass *this); int x;",
    "void *__thiscall f(struct MissingType *this);",
    "void *__thiscall f(FileClass *this) { return 0; }",
])
def test_missing_types_and_non_prototypes_rejected_before_ida_parser(ida, declaration):
    state, _ = ida
    result = plan(declaration=declaration)
    assert result["ok"] is False
    assert len(state.parsed) <= 1  # The trusted expected type may be parsed first.
    assert state.writes == []


def test_interior_address_is_rejected(ida):
    state, _ = ida
    result = plan(address="0x4A3891")
    assert result["ok"] is False
    assert "exact function entry" in result["error"]
    assert state.writes == []


def test_stale_type_is_rejected_but_already_applied_type_is_unchanged(ida):
    state, registry = ida
    state.current.name = "different type"
    assert "Stale" in plan()["error"]
    state.current = copy.deepcopy(registry[NEW])
    assert plan()["unchanged"] is True
    assert state.writes == []


@pytest.mark.parametrize("explicit", [True, False])
def test_apply_readback_restore_preserves_explicit_vs_inferred_state(ida, explicit):
    state, _ = ida
    state.explicit = explicit
    prepared = plan()
    request = {"address": "0x4A3890", "original": prepared["current"], "declaration": NEW,
               "proposed_key": prepared["proposed_key"]}
    assert _ida_prototype({"mode": "apply", **request})["ok"] is True
    assert _ida_prototype({"mode": "verify", **request})["ok"] is True
    assert _ida_prototype({"mode": "restore", **request})["ok"] is True
    assert state.explicit is explicit
    assert str(state.current) == OLD
    assert all(write[1] == 0x4A3890 for write in state.writes)


def test_write_rechecks_snapshot_before_mutation(ida):
    state, _ = ida
    prepared = plan()
    state.current.name = "concurrent edit"
    result = _ida_prototype({"mode": "apply", "address": "0x4A3890",
                             "original": prepared["current"], "declaration": NEW})
    assert result["ok"] is False
    assert result["write_attempted"] is False
    assert state.writes == []


def test_write_is_bound_to_the_preflight_type(ida):
    state, _ = ida
    prepared = plan()
    result = _ida_prototype({"mode": "apply", "address": "0x4A3890", "original": prepared["current"],
                             "declaration": NEW, "proposed_key": "another preflight type"})
    assert result["ok"] is False
    assert "changed after preflight" in result["error"]
    assert result["write_attempted"] is False
    assert state.writes == []


def test_union_refinement_is_outside_first_version(ida):
    state, registry = ida
    registry[NEW].args[0].type.pointee.is_union = lambda: True
    assert plan()["ok"] is False
    assert state.writes == []


def test_decompilation_mismatch_is_detected(ida):
    state, registry = ida
    state.current = copy.deepcopy(registry[NEW])
    state.verify_bad = True
    result = _ida_prototype({"mode": "verify", "address": "0x4A3890",
                             "proposed_key": registry[NEW].serialize()[0].hex()})
    assert result["ok"] is False
    assert "readback mismatch" in result["error"]


def test_model_text_is_data_not_python(ida, capsys):
    state, _ = ida
    request = {"mode": "plan", "address": "0x4A3890", "expected_current": OLD,
               "declaration": "'); raise Exception('injected'); #"}
    exec(prototype_script(request), {})
    output = capsys.readouterr().out
    with pytest.raises(RuntimeError, match="Unsupported declaration"):
        prototype_result({"stdout": output})
    assert state.writes == []


@pytest.mark.parametrize("payload", [None, {}, {"stdout": ""}, {"stderr": "traceback"},
    {"stdout": '__RE_AGENT_PROTOTYPE__{}'},
    {"stdout": '__RE_AGENT_PROTOTYPE__' + json.dumps({"ok": False, "error": "failed"})},
])
def test_empty_or_failed_helper_response_is_never_success(payload):
    with pytest.raises(RuntimeError):
        prototype_result(payload)
