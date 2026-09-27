"""Guarded IDA local writes: first user override, stale locators and rollback."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from re_agent.recovery.ida import _ida_set_local_type


class TypeInfo:
    def __init__(self, text: str = "") -> None:
        self.text = text

    def get_named_type(self, til: object, name: str) -> bool:
        self.text = name
        return name == "Class"

    def is_udt(self) -> bool:
        return self.text == "Class"

    def create_ptr(self, base: TypeInfo) -> bool:
        self.text = base.text + " *"
        return True

    def get_size(self) -> int:
        return 8

    def dstr(self) -> str:
        return self.text

    def equals_to(self, other: TypeInfo) -> bool:
        return self.text == other.text


@pytest.fixture
def environment() -> tuple[dict, dict, dict]:
    location = SimpleNamespace(is_reg1=lambda: False, is_stkoff=lambda: True, stkoff=lambda: 24)
    state = {"type": TypeInfo("void *"), "records": [], "persist": True}
    variable = SimpleNamespace(name="obj", defea=0x401010, width=8, location=location, type=lambda: state["type"])
    cfunc = SimpleNamespace(get_lvars=lambda: [variable])

    def restore(out: object, ea: int) -> None:
        out.lvvec = list(state["records"])

    def modify(ea: int, flags: int, info: object) -> bool:
        state["type"] = info.type
        if state["persist"]:
            state["records"] = [info]
        return True

    def save(ea: int, old: object) -> None:
        state["records"] = old.lvvec
        state["type"] = TypeInfo("void *")

    modules = {
        "ida_funcs": SimpleNamespace(get_func=lambda ea: SimpleNamespace(start_ea=ea)),
        "ida_typeinf": SimpleNamespace(tinfo_t=TypeInfo),
        "ida_hexrays": SimpleNamespace(
            decompile=lambda ea: cfunc, mark_cfunc_dirty=Mock(),
            lvar_uservec_t=lambda: SimpleNamespace(lvvec=[]),
            restore_user_lvar_settings=restore, save_user_lvar_settings=Mock(side_effect=save),
            lvar_saved_info_t=SimpleNamespace,
            lvar_locator_t=lambda loc, ea: SimpleNamespace(location=loc, defea=ea),
            modify_user_lvar_info=Mock(side_effect=modify), MLI_TYPE=1,
        ),
    }
    request = {"address": "0x401000", "name": "obj", "expected_type": "void *", "defea": "0x401010",
               "location": {"kind": "stack", "offset": 24}, "type_name": "Class"}
    return modules, request, state


def test_creates_first_persistent_local_type(environment: tuple) -> None:
    modules, request, state = environment
    assert state["records"] == []
    with patch.dict("sys.modules", modules):
        result = _ida_set_local_type(request)
    assert result == {"ok": True, "name": "obj", "type": "Class *", "persisted": True}
    assert len(state["records"]) == 1


@pytest.mark.parametrize("key,value", [("expected_type", "int"), ("name", "oldname"), ("defea", "0x401011"),
                                       ("type_name", "Missing")])
def test_stale_or_missing_type_rejected_before_write(environment: tuple, key: str, value: str) -> None:
    modules, request, state = environment
    request[key] = value
    with patch.dict("sys.modules", modules), pytest.raises(ValueError):
        _ida_set_local_type(request)
    modules["ida_hexrays"].modify_user_lvar_info.assert_not_called()
    assert state["records"] == []


def test_failed_persistence_restores_original_settings(environment: tuple) -> None:
    modules, request, state = environment
    state["persist"] = False
    with patch.dict("sys.modules", modules):
        result = _ida_set_local_type(request)
    assert result["ok"] is False
    assert result["restored"] is True
    assert state["records"] == []
    assert state["type"].dstr() == "void *"
