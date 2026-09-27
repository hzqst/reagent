"""Readback assertions must identify an actual target, type and byte offset."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from re_agent.recovery.ida import IdaRecoveryClient, tool_error, verify_checks


@pytest.fixture
def snapshot() -> dict:
    return {
        "functions": [{"address": "0x401000", "prototype": "int __cdecl(C *obj)",
                       "locals": [{"name": "obj", "type": "C *"}, {"name": "vt", "type": "C_vtb *"}]}],
        "types": [{"name": "C", "exists": True, "size": 8,
                   "members": [{"name": "vt", "type": "C_vtb *", "offset": 0}]}],
    }


@pytest.mark.parametrize("check", [
    {"kind": "local", "address": "0x401000", "name": "obj", "type": "C *"},
    {"kind": "prototype", "address": "0x401000", "type": "int __cdecl(C *obj)"},
    {"kind": "type", "name": "C", "size": 8},
    {"kind": "member", "name": "C", "member": "vt", "offset": 0, "type": "C_vtb *"},
])
def test_readback_checks_actual_types(snapshot: dict, check: dict) -> None:
    assert verify_checks([check], snapshot)[0]["ok"] is True
    check["type"] = "wrong"
    check["size"] = 16
    assert verify_checks([check], snapshot)[0]["ok"] is False


def test_member_offset_and_unique_local_are_required(snapshot: dict) -> None:
    check = {"kind": "member", "name": "C", "member": "vt", "offset": 8, "type": "C_vtb *"}
    assert verify_checks([check], snapshot)[0]["ok"] is False
    snapshot["functions"][0]["locals"].append({"name": "obj", "type": "C *"})
    check = {"kind": "local", "address": "0x401000", "name": "obj", "type": "C *"}
    assert verify_checks([check], snapshot)[0]["ok"] is False


def test_unknown_assertion_does_not_verify(snapshot: dict) -> None:
    assert verify_checks([{"kind": "pretend", "type": "C *"}], snapshot)[0]["ok"] is False


def test_failed_save_is_not_accepted() -> None:
    with patch.object(IdaRecoveryClient, "call", return_value={"ok": False, "error": "disk full"}), \
         pytest.raises(RuntimeError, match="disk full"):
        IdaRecoveryClient("unused").save()


def test_tool_catalog_pagination() -> None:
    with patch("re_agent.recovery.ida.post_jsonrpc", side_effect=[
        ({"tools": [{"name": "decompile"}], "nextCursor": "next"}, "session"),
        ({"tools": [{"name": "set_type"}]}, "session"),
    ]) as post:
        client = IdaRecoveryClient("unused")
        client._initialized = True
        assert [t["name"] for t in client.tools()] == [
            "decompile", "set_type", "recovery_set_local_type", "recovery_inspect",
        ]
        assert post.call_args.args[2] == {"cursor": "next"}


def test_tool_error_checks_per_item_errors() -> None:
    assert tool_error({"result": [{"ok": True}, {"ok": False, "error": "bad local"}]}) == "bad local"
    assert tool_error({"result": [{"decl": "struct C {};", "error": None}]}) is None


def test_health_retries_transient_busy_response() -> None:
    ready = {"status": "ok", "idb_path": "/tmp/test.i64", "hexrays_ready": True}
    with patch.object(IdaRecoveryClient, "call", side_effect=[{"status": "busy"}, ready]), \
         patch("re_agent.recovery.ida.time.sleep"):
        assert IdaRecoveryClient("unused").health() == ready


def test_health_does_not_assume_database_identity_while_busy() -> None:
    with patch.object(IdaRecoveryClient, "call", return_value={"status": "busy"}), \
         patch("re_agent.recovery.ida.time.sleep"), \
         pytest.raises(RuntimeError, match="known path"):
        IdaRecoveryClient("unused").health()


@pytest.mark.parametrize("argument_flag", [True, lambda: True])
def test_snapshot_supports_ida_argument_property_and_method(argument_flag: object) -> None:
    from types import SimpleNamespace
    from unittest.mock import Mock

    from re_agent.recovery.ida import _ida_snapshot

    variable = SimpleNamespace(
        name="obj", type=lambda: SimpleNamespace(dstr=lambda: "C *"),
        is_arg_var=argument_flag, defea=0x401000,
        location=SimpleNamespace(is_reg1=lambda: True, reg1=lambda: 56, regoff=lambda: 0),
    )
    cfunc = SimpleNamespace(
        get_func_type=lambda t: True, get_lvars=lambda: [variable],
        get_pseudocode=lambda: [SimpleNamespace(line="return obj->vt;")],
    )
    modules = {
        "ida_funcs": SimpleNamespace(get_func=lambda ea: SimpleNamespace(start_ea=ea)),
        "ida_hexrays": SimpleNamespace(mark_cfunc_dirty=Mock(), decompile=lambda ea: cfunc),
        "ida_lines": SimpleNamespace(tag_remove=lambda s: s),
        "ida_typeinf": SimpleNamespace(tinfo_t=lambda: SimpleNamespace(dstr=lambda: "int(C *obj)")),
    }
    with patch.dict("sys.modules", modules):
        result = _ida_snapshot({"addresses": ["0x401000"], "types": []})
    local = result["functions"][0]["locals"][0]
    assert local["argument"] is True
    assert local["type"] == "C *"
    assert local["location"] == {"kind": "register", "register": 56, "offset": 0}


def test_local_preflight_returns_current_locator_on_stale_input(snapshot: dict) -> None:
    snapshot["functions"][0]["locals"][0].update(defea="0x401010", location={"kind": "stack", "offset": 24})
    request = {"address": "0x401000", "name": "obj", "expected_type": "C *", "defea": "0x401011",
               "location": {"kind": "stack", "offset": 24}, "type_name": "C"}
    with patch.object(IdaRecoveryClient, "snapshot", return_value=snapshot), \
         patch.object(IdaRecoveryClient, "_call") as remote:
        with pytest.raises(ValueError, match="0x401010"):
            IdaRecoveryClient("unused").validate_local(request)
        request["defea"] = "0x401010"
        IdaRecoveryClient("unused").validate_local(request)
    remote.assert_not_called()
