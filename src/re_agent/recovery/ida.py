"""IDA recovery transport, tool policy and independent readback."""
from __future__ import annotations

import inspect
import json
import time
import uuid
from collections.abc import Callable
from typing import Any

from re_agent.backend.ida_mcp import post_jsonrpc
from re_agent.backend.ida_write import IdaWriteClient

# Do not trust server annotations to turn an unknown tool into a preview tool.
READ_TOOLS = frozenset({
    "server_health", "survey_binary", "lookup_funcs", "decompile", "disasm", "analyze_function",
    "analyze_batch", "analyze_component", "basic_blocks", "callees", "callgraph", "entity_query",
    "func_profile", "func_query", "list_funcs", "list_globals", "get_bytes", "get_int", "get_string",
    "get_global_value", "imports", "imports_query", "find", "find_bytes", "find_regex", "search_text",
    "insn_query", "read_struct", "search_structs", "stack_frame", "trace_data_flow", "type_inspect",
    "type_query", "xref_query", "xrefs_to", "xrefs_to_field", "int_convert", "export_funcs", "recovery_inspect",
})
WRITE_TOOLS = frozenset({
    "declare_type", "set_type", "type_apply_batch", "infer_types", "rename", "set_comments",
    "append_comments", "force_recompile", "py_eval", "recovery_set_local_type",
})
LOCAL_TYPE_TOOL: dict[str, Any] = {
    "name": "recovery_set_local_type",
    "description": "Persist a class/vtable pointer type on an existing local, guarded by its current locator and type. "
                   "Works even without prior saved local settings. Copy locator fields from the initial snapshot, "
                   "or re-inspect them after edits. On failure attempts to restore original user local settings.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "address": {"type": "string", "description": "Selected function entry, hexadecimal"},
            "name": {"type": "string", "description": "Current local variable name"},
            "expected_type": {"type": "string", "description": "Exact currently printed local type"},
            "defea": {"type": "string", "description": "Hexadecimal variable definition address"},
            "location": {"type": "object", "description": "Snapshot location (stack offset or register and offset)"},
            "type_name": {"type": "string", "description": "Existing class/vtable UDT name; applies a pointer to it"},
        },
        "required": ["address", "name", "expected_type", "defea", "location", "type_name"],
        "additionalProperties": False,
    },
}
INSPECT_TOOL: dict[str, Any] = {
    "name": "recovery_inspect",
    "description": "Fresh decompilation, exact local names/types/locators and named UDT layouts. "
                   "Use before local edits: pseudocode instruction addresses are not lvar definition addresses.",
    "inputSchema": {"type": "object", "properties": {
        "addresses": {"type": "array", "items": {"type": "string"}},
        "types": {"type": "array", "items": {"type": "string"}},
    }, "required": ["addresses"], "additionalProperties": False},
}
SNAPSHOT_MARKER = "__RE_AGENT_RECOVERY__"
HEALTH_ATTEMPTS = 10
HEALTH_RETRY_SECONDS = 0.1


def tool_error(value: Any) -> str | None:
    """Find per-item failures even when MCP itself reports a successful call."""
    if isinstance(value, dict):
        if value.get("error") or value.get("ok") is False or value.get("success") is False or value.get("stderr"):
            return str(value.get("error") or value.get("stderr") or "Tool returned failure")
        for item in value.values():
            error = tool_error(item)
            if error:
                return error
    elif isinstance(value, list):
        for item in value:
            error = tool_error(item)
            if error:
                return error
    return None


class IdaRecoveryClient(IdaWriteClient):
    """Use the configured IDA endpoint without extending the REBackend protocol."""

    def tools(self) -> list[dict[str, Any]]:
        self._ensure_session()
        result: list[dict[str, Any]] = []
        params: dict[str, Any] = {}
        seen: set[str] = set()
        while True:
            page, session = post_jsonrpc(self._url, "tools/list", params, self._timeout_s, self._session_id)
            self._session_id = session or self._session_id
            items = page.get("tools")
            if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
                raise RuntimeError("IDA returned an invalid tool catalog")
            result.extend(items)
            cursor = page.get("nextCursor")
            if not cursor:
                if self._database is not None:
                    # Routing belongs to the harness, not the recovery model.
                    for entry in result:
                        schema = entry.get("inputSchema", {})
                        schema.get("properties", {}).pop("database", None)
                        if "required" in schema:
                            schema["required"] = [key for key in schema["required"] if key != "database"]
                helpers = [LOCAL_TYPE_TOOL, INSPECT_TOOL]
                names = {t["name"] for t in helpers}
                return [t for t in result if t.get("name") not in names] + helpers
            if not isinstance(cursor, str) or cursor in seen:
                raise RuntimeError("IDA repeated an invalid tool catalog cursor")
            seen.add(cursor)
            params = {"cursor": cursor}

    def call(self, name: str, arguments: dict[str, Any]) -> Any:
        if name == "recovery_set_local_type":
            return self._helper(_ida_set_local_type, arguments)
        if name == "recovery_inspect":
            return self.snapshot(arguments["addresses"], arguments.get("types"))
        return self._call(name, arguments)

    def validate_local(self, arguments: dict[str, Any]) -> None:
        """Refresh locator data before dispatch; reject stale requests without writes."""
        current = self.snapshot([arguments["address"]])["functions"][0]["locals"]
        matches = [v for v in current if all(v.get(key) == arguments.get(key)
                                           for key in ("name", "defea", "location"))
                   and v["type"] == arguments.get("expected_type")]
        if len(matches) != 1:
            raise ValueError("Stale/ambiguous local request. Use exact current locator/type: " + json.dumps(current))

    def health(self) -> dict[str, Any]:
        result: Any = None
        for attempt in range(HEALTH_ATTEMPTS):
            result = self.call("server_health", {})
            # A live IDA server can briefly return only busy metadata while
            # servicing another request, without its database identity fields.
            if not isinstance(result, dict) or result.get("status") != "busy":
                break
            if attempt + 1 < HEALTH_ATTEMPTS:
                time.sleep(HEALTH_RETRY_SECONDS)
        if not isinstance(result, dict) or not result.get("idb_path"):
            raise RuntimeError(f"Recovery requires an open IDA database with a known path: {result}")
        if result.get("hexrays_ready") is False:
            raise RuntimeError("Recovery requires Hex-Rays")
        return result

    def backup(self, health: dict[str, Any]) -> str:
        # This path belongs to the IDA host, which may not be the CLI host.
        path = str(health["idb_path"])
        stem, sep, suffix = path.rpartition(".")
        path = f"{stem if sep else path}.re-agent-{uuid.uuid4().hex}.{suffix if sep else 'i64'}"
        result = self.call("idb_save", {"path": path})
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise RuntimeError(f"Cannot back up IDB before recovery: {result}")
        return path

    def save(self) -> None:
        result = self.call("idb_save", {})
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise RuntimeError(f"Cannot save recovered IDB: {result}")

    def snapshot(self, addresses: list[str], types: list[str] | None = None) -> dict[str, Any]:
        request = {"addresses": addresses, "types": types or []}
        return self._helper(_ida_snapshot, request)

    def _helper(self, helper: Callable[[dict[str, Any]], dict[str, Any]], request: dict[str, Any]) -> dict[str, Any]:
        code = (
            "import json\nfrom typing import Any\n" + inspect.getsource(_ida_location) + inspect.getsource(helper)
            + f"\nprint({SNAPSHOT_MARKER!r} + json.dumps({helper.__name__}(json.loads({json.dumps(request)!r}))))"
        )
        payload = self._call("py_eval", {"code": code})
        if not isinstance(payload, dict) or tool_error(payload):
            raise RuntimeError(f"IDA snapshot failed: {payload}")
        lines = [line.removeprefix(SNAPSHOT_MARKER) for line in str(payload.get("stdout", "")).splitlines()
                 if line.startswith(SNAPSHOT_MARKER)]
        if len(lines) != 1:
            raise RuntimeError("IDA snapshot returned no unique result")
        value = json.loads(lines[0])
        if not isinstance(value, dict):
            raise RuntimeError("IDA snapshot returned invalid data")
        return value

    def verify(self, checks: list[dict[str, Any]], snapshot: dict[str, Any]) -> list[dict[str, Any]]:
        return verify_checks(checks, snapshot)


def verify_checks(checks: list[dict[str, Any]], snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """Compare agent assertions with fresh IDA data, never with agent prose."""
    results: list[dict[str, Any]] = []
    for check in checks:
        kind = check.get("kind")
        actual: Any = None
        expected = check.get("type")
        if kind in {"local", "prototype"}:
            functions = [f for f in snapshot["functions"] if f["address"] == check.get("address")]
            if len(functions) == 1:
                if kind == "prototype":
                    actual = functions[0]["prototype"]
                else:
                    variables = [v for v in functions[0]["locals"] if v["name"] == check.get("name")]
                    if len(variables) == 1:
                        actual = variables[0]["type"]
        elif kind in {"member", "type"}:
            types = [t for t in snapshot["types"] if t["name"] == check.get("name") and t.get("exists")]
            if len(types) == 1:
                if kind == "type":
                    actual, expected = types[0]["size"], check.get("size")
                else:
                    members = [m for m in types[0]["members"] if m["name"] == check.get("member")]
                    if len(members) == 1 and members[0]["offset"] == check.get("offset"):
                        actual = members[0]["type"]
        ok = actual is not None and expected is not None and actual == expected
        results.append({"check": check, "actual": actual, "ok": ok})
    return results


def _ida_location(loc: Any) -> dict[str, Any]:
    if loc.is_reg1():
        return {"kind": "register", "register": loc.reg1(), "offset": loc.regoff()}
    if loc.is_stkoff():
        return {"kind": "stack", "offset": loc.stkoff()}
    return {"kind": "other", "atype": loc.atype()}


def _ida_snapshot(request: dict[str, Any]) -> dict[str, Any]:
    # Executed inside IDA. No model-authored code or declarations enter this helper.
    import importlib

    ida_funcs = importlib.import_module("ida_funcs")
    ida_hexrays = importlib.import_module("ida_hexrays")
    ida_lines = importlib.import_module("ida_lines")
    ida_typeinf = importlib.import_module("ida_typeinf")

    functions = []
    for address in request["addresses"]:
        ea = int(address, 16)
        fn = ida_funcs.get_func(ea)
        if fn is None or fn.start_ea != ea:
            raise ValueError("Recovery target must be an exact function entry: " + address)
        ida_hexrays.mark_cfunc_dirty(ea, False)
        cf = ida_hexrays.decompile(ea)
        if cf is None:
            raise ValueError("Cannot decompile " + address)
        tif = ida_typeinf.tinfo_t()
        if not cf.get_func_type(tif):
            raise ValueError("Cannot read function type " + address)
        variables = [{"name": v.name, "type": v.type().dstr(), "location": _ida_location(v.location),
                      "defea": hex(v.defea),
                      "argument": v.is_arg_var() if callable(v.is_arg_var) else bool(v.is_arg_var)}
                     for v in cf.get_lvars()]
        functions.append({"address": hex(ea), "prototype": tif.dstr(), "locals": variables,
                          "pseudocode": "\n".join(ida_lines.tag_remove(line.line) for line in cf.get_pseudocode())})
    types = []
    for name in request["types"]:
        tif = ida_typeinf.tinfo_t()
        exists = tif.get_named_type(None, name)
        entry: dict[str, Any] = {"name": name, "exists": bool(exists), "members": []}
        if exists:
            entry["size"] = tif.get_size()
            entry["declaration"] = tif.dstr()
            udt = ida_typeinf.udt_type_data_t()
            if tif.get_udt_details(udt):
                entry["members"] = [{"name": m.name, "type": m.type.dstr(), "offset": m.offset // 8,
                                     "size": m.size // 8} for m in udt]
        types.append(entry)
    return {"functions": functions, "types": types}


def _ida_set_local_type(request: dict[str, Any]) -> dict[str, Any]:
    """Persist one local pointer type using IDA's native saved-local API."""
    import importlib

    hx = importlib.import_module("ida_hexrays")
    ti = importlib.import_module("ida_typeinf")
    funcs = importlib.import_module("ida_funcs")
    ea = int(request["address"], 16)
    fn = funcs.get_func(ea)
    if fn is None or fn.start_ea != ea:
        raise ValueError("Local target must be an exact function entry")
    if request["location"].get("kind") not in {"register", "stack"}:
        raise ValueError("Unsupported local storage; refusing an ambiguous locator")

    def find_local() -> Any:
        hx.mark_cfunc_dirty(ea, False)
        cf = hx.decompile(ea)
        if cf is None:
            raise ValueError("Cannot decompile local target")
        matches = [v for v in cf.get_lvars() if v.defea == int(request["defea"], 16)
                   and _ida_location(v.location) == request["location"]]
        if len(matches) != 1:
            raise ValueError("Local locator is missing or ambiguous after decompilation")
        # Keep the cfunc owner alive while using its variable proxy.
        return cf, matches[0]

    owner, variable = find_local()
    if variable.name != request["name"] or variable.type().dstr() != request["expected_type"]:
        raise ValueError("Stale local proposal: name or type changed")
    base = ti.tinfo_t()
    if not base.get_named_type(None, request["type_name"]) or not base.is_udt():
        raise ValueError("Local pointer target must be an existing class/vtable UDT")
    pointer = ti.tinfo_t()
    if not pointer.create_ptr(base) or pointer.get_size() != variable.width:
        raise ValueError("Pointer width does not match local storage")
    previous = hx.lvar_uservec_t()
    hx.restore_user_lvar_settings(previous, ea)
    info = hx.lvar_saved_info_t()
    info.ll = hx.lvar_locator_t(variable.location, variable.defea)
    info.type = pointer
    try:
        if not hx.modify_user_lvar_info(ea, hx.MLI_TYPE, info):
            raise ValueError("IDA rejected saved local type")
        owner, actual = find_local()
        if not actual.type().equals_to(pointer):
            raise ValueError("Fresh decompilation did not retain the requested local type")
        saved = hx.lvar_uservec_t()
        hx.restore_user_lvar_settings(saved, ea)
        persisted = [v for v in saved.lvvec if v.ll.defea == info.ll.defea
                     and _ida_location(v.ll.location) == request["location"] and v.type.equals_to(pointer)]
        if len(persisted) != 1:
            raise ValueError("Local type was not persisted in user settings")
        return {"ok": True, "name": actual.name, "type": actual.type().dstr(), "persisted": True}
    except Exception as exc:
        hx.save_user_lvar_settings(ea, previous)
        owner, restored = find_local()
        return {"ok": False, "error": str(exc), "restored": restored.type().dstr() == request["expected_type"]}
