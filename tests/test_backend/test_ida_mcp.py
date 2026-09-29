"""Tests for the ida-pro-mcp backend; no IDA instance or network required."""
from __future__ import annotations

import json

import pytest

from re_agent.backend.ida_mcp import IdaMcpBackend
from re_agent.backend.ida_prototype import PROTOTYPE_MARKER
from re_agent.backend.protocol import REBackend
from re_agent.backend.registry import create_backend
from re_agent.config.schema import BackendConfig
from re_agent.core.models import XRef
from re_agent.core.target_plan import build_plan


def _backend(monkeypatch, responses, session="sess-1"):
    """Patch the module transport; ``responses`` maps tool name to a result.

    ``responses["__tools__"]`` lists the tool names reported by ``tools/list``.
    A ``RuntimeError`` value makes the call raise, standing in for a transport
    failure.
    """
    calls: list[tuple[str, dict]] = []

    def post(url, method, params, timeout_s, session_id=None):
        calls.append((method, params))
        if method == "initialize":
            return {}, session
        if method == "tools/list":
            outcome = responses.get("__tools__", [])
            if isinstance(outcome, Exception):
                raise outcome
            return {"tools": [{"name": n} for n in outcome]}, session
        key = params["uri"] if method == "resources/read" else params["name"]
        outcome = responses[key]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome, session

    monkeypatch.setattr("re_agent.backend.ida_mcp.post_jsonrpc", post)
    return calls


def _ok(structured, *, meta=None):
    result = {"structuredContent": structured, "content": [], "isError": False}
    if meta is not None:
        result["_meta"] = {"ida_mcp": meta}
    return result


def _plain_decompile(code="x"):
    """Responses for a bare decompile call: code, no name, no callees."""
    return {
        "decompile": _ok({"addr": "0x1", "code": code}),
        "lookup_funcs": _ok({"result": []}),
        "callees": _ok({"result": []}),
    }


def test_structured_signature_reaches_the_model_evidence(monkeypatch):
    responses = _plain_decompile()
    responses["__tools__"] = ["py_eval", "decompile"]
    responses["py_eval"] = _ok({"stdout": PROTOTYPE_MARKER + json.dumps({
        "ok": True, "current": {"declaration": "void *__thiscall(void *this)", "source": "database"},
    })})
    _backend(monkeypatch, responses)
    result = IdaMcpBackend().decompile("0x1")
    assert result.signature == "void *__thiscall(void *this)"
    assert result.signature_source == "database"
    assert json.loads(result.raw_output)["signature"] == result.signature


def test_unavailable_type_reader_preserves_decompile_with_explicit_gap(monkeypatch):
    responses = _plain_decompile("body")
    responses["__tools__"] = ["py_eval", "decompile"]
    responses["py_eval"] = RuntimeError("unavailable")
    _backend(monkeypatch, responses)
    result = IdaMcpBackend().decompile("0x1")
    assert result.decompiled == "body"
    assert result.signature == ""
    assert "unavailable" in json.loads(result.raw_output)["signature_error"]


def test_is_re_backend(monkeypatch):
    # ``REBackend`` is @runtime_checkable, so ``isinstance`` probes
    # ``capabilities``, which performs a live ``tools/list`` handshake unless
    # the transport is stubbed like every other test in this module.
    _backend(monkeypatch, {"__tools__": []})
    assert isinstance(IdaMcpBackend(), REBackend)


@pytest.mark.parametrize("backend_type", ["ida-mcp", "ida", "ida_mcp"])
def test_registry_builds_ida_backend(backend_type):
    backend = create_backend(
        BackendConfig(type=backend_type, url="http://127.0.0.1:9999/mcp", timeout_s=90)
    )

    assert isinstance(backend, IdaMcpBackend)
    assert backend._url == "http://127.0.0.1:9999/mcp"
    assert backend._timeout_s == 90


def test_registry_rejects_unknown_type():
    with pytest.raises(ValueError, match="Unknown backend type"):
        create_backend(BackendConfig(type="radare2"))


def test_decompile_populates_code_name_and_callees(monkeypatch):
    _backend(
        monkeypatch,
        {
            "decompile": _ok({"addr": "0x401000", "code": "int f(void) { return 1; }"}),
            "lookup_funcs": _ok(
                {"result": [{"query": "0x401000", "fn": {"name": "CMain::Run"}, "error": None}]}
            ),
            "callees": _ok(
                {
                    "result": [
                        {
                            "addr": "0x401000",
                            "callees": [{"addr": "0x402000", "name": "g", "type": "code"}],
                        }
                    ]
                }
            ),
        },
    )
    result = IdaMcpBackend().decompile("0x401000")

    assert result.address == "0x401000"
    assert result.name == "CMain::Run"
    assert result.decompiled == "int f(void) { return 1; }"
    assert result.callees == 1


def test_decompile_surfaces_in_band_error(monkeypatch):
    _backend(monkeypatch, {"decompile": _ok({"addr": "0x1", "code": None, "error": "No function at 0x1"})})
    with pytest.raises(RuntimeError, match="No function at 0x1"):
        IdaMcpBackend().decompile("0x1")


def test_xrefs_to_unwraps_result_envelope(monkeypatch):
    _backend(
        monkeypatch,
        {
            "xrefs_to": _ok(
                {
                    "result": [
                        {
                            "addr": "0x401000",
                            "xrefs": [{"addr": "0x401100", "type": "code", "fn": {"name": "Caller"}}],
                            "error": None,
                        }
                    ]
                }
            )
        },
    )
    refs = IdaMcpBackend().xrefs_to("0x401000")

    assert len(refs) == 1
    assert refs[0].address == "0x401100"
    # target_plan detects call edges by looking for "CALL" in ref_type.
    assert "CALL" in refs[0].ref_type


def test_xrefs_to_null_entries_are_empty(monkeypatch):
    """An unmapped address yields ``xrefs: null`` rather than an empty list."""
    _backend(
        monkeypatch,
        {"xrefs_to": _ok({"result": [{"addr": "0x1", "xrefs": None, "error": "Address not mapped: 0x1"}]})},
    )
    assert IdaMcpBackend().xrefs_to("0x1") == []


@pytest.mark.parametrize("kind", ["internal", "external", "code", "future-target-kind"])
def test_xrefs_from_classifies_callee_targets_as_calls(monkeypatch, kind):
    _backend(monkeypatch, {"callees": _ok({"result": [{
        "addr": "0x1", "callees": [{"addr": "0x2", "name": "callee", "type": kind}],
    }]})})
    assert [XRef("0x2", "callee", "CALL")] == IdaMcpBackend().xrefs_from("0x1")


def test_xrefs_from_empty_callees_are_valid(monkeypatch):
    _backend(monkeypatch, {"callees": _ok({"result": [{"addr": "0x1", "callees": []}]})})
    assert IdaMcpBackend().xrefs_from("0x1") == []


@pytest.mark.parametrize("payload", [
    None, {}, {"result": []}, {"result": [None]},
    {"result": [{"error": "Address not mapped"}]},
    {"result": [{"callees": None}]},
    {"result": [{"callees": {}}]},
    {"result": [{"callees": [None]}]},
    {"result": [{"callees": [{"name": "missing address"}]}]},
])
def test_unusable_callees_become_plan_gaps(monkeypatch, payload):
    responses = _plain_decompile()
    responses.update({
        "__tools__": ["callees", "analyze_function"],
        "callees": _ok(payload),
    })
    _backend(monkeypatch, responses)
    backend = IdaMcpBackend()
    # Isolate planning's xref path from decompile's optional callee count.
    monkeypatch.setattr(backend, "_callee_count", lambda target: None)
    monkeypatch.setattr(backend, "get_context", lambda target: None)
    plan = build_plan(backend, ["0x1"], "a" * 64)
    assert plan.edges == []
    assert any(gap.origin == "xrefs_from" and gap.kind == "query_failed" for gap in plan.gaps)


def test_plan_expands_current_ida_callees(monkeypatch):
    _backend(monkeypatch, {"__tools__": ["callees", "analyze_function"]})
    backend = IdaMcpBackend()

    def call(tool, arguments):
        if tool == "decompile":
            return {"addr": arguments["addr"], "code": "void f(void) {}"}
        if tool == "lookup_funcs":
            return {"result": []}
        if tool == "analyze_function":
            return {"addr": arguments["addr"], "name": "f"}
        assert tool == "callees"
        entries = [
            {"addr": "0x2", "name": "internal_fn", "type": "internal"},
            {"addr": "0x3", "name": "external_fn", "type": "external"},
        ] if arguments["addrs"] == ["0x00000001"] else []
        return {"result": [{"callees": entries}]}

    monkeypatch.setattr(backend, "_call", call)
    plan = build_plan(backend, ["0x1"], "a" * 64, max_depth=1)
    assert [target.address for target in plan.functions] == ["00000001", "00000002", "00000003"]
    assert plan.edges == [
        {"source": "00000001", "target": "00000002"},
        {"source": "00000001", "target": "00000003"},
    ]
    assert plan.gaps == []


@pytest.mark.parametrize("names, expected", [
    (["xrefs_to"], False), (["callees"], True), (["xrefs_to", "callees"], True),
])
def test_xref_capability_tracks_callees(monkeypatch, names, expected):
    _backend(monkeypatch, {"__tools__": names})
    assert expected == IdaMcpBackend().capabilities.has_xrefs


def test_protocol_level_error_raises(monkeypatch):
    _backend(
        monkeypatch,
        {
            "decompile": {
                "structuredContent": None,
                "content": [{"type": "text", "text": "tool disabled"}],
                "isError": True,
            }
        },
    )
    with pytest.raises(RuntimeError, match="tool disabled"):
        IdaMcpBackend().decompile("0x1")


def test_truncated_output_is_downloaded(monkeypatch):
    _backend(
        monkeypatch,
        {
            "decompile": _ok(
                {"addr": "0x1", "code": "truncated preview"},
                meta={"output_truncated": True, "download_url": "http://127.0.0.1:13337/output/abc.json"},
            ),
            "lookup_funcs": _ok({"result": []}),
            "callees": _ok({"result": []}),
        },
    )
    fetched = []
    monkeypatch.setattr(
        "re_agent.backend.ida_mcp._get_json",
        lambda url, timeout_s: fetched.append(url) or {"addr": "0x1", "code": "the real body"},
    )

    result = IdaMcpBackend().decompile("0x1")

    assert fetched == ["http://127.0.0.1:13337/output/abc.json"]
    assert result.decompiled == "the real body"


def test_truncated_output_without_url_raises(monkeypatch):
    _backend(
        monkeypatch,
        {"decompile": _ok({"code": "preview"}, meta={"output_truncated": True})},
    )
    with pytest.raises(RuntimeError, match="without a download URL"):
        IdaMcpBackend().decompile("0x1")


def test_truncated_download_failure_is_fatal(monkeypatch):
    _backend(
        monkeypatch,
        {"decompile": _ok({"code": "preview"}, meta={"output_truncated": True, "download_url": "http://x/y.json"})},
    )

    def boom(url, timeout_s):
        raise RuntimeError("connection refused")

    monkeypatch.setattr("re_agent.backend.ida_mcp._get_json", boom)
    with pytest.raises(RuntimeError, match="connection refused"):
        IdaMcpBackend().decompile("0x1")


def test_capabilities_derive_from_enabled_tools(monkeypatch):
    _backend(monkeypatch, {"__tools__": ["decompile", "disasm", "list_funcs", "xrefs_to", "callees"]})
    caps = IdaMcpBackend().capabilities

    assert caps.has_decompile
    assert caps.has_asm
    assert caps.has_search
    assert caps.has_xrefs
    # Tools the user did not enable must not be advertised.
    assert not caps.has_structs
    assert not caps.has_context
    assert not caps.has_cfg


def test_capabilities_raise_when_server_unreachable(monkeypatch):
    """An unreachable server must not masquerade as "supports nothing"."""
    calls = _backend(monkeypatch, {"__tools__": RuntimeError("connection refused")})
    backend = IdaMcpBackend()

    with pytest.raises(RuntimeError, match="connection refused"):
        _ = backend.capabilities
    # The failure is cached, so a second access does not re-probe the server.
    with pytest.raises(RuntimeError, match="connection refused"):
        _ = backend.capabilities
    assert [method for method, _ in calls].count("tools/list") == 1


def test_capabilities_are_all_false_when_every_tool_is_disabled(monkeypatch):
    _backend(monkeypatch, {"__tools__": []})
    caps = IdaMcpBackend().capabilities

    assert not caps.has_decompile
    assert not caps.has_xrefs
    assert not caps.has_search


def test_initialize_session_id_is_reused(monkeypatch):
    calls = _backend(monkeypatch, _plain_decompile())
    IdaMcpBackend().decompile("0x1")

    methods = [method for method, _ in calls]
    assert methods[0] == "initialize"
    assert methods.count("initialize") == 1


def test_response_cache_avoids_repeat_calls(monkeypatch):
    calls = _backend(monkeypatch, _plain_decompile())
    backend = IdaMcpBackend()
    backend.decompile("0x1")
    before = len(calls)
    backend.decompile("0x1")

    assert len(calls) == before


def test_remaining_is_approximated_by_name_filter(monkeypatch):
    _backend(
        monkeypatch,
        {
            "list_funcs": _ok(
                {
                    "result": [
                        {
                            "data": [
                                {"addr": "0x401000", "name": "TechnoClass::AI", "size": "0x10"},
                                {"addr": "0x402000", "name": "sub_402000", "size": "0x10"},
                            ],
                            "next_offset": None,
                        }
                    ]
                }
            )
        },
    )
    entries = IdaMcpBackend().remaining("TechnoClass")

    assert [entry.name for entry in entries] == ["AI", "sub_402000"]
    assert entries[0].class_name == "TechnoClass"


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        # ReAgent normalizes addresses to bare hex; IDA rejects those.
        ("0041bef0", "0x0041bef0"),
        ("41bef0", "0x41bef0"),
        # Already-prefixed and symbolic targets pass through untouched.
        ("0x41BEF0", "0x41BEF0"),
        ("sub_402000", "sub_402000"),
        ("TechnoClass::AI_41BEF0", "TechnoClass::AI_41BEF0"),
    ],
)
def test_decompile_renders_target_for_ida(monkeypatch, target, expected):
    calls = _backend(monkeypatch, _plain_decompile())
    IdaMcpBackend().decompile(target)

    _, params = next((m, p) for m, p in calls if m == "tools/call")
    assert params["arguments"]["addr"] == expected


def test_lookup_and_callees_receive_prefixed_address(monkeypatch):
    """Every address-bearing call needs the prefix, not just decompile."""
    calls = _backend(
        monkeypatch,
        {
            "decompile": _ok({"addr": "0x1", "code": "x"}),
            "lookup_funcs": _ok({"result": []}),
            "callees": _ok({"result": []}),
        },
    )
    IdaMcpBackend().decompile("0041bef0")

    arguments = [p["arguments"] for m, p in calls if m == "tools/call"]
    assert {"queries": ["0x0041bef0"]} in arguments
    assert {"addrs": ["0x0041bef0"]} in arguments


def test_list_funcs_sends_glob_filter(monkeypatch):
    calls = _backend(monkeypatch, {"list_funcs": _ok({"result": []})})
    IdaMcpBackend().search("sub_*")

    _, params = next((method, params) for method, params in calls if method == "tools/call")
    assert params["arguments"]["queries"][0]["filter"] == "sub_*"
