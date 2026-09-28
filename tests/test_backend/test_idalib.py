"""Owned IDA stages must release resources and never reuse stale evidence."""
from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import Mock

import pytest

from re_agent.backend.ida_mcp import IdaMcpBackend
from re_agent.backend.ida_write import IdaWriteClient
from re_agent.backend.idalib import IdalibBackend
from re_agent.backend.idalib_lifecycle import IdalibLifecycleError, validate_idalib_config
from re_agent.backend.stages import backend_stage
from re_agent.backend.stub import StubBackend
from re_agent.config.schema import BackendConfig


@pytest.mark.parametrize("client_type", [IdaMcpBackend, IdaWriteClient])
def test_database_binding_cannot_be_overridden(client_type, monkeypatch):
    module = "re_agent.backend.ida_mcp" if client_type is IdaMcpBackend else "re_agent.backend.ida_write"
    rpc = Mock(return_value=({"structuredContent": {"ok": True}}, None))
    monkeypatch.setattr(module + ".post_jsonrpc", rpc)
    client = client_type("http://localhost/mcp", database="owned-db")
    client._call("py_eval", {"code": "1", "database": "another-db"})
    assert rpc.call_args.args[2]["arguments"]["database"] == "owned-db"


def test_external_backend_stage_is_noop():
    backend = StubBackend()
    with backend_stage(backend, "checker") as active:
        assert backend is active


def test_stages_reset_cache_and_cleanup_after_exception(monkeypatch):
    events = []

    @contextmanager
    def lifecycle(config, phase, log_dir=None):
        events.append(("start", phase))
        runtime = Mock(url="http://localhost/mcp", database="db")
        try:
            yield runtime
        finally:
            events.append(("stop", phase))

    monkeypatch.setattr("re_agent.backend.idalib.IdaMcpLifecycle", lifecycle)
    backend = IdalibBackend(BackendConfig(type="idalib-mcp"))
    with backend_stage(backend, "reverse"):
        backend._response_cache[("tool", "{}")] = "old"
        with backend_stage(backend, "nested"):
            assert len(backend._response_cache) == 1
    with pytest.raises(ValueError, match="model failed"), backend_stage(backend, "checker"):
        assert backend._response_cache == {}
        raise ValueError("model failed")
    assert events == [("start", "reverse"), ("stop", "reverse"), ("start", "checker"), ("stop", "checker")]
    with pytest.raises(IdalibLifecycleError, match="stage"):
        backend.decompile("0x1000")


def test_missing_database_fails_before_spawn(tmp_path):
    config = BackendConfig(type="idalib-mcp", database_path=str(tmp_path / "missing.i64"))
    with pytest.raises(ValueError, match="database"):
        validate_idalib_config(config)


def test_supervisor_structs_use_bound_tools_and_preserve_hex_offsets(monkeypatch):
    backend = IdaMcpBackend(database="owned-db")
    tool = Mock(return_value={"result": [{"name": "Object", "exists": True, "is_udt": True,
                                          "size": 16, "member_count": 1,
                                          "members": [{"name": "value", "offset": "0xc",
                                                       "size": 4, "type": "int"}]}]})
    monkeypatch.setattr(backend, "_call", tool)
    result = backend.get_struct("Object")
    assert result is not None
    assert result.fields[0].offset == 12
    assert tool.call_args.args[0] == "type_inspect"


def test_supervisor_structs_reject_incomplete_member_lists(monkeypatch):
    backend = IdaMcpBackend(database="owned-db")
    monkeypatch.setattr(backend, "_call", Mock(return_value={"result": [
        {"exists": True, "is_udt": True, "member_count": 5000, "members": []},
    ]}))
    with pytest.raises(RuntimeError, match="truncated"):
        backend.get_struct("LargeObject")


@pytest.mark.parametrize("manifest", [False, True])
def test_fix_loop_scopes_each_role_and_releases_ida_before_candidate_gate(monkeypatch, manifest):
    from re_agent.agents.loop import run_fix_loop
    from re_agent.core.models import FunctionTarget
    from re_agent.core.target_plan import TargetPlan
    from re_agent.orchestrator.batch_runner import _ManifestBackend

    events = []

    @contextmanager
    def lifecycle(config, phase, log_dir=None):
        events.append(("start", phase))
        try:
            yield Mock(url="http://localhost/mcp", database="db")
        finally:
            events.append(("stop", phase))

    monkeypatch.setattr("re_agent.backend.idalib.IdaMcpLifecycle", lifecycle)
    stub = StubBackend()
    for name in ("decompile", "get_struct", "xrefs_from", "get_asm", "get_context", "get_cfg", "get_pcode",
                 "get_vtable"):
        method = getattr(stub, name)
        monkeypatch.setattr(IdaMcpBackend, name, lambda self, target, method=method: method(target))
    monkeypatch.setattr(IdaMcpBackend, "_probe_capabilities", lambda self: stub.capabilities)
    monkeypatch.setattr(IdaMcpBackend, "_ensure_session", lambda self: None)
    backend = IdalibBackend(BackendConfig(type="idalib-mcp"))
    reverser = Mock(supports_conversations=False)
    reverser.send.return_value = "```cpp\nvoid CTrain::ProcessControl() {}\n```"
    checker = Mock(supports_conversations=False)
    checker.send.side_effect = ["VERDICT: FAIL\nSUMMARY: fix it", "VERDICT: PASS\nSUMMARY: good"]

    def gate(result):
        assert backend._runtime is None
        return result

    target = FunctionTarget("0x6F86A0", "CTrain", "ProcessControl")
    plan = TargetPlan("0" * 64, [target.address], functions=[target])
    active = _ManifestBackend(backend, plan) if manifest else backend
    result = run_fix_loop(target, active,
                          reverser, checker, max_rounds=2, candidate_gate=gate)
    assert result.success
    expected = ["reverse", "checker", "objective", "fix", "checker", "objective"]
    assert events == [(event, phase) for phase in expected for event in ("start", "stop")]


def test_swallowed_evidence_transport_failure_still_fails_stage(monkeypatch):
    from re_agent.backend.ida_mcp import McpTransportError

    @contextmanager
    def lifecycle(*args):
        yield Mock(url="http://localhost/mcp", database="db")

    monkeypatch.setattr("re_agent.backend.idalib.IdaMcpLifecycle", lifecycle)
    backend = IdalibBackend(BackendConfig(type="idalib-mcp"))
    with pytest.raises(IdalibLifecycleError, match="lost evidence"), backend_stage(backend, "reverse"):
        monkeypatch.setattr("re_agent.backend.ida_mcp.post_jsonrpc", Mock(side_effect=McpTransportError("timeout")))
        # Optional evidence helpers normally swallow RuntimeError. The stage
        # must remember the transport failure instead of accepting partial data.
        assert backend.get_context("0x1000") is None


def test_old_project_fingerprint_is_unchanged(tmp_path):
    import hashlib
    import json
    from dataclasses import asdict

    from re_agent.config.schema import ReAgentConfig
    from re_agent.core.identity import project_fingerprint

    config = ReAgentConfig(backend=BackendConfig(type="stub"))
    config.project_profile.source_root = str(tmp_path)
    legacy_backend = {"type": "stub", "export_dir": None, "address_map": None,
                      "cli_path": "ghidra-bridge", "url": "http://127.0.0.1:13337/mcp", "timeout_s": 45}
    values = {"profile": asdict(config.project_profile), "validation": asdict(config.validation),
              "parity": asdict(config.parity), "backend": legacy_backend}
    digest = hashlib.sha256(json.dumps(values, sort_keys=True).encode())
    digest.update(str(tmp_path.resolve()).encode())
    assert project_fingerprint(config) == digest.hexdigest()


@pytest.mark.parametrize("result", [
    {"_meta": {"ida_mcp": {"output_truncated": True}}},
    {"isError": True, "structuredContent": {"busy": True, "error": "worker timed out"}},
])
def test_incomplete_evidence_is_a_transport_failure(monkeypatch, result):
    from re_agent.backend.ida_mcp import McpTransportError

    client = IdaMcpBackend(database="db")
    client._initialized = True
    monkeypatch.setattr("re_agent.backend.ida_mcp.post_jsonrpc", Mock(return_value=(result, None)))
    with pytest.raises(McpTransportError):
        client._call("analyze_function", {"addr": "0x1000"})
