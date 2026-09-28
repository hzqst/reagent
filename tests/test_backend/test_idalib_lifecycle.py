"""Lifecycle ownership and failure paths, without IDA or a model provider."""
from __future__ import annotations

import json
from unittest.mock import Mock

import pytest

from re_agent.backend import idalib_lifecycle as lifecycle
from re_agent.backend.idalib_process import ProcessIdentity
from re_agent.config.schema import BackendConfig


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    database = tmp_path / "sample.i64"
    database.write_bytes(b"test database")
    config = BackendConfig(type="idalib-mcp", database_path=str(database), shutdown_timeout_s=1)
    table = {101: ProcessIdentity(101, 1, "root"), 102: ProcessIdentity(102, 101, "worker")}
    calls = []
    process = Mock(pid=101)
    process.poll.side_effect = lambda: None if 101 in table else 0
    process.terminate.side_effect = lambda: table.pop(101, None)
    monkeypatch.setattr(lifecycle.shutil, "which", lambda _: "/bin/idalib-mcp")
    monkeypatch.setattr(lifecycle.subprocess, "Popen", Mock(return_value=process))
    monkeypatch.setattr(lifecycle, "process_table", lambda: dict(table))
    monkeypatch.setattr(lifecycle, "owns_listener", lambda *_: True)
    killed = []

    def kill(identities):
        killed.extend(identities)
        for pid in identities:
            table.pop(pid, None)

    monkeypatch.setattr(lifecycle, "kill_owned", kill)
    selected = {"session_id": "db", "input_path": str(database), "owned": True,
                "backend": "worker", "is_active": True, "worker_pid": 102}

    def call(client, tool, arguments):
        calls.append((tool, arguments))
        if tool == "idb_open":
            return {"success": True, "session": {"session_id": "db"}}
        if tool == "idb_list":
            return {"sessions": [selected]}
        if tool == "server_health":
            return {"idb_path": str(database), "hexrays_ready": True}
        if "RE_AGENT_NO_AUTO_SAVE" in arguments.get("code", ""):
            return {"stdout": "RE_AGENT_NO_AUTO_SAVE"}
        if "close_database" in arguments.get("code", ""):
            return {"stdout": "RE_AGENT_DATABASE_CLOSED"}
        if "qexit" in arguments.get("code", ""):
            table.pop(102, None)
            raise RuntimeError("connection closed by worker")
        return {"stdout": json.dumps({"pid": 102, "idb_path": str(database)})}

    monkeypatch.setattr(lifecycle.IdaWriteClient, "_call", call)
    owner = lifecycle.IdaMcpLifecycle(config, "test", tmp_path / "logs")
    return owner, calls, process, table, selected, killed


@pytest.mark.parametrize("error", [None, ValueError("model failed"), KeyboardInterrupt()])
def test_closes_without_implicit_save_on_every_exit(runtime, error):
    owner, calls, process, table, _, _ = runtime

    def run():
        with owner:
            assert owner.database == "db"
            assert owner._heartbeat.is_alive()
            if error is not None:
                raise error

    if error is None:
        run()
    else:
        with pytest.raises(type(error)):
            run()
    assert table == {}
    assert not owner._heartbeat.is_alive()
    assert not any(tool == "idb_save" for tool, _ in calls)
    assert any("save=False" in args.get("code", "") for _, args in calls)
    process.wait.assert_called()
    assert owner._log.closed


@pytest.mark.parametrize("change", [
    {"owned": False}, {"worker_pid": 999}, {"backend": "gui"},
    {"input_path": "/another.i64"}, {"is_active": False},
])
def test_rejects_external_or_wrong_database_without_closing_it(runtime, change):
    owner, calls, _, _, selected, killed = runtime
    selected.update(change)
    with pytest.raises(lifecycle.IdalibLifecycleError, match="Refusing"), owner:
        pytest.fail("must not enter")
    assert not any("close_database" in args.get("code", "") for _, args in calls)
    assert 999 not in killed


def test_startup_failure_still_releases_lock_and_processes(runtime, monkeypatch):
    owner, _, _, table, _, _ = runtime
    monkeypatch.setattr(owner, "_open_database", Mock(side_effect=RuntimeError("open failed")))
    with pytest.raises(lifecycle.IdalibLifecycleError, match="open failed"):
        owner.__enter__()
    assert table == {}
    assert owner._log.closed
    # A fresh owner can acquire the same cross-process lock immediately.
    with lifecycle.file_lock(
        lifecycle.Path(lifecycle.tempfile.gettempdir()) / "re-agent-idalib"
        / lifecycle.hashlib.sha256(lifecycle._path_key(owner._path).encode()).hexdigest(),
        blocking=False,
    ):
        pass


def test_failed_graceful_close_forces_cleanup_and_is_not_success(runtime, monkeypatch):
    owner, _, _, table, _, _ = runtime
    with pytest.raises(lifecycle.IdalibLifecycleError, match="cleanup failed"), owner:
        monkeypatch.setattr(lifecycle.IdaWriteClient, "_call", Mock(side_effect=RuntimeError("wedged")))
    assert table == {}


def test_worker_dies_even_without_another_tool_call(runtime):
    owner, _, _, table, _, _ = runtime
    with pytest.raises(lifecycle.IdalibLifecycleError, match="worker exited"), owner:
        table.pop(102)
    assert table == {}


def test_heartbeat_failure_is_fatal_at_stage_exit(runtime, monkeypatch):
    owner, _, _, table, _, _ = runtime
    with pytest.raises(lifecycle.IdalibLifecycleError, match="heartbeat"), owner:
        owner._stop.set()
        owner._heartbeat.join(1)
        stop = Mock()
        stop.wait.side_effect = [False, True]
        monkeypatch.setattr(owner, "_stop", stop)
        original = lifecycle.IdaWriteClient._call

        def call(client, tool, args):
            if tool == "server_health":
                raise RuntimeError("heartbeat failed")
            return original(client, tool, args)

        monkeypatch.setattr(lifecycle.IdaWriteClient, "_call", call)
        owner._keep_alive()
    assert table == {}


def test_active_ida_working_files_are_never_removed(runtime):
    owner, calls, process, _, _, _ = runtime
    part = lifecycle.Path(owner.config.database_path).with_suffix(".id0")
    part.write_bytes(b"belongs to another IDA")
    with pytest.raises(lifecycle.IdalibLifecycleError, match="working files"):
        owner.__enter__()
    assert part.read_bytes() == b"belongs to another IDA"
    assert calls == []
    process.terminate.assert_not_called()


def test_live_foreign_port_does_not_receive_database_requests(runtime, monkeypatch):
    owner, calls, _, table, _, _ = runtime
    monkeypatch.setattr(lifecycle, "owns_listener", lambda *_: False)
    clock = iter(range(1000))
    monkeypatch.setattr(lifecycle.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(lifecycle.time, "sleep", lambda _: None)
    with pytest.raises(lifecycle.IdalibLifecycleError, match="listener"):
        owner.__enter__()
    assert calls == []
    assert table == {}


def test_failed_launch_retries_are_bounded(runtime, monkeypatch):
    owner, calls, process, _, _, _ = runtime
    process.poll.side_effect = lambda: 1
    with pytest.raises(lifecycle.IdalibLifecycleError, match="bind"):
        owner.__enter__()
    assert lifecycle.subprocess.Popen.call_count == lifecycle.START_ATTEMPTS
    assert calls == []


def test_database_lock_conflict_is_reported_before_starting(runtime):
    owner, calls, process, _, _, _ = runtime
    key = lifecycle.hashlib.sha256(lifecycle._path_key(owner.config.database_path).encode()).hexdigest()
    path = lifecycle.Path(lifecycle.tempfile.gettempdir()) / "re-agent-idalib" / key
    with lifecycle.file_lock(path, blocking=False), pytest.raises(lifecycle.IdalibLifecycleError, match="in use"):
        owner.__enter__()
    assert calls == []
    process.terminate.assert_not_called()


def test_startup_waits_for_transient_busy_health(runtime, monkeypatch):
    owner, _, _, _, _, _ = runtime
    original = lifecycle.IdaWriteClient._call
    health_calls = []

    def call(client, tool, args):
        if tool == "server_health":
            health_calls.append(tool)
            if len(health_calls) == 1:
                return {"status": "busy"}
        return original(client, tool, args)

    monkeypatch.setattr(lifecycle.IdaWriteClient, "_call", call)
    with owner:
        assert len(health_calls) == 2
