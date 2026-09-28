"""Opt-in real IDA checks. Always work on a disposable copy of the input IDB."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import time
import uuid
from pathlib import Path

import pytest

from re_agent.backend.ida_write import IdaWriteClient
from re_agent.backend.idalib_lifecycle import IdalibLifecycleError, IdaMcpLifecycle
from re_agent.backend.idalib_process import process_table, same_process
from re_agent.backend.stages import ida_client_stage
from re_agent.config.schema import BackendConfig


@pytest.fixture
def real_database(tmp_path):
    source = os.environ.get("RE_AGENT_IDALIB_TEST_DATABASE")
    if not source:
        pytest.skip("Set RE_AGENT_IDALIB_TEST_DATABASE to opt into real IDA validation")
    database = tmp_path / Path(source).name
    shutil.copy2(source, database)
    config = BackendConfig(type="idalib-mcp", database_path=str(database),
                           idalib_mcp_path=os.environ.get("RE_AGENT_IDALIB_TEST_EXECUTABLE", "idalib-mcp"))
    return config, tmp_path / "logs"


def _comment(client, value=None):
    code = "import idautils, ida_funcs, json; ea=next(idautils.Functions()); fn=ida_funcs.get_func(ea); "
    if value is not None:
        code += f"assert ida_funcs.set_func_cmt(fn, {value!r}, False); "
    code += "print(json.dumps(ida_funcs.get_func_cmt(fn, False)))"
    result = client._call("py_eval", {"code": code})
    assert not result.get("stderr"), result
    return json.loads(result["stdout"])


def test_real_discard_save_and_immediate_reopen(real_database):
    config, logs = real_database
    database = Path(config.database_path)
    original = hashlib.sha256(database.read_bytes()).hexdigest()
    marker = uuid.uuid4().hex
    with ida_client_stage(config, "discard", IdaWriteClient, logs) as client:
        previous = _comment(client)
        assert _comment(client, marker) == marker
    assert hashlib.sha256(database.read_bytes()).hexdigest() == original
    with ida_client_stage(config, "readback", IdaWriteClient, logs) as client:
        assert _comment(client) == previous
    with ida_client_stage(config, "save", IdaWriteClient, logs) as client:
        _comment(client, marker)
        client.save()
    with ida_client_stage(config, "saved-readback", IdaWriteClient, logs) as client:
        assert _comment(client) == marker


@pytest.mark.parametrize("exception", [RuntimeError("model failed"), KeyboardInterrupt()])
def test_real_exception_releases_idb_and_workers(real_database, exception):
    config, logs = real_database
    owner = IdaMcpLifecycle(config, "exception", logs)
    with pytest.raises(type(exception)), owner:
        raise exception
    table = process_table()
    assert not any(same_process(p, table) for p in owner._owned.values())
    with IdaMcpLifecycle(config, "reopen", logs):
        pass


@pytest.mark.skipif(os.name == "nt", reason="Windows SIGTERM does not invoke the worker's signal handler")
def test_real_worker_sigterm_does_not_save_unapproved_changes(real_database):
    config, logs = real_database
    database = Path(config.database_path)
    original = hashlib.sha256(database.read_bytes()).hexdigest()
    owner = IdaMcpLifecycle(config, "worker-sigterm", logs)
    with pytest.raises(IdalibLifecycleError, match="worker exited"), owner:
        client = IdaWriteClient(owner.url, config.timeout_s, database=owner.database)
        _comment(client, "must not be implicitly saved")
        os.kill(owner._worker.pid, signal.SIGTERM)
        deadline = time.monotonic() + config.shutdown_timeout_s
        while same_process(owner._worker, process_table()) and time.monotonic() < deadline:
            time.sleep(0.1)
    assert hashlib.sha256(database.read_bytes()).hexdigest() == original


def test_real_long_running_stages(real_database):
    seconds = int(os.environ.get("RE_AGENT_IDALIB_SOAK_SECONDS", "0"))
    if seconds <= 0:
        pytest.skip("Set RE_AGENT_IDALIB_SOAK_SECONDS=7260 for a run exceeding two hours")
    config, logs = real_database
    started = time.monotonic()
    cycles = 0
    while time.monotonic() - started < seconds:
        phase = ("reverse", "checker", "recover")[cycles % 3]
        owner = IdaMcpLifecycle(config, phase, logs)
        with owner:
            # The first stage outlives its 120s idle TTL. Later stages cross
            # a heartbeat interval, resembling model latency between requests.
            duration = 130 if cycles == 0 else 35
            until = min(started + seconds, time.monotonic() + duration)
            while time.monotonic() < until:
                time.sleep(min(30, max(0, until - time.monotonic())))
                owner.check_ready()
                print(f"IDA soak: stage={cycles + 1} phase={phase} elapsed={time.monotonic() - started:.0f}s",
                      flush=True)
            client = IdaWriteClient(owner.url, config.timeout_s, database=owner.database)
            result = client._call("py_eval", {"code": "print('RE_AGENT_ALIVE')"})
            assert "RE_AGENT_ALIVE" in result.get("stdout", "")
        table = process_table()
        assert not any(same_process(p, table) for p in owner._owned.values())
        cycles += 1
    assert cycles > 0
    print(f"IDA soak completed: {cycles} stages in {time.monotonic() - started:.1f}s", flush=True)
