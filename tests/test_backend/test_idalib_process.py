"""Process ownership must survive detaching, but never follow PID reuse."""
from __future__ import annotations

from unittest.mock import Mock

from re_agent.backend import idalib_process as processes


def test_kill_does_not_follow_recycled_pid(monkeypatch):
    original = processes.ProcessIdentity(100, 1, "original")
    current = processes.ProcessIdentity(100, 1, "replacement")
    monkeypatch.setattr(processes, "process_table", lambda: {100: current})
    kill = Mock()
    run = Mock()
    monkeypatch.setattr(processes.os, "kill", kill)
    monkeypatch.setattr(processes.subprocess, "run", run)
    processes.kill_owned({100: original})
    kill.assert_not_called()
    run.assert_not_called()


def test_descendants_exclude_other_supervisors_and_include_nested_workers():
    rows = [processes.ProcessIdentity(pid, parent, str(pid))
            for pid, parent in [(100, 1), (101, 100), (102, 101), (200, 1), (201, 200)]]
    table = {p.pid: p for p in rows}
    assert set(processes.descendants(100, table)) == {100, 101, 102}


def test_reparented_worker_identity_remains_owned():
    original = processes.ProcessIdentity(101, 100, "worker-created")
    orphan = processes.ProcessIdentity(101, 1, "worker-created")
    assert processes.same_process(original, {101: orphan})
