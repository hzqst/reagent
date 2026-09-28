"""CLI success must include managed IDA shutdown, not only model completion."""
from __future__ import annotations

import json
from contextlib import contextmanager
from unittest.mock import Mock

from re_agent.backend.idalib_lifecycle import IdalibLifecycleError
from re_agent.cli.main import main
from re_agent.config.schema import BackendConfig, OutputConfig, ReAgentConfig, RecoveryConfig


def test_recovery_cleanup_failure_updates_journal_and_exit_code(tmp_path, monkeypatch, capsys):
    config = ReAgentConfig(backend=BackendConfig(type="idalib-mcp"), recovery=RecoveryConfig(),
                           output=OutputConfig(log_dir=str(tmp_path)))
    module = "re_agent.cli.cmd_recover_types"
    monkeypatch.setattr(module + ".load_config", lambda _: config)
    monkeypatch.setattr(module + ".create_recovery_provider", Mock())
    monkeypatch.setattr(module + ".run_recovery", Mock(return_value={"status": "verified", "saved": False}))

    @contextmanager
    def stage(*args):
        yield Mock()
        raise IdalibLifecycleError("worker remained alive")

    monkeypatch.setattr(module + ".ida_client_stage", stage)
    output = tmp_path / "recovery.json"
    assert main(["recover-types", "--address", "0x1000", "--write", "--output", str(output)]) == 1
    report = json.loads(output.read_text())
    assert report["status"] == "failed"
    assert "worker remained alive" in report["error"]
    assert "Without --save" in capsys.readouterr().err


def test_dry_run_address_does_not_require_idalib_or_database(monkeypatch):
    config = ReAgentConfig(backend=BackendConfig(type="idalib-mcp", database_path="missing.i64"))
    monkeypatch.setattr("re_agent.cli.cmd_reverse.load_config", lambda _: config)
    start = Mock(side_effect=AssertionError("dry-run must not start IDA"))
    monkeypatch.setattr("re_agent.backend.idalib.IdaMcpLifecycle", start)
    assert main(["reverse", "--address", "0x1000", "--dry-run"]) == 0
    start.assert_not_called()


def test_annotate_without_proposals_never_starts_ida(monkeypatch):
    config = ReAgentConfig(backend=BackendConfig(type="idalib-mcp", database_path="missing.i64"))
    module = "re_agent.cli.cmd_annotate"
    monkeypatch.setattr(module + ".load_config", lambda _: config)
    monkeypatch.setattr(module + "._load_entries", lambda *_: [])
    start = Mock(side_effect=AssertionError("empty annotate must not start IDA"))
    monkeypatch.setattr(module + ".ida_client_stage", start)
    assert main(["annotate"]) == 0
    start.assert_not_called()


def test_annotate_reports_saved_changes_even_when_shutdown_fails(monkeypatch, capsys):
    from re_agent.cli.cmd_annotate import _Entry
    from re_agent.core.models import SymbolProposal

    config = ReAgentConfig(backend=BackendConfig(type="idalib-mcp"))
    module = "re_agent.cli.cmd_annotate"
    entry = _Entry("0x1000", SymbolProposal("renamed"), current_name="old", name_status="applied")
    monkeypatch.setattr(module + ".load_config", lambda _: config)
    monkeypatch.setattr(module + "._load_entries", lambda *_: [entry])
    monkeypatch.setattr(module + "._annotate", Mock(return_value=(0, True, "")))

    @contextmanager
    def stage(*args):
        yield Mock()
        raise IdalibLifecycleError("cleanup failed")

    monkeypatch.setattr(module + ".ida_client_stage", stage)
    assert main(["annotate", "--write", "--save"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["saved"] is True
    assert report["undo"] == [{"address": "0x1000", "current_name": "old", "new_name": "renamed"}]
    assert "cleanup failed" in report["save_error"]
