"""Recovery runs must preserve the preview/write boundary and report uncertainty."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from re_agent.config.schema import RecoveryConfig
from re_agent.recovery.runner import _parse_response, run_recovery


def client() -> Mock:
    value = Mock()
    value.tools.return_value = [
        {"name": name, "description": name, "inputSchema": {"type": "object"}}
        for name in ("decompile", "declare_type", "py_eval", "recovery_set_local_type", "idb_save", "unknown_write")
    ]
    value.call.return_value = {"ok": True}
    value.health.return_value = {"idb_path": "/tmp/test.i64", "module": "test", "imagebase": "0x400000"}
    value.snapshot.return_value = {"functions": [{"address": "0x401000"}], "types": []}
    value.verify.return_value = [{"ok": True}]
    value.backup.return_value = "/tmp/test.backup.i64"
    return value


def provider(*responses: dict) -> Mock:
    value = Mock()
    value.supports_conversations = False
    value.send.side_effect = [json.dumps(response) for response in responses]
    return value


def finish(**kwargs: object) -> dict:
    return {"action": "finish", "summary": "Recovered", "checks": [], "unresolved": [], **kwargs}


def run(tmp_path: Path, llm: Mock, backend: Mock, **kwargs: object) -> dict:
    return run_recovery(llm, backend, ["0x401000"], RecoveryConfig(max_steps=4), tmp_path / "run.json", **kwargs)


@pytest.mark.parametrize("tool", ["declare_type", "py_eval", "recovery_set_local_type", "idb_save", "unknown_write"])
def test_preview_never_dispatches_unapproved_tools(tmp_path: Path, tool: str) -> None:
    backend = client()
    result = run(tmp_path, provider({"action": "tool", "name": tool, "arguments": {}}, finish()), backend)
    backend.call.assert_not_called()
    backend.backup.assert_not_called()
    assert result["status"] == "planned"
    assert result["events"][0]["status"] == "denied"


def test_backup_precedes_first_write_and_verified_save(tmp_path: Path) -> None:
    backend = client()
    llm = provider(
        {"action": "tool", "name": "declare_type", "arguments": {"decls": ["struct C { void *vt; };"]}},
        finish(checks=[{"kind": "local", "address": "0x401000", "name": "obj", "type": "C *"}]),
    )
    result = run(tmp_path, llm, backend, write=True, save=True)
    assert result["status"] == "verified"
    assert result["saved"] is True
    names = [call[0] for call in backend.mock_calls]
    assert names.index("backup") < names.index("call") < names.index("verify") < names.index("save")


def test_tool_failure_keeps_journal_and_suppresses_save(tmp_path: Path) -> None:
    backend = client()
    backend.call.side_effect = RuntimeError("connection lost after write")
    result = run(tmp_path, provider({"action": "tool", "name": "declare_type", "arguments": {}}),
                 backend, write=True, save=True)
    assert result["status"] == "failed"
    backend.save.assert_not_called()
    report = json.loads((tmp_path / "run.json").read_text())
    assert report["write_attempted"] is True
    assert report["backup_path"]
    assert report["events"][0]["status"] == "failed"


def test_nested_write_error_does_not_count_as_success(tmp_path: Path) -> None:
    backend = client()
    backend.call.return_value = {"result": [{"ok": False, "error": "bad type"}]}
    result = run(tmp_path, provider({"action": "tool", "name": "declare_type", "arguments": {}}),
                 backend, write=True, save=True)
    assert result["status"] == "failed"
    backend.save.assert_not_called()


@pytest.mark.parametrize("checks,verification", [([], []), ([{"kind": "local"}], [{"ok": False}])])
def test_agent_claim_is_not_verification(tmp_path: Path, checks: list, verification: list) -> None:
    backend = client()
    backend.verify.return_value = verification
    result = run(tmp_path, provider(finish(checks=checks)), backend, write=True, save=True)
    assert result["status"] == "incomplete"
    backend.save.assert_not_called()


def test_budget_exhaustion_is_not_success(tmp_path: Path) -> None:
    backend = client()
    response = {"action": "tool", "name": "decompile", "arguments": {"addrs": ["0x401000"]}}
    result = run(tmp_path, provider(*[response] * 4), backend)
    assert result["status"] == "budget-exhausted"
    assert backend.call.call_count == 4


def test_database_switch_stops_before_writing(tmp_path: Path) -> None:
    backend = client()
    backend.health.side_effect = [backend.health.return_value, {"idb_path": "/tmp/other.i64"}]
    result = run(tmp_path, provider({"action": "tool", "name": "declare_type", "arguments": {}}),
                 backend, write=True)
    assert result["status"] == "failed"
    backend.call.assert_not_called()


def test_save_requires_write(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="--write"):
        run(tmp_path, provider(), client(), save=True)


def test_python_syntax_error_is_rejected_before_remote_dispatch(tmp_path: Path) -> None:
    backend = client()
    result = run(tmp_path, provider(
        {"action": "tool", "name": "py_eval", "arguments": {"code": "x = (1, keyword=2)"}},
        finish(checks=[{"kind": "local", "address": "0x401000", "name": "obj", "type": "C *"}]),
    ), backend, write=True)
    assert result["events"][0]["status"] == "invalid"
    backend.call.assert_not_called()
    backend.backup.assert_not_called()
    assert result["status"] == "verified"


def _initial_payload(llm: Mock) -> dict:
    history = llm.send.call_args_list[0].args[0]
    return json.loads(history[1].content)  # history[0] is the system prompt


def _file_run(tmp_path: Path, llm: Mock, backend: Mock, roots: list[str], **kwargs: object) -> dict:
    settings = RecoveryConfig(max_steps=4, file_roots=roots)
    return run_recovery(llm, backend, ["0x401000"], settings, tmp_path / "run.json", **kwargs)


def test_file_tools_absent_and_denied_without_roots(tmp_path: Path) -> None:
    backend = client()
    llm = provider({"action": "tool", "name": "read", "arguments": {"path": "a.h"}}, finish())
    result = _file_run(tmp_path, llm, backend, roots=[])
    payload = _initial_payload(llm)
    assert "read" not in {tool["name"] for tool in payload["tools"]}
    assert "file_roots" not in payload
    assert result["events"][0]["status"] == "denied"
    backend.call.assert_not_called()


def test_file_tools_present_and_dispatched_host_side(tmp_path: Path) -> None:
    root = tmp_path / "refs"
    root.mkdir()
    (root / "a.h").write_text("struct A {};\n", encoding="utf-8")
    backend = client()
    llm = provider({"action": "tool", "name": "read", "arguments": {"path": "a.h"}}, finish())
    result = _file_run(tmp_path, llm, backend, roots=[str(root)])
    payload = _initial_payload(llm)
    assert {"read", "grep", "glob"}.issubset({tool["name"] for tool in payload["tools"]})
    assert str(root.resolve()) in payload["file_roots"]
    assert result["events"][0]["status"] == "ok"
    assert result["events"][0]["result"]["content"] == "struct A {};"
    backend.call.assert_not_called()  # host-side tool, never routed to the IDB


def test_missing_file_root_fails_before_any_dispatch(tmp_path: Path) -> None:
    backend = client()
    result = _file_run(tmp_path, provider(finish()), backend, roots=[str(tmp_path / "nope")])
    assert result["status"] == "failed"
    assert "not a directory" in result["error"]


def test_response_parser_accepts_single_action_but_not_multiple() -> None:
    action = {"action": "tool", "name": "decompile", "arguments": {"addr": "0x401000"}}
    assert _parse_response("Inspect the target.\n" + json.dumps(action)) == action
    with pytest.raises(ValueError, match="one action"):
        _parse_response(json.dumps(action) + "\n" + json.dumps(action))


def test_local_write_outside_selection_is_never_dispatched(tmp_path: Path) -> None:
    backend = client()
    result = run(tmp_path, provider(
        {"action": "tool", "name": "recovery_set_local_type", "arguments": {"address": "0x402000"}},
        finish(),
    ), backend, write=True)
    assert result["events"][0]["status"] == "invalid"
    backend.call.assert_not_called()
    backend.backup.assert_not_called()
