"""Scoped annotations never rename a target in comments-only mode."""
from __future__ import annotations

import json

import pytest

from re_agent.cli.cmd_annotate import cmd_annotate
from re_agent.cli.main import build_parser
from re_agent.config.schema import ReAgentConfig


class CommentClient:
    def __init__(self):
        self.calls = []
        self.comments = {"0x1000": "", "0x2000": ""}
        self.fail = ""

    def function_names(self, addresses):
        self.calls.append(("names", addresses))
        return {"1000": "Class::Method_1000", "2000": "sub_2000"}

    def comment_operation(self, mode, address, **params):
        address = hex(int(address, 16))
        self.calls.append((mode, address))
        if mode == "apply":
            if self.fail == "stale":
                self.comments[address] = "human edit"
            if params["expected"] != self.comments[address]:
                raise RuntimeError("changed since preflight")
            self.comments[address] = params["proposed"]
            if self.fail == "timeout":
                raise RuntimeError("timeout after write")
            if self.fail == "mismatch":
                self.comments[address] = "human edit"
        return {"address": address, "comment": self.comments[address]}

    def save(self):
        self.calls.append(("save", None))

    def rename_functions(self, *args, **kwargs):
        raise AssertionError("comments-only must not call rename, even for dry-run")

    def prototype_operation(self, *args, **kwargs):
        raise AssertionError("comments-only must not query or apply types")


@pytest.fixture
def run(monkeypatch, tmp_path, capsys):
    config = ReAgentConfig()
    config.backend.type = "ida-mcp"
    client = CommentClient()
    monkeypatch.setattr("re_agent.cli.cmd_annotate.load_config", lambda _: config)
    monkeypatch.setattr("re_agent.cli.cmd_annotate.IdaWriteClient", lambda *args: client)
    path = tmp_path / "symbols.json"

    def invoke(*options, rows=None):
        if rows is None:
            rows = [{"address": "0x1000", "name": "Class::Method", "comment": "B", "prototype": "invalid"},
                    {"address": "0x2000", "name": "Other", "comment": "other"}]
        path.write_text(json.dumps({"symbols": rows}))
        args = build_parser().parse_args(["annotate", "--symbols", str(path), *options])
        result = cmd_annotate(args)
        return result, json.loads(capsys.readouterr().out)

    return client, invoke


def test_scoped_dry_run_and_write_are_comments_only(run):
    client, invoke = run
    code, report = invoke("--address", "0X001000", "--comments-only", "--save")
    assert code == 0
    assert False is report["saved"]
    assert report["undo"] == []
    assert report["entries"][0]["name_status"] == "disabled"
    assert report["entries"][0]["prototype"]["status"] == "disabled"
    assert client.comments == {"0x1000": "", "0x2000": ""}
    assert client.calls == [("names", ["0x1000"]), ("read", "0x1000")]
    code, report = invoke("--address", "1000", "--comments-only", "--write", "--save")
    assert code == 0
    assert True is report["saved"]
    assert report["entries"][0]["comment_status"] == "applied"
    assert client.comments["0x2000"] == ""
    client.calls.clear()
    code, report = invoke("--address", "1000", "--comments-only", "--write")
    assert code == 0
    assert report["entries"][0]["comment_status"] == "unchanged"
    assert not any(mode == "apply" for mode, _ in client.calls)


def test_legacy_comment_conflict_and_explicit_migration(run):
    client, invoke = run
    client.comments["0x1000"] = "Legacy A\nLegacy B"
    code, report = invoke("--address", "1000", "--comments-only", "--write")
    assert code == 1
    assert report["entries"][0]["comment_status"] == "conflict"
    assert client.comments["0x1000"] == "Legacy A\nLegacy B"
    code, report = invoke("--address", "1000", "--comments-only", "--replace-function-comment")
    assert code == 0
    assert report["entries"][0]["comment"]["current"] == "Legacy A\nLegacy B"
    assert "Legacy" not in report["entries"][0]["comment"]["proposed"]
    assert client.comments["0x1000"] == "Legacy A\nLegacy B"
    code, report = invoke("--address", "1000", "--comments-only", "--replace-function-comment", "--write")
    assert code == 0
    assert "Legacy" not in client.comments["0x1000"]


@pytest.mark.parametrize("flag", ["--only-unnamed", "--allow-prototype-changes", "--allow-struct-changes"])
def test_incompatible_flags_fail_before_backend_access(run, flag):
    client, invoke = run
    with pytest.raises(ValueError, match="cannot be combined"):
        invoke("--comments-only", flag)
    assert client.calls == []


def test_replacement_requires_scope(run):
    client, invoke = run
    with pytest.raises(ValueError, match="requires --address"):
        invoke("--replace-function-comment", "--write")
    assert client.calls == []


@pytest.mark.parametrize("address", ["0x3000", "symbol", "-1", "0x"])
def test_missing_or_invalid_filter_is_error(run, address):
    client, invoke = run
    with pytest.raises(ValueError):
        invoke("--address", address, "--comments-only", "--write")
    assert client.calls == []


def test_conflicting_duplicates_fail_before_any_writes(run):
    client, invoke = run
    with pytest.raises(ValueError, match="Conflicting"):
        invoke("--comments-only", "--write", rows=[
            {"address": "0x1000", "name": "A"}, {"address": "001000", "name": "B"}])
    assert client.calls == []


def test_scope_excludes_unrelated_conflicts_and_identical_rows_collapse(run):
    client, invoke = run
    code, report = invoke("--address", "1000", "--comments-only", rows=[
        {"address": "0x1000", "name": "A", "comment": "B"},
        {"address": "001000", "name": "A", "comment": "B"},
        {"address": "0x2000", "name": "X"}, {"address": "2000", "name": "Y"}])
    assert code == 0
    assert len(report["entries"]) == 1
    assert all(address != "0x2000" for _, address in client.calls)


def test_repeatable_address_filter(run):
    _, invoke = run
    code, report = invoke("--address", "1000", "--address", "2000", "--comments-only")
    assert code == 0
    assert len(report["entries"]) == 2


@pytest.mark.parametrize("failure", ["stale", "timeout", "mismatch"])
def test_failed_write_or_verification_is_reported_without_retry_or_save(run, failure):
    client, invoke = run
    client.fail = failure
    code, report = invoke("--address", "1000", "--comments-only", "--write", "--save")
    assert code == 1
    assert report["entries"][0]["comment_status"] == "failed"
    assert False is report["saved"]
    assert report["save_error"]
    assert sum(mode == "apply" for mode, _ in client.calls) == 1
    assert not any(mode == "save" for mode, _ in client.calls)
