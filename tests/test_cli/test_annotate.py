"""Tests for the annotate command, its write client, and struct-change guards."""
from __future__ import annotations

from typing import Any

import pytest

from re_agent.backend.ida_write import (
    IdaWriteClient,
    address_key,
    apply_member_change,
    is_unnamed,
)
from re_agent.cli.cmd_annotate import _decide, _Entry, _layout_problem
from re_agent.core.models import StructChange, SymbolProposal

_DECLARATION = "struct S\n{\nchar a;\nint b;\n};\n"


def _client(monkeypatch, handler):
    """Patch the write transport; ``handler(tool, args)`` returns tool content."""
    calls: list[tuple[str, dict[str, Any]]] = []

    def post(url, method, params, timeout_s, session_id=None):
        if method == "initialize":
            return {}, "sess"
        calls.append((params["name"], params["arguments"]))
        outcome = handler(params["name"], params["arguments"])
        if isinstance(outcome, Exception):
            raise outcome
        return {"structuredContent": outcome, "content": [], "isError": False}, "sess"

    monkeypatch.setattr("re_agent.backend.ida_write.post_jsonrpc", post)
    return calls


# -- transport -----------------------------------------------------------------


def test_rename_delegates_dry_run_and_refuses_overwrite(monkeypatch):
    calls = _client(monkeypatch, lambda tool, args: {"result": []})

    IdaWriteClient("http://x/mcp").rename_functions([("0x1", "A::b")], dry_run=True)

    tool, args = calls[0]
    assert tool == "rename"
    # The server reads these from inside ``batch``, not from the top level.
    assert args["batch"]["dry_run"] is True
    assert args["batch"]["allow_overwrite"] is False
    assert "dry_run" not in args
    assert "allow_overwrite" not in args


def test_bare_hex_addresses_are_rendered_for_ida(monkeypatch):
    calls = _client(monkeypatch, lambda tool, args: {"result": []})

    IdaWriteClient("http://x/mcp").rename_functions([("70e000", "A::b")], dry_run=True)

    assert calls[0][1]["batch"]["func"][0]["addr"] == "0x70e000"


def test_function_names_are_indexed_by_address_and_by_name(monkeypatch):
    """A proposal may be addressed by a symbol name rather than an address."""
    _client(
        monkeypatch,
        lambda tool, args: {
            "result": [{"query": "sub_455DD0", "fn": {"addr": "0x455dd0", "name": "sub_455DD0"}}]
        },
    )

    names = IdaWriteClient("http://x/mcp").function_names(["sub_455DD0"])

    assert names[address_key("0x455dd0")] == "sub_455DD0"
    assert names[address_key("sub_455DD0")] == "sub_455DD0"


def test_interior_address_resolves_to_the_containing_function(monkeypatch):
    """An address inside a function resolves to that function.

    Regression: the result was only indexed by the address IDA resolved to, so
    an interior address matched nothing and ``--only-unnamed`` treated the
    already-named containing function as unnamed.  Renaming through an interior
    address renames the whole function.
    """
    _client(
        monkeypatch,
        lambda tool, args: {
            "result": [
                {
                    "query": "0x559E7B",
                    "fn": {"addr": "0x559e40", "name": "LoadOptionsClass::SaveMission_559E40"},
                }
            ]
        },
    )

    names = IdaWriteClient("http://x/mcp").function_names(["0x559E7B"])

    assert names[address_key("0x559E7B")] == "LoadOptionsClass::SaveMission_559E40"


def test_interior_address_is_skipped_as_already_named():
    entries = [_Entry(address="0x559E7B", proposal=SymbolProposal(name="LoadOptionsClass::SaveMission"))]

    _decide(
        entries,
        {address_key("0x559E7B"): "LoadOptionsClass::SaveMission_559E40"},
        only_unnamed=True,
        include_flagged=False,
    )

    assert entries[0].action == "skip-named"


def test_rename_returns_per_item_results(monkeypatch):
    """The tool answers with {"func": [...], "summary": {...}}, not a list."""
    _client(
        monkeypatch,
        lambda tool, args: {"func": [{"addr": "0x1", "ok": True}], "summary": {"ok": 1}},
    )

    results = IdaWriteClient("http://x/mcp").rename_functions([("0x1", "A::b")], dry_run=True)

    assert results == [{"addr": "0x1", "ok": True}]


def test_protocol_error_raises(monkeypatch):
    _client(monkeypatch, lambda tool, args: RuntimeError("connection refused"))

    with pytest.raises(RuntimeError, match="connection refused"):
        IdaWriteClient("http://x/mcp").rename_functions([("0x1", "A::b")], dry_run=True)


def _truncating_client(monkeypatch, structured, meta):
    """Patch the transport so every tool call answers with a truncated preview."""

    def post(url, method, params, timeout_s, session_id=None):
        if method == "initialize":
            return {}, "sess"
        return (
            {
                "structuredContent": structured,
                "content": [],
                "isError": False,
                "_meta": {"ida_mcp": meta},
            },
            "sess",
        )

    monkeypatch.setattr("re_agent.backend.ida_write.post_jsonrpc", post)


def test_truncated_output_is_downloaded(monkeypatch):
    """A bulk lookup past the server's output limit must not be read as a preview.

    Regression: ignoring ``_meta`` made ``function_names`` see only the first few
    hundred addresses, so ``--only-unnamed`` treated already-named functions as
    unnamed and reported them as renames to apply.
    """
    _truncating_client(
        monkeypatch,
        {"result": [{"query": "0x1", "fn": {"addr": "0x1", "name": "preview"}}]},
        {"output_truncated": True, "download_url": "http://x/full.json"},
    )
    fetched = []
    monkeypatch.setattr(
        "re_agent.backend.ida_mcp._get_json",
        lambda url, timeout_s: fetched.append(url)
        or {"result": [{"query": "0x1", "fn": {"addr": "0x1", "name": "real"}}]},
    )

    names = IdaWriteClient("http://x/mcp").function_names(["0x1"])

    assert fetched == ["http://x/full.json"]
    assert names[address_key("0x1")] == "real"


def test_truncated_output_without_url_raises(monkeypatch):
    _truncating_client(monkeypatch, {"result": []}, {"output_truncated": True})

    with pytest.raises(RuntimeError, match="without a download URL"):
        IdaWriteClient("http://x/mcp").function_names(["0x1"])


def test_comment_operation_uses_fixed_helper_and_rejects_empty_result(monkeypatch):
    calls = _client(monkeypatch, lambda tool, args: {"result": []})
    with pytest.raises(RuntimeError, match="no unique result"):
        IdaWriteClient("http://x/mcp").comment_operation("read", "0x1")
    assert calls[0][0] == "py_eval"


def test_read_declaration_rejects_non_identifier(monkeypatch):
    _client(monkeypatch, lambda tool, args: {})

    with pytest.raises(RuntimeError, match="non-identifier"):
        IdaWriteClient("http://x/mcp").read_declaration("TechnoClass; rm -rf /")


# -- naming guards --------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "sub_70E000",
        "nullsub_5",
        "FUN_00401000",
        "unknown_4A0",
        "loc_736C8A",
        # IDA and the imported type libraries qualify placeholders with a class.
        "MouseClass::sub_568350",
        "TechnoClass_sub_70DE00",
    ],
)
def test_placeholder_names_are_recognised(name):
    assert is_unnamed(name)


@pytest.mark.parametrize(
    "name",
    [
        "TechnoClass::DecayGattlingStage_70E000",
        "AudioController::Stop_405D40",
        "MouseClass::IsCoordInMap_568350",
        "UnitClass_UpdateEdgeOfWorld_736C10",
    ],
)
def test_reviewed_names_are_not_placeholders(name):
    assert not is_unnamed(name)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # Headers zero-pad to 7 digits; IDA does not.
        ("0x0529160", "529160"),
        ("0x529160", "529160"),
        ("529160", "529160"),
        ("0x00000000", "0"),
        # Symbol names are not addresses and pass through lowercased.
        ("sub_7018C0", "sub_7018c0"),
    ],
)
def test_address_key_normalises_across_spellings(raw, expected):
    assert address_key(raw) == expected


def test_only_unnamed_skips_already_named_addresses():
    entries = [_Entry(address="0x1", proposal=SymbolProposal(name="A::b"))]

    _decide(entries, {"1": "TechnoClass::Existing"}, only_unnamed=True, include_flagged=False)

    assert entries[0].action == "skip-named"


def test_placeholder_names_are_still_eligible():
    entries = [_Entry(address="0x1", proposal=SymbolProposal(name="A::b"))]

    _decide(entries, {"1": "sub_1"}, only_unnamed=True, include_flagged=False)

    assert entries[0].action == "apply"


def test_flagged_proposals_are_skipped_unless_included():
    proposal = SymbolProposal(name="A::b", checker_ok=False, checker_notes=["contradicts 0x4A4"])
    entries = [_Entry(address="0x1", proposal=proposal)]

    _decide(entries, {}, only_unnamed=False, include_flagged=False)
    assert entries[0].action == "skip-flagged"
    assert entries[0].notes == ["contradicts 0x4A4"]

    _decide(entries, {}, only_unnamed=False, include_flagged=True)
    assert entries[0].action == "apply"


# -- struct member edits --------------------------------------------------------


def test_rename_member_rewrites_the_line():
    change = StructChange(struct_name="S", member="b", operation="rename", type_str="c")

    patched, diff = apply_member_change(_DECLARATION, change)

    assert "int c;" in patched and "int b;" not in patched
    assert len(diff) == 2


def test_retype_member_rewrites_the_line():
    change = StructChange(struct_name="S", member="b", operation="retype", type_str="unsigned int")

    patched, _ = apply_member_change(_DECLARATION, change)

    assert "unsigned int b;" in patched


def test_missing_member_is_rejected():
    change = StructChange(struct_name="S", member="zzz", operation="rename", type_str="q")

    with pytest.raises(ValueError, match="not found"):
        apply_member_change(_DECLARATION, change)


def test_rename_without_a_new_name_is_rejected():
    change = StructChange(struct_name="S", member="b", operation="rename")

    with pytest.raises(ValueError, match="needs a new name"):
        apply_member_change(_DECLARATION, change)


# -- struct guard ---------------------------------------------------------------


def test_size_change_is_rejected():
    change = StructChange(struct_name="T", member="m", operation="retype", type_str="long long")
    problem = _layout_problem(change, {"size": 0x520, "members": {}}, {"size": 0x524, "members": {}})

    assert problem is not None and "size changed" in problem


def test_move_must_land_where_asked():
    change = StructChange(struct_name="T", member="m", operation="move", offset="0x4")
    problem = _layout_problem(change, {"size": 8, "members": {}}, {"size": 8, "members": {"m": "0x8"}})

    assert problem is not None and "not 0x4" in problem


def test_sound_move_passes():
    change = StructChange(struct_name="T", member="m", operation="move", offset="0x4")

    assert _layout_problem(change, {"size": 8, "members": {}}, {"size": 8, "members": {"m": "0x4"}}) is None


def test_retype_is_not_offset_checked():
    change = StructChange(struct_name="T", member="m", operation="retype", type_str="int")

    assert _layout_problem(change, {"size": 8, "members": {}}, {"size": 8, "members": {"m": "0x0"}}) is None
