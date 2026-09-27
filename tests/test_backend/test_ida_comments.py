"""Managed comments preserve human text and use only the regular function slot."""
from __future__ import annotations

import contextlib
import io
import sys
from types import SimpleNamespace

import pytest

from re_agent.backend.ida_comments import comment_result, comment_script, managed_comment


@pytest.mark.parametrize("old", ["", "[re-agent:begin]\nA\n[re-agent:end]"])
def test_create_and_replace(old):
    expected = "[re-agent:begin]\nB\n[re-agent:end]"
    assert expected == managed_comment(old, "B")
    assert expected == managed_comment(expected, "B")


def test_preserve_outside_text_exactly():
    old = "Human\n\n[re-agent:begin]\nA\n[re-agent:end]\nTail\n"
    assert old.replace("\nA\n", "\nB\n") == managed_comment(old, "B")


@pytest.mark.parametrize("old", ["Legacy A\nLegacy B", "[re-agent:begin]\nA", "[re-agent:end]",
                                  "[re-agent:begin]\nA\n[re-agent:end]\n[re-agent:begin]\nB\n[re-agent:end]",
                                  "prefix[re-agent:begin]\nA\n[re-agent:end]"])
def test_unowned_or_malformed_comment_requires_explicit_replacement(old):
    with pytest.raises(ValueError):
        managed_comment(old, "B")
    assert managed_comment(old, "B", replace=True) == "[re-agent:begin]\nB\n[re-agent:end]"


@pytest.mark.parametrize("body", ["contains [re-agent:begin]", "contains [re-agent:end]", "bad\x00text"])
def test_proposal_cannot_inject_markers_or_nul(body):
    with pytest.raises(ValueError):
        managed_comment("", body)


@pytest.fixture
def ida(monkeypatch):
    state = {"comment": "A", "writes": [], "reject": False, "mismatch": False}
    function = SimpleNamespace(start_ea=0x1000)

    def set_comment(f, text, repeatable):
        state["writes"].append((f.start_ea, text, repeatable))
        if state["reject"]:
            return False
        state["comment"] = "unexpected" if state["mismatch"] else text
        return True

    monkeypatch.setitem(sys.modules, "ida_funcs", SimpleNamespace(
        get_func=lambda ea: function if 0x1000 <= ea < 0x1010 else None,
        get_func_cmt=lambda f, repeatable: state["comment"], set_func_cmt=set_comment))
    monkeypatch.setitem(sys.modules, "idaapi", SimpleNamespace(BADADDR=-1))
    monkeypatch.setitem(sys.modules, "ida_name", SimpleNamespace(get_name_ea=lambda bad, name: 0x1000))
    return state


def execute(request):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        exec(comment_script(request), {})
    return comment_result({"stdout": output.getvalue()})


def test_helper_reads_and_guardedly_sets_regular_function_comment(ida):
    assert execute({"mode": "read", "address": "0x1000"})["comment"] == "A"
    assert ida["writes"] == []
    body = 'B "\\\n中文; __import__("not_executed")'
    result = execute({"mode": "apply", "address": "0x1000", "expected": "A", "proposed": body})
    assert body == result["comment"]
    assert [(0x1000, body, False)] == ida["writes"]


@pytest.mark.parametrize("address", ["0x1001", "0x9999"])
def test_helper_rejects_non_entry(ida, address):
    with pytest.raises(RuntimeError, match="function entry"):
        execute({"mode": "read", "address": address})
    assert ida["writes"] == []


def test_stale_snapshot_is_not_overwritten(ida):
    with pytest.raises(RuntimeError, match="changed"):
        execute({"mode": "apply", "address": "0x1000", "expected": "older", "proposed": "B"})
    assert ida["writes"] == []


@pytest.mark.parametrize("failure", ["reject", "mismatch"])
def test_helper_reports_write_and_readback_failures(ida, failure):
    ida[failure] = True
    with pytest.raises(RuntimeError):
        execute({"mode": "apply", "address": "0x1000", "expected": "A", "proposed": "B"})


@pytest.mark.parametrize("payload", [{}, {"stdout": ""}, {"stderr": "error"},
                                      {"stdout": '__RE_AGENT_COMMENT__{}'},
                                      {"stdout": '__RE_AGENT_COMMENT__invalid'}])
def test_missing_or_invalid_response_is_failure(payload):
    with pytest.raises(RuntimeError):
        comment_result(payload)


@pytest.mark.parametrize("proposed", ["A" * 1025, "中" * 342], ids=["ascii", "utf8"])
def test_oversized_write_is_rejected_without_mutation(ida, proposed):
    with pytest.raises(RuntimeError, match="UTF-8 bytes.*1024"):
        execute({"mode": "apply", "address": "0x1000", "expected": "A", "proposed": proposed})
    assert ida["writes"] == []
    assert ida["comment"] == "A"


def test_exact_byte_budget_and_unchanged_oversized_comment(ida):
    proposed = "中" * 341 + "A"
    assert proposed == execute({"mode": "apply", "address": "0x1000", "expected": "A",
                                "proposed": proposed})["comment"]
    ida["comment"] = "A" * 1025
    ida["writes"].clear()
    assert ida["comment"] == execute({"mode": "apply", "address": "0x1000", "expected": ida["comment"],
                                      "proposed": ida["comment"]})["comment"]
    assert ida["writes"] == []


@pytest.mark.parametrize("previous", ["", "Human comment"])
@pytest.mark.parametrize("failure", ["truncate", "reject", "raise", "read"])
def test_failed_write_restores_and_verifies_previous_comment(ida, monkeypatch, previous, failure):
    ida["comment"] = previous
    funcs = sys.modules["ida_funcs"]
    original_set = funcs.set_func_cmt
    original_get = funcs.get_func_cmt
    proposed = managed_comment("", "important evidence\n" * 10)

    def set_comment(f, text, repeatable):
        result = original_set(f, text, repeatable)
        if len(ida["writes"]) == 1:
            # Model a smaller backend budget: both markers survive the lost middle.
            ida["comment"] = text[:32] + "\n" + text.split("\n")[-1]
            if failure == "reject":
                return False
            if failure == "raise":
                raise RuntimeError("setter failed after mutation")
        return result

    def get_comment(f, repeatable):
        if failure == "read" and len(ida["writes"]) == 1:
            raise RuntimeError("read failed after mutation")
        return original_get(f, repeatable)

    monkeypatch.setattr(funcs, "set_func_cmt", set_comment)
    monkeypatch.setattr(funcs, "get_func_cmt", get_comment)
    with pytest.raises(RuntimeError, match="previous comment restored and verified"):
        execute({"mode": "apply", "address": "0x1000", "expected": previous, "proposed": proposed})
    assert previous == ida["comment"]
    assert [(0x1000, proposed, False), (0x1000, previous, False)] == ida["writes"]


@pytest.mark.parametrize("recovery", ["reject", "mismatch", "raise", "read"])
def test_failed_recovery_preserves_both_errors(ida, monkeypatch, recovery):
    funcs = sys.modules["ida_funcs"]
    original_set = funcs.set_func_cmt

    def set_comment(f, text, repeatable):
        result = original_set(f, text, repeatable)
        ida["comment"] = "unexpected"
        if len(ida["writes"]) == 2:
            if recovery == "reject":
                return False
            if recovery == "raise":
                raise RuntimeError("restore setter failed")
        return result

    def get_comment(f, repeatable):
        if recovery == "read" and len(ida["writes"]) == 2:
            raise RuntimeError("restore read failed")
        return ida["comment"]

    monkeypatch.setattr(funcs, "set_func_cmt", set_comment)
    monkeypatch.setattr(funcs, "get_func_cmt", get_comment)
    with pytest.raises(RuntimeError, match="readback mismatch.*restoration failed or could not be confirmed"):
        execute({"mode": "apply", "address": "0x1000", "expected": "A", "proposed": "B"})
    assert len(ida["writes"]) == 2
