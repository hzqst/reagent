"""Prototype proposals must survive artifacts without inheriting naming trust."""
from __future__ import annotations

from dataclasses import asdict

import pytest

from re_agent.core.models import FunctionPrototypeProposal, SymbolProposal
from re_agent.core.symbols import load_symbols, record_symbol


def test_legacy_symbol_has_no_prototype():
    symbol = SymbolProposal.from_dict({"name": "A::f", "confidence": "verified"})
    assert symbol is not None
    assert symbol.prototype is None


def test_prototype_round_trip(tmp_path):
    prototype = FunctionPrototypeProposal(
        declaration="void *__thiscall f(FileClass *this);",
        expected_current="void *__thiscall(void *this)",
        required_types=["FileClass"], confidence="verified",
        evidence=["header:12; matching address"], review_status="approved",
    )
    path = tmp_path / "symbols.json"
    record_symbol(path, "0x4A3890", SymbolProposal(name="FileClass::f", prototype=prototype))
    result = SymbolProposal.from_dict(load_symbols(path)[0])
    assert result is not None
    assert asdict(prototype) == asdict(result.prototype)


@pytest.mark.parametrize("raw", ["void f()", {}, {"declaration": 5}, {"declaration": "void f()", "evidence": "yes"}])
def test_malformed_prototype_is_reportable(raw):
    symbol = SymbolProposal.from_dict({"name": "f", "prototype": raw})
    assert symbol is not None
    assert symbol.prototype is not None
    assert symbol.prototype.validation_error


def test_name_verification_does_not_approve_prototype():
    symbol = SymbolProposal.from_dict({
        "name": "f", "confidence": "verified", "checker_ok": True,
        "prototype": {"declaration": "void f()"},
    })
    assert symbol is not None and symbol.prototype is not None
    assert symbol.prototype.confidence == "inferred"
    assert symbol.prototype.review_status == "unreviewed"
