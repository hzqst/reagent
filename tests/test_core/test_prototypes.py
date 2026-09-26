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


@pytest.mark.parametrize("extra", [
    {"evidence_kind": "guess"},
    {"evidence_kind": "signature-bound", "confidence": "verified"},
    {"confidence": "certain"}, {"evidence_details": []},
    {"abi_evidence": {"return": ""}}, {"evidence_details": {"version": 1}},
])
def test_malformed_structured_evidence_is_rejected(extra):
    prototype = FunctionPrototypeProposal.from_dict({"declaration": "void __cdecl f();", **extra})
    assert prototype.validation_error


def test_structured_evidence_survives_artifact_roundtrip(tmp_path):
    prototype = FunctionPrototypeProposal(
        declaration="A *__thiscall f(A *this);", confidence="inferred",
        evidence_kind="signature-bound",
        evidence_details={"header": "A.h:10", "version": "matched version", "address_binding": "branches"},
        abi_evidence={"calling_convention": "ECX", "return": "all paths return this"},
    )
    path = tmp_path / "symbols.json"
    record_symbol(path, "0x1234", SymbolProposal(name="A::f", prototype=prototype))
    symbol = SymbolProposal.from_dict(load_symbols(path)[0])
    assert asdict(prototype) == asdict(symbol.prototype)
