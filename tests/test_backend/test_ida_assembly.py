"""Physical register evidence, including one alias denoting two registers."""
from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest

from re_agent.backend.ida_assembly import ASSEMBLY_MARKER, assembly_result, assembly_script
from re_agent.backend.ida_mcp import IdaMcpBackend
from tests.test_backend.test_ida_mcp import _backend, _ok


@pytest.mark.parametrize("width, registers", [(1, ("al", "sil")), (2, ("ax", "si")),
                                              (4, ("eax", "esi")), (8, ("rax", "rsi"))])
def test_helper_decodes_each_operand_reg_and_width_without_reusing_aliases(monkeypatch, capsys, width, registers):
    addresses = ["b67a1", "b67a6"]
    rows = {
        0xb67a1: ("mov weaponStr_0, offset wszText", [(1, "weaponStr_0", 0), (5, "offset wszText", 0)]),
        0xb67a6: (f"cmovz weaponStr_0, {registers[0]}", [(1, "weaponStr_0", 6), (1, registers[0], 0)]),
    }

    def decode(insn, ea):
        insn.ops = [SimpleNamespace(n=n, type=kind, reg=reg, dtype=2, value=12345)
                    for n, (kind, printed, reg) in enumerate(rows[ea][1])]
        return 5

    monkeypatch.setitem(sys.modules, "ida_ua", SimpleNamespace(
        insn_t=SimpleNamespace, decode_insn=decode, o_void=0, o_reg=1, get_dtype_size=lambda dtype: width,
    ))
    monkeypatch.setitem(sys.modules, "ida_idp", SimpleNamespace(
        get_reg_name=lambda reg, size: {0: registers[0], 6: registers[1]}[reg] if size == width else None,
    ))
    monkeypatch.setitem(sys.modules, "ida_lines", SimpleNamespace(
        tag_remove=lambda text: text, generate_disasm_line=lambda ea, flags: rows[ea][0],
    ))
    monkeypatch.setitem(sys.modules, "idc", SimpleNamespace(
        print_insn_mnem=lambda ea: rows[ea][0].split()[0],
        print_operand=lambda ea, n: rows[ea][1][n][1],
    ))
    exec(assembly_script(addresses), {})
    result = assembly_result({"stdout": capsys.readouterr().out}, addresses)
    assert result["b67a1"] == f"mov {registers[0]}, offset wszText ; IDA aliases: operand 0: weaponStr_0={registers[0]}"
    assert result["b67a6"] == (
        f"cmovz {registers[1]}, {registers[0]} ; IDA aliases: operand 0: weaponStr_0={registers[1]}"
    )


@pytest.mark.parametrize("payload", [
    {}, {"stdout": "{}"}, {"stderr": "failed"},
    {"stdout": ASSEMBLY_MARKER + '{"ok": true, "instructions": {}}'},
    {"stdout": ASSEMBLY_MARKER + '{"ok": false, "error": "decode failed"}'},
    {"stdout": ASSEMBLY_MARKER + '{"ok": true, "instructions": {"b67a1": ""}}'},
])
def test_decoder_rejects_incomplete_evidence(payload):
    with pytest.raises(RuntimeError):
        assembly_result(payload, ["b67a1"])


@pytest.mark.parametrize("decode_failure", [False, True])
def test_backend_uses_decoded_instructions_or_marks_explicit_gap(monkeypatch, decode_failure):
    rows = [{"addr": "b67a1", "instruction": "mov weaponStr_0, offset wszText"},
            {"addr": "b67a6", "instruction": "cmovz weaponStr_0, eax"}]
    decoded = {"b67a1": "mov eax, offset wszText", "b67a6": "cmovz esi, eax"}
    responses = {
        "__tools__": ["disasm", "py_eval"],
        "disasm": _ok({"asm": {"lines": rows}}),
        "py_eval": RuntimeError("decoder disabled") if decode_failure else _ok({
            "stdout": ASSEMBLY_MARKER + json.dumps({"ok": True, "instructions": decoded}),
        }),
    }
    calls = _backend(monkeypatch, responses)
    result = IdaMcpBackend(database="owned-session").get_asm("b6650")
    assert result is not None
    assert result.instruction_count == 2
    assert result.call_count == 0
    if decode_failure:
        assert "Physical operands unverified: decoder disabled" in result.instructions
    else:
        assert result.instructions == "b67a1  mov eax, offset wszText\nb67a6  cmovz esi, eax"
    assert [params["arguments"]["database"] for method, params in calls
            if method == "tools/call"] == ["owned-session", "owned-session"]
