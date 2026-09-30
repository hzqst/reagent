"""Tests for the parity engine address-fallback logic."""
from __future__ import annotations

from pathlib import Path

import pytest

from re_agent.config.schema import ParityConfig, ProjectProfile, ReAgentConfig
from re_agent.core.models import HookEntry, ParityStatus
from re_agent.parity.engine import fetch_ghidra_data, run_parity
from re_agent.parity.signals import check_call_count_mismatch
from re_agent.parity.source_indexer import SourceIndexer
from tests.test_backend.test_ida_mcp import _repeated_calls_backend


@pytest.mark.parametrize("source_calls, mismatch", [(6, False), (0, True)])
def test_ida_call_sites_reach_parity_without_false_mismatches(monkeypatch, tmp_path, source_calls, mismatch):
    backend = _repeated_calls_backend(monkeypatch)
    data = fetch_ghidra_data("0x10001100", backend)
    source = SourceIndexer(tmp_path, ProjectProfile()).analyze_body(
        "candidate.cpp", 1, "{ " + "NormalizeFrustumPlane(); " * source_calls + "}",
    )

    finding = check_call_count_mismatch(source, data)

    assert data.asm_ok
    assert data.asm_call_count == 6
    assert data.callees == 1
    assert (finding is not None) == mismatch
    if finding is not None:
        assert "vanilla has 6 calls" in finding.reason


def test_incomplete_ida_disassembly_is_not_used_for_parity(monkeypatch, tmp_path):
    backend = _repeated_calls_backend(monkeypatch)
    monkeypatch.setattr(backend, "_call", lambda tool, arguments: (
        {"asm": {"lines": ["10001100  ret"]}, "cursor": {"next": 5000}}
        if tool == "disasm" else {"result": []}
    ))

    data = fetch_ghidra_data("0x10001100", backend)
    source = SourceIndexer(tmp_path, ProjectProfile()).analyze_body("candidate.cpp", 1, "{ " + "f(); " * 6 + "}")

    assert not data.asm_ok
    assert "disassembly is incomplete" in data.asm_error
    assert check_call_count_mismatch(source, data) is None


def _make_config(source_root: str) -> ReAgentConfig:
    profile = ProjectProfile(
        hook_patterns=[
            r"RH_ScopedInstall\s*\(\s*(\w+)\s*,\s*(0x[0-9A-Fa-f]+)",
        ],
        class_macro="RH_ScopedClass",
        source_root=source_root,
        source_extensions=[".cpp"],
        hooks_csv=None,
    )
    config = ReAgentConfig.create_default()
    config.project_profile = profile
    config.parity = ParityConfig(enabled=True)
    return config


def test_address_only_hook_resolves_via_hook_index(tmp_path: Path) -> None:
    """An address-only hook (empty class/fn) should resolve its source
    function body via the hook_address_index built from hook patterns."""
    src = tmp_path / "CTrain.cpp"
    src.write_text('''\
RH_ScopedClass(CTrain);
RH_ScopedInstall(ProcessControl, 0x6F86A0);

void CTrain::ProcessControl() {
    if (m_nStatus == 5) {
        DoStuff();
        MoreLogic();
        EvenMore();
    }
}
''')
    config = _make_config(str(tmp_path))

    # Simulate an address-only hook with no class/fn metadata
    hook = HookEntry(
        class_path="",
        fn_name="",
        address="0x6f86a0",
        reversed=True,
        locked=False,
        is_virtual=False,
    )

    results = run_parity([hook], tmp_path, config)
    assert len(results) == 1
    # Source should have been found (not RED for "missing source")
    assert results[0]["source"] is not None
    assert "DoStuff" in results[0]["source"].body


def test_address_only_hook_no_match_is_red(tmp_path: Path) -> None:
    """An address-only hook with no matching hook pattern should get RED."""
    src = tmp_path / "test.cpp"
    src.write_text("void Foo() { }\n")
    config = _make_config(str(tmp_path))

    hook = HookEntry(
        class_path="",
        fn_name="",
        address="0xDEAD",
        reversed=True,
        locked=False,
        is_virtual=False,
    )

    results = run_parity([hook], tmp_path, config)
    assert len(results) == 1
    assert results[0]["status"] == ParityStatus.RED
