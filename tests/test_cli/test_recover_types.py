"""Independent recovery command routing, selection and exit behavior."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from re_agent.cli.main import main
from re_agent.config.schema import BackendConfig, OutputConfig, ReAgentConfig, RecoveryConfig


@pytest.mark.parametrize("status,code", [("planned", 0), ("verified", 0), ("incomplete", 1), ("failed", 1)])
@pytest.mark.parametrize("backend", ["ida-mcp", "ida"])
def test_recovery_uses_own_model_and_canonical_targets(tmp_path: Path, status: str, code: int, backend: str) -> None:
    config = ReAgentConfig(backend=BackendConfig(type=backend), recovery=RecoveryConfig(provider="pi", model="test"))
    module = "re_agent.cli.cmd_recover_types"
    with patch(f"{module}.load_config", return_value=config), \
         patch(f"{module}.create_recovery_provider", return_value=Mock()) as factory, \
         patch(f"{module}.IdaRecoveryClient"), \
         patch(f"{module}.run_recovery", return_value={"status": status}) as run:
        result = main(["recover-types", "--address", "00401000", "--address", "0x401000",
                       "--output", str(tmp_path / "report.json")])
    assert result == code
    factory.assert_called_once_with(config.recovery)
    assert run.call_args.args[2] == ["0x401000"]
    assert run.call_args.kwargs["write"] is False


def test_recovery_rejects_save_without_write() -> None:
    assert main(["recover-types", "--address", "0x401000", "--save"]) == 1


def test_recovery_includes_candidates_only_when_requested(tmp_path: Path) -> None:
    # reverse names the directory after the typed address, so the overlay is
    # "0x73C5F0" while recovery canonicalizes the target to "0x73c5f0".
    overlay = tmp_path / "candidates" / "0x73C5F0"
    overlay.mkdir(parents=True)
    (overlay / "UnitClass_DrawAsSHP_73C5F0.cpp").write_text("void f() {}\n", encoding="utf-8")
    config = ReAgentConfig(
        backend=BackendConfig(type="ida-mcp"),
        recovery=RecoveryConfig(provider="pi", model="test"),
        output=OutputConfig(report_dir=str(tmp_path)),
    )
    module = "re_agent.cli.cmd_recover_types"
    argv = ["recover-types", "--address", "0x73c5f0", "--include-candidates",
            "--output", str(tmp_path / "r.json")]
    with patch(f"{module}.load_config", return_value=config), \
         patch(f"{module}.create_recovery_provider", return_value=Mock()), \
         patch(f"{module}.IdaRecoveryClient"), \
         patch(f"{module}.run_recovery", return_value={"status": "planned"}) as run:
        assert main(argv) == 0
    evidence = run.call_args.kwargs["evidence"]
    assert evidence.count("Candidate overlay from a prior reverse run") == 1
    assert "UnitClass_DrawAsSHP_73C5F0.cpp" in evidence


@pytest.mark.parametrize("write", [False, True])
def test_recovery_omits_candidates_by_default_even_with_overlay(
    tmp_path: Path, write: bool,
) -> None:
    overlay = tmp_path / "candidates" / "0x73C5F0"
    overlay.mkdir(parents=True)
    (overlay / "UnitClass_DrawAsSHP_73C5F0.cpp").write_text("void f() {}\n", encoding="utf-8")
    config = ReAgentConfig(
        backend=BackendConfig(type="ida-mcp"),
        recovery=RecoveryConfig(provider="pi", model="test"),
        output=OutputConfig(report_dir=str(tmp_path)),
    )
    module = "re_agent.cli.cmd_recover_types"
    argv = ["recover-types", "--address", "0x73c5f0", "--output", str(tmp_path / "r.json")]
    if write:
        argv.append("--write")
    with patch(f"{module}.load_config", return_value=config), \
         patch(f"{module}.create_recovery_provider", return_value=Mock()), \
         patch(f"{module}.IdaRecoveryClient"), \
         patch(f"{module}.run_recovery", return_value={"status": "planned"}) as run:
        assert main(argv) == 0
    assert "Candidate overlay from a prior reverse run" not in run.call_args.kwargs["evidence"]


def test_recovery_errors_when_requested_candidates_are_absent(tmp_path: Path) -> None:
    config = ReAgentConfig(
        backend=BackendConfig(type="ida-mcp"),
        recovery=RecoveryConfig(provider="pi", model="test"),
        output=OutputConfig(report_dir=str(tmp_path)),
    )
    module = "re_agent.cli.cmd_recover_types"
    with patch(f"{module}.load_config", return_value=config), \
         patch(f"{module}.create_recovery_provider") as factory:
        assert main(["recover-types", "--address", "0x73c5f0", "--include-candidates",
                     "--output", str(tmp_path / "r.json")]) == 1
    factory.assert_not_called()


def test_recovery_rejects_candidates_for_other_addresses(tmp_path: Path) -> None:
    overlay = tmp_path / "candidates" / "0x401000"
    overlay.mkdir(parents=True)
    (overlay / "other.cpp").write_text("void g() {}\n", encoding="utf-8")
    config = ReAgentConfig(
        backend=BackendConfig(type="ida-mcp"),
        recovery=RecoveryConfig(provider="pi", model="test"),
        output=OutputConfig(report_dir=str(tmp_path)),
    )
    module = "re_agent.cli.cmd_recover_types"
    with patch(f"{module}.load_config", return_value=config), \
         patch(f"{module}.create_recovery_provider", return_value=Mock()), \
         patch(f"{module}.IdaRecoveryClient"), \
         patch(f"{module}.run_recovery", return_value={"status": "planned"}) as run:
        assert main(["recover-types", "--address", "0x73c5f0", "--include-candidates",
                     "--output", str(tmp_path / "r.json")]) == 1
    run.assert_not_called()


@pytest.mark.parametrize("backend,recovery", [("stub", RecoveryConfig()), ("ida-mcp", None)])
def test_unsupported_recovery_never_starts_model(backend: str, recovery: RecoveryConfig | None) -> None:
    config = ReAgentConfig(backend=BackendConfig(type=backend), recovery=recovery)
    module = "re_agent.cli.cmd_recover_types"
    with patch(f"{module}.load_config", return_value=config), patch(f"{module}.create_recovery_provider") as factory:
        assert main(["recover-types", "--address", "0x401000"]) == 1
    factory.assert_not_called()


def _reference_config(tmp_path: Path) -> ReAgentConfig:
    return ReAgentConfig(
        backend=BackendConfig(type="ida-mcp"),
        recovery=RecoveryConfig(provider="pi", model="test"),
        output=OutputConfig(report_dir=str(tmp_path)),
    )


def _reference_tree(tmp_path: Path) -> Path:
    refs = tmp_path / "refs"
    (refs / "sub").mkdir(parents=True)
    (refs / "keep.h").write_text("struct Header {};\n", encoding="utf-8")
    (refs / "sub" / "impl.cpp").write_text("void impl() {}\n", encoding="utf-8")
    (refs / "notes.txt").write_text("ignore me\n", encoding="utf-8")
    return refs


def _names(paths: list) -> set[str]:
    return {Path(p).name for p in paths}


def test_recovery_evidence_dirs_expand_recursively_with_extension_filter(tmp_path: Path) -> None:
    refs = _reference_tree(tmp_path)
    config = _reference_config(tmp_path)
    module = "re_agent.cli.cmd_recover_types"
    with patch(f"{module}.load_config", return_value=config), \
         patch(f"{module}.create_recovery_provider", return_value=Mock()), \
         patch(f"{module}.IdaRecoveryClient"), \
         patch(f"{module}.run_recovery", return_value={"status": "planned"}) as run:
        assert main(["recover-types", "--address", "0x401000", "--evidence-dirs", str(refs),
                     "--output", str(tmp_path / "r.json")]) == 0
    files = run.call_args.kwargs["evidence_files"]
    assert _names(files) == {"keep.h", "impl.cpp"}       # .txt filtered out by source_extensions
    assert run.call_args.kwargs["evidence"] == ""        # content is not injected


def test_recovery_evidence_dirs_accept_glob_and_underscore_spelling(tmp_path: Path) -> None:
    refs = _reference_tree(tmp_path)
    config = _reference_config(tmp_path)
    module = "re_agent.cli.cmd_recover_types"
    with patch(f"{module}.load_config", return_value=config), \
         patch(f"{module}.create_recovery_provider", return_value=Mock()), \
         patch(f"{module}.IdaRecoveryClient"), \
         patch(f"{module}.run_recovery", return_value={"status": "planned"}) as run:
        assert main(["recover-types", "--address", "0x401000",
                     "--evidence_dirs", str(refs / "sub" / "*.cpp"),
                     "--output", str(tmp_path / "r.json")]) == 0
    assert _names(run.call_args.kwargs["evidence_files"]) == {"impl.cpp"}


def test_recovery_evidence_dirs_glob_still_applies_extension_filter(tmp_path: Path) -> None:
    refs = _reference_tree(tmp_path)
    config = _reference_config(tmp_path)
    module = "re_agent.cli.cmd_recover_types"
    with patch(f"{module}.load_config", return_value=config), \
         patch(f"{module}.create_recovery_provider", return_value=Mock()), \
         patch(f"{module}.IdaRecoveryClient"), \
         patch(f"{module}.run_recovery", return_value={"status": "planned"}) as run:
        # A broad glob is not a literal file: .txt must be filtered out.
        assert main(["recover-types", "--address", "0x401000", "--evidence-dirs", str(refs / "*"),
                     "--output", str(tmp_path / "r.json")]) == 0
    assert "notes.txt" not in _names(run.call_args.kwargs["evidence_files"])


def test_recovery_evidence_is_referenced_by_path(tmp_path: Path) -> None:
    note = tmp_path / "note.md"
    note.write_text("# Fact\nCFrustum is 96 bytes.\n", encoding="utf-8")
    config = _reference_config(tmp_path)
    module = "re_agent.cli.cmd_recover_types"
    with patch(f"{module}.load_config", return_value=config), \
         patch(f"{module}.create_recovery_provider", return_value=Mock()), \
         patch(f"{module}.IdaRecoveryClient"), \
         patch(f"{module}.run_recovery", return_value={"status": "planned"}) as run:
        assert main(["recover-types", "--address", "0x401000", "--evidence", str(note),
                     "--output", str(tmp_path / "r.json")]) == 0
    assert _names(run.call_args.kwargs["evidence_files"]) == {"note.md"}
    assert "96 bytes" not in run.call_args.kwargs["evidence"]   # not inlined


def test_recovery_rejects_missing_evidence_file(tmp_path: Path) -> None:
    config = _reference_config(tmp_path)
    module = "re_agent.cli.cmd_recover_types"
    with patch(f"{module}.load_config", return_value=config), \
         patch(f"{module}.create_recovery_provider") as factory:
        assert main(["recover-types", "--address", "0x401000", "--evidence", str(tmp_path / "nope.md"),
                     "--output", str(tmp_path / "r.json")]) == 1
    factory.assert_not_called()


def test_recovery_errors_when_evidence_dirs_match_nothing(tmp_path: Path) -> None:
    config = _reference_config(tmp_path)
    module = "re_agent.cli.cmd_recover_types"
    with patch(f"{module}.load_config", return_value=config), \
         patch(f"{module}.create_recovery_provider") as factory:
        assert main(["recover-types", "--address", "0x401000",
                     "--evidence-dirs", str(tmp_path / "does-not-exist"),
                     "--output", str(tmp_path / "r.json")]) == 1
    factory.assert_not_called()
