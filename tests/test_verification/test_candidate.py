"""Tests for candidate overlays and validation gates."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from re_agent.config.schema import ProjectProfile, ValidationConfig
from re_agent.core.models import FunctionTarget, Verdict
from re_agent.parity.source_indexer import SourceIndexer
from re_agent.verification.candidate import (
    cleanup_candidate_overlay,
    create_candidate_overlay,
    discover_candidate_files,
    extract_candidate_body,
    validate_candidate,
)


def test_candidate_body_ignores_a_brace_in_a_leading_comment() -> None:
    """Regression: a struct sketched in a comment was mistaken for the body.

    Taken from a real candidate, which the extractor rejected as "more than one
    function body" because the first brace it found was the one in ``// struct
    KamikazeControl { ... };``.
    """
    code = (
        "// KamikazeControl 由证据可得：8 字节\n"
        "//   struct KamikazeControl { AircraftClass *Item; CellClass *Cell; };\n"
        "\n"
        "void Kamikaze::Add(AircraftClass *pAircraft)\n"
        "{\n"
        "    if (!pAircraft->Type->MissileSpawn) { pAircraft->Crash(0); }\n"
        "}\n"
    )

    body = extract_candidate_body(code)

    assert body.startswith("{\n    if (!pAircraft->Type->MissileSpawn)")
    assert body.endswith("}")


def test_candidate_body_ignores_braces_in_block_comments_and_literals() -> None:
    code = (
        "/* layout: struct S { int a; }; */\n"
        'const char *kShape = "}";\n'
        "void Foo() { Bar(); }\n"
    )

    assert extract_candidate_body(code) == "{ Bar(); }"


def test_candidate_body_still_rejects_trailing_code() -> None:
    with pytest.raises(ValueError, match="exactly one complete function body"):
        extract_candidate_body("void Foo() { Bar(); }\nvoid Baz() { Qux(); }")


def test_candidate_body_still_rejects_class_wrappers() -> None:
    with pytest.raises(ValueError, match="without namespace/class wrappers"):
        extract_candidate_body("struct S { void Foo() {} };")


def test_candidate_body_rejects_code_with_no_body() -> None:
    with pytest.raises(ValueError, match="no function body"):
        extract_candidate_body("void Foo();")


def test_candidate_body_accepts_leading_type_definitions() -> None:
    """Regression for #13: leading structs/unions were mistaken for the body."""
    code = (
        "// ... file header comment ...\n"
        "#include <cstdint>\n"
        "\n"
        "struct Matrix3D   { float row[3][4]; };\n"
        "struct DirStruct  { unsigned short Raw; unsigned short Padding; };\n"
        "class  FacingClass\n"
        "{\n"
        "public:\n"
        "    DirStruct   DesiredFacing;\n"
        "    unsigned char RotationTimer[0x0C];\n"
        "};\n"
        "union VoxelIndexKey { int Raw; };\n"
        "class  ILocomotion;\n"
        "\n"
        "Matrix3D *__stdcall Draw_Matrix(ILocomotion *this_, Matrix3D *sret, VoxelIndexKey *pIndex)\n"
        "{\n"
        "    if (pIndex->Raw) { Foo(); }\n"
        "    return sret;\n"
        "}\n"
    )

    body = extract_candidate_body(code)

    assert body.startswith("{\n    if (pIndex->Raw)")
    assert body.endswith("}")


def test_candidate_body_accepts_elaborated_struct_return_type() -> None:
    """``struct`` in the return type is not a wrapper around the function."""
    assert extract_candidate_body("struct M *__thiscall C::F(C *this) { return 0; }\n") == "{ return 0; }"


def test_candidate_body_still_rejects_union_wrapper() -> None:
    with pytest.raises(ValueError, match="without namespace/class wrappers"):
        extract_candidate_body("union S { void Foo() {} };")


def test_candidate_overlay_replaces_only_function_body(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    source_root.mkdir()
    source_file = source_root / "Train.cpp"
    source_file.write_text(
        "void CTrain::Go() { OldCall(); }\nvoid CTrain::Stop() { KeepMe(); }\n",
        encoding="utf-8",
    )
    indexer = SourceIndexer(source_root, ProjectProfile(source_root=str(source_root)))
    source = indexer.find("CTrain", "Go")
    assert source is not None

    candidate = create_candidate_overlay(
        FunctionTarget("0x100", "CTrain", "Go"),
        "void CTrain::Go() { NewCall(); }",
        source,
        source_root,
        tmp_path / "reports",
    )
    text = candidate.read_text(encoding="utf-8")
    assert "NewCall" in text
    assert "OldCall" not in text
    assert "KeepMe" in text
    assert source_file.read_text(encoding="utf-8").startswith("void CTrain::Go() { OldCall")


def test_candidate_overlay_sanitizes_qualified_class_name(tmp_path: Path) -> None:
    candidate = create_candidate_overlay(
        FunctionTarget("0x100", "app::ui::Widget", "Render"),
        "void Render() { NewCall(); }",
        None,
        tmp_path / "src",
        tmp_path / "reports",
    )
    assert candidate.exists()
    assert "::" not in candidate.name
    assert candidate.read_text(encoding="utf-8") == "void Render() { NewCall(); }\n"


def test_candidate_overlay_rejects_invalid_candidate_before_writing(tmp_path: Path) -> None:
    """A candidate rejected for structure must not leave an overlay file behind."""
    target = FunctionTarget("0x100", "C", "F")
    with pytest.raises(ValueError, match="exactly one complete function body"):
        create_candidate_overlay(
            target,
            "void F() { G(); }\nvoid H() { I(); }\n",
            None,
            tmp_path / "src",
            tmp_path / "reports",
        )
    assert not (tmp_path / "reports" / "candidates" / "0x100").exists()


def test_candidate_overlay_sanitizes_template_and_operator_names(tmp_path: Path) -> None:
    candidate = create_candidate_overlay(
        FunctionTarget("0x101", "std::vector<int, alloc>", "operator<"),
        "void operator<() {}",
        None,
        tmp_path / "src",
        tmp_path / "reports",
    )
    assert candidate.exists()
    illegal_chars = set(':<>,/\\*?"| ')
    assert not illegal_chars.intersection(candidate.name)


@pytest.mark.skipif(not Path("/bin/sh").exists(), reason="POSIX shell required")
def test_validation_gate_runs_configured_command(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.cpp"
    candidate.write_text("void f() {}", encoding="utf-8")
    verdict = validate_candidate(
        ValidationConfig(
            build_commands=["test -f '{candidate_file}'"],
            working_directory=str(tmp_path),
            trust_configured_commands=True,
        ),
        candidate,
        None,
    )
    assert verdict.verdict == Verdict.PASS


def test_required_build_without_command_fails(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.cpp"
    candidate.write_text("void f() {}", encoding="utf-8")
    verdict = validate_candidate(ValidationConfig(require_build=True), candidate, None)
    assert verdict.verdict == Verdict.FAIL


def test_nonisolated_command_must_consume_candidate(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.cpp"
    candidate.write_text("this is invalid C++", encoding="utf-8")
    verdict = validate_candidate(
        ValidationConfig(build_commands=["true"], working_directory=str(tmp_path)),
        candidate,
        None,
    )
    assert verdict.verdict == Verdict.FAIL
    assert "explicitly consume" in verdict.summary


@pytest.mark.skipif(not Path("/bin/sh").exists(), reason="POSIX shell required")
def test_untrusted_shell_gate_is_not_accepted_as_proof(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.cpp"
    candidate.write_text("invalid C++", encoding="utf-8")
    verdict = validate_candidate(
        ValidationConfig(
            build_commands=["true # $RE_AGENT_CANDIDATE_FILE"],
            working_directory=str(tmp_path),
        ),
        candidate,
        None,
    )
    assert verdict.verdict == Verdict.UNKNOWN
    assert "trust_configured_commands" in verdict.summary


def test_failed_project_copy_creation_cleans_temporary_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside.cpp"
    outside.write_text("void CTest::Foo() {}\n", encoding="utf-8")
    indexer = SourceIndexer(tmp_path, ProjectProfile(source_root=str(tmp_path)))
    source = indexer.find("CTest", "Foo")
    assert source is not None
    overlay = tmp_path / "forced-overlay"
    monkeypatch.setattr(
        "re_agent.verification.candidate.tempfile.mkdtemp", lambda **_: str(overlay)
    )

    with pytest.raises(ValueError, match="outside validation.project_root"):
        create_candidate_overlay(
            FunctionTarget("0x100", "CTest", "Foo"),
            "void CTest::Foo() {}",
            source,
            tmp_path,
            tmp_path / "reports",
            project_root=project,
            copy_project=True,
        )

    assert not overlay.exists()


def test_copy_project_builds_against_isolated_candidate(tmp_path: Path) -> None:
    project = tmp_path / "project"
    source_root = project / "src"
    source_root.mkdir(parents=True)
    source_file = source_root / "Train.cpp"
    source_file.write_text("void CTrain::Go() { OldCall(); }\n", encoding="utf-8")
    indexer = SourceIndexer(source_root, ProjectProfile(source_root=str(source_root)))
    source = indexer.find("CTrain", "Go")
    assert source is not None

    candidate = create_candidate_overlay(
        FunctionTarget("0x100", "CTrain", "Go"),
        "void CTrain::Go() { NewCall(); }",
        source,
        source_root,
        tmp_path / "reports",
        project_root=project,
        copy_project=True,
    )
    verdict = validate_candidate(
        ValidationConfig(
            copy_project=True,
            project_root=str(project),
            build_commands=[[sys.executable, "-c",
                             "from pathlib import Path; assert 'NewCall' in Path('src/Train.cpp').read_text()"]],
            trust_configured_commands=True,
        ),
        candidate,
        str(source_file),
    )
    assert verdict.verdict == Verdict.PASS
    assert "OldCall" in source_file.read_text(encoding="utf-8")
    overlay_root = candidate.parents[1]
    cleanup_candidate_overlay(candidate)
    assert not overlay_root.exists()


def test_discover_candidate_files_matches_across_case_and_padding(tmp_path: Path) -> None:
    """A reverse run keys the directory on the address as typed, so the case
    may differ from recovery's canonical target (0x73C5F0 vs 0x73c5f0)."""
    report_dir = tmp_path / "reports"
    overlay = report_dir / "candidates" / "0x73C5F0"
    overlay.mkdir(parents=True)
    (overlay / "UnitClass_DrawAsSHP_73C5F0.cpp").write_text("void f() {}\n", encoding="utf-8")
    padded = report_dir / "candidates" / "0x00000073c5f0"
    padded.mkdir()
    (padded / "dup.cpp").write_text("void f() {}\n", encoding="utf-8")

    found = discover_candidate_files(report_dir, ["0x73c5f0"])

    assert {path.name for path in found} == {"UnitClass_DrawAsSHP_73C5F0.cpp", "dup.cpp"}


def test_discover_candidate_files_ignores_other_addresses_and_non_cpp(tmp_path: Path) -> None:
    report_dir = tmp_path / "reports"
    other = report_dir / "candidates" / "0x401000"
    other.mkdir(parents=True)
    (other / "other.cpp").write_text("void g() {}\n", encoding="utf-8")
    target = report_dir / "candidates" / "0x73C5F0"
    target.mkdir()
    (target / ".re-agent-overlay").write_text("schema_version=1\n", encoding="utf-8")
    (target / "notes.md").write_text("x\n", encoding="utf-8")
    (target / "sub").mkdir()

    assert discover_candidate_files(report_dir, ["0x73c5f0"]) == []
    assert discover_candidate_files(tmp_path / "missing", ["0x73c5f0"]) == []
