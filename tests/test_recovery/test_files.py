"""Host-side read/grep/glob tools: bounded output and strict root confinement."""
from __future__ import annotations

from pathlib import Path

import pytest

from re_agent.recovery import files


def make_root(tmp_path: Path) -> Path:
    root = tmp_path / "refs"
    (root / "sub").mkdir(parents=True)
    (root / "a.h").write_text("struct A { int x; };\n// needle\n", encoding="utf-8")
    (root / "sub" / "b.cpp").write_text("void b() {}\n", encoding="utf-8")
    return root.resolve()


def test_read_pages_lines_and_reports_totals(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    out = files.dispatch([root], "read", {"path": "a.h", "offset": 0, "limit": 1})
    assert out["content"] == "struct A { int x; };"
    assert out["total_lines"] == 2
    assert out["path"] == "a.h"


def test_grep_matches_with_file_and_line(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    out = files.dispatch([root], "grep", {"pattern": "needle"})
    assert out["count"] == 1
    assert out["matches"][0] == {"root": str(root), "file": "a.h", "line": 2, "text": "// needle"}


def test_grep_include_glob_limits_files(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    assert files.dispatch([root], "grep", {"pattern": "void", "include": "*.h"})["count"] == 0
    assert files.dispatch([root], "grep", {"pattern": "void", "include": "*.cpp"})["count"] == 1


def test_glob_lists_relative_paths(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    out = files.dispatch([root], "glob", {"pattern": "**/*.cpp"})
    assert out["count"] == 1
    assert out["files"][0]["file"].endswith("b.cpp")


def test_path_outside_root_is_rejected(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    (tmp_path / "secret.txt").write_text("SECRET\n", encoding="utf-8")
    with pytest.raises(files.FileToolError):
        files.dispatch([root], "read", {"path": "../secret.txt"})


def test_second_root_resolves_when_first_does_not(tmp_path: Path) -> None:
    first = make_root(tmp_path)
    second = tmp_path / "other"
    second.mkdir()
    (second / "c.txt").write_text("hello\n", encoding="utf-8")
    out = files.dispatch([first, second.resolve()], "read", {"path": "c.txt"})
    assert out["content"] == "hello"


def test_invalid_regex_is_reported_not_raised_as_crash(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    with pytest.raises(files.FileToolError, match="invalid regex"):
        files.dispatch([root], "grep", {"pattern": "("})
