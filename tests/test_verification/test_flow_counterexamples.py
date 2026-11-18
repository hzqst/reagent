"""Behavioral counterexamples for candidates with inconclusive structural evidence."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from re_agent.verification.differential import compare_commands
from tests.test_verification.test_abi_calls import CANDIDATE as CLOSE
from tests.test_verification.test_unrolling import CANDIDATE as CLEANUP


@pytest.mark.parametrize("reference,candidate,driver,case,expected,actual", [
    (
        CLOSE,
        CLOSE.replace("if (bad) ", "").replace("if (other) ", ""),
        """
        struct Handle { int *data; };
        struct CBaseFileSystem { void Close(Handle *); };
        bool bad, other;
        int warnings;
        void Trace_FClose(Handle *) {}
        void Warning(int id) { warnings = 10 * warnings + id; }
        FUNCTION
        int main() {
            std::cin >> bad;
            other = bad;
            CBaseFileSystem().Close(new Handle{new int(1)});
            std::cout << warnings;
        }
        """,
        0, 0, 12,
    ),
    (
        CLEANUP,
        CLEANUP.replace("        if (c == 0)\n            break;\n", ""),
        """
        FUNCTION
        int main() {
            char in[16] = {'A', 0, 'B'}, out[16] = {};
            int index;
            std::cin >> index;
            W_CleanupName(in, out);
            std::cout << static_cast<int>(out[index]);
        }
        """,
        2, 0, ord("b"),
    ),
    (
        "void f(bool enabled, int &value) { if (enabled) { if (value == 0) value = 7; } }",
        "void f(bool enabled, int &value) {}",
        """
        FUNCTION
        int main() {
            bool enabled;
            std::cin >> enabled;
            int value = 0;
            f(enabled, value);
            std::cout << value;
        }
        """,
        1, 7, 0,
    ),
], ids=["unconditional-warnings", "missing-nul-exit", "deleted-conditional-write"])
def test_differential_detects_removed_behavior(
    tmp_path: Path, reference: str, candidate: str, driver: str, case: int, expected: int, actual: int,
) -> None:
    compiler = shutil.which("c++")
    if not compiler:
        pytest.skip("C++ compiler required")
    for name, code in (("reference", reference), ("candidate", candidate)):
        source = tmp_path / f"{name}.cpp"
        # The calling convention on the original ELF32 target is irrelevant to the harness.
        code = code.replace("__attribute__((cdecl)) ", "")
        source.write_text("#include <iostream>\n#include <ctype.h>\n" + driver.replace("FUNCTION", code))
        subprocess.run([compiler, str(source), "-o", str(tmp_path / f"{name}.exe")], check=True)

    result = compare_commands([str(tmp_path / "reference.exe")], [str(tmp_path / "candidate.exe")], [case], tmp_path)

    assert not result.passed
    assert {"case": case, "reference": expected, "candidate": actual} == json.loads(result.findings[0])
