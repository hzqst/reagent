"""Reverser code-block extraction from fenced responses."""
from __future__ import annotations

from re_agent.agents.reverser import ReverserAgent

_CODE = "int CCFileClass::GetFileSize()\n{\n    return this->Buffer.Size;\n}"


def test_prefers_cpp_block_after_an_asm_block():
    response = (
        "All evidence is in.\n\n"
        "```asm\nmov eax, [esi+58h]\ntest eax, eax\n```\n\n"
        "Branch 1 maps to Buffer.Buffer.\n\n"
        f"```cpp\n{_CODE}\n```\n\n"
        "**Notes**\n- offsets verified\n"
    )

    assert ReverserAgent._extract_code(response) == _CODE


def test_accepts_c_plus_plus_tag():
    response = f"```c++\n{_CODE}\n```"

    assert ReverserAgent._extract_code(response) == _CODE


def test_tagless_block_is_the_fallback():
    response = "analysis\n\n```\nvoid f() {}\n```\n"

    assert ReverserAgent._extract_code(response) == "void f() {}"


def test_json_block_does_not_leak_into_code():
    response = f"```cpp\n{_CODE}\n```\n\n```json\n{{\"symbol\": {{\"name\": \"N\"}}}}\n```\n"

    assert ReverserAgent._extract_code(response) == _CODE


def test_crlf_fences_are_handled():
    response = "```cpp\r\nvoid f()\r\n```\r\n"

    assert ReverserAgent._extract_code(response) == "void f()"


def test_unfenced_response_is_returned_as_is():
    assert ReverserAgent._extract_code("just prose") == "just prose"
