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


def test_action_request_survives_leading_prose():
    """Regression: a request preceded by a sentence was dropped entirely.

    ``0xb02e0`` returned "I need the bytes ...\\n\\n{"actions":[...]}"; the old
    parser required the whole response to start with ``{``, so the action loop
    saw no request, the prose was handed to the candidate parser, and the
    function failed with "only type or initializer blocks were found".
    """
    response = (
        "I need the binary bytes of the format string at 0x1636c8 to confirm it.\n\n"
        '{"actions":[{"tool":"global","target":"0x1636c8"}]}'
    )

    payload = ReverserAgent._extract_json(response)

    assert payload is not None
    assert payload["actions"] == [{"tool": "global", "target": "0x1636c8"}]


def test_action_request_survives_prose_around_a_fenced_block():
    response = (
        "Need two symbols.\n\n"
        "```json\n"
        '{"actions":[{"tool":"asm","target":"0x10"}]}\n'
        "```\n\n"
        "Please return them."
    )

    payload = ReverserAgent._extract_json(response)

    assert payload is not None
    assert payload["actions"] == [{"tool": "asm", "target": "0x10"}]


def test_unrelated_json_snippet_does_not_shadow_the_action_request():
    response = (
        'Example of a proposal: {"symbol": {"name": "Foo::Bar"}}\n\n'
        '{"actions":[{"tool":"decompile","target":"0x20"}]}'
    )

    payload = ReverserAgent._extract_json(response)

    assert payload is not None
    assert payload["actions"] == [{"tool": "decompile", "target": "0x20"}]
