from __future__ import annotations

from re_agent.utils.evidence import bounded_evidence


def test_tool_text_escapes_only_unencodable_characters() -> None:
    assert bounded_evidence("中😀\udc00") == "中😀\\udc00"
