"""Structural counts ignore non-code tokens and preserve real decisions."""
from __future__ import annotations

import pytest

from re_agent.utils.text import count_control_flow, mask_non_code


@pytest.mark.parametrize("body, expected", [
    ("if (a) { if (b) work(); }", 2),
    ("if (a && b) work();", 2),
    ("if (a) return; if (b) return; work();", 2),
    ("if (a || b) return; work();", 2),
    ("if (a && (b || c)) work();", 3),
    ("return a ? 1 : b ? 2 : 0;", 2),
    ("return a & b | c;", 0),
    ("for (;;) { while (a) work(); }", 2),
    ('print("if for while && || ?");', 0),
    ("auto c = 'if'; auto d = '?';", 0),
    ('print(R"tag(if "for" && || ? /*)tag"); if (a) work();', 1),
    ('print(u8R"(if "for" && || ?)"); if (a) work();', 1),
    ('print("http://host"); if (a) work(); if (b) work();', 2),
    ('print("/*"); if (a) work(); print("*/");', 1),
    (r'print("escaped \" if &&"); if (a) work();', 1),
    ("// if (a && b)\n/* for (;;) */ if (a) work();", 1),
    ("// if (a) \\\nif (b) ignored();\nif (c) work();", 1),
    ("auto n = 1'000 + 0xA'B; if (a) work(); if (b) work();", 2),
    ("auto c = '\\''; if (a) work(); auto d = '\\\\'; if (b) work();", 2),
    ("if (a) goto done; done: return;", 2),
])
def test_control_flow_counts_code_only(body: str, expected: int) -> None:
    assert count_control_flow(body) == expected


@pytest.mark.parametrize("name", ["guard variable for", "vtable for", "typeinfo for"])
def test_ida_quoted_names_do_not_count_or_hide_following_code(name: str) -> None:
    code = f"if (`{name}'Dialog::map || !acquire(&`{name}'Dialog::map)) return map;\n"
    code += f"release(&`{name}'Dialog::map); if (other) work();"
    assert count_control_flow(code) == 3


def test_mask_preserves_offsets_and_newlines() -> None:
    code = 'if (a) /* for\nwhile */ print("? &&"); // if\n'
    masked = mask_non_code(code)
    assert len(masked) == len(code)
    assert [i for i, char in enumerate(masked) if char == "\n"] == [
        i for i, char in enumerate(code) if char == "\n"
    ]
    assert masked.startswith("if (a)")
    assert count_control_flow(masked) == 1
