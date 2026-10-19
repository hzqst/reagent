"""Tests for decoding a raw memory blob from the ``global`` tool."""
from __future__ import annotations

import struct

from re_agent.backend.memory_view import describe_memory


def _utf32(text: str, terminate: bool = True) -> bytes:
    data = b"".join(ord(ch).to_bytes(4, "little") for ch in text)
    return data + b"\x00\x00\x00\x00" if terminate else data


def test_utf32_literal_is_reported_with_its_terminator() -> None:
    """The gameui 0x1636c8 case: get_string returned only ``"%"``."""
    described = describe_memory(_utf32("%s1 (%s2)"))

    assert described["strings"]["utf32le"] == {
        "value": "%s1 (%s2)",
        "characters": 9,
        "byte_length": 36,
        "terminator_observed": True,
    }


def test_short_wide_literal_is_kept_when_the_terminator_is_seen() -> None:
    assert describe_memory(_utf32("%hs"))["strings"]["utf32le"]["value"] == "%hs"


def test_unterminated_short_run_is_not_reported_as_text() -> None:
    """Without a terminator, a 2-character window is coincidence, not a string."""
    described = describe_memory(_utf32("ab", terminate=False))

    assert "utf32le" not in described["strings"]


def test_ascii_literal_is_reported() -> None:
    described = describe_memory(b"sprites/wsplash3.spr\x00junk")

    assert described["strings"]["ascii"]["value"] == "sprites/wsplash3.spr"
    assert described["strings"]["ascii"]["terminator_observed"] is True


def test_utf16_literal_is_reported() -> None:
    data = "%hs".encode("utf-16-le") + b"\x00\x00"

    assert describe_memory(data)["strings"]["utf16le"]["value"] == "%hs"


def test_scalar_reports_integer_and_float_views() -> None:
    described = describe_memory(struct.pack("<f", 2.0), preferred_size=4)

    scalar = described["scalar"]
    assert scalar["float32"] == 2.0
    assert scalar["hex"] == hex(0x40000000)


def test_same_bytes_keep_both_readings() -> None:
    """0x25 0 0 0 is the integer 37 and a one-character wide string."""
    described = describe_memory(b"\x25\x00\x00\x00", preferred_size=4)

    assert described["scalar"]["unsigned"] == 37
    # One character is below the threshold, so no string claim is made.
    assert "strings" in described


def test_empty_blob_reports_nothing_but_length() -> None:
    described = describe_memory(b"")

    assert described["length"] == 0
    assert described["strings"] == {}
