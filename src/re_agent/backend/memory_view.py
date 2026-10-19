"""Decode a raw memory blob into the forms a reversed function needs.

IDA's ``get_global_value`` reports one scalar for a short item and arbitrary
hex bytes for a longer one, and its ``get_string`` reads a *char* string — so a
GCC ``wchar_t`` literal (4-byte UTF-32LE on the analyzed i386 targets) comes
back as a single ``"%"``.  A reversed function that passes such a literal to
``ConstructString`` cannot be verified from that, which is exactly the
``0x1636c8`` gap the gameui run hit.

This module turns already-read bytes into a description that names the scalar,
the printable ASCII/UTF-16/UTF-32 renderings, and whether the terminator was
actually observed, without guessing which reading the binary meant.
"""

from __future__ import annotations

import struct

# How many bytes a ``global`` request may pull back.  Wide literals in these
# targets are short (format strings and sprite paths), and the action result is
# capped separately by ``bounded_evidence``.
DEFAULT_GLOBAL_BYTES = 256

# A run of at least this many characters is reported as text.
_MIN_TEXT_RUN = 4

Decoded = tuple[str | None, int, int, bool]
"""``(value, characters, bytes_per_char, terminator_observed)``."""


def describe_memory(data: bytes, *, preferred_size: int | None = None) -> dict[str, object]:
    """Describe *data* as a scalar plus every plausible string reading.

    ``preferred_size`` is the item size IDA attributes to the address; when it
    is 1/2/4/8 the scalar is reported at that width.  No reading is presented
    as the answer: the bytes ``0x25 0x00 0x00 0x00`` are both the integer 37 and
    a one-character UTF-32 string, so the caller sees both and the binary
    evidence decides.
    """
    out: dict[str, object] = {
        "length": len(data),
        "hex": " ".join(f"0x{b:02x}" for b in data),
    }
    if preferred_size in (1, 2, 4, 8) and len(data) >= preferred_size:
        out["scalar"] = _scalar(data[:preferred_size])

    # Widest first: on these GCC i386 targets a wide literal is 4-byte
    # ``wchar_t``, and the ASCII reading of its first unit ("0x25 0x00 ...")
    # stops at the NUL while offering nothing.  Order only affects presentation;
    # every reading that succeeds is still reported.
    strings: dict[str, dict[str, object]] = {}
    for label, decoder in (
        ("utf32le", _decode_utf32le),
        ("utf16le", _decode_utf16le),
        ("ascii", _decode_ascii),
    ):
        value, characters, width, terminated = decoder(data)
        if value is None:
            continue
        strings[label] = {
            "value": value,
            "characters": characters,
            "byte_length": characters * width,
            "terminator_observed": terminated,
        }
    out["strings"] = strings
    return out


def _scalar(raw: bytes) -> dict[str, object]:
    signed = int.from_bytes(raw, "little", signed=True)
    unsigned = int.from_bytes(raw, "little", signed=False)
    return {
        "size": len(raw),
        "signed": signed,
        "unsigned": unsigned,
        "hex": hex(unsigned),
        # The float reading matters for x87 code that loads a constant through a
        # pointer; a 4-byte integer view alone would hide it.
        "float32": struct.unpack("<f", raw)[0] if len(raw) == 4 else None,
        "float64": struct.unpack("<d", raw)[0] if len(raw) == 8 else None,
    }


def _decode_ascii(data: bytes) -> Decoded:
    run: list[str] = []
    for index, byte in enumerate(data):
        if byte == 0:
            return _finish("".join(run), index, 1, True)
        # Tabs/newlines are legal inside literals; anything else non-printable
        # means this is not the ASCII reading (the UTF-32LE bytes of "%" are
        # "0x25 0x00 0x00 0x00", so the NUL stops it immediately).
        if 0x20 <= byte < 0x7F or byte in (0x09, 0x0A, 0x0D):
            run.append(chr(byte))
        else:
            return None, 0, 0, False
    return _finish("".join(run), len(run), 1, False)


def _decode_utf16le(data: bytes) -> Decoded:
    units: list[str] = []
    for offset in range(0, len(data) - 1, 2):
        value = int.from_bytes(data[offset : offset + 2], "little")
        if value == 0:
            return _finish("".join(units), len(units), 2, True)
        if value < 0x20 and value not in (0x09, 0x0A, 0x0D):
            return None, 0, 0, False
        units.append(chr(value))
    return _finish("".join(units), len(units), 2, False)


def _decode_utf32le(data: bytes) -> Decoded:
    units: list[str] = []
    for offset in range(0, len(data) - 3, 4):
        value = int.from_bytes(data[offset : offset + 4], "little")
        if value == 0:
            return _finish("".join(units), len(units), 4, True)
        if value > 0x10FFFF or (value < 0x20 and value not in (0x09, 0x0A, 0x0D)):
            return None, 0, 0, False
        units.append(chr(value))
    return _finish("".join(units), len(units), 4, False)


def _finish(text: str, characters: int, width: int, terminated: bool) -> Decoded:
    # A NUL unit seen inside the window is strong evidence for the wide
    # readings even for short literals ("%hs"); without one, demand a run long
    # enough that coincidence is unlikely.
    minimum = 2 if terminated else _MIN_TEXT_RUN
    if characters < minimum:
        return None, 0, 0, False
    return text, characters, width, terminated
