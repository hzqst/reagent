"""Write-side client for the ida-pro-mcp HTTP endpoint.

:class:`~re_agent.backend.protocol.REBackend` is deliberately read-only, and
backends such as ``ghidra-json`` or ``stub`` have no write capability at all.
Rather than widen that contract, applying annotations is a separate and
explicitly-requested step that talks to the same MCP endpoint.
"""

from __future__ import annotations

import re
from typing import Any

from re_agent.backend.ida_mcp import as_list, ida_target, post_jsonrpc, recover_truncated
from re_agent.backend.ida_prototype import prototype_result, prototype_script
from re_agent.core.models import StructChange

# Function names IDA generates for symbols it has not identified.  Used to keep
# annotations from overwriting names a human already reviewed.
#
# IDA and the imported type libraries also qualify these with a class, as in
# ``MouseClass::sub_568350`` or ``TechnoClass_sub_70DE00``, so a placeholder is
# matched after ``::`` or ``_`` as well as at the start of the name.
UNNAMED_PREFIXES = ("sub_", "nullsub_", "FUN_", "j_sub_", "unknown_", "loc_")

_PLACEHOLDER_RE = re.compile(
    r"(?:^|::|_)(?:" + "|".join(re.escape(prefix) for prefix in UNNAMED_PREFIXES) + r")[0-9A-Fa-f]"
)

_TYPE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_:]*$")

# Reads a type's exact declaration out of IDA's own printer, so alignment
# attributes, gaps and bitfields survive.  ``ida-pro-mcp`` exposes no tool for
# this, and rebuilding the declaration from ``type_inspect`` members would
# silently drop those attributes.  The only interpolation is a validated type
# name; no model-authored code is ever executed here.
_READ_DECLARATION = '''
import ida_typeinf, os, tempfile
name = {name!r}
til = ida_typeinf.get_idati()
tif = ida_typeinf.tinfo_t()
if not tif.get_named_type(til, name):
    print("__RE_AGENT_ERROR__ type not found: " + name)
else:
    flags = (ida_typeinf.PRTYPE_MULTI | ida_typeinf.PRTYPE_TYPE
             | ida_typeinf.PRTYPE_DEF | ida_typeinf.PRTYPE_SEMI)
    decl = ida_typeinf.print_tinfo('', 0, 0, flags, tif, None, None)
    path = os.path.join(tempfile.gettempdir(),
                        "re_agent_type_" + name.replace("::", "__") + ".h")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(decl)
    print("__RE_AGENT_PATH__" + path)
'''


def is_unnamed(name: str) -> bool:
    """Return True when *name* is still an IDA placeholder.

    Recognises class-qualified placeholders (``MouseClass::sub_568350``,
    ``TechnoClass_sub_70DE00``) as well as bare ones, so that
    ``--only-unnamed`` does not mistake them for reviewed names.
    """
    return _PLACEHOLDER_RE.search(name) is not None


def address_key(value: str) -> str:
    """Canonical match key for an address.

    Headers and IDA spell the same address differently -- ``0x0529160`` versus
    ``0x529160`` -- so both sides are reduced to a bare lowercase hex value.
    Anything that is not a hexadecimal address (a symbol name) is returned
    lowercased and otherwise untouched.
    """
    text = value.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    try:
        return format(int(text, 16), "x")
    except ValueError:
        return value.strip().lower()


class IdaWriteClient:
    """Applies symbol annotations to a running IDA database.

    Args:
        url: JSON-RPC endpoint of the IDA MCP server.
        timeout_s: Maximum seconds per HTTP call.
    """

    def __init__(self, url: str, timeout_s: int = 120) -> None:
        self._url = url
        self._timeout_s = timeout_s
        self._session_id: str | None = None
        self._initialized = False

    # -- transport ------------------------------------------------------------

    def _ensure_session(self) -> None:
        if self._initialized:
            return
        _, session_id = post_jsonrpc(
            self._url,
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "re-agent-annotate", "version": "0.4.0"},
            },
            self._timeout_s,
        )
        self._session_id = session_id
        self._initialized = True

    def _call(self, tool: str, arguments: dict[str, Any]) -> Any:
        """Invoke an MCP tool and return its structured content.

        Oversized output is downloaded rather than truncated: a bulk
        ``lookup_funcs`` over a few hundred addresses crosses the server's
        output limit, and a partial result would make already-named functions
        look unnamed to ``--only-unnamed``.
        """
        self._ensure_session()
        result, session_id = post_jsonrpc(
            self._url,
            "tools/call",
            {"name": tool, "arguments": arguments},
            self._timeout_s,
            self._session_id,
        )
        if session_id:
            self._session_id = session_id
        if result.get("isError"):
            text = "\n".join(
                str(block.get("text") or "")
                for block in result.get("content") or []
                if isinstance(block, dict)
            )
            raise RuntimeError(f"IDA MCP tool {tool!r} failed: {text}")
        return recover_truncated(tool, result, self._timeout_s)

    # -- reads ----------------------------------------------------------------

    def prototype_operation(self, mode: str, address: str, **parameters: Any) -> dict[str, Any]:
        """Run a fixed helper; unsupported servers fail closed without writes.

        Apply includes its own snapshot check in the same IDA operation, avoiding
        a check/set race. No model-authored Python is executed.
        """
        request = {**parameters, "mode": mode, "address": ida_target(address)}
        return prototype_result(self._call("py_eval", {"code": prototype_script(request)}))

    def function_names(self, addresses: list[str]) -> dict[str, str]:
        """Return the current name of each target, where IDA knows it.

        Each result is indexed by the address it was queried with, the address
        IDA resolved it to, and its current name, because a proposal may be
        addressed by any of the three: ``reverse --address sub_455DD0`` records
        the name it was given, while IDA reports the address.

        Indexing by the queried address matters most: an address that lands
        *inside* a function resolves to that function, so without it the
        containing function's name never matches and ``--only-unnamed`` would
        treat an already-named function as unnamed -- and renaming it through
        the interior address renames the whole function.
        """
        if not addresses:
            return {}
        items = as_list(
            self._call("lookup_funcs", {"queries": [ida_target(item) for item in addresses]})
        )
        names: dict[str, str] = {}
        for item in items:
            if not isinstance(item, dict) or item.get("error"):
                continue
            info = item.get("fn")
            if not isinstance(info, dict) or not info.get("addr"):
                continue
            current = str(info.get("name") or "")
            for key in (item.get("query"), info.get("addr"), current):
                if key:
                    names[address_key(str(key))] = current
        return names

    def struct_layout(self, name: str) -> dict[str, Any] | None:
        """Return ``{"size": int, "members": {name: offset_hex}}``, or ``None``."""
        payload = self._call(
            "type_inspect",
            {"queries": [{"name": name, "include_members": True, "max_members": 0}]},
        )
        items = as_list(payload) if isinstance(payload, list) else [payload]
        for item in items:
            if isinstance(item, dict) and item.get("exists") and isinstance(item.get("members"), list):
                return {
                    "size": int(item.get("size") or 0),
                    "members": {
                        str(member.get("name")): str(member.get("offset"))
                        for member in item["members"]
                        if isinstance(member, dict)
                    },
                }
        return None

    def read_declaration(self, name: str) -> str:
        """Return a type's full printed declaration.

        Raises:
            RuntimeError: If the name is not a plain identifier, or the type
                does not exist.
        """
        if not _TYPE_NAME_RE.match(name):
            raise RuntimeError(f"Refusing to look up a non-identifier type name: {name!r}")
        payload = self._call("py_eval", {"code": _READ_DECLARATION.format(name=name)})
        stdout = payload.get("stdout") if isinstance(payload, dict) else None
        text = str(stdout or "")
        if "__RE_AGENT_ERROR__" in text:
            raise RuntimeError(f"Type not found in IDA: {name}")
        marker = "__RE_AGENT_PATH__"
        if marker not in text:
            raise RuntimeError(f"Could not read the declaration of {name}: {text.strip()}")
        path = text.split(marker, 1)[1].strip().splitlines()[0].strip()
        from pathlib import Path

        return Path(path).read_text(encoding="utf-8")

    # -- writes ---------------------------------------------------------------

    def rename_functions(
        self,
        renames: list[tuple[str, str]],
        *,
        dry_run: bool,
        allow_overwrite: bool = False,
    ) -> list[dict[str, Any]]:
        """Rename functions, returning the per-item results.

        ``allow_overwrite`` stays False by default so an existing name is never
        silently replaced.  The tool answers with a ``{"func": [...],
        "summary": {...}}`` object rather than a bare list.
        """
        if not renames:
            return []
        # ``dry_run`` and ``allow_overwrite`` are read from inside ``batch`` by
        # the server, even though the published tool schema lists them as
        # top-level parameters; sending them top-level is rejected.
        payload = self._call(
            "rename",
            {
                "batch": {
                    "func": [{"addr": ida_target(addr), "name": name} for addr, name in renames],
                    "dry_run": dry_run,
                    "allow_overwrite": allow_overwrite,
                },
            },
        )
        if not isinstance(payload, dict):
            return []
        items = payload.get("func")
        return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []

    def append_function_comment(self, address: str, comment: str) -> None:
        """Append a function comment; the server dedupes repeated text.

        Raises:
            RuntimeError: If IDA rejects the comment.  The tool reports per-item
                failures in-band rather than through ``isError``, so the result
                must be inspected or failures vanish silently.
        """
        if not comment.strip():
            return
        results = as_list(
            self._call(
                "append_comments",
                {"items": [{"addr": ida_target(address), "comment": comment, "scope": "func"}]},
            )
        )
        for item in results:
            if isinstance(item, dict) and item.get("error"):
                raise RuntimeError(f"IDA rejected the comment for {address}: {item['error']}")

    def declare_type(self, declaration: str) -> list[dict[str, Any]]:
        """Re-declare a type, replacing the existing definition of that name."""
        payload = self._call("declare_type", {"decls": [declaration]})
        return as_list(payload)

    def save(self) -> Any:
        """Persist the database to disk."""
        result = self._call("idb_save", {})
        if not isinstance(result, dict) or result.get("error") or result.get("ok") is not True:
            raise RuntimeError(f"IDA did not confirm saving the database: {result}")
        return result


def apply_member_change(
    declaration: str,
    change: StructChange,
) -> tuple[str, list[str]]:
    """Apply a member change to a printed struct declaration.

    Operates on IDA's own printed text rather than rebuilding the declaration,
    so alignment and gaps survive.  Returns the new declaration and a list of
    the lines that changed, or raises ``ValueError`` when the change cannot be
    expressed.

    Supports:

    * ``rename`` — rename ``change.member``.
    * ``retype`` — retype ``change.member``.
    * ``move`` — reposition ``change.member`` so it lands at ``change.offset``.
    """
    member = re.escape(change.member)
    pattern = re.compile(rf"^(?P<indent>\s*)(?P<type>.+?)\s+(?P<name>{member})\s*;\s*$", re.M)
    match = pattern.search(declaration)
    if match is None:
        raise ValueError(f"member {change.member!r} not found in the declaration")

    old_line = match.group(0)
    indent = match.group("indent")
    member_type = match.group("type").strip()

    if change.operation == "rename":
        # The new name rides in ``type_str`` because the proposal has no
        # dedicated rename target; callers set it explicitly.
        new_name = change.type_str or change.member
        if new_name == change.member:
            raise ValueError(f"rename of {change.member!r} needs a new name in type_str")
        new_line = f"{indent}{member_type} {new_name};"
        return declaration.replace(old_line, new_line, 1), [f"- {old_line.strip()}", f"+ {new_line.strip()}"]

    if change.operation == "retype":
        if not change.type_str:
            raise ValueError(f"retype of {change.member!r} needs a type in type_str")
        new_line = f"{indent}{change.type_str} {change.member};"
        return declaration.replace(old_line, new_line, 1), [f"- {old_line.strip()}", f"+ {new_line.strip()}"]

    # ``move``: drop the line and reinsert it so IDA's parser places it at the
    # requested offset.  The caller verifies the resulting offset afterwards.
    if not change.offset:
        raise ValueError(f"move of {change.member!r} needs a target offset")
    target = int(change.offset, 16) if change.offset.lower().startswith("0x") else int(change.offset)

    body = declaration.replace(old_line + "\n", "", 1)
    if body == declaration:
        body = declaration.replace(old_line, "", 1)
    lines = body.splitlines()
    insert_at = _insertion_index(lines, target)
    lines.insert(insert_at, f"{indent}{member_type} {change.member};")
    return "\n".join(lines) + ("\n" if declaration.endswith("\n") else ""), [
        f"moved {change.member} to ~{hex(target)}"
    ]


def _insertion_index(lines: list[str], target: int) -> int:
    """Return where a moved member should be inserted to land near *target*.

    Members are laid out in declaration order, so the insertion point is the
    first member whose running offset would exceed the target.  Sizes are not
    tracked here; the caller re-reads the offsets afterwards and rejects the
    change if the member did not land where the proposal asked.
    """
    offset = 0
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped in ("{", "}") or stripped.startswith(("//", "#")):
            continue
        size = _declared_size(stripped)
        if offset + size > target:
            return index
        offset += size
    return len(lines)


_DECLARED_SIZE: dict[str, int] = {
    "char": 1, "bool": 1, "short": 2, "int": 4, "long": 4, "float": 4,
    "double": 8, "DWORD": 4, "WORD": 2, "BYTE": 1, "BOOL": 4, "void": 4,
}


def _declared_size(line: str) -> int:
    """Best-effort byte size of a printed member declaration."""
    array = re.search(r"\[\s*(\d+)\s*\]", line)
    if array:
        base = _declared_size(re.sub(r"\[.*?\]", "", line))
        return base * int(array.group(1))
    head = line.split()[0].rstrip("*").strip()
    if line.count("*") or head.endswith("*"):
        return 4
    return _DECLARED_SIZE.get(head, 4)
