"""IDA Pro MCP backend implementation.

Talks to the ``ida-pro-mcp`` plugin's HTTP endpoint (JSON-RPC 2.0) instead of
shelling out to a CLI.  Only the read-only evidence tools are used.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from re_agent.backend.protocol import BackendCapabilities
from re_agent.core.models import (
    AnalysisArtifact,
    AsmResult,
    DecompileResult,
    EnumDef,
    FunctionEntry,
    StructDef,
    StructField,
    XRef,
)
from re_agent.utils.address import format_address
from re_agent.utils.text import has_fp_asm

DEFAULT_URL = "http://127.0.0.1:13337/mcp"

# Key under ``result._meta`` carrying the ida-pro-mcp output-limiting metadata.
_TRUNCATION_META_KEY = "ida_mcp"

# IDA reports cross-reference kinds as ``"code"`` (a call/jump site) or
# ``"data"``.  Callers such as ``core/target_plan.py`` detect call edges by
# looking for ``"CALL"`` in this string, so the mapping matters.
_XREF_TYPE_MAP = {"code": "CALL", "data": "DATA"}

# List-returning tools have their structured content wrapped in a single
# ``{"result": [...]}`` key by the MCP server; dict-returning tools do not.
_PAGE_LIMIT = 100

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def ida_target(target: str) -> str:
    """Render a target the way ``ida-pro-mcp`` expects it.

    ReAgent normalizes addresses to bare lowercase hex (``utils/address.py``),
    but IDA's ``parse_address`` rejects those and demands either a ``0x``
    prefix or a symbol name.
    """
    candidate = target.strip()
    if candidate and all(char in _HEX_DIGITS for char in candidate):
        return format_address(candidate)
    return candidate


def as_list(structured: Any) -> list[Any]:
    """Unwrap a list-returning tool's ``{"result": [...]}`` envelope.

    ``ida-pro-mcp`` passes dict results through untouched but wraps list
    results in a single ``result`` key, so callers of list-returning tools
    need this.  Shared with the write-side client.
    """
    if isinstance(structured, list):
        return structured
    if isinstance(structured, dict):
        value = structured.get("result")
        if isinstance(value, list):
            return value
    raise RuntimeError(f"Expected a list result from the IDA MCP server, got {type(structured).__name__}")


def post_jsonrpc(
    url: str,
    method: str,
    params: dict[str, Any],
    timeout_s: int,
    session_id: str | None = None,
) -> tuple[dict[str, Any], str | None]:
    """POST a single JSON-RPC request, returning ``(result, session_id)``."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id

    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:
            raw = response.read().decode("utf-8")
            returned_session = response.headers.get("Mcp-Session-Id") or session_id
    except OSError as exc:
        raise RuntimeError(f"IDA MCP request failed: {url} ({exc})") from exc

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"IDA MCP returned invalid JSON from {url}") from exc

    if not isinstance(payload, dict):
        raise RuntimeError(f"IDA MCP returned an unexpected payload from {url}")
    if "error" in payload:
        raise RuntimeError(f"IDA MCP {method} failed: {payload['error']}")
    return payload.get("result") or {}, returned_session


def _get_json(url: str, timeout_s: int) -> Any:
    """GET a JSON document (used to recover truncated tool output)."""
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:
            raw = response.read().decode("utf-8")
    except OSError as exc:
        raise RuntimeError(f"Failed to fetch full IDA MCP output from {url} ({exc})") from exc

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"IDA MCP output at {url} was not valid JSON") from exc


class IdaMcpBackend:
    """Backend backed by the ``ida-pro-mcp`` HTTP endpoint.

    Args:
        url: JSON-RPC endpoint of the IDA MCP server.
        timeout_s: Maximum seconds per HTTP call.  The IDA-side tool timeouts
            reach 120s for the composite analysis tools.
    """

    def __init__(self, url: str = DEFAULT_URL, timeout_s: int = 120) -> None:
        self._url = url
        self._timeout_s = timeout_s
        self._caps: BackendCapabilities | None = None
        self._caps_error: RuntimeError | None = None
        self._session_id: str | None = None
        self._initialized = False
        self._response_cache: dict[tuple[str, str], Any] = {}

    # -- transport ------------------------------------------------------------

    def _ensure_session(self) -> None:
        """Run the MCP ``initialize`` handshake once, if not already done."""
        if self._initialized:
            return
        _, session_id = post_jsonrpc(
            self._url,
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "re-agent", "version": "0.4.0"},
            },
            self._timeout_s,
        )
        self._session_id = session_id
        self._initialized = True

    def _call(self, tool: str, arguments: dict[str, Any]) -> Any:
        """Invoke an MCP tool, returning its (possibly recovered) structured content.

        Raises:
            RuntimeError: On transport failure, protocol-level tool error, or
                when truncated output cannot be recovered.
        """
        cache_key = (tool, json.dumps(arguments, sort_keys=True))
        if cache_key in self._response_cache:
            return self._response_cache[cache_key]

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
            raise RuntimeError(f"IDA MCP tool {tool!r} failed: {_content_text(result)}")

        structured = self._recover_truncated(tool, result)
        self._response_cache[cache_key] = structured
        return structured

    def _recover_truncated(self, tool: str, result: dict[str, Any]) -> Any:
        """Return the full structured content, recovering it if truncated.

        The server replaces oversized output with a preview and reports the
        real payload's download URL under ``_meta``.  Using the preview would
        silently corrupt evidence, so a recovery failure is fatal.
        """
        meta = (result.get("_meta") or {}).get(_TRUNCATION_META_KEY) or {}
        if not meta.get("output_truncated"):
            structured = result.get("structuredContent")
            return _content_text(result) if structured is None else structured

        download_url = meta.get("download_url")
        if not download_url:
            raise RuntimeError(f"IDA MCP tool {tool!r} truncated its output without a download URL")
        return _get_json(str(download_url), self._timeout_s)

    @staticmethod
    def _first_item(structured: Any) -> dict[str, Any] | None:
        """Return the first batch item, or ``None`` when the batch is empty."""
        items = as_list(structured)
        return items[0] if items and isinstance(items[0], dict) else None

    # -- capabilities ---------------------------------------------------------

    @property
    def capabilities(self) -> BackendCapabilities:
        """Return the capabilities exposed by the running server.

        Probed from ``tools/list`` so that tools the user disabled in the
        plugin's config page correctly report as unavailable.

        Raises:
            RuntimeError: If the server cannot be reached.  Reporting "no
                capabilities" for an unreachable server would let callers
                silently proceed with degraded evidence.
        """
        if self._caps_error is not None:
            raise self._caps_error
        if self._caps is None:
            try:
                self._caps = self._probe_capabilities()
            except RuntimeError as exc:
                self._caps_error = exc
                raise
        return self._caps

    def _probe_capabilities(self) -> BackendCapabilities:
        self._ensure_session()
        result, session_id = post_jsonrpc(
            self._url, "tools/list", {}, self._timeout_s, self._session_id
        )
        if session_id:
            self._session_id = session_id
        names = {tool.get("name") for tool in result.get("tools", []) if isinstance(tool, dict)}

        return BackendCapabilities(
            has_decompile="decompile" in names,
            has_asm="disasm" in names,
            has_structs="search_structs" in names,
            has_xrefs="xrefs_to" in names,
            has_search="list_funcs" in names,
            has_context="analyze_function" in names,
            has_cfg="basic_blocks" in names,
            has_globals="list_globals" in names,
            has_strings="find_regex" in names,
        )

    # -- decompile ------------------------------------------------------------

    def decompile(self, target: str) -> DecompileResult:
        """Decompile a function by address or symbol name."""
        payload = self._call("decompile", {"addr": ida_target(target), "include_addresses": True})
        if not isinstance(payload, dict):
            raise RuntimeError(f"IDA decompile returned an unexpected payload for {target}")
        if payload.get("error"):
            raise RuntimeError(f"IDA decompile failed for {target}: {payload['error']}")

        code = payload.get("code") or ""
        name = self._function_name(target) or target
        return DecompileResult(
            address=str(payload.get("addr") or target),
            name=name,
            signature="",
            decompiled=code,
            raw_output=json.dumps(payload),
            callers=None,
            callees=self._callee_count(target),
            # ``callers`` is left unset: no production caller compares it, and
            # producing it would cost another round trip per function.
        )

    def _function_name(self, target: str) -> str | None:
        item = self._first_item(self._call("lookup_funcs", {"queries": [ida_target(target)]}))
        if not item or item.get("error"):
            return None
        info = item.get("fn")
        if isinstance(info, dict):
            value = info.get("name")
            return str(value) if value else None
        return None

    def _callee_count(self, target: str) -> int | None:
        item = self._first_item(self._call("callees", {"addrs": [ida_target(target)]}))
        if not item or item.get("error"):
            return None
        callees = item.get("callees")
        return len(callees) if isinstance(callees, list) else None

    # -- xrefs ----------------------------------------------------------------

    def xrefs_to(self, target: str) -> list[XRef]:
        """Parse cross-references TO a function."""
        item = self._first_item(self._call("xrefs_to", {"addrs": [ida_target(target)]}))
        if not item or item.get("error"):
            return []
        return self._parse_xrefs(item.get("xrefs"))

    def xrefs_from(self, target: str) -> list[XRef]:
        """Parse cross-references FROM a function (IDA's "callees")."""
        item = self._first_item(self._call("callees", {"addrs": [ida_target(target)]}))
        if not item or item.get("error"):
            return []
        return self._parse_xrefs(item.get("callees"))

    @staticmethod
    def _parse_xrefs(entries: Any) -> list[XRef]:
        """Convert IDA xref entries into :class:`XRef` objects."""
        if not isinstance(entries, list):
            # An unmapped address yields ``null`` rather than an empty list.
            return []
        results: list[XRef] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            kind = str(entry.get("type") or "code").lower()
            results.append(
                XRef(
                    address=str(entry.get("addr") or ""),
                    name=str((entry.get("fn") or {}).get("name") or "")
                    if isinstance(entry.get("fn"), dict)
                    else "",
                    ref_type=_XREF_TYPE_MAP.get(kind, kind.upper()),
                )
            )
        return results

    # -- struct ---------------------------------------------------------------

    def get_struct(self, name: str) -> StructDef | None:
        """Retrieve a struct definition by name via the ``ida://struct`` resource."""
        try:
            payload, _ = post_jsonrpc(
                self._url,
                "resources/read",
                {"uri": f"ida://struct/{name}"},
                self._timeout_s,
                self._session_id,
            )
        except RuntimeError:
            return None

        text = _resource_text(payload)
        if text is None:
            return None
        return _parse_struct(name, text)

    # -- asm ------------------------------------------------------------------

    def get_asm(self, target: str) -> AsmResult | None:
        """Retrieve disassembly for a function."""
        payload = self._call("disasm", {"addr": ida_target(target)})
        if not isinstance(payload, dict) or payload.get("error"):
            return None

        asm = payload.get("asm")
        instructions = _render_asm(asm)
        if not instructions:
            return None
        count = payload.get("instruction_count")
        return AsmResult(
            address=str(payload.get("addr") or target),
            instructions=instructions,
            instruction_count=int(count) if isinstance(count, int) else len(instructions.splitlines()),
            call_count=sum(1 for line in instructions.splitlines() if line.strip().upper().startswith("CALL")),
            has_fp_sensitive=has_fp_asm(instructions),
        )

    # -- evidence artifacts ---------------------------------------------------

    def get_context(self, target: str) -> AnalysisArtifact | None:
        return self._artifact("function-context", "analyze_function", {"addr": ida_target(target)})

    def get_cfg(self, target: str) -> AnalysisArtifact | None:
        return self._artifact("cfg", "basic_blocks", {"addrs": [ida_target(target)]})

    def search_strings(self, pattern: str) -> AnalysisArtifact | None:
        return self._artifact("strings", "find_regex", {"pattern": pattern})

    def get_enum(self, name: str) -> EnumDef | None:
        raise NotImplementedError("ida-mcp backend does not implement get_enum")

    def get_vtable(self, target: str) -> AnalysisArtifact | None:
        raise NotImplementedError("ida-mcp backend does not implement get_vtable")

    def get_global(self, target: str) -> AnalysisArtifact | None:
        raise NotImplementedError("ida-mcp backend does not implement get_global")

    def get_pcode(self, target: str) -> AnalysisArtifact | None:
        raise NotImplementedError("ida-mcp backend does not implement get_pcode")

    def _artifact(self, kind: str, tool: str, arguments: dict[str, Any]) -> AnalysisArtifact | None:
        try:
            payload = self._call(tool, arguments)
        except RuntimeError:
            return None
        return AnalysisArtifact(kind=kind, target=str(arguments.get("addr") or arguments), content=json.dumps(payload))

    # -- search / unimplemented / remaining -----------------------------------

    def search(self, pattern: str) -> list[FunctionEntry]:
        """Search for functions whose name matches a glob pattern."""
        return self._list_functions(pattern)

    def remaining(self, class_name: str | None = None) -> list[FunctionEntry]:
        """List remaining functions, optionally filtered by class.

        This workspace model has no reconstructed source tree, so "remaining"
        cannot mean "stubs still awaiting a body".  It is approximated as the
        functions whose name matches ``class_name``.
        """
        return self._list_functions(f"*{class_name}*" if class_name else "*")

    def unimplemented(self, filter_pattern: str | None = None) -> list[FunctionEntry]:
        """List functions matching *filter_pattern*.

        Approximated the same way as :meth:`remaining`: without a source tree
        there is no implementation state to query.
        """
        return self._list_functions(filter_pattern or "*")

    def _list_functions(self, filter_pattern: str) -> list[FunctionEntry]:
        pages = as_list(
            self._call(
                "list_funcs",
                {"queries": [{"filter": filter_pattern, "offset": 0, "count": _PAGE_LIMIT}]},
            )
        )
        entries: list[FunctionEntry] = []
        for page in pages:
            if not isinstance(page, dict):
                continue
            for item in page.get("data") or []:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or "")
                class_name, _, bare_name = name.rpartition("::")
                entries.append(
                    FunctionEntry(
                        address=str(item.get("addr") or ""),
                        name=bare_name or name,
                        class_name=class_name,
                        caller_count=0,
                    )
                )
        return entries


def _content_text(result: dict[str, Any]) -> str:
    """Flatten an MCP ``content`` array into plain text."""
    parts = [
        str(block.get("text") or "")
        for block in result.get("content") or []
        if isinstance(block, dict)
    ]
    return "\n".join(part for part in parts if part)


def _resource_text(payload: dict[str, Any]) -> str | None:
    """Extract the text body from a ``resources/read`` result."""
    for entry in payload.get("contents") or []:
        if isinstance(entry, dict) and entry.get("text") is not None:
            return str(entry["text"])
    return None


def _parse_struct(name: str, text: str) -> StructDef | None:
    """Build a :class:`StructDef` from the struct resource payload."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None

    fields: list[StructField] = []
    for member in data.get("fields") or data.get("members") or []:
        if not isinstance(member, dict):
            continue
        try:
            offset = int(member.get("offset") or 0)
        except (TypeError, ValueError):
            offset = 0
        fields.append(
            StructField(
                name=str(member.get("name") or ""),
                offset=offset,
                type_str=str(member.get("type") or "unknown"),
                size=int(member.get("size") or 0) if str(member.get("size") or "0").isdigit() else 0,
            )
        )
    try:
        size = int(data.get("size") or 0)
    except (TypeError, ValueError):
        size = 0
    return StructDef(name=name, size=size, fields=fields)


def _render_asm(asm: Any) -> str:
    """Flatten a disassembly payload into newline-separated instructions."""
    if asm is None:
        return ""
    if isinstance(asm, str):
        return asm
    if isinstance(asm, list):
        return "\n".join(str(entry) for entry in asm)
    if isinstance(asm, dict):
        for key in ("lines", "instructions", "asm", "code"):
            value = asm.get(key)
            if isinstance(value, str):
                return value
            if isinstance(value, list):
                return "\n".join(str(entry) for entry in value)
    return ""
