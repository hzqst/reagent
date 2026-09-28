"""Stage-scoped adapter reusing the existing IDA evidence implementation."""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from re_agent.backend.ida_mcp import IdaMcpBackend, McpTransportError
from re_agent.backend.idalib_lifecycle import IdalibLifecycleError, IdaMcpLifecycle
from re_agent.backend.protocol import BackendCapabilities
from re_agent.config.schema import BackendConfig
from re_agent.core.models import StructDef


class IdalibBackend(IdaMcpBackend):
    """An inactive backend outside a task; a fresh IDA connection inside it."""

    def __init__(self, config: BackendConfig) -> None:
        super().__init__()
        self.config = config
        self.log_dir: Path | None = None
        self._runtime: IdaMcpLifecycle | None = None
        self._stage_error: Exception | None = None

    @contextmanager
    def stage(self, phase: str) -> Iterator[IdalibBackend]:
        if self._runtime is not None:
            yield self
            return
        try:
            with IdaMcpLifecycle(self.config, phase, self.log_dir) as runtime:
                IdaMcpBackend.__init__(self, runtime.url, self.config.timeout_s, database=runtime.database)
                self._runtime = runtime
                self._stage_error = None
                yield self
                if self._stage_error is not None:
                    raise IdalibLifecycleError(f"IDA stage {phase} lost evidence: {self._stage_error}")
        finally:
            self._runtime = None
            self._response_cache.clear()
            self._caps = None
            self._caps_error = None

    def _ensure_session(self) -> None:
        if self._runtime is None:
            raise IdalibLifecycleError("Use backend_stage() before accessing an idalib-mcp backend")
        self._runtime.check_ready()
        super()._ensure_session()

    def _call(self, tool: str, arguments: dict[str, Any]) -> Any:
        try:
            self._ensure_session()
            return super()._call(tool, arguments)
        except (McpTransportError, IdalibLifecycleError) as exc:
            self._stage_error = exc
            raise IdalibLifecycleError(str(exc)) from exc

    def get_struct(self, name: str) -> StructDef | None:
        self._ensure_session()
        return super().get_struct(name)

    @property
    def capabilities(self) -> BackendCapabilities:
        try:
            self._ensure_session()
            return super().capabilities
        except (McpTransportError, IdalibLifecycleError) as exc:
            self._stage_error = exc
            raise IdalibLifecycleError(str(exc)) from exc
