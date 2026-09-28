"""Task boundaries for owned backends without widening the REBackend protocol."""
from __future__ import annotations

import inspect
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from functools import wraps
from pathlib import Path
from typing import ParamSpec, TypeVar

from re_agent.backend.ida_write import IdaWriteClient
from re_agent.backend.idalib import IdalibBackend
from re_agent.backend.idalib_lifecycle import IdalibLifecycleError, IdaMcpLifecycle
from re_agent.backend.protocol import REBackend
from re_agent.config.schema import BackendConfig

P = ParamSpec("P")
R = TypeVar("R")
C = TypeVar("C", bound=IdaWriteClient)


@contextmanager
def backend_stage(backend: REBackend, phase: str) -> Iterator[REBackend]:
    """Nested helper calls share the enclosing task's worker."""
    # Manifest enumeration wraps the analysis backend. Keep yielding the
    # wrapper so its restricted function inventory remains in effect.
    owner = backend if isinstance(backend, IdalibBackend) else getattr(backend, "backend", None)
    if isinstance(owner, IdalibBackend):
        with owner.stage(phase):
            yield backend
    else:
        yield backend


def backend_task(phase: str) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Scope a function's backend argument, or an agent's self.backend."""
    def decorate(function: Callable[P, R]) -> Callable[P, R]:
        signature = inspect.signature(function)

        @wraps(function)
        def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
            arguments = signature.bind(*args, **kwargs).arguments
            backend = arguments.get("backend")
            if backend is None and "self" in arguments:
                backend = arguments["self"].backend
            if backend is None:
                return function(*args, **kwargs)
            with backend_stage(backend, phase):
                return function(*args, **kwargs)

        return wrapped
    return decorate


@contextmanager
def ida_client_stage(config: BackendConfig, phase: str, client_type: type[C],
                     log_dir: Path | None = None) -> Iterator[C]:
    """Share the same lifecycle for annotate and independent type recovery."""
    if config.type.lower().replace("_", "-") != "idalib-mcp":
        yield client_type(config.url, config.timeout_s)
        return
    with IdaMcpLifecycle(config, phase, log_dir) as runtime:
        client = client_type(runtime.url, config.timeout_s, database=runtime.database)
        yield client
        if client.transport_error is not None:
            raise IdalibLifecycleError(f"IDA stage {phase} lost its connection: {client.transport_error}")
