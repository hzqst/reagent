"""One locally owned supervisor/database worker per bounded task stage."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager, suppress
from pathlib import Path
from types import TracebackType
from typing import BinaryIO

from re_agent.backend.ida_write import IdaWriteClient
from re_agent.backend.idalib_process import (
    ProcessIdentity,
    descendants,
    kill_owned,
    owns_listener,
    process_table,
    same_process,
)
from re_agent.config.schema import BackendConfig
from re_agent.utils.storage import file_lock

logger = logging.getLogger(__name__)
HEARTBEAT_SECONDS = 30
POLL_SECONDS = 0.1
START_ATTEMPTS = 3
HOST = "127.0.0.1"
_IDENTITY_SCRIPT = (
    "import os, json, ida_loader; "
    "print(json.dumps({'pid': os.getpid(), 'idb_path': ida_loader.get_path(ida_loader.PATH_TYPE_IDB)}))"
)
_CLOSE_SCRIPT = "import idapro; idapro.close_database(save=False); print('RE_AGENT_DATABASE_CLOSED')"
_NO_AUTO_SAVE_SCRIPT = (
    "import idapro, functools; "
    "idapro.close_database = functools.partial(idapro.close_database, save=False); "
    "print('RE_AGENT_NO_AUTO_SAVE')"
)


class IdalibLifecycleError(RuntimeError):
    """A managed stage cannot safely produce acceptance evidence."""


def validate_idalib_config(config: BackendConfig) -> tuple[Path, str]:
    """Validate only the new mode; existing backend configuration stays compatible."""
    if not config.database_path:
        raise ValueError("backend.database_path is required for idalib-mcp")
    path = Path(config.database_path).expanduser().resolve()
    if path.suffix.lower() not in {".i64", ".idb"} or not path.is_file():
        raise ValueError(f"backend.database_path must be an existing .i64/.idb database: {path}")
    for name in ("startup_timeout_s", "shutdown_timeout_s", "timeout_s"):
        if type(value := getattr(config, name)) is not int or value <= 0:
            raise ValueError(f"backend.{name} must be a positive integer")
    executable = shutil.which(os.path.expanduser(config.idalib_mcp_path))
    if not executable:
        raise ValueError(f"idalib-mcp executable not found: {config.idalib_mcp_path}")
    return path, executable


def _path_key(path: str | Path) -> str:
    return os.path.normcase(str(Path(path).resolve()))


def _database_busy(path: Path) -> bool:
    # IDA unpacks a packed DB into adjacent working files while it is open.
    return any(path.with_suffix(suffix).exists() for suffix in (".id0", ".id1", ".id2", ".nam", ".til"))


@contextmanager
def _startup_lock(path: Path, deadline: float) -> Iterator[None]:
    with ExitStack() as stack:
        while True:
            try:
                stack.enter_context(file_lock(path, blocking=False))
                break
            except OSError as exc:
                if time.monotonic() >= deadline:
                    raise IdalibLifecycleError("Timed out waiting for the idalib-mcp startup lock") from exc
                time.sleep(POLL_SECONDS)
        yield


class IdaMcpLifecycle:
    """Open, verify, keep alive, and close a database without implicit saving."""

    def __init__(self, config: BackendConfig, phase: str, log_dir: Path | None = None) -> None:
        self.config = config
        self.phase = phase
        self.log_dir = log_dir or Path("reports/re-agent/logs/idalib")
        self.url = ""
        self.database = ""
        self.process: subprocess.Popen[bytes] | None = None
        self._owned: dict[int, ProcessIdentity] = {}
        self._worker: ProcessIdentity | None = None
        self._stack = ExitStack()
        self._stop = threading.Event()
        self._heartbeat: threading.Thread | None = None
        self._failure: Exception | None = None
        self._client: IdaWriteClient | None = None
        self._log: BinaryIO | None = None
        self._path: Path | None = None
        self._port = 0
        self._open_requested = False

    def __enter__(self) -> IdaMcpLifecycle:
        try:
            self._path, executable = validate_idalib_config(self.config)
            lock_root = Path(tempfile.gettempdir()) / "re-agent-idalib"
            key = hashlib.sha256(_path_key(self._path).encode()).hexdigest()
            try:
                self._stack.enter_context(file_lock(lock_root / key, blocking=False))
            except OSError as exc:
                raise IdalibLifecycleError(f"Database is in use by another reagent stage: {self._path}") from exc
            if _database_busy(self._path):
                raise IdalibLifecycleError(f"Database has IDA working files; close its owner first: {self._path}")
            self.log_dir.mkdir(parents=True, exist_ok=True)
            log_path = self.log_dir / f"{self.phase}-{uuid.uuid4().hex}.log"
            self._log = self._stack.enter_context(log_path.open("wb"))
            logger.info("IDA stage %s: %s (log: %s)", self.phase, self._path, log_path)
            deadline = time.monotonic() + self.config.startup_timeout_s
            with _startup_lock(lock_root / "startup", deadline):
                self._start(executable, deadline)
            self._open_database(deadline)
            self._heartbeat = threading.Thread(target=self._keep_alive, name="re-agent-idalib-heartbeat", daemon=True)
            self._heartbeat.start()
            return self
        except BaseException as exc:
            try:
                self._finish()
            except Exception as cleanup:
                raise IdalibLifecycleError(f"IDA startup failed: {exc}; cleanup also failed: {cleanup}") from exc
            if isinstance(exc, (KeyboardInterrupt, SystemExit, IdalibLifecycleError, ValueError)):
                raise
            raise IdalibLifecycleError(f"IDA startup failed: {exc}") from exc

    def _capture_children(self) -> None:
        if self.process is not None:
            table = process_table()
            root = self._owned.get(self.process.pid)
            if root is None or same_process(root, table):
                self._owned.update(descendants(self.process.pid, table))

    def _start(self, executable: str, deadline: float) -> None:
        for _ in range(START_ATTEMPTS):
            with socket.socket() as sock:
                sock.bind((HOST, 0))
                self._port = sock.getsockname()[1]
            self.url = f"http://{HOST}:{self._port}/mcp"
            self.process = subprocess.Popen(
                [executable, "--unsafe", "--host", HOST, "--port", str(self._port)],
                stdin=subprocess.DEVNULL, stdout=self._log, stderr=subprocess.STDOUT,
                start_new_session=os.name != "nt",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
            )
            self._capture_children()
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    break
                if owns_listener(self.process.pid, self._port):
                    return
                time.sleep(POLL_SECONDS)
            if self.process.poll() is None:
                raise IdalibLifecycleError("Timed out waiting for the owned idalib-mcp listener")
        raise IdalibLifecycleError("idalib-mcp failed to bind a local port; inspect the stage log")

    def _open_database(self, deadline: float) -> None:
        assert self._path is not None
        def remaining_timeout() -> int:
            remaining = int(deadline - time.monotonic())
            if remaining < 1:
                raise IdalibLifecycleError("IDA database startup exceeded backend.startup_timeout_s")
            return remaining

        remaining = remaining_timeout()
        management = IdaWriteClient(self.url, remaining)
        self._open_requested = True
        opened = management._call("idb_open", {
            "input_path": str(self._path), "mode": "force_headless", "run_auto_analysis": False,
            "idle_ttl_sec": max(HEARTBEAT_SECONDS * 4, self.config.timeout_s * 2),
            "preferred_session_id": uuid.uuid4().hex,
        })
        self._capture_children()
        if not isinstance(opened, dict) or opened.get("success") is not True:
            raise IdalibLifecycleError(f"Could not open existing IDA database: {opened}")
        session = opened.get("session", {})
        self.database = str(session.get("session_id", ""))
        management._timeout_s = remaining_timeout()
        listed = management._call("idb_list", {})
        sessions = listed.get("sessions", []) if isinstance(listed, dict) else []
        matches = [s for s in sessions if s.get("session_id") == self.database]
        if len(matches) != 1:
            raise IdalibLifecycleError("No unique IDA session for the requested database")
        selected = matches[0]
        pid = selected.get("worker_pid") or selected.get("pid")
        if (selected.get("owned") is not True or selected.get("backend") != "worker"
                or selected.get("is_active") is not True or pid not in self._owned
                or _path_key(selected.get("input_path", "")) != _path_key(self._path)):
            raise IdalibLifecycleError("Refusing an external, inactive, or mismatched IDA database worker")
        self._worker = self._owned[pid]
        self._client = IdaWriteClient(self.url, min(remaining_timeout(), self.config.timeout_s), database=self.database)
        identity = self._client._call("py_eval", {"code": _IDENTITY_SCRIPT})
        try:
            value = json.loads(identity["stdout"].strip())
            valid = value["pid"] == pid and _path_key(value["idb_path"]) == _path_key(self._path)
        except (KeyError, ValueError, TypeError) as exc:
            raise IdalibLifecycleError("IDA worker returned invalid database identity") from exc
        if not valid:
            raise IdalibLifecycleError("IDA worker PID or actual IDB path does not match the owned session")
        self._client._timeout_s = min(remaining_timeout(), self.config.timeout_s)
        configured = self._client._call("py_eval", {"code": _NO_AUTO_SAVE_SCRIPT})
        if not isinstance(configured, dict) or "RE_AGENT_NO_AUTO_SAVE" not in configured.get("stdout", ""):
            raise IdalibLifecycleError("Could not disable implicit saves in the owned IDA worker")
        while True:
            self._client._timeout_s = min(remaining_timeout(), self.config.timeout_s)
            health = self._client._call("server_health", {})
            if not isinstance(health, dict) or health.get("status") != "busy":
                break
            time.sleep(POLL_SECONDS)
        if (not isinstance(health, dict) or health.get("error") or not health.get("idb_path")
                or health.get("hexrays_ready") is False):
            raise IdalibLifecycleError(f"IDA database/decompiler is not ready: {health}")
        self.check_ready()
        if time.monotonic() >= deadline:
            raise IdalibLifecycleError("IDA database startup exceeded backend.startup_timeout_s")

    def check_ready(self) -> None:
        if self._failure is not None:
            raise IdalibLifecycleError(f"IDA stage {self.phase} failed: {self._failure}") from self._failure
        if self.process is None or self.process.poll() is not None:
            raise IdalibLifecycleError("Owned idalib-mcp supervisor exited during the stage")
        if self._worker is not None:
            try:
                alive = same_process(self._worker, process_table())
            except Exception as exc:
                raise IdalibLifecycleError(f"Could not verify owned IDA worker identity: {exc}") from exc
            if not alive:
                raise IdalibLifecycleError("Owned IDA database worker exited during the stage")

    def _keep_alive(self) -> None:
        client = IdaWriteClient(self.url, min(self.config.timeout_s, self.config.shutdown_timeout_s),
                                database=self.database)
        while not self._stop.wait(HEARTBEAT_SECONDS):
            try:
                self.check_ready()
                result = client._call("server_health", {})
                if not isinstance(result, dict) or result.get("error"):
                    raise IdalibLifecycleError(f"IDA heartbeat failed: {result}")
            except Exception as exc:
                logger.warning("IDA stage %s heartbeat failed: %s", self.phase, exc)
                self._failure = exc
                return

    def _shutdown(self) -> None:
        if self.process is None:
            return
        self._stop.set()
        if self._heartbeat is not None:
            self._heartbeat.join(timeout=self.config.shutdown_timeout_s + 1)
            if self._heartbeat.is_alive():
                raise IdalibLifecycleError("IDA heartbeat did not stop before shutdown")
        self._capture_children()
        if self._client is not None and self._worker is not None and same_process(self._worker, process_table()):
            closer = IdaWriteClient(self.url, self.config.shutdown_timeout_s, database=self.database)
            try:
                closed = closer._call("py_eval", {"code": _CLOSE_SCRIPT})
                if not isinstance(closed, dict) or "RE_AGENT_DATABASE_CLOSED" not in closed.get("stdout", ""):
                    raise IdalibLifecycleError(f"IDA did not confirm closing without saving: {closed}")
                # qexit normally tears down the HTTP response.
                with suppress(RuntimeError):
                    closer._call("py_eval", {"code": "import ida_pro; ida_pro.qexit(0)"})
            except Exception as exc:
                logger.warning("IDA graceful close failed; stopping owned processes without saving: %s", exc)
                self._failure = self._failure or exc
        # The supervisor deliberately leaves workers alive. Always account for
        # every recorded descendant, including detached workers and schema workers.
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            with suppress(subprocess.TimeoutExpired):
                self.process.wait(timeout=self.config.shutdown_timeout_s)
        kill_owned(self._owned)
        if self.process is not None:
            self.process.wait(timeout=self.config.shutdown_timeout_s)
        deadline = time.monotonic() + self.config.shutdown_timeout_s
        while any(same_process(p, process_table()) for p in self._owned.values()):
            if time.monotonic() >= deadline:
                raise IdalibLifecycleError("Owned IDA processes remained alive after shutdown")
            time.sleep(POLL_SECONDS)
        if self._port:
            with socket.socket() as sock:
                if sock.connect_ex((HOST, self._port)) == 0:
                    raise IdalibLifecycleError(f"IDA port {self._port} remained occupied after shutdown")
        if self._open_requested and self._path is not None and _database_busy(self._path):
            raise IdalibLifecycleError(f"IDA working files remain; inspect before reopening: {self._path}")

    def _finish(self) -> None:
        try:
            try:
                self._shutdown()
            except BaseException as original:
                # Failed closing or joining must not skip stopping known owners.
                try:
                    kill_owned(self._owned)
                    if self.process is not None:
                        self.process.wait(timeout=self.config.shutdown_timeout_s)
                except Exception as fallback:
                    raise IdalibLifecycleError(
                        f"{original}; final owned-process cleanup failed: {fallback}"
                    ) from original
                raise
        finally:
            self._stack.close()

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 traceback: TracebackType | None) -> None:
        try:
            try:
                if exc is None:
                    self.check_ready()
            finally:
                self._finish()
        except Exception as cleanup:
            detail = f"{exc}; " if exc is not None else ""
            raise IdalibLifecycleError(f"{detail}IDA stage shutdown failed: {cleanup}") from cleanup
        if exc is None and self._failure is not None:
            raise IdalibLifecycleError(f"IDA stage cleanup failed: {self._failure}") from self._failure
