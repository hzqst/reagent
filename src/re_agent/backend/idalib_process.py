"""Identify owned processes, including IDA workers that detach their session."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    parent: int
    started: str


def process_table() -> dict[int, ProcessIdentity]:
    """Return PID and creation identity so PID reuse cannot target another process."""
    result: dict[int, ProcessIdentity] = {}
    if sys.platform == "win32":
        script = "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,CreationDate | ConvertTo-Json"
        output = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, check=True, timeout=10,
        ).stdout
        rows = json.loads(output)
        for row in rows if isinstance(rows, list) else [rows]:
            pid = int(row["ProcessId"])
            result[pid] = ProcessIdentity(pid, int(row["ParentProcessId"]), str(row["CreationDate"]))
    elif Path("/proc/self/stat").exists():
        for path in Path("/proc").glob("[0-9]*/stat"):
            try:
                fields = path.read_text().rsplit(")", 1)[1].split()
                if fields[0] == "Z":
                    continue
                pid = int(path.parent.name)
                result[pid] = ProcessIdentity(pid, int(fields[1]), fields[19])
            except (OSError, ValueError, IndexError):
                continue
    else:
        output = subprocess.run(
            ["ps", "-axo", "pid=,ppid=,lstart=,stat="], capture_output=True, text=True, check=True, timeout=10,
        ).stdout
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 8 and not parts[-1].startswith("Z"):
                pid = int(parts[0])
                result[pid] = ProcessIdentity(pid, int(parts[1]), " ".join(parts[2:7]))
    return result


def descendants(root: int, table: dict[int, ProcessIdentity]) -> dict[int, ProcessIdentity]:
    selected = {root}
    while True:
        children = {p.pid for p in table.values() if p.parent in selected}
        if children <= selected:
            break
        selected |= children
    return {pid: table[pid] for pid in selected if pid in table}


def same_process(identity: ProcessIdentity, table: dict[int, ProcessIdentity]) -> bool:
    current = table.get(identity.pid)
    return current is not None and current.started == identity.started


def kill_owned(identities: dict[int, ProcessIdentity]) -> None:
    """Force-stop only recorded identities; SIGTERM could save unwanted IDB edits."""
    table = process_table()
    for identity in identities.values():
        if not same_process(identity, table):
            continue
        # sys.platform is the guard mypy recognises, so the POSIX-only
        # signal.SIGKILL branch is not checked against the Windows stubs.
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/PID", str(identity.pid), "/F"],
                capture_output=True, check=False, timeout=10,
            )
        else:
            with suppress(ProcessLookupError):
                os.kill(identity.pid, signal.SIGKILL)


def owns_listener(pid: int, port: int) -> bool:
    """Check the listener before sending any database-open request."""
    if Path("/proc/self/stat").exists():
        inodes: set[str] = set()
        for name in ("tcp", "tcp6"):
            for line in Path(f"/proc/net/{name}").read_text().splitlines()[1:]:
                fields = line.split()
                if int(fields[1].split(":")[1], 16) == port and fields[3] == "0A":
                    inodes.add(fields[9])
        for fd in Path(f"/proc/{pid}/fd").glob("*"):
            try:
                if os.readlink(fd) in {f"socket:[{inode}]" for inode in inodes}:
                    return True
            except OSError:
                continue
        return False
    if sys.platform == "win32":
        output = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True, check=True, timeout=10,
        ).stdout
        return any(
            len(parts := line.split()) == 5 and parts[1].endswith(f":{port}")
            and parts[3] == "LISTENING" and parts[4] == str(pid)
            for line in output.splitlines()
        )
    result = subprocess.run(
        ["lsof", "-nP", "-a", "-p", str(pid), f"-iTCP:{port}", "-sTCP:LISTEN", "-t"],
        capture_output=True, text=True, check=False, timeout=10,
    )
    return str(pid) in result.stdout.split()
