"""Fingerprint project inputs so completed results cannot silently go stale."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from re_agent.config.schema import ReAgentConfig


def project_fingerprint(config: ReAgentConfig) -> str:
    digest = hashlib.sha256()
    backend = asdict(config.backend)
    if config.backend.type.lower().replace("_", "-") != "idalib-mcp":
        for key in ("database_path", "idalib_mcp_path", "startup_timeout_s", "shutdown_timeout_s"):
            backend.pop(key)
    elif config.backend.database_path:
        backend["database_path"] = str(Path(config.backend.database_path).resolve())
        backend.pop("url")  # The owned endpoint is allocated anew for every stage.
    # Acceptance policy and source profile affect the meaning of an accepted result.
    values = {
        "profile": asdict(config.project_profile),
        "validation": asdict(config.validation),
        "parity": asdict(config.parity),
        "backend": backend,
    }
    digest.update(json.dumps(values, sort_keys=True).encode())
    root = Path(config.project_profile.source_root).resolve()
    digest.update(str(root).encode())
    if root.exists():
        for path in sorted(
            p for p in root.rglob("*") if p.is_file() and p.suffix in config.project_profile.source_extensions
        ):
            digest.update(str(path.relative_to(root)).encode())
            digest.update(path.read_bytes())
    if config.backend.export_dir:
        for path in sorted(Path(config.backend.export_dir).glob("*.json")):
            digest.update(path.name.encode())
            digest.update(path.read_bytes())
    for value in (
        config.backend.address_map,
        config.parity.semantic_rules_file,
        config.validation.differential_cases_file,
        config.project_profile.compilation_database,
    ):
        if value:
            digest.update(Path(value).read_bytes())
    return digest.hexdigest()
