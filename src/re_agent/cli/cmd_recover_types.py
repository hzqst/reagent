"""Run the independent IDA type recovery agent."""
from __future__ import annotations

import argparse
import glob
import logging
import sys
import uuid
from pathlib import Path

from re_agent.backend.idalib_lifecycle import IdalibLifecycleError
from re_agent.backend.stages import ida_client_stage
from re_agent.config import load_config
from re_agent.recovery.ida import IdaRecoveryClient
from re_agent.recovery.provider import create_recovery_provider
from re_agent.recovery.runner import run_recovery
from re_agent.utils.address import checked_address
from re_agent.utils.storage import atomic_json
from re_agent.verification.candidate import discover_candidate_files


def _expand_evidence_dirs(patterns: list[str], extensions: list[str]) -> list[Path]:
    """Expand directory/glob targets into a sorted, extension-filtered file list.

    Each target is a glob relative to the run's cwd. A directory is expanded
    recursively. Results are filtered by ``extensions`` so a broad glob cannot
    pull in non-source files; only a *literal* file path (no glob metacharacter)
    is kept regardless of its extension, so naming one file explicitly always
    works. A target that matches nothing is an error: a silent no-op would look
    like successful injection.
    """
    allowed = {ext.lower() for ext in extensions}
    seen: set[str] = set()
    files: list[Path] = []
    for pattern in patterns:
        matches = [Path(match) for match in glob.glob(pattern, recursive=True)]
        candidates = [match for match in matches if match.is_file()]
        for directory in (match for match in matches if match.is_dir()):
            candidates.extend(sorted(path for path in directory.rglob("*") if path.is_file()))
        if not candidates:
            raise ValueError(f"--evidence-dirs pattern matched no files: {pattern!r}")
        literal_file = not any(ch in pattern for ch in "*?[") and len(candidates) == 1
        for path in candidates:
            if not literal_file and path.suffix.lower() not in allowed:
                continue
            key = str(path.resolve())
            if key not in seen:
                seen.add(key)
                files.append(path)
    return files


def cmd_recover_types(args: argparse.Namespace) -> int:
    """Investigate by default; require explicit write/save authorization."""
    if args.save and not args.write:
        raise ValueError("--save requires --write")
    config = load_config(Path(args.config))
    managed = config.backend.type.lower().replace("_", "-") == "idalib-mcp"
    if config.backend.type.lower().replace("_", "-") not in {"ida-mcp", "ida", "idalib-mcp"}:
        raise ValueError("recover-types requires backend.type 'ida-mcp' or 'idalib-mcp'")
    if config.recovery is None:
        raise ValueError("recover-types requires an independent recovery provider/model configuration")
    addresses = list(dict.fromkeys(hex(int(checked_address(address), 16)) for address in args.address))
    evidence = []
    for path in [*args.evidence, *([config.recovery.runner_prompt_file] if config.recovery.runner_prompt_file else [])]:
        evidence.append(f"Evidence file: {path}\n{Path(path).read_text(encoding='utf-8')}")
    dir_files = _expand_evidence_dirs(args.evidence_dirs, config.project_profile.source_extensions)
    if dir_files:
        print(f"[recover-types] including {len(dir_files)} file(s) from --evidence-dirs as evidence", file=sys.stderr)
    for path in dir_files:
        evidence.append(f"Evidence file: {path}\n{path.read_text(encoding='utf-8')}")
    # Candidate overlays from an earlier reverse run are untrusted inferences
    # about the same functions. They are injected only on explicit request so a
    # preview can stay an unpolluted look at the IDB, and so a write run can
    # decline them. An explicit request that matches nothing is an error: a
    # silent no-op would look like a successful injection.
    if args.include_candidates:
        auto = discover_candidate_files(Path(config.output.report_dir), addresses)
        if not auto:
            raise ValueError(
                "No reverse candidate overlays found for the selected addresses under "
                f"{Path(config.output.report_dir) / 'candidates'}; run reverse first or drop --include-candidates"
            )
        print(f"[recover-types] including {len(auto)} candidate overlay(s) as evidence", file=sys.stderr)
        for path in auto:
            evidence.append(f"Candidate overlay from a prior reverse run (unverified): {path}\n"
                            f"{path.read_text(encoding='utf-8')}")
    report_path = Path(args.output) if args.output else (
        Path(config.output.report_dir) / "recovery" / f"{uuid.uuid4().hex}.json"
    )
    provider = create_recovery_provider(config.recovery)
    if managed and args.write and not args.save:
        print("[recover-types] Without --save, changes will be discarded when this stage closes.", file=sys.stderr)
    logger = logging.getLogger("re_agent.recovery")
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("[recover-types] %(message)s"))
    previous_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    report = None
    try:
        with ida_client_stage(config.backend, "recover", IdaRecoveryClient,
                              Path(config.output.log_dir) / "idalib") as client:
            report = run_recovery(provider, client, addresses, config.recovery, report_path,
                                  write=args.write, save=args.save, evidence="\n\n".join(evidence),
                                  objective=args.objective)
    except IdalibLifecycleError as exc:
        if report is not None:
            report["status"] = "failed"
            report["error"] = f"{report.get('error', '')} IDA lifecycle failed: {exc}".strip()
            atomic_json(report_path, report)
        raise
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
    print(f"[recover-types] {report['status']}: {report_path}", file=sys.stderr)
    if report.get("error"):
        print(f"[recover-types] {report['error']}", file=sys.stderr)
    if report.get("backup_path"):
        print(f"[recover-types] IDA-host backup: {report['backup_path']}", file=sys.stderr)
    if report.get("summary"):
        print(report["summary"])
    return 0 if report["status"] in {"planned", "verified"} else 1
