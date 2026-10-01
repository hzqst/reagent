"""CLI entry point for re-agent."""

from __future__ import annotations

import argparse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="re-agent",
        description="Autonomous reverse engineering agent",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 0.4.0")
    parser.add_argument("--config", default="re-agent.yaml", help="Config file path")

    sub = parser.add_subparsers(dest="command", help="Available commands")

    doctor_p = sub.add_parser("doctor", help="Check configuration and exported evidence without LLM calls")
    doctor_p.add_argument("--address", help="Check evidence for one function")
    benchmark_p = sub.add_parser("benchmark", help="Run a differential harness manifest")
    benchmark_p.add_argument("--manifest", required=True)
    benchmark_p.add_argument("--output")

    plan_p = sub.add_parser("plan", help="Export a bounded target manifest without LLM calls")
    plan_p.add_argument("--address", action="append", help="Seed function address (repeatable)")
    plan_p.add_argument("--match", action="append", help="Backend symbol search (repeatable)")
    plan_p.add_argument("--max-depth", type=int, default=1)
    plan_p.add_argument("--max-functions", type=int, default=100)
    plan_p.add_argument("--output", required=True)

    evidence_p = sub.add_parser("evidence", help="Export stored manifest evidence into searchable packets")
    evidence_p.add_argument("--manifest", required=True)
    evidence_p.add_argument("--output", required=True)

    # init
    init_p = sub.add_parser("init", help="Initialize re-agent.yaml config file")
    init_p.add_argument("--profile", default=None, help="Use a built-in project profile template")

    # reverse
    rev_p = sub.add_parser("reverse", help="Reverse engineer functions")
    rev_p.add_argument("--manifest", help="Target manifest produced by plan")
    rev_p.add_argument("--address", help="Single function address to reverse")
    rev_p.add_argument("--class", dest="class_name", help="Class name for class-level reversal")
    rev_p.add_argument("--max-functions", type=int, default=None, help="Max functions per class")
    rev_p.add_argument("--max-rounds", type=int, default=None, help="Max review rounds per function")
    rev_p.add_argument("--dry-run", action="store_true", help="Show plan without executing")
    rev_p.add_argument("--skip-parity", action="store_true", help="Skip parity check after PASS")

    # parity
    par_p = sub.add_parser("parity", help="Run parity checks on hooked functions")
    par_p.add_argument("--address", action="append", help="Specific address (repeatable)")
    par_p.add_argument("--filter", help="Regex filter on symbol/class")
    par_p.add_argument("--limit", type=int, help="Max functions to check")
    par_p.add_argument("--skip-ghidra", action="store_true", help="Source-only checks")
    par_p.add_argument("--strict-exit", action="store_true", help="Exit 1 on RED")
    par_p.add_argument("--output", help="Output JSON report path")

    # status
    stat_p = sub.add_parser("status", help="Show reversal progress")
    stat_p.add_argument("--manifest", help="Report coverage of a planned function group")
    stat_p.add_argument("--class", dest="class_name", help="Filter by class")
    stat_p.add_argument("--format", choices=["text", "json", "markdown"], default="text")

    # estimate
    estimate_p = sub.add_parser("estimate", help="Estimate token usage before a run")
    estimate_p.add_argument("--address", help="Single function address")
    estimate_p.add_argument("--class", dest="class_name", help="Class name to estimate")
    estimate_p.add_argument("--limit", type=int, default=50, help="Maximum functions to inspect")

    recovery_p = sub.add_parser("recover-types", help="Investigate and recover IDA types with an independent agent")
    recovery_p.add_argument("--address", action="append", required=True, help="Target function entry (repeatable)")
    recovery_p.add_argument("--evidence", action="append", default=[], help="Read additional evidence from a file")
    recovery_p.add_argument(
        "--evidence-dirs", "--evidence_dirs", dest="evidence_dirs", action="append", default=[],
        help="Read evidence from a directory (recursive) or glob pattern; "
             "filtered by project_profile.source_extensions",
    )
    recovery_p.add_argument(
        "--objective", default="Recover evidence-supported class pointers, vtable pointers and virtual calls.",
        help="Recovery objective within the selected functions",
    )
    recovery_p.add_argument("--write", action="store_true",
                            help="Permit IDA type recovery; default is read-only investigation")
    recovery_p.add_argument("--save", action="store_true", help="Save after successful independent type readback")
    recovery_p.add_argument(
        "--include-candidates", action="store_true",
        help="Inject candidate overlays from earlier reverse runs for the selected addresses as evidence",
    )
    recovery_p.add_argument("--output", help="Recovery journal path (default: report_dir/recovery/<run-id>.json)")

    # annotate
    ann_p = sub.add_parser("annotate", help="Apply symbol proposals to an IDA database")
    ann_p.add_argument("--address", action="append", help="Select a hexadecimal address (repeatable)")
    ann_p.add_argument("--comments-only", action="store_true", help="Apply only function comments")
    ann_p.add_argument(
        "--replace-function-comment", action="store_true",
        help="Replace the whole regular function comment; requires --address",
    )
    ann_p.add_argument("--symbols", help="Proposals file (default: report_dir/symbols.json)")
    ann_p.add_argument(
        "--from-hooks",
        nargs="+",
        help="Header directories to read symbol annotations from instead of --symbols",
    )
    ann_p.add_argument(
        "--write", action="store_true", help="Apply the changes; without it nothing is written"
    )
    ann_p.add_argument(
        "--only-unnamed",
        action="store_true",
        help="Skip addresses that already carry a non-placeholder name",
    )
    ann_p.add_argument(
        "--include-flagged",
        action="store_true",
        help="Also apply proposals the checker disputed",
    )
    ann_p.add_argument(
        "--allow-struct-changes",
        action="store_true",
        help="Permit struct member changes, which modify a shared type",
    )
    ann_p.add_argument(
        "--allow-prototype-changes",
        action="store_true",
        help="Permit reviewed void-pointer refinements that preserve the function ABI",
    )
    ann_p.add_argument("--allow-inferred-prototypes", action="store_true",
                       help="Accept independently reviewed inferred prototypes; requires --address")
    ann_p.add_argument("--allow-abi-type-corrections", action="store_true",
                       help="Permit reviewed same-width integer/data-pointer corrections; requires --address")
    ann_p.add_argument(
        "--save", action="store_true", help="Save the IDA database after writing"
    )

    return parser


def _main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "evidence":
        from re_agent.cli.cmd_evidence import cmd_evidence

        return cmd_evidence(args)
    if args.command == "plan":
        from re_agent.cli.cmd_plan import cmd_plan

        return cmd_plan(args)
    if args.command == "doctor":
        from re_agent.cli.cmd_doctor import cmd_doctor

        return cmd_doctor(args)
    if args.command == "benchmark":
        from re_agent.cli.cmd_benchmark import cmd_benchmark

        return cmd_benchmark(args)

    if args.command == "init":
        from re_agent.cli.cmd_init import cmd_init

        return cmd_init(args)

    if args.command == "reverse":
        from re_agent.cli.cmd_reverse import cmd_reverse

        return cmd_reverse(args)

    if args.command == "parity":
        from re_agent.cli.cmd_parity import cmd_parity

        return cmd_parity(args)

    if args.command == "status":
        from re_agent.cli.cmd_status import cmd_status

        return cmd_status(args)

    if args.command == "estimate":
        from re_agent.cli.cmd_estimate import cmd_estimate

        return cmd_estimate(args)

    if args.command == "annotate":
        from re_agent.cli.cmd_annotate import cmd_annotate

        return cmd_annotate(args)

    if args.command == "recover-types":
        from re_agent.cli.cmd_recover_types import cmd_recover_types

        return cmd_recover_types(args)

    parser.print_help()
    return 1


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except (ValueError, RuntimeError, OSError) as exc:
        import sys

        print(f"Error: {exc}", file=sys.stderr)
        return 1
