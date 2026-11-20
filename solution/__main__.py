"""Command-line entry point.

    python -m solution --input cases.json --output result.json

Exit codes
----------
0   every case matched its expectations
1   at least one case did not match (details are in the output file)
2   the input or command line was unusable
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

from .cases import load_cases, run_cases, write_results
from .errors import UpdateError


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m solution",
        description="Replay the offline secure-update cases against a fresh SQLite client state.",
    )
    parser.add_argument("--input", required=True, help="path to cases.json")
    parser.add_argument("--output", required=True, help="path to write result.json")
    parser.add_argument(
        "--work-dir",
        default=None,
        help="scratch directory for synthesised packages and databases "
        "(default: a fresh temporary directory, removed afterwards)",
    )
    parser.add_argument("--keep-work-dir", action="store_true", help="keep the scratch directory")
    parser.add_argument(
        "--quiet", action="store_true", help="do not print a summary line"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    try:
        cases_doc = load_cases(args.input)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, UpdateError) as exc:
        print(f"error: cannot read cases: {exc}", file=sys.stderr)
        return 2

    owned_workdir = args.work_dir is None
    work_dir = args.work_dir or tempfile.mkdtemp(prefix="simupd-cases-")
    os.makedirs(work_dir, exist_ok=True)

    try:
        results = run_cases(cases_doc, work_dir)
        write_results(args.output, results)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        if owned_workdir and not args.keep_work_dir:
            import shutil

            shutil.rmtree(work_dir, ignore_errors=True)

    summary = results["summary"]
    if not args.quiet:
        print(
            f"{summary['passed']}/{summary['total']} cases matched "
            f"({summary['failed']} failed) -> {args.output}"
        )
    for case in results["cases"]:
        if not case["ok"]:
            print(f"  FAIL {case['case']}: {case['failure']}", file=sys.stderr)
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
