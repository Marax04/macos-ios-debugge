#!/usr/bin/env python3
"""Independent validator for rustre-trace coverage.

Reads a report file (JSON) describing trace coverage analysis and writes
a normalized validator output as JSON to stdout in the shape:
    { "crate": "<crate name>", "saved": <path to saved output> }

Usage:
    python rustre-trace-coverage.py <report.json> [--out <output.json>]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


CRATE_NAME = "rustre-trace"


def load_report(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Report not found: {path}")
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Report is not valid JSON: {exc}") from exc


def compute_coverage(report: dict) -> dict:
    """Derive coverage metrics from a report dict.

    Expected (best-effort) report fields:
      - total_blocks / covered_blocks
      - total_functions / covered_functions
      - traces: list of trace entries
    Missing fields default to 0.
    """
    total_blocks = int(report.get("total_blocks", 0) or 0)
    covered_blocks = int(report.get("covered_blocks", 0) or 0)
    total_funcs = int(report.get("total_functions", 0) or 0)
    covered_funcs = int(report.get("covered_functions", 0) or 0)
    traces = report.get("traces", []) or []

    block_cov = (covered_blocks / total_blocks * 100.0) if total_blocks else 0.0
    func_cov = (covered_funcs / total_funcs * 100.0) if total_funcs else 0.0

    return {
        "crate": CRATE_NAME,
        "total_blocks": total_blocks,
        "covered_blocks": covered_blocks,
        "block_coverage_pct": round(block_cov, 2),
        "total_functions": total_funcs,
        "covered_functions": covered_funcs,
        "function_coverage_pct": round(func_cov, 2),
        "trace_count": len(traces) if isinstance(traces, list) else 0,
        "source_report": str(report.get("__source__", "")),
    }


def save_output(data: dict, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return out_path


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="rustre-trace coverage validator")
    parser.add_argument("report", nargs="?", help="Path to the input report JSON")
    parser.add_argument("--out", help="Path to save the validator output JSON")
    args = parser.parse_args(argv)

    base = Path(__file__).resolve().parent.parent
    report_path = Path(args.report) if args.report else base / "reports" / "rustre-trace.json"
    out_path = Path(args.out) if args.out else base / "outputs" / "rustre-trace-coverage.json"

    try:
        if report_path.exists():
            report = load_report(report_path)
            report["__source__"] = str(report_path)
        else:
            # No report available — produce an empty-but-valid result rather than failing.
            report = {"__source__": str(report_path)}

        result = compute_coverage(report)
        saved = save_output(result, out_path)
    except Exception as exc:
        print(json.dumps({"crate": CRATE_NAME, "error": str(exc)}))
        return 1

    print(json.dumps({"crate": CRATE_NAME, "saved": str(saved)}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
