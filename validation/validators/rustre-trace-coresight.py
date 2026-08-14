#!/usr/bin/env python3
"""Independent validator for rustre-trace CoreSight ETM/PTM traces.

Reads a report file (JSON) describing a CoreSight trace capture/decode and
writes a normalized validator output as JSON to stdout in the shape:
    { "crate": "<crate name>", "saved": <path to saved output> }

Usage:
    python rustre-trace-coresight.py <report.json> [--out <output.json>]
"""
from __future__ import annotations

import argparse
import json
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


def compute_coresight(report: dict) -> dict:
    """Derive CoreSight trace metrics from a report dict.

    Expected (best-effort) report fields:
      - protocol: "ETMv4" | "ETMv3" | "PTM" | "STM"
      - sources: list of trace source IDs
      - sinks: list of trace sink names (ETB, ETF, ETR, TPIU)
      - packets: list of decoded trace packets
      - sync_packets / total_packets
      - dropped_packets
      - instructions_traced
      - branches
      - exceptions
      - cycles
      - timestamps: list
      - decode_errors: list
    Missing fields default to 0 / [].
    """
    sources = report.get("sources", []) or []
    sinks = report.get("sinks", []) or []
    packets = report.get("packets", []) or []
    decode_errors = report.get("decode_errors", []) or []
    timestamps = report.get("timestamps", []) or []

    total_packets = int(report.get("total_packets", len(packets) if isinstance(packets, list) else 0) or 0)
    sync_packets = int(report.get("sync_packets", 0) or 0)
    dropped = int(report.get("dropped_packets", 0) or 0)
    instructions = int(report.get("instructions_traced", 0) or 0)
    branches = int(report.get("branches", 0) or 0)
    exceptions = int(report.get("exceptions", 0) or 0)
    cycles = int(report.get("cycles", 0) or 0)

    sync_ratio = (sync_packets / total_packets * 100.0) if total_packets else 0.0
    drop_ratio = (dropped / total_packets * 100.0) if total_packets else 0.0
    ipc = (instructions / cycles) if cycles else 0.0

    return {
        "crate": CRATE_NAME,
        "protocol": str(report.get("protocol", "unknown")),
        "source_count": len(sources) if isinstance(sources, list) else 0,
        "sink_count": len(sinks) if isinstance(sinks, list) else 0,
        "sinks": sinks if isinstance(sinks, list) else [],
        "total_packets": total_packets,
        "sync_packets": sync_packets,
        "sync_ratio_pct": round(sync_ratio, 2),
        "dropped_packets": dropped,
        "drop_ratio_pct": round(drop_ratio, 2),
        "instructions_traced": instructions,
        "branches": branches,
        "exceptions": exceptions,
        "cycles": cycles,
        "ipc": round(ipc, 4),
        "timestamp_count": len(timestamps) if isinstance(timestamps, list) else 0,
        "decode_error_count": len(decode_errors) if isinstance(decode_errors, list) else 0,
        "source_report": str(report.get("__source__", "")),
    }


def save_output(data: dict, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return out_path


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="rustre-trace CoreSight validator")
    parser.add_argument("report", nargs="?", help="Path to the input report JSON")
    parser.add_argument("--out", help="Path to save the validator output JSON")
    args = parser.parse_args(argv)

    base = Path(__file__).resolve().parent.parent
    report_path = Path(args.report) if args.report else base / "reports" / "rustre-trace.json"
    out_path = Path(args.out) if args.out else base / "outputs" / "rustre-trace-coresight.json"

    try:
        if report_path.exists():
            report = load_report(report_path)
            report["__source__"] = str(report_path)
        else:
            report = {"__source__": str(report_path)}

        result = compute_coresight(report)
        saved = save_output(result, out_path)
    except Exception as exc:
        print(json.dumps({"crate": CRATE_NAME, "error": str(exc)}))
        return 1

    print(json.dumps({"crate": CRATE_NAME, "saved": str(saved)}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
