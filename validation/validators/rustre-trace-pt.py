#!/usr/bin/env python3
"""Independent validator for rustre-trace Intel PT (Processor Trace).

Reads a report file (JSON) describing PT trace decoding/analysis and writes
a normalized validator output as JSON. Prints to stdout:
    { "crate": "<crate name>", "saved": "<path>" }

Usage:
    python rustre-trace-pt.py <report.json> [--out <output.json>]
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


def compute_pt(report: dict) -> dict:
    """Derive Intel PT metrics from a report dict.

    Expected (best-effort) report fields:
      - pt_packets: total packets decoded
      - tnt_packets / tip_packets / fup_packets / psb_packets / mtc_packets / cyc_packets
      - decoded_instructions
      - branches_taken / branches_not_taken
      - indirect_branches
      - decode_errors
      - psb_blocks
      - duration_ns
      - traces: list of per-thread/per-cpu trace entries
    Missing fields default to 0.
    """
    def _int(name: str) -> int:
        return int(report.get(name, 0) or 0)

    pt_packets = _int("pt_packets")
    tnt = _int("tnt_packets")
    tip = _int("tip_packets")
    fup = _int("fup_packets")
    psb = _int("psb_packets")
    mtc = _int("mtc_packets")
    cyc = _int("cyc_packets")
    decoded_insns = _int("decoded_instructions")
    taken = _int("branches_taken")
    not_taken = _int("branches_not_taken")
    indirect = _int("indirect_branches")
    decode_errors = _int("decode_errors")
    psb_blocks = _int("psb_blocks")
    duration_ns = _int("duration_ns")
    traces = report.get("traces", []) or []

    total_branches = taken + not_taken + indirect
    taken_rate = (taken / total_branches * 100.0) if total_branches else 0.0
    error_rate = (decode_errors / pt_packets * 100.0) if pt_packets else 0.0
    ipc = (decoded_insns / duration_ns) if duration_ns else 0.0

    return {
        "crate": CRATE_NAME,
        "mode": "intel_pt",
        "pt_packets": pt_packets,
        "packet_breakdown": {
            "tnt": tnt,
            "tip": tip,
            "fup": fup,
            "psb": psb,
            "mtc": mtc,
            "cyc": cyc,
        },
        "decoded_instructions": decoded_insns,
        "branches": {
            "taken": taken,
            "not_taken": not_taken,
            "indirect": indirect,
            "total": total_branches,
            "taken_rate_pct": round(taken_rate, 2),
        },
        "decode_errors": decode_errors,
        "decode_error_rate_pct": round(error_rate, 4),
        "psb_blocks": psb_blocks,
        "duration_ns": duration_ns,
        "insn_per_ns": round(ipc, 6),
        "trace_count": len(traces) if isinstance(traces, list) else 0,
        "source_report": str(report.get("__source__", "")),
    }


def save_output(data: dict, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return out_path


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="rustre-trace Intel PT validator")
    parser.add_argument("report", nargs="?", help="Path to the input report JSON")
    parser.add_argument("--out", help="Path to save the validator output JSON")
    args = parser.parse_args(argv)

    base = Path(__file__).resolve().parent.parent
    report_path = Path(args.report) if args.report else base / "reports" / "rustre-trace-pt.json"
    out_path = Path(args.out) if args.out else base / "outputs" / "rustre-trace-pt.json"

    try:
        if report_path.exists():
            report = load_report(report_path)
            report["__source__"] = str(report_path)
        else:
            report = {"__source__": str(report_path)}

        result = compute_pt(report)
        saved = save_output(result, out_path)
    except Exception as exc:
        print(json.dumps({"crate": CRATE_NAME, "error": str(exc)}))
        return 1

    print(json.dumps({"crate": CRATE_NAME, "saved": str(saved)}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
