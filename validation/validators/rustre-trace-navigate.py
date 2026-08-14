#!/usr/bin/env python3
"""Independent validator for rustre-trace navigation.

Reads a report file (JSON) describing trace navigation analysis and writes
a normalized validator output as JSON to stdout in the shape:
    { "crate": "<crate name>", "saved": <path to saved output> }

Usage:
    python rustre-trace-navigate.py <report.json> [--out <output.json>]
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


def compute_navigation(report: dict) -> dict:
    """Derive navigation metrics from a report dict.

    Expected (best-effort) report fields:
      - frames / steps: list of trace frames or step entries
      - total_steps / current_step
      - jumps: list of navigation jumps (backward/forward)
      - bookmarks: list of saved positions
      - functions_visited / blocks_visited
    Missing fields default to 0.
    """
    frames = report.get("frames") or report.get("steps") or []
    total_steps = int(report.get("total_steps", len(frames) if isinstance(frames, list) else 0) or 0)
    current_step = int(report.get("current_step", 0) or 0)
    jumps = report.get("jumps", []) or []
    bookmarks = report.get("bookmarks", []) or []
    functions_visited = int(report.get("functions_visited", 0) or 0)
    blocks_visited = int(report.get("blocks_visited", 0) or 0)

    forward_jumps = 0
    backward_jumps = 0
    if isinstance(jumps, list):
        for j in jumps:
            if not isinstance(j, dict):
                continue
            direction = (j.get("direction") or "").lower()
            if direction == "forward":
                forward_jumps += 1
            elif direction == "backward" or direction == "back":
                backward_jumps += 1

    progress_pct = (current_step / total_steps * 100.0) if total_steps else 0.0

    return {
        "crate": CRATE_NAME,
        "total_steps": total_steps,
        "current_step": current_step,
        "progress_pct": round(progress_pct, 2),
        "frame_count": len(frames) if isinstance(frames, list) else 0,
        "jump_count": len(jumps) if isinstance(jumps, list) else 0,
        "forward_jumps": forward_jumps,
        "backward_jumps": backward_jumps,
        "bookmark_count": len(bookmarks) if isinstance(bookmarks, list) else 0,
        "functions_visited": functions_visited,
        "blocks_visited": blocks_visited,
        "source_report": str(report.get("__source__", "")),
    }


def save_output(data: dict, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return out_path


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="rustre-trace navigation validator")
    parser.add_argument("report", nargs="?", help="Path to the input report JSON")
    parser.add_argument("--out", help="Path to save the validator output JSON")
    args = parser.parse_args(argv)

    base = Path(__file__).resolve().parent.parent
    report_path = Path(args.report) if args.report else base / "reports" / "rustre-trace.json"
    out_path = Path(args.out) if args.out else base / "outputs" / "rustre-trace-navigate.json"

    try:
        if report_path.exists():
            report = load_report(report_path)
            report["__source__"] = str(report_path)
        else:
            report = {"__source__": str(report_path)}

        result = compute_navigation(report)
        saved = save_output(result, out_path)
    except Exception as exc:
        print(json.dumps({"crate": CRATE_NAME, "error": str(exc)}))
        return 1

    print(json.dumps({"crate": CRATE_NAME, "saved": str(saved)}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
