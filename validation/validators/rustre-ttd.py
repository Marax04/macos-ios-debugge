#!/usr/bin/env python3
"""Independent validator for rustre-ttd (Time Travel Debugging core).

Reads a report file describing TTD trace recording/replay surface (JSON if
present, otherwise the markdown report) and writes a normalized validator
output as JSON. Prints to stdout:

    { "crate": "<crate name>", "saved": "<path>" }

Usage:
    python rustre-ttd.py [<report>] [--out <output.json>]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


CRATE_NAME = "rustre-ttd"


def load_report(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Report not found: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".json":
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Report is not valid JSON: {exc}") from exc
    # Markdown -> derive structural metrics
    return parse_markdown(text)


def parse_markdown(text: str) -> dict:
    """Best-effort extraction from the rustre-ttd markdown report."""
    modules = re.findall(r"^- `([A-Za-z0-9_./]+\.rs)`", text, re.MULTILINE)
    event_kinds = re.findall(
        r"`(MemRead|MemWrite|Call|Return|SyscallEnter|SyscallExit|"
        r"Exception|ThreadCreate|ThreadExit|Breakpoint)\b",
        text,
    )
    errors = re.findall(
        r"`(TraceNotOpen|InvalidPosition|ReadError|IoError|CorruptTrace|"
        r"UnsupportedVersion|DatabaseError|SerdeError)\b",
        text,
    )
    filters = re.findall(
        r"`(ByThread|ByKind|ByRange|ByAddressRange|And|Or|Not)\b", text
    )
    public_types = re.findall(
        r"### `([A-Z][A-Za-z0-9_]+)`", text
    )
    src_match = re.search(r"Source:\s*`([^`]+)`\s*\((\d+)\s*lines", text)
    src_path = src_match.group(1) if src_match else ""
    src_lines = int(src_match.group(2)) if src_match else 0

    return {
        "modules": sorted(set(modules)),
        "event_kinds": sorted(set(event_kinds)),
        "errors": sorted(set(errors)),
        "filter_variants": sorted(set(filters)),
        "public_types": sorted(set(public_types)),
        "source_file": src_path,
        "source_lines": src_lines,
    }


def compute_ttd(report: dict) -> dict:
    """Derive TTD metrics from a report dict.

    Best-effort fields (markdown-derived or JSON-supplied):
      - modules, event_kinds, errors, filter_variants, public_types
      - traces, sessions, events, indexed_events, watchpoints, breakpoints
      - bytes_recorded, threads
    Missing fields default to empty/0.
    """
    def _int(name: str) -> int:
        return int(report.get(name, 0) or 0)

    def _list(name: str) -> list:
        v = report.get(name, []) or []
        return list(v) if isinstance(v, (list, tuple, set)) else []

    modules = _list("modules")
    event_kinds = _list("event_kinds")
    errors = _list("errors")
    filter_variants = _list("filter_variants")
    public_types = _list("public_types")

    events = _int("events")
    indexed_events = _int("indexed_events")
    traces = _int("traces")
    sessions = _int("sessions")
    watchpoints = _int("watchpoints")
    breakpoints = _int("breakpoints")
    bytes_recorded = _int("bytes_recorded")
    threads = _int("threads")

    index_coverage = (
        (indexed_events / events * 100.0) if events else 0.0
    )

    # Static surface expectations from the report
    expected_event_kinds = {
        "MemRead", "MemWrite", "Call", "Return",
        "SyscallEnter", "SyscallExit", "Exception",
        "ThreadCreate", "ThreadExit", "Breakpoint",
    }
    expected_filters = {
        "ByThread", "ByKind", "ByRange", "ByAddressRange",
        "And", "Or", "Not",
    }
    missing_event_kinds = sorted(expected_event_kinds - set(event_kinds))
    missing_filters = sorted(expected_filters - set(filter_variants))

    return {
        "crate": CRATE_NAME,
        "mode": "time_travel_debugging",
        "modules": modules,
        "module_count": len(modules),
        "public_types": public_types,
        "public_type_count": len(public_types),
        "event_kinds": event_kinds,
        "event_kind_count": len(event_kinds),
        "missing_event_kinds": missing_event_kinds,
        "errors": errors,
        "error_count": len(errors),
        "filter_variants": filter_variants,
        "missing_filter_variants": missing_filters,
        "runtime": {
            "traces": traces,
            "sessions": sessions,
            "events": events,
            "indexed_events": indexed_events,
            "index_coverage_pct": round(index_coverage, 2),
            "watchpoints": watchpoints,
            "breakpoints": breakpoints,
            "bytes_recorded": bytes_recorded,
            "threads": threads,
        },
        "source_file": report.get("source_file", ""),
        "source_lines": int(report.get("source_lines", 0) or 0),
        "source_report": str(report.get("__source__", "")),
    }


def save_output(data: dict, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return out_path


def resolve_report(base: Path, explicit: str | None) -> Path:
    if explicit:
        return Path(explicit)
    candidates = [
        base / "reports" / "rustre-ttd.json",
        base / "reports" / "rustre-ttd.md",
    ]
    for c in candidates:
        if c.exists():
            return c
    return candidates[0]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="rustre-ttd validator")
    parser.add_argument("report", nargs="?", help="Path to the input report (.json or .md)")
    parser.add_argument("--out", help="Path to save the validator output JSON")
    args = parser.parse_args(argv)

    base = Path(__file__).resolve().parent.parent
    report_path = resolve_report(base, args.report)
    out_path = Path(args.out) if args.out else base / "outputs" / "rustre-ttd.json"

    try:
        if report_path.exists():
            report = load_report(report_path)
            report["__source__"] = str(report_path)
        else:
            report = {"__source__": str(report_path)}

        result = compute_ttd(report)
        saved = save_output(result, out_path)
    except Exception as exc:
        print(json.dumps({"crate": CRATE_NAME, "error": str(exc)}))
        return 1

    print(json.dumps({"crate": CRATE_NAME, "saved": str(saved)}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
