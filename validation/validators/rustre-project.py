#!/usr/bin/env python3
"""
Independent Python validator for the `rustre-project` crate.

Reimplements pure/testable functions of the crate with stdlib + optional libs
(pefile, lief) so the Rust implementation can be cross-checked.

Usage:
    echo '{"fn":"sha256_hex","data_b64":"..."}' | python rustre-project.py
    python rustre-project.py            # runs built-in self-tests
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import struct
import sys
import sqlite3
import tempfile
from collections import Counter
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Optional deps (best-effort, lazy)
# ---------------------------------------------------------------------------

def _try_import(name):
    try:
        return __import__(name)
    except Exception:
        try:
            import subprocess
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet", name],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            return __import__(name)
        except Exception:
            return None


# ---------------------------------------------------------------------------
# validator_sha256_hex
# ---------------------------------------------------------------------------

def validator_sha256_hex(data: bytes) -> str:
    """Ground truth for crate's sha256_hex(bytes) -> lowercase hex string."""
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# validator_shannon_entropy
# ---------------------------------------------------------------------------

def validator_shannon_entropy(data: bytes) -> float:
    """Ground truth for crate's shannon_entropy. 0.0 for empty input."""
    if not data:
        return 0.0
    n = len(data)
    counts = Counter(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ---------------------------------------------------------------------------
# validator_classify_binary
# ---------------------------------------------------------------------------

# IMAGE_FILE_MACHINE_* (PE)
_PE_MACHINE = {
    0x014C: "x86",
    0x8664: "x86_64",
    0xAA64: "aarch64",
    0x01C0: "arm",
    0x01C4: "arm",  # ARMNT
}

# ELF e_machine
_ELF_MACHINE = {
    0x03: "x86",
    0x3E: "x86_64",
    0x28: "arm",
    0xB7: "aarch64",
    0xF3: "riscv",
    0x08: "mips",
}

# Mach-O magics
_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",  # MH_MAGIC (32-bit BE)
    b"\xce\xfa\xed\xfe",  # MH_CIGAM (32-bit LE)
    b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64 (BE)
    b"\xcf\xfa\xed\xfe",  # MH_CIGAM_64 (LE)
    b"\xca\xfe\xba\xbe",  # FAT_MAGIC
}


def validator_classify_binary(data: bytes, default_arch: str = "unknown"):
    """Ground truth for classify_binary -> (format, arch)."""
    if len(data) < 4:
        return ("unknown", default_arch)

    # PE
    if data[:2] == b"MZ" and len(data) >= 0x40:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if (
            e_lfanew + 6 <= len(data)
            and data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00"
        ):
            machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
            return ("PE", _PE_MACHINE.get(machine, default_arch))
        return ("PE", default_arch)

    # ELF
    if data[:4] == b"\x7fELF" and len(data) >= 20:
        ei_data = data[5]  # 1=LE, 2=BE
        endian = "<" if ei_data == 1 else ">"
        e_machine = struct.unpack_from(endian + "H", data, 18)[0]
        return ("ELF", _ELF_MACHINE.get(e_machine, default_arch))

    # Mach-O
    if data[:4] in _MACHO_MAGICS:
        if data[:4] == b"\xca\xfe\xba\xbe":
            return ("MachO-fat", default_arch)
        return ("MachO", default_arch)

    # WASM
    if data[:4] == b"\x00asm":
        return ("WASM", "wasm32")

    # DEX
    if data[:4] == b"dex\n":
        return ("DEX", "dalvik")

    return ("unknown", default_arch)


# ---------------------------------------------------------------------------
# validator_get_migrations
# ---------------------------------------------------------------------------

def validator_get_migrations() -> dict:
    """Crate exposes exactly 4 migrations numbered 1..=4."""
    expected = [1, 2, 3, 4]
    return {"count": len(expected), "versions": expected, "current_schema_version": 4}


# ---------------------------------------------------------------------------
# validator_run_migrations
# ---------------------------------------------------------------------------

# Tables that must exist after applying all 4 migrations (per report section).
_EXPECTED_TABLES = {
    "schema_migrations",
    "binaries", "functions", "basic_blocks", "edges", "xrefs",
    "symbols", "types", "variables", "comments", "bookmarks",
    "strings", "annotations", "events", "undo_log",
    "scripts", "notes", "patches", "version_history",
    "layout_state", "strings_fts", "triage_results",
}


def validator_run_migrations(db_path: str | None = None) -> dict:
    """
    Simulate the *post-condition* the crate's migrations should leave us in:
    a schema_migrations table with 4 rows. We don't have the SQL DDL here, so
    this validator only verifies the contract (count=4, versions 1..=4).
    Caller can pass an actual SQLite file produced by the crate; we then check
    that schema_migrations row count == 4 and expected tables are present.
    """
    out = {"expected_schema_migration_rows": 4,
           "expected_tables": sorted(_EXPECTED_TABLES)}
    if db_path and os.path.isfile(db_path):
        con = sqlite3.connect(db_path)
        try:
            cur = con.cursor()
            n = cur.execute(
                "SELECT COUNT(*) FROM schema_migrations"
            ).fetchone()[0]
            tabs = {r[0] for r in cur.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table','view')"
            ).fetchall()}
            out["actual_schema_migration_rows"] = n
            out["missing_tables"] = sorted(_EXPECTED_TABLES - tabs)
            out["ok"] = (n == 4 and not (_EXPECTED_TABLES - tabs))
        finally:
            con.close()
    return out


# ---------------------------------------------------------------------------
# validator_unix_to_iso8601
# ---------------------------------------------------------------------------

def validator_unix_to_iso8601(ts: int) -> str:
    """RFC3339 UTC string with '+00:00' offset."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# validator_version_snapshot_pruning
# ---------------------------------------------------------------------------

MAX_VERSION_SNAPSHOTS = 10


def validator_version_snapshot_pruning(insert_count: int) -> dict:
    """save_version_snapshot keeps only the most recent MAX_VERSION_SNAPSHOTS."""
    kept = min(insert_count, MAX_VERSION_SNAPSHOTS)
    return {"inserted": insert_count, "expected_kept": kept,
            "max_snapshots": MAX_VERSION_SNAPSHOTS}


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

DISPATCH = {
    "sha256_hex": lambda p: validator_sha256_hex(
        base64.b64decode(p["data_b64"])),
    "shannon_entropy": lambda p: validator_shannon_entropy(
        base64.b64decode(p["data_b64"])),
    "classify_binary": lambda p: list(validator_classify_binary(
        base64.b64decode(p["data_b64"]),
        p.get("default_arch", "unknown"))),
    "get_migrations": lambda p: validator_get_migrations(),
    "run_migrations": lambda p: validator_run_migrations(p.get("db_path")),
    "unix_to_iso8601": lambda p: validator_unix_to_iso8601(int(p["ts"])),
    "version_snapshot_pruning": lambda p: validator_version_snapshot_pruning(
        int(p["insert_count"])),
}


def _self_test() -> dict:
    """Fixed-vector self-tests."""
    results = {}

    # sha256
    results["sha256_hex_empty"] = validator_sha256_hex(b"")
    results["sha256_hex_abc"] = validator_sha256_hex(b"abc")

    # entropy
    results["entropy_empty"] = validator_shannon_entropy(b"")
    results["entropy_aaaa"] = validator_shannon_entropy(b"AAAA")
    results["entropy_ab"] = validator_shannon_entropy(b"AB")

    # classify
    pe = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40) + b"PE\x00\x00" \
         + struct.pack("<H", 0x8664)
    elf64 = b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 9 \
            + struct.pack("<HH", 2, 0x3E) + b"\x00" * 4
    results["classify_PE_x64"] = list(validator_classify_binary(pe))
    results["classify_ELF_x64"] = list(validator_classify_binary(elf64))
    results["classify_WASM"] = list(validator_classify_binary(b"\x00asm\x01\x00\x00\x00"))
    results["classify_DEX"] = list(validator_classify_binary(b"dex\n035\x00"))
    results["classify_unknown"] = list(validator_classify_binary(b"hello world"))
    results["classify_macho64"] = list(validator_classify_binary(
        b"\xcf\xfa\xed\xfe" + b"\x00" * 28))

    # migrations
    results["migrations"] = validator_get_migrations()

    # unix_to_iso
    results["iso_0"] = validator_unix_to_iso8601(0)
    results["iso_1700000000"] = validator_unix_to_iso8601(1700000000)

    # pruning
    results["prune_12"] = validator_version_snapshot_pruning(12)
    results["prune_5"] = validator_version_snapshot_pruning(5)

    return results


def main():
    if not sys.stdin.isatty():
        raw = sys.stdin.read().strip()
        if raw:
            req = json.loads(raw)
            fn = req.get("fn")
            if fn not in DISPATCH:
                print(json.dumps({"error": f"unknown fn: {fn}"}))
                return
            try:
                out = DISPATCH[fn](req)
                print(json.dumps({"fn": fn, "result": out}))
            except Exception as exc:
                print(json.dumps({"fn": fn, "error": str(exc)}))
            return

    # Self-test mode
    print(json.dumps(_self_test(), indent=2, default=str))


if __name__ == "__main__":
    main()
