#!/usr/bin/env python3
"""
Independent Python validator for the rustre-patch crate.

Reimplements the testable functions of rustre-patch using only stdlib
(plus pefile if available) so its outputs can be cross-checked against
the Rust crate. No MCP calls, no Rust imports.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import subprocess
import sys
from typing import Any


# ---------------------------------------------------------------------------
# Optional deps (pefile) - install lazily
# ---------------------------------------------------------------------------
def _ensure(pkg: str) -> None:
    try:
        __import__(pkg)
    except ImportError:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", pkg]
        )


_ensure("pefile")
import pefile  # noqa: E402


# ---------------------------------------------------------------------------
# 1. parse_hex_bytes
# ---------------------------------------------------------------------------
def validator_parse_hex_bytes(s: str) -> list[int]:
    """Mirrors rustre-patch::parse_hex_bytes. Accepts 'DE AD BE EF' or 'deadbeef'."""
    cleaned = s.replace(" ", "").replace("\t", "").replace("\n", "")
    if len(cleaned) % 2 != 0:
        raise ValueError("odd hex length")
    return list(bytes.fromhex(cleaned))


# ---------------------------------------------------------------------------
# 2. apply_patches (length-preserving)
# ---------------------------------------------------------------------------
def validator_apply_patches(binary: list[int], patches: list[dict]) -> dict:
    """patches: [{offset, original_bytes, patch_bytes}]. Length-preserving only."""
    buf = bytearray(binary)
    applied = 0
    for p in patches:
        off = p["offset"]
        orig = bytes(p["original_bytes"])
        new = bytes(p["patch_bytes"])
        if len(orig) != len(new):
            raise ValueError("apply_patches requires is_same_size")
        if buf[off : off + len(orig)] != orig:
            raise ValueError(f"original_bytes mismatch at offset {off}")
        buf[off : off + len(new)] = new
        applied += 1
    return {
        "binary": list(buf),
        "applied": applied,
        "total_bytes_modified": sum(len(p["patch_bytes"]) for p in patches),
    }


# ---------------------------------------------------------------------------
# 3. checksum_after (deterministic post-patch hash)
# ---------------------------------------------------------------------------
def validator_checksum_after(binary: list[int], patches: list[dict]) -> int:
    res = validator_apply_patches(binary, patches)
    h = hashlib.sha256(bytes(res["binary"])).digest()
    return struct.unpack("<Q", h[:8])[0]


# ---------------------------------------------------------------------------
# 4. validate_patch
# ---------------------------------------------------------------------------
def validator_validate_patch(binary: list[int], patch: dict) -> dict:
    errors: list[str] = []
    warnings: list[str] = []
    off = patch["offset"]
    orig = bytes(patch["original_bytes"])
    new = bytes(patch["patch_bytes"])
    if off < 0 or off + len(orig) > len(binary):
        errors.append("out_of_bounds")
    elif bytes(binary[off : off + len(orig)]) != orig:
        errors.append("original_mismatch")
    if len(orig) != len(new):
        warnings.append("length_change")
    return {"errors": errors, "warnings": warnings, "ok": not errors}


# ---------------------------------------------------------------------------
# 5. find_code_caves
# ---------------------------------------------------------------------------
def validator_find_code_caves(
    binary: list[int], min_size: int, fill_bytes: list[int] | None = None
) -> list[dict]:
    """Find runs of fill byte (0x00, 0x90, or 0xCC by default) >= min_size."""
    fills = set(fill_bytes) if fill_bytes else {0x00, 0x90, 0xCC}
    caves = []
    buf = bytes(binary)
    i = 0
    n = len(buf)
    while i < n:
        if buf[i] in fills:
            b = buf[i]
            j = i
            while j < n and buf[j] == b:
                j += 1
            if j - i >= min_size:
                caves.append({"offset": i, "size": j - i, "fill_byte": b})
            i = j
        else:
            i += 1
    return caves


# ---------------------------------------------------------------------------
# 6. assemble_simple
# ---------------------------------------------------------------------------
_ASM_TABLE = {
    "nop": [0x90],
    "ret": [0xC3],
    "int3": [0xCC],
    "hlt": [0xF4],
    "cld": [0xFC],
    "std": [0xFD],
    "leave": [0xC9],
}


def validator_assemble_simple(asm: str) -> list[int]:
    mnem = asm.strip().lower()
    if mnem not in _ASM_TABLE:
        raise ValueError(f"unsupported mnemonic: {mnem}")
    return list(_ASM_TABLE[mnem])


# ---------------------------------------------------------------------------
# 7. compute_pe_checksum
# ---------------------------------------------------------------------------
def validator_compute_pe_checksum(pe_path: str) -> int:
    pe = pefile.PE(pe_path, fast_load=True)
    return pe.generate_checksum()


# ---------------------------------------------------------------------------
# 8. pe_security_summary
# ---------------------------------------------------------------------------
def validator_pe_security_summary(pe_path: str) -> dict:
    pe = pefile.PE(pe_path, fast_load=True)
    dll = pe.OPTIONAL_HEADER.DllCharacteristics
    return {
        "dll_characteristics": dll,
        "aslr": bool(dll & 0x0040),  # DYNAMIC_BASE
        "high_entropy_va": bool(dll & 0x0020),
        "dep_nx": bool(dll & 0x0100),  # NX_COMPAT
        "no_seh": bool(dll & 0x0400),
        "cfg": bool(dll & 0x4000),  # GUARD_CF
        "force_integrity": bool(dll & 0x0080),
        "tsaware": bool(dll & 0x8000),
    }


# ---------------------------------------------------------------------------
# 9. pe_va_to_file_offset
# ---------------------------------------------------------------------------
def validator_pe_va_to_file_offset(pe_path: str, va: int) -> dict:
    pe = pefile.PE(pe_path, fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    rva = va - image_base
    for s in pe.sections:
        start = s.VirtualAddress
        end = start + max(s.Misc_VirtualSize, s.SizeOfRawData)
        if start <= rva < end:
            file_off = s.PointerToRawData + (rva - start)
            return {
                "section": s.Name.rstrip(b"\x00").decode("ascii", "replace"),
                "file_offset": file_off,
                "rva": rva,
            }
    raise ValueError(f"VA 0x{va:x} not in any section")


# ---------------------------------------------------------------------------
# 10. BinaryDelta: diff + patch round-trip
# ---------------------------------------------------------------------------
def validator_diff(old: list[int], new: list[int]) -> dict:
    """Trivial delta: full replacement. Encoded as ops list."""
    return {
        "ops": [{"op": "insert", "data": list(new)}],
        "old_len": len(old),
        "new_len": len(new),
    }


def validator_patch(old: list[int], delta: dict) -> list[int]:
    out = bytearray()
    for op in delta["ops"]:
        if op["op"] == "insert":
            out.extend(op["data"])
        elif op["op"] == "copy":
            out.extend(old[op["src"] : op["src"] + op["len"]])
    return list(out)


def validator_delta_roundtrip(old: list[int], new: list[int]) -> bool:
    return validator_patch(old, validator_diff(old, new)) == new


# ---------------------------------------------------------------------------
# 11. rollback (apply then revert == original)
# ---------------------------------------------------------------------------
def validator_create_rollback(binary: list[int], patches: list[dict]) -> dict:
    snapshot = {
        "entries": [
            {"offset": p["offset"], "original_bytes": list(p["original_bytes"])}
            for p in patches
        ]
    }
    applied = validator_apply_patches(binary, patches)["binary"]
    return {"snapshot": snapshot, "applied": applied}


def validator_rollback(applied: list[int], snapshot: dict) -> list[int]:
    buf = bytearray(applied)
    for e in snapshot["entries"]:
        off = e["offset"]
        orig = bytes(e["original_bytes"])
        buf[off : off + len(orig)] = orig
    return list(buf)


# ---------------------------------------------------------------------------
# 12. HotPatcher (InMemoryWriter)
# ---------------------------------------------------------------------------
class _InMemoryWriter:
    def __init__(self, buf: list[int]):
        self.buf = bytearray(buf)
        self.live: dict[str, dict] = {}

    def apply(self, pid: str, address: int, new_bytes: list[int]) -> None:
        orig = list(self.buf[address : address + len(new_bytes)])
        self.live[pid] = {"address": address, "original": orig}
        self.buf[address : address + len(new_bytes)] = bytes(new_bytes)

    def revert(self, pid: str) -> None:
        e = self.live.pop(pid)
        self.buf[e["address"] : e["address"] + len(e["original"])] = bytes(
            e["original"]
        )


def validator_hot_patch_roundtrip(
    binary: list[int], address: int, new_bytes: list[int]
) -> bool:
    w = _InMemoryWriter(binary)
    w.apply("p1", address, new_bytes)
    w.revert("p1")
    return list(w.buf) == binary


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
_DISPATCH = {
    "parse_hex_bytes": validator_parse_hex_bytes,
    "apply_patches": validator_apply_patches,
    "checksum_after": validator_checksum_after,
    "validate_patch": validator_validate_patch,
    "find_code_caves": validator_find_code_caves,
    "assemble_simple": validator_assemble_simple,
    "compute_pe_checksum": validator_compute_pe_checksum,
    "pe_security_summary": validator_pe_security_summary,
    "pe_va_to_file_offset": validator_pe_va_to_file_offset,
    "diff": validator_diff,
    "patch": validator_patch,
    "delta_roundtrip": validator_delta_roundtrip,
    "create_rollback": validator_create_rollback,
    "rollback": validator_rollback,
    "hot_patch_roundtrip": validator_hot_patch_roundtrip,
}


def _self_tests() -> dict:
    results = {}

    # parse_hex_bytes
    results["parse_hex_bytes"] = validator_parse_hex_bytes("DE AD BE EF") == [
        0xDE,
        0xAD,
        0xBE,
        0xEF,
    ]

    # apply / rollback / checksum
    bin0 = list(b"\x00" * 16)
    patches = [{"offset": 4, "original_bytes": [0, 0], "patch_bytes": [0x90, 0x90]}]
    ap = validator_apply_patches(bin0, patches)
    results["apply_patches"] = ap["binary"][4:6] == [0x90, 0x90]
    results["checksum_after"] = isinstance(
        validator_checksum_after(bin0, patches), int
    )
    rb = validator_create_rollback(bin0, patches)
    results["rollback"] = validator_rollback(rb["applied"], rb["snapshot"]) == bin0

    # validate_patch
    bad = {"offset": 0, "original_bytes": [0xFF], "patch_bytes": [0x00]}
    results["validate_patch"] = (
        validator_validate_patch(bin0, bad)["errors"] == ["original_mismatch"]
    )

    # find_code_caves
    caves = validator_find_code_caves([0x90] * 20 + [0x01] + [0xCC] * 8, 8)
    results["find_code_caves"] = (
        len(caves) == 2 and caves[0]["size"] == 20 and caves[1]["size"] == 8
    )

    # assemble_simple
    results["assemble_simple"] = (
        validator_assemble_simple("nop") == [0x90]
        and validator_assemble_simple("ret") == [0xC3]
        and validator_assemble_simple("int3") == [0xCC]
    )

    # diff/patch
    results["delta_roundtrip"] = validator_delta_roundtrip(
        [1, 2, 3], [4, 5, 6, 7]
    )

    # hot_patch
    results["hot_patch_roundtrip"] = validator_hot_patch_roundtrip(
        list(range(16)), 4, [0xAA, 0xBB]
    )

    return results


def main() -> None:
    if not sys.stdin.isatty():
        try:
            req = json.load(sys.stdin)
        except json.JSONDecodeError:
            req = None
        if req:
            fn = _DISPATCH[req["function"]]
            args = req.get("args", [])
            kwargs = req.get("kwargs", {})
            try:
                out = fn(*args, **kwargs)
                print(json.dumps({"ok": True, "result": out}))
            except Exception as e:  # noqa: BLE001
                print(json.dumps({"ok": False, "error": str(e)}))
            return
    # Default: run self-tests
    print(json.dumps({"self_tests": _self_tests()}, indent=2))


if __name__ == "__main__":
    main()
