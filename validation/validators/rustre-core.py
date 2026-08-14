#!/usr/bin/env python3
"""
Independent Python validator for the `rustre-core` crate.

Reimplements the externally verifiable pure functions of rustre-core using only
the Python stdlib (no calls into the Rust crate, no MCP). Each function is
exposed as `validator_<name>(input) -> output`. The script supports two modes:

  * stdin JSON: {"function": "<name>", "input": <args>} -> {"output": ...}
  * default (no stdin / `--selftest`): runs an internal selftest with fixed
    boundary inputs and prints a JSON summary.

Targets (from validation/reports/rustre-core.md):
  - encode_uleb128 / decode_uleb128
  - encode_sleb128 / decode_sleb128
  - swap_endian_u16 / u32 / u64 / u128
  - endianbuf_write / endianbuf_read (struct-pack/unpack with explicit endian)
  - rva_resolve
  - segment_va_to_file_offset / segment_file_offset_to_va
  - permissions_as_rwx_string
  - memory_protection_to_permissions
  - pass_manager_topological_order (Kahn's algorithm + cycle detection)
"""

from __future__ import annotations

import json
import struct
import sys
from typing import Any, Dict, List, Tuple


# ---------------------------------------------------------------------------
# LEB128 (DWARF unsigned/signed varint)
# ---------------------------------------------------------------------------

def validator_encode_uleb128(value: int) -> bytes:
    if value < 0:
        raise ValueError("uleb128 requires non-negative value")
    out = bytearray()
    v = value & 0xFFFFFFFFFFFFFFFF  # u64 domain
    while True:
        byte = v & 0x7F
        v >>= 7
        if v != 0:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)


def validator_decode_uleb128(buf: bytes, offset: int = 0) -> Tuple[int, int]:
    result = 0
    shift = 0
    consumed = 0
    i = offset
    while True:
        if i >= len(buf):
            raise ValueError("uleb128 truncated")
        byte = buf[i]
        result |= (byte & 0x7F) << shift
        i += 1
        consumed += 1
        if (byte & 0x80) == 0:
            break
        shift += 7
        if shift >= 70:
            raise ValueError("uleb128 too large for u64")
    return result & 0xFFFFFFFFFFFFFFFF, consumed


def validator_encode_sleb128(value: int) -> bytes:
    # Domain: i64
    if value < -(1 << 63) or value >= (1 << 63):
        raise ValueError("sleb128 out of i64 range")
    out = bytearray()
    more = True
    v = value
    while more:
        byte = v & 0x7F
        # arithmetic shift right by 7 (Python's >> is arithmetic for signed ints)
        v >>= 7
        sign_bit = byte & 0x40
        if (v == 0 and sign_bit == 0) or (v == -1 and sign_bit != 0):
            more = False
            out.append(byte)
        else:
            out.append(byte | 0x80)
    return bytes(out)


def validator_decode_sleb128(buf: bytes, offset: int = 0) -> Tuple[int, int]:
    result = 0
    shift = 0
    consumed = 0
    i = offset
    byte = 0
    while True:
        if i >= len(buf):
            raise ValueError("sleb128 truncated")
        byte = buf[i]
        result |= (byte & 0x7F) << shift
        i += 1
        consumed += 1
        shift += 7
        if (byte & 0x80) == 0:
            break
        if shift >= 70:
            raise ValueError("sleb128 too large for i64")
    # sign-extend
    if shift < 64 and (byte & 0x40):
        result |= -(1 << shift)
    # clamp into i64 two's complement range
    if result >= (1 << 63):
        result -= (1 << 64)
    return result, consumed


# ---------------------------------------------------------------------------
# Endian swaps
# ---------------------------------------------------------------------------

def _swap(value: int, nbytes: int) -> int:
    mask = (1 << (nbytes * 8)) - 1
    return int.from_bytes((value & mask).to_bytes(nbytes, "little"), "big")


def validator_swap_endian_u16(v: int) -> int:
    return _swap(v, 2)


def validator_swap_endian_u32(v: int) -> int:
    return _swap(v, 4)


def validator_swap_endian_u64(v: int) -> int:
    return _swap(v, 8)


def validator_swap_endian_u128(v: int) -> int:
    return _swap(v, 16)


# ---------------------------------------------------------------------------
# EndianBuf read/write (mirrors struct.pack/unpack with explicit endian)
# ---------------------------------------------------------------------------

_FMT = {
    ("u16", "little"): "<H", ("u16", "big"): ">H",
    ("u32", "little"): "<I", ("u32", "big"): ">I",
    ("u64", "little"): "<Q", ("u64", "big"): ">Q",
    ("i16", "little"): "<h", ("i16", "big"): ">h",
    ("i32", "little"): "<i", ("i32", "big"): ">i",
    ("i64", "little"): "<q", ("i64", "big"): ">q",
}


def validator_endianbuf_write(kind: str, endian: str, value: int) -> bytes:
    return struct.pack(_FMT[(kind, endian)], value)


def validator_endianbuf_read(kind: str, endian: str, data: bytes) -> int:
    size = struct.calcsize(_FMT[(kind, endian)])
    return struct.unpack(_FMT[(kind, endian)], data[:size])[0]


# ---------------------------------------------------------------------------
# Address translation
# ---------------------------------------------------------------------------

def validator_rva_resolve(base_va: int, rva: int) -> int:
    return (base_va + rva) & 0xFFFFFFFFFFFFFFFF


def validator_segment_va_to_file_offset(va: int, seg_va: int, seg_file_off: int, seg_size: int):
    if va < seg_va or va >= seg_va + seg_size:
        return None
    return seg_file_off + (va - seg_va)


def validator_segment_file_offset_to_va(file_off: int, seg_va: int, seg_file_off: int, seg_size: int):
    if file_off < seg_file_off or file_off >= seg_file_off + seg_size:
        return None
    return seg_va + (file_off - seg_file_off)


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------

# Bitflags: R=1, W=2, X=4
R, W, X = 1, 2, 4


def validator_permissions_as_rwx_string(bits: int) -> str:
    return (
        ("r" if bits & R else "-")
        + ("w" if bits & W else "-")
        + ("x" if bits & X else "-")
    )


def validator_memory_protection_to_permissions(kind: str) -> int:
    """Map an OS-protection enum variant name to rwx bitflags."""
    kind = kind.strip()
    table = {
        "NoAccess": 0,
        "ReadOnly": R,
        "ReadWrite": R | W,
        "ReadExecute": R | X,
        "ReadWriteExecute": R | W | X,
        "ExecuteOnly": X,
        "WriteOnly": W,
        # Linux/Posix-style aliases occasionally used in the crate
        "LinuxRead": R,
        "LinuxReadWrite": R | W,
        "LinuxReadExec": R | X,
        "LinuxReadWriteExec": R | W | X,
        "LinuxNone": 0,
    }
    if kind not in table:
        raise ValueError(f"unknown MemoryProtection variant: {kind}")
    return table[kind]


# ---------------------------------------------------------------------------
# PassManager topological order (Kahn's algorithm + cycle detect)
# ---------------------------------------------------------------------------

def validator_pass_manager_topological_order(
    passes: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """passes: [{"name": str, "deps": [str, ...]}, ...]

    Returns {"order": [...]} on success or {"error": "cycle", "remaining": [...]}.
    Stable order: among ready nodes, pick alphabetically (deterministic).
    """
    names = [p["name"] for p in passes]
    deps: Dict[str, List[str]] = {p["name"]: list(p.get("deps", [])) for p in passes}
    name_set = set(names)
    # validate deps refer to known passes
    for n, ds in deps.items():
        for d in ds:
            if d not in name_set:
                return {"error": f"unknown dependency '{d}' for pass '{n}'"}

    indeg: Dict[str, int] = {n: 0 for n in names}
    rdeps: Dict[str, List[str]] = {n: [] for n in names}
    for n, ds in deps.items():
        for d in ds:
            indeg[n] += 1
            rdeps[d].append(n)

    ready = sorted([n for n, k in indeg.items() if k == 0])
    order: List[str] = []
    while ready:
        ready.sort()
        n = ready.pop(0)
        order.append(n)
        for m in rdeps[n]:
            indeg[m] -= 1
            if indeg[m] == 0:
                ready.append(m)

    if len(order) != len(names):
        remaining = [n for n in names if n not in order]
        return {"error": "cycle", "remaining": remaining}
    return {"order": order}


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

DISPATCH = {
    "encode_uleb128": lambda inp: list(validator_encode_uleb128(inp["value"])),
    "decode_uleb128": lambda inp: list(validator_decode_uleb128(bytes(inp["buf"]), inp.get("offset", 0))),
    "encode_sleb128": lambda inp: list(validator_encode_sleb128(inp["value"])),
    "decode_sleb128": lambda inp: list(validator_decode_sleb128(bytes(inp["buf"]), inp.get("offset", 0))),
    "swap_endian_u16": lambda inp: validator_swap_endian_u16(inp["value"]),
    "swap_endian_u32": lambda inp: validator_swap_endian_u32(inp["value"]),
    "swap_endian_u64": lambda inp: validator_swap_endian_u64(inp["value"]),
    "swap_endian_u128": lambda inp: validator_swap_endian_u128(inp["value"]),
    "endianbuf_write": lambda inp: list(validator_endianbuf_write(inp["kind"], inp["endian"], inp["value"])),
    "endianbuf_read": lambda inp: validator_endianbuf_read(inp["kind"], inp["endian"], bytes(inp["data"])),
    "rva_resolve": lambda inp: validator_rva_resolve(inp["base_va"], inp["rva"]),
    "segment_va_to_file_offset": lambda inp: validator_segment_va_to_file_offset(
        inp["va"], inp["seg_va"], inp["seg_file_off"], inp["seg_size"]),
    "segment_file_offset_to_va": lambda inp: validator_segment_file_offset_to_va(
        inp["file_off"], inp["seg_va"], inp["seg_file_off"], inp["seg_size"]),
    "permissions_as_rwx_string": lambda inp: validator_permissions_as_rwx_string(inp["bits"]),
    "memory_protection_to_permissions": lambda inp: validator_memory_protection_to_permissions(inp["kind"]),
    "pass_manager_topological_order": lambda inp: validator_pass_manager_topological_order(inp["passes"]),
}


# ---------------------------------------------------------------------------
# Selftest with fixed boundary inputs
# ---------------------------------------------------------------------------

def _selftest() -> Dict[str, Any]:
    results: Dict[str, Any] = {}

    # LEB128 boundary values
    uvals = [0, 0x7F, 0x80, 0x3FFF, 0x4000, 0xFFFFFFFF, (1 << 64) - 1]
    leb_u = []
    for v in uvals:
        enc = validator_encode_uleb128(v)
        dec, n = validator_decode_uleb128(enc, 0)
        leb_u.append({"v": v, "enc": enc.hex(), "dec": dec, "n": n, "ok": dec == v and n == len(enc)})
    results["uleb128"] = leb_u

    svals = [0, 1, -1, 63, 64, -64, -65, (1 << 31) - 1, -(1 << 31), (1 << 63) - 1, -(1 << 63)]
    leb_s = []
    for v in svals:
        enc = validator_encode_sleb128(v)
        dec, n = validator_decode_sleb128(enc, 0)
        leb_s.append({"v": v, "enc": enc.hex(), "dec": dec, "n": n, "ok": dec == v and n == len(enc)})
    results["sleb128"] = leb_s

    # Endian swap
    results["swap"] = {
        "u16_0x1234": hex(validator_swap_endian_u16(0x1234)),
        "u32_0x11223344": hex(validator_swap_endian_u32(0x11223344)),
        "u64": hex(validator_swap_endian_u64(0x0102030405060708)),
    }

    # EndianBuf
    results["endianbuf"] = {
        "u32_le": validator_endianbuf_write("u32", "little", 0xDEADBEEF).hex(),
        "u32_be": validator_endianbuf_write("u32", "big", 0xDEADBEEF).hex(),
        "read_u64_le": validator_endianbuf_read("u64", "little", bytes.fromhex("0102030405060708")),
    }

    # Address translation
    results["rva_resolve"] = hex(validator_rva_resolve(0x400000, 0x1234))
    results["seg_va_to_off"] = validator_segment_va_to_file_offset(0x401050, 0x401000, 0x1000, 0x2000)
    results["seg_off_to_va"] = validator_segment_file_offset_to_va(0x1050, 0x401000, 0x1000, 0x2000)
    results["seg_va_out_of_range"] = validator_segment_va_to_file_offset(0x500000, 0x401000, 0x1000, 0x2000)

    # Permissions
    results["perm_rwx"] = {
        "rwx": validator_permissions_as_rwx_string(R | W | X),
        "r-x": validator_permissions_as_rwx_string(R | X),
        "---": validator_permissions_as_rwx_string(0),
    }
    results["memprot"] = {
        "ReadExecute": validator_memory_protection_to_permissions("ReadExecute"),
        "ReadWrite": validator_memory_protection_to_permissions("ReadWrite"),
    }

    # PassManager
    dag = [
        {"name": "a", "deps": []},
        {"name": "b", "deps": ["a"]},
        {"name": "c", "deps": ["a"]},
        {"name": "d", "deps": ["b", "c"]},
    ]
    results["topo_dag"] = validator_pass_manager_topological_order(dag)
    cyc = [
        {"name": "a", "deps": ["b"]},
        {"name": "b", "deps": ["a"]},
    ]
    results["topo_cycle"] = validator_pass_manager_topological_order(cyc)

    return results


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        print(json.dumps(_selftest(), indent=2, default=str))
        return

    # If stdin has data, treat as a single dispatch call.
    if not sys.stdin.isatty():
        raw = sys.stdin.read().strip()
        if raw:
            req = json.loads(raw)
            fn = req["function"]
            if fn not in DISPATCH:
                print(json.dumps({"error": f"unknown function '{fn}'",
                                  "available": sorted(DISPATCH)}))
                sys.exit(2)
            out = DISPATCH[fn](req.get("input", {}))
            print(json.dumps({"function": fn, "output": out}, default=str))
            return

    # Default: selftest
    print(json.dumps(_selftest(), indent=2, default=str))


if __name__ == "__main__":
    main()
