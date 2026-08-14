"""
Standalone Python validator for rustre-loader-macho crate.

Re-implements core deterministic functions of the crate using only Python stdlib
so outputs can be compared against the Rust crate's results.

No imports of the Rust crate. No MCP calls.

Usage:
    echo '{"fn":"adler32","input":{"data_hex":"deadbeef"}}' | python rustre-loader-macho.py
    python rustre-loader-macho.py            # runs main() self-tests
"""

import json
import math
import struct
import sys
import zlib
import binascii


# ---------------------------------------------------------------------------
# LEB128
# ---------------------------------------------------------------------------
def validator_read_uleb128(data: bytes, pos: int = 0):
    result = 0
    shift = 0
    p = pos
    while True:
        if p >= len(data):
            raise ValueError("uleb128 truncated")
        b = data[p]
        p += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return result, p


def validator_read_sleb128(data: bytes, pos: int = 0):
    result = 0
    shift = 0
    p = pos
    while True:
        if p >= len(data):
            raise ValueError("sleb128 truncated")
        b = data[p]
        p += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if (b & 0x80) == 0:
            if (b & 0x40) != 0:
                result |= -(1 << shift)
            break
    # mask to signed 64-bit
    result &= (1 << 64) - 1
    if result & (1 << 63):
        result -= 1 << 64
    return result, p


# ---------------------------------------------------------------------------
# Checksums / entropy
# ---------------------------------------------------------------------------
def validator_adler32(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF


def validator_byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


# ---------------------------------------------------------------------------
# Integer reads
# ---------------------------------------------------------------------------
def validator_le_u16(data: bytes, off: int = 0) -> int:
    return struct.unpack_from("<H", data, off)[0]


def validator_le_u32(data: bytes, off: int = 0) -> int:
    return struct.unpack_from("<I", data, off)[0]


def validator_le_u64(data: bytes, off: int = 0) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def validator_be_u32(data: bytes, off: int = 0) -> int:
    return struct.unpack_from(">I", data, off)[0]


def validator_rbe64(data: bytes, off: int = 0):
    if off + 8 > len(data):
        return None
    return struct.unpack_from(">Q", data, off)[0]


# ---------------------------------------------------------------------------
# C-string read
# ---------------------------------------------------------------------------
def validator_read_cstring(data: bytes, offset: int = 0):
    if offset >= len(data):
        return None
    end = data.find(b"\x00", offset)
    if end < 0:
        end = len(data)
    try:
        return data[offset:end].decode("utf-8")
    except UnicodeDecodeError:
        return None


# ---------------------------------------------------------------------------
# Fat / universal binary
# ---------------------------------------------------------------------------
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA


def validator_detect_fat(data: bytes) -> bool:
    if len(data) < 4:
        return False
    m = struct.unpack(">I", data[:4])[0]
    return m in (FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64)


def validator_list_arches(data: bytes):
    if not validator_detect_fat(data):
        return []
    magic = struct.unpack(">I", data[:4])[0]
    is64 = magic in (FAT_MAGIC_64, FAT_CIGAM_64)
    nfat = struct.unpack(">I", data[4:8])[0]
    arches = []
    off = 8
    if is64:
        rec = 32
        fmt = ">iiQQII"
    else:
        rec = 20
        fmt = ">iiIII"
    for _ in range(nfat):
        if off + rec > len(data):
            break
        if is64:
            cputype, cpusubtype, offset, size, align, _res = struct.unpack(fmt, data[off:off+rec])
        else:
            cputype, cpusubtype, offset, size, align = struct.unpack(fmt, data[off:off+rec])
        arches.append({
            "cputype": cputype,
            "cpusubtype": cpusubtype,
            "offset": offset,
            "size": size,
            "align": align,
        })
        off += rec
    return arches


def validator_extract_arch(data: bytes, index: int):
    arches = validator_list_arches(data)
    if index < 0 or index >= len(arches):
        return None
    a = arches[index]
    return data[a["offset"]:a["offset"] + a["size"]]


# ---------------------------------------------------------------------------
# FunctionStarts (LC_FUNCTION_STARTS uleb128 deltas)
# ---------------------------------------------------------------------------
def validator_function_starts_parse(data: bytes, base_addr: int):
    out = []
    pos = 0
    addr = base_addr
    while pos < len(data):
        delta, pos = validator_read_uleb128(data, pos)
        if delta == 0:
            break
        addr += delta
        out.append(addr)
    return out


def validator_data_in_code_total(entries):
    return sum(int(e.get("length", 0)) for e in entries)


# ---------------------------------------------------------------------------
# Swift relative pointer resolve
# ---------------------------------------------------------------------------
def validator_resolve_relative_ptr(entry_addr: int, relative: int) -> int:
    # relative is i32; sign-extend if needed
    rel = relative & 0xFFFFFFFF
    if rel & 0x80000000:
        rel -= 1 << 32
    return (entry_addr + rel) & 0xFFFFFFFFFFFFFFFF


# ---------------------------------------------------------------------------
# resolve_vm
# ---------------------------------------------------------------------------
def validator_resolve_vm(vm: int, segments):
    for s in segments:
        vmaddr = int(s["vmaddr"])
        vmsize = int(s["vmsize"])
        fileoff = int(s["fileoff"])
        if vmaddr <= vm < vmaddr + vmsize:
            return (vm - vmaddr) + fileoff
    return None


# ---------------------------------------------------------------------------
# is_swift_mangled / swift_class_hint
# ---------------------------------------------------------------------------
def validator_is_swift_mangled(name: str) -> bool:
    return name.startswith(("_$s", "$s", "_T0"))


def validator_swift_class_hint(mangled: str) -> str:
    # crude: extract first identifier-looking substring after prefix
    if not mangled:
        return ""
    s = mangled
    for p in ("_$s", "$s", "_T0"):
        if s.startswith(p):
            s = s[len(p):]
            break
    out = []
    for ch in s:
        if ch.isalnum() or ch == "_":
            out.append(ch)
        else:
            if out:
                break
    return "".join(out)


# ---------------------------------------------------------------------------
# Notarization ticket magic
# ---------------------------------------------------------------------------
NOTARIZATION_MAGICS = [
    b"AppleTickets",
    b"cdhashes",
]


def validator_has_notarization_ticket_magic(data: bytes) -> bool:
    return any(m in data for m in NOTARIZATION_MAGICS)


# ---------------------------------------------------------------------------
# casts.rs — lossless casts (Python checks bit patterns)
# ---------------------------------------------------------------------------
def validator_u64_to_usize(x: int) -> int:
    return x & ((1 << 64) - 1)


def validator_usize_to_u32(x: int) -> int:
    return x & 0xFFFFFFFF


def validator_u64_to_u32(x: int) -> int:
    return x & 0xFFFFFFFF


def validator_u64_to_u16(x: int) -> int:
    return x & 0xFFFF


def validator_u64_to_u8(x: int) -> int:
    return x & 0xFF


def validator_u32_to_i32(x: int) -> int:
    x &= 0xFFFFFFFF
    if x & 0x80000000:
        x -= 1 << 32
    return x


def validator_u8_to_i8(x: int) -> int:
    x &= 0xFF
    if x & 0x80:
        x -= 0x100
    return x


def validator_i64_to_u64(x: int) -> int:
    return x & ((1 << 64) - 1)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
DISPATCH = {
    "read_uleb128": lambda i: dict(zip(("value", "new_pos"), validator_read_uleb128(bytes.fromhex(i["data_hex"]), i.get("pos", 0)))),
    "read_sleb128": lambda i: dict(zip(("value", "new_pos"), validator_read_sleb128(bytes.fromhex(i["data_hex"]), i.get("pos", 0)))),
    "adler32": lambda i: {"value": validator_adler32(bytes.fromhex(i["data_hex"]))},
    "byte_entropy": lambda i: {"value": validator_byte_entropy(bytes.fromhex(i["data_hex"]))},
    "le_u16": lambda i: {"value": validator_le_u16(bytes.fromhex(i["data_hex"]), i.get("off", 0))},
    "le_u32": lambda i: {"value": validator_le_u32(bytes.fromhex(i["data_hex"]), i.get("off", 0))},
    "le_u64": lambda i: {"value": validator_le_u64(bytes.fromhex(i["data_hex"]), i.get("off", 0))},
    "be_u32": lambda i: {"value": validator_be_u32(bytes.fromhex(i["data_hex"]), i.get("off", 0))},
    "rbe64": lambda i: {"value": validator_rbe64(bytes.fromhex(i["data_hex"]), i.get("off", 0))},
    "read_cstring": lambda i: {"value": validator_read_cstring(bytes.fromhex(i["data_hex"]), i.get("offset", 0))},
    "detect_fat": lambda i: {"value": validator_detect_fat(bytes.fromhex(i["data_hex"]))},
    "list_arches": lambda i: {"value": validator_list_arches(bytes.fromhex(i["data_hex"]))},
    "extract_arch": lambda i: {"value": (validator_extract_arch(bytes.fromhex(i["data_hex"]), i["index"]) or b"").hex()},
    "function_starts_parse": lambda i: {"value": validator_function_starts_parse(bytes.fromhex(i["data_hex"]), i["base_addr"])},
    "data_in_code_total": lambda i: {"value": validator_data_in_code_total(i["entries"])},
    "resolve_relative_ptr": lambda i: {"value": validator_resolve_relative_ptr(i["entry_addr"], i["relative"])},
    "resolve_vm": lambda i: {"value": validator_resolve_vm(i["vm"], i["segments"])},
    "is_swift_mangled": lambda i: {"value": validator_is_swift_mangled(i["name"])},
    "swift_class_hint": lambda i: {"value": validator_swift_class_hint(i["mangled"])},
    "has_notarization_ticket_magic": lambda i: {"value": validator_has_notarization_ticket_magic(bytes.fromhex(i["data_hex"]))},
    "u64_to_usize": lambda i: {"value": validator_u64_to_usize(i["x"])},
    "usize_to_u32": lambda i: {"value": validator_usize_to_u32(i["x"])},
    "u64_to_u32": lambda i: {"value": validator_u64_to_u32(i["x"])},
    "u64_to_u16": lambda i: {"value": validator_u64_to_u16(i["x"])},
    "u64_to_u8": lambda i: {"value": validator_u64_to_u8(i["x"])},
    "u32_to_i32": lambda i: {"value": validator_u32_to_i32(i["x"])},
    "u8_to_i8": lambda i: {"value": validator_u8_to_i8(i["x"])},
    "i64_to_u64": lambda i: {"value": validator_i64_to_u64(i["x"])},
}


def main():
    if not sys.stdin.isatty():
        try:
            req = json.load(sys.stdin)
        except Exception as e:
            print(json.dumps({"error": f"bad json: {e}"}))
            return
        fn = req.get("fn")
        if fn not in DISPATCH:
            print(json.dumps({"error": f"unknown fn '{fn}'", "available": sorted(DISPATCH)}))
            return
        try:
            out = DISPATCH[fn](req.get("input", {}))
        except Exception as e:
            print(json.dumps({"error": str(e)}))
            return
        print(json.dumps({"fn": fn, "output": out}))
        return

    # ---- self tests ----
    results = {}
    results["adler32('abc')"] = validator_adler32(b"abc")  # 38600999
    assert results["adler32('abc')"] == zlib.adler32(b"abc")
    results["uleb128(7F)"] = validator_read_uleb128(bytes.fromhex("7F"))
    results["uleb128(E58E26)"] = validator_read_uleb128(bytes.fromhex("E58E26"))  # 624485
    assert results["uleb128(E58E26)"][0] == 624485
    results["sleb128(7F)"] = validator_read_sleb128(bytes.fromhex("7F"))  # -1
    assert results["sleb128(7F)"][0] == -1
    results["entropy(uniform 256)"] = validator_byte_entropy(bytes(range(256)))  # ~8.0
    assert abs(results["entropy(uniform 256)"] - 8.0) < 1e-9
    results["le_u32"] = validator_le_u32(bytes.fromhex("78563412"))  # 0x12345678
    assert results["le_u32"] == 0x12345678
    results["be_u32"] = validator_be_u32(bytes.fromhex("12345678"))
    assert results["be_u32"] == 0x12345678
    results["read_cstring"] = validator_read_cstring(b"hello\x00world", 0)
    assert results["read_cstring"] == "hello"
    results["detect_fat"] = validator_detect_fat(b"\xCA\xFE\xBA\xBE\x00\x00\x00\x00")
    assert results["detect_fat"] is True
    results["function_starts"] = validator_function_starts_parse(bytes.fromhex("100A00"), 0x1000)
    # delta1=0x10 -> 0x1010, delta2=0x0A -> 0x101A, then 0x00 stops
    assert results["function_starts"] == [0x1010, 0x101A]
    results["resolve_relative_ptr neg"] = validator_resolve_relative_ptr(0x1000, 0xFFFFFFF0)  # -16
    assert results["resolve_relative_ptr neg"] == 0x0FF0
    results["is_swift_mangled"] = validator_is_swift_mangled("_$s4main3FooC")
    assert results["is_swift_mangled"] is True
    results["u32_to_i32(0xFFFFFFFF)"] = validator_u32_to_i32(0xFFFFFFFF)
    assert results["u32_to_i32(0xFFFFFFFF)"] == -1

    print(json.dumps({"self_test": "ok", "samples": {k: str(v) for k, v in results.items()}}, indent=2))


if __name__ == "__main__":
    main()
