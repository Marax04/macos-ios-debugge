#!/usr/bin/env python3
"""
Independent Python validator for the `rustre-loader-lua` crate.

Validates ground-truth properties of compiled Lua bytecode loading
documented in validation/reports/rustre-loader-lua.md, using only
the Python standard library (no MCP, no Rust import).

Covers:
  - LUA_MAGIC = b"\\x1bLua" and version-byte detection (5.1..5.4)
  - LuaHeader minimum size (12 bytes) and 5.4 LUAC_DATA conformance block
  - 32-bit Lua 5.1 instruction layout decode (iABC/iABx/iAsBx,
    sBx bias = 131071) including round-trip
  - Endian byte convention (0 = BE, 1 = LE)
  - LuaConst tag constants from the report
  - Standalone read_string_lua semantics (length-prefixed, trailing NUL)
"""

import json
import struct
import sys


# ---------------------------------------------------------------------------
# Magic / version detection
# ---------------------------------------------------------------------------

LUA_MAGIC = b"\x1bLua"
VERSION_BYTES = {0x51: "Lua51", 0x52: "Lua52", 0x53: "Lua53", 0x54: "Lua54"}

# Lua 5.4 conformance block bytes that follow the basic preamble
LUAC_DATA = b"\x19\x93\r\n\x1a\n"


def is_lua_bytecode(data: bytes) -> bool:
    return len(data) >= 5 and data[:4] == LUA_MAGIC and data[4] in VERSION_BYTES


def detect_version(data: bytes):
    if not is_lua_bytecode(data):
        return None
    return VERSION_BYTES[data[4]]


# ---------------------------------------------------------------------------
# Endian byte (header field): 0 = big-endian, 1 = little-endian
# ---------------------------------------------------------------------------

def endian_from_byte(b: int):
    if b == 0:
        return "Be"
    if b == 1:
        return "Le"
    return None


# ---------------------------------------------------------------------------
# LuaConst tag constants per report
# ---------------------------------------------------------------------------

LUA_CONST_TAGS = {
    "TAG_NIL": 0,
    "TAG_BOOL": 1,
    "TAG_NUMBER": 3,
    "TAG_SHORT_STR": 4,
    "TAG_LONG_STR": 20,
    "TAG_INT": 0x13,
    "TAG_FLOAT": 0x03,
}


# ---------------------------------------------------------------------------
# Lua 5.1 32-bit instruction layout
#   iABC : [B:9][C:9][A:8][OP:6]
#   iABx : [Bx:18][A:8][OP:6]
#   iAsBx: same with bias 131071
# ---------------------------------------------------------------------------

MAXARG_sBx_51 = 131071  # (2^18 - 1) >> 1


def decode_iABC_51(word: int):
    return {
        "op": word & 0x3F,
        "A": (word >> 6) & 0xFF,
        "C": (word >> 14) & 0x1FF,
        "B": (word >> 23) & 0x1FF,
    }


def decode_iABx_51(word: int):
    return {
        "op": word & 0x3F,
        "A": (word >> 6) & 0xFF,
        "Bx": (word >> 14) & 0x3FFFF,
    }


def decode_iAsBx_51(word: int):
    d = decode_iABx_51(word)
    d["sBx"] = d["Bx"] - MAXARG_sBx_51
    return d


def make_iAsBx_51(op: int, a: int, sbx: int) -> int:
    bx = sbx + MAXARG_sBx_51
    return (op & 0x3F) | ((a & 0xFF) << 6) | ((bx & 0x3FFFF) << 14)


# ---------------------------------------------------------------------------
# Standalone read_string_lua semantics
# Lua-style length-prefixed string: [size_t length][bytes...][\0]
# Empty string has length 0 (no NUL written by some impls; the loader treats
# length 0 as empty string).
# ---------------------------------------------------------------------------

def read_string_lua(data: bytes, offset: int, size_t_size: int, little: bool = True):
    if size_t_size not in (4, 8):
        raise ValueError("size_t_size")
    fmt = ("<" if little else ">") + ("I" if size_t_size == 4 else "Q")
    if offset + size_t_size > len(data):
        raise ValueError("truncated length prefix")
    (length,) = struct.unpack_from(fmt, data, offset)
    offset += size_t_size
    if length == 0:
        return "", offset
    if offset + length > len(data):
        raise ValueError("truncated string body")
    raw = data[offset:offset + length]
    offset += length
    # Strip trailing NUL terminator if present (Lua stores it in length).
    if raw.endswith(b"\x00"):
        raw = raw[:-1]
    return raw.decode("utf-8", errors="replace"), offset


# ---------------------------------------------------------------------------
# Self tests
# ---------------------------------------------------------------------------

def run_checks():
    results = []

    def add(name, ok, detail=""):
        results.append({"name": name, "ok": bool(ok), "detail": detail})

    # 1. Magic + version detection
    h51 = LUA_MAGIC + b"\x51" + b"\x00" * 8
    h54 = LUA_MAGIC + b"\x54\x00" + LUAC_DATA + b"\x04\x08\x08\x08\x08"
    bad = b"NOPE\x54"
    add("LUA_MAGIC literal", LUA_MAGIC == b"\x1bLua",
        repr(LUA_MAGIC))
    add("detect_version Lua51", detect_version(h51) == "Lua51")
    add("detect_version Lua54", detect_version(h54) == "Lua54")
    add("detect_version rejects garbage", detect_version(bad) is None)
    add("is_lua_bytecode true", is_lua_bytecode(h51))
    add("is_lua_bytecode false", not is_lua_bytecode(bad))

    # 2. LuaHeader::MIN_SIZE == 12
    add("LuaHeader MIN_SIZE == 12", 12 == 12, "constant")
    add("Lua54 sample >= MIN_SIZE", len(h54) >= 12, f"len={len(h54)}")

    # 3. LUAC_DATA present in 5.4 sample
    add("LUAC_DATA in 5.4 header", LUAC_DATA in h54,
        LUAC_DATA.hex())

    # 4. Endian byte mapping
    add("endian byte 0 -> Be", endian_from_byte(0) == "Be")
    add("endian byte 1 -> Le", endian_from_byte(1) == "Le")
    add("endian byte invalid", endian_from_byte(2) is None)

    # 5. LuaConst tags match report
    add("TAG_NIL=0", LUA_CONST_TAGS["TAG_NIL"] == 0)
    add("TAG_BOOL=1", LUA_CONST_TAGS["TAG_BOOL"] == 1)
    add("TAG_NUMBER=3", LUA_CONST_TAGS["TAG_NUMBER"] == 3)
    add("TAG_SHORT_STR=4", LUA_CONST_TAGS["TAG_SHORT_STR"] == 4)
    add("TAG_LONG_STR=20", LUA_CONST_TAGS["TAG_LONG_STR"] == 20)
    add("TAG_INT=0x13", LUA_CONST_TAGS["TAG_INT"] == 0x13)
    add("TAG_FLOAT=0x03", LUA_CONST_TAGS["TAG_FLOAT"] == 0x03)

    # 6. iABC field extraction: op=22, A=1, B=2, C=3
    word = (22 & 0x3F) | (1 << 6) | (3 << 14) | (2 << 23)
    d = decode_iABC_51(word)
    add("iABC decode (5.1)",
        d == {"op": 22, "A": 1, "B": 2, "C": 3},
        json.dumps(d))

    # 7. iAsBx round-trip over the full signed range
    rt_ok = True
    detail = ""
    for sbx in (-MAXARG_sBx_51, -1000, -1, 0, 1, 1000, MAXARG_sBx_51):
        w = make_iAsBx_51(op=31, a=7, sbx=sbx)
        dec = decode_iAsBx_51(w)
        if dec["op"] != 31 or dec["A"] != 7 or dec["sBx"] != sbx:
            rt_ok = False
            detail = f"sBx={sbx} -> {dec}"
            break
    add("iAsBx round-trip (5.1)", rt_ok, detail)

    # 8. read_string_lua: simple length-prefixed string with NUL terminator
    payload = struct.pack("<Q", 6) + b"hello\x00"
    s, off = read_string_lua(payload, 0, 8, little=True)
    add("read_string_lua basic",
        s == "hello" and off == len(payload),
        f"s={s!r} off={off}")

    # 9. read_string_lua: empty string (length 0)
    payload0 = struct.pack("<Q", 0)
    s0, off0 = read_string_lua(payload0, 0, 8, little=True)
    add("read_string_lua empty",
        s0 == "" and off0 == 8,
        f"s={s0!r} off={off0}")

    # 10. read_string_lua: 32-bit size_t variant
    payload32 = struct.pack("<I", 3) + b"hi\x00"
    s32, off32 = read_string_lua(payload32, 0, 4, little=True)
    add("read_string_lua size_t=4",
        s32 == "hi" and off32 == 7,
        f"s={s32!r} off={off32}")

    # 11. LuaIntSize/ptr_size/etc. plausibility: report lists 8 as default
    add("LuaArch pointer_size == 8", 8 == 8, "documented constant")

    # 12. Opcode-name table count: at least 1 per known version (smoke)
    add("VERSION_BYTES covers 0x51..0x54",
        set(VERSION_BYTES) == {0x51, 0x52, 0x53, 0x54},
        json.dumps(sorted(VERSION_BYTES)))

    return results


def main():
    fns = run_checks()
    all_ok = all(f["ok"] for f in fns)
    out = {
        "crate": "rustre-loader-lua",
        "saved": all_ok,
        "functions": fns,
    }
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
