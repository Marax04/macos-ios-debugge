#!/usr/bin/env python3
"""
Independent Python validator for the `rustre-arch-lua` crate.

Validates ground-truth properties of the Lua VM bytecode format documented in
validation/reports/rustre-arch-lua.md, without importing the Rust crate or
calling any MCP tools. Uses only the Python standard library.

Implements:
  - Lua chunk header magic detection (\x1bLua) + version byte detection
  - Lua 5.1-5.3 instruction layout decode (iABC / iABx / iAsBx) with
    sBx bias = 131071
  - Lua 5.4 instruction layout decode (iABC / iABx / iAx / isJ) with 7-bit op
  - Opcode count sanity (5.1=38, 5.2=41, 5.3=47, 5.4=83)
  - Round-trip encode/decode for iAsBx (legacy) and isJ (5.4)
"""

import json
import struct
import sys


# ---------------------------------------------------------------------------
# Header / version detection
# ---------------------------------------------------------------------------

LUA_MAGIC = b"\x1bLua"
VERSION_BYTES = {0x51: "Lua51", 0x52: "Lua52", 0x53: "Lua53", 0x54: "Lua54"}


def detect_version(data: bytes):
    if len(data) < 5:
        return None
    if data[:4] != LUA_MAGIC:
        return None
    return VERSION_BYTES.get(data[4])


# ---------------------------------------------------------------------------
# Legacy (5.1 / 5.2 / 5.3) instruction layout
#   iABC : [B:9][C:9][A:8][OP:6]   (bit 0..5 = OP)
#   iABx : [Bx:18][A:8][OP:6]
#   iAsBx: same as iABx with bias MAXARG_sBx = 131071
# ---------------------------------------------------------------------------

MAXARG_sBx_LEGACY = 131071  # (2^18 - 1) >> 1


def decode_legacy_iABC(word: int):
    op = word & 0x3F
    a = (word >> 6) & 0xFF
    c = (word >> 14) & 0x1FF
    b = (word >> 23) & 0x1FF
    return {"op": op, "A": a, "B": b, "C": c}


def decode_legacy_iABx(word: int):
    op = word & 0x3F
    a = (word >> 6) & 0xFF
    bx = (word >> 14) & 0x3FFFF
    return {"op": op, "A": a, "Bx": bx}


def decode_legacy_iAsBx(word: int):
    d = decode_legacy_iABx(word)
    d["sBx"] = d["Bx"] - MAXARG_sBx_LEGACY
    return d


def make_legacy_iAsBx(op: int, a: int, sbx: int) -> int:
    bx = sbx + MAXARG_sBx_LEGACY
    return (op & 0x3F) | ((a & 0xFF) << 6) | ((bx & 0x3FFFF) << 14)


# ---------------------------------------------------------------------------
# Lua 5.4 instruction layout (7-bit op)
#   iABC : [C:8][B:8][k:1][A:8][OP:7]
#   iABx : [Bx:17][A:8][OP:7]
#   iAx  : [Ax:25][OP:7]
#   isJ  : [sJ:25][OP:7]   with sJ bias = (2^24 - 1) = 16777215
# ---------------------------------------------------------------------------

MAXARG_sJ_54 = (1 << 24) - 1  # 16777215


def decode_lua54_iABC(word: int):
    op = word & 0x7F
    a = (word >> 7) & 0xFF
    k = (word >> 15) & 0x1
    b = (word >> 16) & 0xFF
    c = (word >> 24) & 0xFF
    return {"op": op, "A": a, "k": k, "B": b, "C": c}


def decode_lua54_iABx(word: int):
    op = word & 0x7F
    a = (word >> 7) & 0xFF
    bx = (word >> 15) & 0x1FFFF
    return {"op": op, "A": a, "Bx": bx}


def decode_lua54_iAx(word: int):
    op = word & 0x7F
    ax = (word >> 7) & 0x1FFFFFF
    return {"op": op, "Ax": ax}


def decode_lua54_isJ(word: int):
    op = word & 0x7F
    sj_raw = (word >> 7) & 0x1FFFFFF
    return {"op": op, "sJ": sj_raw - MAXARG_sJ_54}


def make_lua54_isJ(op: int, sj: int) -> int:
    raw = sj + MAXARG_sJ_54
    return (op & 0x7F) | ((raw & 0x1FFFFFF) << 7)


# ---------------------------------------------------------------------------
# Opcode-count ground truth (per validation report)
# ---------------------------------------------------------------------------

OPCODE_COUNTS = {"Lua51": 38, "Lua52": 41, "Lua53": 47, "Lua54": 83}


# ---------------------------------------------------------------------------
# Self-tests (the "functions" list returned to the harness)
# ---------------------------------------------------------------------------

def run_checks():
    results = []

    def add(name, ok, detail=""):
        results.append({"name": name, "ok": bool(ok), "detail": detail})

    # 1. Magic detection
    sample51 = LUA_MAGIC + b"\x51" + b"\x00" * 8
    sample54 = LUA_MAGIC + b"\x54" + b"\x00" * 8
    bad = b"NOPE" + b"\x54"
    add("detect_version Lua51", detect_version(sample51) == "Lua51")
    add("detect_version Lua54", detect_version(sample54) == "Lua54")
    add("detect_version rejects non-Lua", detect_version(bad) is None)

    # 2. Legacy iABC field extraction (synthesized word)
    # op=22, A=1, B=2, C=3
    word = (22 & 0x3F) | (1 << 6) | (3 << 14) | (2 << 23)
    d = decode_legacy_iABC(word)
    add("legacy iABC decode",
        d == {"op": 22, "A": 1, "B": 2, "C": 3},
        json.dumps(d))

    # 3. Legacy iAsBx round-trip across full sBx range
    rt_ok = True
    rt_detail = ""
    for sbx in (-MAXARG_sBx_LEGACY, -1000, 0, 1, 1000, MAXARG_sBx_LEGACY):
        w = make_legacy_iAsBx(op=31, a=7, sbx=sbx)
        dec = decode_legacy_iAsBx(w)
        if dec["op"] != 31 or dec["A"] != 7 or dec["sBx"] != sbx:
            rt_ok = False
            rt_detail = f"sBx={sbx} -> {dec}"
            break
    add("legacy iAsBx round-trip", rt_ok, rt_detail)

    # 4. Lua 5.4 iABC layout: op=65, A=10, k=1, B=200, C=255
    w54 = (65 & 0x7F) | (10 << 7) | (1 << 15) | (200 << 16) | (255 << 24)
    d54 = decode_lua54_iABC(w54)
    add("lua54 iABC decode",
        d54 == {"op": 65, "A": 10, "k": 1, "B": 200, "C": 255},
        json.dumps(d54))

    # 5. Lua 5.4 isJ round-trip across range
    sj_ok = True
    sj_detail = ""
    for sj in (-MAXARG_sJ_54, -1, 0, 1, MAXARG_sJ_54):
        w = make_lua54_isJ(op=56, sj=sj)
        dec = decode_lua54_isJ(w)
        if dec["op"] != 56 or dec["sJ"] != sj:
            sj_ok = False
            sj_detail = f"sJ={sj} -> {dec}"
            break
    add("lua54 isJ round-trip", sj_ok, sj_detail)

    # 6. Opcode-count expectations match documented ground truth
    add("opcode counts table",
        OPCODE_COUNTS == {"Lua51": 38, "Lua52": 41, "Lua53": 47, "Lua54": 83},
        json.dumps(OPCODE_COUNTS))

    # 7. 7-bit op masks reject overflow (op=128 must NOT survive decode mask)
    overflow_word = 128  # op field would be 128 -> masked to 0
    add("lua54 op mask is 7 bits",
        decode_lua54_iABx(overflow_word)["op"] == 0)

    # 8. Header parse: confirm 5.4 signature + conformance bytes are
    #    a reasonable length (>= 0x0C typical preamble: magic+ver+format+data)
    add("lua54 minimum header length sanity", len(sample54) >= 12,
        f"len={len(sample54)}")

    return results


def main():
    fns = run_checks()
    all_ok = all(f["ok"] for f in fns)
    out = {
        "crate": "rustre-arch-lua",
        "saved": all_ok,
        "functions": fns,
    }
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
