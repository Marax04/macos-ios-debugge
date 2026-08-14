#!/usr/bin/env python3
"""
Standalone validator for rustre-symbols-codeview.

Reimplements minimal CodeView parsing (CV symbol records, .debug$S subsections,
type-record walker, GUID-to-string) in pure Python (stdlib only) to cross-check
the Rust crate's outputs.

Public validator functions:
  validator_guid_to_string(guid16)          -> "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}"
  validator_parse_cv_symbols(data_bytes)    -> [{kind, name, offset, segment, type_index}]
  validator_parse_debug_s(section_bytes)    -> [{kind, name, offset, segment}]
  validator_parse_cv_type_records(data)     -> [{leaf, length}]
  validator_walk_records(data, header_fmt)  -> list of (rec_type, payload)
  validator_cv_symbol_is_sane(name)         -> bool
  validator_primitive_type(index)           -> {name, size}

Usage:
  echo {"fn":"parse_cv_symbols","args":{"hex":"..."}} | python rustre-symbols-codeview.py
  python rustre-symbols-codeview.py            # runs main() with synthesised inputs
"""

import json
import os
import struct
import sys

# ---------- CV symbol record types ----------
S_END        = 0x0006
S_OEM        = 0x0404
S_REGISTER   = 0x1106
S_CONSTANT   = 0x1107
S_UDT        = 0x1108
S_LDATA32    = 0x110C
S_GDATA32    = 0x110D
S_PUB32      = 0x110E
S_LPROC32    = 0x110F
S_GPROC32    = 0x1110
S_REGREL32   = 0x1111
S_LTHREAD32  = 0x1112
S_GTHREAD32  = 0x1113
S_PROCREF    = 0x1125
S_LPROCREF   = 0x1127
S_LABEL32    = 0x1105
S_THUNK32    = 0x1102
S_INLINESITE = 0x114D
S_PROC_ID_END = 0x114F

# .debug$S subsection kinds
DEBUG_S_SYMBOLS    = 0xF1
DEBUG_S_LINES      = 0xF2
DEBUG_S_STRINGTBL  = 0xF3
DEBUG_S_FILECHKSMS = 0xF4
DEBUG_S_FRAMEDATA  = 0xF5


class CvError(Exception):
    pass


# ---------- helpers ----------
def _as_bytes(x):
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if isinstance(x, str):
        return bytes.fromhex(x)
    raise CvError("expected bytes or hex string")


def _read_cstr(buf, off):
    nz = buf.find(b"\x00", off)
    if nz < 0:
        return buf[off:].decode("utf-8", "replace"), len(buf)
    return buf[off:nz].decode("utf-8", "replace"), nz + 1


def _kind_for(rec):
    if rec in (S_LPROC32, S_GPROC32):
        return "Function"
    if rec in (S_GDATA32, S_LDATA32, S_GTHREAD32, S_LTHREAD32):
        return "Data"
    if rec == S_PUB32:
        return "Public"
    if rec == S_LABEL32:
        return "Label"
    if rec == S_THUNK32:
        return "Thunk"
    if rec == S_UDT:
        return "Udt"
    if rec == S_CONSTANT:
        return "Constant"
    if rec == S_REGREL32:
        return "RegRel"
    return "Other"


# ---------- GUID ----------
def validator_guid_to_string(guid16):
    g = _as_bytes(guid16)
    if len(g) != 16:
        raise CvError("guid must be 16 bytes")
    d1 = struct.unpack_from("<I", g, 0)[0]
    d2 = struct.unpack_from("<H", g, 4)[0]
    d3 = struct.unpack_from("<H", g, 6)[0]
    d4 = g[8:10]
    d5 = g[10:16]
    return "{{{:08X}-{:04X}-{:04X}-{}-{}}}".format(
        d1, d2, d3, d4.hex().upper(), d5.hex().upper())


# ---------- generic record walker (length-prefixed 2-byte length + 2-byte kind) ----------
def validator_walk_records(data):
    """Yield (rec_type, payload_bytes). length excludes its own 2 bytes."""
    data = _as_bytes(data)
    i = 0
    n = len(data)
    out = []
    while i + 4 <= n:
        length, rec = struct.unpack_from("<HH", data, i)
        if length < 2 or i + 2 + length > n:
            break
        payload = data[i + 4: i + 2 + length]
        out.append((rec, payload))
        i += 2 + length
    return out


# ---------- CV symbol parsing ----------
def validator_parse_cv_symbols(data):
    data = _as_bytes(data)
    out = []
    for rec, payload in validator_walk_records(data):
        entry = {"kind": _kind_for(rec), "rec": rec}
        if rec == S_PUB32 and len(payload) >= 10:
            flags, offset, segment = struct.unpack_from("<IIH", payload, 0)
            name, _ = _read_cstr(payload, 10)
            entry.update(name=name, offset=offset, segment=segment, flags=flags)
        elif rec in (S_GPROC32, S_LPROC32) and len(payload) >= 35:
            (_p, _e, _n, plen, _ds, _de, type_index,
             offset, segment, _f) = struct.unpack_from("<IIIIIIIIHB", payload, 0)
            name, _ = _read_cstr(payload, 35)
            entry.update(name=name, offset=offset, segment=segment,
                         type_index=type_index, proc_length=plen)
        elif rec in (S_GDATA32, S_LDATA32) and len(payload) >= 10:
            type_index, offset, segment = struct.unpack_from("<IIH", payload, 0)
            name, _ = _read_cstr(payload, 10)
            entry.update(name=name, offset=offset, segment=segment,
                         type_index=type_index)
        elif rec in (S_GTHREAD32, S_LTHREAD32) and len(payload) >= 10:
            type_index, offset, segment = struct.unpack_from("<IIH", payload, 0)
            name, _ = _read_cstr(payload, 10)
            entry.update(name=name, offset=offset, segment=segment,
                         type_index=type_index)
        elif rec == S_UDT and len(payload) >= 4:
            (type_index,) = struct.unpack_from("<I", payload, 0)
            name, _ = _read_cstr(payload, 4)
            entry.update(name=name, type_index=type_index)
        elif rec == S_LABEL32 and len(payload) >= 7:
            offset, segment, _flags = struct.unpack_from("<IHB", payload, 0)
            name, _ = _read_cstr(payload, 7)
            entry.update(name=name, offset=offset, segment=segment)
        elif rec == S_REGREL32 and len(payload) >= 10:
            stk_off, type_index, reg = struct.unpack_from("<IIH", payload, 0)
            name, _ = _read_cstr(payload, 10)
            entry.update(name=name, stack_offset=stk_off,
                         type_index=type_index, register=reg)
        elif rec == S_CONSTANT and len(payload) >= 6:
            type_index, value = struct.unpack_from("<IH", payload, 0)
            name, _ = _read_cstr(payload, 6)
            entry.update(name=name, type_index=type_index, value=value)
        elif rec == S_END or rec == S_PROC_ID_END:
            entry.update(name="")
        else:
            entry["raw_len"] = len(payload)
        out.append(entry)
    return out


# ---------- .debug$S parser ----------
def validator_parse_debug_s(section):
    section = _as_bytes(section)
    if len(section) < 4:
        return []
    sig = struct.unpack_from("<I", section, 0)[0]
    if sig != 4:
        # CV signature must be CV_SIGNATURE_C13 (=4)
        return []
    i = 4
    n = len(section)
    out = []
    while i + 8 <= n:
        kind, length = struct.unpack_from("<II", section, i)
        i += 8
        if i + length > n:
            break
        sub = section[i: i + length]
        if kind == DEBUG_S_SYMBOLS:
            out.extend(validator_parse_cv_symbols(sub))
        # advance + align to 4
        i += length
        i = (i + 3) & ~3
    return out


# ---------- CV type records ----------
def validator_parse_cv_type_records(data):
    data = _as_bytes(data)
    out = []
    for rec, payload in validator_walk_records(data):
        out.append({"leaf": rec, "length": len(payload) + 2})
    return out


# ---------- primitive type decoding ----------
_PRIM = {
    0x0003: ("void", 0),
    0x0010: ("char", 1),
    0x0020: ("unsigned char", 1),
    0x0070: ("char", 1),
    0x0071: ("wchar_t", 2),
    0x0011: ("short", 2),
    0x0021: ("unsigned short", 2),
    0x0072: ("int16", 2),
    0x0073: ("uint16", 2),
    0x0012: ("long", 4),
    0x0022: ("unsigned long", 4),
    0x0074: ("int32", 4),
    0x0075: ("uint32", 4),
    0x0013: ("int64", 8),
    0x0023: ("uint64", 8),
    0x0076: ("int64", 8),
    0x0077: ("uint64", 8),
    0x0040: ("float", 4),
    0x0041: ("double", 8),
}


def validator_primitive_type(index):
    base = index & 0x0FFF
    mode = (index >> 8) & 0x7
    # Direct primitive form
    if index in _PRIM:
        name, size = _PRIM[index]
    elif base in _PRIM:
        name, size = _PRIM[base]
    else:
        return {"name": "unknown(0x{:04X})".format(index), "size": 0,
                "pointer": False}
    # mode 1..6 = pointer forms
    if mode in (1, 2, 3, 4, 5, 6):
        return {"name": name + "*", "size": 8 if mode >= 4 else 4,
                "pointer": True}
    return {"name": name, "size": size, "pointer": False}


# ---------- sanity ----------
def validator_cv_symbol_is_sane(name):
    if not isinstance(name, str) or not name:
        return False
    if len(name) > 4096:
        return False
    bad = set("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f")
    return not any(c in bad for c in name)


# ---------- synthetic builders for self-test ----------
def _build_pub32(name, offset, segment, flags=0):
    n = name.encode("utf-8") + b"\x00"
    payload = struct.pack("<IIH", flags, offset, segment) + n
    # pad to even alignment
    while (len(payload) + 4) % 4 != 0:
        payload += b"\x00"
    length = len(payload) + 2
    return struct.pack("<HH", length, S_PUB32) + payload


def _build_gproc32(name, offset, segment, type_index=0, plen=0x100):
    n = name.encode("utf-8") + b"\x00"
    payload = struct.pack("<IIIIIIIIHB",
                          0, 0, 0, plen, 0, 0, type_index,
                          offset, segment, 0) + n
    while (len(payload) + 4) % 4 != 0:
        payload += b"\x00"
    length = len(payload) + 2
    return struct.pack("<HH", length, S_GPROC32) + payload


# ---------- Dispatcher ----------
FUNCS = {
    "guid_to_string":      lambda a: validator_guid_to_string(a["guid"]),
    "parse_cv_symbols":    lambda a: validator_parse_cv_symbols(a.get("hex", a.get("data", ""))),
    "parse_debug_s":       lambda a: validator_parse_debug_s(a.get("hex", a.get("data", ""))),
    "parse_cv_type_records": lambda a: validator_parse_cv_type_records(a.get("hex", a.get("data", ""))),
    "walk_records":        lambda a: [{"rec": r, "len": len(p)} for r, p in
                                      validator_walk_records(a.get("hex", a.get("data", "")))],
    "primitive_type":      lambda a: validator_primitive_type(int(a["index"])),
    "cv_symbol_is_sane":   lambda a: validator_cv_symbol_is_sane(a["name"]),
}


def main():
    if not sys.stdin.isatty():
        try:
            req = json.load(sys.stdin)
        except Exception:
            req = None
        if req:
            fn = req.get("fn")
            args = req.get("args", {})
            try:
                out = FUNCS[fn](args)
                json.dump({"ok": True, "result": out}, sys.stdout, default=str)
            except Exception as e:
                json.dump({"ok": False, "error": str(e)}, sys.stdout)
            return

    # Synthetic smoke test
    blob = (_build_pub32("?foo@@YAHXZ", 0x1234, 1, flags=2)
            + _build_gproc32("main", 0x2000, 1, type_index=0x1000, plen=0x80)
            + _build_pub32("_ZN4core3fmt9Formatter3padE", 0x3000, 1))
    syms = validator_parse_cv_symbols(blob)
    # Wrap in debug$S
    sub_hdr = struct.pack("<II", DEBUG_S_SYMBOLS, len(blob))
    cv_sig = struct.pack("<I", 4)
    section = cv_sig + sub_hdr + blob
    debug_s = validator_parse_debug_s(section)

    out = {
        "guid_fmt": validator_guid_to_string(
            bytes.fromhex("0102030405060708090a0b0c0d0e0f10")),
        "syms_count": len(syms),
        "syms": syms,
        "debug_s_count": len(debug_s),
        "prim_int32": validator_primitive_type(0x0074),
        "prim_ptr_int32": validator_primitive_type(0x0674),
        "sane_ok": validator_cv_symbol_is_sane("?foo@@YAHXZ"),
        "sane_bad": validator_cv_symbol_is_sane("a\x01b"),
    }
    baseline_pdb = r"C:\Users\Fra\Desktop\RustRE\samples\cargo-zyphora.pdb"
    out["baseline_pdb_exists"] = os.path.exists(baseline_pdb)
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    main()
