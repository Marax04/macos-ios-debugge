#!/usr/bin/env python3
"""
Standalone validator for the rustre-symbols-stabs crate.

Pure-Python (stdlib only) reimplementation of the deterministic, externally
testable behaviour described in reports/rustre-symbols-stabs.md:

  * 12-byte StabRecord parsing (little- and big-endian)
  * StabType / StabsType name + category tables
  * StabTypeCode classification (function/global/static/parameter/typedef/...)
  * StabsTypeParser.parse_descriptor for (n,m), *T, ar..., s..., e...
  * LineNumberTable: sorted insertion + binary-search lookup
  * StabsStringTable: intern -> stable offset, get(offset)
  * StabsParser.process: build FunctionInfo / globals / line table from records

Usage:
    echo '{"fn":"parse_records","stab_hex":"...","str_hex":"...","be":false}' \
        | python rustre-symbols-stabs.py
    python rustre-symbols-stabs.py        # built-in self-tests
"""

import bisect
import json
import struct
import sys
from typing import Any


# ---------------------------------------------------------------------------
# Stab type table — canonical N_ codes from the report
# ---------------------------------------------------------------------------

_STAB_NAMES = {
    0x00: "N_UNDF",
    0x20: "N_GSYM",
    0x22: "N_FNAME",
    0x24: "N_FUN",
    0x26: "N_STSYM",
    0x28: "N_LCSYM",
    0x2A: "N_MAIN",
    0x2C: "N_ROSYM",
    0x30: "N_PC",
    0x38: "N_NSYMS",
    0x3A: "N_NOMAP",
    0x3C: "N_OBJ",
    0x40: "N_OPT",
    0x42: "N_RSYM",
    0x44: "N_SLINE",
    0x46: "N_DSLINE",
    0x48: "N_BSLINE",
    0x4A: "N_DEFD",
    0x4C: "N_FLINE",
    0x4E: "N_EHDECL",
    0x50: "N_CATCH",
    0x60: "N_SSYM",
    0x62: "N_ENDM",
    0x64: "N_SO",
    0x66: "N_OSO",
    0x6C: "N_ALIAS",
    0x80: "N_LSYM",
    0x82: "N_BINCL",
    0x84: "N_SOL",
    0xA0: "N_PSYM",
    0xA2: "N_EINCL",
    0xA4: "N_ENTRY",
    0xC0: "N_LBRAC",
    0xC2: "N_EXCL",
    0xC4: "N_SCOPE",
    0xE0: "N_RBRAC",
    0xE2: "N_BCOMM",
    0xE4: "N_ECOMM",
    0xE8: "N_ECOML",
    0xF8: "N_NBLCS",
}

_SYMBOL_TYPES = {0x20, 0x22, 0x24, 0x26, 0x28, 0x2C, 0x42, 0x80, 0xA0}
_SOURCE_FILE_TYPES = {0x64, 0x84}
_LINE_TYPES = {0x44, 0x46, 0x48, 0x4C}
_SCOPE_TYPES = {0xC0, 0xE0}


def stab_name(b: int) -> str:
    return _STAB_NAMES.get(b & 0xFF, "Unknown")


def stab_category(b: int) -> str:
    if b in _SYMBOL_TYPES:
        return "symbol"
    if b in _SOURCE_FILE_TYPES:
        return "source_file"
    if b in _LINE_TYPES:
        return "line_number"
    if b in _SCOPE_TYPES:
        return "scope_bracket"
    return "other"


# ---------------------------------------------------------------------------
# Record parsing — 12 bytes: strx(u32) type(u8) other(u8) desc(u16) value(u32)
# ---------------------------------------------------------------------------

def _read_cstring(buf: bytes, off: int) -> str:
    if off >= len(buf):
        return ""
    end = buf.find(b"\x00", off)
    if end < 0:
        end = len(buf)
    try:
        return buf[off:end].decode("utf-8", errors="replace")
    except Exception:
        return ""


def parse_records(stab: bytes, stabstr: bytes, be: bool = False) -> list[dict]:
    fmt = ">IBBHI" if be else "<IBBHI"
    out: list[dict] = []
    n = len(stab) // 12
    for i in range(n):
        chunk = stab[i * 12:(i + 1) * 12]
        if len(chunk) < 12:
            break
        strx, ntype, nother, ndesc, value = struct.unpack(fmt, chunk)
        s = _read_cstring(stabstr, strx) if strx else ""
        out.append({
            "strx": strx,
            "stab_type": ntype,
            "type_name": stab_name(ntype),
            "category": stab_category(ntype),
            "other": nother,
            "desc": ndesc,
            "value": value,
            "string": s,
        })
    return out


def symbol_name(record_string: str) -> str:
    """Symbol name = string up to first ':' (STABS convention)."""
    i = record_string.find(":")
    return record_string if i < 0 else record_string[:i]


def type_descriptor(record_string: str) -> str:
    """Descriptor = string after first ':'."""
    i = record_string.find(":")
    return "" if i < 0 else record_string[i + 1:]


# ---------------------------------------------------------------------------
# StabTypeCode — descriptor classification by first character
# ---------------------------------------------------------------------------

_TYPE_CODE_MAP = {
    "f": "Function",
    "F": "GlobalFunction",
    "G": "GlobalVar",
    "S": "StaticVar",
    "V": "StaticVar",      # file-static
    "r": "RegisterVar",
    "p": "Parameter",
    "t": "Typedef",
    "T": "Tag",
    "a": "VarArray",
}


def classify_descriptor(desc: str) -> str:
    if not desc:
        return "Other"
    return _TYPE_CODE_MAP.get(desc[0], f"Other({desc[0]})")


# ---------------------------------------------------------------------------
# StabsTypeParser — minimal descriptor parser
# ---------------------------------------------------------------------------

_PRIMITIVE_TABLE = {
    "(0,1)": {"kind": "int",   "name": "int",            "size": 4},
    "(0,2)": {"kind": "int",   "name": "char",           "size": 1},
    "(0,3)": {"kind": "int",   "name": "short",          "size": 2},
    "(0,4)": {"kind": "int",   "name": "long",           "size": 8},
    "(0,5)": {"kind": "uint",  "name": "unsigned int",   "size": 4},
    "(0,6)": {"kind": "uint",  "name": "unsigned char",  "size": 1},
    "(0,7)": {"kind": "uint",  "name": "unsigned short", "size": 2},
    "(0,8)": {"kind": "uint",  "name": "unsigned long",  "size": 8},
    "(0,12)": {"kind": "float", "name": "float",  "size": 4},
    "(0,13)": {"kind": "float", "name": "double", "size": 8},
    "(0,15)": {"kind": "void",  "name": "void",   "size": 0},
}


class StabsTypeParser:
    def __init__(self) -> None:
        self.table: dict[str, dict] = dict(_PRIMITIVE_TABLE)

    def register(self, type_num: str, info: dict) -> None:
        self.table[type_num] = info

    def lookup(self, type_num: str) -> dict | None:
        return self.table.get(type_num)

    def __len__(self) -> int:
        return len(self.table)

    def is_empty(self) -> bool:
        return not self.table

    def parse_descriptor(self, desc: str) -> dict:
        if not desc:
            return {"kind": "unknown", "name": "?"}
        c = desc[0]
        if c == "(":
            end = desc.find(")")
            if end < 0:
                return {"kind": "unknown", "name": desc}
            key = desc[:end + 1]
            found = self.table.get(key)
            return found if found is not None else {"kind": "ref", "name": key}
        if c == "*":
            inner = self.parse_descriptor(desc[1:])
            return {"kind": "pointer", "name": f"*{inner.get('name','?')}", "to": inner}
        if desc.startswith("ar"):
            return {"kind": "array", "name": "array", "raw": desc}
        if c == "s":
            return {"kind": "struct", "name": "struct", "raw": desc}
        if c == "u":
            return {"kind": "union", "name": "union", "raw": desc}
        if c == "e":
            return {"kind": "enum", "name": "enum", "raw": desc}
        return {"kind": "other", "name": desc}


# ---------------------------------------------------------------------------
# LineNumberTable
# ---------------------------------------------------------------------------

class LineNumberTable:
    def __init__(self) -> None:
        self.entries: list[dict] = []
        self._sorted = True

    def add(self, address: int, line: int, file: str) -> None:
        self.entries.append({"address": int(address), "line": int(line), "file": file})
        self._sorted = False

    def sort(self) -> None:
        self.entries.sort(key=lambda e: e["address"])
        self._sorted = True

    def lookup(self, addr: int) -> dict | None:
        if not self._sorted:
            self.sort()
        keys = [e["address"] for e in self.entries]
        i = bisect.bisect_right(keys, addr) - 1
        if i < 0:
            return None
        return self.entries[i]

    def __len__(self) -> int:
        return len(self.entries)

    def is_empty(self) -> bool:
        return not self.entries


# ---------------------------------------------------------------------------
# StabsStringTable — intern -> offset, get(offset) -> str
# ---------------------------------------------------------------------------

class StabsStringTable:
    def __init__(self) -> None:
        # STABS string tables start with a NUL byte; offset 0 == empty string.
        self.buf = bytearray(b"\x00")
        self.index: dict[str, int] = {"": 0}

    def intern(self, s: str) -> int:
        if s in self.index:
            return self.index[s]
        off = len(self.buf)
        self.buf.extend(s.encode("utf-8"))
        self.buf.append(0)
        self.index[s] = off
        return off

    def get(self, offset: int) -> str:
        return _read_cstring(bytes(self.buf), offset)

    def as_bytes(self) -> bytes:
        return bytes(self.buf)

    def __len__(self) -> int:
        return len(self.buf)

    def is_empty(self) -> bool:
        return len(self.buf) <= 1


# ---------------------------------------------------------------------------
# StabsParser high-level pipeline (subset matching the report API)
# ---------------------------------------------------------------------------

def parser_process(records: list[dict], image_base: int = 0) -> dict:
    """Mirror of StabsParser::process.

    Walks records once, building:
      - functions:  N_FUN  -> FunctionInfo {name, address, source_file, locals, params, start_line}
      - globals:    N_GSYM / N_STSYM
      - line_table: N_SLINE (address = current_fn_addr + value, file = current_so/sol)
      - locals:     N_LSYM, N_RSYM attached to the open function
      - params:     N_PSYM attached to the open function
    """
    functions: list[dict] = []
    globals_: list[dict] = []
    line_table = LineNumberTable()
    cur_file: str | None = None
    cur_fn: dict | None = None

    for r in records:
        t = r["stab_type"]
        s = r["string"]
        name = symbol_name(s)
        desc = type_descriptor(s)

        if t in (0x64, 0x84):  # N_SO / N_SOL
            cur_file = s or cur_file
            continue

        if t == 0x24:  # N_FUN
            if not name:  # end-of-function marker
                cur_fn = None
                continue
            cur_fn = {
                "name": name,
                "address": (image_base + r["value"]) & 0xFFFFFFFFFFFFFFFF,
                "source_file": cur_file,
                "locals": [],
                "parameters": [],
                "start_line": r["desc"],
                "descriptor": desc,
            }
            functions.append(cur_fn)
            continue

        if t in (0x20, 0x26):  # N_GSYM / N_STSYM
            globals_.append({
                "name": name,
                "address": (image_base + r["value"]) & 0xFFFFFFFFFFFFFFFF,
                "kind": "global" if t == 0x20 else "static",
                "descriptor": desc,
            })
            continue

        if t == 0x44:  # N_SLINE
            base_addr = cur_fn["address"] if cur_fn else image_base
            line_table.add(base_addr + r["value"], r["desc"], cur_file or "")
            continue

        if t in (0x80, 0x42) and cur_fn is not None:  # N_LSYM, N_RSYM
            cur_fn["locals"].append({
                "name": name,
                "fp_offset": struct.unpack("<i", struct.pack("<I", r["value"]))[0],
                "type_desc": desc,
            })
            continue

        if t == 0xA0 and cur_fn is not None:  # N_PSYM
            cur_fn["parameters"].append({
                "name": name,
                "offset": struct.unpack("<i", struct.pack("<I", r["value"]))[0],
                "type_desc": desc,
            })
            continue

    line_table.sort()
    return {
        "functions": functions,
        "globals":   globals_,
        "line_table_len": len(line_table),
        "line_table": line_table.entries,
    }


# ---------------------------------------------------------------------------
# Dispatcher / CLI
# ---------------------------------------------------------------------------

def _do_parse_descriptor(req: dict) -> Any:
    p = StabsTypeParser()
    for k, v in (req.get("registry") or {}).items():
        p.register(k, v)
    return p.parse_descriptor(req["desc"])


def _do_line_lookup(req: dict) -> Any:
    lt = LineNumberTable()
    for e in req.get("entries", []):
        lt.add(int(e["address"]), int(e["line"]), e.get("file", ""))
    lt.sort()
    return {"hit": lt.lookup(int(req["addr"]))}


def _do_string_table(req: dict) -> Any:
    st = StabsStringTable()
    offsets = [st.intern(s) for s in req.get("strings", [])]
    return {
        "offsets": offsets,
        "bytes_hex": st.as_bytes().hex(),
        "roundtrip": [st.get(o) for o in offsets],
    }


_DISPATCH = {
    "parse_records":     lambda r: parse_records(
        bytes.fromhex(r["stab_hex"]), bytes.fromhex(r["str_hex"]),
        be=bool(r.get("be", False))),
    "stab_name":         lambda r: stab_name(int(r["byte"])),
    "stab_category":     lambda r: stab_category(int(r["byte"])),
    "symbol_name":       lambda r: symbol_name(r["string"]),
    "type_descriptor":   lambda r: type_descriptor(r["string"]),
    "classify_descriptor": lambda r: classify_descriptor(r["desc"]),
    "parse_descriptor":  _do_parse_descriptor,
    "line_lookup":       _do_line_lookup,
    "string_table":      _do_string_table,
    "parser_process":    lambda r: parser_process(r["records"], int(r.get("image_base", 0))),
}


def _run_request(req: dict) -> Any:
    fn = req.get("fn")
    if fn not in _DISPATCH:
        return {"error": f"unknown fn '{fn}'", "available": sorted(_DISPATCH)}
    return _DISPATCH[fn](req)


def main() -> None:
    if not sys.stdin.isatty():
        raw = sys.stdin.read().strip()
        if raw:
            try:
                req = json.loads(raw)
            except json.JSONDecodeError as e:
                json.dump({"error": f"bad json: {e}"}, sys.stdout)
                return
            json.dump(_run_request(req), sys.stdout, default=list)
            return

    results: dict[str, Any] = {}

    # 1) stab_name / category coverage
    assert stab_name(0x24) == "N_FUN"
    assert stab_category(0x24) == "symbol"
    assert stab_category(0x44) == "line_number"
    assert stab_category(0x64) == "source_file"
    assert stab_category(0xC0) == "scope_bracket"
    results["names"] = {"0x24": stab_name(0x24), "0xC0": stab_name(0xC0)}

    # 2) Record parse round-trip. Build:
    #   stabstr = "\x00main:F1\x00x:p1\x00"
    #   record0 : strx=1, type=N_FUN(0x24), desc=42, value=0x1000  -> "main:F1"
    #   record1 : strx=9, type=N_PSYM(0xA0), desc=0, value=8       -> "x:p1"
    strtab = b"\x00" + b"main:F1\x00" + b"x:p1\x00"
    rec0 = struct.pack("<IBBHI", 1, 0x24, 0, 42, 0x1000)
    rec1 = struct.pack("<IBBHI", 9, 0xA0, 0, 0,  8)
    recs = parse_records(rec0 + rec1, strtab, be=False)
    assert recs[0]["type_name"] == "N_FUN"
    assert recs[0]["string"] == "main:F1"
    assert symbol_name(recs[0]["string"]) == "main"
    assert type_descriptor(recs[0]["string"]) == "F1"
    assert classify_descriptor("F1") == "GlobalFunction"
    results["records"] = recs

    # 3) BE record parsing
    rec_be = struct.pack(">IBBHI", 1, 0x24, 0, 7, 0x2000)
    rb = parse_records(rec_be, strtab, be=True)
    assert rb[0]["value"] == 0x2000 and rb[0]["desc"] == 7

    # 4) Type parser
    tp = StabsTypeParser()
    assert tp.parse_descriptor("(0,1)")["name"] == "int"
    ptr = tp.parse_descriptor("*(0,1)")
    assert ptr["kind"] == "pointer" and ptr["to"]["name"] == "int"
    assert tp.parse_descriptor("s8int:(0,1),0,32;;")["kind"] == "struct"
    assert tp.parse_descriptor("ar(0,1);0;9;(0,2)")["kind"] == "array"
    results["primitives"] = len(tp)

    # 5) Line table lookup
    lt = LineNumberTable()
    lt.add(0x1000, 10, "a.c"); lt.add(0x1020, 11, "a.c"); lt.add(0x1010, 12, "a.c")
    lt.sort()
    assert lt.lookup(0x1015)["line"] == 12
    assert lt.lookup(0x0FFF) is None
    results["line_lookup"] = lt.lookup(0x1015)

    # 6) String table intern determinism
    st = StabsStringTable()
    o1 = st.intern("foo"); o2 = st.intern("bar"); o3 = st.intern("foo")
    assert o1 == o3 and o1 != o2
    assert st.get(o1) == "foo" and st.get(o2) == "bar"
    results["string_table_offsets"] = [o1, o2, o3]

    # 7) End-to-end parser_process
    summary = parser_process(recs, image_base=0)
    assert len(summary["functions"]) == 1
    fn = summary["functions"][0]
    assert fn["name"] == "main" and fn["address"] == 0x1000
    assert len(fn["parameters"]) == 1 and fn["parameters"][0]["name"] == "x"
    results["parser_process"] = summary

    print(json.dumps({"self_test": "ok", "results": results}, indent=2, default=list))


if __name__ == "__main__":
    main()
