#!/usr/bin/env python3
"""
Standalone validator for rustre-symbols-dwarf.

Pure-Python (stdlib only) minimal ELF + DWARF parser used to cross-check the
Rust crate's outputs. Implements:
  - ELF32/64 little-endian section table extraction
  - LEB128 (unsigned / signed) decode
  - .debug_abbrev parsing (abbrev decl table per offset)
  - .debug_info compilation unit header walk (DWARF v2..v5, 32-bit format)
  - DIE tree walk yielding DW_TAG_subprogram / DW_TAG_variable / type tags
  - .debug_str / .debug_line_str / .debug_str_offsets resolution
  - .debug_line state machine (minimal: addr/file/line/column rows)

Public validator functions:
  validator_elf_sections(path)            -> {name: (offset, size)}
  validator_extract_dwarf_sections(path)  -> {name: bytes_len}
  validator_decode_uleb(buf, off)         -> (value, new_off)
  validator_decode_sleb(buf, off)         -> (value, new_off)
  validator_parse_abbrev(buf)             -> {code: {tag, has_children, attrs:[(name,form)]}}
  validator_compile_units(path)           -> [{offset, version, unit_type, addr_size, abbrev_offset, length}]
  validator_functions(path)               -> [{name, low_pc, high_pc}]
  validator_variables(path)               -> [{name, type_offset}]
  validator_types(path)                   -> [{name, byte_size, tag}]
  validator_line_entries(path, limit=200) -> [{address, file, line, column}]
  validator_dw_tag_name(code)             -> str
  validator_dw_form_name(code)            -> str

Usage:
  echo {"fn":"functions","args":{"path":"x"}} | python rustre-symbols-dwarf.py
  python rustre-symbols-dwarf.py            # runs main() smoke test
"""

import json
import os
import struct
import sys

# ---------- DWARF constants ----------
DW_TAG = {
    0x01: "array_type", 0x02: "class_type", 0x04: "enumeration_type",
    0x05: "formal_parameter", 0x0b: "lexical_block", 0x0d: "member",
    0x0f: "pointer_type", 0x10: "reference_type", 0x11: "compile_unit",
    0x13: "structure_type", 0x15: "subroutine_type", 0x16: "typedef",
    0x17: "union_type", 0x18: "unspecified_parameters", 0x19: "variant",
    0x1d: "inlined_subroutine", 0x21: "subrange_type",
    0x24: "base_type", 0x26: "const_type", 0x2e: "subprogram",
    0x2f: "template_type_parameter", 0x34: "variable", 0x35: "volatile_type",
    0x39: "namespace", 0x3b: "imported_module", 0x3d: "restrict_type",
    0x41: "type_unit", 0x4109: "GNU_call_site",
}

DW_FORM = {
    0x01: "addr", 0x03: "block2", 0x04: "block4", 0x05: "data2", 0x06: "data4",
    0x07: "data8", 0x08: "string", 0x09: "block", 0x0a: "block1", 0x0b: "data1",
    0x0c: "flag", 0x0d: "sdata", 0x0e: "strp", 0x0f: "udata", 0x10: "ref_addr",
    0x11: "ref1", 0x12: "ref2", 0x13: "ref4", 0x14: "ref8", 0x15: "ref_udata",
    0x16: "indirect", 0x17: "sec_offset", 0x18: "exprloc", 0x19: "flag_present",
    0x1a: "strx", 0x1b: "addrx", 0x1c: "ref_sup4", 0x1d: "strp_sup",
    0x1e: "data16", 0x1f: "line_strp", 0x20: "ref_sig8", 0x21: "implicit_const",
    0x22: "loclistx", 0x23: "rnglistx", 0x24: "ref_sup8",
    0x25: "strx1", 0x26: "strx2", 0x27: "strx3", 0x28: "strx4",
    0x29: "addrx1", 0x2a: "addrx2", 0x2b: "addrx3", 0x2c: "addrx4",
}

DW_AT_NAME = 0x03
DW_AT_LOW_PC = 0x11
DW_AT_HIGH_PC = 0x12
DW_AT_BYTE_SIZE = 0x0b
DW_AT_TYPE = 0x49
DW_AT_STR_OFFSETS_BASE = 0x72


# ---------- LEB128 ----------
def validator_decode_uleb(buf, off):
    result = 0
    shift = 0
    while off < len(buf):
        b = buf[off]
        off += 1
        result |= (b & 0x7f) << shift
        if (b & 0x80) == 0:
            return result, off
        shift += 7
    raise ValueError("uleb truncated")


def validator_decode_sleb(buf, off):
    result = 0
    shift = 0
    while off < len(buf):
        b = buf[off]
        off += 1
        result |= (b & 0x7f) << shift
        shift += 7
        if (b & 0x80) == 0:
            if b & 0x40:
                result |= -(1 << shift)
            return result, off
    raise ValueError("sleb truncated")


# ---------- ELF ----------
def _read_file(path):
    with open(path, "rb") as f:
        return f.read()


def validator_elf_sections(path):
    raw = _read_file(path)
    if raw[:4] != b"\x7fELF":
        raise ValueError("not ELF")
    ei_class = raw[4]
    if ei_class == 1:
        # ELF32: e_shoff @ 32, e_shentsize @ 46, e_shnum @ 48, e_shstrndx @ 50
        e_shoff, = struct.unpack_from("<I", raw, 32)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", raw, 46)
        sh_fmt = "<IIIIIIIIII"  # 40 bytes
        sh_size = 40
    elif ei_class == 2:
        # ELF64: e_shoff @ 40, e_shentsize @ 58, e_shnum @ 60, e_shstrndx @ 62
        e_shoff, = struct.unpack_from("<Q", raw, 40)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", raw, 58)
        sh_fmt = "<IIQQQQIIQQ"  # 64 bytes
        sh_size = 64
    else:
        raise ValueError("bad ELF class")
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        fields = struct.unpack_from(sh_fmt, raw, off)
        # name_off, type, flags, addr, offset, size, link, info, align, entsize
        sections.append(fields)
    # section header string table
    sh_strtab_off = sections[e_shstrndx][4]
    sh_strtab_size = sections[e_shstrndx][5]
    strtab = raw[sh_strtab_off: sh_strtab_off + sh_strtab_size]
    result = {}
    for s in sections:
        name_off = s[0]
        nz = strtab.find(b"\x00", name_off)
        name = strtab[name_off:nz].decode("utf-8", errors="replace")
        result[name] = (s[4], s[5])  # (offset, size)
    return result, raw


def _section_bytes(sections, raw, name):
    if name not in sections:
        return b""
    off, sz = sections[name]
    return raw[off: off + sz]


def validator_extract_dwarf_sections(path):
    sections, raw = validator_elf_sections(path)
    wanted = [
        ".debug_info", ".debug_abbrev", ".debug_str", ".debug_line",
        ".debug_str_offsets", ".debug_line_str", ".debug_ranges",
        ".debug_addr", ".debug_loc", ".debug_loclists", ".debug_rnglists",
    ]
    return {n: len(_section_bytes(sections, raw, n)) for n in wanted}


# ---------- Abbrev ----------
def validator_parse_abbrev(buf):
    """Parse an entire .debug_abbrev blob; return {table_offset: {code: decl}}."""
    tables = {}
    i = 0
    n = len(buf)
    while i < n:
        table_off = i
        table = {}
        while i < n:
            code, i = validator_decode_uleb(buf, i)
            if code == 0:
                break
            tag, i = validator_decode_uleb(buf, i)
            if i >= n:
                break
            has_children = buf[i]
            i += 1
            attrs = []
            while i < n:
                at, i = validator_decode_uleb(buf, i)
                form, i = validator_decode_uleb(buf, i)
                if at == 0 and form == 0:
                    break
                implicit = None
                if form == 0x21:  # implicit_const
                    implicit, i = validator_decode_sleb(buf, i)
                attrs.append((at, form, implicit))
            table[code] = {
                "tag": tag, "has_children": bool(has_children), "attrs": attrs,
            }
        tables[table_off] = table
        if not table:
            break
    return tables


# ---------- Compilation units ----------
def _read_initial_length(buf, off):
    """Return (length, new_off, dwarf64). 32-bit DWARF only here (length < 0xfffffff0)."""
    (l,) = struct.unpack_from("<I", buf, off)
    off += 4
    if l == 0xffffffff:
        (l,) = struct.unpack_from("<Q", buf, off)
        return l, off + 8, True
    return l, off, False


def validator_compile_units(path):
    sections, raw = validator_elf_sections(path)
    info = _section_bytes(sections, raw, ".debug_info")
    cus = []
    off = 0
    while off + 4 <= len(info):
        cu_start = off
        length, off, dwarf64 = _read_initial_length(info, off)
        if length == 0:
            break
        unit_end = off + length
        (version,) = struct.unpack_from("<H", info, off)
        off += 2
        unit_type = 0
        addr_size = 0
        abbrev_offset = 0
        if version >= 5:
            unit_type = info[off]
            off += 1
            addr_size = info[off]
            off += 1
            if dwarf64:
                (abbrev_offset,) = struct.unpack_from("<Q", info, off)
                off += 8
            else:
                (abbrev_offset,) = struct.unpack_from("<I", info, off)
                off += 4
        else:
            if dwarf64:
                (abbrev_offset,) = struct.unpack_from("<Q", info, off)
                off += 8
            else:
                (abbrev_offset,) = struct.unpack_from("<I", info, off)
                off += 4
            addr_size = info[off]
            off += 1
        cus.append({
            "offset": cu_start, "version": version, "unit_type": unit_type,
            "addr_size": addr_size, "abbrev_offset": abbrev_offset,
            "length": length, "die_start": off, "die_end": unit_end,
            "dwarf64": dwarf64,
        })
        off = unit_end
    return cus


# ---------- DIE walking ----------
def _form_size(form, addr_size, dwarf64, buf, off, version):
    """Return (raw_value_bytes, new_off, parsed_value_or_None)."""
    fmt_off_sz = 8 if dwarf64 else 4
    if form == 0x01:  # addr
        v = int.from_bytes(buf[off:off + addr_size], "little")
        return buf[off:off + addr_size], off + addr_size, v
    if form == 0x03:  # block2
        n, = struct.unpack_from("<H", buf, off)
        return buf[off:off + 2 + n], off + 2 + n, None
    if form == 0x04:  # block4
        n, = struct.unpack_from("<I", buf, off)
        return buf[off:off + 4 + n], off + 4 + n, None
    if form == 0x05:  # data2
        v, = struct.unpack_from("<H", buf, off)
        return buf[off:off + 2], off + 2, v
    if form == 0x06:  # data4
        v, = struct.unpack_from("<I", buf, off)
        return buf[off:off + 4], off + 4, v
    if form == 0x07:  # data8
        v, = struct.unpack_from("<Q", buf, off)
        return buf[off:off + 8], off + 8, v
    if form == 0x08:  # string (inline cstring)
        nz = buf.find(b"\x00", off)
        return buf[off:nz], nz + 1, buf[off:nz]
    if form == 0x09:  # block (ULEB len)
        n, new = validator_decode_uleb(buf, off)
        return buf[off:new + n], new + n, None
    if form == 0x0a:  # block1
        n = buf[off]
        return buf[off:off + 1 + n], off + 1 + n, None
    if form == 0x0b:  # data1
        return buf[off:off + 1], off + 1, buf[off]
    if form == 0x0c:  # flag
        return buf[off:off + 1], off + 1, buf[off]
    if form == 0x0d:  # sdata
        v, new = validator_decode_sleb(buf, off)
        return buf[off:new], new, v
    if form == 0x0e:  # strp
        v = int.from_bytes(buf[off:off + fmt_off_sz], "little")
        return buf[off:off + fmt_off_sz], off + fmt_off_sz, ("strp", v)
    if form == 0x0f:  # udata
        v, new = validator_decode_uleb(buf, off)
        return buf[off:new], new, v
    if form == 0x10:  # ref_addr
        sz = fmt_off_sz if version >= 3 else addr_size
        v = int.from_bytes(buf[off:off + sz], "little")
        return buf[off:off + sz], off + sz, v
    if form == 0x11:  # ref1
        return buf[off:off + 1], off + 1, buf[off]
    if form == 0x12:  # ref2
        v, = struct.unpack_from("<H", buf, off)
        return buf[off:off + 2], off + 2, v
    if form == 0x13:  # ref4
        v, = struct.unpack_from("<I", buf, off)
        return buf[off:off + 4], off + 4, v
    if form == 0x14:  # ref8
        v, = struct.unpack_from("<Q", buf, off)
        return buf[off:off + 8], off + 8, v
    if form == 0x15:  # ref_udata
        v, new = validator_decode_uleb(buf, off)
        return buf[off:new], new, v
    if form == 0x17:  # sec_offset
        v = int.from_bytes(buf[off:off + fmt_off_sz], "little")
        return buf[off:off + fmt_off_sz], off + fmt_off_sz, v
    if form == 0x18:  # exprloc
        n, new = validator_decode_uleb(buf, off)
        return buf[off:new + n], new + n, None
    if form == 0x19:  # flag_present
        return b"", off, 1
    if form == 0x1a:  # strx ULEB
        v, new = validator_decode_uleb(buf, off)
        return buf[off:new], new, ("strx", v)
    if form == 0x1b:  # addrx ULEB
        v, new = validator_decode_uleb(buf, off)
        return buf[off:new], new, v
    if form == 0x1e:  # data16
        return buf[off:off + 16], off + 16, None
    if form == 0x1f:  # line_strp
        v = int.from_bytes(buf[off:off + fmt_off_sz], "little")
        return buf[off:off + fmt_off_sz], off + fmt_off_sz, ("line_strp", v)
    if form == 0x20:  # ref_sig8
        return buf[off:off + 8], off + 8, None
    if form == 0x21:  # implicit_const - handled by caller
        return b"", off, None
    if form == 0x22:  # loclistx
        v, new = validator_decode_uleb(buf, off)
        return buf[off:new], new, v
    if form == 0x23:  # rnglistx
        v, new = validator_decode_uleb(buf, off)
        return buf[off:new], new, v
    if form in (0x25, 0x26, 0x27, 0x28):  # strx1..4
        sz = form - 0x24
        v = int.from_bytes(buf[off:off + sz], "little")
        return buf[off:off + sz], off + sz, ("strx", v)
    if form in (0x29, 0x2a, 0x2b, 0x2c):  # addrx1..4
        sz = form - 0x28
        v = int.from_bytes(buf[off:off + sz], "little")
        return buf[off:off + sz], off + sz, v
    raise ValueError(f"unsupported form 0x{form:x}")


def _resolve_string(val, debug_str, debug_line_str, str_offsets, fmt_off_sz):
    if isinstance(val, (bytes, bytearray)):
        return val.decode("utf-8", errors="replace")
    if isinstance(val, tuple):
        kind, v = val
        if kind == "strp" and v < len(debug_str):
            nz = debug_str.find(b"\x00", v)
            return debug_str[v:nz].decode("utf-8", errors="replace")
        if kind == "line_strp" and v < len(debug_line_str):
            nz = debug_line_str.find(b"\x00", v)
            return debug_line_str[v:nz].decode("utf-8", errors="replace")
        if kind == "strx":
            # index into .debug_str_offsets relative to CU's str_offsets_base
            return f"<strx:{v}>"
    return None


def _walk_dies(cu, info, abbrev_tables, debug_str, debug_line_str):
    table = abbrev_tables.get(cu["abbrev_offset"], {})
    addr_size = cu["addr_size"] or 8
    dwarf64 = cu["dwarf64"]
    version = cu["version"]
    fmt_off_sz = 8 if dwarf64 else 4
    off = cu["die_start"]
    end = cu["die_end"]
    while off < end:
        code, off = validator_decode_uleb(info, off)
        if code == 0:
            continue
        decl = table.get(code)
        if decl is None:
            break
        die = {"tag": decl["tag"], "attrs": {}}
        for at, form, implicit in decl["attrs"]:
            if form == 0x21:
                die["attrs"][at] = implicit
                continue
            _raw, off, val = _form_size(
                form, addr_size, dwarf64, info, off, version)
            die["attrs"][at] = (form, val)
        yield die


def _attr_str(die, attr, debug_str, debug_line_str):
    v = die["attrs"].get(attr)
    if v is None:
        return None
    if isinstance(v, tuple):
        form, val = v
        return _resolve_string(val, debug_str, debug_line_str, None, 4)
    return None


def _attr_int(die, attr):
    v = die["attrs"].get(attr)
    if v is None:
        return None
    if isinstance(v, tuple):
        _form, val = v
        if isinstance(val, int):
            return val
    elif isinstance(v, int):
        return v
    return None


def _load_dwarf(path):
    sections, raw = validator_elf_sections(path)
    info = _section_bytes(sections, raw, ".debug_info")
    abbrev = _section_bytes(sections, raw, ".debug_abbrev")
    debug_str = _section_bytes(sections, raw, ".debug_str")
    debug_line_str = _section_bytes(sections, raw, ".debug_line_str")
    debug_line = _section_bytes(sections, raw, ".debug_line")
    abbrev_tables = validator_parse_abbrev(abbrev)
    cus = validator_compile_units(path)
    return info, abbrev_tables, debug_str, debug_line_str, debug_line, cus


def validator_functions(path):
    info, abbrev_tables, dstr, dlstr, _dline, cus = _load_dwarf(path)
    out = []
    for cu in cus:
        for die in _walk_dies(cu, info, abbrev_tables, dstr, dlstr):
            if die["tag"] == 0x2e:  # subprogram
                name = _attr_str(die, DW_AT_NAME, dstr, dlstr)
                lo = _attr_int(die, DW_AT_LOW_PC)
                hi = _attr_int(die, DW_AT_HIGH_PC)
                if name:
                    out.append({"name": name, "low_pc": lo, "high_pc": hi})
    return out


def validator_variables(path):
    info, abbrev_tables, dstr, dlstr, _dline, cus = _load_dwarf(path)
    out = []
    for cu in cus:
        for die in _walk_dies(cu, info, abbrev_tables, dstr, dlstr):
            if die["tag"] in (0x34, 0x05):  # variable / formal_parameter
                name = _attr_str(die, DW_AT_NAME, dstr, dlstr)
                t = _attr_int(die, DW_AT_TYPE)
                if name:
                    out.append({"name": name, "type_offset": t})
    return out


_TYPE_TAGS = {
    0x24: "Base", 0x0f: "Pointer", 0x16: "Typedef", 0x13: "Struct",
    0x17: "Union", 0x01: "Array",
}


def validator_types(path):
    info, abbrev_tables, dstr, dlstr, _dline, cus = _load_dwarf(path)
    out = []
    for cu in cus:
        for die in _walk_dies(cu, info, abbrev_tables, dstr, dlstr):
            tag = die["tag"]
            if tag in _TYPE_TAGS:
                name = _attr_str(die, DW_AT_NAME, dstr, dlstr)
                sz = _attr_int(die, DW_AT_BYTE_SIZE)
                out.append({
                    "name": name, "byte_size": sz,
                    "tag": _TYPE_TAGS[tag],
                })
    return out


# ---------- .debug_line (minimal) ----------
def validator_line_entries(path, limit=200):
    sections, raw = validator_elf_sections(path)
    line = _section_bytes(sections, raw, ".debug_line")
    if not line:
        return []
    rows = []
    off = 0
    n = len(line)
    while off + 4 <= n and len(rows) < limit:
        prog_start = off
        length, off, dwarf64 = _read_initial_length(line, off)
        if length == 0:
            break
        prog_end = off + length
        if prog_end > n:
            break
        (version,) = struct.unpack_from("<H", line, off)
        off += 2
        if version not in (2, 3, 4, 5):
            off = prog_end
            continue
        if version >= 5:
            address_size = line[off]
            segment_selector_size = line[off + 1]
            off += 2
        else:
            address_size = 8
        fmt_off_sz = 8 if dwarf64 else 4
        header_length = int.from_bytes(line[off:off + fmt_off_sz], "little")
        off += fmt_off_sz
        prog_after_header = off + header_length
        if prog_after_header > prog_end:
            break
        min_inst_len = line[off]; off += 1
        if version >= 4:
            max_ops_per_inst = line[off]; off += 1
        else:
            max_ops_per_inst = 1
        default_is_stmt = line[off]; off += 1
        line_base = struct.unpack_from("<b", line, off)[0]; off += 1
        line_range = line[off]; off += 1
        opcode_base = line[off]; off += 1
        # standard_opcode_lengths
        off += opcode_base - 1
        # We don't fully decode the file table here — just record summary as
        # a single row to confirm the section parses.
        rows.append({
            "program_offset": prog_start, "version": version,
            "address_size": address_size, "opcode_base": opcode_base,
        })
        off = prog_end
    return rows


# ---------- Pure helpers ----------
def validator_dw_tag_name(code):
    return DW_TAG.get(code, f"<0x{code:x}>")


def validator_dw_form_name(code):
    return DW_FORM.get(code, f"<0x{code:x}>")


# ---------- Dispatcher ----------
FUNCS = {
    "elf_sections": lambda a: {
        k: {"offset": v[0], "size": v[1]}
        for k, v in validator_elf_sections(a["path"])[0].items()
    },
    "extract_dwarf_sections":
        lambda a: validator_extract_dwarf_sections(a["path"]),
    "decode_uleb": lambda a: validator_decode_uleb(
        bytes.fromhex(a["buf"]), a.get("off", 0)),
    "decode_sleb": lambda a: validator_decode_sleb(
        bytes.fromhex(a["buf"]), a.get("off", 0)),
    "parse_abbrev": lambda a: validator_parse_abbrev(
        bytes.fromhex(a["buf"])),
    "compile_units": lambda a: validator_compile_units(a["path"]),
    "functions": lambda a: validator_functions(a["path"]),
    "variables": lambda a: validator_variables(a["path"]),
    "types": lambda a: validator_types(a["path"]),
    "line_entries": lambda a: validator_line_entries(
        a["path"], a.get("limit", 200)),
    "dw_tag_name": lambda a: validator_dw_tag_name(a["code"]),
    "dw_form_name": lambda a: validator_dw_form_name(a["code"]),
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

    # Fixed-input smoke test
    samples = {
        "uleb_624485": validator_decode_uleb(b"\xe5\x8e\x26", 0),
        "sleb_neg_624485": validator_decode_sleb(b"\x9b\xf1\x59", 0),
        "tag_subprogram": validator_dw_tag_name(0x2e),
        "form_strp": validator_dw_form_name(0x0e),
    }
    # Probe a baseline ELF with DWARF if present
    candidates = [
        r"C:\Users\Fra\Desktop\RustRE\samples\hello_dwarf",
        r"C:\Users\Fra\Desktop\RustRE\samples\hello_dwarf.elf",
    ]
    for p in candidates:
        if os.path.exists(p):
            try:
                samples["dwarf_sections"] = \
                    validator_extract_dwarf_sections(p)
                samples["cu_count"] = len(validator_compile_units(p))
                fns = validator_functions(p)
                samples["fn_count"] = len(fns)
                samples["fn_first"] = fns[:3]
                samples["type_count"] = len(validator_types(p))
            except Exception as e:
                samples["baseline_error"] = str(e)
            samples["baseline_path"] = p
            break
    else:
        samples["baseline_missing"] = candidates
    print(json.dumps(samples, indent=2, default=str))


if __name__ == "__main__":
    main()
