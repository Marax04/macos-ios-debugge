#!/usr/bin/env python3
"""
Standalone validator for rustre-symbols-pdb.

Reimplements minimal MSF v7 + PDB Info / DBI / GSI / Publics parsing in pure
Python (stdlib only) to cross-check the Rust crate's outputs.

Public validator functions:
  validator_parse_pdb_info(path)        -> {version, signature, age, guid}
  validator_pdb_guid_to_string(guid16)  -> "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}"
  validator_scan_public_symbols(path)   -> [{name, segment, offset, kind}]
  validator_symbols(path)               -> same as scan_public_symbols (alias semantics)
  validator_modules(path)               -> [{name, object_file, stream_index}]
  validator_pdb_symbol_is_sane(name)    -> bool
  validator_check_bad_magic(path)       -> "BadMagic" | "Ok" | "StreamTooShort"

Usage:
  echo {"fn":"parse_pdb_info","args":{"path":"x.pdb"}} | python rustre-symbols-pdb.py
  python rustre-symbols-pdb.py            # runs main() with fixed inputs
"""

import json
import os
import struct
import sys

# ---------- MSF v7 ----------
MSF_V7_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"


class PdbError(Exception):
    pass


def _read_file(path):
    with open(path, "rb") as f:
        return f.read()


def _parse_msf(raw):
    if len(raw) < 56:
        raise PdbError("StreamTooShort")
    if not raw.startswith(MSF_V7_MAGIC):
        raise PdbError("BadMagic")
    (block_size, free_block_map, num_blocks,
     num_dir_bytes, _unk, block_map_addr) = struct.unpack_from("<IIIIII", raw, 32)
    if block_size not in (512, 1024, 2048, 4096):
        raise PdbError("CorruptData")
    # block_map_addr is a block index containing array of block indices that
    # in turn hold the stream directory.
    n_dir_blocks = (num_dir_bytes + block_size - 1) // block_size
    bm_off = block_map_addr * block_size
    dir_block_indices = struct.unpack_from(
        "<" + "I" * n_dir_blocks, raw, bm_off)
    dir_bytes = bytearray()
    for bi in dir_block_indices:
        dir_bytes += raw[bi * block_size: bi * block_size + block_size]
    dir_bytes = bytes(dir_bytes[:num_dir_bytes])
    # Directory: NumStreams, StreamSizes[NumStreams], StreamBlocks[...]
    num_streams = struct.unpack_from("<I", dir_bytes, 0)[0]
    sizes = list(struct.unpack_from(
        "<" + "I" * num_streams, dir_bytes, 4))
    off = 4 + 4 * num_streams
    streams = []
    for sz in sizes:
        if sz == 0xFFFFFFFF:
            streams.append(b"")
            continue
        nb = (sz + block_size - 1) // block_size
        blocks = struct.unpack_from("<" + "I" * nb, dir_bytes, off)
        off += 4 * nb
        data = bytearray()
        for b in blocks:
            data += raw[b * block_size: b * block_size + block_size]
        streams.append(bytes(data[:sz]))
    return streams


# ---------- PDB Info stream (stream 1) ----------
def validator_parse_pdb_info(path):
    raw = _read_file(path)
    streams = _parse_msf(raw)
    if len(streams) < 2 or len(streams[1]) < 28:
        raise PdbError("StreamTooShort")
    info = streams[1]
    version, signature, age = struct.unpack_from("<III", info, 0)
    guid = info[12:28]
    return {
        "version": version,
        "signature": signature,
        "age": age,
        "guid_hex": guid.hex(),
        "guid_fmt": validator_pdb_guid_to_string(guid),
    }


def validator_pdb_guid_to_string(guid16):
    if isinstance(guid16, str):
        guid16 = bytes.fromhex(guid16)
    if len(guid16) != 16:
        raise PdbError("guid must be 16 bytes")
    d1 = struct.unpack_from("<I", guid16, 0)[0]
    d2 = struct.unpack_from("<H", guid16, 4)[0]
    d3 = struct.unpack_from("<H", guid16, 6)[0]
    d4 = guid16[8:10]
    d5 = guid16[10:16]
    return "{{{:08X}-{:04X}-{:04X}-{}-{}}}".format(
        d1, d2, d3, d4.hex().upper(), d5.hex().upper())


# ---------- DBI stream (stream 3) ----------
def _parse_dbi_header(dbi):
    # DbiStreamHeader (new layout): signature 0xFFFFFFFF, version, age, gs, vers, ps, build, ...
    if len(dbi) < 64:
        raise PdbError("StreamTooShort")
    fields = struct.unpack_from("<iIIHHHHHHIIIIIIHHII", dbi, 0)
    # signature, version, age,
    # global_stream_idx, build_number, public_stream_idx, pdb_dll_version,
    # sym_record_stream, pdb_dll_rbld, mod_info_size, sec_contrib_size,
    # sec_map_size, src_info_size, type_server_size, mfc_index, dbg_header_size,
    # ec_substream_size, flags, machine
    return {
        "signature": fields[0],
        "version": fields[1],
        "age": fields[2],
        "global_stream_idx": fields[3],
        "build_number": fields[4],
        "public_stream_idx": fields[5],
        "pdb_dll_version": fields[6],
        "sym_record_stream": fields[7],
        "mod_info_size": fields[9],
    }


def validator_modules(path):
    raw = _read_file(path)
    streams = _parse_msf(raw)
    if len(streams) < 4:
        return []
    dbi = streams[3]
    hdr = _parse_dbi_header(dbi)
    mod_info_size = hdr["mod_info_size"]
    off = 64  # after header
    end = off + mod_info_size
    mods = []
    while off + 64 <= end:
        # ModInfo struct: unused1(u32), SectionContrEntry(28b), flags(u16),
        # ModuleSymStream(i16), SymByteSize(u32), C11ByteSize(u32),
        # C13ByteSize(u32), SourceFileCount(u16), Padding(u16), unused2(u32),
        # SourceFileNameIndex(u32), PdbFilePathNameIndex(u32), then 2 cstrings
        (unused1,) = struct.unpack_from("<I", dbi, off)
        # sec contrib entry is 28 bytes
        (flags, mod_sym_stream) = struct.unpack_from("<Hh", dbi, off + 4 + 28)
        # skip to cstrings: header is 4 + 28 + 2 + 2 + 4 + 4 + 4 + 2 + 2 + 4 + 4 + 4 = 64
        cstr_off = off + 64
        # module name
        try:
            n_end = dbi.index(b"\x00", cstr_off)
        except ValueError:
            break
        module_name = dbi[cstr_off:n_end].decode("utf-8", errors="replace")
        obj_off = n_end + 1
        try:
            o_end = dbi.index(b"\x00", obj_off)
        except ValueError:
            break
        object_file = dbi[obj_off:o_end].decode("utf-8", errors="replace")
        next_off = o_end + 1
        # align to 4
        next_off = (next_off + 3) & ~3
        mods.append({
            "name": module_name,
            "object_file": object_file,
            "stream_index": mod_sym_stream,
        })
        if next_off <= off:
            break
        off = next_off
    return mods


# ---------- Public / global symbol record stream ----------
S_PUB32 = 0x110E
S_LPROC32 = 0x110F
S_GPROC32 = 0x1110
S_GDATA32 = 0x110D
S_LDATA32 = 0x110C
S_LABEL32 = 0x1105
S_THUNK32 = 0x1102


def _kind_for(rec):
    if rec in (S_LPROC32, S_GPROC32):
        return "Function"
    if rec in (S_GDATA32, S_LDATA32):
        return "Data"
    if rec == S_LABEL32:
        return "Label"
    if rec == S_THUNK32:
        return "Thunk"
    if rec == S_PUB32:
        return "Function"  # publics typically code symbols
    return "Other"


def _walk_sym_records(data):
    """Yield (rec_type, payload_bytes)."""
    i = 0
    n = len(data)
    while i + 4 <= n:
        (length, rec) = struct.unpack_from("<HH", data, i)
        if length < 2 or i + 2 + length > n:
            break
        payload = data[i + 4: i + 2 + length]
        yield rec, payload
        i += 2 + length


def validator_scan_public_symbols(path):
    raw = _read_file(path)
    streams = _parse_msf(raw)
    if len(streams) < 4:
        return []
    dbi = streams[3]
    hdr = _parse_dbi_header(dbi)
    sym_idx = hdr["sym_record_stream"]
    if sym_idx >= len(streams):
        return []
    sym = streams[sym_idx]
    out = []
    for rec, payload in _walk_sym_records(sym):
        if rec == S_PUB32 and len(payload) >= 10:
            flags, offset, segment = struct.unpack_from("<IIH", payload, 0)
            name_b = payload[10:]
            nz = name_b.find(b"\x00")
            if nz >= 0:
                name_b = name_b[:nz]
            name = name_b.decode("utf-8", errors="replace")
            out.append({
                "name": name,
                "segment": segment,
                "offset": offset,
                "kind": "Function",
                "flags": flags,
            })
        elif rec in (S_GPROC32, S_LPROC32) and len(payload) >= 35:
            # parent, end, next, len, dbg_start, dbg_end, type, offset, segment, flags, name
            (_p, _e, _n, _l, _ds, _de, _t, offset, segment, _f) = \
                struct.unpack_from("<IIIIIIIIHB", payload, 0)
            name_b = payload[35:]
            nz = name_b.find(b"\x00")
            if nz >= 0:
                name_b = name_b[:nz]
            name = name_b.decode("utf-8", errors="replace")
            out.append({
                "name": name,
                "segment": segment,
                "offset": offset,
                "kind": "Function",
            })
        elif rec in (S_GDATA32, S_LDATA32) and len(payload) >= 10:
            _t, offset, segment = struct.unpack_from("<IIH", payload, 0)
            name_b = payload[10:]
            nz = name_b.find(b"\x00")
            if nz >= 0:
                name_b = name_b[:nz]
            out.append({
                "name": name_b.decode("utf-8", errors="replace"),
                "segment": segment,
                "offset": offset,
                "kind": "Data",
            })
    return out


def validator_symbols(path):
    return validator_scan_public_symbols(path)


# ---------- Pure helpers ----------
def validator_pdb_symbol_is_sane(name):
    if not name or len(name) > 4096:
        return False
    if name[0].isdigit():
        # mangled MSVC names start with ? or _, Rust with _ZN; pure-digit start unusual
        return False
    bad = set("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f")
    return not any(c in bad for c in name)


def validator_check_bad_magic(path):
    try:
        raw = _read_file(path)
        _parse_msf(raw)
        return "Ok"
    except PdbError as e:
        return str(e)


# ---------- Dispatcher ----------
FUNCS = {
    "parse_pdb_info": lambda a: validator_parse_pdb_info(a["path"]),
    "pdb_guid_to_string": lambda a: validator_pdb_guid_to_string(a["guid"]),
    "scan_public_symbols": lambda a: validator_scan_public_symbols(a["path"]),
    "symbols": lambda a: validator_symbols(a["path"]),
    "modules": lambda a: validator_modules(a["path"]),
    "pdb_symbol_is_sane": lambda a: validator_pdb_symbol_is_sane(a["name"]),
    "check_bad_magic": lambda a: validator_check_bad_magic(a["path"]),
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
        "guid_fmt": validator_pdb_guid_to_string(
            bytes.fromhex("0102030405060708090a0b0c0d0e0f10")),
        "sane_ok": validator_pdb_symbol_is_sane("_ZN4core3fmt9Formatter3pad17h0E"),
        "sane_bad_empty": validator_pdb_symbol_is_sane(""),
        "sane_bad_ctrl": validator_pdb_symbol_is_sane("foo\x01bar"),
    }
    baseline_pdb = r"C:\Users\Fra\Desktop\RustRE\samples\cargo-zyphora.pdb"
    if os.path.exists(baseline_pdb):
        try:
            samples["pdb_info"] = validator_parse_pdb_info(baseline_pdb)
            pubs = validator_scan_public_symbols(baseline_pdb)
            samples["public_count"] = len(pubs)
            samples["public_first"] = pubs[:3]
            mods = validator_modules(baseline_pdb)
            samples["module_count"] = len(mods)
            samples["modules_first"] = mods[:3]
        except Exception as e:
            samples["baseline_error"] = str(e)
    else:
        samples["baseline_pdb_missing"] = baseline_pdb
    print(json.dumps(samples, indent=2, default=str))


if __name__ == "__main__":
    main()
