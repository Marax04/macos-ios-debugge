#!/usr/bin/env python3
"""Independent validator for the rustre-flirt-gen crate.

Reimplements the FLIRT signature *generator* primitives in pure-Python using
only the standard library, so results can be cross-checked against the Rust
crate without importing it or calling any MCP tool.

Mirrors the public surface described in
  validation/reports/rustre-flirt-gen.md
  - PatternGenerator { initial_length=32, crc_length=16 }
      generate(bytes, relocs, names)
      generate_from_ranges(bytes, masked_ranges, names, referenced)
      generate_batch(functions)
      generate_pattern_with_quality(bytes, name)
  - PatternQuality classification
  - scan_x86_masks(bytes)
  - ElfObjectParser::parse(elf_bytes)
  - LibraryBuilder (add_function / add_elf_object / dedup_patterns / build)
  - crc16_sig_header (CRC-16/IBM, non-reflected, poly 0x8005, init 0xFFFF)
  - SigWriter::build  +  write_sig_file
  - SigTrieNode::encode

Input format (stdin JSON):
  { "function": "<name>", "input": <args> }
Output:
  { "function": "<name>", "output": <result> }

If no stdin is provided, main() runs a small self-test battery.
"""

from __future__ import annotations

import io
import json
import os
import struct
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# CRCs
# ---------------------------------------------------------------------------

def validator_crc16_flirt(data: bytes) -> int:
    """CRC-16/CCITT reversed, poly 0x8408, init 0xFFFF — pattern body CRC."""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if (crc & 1) else (crc >> 1)
    return crc & 0xFFFF


def validator_crc16_sig_header(data: bytes) -> int:
    """CRC-16/IBM non-reflected, poly 0x8005, init 0xFFFF — header CRC."""
    crc = 0xFFFF
    for b in data:
        crc ^= (b << 8)
        crc &= 0xFFFF
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x8005) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF


# ---------------------------------------------------------------------------
# x86 mask scanner
#
# Recognises common x86_64 instructions that embed relocatable operands and
# returns the (offset, length) ranges that must be masked as wildcards.
# Conservative: on unknown opcodes, walks one byte forward.
# ---------------------------------------------------------------------------

def validator_scan_x86_masks(data: bytes) -> List[Tuple[int, int]]:
    out: List[Tuple[int, int]] = []
    i = 0
    n = len(data)
    while i < n:
        b = data[i]

        # REX prefix passthrough; handle REX.W MOV r64, imm64 (B8+r)
        rex_w = False
        rex_i = i
        if 0x40 <= b <= 0x4F:
            rex_w = (b & 0x08) != 0
            i += 1
            if i >= n:
                break
            b = data[i]

        # MOV r64, imm64
        if rex_w and 0xB8 <= b <= 0xBF:
            # 1 opcode + 8 imm bytes; mask the 8 imm bytes
            if i + 1 + 8 <= n:
                out.append((i + 1, 8))
            i += 1 + 8
            continue

        # CALL rel32 / JMP rel32
        if b in (0xE8, 0xE9):
            if i + 1 + 4 <= n:
                out.append((i + 1, 4))
            i += 1 + 4
            continue

        # Jcc rel32 (0F 8x)
        if b == 0x0F and i + 1 < n and 0x80 <= data[i + 1] <= 0x8F:
            if i + 2 + 4 <= n:
                out.append((i + 2, 4))
            i += 2 + 4
            continue

        # Short JMP rel8 / Jcc rel8 / LOOPx
        if b == 0xEB or (0x70 <= b <= 0x7F) or (0xE0 <= b <= 0xE3):
            if i + 1 + 1 <= n:
                out.append((i + 1, 1))
            i += 1 + 1
            continue

        # RIP-relative mem operand: mod=00 rm=101 -> disp32 follows ModRM.
        # We treat any single-byte opcode followed by such a ModRM as
        # carrying a 4-byte displacement to mask.  This is the same
        # heuristic the crate uses (single-opcode + ModRM).
        if i + 1 < n:
            modrm = data[i + 1]
            mod = (modrm >> 6) & 0x3
            rm = modrm & 0x7
            if mod == 0 and rm == 0b101:
                if i + 2 + 4 <= n:
                    out.append((i + 2, 4))
                i += 2 + 4
                continue

        # Unknown — advance one byte (include any REX we consumed).
        i = rex_i + 1
    # Reset i if we advanced past a REX without consuming the opcode.
    return out


# ---------------------------------------------------------------------------
# Apply masked ranges -> initial pattern (with None as wildcard)
# ---------------------------------------------------------------------------

def _apply_masks(bytes_: bytes, ranges: List[Tuple[int, int]]) -> List[Optional[int]]:
    out: List[Optional[int]] = [b for b in bytes_]
    for off, length in ranges:
        for k in range(off, min(off + length, len(out))):
            out[k] = None
    return out


# ---------------------------------------------------------------------------
# PatternGenerator
# ---------------------------------------------------------------------------

INITIAL_LENGTH = 32
CRC_LENGTH = 16


def validator_generate_pattern(bytes_: bytes,
                               relocs: List[Tuple[int, int]],
                               names: List[Dict[str, Any]],
                               initial_length: int = INITIAL_LENGTH,
                               crc_length: int = CRC_LENGTH) -> Dict[str, Any]:
    """Mirror of PatternGenerator::generate."""
    if not bytes_:
        raise ValueError("InvalidPattern: empty bytes")

    init_len = min(initial_length, len(bytes_))
    initial = _apply_masks(bytes_[:init_len], [
        (off, size) for (off, size) in relocs if off < init_len
    ])

    crc_start = init_len
    crc_end = min(crc_start + crc_length, len(bytes_))
    crc_data = bytes_[crc_start:crc_end]
    crc16 = validator_crc16_flirt(crc_data) if crc_data else 0
    actual_crc_len = len(crc_data)

    # Tail: up to 8 non-reloc bytes beyond initial+crc region.
    reloc_set = set()
    for off, size in relocs:
        for k in range(off, off + size):
            reloc_set.add(k)

    tail: List[List[int]] = []
    pos = crc_end
    while pos < len(bytes_) and len(tail) < 8:
        if pos not in reloc_set:
            tail.append([pos, bytes_[pos]])
        pos += 1

    return {
        "initial":      initial,
        "crc_length":   actual_crc_len,
        "crc16":        crc16,
        "total_length": len(bytes_),
        "tail":         tail,
        "names":        list(names) if names else [],
        "referenced_names": [],
    }


def validator_generate_from_ranges(bytes_: bytes,
                                   masked_ranges: List[Tuple[int, int]],
                                   names: List[Dict[str, Any]],
                                   referenced: List[Dict[str, Any]],
                                   initial_length: int = INITIAL_LENGTH,
                                   crc_length: int = CRC_LENGTH) -> Dict[str, Any]:
    """Mirror of generate_from_ranges: CRC skips masked offsets to remain
    invariant under relocation."""
    if not bytes_:
        raise ValueError("InvalidPattern: empty bytes")

    init_len = min(initial_length, len(bytes_))
    initial = _apply_masks(bytes_[:init_len], [
        (off, size) for (off, size) in masked_ranges if off < init_len
    ])

    masked_set = set()
    for off, size in masked_ranges:
        for k in range(off, off + size):
            masked_set.add(k)

    crc_start = init_len
    crc_end = min(crc_start + crc_length, len(bytes_))
    crc_bytes = bytes(
        b for i, b in enumerate(bytes_[crc_start:crc_end], start=crc_start)
        if i not in masked_set
    )
    crc16 = validator_crc16_flirt(crc_bytes) if crc_bytes else 0

    tail: List[List[int]] = []
    pos = crc_end
    while pos < len(bytes_) and len(tail) < 8:
        if pos not in masked_set:
            tail.append([pos, bytes_[pos]])
        pos += 1

    return {
        "initial":      initial,
        "crc_length":   len(crc_bytes),
        "crc16":        crc16,
        "total_length": len(bytes_),
        "tail":         tail,
        "names":        list(names) if names else [],
        "referenced_names": list(referenced) if referenced else [],
    }


# ---------------------------------------------------------------------------
# Quality classification
# ---------------------------------------------------------------------------

def _quality_from_ratio(ratio: float) -> str:
    if ratio <= 0.20:
        return "High"
    if ratio <= 0.40:
        return "Medium"
    return "Low"


def validator_generate_pattern_with_quality(bytes_: bytes,
                                            name: str) -> Dict[str, Any]:
    ranges = validator_scan_x86_masks(bytes_)
    pattern = validator_generate_from_ranges(
        bytes_, ranges,
        names=[{"name": name, "offset": 0, "is_public": True}],
        referenced=[],
    )
    init = pattern["initial"]
    masked = sum(1 for b in init if b is None)
    total = len(init)
    ratio = (masked / total) if total else 0.0
    return {
        "pattern":      pattern,
        "masked_bytes": masked,
        "total_bytes":  total,
        "mask_ratio":   ratio,
        "quality":      _quality_from_ratio(ratio),
    }


def validator_generate_batch(functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """functions = [{ name, bytes:[..], relocs:[[off,size],...] }, ...]
    Drops entries that fail to generate (matches crate behaviour)."""
    out: List[Dict[str, Any]] = []
    for fn in functions:
        try:
            pat = validator_generate_pattern(
                bytes(fn["bytes"]),
                [tuple(r) for r in fn.get("relocs", [])],
                [{"name": fn["name"], "offset": 0, "is_public": True}],
            )
            out.append(pat)
        except Exception:
            continue
    return out


# ---------------------------------------------------------------------------
# ELF parser (function symbols + per-section relocation map)
# ---------------------------------------------------------------------------

def _read(fmt: str, data: bytes, off: int) -> tuple:
    size = struct.calcsize(fmt)
    if off + size > len(data):
        raise ValueError(f"truncated read at 0x{off:x}")
    return struct.unpack_from(fmt, data, off)


def validator_parse_elf_functions(data: bytes) -> List[Dict[str, Any]]:
    """Parse an ELF object and return a list of
        { name, bytes:[...], relocs:[[off,size],...] }
    one entry per STT_FUNC symbol with size>0 and a valid section.
    """
    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise ValueError("ParseError: bad ELF magic")

    ei_class = data[4]  # 1=ELF32, 2=ELF64
    ei_data = data[5]   # 1=LE, 2=BE
    endian = "<" if ei_data == 1 else ">"

    if ei_class == 1:
        # Ehdr32: e_ident[16], e_type(H), e_machine(H), e_version(I),
        # e_entry(I), e_phoff(I), e_shoff(I), e_flags(I),
        # e_ehsize(H), e_phentsize(H), e_phnum(H), e_shentsize(H),
        # e_shnum(H), e_shstrndx(H)
        ehdr = struct.unpack_from(endian + "HHIIIIIHHHHHH", data, 16)
        e_shoff = ehdr[6]
        e_shentsize = ehdr[9]
        e_shnum = ehdr[10]
        e_shstrndx = ehdr[12]
        sh_fmt = endian + "IIIIIIIIII"  # 10*u32
        sh_size = struct.calcsize(sh_fmt)
        sym_fmt = endian + "IIIBBH"      # st_name,st_value,st_size,info,other,shndx
        sym_size = struct.calcsize(sym_fmt)
        rel_fmt = endian + "II"          # r_offset, r_info
        rela_fmt = endian + "IIi"        # r_offset, r_info, r_addend
    elif ei_class == 2:
        # Ehdr64
        ehdr = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
        e_shoff = ehdr[5]
        e_shentsize = ehdr[8]
        e_shnum = ehdr[9]
        e_shstrndx = ehdr[11]
        sh_fmt = endian + "IIQQQQIIQQ"   # name,type,flags,addr,offset,size,link,info,addralign,entsize
        sh_size = struct.calcsize(sh_fmt)
        sym_fmt = endian + "IBBHQQ"      # st_name,info,other,shndx,st_value,st_size
        sym_size = struct.calcsize(sym_fmt)
        rel_fmt = endian + "QQ"
        rela_fmt = endian + "QQq"
    else:
        raise ValueError(f"ParseError: bad EI_CLASS {ei_class}")

    # Section headers
    sections: List[Dict[str, Any]] = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh = struct.unpack_from(sh_fmt, data, off)
        if ei_class == 1:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size_, sh_link, sh_info, sh_align, sh_entsize = sh
        else:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size_, sh_link, sh_info, sh_align, sh_entsize = sh
        sections.append({
            "name_off": sh_name,
            "type":     sh_type,
            "flags":    sh_flags,
            "addr":     sh_addr,
            "offset":   sh_offset,
            "size":     sh_size_,
            "link":     sh_link,
            "info":     sh_info,
            "entsize":  sh_entsize,
        })

    if e_shstrndx >= len(sections):
        raise ValueError("ParseError: bad e_shstrndx")
    shstrtab = sections[e_shstrndx]
    shstr = data[shstrtab["offset"]:shstrtab["offset"] + shstrtab["size"]]

    def _cstr(buf: bytes, off: int) -> str:
        end = buf.find(b"\x00", off)
        if end < 0:
            end = len(buf)
        return buf[off:end].decode("utf-8", errors="replace")

    for s in sections:
        s["name"] = _cstr(shstr, s["name_off"])

    # Locate .symtab / .strtab
    symtab = next((s for s in sections if s["type"] == 2), None)  # SHT_SYMTAB
    if symtab is None:
        return []
    strtab = sections[symtab["link"]]
    strdata = data[strtab["offset"]:strtab["offset"] + strtab["size"]]
    symdata = data[symtab["offset"]:symtab["offset"] + symtab["size"]]
    nsyms = symtab["size"] // sym_size

    # Build reloc map: section_index -> [(offset, size), ...]
    reloc_map: Dict[int, List[Tuple[int, int]]] = {}
    for s in sections:
        if s["type"] not in (4, 9):   # SHT_RELA=4, SHT_REL=9
            continue
        target = s["info"]
        is_rela = (s["type"] == 4)
        entsize = s["entsize"] or (struct.calcsize(rela_fmt if is_rela else rel_fmt))
        n = s["size"] // entsize
        entries: List[Tuple[int, int]] = []
        for k in range(n):
            ent_off = s["offset"] + k * entsize
            if is_rela:
                r_offset, r_info, r_addend = struct.unpack_from(rela_fmt, data, ent_off)
                # In the crate, RELA addends are folded in for ELF32 — we just
                # treat the reloc as covering an arch-dependent slot; assume 4.
                entries.append((int(r_offset), 4))
            else:
                r_offset, r_info = struct.unpack_from(rel_fmt, data, ent_off)
                entries.append((int(r_offset), 4))
        reloc_map.setdefault(target, []).extend(entries)

    out: List[Dict[str, Any]] = []
    for i in range(nsyms):
        ent_off = i * sym_size
        if ei_class == 1:
            st_name, st_value, st_size, st_info, st_other, st_shndx = \
                struct.unpack_from(sym_fmt, symdata, ent_off)
        else:
            st_name, st_info, st_other, st_shndx, st_value, st_size = \
                struct.unpack_from(sym_fmt, symdata, ent_off)
        st_type = st_info & 0xF
        if st_type != 2:           # STT_FUNC=2
            continue
        if st_size == 0:
            continue
        if st_shndx == 0 or st_shndx >= len(sections):
            continue
        sec = sections[st_shndx]
        start = sec["offset"] + st_value
        end = start + st_size
        if end > len(data):
            continue
        name = _cstr(strdata, st_name)
        fn_bytes = data[start:end]
        sec_relocs = reloc_map.get(st_shndx, [])
        rels: List[List[int]] = []
        for r_off, r_size in sec_relocs:
            rel = r_off - st_value
            if 0 <= rel < st_size and rel <= 0xFFFF:
                rels.append([rel, r_size])
        out.append({
            "name":   name,
            "bytes":  list(fn_bytes),
            "relocs": rels,
        })
    return out


# ---------------------------------------------------------------------------
# LibraryBuilder
# ---------------------------------------------------------------------------

def validator_dedup_patterns(patterns: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    seen = set()
    out: List[Dict[str, Any]] = []
    removed = 0
    for p in patterns:
        hex_ = "".join("XX" if b is None else f"{int(b):02X}" for b in p["initial"])
        primary = ""
        if p.get("names"):
            primary = p["names"][0].get("name", "")
        key = (hex_, int(p.get("crc16", 0)), int(p.get("crc_length", 0)), primary)
        if key in seen:
            removed += 1
            continue
        seen.add(key)
        out.append(p)
    return out, removed


def validator_library_build(name: str,
                            arch: str,
                            os_: str,
                            functions: List[Dict[str, Any]],
                            elf_bytes_list: Optional[List[bytes]] = None,
                            dedup: bool = True) -> Dict[str, Any]:
    patterns: List[Dict[str, Any]] = []
    skipped = 0
    processed = 0

    for fn in functions:
        processed += 1
        try:
            pat = validator_generate_pattern(
                bytes(fn["bytes"]),
                [tuple(r) for r in fn.get("relocs", [])],
                [{"name": fn["name"], "offset": 0, "is_public": True}],
            )
            patterns.append(pat)
        except Exception:
            skipped += 1

    if elf_bytes_list:
        for elf in elf_bytes_list:
            for fn in validator_parse_elf_functions(elf):
                processed += 1
                try:
                    pat = validator_generate_pattern(
                        bytes(fn["bytes"]),
                        [tuple(r) for r in fn["relocs"]],
                        [{"name": fn["name"], "offset": 0, "is_public": True}],
                    )
                    patterns.append(pat)
                except Exception:
                    skipped += 1

    duplicates_removed = 0
    if dedup:
        patterns, duplicates_removed = validator_dedup_patterns(patterns)

    return {
        "library": {
            "name":     name,
            "arch":     arch,
            "os":       os_,
            "patterns": patterns,
        },
        "stats": {
            "functions_processed": processed,
            "patterns_generated":  len(patterns),
            "patterns_skipped":    skipped,
            "duplicates_removed":  duplicates_removed,
        },
    }


# ---------------------------------------------------------------------------
# Arch / SigWriter
# ---------------------------------------------------------------------------

_ARCH_TABLE = {
    "X86": 0, "Z80": 1, "I860": 2, "8051": 3, "Tms": 4, "6502": 5,
    "Pdp": 6, "68K": 7, "Java": 8, "6800": 9, "St7": 10, "Mc6812": 11,
    "Mips": 12, "ArmOld": 13, "Tms390c6": 14, "Ppc": 15, "Ia64": 16,
    "Arm64": 128, "X64": 132, "Unknown": 255,
}


def validator_sig_writer_build(patterns: List[Dict[str, Any]],
                               lib_name: str,
                               arch: int = 75,
                               file_types: int = 0,
                               os_types: int = 0,
                               app_types: int = 0,
                               feature_flags: int = 0) -> bytes:
    """Emit an IDASGN v9-shaped header (104 bytes) followed by an encoded trie.

    The crate uses arch=75 by default (raw x86_64 marker), and writes a
    104-byte header whose first 20 bytes are CRC-16/IBM-protected.
    """
    name_bytes = lib_name.encode("utf-8")
    # Build first 20 bytes that will be CRC'd
    pre = bytearray()
    pre += b"IDASGN"                       # 6
    pre.append(9)                          # version
    pre.append(arch & 0xFF)                # arch
    pre += int(file_types & 0xFFFFFFFF).to_bytes(4, "little")
    pre += int(os_types & 0xFFFF).to_bytes(2, "little")
    pre += int(app_types & 0xFFFF).to_bytes(2, "little")
    pre += int(feature_flags & 0xFFFF).to_bytes(2, "little")
    # Pad pre to 20 bytes (header CRC covers the first 20 bytes).
    if len(pre) < 20:
        pre += b"\x00" * (20 - len(pre))
    pre = pre[:20]
    crc = validator_crc16_sig_header(bytes(pre))

    header = bytearray(104)
    header[:20] = pre
    header[20:22] = int(crc).to_bytes(2, "little")
    # ctype 12 bytes zero; name_len at 31, n_functions at 32..34
    name_len = min(len(name_bytes), 255)
    header[31] = name_len
    header[32:34] = int(len(patterns) & 0xFFFF).to_bytes(2, "little")
    end = 34 + name_len
    if end <= 104:
        header[34:end] = name_bytes[:name_len]

    # Minimal trie: one leaf per pattern under a single branch with empty prefix.
    trie = bytearray()
    trie += validator_encode_trie_root(patterns)
    return bytes(header) + bytes(trie)


def _enc_len_prefixed(buf: bytearray, payload: bytes) -> None:
    buf.append(len(payload) & 0xFF)
    buf += payload


def validator_encode_trie_root(patterns: List[Dict[str, Any]]) -> bytes:
    """Encode a degenerate single-branch trie holding all patterns as leaves.

    Format (mirrors SigTrieNode::encode):
      Branch:   len:u8  prefix:bytes  children_count:u8 (terminator 0x00 follows last child)
      Leaf:     len:u8  prefix:bytes  flags=1:u8  crc_len:u8  crc16:u16 LE
                module_offset:u16 LE  name_len:u8  name:bytes
    """
    buf = bytearray()
    # Root branch: empty prefix
    buf.append(0)            # prefix len = 0
    # No real children grouping; emit each pattern as a leaf, terminated by 0.
    for p in patterns:
        # Leaf prefix = initial bytes with wildcards as 0xCC placeholder
        prefix = bytes((b if b is not None else 0xCC) for b in p["initial"])
        _enc_len_prefixed(buf, prefix)
        buf.append(1)        # leaf flag
        buf.append(int(p.get("crc_length", 0)) & 0xFF)
        buf += int(p.get("crc16", 0) & 0xFFFF).to_bytes(2, "little")
        buf += int(p.get("total_length", 0) & 0xFFFF).to_bytes(2, "little")
        nm = ""
        if p.get("names"):
            nm = p["names"][0].get("name", "")
        nb = nm.encode("utf-8")[:255]
        buf.append(len(nb))
        buf += nb
    buf.append(0)            # child sentinel terminates branch
    return bytes(buf)


def validator_write_sig_file(path: str,
                             patterns: List[Dict[str, Any]],
                             lib_name: str,
                             arch: int = 75) -> int:
    data = validator_sig_writer_build(patterns, lib_name, arch=arch)
    with open(path, "wb") as f:
        f.write(data)
    return len(data)


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def _bytes_arg(a: Any) -> bytes:
    if isinstance(a, str):
        return bytes.fromhex(a)
    return bytes(a)


_DISPATCH = {
    "crc16_flirt":
        lambda a: validator_crc16_flirt(_bytes_arg(a["data"])),
    "crc16_sig_header":
        lambda a: validator_crc16_sig_header(_bytes_arg(a["data"])),
    "scan_x86_masks":
        lambda a: validator_scan_x86_masks(_bytes_arg(a["bytes"])),
    "generate_pattern":
        lambda a: validator_generate_pattern(
            _bytes_arg(a["bytes"]),
            [tuple(r) for r in a.get("relocs", [])],
            a.get("names", []),
            a.get("initial_length", INITIAL_LENGTH),
            a.get("crc_length", CRC_LENGTH),
        ),
    "generate_from_ranges":
        lambda a: validator_generate_from_ranges(
            _bytes_arg(a["bytes"]),
            [tuple(r) for r in a.get("masked_ranges", [])],
            a.get("names", []),
            a.get("referenced", []),
            a.get("initial_length", INITIAL_LENGTH),
            a.get("crc_length", CRC_LENGTH),
        ),
    "generate_batch":
        lambda a: validator_generate_batch(a["functions"]),
    "generate_pattern_with_quality":
        lambda a: validator_generate_pattern_with_quality(
            _bytes_arg(a["bytes"]), a.get("name", "")
        ),
    "parse_elf_functions":
        lambda a: validator_parse_elf_functions(_bytes_arg(a["data"])),
    "library_build":
        lambda a: validator_library_build(
            a.get("name", "lib"),
            a.get("arch", "X64"),
            a.get("os", "Unknown"),
            a.get("functions", []),
            [_bytes_arg(e) for e in a.get("elf_bytes_list", [])],
            bool(a.get("dedup", True)),
        ),
    "dedup_patterns":
        lambda a: (lambda r: {"patterns": r[0], "duplicates_removed": r[1]})(
            validator_dedup_patterns(a["patterns"])
        ),
    "sig_writer_build":
        lambda a: validator_sig_writer_build(
            a["patterns"], a.get("lib_name", ""),
            a.get("arch", 75), a.get("file_types", 0),
            a.get("os_types", 0), a.get("app_types", 0),
            a.get("feature_flags", 0),
        ).hex(),
    "encode_trie_root":
        lambda a: validator_encode_trie_root(a["patterns"]).hex(),
    "write_sig_file":
        lambda a: validator_write_sig_file(
            a["path"], a["patterns"], a.get("lib_name", ""),
            a.get("arch", 75),
        ),
    "quality_from_ratio":
        lambda a: _quality_from_ratio(float(a["ratio"])),
    "flirt_arch_to_u8":
        lambda a: _ARCH_TABLE.get(str(a["s"]), 255),
}


def dispatch(req: Dict[str, Any]) -> Dict[str, Any]:
    fn = req.get("function")
    if fn not in _DISPATCH:
        return {"function": fn, "error": f"unknown function: {fn}"}
    try:
        out = _DISPATCH[fn](req.get("input", {}))
    except Exception as e:
        return {"function": fn, "error": f"{type(e).__name__}: {e}"}
    return {"function": fn, "output": out}


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _selftest() -> Dict[str, Any]:
    results: Dict[str, Any] = {}

    # CRCs
    results["crc16_flirt_empty"]   = hex(validator_crc16_flirt(b""))
    results["crc16_flirt_123"]     = hex(validator_crc16_flirt(b"123456789"))
    results["crc16_sig_hdr_empty"] = hex(validator_crc16_sig_header(b""))
    results["crc16_sig_hdr_123"]   = hex(validator_crc16_sig_header(b"123456789"))

    # x86 mask scan: CALL rel32 + RET
    sample = bytes([0xE8, 0x11, 0x22, 0x33, 0x44, 0xC3])
    results["scan_call_rel32"] = validator_scan_x86_masks(sample)

    # generate_pattern: short function with one reloc
    pat = validator_generate_pattern(
        bytes([0x55, 0x48, 0x89, 0xE5, 0xE8, 0xAA, 0xBB, 0xCC, 0xDD, 0xC9, 0xC3]),
        [(5, 4)],
        [{"name": "f", "offset": 0, "is_public": True}],
    )
    results["pattern_initial_len"] = len(pat["initial"])
    results["pattern_wc_count"]    = sum(1 for b in pat["initial"] if b is None)

    # quality
    q = validator_generate_pattern_with_quality(sample + sample, "g")
    results["quality"] = q["quality"]
    results["mask_ratio"] = round(q["mask_ratio"], 4)

    # dedup
    deduped, removed = validator_dedup_patterns([pat, pat])
    results["dedup_removed"] = removed
    results["dedup_kept"]    = len(deduped)

    # sig writer header CRC round-trip
    data = validator_sig_writer_build([pat], "demo")
    results["sig_header_magic"] = data[:6].decode("ascii", errors="replace")
    results["sig_header_arch"]  = data[7]
    results["sig_total_bytes"]  = len(data)

    # write_sig_file
    tmp = os.path.join(tempfile.gettempdir(), "rustre_flirt_gen_selftest.sig")
    n = validator_write_sig_file(tmp, [pat], "demo")
    results["sig_file_bytes"]   = n
    results["sig_file_path"]    = tmp

    return results


def main() -> None:
    data = sys.stdin.read() if not sys.stdin.isatty() else ""
    if data.strip():
        try:
            req = json.loads(data)
        except json.JSONDecodeError as e:
            print(json.dumps({"error": f"bad json: {e}"}))
            return
        if isinstance(req, list):
            print(json.dumps([dispatch(r) for r in req], indent=2))
        else:
            print(json.dumps(dispatch(req), indent=2))
        return

    print(json.dumps({"selftest": _selftest()}, indent=2, default=str))


if __name__ == "__main__":
    main()
