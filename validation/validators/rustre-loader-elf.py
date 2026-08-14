#!/usr/bin/env python3
"""
Standalone validator for the `rustre-loader-elf` crate.

Reimplements the externally-verifiable behavior of the crate in pure Python,
using stdlib + optional lief/pyelftools (auto-installed via pip if missing).

NO import of the Rust crate. NO MCP calls.

Usage:
    echo '{"fn": "gnu_hash", "input": {"name": "printf"}}' | python rustre-loader-elf.py
    python rustre-loader-elf.py            # runs main() self-tests
"""
from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
from typing import Any


# ---------------------------------------------------------------------------
# Optional deps bootstrap
# ---------------------------------------------------------------------------
def _ensure(pkg: str, import_name: str | None = None):
    name = import_name or pkg
    try:
        return __import__(name)
    except ImportError:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", pkg]
        )
        return __import__(name)


# pyelftools is the python reference for ELF parsing
try:
    elftools = _ensure("pyelftools", "elftools")
except Exception:
    elftools = None

try:
    lief = _ensure("lief")
except Exception:
    lief = None


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------
def validator_can_load(data: bytes) -> bool:
    """ElfLoader::can_load — true iff first 4 bytes are \\x7fELF."""
    return len(data) >= 4 and data[:4] == b"\x7fELF"


def validator_gnu_hash(name: bytes) -> int:
    """gnu_hash(name) — canonical DJB-derived GNU hash (h=5381; h=h*33+b)."""
    h = 5381
    for b in name:
        h = (h * 33 + b) & 0xFFFFFFFF
    return h


def validator_gnu_hash_str(name: str) -> int:
    return validator_gnu_hash(name.encode("utf-8"))


def validator_is_stripped(path: str) -> bool:
    """ElfInfo::is_stripped — true iff no .symtab section is present."""
    from elftools.elf.elffile import ELFFile
    with open(path, "rb") as f:
        elf = ELFFile(f)
        return elf.get_section_by_name(".symtab") is None


def validator_build_id(path: str) -> str | None:
    """ElfInfo::build_id — return hex string of GNU build-id, or None."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import NoteSection
    with open(path, "rb") as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            if not isinstance(section, NoteSection):
                continue
            for note in section.iter_notes():
                if note["n_type"] == "NT_GNU_BUILD_ID":
                    desc = note["n_desc"]
                    if isinstance(desc, str):
                        # pyelftools sometimes returns hex string already
                        return desc.lower()
                    return desc.hex()
    return None


def validator_debug_link(path: str) -> str | None:
    """ElfInfo::debug_link — content of .gnu_debuglink (filename only)."""
    from elftools.elf.elffile import ELFFile
    with open(path, "rb") as f:
        elf = ELFFile(f)
        sec = elf.get_section_by_name(".gnu_debuglink")
        if sec is None:
            return None
        data = sec.data()
        # NUL-terminated filename, followed by padding + 4-byte CRC
        nul = data.find(b"\x00")
        if nul < 0:
            return None
        return data[:nul].decode("utf-8", errors="replace")


def validator_relocation_count(path: str) -> int:
    """ElfInfo::relocation_count — total entries across all RELA/REL sections."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection
    total = 0
    with open(path, "rb") as f:
        elf = ELFFile(f)
        for sec in elf.iter_sections():
            if isinstance(sec, RelocationSection):
                total += sec.num_relocations()
    return total


def validator_needed_libs(path: str) -> list[str]:
    """ElfInfo.needed_libs — DT_NEEDED entries from .dynamic."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
    out: list[str] = []
    with open(path, "rb") as f:
        elf = ELFFile(f)
        for sec in elf.iter_sections():
            if isinstance(sec, DynamicSection):
                for t in sec.iter_tags("DT_NEEDED"):
                    out.append(t.needed)
    return out


def validator_soname(path: str) -> str | None:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
    with open(path, "rb") as f:
        elf = ELFFile(f)
        for sec in elf.iter_sections():
            if isinstance(sec, DynamicSection):
                for t in sec.iter_tags("DT_SONAME"):
                    return t.soname
    return None


def validator_rpath(path: str) -> list[str]:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
    out: list[str] = []
    with open(path, "rb") as f:
        elf = ELFFile(f)
        for sec in elf.iter_sections():
            if isinstance(sec, DynamicSection):
                for tag in ("DT_RPATH", "DT_RUNPATH"):
                    for t in sec.iter_tags(tag):
                        val = t.rpath if tag == "DT_RPATH" else t.runpath
                        out.extend(val.split(":"))
    return [p for p in out if p]


def validator_interpreter(path: str) -> str | None:
    """ElfInfo.interpreter — string in PT_INTERP segment."""
    from elftools.elf.elffile import ELFFile
    with open(path, "rb") as f:
        elf = ELFFile(f)
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_INTERP":
                data = seg.get_interp_name()
                return data
    return None


def validator_header(path: str) -> dict[str, Any]:
    """ElfInfo::parse scalars — arch / bits / endian / type / entry."""
    from elftools.elf.elffile import ELFFile
    with open(path, "rb") as f:
        elf = ELFFile(f)
        hdr = elf.header
        return {
            "bits": 64 if elf.elfclass == 64 else 32,
            "endian": "little" if elf.little_endian else "big",
            "arch": hdr["e_machine"],
            "elf_type": hdr["e_type"],
            "entry": int(hdr["e_entry"]),
        }


def validator_pt_load_segments(path: str) -> list[dict[str, Any]]:
    """ElfLoader::load — PT_LOAD segments with vaddr/filesz/memsz/perms."""
    from elftools.elf.elffile import ELFFile
    out = []
    with open(path, "rb") as f:
        elf = ELFFile(f)
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            flags = seg["p_flags"]
            out.append({
                "vaddr": int(seg["p_vaddr"]),
                "filesz": int(seg["p_filesz"]),
                "memsz": int(seg["p_memsz"]),
                "read": bool(flags & 0x4),
                "write": bool(flags & 0x2),
                "execute": bool(flags & 0x1),
            })
    return out


def validator_plt_entries(path: str) -> list[dict[str, Any]]:
    """ElfInfo::plt_entries — names + GOT addresses from .rela.plt."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection
    out = []
    with open(path, "rb") as f:
        elf = ELFFile(f)
        relplt = (elf.get_section_by_name(".rela.plt")
                  or elf.get_section_by_name(".rel.plt"))
        if not isinstance(relplt, RelocationSection):
            return out
        symtab = elf.get_section(relplt["sh_link"])
        for r in relplt.iter_relocations():
            sym = symtab.get_symbol(r["r_info_sym"])
            out.append({
                "name": sym.name,
                "got_address": int(r["r_offset"]),
            })
    return out


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------
DISPATCH = {
    "can_load": lambda inp: validator_can_load(bytes.fromhex(inp["data_hex"])),
    "gnu_hash": lambda inp: validator_gnu_hash(inp["name"].encode("utf-8")),
    "gnu_hash_str": lambda inp: validator_gnu_hash_str(inp["name"]),
    "is_stripped": lambda inp: validator_is_stripped(inp["path"]),
    "build_id": lambda inp: validator_build_id(inp["path"]),
    "debug_link": lambda inp: validator_debug_link(inp["path"]),
    "relocation_count": lambda inp: validator_relocation_count(inp["path"]),
    "needed_libs": lambda inp: validator_needed_libs(inp["path"]),
    "soname": lambda inp: validator_soname(inp["path"]),
    "rpath": lambda inp: validator_rpath(inp["path"]),
    "interpreter": lambda inp: validator_interpreter(inp["path"]),
    "header": lambda inp: validator_header(inp["path"]),
    "pt_load_segments": lambda inp: validator_pt_load_segments(inp["path"]),
    "plt_entries": lambda inp: validator_plt_entries(inp["path"]),
}


def main() -> None:
    if not sys.stdin.isatty():
        try:
            req = json.load(sys.stdin)
        except Exception:
            req = None
        if req:
            fn = req["fn"]
            inp = req.get("input", {})
            out = DISPATCH[fn](inp)
            json.dump({"fn": fn, "output": out}, sys.stdout, default=str)
            sys.stdout.write("\n")
            return

    # Self-test with fixed inputs (no fixture file required).
    results = {
        "can_load_elf": validator_can_load(b"\x7fELF\x02\x01\x01\x00"),
        "can_load_pe":  validator_can_load(b"MZ\x90\x00"),
        "gnu_hash_empty":  validator_gnu_hash(b""),                # 5381
        "gnu_hash_printf": validator_gnu_hash_str("printf"),       # 0x156b932
        "gnu_hash_exit":   validator_gnu_hash_str("exit"),         # 0x7c967e3f
    }
    # Sanity: well-known GNU hashes
    assert results["gnu_hash_empty"] == 5381
    assert results["gnu_hash_printf"] == 0x156B932
    assert results["gnu_hash_exit"] == 0x7C967E3F
    assert results["can_load_elf"] is True
    assert results["can_load_pe"] is False
    json.dump({"selftest": "ok", "results": results}, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
