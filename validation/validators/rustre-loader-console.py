#!/usr/bin/env python3
"""Independent stdlib validators for rustre-loader-console header parsers.

Mirrors the documented behavior in reports/rustre-loader-console.md without
depending on the Rust crate. Validates: xor_checksum, NES (iNES) header,
SNES header parsing/scoring, Game Boy header checksum + logo, GBA branch
sniff, and format magic detection.
"""

from __future__ import annotations

import struct
import sys
from dataclasses import dataclass
from typing import Optional, Tuple


# ---------- magic helpers ----------

NES_MAGIC = b"NES\x1a"
NES_PRG_BANK_SIZE = 16 * 1024
NES_CHR_BANK_SIZE = 8 * 1024

GB_LOGO = bytes([
    0xCE, 0xED, 0x66, 0x66, 0xCC, 0x0D, 0x00, 0x0B, 0x03, 0x73, 0x00, 0x83,
    0x00, 0x0C, 0x00, 0x0D, 0x00, 0x08, 0x11, 0x1F, 0x88, 0x89, 0x00, 0x0E,
    0xDC, 0xCC, 0x6E, 0xE6, 0xDD, 0xDD, 0xD9, 0x99, 0xBB, 0xBB, 0x67, 0x63,
    0x6E, 0x0E, 0xEC, 0xCC, 0xDD, 0xDC, 0x99, 0x9F, 0xBB, 0xB9, 0x33, 0x3E,
])

SNES_LOROM_HEADER_OFFSET = 0x7FB0
SNES_HIROM_HEADER_OFFSET = 0xFFB0
SNES_EXLOROM_HEADER_OFFSET = 0x40FFB0
SNES_EXHIROM_HEADER_OFFSET = 0x40FFB0  # symbolic; doc lists both


def xor_checksum(data: bytes, skip_offset: Optional[int] = None) -> int:
    acc = 0
    for i, b in enumerate(data):
        if skip_offset is not None and i == skip_offset:
            continue
        acc ^= b
    return acc & 0xFF


# ---------- format detection ----------

def detect_format(data: bytes) -> Optional[str]:
    if len(data) >= 2 and data[:2] == b"MZ":
        return "pe"
    if len(data) >= 4 and data[:4] == b"\x7fELF":
        return "elf"
    if len(data) >= 4 and data[:4] == b"\xCA\xFE\xBA\xBE":
        return "java-class"
    if len(data) >= 4 and data[:4] == b"\x1bLua":
        return "lua-bytecode"
    if len(data) >= 3 and data[:3] == b"\x1bLJ":
        return "luajit-bytecode"
    if len(data) >= 4 and data[:4] == b"dex\n":
        return "dex"
    if len(data) >= 2 and data[:2] == b"PK":
        return "zip"
    if len(data) >= 4 and data[:4] == b"%PDF":
        return "pdf"
    if len(data) >= 8 and data[:8] == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":
        return "ole2"
    if len(data) >= 2 and data[:2] == b"\x1f\x8b":
        return "gzip"
    if is_nes(data):
        return "nes"
    if is_snes(data):
        return "snes"
    if is_gb(data):
        return "gameboy"
    if is_gba(data):
        return "gba"
    if is_genesis(data):
        return "genesis"
    return None


def is_nes(data: bytes) -> bool:
    return len(data) >= 16 and data[:4] == NES_MAGIC


def is_gb(data: bytes) -> bool:
    return len(data) >= 0x0134 and data[0x0104:0x0104 + 48] == GB_LOGO


def is_gba(data: bytes) -> bool:
    # GBA cart entry is an ARM branch (B) instruction: top byte 0xEA
    return len(data) >= 0xC0 and data[3] == 0xEA


def is_genesis(data: bytes) -> bool:
    if len(data) < 0x200:
        return False
    return data[0x100:0x110] in (b"SEGA MEGA DRIVE ", b"SEGA GENESIS    ")


def is_snes(data: bytes) -> bool:
    return snes_score(data, SNES_LOROM_HEADER_OFFSET) >= 4 or \
           snes_score(data, SNES_HIROM_HEADER_OFFSET) >= 4


def snes_score(data: bytes, off: int) -> int:
    if len(data) < off + 0x30:
        return 0
    title = data[off:off + 21]
    score = 0
    if all(0x20 <= b < 0x7f or b == 0 for b in title):
        score += 2
    comp = struct.unpack_from("<H", data, off + 0x2C)[0]
    csum = struct.unpack_from("<H", data, off + 0x2E)[0]
    if (comp ^ csum) == 0xFFFF:
        score += 4
    return score


# ---------- NES header ----------

@dataclass
class NesHeader:
    prg_banks: int
    chr_banks: int
    flag6: int
    flag7: int
    flag9: int
    mapper: int
    has_trainer: bool
    has_battery: bool

    @classmethod
    def parse(cls, data: bytes) -> "NesHeader":
        if len(data) < 16 or data[:4] != NES_MAGIC:
            raise ValueError("not iNES")
        prg = data[4]
        chr_ = data[5]
        f6 = data[6]
        f7 = data[7]
        f9 = data[9]
        mapper = (f7 & 0xF0) | (f6 >> 4)
        return cls(prg, chr_, f6, f7, f9, mapper,
                   bool(f6 & 0x04), bool(f6 & 0x02))

    def prg_rom_size(self) -> int:
        return self.prg_banks * NES_PRG_BANK_SIZE

    def chr_rom_size(self) -> int:
        return self.chr_banks * NES_CHR_BANK_SIZE

    def prg_rom_offset(self) -> int:
        return 16 + (512 if self.has_trainer else 0)


# ---------- Game Boy header ----------

def gb_verify_header_checksum(data: bytes) -> bool:
    if len(data) < 0x150:
        return False
    x = 0
    for i in range(0x0134, 0x014D):
        x = (x - data[i] - 1) & 0xFF
    return x == data[0x014D]


def gb_logo_ok(data: bytes) -> bool:
    return is_gb(data)


# ---------- self-tests ----------

def make_nes() -> bytes:
    hdr = bytearray(16)
    hdr[0:4] = NES_MAGIC
    hdr[4] = 2          # 2 PRG banks
    hdr[5] = 1          # 1 CHR bank
    hdr[6] = 0x12       # mapper low=1, battery=1
    hdr[7] = 0x30       # mapper high=3 -> mapper 0x31
    body = hdr + b"\x00" * (2 * NES_PRG_BANK_SIZE + NES_CHR_BANK_SIZE)
    return bytes(body)


def make_gb() -> bytes:
    buf = bytearray(0x8000)
    buf[0x0104:0x0104 + 48] = GB_LOGO
    # fill 0x0134..0x014C with deterministic data
    for i in range(0x0134, 0x014D):
        buf[i] = (i & 0xFF)
    x = 0
    for i in range(0x0134, 0x014D):
        x = (x - buf[i] - 1) & 0xFF
    buf[0x014D] = x
    return bytes(buf)


def make_snes_lorom() -> bytes:
    buf = bytearray(0x10000)
    off = SNES_LOROM_HEADER_OFFSET
    title = b"TEST CART            "[:21]
    buf[off:off + 21] = title
    # complement+checksum that XOR to 0xFFFF
    csum = 0x1234
    comp = csum ^ 0xFFFF
    struct.pack_into("<H", buf, off + 0x2C, comp)
    struct.pack_into("<H", buf, off + 0x2E, csum)
    return bytes(buf)


def make_gba() -> bytes:
    buf = bytearray(0xC0)
    # B instruction: cond=E, op=A
    buf[0] = 0x00
    buf[1] = 0x00
    buf[2] = 0x00
    buf[3] = 0xEA
    return bytes(buf)


def run_tests() -> Tuple[int, int]:
    passed = 0
    failed = 0

    def check(name, cond):
        nonlocal passed, failed
        if cond:
            passed += 1
        else:
            failed += 1
            print(f"FAIL: {name}", file=sys.stderr)

    # xor_checksum
    check("xor_empty", xor_checksum(b"") == 0)
    check("xor_basic", xor_checksum(b"\x01\x02\x03") == 0x00)
    check("xor_skip", xor_checksum(b"\x01\x02\x03", skip_offset=1) == 0x02)

    # NES
    nes = make_nes()
    check("is_nes", is_nes(nes))
    h = NesHeader.parse(nes)
    check("nes_prg_banks", h.prg_banks == 2)
    check("nes_chr_banks", h.chr_banks == 1)
    check("nes_mapper", h.mapper == 0x31)
    check("nes_battery", h.has_battery is True)
    check("nes_no_trainer", h.has_trainer is False)
    check("nes_prg_size", h.prg_rom_size() == 2 * NES_PRG_BANK_SIZE)
    check("nes_chr_size", h.chr_rom_size() == NES_CHR_BANK_SIZE)
    check("nes_prg_off_no_trainer", h.prg_rom_offset() == 16)

    # GB
    gb = make_gb()
    check("is_gb", is_gb(gb))
    check("gb_checksum", gb_verify_header_checksum(gb))
    check("gb_logo_ok", gb_logo_ok(gb))
    # break checksum
    bad = bytearray(gb)
    bad[0x014D] ^= 0xFF
    check("gb_checksum_bad", not gb_verify_header_checksum(bytes(bad)))

    # SNES
    sn = make_snes_lorom()
    check("snes_lorom_score", snes_score(sn, SNES_LOROM_HEADER_OFFSET) >= 4)
    check("is_snes", is_snes(sn))

    # GBA
    gba = make_gba()
    check("is_gba", is_gba(gba))
    check("not_gba_short", not is_gba(b"\x00\x00\x00\xEA"))

    # detect_format
    check("detect_pe", detect_format(b"MZ\x00\x00") == "pe")
    check("detect_elf", detect_format(b"\x7fELF\x00") == "elf")
    check("detect_zip", detect_format(b"PK\x03\x04") == "zip")
    check("detect_gzip", detect_format(b"\x1f\x8b\x08\x00") == "gzip")
    check("detect_nes", detect_format(nes) == "nes")
    check("detect_gb", detect_format(gb) == "gameboy")
    check("detect_snes", detect_format(sn) == "snes")
    check("detect_gba", detect_format(gba) == "gba")
    check("detect_none", detect_format(b"garbage") is None)

    return passed, failed


if __name__ == "__main__":
    p, f = run_tests()
    print(f"passed={p} failed={f}")
    sys.exit(0 if f == 0 else 1)
