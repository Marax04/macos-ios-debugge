"""Independent validator for rustre-dotnet-edit.

Reimplements pure-logic pieces described in the analysis report:
- IlPatch::apply semantics over an instruction list with `offset` fields
- NewMethodDescriptor::encode_sig (ECMA-335 II.23.2.1 method sig blob)
- encode_instructions header selection (tiny vs fat)
- SignatureStripper::strip on a synthetic raw PE (clears CorFlags.StrongNameSigned
  bit and zeroes the StrongNameSignature data-directory entry)

Uses only the Python standard library.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from typing import List, Tuple


# ---------------------------------------------------------------------------
# IlPatch
# ---------------------------------------------------------------------------

@dataclass
class Instr:
    offset: int
    op: str


def _find_index(insns: List[Instr], offset: int) -> int:
    for i, ins in enumerate(insns):
        if ins.offset == offset:
            return i
    raise ValueError(f"InvalidIlOffset({offset})")


def apply_patch(patch: dict, insns: List[Instr]) -> None:
    kind = patch["kind"]
    if kind == "Replace":
        i = _find_index(insns, patch["offset"])
        insns[i] = Instr(patch["offset"], patch["instruction"])
    elif kind == "InsertBefore":
        i = _find_index(insns, patch["offset"])
        new = [Instr(patch["offset"], op) for op in patch["instructions"]]
        insns[i:i] = new
    elif kind == "InsertAfter":
        i = _find_index(insns, patch["offset"])
        new = [Instr(patch["offset"], op) for op in patch["instructions"]]
        insns[i + 1 : i + 1] = new
    elif kind == "Remove":
        i = _find_index(insns, patch["offset"])
        del insns[i]
    elif kind == "ReplaceRange":
        s = _find_index(insns, patch["start"])
        e = _find_index(insns, patch["end"])
        if e < s:
            raise ValueError("invalid range")
        new = [Instr(patch["start"], op) for op in patch["instructions"]]
        insns[s : e + 1] = new
    elif kind == "Prepend":
        base = insns[0].offset if insns else 0
        new = [Instr(base, op) for op in patch["instructions"]]
        insns[0:0] = new
    elif kind == "Append":
        # insert before terminal `ret` if present, else at end
        idx = len(insns)
        if insns and insns[-1].op == "ret":
            idx = len(insns) - 1
        base = insns[idx - 1].offset if idx > 0 else 0
        new = [Instr(base, op) for op in patch["instructions"]]
        insns[idx:idx] = new
    else:
        raise ValueError(f"unknown patch kind: {kind}")


# ---------------------------------------------------------------------------
# encode_sig for NewMethodDescriptor
# ---------------------------------------------------------------------------

def encode_sig(is_instance: bool, param_types: List[bytes], return_sig: bytes) -> bytes:
    cc = 0x20 if is_instance else 0x00  # HASTHIS
    n = min(len(param_types), 255)
    out = bytearray()
    out.append(cc)
    out.append(n)
    out += return_sig
    for p in param_types[:n]:
        out += p
    return bytes(out)


# ---------------------------------------------------------------------------
# encode_instructions header selection
# ---------------------------------------------------------------------------

def encode_method_body(code: bytes) -> bytes:
    """Produce the method body bytes with tiny or fat header."""
    if len(code) < 64:
        # Tiny header: (code_size << 2) | 0x2
        hdr = bytes([(len(code) << 2) | 0x02])
        return hdr + code
    # Fat header: 12 bytes
    # flags (2 bytes): 0x3003 = FatFormat | InitLocals, header size (3 dwords = nibble 3)
    flags = 0x3003
    max_stack = 8
    code_size = len(code)
    local_var_sig_tok = 0
    hdr = struct.pack("<HHII", flags, max_stack, code_size, local_var_sig_tok)
    return hdr + code


# ---------------------------------------------------------------------------
# SignatureStripper
# ---------------------------------------------------------------------------

# Minimal synthetic PE builder for testing strip()

def build_test_pe(strong_name_bit_set: bool = True) -> Tuple[bytearray, int, int, int]:
    """Build a tiny PE32 with a .text section containing a CLI header.

    Returns (bytes, cli_header_file_offset, corflags_offset, sn_dir_offset_in_cli)
    """
    buf = bytearray(0x600)
    # DOS header
    buf[0:2] = b"MZ"
    pe_off = 0x80
    struct.pack_into("<I", buf, 0x3C, pe_off)
    # PE signature
    buf[pe_off : pe_off + 4] = b"PE\x00\x00"
    coff = pe_off + 4
    # COFF header: machine, nsec=1, timestamp, ptr_to_symtab, nsyms, opt_hdr_size, characteristics
    opt_size = 224  # PE32
    struct.pack_into("<HHIIIHH", buf, coff, 0x14C, 1, 0, 0, 0, opt_size, 0)
    opt = coff + 20
    # Optional header magic PE32 = 0x10B
    buf[opt] = 0x0B
    buf[opt + 1] = 0x01
    # data directories start at opt + 96 for PE32; #14 is COM Descriptor (CLI header)
    dd_off = opt + 96
    # Section header right after optional header
    sec_off = opt + opt_size
    # Place .text at file offset 0x400, RVA 0x2000, size 0x200
    raw_off = 0x400
    rva = 0x2000
    sec_name = b".text\x00\x00\x00"
    struct.pack_into(
        "<8sIIIIIIHHI",
        buf,
        sec_off,
        sec_name,
        0x200,  # virtual size
        rva,    # virtual address
        0x200,  # size of raw data
        raw_off,  # pointer to raw data
        0,
        0,
        0,
        0,
        0x60000020,
    )
    # CLI header at start of .text
    cli_rva = rva
    cli_size = 72
    # Set COM descriptor data dir (index 14)
    com_dd = dd_off + 14 * 8
    struct.pack_into("<II", buf, com_dd, cli_rva, cli_size)
    # CLI header layout (ECMA II.25.3.3): cb(4), major(2), minor(2), MetaData rva(4)+size(4),
    # Flags(4), EntryPointToken(4), Resources rva(4)+size(4), StrongNameSignature rva(4)+size(4), ...
    flags = 0x00000008 if strong_name_bit_set else 0
    sn_rva = rva + 0x100
    sn_size = 0x80
    struct.pack_into(
        "<IHHIIIIIIII",
        buf,
        raw_off,
        cli_size, 2, 5,
        0, 0,
        flags,
        0,
        0, 0,
        sn_rva, sn_size,
    )
    corflags_offset = raw_off + 16  # after cb(4)+maj(2)+min(2)+metaRva(4)+metaSize(4) = 16
    sn_dir_in_cli = raw_off + 32   # after flags(4)+entry(4)+resRva(4)+resSize(4) past corflags
    return buf, raw_off, corflags_offset, sn_dir_in_cli


def strip_strong_name(pe: bytearray) -> None:
    if len(pe) < 0x40 or pe[0:2] != b"MZ":
        raise ValueError("not a PE")
    pe_off = struct.unpack_from("<I", pe, 0x3C)[0]
    if pe[pe_off : pe_off + 4] != b"PE\x00\x00":
        raise ValueError("missing PE sig")
    coff = pe_off + 4
    # COFF: machine(2), nsec(2), timestamp(4), ptrSym(4), nSym(4), optSize(2), char(2)
    nsec = struct.unpack_from("<H", pe, coff + 2)[0]
    opt_size = struct.unpack_from("<H", pe, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", pe, opt)[0]
    if magic == 0x10B:
        dd_off = opt + 96
    elif magic == 0x20B:
        dd_off = opt + 112
    else:
        raise ValueError("bad optional magic")
    com_dd = dd_off + 14 * 8
    cli_rva, cli_size = struct.unpack_from("<II", pe, com_dd)
    if cli_rva == 0:
        return
    sec_off = opt + opt_size
    cli_file = None
    for i in range(nsec):
        s = sec_off + i * 40
        vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", pe, s + 8)
        if vaddr <= cli_rva < vaddr + max(vsize, rsize):
            cli_file = raddr + (cli_rva - vaddr)
            break
    if cli_file is None:
        raise ValueError("CLI header section not found")
    # Clear strong-name bit in CorFlags (offset 16 within CLI header)
    flags_off = cli_file + 16
    f = struct.unpack_from("<I", pe, flags_off)[0]
    struct.pack_into("<I", pe, flags_off, f & ~0x00000008)
    # Zero StrongNameSignature dir entry (offset 32, 8 bytes)
    struct.pack_into("<II", pe, cli_file + 32, 0, 0)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def run() -> dict:
    mismatches = 0
    fixed = 0

    # Test IlPatch::Replace
    insns = [Instr(0, "nop"), Instr(1, "ldc.i4.0"), Instr(2, "ret")]
    apply_patch({"kind": "Replace", "offset": 1, "instruction": "ldc.i4.1"}, insns)
    if insns[1].op != "ldc.i4.1":
        mismatches += 1

    # InsertBefore
    apply_patch({"kind": "InsertBefore", "offset": 2, "instructions": ["nop"]}, insns)
    if [i.op for i in insns] != ["nop", "ldc.i4.1", "nop", "ret"]:
        mismatches += 1

    # Append (ret-aware)
    apply_patch({"kind": "Append", "instructions": ["pop"]}, insns)
    if insns[-1].op != "ret" or insns[-2].op != "pop":
        mismatches += 1

    # Invalid offset
    try:
        apply_patch({"kind": "Remove", "offset": 999}, insns)
        mismatches += 1
    except ValueError:
        pass

    # encode_sig static void with no params
    sig = encode_sig(False, [], b"\x01")  # VOID = 0x01
    if sig != b"\x00\x00\x01":
        mismatches += 1

    # encode_sig instance with 2 params
    sig2 = encode_sig(True, [b"\x08", b"\x08"], b"\x01")
    if sig2 != b"\x20\x02\x01\x08\x08":
        mismatches += 1

    # encode_sig clamps params at 255
    sig3 = encode_sig(False, [b"\x08"] * 300, b"\x01")
    if sig3[1] != 255:
        mismatches += 1

    # method body tiny header
    body = encode_method_body(b"\x2a")  # ret
    if body[0] != ((1 << 2) | 2) or body[1:] != b"\x2a":
        mismatches += 1

    # method body fat header
    big = b"\x00" * 100
    fat = encode_method_body(big)
    if len(fat) != 12 + 100:
        mismatches += 1
    flags, max_stack, code_size, lvsig = struct.unpack_from("<HHII", fat, 0)
    if (flags & 0x3) != 0x3 or max_stack != 8 or code_size != 100 or lvsig != 0:
        mismatches += 1

    # SignatureStripper
    pe, cli_off, corflags_off, sn_dir_off = build_test_pe(strong_name_bit_set=True)
    f_before = struct.unpack_from("<I", pe, corflags_off)[0]
    if f_before & 0x8 == 0:
        mismatches += 1
    strip_strong_name(pe)
    f_after = struct.unpack_from("<I", pe, corflags_off)[0]
    if f_after & 0x8 != 0:
        mismatches += 1
    sn_rva, sn_size = struct.unpack_from("<II", pe, sn_dir_off)
    if sn_rva != 0 or sn_size != 0:
        mismatches += 1

    return {
        "crate": "rustre-dotnet-edit",
        "fixed": fixed,
        "mismatches": mismatches,
        "match_final": mismatches == 0,
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
