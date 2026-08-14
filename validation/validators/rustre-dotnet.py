#!/usr/bin/env python3
"""Independent validator for rustre-dotnet behaviors.

Validates a few core, deterministic algorithms documented in the report:
  - CIL tiny vs fat method body header parsing
  - Branch decoding to absolute offsets
  - Branch / terminator classification
  - MethodFlags / FieldFlags / TypeFlags bit decoding (ECMA-335)
  - AssemblyVersion formatting
  - CustomAttribute.is_type matching ('Foo', '.Foo', '::Foo')

Pure Python stdlib. Exit code 0 == all checks pass.
"""
from __future__ import annotations
import struct
import sys

# ---------------------------------------------------------------------------
# ECMA-335 method body parser (tiny + fat headers)
# ---------------------------------------------------------------------------

def parse_method_body(buf: bytes):
    if not buf:
        raise ValueError("empty body")
    first = buf[0]
    # tiny: low 2 bits == 0x2, size in high 6 bits
    if (first & 0x03) == 0x02:
        code_size = first >> 2
        code = buf[1:1 + code_size]
        return {
            "fat": False,
            "max_stack": 8,
            "init_locals": False,
            "code_size": code_size,
            "code": code,
            "eh": [],
        }
    # fat: low 2 bits == 0x3
    if (first & 0x03) != 0x03:
        raise ValueError(f"unknown method header byte {first:#x}")
    flags = struct.unpack_from("<H", buf, 0)[0]
    init_locals = bool(flags & 0x0010)
    size_dwords = (flags >> 12) & 0x0F
    if size_dwords < 3:
        raise ValueError(f"fat header size dword {size_dwords} < 3")
    header_size = size_dwords * 4
    max_stack = struct.unpack_from("<H", buf, 2)[0]
    code_size = struct.unpack_from("<I", buf, 4)[0]
    code = buf[header_size:header_size + code_size]
    return {
        "fat": True,
        "max_stack": max_stack,
        "init_locals": init_locals,
        "code_size": code_size,
        "code": code,
        "eh": [],
    }


# ---------------------------------------------------------------------------
# Minimal CIL branch/terminator model
# ---------------------------------------------------------------------------

# (opcode_byte, name, operand_kind, size_incl_operand, unconditional)
SHORT_BRANCHES = {
    0x2B: ("br.s",      True,  2, True),
    0x2C: ("brfalse.s", False, 2, False),
    0x2D: ("brtrue.s",  False, 2, False),
    0x2E: ("beq.s",     False, 2, False),
    0x2F: ("bge.s",     False, 2, False),
    0x30: ("bgt.s",     False, 2, False),
    0x31: ("ble.s",     False, 2, False),
    0x32: ("blt.s",     False, 2, False),
    0x33: ("bne.un.s",  False, 2, False),
    0x34: ("bge.un.s",  False, 2, False),
    0x35: ("bgt.un.s",  False, 2, False),
    0x36: ("ble.un.s",  False, 2, False),
    0x37: ("blt.un.s",  False, 2, False),
}
LONG_BRANCHES = {
    0x38: ("br",      True,  5, True),
    0x39: ("brfalse", False, 5, False),
    0x3A: ("brtrue",  False, 5, False),
    0x3B: ("beq",     False, 5, False),
    0x3C: ("bge",     False, 5, False),
    0x3D: ("bgt",     False, 5, False),
    0x3E: ("ble",     False, 5, False),
    0x3F: ("blt",     False, 5, False),
    0x40: ("bne.un",  False, 5, False),
    0x41: ("bge.un",  False, 5, False),
    0x42: ("bgt.un",  False, 5, False),
    0x43: ("ble.un",  False, 5, False),
    0x44: ("blt.un",  False, 5, False),
}
TERMINATORS = {
    0x2A: "ret",
    0x7A: "throw",
    0xDC: "endfinally",
    0xDD: "leave",
    0xDE: "leave.s",
}


def decode_branch_target(code: bytes, offset: int):
    """Return (opcode, abs_target, size, is_branch, is_uncond) or None."""
    op = code[offset]
    if op in SHORT_BRANCHES:
        name, uncond, size, _ = SHORT_BRANCHES[op]
        rel = struct.unpack_from("<b", code, offset + 1)[0]
        target = offset + size + rel
        return (name, target, size, True, uncond)
    if op in LONG_BRANCHES:
        name, uncond, size, _ = LONG_BRANCHES[op]
        rel = struct.unpack_from("<i", code, offset + 1)[0]
        target = offset + size + rel
        return (name, target, size, True, uncond)
    if op == 0xDE:  # leave.s
        rel = struct.unpack_from("<b", code, offset + 1)[0]
        return ("leave.s", offset + 2 + rel, 2, False, True)
    if op == 0xDD:  # leave
        rel = struct.unpack_from("<i", code, offset + 1)[0]
        return ("leave", offset + 5 + rel, 5, False, True)
    return None


def is_terminator(op: int) -> bool:
    if op in TERMINATORS:
        return True
    if op in LONG_BRANCHES and LONG_BRANCHES[op][1]:  # br
        return True
    if op in SHORT_BRANCHES and SHORT_BRANCHES[op][1]:  # br.s
        return True
    return False


# ---------------------------------------------------------------------------
# ECMA-335 flag decoders
# ---------------------------------------------------------------------------

# Method flags (II.23.1.10 MethodAttributes)
M_ACCESS_MASK   = 0x0007
M_PRIVATE       = 0x0001
M_FAMANDASSEM   = 0x0002
M_ASSEMBLY      = 0x0003
M_FAMILY        = 0x0004
M_FAMORASSEM    = 0x0005
M_PUBLIC        = 0x0006
M_STATIC        = 0x0010
M_FINAL         = 0x0020
M_VIRTUAL       = 0x0040
M_HIDEBYSIG     = 0x0080
M_ABSTRACT      = 0x0400
M_SPECIALNAME   = 0x0800
M_PINVOKE       = 0x2000
M_RTSPECIALNAME = 0x1000

def method_is_public(f):    return (f & M_ACCESS_MASK) == M_PUBLIC
def method_is_private(f):   return (f & M_ACCESS_MASK) == M_PRIVATE
def method_is_static(f):    return bool(f & M_STATIC)
def method_is_virtual(f):   return bool(f & M_VIRTUAL)
def method_is_abstract(f):  return bool(f & M_ABSTRACT)
def method_is_pinvoke(f):   return bool(f & M_PINVOKE)

# Field flags (II.23.1.5)
F_ACCESS_MASK    = 0x0007
F_PRIVATE        = 0x0001
F_PUBLIC         = 0x0006
F_STATIC         = 0x0010
F_INITONLY       = 0x0020
F_LITERAL        = 0x0040
F_HASDEFAULT     = 0x8000
F_HASFIELDRVA    = 0x0100

def field_is_static(f):    return bool(f & F_STATIC)
def field_is_literal(f):   return bool(f & F_LITERAL)
def field_is_initonly(f):  return bool(f & F_INITONLY)
def field_has_default(f):  return bool(f & F_HASDEFAULT)

# Type flags (II.23.1.15)
T_VISIBILITY_MASK   = 0x00000007
T_NOTPUBLIC         = 0x00000000
T_PUBLIC            = 0x00000001
T_NESTED_PUBLIC     = 0x00000002
T_NESTED_PRIVATE    = 0x00000003
T_INTERFACE         = 0x00000020
T_ABSTRACT          = 0x00000080
T_SEALED            = 0x00000100
T_SPECIALNAME       = 0x00000400
T_SERIALIZABLE      = 0x00002000

def type_visibility(f):
    v = f & T_VISIBILITY_MASK
    return {
        T_NOTPUBLIC: "NotPublic",
        T_PUBLIC: "Public",
        T_NESTED_PUBLIC: "NestedPublic",
        T_NESTED_PRIVATE: "NestedPrivate",
        0x4: "NestedFamily",
        0x5: "NestedAssembly",
        0x6: "NestedFamilyAndAssembly",
        0x7: "NestedFamilyOrAssembly",
    }[v]

def type_is_interface(f): return bool(f & T_INTERFACE)
def type_is_abstract(f):  return bool(f & T_ABSTRACT)
def type_is_sealed(f):    return bool(f & T_SEALED)


# ---------------------------------------------------------------------------
# AssemblyVersion + CustomAttribute.is_type
# ---------------------------------------------------------------------------

def fmt_assembly_version(a, b, c, d):
    return f"{a}.{b}.{c}.{d}"


def attr_is_type(attr_type: str, name: str) -> bool:
    if attr_type == name:
        return True
    if attr_type.endswith("." + name):
        return True
    if attr_type.endswith("::" + name):
        return True
    return False


# ---------------------------------------------------------------------------
# Validation harness
# ---------------------------------------------------------------------------

def check(label, cond, fails):
    if not cond:
        fails.append(label)


def main():
    fails = []

    # --- Tiny header: byte 0x06 => size 1, just a `ret` (0x2A) ---
    body = parse_method_body(bytes([0x06, 0x2A]))
    check("tiny.fat=false", body["fat"] is False, fails)
    check("tiny.code_size=1", body["code_size"] == 1, fails)
    check("tiny.max_stack=8", body["max_stack"] == 8, fails)
    check("tiny.code=[0x2A]", body["code"] == bytes([0x2A]), fails)

    # --- Fat header: flags=0x3003 (fat + size 3 dwords), max_stack=4, code_size=3 ---
    fat_hdr = struct.pack("<HHII", 0x3003, 4, 3, 0)
    fat = parse_method_body(fat_hdr + bytes([0x16, 0x17, 0x2A]))
    check("fat.fat=true", fat["fat"] is True, fails)
    check("fat.max_stack=4", fat["max_stack"] == 4, fails)
    check("fat.code_size=3", fat["code_size"] == 3, fails)
    check("fat.code", fat["code"] == bytes([0x16, 0x17, 0x2A]), fails)
    check("fat.init_locals=false", fat["init_locals"] is False, fails)

    # Fat with InitLocals (0x0010) and size 3
    fat2_hdr = struct.pack("<HHII", 0x3013, 2, 1, 0)
    fat2 = parse_method_body(fat2_hdr + bytes([0x2A]))
    check("fat.init_locals=true", fat2["init_locals"] is True, fails)

    # Fat header with size < 3 must error
    try:
        bad = struct.pack("<HHII", 0x2003, 0, 0, 0)
        parse_method_body(bad)
        fails.append("fat.size<3 should error")
    except ValueError:
        pass

    # --- Branch decode: short forward `br.s 3` at offset 0 ---
    # bytes: 2B 03 -> target = 0 + 2 + 3 = 5
    code = bytes([0x2B, 0x03, 0x00, 0x00, 0x00, 0x2A])
    dec = decode_branch_target(code, 0)
    check("br.s decode", dec is not None and dec[1] == 5 and dec[4] is True, fails)

    # Short backward branch: brtrue.s -2 at offset 4 -> 4+2-2 = 4 (self loop)
    code2 = bytes([0x16, 0x16, 0x16, 0x16, 0x2D, 0xFE])
    dec2 = decode_branch_target(code2, 4)
    check("brtrue.s back decode", dec2 is not None and dec2[1] == 4 and dec2[4] is False, fails)

    # Long branch: br 0x00000010 at offset 0 -> 0+5+16 = 21
    code3 = bytes([0x38, 0x10, 0x00, 0x00, 0x00])
    dec3 = decode_branch_target(code3, 0)
    check("br long decode", dec3 is not None and dec3[1] == 21 and dec3[4] is True, fails)

    # Terminator classification
    check("ret terminator", is_terminator(0x2A), fails)
    check("throw terminator", is_terminator(0x7A), fails)
    check("br terminator", is_terminator(0x38), fails)
    check("br.s terminator", is_terminator(0x2B), fails)
    check("brtrue NOT terminator-alone", not is_terminator(0x2D), fails)
    check("nop NOT terminator", not is_terminator(0x00), fails)

    # --- Method flags ---
    f = M_PUBLIC | M_STATIC | M_HIDEBYSIG
    check("method public", method_is_public(f), fails)
    check("method static", method_is_static(f), fails)
    check("method not virtual", not method_is_virtual(f), fails)
    check("method not abstract", not method_is_abstract(f), fails)
    f2 = M_PUBLIC | M_VIRTUAL | M_ABSTRACT
    check("method virtual+abstract", method_is_virtual(f2) and method_is_abstract(f2), fails)
    check("method private", method_is_private(M_PRIVATE), fails)

    # --- Field flags ---
    ff = F_PUBLIC | F_STATIC | F_LITERAL | F_HASDEFAULT
    check("field static literal hasdefault", field_is_static(ff) and field_is_literal(ff) and field_has_default(ff), fails)
    check("field initonly false", not field_is_initonly(ff), fails)
    ff2 = F_PUBLIC | F_INITONLY
    check("field initonly", field_is_initonly(ff2), fails)

    # --- Type flags ---
    tf = T_PUBLIC | T_SEALED | T_SERIALIZABLE
    check("type vis Public", type_visibility(tf) == "Public", fails)
    check("type sealed", type_is_sealed(tf), fails)
    check("type not interface", not type_is_interface(tf), fails)
    tf2 = T_NESTED_PRIVATE | T_INTERFACE | T_ABSTRACT
    check("type vis NestedPrivate", type_visibility(tf2) == "NestedPrivate", fails)
    check("type interface", type_is_interface(tf2), fails)
    check("type abstract", type_is_abstract(tf2), fails)

    # --- AssemblyVersion display ---
    check("version fmt", fmt_assembly_version(1, 2, 3, 4) == "1.2.3.4", fails)
    check("version fmt zero", fmt_assembly_version(0, 0, 0, 0) == "0.0.0.0", fails)

    # --- CustomAttribute.is_type ---
    check("attr exact", attr_is_type("Serializable", "Serializable"), fails)
    check("attr .Name", attr_is_type("System.SerializableAttribute", "SerializableAttribute"), fails)
    check("attr ::Name", attr_is_type("System::Foo", "Foo"), fails)
    check("attr no match", not attr_is_type("SerializableExtra", "Serializable"), fails)

    if fails:
        print(f"FAIL ({len(fails)}):", file=sys.stderr)
        for f in fails:
            print(" -", f, file=sys.stderr)
        return 1
    print(f"OK: all rustre-dotnet validator checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
