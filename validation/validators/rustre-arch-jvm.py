#!/usr/bin/env python3
"""
Standalone validator for rustre-arch-jvm.

Reimplements (in pure Python) the externally-verifiable subset of the
rustre-arch-jvm crate, so its Rust outputs can be diffed against a
ground-truth oracle that does not import the crate or talk to MCP.

Covers:
  - JvmInstr::decode  (mnemonic + size for the full opcode table,
                       including wide / tableswitch / lookupswitch padding)
  - ClassFileHeader::decode  (CAFEBABE magic + minor/major)
  - parse_method_descriptor / FieldDescriptor::parse
  - ConstantPoolTag::is_wide / name
  - jvm_count_invocations / jvm_count_allocations
  - jvm_cyclomatic_complexity (branches + 1)
  - JvmArch constants (name, pointer_size, endian)

Usage:
  python rustre-arch-jvm.py            # runs main() self-tests
  echo '{"fn":"decode","bytes":"03"}' | python rustre-arch-jvm.py --stdin
"""

import json
import struct
import sys

# ---------------------------------------------------------------------------
# Opcode table: (mnemonic, fixed_length_or_-1, is_branch, is_invoke, is_alloc)
# Length -1 means variable (wide / tableswitch / lookupswitch).
# Pulled from the JVM SE specification §6.5.
# ---------------------------------------------------------------------------
_OPC = {
    0x00: ("nop", 1), 0x01: ("aconst_null", 1),
    0x02: ("iconst_m1", 1), 0x03: ("iconst_0", 1), 0x04: ("iconst_1", 1),
    0x05: ("iconst_2", 1), 0x06: ("iconst_3", 1), 0x07: ("iconst_4", 1),
    0x08: ("iconst_5", 1),
    0x09: ("lconst_0", 1), 0x0a: ("lconst_1", 1),
    0x0b: ("fconst_0", 1), 0x0c: ("fconst_1", 1), 0x0d: ("fconst_2", 1),
    0x0e: ("dconst_0", 1), 0x0f: ("dconst_1", 1),
    0x10: ("bipush", 2), 0x11: ("sipush", 3),
    0x12: ("ldc", 2), 0x13: ("ldc_w", 3), 0x14: ("ldc2_w", 3),
    0x15: ("iload", 2), 0x16: ("lload", 2), 0x17: ("fload", 2),
    0x18: ("dload", 2), 0x19: ("aload", 2),
    0x1a: ("iload_0", 1), 0x1b: ("iload_1", 1), 0x1c: ("iload_2", 1), 0x1d: ("iload_3", 1),
    0x1e: ("lload_0", 1), 0x1f: ("lload_1", 1), 0x20: ("lload_2", 1), 0x21: ("lload_3", 1),
    0x22: ("fload_0", 1), 0x23: ("fload_1", 1), 0x24: ("fload_2", 1), 0x25: ("fload_3", 1),
    0x26: ("dload_0", 1), 0x27: ("dload_1", 1), 0x28: ("dload_2", 1), 0x29: ("dload_3", 1),
    0x2a: ("aload_0", 1), 0x2b: ("aload_1", 1), 0x2c: ("aload_2", 1), 0x2d: ("aload_3", 1),
    0x2e: ("iaload", 1), 0x2f: ("laload", 1), 0x30: ("faload", 1), 0x31: ("daload", 1),
    0x32: ("aaload", 1), 0x33: ("baload", 1), 0x34: ("caload", 1), 0x35: ("saload", 1),
    0x36: ("istore", 2), 0x37: ("lstore", 2), 0x38: ("fstore", 2),
    0x39: ("dstore", 2), 0x3a: ("astore", 2),
    0x3b: ("istore_0", 1), 0x3c: ("istore_1", 1), 0x3d: ("istore_2", 1), 0x3e: ("istore_3", 1),
    0x3f: ("lstore_0", 1), 0x40: ("lstore_1", 1), 0x41: ("lstore_2", 1), 0x42: ("lstore_3", 1),
    0x43: ("fstore_0", 1), 0x44: ("fstore_1", 1), 0x45: ("fstore_2", 1), 0x46: ("fstore_3", 1),
    0x47: ("dstore_0", 1), 0x48: ("dstore_1", 1), 0x49: ("dstore_2", 1), 0x4a: ("dstore_3", 1),
    0x4b: ("astore_0", 1), 0x4c: ("astore_1", 1), 0x4d: ("astore_2", 1), 0x4e: ("astore_3", 1),
    0x4f: ("iastore", 1), 0x50: ("lastore", 1), 0x51: ("fastore", 1), 0x52: ("dastore", 1),
    0x53: ("aastore", 1), 0x54: ("bastore", 1), 0x55: ("castore", 1), 0x56: ("sastore", 1),
    0x57: ("pop", 1), 0x58: ("pop2", 1),
    0x59: ("dup", 1), 0x5a: ("dup_x1", 1), 0x5b: ("dup_x2", 1),
    0x5c: ("dup2", 1), 0x5d: ("dup2_x1", 1), 0x5e: ("dup2_x2", 1),
    0x5f: ("swap", 1),
    0x60: ("iadd", 1), 0x61: ("ladd", 1), 0x62: ("fadd", 1), 0x63: ("dadd", 1),
    0x64: ("isub", 1), 0x65: ("lsub", 1), 0x66: ("fsub", 1), 0x67: ("dsub", 1),
    0x68: ("imul", 1), 0x69: ("lmul", 1), 0x6a: ("fmul", 1), 0x6b: ("dmul", 1),
    0x6c: ("idiv", 1), 0x6d: ("ldiv", 1), 0x6e: ("fdiv", 1), 0x6f: ("ddiv", 1),
    0x70: ("irem", 1), 0x71: ("lrem", 1), 0x72: ("frem", 1), 0x73: ("drem", 1),
    0x74: ("ineg", 1), 0x75: ("lneg", 1), 0x76: ("fneg", 1), 0x77: ("dneg", 1),
    0x78: ("ishl", 1), 0x79: ("lshl", 1), 0x7a: ("ishr", 1), 0x7b: ("lshr", 1),
    0x7c: ("iushr", 1), 0x7d: ("lushr", 1),
    0x7e: ("iand", 1), 0x7f: ("land", 1), 0x80: ("ior", 1), 0x81: ("lor", 1),
    0x82: ("ixor", 1), 0x83: ("lxor", 1),
    0x84: ("iinc", 3),
    0x85: ("i2l", 1), 0x86: ("i2f", 1), 0x87: ("i2d", 1),
    0x88: ("l2i", 1), 0x89: ("l2f", 1), 0x8a: ("l2d", 1),
    0x8b: ("f2i", 1), 0x8c: ("f2l", 1), 0x8d: ("f2d", 1),
    0x8e: ("d2i", 1), 0x8f: ("d2l", 1), 0x90: ("d2f", 1),
    0x91: ("i2b", 1), 0x92: ("i2c", 1), 0x93: ("i2s", 1),
    0x94: ("lcmp", 1),
    0x95: ("fcmpl", 1), 0x96: ("fcmpg", 1),
    0x97: ("dcmpl", 1), 0x98: ("dcmpg", 1),
    0x99: ("ifeq", 3), 0x9a: ("ifne", 3), 0x9b: ("iflt", 3), 0x9c: ("ifge", 3),
    0x9d: ("ifgt", 3), 0x9e: ("ifle", 3),
    0x9f: ("if_icmpeq", 3), 0xa0: ("if_icmpne", 3), 0xa1: ("if_icmplt", 3),
    0xa2: ("if_icmpge", 3), 0xa3: ("if_icmpgt", 3), 0xa4: ("if_icmple", 3),
    0xa5: ("if_acmpeq", 3), 0xa6: ("if_acmpne", 3),
    0xa7: ("goto", 3), 0xa8: ("jsr", 3), 0xa9: ("ret", 2),
    0xaa: ("tableswitch", -1), 0xab: ("lookupswitch", -1),
    0xac: ("ireturn", 1), 0xad: ("lreturn", 1), 0xae: ("freturn", 1),
    0xaf: ("dreturn", 1), 0xb0: ("areturn", 1), 0xb1: ("return", 1),
    0xb2: ("getstatic", 3), 0xb3: ("putstatic", 3),
    0xb4: ("getfield", 3), 0xb5: ("putfield", 3),
    0xb6: ("invokevirtual", 3), 0xb7: ("invokespecial", 3),
    0xb8: ("invokestatic", 3), 0xb9: ("invokeinterface", 5),
    0xba: ("invokedynamic", 5),
    0xbb: ("new", 3), 0xbc: ("newarray", 2), 0xbd: ("anewarray", 3),
    0xbe: ("arraylength", 1), 0xbf: ("athrow", 1),
    0xc0: ("checkcast", 3), 0xc1: ("instanceof", 3),
    0xc2: ("monitorenter", 1), 0xc3: ("monitorexit", 1),
    0xc4: ("wide", -1),
    0xc5: ("multianewarray", 4),
    0xc6: ("ifnull", 3), 0xc7: ("ifnonnull", 3),
    0xc8: ("goto_w", 5), 0xc9: ("jsr_w", 5),
}

_BRANCHES = set(range(0x99, 0xaa)) | {0xc6, 0xc7, 0xc8, 0xc9}
_INVOKES = {0xb6, 0xb7, 0xb8, 0xb9, 0xba}
_ALLOCS = {0xbb, 0xbc, 0xbd, 0xc5}


def validator_decode(bytes_hex, pc_offset=0):
    """JvmInstr::decode_at — returns dict {mnemonic, size} or {error}."""
    b = bytes.fromhex(bytes_hex)
    if not b:
        return {"error": "Truncated"}
    op = b[0]
    if 0xca <= op <= 0xff:
        return {"error": "Reserved"}
    if op not in _OPC:
        return {"error": "UnknownOpcode"}
    mnem, length = _OPC[op]

    if length > 0:
        if len(b) < length:
            return {"error": "Truncated"}
        return {"mnemonic": mnem, "size": length}

    # variable-length
    if op == 0xc4:  # wide
        if len(b) < 2:
            return {"error": "Truncated"}
        sub = b[1]
        if sub == 0x84:  # wide iinc
            sz = 6
        elif sub in (0x15, 0x16, 0x17, 0x18, 0x19,
                     0x36, 0x37, 0x38, 0x39, 0x3a, 0xa9):
            sz = 4
        else:
            return {"error": "UnknownOpcode"}
        if len(b) < sz:
            return {"error": "Truncated"}
        return {"mnemonic": "wide", "size": sz}

    if op == 0xaa:  # tableswitch
        pad = (4 - ((pc_offset + 1) % 4)) % 4
        hdr = 1 + pad + 12  # default + low + high
        if len(b) < hdr:
            return {"error": "Truncated"}
        low = struct.unpack(">i", b[1 + pad + 4:1 + pad + 8])[0]
        high = struct.unpack(">i", b[1 + pad + 8:1 + pad + 12])[0]
        n = high - low + 1
        sz = hdr + 4 * n
        if len(b) < sz:
            return {"error": "Truncated"}
        return {"mnemonic": "tableswitch", "size": sz}

    if op == 0xab:  # lookupswitch
        pad = (4 - ((pc_offset + 1) % 4)) % 4
        hdr = 1 + pad + 8
        if len(b) < hdr:
            return {"error": "Truncated"}
        npairs = struct.unpack(">i", b[1 + pad + 4:1 + pad + 8])[0]
        sz = hdr + 8 * npairs
        if len(b) < sz:
            return {"error": "Truncated"}
        return {"mnemonic": "lookupswitch", "size": sz}

    return {"error": "UnknownOpcode"}


def _walk(code):
    """Yield (pc, opcode, size) for each instruction. Stop on error."""
    pc = 0
    while pc < len(code):
        r = validator_decode(code[pc:].hex(), pc_offset=pc)
        if "error" in r:
            return
        sz = r["size"]
        yield pc, code[pc], sz
        pc += sz


def validator_class_file_header(bytes_hex):
    b = bytes.fromhex(bytes_hex)
    if len(b) < 8:
        return {"error": "Truncated"}
    magic, minor, major = struct.unpack(">IHH", b[:8])
    if magic != 0xCAFEBABE:
        return {"error": "BadMagic", "magic": f"{magic:08x}"}
    return {"magic": magic, "minor": minor, "major": major}


def validator_field_descriptor(s):
    """Returns dict {kind, raw, consumed} or {error}."""
    if not s:
        return {"error": "Empty"}
    i = 0
    if s[i] == '[':
        depth = 0
        while i < len(s) and s[i] == '[':
            depth += 1
            i += 1
        inner = validator_field_descriptor(s[i:])
        if "error" in inner:
            return inner
        return {"kind": "array", "depth": depth, "inner": inner["kind"],
                "consumed": i + inner["consumed"]}
    c = s[i]
    base = {"B": "byte", "C": "char", "D": "double", "F": "float",
            "I": "int", "J": "long", "S": "short", "Z": "boolean", "V": "void"}
    if c in base:
        return {"kind": base[c], "consumed": 1}
    if c == 'L':
        end = s.find(';', i)
        if end < 0:
            return {"error": "UnterminatedClass"}
        return {"kind": "object", "class": s[i + 1:end], "consumed": end - i + 1}
    return {"error": "BadDescriptor"}


def validator_parse_method_descriptor(s):
    if not s.startswith('('):
        return {"error": "MissingOpenParen"}
    i = 1
    args = []
    while i < len(s) and s[i] != ')':
        sub = validator_field_descriptor(s[i:])
        if "error" in sub:
            return sub
        args.append(sub["kind"] if sub["kind"] != "object" else f"L{sub['class']};")
        i += sub["consumed"]
    if i >= len(s):
        return {"error": "MissingCloseParen"}
    ret = validator_field_descriptor(s[i + 1:])
    if "error" in ret:
        return ret
    return {"args": args, "ret": ret["kind"]}


_CP_TAGS = {
    1: ("Utf8", False), 3: ("Integer", False), 4: ("Float", False),
    5: ("Long", True), 6: ("Double", True),
    7: ("Class", False), 8: ("String", False),
    9: ("Fieldref", False), 10: ("Methodref", False), 11: ("InterfaceMethodref", False),
    12: ("NameAndType", False), 15: ("MethodHandle", False),
    16: ("MethodType", False), 17: ("Dynamic", False),
    18: ("InvokeDynamic", False), 19: ("Module", False), 20: ("Package", False),
}


def validator_cp_tag(tag):
    if tag not in _CP_TAGS:
        return {"error": "UnknownTag"}
    name, wide = _CP_TAGS[tag]
    return {"name": name, "is_wide": wide}


def validator_count_invocations(code_hex):
    code = bytes.fromhex(code_hex)
    return sum(1 for _, op, _ in _walk(code) if op in _INVOKES)


def validator_count_allocations(code_hex):
    code = bytes.fromhex(code_hex)
    return sum(1 for _, op, _ in _walk(code) if op in _ALLOCS)


def validator_cyclomatic_complexity(code_hex):
    code = bytes.fromhex(code_hex)
    branches = sum(1 for _, op, _ in _walk(code) if op in _BRANCHES)
    return branches + 1


def validator_arch_constants():
    return {"name": "jvm", "pointer_size": 4, "endian": "Big"}


# ---------------------------------------------------------------------------
DISPATCH = {
    "decode": lambda p: validator_decode(p["bytes"], p.get("pc_offset", 0)),
    "class_file_header": lambda p: validator_class_file_header(p["bytes"]),
    "field_descriptor": lambda p: validator_field_descriptor(p["s"]),
    "parse_method_descriptor": lambda p: validator_parse_method_descriptor(p["s"]),
    "cp_tag": lambda p: validator_cp_tag(p["tag"]),
    "count_invocations": lambda p: validator_count_invocations(p["bytes"]),
    "count_allocations": lambda p: validator_count_allocations(p["bytes"]),
    "cyclomatic_complexity": lambda p: validator_cyclomatic_complexity(p["bytes"]),
    "arch_constants": lambda p: validator_arch_constants(),
}


def main():
    if "--stdin" in sys.argv:
        req = json.loads(sys.stdin.read())
        fn = req.pop("fn")
        print(json.dumps(DISPATCH[fn](req)))
        return

    # Fixed self-tests
    tests = [
        ("decode iconst_0",        validator_decode("03"),                {"mnemonic": "iconst_0", "size": 1}),
        ("decode bipush 10",       validator_decode("100a"),              {"mnemonic": "bipush", "size": 2}),
        ("decode goto +5",         validator_decode("a70005"),            {"mnemonic": "goto", "size": 3}),
        ("decode goto_w",          validator_decode("c800000005"),        {"mnemonic": "goto_w", "size": 5}),
        ("decode invokeinterface", validator_decode("b9000102 00"),       {"mnemonic": "invokeinterface", "size": 5}),
        ("decode reserved 0xCA",   validator_decode("ca"),                {"error": "Reserved"}),
        ("decode truncated",       validator_decode("10"),                {"error": "Truncated"}),
        ("decode wide iload",      validator_decode("c4150001"),          {"mnemonic": "wide", "size": 4}),
        ("decode wide iinc",       validator_decode("c4840001ffff"),      {"mnemonic": "wide", "size": 6}),
        ("tableswitch pc=0 1..2",  validator_decode(
            "aa" + "000000" + "00000000" + "00000001" + "00000002" + "00000010" + "00000020",
            pc_offset=0),
            {"mnemonic": "tableswitch", "size": 1 + 3 + 12 + 4 * 2}),
        ("class header",           validator_class_file_header("cafebabe000000340000"),
            {"magic": 0xCAFEBABE, "minor": 0, "major": 52}),
        ("desc (IJLjava/lang/String;)V",
            validator_parse_method_descriptor("(IJLjava/lang/String;)V"),
            {"args": ["int", "long", "Ljava/lang/String;"], "ret": "void"}),
        ("field [I",               validator_field_descriptor("[I"),
            {"kind": "array", "depth": 1, "inner": "int", "consumed": 2}),
        ("cp Long wide",           validator_cp_tag(5), {"name": "Long", "is_wide": True}),
        ("arch consts",            validator_arch_constants(),
            {"name": "jvm", "pointer_size": 4, "endian": "Big"}),
        # iconst_0; ifeq +3; return  -> 1 branch -> complexity 2
        ("complexity",             validator_cyclomatic_complexity("0399000301b1"), 2),
        ("count invocations",      validator_count_invocations("b6000103b6000201"), 2),
        ("count allocations",      validator_count_allocations("bb0001bc0a"), 2),
    ]
    failed = 0
    for name, got, want in tests:
        ok = got == want
        if not ok:
            failed += 1
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: got={got!r} want={want!r}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
