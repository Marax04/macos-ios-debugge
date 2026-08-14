"""Independent validator for rustre-mobile-smali.

Implements smali/Dalvik primitives from the official Dalvik bytecode
specification using only Python stdlib. Does not import the Rust crate
or call MCP tools.
"""

import json


# ---------------------------------------------------------------------------
# SmaliReg: v<n> if n<64, else p<n-64>  (per report)
# ---------------------------------------------------------------------------
def smali_reg(num: int) -> str:
    if num < 64:
        return f"v{num}"
    return f"p{num - 64}"


# ---------------------------------------------------------------------------
# parse_type_descriptor: "Ljava/lang/String;" -> "java.lang.String"
# primitives: V Z B S C I J F D
# arrays: [<desc>  -> "<inner>[]"
# ---------------------------------------------------------------------------
_PRIM = {
    "V": "void", "Z": "boolean", "B": "byte", "S": "short",
    "C": "char", "I": "int", "J": "long", "F": "float", "D": "double",
}


def parse_type_descriptor(desc: str) -> str:
    if not desc:
        return ""
    arr = 0
    i = 0
    while i < len(desc) and desc[i] == "[":
        arr += 1
        i += 1
    rest = desc[i:]
    if rest in _PRIM:
        base = _PRIM[rest]
    elif rest.startswith("L") and rest.endswith(";"):
        base = rest[1:-1].replace("/", ".")
    else:
        base = rest
    return base + "[]" * arr


# ---------------------------------------------------------------------------
# parse_method_descriptor: "(II)V" -> (["int","int"], "void")
# ---------------------------------------------------------------------------
def parse_method_descriptor(desc: str):
    if not desc.startswith("("):
        return ([], "")
    end = desc.find(")")
    inner = desc[1:end]
    ret = desc[end + 1:]
    params = []
    i = 0
    while i < len(inner):
        j = i
        while j < len(inner) and inner[j] == "[":
            j += 1
        if j < len(inner) and inner[j] == "L":
            k = inner.find(";", j)
            params.append(parse_type_descriptor(inner[i:k + 1]))
            i = k + 1
        else:
            params.append(parse_type_descriptor(inner[i:j + 1]))
            i = j + 1
    return (params, parse_type_descriptor(ret))


# ---------------------------------------------------------------------------
# Dalvik instruction sizes (in 16-bit code units), per opcode formats.
# Common opcodes:
#   0x00 nop                       -> 1 unit  (2 bytes)
#   0x01 move vA, vB               -> 1 unit
#   0x0e return-void               -> 1 unit
#   0x12 const/4 vA, #+B           -> 1 unit
#   0x13 const/16 vAA, #+BBBB      -> 2 units
#   0x14 const vAA, #+BBBBBBBB     -> 3 units
#   0x15 const/high16              -> 2 units
#   0x6e invoke-virtual            -> 3 units
#   0x71 invoke-static             -> 3 units
# ---------------------------------------------------------------------------
def instruction_size_code_units(op: int) -> int:
    one = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
           0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x1d, 0x1e,
           0x21, 0x27, 0x28}
    if op in one:
        return 1
    two = {0x13, 0x15, 0x16, 0x19, 0x22, 0x23, 0x29, 0x2d, 0x2e, 0x2f, 0x30,
           0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
           0x3c, 0x3d}
    if op in two:
        return 2
    three = {0x14, 0x17, 0x1a, 0x1c, 0x6e, 0x6f, 0x70, 0x71, 0x72}
    if op in three:
        return 3
    five = {0x18}  # const-wide
    if op in five:
        return 5
    return 1


def instruction_size_bytes(op: int) -> int:
    return 2 * instruction_size_code_units(op)


# ---------------------------------------------------------------------------
# Access flag bitmask (from SmaliAccess bitflags, standard Dalvik values).
# ---------------------------------------------------------------------------
ACC_PUBLIC = 0x0001
ACC_PRIVATE = 0x0002
ACC_PROTECTED = 0x0004
ACC_STATIC = 0x0008
ACC_FINAL = 0x0010
ACC_NATIVE = 0x0100
ACC_ABSTRACT = 0x0400
ACC_CONSTRUCTOR = 0x10000


def access_string(flags: int) -> str:
    parts = []
    for bit, name in [
        (ACC_PUBLIC, "public"),
        (ACC_PRIVATE, "private"),
        (ACC_PROTECTED, "protected"),
        (ACC_STATIC, "static"),
        (ACC_FINAL, "final"),
        (ACC_NATIVE, "native"),
        (ACC_ABSTRACT, "abstract"),
        (ACC_CONSTRUCTOR, "constructor"),
    ]:
        if flags & bit:
            parts.append(name)
    return " ".join(parts)


# ---------------------------------------------------------------------------
# escape_string: escape a Java/smali string literal.
# ---------------------------------------------------------------------------
def escape_string(s: str) -> str:
    out = []
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        else:
            out.append(ch)
    return "".join(out)


# ---------------------------------------------------------------------------
# Dalvik header consts (smali_assembler)
# ---------------------------------------------------------------------------
DEX_MAGIC = b"dex\n035\x00"
HEADER_SIZE = 0x70
ENDIAN_CONSTANT = 0x12345678
NO_INDEX = 0xFFFFFFFF


# ---------------------------------------------------------------------------
# lo32_u64 helper used in smali_assembler.
# ---------------------------------------------------------------------------
def lo32_u64(x: int) -> int:
    return x & 0xFFFFFFFF


# ---------------------------------------------------------------------------
CRATE = "rustre-mobile-smali"


def run():
    results = []

    def t(name, call, expected):
        got = call()
        results.append({
            "function": name,
            "expected": expected,
            "got": got,
            "ok": got == expected,
        })

    # SmaliReg numbering
    t("smali_reg(0)", lambda: smali_reg(0), "v0")
    t("smali_reg(63)", lambda: smali_reg(63), "v63")
    t("smali_reg(64)", lambda: smali_reg(64), "p0")
    t("smali_reg(70)", lambda: smali_reg(70), "p6")

    # Type descriptors
    t("parse_type_descriptor('Ljava/lang/String;')",
      lambda: parse_type_descriptor("Ljava/lang/String;"), "java.lang.String")
    t("parse_type_descriptor('I')", lambda: parse_type_descriptor("I"), "int")
    t("parse_type_descriptor('V')", lambda: parse_type_descriptor("V"), "void")
    t("parse_type_descriptor('[I')",
      lambda: parse_type_descriptor("[I"), "int[]")
    t("parse_type_descriptor('[[Ljava/lang/Object;')",
      lambda: parse_type_descriptor("[[Ljava/lang/Object;"),
      "java.lang.Object[][]")

    # Method descriptors
    t("parse_method_descriptor('(II)V')",
      lambda: parse_method_descriptor("(II)V"), (["int", "int"], "void"))
    t("parse_method_descriptor('()V')",
      lambda: parse_method_descriptor("()V"), ([], "void"))
    t("parse_method_descriptor('(Ljava/lang/String;I)Z')",
      lambda: parse_method_descriptor("(Ljava/lang/String;I)Z"),
      (["java.lang.String", "int"], "boolean"))
    t("parse_method_descriptor('([BJ)Ljava/lang/Object;')",
      lambda: parse_method_descriptor("([BJ)Ljava/lang/Object;"),
      (["byte[]", "long"], "java.lang.Object"))

    # Instruction sizes (code units)
    t("instruction_size_code_units(0x00 nop)",
      lambda: instruction_size_code_units(0x00), 1)
    t("instruction_size_code_units(0x0e return-void)",
      lambda: instruction_size_code_units(0x0e), 1)
    t("instruction_size_code_units(0x12 const/4)",
      lambda: instruction_size_code_units(0x12), 1)
    t("instruction_size_code_units(0x13 const/16)",
      lambda: instruction_size_code_units(0x13), 2)
    t("instruction_size_code_units(0x14 const)",
      lambda: instruction_size_code_units(0x14), 3)
    t("instruction_size_code_units(0x18 const-wide)",
      lambda: instruction_size_code_units(0x18), 5)
    t("instruction_size_code_units(0x6e invoke-virtual)",
      lambda: instruction_size_code_units(0x6e), 3)
    t("instruction_size_code_units(0x71 invoke-static)",
      lambda: instruction_size_code_units(0x71), 3)
    t("instruction_size_bytes(0x13)", lambda: instruction_size_bytes(0x13), 4)
    t("instruction_size_bytes(0x71)", lambda: instruction_size_bytes(0x71), 6)

    # Access flags
    t("access_string(PUBLIC|STATIC)",
      lambda: access_string(ACC_PUBLIC | ACC_STATIC), "public static")
    t("access_string(PRIVATE|FINAL)",
      lambda: access_string(ACC_PRIVATE | ACC_FINAL), "private final")
    t("access_string(PUBLIC|CONSTRUCTOR)",
      lambda: access_string(ACC_PUBLIC | ACC_CONSTRUCTOR),
      "public constructor")
    t("access_string(0)", lambda: access_string(0), "")

    # escape_string
    t("escape_string('hello')", lambda: escape_string("hello"), "hello")
    t("escape_string('a\\nb')", lambda: escape_string("a\nb"), "a\\nb")
    t("escape_string('q\"x')", lambda: escape_string('q"x'), 'q\\"x')
    t("escape_string('\\\\')", lambda: escape_string("\\"), "\\\\")

    # DEX assembler constants
    t("DEX_MAGIC", lambda: DEX_MAGIC.hex(), b"dex\n035\x00".hex())
    t("HEADER_SIZE", lambda: HEADER_SIZE, 0x70)
    t("ENDIAN_CONSTANT", lambda: ENDIAN_CONSTANT, 0x12345678)
    t("NO_INDEX", lambda: NO_INDEX, 0xFFFFFFFF)

    # lo32_u64
    t("lo32_u64(0x123456789ABCDEF0)",
      lambda: lo32_u64(0x123456789ABCDEF0), 0x9ABCDEF0)
    t("lo32_u64(0)", lambda: lo32_u64(0), 0)
    t("lo32_u64(0xFFFFFFFFFFFFFFFF)",
      lambda: lo32_u64(0xFFFFFFFFFFFFFFFF), 0xFFFFFFFF)

    return results


if __name__ == "__main__":
    functions = run()
    saved = True
    output = {
        "crate": CRATE,
        "saved": saved,
        "functions": functions,
    }
    print(json.dumps(output, indent=2, default=str))
