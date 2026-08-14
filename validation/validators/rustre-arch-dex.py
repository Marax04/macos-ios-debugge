"""Independent validator for rustre-arch-dex.

Implements DEX-related primitives from the official Dalvik specification
without importing the Rust crate or calling MCP tools. Uses only Python
stdlib. Validates a small set of pure functions documented in the report.
"""

import json
import struct


DEX_MAGIC = b"dex\n"
DEX_ENDIAN_CONSTANT = 0x12345678
DEX_REVERSE_ENDIAN_CONSTANT = 0x78563412
DEX_CODE_ITEM_HEADER_SIZE = 16
DEX_PACKED_SWITCH_IDENT = 0x0100
DEX_SPARSE_SWITCH_IDENT = 0x0200
DEX_FILL_ARRAY_DATA_IDENT = 0x0300


# ---------------------------------------------------------------------------
# dex_param_count: count parameters in a shorty/proto descriptor.
# Shorty form: first char = return type, rest = params (one char each;
#   L = object, [ = array (counts as one slot when used as shorty char),
#   primitives V/Z/B/S/C/I/J/F/D).
# Proto form: "(params)return" with full descriptors.
# ---------------------------------------------------------------------------
def dex_param_count(descriptor: str) -> int:
    if not descriptor:
        return 0
    if descriptor.startswith("("):
        end = descriptor.find(")")
        if end < 0:
            return 0
        inner = descriptor[1:end]
        count = 0
        i = 0
        while i < len(inner):
            c = inner[i]
            if c == "[":
                # array prefix; skip all '['
                while i < len(inner) and inner[i] == "[":
                    i += 1
                if i < len(inner) and inner[i] == "L":
                    while i < len(inner) and inner[i] != ";":
                        i += 1
                    i += 1
                else:
                    i += 1
                count += 1
            elif c == "L":
                while i < len(inner) and inner[i] != ";":
                    i += 1
                i += 1
                count += 1
            else:
                i += 1
                count += 1
        return count
    # shorty: skip return char
    return len(descriptor) - 1


# ---------------------------------------------------------------------------
# dex_internal_to_java_name: java/lang/String -> java.lang.String
# ---------------------------------------------------------------------------
def dex_internal_to_java_name(internal: str) -> str:
    return internal.replace("/", ".")


# ---------------------------------------------------------------------------
# java_name_to_dex_descriptor: java.lang.String -> Ljava/lang/String;
# ---------------------------------------------------------------------------
def java_name_to_dex_descriptor(java_name: str) -> str:
    return "L" + java_name.replace(".", "/") + ";"


# ---------------------------------------------------------------------------
# dex_simple_class_name: Ljava/lang/String; -> String
# ---------------------------------------------------------------------------
def dex_simple_class_name(descriptor: str) -> str:
    s = descriptor
    if s.startswith("L") and s.endswith(";"):
        s = s[1:-1]
    slash = s.rfind("/")
    return s[slash + 1:] if slash >= 0 else s


# ---------------------------------------------------------------------------
# packed/sparse switch payload sizes (in 16-bit code units), per Dalvik spec.
# packed-switch-payload: ident(1) + size(1) + first_key(2) + targets(2*size)
# sparse-switch-payload: ident(1) + size(1) + keys(2*size) + targets(2*size)
# ---------------------------------------------------------------------------
def packed_switch_payload_size(entries: int) -> int:
    return 4 + 2 * entries


def sparse_switch_payload_size(entries: int) -> int:
    return 2 + 4 * entries


# ---------------------------------------------------------------------------
# smali_reg: register index -> "v<n>"
# ---------------------------------------------------------------------------
def smali_reg(n: int) -> str:
    return f"v{n}"


# ---------------------------------------------------------------------------
# Validation harness
# ---------------------------------------------------------------------------
CRATE = "rustre-arch-dex"

FUNCTIONS = []


def check(name, got, expected):
    ok = got == expected
    FUNCTIONS.append({
        "name": name,
        "input": repr(expected[0]) if False else None,
        "expected": expected,
        "got": got,
        "ok": ok,
    })
    return ok


def run():
    results = []

    def t(fn_name, call, expected):
        got = call()
        results.append({
            "function": fn_name,
            "expected": expected,
            "got": got,
            "ok": got == expected,
        })

    # dex_param_count - proto form
    t("dex_param_count('(II)V')", lambda: dex_param_count("(II)V"), 2)
    t("dex_param_count('()V')", lambda: dex_param_count("()V"), 0)
    t("dex_param_count('(Ljava/lang/String;I)V')",
      lambda: dex_param_count("(Ljava/lang/String;I)V"), 2)
    t("dex_param_count('([BLjava/lang/Object;J)Z')",
      lambda: dex_param_count("([BLjava/lang/Object;J)Z"), 3)
    # shorty form: first char is return
    t("dex_param_count('VII')", lambda: dex_param_count("VII"), 2)
    t("dex_param_count('V')", lambda: dex_param_count("V"), 0)

    # dex_internal_to_java_name
    t("dex_internal_to_java_name('java/lang/String')",
      lambda: dex_internal_to_java_name("java/lang/String"), "java.lang.String")

    # java_name_to_dex_descriptor
    t("java_name_to_dex_descriptor('java.lang.String')",
      lambda: java_name_to_dex_descriptor("java.lang.String"),
      "Ljava/lang/String;")

    # dex_simple_class_name
    t("dex_simple_class_name('Ljava/lang/String;')",
      lambda: dex_simple_class_name("Ljava/lang/String;"), "String")
    t("dex_simple_class_name('Lcom/example/Foo;')",
      lambda: dex_simple_class_name("Lcom/example/Foo;"), "Foo")

    # packed/sparse switch payload sizes (in code units)
    t("packed_switch_payload_size(0)", lambda: packed_switch_payload_size(0), 4)
    t("packed_switch_payload_size(3)", lambda: packed_switch_payload_size(3), 10)
    t("sparse_switch_payload_size(0)", lambda: sparse_switch_payload_size(0), 2)
    t("sparse_switch_payload_size(3)", lambda: sparse_switch_payload_size(3), 14)

    # smali_reg
    t("smali_reg(0)", lambda: smali_reg(0), "v0")
    t("smali_reg(42)", lambda: smali_reg(42), "v42")

    # Constants
    t("DEX_MAGIC", lambda: DEX_MAGIC.hex(), b"dex\n".hex())
    t("DEX_ENDIAN_CONSTANT", lambda: DEX_ENDIAN_CONSTANT, 0x12345678)
    t("DEX_CODE_ITEM_HEADER_SIZE", lambda: DEX_CODE_ITEM_HEADER_SIZE, 16)
    t("DEX_PACKED_SWITCH_IDENT", lambda: DEX_PACKED_SWITCH_IDENT, 0x0100)
    t("DEX_SPARSE_SWITCH_IDENT", lambda: DEX_SPARSE_SWITCH_IDENT, 0x0200)
    t("DEX_FILL_ARRAY_DATA_IDENT", lambda: DEX_FILL_ARRAY_DATA_IDENT, 0x0300)

    return results


if __name__ == "__main__":
    functions = run()
    saved = True
    output = {
        "crate": CRATE,
        "saved": saved,
        "functions": functions,
    }
    print(json.dumps(output, indent=2))
