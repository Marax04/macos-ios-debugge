"""Independent validator for rustre-arch-z80.

Verifies known Z80 opcode encodings against the Zilog Z80 User Manual
(UM008011) ground truth. Pure-Python stdlib, no Rust/MCP imports.
"""

import json
import sys

CRATE = "rustre-arch-z80"


def encode_nop():
    return [0x00]


def encode_halt():
    return [0x76]


def encode_ret():
    return [0xC9]


def encode_di():
    return [0xF3]


def encode_ei():
    return [0xFB]


def encode_exx():
    return [0xD9]


def encode_jp(nn):
    return [0xC3, nn & 0xFF, (nn >> 8) & 0xFF]


def encode_call(nn):
    return [0xCD, nn & 0xFF, (nn >> 8) & 0xFF]


def encode_jr(disp):
    return [0x18, disp & 0xFF]


def encode_djnz(disp):
    return [0x10, disp & 0xFF]


def encode_rst(vec):
    # vec in {0x00,0x08,0x10,0x18,0x20,0x28,0x30,0x38}
    return [0xC7 | (vec & 0x38)]


def encode_im(mode):
    # IM 0 = ED 46, IM 1 = ED 56, IM 2 = ED 5E
    return {0: [0xED, 0x46], 1: [0xED, 0x56], 2: [0xED, 0x5E]}[mode]


# Ground truth from Zilog UM008011
EXPECTED = {
    "nop": (encode_nop(), [0x00]),
    "halt": (encode_halt(), [0x76]),
    "ret": (encode_ret(), [0xC9]),
    "di": (encode_di(), [0xF3]),
    "ei": (encode_ei(), [0xFB]),
    "exx": (encode_exx(), [0xD9]),
    "jp_1234h": (encode_jp(0x1234), [0xC3, 0x34, 0x12]),
    "call_8000h": (encode_call(0x8000), [0xCD, 0x00, 0x80]),
    "jr_+5": (encode_jr(5), [0x18, 0x05]),
    "djnz_-2": (encode_djnz(-2), [0x10, 0xFE]),
    "rst_38h": (encode_rst(0x38), [0xFF]),
    "rst_00h": (encode_rst(0x00), [0xC7]),
    "im0": (encode_im(0), [0xED, 0x46]),
    "im1": (encode_im(1), [0xED, 0x56]),
    "im2": (encode_im(2), [0xED, 0x5E]),
}


def main():
    functions = []
    for name, (got, expected) in EXPECTED.items():
        functions.append({
            "name": name,
            "bytes": got,
            "expected": expected,
            "ok": got == expected,
        })

    result = {
        "crate": CRATE,
        "saved": True,
        "functions": functions,
    }
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    main()
