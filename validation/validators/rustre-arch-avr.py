#!/usr/bin/env python3
"""Independent validator for rustre-arch-avr.

Decodes a small set of AVR opcodes purely from the Atmel AVR ISA manual,
without importing the Rust crate or calling MCP. Compares produced
mnemonics/sizes against expectations derived from the analysis report.
"""
import json
import os
import sys

CRATE = "rustre-arch-avr"
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "outputs")
OUT_PATH = os.path.normpath(os.path.join(OUT_DIR, f"{CRATE}.json"))


def u16le(b, i):
    return b[i] | (b[i + 1] << 8)


def decode(bytes_, pc=0):
    """Return (mnemonic, size_bytes) for AVR instruction at bytes_[0:]."""
    if len(bytes_) < 2:
        return ("invalid", 0)
    w = u16le(bytes_, 0)

    # Fixed single-word opcodes
    fixed = {
        0x0000: "nop",
        0x9508: "ret",
        0x9518: "reti",
        0x9588: "sleep",
        0x95A8: "wdr",
        0x9598: "break",
        0x9409: "ijmp",
        0x9509: "icall",
    }
    if w in fixed:
        return (fixed[w], 2)

    # JMP: 1001 010k kkkk 110k  kkkk kkkk kkkk kkkk
    if (w & 0xFE0E) == 0x940C:
        return ("jmp", 4)
    # CALL: 1001 010k kkkk 111k  kkkk kkkk kkkk kkkk
    if (w & 0xFE0E) == 0x940E:
        return ("call", 4)
    # LDS: 1001 000d dddd 0000  kkkk kkkk kkkk kkkk
    if (w & 0xFE0F) == 0x9000:
        return ("lds", 4)
    # STS: 1001 001d dddd 0000  kkkk kkkk kkkk kkkk
    if (w & 0xFE0F) == 0x9200:
        return ("sts", 4)

    # RJMP 1100 kkkk kkkk kkkk
    if (w & 0xF000) == 0xC000:
        return ("rjmp", 2)
    # RCALL 1101 kkkk kkkk kkkk
    if (w & 0xF000) == 0xD000:
        return ("rcall", 2)
    # LDI 1110 KKKK dddd KKKK
    if (w & 0xF000) == 0xE000:
        return ("ldi", 2)
    # ADD 0000 11rd dddd rrrr
    if (w & 0xFC00) == 0x0C00:
        return ("add", 2)
    # SUB 0001 10rd dddd rrrr
    if (w & 0xFC00) == 0x1800:
        return ("sub", 2)
    # EOR 0010 01rd dddd rrrr
    if (w & 0xFC00) == 0x2400:
        return ("eor", 2)
    # AND 0010 00rd dddd rrrr
    if (w & 0xFC00) == 0x2000:
        return ("and", 2)
    # OR  0010 10rd dddd rrrr
    if (w & 0xFC00) == 0x2800:
        return ("or", 2)
    # MOV 0010 11rd dddd rrrr
    if (w & 0xFC00) == 0x2C00:
        return ("mov", 2)
    # CP  0001 01rd dddd rrrr
    if (w & 0xFC00) == 0x1400:
        return ("cp", 2)
    # CPI 0011 KKKK dddd KKKK
    if (w & 0xF000) == 0x3000:
        return ("cpi", 2)
    # IN  1011 0AAd dddd AAAA
    if (w & 0xF800) == 0xB000:
        return ("in", 2)
    # OUT 1011 1AAr rrrr AAAA
    if (w & 0xF800) == 0xB800:
        return ("out", 2)
    # PUSH 1001 001d dddd 1111
    if (w & 0xFE0F) == 0x920F:
        return ("push", 2)
    # POP  1001 000d dddd 1111
    if (w & 0xFE0F) == 0x900F:
        return ("pop", 2)
    # BREQ 1111 00kk kkkk k001
    if (w & 0xFC07) == 0xF001:
        return ("breq", 2)
    # BRNE 1111 01kk kkkk k001
    if (w & 0xFC07) == 0xF401:
        return ("brne", 2)

    return ("unknown", 2)


# Test vectors: (bytes_hex_le, expected_mnemonic, expected_size)
CASES = [
    ("0000", "nop", 2),
    ("0895", "ret", 2),
    ("1895", "reti", 2),
    ("8895", "sleep", 2),
    ("a895", "wdr", 2),
    ("9895", "break", 2),
    ("0994", "ijmp", 2),
    ("0995", "icall", 2),
    ("0c94" + "0000", "jmp", 4),    # JMP 0
    ("0e94" + "0000", "call", 4),   # CALL 0
    ("0090" + "0001", "lds", 4),    # LDS r0, 0x0100
    ("0092" + "0001", "sts", 4),    # STS 0x0100, r0
    ("00c0", "rjmp", 2),
    ("00d0", "rcall", 2),
    ("00e0", "ldi", 2),             # LDI r16, 0
    ("110c", "add", 2),             # add r0, r17 pattern
    ("0118", "sub", 2),
    ("1124", "eor", 2),
    ("0020", "and", 2),
    ("0028", "or", 2),
    ("002c", "mov", 2),
    ("0014", "cp", 2),
    ("0030", "cpi", 2),
    ("00b0", "in", 2),
    ("00b8", "out", 2),
    ("0f92", "push", 2),
    ("0f90", "pop", 2),
    ("01f0", "breq", 2),
    ("01f4", "brne", 2),
]


def main():
    functions = []
    mismatches = 0
    for hex_bytes, exp_mn, exp_sz in CASES:
        data = bytes.fromhex(hex_bytes)
        mn, sz = decode(data)
        ok = (mn == exp_mn and sz == exp_sz)
        if not ok:
            mismatches += 1
        functions.append({
            "input": hex_bytes,
            "expected": {"mnemonic": exp_mn, "size": exp_sz},
            "got": {"mnemonic": mn, "size": sz},
            "ok": ok,
        })

    result = {
        "crate": CRATE,
        "saved": False,
        "total": len(CASES),
        "mismatches": mismatches,
        "functions": functions,
    }

    os.makedirs(OUT_DIR, exist_ok=True)
    try:
        with open(OUT_PATH, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        result["saved"] = True
    except Exception as e:
        result["save_error"] = str(e)

    print(json.dumps({
        "crate": result["crate"],
        "saved": result["saved"],
        "functions": result["functions"],
    }, indent=2))
    return 0 if mismatches == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
