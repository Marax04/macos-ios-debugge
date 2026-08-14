#!/usr/bin/env python3
"""Independent validator for rustre-arch-ppc.

Pure-Python reimplementation of pure-math / table-lookup behavior of the
PowerPC architecture crate. No imports from the Rust workspace, no MCP
calls. Uses only stdlib (capstone optional, best-effort).

Usage:
    echo '{"fn":"encode_li","args":{"rt":3,"simm":1234}}' | \
        python rustre-arch-ppc.py

If no stdin is provided, main() runs a fixed test corpus.

Encodings follow PowerISA v2.07 / v3.1 (big-endian word, 32-bit fixed).
"""
import json
import sys
import subprocess

# ---- optional deps --------------------------------------------------------
def _ensure(mod, pip_name=None):
    try:
        return __import__(mod)
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "-q",
                        pip_name or mod], check=False)
        try:
            return __import__(mod)
        except ImportError:
            return None

capstone = _ensure("capstone")

# ---- constants ------------------------------------------------------------
GPR_NAMES = [f"r{i}" for i in range(32)]
FPR_NAMES = [f"f{i}" for i in range(32)]
VR_NAMES  = [f"v{i}" for i in range(32)]

# SysV PPC EABI role per GPR index
def _role_eabi(idx):
    if idx == 0:                 return "Volatile"      # r0 scratch
    if idx == 1:                 return "StackPointer"  # r1 = sp
    if idx == 2:                 return "Toc"           # r2 = TOC/SDA2
    if idx == 3 or idx == 4:     return "ArgReturn"     # r3/r4
    if 5 <= idx <= 10:           return "Arg"           # r5..r10
    if idx == 11 or idx == 12:   return "Volatile"
    if idx == 13:                return "Sda"           # small-data anchor
    if 14 <= idx <= 31:          return "Saved"         # nonvolatile
    return None

# Common SPR numbers (PowerISA Book III, e500 RM subset)
SPR_TABLE = {
    1:   ("XER",   "Fixed-point exception register"),
    8:   ("LR",    "Link register"),
    9:   ("CTR",   "Count register"),
    18:  ("DSISR", "DSI source"),
    19:  ("DAR",   "Data address register"),
    22:  ("DEC",   "Decrementer"),
    25:  ("SDR1",  "Storage description"),
    26:  ("SRR0",  "Save/restore 0"),
    27:  ("SRR1",  "Save/restore 1"),
    256: ("VRSAVE","Vector register save"),
    272: ("SPRG0", "Software-use SPRG0"),
    273: ("SPRG1", "Software-use SPRG1"),
    274: ("SPRG2", "Software-use SPRG2"),
    275: ("SPRG3", "Software-use SPRG3"),
    287: ("PVR",   "Processor version"),
    528: ("IBAT0U","Instruction BAT 0 upper"),
    1008:("HID0",  "Hardware implementation 0"),
    1009:("HID1",  "Hardware implementation 1"),
}

# MSR bit names (selected, Book III/E)
MSR_BITS = {
    "SF":  63,  "HV": 60,  "VEC": 25, "VSX": 23,
    "POW": 18,  "EE": 15,  "PR": 14,  "FP": 13,
    "ME":  12,  "FE0": 11, "SE": 10,  "BE": 9,
    "FE1": 8,   "IR": 5,   "DR": 4,   "LE": 0,
}

# Standard exception vector base offsets (Book III, classic PPC)
EXCEPTIONS = {
    0x00100: "SystemReset",
    0x00200: "MachineCheck",
    0x00300: "DataStorage",
    0x00400: "InstructionStorage",
    0x00500: "ExternalInterrupt",
    0x00600: "Alignment",
    0x00700: "Program",
    0x00800: "FpUnavailable",
    0x00900: "Decrementer",
    0x00C00: "SystemCall",
    0x00D00: "Trace",
    0x00F20: "VectorUnavailable",
}

# ---- bit utils ------------------------------------------------------------
def _u32(v): return v & 0xFFFFFFFF
def _u64(v): return v & 0xFFFFFFFFFFFFFFFF
def _mask(n): return (1 << n) - 1
def _sx(v, bits):
    v &= _mask(bits)
    if v & (1 << (bits - 1)):
        v -= (1 << bits)
    return v

# ---- byte order / IO ------------------------------------------------------
def validator_read_be32(b, off=0):
    if off + 4 > len(b): return None
    return int.from_bytes(bytes(b[off:off+4]), "big")

def validator_write_be32(word, size=4):
    buf = bytearray(size)
    buf[0:4] = _u32(word).to_bytes(4, "big")
    return list(buf)

def validator_swap32(x):
    x = _u32(x)
    return int.from_bytes(x.to_bytes(4, "big"), "little")

# ---- register lookups -----------------------------------------------------
def validator_gpr(idx):
    if 0 <= idx < 32: return GPR_NAMES[idx]
    return None

def validator_fpr(idx):
    if 0 <= idx < 32: return FPR_NAMES[idx]
    return None

def validator_vr(idx):
    if 0 <= idx < 32: return VR_NAMES[idx]
    return None

def validator_gpr_role_eabi(idx): return _role_eabi(idx)

def validator_lookup_spr(spr):
    e = SPR_TABLE.get(spr & 0x3FF)
    if e is None: return None
    return {"name": e[0], "desc": e[1]}

def validator_spr_name(spr):
    e = SPR_TABLE.get(spr & 0x3FF)
    return e[0] if e else f"SPR{spr & 0x3FF}"

def validator_spr_number(name):
    name = name.upper()
    for n, (nm, _) in SPR_TABLE.items():
        if nm == name: return n
    return None

def validator_lookup_msr_bit(name):
    return MSR_BITS.get(name.upper())

def validator_lookup_ppc_exception(vec):
    return EXCEPTIONS.get(vec & 0xFFFFF)

# ---- branch target math ---------------------------------------------------
def validator_branch_target_i(address, li, aa=0):
    """I-form branch: BD<<2 with LI 24-bit signed, AA flag."""
    li &= 0x00FFFFFF
    disp = _sx(li, 24) << 2
    if aa:
        return _u64(disp & 0xFFFFFFFF)
    return _u64(address + disp)

def validator_branch_target_b(address, bd, aa=0):
    """B-form branch: BD 14-bit signed, AA flag."""
    bd &= 0x3FFF
    disp = _sx(bd, 14) << 2
    if aa:
        return _u64(disp & 0xFFFFFFFF)
    return _u64(address + disp)

# ---- encoders -------------------------------------------------------------
def _opcd(op, rest):
    return _u32(((op & 0x3F) << 26) | (rest & 0x03FFFFFF))

def _dform(op, rt, ra, d):
    return _u32(((op & 0x3F) << 26) |
                ((rt & 0x1F) << 21) |
                ((ra & 0x1F) << 16) |
                (d & 0xFFFF))

def _xform(op, rt, ra, rb, xo, rc=0):
    return _u32(((op & 0x3F) << 26) |
                ((rt & 0x1F) << 21) |
                ((ra & 0x1F) << 16) |
                ((rb & 0x1F) << 11) |
                ((xo & 0x3FF) << 1) |
                (rc & 1))

def _xfxform(op, rt, spr, xo):
    # SPR field is split: low5 | high5 in encoding
    spr &= 0x3FF
    spr_enc = ((spr & 0x1F) << 5) | ((spr >> 5) & 0x1F)
    return _u32(((op & 0x3F) << 26) |
                ((rt & 0x1F) << 21) |
                (spr_enc << 11) |
                ((xo & 0x3FF) << 1))

def _mform(op, rs, ra, sh, mb, me, rc=0):
    return _u32(((op & 0x3F) << 26) |
                ((rs & 0x1F) << 21) |
                ((ra & 0x1F) << 16) |
                ((sh & 0x1F) << 11) |
                ((mb & 0x1F) << 6) |
                ((me & 0x1F) << 1) |
                (rc & 1))

def validator_encode_b(address, target, lk=0, aa=0):
    disp = (target - address) if not aa else target
    li = (disp >> 2) & 0x00FFFFFF
    return _u32((18 << 26) | (li << 2) | ((aa & 1) << 1) | (lk & 1))

def validator_encode_bl(address, target):
    return validator_encode_b(address, target, lk=1)

def validator_encode_bclr(bo=20, bi=0, lk=0):
    # XL-form, opcode 19, XO=16
    return _u32((19 << 26) | ((bo & 0x1F) << 21) | ((bi & 0x1F) << 16) |
                (16 << 1) | (lk & 1))

def validator_encode_li(rt, simm):
    # addi rT, 0, simm
    return _dform(14, rt, 0, simm & 0xFFFF)

def validator_encode_lis(rt, simm):
    # addis rT, 0, simm
    return _dform(15, rt, 0, simm & 0xFFFF)

def validator_encode_addi(rt, ra, simm):
    return _dform(14, rt, ra, simm & 0xFFFF)

def validator_encode_stw(rs, ra, d):
    return _dform(36, rs, ra, d & 0xFFFF)

def validator_encode_lwz(rt, ra, d):
    return _dform(32, rt, ra, d & 0xFFFF)

def validator_encode_stwu(rs, ra, d):
    return _dform(37, rs, ra, d & 0xFFFF)

def validator_encode_lbz(rt, ra, d):
    return _dform(34, rt, ra, d & 0xFFFF)

def validator_encode_lhz(rt, ra, d):
    return _dform(40, rt, ra, d & 0xFFFF)

def validator_encode_lha(rt, ra, d):
    return _dform(42, rt, ra, d & 0xFFFF)

def validator_encode_stb(rs, ra, d):
    return _dform(38, rs, ra, d & 0xFFFF)

def validator_encode_sth(rs, ra, d):
    return _dform(44, rs, ra, d & 0xFFFF)

def validator_encode_lfs(frt, ra, d):
    return _dform(48, frt, ra, d & 0xFFFF)

def validator_encode_stfs(frs, ra, d):
    return _dform(52, frs, ra, d & 0xFFFF)

def validator_encode_cmpwi(bf, ra, simm):
    # opcode 11, L=0
    return _u32((11 << 26) | ((bf & 7) << 23) | ((ra & 0x1F) << 16) |
                (simm & 0xFFFF))

def validator_encode_cmplwi(bf, ra, uimm):
    # opcode 10, L=0
    return _u32((10 << 26) | ((bf & 7) << 23) | ((ra & 0x1F) << 16) |
                (uimm & 0xFFFF))

def validator_encode_twi(to, ra, simm):
    return _dform(3, to, ra, simm & 0xFFFF)

def validator_encode_mfspr(rt, spr):
    # XFX-form, opcode 31, XO=339
    return _xfxform(31, rt, spr, 339)

def validator_encode_mtspr(rs, spr):
    return _xfxform(31, rs, spr, 467)

def validator_encode_mfsr(rt, sr):
    # opcode 31, XO=595, SR in bits 12..15
    return _u32((31 << 26) | ((rt & 0x1F) << 21) | ((sr & 0xF) << 16) |
                (595 << 1))

def validator_encode_mtsr(rs, sr):
    return _u32((31 << 26) | ((rs & 0x1F) << 21) | ((sr & 0xF) << 16) |
                (210 << 1))

def validator_encode_rlwinm(ra, rs, sh, mb, me, rc=0):
    # opcode 21, M-form
    return _mform(21, rs, ra, sh, mb, me, rc)

def validator_encode_srawi(ra, rs, sh, rc=0):
    # opcode 31, XO=824
    return _u32((31 << 26) | ((rs & 0x1F) << 21) | ((ra & 0x1F) << 16) |
                ((sh & 0x1F) << 11) | (824 << 1) | (rc & 1))

# ---- analysis -------------------------------------------------------------
def validator_detect_ppc_prologue(words):
    """First word is typically `stwu r1, -N(r1)` or `mflr r0; stwu r1,-N(r1)`.
    Return the frame size N if recognized, else None."""
    if not words: return None
    for w in words[:4]:
        w = _u32(w)
        op = (w >> 26) & 0x3F
        if op == 37:  # stwu
            rs = (w >> 21) & 0x1F
            ra = (w >> 16) & 0x1F
            d = w & 0xFFFF
            if rs == 1 and ra == 1:
                d = _sx(d, 16)
                if d < 0: return -d
    return None

def validator_detect_ppc_epilogue(words):
    """Epilogue: typically `addi r1,r1,N` followed by `mtlr` and `blr` (0x4E800020)."""
    found_blr = False
    for w in words[-6:]:
        if _u32(w) == 0x4E800020:  # blr
            found_blr = True
    return found_blr

def validator_has_branch(word):
    w = _u32(word)
    op = (w >> 26) & 0x3F
    if op in (16, 18):  # bc, b
        return True
    if op == 19:
        xo = (w >> 1) & 0x3FF
        if xo in (16, 528):  # bclr, bcctr
            return True
    return False

# ---- decoder via capstone (optional) -------------------------------------
def validator_decode_word(word, addr=0, endian="big", mode64=False):
    if capstone is None: return {"error": "capstone-missing"}
    cs_mode = capstone.CS_MODE_BIG_ENDIAN if endian == "big" else capstone.CS_MODE_LITTLE_ENDIAN
    cs_mode |= (capstone.CS_MODE_64 if mode64 else capstone.CS_MODE_32)
    md = capstone.Cs(capstone.CS_ARCH_PPC, cs_mode)
    raw = _u32(word).to_bytes(4, endian)
    for i in md.disasm(raw, addr):
        return {"mnemonic": i.mnemonic, "op_str": i.op_str, "address": i.address}
    return None

# ---- dispatch -------------------------------------------------------------
FUNCTIONS = {
    "read_be32":            validator_read_be32,
    "write_be32":           validator_write_be32,
    "swap32":               validator_swap32,
    "gpr":                  validator_gpr,
    "fpr":                  validator_fpr,
    "vr":                   validator_vr,
    "gpr_role_eabi":        validator_gpr_role_eabi,
    "lookup_spr":           validator_lookup_spr,
    "spr_name":             validator_spr_name,
    "spr_number":           validator_spr_number,
    "lookup_msr_bit":       validator_lookup_msr_bit,
    "lookup_ppc_exception": validator_lookup_ppc_exception,
    "branch_target_i":      validator_branch_target_i,
    "branch_target_b":      validator_branch_target_b,
    "encode_b":             validator_encode_b,
    "encode_bl":            validator_encode_bl,
    "encode_bclr":          validator_encode_bclr,
    "encode_li":            validator_encode_li,
    "encode_lis":           validator_encode_lis,
    "encode_addi":          validator_encode_addi,
    "encode_stw":           validator_encode_stw,
    "encode_lwz":           validator_encode_lwz,
    "encode_stwu":          validator_encode_stwu,
    "encode_lbz":           validator_encode_lbz,
    "encode_lhz":           validator_encode_lhz,
    "encode_lha":           validator_encode_lha,
    "encode_stb":           validator_encode_stb,
    "encode_sth":           validator_encode_sth,
    "encode_lfs":           validator_encode_lfs,
    "encode_stfs":          validator_encode_stfs,
    "encode_cmpwi":         validator_encode_cmpwi,
    "encode_cmplwi":        validator_encode_cmplwi,
    "encode_twi":           validator_encode_twi,
    "encode_mfspr":         validator_encode_mfspr,
    "encode_mtspr":         validator_encode_mtspr,
    "encode_mfsr":          validator_encode_mfsr,
    "encode_mtsr":          validator_encode_mtsr,
    "encode_rlwinm":        validator_encode_rlwinm,
    "encode_srawi":         validator_encode_srawi,
    "detect_ppc_prologue":  validator_detect_ppc_prologue,
    "detect_ppc_epilogue":  validator_detect_ppc_epilogue,
    "has_branch":           validator_has_branch,
    "decode_word":          validator_decode_word,
}

def dispatch(name, args):
    fn = FUNCTIONS[name]
    if isinstance(args, dict): return fn(**args)
    if isinstance(args, list): return fn(*args)
    return fn(args)

def main():
    data = sys.stdin.read().strip() if not sys.stdin.isatty() else ""
    if data:
        req = json.loads(data)
        out = dispatch(req["fn"], req.get("args", {}))
        print(json.dumps({"result": out},
                         default=lambda o: list(o) if isinstance(o, (bytes, bytearray)) else o))
        return
    # fixed self-test corpus
    samples = [
        ("swap32",               [0xAABBCCDD]),
        ("gpr",                  [1]),
        ("gpr_role_eabi",        [3]),
        ("lookup_spr",           [8]),
        ("spr_name",             [9]),
        ("spr_number",           ["LR"]),
        ("lookup_msr_bit",       ["EE"]),
        ("lookup_ppc_exception", [0x00C00]),
        ("branch_target_i",      {"address": 0x1000, "li": 0x100}),
        ("branch_target_b",      {"address": 0x1000, "bd": -4 & 0x3FFF}),
        ("encode_b",             {"address": 0x1000, "target": 0x1100}),
        ("encode_bl",            {"address": 0x1000, "target": 0x2000}),
        ("encode_bclr",          {}),                       # blr
        ("encode_li",            {"rt": 3, "simm": 1234}),
        ("encode_lis",           {"rt": 3, "simm": 0x1234}),
        ("encode_addi",          {"rt": 3, "ra": 4, "simm": -16}),
        ("encode_stwu",          {"rs": 1, "ra": 1, "d": -32 & 0xFFFF}),
        ("encode_lwz",           {"rt": 3, "ra": 1, "d": 8}),
        ("encode_stw",           {"rs": 3, "ra": 1, "d": 8}),
        ("encode_cmpwi",         {"bf": 0, "ra": 3, "simm": 0}),
        ("encode_mfspr",         {"rt": 0, "spr": 8}),       # mflr r0
        ("encode_mtspr",         {"rs": 0, "spr": 8}),       # mtlr r0
        ("encode_rlwinm",        {"ra": 3, "rs": 4, "sh": 2, "mb": 0, "me": 29}),
        ("encode_srawi",         {"ra": 3, "rs": 4, "sh": 31}),
        ("detect_ppc_prologue",  [[0x9421FFE0]]),            # stwu r1,-32(r1)
        ("detect_ppc_epilogue",  [[0x38210020, 0x4E800020]]),# addi r1,r1,32; blr
        ("has_branch",           [0x4E800020]),              # blr
    ]
    results = {}
    for name, a in samples:
        try: results[name] = dispatch(name, a)
        except Exception as e: results[name] = f"ERR:{e}"
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
