#!/usr/bin/env python3
"""
Rigorous ground-truth validation for all sparc_* MCP tools.
Reference implementations are inlined; no shelling to external tools.
"""
import json, subprocess, struct, sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_RESULTS = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_sparc_v2.json"
OUT_SKIP    = r"C:\Users\Fra\Desktop\RustRE\validation\skip_sparc.json"

# ─── Python reference implementations ────────────────────────────────────────
def ref_encode_alu_imm(op3, rs1, simm13, rd):
    simm13_u = simm13 & 0x1FFF
    return ((0b10 << 30) | ((rd & 31) << 25) | ((op3 & 63) << 19)
            | ((rs1 & 31) << 14) | (1 << 13) | simm13_u) & 0xFFFFFFFF

def ref_encode_alu_reg(op3, rs1, rs2, rd):
    return ((0b10 << 30) | ((rd & 31) << 25) | ((op3 & 63) << 19)
            | ((rs1 & 31) << 14) | (rs2 & 31)) & 0xFFFFFFFF

def ref_encode_load(op3, rs1, simm13, rd):
    simm13_u = simm13 & 0x1FFF
    return ((0b11 << 30) | ((rd & 31) << 25) | ((op3 & 63) << 19)
            | ((rs1 & 31) << 14) | (1 << 13) | simm13_u) & 0xFFFFFFFF

def ref_encode_store(op3, rs1, simm13, rd):
    return ref_encode_load(op3, rs1, simm13, rd)

def ref_encode_sethi(rd, imm22):
    return (((rd & 31) << 25) | (0b100 << 22) | (imm22 & 0x3FFFFF)) & 0xFFFFFFFF

def ref_encode_nop():
    return ref_encode_sethi(0, 0)

def ref_encode_call(disp):
    disp30 = (disp >> 2) & 0x3FFFFFFF
    return ((1 << 30) | disp30) & 0xFFFFFFFF

def ref_encode_jmpl(rs1, simm13, rd):
    return ref_encode_alu_imm(0x38, rs1, simm13, rd)

def ref_encode_bicc(cond, annul, disp):
    aligned = disp & ~3
    disp22 = (aligned >> 2) & 0x3FFFFF
    a = 1 if annul else 0
    return ((a << 29) | ((cond & 0xF) << 25) | (0b010 << 22) | disp22) & 0xFFFFFFFF

def ref_synth_mov_imm(imm, rd):
    return ref_encode_alu_imm(0x02, 0, imm, rd)

def ref_synth_mov_reg(rs, rd):
    return ref_encode_alu_reg(0x02, 0, rs, rd)

def ref_synth_clr(rd):
    return ref_encode_alu_reg(0x02, 0, 0, rd)

def ref_synth_not(rs, rd):
    return ref_encode_alu_reg(0x07, rs, 0, rd)

def ref_synth_neg(rs, rd):
    return ref_encode_alu_reg(0x04, 0, rs, rd)

def ref_synth_tst(rs):
    return ref_encode_alu_reg(0x12, 0, rs, 0)

def ref_synth_cmp_reg(rs1, rs2):
    return ref_encode_alu_reg(0x14, rs1, rs2, 0)

def ref_synth_cmp_imm(rs1, imm):
    return ref_encode_alu_imm(0x14, rs1, imm, 0)

def ref_synth_inc(rd):
    return ref_encode_alu_imm(0x00, rd, 1, rd)

def ref_synth_dec(rd):
    return ref_encode_alu_imm(0x04, rd, 1, rd)

def ref_build_prologue(framesize):
    return ref_encode_alu_imm(0x3C, 14, -framesize, 14)

def ref_build_epilogue():
    restore = ref_encode_alu_reg(0x3D, 0, 0, 0)
    nop = ref_encode_nop()
    return [restore, nop]

def ref_build_return_seq():
    jmpl = ref_encode_jmpl(31, 8, 0)
    nop = ref_encode_nop()
    return [jmpl, nop]

def ref_synth_set(val, rd):
    sv = val if val < 0x80000000 else val - 0x100000000  # to signed i32
    if -4096 <= sv <= 4095:
        return [ref_synth_mov_imm(sv, rd)]
    else:
        hi22 = val >> 10
        lo10 = val & 0x3FF
        sethi = ref_encode_sethi(rd, hi22)
        or_w = ref_encode_alu_imm(0x02, rd, lo10, rd)
        return [sethi, or_w]

# Lookup tables (from Rust static tables) – only a few spot-checks are needed
V8_TRAPS = {
    0x00: "reset",
    0x01: "instruction_access_exception",
    0x02: "illegal_instruction",
    0x05: "window_overflow",
    0x80: "syscall (SunOS)",
    0x81: "breakpoint",
}

V9_TRAPS = {
    0x00: "reserved",
    0x01: "power_on_reset",
    0x08: "instruction_access_exception",
}

ASI_TABLE = {
    # Ground truth from SPARC_ASI_TABLE in rustre-arch-sparc/src/lib.rs
    0x04: "ASI_NUCLEUS",
    0x0C: "ASI_NUCLEUS_LITTLE",
    0x10: "ASI_AS_IF_USER_PRIMARY",
}

CONDITIONS = {
    0: ("N", "N"),    # (icc, fcc)
    1: ("E", "NE"),
    8: ("A", "A"),
    9: ("NE", "E"),
}

FP_OPCODES = {
    0x01: "FMOVS",
    0x05: "FNEGS",
    0x09: "FABSS",
    0x41: "FADDS",
    0x42: "FADDD",
    0x49: "FMULS",
    0x51: "FCMPS",
    0x52: "FCMPD",
}

PRIV_REGS = {0: "%tpc", 1: "%tnpc", 2: "%tstate"}

# ─── MCP driver ──────────────────────────────────────────────────────────────
p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL, bufsize=0
)

def send(req):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()

def recv():
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("server died")
    return json.loads(line)

# Initialize
send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
    "protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"rigorous_sparc","version":"1"}}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

# Open project
send({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
    "name":"project.open","arguments":{"path":TARGET}}})
op = recv()
BINARY_ID = json.loads(op["result"]["content"][0]["text"])["binary_id"]

def call_tool(name, args):
    """Call an MCP tool and return the parsed JSON result or raise."""
    send({"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":name,"arguments":args}})
    r = recv()
    if "error" in r:
        raise RuntimeError(f"JSONRPC error: {r['error']}")
    content = r.get("result",{}).get("content",[])
    txt = content[0].get("text","") if content else ""
    if r.get("result",{}).get("isError"):
        raise RuntimeError(f"TOOL_ERROR: {txt}")
    return json.loads(txt)

# ─── Test cases ──────────────────────────────────────────────────────────────
passed, failed, skipped = 0, 0, 0
mismatches = []
skip_records = []

def check(tool, args, expected_key, expected_val, transform=None):
    global passed, failed
    try:
        result = call_tool(tool, args)
        actual = result.get(expected_key)
        if transform:
            actual = transform(actual)
        if actual == expected_val:
            passed += 1
            return True
        else:
            failed += 1
            mismatches.append({"tool": tool, "args": args,
                                "key": expected_key,
                                "expected": expected_val, "actual": actual})
            return False
    except Exception as e:
        failed += 1
        mismatches.append({"tool": tool, "args": args, "error": str(e)})
        return False

def check_word(tool, args, expected_word):
    return check(tool, args, "word", expected_word)

def skip(tool, reason):
    global skipped
    skipped += 1
    skip_records.append({"tool": tool, "reason": reason})

# ── sparc_encode_nop ─────────────────────────────────────────────────────────
check_word("sparc_encode_nop", {}, ref_encode_nop())

# ── sparc_encode_call ────────────────────────────────────────────────────────
check_word("sparc_encode_call", {"disp": 64}, ref_encode_call(64))
check_word("sparc_encode_call", {"disp": 1024}, ref_encode_call(1024))

# ── sparc_encode_sethi ───────────────────────────────────────────────────────
check_word("sparc_encode_sethi", {"rd": 8, "imm22": 0x3FF}, ref_encode_sethi(8, 0x3FF))
check_word("sparc_encode_sethi", {"rd": 0, "imm22": 0}, ref_encode_sethi(0, 0))  # should be NOP encoding

# ── sparc_encode_alu_reg ─────────────────────────────────────────────────────
# ADD %o0, %o1, %o0: op3=0, rs1=8, rs2=9, rd=8
check_word("sparc_encode_alu_reg", {"op3": 0, "rs1": 8, "rs2": 9, "rd": 8},
           ref_encode_alu_reg(0, 8, 9, 8))

# ── sparc_encode_alu_imm ─────────────────────────────────────────────────────
# ADD %o0, 5, %o0: op3=0, rs1=8, simm13=5, rd=8
check_word("sparc_encode_alu_imm", {"op3": 0, "rs1": 8, "simm13": 5, "rd": 8},
           ref_encode_alu_imm(0, 8, 5, 8))
# Negative immediate
check_word("sparc_encode_alu_imm", {"op3": 0x3C, "rs1": 14, "simm13": -96, "rd": 14},
           ref_encode_alu_imm(0x3C, 14, -96, 14))

# ── sparc_encode_load ────────────────────────────────────────────────────────
# LD [%sp+0], %o0: op3=0, rs1=14, simm13=0, rd=8
check_word("sparc_encode_load", {"op3": 0, "rs1": 14, "simm13": 0, "rd": 8},
           ref_encode_load(0, 14, 0, 8))

# ── sparc_encode_store ───────────────────────────────────────────────────────
# ST %o0, [%sp+0]: op3=4, rs1=14, simm13=0, rd=8
check_word("sparc_encode_store", {"op3": 4, "rs1": 14, "simm13": 0, "rd": 8},
           ref_encode_store(4, 14, 0, 8))

# ── sparc_encode_jmpl ────────────────────────────────────────────────────────
# JMPL %i7+8, %g0 -> RETURN
check_word("sparc_encode_jmpl", {"rs1": 31, "simm13": 8, "rd": 0},
           ref_encode_jmpl(31, 8, 0))

# ── sparc_encode_bicc ────────────────────────────────────────────────────────
# BA +4
check_word("sparc_encode_bicc", {"cond": 8, "annul": False, "disp": 4},
           ref_encode_bicc(8, False, 4))
# BNE +16, annul
check_word("sparc_encode_bicc", {"cond": 9, "annul": True, "disp": 16},
           ref_encode_bicc(9, True, 16))

# ── sparc_synth_mov_imm ──────────────────────────────────────────────────────
check_word("sparc_synth_mov_imm", {"imm": 42, "rd": 8}, ref_synth_mov_imm(42, 8))
check_word("sparc_synth_mov_imm", {"imm": -1, "rd": 1}, ref_synth_mov_imm(-1, 1))

# ── sparc_synth_mov_reg ──────────────────────────────────────────────────────
check_word("sparc_synth_mov_reg", {"rs": 8, "rd": 9}, ref_synth_mov_reg(8, 9))

# ── sparc_synth_clr ──────────────────────────────────────────────────────────
check_word("sparc_synth_clr", {"rd": 8}, ref_synth_clr(8))

# ── sparc_synth_neg ──────────────────────────────────────────────────────────
check_word("sparc_synth_neg", {"rs": 8, "rd": 9}, ref_synth_neg(8, 9))

# ── sparc_synth_not ──────────────────────────────────────────────────────────
check_word("sparc_synth_not", {"rs": 8, "rd": 9}, ref_synth_not(8, 9))

# ── sparc_synth_tst ──────────────────────────────────────────────────────────
check_word("sparc_synth_tst", {"rs": 8}, ref_synth_tst(8))

# ── sparc_synth_cmp_reg ──────────────────────────────────────────────────────
check_word("sparc_synth_cmp_reg", {"rs1": 8, "rs2": 9}, ref_synth_cmp_reg(8, 9))

# ── sparc_synth_cmp_imm ──────────────────────────────────────────────────────
check_word("sparc_synth_cmp_imm", {"rs1": 8, "imm": 5}, ref_synth_cmp_imm(8, 5))

# ── sparc_synth_inc ──────────────────────────────────────────────────────────
check_word("sparc_synth_inc", {"rd": 8}, ref_synth_inc(8))

# ── sparc_synth_dec ──────────────────────────────────────────────────────────
check_word("sparc_synth_dec", {"rd": 8}, ref_synth_dec(8))

# ── sparc_build_prologue ─────────────────────────────────────────────────────
check_word("sparc_build_prologue", {"framesize": 96}, ref_build_prologue(96))
check_word("sparc_build_prologue", {"framesize": 112}, ref_build_prologue(112))

# ── sparc_build_epilogue ─────────────────────────────────────────────────────
expected_epi = ref_build_epilogue()
check("sparc_build_epilogue", {}, "words", expected_epi)

# ── sparc_build_return_seq ───────────────────────────────────────────────────
expected_ret = ref_build_return_seq()
check("sparc_build_return_seq", {}, "words", expected_ret)

# ── sparc_synth_set (1-word path) ────────────────────────────────────────────
check("sparc_synth_set", {"val": 42, "rd": 8}, "words", ref_synth_set(42, 8))

# ── sparc_synth_set (2-word path) ────────────────────────────────────────────
check("sparc_synth_set", {"val": 0x12345678, "rd": 8}, "words", ref_synth_set(0x12345678, 8))

# ── sparc_lookup_v8_trap (spot checks) ───────────────────────────────────────
for trap_num, trap_desc in V8_TRAPS.items():
    res = call_tool("sparc_lookup_v8_trap", {"number": trap_num})
    exp_found = True
    exp_desc = trap_desc
    if res.get("found") == exp_found and res.get("description") == exp_desc:
        passed += 1
    else:
        failed += 1
        mismatches.append({"tool": "sparc_lookup_v8_trap",
                            "args": {"number": trap_num},
                            "expected": {"found": True, "description": trap_desc},
                            "actual": res})

# trap not found
res_nf = call_tool("sparc_lookup_v8_trap", {"number": 0x99})
if res_nf.get("found") == False:
    passed += 1
else:
    failed += 1
    mismatches.append({"tool": "sparc_lookup_v8_trap", "args": {"number": 0x99},
                        "expected": {"found": False}, "actual": res_nf})

# ── sparc_lookup_v9_trap (spot checks) ───────────────────────────────────────
for trap_num, trap_desc in V9_TRAPS.items():
    res = call_tool("sparc_lookup_v9_trap", {"number": trap_num})
    if res.get("found") == True and res.get("description") == trap_desc:
        passed += 1
    else:
        failed += 1
        mismatches.append({"tool": "sparc_lookup_v9_trap",
                            "args": {"number": trap_num},
                            "expected": {"found": True, "description": trap_desc},
                            "actual": res})

# ── sparc_lookup_asi (spot checks) ───────────────────────────────────────────
for asi_num, asi_desc in ASI_TABLE.items():
    res = call_tool("sparc_lookup_asi", {"asi": asi_num})
    if res.get("found") == True and res.get("description") == asi_desc:
        passed += 1
    else:
        failed += 1
        mismatches.append({"tool": "sparc_lookup_asi",
                            "args": {"asi": asi_num},
                            "expected": {"found": True, "description": asi_desc},
                            "actual": res})

# ── sparc_lookup_condition (spot checks) ─────────────────────────────────────
for code, (icc, fcc) in CONDITIONS.items():
    res = call_tool("sparc_lookup_condition", {"code": code})
    if res.get("found") == True and res.get("icc_suffix") == icc and res.get("fcc_suffix") == fcc:
        passed += 1
    else:
        failed += 1
        mismatches.append({"tool": "sparc_lookup_condition",
                            "args": {"code": code},
                            "expected": {"icc_suffix": icc, "fcc_suffix": fcc},
                            "actual": res})

# ── sparc_lookup_fp_opcode (spot checks) ─────────────────────────────────────
for opf, mn in FP_OPCODES.items():
    res = call_tool("sparc_lookup_fp_opcode", {"opf": opf})
    if res.get("found") == True and res.get("mnemonic") == mn:
        passed += 1
    else:
        failed += 1
        mismatches.append({"tool": "sparc_lookup_fp_opcode",
                            "args": {"opf": opf},
                            "expected": {"found": True, "mnemonic": mn},
                            "actual": res})

# opf not found
res_nf = call_tool("sparc_lookup_fp_opcode", {"opf": 0xFFF})
if res_nf.get("found") == False:
    passed += 1
else:
    failed += 1
    mismatches.append({"tool": "sparc_lookup_fp_opcode", "args": {"opf": 0xFFF},
                        "expected": {"found": False}, "actual": res_nf})

# ── sparc_lookup_priv_reg (spot checks) ──────────────────────────────────────
for field, name in PRIV_REGS.items():
    res = call_tool("sparc_lookup_priv_reg", {"field": field})
    if res.get("found") == True and res.get("name") == name:
        passed += 1
    else:
        failed += 1
        mismatches.append({"tool": "sparc_lookup_priv_reg",
                            "args": {"field": field},
                            "expected": {"found": True, "name": name},
                            "actual": res})

# ── sparc_extract_branch_targets ─────────────────────────────────────────────
# BA +4 at base 0x1000: [0x10, 0x80, 0x00, 0x01] => target = 0x1000 + 4 = 0x1004
res = call_tool("sparc_extract_branch_targets", {"bytes_hex": "10800001", "base": 0x1000})
targets = res.get("targets", [])
# Expect one target: from 0x1000 to 0x1004
if len(targets) == 1 and targets[0].get("to") == 0x1004:
    passed += 1
else:
    failed += 1
    mismatches.append({"tool": "sparc_extract_branch_targets",
                        "args": {"bytes_hex": "10800001", "base": 0x1000},
                        "expected": {"count": 1, "targets[0].to": 0x1004},
                        "actual": res})

# ─── Teardown ────────────────────────────────────────────────────────────────
p.stdin.close()
p.terminate()

total_hardened = passed + failed

results = {
    "category": "sparc",
    "tools_hardened": total_hardened,
    "checks_total": total_hardened + skipped,
    "checks_passed": passed,
    "checks_failed": failed,
    "checks_skipped": skipped,
    "mismatches": mismatches,
}

with open(OUT_RESULTS, "w") as f:
    json.dump(results, f, indent=2)

with open(OUT_SKIP, "w") as f:
    json.dump(skip_records, f, indent=2)

print(f"sparc rigorous: passed={passed}, failed={failed}, skipped={skipped}")
for m in mismatches:
    print(f"  MISMATCH: {m}")

sys.exit(0 if failed == 0 else 1)
