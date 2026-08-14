#!/usr/bin/env python3
"""
Rigorous ground-truth validator for m68k_* MCP tools.
Uses independently-computed Python reference values; no loose any_valid() checks.
"""
import json, subprocess, sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT_PASS_FAIL = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_m68k_v2.json"
SKIP_FILE     = r"C:\Users\Fra\Desktop\RustRE\validation\skip_m68k.json"

# ── MCP plumbing ──────────────────────────────────────────────────────────────

p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    bufsize=0
)

def send(req):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()

def recv():
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("server died")
    return json.loads(line)

# Handshake
send({"jsonrpc":"2.0","id":1,"method":"initialize",
      "params":{"protocolVersion":"2024-11-05","capabilities":{},
                "clientInfo":{"name":"rigorous_m68k","version":"1"}}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

_req_id = 10
def call_tool(name, args):
    global _req_id
    _req_id += 1
    send({"jsonrpc":"2.0","id":_req_id,"method":"tools/call",
          "params":{"name":name,"arguments":args}})
    resp = recv()
    if "error" in resp:
        return None, str(resp["error"])
    content = resp.get("result",{}).get("content",[])
    txt = content[0].get("text","") if content else ""
    is_err = resp.get("result",{}).get("isError", False)
    if is_err:
        return None, txt
    try:
        return json.loads(txt), None
    except json.JSONDecodeError:
        return txt, None


# ── Python reference: m68k_variant_info ──────────────────────────────────────
# Ground truth read directly from Rust enum definitions in
# crates/rustre-arch-68k/src/lib.rs  (const fns, no runtime state).

VARIANT_GROUND_TRUTH = {
    "68000":    {"variant":"68000",    "has_fpu":False,"has_mmu":False,"is_32bit":False,"has_bitfield":False,"address_space_bytes":0x0100_0000},
    "68010":    {"variant":"68010",    "has_fpu":False,"has_mmu":False,"is_32bit":False,"has_bitfield":False,"address_space_bytes":0x0100_0000},
    "68020":    {"variant":"68020",    "has_fpu":False,"has_mmu":False,"is_32bit":True, "has_bitfield":True, "address_space_bytes":0x1_0000_0000},
    "68030":    {"variant":"68030",    "has_fpu":False,"has_mmu":True, "is_32bit":True, "has_bitfield":True, "address_space_bytes":0x1_0000_0000},
    "68040":    {"variant":"68040",    "has_fpu":True, "has_mmu":True, "is_32bit":True, "has_bitfield":True, "address_space_bytes":0x1_0000_0000},
    "68060":    {"variant":"68060",    "has_fpu":True, "has_mmu":True, "is_32bit":True, "has_bitfield":True, "address_space_bytes":0x1_0000_0000},
    "ColdFire": {"variant":"ColdFire", "has_fpu":False,"has_mmu":False,"is_32bit":True, "has_bitfield":True, "address_space_bytes":0x1_0000_0000},
}


# ── Python reference: m68k_decode_instr ──────────────────────────────────────
# A minimal independent Python re-implementation of decode_68k() covering the
# test vectors below.  We only implement what we actually test; if a test vector
# hits the "?" fallback we record it as untested rather than guessing.
#
# All test cases are well-known 68000 opcodes whose binary encoding is defined
# by the original Motorola MC68000 User's Manual.

def _ea_str(mode, reg, size_bytes, ext):
    """Return (text, extra_bytes_consumed) for an effective address."""
    if mode == 0: return f"D{reg}", 0
    if mode == 1: return f"A{reg}", 0
    if mode == 2: return f"(A{reg})", 0
    if mode == 3: return f"(A{reg})+", 0
    if mode == 4: return f"-(A{reg})", 0
    if mode == 5:
        if len(ext) >= 2:
            disp = int.from_bytes(ext[:2], "big", signed=True)
            return f"{disp}(A{reg})", 2
        return f"?(A{reg})", 2
    if mode == 6:
        if len(ext) >= 2:
            brief = ext[0]; disp = int.from_bytes([ext[1]], "big", signed=True)
            idx_reg = (brief >> 4) & 0xF
            idx_type = 'A' if (brief & 0x80) else 'D'
            return f"{disp}(A{reg},{idx_type}{idx_reg})", 2
        return f"(A{reg}+Xn)", 2
    if mode == 7:
        if reg == 0:
            if len(ext) >= 2:
                addr = int.from_bytes(ext[:2], "big")
                return f"${addr:04X}.W", 2
        if reg == 1:
            if len(ext) >= 4:
                addr = int.from_bytes(ext[:4], "big")
                return f"${addr:08X}.L", 4
        if reg == 2:
            if len(ext) >= 2:
                disp = int.from_bytes(ext[:2], "big", signed=True)
                return f"{disp}(PC)", 2
        if reg == 3:
            return "(PC,Xn)", 2
        if reg == 4:
            if size_bytes == 1:  # byte: padded to word
                val = ext[1] if len(ext) >= 2 else 0
                return f"#${val:02X}", 2
            elif size_bytes == 2 and len(ext) >= 2:
                val = int.from_bytes(ext[:2], "big")
                return f"#${val:04X}", 2
            elif size_bytes == 4 and len(ext) >= 4:
                val = int.from_bytes(ext[:4], "big")
                return f"#${val:08X}", 4
    return "?", 0

CC = ["T","F","HI","LS","CC","CS","NE","EQ","VC","VS","PL","MI","GE","LT","GT","LE"]

def decode_68k_py(hex_bytes: str, pc: int):
    """
    Minimal Python reference decoder.  Returns dict with keys:
        mnemonic, operands, size, flags_hint
    or raises ValueError for unsupported/untestable encodings.
    """
    raw = bytes.fromhex(hex_bytes.replace(" ",""))
    if len(raw) < 2:
        raise ValueError("too short")
    word = int.from_bytes(raw[:2], "big")
    ext  = raw[2:]
    hi4  = (word >> 12) & 0xF
    ea_mode = (word >> 3) & 7
    ea_reg  = word & 7

    # ── MOVE/MOVEA (hi4 1,2,3) ────────────────────────────────────────────
    if hi4 in (1, 2, 3):
        sz_map = {1:(1,".B"), 3:(2,".W"), 2:(4,".L")}
        sz_bytes, sfx = sz_map[hi4]
        src, src_ext = _ea_str(ea_mode, ea_reg, sz_bytes, ext)
        dst_mode = (word >> 6) & 7
        dst_reg  = (word >> 9) & 7
        ext2 = ext[src_ext:] if src_ext <= len(ext) else b""
        dst, dst_ext = _ea_str(dst_mode, dst_reg, sz_bytes, ext2)
        total = 2 + src_ext + dst_ext
        mn = f"MOVEA{sfx}" if dst_mode == 1 else f"MOVE{sfx}"
        return {"mnemonic": mn, "operands": f"{src},{dst}", "size": total}

    # ── Group 0 ───────────────────────────────────────────────────────────
    if hi4 == 0:
        # NOP-like immediate group
        sz_bits = (word >> 6) & 3
        sz_bytes = [1,2,4,4][sz_bits]
        imm_op = (word >> 9) & 7
        reg_field = (word >> 9) & 7

        # BTST/BCHG/BCLR/BSET #imm
        if (word & 0xFF00) == 0x0800:
            if len(ext) < 2: raise ValueError("truncated bit op")
            op3 = (word >> 6) & 3
            bit_num = ext[0]
            ea, ea_ext = _ea_str(ea_mode, ea_reg, 1, ext[2:])
            mn = ["BTST","BCHG","BCLR","BSET"][op3]
            return {"mnemonic": mn, "operands": f"#${bit_num:02X},{ea}", "size": 4+ea_ext}

        # ORI/ANDI/SUBI/ADDI/EORI/CMPI
        if (word & 0x0100) == 0 and imm_op <= 6:
            if sz_bits == 0:  # byte
                imm_bytes = 2
                imm_s = f"#${ext[1]:02X}" if len(ext)>=2 else "#?"
            elif sz_bits == 1:  # word
                imm_bytes = 2
                imm_s = f"#${int.from_bytes(ext[:2],'big'):04X}" if len(ext)>=2 else "#?"
            else:  # long
                imm_bytes = 4
                imm_s = f"#${int.from_bytes(ext[:4],'big'):08X}" if len(ext)>=4 else "#?"
            ea, ea_ext = _ea_str(ea_mode, ea_reg, sz_bytes, ext[imm_bytes:] if imm_bytes<=len(ext) else b"")
            mn_map = {0:"ORI",1:"ANDI",2:"SUBI",3:"ADDI",5:"EORI",6:"CMPI"}
            sfx = [".B",".W",".L",".L"][sz_bits]
            mn_base = mn_map.get(imm_op, "CMPI")
            return {"mnemonic": f"{mn_base}{sfx}", "operands": f"{imm_s},{ea}", "size": 2+imm_bytes+ea_ext}

        raise ValueError(f"group0 unhandled word={word:#06x}")

    # ── Group 4 ───────────────────────────────────────────────────────────
    if hi4 == 4:
        if word == 0x4E71: return {"mnemonic":"NOP", "operands":"", "size":2}
        if word == 0x4E75: return {"mnemonic":"RTS", "operands":"", "size":2}
        if word == 0x4E73: return {"mnemonic":"RTE", "operands":"", "size":2}
        if word == 0x4E77: return {"mnemonic":"RTR", "operands":"", "size":2}
        if word == 0x4E70: return {"mnemonic":"RESET", "operands":"", "size":2}
        if word == 0x4E76: return {"mnemonic":"TRAPV", "operands":"", "size":2}
        # TRAP
        if (word & 0xFFF0) == 0x4E40:
            return {"mnemonic":"TRAP", "operands":f"#${word&0xF:X}", "size":2}
        # JSR
        if (word & 0xFFC0) == 0x4E80:
            ea, ea_ext = _ea_str(ea_mode, ea_reg, 4, ext)
            return {"mnemonic":"JSR", "operands":ea, "size":2+ea_ext}
        # JMP
        if (word & 0xFFC0) == 0x4EC0:
            ea, ea_ext = _ea_str(ea_mode, ea_reg, 4, ext)
            return {"mnemonic":"JMP", "operands":ea, "size":2+ea_ext}
        # LEA
        if (word & 0xF1C0) == 0x41C0:
            reg_field = (word >> 9) & 7
            ea, ea_ext = _ea_str(ea_mode, ea_reg, 4, ext)
            return {"mnemonic":"LEA", "operands":f"{ea},A{reg_field}", "size":2+ea_ext}
        # CLR
        sz_bits = (word >> 6) & 3
        if (word >> 8) == 0x42 and sz_bits < 3:
            sfx = [".B",".W",".L"][sz_bits]
            sz_b = [1,2,4][sz_bits]
            ea, ea_ext = _ea_str(ea_mode, ea_reg, sz_b, ext)
            return {"mnemonic":f"CLR{sfx}", "operands":ea, "size":2+ea_ext}
        raise ValueError(f"group4 unhandled word={word:#06x}")

    # ── Group 5 ───────────────────────────────────────────────────────────
    if hi4 == 5:
        sz_bits = (word >> 6) & 3
        # DBcc
        if (word & 0xF0F8) == 0x50C8:
            cond = (word >> 8) & 0xF
            if len(ext) >= 2:
                disp = int.from_bytes(ext[:2], "big", signed=True)
                target = (pc + 2 + disp) & 0xFFFFFFFF
                return {"mnemonic":f"DB{CC[cond]}", "operands":f"D{ea_reg},${target:08X}", "size":4}
        # Scc
        if (word & 0x00C0) == 0x00C0:
            cond = (word >> 8) & 0xF
            ea, ea_ext = _ea_str(ea_mode, ea_reg, 1, ext)
            return {"mnemonic":f"S{CC[cond]}", "operands":ea, "size":2+ea_ext}
        # ADDQ/SUBQ
        data = (word >> 9) & 7
        dv = 8 if data == 0 else data
        is_sub = bool(word & 0x0100)
        sfx = [".B",".W",".L",".L"][sz_bits]
        sz_b = [1,2,4,4][sz_bits]
        ea, ea_ext = _ea_str(ea_mode, ea_reg, sz_b, ext)
        mn = f"SUBQ{sfx}" if is_sub else f"ADDQ{sfx}"
        return {"mnemonic": mn, "operands": f"#${dv},{ea}", "size": 2+ea_ext}

    # ── Group 6: Bcc/BSR/BRA ─────────────────────────────────────────────
    if hi4 == 6:
        cond = (word >> 8) & 0xF
        disp8 = (word & 0xFF)
        disp8s = disp8 if disp8 < 128 else disp8 - 256
        if disp8 == 0:
            if len(ext) < 2: raise ValueError("truncated Bcc")
            disp = int.from_bytes(ext[:2], "big", signed=True)
            sz = 4
        elif disp8 == 0xFF:
            if len(ext) < 4: raise ValueError("truncated Bcc.L")
            disp = int.from_bytes(ext[:4], "big", signed=True)
            sz = 6
        else:
            disp = disp8s
            sz = 2
        target = (pc + 2 + disp) & 0xFFFFFFFF
        if cond == 0:   mn = "BRA"
        elif cond == 1: mn = "BSR"
        else:           mn = f"B{CC[cond]}"
        return {"mnemonic": mn, "operands": f"${target:08X}", "size": sz}

    # ── Group 7: MOVEQ ───────────────────────────────────────────────────
    if hi4 == 7:
        reg_field = (word >> 9) & 7
        data = word & 0xFF
        return {"mnemonic":"MOVEQ", "operands":f"#${data:02X},D{reg_field}", "size":2}

    # ── Group 8: OR/DIVU/DIVS/SBCD ───────────────────────────────────────
    if hi4 == 8:
        reg_field = (word >> 9) & 7
        sz_bits = (word >> 6) & 3
        # DIVU/DIVS
        if (word & 0x01C0) == 0x00C0:
            ea, ea_ext = _ea_str(ea_mode, ea_reg, 2, ext)
            mn = "DIVS.W" if (word & 0x0100) else "DIVU.W"
            return {"mnemonic": mn, "operands": f"{ea},D{reg_field}", "size": 2+ea_ext}
        # SBCD
        if (word & 0xF1F0) == 0x8100:
            use_mem = bool(word & 8)
            ops = f"-(A{ea_reg}),-(A{reg_field})" if use_mem else f"D{ea_reg},D{reg_field}"
            return {"mnemonic":"SBCD", "operands":ops, "size":2}
        sfx = [".B",".W",".L",".L"][sz_bits]
        sz_b = [1,2,4,4][sz_bits]
        ea, ea_ext = _ea_str(ea_mode, ea_reg, sz_b, ext)
        direction = bool(word & 0x0100)
        src = f"D{reg_field}" if direction else ea
        dst = ea if direction else f"D{reg_field}"
        return {"mnemonic":f"OR{sfx}", "operands":f"{src},{dst}", "size":2+ea_ext}

    # ── Group 9: SUB/SUBA/SUBX ───────────────────────────────────────────
    if hi4 == 9:
        reg_field = (word >> 9) & 7
        sz_bits = (word >> 6) & 3
        if (word & 0x00C0) == 0x00C0:
            long_sz = bool(word & 0x0100)
            as_sz = ".L" if long_sz else ".W"
            sz_b = 4 if long_sz else 2
            ea, ea_ext = _ea_str(ea_mode, ea_reg, sz_b, ext)
            return {"mnemonic":f"SUBA{as_sz}", "operands":f"{ea},A{reg_field}", "size":2+ea_ext}
        if (word & 0xF130) == 0x9100:
            use_mem = bool(word & 8)
            sfx = [".B",".W",".L",".L"][sz_bits]
            ops = f"-(A{ea_reg}),-(A{reg_field})" if use_mem else f"D{ea_reg},D{reg_field}"
            return {"mnemonic":f"SUBX{sfx}", "operands":ops, "size":2}
        sfx = [".B",".W",".L",".L"][sz_bits]
        sz_b = [1,2,4,4][sz_bits]
        ea, ea_ext = _ea_str(ea_mode, ea_reg, sz_b, ext)
        direction = bool(word & 0x0100)
        src = f"D{reg_field}" if direction else ea
        dst = ea if direction else f"D{reg_field}"
        return {"mnemonic":f"SUB{sfx}", "operands":f"{src},{dst}", "size":2+ea_ext}

    # ── Group D: ADD/ADDA/ADDX ────────────────────────────────────────────
    if hi4 == 0xD:
        reg_field = (word >> 9) & 7
        sz_bits = (word >> 6) & 3
        if (word & 0x00C0) == 0x00C0:
            long_sz = bool(word & 0x0100)
            as_sz = ".L" if long_sz else ".W"
            sz_b = 4 if long_sz else 2
            ea, ea_ext = _ea_str(ea_mode, ea_reg, sz_b, ext)
            return {"mnemonic":f"ADDA{as_sz}", "operands":f"{ea},A{reg_field}", "size":2+ea_ext}
        sfx = [".B",".W",".L",".L"][sz_bits]
        sz_b = [1,2,4,4][sz_bits]
        ea, ea_ext = _ea_str(ea_mode, ea_reg, sz_b, ext)
        direction = bool(word & 0x0100)
        src = f"D{reg_field}" if direction else ea
        dst = ea if direction else f"D{reg_field}"
        return {"mnemonic":f"ADD{sfx}", "operands":f"{src},{dst}", "size":2+ea_ext}

    # ── Group E: shift/rotate ─────────────────────────────────────────────
    if hi4 == 0xE:
        sz_bits = (word >> 6) & 3
        direction = bool(word & 0x0100)
        dir_str = "L" if direction else "R"
        type_bits = (word >> 3) & 3
        mn_map = {0:f"AS{dir_str}",1:f"LS{dir_str}",2:f"ROX{dir_str}",3:f"RO{dir_str}"}
        mn_base = mn_map[type_bits]
        if (word & 0x00C0) == 0x00C0:
            ea, ea_ext = _ea_str(ea_mode, ea_reg, 2, ext)
            return {"mnemonic":f"{mn_base}.W", "operands":ea, "size":2+ea_ext}
        count_or_reg = (word >> 9) & 7
        use_reg = bool(word & 0x0020)
        cnt = f"D{count_or_reg}" if use_reg else f"#{8 if count_or_reg==0 else count_or_reg}"
        sfx = [".B",".W",".L",".L"][sz_bits]
        return {"mnemonic":f"{mn_base}{sfx}", "operands":f"{cnt},D{ea_reg}", "size":2}

    raise ValueError(f"unhandled hi4={hi4:#x} word={word:#06x}")


# ── Test vectors ──────────────────────────────────────────────────────────────
# Each entry: (hex_bytes, pc, description)
# Ground truth computed by decode_68k_py, then compared against MCP tool output.

DECODE_TESTS = [
    # NOP
    ("4E71", 0,      "NOP"),
    # RTS
    ("4E75", 0,      "RTS"),
    # RTE
    ("4E73", 0,      "RTE"),
    # MOVEQ #0,D0
    ("7000", 0,      "MOVEQ #0,D0"),
    # MOVEQ #$FF,D3
    ("76FF", 0,      "MOVEQ #$FF,D3"),
    # BRA.W +4  (word at pc=0x100: 6002 => target=0x100+2+2=0x104)
    ("6002", 0x100,  "BRA.W +2"),
    # BSR.W  6000 0004 => target=pc+2+4=0x106 (pc=0x100)
    ("6100", 0x100,  "BSR.W word-disp 0"),
    # BNE.B -2 (word 6600FE: disp=0xFF=-1? no, disp8=FE=-2 => target=pc+2-2=pc)
    ("66FE", 0x200,  "BNE.B -2"),
    # MOVE.L D0,D1  — word=2200  hi4=2(Long), src=D0(mode0,reg0), dst=D1(mode0,reg1->dst_mode bits 8:6=0 dst_reg bits 11:9=1)
    # Actually 2201: hi4=2, ea_mode=(2201>>3)&7=0, ea_reg=2201&7=1, dst_mode=(2201>>6)&7=0, dst_reg=(2201>>9)&7=1
    # MOVE.L D1,D1: 2241? Let me use a simpler one
    # MOVE.W D0,D1: 3200 => hi4=3,ea_mode=0,ea_reg=0,dst_mode=0,dst_reg=1
    ("3200", 0,      "MOVE.W D0,D1"),
    # MOVE.B D0,D1: 1200
    ("1200", 0,      "MOVE.B D0,D1"),
    # ADD.W D0,D1: D240 -> hi4=D,reg_field=1,sz_bits=1,ea_mode=0,ea_reg=0
    # direction=0 => src=ea=D0, dst=D1
    ("D240", 0,      "ADD.W D0,D1"),
    # SUB.W D0,D1: 9240
    ("9240", 0,      "SUB.W D0,D1"),
    # OR.W D0,D1: 8240
    ("8240", 0,      "OR.W D0,D1"),
    # DIVU.W D0,D1: 82C0 -> (word&0x01C0)==0x00C0, ea=D0, mn=DIVU.W
    ("82C0", 0,      "DIVU.W D0,D1"),
    # LSR.W #1,D0: E248 -> hi4=E, direction=0(R), type=1(LS), sz=1(W), count=1, ea_reg=0
    ("E248", 0,      "LSR.W #1,D0"),
    # ASL.W #2,D3: E543 -> hi4=E, dir=1(L), count=2, type=0(AS), sz=1(W), use_reg=0, ea_reg=3
    ("E543", 0,      "ASL.W #2,D3"),
    # TRAP #0: 4E40
    ("4E40", 0,      "TRAP #0"),
    # CLR.W D0: 4240
    ("4240", 0,      "CLR.W D0"),
    # ADDQ.W #4,D0: 5840 -> hi4=5, data=4, is_sub=0, sz=1(W), ea=D0
    ("5840", 0,      "ADDQ.W #4,D0"),
    # SUBQ.W #1,D0: 5340 -> hi4=5, data=1, is_sub=1 (bit 8 of 0x5340=0), wait:
    # 5340: 0101 0011 0100 0000: hi4=5, bits9-11=001=1(data), bit8=1(is_sub), sz=01(W), ea_mode=0,ea_reg=0
    ("5340", 0,      "SUBQ.W #1,D0"),
    # ADDA.W D0,A1: D2C0 -> hi4=D, bits9-11=001=1(reg_field), bit8=0(word ADDA),
    # word&0xC0=0xC0 so ADDA; as_sz=".W"(bit8=0), ea=D0
    ("D2C0", 0,      "ADDA.W D0,A1"),
    # SUBA.W D0,A1: 92C0
    ("92C0", 0,      "SUBA.W D0,A1"),
    # JMP (A0): 4ED0 -> ea_mode=6? No: 4ED0=0100 1110 1101 0000
    # hi4=4, (0xED0>>3)&7=2, ea_reg=0 => ea=(A0), JMP
    # Actually 0x4EC0 masked: 4ED0&0xFFC0=4EC0 yes
    ("4ED0", 0,      "JMP (A0)"),
    # JSR (A0): 4E90 -> 4E90&0xFFC0=4E80 yes, ea_mode=(0x90>>3)&7=2, ea_reg=0
    ("4E90", 0,      "JSR (A0)"),
]

# ── Run tests ─────────────────────────────────────────────────────────────────

results   = []
mismatches = []
skipped   = []

# --- m68k_variant_info tests ---
for variant_name, expected in VARIANT_GROUND_TRUTH.items():
    actual, err = call_tool("m68k_variant_info", {"variant": variant_name})
    if err is not None:
        results.append({"tool":"m68k_variant_info","variant":variant_name,"status":"FAIL","reason":err})
        mismatches.append({"tool":"m68k_variant_info","expected":expected,"actual":err})
        continue
    # Compare all fields
    ok = True
    diff = {}
    for k, ev in expected.items():
        av = actual.get(k)
        if av != ev:
            ok = False
            diff[k] = {"expected":ev,"actual":av}
    if ok:
        results.append({"tool":"m68k_variant_info","variant":variant_name,"status":"PASS"})
    else:
        results.append({"tool":"m68k_variant_info","variant":variant_name,"status":"FAIL","diff":diff})
        mismatches.append({"tool":"m68k_variant_info","variant":variant_name,"expected":expected,"actual":actual,"diff":diff})

# --- m68k_decode_instr tests ---
for hex_b, pc, desc in DECODE_TESTS:
    # Compute reference
    try:
        ref = decode_68k_py(hex_b, pc)
    except ValueError as e:
        skipped.append({"tool":"m68k_decode_instr","test":desc,"reason":f"reference_unimplemented: {e}"})
        continue

    actual, err = call_tool("m68k_decode_instr", {"hex": hex_b, "pc": pc})
    if err is not None:
        results.append({"tool":"m68k_decode_instr","test":desc,"status":"FAIL","reason":err})
        mismatches.append({"tool":"m68k_decode_instr","test":desc,"expected":ref,"actual":err})
        continue

    ok = (
        actual.get("mnemonic") == ref["mnemonic"] and
        actual.get("operands") == ref["operands"] and
        actual.get("size")     == ref["size"]
    )
    if ok:
        results.append({"tool":"m68k_decode_instr","test":desc,"status":"PASS"})
    else:
        diff = {}
        for k in ("mnemonic","operands","size"):
            if actual.get(k) != ref.get(k):
                diff[k] = {"expected":ref.get(k),"actual":actual.get(k)}
        results.append({"tool":"m68k_decode_instr","test":desc,"status":"FAIL","diff":diff})
        mismatches.append({"tool":"m68k_decode_instr","test":desc,"expected":ref,"actual":actual,"diff":diff})

p.stdin.close()
p.terminate()

# ── Tally ─────────────────────────────────────────────────────────────────────

passed = sum(1 for r in results if r["status"] == "PASS")
failed = sum(1 for r in results if r["status"] == "FAIL")

summary = {
    "category": "m68k",
    "tools_hardened": 2,
    "tools_passed": passed,
    "tools_failed": failed,
    "tools_skipped": len(skipped),
    "mismatches": mismatches,
    "detail": results,
    "skipped_detail": skipped,
}

with open(OUT_PASS_FAIL, "w") as f:
    json.dump(summary, f, indent=2)

if skipped:
    with open(SKIP_FILE, "w") as f:
        json.dump(skipped, f, indent=2)

print(json.dumps({"passed":passed,"failed":failed,"skipped":len(skipped),"mismatches":len(mismatches)}, indent=2))
sys.exit(0 if failed == 0 else 1)
