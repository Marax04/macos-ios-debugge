#!/usr/bin/env python3
"""Independent Python validator for the rustre-arch-bpf crate.

Reimplements eBPF/cBPF decoding logic using only the Python standard library
so its outputs can be diffed against the Rust crate's behaviour.

Reference: Linux kernel uapi include/uapi/linux/bpf.h and bpf_common.h.
"""

import json
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Opcode encoding constants (Linux bpf_common.h)
# ---------------------------------------------------------------------------

# BPF instruction classes (lower 3 bits of opcode)
BPF_LD    = 0x00
BPF_LDX   = 0x01
BPF_ST    = 0x02
BPF_STX   = 0x03
BPF_ALU   = 0x04
BPF_JMP   = 0x05
BPF_JMP32 = 0x06
BPF_ALU64 = 0x07

CLASS_NAMES = {
    BPF_LD: "LD", BPF_LDX: "LDX", BPF_ST: "ST", BPF_STX: "STX",
    BPF_ALU: "ALU", BPF_JMP: "JMP", BPF_JMP32: "JMP32", BPF_ALU64: "ALU64",
}

# Size field (bits 3-4)
BPF_W  = 0x00  # 32-bit
BPF_H  = 0x08  # 16-bit
BPF_B  = 0x10  #  8-bit
BPF_DW = 0x18  # 64-bit (eBPF only)

SIZE_NAMES = {BPF_W: "W", BPF_H: "H", BPF_B: "B", BPF_DW: "DW"}
SIZE_BYTES = {BPF_W: 4, BPF_H: 2, BPF_B: 1, BPF_DW: 8}

# Mode field (bits 5-7) for LD/LDX/ST/STX
BPF_IMM  = 0x00
BPF_ABS  = 0x20
BPF_IND  = 0x40
BPF_MEM  = 0x60
BPF_ATOMIC = 0xC0  # eBPF
BPF_XADD = 0xC0    # legacy alias

MODE_NAMES = {
    BPF_IMM: "IMM", BPF_ABS: "ABS", BPF_IND: "IND",
    BPF_MEM: "MEM", BPF_ATOMIC: "ATOMIC",
}

# Source field (bit 3) for ALU/JMP
BPF_K = 0x00  # immediate
BPF_X = 0x08  # register

# ALU operations (upper 4 bits of opcode for ALU/ALU64)
BPF_ADD  = 0x00
BPF_SUB  = 0x10
BPF_MUL  = 0x20
BPF_DIV  = 0x30
BPF_OR   = 0x40
BPF_AND  = 0x50
BPF_LSH  = 0x60
BPF_RSH  = 0x70
BPF_NEG  = 0x80
BPF_MOD  = 0x90
BPF_XOR  = 0xA0
BPF_MOV  = 0xB0  # eBPF
BPF_ARSH = 0xC0  # eBPF
BPF_END  = 0xD0  # eBPF byte-swap

ALU_OP_NAMES = {
    BPF_ADD: "add", BPF_SUB: "sub", BPF_MUL: "mul", BPF_DIV: "div",
    BPF_OR: "or", BPF_AND: "and", BPF_LSH: "lsh", BPF_RSH: "rsh",
    BPF_NEG: "neg", BPF_MOD: "mod", BPF_XOR: "xor",
    BPF_MOV: "mov", BPF_ARSH: "arsh", BPF_END: "end",
}

# JMP operations (upper 4 bits)
BPF_JA   = 0x00
BPF_JEQ  = 0x10
BPF_JGT  = 0x20
BPF_JGE  = 0x30
BPF_JSET = 0x40
BPF_JNE  = 0x50  # eBPF
BPF_JSGT = 0x60  # eBPF signed
BPF_JSGE = 0x70  # eBPF signed
BPF_CALL = 0x80  # eBPF
BPF_EXIT = 0x90  # eBPF
BPF_JLT  = 0xA0  # eBPF
BPF_JLE  = 0xB0  # eBPF
BPF_JSLT = 0xC0  # eBPF signed
BPF_JSLE = 0xD0  # eBPF signed

JMP_OP_NAMES = {
    BPF_JA: "ja", BPF_JEQ: "jeq", BPF_JGT: "jgt", BPF_JGE: "jge",
    BPF_JSET: "jset", BPF_JNE: "jne", BPF_JSGT: "jsgt", BPF_JSGE: "jsge",
    BPF_CALL: "call", BPF_EXIT: "exit",
    BPF_JLT: "jlt", BPF_JLE: "jle", BPF_JSLT: "jslt", BPF_JSLE: "jsle",
}

# Register count
NUM_REGS = 11  # r0..r10

# ---------------------------------------------------------------------------
# Map types (subset of enum bpf_map_type)
# ---------------------------------------------------------------------------

MAP_TYPES = {
    0: "UNSPEC", 1: "HASH", 2: "ARRAY", 3: "PROG_ARRAY",
    4: "PERF_EVENT_ARRAY", 5: "PERCPU_HASH", 6: "PERCPU_ARRAY",
    7: "STACK_TRACE", 8: "CGROUP_ARRAY", 9: "LRU_HASH",
    10: "LRU_PERCPU_HASH", 11: "LPM_TRIE", 12: "ARRAY_OF_MAPS",
    13: "HASH_OF_MAPS", 14: "DEVMAP", 15: "SOCKMAP",
    16: "CPUMAP", 17: "XSKMAP", 18: "SOCKHASH",
    23: "QUEUE", 24: "STACK", 27: "RINGBUF",
}

# ---------------------------------------------------------------------------
# Helper IDs (subset of enum bpf_func_id, just enough for cross-checks)
# ---------------------------------------------------------------------------

KNOWN_HELPERS = {
    1: "map_lookup_elem",
    2: "map_update_elem",
    3: "map_delete_elem",
    4: "probe_read",
    5: "ktime_get_ns",
    6: "trace_printk",
    7: "get_prandom_u32",
    8: "get_smp_processor_id",
    9: "skb_store_bytes",
    10: "l3_csum_replace",
    11: "l4_csum_replace",
    12: "tail_call",
    13: "clone_redirect",
    14: "get_current_pid_tgid",
    15: "get_current_uid_gid",
    16: "get_current_comm",
    17: "get_cgroup_classid",
    18: "skb_vlan_push",
    19: "skb_vlan_pop",
    20: "skb_get_tunnel_key",
    21: "skb_set_tunnel_key",
    25: "perf_event_output",
    44: "perf_event_read_value",
    45: "perf_prog_read_value",
    112: "ringbuf_output",
    113: "ringbuf_reserve",
    114: "ringbuf_submit",
    115: "ringbuf_discard",
    116: "ringbuf_query",
}

# ---------------------------------------------------------------------------
# eBPF instruction decode (8-byte / 16-byte for LD_IMM_DW)
# ---------------------------------------------------------------------------
#
# struct bpf_insn {
#     __u8 code;       /* opcode */
#     __u8 dst_reg:4;
#     __u8 src_reg:4;
#     __s16 off;
#     __s32 imm;
# };

def validator_decode_insn(data: bytes) -> Dict[str, Any]:
    if len(data) < 8:
        return {"ok": False, "error": "too_short"}
    code = data[0]
    regs = data[1]
    dst = regs & 0x0F
    src = (regs >> 4) & 0x0F
    off = struct.unpack("<h", data[2:4])[0]
    imm = struct.unpack("<i", data[4:8])[0]
    cls = code & 0x07
    out: Dict[str, Any] = {
        "ok": True,
        "code": code,
        "class": cls,
        "class_name": CLASS_NAMES.get(cls, "?"),
        "dst_reg": dst,
        "src_reg": src,
        "off": off,
        "imm": imm,
        "size": 8,
    }
    # 64-bit immediate load: LD | IMM | DW spans two 8-byte slots
    if code == (BPF_LD | BPF_IMM | BPF_DW):
        if len(data) < 16:
            return {"ok": False, "error": "ld_imm_dw_truncated"}
        imm_hi = struct.unpack("<i", data[12:16])[0]
        full = (imm & 0xFFFFFFFF) | ((imm_hi & 0xFFFFFFFF) << 32)
        out["imm64"] = full
        out["size"] = 16
        out["mnemonic"] = "lddw"
    elif cls in (BPF_ALU, BPF_ALU64):
        op = code & 0xF0
        src_mode = code & 0x08
        op_name = ALU_OP_NAMES.get(op, "?")
        suffix = "32" if cls == BPF_ALU else ""
        src_kind = "x" if src_mode == BPF_X else "k"
        out["mnemonic"] = f"{op_name}{suffix}_{src_kind}"
        out["alu_op"] = op
        out["alu_op_name"] = op_name
        out["src_kind"] = src_kind
    elif cls in (BPF_JMP, BPF_JMP32):
        op = code & 0xF0
        src_mode = code & 0x08
        op_name = JMP_OP_NAMES.get(op, "?")
        if op == BPF_CALL:
            out["mnemonic"] = "call"
        elif op == BPF_EXIT:
            out["mnemonic"] = "exit"
        elif op == BPF_JA:
            out["mnemonic"] = "ja"
        else:
            suffix = "32" if cls == BPF_JMP32 else ""
            src_kind = "x" if src_mode == BPF_X else "k"
            out["mnemonic"] = f"{op_name}{suffix}_{src_kind}"
            out["src_kind"] = src_kind
        out["jmp_op"] = op
        out["jmp_op_name"] = op_name
    elif cls in (BPF_LDX, BPF_STX, BPF_ST, BPF_LD):
        sz = code & 0x18
        mode = code & 0xE0
        out["mem_size"] = SIZE_NAMES.get(sz, "?")
        out["mem_size_bytes"] = SIZE_BYTES.get(sz, 0)
        out["mem_mode"] = MODE_NAMES.get(mode, "?")
        verb = {BPF_LDX: "ldx", BPF_STX: "stx", BPF_ST: "st", BPF_LD: "ld"}[cls]
        out["mnemonic"] = f"{verb}{out['mem_size'].lower()}"
    return out

def validator_disassemble(data: bytes) -> Dict[str, Any]:
    insns = []
    off = 0
    while off < len(data):
        insn = validator_decode_insn(data[off:])
        if not insn.get("ok"):
            insn["offset"] = off
            insns.append(insn)
            break
        insn["offset"] = off
        insns.append(insn)
        off += insn["size"]
    return {"ok": True, "count": len(insns), "insns": insns, "consumed": off}

# ---------------------------------------------------------------------------
# Helpers / map types lookups
# ---------------------------------------------------------------------------

def validator_helper_name(hid: int) -> Dict[str, Any]:
    if hid in KNOWN_HELPERS:
        return {"ok": True, "id": hid, "name": KNOWN_HELPERS[hid]}
    return {"ok": False, "id": hid}

def validator_map_type_name(t: int) -> Dict[str, Any]:
    if t in MAP_TYPES:
        return {"ok": True, "type": t, "name": MAP_TYPES[t]}
    return {"ok": False, "type": t}

# ---------------------------------------------------------------------------
# Tiny CFG: count exits (BPF_EXIT) and direct branches
# ---------------------------------------------------------------------------

def validator_cfg_summary(data: bytes) -> Dict[str, Any]:
    d = validator_disassemble(data)
    exits = 0
    branches = 0
    calls = 0
    for ins in d["insns"]:
        if not ins.get("ok"):
            continue
        if ins.get("code") == (BPF_JMP | BPF_EXIT):
            exits += 1
        elif ins.get("code") == (BPF_JMP | BPF_CALL):
            calls += 1
        elif ins.get("class") in (BPF_JMP, BPF_JMP32):
            jop = ins.get("jmp_op")
            if jop is not None and jop not in (BPF_CALL, BPF_EXIT):
                branches += 1
    return {
        "ok": True,
        "insn_count": d["count"],
        "exits": exits,
        "branches": branches,
        "calls": calls,
    }

# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

DISPATCH = {
    "decode_insn":       lambda i: validator_decode_insn(bytes(i["bytes"])),
    "disassemble":       lambda i: validator_disassemble(bytes(i["bytes"])),
    "helper_name":       lambda i: validator_helper_name(i["id"]),
    "map_type_name":     lambda i: validator_map_type_name(i["type"]),
    "cfg_summary":       lambda i: validator_cfg_summary(bytes(i["bytes"])),
}

def main() -> None:
    raw = sys.stdin.read().strip()
    if raw:
        req = json.loads(raw)
        fn = req["function"]
        out = DISPATCH[fn](req.get("input", {}))
        print(json.dumps({"function": fn, "output": out}, default=list))
        return
    # Fixed self-tests
    # exit: code=0x95 (JMP|EXIT)
    exit_insn = [0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    # mov64 r0, 0  -> ALU64|MOV|K = 0xB7, dst=0, imm=0
    mov_r0_0 = [0xB7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    # add64 r1, r2 -> ALU64|ADD|X = 0x0F, dst=1, src=2
    add_r1_r2 = [0x0F, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    # call helper #1 (map_lookup_elem): JMP|CALL = 0x85, imm=1
    call_1 = [0x85, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]
    # lddw r1, 0x1122334455667788: LD|IMM|DW = 0x18, dst=1, imm_lo=0x55667788, imm_hi=0x11223344
    lddw = [0x18, 0x01, 0x00, 0x00, 0x88, 0x77, 0x66, 0x55,
            0x00, 0x00, 0x00, 0x00, 0x44, 0x33, 0x22, 0x11]
    # ldxw r0, [r1+4]: LDX|MEM|W = 0x61, dst=0, src=1, off=4
    ldxw = [0x61, 0x10, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]

    program = (
        mov_r0_0 + add_r1_r2 + call_1 + lddw + ldxw + exit_insn
    )

    tests = [
        ("decode_insn",   {"bytes": exit_insn}),
        ("decode_insn",   {"bytes": mov_r0_0}),
        ("decode_insn",   {"bytes": add_r1_r2}),
        ("decode_insn",   {"bytes": call_1}),
        ("decode_insn",   {"bytes": lddw}),
        ("decode_insn",   {"bytes": ldxw}),
        ("disassemble",   {"bytes": program}),
        ("helper_name",   {"id": 1}),
        ("helper_name",   {"id": 6}),
        ("helper_name",   {"id": 9999}),
        ("map_type_name", {"type": 1}),
        ("map_type_name", {"type": 27}),
        ("cfg_summary",   {"bytes": program}),
    ]
    results = []
    for fn, inp in tests:
        try:
            out = DISPATCH[fn](inp)
        except Exception as e:  # pragma: no cover - defensive
            out = {"error": str(e)}
        results.append({"function": fn, "input": inp, "output": out})
    print(json.dumps(results, indent=2, default=list))

if __name__ == "__main__":
    main()
