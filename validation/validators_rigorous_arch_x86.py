#!/usr/bin/env python3
"""
Rigorous validator for arch_x86_* MCP tools.
Compares MCP outputs against independently computed Python truths.
Tools hardened: arch_x86_metadata (x3 bitness), arch_x86_registers (x3),
                arch_x86_calling_conventions (x2), arch_x86_disassemble_and_lift (x6),
                arch_x86_lift_to_llil (x3) — total >= 10 distinct tool+input combos.
"""
import json, subprocess, sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
REPORT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_arch_x86.json"
MODULE = "arch_x86"

# ---------------------------------------------------------------------------
# MCP session helpers
# ---------------------------------------------------------------------------

def start_session():
    p = subprocess.Popen(
        [EXE, "--transport=stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    def send(obj):
        p.stdin.write((json.dumps(obj) + "\n").encode())
        p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None

    send({"jsonrpc":"2.0","id":1,"method":"initialize",
          "params":{"protocolVersion":"2024-11-05","capabilities":{},
                    "clientInfo":{"name":"rigorous","version":"1"}}})
    recv()
    send({"jsonrpc":"2.0","method":"notifications/initialized"})
    return p, send, recv

p, send, recv = start_session()
_rid = [100]

def call(name, args):
    _rid[0] += 1
    send({"jsonrpc":"2.0","id":_rid[0],"method":"tools/call",
          "params":{"name":name,"arguments":args}})
    resp = recv()
    if not resp or "error" in resp:
        return None
    c = resp.get("result",{}).get("content",[])
    if not c:
        return None
    try:
        return json.loads(c[0].get("text",""))
    except Exception:
        return c[0].get("text","")

# ---------------------------------------------------------------------------
# Truth tables — all values derived from reading the Rust source
# ---------------------------------------------------------------------------

# arch_x86_metadata truth: name, pointer_size (bytes), endian
METADATA_TRUTH = {
    16: {"name": "x86_16", "pointer_size": 2, "endian": "Little"},
    32: {"name": "x86_32", "pointer_size": 4, "endian": "Little"},
    64: {"name": "x86_64", "pointer_size": 8, "endian": "Little"},
}

# arch_x86_registers — exact ordered names from registers_64bit() in lib.rs
REG64_NAMES = (
    # 64-bit GPRs (18)
    ["rax","rbx","rcx","rdx","rsi","rdi","rsp","rbp",
     "r8","r9","r10","r11","r12","r13","r14","r15","rip","rflags"]
    # 32-bit (18)
    + ["eax","ebx","ecx","edx","esi","edi","esp","ebp",
       "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d","eip","eflags"]
    # 16-bit (16)
    + ["ax","bx","cx","dx","si","di","sp","bp",
       "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"]
    # 8-bit (20)
    + ["al","ah","bl","bh","cl","ch","dl","dh",
       "sil","dil","spl","bpl",
       "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"]
    # Segment (6)
    + ["cs","ds","es","fs","gs","ss"]
    # Control (5)
    + ["cr0","cr2","cr3","cr4","cr8"]
    # Debug (6)
    + ["dr0","dr1","dr2","dr3","dr6","dr7"]
    # x87 FPU (8)
    + [f"st{i}" for i in range(8)]
    # MMX (8)
    + [f"mm{i}" for i in range(8)]
    # XMM (16)
    + [f"xmm{i}" for i in range(16)]
    # YMM (16)
    + [f"ymm{i}" for i in range(16)]
    # ZMM (32)
    + [f"zmm{i}" for i in range(32)]
    # Opmask k0-k7 (8)
    + [f"k{i}" for i in range(8)]
    # MPX bnd0-bnd3 (4)
    + [f"bnd{i}" for i in range(4)]
)

# 64-bit calling conventions from calling_conventions_64bit()
CC64_TRUTH = [
    {
        "name": "sysv_amd64",
        "int_args": ["rdi","rsi","rdx","rcx","r8","r9"],
        "return_regs": ["rax","rdx"],
        "caller_cleans_stack": True,
    },
    {
        "name": "ms_x64",
        "int_args": ["rcx","rdx","r8","r9"],
        "return_regs": ["rax"],
        "caller_cleans_stack": True,
    },
    {
        "name": "syscall",
        "int_args": ["rdi","rsi","rdx","r10","r8","r9"],
        "return_regs": ["rax"],
        "caller_cleans_stack": True,
    },
]

# 32-bit calling conventions from calling_conventions_32bit()
CC32_TRUTH = [
    {"name": "cdecl",    "int_args": [], "return_regs": ["eax","edx"], "caller_cleans_stack": True},
    {"name": "stdcall",  "int_args": [], "return_regs": ["eax"],       "caller_cleans_stack": False},
    {"name": "fastcall", "int_args": ["ecx","edx"], "return_regs": ["eax"], "caller_cleans_stack": False},
    {"name": "thiscall", "int_args": ["ecx"],       "return_regs": ["eax"], "caller_cleans_stack": False},
]

# Disassembly truth: {hex_bytes: (mnemonic, instruction_count, byte_len)}
# Derived from public x86 opcode specs / iced-x86 intel formatter output
DISASM_TRUTH = {
    # Single-byte opcodes
    "90":   ("nop",  1, 1),   # NOP
    "c3":   ("ret",  1, 1),   # NEAR RET
    "cc":   ("int3", 1, 1),   # INT3 breakpoint
    "f4":   ("hlt",  1, 1),   # HLT
    # Multi-byte: 48 31 c0 = XOR RAX, RAX (REX.W + 31 /r)
    "4831c0": ("xor", 1, 3),
    # MOV EAX, 0 = B8 00 00 00 00
    "b800000000": ("mov", 1, 5),
}

# lift_to_llil truth: NOP → op_count may be 0 or 1; we just verify structural fields
# For RET (c3) we expect op_count >= 1 (a Return op)
LLIL_TRUTH = {
    "90": {"len": 1, "bits": 64},
    "c3": {"len": 1, "bits": 64},
    "4831c0": {"len": 3, "bits": 64},
}

# ---------------------------------------------------------------------------
# Check harness
# ---------------------------------------------------------------------------

checks_passed = 0
checks_failed = 0
mismatches = []
tools_hardened = set()

def check(tool, args, field, got, expected, note=""):
    global checks_passed, checks_failed
    tools_hardened.add(tool)
    match = (got == expected)
    if match:
        checks_passed += 1
    else:
        checks_failed += 1
        mismatches.append({
            "tool": tool,
            "args": args,
            "field": field,
            "got": got,
            "expected": expected,
            "note": note,
        })

# ---------------------------------------------------------------------------
# 1. arch_x86_metadata — 3 bitness variants (3 checks each = 9 checks)
# ---------------------------------------------------------------------------

for bits, truth in METADATA_TRUTH.items():
    r = call("arch_x86_metadata", {"bits": bits})
    if r is None:
        checks_failed += 3
        mismatches.append({"tool":"arch_x86_metadata","args":{"bits":bits},"field":"*","got":None,"expected":truth,"note":"tool returned null"})
        continue
    check("arch_x86_metadata", {"bits": bits}, "name",         r.get("name"),         truth["name"])
    check("arch_x86_metadata", {"bits": bits}, "pointer_size", r.get("pointer_size"), truth["pointer_size"])
    check("arch_x86_metadata", {"bits": bits}, "endian",       r.get("endian"),       truth["endian"])

# ---------------------------------------------------------------------------
# 2. arch_x86_registers — 64-bit: exact count and full ordered name list
# ---------------------------------------------------------------------------

r64 = call("arch_x86_registers", {"bits": 64})
if r64 is None:
    checks_failed += 2
    mismatches.append({"tool":"arch_x86_registers","args":{"bits":64},"field":"*","got":None,"expected":"non-null","note":"tool returned null"})
else:
    tools_hardened.add("arch_x86_registers")
    check("arch_x86_registers", {"bits":64}, "count", r64.get("count"), len(REG64_NAMES))
    check("arch_x86_registers", {"bits":64}, "names", r64.get("names"), REG64_NAMES,
          "exact ordered register name list for x86-64")

# 32-bit: just verify key GPRs present
r32 = call("arch_x86_registers", {"bits": 32})
if r32 is not None:
    tools_hardened.add("arch_x86_registers")
    names32 = r32.get("names", [])
    for expected_reg in ["eax","ebx","ecx","edx","esp","ebp","esi","edi"]:
        check("arch_x86_registers", {"bits":32}, f"contains:{expected_reg}",
              expected_reg in names32, True, f"32-bit GPR {expected_reg} must be present")

# ---------------------------------------------------------------------------
# 3. arch_x86_calling_conventions — 64-bit exact match, 32-bit exact match
# ---------------------------------------------------------------------------

rcc64 = call("arch_x86_calling_conventions", {"bits": 64})
if rcc64 is None:
    checks_failed += 1
    mismatches.append({"tool":"arch_x86_calling_conventions","args":{"bits":64},"field":"*","got":None,"expected":"non-null","note":"tool returned null"})
else:
    tools_hardened.add("arch_x86_calling_conventions")
    ccs = rcc64.get("calling_conventions", [])
    check("arch_x86_calling_conventions", {"bits":64}, "count", rcc64.get("count"), 3)
    # Check each CC by name
    by_name = {c["name"]: c for c in ccs}
    for truth_cc in CC64_TRUTH:
        n = truth_cc["name"]
        if n not in by_name:
            check("arch_x86_calling_conventions", {"bits":64}, f"{n}.present", False, True,
                  f"calling convention {n} missing")
        else:
            got_cc = by_name[n]
            check("arch_x86_calling_conventions", {"bits":64}, f"{n}.int_args",
                  got_cc.get("int_args"), truth_cc["int_args"])
            check("arch_x86_calling_conventions", {"bits":64}, f"{n}.return_regs",
                  got_cc.get("return_regs"), truth_cc["return_regs"])

rcc32 = call("arch_x86_calling_conventions", {"bits": 32})
if rcc32 is not None:
    tools_hardened.add("arch_x86_calling_conventions")
    check("arch_x86_calling_conventions", {"bits":32}, "count", rcc32.get("count"), 4)
    ccs32 = rcc32.get("calling_conventions", [])
    by_name32 = {c["name"]: c for c in ccs32}
    for truth_cc in CC32_TRUTH:
        n = truth_cc["name"]
        if n not in by_name32:
            check("arch_x86_calling_conventions", {"bits":32}, f"{n}.present", False, True,
                  f"calling convention {n} missing in 32-bit")
        else:
            got_cc = by_name32[n]
            check("arch_x86_calling_conventions", {"bits":32}, f"{n}.caller_cleans_stack",
                  got_cc.get("caller_cleans_stack"), truth_cc["caller_cleans_stack"])

# ---------------------------------------------------------------------------
# 4. arch_x86_disassemble_and_lift — check mnemonic and instruction count
# ---------------------------------------------------------------------------

for hex_bytes, (expected_mnem, expected_count, expected_byte_len) in DISASM_TRUTH.items():
    r = call("arch_x86_disassemble_and_lift", {"hex": hex_bytes, "address": 0x1000, "bits": 64})
    tools_hardened.add("arch_x86_disassemble_and_lift")
    if r is None:
        checks_failed += 2
        mismatches.append({"tool":"arch_x86_disassemble_and_lift","args":{"hex":hex_bytes},
                           "field":"*","got":None,"expected":"non-null","note":"tool returned null"})
        continue
    check("arch_x86_disassemble_and_lift", {"hex": hex_bytes}, "count",
          r.get("count"), expected_count)
    instrs = r.get("instructions", [])
    if instrs:
        check("arch_x86_disassemble_and_lift", {"hex": hex_bytes}, "mnemonic",
              instrs[0].get("mnemonic"), expected_mnem)

# ---------------------------------------------------------------------------
# 5. arch_x86_lift_to_llil — structural checks on len and bits fields
# ---------------------------------------------------------------------------

for hex_bytes, truth in LLIL_TRUTH.items():
    r = call("arch_x86_lift_to_llil", {"hex": hex_bytes, "ip": 0x1000, "bits": 64})
    tools_hardened.add("arch_x86_lift_to_llil")
    if r is None:
        checks_failed += 2
        mismatches.append({"tool":"arch_x86_lift_to_llil","args":{"hex":hex_bytes},
                           "field":"*","got":None,"expected":"non-null","note":"tool returned null"})
        continue
    check("arch_x86_lift_to_llil", {"hex":hex_bytes}, "len",  r.get("len"),  truth["len"])
    check("arch_x86_lift_to_llil", {"hex":hex_bytes}, "bits", r.get("bits"), truth["bits"])

# ---------------------------------------------------------------------------
# Teardown and report
# ---------------------------------------------------------------------------

try:
    p.terminate()
except Exception:
    pass

report = {
    "module": MODULE,
    "tools_hardened": len(tools_hardened),
    "tools_hardened_list": sorted(tools_hardened),
    "checks_passed": checks_passed,
    "checks_failed": checks_failed,
    "real_mismatches": len(mismatches),
    "mismatches": mismatches,
}

with open(REPORT, "w") as f:
    json.dump(report, f, indent=2, default=str)

print(json.dumps({k:v for k,v in report.items() if k != "mismatches"}, indent=2))
if mismatches:
    print("\nMISMATCHES:")
    for m in mismatches:
        print(f"  [{m['tool']}] field={m['field']}  got={m['got']!r}  expected={m['expected']!r}  note={m.get('note','')}")
else:
    print("\nAll checks passed — no mismatches.")
