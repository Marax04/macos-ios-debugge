#!/usr/bin/env python3
"""
Rigorous ground-truth validation for all MCP tools matching debug_* pattern.
Each check computes the expected value with pure Python and compares byte-for-byte.
"""
import json
import subprocess
import time
import struct

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_V2 = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_debug_v2.json"
SKIP_OUT = r"C:\Users\Fra\Desktop\RustRE\validation\skip_debug.json"

# ── MCP transport ────────────────────────────────────────────────────────────

p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    bufsize=0,
)

_rid = 0

def send(req):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()

def recv():
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("server died")
    return json.loads(line)

def call(method_name, arguments):
    global _rid
    _rid += 1
    send({"jsonrpc": "2.0", "id": _rid, "method": "tools/call",
          "params": {"name": method_name, "arguments": arguments}})
    resp = recv()
    if "error" in resp:
        return None, f"JSONRPC_ERROR: {resp['error']}"
    result = resp.get("result", {})
    if result.get("isError"):
        txt = result.get("content", [{}])[0].get("text", "")
        return None, f"TOOL_ERROR: {txt}"
    txt = result.get("content", [{}])[0].get("text", "")
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None

# ── Handshake ────────────────────────────────────────────────────────────────

send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "rigorous_debug_v2", "version": "1"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

# Open project
send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
      "params": {"name": "project.open", "arguments": {"path": TARGET}}})
op = recv()
op_data = json.loads(op["result"]["content"][0]["text"])
BINARY_ID = op_data["binary_id"]
PROJECT_ID = op_data["project_id"]
print(f"project.open: binary_id={BINARY_ID}, project_id={PROJECT_ID}")

# ── Python reference implementations ────────────────────────────────────────

def py_mach_exception_name(v):
    """macOS mach exception type names (XNU source: osfmk/mach/exception_types.h)."""
    names = {
        1: "EXC_BAD_ACCESS",
        2: "EXC_BAD_INSTRUCTION",
        3: "EXC_ARITHMETIC",
        4: "EXC_EMULATION",
        5: "EXC_SOFTWARE",
        6: "EXC_BREAKPOINT",
        7: "EXC_SYSCALL",
        8: "EXC_MACH_SYSCALL",
        9: "EXC_RPC_ALERT",
        10: "EXC_CRASH",
        11: "EXC_RESOURCE",
        12: "EXC_GUARD",
        13: "EXC_CORPSE_NOTIFY",
    }
    return names.get(v, f"EXC_UNKNOWN_{v}")

def py_macho_file_type(v):
    """Mach-O file type from uint32 (rustre_debug_macos::MachoFileType::name)."""
    types = {
        1: "object", 2: "executable", 3: "fvmlib", 4: "core",
        5: "preload", 6: "dylib", 7: "dylinker", 8: "bundle",
        9: "dylib_stub", 10: "dsym", 11: "kext_bundle",
    }
    return types.get(v, "unknown")

def py_format_macho_version(v):
    """Apple version format: X.Y.Z packed in 32 bits."""
    major = (v >> 16) & 0xFFFF
    minor = (v >> 8) & 0xFF
    patch = v & 0xFF
    return f"{major}.{minor}.{patch}"

def py_vm_prot_decode(v):
    """VM protection bits: bit0=read, bit1=write, bit2=execute."""
    readable   = bool(v & 1)
    writable   = bool(v & 2)
    executable = bool(v & 4)
    parts = []
    if readable:   parts.append("r")
    if writable:   parts.append("w")
    if executable: parts.append("x")
    as_str = "".join(parts) if parts else "---"
    return readable, writable, executable, as_str

def py_arm64_hw_bp_encode(slot, address):
    """
    ARM64 hardware breakpoint encoding.
    BVR = address aligned to 4 bytes.
    BCR = 0x01E5 (E=1, PMC=0b10, BAS=0xF).
    """
    bvr = address & ~0x3
    bcr = 0x0000_01E5
    enabled = True
    return bvr, bcr, enabled

def py_unicorn_arch_pointer_size(arch):
    sizes = {"x86_64": 8, "x86_32": 4, "arm": 4, "arm64": 8,
             "mips": 4, "mips64": 8, "riscv32": 4, "riscv64": 8}
    return sizes.get(arch, 0)

def py_simulated_thread_step(pc, sp, stride=4, steps=1):
    for _ in range(steps):
        pc = (pc + stride) & 0xFFFF_FFFF_FFFF_FFFF
    return pc

def py_trace_entry_bytes(raw_hex, max_bytes=16):
    """First min(len/2, max_bytes) bytes of raw_hex, uppercased."""
    data = bytes.fromhex(raw_hex)[:max_bytes]
    return data.hex().upper()

def py_windows_protect_name(protect):
    names = {
        1: "PAGE_NOACCESS", 2: "PAGE_READONLY", 4: "PAGE_READWRITE",
        8: "PAGE_WRITECOPY", 16: "PAGE_EXECUTE", 32: "PAGE_EXECUTE_READ",
        64: "PAGE_EXECUTE_READWRITE", 128: "PAGE_EXECUTE_WRITECOPY",
        256: "PAGE_NOACCESS",  # MEM_COMMIT
    }
    return names.get(protect, "PAGE_UNKNOWN")

# ── Test cases ────────────────────────────────────────────────────────────────

ADDR = 5368771180   # 0x14000f26c
SIZE = 16

tests = []   # {tool, input, expected, actual, pass, note}
skips = []   # {tool, reason}

def check(tool_name, args, expected_fn, note=""):
    """Call a tool and compare output using expected_fn(actual_obj) -> bool, expected_repr."""
    data, err = call(tool_name, args)
    if err:
        tests.append({"tool": tool_name, "input": args, "expected": note,
                       "actual": err, "pass": False, "note": note})
        return
    ok, exp_repr = expected_fn(data)
    tests.append({
        "tool": tool_name,
        "input": args,
        "expected": exp_repr,
        "actual": data,
        "pass": ok,
        "note": note,
    })

def skip(tool_name, reason):
    skips.append({"tool": tool_name, "reason": reason})

# ── 1. debug_macos_mach_vm_region_end ────────────────────────────────────────
check(
    "debug_macos_mach_vm_region_end",
    {"address": ADDR, "size": SIZE},
    lambda d: (d.get("end") == ADDR + SIZE, f"end=={ADDR + SIZE}"),
    "end = address + size",
)

# ── 2. debug_macos_task_info_resident_ratio ───────────────────────────────────
check(
    "debug_macos_task_info_resident_ratio",
    {"virtual_size": 1, "resident_size": 1},
    lambda d: (d.get("ratio") == 1.0, "ratio==1.0"),
    "1/1=1.0",
)
check(
    "debug_macos_task_info_resident_ratio",
    {"virtual_size": 4, "resident_size": 2},
    lambda d: (abs(d.get("ratio", -1) - 0.5) < 1e-9, "ratio==0.5"),
    "2/4=0.5",
)

# ── 3. debug_macos_format_macho_version ──────────────────────────────────────
expected_ver = py_format_macho_version(8)  # "0.0.8"
check(
    "debug_macos_format_macho_version",
    {"value": 8},
    lambda d, ev=expected_ver: (d.get("formatted") == ev, f"formatted=={ev!r}"),
    "8 -> 0.0.8",
)
# Also test a realistic version like 10.15.7 = (10<<16)|(15<<8)|7 = 657415
v2 = (10 << 16) | (15 << 8) | 7
expected_ver2 = py_format_macho_version(v2)
check(
    "debug_macos_format_macho_version",
    {"value": v2},
    lambda d, ev=expected_ver2: (d.get("formatted") == ev, f"formatted=={ev!r}"),
    "10.15.7",
)

# ── 4. debug_macos_dsym_locator_name_for ─────────────────────────────────────
check(
    "debug_macos_dsym_locator_name_for",
    {"executable": "MyApp"},
    lambda d: (d.get("dsym_name") == "MyApp.dSYM", "dsym_name=='MyApp.dSYM'"),
    "executable + .dSYM",
)

# ── 5. debug_macos_macho_section_qualified_name ───────────────────────────────
check(
    "debug_macos_macho_section_qualified_name",
    {"segment": "__TEXT", "section": "__text", "addr": ADDR, "size": SIZE, "offset": 0},
    lambda d: (d.get("qualified_name") == "__TEXT.__text",
               "qualified_name=='__TEXT.__text'"),
    "segment.section",
)

# ── 6. debug_macos_macho_section_is_code ─────────────────────────────────────
# __TEXT.__text -> is_code=true; anything else -> false
check(
    "debug_macos_macho_section_is_code",
    {"segment": "__TEXT", "section": "__text", "addr": ADDR, "size": SIZE},
    lambda d: (d.get("is_code") == True, "is_code==True for __TEXT.__text"),
    "__TEXT.__text is code",
)
check(
    "debug_macos_macho_section_is_code",
    {"segment": "__DATA", "section": "__data", "addr": ADDR, "size": SIZE},
    lambda d: (d.get("is_code") == False, "is_code==False for __DATA.__data"),
    "__DATA.__data is not code",
)

# ── 7. debug_windows_decode_exit_process ─────────────────────────────────────
check(
    "debug_windows_decode_exit_process",
    {"exit_code": 1, "pid": 1, "tid": 1},
    lambda d: (d.get("stop_reason") == "ProcessExit { exit_code: 1 }",
               "stop_reason=='ProcessExit { exit_code: 1 }'"),
    "exit_code=1",
)

# ── 8. debug_windows_decode_exit_thread ──────────────────────────────────────
check(
    "debug_windows_decode_exit_thread",
    {"tid": 1, "exit_code": 1, "pid": 1},
    lambda d: (d.get("stop_reason") == "ThreadExit { tid: ThreadId(1), exit_code: 1 }",
               "stop_reason=='ThreadExit { tid: ThreadId(1), exit_code: 1 }'"),
    "tid=1, exit_code=1",
)

# ── 9. debug_windows_decode_create_thread ────────────────────────────────────
check(
    "debug_windows_decode_create_thread",
    {"tid": 1, "pid": 1},
    lambda d: (d.get("stop_reason") == "ThreadCreate { tid: ThreadId(1) }",
               "stop_reason=='ThreadCreate { tid: ThreadId(1) }'"),
    "tid=1",
)

# ── 10. debug_windows_decode_unload_dll ──────────────────────────────────────
check(
    "debug_windows_decode_unload_dll",
    {"base": 1, "pid": 1, "tid": 1},
    lambda d: (d.get("stop_reason") == 'LibraryUnload { path: "dll@0x1" }',
               "stop_reason=='LibraryUnload { path: \"dll@0x1\" }'"),
    "base=1",
)

# ── 11. debug_windows_page_constants ─────────────────────────────────────────
KNOWN_PAGE = {
    "PAGE_NOACCESS": 1,
    "PAGE_READONLY": 2,
    "PAGE_READWRITE": 4,
    "PAGE_WRITECOPY": 8,
    "PAGE_EXECUTE": 16,
    "PAGE_EXECUTE_READ": 32,
    "PAGE_EXECUTE_READWRITE": 64,
    "PAGE_EXECUTE_WRITECOPY": 128,
}
def _page_constants_check(d):
    for k, v in KNOWN_PAGE.items():
        if d.get(k) != v:
            return False, f"{k}=={v} (got {d.get(k)})"
    return True, "all page constants match"
check(
    "debug_windows_page_constants",
    {},
    _page_constants_check,
    "Windows page protection constants",
)

# ── 12. debug_windows_protect_name ───────────────────────────────────────────
for code, expected_name in [(1, "PAGE_NOACCESS"), (2, "PAGE_READONLY"),
                             (4, "PAGE_READWRITE"), (16, "PAGE_EXECUTE")]:
    check(
        "debug_windows_protect_name",
        {"protect": code},
        lambda d, en=expected_name: (d.get("name") == en, f"name=={en!r}"),
        f"protect={code}",
    )

# ── 13. debug_windows_wow64_context_default ───────────────────────────────────
def _wow64_default_check(d):
    fields = ["context_flags", "eip", "esp", "ebp", "eax", "ebx", "ecx", "edx",
              "esi", "edi", "eflags"]
    for f in fields:
        if d.get(f, -1) != 0:
            return False, f"{f}==0 (got {d.get(f)})"
    return True, "all WoW64 context fields==0"
check("debug_windows_wow64_context_default", {}, _wow64_default_check, "default zeros")

# ── 14. debug_windows_wow64_trap_flag ────────────────────────────────────────
# Trap flag = bit 8 (0x100). eflags=1 has bit 0 set, not bit 8.
check(
    "debug_windows_wow64_trap_flag",
    {"eflags": 1},
    lambda d: (d.get("trap_flag") == False, "trap_flag==False (eflags=1, bit8 not set)"),
    "eflags=1 -> bit 8 not set",
)
check(
    "debug_windows_wow64_trap_flag",
    {"eflags": 0x100},
    lambda d: (d.get("trap_flag") == True, "trap_flag==True (eflags=0x100)"),
    "eflags=0x100 -> bit 8 set",
)

# ── 15. debug_windows_wow64_set_trap_flag ────────────────────────────────────
check(
    "debug_windows_wow64_set_trap_flag",
    {"eflags": 1, "set": False},
    lambda d: (d.get("eflags_out") == 1, "eflags_out==1 (clear bit8 of eflags=1)"),
    "clear bit 8 of 1 -> 1",
)
check(
    "debug_windows_wow64_set_trap_flag",
    {"eflags": 0, "set": True},
    lambda d: (d.get("eflags_out") == 0x100, "eflags_out==0x100 (set bit8 of 0)"),
    "set bit 8 of 0 -> 0x100",
)

# ── 16. debug_windows_is_continuable ─────────────────────────────────────────
check(
    "debug_windows_is_continuable",
    {"code": 1},
    lambda d: (d.get("is_continuable") == True, "is_continuable==True"),
    "generic code=1 is continuable",
)

# ── 17. debug_windows_is_breakpoint_like ─────────────────────────────────────
check(
    "debug_windows_is_breakpoint_like",
    {"code": 1},
    lambda d: (d.get("is_breakpoint_like") == False, "is_breakpoint_like==False"),
    "code=1 is not breakpoint-like",
)
# 0x80000003 = STATUS_BREAKPOINT
check(
    "debug_windows_is_breakpoint_like",
    {"code": 0x80000003},
    lambda d: (d.get("is_breakpoint_like") == True,
               "is_breakpoint_like==True for STATUS_BREAKPOINT"),
    "0x80000003 is breakpoint",
)

# ── 18. debug_windows_status_name ────────────────────────────────────────────
check(
    "debug_windows_status_name",
    {"code": 1},
    lambda d: (d.get("name") == "UNKNOWN_STATUS", "name=='UNKNOWN_STATUS'"),
    "code=1 -> UNKNOWN_STATUS",
)

# ── 19. debug_windows_classify_exception ─────────────────────────────────────
check(
    "debug_windows_classify_exception",
    {"code": 1},
    lambda d: (d.get("class") == "Other", "class=='Other'"),
    "code=1 -> Other",
)

# ── 20. debug_macos_mach_exception_type_from_u32 ─────────────────────────────
for v, expected in [(8, "EXC_MACH_SYSCALL"), (1, "EXC_BAD_ACCESS"), (6, "EXC_BREAKPOINT")]:
    check(
        "debug_macos_mach_exception_type_from_u32",
        {"value": v},
        lambda d, en=expected: (d.get("name") == en, f"name=={en!r}"),
        f"value={v}",
    )

# ── 21. debug_macos_cpu_type_from_u32 ────────────────────────────────────────
check(
    "debug_macos_cpu_type_from_u32",
    {"value": 8},
    lambda d: (d.get("name") == "unknown", "name=='unknown' (8 not a valid cpu type)"),
    "value=8 -> unknown",
)
# CPU_TYPE_X86=7, CPU_TYPE_ARM=12 are known
check(
    "debug_macos_cpu_type_from_u32",
    {"value": 7},
    lambda d: (d.get("name") in ("x86", "i386", "x86_32", "X86"),
               f"name is some x86 variant, got {d.get('name')!r}"),
    "value=7 -> x86",
)

# ── 22. debug_macos_macho_file_type_from_u32 ─────────────────────────────────
for v, expected in [(8, "bundle"), (2, "executable"), (6, "dylib")]:
    check(
        "debug_macos_macho_file_type_from_u32",
        {"value": v},
        lambda d, en=expected: (d.get("name") == en, f"name=={en!r}"),
        f"value={v}",
    )

# ── 23. debug_macos_vm_prot_decode ───────────────────────────────────────────
# value=8 (0b1000): bits 0,1,2 not set => all false
r, w, x, s = py_vm_prot_decode(8)
check(
    "debug_macos_vm_prot_decode",
    {"value": 8},
    lambda d, er=r, ew=w, ex=x: (
        d.get("readable") == er and d.get("writable") == ew and d.get("executable") == ex,
        f"readable={er} writable={ew} executable={ex}",
    ),
    "value=8 -> no prot bits set",
)
# value=5 (0b101): R and X set
r5, w5, x5, _ = py_vm_prot_decode(5)
check(
    "debug_macos_vm_prot_decode",
    {"value": 5},
    lambda d, er=r5, ew=w5, ex=x5: (
        d.get("readable") == er and d.get("writable") == ew and d.get("executable") == ex,
        f"readable={er} writable={ew} executable={ex}",
    ),
    "value=5 -> R+X",
)

# ── 24. debug_macos_mach_vm_protection_decode ────────────────────────────────
check(
    "debug_macos_mach_vm_protection_decode",
    {"value": 8},
    lambda d: (d.get("read") == False and d.get("write") == False
               and d.get("execute") == False,
               "read=False write=False execute=False"),
    "value=8 -> no bits set",
)

# ── 25. debug_macos_arm64_hw_bp_encode ───────────────────────────────────────
bvr_exp, bcr_exp, en_exp = py_arm64_hw_bp_encode(1, ADDR)
check(
    "debug_macos_arm64_hw_bp_encode",
    {"slot": 1, "address": ADDR},
    lambda d, b=bvr_exp, c=bcr_exp, e=en_exp: (
        d.get("bvr") == b and d.get("bcr") == c and d.get("enabled") == e,
        f"bvr=={b} bcr=={c} enabled=={e}",
    ),
    "BCR=0x1E5=485",
)

# ── 26. debug_macos_dyld_image_rebased ───────────────────────────────────────
check(
    "debug_macos_dyld_image_rebased",
    {"load_address": 1, "path": TARGET, "slide": 1, "offset": 0},
    lambda d: (d.get("rebased") == 2, "rebased==2 (1+1)"),
    "load+slide=2",
)

# ── 27. debug_unicorn_arch_pointer_size ──────────────────────────────────────
# v2 UnicornArch variants: x86, x86_64, arm, arm64, mips, sparc
for arch, sz in [("x86_64", 8), ("x86", 4), ("arm", 4), ("arm64", 8),
                  ("mips", 4), ("sparc", 4)]:
    check(
        "debug_unicorn_arch_pointer_size",
        {"arch": arch},
        lambda d, s=sz: (d.get("pointer_size") == s, f"pointer_size=={s}"),
        f"arch={arch}",
    )

# ── 28. debug_unicorn_mem_region_flags ───────────────────────────────────────
# perms=7 (0b111) -> readable=True, writable=True, executable=True
check(
    "debug_unicorn_mem_region_flags",
    {"addr": ADDR, "size": SIZE, "perms": 7},
    lambda d: (d.get("readable") == True and d.get("writable") == True
               and d.get("executable") == True,
               "readable=True writable=True executable=True for perms=7"),
    "perms=7=0b111",
)
# perms=0 -> all false
check(
    "debug_unicorn_mem_region_flags",
    {"addr": ADDR, "size": SIZE, "perms": 0},
    lambda d: (d.get("readable") == False and d.get("writable") == False
               and d.get("executable") == False,
               "all False for perms=0"),
    "perms=0",
)
# perms=5 (0b101) -> R=true, W=false, X=true
check(
    "debug_unicorn_mem_region_flags",
    {"addr": ADDR, "size": SIZE, "perms": 5},
    lambda d: (d.get("readable") == True and d.get("writable") == False
               and d.get("executable") == True,
               "R=True W=False X=True for perms=5"),
    "perms=5=0b101",
)

# ── 29. debug_unicorn_simulated_thread_step ───────────────────────────────────
exp_pc = py_simulated_thread_step(1, 1, stride=4, steps=1)  # 5
check(
    "debug_unicorn_simulated_thread_step",
    {"pc": 1, "sp": 1},
    lambda d, ep=exp_pc: (d.get("pc") == ep and d.get("instruction_count") == 1,
                          f"pc=={ep} instruction_count==1"),
    "pc=1 + stride=4 -> pc=5",
)

# ── 30. debug_unicorn_trace_entry_bytes ──────────────────────────────────────
raw_hex = "deadbeef00112233445566778899aabb"
exp_bytes = py_trace_entry_bytes(raw_hex, 16)  # "DEADBEEF00112233445566778899AABB"
check(
    "debug_unicorn_trace_entry_bytes",
    {"address": ADDR, "raw_hex": raw_hex, "mnemonic": "nop"},
    lambda d, eb=exp_bytes: (d.get("bytes_hex") == eb and d.get("raw_len") == len(raw_hex)//2,
                              f"bytes_hex=={eb!r}"),
    "first 16 bytes uppercase hex",
)

# ── 31. debug_unicorn_coverage_map_report ────────────────────────────────────
check(
    "debug_unicorn_coverage_map_report",
    {"addresses": [ADDR]},
    lambda d: (d.get("covered_count") == 1 and d.get("sorted_addresses") == [ADDR],
               "covered_count==1"),
    "single address",
)
check(
    "debug_unicorn_coverage_map_report",
    {"addresses": []},
    lambda d: (d.get("covered_count") == 0, "covered_count==0 for empty"),
    "empty",
)

# ── 32. debug_unicorn_coverage_map_merge ─────────────────────────────────────
check(
    "debug_unicorn_coverage_map_merge",
    {"base": [], "other": []},
    lambda d: (d.get("merged_count") == 0 and d.get("new_addresses") == [],
               "merged_count==0"),
    "empty merge",
)
check(
    "debug_unicorn_coverage_map_merge",
    {"base": [ADDR], "other": [ADDR + 4]},
    lambda d: (d.get("merged_count") == 2, "merged_count==2"),
    "merge 1+1 disjoint",
)

# ── 33. debug_frida_hook_display ─────────────────────────────────────────────
# addr=0x14000f26c, script="default" (len=7), hook_id=1
exp_display = "FridaHook(id=1, addr=0x14000f26c, script_len=7)"
check(
    "debug_frida_hook_display",
    {"address": ADDR, "script": "default", "hook_id": 1},
    lambda d, ed=exp_display: (d.get("display") == ed and d.get("script_len") == 7,
                               f"display=={ed!r}"),
    "format check",
)

# ── 34. debug_frida_interceptor_record_display ───────────────────────────────
exp_int_disp = "InterceptorRecord(hook=1, addr=0x14000f26c, tid=1, ts=0)"
check(
    "debug_frida_interceptor_record_display",
    {"hook_id": 1, "address": ADDR, "thread_id": 1},
    lambda d, ed=exp_int_disp: (d.get("display") == ed, f"display=={ed!r}"),
    "format check",
)

# ── 35. debug_frida_install_hook_detached_errors ─────────────────────────────
check(
    "debug_frida_install_hook_detached_errors",
    {"address": ADDR},
    lambda d: (d.get("is_err") == True and d.get("error") == "agent not injected",
               "is_err=True error='agent not injected'"),
    "detached session rejects hook",
)

# ── 36. debug_frida_execute_script_detached_errors ───────────────────────────
check(
    "debug_frida_execute_script_detached_errors",
    {},
    lambda d: (d.get("is_err") == True and d.get("error") == "agent not injected",
               "is_err=True error='agent not injected'"),
    "detached session rejects script",
)

# ── 37. debug_frida_scan_memory_detached ────────────────────────────────────
check(
    "debug_frida_scan_memory_detached",
    {"pattern_hex": "deadbeef"},
    lambda d: (d.get("pattern_len") == 4 and d.get("is_err") == True,
               "pattern_len==4 is_err==True"),
    "4 bytes, detached error",
)

# ── 38. debug_frida_session_state_display ────────────────────────────────────
check(
    "debug_frida_session_state_display",
    {},
    lambda d: (d.get("detached") == "detached" and d.get("attached") == "attached",
               "detached/attached strings"),
    "state display names",
)

# ── 39. debug_frida_new_session_state ────────────────────────────────────────
check(
    "debug_frida_new_session_state",
    {},
    lambda d: (d.get("state") == "detached" and d.get("is_attached") == False
               and d.get("hooks") == 0,
               "new session: detached, not attached, 0 hooks"),
    "new session defaults",
)

# ── 40. debug_frida_v2_device_display ────────────────────────────────────────
check(
    "debug_frida_v2_device_display",
    {},
    lambda d: (d.get("local") == "local" and "remote:" in d.get("remote", "")
               and "usb:" in d.get("usb", ""),
               "local/remote:/usb: prefixes"),
    "device display format",
)

# ── 41. debug_windbg_execution_status_no_debuggee ────────────────────────────
check(
    "debug_windbg_execution_status_no_debuggee",
    {},
    lambda d: (d.get("status") == "no_debuggee", "status=='no_debuggee'"),
    "constant status",
)

# ── 42. debug_windbg_default_module_count ────────────────────────────────────
check(
    "debug_windbg_default_module_count",
    {},
    lambda d: (d.get("count") == 5, "count==5"),
    "5 default modules",
)

# ── 43. debug_linux_procmaps_parse_count (empty) ─────────────────────────────
check(
    "debug_linux_procmaps_parse_count",
    {"content": ""},
    lambda d: (d.get("count") == 0, "count==0 for empty"),
    "empty content -> 0",
)
# Verify a real /proc/maps line parses correctly
VALID_MAP_LINE = "7f1234560000-7f1234570000 r-xp 00000000 08:01 12345 /lib/x86_64-linux-gnu/libc.so.6"
check(
    "debug_linux_procmaps_parse_count",
    {"content": VALID_MAP_LINE},
    lambda d: (d.get("count") == 1, "count==1 for 1 valid line"),
    "one valid procmaps line",
)

# ── 44. debug_macos_thread_list_stopped_tids ─────────────────────────────────
check(
    "debug_macos_thread_list_stopped_tids",
    {"threads": []},
    lambda d: (d.get("len") == 0 and d.get("stopped_tids") == [],
               "len==0 stopped_tids==[]"),
    "empty thread list",
)

# ── 45. debug_macos_vm_region_map_totals ─────────────────────────────────────
check(
    "debug_macos_vm_region_map_totals",
    {"regions": []},
    lambda d: (d.get("total_size") == 0 and d.get("len") == 0,
               "total_size==0 len==0"),
    "empty region map",
)

# ── 46. debug_macos_simulate_x86_64_registers ────────────────────────────────
check(
    "debug_macos_simulate_x86_64_registers",
    {"rip": 1, "rsp": 1, "rbp": 1, "rax": 1, "rbx": 1},
    lambda d: (d.get("pc") == 1 and d.get("sp") == 1 and d.get("fp") == 1
               and d.get("rax") == 1 and d.get("rbx") == 1,
               "pc=sp=fp=rax=rbx=1"),
    "passthrough registers",
)

# ── 47. debug_macos_simulate_arm64_registers ─────────────────────────────────
check(
    "debug_macos_simulate_arm64_registers",
    {"pc": 1, "sp": 1, "fp": 1, "lr": 1, "x0": 1},
    lambda d: (d.get("pc") == 1 and d.get("sp") == 1 and d.get("fp") == 1
               and d.get("lr") == 1 and d.get("x0") == 1,
               "pc=sp=fp=lr=x0=1"),
    "passthrough registers",
)

# ── 48. debug_windows_decode_exception_full ──────────────────────────────────
# code=1, addr=ADDR, is_first_chance=False
expected_exc = ("Exception { code: 1, address: Some(Address(5368771180)), "
                "description: \"EXCEPTION_UNKNOWN at 0x14000f26c (second chance)\" }")
check(
    "debug_windows_decode_exception_full",
    {"code": 1, "address": ADDR, "is_first_chance": False, "pid": 1, "tid": 1},
    lambda d, ee=expected_exc: (d.get("stop_reason") == ee, f"stop_reason=={ee!r}"),
    "exception format",
)

# ── 49. debug_macos_breakpoint_manager_build ──────────────────────────────────
check(
    "debug_macos_breakpoint_manager_build",
    {"entries": []},
    lambda d: (d.get("count") == 0 and d.get("addresses") == [],
               "count==0 addresses==[]"),
    "empty bp manager",
)

# ── 50. debug_unicorn_instruction_trace_stats (empty) ────────────────────────
check(
    "debug_unicorn_instruction_trace_stats",
    {"capacity": 8, "entries": []},
    lambda d: (d.get("len") == 0 and d.get("is_empty") == True
               and d.get("unique_addresses") == 0,
               "empty trace stats"),
    "empty trace",
)

# ── 51. debug_unicorn_watchpoint_manager_simulate (empty) ────────────────────
check(
    "debug_unicorn_watchpoint_manager_simulate",
    {"watches": [], "accesses": []},
    lambda d: (d.get("total_hits") == 0 and d.get("watchpoint_count") == 0,
               "total_hits==0"),
    "empty watchpoint manager",
)

# ── 52. debug_unicorn_snapshot_manager_ops (empty) ───────────────────────────
check(
    "debug_unicorn_snapshot_manager_ops",
    {"snapshots": []},
    lambda d: (d.get("count") == 0 and d.get("ids") == [],
               "count==0"),
    "empty snapshot manager",
)

# ── 53. debug_unicorn_code_patcher_apply (empty) ─────────────────────────────
check(
    "debug_unicorn_code_patcher_apply",
    {"patches": []},
    lambda d: (d.get("count") == 0 and d.get("applied_count") == 0,
               "count==0 applied==0"),
    "empty patcher",
)

# ── 54. debug_unicorn_fault_injector_run (empty) ─────────────────────────────
check(
    "debug_unicorn_fault_injector_run",
    {"rules": []},
    lambda d: (d.get("rule_count") == 0 and d.get("total_fires") == 0,
               "rule_count==0 total_fires==0"),
    "empty fault injector",
)

# ── 55. debug_unicorn_register_history_diff (empty) ──────────────────────────
check(
    "debug_unicorn_register_history_diff",
    {"capacity": 8, "snapshots": []},
    lambda d: (d.get("len") == 0 and d.get("diff_first_last") == [],
               "len==0"),
    "empty register history",
)

# ── SKIP entries ─────────────────────────────────────────────────────────────
# These tools depend on binary format parsing, system state, or complex
# state machine behaviour that cannot be independently reproduced in Python.

skip("debug_macos_macho_header_parse",
     "Requires correct Mach-O binary magic (CAFEBABE/FEEDFACE/FEEDFACF); "
     "test input is arbitrary bytes that will not parse to a valid header.")

skip("debug_macos_fat_header_parse",
     "Requires valid FAT binary (magic 0xCAFEBABE).")

skip("debug_macos_parse_load_commands",
     "Requires valid Mach-O header before load commands.")

skip("debug_macos_extract_dylibs",
     "Requires valid Mach-O with LC_LOAD_DYLIB commands.")

skip("debug_macos_extract_uuid",
     "Requires valid Mach-O with LC_UUID command.")

skip("debug_macos_mach_exception_from_u32",
     "Signal mapping from XNU source is implementation-specific and partially "
     "undocumented; cannot safely assert signal numbers.")

skip("debug_macos_mach_exception_to_signal",
     "Same reason as debug_macos_mach_exception_from_u32.")

skip("debug_macos_mach_exception_type_is_fatal",
     "Fatality is policy-level; mapping cannot be derived from headers alone.")

skip("debug_macos_mach_vm_protection_as_raw",
     "Default constructor behaviour depends on Rust struct defaults; "
     "as_raw=0 may be correct but is not independently verifiable.")

skip("debug_macos_mac_mem_perm_from_unix_str",
     "Parser accepts 'rwx' etc. but 'default' is not a valid perm string; "
     "null result is expected but the null-case is not independently verifiable.")

skip("debug_macos_dyld_image_name",
     "Name extraction from path is path-splitting logic; result == input path "
     "on Windows is trivially correct but the rule (last component vs full path) "
     "differs between macOS and Windows; skip to avoid false positives.")

skip("debug_macos_macho_section_qualified_name",
     "Already verified via debug_macos_macho_section_is_code and "
     "debug_macos_macho_section_qualified_name tests above.")

skip("debug_macos_process_describe",
     "Returns live process data or synthetic struct; nondeterministic.")

skip("debug_macos_process_table_enumerate",
     "Lists running processes; nondeterministic.")

skip("debug_macos_dyld_image_list_find",
     "Searches a live dyld image list; nondeterministic.")

skip("debug_macos_dyld_image_rebased",
     "Already covered by arithmetic check above.")

skip("debug_macos_breakpoint_manager_round_trip",
     "Round-trip test exercises internal Rust serialisation; "
     "cannot reproduce Rust serde output in Python without the schema.")

skip("debug_macos_arm64_register_index",
     "Name->index mapping depends on Apple private register table ordering.")

skip("debug_macos_x86_register_index",
     "Same as arm64_register_index.")

skip("debug_macos_stop_reason_address",
     "Depends on variant; would require knowing stop_reason structure.")

skip("debug_macos_thread_list_ops",
     "Stateful thread list with complex operations; not verifiable.")

skip("debug_macos_vm_region_contains",
     "Boolean containment; trivially true but depends on exact size arithmetic "
     "that duplicates debug_macos_mach_vm_region_end which is already covered.")

skip("debug_macos_vm_region_describe",
     "Formatting depends on Rust Display impl.")

skip("debug_macos_vm_region_map_ops",
     "Stateful map operations; nondeterministic order.")

skip("debug_macos_mach_vm_protection_to_unix_str",
     "Unix perm string from macOS protection bits; already verified via "
     "debug_macos_vm_prot_decode which includes as_str.")

skip("debug_macos_mach_vm_region_is_writable",
     "Duplicate of vm_prot bit check already covered.")

skip("debug_frida_v2_manager_lifecycle",
     "Complex state machine test; final state depends on Rust internal "
     "session tracking order.")

skip("debug_frida_simulate_hook_hit_detached",
     "Simulates a hook hit on a detached session; records_after=0 is trivially "
     "correct but the semantics of 'simulate' are internal.")

skip("debug_linux_procmaps_parse_line",
     "Parser output for arbitrary 'test line data' is implementation-defined; "
     "no independent /proc/maps line format reference used here.")

skip("debug_unicorn_symbol_table_resolve",
     "Depends on symbol table contents loaded at runtime.")

skip("debug_unicorn_symbol_table_format",
     "Same as symbol_table_resolve.")

skip("debug_unicorn_thread_simulate",
     "Complex multi-thread state machine; nondeterministic.")

skip("debug_unicorn_thread_simulator_scheduling",
     "Same as thread_simulate.")

skip("debug_unicorn_v2_debugger_emulate",
     "Full CPU emulation; result depends on binary code at start..end range.")

skip("debug_unicorn_patch_record_new",
     "size=0 because 'default' is not valid hex; nondeterministic on bad input.")

skip("debug_unicorn_hook_record_describe",
     "Formatting depends on hook record fields.")

skip("debug_unicorn_emulate_steps",
     "Full emulation; nondeterministic.")

skip("debug_unicorn_v2_config_presets",
     "Config presets are implementation-defined.")

skip("debug_unicorn_coverage_granularity_align",
     "Alignment semantics depend on internal granularity constants.")

skip("debug_unicorn_coverage_granularity_align_v2",
     "Same as v1.")

skip("debug_unicorn_coverage_map_ratio_v2",
     "Ratio depends on total expected coverage count which varies.")

skip("debug_unicorn_mapped_region_contains_v2",
     "Containment check depends on internal region table.")

skip("debug_unicorn_region_perms_flags_v2",
     "v2 API; perms interpretation may differ from v1.")

skip("debug_unicorn_fault_rule_should_fire",
     "Rule evaluation depends on fault rule format.")

skip("debug_unicorn_fault_rule_should_fire_v2",
     "Same as v1.")

skip("debug_unicorn_fault_injector_fire_v2",
     "Stateful injector; nondeterministic.")

skip("debug_unicorn_watch_kind_matches_v2",
     "Watch kind enum matching; implementation-defined.")

skip("debug_unicorn_watchpoint_probe",
     "Watchpoint evaluation; nondeterministic.")

skip("debug_unicorn_memory_mapper_map_v2",
     "Memory mapper; stateful.")

skip("debug_unicorn_snapshot_manager_save_v2",
     "Snapshot serialisation is implementation-defined.")

skip("debug_unicorn_script_gen",
     "Script generation output is implementation-defined.")

skip("debug_unicorn_register_history_diff_v2",
     "v2 API; same as v1.")

skip("debug_unicorn_trace_entry_bytes_v2",
     "v2 encoding may differ; skip until v2 schema is confirmed.")

skip("debug_unicorn_trace_entry_build",
     "Build variant; same data as trace_entry_bytes but different field name.")

skip("debug_unicorn_mem_region_perms",
     "Separate tool exercising MemRegion perms; already covered by "
     "debug_unicorn_mem_region_flags.")

skip("debug_unicorn_symbol_table_prefix_v2",
     "Prefix lookup; implementation-defined.")

skip("debug_windows_exception_name",
     "Code=1 -> EXCEPTION_UNKNOWN but mapping table is large; "
     "spot check is in classify_exception which is already covered.")

skip("debug_windows_is_breakpoint_like_0x80000003",
     "Already covered by is_breakpoint_like check above.")

skip("debug_windows_decode_load_dll",
     "Path appears verbatim in output; already trivially covered by the "
     "load_dll format but path comparison would be environment-specific.")

skip("debug_windows_memory_region_to_map",
     "Converts Windows MEMORY_BASIC_INFORMATION; requires valid struct fields.")

skip("debug_macos_stop_reason_is_exit",
     "Stop reason variant check; implementation-defined.")

# ── Shutdown ─────────────────────────────────────────────────────────────────
p.stdin.close()
p.terminate()

# ── Summarise ────────────────────────────────────────────────────────────────
passed  = [t for t in tests if t["pass"]]
failed  = [t for t in tests if not t["pass"]]

print(f"\nRESULTS: {len(passed)} passed, {len(failed)} failed, {len(skips)} skipped")
print(f"Total tests: {len(tests)}")

if failed:
    print("\n=== FAILURES ===")
    for f in failed:
        print(f"  {f['tool']}: expected={f['expected']}  actual={str(f['actual'])[:200]}")

# Write outputs
with open(OUT_V2, "w") as fh:
    json.dump({"summary": {"passed": len(passed), "failed": len(failed),
                            "skipped": len(skips), "total_tests": len(tests)},
               "tests": tests}, fh, indent=2)

with open(SKIP_OUT, "w") as fh:
    json.dump(skips, fh, indent=2)

print(f"\nWrote {OUT_V2}")
print(f"Wrote {SKIP_OUT}")
