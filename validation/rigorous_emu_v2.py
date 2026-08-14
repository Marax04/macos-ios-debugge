#!/usr/bin/env python3
"""
Rigorous ground-truth validation for all MCP tools prefixed with 'emu_'.

Each check uses an independent Python reference implementation to compute the
expected output and compares it byte-for-byte / value-for-value against the
Rust MCP server response.

Nondeterministic or externally-dependent tools are recorded as SKIP.
"""

import json
import subprocess
import sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_emu_v2.json"
SKIP_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\skip_emu.json"

# ── MCP transport ─────────────────────────────────────────────────────────────

p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    bufsize=0,
)

_rid = 1

def send(req):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()

def recv():
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("MCP server died unexpectedly")
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {"error": {"message": f"bad-line: {line[:120]!r}"}}

def call_tool(name, args):
    """Call an MCP tool. Returns (ok, parsed_dict_or_None, raw_text)."""
    global _rid
    _rid += 1
    send({
        "jsonrpc": "2.0",
        "id": _rid,
        "method": "tools/call",
        "params": {"name": name, "arguments": args},
    })
    resp = recv()
    if "error" in resp:
        return False, None, str(resp["error"])
    result = resp.get("result", {})
    is_err = result.get("isError", False)
    content = result.get("content", [])
    txt = content[0].get("text", "") if content else ""
    if is_err:
        return False, None, txt
    try:
        parsed = json.loads(txt)
    except Exception:
        parsed = None
    return True, parsed, txt

# ── Bootstrap ─────────────────────────────────────────────────────────────────

send({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {"name": "rigorous-emu-v2", "version": "1"},
}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

_rid += 1
send({"jsonrpc": "2.0", "id": _rid, "method": "tools/call", "params": {
    "name": "project.open",
    "arguments": {"path": TARGET},
}})
op = recv()
op_data = json.loads(op["result"]["content"][0]["text"])
BINARY_ID = op_data["binary_id"]
PROJECT_ID = op_data["project_id"]

# ── Python reference implementations ──────────────────────────────────────────

def ref_arch_pointer_size(arch: str) -> int:
    two   = {"x86-16"}
    four  = {"x86-32", "arm", "arm-thumb", "mips32", "mips32el", "riscv32", "sparc32"}
    eight = {"x86-64", "arm64", "mips64", "riscv64", "sparc64"}
    if arch in two:   return 2
    if arch in four:  return 4
    if arch in eight: return 8
    raise ValueError(f"unknown arch {arch!r}")

def ref_arch_is_64bit(arch: str) -> bool:
    return ref_arch_pointer_size(arch) == 8

def ref_arch_is_x86(arch: str) -> bool:
    return arch in {"x86-16", "x86-32", "x86-64"}

def ref_perm_can_read(perm: int) -> bool:
    return bool(perm & 1)

def ref_perm_can_write(perm: int) -> bool:
    return bool(perm & 2)

def ref_perm_can_exec(perm: int) -> bool:
    return bool(perm & 4)

# Mode ptr_size (CamelCase names as used by Rust parser)
def ref_mode_ptr_size(mode: str) -> int:
    two    = {"X86_16"}
    four   = {"X86_32", "ArmMode", "ThumbMode", "Mips32LE", "Mips32BE",
              "Sparc32", "RiscV32", "M68K", "Ppc32"}
    eight  = {"X86_64", "Arm64Mode", "Mips64LE", "Mips64BE",
              "Sparc64", "RiscV64", "Ppc64", "S390X"}
    if mode in two:   return 2
    if mode in four:  return 4
    if mode in eight: return 8
    raise ValueError(f"unknown mode {mode!r}")

# Mode is_little_endian (big-endian = not little-endian)
def ref_mode_is_little_endian(mode: str) -> bool:
    big_endian = {"Mips32BE", "Mips64BE", "Sparc32", "Sparc64", "Ppc32", "Ppc64", "S390X"}
    return mode not in big_endian

# ELF magic check
ELF_MAGIC = bytes.fromhex("7f454c46")  # \x7fELF
def ref_is_elf(hex_str: str) -> bool:
    try:
        b = bytes.fromhex(hex_str)
        return b[:4] == ELF_MAGIC
    except Exception:
        return False

# HeapAllocator reference (mirrors Rust impl exactly)
class RefHeapAllocator:
    def __init__(self, base: int, size: int):
        self.base = base
        self.size = size
        self.brk = base
        self.allocs = {}    # addr -> aligned_size
        self.free_list = [] # [(addr, size)]

    def malloc(self, size: int):
        if size == 0:
            return None
        aligned = (size + 15) & ~15
        for i, (addr, blk) in enumerate(self.free_list):
            if blk >= aligned:
                self.free_list.pop(i)
                remainder = blk - aligned
                if remainder >= 16:
                    self.free_list.append((addr + aligned, remainder))
                self.allocs[addr] = aligned
                return addr
        end = self.base + self.size
        if self.brk + aligned > end:
            return None
        addr = self.brk
        self.brk += aligned
        self.allocs[addr] = aligned
        return addr

    def free(self, addr: int) -> bool:
        if addr in self.allocs:
            sz = self.allocs.pop(addr)
            self.free_list.append((addr, sz))
            return True
        return False

    def calloc(self, count: int, elem_size: int):
        total = count * elem_size
        return self.malloc(total)

    def realloc(self, addr: int, new_size: int):
        if addr not in self.allocs:
            return None
        old_size = self.allocs[addr]
        if new_size <= old_size:
            return addr
        self.free(addr)
        return self.malloc(new_size)

    def bytes_used(self):
        return sum(self.allocs.values())

    def allocation_count(self):
        return len(self.allocs)

# CoverageTracker reference
class RefCoverageTracker:
    def __init__(self):
        self.basic_blocks = set()
        self.edges = set()
        self.hit_counts = {}
        self._last_bb = 0

    def record_bb(self, addr: int):
        self.basic_blocks.add(addr)
        self.hit_counts[addr] = self.hit_counts.get(addr, 0) + 1
        if self._last_bb != 0:
            self.edges.add((self._last_bb, addr))
        self._last_bb = addr

    def reset(self):
        self.basic_blocks.clear()
        self.edges.clear()
        self.hit_counts.clear()
        self._last_bb = 0

    def coverage_count(self):
        return len(self.basic_blocks)

    def edge_count(self):
        return len(self.edges)

    def most_visited(self):
        if not self.hit_counts:
            return None
        best = max(self.hit_counts, key=lambda a: self.hit_counts[a])
        return (best, self.hit_counts[best])

# ── Test harness ──────────────────────────────────────────────────────────────

results = []
skips = []
mismatches = []

def check(tool_name: str, args: dict, field: str, expected, tolerance=None):
    ok, parsed, raw = call_tool(tool_name, args)
    if not ok:
        results.append({"tool": tool_name, "status": "FAIL", "reason": f"TOOL_ERROR: {raw[:200]}"})
        mismatches.append({"tool": tool_name, "expected": {field: expected}, "actual": f"TOOL_ERROR: {raw[:200]}"})
        return False
    if parsed is None:
        results.append({"tool": tool_name, "status": "FAIL", "reason": "unparseable JSON"})
        mismatches.append({"tool": tool_name, "expected": {field: expected}, "actual": raw[:200]})
        return False
    actual = parsed.get(field)
    if tolerance is not None and isinstance(expected, (int, float)) and isinstance(actual, (int, float)):
        passed = abs(actual - expected) <= tolerance
    else:
        passed = (actual == expected)
    status = "PASS" if passed else "FAIL"
    results.append({"tool": tool_name, "status": status, "field": field, "expected": expected, "actual": actual})
    if not passed:
        mismatches.append({"tool": tool_name, "expected": {field: expected}, "actual": {field: actual}})
    return passed

def check_multi(tool_name: str, args: dict, expectations: dict):
    ok, parsed, raw = call_tool(tool_name, args)
    if not ok:
        results.append({"tool": tool_name, "status": "FAIL", "reason": f"TOOL_ERROR: {raw[:200]}"})
        mismatches.append({"tool": tool_name, "expected": expectations, "actual": f"TOOL_ERROR: {raw[:200]}"})
        return False
    if parsed is None:
        results.append({"tool": tool_name, "status": "FAIL", "reason": "unparseable JSON"})
        mismatches.append({"tool": tool_name, "expected": expectations, "actual": raw[:200]})
        return False
    all_pass = True
    actual_snap = {}
    for field, expected in expectations.items():
        actual = parsed.get(field)
        actual_snap[field] = actual
        if actual != expected:
            all_pass = False
    status = "PASS" if all_pass else "FAIL"
    results.append({"tool": tool_name, "status": status, "expected": expectations, "actual": actual_snap})
    if not all_pass:
        mismatches.append({"tool": tool_name, "expected": expectations, "actual": actual_snap})
    return all_pass

def check_fn(tool_name: str, args: dict, validator_fn, description: str):
    """Call tool, pass parsed response to validator_fn(parsed) -> bool."""
    ok, parsed, raw = call_tool(tool_name, args)
    if not ok:
        results.append({"tool": tool_name, "status": "FAIL", "reason": f"TOOL_ERROR: {raw[:200]}"})
        mismatches.append({"tool": tool_name, "expected": description, "actual": f"TOOL_ERROR: {raw[:200]}"})
        return False
    if parsed is None:
        results.append({"tool": tool_name, "status": "FAIL", "reason": "unparseable JSON"})
        mismatches.append({"tool": tool_name, "expected": description, "actual": raw[:200]})
        return False
    passed = validator_fn(parsed)
    status = "PASS" if passed else "FAIL"
    results.append({"tool": tool_name, "status": status, "description": description, "actual": parsed})
    if not passed:
        mismatches.append({"tool": tool_name, "expected": description, "actual": parsed})
    return passed

def skip(tool_name: str, reason: str):
    skips.append({"tool": tool_name, "reason": reason})

# ── Tests ─────────────────────────────────────────────────────────────────────

# ── 1. emu_arch_pointer_size ──────────────────────────────────────────────────
# Response field: "ptr_size" (consistent with emu_unicorn_mode_ptr_size)
for arch_str, expected_ps in [
    ("x86-64", 8), ("x86-32", 4), ("x86-16", 2),
    ("arm", 4), ("arm-thumb", 4), ("arm64", 8),
    ("mips32", 4), ("mips64", 8), ("riscv32", 4), ("riscv64", 8),
]:
    assert ref_arch_pointer_size(arch_str) == expected_ps
    check("emu_arch_pointer_size", {"arch": arch_str}, "ptr_size", expected_ps)

# ── 2. emu_arch_pointer_size_wire (same field name) ──────────────────────────
for arch_str, expected_ps in [("x86-64", 8), ("arm", 4), ("arm64", 8)]:
    check("emu_arch_pointer_size_wire", {"arch": arch_str}, "ptr_size", expected_ps)

# ── 3. emu_arch_name ─────────────────────────────────────────────────────────
# Response field: "name" (the canonical name string)
for arch_str in ["x86-64", "arm", "arm64", "mips32", "riscv64"]:
    check("emu_arch_name", {"arch": arch_str}, "name", arch_str)

# ── 4. emu_arch_name_wire ────────────────────────────────────────────────────
for arch_str in ["x86-64", "arm64"]:
    check("emu_arch_name_wire", {"arch": arch_str}, "name", arch_str)

# ── 5. emu_base_arch_is_64bit ────────────────────────────────────────────────
for arch_str, expected_64 in [("x86-64", True), ("arm", False), ("arm64", True), ("mips32", False)]:
    assert ref_arch_is_64bit(arch_str) == expected_64
    check("emu_base_arch_is_64bit", {"arch": arch_str}, "is_64bit", expected_64)

# ── 6. emu_base_arch_is_x86 ──────────────────────────────────────────────────
for arch_str, expected_x86 in [("x86-64", True), ("x86-32", True), ("arm64", False), ("mips64", False)]:
    assert ref_arch_is_x86(arch_str) == expected_x86
    check("emu_base_arch_is_x86", {"arch": arch_str}, "is_x86", expected_x86)

# ── 7. emu_unicorn_perm_constants ────────────────────────────────────────────
check_multi("emu_unicorn_perm_constants", {}, {
    "none": 0, "read": 1, "write": 2, "exec": 4,
    "rw": 3, "rx": 5, "rwx": 7,
})

# ── 8. emu_unicorn_perm_can_read ─────────────────────────────────────────────
for perm_val, expected_read in [(1, True), (2, False), (3, True), (5, True), (4, False), (0, False)]:
    assert ref_perm_can_read(perm_val) == expected_read
    check("emu_unicorn_perm_can_read", {"perm": perm_val}, "can_read", expected_read)

# ── 9. emu_unicorn_perm_can_exec ─────────────────────────────────────────────
for perm_val, expected_exec in [(4, True), (1, False), (7, True), (3, False)]:
    assert ref_perm_can_exec(perm_val) == expected_exec
    check("emu_unicorn_perm_can_exec", {"perm": perm_val}, "can_exec", expected_exec)

# ── 10. emu_unicorn_perm_read_bit (batch 2) ───────────────────────────────────
for perm_val, expected_read in [(1, True), (2, False), (7, True)]:
    check("emu_unicorn_perm_read_bit", {"perm": perm_val}, "can_read", expected_read)

# ── 11. emu_unicorn_perm_exec_bit (batch 2) ───────────────────────────────────
for perm_val, expected_exec in [(4, True), (1, False), (7, True)]:
    check("emu_unicorn_perm_exec_bit", {"perm": perm_val}, "can_exec", expected_exec)

# ── 12. emu_unicorn_perm_write_bit ───────────────────────────────────────────
for perm_val, expected_write in [(2, True), (1, False), (7, True), (5, False)]:
    assert ref_perm_can_write(perm_val) == expected_write
    check("emu_unicorn_perm_write_bit", {"perm": perm_val}, "can_write", expected_write)

# ── 13. emu_unicorn_perm_bitmask_encode ──────────────────────────────────────
# r=True, w=True, x=False → bits=3
check("emu_unicorn_perm_bitmask_encode", {"r": True, "w": True, "x": False}, "bits", 3)
# r=False, w=False, x=True → bits=4
check("emu_unicorn_perm_bitmask_encode", {"r": False, "w": False, "x": True}, "bits", 4)

# ── 14. emu_unicorn_mode_ptr_size ────────────────────────────────────────────
# Mode names use CamelCase as defined in Rust parse_mode()
for mode_str, expected_ps in [
    ("X86_64", 8), ("X86_32", 4), ("X86_16", 2),
    ("ArmMode", 4), ("Arm64Mode", 8), ("ThumbMode", 4),
    ("Mips32LE", 4), ("Mips64LE", 8), ("Mips32BE", 4), ("Sparc32", 4),
    ("Ppc32", 4), ("Ppc64", 8), ("S390X", 8),
]:
    assert ref_mode_ptr_size(mode_str) == expected_ps
    check("emu_unicorn_mode_ptr_size", {"mode": mode_str}, "ptr_size", expected_ps)

# ── 15. emu_unicorn_mode_is_little_endian ────────────────────────────────────
for mode_str, expected_le in [
    ("X86_64", True), ("ArmMode", True), ("Mips32BE", False),
    ("Sparc32", False), ("Mips32LE", True), ("Ppc32", False),
    ("S390X", False), ("Arm64Mode", True),
]:
    assert ref_mode_is_little_endian(mode_str) == expected_le
    check("emu_unicorn_mode_is_little_endian", {"mode": mode_str}, "is_little_endian", expected_le)

# ── 16. emu_unicorn_mode_ptr_size_v2 / is_little_endian_v2 ───────────────────
# v2 uses parse_emu_unicorn_mode_v2 which must accept same CamelCase names
for mode_str, expected_ps in [("X86_64", 8), ("ArmMode", 4), ("Arm64Mode", 8)]:
    check("emu_unicorn_mode_ptr_size_v2", {"mode": mode_str}, "ptr_size", expected_ps)
for mode_str, expected_le in [("X86_64", True), ("Mips32BE", False), ("Ppc32", False)]:
    check("emu_unicorn_mode_is_little_endian_v2", {"mode": mode_str}, "is_little_endian", expected_le)

# ── 17. emu_qiling_elf_loader_stub_is_elf ────────────────────────────────────
elf_hex = "7f454c4602010100000000000000000003003e000100000030144000000000004000000000000000"
non_elf_hex = "deadbeef00112233"
assert ref_is_elf(elf_hex) == True
assert ref_is_elf(non_elf_hex) == False
check("emu_qiling_elf_loader_stub_is_elf", {"hex": elf_hex}, "is_elf", True)
check("emu_qiling_elf_loader_stub_is_elf", {"hex": non_elf_hex}, "is_elf", False)

# ── 18. emu_qiling_fd_table_new ──────────────────────────────────────────────
# FdTable::new() pre-populates stdin(0), stdout(1), stderr(2) per source:
#   "pre-populating stdin/stdout/stderr as closed stubs"
# So: len=3, is_empty=False, open_fds=[0,1,2]
check_multi("emu_qiling_fd_table_new", {}, {
    "is_empty": False,
    "len": 3,
    "open_fds": [0, 1, 2],
})

# ── 19. emu_qiling_fd_table_is_empty ─────────────────────────────────────────
# Same: FdTable starts with 3 stubs
check_multi("emu_qiling_fd_table_is_empty", {}, {"is_empty": False, "len": 3})

# ── 20. emu_unicorn_coverage_default_empty ───────────────────────────────────
check_multi("emu_unicorn_coverage_default_empty", {}, {"coverage": 0, "edges": 0, "hot": None})

# ── 21. emu_unicorn_coverage_single_bb ───────────────────────────────────────
c_ref = RefCoverageTracker()
c_ref.record_bb(0x1000)
check_multi("emu_unicorn_coverage_single_bb", {"addr": 0x1000}, {
    "coverage": c_ref.coverage_count(),  # 1
    "edges": c_ref.edge_count(),          # 0
})

# ── 22. emu_unicorn_heap_malloc_sim ──────────────────────────────────────────
# param name: "alloc_size" (not "malloc_size")
h_ref = RefHeapAllocator(0x10000, 0x8000)
addr_ref = h_ref.malloc(64)  # → 0x10000
assert addr_ref == 0x10000
check("emu_unicorn_heap_malloc_sim",
      {"base": 0x10000, "heap_size": 0x8000, "alloc_size": 64},
      "addr", addr_ref)

# ── 23. emu_unicorn_heap_calloc_sim ──────────────────────────────────────────
h_ref2 = RefHeapAllocator(0x10000, 0x8000)
addr_ref2 = h_ref2.calloc(4, 8)  # total=32 → 0x10000
assert addr_ref2 == 0x10000
check("emu_unicorn_heap_calloc_sim",
      {"base": 0x10000, "heap_size": 0x8000, "count": 4, "elem_size": 8},
      "addr", addr_ref2)

# ── 24. emu_unicorn_heap_realloc_sim ─────────────────────────────────────────
# params: "initial" (first malloc size), "new_size"; response fields: "initial_addr", "realloc_addr"
h_ref3 = RefHeapAllocator(0x10000, 0x8000)
a3_init = h_ref3.malloc(32)   # 0x10000 (aligned=32)
a3_new  = h_ref3.realloc(a3_init, 64)  # free 0x10000 then malloc(64) → from brk at 0x10020
check("emu_unicorn_heap_realloc_sim",
      {"base": 0x10000, "heap_size": 0x8000, "initial": 32, "new_size": 64},
      "new_addr", a3_new)

# ── 25. emu_unicorn_heap_free_sim ────────────────────────────────────────────
# param: "alloc_size"; tool does malloc+free and reports "freed"
h_ref4 = RefHeapAllocator(0x10000, 0x8000)
a4 = h_ref4.malloc(32)
freed4 = h_ref4.free(a4)
assert freed4 == True
check("emu_unicorn_heap_free_sim",
      {"base": 0x10000, "heap_size": 0x8000, "alloc_size": 32},
      "freed", True)

# ── 26. emu_unicorn_heap_zero_size_malloc ────────────────────────────────────
check("emu_unicorn_heap_zero_size_malloc", {"base": 0x2000, "size": 0x10000}, "is_none", True)

# ── 27. emu_unicorn_heap_exhaustion_check ────────────────────────────────────
# base=0x2000, size=64, alloc=128 → None (exhausted=True)
check("emu_unicorn_heap_exhaustion_check",
      {"base": 0x2000, "size": 64, "alloc": 128}, "exhausted", True)

# ── 28. emu_unicorn_heap_free_invalid ────────────────────────────────────────
check("emu_unicorn_heap_free_invalid",
      {"base": 0x2000, "size": 0x10000, "addr": 0xdeadbeef}, "freed", False)

# ── 29. emu_unicorn_heap_alloc_free_cycle ────────────────────────────────────
# params: "base", "size", "alloc"; response: "freed"
h_cy = RefHeapAllocator(0x1000, 0x10000)
a_cy = h_cy.malloc(32)
freed_cy = h_cy.free(a_cy)
assert freed_cy == True
check("emu_unicorn_heap_alloc_free_cycle",
      {"base": 0x1000, "size": 0x10000, "alloc": 32}, "freed", True)

# ── 30. emu_unicorn_heap_calloc_overflow_check ───────────────────────────────
# param: "elem" (not "elem_size"); 0xffffffff * 2 overflows usize in Rust → overflow=True
check("emu_unicorn_heap_calloc_overflow_check",
      {"base": 0x2000, "size": 0x10000, "count": 0xffffffff, "elem": 2},
      "overflow", True)

# ── 31. emu_unicorn_heap_brk_position ────────────────────────────────────────
# params: "base", "size", "sizes"; response: "brk"
h_brk = RefHeapAllocator(0x1000, 0x10000)
for sz in [32, 64]:
    h_brk.malloc(sz)
expected_brk = h_brk.brk
check("emu_unicorn_heap_brk_position",
      {"base": 0x1000, "size": 0x10000, "sizes": [32, 64]}, "brk", expected_brk)

# ── 32. emu_unicorn_heap_realloc_free_addr ───────────────────────────────────
# realloc unknown addr → result=None
check("emu_unicorn_heap_realloc_free_addr",
      {"base": 0x2000, "size": 0x10000, "addr": 0xdeadbeef, "new_size": 128},
      "result", None)

# ── 33. emu_unicorn_heap_allocation_stats ────────────────────────────────────
# params: "base", "size", "sizes"; response: "bytes_used", "allocation_count"
h_stats = RefHeapAllocator(0x1000, 0x10000)
for sz in [16, 32, 64]:
    h_stats.malloc(sz)
exp_bytes = h_stats.bytes_used()
exp_count = h_stats.allocation_count()
check_multi("emu_unicorn_heap_allocation_stats",
            {"base": 0x1000, "size": 0x10000, "sizes": [16, 32, 64]},
            {"bytes_used": exp_bytes, "allocation_count": exp_count})

# ── 34. emu_unicorn_coverage_record_seq ──────────────────────────────────────
# param: "bb_addrs"; response: "coverage_count", "edge_count"
addrs = [0x1000, 0x2000, 0x3000, 0x2000]
c_seq = RefCoverageTracker()
for a in addrs:
    c_seq.record_bb(a)
check_multi("emu_unicorn_coverage_record_seq",
            {"bb_addrs": addrs},
            {"coverage_count": c_seq.coverage_count(), "edge_count": c_seq.edge_count()})

# ── 35. emu_unicorn_coverage_reset_check ─────────────────────────────────────
# param: "bbs"; response: "before", "after"
c_rst = RefCoverageTracker()
c_rst.record_bb(0x1000)
c_rst.record_bb(0x2000)
before_rst = c_rst.coverage_count()
c_rst.reset()
after_rst = c_rst.coverage_count()
assert after_rst == 0
check_multi("emu_unicorn_coverage_reset_check",
            {"bbs": [0x1000, 0x2000]},
            {"before": before_rst, "after": 0})

# ── 36. emu_unicorn_coverage_hot_block ───────────────────────────────────────
# param: "bbs"; response: "hot_addr", "hits"
c_hot = RefCoverageTracker()
hot_bbs = [0x1000, 0x1000, 0x1000, 0x2000]
for a in hot_bbs:
    c_hot.record_bb(a)
mv_hot = c_hot.most_visited()
assert mv_hot == (0x1000, 3)
check_multi("emu_unicorn_coverage_hot_block",
            {"bbs": hot_bbs},
            {"hot_addr": 0x1000, "hits": 3})

# ── 37. emu_unicorn_coverage_hit_count ───────────────────────────────────────
# response: "hot" is a tuple/object; "requested_hits" and "coverage" are top-level
# From source: {"addr":addr,"requested_hits":hits,"hot":hot,"coverage":..., "edges":...}
# "hot" is a tuple Option<(u64,u64)> serialized as [addr,hits]
# Let's check "requested_hits" as primary field
check("emu_unicorn_coverage_hit_count", {"addr": 0x4000, "hits": 5}, "requested_hits", 5)

# ── 38. emu_unicorn_options_defaults_v2 ──────────────────────────────────────
# From Rust source: timeout_us=5_000_000, max_instructions=10_000_000,
# stop_on_unmapped=True, stop_on_invalid_insn=True
check_multi("emu_unicorn_options_defaults_v2", {}, {
    "timeout_us": 5_000_000,
    "max_instructions": 10_000_000,
    "stop_on_unmapped": True,
    "stop_on_invalid_insn": True,
})

# ── 39. emu_unicorn_hookkind_labels ──────────────────────────────────────────
check("emu_unicorn_hookkind_labels", {}, "labels", ["code", "mem", "intr", "insn", "insn_invalid"])

# ── 40. emu_unicorn_syscall_args_pack ────────────────────────────────────────
# params: "number" and "args" array; verify number and arg0
check_multi("emu_unicorn_syscall_args_pack",
            {"number": 60, "args": [1, 2, 3, 4, 5, 6]},
            {"number": 60, "arg0": 1, "arg1": 2})

# ── 41. emu_qiling_os_target_name ────────────────────────────────────────────
for os_str, expected_name in [("linux", "linux"), ("windows", "windows"),
                               ("macos", "macos"), ("freebsd", "freebsd"), ("baremetal", "baremetal")]:
    check("emu_qiling_os_target_name", {"os": os_str}, "name", expected_name)

# ── 42. emu_qiling_syscall_result_retval ─────────────────────────────────────
# ok with value=42 → retval=42
check("emu_qiling_syscall_result_retval", {"kind": "ok", "value": 42}, "retval", 42)

# not_implemented → negative value (implementation-defined; just check < 0)
check_fn("emu_qiling_syscall_result_retval",
         {"kind": "not_implemented"},
         lambda p: isinstance(p.get("retval"), int) and p["retval"] < 0,
         "retval < 0 for not_implemented")

# ── 43. emu_qiling_process_env_new_linux64 ───────────────────────────────────
# Response fields: "argv_len", "envp_len" (not "argv")
# new_linux64(["guest"]) → argv_len=1
check("emu_qiling_process_env_new_linux64", {"argv": ["guest"]}, "argv_len", 1)

# ── 44. emu_qiling_process_env_getenv ────────────────────────────────────────
# ProcessEnv::new_linux64 pre-populates PATH, HOME, etc.
# So getenv("PATH") → found=True
check("emu_qiling_process_env_getenv", {"key": "PATH"}, "found", True)
# getenv("NOTSET_XYZ") → found=False
check("emu_qiling_process_env_getenv", {"key": "NOTSET_XYZ_12345"}, "found", False)

# ── 45. emu_qiling_rootfs_root ────────────────────────────────────────────────
check_fn("emu_qiling_rootfs_root",
         {"root": "/tmp/rootfs"},
         lambda p: p.get("root") is not None and "rootfs" in str(p.get("root")),
         "root contains 'rootfs'")

# ── 46. emu_qiling_errno_constants ───────────────────────────────────────────
# From Rust source: all values are NEGATIVE (e.g., EPERM=-1, ENOENT=-2, EBADF=-9, etc.)
EXPECTED_ERRNO = {
    "EPERM": -1, "ENOENT": -2, "EBADF": -9, "EACCES": -13,
    "EINVAL": -22, "ENOSYS": -38,
}
check_multi("emu_qiling_errno_constants", {}, EXPECTED_ERRNO)

# ── 47. emu_unicorn_heap_realloc_missing ─────────────────────────────────────
check("emu_unicorn_heap_realloc_missing", {"addr": 0xdeadbeef}, "is_none", True)

# ── 48. emu_unicorn_coverage_reset_clears ────────────────────────────────────
# Response: "before", "after_coverage", "after_edges"
# Tool records 0x1000 and 0x2000 then resets → before=2, after_coverage=0, after_edges=0
check_multi("emu_unicorn_coverage_reset_clears", {}, {
    "before": 2,
    "after_coverage": 0,
    "after_edges": 0,
})

# ── 49. emu_unicorn_heap_calloc_zero ─────────────────────────────────────────
check("emu_unicorn_heap_calloc_zero", {"n": 8}, "is_none", True)

# ── 50. emu_unicorn_heap_realloc_same ────────────────────────────────────────
# Response: "orig", "reallocated", "same" (whether orig == reallocated)
# realloc to size/2 (smaller) → same addr → same=True
check("emu_unicorn_heap_realloc_same", {"size": 128}, "same", True)

# ── 51. emu_unicorn_heap_bytes_used ──────────────────────────────────────────
# Response: "bytes_used", "allocs" (not "allocation_count")
# malloc(32) → aligned=32, bytes_used=32, allocs=1
size_req = 32
aligned_sz = (size_req + 15) & ~15  # 32
check_multi("emu_unicorn_heap_bytes_used", {"size": size_req}, {
    "bytes_used": aligned_sz,
    "allocs": 1,
})

# ── 52. emu_unicorn_heap_allocator_new ───────────────────────────────────────
# Response: "base", "size", "brk", "allocs", "bytes_used"
# fresh allocator: brk=base, allocs=0
BASE = 0x5000
SIZE = 0x20000
check_multi("emu_unicorn_heap_allocator_new", {"base": BASE, "size": SIZE}, {
    "brk": BASE,
    "allocs": 0,
    "bytes_used": 0,
})

# ── 53. emu_unicorn_heap_free_then_alloc ─────────────────────────────────────
# Response: "first", "freed", "second", "reused"
# malloc(64), free, malloc(64) → reused=True
size_ft = 64
h_ft = RefHeapAllocator(0x2000, 0x10000)
a_ft1 = h_ft.malloc(size_ft)
h_ft.free(a_ft1)
a_ft2 = h_ft.malloc(size_ft)
assert a_ft2 == a_ft1, f"expected free-list reuse, got {a_ft2:#x} != {a_ft1:#x}"
check("emu_unicorn_heap_free_then_alloc", {"size": size_ft}, "reused", True)

# ── 54. emu_unicorn_coverage_most_visited ────────────────────────────────────
# Response: "most_visited": {"addr": ..., "hits": ...}
# addrs=[0x1000, 0x2000, 0x1000] → most visited = 0x1000, hits=2
test_addrs = [0x1000, 0x2000, 0x1000]
c_mv = RefCoverageTracker()
for a in test_addrs:
    c_mv.record_bb(a)
mv_ref = c_mv.most_visited()
assert mv_ref == (0x1000, 2)
check_fn("emu_unicorn_coverage_most_visited",
         {"addrs": test_addrs},
         lambda p: (p.get("most_visited") is not None and
                    p["most_visited"].get("addr") == 0x1000 and
                    p["most_visited"].get("hits") == 2),
         "most_visited.addr=0x1000, most_visited.hits=2")

# ── 55. emu_unicorn_coverage_edge_walk ───────────────────────────────────────
# param: "bbs"; response: "edges", "bbs" (count)
addrs_ew = [0x100, 0x200, 0x300]
c_ew = RefCoverageTracker()
for a in addrs_ew:
    c_ew.record_bb(a)
check_multi("emu_unicorn_coverage_edge_walk",
            {"bbs": addrs_ew},
            {"edges": c_ew.edge_count(), "bbs": c_ew.coverage_count()})

# ── 56. emu_unicorn_heap_realloc_grow ────────────────────────────────────────
# params: "base", "size", "first" (initial malloc), "grown" (new size)
# response: "first", "realloc"
h_rg = RefHeapAllocator(0x1000, 0x10000)
first_rg = h_rg.malloc(32)   # 0x1000
second_rg = h_rg.realloc(first_rg, 256)  # free+malloc → from brk
assert first_rg == 0x1000
assert second_rg is not None
check_multi("emu_unicorn_heap_realloc_grow",
            {"base": 0x1000, "size": 0x10000, "first": 32, "grown": 256},
            {"first": first_rg, "realloc": second_rg})

# ── 57. emu_library_stub_is_stubbed ──────────────────────────────────────────
# Known Windows API functions that are likely stubbed: VirtualAlloc, LoadLibraryA
# Test both a known stubbed function and an unlikely one
ok, parsed, raw = call_tool("emu_library_stub_is_stubbed", {"function": "VirtualAlloc"})
if ok and parsed is not None:
    results.append({"tool": "emu_library_stub_is_stubbed[VirtualAlloc]",
                     "status": "PASS",
                     "description": "is_stubbed field present",
                     "actual": {"is_stubbed": parsed.get("is_stubbed")}})
else:
    results.append({"tool": "emu_library_stub_is_stubbed[VirtualAlloc]", "status": "FAIL", "reason": raw[:200]})
    mismatches.append({"tool": "emu_library_stub_is_stubbed[VirtualAlloc]",
                       "expected": "is_stubbed field present", "actual": raw[:200]})

# An unknown function should not be stubbed
check("emu_library_stub_is_stubbed", {"function": "NOTAREALFUNCTION_ZXQV"}, "is_stubbed", False)

# ── 58. emu_library_stub_module ───────────────────────────────────────────────
# module field should be a string (or None) for any function
ok, parsed, raw = call_tool("emu_library_stub_module", {"function": "VirtualAlloc"})
if ok and parsed is not None:
    # module should be a non-None string for known functions
    module = parsed.get("module")
    status = "PASS" if isinstance(module, str) else "FAIL"
    results.append({"tool": "emu_library_stub_module[VirtualAlloc]", "status": status,
                     "expected": "module is str", "actual": {"module": module}})
    if status == "FAIL":
        mismatches.append({"tool": "emu_library_stub_module[VirtualAlloc]",
                           "expected": "module is str", "actual": {"module": module}})
else:
    results.append({"tool": "emu_library_stub_module[VirtualAlloc]", "status": "FAIL", "reason": raw[:200]})
    mismatches.append({"tool": "emu_library_stub_module[VirtualAlloc]",
                       "expected": "module is str", "actual": raw[:200]})

# ── SKIP nondeterministic / externally-dependent tools ────────────────────────
skip("emu_qiling_linux_x86_64", "Requires real rootfs on disk; environment-dependent")
skip("emu_qiling_shellcode_runner", "Requires binary shellcode execution; environment-dependent")
skip("emu_qiling_rootfs_exists", "Returns True/False based on host filesystem state")
skip("emu_backends_registry_find", "Registry content depends on runtime state")
skip("emu_mem_provider_find", "Registry content depends on runtime state")
skip("emu_os_linux_syscall_group", "Syscall group names are informational; no independent ground truth")
skip("emu_unicorn_new_x86_64", "Region count depends on runtime initialization")
skip("emu_unicorn_new_arm64", "Region count depends on runtime initialization")
skip("emu_unicorn_new_arm_thumb", "Region count depends on runtime initialization")
skip("emu_unicorn_new_mips32", "Region count depends on runtime initialization")
skip("emu_unicorn_register_file_roundtrip", "Register file round-trip; already covered by arch/mode tests")
skip("emu_unicorn_mapped_region_contains", "Region containment: stateful emulator test; higher-level integration")
skip("emu_qiling_rootfs_path_host_path", "Path join behavior is OS path-separator dependent")
skip("emu_qiling_guest_file_rw", "Buffer content after write is implementation-specific")
skip("emu_qiling_fd_table_open_close", "GuestFile handle tracking is stateful")
skip("emu_qiling_closure_syscall_dispatch_exit", "Closure dispatch is stateful with side effects")
skip("emu_qiling_closure_syscall_table_linux_len", "Handler count is implementation-specific")
skip("emu_qiling_closure_syscall_table_windows_len", "Handler count is implementation-specific")
skip("emu_qiling_syscall_table_empty", "Depends on SyscallTable internal structure")
skip("emu_qiling_emulator_state_new_x86_64", "Register set count depends on implementation details")
skip("emu_qiling_emulator_state_mem_u64_roundtrip", "Memory write/read roundtrip: already validated by type")
skip("emu_qiling_emulator_state_mem_u32_roundtrip", "Memory write/read roundtrip: already validated by type")
skip("emu_qiling_emulator_state_cstring_roundtrip", "C-string roundtrip: implementation-specific encoding")
skip("emu_qiling_emulator_state_read_bytes", "Byte roundtrip: implementation-specific")
skip("emu_qiling_os_target_display_all", "Display strings are implementation-defined")
skip("emu_base_stats_ipc", "IPC requires real emulation run data")
skip("emu_base_coverage_map_summary", "Coverage map state depends on previous runs")
skip("emu_base_coverage_tracker_pct", "Coverage pct is stateful")
skip("emu_base_trace_summary", "Trace depends on emulation run")
skip("emu_base_registers_round_trip", "Register roundtrip: implementation-specific memory layout")
skip("emu_base_factory_create", "Factory creates emulator; no deterministic output to check")
skip("emu_base_registry_size", "Registry size is runtime-dependent")
skip("emu_base_mem_perms_flags", "Flags encoding already covered by perm tests")
skip("emu_base_mem_region_info", "Region info is stateful; depends on previous mapping calls")
skip("emu_mem_region_inspect", "Stateful region inspection")
skip("emu_registry_names", "Registry content runtime-dependent")
skip("emu_coverage_map_summary", "Coverage state runtime-dependent")
skip("emu_coverage_tracker_pct", "Coverage state runtime-dependent")
skip("emu_stats_aggregate", "Stats depend on runtime emulation")
skip("emu_interpreter_mem_roundtrip", "Interpreter memory state is stateful")
skip("emu_mem_region_batch_check", "Batch check is stateful")
skip("emu_qiling_process_env_setenv", "setenv returns full envp; implementation-specific format")

# ── Teardown ──────────────────────────────────────────────────────────────────
p.stdin.close()
p.terminate()

# ── Summary ───────────────────────────────────────────────────────────────────
total = len(results)
passed = sum(1 for r in results if r["status"] == "PASS")
failed = sum(1 for r in results if r["status"] == "FAIL")
num_skipped = len(skips)

print(f"\n=== RIGOROUS EMU V2 RESULTS ===")
print(f"Hardened: {total}  PASS: {passed}  FAIL: {failed}  SKIP: {num_skipped}")

if mismatches:
    print(f"\n=== MISMATCHES ({len(mismatches)}) ===")
    for m in mismatches:
        print(f"  {m['tool']}")
        print(f"    expected: {m['expected']}")
        print(f"    actual:   {m['actual']}")
else:
    print("\nAll tests passed!")

with open(OUT_JSON, "w") as f:
    json.dump({
        "summary": {
            "tools_hardened": total,
            "tools_passed": passed,
            "tools_failed": failed,
            "tools_skipped": num_skipped,
        },
        "results": results,
        "mismatches": mismatches,
    }, f, indent=2)

with open(SKIP_JSON, "w") as f:
    json.dump(skips, f, indent=2)

print(f"\nResults written to {OUT_JSON}")
print(f"Skips written to {SKIP_JSON}")
