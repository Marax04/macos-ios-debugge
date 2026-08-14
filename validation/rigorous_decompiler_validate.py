#!/usr/bin/env python3
"""
Rigorous ground-truth validation for MCP tools prefixed with decompiler_.
Each tool is called via JSON-RPC-over-stdio (same mechanism as exercise_v3.py),
and the result is compared against an independently computed Python reference.
Results are written to rigorous_decompiler_v2.json.
"""
import json
import re
import subprocess
import sys
import time

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
PDB = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo_zyphora.pdb"

# ─────────────────────────────────────────────────────────────────────────────
# MCP transport helpers (same pattern as exercise_v3.py)
# ─────────────────────────────────────────────────────────────────────────────

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
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {"error": {"message": f"bad-line: {line[:100]!r}"}}

def call(method_name, args, rid_val):
    send({"jsonrpc": "2.0", "id": rid_val, "method": "tools/call",
          "params": {"name": method_name, "arguments": args}})
    resp = recv()
    if "error" in resp:
        return None, str(resp["error"])
    content = resp.get("result", {}).get("content", [])
    is_err = resp.get("result", {}).get("isError", False)
    txt = content[0].get("text", "") if content else ""
    if is_err:
        return None, txt
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None

# Initialize
send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "rigorous_decompiler", "version": "1"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

# Open project
send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
      "params": {"name": "project.open", "arguments": {"path": TARGET}}})
op = recv()
op_data = json.loads(op["result"]["content"][0]["text"])
BINARY_ID = op_data["binary_id"]
PROJECT_ID = op_data["project_id"]

RID = 100

def next_rid():
    global RID
    RID += 1
    return RID

# ─────────────────────────────────────────────────────────────────────────────
# Python reference implementations (ground truth)
# ─────────────────────────────────────────────────────────────────────────────

# C keywords from rustre-decompiler/src/pseudocode_generator.rs
C_KEYWORDS = {
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if",
    "inline", "int", "long", "register", "restrict", "return", "short",
    "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
    "unsigned", "void", "volatile", "while",
    "_Alignas", "_Alignof", "_Atomic", "_Bool", "_Complex", "_Generic",
    "_Imaginary", "_Noreturn", "_Static_assert", "_Thread_local",
}

def ref_identifier_tokens(s: str):
    """Mirror of rustre_decompiler_cfs::identifier_tokens."""
    out = []
    cur = ""
    for ch in s:
        if ch.isalnum() or ch == '_':
            cur += ch
        else:
            if cur:
                if not cur.isdigit():
                    out.append(cur)
                cur = ""
    if cur and not cur.isdigit():
        out.append(cur)
    return out

def ref_arch_from_str(arch: str) -> str:
    """Mirror of rustre_decompiler::arch_from_str."""
    a = arch.lower()
    if "aarch64" in a or "arm64" in a:
        return "Arm64"
    elif "arm" in a:
        return "Arm32"
    elif "x86_64" in a or "x86-64" in a or "amd64" in a:
        return "X86_64"
    elif "x86" in a or "i386" in a or "i686" in a:
        return "X86"
    elif "riscv64" in a:
        return "RiscV64"
    elif "riscv32" in a:
        return "RiscV32"
    elif "mips64" in a:
        return "Mips64"
    elif "mips" in a:
        return "Mips32"
    else:
        return "X86_64"

def ref_os_from_pe_flag(is_pe: bool) -> str:
    return "Windows" if is_pe else "Linux"

def ref_block_id_display(id_val: int) -> str:
    return f"bb{id_val}"

def ref_is_c_keyword(name: str) -> bool:
    return name in C_KEYWORDS

# ─────────────────────────────────────────────────────────────────────────────
# Test cases
# ─────────────────────────────────────────────────────────────────────────────

results = []
skip_reasons = {}

def record(tool, status, expected, actual, note=""):
    mismatch = None
    if status == "FAIL":
        mismatch = {"tool": tool, "expected": expected, "actual": actual}
    results.append({
        "tool": tool,
        "status": status,
        "expected": expected,
        "actual": actual,
        "note": note,
    })
    return mismatch

mismatches = []

# ─────────────────────────────────────────────────────────────────────────────
# 1. decompiler_cfs_identifier_tokens
# ─────────────────────────────────────────────────────────────────────────────
tool = "decompiler_cfs_identifier_tokens"
test_text = "i < 10 + count_var"
expected_tokens = ref_identifier_tokens(test_text)  # ["i", "count_var"]
actual, err = call(tool, {"text": test_text}, next_rid())
if err:
    m = record(tool, "FAIL", expected_tokens, f"ERROR: {err}", "identifier_tokens error")
    mismatches.append(m)
else:
    got_tokens = actual.get("tokens", [])
    got_count = actual.get("count", -1)
    if got_tokens == expected_tokens and got_count == len(expected_tokens):
        record(tool, "PASS", expected_tokens, got_tokens)
    else:
        m = record(tool, "FAIL", {"tokens": expected_tokens, "count": len(expected_tokens)},
                   {"tokens": got_tokens, "count": got_count})
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 2. decompiler_cfs_identifier_tokens — numeric tokens are skipped
# ─────────────────────────────────────────────────────────────────────────────
tool = "decompiler_cfs_identifier_tokens"
test_text2 = "x + 42 - y"
expected_tokens2 = ref_identifier_tokens(test_text2)  # ["x", "y"]
actual2, err2 = call(tool, {"text": test_text2}, next_rid())
label = tool + " (numeric-skip)"
if err2:
    m = record(label, "FAIL", expected_tokens2, f"ERROR: {err2}")
    mismatches.append(m)
else:
    got2 = actual2.get("tokens", [])
    if got2 == expected_tokens2:
        record(label, "PASS", expected_tokens2, got2)
    else:
        m = record(label, "FAIL", expected_tokens2, got2)
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 3. decompiler_cfs_branch_condition — block with Branch stmt
# ─────────────────────────────────────────────────────────────────────────────
tool = "decompiler_cfs_branch_condition"
cond_input = {"id": 0, "stmts": [{"Raw": "x = 1"}, {"Branch": "x > 0"}]}
expected_cond = "x > 0"
actual3, err3 = call(tool, cond_input, next_rid())
if err3:
    m = record(tool, "FAIL", expected_cond, f"ERROR: {err3}")
    mismatches.append(m)
else:
    got_cond = actual3.get("condition")
    if got_cond == expected_cond:
        record(tool, "PASS", expected_cond, got_cond)
    else:
        m = record(tool, "FAIL", expected_cond, got_cond)
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 4. decompiler_cfs_branch_condition — no branch → null
# ─────────────────────────────────────────────────────────────────────────────
tool = "decompiler_cfs_branch_condition"
label = tool + " (no-branch)"
no_branch_input = {"id": 0, "stmts": [{"Raw": "x = 1"}, {"Return": None}]}
actual4, err4 = call(tool, no_branch_input, next_rid())
if err4:
    m = record(label, "FAIL", None, f"ERROR: {err4}")
    mismatches.append(m)
else:
    got_cond4 = actual4.get("condition")
    if got_cond4 is None:
        record(label, "PASS", None, got_cond4)
    else:
        m = record(label, "FAIL", None, got_cond4)
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 5. decompiler_c_version
# ─────────────────────────────────────────────────────────────────────────────
tool = "decompiler_c_version"
# Read from Cargo.toml
import re as _re
try:
    with open(r"C:\Users\Fra\Desktop\RustRE\crates\rustre-decompiler-c\Cargo.toml") as f:
        cargo_content = f.read()
    m_ver = _re.search(r'^version\s*=\s*"([^"]+)"', cargo_content, _re.MULTILINE)
    expected_version = m_ver.group(1) if m_ver else "0.1.0"
except Exception:
    expected_version = "0.1.0"

actual5, err5 = call(tool, {}, next_rid())
if err5:
    m = record(tool, "FAIL", expected_version, f"ERROR: {err5}")
    mismatches.append(m)
else:
    got_ver = actual5.get("version")
    if got_ver == expected_version:
        record(tool, "PASS", expected_version, got_ver)
    else:
        m = record(tool, "FAIL", expected_version, got_ver)
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 6. decompiler_c_supported_languages
# ─────────────────────────────────────────────────────────────────────────────
tool = "decompiler_c_supported_languages"
expected_langs = ["c", "c++"]
actual6, err6 = call(tool, {}, next_rid())
if err6:
    m = record(tool, "FAIL", expected_langs, f"ERROR: {err6}")
    mismatches.append(m)
else:
    got_langs = actual6.get("languages", [])
    if got_langs == expected_langs:
        record(tool, "PASS", expected_langs, got_langs)
    else:
        m = record(tool, "FAIL", expected_langs, got_langs)
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 7. decompiler_c_max_decompile_depth
# ─────────────────────────────────────────────────────────────────────────────
tool = "decompiler_c_max_decompile_depth"
expected_depth = 32
actual7, err7 = call(tool, {}, next_rid())
if err7:
    m = record(tool, "FAIL", expected_depth, f"ERROR: {err7}")
    mismatches.append(m)
else:
    got_depth = actual7.get("max_decompile_depth")
    if got_depth == expected_depth:
        record(tool, "PASS", expected_depth, got_depth)
    else:
        m = record(tool, "FAIL", expected_depth, got_depth)
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 8. decompiler_c_brace_style_default
# ─────────────────────────────────────────────────────────────────────────────
tool = "decompiler_c_brace_style_default"
expected_brace = "KAndR"
actual8, err8 = call(tool, {}, next_rid())
if err8:
    m = record(tool, "FAIL", expected_brace, f"ERROR: {err8}")
    mismatches.append(m)
else:
    got_brace = actual8.get("brace_style")
    if got_brace == expected_brace:
        record(tool, "PASS", expected_brace, got_brace)
    else:
        m = record(tool, "FAIL", expected_brace, got_brace)
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 9. decompiler_arch_from_str (x86_64)
# ─────────────────────────────────────────────────────────────────────────────
tool = "decompiler_arch_from_str"
expected_arch = ref_arch_from_str("x86_64")  # "X86_64"
actual9, err9 = call(tool, {"arch": "x86_64"}, next_rid())
if err9:
    m = record(tool, "FAIL", expected_arch, f"ERROR: {err9}")
    mismatches.append(m)
else:
    got_arch = actual9.get("arch")
    if got_arch == expected_arch:
        record(tool, "PASS", expected_arch, got_arch)
    else:
        m = record(tool, "FAIL", expected_arch, got_arch)
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 10. decompiler_arch_from_str (aarch64)
# ─────────────────────────────────────────────────────────────────────────────
tool = "decompiler_arch_from_str"
label = tool + " (aarch64)"
expected_arch2 = ref_arch_from_str("aarch64")  # "Arm64"
actual10, err10 = call(tool, {"arch": "aarch64"}, next_rid())
if err10:
    m = record(label, "FAIL", expected_arch2, f"ERROR: {err10}")
    mismatches.append(m)
else:
    got_arch2 = actual10.get("arch")
    if got_arch2 == expected_arch2:
        record(label, "PASS", expected_arch2, got_arch2)
    else:
        m = record(label, "FAIL", expected_arch2, got_arch2)
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 11. decompiler_arch_from_str (unknown → X86_64)
# ─────────────────────────────────────────────────────────────────────────────
tool = "decompiler_arch_from_str"
label = tool + " (unknown→X86_64)"
expected_arch3 = ref_arch_from_str("unknown")  # "X86_64"
actual11, err11 = call(tool, {"arch": "unknown"}, next_rid())
if err11:
    m = record(label, "FAIL", expected_arch3, f"ERROR: {err11}")
    mismatches.append(m)
else:
    got_arch3 = actual11.get("arch")
    if got_arch3 == expected_arch3:
        record(label, "PASS", expected_arch3, got_arch3)
    else:
        m = record(label, "FAIL", expected_arch3, got_arch3)
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 12. decompiler_os_from_pe_flag (is_pe=True → Windows)
# ─────────────────────────────────────────────────────────────────────────────
tool = "decompiler_os_from_pe_flag"
expected_os = ref_os_from_pe_flag(True)  # "Windows"
actual12, err12 = call(tool, {"is_pe": True}, next_rid())
if err12:
    m = record(tool, "FAIL", expected_os, f"ERROR: {err12}")
    mismatches.append(m)
else:
    got_os = actual12.get("os")
    if got_os == expected_os:
        record(tool, "PASS", expected_os, got_os)
    else:
        m = record(tool, "FAIL", expected_os, got_os)
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 13. decompiler_os_from_pe_flag (is_pe=False → Linux)
# ─────────────────────────────────────────────────────────────────────────────
tool = "decompiler_os_from_pe_flag"
label = tool + " (is_pe=false)"
expected_os2 = ref_os_from_pe_flag(False)  # "Linux"
actual13, err13 = call(tool, {"is_pe": False}, next_rid())
if err13:
    m = record(label, "FAIL", expected_os2, f"ERROR: {err13}")
    mismatches.append(m)
else:
    got_os2 = actual13.get("os")
    if got_os2 == expected_os2:
        record(label, "PASS", expected_os2, got_os2)
    else:
        m = record(label, "FAIL", expected_os2, got_os2)
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 14. decompiler_cfs_block_id_display
# ─────────────────────────────────────────────────────────────────────────────
tool = "decompiler_cfs_block_id_display"
expected_disp = ref_block_id_display(5)  # "bb5"
actual14, err14 = call(tool, {"id": 5}, next_rid())
if err14:
    m = record(tool, "FAIL", expected_disp, f"ERROR: {err14}")
    mismatches.append(m)
else:
    got_disp = actual14.get("display")
    if got_disp == expected_disp:
        record(tool, "PASS", expected_disp, got_disp)
    else:
        m = record(tool, "FAIL", expected_disp, got_disp)
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 15. rustre_decompiler_callconv_arch_from_str
# ─────────────────────────────────────────────────────────────────────────────
tool = "rustre_decompiler_callconv_arch_from_str"
expected_arch4 = ref_arch_from_str("x86_64")  # "X86_64"
actual15, err15 = call(tool, {"arch": "x86_64"}, next_rid())
if err15:
    m = record(tool, "FAIL", expected_arch4, f"ERROR: {err15}")
    mismatches.append(m)
else:
    got_arch4 = actual15.get("arch")
    if got_arch4 == expected_arch4:
        record(tool, "PASS", expected_arch4, got_arch4)
    else:
        m = record(tool, "FAIL", expected_arch4, got_arch4)
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 16. rustre_decompiler_batch_is_c_keyword — known keywords
# ─────────────────────────────────────────────────────────────────────────────
tool = "rustre_decompiler_batch_is_c_keyword"
test_names = ["int", "void", "if", "main", "foo"]
expected_hits = sum(1 for n in test_names if ref_is_c_keyword(n))  # 3
actual16, err16 = call(tool, {"names": test_names}, next_rid())
if err16:
    m = record(tool, "FAIL", expected_hits, f"ERROR: {err16}")
    mismatches.append(m)
else:
    got_hits = actual16.get("keyword_hits", -1)
    got_count = actual16.get("count", -1)
    if got_hits == expected_hits and got_count == len(test_names):
        record(tool, "PASS", {"keyword_hits": expected_hits, "count": len(test_names)},
               {"keyword_hits": got_hits, "count": got_count})
    else:
        m = record(tool, "FAIL",
                   {"keyword_hits": expected_hits, "count": len(test_names)},
                   {"keyword_hits": got_hits, "count": got_count})
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 17. rustre_decompiler_default_options — spot-check key fields
# ─────────────────────────────────────────────────────────────────────────────
tool = "rustre_decompiler_default_options"
actual17, err17 = call(tool, {}, next_rid())
if err17:
    m = record(tool, "FAIL", {"target_level": "PseudoC", "max_function_size": 10000},
               f"ERROR: {err17}")
    mismatches.append(m)
else:
    # Ground truth from rustre_decompiler::DecompOptions::default()
    expected_level = "PseudoC"
    expected_max = 10000
    got_level = actual17.get("target_level")
    got_max = actual17.get("max_function_size")
    if got_level == expected_level and got_max == expected_max:
        record(tool, "PASS",
               {"target_level": expected_level, "max_function_size": expected_max},
               {"target_level": got_level, "max_function_size": got_max})
    else:
        m = record(tool, "FAIL",
                   {"target_level": expected_level, "max_function_size": expected_max},
                   {"target_level": got_level, "max_function_size": got_max})
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 18. rustre_decompiler_standard_pass_specs — count=9
# ─────────────────────────────────────────────────────────────────────────────
tool = "rustre_decompiler_standard_pass_specs"
expected_passes = 9
actual18, err18 = call(tool, {}, next_rid())
if err18:
    m = record(tool, "FAIL", expected_passes, f"ERROR: {err18}")
    mismatches.append(m)
else:
    got_passes = actual18.get("count", -1)
    if got_passes == expected_passes:
        record(tool, "PASS", expected_passes, got_passes)
    else:
        m = record(tool, "FAIL", expected_passes, got_passes)
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 19. rustre_decompiler_mem_operand_parse — "default" → 0 operands
# ─────────────────────────────────────────────────────────────────────────────
tool = "rustre_decompiler_mem_operand_parse"
actual19, err19 = call(tool, {"operands": "default"}, next_rid())
if err19:
    m = record(tool, "FAIL", {"count": 0, "operands": []}, f"ERROR: {err19}")
    mismatches.append(m)
else:
    got_count19 = actual19.get("count", -1)
    got_ops = actual19.get("operands", [])
    # "default" is not a valid operand string → 0 parsed
    if got_count19 == 0 and got_ops == []:
        record(tool, "PASS", {"count": 0, "operands": []},
               {"count": got_count19, "operands": got_ops})
    else:
        m = record(tool, "FAIL", {"count": 0, "operands": []},
                   {"count": got_count19, "operands": got_ops})
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 20. decompiler_type_qualifier_string (empty → all false, qualifier="")
# ─────────────────────────────────────────────────────────────────────────────
tool = "decompiler_type_qualifier_string"
actual20, err20 = call(tool, {}, next_rid())
if err20:
    m = record(tool, "FAIL", {"qualifier": "", "is_const": False}, f"ERROR: {err20}")
    mismatches.append(m)
else:
    ok = (actual20.get("qualifier") == "" and
          actual20.get("is_const") is False and
          actual20.get("is_volatile") is False and
          actual20.get("is_restrict") is False)
    if ok:
        record(tool, "PASS", {"qualifier": "", "is_const": False, "is_volatile": False, "is_restrict": False},
               {k: actual20.get(k) for k in ["qualifier", "is_const", "is_volatile", "is_restrict"]})
    else:
        m = record(tool, "FAIL",
                   {"qualifier": "", "is_const": False, "is_volatile": False, "is_restrict": False},
                   {k: actual20.get(k) for k in ["qualifier", "is_const", "is_volatile", "is_restrict"]})
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 21. decompiler_type_rename_all (empty vars → empty mapping)
# ─────────────────────────────────────────────────────────────────────────────
tool = "decompiler_type_rename_all"
actual21, err21 = call(tool, {"vars": []}, next_rid())
if err21:
    m = record(tool, "FAIL", {"mapping": {}}, f"ERROR: {err21}")
    mismatches.append(m)
else:
    got_mapping = actual21.get("mapping", None)
    if got_mapping == {}:
        record(tool, "PASS", {"mapping": {}}, {"mapping": got_mapping})
    else:
        m = record(tool, "FAIL", {"mapping": {}}, {"mapping": got_mapping})
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 22. decompiler_type_database_windows_counts_wp
# ─────────────────────────────────────────────────────────────────────────────
tool = "decompiler_type_database_windows_counts_wp"
expected_win = {"structs": 2, "unions": 0, "functions": 0, "typedefs": 20}
actual22, err22 = call(tool, {}, next_rid())
if err22:
    m = record(tool, "FAIL", expected_win, f"ERROR: {err22}")
    mismatches.append(m)
else:
    got_win = {k: actual22.get(k) for k in expected_win}
    if got_win == expected_win:
        record(tool, "PASS", expected_win, got_win)
    else:
        m = record(tool, "FAIL", expected_win, got_win)
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 23. decompiler_type_database_linux_counts_wp
# ─────────────────────────────────────────────────────────────────────────────
tool = "decompiler_type_database_linux_counts_wp"
expected_lin = {"structs": 0, "unions": 0, "functions": 0, "typedefs": 13}
actual23, err23 = call(tool, {}, next_rid())
if err23:
    m = record(tool, "FAIL", expected_lin, f"ERROR: {err23}")
    mismatches.append(m)
else:
    got_lin = {k: actual23.get(k) for k in expected_lin}
    if got_lin == expected_lin:
        record(tool, "PASS", expected_lin, got_lin)
    else:
        m = record(tool, "FAIL", expected_lin, got_lin)
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 24. decompiler_type_stdlib_db_counts_wp
# ─────────────────────────────────────────────────────────────────────────────
tool = "decompiler_type_stdlib_db_counts_wp"
expected_stdlib = {"structs": 0, "unions": 0, "functions": 6, "typedefs": 0}
actual24, err24 = call(tool, {}, next_rid())
if err24:
    m = record(tool, "FAIL", expected_stdlib, f"ERROR: {err24}")
    mismatches.append(m)
else:
    got_stdlib = {k: actual24.get(k) for k in expected_stdlib}
    if got_stdlib == expected_stdlib:
        record(tool, "PASS", expected_stdlib, got_stdlib)
    else:
        m = record(tool, "FAIL", expected_stdlib, got_stdlib)
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 25. decompiler_type_layout_padded_size_wp
# ─────────────────────────────────────────────────────────────────────────────
tool = "decompiler_type_layout_padded_size_wp"
expected_layout = {"size": 9, "alignment": 4, "padded_size": 12}
actual25, err25 = call(tool, {}, next_rid())
if err25:
    m = record(tool, "FAIL", expected_layout, f"ERROR: {err25}")
    mismatches.append(m)
else:
    got_layout = {k: actual25.get(k) for k in expected_layout}
    if got_layout == expected_layout:
        record(tool, "PASS", expected_layout, got_layout)
    else:
        m = record(tool, "FAIL", expected_layout, got_layout)
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 26. decompiler_type_qualifier_flags_wp (all false by default)
# ─────────────────────────────────────────────────────────────────────────────
tool = "decompiler_type_qualifier_flags_wp"
actual26, err26 = call(tool, {}, next_rid())
if err26:
    m = record(tool, "FAIL", {"is_const": False, "qualifier_string": ""}, f"ERROR: {err26}")
    mismatches.append(m)
else:
    ok = (actual26.get("is_const") is False and
          actual26.get("is_volatile") is False and
          actual26.get("is_restrict") is False and
          actual26.get("qualifier_string") == "")
    if ok:
        record(tool, "PASS",
               {"is_const": False, "is_volatile": False, "is_restrict": False, "qualifier_string": ""},
               {k: actual26.get(k) for k in ["is_const", "is_volatile", "is_restrict", "qualifier_string"]})
    else:
        m = record(tool, "FAIL",
                   {"is_const": False, "is_volatile": False, "is_restrict": False, "qualifier_string": ""},
                   {k: actual26.get(k) for k in ["is_const", "is_volatile", "is_restrict", "qualifier_string"]})
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 27. decompiler_type_union_c_name_wp (name="main" → "union main")
# ─────────────────────────────────────────────────────────────────────────────
tool = "decompiler_type_union_c_name_wp"
expected_union = "union main"
actual27, err27 = call(tool, {"name": "main"}, next_rid())
if err27:
    m = record(tool, "FAIL", expected_union, f"ERROR: {err27}")
    mismatches.append(m)
else:
    got_union = actual27.get("c_name")
    if got_union == expected_union:
        record(tool, "PASS", expected_union, got_union)
    else:
        m = record(tool, "FAIL", expected_union, got_union)
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 28. decompiler_type_pointer_analysis_not_null_wp (any ptr → not_null=True)
# ─────────────────────────────────────────────────────────────────────────────
tool = "decompiler_type_pointer_analysis_not_null_wp"
actual28, err28 = call(tool, {"ptr": "default", "target": "default"}, next_rid())
if err28:
    m = record(tool, "FAIL", {"not_null": True}, f"ERROR: {err28}")
    mismatches.append(m)
else:
    got_nn = actual28.get("not_null")
    if got_nn is True:
        record(tool, "PASS", {"not_null": True}, {"not_null": got_nn})
    else:
        m = record(tool, "FAIL", {"not_null": True}, {"not_null": got_nn})
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# 29. decompiler_stack_frame_report (empty instructions → frame_size=0)
# ─────────────────────────────────────────────────────────────────────────────
tool = "decompiler_stack_frame_report"
actual29, err29 = call(tool, {"function_addr": 0, "instructions": [], "arch": "x86_64"}, next_rid())
if err29:
    m = record(tool, "FAIL", {"frame_size": 0}, f"ERROR: {err29}")
    mismatches.append(m)
else:
    data29 = actual29.get("data", {}) if isinstance(actual29, dict) else {}
    got_fs = data29.get("frame_size", -1)
    if got_fs == 0:
        record(tool, "PASS", {"frame_size": 0, "saved_regs": []},
               {"frame_size": got_fs, "saved_regs": data29.get("saved_regs", [])})
    else:
        m = record(tool, "FAIL", {"frame_size": 0}, {"frame_size": got_fs})
        mismatches.append(m)

# ─────────────────────────────────────────────────────────────────────────────
# SKIP tools — binary-dependent, nondeterministic, or require network
# ─────────────────────────────────────────────────────────────────────────────
SKIPPED = {
    "decompiler_core_batch_decompile": "binary-dependent: result varies with analysis (timing, function count)",
    "decompiler_recover_structs": "binary-dependent: struct recovery depends on PE analysis",
    "decompiler_load_binary_info": "binary-dependent: depends on PE parsing of target",
    "decompiler_detect_functions": "binary-dependent: function count depends on PE parsing",
    "decompiler_disassemble_function_x86": "binary-dependent: disasm output depends on actual bytes at VA",
    "decompiler_cfs_scc_groups": "requires non-empty CFG blocks with specific structure",
    "decompiler_type_rename_variables": "identity passthrough with no renaming context - not independently verifiable",
}

skip_records = []
for stool, sreason in SKIPPED.items():
    skip_records.append({"tool": stool, "reason": sreason})

# ─────────────────────────────────────────────────────────────────────────────
# Shut down
# ─────────────────────────────────────────────────────────────────────────────
p.stdin.close()
p.terminate()

# ─────────────────────────────────────────────────────────────────────────────
# Write results
# ─────────────────────────────────────────────────────────────────────────────
tools_passed = sum(1 for r in results if r["status"] == "PASS")
tools_failed = sum(1 for r in results if r["status"] == "FAIL")
tools_skipped = len(SKIPPED)
tools_hardened = len(results)  # number of tools with rigorous checks applied

summary = {
    "category": "decompiler",
    "tools_hardened": tools_hardened,
    "tools_passed": tools_passed,
    "tools_failed": tools_failed,
    "tools_skipped": tools_skipped,
    "mismatches": [m for m in mismatches if m is not None],
    "results": results,
}

OUT_V2 = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_decompiler_v2.json"
with open(OUT_V2, "w") as f:
    json.dump(summary, f, indent=2)

SKIP_OUT = r"C:\Users\Fra\Desktop\RustRE\validation\skip_decompiler.json"
with open(SKIP_OUT, "w") as f:
    json.dump({"skipped": skip_records}, f, indent=2)

print(f"Hardened: {tools_hardened}  Passed: {tools_passed}  Failed: {tools_failed}  Skipped: {tools_skipped}")
if mismatches:
    print("MISMATCHES:")
    for m in mismatches:
        if m:
            print(f"  {m['tool']}: expected={m['expected']}  actual={m['actual']}")
else:
    print("No mismatches.")
print(f"Results written to: {OUT_V2}")
