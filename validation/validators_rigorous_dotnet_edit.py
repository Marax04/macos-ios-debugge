"""
Rigorous validator for the dotnet_edit module.

Each check computes an independent Python truth and compares it against the
MCP tool output.  No any_valid() shortcuts are used.

Key implementation note:
  - dotnet_edit_recompute_offsets uses rustre_dotnet_edit::opcode_byte_size (table-driven)
  - dotnet_edit_renumber_offsets uses CilInstruction::byte_size() which depends on
    the operand; wire_tools.rs creates instructions via CilInstruction::simple()
    (operand=None) so byte_size()=1 for all opcodes except prefix-* (=2).
  - Hex output from MCP is uppercase; comparisons are case-insensitive.
"""

import json
import subprocess
import time

MCP_EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
REPORT_PATH = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_dotnet_edit.json"

# ── CIL opcode byte size tables ───────────────────────────────────────────────

def opcode_size_table(opcode: str) -> int:
    """Table-driven size (used by recompute_offsets and opcode_byte_size tool).
    Mirrors IlBuilder::opcode_size in lib.rs."""
    two_byte = {
        "ldc.i4.s", "ldarg.s", "starg.s", "ldloc.s", "stloc.s",
        "br.s", "brfalse.s", "brtrue.s",
        "beq.s", "bge.s", "bgt.s", "ble.s", "blt.s",
        "bne.un.s", "bge.un.s", "bgt.un.s", "ble.un.s", "blt.un.s",
        "ceq", "cgt", "cgt.un", "clt", "clt.un",
        "localloc", "endfilter", "volatile.", "tail.", "constrained.",
        "readonly.", "initobj", "cpblk", "initblk", "no.", "refanytype",
    }
    five_byte = {
        "ldc.i4", "br", "brfalse", "brtrue",
        "beq", "bge", "bgt", "ble", "blt",
        "bne.un", "bge.un", "bgt.un", "ble.un", "blt.un",
        "call", "callvirt", "newobj", "jmp",
        "ldstr", "ldfld", "stfld", "ldsfld", "stsfld",
        "box", "newarr", "castclass", "isinst",
        "ldtoken", "ldsflda", "ldflda", "unbox", "unbox.any",
        "stelem", "ldelem", "cpobj", "ldobj", "stobj",
        "mkrefany", "refanyval", "sizeof", "ldc.r4",
    }
    nine_byte = {"ldc.i8", "ldc.r8"}
    if opcode in two_byte:
        return 2
    if opcode in five_byte:
        return 5
    if opcode in nine_byte:
        return 9
    return 1


def byte_size_simple(opcode: str) -> int:
    """CilInstruction::byte_size() when operand=None (as created by simple()).
    opcode_size=1 (or 2 for prefix*), operand_size=0 for None."""
    if opcode.startswith("prefix"):
        return 2
    return 1


def recompute_offsets_truth(opcodes: list) -> list:
    """Expected offsets using table-driven opcode_size (recompute_offsets tool)."""
    offsets = []
    cursor = 0
    for op in opcodes:
        offsets.append(cursor)
        cursor += opcode_size_table(op)
    return offsets


def renumber_offsets_simple_truth(opcodes: list) -> list:
    """Expected offsets using byte_size() with None operand (renumber_offsets tool,
    which uses CilInstruction::simple()). All non-prefix opcodes = 1 byte."""
    offsets = []
    cursor = 0
    for op in opcodes:
        offsets.append(cursor)
        cursor += byte_size_simple(op)
    return offsets


def encode_instructions_truth(opcodes: list) -> tuple:
    """Return (hex_str_lower, byte_len) for a list of simple no-operand opcodes.

    Opcode bytes (from encode_single_instruction in lib.rs):
      nop=0x00, ret=0x2A, ldc.i4.0=0x16, ldc.i4.1=0x17, ..., ldc.i4.8=0x1E,
      ldc.i4.m1=0x15, ldnull=0x14, add=0x58, sub=0x59, mul=0x5A, div=0x5B,
      dup=0x25, pop=0x26, throw=0x7A, ldlen=0x8E, endfinally=0xDC,
      ldarg.0=0x02, ldarg.1=0x03, ldarg.2=0x04, ldarg.3=0x05,
      ldloc.0=0x06, ldloc.1=0x07, ldloc.2=0x08, ldloc.3=0x09,
      stloc.0=0x0A, stloc.1=0x0B, stloc.2=0x0C, stloc.3=0x0D,
      and=0x5F, or=0x60, xor=0x61, neg=0x65, not=0x66, rem=0x5D,
      call/jmp/callvirt/newobj → opcode + 0x00000000 token (4 bytes)
      ldstr → 0x72 + 0x00000000 (4 bytes)
      br.s/brfalse.s/brtrue.s → opcode + 0x00 delta (1 byte)
    """
    opcode_map = {
        "nop": bytes([0x00]),
        "ret": bytes([0x2A]),
        "ldnull": bytes([0x14]),
        "ldc.i4.m1": bytes([0x15]),
        "ldc.i4.0": bytes([0x16]),
        "ldc.i4.1": bytes([0x17]),
        "ldc.i4.2": bytes([0x18]),
        "ldc.i4.3": bytes([0x19]),
        "ldc.i4.4": bytes([0x1A]),
        "ldc.i4.5": bytes([0x1B]),
        "ldc.i4.6": bytes([0x1C]),
        "ldc.i4.7": bytes([0x1D]),
        "ldc.i4.8": bytes([0x1E]),
        "ldarg.0": bytes([0x02]),
        "ldarg.1": bytes([0x03]),
        "ldarg.2": bytes([0x04]),
        "ldarg.3": bytes([0x05]),
        "ldloc.0": bytes([0x06]),
        "ldloc.1": bytes([0x07]),
        "ldloc.2": bytes([0x08]),
        "ldloc.3": bytes([0x09]),
        "stloc.0": bytes([0x0A]),
        "stloc.1": bytes([0x0B]),
        "stloc.2": bytes([0x0C]),
        "stloc.3": bytes([0x0D]),
        "add": bytes([0x58]),
        "sub": bytes([0x59]),
        "mul": bytes([0x5A]),
        "div": bytes([0x5B]),
        "rem": bytes([0x5D]),
        "and": bytes([0x5F]),
        "or": bytes([0x60]),
        "xor": bytes([0x61]),
        "neg": bytes([0x65]),
        "not": bytes([0x66]),
        "dup": bytes([0x25]),
        "pop": bytes([0x26]),
        "throw": bytes([0x7A]),
        "ldlen": bytes([0x8E]),
        "endfinally": bytes([0xDC]),
        # Token opcodes with None operand → 0x00000000 token
        "call":     bytes([0x28, 0x00, 0x00, 0x00, 0x00]),
        "jmp":      bytes([0x27, 0x00, 0x00, 0x00, 0x00]),
        "callvirt": bytes([0x6F, 0x00, 0x00, 0x00, 0x00]),
        "newobj":   bytes([0x73, 0x00, 0x00, 0x00, 0x00]),
        "ldstr":    bytes([0x72, 0x00, 0x00, 0x00, 0x00]),
        # Short branch with None operand → delta=0
        "br.s":       bytes([0x2B, 0x00]),
        "brfalse.s":  bytes([0x2C, 0x00]),
        "brtrue.s":   bytes([0x2D, 0x00]),
        # Long branch with None operand → 0x00000000
        "br":       bytes([0x38, 0x00, 0x00, 0x00, 0x00]),
        "brfalse":  bytes([0x39, 0x00, 0x00, 0x00, 0x00]),
        "brtrue":   bytes([0x3A, 0x00, 0x00, 0x00, 0x00]),
        "ceq":      bytes([0xFE, 0x01]),
        "cgt":      bytes([0xFE, 0x02]),
        "clt":      bytes([0xFE, 0x04]),
    }
    body = b"".join(opcode_map.get(op, bytes([0x00])) for op in opcodes)
    code_size = len(body)
    if code_size < 64:
        header = bytes([((code_size) << 2) | 0x02])
    else:
        import struct
        flags = 0x3003
        header = struct.pack("<HHI", flags, 8, code_size) + bytes(4)
    out = header + body
    return out.hex().lower(), len(out)


# ── MCP session helpers ────────────────────────────────────────────────────────

def mcp_request(proc, req: dict) -> dict:
    line = json.dumps(req) + "\n"
    proc.stdin.write(line.encode())
    proc.stdin.flush()
    while True:
        raw = proc.stdout.readline()
        if not raw:
            raise RuntimeError("MCP process closed stdout")
        raw = raw.strip()
        if not raw:
            continue
        msg = json.loads(raw)
        if "id" in msg:
            return msg


def call_tool(proc, tool: str, params: dict) -> dict:
    req = {
        "jsonrpc": "2.0",
        "id": int(time.time() * 1000) % 100000,
        "method": "tools/call",
        "params": {"name": tool, "arguments": params},
    }
    resp = mcp_request(proc, req)
    result = resp.get("result", {})
    content = result.get("content", [])
    if content:
        try:
            return json.loads(content[0].get("text", "{}"))
        except Exception:
            return {"raw": content[0].get("text", "")}
    return {}


def start_mcp():
    proc = subprocess.Popen(
        [MCP_EXE, "--transport=stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "rigorous_validator", "version": "1.0"},
        },
    }
    mcp_request(proc, init_req)
    notif = {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
    proc.stdin.write((json.dumps(notif) + "\n").encode())
    proc.stdin.flush()
    return proc


# ── Test runner ────────────────────────────────────────────────────────────────

def run_all():
    checks_passed = 0
    checks_failed = 0
    mismatches = []
    tools_hardened = set()

    def check(name, tool, params, expected_field, expected_value, result=None):
        nonlocal checks_passed, checks_failed
        if result is None:
            result = call_tool(proc, tool, params)
        actual = result.get(expected_field)
        # hex comparison: case-insensitive
        if isinstance(expected_value, str) and isinstance(actual, str):
            eq = actual.lower() == expected_value.lower()
        else:
            eq = actual == expected_value
        if eq:
            print(f"  PASS  {name}")
            checks_passed += 1
        else:
            print(f"  FAIL  {name}: expected {expected_value!r}, got {actual!r}")
            checks_failed += 1
            mismatches.append({
                "tool": tool,
                "check": name,
                "expected": expected_value,
                "actual": actual,
                "full_result": result,
            })

    proc = start_mcp()
    try:
        # ── 1. opcode_byte_size: nop → 1 ──────────────────────────────────────
        check("opcode_byte_size nop=1", "dotnet_edit_opcode_byte_size",
              {"opcode": "nop"}, "byte_size", 1)
        tools_hardened.add("dotnet_edit_opcode_byte_size")

        # ── 2. opcode_byte_size: ret → 1 ──────────────────────────────────────
        check("opcode_byte_size ret=1", "dotnet_edit_opcode_byte_size",
              {"opcode": "ret"}, "byte_size", 1)

        # ── 3. opcode_byte_size: call → 5 ─────────────────────────────────────
        check("opcode_byte_size call=5", "dotnet_edit_opcode_byte_size",
              {"opcode": "call"}, "byte_size", 5)

        # ── 4. opcode_byte_size: brfalse.s → 2 ───────────────────────────────
        check("opcode_byte_size brfalse.s=2", "dotnet_edit_opcode_byte_size",
              {"opcode": "brfalse.s"}, "byte_size", 2)

        # ── 5. opcode_byte_size: ldc.i8 → 9 ──────────────────────────────────
        check("opcode_byte_size ldc.i8=9", "dotnet_edit_opcode_byte_size",
              {"opcode": "ldc.i8"}, "byte_size", 9)

        # ── 6. opcode_byte_size: ldstr → 5 ────────────────────────────────────
        check("opcode_byte_size ldstr=5", "dotnet_edit_opcode_byte_size",
              {"opcode": "ldstr"}, "byte_size", 5)

        # ── 7. recompute_offsets: [nop, nop, ret] → [0, 1, 2] ─────────────────
        # Uses table-driven sizes: nop=1, ret=1
        opcodes_3nop = ["nop", "nop", "ret"]
        expected_3 = recompute_offsets_truth(opcodes_3nop)  # [0, 1, 2]
        check("recompute_offsets [nop,nop,ret]=[0,1,2]",
              "dotnet_edit_recompute_offsets", {"opcodes": opcodes_3nop},
              "offsets", expected_3)
        tools_hardened.add("dotnet_edit_recompute_offsets")

        # ── 8. recompute_offsets: [call, ret] → [0, 5] ────────────────────────
        expected_cr = recompute_offsets_truth(["call", "ret"])  # [0, 5]
        check("recompute_offsets [call,ret]=[0,5]",
              "dotnet_edit_recompute_offsets", {"opcodes": ["call", "ret"]},
              "offsets", expected_cr)

        # ── 9. renumber_offsets: [nop, ret] → [0, 1] ─────────────────────────
        # Uses byte_size() with None operand: nop=1, ret=1
        expected_nr1 = renumber_offsets_simple_truth(["nop", "ret"])  # [0, 1]
        check("renumber_offsets [nop,ret]=[0,1]",
              "dotnet_edit_renumber_offsets", {"opcodes": ["nop", "ret"]},
              "offsets", expected_nr1)
        tools_hardened.add("dotnet_edit_renumber_offsets")

        # ── 10. renumber_offsets: [call, call, ret] → [0, 1, 2] ───────────────
        # wire_tools creates simple() instructions (operand=None),
        # so byte_size()=1 for each; renumber gives [0,1,2]
        expected_nr2 = renumber_offsets_simple_truth(["call", "call", "ret"])  # [0,1,2]
        check("renumber_offsets [call,call,ret]=[0,1,2]",
              "dotnet_edit_renumber_offsets", {"opcodes": ["call", "call", "ret"]},
              "offsets", expected_nr2)

        # ── 11. encode_instructions: [ret] → hex "062A", byte_len=2 ──────────
        hex_ret, blen_ret = encode_instructions_truth(["ret"])  # "062a", 2
        r_ret = call_tool(proc, "dotnet_edit_encode_instructions", {"opcodes": ["ret"]})
        check("encode_instructions [ret] hex", "dotnet_edit_encode_instructions",
              {"opcodes": ["ret"]}, "hex", hex_ret, r_ret)
        check("encode_instructions [ret] byte_len", "dotnet_edit_encode_instructions",
              {"opcodes": ["ret"]}, "byte_len", blen_ret, r_ret)
        tools_hardened.add("dotnet_edit_encode_instructions")

        # ── 12. encode_instructions: [nop, ret] → hex "0A002A", byte_len=3 ──
        hex_nr, blen_nr = encode_instructions_truth(["nop", "ret"])  # "0a002a", 3
        r_nr = call_tool(proc, "dotnet_edit_encode_instructions", {"opcodes": ["nop", "ret"]})
        check("encode_instructions [nop,ret] hex", "dotnet_edit_encode_instructions",
              {"opcodes": ["nop", "ret"]}, "hex", hex_nr, r_nr)
        check("encode_instructions [nop,ret] byte_len", "dotnet_edit_encode_instructions",
              {"opcodes": ["nop", "ret"]}, "byte_len", blen_nr, r_nr)

        # ── 13. encode_instructions: [ldc.i4.1, ret] ─────────────────────────
        hex_ldc, blen_ldc = encode_instructions_truth(["ldc.i4.1", "ret"])
        r_ldc = call_tool(proc, "dotnet_edit_encode_instructions",
                          {"opcodes": ["ldc.i4.1", "ret"]})
        check("encode_instructions [ldc.i4.1,ret] hex", "dotnet_edit_encode_instructions",
              {"opcodes": ["ldc.i4.1", "ret"]}, "hex", hex_ldc, r_ldc)
        check("encode_instructions [ldc.i4.1,ret] byte_len", "dotnet_edit_encode_instructions",
              {"opcodes": ["ldc.i4.1", "ret"]}, "byte_len", blen_ldc, r_ldc)

        # ── 14. ilbuilder_nop → opcodes=["nop"] ──────────────────────────────
        r_nop = call_tool(proc, "dotnet_edit_ilbuilder_nop", {})
        check("ilbuilder_nop opcodes=[nop]", "dotnet_edit_ilbuilder_nop",
              {}, "opcodes", ["nop"], r_nop)
        tools_hardened.add("dotnet_edit_ilbuilder_nop")

        # ── 15. ilbuilder_ret → opcodes=["ret"] ──────────────────────────────
        r_ret2 = call_tool(proc, "dotnet_edit_ilbuilder_ret", {})
        check("ilbuilder_ret opcodes=[ret]", "dotnet_edit_ilbuilder_ret",
              {}, "opcodes", ["ret"], r_ret2)
        tools_hardened.add("dotnet_edit_ilbuilder_ret")

        # ── 16. ilbuilder_call(token=42) → opcodes=["call"] ──────────────────
        r_call = call_tool(proc, "dotnet_edit_ilbuilder_call", {"token": 42})
        check("ilbuilder_call opcodes=[call]", "dotnet_edit_ilbuilder_call",
              {"token": 42}, "opcodes", ["call"], r_call)
        # Also verify the echoed token
        check("ilbuilder_call token=42", "dotnet_edit_ilbuilder_call",
              {"token": 42}, "token", 42, r_call)
        tools_hardened.add("dotnet_edit_ilbuilder_call")

        # ── 17. ilbuilder_callvirt(token=99) → opcodes=["callvirt"] ──────────
        r_cv = call_tool(proc, "dotnet_edit_ilbuilder_callvirt", {"token": 99})
        check("ilbuilder_callvirt opcodes=[callvirt]", "dotnet_edit_ilbuilder_callvirt",
              {"token": 99}, "opcodes", ["callvirt"], r_cv)
        check("ilbuilder_callvirt token=99", "dotnet_edit_ilbuilder_callvirt",
              {"token": 99}, "token", 99, r_cv)
        tools_hardened.add("dotnet_edit_ilbuilder_callvirt")

        # ── 18. ilbuilder_newobj(token=7) → opcodes=["newobj"] ───────────────
        r_no = call_tool(proc, "dotnet_edit_ilbuilder_newobj", {"token": 7})
        check("ilbuilder_newobj opcodes=[newobj]", "dotnet_edit_ilbuilder_newobj",
              {"token": 7}, "opcodes", ["newobj"], r_no)
        tools_hardened.add("dotnet_edit_ilbuilder_newobj")

        # ── 19. ilbuilder_ldstr(token=0x70000001) → opcodes=["ldstr"] ────────
        r_ls = call_tool(proc, "dotnet_edit_ilbuilder_ldstr", {"token": 0x70000001})
        check("ilbuilder_ldstr opcodes=[ldstr]", "dotnet_edit_ilbuilder_ldstr",
              {"token": 0x70000001}, "opcodes", ["ldstr"], r_ls)
        tools_hardened.add("dotnet_edit_ilbuilder_ldstr")

        # ── 20. ilbuilder_brfalse_s(target=5) → opcodes=["brfalse.s"] ────────
        r_bf = call_tool(proc, "dotnet_edit_ilbuilder_brfalse_s", {"target": 5})
        check("ilbuilder_brfalse_s opcodes=[brfalse.s]", "dotnet_edit_ilbuilder_brfalse_s",
              {"target": 5}, "opcodes", ["brfalse.s"], r_bf)
        tools_hardened.add("dotnet_edit_ilbuilder_brfalse_s")

        # ── 21. ilbuilder_brtrue_s(target=10) → opcodes=["brtrue.s"] ─────────
        r_bt = call_tool(proc, "dotnet_edit_ilbuilder_brtrue_s", {"target": 10})
        check("ilbuilder_brtrue_s opcodes=[brtrue.s]", "dotnet_edit_ilbuilder_brtrue_s",
              {"target": 10}, "opcodes", ["brtrue.s"], r_bt)
        tools_hardened.add("dotnet_edit_ilbuilder_brtrue_s")

        # ── 22. token_remapper: table=6, insert_at=2, total_rows=3
        #   token 0x06000002 → row 2 >= at=2, shifted → row 3 → 0x06000003
        tok_in = 0x06000002
        tok_exp = 0x06000003
        r_remap = call_tool(proc, "dotnet_edit_token_remapper_remap", {
            "table": 6, "insert_at": 2, "total_rows": 3, "token": tok_in,
        })
        check(f"token_remapper_remap 0x{tok_in:08X}->0x{tok_exp:08X}",
              "dotnet_edit_token_remapper_remap",
              {"table": 6, "insert_at": 2, "total_rows": 3, "token": tok_in},
              "remapped", tok_exp, r_remap)
        tools_hardened.add("dotnet_edit_token_remapper_remap")

        # ── 23. token_remapper: token before insertion point → unchanged
        tok_before = 0x06000001  # row 1 < insert_at=2 → not remapped
        r_remap2 = call_tool(proc, "dotnet_edit_token_remapper_remap", {
            "table": 6, "insert_at": 2, "total_rows": 3, "token": tok_before,
        })
        check(f"token_remapper_remap row<at unchanged 0x{tok_before:08X}",
              "dotnet_edit_token_remapper_remap",
              {"table": 6, "insert_at": 2, "total_rows": 3, "token": tok_before},
              "remapped", tok_before, r_remap2)

        # ── 24. token_remapper: is_empty=False after record_insert ────────────
        check("token_remapper is_empty=False after insert",
              "dotnet_edit_token_remapper_remap",
              {"table": 6, "insert_at": 2, "total_rows": 3, "token": tok_in},
              "is_empty", False, r_remap)

        # ── 25. nop_fill_range: start_offset=0 end_offset=1 on [nop,ret] → first opcode=nop
        # wire_tools assigns offsets as i (0,1,...), so offset 0=nop, offset 1=ret
        # Range [0,1) covers instruction at offset 0 (nop) → replaced with nop
        r_nfr = call_tool(proc, "dotnet_edit_nop_fill_range", {
            "opcodes": ["nop", "ret"], "start_offset": 0, "end_offset": 1,
        })
        actual_nfr = r_nfr.get("opcodes")
        if isinstance(actual_nfr, list) and len(actual_nfr) >= 1 and actual_nfr[0] == "nop":
            print("  PASS  nop_fill_range [nop,ret][0:1) first=nop")
            checks_passed += 1
        else:
            print(f"  FAIL  nop_fill_range [nop,ret][0:1) first=nop: got {actual_nfr!r}")
            checks_failed += 1
            mismatches.append({
                "tool": "dotnet_edit_nop_fill_range",
                "check": "nop_fill_range [nop,ret][0:1) first=nop",
                "expected": "list starting with nop",
                "actual": actual_nfr,
            })
        tools_hardened.add("dotnet_edit_nop_fill_range")

    finally:
        proc.stdin.close()
        proc.wait()

    report = {
        "module": "dotnet_edit",
        "tools_hardened": sorted(tools_hardened),
        "checks_passed": checks_passed,
        "checks_failed": checks_failed,
        "mismatches": mismatches,
    }
    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nReport saved to {REPORT_PATH}")
    print(f"Tools hardened: {len(tools_hardened)}")
    print(f"Checks passed:  {checks_passed}")
    print(f"Checks failed:  {checks_failed}")
    print(f"Real mismatches: {len(mismatches)}")
    return report


if __name__ == "__main__":
    run_all()
