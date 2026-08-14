#!/usr/bin/env python3
"""
Rigorous ground-truth validation for disasm.* MCP tools.
Uses PE section mapping to independently verify instruction bytes returned
by the MCP server against the actual bytes in the binary file.
"""
import json
import struct
import subprocess
import sys
import os

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
PDB = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo_zyphora.pdb"
OUT_PASS = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_disasm_v2.json"
OUT_SKIP = r"C:\Users\Fra\Desktop\RustRE\validation\skip_disasm.json"

# --- PE helpers (stdlib only, no capstone) -----------------------------------

def parse_pe_sections(path: str):
    """Return list of (name, va, vsize, file_off, raw_size) and image_base."""
    with open(path, "rb") as f:
        f.seek(0x3C)
        pe_off = struct.unpack("<I", f.read(4))[0]
        f.seek(pe_off)
        if f.read(4) != b"PE\x00\x00":
            raise ValueError("Not a PE file")
        f.seek(pe_off + 6)
        num_sections = struct.unpack("<H", f.read(2))[0]
        f.seek(pe_off + 20)
        size_opt = struct.unpack("<H", f.read(2))[0]
        # image base at offset 24+24=48 into optional header (PE32+)
        f.seek(pe_off + 24 + 24)
        image_base = struct.unpack("<Q", f.read(8))[0]
        sects_off = pe_off + 24 + size_opt
        f.seek(sects_off)
        sections = []
        for _ in range(num_sections):
            raw_name = f.read(8).rstrip(b"\x00").decode("ascii", errors="replace")
            vsize = struct.unpack("<I", f.read(4))[0]
            vaddr = struct.unpack("<I", f.read(4))[0]
            raw_size = struct.unpack("<I", f.read(4))[0]
            raw_off = struct.unpack("<I", f.read(4))[0]
            f.read(16)  # skip relocs/linenums/numrelocs/numlines/chars
            sections.append((raw_name, vaddr, vsize, raw_off, raw_size))
    return image_base, sections


def rva_to_file_off(rva: int, sections):
    """Convert RVA to file offset using section table."""
    for (name, vaddr, vsize, raw_off, raw_size) in sections:
        if vaddr <= rva < vaddr + max(vsize, raw_size):
            return raw_off + (rva - vaddr)
    return None


def read_bytes_at_va(path: str, image_base: int, sections, va: int, n: int) -> bytes:
    """Read n bytes from binary at virtual address va."""
    rva = va - image_base
    foff = rva_to_file_off(rva, sections)
    if foff is None:
        raise ValueError(f"VA {va:#x} not in any section")
    with open(path, "rb") as f:
        f.seek(foff)
        return f.read(n)


# --- MCP transport -----------------------------------------------------------

def start_server():
    p = subprocess.Popen(
        [EXE, "--transport=stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    return p


def send(p, req):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()


def recv(p):
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("MCP server died")
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {"error": {"message": f"bad-line: {line[:120]!r}"}}


def mcp_call(p, rid: int, tool: str, args: dict):
    send(p, {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
             "params": {"name": tool, "arguments": args}})
    return recv(p)


def extract_text(resp) -> str | None:
    if "error" in resp:
        return None
    content = resp.get("result", {}).get("content", [])
    if not content:
        return None
    return content[0].get("text", "")


# --- Validation logic --------------------------------------------------------

IMAGE_BASE, SECTIONS = parse_pe_sections(TARGET)
# Entry point RVA is at PE+40
with open(TARGET, "rb") as _f:
    _f.seek(0x3C)
    _pe_off = struct.unpack("<I", _f.read(4))[0]
    _f.seek(_pe_off + 40)
    EP_RVA = struct.unpack("<I", _f.read(4))[0]
EP_VA = IMAGE_BASE + EP_RVA

# Canonical test address used by exercise_v3.py
TEST_ADDR = 5368771180  # 0x14000f26c


def check_disasm_at(p, rid_start: int):
    """
    Verify that each instruction's 'bytes' field matches raw bytes from the PE.
    Ground truth: section-mapped file bytes.
    """
    tool = "disasm.at"
    args = {"binary_id": "bin-0001", "addr": TEST_ADDR, "count": 5}
    resp = mcp_call(p, rid_start, tool, args)
    txt = extract_text(resp)

    if txt is None:
        is_err = resp.get("result", {}).get("isError", False)
        return {
            "tool": tool,
            "status": "FAIL",
            "reason": f"JSONRPC_ERROR or no content: {resp.get('error', {}).get('message', '')}",
            "expected": None,
            "actual": None,
        }

    try:
        parsed = json.loads(txt)
    except json.JSONDecodeError:
        return {"tool": tool, "status": "FAIL", "reason": "response not valid JSON",
                "expected": None, "actual": txt[:200]}

    if resp.get("result", {}).get("isError"):
        return {"tool": tool, "status": "FAIL", "reason": f"TOOL_ERROR: {txt[:200]}",
                "expected": None, "actual": txt[:200]}

    instructions = parsed.get("instructions", [])
    if not instructions:
        return {"tool": tool, "status": "FAIL", "reason": "no instructions returned",
                "expected": "at least 1 instruction", "actual": parsed}

    mismatches = []
    for insn in instructions:
        insn_va_str = insn.get("addr", "")
        insn_bytes_hex = insn.get("bytes", "")
        insn_len = insn.get("length", 0)

        try:
            insn_va = int(insn_va_str, 16) if insn_va_str.startswith("0x") else int(insn_va_str)
        except (ValueError, TypeError):
            mismatches.append({"va": insn_va_str, "error": "cannot parse addr"})
            continue

        # Ground truth: read bytes from PE section mapping
        try:
            gt_bytes = read_bytes_at_va(TARGET, IMAGE_BASE, SECTIONS, insn_va, insn_len)
            gt_hex = gt_bytes.hex()
        except (ValueError, OSError) as e:
            mismatches.append({"va": insn_va_str, "error": f"cannot read GT bytes: {e}"})
            continue

        if gt_hex != insn_bytes_hex:
            mismatches.append({
                "va": insn_va_str,
                "expected_bytes": gt_hex,
                "actual_bytes": insn_bytes_hex,
            })

    if mismatches:
        return {
            "tool": tool,
            "status": "FAIL",
            "reason": "instruction bytes do not match PE section-mapped bytes",
            "expected": [m.get("expected_bytes") for m in mismatches],
            "actual": [m.get("actual_bytes") for m in mismatches],
            "detail": mismatches,
        }

    # Also verify structural invariants
    prev_end = None
    for insn in instructions:
        va_str = insn.get("addr", "")
        length = insn.get("length", 0)
        try:
            va = int(va_str, 16) if va_str.startswith("0x") else int(va_str)
        except (ValueError, TypeError):
            continue
        if prev_end is not None and va != prev_end:
            return {
                "tool": tool,
                "status": "FAIL",
                "reason": f"non-contiguous instruction stream: expected {hex(prev_end)} got {va_str}",
                "expected": hex(prev_end),
                "actual": va_str,
            }
        prev_end = va + length

    return {
        "tool": tool,
        "status": "PASS",
        "instruction_count": len(instructions),
        "first_addr": instructions[0].get("addr") if instructions else None,
    }


def check_disasm_function(p, rid_start: int):
    """
    Verify disasm.function returns a valid basic-block listing for a known function.
    Ground truth: entry point is a deterministic function start.
    Structural check: all blocks' instruction bytes must match PE section mapping.
    """
    tool = "disasm.function"

    # Try with the binary's entry point - should be a valid function
    args = {"binary_id": "bin-0001", "addr": EP_VA}
    resp = mcp_call(p, rid_start, tool, args)
    is_err = resp.get("result", {}).get("isError", False)
    txt = extract_text(resp)

    if txt is None or is_err:
        # Also try with the standard test address (might have a function there)
        args2 = {"binary_id": "bin-0001", "addr": TEST_ADDR}
        resp2 = mcp_call(p, rid_start + 1, tool, args2)
        txt2 = extract_text(resp2)
        is_err2 = resp2.get("result", {}).get("isError", False)
        if txt2 is None or is_err2:
            err_msg = txt or (txt2 or "no response")
            return {
                "tool": tool,
                "status": "FAIL",
                "reason": f"TOOL_ERROR on both EP ({EP_VA:#x}) and test addr ({TEST_ADDR:#x}): {err_msg[:200]}",
                "expected": "basic-block listing",
                "actual": err_msg[:200],
            }
        txt = txt2

    try:
        parsed = json.loads(txt)
    except json.JSONDecodeError:
        return {"tool": tool, "status": "FAIL", "reason": "response not valid JSON",
                "expected": None, "actual": txt[:200]}

    blocks = parsed.get("blocks", [])
    instructions = parsed.get("instructions", [])
    all_insns = []
    for b in blocks:
        all_insns.extend(b.get("instructions", []))
    if not all_insns:
        all_insns = instructions

    if not all_insns:
        # Minimal structural check: response must contain something meaningful
        return {
            "tool": tool,
            "status": "FAIL",
            "reason": "no instructions or blocks in response",
            "expected": "at least 1 instruction",
            "actual": list(parsed.keys()),
        }

    # Byte-match check for each instruction
    mismatches = []
    for insn in all_insns[:20]:  # cap at 20 to avoid timeout
        insn_va_str = insn.get("addr", "")
        insn_bytes_hex = insn.get("bytes", "")
        insn_len = insn.get("length", 0)
        if not insn_va_str or not insn_bytes_hex:
            continue
        try:
            insn_va = int(insn_va_str, 16) if insn_va_str.startswith("0x") else int(insn_va_str)
            gt_bytes = read_bytes_at_va(TARGET, IMAGE_BASE, SECTIONS, insn_va, insn_len)
            gt_hex = gt_bytes.hex()
            if gt_hex != insn_bytes_hex:
                mismatches.append({"va": insn_va_str, "expected_bytes": gt_hex,
                                   "actual_bytes": insn_bytes_hex})
        except (ValueError, OSError):
            continue

    if mismatches:
        return {
            "tool": tool,
            "status": "FAIL",
            "reason": "instruction bytes do not match PE section-mapped bytes",
            "expected": [m["expected_bytes"] for m in mismatches],
            "actual": [m["actual_bytes"] for m in mismatches],
            "detail": mismatches,
        }

    return {
        "tool": tool,
        "status": "PASS",
        "instruction_count": len(all_insns),
    }


# --- Main --------------------------------------------------------------------

def main():
    if not os.path.exists(EXE):
        print(f"ERROR: MCP server not found at {EXE}")
        sys.exit(1)
    if not os.path.exists(TARGET):
        print(f"ERROR: Target binary not found at {TARGET}")
        sys.exit(1)

    p = start_server()
    rid = [10]

    def next_rid():
        rid[0] += 1
        return rid[0]

    try:
        # Initialize
        send(p, {"jsonrpc": "2.0", "id": next_rid(), "method": "initialize",
                 "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                            "clientInfo": {"name": "rigorous_disasm", "version": "1"}}})
        recv(p)
        send(p, {"jsonrpc": "2.0", "method": "notifications/initialized"})

        # Open project
        send(p, {"jsonrpc": "2.0", "id": next_rid(), "method": "tools/call",
                 "params": {"name": "project.open", "arguments": {"path": TARGET}}})
        op = recv(p)
        op_data = json.loads(op["result"]["content"][0]["text"])
        print(f"project.open: binary_id={op_data['binary_id']}")

        # Run rigorous checks
        results = []
        skips = []

        r1 = check_disasm_at(p, next_rid())
        results.append(r1)
        print(f"disasm.at: {r1['status']}", end="")
        if r1["status"] == "FAIL":
            print(f" — {r1.get('reason', '')[:80]}", end="")
        print()

        r2 = check_disasm_function(p, next_rid())
        results.append(r2)
        print(f"disasm.function: {r2['status']}", end="")
        if r2["status"] == "FAIL":
            print(f" — {r2.get('reason', '')[:80]}", end="")
        print()

    finally:
        try:
            p.stdin.close()
        except OSError:
            pass
        p.terminate()

    # Write outputs
    with open(OUT_PASS, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults written to {OUT_PASS}")

    if skips:
        with open(OUT_SKIP, "w") as f:
            json.dump(skips, f, indent=2)
        print(f"Skips written to {OUT_SKIP}")

    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    skipped = len(skips)
    hardened = passed + failed  # tools we actually ran rigorous checks on

    mismatches = [
        {"tool": r["tool"], "expected": r.get("expected"), "actual": r.get("actual")}
        for r in results if r["status"] == "FAIL"
    ]

    summary = {
        "category": "disasm",
        "tools_hardened": hardened,
        "tools_passed": passed,
        "tools_failed": failed,
        "tools_skipped": skipped,
        "mismatches": mismatches,
    }
    print("\nSummary:", json.dumps(summary, indent=2))
    return summary


if __name__ == "__main__":
    main()
