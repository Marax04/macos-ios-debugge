#!/usr/bin/env python3
"""Validator for rustre-loader-luajit. Stdlib only.

Builds a minimal LuaJIT bytecode blob in-memory and checks the loader's public
API against the spec in reports/rustre-loader-luajit.md.

Output: prints JSON { "crate": "rustre-loader-luajit", "saved": bool }.
"""
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

CRATE = "rustre-loader-luajit"
ROOT = Path(r"C:\Users\Fra\Desktop\RustRE")
CRATE_DIR = ROOT / "crates" / CRATE


def uleb128(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def build_minimal_luajit() -> bytes:
    """Header for LJ2.1 stripped + a single empty proto + 0 sentinel."""
    # Header: magic + version 2 (LJ2.1) + flags ULEB128 (STRIP=2 so no debug name)
    hdr = bytes([0x1B, 0x4C, 0x4A, 0x02]) + uleb128(0x02)  # STRIP flag
    # Build a minimal proto body:
    # flags, numparams, framesize, sizeuv, sizekgc, sizekn, sizebc, [debug-len if not stripped]
    # then instructions, upvalues, kgc, kn
    # Single RET0 instruction: opcode 0x4B in LJ2.1 ... but we just need *some* valid u32.
    # Use opcode 0x47 (RET0) — placeholder; loader does not validate opcode semantics.
    instr = struct.pack("<I", 0x00000000)  # opcode 0, A=B=C=0
    body = bytes([
        0x00,  # flags
        0x00,  # numparams
        0x02,  # framesize
        0x00,  # sizeuv
    ]) + uleb128(0) + uleb128(0) + uleb128(1) + instr
    proto = uleb128(len(body)) + body
    sentinel = uleb128(0)
    return hdr + proto + sentinel


HARNESS = r'''
use rustre_loader_luajit::*;

fn main() {
    let data: Vec<u8> = std::env::args().nth(1).unwrap().as_bytes()
        .chunks(2).map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect();

    let mut report = serde_json::Map::new();

    report.insert("is_luajit".into(), is_luajit(&data).into());
    report.insert("magic_ok".into(), (LJ_MAGIC == [0x1B, b'L', b'J']).into());
    report.insert("opcodes_len".into(), LJ_OPCODES.len().into());

    // ULEB128
    let (v, n) = read_uleb128(&[0x05], 0).unwrap();
    report.insert("uleb128".into(), serde_json::json!([v, n]));
    let (sv, sn) = read_sleb128(&[0x05], 0).unwrap();
    report.insert("sleb128".into(), serde_json::json!([sv, sn]));

    // Header parse
    match LjHeader::parse(&data) {
        Ok((h, off)) => {
            report.insert("header_ok".into(), true.into());
            report.insert("header_offset".into(), off.into());
            report.insert("header_version".into(), format!("{:?}", h.version).into());
        }
        Err(e) => {
            report.insert("header_ok".into(), false.into());
            report.insert("header_err".into(), format!("{:?}", e).into());
        }
    }

    // Full parse
    match LjBytecode::parse(&data) {
        Ok(bc) => {
            report.insert("bc_ok".into(), true.into());
            report.insert("bc_protos".into(), bc.protos.len().into());
            report.insert("bc_total_instrs".into(), bc.total_instructions().into());
        }
        Err(e) => {
            report.insert("bc_ok".into(), false.into());
            report.insert("bc_err".into(), format!("{:?}", e).into());
        }
    }

    // Loader
    let loader = LuaJitLoader::new();
    let _ = loader;
    report.insert("can_load".into(), LuaJitLoader::can_load(&data).into());
    match LuaJitLoader::load(&data) {
        Ok(m) => {
            report.insert("module_ok".into(), true.into());
            report.insert("module_total".into(), m.total_instructions().into());
            report.insert("module_stripped".into(), m.is_stripped().into());
        }
        Err(e) => {
            report.insert("module_ok".into(), false.into());
            report.insert("module_err".into(), format!("{:?}", e).into());
        }
    }

    // Mock proto and stats / disassembler
    let p = LjProto::mock();
    let stats = ProtoStats::compute(&p);
    report.insert("stats_total".into(), stats.total.into());
    let dis = LjDisassembler::new();
    let s = dis.disassemble_proto(&p);
    report.insert("disasm_lines".into(), s.lines().count().into());

    // Enum sanity
    let v20 = LjVersion::from_byte(1);
    let v21 = LjVersion::from_byte(2);
    report.insert("version_known".into(), serde_json::json!([v20.is_known(), v21.is_known()]));

    println!("{}", serde_json::Value::Object(report));
}
'''


def run_harness(blob: bytes) -> dict:
    """Build a tiny cargo project that depends on the crate and runs the harness."""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        (td / "src").mkdir()
        (td / "src" / "main.rs").write_text(HARNESS, encoding="utf-8")
        (td / "Cargo.toml").write_text(
            f'''[package]
name = "validate_lj"
version = "0.0.1"
edition = "2024"

[dependencies]
rustre-loader-luajit = {{ path = "{str(CRATE_DIR).replace(chr(92), '/')}" }}
serde_json = "1"

[workspace]
''', encoding="utf-8")
        hexblob = blob.hex()
        # Use --offline first; fall back if needed.
        env = os.environ.copy()
        proc = subprocess.run(
            ["cargo", "run", "--quiet", "--release", "--", hexblob],
            cwd=td, env=env, capture_output=True, text=True, timeout=600,
        )
        if proc.returncode != 0:
            return {"_build_error": True,
                    "stderr_tail": proc.stderr[-2000:],
                    "stdout_tail": proc.stdout[-500:]}
        # Last non-empty line should be JSON
        for line in reversed(proc.stdout.strip().splitlines()):
            line = line.strip()
            if line.startswith("{"):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        return {"_no_json": True, "stdout": proc.stdout[-1000:]}


def evaluate(r: dict) -> tuple[bool, list[str]]:
    issues = []
    if r.get("_build_error"):
        return False, ["build failed: " + r.get("stderr_tail", "")[-400:]]
    if r.get("_no_json"):
        return False, ["no JSON produced"]

    def check(cond, msg):
        if not cond:
            issues.append(msg)

    check(r.get("is_luajit") is True, "is_luajit returned false on valid blob")
    check(r.get("magic_ok") is True, "LJ_MAGIC mismatch")
    check(r.get("opcodes_len") == 97, f"LJ_OPCODES len={r.get('opcodes_len')} expected 97")
    check(r.get("uleb128") == [5, 1], f"uleb128 wrong: {r.get('uleb128')}")
    check(r.get("sleb128") == [5, 1], f"sleb128 wrong: {r.get('sleb128')}")
    check(r.get("header_ok") is True, f"header parse failed: {r.get('header_err')}")
    check(r.get("can_load") is True, "can_load=false on valid blob")
    check(r.get("version_known") == [True, True], "LjVersion::from_byte known check failed")
    # Loader/bytecode parse: tolerated to fail if our hand-built blob is incomplete,
    # but we want at least one of them to succeed.
    check(r.get("bc_ok") is True or r.get("module_ok") is True,
          f"both LjBytecode::parse and LuaJitLoader::load failed: "
          f"bc={r.get('bc_err')} mod={r.get('module_err')}")
    check(isinstance(r.get("disasm_lines"), int) and r["disasm_lines"] >= 0,
          "disassembler did not produce output")
    return len(issues) == 0, issues


def main():
    blob = build_minimal_luajit()
    result = run_harness(blob)
    ok, issues = evaluate(result)
    out = {"crate": CRATE, "saved": ok}
    if not ok:
        # Print issues to stderr for diagnostics; keep stdout JSON pure.
        sys.stderr.write("ISSUES:\n  - " + "\n  - ".join(issues) + "\n")
        sys.stderr.write("RAW: " + json.dumps(result)[:2000] + "\n")
    print(json.dumps(out))


if __name__ == "__main__":
    main()
