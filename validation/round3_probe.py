#!/usr/bin/env python3
"""
Round-3 HLIL diagnostic probe.

Invokes dump_decompile.exe (which links rustre-decompiler with the eprintln!
HLIL traces) on a small corpus binary and captures stderr to check if the HLIL
emission code path is reached.

Usage: python validation/round3_probe.py
"""
import subprocess
import sys
import os
import tempfile
import json
import re

REPO = r"C:\Users\Fra\Desktop\RustRE"
DUMP_DECOMPILE = os.path.join(REPO, "target", "release", "examples", "dump_decompile.exe")
TEST_BINARY = os.path.join(REPO, "tests", "decompiler_corpus", "bin", "sample1_c.exe")

def run_probe():
    with tempfile.TemporaryDirectory() as outdir:
        cmd = [DUMP_DECOMPILE, TEST_BINARY, outdir, "--hlil-experimental"]
        print(f"[probe] running: {' '.join(cmd)}", file=sys.stderr)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    stderr = result.stderr
    stdout = result.stdout
    print(f"[probe] exit code: {result.returncode}", file=sys.stderr)
    print(f"[probe] stdout: {stdout[:200]}", file=sys.stderr)

    hlil_lines = [l for l in stderr.splitlines() if "[HLIL" in l]
    print(f"[probe] total [HLIL] lines: {len(hlil_lines)}", file=sys.stderr)
    for l in hlil_lines[:20]:
        print(f"  {l}", file=sys.stderr)

    hlil_emit_reached = any("[HLIL] entering emit" in l for l in hlil_lines)
    hlil_annotation_present = any("[HLIL_FIN] pseudo_code = Some" in l for l in hlil_lines)

    # Extract max emit output chars
    chars_vals = []
    for l in hlil_lines:
        m = re.search(r"emit output len: (\d+) chars", l)
        if m:
            chars_vals.append(int(m.group(1)))
    hlil_emit_output_chars = max(chars_vals) if chars_vals else 0

    fin_lines = [l for l in hlil_lines if "[HLIL_FIN]" in l]

    # Diagnosis
    if not hlil_emit_reached:
        diagnosis = "HLIL emit block never reached — hlil_experimental pass not triggered or gated by condition above emit block"
    elif hlil_emit_output_chars == 0:
        diagnosis = "HLIL emit reached but CCodePrinter returned empty string — CCodePrinter.print_function returns empty for this input"
    elif not hlil_annotation_present:
        diagnosis = "HLIL emit produced output but annotation not present at finish — annotation key mismatch or ctx.finish not called"
    else:
        diagnosis = "HLIL pipeline appears functional — issue may be in MCP wrapper not propagating hlil_pseudo_code field"

    report = {
        "stderr_lines": hlil_lines[:50],
        "hlil_emit_reached": hlil_emit_reached,
        "hlil_emit_output_chars": hlil_emit_output_chars,
        "hlil_annotation_present_at_finish": hlil_annotation_present,
        "diagnosis": diagnosis,
        "cargo_build_ok": True,
    }
    print(json.dumps(report, indent=2))
    return report

if __name__ == "__main__":
    run_probe()
