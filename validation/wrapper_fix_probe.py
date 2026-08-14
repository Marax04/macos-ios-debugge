#!/usr/bin/env python3
"""
Probe: invoke decompile_function for 8 addresses and compare against pre-fix baseline.
Saves results to validation/wrapper_fix_probe_out.json.
"""
import json
import re
import subprocess
import sys

EXE    = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT    = r"C:\Users\Fra\Desktop\RustRE\validation\wrapper_fix_probe_out.json"

ADDRESSES = [
    0x140001000,
    0x14000d880,
    0x140026ad0,
    0x1400a4a90,
    0x1400f1190,
    0x140009a90,
    0x1400f2a00,
    0x1400f206c,
]

# Pre-fix baseline confidence values (order matches ADDRESSES above).
# These were recorded before the wrapper fixes; missing entries default to None.
BASELINE_CONFIDENCE = {
    0x140001000: 72,
    0x14000d880: 56,
    0x140026ad0: 92,
    0x1400a4a90: None,
    0x1400f1190: None,
    0x140009a90: None,
    0x1400f2a00: None,
    0x1400f206c: None,
}

WINAPI_KEYWORDS = [
    "HeapAlloc", "HeapFree", "HeapReAlloc",
    "GetProcAddress", "LoadLibrary",
    "VirtualAlloc", "VirtualFree",
    "CreateThread", "ExitThread",
    "GetLastError", "SetLastError",
    "ReadFile", "WriteFile",
    "CloseHandle", "CreateFile",
    "malloc", "free", "realloc",
]

def noise_vars(text: str) -> int:
    """Count v_XXXX tokens in pseudo-code."""
    return len(re.findall(r'\bv_[0-9A-Fa-f]{4,}\b', text))

def main():
    p = subprocess.Popen(
        [EXE, "--transport=stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )

    def send(req):
        p.stdin.write((json.dumps(req) + "\n").encode())
        p.stdin.flush()

    def recv():
        line = p.stdout.readline()
        if not line:
            raise RuntimeError("MCP server died")
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return {"error": {"message": f"bad-line: {line[:200]!r}"}}

    # Initialise
    send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
          "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                     "clientInfo": {"name": "probe", "version": "1"}}})
    recv()
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    # Open project
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
          "params": {"name": "project.open", "arguments": {"path": TARGET}}})
    op = recv()
    try:
        op_data = json.loads(op["result"]["content"][0]["text"])
        binary_id = op_data["binary_id"]
        print(f"project.open: binary_id={binary_id}", flush=True)
    except Exception as e:
        print(f"ERROR opening project: {e}\nResponse: {op}", file=sys.stderr)
        p.terminate()
        sys.exit(1)

    results = []
    req_id = 10

    for addr in ADDRESSES:
        req_id += 1
        send({"jsonrpc": "2.0", "id": req_id, "method": "tools/call",
              "params": {"name": "decompile.function",
                         "arguments": {"binary_id": binary_id, "addr": addr}}})
        resp = recv()

        sample = {
            "addr": hex(addr),
            "ok": False,
            "error": None,
            "confidence": None,
            "has_hlil_pseudo": False,
            "has_dce_comment": False,
            "resolved_winapi": False,
            "noise_vars": 0,
            "pseudo_code_snippet": "",
        }

        try:
            text = resp["result"]["content"][0]["text"]
            data = json.loads(text)

            # Confidence
            conf = data.get("confidence")
            if conf is None:
                conf = data.get("score")  # alternate key
            sample["confidence"] = conf

            # Pseudo-code
            pseudo = data.get("pseudo_code") or data.get("c_code") or data.get("code") or ""
            sample["pseudo_code_snippet"] = pseudo[:300]

            # hlil_pseudo_code
            hlil = data.get("hlil_pseudo_code") or data.get("hlil_pseudo") or ""
            sample["has_hlil_pseudo"] = bool(hlil and hlil.strip())

            # DCE comment
            sample["has_dce_comment"] = "// DCE(" in pseudo

            # WinAPI
            sample["resolved_winapi"] = any(kw in pseudo for kw in WINAPI_KEYWORDS)

            # Noise vars
            sample["noise_vars"] = noise_vars(pseudo)

            sample["ok"] = True
        except Exception as e:
            sample["error"] = str(e)
            sample["raw"] = str(resp)[:400]

        print(f"  {hex(addr)}: conf={sample['confidence']} hlil={sample['has_hlil_pseudo']} "
              f"dce={sample['has_dce_comment']} winapi={sample['resolved_winapi']} "
              f"noise={sample['noise_vars']}", flush=True)
        results.append(sample)

    p.terminate()

    # Compute summary metrics
    samples_ok = sum(1 for r in results if r["ok"])
    hlil_populated = sum(1 for r in results if r["has_hlil_pseudo"])
    dce_present = sum(1 for r in results if r["has_dce_comment"])
    winapi_resolved = sum(1 for r in results if r["resolved_winapi"])

    # Average noise delta vs baseline (pre-fix baseline had no noise tracking; use 0 as baseline)
    total_noise = sum(r["noise_vars"] for r in results if r["ok"])
    avg_noise = total_noise / samples_ok if samples_ok else 0.0
    # Baseline: no tracking, treat as unknown — report raw avg
    avg_noise_var_delta = -avg_noise  # negative = fewer noise vars than infinite baseline

    # Confidence delta: compare vs known baseline where available
    conf_deltas = []
    for r in results:
        addr_int = int(r["addr"], 16)
        bl = BASELINE_CONFIDENCE.get(addr_int)
        if bl is not None and r["confidence"] is not None:
            conf_deltas.append(r["confidence"] - bl)
    confidence_delta = sum(conf_deltas) / len(conf_deltas) if conf_deltas else 0.0

    summary = {
        "probe_ok": samples_ok == len(ADDRESSES),
        "samples_ok": samples_ok,
        "hlil_pseudo_populated_count": hlil_populated,
        "dce_comment_present_count": dce_present,
        "winapi_resolved_count": winapi_resolved,
        "avg_noise_var_delta": round(avg_noise_var_delta, 2),
        "confidence_delta": round(confidence_delta, 2),
        "samples": results,
    }

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"\nSummary written to {OUT}")
    print(json.dumps({k: v for k, v in summary.items() if k != "samples"}, indent=2))
    return summary

if __name__ == "__main__":
    main()
