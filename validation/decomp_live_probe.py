"""
Live MCP decompiler probe for cargo-zyphora.exe.
Spawns rustre-mcp via stdio, sends JSON-RPC calls, captures results.
"""

import json
import subprocess
import sys
import time
import os
import re
from pathlib import Path

BINARY = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
SAMPLE = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_FILE = r"C:\Users\Fra\Desktop\RustRE\validation\decomp_live_probe_out.json"

def send_request(proc, req_id, method, params=None):
    msg = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    data = json.dumps(msg) + "\n"
    proc.stdin.write(data.encode())
    proc.stdin.flush()

def read_response(proc, timeout=60):
    start = time.time()
    buf = b""
    while time.time() - start < timeout:
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.05)
            continue
        buf += line
        try:
            return json.loads(buf.decode())
        except json.JSONDecodeError:
            continue
    return None

def send_notification(proc, method, params=None):
    msg = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    data = json.dumps(msg) + "\n"
    proc.stdin.write(data.encode())
    proc.stdin.flush()

def tool_call(proc, req_id, name, arguments, timeout=60):
    send_request(proc, req_id, "tools/call", {"name": name, "arguments": arguments})
    resp = read_response(proc, timeout=timeout)
    return resp

def get_text(resp):
    if resp and "result" in resp:
        content = resp["result"].get("content", [])
        if content:
            return content[0].get("text", "")
    return ""

def is_error_resp(resp):
    if resp and "result" in resp:
        if resp["result"].get("isError", False):
            return True
        text = get_text(resp)
        if text.startswith("execution failed"):
            return True
    if resp and "error" in resp:
        return True
    return False

def main():
    results = {
        "binary_built_ok": os.path.exists(BINARY),
        "server_started_ok": False,
        "project_open_ok": False,
        "functions_detected": 0,
        "decompile_calls_ok": 0,
        "decompile_calls_error": 0,
        "avg_decompile_ms": 0.0,
        "typed_vars": 0,
        "unknown_vars": 0,
        "c_output_sample": "",
        "quality_signals": {
            "has_types": False,
            "has_casts": False,
            "has_function_names": False,
            "has_control_flow": False,
        },
        "verdict": "BROKEN",
        "notes": "",
    }

    if not results["binary_built_ok"]:
        results["notes"] = f"Binary not found at {BINARY}"
        with open(OUT_FILE, "w") as f:
            json.dump(results, f, indent=2)
        print(json.dumps(results, indent=2))
        return

    proc = subprocess.Popen(
        [BINARY],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )

    try:
        results["server_started_ok"] = proc.poll() is None

        # 1. Initialize
        send_request(proc, 1, "initialize", {
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "probe", "version": "0.1"},
            "capabilities": {}
        })
        init_resp = read_response(proc, timeout=15)
        if init_resp is None or "error" in init_resp:
            results["notes"] = f"initialize failed: {init_resp}"
            with open(OUT_FILE, "w") as f:
                json.dump(results, f, indent=2)
            print(json.dumps(results, indent=2))
            return

        send_notification(proc, "notifications/initialized")

        # 2. project.open
        open_resp = tool_call(proc, 2, "project.open", {"path": SAMPLE}, timeout=30)
        binary_id = None
        project_id = None
        if open_resp and "result" in open_resp and not is_error_resp(open_resp):
            text = get_text(open_resp)
            try:
                data = json.loads(text)
                binary_id = data.get("binary_id")
                project_id = data.get("project_id")
                results["project_open_ok"] = data.get("status") == "loaded"
            except Exception:
                results["project_open_ok"] = bool(text) and not text.startswith("execution failed")

        if not binary_id:
            results["notes"] = f"project.open failed or no binary_id. open_resp={json.dumps(open_resp)[:200]}"
            with open(OUT_FILE, "w") as f:
                json.dump(results, f, indent=2)
            print(json.dumps(results, indent=2))
            return

        # 3. analyze.full to detect functions
        full_resp = tool_call(proc, 3, "analyze.full", {"binary_id": binary_id}, timeout=120)
        fn_count = 0
        if full_resp and "result" in full_resp:
            text = get_text(full_resp)
            try:
                data = json.loads(text)
                fn_count = data.get("functions_found", 0)
            except Exception:
                m = re.search(r'(\d+)\s+function', text, re.IGNORECASE)
                if m:
                    fn_count = int(m.group(1))
        results["functions_detected"] = fn_count

        # 4. Get function list for addresses to decompile
        list_resp = tool_call(proc, 4, "kg.list_functions", {"binary_id": binary_id}, timeout=30)
        addrs_to_decompile = []
        if list_resp and "result" in list_resp:
            text = get_text(list_resp)
            try:
                data = json.loads(text)
                fns = data.get("functions", [])
                addrs_to_decompile = [f["addr"] for f in fns[:8]]
            except Exception:
                addrs = re.findall(r'0x[0-9a-fA-F]{6,}', text)
                addrs_to_decompile = addrs[:8]

        if not addrs_to_decompile:
            # Fallback: known addresses from IDA baseline
            addrs_to_decompile = [
                "0x140001000", "0x140001350", "0x140002000",
                "0x140003000", "0x140004000", "0x140005000",
                "0x140006000", "0x140007000",
            ]

        # 5. analysis_fn_detect_functions_path (if available)
        afn_resp = tool_call(proc, 5, "analysis_fn_detect_functions_path",
                             {"path": SAMPLE}, timeout=60)
        if afn_resp and not is_error_resp(afn_resp):
            text = get_text(afn_resp)
            m = re.search(r'(\d+)', text)
            if m:
                count = int(m.group(1))
                if count > fn_count:
                    results["functions_detected"] = count

        # 6. decompiler_detect_functions (if available)
        ddf_resp = tool_call(proc, 6, "decompiler_detect_functions", {}, timeout=60)
        if ddf_resp and not is_error_resp(ddf_resp):
            text = get_text(ddf_resp)
            m = re.search(r'(\d+)', text)
            if m:
                count = int(m.group(1))
                if count > results["functions_detected"]:
                    results["functions_detected"] = count

        # 7. rustre_decompiler_load_binary_info (if available)
        info_resp = tool_call(proc, 7, "rustre_decompiler_load_binary_info", {}, timeout=30)

        # 8. Decompile 8 functions
        decompile_times = []
        all_c_output = []
        req_id = 10

        for addr in addrs_to_decompile[:8]:
            t0 = time.time()
            resp = tool_call(proc, req_id, "decompile.function",
                             {"binary_id": binary_id, "address": addr}, timeout=45)
            elapsed_ms = (time.time() - t0) * 1000

            if resp and not is_error_resp(resp):
                text = get_text(resp)
                try:
                    data = json.loads(text)
                    pseudo = data.get("pseudo_code", "")
                    if pseudo:
                        results["decompile_calls_ok"] += 1
                        decompile_times.append(elapsed_ms)
                        all_c_output.append(pseudo)
                    else:
                        results["decompile_calls_error"] += 1
                except Exception:
                    if text and len(text) > 20:
                        results["decompile_calls_ok"] += 1
                        decompile_times.append(elapsed_ms)
                        all_c_output.append(text)
                    else:
                        results["decompile_calls_error"] += 1
            else:
                results["decompile_calls_error"] += 1

            req_id += 1
            time.sleep(0.05)

        if decompile_times:
            results["avg_decompile_ms"] = sum(decompile_times) / len(decompile_times)

        # Analyze C output quality
        if all_c_output:
            combined = "\n".join(all_c_output)
            results["c_output_sample"] = all_c_output[0][:800]

            typed = len(re.findall(
                r'\b(uint64_t|uint32_t|uint16_t|uint8_t|int64_t|int32_t|int8_t|bool|char|void\s*\*|DWORD|QWORD|BYTE|WORD|__int64|size_t)\b',
                combined))
            unknown = len(re.findall(r'\b(UNKNOWN|unknown|\?\?\?|__unknown|undef)\b', combined, re.IGNORECASE))
            unresolved = len(re.findall(r'unresolved', combined, re.IGNORECASE))
            results["typed_vars"] = typed
            results["unknown_vars"] = unknown + unresolved

            qs = results["quality_signals"]
            qs["has_types"] = typed > 0
            qs["has_casts"] = bool(re.search(r'\([a-z_]+[\s\*]+\)', combined))
            qs["has_function_names"] = bool(re.search(r'sub_[0-9a-fA-F]+\s*\(', combined))
            qs["has_control_flow"] = bool(re.search(r'\b(if|while|for|switch)\b', combined))

        # Verdict
        ok = results["decompile_calls_ok"]
        err = results["decompile_calls_error"]
        total = ok + err
        if total == 0 or ok == 0:
            results["verdict"] = "BROKEN"
        elif ok >= total * 0.75:
            results["verdict"] = "WORKING"
        else:
            results["verdict"] = "PARTIAL"

        notes_parts = [
            f"functions_detected={results['functions_detected']}",
            f"decompile ok={ok}/{total}",
        ]
        if decompile_times:
            notes_parts.append(f"avg_ms={results['avg_decompile_ms']:.1f}")
        if results["unknown_vars"]:
            notes_parts.append(f"unresolved_exprs={results['unknown_vars']}")
        results["notes"] = "; ".join(notes_parts)

    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.kill()

    with open(OUT_FILE, "w") as f:
        json.dump(results, f, indent=2)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
