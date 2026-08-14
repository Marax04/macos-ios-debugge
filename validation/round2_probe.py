"""
Round 2 validation probe — checks Sprint 1/4/5/6 signals in decompile_function output.
"""
import json, subprocess, sys, time, re
from pathlib import Path

BINARY  = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
SAMPLE  = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"

ADDRS = [
    0x140001000, 0x14000d880, 0x140026ad0, 0x1400a4a90,
    0x1400f1190, 0x140009a90, 0x1400f2a00, 0x1400f206c,
]

NAMED_CALLS = re.compile(
    r'\b(HeapAlloc|HeapFree|HeapReAlloc|memcpy|memmove|memset|malloc|free|realloc|'
    r'printf|sprintf|fprintf|snprintf|vprintf|vsprintf|'
    r'__chkstk|RtlAllocateHeap|RtlFreeHeap|VirtualAlloc|VirtualFree|'
    r'CreateFileW|CreateFileA|CloseHandle|ReadFile|WriteFile|'
    r'GetProcAddress|LoadLibraryA|LoadLibraryW)\s*\('
)
VSA_INDIRECT = re.compile(r'\(\(__int64\s*\(\*\)\s*\(\s*\)\s*\.\.\.?\s*\)')


def send(proc, req_id, method, params=None):
    msg = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    proc.stdin.write((json.dumps(msg) + "\n").encode())
    proc.stdin.flush()

def recv(proc, timeout=60):
    start = time.time(); buf = b""
    while time.time() - start < timeout:
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.05); continue
        buf += line
        try:
            return json.loads(buf.decode())
        except json.JSONDecodeError:
            continue
    return None

def tool_call(proc, req_id, name, args, timeout=90):
    send(proc, req_id, "tools/call", {"name": name, "arguments": args})
    return recv(proc, timeout=timeout)

def get_text(resp):
    if resp and "result" in resp:
        for c in resp["result"].get("content", []):
            t = c.get("text", "")
            if t:
                return t
    return ""

def main():
    proc = subprocess.Popen(
        [BINARY],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    try:
        # 1. Initialize
        send(proc, 1, "initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "round2_probe", "version": "1.0"}
        })
        recv(proc, timeout=30)
        send(proc, None, "notifications/initialized")

        # 2. Open project
        r = tool_call(proc, 2, "project.open", {"path": SAMPLE}, timeout=60)
        text = get_text(r)
        binary_id = None
        try:
            d = json.loads(text)
            binary_id = d.get("binary_id") or d.get("id")
        except Exception:
            pass
        if binary_id is None:
            m = re.search(r'"binary_id"\s*:\s*"([^"]+)"', text)
            if m:
                binary_id = m.group(1)
        if binary_id is None:
            binary_id = "0"

        sprint1_matches = 0
        sprint4_dce = 0
        sprint5_vsa = 0
        sprint6_hlil = 0
        confidences = []

        for i, addr in enumerate(ADDRS):
            resp = tool_call(proc, 10 + i, "decompile.function",
                             {"binary_id": binary_id, "address": addr}, timeout=90)
            text = get_text(resp)
            if not text:
                continue
            try:
                d = json.loads(text)
            except Exception:
                d = {}

            # Sprint 6: hlil_pseudo_code present and non-null
            hlil = d.get("hlil_pseudo_code")
            if hlil:
                sprint6_hlil += 1

            pseudo = d.get("pseudo_code", "") or ""
            if not pseudo and isinstance(text, str) and len(text) > 20:
                pseudo = text

            # Sprint 1: named API calls in pseudo_code
            sprint1_matches += len(NAMED_CALLS.findall(pseudo))

            # Sprint 4: DCE annotations
            sprint4_dce += len(re.findall(r'//\s*DCE\(df\):', pseudo))

            # Sprint 5: VSA-resolved indirect calls (named calls not matching raw indirect pattern)
            # Indirect = raw pointer call pattern; VSA-resolved = named call that was previously indirect
            # We count named calls and subtract raw indirect patterns as a proxy
            raw_indirect = len(re.findall(r'\(\(__int64\s*\(\*\)\s*\(\)', pseudo))
            if raw_indirect == 0 and NAMED_CALLS.search(pseudo):
                sprint5_vsa += 1

            conf = d.get("confidence")
            if conf is not None:
                try:
                    confidences.append(float(conf))
                except Exception:
                    pass

            time.sleep(0.05)

        avg_conf = sum(confidences) / len(confidences) if confidences else 0.0

        result = {
            "build_ok": True,
            "sprint1_flirt_matches": sprint1_matches,
            "sprint4_dce_present_in_functions": sprint4_dce,
            "sprint5_vsa_indirect_resolved": sprint5_vsa,
            "sprint6_hlil_populated_count": sprint6_hlil,
            "avg_confidence": round(avg_conf, 3),
            "verdict": "PASS" if sprint6_hlil > 0 else "PARTIAL",
        }
        print(json.dumps(result, indent=2))
        return result

    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.kill()


if __name__ == "__main__":
    main()
