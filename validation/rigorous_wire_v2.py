#!/usr/bin/env python3
"""
Rigorous ground-truth validation for wire_* MCP tools.
Each tool is called via JSON-RPC over stdio; results are compared
against an independent Python reference implementation.
"""
import json, subprocess, sys, time

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_JSON  = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_wire_v2.json"
SKIP_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\skip_wire.json"

# ── Python reference implementations ─────────────────────────────────────────

def ref_bytes_len(hex_str: str) -> int:
    """len(bytes.fromhex(hex_str))"""
    return len(bytes.fromhex(hex_str))

def ref_bytes_hex_encode(hex_str: str) -> str:
    """Round-trip: decode then re-encode lower-case hex."""
    return bytes.fromhex(hex_str).hex()

def ref_echo_string(text: str) -> str:
    return text

def ref_string_len(text: str) -> int:
    """UTF-8 byte length (same as Rust str.len())."""
    return len(text.encode("utf-8"))

# ── MCP subprocess helpers ────────────────────────────────────────────────────

p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL, bufsize=0,
)

def send(req):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()

def recv():
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("server died")
    return json.loads(line)

# Initialise
send({"jsonrpc":"2.0","id":1,"method":"initialize",
      "params":{"protocolVersion":"2024-11-05","capabilities":{},
                "clientInfo":{"name":"rigorous_wire","version":"2"}}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

# Open project (required by server before any tool call)
send({"jsonrpc":"2.0","id":2,"method":"tools/call",
      "params":{"name":"project.open","arguments":{"path":TARGET}}})
recv()  # we don't need the IDs for wire_ tools

_rid = 100
def call_tool(name, arguments):
    global _rid
    _rid += 1
    send({"jsonrpc":"2.0","id":_rid,"method":"tools/call",
          "params":{"name":name,"arguments":arguments}})
    resp = recv()
    if "error" in resp:
        return None, f"JSONRPC_ERROR: {resp['error']}"
    content = resp.get("result", {}).get("content", [])
    txt = content[0].get("text", "") if content else ""
    if resp.get("result", {}).get("isError"):
        return None, f"TOOL_ERROR: {txt}"
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None

# ── Test cases ────────────────────────────────────────────────────────────────

TEST_HEX   = "deadbeef00112233"
TEST_TEXT  = "hello, 世界"   # mix of ASCII and multibyte UTF-8

results = []
skips   = []
mismatches = []

# --- wire_bytes_len ---
expected = ref_bytes_len(TEST_HEX)
data, err = call_tool("wire_bytes_len", {"hex": TEST_HEX})
if err:
    results.append({"tool":"wire_bytes_len","status":"FAIL","reason":err})
    mismatches.append({"tool":"wire_bytes_len","expected":expected,"actual":err})
elif data is None or data.get("len") != expected:
    actual = data.get("len") if data else None
    results.append({"tool":"wire_bytes_len","status":"FAIL",
                    "expected":expected,"actual":actual})
    mismatches.append({"tool":"wire_bytes_len","expected":expected,"actual":actual})
else:
    results.append({"tool":"wire_bytes_len","status":"PASS",
                    "expected":expected,"actual":data.get("len")})

# --- wire_bytes_hex_encode ---
expected_hex = ref_bytes_hex_encode(TEST_HEX)
data, err = call_tool("wire_bytes_hex_encode", {"hex": TEST_HEX})
if err:
    results.append({"tool":"wire_bytes_hex_encode","status":"FAIL","reason":err})
    mismatches.append({"tool":"wire_bytes_hex_encode","expected":expected_hex,"actual":err})
elif data is None or data.get("hex") != expected_hex:
    actual = data.get("hex") if data else None
    results.append({"tool":"wire_bytes_hex_encode","status":"FAIL",
                    "expected":expected_hex,"actual":actual})
    mismatches.append({"tool":"wire_bytes_hex_encode","expected":expected_hex,"actual":actual})
else:
    results.append({"tool":"wire_bytes_hex_encode","status":"PASS",
                    "expected":expected_hex,"actual":data.get("hex")})

# --- wire_echo_string ---
expected_echo = ref_echo_string(TEST_TEXT)
data, err = call_tool("wire_echo_string", {"text": TEST_TEXT})
if err:
    results.append({"tool":"wire_echo_string","status":"FAIL","reason":err})
    mismatches.append({"tool":"wire_echo_string","expected":expected_echo,"actual":err})
elif data is None or data.get("echo") != expected_echo:
    actual = data.get("echo") if data else None
    results.append({"tool":"wire_echo_string","status":"FAIL",
                    "expected":expected_echo,"actual":actual})
    mismatches.append({"tool":"wire_echo_string","expected":expected_echo,"actual":actual})
else:
    results.append({"tool":"wire_echo_string","status":"PASS",
                    "expected":expected_echo,"actual":data.get("echo")})

# --- wire_string_len ---
expected_slen = ref_string_len(TEST_TEXT)
data, err = call_tool("wire_string_len", {"text": TEST_TEXT})
if err:
    results.append({"tool":"wire_string_len","status":"FAIL","reason":err})
    mismatches.append({"tool":"wire_string_len","expected":expected_slen,"actual":err})
elif data is None or data.get("len") != expected_slen:
    actual = data.get("len") if data else None
    results.append({"tool":"wire_string_len","status":"FAIL",
                    "expected":expected_slen,"actual":actual})
    mismatches.append({"tool":"wire_string_len","expected":expected_slen,"actual":actual})
else:
    results.append({"tool":"wire_string_len","status":"PASS",
                    "expected":expected_slen,"actual":data.get("len")})

# ── Teardown ──────────────────────────────────────────────────────────────────
try:
    p.stdin.close()
    p.terminate()
except Exception:
    pass

# ── Write output files ────────────────────────────────────────────────────────
with open(OUT_JSON, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

with open(SKIP_JSON, "w", encoding="utf-8") as f:
    json.dump(skips, f, indent=2)

passed  = sum(1 for r in results if r["status"] == "PASS")
failed  = sum(1 for r in results if r["status"] == "FAIL")
skipped = len(skips)
hardened = len(results) + skipped   # all tools we touched

print(json.dumps({
    "category":       "wire",
    "tools_hardened": hardened,
    "tools_passed":   passed,
    "tools_failed":   failed,
    "tools_skipped":  skipped,
    "mismatches":     mismatches,
}, indent=2))
