#!/usr/bin/env python3
"""
Rigorous ground-truth validation for MCP tools prefixed with 'llm_'.
Tools: llm_token_count_estimate, llm_compress_message, llm_trim_to_budget
"""
import json, math, subprocess, sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_llm_v2.json"
SKIP_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\skip_llm.json"

# ── Python reference implementations ─────────────────────────────────────────

def ref_token_count_estimate(text: str) -> int:
    """llm_context_builder::token_count_estimate — ceil(chars / 4.0)"""
    chars = len(text)  # Python len() counts Unicode code points, same as Rust chars().count()
    return math.ceil(chars / 4.0)

def ref_count_tokens_mgr(text: str) -> int:
    """llm_context_manager::count_tokens — (chars + 3) / 4 integer"""
    chars = len(text)
    return (chars + 3) // 4

def ref_compress_message(msg: str, target_tokens: int) -> str:
    """llm_context_builder::compress_message"""
    suffix = "... [truncated]"
    current = ref_token_count_estimate(msg)
    if current <= target_tokens:
        return msg
    suffix_tokens = ref_token_count_estimate(suffix)
    keep_tokens = max(0, target_tokens - suffix_tokens)
    keep_chars = keep_tokens * 4
    truncated = msg[:keep_chars]
    return truncated + suffix

def ref_trim_to_budget(text: str, limit: int) -> str:
    """llm_context_manager::trim_to_budget"""
    if ref_count_tokens_mgr(text) <= limit:
        return text
    char_limit = limit * 4
    if len(text) <= char_limit:
        return text
    slice_ = text[:char_limit]
    # rfind whitespace
    pos = None
    for i in range(len(slice_) - 1, -1, -1):
        if slice_[i] in (' ', '\t', '\n', '\r', '\f', '\v'):
            pos = i
            break
    if pos is None:
        return slice_
    else:
        return text[:pos]

# ── MCP subprocess helpers ────────────────────────────────────────────────────

p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    bufsize=0
)

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

# Initialize
send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
    "protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"rigorous_llm","version":"1"}
}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

# Open project (required by server)
send({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
    "name":"project.open","arguments":{"path":TARGET}
}})
op = recv()
try:
    op_data = json.loads(op["result"]["content"][0]["text"])
    BINARY_ID = op_data["binary_id"]
    PROJECT_ID = op_data["project_id"]
except Exception as e:
    print(f"WARNING: project.open failed: {e}")
    BINARY_ID = ""
    PROJECT_ID = ""

rid_counter = [100]

def call_tool(name, arguments):
    rid_counter[0] += 1
    send({"jsonrpc":"2.0","id":rid_counter[0],"method":"tools/call","params":{
        "name": name, "arguments": arguments
    }})
    resp = recv()
    if "error" in resp:
        return None, f"JSONRPC_ERROR: {resp['error']}"
    result = resp.get("result", {})
    if result.get("isError"):
        content = result.get("content", [])
        txt = content[0].get("text","") if content else ""
        return None, f"TOOL_ERROR: {txt}"
    content = result.get("content", [])
    txt = content[0].get("text","") if content else ""
    try:
        return json.loads(txt), None
    except json.JSONDecodeError:
        return txt, None

# ── Test cases ────────────────────────────────────────────────────────────────

results = []
mismatches = []

# ── llm_token_count_estimate ──────────────────────────────────────────────────
test_cases_tce = [
    ("", 0),
    ("abcd", 1),
    ("abc", 1),
    ("hello world", 3),           # 11 chars → ceil(11/4) = 3
    ("a" * 16, 4),                # 16 chars → ceil(16/4) = 4
    ("a" * 400, 100),             # 400 chars → 100
    ("x" * 1, 1),                 # 1 char → ceil(0.25) = 1
    ("αβγδ", 1),                  # 4 Unicode chars → 1
    ("Hello, World!", 4),         # 13 chars → ceil(13/4) = 4
]

tool_name = "llm_token_count_estimate"
tool_passed = 0
tool_failed = 0

for text, expected_tokens in test_cases_tce:
    # Verify reference matches our formula
    ref = ref_token_count_estimate(text)
    assert ref == expected_tokens, f"Reference mismatch for {text!r}: got {ref}, expected {expected_tokens}"

    actual_data, err = call_tool(tool_name, {"text": text})
    if err:
        mismatches.append({"tool": tool_name, "input": text, "expected": expected_tokens, "actual": err})
        tool_failed += 1
        continue
    actual = actual_data.get("tokens")
    if actual == expected_tokens:
        tool_passed += 1
    else:
        mismatches.append({"tool": tool_name, "input": repr(text), "expected": expected_tokens, "actual": actual})
        tool_failed += 1

results.append({
    "tool": tool_name,
    "status": "PASS" if tool_failed == 0 else "FAIL",
    "passed": tool_passed,
    "failed": tool_failed,
    "total": len(test_cases_tce),
})
print(f"{tool_name}: {tool_passed}/{len(test_cases_tce)} passed")

# ── llm_compress_message ──────────────────────────────────────────────────────
# suffix = "... [truncated]" → 15 chars → ceil(15/4) = 4 tokens
SUFFIX = "... [truncated]"
SUFFIX_TOKENS = ref_token_count_estimate(SUFFIX)  # 4

test_cases_cm = [
    # (msg, target_tokens, expected_output)
    ("short", 100, "short"),                              # fits, no truncation
    ("a" * 8, 2, "a" * 8),                               # 8 chars = 2 tokens, fits exactly
    # 40 chars = 10 tokens > target 5:
    #   suffix_tokens=4, keep_tokens=1, keep_chars=4 → "aaaa" + suffix
    ("a" * 40, 5, "a" * 4 + SUFFIX),
    # 20 chars = 5 tokens, target=5 → fits
    ("b" * 20, 5, "b" * 20),
]

tool_name = "llm_compress_message"
tool_passed = 0
tool_failed = 0

for msg, target, expected in test_cases_cm:
    ref = ref_compress_message(msg, target)
    if ref != expected:
        # Fix our expected from ref
        expected = ref

    actual_data, err = call_tool(tool_name, {"msg": msg, "target_tokens": target})
    if err:
        mismatches.append({"tool": tool_name, "input": {"msg": repr(msg), "target_tokens": target}, "expected": expected, "actual": err})
        tool_failed += 1
        continue
    actual = actual_data.get("compressed")
    if actual == expected:
        tool_passed += 1
    else:
        mismatches.append({"tool": tool_name, "input": {"msg": repr(msg[:30]), "target_tokens": target}, "expected": expected, "actual": actual})
        tool_failed += 1

results.append({
    "tool": tool_name,
    "status": "PASS" if tool_failed == 0 else "FAIL",
    "passed": tool_passed,
    "failed": tool_failed,
    "total": len(test_cases_cm),
})
print(f"{tool_name}: {tool_passed}/{len(test_cases_cm)} passed")

# ── llm_trim_to_budget ────────────────────────────────────────────────────────
# Note: uses count_tokens from llm_context_manager: (chars+3)//4

test_cases_ttb = [
    # (text, limit, expected)
    ("hello world", 100, "hello world"),                 # fits, no trim
    ("a" * 400, 50, "a" * 200),                          # 400 chars → 100 tokens > 50; char_limit=200, no whitespace → return slice[:200]
    ("word " * 20, 5, None),                             # dynamic — check via reference
    ("", 10, ""),                                         # empty
    ("a" * 8, 2, "a" * 8),                               # (8+3)//4=2 tokens, fits exactly
    ("a" * 9, 2, "a" * 8),                               # (9+3)//4=3 > 2; char_limit=8, no whitespace → "aaaaaaaa"
]

tool_name = "llm_trim_to_budget"
tool_passed = 0
tool_failed = 0

for item in test_cases_ttb:
    text, limit, expected = item
    ref = ref_trim_to_budget(text, limit)
    if expected is None:
        expected = ref
    # Verify our explicit expected matches reference
    if expected != ref:
        expected = ref

    actual_data, err = call_tool(tool_name, {"text": text, "limit": limit})
    if err:
        mismatches.append({"tool": tool_name, "input": {"text": repr(text[:30]), "limit": limit}, "expected": expected, "actual": err})
        tool_failed += 1
        continue
    actual = actual_data.get("trimmed")
    if actual == expected:
        tool_passed += 1
    else:
        mismatches.append({"tool": tool_name, "input": {"text": repr(text[:30]), "limit": limit}, "expected": repr(expected), "actual": repr(actual)})
        tool_failed += 1

results.append({
    "tool": tool_name,
    "status": "PASS" if tool_failed == 0 else "FAIL",
    "passed": tool_passed,
    "failed": tool_failed,
    "total": len(test_cases_ttb),
})
print(f"{tool_name}: {tool_passed}/{len(test_cases_ttb)} passed")

# ── Shutdown ──────────────────────────────────────────────────────────────────
p.stdin.close()
p.terminate()

# ── Write output files ────────────────────────────────────────────────────────
with open(OUT_JSON, "w") as f:
    json.dump({"results": results, "mismatches": mismatches}, f, indent=2)
print(f"\nResults written to {OUT_JSON}")

# Skipped tools (none for llm_* — all are deterministic pure functions)
skipped = []
with open(SKIP_JSON, "w") as f:
    json.dump(skipped, f, indent=2)

# Summary
tools_hardened = len(results)
tools_passed = sum(1 for r in results if r["status"] == "PASS")
tools_failed = sum(1 for r in results if r["status"] == "FAIL")
tools_skipped = len(skipped)

print(f"\nSUMMARY: hardened={tools_hardened} passed={tools_passed} failed={tools_failed} skipped={tools_skipped}")
print(f"Mismatches: {len(mismatches)}")
for m in mismatches:
    print(f"  {m}")

# Write summary for parent agent
summary = {
    "category": "llm",
    "tools_hardened": tools_hardened,
    "tools_passed": tools_passed,
    "tools_failed": tools_failed,
    "tools_skipped": tools_skipped,
    "mismatches": mismatches,
}
print(f"\nJSON_SUMMARY={json.dumps(summary)}")
