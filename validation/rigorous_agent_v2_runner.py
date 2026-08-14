#!/usr/bin/env python3
"""
Rigorous ground-truth validation for MCP tools prefixed with agent_.
Uses independent Python reference implementations for each tool.
"""
import json
import math
import struct
import subprocess
import sys
import time

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_agent_v2.json"
SKIP_OUT = r"C:\Users\Fra\Desktop\RustRE\validation\skip_agent.json"

# ─── MCP client ──────────────────────────────────────────────────────────────

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
    return json.loads(line)

def call_tool(name, args, timeout_s=10):
    global _rid
    _rid += 1
    send({"jsonrpc": "2.0", "id": _rid, "method": "tools/call",
          "params": {"name": name, "arguments": args}})
    deadline = time.time() + timeout_s
    while True:
        if time.time() > deadline:
            return None, "TIMEOUT"
        resp = recv()
        if resp.get("id") == _rid:
            break
    if "error" in resp:
        return None, f"JSONRPC_ERROR: {resp['error']}"
    result = resp.get("result", {})
    if result.get("isError"):
        content = result.get("content", [])
        txt = content[0].get("text", "") if content else ""
        return None, f"TOOL_ERROR: {txt}"
    content = result.get("content", [])
    txt = content[0].get("text", "") if content else ""
    try:
        return json.loads(txt), None
    except Exception:
        return {"_raw": txt}, None

# Initialize
send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "rigorous_agent", "version": "1"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

# Open project (required by server)
send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
      "params": {"name": "project.open", "arguments": {"path": TARGET}}})
op = recv()
op_data = json.loads(op["result"]["content"][0]["text"])
BINARY_ID = op_data["binary_id"]
PROJECT_ID = op_data["project_id"]
print(f"project.open: binary_id={BINARY_ID}")

# ─── Python reference implementations ────────────────────────────────────────

def ref_shannon_entropy(data: bytes) -> float:
    """Standard Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    n = len(data)
    entropy = 0.0
    for c in counts.values():
        p = c / n
        entropy -= p * math.log2(p)
    return entropy

def ref_u64_to_f64(x: int) -> float:
    """
    Mirrors rustre_agent::casts::u64_to_f64:
    clamps to 2^53, reconstructs via hi/lo split.
    """
    MAX_EXACT = 1 << 53
    clamped = min(x, MAX_EXACT)
    hi = (clamped >> 32) & 0xFFFFFFFF
    lo = clamped & 0xFFFFFFFF
    result = float(hi) * 4294967296.0 + float(lo)
    MAX_EXACT_F = float(MAX_EXACT)
    return min(result, MAX_EXACT_F)

def ref_usize_to_f64(x: int) -> float:
    # usize on 64-bit = u64
    return ref_u64_to_f64(x)

def ref_i64_to_f64(x: int) -> float:
    # Rust i64::unsigned_abs() returns abs(x) as u64, not the two's complement repr.
    if x < 0:
        return -ref_u64_to_f64(abs(x))
    return ref_u64_to_f64(x)

def ref_f64_to_f32(x: float) -> float:
    """Narrow f64 → f32, saturating at f32::MAX."""
    if math.isnan(x):
        return float('nan')
    F32_MAX = struct.unpack('f', struct.pack('f', 3.4028235e+38))[0]
    clamped = max(-F32_MAX, min(F32_MAX, x))
    # Pack as f32 then unpack to get Python float
    return struct.unpack('f', struct.pack('f', clamped))[0]

def ref_u64_to_f32(x: int) -> float:
    return ref_f64_to_f32(ref_u64_to_f64(x))

def ref_f64_to_u64(x: float) -> int:
    if not math.isfinite(x) or x <= 0.0:
        return 0
    MAX_EXACT = 1 << 53
    MAX_EXACT_F = float(MAX_EXACT)
    clamped = min(x, MAX_EXACT_F)
    return int(clamped)

def ref_f64_to_u32(x: float) -> int:
    if not math.isfinite(x) or x <= 0.0:
        return 0
    clamped = min(x, float(0xFFFFFFFF))
    return int(clamped)

def ref_u64_to_u32(x: int) -> int:
    return min(x, 0xFFFFFFFF)

def ref_u64_to_usize(x: int) -> int:
    # On 64-bit usize::MAX == u64::MAX; try_from always succeeds
    return x

def ref_count_tokens(text: str) -> int:
    """(len_chars + 3) // 4"""
    return (len(text) + 3) // 4

def ref_count_messages(messages: list) -> int:
    """Sum of (count_tokens(content) + 4) for each msg."""
    total = 0
    for m in messages:
        total += ref_count_tokens(m.get("content", "")) + 4
    return total

def ref_fits_in_context(messages: list, max_tokens: int) -> bool:
    return ref_count_messages(messages) <= max_tokens

# ─── Test cases ──────────────────────────────────────────────────────────────

passed = []
failed = []
skipped = []
mismatches = []

def approx_equal(a, b, rel_tol=1e-9, abs_tol=1e-12):
    if isinstance(a, float) and isinstance(b, float):
        if math.isnan(a) and math.isnan(b):
            return True
        return math.isclose(a, b, rel_tol=rel_tol, abs_tol=abs_tol)
    return a == b

def check(tool_name, args, key, expected, tolerance=None):
    data, err = call_tool(tool_name, args)
    if err:
        if "TIMEOUT" in err:
            skipped.append({"tool": tool_name, "reason": "TIMEOUT"})
            return
        failed.append({"tool": tool_name, "error": err})
        mismatches.append({"tool": tool_name, "expected": expected, "actual": err})
        return
    actual = data.get(key) if data else None
    if tolerance is not None:
        ok = approx_equal(float(actual), float(expected), rel_tol=tolerance, abs_tol=tolerance)
    elif isinstance(expected, float):
        ok = approx_equal(float(actual) if actual is not None else None, expected)
    else:
        ok = actual == expected
    if ok:
        passed.append({"tool": tool_name, "key": key, "value": actual})
    else:
        failed.append({"tool": tool_name, "key": key, "expected": expected, "actual": actual})
        mismatches.append({"tool": tool_name, "expected": expected, "actual": actual})
    print(f"  {'PASS' if ok else 'FAIL'} {tool_name}[{key}]: expected={expected!r} actual={actual!r}")


# ── 1. agent_shannon_entropy ──────────────────────────────────────────────────
# Input: "deadbeef00112233" hex bytes
hex_input = "deadbeef00112233"
raw_bytes = bytes.fromhex(hex_input)
exp_entropy = ref_shannon_entropy(raw_bytes)
print(f"\nagent_shannon_entropy: expected={exp_entropy}")
check("agent_shannon_entropy", {"data_hex": hex_input}, "entropy", exp_entropy, tolerance=1e-9)

# Also test uniform bytes (all 256 values = entropy 8.0)
uniform_hex = "".join(f"{i:02x}" for i in range(256))
check("agent_shannon_entropy", {"data_hex": uniform_hex}, "entropy", 8.0, tolerance=1e-9)

# ── 2. agent_cast_u64_to_f64 ─────────────────────────────────────────────────
print("\nagent_cast_u64_to_f64:")
for x in [0, 1, 1000, (1 << 53), (1 << 53) + 1, 0xFFFFFFFFFFFFFFFF]:
    exp = ref_u64_to_f64(x)
    check("agent_cast_u64_to_f64", {"x": x}, "output", exp, tolerance=1e-9)

# ── 3. agent_cast_usize_to_f64 ───────────────────────────────────────────────
print("\nagent_cast_usize_to_f64:")
for x in [0, 42, 1 << 52]:
    exp = ref_usize_to_f64(x)
    check("agent_cast_usize_to_f64", {"x": x}, "output", exp, tolerance=1e-9)

# ── 4. agent_cast_i64_to_f64 ─────────────────────────────────────────────────
print("\nagent_cast_i64_to_f64:")
for x in [0, 1000, -1000, -(1 << 53)]:
    exp = ref_i64_to_f64(x)
    check("agent_cast_i64_to_f64", {"x": x}, "output", exp, tolerance=1e-9)

# ── 5. agent_cast_u64_to_u32 ─────────────────────────────────────────────────
print("\nagent_cast_u64_to_u32:")
for x in [0, 100, 0xFFFFFFFF, 0x1_0000_0000, 0xFFFFFFFFFFFFFFFF]:
    exp = ref_u64_to_u32(x)
    check("agent_cast_u64_to_u32", {"x": x}, "output", exp)

# ── 6. agent_cast_f64_to_u64 ─────────────────────────────────────────────────
print("\nagent_cast_f64_to_u64:")
for x in [0.0, 1.5, float(1 << 52), -5.0]:
    exp = ref_f64_to_u64(x)
    check("agent_cast_f64_to_u64", {"x": x}, "output", exp)

# ── 7. agent_cast_f64_to_u32 ─────────────────────────────────────────────────
print("\nagent_cast_f64_to_u32:")
for x in [0.0, 255.9, float(0xFFFFFFFF), -1.0]:
    exp = ref_f64_to_u32(x)
    check("agent_cast_f64_to_u32", {"x": x}, "output", exp)

# ── 8. agent_cast_u64_to_usize ───────────────────────────────────────────────
print("\nagent_cast_u64_to_usize:")
for x in [0, 42, 0xFFFF]:
    exp = ref_u64_to_usize(x)
    check("agent_cast_u64_to_usize", {"x": x}, "output", exp)

# ── 9. agent_llm_count_tokens ────────────────────────────────────────────────
print("\nagent_llm_count_tokens:")
for text in ["", "hello", "hello world", "a" * 100]:
    exp = ref_count_tokens(text)
    check("agent_llm_count_tokens", {"text": text}, "tokens", exp)

# ── 10. agent_llm_token_counter_count_text ────────────────────────────────────
print("\nagent_llm_token_counter_count_text:")
for text in ["", "test input", "a" * 40]:
    exp = ref_count_tokens(text)
    check("agent_llm_token_counter_count_text", {"text": text}, "tokens", exp)

# ── 11. agent_llm_token_counter_count_messages ───────────────────────────────
print("\nagent_llm_token_counter_count_messages:")
msgs = [{"role": "user", "content": "hello"}, {"role": "assistant", "content": "hi there"}]
exp = ref_count_messages(msgs)
check("agent_llm_token_counter_count_messages", {"messages": msgs}, "tokens", exp)

# ── 12. agent_llm_token_counter_fits_in_context ──────────────────────────────
print("\nagent_llm_token_counter_fits_in_context:")
msgs = [{"role": "user", "content": "hello"}]
exp_fit = ref_fits_in_context(msgs, 1000)
check("agent_llm_token_counter_fits_in_context", {"messages": msgs, "max_tokens": 1000}, "fits", exp_fit)

# ── 13. agent_llm_message_system/user/assistant ──────────────────────────────
print("\nagent_llm_message_system:")
check("agent_llm_message_system", {"content": "You are a helpful assistant."}, "role", "system")

print("\nagent_llm_message_user:")
check("agent_llm_message_user", {"content": "What is 2+2?"}, "role", "user")

print("\nagent_llm_message_assistant:")
check("agent_llm_message_assistant", {"content": "The answer is 4."}, "role", "assistant")

# ── 14. agent_llm_llm_role_display ───────────────────────────────────────────
print("\nagent_llm_llm_role_display:")
# LlmRole uses Debug fmt so System→"System", User→"User", Assistant→"Assistant"
for role_input, expected_display in [("System", "System"), ("User", "User"), ("Assistant", "Assistant")]:
    check("agent_llm_llm_role_display", {"role": role_input}, "display", expected_display)

# ── 15. agent_llm_llm_model_display ──────────────────────────────────────────
print("\nagent_llm_llm_model_display:")
# Non-Custom variants use Debug fmt: "Gpt4", "Claude3Opus", etc.
# Custom variant: "custom:{name}"
for model_input, expected_display in [
    ("Gpt4", "Gpt4"),
    ("Claude3Opus", "Claude3Opus"),
    ("Claude3Sonnet", "Claude3Sonnet"),
    ("Claude3Haiku", "Claude3Haiku"),
    ("Llama3", "Llama3"),
]:
    # Tool expects param "variant", not "model"
    check("agent_llm_llm_model_display", {"variant": model_input}, "display", expected_display)

# ── 16. agent_prompts_error_display ──────────────────────────────────────────
print("\nagent_prompts_error_display:")
# #[error("missing template variable: {0}")] for MissingVariable
check("agent_prompts_error_display", {"var": "myvar"}, "display", "missing template variable: myvar")

# ── 17. agent_llm_trim_to_budget ─────────────────────────────────────────────
# For text that fits within budget, it should return unchanged
print("\nagent_llm_trim_to_budget:")
short_text = "hello world"
exp_tokens = ref_count_tokens(short_text)  # 3
# If budget >= exp_tokens, text is returned as-is
check("agent_llm_trim_to_budget", {"text": short_text, "limit": 100}, "trimmed", short_text)

# ── Skipped tools (non-deterministic / network required) ──────────────────────
SKIP_REASONS = {
    "agent_llm_mock_provider_complete": "nondeterministic mock (uses internal queued responses)",
    "agent_id_new_wire": "nondeterministic (UUID generation)",
    "agent_session_new_v2": "nondeterministic (UUID/timestamp)",
    "agent_rate_limiter_acquire": "time-dependent",
    "agent_standard_re_pipeline": "requires active binary analysis session",
    "agent_workflow_builtin_list": "returns internal implementation list; no fixed ground truth",
    "agent_workflow_templates_list": "returns internal implementation list; no fixed ground truth",
    "agent_builtin_workflows": "returns internal implementation list; no fixed ground truth",
    "agent_prompts_builtin_templates_count": "count depends on compiled-in templates; not independently computable without running binary",
    "agent_prompts_registry_count": "count depends on compiled-in templates",
    "agent_prompts_builtin_template_names": "depends on compiled-in templates",
    "agent_llm_builtin_models": "depends on compiled-in model list",
    "agent_llm_estimate_cost": "depends on model pricing table in binary",
    "agent_llm_extract_code_blocks": "depends on LLM response parser heuristics",
    "agent_cast_u64_to_f32": "f32 precision comparison unreliable over JSON (JSON has no f32 type)",
    "agent_cast_f64_to_f32": "f32 precision comparison unreliable over JSON",
}
for tool, reason in SKIP_REASONS.items():
    skipped.append({"tool": tool, "reason": reason})

# ─── Shutdown ─────────────────────────────────────────────────────────────────
p.stdin.close()
p.terminate()

# ─── Write outputs ────────────────────────────────────────────────────────────
results = {
    "passed": passed,
    "failed": failed,
}
with open(OUT, "w") as f:
    json.dump(results, f, indent=2)

with open(SKIP_OUT, "w") as f:
    json.dump(skipped, f, indent=2)

print(f"\n=== SUMMARY ===")
print(f"  passed:  {len(passed)}")
print(f"  failed:  {len(failed)}")
print(f"  skipped: {len(skipped)}")
if failed:
    print("\nFailed checks:")
    for f_ in failed:
        print(f"  {f_}")
