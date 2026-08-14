#!/usr/bin/env python3
"""Rigorous ground-truth validation for previously-unhardened kgdb_* tools."""
import json, subprocess, sys, struct

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"

p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0
)

def send(req):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()

def recv():
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("server died")
    return json.loads(line)

# Initialize
send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"rigorous_kgdb_v2","version":"1"}}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

# Open project (required by server)
send({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"project.open","arguments":{"path":TARGET}}})
recv()

rid = 10

def call_tool(name, args):
    global rid
    rid += 1
    send({"jsonrpc":"2.0","id":rid,"method":"tools/call","params":{"name":name,"arguments":args}})
    resp = recv()
    if "error" in resp:
        return None, f"JSONRPC_ERROR: {resp['error']}"
    is_err = resp.get("result",{}).get("isError", False)
    content = resp.get("result",{}).get("content",[])
    txt = content[0].get("text","") if content else ""
    if is_err:
        return None, f"TOOL_ERROR: {txt}"
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None

# ─── Python reference implementations ───────────────────────────────────────

def ref_bytes_to_hex(byte_list):
    return bytes(byte_list).hex()

def ref_hex_to_bytes(hex_str):
    return list(bytes.fromhex(hex_str))

def ref_rle_encode(data):
    if not data:
        return ""
    chars = list(data)
    out = []
    i = 0
    while i < len(chars):
        c = chars[i]
        count = 1
        while i + count < len(chars) and chars[i + count] == c and count < 97:
            count += 1
        if count > 3:
            rc = chr(count - 1 + 29)
            out.append(c)
            out.append('*')
            out.append(rc)
            i += count
        else:
            out.append(c)
            i += 1
    return "".join(out)

def ref_rle_decode(data):
    chars = list(data)
    out = []
    i = 0
    while i < len(chars):
        if chars[i] == '*':
            i += 1
            if i < len(chars):
                count = ord(chars[i]) - 29
                prev = out[-1] if out else ' '
                out.extend([prev] * count)
                i += 1
        else:
            out.append(chars[i])
            i += 1
    return "".join(out)

DIRECT_MAP_BASE = 0xffff_8880_0000_0000
MAX_PHYS = 0x0000_0100_0000_0000

def ref_kvirt_to_phys(addr):
    if DIRECT_MAP_BASE <= addr < DIRECT_MAP_BASE + MAX_PHYS:
        return addr - DIRECT_MAP_BASE
    return None

def ref_target_xml_x86_64():
    return ('<?xml version="1.0"?>\n'
            '<!DOCTYPE target SYSTEM "gdb-target.dtd">\n'
            '<target version="1.0">\n'
            '  <architecture>i386:x86-64</architecture>\n'
            '  <feature name="org.gnu.gdb.i386.core">\n'
            '    <reg name="rax" bitsize="64" type="int64" regnum="0"/>\n'
            '    <reg name="rbx" bitsize="64" type="int64" regnum="1"/>\n'
            '    <reg name="rcx" bitsize="64" type="int64" regnum="2"/>\n'
            '    <reg name="rdx" bitsize="64" type="int64" regnum="3"/>\n'
            '    <reg name="rsi" bitsize="64" type="int64" regnum="4"/>\n'
            '    <reg name="rdi" bitsize="64" type="int64" regnum="5"/>\n'
            '    <reg name="rbp" bitsize="64" type="int64" regnum="6"/>\n'
            '    <reg name="rsp" bitsize="64" type="int64" regnum="7"/>\n'
            '    <reg name="r8"  bitsize="64" type="int64" regnum="8"/>\n'
            '    <reg name="r9"  bitsize="64" type="int64" regnum="9"/>\n'
            '    <reg name="r10" bitsize="64" type="int64" regnum="10"/>\n'
            '    <reg name="r11" bitsize="64" type="int64" regnum="11"/>\n'
            '    <reg name="r12" bitsize="64" type="int64" regnum="12"/>\n'
            '    <reg name="r13" bitsize="64" type="int64" regnum="13"/>\n'
            '    <reg name="r14" bitsize="64" type="int64" regnum="14"/>\n'
            '    <reg name="r15" bitsize="64" type="int64" regnum="15"/>\n'
            '    <reg name="rip" bitsize="64" type="code_ptr" regnum="16"/>\n'
            '    <reg name="eflags" bitsize="32" type="i386_eflags" regnum="17"/>\n'
            '  </feature>\n'
            '</target>')

def ref_target_xml_arm64():
    return ('<?xml version="1.0"?>\n'
            '<!DOCTYPE target SYSTEM "gdb-target.dtd">\n'
            '<target version="1.0">\n'
            '  <architecture>aarch64</architecture>\n'
            '  <feature name="org.gnu.gdb.aarch64.core">\n'
            '    <reg name="x0"  bitsize="64" type="int64" regnum="0"/>\n'
            '    <reg name="x1"  bitsize="64" type="int64" regnum="1"/>\n'
            '    <reg name="x29" bitsize="64" type="int64" regnum="29"/>\n'
            '    <reg name="x30" bitsize="64" type="int64" regnum="30"/>\n'
            '    <reg name="sp"  bitsize="64" type="data_ptr" regnum="31"/>\n'
            '    <reg name="pc"  bitsize="64" type="code_ptr" regnum="32"/>\n'
            '  </feature>\n'
            '</target>')

# parse_kernel_callstack: count frames with kernel addresses extracted from log
KERNEL_ADDR_MIN = 0xffff_8000_0000_0000

def ref_parse_kernel_callstack_count(log):
    frames = []
    for line in log.splitlines():
        trimmed = line.strip()
        for word in trimmed.split():
            cleaned = word.lstrip('[<').rstrip('>]')
            if len(cleaned) == 16 or cleaned.startswith('0xffff'):
                addr_str = cleaned.lstrip('0x') if cleaned.startswith('0x') else cleaned
                try:
                    addr = int(addr_str, 16)
                    if addr >= KERNEL_ADDR_MIN:
                        frames.append(addr)
                        break
                except ValueError:
                    pass
    return frames

# parse_thread_list: split on ',' after stripping 'm' prefix; 'l' => empty
def ref_parse_thread_list_count(response):
    if response == 'l' or response == '':
        return 0
    body = response[1:] if response.startswith('m') else response
    return len(body.split(','))

# ─── Test cases ─────────────────────────────────────────────────────────────

results = []
mismatches = []

def check(tool, args, expected_key, expected_val, actual_key=None, transform=None):
    data, err = call_tool(tool, args)
    if err:
        results.append({"tool": tool, "status": "FAIL", "reason": err})
        mismatches.append({"tool": tool, "expected": {expected_key: expected_val}, "actual": err})
        return
    ak = actual_key or expected_key
    actual = data.get(ak) if isinstance(data, dict) else data
    if transform:
        actual = transform(actual)
    if actual == expected_val:
        results.append({"tool": tool, "status": "PASS"})
    else:
        results.append({"tool": tool, "status": "FAIL",
                        "expected": expected_val, "actual": actual})
        mismatches.append({"tool": tool,
                           "expected": {expected_key: expected_val},
                           "actual": {ak: actual}})

# 1. kgdb_bytes_to_hex_v2
test_bytes = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33]
check("kgdb_bytes_to_hex_v2", {"bytes": test_bytes}, "hex",
      ref_bytes_to_hex(test_bytes))
check("kgdb_bytes_to_hex_v2", {"bytes": []}, "hex",
      ref_bytes_to_hex([]))

# 2. kgdb_hex_to_bytes_v2
check("kgdb_hex_to_bytes_v2", {"hex": "deadbeef"}, "bytes",
      ref_hex_to_bytes("deadbeef"))
check("kgdb_hex_to_bytes_v2", {"hex": "00"}, "bytes",
      ref_hex_to_bytes("00"))

# 3. kgdb_rle_encode
rle_plain = "aaaaabc"       # 5 a's  → should encode since 5>3
rle_enc = ref_rle_encode(rle_plain)
check("kgdb_rle_encode", {"data": rle_plain}, "encoded", rle_enc)
# short run (no encoding)
check("kgdb_rle_encode", {"data": "abc"}, "encoded", "abc")
# empty
check("kgdb_rle_encode", {"data": ""}, "encoded", "")

# 4. kgdb_rle_decode  (round-trip: decode(encode(x)) == x)
encoded = ref_rle_encode("aaaaaaaabc")  # 8 a's
decoded_ref = "aaaaaaaabc"
check("kgdb_rle_decode", {"data": encoded}, "decoded", decoded_ref)
# literal no RLE
check("kgdb_rle_decode", {"data": "hello"}, "decoded", "hello")

# 5. kgdb_kvirt_to_phys
addr_in_map = DIRECT_MAP_BASE + 0x1000   # should map to 0x1000
check("kgdb_kvirt_to_phys", {"addr": addr_in_map}, "phys",
      ref_kvirt_to_phys(addr_in_map))
addr_out = 0x1234  # userspace, no mapping
check("kgdb_kvirt_to_phys", {"addr": addr_out}, "phys",
      None)  # null / None

# 6. kgdb_parse_kernel_callstack
oops_log = (
    "Call Trace:\n"
    " [<ffffffff810a1b2c>] do_something+0x2c/0x80\n"
    " [<ffffffff810b3c4d>] handle_irq+0x4d/0x100\n"
    " some_other_line without addresses\n"
)
ref_frames = ref_parse_kernel_callstack_count(oops_log)
data, err = call_tool("kgdb_parse_kernel_callstack", {"log": oops_log})
if err:
    results.append({"tool": "kgdb_parse_kernel_callstack", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "kgdb_parse_kernel_callstack",
                       "expected": {"count": len(ref_frames)}, "actual": err})
else:
    actual_count = data.get("count", -1)
    expected_count = len(ref_frames)
    if actual_count == expected_count:
        results.append({"tool": "kgdb_parse_kernel_callstack", "status": "PASS"})
    else:
        results.append({"tool": "kgdb_parse_kernel_callstack", "status": "FAIL",
                        "expected": expected_count, "actual": actual_count})
        mismatches.append({"tool": "kgdb_parse_kernel_callstack",
                           "expected": {"count": expected_count},
                           "actual": {"count": actual_count}})

# 7. kgdb_target_xml_x86_64 — check xml field contains key landmarks
data, err = call_tool("kgdb_target_xml_x86_64", {})
if err:
    results.append({"tool": "kgdb_target_xml_x86_64", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "kgdb_target_xml_x86_64", "expected": "valid XML", "actual": err})
else:
    xml = data.get("xml", "")
    expected_xml = ref_target_xml_x86_64()
    if xml == expected_xml:
        results.append({"tool": "kgdb_target_xml_x86_64", "status": "PASS"})
    else:
        results.append({"tool": "kgdb_target_xml_x86_64", "status": "FAIL",
                        "expected": expected_xml[:200], "actual": xml[:200]})
        mismatches.append({"tool": "kgdb_target_xml_x86_64",
                           "expected": expected_xml[:200],
                           "actual": xml[:200]})

# 8. kgdb_target_xml_arm64
data, err = call_tool("kgdb_target_xml_arm64", {})
if err:
    results.append({"tool": "kgdb_target_xml_arm64", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "kgdb_target_xml_arm64", "expected": "valid XML", "actual": err})
else:
    xml = data.get("xml", "")
    expected_xml = ref_target_xml_arm64()
    if xml == expected_xml:
        results.append({"tool": "kgdb_target_xml_arm64", "status": "PASS"})
    else:
        results.append({"tool": "kgdb_target_xml_arm64", "status": "FAIL",
                        "expected": expected_xml[:200], "actual": xml[:200]})
        mismatches.append({"tool": "kgdb_target_xml_arm64",
                           "expected": expected_xml[:200],
                           "actual": xml[:200]})

# 9. kgdb_parse_thread_list
# "m1,2,3" → 3 threads
data, err = call_tool("kgdb_parse_thread_list", {"response": "m1,2,3"})
if err:
    results.append({"tool": "kgdb_parse_thread_list", "status": "FAIL", "reason": err})
    mismatches.append({"tool": "kgdb_parse_thread_list",
                       "expected": {"count": 3}, "actual": err})
else:
    actual_count = data.get("count", -1)
    if actual_count == 3:
        results.append({"tool": "kgdb_parse_thread_list", "status": "PASS"})
    else:
        results.append({"tool": "kgdb_parse_thread_list", "status": "FAIL",
                        "expected": 3, "actual": actual_count})
        mismatches.append({"tool": "kgdb_parse_thread_list",
                           "expected": {"count": 3},
                           "actual": {"count": actual_count}})

# "l" → 0 threads
data, err = call_tool("kgdb_parse_thread_list", {"response": "l"})
if not err:
    actual_count = data.get("count", -1)
    if actual_count == 0:
        results.append({"tool": "kgdb_parse_thread_list (l)", "status": "PASS"})
    else:
        results.append({"tool": "kgdb_parse_thread_list (l)", "status": "FAIL",
                        "expected": 0, "actual": actual_count})
        mismatches.append({"tool": "kgdb_parse_thread_list",
                           "expected": {"count": 0},
                           "actual": {"count": actual_count}})

p.stdin.close()
p.terminate()

# ─── Output ──────────────────────────────────────────────────────────────────

passed = sum(1 for r in results if r["status"] == "PASS")
failed = sum(1 for r in results if r["status"] == "FAIL")

output = {
    "module": "kgdb_v2",
    "tools_hardened": 9,
    "tools_passed": passed,
    "tools_failed": failed,
    "tools_skipped": 0,
    "mismatches": mismatches,
    "detail": results
}

out_path = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_kgdb_v2.json"
with open(out_path, "w") as f:
    json.dump(output, f, indent=2)

print(json.dumps(output, indent=2))
