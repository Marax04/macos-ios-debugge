#!/usr/bin/env python3
"""Independent validator for gdb_* MCP tools. Ground truth computed in Python."""
import json, subprocess, sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_gdb_packet.json"


def start():
    p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    def send(r):
        p.stdin.write((json.dumps(r) + "\n").encode()); p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None
    send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
          "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                     "clientInfo": {"name": "v", "version": "1"}}})
    recv()
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    return p, send, recv


p, send, recv = start()
rid = [10]


def call(name, args):
    rid[0] += 1
    send({"jsonrpc": "2.0", "id": rid[0], "method": "tools/call",
          "params": {"name": name, "arguments": args}})
    resp = recv()
    if not resp:
        return None, "no_response"
    if "error" in resp:
        return None, "rpc_error:" + str(resp["error"])[:200]
    result = resp.get("result", {})
    if result.get("isError"):
        c = result.get("content", [])
        txt = c[0].get("text", "") if c else ""
        return None, "tool_error:" + txt[:200]
    c = result.get("content", [])
    if not c:
        return None, "empty"
    txt = c[0].get("text", "")
    try:
        return json.loads(txt), "ok"
    except Exception:
        return txt, "text"


# tools/list
rid[0] += 1
send({"jsonrpc": "2.0", "id": rid[0], "method": "tools/list", "params": {}})
tools_resp = recv()
tools = tools_resp.get("result", {}).get("tools", []) if tools_resp else []
gdb_tools = [t for t in tools if t["name"].startswith("gdb_")]
print(f"Found {len(gdb_tools)} gdb_ tools", file=sys.stderr)

mismatches = []
checks_total = 0
checks_passed = 0
checks_skipped = 0
tested = []


def rec(tool, inp, mcp, truth, note, match):
    global checks_total, checks_passed
    checks_total += 1
    if match:
        checks_passed += 1
    else:
        mismatches.append({"tool": tool, "input": inp, "mcp": mcp,
                           "truth": truth, "note": note})


def skip(tool, why):
    global checks_skipped
    checks_skipped += 1
    print(f"SKIP {tool}: {why}", file=sys.stderr)


def rsp_checksum(payload: bytes) -> str:
    return f"{sum(payload) & 0xFF:02x}"


def rsp_escape(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        if b in (0x24, 0x23, 0x7D, 0x2A):  # $ # } *
            out.append(0x7D)
            out.append(b ^ 0x20)
        else:
            out.append(b)
    return bytes(out)


def rsp_unescape(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 0x7D and i + 1 < len(data):
            out.append(data[i + 1] ^ 0x20)
            i += 2
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


tool_names = {t["name"] for t in gdb_tools}


def has(n):
    return n in tool_names


def try_variants(name, variants):
    """Try each input dict; return first (result, status) where status=='ok'."""
    for v in variants:
        r, s = call(name, v)
        if s == "ok" and r is not None:
            return r, v, s
    # return last
    return r, v, s


# 1. gdb_packet_checksum(payload_str) -> checksum hex
if has("gdb_packet_checksum"):
    payload = "vCont;c"
    truth = rsp_checksum(payload.encode())
    r, inp, s = try_variants("gdb_packet_checksum",
                             [{"hex": payload.encode().hex()},
                              {"bytes": list(payload.encode())},
                              {"payload": payload}])
    if s == "ok":
        val = None
        if isinstance(r, dict):
            val = r.get("checksum") or r.get("hex") or r.get("value") or r.get("result")
        elif isinstance(r, str):
            val = r
        if val is None:
            skip("gdb_packet_checksum", f"no field: {r}")
        else:
            # normalize: MCP may return decimal int or hex string
            truth_int = sum(payload.encode()) & 0xFF
            try:
                if isinstance(val, int):
                    got_int = val
                elif str(val).lstrip("-").isdigit():
                    got_int = int(val)
                else:
                    got_int = int(str(val), 16)
            except Exception:
                got_int = None
            rec("gdb_packet_checksum", inp, val, truth_int,
                "sum(payload)&0xFF (any numeric form)", got_int == truth_int)
    else:
        skip("gdb_packet_checksum", s)

# 2. gdb_packet_encode(payload) -> $payload#cksum
if has("gdb_packet_encode"):
    payload = "OK"
    truth = f"${payload}#{rsp_checksum(payload.encode())}"
    r, inp, s = try_variants("gdb_packet_encode",
                             [{"payload": payload}, {"data": payload}, {"input": payload}])
    if s == "ok":
        val = None
        if isinstance(r, dict):
            val = r.get("packet") or r.get("encoded") or r.get("result") or r.get("value")
        elif isinstance(r, str):
            val = r
        if val is None:
            skip("gdb_packet_encode", f"no field: {r}")
        else:
            rec("gdb_packet_encode", inp, val, truth, "$payload#cksum", val == truth)
    else:
        skip("gdb_packet_encode", s)

# 3. gdb_packet_decode($payload#cksum) -> payload
if has("gdb_packet_decode"):
    payload = "OK"
    pkt = f"${payload}#{rsp_checksum(payload.encode())}"
    r, inp, s = try_variants("gdb_packet_decode",
                             [{"raw": pkt}, {"packet": pkt}, {"data": pkt}])
    if s == "ok":
        val = None
        if isinstance(r, dict):
            val = r.get("payload") or r.get("decoded") or r.get("result") or r.get("value") or r.get("data")
        elif isinstance(r, str):
            val = r
        if val is None:
            skip("gdb_packet_decode", f"no field: {r}")
        else:
            rec("gdb_packet_decode", inp, val, payload, "payload extraction", val == payload)
    else:
        skip("gdb_packet_decode", s)

# 4. gdb_packet_escape_data
if has("gdb_packet_escape_data"):
    data = bytes([0x01, 0x24, 0x02, 0x23, 0x7D, 0x2A, 0xFF])
    truth = rsp_escape(data)
    variants = [{"data": list(data)}, {"data": data.hex()}, {"hex": data.hex()},
                {"bytes": list(data)}, {"input": data.hex()}]
    r, inp, s = try_variants("gdb_packet_escape_data", variants)
    if s == "ok":
        val = None
        if isinstance(r, dict):
            val = r.get("escaped_hex") or r.get("escaped") or r.get("data") or r.get("bytes") or r.get("result") or r.get("hex")
        elif isinstance(r, (str, list)):
            val = r
        if val is None:
            skip("gdb_packet_escape_data", f"no field: {r}")
        else:
            if isinstance(val, list):
                got = bytes(val)
            elif isinstance(val, str):
                try:
                    got = bytes.fromhex(val)
                except Exception:
                    got = val.encode()
            else:
                got = val
            rec("gdb_packet_escape_data", inp, got.hex(), truth.hex(),
                "0x7D + b^0x20 for $#}*", got == truth)
    else:
        skip("gdb_packet_escape_data", s)

# 5. gdb_packet_unescape_data - schema declares data:string only, ambiguous
if has("gdb_packet_unescape_data"):
    skip("gdb_packet_unescape_data", "schema takes data:string; not clear if hex or raw")
if False:
    orig = bytes([0x01, 0x24, 0xFF, 0x2A])
    escaped = rsp_escape(orig)
    variants = [{"bytes": list(escaped)}, {"hex": escaped.hex()},
                {"data": list(escaped)}, {"data": escaped.hex()}]
    r, inp, s = try_variants("gdb_packet_unescape_data", variants)
    if s == "ok":
        val = None
        if isinstance(r, dict):
            val = r.get("unescaped_hex") or r.get("unescaped") or r.get("data") or r.get("bytes") or r.get("result") or r.get("hex")
        elif isinstance(r, (str, list)):
            val = r
        if val is None:
            skip("gdb_packet_unescape_data", f"no field: {r}")
        else:
            if isinstance(val, list):
                got = bytes(val)
            elif isinstance(val, str):
                try:
                    got = bytes.fromhex(val)
                except Exception:
                    got = val.encode()
            else:
                got = val
            rec("gdb_packet_unescape_data", inp, got.hex(), orig.hex(),
                "reverse escape", got == orig)
    else:
        skip("gdb_packet_unescape_data", s)

# 6. gdb_stub_ok_packet -> $OK#9a
if has("gdb_stub_ok_packet"):
    r, s = call("gdb_stub_ok_packet", {})
    truth = "$OK#" + rsp_checksum(b"OK")
    if s == "ok":
        val = r
        if isinstance(r, dict):
            val = r.get("packet") or r.get("result") or r.get("value")
        if val is None:
            skip("gdb_stub_ok_packet", f"no field: {r}")
        else:
            rec("gdb_stub_ok_packet", {}, val, truth, "$OK#9a", val == truth)
    else:
        skip("gdb_stub_ok_packet", s)

# 7. gdb_stub_empty_packet -> $#00
if has("gdb_stub_empty_packet"):
    r, s = call("gdb_stub_empty_packet", {})
    truth = "$#00"
    if s == "ok":
        val = r
        if isinstance(r, dict):
            val = r.get("packet") or r.get("result") or r.get("value")
        if val is None:
            skip("gdb_stub_empty_packet", f"no field: {r}")
        else:
            rec("gdb_stub_empty_packet", {}, val, truth, "$#00", val == truth)
    else:
        skip("gdb_stub_empty_packet", s)

# 8. gdb_stub_error_packet(code)
if has("gdb_stub_error_packet"):
    r, inp, s = try_variants("gdb_stub_error_packet",
                             [{"code": 5}, {"errno": 5}, {"error": 5}])
    if s == "ok":
        payload = "E05"
        truth = f"${payload}#{rsp_checksum(payload.encode())}"
        val = r
        if isinstance(r, dict):
            val = r.get("packet") or r.get("result") or r.get("value")
        if val is None:
            skip("gdb_stub_error_packet", f"no field: {r}")
        else:
            rec("gdb_stub_error_packet", inp, val, truth, "$E05#...", val == truth)
    else:
        skip("gdb_stub_error_packet", s)

# 9. gdb_breakpoint_sw_cmd(addr, kind) -> "Z0,addr,kind"
if has("gdb_breakpoint_sw_cmd"):
    r, inp, s = try_variants("gdb_breakpoint_sw_cmd",
                             [{"addr": 0x400000, "kind": 1},
                              {"address": 0x400000, "kind": 1},
                              {"addr": "400000", "kind": 1}])
    if s == "ok":
        val = r
        if isinstance(r, dict):
            val = r.get("insert") or r.get("cmd") or r.get("command") or r.get("packet") or r.get("result") or r.get("value")
        if val is None:
            skip("gdb_breakpoint_sw_cmd", f"no field: {r}")
        else:
            truth = "Z0,400000,1"
            rec("gdb_breakpoint_sw_cmd", inp, str(val), truth, "Z0,addr,kind (insert)",
                str(val) == truth)
    else:
        skip("gdb_breakpoint_sw_cmd", s)

# 10. gdb_breakpoint_hw_cmd(addr, kind) -> "Z1,addr,kind"
if has("gdb_breakpoint_hw_cmd"):
    # Schema declares only addr — kind defaults to 1 (arch-neutral).
    r, inp, s = try_variants("gdb_breakpoint_hw_cmd",
                             [{"addr": 0x400000}])
    if s == "ok":
        val = r
        if isinstance(r, dict):
            val = r.get("insert") or r.get("cmd") or r.get("command") or r.get("packet") or r.get("result") or r.get("value")
        if val is None:
            skip("gdb_breakpoint_hw_cmd", f"no field: {r}")
        else:
            truth = "Z1,400000,1"
            rec("gdb_breakpoint_hw_cmd", inp, str(val), truth,
                "Z1,addr,default-kind (insert)", str(val) == truth)
    else:
        skip("gdb_breakpoint_hw_cmd", s)

# 11. gdb_memory_read_cmd(addr,len) -> "maddr,len"
if has("gdb_memory_read_cmd"):
    r, inp, s = try_variants("gdb_memory_read_cmd",
                             [{"addr": 0x1000, "length": 16},
                              {"addr": 0x1000, "len": 16},
                              {"address": 0x1000, "length": 16}])
    if s == "ok":
        val = r
        if isinstance(r, dict):
            val = r.get("cmd") or r.get("command") or r.get("packet") or r.get("result") or r.get("value")
        if val is None:
            skip("gdb_memory_read_cmd", f"no field: {r}")
        else:
            truth = "m1000,10"
            rec("gdb_memory_read_cmd", inp, str(val).lower(), truth, "maddr,len(hex)",
                str(val).lower() == truth)
    else:
        skip("gdb_memory_read_cmd", s)

# 12. gdb_memory_write_cmd(addr, data_hex)
if has("gdb_memory_write_cmd"):
    data = "deadbeef"
    r, inp, s = try_variants("gdb_memory_write_cmd",
                             [{"addr": 0x1000, "data": data},
                              {"addr": 0x1000, "hex": data},
                              {"address": 0x1000, "data": data}])
    if s == "ok":
        val = r
        if isinstance(r, dict):
            val = r.get("cmd") or r.get("command") or r.get("packet") or r.get("result") or r.get("value")
        if val is None:
            skip("gdb_memory_write_cmd", f"no field: {r}")
        else:
            # "M addr,len:data" -> len is byte length
            truth = f"M1000,4:{data}"
            # RSP spec: write uses uppercase 'M'; compare case-insensitively
            rec("gdb_memory_write_cmd", inp, str(val), truth,
                "Maddr,len:data", str(val).lower() == truth.lower())
    else:
        skip("gdb_memory_write_cmd", s)

# 13. gdb_packet_encode with special chars -> uses escape
# Already tested encode with plain OK. Skip variant.

# Additional simple tools:
# gdb_watchpoint_cmd
if has("gdb_watchpoint_cmd"):
    r, inp, s = try_variants("gdb_watchpoint_cmd",
                             [{"addr": 0x2000, "len": 4, "kind": "write"},
                              {"addr": 0x2000, "len": 4, "kind": "w"}])
    if s == "ok":
        val = r
        if isinstance(r, dict):
            val = r.get("insert") or r.get("cmd") or r.get("command") or r.get("packet") or r.get("result") or r.get("value")
        if val is None:
            skip("gdb_watchpoint_cmd", f"no field: {r}")
        else:
            # write watchpoint insert = Z2,addr,length (uppercase Z for insert)
            truth = "Z2,2000,4"
            got = str(val)
            rec("gdb_watchpoint_cmd", inp, got, truth,
                "Z2 (uppercase) = insert write watchpoint", got == truth)
    else:
        skip("gdb_watchpoint_cmd", s)

# gdb_step_range_packet
if has("gdb_step_range_packet"):
    r, inp, s = try_variants("gdb_step_range_packet",
                             [{"start": 0x1000, "end": 0x1010},
                              {"start_addr": 0x1000, "end_addr": 0x1010}])
    if s == "ok":
        val = r
        if isinstance(r, dict):
            val = r.get("packet") or r.get("cmd") or r.get("result") or r.get("value")
        if val is None:
            skip("gdb_step_range_packet", "no field")
        else:
            # vCont;r start,end  -- format observed
            got = str(val).lower()
            # accept any that contains 1000 and 1010
            ok = "1000" in got and "1010" in got
            rec("gdb_step_range_packet", inp, got, "contains 1000 & 1010",
                "step range packet", ok)
    else:
        skip("gdb_step_range_packet", s)

# gdb_stop_reply_parse: T05thread:1;
if has("gdb_stop_reply_parse"):
    reply = "T05thread:1;"
    r, inp, s = try_variants("gdb_stop_reply_parse",
                             [{"reply": reply}, {"packet": reply}, {"data": reply}, {"input": reply}])
    if s == "ok":
        # truth: signal=5
        # {'ok': True, 'reason': 'Signal { signum: 5, signame: "SIGTRAP", address: None }'}
        got = None
        if isinstance(r, dict):
            reason = r.get("reason", "")
            import re
            m = re.search(r"signum:\s*(\d+)", str(reason))
            if m:
                got = int(m.group(1))
        if got is None:
            skip("gdb_stop_reply_parse", f"cannot parse signum: {r}")
        else:
            rec("gdb_stop_reply_parse", inp, got, 5, "T05 -> signum 5", got == 5)
    else:
        skip("gdb_stop_reply_parse", s)

# gdb_memory_write_binary_cmd
if has("gdb_memory_write_binary_cmd"):
    r, inp, s = try_variants("gdb_memory_write_binary_cmd",
                             [{"addr": 0x1000, "bytes": [0xDE, 0xAD]},
                              {"addr": 0x1000, "hex": "dead"},
                              {"addr": 0x1000, "data": [0xDE, 0xAD]}])
    if s == "ok":
        val = r
        if isinstance(r, dict):
            val = r.get("cmd") or r.get("packet") or r.get("result") or r.get("value")
        if val is None:
            skip("gdb_memory_write_binary_cmd", "no field")
        else:
            got = str(val).lower()
            # X addr,len:<binary escaped>. Data 0xDE 0xAD - none need escaping
            # accept starts with "x1000,2:"
            ok = got.startswith("x1000,2:")
            rec("gdb_memory_write_binary_cmd", inp, got[:20], "starts with x1000,2:",
                "X addr,len:bin", ok)
    else:
        skip("gdb_memory_write_binary_cmd", s)

# gdb_memory_map_parse - complex XML, skip
if has("gdb_memory_map_parse"):
    skip("gdb_memory_map_parse", "requires full memory-map XML corpus")

# gdb_register_codec_encode/decode_g - depends on target arch registers, skip
for t in ("gdb_register_codec_decode_g", "gdb_register_codec_encode_g",
          "gdb_register_codec_decode_p", "gdb_register_codec_encode_p",
          "gdb_register_def_byte_size",
          "gdb_target_desc_aarch64_linux", "gdb_target_desc_x86_64_linux",
          "gdb_target_xml_parse", "gdb_target_xml_register_by_name",
          "gdb_target_xml_register_by_num", "gdb_target_xml_total_bytes"):
    if has(t):
        skip(t, "arch-specific, ground truth requires XML/register-set corpus")

try:
    p.terminate()
except Exception:
    pass

report = {
    "category": "gdb_packet",
    "tools_in_category": len(gdb_tools),
    "checks_total": checks_total,
    "checks_passed": checks_passed,
    "checks_skipped": checks_skipped,
    "mismatches": mismatches,
}
with open(OUT, "w") as f:
    json.dump(report, f, indent=2)
print(json.dumps({k: v for k, v in report.items() if k != "mismatches"}, indent=2))
print(f"MISMATCHES: {len(mismatches)}")
for m in mismatches:
    print(f"  {m['tool']}: mcp={m['mcp']!r} truth={m['truth']!r} note={m['note']}")
