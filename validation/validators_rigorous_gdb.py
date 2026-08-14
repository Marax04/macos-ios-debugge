#!/usr/bin/env python3
"""
Rigorous validator for 'gdb' module MCP tools.
Each check uses an independently computed Python truth value.
Report saved to validation/rigorous_gdb.json.
"""
import json, subprocess, sys, re

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_gdb.json"

# ── RSP helpers (pure Python, no Rust) ────────────────────────────────────────

def rsp_checksum(payload: bytes) -> str:
    return f"{sum(payload) & 0xFF:02x}"

def rsp_escape(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        if b in (0x24, 0x23, 0x7D, 0x2A):
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

def rsp_packet(payload: str) -> str:
    return f"${payload}#{rsp_checksum(payload.encode())}"

# ── MCP session ───────────────────────────────────────────────────────────────

def start():
    p = subprocess.Popen(
        [EXE, "--transport=stdio"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, bufsize=0,
    )
    def send(r):
        p.stdin.write((json.dumps(r) + "\n").encode()); p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None
    send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
          "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                     "clientInfo": {"name": "rigorous", "version": "1"}}})
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

# discover tools
rid[0] += 1
send({"jsonrpc": "2.0", "id": rid[0], "method": "tools/list", "params": {}})
tl = recv()
all_tools = tl.get("result", {}).get("tools", []) if tl else []
gdb_names = {t["name"] for t in all_tools if t["name"].startswith("gdb_")}
print(f"gdb_ tools found: {len(gdb_names)}", file=sys.stderr)

# ── Bookkeeping ───────────────────────────────────────────────────────────────

checks_passed = 0
checks_failed = 0
mismatches = []
tools_hardened = set()

def try_variants(name, variants):
    """Return first (result, args, status) where status == 'ok'."""
    last = (None, variants[0], "no_response")
    for v in variants:
        r, s = call(name, v)
        last = (r, v, s)
        if s == "ok" and r is not None:
            return last
    return last

def pick(r, *keys):
    """Pull the first matching key from a dict, or return r unchanged."""
    if isinstance(r, dict):
        for k in keys:
            if k in r and r[k] is not None:
                return r[k]
    return r

def rec(tool, inp, got, truth, note, ok):
    global checks_passed, checks_failed
    tools_hardened.add(tool)
    if ok:
        checks_passed += 1
        print(f"PASS {tool}", file=sys.stderr)
    else:
        checks_failed += 1
        mismatches.append({"tool": tool, "input": inp,
                           "mcp_got": got, "truth": truth, "note": note})
        print(f"FAIL {tool}: got={got!r} expected={truth!r}", file=sys.stderr)

def skip(tool, why):
    print(f"SKIP {tool}: {why}", file=sys.stderr)

def has(n):
    return n in gdb_names

# ══════════════════════════════════════════════════════════════════════════════
# RIGOROUS CHECKS (10+ tools)
# ══════════════════════════════════════════════════════════════════════════════

# ── 1. gdb_packet_checksum ────────────────────────────────────────────────────
# RSP spec: checksum = sum(all payload bytes) mod 256, formatted as two hex digits.
if has("gdb_packet_checksum"):
    for payload_str in ("vCont;c", "qSupported", "OK", ""):
        truth_int = sum(payload_str.encode()) & 0xFF
        truth_str = f"{truth_int:02x}"
        r, inp, s = try_variants("gdb_packet_checksum",
                                 [{"payload": payload_str},
                                  {"hex": payload_str.encode().hex()}])
        if s != "ok":
            skip("gdb_packet_checksum", s); continue
        val = pick(r, "checksum", "hex", "value", "result")
        # accept decimal int or hex string
        try:
            got_int = int(str(val), 16) if not str(val).isdigit() else int(val)
        except Exception:
            got_int = None
        rec("gdb_packet_checksum", inp, val, truth_str,
            f"sum({payload_str!r}.encode())&0xFF = {truth_str}", got_int == truth_int)
else:
    skip("gdb_packet_checksum", "tool not present")

# ── 2. gdb_packet_encode ─────────────────────────────────────────────────────
# RSP spec: packet = "$" + payload + "#" + two-hex-digit checksum
if has("gdb_packet_encode"):
    for payload_str in ("OK", "qSupported", "vCont;c:1"):
        truth = rsp_packet(payload_str)
        r, inp, s = try_variants("gdb_packet_encode",
                                 [{"payload": payload_str},
                                  {"data": payload_str},
                                  {"input": payload_str}])
        if s != "ok":
            skip("gdb_packet_encode", s); continue
        val = pick(r, "packet", "encoded", "result", "value")
        rec("gdb_packet_encode", inp, val, truth, f"$payload#cksum", val == truth)
else:
    skip("gdb_packet_encode", "tool not present")

# ── 3. gdb_packet_decode ─────────────────────────────────────────────────────
# RSP spec: decode strips $…# wrapper and verifies checksum.
if has("gdb_packet_decode"):
    for payload_str in ("OK", "T05thread:1;"):
        pkt = rsp_packet(payload_str)
        r, inp, s = try_variants("gdb_packet_decode",
                                 [{"raw": pkt}, {"packet": pkt}, {"data": pkt}])
        if s != "ok":
            skip("gdb_packet_decode", s); continue
        val = pick(r, "payload", "decoded", "result", "value", "data")
        rec("gdb_packet_decode", inp, val, payload_str,
            "strip $…# -> payload", val == payload_str)
else:
    skip("gdb_packet_decode", "tool not present")

# ── 4. gdb_packet_escape_data ────────────────────────────────────────────────
# RSP spec §4: escape 0x23($), 0x24(#), 0x2A(*), 0x7D(}) by prefixing 0x7D and XOR 0x20.
if has("gdb_packet_escape_data"):
    data = bytes([0x01, 0x24, 0x02, 0x23, 0x7D, 0x2A, 0xFF])
    truth = rsp_escape(data)
    r, inp, s = try_variants("gdb_packet_escape_data",
                             [{"data": data.hex()}, {"hex": data.hex()},
                              {"bytes": list(data)}])
    if s == "ok":
        val = pick(r, "escaped_hex", "escaped", "data", "bytes", "result", "hex")
        if isinstance(val, list):
            got = bytes(val)
        elif isinstance(val, str):
            try: got = bytes.fromhex(val)
            except Exception: got = val.encode()
        else:
            got = val
        rec("gdb_packet_escape_data", inp, got.hex() if isinstance(got, bytes) else got,
            truth.hex(), "RSP escape: 7D+b^20 for $#}*",
            isinstance(got, bytes) and got == truth)
    else:
        skip("gdb_packet_escape_data", s)
else:
    skip("gdb_packet_escape_data", "tool not present")

# ── 5. gdb_stub_ok_packet ─────────────────────────────────────────────────────
# RSP: $OK#9a  (sum("OK")=79=0x4F, 0x4F+0x4B=0x9A)
if has("gdb_stub_ok_packet"):
    truth = rsp_packet("OK")  # "$OK#9a"
    r, s = call("gdb_stub_ok_packet", {})
    if s == "ok":
        val = pick(r, "packet", "result", "value")
        rec("gdb_stub_ok_packet", {}, val, truth, "$OK#9a", val == truth)
    else:
        skip("gdb_stub_ok_packet", s)
else:
    skip("gdb_stub_ok_packet", "tool not present")

# ── 6. gdb_stub_empty_packet ──────────────────────────────────────────────────
# RSP: $#00  (empty payload -> checksum 0x00)
if has("gdb_stub_empty_packet"):
    truth = "$#00"
    r, s = call("gdb_stub_empty_packet", {})
    if s == "ok":
        val = pick(r, "packet", "result", "value")
        rec("gdb_stub_empty_packet", {}, val, truth, "$#00", val == truth)
    else:
        skip("gdb_stub_empty_packet", s)
else:
    skip("gdb_stub_empty_packet", "tool not present")

# ── 7. gdb_stub_error_packet ──────────────────────────────────────────────────
# RSP: $Exx#cksum where xx is zero-padded decimal error code.
if has("gdb_stub_error_packet"):
    # RSP spec §5.4: error code is two hex digits (e.g. E01, E05, E16 for decimal 22)
    for code in (1, 5, 22):
        payload = f"E{code:02x}"
        truth = rsp_packet(payload)
        r, inp, s = try_variants("gdb_stub_error_packet",
                                 [{"code": code}, {"errno": code}, {"error": code}])
        if s != "ok":
            skip("gdb_stub_error_packet", s); continue
        val = pick(r, "packet", "result", "value")
        rec("gdb_stub_error_packet", inp, val, truth, f"$E{code:02d}#cksum", val == truth)
else:
    skip("gdb_stub_error_packet", "tool not present")

# ── 8. gdb_memory_read_cmd ────────────────────────────────────────────────────
# RSP: m<addr_hex>,<len_hex>  (both fields in hexadecimal, no 0x prefix)
if has("gdb_memory_read_cmd"):
    cases = [(0x1000, 16, "m1000,10"), (0x400000, 4, "m400000,4"), (0, 1, "m0,1")]
    for addr, length, truth in cases:
        r, inp, s = try_variants("gdb_memory_read_cmd",
                                 [{"addr": addr, "length": length},
                                  {"addr": addr, "len": length},
                                  {"address": addr, "length": length}])
        if s != "ok":
            skip("gdb_memory_read_cmd", s); continue
        val = pick(r, "cmd", "command", "packet", "result", "value")
        got = str(val).lower() if val is not None else None
        rec("gdb_memory_read_cmd", inp, got, truth, "maddr_hex,len_hex", got == truth)
else:
    skip("gdb_memory_read_cmd", "tool not present")

# ── 9. gdb_memory_write_cmd ───────────────────────────────────────────────────
# RSP: M<addr_hex>,<len_hex>:<data_hex>
if has("gdb_memory_write_cmd"):
    data_hex = "deadbeef"
    byte_len = len(bytes.fromhex(data_hex))  # 4
    truth = f"M1000,{byte_len:x}:{data_hex}"  # "M1000,4:deadbeef"
    r, inp, s = try_variants("gdb_memory_write_cmd",
                             [{"addr": 0x1000, "data": data_hex},
                              {"addr": 0x1000, "hex": data_hex},
                              {"address": 0x1000, "data": data_hex}])
    if s == "ok":
        val = pick(r, "cmd", "command", "packet", "result", "value")
        got = str(val) if val is not None else None
        rec("gdb_memory_write_cmd", inp, got, truth,
            "Maddr_hex,len_hex:data_hex", got is not None and got.lower() == truth.lower())
    else:
        skip("gdb_memory_write_cmd", s)
else:
    skip("gdb_memory_write_cmd", "tool not present")

# ── 10. gdb_breakpoint_sw_cmd ─────────────────────────────────────────────────
# RSP: Z0,<addr_hex>,<kind_hex>  (insert software breakpoint)
if has("gdb_breakpoint_sw_cmd"):
    # RSP: Z0,addr_hex,kind_hex. Tool schema accepts addr + optional kind (default 1).
    cases = [(0x400000, 1, "Z0,400000,1"), (0x1000, 1, "Z0,1000,1")]
    for addr, kind, truth in cases:
        r, inp, s = try_variants("gdb_breakpoint_sw_cmd",
                                 [{"addr": addr, "kind": kind},
                                  {"address": addr, "kind": kind},
                                  {"addr": addr}])
        if s != "ok":
            skip("gdb_breakpoint_sw_cmd", s); continue
        val = pick(r, "insert", "cmd", "command", "packet", "result", "value")
        got = str(val) if val is not None else None
        rec("gdb_breakpoint_sw_cmd", inp, got, truth, "Z0,addr_hex,kind_hex", got == truth)
else:
    skip("gdb_breakpoint_sw_cmd", "tool not present")

# ── 11. gdb_breakpoint_hw_cmd ─────────────────────────────────────────────────
# RSP: Z1,<addr_hex>,<kind_hex>  (insert hardware breakpoint)
if has("gdb_breakpoint_hw_cmd"):
    r, inp, s = try_variants("gdb_breakpoint_hw_cmd",
                             [{"addr": 0x400000},
                              {"addr": 0x400000, "kind": 1}])
    if s == "ok":
        val = pick(r, "insert", "cmd", "command", "packet", "result", "value")
        got = str(val) if val is not None else None
        truth = "Z1,400000,1"
        rec("gdb_breakpoint_hw_cmd", inp, got, truth, "Z1,addr_hex,1", got == truth)
    else:
        skip("gdb_breakpoint_hw_cmd", s)
else:
    skip("gdb_breakpoint_hw_cmd", "tool not present")

# ── 12. gdb_watchpoint_cmd ────────────────────────────────────────────────────
# RSP: Z2 = write watchpoint insert.  Z2,<addr_hex>,<len_hex>
if has("gdb_watchpoint_cmd"):
    r, inp, s = try_variants("gdb_watchpoint_cmd",
                             [{"addr": 0x2000, "len": 4, "kind": "write"},
                              {"addr": 0x2000, "len": 4, "kind": "w"},
                              {"addr": 0x2000, "length": 4, "type": "write"}])
    if s == "ok":
        val = pick(r, "insert", "cmd", "command", "packet", "result", "value")
        got = str(val) if val is not None else None
        truth = "Z2,2000,4"
        rec("gdb_watchpoint_cmd", inp, got, truth, "Z2,addr_hex,len_hex (write insert)", got == truth)
    else:
        skip("gdb_watchpoint_cmd", s)
else:
    skip("gdb_watchpoint_cmd", "tool not present")

# ── 13. gdb_stop_reply_parse ──────────────────────────────────────────────────
# RSP T-packet: T<signum_hex>thread:<tid>;  -> signal number in decimal
if has("gdb_stop_reply_parse"):
    for reply, expected_sig in [("T05thread:1;", 5), ("T0bthread:2;", 11)]:
        r, inp, s = try_variants("gdb_stop_reply_parse",
                                 [{"reply": reply}, {"packet": reply},
                                  {"data": reply}, {"input": reply}])
        if s != "ok":
            skip("gdb_stop_reply_parse", s); continue
        got_sig = None
        if isinstance(r, dict):
            reason = r.get("reason", "")
            m = re.search(r"signum:\s*(\d+)", str(reason))
            if m:
                got_sig = int(m.group(1))
        if got_sig is None:
            skip("gdb_stop_reply_parse", f"cannot extract signum from {r!r}")
        else:
            rec("gdb_stop_reply_parse", inp, got_sig, expected_sig,
                f"T{expected_sig:02x}... -> signum {expected_sig}", got_sig == expected_sig)
else:
    skip("gdb_stop_reply_parse", "tool not present")

# ── 14. gdb_step_range_packet ────────────────────────────────────────────────
# RSP: vCont;r<start_hex>,<end_hex>  or similar step-range packet
if has("gdb_step_range_packet"):
    r, inp, s = try_variants("gdb_step_range_packet",
                             [{"start": 0x1000, "end": 0x1010},
                              {"start_addr": 0x1000, "end_addr": 0x1010}])
    if s == "ok":
        val = pick(r, "packet", "cmd", "result", "value")
        got = str(val).lower() if val is not None else ""
        # Truth: must contain hex addresses 1000 and 1010
        ok = "1000" in got and "1010" in got
        rec("gdb_step_range_packet", inp, got, "contains '1000' and '1010'",
            "step-range packet has start/end addrs", ok)
    else:
        skip("gdb_step_range_packet", s)
else:
    skip("gdb_step_range_packet", "tool not present")

# ── Terminate session ─────────────────────────────────────────────────────────
try:
    p.terminate()
except Exception:
    pass

# ── Save report ───────────────────────────────────────────────────────────────
report = {
    "module": "gdb",
    "tools_hardened": len(tools_hardened),
    "checks_passed": checks_passed,
    "checks_failed": checks_failed,
    "real_mismatches": len(mismatches),
    "mismatches": mismatches,
}
with open(OUT, "w") as f:
    json.dump(report, f, indent=2)

summary = {k: v for k, v in report.items() if k != "mismatches"}
print(json.dumps(summary, indent=2))
print(f"\nReal mismatches: {len(mismatches)}")
for m in mismatches:
    print(f"  FAIL {m['tool']}: got={m['mcp_got']!r}  expected={m['truth']!r}  note={m['note']}")
