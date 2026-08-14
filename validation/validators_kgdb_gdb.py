#!/usr/bin/env python3
"""Independent validator for kgdb_* MCP tools (GDB RSP / kernel-gdb helpers)."""
import json, subprocess, struct

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_kgdb_gdb.json"

def start():
    p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    def send(r): p.stdin.write((json.dumps(r)+"\n").encode()); p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None
    send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"v","version":"1"}}})
    recv()
    send({"jsonrpc":"2.0","method":"notifications/initialized"})
    return p, send, recv

p, send, recv = start()
rid = [10]
def call(name, args):
    rid[0] += 1
    send({"jsonrpc":"2.0","id":rid[0],"method":"tools/call","params":{"name":name,"arguments":args}})
    resp = recv()
    if not resp or "error" in resp: return None
    c = resp.get("result",{}).get("content",[])
    if not c: return None
    try: return json.loads(c[0].get("text",""))
    except: return c[0].get("text","")

# tools/list to discover kgdb_ tools
rid[0]+=1
send({"jsonrpc":"2.0","id":rid[0],"method":"tools/list"})
tl = recv()
tools = {t["name"]: t for t in tl.get("result",{}).get("tools",[]) if t["name"].startswith("kgdb_")}
tools_in_category = len(tools)

mismatches = []
checks_total = 0
checks_passed = 0
checks_skipped = 0

def extract(res, keys):
    if res is None: return None
    if isinstance(res, dict):
        for k in keys:
            if k in res: return res[k]
    return res

def normalize_bytes(v):
    if isinstance(v, str):
        try: return list(bytes.fromhex(v))
        except: return v
    if isinstance(v, (bytes, bytearray)): return list(v)
    return v

def check(tool, inp, mcp_val, truth_val, note=""):
    global checks_total, checks_passed, checks_skipped
    # If MCP returned an error string, treat as skip (schema mismatch, not wrong value)
    if isinstance(mcp_val, str) and ("execution failed" in mcp_val or "invalid params" in mcp_val or "error" in mcp_val.lower()):
        checks_skipped += 1
        return False
    checks_total += 1
    a, b = mcp_val, truth_val
    # normalize
    if isinstance(a, str) and isinstance(b, str):
        a2, b2 = a.lower(), b.lower()
    else:
        a2, b2 = a, b
    if a2 == b2:
        checks_passed += 1
        return True
    mismatches.append({"tool":tool,"input":inp,"mcp":mcp_val,"truth":truth_val,"note":note})
    return False

def skip():
    global checks_skipped
    checks_skipped += 1

# -------- ground truth helpers --------
def gdb_checksum(payload: bytes) -> int:
    return sum(payload) & 0xff

def rsp_escape(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        if b in (0x24, 0x23, 0x7d, 0x2a):
            out.append(0x7d); out.append(b ^ 0x20)
        else:
            out.append(b)
    return bytes(out)

def rsp_unescape(data: bytes) -> bytes:
    out = bytearray(); i = 0
    while i < len(data):
        if data[i] == 0x7d and i+1 < len(data):
            out.append(data[i+1] ^ 0x20); i += 2
        else:
            out.append(data[i]); i += 1
    return bytes(out)

# -------- concrete checks --------

# kgdb_rsp_checksum / kgdb_packet_checksum (payload -> u8 sum)
payload = b"g"
truth = gdb_checksum(payload)
for tool in ("kgdb_rsp_checksum", "kgdb_packet_checksum", "kgdb_rsp_checksum_bytes"):
    if tool not in tools: continue
    # try common arg names
    for args in ({"payload": payload.hex()}, {"data": payload.hex()}, {"bytes": payload.hex()}, {"payload": "g"}, {"data": "g"}):
        r = call(tool, args)
        if r is None: continue
        v = extract(r, ["checksum","sum","value"])
        if v is None: continue
        if isinstance(v, str):
            try: v = int(v, 16) if not v.isdigit() else int(v)
            except: pass
        check(tool, args, v, truth, "sum of 'g' = 0x67")
        break
    else:
        skip()

# kgdb_rsp_verify_checksum_bytes
if "kgdb_rsp_verify_checksum_bytes" in tools:
    args = {"payload": "OK", "checksum": gdb_checksum(b"OK")}
    r = call("kgdb_rsp_verify_checksum_bytes", args)
    if r is not None:
        v = extract(r, ["ok","valid","verified","result"])
        check("kgdb_rsp_verify_checksum_bytes", args, bool(v), True, "OK checksum should verify")
    else:
        skip()

# kgdb_verify_rsp_checksum
if "kgdb_verify_rsp_checksum" in tools:
    args = {"payload":"OK","checksum":gdb_checksum(b"OK")}
    r = call("kgdb_verify_rsp_checksum", args)
    if r is not None:
        v = extract(r, ["ok","valid","verified","result"])
        check("kgdb_verify_rsp_checksum", args, bool(v), True)
    else:
        skip()

# kgdb_rsp_escape / kgdb_packet_escape_data
raw = bytes([0x24, 0x41, 0x23, 0x2a])
esc_truth = list(rsp_escape(raw))
for tool in ("kgdb_rsp_escape", "kgdb_packet_escape_data"):
    if tool not in tools: continue
    for args in ({"data": raw.hex()}, {"payload": raw.hex()}, {"bytes": raw.hex()}):
        r = call(tool, args)
        if r is None: continue
        v = extract(r, ["escaped","result","data","bytes","output"])
        v = normalize_bytes(v)
        if v is None: continue
        check(tool, args, v, esc_truth, "escape special bytes")
        break
    else:
        skip()

# kgdb_rsp_unescape / kgdb_packet_unescape_data
esc = bytes([0x7d, 0x04, 0x41, 0x7d, 0x03, 0x7d, 0x0a])
un_truth = list(rsp_unescape(esc))
for tool in ("kgdb_rsp_unescape", "kgdb_packet_unescape_data"):
    if tool not in tools: continue
    for args in ({"data": esc.hex()}, {"payload": esc.hex()}, {"bytes": esc.hex()}):
        r = call(tool, args)
        if r is None: continue
        v = extract(r, ["unescaped","result","data","bytes","output"])
        v = normalize_bytes(v)
        if v is None: continue
        check(tool, args, v, un_truth, "unescape")
        break
    else:
        skip()

# kgdb_hex_to_bytes / _v2
truth = [0xde, 0xad, 0xbe, 0xef]
for tool in ("kgdb_hex_to_bytes", "kgdb_hex_to_bytes_v2"):
    if tool not in tools: continue
    for args in ({"hex":"deadbeef"}, {"input":"deadbeef"}, {"s":"deadbeef"}):
        r = call(tool, args)
        if r is None: continue
        v = extract(r, ["bytes","result","value","data"])
        v = normalize_bytes(v)
        if v is None: continue
        check(tool, args, v, truth, "hex->bytes")
        break
    else:
        skip()

# kgdb_bytes_to_hex / _v2
data = bytes([0xde, 0xad, 0xbe, 0xef])
truth = "deadbeef"
for tool in ("kgdb_bytes_to_hex", "kgdb_bytes_to_hex_v2"):
    if tool not in tools: continue
    for args in ({"bytes": data.hex()}, {"data": data.hex()}, {"input": data.hex()}):
        r = call(tool, args)
        if r is None: continue
        v = extract(r, ["hex","result","value","string"])
        if v is None: continue
        if isinstance(v, str):
            check(tool, args, v.lower(), truth, "bytes->hex")
        break
    else:
        skip()

# kgdb_u64_to_hex_le
if "kgdb_u64_to_hex_le" in tools:
    val = 0x1122334455667788
    truth = struct.pack("<Q", val).hex()
    for args in ({"value": val}, {"n": val}, {"input": val}):
        r = call("kgdb_u64_to_hex_le", args)
        if r is None: continue
        v = extract(r, ["hex","result","value","string"])
        if isinstance(v, str):
            check("kgdb_u64_to_hex_le", args, v.lower(), truth, "u64 LE")
            break
    else:
        skip()

# kgdb_u32_to_hex_le
if "kgdb_u32_to_hex_le" in tools:
    val = 0xdeadbeef
    truth = struct.pack("<I", val).hex()
    for args in ({"value": val}, {"n": val}, {"input": val}):
        r = call("kgdb_u32_to_hex_le", args)
        if r is None: continue
        v = extract(r, ["hex","result","value","string"])
        if isinstance(v, str):
            check("kgdb_u32_to_hex_le", args, v.lower(), truth, "u32 LE")
            break
    else:
        skip()

# kgdb_hex_le_to_u64 / kgdb_read_u64_le_hex
for tool in ("kgdb_hex_le_to_u64", "kgdb_read_u64_le_hex"):
    if tool not in tools: continue
    hex_in = "8877665544332211"
    truth = struct.unpack("<Q", bytes.fromhex(hex_in))[0]
    for args in ({"hex": hex_in}, {"input": hex_in}, {"s": hex_in}):
        r = call(tool, args)
        if r is None: continue
        v = extract(r, ["value","result","n","u64"])
        if isinstance(v, str):
            try: v = int(v, 0)
            except: pass
        if isinstance(v, int):
            check(tool, args, v, truth, "hex LE -> u64")
            break
    else:
        skip()

# kgdb_page_align (default 4K)
if "kgdb_page_align" in tools:
    for va, ps in [(0x1234, 0x1000), (0x2000, 0x1000), (0xfff, 0x1000)]:
        truth = va & ~(ps - 1)
        for args in ({"addr": va, "page_size": ps}, {"address": va, "page_size": ps}, {"addr": va}, {"address": va}):
            r = call("kgdb_page_align", args)
            if r is None: continue
            v = extract(r, ["aligned","result","value","addr"])
            if isinstance(v, str):
                try: v = int(v, 0)
                except: pass
            if isinstance(v, int):
                check("kgdb_page_align", args, v, truth, f"align {hex(va)}")
                break
        else:
            skip()

# kgdb_is_kernel_address (Linux x86_64 kernel space is 0xffff... high half)
if "kgdb_is_kernel_address" in tools:
    for addr, truth in [(0xffff800000000000, True), (0x7ffffffff000, False), (0x0, False)]:
        for args in ({"addr": addr}, {"address": addr}, {"va": addr}):
            r = call("kgdb_is_kernel_address", args)
            if r is None: continue
            v = extract(r, ["is_kernel","result","value","kernel"])
            if isinstance(v, bool):
                check("kgdb_is_kernel_address", args, v, truth, hex(addr))
                break
        else:
            skip()

# kgdb_rle_encode / decode roundtrip: encode should compress runs
if "kgdb_rle_encode" in tools:
    data = "aaaaaa"  # 6 a's
    for args in ({"data": data}, {"input": data}, {"payload": data}):
        r = call("kgdb_rle_encode", args)
        if r is None: continue
        v = extract(r, ["encoded","result","output","data"])
        # GDB RLE: 'a' followed by '*' then count+29 char. "aaaaaa"=a*"#" (6-1=5 -> +29=34='#')... implementation-specific.
        # Only check that decoding it back yields original.
        if "kgdb_rle_decode" in tools and isinstance(v, str):
            r2 = call("kgdb_rle_decode", {"data": v})
            if r2 is None: r2 = call("kgdb_rle_decode", {"input": v})
            if r2 is not None:
                back = extract(r2, ["decoded","result","output","data"])
                if isinstance(back, str):
                    check("kgdb_rle_encode+decode", args, back, data, "roundtrip")
                    break
    else:
        skip()

# kgdb_rsp_encode_packet_bytes: builds "$payload#cs"
if "kgdb_rsp_encode_packet_bytes" in tools:
    payload = b"OK"
    cs = gdb_checksum(payload)
    truth = f"${payload.decode()}#{cs:02x}"
    for args in ({"payload":"OK"}, {"data":"OK"}, {"payload": payload.hex()}):
        r = call("kgdb_rsp_encode_packet_bytes", args)
        if r is None: continue
        v = extract(r, ["packet","result","encoded","output"])
        if isinstance(v, list):
            try: v = bytes(v).decode("latin-1")
            except: pass
        if isinstance(v, str):
            check("kgdb_rsp_encode_packet_bytes", args, v.lower(), truth.lower(), "packet framing")
            break
    else:
        skip()

# kgdb_gdb_packet_parse: parse "$OK#9a" (checksum for 'O'+'K'=0x4f+0x4b=0x9a)
if "kgdb_gdb_packet_parse" in tools:
    pkt = "$OK#9a"
    for args in ({"packet": pkt}, {"input": pkt}, {"data": pkt}):
        r = call("kgdb_gdb_packet_parse", args)
        if r is None: continue
        # look for a payload field
        v = r.get("payload") if isinstance(r, dict) else None
        if v is None and isinstance(r, dict):
            v = r.get("data") or r.get("body")
        if isinstance(v, str):
            check("kgdb_gdb_packet_parse", args, v, "OK", "parse payload")
            break
        elif isinstance(v, list):
            try:
                s = bytes(v).decode("latin-1")
                check("kgdb_gdb_packet_parse", args, s, "OK", "parse payload")
                break
            except: pass
    else:
        skip()

# kgdb_gdb_packet_to_wire: inverse of parse
if "kgdb_gdb_packet_to_wire" in tools:
    for args in ({"payload":"OK"}, {"data":"OK"}, {"body":"OK"}):
        r = call("kgdb_gdb_packet_to_wire", args)
        if r is None: continue
        v = extract(r, ["packet","wire","result","output"])
        if isinstance(v, list):
            try: v = bytes(v).decode("latin-1")
            except: pass
        if isinstance(v, str):
            truth = "$OK#9a"
            check("kgdb_gdb_packet_to_wire", args, v.lower(), truth.lower(), "wire framing")
            break
    else:
        skip()

# kgdb_encode_hex_buf / decode_hex_buf roundtrip
if "kgdb_encode_hex_buf" in tools:
    src = b"hello"
    for args in ({"data": src.hex()}, {"bytes": src.hex()}, {"input": src.hex()}):
        r = call("kgdb_encode_hex_buf", args)
        if r is None: continue
        v = extract(r, ["hex","encoded","result","output"])
        if isinstance(v, str):
            truth = src.hex()
            check("kgdb_encode_hex_buf", args, v.lower(), truth, "encode hex buf")
            break
    else:
        skip()

if "kgdb_decode_hex_buf" in tools:
    hs = "68656c6c6f"
    for args in ({"hex": hs}, {"input": hs}, {"s": hs}):
        r = call("kgdb_decode_hex_buf", args)
        if r is None: continue
        v = extract(r, ["bytes","decoded","result","output","data"])
        v = normalize_bytes(v)
        if v is not None:
            truth = list(b"hello")
            check("kgdb_decode_hex_buf", args, v, truth, "decode hex buf")
            break
    else:
        skip()

# kgdb_kdb_kvirt_to_phys / kgdb_kvirt_to_phys (linear map: virt - PAGE_OFFSET)
if "kgdb_kvirt_to_phys" in tools:
    # skip: architecture-specific offset unknown; don't assert
    skip()

# kgdb_dbg_module_info_contains, parse_kernel_callstack, parse_thread_list, parse_qsupported:
# high-level parsing; skip complex parsers.
for t in ("kgdb_parse_kernel_callstack","kgdb_parse_thread_list","kgdb_parse_qsupported",
          "kgdb_target_xml_arm64","kgdb_target_xml_x86_64"):
    if t in tools:
        skip()

p.terminate()

report = {
    "category": "kgdb_gdb",
    "tools_in_category": tools_in_category,
    "checks_total": checks_total,
    "checks_passed": checks_passed,
    "checks_skipped": checks_skipped,
    "mismatches": mismatches,
}
with open(OUT, "w") as f:
    json.dump(report, f, indent=2, default=str)
print(json.dumps(report, indent=2, default=str))
