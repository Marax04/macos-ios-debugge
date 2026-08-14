#!/usr/bin/env python3
"""Independent validator for net_parse_* MCP tools.

Compares MCP tool output vs ground-truth computed inline (Ethernet/IPv4/IPv6/
TCP/UDP/ICMP/ARP header parsing per RFC 791/793/768/792/826 and IEEE 802.3).
"""
import json, subprocess, struct, sys, os

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_net_parse.json"
PREFIX = "net_parse_"

# -------------------- MCP transport --------------------
def start():
    p = subprocess.Popen([EXE, "--transport=stdio"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, bufsize=0)
    def send(r):
        p.stdin.write((json.dumps(r)+"\n").encode()); p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None
    send({"jsonrpc":"2.0","id":1,"method":"initialize",
          "params":{"protocolVersion":"2024-11-05","capabilities":{},
                    "clientInfo":{"name":"v","version":"1"}}})
    recv()
    send({"jsonrpc":"2.0","method":"notifications/initialized"})
    return p, send, recv

p, send, recv = start()
rid = [10]

def call(name, args):
    rid[0] += 1
    send({"jsonrpc":"2.0","id":rid[0],"method":"tools/call",
          "params":{"name":name,"arguments":args}})
    resp = recv()
    if not resp or "error" in resp:
        return None
    c = resp.get("result",{}).get("content",[])
    if not c: return None
    txt = c[0].get("text","")
    try: return json.loads(txt)
    except: return txt

def list_tools():
    rid[0] += 1
    send({"jsonrpc":"2.0","id":rid[0],"method":"tools/list","params":{}})
    resp = recv()
    return resp.get("result",{}).get("tools",[]) if resp else []

tools = [t for t in list_tools() if t["name"].startswith(PREFIX)]
tool_names = {t["name"]: t for t in tools}
print(f"Discovered {len(tools)} tools with prefix {PREFIX}")

mismatches = []
checks_total = 0
checks_passed = 0
checks_skipped = 0

def get_val(d, *keys):
    if not isinstance(d, dict): return None
    for k in keys:
        if k in d and d[k] is not None: return d[k]
    return None

def try_input_variants(tool, variants):
    """Try each variant until one returns a non-error dict; return (args, result)."""
    for v in variants:
        r = call(tool, v)
        if isinstance(r, dict) and r:
            # Reject if it looks like a stub error
            if any(k in r for k in ("error","Error")): continue
            return v, r
    return None, None

def check(tool, args, mcp_val, truth_val, note=""):
    global checks_total, checks_passed
    checks_total += 1
    # normalize
    def norm(x):
        if isinstance(x, str):
            xs = x.lower().replace(":","").replace("-","").replace(" ","")
            return xs
        return x
    a, b = mcp_val, truth_val
    if isinstance(a, float) or isinstance(b, float):
        try:
            if abs(float(a)-float(b)) < 1e-6:
                checks_passed += 1; return
        except: pass
    if a == b or norm(a) == norm(b):
        checks_passed += 1; return
    mismatches.append({"tool":tool,"input":args,"mcp":mcp_val,"truth":truth_val,"note":note})

def skip(reason):
    global checks_skipped
    checks_skipped += 1
    print(f"  skip: {reason}")

# -------------------- Ground-truth packet builders --------------------
def build_eth(dst=b"\xaa\xbb\xcc\xdd\xee\xff", src=b"\x11\x22\x33\x44\x55\x66", etype=0x0800):
    return dst + src + struct.pack("!H", etype)

def ip_checksum(hdr):
    if len(hdr) % 2: hdr += b"\x00"
    s = 0
    for i in range(0, len(hdr), 2):
        s += (hdr[i] << 8) | hdr[i+1]
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def build_ipv4(src="10.0.0.1", dst="10.0.0.2", proto=6, payload=b"", ihl=5, ttl=64, ident=0x1234, flags_frag=0x4000, tos=0):
    import ipaddress
    ver_ihl = (4 << 4) | ihl
    tot_len = ihl*4 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s",
        ver_ihl, tos, tot_len, ident, flags_frag, ttl, proto, 0,
        ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    csum = ip_checksum(hdr)
    hdr = hdr[:10] + struct.pack("!H", csum) + hdr[12:]
    return hdr + payload

def build_ipv6(src="2001:db8::1", dst="2001:db8::2", nxt=6, hop=64, payload=b"", flow=0, tclass=0):
    import ipaddress
    vtcfl = (6 << 28) | (tclass << 20) | flow
    hdr = struct.pack("!IHBB16s16s",
        vtcfl, len(payload), nxt, hop,
        ipaddress.IPv6Address(src).packed, ipaddress.IPv6Address(dst).packed)
    return hdr + payload

def build_tcp(sport=1234, dport=80, seq=0x11223344, ack=0x55667788, flags=0x02, window=8192, data_offset=5, payload=b""):
    off_flags = (data_offset << 12) | flags
    return struct.pack("!HHIIHHHH", sport, dport, seq, ack, off_flags, window, 0, 0) + payload

def build_udp(sport=1234, dport=53, payload=b"hello"):
    length = 8 + len(payload)
    return struct.pack("!HHHH", sport, dport, length, 0) + payload

def build_icmp(itype=8, code=0, ident=0x1234, seq=1, payload=b"abcd"):
    hdr = struct.pack("!BBHHH", itype, code, 0, ident, seq)
    csum = ip_checksum(hdr + payload)
    hdr = struct.pack("!BBHHH", itype, code, csum, ident, seq)
    return hdr + payload

def build_arp(op=1, sha=b"\x11\x22\x33\x44\x55\x66", spa="10.0.0.1",
              tha=b"\x00\x00\x00\x00\x00\x00", tpa="10.0.0.2"):
    import ipaddress
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + sha + \
           ipaddress.IPv4Address(spa).packed + tha + ipaddress.IPv4Address(tpa).packed

def hex_of(b): return b.hex()

# -------------------- Per-tool checks --------------------
def maybe(tool):
    return tool in tool_names

def input_variants_for_bytes(b):
    h = hex_of(b)
    lst = list(b)
    return [
        {"data": h},
        {"bytes": h},
        {"hex": h},
        {"packet": h},
        {"data": lst},
        {"bytes": lst},
    ]

# ethernet
if maybe("net_parse_ethernet_v2") or maybe("net_parse_ethernet_ext"):
    pkt = build_eth(etype=0x0800)
    for tool in ["net_parse_ethernet_v2", "net_parse_ethernet_ext"]:
        if not maybe(tool): continue
        args, r = try_input_variants(tool, input_variants_for_bytes(pkt))
        if not r:
            skip(f"{tool}: no input variant accepted"); continue
        # ethertype
        et = get_val(r, "ethertype", "ether_type", "type", "etype")
        if et is not None:
            if isinstance(et, str):
                try: et = int(et, 0)
                except: pass
            check(tool, args, et, 0x0800, "ethertype IPv4")
        else:
            skip(f"{tool}: no ethertype field")

# ipv4
if maybe("net_parse_ipv4_v2"):
    tool = "net_parse_ipv4_v2"
    ip = build_ipv4(src="10.0.0.1", dst="10.0.0.2", proto=17, payload=b"", ttl=64, ident=0x1234)
    args, r = try_input_variants(tool, input_variants_for_bytes(ip))
    if r:
        ver = get_val(r, "version");
        if ver is not None: check(tool, args, ver, 4, "version")
        ttl = get_val(r, "ttl", "hop_limit")
        if ttl is not None: check(tool, args, ttl, 64, "ttl")
        proto = get_val(r, "protocol", "proto", "next_protocol")
        if proto is not None:
            if isinstance(proto, str):
                try: proto_i = int(proto, 0)
                except: proto_i = proto
            else:
                proto_i = proto
            check(tool, args, proto_i, 17, "protocol=UDP")
        src = get_val(r, "src", "source", "src_ip", "source_ip", "src_addr")
        if src: check(tool, args, src, "10.0.0.1", "src ip")
        dst = get_val(r, "dst", "destination", "dst_ip", "destination_ip", "dst_addr")
        if dst: check(tool, args, dst, "10.0.0.2", "dst ip")
    else:
        skip(f"{tool}: no input variant accepted")

# ipv6
for tool in ["net_parse_ipv6_v2", "net_parse_ipv6_full"]:
    if not maybe(tool): continue
    ip6 = build_ipv6(src="2001:db8::1", dst="2001:db8::2", nxt=17, hop=32, payload=b"hi")
    args, r = try_input_variants(tool, input_variants_for_bytes(ip6))
    if not r:
        skip(f"{tool}: no input variant accepted"); continue
    ver = get_val(r, "version")
    if ver is not None: check(tool, args, ver, 6, "version")
    hop = get_val(r, "hop_limit", "ttl", "hop")
    if hop is not None: check(tool, args, hop, 32, "hop_limit")
    nxt = get_val(r, "next_header", "next", "nxt", "protocol")
    if nxt is not None:
        try: nxt_i = int(nxt, 0) if isinstance(nxt,str) else nxt
        except: nxt_i = nxt
        check(tool, args, nxt_i, 17, "next_header=UDP")

# tcp
if maybe("net_parse_tcp_v2"):
    tool = "net_parse_tcp_v2"
    tcp = build_tcp(sport=1234, dport=80, seq=0x11223344, ack=0x55667788, flags=0x12)  # SYN+ACK
    args, r = try_input_variants(tool, input_variants_for_bytes(tcp))
    if r:
        sp = get_val(r, "src_port", "source_port", "sport")
        if sp is not None: check(tool, args, sp, 1234, "sport")
        dp = get_val(r, "dst_port", "destination_port", "dport")
        if dp is not None: check(tool, args, dp, 80, "dport")
        seq = get_val(r, "sequence", "seq", "seq_num", "sequence_number")
        if seq is not None: check(tool, args, seq, 0x11223344, "seq")
        acknum = get_val(r, "acknowledgment", "ack", "ack_num", "acknowledgment_number", "ack_number")
        if acknum is not None: check(tool, args, acknum, 0x55667788, "ack")
        # SYN + ACK
        flags = get_val(r, "flags")
        if isinstance(flags, dict):
            if "syn" in {k.lower() for k in flags}:
                check(tool, args, bool(flags.get("syn") or flags.get("SYN")), True, "SYN flag")
                check(tool, args, bool(flags.get("ack") or flags.get("ACK")), True, "ACK flag")
        elif isinstance(flags, int):
            check(tool, args, flags & 0x12, 0x12, "flags SYN+ACK bits")
    else:
        skip(f"{tool}: no input variant accepted")

# udp
if maybe("net_parse_udp_v2"):
    tool = "net_parse_udp_v2"
    payload = b"hello"
    udp = build_udp(sport=53535, dport=53, payload=payload)
    args, r = try_input_variants(tool, input_variants_for_bytes(udp))
    if r:
        sp = get_val(r, "src_port", "source_port", "sport")
        if sp is not None: check(tool, args, sp, 53535, "sport")
        dp = get_val(r, "dst_port", "destination_port", "dport")
        if dp is not None: check(tool, args, dp, 53, "dport")
        ln = get_val(r, "length", "len")
        if ln is not None: check(tool, args, ln, 8+len(payload), "udp length")
    else:
        skip(f"{tool}: no input variant accepted")

# icmp
if maybe("net_parse_icmp_v2"):
    tool = "net_parse_icmp_v2"
    icmp = build_icmp(itype=8, code=0)
    args, r = try_input_variants(tool, input_variants_for_bytes(icmp))
    if r:
        t = get_val(r, "type", "icmp_type")
        if t is not None:
            try: t_i = int(t,0) if isinstance(t,str) else t
            except: t_i = t
            check(tool, args, t_i, 8, "echo request")
        c = get_val(r, "code")
        if c is not None: check(tool, args, c, 0, "code=0")
    else:
        skip(f"{tool}: no input variant accepted")

if maybe("net_parse_icmp_echo"):
    tool = "net_parse_icmp_echo"
    icmp = build_icmp(itype=8, code=0, ident=0xBEEF, seq=42)
    args, r = try_input_variants(tool, input_variants_for_bytes(icmp))
    if r:
        i = get_val(r, "identifier", "id", "ident")
        if i is not None: check(tool, args, i, 0xBEEF, "ident")
        s = get_val(r, "sequence", "seq", "sequence_number")
        if s is not None: check(tool, args, s, 42, "seq")
    else:
        skip(f"{tool}: no input variant accepted")

# arp
if maybe("net_parse_arp_v2"):
    tool = "net_parse_arp_v2"
    arp = build_arp(op=1, spa="10.0.0.1", tpa="10.0.0.2")
    args, r = try_input_variants(tool, input_variants_for_bytes(arp))
    if r:
        op = get_val(r, "operation", "op", "opcode")
        if op is not None:
            # ARP opcode 1 = "Request" per RFC 826; accept both numeric and semantic names
            if isinstance(op, str):
                s = op.strip()
                if s.lstrip('-').isdigit() or s.lower().startswith('0x'):
                    try: op_i = int(s, 0)
                    except: op_i = op
                elif s.lower() in ('request', 'arp_request', 'req'):
                    op_i = 1
                elif s.lower() in ('reply', 'response', 'arp_reply'):
                    op_i = 2
                else:
                    op_i = op
            else:
                op_i = op
            check(tool, args, op_i, 1, "ARP request opcode")
        spa = get_val(r, "sender_ip", "spa", "src_ip", "sender_protocol_address")
        if spa: check(tool, args, spa, "10.0.0.1", "sender ip")
        tpa = get_val(r, "target_ip", "tpa", "dst_ip", "target_protocol_address")
        if tpa: check(tool, args, tpa, "10.0.0.2", "target ip")
    else:
        skip(f"{tool}: no input variant accepted")

# -------------------- Emit report --------------------
report = {
    "category": PREFIX.rstrip("_"),
    "tools_in_category": len(tools),
    "checks_total": checks_total,
    "checks_passed": checks_passed,
    "checks_skipped": checks_skipped,
    "mismatches": mismatches,
}
with open(OUT, "w") as f:
    json.dump(report, f, indent=2, default=str)
print(json.dumps({k:v for k,v in report.items() if k!="mismatches"}, indent=2))
print(f"mismatches: {len(mismatches)}  -> {OUT}")

try: p.terminate()
except: pass
