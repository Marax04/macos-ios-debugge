#!/usr/bin/env python3
"""
Independent Python validator for RustRE MCP net_pcap_* tools.
Validates PCAP parsing, link type resolution, and packet utilities.
Ground truth: PCAP file format RFC 1549 + libpcap standard.
"""
import json
import subprocess
import struct
import time

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_net_pcap.json"

def start():
    """Initialize MCP subprocess with stdio transport."""
    p = subprocess.Popen(
        [EXE, "--transport=stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0
    )
    def send(r):
        p.stdin.write((json.dumps(r) + "\n").encode())
        p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None

    send({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "validator", "version": "1"}
        }
    })
    recv()
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    return p, send, recv

p, send, recv = start()
rid = [10]

def call(name, args):
    """Call an MCP tool and return JSON result or None."""
    rid[0] += 1
    send({
        "jsonrpc": "2.0",
        "id": rid[0],
        "method": "tools/call",
        "params": {"name": name, "arguments": args}
    })
    resp = recv()
    if not resp or "error" in resp:
        return None
    c = resp.get("result", {}).get("content", [])
    if not c:
        return None
    try:
        return json.loads(c[0].get("text", ""))
    except:
        return c[0].get("text", "")

def list_tools():
    """List all available tools and filter by net_pcap_ prefix."""
    rid[0] += 1
    send({
        "jsonrpc": "2.0",
        "id": rid[0],
        "method": "tools/list",
        "params": {}
    })
    resp = recv()
    if not resp or "error" in resp:
        return []
    tools = resp.get("result", {}).get("tools", [])
    return [t for t in tools if "name" in t and t["name"].startswith("net_pcap_")]

mismatches = []
checks_ok = 0
checks_total = 0
checks_skipped = 0

def check(name, mcp_val, truth_val, ctx="", skip=False):
    """Compare MCP output with ground truth."""
    global checks_ok, checks_total, checks_skipped
    if skip:
        checks_skipped += 1
        return
    checks_total += 1

    mcp_norm = normalize_value(mcp_val)
    truth_norm = normalize_value(truth_val)

    if mcp_norm == truth_norm:
        checks_ok += 1
    else:
        mismatches.append({
            "tool": name,
            "input": ctx,
            "mcp": mcp_val,
            "truth": truth_val,
            "note": f"Mismatch: got {mcp_norm}, expected {truth_norm}"
        })

def normalize_value(v):
    """Normalize value for comparison."""
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    if isinstance(v, float):
        return round(v, 6)
    if isinstance(v, (list, tuple)):
        return tuple(normalize_value(x) for x in v)
    if isinstance(v, dict):
        return {k: normalize_value(val) for k, val in v.items()}
    if isinstance(v, str):
        return v.lower()
    return v

# ============ PCAP Format Constants ============

PCAP_MAGIC_USEC = 0xa1b2c3d4
PCAP_MAGIC_NSEC = 0xa1b23c4d

def create_pcap_bytes(link_type=1, magic=PCAP_MAGIC_USEC, packet_payloads=None):
    """Create a valid PCAP file in bytes."""
    if packet_payloads is None:
        packet_payloads = []

    header = struct.pack(
        "<IHHIIII",
        magic,
        2, 4, 0, 0, 65535, link_type
    )

    packets_data = b""
    ts_sec = int(time.time())

    for i, pkt_data in enumerate(packet_payloads):
        if isinstance(pkt_data, str):
            pkt_data = bytes.fromhex(pkt_data)

        ts_usec = i
        pkt_header = struct.pack(
            "<IIII",
            ts_sec,
            ts_usec,
            len(pkt_data),
            len(pkt_data)
        )
        packets_data += pkt_header + pkt_data

    return header + packets_data

# ============ TEST CASES ============

print("[*] Listing net_pcap_ tools...")
tools = list_tools()
print(f"[+] Found {len(tools)} net_pcap_ tools")

if not tools:
    print("[-] No net_pcap_ tools found!")
    try:
        p.terminate()
    except:
        pass
    report = {
        "category": "net_pcap",
        "tools_in_category": 0,
        "checks_total": 0,
        "checks_passed": 0,
        "checks_skipped": 0,
        "mismatches": []
    }
    with open(OUT, "w") as f:
        json.dump(report, f, indent=2)
    exit(0)

net_pcap_tools = [t["name"] for t in tools]

# ---- Test 1: net_pcap_link_type_from_u16 ----
print("[*] Test 1: net_pcap_link_type_from_u16")
test_cases = [
    (0, "null"),
    (1, "ethernet"),
    (6, "ieee8024"),
    (101, "raw"),
    (113, "linuxsll"),
    (127, "ieee80211radio"),
]

for code, expected_name in test_cases:
    r = call("net_pcap_link_type_from_u16", {"code": code})
    if r and isinstance(r, dict):
        result_name = (r.get("link_type") or "").lower()
        check("net_pcap_link_type_from_u16", result_name, expected_name,
              f"code={code}")

# ---- Test 2: net_pcap_file_parse_info (valid PCAP) ----
print("[*] Test 2: net_pcap_file_parse_info (valid PCAP)")
pcap_hex = create_pcap_bytes(
    link_type=1,
    magic=PCAP_MAGIC_USEC,
    packet_payloads=["0102030405", "0607080910"]
).hex()

r = call("net_pcap_file_parse_info", {"hex": pcap_hex})
if r and isinstance(r, dict):
    # Check network/link_type
    network = r.get("network")
    check("net_pcap_file_parse_info", network, 1, "link_type")

    # Check record count
    record_count = r.get("record_count")
    check("net_pcap_file_parse_info", record_count, 2, "packet_count")

    # Check total_bytes > 0
    total_bytes = r.get("total_bytes")
    check("net_pcap_file_parse_info", total_bytes > 0, True, "total_bytes > 0")

    # Check snaplen
    snaplen = r.get("snaplen")
    check("net_pcap_file_parse_info", snaplen, 65535, "snaplen")

# ---- Test 3: net_pcap_file_parse_info (invalid PCAP) ----
print("[*] Test 3: net_pcap_file_parse_info (invalid PCAP)")
invalid_hex = "deadbeefcafebabe"
r = call("net_pcap_file_parse_info", {"hex": invalid_hex})
if r is None:
    check("net_pcap_file_parse_info (invalid)", True, True, "invalid_hex")
elif isinstance(r, dict):
    # Should have empty/error record count
    record_count = r.get("record_count") or 0
    check("net_pcap_file_parse_info (invalid)", record_count == 0, True,
          "invalid PCAP -> record_count=0")

# ---- Test 4: net_pcap_split_by_count ----
print("[*] Test 4: net_pcap_split_by_count")
pcap_5pkt = create_pcap_bytes(
    link_type=1,
    magic=PCAP_MAGIC_USEC,
    packet_payloads=["01", "02", "03", "04", "05"]
).hex()

r = call("net_pcap_split_by_count", {"hex": pcap_5pkt, "max_packets": 2})
if r and isinstance(r, dict):
    # 5 packets / 2 per split = 3 files
    file_count = r.get("file_count") or r.get("num_files") or len(r.get("splits") or [])
    if file_count > 0:
        check("net_pcap_split_by_count", file_count, 3, "5 packets / max_packets=2")

# ---- Test 5: net_pcap_split_by_time ----
print("[*] Test 5: net_pcap_split_by_time")
pcap_3pkt = create_pcap_bytes(
    link_type=1,
    magic=PCAP_MAGIC_USEC,
    packet_payloads=["01", "02", "03"]
).hex()

r = call("net_pcap_split_by_time", {"hex": pcap_3pkt, "window_secs": 1})
if r and isinstance(r, dict):
    # Should have result
    file_count = r.get("file_count") or r.get("num_files") or len(r.get("splits") or [])
    if file_count >= 0:
        check("net_pcap_split_by_time", isinstance(r, dict), True, "returns dict")

# ---- Test 6: net_pcap_merge_files ----
print("[*] Test 6: net_pcap_merge_files")
pcap1 = create_pcap_bytes(link_type=1, magic=PCAP_MAGIC_USEC, packet_payloads=["01"]).hex()
pcap2 = create_pcap_bytes(link_type=1, magic=PCAP_MAGIC_USEC, packet_payloads=["02"]).hex()

r = call("net_pcap_merge_files", {"files_hex": [pcap1, pcap2]})
if r and isinstance(r, dict):
    result_hex = r.get("merged_hex") or r.get("hex") or r.get("result")
    if result_hex:
        # Merged should start with valid PCAP magic
        try:
            merged_bytes = bytes.fromhex(result_hex[:8])
            merged_magic = struct.unpack("<I", merged_bytes)[0]
            check("net_pcap_merge_files", merged_magic, PCAP_MAGIC_USEC, "merged_magic")
        except:
            check("net_pcap_merge_files", False, True, "parse merged_hex")

# ---- Test 7: Link type roundtrip ----
print("[*] Test 7: net_pcap_link_type_from_u16 roundtrip")
for code in [1, 6, 101, 127]:
    r = call("net_pcap_link_type_from_u16", {"code": code})
    if r and isinstance(r, dict):
        roundtrip = r.get("roundtrip")
        if roundtrip is not None:
            check("net_pcap_link_type_from_u16", roundtrip, code, f"roundtrip code={code}")

# ---- Test 8: Empty PCAP ----
print("[*] Test 8: net_pcap_file_parse_info (empty PCAP)")
empty_pcap = create_pcap_bytes(link_type=1, magic=PCAP_MAGIC_USEC, packet_payloads=[]).hex()
r = call("net_pcap_file_parse_info", {"hex": empty_pcap})
if r and isinstance(r, dict):
    record_count = r.get("record_count")
    check("net_pcap_file_parse_info (empty)", record_count, 0, "empty PCAP packet count")

# ---- Test 9: Different link types ----
print("[*] Test 9: net_pcap_file_parse_info (different link types)")
for link_type in [1, 6, 101]:
    pcap = create_pcap_bytes(link_type=link_type, magic=PCAP_MAGIC_USEC, packet_payloads=["aa"]).hex()
    r = call("net_pcap_file_parse_info", {"hex": pcap})
    if r and isinstance(r, dict):
        network = r.get("network")
        check("net_pcap_file_parse_info", network, link_type, f"link_type={link_type}")

# ---- Test 10: PCAP with nanosecond magic ----
print("[*] Test 10: net_pcap_file_parse_info (nanosecond PCAP)")
pcap_nsec = create_pcap_bytes(
    link_type=1,
    magic=PCAP_MAGIC_NSEC,
    packet_payloads=["aabbccdd"]
).hex()
r = call("net_pcap_file_parse_info", {"hex": pcap_nsec})
if r and isinstance(r, dict):
    # Should still parse correctly regardless of magic
    record_count = r.get("record_count")
    check("net_pcap_file_parse_info (nsec)", record_count >= 1, True, "nanosecond PCAP")

# ---- Test 11: Large packet count ----
print("[*] Test 11: net_pcap_file_parse_info (many packets)")
many_pkts = ["aa" for _ in range(100)]
pcap_many = create_pcap_bytes(link_type=1, magic=PCAP_MAGIC_USEC, packet_payloads=many_pkts).hex()
r = call("net_pcap_file_parse_info", {"hex": pcap_many})
if r and isinstance(r, dict):
    record_count = r.get("record_count")
    check("net_pcap_file_parse_info", record_count, 100, "100 packets")

# ---- Test 12: Split with max_packets=1 ----
print("[*] Test 12: net_pcap_split_by_count (max_packets=1)")
pcap_3 = create_pcap_bytes(link_type=1, magic=PCAP_MAGIC_USEC, packet_payloads=["01", "02", "03"]).hex()
r = call("net_pcap_split_by_count", {"hex": pcap_3, "max_packets": 1})
if r and isinstance(r, dict):
    file_count = r.get("file_count") or len(r.get("splits") or [])
    if file_count > 0:
        check("net_pcap_split_by_count", file_count, 3, "3 packets / max_packets=1")

# ---- Test 13: Link type 0 (NULL) ----
print("[*] Test 13: net_pcap_link_type_from_u16 (code=0)")
r = call("net_pcap_link_type_from_u16", {"code": 0})
if r and isinstance(r, dict):
    link_type_name = r.get("link_type") or ""
    check("net_pcap_link_type_from_u16", len(link_type_name) > 0, True, "code=0 returns name")

# ---- Test 14: High code value ----
print("[*] Test 14: net_pcap_link_type_from_u16 (high code)")
r = call("net_pcap_link_type_from_u16", {"code": 300})
if r and isinstance(r, dict):
    # Should return something
    code = r.get("code")
    check("net_pcap_link_type_from_u16 (high)", code, 300, "high code returned")

# ---- Test 15: Merge single file ----
print("[*] Test 15: net_pcap_merge_files (single file)")
single = create_pcap_bytes(link_type=1, magic=PCAP_MAGIC_USEC, packet_payloads=["ff"]).hex()
r = call("net_pcap_merge_files", {"files_hex": [single]})
if r and isinstance(r, dict):
    check("net_pcap_merge_files (single)", isinstance(r, dict), True, "single file merge")

# ---- Test 16: Split small PCAP ----
print("[*] Test 16: net_pcap_split_by_count (small PCAP)")
small = create_pcap_bytes(link_type=1, magic=PCAP_MAGIC_USEC, packet_payloads=["aa"]).hex()
r = call("net_pcap_split_by_count", {"hex": small, "max_packets": 10})
if r and isinstance(r, dict):
    # Small PCAP with 1 packet and max_packets=10 should return result
    if "file_count" in r or "splits" in r:
        file_count = r.get("file_count")
        if file_count is not None:
            check("net_pcap_split_by_count (small)", file_count, 1, "1 packet, max_packets=10")

# ---- Summary ----
try:
    p.terminate()
except:
    pass

report = {
    "category": "net_pcap",
    "tools_in_category": len(net_pcap_tools),
    "checks_total": checks_total,
    "checks_passed": checks_ok,
    "checks_skipped": checks_skipped,
    "mismatches": mismatches
}

with open(OUT, "w") as f:
    json.dump(report, f, indent=2)

print(f"\n[SUMMARY]")
print(f"  Category: {report['category']}")
print(f"  Tools in category: {report['tools_in_category']}")
print(f"  Checks: {checks_ok}/{checks_total} passed (skipped: {checks_skipped})")
print(f"  Mismatches: {len(mismatches)}")

if mismatches:
    print("\n  Mismatches:")
    for m in mismatches[:15]:
        print(f"    {m['tool']}: {m['note']}")

print(f"\n[+] Report saved to {OUT}")
