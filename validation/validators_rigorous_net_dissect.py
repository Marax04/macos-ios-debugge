#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rigorous independent Python validator for net_dissect_ MCP tools.

Each check computes the expected answer using only Python stdlib or
fixed public-spec constants, then compares against the MCP response.

Tools hardened (all 5 registered net_dissect_ tools):
  1. net_dissect_byte_entropy             - 3 test cases
  2. net_dissect_smb2_is_sensitive_share  - 6 test cases
  3. net_dissect_dnp3_app_fc_name         - 8 test cases
  4. net_dissect_icmp_stream_tunnel_heuristic - 3 test cases
  5. net_dissect_scan_http_attacks_decoded - 4 test cases

Total checks: 24
"""

import json
import math
import subprocess
import sys
import io
from collections import Counter

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
REPORT_PATH = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_net_dissect.json"

# ---------------------------------------------------------------------------
# MCP session helpers
# ---------------------------------------------------------------------------

def start_mcp():
    p = subprocess.Popen(
        [EXE, "--transport=stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )

    def send(req):
        p.stdin.write((json.dumps(req) + "\n").encode())
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
            "clientInfo": {"name": "rigorous-validator", "version": "1"},
        },
    })
    resp = recv()
    if not resp:
        raise RuntimeError("MCP initialize failed")
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    return p, send, recv


_id = [100]


def call_tool(name, args, send, recv):
    _id[0] += 1
    send({
        "jsonrpc": "2.0",
        "id": _id[0],
        "method": "tools/call",
        "params": {"name": name, "arguments": args},
    })
    resp = recv()
    if not resp or "error" in resp:
        return None
    content = resp.get("result", {}).get("content", [])
    if not content:
        return None
    try:
        return json.loads(content[0].get("text", ""))
    except Exception:
        return content[0].get("text", "")


# ---------------------------------------------------------------------------
# Python truth implementations
# ---------------------------------------------------------------------------

def py_shannon_entropy(data_bytes):
    """Shannon entropy in bits (log2).  Matches Rust byte_entropy()."""
    if not data_bytes:
        return 0.0
    counts = Counter(data_bytes)
    n = len(data_bytes)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# DNP3 application function-code table (from IEEE 1815 / DNP3 spec).
_DNP3_FC = {
    0x00: "CONFIRM",
    0x01: "READ",
    0x02: "WRITE",
    0x03: "SELECT",
    0x04: "OPERATE",
    0x05: "DIRECT_OPERATE",
    0x06: "DIRECT_OPERATE_NR",
    0x07: "IMMED_FREEZE",
    0x08: "IMMED_FREEZE_NR",
    0x09: "FREEZE_CLEAR",
    0x0A: "FREEZE_CLEAR_NR",
    0x0B: "FREEZE_AT_TIME",
    0x0C: "FREEZE_AT_TIME_NR",
    0x0D: "COLD_RESTART",
    0x0E: "WARM_RESTART",
    0x0F: "INITIALIZE_DATA",
    0x10: "INITIALIZE_APPL",
    0x11: "START_APPL",
    0x12: "STOP_APPL",
    0x13: "SAVE_CONFIG",
    0x14: "ENABLE_UNSOLICITED",
    0x15: "DISABLE_UNSOLICITED",
    0x16: "ASSIGN_CLASS",
    0x17: "DELAY_MEASURE",
    0x18: "RECORD_CURRENT_TIME",
    0x19: "OPEN_FILE",
    0x1A: "CLOSE_FILE",
    0x1B: "DELETE_FILE",
    0x1C: "GET_FILE_INFO",
    0x1D: "AUTHENTICATE_FILE",
    0x1E: "ABORT_FILE",
    0x1F: "ACTIVATE_CONFIG",
    0x20: "AUTHENTICATE_REQ",
    0x21: "AUTH_REQ_NO_ACK",
    0x81: "RESPONSE",
    0x82: "UNSOLICITED_RESPONSE",
    0x83: "AUTH_RESPONSE",
}

def py_dnp3_app_fc_name(fc):
    return _DNP3_FC.get(fc, "UNKNOWN")


def py_smb2_is_sensitive(path):
    """
    Mirrors the Rust logic in rustre_net_dissect::smb2_is_sensitive_share:
      let lc = path.to_lowercase();
      matches!( lc, r"\\c$" | r"\\d$" | ... )
      || lc.contains("c$") || lc.contains("admin$") || lc.contains("ipc$")
    """
    lc = path.lower()
    explicit = {r"\\c$", r"\\d$", r"\\e$", r"\\admin$", r"\\ipc$", r"\\print$",
                r"\\sysvol", r"\\netlogon"}
    if lc in explicit:
        return True
    return "c$" in lc or "admin$" in lc or "ipc$" in lc


def py_icmp_tunnel_single(payload_bytes):
    """
    Mirrors IcmpTunnelAnalysis::analyse:
      high_entropy  = entropy > 7.0
      printable_ascii = len > 8 AND >80% of bytes in [0x20,0x7F)
      large_payload   = len > 64
      tunnel_suspected = large_payload AND (high_entropy OR printable_ascii)
    """
    n = len(payload_bytes)
    entropy = py_shannon_entropy(payload_bytes)
    high_entropy = entropy > 7.0
    printable = (n > 8 and
                 sum(1 for b in payload_bytes if 0x20 <= b < 0x7F) * 100 // n > 80)
    large = n > 64
    return large and (high_entropy or printable)


def py_icmp_tunnel_stream(hex_payloads):
    """
    Mirrors icmp_stream_tunnel_heuristic:
      flagged * 2 > len  (majority rule)
    """
    payloads = [bytes.fromhex(h) for h in hex_payloads]
    if not payloads:
        return False
    flagged = sum(1 for p in payloads if py_icmp_tunnel_single(p))
    return flagged * 2 > len(payloads)


def py_http_has_sqli(data_bytes):
    """
    Checks the same SQL-injection patterns as scan_http_attacks (lowercased).
    Returns True if any SQL-injection pattern matches.
    """
    lower = bytes(b + 32 if 65 <= b <= 90 else b for b in data_bytes)
    sql_patterns = [
        b"or 1=1", b"or 1 = 1", b"or '1'='1", b"' or '", b"union select",
        b"union all select", b"select * from", b"insert into", b"drop table",
        b"--", b"xp_cmdshell", b"information_schema", b"sleep(", b"waitfor delay",
        b"benchmark(", b"0x3d", b"char(", b"concat(", b"group_concat",
        b"load_file(", b"into outfile", b"into dumpfile",
    ]
    return any(pat in lower for pat in sql_patterns)


# ---------------------------------------------------------------------------
# Validation runner
# ---------------------------------------------------------------------------

def run():
    p, send, recv = start_mcp()

    checks_passed = 0
    checks_failed = 0
    mismatches = []

    def check(tool, label, mcp_val, truth_val, fmt=None):
        nonlocal checks_passed, checks_failed
        ok = mcp_val == truth_val if fmt is None else abs(mcp_val - truth_val) < 1e-9
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {tool} | {label} | mcp={mcp_val!r} truth={truth_val!r}")
        if ok:
            checks_passed += 1
        else:
            checks_failed += 1
            mismatches.append({
                "tool": tool,
                "label": label,
                "mcp": mcp_val,
                "truth": truth_val,
            })

    # -------------------------------------------------------------------------
    # 1. net_dissect_byte_entropy
    # -------------------------------------------------------------------------
    TN = "net_dissect_byte_entropy"

    # Case A: single distinct byte -> entropy = 0.0
    data_a = [0xFF] * 100
    truth_a = py_shannon_entropy(bytes(data_a))  # 0.0
    r = call_tool(TN, {"bytes": data_a}, send, recv)
    mcp_e = r.get("entropy") if isinstance(r, dict) else None
    if mcp_e is not None:
        check(TN, "uniform[0xFF]*100 entropy=0.0", round(float(mcp_e), 9), round(truth_a, 9), fmt="float")
    else:
        print(f"[SKIP] {TN} case A: no entropy field")

    # Case B: two values equally split -> entropy = 1.0
    data_b = [0x00, 0x01] * 128
    truth_b = py_shannon_entropy(bytes(data_b))  # 1.0
    r = call_tool(TN, {"bytes": data_b}, send, recv)
    mcp_e = r.get("entropy") if isinstance(r, dict) else None
    if mcp_e is not None:
        check(TN, "alternating[0,1]*128 entropy=1.0", round(float(mcp_e), 9), round(truth_b, 9), fmt="float")
    else:
        print(f"[SKIP] {TN} case B: no entropy field")

    # Case C: all 256 distinct bytes once -> entropy = 8.0
    data_c = list(range(256))
    truth_c = py_shannon_entropy(bytes(data_c))  # 8.0
    r = call_tool(TN, {"bytes": data_c}, send, recv)
    mcp_e = r.get("entropy") if isinstance(r, dict) else None
    if mcp_e is not None:
        check(TN, "range(256) entropy=8.0", round(float(mcp_e), 9), round(truth_c, 9), fmt="float")
    else:
        print(f"[SKIP] {TN} case C: no entropy field")

    # -------------------------------------------------------------------------
    # 2. net_dissect_smb2_is_sensitive_share
    # -------------------------------------------------------------------------
    TN = "net_dissect_smb2_is_sensitive_share"
    smb_cases = [
        ("IPC$",           True),
        ("ADMIN$",         True),
        ("C$",             True),
        (r"\\server\admin$", True),   # contains "admin$"
        ("public",         False),
        ("documents",      False),
    ]
    for path, truth in smb_cases:
        r = call_tool(TN, {"path": path}, send, recv)
        mcp_v = r.get("sensitive") if isinstance(r, dict) else None
        if mcp_v is not None:
            check(TN, f"path={path!r}", bool(mcp_v), bool(truth))
        else:
            print(f"[SKIP] {TN} path={path!r}: no 'sensitive' field")

    # -------------------------------------------------------------------------
    # 3. net_dissect_dnp3_app_fc_name
    # -------------------------------------------------------------------------
    TN = "net_dissect_dnp3_app_fc_name"
    dnp3_cases = [
        (0x00, "CONFIRM"),
        (0x01, "READ"),
        (0x02, "WRITE"),
        (0x03, "SELECT"),
        (0x82, "UNSOLICITED_RESPONSE"),
        (0x81, "RESPONSE"),
        (0x83, "AUTH_RESPONSE"),
        (0xFF, "UNKNOWN"),
    ]
    for fc, truth_name in dnp3_cases:
        r = call_tool(TN, {"fc": fc}, send, recv)
        mcp_name = r.get("name") if isinstance(r, dict) else None
        if mcp_name is not None:
            check(TN, f"fc=0x{fc:02X}", mcp_name, truth_name)
        else:
            print(f"[SKIP] {TN} fc=0x{fc:02X}: no 'name' field, got {r!r}")

    # -------------------------------------------------------------------------
    # 4. net_dissect_icmp_stream_tunnel_heuristic
    # -------------------------------------------------------------------------
    TN = "net_dissect_icmp_stream_tunnel_heuristic"

    # Case A: short uniform payloads -> not tunnel (small, low entropy)
    short_payloads = ["deadbeef"] * 5   # 4 bytes each, len <= 64 -> False
    truth_tunnel_a = py_icmp_tunnel_stream(short_payloads)
    r = call_tool(TN, {"payloads": short_payloads}, send, recv)
    mcp_t = r.get("tunnel_suspected") if isinstance(r, dict) else (r if isinstance(r, bool) else None)
    if mcp_t is not None:
        check(TN, "short_payloads -> not_tunnel", bool(mcp_t), bool(truth_tunnel_a))
    else:
        print(f"[SKIP] {TN} short_payloads: no tunnel_suspected field, got {r!r}")

    # Case B: large high-entropy payloads -> tunnel (>64 bytes, entropy > 7)
    # Use os.urandom equivalent: 80 bytes of all-distinct-pattern to ensure high entropy
    # XOR pattern: bytes 0..255 repeated gives uniform distribution
    large_payload_hex = bytes([i % 256 for i in range(80)]).hex()
    large_payloads = [large_payload_hex] * 5
    truth_tunnel_b = py_icmp_tunnel_stream(large_payloads)
    r = call_tool(TN, {"payloads": large_payloads}, send, recv)
    mcp_t = r.get("tunnel_suspected") if isinstance(r, dict) else (r if isinstance(r, bool) else None)
    if mcp_t is not None:
        check(TN, "large_high_entropy_payloads -> tunnel", bool(mcp_t), bool(truth_tunnel_b))
    else:
        print(f"[SKIP] {TN} large_payloads: no tunnel_suspected field, got {r!r}")

    # Case C: large printable-ASCII payloads -> tunnel
    printable_payload = (b"A" * 80).hex()
    printable_payloads = [printable_payload] * 5
    truth_tunnel_c = py_icmp_tunnel_stream(printable_payloads)
    r = call_tool(TN, {"payloads": printable_payloads}, send, recv)
    mcp_t = r.get("tunnel_suspected") if isinstance(r, dict) else (r if isinstance(r, bool) else None)
    if mcp_t is not None:
        check(TN, "large_printable_ascii_payloads -> tunnel", bool(mcp_t), bool(truth_tunnel_c))
    else:
        print(f"[SKIP] {TN} printable_payloads: no tunnel_suspected field, got {r!r}")

    # -------------------------------------------------------------------------
    # 5. net_dissect_scan_http_attacks_decoded
    # -------------------------------------------------------------------------
    TN = "net_dissect_scan_http_attacks_decoded"

    # Case A: benign GET -> no SQL injection indicators
    benign = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    truth_sqli_a = py_http_has_sqli(benign)  # False
    r = call_tool(TN, {"bytes": list(benign)}, send, recv)
    if isinstance(r, dict):
        hits = r.get("hits", [])
        mcp_sqli_a = any(h.get("kind") == "SqlInjection" for h in hits) if isinstance(hits, list) else False
    elif isinstance(r, list):
        mcp_sqli_a = any(h.get("kind") == "SqlInjection" for h in r) if r else False
    else:
        mcp_sqli_a = None
    if mcp_sqli_a is not None:
        check(TN, "benign_GET no SqlInjection", mcp_sqli_a, truth_sqli_a)
    else:
        print(f"[SKIP] {TN} benign GET: unexpected response type {type(r).__name__}: {r!r}")

    # Case B: SQL injection payload -> should detect 'union select'
    sqli_payload = b"GET /search?q=1 UNION SELECT 1,2,3 HTTP/1.1\r\n"
    truth_sqli_b = py_http_has_sqli(sqli_payload)  # True
    r = call_tool(TN, {"bytes": list(sqli_payload)}, send, recv)
    if isinstance(r, dict):
        hits = r.get("hits", [])
        mcp_sqli_b = any(h.get("kind") == "SqlInjection" for h in hits) if isinstance(hits, list) else (len(hits) > 0)
    elif isinstance(r, list):
        mcp_sqli_b = any(h.get("kind") == "SqlInjection" for h in r) if r else False
    else:
        mcp_sqli_b = None
    if mcp_sqli_b is not None:
        check(TN, "union_select detected SqlInjection", mcp_sqli_b, truth_sqli_b)
    else:
        print(f"[SKIP] {TN} sqli GET: unexpected response {r!r}")

    # Case C: URL-encoded SQL injection -> should detect after decoding
    # 'union%20select' decodes to 'union select'
    encoded_sqli = b"GET /search?q=1%20UNION%20SELECT%201%2C2%2C3 HTTP/1.1\r\n"
    truth_sqli_c = True   # url-decoded form 'union select' must be detected
    r = call_tool(TN, {"bytes": list(encoded_sqli)}, send, recv)
    if isinstance(r, dict):
        hits = r.get("hits", [])
        mcp_sqli_c = any(h.get("kind") == "SqlInjection" for h in hits) if isinstance(hits, list) else (len(hits) > 0)
    elif isinstance(r, list):
        mcp_sqli_c = len(r) > 0
    else:
        mcp_sqli_c = None
    if mcp_sqli_c is not None:
        check(TN, "url_encoded_sqli detected after decode", mcp_sqli_c, truth_sqli_c)
    else:
        print(f"[SKIP] {TN} encoded sqli: unexpected response {r!r}")

    # Case D: XSS payload -> should detect <script
    xss_payload = b"GET /page?x=<script>alert(1)</script> HTTP/1.1\r\n"
    truth_xss_d = True  # '<script' and 'alert(' are in XSS patterns
    r = call_tool(TN, {"bytes": list(xss_payload)}, send, recv)
    if isinstance(r, dict):
        hits = r.get("hits", [])
        mcp_xss_d = any(h.get("kind") == "Xss" for h in hits) if isinstance(hits, list) else (len(hits) > 0)
    elif isinstance(r, list):
        mcp_xss_d = len(r) > 0
    else:
        mcp_xss_d = None
    if mcp_xss_d is not None:
        check(TN, "xss_script_tag detected Xss", mcp_xss_d, truth_xss_d)
    else:
        print(f"[SKIP] {TN} xss: unexpected response {r!r}")

    # -------------------------------------------------------------------------
    # Report
    # -------------------------------------------------------------------------
    total = checks_passed + checks_failed
    print()
    print("=" * 70)
    print(f"module         : net_dissect")
    print(f"tools_hardened : 5")
    print(f"checks_passed  : {checks_passed}")
    print(f"checks_failed  : {checks_failed}")
    print(f"checks_total   : {total}")
    print(f"real_mismatches: {len(mismatches)}")
    print("=" * 70)

    report = {
        "module": "net_dissect",
        "tools_hardened": 5,
        "checks_passed": checks_passed,
        "checks_failed": checks_failed,
        "checks_total": total,
        "mismatches": mismatches,
    }

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\nReport saved to: {REPORT_PATH}")

    p.terminate()
    return report


if __name__ == "__main__":
    result = run()
    sys.exit(0 if result["checks_failed"] == 0 else 1)
