"""
Rigorous validator for the net_proxy module.
Starts rustre-mcp.exe --transport=stdio and verifies at least 10 tools
against independently computed Python truths.
Saves report to validation/rigorous_net_proxy.json.
"""

import subprocess
import json
import base64
import datetime
import sys
import os

MCP_EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
REPORT_PATH = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_net_proxy.json"

# ── MCP stdio helpers ──────────────────────────────────────────────────────

def start_mcp():
    return subprocess.Popen(
        [MCP_EXE, "--transport=stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )


def send_request(proc, method, params, req_id=1):
    msg = json.dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
    line = (msg + "\n").encode()
    proc.stdin.write(line)
    proc.stdin.flush()
    while True:
        raw = proc.stdout.readline()
        if not raw:
            raise RuntimeError("MCP process closed stdout")
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if obj.get("id") == req_id:
            return obj


def call_tool(proc, tool_name, arguments, req_id=1):
    resp = send_request(proc, "tools/call", {"name": tool_name, "arguments": arguments}, req_id)
    if "error" in resp:
        return None, resp["error"]
    content = resp.get("result", {}).get("content", [])
    if content:
        text = content[0].get("text", "")
        try:
            return json.loads(text), None
        except json.JSONDecodeError:
            return text, None
    return None, "empty result"


def initialize(proc):
    send_request(proc, "initialize", {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "rigorous-validator", "version": "1.0"},
    }, req_id=0)
    # Send initialized notification (no response expected)
    msg = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
    proc.stdin.write((msg + "\n").encode())
    proc.stdin.flush()


# ── Python reference implementations ──────────────────────────────────────

def py_hex_encode(data: bytes) -> str:
    return data.hex()


def py_hex_decode(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def py_base64_decode(encoded: str) -> bytes:
    return base64.b64decode(encoded)


def py_ms_to_iso8601(ms: int) -> str:
    dt = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(milliseconds=ms)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def py_parse_request_line(line: str):
    """Parse 'METHOD URI VERSION' per HTTP spec."""
    parts = line.split(" ", 2)
    if len(parts) != 3:
        return None
    method, uri, version = parts
    return {"method": method, "uri": uri, "version": version}


def py_parse_status_line(line: str):
    """Parse 'VERSION CODE REASON'."""
    parts = line.split(" ", 2)
    if len(parts) < 2:
        return None
    version = parts[0]
    try:
        code = int(parts[1])
    except ValueError:
        return None
    reason = parts[2] if len(parts) > 2 else ""
    return {"version": version, "code": code, "reason": reason}


def py_is_success(code: int) -> bool:
    return 200 <= code < 300


def py_is_redirect(code: int) -> bool:
    return 300 <= code < 400


def py_is_client_error(code: int) -> bool:
    return 400 <= code < 500


def py_is_server_error(code: int) -> bool:
    return 500 <= code < 600


def py_is_http11(version: str) -> bool:
    return version == "HTTP/1.1"


def py_is_http2(version: str) -> bool:
    return version == "HTTP/2"


def py_glob_match(pattern: str, text: str) -> bool:
    """Simple glob: * matches within segment, ** crosses slashes, ? matches one non-slash char."""
    import fnmatch
    # Use fnmatch for *.txt style; for ** we handle manually
    # The Rust impl uses a custom glob; test only simple cases
    return fnmatch.fnmatchcase(text, pattern)


def py_http_method_is_idempotent(method: str) -> bool:
    return method.upper() in {"GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"}


def py_http_method_has_body(method: str) -> bool:
    return method.upper() in {"POST", "PUT", "PATCH"}


def py_acl_deny_host_matches(deny_host: str, host: str) -> bool:
    return deny_host.lower() == host.lower()


def py_headers_to_json(pairs: list) -> str:
    items = [f'{{"name":{json_string(k)},"value":{json_string(v)}}}' for k, v in pairs]
    return "[" + ",".join(items) + "]"


def json_string(s: str) -> str:
    return json.dumps(s)


# ── Test cases ─────────────────────────────────────────────────────────────

def run_checks(proc):
    checks_passed = 0
    checks_failed = 0
    mismatches = []
    tools_hardened = set()

    req_id = 1

    def check(tool, desc, result, err, expected, key=None):
        nonlocal checks_passed, checks_failed, req_id
        tools_hardened.add(tool)
        if err:
            checks_failed += 1
            mismatches.append({"tool": tool, "desc": desc, "error": str(err)})
            return
        actual = result.get(key) if key and isinstance(result, dict) else result
        if actual == expected:
            checks_passed += 1
        else:
            checks_failed += 1
            mismatches.append({
                "tool": tool,
                "desc": desc,
                "expected": expected,
                "actual": actual,
                "full_result": result,
            })

    # 1. hex_encode
    data = bytes([0xDE, 0xAD, 0xBE, 0xEF])
    expected_hex = py_hex_encode(data)
    r, e = call_tool(proc, "net_proxy_hex_encode", {"bytes": list(data)}, req_id); req_id += 1
    check("net_proxy_hex_encode", "encode deadbeef", r, e, expected_hex, "hex")

    # 2. hex_encode empty
    r, e = call_tool(proc, "net_proxy_hex_encode", {"bytes": []}, req_id); req_id += 1
    check("net_proxy_hex_encode", "encode empty", r, e, "", "hex")

    # 3. hex_decode (output key is "bytes_hex")
    hex_str = "cafebabe"
    expected_bytes = py_hex_decode(hex_str).hex()
    r, e = call_tool(proc, "net_proxy_hex_decode", {"hex": hex_str}, req_id); req_id += 1
    check("net_proxy_hex_decode", "decode cafebabe", r, e, expected_bytes, "bytes_hex")

    # 4. base64_decode (output key is "bytes_hex")
    encoded = base64.b64encode(b"Hello, World!").decode()
    expected_decoded_hex = b"Hello, World!".hex()
    r, e = call_tool(proc, "net_proxy_base64_decode", {"encoded": encoded}, req_id); req_id += 1
    check("net_proxy_base64_decode", "decode Hello World", r, e, expected_decoded_hex, "bytes_hex")

    # 5. ms_to_iso8601 — epoch
    ms = 0
    expected_iso = py_ms_to_iso8601(ms)
    r, e = call_tool(proc, "net_proxy_ms_to_iso8601", {"ms": ms}, req_id); req_id += 1
    check("net_proxy_ms_to_iso8601", "epoch 0ms", r, e, expected_iso, "iso8601")

    # 6. ms_to_iso8601 — known date: 2024-01-01T00:00:00.000Z = 1704067200000 ms
    ms = 1_704_067_200_000
    expected_iso = py_ms_to_iso8601(ms)
    r, e = call_tool(proc, "net_proxy_ms_to_iso8601", {"ms": ms}, req_id); req_id += 1
    check("net_proxy_ms_to_iso8601", "2024-01-01 known date", r, e, expected_iso, "iso8601")

    # 7. parse_request_line — GET
    line = "GET /index.html HTTP/1.1"
    py_rl = py_parse_request_line(line)
    r, e = call_tool(proc, "net_proxy_parse_request_line", {"line": line}, req_id); req_id += 1
    # Check method, uri, version individually
    tools_hardened.add("net_proxy_parse_request_line")
    if e:
        checks_failed += 1
        mismatches.append({"tool": "net_proxy_parse_request_line", "desc": "parse GET line error", "error": str(e)})
    else:
        for field in ("method", "uri", "version"):
            exp = py_rl[field]
            act = r.get(field) if isinstance(r, dict) else None
            if act == exp:
                checks_passed += 1
            else:
                checks_failed += 1
                mismatches.append({"tool": "net_proxy_parse_request_line", "desc": f"field {field}", "expected": exp, "actual": act})

    # 8. parse_status_line — 200 OK
    line = "HTTP/1.1 200 OK"
    py_sl = py_parse_status_line(line)
    r, e = call_tool(proc, "net_proxy_parse_status_line", {"line": line}, req_id); req_id += 1
    tools_hardened.add("net_proxy_parse_status_line")
    if e:
        checks_failed += 1
        mismatches.append({"tool": "net_proxy_parse_status_line", "desc": "parse 200 OK error", "error": str(e)})
    else:
        for field, exp in [("code", py_sl["code"]), ("version", py_sl["version"]), ("reason", py_sl["reason"])]:
            act = r.get(field) if isinstance(r, dict) else None
            if act == exp:
                checks_passed += 1
            else:
                checks_failed += 1
                mismatches.append({"tool": "net_proxy_parse_status_line", "desc": f"field {field}", "expected": exp, "actual": act})

    # 9. http_status_classify — is_success for 200
    line = "HTTP/1.1 200 OK"
    r, e = call_tool(proc, "net_proxy_http_status_classify", {"line": line}, req_id); req_id += 1
    check("net_proxy_http_status_classify", "200 is_success=True", r, e, True, "is_success")
    check("net_proxy_http_status_classify", "200 is_redirect=False", r, e, False, "is_redirect")

    # 10. http_status_classify — 301 redirect
    line = "HTTP/1.1 301 Moved Permanently"
    r, e = call_tool(proc, "net_proxy_http_status_classify", {"line": line}, req_id); req_id += 1
    check("net_proxy_http_status_classify", "301 is_redirect=True", r, e, True, "is_redirect")
    check("net_proxy_http_status_classify", "301 is_success=False", r, e, False, "is_success")

    # 11. http_status_classify — 404 client error
    line = "HTTP/1.1 404 Not Found"
    r, e = call_tool(proc, "net_proxy_http_status_classify", {"line": line}, req_id); req_id += 1
    check("net_proxy_http_status_classify", "404 is_client_error=True", r, e, True, "is_client_error")

    # 12. http_status_classify — 500 server error
    line = "HTTP/1.1 500 Internal Server Error"
    r, e = call_tool(proc, "net_proxy_http_status_classify", {"line": line}, req_id); req_id += 1
    check("net_proxy_http_status_classify", "500 is_server_error=True", r, e, True, "is_server_error")

    # 13. http_method_is_idempotent — GET
    r, e = call_tool(proc, "net_proxy_http_method_is_idempotent", {"method": "GET"}, req_id); req_id += 1
    check("net_proxy_http_method_is_idempotent", "GET is_idempotent=True", r, e, True, "is_idempotent")

    # 14. http_method_is_idempotent — POST
    r, e = call_tool(proc, "net_proxy_http_method_is_idempotent", {"method": "POST"}, req_id); req_id += 1
    check("net_proxy_http_method_is_idempotent", "POST is_idempotent=False", r, e, False, "is_idempotent")

    # 15. http_method_has_body — POST
    r, e = call_tool(proc, "net_proxy_http_method_has_body", {"method": "POST"}, req_id); req_id += 1
    check("net_proxy_http_method_has_body", "POST has_body=True", r, e, True, "has_body")

    # 16. http_method_has_body — GET
    r, e = call_tool(proc, "net_proxy_http_method_has_body", {"method": "GET"}, req_id); req_id += 1
    check("net_proxy_http_method_has_body", "GET has_body=False", r, e, False, "has_body")

    # 17. http_request_line_version — is_http11
    line = "GET / HTTP/1.1"
    r, e = call_tool(proc, "net_proxy_http_request_line_version", {"line": line}, req_id); req_id += 1
    check("net_proxy_http_request_line_version", "HTTP/1.1 is_http11=True", r, e, True, "is_http11")
    check("net_proxy_http_request_line_version", "HTTP/1.1 is_http2=False", r, e, False, "is_http2")

    # 18. acl_entry_matches — deny_host match
    r, e = call_tool(proc, "net_proxy_acl_entry_matches", {"deny_host": "evil.com", "host": "evil.com", "port": 80}, req_id); req_id += 1
    check("net_proxy_acl_entry_matches", "deny evil.com matches evil.com", r, e, True, "deny_matches")

    # 19. acl_entry_matches — deny_host non-match
    r, e = call_tool(proc, "net_proxy_acl_entry_matches", {"deny_host": "evil.com", "host": "good.com", "port": 80}, req_id); req_id += 1
    check("net_proxy_acl_entry_matches", "deny evil.com doesn't match good.com", r, e, False, "deny_matches")

    # 20. acl_entry_matches — allow_all always matches
    r, e = call_tool(proc, "net_proxy_acl_entry_matches", {"deny_host": "evil.com", "host": "any.com", "port": 443}, req_id); req_id += 1
    check("net_proxy_acl_entry_matches", "allow_all matches any host", r, e, True, "allow_all_matches")

    # 21. glob_match — simple literal
    r, e = call_tool(proc, "net_proxy_glob_match", {"pattern": "hello", "text": "hello"}, req_id); req_id += 1
    check("net_proxy_glob_match", "literal match", r, e, True, "matched")

    # 22. glob_match — *.txt matches file.txt
    r, e = call_tool(proc, "net_proxy_glob_match", {"pattern": "*.txt", "text": "file.txt"}, req_id); req_id += 1
    check("net_proxy_glob_match", "*.txt matches file.txt", r, e, True, "matched")

    # 23. glob_match — *.txt does not match dir/file.txt
    r, e = call_tool(proc, "net_proxy_glob_match", {"pattern": "*.txt", "text": "dir/file.txt"}, req_id); req_id += 1
    check("net_proxy_glob_match", "*.txt no match dir/file.txt", r, e, False, "matched")

    # 24. simple_regex_match — dot-star
    r, e = call_tool(proc, "net_proxy_simple_regex_match", {"pattern": "he.*world", "text": "hello world"}, req_id); req_id += 1
    check("net_proxy_simple_regex_match", "he.*world matches hello world", r, e, True, "matched")

    # 25. simple_regex_match — anchored ^hello$
    r, e = call_tool(proc, "net_proxy_simple_regex_match", {"pattern": "^hello$", "text": "hello"}, req_id); req_id += 1
    check("net_proxy_simple_regex_match", "^hello$ matches hello", r, e, True, "matched")

    # 26. simple_regex_match — anchored ^hello$ no match
    r, e = call_tool(proc, "net_proxy_simple_regex_match", {"pattern": "^hello$", "text": "hello world"}, req_id); req_id += 1
    check("net_proxy_simple_regex_match", "^hello$ no match hello world", r, e, False, "matched")

    # 27. headers_to_json — single pair (parameter key is "headers")
    pairs = [["Content-Type", "application/json"]]
    r, e = call_tool(proc, "net_proxy_headers_to_json", {"headers": pairs}, req_id); req_id += 1
    tools_hardened.add("net_proxy_headers_to_json")
    expected_json = '[{"name":"Content-Type","value":"application/json"}]'
    if e:
        checks_failed += 1
        mismatches.append({"tool": "net_proxy_headers_to_json", "desc": "single pair", "error": str(e)})
    else:
        actual = r.get("json") if isinstance(r, dict) else None
        # Parse both as JSON to compare semantically
        try:
            act_parsed = json.loads(actual) if actual else None
            exp_parsed = json.loads(expected_json)
            if act_parsed == exp_parsed:
                checks_passed += 1
            else:
                checks_failed += 1
                mismatches.append({"tool": "net_proxy_headers_to_json", "desc": "single pair content", "expected": expected_json, "actual": actual})
        except Exception as ex:
            checks_failed += 1
            mismatches.append({"tool": "net_proxy_headers_to_json", "desc": "single pair parse error", "error": str(ex), "actual": actual})

    # 28. shared_stats_ops — req_bytes=100, resp_bytes=200
    # Tool: inc_connections(1), inc_requests(req_bytes), inc_responses(resp_bytes), inc_errors(1)
    # snapshot: requests=1, bytes_in=100, bytes_out=200, errors=1, connections=1
    r, e = call_tool(proc, "net_proxy_shared_stats_ops", {"req_bytes": 100, "resp_bytes": 200}, req_id); req_id += 1
    tools_hardened.add("net_proxy_shared_stats_ops")
    if e:
        checks_failed += 1
        mismatches.append({"tool": "net_proxy_shared_stats_ops", "desc": "stats ops", "error": str(e)})
    else:
        # bytes_in should equal req_bytes=100
        act_bytes_in = r.get("bytes_in") if isinstance(r, dict) else None
        if act_bytes_in == 100:
            checks_passed += 1
        else:
            checks_failed += 1
            mismatches.append({"tool": "net_proxy_shared_stats_ops", "desc": "bytes_in", "expected": 100, "actual": act_bytes_in})
        # bytes_out should equal resp_bytes=200
        act_bytes_out = r.get("bytes_out") if isinstance(r, dict) else None
        if act_bytes_out == 200:
            checks_passed += 1
        else:
            checks_failed += 1
            mismatches.append({"tool": "net_proxy_shared_stats_ops", "desc": "bytes_out", "expected": 200, "actual": act_bytes_out})

    return tools_hardened, checks_passed, checks_failed, mismatches


def main():
    print(f"Starting MCP: {MCP_EXE}")
    if not os.path.exists(MCP_EXE):
        print(f"ERROR: MCP binary not found at {MCP_EXE}", file=sys.stderr)
        sys.exit(1)

    proc = start_mcp()
    try:
        initialize(proc)
        tools_hardened, checks_passed, checks_failed, mismatches = run_checks(proc)
    finally:
        proc.stdin.close()
        proc.wait(timeout=5)

    report = {
        "module": "net_proxy",
        "tools_hardened": len(tools_hardened),
        "checks_passed": checks_passed,
        "checks_failed": checks_failed,
        "mismatches": mismatches,
    }

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\n=== net_proxy rigorous validation ===")
    print(f"Tools hardened : {len(tools_hardened)}")
    print(f"Checks passed  : {checks_passed}")
    print(f"Checks failed  : {checks_failed}")
    if mismatches:
        print(f"\nMismatches ({len(mismatches)}):")
        for m in mismatches:
            print(f"  [{m['tool']}] {m.get('desc','')}: expected={m.get('expected')} actual={m.get('actual')} error={m.get('error','')}")
    print(f"\nReport saved to: {REPORT_PATH}")
    return report


if __name__ == "__main__":
    main()
