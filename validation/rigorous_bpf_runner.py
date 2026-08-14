#!/usr/bin/env python3
"""
Rigorous ground-truth validation for bpf_* MCP tools.
Reference data derived directly from the Rust source static HELPERS table.
"""
import json, subprocess, sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"

# ── Ground-truth table extracted from crates/rustre-arch-bpf/src/lib.rs ──────
# Only a representative slice is needed; we check enough to confirm the table
# and the lookup logic are correct.

KNOWN_HELPERS = {
    1:  {"name": "bpf_map_lookup_elem",
         "proto": "void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)",
         "may_sleep": False, "pkt_access": False},
    2:  {"name": "bpf_map_update_elem",
         "proto": "int bpf_map_update_elem(struct bpf_map *map, const void *key, const void *value, u64 flags)",
         "may_sleep": False, "pkt_access": False},
    206: {"name": "bpf_tcp_raw_check_syncookie_ipv4",
          "proto": "long bpf_tcp_raw_check_syncookie_ipv4(struct iphdr *iph, struct tcphdr *th)",
          "may_sleep": False, "pkt_access": False},
}

# Helper IDs that do NOT exist (beyond 206)
UNKNOWN_IDS = [0, 207, 9999]


# ── MCP subprocess helpers ────────────────────────────────────────────────────

def start_server():
    p = subprocess.Popen(
        [EXE, "--transport=stdio"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, bufsize=0
    )
    return p

def send(p, req):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()

def recv(p):
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("server died")
    return json.loads(line)

def call_tool(p, rid, name, args):
    send(p, {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
             "params": {"name": name, "arguments": args}})
    resp = recv(p)
    if "error" in resp:
        raise RuntimeError(f"JSONRPC error: {resp['error']}")
    result = resp["result"]
    if result.get("isError"):
        raise RuntimeError(f"Tool error: {result['content'][0]['text']}")
    return json.loads(result["content"][0]["text"])


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    p = start_server()
    rid = 0

    def next_id():
        nonlocal rid
        rid += 1
        return rid

    # Handshake
    send(p, {"jsonrpc": "2.0", "id": next_id(), "method": "initialize",
             "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": {"name": "rigorous_bpf", "version": "1"}}})
    recv(p)
    send(p, {"jsonrpc": "2.0", "method": "notifications/initialized"})

    # project.open (required by server before other tools)
    send(p, {"jsonrpc": "2.0", "id": next_id(), "method": "tools/call",
             "params": {"name": "project.open", "arguments": {"path": TARGET}}})
    recv(p)

    results = []
    mismatches = []

    # ── Test bpf_lookup_helper ────────────────────────────────────────────────
    # 1a. Known helpers must return found=true with correct fields
    for helper_id, expected in KNOWN_HELPERS.items():
        try:
            actual = call_tool(p, next_id(), "bpf_lookup_helper", {"id": helper_id})
        except Exception as e:
            results.append({"tool": "bpf_lookup_helper", "id": helper_id,
                            "status": "FAIL", "reason": str(e)})
            mismatches.append({"tool": "bpf_lookup_helper",
                                "expected": f"found helper {helper_id}",
                                "actual": str(e)})
            continue

        ok = True
        reasons = []
        if actual.get("found") is not True:
            ok = False; reasons.append(f"found={actual.get('found')} want True")
        if actual.get("id") != helper_id:
            ok = False; reasons.append(f"id={actual.get('id')} want {helper_id}")
        if actual.get("name") != expected["name"]:
            ok = False; reasons.append(f"name={actual.get('name')!r} want {expected['name']!r}")
        if actual.get("proto") != expected["proto"]:
            ok = False; reasons.append(f"proto mismatch")
        if actual.get("may_sleep") != expected["may_sleep"]:
            ok = False; reasons.append(f"may_sleep={actual.get('may_sleep')} want {expected['may_sleep']}")
        if actual.get("pkt_access") != expected["pkt_access"]:
            ok = False; reasons.append(f"pkt_access={actual.get('pkt_access')} want {expected['pkt_access']}")

        status = "PASS" if ok else "FAIL"
        entry = {"tool": "bpf_lookup_helper", "id": helper_id, "status": status}
        if not ok:
            entry["reasons"] = reasons
            mismatches.append({"tool": "bpf_lookup_helper",
                                "expected": expected,
                                "actual": actual})
        results.append(entry)

    # 1b. Unknown IDs must return found=false
    for bad_id in UNKNOWN_IDS:
        try:
            actual = call_tool(p, next_id(), "bpf_lookup_helper", {"id": bad_id})
        except Exception as e:
            results.append({"tool": "bpf_lookup_helper", "id": bad_id,
                            "status": "FAIL", "reason": str(e)})
            mismatches.append({"tool": "bpf_lookup_helper",
                                "expected": {"found": False},
                                "actual": str(e)})
            continue

        ok = actual.get("found") is False
        entry = {"tool": "bpf_lookup_helper", "id": bad_id,
                 "status": "PASS" if ok else "FAIL"}
        if not ok:
            entry["reason"] = f"found={actual.get('found')} want False"
            mismatches.append({"tool": "bpf_lookup_helper",
                                "expected": {"found": False}, "actual": actual})
        results.append(entry)

    # ── Test bpf_lookup_helper_by_name ────────────────────────────────────────
    # 2a. Known names
    for helper_id, expected in KNOWN_HELPERS.items():
        name_str = expected["name"]
        try:
            actual = call_tool(p, next_id(), "bpf_lookup_helper_by_name",
                               {"name": name_str})
        except Exception as e:
            results.append({"tool": "bpf_lookup_helper_by_name", "name": name_str,
                            "status": "FAIL", "reason": str(e)})
            mismatches.append({"tool": "bpf_lookup_helper_by_name",
                                "expected": f"found helper {name_str}",
                                "actual": str(e)})
            continue

        ok = True
        reasons = []
        if actual.get("found") is not True:
            ok = False; reasons.append(f"found={actual.get('found')} want True")
        if actual.get("id") != helper_id:
            ok = False; reasons.append(f"id={actual.get('id')} want {helper_id}")
        if actual.get("name") != name_str:
            ok = False; reasons.append(f"name={actual.get('name')!r} want {name_str!r}")

        status = "PASS" if ok else "FAIL"
        entry = {"tool": "bpf_lookup_helper_by_name", "name": name_str,
                 "status": status}
        if not ok:
            entry["reasons"] = reasons
            mismatches.append({"tool": "bpf_lookup_helper_by_name",
                                "expected": expected, "actual": actual})
        results.append(entry)

    # 2b. Unknown name
    try:
        actual = call_tool(p, next_id(), "bpf_lookup_helper_by_name",
                           {"name": "bpf_does_not_exist"})
        ok = actual.get("found") is False
        entry = {"tool": "bpf_lookup_helper_by_name",
                 "name": "bpf_does_not_exist",
                 "status": "PASS" if ok else "FAIL"}
        if not ok:
            entry["reason"] = f"found={actual.get('found')} want False"
            mismatches.append({"tool": "bpf_lookup_helper_by_name",
                                "expected": {"found": False}, "actual": actual})
        results.append(entry)
    except Exception as e:
        results.append({"tool": "bpf_lookup_helper_by_name",
                        "name": "bpf_does_not_exist",
                        "status": "FAIL", "reason": str(e)})
        mismatches.append({"tool": "bpf_lookup_helper_by_name",
                            "expected": {"found": False}, "actual": str(e)})

    p.stdin.close(); p.terminate()

    # ── Summary ───────────────────────────────────────────────────────────────
    passed  = sum(1 for r in results if r["status"] == "PASS")
    failed  = sum(1 for r in results if r["status"] == "FAIL")
    skipped = sum(1 for r in results if r["status"] == "SKIP")
    # Two distinct tools exercised
    tools_hardened = 2

    output = {
        "category": "bpf",
        "tools_hardened": tools_hardened,
        "tools_passed":  passed,
        "tools_failed":  failed,
        "tools_skipped": skipped,
        "mismatches": mismatches,
        "detail": results,
    }

    out_path = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_bpf_v2.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    print(json.dumps({k: v for k, v in output.items() if k != "detail"}, indent=2))
    return output

if __name__ == "__main__":
    main()
