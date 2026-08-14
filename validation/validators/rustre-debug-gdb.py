"""Independent validator for rustre-debug-gdb.

Verifies GDB Remote Serial Protocol primitives using only Python stdlib.
No imports from the Rust crate, no MCP calls.
"""
import json


def checksum(data: bytes) -> int:
    return sum(data) % 256


def escape_data(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        if b in (0x23, 0x24, 0x7D, 0x2A):  # # $ } *
            out.append(0x7D)
            out.append(b ^ 0x20)
        else:
            out.append(b)
    return bytes(out)


def unescape_data(data: bytes) -> bytes:
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


def encode_packet(payload: str) -> str:
    cs = checksum(payload.encode())
    return f"${payload}#{cs:02x}"


def mem_read_cmd(addr: int, length: int) -> str:
    return f"m{addr:x},{length:x}"


def mem_write_cmd(addr: int, data: bytes) -> str:
    return f"M{addr:x},{len(data):x}:" + data.hex()


def set_sw_bp_cmd(addr: int, kind: int = 1) -> str:
    return f"Z0,{addr:x},{kind}"


def set_watchpoint_write_cmd(addr: int, length: int) -> str:
    return f"Z2,{addr:x},{length:x}"


def parse_stop_reply(reply: str):
    """Return ('breakpoint'|'signal'|'exit'|'unknown', detail_dict)."""
    if not reply:
        return "unknown", {}
    tag = reply[0]
    if tag == "S":
        return "signal", {"signal": int(reply[1:3], 16)}
    if tag == "T":
        sig = int(reply[1:3], 16)
        fields = {}
        rest = reply[3:]
        for kv in rest.split(";"):
            if ":" in kv:
                k, v = kv.split(":", 1)
                fields[k] = v
        reason = fields.get("reason", "")
        kind = "signal"
        if reason in ("breakpoint", "swbreak", "hwbreak"):
            kind = "breakpoint"
        detail = {"signal": sig, "reason": reason}
        if "pc" in fields:
            try:
                detail["pc"] = int(fields["pc"], 16)
            except ValueError:
                pass
        return kind, detail
    if tag in ("W", "X"):
        return "exit", {"code": int(reply[1:3], 16)}
    return "unknown", {"raw": reply}


def signal_name(num: int) -> str:
    table = {1: "SIGHUP", 2: "SIGINT", 5: "SIGTRAP", 6: "SIGABRT",
             9: "SIGKILL", 11: "SIGSEGV", 13: "SIGPIPE", 15: "SIGTERM"}
    return table.get(num, f"SIG{num}")


def run():
    functions = []

    # 1. checksum vCont;c == 0xa8
    cs1 = checksum(b"vCont;c")
    functions.append({"name": "checksum_vCont_c", "expected": "0xa8",
                      "got": f"0x{cs1:02x}", "ok": cs1 == 0xa8})

    # 2. checksum g == 0x67
    cs2 = checksum(b"g")
    functions.append({"name": "checksum_g", "expected": "0x67",
                      "got": f"0x{cs2:02x}", "ok": cs2 == 0x67})

    # 3. encode g
    enc = encode_packet("g")
    functions.append({"name": "encode_g", "expected": "$g#67",
                      "got": enc, "ok": enc == "$g#67"})

    # 4. escape round-trip
    raw = bytes([0x10, 0x23, 0x24, 0x7D, 0x2A, 0xFF])
    rt = unescape_data(escape_data(raw))
    functions.append({"name": "escape_roundtrip", "expected": raw.hex(),
                      "got": rt.hex(), "ok": rt == raw})

    # 5. escape produces correct bytes for '#'
    esc_hash = escape_data(b"#")
    functions.append({"name": "escape_hash", "expected": "7d03",
                      "got": esc_hash.hex(), "ok": esc_hash == b"\x7d\x03"})

    # 6. memory read cmd
    mr = mem_read_cmd(0x1000, 4)
    functions.append({"name": "mem_read_cmd", "expected": "m1000,4",
                      "got": mr, "ok": mr == "m1000,4"})

    # 7. memory write cmd
    mw = mem_write_cmd(0x1000, bytes.fromhex("deadbeef"))
    functions.append({"name": "mem_write_cmd", "expected": "M1000,4:deadbeef",
                      "got": mw, "ok": mw == "M1000,4:deadbeef"})

    # 8. sw breakpoint cmd
    bp = set_sw_bp_cmd(0x401000)
    functions.append({"name": "set_sw_bp_cmd", "expected": "Z0,401000,1",
                      "got": bp, "ok": bp == "Z0,401000,1"})

    # 9. watchpoint cmd
    wp = set_watchpoint_write_cmd(0x402000, 4)
    functions.append({"name": "set_watchpoint_write_cmd",
                      "expected": "Z2,402000,4", "got": wp,
                      "ok": wp == "Z2,402000,4"})

    # 10. stop reply: T05 breakpoint pc
    kind, det = parse_stop_reply("T05thread:1;reason:breakpoint;pc:400500")
    ok = kind == "breakpoint" and det.get("pc") == 0x400500
    functions.append({"name": "parse_stop_T05_breakpoint",
                      "expected": "breakpoint pc=0x400500",
                      "got": f"{kind} pc=0x{det.get('pc', 0):x}", "ok": ok})

    # 11. stop reply: bare SIGTRAP stays signal
    kind2, det2 = parse_stop_reply("S05")
    ok2 = kind2 == "signal" and det2.get("signal") == 5
    functions.append({"name": "parse_stop_S05_signal",
                      "expected": "signal 5", "got": f"{kind2} {det2.get('signal')}",
                      "ok": ok2})

    # 12. exit reply
    kind3, det3 = parse_stop_reply("W00")
    ok3 = kind3 == "exit" and det3.get("code") == 0
    functions.append({"name": "parse_stop_W00_exit",
                      "expected": "exit 0", "got": f"{kind3} {det3.get('code')}",
                      "ok": ok3})

    # 13. POSIX signals
    s5 = signal_name(5)
    s11 = signal_name(11)
    functions.append({"name": "signal_name_5", "expected": "SIGTRAP",
                      "got": s5, "ok": s5 == "SIGTRAP"})
    functions.append({"name": "signal_name_11", "expected": "SIGSEGV",
                      "got": s11, "ok": s11 == "SIGSEGV"})

    result = {
        "crate": "rustre-debug-gdb",
        "saved": True,
        "functions": functions,
    }
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    run()
