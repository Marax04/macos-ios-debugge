#!/usr/bin/env python3
"""Independent Python validator for rustre-debug-kgdb.

Reimplements (without importing the Rust crate or calling MCP) a subset of the
functions described in reports/rustre-debug-kgdb.md, using only Python stdlib.
"""
import json
import struct


# ---------- hex helpers ----------
def bytes_to_hex(data: bytes) -> str:
    return data.hex()


def hex_to_bytes(s: str) -> bytes:
    if len(s) % 2 != 0:
        raise ValueError("odd hex length")
    return bytes.fromhex(s)


def u32_to_hex_le(v: int) -> str:
    return struct.pack("<I", v & 0xFFFFFFFF).hex()


def u64_to_hex_le(v: int) -> str:
    return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF).hex()


def hex_le_to_u64(s: str) -> int:
    b = bytes.fromhex(s)
    if len(b) > 8:
        raise ValueError("too long")
    b = b + b"\x00" * (8 - len(b))
    return struct.unpack("<Q", b)[0]


# ---------- RSP packet ----------
def rsp_checksum(payload: bytes) -> int:
    return sum(payload) % 256


def rsp_encode(payload: bytes) -> bytes:
    return b"$" + payload + b"#" + f"{rsp_checksum(payload):02x}".encode()


def rsp_decode(packet: bytes):
    if not packet.startswith(b"$") or b"#" not in packet:
        raise ValueError("bad packet")
    body, _, tail = packet[1:].partition(b"#")
    cs = int(tail[:2], 16)
    if cs != rsp_checksum(body):
        raise ValueError("checksum mismatch")
    return body


# ---------- gdb Z/z command ----------
def gdb_z_command(insert: bool, kind: int, address: int, size: int) -> str:
    op = "Z" if insert else "z"
    return f"{op}{kind},{address:x},{size}"


# ---------- DR7 decoder (Intel SDM Vol.3B 17.2) ----------
def describe_dr7(dr7: int):
    out = []
    for i in range(4):
        local = (dr7 >> (i * 2)) & 1
        glob = (dr7 >> (i * 2 + 1)) & 1
        if not (local or glob):
            continue
        rw = (dr7 >> (16 + i * 4)) & 0b11
        ln = (dr7 >> (18 + i * 4)) & 0b11
        rw_map = {0: "X", 1: "W", 2: "IO", 3: "RW"}
        len_map = {0: 1, 1: 2, 2: 8, 3: 4}
        out.append(f"DR{i} L={local} G={glob} RW={rw_map[rw]} LEN={len_map[ln]}")
    return out


# ---------- kallsyms parser ----------
def parse_kallsyms(text: str):
    entries = []
    for line in text.splitlines():
        parts = line.split(None, 3)
        if len(parts) < 3:
            continue
        try:
            addr = int(parts[0], 16)
        except ValueError:
            continue
        entries.append({
            "addr": addr,
            "type": parts[1],
            "name": parts[2],
            "module": parts[3].strip("[]") if len(parts) > 3 else None,
        })
    return entries


def kaslr_slide(runtime_sym_addr: int, system_map_addr: int) -> int:
    return runtime_sym_addr - system_map_addr


# ---------- /proc/iomem parser ----------
def parse_iomem(text: str):
    regions = []
    for line in text.splitlines():
        line = line.rstrip()
        if not line or ":" not in line:
            continue
        rng, _, desc = line.strip().partition(":")
        try:
            start_s, end_s = rng.strip().split("-")
            regions.append({
                "start": int(start_s, 16),
                "end": int(end_s, 16),
                "desc": desc.strip(),
            })
        except ValueError:
            continue
    return regions


# ---------- KD packet header ----------
KD_LEADER_CONTROL = 0x30303030
KD_LEADER_DATA = 0x69696969


def kd_parse_header(buf: bytes):
    if len(buf) < 16:
        raise ValueError("short")
    leader, ptype, bcount, pid, csum = struct.unpack("<IHHII", buf[:16])
    return {
        "leader": leader,
        "type": ptype,
        "byte_count": bcount,
        "id": pid,
        "checksum": csum,
        "is_control": leader == KD_LEADER_CONTROL,
        "is_data": leader == KD_LEADER_DATA,
    }


# ---------- self-tests on functions ----------
def run():
    functions = []

    def add(name, ok, detail=""):
        functions.append({"name": name, "ok": bool(ok), "detail": detail})

    add("bytes_to_hex", bytes_to_hex(b"\x00\xff") == "00ff")
    add("hex_to_bytes", hex_to_bytes("deadbeef") == b"\xde\xad\xbe\xef")
    add("u32_to_hex_le", u32_to_hex_le(0x11223344) == "44332211")
    add("u64_to_hex_le", u64_to_hex_le(0x1122334455667788) == "8877665544332211")
    add("hex_le_to_u64", hex_le_to_u64("44332211") == 0x11223344)

    pkt = rsp_encode(b"OK")
    add("rsp_encode", pkt == b"$OK#9a")
    add("rsp_decode", rsp_decode(pkt) == b"OK")
    add("rsp_checksum", rsp_checksum(b"OK") == (ord("O") + ord("K")) % 256)

    add("gdb_z_command_insert_sw", gdb_z_command(True, 0, 0x1000, 1) == "Z0,1000,1")
    add("gdb_z_command_remove_hw_write", gdb_z_command(False, 2, 0xdeadbeef, 4) == "z2,deadbeef,4")

    # DR7: enable DR0 local, RW=W(1), LEN=4(3) -> bits 0=1, 16..17=01, 18..19=11
    dr7 = 1 | (1 << 16) | (3 << 18)
    desc = describe_dr7(dr7)
    add("describe_dr7", len(desc) == 1 and "DR0" in desc[0] and "LEN=4" in desc[0] and "RW=W" in desc[0], str(desc))

    syms = parse_kallsyms("ffffffff81000000 T _stext\nffffffff81000100 t local_fn\nffffffff81000200 T mod_fn\t[mymod]\n")
    add("parse_kallsyms", len(syms) == 3 and syms[0]["name"] == "_stext" and syms[2]["module"] == "mymod", json.dumps(syms))

    add("kaslr_slide", kaslr_slide(0xffffffffa1000000, 0xffffffff81000000) == 0x20000000)

    iomem = parse_iomem("00000000-00000fff : Reserved\n00001000-0009fbff : System RAM\n")
    add("parse_iomem", len(iomem) == 2 and iomem[1]["desc"] == "System RAM" and iomem[1]["end"] == 0x9fbff)

    # KD header round-trip
    hdr = struct.pack("<IHHII", KD_LEADER_CONTROL, 2, 0, 0xcafebabe, 0)
    parsed = kd_parse_header(hdr)
    add("kd_parse_header", parsed["is_control"] and parsed["id"] == 0xcafebabe)

    saved_all = all(f["ok"] for f in functions)
    result = {
        "crate": "rustre-debug-kgdb",
        "saved": saved_all,
        "functions": functions,
    }
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    run()
