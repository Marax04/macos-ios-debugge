"""Independent validator for rustre-adb crate.

Reimplements pure-logic primitives described in
validation/reports/rustre-adb.md using only Python stdlib, and
emits expected results that can be compared against the crate's
actual behavior.
"""

import json
import struct
from typing import Optional


# ---------- ADB wire constants (AOSP system/core/adb/protocol.txt) ----------
CMD = {
    "SYNC": 0x434e5953,  # 'SYNC'
    "CNXN": 0x4e584e43,  # 'CNXN'
    "AUTH": 0x48545541,  # 'AUTH'
    "OPEN": 0x4e45504f,  # 'OPEN'
    "OKAY": 0x59414b4f,  # 'OKAY'
    "CLSE": 0x45534c43,  # 'CLSE'
    "WRTE": 0x45545257,  # 'WRTE'
}
ADB_VERSION = 0x01000000
ADB_MAX_PAYLOAD = 262144
SYNC_MAX_DATA_CHUNK = 65536


def fourcc(s: str) -> int:
    b = s.encode("ascii")
    return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)


def compute_crc32(data: bytes) -> int:
    """ADB CRC = sum of bytes mod 2^32 (NOT IEEE)."""
    return sum(data) & 0xFFFFFFFF


def encode_message(cmd: int, arg0: int, arg1: int, data: bytes) -> bytes:
    magic = cmd ^ 0xFFFFFFFF
    crc = compute_crc32(data)
    header = struct.pack("<IIIII I", cmd, arg0, arg1, len(data), crc, magic)
    # struct above has a space-typo guard; rebuild cleanly:
    header = struct.pack("<6I", cmd, arg0, arg1, len(data), crc, magic)
    return header + data


def decode_message(buf: bytes) -> dict:
    if len(buf) < 24:
        raise ValueError("short header")
    cmd, arg0, arg1, dlen, crc, magic = struct.unpack("<6I", buf[:24])
    data = buf[24:24 + dlen]
    if len(data) != dlen:
        raise ValueError("short data")
    if magic != (cmd ^ 0xFFFFFFFF):
        raise ValueError("bad magic")
    return {
        "command": cmd, "arg0": arg0, "arg1": arg1,
        "data": data, "crc32": crc, "magic": magic,
    }


def host_request(s: str) -> bytes:
    return f"{len(s):04X}{s}".encode("ascii")


# ---------- logcat parsers ----------
def parse_brief(line: str) -> Optional[dict]:
    # Format: "L/Tag(  pid): message"
    if len(line) < 4 or line[1] != "/":
        return None
    lvl = line[0]
    rest = line[2:]
    if "(" not in rest or "):" not in rest:
        return None
    tag, after = rest.split("(", 1)
    pid_str, msg = after.split("):", 1)
    try:
        pid = int(pid_str.strip())
    except ValueError:
        return None
    return {"level": lvl, "tag": tag.strip(), "pid": pid, "message": msg.lstrip()}


def parse_threadtime(line: str) -> Optional[dict]:
    # "MM-DD HH:MM:SS.mmm  PID  TID L Tag: msg"
    parts = line.split(None, 5)
    if len(parts) < 6:
        return None
    date, time_, pid, tid, lvl, rest = parts
    try:
        pid_i = int(pid); tid_i = int(tid)
    except ValueError:
        return None
    if ":" not in rest:
        return None
    tag, msg = rest.split(":", 1)
    return {
        "timestamp": f"{date} {time_}",
        "pid": pid_i, "tid": tid_i, "level": lvl,
        "tag": tag.strip(), "message": msg.lstrip(),
    }


# ---------- validation functions ----------
def fn_constants():
    return {
        "ADB_VERSION": ADB_VERSION,
        "ADB_MAX_PAYLOAD": ADB_MAX_PAYLOAD,
        "SYNC_MAX_DATA_CHUNK": SYNC_MAX_DATA_CHUNK,
        "cmd_CNXN": CMD["CNXN"],
        "cmd_AUTH": CMD["AUTH"],
        "cmd_OPEN": CMD["OPEN"],
        "cmd_OKAY": CMD["OKAY"],
        "cmd_CLSE": CMD["CLSE"],
        "cmd_WRTE": CMD["WRTE"],
        "cmd_SYNC": CMD["SYNC"],
        "cmd_CNXN_fourcc_check": fourcc("CNXN"),
    }


def fn_compute_crc32():
    return {
        "empty": compute_crc32(b""),
        "ABC": compute_crc32(b"ABC"),       # 198
        "hello": compute_crc32(b"hello"),    # 532
    }


def fn_encode_decode_roundtrip():
    msg = encode_message(CMD["OPEN"], 1, 0, b"shell:\x00")
    dec = decode_message(msg)
    return {
        "encoded_len": len(msg),
        "header_magic_ok": dec["magic"] == (CMD["OPEN"] ^ 0xFFFFFFFF),
        "command": dec["command"],
        "arg0": dec["arg0"],
        "arg1": dec["arg1"],
        "data_hex": dec["data"].hex(),
        "crc32": dec["crc32"],
    }


def fn_host_request():
    return {
        "host_version": host_request("host:version").decode("ascii"),
        "host_devices_l": host_request("host:devices-l").decode("ascii"),
    }


def fn_parse_brief():
    return parse_brief("I/Foo(123): hello")


def fn_parse_threadtime():
    return parse_threadtime("01-01 12:00:00.000  1234  5678 I Tag: msg")


FUNCTIONS = [
    ("constants", fn_constants),
    ("compute_crc32", fn_compute_crc32),
    ("encode_decode_roundtrip", fn_encode_decode_roundtrip),
    ("host_request", fn_host_request),
    ("parse_brief", fn_parse_brief),
    ("parse_threadtime", fn_parse_threadtime),
]


def main():
    results = []
    for name, fn in FUNCTIONS:
        try:
            results.append({"name": name, "ok": True, "result": fn()})
        except Exception as e:
            results.append({"name": name, "ok": False, "error": str(e)})
    out = {"crate": "rustre-adb", "saved": True, "functions": results}
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    main()
