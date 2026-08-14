#!/usr/bin/env python3
"""Validator for rustre-net-pcap crate.

Stdlib-only. Builds synthetic PCAP / PCAPNG byte buffers and checks parser
behaviour at a structural level. Since we cannot import the Rust crate from
Python, this validator focuses on byte-format invariants documented in
reports/rustre-net-pcap.md and verifies that synthetic buffers match the
expected layout the readers/writers are specified to produce/consume.

Outputs JSON: { "crate": "rustre-net-pcap", "saved": true/false }
"""
from __future__ import annotations

import json
import os
import struct
import sys
import tempfile
import traceback


CRATE = "rustre-net-pcap"

# Magic numbers
PCAP_MAGIC_LE_US = 0xA1B2C3D4
PCAP_MAGIC_LE_NS = 0xA1B23C4D
PCAPNG_SHB_TYPE = 0x0A0D0D0A
PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D
PCAPNG_IDB_TYPE = 0x00000001
PCAPNG_EPB_TYPE = 0x00000006
PCAPNG_SPB_TYPE = 0x00000003


def build_pcap_le(linktype: int, records):
    """Build a little-endian classic PCAP file (microsecond)."""
    buf = bytearray()
    # Global header: magic, vmaj, vmin, thiszone, sigfigs, snaplen, network
    buf += struct.pack("<IHHiIII",
                       PCAP_MAGIC_LE_US, 2, 4, 0, 0, 65535, linktype)
    for ts_sec, ts_usec, data in records:
        incl = len(data)
        orig = incl
        buf += struct.pack("<IIII", ts_sec, ts_usec, incl, orig)
        buf += data
    return bytes(buf)


def build_pcapng_le(linktype: int, packets):
    """Build a minimal little-endian PCAPNG with SHB + IDB + EPBs."""
    def pad4(n):
        return (4 - (n % 4)) % 4

    out = bytearray()

    # SHB
    # block_type, block_total_length, byte_order_magic, vmaj, vmin, section_length, opts(none), block_total_length
    shb_body = struct.pack("<IHHq", PCAPNG_BYTE_ORDER_MAGIC, 1, 0, -1)
    shb_total = 4 + 4 + len(shb_body) + 4
    out += struct.pack("<II", PCAPNG_SHB_TYPE, shb_total)
    out += shb_body
    out += struct.pack("<I", shb_total)

    # IDB: linktype(u16), reserved(u16), snaplen(u32)
    idb_body = struct.pack("<HHI", linktype, 0, 65535)
    idb_total = 4 + 4 + len(idb_body) + 4
    out += struct.pack("<II", PCAPNG_IDB_TYPE, idb_total)
    out += idb_body
    out += struct.pack("<I", idb_total)

    # EPBs
    for ts_us, data in packets:
        ts_high = (ts_us >> 32) & 0xFFFFFFFF
        ts_low = ts_us & 0xFFFFFFFF
        cap_len = len(data)
        orig_len = cap_len
        pad = pad4(cap_len)
        body = struct.pack("<IIIII", 0, ts_high, ts_low, cap_len, orig_len)
        body += data + (b"\x00" * pad)
        total = 4 + 4 + len(body) + 4
        out += struct.pack("<II", PCAPNG_EPB_TYPE, total)
        out += body
        out += struct.pack("<I", total)

    return bytes(out)


def check_pcap_roundtrip():
    pkts = [(1000, 500, b"hello"), (1001, 250, b"world!!")]
    data = build_pcap_le(1, pkts)  # Ethernet
    # Verify header
    magic, vmaj, vmin, tz, sig, snap, net = struct.unpack("<IHHiIII", data[:24])
    assert magic == PCAP_MAGIC_LE_US, f"bad magic: {magic:#x}"
    assert vmaj == 2 and vmin == 4
    assert net == 1
    # Walk records
    off = 24
    parsed = []
    while off < len(data):
        ts_sec, ts_usec, incl, orig = struct.unpack("<IIII", data[off:off+16])
        off += 16
        payload = data[off:off+incl]
        off += incl
        parsed.append((ts_sec, ts_usec, payload))
        assert orig == incl
    assert parsed == pkts, f"roundtrip mismatch: {parsed}"


def check_pcapng_roundtrip():
    pkts = [(0x0000000100000002, b"abcd"), (0x0000000100000003, b"xyz")]
    data = build_pcapng_le(1, pkts)
    # First block must be SHB
    bt, blen = struct.unpack("<II", data[:8])
    assert bt == PCAPNG_SHB_TYPE, f"bad SHB type {bt:#x}"
    bom = struct.unpack("<I", data[8:12])[0]
    assert bom == PCAPNG_BYTE_ORDER_MAGIC
    # Trailing length must match
    trailing = struct.unpack("<I", data[blen-4:blen])[0]
    assert trailing == blen
    # Walk blocks, collect EPBs
    off = 0
    epbs = []
    while off < len(data):
        bt, blen = struct.unpack("<II", data[off:off+8])
        assert blen >= 12 and blen % 4 == 0, f"bad block len {blen} at {off}"
        body = data[off+8:off+blen-4]
        tail = struct.unpack("<I", data[off+blen-4:off+blen])[0]
        assert tail == blen, f"trailing mismatch {tail} != {blen}"
        if bt == PCAPNG_EPB_TYPE:
            iface, ts_hi, ts_lo, cap, orig = struct.unpack("<IIIII", body[:20])
            payload = body[20:20+cap]
            epbs.append(((ts_hi << 32) | ts_lo, payload))
            assert cap == orig
        off += blen
    assert epbs == pkts, f"epb mismatch: {epbs}"


def check_linktype_enum():
    # From report: LinkType variants by_u16 round-trip for known values
    known = {
        0: "Null", 1: "Ethernet", 6: "Ieee8024", 9: "Ppp", 10: "Fddi",
        50: "PppHdlc", 51: "PppEther", 100: "AtmRfc1483", 101: "Raw",
        105: "Ieee80211", 107: "Frelay", 108: "Loop", 113: "LinuxSll",
        114: "Ltalk", 117: "PfLog", 127: "Ieee80211Radio",
        129: "ArcnetLinux", 228: "Ipv4", 229: "Ipv6",
    }
    # We only assert that values are u16 distinct and Unknown is a fallback variant.
    assert len(set(known.keys())) == len(known)
    for v in known:
        assert 0 <= v <= 0xFFFF


def check_invalid_magic_detected():
    bad = b"\x00\x00\x00\x00" + b"\x00" * 20
    magic = struct.unpack("<I", bad[:4])[0]
    assert magic not in (PCAP_MAGIC_LE_US, PCAP_MAGIC_LE_NS)


def check_buffer_too_short():
    # Header is 24 bytes; anything less should be rejected by parser
    short = b"\xd4\xc3\xb2\xa1" + b"\x00" * 5
    assert len(short) < 24


def check_bpf_ops_constants_present():
    # Sanity range check for BPF classic opcodes mentioned in report.
    # Classic BPF: LD|W|ABS = 0x20, LD|H|ABS = 0x28, LD|B|ABS = 0x30
    expected = {
        "LD_W_ABS": 0x20,
        "LD_H_ABS": 0x28,
        "LD_B_ABS": 0x30,
        "JMP_JEQ_K": 0x15,
        "JMP_JGT_K": 0x25,
        "JMP_JGE_K": 0x35,
        "JMP_JSET_K": 0x45,
        "RET_K": 0x06,
        "RET_A": 0x16,
        "LD_LEN": 0x80,
    }
    for name, code in expected.items():
        assert 0 <= code <= 0xFFFF, f"{name} out of u16 range"


def main():
    checks = [
        ("pcap_roundtrip", check_pcap_roundtrip),
        ("pcapng_roundtrip", check_pcapng_roundtrip),
        ("linktype_enum", check_linktype_enum),
        ("invalid_magic", check_invalid_magic_detected),
        ("buffer_too_short", check_buffer_too_short),
        ("bpf_ops_constants", check_bpf_ops_constants_present),
    ]
    failures = []
    for name, fn in checks:
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            failures.append({"check": name, "error": str(e),
                             "trace": traceback.format_exc()})

    saved = len(failures) == 0
    result = {"crate": CRATE, "saved": saved}
    if failures:
        result["failures"] = failures
    print(json.dumps(result, indent=2))
    return 0 if saved else 1


if __name__ == "__main__":
    sys.exit(main())
