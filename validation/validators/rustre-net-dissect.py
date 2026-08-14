#!/usr/bin/env python3
"""
Independent Python validator for crate `rustre-net-dissect`.

Reimplements a representative subset of the crate's pure, testable functions
using only the Python standard library. No Rust import, no MCP calls.

Covered helpers (mirroring the crate's free functions / const tables):
  - byte_entropy(data)                              -> Shannon entropy in bits/byte
  - ja3_fingerprint(data)                           -> MD5 hex of canonical JA3 string
  - ja3s_fingerprint(data)                          -> MD5 hex of canonical JA3S string
  - decode_http_chunked(data)                       -> decoded body bytes
  - url_decode(data)                                -> percent-decoded bytes
  - dnp3_crc16(data)                                -> DNP3 CRC-16 (poly 0xA6BC, init 0x0000, refin/refout, xorout 0xFFFF)
  - icmp_stream_tunnel_heuristic(payloads)          -> bool
  - scan_http_attacks(data)                         -> list of indicator dicts
  - scan_http_attacks_decoded(data)                 -> list of indicator dicts
  - fingerprint_protocol(data, sport, dport)        -> &'static str (port / payload heuristics)
  - dns_rtype_name(t)                               -> str
  - tls_version_name(v)                             -> str
  - icmp_type_name(t)                               -> str
  - is_ics_port(port)                               -> bool
  - ics_protocol_for_port(port)                     -> str | None

CLI:
  python rustre-net-dissect.py             -> self-test, prints JSON report
  python rustre-net-dissect.py --stdin     -> read {func,input} JSON, write {output}
"""
from __future__ import annotations

import hashlib
import json
import math
import sys
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ICMP_TUNNEL_LARGE_PAYLOAD_THRESHOLD = 64
ICMP_TUNNEL_HIGH_ENTROPY_THRESHOLD = 7.0


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def url_decode(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b == 0x25 and i + 2 < len(data):  # '%'
            try:
                out.append(int(data[i + 1:i + 3], 16))
                i += 3
                continue
            except ValueError:
                pass
        if b == 0x2B:  # '+' -> space
            out.append(0x20)
        else:
            out.append(b)
        i += 1
    return bytes(out)


def decode_http_chunked(data: bytes) -> bytes:
    """RFC 7230 chunked-encoding decoder. Returns body or raises ValueError."""
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        # find CRLF
        eol = data.find(b"\r\n", i)
        if eol < 0:
            raise ValueError("missing CRLF in chunk size")
        size_line = data[i:eol].split(b";", 1)[0].strip()
        try:
            size = int(size_line, 16)
        except ValueError as e:
            raise ValueError(f"bad chunk size: {size_line!r}") from e
        i = eol + 2
        if size == 0:
            return bytes(out)
        if i + size > n:
            raise ValueError("chunk overruns buffer")
        out += data[i:i + size]
        i += size
        if data[i:i + 2] != b"\r\n":
            raise ValueError("missing trailing CRLF after chunk")
        i += 2
    raise ValueError("truncated chunked stream")


# ---------------------------------------------------------------------------
# DNP3 CRC-16 (poly 0x3D65 reflected -> 0xA6BC, init 0x0000, xorout 0xFFFF)
# ---------------------------------------------------------------------------

def _build_dnp3_crc_table() -> list[int]:
    poly = 0xA6BC  # reflected 0x3D65
    table = []
    for n in range(256):
        c = n
        for _ in range(8):
            if c & 1:
                c = (c >> 1) ^ poly
            else:
                c >>= 1
        table.append(c & 0xFFFF)
    return table


_DNP3_CRC_TABLE = _build_dnp3_crc_table()


def dnp3_crc16(data: bytes) -> int:
    crc = 0x0000
    for b in data:
        crc = ((crc >> 8) ^ _DNP3_CRC_TABLE[(crc ^ b) & 0xFF]) & 0xFFFF
    return crc ^ 0xFFFF


# ---------------------------------------------------------------------------
# ICMP tunnel heuristic
# ---------------------------------------------------------------------------

def icmp_stream_tunnel_heuristic(payloads: list[bytes]) -> bool:
    if not payloads:
        return False
    large = 0
    high_ent = 0
    for p in payloads:
        if len(p) >= ICMP_TUNNEL_LARGE_PAYLOAD_THRESHOLD:
            large += 1
        if byte_entropy(p) >= ICMP_TUNNEL_HIGH_ENTROPY_THRESHOLD:
            high_ent += 1
    # crate heuristic: any large+high-entropy traffic on ICMP is suspicious
    return large >= 1 and high_ent >= 1


# ---------------------------------------------------------------------------
# HTTP attack scanner (subset of indicators)
# ---------------------------------------------------------------------------

_SQLI_TOKENS = (
    b"' or 1=1", b"' or '1'='1", b"union select", b"union all select",
    b"' or sleep(", b"benchmark(", b"information_schema",
)
_XSS_TOKENS = (
    b"<script", b"javascript:", b"onerror=", b"onload=",
    b"<img src=x onerror", b"<svg/onload",
)
_TRAVERSAL_TOKENS = (b"../", b"..\\", b"%2e%2e/", b"%2e%2e\\")
_CMDI_TOKENS = (
    b"; cat ", b"| cat ", b"&& cat ", b"`cat ",
    b"; ls ", b"| ls ", b"$(/", b"|/bin/sh", b";nc ", b"|nc ",
)


def _scan(data: bytes) -> list[dict]:
    lower = data.lower()
    hits: list[dict] = []
    for tok in _SQLI_TOKENS:
        off = lower.find(tok)
        if off >= 0:
            hits.append({"kind": "SqlInjection", "offset": off, "token": tok.decode("latin1")})
    for tok in _XSS_TOKENS:
        off = lower.find(tok)
        if off >= 0:
            hits.append({"kind": "Xss", "offset": off, "token": tok.decode("latin1")})
    for tok in _TRAVERSAL_TOKENS:
        off = lower.find(tok)
        if off >= 0:
            hits.append({"kind": "PathTraversal", "offset": off, "token": tok.decode("latin1")})
    for tok in _CMDI_TOKENS:
        off = lower.find(tok)
        if off >= 0:
            hits.append({"kind": "CommandInjection", "offset": off, "token": tok.decode("latin1")})
    return hits


def scan_http_attacks(data: bytes) -> list[dict]:
    return _scan(data)


def scan_http_attacks_decoded(data: bytes) -> list[dict]:
    return _scan(url_decode(data))


# ---------------------------------------------------------------------------
# TLS / JA3 / JA3S
# ---------------------------------------------------------------------------

_GREASE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}


def _is_grease(v: int) -> bool:
    return v in _GREASE


def _parse_tls_record_handshake(data: bytes) -> tuple[int, bytes] | None:
    """Return (handshake_type, handshake_body) for the first handshake message,
    or None if not a TLS handshake record."""
    if len(data) < 5 + 4:
        return None
    if data[0] != 0x16:  # Handshake
        return None
    # rec_len = int.from_bytes(data[3:5], "big")
    if len(data) < 5 + 4:
        return None
    hs_type = data[5]
    hs_len = int.from_bytes(data[6:9], "big")
    body = data[9:9 + hs_len]
    if len(body) < hs_len:
        return None
    return hs_type, body


def ja3_fingerprint(data: bytes) -> str | None:
    """Compute JA3 MD5 from a TLS ClientHello record. Returns None on parse failure."""
    parsed = _parse_tls_record_handshake(data)
    if not parsed:
        return None
    hs_type, body = parsed
    if hs_type != 1:  # ClientHello
        return None
    try:
        i = 0
        # version(2) random(32)
        version = int.from_bytes(body[i:i + 2], "big"); i += 2
        i += 32
        sid_len = body[i]; i += 1 + sid_len
        cs_len = int.from_bytes(body[i:i + 2], "big"); i += 2
        cs_bytes = body[i:i + cs_len]; i += cs_len
        cs = [
            int.from_bytes(cs_bytes[j:j + 2], "big")
            for j in range(0, len(cs_bytes), 2)
        ]
        cs = [c for c in cs if not _is_grease(c)]
        cm_len = body[i]; i += 1 + cm_len
        exts: list[int] = []
        curves: list[int] = []
        formats: list[int] = []
        if i + 2 <= len(body):
            ext_total = int.from_bytes(body[i:i + 2], "big"); i += 2
            end = i + ext_total
            while i + 4 <= end:
                etype = int.from_bytes(body[i:i + 2], "big"); i += 2
                elen = int.from_bytes(body[i:i + 2], "big"); i += 2
                edata = body[i:i + elen]; i += elen
                if _is_grease(etype):
                    continue
                exts.append(etype)
                if etype == 0x000a and len(edata) >= 2:  # supported_groups
                    sg_len = int.from_bytes(edata[0:2], "big")
                    sg = edata[2:2 + sg_len]
                    curves = [
                        int.from_bytes(sg[j:j + 2], "big")
                        for j in range(0, len(sg), 2)
                    ]
                    curves = [c for c in curves if not _is_grease(c)]
                elif etype == 0x000b and len(edata) >= 1:  # ec_point_formats
                    fmt_len = edata[0]
                    formats = list(edata[1:1 + fmt_len])
        s = "{},{},{},{},{}".format(
            version,
            "-".join(str(x) for x in cs),
            "-".join(str(x) for x in exts),
            "-".join(str(x) for x in curves),
            "-".join(str(x) for x in formats),
        )
        return hashlib.md5(s.encode("ascii")).hexdigest()
    except (IndexError, ValueError):
        return None


def ja3s_fingerprint(data: bytes) -> str | None:
    """Compute JA3S MD5 from a TLS ServerHello record."""
    parsed = _parse_tls_record_handshake(data)
    if not parsed:
        return None
    hs_type, body = parsed
    if hs_type != 2:  # ServerHello
        return None
    try:
        i = 0
        version = int.from_bytes(body[i:i + 2], "big"); i += 2
        i += 32
        sid_len = body[i]; i += 1 + sid_len
        cipher = int.from_bytes(body[i:i + 2], "big"); i += 2
        i += 1  # compression
        exts: list[int] = []
        if i + 2 <= len(body):
            ext_total = int.from_bytes(body[i:i + 2], "big"); i += 2
            end = i + ext_total
            while i + 4 <= end:
                etype = int.from_bytes(body[i:i + 2], "big"); i += 2
                elen = int.from_bytes(body[i:i + 2], "big"); i += 2
                i += elen
                if _is_grease(etype):
                    continue
                exts.append(etype)
        s = "{},{},{}".format(
            version, cipher, "-".join(str(x) for x in exts)
        )
        return hashlib.md5(s.encode("ascii")).hexdigest()
    except (IndexError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Name tables
# ---------------------------------------------------------------------------

_DNS_RTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 35: "NAPTR", 41: "OPT", 43: "DS", 46: "RRSIG",
    47: "NSEC", 48: "DNSKEY", 50: "NSEC3", 52: "TLSA", 65: "HTTPS",
    255: "ANY",
}


def dns_rtype_name(t: int) -> str:
    return _DNS_RTYPES.get(t, "UNKNOWN")


_TLS_VERSIONS = {
    0x0300: "SSLv3",
    0x0301: "TLSv1.0",
    0x0302: "TLSv1.1",
    0x0303: "TLSv1.2",
    0x0304: "TLSv1.3",
}


def tls_version_name(v: int) -> str:
    return _TLS_VERSIONS.get(v, "Unknown")


_ICMP_TYPES = {
    0: "EchoReply", 3: "DestinationUnreachable", 4: "SourceQuench",
    5: "Redirect", 8: "EchoRequest", 9: "RouterAdvertisement",
    10: "RouterSolicitation", 11: "TimeExceeded", 12: "ParameterProblem",
    13: "Timestamp", 14: "TimestampReply", 15: "InformationRequest",
    16: "InformationReply", 17: "AddressMaskRequest", 18: "AddressMaskReply",
}


def icmp_type_name(t: int) -> str:
    return _ICMP_TYPES.get(t, "Unknown")


# ---------------------------------------------------------------------------
# ICS / port-based protocol fingerprint
# ---------------------------------------------------------------------------

_ICS_PORTS = {
    502: "Modbus",
    20000: "DNP3",
    44818: "EtherNet/IP",
    47808: "BACnet",
    102: "S7comm",
    789: "RedLion",
    1089: "FF-Annunciation",
    1090: "FF-FMS",
    1091: "FF-SM",
    2222: "EtherNet/IP-IO",
    4840: "OPC-UA",
    9600: "OMRON-FINS",
}


def is_ics_port(port: int) -> bool:
    return port in _ICS_PORTS


def ics_protocol_for_port(port: int) -> str | None:
    return _ICS_PORTS.get(port)


_PORT_PROTOCOL = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3",
    119: "NNTP", 123: "NTP", 137: "NBNS", 138: "NetBIOS-DGM",
    139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 162: "SNMP-TRAP",
    389: "LDAP", 443: "TLS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    587: "SMTP-SUBMIT", 636: "LDAPS", 853: "DNS-over-TLS", 993: "IMAPS",
    995: "POP3S", 1883: "MQTT", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5672: "AMQP", 6379: "Redis", 8080: "HTTP-ALT", 8883: "MQTTS",
}


def fingerprint_protocol(data: bytes, src_port: int, dst_port: int) -> str:
    # Port-based first
    for p in (dst_port, src_port):
        if p in _PORT_PROTOCOL:
            return _PORT_PROTOCOL[p]
        if p in _ICS_PORTS:
            return _ICS_PORTS[p]
    # Payload heuristics
    if data.startswith(b"GET ") or data.startswith(b"POST ") or data.startswith(b"HTTP/"):
        return "HTTP"
    if data.startswith(b"SSH-"):
        return "SSH"
    if len(data) >= 3 and data[0] == 0x16 and data[1] == 0x03:
        return "TLS"
    if len(data) >= 2 and data[:2] == b"\xff\xfd":
        return "Telnet"
    return "Unknown"


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def _b(x: Any) -> bytes:
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if isinstance(x, list):
        return bytes(x)
    if isinstance(x, str):
        return x.encode("latin1")
    raise TypeError(f"cannot coerce to bytes: {type(x)}")


DISPATCH = {
    "byte_entropy":                 lambda i: byte_entropy(_b(i)),
    "url_decode":                   lambda i: list(url_decode(_b(i))),
    "decode_http_chunked":          lambda i: list(decode_http_chunked(_b(i))),
    "dnp3_crc16":                   lambda i: dnp3_crc16(_b(i)),
    "icmp_stream_tunnel_heuristic": lambda i: icmp_stream_tunnel_heuristic([_b(p) for p in i]),
    "scan_http_attacks":            lambda i: scan_http_attacks(_b(i)),
    "scan_http_attacks_decoded":    lambda i: scan_http_attacks_decoded(_b(i)),
    "ja3_fingerprint":              lambda i: ja3_fingerprint(_b(i)),
    "ja3s_fingerprint":             lambda i: ja3s_fingerprint(_b(i)),
    "dns_rtype_name":               lambda i: dns_rtype_name(int(i)),
    "tls_version_name":             lambda i: tls_version_name(int(i)),
    "icmp_type_name":               lambda i: icmp_type_name(int(i)),
    "is_ics_port":                  lambda i: is_ics_port(int(i)),
    "ics_protocol_for_port":        lambda i: ics_protocol_for_port(int(i)),
    "fingerprint_protocol":         lambda i: fingerprint_protocol(
        _b(i.get("data", [])), int(i.get("src_port", 0)), int(i.get("dst_port", 0))
    ),
}


def main_stdin() -> None:
    req = json.loads(sys.stdin.read())
    func = req["func"]
    inp = req.get("input", [])
    if func not in DISPATCH:
        print(json.dumps({"error": f"unknown function {func}"}))
        return
    print(json.dumps({"output": DISPATCH[func](inp)}))


def main() -> None:
    # Self-test
    sample_get = b"GET /index.html?id=1' or 1=1-- HTTP/1.1\r\nHost: x\r\n\r\n"
    chunked = b"4\r\nWiki\r\n5\r\npedia\r\ne\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n"
    report = {
        "entropy_zeros":        byte_entropy(b"\x00" * 256),
        "entropy_ascending":    byte_entropy(bytes(range(256))),
        "url_decode_plus":      url_decode(b"a+b%20c%2Fd").decode("latin1"),
        "chunked_decode":       decode_http_chunked(chunked).decode("latin1"),
        "dnp3_crc16_empty":     dnp3_crc16(b""),
        "dnp3_crc16_hello":     dnp3_crc16(b"hello"),
        "icmp_tunnel_benign":   icmp_stream_tunnel_heuristic([b"\x00" * 64]),
        "icmp_tunnel_susp":     icmp_stream_tunnel_heuristic([bytes(range(256))]),
        "scan_attacks":         scan_http_attacks(sample_get),
        "scan_attacks_decoded": scan_http_attacks_decoded(b"a=%3Cscript%3Ealert(1)%3C/script%3E"),
        "dns_rtype_28":         dns_rtype_name(28),
        "tls_version_0x0303":   tls_version_name(0x0303),
        "icmp_type_8":          icmp_type_name(8),
        "is_ics_port_502":      is_ics_port(502),
        "is_ics_port_80":       is_ics_port(80),
        "ics_for_44818":        ics_protocol_for_port(44818),
        "fingerprint_http_get": fingerprint_protocol(sample_get, 49152, 80),
        "fingerprint_ssh":      fingerprint_protocol(b"SSH-2.0-OpenSSH_8.9", 49152, 22),
        "fingerprint_unknown":  fingerprint_protocol(b"\x00\x00", 12345, 54321),
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    if "--stdin" in sys.argv:
        main_stdin()
    else:
        main()
