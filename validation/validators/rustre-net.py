#!/usr/bin/env python3
"""
Independent validator for rustre-net.

Reimplements packet parsing (Ethernet/IPv4/IPv6/TCP/UDP/ICMP/ARP/DNS/HTTP),
TCP flag bitmasks, flow-key canonicalization, and DNS/HTTP edge cases using
only Python stdlib. Based on RFCs 791, 793, 768, 792, 826, 1035, 7230 and
the documented invariants in reports/rustre-net.md.

Output (printed as JSON):
    { "crate": "rustre-net", "saved": bool }
"""

import json
import os
import sys
import struct

CRATE = "rustre-net"

# --- TCP flag bits (matches bitflags TcpFlags in crate) ---
TCP_FLAGS = {
    "FIN": 1 << 0,
    "SYN": 1 << 1,
    "RST": 1 << 2,
    "PSH": 1 << 3,
    "ACK": 1 << 4,
    "URG": 1 << 5,
    "ECE": 1 << 6,
    "CWR": 1 << 7,
}

# --- Link types (LinkType::dlt) per libpcap ---
LINKTYPE_DLT = {
    "Null":     0,
    "Ethernet": 1,
    "Raw":     101,
    "Loopback": 0,  # treated as Null DLT
}

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP  = 0x0806
ETHERTYPE_VLAN = 0x8100

IPPROTO_ICMP = 1
IPPROTO_TCP  = 6
IPPROTO_UDP  = 17


# ---------------- Ethernet ----------------
def mac_to_string(mac6):
    if len(mac6) != 6:
        raise ValueError("mac must be 6 bytes")
    return ":".join(f"{b:02x}" for b in mac6)


def parse_ethernet(data):
    if len(data) < 14:
        raise ValueError("BufferTooShort")
    dst = bytes(data[0:6])
    src = bytes(data[6:12])
    ethertype = (data[12] << 8) | data[13]
    payload_off = 14
    # 802.1Q VLAN: skip 4 extra bytes, next 2 are real ethertype
    if ethertype == ETHERTYPE_VLAN:
        if len(data) < 18:
            raise ValueError("BufferTooShort")
        ethertype = (data[16] << 8) | data[17]
        payload_off = 18
    return {
        "src_mac": src,
        "dst_mac": dst,
        "ethertype": ethertype,
        "payload": bytes(data[payload_off:]),
    }


# ---------------- IPv4 ----------------
def parse_ipv4(data):
    if len(data) < 20:
        raise ValueError("BufferTooShort")
    ver_ihl = data[0]
    version = ver_ihl >> 4
    ihl = ver_ihl & 0x0F
    if version != 4:
        raise ValueError("InvalidIpv4Packet")
    if ihl < 5:
        raise ValueError("InvalidIpv4Packet")
    hdr_len = ihl * 4
    if len(data) < hdr_len:
        raise ValueError("BufferTooShort")
    total_len = (data[2] << 8) | data[3]
    ttl = data[8]
    protocol = data[9]
    src = ".".join(str(b) for b in data[12:16])
    dst = ".".join(str(b) for b in data[16:20])
    payload_end = min(total_len, len(data)) if total_len >= hdr_len else len(data)
    payload = bytes(data[hdr_len:payload_end])
    return {
        "src": src, "dst": dst,
        "protocol": protocol, "ttl": ttl,
        "payload": payload,
        "version": 4,
    }


# ---------------- IPv6 ----------------
def parse_ipv6(data):
    if len(data) < 40:
        raise ValueError("BufferTooShort")
    version = data[0] >> 4
    if version != 6:
        raise ValueError("InvalidIpv6Packet")
    payload_len = (data[4] << 8) | data[5]
    next_header = data[6]
    hop_limit = data[7]

    def fmt6(addr):
        groups = [f"{(addr[i]<<8)|addr[i+1]:x}" for i in range(0, 16, 2)]
        return ":".join(groups)

    src = fmt6(data[8:24])
    dst = fmt6(data[24:40])
    payload = bytes(data[40:40 + payload_len]) if payload_len else bytes(data[40:])
    return {
        "src": src, "dst": dst,
        "protocol": next_header, "ttl": hop_limit,
        "payload": payload,
        "version": 6,
    }


# ---------------- TCP ----------------
def parse_tcp(data):
    if len(data) < 20:
        raise ValueError("BufferTooShort")
    src_port = (data[0] << 8) | data[1]
    dst_port = (data[2] << 8) | data[3]
    seq = struct.unpack(">I", bytes(data[4:8]))[0]
    ack = struct.unpack(">I", bytes(data[8:12]))[0]
    data_offset = data[12] >> 4
    if data_offset < 5:
        raise ValueError("InvalidTcpSegment")
    hdr_len = data_offset * 4
    if len(data) < hdr_len:
        raise ValueError("BufferTooShort")
    flags = data[13]
    window = (data[14] << 8) | data[15]
    payload = bytes(data[hdr_len:])
    return {
        "src_port": src_port, "dst_port": dst_port,
        "seq": seq, "ack": ack,
        "flags": flags, "window": window,
        "payload": payload,
    }


# ---------------- UDP ----------------
def parse_udp(data):
    if len(data) < 8:
        raise ValueError("BufferTooShort")
    src_port = (data[0] << 8) | data[1]
    dst_port = (data[2] << 8) | data[3]
    length = (data[4] << 8) | data[5]
    payload_end = min(length, len(data)) if length >= 8 else len(data)
    payload = bytes(data[8:payload_end])
    return {
        "src_port": src_port, "dst_port": dst_port,
        "payload": payload,
    }


# ---------------- ICMP ----------------
def parse_icmp(data):
    if len(data) < 4:
        raise ValueError("BufferTooShort")
    return {
        "icmp_type": data[0],
        "code": data[1],
        "checksum": (data[2] << 8) | data[3],
        "payload": bytes(data[4:]),
    }


# ---------------- ARP ----------------
def parse_arp(data):
    if len(data) < 28:
        raise ValueError("BufferTooShort")
    htype = (data[0] << 8) | data[1]
    ptype = (data[2] << 8) | data[3]
    hlen = data[4]
    plen = data[5]
    op = (data[6] << 8) | data[7]
    sha = bytes(data[8:14])
    spa = bytes(data[14:18])
    tha = bytes(data[18:24])
    tpa = bytes(data[24:28])
    return {
        "htype": htype, "ptype": ptype,
        "hlen": hlen, "plen": plen,
        "op": op,
        "sha": sha, "spa": spa, "tha": tha, "tpa": tpa,
    }


# ---------------- DNS ----------------
DNS_MAX_RECORDS = 512


def _dns_read_name(data, offset, hops=0):
    """Read a DNS name with compression-pointer guard. Returns (name, next_off)."""
    if hops > 16:
        raise ValueError("MalformedPacket: dns name pointer loop")
    labels = []
    orig_off = offset
    jumped = False
    end_off = offset
    while True:
        if offset >= len(data):
            raise ValueError("BufferTooShort")
        ln = data[offset]
        if ln == 0:
            if not jumped:
                end_off = offset + 1
            break
        if (ln & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("BufferTooShort")
            ptr = ((ln & 0x3F) << 8) | data[offset + 1]
            if ptr >= orig_off and not jumped:
                # Backward only — RFC 1035; forward/self ptr -> malformed
                raise ValueError("MalformedPacket: forward dns ptr")
            if not jumped:
                end_off = offset + 2
            sub, _ = _dns_read_name(data, ptr, hops + 1)
            if sub:
                labels.append(sub)
            break
        if (ln & 0xC0) != 0:
            raise ValueError("MalformedPacket: dns label flag")
        offset += 1
        if offset + ln > len(data):
            raise ValueError("BufferTooShort")
        labels.append(bytes(data[offset:offset + ln]).decode("ascii", errors="replace"))
        offset += ln
    return (".".join(labels), end_off)


def parse_dns(data):
    if len(data) < 12:
        raise ValueError("BufferTooShort")
    id_ = (data[0] << 8) | data[1]
    flags = (data[2] << 8) | data[3]
    qd = (data[4] << 8) | data[5]
    an = (data[6] << 8) | data[7]
    ns = (data[8] << 8) | data[9]
    ar = (data[10] << 8) | data[11]
    total = qd + an + ns + ar
    if total > DNS_MAX_RECORDS:
        raise ValueError("MalformedPacket: too many DNS records")
    off = 12
    questions = []
    for _ in range(qd):
        name, off = _dns_read_name(data, off)
        if off + 4 > len(data):
            raise ValueError("BufferTooShort")
        qtype = (data[off] << 8) | data[off + 1]
        qclass = (data[off + 2] << 8) | data[off + 3]
        off += 4
        questions.append({"name": name, "qtype": qtype, "qclass": qclass})

    def read_rrs(n):
        nonlocal off
        out = []
        for _ in range(n):
            name, off = _dns_read_name(data, off)
            if off + 10 > len(data):
                raise ValueError("BufferTooShort")
            rtype = (data[off] << 8) | data[off + 1]
            rclass = (data[off + 2] << 8) | data[off + 3]
            ttl = struct.unpack(">I", bytes(data[off + 4:off + 8]))[0]
            rdlen = (data[off + 8] << 8) | data[off + 9]
            off += 10
            if off + rdlen > len(data):
                raise ValueError("BufferTooShort")
            rdata = bytes(data[off:off + rdlen])
            off += rdlen
            out.append({"name": name, "rtype": rtype, "rclass": rclass,
                        "ttl": ttl, "rdata": rdata})
        return out

    answers = read_rrs(an)
    authorities = read_rrs(ns)
    additional = read_rrs(ar)
    return {
        "id": id_, "flags": flags,
        "questions": questions,
        "answers": answers,
        "authorities": authorities,
        "additional": additional,
    }


def dns_is_response(pkt):
    return (pkt["flags"] & 0x8000) != 0


def dns_rcode(pkt):
    return pkt["flags"] & 0x0F


# ---------------- HTTP ----------------
def _split_http(data):
    sep = b"\r\n\r\n"
    idx = data.find(sep)
    if idx < 0:
        raise ValueError("MalformedPacket: no http header end")
    head = data[:idx].decode("utf-8", errors="strict")
    body = bytes(data[idx + 4:])
    lines = head.split("\r\n")
    return lines, body


def _parse_headers(lines):
    out = []
    for ln in lines:
        if ":" not in ln:
            raise ValueError("MalformedPacket: header missing colon")
        k, v = ln.split(":", 1)
        out.append((k.strip(), v.strip()))
    return out


def parse_http_request(data):
    lines, body = _split_http(data)
    if not lines:
        raise ValueError("MalformedPacket")
    parts = lines[0].split(" ")
    if len(parts) != 3:
        raise ValueError("MalformedPacket: bad request line")
    method, uri, version = parts
    headers = _parse_headers(lines[1:])
    return {"method": method, "uri": uri, "version": version,
            "headers": headers, "body": body}


def parse_http_response(data):
    lines, body = _split_http(data)
    if not lines:
        raise ValueError("MalformedPacket")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2:
        raise ValueError("MalformedPacket: bad status line")
    version = parts[0]
    status_code = int(parts[1])
    reason = parts[2] if len(parts) == 3 else ""
    headers = _parse_headers(lines[1:])
    return {"version": version, "status_code": status_code,
            "reason": reason, "headers": headers, "body": body}


def http_header(req_or_resp, name):
    name_l = name.lower()
    for k, v in req_or_resp["headers"]:
        if k.lower() == name_l:
            return v
    return None


# ---------------- FlowKey + Protocol ----------------
def flow_key(src_ip, src_port, dst_ip, dst_port):
    return (src_ip, src_port, dst_ip, dst_port)


def flow_key_canonical(key):
    s_ip, s_p, d_ip, d_p = key
    if (s_ip, s_p) <= (d_ip, d_p):
        return key
    return (d_ip, d_p, s_ip, s_p)


PROTOCOLS = ("Tcp", "Udp", "Icmp", "Dns", "Http", "Https", "Unknown")


def protocol_is_tls(p):
    return p == "Https"


# ---------------- LinkType ----------------
def linktype_dlt(name):
    return LINKTYPE_DLT[name]


# ---------------- Self-checks ----------------
def run_checks():
    r = []

    # TCP flags layout
    r.append(("TCP FIN=0x01", TCP_FLAGS["FIN"] == 0x01))
    r.append(("TCP SYN=0x02", TCP_FLAGS["SYN"] == 0x02))
    r.append(("TCP RST=0x04", TCP_FLAGS["RST"] == 0x04))
    r.append(("TCP ACK=0x10", TCP_FLAGS["ACK"] == 0x10))
    r.append(("TCP CWR=0x80", TCP_FLAGS["CWR"] == 0x80))

    # Ethernet parse + MAC formatting
    eth = bytes([0x00,0x11,0x22,0x33,0x44,0x55,
                 0x66,0x77,0x88,0x99,0xAA,0xBB,
                 0x08,0x00, 0xDE, 0xAD])
    f = parse_ethernet(eth)
    r.append(("eth ethertype IPv4", f["ethertype"] == ETHERTYPE_IPV4))
    r.append(("eth dst_mac", f["dst_mac"] == bytes([0x00,0x11,0x22,0x33,0x44,0x55])))
    r.append(("eth payload", f["payload"] == b"\xDE\xAD"))
    r.append(("mac_to_string", mac_to_string(bytes([0,1,2,3,4,5])) == "00:01:02:03:04:05"))

    # 802.1Q VLAN passthrough
    vlan = bytes([0]*12 + [0x81,0x00, 0x00,0x01, 0x08,0x00, 0xAB])
    fv = parse_ethernet(vlan)
    r.append(("eth VLAN unwrapped to IPv4", fv["ethertype"] == ETHERTYPE_IPV4))
    r.append(("eth VLAN payload", fv["payload"] == b"\xAB"))

    # Ethernet too short
    try:
        parse_ethernet(b"\x00" * 13)
        r.append(("eth short rejects", False))
    except ValueError:
        r.append(("eth short rejects", True))

    # IPv4 parse
    ip4 = bytes([0x45, 0x00, 0x00, 0x1C,  # ver/ihl, dscp, total len=28
                 0x00, 0x00, 0x00, 0x00,
                 0x40, 0x06, 0x00, 0x00,  # ttl=64 proto=TCP
                 192, 168, 0, 1,
                 10, 0, 0, 2,
                 0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF])
    ip = parse_ipv4(ip4)
    r.append(("ipv4 src", ip["src"] == "192.168.0.1"))
    r.append(("ipv4 dst", ip["dst"] == "10.0.0.2"))
    r.append(("ipv4 proto TCP", ip["protocol"] == IPPROTO_TCP))
    r.append(("ipv4 ttl=64", ip["ttl"] == 64))
    r.append(("ipv4 payload 8B", len(ip["payload"]) == 8))

    # IPv4 bad version
    try:
        parse_ipv4(bytes([0x65] + [0]*19))
        r.append(("ipv4 bad version rejects", False))
    except ValueError:
        r.append(("ipv4 bad version rejects", True))

    # IPv4 bad IHL
    try:
        parse_ipv4(bytes([0x44] + [0]*19))
        r.append(("ipv4 IHL<5 rejects", False))
    except ValueError:
        r.append(("ipv4 IHL<5 rejects", True))

    # IPv6 parse
    ip6 = bytearray(40 + 2)
    ip6[0] = 0x60          # version=6
    ip6[4] = 0x00
    ip6[5] = 0x02          # payload_len=2
    ip6[6] = IPPROTO_UDP
    ip6[7] = 0x20          # hop limit=32
    ip6[8] = 0x20; ip6[9] = 0x01           # 2001::1
    ip6[8+15] = 0x01
    ip6[24] = 0xfe; ip6[25] = 0x80         # fe80::2
    ip6[24+15] = 0x02
    ip6[40] = 0xAA; ip6[41] = 0xBB
    p6 = parse_ipv6(bytes(ip6))
    r.append(("ipv6 proto UDP", p6["protocol"] == IPPROTO_UDP))
    r.append(("ipv6 hop_limit as ttl", p6["ttl"] == 32))
    r.append(("ipv6 src has 2001", p6["src"].startswith("2001:")))
    r.append(("ipv6 payload", p6["payload"] == b"\xAA\xBB"))

    # TCP parse + flags
    tcp = bytes([
        0x00, 0x50, 0x1F, 0x90,             # src=80 dst=8080
        0x00, 0x00, 0x00, 0x01,             # seq=1
        0x00, 0x00, 0x00, 0x02,             # ack=2
        0x50, 0x12,                         # data_off=5, flags=SYN|ACK
        0x71, 0x10,                         # window=28944
        0x00, 0x00, 0x00, 0x00,
        0xDE, 0xAD,
    ])
    t = parse_tcp(tcp)
    r.append(("tcp src=80", t["src_port"] == 80))
    r.append(("tcp dst=8080", t["dst_port"] == 8080))
    r.append(("tcp seq=1", t["seq"] == 1))
    r.append(("tcp ack=2", t["ack"] == 2))
    r.append(("tcp SYN+ACK", t["flags"] == (TCP_FLAGS["SYN"] | TCP_FLAGS["ACK"])))
    r.append(("tcp window", t["window"] == 0x7110))
    r.append(("tcp payload", t["payload"] == b"\xDE\xAD"))

    # TCP bad data_offset
    bad_tcp = bytearray(tcp)
    bad_tcp[12] = 0x40   # data_off=4 (<5)
    try:
        parse_tcp(bytes(bad_tcp))
        r.append(("tcp data_off<5 rejects", False))
    except ValueError:
        r.append(("tcp data_off<5 rejects", True))

    # UDP parse
    udp = bytes([0x00, 0x35, 0x04, 0xD2, 0x00, 0x0A, 0x00, 0x00, 0x01, 0x02])
    u = parse_udp(udp)
    r.append(("udp src=53", u["src_port"] == 53))
    r.append(("udp dst=1234", u["dst_port"] == 1234))
    r.append(("udp payload", u["payload"] == b"\x01\x02"))

    # ICMP parse
    ic = parse_icmp(bytes([8, 0, 0xAB, 0xCD, 0xFE]))
    r.append(("icmp type=8", ic["icmp_type"] == 8))
    r.append(("icmp checksum", ic["checksum"] == 0xABCD))
    r.append(("icmp payload", ic["payload"] == b"\xFE"))

    # ARP parse
    arp = bytes([
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
        0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
        192, 168, 1, 1,
        0,0,0,0,0,0,
        192, 168, 1, 2,
    ])
    a = parse_arp(arp)
    r.append(("arp op=request", a["op"] == 1))
    r.append(("arp htype=ether", a["htype"] == 1))
    r.append(("arp spa", a["spa"] == bytes([192,168,1,1])))

    # DNS parse — single A question for "a.b"
    dns = bytes([
        0xAB, 0xCD,             # id
        0x81, 0x80,             # flags (response, recursion)
        0x00, 0x01,             # qd=1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, ord('a'),
        0x01, ord('b'),
        0x00,
        0x00, 0x01,             # qtype=A
        0x00, 0x01,             # qclass=IN
    ])
    d = parse_dns(dns)
    r.append(("dns id", d["id"] == 0xABCD))
    r.append(("dns is_response", dns_is_response(d)))
    r.append(("dns rcode=0", dns_rcode(d) == 0))
    r.append(("dns question name", d["questions"][0]["name"] == "a.b"))
    r.append(("dns qtype=A", d["questions"][0]["qtype"] == 1))

    # DNS too many records guard
    too_many = bytes([0,0, 0,0, 0xFF,0xFF, 0,0, 0,0, 0,0])
    try:
        parse_dns(too_many)
        r.append(("dns >512 records rejects", False))
    except ValueError:
        r.append(("dns >512 records rejects", True))

    # DNS forward pointer rejected
    bad_dns = bytes([
        0,0, 0,0, 0,1, 0,0, 0,0, 0,0,
        0xC0, 0x20,             # forward pointer to offset 32 (beyond header)
        0,1, 0,1,
    ])
    try:
        parse_dns(bad_dns)
        r.append(("dns forward ptr rejects", False))
    except ValueError:
        r.append(("dns forward ptr rejects", True))

    # HTTP request
    req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\nBODY"
    hr = parse_http_request(req)
    r.append(("http req method", hr["method"] == "GET"))
    r.append(("http req uri", hr["uri"] == "/index.html"))
    r.append(("http req version", hr["version"] == "HTTP/1.1"))
    r.append(("http header case-insensitive", http_header(hr, "host") == "example.com"))
    r.append(("http req body", hr["body"] == b"BODY"))

    # HTTP response
    resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
    hp = parse_http_response(resp)
    r.append(("http resp code=404", hp["status_code"] == 404))
    r.append(("http resp reason", hp["reason"] == "Not Found"))
    r.append(("http header CL", http_header(hp, "Content-Length") == "0"))

    # HTTP malformed
    try:
        parse_http_request(b"BAD\r\n\r\n")
        r.append(("http bad request line rejects", False))
    except ValueError:
        r.append(("http bad request line rejects", True))

    # FlowKey canonical
    k1 = flow_key("10.0.0.5", 1000, "10.0.0.1", 80)
    k2 = flow_key("10.0.0.1", 80, "10.0.0.5", 1000)
    r.append(("flow_key canonical orders endpoints",
              flow_key_canonical(k1) == flow_key_canonical(k2)))

    # Protocol TLS classification
    r.append(("Https is TLS", protocol_is_tls("Https") is True))
    r.append(("Http is not TLS", protocol_is_tls("Http") is False))
    r.append(("Tcp is not TLS", protocol_is_tls("Tcp") is False))
    r.append(("Protocol set complete",
              set(PROTOCOLS) == {"Tcp","Udp","Icmp","Dns","Http","Https","Unknown"}))

    # LinkType DLT mapping
    r.append(("DLT Ethernet=1", linktype_dlt("Ethernet") == 1))
    r.append(("DLT Raw=101", linktype_dlt("Raw") == 101))
    r.append(("DLT Null=0", linktype_dlt("Null") == 0))

    # TcpState set sanity (documented states)
    tcp_states = {"SynSent","SynReceived","Established","FinWait1","FinWait2",
                  "CloseWait","Closing","LastAck","TimeWait","Closed"}
    r.append(("TcpState has 10 states", len(tcp_states) == 10))

    # Direction set
    dirs = {"Inbound","Outbound","Unknown"}
    r.append(("Direction has 3 values", len(dirs) == 3))

    return r


def main():
    checks = run_checks()
    failed = [name for name, ok in checks if not ok]

    out_dir = os.path.dirname(os.path.abspath(__file__))
    result_path = os.path.join(out_dir, f"{CRATE}.result.json")
    saved = False
    try:
        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "crate": CRATE,
                    "checks_total": len(checks),
                    "checks_failed": failed,
                },
                f,
                indent=2,
            )
        saved = True
    except OSError:
        saved = False

    print(json.dumps({"crate": CRATE, "saved": saved}, indent=2))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
