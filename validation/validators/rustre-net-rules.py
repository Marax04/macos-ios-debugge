#!/usr/bin/env python3
"""
Independent Python validator for crate `rustre-net-rules`.

Reimplements (subset of) the crate's testable functions using only the Python
stdlib — no Rust import, no MCP, no third-party deps. Cross-checks:
  - Snort-style rule parser (msg, sid, content, dsize, flags, offset, depth,
    within, distance, ttl, pcre)
  - Aho-Corasick-equivalent multi-pattern search (naive reference)
  - PacketContext::from_ipv4 IPv4 header parsing
  - RuleEngine.evaluate / evaluate_all over a PacketContext
  - IpSpec / PortSpec / NetworkSpec matching primitives

CLI:
    python rustre-net-rules.py                -> runs main() with fixed inputs
    python rustre-net-rules.py --stdin        -> reads JSON {func,input} on stdin,
                                                 prints JSON {output}
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import struct
import sys
from typing import Any


# ---------------------------------------------------------------------------
# IpSpec / PortSpec / NetworkSpec
# ---------------------------------------------------------------------------

def ip_spec_matches(spec: dict, ip_str: str) -> bool:
    """spec ∈ {kind: any|single|range|cidr|group|not, value: ...}"""
    kind = spec.get("kind")
    ip = ipaddress.ip_address(ip_str)
    if kind == "any":
        return True
    if kind == "single":
        return ip == ipaddress.ip_address(spec["value"])
    if kind == "range":
        lo = ipaddress.ip_address(spec["lo"])
        hi = ipaddress.ip_address(spec["hi"])
        return int(lo) <= int(ip) <= int(hi)
    if kind == "cidr":
        return ip in ipaddress.ip_network(spec["value"], strict=False)
    if kind == "group":
        return any(ip_spec_matches(s, ip_str) for s in spec["value"])
    if kind == "not":
        return not ip_spec_matches(spec["value"], ip_str)
    return False


def port_spec_matches(spec: dict, port: int) -> bool:
    kind = spec.get("kind")
    if kind == "any":
        return True
    if kind == "single":
        return port == int(spec["value"])
    if kind == "range":
        return int(spec["lo"]) <= port <= int(spec["hi"])
    if kind == "list":
        return port in [int(x) for x in spec["value"]]
    if kind == "not":
        return not port_spec_matches(spec["value"], port)
    return False


def network_spec_matches(spec: dict, ip: str, port: int) -> bool:
    return ip_spec_matches(spec["addr"], ip) and port_spec_matches(spec["port"], port)


# ---------------------------------------------------------------------------
# Snort-style rule parser
# ---------------------------------------------------------------------------

VALID_FLAGS = set("SAFRPU")


def _decode_content(raw: str) -> bytes:
    """Decode Snort content: literal text and `|hex bytes|` runs."""
    out = bytearray()
    i = 0
    in_hex = False
    while i < len(raw):
        c = raw[i]
        if c == "|":
            in_hex = not in_hex
            i += 1
            continue
        if in_hex:
            if c.isspace():
                i += 1
                continue
            if i + 1 >= len(raw):
                raise ValueError("truncated hex run")
            byte = raw[i:i + 2]
            try:
                out.append(int(byte, 16))
            except ValueError as e:
                raise ValueError(f"bad hex: {byte!r}") from e
            i += 2
        else:
            out.append(ord(c))
            i += 1
    return bytes(out)


def parse_dsize(val: str) -> dict:
    val = val.strip()
    m = re.fullmatch(r"(\d+)<>(\d+)", val)
    if m:
        return {"kind": "range", "lo": int(m.group(1)), "hi": int(m.group(2))}
    if val.startswith("<"):
        return {"kind": "lt", "value": int(val[1:])}
    if val.startswith(">"):
        return {"kind": "gt", "value": int(val[1:])}
    return {"kind": "eq", "value": int(val)}


def rule_parser_parse(text: str) -> dict:
    """
    Parse a single Snort-style rule:  action proto src sport -> dst dport ( opts )
    Returns a dict; raises ValueError on parse failure (RuleError::ParseError).
    """
    text = text.strip()
    if not text:
        raise ValueError("ParseError: empty")
    # Split header / options
    paren = text.find("(")
    if paren < 0 or not text.endswith(")"):
        raise ValueError("ParseError: missing options block")
    header = text[:paren].strip()
    options_str = text[paren + 1:-1].strip()

    htoks = header.split()
    # action proto src sport dir dst dport  (7 tokens)
    if len(htoks) != 7:
        raise ValueError(f"ParseError: header expects 7 tokens, got {len(htoks)}")
    action, proto, src, sport, direction, dst, dport = htoks
    action_lc = action.lower()
    if action_lc not in {"alert", "pass", "drop", "log", "reject"}:
        raise ValueError(f"ParseError: bad action {action!r}")
    proto_lc = proto.lower()
    if proto_lc not in {"tcp", "udp", "icmp", "any", "ip"}:
        raise ValueError(f"ParseError: bad proto {proto!r}")

    options: list[dict] = []
    msg = ""
    sid: int | None = None

    # Split options on `;` outside quotes
    for opt in _split_options(options_str):
        opt = opt.strip()
        if not opt:
            continue
        if ":" in opt:
            key, _, val = opt.partition(":")
            key = key.strip().lower()
            val = val.strip()
            if val.startswith('"') and val.endswith('"'):
                val_inner = val[1:-1]
            else:
                val_inner = val
        else:
            key = opt.strip().lower()
            val = ""
            val_inner = ""

        if key == "msg":
            msg = val_inner
            options.append({"kind": "Msg", "value": val_inner})
        elif key == "sid":
            try:
                sid = int(val_inner)
            except ValueError as e:
                raise ValueError(f"ParseError: bad sid {val_inner!r}") from e
            options.append({"kind": "Sid", "value": sid})
        elif key == "content":
            options.append({"kind": "Content", "value": list(_decode_content(val_inner))})
        elif key == "pcre":
            options.append({"kind": "Pcre", "value": val_inner})
        elif key == "dsize":
            options.append({"kind": "DSize", "value": parse_dsize(val_inner)})
        elif key == "flags":
            for ch in val_inner:
                if ch not in VALID_FLAGS:
                    raise ValueError(f"ParseError: bad flag {ch!r}")
            options.append({"kind": "Flags", "value": val_inner})
        elif key in {"offset", "depth", "within", "distance", "ttl"}:
            try:
                num = int(val_inner)
            except ValueError as e:
                raise ValueError(f"ParseError: bad {key} {val_inner!r}") from e
            options.append({"kind": key.capitalize(), "value": num})
        elif key == "nocase":
            options.append({"kind": "Nocase"})
        elif key in {"rev", "classtype"}:
            options.append({"kind": key.capitalize(), "value": val_inner})
        else:
            options.append({"kind": "Unknown", "name": key, "value": val_inner})

    return {
        "action": action_lc,
        "proto": proto_lc,
        "src": src,
        "src_port": sport,
        "dir": direction,
        "dst": dst,
        "dst_port": dport,
        "options": options,
        "msg": msg,
        "sid": sid,
    }


def _split_options(s: str) -> list[str]:
    """Split on `;` outside of double quotes."""
    out: list[str] = []
    buf: list[str] = []
    in_q = False
    for ch in s:
        if ch == '"':
            in_q = not in_q
            buf.append(ch)
        elif ch == ";" and not in_q:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf and "".join(buf).strip():
        out.append("".join(buf))
    return out


def rule_parser_parse_many(text: str) -> list[dict]:
    results: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            results.append({"ok": rule_parser_parse(line)})
        except ValueError as e:
            results.append({"err": str(e)})
    return results


# ---------------------------------------------------------------------------
# Aho-Corasick reference (naive multi-pattern search)
# ---------------------------------------------------------------------------

def aho_corasick_find_all(patterns: list[bytes], haystack: bytes) -> list[dict]:
    hits: list[dict] = []
    for idx, pat in enumerate(patterns):
        if not pat:
            continue
        i = 0
        while True:
            off = haystack.find(pat, i)
            if off < 0:
                break
            hits.append({"pattern_idx": idx, "start": off, "end": off + len(pat)})
            i = off + 1
    hits.sort(key=lambda h: (h["start"], h["pattern_idx"]))
    return hits


def aho_corasick_find_first(patterns: list[bytes], haystack: bytes) -> dict | None:
    all_hits = aho_corasick_find_all(patterns, haystack)
    return all_hits[0] if all_hits else None


def aho_corasick_contains_any(patterns: list[bytes], haystack: bytes) -> bool:
    return any(p and p in haystack for p in patterns)


# ---------------------------------------------------------------------------
# PacketContext::from_ipv4
# ---------------------------------------------------------------------------

def packet_context_from_ipv4(data: bytes) -> dict | None:
    """Parse an IPv4 datagram (with optional TCP/UDP) into PacketContext fields."""
    if len(data) < 20:
        return None
    vihl = data[0]
    version = vihl >> 4
    ihl = (vihl & 0x0F) * 4
    if version != 4 or ihl < 20 or len(data) < ihl:
        return None
    total_len = struct.unpack(">H", data[2:4])[0]
    ttl = data[8]
    proto = data[9]
    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])

    src_port = 0
    dst_port = 0
    tcp_flags = 0
    payload = b""

    body = data[ihl:total_len] if total_len <= len(data) else data[ihl:]
    if proto == 6 and len(body) >= 20:  # TCP
        src_port, dst_port = struct.unpack(">HH", body[0:4])
        data_off = (body[12] >> 4) * 4
        tcp_flags = body[13]
        if data_off <= len(body):
            payload = body[data_off:]
    elif proto == 17 and len(body) >= 8:  # UDP
        src_port, dst_port = struct.unpack(">HH", body[0:4])
        payload = body[8:]
    else:
        payload = body

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "ip_proto": proto,
        "ttl": ttl,
        "tcp_flags": tcp_flags,
        "payload": list(payload),
    }


# ---------------------------------------------------------------------------
# RuleEngine evaluate / evaluate_all
# ---------------------------------------------------------------------------

PROTO_TO_NUM = {"tcp": 6, "udp": 17, "icmp": 1, "any": None}


def _check_condition(cond: dict, pkt: dict) -> bool:
    kind = cond.get("kind") or cond.get("type")
    payload = bytes(pkt.get("payload", []))
    if kind == "Content":
        return bytes(cond["value"]) in payload
    if kind == "Pcre":
        try:
            return re.search(cond["value"].encode("utf-8", "replace"), payload) is not None
        except re.error:
            return False
    if kind == "DSize":
        v = cond["value"]
        n = len(payload)
        if v["kind"] == "eq": return n == v["value"]
        if v["kind"] == "lt": return n < v["value"]
        if v["kind"] == "gt": return n > v["value"]
        if v["kind"] == "range": return v["lo"] <= n <= v["hi"]
        return False
    if kind == "Flags":
        mask = 0
        m = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10, "U": 0x20}
        for ch in cond["value"]:
            mask |= m.get(ch, 0)
        return (pkt.get("tcp_flags", 0) & mask) == mask
    if kind == "Ttl":
        return pkt.get("ttl", 0) == cond["value"]
    if kind == "SrcPort":
        return pkt.get("src_port", 0) == cond["value"]
    if kind == "DstPort":
        return pkt.get("dst_port", 0) == cond["value"]
    if kind in {"Offset", "Depth", "Within", "Distance", "Nocase",
                "Msg", "Sid", "Rev", "Classtype", "Unknown"}:
        return True  # modifiers / metadata — non-filtering
    return False


def rule_matches(rule: dict, pkt: dict) -> bool:
    proto_num = PROTO_TO_NUM.get(rule.get("proto", "any"))
    if proto_num is not None and pkt.get("ip_proto") != proto_num:
        return False
    src = rule.get("src")
    if isinstance(src, dict) and not network_spec_matches(
        src, pkt["src_ip"], pkt.get("src_port", 0)
    ):
        return False
    dst = rule.get("dst")
    if isinstance(dst, dict) and not network_spec_matches(
        dst, pkt["dst_ip"], pkt.get("dst_port", 0)
    ):
        return False
    for cond in rule.get("conditions", []):
        if not _check_condition(cond, pkt):
            return False
    return True


def rule_engine_evaluate(rules: list[dict], pkt: dict) -> dict | None:
    for r in rules:
        if not r.get("enabled", True):
            continue
        if rule_matches(r, pkt):
            return {
                "matched": True,
                "rule_id": r.get("id"),
                "action": r.get("action"),
                "msg": r.get("msg", ""),
            }
    return None


def rule_engine_evaluate_all(rules: list[dict], pkt: dict) -> list[dict]:
    out: list[dict] = []
    for r in rules:
        if not r.get("enabled", True):
            continue
        if rule_matches(r, pkt):
            out.append({
                "matched": True,
                "rule_id": r.get("id"),
                "action": r.get("action"),
                "msg": r.get("msg", ""),
            })
    return out


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

DISPATCH = {
    "ip_spec_matches":         lambda i: ip_spec_matches(i["spec"], i["ip"]),
    "port_spec_matches":       lambda i: port_spec_matches(i["spec"], int(i["port"])),
    "network_spec_matches":    lambda i: network_spec_matches(i["spec"], i["ip"], int(i["port"])),
    "rule_parser_parse":       lambda i: rule_parser_parse(i if isinstance(i, str) else i["text"]),
    "rule_parser_parse_many":  lambda i: rule_parser_parse_many(i if isinstance(i, str) else i["text"]),
    "decode_content":          lambda i: list(_decode_content(i if isinstance(i, str) else i["raw"])),
    "parse_dsize":             lambda i: parse_dsize(i if isinstance(i, str) else i["val"]),
    "ac_find_all":             lambda i: aho_corasick_find_all(
                                    [bytes(p) for p in i["patterns"]], bytes(i["haystack"])),
    "ac_find_first":           lambda i: aho_corasick_find_first(
                                    [bytes(p) for p in i["patterns"]], bytes(i["haystack"])),
    "ac_contains_any":         lambda i: aho_corasick_contains_any(
                                    [bytes(p) for p in i["patterns"]], bytes(i["haystack"])),
    "packet_from_ipv4":        lambda i: packet_context_from_ipv4(bytes(i)),
    "rule_engine_evaluate":    lambda i: rule_engine_evaluate(i["rules"], i["pkt"]),
    "rule_engine_evaluate_all":lambda i: rule_engine_evaluate_all(i["rules"], i["pkt"]),
}


def main_stdin() -> None:
    req = json.loads(sys.stdin.read())
    func = req["func"]
    inp = req.get("input")
    if func not in DISPATCH:
        print(json.dumps({"error": f"unknown function {func}"}))
        return
    try:
        out = DISPATCH[func](inp)
        print(json.dumps({"output": out}))
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"error": f"{type(e).__name__}: {e}"}))


def _build_test_ipv4_tcp() -> bytes:
    # Minimal IPv4 + TCP + payload "hello"
    payload = b"hello"
    # TCP header: sport=1234 dport=80 seq=0 ack=0 dataoff=5<<4 flags=SYN(0x02) win=0 csum=0 urg=0
    tcp = struct.pack(">HHIIBBHHH", 1234, 80, 0, 0, 5 << 4, 0x02, 0, 0, 0) + payload
    total = 20 + len(tcp)
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        (4 << 4) | 5, 0, total, 0, 0, 64, 6, 0,
        socket.inet_aton("10.0.0.1"),
        socket.inet_aton("10.0.0.2"),
    )
    return ip + tcp


def main() -> None:
    rule_text = (
        'alert tcp any any -> any 80 '
        '(msg:"hello hit"; content:"hello"; sid:1001;)'
    )
    parsed = rule_parser_parse(rule_text)

    rule = {
        "id": 1001,
        "action": "alert",
        "proto": "tcp",
        "src": {"addr": {"kind": "any"}, "port": {"kind": "any"}},
        "dst": {"addr": {"kind": "any"}, "port": {"kind": "single", "value": 80}},
        "conditions": [{"kind": "Content", "value": list(b"hello")}],
        "msg": "hello hit",
        "enabled": True,
    }

    pkt = packet_context_from_ipv4(_build_test_ipv4_tcp())

    report = {
        "decode_content_mixed": list(_decode_content('GET |20|/index')),
        "parse_dsize_lt":       parse_dsize("<100"),
        "parse_dsize_range":    parse_dsize("10<>20"),
        "rule_parse":           parsed,
        "ac_find_all":          aho_corasick_find_all(
                                    [b"he", b"llo", b"xyz"], b"hello hello"),
        "ac_contains_any_true": aho_corasick_contains_any([b"foo", b"ell"], b"hello"),
        "ip_spec_cidr_match":   ip_spec_matches(
                                    {"kind": "cidr", "value": "10.0.0.0/8"}, "10.1.2.3"),
        "ip_spec_not":          ip_spec_matches(
                                    {"kind": "not",
                                     "value": {"kind": "single", "value": "1.2.3.4"}},
                                    "1.2.3.4"),
        "port_spec_list":       port_spec_matches(
                                    {"kind": "list", "value": [80, 443, 8080]}, 443),
        "packet_from_ipv4":     pkt,
        "engine_match":         rule_engine_evaluate([rule], pkt),
        "engine_match_all":     rule_engine_evaluate_all([rule], pkt),
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    if "--stdin" in sys.argv:
        main_stdin()
    else:
        main()
