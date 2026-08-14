# rustre-net

Network capture and traffic analysis core for the RustRE platform. Provides protocol parsing, connection tracking, packet capture traits, application-layer dissection, traffic reassembly, C2 detection, and protocol fingerprinting.

## Cargo.toml

- **name**: `rustre-net`
- **edition / version / license**: inherited from workspace
- **Dependencies**: `thiserror`, `serde`, `serde_json`, `async-trait`, `parking_lot`, `bitflags`
- `#![forbid(unsafe_code)]`

## Modules

- `c2_detector` — command-and-control beaconing detection
- `network_analyzer` — high-level analysis pipeline
- `packet_builder` — synthesize packets
- `packet_decoder` — layered decoder
- `protocol_dissector` — application protocol dissection
- `protocol_fingerprint` — JA3/JA4-style fingerprints
- `traffic_reassembler` — TLS keys, HTTP/1, HTTP/2, stream reconstruction
- `tcp_reassembler` — TCP stream reassembly
- `flow_tracker` — flow tracking
- `registry` — protocol/dissector registry

## Core API (lib.rs)

### Error types
- `NetError` — buffer/protocol/IO/capture errors (`BufferTooShort`, `InvalidIpv4Packet`, `InvalidTcpSegment`, `BpfFilterError`, `Io(std::io::Error)`, `MalformedPacket`, …)
- `NetworkError` — `ParseError`, `IoError`, `UnsupportedProtocol`, `InvalidAddress`

### Packet structs
- `EthernetFrame { src_mac, dst_mac, ethertype, payload }` — `mac_to_string(&[u8;6]) -> String`
- `IpPacket { src: IpAddr, dst, protocol: u8, ttl, payload }`
- `TcpSegment { src_port, dst_port, seq, ack, flags: TcpFlags, window, payload }`
- `UdpDatagram { src_port, dst_port, payload }`
- `IcmpPacket { icmp_type, code, checksum, payload }`
- `ArpPacket { htype: ArpHwType, ptype, hlen, plen, op: ArpOp, sha, spa, tha, tpa }` — `sha_str()`
- `TcpFlags` (bitflags): `FIN SYN RST PSH ACK URG ECE CWR`
- `Packet { timestamp, data, layer: NetworkLayer }` — `new_ethernet(...)`, `new_raw(...)`
- `NetworkLayer { Ethernet(EthernetFrame), Raw(Vec<u8>) }`
- `PacketBuffer { data, timestamp_us, link_type: CaptureLink }` — `new`, `len`, `is_empty`
- `CaptureLink` / `LinkType` — `Ethernet | Raw | Loopback | Null`, `LinkType::dlt() -> u32`

### Parsers (`fn`s in lib.rs)

| Function | Input | Output | Notes |
|---|---|---|---|
| `parse_ethernet(&[u8])` | raw bytes (>=14) | `EthernetFrame` | Handles 802.1Q VLAN |
| `parse_ipv4(&[u8])` | IP hdr+ (>=20) | `IpPacket` | Validates IHL/version |
| `parse_ipv6(&[u8])` | IPv6 hdr (>=40) | `IpPacket` | Hop-limit as ttl |
| `parse_tcp(&[u8])` | TCP segment (>=20) | `TcpSegment` | Validates data-offset |
| `parse_udp(&[u8])` | UDP datagram (>=8) | `UdpDatagram` | |
| `parse_icmp(&[u8])` | ICMP (>=4) | `IcmpPacket` | |
| `parse_dns(&[u8])` | DNS payload (>=12) | `DnsPacket` | Compression-pointer safe, MAX 512 records, hop-limit on names |
| `parse_http_request(&[u8])` | UTF-8 HTTP/1.x | `HttpRequest` | |
| `parse_http_response(&[u8])` | UTF-8 HTTP/1.x | `HttpResponse` | |

### DNS
- `DnsPacket { id, flags, questions, answers, authorities, additional }` — `is_response()`, `rcode() -> u8`
- `DnsQuestion { name, qtype, qclass }`
- `DnsRecord { name, rtype, rclass, ttl, rdata }`

### HTTP
- `HttpRequest { method, uri, version, headers, body }` — `header(name) -> Option<&str>` (case-insensitive)
- `HttpResponse { version, status_code, reason, headers, body }` — `header(name)`

### Connection tracking
- `FlowKey { src_ip, src_port, dst_ip, dst_port }` — `new`, `canonical()`
- `TcpState` — SynSent, SynReceived, Established, FinWait1/2, CloseWait, Closing, LastAck, TimeWait, Closed
- `Connection { key, state, stream_data, packet_count, byte_count, first_seen, last_seen }`
- `ConnectionTracker` — `new`, `process(&IpPacket, now) -> Result<()>`, `get(&FlowKey)`, `all()`, `remove`, `len`, `is_empty`
- `ConnectionInfo { src: SocketAddr, dst, protocol: Protocol, pid: Option<u32> }` — `new`, `is_local()`
- `Protocol` — `Tcp Udp Icmp Dns Http Https Unknown`
- `protocol_is_tls(&Protocol) -> bool`
- `Direction` — `Inbound | Outbound | Unknown`

### Traits
- `#[async_trait] PacketCapture { capture_next() async -> Result<Packet>; filter(bpf: &str); stats() -> CaptureStats }`
- `PacketSink { accept(&PacketBuffer) -> Result<(),NetworkError>; flush() default }`
  - `BlackholePacketSink` — discards
  - `BufferingPacketSink` — `new`, `drain() -> Vec<PacketBuffer>`

### Stats
- `CaptureStats { received, dropped, if_dropped }`

## Sub-module highlights (traffic_reassembler)

- `StreamKey`, `TransportProto`, `TcpSegment` (reassembler-local), `TcpStream`
- `KeyLogEntry`, `TlsKeyStore`, `decrypt_tls_stream(...)`
- `AppProtocol`, `HttpMessage`, `HttpDirection`, `parse_http1_stream(&[u8]) -> Vec<HttpMessage>`
- `Http2Frame`, `parse_http2_frames(&[u8]) -> Vec<Http2Frame>`
- `ReconstructedStream`, `StreamSummary`

## I/O summary

- **Input**: raw byte slices (link/IP/transport/app frames), `IpPacket`s into trackers, `PacketBuffer`s into sinks, BPF filter strings.
- **Output**: typed parsed structs (Ethernet/IP/TCP/UDP/ICMP/DNS/HTTP/ARP), `Connection`/`ConnectionInfo` records, reassembled `TcpStream`/`HttpMessage`/`Http2Frame`, `CaptureStats`. All major types `Serialize+Deserialize`.

## Tests
`tests/blitz.rs`, `tests/blitz2.rs` — integration smoke tests. Library is fully unit-testable (pure parsers + in-memory tracker, no I/O dependencies except the optional `PacketCapture` trait).
