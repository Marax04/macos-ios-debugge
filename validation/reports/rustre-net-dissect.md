# rustre-net-dissect

Deep packet dissection and protocol recognition library: trait-based dissector framework with registry, built-in dissectors for many L2-L7 protocols, fingerprinting (JA3/JA3S), TCP stream reassembly, and protocol statistics.

## Cargo.toml

- **name**: `rustre-net-dissect`
- **edition / version / license / authors / repo**: workspace-inherited
- **Dependencies**:
  - `rustre-net` (path `../rustre-net`) — base L2-L4 parsers
  - `anyhow`, `thiserror` — errors
  - `serde`, `serde_json` — serialization
  - `parking_lot` — RwLock
  - `md-5` — fingerprint hashing (JA3)
  - `bitflags` — flag types
- **Lints**: workspace
- **Lib**: `#![forbid(unsafe_code)]`

## Modules

- `application_protocols` — HTTP/1.1, HTTP/2, DNS, SMTP, FTP, SSH, MQTT, AMQP
- `protocol_stats` — counters, conversation matrix, bandwidth
- `stream_reassembler` — TCP reassembly, OOO queue, PDU extraction
- `tls_dissector`, `dns_dissector`, `http2_dissector`
- `dissectors_application`, `dissectors_c2`, `dissectors_industrial`

## Core API (lib.rs)

### Error / value types
- `enum DissectError` — `BufferTooShort`, `TooShort`, `InvalidMagic`, `MalformedField`, `UnsupportedProtocol`, `NoDissector`, `Failed`, `ParseError`, `UnsupportedVersion`
- `enum FieldValue` — `Bytes/Uint/Int/Str/IpAddr/MacAddr/Bool/Float`
- `enum FrameFieldValue`, `struct Field`, `struct DissectedFrame`, `struct DissectorContext`

### Layer model
- `struct ProtoField { name, value, description, raw_offset, raw_len }`
- `struct ProtoLayer { protocol, fields, children, raw_data }`
- `struct DissectedPacket { layers, length, timestamp_us }`

### Traits
- `trait ProtocolDissector: Send + Sync` — `name()`, `dissect(&[u8]) -> Result<ProtoLayer, DissectError>`, optional `next_protocol(&ProtoLayer) -> Option<&str>`
- `trait Dissector: Send + Sync` — frame-style API

### Registry
- `struct DissectorRegistry` — register/get, dissect full chain
- `pub fn default_registry() -> DissectorRegistry`
- `pub fn full_registry() -> DissectorRegistry`
- `pub fn extended_registry() -> DissectorRegistry`
- `struct FrameDissectorRegistry`
- `struct DissectorChain`
- `struct DissectionSession`

### Built-in protocol dissectors (struct + impl ProtocolDissector)
- L2/L3/L4: `EthernetDissector`, `Ipv4Dissector`, `Ipv6Dissector`, `TcpDissector`, `UdpDissector`, `IcmpDissector`, `IcmpExtDissector`, `IcmpEnhancedDissector`
- App: `DnsDissector`, `DnsFullDissector`, `HttpDissector`, `TlsDissector`, `TlsFullDissector`, `SmbDissector`, `SmbFullDissector`, `Smb2FullDissector`, `FtpDissector`, `FtpFullDissector`, `SmtpDissector`, `SmtpFullDissector`, `Pop3Dissector`, `ImapDissector`, `SshDissector`, `RdpDissector`, `DhcpDissector`, `TelnetDissector`, `NtpDissector`, `SyslogDissector`, `SnmpDissector`, `NbnsDissector`, `KerberosDissector`
- Frame variants: `EthernetFrameDissector`, `Ipv4FrameDissector`, `Ipv6FrameDissector`, `TcpFrameDissector`, `UdpFrameDissector`, `DnsFrameDissector`, `HttpFrameDissector`, `TlsFrameDissector`
- Security/ICS: `HttpAttackDissector`, `ModbusDissector`, `Dnp3Dissector`, `AutoDetectDissector`

### Parsed messages
- `EthernetFrame`, `Ipv4Packet`, `TcpSegment`, `UdpDatagram`
- `DnsQuestion`, `DnsQuery`, `DnsMessage`, `DnsRecord`, `DnsRdata`, `DnsFullMessage`
- `HttpRequest`, `HttpResponse`, `HttpMessage`, `HttpFrameRequest`, `HttpFrameResponse`
- `TlsRecord`, `TlsHandshakeMessage`, `TlsHandshakeType`, `TlsContentType`, `TlsFingerprint`
- `Smb2Header`, `Smb2NegotiateRequest`, `Smb2CreateRequest`, `Smb2ReadRequest`, `Smb2WriteRequest`, `Smb2Command`
- `KerberosMessage`, `KerberosMessageType`, `KerberosEtype`
- `ModbusPacket`, `ModbusFunctionCode`
- `Dnp3Frame`, `Dnp3LinkControl`, `Dnp3LinkBits`, `Dnp3ObjectHeader`
- `DhcpMessage`, `DhcpOption`, `DhcpMsgType`
- `TelnetNegotiation`, `TelnetDissection`, `TelnetCommand`
- `NtpPacket`, `NtpLeap`, `NtpMode`
- `SyslogMessage`, `SyslogSeverity`, `SyslogFacility`
- `SnmpHeader`, `SnmpVersion`, `SnmpPduType`
- `NbnsHeader`, `NbnsOpcode`
- `RdpPduType`, `IpVersion`, `FlowDir`

### Free functions (top-level)
- `fn fingerprint_protocol(data: &[u8], src_port: u16, dst_port: u16) -> &'static str`
- `fn fingerprint_detailed(data, src_port, dst_port) -> FingerprintResult` (+ `FingerprintConfidence`)
- `fn fingerprint_udp_payload(data: &[u8]) -> Option<&'static str>`
- `fn fingerprint_tcp_payload(data: &[u8]) -> Option<&'static str>`
- `fn auto_detect_protocol(src_port, dst_port, data) -> Option<AutoDetectResult>` (+ `DetectConfidence`)
- `fn ja3_fingerprint(data: &[u8]) -> Option<String>`
- `fn ja3s_fingerprint(data: &[u8]) -> Option<String>`
- `fn tls_server_cipher_suite(data: &[u8]) -> String`
- `fn compute_tls_fingerprint(packets: &[&[u8]]) -> TlsFingerprint`
- `fn dissect_http(packet: &[u8]) -> Option<HttpMessage>`
- `fn decode_http_chunked(data: &[u8]) -> Result<Vec<u8>, DissectError>`
- `fn dissect_ethernet/ipv4/ipv6_frame/tcp_frame/udp_frame/dns_frame/tls_frame(payload) -> Result<DissectedFrame, DissectError>`
- `fn scan_http_attacks(data: &[u8]) -> Vec<HttpAttackIndicator>` (+ `HttpAttackKind`)
- `fn scan_http_attacks_decoded(data: &[u8]) -> Vec<HttpAttackIndicator>`
- `fn url_decode(input: &[u8]) -> Vec<u8>`
- `fn parse_kerberos(data: &[u8]) -> Result<KerberosMessage, DissectError>`
- `fn byte_entropy(data: &[u8]) -> f64`
- `fn dnp3_crc16(data: &[u8]) -> u16`
- `fn icmp_stream_tunnel_heuristic(payloads: &[&[u8]]) -> bool` (+ `IcmpTunnelAnalysis`)
- Name lookups (`const fn`): `dns_rtype_name`, `tls_version_name`, `ssh_msg_type_name`, `icmp_type_name`, `smb1_command_name`, `smb2_command_name`, `nt_status_name`, `dnp3_app_fc_name`
- Description helpers: `ftp_command_description`, `smtp_command_description`, `smtp_response_description`, `pop3_command_description`
- ICS helpers: `ics_protocol_for_port`, `is_ics_port`, `modbus_fc_is_write`, `modbus_fc_is_diagnostic`, `dnp3_fc_is_control`, `smb2_is_sensitive_share`
- Constants: `ICMP_TUNNEL_LARGE_PAYLOAD_THRESHOLD: usize = 64`, `ICMP_TUNNEL_HIGH_ENTROPY_THRESHOLD: f64 = 7.0`

## Submodule API highlights

- **tls_dissector**: `TlsDissector`, `TlsSession`, `TlsSessionState`, `TlsRecord`, `Handshake`, `HandshakeType`, `CipherSuite(u16)`, `Extension`, `Certificate`, `KeyExchange`, `KeyExchangeAlgorithm`, `Alert`, `AlertLevel`, `TlsVersion`, `ContentType`, `TlsError`
- **stream_reassembler**: `TCPSegment`, `GapDetector`, `OutOfOrderQueue` (and others) — TCP reassembly + PDU extraction

## I/O contract

- **Input**: raw byte slices (`&[u8]`) representing frame/packet/PDU payloads, plus port hints for fingerprinting; for stateful flows, a `DissectionSession` per (src/dst, flow direction)
- **Output**:
  - `ProtoLayer` / nested `DissectedPacket` (registry path) — protocol name, fields with raw offsets, child layers
  - `DissectedFrame` (frame dissector path) — fields with offsets/lengths
  - Typed structs for specific protocols (e.g. `DnsFullMessage`, `Smb2Header`, `ModbusPacket`)
  - Fingerprint outputs: `&'static str` (quick), `FingerprintResult` (detailed with `FingerprintConfidence`), `AutoDetectResult` (`DetectConfidence`), `TlsFingerprint` (JA3/JA3S strings + MD5)
  - Error: `DissectError`
- **Side effects**: none; pure dissection. Registries use `parking_lot::RwLock` internally, all `Send + Sync`.

## Testability

Fully testable as a pure library: deterministic functions over byte slices with no I/O, no `unsafe`. Test vectors can be supplied as hex byte arrays; assertions against returned `ProtoLayer`/typed structs and fingerprint strings.
