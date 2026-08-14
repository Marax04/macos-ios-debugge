
// ─── TCP stream reassembly ────────────────────────────────────────────────────

use std::collections::BTreeMap;

/// A five-tuple key (canonical form).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TcpSessionKey {
    pub src_ip:   [u8; 4],
    pub dst_ip:   [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
}

impl TcpSessionKey {
    /// Create a canonical (sorted) key so both directions map to the same session.
    #[must_use]
    pub fn canonical(sa: [u8; 4], sp: u16, da: [u8; 4], dp: u16) -> Self {
        if (sa, sp) <= (da, dp) {
            Self { src_ip: sa, dst_ip: da, src_port: sp, dst_port: dp }
        } else {
            Self { src_ip: da, dst_ip: sa, src_port: dp, dst_port: sp }
        }
    }

    #[must_use]
    pub fn src_str(&self) -> String {
        format!("{}.{}.{}.{}:{}", self.src_ip[0], self.src_ip[1], self.src_ip[2], self.src_ip[3], self.src_port)
    }

    #[must_use]
    pub fn dst_str(&self) -> String {
        format!("{}.{}.{}.{}:{}", self.dst_ip[0], self.dst_ip[1], self.dst_ip[2], self.dst_ip[3], self.dst_port)
    }
}

impl std::fmt::Display for TcpSessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} <-> {}", self.src_str(), self.dst_str())
    }
}

/// Pending out-of-order TCP segment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpSegment {
    pub seq: u32,
    pub data: Vec<u8>,
    pub fin: bool,
    pub rst: bool,
}

/// State machine for one direction of a TCP stream.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TcpStreamHalf {
    /// Next expected sequence number.
    pub next_seq: u32,
    /// Reassembled in-order data.
    pub data: Vec<u8>,
    /// Out-of-order segments (keyed by seq).
    pub ooo: BTreeMap<u32, TcpSegment>,
    /// Whether FIN has been seen.
    pub fin_seen: bool,
    /// Whether RST has been seen.
    pub rst_seen: bool,
}

impl TcpStreamHalf {
    /// Feed a segment into this half-stream.
    pub fn insert(&mut self, seg: TcpSegment) {
        if seg.rst {
            self.rst_seen = true;
            return;
        }
        let end = seg.seq.wrapping_add(seg.data.len() as u32);
        if seg.seq == self.next_seq {
            self.data.extend_from_slice(&seg.data);
            self.next_seq = end;
            if seg.fin { self.fin_seen = true; }
            // Try to drain out-of-order queue
            loop {
                if let Some((&k, _)) = self.ooo.iter().next() {
                    if k == self.next_seq {
                        let s = self.ooo.remove(&k).unwrap();
                        let e = s.seq.wrapping_add(s.data.len() as u32);
                        self.data.extend_from_slice(&s.data);
                        self.next_seq = e;
                        if s.fin { self.fin_seen = true; }
                        continue;
                    }
                }
                break;
            }
        } else if seg.seq.wrapping_sub(self.next_seq) < 0x7FFF_FFFF {
            // Future segment — queue it
            self.ooo.insert(seg.seq, seg);
        }
        // Past segment (retransmit) — ignore
    }
}

/// State of a reassembled TCP session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TcpSessionState {
    Open,
    HalfClosed,
    Closed,
    Reset,
}

/// A full reassembled TCP session with both half-streams.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpSession {
    pub key: TcpSessionKey,
    pub client: TcpStreamHalf,   // src→dst direction
    pub server: TcpStreamHalf,   // dst→src direction
    pub state: TcpSessionState,
    pub first_seen_us: u64,
    pub last_seen_us: u64,
    pub packet_count: u64,
}

impl TcpSession {
    #[must_use]
    pub fn new(key: TcpSessionKey, ts: u64) -> Self {
        Self {
            key,
            client: TcpStreamHalf::default(),
            server: TcpStreamHalf::default(),
            state: TcpSessionState::Open,
            first_seen_us: ts,
            last_seen_us: ts,
            packet_count: 0,
        }
    }

    #[must_use]
    pub fn duration_ms(&self) -> u64 {
        self.last_seen_us.saturating_sub(self.first_seen_us) / 1000
    }

    #[must_use]
    pub fn bytes_client(&self) -> usize { self.client.data.len() }
    #[must_use]
    pub fn bytes_server(&self) -> usize { self.server.data.len() }
    #[must_use]
    pub fn total_bytes(&self) -> usize { self.client.data.len() + self.server.data.len() }
}

/// TCP stream reassembler: tracks multiple sessions.
#[derive(Debug, Default)]
pub struct TcpReassembler {
    pub sessions: std::collections::HashMap<TcpSessionKey, TcpSession>,
    /// Timeout for idle sessions (microseconds). Default: 60 s.
    pub timeout_us: u64,
}

impl TcpReassembler {
    #[must_use]
    pub fn new() -> Self {
        Self { sessions: Default::default(), timeout_us: 60_000_000 }
    }

    /// Process a raw Ethernet frame (assumes Ethernet → IPv4 → TCP).
    pub fn process_frame(&mut self, data: &[u8], ts_us: u64) {
        // Parse Ethernet header (14 bytes)
        if data.len() < 14 { return; }
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        if ethertype != 0x0800 { return; } // IPv4 only

        // Parse IPv4 header
        if data.len() < 34 { return; }
        let ip_hdr_len = ((data[14] & 0x0F) as usize) * 4;
        if data[23] != 6 { return; } // TCP only
        let ip_start = 14usize;
        if data.len() < ip_start + ip_hdr_len + 20 { return; }

        let src_ip = [data[26], data[27], data[28], data[29]];
        let dst_ip = [data[30], data[31], data[32], data[33]];

        // Parse TCP header
        let tcp_start = ip_start + ip_hdr_len;
        let src_port = u16::from_be_bytes([data[tcp_start], data[tcp_start + 1]]);
        let dst_port = u16::from_be_bytes([data[tcp_start + 2], data[tcp_start + 3]]);
        let seq = u32::from_be_bytes([data[tcp_start + 4], data[tcp_start + 5], data[tcp_start + 6], data[tcp_start + 7]]);
        let tcp_data_off = ((data[tcp_start + 12] >> 4) as usize) * 4;
        let flags = data[tcp_start + 13];
        let fin = flags & 0x01 != 0;
        let syn = flags & 0x02 != 0;
        let rst = flags & 0x04 != 0;

        let payload_start = tcp_start + tcp_data_off;
        let payload = if payload_start < data.len() { data[payload_start..].to_vec() } else { vec![] };

        let key = TcpSessionKey::canonical(src_ip, src_port, dst_ip, dst_port);
        let is_client_dir = (src_ip, src_port) == (key.src_ip, key.src_port);

        let session = self.sessions.entry(key.clone()).or_insert_with(|| TcpSession::new(key, ts_us));
        session.last_seen_us = ts_us;
        session.packet_count += 1;

        if rst {
            session.state = TcpSessionState::Reset;
        } else if !syn {
            let seg = TcpSegment { seq, data: payload, fin, rst };
            if is_client_dir {
                session.client.insert(seg);
            } else {
                session.server.insert(seg);
            }
            if fin {
                session.state = TcpSessionState::HalfClosed;
            }
        }
    }

    /// Collect all sessions that have been idle longer than `timeout_us`.
    pub fn collect_expired(&mut self, now_us: u64) -> Vec<TcpSession> {
        let expired: Vec<TcpSessionKey> = self.sessions
            .iter()
            .filter(|(_, s)| now_us.saturating_sub(s.last_seen_us) > self.timeout_us)
            .map(|(k, _)| k.clone())
            .collect();
        expired.into_iter().filter_map(|k| self.sessions.remove(&k)).collect()
    }
}

// ─── HTTP/1.1 parser ──────────────────────────────────────────────────────────

/// HTTP request parsed from reassembled TCP data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub host: String,
    pub content_length: Option<usize>,
    pub is_chunked: bool,
}

impl HttpRequest {
    /// Parse an HTTP/1.1 request from raw bytes.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(data).ok()?;
        let header_end = text.find("\r\n\r\n")?;
        let header_part = &text[..header_end];
        let mut lines = header_part.lines();
        let request_line = lines.next()?;
        let mut parts = request_line.splitn(3, ' ');
        let method  = parts.next()?.to_string();
        let path    = parts.next()?.to_string();
        let version = parts.next().unwrap_or("HTTP/1.1").to_string();

        let mut headers = Vec::new();
        let mut host = String::new();
        let mut content_length = None;
        let mut is_chunked = false;

        for line in lines {
            if let Some(colon) = line.find(':') {
                let name  = line[..colon].trim().to_lowercase();
                let value = line[colon + 1..].trim().to_string();
                if name == "host" { host = value.clone(); }
                if name == "content-length" {
                    content_length = value.parse().ok();
                }
                if name == "transfer-encoding" && value.to_lowercase().contains("chunked") {
                    is_chunked = true;
                }
                headers.push((line[..colon].trim().to_string(), value));
            }
        }

        let body_start = header_end + 4;
        let body = data.get(body_start..).unwrap_or(&[]).to_vec();

        Some(Self { method, path, version, headers, body, host, content_length, is_chunked })
    }

    /// Reconstruct the full URL if a Host header is present.
    #[must_use]
    pub fn url(&self) -> String {
        if self.host.is_empty() {
            self.path.clone()
        } else {
            format!("http://{}{}", self.host, self.path)
        }
    }
}

/// HTTP response parsed from reassembled TCP data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub version: String,
    pub status_code: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub content_length: Option<usize>,
    pub is_chunked: bool,
    pub content_type: String,
}

impl HttpResponse {
    /// Parse an HTTP/1.1 response from raw bytes.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(data).ok()?;
        let header_end = text.find("\r\n\r\n")?;
        let header_part = &text[..header_end];
        let mut lines = header_part.lines();
        let status_line = lines.next()?;
        let mut parts = status_line.splitn(3, ' ');
        let version     = parts.next()?.to_string();
        let status_code: u16 = parts.next()?.parse().ok()?;
        let reason      = parts.next().unwrap_or("").to_string();

        let mut headers = Vec::new();
        let mut content_length = None;
        let mut is_chunked = false;
        let mut content_type = String::new();

        for line in lines {
            if let Some(colon) = line.find(':') {
                let name  = line[..colon].trim().to_lowercase();
                let value = line[colon + 1..].trim().to_string();
                if name == "content-length" { content_length = value.parse().ok(); }
                if name == "transfer-encoding" && value.to_lowercase().contains("chunked") { is_chunked = true; }
                if name == "content-type" { content_type = value.clone(); }
                headers.push((line[..colon].trim().to_string(), value));
            }
        }

        let body_start = header_end + 4;
        let body = data.get(body_start..).unwrap_or(&[]).to_vec();
        Some(Self { version, status_code, reason, headers, body, content_length, is_chunked, content_type })
    }
}

// ─── TLS ClientHello parser ───────────────────────────────────────────────────

/// A parsed TLS ClientHello message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsClientHello {
    /// TLS record layer version (e.g. 0x0301).
    pub record_version: u16,
    /// Handshake ClientHello version.
    pub client_version: u16,
    /// 32-byte random.
    pub random: Vec<u8>,
    /// Session ID (0–32 bytes).
    pub session_id: Vec<u8>,
    /// Cipher suites.
    pub cipher_suites: Vec<u16>,
    /// Compression methods.
    pub compression_methods: Vec<u8>,
    /// SNI hostname (from extension 0x0000).
    pub sni: Option<String>,
    /// Supported groups (from extension 0x000A).
    pub supported_groups: Vec<u16>,
    /// ALPN protocols (from extension 0x0010).
    pub alpn: Vec<String>,
    /// Whether early data extension is present (0x002A).
    pub early_data: bool,
    /// Raw extension types present.
    pub extension_types: Vec<u16>,
}

/// Parse a TLS ClientHello from a TCP payload.
///
/// Returns `None` if the data is not a valid ClientHello.
#[must_use]
pub fn parse_tls_client_hello(data: &[u8]) -> Option<TlsClientHello> {
    if data.len() < 43 { return None; }
    // TLS record layer
    if data[0] != 0x16 { return None; } // Handshake
    let record_version = u16::from_be_bytes([data[1], data[2]]);
    // let record_len = u16::from_be_bytes([data[3], data[4]]);
    // Handshake header
    if data[5] != 0x01 { return None; } // ClientHello
    // let hs_len = u24_be(&data[6..9]);
    let client_version = u16::from_be_bytes([data[9], data[10]]);
    let random = data[11..43].to_vec();
    let mut off = 43usize;
    // Session ID
    if off >= data.len() { return None; }
    let sid_len = data[off] as usize;
    off += 1;
    if off + sid_len > data.len() { return None; }
    let session_id = data[off..off + sid_len].to_vec();
    off += sid_len;
    // Cipher suites
    if off + 2 > data.len() { return None; }
    let cs_len = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
    off += 2;
    if off + cs_len > data.len() { return None; }
    let mut cipher_suites = Vec::new();
    for i in (0..cs_len).step_by(2) {
        cipher_suites.push(u16::from_be_bytes([data[off + i], data[off + i + 1]]));
    }
    off += cs_len;
    // Compression methods
    if off >= data.len() { return None; }
    let cm_len = data[off] as usize;
    off += 1;
    if off + cm_len > data.len() { return None; }
    let compression_methods = data[off..off + cm_len].to_vec();
    off += cm_len;
    // Extensions
    let mut sni = None;
    let mut supported_groups = Vec::new();
    let mut alpn = Vec::new();
    let mut early_data = false;
    let mut extension_types = Vec::new();

    if off + 2 <= data.len() {
        let ext_total = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        let ext_end = off + ext_total;
        while off + 4 <= ext_end.min(data.len()) {
            let ext_type = u16::from_be_bytes([data[off], data[off + 1]]);
            let ext_len  = u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize;
            off += 4;
            extension_types.push(ext_type);
            if off + ext_len > data.len() { break; }
            let ext_data = &data[off..off + ext_len];
            match ext_type {
                0x0000 => { // SNI
                    if ext_data.len() >= 5 {
                        let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
                        if ext_data.len() >= 5 + name_len {
                            sni = std::str::from_utf8(&ext_data[5..5 + name_len]).ok().map(String::from);
                        }
                    }
                }
                0x000A => { // Supported groups
                    if ext_data.len() >= 2 {
                        let glen = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                        for i in (0..glen.min(ext_data.len() - 2)).step_by(2) {
                            supported_groups.push(u16::from_be_bytes([ext_data[2 + i], ext_data[2 + i + 1]]));
                        }
                    }
                }
                0x0010 => { // ALPN
                    let mut ap = 2usize;
                    while ap + 1 < ext_data.len() {
                        let plen = ext_data[ap] as usize;
                        ap += 1;
                        if ap + plen <= ext_data.len() {
                            if let Ok(s) = std::str::from_utf8(&ext_data[ap..ap + plen]) {
                                alpn.push(s.to_string());
                            }
                        }
                        ap += plen;
                    }
                }
                0x002A => { early_data = true; }
                _ => {}
            }
            off += ext_len;
        }
    }

    Some(TlsClientHello {
        record_version, client_version, random, session_id,
        cipher_suites, compression_methods,
        sni, supported_groups, alpn, early_data, extension_types,
    })
}

// ─── JA3 fingerprint ──────────────────────────────────────────────────────────

/// Grease values to exclude from JA3 computation.
const GREASE: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a,
    0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
];

fn is_grease(v: u16) -> bool { GREASE.contains(&v) }

/// Compute the JA3 fingerprint string (before MD5) from a [`TlsClientHello`].
#[must_use]
pub fn ja3_string(hello: &TlsClientHello) -> String {
    let version = hello.client_version.to_string();

    let ciphers: Vec<String> = hello.cipher_suites.iter()
        .filter(|&&c| !is_grease(c))
        .map(|c| c.to_string())
        .collect();

    let ext_types: Vec<String> = hello.extension_types.iter()
        .filter(|&&e| !is_grease(e))
        .map(|e| e.to_string())
        .collect();

    let groups: Vec<String> = hello.supported_groups.iter()
        .filter(|&&g| !is_grease(g))
        .map(|g| g.to_string())
        .collect();

    // Point formats: assume uncompressed (0) if not present
    let point_formats = "0";

    format!(
        "{},{},{},{},{}",
        version,
        ciphers.join("-"),
        ext_types.join("-"),
        groups.join("-"),
        point_formats,
    )
}

/// Compute the JA3 MD5 hash from a [`TlsClientHello`].
///
/// Uses a simple MD5 implementation. If the `md5` crate is not available,
/// returns the raw JA3 string prefixed with `raw:`.
#[must_use]
pub fn ja3_fingerprint(hello: &TlsClientHello) -> String {
    let s = ja3_string(hello);
    // Compute MD5 via the md5 module (inline implementation to avoid dependency)
    format!("ja3:{}", md5_hex(s.as_bytes()))
}

/// Minimal MD5 implementation (RFC 1321) — no external dependency.
fn md5_hex(input: &[u8]) -> String {
    let digest = md5_compute(input);
    digest.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("")
}

fn md5_compute(input: &[u8]) -> [u8; 16] {
    // Constants
    const S: [u32; 64] = [
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];
    let mut msg = input.to_vec();
    let original_bit_len = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&original_bit_len.to_le_bytes());
    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;
    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            *w = u32::from_le_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64u32 {
            let (f, g) = match i {
                0..=15  => ((b & c) | (!b & d),              i),
                16..=31 => ((d & b) | (!d & c),              (5*i+1) % 16),
                32..=47 => (b ^ c ^ d,                       (3*i+5) % 16),
                _       => (c ^ (b | !d),                    (7*i) % 16),
            };
            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add((a.wrapping_add(f).wrapping_add(K[i as usize]).wrapping_add(m[g as usize])).rotate_left(S[i as usize]));
            a = temp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

// ─── DNS parser ───────────────────────────────────────────────────────────────

/// A DNS question.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// A DNS resource record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRR {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: DnsRData,
}

/// Decoded DNS record data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DnsRData {
    A([u8; 4]),
    Aaaa([u8; 16]),
    Cname(String),
    Ns(String),
    Mx { priority: u16, exchange: String },
    Txt(Vec<String>),
    Soa { mname: String, rname: String, serial: u32 },
    Ptr(String),
    Raw(Vec<u8>),
}

impl std::fmt::Display for DnsRData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A(a)         => write!(f, "{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
            Self::Aaaa(a)      => {
                let words: Vec<String> = (0..8).map(|i| format!("{:x}", u16::from_be_bytes([a[i*2], a[i*2+1]]))).collect();
                write!(f, "{}", words.join(":"))
            }
            Self::Cname(s) | Self::Ns(s) | Self::Ptr(s) => write!(f, "{s}"),
            Self::Mx { priority, exchange } => write!(f, "{priority} {exchange}"),
            Self::Txt(parts)   => write!(f, "{}", parts.join(" ")),
            Self::Soa { mname, rname, serial } => write!(f, "{mname} {rname} {serial}"),
            Self::Raw(d)       => write!(f, "[{} bytes]", d.len()),
        }
    }
}

/// A complete DNS message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsMessage {
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub rcode: u8,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRR>,
    pub authority: Vec<DnsRR>,
    pub additional: Vec<DnsRR>,
}

/// Parse a DNS name starting at `off` in `data`, handling compression pointers.
fn parse_dns_name(data: &[u8], off: usize) -> Option<(String, usize)> {
    let mut parts = Vec::new();
    let mut pos = off;
    let mut jumped = false;
    let mut end_pos = off;
    let mut safety = 0usize;
    loop {
        safety += 1;
        if safety > 128 || pos >= data.len() { break; }
        let len = data[pos];
        if len == 0 {
            if !jumped { end_pos = pos + 1; }
            break;
        } else if len & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() { return None; }
            let ptr = (((len & 0x3F) as usize) << 8) | data[pos + 1] as usize;
            if !jumped { end_pos = pos + 2; }
            jumped = true;
            pos = ptr;
        } else {
            let l = len as usize;
            pos += 1;
            if pos + l > data.len() { return None; }
            parts.push(std::str::from_utf8(&data[pos..pos+l]).unwrap_or("?").to_string());
            pos += l;
        }
    }
    Some((parts.join("."), end_pos))
}

/// Parse a DNS message from raw UDP payload.
#[must_use]
pub fn parse_dns(data: &[u8]) -> Option<DnsMessage> {
    if data.len() < 12 { return None; }
    let id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let is_response = flags & 0x8000 != 0;
    let opcode = ((flags >> 11) & 0xF) as u8;
    let truncated = flags & 0x0200 != 0;
    let recursion_desired = flags & 0x0100 != 0;
    let recursion_available = flags & 0x0080 != 0;
    let rcode = (flags & 0x000F) as u8;
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;
    let mut off = 12usize;

    let mut questions = Vec::new();
    for _ in 0..qdcount {
        let (name, next) = parse_dns_name(data, off)?;
        off = next;
        if off + 4 > data.len() { return None; }
        let qtype  = u16::from_be_bytes([data[off], data[off+1]]);
        let qclass = u16::from_be_bytes([data[off+2], data[off+3]]);
        off += 4;
        questions.push(DnsQuestion { name, qtype, qclass });
    }

    let parse_rrs = |count: usize, off: &mut usize| -> Option<Vec<DnsRR>> {
        let mut rrs = Vec::new();
        for _ in 0..count {
            let (name, next) = parse_dns_name(data, *off)?;
            *off = next;
            if *off + 10 > data.len() { return None; }
            let rtype  = u16::from_be_bytes([data[*off], data[*off+1]]);
            let rclass = u16::from_be_bytes([data[*off+2], data[*off+3]]);
            let ttl    = u32::from_be_bytes([data[*off+4], data[*off+5], data[*off+6], data[*off+7]]);
            let rdlen  = u16::from_be_bytes([data[*off+8], data[*off+9]]) as usize;
            *off += 10;
            if *off + rdlen > data.len() { return None; }
            let rdata_raw = &data[*off..*off + rdlen];
            let rdata = match (rtype, rdlen) {
                (1, 4) => DnsRData::A([rdata_raw[0], rdata_raw[1], rdata_raw[2], rdata_raw[3]]),
                (28, 16) => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(rdata_raw);
                    DnsRData::Aaaa(a)
                }
                (5, _) | (2, _) | (12, _) => {
                    let (n, _) = parse_dns_name(data, *off)?;
                    match rtype {
                        5  => DnsRData::Cname(n),
                        2  => DnsRData::Ns(n),
                        12 => DnsRData::Ptr(n),
                        _  => unreachable!(),
                    }
                }
                (15, _) if rdlen >= 2 => {
                    let priority = u16::from_be_bytes([rdata_raw[0], rdata_raw[1]]);
                    let (exchange, _) = parse_dns_name(data, *off + 2)?;
                    DnsRData::Mx { priority, exchange }
                }
                (16, _) => {
                    let mut parts = Vec::new();
                    let mut i = 0;
                    while i < rdlen {
                        let tlen = rdata_raw[i] as usize;
                        i += 1;
                        if i + tlen <= rdlen {
                            parts.push(String::from_utf8_lossy(&rdata_raw[i..i+tlen]).to_string());
                        }
                        i += tlen;
                    }
                    DnsRData::Txt(parts)
                }
                _ => DnsRData::Raw(rdata_raw.to_vec()),
            };
            *off += rdlen;
            rrs.push(DnsRR { name, rtype, rclass, ttl, rdata });
        }
        Some(rrs)
    };

    let answers    = parse_rrs(ancount, &mut off)?;
    let authority  = parse_rrs(nscount, &mut off)?;
    let additional = parse_rrs(arcount, &mut off)?;

    Some(DnsMessage { id, is_response, opcode, truncated, recursion_desired, recursion_available, rcode, questions, answers, authority, additional })
}

// ─── Application protocol identification ─────────────────────────────────────

/// Detected application-layer protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppProtocol {
    Http, Https, Dns, Ftp, Smtp, Ssh, Rdp, Smb, Unknown,
}

impl std::fmt::Display for AppProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http    => write!(f, "HTTP"),
            Self::Https   => write!(f, "HTTPS"),
            Self::Dns     => write!(f, "DNS"),
            Self::Ftp     => write!(f, "FTP"),
            Self::Smtp    => write!(f, "SMTP"),
            Self::Ssh     => write!(f, "SSH"),
            Self::Rdp     => write!(f, "RDP"),
            Self::Smb     => write!(f, "SMB"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Identify the application protocol for a connection.
///
/// `lo` is the lower of the two port numbers, `hi` is the higher.
/// `payloads` provides sample data from both directions.
#[must_use]
pub fn identify_protocol(lo: u16, hi: u16, payloads: &[&[u8]]) -> AppProtocol {
    match lo {
        22   => return AppProtocol::Ssh,
        3389 => return AppProtocol::Rdp,
        445  => return AppProtocol::Smb,
        53   => return AppProtocol::Dns,
        21 | 20 => return AppProtocol::Ftp,
        25 | 587 | 465 => return AppProtocol::Smtp,
        _ => {}
    }
    match hi {
        80 | 8080 | 8000 => return AppProtocol::Http,
        443 | 8443       => return AppProtocol::Https,
        53               => return AppProtocol::Dns,
        22               => return AppProtocol::Ssh,
        3389             => return AppProtocol::Rdp,
        445              => return AppProtocol::Smb,
        21 | 20          => return AppProtocol::Ftp,
        25 | 587 | 465   => return AppProtocol::Smtp,
        _ => {}
    }
    for payload in payloads {
        if payload.is_empty() { continue; }
        if payload.starts_with(b"HTTP/") || is_http_method_ext(payload) { return AppProtocol::Http; }
        if payload[0] == 22 && payload.len() >= 3 { return AppProtocol::Https; }
        if payload.len() >= 4 && &payload[..4] == b"SSH-" { return AppProtocol::Ssh; }
        if payload.len() >= 4 && (&payload[..4] == b"\xFFSMB" || &payload[..4] == b"\xFESMB") { return AppProtocol::Smb; }
    }
    AppProtocol::Unknown
}

fn is_http_method_ext(data: &[u8]) -> bool {
    for m in [b"GET " as &[u8], b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE "] {
        if data.starts_with(m) { return true; }
    }
    false
}

// ─── HAR export ───────────────────────────────────────────────────────────────

/// A HAR (HTTP Archive) entry for a single HTTP transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarEntry {
    pub started_datetime: String,
    pub time_ms: f64,
    pub request: HarRequest,
    pub response: HarResponse,
    pub server_ip_address: String,
    pub connection: String,
}

/// HAR request record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarRequest {
    pub method: String,
    pub url: String,
    pub http_version: String,
    pub headers: Vec<HarNameValue>,
    pub body_size: i64,
}

/// HAR response record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarResponse {
    pub status: u16,
    pub status_text: String,
    pub http_version: String,
    pub headers: Vec<HarNameValue>,
    pub body_size: i64,
    pub content: HarContent,
}

/// HAR name:value pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarNameValue {
    pub name: String,
    pub value: String,
}

/// HAR response content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarContent {
    pub size: i64,
    pub mime_type: String,
}

/// Build a minimal HAR log from HTTP requests/responses.
#[must_use]
pub fn build_har(entries: &[HarEntry]) -> String {
    let entries_json: Vec<String> = entries.iter().map(|e| {
        let req_headers: Vec<String> = e.request.headers.iter()
            .map(|h| format!("{{\"name\":{:?},\"value\":{:?}}}", h.name, h.value))
            .collect();
        let resp_headers: Vec<String> = e.response.headers.iter()
            .map(|h| format!("{{\"name\":{:?},\"value\":{:?}}}", h.name, h.value))
            .collect();
        format!(
            "{{\"startedDateTime\":{:?},\"time\":{},\"request\":{{\"method\":{:?},\"url\":{:?},\"httpVersion\":{:?},\"headers\":[{}],\"bodySize\":{}}},\"response\":{{\"status\":{},\"statusText\":{:?},\"httpVersion\":{:?},\"headers\":[{}],\"bodySize\":{},\"content\":{{\"size\":{},\"mimeType\":{:?}}}}}}}",
            e.started_datetime, e.time_ms,
            e.request.method, e.request.url, e.request.http_version,
            req_headers.join(","), e.request.body_size,
            e.response.status, e.response.status_text, e.response.http_version,
            resp_headers.join(","), e.response.body_size,
            e.response.content.size, e.response.content.mime_type,
        )
    }).collect();
    format!(
        "{{\"log\":{{\"version\":\"1.2\",\"creator\":{{\"name\":\"rustre-net-pcap\",\"version\":\"0.1\"}},\"entries\":[{}]}}}}",
        entries_json.join(",")
    )
}

// ─── Connection statistics ────────────────────────────────────────────────────

/// Per-connection stats for export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnStats {
    pub key: String,
    pub protocol: String,
    pub app_protocol: String,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packet_count: u64,
    pub first_seen_us: u64,
    pub last_seen_us: u64,
    pub duration_ms: u64,
}

impl ConnStats {
    #[must_use]
    pub fn from_session(s: &TcpSession) -> Self {
        Self {
            key: s.key.to_string(),
            protocol: "TCP".to_string(),
            app_protocol: AppProtocol::Unknown.to_string(),
            bytes_sent: s.bytes_client() as u64,
            bytes_recv: s.bytes_server() as u64,
            packet_count: s.packet_count,
            first_seen_us: s.first_seen_us,
            last_seen_us: s.last_seen_us,
            duration_ms: s.duration_ms(),
        }
    }

    /// Emit a CSV row with a fixed header.
    #[must_use]
    pub fn csv_header() -> &'static str {
        "key,protocol,app_protocol,bytes_sent,bytes_recv,packets,first_seen_us,last_seen_us,duration_ms"
    }

    #[must_use]
    pub fn to_csv(&self) -> String {
        format!("{},{},{},{},{},{},{},{},{}",
            self.key, self.protocol, self.app_protocol,
            self.bytes_sent, self.bytes_recv, self.packet_count,
            self.first_seen_us, self.last_seen_us, self.duration_ms,
        )
    }
}

// ─── Additional tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod pcap_ext_tests {
    use super::*;

    #[test]
    fn test_tcp_session_key_canonical() {
        let k1 = TcpSessionKey::canonical([1,2,3,4], 1234, [5,6,7,8], 80);
        let k2 = TcpSessionKey::canonical([5,6,7,8], 80, [1,2,3,4], 1234);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_tcp_stream_half_in_order() {
        let mut h = TcpStreamHalf::default();
        h.next_seq = 100;
        h.insert(TcpSegment { seq: 100, data: b"hello".to_vec(), fin: false, rst: false });
        h.insert(TcpSegment { seq: 105, data: b" world".to_vec(), fin: false, rst: false });
        assert_eq!(h.data, b"hello world");
    }

    #[test]
    fn test_tcp_stream_half_out_of_order() {
        let mut h = TcpStreamHalf::default();
        h.next_seq = 0;
        h.insert(TcpSegment { seq: 5, data: b"world".to_vec(), fin: false, rst: false });
        h.insert(TcpSegment { seq: 0, data: b"hello".to_vec(), fin: false, rst: false });
        assert_eq!(&h.data[..5], b"hello");
        assert_eq!(&h.data[5..], b"world");
    }

    #[test]
    fn test_tcp_stream_half_rst() {
        let mut h = TcpStreamHalf::default();
        h.insert(TcpSegment { seq: 0, data: vec![], fin: false, rst: true });
        assert!(h.rst_seen);
    }

    #[test]
    fn test_http_request_parse_get() {
        let raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let req = HttpRequest::parse(raw).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/index.html");
        assert_eq!(req.host, "example.com");
        assert_eq!(req.url(), "http://example.com/index.html");
    }

    #[test]
    fn test_http_request_parse_post_with_body() {
        let raw = b"POST /submit HTTP/1.1\r\nHost: test.com\r\nContent-Length: 5\r\n\r\nhello";
        let req = HttpRequest::parse(raw).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.content_length, Some(5));
        assert_eq!(req.body, b"hello");
    }

    #[test]
    fn test_http_response_parse_200() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 4\r\n\r\nbody";
        let resp = HttpResponse::parse(raw).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.content_type, "text/html");
        assert_eq!(resp.body, b"body");
    }

    #[test]
    fn test_http_response_parse_404() {
        let raw = b"HTTP/1.1 404 Not Found\r\n\r\n";
        let resp = HttpResponse::parse(raw).unwrap();
        assert_eq!(resp.status_code, 404);
        assert_eq!(resp.reason, "Not Found");
    }

    #[test]
    fn test_identify_protocol_http_port() {
        assert_eq!(identify_protocol(80, 1234, &[]), AppProtocol::Http);
    }

    #[test]
    fn test_identify_protocol_dns_port() {
        assert_eq!(identify_protocol(53, 5000, &[]), AppProtocol::Dns);
    }

    #[test]
    fn test_identify_protocol_https_payload() {
        // TLS record byte 22 = 0x16
        let payload: &[u8] = &[0x16, 0x03, 0x01];
        assert_eq!(identify_protocol(40000, 12345, &[payload]), AppProtocol::Https);
    }

    #[test]
    fn test_identify_protocol_http_method() {
        let payload: &[u8] = b"GET / HTTP/1.1\r\n";
        assert_eq!(identify_protocol(50000, 8000, &[payload]), AppProtocol::Http);
    }

    #[test]
    fn test_ja3_string_not_empty() {
        let hello = TlsClientHello {
            record_version: 0x0301,
            client_version: 0x0303,
            random: vec![0u8; 32],
            session_id: vec![],
            cipher_suites: vec![0x002f, 0x0035],
            compression_methods: vec![0],
            sni: Some("example.com".to_string()),
            supported_groups: vec![0x0017],
            alpn: vec!["h2".to_string()],
            early_data: false,
            extension_types: vec![0x0000, 0x000A, 0x0010],
        };
        let s = ja3_string(&hello);
        assert!(!s.is_empty());
        assert!(s.contains(','));
    }

    #[test]
    fn test_ja3_fingerprint_format() {
        let hello = TlsClientHello {
            record_version: 0x0301, client_version: 0x0303,
            random: vec![0u8; 32], session_id: vec![],
            cipher_suites: vec![0x002f], compression_methods: vec![0],
            sni: None, supported_groups: vec![], alpn: vec![],
            early_data: false, extension_types: vec![],
        };
        let fp = ja3_fingerprint(&hello);
        assert!(fp.starts_with("ja3:"));
        assert_eq!(fp.len(), 4 + 32); // "ja3:" + 32 hex chars
    }

    #[test]
    fn test_md5_empty() {
        let h = md5_hex(&[]);
        assert_eq!(h, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_md5_hello_world() {
        let h = md5_hex(b"hello world");
        assert_eq!(h, "5eb63bbbe01eeed093cb22bb8f5acdc3");
    }

    #[test]
    fn test_dns_parse_query() {
        // Minimal DNS query for "example.com" type A
        let mut pkt = vec![
            0x00, 0x01, // ID
            0x01, 0x00, // flags: QR=0 RD=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
        ];
        // name: "example.com"
        pkt.extend_from_slice(&[7u8]); pkt.extend_from_slice(b"example");
        pkt.extend_from_slice(&[3u8]); pkt.extend_from_slice(b"com");
        pkt.push(0); // root
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
        let msg = parse_dns(&pkt).unwrap();
        assert!(!msg.is_response);
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].name, "example.com");
        assert_eq!(msg.questions[0].qtype, 1);
    }

    #[test]
    fn test_tcp_session_duration() {
        let key = TcpSessionKey { src_ip: [1,2,3,4], dst_ip: [5,6,7,8], src_port: 1234, dst_port: 80 };
        let mut s = TcpSession::new(key, 1_000_000);
        s.last_seen_us = 3_000_000;
        assert_eq!(s.duration_ms(), 2000);
    }

    #[test]
    fn test_conn_stats_csv() {
        let key = TcpSessionKey { src_ip: [1,2,3,4], dst_ip: [5,6,7,8], src_port: 1234, dst_port: 80 };
        let s = TcpSession::new(key, 0);
        let cs = ConnStats::from_session(&s);
        let csv = cs.to_csv();
        assert!(csv.contains("TCP"));
    }

    #[test]
    fn test_har_build() {
        let entries = vec![HarEntry {
            started_datetime: "2024-01-01T00:00:00Z".to_string(),
            time_ms: 12.5,
            request: HarRequest {
                method: "GET".to_string(),
                url: "http://example.com/".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: vec![HarNameValue { name: "Host".to_string(), value: "example.com".to_string() }],
                body_size: 0,
            },
            response: HarResponse {
                status: 200,
                status_text: "OK".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: vec![],
                body_size: 100,
                content: HarContent { size: 100, mime_type: "text/html".to_string() },
            },
            server_ip_address: "93.184.216.34".to_string(),
            connection: "1".to_string(),
        }];
        let har = build_har(&entries);
        assert!(har.contains("\"version\":\"1.2\""));
        assert!(har.contains("GET"));
        assert!(har.contains("example.com"));
    }

    #[test]
    fn test_conn_stats_csv_header() {
        assert!(ConnStats::csv_header().starts_with("key,protocol"));
    }

    #[test]
    fn test_tls_client_hello_parse_minimal() {
        // Build a minimal ClientHello
        let mut data = vec![
            0x16,       // content type: Handshake
            0x03, 0x01, // record version TLS 1.0
            0x00, 0x2f, // record length (placeholder, not validated strictly)
            0x01,       // HandshakeType: ClientHello
            0x00, 0x00, 0x2b, // length
            0x03, 0x03, // client version TLS 1.2
        ];
        data.extend_from_slice(&[0u8; 32]); // random
        data.push(0); // session ID length = 0
        data.extend_from_slice(&[0, 4]);   // cipher suites length = 4
        data.extend_from_slice(&[0x00, 0x2f, 0x00, 0x35]); // TLS_RSA_WITH_AES_128/256
        data.push(1); data.push(0); // compression methods: 1 byte = null
        data.extend_from_slice(&[0, 0]); // extensions length = 0
        let hello = parse_tls_client_hello(&data);
        assert!(hello.is_some());
        let h = hello.unwrap();
        assert_eq!(h.client_version, 0x0303);
        assert_eq!(h.cipher_suites, vec![0x002f, 0x0035]);
    }
}
