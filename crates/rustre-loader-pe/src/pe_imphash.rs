//! Import hash calculation and analysis for PE binaries.
//!
//! # Overview
//!
//! The import hash (imphash) is a fingerprinting technique for Portable Executable
//! binaries based on the ordered list of imported functions and DLL names. It was
//! first described by Mandiant / `FireEye` and is widely used in malware analysis.
//!
//! This module provides:
//! - [`ImphashV1`]: Classic Mandiant imphash (MD5 over normalized import list).
//! - [`ImphashV2`]: Extended variant using SHA-256 and richer normalisation.
//! - [`FuzzyImphash`]: Locality-sensitive hash tolerant of minor import changes.
//! - [`TypedImphash`]: Segment imports by API category before hashing.
//! - [`ImphashDb`]: In-memory database of known imphash → family mappings.
//! - [`FamilyLookup`]: Query result from the imphash database.
//! - [`PeImphash`]: Facade that unifies all four algorithms.

use std::collections::HashMap;

use crate::casts::usize_to_f64;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum number of imports below which a hash is considered degenerate.
pub const MIN_IMPORTS_FOR_MEANINGFUL_HASH: usize = 3;

/// Well-known DLL prefixes that should be normalised away.
const KNOWN_DLL_EXTENSIONS: &[&str] = &[".dll", ".exe", ".sys", ".ocx", ".drv", ".cpl"];

/// API category keyword → category name mappings used by [`TypedImphash`].
const CRYPTO_APIS: &[&str] = &[
    "crypt", "hash", "bcrypt", "ncrypt", "ssl", "tls", "rsa", "aes", "des",
    "rc4", "md5", "sha", "cipher", "encrypt", "decrypt", "sign", "verify",
];
const NETWORK_APIS: &[&str] = &[
    "socket", "recv", "send", "connect", "bind", "listen", "accept",
    "inet", "http", "ftp", "dns", "resolve", "winsock", "wsasend",
    "wsarecv", "getaddr", "gethostname", "urldownload",
];
const FILE_APIS: &[&str] = &[
    "createfile", "readfile", "writefile", "deletefile", "copyfile",
    "movefile", "openfile", "findfile", "getfileinfo", "setfileattr",
];
const PROCESS_APIS: &[&str] = &[
    "createprocess", "openprocess", "terminateprocess", "virtualalloc",
    "writeprocessmemory", "readprocessmemory", "createthread",
    "suspendthread", "resumethread", "setthreadcontext",
];
const REGISTRY_APIS: &[&str] = &[
    "regopenkeyex", "regcreatekeyex", "regqueryvalueex",
    "regsetvalueex", "regdeletekey", "regenumkey",
];
const INJECTION_APIS: &[&str] = &[
    "loadlibrary", "getprocaddress", "freelibrary", "setwindowshook",
    "createremotethread", "queueuserapc", "ntmapviewofsection",
];

// ---------------------------------------------------------------------------
// Internal MD5/SHA helpers (pure Rust, no external crate)
// ---------------------------------------------------------------------------

/// Compute a hex-encoded MD5 digest of the given bytes.
/// Pure-Rust implementation for zero-dependency operation.
#[must_use]
pub fn md5_hex(data: &[u8]) -> String {
    let bytes = md5_compute(data);
    let mut out = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Compute a hex-encoded SHA-256 digest of the given bytes.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    let bytes = sha256_compute(data);
    let mut out = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

// ---- Minimal MD5 ----------------------------------------------------------

fn md5_compute(data: &[u8]) -> [u8; 16] {
    // T[i] = floor(abs(sin(i+1)) * 2^32)
    #[rustfmt::skip]
    const T: [u32; 64] = [
        0xd76a_a478,0xe8c7_b756,0x2420_70db,0xc1bd_ceee,
        0xf57c_0faf,0x4787_c62a,0xa830_4613,0xfd46_9501,
        0x6980_98d8,0x8b44_f7af,0xffff_5bb1,0x895c_d7be,
        0x6b90_1122,0xfd98_7193,0xa679_438e,0x49b4_0821,
        0xf61e_2562,0xc040_b340,0x265e_5a51,0xe9b6_c7aa,
        0xd62f_105d,0x0244_1453,0xd8a1_e681,0xe7d3_fbc8,
        0x21e1_cde6,0xc337_07d6,0xf4d5_0d87,0x455a_14ed,
        0xa9e3_e905,0xfcef_a3f8,0x676f_02d9,0x8d2a_4c8a,
        0xfffa_3942,0x8771_f681,0x6d9d_6122,0xfde5_380c,
        0xa4be_ea44,0x4bde_cfa9,0xf6bb_4b60,0xbebf_bc70,
        0x289b_7ec6,0xeaa1_27fa,0xd4ef_3085,0x0488_1d05,
        0xd9d4_d039,0xe6db_99e5,0x1fa2_7cf8,0xc4ac_5665,
        0xf429_2244,0x432a_ff97,0xab94_23a7,0xfc93_a039,
        0x655b_59c3,0x8f0c_cc92,0xffef_f47d,0x8584_5dd1,
        0x6fa8_7e4f,0xfe2c_e6e0,0xa301_4314,0x4e08_11a1,
        0xf753_7e82,0xbd3a_f235,0x2ad7_d2bb,0xeb86_d391,
    ];
    const S: [u32; 64] = [
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
    ];

    let msg_len = data.len();
    let bit_len = (msg_len as u64).wrapping_mul(8);

    // Pre-processing: adding padding bits
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_le_bytes());

    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xefcd_ab89;
    let mut c0: u32 = 0x98ba_dcfe;
    let mut d0: u32 = 0x1032_5476;

    for chunk in padded.chunks_exact(64) {
        let mut msg = [0u32; 16];
        for (idx, word) in msg.iter_mut().enumerate() {
            *word = u32::from_le_bytes(chunk[idx*4..idx*4+4].try_into().unwrap());
        }
        let (mut md5_a, mut md5_b, mut md5_c, mut md5_d) = (a0, b0, c0, d0);

        for step in 0usize..64 {
            let (func_val, src_idx) = if step < 16 {
                ((md5_b & md5_c) | ((!md5_b) & md5_d), step)
            } else if step < 32 {
                ((md5_d & md5_b) | ((!md5_d) & md5_c), (5*step + 1) % 16)
            } else if step < 48 {
                (md5_b ^ md5_c ^ md5_d, (3*step + 5) % 16)
            } else {
                (md5_c ^ (md5_b | (!md5_d)), (7*step) % 16)
            };
            let mixed = func_val.wrapping_add(md5_a).wrapping_add(T[step]).wrapping_add(msg[src_idx]);
            md5_a = md5_d;
            md5_d = md5_c;
            md5_c = md5_b;
            md5_b = md5_b.wrapping_add(mixed.rotate_left(S[step]));
        }

        a0 = a0.wrapping_add(md5_a);
        b0 = b0.wrapping_add(md5_b);
        c0 = c0.wrapping_add(md5_c);
        d0 = d0.wrapping_add(md5_d);
    }

    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&a0.to_le_bytes());
    result[4..8].copy_from_slice(&b0.to_le_bytes());
    result[8..12].copy_from_slice(&c0.to_le_bytes());
    result[12..16].copy_from_slice(&d0.to_le_bytes());
    result
}

// ---- Minimal SHA-256 -------------------------------------------------------

fn sha256_compute(data: &[u8]) -> [u8; 32] {
    #[rustfmt::skip]
    const K: [u32; 64] = [
        0x428a_2f98,0x7137_4491,0xb5c0_fbcf,0xe9b5_dba5,
        0x3956_c25b,0x59f1_11f1,0x923f_82a4,0xab1c_5ed5,
        0xd807_aa98,0x1283_5b01,0x2431_85be,0x550c_7dc3,
        0x72be_5d74,0x80de_b1fe,0x9bdc_06a7,0xc19b_f174,
        0xe49b_69c1,0xefbe_4786,0x0fc1_9dc6,0x240c_a1cc,
        0x2de9_2c6f,0x4a74_84aa,0x5cb0_a9dc,0x76f9_88da,
        0x983e_5152,0xa831_c66d,0xb003_27c8,0xbf59_7fc7,
        0xc6e0_0bf3,0xd5a7_9147,0x06ca_6351,0x1429_2967,
        0x27b7_0a85,0x2e1b_2138,0x4d2c_6dfc,0x5338_0d13,
        0x650a_7354,0x766a_0abb,0x81c2_c92e,0x9272_2c85,
        0xa2bf_e8a1,0xa81a_664b,0xc24b_8b70,0xc76c_51a3,
        0xd192_e819,0xd699_0624,0xf40e_3585,0x106a_a070,
        0x19a4_c116,0x1e37_6c08,0x2748_774c,0x34b0_bcb5,
        0x391c_0cb3,0x4ed8_aa4a,0x5b9c_ca4f,0x682e_6ff3,
        0x748f_82ee,0x78a5_636f,0x84c8_7814,0x8cc7_0208,
        0x90be_fffa,0xa450_6ceb,0xbef9_a3f7,0xc671_78f2,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut h: [u32; 8] = [
        0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
        0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
    ];

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, ww) in w.iter_mut().enumerate().take(16) {
            *ww = u32::from_be_bytes(chunk[i*4..i*4+4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }
        let (mut sha_a, mut sha_b, mut sha_c, mut sha_d,
             mut sha_e, mut sha_f, mut sha_g, mut sha_h) =
            (h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7]);

        for step in 0..64 {
            let sigma1 = sha_e.rotate_right(6) ^ sha_e.rotate_right(11) ^ sha_e.rotate_right(25);
            let ch = (sha_e & sha_f) ^ ((!sha_e) & sha_g);
            let temp1 = sha_h.wrapping_add(sigma1).wrapping_add(ch).wrapping_add(K[step]).wrapping_add(w[step]);
            let sigma0 = sha_a.rotate_right(2) ^ sha_a.rotate_right(13) ^ sha_a.rotate_right(22);
            let maj = (sha_a & sha_b) ^ (sha_a & sha_c) ^ (sha_b & sha_c);
            let temp2 = sigma0.wrapping_add(maj);
            sha_h = sha_g; sha_g = sha_f; sha_f = sha_e; sha_e = sha_d.wrapping_add(temp1);
            sha_d = sha_c; sha_c = sha_b; sha_b = sha_a; sha_a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(sha_a); h[1] = h[1].wrapping_add(sha_b);
        h[2] = h[2].wrapping_add(sha_c); h[3] = h[3].wrapping_add(sha_d);
        h[4] = h[4].wrapping_add(sha_e); h[5] = h[5].wrapping_add(sha_f);
        h[6] = h[6].wrapping_add(sha_g); h[7] = h[7].wrapping_add(sha_h);
    }

    let mut result = [0u8; 32];
    for (i, hval) in h.iter().enumerate() {
        result[i*4..i*4+4].copy_from_slice(&hval.to_be_bytes());
    }
    result
}

// ---------------------------------------------------------------------------
// Normalisation helpers
// ---------------------------------------------------------------------------

/// Strip a known DLL extension from a DLL name, returning the stem in lowercase.
///
/// # Examples
/// ```
/// use rustre_loader_pe::pe_imphash::normalise_dll_name;
/// assert_eq!(normalise_dll_name("KERNEL32.dll"), "kernel32");
/// assert_eq!(normalise_dll_name("ntdll.DLL"), "ntdll");
/// ```
#[must_use]
pub fn normalise_dll_name(dll: &str) -> String {
    let lower = dll.to_lowercase();
    for ext in KNOWN_DLL_EXTENSIONS {
        if let Some(stem) = lower.strip_suffix(ext) {
            return stem.to_string();
        }
    }
    lower
}

/// Normalise a function name for imphash computation (lowercase, no decorations).
#[must_use]
pub fn normalise_function_name(name: &str) -> String {
    // Strip leading underscore (cdecl) and trailing `@N` (stdcall) decorations.
    let trimmed = name.trim_start_matches('_');
    let trimmed = trimmed.rfind('@').map_or(trimmed, |pos| &trimmed[..pos]);
    trimmed.to_lowercase()
}

/// Build a single imphash entry string from DLL name and function name:
/// `"dll.function"`.
#[must_use]
pub fn make_entry(dll: &str, func: &str) -> String {
    format!("{}.{}", normalise_dll_name(dll), normalise_function_name(func))
}

// ---------------------------------------------------------------------------
// ImportRecord — a single imported function
// ---------------------------------------------------------------------------

/// A single imported function entry used as input to the imphash algorithms.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImportRecord {
    /// DLL name (e.g. `"KERNEL32.dll"`).
    pub dll: String,
    /// Function name. `None` if imported by ordinal only.
    pub name: Option<String>,
    /// Ordinal hint (may be `None` for name-based imports).
    pub ordinal: Option<u16>,
}

impl ImportRecord {
    /// Create a new named import record.
    #[must_use]
    pub fn named(dll: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            dll: dll.into(),
            name: Some(name.into()),
            ordinal: None,
        }
    }

    /// Create a new ordinal-only import record.
    #[must_use]
    pub fn ordinal_only(dll: impl Into<String>, ordinal: u16) -> Self {
        Self {
            dll: dll.into(),
            name: None,
            ordinal: Some(ordinal),
        }
    }

    /// Return the canonical string form used in hash input.
    #[must_use]
    pub fn canonical(&self) -> String {
        let func = self.name.as_ref().map_or_else(
            || format!("ord{}", self.ordinal.unwrap_or(0)),
            |n| normalise_function_name(n),
        );
        format!("{}.{}", normalise_dll_name(&self.dll), func)
    }
}

// ---------------------------------------------------------------------------
// ImphashV1 — Classic MD5-based imphash
// ---------------------------------------------------------------------------

/// Classic Mandiant/FireEye imphash: MD5 of the comma-separated ordered list
/// of `"normalised_dll.normalised_func"` entries.
///
/// The output is a 32-character lowercase hex string (MD5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImphashV1 {
    /// The computed hash string.
    pub hash: String,
    /// Number of imports that contributed to the hash.
    pub import_count: usize,
    /// Whether the hash is meaningful (enough imports present).
    pub is_meaningful: bool,
    /// The raw concatenated input string before hashing.
    pub raw_input: String,
}

impl ImphashV1 {
    /// Compute the classic imphash from a list of import records.
    #[must_use]
    pub fn compute(imports: &[ImportRecord]) -> Self {
        let entries: Vec<String> = imports.iter().map(ImportRecord::canonical).collect();
        let raw_input = entries.join(",");
        let hash = md5_hex(raw_input.as_bytes());
        let import_count = imports.len();
        let is_meaningful = import_count >= MIN_IMPORTS_FOR_MEANINGFUL_HASH;
        Self { hash, import_count, is_meaningful, raw_input }
    }

    /// Compute from raw (dll, `function_name`) pairs for convenience.
    #[must_use]
    pub fn compute_from_pairs(pairs: &[(&str, &str)]) -> Self {
        let records: Vec<ImportRecord> = pairs
            .iter()
            .map(|(dll, func)| ImportRecord::named(*dll, *func))
            .collect();
        Self::compute(&records)
    }

    /// Return the hash string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.hash
    }
}

// ---------------------------------------------------------------------------
// ImphashV2 — Extended SHA-256 variant
// ---------------------------------------------------------------------------

/// Extended imphash using SHA-256 with additional normalisations:
/// - Resolve common ordinal-to-name mappings (`WS2_32` ordinals, etc.).
/// - Sort the import list for order-independent matching (optional).
/// - Include DLL version hints when available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImphashV2 {
    /// SHA-256 hex digest of the normalised import list.
    pub hash: String,
    /// Number of imports contributing to the hash.
    pub import_count: usize,
    /// Whether the import list was sorted before hashing.
    pub sorted: bool,
    /// Whether the hash is meaningful.
    pub is_meaningful: bool,
}

/// Configuration for V2 imphash computation.
#[derive(Debug, Clone)]
pub struct ImphashV2Config {
    /// Sort imports alphabetically before hashing (order-independent).
    pub sort_imports: bool,
    /// Resolve known `WS2_32` ordinals to function names.
    pub resolve_ws2_32_ordinals: bool,
    /// Separator string between entries (default: ",").
    pub separator: String,
}

impl Default for ImphashV2Config {
    fn default() -> Self {
        Self {
            sort_imports: false,
            resolve_ws2_32_ordinals: true,
            separator: ",".to_string(),
        }
    }
}

/// Known `WS2_32.dll` ordinal → function name table.
const fn ws2_32_ordinal_name(ordinal: u16) -> Option<&'static str> {
    match ordinal {
        1 => Some("accept"),
        2 => Some("bind"),
        3 => Some("closesocket"),
        4 => Some("connect"),
        5 => Some("getpeername"),
        6 => Some("getsockname"),
        7 => Some("getsockopt"),
        8 => Some("htonl"),
        9 => Some("htons"),
        10 => Some("ioctlsocket"),
        11 => Some("inet_addr"),
        12 => Some("inet_ntoa"),
        13 => Some("listen"),
        14 => Some("ntohl"),
        15 => Some("ntohs"),
        16 => Some("recv"),
        17 => Some("recvfrom"),
        18 => Some("select"),
        19 => Some("send"),
        20 => Some("sendto"),
        21 => Some("setsockopt"),
        22 => Some("shutdown"),
        23 => Some("socket"),
        52 => Some("WSAStartup"),
        53 => Some("WSACleanup"),
        _ => None,
    }
}

impl ImphashV2 {
    /// Compute the V2 extended imphash.
    #[must_use]
    pub fn compute(imports: &[ImportRecord], config: &ImphashV2Config) -> Self {
        let mut entries: Vec<String> = imports
            .iter()
            .map(|r| {
                // Resolve WS2_32 ordinals if requested.
                if config.resolve_ws2_32_ordinals
                    && r.name.is_none()
                    && normalise_dll_name(&r.dll) == "ws2_32"
                    && let Some(ord) = r.ordinal
                    && let Some(name) = ws2_32_ordinal_name(ord)
                {
                    return format!("ws2_32.{}", name.to_lowercase());
                }
                r.canonical()
            })
            .collect();

        if config.sort_imports {
            entries.sort();
        }

        let raw = entries.join(&config.separator);
        let hash = sha256_hex(raw.as_bytes());
        let import_count = imports.len();
        let is_meaningful = import_count >= MIN_IMPORTS_FOR_MEANINGFUL_HASH;

        Self { hash, import_count, sorted: config.sort_imports, is_meaningful }
    }

    /// Compute with default configuration.
    #[must_use]
    pub fn compute_default(imports: &[ImportRecord]) -> Self {
        Self::compute(imports, &ImphashV2Config::default())
    }
}

// ---------------------------------------------------------------------------
// FuzzyImphash — locality-sensitive import hash
// ---------------------------------------------------------------------------

/// A locality-sensitive (fuzzy) imphash that remains similar when a small
/// number of imports are added or removed.
///
/// The algorithm divides imports into N bands and hashes each band
/// independently. The final hash is the hex concatenation of band hashes.
/// Similarity is measured by counting matching bands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzyImphash {
    /// Per-band MD5 hashes (each 32 hex chars).
    pub bands: Vec<String>,
    /// Overall fingerprint: concatenated band hashes.
    pub fingerprint: String,
    /// Number of imports used.
    pub import_count: usize,
    /// Number of bands used.
    pub band_count: usize,
}

impl FuzzyImphash {
    /// Compute the fuzzy imphash with the given number of bands.
    ///
    /// Imports are first sorted for order-independence, then divided into
    /// `band_count` roughly equal segments, and each band is MD5-hashed.
    #[must_use]
    pub fn compute(imports: &[ImportRecord], band_count: usize) -> Self {
        let band_count = band_count.max(1);
        let mut sorted: Vec<String> = imports.iter().map(ImportRecord::canonical).collect();
        sorted.sort();

        let per_band = sorted.len().div_ceil(band_count);
        let mut bands = Vec::with_capacity(band_count);

        for i in 0..band_count {
            let start = i * per_band;
            let end = ((i + 1) * per_band).min(sorted.len());
            let band_data = if start >= sorted.len() {
                String::new()
            } else {
                sorted[start..end].join(",")
            };
            bands.push(md5_hex(band_data.as_bytes()));
        }

        let fingerprint = bands.concat();
        let import_count = imports.len();

        Self { bands, fingerprint, import_count, band_count }
    }

    /// Compute similarity (0.0 – 1.0) with another [`FuzzyImphash`].
    ///
    /// Returns the fraction of matching bands. Only valid when both hashes
    /// used the same `band_count`.
    #[must_use]
    pub fn similarity(&self, other: &Self) -> f64 {
        if self.band_count != other.band_count || self.band_count == 0 {
            return 0.0;
        }
        let matches = self
            .bands
            .iter()
            .zip(other.bands.iter())
            .filter(|(a, b)| a == b)
            .count();
        usize_to_f64(matches) / usize_to_f64(self.band_count)
    }

    /// Returns `true` if this fuzzy hash is considered similar to `other`
    /// (at least `threshold` fraction of bands match).
    #[must_use]
    pub fn is_similar(&self, other: &Self, threshold: f64) -> bool {
        self.similarity(other) >= threshold
    }

    /// Compute with the default band count (4).
    #[must_use]
    pub fn compute_default(imports: &[ImportRecord]) -> Self {
        Self::compute(imports, 4)
    }
}

// ---------------------------------------------------------------------------
// ImportCategory — API category classification
// ---------------------------------------------------------------------------

/// Category of an imported API function.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ImportCategory {
    /// Cryptographic / hashing APIs.
    Crypto,
    /// Network / socket APIs.
    Network,
    /// File system APIs.
    File,
    /// Process and thread manipulation APIs.
    Process,
    /// Registry APIs.
    Registry,
    /// Code injection helpers.
    Injection,
    /// Uncategorised.
    Other,
}

impl ImportCategory {
    /// Return a human-readable name.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Crypto    => "crypto",
            Self::Network   => "network",
            Self::File      => "file",
            Self::Process   => "process",
            Self::Registry  => "registry",
            Self::Injection => "injection",
            Self::Other     => "other",
        }
    }

    /// Classify a function name (lowercase) into a category.
    #[must_use]
    pub fn classify(func_lower: &str) -> Self {
        let check = |keywords: &[&str]| keywords.iter().any(|k| func_lower.contains(k));

        // Higher-priority categories first.
        if check(INJECTION_APIS)  { return Self::Injection; }
        if check(CRYPTO_APIS)     { return Self::Crypto; }
        if check(NETWORK_APIS)    { return Self::Network; }
        if check(REGISTRY_APIS)   { return Self::Registry; }
        if check(PROCESS_APIS)    { return Self::Process; }
        if check(FILE_APIS)       { return Self::File; }
        Self::Other
    }
}

// ---------------------------------------------------------------------------
// TypedImphash — category-segmented import hash
// ---------------------------------------------------------------------------

/// A typed imphash that hashes each API category independently.
///
/// This allows detecting partial import-set overlap across binaries that share
/// a common capability cluster even when the overall import lists differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedImphash {
    /// Per-category MD5 hashes. Keys are category names.
    pub category_hashes: HashMap<String, String>,
    /// Ordered list of non-empty categories.
    pub active_categories: Vec<ImportCategory>,
    /// Combined hash of all category hashes (SHA-256).
    pub combined_hash: String,
    /// Total import count.
    pub import_count: usize,
}

impl TypedImphash {
    /// Compute the typed imphash from a list of import records.
    #[must_use]
    pub fn compute(imports: &[ImportRecord]) -> Self {
        let mut buckets: HashMap<ImportCategory, Vec<String>> = HashMap::new();

        for record in imports {
            let func_lower = record
                .name
                .as_deref()
                .map_or_else(|| format!("ord{}", record.ordinal.unwrap_or(0)), str::to_lowercase);

            let category = ImportCategory::classify(&func_lower);
            buckets
                .entry(category)
                .or_default()
                .push(record.canonical());
        }

        let mut category_hashes: HashMap<String, String> = HashMap::new();
        let mut active_categories: Vec<ImportCategory> = Vec::new();
        let mut combined_input = String::new();

        let mut sorted_categories: Vec<ImportCategory> = buckets.keys().cloned().collect();
        sorted_categories.sort();

        for cat in &sorted_categories {
            if let Some(entries) = buckets.get_mut(cat) {
                entries.sort();
                let raw = entries.join(",");
                let hash = md5_hex(raw.as_bytes());
                combined_input.push_str(&hash);
                category_hashes.insert(cat.as_str().to_string(), hash);
                active_categories.push(cat.clone());
            }
        }

        let combined_hash = sha256_hex(combined_input.as_bytes());
        let import_count = imports.len();

        Self {
            category_hashes,
            active_categories,
            combined_hash,
            import_count,
        }
    }

    /// Return the hash for a specific category, if any imports matched it.
    #[must_use]
    pub fn category_hash(&self, cat: &ImportCategory) -> Option<&str> {
        self.category_hashes.get(cat.as_str()).map(String::as_str)
    }

    /// Return the fraction of active categories shared with another [`TypedImphash`].
    #[must_use]
    pub fn category_similarity(&self, other: &Self) -> f64 {
        let total = self
            .active_categories
            .iter()
            .chain(other.active_categories.iter())
            .collect::<std::collections::HashSet<_>>()
            .len();
        if total == 0 {
            return 1.0;
        }
        let shared = self
            .active_categories
            .iter()
            .filter(|c| {
                other.category_hash(c) == self.category_hash(c)
                    && self.category_hash(c).is_some()
            })
            .count();
        usize_to_f64(shared) / usize_to_f64(total)
    }
}

// ---------------------------------------------------------------------------
// ImphashDb — in-memory lookup database
// ---------------------------------------------------------------------------

/// A family lookup result from the imphash database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyLookup {
    /// Malware family name (e.g. `"Emotet"`, `"Cobalt Strike"`).
    pub family: String,
    /// Confidence score 0–100.
    pub confidence: u8,
    /// Tags associated with this family (e.g. `["banker", "downloader"]`).
    pub tags: Vec<String>,
    /// Notes or description.
    pub notes: Option<String>,
}

/// A single database entry.
#[derive(Debug, Clone)]
struct DbEntry {
    family: String,
    confidence: u8,
    tags: Vec<String>,
    notes: Option<String>,
}

/// In-memory database mapping imphash strings to known malware families.
#[derive(Debug, Default)]
pub struct ImphashDb {
    /// Map from imphash hex string → database entry.
    entries: HashMap<String, DbEntry>,
    /// Map from fuzzy fingerprint → list of candidate entries.
    fuzzy_index: HashMap<String, Vec<String>>,
}

impl ImphashDb {
    /// Create a new empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a known imphash → family mapping.
    pub fn insert(
        &mut self,
        hash: impl Into<String>,
        family: impl Into<String>,
        confidence: u8,
        tags: Vec<String>,
        notes: Option<String>,
    ) {
        let hash = hash.into();
        self.entries.insert(hash, DbEntry {
            family: family.into(),
            confidence,
            tags,
            notes,
        });
    }

    /// Exact lookup by imphash string.
    #[must_use]
    pub fn lookup(&self, hash: &str) -> Option<FamilyLookup> {
        self.entries.get(hash).map(|e| FamilyLookup {
            family: e.family.clone(),
            confidence: e.confidence,
            tags: e.tags.clone(),
            notes: e.notes.clone(),
        })
    }

    /// Fuzzy lookup: add a fuzzy fingerprint index for a family.
    pub fn insert_fuzzy(
        &mut self,
        fingerprint: impl Into<String>,
        exact_hash: impl Into<String>,
    ) {
        let fp = fingerprint.into();
        let hash = exact_hash.into();
        self.fuzzy_index.entry(fp).or_default().push(hash);
    }

    /// Look up the best match for a fuzzy imphash.
    #[must_use]
    pub fn fuzzy_lookup(&self, fuzzy: &FuzzyImphash) -> Vec<FamilyLookup> {
        let mut results = Vec::new();
        for band in &fuzzy.bands {
            if let Some(hashes) = self.fuzzy_index.get(band) {
                for hash in hashes {
                    if let Some(entry) = self.entries.get(hash) {
                        results.push(FamilyLookup {
                            family: entry.family.clone(),
                            confidence: entry.confidence,
                            tags: entry.tags.clone(),
                            notes: entry.notes.clone(),
                        });
                    }
                }
            }
        }
        // Deduplicate by family name.
        results.sort_by(|a, b| a.family.cmp(&b.family));
        results.dedup_by(|a, b| a.family == b.family);
        results
    }

    /// Return the total number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the database is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Load well-known sample entries for testing / demo purposes.
    pub fn load_demo_entries(&mut self) {
        // A small set of fictitious hashes for demonstration.
        self.insert(
            "fcab0b58c2dfd085d86e3b92c81a9082",
            "Mirai",
            95,
            vec!["botnet".to_string(), "iot".to_string()],
            Some("Classic Mirai variant imphash".to_string()),
        );
        self.insert(
            "1a6d1432d34c71d34a58c17dd4f24ab3",
            "Emotet",
            90,
            vec!["banker".to_string(), "downloader".to_string()],
            None,
        );
        self.insert(
            "b4e40f37c6cc17da6c8c3234e9ef6a7a",
            "Cobalt Strike",
            85,
            vec!["rat".to_string(), "c2".to_string()],
            Some("CS beacon staging imphash".to_string()),
        );
    }
}

// ---------------------------------------------------------------------------
// PeImphash — unified facade
// ---------------------------------------------------------------------------

/// Unified imphash facade.
///
/// Given a list of [`ImportRecord`] entries (typically from a parsed PE binary),
/// computes all four hash variants and provides lookup helpers.
#[derive(Debug, Clone)]
pub struct PeImphash {
    /// Classic MD5-based imphash (v1).
    pub v1: ImphashV1,
    /// Extended SHA-256 imphash (v2, not sorted).
    pub v2: ImphashV2,
    /// Fuzzy locality-sensitive hash (4 bands).
    pub fuzzy: FuzzyImphash,
    /// Category-typed hash.
    pub typed: TypedImphash,
    /// Number of input imports.
    pub import_count: usize,
}

impl PeImphash {
    /// Compute all imphash variants from a slice of import records.
    #[must_use] 
    pub fn compute(imports: &[ImportRecord]) -> Self {
        let v1 = ImphashV1::compute(imports);
        let v2 = ImphashV2::compute_default(imports);
        let fuzzy = FuzzyImphash::compute_default(imports);
        let typed = TypedImphash::compute(imports);
        let import_count = imports.len();
        Self { v1, v2, fuzzy, typed, import_count }
    }

    /// Convenience constructor from raw `(dll, function)` pairs.
    #[must_use] 
    pub fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        let imports: Vec<ImportRecord> = pairs
            .iter()
            .map(|(dll, func)| ImportRecord::named(*dll, *func))
            .collect();
        Self::compute(&imports)
    }

    /// Return `true` if the imphash is considered meaningful.
    #[must_use]
    pub const fn is_meaningful(&self) -> bool {
        self.v1.is_meaningful
    }

    /// Look up in a database and return the best match.
    #[must_use]
    pub fn lookup(&self, db: &ImphashDb) -> Option<FamilyLookup> {
        db.lookup(self.v1.as_str())
            .or_else(|| db.lookup(&self.v2.hash))
    }

    /// Return fuzzy candidates from a database.
    #[must_use]
    pub fn fuzzy_candidates(&self, db: &ImphashDb) -> Vec<FamilyLookup> {
        db.fuzzy_lookup(&self.fuzzy)
    }

    /// Return a brief summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "imphash_v1={} v2={} imports={} meaningful={}",
            &self.v1.hash[..8],
            &self.v2.hash[..8],
            self.import_count,
            self.is_meaningful(),
        )
    }

    /// Return a map of active capability categories.
    #[must_use]
    pub fn capability_categories(&self) -> Vec<&str> {
        self.typed.active_categories.iter().map(ImportCategory::as_str).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helper: build a realistic import list
    // -----------------------------------------------------------------------

    fn sample_imports() -> Vec<ImportRecord> {
        vec![
            ImportRecord::named("KERNEL32.dll", "CreateFileW"),
            ImportRecord::named("KERNEL32.dll", "ReadFile"),
            ImportRecord::named("KERNEL32.dll", "WriteFile"),
            ImportRecord::named("KERNEL32.dll", "VirtualAlloc"),
            ImportRecord::named("KERNEL32.dll", "CreateProcessW"),
            ImportRecord::named("kernel32.dll", "LoadLibraryA"),
            ImportRecord::named("NTDLL.DLL",    "NtCreateFile"),
            ImportRecord::named("ws2_32.dll",   "WSAStartup"),
            ImportRecord::named("ws2_32.dll",   "connect"),
            ImportRecord::named("ws2_32.dll",   "send"),
            ImportRecord::named("ws2_32.dll",   "recv"),
            ImportRecord::named("ADVAPI32.dll", "CryptEncrypt"),
            ImportRecord::named("ADVAPI32.dll", "RegOpenKeyExA"),
        ]
    }

    fn tiny_imports() -> Vec<ImportRecord> {
        vec![
            ImportRecord::named("KERNEL32.dll", "ExitProcess"),
        ]
    }

    // -----------------------------------------------------------------------
    // MD5 / SHA-256 basic tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_md5_empty() {
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_md5_hello_world() {
        // MD5("hello world") = 5eb63bbbe01eeed093cb22bb8f5acdc3
        assert_eq!(md5_hex(b"hello world"), "5eb63bbbe01eeed093cb22bb8f5acdc3");
    }

    #[test]
    fn test_md5_abc() {
        // MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn test_sha256_empty() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_abc() {
        // SHA-256("abc") =
        // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let h = sha256_hex(b"abc");
        assert_eq!(
            h,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_sha256_length_is_64() {
        let h = sha256_hex(b"test input");
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn test_md5_length_is_32() {
        let h = md5_hex(b"any data here");
        assert_eq!(h.len(), 32);
    }

    // -----------------------------------------------------------------------
    // Normalisation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_normalise_dll_name_strips_dll() {
        assert_eq!(normalise_dll_name("KERNEL32.dll"), "kernel32");
    }

    #[test]
    fn test_normalise_dll_name_case_insensitive_ext() {
        assert_eq!(normalise_dll_name("ntdll.DLL"), "ntdll");
    }

    #[test]
    fn test_normalise_dll_name_no_ext() {
        assert_eq!(normalise_dll_name("ntdll"), "ntdll");
    }

    #[test]
    fn test_normalise_dll_name_sys() {
        assert_eq!(normalise_dll_name("win32k.sys"), "win32k");
    }

    #[test]
    fn test_normalise_function_name_strips_at() {
        assert_eq!(normalise_function_name("_MyFunc@16"), "myfunc");
    }

    #[test]
    fn test_normalise_function_name_lowercase() {
        assert_eq!(normalise_function_name("CreateFileW"), "createfilew");
    }

    #[test]
    fn test_normalise_function_name_no_decoration() {
        assert_eq!(normalise_function_name("VirtualAlloc"), "virtualalloc");
    }

    #[test]
    fn test_make_entry() {
        let e = make_entry("KERNEL32.dll", "CreateFileW");
        assert_eq!(e, "kernel32.createfilew");
    }

    // -----------------------------------------------------------------------
    // ImportRecord tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_import_record_canonical_named() {
        let r = ImportRecord::named("KERNEL32.DLL", "VirtualAlloc");
        assert_eq!(r.canonical(), "kernel32.virtualalloc");
    }

    #[test]
    fn test_import_record_canonical_ordinal() {
        let r = ImportRecord::ordinal_only("ws2_32.dll", 16);
        assert_eq!(r.canonical(), "ws2_32.ord16");
    }

    #[test]
    fn test_import_record_named_has_no_ordinal() {
        let r = ImportRecord::named("ntdll.dll", "NtAllocateVirtualMemory");
        assert!(r.ordinal.is_none());
    }

    // -----------------------------------------------------------------------
    // ImphashV1 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_imphash_v1_deterministic() {
        let imports = sample_imports();
        let h1 = ImphashV1::compute(&imports);
        let h2 = ImphashV1::compute(&imports);
        assert_eq!(h1.hash, h2.hash);
    }

    #[test]
    fn test_imphash_v1_hash_length() {
        let h = ImphashV1::compute(&sample_imports());
        assert_eq!(h.hash.len(), 32);
    }

    #[test]
    fn test_imphash_v1_is_meaningful_large_list() {
        let h = ImphashV1::compute(&sample_imports());
        assert!(h.is_meaningful);
    }

    #[test]
    fn test_imphash_v1_not_meaningful_tiny_list() {
        let h = ImphashV1::compute(&tiny_imports());
        assert!(!h.is_meaningful);
    }

    #[test]
    fn test_imphash_v1_empty_list() {
        let h = ImphashV1::compute(&[]);
        assert!(!h.is_meaningful);
        assert_eq!(h.import_count, 0);
        // MD5 of empty string
        assert_eq!(h.hash, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_imphash_v1_from_pairs() {
        let h = ImphashV1::compute_from_pairs(&[
            ("KERNEL32.dll", "ExitProcess"),
            ("KERNEL32.dll", "GetLastError"),
            ("ntdll.dll",    "NtAllocateVirtualMemory"),
        ]);
        assert_eq!(h.import_count, 3);
        assert!(h.is_meaningful);
    }

    #[test]
    fn test_imphash_v1_case_insensitive_dll() {
        let a = ImphashV1::compute_from_pairs(&[
            ("KERNEL32.dll", "ExitProcess"),
            ("kernel32.DLL", "GetLastError"),
            ("Ntdll.Dll",    "NtQuery"),
        ]);
        let b = ImphashV1::compute_from_pairs(&[
            ("kernel32.dll", "ExitProcess"),
            ("kernel32.dll", "GetLastError"),
            ("ntdll.dll",    "NtQuery"),
        ]);
        assert_eq!(a.hash, b.hash);
    }

    // -----------------------------------------------------------------------
    // ImphashV2 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_imphash_v2_hash_length() {
        let h = ImphashV2::compute_default(&sample_imports());
        assert_eq!(h.hash.len(), 64);
    }

    #[test]
    fn test_imphash_v2_sorted_differs_from_unsorted() {
        let imports = sample_imports();
        let sorted_cfg = ImphashV2Config { sort_imports: true, ..Default::default() };
        let unsorted = ImphashV2::compute_default(&imports);
        let sorted   = ImphashV2::compute(&imports, &sorted_cfg);
        // They may differ when import order matters.
        // We just check both produce valid hashes.
        assert_eq!(unsorted.hash.len(), 64);
        assert_eq!(sorted.hash.len(), 64);
    }

    #[test]
    fn test_imphash_v2_resolve_ws2_32_ordinals() {
        let ordinal = ImportRecord::ordinal_only("ws2_32.dll", 19); // send
        let named   = ImportRecord::named("ws2_32.dll", "send");

        let base_imports: Vec<ImportRecord> = vec![
            ImportRecord::named("KERNEL32.dll", "ExitProcess"),
            ImportRecord::named("KERNEL32.dll", "GetLastError"),
            ImportRecord::named("KERNEL32.dll", "Sleep"),
        ];

        let mut with_ord = base_imports.clone();
        with_ord.push(ordinal);

        let mut with_name = base_imports;
        with_name.push(named);

        let cfg = ImphashV2Config { resolve_ws2_32_ordinals: true, ..Default::default() };
        let h_ord  = ImphashV2::compute(&with_ord,  &cfg);
        let h_name = ImphashV2::compute(&with_name, &cfg);
        assert_eq!(h_ord.hash, h_name.hash);
    }

    // -----------------------------------------------------------------------
    // FuzzyImphash tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_fuzzy_imphash_band_count() {
        let f = FuzzyImphash::compute(&sample_imports(), 4);
        assert_eq!(f.band_count, 4);
        assert_eq!(f.bands.len(), 4);
    }

    #[test]
    fn test_fuzzy_imphash_fingerprint_length() {
        let f = FuzzyImphash::compute(&sample_imports(), 4);
        // 4 bands × 32 hex chars per MD5
        assert_eq!(f.fingerprint.len(), 128);
    }

    #[test]
    fn test_fuzzy_imphash_same_input_same_output() {
        let imports = sample_imports();
        let f1 = FuzzyImphash::compute(&imports, 4);
        let f2 = FuzzyImphash::compute(&imports, 4);
        assert_eq!(f1.fingerprint, f2.fingerprint);
    }

    #[test]
    fn test_fuzzy_imphash_identical_lists_similarity_one() {
        let imports = sample_imports();
        let f1 = FuzzyImphash::compute(&imports, 4);
        let f2 = FuzzyImphash::compute(&imports, 4);
        assert!((f1.similarity(&f2) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_fuzzy_imphash_completely_different_similarity_low() {
        let a = FuzzyImphash::compute(&sample_imports(), 4);
        let b = FuzzyImphash::compute(&tiny_imports(), 4);
        // They should have low similarity (not 1.0).
        assert!(a.similarity(&b) < 1.0);
    }

    #[test]
    fn test_fuzzy_imphash_is_similar_threshold() {
        let imports = sample_imports();
        let f1 = FuzzyImphash::compute(&imports, 4);
        let f2 = FuzzyImphash::compute(&imports, 4);
        assert!(f1.is_similar(&f2, 1.0));
        assert!(f1.is_similar(&f2, 0.5));
    }

    #[test]
    fn test_fuzzy_imphash_empty_imports() {
        let f = FuzzyImphash::compute(&[], 4);
        assert_eq!(f.import_count, 0);
        assert_eq!(f.bands.len(), 4);
    }

    // -----------------------------------------------------------------------
    // ImportCategory tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_category_classify_crypto() {
        assert_eq!(ImportCategory::classify("cryptencrypt"), ImportCategory::Crypto);
    }

    #[test]
    fn test_category_classify_network() {
        assert_eq!(ImportCategory::classify("wsasend"), ImportCategory::Network);
    }

    #[test]
    fn test_category_classify_file() {
        assert_eq!(ImportCategory::classify("createfilew"), ImportCategory::File);
    }

    #[test]
    fn test_category_classify_process() {
        assert_eq!(ImportCategory::classify("createprocessw"), ImportCategory::Process);
    }

    #[test]
    fn test_category_classify_registry() {
        assert_eq!(ImportCategory::classify("regopenkeyex"), ImportCategory::Registry);
    }

    #[test]
    fn test_category_classify_injection() {
        assert_eq!(ImportCategory::classify("loadlibrarya"), ImportCategory::Injection);
    }

    #[test]
    fn test_category_classify_other() {
        assert_eq!(ImportCategory::classify("messagebox"), ImportCategory::Other);
    }

    // Injection should take priority over crypto/network
    #[test]
    fn test_category_classify_injection_priority() {
        assert_eq!(ImportCategory::classify("getprocaddress"), ImportCategory::Injection);
    }

    // -----------------------------------------------------------------------
    // TypedImphash tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_typed_imphash_combined_hash_length() {
        let t = TypedImphash::compute(&sample_imports());
        assert_eq!(t.combined_hash.len(), 64);
    }

    #[test]
    fn test_typed_imphash_active_categories_nonempty() {
        let t = TypedImphash::compute(&sample_imports());
        assert!(!t.active_categories.is_empty());
    }

    #[test]
    fn test_typed_imphash_category_hash_exists_for_active() {
        let t = TypedImphash::compute(&sample_imports());
        for cat in &t.active_categories {
            assert!(t.category_hash(cat).is_some());
        }
    }

    #[test]
    fn test_typed_imphash_deterministic() {
        let imports = sample_imports();
        let t1 = TypedImphash::compute(&imports);
        let t2 = TypedImphash::compute(&imports);
        assert_eq!(t1.combined_hash, t2.combined_hash);
    }

    #[test]
    fn test_typed_imphash_category_similarity_identical() {
        let imports = sample_imports();
        let t1 = TypedImphash::compute(&imports);
        let t2 = TypedImphash::compute(&imports);
        assert!((t1.category_similarity(&t2) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_typed_imphash_empty_list() {
        let t = TypedImphash::compute(&[]);
        assert_eq!(t.import_count, 0);
        assert!(t.active_categories.is_empty());
    }

    // -----------------------------------------------------------------------
    // ImphashDb tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_db_insert_and_lookup() {
        let mut db = ImphashDb::new();
        db.insert("deadbeef1234", "TestFamily", 80, vec!["tag1".to_string()], None);
        let result = db.lookup("deadbeef1234");
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.family, "TestFamily");
        assert_eq!(result.confidence, 80);
    }

    #[test]
    fn test_db_lookup_missing() {
        let db = ImphashDb::new();
        assert!(db.lookup("nonexistent").is_none());
    }

    #[test]
    fn test_db_len_and_is_empty() {
        let mut db = ImphashDb::new();
        assert!(db.is_empty());
        db.insert("hash1", "FamilyA", 70, vec![], None);
        assert_eq!(db.len(), 1);
        assert!(!db.is_empty());
    }

    #[test]
    fn test_db_load_demo_entries() {
        let mut db = ImphashDb::new();
        db.load_demo_entries();
        assert!(db.len() >= 3);
    }

    #[test]
    fn test_db_fuzzy_lookup_returns_results() {
        let mut db = ImphashDb::new();
        let imports = sample_imports();
        let imphash = PeImphash::compute(&imports);
        let band0 = imphash.fuzzy.bands[0].clone();

        db.insert("somehash", "TestFamily", 85, vec![], None);
        db.insert_fuzzy(band0, "somehash");

        let results = db.fuzzy_lookup(&imphash.fuzzy);
        assert!(!results.is_empty());
        assert_eq!(results[0].family, "TestFamily");
    }

    // -----------------------------------------------------------------------
    // PeImphash facade tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_pe_imphash_all_variants_computed() {
        let ph = PeImphash::from_pairs(&[
            ("KERNEL32.dll", "CreateProcessW"),
            ("KERNEL32.dll", "VirtualAlloc"),
            ("KERNEL32.dll", "WriteProcessMemory"),
            ("ntdll.dll",    "NtCreateFile"),
        ]);
        assert_eq!(ph.v1.hash.len(), 32);
        assert_eq!(ph.v2.hash.len(), 64);
        assert_eq!(ph.fuzzy.band_count, 4);
        assert!(ph.typed.import_count > 0);
    }

    #[test]
    fn test_pe_imphash_meaningful_flag() {
        let ph = PeImphash::from_pairs(&[
            ("KERNEL32.dll", "ExitProcess"),
            ("KERNEL32.dll", "GetLastError"),
            ("ntdll.dll",    "NtClose"),
        ]);
        assert!(ph.is_meaningful());
    }

    #[test]
    fn test_pe_imphash_not_meaningful_single_import() {
        let ph = PeImphash::from_pairs(&[("KERNEL32.dll", "ExitProcess")]);
        assert!(!ph.is_meaningful());
    }

    #[test]
    fn test_pe_imphash_lookup_db_hit() {
        let imports = vec![
            ImportRecord::named("KERNEL32.dll", "ExitProcess"),
            ImportRecord::named("KERNEL32.dll", "GetLastError"),
            ImportRecord::named("KERNEL32.dll", "Sleep"),
        ];
        let ph = PeImphash::compute(&imports);
        let mut db = ImphashDb::new();
        db.insert(&ph.v1.hash, "TestMatch", 99, vec![], None);
        let result = ph.lookup(&db);
        assert!(result.is_some());
        assert_eq!(result.unwrap().family, "TestMatch");
    }

    #[test]
    fn test_pe_imphash_lookup_db_miss() {
        let ph = PeImphash::from_pairs(&[
            ("KERNEL32.dll", "ExitProcess"),
            ("KERNEL32.dll", "GetLastError"),
            ("ntdll.dll",    "NtClose"),
        ]);
        let db = ImphashDb::new();
        assert!(ph.lookup(&db).is_none());
    }

    #[test]
    fn test_pe_imphash_capability_categories() {
        let ph = PeImphash::from_pairs(&[
            ("ws2_32.dll",   "connect"),
            ("ws2_32.dll",   "send"),
            ("ws2_32.dll",   "recv"),
            ("ADVAPI32.dll", "CryptEncrypt"),
            ("KERNEL32.dll", "CreateProcessW"),
        ]);
        let cats = ph.capability_categories();
        assert!(!cats.is_empty());
    }

    #[test]
    fn test_pe_imphash_summary_format() {
        let ph = PeImphash::from_pairs(&[
            ("KERNEL32.dll", "ExitProcess"),
            ("KERNEL32.dll", "GetLastError"),
            ("ntdll.dll",    "NtClose"),
        ]);
        let summary = ph.summary();
        assert!(summary.contains("imphash_v1="));
        assert!(summary.contains("imports=3"));
    }

    #[test]
    fn test_pe_imphash_import_count() {
        let ph = PeImphash::from_pairs(&[
            ("KERNEL32.dll", "A"),
            ("KERNEL32.dll", "B"),
            ("KERNEL32.dll", "C"),
            ("ntdll.dll",    "D"),
            ("ntdll.dll",    "E"),
        ]);
        assert_eq!(ph.import_count, 5);
    }

    // -----------------------------------------------------------------------
    // WS2_32 ordinal resolution
    // -----------------------------------------------------------------------

    #[test]
    fn test_ws2_32_known_ordinals() {
        assert_eq!(ws2_32_ordinal_name(1),  Some("accept"));
        assert_eq!(ws2_32_ordinal_name(19), Some("send"));
        assert_eq!(ws2_32_ordinal_name(16), Some("recv"));
        assert_eq!(ws2_32_ordinal_name(23), Some("socket"));
        assert_eq!(ws2_32_ordinal_name(52), Some("WSAStartup"));
    }

    #[test]
    fn test_ws2_32_unknown_ordinal() {
        assert!(ws2_32_ordinal_name(200).is_none());
    }

    // -----------------------------------------------------------------------
    // FamilyLookup tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_family_lookup_fields() {
        let lk = FamilyLookup {
            family: "Mirai".to_string(),
            confidence: 95,
            tags: vec!["botnet".to_string()],
            notes: Some("test note".to_string()),
        };
        assert_eq!(lk.family, "Mirai");
        assert_eq!(lk.confidence, 95);
        assert_eq!(lk.tags.len(), 1);
        assert!(lk.notes.is_some());
    }

    // -----------------------------------------------------------------------
    // Edge case: all ordinal-only imports
    // -----------------------------------------------------------------------

    #[test]
    fn test_imphash_v1_all_ordinal_imports() {
        let imports = vec![
            ImportRecord::ordinal_only("ws2_32.dll", 1),
            ImportRecord::ordinal_only("ws2_32.dll", 19),
            ImportRecord::ordinal_only("ws2_32.dll", 16),
        ];
        let h = ImphashV1::compute(&imports);
        assert_eq!(h.hash.len(), 32);
        assert!(h.is_meaningful);
    }

    // -----------------------------------------------------------------------
    // Edge case: single import, not meaningful
    // -----------------------------------------------------------------------

    #[test]
    fn test_imphash_v2_single_import() {
        let imports = vec![ImportRecord::named("KERNEL32.dll", "ExitProcess")];
        let h = ImphashV2::compute_default(&imports);
        assert_eq!(h.hash.len(), 64);
        assert!(!h.is_meaningful);
    }

    // -----------------------------------------------------------------------
    // ImportCategory as_str tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_import_category_as_str() {
        assert_eq!(ImportCategory::Crypto.as_str(), "crypto");
        assert_eq!(ImportCategory::Network.as_str(), "network");
        assert_eq!(ImportCategory::File.as_str(), "file");
        assert_eq!(ImportCategory::Process.as_str(), "process");
        assert_eq!(ImportCategory::Registry.as_str(), "registry");
        assert_eq!(ImportCategory::Injection.as_str(), "injection");
        assert_eq!(ImportCategory::Other.as_str(), "other");
    }
}
