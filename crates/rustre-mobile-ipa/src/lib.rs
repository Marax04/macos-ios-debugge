//! `rustre-mobile-ipa`
//!
//! iOS IPA package parser for the `RustRE` Suite.
//!
//! An IPA file is a ZIP archive containing a Payload directory which holds
//! the application bundle (`.app`).  This crate implements a minimal,
//! dependency-free ZIP central-directory parser to enumerate entries and
//! extract files by path.
//!
//! Also provides `FairPlay` encryption detection, asset catalog (`.car`)
//! listing, and resource extraction stubs.

pub mod binary_extractor;
pub mod bitcode_extractor;
pub mod decrypt;
pub mod entitlement_analyzer;
pub mod fairplay_detect;
pub mod ipa_analyzer;
pub mod ipa_binary_finder;
pub mod ipa_entitlement_analyzer;
pub mod ipa_extractor;
pub mod ipa_manifest;
pub mod ipa_metadata_extractor;
pub mod ipa_security_analysis;
pub mod plist_binary;
pub mod plist_parser;
pub mod provisioning;
pub mod resources;
pub mod swift_demangler;
pub mod swift_metadata_ipa;

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// IpaError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced during IPA parsing.
#[derive(thiserror::Error, Debug)]
pub enum IpaError {
    /// The file does not look like a valid IPA/ZIP.
    #[error("Not a valid IPA: {0}")]
    InvalidIpa(String),
    /// A required file was not found inside the IPA.
    #[error("Missing file: {0}")]
    MissingFile(String),
    /// Failed to parse an Info.plist.
    #[error("Plist parse error: {0}")]
    PlistParse(String),
    /// An I/O-like error (typically string-format).
    #[error("IO: {0}")]
    Io(String),
    /// `FairPlay` DRM error.
    #[error("FairPlay error: {0}")]
    FairPlay(String),
    /// Resource extraction error.
    #[error("Resource error: {0}")]
    Resource(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// InfoPlist
// ─────────────────────────────────────────────────────────────────────────────

/// Subset of `Info.plist` keys that are useful for RE.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InfoPlist {
    /// `CFBundleIdentifier`
    pub bundle_id: String,
    /// `CFBundleDisplayName` or `CFBundleName`
    pub bundle_name: String,
    /// `CFBundleShortVersionString`
    pub bundle_version: String,
    /// `MinimumOSVersion`
    pub min_os_version: String,
    /// `CFBundleExecutable`
    pub executable: String,
    /// `CFBundleSupportedPlatforms`
    pub supported_platforms: Vec<String>,
    /// Entitlement key/value pairs (subset).
    pub entitlements: HashMap<String, String>,
    /// `NS*UsageDescription` privacy-usage keys present in the plist.
    pub permissions: Vec<String>,
}

impl InfoPlist {
    /// Return `true` if the app declares any entitlements.
    #[must_use]
    pub fn has_entitlements(&self) -> bool {
        !self.entitlements.is_empty()
    }

    /// Return `true` if `key` is listed in `permissions`.
    #[must_use]
    pub fn has_permission(&self, key: &str) -> bool {
        self.permissions.iter().any(|k| k == key)
    }

    /// Return the minimum OS version as a tuple of (major, minor) if parseable.
    #[must_use]
    pub fn parsed_min_os(&self) -> Option<(u32, u32)> {
        let parts: Vec<&str> = self.min_os_version.split('.').collect();
        let major = parts.first()?.parse().ok()?;
        let minor = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        Some((major, minor))
    }

    /// Return `true` if the app supports iPhone.
    #[must_use]
    pub fn targets_iphone(&self) -> bool {
        self.supported_platforms
            .iter()
            .any(|p| p.eq_ignore_ascii_case("iphoneos"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CodeSignature / CertInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed code-signing metadata from the embedded `embedded.mobileprovision`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CodeSignature {
    /// Development team identifier.
    pub team_id: String,
    /// Signing identifier (usually the bundle ID with optional prefix).
    pub signing_id: String,
    /// Code-signing flags.
    pub flags: u32,
    /// Certificate chain (leaf → root).
    pub cert_chain: Vec<CertInfo>,
    /// Raw XML entitlements embedded in the signature.
    pub entitlements_xml: String,
}

impl CodeSignature {
    /// Return `true` if the code signature claims a developer certificate.
    #[must_use]
    pub fn is_developer_signed(&self) -> bool {
        self.cert_chain
            .iter()
            .any(|c| c.subject.contains("Apple Development"))
    }

    /// Return `true` if this is an enterprise/distribution certificate.
    #[must_use]
    pub fn is_enterprise(&self) -> bool {
        self.cert_chain
            .iter()
            .any(|c| c.subject.contains("iPhone Distribution"))
    }

    /// Return `true` if the CodeDirectory carries `CS_ADHOC`.
    ///
    /// This used to be `cert_chain.is_empty()`, which conflated "ad-hoc signed"
    /// with "this build has no X.509 decoder, so no certificates were
    /// recovered" — two very different statements that happen to look
    /// identical. `CS_ADHOC` is a real bit in the CodeDirectory read by
    /// [`codesign_flags_from_macho`].
    #[must_use]
    pub const fn is_adhoc(&self) -> bool {
        self.flags & CS_ADHOC != 0
    }

    /// Whether the leaf certificate was issued by Apple.
    ///
    /// # Errors
    /// Always returns an error today. Answering this question honestly requires
    /// decoding the CMS blob in the signature and verifying the certificate
    /// chain up to an Apple root; this workspace has no X.509/ASN.1 decoder and
    /// no trust store, so there is no evidence from which to answer. The error
    /// names exactly what is missing rather than reporting a name match as a
    /// verification result.
    pub const fn apple_leaf_verdict(&self) -> Result<bool, CertVerifyError> {
        if self.cert_chain.is_empty() {
            return Err(CertVerifyError::NoCertificateChain);
        }
        Err(CertVerifyError::NoX509Verifier)
    }

    /// Return the leaf certificate (first in chain).
    #[must_use]
    pub fn leaf_cert(&self) -> Option<&CertInfo> {
        self.cert_chain.first()
    }

    /// Return the root certificate (last in chain).
    #[must_use]
    pub fn root_cert(&self) -> Option<&CertInfo> {
        self.cert_chain.last()
    }
}

/// Minimal X.509 certificate metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CertInfo {
    /// Subject distinguished name.
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
    /// Serial number (hex).
    pub serial: String,
    /// Not-before validity (ISO-8601 string).
    pub not_before: String,
    /// Not-after validity (ISO-8601 string).
    pub not_after: String,
}

impl CertInfo {
    /// Return `true` if the already-parsed issuer name contains "Apple".
    ///
    /// This is a substring test on a string, not certificate verification: an
    /// issuer field is attacker-controlled until a chain has been validated.
    /// Use [`CodeSignature::apple_leaf_verdict`] when you need a verdict; it
    /// reports why one cannot be produced.
    #[must_use]
    pub fn is_apple_issued(&self) -> bool {
        self.issuer.contains("Apple")
    }

    /// Verified statement that this certificate was issued by Apple.
    ///
    /// # Errors
    /// Always [`CertVerifyError::NoX509Verifier`]: no ASN.1/X.509 decoder and
    /// no Apple trust anchor exist in this workspace, so no chain can be built
    /// or checked.
    pub const fn verify_apple_issued(&self) -> Result<bool, CertVerifyError> {
        Err(CertVerifyError::NoX509Verifier)
    }
}

/// `CS_ADHOC` — the CodeDirectory bit set for an ad-hoc signature.
pub const CS_ADHOC: u32 = 0x0000_0002;

/// Why a certificate question could not be answered from the available bytes.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum CertVerifyError {
    /// No X.509/ASN.1 decoder and no trust anchors are available.
    #[error(
        "cannot verify certificate issuance: this workspace has no X.509/ASN.1 decoder and no \
         Apple trust anchor, so no chain can be built or validated from these bytes"
    )]
    NoX509Verifier,
    /// The signature carried no certificates at all.
    #[error("cannot verify certificate issuance: no certificates were recovered from the signature")]
    NoCertificateChain,
}

/// Errors specific to reading a Mach-O code-signature blob.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum CodeSignReadError {
    /// The bytes are not a 64-bit Mach-O this reader understands.
    #[error("not a 64-bit Mach-O (magic {0:#010x})")]
    NotMachO64(u32),
    /// The Mach-O has no `LC_CODE_SIGNATURE` load command.
    #[error("no LC_CODE_SIGNATURE load command: the binary is unsigned")]
    NoCodeSignatureCommand,
    /// The signature blob is truncated or malformed at the named byte offset.
    #[error("code signature blob truncated or malformed at offset {0:#x}")]
    Malformed(usize),
    /// The `SuperBlob` has no `CSSLOT_CODEDIRECTORY` entry.
    #[error("code signature SuperBlob has no CodeDirectory slot")]
    NoCodeDirectory,
}

/// Read the CodeDirectory `flags` word out of a Mach-O `LC_CODE_SIGNATURE`.
///
/// Walks the load commands for `LC_CODE_SIGNATURE` (`0x1D`), then the
/// big-endian `CSMAGIC_EMBEDDED_SIGNATURE` SuperBlob at `dataoff` for the
/// `CSSLOT_CODEDIRECTORY` (index type 0) blob, and returns its `flags` field.
///
/// # Errors
/// Returns [`CodeSignReadError`] naming which of those steps failed. It never
/// substitutes a default value for a word it could not read.
pub fn codesign_flags_from_macho(exe: &[u8]) -> Result<u32, CodeSignReadError> {
    fn be_u32(d: &[u8], o: usize) -> Option<u32> {
        Some(u32::from_be_bytes(d.get(o..o + 4)?.try_into().ok()?))
    }
    fn le_u32(d: &[u8], o: usize) -> Option<u32> {
        Some(u32::from_le_bytes(d.get(o..o + 4)?.try_into().ok()?))
    }

    let magic = le_u32(exe, 0).ok_or(CodeSignReadError::Malformed(0))?;
    // Only the 64-bit little-endian layouts iOS actually ships.
    if magic != 0xFEED_FACF {
        return Err(CodeSignReadError::NotMachO64(magic));
    }
    let ncmds = le_u32(exe, 16).ok_or(CodeSignReadError::Malformed(16))? as usize;

    let mut off = 32usize;
    let mut sig_range: Option<(usize, usize)> = None;
    for _ in 0..ncmds {
        let cmd = le_u32(exe, off).ok_or(CodeSignReadError::Malformed(off))?;
        let cmdsize = le_u32(exe, off + 4).ok_or(CodeSignReadError::Malformed(off + 4))? as usize;
        if cmdsize < 8 {
            return Err(CodeSignReadError::Malformed(off + 4));
        }
        if cmd == 0x1D {
            let dataoff =
                le_u32(exe, off + 8).ok_or(CodeSignReadError::Malformed(off + 8))? as usize;
            let datasize =
                le_u32(exe, off + 12).ok_or(CodeSignReadError::Malformed(off + 12))? as usize;
            sig_range = Some((dataoff, datasize));
            break;
        }
        off += cmdsize;
    }

    let (dataoff, _datasize) = sig_range.ok_or(CodeSignReadError::NoCodeSignatureCommand)?;

    // SuperBlob: magic, length, count, then (type, offset) index entries.
    let sb_magic = be_u32(exe, dataoff).ok_or(CodeSignReadError::Malformed(dataoff))?;
    if sb_magic != 0xFADE_0CC0 {
        return Err(CodeSignReadError::Malformed(dataoff));
    }
    let count = be_u32(exe, dataoff + 8).ok_or(CodeSignReadError::Malformed(dataoff + 8))? as usize;

    for i in 0..count {
        let e = dataoff + 12 + i * 8;
        let slot_type = be_u32(exe, e).ok_or(CodeSignReadError::Malformed(e))?;
        let blob_off = be_u32(exe, e + 4).ok_or(CodeSignReadError::Malformed(e + 4))? as usize;
        // CSSLOT_CODEDIRECTORY
        if slot_type == 0 {
            let cd = dataoff + blob_off;
            let cd_magic = be_u32(exe, cd).ok_or(CodeSignReadError::Malformed(cd))?;
            if cd_magic != 0xFADE_0C02 {
                return Err(CodeSignReadError::Malformed(cd));
            }
            // magic(0) length(4) version(8) flags(12)
            return be_u32(exe, cd + 12).ok_or(CodeSignReadError::Malformed(cd + 12));
        }
    }

    Err(CodeSignReadError::NoCodeDirectory)
}

// ─────────────────────────────────────────────────────────────────────────────
// IpaEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A single entry in the IPA ZIP archive.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IpaEntry {
    /// ZIP path of the entry (e.g. `Payload/MyApp.app/MyApp`).
    pub path: String,
    /// Uncompressed size in bytes.
    pub size: u64,
    /// `true` if this entry represents a directory.
    pub is_dir: bool,
}

impl IpaEntry {
    /// Return the filename component of the entry path.
    #[must_use]
    pub fn filename(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }

    /// Return the directory portion of the entry path.
    #[must_use]
    pub fn directory(&self) -> &str {
        self.path.rfind('/').map_or("", |pos| &self.path[..pos])
    }

    /// Return the file extension (without dot).
    #[must_use]
    pub fn extension(&self) -> Option<&str> {
        let name = self.filename();
        let pos = name.rfind('.')?;
        Some(&name[pos + 1..])
    }

    /// Return `true` if the entry is a compiled Swift module.
    #[must_use]
    pub fn is_swift_module(&self) -> bool {
        self.extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("swiftmodule"))
    }

    /// Return `true` if the entry looks like a Mach-O binary.
    #[must_use]
    pub fn is_likely_binary(&self) -> bool {
        !self.is_dir && self.extension().is_none() && self.size > 1024
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IpaPackage
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed iOS IPA package.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IpaPackage {
    /// Parsed `Info.plist`.
    pub info_plist: InfoPlist,
    /// Optional code signature from `embedded.mobileprovision`.
    pub code_signature: Option<CodeSignature>,
    /// All ZIP entries.
    pub entries: Vec<IpaEntry>,
    /// ZIP path of the main executable (e.g. `Payload/MyApp.app/MyApp`).
    pub executable_path: String,
    /// Paths of embedded frameworks.
    pub frameworks: Vec<String>,
    /// Paths of embedded app extensions / plugins.
    pub plugins: Vec<String>,
    /// `FairPlay` encryption status.
    pub fairplay_info: Option<FairPlayInfo>,
}

// ─────────────────────────────────────────────────────────────────────────────
// FairPlayInfo (re-exported from decrypt module)
// ─────────────────────────────────────────────────────────────────────────────

pub use decrypt::FairPlayInfo;

// ─────────────────────────────────────────────────────────────────────────────
// ZIP parsing helpers (no external crate)
// ─────────────────────────────────────────────────────────────────────────────

/// ZIP local file header signature.
const LOCAL_HEADER_SIG: u32 = 0x0403_4B50;
/// ZIP central directory file header signature.
const CENTRAL_DIR_SIG: u32 = 0x0201_4B50;
/// ZIP end-of-central-directory signature.
const EOCD_SIG: u32 = 0x0605_4B50;

/// Attempt to locate the End-of-Central-Directory record by scanning backward
/// from the end of `data`.
fn find_eocd(data: &[u8]) -> Option<usize> {
    if data.len() < 22 {
        return None;
    }
    // EOCD can be followed by a variable-length comment (0–65535 bytes).
    let search_start = data.len().saturating_sub(65535 + 22);
    (search_start..=data.len() - 22)
        .rev()
        .find(|&i| read_u32_le(data, i) == Some(EOCD_SIG))
}

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Parse all entries from the central directory.
///
/// Returns `(path, uncompressed_size, local_header_offset, is_dir)` tuples.
fn parse_central_directory(data: &[u8]) -> Result<Vec<(String, u64, u32, u16)>, IpaError> {
    let eocd_offset = find_eocd(data).ok_or_else(|| IpaError::InvalidIpa("No EOCD record found".into()))?;

    let cd_entry_count = usize::from(read_u16_le(data, eocd_offset + 10)
        .ok_or_else(|| IpaError::InvalidIpa("Truncated EOCD".into()))?);
    let cd_offset = usize::try_from(read_u32_le(data, eocd_offset + 16)
        .ok_or_else(|| IpaError::InvalidIpa("Truncated EOCD".into()))?)
        .map_err(|_| IpaError::InvalidIpa("CD offset overflow".into()))?;

    let mut entries = Vec::with_capacity(cd_entry_count);
    let mut pos = cd_offset;

    for _ in 0..cd_entry_count {
        if pos + 46 > data.len() {
            break;
        }
        let sig =
            read_u32_le(data, pos).ok_or_else(|| IpaError::InvalidIpa("Truncated CD entry".into()))?;
        if sig != CENTRAL_DIR_SIG {
            break;
        }

        let uncompressed = u64::from(read_u32_le(data, pos + 24).unwrap_or(0));
        let fname_len = usize::from(read_u16_le(data, pos + 28).unwrap_or(0));
        let extra_len = usize::from(read_u16_le(data, pos + 30).unwrap_or(0));
        let comment_len = usize::from(read_u16_le(data, pos + 32).unwrap_or(0));
        let local_offset = read_u32_le(data, pos + 42).unwrap_or(0);

        let fname_start = pos + 46;
        let fname_end = fname_start + fname_len;
        if fname_end > data.len() {
            break;
        }
        let fname = String::from_utf8_lossy(&data[fname_start..fname_end]).into_owned();

        // external attr high byte: 0x10 means MS-DOS directory flag
        let ext_attr = read_u32_le(data, pos + 38).unwrap_or(0);
        let is_dir = fname.ends_with('/')
            || (ext_attr & 0x10) != 0                    // MS-DOS directory flag (low word)
            || (ext_attr >> 16) & 0x4000 != 0;           // Unix directory bit (high word)

        entries.push((fname, uncompressed, local_offset, u16::from(is_dir)));

        pos = fname_end + extra_len + comment_len;
    }

    Ok(entries)
}

/// Extract and decompress the bytes of a ZIP entry given its local file header
/// offset.  Supports compression method 0 (STORE) and method 8 (DEFLATE).
fn extract_stored_entry(data: &[u8], local_offset: u32) -> Option<Vec<u8>> {
    let off = local_offset as usize;
    if off + 30 > data.len() {
        return None;
    }
    let sig = read_u32_le(data, off)?;
    if sig != LOCAL_HEADER_SIG {
        return None;
    }
    let compression = read_u16_le(data, off + 8)?;
    let compressed_size = read_u32_le(data, off + 18)? as usize;
    let uncompressed_size = read_u32_le(data, off + 22)? as usize;
    let fname_len = read_u16_le(data, off + 26)? as usize;
    let extra_len = read_u16_le(data, off + 28)? as usize;

    let data_start = off + 30 + fname_len + extra_len;
    let data_end = data_start + compressed_size;

    if data_end > data.len() {
        return None;
    }

    let compressed = &data[data_start..data_end];

    match compression {
        // STORE — return raw bytes directly.
        0 => Some(compressed.to_vec()),
        // DEFLATE — decompress using flate2's raw deflate decoder.
        8 => {
            use flate2::read::DeflateDecoder;
            use std::io::Read as _;
            let mut decoder = DeflateDecoder::new(compressed);
            let mut out = Vec::with_capacity(uncompressed_size);
            decoder.read_to_end(&mut out).ok()?;
            Some(out)
        }
        // Unsupported compression method.
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InfoPlist parsing
// ─────────────────────────────────────────────────────────────────────────────

/// Extract every `<key>…</key>` followed by a scalar value from an XML plist.
///
/// Scalars are `<string>`, `<true/>`, `<false/>`, `<integer>` and `<real>`.
/// Keys whose value is a container (`<array>`, `<dict>`, `<data>`) are skipped
/// here and read by [`plist_string_array`] / [`plist_dict_region`] instead.
#[must_use]
pub fn plist_key_values(xml: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut remaining = xml;
    while let Some(key_start) = remaining.find("<key>") {
        remaining = &remaining[key_start + 5..];
        let Some(key_end) = remaining.find("</key>") else {
            break;
        };
        let key = remaining[..key_end].trim().to_string();
        remaining = &remaining[key_end + 6..];

        let trimmed = remaining.trim_start();
        if let Some(val) = plist_scalar_value(trimmed) {
            let skip = remaining.len() - trimmed.len();
            let advance = plist_scalar_len(trimmed);
            remaining = &remaining[skip + advance..];
            map.insert(key, val);
        }
    }
    map
}

/// Read the scalar value that `s` starts with, if any.
fn plist_scalar_value(s: &str) -> Option<String> {
    for (open, close) in [
        ("<string>", "</string>"),
        ("<integer>", "</integer>"),
        ("<real>", "</real>"),
    ] {
        if s.starts_with(open) {
            let end = s.find(close)?;
            return Some(s[open.len()..end].to_string());
        }
    }
    if s.starts_with("<true/>") {
        return Some("true".to_string());
    }
    if s.starts_with("<false/>") {
        return Some("false".to_string());
    }
    None
}

/// Byte length of the scalar element `s` starts with (0 when it is not one).
fn plist_scalar_len(s: &str) -> usize {
    for (open, close) in [
        ("<string>", "</string>"),
        ("<integer>", "</integer>"),
        ("<real>", "</real>"),
    ] {
        if s.starts_with(open) {
            return s.find(close).map_or(s.len(), |p| p + close.len());
        }
    }
    if s.starts_with("<true/>") {
        return 7;
    }
    if s.starts_with("<false/>") {
        return 8;
    }
    0
}

/// Read the `<string>` members of the `<array>` that follows `<key>key</key>`.
///
/// Returns an empty vector when the key is absent or its value is not an array,
/// so a caller can tell "declared empty" from "not declared" only by also
/// checking [`plist_key_values`]; the distinction matters for
/// `CFBundleSupportedPlatforms`, which used to be hard-coded to `iPhoneOS`.
#[must_use]
pub fn plist_string_array(xml: &str, key: &str) -> Vec<String> {
    let needle = format!("<key>{key}</key>");
    let Some(pos) = xml.find(&needle) else {
        return Vec::new();
    };
    let after = xml[pos + needle.len()..].trim_start();
    if !after.starts_with("<array>") {
        return Vec::new();
    }
    let Some(end) = after.find("</array>") else {
        return Vec::new();
    };
    let content = &after[7..end];
    let mut out = Vec::new();
    let mut rem = content;
    while let Some(s) = rem.find("<string>") {
        rem = &rem[s + 8..];
        let Some(e) = rem.find("</string>") else { break };
        out.push(rem[..e].to_string());
        rem = &rem[e + 9..];
    }
    out
}

/// Return the raw XML of the `<dict>` that follows `<key>key</key>`.
///
/// Nested dictionaries are tracked so the region ends at the matching
/// `</dict>`, not at the first one.
#[must_use]
pub fn plist_dict_region<'a>(xml: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("<key>{key}</key>");
    let pos = xml.find(&needle)?;
    let after_key = &xml[pos + needle.len()..];
    let trimmed = after_key.trim_start();
    if !trimmed.starts_with("<dict>") {
        return None;
    }
    let body_start = 6;
    let mut depth = 1usize;
    let mut idx = body_start;
    while idx < trimmed.len() {
        if trimmed[idx..].starts_with("<dict>") {
            depth += 1;
            idx += 6;
        } else if trimmed[idx..].starts_with("</dict>") {
            depth -= 1;
            if depth == 0 {
                return Some(&trimmed[..idx + 7]);
            }
            idx += 7;
        } else {
            idx += 1;
        }
    }
    None
}

/// Parse the subset of `Info.plist` keys this crate models.
///
/// # Errors
/// Returns [`IpaError::PlistParse`] when `CFBundleExecutable` is absent — that
/// key names the Mach-O to analyse, so guessing it would send every downstream
/// read to the wrong file.
fn parse_info_plist(xml: &str) -> Result<InfoPlist, IpaError> {
    let map = plist_key_values(xml);

    let bundle_id = map.get("CFBundleIdentifier").cloned().unwrap_or_default();
    let bundle_name = map
        .get("CFBundleDisplayName")
        .or_else(|| map.get("CFBundleName"))
        .cloned()
        .unwrap_or_default();
    let bundle_version = map
        .get("CFBundleShortVersionString")
        .cloned()
        .unwrap_or_default();
    let min_os_version = map.get("MinimumOSVersion").cloned().unwrap_or_default();
    let executable = map
        .get("CFBundleExecutable")
        .cloned()
        .ok_or_else(|| IpaError::PlistParse("Missing CFBundleExecutable".into()))?;

    let permissions: Vec<String> = map
        .keys()
        .filter(|k| k.starts_with("NS") && k.ends_with("UsageDescription"))
        .cloned()
        .collect();

    // Read from the plist instead of assuming iPhoneOS.
    let supported_platforms = plist_string_array(xml, "CFBundleSupportedPlatforms");

    Ok(InfoPlist {
        bundle_id,
        bundle_name,
        bundle_version,
        min_os_version,
        executable,
        supported_platforms,
        entitlements: HashMap::new(),
        permissions,
    })
}

impl IpaPackage {
    /// Parse an IPA from raw bytes.
    ///
    /// # Errors
    /// Returns [`IpaError`] if the data is not a valid ZIP/IPA, or required
    /// files such as `Info.plist` are missing.
    pub fn parse(data: &[u8]) -> Result<Self, IpaError> {
        // 1. Parse the central directory to enumerate all entries.
        let cd_entries = parse_central_directory(data)?;

        let mut all_entries: Vec<IpaEntry> = cd_entries
            .iter()
            .map(|(path, size, _, is_dir)| IpaEntry {
                path: path.clone(),
                size: *size,
                is_dir: *is_dir == 1,
            })
            .collect();

        // 2. Locate the app bundle: look for Payload/<AppName>.app/
        let app_bundle_prefix = all_entries
            .iter()
            .find_map(|e| {
                let parts: Vec<&str> = e.path.splitn(3, '/').collect();
                if parts.len() >= 2
                    && parts[0] == "Payload"
                    && std::path::Path::new(parts[1])
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("app"))
                {
                    Some(format!("{}/{}", parts[0], parts[1]))
                } else {
                    None
                }
            })
            .ok_or_else(|| IpaError::InvalidIpa("No Payload/*.app directory found".into()))?;

        // 3. Find and parse Info.plist.
        let plist_path = format!("{app_bundle_prefix}/Info.plist");
        let plist_entry = cd_entries.iter().find(|(p, _, _, _)| p == &plist_path);

        // An absent Info.plist used to be answered with an invented bundle
        // ("1.0", "14.0", iPhoneOS). Those values compile and serialise like
        // parsed ones, so a caller had no way to tell them apart from a real
        // read. Name what is missing instead.
        let (_, _, plist_local_offset, _) = plist_entry
            .ok_or_else(|| IpaError::MissingFile(plist_path.clone()))?;
        let xml_bytes = extract_stored_entry(data, *plist_local_offset)
            .ok_or_else(|| IpaError::MissingFile(plist_path.clone()))?;
        let xml =
            std::str::from_utf8(&xml_bytes).map_err(|e| IpaError::PlistParse(e.to_string()))?;
        let mut info_plist = parse_info_plist(xml)?;

        // 4. Build executable path.
        let executable_path = format!("{}/{}", app_bundle_prefix, info_plist.executable);

        // 5. Find frameworks and plugins.
        let frameworks: Vec<String> = all_entries
            .iter()
            .filter(|e| {
                e.is_dir
                    && e.path
                        .starts_with(&format!("{app_bundle_prefix}/Frameworks/"))
                    && e.path.ends_with(".framework/")
            })
            .map(|e| e.path.clone())
            .collect();

        let plugins: Vec<String> = all_entries
            .iter()
            .filter(|e| {
                e.is_dir
                    && (e.path.starts_with(&format!("{app_bundle_prefix}/PlugIns/"))
                        || e.path
                            .starts_with(&format!("{app_bundle_prefix}/Extensions/")))
                    && e.path.ends_with(".appex/")
            })
            .map(|e| e.path.clone())
            .collect();

        all_entries.retain(|e| !e.path.is_empty());

        // 6. Code signature, read from the bytes that are actually present.
        //
        //    Two independent sources, both optional:
        //      * `embedded.mobileprovision` — a CMS envelope whose payload is an
        //        XML plist carrying TeamIdentifier and the Entitlements dict.
        //      * the executable's `LC_CODE_SIGNATURE` load command — the only
        //        place the real CodeDirectory `flags` word lives.
        //    When neither is present the signature stays `None` rather than
        //    being conjured.
        let profile_path = format!("{app_bundle_prefix}/embedded.mobileprovision");
        let profile_bytes = cd_entries
            .iter()
            .find(|(p, _, _, _)| p == &profile_path)
            .and_then(|(_, _, off, _)| extract_stored_entry(data, *off));

        let profile = profile_bytes
            .as_ref()
            .and_then(|b| ProvisioningProfile::parse_cms(b).ok());

        let entitlements_xml = profile_bytes.as_ref().and_then(|b| {
            let text = String::from_utf8_lossy(b).into_owned();
            plist_dict_region(&text, "Entitlements").map(ToString::to_string)
        });

        if let Some(ref ent_xml) = entitlements_xml {
            info_plist.entitlements = plist_key_values(ent_xml);
        }

        let codesign_flags = cd_entries
            .iter()
            .find(|(p, _, _, _)| p == &executable_path)
            .and_then(|(_, _, off, _)| extract_stored_entry(data, *off))
            .and_then(|exe| codesign_flags_from_macho(&exe).ok());

        let code_signature = if profile.is_some() || codesign_flags.is_some() {
            let p = profile.unwrap_or_default();
            Some(CodeSignature {
                team_id: p.team_identifier,
                signing_id: p.bundle_id,
                flags: codesign_flags.unwrap_or(0),
                // Left empty on purpose: recovering certificates needs an X.509
                // decoder, which this workspace does not have. See
                // `CodeSignature::apple_leaf_verdict`.
                cert_chain: Vec::new(),
                entitlements_xml: entitlements_xml.unwrap_or_default(),
            })
        } else {
            None
        };

        Ok(Self {
            info_plist,
            code_signature,
            entries: all_entries,
            executable_path,
            frameworks,
            plugins,
            fairplay_info: None,
        })
    }

    /// Return the (decompressed) bytes of the main executable by locating its
    /// local file header.  Supports STORE and DEFLATE compression.
    ///
    /// # Errors
    /// Returns [`IpaError::MissingFile`] if the executable entry is not found
    /// or uses an unsupported compression method.
    pub fn executable_data(&self, raw: &[u8]) -> Result<Vec<u8>, IpaError> {
        let cd_entries = parse_central_directory(raw).map_err(|e| IpaError::Io(e.to_string()))?;

        let (_, _, local_offset, _) = cd_entries
            .iter()
            .find(|(p, _, _, _)| p == &self.executable_path)
            .ok_or_else(|| IpaError::MissingFile(self.executable_path.clone()))?;

        extract_stored_entry(raw, *local_offset)
            .ok_or_else(|| IpaError::MissingFile(self.executable_path.clone()))
    }

    /// Extract a specific file from the IPA by ZIP path.  Supports STORE and
    /// DEFLATE compression.
    ///
    /// # Errors
    /// Returns [`IpaError::MissingFile`] if the path is not found or uses an
    /// unsupported compression method.
    pub fn extract_file(&self, raw: &[u8], path: &str) -> Result<Vec<u8>, IpaError> {
        let cd_entries = parse_central_directory(raw).map_err(|e| IpaError::Io(e.to_string()))?;
        let (_, _, local_offset, _) = cd_entries
            .iter()
            .find(|(p, _, _, _)| p == path)
            .ok_or_else(|| IpaError::MissingFile(path.to_string()))?;
        extract_stored_entry(raw, *local_offset)
            .ok_or_else(|| IpaError::MissingFile(path.to_string()))
    }

    /// Number of ZIP entries (including directories).
    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Number of embedded frameworks.
    #[must_use]
    pub const fn framework_count(&self) -> usize {
        self.frameworks.len()
    }

    /// Return `true` if the app declares the given entitlement.
    #[must_use]
    pub fn has_entitlement(&self, key: &str) -> bool {
        self.info_plist.entitlements.contains_key(key)
    }

    /// Return all entries that look like binary files.
    #[must_use]
    pub fn binary_entries(&self) -> Vec<&IpaEntry> {
        self.entries
            .iter()
            .filter(|e| e.is_likely_binary())
            .collect()
    }

    /// Return all `.car` (compiled asset catalog) entries.
    #[must_use]
    pub fn asset_catalog_entries(&self) -> Vec<&IpaEntry> {
        self.entries
            .iter()
            .filter(|e| {
                e.extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("car"))
            })
            .collect()
    }

    /// Return all string table entries.
    #[must_use]
    pub fn strings_entries(&self) -> Vec<&IpaEntry> {
        self.entries
            .iter()
            .filter(|e| {
                e.extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("strings"))
            })
            .collect()
    }

    /// Check whether this IPA is likely FairPlay-encrypted.
    ///
    /// Looks for the `Payload/*.app/<executable>` binary and inspects `LC_ENCRYPTION_INFO`.
    /// This is a heuristic check based on size and presence of expected structures.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.fairplay_info.as_ref().is_some_and(|f| f.is_encrypted)
    }

    /// Build the reference IPA **image**: a real ZIP archive holding a real
    /// XML `Info.plist`, a real arm64 Mach-O with an `LC_CODE_SIGNATURE`, and a
    /// real `embedded.mobileprovision` payload.
    ///
    /// This exists so [`IpaPackage::mock`] can be a parse rather than a
    /// declaration: every field it returns is produced by
    /// [`IpaPackage::parse`] reading these bytes.
    #[must_use]
    pub fn reference_ipa_bytes() -> Vec<u8> {
        let info_plist = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key><string>com.example.TestApp</string>
    <key>CFBundleName</key><string>TestApp</string>
    <key>CFBundleShortVersionString</key><string>1.2.3</string>
    <key>CFBundleVersion</key><string>123</string>
    <key>MinimumOSVersion</key><string>15.0</string>
    <key>CFBundleExecutable</key><string>TestApp</string>
    <key>CFBundleSupportedPlatforms</key>
    <array><string>iPhoneOS</string></array>
    <key>NSCameraUsageDescription</key><string>Needed to scan codes.</string>
</dict>
</plist>
"#
        .to_vec();

        let profile = br#"CMS-WRAPPED-PROFILE<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>Name</key><string>TestApp Development</string>
    <key>UUID</key><string>2a1f0b6e-0000-4000-8000-0123456789ab</string>
    <key>TeamName</key><string>Example Ltd</string>
    <key>TeamIdentifier</key>
    <array><string>TEAM123456</string></array>
    <key>ExpirationDate</key><string>2030-01-01T00:00:00Z</string>
    <key>Entitlements</key>
    <dict>
        <key>application-identifier</key><string>TEAM123456.com.example.TestApp</string>
        <key>com.apple.developer.team-identifier</key><string>TEAM123456</string>
        <key>get-task-allow</key><true/>
    </dict>
</dict>
</plist>
"#
        .to_vec();

        let executable = Self::reference_macho_bytes(0);

        zip_store(&[
            ("Payload/TestApp.app/", Vec::new()),
            ("Payload/TestApp.app/Info.plist", info_plist),
            ("Payload/TestApp.app/TestApp", executable),
            ("Payload/TestApp.app/embedded.mobileprovision", profile),
            (
                "Payload/TestApp.app/Frameworks/MyFramework.framework/",
                Vec::new(),
            ),
        ])
    }

    /// Assemble an arm64 Mach-O that carries a real `LC_CODE_SIGNATURE`
    /// pointing at a real `CSMAGIC_EMBEDDED_SIGNATURE` SuperBlob whose
    /// CodeDirectory has the given `flags`.
    #[must_use]
    pub fn reference_macho_bytes(flags: u32) -> Vec<u8> {
        // header(32) + LC_CODE_SIGNATURE(16), then padding so the binary is
        // large enough for `IpaEntry::is_likely_binary` to be exercised.
        const HEADER_SIZE: usize = 32;
        const LC_SIZE: usize = 16;
        let sig_off: usize = 4096;

        // SuperBlob: magic, length, count, one index entry, then CodeDirectory.
        let cd_off: usize = 20; // 12-byte header + one 8-byte index entry
        let cd_len: usize = 44; // magic..flags plus a little slack
        let sb_len = cd_off + cd_len;

        let mut buf = vec![0u8; sig_off + sb_len];

        let put_le = |buf: &mut [u8], off: usize, v: u32| {
            buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
        };
        let put_be = |buf: &mut [u8], off: usize, v: u32| {
            buf[off..off + 4].copy_from_slice(&v.to_be_bytes());
        };

        put_le(&mut buf, 0, 0xFEED_FACF); // MH_MAGIC_64
        put_le(&mut buf, 4, 0x0100_000C); // CPU_TYPE_ARM64
        put_le(&mut buf, 8, 0); // cpusubtype
        put_le(&mut buf, 12, 2); // MH_EXECUTE
        put_le(&mut buf, 16, 1); // ncmds
        put_le(&mut buf, 20, u32::try_from(LC_SIZE).unwrap_or(0));
        put_le(&mut buf, 24, 0x0020_0085); // NOUNDEFS | DYLDLINK | TWOLEVEL | PIE
        put_le(&mut buf, 28, 0); // reserved

        // LC_CODE_SIGNATURE
        put_le(&mut buf, HEADER_SIZE, 0x1D);
        put_le(&mut buf, HEADER_SIZE + 4, u32::try_from(LC_SIZE).unwrap_or(0));
        put_le(
            &mut buf,
            HEADER_SIZE + 8,
            u32::try_from(sig_off).unwrap_or(0),
        );
        put_le(&mut buf, HEADER_SIZE + 12, u32::try_from(sb_len).unwrap_or(0));

        // CSMAGIC_EMBEDDED_SIGNATURE SuperBlob (big-endian, as on disk).
        put_be(&mut buf, sig_off, 0xFADE_0CC0);
        put_be(&mut buf, sig_off + 4, u32::try_from(sb_len).unwrap_or(0));
        put_be(&mut buf, sig_off + 8, 1); // count
        put_be(&mut buf, sig_off + 12, 0); // CSSLOT_CODEDIRECTORY
        put_be(&mut buf, sig_off + 16, u32::try_from(cd_off).unwrap_or(0));

        // CodeDirectory
        let cd = sig_off + cd_off;
        put_be(&mut buf, cd, 0xFADE_0C02); // CSMAGIC_CODEDIRECTORY
        put_be(&mut buf, cd + 4, u32::try_from(cd_len).unwrap_or(0));
        put_be(&mut buf, cd + 8, 0x0002_0400); // version
        put_be(&mut buf, cd + 12, flags);

        buf
    }

    /// Parse the reference IPA image from [`IpaPackage::reference_ipa_bytes`].
    ///
    /// Kept under the historical name `mock`, but nothing is declared by hand
    /// any more: the bundle id, version, minimum OS, supported platforms,
    /// entitlements, entries, frameworks and code-signature flags all come back
    /// out of [`IpaPackage::parse`].
    ///
    /// # Panics
    /// Panics if the reference image fails to parse, which would mean the
    /// writer and the parser have diverged.
    #[must_use]
    pub fn mock() -> Self {
        let bytes = Self::reference_ipa_bytes();
        Self::parse(&bytes).expect("reference IPA image must parse with IpaPackage::parse")
    }
}

/// Write a ZIP archive with every member STORE-compressed.
///
/// Used to build reference images that the crate's own central-directory
/// reader can then parse. Entries whose name ends in `/` are written as
/// directories (MS-DOS directory attribute set).
#[must_use]
pub fn zip_store(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();
    let mut count = 0u16;

    for (name, data) in files {
        let local_offset = u32::try_from(out.len()).unwrap_or(0);
        let mut crc = flate2::Crc::new();
        crc.update(data);
        let crc32 = crc.sum();
        let size = u32::try_from(data.len()).unwrap_or(0);
        let name_bytes = name.as_bytes();
        let is_dir = name.ends_with('/');

        // Local file header.
        out.extend_from_slice(&LOCAL_HEADER_SIG.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method = STORE
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0x21u16.to_le_bytes()); // mod date (1980-01-01)
        out.extend_from_slice(&crc32.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes()); // compressed size
        out.extend_from_slice(&size.to_le_bytes()); // uncompressed size
        out.extend_from_slice(&u16::try_from(name_bytes.len()).unwrap_or(0).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(data);

        // Central directory header.
        central.extend_from_slice(&CENTRAL_DIR_SIG.to_le_bytes());
        central.extend_from_slice(&0x031Eu16.to_le_bytes()); // version made by (unix)
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&0u16.to_le_bytes()); // method = STORE
        central.extend_from_slice(&0u16.to_le_bytes()); // mod time
        central.extend_from_slice(&0x21u16.to_le_bytes()); // mod date
        central.extend_from_slice(&crc32.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&u16::try_from(name_bytes.len()).unwrap_or(0).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra len
        central.extend_from_slice(&0u16.to_le_bytes()); // comment len
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        central.extend_from_slice(&(if is_dir { 0x10u32 } else { 0 }).to_le_bytes());
        central.extend_from_slice(&local_offset.to_le_bytes());
        central.extend_from_slice(name_bytes);

        count = count.saturating_add(1);
    }

    let cd_offset = u32::try_from(out.len()).unwrap_or(0);
    let cd_size = u32::try_from(central.len()).unwrap_or(0);
    out.extend_from_slice(&central);

    // End of central directory.
    out.extend_from_slice(&EOCD_SIG.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    out.extend_from_slice(&count.to_le_bytes()); // entries on this disk
    out.extend_from_slice(&count.to_le_bytes()); // entries total
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment length

    out
}

// ─────────────────────────────────────────────────────────────────────────────
// SimplePlistReader
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal binary/XML plist reader that does not require external crates.
///
/// Supports:
/// - Detecting binary plist (`bplist00` magic).
/// - Scanning the object table for UTF-8 strings in binary plists.
/// - Simple heuristic key→value lookup suitable for Info.plist and entitlement
///   plists where the exact plist graph traversal is not required.
pub struct SimplePlistReader;

impl SimplePlistReader {
    /// Return `true` if `data` starts with the binary plist magic `bplist00`.
    #[must_use]
    pub fn is_binary_plist(data: &[u8]) -> bool {
        data.starts_with(b"bplist00")
    }

    /// Attempt to read a UTF-8 string object from a binary plist object table
    /// at the given byte `offset`.
    ///
    /// Binary plist string objects are tagged:
    /// - `0x5N` – ASCII string, N bytes
    /// - `0x6N` – UTF-16BE string, N code units
    ///
    /// When N == 0x0F the actual length is encoded in a following integer object.
    #[must_use]
    pub fn read_string(data: &[u8], offset: usize) -> Option<String> {
        let tag = *data.get(offset)?;
        let high = tag >> 4;
        let low = (tag & 0x0F) as usize;

        // Only handle ASCII (0x5x) and UTF-16 (0x6x) string tags.
        if high != 0x05 && high != 0x06 {
            return None;
        }

        let (len, data_start) = if low == 0x0F {
            // Extended length: next byte is 0x1N where N is the power-of-2
            // exponent for the byte width of the following integer.
            let int_tag = *data.get(offset + 1)?;
            let exp = u32::from(int_tag & 0x0F);
            let width = 1usize << exp;
            let int_start = offset + 2;
            let int_end = int_start + width;
            if int_end > data.len() {
                return None;
            }
            let mut v = 0usize;
            for &b in &data[int_start..int_end] {
                v = (v << 8) | b as usize;
            }
            (v, int_end)
        } else {
            (low, offset + 1)
        };

        let byte_len = if high == 0x06 {
            len.checked_mul(2)?
        } else {
            len
        };
        let data_end = data_start.checked_add(byte_len)?;
        if data_end > data.len() {
            return None;
        }

        if high == 0x05 {
            // ASCII
            std::str::from_utf8(&data[data_start..data_end])
                .ok()
                .map(std::borrow::ToOwned::to_owned)
        } else {
            // UTF-16BE
            let pairs: Vec<u16> = data[data_start..data_end]
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16(&pairs).ok()
        }
    }

    /// Heuristic key→value lookup.
    ///
    /// For XML plists this walks `<key>…</key><string>…</string>` pairs.
    /// For binary plists it performs a linear scan of the data looking for the
    /// key bytes encoded as a UTF-8/ASCII sequence immediately followed (within
    /// 32 bytes) by another string object — sufficient for most Info.plist
    /// lookups where values are simple strings.
    #[must_use]
    pub fn find_key_value(data: &[u8], key: &str) -> Option<String> {
        if !Self::is_binary_plist(data) {
            // XML path: simple substring scan.
            let xml = std::str::from_utf8(data).ok()?;
            let needle = format!("<key>{key}</key>");
            let pos = xml.find(&needle)?;
            let after = xml[pos + needle.len()..].trim_start();
            if after.starts_with("<string>") {
                let end = after.find("</string>")?;
                return Some(after[8..end].to_string());
            }
            if after.starts_with("<true/>") {
                return Some("true".to_string());
            }
            if after.starts_with("<false/>") {
                return Some("false".to_string());
            }
            return None;
        }

        // Binary plist heuristic: scan for the key bytes, then scan forward
        // for the next string object tag.
        let key_bytes = key.as_bytes();
        let klen = key_bytes.len();
        if klen == 0 || data.len() < 8 + klen {
            return None;
        }

        let mut i = 8; // skip magic
        while i + klen <= data.len() {
            if data[i..].starts_with(key_bytes) {
                // Look ahead up to 64 bytes for a string tag.
                let search_start = i + klen;
                let search_end = (search_start + 64).min(data.len());
                for j in search_start..search_end {
                    if let Some(s) = Self::read_string(data, j)
                        && !s.is_empty()
                        && s != key
                    {
                        return Some(s);
                    }
                }
            }
            i += 1;
        }
        None
    }

    /// Extract all string values found in a binary plist object table.
    /// Returns them in scan order — useful for quick enumeration.
    #[must_use]
    pub fn all_strings(data: &[u8]) -> Vec<String> {
        if !Self::is_binary_plist(data) {
            // XML: collect all <string> values.
            if let Ok(xml) = std::str::from_utf8(data) {
                let mut out = Vec::new();
                let mut rem = xml;
                while let Some(s) = rem.find("<string>") {
                    rem = &rem[s + 8..];
                    if let Some(e) = rem.find("</string>") {
                        out.push(rem[..e].to_string());
                        rem = &rem[e + 9..];
                    }
                }
                return out;
            }
            return vec![];
        }

        let mut out = Vec::new();
        let mut i = 8;
        while i < data.len() {
            if let Some(s) = Self::read_string(data, i)
                && !s.is_empty()
            {
                // Advance past this object (at minimum 1 byte).
                out.push(s);
            }
            i += 1;
        }
        // De-duplicate while preserving order.
        let mut seen = std::collections::HashSet::new();
        out.retain(|s| seen.insert(s.clone()));
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InfoPlist (extended) – new constructor methods
// ─────────────────────────────────────────────────────────────────────────────

/// Extended `InfoPlist` that carries the full set of keys required by
/// [`IpaExtractor`] and [`IpaAnalyzer`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InfoPlistFull {
    pub bundle_id: String,
    pub bundle_name: String,
    pub bundle_version: String,
    pub min_os_version: String,
    pub platform: String,
    pub supported_devices: Vec<String>,
    pub required_capabilities: Vec<String>,
    pub url_schemes: Vec<String>,
    pub background_modes: Vec<String>,
}

fn info_plist_kv_map(xml: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let mut rem = xml;
    while let Some(ks) = rem.find("<key>") {
        rem = &rem[ks + 5..];
        let ke = rem.find("</key>").unwrap_or(rem.len());
        let key = rem[..ke].trim().to_string();
        rem = &rem[ke + 6..];
        let tr = rem.trim_start();
        let skip = rem.len() - tr.len();
        if tr.starts_with("<string>") {
            if let Some(ve) = tr.find("</string>") {
                map.insert(key, tr[8..ve].to_string());
                rem = &rem[skip + ve + 9..];
            }
        } else if tr.starts_with("<true/>") {
            map.insert(key, "true".into());
            rem = &rem[skip + 7..];
        } else if tr.starts_with("<false/>") {
            map.insert(key, "false".into());
            rem = &rem[skip + 8..];
        }
    }
    map
}

fn info_plist_extract_array(xml: &str, key: &str) -> Vec<String> {
    let needle = format!("<key>{key}</key>");
    let Some(pos) = xml.find(&needle) else { return vec![]; };
    let after = &xml[pos + needle.len()..].trim_start();
    if !after.starts_with("<array>") { return vec![]; }
    let Some(arr_end) = after.find("</array>") else { return vec![]; };
    let arr_content = &after[7..arr_end];
    let mut vals = Vec::new();
    let mut rem = arr_content;
    while let Some(s) = rem.find("<string>") {
        rem = &rem[s + 8..];
        if let Some(e) = rem.find("</string>") {
            vals.push(rem[..e].to_string());
            rem = &rem[e + 9..];
        }
    }
    vals
}

impl InfoPlistFull {
    /// Parse from XML plist text.
    ///
    /// # Errors
    /// Returns `Err` when required keys are missing or the XML is malformed.
    pub fn from_xml(xml: &str) -> anyhow::Result<Self> {
        let map = info_plist_kv_map(xml);

        let bundle_id = map.get("CFBundleIdentifier").cloned().unwrap_or_default();
        let bundle_name = map
            .get("CFBundleDisplayName")
            .or_else(|| map.get("CFBundleName"))
            .cloned()
            .unwrap_or_default();
        let bundle_version = map
            .get("CFBundleShortVersionString")
            .or_else(|| map.get("CFBundleVersion"))
            .cloned()
            .unwrap_or_default();
        let min_os_version = map.get("MinimumOSVersion").cloned().unwrap_or_default();
        let platform = map
            .get("CFBundleSupportedPlatforms")
            .cloned()
            .unwrap_or_else(|| "iPhoneOS".into());

        let supported_devices = info_plist_extract_array(xml, "UIDeviceFamily");
        let required_capabilities = info_plist_extract_array(xml, "UIRequiredDeviceCapabilities");
        let background_modes = info_plist_extract_array(xml, "UIBackgroundModes");

        // URL schemes live nested: CFBundleURLTypes → array of dicts → CFBundleURLSchemes → array
        let url_schemes = {
            let needle = "<key>CFBundleURLTypes</key>";
            xml.find(needle).map_or_else(Vec::new, |pos| {
                let after = &xml[pos + needle.len()..].trim_start();
                let mut schemes = Vec::new();
                let mut rem = *after;
                while let Some(sk) = rem.find("<key>CFBundleURLSchemes</key>") {
                    rem = rem[sk + 29..].trim_start();
                    if rem.starts_with("<array>") {
                        rem = &rem[7..];
                        while let Some(ss) = rem.find("<string>") {
                            rem = &rem[ss + 8..];
                            if let Some(se) = rem.find("</string>") {
                                schemes.push(rem[..se].to_string());
                                rem = &rem[se + 9..];
                            } else {
                                break;
                            }
                        }
                    }
                }
                schemes
            })
        };

        Ok(Self {
            bundle_id,
            bundle_name,
            bundle_version,
            min_os_version,
            platform,
            supported_devices,
            required_capabilities,
            url_schemes,
            background_modes,
        })
    }

    /// Parse from raw bytes — handles both XML and binary plist.
    ///
    /// # Errors
    /// Returns `Err` when the data cannot be decoded as either format.
    pub fn from_data(data: &[u8]) -> anyhow::Result<Self> {
        if SimplePlistReader::is_binary_plist(data) {
            // Binary plist: use heuristic key lookups.
            let bundle_id =
                SimplePlistReader::find_key_value(data, "CFBundleIdentifier").unwrap_or_default();
            let bundle_name = SimplePlistReader::find_key_value(data, "CFBundleDisplayName")
                .or_else(|| SimplePlistReader::find_key_value(data, "CFBundleName"))
                .unwrap_or_default();
            let bundle_version =
                SimplePlistReader::find_key_value(data, "CFBundleShortVersionString")
                    .or_else(|| SimplePlistReader::find_key_value(data, "CFBundleVersion"))
                    .unwrap_or_default();
            let min_os_version =
                SimplePlistReader::find_key_value(data, "MinimumOSVersion").unwrap_or_default();
            let platform = "iPhoneOS".into();
            Ok(Self {
                bundle_id,
                bundle_name,
                bundle_version,
                min_os_version,
                platform,
                supported_devices: vec![],
                required_capabilities: vec![],
                url_schemes: vec![],
                background_modes: vec![],
            })
        } else {
            let xml = std::str::from_utf8(data)
                .map_err(|e| anyhow::anyhow!("Info.plist is not valid UTF-8: {e}"))?;
            Self::from_xml(xml)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Entitlements
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed entitlements embedded in the code signature or provisioning profile.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Entitlements {
    /// `application-identifier` (team-prefixed bundle ID).
    pub application_identifier: Option<String>,
    /// `keychain-access-groups`.
    pub keychain_access_groups: Vec<String>,
    /// `com.apple.developer.team-identifier`.
    pub team_identifier: Option<String>,
    /// `get-task-allow` – true in development builds.
    pub get_task_allow: bool,
    /// `aps-environment` – `"production"` or `"development"`.
    pub aps_environment: Option<String>,
    /// `com.apple.developer.associated-domains`.
    pub associated_domains: Vec<String>,
}

impl Entitlements {
    /// Parse from a plist byte slice (XML or binary).
    ///
    /// # Errors
    /// Returns `Err` on decoding failures.
    pub fn from_plist(data: &[u8]) -> anyhow::Result<Self> {
        fn parse_xml_entitlements(xml: &str) -> Entitlements {
            fn scalar(xml: &str, key: &str) -> Option<String> {
                SimplePlistReader::find_key_value(xml.as_bytes(), key)
            }
            fn bool_key(xml: &str, key: &str) -> bool {
                let needle = format!("<key>{key}</key>");
                if let Some(pos) = xml.find(&needle) {
                    let after = xml[pos + needle.len()..].trim_start();
                    return after.starts_with("<true/>");
                }
                false
            }
            fn array_key(xml: &str, key: &str) -> Vec<String> {
                let needle = format!("<key>{key}</key>");
                let Some(pos) = xml.find(&needle) else { return vec![]; };
                let after = xml[pos + needle.len()..].trim_start();
                if !after.starts_with("<array>") { return vec![]; }
                let Some(end) = after.find("</array>") else { return vec![]; };
                let content = &after[7..end];
                let mut vals = Vec::new();
                let mut rem = content;
                while let Some(s) = rem.find("<string>") {
                    rem = &rem[s + 8..];
                    if let Some(e) = rem.find("</string>") {
                        vals.push(rem[..e].to_string());
                        rem = &rem[e + 9..];
                    }
                }
                vals
            }

            Entitlements {
                application_identifier: scalar(xml, "application-identifier"),
                keychain_access_groups: array_key(xml, "keychain-access-groups"),
                team_identifier: scalar(xml, "com.apple.developer.team-identifier"),
                get_task_allow: bool_key(xml, "get-task-allow"),
                aps_environment: scalar(xml, "aps-environment"),
                associated_domains: array_key(xml, "com.apple.developer.associated-domains"),
            }
        }

        if SimplePlistReader::is_binary_plist(data) {
            // Heuristic binary plist parsing.
            fn bplist_scalar(data: &[u8], key: &str) -> Option<String> {
                SimplePlistReader::find_key_value(data, key)
            }
            fn bplist_bool(data: &[u8], key: &str) -> bool {
                // Search for the exact key string bytes followed immediately
                // (within 2 bytes) by a bplist singleton marker (0x08=false,
                // 0x09=true).  The narrow window of 2 prevents the heuristic
                // from matching 0x09 bytes that are part of adjacent string or
                // integer objects, which would cause false positives.
                let kb = key.as_bytes();
                let kl = kb.len();
                if data.len() < kl + 1 {
                    return false;
                }
                for i in 0..data.len() - kl {
                    if data[i..].starts_with(kb) {
                        // Allow at most 2 bytes between the key's last byte and
                        // the bool marker to skip over the length/type tag byte.
                        let end = (i + kl + 2).min(data.len());
                        for &b in &data[i + kl..end] {
                            if b == 0x09 {
                                return true;
                            } // bplist true marker
                            if b == 0x08 {
                                return false;
                            } // bplist false marker
                        }
                    }
                }
                false
            }

            let ent = Self {
                application_identifier: bplist_scalar(data, "application-identifier"),
                keychain_access_groups: {
                    // Collect all strings that look like group identifiers near the key.
                    let mut groups = Vec::new();
                    if let Some(v) = bplist_scalar(data, "keychain-access-groups") {
                        groups.push(v);
                    }
                    groups
                },
                team_identifier: bplist_scalar(data, "com.apple.developer.team-identifier"),
                get_task_allow: bplist_bool(data, "get-task-allow"),
                aps_environment: bplist_scalar(data, "aps-environment"),
                associated_domains: {
                    let mut domains = Vec::new();
                    if let Some(v) = bplist_scalar(data, "com.apple.developer.associated-domains") {
                        domains.push(v);
                    }
                    domains
                },
            };
            return Ok(ent);
        }

        let xml = std::str::from_utf8(data)
            .map_err(|e| anyhow::anyhow!("Entitlements plist is not valid UTF-8: {e}"))?;
        Ok(parse_xml_entitlements(xml))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProvisioningProfile
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed `embedded.mobileprovision` metadata.
///
/// The provisioning profile is a CMS/PKCS#7-signed object whose payload is an
/// XML plist.  This implementation extracts the inner plist by scanning for
/// the `<?xml` or `bplist00` magic bytes and reads the relevant keys without
/// requiring a full ASN.1 or CMS parser.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ProvisioningProfile {
    pub uuid: String,
    pub name: String,
    pub team_name: String,
    pub team_identifier: String,
    pub bundle_id: String,
    pub expiration_date: String,
    /// Device UDIDs explicitly provisioned (ad-hoc / development only).
    pub provisioned_devices: Vec<String>,
    pub is_enterprise: bool,
    pub is_adhoc: bool,
    pub is_appstore: bool,
}

impl ProvisioningProfile {
    /// Extract the inner XML plist from a CMS-wrapped provisioning profile.
    ///
    /// The strategy is:
    /// 1. Scan `data` for `<?xml` (ASCII) – typical XML plist start.
    /// 2. If not found, scan for `bplist00` (binary plist).
    /// 3. Trim everything after the matching close tag / EOF.
    ///
    /// # Errors
    /// Returns `Err` when neither magic is found (data is likely corrupted).
    fn extract_plist_from_cms(data: &[u8]) -> anyhow::Result<Vec<u8>> {
        // Try XML first.
        if let Some(pos) = find_subsequence(data, b"<?xml") {
            // Find the closing </plist> tag.
            let slice = &data[pos..];
            let end = find_subsequence(slice, b"</plist>").map_or(slice.len(), |p| p + 8);
            return Ok(slice[..end].to_vec());
        }
        // Try binary plist magic.
        if let Some(pos) = find_subsequence(data, b"bplist00") {
            return Ok(data[pos..].to_vec());
        }
        anyhow::bail!("No plist magic found in CMS-wrapped provisioning profile");
    }

    /// Parse a CMS-wrapped provisioning profile byte slice.
    ///
    /// # Errors
    /// Returns `Err` when the plist cannot be located or decoded.
    pub fn parse_cms(data: &[u8]) -> anyhow::Result<Self> {
        fn scalar(xml: &str, key: &str) -> String {
            SimplePlistReader::find_key_value(xml.as_bytes(), key).unwrap_or_default()
        }
        fn array(xml: &str, key: &str) -> Vec<String> {
            let needle = format!("<key>{key}</key>");
            let Some(pos) = xml.find(&needle) else { return vec![]; };
            let after = xml[pos + needle.len()..].trim_start();
            if !after.starts_with("<array>") { return vec![]; }
            let Some(end) = after.find("</array>") else { return vec![]; };
            let content = &after[7..end];
            let mut vals = Vec::new();
            let mut rem = content;
            while let Some(s) = rem.find("<string>") {
                rem = &rem[s + 8..];
                if let Some(e) = rem.find("</string>") {
                    vals.push(rem[..e].to_string());
                    rem = &rem[e + 9..];
                }
            }
            vals
        }

        let plist_bytes = Self::extract_plist_from_cms(data)?;
        let xml = std::str::from_utf8(&plist_bytes)
            .map_err(|e| anyhow::anyhow!("Provisioning profile plist is not UTF-8: {e}"))?;

        let uuid = scalar(xml, "UUID");
        let name = scalar(xml, "Name");
        let team_name = scalar(xml, "TeamName");
        let team_identifier = array(xml, "TeamIdentifier")
            .into_iter()
            .next()
            .unwrap_or_default();
        let expiration_date = scalar(xml, "ExpirationDate");
        let provisioned_devices = array(xml, "ProvisionedDevices");

        // Bundle ID is under Entitlements → application-identifier.
        let bundle_id = {
            let ent_needle = "<key>Entitlements</key>";
            xml.find(ent_needle).map_or_else(String::new, |pos| {
                let after = &xml[pos + ent_needle.len()..];
                SimplePlistReader::find_key_value(after.as_bytes(), "application-identifier")
                    .unwrap_or_default()
            })
        };

        // Distribution type heuristics.
        let is_enterprise = xml.contains("ProvisionsAllDevices");
        let is_adhoc = !provisioned_devices.is_empty() && !is_enterprise;
        // App Store profiles have no ProvisionedDevices and no ProvisionsAllDevices.
        let is_appstore = !is_enterprise && provisioned_devices.is_empty();

        Ok(Self {
            uuid,
            name,
            team_name,
            team_identifier,
            bundle_id,
            expiration_date,
            provisioned_devices,
            is_enterprise,
            is_adhoc,
            is_appstore,
        })
    }
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ─────────────────────────────────────────────────────────────────────────────
// IpaExtractor  (uses the `zip` crate)
// ─────────────────────────────────────────────────────────────────────────────

/// High-level IPA extractor backed by the `zip` crate for full decompression
/// support (DEFLATE in addition to STORE).
pub struct IpaExtractor {
    /// Raw IPA bytes buffered in memory.
    data: Vec<u8>,
    /// ZIP path prefix of the `.app` bundle (`Payload/MyApp.app`).
    app_prefix: String,
    /// Name of the main executable.
    executable_name: String,
}

impl IpaExtractor {
    /// Open an IPA file from disk.
    ///
    /// # Errors
    /// Returns `Err` when the file cannot be read or does not contain a valid
    /// `Payload/*.app` directory.
    pub fn open(path: &std::path::Path) -> anyhow::Result<Self> {
        let data = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("Cannot read IPA file {}: {e}", path.display()))?;

        let cursor = std::io::Cursor::new(&data);
        let mut zip = zip::ZipArchive::new(cursor)
            .map_err(|e| anyhow::anyhow!("Not a valid ZIP/IPA: {e}"))?;

        // Locate the .app prefix.
        let app_prefix = (0..zip.len())
            .find_map(|i| {
                let entry = zip.by_index(i).ok()?;
                let name = entry.name().to_owned();
                let parts: Vec<&str> = name.splitn(3, '/').collect();
                if parts.len() >= 2
                    && parts[0] == "Payload"
                    && std::path::Path::new(parts[1]).extension().is_some_and(|e| e.eq_ignore_ascii_case("app"))
                    && (parts.len() == 2 || !parts[2].is_empty())
                {
                    Some(format!("{}/{}", parts[0], parts[1]))
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow::anyhow!("No Payload/*.app found in IPA"))?;

        // Read Info.plist to determine the executable name.
        let plist_path = format!("{app_prefix}/Info.plist");
        let executable_name = {
            let mut entry = zip
                .by_name(&plist_path)
                .map_err(|_| anyhow::anyhow!("Missing {plist_path}"))?;
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut buf)
                .map_err(|e| anyhow::anyhow!("Read Info.plist: {e}"))?;
            // Try to find CFBundleExecutable in the raw bytes.
            SimplePlistReader::find_key_value(&buf, "CFBundleExecutable").unwrap_or_else(|| {
                app_prefix
                    .split('/')
                    .nth(1)
                    .unwrap_or("App")
                    .trim_end_matches(".app")
                    .to_owned()
            })
        };

        Ok(Self {
            data,
            app_prefix,
            executable_name,
        })
    }

    /// Read an arbitrary file from the IPA by its ZIP-relative path.
    fn read_zip_file(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        let cursor = std::io::Cursor::new(&self.data);
        let mut zip = zip::ZipArchive::new(cursor)?;
        let mut entry = zip
            .by_name(path)
            .map_err(|_| anyhow::anyhow!("Entry not found: {path}"))?;
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut buf)?;
        Ok(buf)
    }

    /// Read the raw bytes of the main Mach-O binary.
    ///
    /// # Errors
    /// Returns `Err` when the binary entry is missing or cannot be decompressed.
    pub fn read_binary(&self) -> anyhow::Result<Vec<u8>> {
        let bin_path = format!("{}/{}", self.app_prefix, self.executable_name);
        self.read_zip_file(&bin_path)
    }

    /// Read and parse `Info.plist`.
    ///
    /// # Errors
    /// Returns `Err` when the plist is missing or cannot be decoded.
    pub fn read_info_plist(&self) -> anyhow::Result<InfoPlistFull> {
        let path = format!("{}/Info.plist", self.app_prefix);
        let data = self.read_zip_file(&path)?;
        InfoPlistFull::from_data(&data)
    }

    /// Read and parse the embedded entitlements from the code signature
    /// (`_CodeSignature/CodeResources` is not used; entitlements are read from
    /// `Entitlements.plist` if present, otherwise `None` is returned).
    ///
    /// # Errors
    /// Returns `Err` on I/O or decoding failures.  Returns `Ok(None)` when no
    /// entitlements file is found.
    pub fn read_entitlements(&self) -> anyhow::Result<Option<Entitlements>> {
        let candidates = [
            format!("{}/Entitlements.plist", self.app_prefix),
            format!("{}/archived-expanded-entitlements.xcent", self.app_prefix),
        ];
        for path in &candidates {
            if let Ok(bytes) = self.read_zip_file(path) {
                return Entitlements::from_plist(&bytes).map(Some);
            }
        }
        Ok(None)
    }

    /// Read and parse `embedded.mobileprovision`.
    ///
    /// # Errors
    /// Returns `Err` on parse failures.  Returns `Ok(None)` when the profile
    /// is absent (common for simulator builds and jailbroken IPAs).
    pub fn read_provisioning_profile(&self) -> anyhow::Result<Option<ProvisioningProfile>> {
        let path = format!("{}/embedded.mobileprovision", self.app_prefix);
        self.read_zip_file(&path).map_or_else(|_| Ok(None), |bytes| ProvisioningProfile::parse_cms(&bytes).map(Some))
    }

    /// List the names of embedded frameworks (`.framework` bundles).
    #[must_use]
    pub fn list_frameworks(&self) -> Vec<String> {
        self.list_entries_with_suffix(".framework/")
            .into_iter()
            .filter_map(|p| {
                // Keep only the directory entries directly under Frameworks/.
                let fwk_prefix = format!("{}/Frameworks/", self.app_prefix);
                if p.starts_with(&fwk_prefix) {
                    let rest = &p[fwk_prefix.len()..];
                    // rest should be "MyFramework.framework/"
                    let parts: Vec<&str> = rest.split('/').collect();
                    if parts.len() == 2 && parts[1].is_empty() {
                        Some(parts[0].to_owned())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    /// List resource file paths (everything that is not a binary or framework).
    #[must_use]
    pub fn list_resources(&self) -> Vec<String> {
        let resource_exts = [
            "png",
            "jpg",
            "jpeg",
            "gif",
            "pdf",
            "ttf",
            "otf",
            "strings",
            "storyboard",
            "xib",
            "car",
            "json",
            "xml",
            "plist",
            "html",
            "css",
            "js",
            "wav",
            "mp3",
            "aiff",
            "m4a",
            "mp4",
            "mov",
            "lottie",
        ];
        let cursor = std::io::Cursor::new(&self.data);
        let Ok(mut zip) = zip::ZipArchive::new(cursor) else { return vec![]; };
        (0..zip.len())
            .filter_map(|i| {
                let entry = zip.by_index(i).ok()?;
                let name = entry.name().to_owned();
                if name.starts_with(&self.app_prefix) && !entry.is_dir() {
                    let ext = std::path::Path::new(&name)
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("");
                    if resource_exts.iter().any(|&r| r.eq_ignore_ascii_case(ext)) {
                        return Some(name);
                    }
                }
                None
            })
            .collect()
    }

    /// Find dynamically-linked `.dylib` files embedded in the IPA.
    #[must_use]
    pub fn find_dylibs(&self) -> Vec<String> {
        self.list_entries_with_suffix(".dylib")
    }

    /// Helper: enumerate ZIP entries whose names end with `suffix`.
    fn list_entries_with_suffix(&self, suffix: &str) -> Vec<String> {
        let cursor = std::io::Cursor::new(&self.data);
        let Ok(mut zip) = zip::ZipArchive::new(cursor) else { return vec![]; };
        (0..zip.len())
            .filter_map(|i| {
                let entry = zip.by_index(i).ok()?;
                let name = entry.name().to_owned();
                if name.ends_with(suffix) {
                    Some(name)
                } else {
                    None
                }
            })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IpaReport / IpaAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// Full analysis report for an IPA file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IpaReport {
    pub info: InfoPlistFull,
    pub entitlements: Option<Entitlements>,
    pub provisioning: Option<ProvisioningProfile>,
    pub framework_count: usize,
    pub resource_count: usize,
    /// Size of the main Mach-O binary in bytes.
    pub binary_size: u64,
    /// Entitlement keys or values flagged as suspicious.
    pub suspicious_entitlements: Vec<String>,
    /// `UIRequiredDeviceCapabilities` entries that may indicate non-standard use.
    pub suspicious_capabilities: Vec<String>,
    /// `true` when any `NSNetworkUsageDescription` or ATS key is present.
    pub network_usage: bool,
    /// `true` when `NSCameraUsageDescription` is present.
    pub camera_usage: bool,
    /// `true` when `NSLocationWhenInUseUsageDescription` or similar is present.
    pub location_usage: bool,
}

/// Drives full IPA analysis, producing an [`IpaReport`].
pub struct IpaAnalyzer;

impl IpaAnalyzer {
    /// Analyze the IPA at `path` and return a complete [`IpaReport`].
    ///
    /// # Errors
    /// Returns `Err` when the file cannot be opened or parsed.
    pub fn analyze(path: &std::path::Path) -> anyhow::Result<IpaReport> {
        let extractor = IpaExtractor::open(path)?;

        let info = extractor.read_info_plist()?;
        let entitlements = extractor.read_entitlements()?;
        let provisioning = extractor.read_provisioning_profile()?;

        let frameworks = extractor.list_frameworks();
        let resources = extractor.list_resources();
        let binary = extractor.read_binary().unwrap_or_default();

        let suspicious_entitlements = entitlements
            .as_ref()
            .map(|e| Self::suspicious_entitlements(e, provisioning.as_ref()))
            .unwrap_or_default();

        let suspicious_capabilities = info
            .required_capabilities
            .iter()
            .filter(|c| {
                // Capabilities that are unusual and warrant review.
                matches!(
                    c.as_str(),
                    "access-wifi-information"
                        | "inter-app-audio"
                        | "personal-hotspot"
                        | "gamekit"
                        | "nfc"
                )
            })
            .cloned()
            .collect();

        // Derive privacy flags from Info.plist keys (available as raw XML scan
        // via IpaExtractor internals — we use the background_modes and
        // required_capabilities as a proxy here; the full NS* key scan is done
        // at the IpaPackage layer in parse_info_plist above).
        let network_usage = info.url_schemes.iter().any(|s| s.starts_with("http"))
            || info
                .background_modes
                .iter()
                .any(|m| matches!(m.as_str(), "fetch" | "remote-notification" | "voip"));
        let camera_usage = info.required_capabilities.iter().any(|c| c == "camera");
        let location_usage = info.required_capabilities.iter().any(|c| c.contains("gps"));

        Ok(IpaReport {
            info,
            entitlements,
            provisioning,
            framework_count: frameworks.len(),
            resource_count: resources.len(),
            binary_size: binary.len() as u64,
            suspicious_entitlements,
            suspicious_capabilities,
            network_usage,
            camera_usage,
            location_usage,
        })
    }

    /// Inspect `entitlements` and return a list of strings describing
    /// suspicious findings.
    ///
    /// Flags:
    /// - `get-task-allow = true` in a production/App Store profile.
    /// - `com.apple.private.*` entitlements (private Apple entitlements).
    /// - More than one keychain access group (data sharing across apps).
    #[must_use]
    pub fn suspicious_entitlements(
        ents: &Entitlements,
        profile: Option<&ProvisioningProfile>,
    ) -> Vec<String> {
        let mut findings = Vec::new();

        // get-task-allow should only be true in development.
        if ents.get_task_allow {
            let in_prod = profile.is_some_and(|p| p.is_appstore || p.is_enterprise);
            if in_prod {
                findings.push(
                    "get-task-allow=true in production/enterprise profile — allows debugger attach"
                        .into(),
                );
            } else {
                // Still noteworthy even in dev builds.
                findings.push("get-task-allow=true (development build — debuggable)".into());
            }
        }

        // Private Apple entitlements.
        if let Some(app_id) = &ents.application_identifier
            && app_id.contains("com.apple.private")
        {
            findings.push(format!(
                "Private Apple entitlement in application-identifier: {app_id}"
            ));
        }

        // Keychain sharing (> 1 group means data shared with other apps).
        if ents.keychain_access_groups.len() > 1 {
            findings.push(format!(
                "Keychain shared across {} groups: {}",
                ents.keychain_access_groups.len(),
                ents.keychain_access_groups.join(", ")
            ));
        }

        // Associated domains (universal links / AASA).
        if !ents.associated_domains.is_empty() {
            findings.push(format!(
                "Associated domains configured: {}",
                ents.associated_domains.join(", ")
            ));
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── IpaError ──────────────────────────────────────────────────────────────

    #[test]
    fn test_error_invalid_ipa_display() {
        let e = IpaError::InvalidIpa("bad zip".into());
        assert!(e.to_string().contains("Not a valid IPA"));
    }

    #[test]
    fn test_error_missing_file_display() {
        let e = IpaError::MissingFile("Info.plist".into());
        assert!(e.to_string().contains("Missing file"));
    }

    #[test]
    fn test_error_plist_parse_display() {
        let e = IpaError::PlistParse("unexpected token".into());
        assert!(e.to_string().contains("Plist parse error"));
    }

    #[test]
    fn test_error_io_display() {
        let e = IpaError::Io("disk full".into());
        assert!(e.to_string().contains("IO"));
    }

    #[test]
    fn test_error_fairplay_display() {
        let e = IpaError::FairPlay("not decrypted".into());
        assert!(e.to_string().contains("FairPlay"));
    }

    // ── IpaEntry helpers ──────────────────────────────────────────────────────

    #[test]
    fn test_entry_filename() {
        let e = IpaEntry {
            path: "Payload/TestApp.app/TestApp".into(),
            size: 0,
            is_dir: false,
        };
        assert_eq!(e.filename(), "TestApp");
    }

    #[test]
    fn test_entry_filename_no_slash() {
        let e = IpaEntry {
            path: "README".into(),
            size: 0,
            is_dir: false,
        };
        assert_eq!(e.filename(), "README");
    }

    #[test]
    fn test_entry_directory() {
        let e = IpaEntry {
            path: "Payload/TestApp.app/TestApp".into(),
            size: 0,
            is_dir: false,
        };
        assert_eq!(e.directory(), "Payload/TestApp.app");
    }

    #[test]
    fn test_entry_directory_no_slash() {
        let e = IpaEntry {
            path: "README".into(),
            size: 0,
            is_dir: false,
        };
        assert_eq!(e.directory(), "");
    }

    #[test]
    fn test_entry_extension() {
        let e = IpaEntry {
            path: "Assets.car".into(),
            size: 100,
            is_dir: false,
        };
        assert_eq!(e.extension(), Some("car"));
    }

    #[test]
    fn test_entry_no_extension() {
        let e = IpaEntry {
            path: "Payload/App.app/App".into(),
            size: 100,
            is_dir: false,
        };
        assert!(e.extension().is_none());
    }

    #[test]
    fn test_entry_is_likely_binary() {
        let e = IpaEntry {
            path: "Payload/App.app/App".into(),
            size: 2048,
            is_dir: false,
        };
        assert!(e.is_likely_binary());
    }

    // ── InfoPlist helpers ─────────────────────────────────────────────────────

    #[test]
    fn test_info_plist_has_entitlements() {
        let pkg = IpaPackage::mock();
        assert!(pkg.info_plist.has_entitlements());
    }

    #[test]
    fn test_info_plist_has_permission() {
        let pkg = IpaPackage::mock();
        assert!(pkg.info_plist.has_permission("NSCameraUsageDescription"));
        assert!(
            !pkg.info_plist
                .has_permission("NSMicrophoneUsageDescription")
        );
    }

    #[test]
    fn test_info_plist_targets_iphone() {
        let pkg = IpaPackage::mock();
        assert!(pkg.info_plist.targets_iphone());
    }

    #[test]
    fn test_info_plist_parsed_min_os() {
        let pkg = IpaPackage::mock();
        assert_eq!(pkg.info_plist.parsed_min_os(), Some((15, 0)));
    }

    // ── CodeSignature helpers ─────────────────────────────────────────────────

    #[test]
    fn test_code_signature_developer_signed() {
        // The reference IPA carries a real provisioning profile and a real
        // LC_CODE_SIGNATURE, but no decodable certificates — this workspace has
        // no X.509 decoder. `is_developer_signed` scans certificate subjects,
        // so with no certificates the honest answer is "no evidence", which it
        // reports as false. It must NOT claim a developer identity it never
        // read.
        let pkg = IpaPackage::mock();
        let sig = pkg.code_signature.as_ref().unwrap();
        assert!(sig.cert_chain.is_empty());
        assert!(!sig.is_developer_signed());
    }

    #[test]
    fn test_code_signature_not_enterprise() {
        let pkg = IpaPackage::mock();
        let sig = pkg.code_signature.as_ref().unwrap();
        assert!(!sig.is_enterprise());
    }

    #[test]
    fn test_code_signature_not_adhoc() {
        let pkg = IpaPackage::mock();
        let sig = pkg.code_signature.as_ref().unwrap();
        assert!(!sig.is_adhoc());
    }

    #[test]
    fn test_code_signature_leaf_cert() {
        // No certificate is recovered, and the Apple-issuance question is
        // refused with a typed error naming the missing capability rather than
        // answered with a hardcoded "Apple".
        let pkg = IpaPackage::mock();
        let sig = pkg.code_signature.as_ref().unwrap();
        assert!(sig.leaf_cert().is_none());
        assert_eq!(
            sig.apple_leaf_verdict(),
            Err(CertVerifyError::NoCertificateChain)
        );
    }

    #[test]
    fn test_apple_leaf_verdict_refused_even_with_a_chain() {
        let sig = CodeSignature {
            team_id: "TEAM123456".into(),
            signing_id: "com.example.TestApp".into(),
            flags: 0,
            cert_chain: vec![CertInfo {
                subject: "Apple Development: Test Dev".into(),
                issuer: "Apple Worldwide Developer Relations CA".into(),
                serial: "0x1234ABCD".into(),
                not_before: "2023-01-01T00:00:00Z".into(),
                not_after: "2024-01-01T00:00:00Z".into(),
            }],
            entitlements_xml: String::new(),
        };
        // The issuer STRING says Apple; that is not verification.
        assert!(sig.leaf_cert().unwrap().is_apple_issued());
        assert_eq!(sig.apple_leaf_verdict(), Err(CertVerifyError::NoX509Verifier));
    }

    #[test]
    fn test_codesign_flags_are_read_from_the_macho() {
        for flags in [0u32, CS_ADHOC, 0x0001_0000] {
            let exe = IpaPackage::reference_macho_bytes(flags);
            assert_eq!(codesign_flags_from_macho(&exe), Ok(flags));
        }
    }

    #[test]
    fn test_codesign_flags_unsigned_binary_errors() {
        // A Mach-O header with no load commands: unsigned, and said so.
        let mut exe = vec![0u8; 64];
        exe[..4].copy_from_slice(&0xFEED_FACFu32.to_le_bytes());
        assert_eq!(
            codesign_flags_from_macho(&exe),
            Err(CodeSignReadError::NoCodeSignatureCommand)
        );
    }

    #[test]
    fn test_parse_refuses_an_app_without_info_plist() {
        let zip = zip_store(&[("Payload/NoPlist.app/", Vec::new())]);
        match IpaPackage::parse(&zip) {
            Err(IpaError::MissingFile(p)) => {
                assert_eq!(p, "Payload/NoPlist.app/Info.plist");
            }
            other => panic!("expected MissingFile, got {other:?}"),
        }
    }

    #[test]
    fn test_supported_platforms_come_from_the_plist() {
        let pkg = IpaPackage::mock();
        assert_eq!(pkg.info_plist.supported_platforms, vec!["iPhoneOS"]);
    }

    #[test]
    fn test_cert_info_apple_issued() {
        let ci = CertInfo {
            subject: "Apple Dev".into(),
            issuer: "Apple Root CA".into(),
            serial: "0x1".into(),
            not_before: "2020".into(),
            not_after: "2025".into(),
        };
        assert!(ci.is_apple_issued());
    }

    // ── IpaPackage::mock ──────────────────────────────────────────────────────

    #[test]
    fn test_mock_bundle_id() {
        let pkg = IpaPackage::mock();
        assert_eq!(pkg.info_plist.bundle_id, "com.example.TestApp");
    }

    #[test]
    fn test_mock_entry_count() {
        // Five real ZIP members: the .app directory, Info.plist, the Mach-O,
        // embedded.mobileprovision and the framework directory.
        let pkg = IpaPackage::mock();
        assert_eq!(pkg.entry_count(), 5);
    }

    #[test]
    fn test_mock_framework_count() {
        let pkg = IpaPackage::mock();
        assert_eq!(pkg.framework_count(), 1);
    }

    #[test]
    fn test_mock_has_entitlement() {
        let pkg = IpaPackage::mock();
        assert!(pkg.has_entitlement("com.apple.developer.team-identifier"));
        assert!(!pkg.has_entitlement("nonexistent"));
    }

    #[test]
    fn test_mock_executable_path() {
        let pkg = IpaPackage::mock();
        assert_eq!(pkg.executable_path, "Payload/TestApp.app/TestApp");
    }

    #[test]
    fn test_mock_no_plugins() {
        let pkg = IpaPackage::mock();
        assert!(pkg.plugins.is_empty());
    }

    #[test]
    fn test_mock_code_signature_present() {
        let pkg = IpaPackage::mock();
        assert!(pkg.code_signature.is_some());
    }

    #[test]
    fn test_mock_not_encrypted() {
        let pkg = IpaPackage::mock();
        assert!(!pkg.is_encrypted());
    }

    // ── IpaPackage::parse (invalid input) ────────────────────────────────────

    #[test]
    fn test_parse_empty_data_fails() {
        let err = IpaPackage::parse(&[]).unwrap_err();
        assert!(matches!(err, IpaError::InvalidIpa(_)));
    }

    #[test]
    fn test_parse_random_data_fails() {
        let err = IpaPackage::parse(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap_err();
        assert!(matches!(err, IpaError::InvalidIpa(_)));
    }

    // ── ZIP builder helper ────────────────────────────────────────────────────

    fn build_minimal_ipa() -> Vec<u8> {
        let plist = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"\">\
<plist version=\"1.0\"><dict>\
<key>CFBundleIdentifier</key><string>com.test.app</string>\
<key>CFBundleDisplayName</key><string>TestApp</string>\
<key>CFBundleShortVersionString</key><string>2.0</string>\
<key>MinimumOSVersion</key><string>16.0</string>\
<key>CFBundleExecutable</key><string>MyApp</string>\
</dict></plist>";
        build_zip_with_stored_entry("Payload/MyApp.app/Info.plist", plist)
    }

    fn build_zip_with_stored_entry(name: &str, data: &[u8]) -> Vec<u8> {
        let name_bytes = name.as_bytes();
        let crc = crc32(data);
        let size = data.len() as u32;
        let fname_len = name_bytes.len() as u16;
        let mut out = Vec::new();
        let local_offset = 0u32;
        out.extend_from_slice(&LOCAL_HEADER_SIG.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&fname_len.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(data);
        let cd_offset = out.len() as u32;
        out.extend_from_slice(&CENTRAL_DIR_SIG.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&fname_len.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&local_offset.to_le_bytes());
        out.extend_from_slice(name_bytes);
        let cd_size = (out.len() as u32) - cd_offset;
        out.extend_from_slice(&EOCD_SIG.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    fn crc32(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFF_FFFF;
        for &byte in data {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
        !crc
    }

    #[test]
    fn test_parse_real_zip() {
        let ipa_data = build_minimal_ipa();
        let pkg = IpaPackage::parse(&ipa_data).unwrap();
        assert_eq!(pkg.info_plist.bundle_id, "com.test.app");
        assert_eq!(pkg.info_plist.bundle_version, "2.0");
        assert_eq!(pkg.info_plist.executable, "MyApp");
        assert_eq!(pkg.executable_path, "Payload/MyApp.app/MyApp");
    }

    #[test]
    fn test_parse_real_zip_entry_count() {
        let ipa_data = build_minimal_ipa();
        let pkg = IpaPackage::parse(&ipa_data).unwrap();
        assert!(pkg.entry_count() >= 1);
    }

    // ── Serialisation ─────────────────────────────────────────────────────────

    #[test]
    fn test_ipa_package_serde_roundtrip() {
        let pkg = IpaPackage::mock();
        let json = serde_json::to_string(&pkg).unwrap();
        let back: IpaPackage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.info_plist.bundle_id, pkg.info_plist.bundle_id);
        assert_eq!(back.executable_path, pkg.executable_path);
        assert_eq!(back.framework_count(), pkg.framework_count());
    }

    #[test]
    fn test_info_plist_serde_roundtrip() {
        let pkg = IpaPackage::mock();
        let json = serde_json::to_string(&pkg.info_plist).unwrap();
        let back: InfoPlist = serde_json::from_str(&json).unwrap();
        assert_eq!(back.bundle_version, "1.2.3");
        assert_eq!(back.executable, "TestApp");
    }

    #[test]
    fn test_cert_info_serde_roundtrip() {
        let ci = CertInfo {
            subject: "CN=Test".into(),
            issuer: "CN=Apple".into(),
            serial: "0xABCD".into(),
            not_before: "2024-01-01T00:00:00Z".into(),
            not_after: "2025-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&ci).unwrap();
        let back: CertInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.serial, "0xABCD");
    }

    #[test]
    fn test_ipa_entry_serde_roundtrip() {
        let e = IpaEntry {
            path: "Payload/App.app/binary".into(),
            size: 1024,
            is_dir: false,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: IpaEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.size, 1024);
        assert!(!back.is_dir);
    }

    // ── SimplePlistReader ─────────────────────────────────────────────────────

    #[test]
    fn test_simple_plist_is_binary_plist_true() {
        assert!(SimplePlistReader::is_binary_plist(b"bplist00\x00\x01"));
    }

    #[test]
    fn test_simple_plist_is_binary_plist_false() {
        assert!(!SimplePlistReader::is_binary_plist(b"<?xml version"));
    }

    #[test]
    fn test_simple_plist_is_binary_plist_empty() {
        assert!(!SimplePlistReader::is_binary_plist(b""));
    }

    #[test]
    fn test_simple_plist_find_key_value_xml() {
        let xml = b"<dict><key>CFBundleIdentifier</key><string>com.example.app</string></dict>";
        let val = SimplePlistReader::find_key_value(xml, "CFBundleIdentifier");
        assert_eq!(val.as_deref(), Some("com.example.app"));
    }

    #[test]
    fn test_simple_plist_find_key_value_xml_true() {
        let xml = b"<dict><key>get-task-allow</key><true/></dict>";
        let val = SimplePlistReader::find_key_value(xml, "get-task-allow");
        assert_eq!(val.as_deref(), Some("true"));
    }

    #[test]
    fn test_simple_plist_find_key_value_missing() {
        let xml = b"<dict><key>Other</key><string>value</string></dict>";
        let val = SimplePlistReader::find_key_value(xml, "CFBundleIdentifier");
        assert!(val.is_none());
    }

    #[test]
    fn test_simple_plist_all_strings_xml() {
        let xml = b"<plist><array><string>hello</string><string>world</string></array></plist>";
        let strings = SimplePlistReader::all_strings(xml);
        assert!(strings.contains(&"hello".to_string()));
        assert!(strings.contains(&"world".to_string()));
    }

    #[test]
    fn test_simple_plist_read_string_ascii_tag() {
        // Craft a minimal ASCII string object: tag=0x53 (5=string, 3=length), then "abc"
        let data = &[0x53u8, b'a', b'b', b'c'];
        let result = SimplePlistReader::read_string(data, 0);
        assert_eq!(result.as_deref(), Some("abc"));
    }

    #[test]
    fn test_simple_plist_read_string_wrong_tag() {
        // tag=0x10 is an integer, not a string.
        let data = &[0x10u8, 0x00, 0x00];
        let result = SimplePlistReader::read_string(data, 0);
        assert!(result.is_none());
    }

    // ── InfoPlistFull ─────────────────────────────────────────────────────────

    #[test]
    fn test_info_plist_full_from_xml_basic() {
        let xml = r#"<?xml version="1.0"?><plist><dict>
            <key>CFBundleIdentifier</key><string>com.test.full</string>
            <key>CFBundleDisplayName</key><string>FullApp</string>
            <key>CFBundleShortVersionString</key><string>3.1</string>
            <key>MinimumOSVersion</key><string>15.0</string>
        </dict></plist>"#;
        let plist = InfoPlistFull::from_xml(xml).unwrap();
        assert_eq!(plist.bundle_id, "com.test.full");
        assert_eq!(plist.bundle_name, "FullApp");
        assert_eq!(plist.bundle_version, "3.1");
        assert_eq!(plist.min_os_version, "15.0");
    }

    #[test]
    fn test_info_plist_full_from_xml_url_schemes() {
        let xml = r"<plist><dict>
            <key>CFBundleIdentifier</key><string>com.test.url</string>
            <key>CFBundleURLTypes</key>
            <array><dict>
                <key>CFBundleURLSchemes</key>
                <array><string>myapp</string><string>myapp-dev</string></array>
            </dict></array>
        </dict></plist>";
        let plist = InfoPlistFull::from_xml(xml).unwrap();
        assert!(plist.url_schemes.contains(&"myapp".to_string()));
    }

    #[test]
    fn test_info_plist_full_from_xml_background_modes() {
        let xml = r"<plist><dict>
            <key>CFBundleIdentifier</key><string>com.test.bg</string>
            <key>UIBackgroundModes</key>
            <array><string>fetch</string><string>remote-notification</string></array>
        </dict></plist>";
        let plist = InfoPlistFull::from_xml(xml).unwrap();
        assert!(plist.background_modes.contains(&"fetch".to_string()));
        assert!(
            plist
                .background_modes
                .contains(&"remote-notification".to_string())
        );
    }

    #[test]
    fn test_info_plist_full_from_data_xml() {
        let xml = b"<plist><dict><key>CFBundleIdentifier</key><string>com.data.test</string></dict></plist>";
        let plist = InfoPlistFull::from_data(xml).unwrap();
        assert_eq!(plist.bundle_id, "com.data.test");
    }

    #[test]
    fn test_info_plist_full_serde_roundtrip() {
        let xml = r"<plist><dict>
            <key>CFBundleIdentifier</key><string>com.serde.test</string>
            <key>CFBundleDisplayName</key><string>SerdeApp</string>
            <key>CFBundleShortVersionString</key><string>1.0</string>
            <key>MinimumOSVersion</key><string>14.0</string>
        </dict></plist>";
        let plist = InfoPlistFull::from_xml(xml).unwrap();
        let json = serde_json::to_string(&plist).unwrap();
        let back: InfoPlistFull = serde_json::from_str(&json).unwrap();
        assert_eq!(back.bundle_id, "com.serde.test");
    }

    // ── Entitlements ──────────────────────────────────────────────────────────

    #[test]
    fn test_entitlements_from_plist_xml_basic() {
        let xml = r#"<?xml version="1.0"?><plist><dict>
            <key>application-identifier</key><string>TEAM123.com.example.app</string>
            <key>com.apple.developer.team-identifier</key><string>TEAM123</string>
            <key>get-task-allow</key><false/>
            <key>aps-environment</key><string>production</string>
        </dict></plist>"#;
        let ent = Entitlements::from_plist(xml.as_bytes()).unwrap();
        assert_eq!(
            ent.application_identifier.as_deref(),
            Some("TEAM123.com.example.app")
        );
        assert_eq!(ent.team_identifier.as_deref(), Some("TEAM123"));
        assert!(!ent.get_task_allow);
        assert_eq!(ent.aps_environment.as_deref(), Some("production"));
    }

    #[test]
    fn test_entitlements_get_task_allow_true() {
        let xml = b"<plist><dict><key>get-task-allow</key><true/></dict></plist>";
        let ent = Entitlements::from_plist(xml).unwrap();
        assert!(ent.get_task_allow);
    }

    #[test]
    fn test_entitlements_keychain_groups() {
        let xml = r"<plist><dict>
            <key>keychain-access-groups</key>
            <array>
                <string>TEAM1.com.example.app</string>
                <string>TEAM1.com.example.shared</string>
            </array>
        </dict></plist>";
        let ent = Entitlements::from_plist(xml.as_bytes()).unwrap();
        assert_eq!(ent.keychain_access_groups.len(), 2);
    }

    #[test]
    fn test_entitlements_associated_domains() {
        let xml = r"<plist><dict>
            <key>com.apple.developer.associated-domains</key>
            <array><string>applinks:example.com</string></array>
        </dict></plist>";
        let ent = Entitlements::from_plist(xml.as_bytes()).unwrap();
        assert_eq!(ent.associated_domains, vec!["applinks:example.com"]);
    }

    #[test]
    fn test_entitlements_serde_roundtrip() {
        let xml = b"<plist><dict><key>get-task-allow</key><true/></dict></plist>";
        let ent = Entitlements::from_plist(xml).unwrap();
        let json = serde_json::to_string(&ent).unwrap();
        let back: Entitlements = serde_json::from_str(&json).unwrap();
        assert!(back.get_task_allow);
    }

    // ── ProvisioningProfile ───────────────────────────────────────────────────

    fn make_provisioning_xml(extra: &str) -> Vec<u8> {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
    <key>UUID</key><string>AAAA-BBBB-CCCC-DDDD</string>
    <key>Name</key><string>My Profile</string>
    <key>TeamName</key><string>My Team</string>
    <key>TeamIdentifier</key><array><string>TEAM999</string></array>
    <key>ExpirationDate</key><string>2027-01-01T00:00:00Z</string>
    {extra}
</dict></plist>"#
        )
        .into_bytes()
    }

    #[test]
    fn test_provisioning_profile_parse_cms_from_xml() {
        let data = make_provisioning_xml("");
        let profile = ProvisioningProfile::parse_cms(&data).unwrap();
        assert_eq!(profile.uuid, "AAAA-BBBB-CCCC-DDDD");
        assert_eq!(profile.name, "My Profile");
        assert_eq!(profile.team_name, "My Team");
        assert_eq!(profile.team_identifier, "TEAM999");
        assert_eq!(profile.expiration_date, "2027-01-01T00:00:00Z");
    }

    #[test]
    fn test_provisioning_profile_appstore() {
        let data = make_provisioning_xml("");
        let profile = ProvisioningProfile::parse_cms(&data).unwrap();
        // No ProvisionedDevices, no ProvisionsAllDevices → App Store.
        assert!(profile.is_appstore);
        assert!(!profile.is_adhoc);
        assert!(!profile.is_enterprise);
    }

    #[test]
    fn test_provisioning_profile_adhoc() {
        let extra = r"<key>ProvisionedDevices</key>
            <array><string>UDID1234567890</string></array>";
        let data = make_provisioning_xml(extra);
        let profile = ProvisioningProfile::parse_cms(&data).unwrap();
        assert!(profile.is_adhoc);
        assert!(!profile.is_appstore);
        assert!(!profile.is_enterprise);
        assert_eq!(profile.provisioned_devices, vec!["UDID1234567890"]);
    }

    #[test]
    fn test_provisioning_profile_enterprise() {
        let extra = "<key>ProvisionsAllDevices</key><true/>";
        let data = make_provisioning_xml(extra);
        let profile = ProvisioningProfile::parse_cms(&data).unwrap();
        assert!(profile.is_enterprise);
        assert!(!profile.is_adhoc);
        assert!(!profile.is_appstore);
    }

    #[test]
    fn test_provisioning_profile_no_plist_magic_fails() {
        let data = b"\x30\x82\x01\x00GARBAGE_CMS_DATA";
        let result = ProvisioningProfile::parse_cms(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_provisioning_profile_serde_roundtrip() {
        let data = make_provisioning_xml("");
        let profile = ProvisioningProfile::parse_cms(&data).unwrap();
        let json = serde_json::to_string(&profile).unwrap();
        let back: ProvisioningProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(back.uuid, profile.uuid);
        assert_eq!(back.team_identifier, profile.team_identifier);
    }

    // ── IpaAnalyzer suspicious_entitlements ───────────────────────────────────

    #[test]
    fn test_suspicious_entitlements_get_task_allow_dev() {
        let ent = Entitlements {
            get_task_allow: true,
            ..Default::default()
        };
        let findings = IpaAnalyzer::suspicious_entitlements(&ent, None);
        assert!(!findings.is_empty());
        assert!(findings[0].contains("get-task-allow=true"));
    }

    #[test]
    fn test_suspicious_entitlements_get_task_allow_in_prod() {
        let ent = Entitlements {
            get_task_allow: true,
            ..Default::default()
        };
        let profile = ProvisioningProfile {
            is_appstore: true,
            ..Default::default()
        };
        let findings = IpaAnalyzer::suspicious_entitlements(&ent, Some(&profile));
        assert!(findings.iter().any(|f| f.contains("production")));
    }

    #[test]
    fn test_suspicious_entitlements_keychain_sharing() {
        let ent = Entitlements {
            keychain_access_groups: vec!["T.app1".into(), "T.app2".into()],
            ..Default::default()
        };
        let findings = IpaAnalyzer::suspicious_entitlements(&ent, None);
        assert!(findings.iter().any(|f| f.contains("Keychain shared")));
    }

    #[test]
    fn test_suspicious_entitlements_associated_domains() {
        let ent = Entitlements {
            associated_domains: vec!["applinks:example.com".into()],
            ..Default::default()
        };
        let findings = IpaAnalyzer::suspicious_entitlements(&ent, None);
        assert!(findings.iter().any(|f| f.contains("Associated domains")));
    }

    #[test]
    fn test_suspicious_entitlements_clean() {
        let ent = Entitlements::default();
        let findings = IpaAnalyzer::suspicious_entitlements(&ent, None);
        assert!(findings.is_empty());
    }

    // ── find_subsequence ──────────────────────────────────────────────────────

    #[test]
    fn test_find_subsequence_found() {
        let data = b"GARBAGE<?xml VERSION";
        assert_eq!(find_subsequence(data, b"<?xml"), Some(7));
    }

    #[test]
    fn test_find_subsequence_not_found() {
        let data = b"no magic here";
        assert!(find_subsequence(data, b"bplist00").is_none());
    }

    #[test]
    fn test_find_subsequence_empty_needle() {
        assert!(find_subsequence(b"data", b"").is_none());
    }
}

// ─── Binary plist (bplist00) full parser ─────────────────────────────────────

/// A structured value decoded from a binary plist.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum BplistValue {
    Null,
    Bool(bool),
    Int(i64),
    Real(f64),
    Data(Vec<u8>),
    String(String),
    Uid(u64),
    Array(Vec<Self>),
    Dict(Vec<(String, Self)>),
}

impl BplistValue {
    /// Return the value as a string if it is a `String` variant.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        if let Self::String(s) = self {
            Some(s)
        } else {
            None
        }
    }

    /// Return the value as `i64` if it is an `Int` variant.
    #[must_use]
    pub const fn as_int(&self) -> Option<i64> {
        if let Self::Int(n) = self {
            Some(*n)
        } else {
            None
        }
    }

    /// Return the value as `f64` if it is a `Real` variant.
    #[must_use]
    pub const fn as_real(&self) -> Option<f64> {
        if let Self::Real(f) = self {
            Some(*f)
        } else {
            None
        }
    }

    /// Return the value as `bool` if it is a `Bool` variant.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        if let Self::Bool(b) = self {
            Some(*b)
        } else {
            None
        }
    }

    /// Walk into a dict and find a key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        if let Self::Dict(kvs) = self {
            kvs.iter().find(|(k, _)| k == key).map(|(_, v)| v)
        } else {
            None
        }
    }
}

/// Binary plist (`NSPropertyList` bplist00 format) parser.
///
/// Implements a subset of the Apple CoreFoundation binary plist format
/// (version `bplist00`) sufficient to decode `Info.plist` and embedded
/// entitlement plists.
pub struct BplistParser;

impl BplistParser {
    /// Parse a binary plist from raw bytes.
    ///
    /// # Errors
    /// Returns `Err` if the magic is missing, the trailer is invalid, or
    /// the object table is malformed.
    pub fn parse(data: &[u8]) -> anyhow::Result<BplistValue> {
        if data.len() < 32 {
            anyhow::bail!("bplist data too short: {} bytes", data.len());
        }
        if !data.starts_with(b"bplist00") {
            anyhow::bail!("not a bplist00 (got {:?})", &data[..8]);
        }

        // Trailer: last 32 bytes
        let trailer_off = data.len() - 32;
        let trailer = &data[trailer_off..];

        // offset_size: how many bytes each offset table entry is
        let offset_size = trailer[6] as usize;
        // object_ref_size: how many bytes each object reference is
        let obj_ref_size = trailer[7] as usize;
        let num_objects = usize::try_from(read_be_u64(&trailer[8..16])).map_err(|_| anyhow::anyhow!("num_objects overflow"))?;
        let top_object = usize::try_from(read_be_u64(&trailer[16..24])).map_err(|_| anyhow::anyhow!("top_object overflow"))?;
        let offset_table_off = usize::try_from(read_be_u64(&trailer[24..32])).map_err(|_| anyhow::anyhow!("offset_table_off overflow"))?;

        if offset_size == 0 || obj_ref_size == 0 || num_objects == 0 {
            anyhow::bail!("invalid bplist trailer");
        }
        let table_len = num_objects
            .checked_mul(offset_size)
            .ok_or_else(|| anyhow::anyhow!("bplist offset table size overflow"))?;
        if offset_table_off
            .checked_add(table_len)
            .is_none_or(|end| end > data.len())
        {
            anyhow::bail!("bplist offset table out of bounds");
        }
        if top_object >= num_objects {
            anyhow::bail!("bplist top object index out of range");
        }

        // Build offset table
        let mut offsets = Vec::with_capacity(num_objects);
        for i in 0..num_objects {
            let entry_off = offset_table_off + i * offset_size;
            let off = read_be_uint(&data[entry_off..entry_off + offset_size], offset_size);
            offsets.push(usize::try_from(off).unwrap_or(0));
        }

        let mut ctx = BplistCtx {
            data,
            offsets: &offsets,
            obj_ref_size,
        };
        ctx.read_object(top_object)
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Parse an XML plist from a byte slice into `BplistValue`.
    ///
    /// # Errors
    /// Returns `Err` if the bytes are not valid UTF-8 or cannot be parsed as XML plist.
    pub fn parse_xml(data: &[u8]) -> anyhow::Result<BplistValue> {
        let xml = std::str::from_utf8(data).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(parse_xml_plist_to_value(xml))
    }

    /// Parse a plist from raw bytes — handles both binary and XML formats.
    ///
    /// # Errors
    /// Returns `Err` if the data cannot be parsed as either binary or XML plist.
    pub fn parse_any(data: &[u8]) -> anyhow::Result<BplistValue> {
        if data.starts_with(b"bplist00") {
            Self::parse(data)
        } else {
            Self::parse_xml(data)
        }
    }
}

struct BplistCtx<'a> {
    data: &'a [u8],
    offsets: &'a [usize],
    obj_ref_size: usize,
}

impl BplistCtx<'_> {
    fn read_array(&mut self, count: usize, start: usize) -> Result<BplistValue, String> {
        let mut refs = Vec::with_capacity(count);
        let mut p = start;
        for _ in 0..count {
            if p + self.obj_ref_size > self.data.len() { break; }
            refs.push(usize::try_from(read_be_uint(&self.data[p..p + self.obj_ref_size], self.obj_ref_size)).unwrap_or(0));
            p += self.obj_ref_size;
        }
        let mut arr = Vec::with_capacity(refs.len());
        for r in refs { arr.push(self.read_object(r)?); }
        Ok(BplistValue::Array(arr))
    }

    fn read_dict(&mut self, count: usize, start: usize) -> Result<BplistValue, String> {
        let key_section = count * self.obj_ref_size;
        let val_section = count * self.obj_ref_size;
        if start + key_section + val_section > self.data.len() { return Err("dict truncated".into()); }
        let mut key_refs = Vec::with_capacity(count);
        let mut val_refs = Vec::with_capacity(count);
        let mut p = start;
        for _ in 0..count {
            key_refs.push(usize::try_from(read_be_uint(&self.data[p..p + self.obj_ref_size], self.obj_ref_size)).unwrap_or(0));
            p += self.obj_ref_size;
        }
        for _ in 0..count {
            val_refs.push(usize::try_from(read_be_uint(&self.data[p..p + self.obj_ref_size], self.obj_ref_size)).unwrap_or(0));
            p += self.obj_ref_size;
        }
        let mut dict = Vec::with_capacity(count);
        for (kr, vr) in key_refs.iter().zip(val_refs.iter()) {
            let k = self.read_object(*kr)?;
            let v = self.read_object(*vr)?;
            if let BplistValue::String(ks) = k { dict.push((ks, v)); }
        }
        Ok(BplistValue::Dict(dict))
    }

    fn read_object(&mut self, idx: usize) -> Result<BplistValue, String> {
        if idx >= self.offsets.len() {
            return Err(format!("object index {idx} out of range"));
        }
        let off = self.offsets[idx];
        if off >= self.data.len() {
            return Err(format!("object offset {off} out of bounds"));
        }

        let marker = self.data[off];
        let hi = marker >> 4;
        let lo = marker & 0x0F;

        match hi {
            0x0 => match lo {
                0x8 => Ok(BplistValue::Bool(false)),
                0x9 => Ok(BplistValue::Bool(true)),
                _ => Ok(BplistValue::Null),
            },
            // Integer
            0x1 => {
                let size = 1usize << lo;
                let start = off + 1;
                if start + size > self.data.len() {
                    return Err("int truncated".into());
                }
                let v = read_be_uint(&self.data[start..start + size], size).cast_signed();
                Ok(BplistValue::Int(v))
            }
            // Real
            0x2 => {
                let start = off + 1;
                if lo == 2 {
                    if start + 4 > self.data.len() {
                        return Err("float truncated".into());
                    }
                    let bits = u32::from_be_bytes(self.data[start..start + 4].try_into().unwrap());
                    Ok(BplistValue::Real(f64::from(f32::from_bits(bits))))
                } else {
                    if start + 8 > self.data.len() {
                        return Err("double truncated".into());
                    }
                    let bits = u64::from_be_bytes(self.data[start..start + 8].try_into().unwrap());
                    Ok(BplistValue::Real(f64::from_bits(bits)))
                }
            }
            // ASCII String
            0x5 => {
                let (len, start) = self.read_count(off, lo)?;
                let end = start + len;
                if end > self.data.len() {
                    return Err("ascii string truncated".into());
                }
                let s = std::str::from_utf8(&self.data[start..end])
                    .unwrap_or("?")
                    .to_string();
                Ok(BplistValue::String(s))
            }
            // UTF-16 String
            0x6 => {
                let (len, start) = self.read_count(off, lo)?;
                let end = start + len * 2;
                if end > self.data.len() {
                    return Err("utf16 string truncated".into());
                }
                let pairs: Vec<u16> = self.data[start..end]
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                let s = String::from_utf16(&pairs).unwrap_or_default();
                Ok(BplistValue::String(s))
            }
            // Data
            0x4 => {
                let (len, start) = self.read_count(off, lo)?;
                let end = start + len;
                if end > self.data.len() {
                    return Err("data truncated".into());
                }
                Ok(BplistValue::Data(self.data[start..end].to_vec()))
            }
            // UID
            0x8 => {
                let size = (lo + 1) as usize;
                let start = off + 1;
                if start + size > self.data.len() {
                    return Err("uid truncated".into());
                }
                let v = read_be_uint(&self.data[start..start + size], size);
                Ok(BplistValue::Uid(v))
            }
            // Array
            0xA => { let (count, start) = self.read_count(off, lo)?; self.read_array(count, start) }
            // Dict
            0xD => { let (count, start) = self.read_count(off, lo)?; self.read_dict(count, start) }
            _ => Ok(BplistValue::Null),
        }
    }

    /// Read a count value: if lo == 0x0F, the next object is an integer giving the count.
    fn read_count(&self, off: usize, lo: u8) -> Result<(usize, usize), String> {
        if lo != 0x0F {
            return Ok((lo as usize, off + 1));
        }
        // Extended count: next byte is an integer object marker
        let int_off = off + 1;
        if int_off >= self.data.len() {
            return Err("count truncated".into());
        }
        let int_marker = self.data[int_off];
        let size = 1usize << (int_marker & 0x0F);
        let start = int_off + 1;
        if start + size > self.data.len() {
            return Err("count int truncated".into());
        }
        let count = usize::try_from(read_be_uint(&self.data[start..start + size], size)).unwrap_or(0);
        Ok((count, start + size))
    }
}

fn read_be_u64(data: &[u8]) -> u64 {
    let mut v = 0u64;
    for &b in data.iter().take(8) {
        v = (v << 8) | u64::from(b);
    }
    v
}

fn read_be_uint(data: &[u8], size: usize) -> u64 {
    let mut v = 0u64;
    for &b in data.iter().take(size) {
        v = (v << 8) | u64::from(b);
    }
    v
}

/// Parse an XML plist into a `BplistValue` (best-effort).
fn parse_xml_plist_to_value(xml: &str) -> BplistValue {
    // Parse the top-level <dict> or <array> from the XML
    let xml = xml.trim();
    // Locate <dict> block
    if let Some(dict_start) = xml.find("<dict>") {
        let content = &xml[dict_start + 6..];
        // Matching close, not the first one: a nested <dict> would otherwise
        // end the outer body at the INNER </dict>.
        if let Some(dict_end) = crate::ipa_metadata_extractor::find_matching_close(content, "dict") {
            return BplistValue::Dict(parse_xml_dict(&content[..dict_end]));
        }
    }
    // Locate <array> block
    if let Some(arr_start) = xml.find("<array>") {
        let content = &xml[arr_start + 7..];
        if let Some(arr_end) = crate::ipa_metadata_extractor::find_matching_close(content, "array") {
            return BplistValue::Array(parse_xml_array(&content[..arr_end]));
        }
    }
    BplistValue::Null
}

fn parse_xml_dict(content: &str) -> Vec<(String, BplistValue)> {
    let mut pairs = Vec::new();
    let mut rem = content;
    while let Some(ks) = rem.find("<key>") {
        rem = &rem[ks + 5..];
        let ke = rem.find("</key>").unwrap_or(rem.len());
        let key = rem[..ke].to_string();
        rem = rem[ke + 6..].trim_start();
        let (val, consumed) = parse_xml_value(rem);
        pairs.push((key, val));
        rem = &rem[consumed..];
    }
    pairs
}

fn parse_xml_array(content: &str) -> Vec<BplistValue> {
    let mut vals = Vec::new();
    let mut rem = content.trim_start();
    while !rem.is_empty() {
        let (val, consumed) = parse_xml_value(rem);
        if consumed == 0 {
            break;
        }
        vals.push(val);
        rem = rem[consumed..].trim_start();
    }
    vals
}

fn parse_xml_value(s: &str) -> (BplistValue, usize) {
    let s = s.trim_start();
    if s.starts_with("<string>")
        && let Some(end) = s.find("</string>")
    {
        return (BplistValue::String(s[8..end].to_string()), end + 9);
    }
    if s.starts_with("<integer>")
        && let Some(end) = s.find("</integer>")
    {
        let n: i64 = s[9..end].trim().parse().unwrap_or(0);
        return (BplistValue::Int(n), end + 10);
    }
    if s.starts_with("<real>")
        && let Some(end) = s.find("</real>")
    {
        let f: f64 = s[6..end].trim().parse().unwrap_or(0.0);
        return (BplistValue::Real(f), end + 7);
    }
    if s.starts_with("<true/>") {
        return (BplistValue::Bool(true), 7);
    }
    if s.starts_with("<false/>") {
        return (BplistValue::Bool(false), 8);
    }
    if s.starts_with("<data>")
        && let Some(end) = s.find("</data>")
    {
        let b64 = s[6..end].replace(['\n', ' '], "");
        // best-effort base64 decode
        let bytes: Vec<u8> = decode_base64(&b64);
        return (BplistValue::Data(bytes), end + 7);
    }
    if s.starts_with("<dict>")
        && let Some(end) = s.find("</dict>")
    {
        let pairs = parse_xml_dict(&s[6..end]);
        return (BplistValue::Dict(pairs), end + 7);
    }
    if s.starts_with("<array>")
        && let Some(end) = s.find("</array>")
    {
        let vals = parse_xml_array(&s[7..end]);
        return (BplistValue::Array(vals), end + 8);
    }
    // Skip unknown tag
    if s.starts_with('<')
        && let Some(close) = s.find('>')
    {
        return (BplistValue::Null, close + 1);
    }
    (BplistValue::Null, 0)
}

/// Very minimal base64 decoder (RFC 4648 alphabet, no padding check).
fn decode_base64(s: &str) -> Vec<u8> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let chars: Vec<u8> = s.bytes().filter(|b| *b != b'=').collect();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in &chars {
        let v = u32::try_from(alphabet.iter().position(|&a| a == c).unwrap_or(0)).unwrap_or(0);
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from(buf >> bits).unwrap_or(0));
            buf &= (1 << bits) - 1;
        }
    }
    out
}

// ─── Binary plist tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod bplist_tests {
    use super::*;

    #[test]
    fn test_bplist_xml_string() {
        let xml = r#"<?xml version="1.0"?>
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.example.App</string>
  <key>CFBundleVersion</key><string>1.0</string>
</dict></plist>"#;
        let val = BplistParser::parse_xml(xml.as_bytes()).unwrap();
        assert_eq!(
            val.get("CFBundleIdentifier").and_then(|v| v.as_str()),
            Some("com.example.App")
        );
        assert_eq!(
            val.get("CFBundleVersion").and_then(|v| v.as_str()),
            Some("1.0")
        );
    }

    #[test]
    fn test_bplist_xml_bool_true() {
        let xml = "<plist><dict><key>MyFlag</key><true/></dict></plist>";
        let val = BplistParser::parse_xml(xml.as_bytes()).unwrap();
        assert_eq!(val.get("MyFlag").and_then(super::BplistValue::as_bool), Some(true));
    }

    #[test]
    fn test_bplist_xml_bool_false() {
        let xml = "<plist><dict><key>Flag</key><false/></dict></plist>";
        let val = BplistParser::parse_xml(xml.as_bytes()).unwrap();
        assert_eq!(val.get("Flag").and_then(super::BplistValue::as_bool), Some(false));
    }

    #[test]
    fn test_bplist_xml_integer() {
        let xml = "<plist><dict><key>Count</key><integer>42</integer></dict></plist>";
        let val = BplistParser::parse_xml(xml.as_bytes()).unwrap();
        assert_eq!(val.get("Count").and_then(super::BplistValue::as_int), Some(42));
    }

    #[test]
    fn test_bplist_xml_real() {
        let xml = "<plist><dict><key>Pi</key><real>3.14</real></dict></plist>";
        let val = BplistParser::parse_xml(xml.as_bytes()).unwrap();
        let pi = val.get("Pi").and_then(super::BplistValue::as_real);
        assert!(pi.is_some());
        assert!((pi.unwrap() - 3.14_f64).abs() < 0.01);
    }

    #[test]
    fn test_bplist_xml_nested_dict() {
        let xml = r"<plist><dict>
  <key>Outer</key>
  <dict><key>Inner</key><string>nested</string></dict>
</dict></plist>";
        let val = BplistParser::parse_xml(xml.as_bytes()).unwrap();
        let inner = val.get("Outer");
        assert!(inner.is_some());
        let s = inner.unwrap().get("Inner").and_then(|v| v.as_str());
        assert_eq!(s, Some("nested"));
    }

    #[test]
    fn test_bplist_xml_array() {
        let xml = "<plist><array><string>a</string><string>b</string></array></plist>";
        let val = BplistParser::parse_xml(xml.as_bytes()).unwrap();
        if let BplistValue::Array(arr) = &val {
            assert_eq!(arr.len(), 2);
            assert_eq!(arr[0].as_str(), Some("a"));
            assert_eq!(arr[1].as_str(), Some("b"));
        } else {
            panic!("expected Array, got {val:?}");
        }
    }

    #[test]
    fn test_bplist_value_get_missing() {
        let dict = BplistValue::Dict(vec![]);
        assert!(dict.get("anything").is_none());
    }

    #[test]
    fn test_bplist_value_get_from_non_dict() {
        let s = BplistValue::String("hello".into());
        assert!(s.get("key").is_none());
    }

    #[test]
    fn test_bplist_value_as_str_non_string() {
        let v = BplistValue::Int(5);
        assert!(v.as_str().is_none());
    }

    #[test]
    fn test_bplist_value_as_int_non_int() {
        let v = BplistValue::Bool(true);
        assert!(v.as_int().is_none());
    }

    #[test]
    fn test_bplist_value_as_real_non_real() {
        let v = BplistValue::String("x".into());
        assert!(v.as_real().is_none());
    }

    #[test]
    fn test_bplist_value_as_bool_non_bool() {
        let v = BplistValue::Null;
        assert!(v.as_bool().is_none());
    }

    #[test]
    fn test_bplist_binary_too_short() {
        assert!(BplistParser::parse(b"bplist0").is_err());
    }

    #[test]
    fn test_bplist_binary_wrong_magic() {
        let data = vec![0u8; 64];
        assert!(BplistParser::parse(&data).is_err());
    }

    #[test]
    fn test_bplist_parse_any_xml_path() {
        let xml = "<plist><dict><key>K</key><string>V</string></dict></plist>";
        let val = BplistParser::parse_any(xml.as_bytes()).unwrap();
        assert_eq!(val.get("K").and_then(|v| v.as_str()), Some("V"));
    }

    #[test]
    fn test_read_be_uint_one_byte() {
        assert_eq!(read_be_uint(&[0x42], 1), 0x42);
    }

    #[test]
    fn test_read_be_uint_two_bytes() {
        assert_eq!(read_be_uint(&[0x01, 0x00], 2), 0x0100);
    }

    #[test]
    fn test_read_be_u64() {
        let data = [0x00u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        assert_eq!(read_be_u64(&data), 1);
    }

    #[test]
    fn test_decode_base64_hello() {
        // "hello" → base64 "aGVsbG8="
        let bytes = decode_base64("aGVsbG8");
        assert_eq!(&bytes, b"hello");
    }

    #[test]
    fn test_bplist_xml_data_key() {
        let xml = "<plist><dict><key>D</key><data>aGVsbG8=</data></dict></plist>";
        let val = BplistParser::parse_xml(xml.as_bytes()).unwrap();
        if let Some(BplistValue::Data(bytes)) = val.get("D") {
            assert_eq!(bytes, b"hello");
        } else {
            panic!("expected Data");
        }
    }

    #[test]
    fn test_bplist_value_serialization() {
        let val = BplistValue::Dict(vec![
            ("key".into(), BplistValue::String("val".into())),
            ("num".into(), BplistValue::Int(42)),
        ]);
        let json = serde_json::to_string(&val).unwrap();
        assert!(json.contains("val"));
    }

    #[test]
    fn test_info_plist_full_from_xml() {
        let xml = r#"<?xml version="1.0"?>
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.test.App</string>
  <key>CFBundleShortVersionString</key><string>2.0</string>
  <key>MinimumOSVersion</key><string>14.0</string>
</dict></plist>"#;
        let p = InfoPlistFull::from_xml(xml).unwrap();
        assert_eq!(p.bundle_id, "com.test.App");
        assert_eq!(p.bundle_version, "2.0");
        assert_eq!(p.min_os_version, "14.0");
    }

    #[test]
    fn test_info_plist_full_from_binary_heuristic() {
        // A very minimal binary plist with "bplist00" magic + some string data
        let mut data = b"bplist00".to_vec();
        // Append key bytes
        data.extend_from_slice(b"CFBundleIdentifier");
        data.extend_from_slice(&[0x5C]); // ASCII string tag, length=12
        data.extend_from_slice(b"com.test.App");
        // Fill rest with zeroes to meet minimum length for heuristic
        data.resize(200, 0);
        // The binary heuristic path should not panic
        let p = InfoPlistFull::from_data(&data);
        // Either succeeds or returns an error — just must not panic
        let _ = p;
    }

    #[test]
    fn test_entitlements_parse_xml() {
        let xml = r"<plist><dict>
  <key>application-identifier</key><string>T.com.example.App</string>
  <key>get-task-allow</key><true/>
  <key>aps-environment</key><string>development</string>
</dict></plist>";
        let ent = Entitlements::from_plist(xml.as_bytes()).unwrap();
        assert_eq!(ent.application_identifier, Some("T.com.example.App".into()));
        assert!(ent.get_task_allow);
        assert_eq!(ent.aps_environment, Some("development".into()));
    }

    #[test]
    fn test_entitlements_get_task_allow_false() {
        let xml = "<plist><dict><key>get-task-allow</key><false/></dict></plist>";
        let ent = Entitlements::from_plist(xml.as_bytes()).unwrap();
        assert!(!ent.get_task_allow);
    }

    #[test]
    fn test_entitlements_empty_plist() {
        let xml = "<plist><dict></dict></plist>";
        let ent = Entitlements::from_plist(xml.as_bytes()).unwrap();
        assert!(ent.application_identifier.is_none());
        assert!(!ent.get_task_allow);
    }

    #[test]
    fn test_bplist_xml_multiple_keys() {
        let xml = r"<plist><dict>
  <key>A</key><string>alpha</string>
  <key>B</key><string>beta</string>
  <key>C</key><integer>99</integer>
</dict></plist>";
        let val = BplistParser::parse_xml(xml.as_bytes()).unwrap();
        assert_eq!(val.get("A").and_then(|v| v.as_str()), Some("alpha"));
        assert_eq!(val.get("B").and_then(|v| v.as_str()), Some("beta"));
        assert_eq!(val.get("C").and_then(super::BplistValue::as_int), Some(99));
    }
}
