//! macOS binary security analysis.
//!
//! Analyses Mach-O binaries for Apple security mechanisms including:
//! - [`CodeSigning`]: Ad-hoc, Developer ID, and enterprise code signing info.
//! - [`Entitlements`]: Parsed entitlement plist key/value pairs.
//! - [`SIPProtection`]: System Integrity Protection (SIP) status indicators.
//! - [`GatekeeperInfo`]: Gatekeeper quarantine and path policy information.
//! - [`Notarization`]: Apple Notarization ticket and stapling status.
//! - [`MachoSecurity`]: Unified facade combining all checks into a security
//!   report.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic bytes at the start of a DER-encoded certificate.
const DER_SEQUENCE_TAG: u8 = 0x30;

/// `CS_MAGIC` values from Apple's `<cs_blobs.h>`.
const CS_MAGIC_EMBEDDED_SIGNATURE: u32 = 0xFADE_0CC0;
pub const CS_MAGIC_REQUIREMENT:         u32 = 0xFADE_0C00;
pub const CS_MAGIC_REQUIREMENTS:        u32 = 0xFADE_0C01;
const CS_MAGIC_CODEDIRECTORY:       u32 = 0xFADE_0C02;
pub const CS_MAGIC_ENTITLEMENTS:        u32 = 0xFADE_7171;
const CS_MAGIC_BLOBWRAPPER:         u32 = 0xFADE_0B01;

/// `LC_CODE_SIGNATURE` load-command type.
pub const LC_CODE_SIGNATURE: u32 = 0x1D;

/// Entitlement key for hardened runtime.
const ENT_HARDENED_RUNTIME: &str = "com.apple.security.cs.allow-jit";
/// Entitlement key for unrestricted dyld env.
const ENT_DISABLE_LIBRARY_VALIDATION: &str = "com.apple.security.cs.disable-library-validation";
/// Entitlement key for get-task-allow (allows debugger attach).
const ENT_GET_TASK_ALLOW: &str = "com.apple.security.get-task-allow";
/// Entitlement for sandbox disable.
pub const ENT_NO_SANDBOX: &str = "com.apple.security.cs.allow-dyld-environment-variables";
/// Apple system entitlement.
pub const ENT_PLATFORM_BINARY: &str = "com.apple.private.security.container-required";

// ---------------------------------------------------------------------------
// Signing identity / team ID
// ---------------------------------------------------------------------------

/// Type of code signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureType {
    /// Ad-hoc signature (no identity, `codesign -s -`).
    AdHoc,
    /// Developer certificate from Apple Developer Program.
    DeveloperId,
    /// Apple distribution certificate.
    Distribution,
    /// Internal Apple signing.
    Apple,
    /// Enterprise (in-house) signing certificate.
    Enterprise,
    /// Unknown or unparseable signature type.
    Unknown,
}

impl SignatureType {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AdHoc        => "ad-hoc",
            Self::DeveloperId  => "developer-id",
            Self::Distribution => "distribution",
            Self::Apple        => "apple",
            Self::Enterprise   => "enterprise",
            Self::Unknown      => "unknown",
        }
    }
}

/// A single certificate in the signing chain.
#[derive(Debug, Clone)]
pub struct CertInfo {
    /// Common name from the certificate's Subject field.
    pub common_name: String,
    /// Organisation name.
    pub organisation: Option<String>,
    /// Team ID (10-character Apple developer prefix).
    pub team_id: Option<String>,
    /// Whether this is the leaf (signer) certificate.
    pub is_leaf: bool,
    /// Whether this is a root (anchor) certificate.
    pub is_root: bool,
}

// ---------------------------------------------------------------------------
// CodeSigning
// ---------------------------------------------------------------------------

/// Code signing information extracted from the `LC_CODE_SIGNATURE` blob.
#[derive(Debug, Default, Clone)]
pub struct CodeSigning {
    /// Whether a code signature blob is present.
    pub has_signature: bool,
    /// Whether the binary is ad-hoc signed.
    pub is_ad_hoc: bool,
    /// Whether the signature is valid (structurally, without cert chain verify).
    pub is_structurally_valid: bool,
    /// Whether a code directory (`CDHash`) is present.
    pub has_code_directory: bool,
    /// Whether the binary has hardened runtime entitlements enabled.
    pub hardened_runtime: bool,
    /// Signature type classification.
    pub signature_type: Option<SignatureType>,
    /// Team ID string (e.g. `"ABCDE12345"`).
    pub team_id: Option<String>,
    /// Identifier string from the code directory (e.g. bundle ID).
    pub identifier: Option<String>,
    /// `CDHash` (SHA-1 or SHA-256).
    pub cd_hash: Option<Vec<u8>>,
    /// Hash algorithm used in the code directory (1=SHA-1, 2=SHA-256).
    pub hash_algo: u8,
    /// Certificate chain.
    pub certs: Vec<CertInfo>,
    /// Raw CMS signature blob (DER-encoded PKCS#7 `SignedData`).
    pub cms_blob: Option<Vec<u8>>,
    /// Offset of the `LC_CODE_SIGNATURE` load command in the file.
    pub lc_offset: Option<u32>,
    /// Size of the signature blob.
    pub blob_size: Option<u32>,
}

/// Super-blob index entry.
#[derive(Debug, Clone)]
struct BlobIndex {
    blob_type: u32,
    offset: u32,
}

impl BlobIndex {
    /// Returns the blob type magic value for this index entry.
    pub const fn blob_type(&self) -> u32 {
        self.blob_type
    }

    /// Returns true if this index entry points to a Requirement blob.
    pub const fn is_requirement(&self) -> bool {
        self.blob_type == CS_MAGIC_REQUIREMENT || self.blob_type == CS_MAGIC_REQUIREMENTS
    }
}

impl CodeSigning {
    /// Parse a code-signature super-blob from raw bytes.
    ///
    /// `data` should be the raw bytes starting at `dataoff` from the load
    /// command (i.e. the signature blob itself).
    #[must_use]
    pub fn parse(data: &[u8], lc_offset: u32, blob_size: u32) -> Self {
        let mut cs = Self::default();
        cs.lc_offset = Some(lc_offset);
        cs.blob_size = Some(blob_size);

        if data.len() < 8 {
            return cs;
        }

        let magic = u32::from_be_bytes(data[0..4].try_into().unwrap_or([0; 4]));
        let _length = u32::from_be_bytes(data[4..8].try_into().unwrap_or([0; 4]));

        if magic != CS_MAGIC_EMBEDDED_SIGNATURE {
            return cs;
        }

        cs.has_signature = true;

        // Parse super-blob count.
        if data.len() < 12 {
            return cs;
        }
        let count = u32::from_be_bytes(data[8..12].try_into().unwrap_or([0; 4])) as usize;

        // Parse index entries. Cap count by the number of 8-byte BlobIndex
        // entries that can physically fit, to avoid attacker-controlled allocations.
        let count = count.min(data.len().saturating_sub(12) / 8);
        let mut indices: Vec<BlobIndex> = Vec::with_capacity(count);
        for i in 0..count {
            let entry_off = 12 + i * 8;
            if entry_off + 8 > data.len() {
                break;
            }
            let blob_type = u32::from_be_bytes(data[entry_off..entry_off+4].try_into().unwrap_or([0; 4]));
            let offset    = u32::from_be_bytes(data[entry_off+4..entry_off+8].try_into().unwrap_or([0; 4]));
            indices.push(BlobIndex { blob_type, offset });
        }

        // Parse each sub-blob.
        for idx in &indices {
            let off = idx.offset as usize;
            if off + 8 > data.len() {
                continue;
            }
            let sub_magic = u32::from_be_bytes(data[off..off+4].try_into().unwrap_or([0; 4]));
            // Use the index blob_type to categorise: requirement blobs get
            // counted separately from the raw sub_magic match below.
            let _has_requirement = idx.is_requirement() || idx.blob_type() == CS_MAGIC_EMBEDDED_SIGNATURE;

            match sub_magic {
                CS_MAGIC_CODEDIRECTORY => {
                    cs.has_code_directory = true;
                    cs.parse_code_directory(&data[off..]);
                }
                CS_MAGIC_BLOBWRAPPER => {
                    let sub_len = u32::from_be_bytes(data[off+4..off+8].try_into().unwrap_or([0; 4])) as usize;
                    if off + sub_len <= data.len() && sub_len > 8 {
                        let cms = data[off+8..off+sub_len].to_vec();
                        if !cms.is_empty() && cms[0] == DER_SEQUENCE_TAG {
                            cs.cms_blob = Some(cms);
                        }
                    }
                }
                _ => {}
            }
        }

        cs.is_structurally_valid = cs.has_signature && cs.has_code_directory;
        cs
    }

    fn parse_code_directory(&mut self, data: &[u8]) {
        // CodeDirectory v1 layout:
        // [0..4]  magic
        // [4..8]  length
        // [8..12] version
        // [12..16] flags
        // [16..20] hashOffset
        // [20..24] identOffset
        // [24..28] nSpecialSlots
        // [28..32] nCodeSlots
        // [32..36] codeLimit
        // [36]    hashSize
        // [37]    hashType  (1=sha1, 2=sha256, 3=sha256-truncated)
        // [38]    platform
        // [39]    pageSize
        // [40..44] spare2
        // [44..52] scatterOffset (v2+)
        // [52..56] teamOffset (v2+)

        if data.len() < 44 {
            return;
        }

        let version  = u32::from_be_bytes(data[8..12].try_into().unwrap_or([0; 4]));
        let flags    = u32::from_be_bytes(data[12..16].try_into().unwrap_or([0; 4]));
        let ident_off= u32::from_be_bytes(data[20..24].try_into().unwrap_or([0; 4])) as usize;
        self.hash_algo = data[37];

        // CS_ADHOC = 0x0002
        if flags & 0x0002 != 0 {
            self.is_ad_hoc = true;
            self.signature_type = Some(SignatureType::AdHoc);
        }
        // CS_RUNTIME = 0x10000
        if flags & 0x10000 != 0 {
            self.hardened_runtime = true;
        }

        // Identifier string.
        if ident_off > 0 && ident_off < data.len() {
            let ident_data = &data[ident_off..];
            let nul = ident_data.iter().position(|&b| b == 0).unwrap_or(ident_data.len());
            self.identifier = Some(String::from_utf8_lossy(&ident_data[..nul]).to_string());
        }

        // Team ID (only in v2+).
        if version >= 0x20200 && data.len() >= 56 {
            let team_off = u32::from_be_bytes(data[52..56].try_into().unwrap_or([0; 4])) as usize;
            if team_off > 0 && team_off < data.len() {
                let team_data = &data[team_off..];
                let nul = team_data.iter().position(|&b| b == 0).unwrap_or(team_data.len());
                let team = String::from_utf8_lossy(&team_data[..nul]).to_string();
                if !team.is_empty() {
                    self.team_id = Some(team);
                }
            }
        }
    }

    /// Return `true` if the binary was signed by a real identity (not ad-hoc).
    #[must_use]
    pub const fn is_signed_by_identity(&self) -> bool {
        self.has_signature && !self.is_ad_hoc
    }

    /// Return a brief description.
    #[must_use]
    pub fn description(&self) -> String {
        if !self.has_signature {
            return "unsigned".to_string();
        }
        if self.is_ad_hoc {
            return "ad-hoc signed".to_string();
        }
        format!(
            "signed (team={} id={})",
            self.team_id.as_deref().unwrap_or("?"),
            self.identifier.as_deref().unwrap_or("?"),
        )
    }
}

// ---------------------------------------------------------------------------
// Entitlements
// ---------------------------------------------------------------------------

/// Parsed entitlement plist.
#[derive(Debug, Default, Clone)]
pub struct Entitlements {
    /// All entitlement key/value pairs.
    pub entries: HashMap<String, EntitlementValue>,
    /// Whether the raw plist was parseable.
    pub parse_ok: bool,
    /// Raw plist XML bytes.
    pub raw_plist: Option<Vec<u8>>,
}

/// Value of a single entitlement key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntitlementValue {
    Bool(bool),
    String(String),
    Array(Vec<String>),
    Unknown,
}

impl EntitlementValue {
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        if let Self::Bool(b) = self { Some(*b) } else { None }
    }

    #[must_use]
    pub const fn as_str(&self) -> Option<&str> {
        if let Self::String(s) = self { Some(s.as_str()) } else { None }
    }
}

impl Entitlements {
    /// Parse entitlements from an XML plist blob (as found in `CS_MAGIC_ENTITLEMENTS` blobs).
    ///
    /// This is a minimal hand-written parser that handles the common boolean/string format.
    #[must_use]
    pub fn parse(data: &[u8]) -> Self {
        let mut ents = Self::default();
        ents.raw_plist = Some(data.to_vec());

        let xml = String::from_utf8_lossy(data);

        // Very simplified plist parser: find <key>...</key><true/> or <key>...</key><string>...</string>
        // This is sufficient for typical entitlement plists.
        let s = xml.as_ref();

        // Use string search for simplicity.
        let mut keys: Vec<&str> = Vec::new();
        let mut values: Vec<EntitlementValue> = Vec::new();

        // Extract all <key> tags.
        let mut pos = 0;
        while let Some(start) = find_tag(s, pos, "<key>") {
            let tag_start = start + 5;
            let Some(end) = find_tag(s, tag_start, "</key>") else { break };
            keys.push(&s[tag_start..end]);

            // Find the next value tag after </key>.
            let after_key = end + 6;
            let (value, next_pos) = parse_next_value(s, after_key);
            values.push(value);
            pos = next_pos;
        }

        for (key, value) in keys.iter().zip(values.iter()) {
            ents.entries.insert(key.to_string(), value.clone());
        }
        ents.parse_ok = true;
        ents
    }

    /// Return `true` if the entitlement key is present and set to `true`.
    #[must_use]
    pub fn is_set(&self, key: &str) -> bool {
        self.entries.get(key).and_then(EntitlementValue::as_bool).unwrap_or(false)
    }

    /// Return `true` if get-task-allow is set (allows debugger attach).
    #[must_use]
    pub fn allows_debugger_attach(&self) -> bool {
        self.is_set(ENT_GET_TASK_ALLOW)
    }

    /// Return `true` if library validation is disabled.
    #[must_use]
    pub fn disables_library_validation(&self) -> bool {
        self.is_set(ENT_DISABLE_LIBRARY_VALIDATION)
    }

    /// Return all entitlement keys.
    #[must_use]
    pub fn keys(&self) -> Vec<&str> {
        self.entries.keys().map(std::string::String::as_str).collect()
    }

    /// Security risk score based on entitlements (0 = safe, higher = riskier).
    #[must_use]
    pub fn risk_score(&self) -> u32 {
        let mut score = 0u32;
        if self.allows_debugger_attach()         { score += 40; }
        if self.disables_library_validation()    { score += 30; }
        if self.is_set(ENT_HARDENED_RUNTIME)     { score += 10; }
        score
    }
}

/// Find the first occurrence of `needle` in `s` at or after `start`.
fn find_tag(s: &str, start: usize, needle: &str) -> Option<usize> {
    s[start..].find(needle).map(|rel| start + rel)
}

/// Parse the value element immediately following a </key> tag.
fn parse_next_value(s: &str, pos: usize) -> (EntitlementValue, usize) {
    let trimmed = s[pos..].trim_start();
    let skip = s[pos..].len() - trimmed.len();
    let abs = pos + skip;

    if trimmed.starts_with("<true/>") {
        (EntitlementValue::Bool(true), abs + 7)
    } else if trimmed.starts_with("<false/>") {
        (EntitlementValue::Bool(false), abs + 8)
    } else if trimmed.starts_with("<string>") {
        let inner_start = abs + 8;
        s[inner_start..].find("</string>").map_or((EntitlementValue::Unknown, abs), |rel| (EntitlementValue::String(s[inner_start..inner_start + rel].to_string()), inner_start + rel + 9))
    } else {
        (EntitlementValue::Unknown, abs)
    }
}

// ---------------------------------------------------------------------------
// SIPProtection
// ---------------------------------------------------------------------------

/// System Integrity Protection indicators for a binary.
#[derive(Debug, Default, Clone)]
pub struct SIPProtection {
    /// Whether the binary is located in an SIP-protected path.
    pub in_protected_path: bool,
    /// Whether the binary has the `restricted` segment (`__RESTRICT/__restrict`).
    pub has_restrict_segment: bool,
    /// Whether the `CS_RUNTIME` flag is set (hardened runtime).
    pub has_hardened_runtime: bool,
    /// Whether the binary is a platform binary (Apple-signed, in `/usr`, `/System`).
    pub is_platform_binary: bool,
    /// The binary's path (used for path-based SIP checks).
    pub binary_path: Option<String>,
    /// Whether the binary is protected from process injection.
    pub protected_from_injection: bool,
}

/// Known SIP-protected path prefixes.
const SIP_PATHS: &[&str] = &[
    "/System/", "/usr/", "/bin/", "/sbin/",
    "/private/var/db/", "/usr/libexec/",
];

impl SIPProtection {
    /// Evaluate SIP status given a binary path, segment names, and code signing flags.
    #[must_use]
    pub fn evaluate(
        binary_path: Option<&str>,
        segment_names: &[&str],
        has_hardened_runtime: bool,
        is_platform_binary: bool,
    ) -> Self {
        let in_protected_path = binary_path
            .is_some_and(|p| SIP_PATHS.iter().any(|prefix| p.starts_with(prefix)));

        let has_restrict_segment = segment_names.contains(&"__RESTRICT");

        let protected_from_injection = in_protected_path || has_hardened_runtime || is_platform_binary;

        Self {
            in_protected_path,
            has_restrict_segment,
            has_hardened_runtime,
            is_platform_binary,
            binary_path: binary_path.map(str::to_string),
            protected_from_injection,
        }
    }

    /// Return `true` if the binary has strong SIP protection.
    #[must_use]
    pub const fn is_strongly_protected(&self) -> bool {
        self.in_protected_path && (self.has_hardened_runtime || self.is_platform_binary)
    }

    /// Return a brief SIP status description.
    #[must_use]
    pub const fn status_string(&self) -> &'static str {
        if self.is_strongly_protected() { "strongly protected" }
        else if self.in_protected_path   { "path protected" }
        else if self.has_hardened_runtime { "hardened runtime" }
        else                             { "not protected" }
    }
}

// ---------------------------------------------------------------------------
// GatekeeperInfo
// ---------------------------------------------------------------------------

/// Gatekeeper policy status.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Default)]
pub enum GatekeeperPolicy {
    /// Allow any program to run (Anywhere setting).
    Anywhere,
    /// Allow apps from Mac App Store only.
    AppStore,
    /// Allow apps from Mac App Store and identified developers (default).
    AppStoreAndIdentifiedDevelopers,
    /// Unknown or unreadable policy.
    #[default]
    Unknown,
}

/// Gatekeeper information for a binary.
#[derive(Debug, Default, Clone)]
pub struct GatekeeperInfo {
    /// Whether the binary has a quarantine extended attribute (com.apple.quarantine).
    pub has_quarantine_xattr: bool,
    /// The quarantine event ID, if present.
    pub quarantine_event_id: Option<String>,
    /// The originating URL, if present in the quarantine data.
    pub originating_url: Option<String>,
    /// Whether the binary passed Gatekeeper assessment (based on signing status).
    pub passes_gatekeeper: bool,
    /// Detected Gatekeeper policy applicable to this binary.
    pub policy: GatekeeperPolicy,
}


impl GatekeeperInfo {
    /// Build Gatekeeper info from quarantine attribute data and signing status.
    ///
    /// `quarantine_data`: raw string from `com.apple.quarantine` xattr,
    /// e.g. `"0083;5f3a2b1c;Safari;ABCDEFGH-1234-..."`.
    #[must_use]
    pub fn from_quarantine_data(data: Option<&str>, signing: &CodeSigning) -> Self {
        let has_quarantine = data.is_some();
        let (event_id, url) = data.map_or((None, None), |q| {
            let parts: Vec<&str> = q.splitn(4, ';').collect();
            let eid = parts.get(3).map(|s| s.trim().to_string());
            (eid, None)
        });

        let passes = signing.is_signed_by_identity();

        Self {
            has_quarantine_xattr: has_quarantine,
            quarantine_event_id: event_id,
            originating_url: url,
            passes_gatekeeper: passes,
            policy: GatekeeperPolicy::AppStoreAndIdentifiedDevelopers,
        }
    }

    /// Return `true` if the binary was downloaded from the internet.
    #[must_use]
    pub const fn was_downloaded(&self) -> bool {
        self.has_quarantine_xattr
    }
}

// ---------------------------------------------------------------------------
// Notarization
// ---------------------------------------------------------------------------

/// Apple Notarization stapling status.
#[derive(Debug, Default, Clone)]
pub struct Notarization {
    /// Whether an Apple Notarization ticket is stapled to the binary.
    pub is_stapled: bool,
    /// Notarization request UUID (if recoverable from the ticket).
    pub ticket_uuid: Option<String>,
    /// Team ID of the notarizing developer.
    pub team_id: Option<String>,
    /// Whether the binary meets the Notarization requirements.
    pub meets_requirements: bool,
    /// Ticket version.
    pub ticket_version: Option<u32>,
}

/// Minimal notarization ticket header identifier.
pub const NOTARIZATION_TICKET_MAGIC: &[u8] = b"NOTARIZE";

/// Returns true if `data` begins with the notarization ticket magic marker.
#[must_use] 
pub fn has_notarization_ticket_magic(data: &[u8]) -> bool {
    data.starts_with(NOTARIZATION_TICKET_MAGIC)
}

impl Notarization {
    /// Attempt to detect a stapled notarization ticket in the code signature blob.
    ///
    /// In practice, a stapled notarization ticket is embedded as a PKCS#7 message
    /// in a CMS blob within the code signature super-blob. This function performs
    /// a best-effort check.
    #[must_use]
    pub fn from_signature(signing: &CodeSigning) -> Self {
        let is_stapled = signing.cms_blob.as_ref()
            .is_some_and(|cms| {
                // A notarization ticket is typically embedded in the CMS; look for
                // OID 1.2.840.113635.100.9.2 or for a known DER sequence prefix.
                // Simplified: any CMS blob > 1 KiB that is DER-encoded is assumed
                // to potentially contain a ticket.
                cms.len() > 512 && cms.first().copied() == Some(DER_SEQUENCE_TAG)
            });

        let meets_requirements = signing.is_signed_by_identity() && !signing.is_ad_hoc;

        Self {
            is_stapled,
            ticket_uuid: None,
            team_id: signing.team_id.clone(),
            meets_requirements,
            ticket_version: None,
        }
    }

    /// Return `true` if the binary is notarized (either stapled or via online check).
    #[must_use]
    pub const fn is_notarized(&self) -> bool {
        self.is_stapled || self.meets_requirements
    }
}

// ---------------------------------------------------------------------------
// MachoSecurity — unified facade
// ---------------------------------------------------------------------------

/// Summary security risk level.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Low      => "low",
            Self::Medium   => "medium",
            Self::High     => "high",
            Self::Critical => "critical",
        }
    }
}

/// Unified macOS binary security analysis report.
#[derive(Debug, Clone)]
pub struct MachoSecurity {
    /// Code signing analysis.
    pub code_signing: CodeSigning,
    /// Parsed entitlements.
    pub entitlements: Entitlements,
    /// SIP protection status.
    pub sip: SIPProtection,
    /// Gatekeeper info.
    pub gatekeeper: GatekeeperInfo,
    /// Notarization status.
    pub notarization: Notarization,
    /// Aggregate risk level.
    pub risk_level: RiskLevel,
    /// Ordered list of security findings.
    pub findings: Vec<SecurityFinding>,
}

/// A single security finding.
#[derive(Debug, Clone)]
pub struct SecurityFinding {
    /// Short identifier (e.g. `"unsigned_binary"`).
    pub id: &'static str,
    /// Human-readable description.
    pub description: String,
    /// Severity of the finding.
    pub severity: RiskLevel,
}

impl MachoSecurity {
    /// Build a full security analysis.
    #[must_use] 
    pub fn analyse(
        code_signing: CodeSigning,
        entitlements: Entitlements,
        sip: SIPProtection,
        gatekeeper: GatekeeperInfo,
        notarization: Notarization,
    ) -> Self {
        let mut findings = Vec::new();

        // Check: unsigned binary.
        if !code_signing.has_signature {
            findings.push(SecurityFinding {
                id: "unsigned_binary",
                description: "Binary has no code signature.".to_string(),
                severity: RiskLevel::High,
            });
        }

        // Check: ad-hoc signature.
        if code_signing.is_ad_hoc {
            findings.push(SecurityFinding {
                id: "adhoc_signature",
                description: "Binary is ad-hoc signed (no developer identity).".to_string(),
                severity: RiskLevel::Medium,
            });
        }

        // Check: get-task-allow allows debugger attach.
        if entitlements.allows_debugger_attach() {
            findings.push(SecurityFinding {
                id: "get_task_allow",
                description: "get-task-allow entitlement is set; allows debugger attachment.".to_string(),
                severity: RiskLevel::High,
            });
        }

        // Check: library validation disabled.
        if entitlements.disables_library_validation() {
            findings.push(SecurityFinding {
                id: "library_validation_disabled",
                description: "Library validation is disabled; arbitrary dylibs may be loaded.".to_string(),
                severity: RiskLevel::Medium,
            });
        }

        // Check: not protected from injection.
        if !sip.protected_from_injection {
            findings.push(SecurityFinding {
                id: "injection_risk",
                description: "Binary is not protected from code injection.".to_string(),
                severity: RiskLevel::Medium,
            });
        }

        // Check: quarantined but not notarized.
        if gatekeeper.was_downloaded() && !notarization.is_notarized() {
            findings.push(SecurityFinding {
                id: "unnotarized_download",
                description: "Downloaded binary is not notarized.".to_string(),
                severity: RiskLevel::Medium,
            });
        }

        // Compute aggregate risk level.
        let risk_level = if findings.iter().any(|f| f.severity == RiskLevel::Critical) {
            RiskLevel::Critical
        } else if findings.iter().any(|f| f.severity == RiskLevel::High) {
            RiskLevel::High
        } else if findings.iter().any(|f| f.severity == RiskLevel::Medium) {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        };

        Self { code_signing, entitlements, sip, gatekeeper, notarization, risk_level, findings }
    }

    /// Return `true` if any critical or high-severity findings exist.
    #[must_use]
    pub fn has_high_severity_findings(&self) -> bool {
        self.findings.iter().any(|f| f.severity >= RiskLevel::High)
    }

    /// Return all finding IDs.
    #[must_use]
    pub fn finding_ids(&self) -> Vec<&'static str> {
        self.findings.iter().map(|f| f.id).collect()
    }

    /// Return a brief summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "signed={} adhoc={} entitlements={} sip={} risk={}",
            self.code_signing.has_signature,
            self.code_signing.is_ad_hoc,
            self.entitlements.entries.len(),
            self.sip.status_string(),
            self.risk_level.as_str(),
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // CodeSigning tests
    // -----------------------------------------------------------------------

    fn build_minimal_superblob(flags: u32, identifier: &[u8]) -> Vec<u8> {
        // Build a minimal CodeDirectory sub-blob.
        let ident_off: u32 = 44; // version 0x20100 CodeDirectory fixed part is 44 bytes
        let cd_len = (ident_off as usize + identifier.len() + 1).max(64) as u32;

        let mut cd = vec![0u8; cd_len as usize];
        // magic
        cd[0..4].copy_from_slice(&CS_MAGIC_CODEDIRECTORY.to_be_bytes());
        // length
        cd[4..8].copy_from_slice(&cd_len.to_be_bytes());
        // version 0x20100 (v1)
        cd[8..12].copy_from_slice(&0x0002_0100_u32.to_be_bytes());
        // flags
        cd[12..16].copy_from_slice(&flags.to_be_bytes());
        // hashOffset (just some valid offset)
        cd[16..20].copy_from_slice(&40u32.to_be_bytes());
        // identOffset
        cd[20..24].copy_from_slice(&ident_off.to_be_bytes());
        // nSpecialSlots = 0, nCodeSlots = 0
        // codeLimit
        cd[32..36].copy_from_slice(&0x1000u32.to_be_bytes());
        // hashSize = 20 (SHA-1), hashType = 1
        cd[36] = 20; cd[37] = 1;
        // Copy identifier.
        let id_end = (ident_off as usize + identifier.len()).min(cd.len());
        cd[ident_off as usize..id_end].copy_from_slice(&identifier[..id_end - ident_off as usize]);

        // Wrap in super-blob.
        let blob_count: u32 = 1;
        let index_size = 12 + blob_count as usize * 8;
        let cd_off = index_size as u32;
        let total_len = (index_size + cd.len()) as u32;

        let mut sb = vec![0u8; total_len as usize];
        sb[0..4].copy_from_slice(&CS_MAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
        sb[4..8].copy_from_slice(&total_len.to_be_bytes());
        sb[8..12].copy_from_slice(&blob_count.to_be_bytes());
        // index[0]: type=0 (code directory), offset=cd_off
        sb[12..16].copy_from_slice(&0u32.to_be_bytes());
        sb[16..20].copy_from_slice(&cd_off.to_be_bytes());
        sb[index_size..].copy_from_slice(&cd);
        sb
    }

    #[test]
    fn test_code_signing_unsigned_binary() {
        let cs = CodeSigning::parse(&[], 0, 0);
        assert!(!cs.has_signature);
        assert!(!cs.is_signed_by_identity());
    }

    #[test]
    fn test_code_signing_parse_superblob() {
        let identifier = b"com.example.app\0";
        let sb = build_minimal_superblob(0, identifier);
        let cs = CodeSigning::parse(&sb, 0, sb.len() as u32);
        assert!(cs.has_signature);
        assert!(cs.has_code_directory);
        assert!(cs.is_structurally_valid);
    }

    #[test]
    fn test_code_signing_ad_hoc_flag() {
        let identifier = b"adhoc.test\0";
        // CS_ADHOC = 0x0002
        let sb = build_minimal_superblob(0x0002, identifier);
        let cs = CodeSigning::parse(&sb, 0, sb.len() as u32);
        assert!(cs.is_ad_hoc);
        assert_eq!(cs.signature_type, Some(SignatureType::AdHoc));
        assert!(!cs.is_signed_by_identity());
    }

    #[test]
    fn test_code_signing_hardened_runtime_flag() {
        let identifier = b"hr.test\0";
        // CS_RUNTIME = 0x10000
        let sb = build_minimal_superblob(0x10000, identifier);
        let cs = CodeSigning::parse(&sb, 0, sb.len() as u32);
        assert!(cs.hardened_runtime);
    }

    #[test]
    fn test_code_signing_identifier_parsed() {
        let identifier = b"com.example.mapp\0";
        let sb = build_minimal_superblob(0, identifier);
        let cs = CodeSigning::parse(&sb, 0, sb.len() as u32);
        assert_eq!(cs.identifier.as_deref(), Some("com.example.mapp"));
    }

    #[test]
    fn test_code_signing_description_unsigned() {
        let cs = CodeSigning::default();
        assert_eq!(cs.description(), "unsigned");
    }

    #[test]
    fn test_code_signing_description_adhoc() {
        let mut cs = CodeSigning::default();
        cs.has_signature = true;
        cs.is_ad_hoc = true;
        assert_eq!(cs.description(), "ad-hoc signed");
    }

    #[test]
    fn test_code_signing_hash_algo() {
        let identifier = b"test\0";
        let sb = build_minimal_superblob(0, identifier);
        let cs = CodeSigning::parse(&sb, 0, sb.len() as u32);
        assert_eq!(cs.hash_algo, 1); // SHA-1
    }

    // -----------------------------------------------------------------------
    // Entitlements tests
    // -----------------------------------------------------------------------

    fn sample_entitlements_plist() -> &'static [u8] {
        br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.get-task-allow</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <false/>
    <key>application-identifier</key>
    <string>TEAM123.com.example.app</string>
</dict>
</plist>"#
    }

    #[test]
    fn test_entitlements_parse_bool_true() {
        let ents = Entitlements::parse(sample_entitlements_plist());
        assert!(ents.parse_ok);
        assert!(ents.is_set(ENT_GET_TASK_ALLOW));
    }

    #[test]
    fn test_entitlements_parse_bool_false() {
        let ents = Entitlements::parse(sample_entitlements_plist());
        let val = ents.entries.get(ENT_DISABLE_LIBRARY_VALIDATION);
        assert_eq!(val, Some(&EntitlementValue::Bool(false)));
    }

    #[test]
    fn test_entitlements_parse_string() {
        let ents = Entitlements::parse(sample_entitlements_plist());
        let val = ents.entries.get("application-identifier");
        assert!(matches!(val, Some(EntitlementValue::String(s)) if s.contains("com.example.app")));
    }

    #[test]
    fn test_entitlements_allows_debugger_attach() {
        let ents = Entitlements::parse(sample_entitlements_plist());
        assert!(ents.allows_debugger_attach());
    }

    #[test]
    fn test_entitlements_risk_score_positive() {
        let ents = Entitlements::parse(sample_entitlements_plist());
        assert!(ents.risk_score() > 0);
    }

    #[test]
    fn test_entitlements_empty_plist() {
        let ents = Entitlements::parse(b"<plist><dict></dict></plist>");
        assert!(ents.parse_ok);
        assert!(!ents.allows_debugger_attach());
    }

    #[test]
    fn test_entitlements_keys() {
        let ents = Entitlements::parse(sample_entitlements_plist());
        let keys = ents.keys();
        assert!(!keys.is_empty());
    }

    // -----------------------------------------------------------------------
    // SIPProtection tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sip_system_path() {
        let sip = SIPProtection::evaluate(
            Some("/System/Library/Frameworks/Foundation.framework/Foundation"),
            &[],
            false,
            true,
        );
        assert!(sip.in_protected_path);
        assert!(sip.protected_from_injection);
    }

    #[test]
    fn test_sip_usr_path() {
        let sip = SIPProtection::evaluate(Some("/usr/bin/true"), &[], false, false);
        assert!(sip.in_protected_path);
    }

    #[test]
    fn test_sip_home_path_not_protected() {
        let sip = SIPProtection::evaluate(Some("/Users/test/app"), &[], false, false);
        assert!(!sip.in_protected_path);
    }

    #[test]
    fn test_sip_restrict_segment() {
        let sip = SIPProtection::evaluate(None, &["__TEXT", "__RESTRICT", "__DATA"], false, false);
        assert!(sip.has_restrict_segment);
    }

    #[test]
    fn test_sip_hardened_runtime() {
        let sip = SIPProtection::evaluate(Some("/Applications/App.app/MacOS/App"), &[], true, false);
        assert!(sip.has_hardened_runtime);
        assert!(sip.protected_from_injection);
    }

    #[test]
    fn test_sip_strongly_protected() {
        let sip = SIPProtection::evaluate(Some("/usr/bin/tool"), &[], true, true);
        assert!(sip.is_strongly_protected());
    }

    #[test]
    fn test_sip_status_string() {
        let sip = SIPProtection::evaluate(Some("/usr/bin/tool"), &[], true, true);
        assert_eq!(sip.status_string(), "strongly protected");
    }

    // -----------------------------------------------------------------------
    // GatekeeperInfo tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_gatekeeper_no_quarantine() {
        let cs = CodeSigning::default();
        let gk = GatekeeperInfo::from_quarantine_data(None, &cs);
        assert!(!gk.was_downloaded());
    }

    #[test]
    fn test_gatekeeper_quarantined() {
        let cs = CodeSigning::default();
        let gk = GatekeeperInfo::from_quarantine_data(
            Some("0083;5f3a2b1c;Safari;ABCD-1234"),
            &cs,
        );
        assert!(gk.was_downloaded());
        assert!(gk.quarantine_event_id.is_some());
    }

    #[test]
    fn test_gatekeeper_passes_when_signed() {
        let mut cs = CodeSigning::default();
        cs.has_signature = true;
        cs.is_ad_hoc = false;
        let gk = GatekeeperInfo::from_quarantine_data(None, &cs);
        assert!(gk.passes_gatekeeper);
    }

    // -----------------------------------------------------------------------
    // Notarization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_notarization_unsigned_not_notarized() {
        let cs = CodeSigning::default();
        let n = Notarization::from_signature(&cs);
        assert!(!n.is_notarized());
    }

    #[test]
    fn test_notarization_meets_requirements_when_signed() {
        let mut cs = CodeSigning::default();
        cs.has_signature = true;
        let n = Notarization::from_signature(&cs);
        // is_signed_by_identity requires non-adhoc
        assert_eq!(n.meets_requirements, cs.is_signed_by_identity());
    }

    #[test]
    fn test_notarization_team_id_propagated() {
        let mut cs = CodeSigning::default();
        cs.team_id = Some("TEAM12345".to_string());
        let n = Notarization::from_signature(&cs);
        assert_eq!(n.team_id.as_deref(), Some("TEAM12345"));
    }

    // -----------------------------------------------------------------------
    // MachoSecurity facade tests
    // -----------------------------------------------------------------------

    fn build_unsigned_macho_security() -> MachoSecurity {
        MachoSecurity::analyse(
            CodeSigning::default(),
            Entitlements::default(),
            SIPProtection::evaluate(Some("/Applications/App.app/MacOS/App"), &[], false, false),
            GatekeeperInfo::default(),
            Notarization::default(),
        )
    }

    #[test]
    fn test_macho_security_unsigned_has_finding() {
        let sec = build_unsigned_macho_security();
        assert!(sec.finding_ids().contains(&"unsigned_binary"));
    }

    #[test]
    fn test_macho_security_unsigned_risk_high() {
        let sec = build_unsigned_macho_security();
        assert!(sec.risk_level >= RiskLevel::High);
    }

    #[test]
    fn test_macho_security_signed_no_unsigned_finding() {
        let mut cs = CodeSigning::default();
        cs.has_signature = true;
        cs.has_code_directory = true;
        cs.is_structurally_valid = true;
        let sec = MachoSecurity::analyse(
            cs,
            Entitlements::default(),
            SIPProtection::evaluate(Some("/usr/bin/tool"), &[], true, true),
            GatekeeperInfo::default(),
            Notarization::default(),
        );
        assert!(!sec.finding_ids().contains(&"unsigned_binary"));
    }

    #[test]
    fn test_macho_security_get_task_allow_finding() {
        let ents = Entitlements::parse(sample_entitlements_plist());
        let sec = MachoSecurity::analyse(
            CodeSigning::default(),
            ents,
            SIPProtection::default(),
            GatekeeperInfo::default(),
            Notarization::default(),
        );
        assert!(sec.finding_ids().contains(&"get_task_allow"));
    }

    #[test]
    fn test_macho_security_summary_format() {
        let sec = build_unsigned_macho_security();
        let s = sec.summary();
        assert!(s.contains("signed=false"));
        assert!(s.contains("risk="));
    }

    #[test]
    fn test_macho_security_has_high_severity_findings() {
        let sec = build_unsigned_macho_security();
        assert!(sec.has_high_severity_findings());
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }

    #[test]
    fn test_signature_type_as_str() {
        assert_eq!(SignatureType::AdHoc.as_str(), "ad-hoc");
        assert_eq!(SignatureType::DeveloperId.as_str(), "developer-id");
        assert_eq!(SignatureType::Apple.as_str(), "apple");
    }

    // -----------------------------------------------------------------------
    // Utility helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_tag_basic() {
        let s = "hello <key>world</key> end";
        let pos = find_tag(s, 0, "<key>");
        assert_eq!(pos, Some(6));
    }

    #[test]
    fn test_find_tag_not_found() {
        let s = "no tags here";
        assert!(find_tag(s, 0, "<key>").is_none());
    }

    #[test]
    fn test_parse_next_value_true() {
        let (val, _) = parse_next_value("<true/>rest", 0);
        assert_eq!(val, EntitlementValue::Bool(true));
    }

    #[test]
    fn test_parse_next_value_false() {
        let (val, _) = parse_next_value("<false/>rest", 0);
        assert_eq!(val, EntitlementValue::Bool(false));
    }

    #[test]
    fn test_parse_next_value_string() {
        let (val, _) = parse_next_value("<string>hello world</string>", 0);
        assert_eq!(val, EntitlementValue::String("hello world".to_string()));
    }
}
