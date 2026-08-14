//! IPA entitlement analyzer — parses entitlement plists embedded in Mach-O
//! binaries or provisioning profiles and classifies each entitlement by its
//! security risk level.
//!
//! Entitlements are key-value pairs granted to an iOS application by Apple.
//! Some entitlements confer powerful capabilities (e.g. `com.apple.security.
//! network.client` for outbound network access, or `platform-application` for
//! direct kernel access) that are relevant when reverse-engineering an app's
//! attack surface.
//!
//! # Example
//! ```rust,ignore
//! let xml = std::fs::read("entitlements.plist").unwrap();
//! let analyzer = IpaEntitlementAnalyzer::new();
//! let result = analyzer.analyze_xml(&xml).unwrap();
//! for risk in result.risks_by_level(RiskLevel::High) {
//!     println!("HIGH: {}", risk.key);
//! }
//! ```

use std::collections::HashMap;

// ── Risk level ────────────────────────────────────────────────────────────────

/// Severity classification of an entitlement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum RiskLevel {
    /// Informational — no direct security implication.
    Info = 0,
    /// Low risk — commonly granted, limited attack surface.
    Low = 1,
    /// Medium risk — notable capability, worth auditing.
    Medium = 2,
    /// High risk — significant capability that enlarges the attack surface.
    High = 3,
    /// Critical — typically reserved for privileged / platform applications.
    Critical = 4,
}

impl RiskLevel {
    /// Return the level as a human-readable label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

// ── EntitlementKind ───────────────────────────────────────────────────────────

/// Broad category of an entitlement.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EntitlementKind {
    /// Access to a hardware sensor or radio.
    Hardware,
    /// Network access (inbound or outbound).
    Network,
    /// Filesystem access beyond the app container.
    Filesystem,
    /// Inter-process communication or shared memory.
    Ipc,
    /// Keychain sharing.
    Keychain,
    /// Push notification capability.
    PushNotifications,
    /// App group or shared data container.
    AppGroup,
    /// Access to `HealthKit`.
    Health,
    /// Access to `HomeKit`.
    HomeKit,
    /// Access to wallet / Apple Pay.
    Wallet,
    /// Platform-application or kernel-level entitlement.
    Platform,
    /// Developer or debugging capability.
    Developer,
    /// Entitlement team identifier.
    TeamId,
    /// Entitlement not matching any known category.
    Unknown,
}

// ── EntitlementRisk ───────────────────────────────────────────────────────────

/// A single entitlement and its assessed risk.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntitlementRisk {
    /// The full entitlement key string.
    pub key: String,
    /// The raw value as it appeared in the plist (stringified).
    pub value: String,
    /// Risk severity.
    pub level: RiskLevel,
    /// Broad category.
    pub kind: EntitlementKind,
    /// Human-readable description of why this level was assigned.
    pub rationale: String,
    /// Whether this entitlement is specific to an Apple internal / platform
    /// build (rarely seen in App Store binaries).
    pub is_platform_only: bool,
}

// ── AnalysisError ─────────────────────────────────────────────────────────────

/// Errors produced by [`IpaEntitlementAnalyzer`].
#[derive(Debug)]
pub enum AnalysisError {
    /// Input bytes are not valid UTF-8.
    Utf8(String),
    /// The plist XML is malformed or missing the expected structure.
    Parse(String),
    /// No entitlements dict was found in the input.
    Empty,
}

impl std::fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Utf8(s) => write!(f, "UTF-8 error: {s}"),
            Self::Parse(s) => write!(f, "plist parse error: {s}"),
            Self::Empty => write!(f, "no entitlements found"),
        }
    }
}

impl std::error::Error for AnalysisError {}

// ── AnalysisResult ────────────────────────────────────────────────────────────

/// The result of analyzing an entitlements plist.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnalysisResult {
    /// All entitlements with their risk classifications.
    pub entries: Vec<EntitlementRisk>,
    /// Overall maximum risk level across all entitlements.
    pub max_level: RiskLevel,
    /// Total number of entitlement keys.
    pub total: usize,
    /// Number of entitlements classified as High or Critical.
    pub high_plus_count: usize,
}

impl AnalysisResult {
    /// Return all [`EntitlementRisk`] items whose level is `>= min_level`.
    #[must_use]
    pub fn risks_by_level(&self, min_level: RiskLevel) -> Vec<&EntitlementRisk> {
        self.entries
            .iter()
            .filter(|r| r.level >= min_level)
            .collect()
    }

    /// Return all entries of a given [`EntitlementKind`].
    #[must_use]
    pub fn by_kind(&self, kind: &EntitlementKind) -> Vec<&EntitlementRisk> {
        self.entries.iter().filter(|r| &r.kind == kind).collect()
    }

    /// Return `true` if any Critical entitlement was found.
    #[must_use]
    pub fn has_critical(&self) -> bool {
        self.max_level == RiskLevel::Critical
    }

    /// Return a map of risk level → count.
    #[must_use]
    pub fn level_histogram(&self) -> HashMap<String, usize> {
        let mut map: HashMap<String, usize> = HashMap::new();
        for e in &self.entries {
            *map.entry(e.level.label().to_string()).or_insert(0) += 1;
        }
        map
    }
}

// ── Known-entitlement database ────────────────────────────────────────────────

struct EntitlementRule {
    prefix: &'static str,
    level: RiskLevel,
    kind: EntitlementKind,
    rationale: &'static str,
    platform_only: bool,
}

/// Static database of known entitlements with pre-assigned risk levels.
static RULES: &[EntitlementRule] = &[
    // ── Platform / kernel ────────────────────────────────────────────────────
    EntitlementRule {
        prefix: "platform-application",
        level: RiskLevel::Critical,
        kind: EntitlementKind::Platform,
        rationale: "Grants direct kernel-level access; only present in Apple system daemons.",
        platform_only: true,
    },
    EntitlementRule {
        prefix: "com.apple.private.security.no-sandbox",
        level: RiskLevel::Critical,
        kind: EntitlementKind::Platform,
        rationale: "Disables the iOS sandbox; exclusive to Apple internal builds.",
        platform_only: true,
    },
    EntitlementRule {
        prefix: "com.apple.private.",
        level: RiskLevel::High,
        kind: EntitlementKind::Platform,
        rationale: "Private Apple entitlement not available to third-party apps.",
        platform_only: true,
    },
    EntitlementRule {
        prefix: "com.apple.security.cs.disable-library-validation",
        level: RiskLevel::High,
        kind: EntitlementKind::Developer,
        rationale: "Allows loading of unsigned dynamic libraries.",
        platform_only: false,
    },
    EntitlementRule {
        prefix: "com.apple.security.cs.allow-unsigned-executable-memory",
        level: RiskLevel::High,
        kind: EntitlementKind::Developer,
        rationale: "Allows writing and executing unsigned memory pages.",
        platform_only: false,
    },
    // ── Network ──────────────────────────────────────────────────────────────
    EntitlementRule {
        prefix: "com.apple.security.network.server",
        level: RiskLevel::Medium,
        kind: EntitlementKind::Network,
        rationale: "App can accept inbound network connections.",
        platform_only: false,
    },
    EntitlementRule {
        prefix: "com.apple.security.network.client",
        level: RiskLevel::Low,
        kind: EntitlementKind::Network,
        rationale: "App can open outbound network connections.",
        platform_only: false,
    },
    // ── Filesystem ───────────────────────────────────────────────────────────
    EntitlementRule {
        prefix: "com.apple.security.files.user-selected.read-write",
        level: RiskLevel::Medium,
        kind: EntitlementKind::Filesystem,
        rationale: "App can read and write user-selected files.",
        platform_only: false,
    },
    EntitlementRule {
        prefix: "com.apple.security.files.downloads.read-write",
        level: RiskLevel::Medium,
        kind: EntitlementKind::Filesystem,
        rationale: "App can read and write the Downloads folder.",
        platform_only: false,
    },
    EntitlementRule {
        prefix: "com.apple.security.temporary-exception.files",
        level: RiskLevel::High,
        kind: EntitlementKind::Filesystem,
        rationale: "Temporary exception granting access to arbitrary file paths.",
        platform_only: false,
    },
    // ── IPC / XPC ────────────────────────────────────────────────────────────
    EntitlementRule {
        prefix: "com.apple.security.temporary-exception.mach-lookup.global-name",
        level: RiskLevel::High,
        kind: EntitlementKind::Ipc,
        rationale: "Grants access to global Mach services not normally reachable from sandbox.",
        platform_only: false,
    },
    EntitlementRule {
        prefix: "com.apple.security.temporary-exception.shared-preference",
        level: RiskLevel::Medium,
        kind: EntitlementKind::Ipc,
        rationale: "Access to preferences domains of other apps.",
        platform_only: false,
    },
    // ── Keychain ─────────────────────────────────────────────────────────────
    EntitlementRule {
        prefix: "keychain-access-groups",
        level: RiskLevel::Medium,
        kind: EntitlementKind::Keychain,
        rationale: "Declares the keychain access groups this app participates in.",
        platform_only: false,
    },
    // ── Push notifications ───────────────────────────────────────────────────
    EntitlementRule {
        prefix: "aps-environment",
        level: RiskLevel::Low,
        kind: EntitlementKind::PushNotifications,
        rationale: "App is registered for Apple Push Notification service.",
        platform_only: false,
    },
    // ── App groups ───────────────────────────────────────────────────────────
    EntitlementRule {
        prefix: "com.apple.security.application-groups",
        level: RiskLevel::Low,
        kind: EntitlementKind::AppGroup,
        rationale: "App participates in a shared data container.",
        platform_only: false,
    },
    // ── Health ───────────────────────────────────────────────────────────────
    EntitlementRule {
        prefix: "com.apple.developer.healthkit",
        level: RiskLevel::Medium,
        kind: EntitlementKind::Health,
        rationale: "App can read or write HealthKit data.",
        platform_only: false,
    },
    // ── HomeKit ──────────────────────────────────────────────────────────────
    EntitlementRule {
        prefix: "com.apple.developer.homekit",
        level: RiskLevel::Medium,
        kind: EntitlementKind::HomeKit,
        rationale: "App can control HomeKit accessories.",
        platform_only: false,
    },
    // ── Wallet ───────────────────────────────────────────────────────────────
    EntitlementRule {
        prefix: "com.apple.developer.payment-pass-provisioning",
        level: RiskLevel::High,
        kind: EntitlementKind::Wallet,
        rationale: "App can provision payment passes to Apple Wallet.",
        platform_only: false,
    },
    EntitlementRule {
        prefix: "com.apple.developer.pass-type-identifiers",
        level: RiskLevel::Medium,
        kind: EntitlementKind::Wallet,
        rationale: "App manages Wallet passes.",
        platform_only: false,
    },
    // ── Hardware ─────────────────────────────────────────────────────────────
    EntitlementRule {
        prefix: "com.apple.developer.nfc.readersession.formats",
        level: RiskLevel::Medium,
        kind: EntitlementKind::Hardware,
        rationale: "App can access the NFC reader.",
        platform_only: false,
    },
    EntitlementRule {
        prefix: "com.apple.developer.driverkit",
        level: RiskLevel::Critical,
        kind: EntitlementKind::Hardware,
        rationale: "App ships a DriverKit system extension with kernel-adjacent access.",
        platform_only: false,
    },
    // ── Developer ────────────────────────────────────────────────────────────
    EntitlementRule {
        prefix: "com.apple.security.get-task-allow",
        level: RiskLevel::High,
        kind: EntitlementKind::Developer,
        rationale: "Allows other processes to get the task port (debugger attach).",
        platform_only: false,
    },
    EntitlementRule {
        prefix: "com.apple.developer.kernel.increased-memory-limit",
        level: RiskLevel::Low,
        kind: EntitlementKind::Developer,
        rationale: "App is allowed higher physical memory limits.",
        platform_only: false,
    },
    // ── Team ID ──────────────────────────────────────────────────────────────
    EntitlementRule {
        prefix: "com.apple.developer.team-identifier",
        level: RiskLevel::Info,
        kind: EntitlementKind::TeamId,
        rationale: "Identifies the developer team; informational only.",
        platform_only: false,
    },
    EntitlementRule {
        prefix: "application-identifier",
        level: RiskLevel::Info,
        kind: EntitlementKind::TeamId,
        rationale: "Full application identifier (team + bundle ID); informational.",
        platform_only: false,
    },
];

static FALLBACK_RULE: EntitlementRule = EntitlementRule {
    prefix: "",
    level: RiskLevel::Info,
    kind: EntitlementKind::Unknown,
    rationale: "Unknown entitlement; requires manual review.",
    platform_only: false,
};

fn classify(key: &str) -> (&'static EntitlementRule, bool) {
    // Try longest-prefix match.
    let mut best: Option<&EntitlementRule> = None;
    for rule in RULES {
        if key.starts_with(rule.prefix) {
            match best {
                None => best = Some(rule),
                Some(b) if rule.prefix.len() > b.prefix.len() => best = Some(rule),
                _ => {}
            }
        }
    }
    best.map_or((&FALLBACK_RULE, true), |r| (r, false))
}

// ── IpaEntitlementAnalyzer ────────────────────────────────────────────────────

/// Analyzes entitlements embedded in an IPA or provisioning profile.
pub struct IpaEntitlementAnalyzer {
    /// When `true`, entitlements whose level is `Info` are included in the
    /// output (default: `true`).
    pub include_informational: bool,
    /// When `true`, unknown entitlements are flagged at `Medium` risk rather
    /// than `Info` (more conservative analysis).
    pub conservative: bool,
}

impl Default for IpaEntitlementAnalyzer {
    fn default() -> Self {
        Self { include_informational: true, conservative: false }
    }
}

impl IpaEntitlementAnalyzer {
    /// Create an analyzer with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a conservative analyzer that treats unknown entitlements as Medium
    /// risk and suppresses informational entries.
    #[must_use]
    pub const fn conservative() -> Self {
        Self { include_informational: false, conservative: true }
    }

    /// Analyze an entitlements plist from its raw XML bytes.
    ///
    /// # Errors
    /// Returns an error if the bytes are not valid UTF-8 or the plist is empty or malformed.
    pub fn analyze_xml(&self, xml: &[u8]) -> Result<AnalysisResult, AnalysisError> {
        let text = std::str::from_utf8(xml)
            .map_err(|e| AnalysisError::Utf8(e.to_string()))?;

        let kv = parse_entitlements_xml(text)?;
        if kv.is_empty() {
            return Err(AnalysisError::Empty);
        }
        Ok(self.build_result(&kv))
    }

    /// Analyze a pre-parsed map of entitlement key → value strings.
    #[must_use]
    pub fn analyze_map(&self, kv: &HashMap<String, String>) -> AnalysisResult {
        self.build_result(kv)
    }

    fn build_result(&self, kv: &HashMap<String, String>) -> AnalysisResult {
        let mut entries: Vec<EntitlementRisk> = Vec::new();
        let mut max_level = RiskLevel::Info;

        for (key, value) in kv {
            let (rule, _is_fallback) = classify(key);
            let mut level = rule.level;
            if self.conservative && level == RiskLevel::Info && rule.kind == EntitlementKind::Unknown {
                level = RiskLevel::Medium;
            }
            if !self.include_informational && level == RiskLevel::Info {
                continue;
            }
            if level > max_level {
                max_level = level;
            }
            entries.push(EntitlementRisk {
                key: key.clone(),
                value: value.clone(),
                level,
                kind: rule.kind.clone(),
                rationale: rule.rationale.to_string(),
                is_platform_only: rule.platform_only,
            });
        }

        // Sort: highest risk first, then alphabetically.
        entries.sort_by(|a, b| b.level.cmp(&a.level).then(a.key.cmp(&b.key)));

        let high_plus_count = entries
            .iter()
            .filter(|e| e.level >= RiskLevel::High)
            .count();
        let total = kv.len();

        AnalysisResult { entries, max_level, total, high_plus_count }
    }
}

// ── Minimal XML entitlements parser ──────────────────────────────────────────
// Parses a flat key-value dict from XML plist (values flattened to strings).

fn parse_entitlements_xml(xml: &str) -> Result<HashMap<String, String>, AnalysisError> {
    // Locate the outermost <dict>.
    let dict_start = xml
        .find("<dict>")
        .ok_or_else(|| AnalysisError::Parse("no <dict> element found".into()))?;
    let body_start = dict_start + 6;
    let dict_end = xml[body_start..]
        .find("</dict>")
        .map(|p| body_start + p)
        .ok_or_else(|| AnalysisError::Parse("no </dict> found".into()))?;
    let body = &xml[body_start..dict_end];

    let mut map = HashMap::new();
    let mut rest = body;

    while let Some(key_start) = rest.find("<key>") {
        let key_content_start = key_start + 5;
        let key_end = rest[key_content_start..]
            .find("</key>")
            .map(|p| key_content_start + p);
        let Some(key_end) = key_end else { break };
        let key = rest[key_content_start..key_end].trim().to_string();
        rest = &rest[key_end + 6..];

        // Parse the next non-whitespace element as the value.
        let value = extract_next_value(rest);
        // Advance past the value element.
        rest = advance_past_value(rest);
        map.insert(key, value);
    }

    Ok(map)
}

/// Extract the text content of the next plist value element (stringified).
fn extract_next_value(src: &str) -> String {
    let src = src.trim_start();
    if src.starts_with("<true") {
        return "true".to_string();
    }
    if src.starts_with("<false") {
        return "false".to_string();
    }
    if src.starts_with("<array>") {
        return extract_array_strings(src);
    }
    // For string, integer, real, date: read content between open and close tag.
    let tag_end = src.find('>').unwrap_or(src.len());
    let tag = src[1..tag_end.min(src.len())].split_whitespace().next().unwrap_or("");
    let close = format!("</{tag}>");
    let content_start = tag_end + 1;
    src[content_start..].find(&close).map_or_else(String::new, |rel| src[content_start..content_start + rel].trim().to_string())
}

fn extract_array_strings(src: &str) -> String {
    let inner_start = src.find('>').map_or(src.len(), |p| p + 1);
    let inner_end = src.find("</array>").unwrap_or(src.len());
    let inner = &src[inner_start..inner_end];
    let mut items = Vec::new();
    let mut rest = inner;
    while let Some(s) = rest.find("<string>") {
        let content_start = s + 8;
        if let Some(e) = rest[content_start..].find("</string>") {
            items.push(rest[content_start..content_start + e].trim().to_string());
            rest = &rest[content_start + e + 9..];
        } else {
            break;
        }
    }
    format!("[{}]", items.join(", "))
}

/// Advance `src` past the next value element.
fn advance_past_value(src: &str) -> &str {
    let s = src.trim_start();
    if s.starts_with("<true/>") || s.starts_with("<true />") {
        return &s[7..];
    }
    if s.starts_with("<false/>") || s.starts_with("<false />") {
        return &s[8..];
    }
    if s.starts_with("<array>") {
        if let Some(end) = s.find("</array>") {
            return &s[end + 8..];
        }
        return s;
    }
    // Generic open-close tag.
    let tag_end = s.find('>').unwrap_or(s.len());
    let tag = s[1..tag_end.min(s.len())]
        .split_whitespace()
        .next()
        .unwrap_or("");
    let close = format!("</{tag}>");
    let content_start = tag_end + 1;
    s[content_start..].find(&close).map_or(s, |rel| &s[content_start + rel + close.len()..])
}

// ── Mach-O entitlement extraction ────────────────────────────────────────────

/// Extract the entitlements XML blob from a Mach-O binary.
///
/// The entitlements are embedded as a `LC_CODE_SIGNATURE`-linked blob of type
/// `CSMAGIC_ENTITLEMENTS` (0xFADE7171).  The function locates it by scanning
/// the raw binary for the magic bytes.
///
/// Returns the raw XML bytes, or `None` if no entitlement blob is found.
#[must_use] 
pub fn extract_entitlements_from_macho(data: &[u8]) -> Option<Vec<u8>> {
    const ENTITLEMENTS_MAGIC: u32 = 0xFADE_7171;
    let magic_bytes = ENTITLEMENTS_MAGIC.to_be_bytes();

    let start = data.windows(4).position(|w| w == magic_bytes)?;
    // Layout: [4] magic, [4] length, [N] XML bytes.
    if start + 8 > data.len() {
        return None;
    }
    let length = u32::from_be_bytes(data[start + 4..start + 8].try_into().ok()?) as usize;
    let xml_start = start + 8;
    let xml_end = (xml_start + length.saturating_sub(8)).min(data.len());
    if xml_end <= xml_start {
        return None;
    }
    Some(data[xml_start..xml_end].to_vec())
}

// ── App Store compliance checker ──────────────────────────────────────────────

/// Check entitlements against App Store submission policy.
///
/// Use [`AppStoreComplianceChecker::check`] on an [`AnalysisResult`] to obtain
/// a list of [`ComplianceViolation`]s.  Violations with severity
/// [`ViolationSeverity::Reject`] will cause App Store review rejection;
/// [`ViolationSeverity::Warn`] entries require Apple approval to pass review.
pub struct AppStoreComplianceChecker;

impl AppStoreComplianceChecker {
    /// Entitlements that are NEVER allowed in App Store submissions.
    const FORBIDDEN: &'static [&'static str] = &[
        "get-task-allow",
        "platform-application",
        "com.apple.private.security.no-sandbox",
        "com.apple.private.security.no-container",
        "com.apple.private.skip-library-validation",
        "com.apple.private.security.all-files",
    ];

    /// Check an [`AnalysisResult`] for App Store policy violations.
    #[must_use]
    pub fn check(result: &AnalysisResult) -> Vec<ComplianceViolation> {
        let mut violations = Vec::new();
        let keys: std::collections::HashSet<&str> =
            result.entries.iter().map(|e| e.key.as_str()).collect();

        for &forbidden in Self::FORBIDDEN {
            if keys.contains(forbidden) {
                violations.push(ComplianceViolation {
                    key: forbidden.to_string(),
                    severity: ViolationSeverity::Reject,
                    reason: format!("{forbidden} is not permitted in App Store submissions"),
                });
            }
        }

        // Flag all private entitlements not already listed as forbidden.
        for entry in &result.entries {
            if entry.is_platform_only && !violations.iter().any(|v| v.key == entry.key) {
                violations.push(ComplianceViolation {
                    key: entry.key.clone(),
                    severity: ViolationSeverity::Warn,
                    reason: "Private Apple entitlements require explicit Apple approval".into(),
                });
            }
        }

        violations
    }
}

/// A single App Store compliance violation.
#[derive(Debug, Clone)]
pub struct ComplianceViolation {
    pub key: String,
    pub severity: ViolationSeverity,
    pub reason: String,
}

/// Severity of a compliance violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationSeverity {
    /// App will be rejected.
    Reject,
    /// App may be rejected or flagged for Apple review.
    Warn,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entitlements_xml(pairs: &[(&str, &str)]) -> String {
        let mut s = String::from(
            r#"<?xml version="1.0"?>
<plist version="1.0">
<dict>
"#,
        );
        for (k, v) in pairs {
            s.push_str(&format!("    <key>{k}</key>\n    <string>{v}</string>\n"));
        }
        s.push_str("</dict>\n</plist>\n");
        s
    }

    #[test]
    fn test_basic_analysis() {
        let xml = make_entitlements_xml(&[
            ("application-identifier", "TEAM.com.example.App"),
            ("com.apple.security.network.client", "1"),
        ]);
        let analyzer = IpaEntitlementAnalyzer::new();
        let result = analyzer.analyze_xml(xml.as_bytes()).unwrap();
        assert_eq!(result.total, 2);
        assert!(result.max_level >= RiskLevel::Low);
    }

    #[test]
    fn test_platform_entitlement_critical() {
        let xml = make_entitlements_xml(&[("platform-application", "true")]);
        let analyzer = IpaEntitlementAnalyzer::new();
        let result = analyzer.analyze_xml(xml.as_bytes()).unwrap();
        assert!(result.has_critical());
        assert_eq!(result.high_plus_count, 1);
    }

    #[test]
    fn test_risks_by_level_filter() {
        let xml = make_entitlements_xml(&[
            ("application-identifier", "TEAM.com.example"),
            ("com.apple.security.get-task-allow", "true"),
            ("com.apple.security.network.client", "true"),
        ]);
        let analyzer = IpaEntitlementAnalyzer::new();
        let result = analyzer.analyze_xml(xml.as_bytes()).unwrap();
        let highs = result.risks_by_level(RiskLevel::High);
        assert!(!highs.is_empty());
        assert!(highs.iter().all(|r| r.level >= RiskLevel::High));
    }

    #[test]
    fn test_conservative_mode() {
        // An unknown entitlement should be Medium in conservative mode.
        let xml = make_entitlements_xml(&[
            ("com.example.custom.entitlement", "value"),
        ]);
        let analyzer = IpaEntitlementAnalyzer::conservative();
        let result = analyzer.analyze_xml(xml.as_bytes()).unwrap();
        // conservative suppresses Info; custom → Medium
        assert!(result.entries.iter().any(|e| e.level == RiskLevel::Medium));
    }

    #[test]
    fn test_no_info_in_conservative() {
        let xml = make_entitlements_xml(&[
            ("application-identifier", "TEAM.com.example"),
        ]);
        let analyzer = IpaEntitlementAnalyzer::conservative();
        let result = analyzer.analyze_xml(xml.as_bytes()).unwrap();
        // application-identifier is Info and should be excluded.
        assert!(!result.entries.iter().any(|e| e.key == "application-identifier"));
    }

    #[test]
    fn test_level_histogram() {
        let xml = make_entitlements_xml(&[
            ("application-identifier", "TEAM.com.x"),
            ("com.apple.security.network.client", "true"),
            ("platform-application", "true"),
        ]);
        let result = IpaEntitlementAnalyzer::new()
            .analyze_xml(xml.as_bytes())
            .unwrap();
        let hist = result.level_histogram();
        assert!(hist.contains_key("CRITICAL"));
        assert!(hist.contains_key("LOW"));
    }

    #[test]
    fn test_by_kind_network() {
        let xml = make_entitlements_xml(&[
            ("com.apple.security.network.client", "true"),
            ("com.apple.security.network.server", "true"),
        ]);
        let result = IpaEntitlementAnalyzer::new()
            .analyze_xml(xml.as_bytes())
            .unwrap();
        let net = result.by_kind(&EntitlementKind::Network);
        assert_eq!(net.len(), 2);
    }

    #[test]
    fn test_analyze_map() {
        let mut map = HashMap::new();
        map.insert(
            "keychain-access-groups".to_string(),
            "[TEAM.com.example]".to_string(),
        );
        map.insert(
            "aps-environment".to_string(),
            "production".to_string(),
        );
        let result = IpaEntitlementAnalyzer::new().analyze_map(&map);
        assert_eq!(result.total, 2);
    }

    #[test]
    fn test_serde_roundtrip() {
        let xml = make_entitlements_xml(&[
            ("com.apple.security.get-task-allow", "true"),
        ]);
        let result = IpaEntitlementAnalyzer::new()
            .analyze_xml(xml.as_bytes())
            .unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let back: AnalysisResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.total, result.total);
        assert_eq!(back.max_level, result.max_level);
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Critical > RiskLevel::High);
        assert!(RiskLevel::High > RiskLevel::Medium);
        assert!(RiskLevel::Medium > RiskLevel::Low);
        assert!(RiskLevel::Low > RiskLevel::Info);
    }

    #[test]
    fn test_empty_entitlements_error() {
        let xml = b"<?xml version='1.0'?><plist><dict></dict></plist>";
        let result = IpaEntitlementAnalyzer::new().analyze_xml(xml);
        assert!(matches!(result, Err(AnalysisError::Empty)));
    }

    #[test]
    fn test_private_entitlement_high() {
        let xml = make_entitlements_xml(&[
            ("com.apple.private.security.container-required", "true"),
        ]);
        let result = IpaEntitlementAnalyzer::new()
            .analyze_xml(xml.as_bytes())
            .unwrap();
        let e = result.entries.iter().find(|e| e.key.contains("private")).unwrap();
        assert!(e.is_platform_only);
        assert_eq!(e.level, RiskLevel::High);
    }
}
