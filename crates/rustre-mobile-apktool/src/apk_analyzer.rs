//! APK security analysis and risk scoring.
//!
//! Inspects a parsed [`AndroidManifest`] and lists of class names to emit
//! [`SecurityFinding`] records, compute a risk score, and generate a
//! markdown-style report.

use crate::manifest::AndroidManifest;

// ─── Severity ─────────────────────────────────────────────────────────────────

/// Severity of a security finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Informational; no direct risk.
    Info,
    /// Low risk; generally benign but worth noting.
    Low,
    /// Medium risk; deserves review.
    Medium,
    /// High risk; likely to be abused.
    High,
    /// Critical risk; strongly indicative of malicious behaviour.
    Critical,
}

impl Severity {
    /// Short label for display.
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

    /// Numeric weight used for risk scoring.
    #[must_use]
    pub const fn weight(&self) -> u32 {
        match self {
            Self::Info => 1,
            Self::Low => 3,
            Self::Medium => 5,
            Self::High => 10,
            Self::Critical => 25,
        }
    }
}

// ─── Category ─────────────────────────────────────────────────────────────────

/// Semantic category of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    /// Permission-related finding.
    Permission,
    /// Exported or improperly protected component.
    Component,
    /// Weak or dangerous cryptographic usage.
    Crypto,
    /// Insecure network configuration.
    Network,
    /// Insecure data storage.
    Storage,
    /// Dangerous code pattern (reflection, dynamic loading, etc.).
    Code,
    /// Application configuration issue.
    Configuration,
    /// Privacy leak.
    PrivacyLeak,
    /// Code obfuscation / packing indicator.
    Obfuscation,
    /// Intent-redirection vulnerability.
    IntentRedirection,
}

impl Category {
    /// Human-readable category name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Permission => "Permission",
            Self::Component => "Component",
            Self::Crypto => "Crypto",
            Self::Network => "Network",
            Self::Storage => "Storage",
            Self::Code => "Code",
            Self::Configuration => "Configuration",
            Self::PrivacyLeak => "PrivacyLeak",
            Self::Obfuscation => "Obfuscation",
            Self::IntentRedirection => "IntentRedirection",
        }
    }
}

// ─── SecurityFinding ──────────────────────────────────────────────────────────

/// A single security finding produced by the APK analyzer.
#[derive(Debug, Clone)]
pub struct SecurityFinding {
    /// How severe this finding is.
    pub severity: Severity,
    /// What category this belongs to.
    pub category: Category,
    /// Short title for the finding.
    pub title: String,
    /// Detailed description / remediation advice.
    pub description: String,
    /// CWE identifier, if applicable.
    pub cwe_id: Option<u32>,
    /// The component or class name this finding relates to (if any).
    pub component: Option<String>,
}

impl SecurityFinding {
    /// Construct a finding.
    #[must_use]
    pub fn new(
        severity: Severity,
        category: Category,
        title: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            category,
            title: title.into(),
            description: description.into(),
            cwe_id: None,
            component: None,
        }
    }

    /// Attach a CWE ID.
    #[must_use]
    pub const fn with_cwe(mut self, cwe: u32) -> Self {
        self.cwe_id = Some(cwe);
        self
    }

    /// Attach a component name.
    #[must_use]
    pub fn with_component(mut self, comp: impl Into<String>) -> Self {
        self.component = Some(comp.into());
        self
    }
}

// ─── ApkAnalyzer ─────────────────────────────────────────────────────────────

/// Accumulates security findings from manifest and class-name analysis.
#[derive(Debug, Default)]
pub struct ApkAnalyzer {
    findings: Vec<SecurityFinding>,
}

impl ApkAnalyzer {
    /// Create an empty analyzer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }

    /// Return all accumulated findings.
    #[must_use]
    pub fn findings(&self) -> &[SecurityFinding] {
        &self.findings
    }

    /// Clear all findings.
    pub fn clear(&mut self) {
        self.findings.clear();
    }

    // ─── Manifest analysis ────────────────────────────────────────────────────

    /// Analyze the manifest for security issues.
    pub fn analyze_manifest(&mut self, manifest: &AndroidManifest) {
        self.check_permissions(manifest);
        self.check_debug_flag(manifest);
        self.check_backup_flag(manifest);
        self.check_cleartext_traffic(manifest);
        self.check_exported_components(manifest);
        self.check_permission_count(manifest);
    }

    fn check_permissions(&mut self, manifest: &AndroidManifest) {
        // Critical permissions
        const CRITICAL_PERMS: &[&str] = &[
            "android.permission.INSTALL_PACKAGES",
            "android.permission.CHANGE_COMPONENT_ENABLED_STATE",
        ];

        // High severity permissions
        const HIGH_PERMS: &[(&str, &str)] = &[
            ("android.permission.READ_CONTACTS", "Reads user contacts"),
            (
                "android.permission.ACCESS_FINE_LOCATION",
                "Tracks precise location",
            ),
            ("android.permission.CAMERA", "Accesses the camera"),
            ("android.permission.READ_CALL_LOG", "Reads call log"),
            (
                "android.permission.RECORD_AUDIO",
                "Records microphone audio",
            ),
            ("android.permission.READ_SMS", "Reads SMS messages"),
            (
                "android.permission.PROCESS_OUTGOING_CALLS",
                "Intercepts outgoing calls",
            ),
        ];

        for perm in &manifest.permissions {
            if CRITICAL_PERMS.contains(&perm.name.as_str()) {
                self.findings.push(
                    SecurityFinding::new(
                        Severity::Critical,
                        Category::Permission,
                        format!("Critical permission: {}", perm.name),
                        format!(
                            "The app declares '{}', which can be used for malicious device control.",
                            perm.name
                        ),
                    )
                    .with_cwe(250)
                    .with_component(perm.name.clone()),
                );
            } else {
                for (hp, desc) in HIGH_PERMS {
                    if perm.name == *hp {
                        self.findings.push(
                            SecurityFinding::new(
                                Severity::High,
                                Category::PrivacyLeak,
                                format!("Sensitive permission: {}", perm.name),
                                format!("{desc}. This permission may be used for privacy leaks."),
                            )
                            .with_cwe(276)
                            .with_component(perm.name.clone()),
                        );
                    }
                }
            }
        }
    }

    fn check_debug_flag(&mut self, manifest: &AndroidManifest) {
        if manifest.debuggable {
            self.findings.push(
                SecurityFinding::new(
                    Severity::High,
                    Category::Configuration,
                    "Application is debuggable",
                    "android:debuggable=\"true\" allows an attacker to attach a debugger, \
                     read memory, and extract secrets from the application process.",
                )
                .with_cwe(94),
            );
        }
    }

    fn check_backup_flag(&mut self, manifest: &AndroidManifest) {
        if manifest.allow_backup {
            self.findings.push(
                SecurityFinding::new(
                    Severity::Medium,
                    Category::Storage,
                    "Backup is allowed",
                    "android:allowBackup=\"true\" permits ADB backup of application data, \
                     which may expose sensitive user information.",
                )
                .with_cwe(312),
            );
        }
    }

    fn check_cleartext_traffic(&mut self, manifest: &AndroidManifest) {
        if manifest.uses_cleartext_traffic {
            self.findings.push(
                SecurityFinding::new(
                    Severity::Medium,
                    Category::Network,
                    "Cleartext traffic permitted",
                    "android:usesCleartextTraffic=\"true\" allows the app to transmit data \
                     over unencrypted HTTP connections, enabling man-in-the-middle attacks.",
                )
                .with_cwe(319),
            );
        }
    }

    fn check_exported_components(&mut self, manifest: &AndroidManifest) {
        for act in manifest.exported_activities() {
            if act.base.permission.is_none() {
                self.findings.push(
                    SecurityFinding::new(
                        Severity::Medium,
                        Category::Component,
                        "Exported activity with no permission guard",
                        format!(
                            "Activity '{}' is exported without a permission, making it accessible \
                             to any app on the device.",
                            act.base.name
                        ),
                    )
                    .with_cwe(926)
                    .with_component(act.base.name.clone()),
                );
            }
        }

        for prov in &manifest.providers {
            // Content providers differ from other components: when
            // `android:exported` is absent they default to exported (the
            // historical pre-API-17 default), regardless of intent filters.
            let provider_exported = prov.base.exported.unwrap_or(true);
            if provider_exported {
                self.findings.push(
                    SecurityFinding::new(
                        Severity::Medium,
                        Category::Component,
                        "Exported content provider",
                        format!(
                            "Provider '{}' (authorities: '{}') is exported. \
                             Improperly secured providers can expose sensitive data.",
                            prov.base.name, prov.authorities
                        ),
                    )
                    .with_cwe(926)
                    .with_component(prov.base.name.clone()),
                );
            }
        }
    }

    fn check_permission_count(&mut self, manifest: &AndroidManifest) {
        let count = manifest.permissions.len();
        if count > 20 {
            self.findings.push(
                SecurityFinding::new(
                    Severity::Low,
                    Category::Permission,
                    format!("Excessive permissions ({count} declared)"),
                    "Requesting an unusually large number of permissions increases the \
                     attack surface and may indicate overly-broad data collection.",
                )
                .with_cwe(250),
            );
        }
    }

    // ─── Class-name analysis ──────────────────────────────────────────────────

    /// Analyze a list of class names for suspicious patterns.
    pub fn analyze_class_names(&mut self, names: &[String]) {
        for name in names {
            self.analyze_single_class(name);
        }
    }

    fn analyze_single_class(&mut self, name: &str) {
        // Weak crypto
        if name.contains("javax.crypto.Cipher") {
            for weak in &["ECB", "DES/", "RC4", "ARCFOUR", "Blowfish/ECB"] {
                if name.contains(weak) {
                    self.findings.push(
                        SecurityFinding::new(
                            Severity::High,
                            Category::Crypto,
                            format!("Weak cipher in use: {name}"),
                            format!(
                                "The cipher transformation '{name}' is considered cryptographically weak."
                            ),
                        )
                        .with_cwe(327)
                        .with_component(name.to_string()),
                    );
                }
            }
        }

        // SSL bypass / trust manager
        if name.contains("javax.net.ssl.X509TrustManager") || name.contains("X509TrustManager") {
            if name.contains("AllowAll") || name.contains("Trust") || name.contains("Empty") {
                self.findings.push(
                    SecurityFinding::new(
                        Severity::Critical,
                        Category::Network,
                        "Custom X509TrustManager — potential cert pinning bypass",
                        format!(
                            "Class '{name}' implements X509TrustManager. Custom implementations \
                             often disable certificate validation, enabling MITM attacks."
                        ),
                    )
                    .with_cwe(295)
                    .with_component(name.to_string()),
                );
            } else {
                self.findings.push(
                    SecurityFinding::new(
                        Severity::Medium,
                        Category::Network,
                        "Custom X509TrustManager implementation",
                        format!(
                            "Class '{name}' implements X509TrustManager. Review this implementation \
                             to ensure certificate validation is not bypassed."
                        ),
                    )
                    .with_cwe(295)
                    .with_component(name.to_string()),
                );
            }
        }

        // Reflection
        if name.contains("java.lang.reflect.Method") || name.contains("java.lang.reflect.Field") {
            self.findings.push(
                SecurityFinding::new(
                    Severity::Low,
                    Category::Code,
                    "Java reflection usage detected",
                    format!(
                        "Class '{name}' uses Java reflection, which can be used to bypass \
                              access controls and is a common obfuscation technique."
                    ),
                )
                .with_cwe(470)
                .with_component(name.to_string()),
            );
        }

        // Dynamic class loading
        if name.contains("dalvik.system.DexClassLoader")
            || name.contains("dalvik.system.PathClassLoader")
            || name.contains("java.net.URLClassLoader")
        {
            self.findings.push(
                SecurityFinding::new(
                    Severity::High,
                    Category::Code,
                    "Dynamic code loading detected",
                    format!(
                        "Class '{name}' loads code at runtime, which is a common malware technique \
                         used to evade static analysis."
                    ),
                )
                .with_cwe(502)
                .with_component(name.to_string()),
            );
        }

        // Root detection / bypass
        if name.to_lowercase().contains("rootbeer") || name.contains("com.topjohnwu.magisk") {
            self.findings.push(
                SecurityFinding::new(
                    Severity::Info,
                    Category::Code,
                    "Root detection library detected",
                    format!(
                        "Class '{name}' appears to use a root-detection library. \
                              Verify this is used defensively, not offensively."
                    ),
                )
                .with_component(name.to_string()),
            );
        }

        // su/busybox
        if name == "su" || name == "busybox" {
            self.findings.push(
                SecurityFinding::new(
                    Severity::High,
                    Category::Code,
                    format!("Root binary reference: {name}"),
                    format!("Class or string '{name}' may indicate root privilege escalation."),
                )
                .with_cwe(250)
                .with_component(name.to_string()),
            );
        }
    }

    // ─── Risk score ───────────────────────────────────────────────────────────

    /// Compute an overall risk score (0–100) based on accumulated findings.
    #[must_use]
    pub fn compute_risk(&self) -> RiskScore {
        let mut critical = 0usize;
        let mut high = 0usize;
        let mut medium = 0usize;
        let mut low = 0usize;
        let mut info = 0usize;
        let mut total_weight = 0u32;

        for f in &self.findings {
            match f.severity {
                Severity::Critical => critical += 1,
                Severity::High => high += 1,
                Severity::Medium => medium += 1,
                Severity::Low => low += 1,
                Severity::Info => info += 1,
            }
            total_weight += f.severity.weight();
        }

        // Normalise to 0–100 using a soft-cap: 200 weight points → score 100
        let score = u8::try_from(total_weight.min(200) * 100 / 200).unwrap_or(u8::MAX);

        RiskScore {
            score,
            critical,
            high,
            medium,
            low,
            info,
        }
    }

    // ─── Report generation ────────────────────────────────────────────────────

    /// Generate a human-readable, markdown-style report.
    #[must_use]
    pub fn generate_report(&self) -> String {
        use std::fmt::Write;
        let risk = self.compute_risk();
        let mut out = String::new();

        out.push_str("# APK Security Analysis Report\n\n");
        let _ = writeln!(out, "**Risk Score:** {}/100\n", risk.score);
        out.push_str("## Summary\n\n");
        let _ = write!(
            out,
            "| Severity | Count |\n|----------|-------|\n\
             | Critical | {} |\n| High | {} |\n| Medium | {} |\n| Low | {} |\n| Info | {} |\n\n",
            risk.critical, risk.high, risk.medium, risk.low, risk.info
        );
        out.push_str("## Findings\n\n");

        if self.findings.is_empty() {
            out.push_str("No findings.\n");
            return out;
        }

        // Group by severity (highest first)
        for severity in &[
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            let group: Vec<&SecurityFinding> = self
                .findings
                .iter()
                .filter(|f| f.severity == *severity)
                .collect();
            if group.is_empty() {
                continue;
            }

            let _ = writeln!(out, "### {} Severity\n", severity.label());
            for f in group {
                let _ = writeln!(out, "#### {}\n", f.title);
                let _ = writeln!(out, "- **Category:** {}", f.category.name());
                if let Some(cwe) = f.cwe_id {
                    let _ = writeln!(out, "- **CWE:** CWE-{cwe}");
                }
                if let Some(comp) = &f.component {
                    let _ = writeln!(out, "- **Component:** `{comp}`");
                }
                let _ = write!(out, "\n{}\n\n", f.description);
            }
        }

        out
    }
}

// ─── RiskScore ────────────────────────────────────────────────────────────────

/// Overall risk score and per-severity finding counts.
#[derive(Debug, Clone, Copy)]
pub struct RiskScore {
    /// Normalised score 0–100 (100 = maximum risk).
    pub score: u8,
    /// Number of Critical findings.
    pub critical: usize,
    /// Number of High findings.
    pub high: usize,
    /// Number of Medium findings.
    pub medium: usize,
    /// Number of Low findings.
    pub low: usize,
    /// Number of Info findings.
    pub info: usize,
}

impl RiskScore {
    /// Total number of findings.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }

    /// Return a textual risk label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self.score {
            0..=19 => "Low",
            20..=49 => "Medium",
            50..=74 => "High",
            75..=100 => "Critical",
            _ => "Unknown",
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{
        ActivityInfo, AndroidManifest, IntentFilter, ProviderInfo, UsesPermission,
    };

    fn make_manifest_clean() -> AndroidManifest {
        AndroidManifest {
            package: "com.example.app".into(),
            target_sdk: 33,
            allow_backup: false,
            ..AndroidManifest::default()
        }
    }

    fn make_manifest_dangerous() -> AndroidManifest {
        let mut m = AndroidManifest {
            debuggable: true,
            allow_backup: true,
            uses_cleartext_traffic: true,
            ..AndroidManifest::default()
        };

        m.permissions.push(UsesPermission {
            name: "android.permission.INSTALL_PACKAGES".into(),
            max_sdk: None,
        });
        m.permissions.push(UsesPermission {
            name: "android.permission.CAMERA".into(),
            max_sdk: None,
        });
        m.permissions.push(UsesPermission {
            name: "android.permission.ACCESS_FINE_LOCATION".into(),
            max_sdk: None,
        });
        m.permissions.push(UsesPermission {
            name: "android.permission.READ_CALL_LOG".into(),
            max_sdk: None,
        });
        m.permissions.push(UsesPermission {
            name: "android.permission.CHANGE_COMPONENT_ENABLED_STATE".into(),
            max_sdk: None,
        });

        let mut act = ActivityInfo::new("com.example.app.ExportedActivity");
        act.base.exported = Some(true);
        let mut filter = IntentFilter::default();
        filter.actions.push("android.intent.action.VIEW".into());
        act.base.intent_filters.push(filter);
        m.activities.push(act);

        let prov = ProviderInfo::new("com.example.app.DataProvider", "com.example.app.data");
        m.providers.push(prov);

        m
    }

    // ─── analyze_manifest ─────────────────────────────────────────────────────

    #[test]
    fn analyze_manifest_finds_install_packages() {
        let m = make_manifest_dangerous();
        let mut a = ApkAnalyzer::new();
        a.analyze_manifest(&m);
        assert!(
            a.findings()
                .iter()
                .any(|f| f.severity == Severity::Critical && f.title.contains("INSTALL_PACKAGES"))
        );
    }

    #[test]
    fn analyze_manifest_finds_change_component() {
        let m = make_manifest_dangerous();
        let mut a = ApkAnalyzer::new();
        a.analyze_manifest(&m);
        assert!(a.findings().iter().any(|f| f.severity == Severity::Critical
            && f.title.contains("CHANGE_COMPONENT_ENABLED_STATE")));
    }

    #[test]
    fn analyze_manifest_camera_high() {
        let m = make_manifest_dangerous();
        let mut a = ApkAnalyzer::new();
        a.analyze_manifest(&m);
        assert!(
            a.findings()
                .iter()
                .any(|f| f.severity == Severity::High && f.title.contains("CAMERA"))
        );
    }

    #[test]
    fn analyze_manifest_debuggable_high() {
        let m = make_manifest_dangerous();
        let mut a = ApkAnalyzer::new();
        a.analyze_manifest(&m);
        assert!(
            a.findings()
                .iter()
                .any(|f| f.severity == Severity::High && f.category == Category::Configuration)
        );
    }

    #[test]
    fn analyze_manifest_backup_medium() {
        let m = make_manifest_dangerous();
        let mut a = ApkAnalyzer::new();
        a.analyze_manifest(&m);
        assert!(
            a.findings()
                .iter()
                .any(|f| f.severity == Severity::Medium && f.category == Category::Storage)
        );
    }

    #[test]
    fn analyze_manifest_cleartext_medium() {
        let m = make_manifest_dangerous();
        let mut a = ApkAnalyzer::new();
        a.analyze_manifest(&m);
        assert!(
            a.findings()
                .iter()
                .any(|f| f.severity == Severity::Medium && f.category == Category::Network)
        );
    }

    #[test]
    fn analyze_manifest_exported_activity_no_permission() {
        let m = make_manifest_dangerous();
        let mut a = ApkAnalyzer::new();
        a.analyze_manifest(&m);
        assert!(a.findings().iter().any(|f| f.severity == Severity::Medium
            && f.category == Category::Component
            && f.title.contains("Exported activity")));
    }

    #[test]
    fn analyze_manifest_exported_provider() {
        let m = make_manifest_dangerous();
        let mut a = ApkAnalyzer::new();
        a.analyze_manifest(&m);
        assert!(a.findings().iter().any(|f| f.severity == Severity::Medium
            && f.category == Category::Component
            && f.title.contains("provider")));
    }

    #[test]
    fn analyze_manifest_clean_no_findings() {
        let m = make_manifest_clean();
        let mut a = ApkAnalyzer::new();
        a.analyze_manifest(&m);
        // Clean manifest with allow_backup=false should have no findings
        assert!(a.findings().is_empty());
    }

    #[test]
    fn analyze_manifest_excess_permissions() {
        let mut m = make_manifest_clean();
        for i in 0..25 {
            m.permissions.push(UsesPermission {
                name: format!("android.permission.CUSTOM_{i}"),
                max_sdk: None,
            });
        }
        let mut a = ApkAnalyzer::new();
        a.analyze_manifest(&m);
        assert!(
            a.findings()
                .iter()
                .any(|f| f.title.contains("Excessive permissions"))
        );
    }

    // ─── analyze_class_names ──────────────────────────────────────────────────

    #[test]
    fn class_analysis_weak_cipher_ecb() {
        let mut a = ApkAnalyzer::new();
        a.analyze_class_names(&["javax.crypto.Cipher/AES/ECB/PKCS5Padding".to_string()]);
        assert!(
            a.findings()
                .iter()
                .any(|f| f.severity == Severity::High && f.category == Category::Crypto)
        );
    }

    #[test]
    fn class_analysis_des_weak() {
        let mut a = ApkAnalyzer::new();
        a.analyze_class_names(&["javax.crypto.Cipher/DES/CBC/PKCS5Padding".to_string()]);
        assert!(a.findings().iter().any(|f| f.category == Category::Crypto));
    }

    #[test]
    fn class_analysis_trust_manager_bypass() {
        let mut a = ApkAnalyzer::new();
        a.analyze_class_names(&["com.example.AllowAllTrustManagerX509TrustManager".to_string()]);
        assert!(
            a.findings()
                .iter()
                .any(|f| f.severity == Severity::Critical && f.category == Category::Network)
        );
    }

    #[test]
    fn class_analysis_trust_manager_medium() {
        let mut a = ApkAnalyzer::new();
        a.analyze_class_names(&["com.example.CustomX509TrustManager".to_string()]);
        assert!(a.findings().iter().any(|f| f.category == Category::Network));
    }

    #[test]
    fn class_analysis_reflection() {
        let mut a = ApkAnalyzer::new();
        a.analyze_class_names(&["java.lang.reflect.Method".to_string()]);
        assert!(
            a.findings()
                .iter()
                .any(|f| f.category == Category::Code && f.severity == Severity::Low)
        );
    }

    #[test]
    fn class_analysis_dex_classloader() {
        let mut a = ApkAnalyzer::new();
        a.analyze_class_names(&["dalvik.system.DexClassLoader".to_string()]);
        assert!(
            a.findings()
                .iter()
                .any(|f| f.severity == Severity::High && f.category == Category::Code)
        );
    }

    #[test]
    fn class_analysis_root_binary() {
        let mut a = ApkAnalyzer::new();
        a.analyze_class_names(&["su".to_string()]);
        assert!(a.findings().iter().any(|f| f.severity == Severity::High));
    }

    // ─── compute_risk ─────────────────────────────────────────────────────────

    #[test]
    fn risk_score_clean_is_zero() {
        let a = ApkAnalyzer::new();
        let r = a.compute_risk();
        assert_eq!(r.score, 0);
        assert_eq!(r.total(), 0);
    }

    #[test]
    fn risk_score_nonzero_after_findings() {
        let m = make_manifest_dangerous();
        let mut a = ApkAnalyzer::new();
        a.analyze_manifest(&m);
        let r = a.compute_risk();
        assert!(r.score > 0);
        assert!(r.critical > 0 || r.high > 0);
    }

    #[test]
    fn risk_score_capped_at_100() {
        let mut a = ApkAnalyzer::new();
        // Add lots of critical findings
        for i in 0..20 {
            a.findings.push(SecurityFinding::new(
                Severity::Critical,
                Category::Permission,
                format!("Critical finding {i}"),
                "test",
            ));
        }
        let r = a.compute_risk();
        assert!(r.score <= 100);
    }

    #[test]
    fn risk_score_label_critical() {
        let r = RiskScore {
            score: 80,
            critical: 5,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
        };
        assert_eq!(r.label(), "Critical");
    }

    #[test]
    fn risk_score_label_low() {
        let r = RiskScore {
            score: 5,
            critical: 0,
            high: 0,
            medium: 0,
            low: 1,
            info: 0,
        };
        assert_eq!(r.label(), "Low");
    }

    // ─── generate_report ──────────────────────────────────────────────────────

    #[test]
    fn report_has_header() {
        let a = ApkAnalyzer::new();
        let r = a.generate_report();
        assert!(r.contains("APK Security Analysis Report"));
    }

    #[test]
    fn report_has_risk_score() {
        let a = ApkAnalyzer::new();
        let r = a.generate_report();
        assert!(r.contains("Risk Score"));
    }

    #[test]
    fn report_no_findings() {
        let a = ApkAnalyzer::new();
        let r = a.generate_report();
        assert!(r.contains("No findings"));
    }

    #[test]
    fn report_includes_finding_title() {
        let m = make_manifest_dangerous();
        let mut a = ApkAnalyzer::new();
        a.analyze_manifest(&m);
        let r = a.generate_report();
        assert!(r.contains("INSTALL_PACKAGES") || r.contains("debuggable"));
    }

    #[test]
    fn report_includes_cwe() {
        let m = make_manifest_dangerous();
        let mut a = ApkAnalyzer::new();
        a.analyze_manifest(&m);
        let r = a.generate_report();
        assert!(r.contains("CWE-"));
    }

    // ─── Misc ─────────────────────────────────────────────────────────────────

    #[test]
    fn analyzer_clear() {
        let m = make_manifest_dangerous();
        let mut a = ApkAnalyzer::new();
        a.analyze_manifest(&m);
        assert!(!a.findings().is_empty());
        a.clear();
        assert!(a.findings().is_empty());
    }

    #[test]
    fn finding_with_cwe_and_component() {
        let f = SecurityFinding::new(Severity::High, Category::Crypto, "title", "desc")
            .with_cwe(327)
            .with_component("MyClass");
        assert_eq!(f.cwe_id, Some(327));
        assert_eq!(f.component.as_deref(), Some("MyClass"));
    }

    #[test]
    fn severity_weight_ordering() {
        assert!(Severity::Critical.weight() > Severity::High.weight());
        assert!(Severity::High.weight() > Severity::Medium.weight());
    }

    #[test]
    fn severity_label() {
        assert_eq!(Severity::Critical.label(), "CRITICAL");
        assert_eq!(Severity::Info.label(), "INFO");
    }

    #[test]
    fn category_name() {
        assert_eq!(Category::Crypto.name(), "Crypto");
        assert_eq!(Category::Permission.name(), "Permission");
    }
}
