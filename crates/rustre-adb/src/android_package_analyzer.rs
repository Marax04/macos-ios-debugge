//! `android_package_analyzer` — Parse and analyze installed Android packages.
//!
//! Parses the output of `adb shell dumpsys package` to build a catalogue of
//! installed applications, their permissions, and their declared components.
//! Computes a risk score for each app based on dangerous permissions and
//! debug-mode flags.

use std::collections::HashMap;
use std::fmt;

// ── InstalledPackage ──────────────────────────────────────────────────────────

/// Metadata about a single installed Android package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledPackage {
    /// Canonical Java-style package identifier, e.g. `com.example.app`.
    pub package_name: String,
    /// Human-readable version string, e.g. `"3.1.2"`.
    pub version_name: String,
    /// Numeric version code from `AndroidManifest.xml`.
    pub version_code: u64,
    /// `true` if the package was installed as part of the system image.
    pub is_system: bool,
    /// `true` if the package was signed with a debug key or has debuggable=true.
    pub is_debug: bool,
    /// Path to the installed APK on the device.
    pub apk_path: String,
    /// First-install timestamp in milliseconds since epoch (0 if unknown).
    pub first_install_time_ms: u64,
    /// Last-update timestamp in milliseconds since epoch (0 if unknown).
    pub last_update_time_ms: u64,
}

impl InstalledPackage {
    /// Return `true` if the package was installed by the user (not system).
    #[must_use]
    pub const fn is_user_installed(&self) -> bool {
        !self.is_system
    }
}

impl fmt::Display for InstalledPackage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} v{} (code={}{}{})",
            self.package_name,
            self.version_name,
            self.version_code,
            if self.is_system { ", system" } else { "" },
            if self.is_debug { ", debug" } else { "" },
        )
    }
}

// ── PackagePermissions ────────────────────────────────────────────────────────

/// Permission state for a single package.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PackagePermissions {
    /// Permissions that the app declares it may need (from `uses-permission`).
    pub requested: Vec<String>,
    /// Permissions that have been granted at runtime.
    pub granted: Vec<String>,
    /// Permissions that were requested but explicitly denied.
    pub denied: Vec<String>,
}

impl PackagePermissions {
    /// Return `true` if the package holds the named permission.
    #[must_use]
    pub fn has_permission(&self, perm: &str) -> bool {
        self.granted.iter().any(|g| g == perm)
    }

    /// Count how many dangerous permissions from the standard list are granted.
    #[must_use]
    pub fn count_dangerous(&self) -> usize {
        DANGEROUS_PERMISSIONS
            .iter()
            .filter(|&&p| self.has_permission(p))
            .count()
    }
}

// ── ComponentInfo ─────────────────────────────────────────────────────────────

/// Declared Android components for a single package.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ComponentInfo {
    /// Activity class names.
    pub activities: Vec<String>,
    /// Service class names.
    pub services: Vec<String>,
    /// Broadcast-receiver class names.
    pub receivers: Vec<String>,
    /// Content-provider authorities.
    pub providers: Vec<String>,
}

impl ComponentInfo {
    /// Return the total number of declared components.
    #[must_use]
    pub const fn total_count(&self) -> usize {
        self.activities.len() + self.services.len() + self.receivers.len() + self.providers.len()
    }
}

// ── AppSecurityReport ─────────────────────────────────────────────────────────

/// Combined security report for a single package.
#[derive(Debug, Clone)]
pub struct AppSecurityReport {
    /// Package metadata.
    pub package: InstalledPackage,
    /// Permission state.
    pub permissions: PackagePermissions,
    /// Component catalogue.
    pub components: ComponentInfo,
    /// Risk score 0-100 computed from permissions, debug flag, etc.
    pub risk_score: u8,
}

impl AppSecurityReport {
    /// Return a human-readable risk category.
    #[must_use]
    pub const fn risk_category(&self) -> &'static str {
        match self.risk_score {
            0..=20 => "Low",
            21..=50 => "Medium",
            51..=75 => "High",
            _ => "Critical",
        }
    }
}

// ── Dangerous permissions list ────────────────────────────────────────────────

/// Well-known Android permissions classified as dangerous by the platform.
pub static DANGEROUS_PERMISSIONS: &[&str] = &[
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BODY_SENSORS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
];

// ── AndroidPackageAnalyzer ────────────────────────────────────────────────────

/// Parses and analyses Android package information.
#[derive(Debug, Default)]
pub struct AndroidPackageAnalyzer {
    /// Packages found in the most recent parse.
    packages: Vec<InstalledPackage>,
    /// Permission data keyed by package name.
    permissions: HashMap<String, PackagePermissions>,
    /// Component data keyed by package name.
    components: HashMap<String, ComponentInfo>,
}

impl AndroidPackageAnalyzer {
    /// Create a new analyser with no packages loaded.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Access the loaded package list.
    #[must_use]
    pub fn packages(&self) -> &[InstalledPackage] {
        &self.packages
    }

    /// Parse the output of `adb shell dumpsys package` and populate the
    /// internal package list.
    ///
    /// Only lines that start relevant key/value pairs are examined; everything
    /// else is skipped so that the parser is robust to format variations across
    /// different Android versions.
    pub fn parse_dumpsys_packages(&mut self, output: &str) -> Vec<InstalledPackage> {
        self.packages = parse_dumpsys_packages(output);
        self.packages.clone()
    }

    /// Parse permissions for `package_name` from a `dumpsys package <name>`
    /// or full `dumpsys package` output.
    pub fn parse_permissions(&mut self, output: &str, package: &str) -> PackagePermissions {
        let perms = parse_permissions(output, package);
        self.permissions.insert(package.to_owned(), perms.clone());
        perms
    }

    /// Parse component info for `package_name`.
    pub fn parse_components(&mut self, output: &str, package: &str) -> ComponentInfo {
        let info = parse_components(output, package);
        self.components.insert(package.to_owned(), info.clone());
        info
    }

    /// Build [`AppSecurityReport`]s for all packages that have either
    /// dangerous permissions or the debug flag set.
    #[must_use]
    pub fn identify_dangerous_packages(&self) -> Vec<AppSecurityReport> {
        let mut reports = Vec::new();
        for pkg in &self.packages {
            let permissions = self
                .permissions
                .get(&pkg.package_name)
                .cloned()
                .unwrap_or_default();
            let components = self
                .components
                .get(&pkg.package_name)
                .cloned()
                .unwrap_or_default();
            let dangerous_count = permissions.count_dangerous();
            if dangerous_count == 0 && !pkg.is_debug {
                continue;
            }
            let risk_score = compute_risk_score(pkg, &permissions);
            reports.push(AppSecurityReport {
                package: pkg.clone(),
                permissions,
                components,
                risk_score,
            });
        }
        reports.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));
        reports
    }

    /// Build a full security report for every package.
    #[must_use]
    pub fn full_report(&self) -> Vec<AppSecurityReport> {
        self.packages
            .iter()
            .map(|pkg| {
                let permissions = self
                    .permissions
                    .get(&pkg.package_name)
                    .cloned()
                    .unwrap_or_default();
                let components = self
                    .components
                    .get(&pkg.package_name)
                    .cloned()
                    .unwrap_or_default();
                let risk_score = compute_risk_score(pkg, &permissions);
                AppSecurityReport {
                    package: pkg.clone(),
                    permissions,
                    components,
                    risk_score,
                }
            })
            .collect()
    }
}

// ── compute_risk_score ────────────────────────────────────────────────────────

/// Compute a 0-100 risk score for a package.
fn compute_risk_score(pkg: &InstalledPackage, perms: &PackagePermissions) -> u8 {
    let mut score: u32 = 0;
    // Each dangerous permission adds points
    score += u32::try_from(perms.count_dangerous()).unwrap_or(u32::MAX) * 5;
    // Debug flag is a big red flag
    if pkg.is_debug {
        score += 25;
    }
    // System packages get a small reduction (assumed more trustworthy)
    if pkg.is_system && score >= 10 {
        score -= 5;
    }
    // High component count suggests attack surface
    let total_components = u32::try_from(perms.requested.len()).unwrap_or(u32::MAX);
    score += total_components / 10;

    u8::try_from(score.min(100)).unwrap_or(100)
}

// ── Standalone parsing functions ──────────────────────────────────────────────

/// Parse the full `dumpsys package` output and return a list of packages.
///
/// Format hint (simplified):
/// ```text
/// Package [com.example.app] (...):
///   userId=10142
///   pkg=Package{...}
///   versionCode=42 minSdk=21 targetSdk=33
///   versionName=1.2.3
///   codePath=/data/app/com.example.app-...
///   flags=[ DEBUGGABLE ]
///   firstInstallTime=2024-01-01 12:00:00
///   lastUpdateTime=2024-06-01 08:00:00
/// ```
#[must_use]
pub fn parse_dumpsys_packages(output: &str) -> Vec<InstalledPackage> {
    let mut packages = Vec::new();
    let mut current: Option<InstalledPackage> = None;

    for line in output.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("Package [") {
            // Flush previous
            if let Some(pkg) = current.take() {
                packages.push(pkg);
            }
            // Extract package name
            if let Some(name) = extract_between(trimmed, "Package [", "]") {
                current = Some(InstalledPackage {
                    package_name: name.to_owned(),
                    version_name: String::new(),
                    version_code: 0,
                    is_system: false,
                    is_debug: false,
                    apk_path: String::new(),
                    first_install_time_ms: 0,
                    last_update_time_ms: 0,
                });
            }
        } else if let Some(ref mut pkg) = current {
            if let Some(rest) = trimmed.strip_prefix("versionCode=") {
                let code_str = rest.split_whitespace().next().unwrap_or("0");
                pkg.version_code = code_str.parse().unwrap_or(0);
            } else if let Some(rest) = trimmed.strip_prefix("versionName=") {
                rest.trim().clone_into(&mut pkg.version_name);
            } else if let Some(rest) = trimmed.strip_prefix("codePath=") {
                rest.trim().clone_into(&mut pkg.apk_path);
            } else if trimmed.starts_with("flags=") {
                if trimmed.contains("DEBUGGABLE") {
                    pkg.is_debug = true;
                }
                if trimmed.contains("SYSTEM") {
                    pkg.is_system = true;
                }
            } else if trimmed.starts_with("pkgFlags=") {
                if trimmed.contains("SYSTEM") {
                    pkg.is_system = true;
                }
            } else if let Some(rest) = trimmed.strip_prefix("firstInstallTime=") {
                pkg.first_install_time_ms = parse_timestamp_ms(rest.trim());
            } else if let Some(rest) = trimmed.strip_prefix("lastUpdateTime=") {
                pkg.last_update_time_ms = parse_timestamp_ms(rest.trim());
            }
        }
    }
    // Final package
    if let Some(pkg) = current {
        packages.push(pkg);
    }
    packages
}

/// Parse permissions for a specific package from `dumpsys package` output.
///
/// Looks for the block:
/// ```text
/// Package [com.example.app]:
///   requested permissions:
///     android.permission.INTERNET
///   install permissions:
///     android.permission.INTERNET: granted=true
///   runtime permissions:
///     android.permission.CAMERA: granted=true
/// ```
#[must_use]
pub fn parse_permissions(output: &str, package: &str) -> PackagePermissions {
    let mut perms = PackagePermissions::default();
    let mut in_package = false;
    let mut in_requested = false;
    let mut in_runtime = false;

    for line in output.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("Package [") {
            let name_opt = extract_between(trimmed, "Package [", "]");
            in_package = name_opt == Some(package);
            in_requested = false;
            in_runtime = false;
            continue;
        }

        if !in_package {
            continue;
        }

        if trimmed == "requested permissions:" || trimmed.starts_with("requested permissions:") {
            in_requested = true;
            in_runtime = false;
            continue;
        }
        if trimmed.starts_with("install permissions:") || trimmed.starts_with("runtime permissions:") {
            in_requested = false;
            in_runtime = true;
            continue;
        }

        if in_requested {
            if trimmed.starts_with("android.permission.") || trimmed.contains(".permission.") {
                perms.requested.push(trimmed.split(':').next().unwrap_or(trimmed).trim().to_owned());
            } else if !trimmed.is_empty() && !trimmed.starts_with("android.") && !trimmed.contains('.') {
                // end of block
                in_requested = false;
            }
        }

        if in_runtime && trimmed.contains(": granted=") {
            let perm_name = trimmed.split(':').next().unwrap_or("").trim().to_owned();
            if trimmed.contains("granted=true") {
                perms.granted.push(perm_name);
            } else {
                perms.denied.push(perm_name);
            }
        }
    }
    perms
}

/// Parse component info for a specific package from `dumpsys package` output.
///
/// Looks for Activity/Service/BroadcastReceiver/ContentProvider sections.
#[must_use]
pub fn parse_components(output: &str, package: &str) -> ComponentInfo {
    let mut info = ComponentInfo::default();
    let mut in_package = false;
    let mut mode: u8 = 0; // 1=activity 2=service 3=receiver 4=provider

    for line in output.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("Package [") {
            let name_opt = extract_between(trimmed, "Package [", "]");
            in_package = name_opt == Some(package);
            mode = 0;
            continue;
        }

        if !in_package {
            continue;
        }

        if trimmed.starts_with("Activity [") || trimmed.starts_with("android.app.Activity") {
            mode = 1;
        } else if trimmed.starts_with("Service [") {
            mode = 2;
        } else if trimmed.starts_with("Receiver [") {
            mode = 3;
        } else if trimmed.starts_with("Provider [") {
            mode = 4;
        }

        // Component class names typically look like "    com.example.MainActivity"
        if trimmed.starts_with(package) {
            match mode {
                1 => info.activities.push(trimmed.to_owned()),
                2 => info.services.push(trimmed.to_owned()),
                3 => info.receivers.push(trimmed.to_owned()),
                4 => info.providers.push(trimmed.to_owned()),
                _ => {}
            }
        }
    }
    info
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn extract_between<'a>(s: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let start_pos = s.find(start)? + start.len();
    let end_pos = s[start_pos..].find(end)? + start_pos;
    Some(&s[start_pos..end_pos])
}

/// Very rough timestamp parser.  Accepts millisecond integers or YYYY-MM-DD.
fn parse_timestamp_ms(s: &str) -> u64 {
    // Try raw integer first (milliseconds since epoch)
    if let Ok(ms) = s.parse::<u64>() {
        return ms;
    }
    // Try "YYYY-MM-DD HH:MM:SS" → produce 0 (no std time parsing without deps)
    0
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_dumpsys() -> &'static str {
        r"
Package [com.example.app] (7a3f9b2):
  userId=10200
  versionCode=42 minSdk=24 targetSdk=33
  versionName=2.0.1
  codePath=/data/app/com.example.app-abc123
  flags=[ DEBUGGABLE ]
  firstInstallTime=1700000000000
  lastUpdateTime=1710000000000

Package [com.android.settings] (1234abc):
  userId=1000
  versionCode=100
  versionName=13.0
  codePath=/system/app/Settings
  pkgFlags=[ SYSTEM ]
"
    }

    fn sample_dumpsys_with_perms() -> &'static str {
        r"
Package [com.example.app]:
  requested permissions:
    android.permission.CAMERA
    android.permission.INTERNET
  runtime permissions:
    android.permission.CAMERA: granted=true
    android.permission.READ_CONTACTS: granted=false
"
    }

    #[test]
    fn test_parse_dumpsys_package_count() {
        let pkgs = parse_dumpsys_packages(sample_dumpsys());
        assert_eq!(pkgs.len(), 2);
    }

    #[test]
    fn test_parse_dumpsys_package_name() {
        let pkgs = parse_dumpsys_packages(sample_dumpsys());
        assert_eq!(pkgs[0].package_name, "com.example.app");
    }

    #[test]
    fn test_parse_dumpsys_version_code() {
        let pkgs = parse_dumpsys_packages(sample_dumpsys());
        assert_eq!(pkgs[0].version_code, 42);
    }

    #[test]
    fn test_parse_dumpsys_version_name() {
        let pkgs = parse_dumpsys_packages(sample_dumpsys());
        assert_eq!(pkgs[0].version_name, "2.0.1");
    }

    #[test]
    fn test_parse_dumpsys_debuggable_flag() {
        let pkgs = parse_dumpsys_packages(sample_dumpsys());
        assert!(pkgs[0].is_debug);
        assert!(!pkgs[1].is_debug);
    }

    #[test]
    fn test_parse_dumpsys_system_flag() {
        let pkgs = parse_dumpsys_packages(sample_dumpsys());
        assert!(!pkgs[0].is_system);
        assert!(pkgs[1].is_system);
    }

    #[test]
    fn test_parse_dumpsys_apk_path() {
        let pkgs = parse_dumpsys_packages(sample_dumpsys());
        assert!(pkgs[0].apk_path.contains("com.example.app"));
    }

    #[test]
    fn test_parse_dumpsys_timestamps() {
        let pkgs = parse_dumpsys_packages(sample_dumpsys());
        assert_eq!(pkgs[0].first_install_time_ms, 1_700_000_000_000);
        assert_eq!(pkgs[0].last_update_time_ms, 1_710_000_000_000);
    }

    #[test]
    fn test_parse_permissions_granted() {
        let perms = parse_permissions(sample_dumpsys_with_perms(), "com.example.app");
        assert!(perms.has_permission("android.permission.CAMERA"));
    }

    #[test]
    fn test_parse_permissions_denied() {
        let perms = parse_permissions(sample_dumpsys_with_perms(), "com.example.app");
        assert!(perms.denied.contains(&"android.permission.READ_CONTACTS".to_owned()));
    }

    #[test]
    fn test_parse_permissions_requested() {
        let perms = parse_permissions(sample_dumpsys_with_perms(), "com.example.app");
        assert!(perms.requested.contains(&"android.permission.CAMERA".to_owned()));
        assert!(perms.requested.contains(&"android.permission.INTERNET".to_owned()));
    }

    #[test]
    fn test_parse_permissions_wrong_package() {
        let perms = parse_permissions(sample_dumpsys_with_perms(), "com.other.app");
        assert!(perms.granted.is_empty());
    }

    #[test]
    fn test_risk_score_debug_flag() {
        let pkg = InstalledPackage {
            package_name: "test".into(),
            version_name: "1.0".into(),
            version_code: 1,
            is_system: false,
            is_debug: true,
            apk_path: String::new(),
            first_install_time_ms: 0,
            last_update_time_ms: 0,
        };
        let perms = PackagePermissions::default();
        let score = compute_risk_score(&pkg, &perms);
        assert!(score >= 25, "debug flag should add at least 25 pts");
    }

    #[test]
    fn test_risk_score_dangerous_permissions() {
        let pkg = InstalledPackage {
            package_name: "test".into(),
            version_name: "1.0".into(),
            version_code: 1,
            is_system: false,
            is_debug: false,
            apk_path: String::new(),
            first_install_time_ms: 0,
            last_update_time_ms: 0,
        };
        let mut perms = PackagePermissions::default();
        perms.granted.push("android.permission.CAMERA".into());
        perms.granted.push("android.permission.RECORD_AUDIO".into());
        let score = compute_risk_score(&pkg, &perms);
        assert!(score >= 10);
    }

    #[test]
    fn test_risk_category_low() {
        let report = AppSecurityReport {
            package: InstalledPackage {
                package_name: "a".into(),
                version_name: "1".into(),
                version_code: 1,
                is_system: false,
                is_debug: false,
                apk_path: String::new(),
                first_install_time_ms: 0,
                last_update_time_ms: 0,
            },
            permissions: PackagePermissions::default(),
            components: ComponentInfo::default(),
            risk_score: 10,
        };
        assert_eq!(report.risk_category(), "Low");
    }

    #[test]
    fn test_risk_category_critical() {
        let report = AppSecurityReport {
            package: InstalledPackage {
                package_name: "a".into(),
                version_name: "1".into(),
                version_code: 1,
                is_system: false,
                is_debug: false,
                apk_path: String::new(),
                first_install_time_ms: 0,
                last_update_time_ms: 0,
            },
            permissions: PackagePermissions::default(),
            components: ComponentInfo::default(),
            risk_score: 90,
        };
        assert_eq!(report.risk_category(), "Critical");
    }

    #[test]
    fn test_dangerous_permissions_list_not_empty() {
        assert!(!DANGEROUS_PERMISSIONS.is_empty());
    }

    #[test]
    fn test_count_dangerous() {
        let mut perms = PackagePermissions::default();
        perms.granted.push("android.permission.CAMERA".into());
        perms.granted.push("android.permission.SEND_SMS".into());
        assert_eq!(perms.count_dangerous(), 2);
    }

    #[test]
    fn test_component_total_count() {
        let mut info = ComponentInfo::default();
        info.activities.push("Main".into());
        info.services.push("Background".into());
        assert_eq!(info.total_count(), 2);
    }
}
