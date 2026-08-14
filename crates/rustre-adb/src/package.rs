//! # package.rs — Android Package Management
//!
//! Provides structured access to the Android Package Manager (`pm`) via ADB
//! shell commands.  All operations ultimately call `AdbClient::shell()` and
//! parse the text output.
//!
//! ## Supported operations
//!
//! - List installed packages (`pm list packages -f [-s|-3]`)
//! - Get detailed package info (`pm dump <pkg>`)
//! - Install APK (`pm install -r`)
//! - Uninstall package (`pm uninstall [--keep-data]`)
//! - Clear package data (`pm clear`)
//! - Enable / disable package (`pm enable` / `pm disable-user`)
//! - Grant / revoke permissions (`pm grant` / `pm revoke`)
//! - List permissions (`pm list permissions`)

pub use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{AdbClient, AdbError, PackageInfo, Result};

// ─── PackageFlags ─────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Android package flags (subset of `android.content.pm.ApplicationInfo` flags).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct PackageFlags: u32 {
        const SYSTEM           = 0x0000_0001;
        const DEBUGGABLE       = 0x0000_0002;
        const HAS_CODE         = 0x0000_0004;
        const PERSISTENT       = 0x0000_0008;
        const ALLOW_BACKUP     = 0x0000_8000;
        const LARGE_HEAP       = 0x0100_0000;
        const RESIZEABLE       = 0x0000_0200;
        const SUPPORTS_SCREENS = 0x0000_0020;
    }
}

// ─── InstallLocation ──────────────────────────────────────────────────────────

/// Where the APK is installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstallLocation {
    /// In `/data/app/` (user-installed, typical for third-party apps).
    InternalStorage,
    /// On SD card (`/mnt/asec/`).
    ExternalStorage,
    /// In `/system/app/` or `/system/priv-app/` (ROM-shipped).
    System,
    /// In `/product/app/` or similar.
    Product,
    Unknown,
}

impl InstallLocation {
    #[must_use]
    pub fn from_path(path: &str) -> Self {
        if path.starts_with("/data/app/") || path.starts_with("/data/priv-app/") {
            Self::InternalStorage
        } else if path.starts_with("/mnt/asec/") || path.starts_with("/sdcard/") {
            Self::ExternalStorage
        } else if path.starts_with("/system/") || path.starts_with("/vendor/") {
            Self::System
        } else if path.starts_with("/product/") || path.starts_with("/oem/") {
            Self::Product
        } else {
            Self::Unknown
        }
    }
}

// ─── PackageDetails ───────────────────────────────────────────────────────────

/// Detailed information about an installed package, as returned by `pm dump`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageDetails {
    /// Basic package info (name, path, versions).
    pub info: PackageInfo,
    /// Install location.
    pub install_location: InstallLocation,
    /// Granted runtime permissions.
    pub permissions: Vec<String>,
    /// Activities declared in the manifest.
    pub activities: Vec<String>,
    /// Services declared in the manifest.
    pub services: Vec<String>,
    /// Receivers declared in the manifest.
    pub receivers: Vec<String>,
    /// Providers declared in the manifest.
    pub providers: Vec<String>,
    /// Target SDK version.
    pub target_sdk: Option<u32>,
    /// Minimum SDK version.
    pub min_sdk: Option<u32>,
    /// Whether the package is currently enabled.
    pub enabled: bool,
    /// User ID the package runs as.
    pub uid: Option<u32>,
    /// Signatures (hex SHA-256 thumbprints).
    pub signatures: Vec<String>,
}

impl PackageDetails {
    /// Return `true` if the package is a system app.
    #[must_use]
    pub const fn is_system(&self) -> bool {
        self.info.is_system
    }

    /// Return `true` if the package is debuggable.
    #[must_use]
    pub const fn is_debuggable(&self) -> bool {
        matches!(self.install_location, InstallLocation::InternalStorage)
    }
}

// ─── ListOptions ─────────────────────────────────────────────────────────────

/// Options for filtering the package list.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListOptions {
    /// Only show third-party packages (`-3`).
    pub third_party_only: bool,
    /// Only show system packages (`-s`).
    pub system_only: bool,
    /// Include APK paths in output.
    pub include_paths: bool,
    /// Filter by name substring.
    pub name_filter: Option<String>,
}

impl ListOptions {
    /// Build the `pm list packages` arguments for this option set.
    #[must_use]
    pub fn pm_args(&self) -> Vec<&str> {
        let mut args = vec!["list", "packages"];
        if self.include_paths {
            args.push("-f");
        }
        if self.third_party_only {
            args.push("-3");
        } else if self.system_only {
            args.push("-s");
        }
        args
    }
}

// ─── Parse helpers ────────────────────────────────────────────────────────────

/// Parse a single `pm list packages [-f]` output line.
#[must_use]
pub fn parse_pm_list_line(line: &str) -> Option<PackageInfo> {
    let line = line.trim();
    let rest = line.strip_prefix("package:")?;
    let (apk_path, package_name) = rest.rfind('=').map_or_else(
        || (None, rest.to_owned()),
        |eq| (Some(rest[..eq].to_owned()), rest[eq + 1..].to_owned()),
    );
    if package_name.is_empty() {
        return None;
    }
    let is_system = apk_path
        .as_deref()
        .is_some_and(|p| p.starts_with("/system/") || p.starts_with("/vendor/"));
    Some(PackageInfo {
        package_name,
        apk_path,
        version_code: None,
        version_name: None,
        is_system,
    })
}

/// Parse multiple `pm list packages` lines.
pub fn parse_pm_list_output(output: &str) -> Vec<PackageInfo> {
    output.lines().filter_map(parse_pm_list_line).collect()
}

/// Extract `versionCode` from `pm dump <pkg>` output.
fn extract_version_code(dump: &str) -> Option<u32> {
    for line in dump.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("versionCode=") {
            return rest.split_whitespace().next()?.parse().ok();
        }
        // Alternative format: "    versionCode=42 targetSdk=..."
        if line.contains("versionCode=") {
            for tok in line.split_whitespace() {
                if let Some(v) = tok.strip_prefix("versionCode=")
                    && let Ok(n) = v.parse::<u32>()
                {
                    return Some(n);
                }
            }
        }
    }
    None
}

/// Extract `versionName` from `pm dump` output.
fn extract_version_name(dump: &str) -> Option<String> {
    for line in dump.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("versionName=") {
            return Some(rest.split_whitespace().next()?.to_owned());
        }
        if line.contains("versionName=") {
            for tok in line.split_whitespace() {
                if let Some(v) = tok.strip_prefix("versionName=") {
                    return Some(v.to_owned());
                }
            }
        }
    }
    None
}

/// Extract `userId` from `pm dump` output.
fn extract_uid(dump: &str) -> Option<u32> {
    for line in dump.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("userId=") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// Extract `targetSdk` from `pm dump` output.
fn extract_target_sdk(dump: &str) -> Option<u32> {
    for line in dump.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("targetSdk=") {
            return rest.split_whitespace().next()?.parse().ok();
        }
        if line.contains("targetSdk=") {
            for tok in line.split_whitespace() {
                if let Some(v) = tok.strip_prefix("targetSdk=")
                    && let Ok(n) = v.parse::<u32>()
                {
                    return Some(n);
                }
            }
        }
    }
    None
}

/// Extract granted permissions from `pm dump` output.
fn extract_permissions(dump: &str) -> Vec<String> {
    let mut in_section = false;
    let mut perms = Vec::new();
    for line in dump.lines() {
        let trimmed = line.trim();
        if trimmed == "grantedPermissions:" || trimmed == "runtime permissions:" {
            in_section = true;
            continue;
        }
        if in_section {
            if trimmed.is_empty()
                || (!trimmed.starts_with("android.permission")
                    && !trimmed.starts_with("com.")
                    && !trimmed.contains("permission"))
            {
                // End of section
                if !trimmed.starts_with("android.") && !trimmed.starts_with("com.") {
                    in_section = false;
                    continue;
                }
            }
            let raw = trimmed.split(':').next().unwrap_or(trimmed).trim();
            if !raw.is_empty() && raw.contains('.') {
                perms.push(raw.to_owned());
            }
        }
    }
    perms
}

/// Extract the list of activities from `pm dump` output.
fn extract_activities(dump: &str) -> Vec<String> {
    extract_components(dump, "Activity ")
}

/// Extract the list of services from `pm dump` output.
fn extract_services(dump: &str) -> Vec<String> {
    extract_components(dump, "Service ")
}

/// Generic component extractor from `pm dump`.
fn extract_components(dump: &str, prefix: &str) -> Vec<String> {
    dump.lines()
        .filter_map(|line| {
            let t = line.trim();
            t.strip_prefix(prefix).and_then(|stripped| {
                let rest = stripped.trim();
                // Component name may be followed by ':' or '{'
                let name = rest.split([':', ' ', '{']).next().unwrap_or(rest).trim();
                if name.is_empty() {
                    None
                } else {
                    Some(name.to_owned())
                }
            })
        })
        .collect()
}

/// Parse a `pm dump <pkg>` block into a `PackageDetails` struct.
pub fn parse_pm_dump(package_name: &str, dump: &str, base_info: PackageInfo) -> PackageDetails {
    let install_location = base_info
        .apk_path
        .as_deref()
        .map_or(InstallLocation::Unknown, InstallLocation::from_path);

    let mut info = base_info;
    if info.package_name.is_empty() {
        package_name.clone_into(&mut info.package_name);
    }
    info.version_code = extract_version_code(dump);
    info.version_name = extract_version_name(dump);

    PackageDetails {
        info,
        install_location,
        permissions: extract_permissions(dump),
        activities: extract_activities(dump),
        services: extract_services(dump),
        receivers: Vec::new(),
        providers: Vec::new(),
        target_sdk: extract_target_sdk(dump),
        min_sdk: None,
        enabled: !dump.contains("enabled=false"),
        uid: extract_uid(dump),
        signatures: Vec::new(),
    }
}

// ─── Install / Uninstall helpers (pure, no I/O) ───────────────────────────────

/// Build the `pm install` shell command string.
///
/// `options` are extra flags passed after `install` (e.g. `["-t", "-g"]`).
#[must_use]
pub fn build_install_command(remote_apk: &str, options: &[&str]) -> String {
    // The APK path is not trusted — it is a device path chosen by the caller —
    // and it was concatenated raw, so a quote or a semicolon in it started a new
    // command. `options` are flags this crate's own callers supply, so they are
    // left as written.
    let escaped = crate::shell::shell_escape(remote_apk);
    let mut parts = vec!["pm", "install", "-r"];
    parts.extend_from_slice(options);
    parts.push(&escaped);
    parts.join(" ")
}

/// Build the `pm uninstall` shell command string.
///
/// If `keep_data` is `true`, appends `-k` so that app data is preserved.
#[must_use]
pub fn build_uninstall_command(package: &str, keep_data: bool) -> String {
    if keep_data {
        format!("pm uninstall -k {}", crate::shell::shell_escape(package))
    } else {
        format!("pm uninstall {}", crate::shell::shell_escape(package))
    }
}

/// Return `true` if the `pm install` output indicates success.
#[must_use]
pub fn install_succeeded(output: &str) -> bool {
    output.lines().any(|l| l.trim() == "Success")
}

/// Return `true` if the `pm uninstall` output indicates success.
#[must_use]
pub fn uninstall_succeeded(output: &str) -> bool {
    output.lines().any(|l| l.trim() == "Success")
}

/// Extract the failure reason from a `pm install` failure message.
///
/// Returns `None` if it looks like a success.
#[must_use]
pub fn extract_install_failure(output: &str) -> Option<String> {
    for line in output.lines() {
        let t = line.trim();
        if t.starts_with("Failure [") && t.ends_with(']') {
            return Some(t.to_owned());
        }
        if t.starts_with("INSTALL_FAILED_") || t.starts_with("Error:") {
            return Some(t.to_owned());
        }
    }
    None
}

// ─── AdbPackageManager — higher-level API ─────────────────────────────────────

/// High-level package manager wrapping `AdbClient`.
#[derive(Debug, Clone)]
pub struct AdbPackageManager {
    pub client: AdbClient,
    pub serial: String,
}

impl AdbPackageManager {
    /// Create a package manager for the given device serial.
    pub fn new(client: AdbClient, serial: impl Into<String>) -> Self {
        Self {
            client,
            serial: serial.into(),
        }
    }

    /// List all installed packages.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn list_packages(&self, opts: &ListOptions) -> Result<Vec<PackageInfo>> {
        let args = opts.pm_args();
        let cmd = args.join(" ");
        let output = self.client.shell(&self.serial, &cmd).await?;
        let mut packages = parse_pm_list_output(&output);
        if let Some(ref filter) = opts.name_filter {
            let lower = filter.to_lowercase();
            packages.retain(|p| p.package_name.to_lowercase().contains(&lower));
        }
        Ok(packages)
    }

    /// List only third-party (user-installed) packages.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn list_third_party(&self) -> Result<Vec<PackageInfo>> {
        let opts = ListOptions {
            third_party_only: true,
            include_paths: true,
            ..Default::default()
        };
        self.list_packages(&opts).await
    }

    /// List only system packages.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn list_system(&self) -> Result<Vec<PackageInfo>> {
        let opts = ListOptions {
            system_only: true,
            include_paths: true,
            ..Default::default()
        };
        self.list_packages(&opts).await
    }

    /// Get detailed info for a specific package.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn get_package_info(&self, package: &str) -> Result<PackageDetails> {
        // First get the APK path via `pm list packages -f`
        let list_cmd = format!("pm list packages -f {}", crate::shell::shell_escape(package));
        let list_out = self.client.shell(&self.serial, &list_cmd).await?;
        let base_info = parse_pm_list_output(&list_out)
            .into_iter()
            .find(|p| p.package_name == package)
            .unwrap_or_else(|| PackageInfo {
                package_name: package.to_owned(),
                apk_path: None,
                version_code: None,
                version_name: None,
                is_system: false,
            });

        let dump_cmd = format!("pm dump {}", crate::shell::shell_escape(package));
        let dump_out = self.client.shell(&self.serial, &dump_cmd).await?;
        Ok(parse_pm_dump(package, &dump_out, base_info))
    }

    /// Install an APK from a local path.
    ///
    /// Pushes the APK to `/data/local/tmp/`, installs it, then removes the temp file.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn install_apk(&self, apk_path: &Path, extra_flags: &[&str]) -> Result<()> {
        let filename = apk_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("install.apk");
        let tmp_path = format!("/data/local/tmp/{filename}");

        // Push APK
        self.client.push(&self.serial, apk_path, &tmp_path).await?;

        // Install
        let cmd = build_install_command(&tmp_path, extra_flags);
        let output = self.client.shell(&self.serial, &cmd).await?;

        // Cleanup
        let _ = self
            .client
            .shell(&self.serial, &format!("rm {}", crate::shell::shell_escape(&tmp_path)))
            .await;

        if install_succeeded(&output) {
            Ok(())
        } else {
            let reason =
                extract_install_failure(&output).unwrap_or_else(|| output.trim().to_owned());
            Err(AdbError::CommandFailed(reason))
        }
    }

    /// Uninstall a package by name.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn uninstall_package(&self, package: &str, keep_data: bool) -> Result<()> {
        let cmd = build_uninstall_command(package, keep_data);
        let output = self.client.shell(&self.serial, &cmd).await?;
        if uninstall_succeeded(&output) {
            Ok(())
        } else {
            Err(AdbError::CommandFailed(output.trim().to_owned()))
        }
    }

    /// Clear all data for a package (`pm clear <pkg>`).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn clear_data(&self, package: &str) -> Result<()> {
        let output = self
            .client
            .shell(&self.serial, &format!("pm clear {}", crate::shell::shell_escape(package)))
            .await?;
        if output.contains("Success") {
            Ok(())
        } else {
            Err(AdbError::CommandFailed(output.trim().to_owned()))
        }
    }

    /// Enable a package.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn enable(&self, package: &str) -> Result<()> {
        self.client
            .shell(&self.serial, &format!("pm enable {}", crate::shell::shell_escape(package)))
            .await?;
        Ok(())
    }

    /// Disable a package (for the current user).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn disable(&self, package: &str) -> Result<()> {
        self.client
            .shell(&self.serial, &format!("pm disable-user {}", crate::shell::shell_escape(package)))
            .await?;
        Ok(())
    }

    /// Grant a runtime permission to a package.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn grant_permission(&self, package: &str, permission: &str) -> Result<()> {
        let output = self
            .client
            .shell(
                &self.serial,
                &format!(
                    "pm grant {} {}",
                    crate::shell::shell_escape(package),
                    crate::shell::shell_escape(permission)
                ),
            )
            .await?;
        if output.trim().is_empty() || output.contains("granted") {
            Ok(())
        } else {
            Err(AdbError::CommandFailed(output.trim().to_owned()))
        }
    }

    /// Revoke a runtime permission from a package.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn revoke_permission(&self, package: &str, permission: &str) -> Result<()> {
        let output = self
            .client
            .shell(
                &self.serial,
                &format!(
                    "pm revoke {} {}",
                    crate::shell::shell_escape(package),
                    crate::shell::shell_escape(permission)
                ),
            )
            .await?;
        if output.trim().is_empty() {
            Ok(())
        } else {
            Err(AdbError::CommandFailed(output.trim().to_owned()))
        }
    }

    /// Return `true` if the package is installed.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn is_installed(&self, package: &str) -> Result<bool> {
        let cmd = format!("pm list packages {}", crate::shell::shell_escape(package));
        let output = self.client.shell(&self.serial, &cmd).await?;
        Ok(output.lines().any(|l| {
            l.trim()
                .split('=')
                .next_back()
                .is_some_and(|p| p == package)
        }))
    }

    /// Start the app's default activity via `monkey`.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn launch(&self, package: &str) -> Result<()> {
        let cmd = format!("monkey -p '{package}' -c android.intent.category.LAUNCHER 1");
        let output = self.client.shell(&self.serial, &cmd).await?;
        if output.contains("Events injected: 1") {
            Ok(())
        } else {
            Err(AdbError::CommandFailed(output.trim().to_owned()))
        }
    }

    /// Force-stop a running package.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn force_stop(&self, package: &str) -> Result<()> {
        self.client
            .shell(&self.serial, &format!("am force-stop {}", crate::shell::shell_escape(package)))
            .await?;
        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_pm_list_line ────────────────────────────────────────────────────

    #[test]
    fn test_parse_pm_list_with_path() {
        let line = "package:/data/app/com.example-ABCDEF==.apk=com.example";
        let p = parse_pm_list_line(line).unwrap();
        assert_eq!(p.package_name, "com.example");
        assert!(p.apk_path.is_some());
        assert!(!p.is_system);
    }

    #[test]
    fn test_parse_pm_list_without_path() {
        let line = "package:com.android.settings";
        let p = parse_pm_list_line(line).unwrap();
        assert_eq!(p.package_name, "com.android.settings");
        assert!(p.apk_path.is_none());
    }

    #[test]
    fn test_parse_pm_list_system_path() {
        let line = "package:/system/app/Settings/Settings.apk=com.android.settings";
        let p = parse_pm_list_line(line).unwrap();
        assert!(p.is_system);
    }

    #[test]
    fn test_parse_pm_list_empty_package_name() {
        assert!(parse_pm_list_line("package:").is_none());
    }

    #[test]
    fn test_parse_pm_list_non_package_line() {
        assert!(parse_pm_list_line("Total packages: 5").is_none());
    }

    #[test]
    fn test_parse_pm_list_output_multiple() {
        let output = "package:/data/app/com.a-1.apk=com.a\npackage:/data/app/com.b-2.apk=com.b\n";
        let packages = parse_pm_list_output(output);
        assert_eq!(packages.len(), 2);
    }

    // ── install/uninstall helpers ─────────────────────────────────────────────

    #[test]
    fn test_install_succeeded_positive() {
        assert!(install_succeeded("Performing Streamed Install\nSuccess\n"));
    }

    #[test]
    fn test_install_succeeded_negative() {
        assert!(!install_succeeded("INSTALL_FAILED_ALREADY_EXISTS"));
    }

    #[test]
    fn test_uninstall_succeeded_positive() {
        assert!(uninstall_succeeded("Success\n"));
    }

    #[test]
    fn test_uninstall_succeeded_negative() {
        assert!(!uninstall_succeeded("Failure\n"));
    }

    #[test]
    fn test_extract_install_failure_bracket() {
        let output = "Failure [INSTALL_FAILED_VERSION_DOWNGRADE]";
        let reason = extract_install_failure(output).unwrap();
        assert!(reason.contains("INSTALL_FAILED_VERSION_DOWNGRADE"));
    }

    #[test]
    fn test_extract_install_failure_error_prefix() {
        let output = "Error: Unable to open file";
        let reason = extract_install_failure(output).unwrap();
        assert!(reason.contains("Error:"));
    }

    #[test]
    fn test_extract_install_failure_success() {
        let output = "Success";
        assert!(extract_install_failure(output).is_none());
    }

    // ── build_install_command ─────────────────────────────────────────────────

    #[test]
    fn test_build_install_command_basic() {
        let cmd = build_install_command("/data/local/tmp/app.apk", &[]);
        assert!(cmd.contains("pm install -r"));
        assert!(cmd.contains("app.apk"));
    }

    #[test]
    fn test_build_install_command_with_flags() {
        let cmd = build_install_command("/data/local/tmp/app.apk", &["-t", "-g"]);
        assert!(cmd.contains("-t"));
        assert!(cmd.contains("-g"));
    }

    #[test]
    fn test_build_uninstall_command_basic() {
        let cmd = build_uninstall_command("com.example", false);
        assert!(cmd.contains("pm uninstall"));
        assert!(cmd.contains("com.example"));
        assert!(!cmd.contains("-k"));
    }

    #[test]
    fn test_build_uninstall_command_keep_data() {
        let cmd = build_uninstall_command("com.example", true);
        assert!(cmd.contains("-k"));
    }

    // ── InstallLocation ───────────────────────────────────────────────────────

    #[test]
    fn test_install_location_internal() {
        assert_eq!(
            InstallLocation::from_path("/data/app/com.example-1.apk"),
            InstallLocation::InternalStorage
        );
    }

    #[test]
    fn test_install_location_system() {
        assert_eq!(
            InstallLocation::from_path("/system/app/Settings.apk"),
            InstallLocation::System
        );
    }

    #[test]
    fn test_install_location_external() {
        assert_eq!(
            InstallLocation::from_path("/mnt/asec/com.example-1/pkg.apk"),
            InstallLocation::ExternalStorage
        );
    }

    #[test]
    fn test_install_location_unknown() {
        assert_eq!(
            InstallLocation::from_path("/weird/path/app.apk"),
            InstallLocation::Unknown
        );
    }

    // ── ListOptions ───────────────────────────────────────────────────────────

    #[test]
    fn test_list_options_default_args() {
        let opts = ListOptions::default();
        let args = opts.pm_args();
        assert!(args.contains(&"list"));
        assert!(args.contains(&"packages"));
    }

    #[test]
    fn test_list_options_third_party() {
        let opts = ListOptions {
            third_party_only: true,
            include_paths: true,
            ..Default::default()
        };
        let args = opts.pm_args();
        assert!(args.contains(&"-3"));
        assert!(args.contains(&"-f"));
    }

    #[test]
    fn test_list_options_system_only() {
        let opts = ListOptions {
            system_only: true,
            ..Default::default()
        };
        let args = opts.pm_args();
        assert!(args.contains(&"-s"));
    }

    // ── parse_pm_dump ─────────────────────────────────────────────────────────

    #[test]
    fn test_parse_pm_dump_version_code() {
        let dump = "Package [com.example] (xxx):\n  versionCode=42 targetSdk=30\n";
        let base = PackageInfo {
            package_name: "com.example".into(),
            apk_path: Some("/data/app/com.example-1.apk".into()),
            version_code: None,
            version_name: None,
            is_system: false,
        };
        let details = parse_pm_dump("com.example", dump, base);
        assert_eq!(details.info.version_code, Some(42));
        assert_eq!(details.target_sdk, Some(30));
    }

    #[test]
    fn test_parse_pm_dump_uid() {
        let dump = "  userId=10123\n";
        let base = PackageInfo {
            package_name: "com.x".into(),
            apk_path: None,
            version_code: None,
            version_name: None,
            is_system: false,
        };
        let details = parse_pm_dump("com.x", dump, base);
        assert_eq!(details.uid, Some(10123));
    }

    #[test]
    fn test_parse_pm_dump_enabled_by_default() {
        let dump = "  versionCode=1\n";
        let base = PackageInfo {
            package_name: "com.x".into(),
            apk_path: None,
            version_code: None,
            version_name: None,
            is_system: false,
        };
        let details = parse_pm_dump("com.x", dump, base);
        assert!(details.enabled);
    }

    #[test]
    fn test_parse_pm_dump_disabled() {
        let dump = "  enabled=false\n";
        let base = PackageInfo {
            package_name: "com.x".into(),
            apk_path: None,
            version_code: None,
            version_name: None,
            is_system: false,
        };
        let details = parse_pm_dump("com.x", dump, base);
        assert!(!details.enabled);
    }

    // ── PackageFlags ──────────────────────────────────────────────────────────

    #[test]
    fn test_package_flags_system() {
        let flags = PackageFlags::SYSTEM;
        assert!(flags.contains(PackageFlags::SYSTEM));
        assert!(!flags.contains(PackageFlags::DEBUGGABLE));
    }

    #[test]
    fn test_package_flags_combine() {
        let flags = PackageFlags::SYSTEM | PackageFlags::DEBUGGABLE;
        assert!(flags.contains(PackageFlags::SYSTEM));
        assert!(flags.contains(PackageFlags::DEBUGGABLE));
    }

    // ── Extract helpers ───────────────────────────────────────────────────────

    #[test]
    fn test_extract_version_code() {
        let dump = "    versionCode=99 targetSdk=31\n";
        assert_eq!(extract_version_code(dump), Some(99));
    }

    #[test]
    fn test_extract_version_name() {
        let dump = "    versionName=1.2.3\n";
        assert_eq!(extract_version_name(dump), Some("1.2.3".to_owned()));
    }

    #[test]
    fn test_extract_uid_from_dump() {
        let dump = "  userId=10456\n";
        assert_eq!(extract_uid(dump), Some(10456));
    }

    #[test]
    fn test_extract_target_sdk() {
        let dump = "    versionCode=1 targetSdk=33\n";
        assert_eq!(extract_target_sdk(dump), Some(33));
    }

    #[test]
    fn test_extract_permissions_section() {
        let dump = "grantedPermissions:\n  android.permission.INTERNET\n  android.permission.CAMERA\nSomeOtherSection:\n";
        let perms = extract_permissions(dump);
        assert!(!perms.is_empty());
    }

    #[test]
    fn test_extract_activities() {
        let dump =
            "  Activity com.example/.MainActivity:\n  Activity com.example/.SettingsActivity:\n";
        let acts = extract_activities(dump);
        assert_eq!(acts.len(), 2);
    }

    // ── PackageInfo serde ─────────────────────────────────────────────────────

    #[test]
    fn test_package_info_serde() {
        let p = PackageInfo {
            package_name: "com.test".into(),
            apk_path: Some("/data/app/test.apk".into()),
            version_code: Some(5),
            version_name: Some("1.0.5".into()),
            is_system: false,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: PackageInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.package_name, "com.test");
        assert_eq!(back.version_code, Some(5));
    }
}
