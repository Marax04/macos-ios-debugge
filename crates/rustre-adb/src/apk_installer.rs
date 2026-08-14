//! `apk_installer` — Install and uninstall APKs via ADB.
//!
//! Pushes the APK to `/data/local/tmp/`, invokes `pm install`, tracks the
//! result, and cleans up temporary files.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// InstallOptions
// ─────────────────────────────────────────────────────────────────────────────

/// Options for `pm install`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallOptions {
    /// Replace an existing app (`-r`).
    pub replace: bool,
    /// Allow version downgrade (`-d`).
    pub allow_downgrade: bool,
    /// Grant all runtime permissions at install time (`-g`).
    pub grant_permissions: bool,
    /// Install to external storage (`--sdcard`).
    pub external_storage: bool,
    /// Forward lock installation (`-l`).
    pub forward_lock: bool,
    /// Bypass signature verification (requires `--bypass-low-target-sdk-block` on newer APIs).
    pub bypass_verification: bool,
    /// Staging directory on device (default `/data/local/tmp`).
    pub staging_dir: String,
    /// Shell command timeout in seconds.
    pub timeout_secs: u64,
    /// Whether to remove the APK from the staging area after install.
    pub clean_staging: bool,
}

impl Default for InstallOptions {
    fn default() -> Self {
        Self {
            replace: true,
            allow_downgrade: false,
            grant_permissions: false,
            external_storage: false,
            forward_lock: false,
            bypass_verification: false,
            staging_dir: "/data/local/tmp".to_owned(),
            timeout_secs: 120,
            clean_staging: true,
        }
    }
}

impl InstallOptions {
    /// Create default options.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable all-permissions grant.
    #[must_use]
    pub const fn with_grant_permissions(mut self) -> Self {
        self.grant_permissions = true;
        self
    }

    /// Enable downgrade.
    #[must_use]
    pub const fn with_allow_downgrade(mut self) -> Self {
        self.allow_downgrade = true;
        self
    }

    /// Build the `pm install` argument string for these options.
    #[must_use]
    pub fn pm_install_args(&self) -> String {
        let mut args = Vec::new();
        if self.replace {
            args.push("-r");
        }
        if self.allow_downgrade {
            args.push("-d");
        }
        if self.grant_permissions {
            args.push("-g");
        }
        if self.external_storage {
            args.push("--sdcard");
        }
        if self.forward_lock {
            args.push("-l");
        }
        args.join(" ")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InstallStatus
// ─────────────────────────────────────────────────────────────────────────────

/// Status of an install operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstallStatus {
    /// Not yet started.
    Pending,
    /// APK is being transferred to device.
    Pushing,
    /// `pm install` is running.
    Installing,
    /// Install completed successfully.
    Success,
    /// Install failed.
    Failed,
    /// Install was cancelled.
    Cancelled,
}

impl InstallStatus {
    /// Returns `true` if the install is in a terminal state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Success | Self::Failed | Self::Cancelled)
    }
}

impl std::fmt::Display for InstallStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Pending => "pending",
            Self::Pushing => "pushing",
            Self::Installing => "installing",
            Self::Success => "success",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InstallFailureCode
// ─────────────────────────────────────────────────────────────────────────────

/// Reason codes for install failure as reported by `pm install`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstallFailureCode {
    AlreadyExists,
    InvalidApk,
    InvalidUri,
    InsufficientStorage,
    Conflict,
    VersionDowngrade,
    PermissionDenied,
    DeviceNotConnected,
    ParseFailed,
    UpdateIncompatible,
    Unknown(String),
}

impl InstallFailureCode {
    /// Parse a `pm install` failure output string into a code.
    #[must_use]
    pub fn from_pm_output(output: &str) -> Self {
        if output.contains("INSTALL_FAILED_ALREADY_EXISTS") {
            Self::AlreadyExists
        } else if output.contains("INSTALL_FAILED_INVALID_APK") {
            Self::InvalidApk
        } else if output.contains("INSTALL_FAILED_INVALID_URI") {
            Self::InvalidUri
        } else if output.contains("INSTALL_FAILED_INSUFFICIENT_STORAGE") {
            Self::InsufficientStorage
        } else if output.contains("INSTALL_FAILED_CONFLICTING_PROVIDER") {
            Self::Conflict
        } else if output.contains("INSTALL_FAILED_VERSION_DOWNGRADE") {
            Self::VersionDowngrade
        } else if output.contains("INSTALL_PARSE_FAILED") {
            Self::ParseFailed
        } else if output.contains("INSTALL_FAILED_UPDATE_INCOMPATIBLE") {
            Self::UpdateIncompatible
        } else {
            Self::Unknown(output.trim().to_owned())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InstallResult
// ─────────────────────────────────────────────────────────────────────────────

/// The result of an APK installation attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallResult {
    /// Final status of the install.
    pub status: InstallStatus,
    /// Package name that was installed (if determinable from the APK).
    pub package_name: Option<String>,
    /// Path the APK was pushed to on the device.
    pub device_path: String,
    /// Raw `pm install` output.
    pub pm_output: String,
    /// Failure code if the install failed.
    pub failure_code: Option<InstallFailureCode>,
    /// Total wall-clock duration of the operation.
    pub duration: Duration,
    /// Size of the APK in bytes.
    pub apk_size_bytes: u64,
}

impl InstallResult {
    /// Returns `true` if the install succeeded.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self.status, InstallStatus::Success)
    }

    /// Build a human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let pkg = self.package_name.as_deref().unwrap_or("unknown");
        match self.status {
            InstallStatus::Success => format!(
                "Installed {pkg} ({} bytes) in {:.1}s",
                self.apk_size_bytes,
                self.duration.as_secs_f64()
            ),
            InstallStatus::Failed => {
                let code = self
                    .failure_code
                    .as_ref()
                    .map_or_else(|| "UNKNOWN".to_string(), |c| format!("{c:?}"));
                format!("Install FAILED for {pkg}: {code}")
            }
            _ => format!("Install {}", self.status),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ApkInstaller
// ─────────────────────────────────────────────────────────────────────────────

/// Install and uninstall APKs on a connected Android device via an [`AdbClient`].
///
/// This type is intentionally pure (no async runtime embedded) so it can be
/// used with any async executor.  The actual network I/O is performed by
/// the [`crate::AdbClient`] methods.
#[derive(Debug, Clone)]
pub struct ApkInstaller {
    /// Serial number of the target device.
    pub serial: String,
    /// Default installation options.
    pub options: InstallOptions,
}

impl ApkInstaller {
    /// Create a new installer for `serial`.
    #[must_use]
    pub fn new(serial: impl Into<String>) -> Self {
        Self {
            serial: serial.into(),
            options: InstallOptions::default(),
        }
    }

    /// Create a new installer with custom options.
    #[must_use]
    pub fn with_options(serial: impl Into<String>, options: InstallOptions) -> Self {
        Self {
            serial: serial.into(),
            options,
        }
    }

    /// Build the full shell command to push and install an APK.
    ///
    /// Returns `(push_dest, pm_command)` where `push_dest` is the device path
    /// the APK will be pushed to.
    #[must_use]
    pub fn build_install_command(&self, apk_path: &Path) -> (String, String) {
        let filename = apk_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("app.apk");
        let dest = format!("{}/{}", self.options.staging_dir, filename);
        let pm_args = self.options.pm_install_args();
        let pm_cmd = format!("pm install {pm_args} {}", crate::shell::shell_escape(&dest));
        (dest, pm_cmd)
    }

    /// Build the `pm uninstall` command for a package.
    #[must_use]
    pub fn build_uninstall_command(package: &str, keep_data: bool) -> String {
        if keep_data {
            format!("pm uninstall -k {}", crate::shell::shell_escape(package))
        } else {
            format!("pm uninstall {}", crate::shell::shell_escape(package))
        }
    }

    /// Parse raw `pm install` / `pm uninstall` output to determine success.
    ///
    /// Returns `(success, failure_code)`.
    #[must_use]
    pub fn parse_pm_output(output: &str) -> (bool, Option<InstallFailureCode>) {
        let trimmed = output.trim();
        if trimmed.contains("Success") {
            (true, None)
        } else {
            let code = InstallFailureCode::from_pm_output(trimmed);
            (false, Some(code))
        }
    }

    /// Parse the package name from `aapt dump badging` output.
    ///
    /// Looks for `package: name='com.example'` in the output.
    #[must_use]
    pub fn parse_package_name(aapt_output: &str) -> Option<String> {
        for line in aapt_output.lines() {
            let line = line.trim();
            if line.starts_with("package:") {
                // "package: name='com.example' versionCode='1' ..."
                if let Some(name_start) = line.find("name='") {
                    let after = &line[name_start + 6..];
                    if let Some(end) = after.find('\'') {
                        return Some(after[..end].to_owned());
                    }
                }
            }
        }
        None
    }

    /// Parse the package name from an APK manifest XML snippet.
    ///
    /// Looks for `package="com.example"` in the XML.
    #[must_use]
    pub fn parse_package_name_from_manifest(xml: &str) -> Option<String> {
        // Simple string search; no full XML parser required.
        let marker = "package=\"";
        if let Some(start) = xml.find(marker) {
            let after = &xml[start + marker.len()..];
            if let Some(end) = after.find('"') {
                let pkg = &after[..end];
                if !pkg.is_empty() {
                    return Some(pkg.to_owned());
                }
            }
        }
        None
    }

    /// Verify that a local file is a plausible APK (starts with ZIP PK magic).
    #[must_use]
    pub fn verify_apk_magic(data: &[u8]) -> bool {
        data.len() >= 4 && data[0] == b'P' && data[1] == b'K' && data[2] == 0x03 && data[3] == 0x04
    }

    /// Return the staging path for a given filename and options.
    #[must_use]
    pub fn staging_path(&self, filename: &str) -> String {
        format!("{}/{}", self.options.staging_dir, filename)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UninstallResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result of an uninstall operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UninstallResult {
    /// Whether the uninstall succeeded.
    pub success: bool,
    /// Package that was uninstalled.
    pub package_name: String,
    /// Raw `pm uninstall` output.
    pub pm_output: String,
    /// Whether app data was preserved (`-k` flag).
    pub data_preserved: bool,
}

impl UninstallResult {
    /// Create a successful uninstall result.
    #[must_use]
    pub fn success(package: impl Into<String>, output: impl Into<String>, data_preserved: bool) -> Self {
        Self {
            success: true,
            package_name: package.into(),
            pm_output: output.into(),
            data_preserved,
        }
    }

    /// Create a failed uninstall result.
    #[must_use]
    pub fn failure(package: impl Into<String>, output: impl Into<String>) -> Self {
        Self {
            success: false,
            package_name: package.into(),
            pm_output: output.into(),
            data_preserved: false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InstallQueue
// ─────────────────────────────────────────────────────────────────────────────

/// A queue of APKs to be installed sequentially.
#[derive(Debug, Default)]
pub struct InstallQueue {
    items: Vec<(PathBuf, InstallOptions)>,
}

impl InstallQueue {
    /// Create an empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enqueue an APK with default options.
    pub fn enqueue(&mut self, path: impl Into<PathBuf>) {
        self.items.push((path.into(), InstallOptions::default()));
    }

    /// Enqueue an APK with specific options.
    pub fn enqueue_with_options(&mut self, path: impl Into<PathBuf>, opts: InstallOptions) {
        self.items.push((path.into(), opts));
    }

    /// Return the number of queued items.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns `true` if the queue is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Pop the next item from the front of the queue.
    #[must_use]
    pub fn pop_front(&mut self) -> Option<(PathBuf, InstallOptions)> {
        if self.items.is_empty() {
            None
        } else {
            Some(self.items.remove(0))
        }
    }

    /// Return all queued paths (without consuming the queue).
    #[must_use]
    pub fn paths(&self) -> Vec<&Path> {
        self.items.iter().map(|(p, _)| p.as_path()).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_install_options_default() {
        let o = InstallOptions::default();
        assert!(o.replace);
        assert!(!o.allow_downgrade);
        assert!(o.clean_staging);
    }

    #[test]
    fn test_pm_install_args_replace() {
        let o = InstallOptions::new();
        let args = o.pm_install_args();
        assert!(args.contains("-r"));
    }

    #[test]
    fn test_pm_install_args_all_flags() {
        let o = InstallOptions {
            replace: true,
            allow_downgrade: true,
            grant_permissions: true,
            external_storage: false,
            forward_lock: false,
            bypass_verification: false,
            staging_dir: "/data/local/tmp".to_owned(),
            timeout_secs: 60,
            clean_staging: true,
        };
        let args = o.pm_install_args();
        assert!(args.contains("-r"));
        assert!(args.contains("-d"));
        assert!(args.contains("-g"));
    }

    #[test]
    fn test_build_install_command() {
        let installer = ApkInstaller::new("emulator-5554");
        let path = Path::new("/tmp/app-debug.apk");
        let (dest, cmd) = installer.build_install_command(path);
        assert!(dest.ends_with("app-debug.apk"));
        assert!(cmd.contains("pm install"));
        assert!(cmd.contains("app-debug.apk"));
    }

    #[test]
    fn test_build_uninstall_command() {
        let cmd = ApkInstaller::build_uninstall_command("com.example", false);
        assert!(cmd.contains("pm uninstall"));
        assert!(cmd.contains("com.example"));
        assert!(!cmd.contains("-k"));
    }

    #[test]
    fn test_build_uninstall_keep_data() {
        let cmd = ApkInstaller::build_uninstall_command("com.example", true);
        assert!(cmd.contains("-k"));
    }

    #[test]
    fn test_parse_pm_output_success() {
        let (ok, code) = ApkInstaller::parse_pm_output("Success\n");
        assert!(ok);
        assert!(code.is_none());
    }

    #[test]
    fn test_parse_pm_output_failure_version() {
        let out = "Failure [INSTALL_FAILED_VERSION_DOWNGRADE]";
        let (ok, code) = ApkInstaller::parse_pm_output(out);
        assert!(!ok);
        assert_eq!(code, Some(InstallFailureCode::VersionDowngrade));
    }

    #[test]
    fn test_parse_pm_output_failure_storage() {
        let out = "Failure [INSTALL_FAILED_INSUFFICIENT_STORAGE]";
        let (ok, code) = ApkInstaller::parse_pm_output(out);
        assert!(!ok);
        assert_eq!(code, Some(InstallFailureCode::InsufficientStorage));
    }

    #[test]
    fn test_parse_package_name_aapt() {
        let output = "package: name='com.example.app' versionCode='10' versionName='1.0'";
        let pkg = ApkInstaller::parse_package_name(output).unwrap();
        assert_eq!(pkg, "com.example.app");
    }

    #[test]
    fn test_parse_package_name_manifest() {
        let xml = r#"<manifest package="com.test.app" android:versionCode="1">"#;
        let pkg = ApkInstaller::parse_package_name_from_manifest(xml).unwrap();
        assert_eq!(pkg, "com.test.app");
    }

    #[test]
    fn test_verify_apk_magic_valid() {
        let data = [b'P', b'K', 0x03, 0x04, 0x00, 0x00];
        assert!(ApkInstaller::verify_apk_magic(&data));
    }

    #[test]
    fn test_verify_apk_magic_invalid() {
        let data = [0x7F, b'E', b'L', b'F'];
        assert!(!ApkInstaller::verify_apk_magic(&data));
    }

    #[test]
    fn test_install_result_is_success() {
        let r = InstallResult {
            status: InstallStatus::Success,
            package_name: Some("com.example".to_string()),
            device_path: "/data/local/tmp/app.apk".to_string(),
            pm_output: "Success".to_string(),
            failure_code: None,
            duration: Duration::from_secs(5),
            apk_size_bytes: 1024,
        };
        assert!(r.is_success());
        assert!(r.summary().contains("com.example"));
    }

    #[test]
    fn test_install_status_is_terminal() {
        assert!(InstallStatus::Success.is_terminal());
        assert!(InstallStatus::Failed.is_terminal());
        assert!(!InstallStatus::Pushing.is_terminal());
    }

    #[test]
    fn test_install_queue() {
        let mut q = InstallQueue::new();
        q.enqueue("/tmp/a.apk");
        q.enqueue("/tmp/b.apk");
        assert_eq!(q.len(), 2);
        let first = q.pop_front().unwrap();
        assert_eq!(first.0, PathBuf::from("/tmp/a.apk"));
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn test_install_queue_is_empty() {
        let q = InstallQueue::new();
        assert!(q.is_empty());
    }

    #[test]
    fn test_uninstall_result_success() {
        let r = UninstallResult::success("com.example", "Success", false);
        assert!(r.success);
        assert_eq!(r.package_name, "com.example");
    }

    #[test]
    fn test_uninstall_result_failure() {
        let r = UninstallResult::failure("com.gone", "Failure [DELETE_FAILED]");
        assert!(!r.success);
    }

    #[test]
    fn test_staging_path() {
        let installer = ApkInstaller::new("device1");
        assert_eq!(
            installer.staging_path("app.apk"),
            "/data/local/tmp/app.apk"
        );
    }
}
