//! iOS App Bundle structure analysis.
//!
//! Represents an `.app` directory on disk and provides structured access to
//! Info.plist, entitlements, embedded frameworks, plugins, and binary info.

use crate::IosError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ─── Platform ─────────────────────────────────────────────────────────────────

/// An Apple platform identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    IphoneOs,
    MacOsX,
    TvOs,
    WatchOs,
    VisionOs,
    IphoneSimulator,
    AppleTvSimulator,
    WatchSimulator,
    XrOs,
}

impl Platform {
    /// Parse from a `CFBundleSupportedPlatforms` string.
    #[must_use]
    pub fn parse_platform(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "iphoneos" => Some(Self::IphoneOs),
            "macosx" => Some(Self::MacOsX),
            "tvos" => Some(Self::TvOs),
            "watchos" => Some(Self::WatchOs),
            "visionos" | "xros" => Some(Self::VisionOs),
            "iphonesimulator" => Some(Self::IphoneSimulator),
            "appletvsimulator" => Some(Self::AppleTvSimulator),
            "watchsimulator" => Some(Self::WatchSimulator),
            _ => None,
        }
    }

    /// Return the canonical string representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::IphoneOs => "iphoneos",
            Self::MacOsX => "macosx",
            Self::TvOs => "tvos",
            Self::WatchOs => "watchos",
            Self::VisionOs => "visionos",
            Self::IphoneSimulator => "iphonesimulator",
            Self::AppleTvSimulator => "appletvsimulator",
            Self::WatchSimulator => "watchsimulator",
            Self::XrOs => "xros",
        }
    }
}

// ─── EmbeddedFramework ────────────────────────────────────────────────────────

/// An embedded `.framework` inside the app bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedFramework {
    pub name: String,
    pub path: PathBuf,
    pub binary_path: PathBuf,
    pub is_swift: bool,
    pub is_xcframework: bool,
}

// ─── EmbeddedDylib ────────────────────────────────────────────────────────────

/// A raw `.dylib` embedded in the app bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedDylib {
    pub name: String,
    pub path: PathBuf,
    pub size: u64,
}

// ─── AppPlugin ────────────────────────────────────────────────────────────────

/// An app extension (`.appex`) bundled in `PlugIns/`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppPlugin {
    pub name: String,
    pub path: PathBuf,
    pub extension_point: Option<String>,
    pub bundle_id: Option<String>,
}

// ─── WatchApp ─────────────────────────────────────────────────────────────────

/// A Watch app embedded in `Watch/`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchApp {
    pub name: String,
    pub path: PathBuf,
    pub minimum_watch_os: Option<String>,
}

// ─── BundleBinary ─────────────────────────────────────────────────────────────

/// The main Mach-O binary of an app bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleBinary {
    pub path: PathBuf,
    pub size: u64,
    pub is_fat: bool,
    pub architectures: Vec<String>,
}

impl BundleBinary {
    /// Return `true` if the binary supports arm64.
    #[must_use]
    pub fn supports_arm64(&self) -> bool {
        self.architectures
            .iter()
            .any(|a| a == "arm64" || a == "arm64e")
    }

    /// Return `true` if the binary supports `x86_64` (Simulator / Catalyst).
    #[must_use]
    pub fn supports_x86_64(&self) -> bool {
        self.architectures.iter().any(|a| a == "x86_64")
    }
}

// ─── AtsConfig ────────────────────────────────────────────────────────────────

/// Simplified App Transport Security configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AtsConfig {
    pub allows_arbitrary_loads: bool,
    pub exception_domains: Vec<String>,
}

// ─── AppBundle ────────────────────────────────────────────────────────────────

/// Represents a parsed `.app` bundle directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppBundle {
    pub path: PathBuf,
    pub bundle_id: Option<String>,
    pub display_name: Option<String>,
    pub bundle_version: Option<String>,
    pub short_version: Option<String>,
    pub minimum_os_version: Option<String>,
    pub main_executable_name: Option<String>,
    pub main_binary: Option<BundleBinary>,
    pub frameworks: Vec<EmbeddedFramework>,
    pub dylibs: Vec<EmbeddedDylib>,
    pub plugins: Vec<AppPlugin>,
    pub watch_app: Option<WatchApp>,
    pub supported_platforms: Vec<Platform>,
    pub url_schemes: Vec<String>,
    pub queried_url_schemes: Vec<String>,
    pub background_modes: Vec<String>,
    pub required_device_capabilities: Vec<String>,
    pub privacy_keys: Vec<String>,
    pub ats_config: Option<AtsConfig>,
}

impl AppBundle {
    /// Open an `.app` directory from the file system.
    ///
    /// # Errors
    /// Returns [`IosError`] if the path does not look like a valid `.app` directory.
    pub fn open(path: &Path) -> Result<Self, IosError> {
        if !path.is_dir() {
            return Err(IosError::InvalidBundle(format!(
                "{} is not a directory",
                path.display()
            )));
        }
        if !path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("app"))
        {
            return Err(IosError::InvalidBundle(
                "path does not have .app extension".into(),
            ));
        }

        // Try to find and parse Info.plist.
        let info_plist_path = path.join("Info.plist");
        let mut bundle = Self::empty(path.to_path_buf());

        if info_plist_path.exists() {
            let data = std::fs::read(&info_plist_path).map_err(|e| IosError::Io(e.to_string()))?;
            let plist = crate::plist::plist_auto_detect(&data)
                .map_err(|e| IosError::Plist(e.to_string()))?;
            let info = crate::info_plist::InfoPlist::from_plist(plist);

            bundle.bundle_id = info.bundle_id().map(str::to_string);
            bundle.display_name = info.display_name().map(str::to_string);
            bundle.bundle_version = info.bundle_version().map(str::to_string);
            bundle.short_version = info.bundle_short_version().map(str::to_string);
            bundle.minimum_os_version = info.minimum_os_version().map(str::to_string);
            bundle.main_executable_name = info.bundle_executable().map(str::to_string);
            bundle.url_schemes = info.url_schemes().into_iter().map(str::to_string).collect();
            bundle.queried_url_schemes = info
                .queried_url_schemes()
                .into_iter()
                .map(str::to_string)
                .collect();
            bundle.background_modes = info
                .background_modes()
                .into_iter()
                .map(str::to_string)
                .collect();
            bundle.required_device_capabilities = info
                .required_device_capabilities()
                .into_iter()
                .map(str::to_string)
                .collect();
            bundle.privacy_keys = info
                .privacy_usage_descriptions()
                .into_keys()
                .map(str::to_string)
                .collect();
        }

        // Probe Frameworks/ directory.
        let frameworks_dir = path.join("Frameworks");
        if frameworks_dir.is_dir()
            && let Ok(entries) = std::fs::read_dir(&frameworks_dir)
        {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("framework"))
                {
                    let name = p
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let binary_path = p.join(&name);
                    let is_swift = p.join("_CodeSignature").join("SwiftModules").exists()
                        || p.join("Modules").exists();
                    bundle.frameworks.push(EmbeddedFramework {
                        name,
                        is_swift,
                        binary_path,
                        path: p,
                        is_xcframework: false,
                    });
                }
            }
        }

        // Probe PlugIns/ directory.
        let plugins_dir = path.join("PlugIns");
        if plugins_dir.is_dir()
            && let Ok(entries) = std::fs::read_dir(&plugins_dir)
        {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("appex"))
                {
                    let name = p
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("unknown")
                        .to_string();
                    bundle.plugins.push(AppPlugin {
                        name,
                        path: p,
                        extension_point: None,
                        bundle_id: None,
                    });
                }
            }
        }

        // Probe Watch/ directory.
        let watch_dir = path.join("Watch");
        if watch_dir.is_dir()
            && let Ok(mut entries) = std::fs::read_dir(&watch_dir)
            && let Some(Ok(entry)) = entries.next()
        {
            let p = entry.path();
            let name = p
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("WatchApp")
                .to_string();
            bundle.watch_app = Some(WatchApp {
                name,
                path: p,
                minimum_watch_os: None,
            });
        }

        Ok(bundle)
    }

    /// Create an empty bundle struct for the given path (no parsing).
    #[must_use]
    pub const fn empty(path: PathBuf) -> Self {
        Self {
            path,
            bundle_id: None,
            display_name: None,
            bundle_version: None,
            short_version: None,
            minimum_os_version: None,
            main_executable_name: None,
            main_binary: None,
            frameworks: Vec::new(),
            dylibs: Vec::new(),
            plugins: Vec::new(),
            watch_app: None,
            supported_platforms: Vec::new(),
            url_schemes: Vec::new(),
            queried_url_schemes: Vec::new(),
            background_modes: Vec::new(),
            required_device_capabilities: Vec::new(),
            privacy_keys: Vec::new(),
            ats_config: None,
        }
    }

    /// Create a mock bundle for testing.
    #[must_use]
    pub fn mock() -> Self {
        Self {
            path: PathBuf::from("/tmp/ExampleApp.app"),
            bundle_id: Some("com.example.App".into()),
            display_name: Some("ExampleApp".into()),
            bundle_version: Some("42".into()),
            short_version: Some("3.1.4".into()),
            minimum_os_version: Some("16.0".into()),
            main_executable_name: Some("ExampleApp".into()),
            main_binary: Some(BundleBinary {
                path: PathBuf::from("/tmp/ExampleApp.app/ExampleApp"),
                size: 4 * 1024 * 1024,
                is_fat: true,
                architectures: vec!["arm64".into(), "arm64e".into()],
            }),
            frameworks: vec![EmbeddedFramework {
                name: "Alamofire".into(),
                path: PathBuf::from("/tmp/ExampleApp.app/Frameworks/Alamofire.framework"),
                binary_path: PathBuf::from(
                    "/tmp/ExampleApp.app/Frameworks/Alamofire.framework/Alamofire",
                ),
                is_swift: true,
                is_xcframework: false,
            }],
            dylibs: vec![],
            plugins: vec![],
            watch_app: None,
            supported_platforms: vec![Platform::IphoneOs],
            url_schemes: vec!["exampleapp".into()],
            queried_url_schemes: vec!["fb".into()],
            background_modes: vec!["audio".into()],
            required_device_capabilities: vec!["arm64".into()],
            privacy_keys: vec!["NSCameraUsageDescription".into()],
            ats_config: Some(AtsConfig {
                allows_arbitrary_loads: false,
                exception_domains: vec![],
            }),
        }
    }

    /// Return `true` if this appears to be a macOS Catalyst app.
    #[must_use]
    pub fn is_catalyst(&self) -> bool {
        self.supported_platforms.contains(&Platform::MacOsX)
            && self.supported_platforms.contains(&Platform::IphoneOs)
    }

    /// Return the minimum OS version string or `"unknown"`.
    #[must_use]
    pub fn minimum_os_version(&self) -> &str {
        self.minimum_os_version.as_deref().unwrap_or("unknown")
    }

    /// Return the number of embedded frameworks.
    #[must_use]
    pub const fn framework_count(&self) -> usize {
        self.frameworks.len()
    }

    /// Return the number of plugin/extension targets.
    #[must_use]
    pub const fn plugin_count(&self) -> usize {
        self.plugins.len()
    }

    /// Return `true` if the binary supports arm64/arm64e.
    #[must_use]
    pub fn supports_arm64(&self) -> bool {
        self.main_binary
            .as_ref()
            .is_some_and(BundleBinary::supports_arm64)
    }

    /// Return `true` if any privacy description keys are declared.
    #[must_use]
    pub const fn has_privacy_keys(&self) -> bool {
        !self.privacy_keys.is_empty()
    }

    /// Return `true` if the app registers custom URL schemes.
    #[must_use]
    pub const fn has_url_schemes(&self) -> bool {
        !self.url_schemes.is_empty()
    }

    /// Return the full path to the main executable.
    #[must_use]
    pub fn executable_path(&self) -> Option<PathBuf> {
        self.main_executable_name
            .as_ref()
            .map(|name| self.path.join(name))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_bundle_id() {
        let b = AppBundle::mock();
        assert_eq!(b.bundle_id.as_deref(), Some("com.example.App"));
    }

    #[test]
    fn test_mock_min_os() {
        let b = AppBundle::mock();
        assert_eq!(b.minimum_os_version(), "16.0");
    }

    #[test]
    fn test_mock_framework_count() {
        let b = AppBundle::mock();
        assert_eq!(b.framework_count(), 1);
    }

    #[test]
    fn test_mock_plugin_count() {
        let b = AppBundle::mock();
        assert_eq!(b.plugin_count(), 0);
    }

    #[test]
    fn test_mock_supports_arm64() {
        let b = AppBundle::mock();
        assert!(b.supports_arm64());
    }

    #[test]
    fn test_mock_has_privacy_keys() {
        let b = AppBundle::mock();
        assert!(b.has_privacy_keys());
    }

    #[test]
    fn test_mock_has_url_schemes() {
        let b = AppBundle::mock();
        assert!(b.has_url_schemes());
    }

    #[test]
    fn test_mock_executable_path() {
        let b = AppBundle::mock();
        let p = b.executable_path().unwrap();
        assert!(p.ends_with("ExampleApp"));
    }

    #[test]
    fn test_platform_from_str() {
        assert_eq!(
            Platform::parse_platform("iphoneos"),
            Some(Platform::IphoneOs)
        );
        assert_eq!(Platform::parse_platform("macosx"), Some(Platform::MacOsX));
        assert_eq!(Platform::parse_platform("tvos"), Some(Platform::TvOs));
        assert_eq!(Platform::parse_platform("unknown"), None);
    }

    #[test]
    fn test_platform_as_str() {
        assert_eq!(Platform::IphoneOs.as_str(), "iphoneos");
        assert_eq!(Platform::WatchOs.as_str(), "watchos");
    }

    #[test]
    fn test_bundle_binary_arm64() {
        let b = BundleBinary {
            path: PathBuf::from("/tmp/App"),
            size: 1024,
            is_fat: false,
            architectures: vec!["arm64".into()],
        };
        assert!(b.supports_arm64());
        assert!(!b.supports_x86_64());
    }

    #[test]
    fn test_bundle_binary_fat() {
        let b = BundleBinary {
            path: PathBuf::from("/tmp/App"),
            size: 2048,
            is_fat: true,
            architectures: vec!["arm64".into(), "x86_64".into()],
        };
        assert!(b.supports_arm64());
        assert!(b.supports_x86_64());
    }

    #[test]
    fn test_is_catalyst_false() {
        let b = AppBundle::mock();
        // Mock only has IphoneOs.
        assert!(!b.is_catalyst());
    }

    #[test]
    fn test_empty_bundle() {
        let b = AppBundle::empty(PathBuf::from("/tmp/Foo.app"));
        assert!(b.bundle_id.is_none());
        assert_eq!(b.framework_count(), 0);
    }

    #[test]
    fn test_open_invalid_path() {
        let err = AppBundle::open(Path::new("/tmp/does_not_exist.app")).unwrap_err();
        matches!(err, IosError::InvalidBundle(_));
    }

    #[test]
    fn test_open_non_app_dir() {
        let err = AppBundle::open(Path::new("/tmp")).unwrap_err();
        matches!(err, IosError::InvalidBundle(_));
    }

    #[test]
    fn test_serialization() {
        let b = AppBundle::mock();
        let json = serde_json::to_string(&b).unwrap();
        let back: AppBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back.bundle_id, b.bundle_id);
    }
}
