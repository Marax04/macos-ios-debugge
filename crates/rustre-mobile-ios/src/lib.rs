//! `rustre-mobile-ios` — iOS bundle analysis: plist, entitlements, ObjC/Swift metadata,
//! code signature, PAC analysis, bundle structure.

pub mod fairplay;
pub mod bundle;
pub mod codesign;
pub mod entitlements;
pub mod info_plist;
pub mod ios_malware;
pub mod jailbreak_detection;
pub mod objc_runtime;
pub mod objc_runtime_analysis;
pub mod pac;
pub mod plist;
pub mod swift_metadata;
pub mod macho_objc_runtime;
pub mod ios_entitlements_parser;
pub mod ios_codesign_verifier;
pub mod ios_dylib_injector_detector;
pub mod ios_jailbreak_detector;
pub mod ios_swift_metadata_parser;

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum IosError {
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("missing info: {0}")]
    MissingInfo(String),
    #[error("invalid bundle: {0}")]
    InvalidBundle(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("codesign error: {0}")]
    CodeSign(String),
    #[error("plist error: {0}")]
    Plist(String),
}

// ─── IosPlatform ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IosPlatform {
    IphoneOs,
    MacOs,
    TvOs,
    WatchOs,
    VisionOs,
}

impl fmt::Display for IosPlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IphoneOs => write!(f, "iphoneos"),
            Self::MacOs => write!(f, "macos"),
            Self::TvOs => write!(f, "tvos"),
            Self::WatchOs => write!(f, "watchos"),
            Self::VisionOs => write!(f, "visionos"),
        }
    }
}

// ─── EntitlementValue ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntitlementValue {
    Bool(bool),
    Str(String),
    Array(Vec<String>),
}

impl fmt::Display for EntitlementValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(b) => write!(f, "{b}"),
            Self::Str(s) => write!(f, "{s}"),
            Self::Array(arr) => write!(f, "[{}]", arr.join(", ")),
        }
    }
}

// ─── Entitlement ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entitlement {
    pub key: String,
    pub value: EntitlementValue,
}

// ─── CodeSignature ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSignature {
    pub team_id: String,
    pub signing_id: String,
    pub entitlements: Vec<Entitlement>,
}

impl CodeSignature {
    /// Check if an entitlement key exists.
    #[must_use]
    pub fn has(&self, key: &str) -> bool {
        self.entitlements.iter().any(|e| e.key == key)
    }

    /// Get an entitlement value by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&EntitlementValue> {
        self.entitlements
            .iter()
            .find(|e| e.key == key)
            .map(|e| &e.value)
    }
}

// ─── BundleInfo ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleInfo {
    pub bundle_id: String,
    pub name: String,
    pub version: String,
    pub min_os: String,
    pub platform: IosPlatform,
}

// ─── IosFramework ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosFramework {
    pub name: String,
    pub path: String,
    pub is_system: bool,
}

// ─── IpaBundle ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpaBundle {
    pub info: BundleInfo,
    pub signature: Option<CodeSignature>,
    pub frameworks: Vec<IosFramework>,
    pub executable: String,
}

impl IpaBundle {
    /// Parse an IPA from raw ZIP bytes.
    ///
    /// Everything returned is read from the archive:
    /// * `info` from the bundle's `Info.plist`;
    /// * embedded frameworks from the `Frameworks/*.framework/` members;
    /// * system frameworks from the executable's `LC_LOAD_DYLIB` commands;
    /// * `signature` from the `Entitlements` dictionary inside
    ///   `embedded.mobileprovision`.
    ///
    /// # Errors
    /// Returns [`IosError`] naming the archive member or the `Info.plist` key
    /// that is missing. No value is defaulted: an IPA without
    /// `CFBundleExecutable` is an error, not an app called after its directory.
    pub fn from_ipa_bytes(data: &[u8]) -> Result<Self, IosError> {
        use crate::plist::{parse_xml_plist, PlistValue};
        use std::io::Read as _;

        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(data))
            .map_err(|e| IosError::InvalidBundle(format!("not a readable IPA archive: {e}")))?;

        let names: Vec<String> = (0..zip.len())
            .filter_map(|i| zip.name_for_index(i).map(ToString::to_string))
            .collect();

        let prefix = names
            .iter()
            .find_map(|n| {
                let mut parts = n.splitn(3, '/');
                let p0 = parts.next()?;
                let p1 = parts.next()?;
                if p0 == "Payload" && p1.ends_with(".app") {
                    Some(format!("{p0}/{p1}/"))
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                IosError::InvalidBundle("no Payload/*.app directory in the archive".to_string())
            })?;

        fn member(
            zip: &mut zip::ZipArchive<std::io::Cursor<&[u8]>>,
            path: &str,
        ) -> Option<Vec<u8>> {
            let mut f = zip.by_name(path).ok()?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).ok()?;
            Some(buf)
        }

        // ── Info.plist ──────────────────────────────────────────────────────
        let plist_path = format!("{prefix}Info.plist");
        let raw = member(&mut zip, &plist_path)
            .ok_or_else(|| IosError::MissingInfo(plist_path.clone()))?;
        let info = parse_xml_plist(&raw).map_err(|e| IosError::Plist(e.to_string()))?;

        let text = |key: &str| {
            info.get(key)
                .and_then(PlistValue::as_str)
                .map(ToString::to_string)
        };

        let bundle_id =
            text("CFBundleIdentifier").ok_or_else(|| IosError::MissingInfo("CFBundleIdentifier".to_string()))?;
        let executable =
            text("CFBundleExecutable").ok_or_else(|| IosError::MissingInfo("CFBundleExecutable".to_string()))?;
        let name = text("CFBundleDisplayName")
            .or_else(|| text("CFBundleName"))
            .unwrap_or_else(|| executable.clone());
        let version = text("CFBundleShortVersionString")
            .or_else(|| text("CFBundleVersion"))
            .ok_or_else(|| IosError::MissingInfo("CFBundleShortVersionString".to_string()))?;
        let min_os =
            text("MinimumOSVersion").ok_or_else(|| IosError::MissingInfo("MinimumOSVersion".to_string()))?;

        let platform_name = info
            .get("CFBundleSupportedPlatforms")
            .map(PlistValue::string_array)
            .and_then(|v| v.first().map(ToString::to_string))
            .ok_or_else(|| IosError::MissingInfo("CFBundleSupportedPlatforms".to_string()))?;
        let platform = match platform_name.as_str() {
            "iPhoneOS" => IosPlatform::IphoneOs,
            "MacOSX" => IosPlatform::MacOs,
            "AppleTVOS" => IosPlatform::TvOs,
            "WatchOS" => IosPlatform::WatchOs,
            "XROS" => IosPlatform::VisionOs,
            other => {
                return Err(IosError::ParseError(format!(
                    "unknown CFBundleSupportedPlatforms entry {other:?}"
                )))
            }
        };

        // ── Embedded frameworks, from the archive members ───────────────────
        let fw_prefix = format!("{prefix}Frameworks/");
        let mut frameworks: Vec<IosFramework> = Vec::new();
        for n in &names {
            let Some(rest) = n.strip_prefix(&fw_prefix) else {
                continue;
            };
            let Some(dir) = rest.split('/').next() else {
                continue;
            };
            if !dir.ends_with(".framework") {
                continue;
            }
            let fw_name = dir.trim_end_matches(".framework").to_string();
            if frameworks.iter().any(|f| f.name == fw_name) {
                continue;
            }
            frameworks.push(IosFramework {
                name: fw_name,
                path: format!("Frameworks/{dir}"),
                is_system: false,
            });
        }

        // ── System frameworks, from the executable's LC_LOAD_DYLIB list ─────
        let exe_path = format!("{prefix}{executable}");
        if let Some(exe) = member(&mut zip, &exe_path)
            && let Ok(macho) = goblin::mach::MachO::parse(&exe, 0)
        {
            for lib in &macho.libs {
                if *lib == "self" {
                    continue;
                }
                let Some(idx) = lib.find(".framework/") else {
                    continue;
                };
                let dir = &lib[..idx + ".framework".len()];
                let Some(fw_name) = dir.rsplit('/').next().map(|d| d.trim_end_matches(".framework"))
                else {
                    continue;
                };
                if !dir.starts_with("/System/Library/") {
                    continue;
                }
                if frameworks.iter().any(|f| f.name == fw_name) {
                    continue;
                }
                frameworks.push(IosFramework {
                    name: fw_name.to_string(),
                    path: dir.to_string(),
                    is_system: true,
                });
            }
        }

        // ── Entitlements, from embedded.mobileprovision ─────────────────────
        let signature = member(&mut zip, &format!("{prefix}embedded.mobileprovision"))
            .and_then(|raw| Self::code_signature_from_profile(&raw));

        Ok(Self {
            info: BundleInfo {
                bundle_id,
                name,
                version,
                min_os,
                platform,
            },
            signature,
            frameworks,
            executable,
        })
    }

    /// Build a [`CodeSignature`] from the `Entitlements` dictionary inside a
    /// CMS-wrapped `embedded.mobileprovision`.
    ///
    /// Returns `None` when no XML plist payload or no `Entitlements` dictionary
    /// can be found — an absent entitlement set is reported as absent.
    #[must_use]
    fn code_signature_from_profile(raw: &[u8]) -> Option<CodeSignature> {
        use crate::plist::{parse_xml_plist_str, PlistValue};

        let text = String::from_utf8_lossy(raw);
        let start = text.find("<?xml")?;
        let end = text.find("</plist>").map_or(text.len(), |p| p + 8);
        let xml = &text[start..end];
        let root = parse_xml_plist_str(xml).ok()?;

        let team_id = root
            .get("TeamIdentifier")
            .map(PlistValue::string_array)
            .and_then(|v| v.first().map(ToString::to_string))
            .unwrap_or_default();

        let ent_dict = root.get("Entitlements")?;
        let PlistValue::Dict(pairs) = ent_dict else {
            return None;
        };

        let mut entitlements = Vec::with_capacity(pairs.len());
        for (key, value) in pairs {
            let converted = match value {
                PlistValue::Boolean(b) => EntitlementValue::Bool(*b),
                PlistValue::String(s) => EntitlementValue::Str(s.clone()),
                PlistValue::Array(_) => EntitlementValue::Array(
                    value.string_array().into_iter().map(ToString::to_string).collect(),
                ),
                other => EntitlementValue::Str(format!("{other:?}")),
            };
            entitlements.push(Entitlement {
                key: key.clone(),
                value: converted,
            });
        }

        let signing_id = entitlements
            .iter()
            .find(|e| e.key == "application-identifier")
            .map(|e| e.value.to_string())
            .unwrap_or_default();

        Some(CodeSignature {
            team_id,
            signing_id,
            entitlements,
        })
    }

    /// Build the reference IPA image parsed by [`IpaBundle::mock`].
    ///
    /// A real ZIP archive with a real XML `Info.plist`, a real arm64 Mach-O
    /// declaring two `LC_LOAD_DYLIB` system frameworks, an embedded framework
    /// directory, and a real provisioning-profile payload.
    ///
    /// # Panics
    /// Panics if the archive cannot be written, which would mean the `zip`
    /// writer is unusable in this build.
    #[must_use]
    pub fn reference_ipa_bytes() -> Vec<u8> {
        use std::io::Write as _;
        use zip::write::SimpleFileOptions;

        let opts = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);

        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut cursor);

            w.add_directory("Payload/ExampleApp.app/", opts)
                .expect("zip directory");

            w.start_file("Payload/ExampleApp.app/Info.plist", opts)
                .expect("zip Info.plist");
            w.write_all(REFERENCE_INFO_PLIST).expect("write Info.plist");

            w.start_file("Payload/ExampleApp.app/ExampleApp", opts)
                .expect("zip executable");
            w.write_all(&reference_macho_with_dylibs(&[
                "/System/Library/Frameworks/UIKit.framework/UIKit",
                "/System/Library/Frameworks/Foundation.framework/Foundation",
            ]))
            .expect("write executable");

            w.start_file("Payload/ExampleApp.app/embedded.mobileprovision", opts)
                .expect("zip profile");
            w.write_all(REFERENCE_PROFILE).expect("write profile");

            w.add_directory(
                "Payload/ExampleApp.app/Frameworks/Alamofire.framework/",
                opts,
            )
            .expect("zip framework dir");

            w.finish().expect("finish zip");
        }
        cursor.into_inner()
    }

    /// Parse the reference IPA image from [`IpaBundle::reference_ipa_bytes`].
    ///
    /// Kept under the historical name `mock`, but the bundle id, name, version,
    /// minimum OS, platform, framework list and entitlements are now all read
    /// out of those bytes by [`IpaBundle::from_ipa_bytes`].
    ///
    /// # Panics
    /// Panics if the reference image fails to parse, which would mean the
    /// writer and the parser have diverged.
    #[must_use]
    pub fn mock() -> Self {
        Self::from_ipa_bytes(&Self::reference_ipa_bytes())
            .expect("reference IPA image must parse with IpaBundle::from_ipa_bytes")
    }

    /// Return the number of frameworks.
    #[must_use]
    pub const fn framework_count(&self) -> usize {
        self.frameworks.len()
    }

    /// Returns `true` if the bundle has the `get-task-allow` entitlement set to `Bool(true)`.
    #[must_use]
    pub fn is_debuggable(&self) -> bool {
        self.signature.as_ref().is_some_and(|sig| {
            matches!(
                sig.get("get-task-allow"),
                Some(EntitlementValue::Bool(true))
            )
        })
    }

    /// Return all system frameworks.
    #[must_use]
    pub fn system_frameworks(&self) -> Vec<&IosFramework> {
        self.frameworks.iter().filter(|f| f.is_system).collect()
    }
}

/// `Info.plist` of the reference IPA image, as real XML.
const REFERENCE_INFO_PLIST: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key><string>com.example.App</string>
    <key>CFBundleName</key><string>ExampleApp</string>
    <key>CFBundleShortVersionString</key><string>1.0.0</string>
    <key>CFBundleVersion</key><string>42</string>
    <key>MinimumOSVersion</key><string>14.0</string>
    <key>CFBundleExecutable</key><string>ExampleApp</string>
    <key>CFBundleSupportedPlatforms</key>
    <array><string>iPhoneOS</string></array>
</dict>
</plist>
"#;

/// `embedded.mobileprovision` payload of the reference IPA image.
///
/// The leading bytes stand in for the CMS envelope that wraps the plist on a
/// real device build; the parser locates the payload by its `<?xml` magic, so
/// this exercises the same path.
const REFERENCE_PROFILE: &[u8] = br#"CMS-WRAPPED-PROFILE<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>Name</key><string>ExampleApp Development</string>
    <key>TeamIdentifier</key>
    <array><string>ABCD1234EF</string></array>
    <key>Entitlements</key>
    <dict>
        <key>get-task-allow</key><false/>
        <key>application-identifier</key><string>ABCD1234EF.com.example.App</string>
        <key>keychain-access-groups</key>
        <array><string>ABCD1234EF.*</string></array>
    </dict>
</dict>
</plist>
"#;

/// Assemble an arm64 Mach-O executable that declares `dylibs` through real
/// `LC_LOAD_DYLIB` commands, so a parser has to read them to find them.
#[must_use]
fn reference_macho_with_dylibs(dylibs: &[&str]) -> Vec<u8> {
    const HEADER_SIZE: usize = 32;
    const SEG_CMD_SIZE: usize = 72;

    fn put_u32(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, v: u64) {
        buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    // Each LC_LOAD_DYLIB is a 24-byte command followed by its NUL-terminated
    // path, padded so the next command stays 8-byte aligned.
    let dylib_sizes: Vec<usize> = dylibs
        .iter()
        .map(|d| {
            let raw = 24 + d.len() + 1;
            raw.div_ceil(8) * 8
        })
        .collect();
    let cmds_size: usize = SEG_CMD_SIZE + dylib_sizes.iter().sum::<usize>();
    let total = HEADER_SIZE + cmds_size;

    let mut buf = vec![0u8; total];

    put_u32(&mut buf, 0, 0xFEED_FACF); // MH_MAGIC_64
    put_u32(&mut buf, 4, 0x0100_000C); // CPU_TYPE_ARM64
    put_u32(&mut buf, 8, 0); // cpusubtype
    put_u32(&mut buf, 12, 2); // MH_EXECUTE
    put_u32(&mut buf, 16, u32::try_from(1 + dylibs.len()).unwrap_or(0)); // ncmds
    put_u32(&mut buf, 20, u32::try_from(cmds_size).unwrap_or(0));
    put_u32(&mut buf, 24, 0x0020_0085); // NOUNDEFS | DYLDLINK | TWOLEVEL | PIE
    put_u32(&mut buf, 28, 0); // reserved

    // LC_SEGMENT_64 __TEXT
    let seg = HEADER_SIZE;
    put_u32(&mut buf, seg, 0x19);
    put_u32(&mut buf, seg + 4, u32::try_from(SEG_CMD_SIZE).unwrap_or(0));
    buf[seg + 8..seg + 14].copy_from_slice(b"__TEXT");
    put_u64(&mut buf, seg + 24, 0x1_0000_0000); // vmaddr
    put_u64(&mut buf, seg + 32, 0x4000); // vmsize
    put_u64(&mut buf, seg + 40, 0); // fileoff
    put_u64(&mut buf, seg + 48, total as u64); // filesize
    put_u32(&mut buf, seg + 56, 5); // maxprot
    put_u32(&mut buf, seg + 60, 5); // initprot
    put_u32(&mut buf, seg + 64, 0); // nsects
    put_u32(&mut buf, seg + 68, 0); // flags

    let mut off = seg + SEG_CMD_SIZE;
    for (path, size) in dylibs.iter().zip(&dylib_sizes) {
        put_u32(&mut buf, off, 0x0C); // LC_LOAD_DYLIB
        put_u32(&mut buf, off + 4, u32::try_from(*size).unwrap_or(0));
        put_u32(&mut buf, off + 8, 24); // dylib.name offset
        put_u32(&mut buf, off + 12, 0); // timestamp
        put_u32(&mut buf, off + 16, 0x0001_0000); // current_version
        put_u32(&mut buf, off + 20, 0x0001_0000); // compatibility_version
        buf[off + 24..off + 24 + path.len()].copy_from_slice(path.as_bytes());
        off += size;
    }

    buf
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ios_platform_display_iphone() {
        assert_eq!(IosPlatform::IphoneOs.to_string(), "iphoneos");
    }

    #[test]
    fn test_ios_platform_display_macos() {
        assert_eq!(IosPlatform::MacOs.to_string(), "macos");
    }

    #[test]
    fn test_ios_platform_display_tvos() {
        assert_eq!(IosPlatform::TvOs.to_string(), "tvos");
    }

    #[test]
    fn test_ios_platform_display_watchos() {
        assert_eq!(IosPlatform::WatchOs.to_string(), "watchos");
    }

    #[test]
    fn test_ios_platform_display_visionos() {
        assert_eq!(IosPlatform::VisionOs.to_string(), "visionos");
    }

    #[test]
    fn test_entitlement_value_display_bool() {
        assert_eq!(EntitlementValue::Bool(true).to_string(), "true");
        assert_eq!(EntitlementValue::Bool(false).to_string(), "false");
    }

    #[test]
    fn test_entitlement_value_display_str() {
        assert_eq!(
            EntitlementValue::Str("hello".to_string()).to_string(),
            "hello"
        );
    }

    #[test]
    fn test_entitlement_value_display_array() {
        let v = EntitlementValue::Array(vec!["a".to_string(), "b".to_string()]);
        assert_eq!(v.to_string(), "[a, b]");
    }

    #[test]
    fn test_code_signature_has_existing() {
        let sig = CodeSignature {
            team_id: "T1".to_string(),
            signing_id: "id".to_string(),
            entitlements: vec![Entitlement {
                key: "get-task-allow".to_string(),
                value: EntitlementValue::Bool(false),
            }],
        };
        assert!(sig.has("get-task-allow"));
    }

    #[test]
    fn test_code_signature_has_missing() {
        let sig = CodeSignature {
            team_id: "T1".to_string(),
            signing_id: "id".to_string(),
            entitlements: vec![],
        };
        assert!(!sig.has("nonexistent"));
    }

    #[test]
    fn test_code_signature_get_bool() {
        let sig = CodeSignature {
            team_id: "T1".to_string(),
            signing_id: "id".to_string(),
            entitlements: vec![Entitlement {
                key: "get-task-allow".to_string(),
                value: EntitlementValue::Bool(true),
            }],
        };
        assert_eq!(
            sig.get("get-task-allow"),
            Some(&EntitlementValue::Bool(true))
        );
    }

    #[test]
    fn test_code_signature_get_none() {
        let sig = CodeSignature {
            team_id: "T1".to_string(),
            signing_id: "id".to_string(),
            entitlements: vec![],
        };
        assert!(sig.get("key").is_none());
    }

    #[test]
    fn test_from_ipa_bytes_rejects_non_zip() {
        match IpaBundle::from_ipa_bytes(b"not a zip at all") {
            Err(IosError::InvalidBundle(m)) => assert!(m.contains("readable IPA archive")),
            other => panic!("expected InvalidBundle, got {other:?}"),
        }
    }

    #[test]
    fn test_from_ipa_bytes_names_the_missing_info_plist() {
        use std::io::Write as _;
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut cursor);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            w.start_file("Payload/Empty.app/placeholder", opts).unwrap();
            w.write_all(b"x").unwrap();
            w.finish().unwrap();
        }
        match IpaBundle::from_ipa_bytes(&cursor.into_inner()) {
            Err(IosError::MissingInfo(m)) => assert_eq!(m, "Payload/Empty.app/Info.plist"),
            other => panic!("expected MissingInfo, got {other:?}"),
        }
    }

    #[test]
    fn test_system_frameworks_come_from_load_dylib_commands() {
        // Remove the LC_LOAD_DYLIB list and the system frameworks must vanish:
        // they are read from the binary, not assumed.
        let b = IpaBundle::mock();
        assert_eq!(b.system_frameworks().len(), 2);
        let names: Vec<&str> = b
            .system_frameworks()
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        assert!(names.contains(&"UIKit"));
        assert!(names.contains(&"Foundation"));
        // The one embedded framework comes from an archive member instead.
        let embedded: Vec<&str> = b
            .frameworks
            .iter()
            .filter(|f| !f.is_system)
            .map(|f| f.name.as_str())
            .collect();
        assert_eq!(embedded, vec!["Alamofire"]);
    }

    #[test]
    fn test_entitlements_come_from_the_provisioning_profile() {
        let b = IpaBundle::mock();
        let sig = b.signature.as_ref().expect("profile carries entitlements");
        assert_eq!(sig.team_id, "ABCD1234EF");
        assert!(sig.has("keychain-access-groups"));
        assert!(matches!(
            sig.get("get-task-allow"),
            Some(EntitlementValue::Bool(false))
        ));
    }

    #[test]
    fn test_ipa_bundle_mock() {
        let b = IpaBundle::mock();
        assert_eq!(b.info.bundle_id, "com.example.App");
    }

    #[test]
    fn test_ipa_bundle_framework_count() {
        let b = IpaBundle::mock();
        assert_eq!(b.framework_count(), 3);
    }

    #[test]
    fn test_ipa_bundle_is_not_debuggable() {
        let b = IpaBundle::mock();
        assert!(!b.is_debuggable());
    }

    #[test]
    fn test_ipa_bundle_is_debuggable() {
        let mut b = IpaBundle::mock();
        if let Some(sig) = &mut b.signature
            && let Some(e) = sig
                .entitlements
                .iter_mut()
                .find(|e| e.key == "get-task-allow")
        {
            e.value = EntitlementValue::Bool(true);
        }
        assert!(b.is_debuggable());
    }

    #[test]
    fn test_ipa_bundle_is_debuggable_no_signature() {
        let mut b = IpaBundle::mock();
        b.signature = None;
        assert!(!b.is_debuggable());
    }

    #[test]
    fn test_ipa_bundle_system_frameworks() {
        let b = IpaBundle::mock();
        let sys = b.system_frameworks();
        assert_eq!(sys.len(), 2);
        assert!(sys.iter().all(|f| f.is_system));
    }

    #[test]
    fn test_ios_error_parse() {
        let e = IosError::ParseError("bad plist".to_string());
        assert!(e.to_string().contains("bad plist"));
    }

    #[test]
    fn test_ios_error_missing_info() {
        let e = IosError::MissingInfo("CFBundleIdentifier".to_string());
        assert!(e.to_string().contains("CFBundleIdentifier"));
    }

    #[test]
    fn test_ios_error_invalid_bundle() {
        let e = IosError::InvalidBundle("no Payload/".to_string());
        assert!(e.to_string().contains("no Payload/"));
    }

    #[test]
    fn test_ipa_bundle_serialization() {
        let b = IpaBundle::mock();
        let json = serde_json::to_string(&b).unwrap();
        let decoded: IpaBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.info.bundle_id, b.info.bundle_id);
    }

    #[test]
    fn test_bundle_info_platform() {
        let b = IpaBundle::mock();
        assert_eq!(b.info.platform, IosPlatform::IphoneOs);
    }

    #[test]
    fn test_bundle_info_min_os() {
        let b = IpaBundle::mock();
        assert_eq!(b.info.min_os, "14.0");
    }

    #[test]
    fn test_system_frameworks_empty() {
        let mut b = IpaBundle::mock();
        for f in &mut b.frameworks {
            f.is_system = false;
        }
        assert!(b.system_frameworks().is_empty());
    }

    #[test]
    fn test_framework_count_empty() {
        let mut b = IpaBundle::mock();
        b.frameworks.clear();
        assert_eq!(b.framework_count(), 0);
    }
}

// ─── ObjC Metadata ───────────────────────────────────────────────────────────

/// A single Objective-C method descriptor recovered from a Mach-O binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjcMethod {
    /// Selector string (e.g. `"initWithFrame:"`).
    pub name: String,
    /// Raw `ObjC` type-encoding string (e.g. `"v16@0:8"`).
    pub type_encoding: String,
    /// Virtual address of the method implementation.
    pub imp_addr: u64,
}

/// An Objective-C instance variable descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjcIvar {
    /// Ivar name (e.g. `"_delegate"`).
    pub name: String,
    /// `ObjC` type-encoding of the ivar's declared type.
    pub type_encoding: String,
    /// Byte offset of the ivar within the class instance.
    pub offset: u32,
    /// Declared size of the ivar in bytes.
    pub size: u32,
}

/// An Objective-C declared property (synthesised or dynamic).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjcProperty {
    /// Property name (e.g. `"delegate"`).
    pub name: String,
    /// Raw attributes string (e.g. `"T@\"NSObject\",N,V_delegate"`).
    pub attributes: String,
}

/// Full description of an Objective-C class as recovered from a Mach-O binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjcClass {
    /// Unmangled class name.
    pub name: String,
    /// Name of the superclass, if known.
    pub superclass: Option<String>,
    /// Names of adopted protocols.
    pub protocols: Vec<String>,
    /// Instance method list.
    pub instance_methods: Vec<ObjcMethod>,
    /// Class ("`+`") method list.
    pub class_methods: Vec<ObjcMethod>,
    /// Instance variable list.
    pub ivars: Vec<ObjcIvar>,
    /// Declared properties.
    pub properties: Vec<ObjcProperty>,
}

impl ObjcClass {
    /// Total number of methods (instance + class).
    #[must_use]
    pub const fn total_method_count(&self) -> usize {
        self.instance_methods.len() + self.class_methods.len()
    }

    /// Returns `true` if the class adopts the named protocol.
    #[must_use]
    pub fn adopts_protocol(&self, proto: &str) -> bool {
        self.protocols.iter().any(|p| p == proto)
    }

    /// Find an instance method by selector name.
    #[must_use]
    pub fn find_instance_method(&self, sel: &str) -> Option<&ObjcMethod> {
        self.instance_methods.iter().find(|m| m.name == sel)
    }

    /// Find a class method by selector name.
    #[must_use]
    pub fn find_class_method(&self, sel: &str) -> Option<&ObjcMethod> {
        self.class_methods.iter().find(|m| m.name == sel)
    }
}

// ─── Type-Encoding Decoder ────────────────────────────────────────────────────

/// Decode an Objective-C type-encoding string into human-readable type names.
///
/// Supports:
/// * Primitive specifiers: `v c i s l q C I S L Q f d B`
/// * Object specifiers: `@ # :`
/// * Pointer: `^T` → `"*T"`
/// * C-string: `*` → `"char*"`
/// * Array: `[NT]` → `"T[N]"`
/// * Struct: `{name=…}` → `"struct name"`
/// * Union: `(name=…)` → `"union name"`
/// * Qualifiers `r n N o O R V` are silently consumed.
///
/// # Example
/// ```
/// # use rustre_mobile_ios::decode_type_encoding;
/// let parts = decode_type_encoding("@:I");
/// assert_eq!(parts, ["id", "SEL", "unsigned int"]);
/// ```
#[must_use]
pub fn decode_type_encoding(enc: &str) -> Vec<String> {
    let chars: Vec<char> = enc.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let (ty, consumed) = decode_one_type(&chars, i);
        out.push(ty);
        i += consumed.max(1);
    }
    out
}

/// Internal helper — decode a single type at `pos`, returning `(type_string, chars_consumed)`.
fn decode_one_type(chars: &[char], pos: usize) -> (String, usize) {
    if pos >= chars.len() {
        return ("?".to_string(), 1);
    }
    match chars[pos] {
        // Qualifiers — consume silently and recurse
        'r' | 'n' | 'N' | 'o' | 'O' | 'R' | 'V' => {
            let (inner, n) = decode_one_type(chars, pos + 1);
            (inner, 1 + n)
        }
        'v' => ("void".to_string(), 1),
        'c' => ("char".to_string(), 1),
        'i' => ("int".to_string(), 1),
        's' => ("short".to_string(), 1),
        'l' => ("long".to_string(), 1),
        'q' => ("long long".to_string(), 1),
        'C' => ("unsigned char".to_string(), 1),
        'I' => ("unsigned int".to_string(), 1),
        'S' => ("unsigned short".to_string(), 1),
        'L' => ("unsigned long".to_string(), 1),
        'Q' => ("unsigned long long".to_string(), 1),
        'f' => ("float".to_string(), 1),
        'd' => ("double".to_string(), 1),
        'B' => ("bool".to_string(), 1),
        '@' => {
            // Check for @"ClassName"
            if pos + 1 < chars.len() && chars[pos + 1] == '"' {
                let start = pos + 2;
                let end = chars[start..]
                    .iter()
                    .position(|&c| c == '"')
                    .map(|p| start + p);
                if let Some(e) = end {
                    let name: String = chars[start..e].iter().collect();
                    return (format!("id<{name}>"), e - pos + 1);
                }
            }
            ("id".to_string(), 1)
        }
        '#' => ("Class".to_string(), 1),
        ':' => ("SEL".to_string(), 1),
        '*' => ("char*".to_string(), 1),
        '^' => {
            // Pointer to the next type
            let (inner, n) = decode_one_type(chars, pos + 1);
            (format!("*{inner}"), 1 + n)
        }
        '[' => {
            // Array: [<count><type>]
            let start = pos + 1;
            let mut j = start;
            while j < chars.len() && chars[j].is_ascii_digit() {
                j += 1;
            }
            let count: String = chars[start..j].iter().collect();
            let (inner, n) = decode_one_type(chars, j);
            // Skip closing ']'
            let close = j + n;
            let total = close - pos + usize::from(close < chars.len() && chars[close] == ']');
            (format!("{inner}[{count}]"), total)
        }
        '{' => {
            // Struct: {name=types} or {name}
            let name = extract_composite_name(chars, pos + 1);
            let total = skip_to_close(chars, pos, '{', '}');
            (format!("struct {name}"), total)
        }
        '(' => {
            // Union: (name=types) or (name)
            let name = extract_composite_name(chars, pos + 1);
            let total = skip_to_close(chars, pos, '(', ')');
            (format!("union {name}"), total)
        }
        '?' => ("func_ptr".to_string(), 1),
        // Numeric offset suffixes — swallow the digits
        c if c.is_ascii_digit() => {
            let mut j = pos + 1;
            while j < chars.len() && chars[j].is_ascii_digit() {
                j += 1;
            }
            // These are purely offset annotations; emit nothing meaningful
            (String::new(), j - pos)
        }
        other => (format!("{other}"), 1),
    }
}

/// Extract the composite type name (before `=` or the closing delimiter).
fn extract_composite_name(chars: &[char], start: usize) -> String {
    let mut name = String::new();
    for &c in &chars[start..] {
        if c == '=' || c == '}' || c == ')' {
            break;
        }
        name.push(c);
    }
    if name.is_empty() {
        "?".to_string()
    } else {
        name
    }
}

/// Returns how many chars the balanced delimited block `open…close` spans,
/// starting from `pos` (which must be the opening delimiter).
fn skip_to_close(chars: &[char], pos: usize, open: char, close: char) -> usize {
    let mut depth = 0usize;
    let mut j = pos;
    while j < chars.len() {
        if chars[j] == open {
            depth += 1;
        } else if chars[j] == close {
            depth -= 1;
            if depth == 0 {
                return j - pos + 1;
            }
        }
        j += 1;
    }
    chars.len() - pos
}

// ─── Mach-O Section Scanning ─────────────────────────────────────────────────

/// Read all null-terminated strings from a raw byte slice.
fn read_cstrings(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for (i, &b) in data.iter().enumerate() {
        if b == 0 {
            if i > start
                && let Ok(s) = std::str::from_utf8(&data[start..i])
            {
                let s = s.trim();
                if !s.is_empty() {
                    out.push(s.to_string());
                }
            }
            start = i + 1;
        }
    }
    // Handle string without trailing NUL
    if start < data.len()
        && let Ok(s) = std::str::from_utf8(&data[start..])
    {
        let s = s.trim();
        if !s.is_empty() {
            out.push(s.to_string());
        }
    }
    out
}

/// Extract data for a named section from a goblin Mach-O object.
/// `binary` must be the same byte slice that was used to parse `macho`.
fn macho_section_data<'a>(
    macho: &goblin::mach::MachO<'_>,
    binary: &'a [u8],
    seg: &str,
    sect: &str,
) -> Option<&'a [u8]> {
    for sect_hdr in macho.segments.sections().flatten() {
        let Ok((hdr, _)) = sect_hdr else { continue };
        let sn = std::str::from_utf8(&hdr.sectname)
            .unwrap_or("")
            .trim_end_matches('\0');
        let sn_seg = std::str::from_utf8(&hdr.segname)
            .unwrap_or("")
            .trim_end_matches('\0');
        if sn == sect && sn_seg == seg {
            let off = hdr.offset as usize;
            let Ok(sz) = usize::try_from(hdr.size) else {
                continue;
            };
            if off + sz <= binary.len() {
                return Some(&binary[off..off + sz]);
            }
        }
    }
    None
}

/// Scan a Mach-O binary for `ObjC` selector strings.
///
/// Checks `__TEXT,__objc_methnames` first, then falls back to
/// `__DATA,__objc_selrefs`.  Returns an empty `Vec` if the binary cannot be
/// parsed or contains no `ObjC` selector data.
#[must_use]
pub fn scan_objc_selectors(binary: &[u8]) -> Vec<String> {
    match goblin::mach::MachO::parse(binary, 0) {
        Ok(macho) => {
            // Primary: __TEXT,__objc_methnames
            if let Some(data) = macho_section_data(&macho, binary, "__TEXT", "__objc_methnames") {
                return read_cstrings(data);
            }
            // Fallback: __DATA,__objc_selrefs — contains pointers, but we do a
            // best-effort scan for printable ASCII runs instead.
            if let Some(data) = macho_section_data(&macho, binary, "__DATA", "__objc_selrefs") {
                return read_cstrings(data);
            }
            Vec::new()
        }
        Err(_) => Vec::new(),
    }
}

/// Scan a Mach-O binary for `ObjC` class name strings.
///
/// Checks `__TEXT,__objc_classnames` first, then `__DATA,__objc_classrefs`.
#[must_use]
pub fn scan_objc_classes(binary: &[u8]) -> Vec<String> {
    match goblin::mach::MachO::parse(binary, 0) {
        Ok(macho) => {
            if let Some(data) = macho_section_data(&macho, binary, "__TEXT", "__objc_classnames") {
                return read_cstrings(data);
            }
            if let Some(data) = macho_section_data(&macho, binary, "__DATA", "__objc_classrefs") {
                return read_cstrings(data);
            }
            Vec::new()
        }
        Err(_) => Vec::new(),
    }
}

// ─── Swift Demangler ─────────────────────────────────────────────────────────

/// A lightweight Swift symbol demangler for Swift 5 ABI-stable mangled names.
///
/// This is a heuristic demangler intended for rapid triage during binary
/// analysis.  It handles common patterns without implementing the full
/// grammar defined in `docs/ABI/Mangling.rst`.
pub struct SwiftDemangler;

impl SwiftDemangler {
    /// Returns `true` when `name` looks like a Swift 5 mangled symbol.
    ///
    /// Swift 5 ABI-stable symbols start with `_$s` (lowercase) or `_$S`
    /// (uppercase, used in older Swift 5 betas).
    #[must_use]
    pub fn is_swift_mangled(name: &str) -> bool {
        name.starts_with("_$s") || name.starts_with("_$S")
    }

    /// Attempt to demangle a Swift 5 mangled symbol.
    ///
    /// Returns `Some(demangled)` when a pattern is recognised, `None` otherwise.
    ///
    /// Recognised patterns (heuristic subset):
    /// * `_$sSS…` → `Swift.String`
    /// * `_$sSi…` → `Swift.Int`
    /// * `_$sSb…` → `Swift.Bool`
    /// * `_$sSf…` → `Swift.Float`
    /// * `_$sSd…` → `Swift.Double`
    /// * `_$sS2S…` → `String, String`
    /// * `…FooC` suffix → `Foo (class)`
    /// * `…FooV` suffix → `Foo (struct)`
    /// * `…FooO` suffix → `Foo (enum)`
    /// * `…yyyF` suffix → `() -> ()`
    /// * `…yyF` suffix → `() -> ()`
    /// * Fallback: split on uppercase letter boundaries for name recovery.
    #[must_use]
    pub fn demangle(mangled: &str) -> Option<String> {
        if !Self::is_swift_mangled(mangled) {
            return None;
        }

        // Strip the `_$s` / `_$S` prefix.
        let body = &mangled[3..];

        // Well-known stdlib types by prefix
        if body.starts_with("SS") {
            return Some("Swift.String".to_string());
        }
        if body.starts_with("Si") {
            return Some("Swift.Int".to_string());
        }
        if body.starts_with("Sb") {
            return Some("Swift.Bool".to_string());
        }
        if body.starts_with("Sf") {
            return Some("Swift.Float".to_string());
        }
        if body.starts_with("Sd") {
            return Some("Swift.Double".to_string());
        }
        if body.starts_with("Su") {
            return Some("Swift.UInt".to_string());
        }
        if body.starts_with("S2S") {
            return Some("String, String".to_string());
        }
        if body.starts_with("SayS") {
            return Some("Array<String>".to_string());
        }

        // Suffix patterns for nominal type descriptors
        if body.ends_with("yyyF") || body.ends_with("yyF") {
            return Some("() -> ()".to_string());
        }
        if body.ends_with('C') && body.len() > 1 {
            let stem = &body[..body.len() - 1];
            let name = Self::split_camel(stem);
            return Some(format!("{name} (class)"));
        }
        if body.ends_with('V') && body.len() > 1 {
            let stem = &body[..body.len() - 1];
            let name = Self::split_camel(stem);
            return Some(format!("{name} (struct)"));
        }
        if body.ends_with('O') && body.len() > 1 {
            let stem = &body[..body.len() - 1];
            let name = Self::split_camel(stem);
            return Some(format!("{name} (enum)"));
        }

        // Attempt generic name recovery by decoding length-prefixed identifiers
        if let Some(recovered) = Self::decode_length_prefixed(body) {
            return Some(recovered);
        }

        // Last resort: split on uppercase transitions
        let name = Self::split_camel(body);
        if name.is_empty() || name == body {
            return None;
        }
        Some(name)
    }

    /// Decode a sequence of Swift length-prefixed identifiers at the start of
    /// `body` (e.g. `"3Foo3Bar"` → `"Foo.Bar"`).
    fn decode_length_prefixed(body: &str) -> Option<String> {
        let bytes = body.as_bytes();
        let mut pos = 0usize;
        let mut parts: Vec<String> = Vec::new();

        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            // Read decimal length
            let len_start = pos;
            while pos < bytes.len() && bytes[pos].is_ascii_digit() {
                pos += 1;
            }
            let len_str = std::str::from_utf8(&bytes[len_start..pos]).ok()?;
            let len: usize = len_str.parse().ok()?;
            if len == 0 || pos + len > bytes.len() {
                break;
            }
            let ident = std::str::from_utf8(&bytes[pos..pos + len]).ok()?;
            // Only accept valid identifiers
            if ident.chars().all(|c| c.is_alphanumeric() || c == '_') {
                parts.push(ident.to_string());
            } else {
                break;
            }
            pos += len;
        }

        if parts.is_empty() {
            None
        } else {
            Some(parts.join("."))
        }
    }

    /// Split a camel-case / mangled identifier into space-separated words,
    /// stripping leading digits.
    fn split_camel(s: &str) -> String {
        // Strip leading digits (length prefix artefacts)
        let s = s.trim_start_matches(|c: char| c.is_ascii_digit());
        if s.is_empty() {
            return String::new();
        }
        let mut out = String::new();
        let mut prev_upper = false;
        for (i, c) in s.chars().enumerate() {
            if i == 0 {
                out.push(c.to_ascii_uppercase());
                prev_upper = c.is_uppercase();
            } else if c.is_uppercase() && !prev_upper {
                out.push(' ');
                out.push(c);
                prev_upper = true;
            } else {
                out.push(c);
                prev_upper = c.is_uppercase();
            }
        }
        out
    }
}

// ─── IpaInfo ──────────────────────────────────────────────────────────────────

/// High-level analysis summary produced by scanning a Mach-O executable
/// extracted from an IPA archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpaInfo {
    /// `CFBundleIdentifier` from the embedded Info.plist, if recoverable.
    pub bundle_id: String,
    /// `CFBundleShortVersionString`.
    pub version: String,
    /// `MinimumOSVersion` or `LSMinimumSystemVersion`.
    pub min_os: String,
    /// Number of `ObjC` classes found in `__TEXT,__objc_classnames`.
    pub class_count: usize,
    /// Total number of selectors found in `__TEXT,__objc_methnames`.
    pub method_count: usize,
    /// Number of Swift-mangled symbols detected among the symbol table.
    pub swift_class_count: usize,
    /// Entitlement keys extracted from the code-signature blob.
    pub entitlements: Vec<String>,
    /// Whether the binary contains a `__LLVM,__bitcode` section.
    pub has_bitcode: bool,
    /// CPU type strings present (handles fat/universal binaries).
    pub architectures: Vec<String>,
}

impl IpaInfo {
    /// Analyse a raw Mach-O byte slice and populate an `IpaInfo`.
    ///
    /// For fat/universal binaries every slice is analysed and results are
    /// merged. Fields like `bundle_id` / `version` / `min_os` that cannot be
    /// recovered from Mach-O metadata alone are set to `"unknown"`.
    #[must_use]
    pub fn from_macho(binary: &[u8]) -> Self {
        let mut info = Self {
            bundle_id: "unknown".to_string(),
            version: "unknown".to_string(),
            min_os: "unknown".to_string(),
            class_count: 0,
            method_count: 0,
            swift_class_count: 0,
            entitlements: Vec::new(),
            has_bitcode: false,
            architectures: Vec::new(),
        };

        match goblin::Object::parse(binary) {
            Ok(goblin::Object::Mach(goblin::mach::Mach::Fat(fat))) => {
                for arch in fat.arches().into_iter().flatten() {
                    let arch_name = cpu_type_to_string(arch.cputype);
                    if !info.architectures.contains(&arch_name) {
                        info.architectures.push(arch_name);
                    }
                    let slice = arch.slice(binary);
                    info.merge_macho_slice(slice);
                }
            }
            Ok(goblin::Object::Mach(goblin::mach::Mach::Binary(macho))) => {
                let arch = cpu_type_to_string(macho.header.cputype);
                info.architectures.push(arch);
                info.merge_macho_slice(binary);
            }
            _ => {}
        }

        info
    }

    /// Merge analysis data from a single thin Mach-O slice into `self`.
    fn merge_macho_slice(&mut self, binary: &[u8]) {
        let classes = scan_objc_classes(binary);
        self.class_count += classes.len();

        let selectors = scan_objc_selectors(binary);
        self.method_count += selectors.len();

        // Count Swift-mangled symbols
        if let Ok(goblin::Object::Mach(goblin::mach::Mach::Binary(macho))) =
            goblin::Object::parse(binary)
        {
            for sym in macho.symbols().flatten() {
                let (name, _nlist) = sym;
                if SwiftDemangler::is_swift_mangled(name) {
                    self.swift_class_count += 1;
                }
            }

            // Bitcode detection
            if !self.has_bitcode && has_bitcode_section(&macho) {
                self.has_bitcode = true;
            }

            // Min OS from build version or version min load command
            if self.min_os == "unknown"
                && let Some(ver) = extract_min_os(&macho)
            {
                self.min_os = ver;
            }
        }
    }
}

/// Returns `true` when the Mach-O contains an `__LLVM,__bitcode` section.
fn has_bitcode_section(macho: &goblin::mach::MachO<'_>) -> bool {
    for sect in macho.segments.sections().flatten() {
        let Ok((hdr, _)) = sect else { continue };
        let sn = std::str::from_utf8(&hdr.sectname)
            .unwrap_or("")
            .trim_end_matches('\0');
        let sg = std::str::from_utf8(&hdr.segname)
            .unwrap_or("")
            .trim_end_matches('\0');
        if sg == "__LLVM" && sn == "__bitcode" {
            return true;
        }
    }
    false
}

/// Convert a Mach-O `cputype` integer to a human-readable architecture string.
fn cpu_type_to_string(cputype: u32) -> String {
    // Constants from `<mach/machine.h>`
    match cputype {
        0x0000_000C => "arm".to_string(),
        0x0100_000C => "arm64".to_string(),
        0x0200_000C => "arm64_32".to_string(),
        0x0000_0007 => "x86".to_string(),
        0x0100_0007 => "x86_64".to_string(),
        other => format!("cpu_{other:#010x}"),
    }
}

/// Best-effort extraction of the minimum OS version from Mach-O load commands.
fn extract_min_os(macho: &goblin::mach::MachO<'_>) -> Option<String> {
    use goblin::mach::load_command::CommandVariant;
    for lc in &macho.load_commands {
        match lc.command {
            CommandVariant::BuildVersion(ref bv) => {
                let raw = bv.minos;
                let major = (raw >> 16) & 0xFFFF;
                let minor = (raw >> 8) & 0xFF;
                let patch = raw & 0xFF;
                if patch == 0 {
                    return Some(format!("{major}.{minor}"));
                }
                return Some(format!("{major}.{minor}.{patch}"));
            }
            CommandVariant::VersionMinIphoneos(ref vm)
            | CommandVariant::VersionMinMacosx(ref vm)
            | CommandVariant::VersionMinTvos(ref vm)
            | CommandVariant::VersionMinWatchos(ref vm) => {
                let raw = vm.version;
                let major = (raw >> 16) & 0xFFFF;
                let minor = (raw >> 8) & 0xFF;
                let patch = raw & 0xFF;
                if patch == 0 {
                    return Some(format!("{major}.{minor}"));
                }
                return Some(format!("{major}.{minor}.{patch}"));
            }
            _ => {}
        }
    }
    None
}

// ─── IosAppInfo ───────────────────────────────────────────────────────────────

/// Application metadata extracted from an IPA's `Info.plist`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosAppInfo {
    /// `CFBundleIdentifier`
    pub bundle_id: String,
    /// `CFBundleShortVersionString` or `CFBundleVersion`
    pub version: String,
    /// `MinimumOSVersion`
    pub min_ios: String,
    /// Usage description keys (e.g. `NSCameraUsageDescription`) that indicate
    /// what permissions the app requests.
    pub permissions: Vec<String>,
}

/// Known `Info.plist` keys that correspond to privacy/permission strings.
static PERMISSION_KEYS: &[&str] = &[
    "NSCameraUsageDescription",
    "NSMicrophoneUsageDescription",
    "NSLocationWhenInUseUsageDescription",
    "NSLocationAlwaysUsageDescription",
    "NSLocationAlwaysAndWhenInUseUsageDescription",
    "NSPhotoLibraryUsageDescription",
    "NSPhotoLibraryAddUsageDescription",
    "NSContactsUsageDescription",
    "NSCalendarsUsageDescription",
    "NSRemindersUsageDescription",
    "NSBluetoothAlwaysUsageDescription",
    "NSBluetoothPeripheralUsageDescription",
    "NSMotionUsageDescription",
    "NSHealthShareUsageDescription",
    "NSHealthUpdateUsageDescription",
    "NSFaceIDUsageDescription",
    "NSUserTrackingUsageDescription",
    "NFCReaderUsageDescription",
    "NSSpeechRecognitionUsageDescription",
];

/// Extracts `IosAppInfo` from a raw IPA (ZIP) byte slice.
pub struct IosAppInfoExtractor;

impl IosAppInfoExtractor {
    /// Scan an IPA ZIP for `*.app/Info.plist`, parse it, and return the
    /// extracted metadata.  Returns `None` when the IPA cannot be parsed or
    /// the plist is absent/unreadable.
    #[must_use]
    pub fn extract_app_info(ipa_bytes: &[u8]) -> Option<IosAppInfo> {
        use std::io::{Cursor, Read};
        let cursor = Cursor::new(ipa_bytes);
        let mut zip = zip::ZipArchive::new(cursor).ok()?;

        // Find the Info.plist entry.
        let plist_index = (0..zip.len()).find(|&i| {
            zip.by_index(i)
                .is_ok_and(|f| {
                    let name = f.name().to_string();
                    name.ends_with(".app/Info.plist") || name.ends_with(".app\\Info.plist")
                })
        })?;

        let mut file = zip.by_index(plist_index).ok()?;
        // Cap allocation: plist files are small; silently clamp to 64 MiB.
        let capacity = usize::try_from(file.size()).unwrap_or(0).min(64 * 1024 * 1024);
        let mut raw = Vec::with_capacity(capacity);
        file.read_to_end(&mut raw).ok()?;

        Self::parse_plist(&raw)
    }

    /// Parse a raw plist byte slice (binary `bplist00`, XML, or simple
    /// text/OpenStep) and extract the fields we care about.
    #[must_use]
    pub fn parse_plist(raw: &[u8]) -> Option<IosAppInfo> {
        if raw.starts_with(b"bplist00") {
            Some(Self::parse_binary_plist(raw))
        } else {
            // Try XML / OpenStep text plist
            let text = std::str::from_utf8(raw).ok()?;
            if text.trim_start().starts_with("<?xml") || text.trim_start().starts_with('<') {
                Some(Self::parse_xml_plist(text))
            } else {
                Some(Self::parse_text_plist(text))
            }
        }
    }

    // ── Binary plist (bplist00) ───────────────────────────────────────────
    // Only a minimal scanner: we walk the raw bytes looking for known key
    // names followed by their UTF-8 string values.  Full binary-plist
    // decoding would require a proper parser; this covers the common case
    // used by Apple tooling.
    fn parse_binary_plist(raw: &[u8]) -> IosAppInfo {
        let text_repr = String::from_utf8_lossy(raw);
        Self::extract_from_text_repr(&text_repr)
    }

    // ── XML plist ─────────────────────────────────────────────────────────
    fn parse_xml_plist(text: &str) -> IosAppInfo {
        Self::extract_from_text_repr(text)
    }

    // ── OpenStep / text plist ─────────────────────────────────────────────
    fn parse_text_plist(text: &str) -> IosAppInfo {
        Self::extract_from_text_repr(text)
    }

    /// Heuristic extractor: scans `text` for known key patterns regardless of
    /// exact plist format.
    fn extract_from_text_repr(text: &str) -> IosAppInfo {
        let bundle_id = Self::extract_value(text, "CFBundleIdentifier")
            .unwrap_or_else(|| "unknown".to_string());
        let version = Self::extract_value(text, "CFBundleShortVersionString")
            .or_else(|| Self::extract_value(text, "CFBundleVersion"))
            .unwrap_or_else(|| "unknown".to_string());
        let min_ios =
            Self::extract_value(text, "MinimumOSVersion").unwrap_or_else(|| "unknown".to_string());

        let permissions = PERMISSION_KEYS
            .iter()
            .filter(|&&k| text.contains(k))
            .map(|&k| k.to_string())
            .collect();

        IosAppInfo {
            bundle_id,
            version,
            min_ios,
            permissions,
        }
    }

    /// Find the string value following `key` in an XML or text plist.
    fn extract_value(text: &str, key: &str) -> Option<String> {
        // XML plist: <key>CFBundleIdentifier</key>\n<string>VALUE</string>
        if let Some(key_pos) = text.find(key) {
            let after = &text[key_pos + key.len()..];
            // XML: look for <string>…</string>
            if let Some(s) = after.find("<string>") {
                let start = s + 8; // len("<string>") == 8
                let end = after[start..].find("</string>")?;
                return Some(after[start..start + end].trim().to_string());
            }
            // Text/OpenStep plist: = "VALUE";
            if let Some(eq) = after.find('=') {
                let rest = after[eq + 1..].trim_start();
                if let Some(inner) = rest.strip_prefix('"') {
                    let close = inner.find('"')?;
                    return Some(inner[..close].to_string());
                }
            }
        }
        None
    }
}

// ─── IosSecurityReport ────────────────────────────────────────────────────────

/// Whether debug symbols (`N_OSO` stab entries) are present in a Mach-O binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DebugSymbolStatus {
    /// Debug symbols are present.
    Present,
    /// Debug symbols are not present.
    Absent,
}

impl DebugSymbolStatus {
    /// Convert from a boolean (`true` = present).
    #[must_use]
    pub const fn from_bool(present: bool) -> Self {
        if present { Self::Present } else { Self::Absent }
    }

    /// Returns `true` when debug symbols are present.
    #[must_use]
    pub const fn is_present(self) -> bool {
        matches!(self, Self::Present)
    }
}

impl fmt::Display for DebugSymbolStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.is_present() { "true" } else { "false" })
    }
}

/// Summary of security properties found (or not found) in a Mach-O binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosSecurityReport {
    /// Automatic Reference Counting — `_objc_release` symbol present.
    pub arc: bool,
    /// Position-Independent Executable — `MH_PIE` flag set in Mach-O header.
    pub pie: bool,
    /// Stack protector — `___stack_chk_fail` symbol present.
    pub stack_canary: bool,
    /// Debug symbols — `N_OSO` stab entries present in the symbol table.
    pub has_debug_symbols: DebugSymbolStatus,
}

/// Analyses a Mach-O binary for common security properties.
pub struct IosSecurityChecker;

impl IosSecurityChecker {
    /// Check for ARC usage: look for the `_objc_release` symbol.
    #[must_use]
    pub fn check_arc_usage(macho_bytes: &[u8]) -> bool {
        Self::has_symbol(macho_bytes, "_objc_release")
    }

    /// Check for PIE: `MH_PIE` flag (`0x0020_0000`) in the Mach-O header flags.
    #[must_use]
    pub fn check_pie_enabled(macho_bytes: &[u8]) -> bool {
        const MH_PIE: u32 = 0x0020_0000;
        match goblin::mach::MachO::parse(macho_bytes, 0) {
            Ok(macho) => (macho.header.flags & MH_PIE) != 0,
            Err(_) => false,
        }
    }

    /// Check for stack canary: look for `___stack_chk_fail` symbol.
    #[must_use]
    pub fn check_stack_canary(macho_bytes: &[u8]) -> bool {
        Self::has_symbol(macho_bytes, "___stack_chk_fail")
            || Self::has_symbol(macho_bytes, "__stack_chk_fail")
    }

    /// Check for debug symbols: presence of `N_OSO` stab entries (type 0x66).
    /// `N_OSO` stabs record the path to the object file and are stripped in
    /// release builds.
    #[must_use]
    pub fn check_debug_symbols(macho_bytes: &[u8]) -> bool {
        const N_OSO: u8 = 0x66;
        goblin::mach::MachO::parse(macho_bytes, 0).is_ok_and(|macho| {
            macho
                .symbols()
                .flatten()
                .any(|(_, nlist)| nlist.n_type == N_OSO)
        })
    }

    /// Run all checks and return a consolidated `IosSecurityReport`.
    #[must_use]
    pub fn report(macho_bytes: &[u8]) -> IosSecurityReport {
        IosSecurityReport {
            arc: Self::check_arc_usage(macho_bytes),
            pie: Self::check_pie_enabled(macho_bytes),
            stack_canary: Self::check_stack_canary(macho_bytes),
            has_debug_symbols: DebugSymbolStatus::from_bool(Self::check_debug_symbols(macho_bytes)),
        }
    }

    /// Alias of [`report`](Self::report) kept for callers that expect the
    /// more descriptive `full_report` name.
    #[must_use]
    pub fn full_report(macho_bytes: &[u8]) -> IosSecurityReport {
        Self::report(macho_bytes)
    }

    // ── helpers ──────────────────────────────────────────────────────────

    fn has_symbol(macho_bytes: &[u8], target: &str) -> bool {
        goblin::mach::MachO::parse(macho_bytes, 0)
            .is_ok_and(|macho| macho.symbols().flatten().any(|(name, _)| name == target))
    }
}

// ─── IosClassDumper ───────────────────────────────────────────────────────────

/// Extracts `ObjC` class names and Swift type names from a Mach-O binary.
pub struct IosClassDumper;

impl IosClassDumper {
    /// Extract `ObjC` class names from `__TEXT,__objc_classnames` (falling back
    /// to `__DATA,__objc_classrefs`) in the Mach-O binary.
    ///
    /// Returns an empty `Vec` when the binary cannot be parsed or contains no
    /// `ObjC` class name data.
    #[must_use]
    pub fn extract_objc_classes(macho_bytes: &[u8]) -> Vec<String> {
        scan_objc_classes(macho_bytes)
    }

    /// Extract Swift type names by scanning the symbol table for symbols whose
    /// names begin with the Swift 5 ABI-stable prefix `_$s`.
    ///
    /// Only distinct names are returned; the raw mangled form is preserved so
    /// callers can pass them through `SwiftDemangler` if needed.
    #[must_use]
    pub fn extract_swift_types(macho_bytes: &[u8]) -> Vec<String> {
        goblin::mach::MachO::parse(macho_bytes, 0).map_or_else(
            |_| Vec::new(),
            |macho| {
                let mut seen = std::collections::HashSet::new();
                let mut out = Vec::new();
                for sym in macho.symbols().flatten() {
                    let (name, _) = sym;
                    if SwiftDemangler::is_swift_mangled(name) && seen.insert(name.to_string()) {
                        out.push(name.to_string());
                    }
                }
                out
            },
        )
    }
}

// ─── ObjC Metadata Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod objc_tests {
    use super::*;

    // ── ObjcClass helpers ──────────────────────────────────────────────────

    fn sample_class() -> ObjcClass {
        ObjcClass {
            name: "MyViewController".to_string(),
            superclass: Some("UIViewController".to_string()),
            protocols: vec![
                "UITableViewDelegate".to_string(),
                "UITableViewDataSource".to_string(),
            ],
            instance_methods: vec![
                ObjcMethod {
                    name: "viewDidLoad".to_string(),
                    type_encoding: "v16@0:8".to_string(),
                    imp_addr: 0x1000_4000,
                },
                ObjcMethod {
                    name: "tableView:numberOfRowsInSection:".to_string(),
                    type_encoding: "i24@0:8@16i20".to_string(),
                    imp_addr: 0x1000_4100,
                },
            ],
            class_methods: vec![ObjcMethod {
                name: "alloc".to_string(),
                type_encoding: "@16@0:8".to_string(),
                imp_addr: 0x1000_4200,
            }],
            ivars: vec![ObjcIvar {
                name: "_tableView".to_string(),
                type_encoding: "@\"UITableView\"".to_string(),
                offset: 8,
                size: 8,
            }],
            properties: vec![ObjcProperty {
                name: "tableView".to_string(),
                attributes: "T@\"UITableView\",N,V_tableView".to_string(),
            }],
        }
    }

    #[test]
    fn test_objc_class_total_method_count() {
        let c = sample_class();
        assert_eq!(c.total_method_count(), 3);
    }

    #[test]
    fn test_objc_class_adopts_protocol_true() {
        let c = sample_class();
        assert!(c.adopts_protocol("UITableViewDelegate"));
    }

    #[test]
    fn test_objc_class_adopts_protocol_false() {
        let c = sample_class();
        assert!(!c.adopts_protocol("NSCoding"));
    }

    #[test]
    fn test_objc_class_find_instance_method() {
        let c = sample_class();
        let m = c.find_instance_method("viewDidLoad");
        assert!(m.is_some());
        assert_eq!(m.unwrap().imp_addr, 0x1000_4000);
    }

    #[test]
    fn test_objc_class_find_instance_method_missing() {
        let c = sample_class();
        assert!(c.find_instance_method("nonexistent:").is_none());
    }

    #[test]
    fn test_objc_class_find_class_method() {
        let c = sample_class();
        let m = c.find_class_method("alloc");
        assert!(m.is_some());
        assert_eq!(m.unwrap().imp_addr, 0x1000_4200);
    }

    #[test]
    fn test_objc_class_serialization() {
        let c = sample_class();
        let json = serde_json::to_string(&c).unwrap();
        let decoded: ObjcClass = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.name, c.name);
        assert_eq!(decoded.instance_methods.len(), 2);
    }

    // ── decode_type_encoding ───────────────────────────────────────────────

    #[test]
    fn test_decode_type_encoding_basic() {
        let parts = decode_type_encoding("@:I");
        assert_eq!(parts, ["id", "SEL", "unsigned int"]);
    }

    #[test]
    fn test_decode_type_encoding_void_id_sel() {
        let parts = decode_type_encoding("v@:");
        assert_eq!(parts, ["void", "id", "SEL"]);
    }

    #[test]
    fn test_decode_type_encoding_primitives() {
        let parts = decode_type_encoding("cifsqd");
        assert_eq!(
            parts,
            ["char", "int", "float", "short", "long long", "double"]
        );
    }

    #[test]
    fn test_decode_type_encoding_unsigned() {
        let parts = decode_type_encoding("CISQ");
        assert_eq!(
            parts,
            [
                "unsigned char",
                "unsigned int",
                "unsigned short",
                "unsigned long long"
            ]
        );
    }

    #[test]
    fn test_decode_type_encoding_pointer() {
        let parts = decode_type_encoding("^i");
        assert_eq!(parts, ["*int"]);
    }

    #[test]
    fn test_decode_type_encoding_cstring() {
        let parts = decode_type_encoding("*");
        assert_eq!(parts, ["char*"]);
    }

    #[test]
    fn test_decode_type_encoding_bool() {
        let parts = decode_type_encoding("B");
        assert_eq!(parts, ["bool"]);
    }

    #[test]
    fn test_decode_type_encoding_class() {
        let parts = decode_type_encoding("#");
        assert_eq!(parts, ["Class"]);
    }

    #[test]
    fn test_decode_type_encoding_struct() {
        let parts = decode_type_encoding("{CGRect=dddd}");
        assert_eq!(parts[0], "struct CGRect");
    }

    #[test]
    fn test_decode_type_encoding_union() {
        let parts = decode_type_encoding("(value=id)");
        assert_eq!(parts[0], "union value");
    }

    #[test]
    fn test_decode_type_encoding_array() {
        let parts = decode_type_encoding("[4i]");
        assert_eq!(parts[0], "int[4]");
    }

    #[test]
    fn test_decode_type_encoding_pointer_to_object() {
        let parts = decode_type_encoding("^@");
        assert_eq!(parts, ["*id"]);
    }

    // ── scan_objc_selectors / scan_objc_classes ────────────────────────────

    #[test]
    fn test_scan_objc_selectors_empty_binary() {
        let result = scan_objc_selectors(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_scan_objc_selectors_garbage_binary() {
        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02];
        let result = scan_objc_selectors(&garbage);
        assert!(result.is_empty());
    }

    #[test]
    fn test_scan_objc_classes_empty_binary() {
        let result = scan_objc_classes(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_scan_objc_classes_garbage_binary() {
        let garbage = vec![0xCA, 0xFE, 0xBA, 0xBE];
        let result = scan_objc_classes(&garbage);
        assert!(result.is_empty());
    }

    // ── read_cstrings ──────────────────────────────────────────────────────

    #[test]
    fn test_read_cstrings_basic() {
        let data = b"hello\0world\0";
        let result = read_cstrings(data);
        assert_eq!(result, ["hello", "world"]);
    }

    #[test]
    fn test_read_cstrings_no_trailing_nul() {
        let data = b"hello\0world";
        let result = read_cstrings(data);
        assert_eq!(result, ["hello", "world"]);
    }

    #[test]
    fn test_read_cstrings_empty() {
        let result = read_cstrings(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_read_cstrings_only_nuls() {
        let data = b"\0\0\0";
        let result = read_cstrings(data);
        assert!(result.is_empty());
    }

    // ── SwiftDemangler ─────────────────────────────────────────────────────

    #[test]
    fn test_swift_is_mangled_true() {
        assert!(SwiftDemangler::is_swift_mangled("_$sSS10Foundation"));
        assert!(SwiftDemangler::is_swift_mangled("_$S3FooC"));
    }

    #[test]
    fn test_swift_is_mangled_false() {
        assert!(!SwiftDemangler::is_swift_mangled("_objc_msgSend"));
        assert!(!SwiftDemangler::is_swift_mangled("__ZN3Foo3barEv"));
        assert!(!SwiftDemangler::is_swift_mangled(""));
    }

    #[test]
    fn test_swift_demangle_string() {
        assert_eq!(
            SwiftDemangler::demangle("_$sSS"),
            Some("Swift.String".to_string())
        );
    }

    #[test]
    fn test_swift_demangle_int() {
        assert_eq!(
            SwiftDemangler::demangle("_$sSi"),
            Some("Swift.Int".to_string())
        );
    }

    #[test]
    fn test_swift_demangle_bool() {
        assert_eq!(
            SwiftDemangler::demangle("_$sSb"),
            Some("Swift.Bool".to_string())
        );
    }

    #[test]
    fn test_swift_demangle_float() {
        assert_eq!(
            SwiftDemangler::demangle("_$sSf"),
            Some("Swift.Float".to_string())
        );
    }

    #[test]
    fn test_swift_demangle_double() {
        assert_eq!(
            SwiftDemangler::demangle("_$sSd"),
            Some("Swift.Double".to_string())
        );
    }

    #[test]
    fn test_swift_demangle_uint() {
        assert_eq!(
            SwiftDemangler::demangle("_$sSu"),
            Some("Swift.UInt".to_string())
        );
    }

    #[test]
    fn test_swift_demangle_string_pair() {
        assert_eq!(
            SwiftDemangler::demangle("_$sS2S"),
            Some("String, String".to_string())
        );
    }

    #[test]
    fn test_swift_demangle_class_suffix() {
        let result = SwiftDemangler::demangle("_$s3FooC");
        assert!(result.is_some());
        let s = result.unwrap();
        assert!(s.contains("class"), "expected 'class' in '{s}'");
    }

    #[test]
    fn test_swift_demangle_struct_suffix() {
        let result = SwiftDemangler::demangle("_$s3FooV");
        assert!(result.is_some());
        let s = result.unwrap();
        assert!(s.contains("struct"), "expected 'struct' in '{s}'");
    }

    #[test]
    fn test_swift_demangle_enum_suffix() {
        let result = SwiftDemangler::demangle("_$s3FooO");
        assert!(result.is_some());
        let s = result.unwrap();
        assert!(s.contains("enum"), "expected 'enum' in '{s}'");
    }

    #[test]
    fn test_swift_demangle_void_func() {
        assert_eq!(
            SwiftDemangler::demangle("_$syyyF"),
            Some("() -> ()".to_string())
        );
    }

    #[test]
    fn test_swift_demangle_void_func_short() {
        assert_eq!(
            SwiftDemangler::demangle("_$syyF"),
            Some("() -> ()".to_string())
        );
    }

    #[test]
    fn test_swift_demangle_non_mangled_returns_none() {
        assert!(SwiftDemangler::demangle("_objc_msgSend").is_none());
    }

    #[test]
    fn test_swift_demangle_length_prefixed() {
        // "3Foo3Bar" should decode to "Foo.Bar"
        let result = SwiftDemangler::demangle("_$s3Foo3Bar");
        assert!(result.is_some());
        let s = result.unwrap();
        assert_eq!(s, "Foo.Bar");
    }

    #[test]
    fn test_swift_demangle_array_string() {
        assert_eq!(
            SwiftDemangler::demangle("_$sSayS"),
            Some("Array<String>".to_string())
        );
    }

    // ── IpaInfo ────────────────────────────────────────────────────────────

    #[test]
    fn test_ipa_info_from_empty_binary() {
        let info = IpaInfo::from_macho(&[]);
        assert_eq!(info.bundle_id, "unknown");
        assert_eq!(info.class_count, 0);
        assert_eq!(info.method_count, 0);
        assert!(!info.has_bitcode);
        assert!(info.architectures.is_empty());
    }

    #[test]
    fn test_ipa_info_from_garbage() {
        let pattern = [0xDE_u8, 0xAD, 0xBE, 0xEF];
        let garbage: Vec<u8> = pattern.iter().cycle().take(64).copied().collect();
        let info = IpaInfo::from_macho(&garbage);
        assert_eq!(info.bundle_id, "unknown");
        assert!(info.architectures.is_empty());
    }

    #[test]
    fn test_ipa_info_serialization() {
        let info = IpaInfo {
            bundle_id: "com.test.App".to_string(),
            version: "2.0".to_string(),
            min_os: "15.0".to_string(),
            class_count: 42,
            method_count: 200,
            swift_class_count: 10,
            entitlements: vec!["get-task-allow".to_string()],
            has_bitcode: false,
            architectures: vec!["arm64".to_string()],
        };
        let json = serde_json::to_string(&info).unwrap();
        let decoded: IpaInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.bundle_id, "com.test.App");
        assert_eq!(decoded.class_count, 42);
        assert_eq!(decoded.swift_class_count, 10);
    }

    #[test]
    fn test_cpu_type_to_string_arm64() {
        assert_eq!(cpu_type_to_string(0x0100_000C), "arm64");
    }

    #[test]
    fn test_cpu_type_to_string_x86_64() {
        assert_eq!(cpu_type_to_string(0x0100_0007), "x86_64");
    }

    #[test]
    fn test_cpu_type_to_string_unknown() {
        let s = cpu_type_to_string(0xDEAD);
        assert!(s.starts_with("cpu_"));
    }

    // ── IosAppInfoExtractor ────────────────────────────────────────────────

    #[test]
    fn test_extract_app_info_returns_none_for_empty() {
        let result = IosAppInfoExtractor::extract_app_info(&[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_ios_app_info_fields() {
        let info = IosAppInfo {
            bundle_id: "com.example.Test".to_string(),
            version: "3.1".to_string(),
            min_ios: "16.0".to_string(),
            permissions: vec!["NSCameraUsageDescription".to_string()],
        };
        assert_eq!(info.bundle_id, "com.example.Test");
        assert_eq!(info.permissions.len(), 1);
    }

    // ── IosSecurityChecker ─────────────────────────────────────────────────

    #[test]
    fn test_security_checker_empty_bytes() {
        assert!(!IosSecurityChecker::check_arc_usage(&[]));
        assert!(!IosSecurityChecker::check_pie_enabled(&[]));
        assert!(!IosSecurityChecker::check_stack_canary(&[]));
        assert!(!IosSecurityChecker::check_debug_symbols(&[]));
    }

    #[test]
    fn test_security_report_serialization() {
        let report = IosSecurityReport {
            arc: true,
            pie: true,
            stack_canary: false,
            has_debug_symbols: DebugSymbolStatus::Absent,
        };
        let json = serde_json::to_string(&report).unwrap();
        let decoded: IosSecurityReport = serde_json::from_str(&json).unwrap();
        assert!(decoded.arc);
        assert!(decoded.pie);
        assert!(!decoded.stack_canary);
        assert!(!decoded.has_debug_symbols.is_present());
    }

    // ── IosClassDumper ─────────────────────────────────────────────────────

    #[test]
    fn test_class_dumper_empty_binary() {
        let classes = IosClassDumper::extract_objc_classes(&[]);
        assert!(classes.is_empty());
        let swift = IosClassDumper::extract_swift_types(&[]);
        assert!(swift.is_empty());
    }
}

// ─── Jailbreak detection pattern database ────────────────────────────────────

/// Known file-system paths checked by jailbreak detection routines.
pub static JAILBREAK_PATHS: &[&str] = &[
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/bin/bash",
    "/bin/sh",
    "/usr/sbin/sshd",
    "/usr/bin/ssh",
    "/etc/apt",
    "/var/lib/dpkg/info",
    "/var/lib/cydia",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/stash",
    "/var/checkra1n.dmg",
    "/.bootstrapped_electra",
    "/taurine/jailbreakd",
    "/palera1n",
];

/// Known dylib/framework paths injected by jailbreak tools.
pub static JAILBREAK_DYLIBS: &[&str] = &[
    "MobileSubstrate",
    "CydiaSubstrate",
    "Substitute",
    "libsubstitute",
    "TweakInject",
    "Dopamine",
    "Electra",
    "checkra1n",
];

/// A jailbreak detection indicator found in a binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JailbreakIndicator {
    /// The type of detection technique used.
    pub technique: JailbreakTechnique,
    /// The specific pattern or value that triggered the detection.
    pub pattern: String,
    /// Virtual address in the binary where the pattern was found (0 = N/A).
    pub address: u64,
}

/// Classification of a jailbreak detection technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JailbreakTechnique {
    /// Path existence check via `stat` / `access` / `fopen`.
    FileSystemCheck,
    /// `fork()` call (forbidden in non-jailbroken apps).
    ForkCall,
    /// `ptrace(PT_DENY_ATTACH, ...)` anti-debug.
    PtraceAntiDebug,
    /// Dynamic library presence check.
    DylibCheck,
    /// `system()` or `popen()` shell invocation.
    ShellExec,
    /// URL scheme handler check (e.g. `cydia://`).
    UrlSchemeCheck,
    /// Checking the sandbox via `sandbox_check`.
    SandboxCheck,
    /// Checking for write access outside sandbox.
    WriteCheck,
    /// Symbol visibility check via `dlsym`.
    DlsymCheck,
}

impl JailbreakTechnique {
    /// Returns a human-readable description of the technique.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::FileSystemCheck => "File-system existence check",
            Self::ForkCall => "fork() call — forbidden in sandboxed apps",
            Self::PtraceAntiDebug => "ptrace(PT_DENY_ATTACH) anti-debug",
            Self::DylibCheck => "Dynamic library presence check",
            Self::ShellExec => "Shell execution via system()/popen()",
            Self::UrlSchemeCheck => "URL scheme registration check",
            Self::SandboxCheck => "Sandbox violation check",
            Self::WriteCheck => "Filesystem write outside sandbox",
            Self::DlsymCheck => "dlsym() symbol lookup",
        }
    }
}

/// Heuristic jailbreak detection analyser.
///
/// Scans string literals and symbol imports in a binary for known
/// jailbreak-detection patterns.  Results are indicative only — both
/// false positives (app uses paths for legitimate reasons) and false
/// negatives (obfuscated checks) are possible.
pub struct JailbreakDetector;

impl JailbreakDetector {
    /// Scan raw binary bytes for jailbreak detection patterns.
    ///
    /// Looks for:
    /// 1. Known jailbreak path strings in the `__cstring` section (or via
    ///    raw substring scan when Mach-O parsing is not available).
    /// 2. `fork`, `ptrace`, `system`, `popen`, `sandbox_check`, `dlsym`
    ///    imports in the symbol table.
    /// 3. `cydia://` and `sileo://` URL scheme strings.
    #[must_use]
    pub fn scan(binary: &[u8]) -> Vec<JailbreakIndicator> {
        let mut indicators = Vec::new();

        // ── String-based detection ─────────────────────────────────────────
        for path in JAILBREAK_PATHS {
            if contains_bytes(binary, path.as_bytes()) {
                indicators.push(JailbreakIndicator {
                    technique: JailbreakTechnique::FileSystemCheck,
                    pattern: path.to_string(),
                    address: 0,
                });
            }
        }

        for dylib in JAILBREAK_DYLIBS {
            if contains_bytes(binary, dylib.as_bytes()) {
                indicators.push(JailbreakIndicator {
                    technique: JailbreakTechnique::DylibCheck,
                    pattern: dylib.to_string(),
                    address: 0,
                });
            }
        }

        for scheme in &["cydia://", "sileo://", "zebra://"] {
            if contains_bytes(binary, scheme.as_bytes()) {
                indicators.push(JailbreakIndicator {
                    technique: JailbreakTechnique::UrlSchemeCheck,
                    pattern: scheme.to_string(),
                    address: 0,
                });
            }
        }

        // ── Symbol / import scan ───────────────────────────────────────────
        let suspicious_syms = [
            ("_fork", JailbreakTechnique::ForkCall),
            ("_ptrace", JailbreakTechnique::PtraceAntiDebug),
            ("_system", JailbreakTechnique::ShellExec),
            ("_popen", JailbreakTechnique::ShellExec),
            ("sandbox_check", JailbreakTechnique::SandboxCheck),
            ("_dlsym", JailbreakTechnique::DlsymCheck),
        ];

        for (sym, technique) in &suspicious_syms {
            if contains_bytes(binary, sym.as_bytes()) {
                indicators.push(JailbreakIndicator {
                    technique: *technique,
                    pattern: sym.to_string(),
                    address: 0,
                });
            }
        }

        // Deduplicate by pattern
        indicators.sort_by(|a, b| a.pattern.cmp(&b.pattern));
        indicators.dedup_by(|a, b| a.pattern == b.pattern);

        indicators
    }

    /// Returns `true` if the binary contains at least one jailbreak check.
    #[must_use]
    pub fn has_jailbreak_detection(binary: &[u8]) -> bool {
        !Self::scan(binary).is_empty()
    }

    /// Returns a summary of how many indicators were found per technique category.
    #[must_use]
    pub fn technique_summary(indicators: &[JailbreakIndicator]) -> Vec<(&'static str, usize)> {
        let mut counts: std::collections::HashMap<&'static str, usize> =
            std::collections::HashMap::new();
        for ind in indicators {
            *counts.entry(ind.technique.description()).or_default() += 1;
        }
        let mut result: Vec<_> = counts.into_iter().collect();
        result.sort_by_key(|(k, _)| *k);
        result
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ─── SSL pinning detection ────────────────────────────────────────────────────

/// SSL pinning indicator found in a binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SslPinningIndicator {
    /// Detection category.
    pub kind: SslPinningKind,
    /// Specific pattern found.
    pub pattern: String,
}

/// Classification of an SSL pinning technique.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SslPinningKind {
    /// Custom `NSURLSessionDelegate` with certificate validation.
    NsUrlSessionDelegate,
    /// `SecTrustEvaluate` / `SecTrustEvaluateWithError` calls.
    SecTrustEvaluate,
    /// `TrustKit`, Alamofire certificate pinner, or similar library.
    ThirdPartyLibrary,
    /// `AFNetworking` pinning API.
    AfNetworking,
    /// `OkHttp` / `OkHttp3` certificate pinner pattern (cross-platform).
    OkHttp,
    /// Custom public-key pinning via `SecCertificateCopyKey`.
    PublicKeyPinning,
}

impl SslPinningKind {
    /// Returns a human-readable label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::NsUrlSessionDelegate => "NSURLSessionDelegate",
            Self::SecTrustEvaluate => "SecTrustEvaluate",
            Self::ThirdPartyLibrary => "Third-party pinning library",
            Self::AfNetworking => "AFNetworking",
            Self::OkHttp => "OkHttp certificate pinner",
            Self::PublicKeyPinning => "Public-key pinning",
        }
    }
}

/// SSL pinning pattern detector.
pub struct SslPinningDetector;

impl SslPinningDetector {
    /// Scan a binary for SSL pinning patterns.
    #[must_use]
    pub fn scan(binary: &[u8]) -> Vec<SslPinningIndicator> {
        let patterns: &[(&[u8], SslPinningKind)] = &[
            (b"SecTrustEvaluate", SslPinningKind::SecTrustEvaluate),
            (
                b"SecTrustEvaluateWithError",
                SslPinningKind::SecTrustEvaluate,
            ),
            (
                b"URLSession:didReceiveChallenge:",
                SslPinningKind::NsUrlSessionDelegate,
            ),
            (
                b"didReceiveAuthenticationChallenge",
                SslPinningKind::NsUrlSessionDelegate,
            ),
            (b"TrustKit", SslPinningKind::ThirdPartyLibrary),
            (b"TSKPinningValidator", SslPinningKind::ThirdPartyLibrary),
            (b"AFSecurityPolicy", SslPinningKind::AfNetworking),
            (b"pinnedCertificates", SslPinningKind::AfNetworking),
            (b"CertificatePinner", SslPinningKind::OkHttp),
            (b"SecCertificateCopyKey", SslPinningKind::PublicKeyPinning),
            (b"SecKeyCreateWithData", SslPinningKind::PublicKeyPinning),
        ];

        let mut found = Vec::new();
        for (pattern, kind) in patterns {
            if contains_bytes(binary, pattern) {
                found.push(SslPinningIndicator {
                    kind: kind.clone(),
                    pattern: std::str::from_utf8(pattern).unwrap_or("?").to_string(),
                });
            }
        }

        // Deduplicate by pattern
        found.sort_by(|a, b| a.pattern.cmp(&b.pattern));
        found.dedup_by(|a, b| a.pattern == b.pattern);
        found
    }

    /// Returns `true` if any SSL pinning pattern was found.
    #[must_use]
    pub fn has_ssl_pinning(binary: &[u8]) -> bool {
        !Self::scan(binary).is_empty()
    }
}

// ─── ObjC method swizzling detector ──────────────────────────────────────────

/// Evidence of Objective-C method swizzling found in a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwizzlingIndicator {
    /// The swizzling API used.
    pub api: String,
    /// Class or module name hint, if recoverable.
    pub context: String,
}

/// Detector for Objective-C runtime method swizzling.
pub struct SwizzlingDetector;

impl SwizzlingDetector {
    /// Known Objective-C runtime APIs used for method swizzling.
    const SWIZZLE_APIS: &'static [&'static str] = &[
        "method_exchangeImplementations",
        "method_setImplementation",
        "method_getImplementation",
        "class_addMethod",
        "class_replaceMethod",
        "objc_getClass",
        "objc_allocateClassPair",
        "objc_registerClassPair",
    ];

    /// Scan a binary for method swizzling APIs.
    #[must_use]
    pub fn scan(binary: &[u8]) -> Vec<SwizzlingIndicator> {
        let mut indicators = Vec::new();
        for api in Self::SWIZZLE_APIS {
            if contains_bytes(binary, api.as_bytes()) {
                indicators.push(SwizzlingIndicator {
                    api: api.to_string(),
                    context: String::new(),
                });
            }
        }
        indicators
    }

    /// Returns `true` if any swizzling API was found.
    #[must_use]
    pub fn has_swizzling(binary: &[u8]) -> bool {
        !Self::scan(binary).is_empty()
    }
}

// ─── Comprehensive iOS analysis report ────────────────────────────────────────

/// Full security analysis report for an iOS binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosAnalysisReport {
    /// Security hardening flags.
    pub security: IosSecurityReport,
    /// Jailbreak detection indicators.
    pub jailbreak_indicators: Vec<JailbreakIndicator>,
    /// SSL pinning indicators.
    pub ssl_pinning_indicators: Vec<SslPinningIndicator>,
    /// Method swizzling indicators.
    pub swizzling_indicators: Vec<SwizzlingIndicator>,
    /// `ObjC` selectors found.
    pub objc_selectors: Vec<String>,
    /// `ObjC` class names found.
    pub objc_classes: Vec<String>,
}

impl IosAnalysisReport {
    /// Run all detectors on `binary` and build a report.
    #[must_use]
    pub fn analyse(binary: &[u8]) -> Self {
        Self {
            security: IosSecurityChecker::full_report(binary),
            jailbreak_indicators: JailbreakDetector::scan(binary),
            ssl_pinning_indicators: SslPinningDetector::scan(binary),
            swizzling_indicators: SwizzlingDetector::scan(binary),
            objc_selectors: scan_objc_selectors(binary),
            objc_classes: scan_objc_classes(binary),
        }
    }

    /// Returns `true` if the binary has any jailbreak detection.
    #[must_use]
    pub const fn has_jailbreak_detection(&self) -> bool {
        !self.jailbreak_indicators.is_empty()
    }

    /// Returns `true` if the binary has any SSL pinning.
    #[must_use]
    pub const fn has_ssl_pinning(&self) -> bool {
        !self.ssl_pinning_indicators.is_empty()
    }

    /// Returns `true` if the binary uses method swizzling.
    #[must_use]
    pub const fn has_swizzling(&self) -> bool {
        !self.swizzling_indicators.is_empty()
    }

    /// Summarise the report as a multi-line string.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut lines = Vec::with_capacity(9);
        lines.push(format!("ARC: {}", self.security.arc));
        lines.push(format!("PIE: {}", self.security.pie));
        lines.push(format!("Stack Canary: {}", self.security.stack_canary));
        lines.push(format!(
            "Debug Symbols: {}",
            self.security.has_debug_symbols
        ));
        lines.push(format!(
            "Jailbreak Indicators: {}",
            self.jailbreak_indicators.len()
        ));
        lines.push(format!(
            "SSL Pinning Indicators: {}",
            self.ssl_pinning_indicators.len()
        ));
        lines.push(format!(
            "Swizzling APIs: {}",
            self.swizzling_indicators.len()
        ));
        lines.push(format!("ObjC Classes: {}", self.objc_classes.len()));
        lines.push(format!("ObjC Selectors: {}", self.objc_selectors.len()));
        lines.join("\n")
    }
}

// ─── Enterprise iOS tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod enterprise_ios_tests {
    use super::*;

    fn binary_with(patterns: &[&str]) -> Vec<u8> {
        let mut v = Vec::new();
        for p in patterns {
            v.extend_from_slice(p.as_bytes());
            v.push(0); // NUL separator
        }
        v
    }

    // ── JailbreakDetector ─────────────────────────────────────────────────

    #[test]
    fn test_jailbreak_empty_binary() {
        assert!(!JailbreakDetector::has_jailbreak_detection(&[]));
    }

    #[test]
    fn test_jailbreak_cydia_path() {
        let bin = binary_with(&["/Applications/Cydia.app"]);
        assert!(JailbreakDetector::has_jailbreak_detection(&bin));
    }

    #[test]
    fn test_jailbreak_bash_path() {
        let bin = binary_with(&["/bin/bash"]);
        assert!(JailbreakDetector::has_jailbreak_detection(&bin));
    }

    #[test]
    fn test_jailbreak_fork_symbol() {
        let bin = binary_with(&["_fork"]);
        let indicators = JailbreakDetector::scan(&bin);
        assert!(
            indicators
                .iter()
                .any(|i| i.technique == JailbreakTechnique::ForkCall)
        );
    }

    #[test]
    fn test_jailbreak_ptrace_symbol() {
        let bin = binary_with(&["_ptrace"]);
        let indicators = JailbreakDetector::scan(&bin);
        assert!(
            indicators
                .iter()
                .any(|i| i.technique == JailbreakTechnique::PtraceAntiDebug)
        );
    }

    #[test]
    fn test_jailbreak_url_scheme_cydia() {
        let bin = binary_with(&["cydia://"]);
        let indicators = JailbreakDetector::scan(&bin);
        assert!(
            indicators
                .iter()
                .any(|i| i.technique == JailbreakTechnique::UrlSchemeCheck)
        );
    }

    #[test]
    fn test_jailbreak_dylib_substrate() {
        let bin = binary_with(&["MobileSubstrate"]);
        let indicators = JailbreakDetector::scan(&bin);
        assert!(
            indicators
                .iter()
                .any(|i| i.technique == JailbreakTechnique::DylibCheck)
        );
    }

    #[test]
    fn test_jailbreak_technique_description_not_empty() {
        for tech in &[
            JailbreakTechnique::FileSystemCheck,
            JailbreakTechnique::ForkCall,
            JailbreakTechnique::PtraceAntiDebug,
            JailbreakTechnique::DylibCheck,
            JailbreakTechnique::ShellExec,
            JailbreakTechnique::UrlSchemeCheck,
            JailbreakTechnique::SandboxCheck,
            JailbreakTechnique::WriteCheck,
            JailbreakTechnique::DlsymCheck,
        ] {
            assert!(!tech.description().is_empty());
        }
    }

    #[test]
    fn test_jailbreak_technique_summary() {
        let bin = binary_with(&["/bin/bash", "_fork"]);
        let indicators = JailbreakDetector::scan(&bin);
        let summary = JailbreakDetector::technique_summary(&indicators);
        assert!(!summary.is_empty());
    }

    #[test]
    fn test_jailbreak_dedup() {
        // Same path twice should not produce duplicate indicators
        let mut bin = Vec::new();
        bin.extend_from_slice(b"/bin/bash\0");
        bin.extend_from_slice(b"/bin/bash\0");
        let indicators = JailbreakDetector::scan(&bin);
        let count = indicators
            .iter()
            .filter(|i| i.pattern == "/bin/bash")
            .count();
        assert_eq!(count, 1);
    }

    // ── SslPinningDetector ────────────────────────────────────────────────

    #[test]
    fn test_ssl_pinning_empty_binary() {
        assert!(!SslPinningDetector::has_ssl_pinning(&[]));
    }

    #[test]
    fn test_ssl_pinning_sec_trust_evaluate() {
        let bin = binary_with(&["SecTrustEvaluate"]);
        assert!(SslPinningDetector::has_ssl_pinning(&bin));
    }

    #[test]
    fn test_ssl_pinning_afnetworking() {
        let bin = binary_with(&["AFSecurityPolicy"]);
        let indicators = SslPinningDetector::scan(&bin);
        assert!(
            indicators
                .iter()
                .any(|i| i.kind == SslPinningKind::AfNetworking)
        );
    }

    #[test]
    fn test_ssl_pinning_trustkit() {
        let bin = binary_with(&["TrustKit"]);
        let indicators = SslPinningDetector::scan(&bin);
        assert!(
            indicators
                .iter()
                .any(|i| i.kind == SslPinningKind::ThirdPartyLibrary)
        );
    }

    #[test]
    fn test_ssl_pinning_delegate_selector() {
        let bin = binary_with(&["URLSession:didReceiveChallenge:"]);
        let indicators = SslPinningDetector::scan(&bin);
        assert!(
            indicators
                .iter()
                .any(|i| i.kind == SslPinningKind::NsUrlSessionDelegate)
        );
    }

    #[test]
    fn test_ssl_pinning_kind_labels_not_empty() {
        for kind in &[
            SslPinningKind::NsUrlSessionDelegate,
            SslPinningKind::SecTrustEvaluate,
            SslPinningKind::ThirdPartyLibrary,
            SslPinningKind::AfNetworking,
            SslPinningKind::OkHttp,
            SslPinningKind::PublicKeyPinning,
        ] {
            assert!(!kind.label().is_empty());
        }
    }

    // ── SwizzlingDetector ─────────────────────────────────────────────────

    #[test]
    fn test_swizzling_empty_binary() {
        assert!(!SwizzlingDetector::has_swizzling(&[]));
    }

    #[test]
    fn test_swizzling_method_exchange() {
        let bin = binary_with(&["method_exchangeImplementations"]);
        assert!(SwizzlingDetector::has_swizzling(&bin));
    }

    #[test]
    fn test_swizzling_class_add_method() {
        let bin = binary_with(&["class_addMethod"]);
        let indicators = SwizzlingDetector::scan(&bin);
        assert_eq!(indicators.len(), 1);
        assert_eq!(indicators[0].api, "class_addMethod");
    }

    #[test]
    fn test_swizzling_multiple_apis() {
        let bin = binary_with(&["method_exchangeImplementations", "class_replaceMethod"]);
        let indicators = SwizzlingDetector::scan(&bin);
        assert_eq!(indicators.len(), 2);
    }

    // ── IosAnalysisReport ────────────────────────────────────────────────

    #[test]
    fn test_analysis_report_empty() {
        let report = IosAnalysisReport::analyse(&[]);
        assert!(!report.has_jailbreak_detection());
        assert!(!report.has_ssl_pinning());
        assert!(!report.has_swizzling());
    }

    #[test]
    fn test_analysis_report_summary_nonempty() {
        let report = IosAnalysisReport::analyse(&[]);
        let s = report.summary();
        assert!(s.contains("ARC:"));
        assert!(s.contains("PIE:"));
    }

    #[test]
    fn test_analysis_report_jailbreak_detected() {
        let bin = binary_with(&["/Applications/Cydia.app"]);
        let report = IosAnalysisReport::analyse(&bin);
        assert!(report.has_jailbreak_detection());
    }

    #[test]
    fn test_analysis_report_ssl_detected() {
        let bin = binary_with(&["SecTrustEvaluate"]);
        let report = IosAnalysisReport::analyse(&bin);
        assert!(report.has_ssl_pinning());
    }

    #[test]
    fn test_analysis_report_swizzling_detected() {
        let bin = binary_with(&["method_exchangeImplementations"]);
        let report = IosAnalysisReport::analyse(&bin);
        assert!(report.has_swizzling());
    }

    #[test]
    fn test_analysis_report_serialization() {
        let report = IosAnalysisReport::analyse(&[]);
        let json = serde_json::to_string(&report).unwrap();
        let decoded: IosAnalysisReport = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.objc_classes.len(), report.objc_classes.len());
    }

    // ── ObjcClass helpers ─────────────────────────────────────────────────

    #[test]
    fn test_objc_class_total_method_count() {
        let cls = ObjcClass {
            name: "Foo".into(),
            superclass: None,
            protocols: vec![],
            instance_methods: vec![ObjcMethod {
                name: "foo".into(),
                type_encoding: "v@:".into(),
                imp_addr: 0,
            }],
            class_methods: vec![ObjcMethod {
                name: "bar".into(),
                type_encoding: "@".into(),
                imp_addr: 0,
            }],
            ivars: vec![],
            properties: vec![],
        };
        assert_eq!(cls.total_method_count(), 2);
    }

    #[test]
    fn test_objc_class_adopts_protocol() {
        let cls = ObjcClass {
            name: "MyVC".into(),
            superclass: Some("UIViewController".into()),
            protocols: vec!["UITableViewDelegate".into(), "UITableViewDataSource".into()],
            instance_methods: vec![],
            class_methods: vec![],
            ivars: vec![],
            properties: vec![],
        };
        assert!(cls.adopts_protocol("UITableViewDelegate"));
        assert!(!cls.adopts_protocol("NSCoding"));
    }

    #[test]
    fn test_objc_class_find_instance_method() {
        let cls = ObjcClass {
            name: "MyClass".into(),
            superclass: None,
            protocols: vec![],
            instance_methods: vec![ObjcMethod {
                name: "init".into(),
                type_encoding: "@@:".into(),
                imp_addr: 0x1000,
            }],
            class_methods: vec![],
            ivars: vec![],
            properties: vec![],
        };
        let m = cls.find_instance_method("init");
        assert!(m.is_some());
        assert_eq!(m.unwrap().imp_addr, 0x1000);
        assert!(cls.find_instance_method("dealloc").is_none());
    }

    #[test]
    fn test_jailbreak_sandbox_check_symbol() {
        let bin = binary_with(&["sandbox_check"]);
        let indicators = JailbreakDetector::scan(&bin);
        assert!(
            indicators
                .iter()
                .any(|i| i.technique == JailbreakTechnique::SandboxCheck)
        );
    }

    #[test]
    fn test_jailbreak_paths_table_nonempty() {
        assert!(!JAILBREAK_PATHS.is_empty());
    }

    #[test]
    fn test_jailbreak_dylibs_table_nonempty() {
        assert!(!JAILBREAK_DYLIBS.is_empty());
    }

    #[test]
    fn test_ssl_pinning_public_key() {
        let bin = binary_with(&["SecCertificateCopyKey"]);
        let indicators = SslPinningDetector::scan(&bin);
        assert!(
            indicators
                .iter()
                .any(|i| i.kind == SslPinningKind::PublicKeyPinning)
        );
    }
}
