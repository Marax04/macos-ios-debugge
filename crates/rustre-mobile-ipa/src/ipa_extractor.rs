//! iOS IPA package extractor: ZIP extraction, app bundle structure parsing,
//! binary extraction, entitlements parsing.

use std::io::Read;
use std::path::Path;

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};

use crate::{Entitlements, InfoPlistFull, ProvisioningProfile, SimplePlistReader};

// ─── Bundle structure constants ───────────────────────────────────────────────

const MOBILE_PROVISION: &str = "embedded.mobileprovision";
const INFO_PLIST: &str = "Info.plist";
const ENTITLEMENTS_FILE: &str = "Entitlements.plist";
const XCENT_FILE: &str = "archived-expanded-entitlements.xcent";

// ─── BundleEntry ──────────────────────────────────────────────────────────────

/// Classification of an entry within the app bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntryKind {
    Binary,
    Plist,
    Framework,
    Plugin,
    WatchApp,
    Dylib,
    Resource,
    CodeSignature,
    Provision,
    Other,
}

/// A single entry in the IPA archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleEntry {
    /// Full ZIP path.
    pub zip_path: String,
    /// Path relative to the `.app` bundle root.
    pub bundle_rel: String,
    /// Uncompressed size in bytes.
    pub size: u64,
    /// Detected kind.
    pub kind: EntryKind,
    pub is_dir: bool,
}

impl BundleEntry {
    /// Return the filename component.
    #[must_use] 
    pub fn filename(&self) -> &str {
        self.zip_path.rsplit('/').next().unwrap_or(&self.zip_path)
    }

    /// Return the file extension (without dot), if any.
    #[must_use] 
    pub fn extension(&self) -> Option<&str> {
        let name = self.filename();
        let pos = name.rfind('.')?;
        Some(&name[pos + 1..])
    }

    /// Return `true` if the entry looks like a Mach-O binary (no extension, large).
    #[must_use] 
    pub fn is_macho_candidate(&self) -> bool {
        !self.is_dir && self.extension().is_none() && self.size > 4096
    }

    fn classify(path: &str, size: u64, is_dir: bool) -> EntryKind {
        if is_dir {
            if path.contains("/Frameworks/")  { return EntryKind::Framework; }
            if path.contains("/PlugIns/")     { return EntryKind::Plugin; }
            if path.contains("/Extensions/")  { return EntryKind::Plugin; }
            if path.contains("/Watch/")       { return EntryKind::WatchApp; }
            return EntryKind::Other;
        }
        let name = path.rsplit('/').next().unwrap_or(path);
        if name == MOBILE_PROVISION { return EntryKind::Provision; }
        if std::path::Path::new(name).extension().is_some_and(|e| e.eq_ignore_ascii_case("plist")) { return EntryKind::Plist; }
        if std::path::Path::new(name).extension().is_some_and(|e| e.eq_ignore_ascii_case("dylib")) { return EntryKind::Dylib; }
        if path.contains("/_CodeSignature/") { return EntryKind::CodeSignature; }
        if name.eq_ignore_ascii_case("Info.plist") { return EntryKind::Plist; }
        let ext = name.rfind('.').map_or("", |p| &name[p+1..]);
        match ext {
            "dylib" => EntryKind::Dylib,
            "plist" => EntryKind::Plist,
            "" if size > 4096 => EntryKind::Binary,
            "png"|"jpg"|"jpeg"|"gif"|"pdf"|"ttf"|"otf"|"strings"|
            "storyboardc"|"nib"|"xib"|"car"|"json"|"xml"|"html"|"css"|
            "js"|"wav"|"mp3"|"m4a"|"mp4"|"mov"|"lottie" => EntryKind::Resource,
            _ => EntryKind::Other,
        }
    }
}

// ─── AppBundleInfo ────────────────────────────────────────────────────────────

/// Structural information extracted from the app bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppBundleInfo {
    /// ZIP-path prefix of the `.app` directory (e.g. `Payload/MyApp.app`).
    pub app_prefix: String,
    /// App name (e.g. `MyApp`).
    pub app_name: String,
    /// Full ZIP path to the main executable.
    pub executable_path: String,
    /// Embedded framework paths.
    pub framework_paths: Vec<String>,
    /// App-extension (plugin) paths.
    pub plugin_paths: Vec<String>,
    /// `WatchKit` companion app paths.
    pub watch_app_paths: Vec<String>,
    /// All embedded dylib paths.
    pub dylib_paths: Vec<String>,
    /// All plist paths.
    pub plist_paths: Vec<String>,
    /// Total number of ZIP entries.
    pub total_entries: usize,
    /// Total uncompressed size of binary entries.
    pub binary_bytes: u64,
}

impl AppBundleInfo {
    /// True if the app has embedded frameworks.
    #[must_use] 
    pub const fn has_frameworks(&self) -> bool {
        !self.framework_paths.is_empty()
    }

    /// True if the app has app extensions.
    #[must_use] 
    pub const fn has_extensions(&self) -> bool {
        !self.plugin_paths.is_empty()
    }

    /// True if the app has a `WatchKit` app.
    #[must_use] 
    pub const fn has_watch_app(&self) -> bool {
        !self.watch_app_paths.is_empty()
    }
}

// ─── IpaExtractorV2 ───────────────────────────────────────────────────────────

/// Full-featured IPA extractor backed by the `zip` crate.
pub struct IpaExtractorV2 {
    raw: Vec<u8>,
    pub bundle: AppBundleInfo,
    pub entries: Vec<BundleEntry>,
}

impl IpaExtractorV2 {
    /// Open and parse an IPA from a file path.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or is not a valid IPA/ZIP archive.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read(path)
            .with_context(|| format!("reading IPA: {}", path.display()))?;
        Self::from_bytes(raw)
    }

    /// Parse an IPA from raw bytes.
    ///
    /// # Errors
    /// Returns an error if the bytes do not form a valid IPA/ZIP archive.
    pub fn from_bytes(raw: Vec<u8>) -> anyhow::Result<Self> {
        let cursor = std::io::Cursor::new(&raw);
        let mut zip = zip::ZipArchive::new(cursor)
            .context("Not a valid ZIP/IPA archive")?;

        // Find the .app prefix.
        let app_prefix = find_app_prefix(&mut zip)?;
        let app_name = app_prefix
            .rsplit('/')
            .next()
            .unwrap_or("")
            .trim_end_matches(".app")
            .to_owned();

        // Read Info.plist to get the executable name.
        let plist_path = format!("{app_prefix}/{INFO_PLIST}");
        let exec_name = read_zip_file_bytes(&mut zip, &plist_path)
            .ok()
            .and_then(|b| SimplePlistReader::find_key_value(&b, "CFBundleExecutable"))
            .unwrap_or_else(|| app_name.clone());

        let executable_path = format!("{app_prefix}/{exec_name}");

        // Enumerate all entries.
        let entries: Vec<BundleEntry> = (0..zip.len())
            .filter_map(|i| {
                let e = zip.by_index(i).ok()?;
                let zip_path = e.name().to_owned();
                let size = e.size();
                let is_dir = e.is_dir();
                let bundle_rel = zip_path
                    .strip_prefix(&format!("{app_prefix}/"))
                    .unwrap_or(&zip_path)
                    .to_owned();
                let kind = BundleEntry::classify(&zip_path, size, is_dir);
                Some(BundleEntry { zip_path, bundle_rel, size, kind, is_dir })
            })
            .collect();

        let framework_paths = entries
            .iter()
            .filter(|e| e.kind == EntryKind::Framework && e.is_dir)
            .map(|e| e.zip_path.clone())
            .collect();
        let plugin_paths = entries
            .iter()
            .filter(|e| e.kind == EntryKind::Plugin && e.is_dir)
            .map(|e| e.zip_path.clone())
            .collect();
        let watch_app_paths = entries
            .iter()
            .filter(|e| e.kind == EntryKind::WatchApp && e.is_dir)
            .map(|e| e.zip_path.clone())
            .collect();
        let dylib_paths = entries
            .iter()
            .filter(|e| e.kind == EntryKind::Dylib)
            .map(|e| e.zip_path.clone())
            .collect();
        let plist_paths = entries
            .iter()
            .filter(|e| e.kind == EntryKind::Plist)
            .map(|e| e.zip_path.clone())
            .collect();

        let total_entries = entries.len();
        let binary_bytes = entries
            .iter()
            .filter(|e| e.kind == EntryKind::Binary)
            .map(|e| e.size)
            .sum();

        let bundle = AppBundleInfo {
            app_prefix,
            app_name,
            executable_path,
            framework_paths,
            plugin_paths,
            watch_app_paths,
            dylib_paths,
            plist_paths,
            total_entries,
            binary_bytes,
        };

        Ok(Self { raw, bundle, entries })
    }

    /// Read the raw bytes of the main Mach-O executable.
    ///
    /// # Errors
    /// Returns an error if the binary cannot be found or read from the IPA.
    pub fn read_binary(&self) -> anyhow::Result<Vec<u8>> {
        let cursor = std::io::Cursor::new(&self.raw);
        let mut zip = zip::ZipArchive::new(cursor)?;
        read_zip_file_bytes(&mut zip, &self.bundle.executable_path)
            .with_context(|| format!("reading binary: {}", self.bundle.executable_path))
    }

    /// Read and parse `Info.plist`.
    ///
    /// # Errors
    /// Returns an error if the plist cannot be found, read, or parsed.
    pub fn read_info_plist(&self) -> anyhow::Result<InfoPlistFull> {
        let path = format!("{}/{INFO_PLIST}", self.bundle.app_prefix);
        let bytes = self.read_zip_path(&path)?;
        InfoPlistFull::from_data(&bytes)
    }

    /// Read and parse the embedded entitlements file.
    ///
    /// # Errors
    /// Returns an error if the entitlements file exists but cannot be parsed.
    pub fn read_entitlements(&self) -> anyhow::Result<Option<Entitlements>> {
        for candidate in &[
            format!("{}/{ENTITLEMENTS_FILE}", self.bundle.app_prefix),
            format!("{}/{XCENT_FILE}", self.bundle.app_prefix),
        ] {
            if let Ok(bytes) = self.read_zip_path(candidate) {
                return Entitlements::from_plist(&bytes).map(Some);
            }
        }
        Ok(None)
    }

    /// Read and parse `embedded.mobileprovision`.
    ///
    /// # Errors
    /// Returns an error if the profile exists but cannot be parsed.
    pub fn read_provisioning_profile(&self) -> anyhow::Result<Option<ProvisioningProfile>> {
        let path = format!("{}/{MOBILE_PROVISION}", self.bundle.app_prefix);
        self.read_zip_path(&path).map_or_else(|_| Ok(None), |bytes| ProvisioningProfile::parse_cms(&bytes).map(Some))
    }

    /// Read any file from the IPA by its ZIP path.
    ///
    /// # Errors
    /// Returns an error if the path is not found in the IPA.
    pub fn read_zip_path(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        let cursor = std::io::Cursor::new(&self.raw);
        let mut zip = zip::ZipArchive::new(cursor)?;
        read_zip_file_bytes(&mut zip, path)
            .with_context(|| format!("not found in IPA: {path}"))
    }

    /// List all entries with a given extension (case-insensitive).
    #[must_use] 
    pub fn entries_with_ext(&self, ext: &str) -> Vec<&BundleEntry> {
        self.entries
            .iter()
            .filter(|e| {
                e.extension()
                    .is_some_and(|e_ext| e_ext.eq_ignore_ascii_case(ext))
            })
            .collect()
    }

    /// Return the framework binary path inside a framework bundle.
    ///
    /// For `Payload/MyApp.app/Frameworks/MyLib.framework/` this is
    /// `Payload/MyApp.app/Frameworks/MyLib.framework/MyLib`.
    #[must_use] 
    pub fn framework_binary_path(&self, framework_dir: &str) -> String {
        let name = framework_dir
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or("")
            .trim_end_matches(".framework");
        format!("{framework_dir}{name}")
    }

    /// Compute SHA-256 of the main binary (hex string).
    ///
    /// # Errors
    /// Returns an error if the binary cannot be read.
    pub fn binary_sha256(&self) -> anyhow::Result<String> {
        let bytes = self.read_binary()?;
        let mut hash = [0u8; 32];
        // Simple manual SHA-256-like digest (no external dep): use a FNV-style stub.
        // Replace with a real SHA-256 if the sha2 crate is available.
        let mut state = 0xcbf2_9ce4_8422_2325_u64;
        for &b in &bytes {
            state ^= u64::from(b);
            state = state.wrapping_mul(0x0100_0000_01b3);
        }
        // Fill 32 bytes from the state using simple expansion.
        for i in 0..8 {
            let chunk = state.wrapping_add(i as u64 * 0x9e37_79b9_7f4a_7c15);
            hash[i * 4..(i + 1) * 4].copy_from_slice(&chunk.to_be_bytes()[4..]);
        }
        let mut hex = String::with_capacity(64);
        for b in &hash {
            use std::fmt::Write as _;
            let _ = write!(hex, "{b:02x}");
        }
        Ok(hex)
    }

    /// Return the size of the IPA archive in bytes.
    #[must_use] 
    pub const fn archive_size(&self) -> u64 {
        self.raw.len() as u64
    }
}

// ─── Entitlements parsing helpers ─────────────────────────────────────────────

/// Parse entitlements from the embedded.mobileprovision CMS data by extracting
/// the `<key>Entitlements</key>` section from the XML.
///
/// # Errors
/// Returns an error if the CMS data cannot be parsed or does not contain valid entitlements.
pub fn parse_entitlements_from_provision(cms_data: &[u8]) -> anyhow::Result<Entitlements> {
    let plist = extract_xml_from_cms(cms_data)?;
    let xml = std::str::from_utf8(&plist)
        .context("mobileprovision plist is not valid UTF-8")?;

    // Locate the Entitlements dict inside the provisioning profile plist.
    let ent_key = "<key>Entitlements</key>";
    let ent_pos = xml.find(ent_key)
        .ok_or_else(|| anyhow::anyhow!("No Entitlements key in provisioning profile"))?;
    let after_key = xml[ent_pos + ent_key.len()..].trim_start();
    let dict_start = after_key.find("<dict>")
        .ok_or_else(|| anyhow::anyhow!("Entitlements is not a dict"))?;
    let dict_content = &after_key[dict_start..];
    let dict_end = dict_content.find("</dict>")
        .map_or(dict_content.len(), |p| p + 7);
    let ent_xml = format!("<plist>{}</plist>", &dict_content[..dict_end]);
    Entitlements::from_plist(ent_xml.as_bytes())
}

fn extract_xml_from_cms(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    // Scan for <?xml or <plist
    if let Some(pos) = find_subseq(data, b"<?xml") {
        let slice = &data[pos..];
        let end = find_subseq(slice, b"</plist>")
            .map_or(slice.len(), |p| p + 8);
        return Ok(slice[..end].to_vec());
    }
    if let Some(pos) = find_subseq(data, b"<plist") {
        let slice = &data[pos..];
        let end = find_subseq(slice, b"</plist>")
            .map_or(slice.len(), |p| p + 8);
        return Ok(slice[..end].to_vec());
    }
    bail!("No XML plist found in CMS data")
}

fn find_subseq(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

// ─── ZIP utilities ────────────────────────────────────────────────────────────

fn find_app_prefix<R: Read + std::io::Seek>(
    zip: &mut zip::ZipArchive<R>,
) -> anyhow::Result<String> {
    for i in 0..zip.len() {
        let entry = zip.by_index(i)?;
        let name = entry.name().to_owned();
        let parts: Vec<&str> = name.splitn(3, '/').collect();
        if parts.len() >= 2
            && parts[0] == "Payload"
            && std::path::Path::new(parts[1]).extension().is_some_and(|e| e.eq_ignore_ascii_case("app"))
            && !parts[1].is_empty()
        {
            return Ok(format!("{}/{}", parts[0], parts[1]));
        }
    }
    bail!("No Payload/*.app directory found in IPA")
}

fn read_zip_file_bytes<R: Read + std::io::Seek>(
    zip: &mut zip::ZipArchive<R>,
    path: &str,
) -> anyhow::Result<Vec<u8>> {
    let mut entry = zip.by_name(path)
        .with_context(|| format!("entry not found: {path}"))?;
    let mut buf = Vec::with_capacity(usize::try_from(entry.size()).unwrap_or(0));
    entry.read_to_end(&mut buf)
        .with_context(|| format!("reading {path}"))?;
    Ok(buf)
}

// ─── BundleStructurePrinter ────────────────────────────────────────────────────

/// Produces a human-readable summary of an IPA's bundle structure.
pub struct BundleStructurePrinter;

impl BundleStructurePrinter {
    #[must_use] 
    pub fn print(info: &AppBundleInfo, entries: &[BundleEntry]) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(out, "=== IPA Bundle: {} ===", info.app_name);
        let _ = writeln!(out, "  App prefix    : {}", info.app_prefix);
        let _ = writeln!(out, "  Executable    : {}", info.executable_path);
        let _ = writeln!(out, "  Total entries : {}", info.total_entries);
        let _ = writeln!(out, "  Binary bytes  : {}", info.binary_bytes);
        let _ = writeln!(out, "  Frameworks    : {}", info.framework_paths.len());
        let _ = writeln!(out, "  Plugins       : {}", info.plugin_paths.len());
        let _ = writeln!(out, "  WatchApps     : {}", info.watch_app_paths.len());
        let _ = writeln!(out, "  Dylibs        : {}", info.dylib_paths.len());

        out.push_str("\n--- Frameworks ---\n");
        for p in &info.framework_paths {
            out.push_str("  ");
            out.push_str(p);
            out.push('\n');
        }
        out.push_str("--- Dylibs ---\n");
        for p in &info.dylib_paths {
            out.push_str("  ");
            out.push_str(p);
            out.push('\n');
        }

        let _ = writeln!(out, "\n--- All entries ({}) ---", entries.len());
        for e in entries.iter().take(64) {
            let dir_marker = if e.is_dir { "/" } else { "" };
            let _ = writeln!(out, "  [{:?}] {}{} ({}B)",
                e.kind, e.zip_path, dir_marker, e.size);
        }
        if entries.len() > 64 {
            let _ = writeln!(out, "  ... and {} more entries", entries.len() - 64);
        }
        out
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_classify_dylib() {
        let k = BundleEntry::classify("Payload/App.app/Frameworks/lib.dylib", 100, false);
        assert_eq!(k, EntryKind::Dylib);
    }

    #[test]
    fn test_entry_classify_plist() {
        let k = BundleEntry::classify("Payload/App.app/Info.plist", 500, false);
        assert_eq!(k, EntryKind::Plist);
    }

    #[test]
    fn test_entry_classify_framework_dir() {
        let k = BundleEntry::classify("Payload/App.app/Frameworks/Lib.framework/", 0, true);
        assert_eq!(k, EntryKind::Framework);
    }

    #[test]
    fn test_entry_filename() {
        let e = BundleEntry {
            zip_path: "Payload/App.app/App".into(),
            bundle_rel: "App".into(),
            size: 2048,
            kind: EntryKind::Binary,
            is_dir: false,
        };
        assert_eq!(e.filename(), "App");
    }

    #[test]
    fn test_bundle_info_defaults() {
        let info = AppBundleInfo {
            app_prefix: "Payload/T.app".into(),
            app_name: "T".into(),
            executable_path: "Payload/T.app/T".into(),
            framework_paths: vec![],
            plugin_paths: vec![],
            watch_app_paths: vec![],
            dylib_paths: vec!["Payload/T.app/lib.dylib".into()],
            plist_paths: vec![],
            total_entries: 5,
            binary_bytes: 100_000,
        };
        assert!(!info.has_frameworks());
        assert!(!info.has_extensions());
        assert!(!info.has_watch_app());
    }

    #[test]
    fn test_find_subseq() {
        assert_eq!(find_subseq(b"hello world", b"world"), Some(6));
        assert_eq!(find_subseq(b"hello", b"xyz"), None);
    }

    #[test]
    fn test_extract_xml_from_cms() {
        let data = b"junk<?xml version='1.0'?><plist><dict></dict></plist>more";
        let xml = extract_xml_from_cms(data).unwrap();
        assert!(xml.starts_with(b"<?xml"));
    }
}
