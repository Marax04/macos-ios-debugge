//! JAR manifest (META-INF/MANIFEST.MF) parser and JAR metadata analyser.

use std::collections::HashMap;
use std::fmt;

// ── ManifestSection ───────────────────────────────────────────────────────────

/// A single section from a JAR manifest (RFC 822-style).
#[derive(Debug, Clone, Default)]
pub struct ManifestSection {
    /// Section name (None for the main section).
    pub name: Option<String>,
    /// All key-value attributes in insertion order, also indexed.
    pub attributes: HashMap<String, String>,
    pub attribute_order: Vec<String>,
}

impl ManifestSection {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }
    pub fn named(name: impl Into<String>) -> Self {
        Self { name: Some(name.into()), ..Self::default() }
    }
    #[must_use] 
    pub fn get(&self, key: &str) -> Option<&str> {
        self.attributes.get(&key.to_ascii_lowercase()).map(std::string::String::as_str)
    }
    pub fn insert(&mut self, key: String, value: String) {
        let k = key.to_ascii_lowercase();
        if !self.attributes.contains_key(&k) {
            self.attribute_order.push(k.clone());
        }
        self.attributes.insert(k, value);
    }
}

// ── Manifest ──────────────────────────────────────────────────────────────────

/// A parsed JAR manifest file.
#[derive(Debug, Clone, Default)]
pub struct Manifest {
    pub main_section: ManifestSection,
    pub named_sections: Vec<ManifestSection>,
}

impl Manifest {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn get_main_class(&self) -> Option<&str> {
        self.main_section.get("main-class")
    }

    #[must_use] 
    pub fn get_class_path(&self) -> Vec<String> {
        self.main_section
            .get("class-path")
            .map(|v| v.split_whitespace().map(std::string::ToString::to_string).collect())
            .unwrap_or_default()
    }

    #[must_use] 
    pub fn get_sealed(&self) -> bool {
        self.main_section
            .get("sealed")
            .is_some_and(|v| v.eq_ignore_ascii_case("true"))
    }

    #[must_use] 
    pub fn manifest_version(&self) -> Option<&str> {
        self.main_section.get("manifest-version")
    }

    #[must_use] 
    pub fn implementation_version(&self) -> Option<&str> {
        self.main_section.get("implementation-version")
    }
}

impl fmt::Display for Manifest {
    /// Render the manifest back to RFC 822 form (main section then named sections).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for key in &self.main_section.attribute_order {
            if let Some(value) = self.main_section.attributes.get(key) {
                writeln!(f, "{key}: {value}")?;
            }
        }
        for section in &self.named_sections {
            writeln!(f)?;
            if let Some(name) = &section.name {
                writeln!(f, "Name: {name}")?;
            }
            for key in &section.attribute_order {
                if let Some(value) = section.attributes.get(key) {
                    writeln!(f, "{key}: {value}")?;
                }
            }
        }
        Ok(())
    }
}

// ── ManifestEntry ─────────────────────────────────────────────────────────────

/// A known or custom manifest attribute entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestEntry {
    MainClass(String),
    ClassPath(Vec<String>),
    ImplementationVersion(String),
    SpecificationVersion(String),
    ManifestVersion(String),
    Custom(String, String),
}

// ── CertInfo ─────────────────────────────────────────────────────────────────

/// Certificate information parsed from a signature file.
#[derive(Debug, Clone)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub valid_from: String,
    pub valid_to: String,
    pub serial: String,
}

impl CertInfo {
    pub fn stub(subject: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            issuer: String::new(),
            valid_from: String::new(),
            valid_to: String::new(),
            serial: String::new(),
        }
    }
}

// ── SignatureFileEntry ────────────────────────────────────────────────────────

/// A digest entry from a .SF signature file.
#[derive(Debug, Clone)]
pub struct SfEntry {
    pub name: String,
    pub sha256_digest: Option<String>,
    pub sha1_digest: Option<String>,
}

// ── JarAnalysis ───────────────────────────────────────────────────────────────

/// High-level analysis of a JAR archive.
#[derive(Debug, Clone)]
pub struct JarAnalysis {
    pub manifest: Manifest,
    pub entry_count: u32,
    pub class_count: u32,
    pub resource_count: u32,
    pub signed: bool,
    pub certificates: Vec<CertInfo>,
    pub signature_files: Vec<String>,
    pub meta_inf_files: Vec<String>,
}

impl JarAnalysis {
    #[must_use] 
    pub const fn is_signed(&self) -> bool {
        self.signed
    }
    #[must_use] 
    pub fn main_class(&self) -> Option<&str> {
        self.manifest.get_main_class()
    }
}

// ── JarManifestParser ─────────────────────────────────────────────────────────

/// Parser for `META-INF/MANIFEST.MF` and related JAR metadata.
pub struct JarManifestParser;

impl JarManifestParser {
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }

    /// Parse a MANIFEST.MF byte slice (RFC 822-style format).
    ///
    /// Lines: `key: value\r\n`, continuation lines start with a single space,
    /// sections separated by blank lines.
    #[must_use] 
    pub fn parse_manifest(&self, data: &[u8]) -> Manifest {
        let text = String::from_utf8_lossy(data);
        self.parse_manifest_str(&text)
    }

    #[must_use] 
    pub fn parse_manifest_str(&self, text: &str) -> Manifest {
        let mut manifest = Manifest::new();
        let mut current_section: Option<ManifestSection> = Some(ManifestSection::new());
        let mut current_key: Option<String> = None;
        let mut current_value = String::new();

        let flush_attr =
            |key: &mut Option<String>, value: &mut String, section: &mut ManifestSection| {
                if let Some(k) = key.take() {
                    let v = std::mem::take(value);
                    section.insert(k, v);
                }
            };

        let lines: Vec<&str> = text.lines().collect();
        let mut i = 0;

        // Helper: is line a continuation (starts with single space)
        while i < lines.len() {
            let raw = lines[i];
            // Normalise: strip trailing CR if present (files may use CRLF or LF)
            let line = raw.trim_end_matches('\r');
            i += 1;

            if line.is_empty() {
                // End of section
                if let Some(ref mut sec) = current_section {
                    flush_attr(&mut current_key, &mut current_value, sec);
                }
                let sec = current_section.take().unwrap_or_default();
                if sec.name.is_none() {
                    manifest.main_section = sec;
                } else {
                    manifest.named_sections.push(sec);
                }
                current_section = Some(ManifestSection::new());
                continue;
            }

            if line.starts_with(' ') {
                // Continuation of previous value — preserve a whitespace
                // separator so space-separated values like Class-Path stay
                // split when re-tokenised.
                current_value.push(' ');
                current_value.push_str(&line[1..]);
                continue;
            }

            // New key: value pair
            if let Some(ref mut sec) = current_section {
                flush_attr(&mut current_key, &mut current_value, sec);
            }
            if let Some(colon_pos) = line.find(':') {
                let k = line[..colon_pos].trim().to_string();
                let v = line[colon_pos + 1..].trim_start_matches(' ').to_string();
                if let Some(ref sec) = current_section {
                    let _ = sec; // borrow check dance
                }
                // Handle "Name" entry which starts a new named section
                if k.eq_ignore_ascii_case("Name") {
                    // Flush and create named section
                    if let Some(ref mut sec) = current_section {
                        flush_attr(&mut current_key, &mut current_value, sec);
                    }
                    let old = current_section.replace(ManifestSection::named(v.clone()));
                    if let Some(sec) = old {
                        if sec.name.is_none() {
                            manifest.main_section = sec;
                        } else {
                            manifest.named_sections.push(sec);
                        }
                    }
                } else {
                    current_key = Some(k);
                    current_value = v;
                }
            }
        }
        // Flush final section
        if let Some(ref mut sec) = current_section {
            flush_attr(&mut current_key, &mut current_value, sec);
        }
        if let Some(sec) = current_section {
            if sec.name.is_none() && (!sec.attributes.is_empty() || manifest.main_section.attributes.is_empty()) {
                manifest.main_section = sec;
            } else if sec.name.is_some() {
                manifest.named_sections.push(sec);
            }
        }
        manifest
    }

    /// Parse a .SF signature file and return per-entry digests.
    #[must_use] 
    pub fn verify_signature_file(&self, sf_data: &[u8]) -> Vec<SfEntry> {
        let text = String::from_utf8_lossy(sf_data);
        let mut entries: Vec<SfEntry> = Vec::new();
        let mut current_name: Option<String> = None;
        let mut current_sha256: Option<String> = None;
        let mut current_sha1: Option<String> = None;

        for raw in text.lines() {
            let line = raw.trim_end_matches('\r');
            if line.is_empty() {
                if let Some(name) = current_name.take() {
                    entries.push(SfEntry {
                        name,
                        sha256_digest: current_sha256.take(),
                        sha1_digest: current_sha1.take(),
                    });
                }
                continue;
            }
            if let Some(colon_pos) = line.find(':') {
                let k = line[..colon_pos].trim().to_ascii_lowercase();
                let v = line[colon_pos + 1..].trim_start_matches(' ').to_string();
                match k.as_str() {
                    "name" => { current_name = Some(v); }
                    "sha-256-digest" | "sha256-digest" => { current_sha256 = Some(v); }
                    "sha-1-digest" | "sha1-digest" => { current_sha1 = Some(v); }
                    _ => {}
                }
            }
        }
        if let Some(name) = current_name {
            entries.push(SfEntry { name, sha256_digest: current_sha256, sha1_digest: current_sha1 });
        }
        entries
    }

    /// Parse META-INF directory listing from a list of zip entry names.
    ///
    /// Returns (`manifest_found`, `sf_files`, `cert_files`, `other_files`).
    #[must_use] 
    pub fn parse_meta_inf(
        &self,
        entries: &[String],
    ) -> (bool, Vec<String>, Vec<String>, Vec<String>) {
        let mut manifest_found = false;
        let mut sf_files = Vec::new();
        let mut cert_files = Vec::new();
        let mut other_files = Vec::new();

        for entry in entries {
            let upper = entry.to_ascii_uppercase();
            if upper == "META-INF/MANIFEST.MF" || upper.ends_with("/MANIFEST.MF") {
                manifest_found = true;
            } else if upper.starts_with("META-INF/") {
                let fname = upper.rsplit('/').next().unwrap_or("");
                if fname.ends_with(".SF") {
                    sf_files.push(entry.clone());
                } else if fname.ends_with(".RSA") || fname.ends_with(".DSA") || fname.ends_with(".EC") {
                    cert_files.push(entry.clone());
                } else {
                    other_files.push(entry.clone());
                }
            }
        }
        (manifest_found, sf_files, cert_files, other_files)
    }

    /// Build a `JarAnalysis` from a manifest byte slice + a listing of all ZIP entries.
    #[must_use] 
    pub fn analyse(
        &self,
        manifest_data: &[u8],
        zip_entries: &[String],
        cert_stubs: Vec<CertInfo>,
    ) -> JarAnalysis {
        let manifest = self.parse_manifest(manifest_data);
        let mut class_count = 0u32;
        let mut resource_count = 0u32;
        for e in zip_entries {
            if e.ends_with(".class") {
                class_count += 1;
            } else if !e.ends_with('/') {
                resource_count += 1;
            }
        }
        let (_, sf_files, cert_files, meta_inf_other) = self.parse_meta_inf(zip_entries);
        let signed = !sf_files.is_empty() && !cert_files.is_empty();
        let mut meta_inf_files: Vec<String> = sf_files.iter().chain(cert_files.iter()).chain(meta_inf_other.iter()).cloned().collect();
        meta_inf_files.sort();

        JarAnalysis {
            manifest,
            entry_count: zip_entries.len() as u32,
            class_count,
            resource_count,
            signed,
            certificates: cert_stubs,
            signature_files: sf_files,
            meta_inf_files,
        }
    }

    /// Extract all known manifest entries from a manifest.
    #[must_use] 
    pub fn extract_entries(&self, manifest: &Manifest) -> Vec<ManifestEntry> {
        let mut out = Vec::new();
        if let Some(v) = manifest.main_section.get("main-class") {
            out.push(ManifestEntry::MainClass(v.to_string()));
        }
        if let Some(v) = manifest.main_section.get("class-path") {
            out.push(ManifestEntry::ClassPath(
                v.split_whitespace().map(std::string::ToString::to_string).collect(),
            ));
        }
        if let Some(v) = manifest.main_section.get("implementation-version") {
            out.push(ManifestEntry::ImplementationVersion(v.to_string()));
        }
        if let Some(v) = manifest.main_section.get("specification-version") {
            out.push(ManifestEntry::SpecificationVersion(v.to_string()));
        }
        if let Some(v) = manifest.main_section.get("manifest-version") {
            out.push(ManifestEntry::ManifestVersion(v.to_string()));
        }
        for key in &manifest.main_section.attribute_order {
            let already_handled = [
                "main-class", "class-path", "implementation-version",
                "specification-version", "manifest-version",
            ];
            if !already_handled.contains(&key.as_str())
                && let Some(v) = manifest.main_section.attributes.get(key) {
                    out.push(ManifestEntry::Custom(key.clone(), v.clone()));
                }
        }
        out
    }
}

impl Default for JarManifestParser {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE_MANIFEST: &str = "\
Manifest-Version: 1.0\r\n\
Main-Class: com.example.Main\r\n\
Class-Path: lib/a.jar lib/b.jar\r\n\
Sealed: true\r\n\
\r\n";

    const MULTI_SECTION: &str = "\
Manifest-Version: 1.0\r\n\
\r\n\
Name: com/example/Foo.class\r\n\
SHA-256-Digest: abc123\r\n\
\r\n";

    fn parser() -> JarManifestParser {
        JarManifestParser::new()
    }

    #[test]
    fn test_parse_manifest_version() {
        let m = parser().parse_manifest_str(SIMPLE_MANIFEST);
        assert_eq!(m.manifest_version(), Some("1.0"));
    }

    #[test]
    fn test_get_main_class() {
        let m = parser().parse_manifest_str(SIMPLE_MANIFEST);
        assert_eq!(m.get_main_class(), Some("com.example.Main"));
    }

    #[test]
    fn test_get_class_path() {
        let m = parser().parse_manifest_str(SIMPLE_MANIFEST);
        let cp = m.get_class_path();
        assert_eq!(cp.len(), 2);
        assert!(cp.contains(&"lib/a.jar".to_string()));
    }

    #[test]
    fn test_get_sealed() {
        let m = parser().parse_manifest_str(SIMPLE_MANIFEST);
        assert!(m.get_sealed());
    }

    #[test]
    fn test_not_sealed_by_default() {
        let m = parser().parse_manifest_str("Manifest-Version: 1.0\r\n\r\n");
        assert!(!m.get_sealed());
    }

    #[test]
    fn test_empty_manifest() {
        let m = parser().parse_manifest(b"");
        assert!(m.get_main_class().is_none());
        assert!(m.get_class_path().is_empty());
    }

    #[test]
    fn test_continuation_line() {
        let text = "Manifest-Version: 1.0\r\nClass-Path: a.jar\r\n b.jar\r\n\r\n";
        let m = parser().parse_manifest_str(text);
        let cp = m.get_class_path();
        assert_eq!(cp.len(), 2);
    }

    #[test]
    fn test_named_section() {
        let m = parser().parse_manifest_str(MULTI_SECTION);
        assert_eq!(m.named_sections.len(), 1);
        assert_eq!(m.named_sections[0].name.as_deref(), Some("com/example/Foo.class"));
    }

    #[test]
    fn test_named_section_attribute() {
        let m = parser().parse_manifest_str(MULTI_SECTION);
        let sec = &m.named_sections[0];
        assert_eq!(sec.get("sha-256-digest"), Some("abc123"));
    }

    #[test]
    fn test_parse_meta_inf_manifest() {
        let entries = vec!["META-INF/MANIFEST.MF".to_string(), "META-INF/CERT.RSA".to_string(), "META-INF/CERT.SF".to_string()];
        let (mf, sf, cert, _) = parser().parse_meta_inf(&entries);
        assert!(mf);
        assert_eq!(sf.len(), 1);
        assert_eq!(cert.len(), 1);
    }

    #[test]
    fn test_parse_meta_inf_no_manifest() {
        let entries: Vec<String> = vec!["com/example/Main.class".to_string()];
        let (mf, _, _, _) = parser().parse_meta_inf(&entries);
        assert!(!mf);
    }

    #[test]
    fn test_verify_sf_file() {
        let sf = "Name: com/example/Foo.class\r\nSHA-256-Digest: abc\r\n\r\n";
        let entries = parser().verify_signature_file(sf.as_bytes());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "com/example/Foo.class");
        assert_eq!(entries[0].sha256_digest.as_deref(), Some("abc"));
    }

    #[test]
    fn test_analyse_class_count() {
        let zip_entries = vec![
            "com/example/Main.class".to_string(),
            "com/example/Util.class".to_string(),
            "META-INF/MANIFEST.MF".to_string(),
            "resources/app.properties".to_string(),
        ];
        let analysis = parser().analyse(SIMPLE_MANIFEST.as_bytes(), &zip_entries, vec![]);
        assert_eq!(analysis.class_count, 2);
    }

    #[test]
    fn test_analyse_signed_jar() {
        let entries = vec![
            "META-INF/MANIFEST.MF".to_string(),
            "META-INF/CERT.SF".to_string(),
            "META-INF/CERT.RSA".to_string(),
        ];
        let analysis = parser().analyse(b"Manifest-Version: 1.0\r\n\r\n", &entries, vec![CertInfo::stub("CN=Test")]);
        assert!(analysis.is_signed());
        assert_eq!(analysis.certificates.len(), 1);
    }

    #[test]
    fn test_analyse_unsigned_jar() {
        let entries = vec!["META-INF/MANIFEST.MF".to_string()];
        let analysis = parser().analyse(b"Manifest-Version: 1.0\r\n\r\n", &entries, vec![]);
        assert!(!analysis.is_signed());
    }

    #[test]
    fn test_extract_entries_main_class() {
        let m = parser().parse_manifest_str(SIMPLE_MANIFEST);
        let entries = parser().extract_entries(&m);
        assert!(entries.iter().any(|e| matches!(e, ManifestEntry::MainClass(_))));
    }

    #[test]
    fn test_manifest_section_get_case_insensitive() {
        let mut sec = ManifestSection::new();
        sec.insert("Main-Class".to_string(), "com.example.Main".to_string());
        assert_eq!(sec.get("main-class"), Some("com.example.Main"));
        assert_eq!(sec.get("MAIN-CLASS"), Some("com.example.Main"));
    }

    #[test]
    fn test_manifest_entry_class_path_list() {
        let m = parser().parse_manifest_str(SIMPLE_MANIFEST);
        let entries = parser().extract_entries(&m);
        let cp = entries.iter().find_map(|e| {
            if let ManifestEntry::ClassPath(v) = e { Some(v) } else { None }
        });
        assert!(cp.is_some());
        assert_eq!(cp.unwrap().len(), 2);
    }

    // ── Extra edge-case coverage ────────────────────────────────────────────

    #[test]
    fn test_empty_bytes_parse_no_panic() {
        let m = parser().parse_manifest(&[]);
        assert!(m.main_section.attributes.is_empty());
        assert!(m.named_sections.is_empty());
    }

    #[test]
    fn test_invalid_utf8_bytes_handled() {
        // Invalid UTF-8 sequence — parser should not panic.
        let bytes = b"Manifest-Version: 1.0\r\n\xFF\xFE\xFD\r\n\r\n";
        let _ = parser().parse_manifest(bytes);
    }

    #[test]
    fn test_only_lf_line_endings() {
        // Manifests typically use CRLF but parser should also accept LF.
        let text = "Manifest-Version: 1.0\nMain-Class: a.B\n\n";
        let m = parser().parse_manifest_str(text);
        // Either it parses or it produces empty; just must not panic.
        let _ = m.get_main_class();
    }

    #[test]
    fn test_classpath_missing_returns_empty() {
        let m = parser().parse_manifest_str("Manifest-Version: 1.0\r\n\r\n");
        assert!(m.get_class_path().is_empty());
    }

    #[test]
    fn test_meta_inf_case_variants() {
        let entries = vec![
            "META-INF/MANIFEST.MF".to_string(),
            "META-INF/services/foo".to_string(),
        ];
        let (mf, _sf, _cert, _) = parser().parse_meta_inf(&entries);
        assert!(mf);
    }

    #[test]
    fn test_verify_sf_empty_input() {
        let entries = parser().verify_signature_file(&[]);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_manifest_section_get_missing() {
        let sec = ManifestSection::new();
        assert!(sec.get("anything").is_none());
    }

    #[test]
    fn test_analyse_empty_jar() {
        let analysis = parser().analyse(&[], &[], vec![]);
        assert_eq!(analysis.class_count, 0);
        assert!(!analysis.is_signed());
    }
}
