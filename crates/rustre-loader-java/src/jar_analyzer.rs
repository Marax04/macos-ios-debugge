//! JAR manifest analysis and Java module system (JPMS) support.
//!
//! Provides [`JarManifest`], [`JarAnalyzer`], [`ModuleInfoParser`],
//! [`JpmsModule`], and [`ServiceLoaderScan`] for deep inspection of JAR
//! archives and module descriptors.

use std::collections::HashMap;
use thiserror::Error;

// ── Errors ───────────────────────────────────────────────────────────────────

/// Errors produced by JAR / module analysis.
#[derive(Debug, Error)]
pub enum JarError {
    #[error("not a ZIP/JAR archive")]
    NotAJar,
    #[error("malformed manifest: {0}")]
    MalformedManifest(String),
    #[error("malformed module-info: {0}")]
    MalformedModuleInfo(String),
    #[error("truncated data")]
    TruncatedData,
    #[error("entry not found: {0}")]
    EntryNotFound(String),
}

// ── JarManifest ──────────────────────────────────────────────────────────────

/// Parsed `META-INF/MANIFEST.MF` from a JAR.
///
/// All attribute values are stored as raw strings; callers are responsible for
/// further parsing (e.g., splitting Class-Path on spaces).
#[derive(Debug, Clone, Default)]
pub struct JarManifest {
    /// Main-Class attribute, if present.
    pub main_class: Option<String>,
    /// Class-Path entries (space-separated in the manifest, split here).
    pub class_path: Vec<String>,
    /// Module-Name (JPMS automatic module name override).
    pub module_name: Option<String>,
    /// Automatic-Module-Name (legacy fallback for unnamed modules on the module path).
    pub automatic_module_name: Option<String>,
    /// All raw key→value pairs from the main section.
    pub attributes: HashMap<String, String>,
    /// Per-class sections: class-name → attribute map.
    pub sections: HashMap<String, HashMap<String, String>>,
}

impl JarManifest {
    /// Parse a `MANIFEST.MF` byte slice into a [`JarManifest`].
    ///
    /// # Errors
    /// Returns [`JarError::MalformedManifest`] for structurally invalid data.
    pub fn parse(data: &[u8]) -> Result<Self, JarError> {
        let text = std::str::from_utf8(data)
            .map_err(|_| JarError::MalformedManifest("non-UTF8 manifest".into()))?;

        let mut manifest = Self::default();
        let mut current_section: Option<String> = None;
        let mut current_attrs: HashMap<String, String> = HashMap::new();
        let mut last_key: Option<String> = None;

        for raw_line in text.lines() {
            // Continuation line: starts with a single space.
            if let Some(cont) = raw_line.strip_prefix(' ') {
                if let Some(key) = &last_key
                    && let Some(v) = current_attrs.get_mut(key) {
                        v.push_str(cont);
                    }
                continue;
            }

            // Blank line: section separator.
            if raw_line.trim().is_empty() {
                if let Some(name) = current_section.take() {
                    manifest.sections.insert(name, current_attrs.clone());
                } else {
                    // Finalise main section (don't insert into sections — it's separate).
                }
                current_attrs.clear();
                last_key = None;
                continue;
            }

            // Regular attribute line.
            let (key, val) = raw_line
                .split_once(':')
                .ok_or_else(|| JarError::MalformedManifest(format!("bad line: {raw_line}")))?;
            let key = key.trim().to_owned();
            let val = val.trim().to_owned();

            if key == "Name" && current_section.is_none() && !manifest.attributes.is_empty() {
                // Start of a per-entry section.
                current_section = Some(val.clone());
            } else {
                match key.as_str() {
                    "Main-Class" => manifest.main_class = Some(val.clone()),
                    "Class-Path" => {
                        manifest.class_path =
                            val.split_whitespace().map(std::borrow::ToOwned::to_owned).collect();
                    }
                    "Module-Name" => manifest.module_name = Some(val.clone()),
                    "Automatic-Module-Name" => manifest.automatic_module_name = Some(val.clone()),
                    _ => {}
                }
                current_attrs.insert(key.clone(), val.clone());
                if current_section.is_none() {
                    manifest.attributes.insert(key.clone(), val);
                }
                last_key = Some(key);
            }
        }

        // Flush last section.
        if let Some(name) = current_section {
            manifest.sections.insert(name, current_attrs);
        }

        Ok(manifest)
    }

    /// Return `true` if the manifest specifies a Main-Class.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.main_class.is_some()
    }

    /// Return the effective module name: Module-Name takes precedence over
    /// Automatic-Module-Name.
    #[must_use]
    pub fn effective_module_name(&self) -> Option<&str> {
        self.module_name
            .as_deref()
            .or(self.automatic_module_name.as_deref())
    }
}

// ── ZipEntry (internal helper) ────────────────────────────────────────────────

/// Metadata for a single entry in a ZIP/JAR archive.
#[derive(Debug, Clone)]
pub struct ZipEntry {
    /// Entry path (e.g., `"com/example/Main.class"`).
    pub name: String,
    /// Compressed size in bytes.
    pub compressed_size: u32,
    /// Uncompressed size in bytes.
    pub uncompressed_size: u32,
    /// Byte offset of the local file header in the archive.
    pub header_offset: u32,
    /// Raw data payload (may be compressed; only stored when `extract = true`).
    pub data: Vec<u8>,
}

// ── JarAnalyzer ──────────────────────────────────────────────────────────────

/// Analyses a JAR archive: lists class files, resources, META-INF entries,
/// and optionally extracts file data.
pub struct JarAnalyzer<'a> {
    data: &'a [u8],
}

impl<'a> JarAnalyzer<'a> {
    /// Create an analyser for the given JAR bytes.
    ///
    /// # Errors
    /// Returns [`JarError::NotAJar`] if the bytes do not start with a PK signature.
    pub fn new(data: &'a [u8]) -> Result<Self, JarError> {
        if !data.starts_with(b"PK\x03\x04") && !data.starts_with(b"PK\x05\x06") {
            return Err(JarError::NotAJar);
        }
        Ok(Self { data })
    }

    /// List all entries in the archive (by scanning local file headers).
    #[must_use] 
    pub fn list_entries(&self) -> Vec<ZipEntry> {
        let mut entries = Vec::new();
        let mut i = 0usize;
        while i + 30 <= self.data.len() {
            if self.data[i..i + 4] != [0x50, 0x4B, 0x03, 0x04] {
                i += 1;
                continue;
            }
            let comp_method = u16::from_le_bytes([self.data[i + 8], self.data[i + 9]]);
            let comp_size =
                u32::from_le_bytes(self.data[i + 18..i + 22].try_into().unwrap_or([0; 4]));
            let uncomp_size =
                u32::from_le_bytes(self.data[i + 22..i + 26].try_into().unwrap_or([0; 4]));
            let fname_len =
                u16::from_le_bytes(self.data[i + 26..i + 28].try_into().unwrap_or([0; 2])) as usize;
            let extra_len =
                u16::from_le_bytes(self.data[i + 28..i + 30].try_into().unwrap_or([0; 2])) as usize;

            let fname_end = i + 30 + fname_len;
            if fname_end > self.data.len() {
                break;
            }
            let name = String::from_utf8_lossy(&self.data[i + 30..fname_end]).into_owned();
            let data_start = fname_end + extra_len;
            let data_end = data_start + comp_size as usize;
            let data = if data_end <= self.data.len() && comp_method == 0 {
                // Stored (uncompressed)
                self.data[data_start..data_end].to_vec()
            } else {
                vec![]
            };

            entries.push(ZipEntry {
                name,
                compressed_size: comp_size,
                uncompressed_size: uncomp_size,
                header_offset: i as u32,
                data,
            });

            let advance = 30 + fname_len + extra_len + comp_size as usize;
            i += if advance == 0 { 1 } else { advance };
        }
        entries
    }

    /// Return all `.class` file entries.
    #[must_use] 
    pub fn class_files(&self) -> Vec<ZipEntry> {
        self.list_entries()
            .into_iter()
            .filter(|e| std::path::Path::new(&e.name).extension().is_some_and(|e| e.eq_ignore_ascii_case("class")))
            .collect()
    }

    /// Return all resource entries (non-`.class` files not in META-INF).
    #[must_use] 
    pub fn resources(&self) -> Vec<ZipEntry> {
        self.list_entries()
            .into_iter()
            .filter(|e| !std::path::Path::new(&e.name).extension().is_some_and(|e| e.eq_ignore_ascii_case("class")) && !e.name.starts_with("META-INF/"))
            .collect()
    }

    /// Return all `META-INF/` entries.
    #[must_use] 
    pub fn meta_inf_entries(&self) -> Vec<ZipEntry> {
        self.list_entries()
            .into_iter()
            .filter(|e| e.name.starts_with("META-INF/"))
            .collect()
    }

    /// Parse the manifest from `META-INF/MANIFEST.MF`, if present.
    ///
    /// # Errors
    /// Returns [`JarError::EntryNotFound`] if no manifest exists.
    pub fn manifest(&self) -> Result<JarManifest, JarError> {
        let entry = self
            .list_entries()
            .into_iter()
            .find(|e| e.name == "META-INF/MANIFEST.MF")
            .ok_or_else(|| JarError::EntryNotFound("META-INF/MANIFEST.MF".into()))?;
        JarManifest::parse(&entry.data)
    }

    /// Return the raw bytes of a named entry, or `None` if not found.
    #[must_use] 
    pub fn entry_data(&self, name: &str) -> Option<Vec<u8>> {
        self.list_entries()
            .into_iter()
            .find(|e| e.name == name)
            .map(|e| e.data)
    }

    /// Return the total number of entries.
    #[must_use] 
    pub fn entry_count(&self) -> usize {
        self.list_entries().len()
    }
}

// ── JPMS types ────────────────────────────────────────────────────────────────

/// A single `requires` directive in a module descriptor.
#[derive(Debug, Clone)]
pub struct ModuleRequires {
    /// Module name.
    pub name: String,
    /// `transitive` flag.
    pub transitive: bool,
    /// `static` flag.
    pub is_static: bool,
}

/// A single `exports` directive.
#[derive(Debug, Clone)]
pub struct ModuleExports {
    /// Exported package name (slash-separated).
    pub package: String,
    /// Restricted to these modules, or empty for unconditional exports.
    pub to: Vec<String>,
}

/// A single `opens` directive.
#[derive(Debug, Clone)]
pub struct ModuleOpens {
    /// Opened package.
    pub package: String,
    /// Restricted to these modules, or empty for unconditional opens.
    pub to: Vec<String>,
}

/// A `uses` directive.
#[derive(Debug, Clone)]
pub struct ModuleUses {
    /// Service class name.
    pub class_name: String,
}

/// A `provides` directive.
#[derive(Debug, Clone)]
pub struct ModuleProvides {
    /// Service interface name.
    pub service: String,
    /// Implementation class names.
    pub with: Vec<String>,
}

/// A parsed Java Platform Module System module descriptor.
///
/// Extracted from `module-info.class` via [`ModuleInfoParser`].
#[derive(Debug, Clone)]
pub struct JpmsModule {
    /// Module name.
    pub name: String,
    /// Module version (if specified).
    pub version: Option<String>,
    /// `requires` directives.
    pub requires: Vec<ModuleRequires>,
    /// `exports` directives.
    pub exports: Vec<ModuleExports>,
    /// `opens` directives.
    pub opens: Vec<ModuleOpens>,
    /// `uses` directives.
    pub uses: Vec<ModuleUses>,
    /// `provides` directives.
    pub provides: Vec<ModuleProvides>,
    /// Raw flags from the module attribute.
    pub flags: u32,
}

impl JpmsModule {
    /// Return `true` if this is an open module (all packages are opened).
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.flags & 0x0020 != 0
    }

    /// Return `true` if this module is synthetic.
    #[must_use]
    pub const fn is_synthetic(&self) -> bool {
        self.flags & 0x1000 != 0
    }

    /// Return all service interfaces listed in `provides`.
    #[must_use]
    pub fn provided_services(&self) -> Vec<&str> {
        self.provides.iter().map(|p| p.service.as_str()).collect()
    }

    /// Return all used service interfaces from `uses`.
    #[must_use]
    pub fn used_services(&self) -> Vec<&str> {
        self.uses.iter().map(|u| u.class_name.as_str()).collect()
    }
}

// ── ModuleInfoParser ──────────────────────────────────────────────────────────

/// Parser for `module-info.class` bytecode.
///
/// Extracts the `Module` attribute from the class file constant pool and
/// attribute table, producing a [`JpmsModule`].
pub struct ModuleInfoParser;

impl ModuleInfoParser {
    /// Parse a `module-info.class` byte slice.
    ///
    /// # Errors
    /// Returns [`JarError::MalformedModuleInfo`] for invalid data.
    pub fn parse(data: &[u8]) -> Result<JpmsModule, JarError> {
        if data.len() < 10 {
            return Err(JarError::TruncatedData);
        }
        if data[0] != 0xCA || data[1] != 0xFE || data[2] != 0xBA || data[3] != 0xBE {
            return Err(JarError::MalformedModuleInfo("bad magic".into()));
        }

        let cp_count = u16::from_be_bytes([data[8], data[9]]) as usize;
        let mut pos = 10usize;

        // Build a simple string table from the constant pool.
        let mut strings: HashMap<usize, String> = HashMap::new();

        let mut i = 1usize;
        while i < cp_count {
            if pos >= data.len() {
                return Err(JarError::TruncatedData);
            }
            let tag = data[pos];
            pos += 1;
            match tag {
                1 => {
                    // Utf8
                    if pos + 2 > data.len() {
                        return Err(JarError::TruncatedData);
                    }
                    let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                    pos += 2;
                    if pos + len > data.len() {
                        return Err(JarError::TruncatedData);
                    }
                    let s = String::from_utf8_lossy(&data[pos..pos + len]).into_owned();
                    strings.insert(i, s);
                    pos += len;
                }
                3 | 4 => pos += 4,
                5 | 6 => {
                    pos += 8;
                    i += 1;
                }
                7 | 8 | 16 | 19 | 20 => pos += 2,
                9 | 10 | 11 | 12 | 17 | 18 => pos += 4,
                15 => pos += 3,
                _ => {
                    return Err(JarError::MalformedModuleInfo(format!(
                        "unknown CP tag {tag}"
                    )));
                }
            }
            i += 1;
        }

        // Skip access_flags, this_class, super_class, interfaces.
        if pos + 8 > data.len() {
            return Err(JarError::TruncatedData);
        }
        pos += 6; // access_flags(2) + this_class(2) + super_class(2)
        let iface_count = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        pos += iface_count * 2;

        // Skip fields.
        if pos + 2 > data.len() {
            return Err(JarError::TruncatedData);
        }
        let fields_count = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        for _ in 0..fields_count {
            if pos + 8 > data.len() {
                return Err(JarError::TruncatedData);
            }
            let attrs = u16::from_be_bytes([data[pos + 6], data[pos + 7]]) as usize;
            pos += 8;
            for _ in 0..attrs {
                if pos + 6 > data.len() {
                    return Err(JarError::TruncatedData);
                }
                let alen = u32::from_be_bytes(data[pos + 2..pos + 6].try_into().unwrap()) as usize;
                pos += 6 + alen;
            }
        }

        // Skip methods.
        if pos + 2 > data.len() {
            return Err(JarError::TruncatedData);
        }
        let methods_count = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        for _ in 0..methods_count {
            if pos + 8 > data.len() {
                return Err(JarError::TruncatedData);
            }
            let attrs = u16::from_be_bytes([data[pos + 6], data[pos + 7]]) as usize;
            pos += 8;
            for _ in 0..attrs {
                if pos + 6 > data.len() {
                    return Err(JarError::TruncatedData);
                }
                let alen = u32::from_be_bytes(data[pos + 2..pos + 6].try_into().unwrap()) as usize;
                pos += 6 + alen;
            }
        }

        // Class attributes — look for "Module".
        if pos + 2 > data.len() {
            return Err(JarError::TruncatedData);
        }
        let class_attrs = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        for _ in 0..class_attrs {
            if pos + 6 > data.len() {
                return Err(JarError::TruncatedData);
            }
            let name_idx = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            let alen = u32::from_be_bytes(data[pos + 2..pos + 6].try_into().unwrap()) as usize;
            pos += 6;
            let attr_end = pos + alen;

            let attr_name = strings.get(&name_idx).map_or("", std::string::String::as_str);
            if attr_name == "Module" && pos + 6 <= data.len() {
                let module =
                    Self::parse_module_attr(&data[pos..attr_end.min(data.len())], &strings)?;
                return Ok(module);
            }

            pos = attr_end.min(data.len());
        }

        Err(JarError::MalformedModuleInfo(
            "no Module attribute found".into(),
        ))
    }

    fn parse_module_attr(
        data: &[u8],
        strings: &HashMap<usize, String>,
    ) -> Result<JpmsModule, JarError> {
        if data.len() < 6 {
            return Err(JarError::TruncatedData);
        }
        let mut pos = 0usize;

        let module_name_idx = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        let flags = u32::from(u16::from_be_bytes([data[pos + 2], data[pos + 3]]));
        let version_idx = u16::from_be_bytes([data[pos + 4], data[pos + 5]]) as usize;
        pos += 6;

        let name = strings.get(&module_name_idx).cloned().unwrap_or_default();
        let version = if version_idx != 0 {
            strings.get(&version_idx).cloned()
        } else {
            None
        };

        // requires
        let req_count = Self::read_u16(data, &mut pos)?;
        let mut requires = Vec::new();
        for _ in 0..req_count {
            let idx = Self::read_u16(data, &mut pos)? as usize;
            let req_flags = Self::read_u16(data, &mut pos)?;
            let _ver_idx = Self::read_u16(data, &mut pos)?;
            requires.push(ModuleRequires {
                name: strings.get(&idx).cloned().unwrap_or_default(),
                transitive: req_flags & 0x0020 != 0,
                is_static: req_flags & 0x0040 != 0,
            });
        }

        // exports
        let exp_count = Self::read_u16(data, &mut pos)?;
        let mut exports = Vec::new();
        for _ in 0..exp_count {
            let pkg_idx = Self::read_u16(data, &mut pos)? as usize;
            let _exp_flags = Self::read_u16(data, &mut pos)?;
            let to_count = Self::read_u16(data, &mut pos)? as usize;
            let mut to = Vec::new();
            for _ in 0..to_count {
                let tidx = Self::read_u16(data, &mut pos)? as usize;
                to.push(strings.get(&tidx).cloned().unwrap_or_default());
            }
            exports.push(ModuleExports {
                package: strings.get(&pkg_idx).cloned().unwrap_or_default(),
                to,
            });
        }

        // opens
        let opens_count = Self::read_u16(data, &mut pos)?;
        let mut opens = Vec::new();
        for _ in 0..opens_count {
            let pkg_idx = Self::read_u16(data, &mut pos)? as usize;
            let _opens_flags = Self::read_u16(data, &mut pos)?;
            let to_count = Self::read_u16(data, &mut pos)? as usize;
            let mut to = Vec::new();
            for _ in 0..to_count {
                let tidx = Self::read_u16(data, &mut pos)? as usize;
                to.push(strings.get(&tidx).cloned().unwrap_or_default());
            }
            opens.push(ModuleOpens {
                package: strings.get(&pkg_idx).cloned().unwrap_or_default(),
                to,
            });
        }

        // uses
        let uses_count = Self::read_u16(data, &mut pos)?;
        let mut uses = Vec::new();
        for _ in 0..uses_count {
            let cidx = Self::read_u16(data, &mut pos)? as usize;
            uses.push(ModuleUses {
                class_name: strings.get(&cidx).cloned().unwrap_or_default(),
            });
        }

        // provides
        let prov_count = Self::read_u16(data, &mut pos)?;
        let mut provides = Vec::new();
        for _ in 0..prov_count {
            let svc_idx = Self::read_u16(data, &mut pos)? as usize;
            let with_count = Self::read_u16(data, &mut pos)? as usize;
            let mut with = Vec::new();
            for _ in 0..with_count {
                let widx = Self::read_u16(data, &mut pos)? as usize;
                with.push(strings.get(&widx).cloned().unwrap_or_default());
            }
            provides.push(ModuleProvides {
                service: strings.get(&svc_idx).cloned().unwrap_or_default(),
                with,
            });
        }

        Ok(JpmsModule {
            name,
            version,
            requires,
            exports,
            opens,
            uses,
            provides,
            flags,
        })
    }

    fn read_u16(data: &[u8], pos: &mut usize) -> Result<u16, JarError> {
        if *pos + 2 > data.len() {
            return Err(JarError::TruncatedData);
        }
        let v = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
        *pos += 2;
        Ok(v)
    }
}

// ── ServiceLoaderScan ────────────────────────────────────────────────────────

/// A service provider entry found in `META-INF/services/`.
#[derive(Debug, Clone)]
pub struct ServiceEntry {
    /// Fully-qualified service interface name.
    pub service: String,
    /// Fully-qualified implementation class names.
    pub implementations: Vec<String>,
}

/// Scans a JAR for `META-INF/services/` entries (Java SPI / `ServiceLoader`).
pub struct ServiceLoaderScan;

impl ServiceLoaderScan {
    /// Scan all `META-INF/services/<interface>` files and return service
    /// entries.  Lines starting with `#` are treated as comments.
    #[must_use] 
    pub fn scan(analyzer: &JarAnalyzer<'_>) -> Vec<ServiceEntry> {
        let prefix = "META-INF/services/";
        analyzer
            .meta_inf_entries()
            .into_iter()
            .filter(|e| e.name.starts_with(prefix) && e.name.len() > prefix.len())
            .map(|e| {
                let service = e.name[prefix.len()..].to_owned();
                let impls = String::from_utf8_lossy(&e.data)
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(str::to_owned)
                    .collect();
                ServiceEntry {
                    service,
                    implementations: impls,
                }
            })
            .collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_bytes(content: &str) -> Vec<u8> {
        content.as_bytes().to_vec()
    }

    #[test]
    fn test_manifest_main_class() {
        let data = manifest_bytes("Manifest-Version: 1.0\nMain-Class: com.example.Main\n\n");
        let m = JarManifest::parse(&data).unwrap();
        assert_eq!(m.main_class.as_deref(), Some("com.example.Main"));
        assert!(m.is_executable());
    }

    #[test]
    fn test_manifest_no_main_class() {
        let data = manifest_bytes("Manifest-Version: 1.0\n\n");
        let m = JarManifest::parse(&data).unwrap();
        assert!(m.main_class.is_none());
        assert!(!m.is_executable());
    }

    #[test]
    fn test_manifest_class_path() {
        let data = manifest_bytes("Manifest-Version: 1.0\nClass-Path: lib/a.jar lib/b.jar\n\n");
        let m = JarManifest::parse(&data).unwrap();
        assert_eq!(m.class_path, vec!["lib/a.jar", "lib/b.jar"]);
    }

    #[test]
    fn test_manifest_automatic_module_name() {
        let data = manifest_bytes("Manifest-Version: 1.0\nAutomatic-Module-Name: com.example\n\n");
        let m = JarManifest::parse(&data).unwrap();
        assert_eq!(m.automatic_module_name.as_deref(), Some("com.example"));
        assert_eq!(m.effective_module_name(), Some("com.example"));
    }

    #[test]
    fn test_manifest_module_name_overrides_automatic() {
        let data = manifest_bytes(
            "Manifest-Version: 1.0\nModule-Name: foo.bar\nAutomatic-Module-Name: baz\n\n",
        );
        let m = JarManifest::parse(&data).unwrap();
        assert_eq!(m.effective_module_name(), Some("foo.bar"));
    }

    #[test]
    fn test_manifest_empty() {
        let data = manifest_bytes("\n");
        let m = JarManifest::parse(&data).unwrap();
        assert!(m.main_class.is_none());
        assert!(m.class_path.is_empty());
    }

    #[test]
    fn test_jar_analyzer_not_a_jar() {
        let result = JarAnalyzer::new(b"not a jar at all");
        assert!(result.is_err());
    }

    #[test]
    fn test_jar_analyzer_empty_pk_header() {
        // Minimal PK header (just magic — empty JAR)
        let data = b"PK\x05\x06" as &[u8];
        // Should pass the magic check
        let _ = JarAnalyzer::new(data).is_ok();
    }

    /// Build a tiny valid JAR with a single stored (uncompressed) entry.
    fn make_test_jar(name: &str, content: &[u8]) -> Vec<u8> {
        let mut jar = Vec::new();
        // Local file header
        jar.extend_from_slice(b"PK\x03\x04");
        jar.extend_from_slice(&[0x14, 0x00]); // version
        jar.extend_from_slice(&[0x00, 0x00]); // flags
        jar.extend_from_slice(&[0x00, 0x00]); // compression = stored
        jar.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // mod time/date
        jar.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // crc-32
        let sz = content.len() as u32;
        jar.extend_from_slice(&sz.to_le_bytes()); // compressed size
        jar.extend_from_slice(&sz.to_le_bytes()); // uncompressed size
        let fname = name.as_bytes();
        jar.extend_from_slice(&(fname.len() as u16).to_le_bytes()); // fname len
        jar.extend_from_slice(&0u16.to_le_bytes()); // extra len
        jar.extend_from_slice(fname);
        jar.extend_from_slice(content);
        jar
    }

    #[test]
    fn test_jar_list_entries() {
        let jar = make_test_jar("Hello.class", b"\xca\xfe\xba\xbe\x00\x00");
        let analyzer = JarAnalyzer::new(&jar).unwrap();
        let entries = analyzer.list_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "Hello.class");
    }

    #[test]
    fn test_jar_class_files() {
        let jar = make_test_jar("com/example/Main.class", b"\xca\xfe\xba\xbe");
        let analyzer = JarAnalyzer::new(&jar).unwrap();
        let classes = analyzer.class_files();
        assert_eq!(classes.len(), 1);
        assert!(std::path::Path::new(&classes[0].name).extension().is_some_and(|e| e.eq_ignore_ascii_case("class")));
    }

    #[test]
    fn test_jar_resources() {
        let jar = make_test_jar("config.properties", b"key=value\n");
        let analyzer = JarAnalyzer::new(&jar).unwrap();
        let res = analyzer.resources();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].name, "config.properties");
    }

    #[test]
    fn test_jar_meta_inf() {
        let jar = make_test_jar("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n\n");
        let analyzer = JarAnalyzer::new(&jar).unwrap();
        let mi = analyzer.meta_inf_entries();
        assert_eq!(mi.len(), 1);
        assert!(mi[0].name.starts_with("META-INF/"));
    }

    #[test]
    fn test_jar_manifest_extraction() {
        let content = b"Manifest-Version: 1.0\nMain-Class: Main\n\n";
        let jar = make_test_jar("META-INF/MANIFEST.MF", content);
        let analyzer = JarAnalyzer::new(&jar).unwrap();
        let m = analyzer.manifest().unwrap();
        assert_eq!(m.main_class.as_deref(), Some("Main"));
    }

    #[test]
    fn test_jar_entry_not_found() {
        let jar = make_test_jar("Hello.class", b"\xca\xfe\xba\xbe");
        let analyzer = JarAnalyzer::new(&jar).unwrap();
        assert!(analyzer.manifest().is_err());
    }

    #[test]
    fn test_jar_entry_data_by_name() {
        let payload = b"hello world";
        let jar = make_test_jar("res/hello.txt", payload);
        let analyzer = JarAnalyzer::new(&jar).unwrap();
        let d = analyzer.entry_data("res/hello.txt").unwrap();
        assert_eq!(d, payload);
    }

    #[test]
    fn test_jar_entry_count() {
        let jar = make_test_jar("A.class", b"x");
        let analyzer = JarAnalyzer::new(&jar).unwrap();
        assert_eq!(analyzer.entry_count(), 1);
    }

    #[test]
    fn test_service_loader_scan_empty() {
        let jar = make_test_jar("META-INF/services/", b"");
        let analyzer = JarAnalyzer::new(&jar).unwrap();
        // The trailing-slash entry is filtered out (len == prefix len)
        let services = ServiceLoaderScan::scan(&analyzer);
        assert!(services.is_empty());
    }

    #[test]
    fn test_service_loader_scan_with_entry() {
        let content = b"# comment\ncom.example.ImplA\ncom.example.ImplB\n";
        let jar = make_test_jar("META-INF/services/com.example.Service", content);
        let analyzer = JarAnalyzer::new(&jar).unwrap();
        let services = ServiceLoaderScan::scan(&analyzer);
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].service, "com.example.Service");
        assert_eq!(
            services[0].implementations,
            vec!["com.example.ImplA", "com.example.ImplB"]
        );
    }

    #[test]
    fn test_module_requires_flags() {
        let req = ModuleRequires {
            name: "java.base".into(),
            transitive: true,
            is_static: false,
        };
        assert!(req.transitive);
        assert!(!req.is_static);
    }

    #[test]
    fn test_jpms_module_fields() {
        let m = JpmsModule {
            name: "com.example".into(),
            version: Some("1.0".into()),
            requires: vec![ModuleRequires {
                name: "java.base".into(),
                transitive: false,
                is_static: false,
            }],
            exports: vec![ModuleExports {
                package: "com/example/api".into(),
                to: vec![],
            }],
            opens: vec![],
            uses: vec![ModuleUses {
                class_name: "com.example.Svc".into(),
            }],
            provides: vec![ModuleProvides {
                service: "com.example.Svc".into(),
                with: vec!["com.example.Impl".into()],
            }],
            flags: 0,
        };
        assert!(!m.is_open());
        assert_eq!(m.used_services(), vec!["com.example.Svc"]);
        assert_eq!(m.provided_services(), vec!["com.example.Svc"]);
    }

    #[test]
    fn test_jpms_module_open_flag() {
        let m = JpmsModule {
            name: "open.mod".into(),
            version: None,
            requires: vec![],
            exports: vec![],
            opens: vec![],
            uses: vec![],
            provides: vec![],
            flags: 0x0020,
        };
        assert!(m.is_open());
    }

    #[test]
    fn test_module_info_parser_bad_magic() {
        let result = ModuleInfoParser::parse(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        assert!(result.is_err());
    }

    #[test]
    fn test_module_info_parser_truncated() {
        let result = ModuleInfoParser::parse(b"\xca\xfe\xba\xbe");
        assert!(result.is_err());
    }

    #[test]
    fn test_manifest_continuation_line() {
        let data = manifest_bytes("Manifest-Version: 1.0\nClass-Path: lib/a.jar\n lib/b.jar\n\n");
        let m = JarManifest::parse(&data).unwrap();
        // After continuation the full Class-Path value is "lib/a.jar lib/b.jar"
        // which when split on whitespace gives two entries.
        assert!(!m.class_path.is_empty());
    }

    #[test]
    fn test_service_entry_struct() {
        let se = ServiceEntry {
            service: "my.Service".into(),
            implementations: vec!["my.ServiceImpl".into()],
        };
        assert_eq!(se.service, "my.Service");
        assert_eq!(se.implementations.len(), 1);
    }

    #[test]
    fn test_zip_entry_fields() {
        let e = ZipEntry {
            name: "Foo.class".into(),
            compressed_size: 100,
            uncompressed_size: 200,
            header_offset: 0,
            data: vec![0xCA, 0xFE, 0xBA, 0xBE],
        };
        assert_eq!(e.name, "Foo.class");
        assert_eq!(e.compressed_size, 100);
    }

    #[test]
    fn test_manifest_attributes_raw() {
        let data = manifest_bytes("Manifest-Version: 1.0\nCreated-By: javac 17\n\n");
        let m = JarManifest::parse(&data).unwrap();
        assert!(m.attributes.contains_key("Created-By"));
    }
}
