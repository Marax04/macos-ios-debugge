//! JAR loading: ZIP extraction, manifest parsing, classpath resolution,
//! multi-release JARs, module-info detection, and inter-class dependency graph.

use std::collections::{HashMap, HashSet, VecDeque};
use thiserror::Error;
use crate::class_parser_full::{ClassFile, ClassParseError};

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum JarError {
    #[error("not a ZIP/JAR archive (bad magic at offset 0)")]
    NotZip,
    #[error("malformed ZIP: {0}")]
    MalformedZip(String),
    #[error("class parse error in '{0}': {1}")]
    ClassParse(String, #[source] ClassParseError),
    #[error("manifest parse error: {0}")]
    ManifestParse(String),
    #[error("I/O error: {0}")]
    Io(String),
}

// ── Minimal ZIP parser ────────────────────────────────────────────────────────
// We implement enough of the ZIP spec to list + extract entries without
// pulling in an external dependency.

const ZIP_LOCAL_MAGIC:   u32 = 0x0403_4B50;
const ZIP_CD_MAGIC:      u32 = 0x0201_4B50;
const ZIP_EOCD_MAGIC:    u32 = 0x0605_4B50;
const ZIP_EOCD64_MAGIC:  u32 = 0x0606_4B50;

fn le_u16(b: &[u8], off: usize) -> u16 {
    u16::from(b[off]) | (u16::from(b[off + 1]) << 8)
}
fn le_u32(b: &[u8], off: usize) -> u32 {
    u32::from(b[off])
        | (u32::from(b[off + 1]) << 8)
        | (u32::from(b[off + 2]) << 16)
        | (u32::from(b[off + 3]) << 24)
}
fn le_u64(b: &[u8], off: usize) -> u64 {
    u64::from(le_u32(b, off)) | (u64::from(le_u32(b, off + 4)) << 32)
}

#[derive(Debug, Clone)]
struct CentralDirEntry {
    name:             String,
    compressed_size:  u64,
    uncompressed_size:u64,
    local_header_off: u64,
    compression:      u16,
    crc32:            u32,
}

fn find_eocd(data: &[u8]) -> Result<usize, JarError> {
    // Scan backwards for EOCD signature
    if data.len() < 22 {
        return Err(JarError::NotZip);
    }
    let start = data.len() - 22;
    for i in (0..=start).rev() {
        if data.len() >= i + 4 && le_u32(data, i) == ZIP_EOCD_MAGIC {
            return Ok(i);
        }
    }
    Err(JarError::MalformedZip("EOCD not found".into()))
}

fn parse_central_directory(data: &[u8]) -> Result<Vec<CentralDirEntry>, JarError> {
    let eocd_off = find_eocd(data)?;
    if eocd_off + 22 > data.len() {
        return Err(JarError::MalformedZip("EOCD truncated".into()));
    }

    let mut cd_offset = u64::from(le_u32(data, eocd_off + 16));
    let mut cd_count  = u64::from(le_u16(data, eocd_off + 10));

    // Check for ZIP64 locator just before EOCD
    if eocd_off >= 20 && le_u32(data, eocd_off - 20) == 0x0706_4B50 {
        let z64_off = le_u64(data, eocd_off - 12) as usize;
        if z64_off + 56 <= data.len() && le_u32(data, z64_off) == ZIP_EOCD64_MAGIC {
            cd_count  = le_u64(data, z64_off + 32);
            cd_offset = le_u64(data, z64_off + 48);
        }
    }

    // Cap pre-allocation to avoid OOM from a crafted ZIP64 cd_count.
    // Each CD entry is at least 46 bytes, so we can't have more entries than data.len()/46.
    let max_entries = data.len() / 46;
    let prealloc = (cd_count as usize).min(max_entries);
    let mut entries = Vec::with_capacity(prealloc);
    let mut pos = cd_offset as usize;

    for _ in 0..cd_count {
        if pos + 46 > data.len() { break; }
        if le_u32(data, pos) != ZIP_CD_MAGIC {
            return Err(JarError::MalformedZip(format!("bad CD magic at {pos}")));
        }
        let compression      = le_u16(data, pos + 10);
        let crc32            = le_u32(data, pos + 16);
        let mut comp_size    = u64::from(le_u32(data, pos + 20));
        let mut uncomp_size  = u64::from(le_u32(data, pos + 24));
        let name_len         = le_u16(data, pos + 28) as usize;
        let extra_len        = le_u16(data, pos + 30) as usize;
        let comment_len      = le_u16(data, pos + 32) as usize;
        let mut lh_offset    = u64::from(le_u32(data, pos + 42));

        let name_bytes = data.get(pos + 46..pos + 46 + name_len)
            .ok_or_else(|| JarError::MalformedZip("CD name truncated".into()))?;
        let name = String::from_utf8_lossy(name_bytes).into_owned();

        // Parse ZIP64 extra field
        let extra_start = pos + 46 + name_len;
        let extra_end   = extra_start + extra_len;
        if extra_end <= data.len() {
            let extra = &data[extra_start..extra_end];
            let mut ep = 0usize;
            while ep + 4 <= extra.len() {
                let tag  = le_u16(extra, ep);
                let size = le_u16(extra, ep + 2) as usize;
                ep += 4;
                if tag == 0x0001 && ep + size <= extra.len() {
                    let mut fp = ep;
                    if uncomp_size == 0xFFFF_FFFF && fp + 8 <= ep + size {
                        uncomp_size = le_u64(extra, fp); fp += 8;
                    }
                    if comp_size == 0xFFFF_FFFF && fp + 8 <= ep + size {
                        comp_size = le_u64(extra, fp); fp += 8;
                    }
                    if lh_offset == 0xFFFF_FFFF && fp + 8 <= ep + size {
                        lh_offset = le_u64(extra, fp);
                    }
                }
                ep += size;
            }
        }

        entries.push(CentralDirEntry {
            name,
            compressed_size: comp_size,
            uncompressed_size: uncomp_size,
            local_header_off: lh_offset,
            compression,
            crc32,
        });

        pos += 46 + name_len + extra_len + comment_len;
    }

    Ok(entries)
}

/// Extract raw bytes for a single entry given the whole archive slice.
fn extract_entry(data: &[u8], entry: &CentralDirEntry) -> Result<Vec<u8>, JarError> {
    let lh = entry.local_header_off as usize;
    if lh + 30 > data.len() {
        return Err(JarError::MalformedZip(format!("LH offset {lh} out of range")));
    }
    if le_u32(data, lh) != ZIP_LOCAL_MAGIC {
        return Err(JarError::MalformedZip(format!("bad LH magic at {lh}")));
    }
    let lh_name_len  = le_u16(data, lh + 26) as usize;
    let lh_extra_len = le_u16(data, lh + 28) as usize;
    let data_start = lh.checked_add(30)
        .and_then(|a| a.checked_add(lh_name_len))
        .and_then(|a| a.checked_add(lh_extra_len))
        .ok_or_else(|| JarError::MalformedZip("LH header fields overflow".into()))?;
    let compressed_size = usize::try_from(entry.compressed_size)
        .map_err(|_| JarError::MalformedZip("compressed_size overflows usize".into()))?;
    let data_end = data_start.checked_add(compressed_size)
        .ok_or_else(|| JarError::MalformedZip("entry data range overflows".into()))?;
    if data_end > data.len() {
        return Err(JarError::MalformedZip("entry data truncated".into()));
    }
    let compressed = &data[data_start..data_end];

    let uncompressed_size = usize::try_from(entry.uncompressed_size)
        .map_err(|_| JarError::MalformedZip("uncompressed_size overflows usize".into()))?;
    match entry.compression {
        0 => Ok(compressed.to_vec()), // stored
        8 => inflate_raw(compressed, uncompressed_size),
        m => Err(JarError::MalformedZip(format!("unsupported compression {m}"))),
    }
}

/// Minimal inflate (deflate raw) using a pure-Rust reimplementation stub.
/// In production this would link to miniz or flate2.
fn inflate_raw(data: &[u8], _expected: usize) -> Result<Vec<u8>, JarError> {
    // Stub — returns compressed data as-is when the decompressor is absent.
    // Replace with `miniz_oxide::inflate::decompress_to_vec_zlib(data)` or similar.
    let _ = data;
    Err(JarError::Io("deflate decompressor not linked; link flate2 or miniz_oxide".into()))
}

// ── Manifest ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct JarManifest {
    /// Main section headers
    pub main_attrs:  HashMap<String, String>,
    /// Per-entry sections keyed by `Name:` value
    pub entry_attrs: HashMap<String, HashMap<String, String>>,
    /// Per-entry section names in the order they appeared in the manifest.
    #[serde(default)]
    pub entry_order: Vec<String>,
}

impl JarManifest {
    pub fn main_class(&self) -> Option<&str> {
        self.main_attrs.get("Main-Class").map(String::as_str)
    }
    #[must_use] 
    pub fn class_path(&self) -> Vec<&str> {
        self.main_attrs
            .get("Class-Path")
            .map(|s| s.split_ascii_whitespace().collect())
            .unwrap_or_default()
    }
    #[must_use] 
    pub fn is_sealed(&self) -> bool {
        self.main_attrs.get("Sealed").is_some_and(|v| v.eq_ignore_ascii_case("true"))
    }
    pub fn spec_version(&self) -> Option<&str> {
        self.main_attrs.get("Specification-Version").map(String::as_str)
    }
    pub fn impl_version(&self) -> Option<&str> {
        self.main_attrs.get("Implementation-Version").map(String::as_str)
    }
    pub fn manifest_version(&self) -> Option<&str> {
        self.main_attrs.get("Manifest-Version").map(String::as_str)
    }
}

fn parse_manifest(raw: &[u8]) -> Result<JarManifest, JarError> {
    let text = std::str::from_utf8(raw)
        .map_err(|e| JarError::ManifestParse(e.to_string()))?;

    // Un-fold continuation lines (RFC 822 style: " " at start of next line)
    let mut unfolded = String::with_capacity(text.len());
    let lines = text.lines().peekable();
    for line in lines {
        if let Some(trimmed) = line.strip_prefix(' ') {
            // continuation — preserve a whitespace separator so that
            // space-separated values like Class-Path entries remain split.
            unfolded.push(' ');
            unfolded.push_str(trimmed);
        } else {
            if !unfolded.is_empty() { unfolded.push('\n'); }
            unfolded.push_str(line);
        }
    }

    let mut manifest = JarManifest::default();
    let mut current_section: Option<String> = None;
    let mut current_name:    Option<String> = None;

    for line in unfolded.lines() {
        if line.is_empty() {
            // blank line → end of section; if we just finished a named section,
            // record it in the insertion-order list.
            if let Some(name) = current_name.take() {
                manifest.entry_order.push(name);
            }
            current_section = None;
            continue;
        }
        if let Some(colon) = line.find(':') {
            let key   = line[..colon].trim().to_owned();
            let value = line[colon + 1..].trim().to_owned();
            if key == "Name" && current_section.is_none() {
                current_name    = Some(value.clone());
                current_section = Some(value);
            } else {
                match &current_section {
                    None => { manifest.main_attrs.insert(key, value); }
                    Some(sec) => {
                        manifest.entry_attrs
                            .entry(sec.clone())
                            .or_default()
                            .insert(key, value);
                    }
                }
            }
        }
    }
    // Flush trailing named section (no terminating blank line).
    if let Some(name) = current_name.take() {
        manifest.entry_order.push(name);
    }

    Ok(manifest)
}

// ── Multi-release JAR ─────────────────────────────────────────────────────────

/// Check whether the manifest declares Multi-Release support.
fn is_multi_release(manifest: &JarManifest) -> bool {
    manifest.main_attrs
        .get("Multi-Release")
        .is_some_and(|v| v.eq_ignore_ascii_case("true"))
}

/// For a multi-release JAR, select the best class entry path given a target JDK version.
/// Classes under `META-INF/versions/N/` override the root class if N <= `target_version`.
fn select_versioned<'a>(
    name:           &'a str,
    all_names:      &'a [String],
    target_version: u32,
) -> &'a str {
    let base      = name; // e.g. "com/example/Foo.class"
    let mut best  = base;
    let mut best_v = 0u32;

    for n in all_names {
        // META-INF/versions/9/com/example/Foo.class
        if let Some(rest) = n.strip_prefix("META-INF/versions/")
            && let Some(slash) = rest.find('/') {
                let ver_str = &rest[..slash];
                let suffix  = &rest[slash + 1..];
                if suffix == name
                    && let Ok(v) = ver_str.parse::<u32>()
                        && v <= target_version && v > best_v {
                            best   = n.as_str();
                            best_v = v;
                        }
            }
    }
    best
}

// ── Class-path resolution ─────────────────────────────────────────────────────

/// A resolved classpath entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ClasspathEntry {
    /// An inline class inside this JAR (by path e.g. `com/example/Foo.class`)
    InJar(String),
    /// An external JAR reference from Class-Path
    ExternalJar(String),
    /// A directory reference
    Directory(String),
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Classpath {
    pub entries: Vec<ClasspathEntry>,
}

impl Classpath {
    pub fn add_in_jar(&mut self, path: String) {
        self.entries.push(ClasspathEntry::InJar(path));
    }
    pub fn add_external(&mut self, path: String) {
        self.entries.push(ClasspathEntry::ExternalJar(path));
    }
    #[must_use] 
    pub fn find_class(&self, binary_name: &str) -> Option<&ClasspathEntry> {
        let target = format!("{}.class", binary_name.replace('.', "/"));
        self.entries.iter().find(|e| matches!(e, ClasspathEntry::InJar(p) if *p == target))
    }
}

// ── Dependency graph ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DepGraph {
    /// adjacency list: `class_binary_name` → set of referenced class names
    pub edges: HashMap<String, HashSet<String>>,
}

impl DepGraph {
    pub fn add_class(&mut self, name: String) {
        self.edges.entry(name).or_default();
    }
    pub fn add_dep(&mut self, from: &str, to: String) {
        self.edges.entry(from.to_owned()).or_default().insert(to);
    }
    /// Transitive closure via BFS starting from `root`.
    #[must_use]
    pub fn transitive_deps<'a>(&'a self, root: &'a str) -> HashSet<&'a str> {
        let mut visited = HashSet::new();
        let mut queue   = VecDeque::new();
        queue.push_back(root);
        while let Some(node) = queue.pop_front() {
            if visited.insert(node)
                && let Some(deps) = self.edges.get(node) {
                    for d in deps { queue.push_back(d.as_str()); }
                }
        }
        visited
    }
    /// Classes with no incoming edges (potential entry points / roots).
    #[must_use]
    pub fn roots(&self) -> Vec<&str> {
        let all: HashSet<&str> = self.edges.keys().map(String::as_str).collect();
        let reachable: HashSet<&str> = self.edges.values()
            .flat_map(|s| s.iter().map(String::as_str))
            .collect();
        all.difference(&reachable).copied().collect()
    }
}

fn build_dep_graph(classes: &HashMap<String, ClassFile>) -> DepGraph {
    let mut g = DepGraph::default();
    for (name, cf) in classes {
        g.add_class(name.clone());
        for (_, ref_name) in cf.referenced_classes() {
            if ref_name != name {
                g.add_dep(name, ref_name.to_owned());
            }
        }
    }
    g
}

// ── module-info detection ─────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModuleInfo {
    pub name:    String,
    pub version: Option<String>,
    /// Exported packages
    pub exports: Vec<String>,
    /// Required modules
    pub requires: Vec<String>,
}

fn extract_module_info(cf: &ClassFile) -> Option<ModuleInfo> {
    use crate::class_parser_full::Attribute;
    for attr in &cf.attributes {
        if let Attribute::Module(m) = attr {
            let name = cf.constant_pool.utf8(
                match cf.constant_pool.get(m.module_name_index).ok()? {
                    crate::class_parser_full::CpEntry::Module { name_index } => *name_index,
                    _ => return None,
                }
            ).ok()?.to_owned();
            let version = if m.module_version_index == 0 {
                None
            } else {
                cf.constant_pool.utf8(m.module_version_index).ok().map(str::to_owned)
            };
            let exports = m.exports.iter().filter_map(|e| {
                cf.constant_pool.get(e.package_index).ok().and_then(|c| {
                    if let crate::class_parser_full::CpEntry::Package { name_index } = c {
                        cf.constant_pool.utf8(*name_index).ok().map(str::to_owned)
                    } else { None }
                })
            }).collect();
            let requires = m.requires.iter().filter_map(|req| {
                cf.constant_pool.get(req.module_index).ok().and_then(|c| {
                    if let crate::class_parser_full::CpEntry::Module { name_index } = c {
                        cf.constant_pool.utf8(*name_index).ok().map(str::to_owned)
                    } else { None }
                })
            }).collect();
            return Some(ModuleInfo { name, version, exports, requires });
        }
    }
    None
}

// ── JarFile ───────────────────────────────────────────────────────────────────

/// A fully-loaded JAR with all class files parsed and analyzed.
#[derive(Debug)]
pub struct JarFile {
    pub manifest:    Option<JarManifest>,
    pub classes:     HashMap<String, ClassFile>,
    pub raw_entries: HashMap<String, Vec<u8>>,
    /// CRC-32 values reported by the ZIP central directory, keyed by entry name.
    pub entry_crc32: HashMap<String, u32>,
    pub classpath:   Classpath,
    pub dep_graph:   DepGraph,
    pub module_info: Option<ModuleInfo>,
    pub is_multi_release: bool,
    pub target_version:   u32,
}

impl JarFile {
    /// Parse a JAR from raw bytes.
    pub fn parse(data: &[u8], target_version: u32) -> Result<Self, JarError> {
        if data.len() < 4 || le_u32(data, 0) != ZIP_LOCAL_MAGIC {
            return Err(JarError::NotZip);
        }

        let cd = parse_central_directory(data)?;
        let entry_names: Vec<String> = cd.iter().map(|e| e.name.clone()).collect();

        let mut raw_entries: HashMap<String, Vec<u8>> = HashMap::new();
        let mut entry_crc32: HashMap<String, u32> = HashMap::new();
        for entry in &cd {
            entry_crc32.insert(entry.name.clone(), entry.crc32);
            match extract_entry(data, entry) {
                Ok(bytes) => { raw_entries.insert(entry.name.clone(), bytes); }
                Err(e) => {
                    // Skip unextractable entries (e.g. directories, unsupported compression)
                    // but surface the reason at debug level so failures are traceable.
                    eprintln!("DEBUG: skipping entry '{}': {e}", entry.name);
                }
            }
        }

        // Parse manifest
        let manifest = raw_entries
            .get("META-INF/MANIFEST.MF")
            .or_else(|| raw_entries.get("META-INF/manifest.mf"))
            .map(|raw| parse_manifest(raw))
            .transpose()?;

        let multi_release = manifest.as_ref().is_some_and(is_multi_release);

        // Build classpath
        let mut classpath = Classpath::default();
        for name in &entry_names {
            if name.ends_with(".class") && !name.starts_with("META-INF/versions/") {
                classpath.add_in_jar(name.clone());
            }
        }
        if let Some(mf) = &manifest {
            for ext in mf.class_path() {
                classpath.add_external(ext.to_owned());
            }
        }

        // Parse class files
        let mut classes: HashMap<String, ClassFile> = HashMap::new();
        let mut module_info: Option<ModuleInfo> = None;

        for name in &entry_names {
            if !name.ends_with(".class") { continue; }

            // Multi-release: skip versioned duplicates if we already have root
            let effective = if multi_release {
                select_versioned(name, &entry_names, target_version)
            } else {
                name.as_str()
            };

            // binary name = path without .class, slashes → dots
            let binary_name = name
                .strip_suffix(".class").unwrap_or(name)
                .replace('/', ".");

            if let Some(raw) = raw_entries.get(effective) {
                match ClassFile::parse(raw) {
                    Ok(cf) => {
                        if binary_name == "module-info" || name == "module-info.class" {
                            module_info = extract_module_info(&cf);
                        }
                        classes.insert(binary_name, cf);
                    }
                    Err(e) => {
                        // Log parse error but continue
                        eprintln!("WARN: could not parse {name}: {e}");
                    }
                }
            }
        }

        let dep_graph = build_dep_graph(&classes);

        Ok(Self {
            manifest,
            classes,
            raw_entries,
            entry_crc32,
            classpath,
            dep_graph,
            module_info,
            is_multi_release: multi_release,
            target_version,
        })
    }

    // ── Convenience ──────────────────────────────────────────────────────────

    #[must_use]
    pub fn main_class(&self) -> Option<&str> {
        self.manifest.as_ref()?.main_class()
    }

    #[must_use]
    pub fn class(&self, binary_name: &str) -> Option<&ClassFile> {
        self.classes.get(binary_name)
    }

    /// All class binary names contained in this JAR.
    #[must_use]
    pub fn class_names(&self) -> Vec<&str> {
        self.classes.keys().map(String::as_str).collect()
    }

    /// String literals from all classes.
    #[must_use]
    pub fn all_string_literals(&self) -> Vec<(&str, Vec<&str>)> {
        self.classes
            .iter()
            .map(|(n, cf)| (n.as_str(), cf.string_literals()))
            .filter(|(_, v)| !v.is_empty())
            .collect()
    }

    /// Count of classes per top-level package.
    #[must_use]
    pub fn package_stats(&self) -> HashMap<&str, usize> {
        let mut map: HashMap<&str, usize> = HashMap::new();
        for name in self.classes.keys() {
            let pkg = name.rfind('.').map_or("(default)", |i| &name[..i]);
            *map.entry(pkg).or_insert(0) += 1;
        }
        map
    }

    /// Check whether the JAR contains any signed entries.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        self.raw_entries.keys().any(|k| {
            let u = k.to_uppercase();
            u.starts_with("META-INF/") && (u.ends_with(".RSA") || u.ends_with(".DSA") || u.ends_with(".EC"))
        })
    }

    /// Resource (non-class) files.
    #[must_use]
    pub fn resources(&self) -> Vec<&str> {
        self.raw_entries
            .keys()
            .filter(|k| !k.ends_with(".class") && !k.ends_with('/'))
            .map(String::as_str)
            .collect()
    }

    /// Return Service Provider Interface declarations from META-INF/services/.
    #[must_use]
    pub fn spi_providers(&self) -> HashMap<&str, Vec<&str>> {
        let mut map: HashMap<&str, Vec<&str>> = HashMap::new();
        for (path, raw) in &self.raw_entries {
            if let Some(svc) = path.strip_prefix("META-INF/services/")
                && let Ok(text) = std::str::from_utf8(raw) {
                    let impls: Vec<&str> = text.lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty() && !l.starts_with('#'))
                        .collect();
                    map.insert(svc, impls);
                }
        }
        map
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_parsing() {
        let raw = b"Manifest-Version: 1.0\r\nMain-Class: com.example.Main\r\nClass-Path: libs/dep.jar\r\n\r\n";
        let mf = parse_manifest(raw).unwrap();
        assert_eq!(mf.main_class(), Some("com.example.Main"));
        assert_eq!(mf.class_path(), vec!["libs/dep.jar"]);
    }

    #[test]
    fn manifest_multiline() {
        let raw = b"Manifest-Version: 1.0\r\nClass-Path: a.jar\r\n b.jar\r\n c.jar\r\n\r\n";
        let mf = parse_manifest(raw).unwrap();
        assert_eq!(mf.class_path().len(), 3);
    }

    #[test]
    fn versioned_selection() {
        let names: Vec<String> = vec![
            "com/example/Foo.class".into(),
            "META-INF/versions/9/com/example/Foo.class".into(),
            "META-INF/versions/17/com/example/Foo.class".into(),
        ];
        assert_eq!(select_versioned("com/example/Foo.class", &names, 11),
                   "META-INF/versions/9/com/example/Foo.class");
        assert_eq!(select_versioned("com/example/Foo.class", &names, 17),
                   "META-INF/versions/17/com/example/Foo.class");
        assert_eq!(select_versioned("com/example/Foo.class", &names, 8),
                   "com/example/Foo.class");
    }

    #[test]
    fn dep_graph_roots() {
        let mut g = DepGraph::default();
        g.add_class("A".into());
        g.add_class("B".into());
        g.add_dep("A", "B".into());
        let roots = g.roots();
        assert!(roots.contains(&"A"), "A should be a root");
        assert!(!roots.contains(&"B"), "B is depended-on, not a root");
    }

    #[test]
    fn reject_not_zip() {
        let err = JarFile::parse(b"\x00\x00\x00\x00", 17).unwrap_err();
        assert!(matches!(err, JarError::NotZip));
    }
}
