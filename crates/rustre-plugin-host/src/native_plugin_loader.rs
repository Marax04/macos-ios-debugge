//! Native plugin loader — loads, verifies, and catalogs native shared-library plugins.
//!
//! Provides `NativePluginLoader`, `NativePlugin`, `PluginManifest`, `LoadError`,
//! `PluginSymbol`, `NativePluginRegistry`, and export-table scanners for PE and ELF.

use std::collections::HashMap;

// ── SymType ───────────────────────────────────────────────────────────────────

/// Type of a symbol exported from a native plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymType {
    Function,
    Variable,
    Unknown,
}

// ── PluginSymbol ──────────────────────────────────────────────────────────────

/// A resolved symbol from a native plugin's export table.
#[derive(Debug, Clone)]
pub struct PluginSymbol {
    pub name: String,
    /// Absolute virtual address (or RVA for unloaded images).
    pub address: u64,
    pub symbol_type: SymType,
}

impl PluginSymbol {
    pub fn new(name: impl Into<String>, address: u64, symbol_type: SymType) -> Self {
        Self { name: name.into(), address, symbol_type }
    }
}

// ── PluginManifest ────────────────────────────────────────────────────────────

/// Metadata describing a native plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    /// Host API version this plugin was compiled against.
    pub api_version: u32,
    /// Symbol name of the plugin entry point (e.g., `"plugin_init"`).
    pub entry_point: String,
    /// All symbols this plugin exports.
    pub exports: Vec<String>,
    /// Other plugin names this plugin requires.
    pub dependencies: Vec<String>,
}

impl PluginManifest {
    pub fn new(name: impl Into<String>, version: impl Into<String>, api_version: u32) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            api_version,
            entry_point: "plugin_init".to_string(),
            exports: Vec::new(),
            dependencies: Vec::new(),
        }
    }

    /// Parse a manifest from a simple key=value text format.
    ///
    /// Lines: `name=`, `version=`, `api_version=`, `entry_point=`,
    ///        `export=`, `dependency=` (multiple export/dependency lines allowed).
    pub fn parse(text: &str) -> Option<Self> {
        let mut name = String::new();
        let mut version = String::new();
        let mut api_version = 0u32;
        let mut entry_point = "plugin_init".to_string();
        let mut exports = Vec::new();
        let mut dependencies = Vec::new();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let (key, value) = match line.split_once('=') {
                Some(kv) => kv,
                None => continue,
            };
            match key.trim() {
                "name"         => name = value.trim().to_string(),
                "version"      => version = value.trim().to_string(),
                "api_version"  => api_version = value.trim().parse().unwrap_or(0),
                "entry_point"  => entry_point = value.trim().to_string(),
                "export"       => exports.push(value.trim().to_string()),
                "dependency"   => dependencies.push(value.trim().to_string()),
                _ => {}
            }
        }

        if name.is_empty() { return None; }
        Some(Self {
            name,
            version,
            api_version,
            entry_point,
            exports,
            dependencies,
        })
    }

    /// Serialise the manifest back to key=value format.
    pub fn to_text(&self) -> String {
        let mut s = format!(
            "name={}\nversion={}\napi_version={}\nentry_point={}\n",
            self.name, self.version, self.api_version, self.entry_point
        );
        for e in &self.exports {
            s.push_str(&format!("export={}\n", e));
        }
        for d in &self.dependencies {
            s.push_str(&format!("dependency={}\n", d));
        }
        s
    }
}

// ── LoadError ─────────────────────────────────────────────────────────────────

/// Errors that can occur while loading a native plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    FileNotFound,
    InvalidManifest,
    ApiVersionMismatch { required: u32, got: u32 },
    MissingExport(String),
    DependencyNotFound(String),
    InvalidBinary(String),
    AlreadyLoaded,
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::FileNotFound => write!(f, "file not found"),
            LoadError::InvalidManifest => write!(f, "invalid manifest"),
            LoadError::ApiVersionMismatch { required, got } =>
                write!(f, "API version mismatch: required {}, got {}", required, got),
            LoadError::MissingExport(sym) => write!(f, "missing export: {}", sym),
            LoadError::DependencyNotFound(dep) => write!(f, "dependency not found: {}", dep),
            LoadError::InvalidBinary(msg) => write!(f, "invalid binary: {}", msg),
            LoadError::AlreadyLoaded => write!(f, "plugin already loaded"),
        }
    }
}

// ── NativePlugin ─────────────────────────────────────────────────────────────

/// A loaded (or pending) native plugin.
#[derive(Debug, Clone)]
pub struct NativePlugin {
    /// Path to the shared library on disk.
    pub path: String,
    /// Simulated OS library handle (0 = unloaded).
    pub handle: u64,
    pub manifest: PluginManifest,
    pub loaded: bool,
    pub symbols: Vec<PluginSymbol>,
}

impl NativePlugin {
    pub fn new(path: impl Into<String>, manifest: PluginManifest) -> Self {
        Self {
            path: path.into(),
            handle: 0,
            manifest,
            loaded: false,
            symbols: Vec::new(),
        }
    }

    /// Simulate loading the plugin (assigns a mock handle).
    pub fn load(&mut self) -> Result<(), LoadError> {
        if self.loaded { return Err(LoadError::AlreadyLoaded); }
        // In a real implementation this calls dlopen/LoadLibrary.
        self.handle = 0xDEAD_BEEF_0000_0000 | (self.manifest.name.len() as u64);
        self.loaded = true;
        Ok(())
    }

    pub fn unload(&mut self) {
        self.handle = 0;
        self.loaded = false;
    }

    pub fn find_symbol(&self, name: &str) -> Option<&PluginSymbol> {
        self.symbols.iter().find(|s| s.name == name)
    }

    pub fn has_export(&self, name: &str) -> bool {
        self.manifest.exports.contains(&name.to_string())
    }
}

// ── PE/ELF export-table scanners ──────────────────────────────────────────────

/// Minimal PE64 export directory layout (offsets only).
const PE_DOS_MAGIC: [u8; 2] = [0x4D, 0x5A]; // "MZ"
const PE_NT_MAGIC:  [u8; 4] = [0x50, 0x45, 0x00, 0x00]; // "PE\0\0"
const ELF_MAGIC:    [u8; 4] = [0x7F, 0x45, 0x4C, 0x46]; // "\x7FELF"

/// Try to scan PE export names from a raw PE image slice.
pub fn scan_pe_exports(data: &[u8]) -> Vec<String> {
    if data.len() < 64 { return Vec::new(); }
    if &data[0..2] != PE_DOS_MAGIC { return Vec::new(); }
    let pe_off = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap_or([0; 4])) as usize;
    if pe_off + 4 > data.len() { return Vec::new(); }
    if &data[pe_off..pe_off + 4] != PE_NT_MAGIC { return Vec::new(); }

    // Optional header offset: pe_off + 4 (FileHeader) + 20 bytes = pe_off + 24
    let opt_hdr = pe_off + 24;
    if opt_hdr + 4 > data.len() { return Vec::new(); }
    let magic = u16::from_le_bytes([data[opt_hdr], data[opt_hdr + 1]]);
    let export_dir_rva_off = if magic == 0x020B {
        // PE32+
        opt_hdr + 112
    } else {
        // PE32
        opt_hdr + 96
    };
    if export_dir_rva_off + 8 > data.len() { return Vec::new(); }
    let export_rva = u32::from_le_bytes(
        data[export_dir_rva_off..export_dir_rva_off + 4].try_into().unwrap_or([0; 4])
    ) as usize;
    if export_rva == 0 || export_rva + 40 > data.len() { return Vec::new(); }

    // Export directory layout:
    // +18: NumberOfNames (u32)
    // +32: AddressOfNames RVA (u32)
    let num_names = u32::from_le_bytes(
        data[export_rva + 18..export_rva + 22].try_into().unwrap_or([0; 4])
    ) as usize;
    let names_rva = u32::from_le_bytes(
        data[export_rva + 32..export_rva + 36].try_into().unwrap_or([0; 4])
    ) as usize;
    let names_table_end = match num_names.checked_mul(4).and_then(|s| names_rva.checked_add(s)) {
        Some(end) => end,
        None => return Vec::new(),
    };
    if names_table_end > data.len() { return Vec::new(); }

    let mut names = Vec::with_capacity(num_names);
    for i in 0..num_names {
        let name_rva_off = names_rva + i * 4;
        if name_rva_off + 4 > data.len() { break; }
        let name_rva = u32::from_le_bytes(
            data[name_rva_off..name_rva_off + 4].try_into().unwrap_or([0; 4])
        ) as usize;
        if name_rva >= data.len() { continue; }
        let null = match data[name_rva..].iter().position(|&b| b == 0) {
            Some(n) => n,
            None => continue, // no null terminator in remaining data — skip
        };
        if null == 0 { continue; } // empty name — skip
        if let Ok(s) = std::str::from_utf8(&data[name_rva..name_rva + null]) {
            names.push(s.to_string());
        }
    }
    names
}

/// Try to extract exported symbol names from a minimal ELF image slice.
pub fn scan_elf_exports(data: &[u8]) -> Vec<String> {
    if data.len() < 64 { return Vec::new(); }
    if &data[0..4] != ELF_MAGIC { return Vec::new(); }
    // This is a stub implementation.  A full ELF parser would walk the
    // dynamic symbol table (.dynsym) and string table (.dynstr).
    // We return an empty list here since full ELF parsing is out of scope.
    Vec::new()
}

// ── verify_api_version ────────────────────────────────────────────────────────

/// True if `plugin_api` is compatible with `host_api`.
///
/// Compatibility rule: major versions must match (major = api_version / 1000).
pub fn verify_api_version(plugin_api: u32, host_api: u32) -> bool {
    let plugin_major = plugin_api / 1000;
    let host_major   = host_api   / 1000;
    plugin_major == host_major && plugin_api <= host_api
}

// ── NativePluginLoader ────────────────────────────────────────────────────────

/// Loads native plugins from disk, verifies their manifests, and resolves exports.
pub struct NativePluginLoader {
    /// The host's API version for compatibility checking.
    pub host_api_version: u32,
    /// Staged plugins (not yet loaded into the registry).
    staged: Vec<NativePlugin>,
}

impl NativePluginLoader {
    pub fn new(host_api_version: u32) -> Self {
        Self { host_api_version, staged: Vec::new() }
    }

    /// Stage a plugin from a manifest text and a mock binary slice.
    pub fn stage(
        &mut self,
        path: impl Into<String>,
        manifest_text: &str,
        binary: &[u8],
    ) -> Result<(), LoadError> {
        let manifest = PluginManifest::parse(manifest_text)
            .ok_or(LoadError::InvalidManifest)?;
        if !verify_api_version(manifest.api_version, self.host_api_version) {
            return Err(LoadError::ApiVersionMismatch {
                required: manifest.api_version,
                got: self.host_api_version,
            });
        }
        let mut plugin = NativePlugin::new(path, manifest.clone());
        // Populate symbols from PE/ELF scan or from manifest.exports.
        let export_names = if !binary.is_empty() && &binary[0..2] == b"MZ" {
            scan_pe_exports(binary)
        } else if !binary.is_empty() && binary.len() >= 4 && &binary[0..4] == ELF_MAGIC {
            scan_elf_exports(binary)
        } else {
            manifest.exports.clone()
        };
        // Verify all manifest exports are present.
        for req in &manifest.exports {
            if !export_names.contains(req) && !export_names.is_empty() {
                return Err(LoadError::MissingExport(req.clone()));
            }
        }
        // Build symbol table.
        for (i, name) in export_names.iter().enumerate() {
            plugin.symbols.push(PluginSymbol::new(
                name,
                0x1000 + i as u64 * 0x10,
                SymType::Function,
            ));
        }
        plugin.load()?;
        self.staged.push(plugin);
        Ok(())
    }

    /// Resolve exports for all staged plugins.
    pub fn resolve_exports(&mut self) {
        // In a real loader, this would resolve import symbols against loaded plugins.
        // Here we mark all staged plugins as having their exports resolved.
        for plugin in &mut self.staged {
            if plugin.loaded && plugin.symbols.is_empty() {
                for (i, name) in plugin.manifest.exports.iter().enumerate() {
                    plugin.symbols.push(PluginSymbol::new(
                        name,
                        0x2000 + i as u64 * 0x10,
                        SymType::Function,
                    ));
                }
            }
        }
    }

    /// Move all staged plugins into a `NativePluginRegistry`.
    pub fn commit(mut self) -> NativePluginRegistry {
        self.resolve_exports();
        let mut reg = NativePluginRegistry::new(self.host_api_version);
        for plugin in self.staged {
            reg.register(plugin);
        }
        reg
    }

    pub fn staged_count(&self) -> usize { self.staged.len() }
}

// ── NativePluginRegistry ──────────────────────────────────────────────────────

/// Registry of loaded native plugins.
pub struct NativePluginRegistry {
    pub plugins: HashMap<String, NativePlugin>,
    pub host_api_version: u32,
}

impl NativePluginRegistry {
    pub fn new(host_api_version: u32) -> Self {
        Self {
            plugins: HashMap::new(),
            host_api_version,
        }
    }

    /// Register a plugin.
    pub fn register(&mut self, plugin: NativePlugin) {
        self.plugins.insert(plugin.manifest.name.clone(), plugin);
    }

    /// Look up a plugin by name.
    pub fn get(&self, name: &str) -> Option<&NativePlugin> {
        self.plugins.get(name)
    }

    /// Unload a plugin by name.
    pub fn unload(&mut self, name: &str) -> bool {
        if let Some(p) = self.plugins.get_mut(name) {
            p.unload();
            true
        } else {
            false
        }
    }

    /// Check that all dependencies of all registered plugins are satisfied.
    pub fn check_dependencies(&self) -> Vec<LoadError> {
        let mut errors = Vec::new();
        for plugin in self.plugins.values() {
            for dep in &plugin.manifest.dependencies {
                if !self.plugins.contains_key(dep.as_str()) {
                    errors.push(LoadError::DependencyNotFound(dep.clone()));
                }
            }
        }
        errors
    }

    pub fn loaded_count(&self) -> usize {
        self.plugins.values().filter(|p| p.loaded).count()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST_TEXT: &str = "
name=test_plugin
version=1.0.0
api_version=1000
entry_point=plugin_init
export=plugin_init
export=plugin_tick
";

    #[test]
    fn parse_manifest_basic() {
        let m = PluginManifest::parse(MANIFEST_TEXT).unwrap();
        assert_eq!(m.name, "test_plugin");
        assert_eq!(m.version, "1.0.0");
        assert_eq!(m.api_version, 1000);
        assert_eq!(m.entry_point, "plugin_init");
        assert_eq!(m.exports.len(), 2);
    }

    #[test]
    fn parse_manifest_missing_name() {
        assert!(PluginManifest::parse("version=1.0.0\n").is_none());
    }

    #[test]
    fn manifest_roundtrip() {
        let m = PluginManifest::parse(MANIFEST_TEXT).unwrap();
        let text = m.to_text();
        let m2 = PluginManifest::parse(&text).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn verify_api_version_compatible() {
        assert!(verify_api_version(1000, 1050));
        assert!(verify_api_version(1000, 1000));
    }

    #[test]
    fn verify_api_version_plugin_newer_than_host() {
        assert!(!verify_api_version(1100, 1000)); // plugin > host
    }

    #[test]
    fn verify_api_version_major_mismatch() {
        assert!(!verify_api_version(2000, 1999)); // major differs
    }

    #[test]
    fn native_plugin_load_unload() {
        let m = PluginManifest::parse(MANIFEST_TEXT).unwrap();
        let mut plugin = NativePlugin::new("/tmp/test.so", m);
        assert!(!plugin.loaded);
        plugin.load().unwrap();
        assert!(plugin.loaded);
        assert_ne!(plugin.handle, 0);
        plugin.unload();
        assert!(!plugin.loaded);
    }

    #[test]
    fn native_plugin_double_load_error() {
        let m = PluginManifest::parse(MANIFEST_TEXT).unwrap();
        let mut plugin = NativePlugin::new("/tmp/test.so", m);
        plugin.load().unwrap();
        assert_eq!(plugin.load().unwrap_err(), LoadError::AlreadyLoaded);
    }

    #[test]
    fn loader_stage_valid_plugin() {
        let mut loader = NativePluginLoader::new(1000);
        loader.stage("/tmp/test.so", MANIFEST_TEXT, &[]).unwrap();
        assert_eq!(loader.staged_count(), 1);
    }

    #[test]
    fn loader_stage_api_version_mismatch() {
        let mut loader = NativePluginLoader::new(1000);
        let bad_manifest = "name=bad\nversion=1.0\napi_version=2000\nentry_point=init\n";
        let err = loader.stage("/tmp/bad.so", bad_manifest, &[]).unwrap_err();
        assert!(matches!(err, LoadError::ApiVersionMismatch { .. }));
    }

    #[test]
    fn loader_commit_builds_registry() {
        let mut loader = NativePluginLoader::new(1000);
        loader.stage("/tmp/test.so", MANIFEST_TEXT, &[]).unwrap();
        let reg = loader.commit();
        assert_eq!(reg.loaded_count(), 1);
        assert!(reg.get("test_plugin").is_some());
    }

    #[test]
    fn registry_check_dependencies_ok() {
        let mut loader = NativePluginLoader::new(1000);
        loader.stage("/tmp/a.so", MANIFEST_TEXT, &[]).unwrap();
        let reg = loader.commit();
        let errors = reg.check_dependencies();
        assert!(errors.is_empty());
    }

    #[test]
    fn registry_check_dependencies_missing() {
        let mut reg = NativePluginRegistry::new(1000);
        let m = PluginManifest {
            name: "a".to_string(),
            version: "1.0".to_string(),
            api_version: 1000,
            entry_point: "init".to_string(),
            exports: vec![],
            dependencies: vec!["b".to_string()],
        };
        let mut p = NativePlugin::new("/tmp/a.so", m);
        p.loaded = true;
        reg.register(p);
        let errors = reg.check_dependencies();
        assert_eq!(errors.len(), 1);
        assert!(matches!(&errors[0], LoadError::DependencyNotFound(dep) if dep == "b"));
    }

    #[test]
    fn load_error_display() {
        assert_eq!(LoadError::FileNotFound.to_string(), "file not found");
        assert!(LoadError::MissingExport("foo".to_string()).to_string().contains("foo"));
    }

    #[test]
    fn plugin_symbol_find() {
        let m = PluginManifest::parse(MANIFEST_TEXT).unwrap();
        let mut plugin = NativePlugin::new("/tmp/test.so", m);
        plugin.symbols.push(PluginSymbol::new("plugin_init", 0x1000, SymType::Function));
        assert!(plugin.find_symbol("plugin_init").is_some());
        assert!(plugin.find_symbol("not_here").is_none());
    }

    #[test]
    fn plugin_has_export() {
        let m = PluginManifest::parse(MANIFEST_TEXT).unwrap();
        let plugin = NativePlugin::new("/tmp/test.so", m);
        assert!(plugin.has_export("plugin_init"));
        assert!(!plugin.has_export("not_exported"));
    }

    #[test]
    fn registry_unload() {
        let mut loader = NativePluginLoader::new(1000);
        loader.stage("/tmp/test.so", MANIFEST_TEXT, &[]).unwrap();
        let mut reg = loader.commit();
        assert!(reg.unload("test_plugin"));
        assert!(!reg.get("test_plugin").unwrap().loaded);
    }
}
