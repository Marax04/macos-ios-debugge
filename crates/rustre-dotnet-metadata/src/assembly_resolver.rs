// assembly_resolver.rs — .NET assembly resolver
// GAC lookup, probe paths, binding redirects, strong name validation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

// ─── Assembly identity ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssemblyName {
    pub simple_name: String,
    pub version: Option<AssemblyVersion>,
    pub culture: Option<String>,
    pub public_key_token: Option<PublicKeyToken>,
    pub flags: AssemblyFlags,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssemblyVersion {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub revision: u16,
}

impl AssemblyVersion {
    pub fn new(major: u16, minor: u16, build: u16, revision: u16) -> Self {
        Self { major, minor, build, revision }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 { return None; }
        let major = parts[0].parse().ok()?;
        let minor = parts[1].parse().ok()?;
        let build = parts[2].parse().ok()?;
        let revision = parts[3].parse().ok()?;
        Some(Self { major, minor, build, revision })
    }

    pub fn is_compatible_with(self, required: Self) -> bool {
        // major must match exactly; minor.build.revision must be >=
        self.major == required.major
            && (self.minor > required.minor
                || (self.minor == required.minor && self.build > required.build)
                || (self.minor == required.minor && self.build == required.build && self.revision >= required.revision))
    }
}

impl fmt::Display for AssemblyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.major, self.minor, self.build, self.revision)
    }
}

impl PartialOrd for AssemblyVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AssemblyVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.major, self.minor, self.build, self.revision).cmp(&(other.major, other.minor, other.build, other.revision))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKeyToken(pub [u8; 8]);

impl PublicKeyToken {
    pub fn from_hex(hex: &str) -> Option<Self> {
        if hex.len() != 16 { return None; }
        let mut bytes = [0u8; 8];
        for i in 0..8 {
            bytes[i] = u8::from_str_radix(&hex[i*2..i*2+2], 16).ok()?;
        }
        Some(Self(bytes))
    }

    pub fn to_hex(&self) -> String {
        use std::fmt::Write as _;
        self.0.iter().fold(String::with_capacity(self.0.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    pub fn is_microsoft(&self) -> bool {
        // b77a5c561934e089 and b03f5f7f11d50a3a are common MS tokens
        let hex = self.to_hex();
        matches!(hex.as_str(), "b77a5c561934e089" | "b03f5f7f11d50a3a" | "31bf3856ad364e35" | "cc7b13ffcd2ddd51")
    }
}

impl fmt::Display for PublicKeyToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct AssemblyFlags(pub u32);

impl AssemblyFlags {
    pub const NONE: Self = Self(0);
    pub const PUBLIC_KEY: Self = Self(0x0001);
    pub const RETARGETABLE: Self = Self(0x0100);
    pub const DISABLE_JIT_COMPILE_OPTIMIZER: Self = Self(0x4000);
    pub const ENABLE_JIT_COMPILE_TRACKING: Self = Self(0x8000);

    pub fn is_retargetable(self) -> bool { self.0 & 0x0100 != 0 }
    pub fn has_full_public_key(self) -> bool { self.0 & 0x0001 != 0 }
}

impl AssemblyName {
    pub fn new(simple_name: &str) -> Self {
        Self {
            simple_name: simple_name.to_string(),
            version: None,
            culture: None,
            public_key_token: None,
            flags: AssemblyFlags::NONE,
        }
    }

    #[must_use]
    pub fn with_version(mut self, v: AssemblyVersion) -> Self {
        self.version = Some(v);
        self
    }

    #[must_use]
    pub fn with_culture(mut self, c: &str) -> Self {
        self.culture = Some(if c.eq_ignore_ascii_case("neutral") { String::new() } else { c.to_string() });
        self
    }

    #[must_use]
    pub fn with_pkt(mut self, pkt: PublicKeyToken) -> Self {
        self.public_key_token = Some(pkt);
        self
    }

    pub fn is_strong_named(&self) -> bool {
        self.public_key_token.is_some()
    }

    pub fn is_neutral_culture(&self) -> bool {
        self.culture.as_deref().is_none_or(|c| c.is_empty())
    }

    pub fn display_name(&self) -> String {
        let mut s = self.simple_name.clone();
        if let Some(v) = &self.version { s.push_str(&format!(", Version={v}")); }
        if let Some(c) = &self.culture {
            s.push_str(&format!(", Culture={}", if c.is_empty() { "neutral" } else { c }));
        }
        if let Some(pkt) = &self.public_key_token { s.push_str(&format!(", PublicKeyToken={pkt}")); }
        s
    }

    /// Partial fusion identity (name + pkt only, ignoring version/culture for initial lookup)
    pub fn fusion_key(&self) -> String {
        match &self.public_key_token {
            Some(pkt) => format!("{}__{}", self.simple_name.to_ascii_lowercase(), pkt),
            None => self.simple_name.to_ascii_lowercase(),
        }
    }
}

impl fmt::Display for AssemblyName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ─── Binding redirect ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingRedirect {
    pub assembly_name: String,
    pub public_key_token: Option<PublicKeyToken>,
    pub old_version_range_start: AssemblyVersion,
    pub old_version_range_end: AssemblyVersion,
    pub new_version: AssemblyVersion,
    pub new_path: Option<PathBuf>,
}

impl BindingRedirect {
    pub fn applies_to(&self, name: &AssemblyName) -> bool {
        if !name.simple_name.eq_ignore_ascii_case(&self.assembly_name) {
            return false;
        }
        if let (Some(req_pkt), Some(our_pkt)) = (&name.public_key_token, &self.public_key_token)
            && req_pkt != our_pkt { return false; }
        if let Some(version) = &name.version {
            return *version >= self.old_version_range_start && *version <= self.old_version_range_end;
        }
        true
    }

    pub fn redirected_name(&self, original: &AssemblyName) -> AssemblyName {
        let mut new_name = original.clone();
        new_name.version = Some(self.new_version);
        new_name
    }
}

// ─── GAC entry ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GacEntry {
    pub name: AssemblyName,
    pub path: PathBuf,
    pub gac_version: GacVersion,
    pub file_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GacVersion {
    V1,    // C:\Windows\assembly\GAC\
    V2,    // C:\Windows\assembly\GAC_MSIL\ etc.
    V4,    // C:\Windows\Microsoft.NET\assembly\GAC_MSIL\ etc.
}

impl GacVersion {
    pub fn root_paths(self) -> &'static [&'static str] {
        match self {
            Self::V1 => &[r"C:\Windows\assembly\GAC"],
            Self::V2 => &[
                r"C:\Windows\assembly\GAC_MSIL",
                r"C:\Windows\assembly\GAC_32",
                r"C:\Windows\assembly\GAC_64",
            ],
            Self::V4 => &[
                r"C:\Windows\Microsoft.NET\assembly\GAC_MSIL",
                r"C:\Windows\Microsoft.NET\assembly\GAC_32",
                r"C:\Windows\Microsoft.NET\assembly\GAC_64",
            ],
        }
    }
}

// ─── Resolution result ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionResult {
    pub requested: AssemblyName,
    pub resolved: Option<ResolvedAssembly>,
    pub strategy: ResolutionStrategy,
    pub redirect_applied: Option<BindingRedirect>,
    pub probed_paths: Vec<PathBuf>,
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedAssembly {
    pub path: PathBuf,
    pub actual_name: AssemblyName,
    pub is_framework: bool,
    pub file_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolutionStrategy {
    GacV4,
    GacV2,
    GacV1,
    ProbePath,
    AppBase,
    PrivatePath,
    RegisteredCodeBase,
    LoadFromContext,
    Failed,
}

impl fmt::Display for ResolutionStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::GacV4 => "GAC_v4",
            Self::GacV2 => "GAC_v2",
            Self::GacV1 => "GAC_v1",
            Self::ProbePath => "ProbePath",
            Self::AppBase => "AppBase",
            Self::PrivatePath => "PrivatePath",
            Self::RegisteredCodeBase => "CodeBase",
            Self::LoadFromContext => "LoadFrom",
            Self::Failed => "FAILED",
        };
        write!(f, "{s}")
    }
}

impl ResolutionResult {
    pub fn succeeded(&self) -> bool {
        self.resolved.is_some()
    }

    pub fn path(&self) -> Option<&Path> {
        self.resolved.as_ref().map(|r| r.path.as_path())
    }

    pub fn was_redirected(&self) -> bool {
        self.redirect_applied.is_some()
    }
}

// ─── Assembly resolver configuration ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverConfig {
    pub app_base: Option<PathBuf>,
    pub private_bin_paths: Vec<PathBuf>,
    pub gac_roots: Vec<PathBuf>,
    pub framework_dirs: Vec<PathBuf>,
    pub code_bases: HashMap<String, PathBuf>,
    pub binding_redirects: Vec<BindingRedirect>,
    pub allow_partial_names: bool,
    pub shadow_copy_enabled: bool,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            app_base: None,
            private_bin_paths: Vec::new(),
            gac_roots: default_gac_roots(),
            framework_dirs: default_framework_dirs(),
            code_bases: HashMap::new(),
            binding_redirects: Vec::new(),
            allow_partial_names: false,
            shadow_copy_enabled: false,
        }
    }
}

fn default_gac_roots() -> Vec<PathBuf> {
    vec![
        PathBuf::from(r"C:\Windows\Microsoft.NET\assembly\GAC_MSIL"),
        PathBuf::from(r"C:\Windows\Microsoft.NET\assembly\GAC_32"),
        PathBuf::from(r"C:\Windows\Microsoft.NET\assembly\GAC_64"),
        PathBuf::from(r"C:\Windows\assembly\GAC_MSIL"),
        PathBuf::from(r"C:\Windows\assembly\GAC_32"),
        PathBuf::from(r"C:\Windows\assembly\GAC_64"),
    ]
}

fn default_framework_dirs() -> Vec<PathBuf> {
    vec![
        PathBuf::from(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319"),
        PathBuf::from(r"C:\Windows\Microsoft.NET\Framework\v4.0.30319"),
        PathBuf::from(r"C:\Program Files\dotnet\shared\Microsoft.NETCore.App"),
    ]
}

// ─── GAC path builder ─────────────────────────────────────────────────────────

pub struct GacPathBuilder;

impl GacPathBuilder {
    /// Construct GAC path for v4: <gac_root>\<name>\<version>__<pkt>\<name>.dll
    pub fn v4_path(gac_root: &Path, name: &AssemblyName) -> Option<PathBuf> {
        let version = name.version?;
        let pkt = name.public_key_token.as_ref()?;
        let version_dir = format!("v4.0_{version}__{pkt}");
        Some(gac_root.join(&name.simple_name).join(version_dir).join(format!("{}.dll", name.simple_name)))
    }

    /// v2 GAC: <gac_root>\<name>\<version>__<pkt>\<name>.dll
    pub fn v2_path(gac_root: &Path, name: &AssemblyName) -> Option<PathBuf> {
        let version = name.version?;
        let pkt = name.public_key_token.as_ref()?;
        let version_dir = format!("{version}__{pkt}");
        Some(gac_root.join(&name.simple_name).join(version_dir).join(format!("{}.dll", name.simple_name)))
    }
}

// ─── Strong name verifier (minimal — no actual crypto) ───────────────────────

pub struct StrongNameVerifier;

impl StrongNameVerifier {
    /// Check if a byte pattern in the PE looks like a valid strong name signature structure.
    /// This is a heuristic — real verification requires RSA.
    pub fn has_strong_name_signature_structure(pe_bytes: &[u8]) -> bool {
        // Look for the known CLR header magic and StrongNameSignature RVA
        // In a properly formed PE, bytes at offset after CLR header magic indicate SN presence.
        // Simplified: check for 0x48424A4A (BSJB) metadata magic
        let bsjb = b"BSJB";
        pe_bytes.windows(4).any(|w| w == bsjb)
    }

    pub fn public_key_token_from_public_key(public_key: &[u8]) -> Option<PublicKeyToken> {
        if public_key.len() < 8 { return None; }
        // Real algorithm: SHA-1 hash of public key, take last 8 bytes, reverse
        // Here we use a simple deterministic hash for structural completeness.
        let mut hash = [0u8; 20];
        let mut state: u32 = 0xDEADBEEF;
        for (i, &b) in public_key.iter().enumerate() {
            state = state.wrapping_add(u32::from(b)).rotate_left((i % 29) as u32);
            hash[i % 20] ^= (state & 0xFF) as u8;
        }
        let mut token = [0u8; 8];
        for i in 0..8 { token[i] = hash[19 - i]; }
        Some(PublicKeyToken(token))
    }
}

// ─── Cached assembly database ─────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct AssemblyDatabase {
    by_simple_name: HashMap<String, Vec<GacEntry>>,
    by_full_identity: HashMap<String, GacEntry>,
}

impl AssemblyDatabase {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, entry: GacEntry) {
        let key = entry.name.display_name();
        self.by_full_identity.insert(key, entry.clone());
        self.by_simple_name.entry(entry.name.simple_name.to_ascii_lowercase()).or_default().push(entry);
    }

    pub fn lookup_exact(&self, name: &AssemblyName) -> Option<&GacEntry> {
        self.by_full_identity.get(&name.display_name())
    }

    pub fn lookup_partial(&self, simple_name: &str) -> Vec<&GacEntry> {
        self.by_simple_name.get(&simple_name.to_ascii_lowercase()).map_or(vec![], |v| v.iter().collect())
    }

    pub fn lookup_best_version(&self, name: &AssemblyName) -> Option<&GacEntry> {
        let candidates = self.by_simple_name.get(&name.simple_name.to_ascii_lowercase())?;
        let required_version = name.version;

        // Filter by public key token if present
        let filtered: Vec<&GacEntry> = if let Some(ref pkt) = name.public_key_token {
            candidates.iter().filter(|e| e.name.public_key_token.as_ref() == Some(pkt)).collect()
        } else {
            candidates.iter().collect()
        };

        if filtered.is_empty() { return None; }

        // Find best: exact version first, then highest compatible version
        if let Some(rv) = required_version {
            if let Some(exact) = filtered.iter().find(|e| e.name.version == Some(rv)) {
                return Some(exact);
            }
            // Find highest version that is compatible
            filtered.iter().filter(|e| e.name.version.is_some_and(|ev| ev.is_compatible_with(rv)))
                .max_by_key(|e| e.name.version)
                .copied()
        } else {
            // No version specified: return highest available
            filtered.iter().max_by_key(|e| e.name.version).copied()
        }
    }

    pub fn total_entries(&self) -> usize {
        self.by_full_identity.len()
    }
}

// ─── Core assembly resolver ───────────────────────────────────────────────────

#[derive(Debug)]
pub struct AssemblyResolver {
    config: ResolverConfig,
    gac_database: AssemblyDatabase,
    resolution_cache: HashMap<String, ResolutionResult>,
    resolution_count: u32,
}

impl AssemblyResolver {
    pub fn new(config: ResolverConfig) -> Self {
        Self {
            config,
            gac_database: AssemblyDatabase::new(),
            resolution_cache: HashMap::new(),
            resolution_count: 0,
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(ResolverConfig::default())
    }

    pub fn register_gac_entry(&mut self, entry: GacEntry) {
        self.gac_database.register(entry);
    }

    pub fn add_binding_redirect(&mut self, redirect: BindingRedirect) {
        self.config.binding_redirects.push(redirect);
    }

    pub fn set_app_base(&mut self, path: PathBuf) {
        self.config.app_base = Some(path);
    }

    pub fn add_probe_path(&mut self, path: PathBuf) {
        self.config.private_bin_paths.push(path);
    }

    pub fn register_codebase(&mut self, assembly_name: String, path: PathBuf) {
        self.config.code_bases.insert(assembly_name.to_ascii_lowercase(), path);
    }

    /// Resolve an assembly reference.
    pub fn resolve(&mut self, name: &AssemblyName) -> ResolutionResult {
        self.resolution_count += 1;
        let cache_key = name.display_name();

        if let Some(cached) = self.resolution_cache.get(&cache_key) {
            return cached.clone();
        }

        let result = self.resolve_internal(name);
        self.resolution_cache.insert(cache_key, result.clone());
        result
    }

    fn resolve_internal(&self, name: &AssemblyName) -> ResolutionResult {
        let mut probed_paths: Vec<PathBuf> = Vec::new();
        let mut redirect_applied: Option<BindingRedirect> = None;

        // 1. Apply binding redirects
        let effective_name = self.apply_redirects(name, &mut redirect_applied);

        // 2. Check registered codebase
        if let Some(path) = self.config.code_bases.get(&effective_name.simple_name.to_ascii_lowercase()) {
            probed_paths.push(path.clone());
            return ResolutionResult {
                requested: name.clone(),
                resolved: Some(ResolvedAssembly {
                    path: path.clone(),
                    actual_name: effective_name.clone(),
                    is_framework: false,
                    file_size: 0,
                }),
                strategy: ResolutionStrategy::RegisteredCodeBase,
                redirect_applied,
                probed_paths,
                failure_reason: None,
            };
        }

        // 3. GAC lookup (v4 first, then v2)
        if effective_name.is_strong_named()
            && let Some(entry) = self.gac_database.lookup_best_version(&effective_name)
        {
            let strategy = match entry.gac_version {
                GacVersion::V4 => ResolutionStrategy::GacV4,
                GacVersion::V2 => ResolutionStrategy::GacV2,
                GacVersion::V1 => ResolutionStrategy::GacV1,
            };
            return ResolutionResult {
                requested: name.clone(),
                resolved: Some(ResolvedAssembly {
                    path: entry.path.clone(),
                    actual_name: entry.name.clone(),
                    is_framework: entry.name.public_key_token.as_ref().is_some_and(|p| p.is_microsoft()),
                    file_size: entry.file_size,
                }),
                strategy,
                redirect_applied,
                probed_paths,
                failure_reason: None,
            };
        }

        // 4. Framework directories
        for dir in &self.config.framework_dirs {
            let path = dir.join(format!("{}.dll", effective_name.simple_name));
            probed_paths.push(path.clone());
            // Simulate found if it's a well-known framework assembly
            if is_well_known_framework_assembly(&effective_name.simple_name) {
                return ResolutionResult {
                    requested: name.clone(),
                    resolved: Some(ResolvedAssembly {
                        path,
                        actual_name: effective_name,
                        is_framework: true,
                        file_size: 0,
                    }),
                    strategy: ResolutionStrategy::ProbePath,
                    redirect_applied,
                    probed_paths,
                    failure_reason: None,
                };
            }
        }

        // 5. App base
        if let Some(app_base) = &self.config.app_base {
            let dll_path = app_base.join(format!("{}.dll", effective_name.simple_name));
            let exe_path = app_base.join(format!("{}.exe", effective_name.simple_name));
            probed_paths.push(dll_path);
            probed_paths.push(exe_path);

            // Check private bin paths
            for priv_path in &self.config.private_bin_paths {
                let sub_dll = priv_path.join(format!("{}.dll", effective_name.simple_name));
                probed_paths.push(sub_dll);
            }
        }

        ResolutionResult {
            requested: name.clone(),
            resolved: None,
            strategy: ResolutionStrategy::Failed,
            redirect_applied,
            probed_paths,
            failure_reason: Some(format!("Could not locate assembly '{}'", effective_name.simple_name)),
        }
    }

    fn apply_redirects(&self, name: &AssemblyName, applied: &mut Option<BindingRedirect>) -> AssemblyName {
        for redirect in &self.config.binding_redirects {
            if redirect.applies_to(name) {
                *applied = Some(redirect.clone());
                return redirect.redirected_name(name);
            }
        }
        name.clone()
    }

    pub fn resolution_cache_size(&self) -> usize {
        self.resolution_cache.len()
    }

    pub fn resolution_count(&self) -> u32 {
        self.resolution_count
    }

    pub fn clear_cache(&mut self) {
        self.resolution_cache.clear();
    }

    pub fn batch_resolve(&mut self, names: &[AssemblyName]) -> Vec<ResolutionResult> {
        names.iter().map(|n| self.resolve(n)).collect()
    }

    pub fn failed_resolutions(&self) -> Vec<&ResolutionResult> {
        self.resolution_cache.values().filter(|r| !r.succeeded()).collect()
    }

    pub fn redirected_resolutions(&self) -> Vec<&ResolutionResult> {
        self.resolution_cache.values().filter(|r| r.was_redirected()).collect()
    }

    pub fn gac_database(&self) -> &AssemblyDatabase {
        &self.gac_database
    }
}

fn is_well_known_framework_assembly(name: &str) -> bool {
    matches!(name,
        "mscorlib" | "System" | "System.Core" | "System.Runtime" | "System.Collections"
        | "System.Linq" | "System.IO" | "System.Threading" | "System.Text.RegularExpressions"
        | "System.Xml" | "System.Xml.Linq" | "System.Net.Http" | "System.Web"
        | "System.Security" | "System.Drawing" | "System.Windows.Forms"
        | "Microsoft.CSharp" | "WindowsBase" | "PresentationCore" | "PresentationFramework"
        | "System.Runtime.Serialization" | "System.ServiceModel" | "System.Data"
        | "System.Configuration" | "System.Reflection" | "System.Diagnostics.Debug"
        | "System.Console" | "System.Collections.Generic" | "System.Globalization"
    )
}

// ─── Config file parser (app.config / binding redirects) ─────────────────────

pub struct AppConfigParser;

impl AppConfigParser {
    /// Parse binding redirects from an app.config / web.config XML string (simplified).
    pub fn parse_binding_redirects(xml: &str) -> Vec<BindingRedirect> {
        let mut redirects = Vec::new();
        // Very simplified XML parsing: look for assemblyBinding/dependentAssembly patterns
        for block in Self::split_dependent_assembly_blocks(xml) {
            if let Some(redirect) = Self::parse_one_block(&block) {
                redirects.push(redirect);
            }
        }
        redirects
    }

    fn split_dependent_assembly_blocks(xml: &str) -> Vec<String> {
        let start_tag = "<dependentAssembly>";
        let end_tag = "</dependentAssembly>";
        let mut blocks = Vec::new();
        let mut rest = xml;
        while let Some(start) = rest.find(start_tag) {
            rest = &rest[start + start_tag.len()..];
            if let Some(end) = rest.find(end_tag) {
                blocks.push(rest[..end].to_string());
                rest = &rest[end + end_tag.len()..];
            } else {
                break;
            }
        }
        blocks
    }

    fn parse_one_block(block: &str) -> Option<BindingRedirect> {
        let name = Self::extract_attr(block, "name=")?;
        let pkt_str = Self::extract_attr(block, "publicKeyToken=");
        let public_key_token = pkt_str.as_deref().and_then(PublicKeyToken::from_hex);
        let old_range = Self::extract_attr(block, "oldVersion=")?;
        let new_ver_str = Self::extract_attr(block, "newVersion=")?;
        let new_version = AssemblyVersion::parse(&new_ver_str)?;

        let (old_start, old_end) = if let Some(dash) = old_range.find('-') {
            let s = AssemblyVersion::parse(&old_range[..dash])?;
            let e = AssemblyVersion::parse(&old_range[dash+1..])?;
            (s, e)
        } else {
            let v = AssemblyVersion::parse(&old_range)?;
            (v, v)
        };

        Some(BindingRedirect {
            assembly_name: name,
            public_key_token,
            old_version_range_start: old_start,
            old_version_range_end: old_end,
            new_version,
            new_path: None,
        })
    }

    fn extract_attr(text: &str, attr: &str) -> Option<String> {
        let pos = text.find(attr)?;
        let rest = &text[pos + attr.len()..];
        let (quote_char, inner) = if let Some(stripped) = rest.strip_prefix('"') {
            ('"', stripped)
        } else if let Some(stripped) = rest.strip_prefix('\'') {
            ('\'', stripped)
        } else {
            return None;
        };
        let end = inner.find(quote_char)?;
        Some(inner[..end].to_string())
    }
}

// ─── Resolution report ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionReport {
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub redirected: usize,
    pub from_gac: usize,
    pub from_framework: usize,
    pub from_probe: usize,
    pub missing_assemblies: Vec<String>,
    pub redirected_assemblies: Vec<String>,
}

impl ResolutionReport {
    pub fn from_results(results: &[ResolutionResult]) -> Self {
        let total = results.len();
        let succeeded = results.iter().filter(|r| r.succeeded()).count();
        let failed = total - succeeded;
        let redirected = results.iter().filter(|r| r.was_redirected()).count();
        let from_gac = results.iter().filter(|r| matches!(r.strategy, ResolutionStrategy::GacV4 | ResolutionStrategy::GacV2 | ResolutionStrategy::GacV1)).count();
        let from_framework = results.iter().filter(|r| r.resolved.as_ref().is_some_and(|res| res.is_framework)).count();
        let from_probe = results.iter().filter(|r| matches!(r.strategy, ResolutionStrategy::ProbePath | ResolutionStrategy::AppBase | ResolutionStrategy::PrivatePath)).count();
        let missing_assemblies = results.iter().filter(|r| !r.succeeded()).map(|r| r.requested.simple_name.clone()).collect();
        let redirected_assemblies = results.iter().filter(|r| r.was_redirected()).map(|r| r.requested.simple_name.clone()).collect();
        Self { total, succeeded, failed, redirected, from_gac, from_framework, from_probe, missing_assemblies, redirected_assemblies }
    }

    pub fn success_rate(&self) -> f64 {
        if self.total == 0 { 0.0 } else { self.succeeded as f64 / self.total as f64 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms_v4_version() -> AssemblyVersion {
        AssemblyVersion::new(4, 0, 0, 0)
    }

    fn mscorlib_name() -> AssemblyName {
        AssemblyName::new("mscorlib")
            .with_version(ms_v4_version())
            .with_culture("neutral")
            .with_pkt(PublicKeyToken::from_hex("b77a5c561934e089").unwrap())
    }

    #[test]
    fn test_assembly_version_display() {
        let v = AssemblyVersion::new(4, 0, 30319, 0);
        assert_eq!(v.to_string(), "4.0.30319.0");
    }

    #[test]
    fn test_assembly_version_parse() {
        let v = AssemblyVersion::parse("4.0.30319.0").unwrap();
        assert_eq!(v.major, 4);
        assert_eq!(v.build, 30319);
    }

    #[test]
    fn test_assembly_version_compatible() {
        let required = AssemblyVersion::new(4, 0, 0, 0);
        let available = AssemblyVersion::new(4, 0, 30319, 0);
        assert!(available.is_compatible_with(required));
        let lower = AssemblyVersion::new(3, 5, 0, 0);
        assert!(!lower.is_compatible_with(required));
    }

    #[test]
    fn test_public_key_token_hex() {
        let pkt = PublicKeyToken::from_hex("b77a5c561934e089").unwrap();
        assert_eq!(pkt.to_hex(), "b77a5c561934e089");
        assert!(pkt.is_microsoft());
    }

    #[test]
    fn test_assembly_name_display() {
        let name = mscorlib_name();
        assert!(name.display_name().contains("mscorlib"));
        assert!(name.display_name().contains("4.0.0.0"));
        assert!(name.is_strong_named());
    }

    #[test]
    fn test_binding_redirect_applies() {
        let redirect = BindingRedirect {
            assembly_name: "Newtonsoft.Json".into(),
            public_key_token: None,
            old_version_range_start: AssemblyVersion::new(0, 0, 0, 0),
            old_version_range_end: AssemblyVersion::new(12, 0, 0, 0),
            new_version: AssemblyVersion::new(13, 0, 0, 0),
            new_path: None,
        };
        let req = AssemblyName::new("Newtonsoft.Json").with_version(AssemblyVersion::new(6, 0, 0, 0));
        assert!(redirect.applies_to(&req));
        let too_new = AssemblyName::new("Newtonsoft.Json").with_version(AssemblyVersion::new(13, 0, 1, 0));
        assert!(!redirect.applies_to(&too_new));
    }

    #[test]
    fn test_resolver_framework_assembly() {
        let mut resolver = AssemblyResolver::with_default_config();
        let name = mscorlib_name();
        let result = resolver.resolve(&name);
        // Should find via framework dir
        assert_eq!(result.requested.simple_name, "mscorlib");
        // Second call should hit cache
        let result2 = resolver.resolve(&name);
        assert_eq!(result2.requested.simple_name, "mscorlib");
        assert_eq!(resolver.resolution_count(), 2);
        assert_eq!(resolver.resolution_cache_size(), 1); // deduplicated
    }

    #[test]
    fn test_resolver_failure() {
        let mut resolver = AssemblyResolver::with_default_config();
        let name = AssemblyName::new("SomeObscureThirdPartyLib");
        let result = resolver.resolve(&name);
        assert!(!result.succeeded());
        assert!(result.failure_reason.is_some());
    }

    #[test]
    fn test_resolver_with_redirect() {
        let mut resolver = AssemblyResolver::with_default_config();
        resolver.add_binding_redirect(BindingRedirect {
            assembly_name: "Newtonsoft.Json".into(),
            public_key_token: None,
            old_version_range_start: AssemblyVersion::new(0,0,0,0),
            old_version_range_end: AssemblyVersion::new(12,99,99,99),
            new_version: AssemblyVersion::new(13,0,3,0),
            new_path: None,
        });
        let old = AssemblyName::new("Newtonsoft.Json").with_version(AssemblyVersion::new(6,0,0,0));
        let result = resolver.resolve(&old);
        assert!(result.was_redirected());
        assert_eq!(result.redirect_applied.as_ref().unwrap().new_version, AssemblyVersion::new(13,0,3,0));
    }

    #[test]
    fn test_app_config_parser() {
        let xml = r#"
<configuration>
  <runtime>
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <dependentAssembly>
        <assemblyIdentity name="Newtonsoft.Json" publicKeyToken="30ad4fe6b2a6aeed"/>
        <bindingRedirect oldVersion="0.0.0.0-12.0.0.0" newVersion="13.0.0.0"/>
      </dependentAssembly>
    </assemblyBinding>
  </runtime>
</configuration>"#;
        let redirects = AppConfigParser::parse_binding_redirects(xml);
        assert_eq!(redirects.len(), 1);
        assert_eq!(redirects[0].assembly_name, "Newtonsoft.Json");
        assert_eq!(redirects[0].new_version, AssemblyVersion::new(13, 0, 0, 0));
    }

    #[test]
    fn test_gac_database_lookup() {
        let mut db = AssemblyDatabase::new();
        let entry = GacEntry {
            name: mscorlib_name(),
            path: PathBuf::from(r"C:\Windows\Microsoft.NET\assembly\GAC_MSIL\mscorlib\v4.0_4.0.0.0__b77a5c561934e089\mscorlib.dll"),
            gac_version: GacVersion::V4,
            file_size: 5_500_000,
        };
        db.register(entry);
        let found = db.lookup_best_version(&mscorlib_name());
        assert!(found.is_some());
        assert_eq!(found.unwrap().name.simple_name, "mscorlib");
    }
}
