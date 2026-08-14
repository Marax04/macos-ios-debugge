// IPA static analysis — Mach-O binary inspection, linked frameworks,
// URL schemes, permission usage descriptions, exported symbols, and
// security-relevant metadata without executing the binary.

use std::collections::{HashMap, HashSet};
use crate::plist_parser::{PlistParser, PlistValue};

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum AnalysisError {
    NoBinary,
    NoPlist,
    PlistParse(String),
    MachoParse(String),
    Utf8(String),
}

impl std::fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoBinary => write!(f, "no main binary found"),
            Self::NoPlist => write!(f, "Info.plist not found"),
            Self::PlistParse(s) => write!(f, "plist parse error: {s}"),
            Self::MachoParse(s) => write!(f, "Mach-O parse error: {s}"),
            Self::Utf8(s) => write!(f, "UTF-8 error: {s}"),
        }
    }
}

impl std::error::Error for AnalysisError {}

// ── Mach-O constants ──────────────────────────────────────────────────────────

const MH_MAGIC: u32 = 0xFEED_FACE;
const MH_CIGAM: u32 = 0xCEFA_EDFE;
const MH_MAGIC_64: u32 = 0xFEED_FACF;
const MH_CIGAM_64: u32 = 0xCFFA_EDFE;
const FAT_MAGIC: u32 = 0xCAFE_BABE;
const FAT_CIGAM: u32 = 0xBEBA_FECA;

const LC_SEGMENT: u32 = 0x1;
const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x2;
const LC_LOAD_DYLIB: u32 = 0xC;
const LC_ID_DYLIB: u32 = 0xD;
const LC_RPATH: u32 = 0x8000_001C;
const LC_UUID: u32 = 0x1B;
const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
const LC_BUILD_VERSION: u32 = 0x32;
const LC_CODE_SIGNATURE: u32 = 0x1D;
const LC_ENCRYPTION_INFO: u32 = 0x21;
const LC_ENCRYPTION_INFO_64: u32 = 0x2C;
const LC_SOURCE_VERSION: u32 = 0x2A;

// CPU types
const CPU_TYPE_ARM: i32 = 12;
const CPU_TYPE_ARM64: i32 = 0x0100_000C;
const CPU_TYPE_X86: i32 = 7;
const CPU_TYPE_X86_64: i32 = 0x0100_0007;

// ── Result structs ────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct MachOSlice {
    pub arch: String,
    pub cpu_type: i32,
    pub cpu_subtype: i32,
    /// Packed attribute flags. Use accessor methods.
    pub attr_flags: u8,
    pub file_type: u32,
    pub flags: u32,
    pub linked_dylibs: Vec<String>,
    pub rpath_entries: Vec<String>,
    pub segments: Vec<SegmentInfo>,
    pub uuid: Option<[u8; 16]>,
    pub min_ios_version: Option<(u16, u16, u16)>, // major.minor.patch
    pub exported_symbol_count: usize,
    pub imported_symbol_count: usize,
    pub source_version: Option<u64>,
}
impl MachOSlice {
    pub const IS_64BIT: u8 = 1;
    pub const LITTLE_ENDIAN: u8 = 2;
    pub const IS_ENCRYPTED: u8 = 4;
    pub const HAS_CODE_SIGNATURE: u8 = 8;
    #[must_use] pub const fn is_64bit(&self) -> bool { self.attr_flags & Self::IS_64BIT != 0 }
    #[must_use] pub const fn little_endian(&self) -> bool { self.attr_flags & Self::LITTLE_ENDIAN != 0 }
    #[must_use] pub const fn is_encrypted(&self) -> bool { self.attr_flags & Self::IS_ENCRYPTED != 0 }
    #[must_use] pub const fn has_code_signature(&self) -> bool { self.attr_flags & Self::HAS_CODE_SIGNATURE != 0 }
}

#[derive(Debug, Default, Clone)]
pub struct SegmentInfo {
    pub name: String,
    pub vm_addr: u64,
    pub vm_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub init_prot: u32,
    pub max_prot: u32,
    pub section_count: u32,
    pub sections: Vec<SectionInfo>,
}

#[derive(Debug, Default, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub segment: String,
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub flags: u32,
}

#[derive(Debug, Default, Clone)]
pub struct AppPermissions {
    pub usage_descriptions: HashMap<String, String>,
    pub entitlement_keys: Vec<String>,
    pub has_push_notifications: bool,
    pub has_background_modes: Vec<String>,
    pub has_associated_domains: Vec<String>,
    pub has_app_groups: Vec<String>,
    pub has_keychain_sharing: bool,
    pub network_config: NetworkSecurityConfig,
}

#[derive(Debug, Default, Clone)]
pub struct NetworkSecurityConfig {
    pub allows_arbitrary_loads: bool,
    pub allows_local_networking: bool,
    pub exception_domains: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct UrlSchemeInfo {
    pub schemes: Vec<String>,
    pub queried_schemes: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct IpaAnalysisResult {
    pub bundle_id: Option<String>,
    pub bundle_name: Option<String>,
    pub bundle_version: Option<String>,
    pub bundle_short_version: Option<String>,
    pub minimum_os_version: Option<String>,
    pub platform: Option<String>,
    pub executable_name: Option<String>,
    pub ui_launch_storyboard: Option<String>,
    pub main_storyboard: Option<String>,
    pub device_families: Vec<u64>,
    pub macho_slices: Vec<MachOSlice>,
    pub frameworks: Vec<FrameworkInfo>,
    pub plugins: Vec<PluginInfo>,
    pub url_schemes: UrlSchemeInfo,
    pub permissions: AppPermissions,
    pub build_settings: HashMap<String, String>,
    pub swift_present: bool,
    pub objc_present: bool,
    pub bitcode_present: bool,
    pub exported_symbols: Vec<String>,
    pub imported_symbols: Vec<String>,
    pub strings_of_interest: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct FrameworkInfo {
    pub name: String,
    pub bundle_id: Option<String>,
    pub version: Option<String>,
    pub is_system: bool,
    pub is_embedded: bool,
}

#[derive(Debug, Default, Clone)]
pub struct PluginInfo {
    pub name: String,
    pub bundle_id: Option<String>,
    pub extension_point: Option<String>,
}

// ── Main analyzer ─────────────────────────────────────────────────────────────

pub struct IpaAnalyzer;

impl IpaAnalyzer {
    /// Perform full static analysis of an IPA.
    ///
    /// # Errors
    /// Returns [`AnalysisError::PlistParse`] if the Info.plist cannot be parsed,
    /// or [`AnalysisError::MachoParse`] if the Mach-O binary cannot be parsed.
    pub fn analyze(
        binary: Option<&[u8]>,
        info_plist: Option<&[u8]>,
        entitlements_plist: Option<&[u8]>,
        framework_infos: &[(String, Option<Vec<u8>>)],
        plugin_infos: &[(String, Option<Vec<u8>>)],
    ) -> Result<IpaAnalysisResult, AnalysisError> {
        let mut result = IpaAnalysisResult::default();

        // Parse Info.plist
        if let Some(plist_bytes) = info_plist {
            let plist = PlistParser::parse(plist_bytes)
                .map_err(|e| AnalysisError::PlistParse(e.to_string()))?;
            extract_info_plist(&plist, &mut result);
        }

        // Parse entitlements
        if let Some(ent_bytes) = entitlements_plist
            && let Ok(plist) = PlistParser::parse(ent_bytes)
        {
            extract_entitlements(&plist, &mut result.permissions);
        }

        // Parse Mach-O binary
        if let Some(bin) = binary {
            let slices = parse_macho_fat(bin)
                .map_err(AnalysisError::MachoParse)?;
            result.swift_present = slices.iter().any(|s| {
                s.segments.iter().any(|seg| {
                    seg.sections.iter().any(|sec| sec.name.starts_with("__swift"))
                })
            });
            result.objc_present = slices.iter().any(|s| {
                s.segments.iter().any(|seg| {
                    seg.sections.iter().any(|sec| sec.name == "__objc_classlist")
                })
            });
            result.bitcode_present = slices.iter().any(|s| {
                s.segments.iter().any(|seg| seg.name == "__LLVM")
            });
            // Collect dylib names from all slices
            let all_dylibs: HashSet<String> = slices.iter()
                .flat_map(|s| s.linked_dylibs.iter().cloned())
                .collect();
            for dylib in &all_dylibs {
                if is_system_framework(dylib) {
                    let name = framework_name_from_path(dylib);
                    result.frameworks.push(FrameworkInfo {
                        name,
                        bundle_id: None,
                        version: None,
                        is_system: true,
                        is_embedded: false,
                    });
                }
            }
            result.macho_slices = slices;
        }

        // Parse embedded frameworks
        for (path, info_opt) in framework_infos {
            let name = framework_display_name(path);
            let mut fw = FrameworkInfo {
                name,
                bundle_id: None,
                version: None,
                is_system: false,
                is_embedded: true,
            };
            if let Some(info_bytes) = info_opt
                && let Ok(plist) = PlistParser::parse(info_bytes)
            {
                fw.bundle_id = plist.dict_get("CFBundleIdentifier")
                    .and_then(|v| v.as_str()).map(ToString::to_string);
                fw.version = plist.dict_get("CFBundleShortVersionString")
                    .or_else(|| plist.dict_get("CFBundleVersion"))
                    .and_then(|v| v.as_str()).map(ToString::to_string);
            }
            result.frameworks.push(fw);
        }

        // Parse plugins
        for (path, info_opt) in plugin_infos {
            let name = framework_display_name(path);
            let mut plugin = PluginInfo { name, bundle_id: None, extension_point: None };
            if let Some(info_bytes) = info_opt
                && let Ok(plist) = PlistParser::parse(info_bytes)
            {
                plugin.bundle_id = plist.dict_get("CFBundleIdentifier")
                    .and_then(|v| v.as_str()).map(ToString::to_string);
                // NSExtension.NSExtensionPointIdentifier
                plugin.extension_point = plist.dict_get("NSExtension")
                    .and_then(|ext| ext.dict_get("NSExtensionPointIdentifier"))
                    .and_then(|v| v.as_str()).map(ToString::to_string);
            }
            result.plugins.push(plugin);
        }

        Ok(result)
    }

    /// Generate a human-readable summary of the analysis result.
    #[must_use]
    pub fn summarize(r: &IpaAnalysisResult) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();

        out.push_str("=== IPA Analysis Summary ===\n\n");

        if let Some(id) = &r.bundle_id {
            writeln!(out, "Bundle ID:        {id}").ok();
        }
        if let Some(name) = &r.bundle_name {
            writeln!(out, "Name:             {name}").ok();
        }
        if let Some(ver) = &r.bundle_version {
            writeln!(out, "Build:            {ver}").ok();
        }
        if let Some(short) = &r.bundle_short_version {
            writeln!(out, "Version:          {short}").ok();
        }
        if let Some(os) = &r.minimum_os_version {
            writeln!(out, "Min iOS:          {os}").ok();
        }
        if let Some(exe) = &r.executable_name {
            writeln!(out, "Executable:       {exe}").ok();
        }

        out.push('\n');

        // Architectures
        if !r.macho_slices.is_empty() {
            out.push_str("Architectures:\n");
            for s in &r.macho_slices {
                let enc = if s.is_encrypted() { " [ENCRYPTED]" } else { "" };
                writeln!(out, "  {}{}", s.arch, enc).ok();
            }
            out.push('\n');
        }

        // Features
        let mut features = Vec::new();
        if r.swift_present { features.push("Swift"); }
        if r.objc_present { features.push("Objective-C"); }
        if r.bitcode_present { features.push("Bitcode"); }
        if !features.is_empty() {
            write!(out, "Languages/features: {}\n\n", features.join(", ")).ok();
        }

        // URL schemes
        if !r.url_schemes.schemes.is_empty() {
            out.push_str("URL Schemes (registered):\n");
            for s in &r.url_schemes.schemes {
                writeln!(out, "  {s}").ok();
            }
            out.push('\n');
        }
        if !r.url_schemes.queried_schemes.is_empty() {
            out.push_str("URL Schemes (queried):\n");
            for s in &r.url_schemes.queried_schemes {
                writeln!(out, "  {s}").ok();
            }
            out.push('\n');
        }

        // Permissions
        if !r.permissions.usage_descriptions.is_empty() {
            out.push_str("Privacy permissions:\n");
            let mut keys: Vec<_> = r.permissions.usage_descriptions.keys().collect();
            keys.sort();
            for k in keys {
                writeln!(out, "  {k}").ok();
            }
            out.push('\n');
        }

        // Embedded frameworks
        let embedded: Vec<_> = r.frameworks.iter().filter(|f| f.is_embedded).collect();
        if !embedded.is_empty() {
            out.push_str("Embedded frameworks:\n");
            for fw in &embedded {
                let ver = fw.version.as_deref().unwrap_or("?");
                writeln!(out, "  {} ({})", fw.name, ver).ok();
            }
            out.push('\n');
        }

        // Plugins
        if !r.plugins.is_empty() {
            out.push_str("App extensions:\n");
            for p in &r.plugins {
                let ep = p.extension_point.as_deref().unwrap_or("unknown");
                writeln!(out, "  {} [{}]", p.name, ep).ok();
            }
            out.push('\n');
        }

        // Security flags
        out.push_str("Security:\n");
        let ats_ok = !r.permissions.network_config.allows_arbitrary_loads;
        writeln!(out, "  ATS enabled:         {ats_ok}").ok();
        let encrypted = r.macho_slices.iter().any(MachOSlice::is_encrypted);
        writeln!(out, "  Binary encrypted:    {encrypted}").ok();
        let has_sig = r.macho_slices.iter().any(MachOSlice::has_code_signature);
        writeln!(out, "  Code signature LC:   {has_sig}").ok();

        out
    }
}

// ── Mach-O parser ─────────────────────────────────────────────────────────────

fn parse_macho_fat(data: &[u8]) -> Result<Vec<MachOSlice>, String> {
    if data.len() < 4 {
        return Err("file too small".into());
    }
    let magic = u32::from_be_bytes(data[0..4].try_into().unwrap());
    match magic {
        FAT_MAGIC | FAT_CIGAM => parse_fat_binary(data),
        _ => {
            let slice = parse_macho_thin(data, 0)?;
            Ok(vec![slice])
        }
    }
}

fn parse_fat_binary(data: &[u8]) -> Result<Vec<MachOSlice>, String> {
    if data.len() < 8 { return Err("fat binary too small".into()); }
    let nfat = u32::from_be_bytes(data[4..8].try_into().unwrap()) as usize;
    let mut slices = Vec::new();
    for i in 0..nfat {
        let base = 8 + i * 20;
        if base + 20 > data.len() { break; }
        let offset = u32::from_be_bytes(data[base + 8..base + 12].try_into().unwrap()) as usize;
        let size = u32::from_be_bytes(data[base + 12..base + 16].try_into().unwrap()) as usize;
        if offset + size > data.len() { continue; }
        if let Ok(s) = parse_macho_thin(&data[offset..offset + size], offset) {
            slices.push(s);
        }
    }
    Ok(slices)
}

fn macho_r32(buf: &[u8], off: usize, le: bool) -> u32 {
    let b: [u8; 4] = buf[off..off + 4].try_into().unwrap();
    if le { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) }
}
fn macho_r64(buf: &[u8], off: usize, le: bool) -> u64 {
    let b: [u8; 8] = buf[off..off + 8].try_into().unwrap();
    if le { u64::from_le_bytes(b) } else { u64::from_be_bytes(b) }
}
fn macho_r16(buf: &[u8], off: usize, le: bool) -> u16 {
    let b: [u8; 2] = buf[off..off + 2].try_into().unwrap();
    if le { u16::from_le_bytes(b) } else { u16::from_be_bytes(b) }
}
const fn ver_triple(v: u32) -> (u16, u16, u16) {
    ((v >> 16) as u16, ((v >> 8) & 0xff) as u16, (v & 0xff) as u16)
}

fn apply_load_command(cmd: u32, lc_data: &[u8], cmdsize: usize, le: bool, slice: &mut MachOSlice) {
    match cmd {
        LC_SEGMENT | LC_SEGMENT_64 => {
            let r32 = |b: &[u8], o: usize| macho_r32(b, o, le);
            let r64 = |b: &[u8], o: usize| macho_r64(b, o, le);
            let r16 = |b: &[u8], o: usize| macho_r16(b, o, le);
            slice.segments.push(parse_segment(lc_data, cmd == LC_SEGMENT_64, &r32, &r64, &r16));
        }
        LC_LOAD_DYLIB | LC_ID_DYLIB => {
            if cmdsize >= 12 {
                let name_off = macho_r32(lc_data, 8, le) as usize;
                if name_off < cmdsize && cmd == LC_LOAD_DYLIB {
                    slice.linked_dylibs.push(cstr_from(&lc_data[name_off..]));
                }
            }
        }
        LC_RPATH => {
            let off = macho_r32(lc_data, 8, le) as usize;
            if off < cmdsize { slice.rpath_entries.push(cstr_from(&lc_data[off..])); }
        }
        LC_UUID => {
            if cmdsize >= 24 {
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&lc_data[8..24]);
                slice.uuid = Some(uuid);
            }
        }
        LC_VERSION_MIN_IPHONEOS => {
            if cmdsize >= 16 { slice.min_ios_version = Some(ver_triple(macho_r32(lc_data, 8, le))); }
        }
        LC_BUILD_VERSION => {
            if cmdsize >= 20 { slice.min_ios_version = Some(ver_triple(macho_r32(lc_data, 12, le))); }
        }
        LC_CODE_SIGNATURE => { slice.attr_flags |= MachOSlice::HAS_CODE_SIGNATURE; }
        LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 => {
            if cmdsize >= 20 {
                if macho_r32(lc_data, 16, le) != 0 { slice.attr_flags |= MachOSlice::IS_ENCRYPTED; }
                else { slice.attr_flags &= !MachOSlice::IS_ENCRYPTED; }
            }
        }
        LC_SOURCE_VERSION => {
            if cmdsize >= 16 { slice.source_version = Some(macho_r64(lc_data, 8, le)); }
        }
        LC_SYMTAB
            if cmdsize >= 24 => {
                let nsyms = macho_r32(lc_data, 12, le) as usize;
                slice.exported_symbol_count = nsyms / 2;
                slice.imported_symbol_count = nsyms - nsyms / 2;
            }
        _ => {}
    }
}

fn parse_macho_thin(data: &[u8], _fat_offset: usize) -> Result<MachOSlice, String> {
    if data.len() < 8 { return Err("too small".into()); }
    let magic = u32::from_ne_bytes(data[0..4].try_into().unwrap());
    let (swap, is64) = match magic {
        MH_MAGIC => (false, false),
        MH_CIGAM => (true, false),
        MH_MAGIC_64 => (false, true),
        MH_CIGAM_64 => (true, true),
        _ => return Err(format!("bad magic {magic:#010x}")),
    };
    let le = !swap;
    let cpu_type = macho_r32(data, 4, le).cast_signed();
    let cpu_subtype = macho_r32(data, 8, le).cast_signed();
    let file_type = macho_r32(data, 12, le);
    let ncmds = macho_r32(data, 16, le) as usize;
    let flags = macho_r32(data, 24, le);
    let hdr_size: usize = if is64 { 32 } else { 28 };
    let mut attr_flags = 0u8;
    if is64 { attr_flags |= MachOSlice::IS_64BIT; }
    if le { attr_flags |= MachOSlice::LITTLE_ENDIAN; }
    let mut slice = MachOSlice { arch: cpu_arch_name(cpu_type, cpu_subtype), cpu_type, cpu_subtype, attr_flags, file_type, flags, ..Default::default() };
    let mut lc_off = hdr_size;
    for _ in 0..ncmds {
        if lc_off + 8 > data.len() { break; }
        let cmd = macho_r32(data, lc_off, le);
        let cmdsize = macho_r32(data, lc_off + 4, le) as usize;
        if cmdsize < 8 || lc_off + cmdsize > data.len() { break; }
        apply_load_command(cmd, &data[lc_off..lc_off + cmdsize], cmdsize, le, &mut slice);
        lc_off += cmdsize;
    }
    Ok(slice)
}

fn parse_segment<F32, F64, F16>(
    data: &[u8],
    is64: bool,
    r32: &F32,
    r64: &F64,
    _r16: &F16,
) -> SegmentInfo
where
    F32: Fn(&[u8], usize) -> u32,
    F64: Fn(&[u8], usize) -> u64,
    F16: Fn(&[u8], usize) -> u16,
{
    let name = segment_name(&data[8..24]);
    if is64 {
        let vm_addr = r64(data, 24);
        let vm_size = r64(data, 32);
        let file_offset = r64(data, 40);
        let file_size = r64(data, 48);
        let max_prot = r32(data, 56);
        let init_prot = r32(data, 60);
        let nsects = r32(data, 64);
        let mut sections = Vec::new();
        let sect_base = 72usize;
        for i in 0..nsects as usize {
            let off = sect_base + i * 80;
            if off + 80 > data.len() { break; }
            sections.push(parse_section64(&data[off..off + 80]));
        }
        SegmentInfo { name, vm_addr, vm_size, file_offset, file_size, init_prot, max_prot, section_count: nsects, sections }
    } else {
        let vm_addr = u64::from(r32(data, 24));
        let vm_size = u64::from(r32(data, 28));
        let file_offset = u64::from(r32(data, 32));
        let file_size = u64::from(r32(data, 36));
        let max_prot = r32(data, 40);
        let init_prot = r32(data, 44);
        let nsects = r32(data, 48);
        let mut sections = Vec::new();
        let sect_base = 56usize;
        for i in 0..nsects as usize {
            let off = sect_base + i * 68;
            if off + 68 > data.len() { break; }
            sections.push(parse_section32(&data[off..off + 68]));
        }
        SegmentInfo { name, vm_addr, vm_size, file_offset, file_size, init_prot, max_prot, section_count: nsects, sections }
    }
}

fn parse_section64(data: &[u8]) -> SectionInfo {
    let name = segment_name(&data[0..16]);
    let segment = segment_name(&data[16..32]);
    let addr = u64::from_le_bytes(data[32..40].try_into().unwrap_or([0; 8]));
    let size = u64::from_le_bytes(data[40..48].try_into().unwrap_or([0; 8]));
    let offset = u32::from_le_bytes(data[48..52].try_into().unwrap_or([0; 4]));
    let flags = u32::from_le_bytes(data[64..68].try_into().unwrap_or([0; 4]));
    SectionInfo { name, segment, addr, size, offset, flags }
}

fn parse_section32(data: &[u8]) -> SectionInfo {
    let name = segment_name(&data[0..16]);
    let segment = segment_name(&data[16..32]);
    let addr = u64::from(u32::from_le_bytes(data[32..36].try_into().unwrap_or([0; 4])));
    let size = u64::from(u32::from_le_bytes(data[36..40].try_into().unwrap_or([0; 4])));
    let offset = u32::from_le_bytes(data[40..44].try_into().unwrap_or([0; 4]));
    let flags = u32::from_le_bytes(data[56..60].try_into().unwrap_or([0; 4]));
    SectionInfo { name, segment, addr, size, offset, flags }
}

fn segment_name(b: &[u8]) -> String {
    let end = b.iter().position(|&x| x == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).to_string()
}

fn cstr_from(b: &[u8]) -> String {
    let end = b.iter().position(|&x| x == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).to_string()
}

fn cpu_arch_name(cpu_type: i32, cpu_subtype: i32) -> String {
    match cpu_type {
        CPU_TYPE_ARM64 => {
            if cpu_subtype == 2 { "arm64e".into() } else { "arm64".into() }
        }
        CPU_TYPE_ARM => "armv7".into(),
        CPU_TYPE_X86_64 => "x86_64".into(),
        CPU_TYPE_X86 => "i386".into(),
        _ => format!("cpu{cpu_type:#010x}"),
    }
}

// ── Info.plist extraction ─────────────────────────────────────────────────────

fn extract_info_plist(plist: &PlistValue, r: &mut IpaAnalysisResult) {
    r.bundle_id = str_key(plist, "CFBundleIdentifier");
    r.bundle_name = str_key(plist, "CFBundleDisplayName")
        .or_else(|| str_key(plist, "CFBundleName"));
    r.bundle_version = str_key(plist, "CFBundleVersion");
    r.bundle_short_version = str_key(plist, "CFBundleShortVersionString");
    r.minimum_os_version = str_key(plist, "MinimumOSVersion")
        .or_else(|| str_key(plist, "LSMinimumSystemVersion"));
    r.executable_name = str_key(plist, "CFBundleExecutable");
    r.ui_launch_storyboard = str_key(plist, "UILaunchStoryboardName");
    r.main_storyboard = str_key(plist, "NSMainStoryboardFile");
    r.platform = str_key(plist, "CFBundleSupportedPlatforms")
        .or_else(|| str_key(plist, "DTPlatformName"));

    // Device families
    if let Some(PlistValue::Array(arr)) = plist.dict_get("UIDeviceFamily") {
        for v in arr {
            if let Some(n) = v.as_i64() { r.device_families.push(n.cast_unsigned()); }
        }
    }

    // URL schemes
    if let Some(PlistValue::Array(url_types)) = plist.dict_get("CFBundleURLTypes") {
        for ut in url_types {
            if let Some(PlistValue::Array(schemes)) = ut.dict_get("CFBundleURLSchemes") {
                for s in schemes {
                    if let Some(scheme) = s.as_str() {
                        r.url_schemes.schemes.push(scheme.to_lowercase());
                    }
                }
            }
        }
    }
    if let Some(PlistValue::Array(queried)) = plist.dict_get("LSApplicationQueriesSchemes") {
        for s in queried {
            if let Some(scheme) = s.as_str() {
                r.url_schemes.queried_schemes.push(scheme.to_lowercase());
            }
        }
    }

    // Privacy usage descriptions (keys ending in UsageDescription)
    if let Some(dict) = plist.as_dict() {
        for (k, v) in dict.iter() {
            if k.ends_with("UsageDescription")
                && let Some(desc) = v.as_str() {
                    r.permissions.usage_descriptions.insert(k.to_string(), desc.to_string());
                }
        }
    }

    // Background modes
    if let Some(PlistValue::Array(modes)) = plist.dict_get("UIBackgroundModes") {
        for m in modes {
            if let Some(s) = m.as_str() {
                r.permissions.has_background_modes.push(s.to_string());
            }
        }
    }

    // ATS
    if let Some(ats) = plist.dict_get("NSAppTransportSecurity") {
        r.permissions.network_config.allows_arbitrary_loads =
            ats.dict_get("NSAllowsArbitraryLoads").and_then(PlistValue::as_bool).unwrap_or(false);
        r.permissions.network_config.allows_local_networking =
            ats.dict_get("NSAllowsLocalNetworking").and_then(PlistValue::as_bool).unwrap_or(false);
        if let Some(PlistValue::Dict(exceptions)) = ats.dict_get("NSExceptionDomains") {
            for (domain, _) in exceptions.iter() {
                r.permissions.network_config.exception_domains.push(domain.to_string());
            }
        }
    }

    // Push notification
    if let Some(PlistValue::Dict(caps)) = plist.dict_get("UIRequiredDeviceCapabilities")
        && caps.contains_key("push-notifications")
    {
        r.permissions.has_push_notifications = true;
    }
}

fn str_key(plist: &PlistValue, key: &str) -> Option<String> {
    plist.dict_get(key)?.as_str().map(ToString::to_string)
}

// ── Entitlements extraction ───────────────────────────────────────────────────

fn extract_entitlements(plist: &PlistValue, perms: &mut AppPermissions) {
    if let Some(dict) = plist.as_dict() {
        for (k, v) in dict.iter() {
            perms.entitlement_keys.push(k.to_string());
            match k {
                "aps-environment" => perms.has_push_notifications = true,
                "com.apple.developer.associated-domains" => {
                    if let Some(arr) = v.as_array() {
                        for d in arr {
                            if let Some(s) = d.as_str() {
                                perms.has_associated_domains.push(s.to_string());
                            }
                        }
                    }
                }
                "com.apple.security.application-groups" => {
                    if let Some(arr) = v.as_array() {
                        for g in arr {
                            if let Some(s) = g.as_str() {
                                perms.has_app_groups.push(s.to_string());
                            }
                        }
                    }
                }
                "keychain-access-groups" => {
                    perms.has_keychain_sharing = true;
                }
                _ => {}
            }
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn is_system_framework(path: &str) -> bool {
    path.contains("/usr/lib/") || path.contains("/System/Library/")
        || path.contains("@rpath/") && !path.contains("Frameworks/")
}

fn framework_name_from_path(path: &str) -> String {
    // e.g. /System/Library/Frameworks/UIKit.framework/UIKit → UIKit
    path.split('/').rev()
        .find(|s| !s.is_empty() && *s != "UIKit")
        .map_or_else(|| path.to_string(), |s| s.trim_end_matches(".framework").to_string())
}

fn framework_display_name(path: &str) -> String {
    // Extract "SomeLib" from paths like Frameworks/SomeLib.framework/
    for part in path.split('/') {
        let pl = part.to_ascii_lowercase();
        if pl.ends_with(".framework") || std::path::Path::new(part).extension().is_some_and(|e| e.eq_ignore_ascii_case("appex")) {
            return part.trim_end_matches(".framework")
                .trim_end_matches(".appex")
                .to_string();
        }
    }
    path.split('/').next_back().unwrap_or(path).to_string()
}

// ── Security risk scoring ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RiskItem {
    pub severity: RiskSeverity,
    pub category: &'static str,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskSeverity { Low, Medium, High, Critical }

impl std::fmt::Display for RiskSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[must_use]
pub fn security_risks(r: &IpaAnalysisResult) -> Vec<RiskItem> {
    let mut risks = Vec::new();

    if r.permissions.network_config.allows_arbitrary_loads {
        risks.push(RiskItem {
            severity: RiskSeverity::High,
            category: "network",
            description: "NSAllowsArbitraryLoads disables ATS — all HTTP traffic is permitted".into(),
        });
    }

    for domain in &r.permissions.network_config.exception_domains {
        risks.push(RiskItem {
            severity: RiskSeverity::Medium,
            category: "network",
            description: format!("ATS exception domain: {domain}"),
        });
    }

    if r.macho_slices.iter().any(|s| !s.is_encrypted()) && !r.macho_slices.is_empty() {
        risks.push(RiskItem {
            severity: RiskSeverity::Medium,
            category: "binary",
            description: "Binary is not encrypted (not from App Store or encryption stripped)".into(),
        });
    }

    if !r.macho_slices.iter().any(MachOSlice::has_code_signature) && !r.macho_slices.is_empty() {
        risks.push(RiskItem {
            severity: RiskSeverity::High,
            category: "binary",
            description: "No code signature load command found".into(),
        });
    }

    if r.permissions.has_push_notifications {
        risks.push(RiskItem {
            severity: RiskSeverity::Low,
            category: "capabilities",
            description: "App uses push notifications (aps-environment entitlement)".into(),
        });
    }

    if r.permissions.has_keychain_sharing {
        risks.push(RiskItem {
            severity: RiskSeverity::Medium,
            category: "storage",
            description: "Keychain access groups configured — potential credential sharing between apps".into(),
        });
    }

    for bg in &r.permissions.has_background_modes {
        if bg == "fetch" || bg == "remote-notification" || bg == "processing" {
            risks.push(RiskItem {
                severity: RiskSeverity::Low,
                category: "background",
                description: format!("Background mode: {bg}"),
            });
        }
    }

    // Check dangerous URL schemes that could be hijacked
    let dangerous_schemes = ["fb", "twitter", "snapchat", "instagram", "tg", "whatsapp"];
    for scheme in &r.url_schemes.queried_schemes {
        if dangerous_schemes.iter().any(|d| scheme.starts_with(d)) {
            risks.push(RiskItem {
                severity: RiskSeverity::Low,
                category: "urlscheme",
                description: format!("Queries third-party app scheme: {scheme}"),
            });
        }
    }

    // Sort by severity descending
    risks.sort_by(|a, b| b.severity.cmp(&a.severity));
    risks
}

// ── String scanner ────────────────────────────────────────────────────────────

/// Extract printable ASCII strings of at least `min_len` from a binary blob,
/// optionally filtering to those matching any of the interest patterns.
#[must_use]
pub fn extract_strings(data: &[u8], min_len: usize, max_count: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut run_start = None;

    for (i, &b) in data.iter().enumerate() {
        if (0x20..0x7f).contains(&b) {
            if run_start.is_none() { run_start = Some(i); }
        } else if let Some(start) = run_start.take() {
            let len = i - start;
            if len >= min_len {
                let s = std::str::from_utf8(&data[start..i]).unwrap_or("").to_string();
                out.push(s);
                if out.len() >= max_count { break; }
            }
        }
    }
    out
}

/// Filter extracted strings to those likely interesting for analysis.
#[must_use]
pub fn filter_interesting_strings(strings: &[String]) -> Vec<String> {
    let patterns = [
        "http://", "https://", "ftp://", "ws://", "wss://",
        "api.", "cdn.", "s3.", ".amazonaws.com", ".cloudfront.net",
        "Authorization", "Bearer ", "token", "secret", "password",
        "BEGIN CERTIFICATE", "BEGIN PRIVATE KEY", "BEGIN RSA",
        "sqlite", ".db", "keychain", "UserDefaults",
        "NSLog", "NSAssert", "assert", "TODO", "FIXME", "HACK",
        "192.168.", "10.0.", "localhost", "127.0.0.1",
    ];
    strings.iter()
        .filter(|s| {
            let lower = s.to_lowercase();
            patterns.iter().any(|p| lower.contains(p))
        })
        .cloned()
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_analysis() {
        let xml = br#"<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>com.test.app</string>
  <key>CFBundleVersion</key><string>100</string>
  <key>CFBundleShortVersionString</key><string>2.5.1</string>
  <key>MinimumOSVersion</key><string>15.0</string>
  <key>CFBundleExecutable</key><string>TestApp</string>
  <key>NSCameraUsageDescription</key><string>Camera for scanning</string>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsArbitraryLoads</key><true/>
  </dict>
</dict>
</plist>"#;
        let r = IpaAnalyzer::analyze(None, Some(xml), None, &[], &[]).unwrap();
        assert_eq!(r.bundle_id.as_deref(), Some("com.test.app"));
        assert_eq!(r.bundle_short_version.as_deref(), Some("2.5.1"));
        assert!(r.permissions.usage_descriptions.contains_key("NSCameraUsageDescription"));
        assert!(r.permissions.network_config.allows_arbitrary_loads);
        let risks = security_risks(&r);
        assert!(risks.iter().any(|ri| ri.severity == RiskSeverity::High));
    }

    #[test]
    fn test_url_schemes() {
        let xml = br#"<plist version="1.0">
<dict>
  <key>CFBundleURLTypes</key>
  <array>
    <dict>
      <key>CFBundleURLSchemes</key>
      <array><string>myapp</string><string>myapp-debug</string></array>
    </dict>
  </array>
  <key>LSApplicationQueriesSchemes</key>
  <array><string>fb</string><string>twitter</string></array>
</dict>
</plist>"#;
        let r = IpaAnalyzer::analyze(None, Some(xml), None, &[], &[]).unwrap();
        assert!(r.url_schemes.schemes.contains(&"myapp".to_string()));
        assert!(r.url_schemes.queried_schemes.contains(&"twitter".to_string()));
    }

    #[test]
    fn test_extract_strings() {
        let data = b"hello\x00world\x00this is a long enough string\x00ab";
        let strings = extract_strings(data, 5, 100);
        assert!(strings.iter().any(|s| s == "hello"));
        assert!(strings.iter().any(|s| s.contains("long enough")));
    }

    #[test]
    fn test_framework_display_name() {
        assert_eq!(framework_display_name("Frameworks/Alamofire.framework/"), "Alamofire");
        assert_eq!(framework_display_name("PlugIns/ShareExtension.appex"), "ShareExtension");
    }

    #[test]
    fn test_segment_name_strip_nulls() {
        let b = b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert_eq!(segment_name(b), "__TEXT");
    }
}
