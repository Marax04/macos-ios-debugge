//! `manifest_parser` — PE application manifest extraction and parsing
//!
//! Windows PE executables embed an XML application manifest in the resource
//! section as resource type `RT_MANIFEST` (ID 24, decimal).  This module:
//!
//! 1. Locates the RT_MANIFEST resource inside the resource directory.
//! 2. Extracts the raw XML bytes.
//! 3. Parses the XML to extract:
//!    * `requestedExecutionLevel` (asInvoker / highestAvailable / requireAdministrator).
//!    * `trustInfo` / UAC attributes.
//!    * `dependency` assembly references (side-by-side manifests).
//!    * `supportedOS` GUIDs (Windows version compatibility list).
//!    * DPI awareness mode (system / per-monitor / unaware).
//!    * Long-path aware flag.
//!    * Application name and version from the `assemblyIdentity` element.
//!
//! The XML parser is a hand-written subset scanner — no external XML library
//! dependency required.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Resource directory constants
// ---------------------------------------------------------------------------

/// `RT_MANIFEST` resource type ID.
pub const RT_MANIFEST: u32 = 24;
/// `RT_MANIFEST` language-neutral resource name ID for EXE manifests.
pub const MANIFEST_ID_EXE: u32 = 1;
/// `RT_MANIFEST` resource name ID for DLL manifests.
pub const MANIFEST_ID_DLL: u32 = 2;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("no resource directory found")]
    NoResourceDir,
    #[error("RT_MANIFEST resource not found")]
    ManifestNotFound,
    #[error("resource data out of bounds")]
    ResourceOob,
    #[error("manifest XML is not valid UTF-8: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error("PE parse error: {0}")]
    ParseError(String),
}

// ---------------------------------------------------------------------------
// Parsed manifest
// ---------------------------------------------------------------------------

/// requestedExecutionLevel value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionLevel {
    AsInvoker,
    HighestAvailable,
    RequireAdministrator,
    /// Any other value (stored as-is).
    Other(String),
}

impl ExecutionLevel {
    fn from_str(s: &str) -> Self {
        match s.trim() {
            "asInvoker"              => Self::AsInvoker,
            "highestAvailable"       => Self::HighestAvailable,
            "requireAdministrator"   => Self::RequireAdministrator,
            other                    => Self::Other(other.to_owned()),
        }
    }
}

impl std::fmt::Display for ExecutionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AsInvoker            => write!(f, "asInvoker"),
            Self::HighestAvailable     => write!(f, "highestAvailable"),
            Self::RequireAdministrator => write!(f, "requireAdministrator"),
            Self::Other(s)             => write!(f, "{s}"),
        }
    }
}

/// DPI awareness mode declared in the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DpiAwareness {
    Unaware,
    System,
    PerMonitor,
    PerMonitorV2,
    Other(String),
}

impl DpiAwareness {
    fn from_str(s: &str) -> Self {
        match s.to_lowercase().trim() {
            "true" | "system"      => Self::System,
            "false" | "unaware"    => Self::Unaware,
            "permonitor"           => Self::PerMonitor,
            "permonitorv2"         => Self::PerMonitorV2,
            other                  => Self::Other(other.to_owned()),
        }
    }
}

/// A side-by-side assembly dependency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssemblyDependency {
    /// Assembly name.
    pub name: String,
    /// Requested version.
    pub version: String,
    /// Processor architecture.
    pub processor_architecture: String,
    /// Public key token.
    pub public_key_token: String,
    /// Assembly type (win32, win32-policy, etc.).
    pub assembly_type: String,
}

/// A supportedOS GUID entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedOs {
    /// Raw GUID string, e.g. `"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"`.
    pub guid: String,
    /// Human-readable OS name derived from the GUID.
    pub os_name: String,
}

impl SupportedOs {
    fn from_guid(guid: &str) -> Self {
        let os_name = match guid.to_lowercase().trim_matches(['{', '}']) {
            "8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a" => "Windows 10 / 11",
            "1f676c76-80e1-4239-95bb-83d0f6d0da78" => "Windows 8.1",
            "4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38" => "Windows 8",
            "35138b9a-5d96-4fbd-8e2d-a2440225f93a" => "Windows 7",
            "e2011457-1546-43c5-a5fe-008deee3d3f0" => "Windows Vista",
            _                                        => "Unknown Windows version",
        };
        Self { guid: guid.to_owned(), os_name: os_name.to_owned() }
    }
}

/// Fully parsed application manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedManifest {
    /// Raw XML text.
    pub xml: String,
    /// Application executable level.
    pub execution_level: Option<ExecutionLevel>,
    /// UI access flag.
    pub ui_access: bool,
    /// DPI awareness.
    pub dpi_awareness: Option<DpiAwareness>,
    /// Long-path aware flag.
    pub long_path_aware: bool,
    /// Side-by-side assembly dependencies.
    pub dependencies: Vec<AssemblyDependency>,
    /// Supported OS GUIDs.
    pub supported_os: Vec<SupportedOs>,
    /// assemblyIdentity name.
    pub assembly_name: String,
    /// assemblyIdentity version.
    pub assembly_version: String,
    /// Raw attributes map for any unrecognised elements.
    pub extra_attributes: HashMap<String, String>,
}

impl ParsedManifest {
    /// Returns `true` if the manifest requires elevation.
    #[must_use] 
    pub const fn requires_elevation(&self) -> bool {
        matches!(
            &self.execution_level,
            Some(ExecutionLevel::RequireAdministrator | ExecutionLevel::HighestAvailable)
        )
    }

    /// Returns `true` if Windows 10 / 11 is declared as supported.
    #[must_use] 
    pub fn supports_windows10(&self) -> bool {
        self.supported_os.iter().any(|os| os.os_name.contains("Windows 10"))
    }
}

// ---------------------------------------------------------------------------
// ManifestParser
// ---------------------------------------------------------------------------

/// Extracts and parses the `RT_MANIFEST` from a raw PE byte slice.
pub struct ManifestParser<'a> {
    data: &'a [u8],
    pe_offset: usize,
    is_pe32plus: bool,
}

impl<'a> ManifestParser<'a> {
    /// Construct from a raw PE slice.  Returns `None` if not a PE.
    #[must_use] 
    pub fn new(data: &'a [u8]) -> Option<Self> {
        let pe_offset = locate_pe(data)?;
        let is_pe32plus = detect_pe32plus(data, pe_offset);
        Some(Self { data, pe_offset, is_pe32plus })
    }

    const fn opt(&self) -> usize { self.pe_offset + 24 }

    /// Read the resource data directory entry (index 2).
    fn resource_dd(&self) -> (u32, u32) {
        let opt = self.opt();
        let dd_base = if self.is_pe32plus { opt + 112 + 2 * 8 } else { opt + 96 + 2 * 8 };
        if dd_base + 8 > self.data.len() { return (0, 0); }
        let rva = u32::from_le_bytes(self.data[dd_base..dd_base+4].try_into().unwrap());
        let sz  = u32::from_le_bytes(self.data[dd_base+4..dd_base+8].try_into().unwrap());
        (rva, sz)
    }

    /// Resolve an RVA to a file offset using the section table.
    fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        let coff     = self.pe_offset + 4;
        let num_sec  = u16::from_le_bytes(self.data[coff+2..coff+4].try_into().ok()?) as usize;
        let opt_sz   = u16::from_le_bytes(self.data[coff+16..coff+18].try_into().ok()?) as usize;
        let sec_base = self.pe_offset + 4 + 20 + opt_sz;
        for i in 0..num_sec {
            let s = sec_base + i * 40;
            if s + 40 > self.data.len() { break; }
            let virt_addr = u32::from_le_bytes(self.data[s+12..s+16].try_into().ok()?);
            let virt_size = u32::from_le_bytes(self.data[s+8..s+12].try_into().ok()?);
            let raw_ptr   = u32::from_le_bytes(self.data[s+20..s+24].try_into().ok()?) as usize;
            // `virt_addr`/`virt_size` come straight from a hostile section
            // header: a wrapping `virt_addr + virt_size` would make the range
            // test silently false and skip the section.  See the canonical
            // `PeFile::rva_to_offset`, which uses checked arithmetic.
            if rva >= virt_addr && rva < virt_addr.saturating_add(virt_size) {
                return raw_ptr.checked_add((rva - virt_addr) as usize);
            }
        }
        None
    }

    /// Walk a resource directory and find an entry with the given `id`.
    fn find_res_entry(&self, dir_offset: usize, id: u32) -> Option<u32> {
        if dir_offset + 16 > self.data.len() { return None; }
        let named_count  = u16::from_le_bytes(self.data[dir_offset+12..dir_offset+14].try_into().ok()?) as usize;
        let id_count     = u16::from_le_bytes(self.data[dir_offset+14..dir_offset+16].try_into().ok()?) as usize;
        let total        = named_count + id_count;
        for i in 0..total {
            let entry_off = dir_offset + 16 + i * 8;
            if entry_off + 8 > self.data.len() { break; }
            let name_id  = u32::from_le_bytes(self.data[entry_off..entry_off+4].try_into().ok()?);
            let offset_v = u32::from_le_bytes(self.data[entry_off+4..entry_off+8].try_into().ok()?);
            // High bit set = subdirectory, clear = leaf data entry.
            let is_subdir  = offset_v & 0x8000_0000 != 0;
            let actual_off = (offset_v & 0x7FFF_FFFF) as usize;
            let name_is_id = name_id & 0x8000_0000 == 0;
            if name_is_id && name_id == id {
                // For subdirectories the high bit stays set so callers can detect
                // the subdirectory flag; actual_off is used for bounds validation.
                if is_subdir && actual_off > self.data.len() { return None; }
                return Some(offset_v);
            }
        }
        None
    }

    /// Extract the raw manifest XML bytes from the PE resource section.
    ///
    /// # Errors
    ///
    /// Returns `ManifestError` if the resource directory is absent, the
    /// manifest resource cannot be located, or data offsets are out of bounds.
    ///
    /// # Panics
    ///
    /// Panics if internal slice indexing is inconsistent (should not occur with
    /// well-formed PE files that pass the preceding bounds checks).
    pub fn extract_raw(&self) -> Result<Vec<u8>, ManifestError> {
        let (rsrc_rva, _rsrc_sz) = self.resource_dd();
        if rsrc_rva == 0 { return Err(ManifestError::NoResourceDir); }
        let rsrc_off = self.rva_to_offset(rsrc_rva)
            .ok_or(ManifestError::NoResourceDir)?;

        // Level 1: type directory — find RT_MANIFEST (24).
        let type_entry = self.find_res_entry(rsrc_off, RT_MANIFEST)
            .ok_or(ManifestError::ManifestNotFound)?;
        let type_sub = (type_entry & 0x7FFF_FFFF) as usize + rsrc_off;

        // Level 2: name directory — take the first entry (ID 1 preferred).
        if type_sub + 16 > self.data.len() { return Err(ManifestError::ManifestNotFound); }
        let name_total = (u16::from_le_bytes(self.data[type_sub+12..type_sub+14].try_into().unwrap())
            + u16::from_le_bytes(self.data[type_sub+14..type_sub+16].try_into().unwrap())) as usize;
        if name_total == 0 { return Err(ManifestError::ManifestNotFound); }

        let mut best_offset = 0usize;
        for i in 0..name_total {
            let entry_off = type_sub + 16 + i * 8;
            if entry_off + 8 > self.data.len() { break; }
            let name_id  = u32::from_le_bytes(self.data[entry_off..entry_off+4].try_into().unwrap());
            let offset_v = u32::from_le_bytes(self.data[entry_off+4..entry_off+8].try_into().unwrap());
            let actual   = (offset_v & 0x7FFF_FFFF) as usize + rsrc_off;
            // Prefer ID 1 (EXE) or ID 2 (DLL).
            if name_id == MANIFEST_ID_EXE || i == 0 { best_offset = actual; }
            if name_id == MANIFEST_ID_EXE { break; }
        }
        if best_offset == 0 { return Err(ManifestError::ManifestNotFound); }

        // Level 3: language directory — take the first leaf.
        if best_offset + 16 > self.data.len() { return Err(ManifestError::ManifestNotFound); }
        let lang_total = (u16::from_le_bytes(self.data[best_offset+12..best_offset+14].try_into().unwrap())
            + u16::from_le_bytes(self.data[best_offset+14..best_offset+16].try_into().unwrap())) as usize;
        if lang_total == 0 { return Err(ManifestError::ManifestNotFound); }

        let leaf_off_raw = u32::from_le_bytes(
            self.data[best_offset+16+4..best_offset+16+8].try_into().unwrap()
        ) as usize;
        let leaf_off = leaf_off_raw + rsrc_off;

        // Resource data entry: RVA (4) + Size (4) + CodePage (4) + Reserved (4).
        if leaf_off + 16 > self.data.len() { return Err(ManifestError::ResourceOob); }
        let data_rva  = u32::from_le_bytes(self.data[leaf_off..leaf_off+4].try_into().unwrap());
        let data_size = u32::from_le_bytes(self.data[leaf_off+4..leaf_off+8].try_into().unwrap()) as usize;
        let data_off  = self.rva_to_offset(data_rva).ok_or(ManifestError::ResourceOob)?;
        if data_off + data_size > self.data.len() { return Err(ManifestError::ResourceOob); }

        Ok(self.data[data_off..data_off + data_size].to_vec())
    }

    /// Extract and fully parse the manifest.
    ///
    /// # Errors
    ///
    /// Returns `ManifestError` if the manifest XML cannot be extracted or
    /// the bytes are not valid UTF-8.
    pub fn parse(&self) -> Result<ParsedManifest, ManifestError> {
        let raw = self.extract_raw()?;
        let xml = std::str::from_utf8(&raw)?.to_owned();
        Ok(parse_manifest_xml(&xml))
    }
}

// ---------------------------------------------------------------------------
// XML parsing
// ---------------------------------------------------------------------------

/// Parse a manifest XML string into a [`ParsedManifest`].
#[must_use] 
pub fn parse_manifest_xml(xml: &str) -> ParsedManifest {
    let mut manifest = ParsedManifest {
        xml: xml.to_owned(),
        execution_level: None,
        ui_access: false,
        dpi_awareness: None,
        long_path_aware: false,
        dependencies: Vec::new(),
        supported_os: Vec::new(),
        assembly_name: String::new(),
        assembly_version: String::new(),
        extra_attributes: HashMap::new(),
    };

    // Extract requestedExecutionLevel.
    if let Some(level) = attr_value(xml, "requestedExecutionLevel", "level") {
        manifest.execution_level = Some(ExecutionLevel::from_str(&level));
    }
    if let Some(ua) = attr_value(xml, "requestedExecutionLevel", "uiAccess") {
        manifest.ui_access = ua.trim() == "true";
    }

    // DPI awareness — two locations: legacy dpiAware and modern dpiAwareness.
    if let Some(v) = element_content(xml, "dpiAwareness") {
        manifest.dpi_awareness = Some(DpiAwareness::from_str(&v));
    } else if let Some(v) = element_content(xml, "dpiAware") {
        manifest.dpi_awareness = Some(DpiAwareness::from_str(&v));
    }

    // Long-path aware.
    if let Some(v) = element_content(xml, "longPathAware") {
        manifest.long_path_aware = v.trim() == "true";
    }

    // assemblyIdentity (root element).
    if let Some(name) = attr_value_first(xml, "assemblyIdentity", "name") {
        manifest.assembly_name = name;
    }
    if let Some(ver) = attr_value_first(xml, "assemblyIdentity", "version") {
        manifest.assembly_version = ver;
    }

    // Dependency assemblies.
    manifest.dependencies = parse_dependencies(xml);

    // supportedOS GUIDs.
    manifest.supported_os = parse_supported_os(xml);

    manifest
}

// ---------------------------------------------------------------------------
// Mini XML attribute scanner
// ---------------------------------------------------------------------------

/// Find `<tag ... attr="value" ...>` and return the value of `attr`.
fn attr_value(xml: &str, tag: &str, attr: &str) -> Option<String> {
    // Find the tag.
    let tag_start = xml.find(&format!("<{tag}"))?;
    let tag_end   = xml[tag_start..].find('>')?;
    let tag_body  = &xml[tag_start..=(tag_start + tag_end)];
    extract_attr(tag_body, attr)
}

/// Like `attr_value` but for the first occurrence of a tag with the given local name.
fn attr_value_first(xml: &str, local_name: &str, attr: &str) -> Option<String> {
    attr_value(xml, local_name, attr)
}

/// Extract `<tag>content</tag>` inner text.
fn element_content(xml: &str, tag: &str) -> Option<String> {
    let open_tag = format!("<{tag}");
    let close_tag = format!("</{tag}");
    let start = xml.find(&open_tag)?;
    let after_open = xml[start..].find('>')?;
    let content_start = start + after_open + 1;
    let content_end = xml[content_start..].find(close_tag.as_str())?;
    Some(xml[content_start..content_start + content_end].trim().to_owned())
}

/// Extract an attribute value from a tag fragment string.
fn extract_attr(tag_body: &str, attr: &str) -> Option<String> {
    // Match `attr="value"` or `attr='value'`.
    for quote in ['"', '\''] {
        let pattern = format!("{attr}={quote}");
        if let Some(pos) = tag_body.find(&pattern) {
            let val_start = pos + pattern.len();
            if let Some(end) = tag_body[val_start..].find(quote) {
                return Some(tag_body[val_start..val_start + end].to_owned());
            }
        }
    }
    None
}

fn parse_dependencies(xml: &str) -> Vec<AssemblyDependency> {
    let mut deps = Vec::new();
    let mut rest = xml;
    while let Some(pos) = rest.find("<assemblyIdentity") {
        let after = &rest[pos..];
        let close = after.find('>').unwrap_or(after.len());
        let fragment = &after[..=close];
        // Skip root identity (has no processorArchitecture attribute in main identity,
        // but check if it is inside a <dependency> element).
        let in_dep = rest[..pos].contains("<dependency");
        if in_dep {
            deps.push(AssemblyDependency {
                name:                   extract_attr(fragment, "name").unwrap_or_default(),
                version:                extract_attr(fragment, "version").unwrap_or_default(),
                processor_architecture: extract_attr(fragment, "processorArchitecture").unwrap_or_default(),
                public_key_token:       extract_attr(fragment, "publicKeyToken").unwrap_or_default(),
                assembly_type:          extract_attr(fragment, "type").unwrap_or_default(),
            });
        }
        rest = &rest[pos + 1..];
    }
    deps
}

fn parse_supported_os(xml: &str) -> Vec<SupportedOs> {
    let mut list = Vec::new();
    let mut rest = xml;
    while let Some(pos) = rest.find("<supportedOS") {
        let after = &rest[pos..];
        let close = after.find('>').unwrap_or(after.len());
        let fragment = &after[..=close];
        if let Some(guid) = extract_attr(fragment, "Id").or_else(|| extract_attr(fragment, "id")) {
            list.push(SupportedOs::from_guid(&guid));
        }
        rest = &rest[pos + 1..];
    }
    list
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn locate_pe(data: &[u8]) -> Option<usize> {
    if data.len() < 0x40 { return None; }
    if data[0] == b'M' && data[1] == b'Z' {
        let lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().ok()?) as usize;
        if lfanew + 4 <= data.len() && &data[lfanew..lfanew+4] == b"PE\0\0" {
            return Some(lfanew);
        }
    }
    None
}

fn detect_pe32plus(data: &[u8], pe_offset: usize) -> bool {
    let opt = pe_offset + 24;
    if opt + 2 > data.len() { return false; }
    u16::from_le_bytes(data[opt..opt+2].try_into().unwrap()) == 0x020B
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0" name="MyApp.exe" type="win32"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true</dpiAware>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </windowsSettings>
  </application>
</assembly>"#;

    #[test]
    fn parse_execution_level() {
        let m = parse_manifest_xml(SAMPLE_MANIFEST);
        assert_eq!(m.execution_level, Some(ExecutionLevel::RequireAdministrator));
    }

    #[test]
    fn parse_ui_access_false() {
        let m = parse_manifest_xml(SAMPLE_MANIFEST);
        assert!(!m.ui_access);
    }

    #[test]
    fn parse_requires_elevation() {
        let m = parse_manifest_xml(SAMPLE_MANIFEST);
        assert!(m.requires_elevation());
    }

    #[test]
    fn parse_supported_os_count() {
        let m = parse_manifest_xml(SAMPLE_MANIFEST);
        assert_eq!(m.supported_os.len(), 2);
    }

    #[test]
    fn parse_windows10_support() {
        let m = parse_manifest_xml(SAMPLE_MANIFEST);
        assert!(m.supports_windows10());
    }

    #[test]
    fn parse_long_path_aware() {
        let m = parse_manifest_xml(SAMPLE_MANIFEST);
        assert!(m.long_path_aware);
    }

    #[test]
    fn parse_dpi_aware() {
        let m = parse_manifest_xml(SAMPLE_MANIFEST);
        assert!(m.dpi_awareness.is_some());
    }

    #[test]
    fn parse_assembly_name() {
        let m = parse_manifest_xml(SAMPLE_MANIFEST);
        assert_eq!(m.assembly_name, "MyApp.exe");
    }
}
