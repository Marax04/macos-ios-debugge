//! `resource_editor` — Edit PE resource directories, version info, manifests,
//! icons and string tables.
//!
//! Provides [`ResourceEditor`] as the main entry-point, backed by
//! [`ResourceNode`], [`ResourceEntry`], [`VersionInfoEditor`],
//! [`ManifestEditor`], [`IconReplacer`], and [`StringTableEditor`].

use std::collections::HashMap;

pub use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from the resource editor.
#[derive(Debug, Error)]
pub enum ResourceError {
    #[error("resource not found: type={type_id}, name={name_id}, lang={lang_id}")]
    NotFound {
        type_id: u16,
        name_id: u16,
        lang_id: u16,
    },
    #[error("resource data exceeds available space: need {need} have {have}")]
    NoSpace { need: usize, have: usize },
    #[error("malformed resource directory at offset {0:#x}")]
    MalformedDirectory(usize),
    #[error("invalid string table block {0}")]
    InvalidStringBlock(u16),
    #[error("manifest XML is malformed: {0}")]
    MalformedManifest(String),
    #[error("icon data is corrupt")]
    CorruptIcon,
    #[error("version info structure is corrupt: {0}")]
    CorruptVersionInfo(String),
    #[error("write error: {0}")]
    Write(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// Well-known resource type IDs
// ─────────────────────────────────────────────────────────────────────────────

/// Standard PE resource type identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum ResourceType {
    Cursor = 1,
    Bitmap = 2,
    Icon = 3,
    Menu = 4,
    Dialog = 5,
    String = 6,
    FontDir = 7,
    Font = 8,
    Accelerator = 9,
    RcData = 10,
    MessageTable = 11,
    CursorGroup = 12,
    IconGroup = 14,
    VersionInfo = 16,
    DlgInclude = 17,
    PlugPlay = 19,
    Vxd = 20,
    AniCursor = 21,
    AniIcon = 22,
    Html = 23,
    Manifest = 24,
    Custom(u16),
}

impl ResourceType {
    #[must_use] 
    pub const fn id(self) -> u16 {
        match self {
            Self::Custom(id) => id,
            Self::Cursor => 1,
            Self::Bitmap => 2,
            Self::Icon => 3,
            Self::Menu => 4,
            Self::Dialog => 5,
            Self::String => 6,
            Self::FontDir => 7,
            Self::Font => 8,
            Self::Accelerator => 9,
            Self::RcData => 10,
            Self::MessageTable => 11,
            Self::CursorGroup => 12,
            Self::IconGroup => 14,
            Self::VersionInfo => 16,
            Self::DlgInclude => 17,
            Self::PlugPlay => 19,
            Self::Vxd => 20,
            Self::AniCursor => 21,
            Self::AniIcon => 22,
            Self::Html => 23,
            Self::Manifest => 24,
        }
    }

    #[must_use] 
    pub const fn from_id(id: u16) -> Self {
        match id {
            1 => Self::Cursor,
            2 => Self::Bitmap,
            3 => Self::Icon,
            4 => Self::Menu,
            5 => Self::Dialog,
            6 => Self::String,
            7 => Self::FontDir,
            8 => Self::Font,
            9 => Self::Accelerator,
            10 => Self::RcData,
            11 => Self::MessageTable,
            12 => Self::CursorGroup,
            14 => Self::IconGroup,
            16 => Self::VersionInfo,
            17 => Self::DlgInclude,
            19 => Self::PlugPlay,
            20 => Self::Vxd,
            21 => Self::AniCursor,
            22 => Self::AniIcon,
            23 => Self::Html,
            24 => Self::Manifest,
            n => Self::Custom(n),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResourceEntry / ResourceNode
// ─────────────────────────────────────────────────────────────────────────────

/// Identifies a resource.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceEntry {
    /// Type id or 0 for named.
    pub type_id: u16,
    /// Name id (numeric) or 0 if the name is a string.
    pub name_id: u16,
    /// Optional name string.
    pub name_str: Option<String>,
    /// Language id.
    pub lang_id: u16,
}

impl ResourceEntry {
    #[must_use] 
    pub const fn new(type_id: u16, name_id: u16, lang_id: u16) -> Self {
        Self {
            type_id,
            name_id,
            name_str: None,
            lang_id,
        }
    }

    pub fn named(type_id: u16, name: impl Into<String>, lang_id: u16) -> Self {
        Self {
            type_id,
            name_id: 0,
            name_str: Some(name.into()),
            lang_id,
        }
    }
}

/// A node in the resource directory tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceNode {
    /// Directory containing child nodes (keyed by id or name).
    Directory {
        entries: Vec<(ResourceEntry, Self)>,
        characteristics: u32,
        time_date_stamp: u32,
        major_version: u16,
        minor_version: u16,
    },
    /// Leaf node holding the raw resource data.
    Data {
        raw: Vec<u8>,
        code_page: u32,
        reserved: u32,
    },
}

impl ResourceNode {
    /// Create a new directory node.
    #[must_use] 
    pub const fn directory() -> Self {
        Self::Directory {
            entries: Vec::new(),
            characteristics: 0,
            time_date_stamp: 0,
            major_version: 0,
            minor_version: 0,
        }
    }

    /// Create a data leaf.
    #[must_use] 
    pub const fn data(raw: Vec<u8>) -> Self {
        Self::Data {
            raw,
            code_page: 0,
            reserved: 0,
        }
    }

    /// Return the raw data slice if this is a Data node.
    #[must_use] 
    pub fn as_data(&self) -> Option<&[u8]> {
        match self {
            Self::Data { raw, .. } => Some(raw),
            Self::Directory { .. } => None,
        }
    }

    /// Number of child entries (0 for Data nodes).
    #[must_use] 
    pub const fn child_count(&self) -> usize {
        match self {
            Self::Directory { entries, .. } => entries.len(),
            Self::Data { .. } => 0,
        }
    }

    /// Recursively find a leaf by (type, name, lang).
    /// Pass `0` for any ID to match any value at that level.
    #[must_use]
    pub fn find(&self, type_id: u16, name_id: u16, lang_id: u16) -> Option<&[u8]> {
        match self {
            Self::Data { raw, .. } => Some(raw),
            Self::Directory { entries, .. } => {
                for (entry, child) in entries {
                    if (type_id == 0 || entry.type_id == 0 || entry.type_id == type_id)
                        && (name_id == 0 || entry.name_id == 0 || entry.name_id == name_id)
                        && (lang_id == 0 || entry.lang_id == 0 || entry.lang_id == lang_id)
                        && let result @ Some(_) = child.find(type_id, name_id, lang_id) {
                            return result;
                        }
                }
                None
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VersionInfoEditor
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed `VS_VERSION_INFO` structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub file_version: [u16; 4],
    pub product_version: [u16; 4],
    pub file_flags_mask: u32,
    pub file_flags: u32,
    pub file_os: u32,
    pub file_type: u32,
    pub file_subtype: u32,
    /// String values from `StringFileInfo` (lang+codepage → key → value).
    pub strings: HashMap<String, HashMap<String, String>>,
}

impl Default for VersionInfo {
    fn default() -> Self {
        Self {
            file_version: [1, 0, 0, 0],
            product_version: [1, 0, 0, 0],
            file_flags_mask: 0x3F,
            file_flags: 0,
            file_os: 4,   // VOS_NT_WINDOWS32
            file_type: 1, // VFT_APP
            file_subtype: 0,
            strings: HashMap::new(),
        }
    }
}

/// Editor for `VS_VERSION_INFO` resources.
#[derive(Debug, Default)]
pub struct VersionInfoEditor {
    pub info: VersionInfo,
}

impl VersionInfoEditor {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub const fn set_file_version(&mut self, maj: u16, min: u16, build: u16, rev: u16) {
        self.info.file_version = [maj, min, build, rev];
    }

    pub const fn set_product_version(&mut self, maj: u16, min: u16, build: u16, rev: u16) {
        self.info.product_version = [maj, min, build, rev];
    }

    pub fn set_string(&mut self, lang_cp: &str, key: &str, value: &str) {
        self.info
            .strings
            .entry(lang_cp.to_string())
            .or_default()
            .insert(key.to_string(), value.to_string());
    }

    #[must_use] 
    pub fn get_string(&self, lang_cp: &str, key: &str) -> Option<&str> {
        self.info.strings.get(lang_cp)?.get(key).map(std::string::String::as_str)
    }

    /// Serialise to a minimal binary `VS_VERSION_INFO` blob.
    #[must_use] 
    pub fn serialize(&self) -> Vec<u8> {
        // Minimal stub: just the VS_FIXEDFILEINFO (52 bytes) + padding.
        let mut out = vec![0u8; 52];
        // dwSignature = 0xFEEF04BD
        out[0..4].copy_from_slice(&0xFEEF_04BD_u32.to_le_bytes());
        // dwStrucVersion = 1.0
        out[4..8].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        // dwFileVersionMS / LS
        let fv = &self.info.file_version;
        out[8..12].copy_from_slice(&((u32::from(fv[0]) << 16) | u32::from(fv[1])).to_le_bytes());
        out[12..16].copy_from_slice(&((u32::from(fv[2]) << 16) | u32::from(fv[3])).to_le_bytes());
        // dwProductVersionMS / LS
        let pv = &self.info.product_version;
        out[16..20].copy_from_slice(&((u32::from(pv[0]) << 16) | u32::from(pv[1])).to_le_bytes());
        out[20..24].copy_from_slice(&((u32::from(pv[2]) << 16) | u32::from(pv[3])).to_le_bytes());
        out[24..28].copy_from_slice(&self.info.file_flags_mask.to_le_bytes());
        out[28..32].copy_from_slice(&self.info.file_flags.to_le_bytes());
        out[32..36].copy_from_slice(&self.info.file_os.to_le_bytes());
        out[36..40].copy_from_slice(&self.info.file_type.to_le_bytes());
        out[40..44].copy_from_slice(&self.info.file_subtype.to_le_bytes());
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ManifestEditor
// ─────────────────────────────────────────────────────────────────────────────

/// Edit the application manifest embedded in `RT_MANIFEST` resources.
#[derive(Debug, Clone)]
pub struct ManifestEditor {
    pub xml: String,
}

impl ManifestEditor {
    pub fn new(xml: impl Into<String>) -> Self {
        Self { xml: xml.into() }
    }

    /// Validate that the XML is non-empty and contains `<assembly`.
    ///
    /// # Errors
    /// Returns [`ResourceError::MalformedManifest`] if the manifest is empty or missing `<assembly`.
    pub fn validate(&self) -> Result<(), ResourceError> {
        if self.xml.trim().is_empty() {
            return Err(ResourceError::MalformedManifest("empty manifest".into()));
        }
        if !self.xml.contains("<assembly") {
            return Err(ResourceError::MalformedManifest(
                "missing <assembly> root".into(),
            ));
        }
        Ok(())
    }

    /// Replace the `requestedExecutionLevel` attribute value.
    pub fn set_execution_level(&mut self, level: &str) {
        // Very simple text replacement.
        if let Some(start) = self.xml.find("requestedExecutionLevel level=\"") {
            let attr_start = start + "requestedExecutionLevel level=\"".len();
            if let Some(end) = self.xml[attr_start..].find('"') {
                self.xml = format!(
                    "{}{}{}",
                    &self.xml[..attr_start],
                    level,
                    &self.xml[attr_start + end..]
                );
            }
        }
    }

    /// Returns the raw UTF-8 bytes of the manifest.
    #[must_use] 
    pub fn as_bytes(&self) -> Vec<u8> {
        self.xml.as_bytes().to_vec()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IconReplacer
// ─────────────────────────────────────────────────────────────────────────────

/// Replace icons in the PE resource directory.
#[derive(Debug)]
pub struct IconReplacer {
    /// Pending icon replacements: (`RT_ICON` `name_id`) → new ICO file bytes.
    replacements: HashMap<u16, Vec<u8>>,
}

impl IconReplacer {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            replacements: HashMap::new(),
        }
    }

    /// Queue a replacement for icon with `name_id`.
    pub fn queue(&mut self, name_id: u16, ico_data: Vec<u8>) {
        self.replacements.insert(name_id, ico_data);
    }

    /// Number of queued replacements.
    #[must_use] 
    pub fn pending_count(&self) -> usize {
        self.replacements.len()
    }

    /// Validate that all queued icon data starts with a valid ICO signature.
    ///
    /// # Errors
    /// Returns [`ResourceError`] if any icon data is invalid or has an incorrect signature.
    pub fn validate(&self) -> Result<(), ResourceError> {
        for (&id, data) in &self.replacements {
            if id == 0 {
                return Err(ResourceError::NotFound {
                    type_id: 3,
                    name_id: id,
                    lang_id: 0,
                });
            }
            if data.len() < 6 {
                return Err(ResourceError::CorruptIcon);
            }
            let reserved = u16::from_le_bytes([data[0], data[1]]);
            let ico_type = u16::from_le_bytes([data[2], data[3]]);
            if reserved != 0 || (ico_type != 1 && ico_type != 2) {
                return Err(ResourceError::CorruptIcon);
            }
        }
        Ok(())
    }

    /// Return the replacement data for `name_id`, if any.
    #[must_use] 
    pub fn get(&self, name_id: u16) -> Option<&[u8]> {
        self.replacements.get(&name_id).map(std::vec::Vec::as_slice)
    }
}

impl Default for IconReplacer {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringTableEditor
// ─────────────────────────────────────────────────────────────────────────────

/// Edit PE string table resources (`RT_STRING`, type 6).
///
/// A string table block groups 16 consecutive string IDs.
/// Block ID = (`string_id` >> 4) + 1.
#[derive(Debug, Clone, Default)]
pub struct StringTableEditor {
    /// `block_id` → (`index_in_block` → string value).
    blocks: HashMap<u16, [Option<String>; 16]>,
}

impl StringTableEditor {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Set string with `id` to `value`.
    pub fn set(&mut self, id: u16, value: impl Into<String>) {
        let block = (id >> 4) + 1;
        let index = (id & 0x0F) as usize;
        let entry = self
            .blocks
            .entry(block)
            .or_insert_with(|| std::array::from_fn(|_| None));
        entry[index] = Some(value.into());
    }

    /// Get the string with `id`.
    #[must_use] 
    pub fn get(&self, id: u16) -> Option<&str> {
        let block = (id >> 4) + 1;
        let index = (id & 0x0F) as usize;
        self.blocks.get(&block)?.get(index)?.as_deref()
    }

    /// Remove string `id`.
    pub fn remove(&mut self, id: u16) {
        let block = (id >> 4) + 1;
        let index = (id & 0x0F) as usize;
        if let Some(b) = self.blocks.get_mut(&block) {
            b[index] = None;
        }
    }

    /// Number of non-None string entries.
    #[must_use] 
    pub fn entry_count(&self) -> usize {
        self.blocks
            .values()
            .flat_map(|b| b.iter())
            .filter(|s| s.is_some())
            .count()
    }

    /// Serialise block `block_id` into a raw `RT_STRING` binary blob.
    /// Each string is encoded as u16-length + UTF-16LE characters.
    ///
    /// # Errors
    /// Returns [`ResourceError::InvalidStringBlock`] if `block_id` is not present.
    pub fn serialize_block(&self, block_id: u16) -> Result<Vec<u8>, ResourceError> {
        let block = self
            .blocks
            .get(&block_id)
            .ok_or(ResourceError::InvalidStringBlock(block_id))?;
        // Pre-size: each None is 2 bytes; each Some(s) is 2 + 2*utf16_len bytes.
        let estimated = block
            .iter()
            .map(|e| e.as_ref().map_or(2, |s| 2 + s.len() * 2))
            .sum();
        let mut out = Vec::with_capacity(estimated);
        for entry in block {
            match entry {
                None => out.extend_from_slice(&[0u8, 0]),
                Some(s) => {
                    // Reserve worst case for this entry then stream utf16 units
                    // directly into `out` without allocating an intermediate Vec.
                    let len_pos = out.len();
                    out.extend_from_slice(&[0u8, 0]);
                    let mut count: u16 = 0;
                    for c in s.encode_utf16() {
                        out.extend_from_slice(&c.to_le_bytes());
                        count += 1;
                    }
                    out[len_pos..len_pos + 2].copy_from_slice(&count.to_le_bytes());
                }
            }
        }
        Ok(out)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResourceEditor
// ─────────────────────────────────────────────────────────────────────────────

/// Main resource editor, holding the full resource tree and sub-editors.
#[derive(Debug)]
pub struct ResourceEditor {
    pub root: ResourceNode,
    pub version: VersionInfoEditor,
    pub manifest: Option<ManifestEditor>,
    pub icons: IconReplacer,
    pub strings: StringTableEditor,
    dirty: bool,
}

impl ResourceEditor {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            root: ResourceNode::directory(),
            version: VersionInfoEditor::new(),
            manifest: None,
            icons: IconReplacer::new(),
            strings: StringTableEditor::new(),
            dirty: false,
        }
    }

    /// Mark the editor as having pending changes.
    pub const fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Returns `true` if any edits have been made.
    #[must_use] 
    pub const fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Insert a raw resource leaf into the tree at (type, name, lang).
    pub fn insert_raw(&mut self, type_id: u16, name_id: u16, lang_id: u16, data: Vec<u8>) {
        let entry = ResourceEntry::new(type_id, name_id, lang_id);
        let node = ResourceNode::data(data);
        if let ResourceNode::Directory { entries, .. } = &mut self.root {
            entries.push((entry, node));
        }
        self.dirty = true;
    }

    /// Remove all entries matching `type_id`.
    pub fn remove_type(&mut self, type_id: u16) -> usize {
        if let ResourceNode::Directory { entries, .. } = &mut self.root {
            let before = entries.len();
            entries.retain(|(e, _)| e.type_id != type_id);
            let removed = before - entries.len();
            if removed > 0 {
                self.dirty = true;
            }
            removed
        } else {
            0
        }
    }

    /// Find raw data for (type, name, lang).
    #[must_use] 
    pub fn find_raw(&self, type_id: u16, name_id: u16, lang_id: u16) -> Option<&[u8]> {
        if let ResourceNode::Directory { entries, .. } = &self.root {
            for (entry, node) in entries {
                if entry.type_id == type_id
                    && (entry.name_id == name_id || name_id == 0)
                    && (entry.lang_id == lang_id || lang_id == 0)
                {
                    return node.as_data();
                }
            }
        }
        None
    }

    /// Total number of leaf nodes in the tree.
    #[must_use] 
    pub fn leaf_count(&self) -> usize {
        fn count(node: &ResourceNode) -> usize {
            match node {
                ResourceNode::Data { .. } => 1,
                ResourceNode::Directory { entries, .. } => {
                    entries.iter().map(|(_, n)| count(n)).sum()
                }
            }
        }
        count(&self.root)
    }
}

impl Default for ResourceEditor {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ResourceType ─────────────────────────────────────────────────────────

    #[test]
    fn resource_type_icon_id() {
        assert_eq!(ResourceType::Icon.id(), 3);
    }

    #[test]
    fn resource_type_manifest_id() {
        assert_eq!(ResourceType::Manifest.id(), 24);
    }

    #[test]
    fn resource_type_custom() {
        assert_eq!(ResourceType::Custom(99).id(), 99);
    }

    #[test]
    fn resource_type_from_id_roundtrip() {
        for id in [1u16, 3, 6, 14, 16, 24] {
            let rt = ResourceType::from_id(id);
            assert_eq!(rt.id(), id);
        }
    }

    #[test]
    fn resource_type_from_unknown_is_custom() {
        let rt = ResourceType::from_id(0xFF);
        assert_eq!(rt.id(), 0xFF);
    }

    // ── ResourceEntry ────────────────────────────────────────────────────────

    #[test]
    fn resource_entry_new() {
        let e = ResourceEntry::new(3, 1, 0x409);
        assert_eq!(e.type_id, 3);
        assert_eq!(e.lang_id, 0x409);
    }

    #[test]
    fn resource_entry_named() {
        let e = ResourceEntry::named(10, "MyResource", 0);
        assert_eq!(e.name_str.as_deref(), Some("MyResource"));
    }

    // ── ResourceNode ─────────────────────────────────────────────────────────

    #[test]
    fn resource_node_data_as_data() {
        let n = ResourceNode::data(vec![1, 2, 3]);
        assert_eq!(n.as_data(), Some([1, 2, 3].as_slice()));
    }

    #[test]
    fn resource_node_directory_child_count_zero() {
        let n = ResourceNode::directory();
        assert_eq!(n.child_count(), 0);
    }

    #[test]
    fn resource_node_data_as_directory_none() {
        let n = ResourceNode::data(vec![]);
        assert!(n.as_data().is_some());
    }

    // ── VersionInfoEditor ────────────────────────────────────────────────────

    #[test]
    fn version_info_set_file_version() {
        let mut v = VersionInfoEditor::new();
        v.set_file_version(2, 0, 1, 0);
        assert_eq!(v.info.file_version, [2, 0, 1, 0]);
    }

    #[test]
    fn version_info_set_string() {
        let mut v = VersionInfoEditor::new();
        v.set_string("040904b0", "ProductName", "MyApp");
        assert_eq!(v.get_string("040904b0", "ProductName"), Some("MyApp"));
    }

    #[test]
    fn version_info_missing_key_none() {
        let v = VersionInfoEditor::new();
        assert!(v.get_string("040904b0", "NoKey").is_none());
    }

    #[test]
    fn version_info_serialize_starts_with_magic() {
        let v = VersionInfoEditor::new();
        let bytes = v.serialize();
        let sig = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        assert_eq!(sig, 0xFEEF04BD);
    }

    #[test]
    fn version_info_serialize_file_version() {
        let mut v = VersionInfoEditor::new();
        v.set_file_version(3, 2, 1, 0);
        let bytes = v.serialize();
        let ms = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        assert_eq!(ms >> 16, 3); // major
        assert_eq!(ms & 0xFFFF, 2); // minor
    }

    // ── ManifestEditor ───────────────────────────────────────────────────────

    #[test]
    fn manifest_validate_ok() {
        let m =
            ManifestEditor::new("<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\"></assembly>");
        assert!(m.validate().is_ok());
    }

    #[test]
    fn manifest_validate_empty_error() {
        let m = ManifestEditor::new("");
        assert!(m.validate().is_err());
    }

    #[test]
    fn manifest_validate_missing_assembly_error() {
        let m = ManifestEditor::new("<xml></xml>");
        assert!(m.validate().is_err());
    }

    #[test]
    fn manifest_as_bytes_utf8() {
        let m = ManifestEditor::new("<assembly/>");
        assert_eq!(m.as_bytes(), b"<assembly/>");
    }

    #[test]
    fn manifest_set_execution_level() {
        let mut m = ManifestEditor::new(
            r#"<assembly><requestedExecutionLevel level="asInvoker" uiAccess="false"/></assembly>"#,
        );
        m.set_execution_level("requireAdministrator");
        assert!(m.xml.contains("requireAdministrator"));
    }

    // ── IconReplacer ─────────────────────────────────────────────────────────

    #[test]
    fn icon_replacer_queue_and_count() {
        let mut r = IconReplacer::new();
        // Valid ICO header: reserved=0, type=1, count=1
        let ico = vec![0u8, 0, 1, 0, 1, 0];
        r.queue(1, ico);
        assert_eq!(r.pending_count(), 1);
    }

    #[test]
    fn icon_replacer_validate_valid() {
        let mut r = IconReplacer::new();
        let ico = vec![0u8, 0, 1, 0, 1, 0];
        r.queue(2, ico);
        assert!(r.validate().is_ok());
    }

    #[test]
    fn icon_replacer_validate_corrupt() {
        let mut r = IconReplacer::new();
        r.queue(3, vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // bad signature
        assert!(r.validate().is_err());
    }

    #[test]
    fn icon_replacer_get_returns_data() {
        let mut r = IconReplacer::new();
        r.queue(5, vec![0, 0, 1, 0, 0, 0]);
        assert!(r.get(5).is_some());
    }

    // ── StringTableEditor ────────────────────────────────────────────────────

    #[test]
    fn string_table_set_and_get() {
        let mut s = StringTableEditor::new();
        s.set(0x100, "Hello World");
        assert_eq!(s.get(0x100), Some("Hello World"));
    }

    #[test]
    fn string_table_remove() {
        let mut s = StringTableEditor::new();
        s.set(1, "Temp");
        s.remove(1);
        assert!(s.get(1).is_none());
    }

    #[test]
    fn string_table_entry_count() {
        let mut s = StringTableEditor::new();
        s.set(0, "A");
        s.set(1, "B");
        s.set(2, "C");
        assert_eq!(s.entry_count(), 3);
    }

    #[test]
    fn string_table_serialize_block() {
        let mut s = StringTableEditor::new();
        s.set(0, "Hi"); // id=0 → block=1, index=0
        let bytes = s.serialize_block(1).unwrap();
        // First 2 bytes: length 2 (u16 LE)
        assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), 2);
    }

    #[test]
    fn string_table_serialize_missing_block_error() {
        let s = StringTableEditor::new();
        assert!(s.serialize_block(99).is_err());
    }

    // ── ResourceEditor ───────────────────────────────────────────────────────

    #[test]
    fn resource_editor_insert_raw() {
        let mut e = ResourceEditor::new();
        e.insert_raw(10, 1, 0x409, vec![1, 2, 3, 4]);
        assert_eq!(e.leaf_count(), 1);
    }

    #[test]
    fn resource_editor_dirty_after_insert() {
        let mut e = ResourceEditor::new();
        e.insert_raw(10, 1, 0, vec![]);
        assert!(e.is_dirty());
    }

    #[test]
    fn resource_editor_find_raw() {
        let mut e = ResourceEditor::new();
        e.insert_raw(10, 2, 0, vec![0xAA, 0xBB]);
        let data = e.find_raw(10, 2, 0).unwrap();
        assert_eq!(data, &[0xAA, 0xBB]);
    }

    #[test]
    fn resource_editor_remove_type() {
        let mut e = ResourceEditor::new();
        e.insert_raw(3, 1, 0, vec![]); // icon
        e.insert_raw(3, 2, 0, vec![]); // icon
        e.insert_raw(6, 1, 0, vec![]); // string
        let removed = e.remove_type(3);
        assert_eq!(removed, 2);
        assert_eq!(e.leaf_count(), 1);
    }

    #[test]
    fn resource_editor_leaf_count_zero_initially() {
        let e = ResourceEditor::new();
        assert_eq!(e.leaf_count(), 0);
    }

    #[test]
    fn resource_editor_not_dirty_initially() {
        let e = ResourceEditor::new();
        assert!(!e.is_dirty());
    }

    #[test]
    fn resource_editor_mark_dirty() {
        let mut e = ResourceEditor::new();
        e.mark_dirty();
        assert!(e.is_dirty());
    }
}
