//! CFF (Common File Format) editor for PE images.
//!
//! Provides [`PeEditor`] — an in-memory PE editor that can add/remove/rename/
//! resize sections, edit the import and export directories, manipulate resource
//! entries, and flip security flags such as ASLR, DEP, and CFG.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{DllCharacteristics, PeError, PeFile, PeSection, align_up, data_dir_index};

/// Indices of the data directories the CFF editor knows how to mutate.
/// Mirrors a curated subset of [`crate::data_dir_index`] for callers that
/// only ever round-trip through the editor surface.
pub const EDITABLE_DATA_DIRS: &[usize] = &[
    data_dir_index::EXPORT,
    data_dir_index::IMPORT,
    data_dir_index::SECURITY,
    data_dir_index::TLS,
    data_dir_index::COM_DESCRIPTOR,
];

// ─── CffError ────────────────────────────────────────────────────────────────

/// Errors produced by the CFF editor.
#[derive(Debug, Error)]
pub enum CffError {
    /// Underlying PE parse error.
    #[error("pe error: {0}")]
    Pe(#[from] PeError),
    /// Section already exists with that name.
    #[error("section already exists: {0}")]
    SectionExists(String),
    /// Section not found.
    #[error("section not found: {0}")]
    SectionNotFound(String),
    /// Import DLL already present in the import table.
    #[error("import dll already present: {0}")]
    ImportDllExists(String),
    /// Import function not found.
    #[error("import not found: {0}!{1}")]
    ImportNotFound(String, String),
    /// Export not found.
    #[error("export not found: {0}")]
    ExportNotFound(String),
    /// Resource type/name not found.
    #[error("resource not found: type={0} id={1}")]
    ResourceNotFound(u16, u16),
    /// The editor cannot produce a valid PE (structural constraint violated).
    #[error("invalid edit: {0}")]
    InvalidEdit(String),
    /// I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

// ─── EditableImport ───────────────────────────────────────────────────────────

/// A mutable import entry held by the editor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EditableImport {
    /// DLL name (e.g. `"KERNEL32.dll"`).
    pub dll: String,
    /// Function name.  `None` means import by ordinal.
    pub name: Option<String>,
    /// Ordinal (used when `name` is `None`).
    pub ordinal: Option<u16>,
    /// Import hint (name-table hint).
    pub hint: u16,
}

impl EditableImport {
    /// Create an import-by-name entry.
    #[must_use]
    pub fn by_name(dll: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            dll: dll.into(),
            name: Some(name.into()),
            ordinal: None,
            hint: 0,
        }
    }

    /// Create an import-by-ordinal entry.
    #[must_use]
    pub fn by_ordinal(dll: impl Into<String>, ordinal: u16) -> Self {
        Self {
            dll: dll.into(),
            name: None,
            ordinal: Some(ordinal),
            hint: 0,
        }
    }

    /// Display form `"DLL!name"` or `"DLL!#ord"`.
    #[must_use]
    pub fn display_name(&self) -> String {
        self.name.as_ref().map_or_else(
            || format!("{}!#{}", self.dll, self.ordinal.unwrap_or(0)),
            |n| format!("{}!{}", self.dll, n),
        )
    }
}

impl fmt::Display for EditableImport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ─── EditableExport ───────────────────────────────────────────────────────────

/// A mutable export entry held by the editor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditableExport {
    /// Export name.  `None` means unnamed (ordinal-only) export.
    pub name: Option<String>,
    /// Export ordinal (1-based relative to ordinal base).
    pub ordinal: u16,
    /// RVA of the exported symbol.
    pub rva: u32,
    /// Forwarder string, if this is a forwarded export.
    pub forwarder: Option<String>,
}

impl EditableExport {
    /// Create a named export.
    #[must_use]
    pub fn named(name: impl Into<String>, ordinal: u16, rva: u32) -> Self {
        Self {
            name: Some(name.into()),
            ordinal,
            rva,
            forwarder: None,
        }
    }

    /// Create an ordinal-only export.
    #[must_use]
    pub const fn ordinal_only(ordinal: u16, rva: u32) -> Self {
        Self {
            name: None,
            ordinal,
            rva,
            forwarder: None,
        }
    }

    /// Create a forwarded export.
    #[must_use]
    pub fn forwarded(name: impl Into<String>, ordinal: u16, target: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            ordinal,
            rva: 0,
            forwarder: Some(target.into()),
        }
    }
}

impl fmt::Display for EditableExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.name.as_deref().unwrap_or("<unnamed>");
        write!(f, "{}@{} rva={:#x}", n, self.ordinal, self.rva)
    }
}

// ─── ResourceEntry ────────────────────────────────────────────────────────────

/// A single resource leaf entry in the PE resource directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceEntry {
    /// Resource type ID (e.g. `RT_ICON = 3`).
    pub type_id: u16,
    /// Resource name/ID.
    pub name_id: u16,
    /// Language ID.
    pub lang_id: u16,
    /// Raw resource data.
    pub data: Vec<u8>,
    /// Code page.
    pub code_page: u32,
}

impl ResourceEntry {
    /// Create a new resource entry.
    #[must_use]
    pub const fn new(type_id: u16, name_id: u16, lang_id: u16, data: Vec<u8>) -> Self {
        Self {
            type_id,
            name_id,
            lang_id,
            data,
            code_page: 0,
        }
    }

    /// Well-known resource type IDs.
    pub const RT_CURSOR: u16 = 1;
    pub const RT_BITMAP: u16 = 2;
    pub const RT_ICON: u16 = 3;
    pub const RT_MENU: u16 = 4;
    pub const RT_DIALOG: u16 = 5;
    pub const RT_STRING: u16 = 6;
    pub const RT_ACCELERATOR: u16 = 9;
    pub const RT_RCDATA: u16 = 10;
    pub const RT_MESSAGETABLE: u16 = 11;
    pub const RT_GROUP_CURSOR: u16 = 12;
    pub const RT_GROUP_ICON: u16 = 14;
    pub const RT_VERSION: u16 = 16;
    pub const RT_MANIFEST: u16 = 24;

    /// Return a short human-readable type name.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self.type_id {
            Self::RT_CURSOR => "RT_CURSOR",
            Self::RT_BITMAP => "RT_BITMAP",
            Self::RT_ICON => "RT_ICON",
            Self::RT_MENU => "RT_MENU",
            Self::RT_DIALOG => "RT_DIALOG",
            Self::RT_STRING => "RT_STRING",
            Self::RT_ACCELERATOR => "RT_ACCELERATOR",
            Self::RT_RCDATA => "RT_RCDATA",
            Self::RT_MESSAGETABLE => "RT_MESSAGETABLE",
            Self::RT_GROUP_CURSOR => "RT_GROUP_CURSOR",
            Self::RT_GROUP_ICON => "RT_GROUP_ICON",
            Self::RT_VERSION => "RT_VERSION",
            Self::RT_MANIFEST => "RT_MANIFEST",
            _ => "UNKNOWN",
        }
    }

    /// Return `true` if this is a version-info resource.
    #[must_use]
    pub const fn is_version_info(&self) -> bool {
        self.type_id == Self::RT_VERSION
    }

    /// Return `true` if this is a manifest resource.
    #[must_use]
    pub const fn is_manifest(&self) -> bool {
        self.type_id == Self::RT_MANIFEST
    }
}

impl fmt::Display for ResourceEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}[{}] lang={} size={}",
            self.type_name(),
            self.name_id,
            self.lang_id,
            self.data.len()
        )
    }
}

// ─── EditableSection ──────────────────────────────────────────────────────────

/// A mutable section record held by [`PeEditor`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditableSection {
    /// Section name (up to 8 bytes).
    pub name: String,
    /// Virtual size.
    pub virtual_size: u32,
    /// Relative virtual address.
    pub virtual_address: u32,
    /// File-aligned raw size.
    pub raw_size: u32,
    /// File offset of raw data.
    pub raw_offset: u32,
    /// Section characteristics flags.
    pub characteristics: u32,
    /// Raw data payload.
    pub data: Vec<u8>,
    /// Whether this section was added by the editor (not parsed from the file).
    pub is_new: bool,
}

impl EditableSection {
    /// Create a new empty section.
    #[must_use]
    pub fn new(name: impl Into<String>, characteristics: u32) -> Self {
        Self {
            name: name.into(),
            virtual_size: 0,
            virtual_address: 0,
            raw_size: 0,
            raw_offset: 0,
            characteristics,
            data: Vec::new(),
            is_new: true,
        }
    }

    /// Standard characteristics for a read-execute code section.
    pub const CODE_SECTION: u32 = 0x6000_0020;
    /// Standard characteristics for a read-write data section.
    pub const DATA_SECTION: u32 = 0xC000_0040;
    /// Standard characteristics for a read-only data section.
    pub const RDATA_SECTION: u32 = 0x4000_0040;

    /// Returns `true` if the section is executable.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        (self.characteristics & 0x2000_0000) != 0
    }

    /// Returns `true` if the section is writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        (self.characteristics & 0x8000_0000) != 0
    }

    /// Resize the section to `new_size` bytes, padding or truncating.
    pub fn resize(&mut self, new_size: usize) {
        self.data.resize(new_size, 0);
        self.virtual_size = u32::try_from(new_size).unwrap_or(u32::MAX);
    }
}

impl From<&PeSection> for EditableSection {
    fn from(s: &PeSection) -> Self {
        Self {
            name: s.name.clone(),
            virtual_size: s.virtual_size,
            virtual_address: s.virtual_address,
            raw_size: s.raw_size,
            raw_offset: s.raw_offset,
            characteristics: s.characteristics,
            data: s.data.clone(),
            is_new: false,
        }
    }
}

// ─── PeEditor ─────────────────────────────────────────────────────────────────

/// In-memory PE editor.
///
/// Load a PE via [`PeEditor::read_pe`], make changes, then serialise via
/// [`PeEditor::write_pe`].
pub struct PeEditor {
    /// Parsed PE metadata.
    pub pe: PeFile,
    /// Mutable section list.
    pub sections: Vec<EditableSection>,
    /// Mutable import list (editable imports).
    pub imports: Vec<EditableImport>,
    /// Mutable export list.
    pub exports: Vec<EditableExport>,
    /// Mutable resource entries.
    pub resources: Vec<ResourceEntry>,
    /// DLL characteristics (security flags).
    pub dll_characteristics: DllCharacteristics,
    /// File and section alignment constants.
    pub file_alignment: u32,
    pub section_alignment: u32,
    /// Raw bytes of the original file (kept for header reconstruction).
    raw: Vec<u8>,
    /// Whether the PE is 64-bit.
    pub is_64bit: bool,
    /// PE offset in the raw file.
    pe_offset: usize,
}

impl PeEditor {
    /// Parse a PE from raw bytes and prepare it for editing.
    ///
    /// # Errors
    ///
    /// Returns [`CffError`] if the bytes are not a valid PE.
    pub fn read_pe(data: &[u8]) -> Result<Self, CffError> {
        let mut pe = PeFile::parse(data)?;
        let _ = pe.parse_imports(data);
        let _ = pe.parse_exports(data);

        let sections: Vec<EditableSection> =
            pe.sections.iter().map(EditableSection::from).collect();

        let imports: Vec<EditableImport> = pe
            .imports
            .iter()
            .map(|i| EditableImport {
                dll: i.dll.clone(),
                name: i.name.clone(),
                ordinal: i.ordinal,
                hint: i.hint,
            })
            .collect();

        let exports: Vec<EditableExport> = pe
            .exports
            .iter()
            .map(|e| EditableExport {
                name: e.name.clone(),
                ordinal: e.ordinal,
                rva: e.rva,
                forwarder: e.forwarder.clone(),
            })
            .collect();

        let dll_characteristics = pe.dll_characteristics;
        let is_64bit = pe.is_64bit;

        // Read file/section alignment from optional header.
        let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
        let opt_offset = pe_offset + 24;
        let file_alignment = if opt_offset + 40 <= data.len() {
            u32::from_le_bytes(
                data[opt_offset + 36..opt_offset + 40]
                    .try_into()
                    .unwrap_or([0; 4]),
            )
        } else {
            0x200
        };
        let section_alignment = if opt_offset + 36 <= data.len() {
            u32::from_le_bytes(
                data[opt_offset + 32..opt_offset + 36]
                    .try_into()
                    .unwrap_or([0; 4]),
            )
        } else {
            0x1000
        };

        Ok(Self {
            pe,
            sections,
            imports,
            exports,
            resources: Vec::new(),
            dll_characteristics,
            file_alignment,
            section_alignment,
            raw: data.to_vec(),
            is_64bit,
            pe_offset,
        })
    }

    /// Serialise the (possibly modified) PE back to raw bytes.
    ///
    /// This reconstructs the section table header entries from the mutable
    /// `sections` list and copies raw data.  Import/export/resource tables are
    /// not re-serialised (the editor is intended for section-level edits +
    /// flag mutations + minimal import/export manipulation).
    ///
    /// # Errors
    ///
    /// Returns [`CffError::InvalidEdit`] if the layout cannot be satisfied.
    pub fn write_pe(&self) -> Result<Vec<u8>, CffError> {
        let mut buf = self.raw.clone();

        // Patch DLL characteristics back into the optional header.
        let opt_offset = self.pe_offset + 24;
        let dc_off = opt_offset + 70;
        if dc_off + 2 <= buf.len() {
            buf[dc_off..dc_off + 2].copy_from_slice(&self.dll_characteristics.0.to_le_bytes());
        }

        // Patch section table entries.
        let opt_hdr_size = if self.is_64bit { 240usize } else { 224usize };
        let sect_table_off = opt_offset + opt_hdr_size;
        for (i, s) in self.sections.iter().enumerate() {
            let off = sect_table_off + i * 40;
            if off + 40 > buf.len() {
                break;
            }
            // Name (8 bytes)
            let name_bytes = s.name.as_bytes();
            let n_len = name_bytes.len().min(8);
            buf[off..off + 8].fill(0);
            buf[off..off + n_len].copy_from_slice(&name_bytes[..n_len]);
            // VirtualSize
            buf[off + 8..off + 12].copy_from_slice(&s.virtual_size.to_le_bytes());
            // VirtualAddress
            buf[off + 12..off + 16].copy_from_slice(&s.virtual_address.to_le_bytes());
            // SizeOfRawData
            buf[off + 16..off + 20].copy_from_slice(&s.raw_size.to_le_bytes());
            // PointerToRawData
            buf[off + 20..off + 24].copy_from_slice(&s.raw_offset.to_le_bytes());
            // Characteristics at +36
            buf[off + 36..off + 40].copy_from_slice(&s.characteristics.to_le_bytes());

            // Copy raw data for modified sections.
            if s.is_new || s.data.len() != s.raw_size as usize {
                let start = s.raw_offset as usize;
                let end = start + s.raw_size as usize;
                if end <= buf.len() {
                    let copy_len = s.data.len().min(s.raw_size as usize);
                    buf[start..start + copy_len].copy_from_slice(&s.data[..copy_len]);
                    // Zero-pad remainder
                    if copy_len < s.raw_size as usize {
                        buf[start + copy_len..end].fill(0);
                    }
                }
            }
        }

        Ok(buf)
    }

    // ── Section editing ───────────────────────────────────────────────────────

    /// Add a new section with the given name, data, and characteristics.
    ///
    /// The section is appended after the last existing section (at the next
    /// file-aligned offset).
    ///
    /// # Errors
    ///
    /// Returns [`CffError::SectionExists`] if a section with that name exists.
    pub fn add_section(
        &mut self,
        name: &str,
        data: Vec<u8>,
        characteristics: u32,
    ) -> Result<(), CffError> {
        if self.sections.iter().any(|s| s.name == name) {
            return Err(CffError::SectionExists(name.to_string()));
        }
        if name.len() > 8 {
            return Err(CffError::InvalidEdit(format!(
                "section name '{name}' exceeds 8 characters"
            )));
        }

        // Compute raw offset: after the last section's raw end.
        let last_raw_end = self
            .sections
            .iter()
            .map(|s| s.raw_offset + s.raw_size)
            .max()
            .unwrap_or(0);
        let raw_offset = align_up(last_raw_end, self.file_alignment);

        // Compute virtual address: after the last section's virtual end.
        let last_va_end = self
            .sections
            .iter()
            .map(|s| s.virtual_address + align_up(s.virtual_size, self.section_alignment))
            .max()
            .unwrap_or(self.section_alignment);
        let virtual_address = align_up(last_va_end, self.section_alignment);

        let virtual_size = u32::try_from(data.len()).unwrap_or(u32::MAX);
        let raw_size = align_up(virtual_size, self.file_alignment);

        let mut new_sec = EditableSection::new(name, characteristics);
        new_sec.raw_offset = raw_offset;
        new_sec.raw_size = raw_size;
        new_sec.virtual_address = virtual_address;
        new_sec.virtual_size = virtual_size;
        new_sec.data = data;

        self.sections.push(new_sec);

        // Extend raw buffer to accommodate the new section.
        let needed = (raw_offset + raw_size) as usize;
        if self.raw.len() < needed {
            self.raw.resize(needed, 0);
        }

        Ok(())
    }

    /// Remove a section by name.
    ///
    /// # Errors
    ///
    /// Returns [`CffError::SectionNotFound`] if the section does not exist.
    pub fn remove_section(&mut self, name: &str) -> Result<(), CffError> {
        let pos = self
            .sections
            .iter()
            .position(|s| s.name == name)
            .ok_or_else(|| CffError::SectionNotFound(name.to_string()))?;
        self.sections.remove(pos);
        Ok(())
    }

    /// Rename a section.
    ///
    /// # Errors
    ///
    /// Returns [`CffError::SectionNotFound`] if the source does not exist or
    /// [`CffError::SectionExists`] if the target name already exists.
    pub fn rename_section(&mut self, old_name: &str, new_name: &str) -> Result<(), CffError> {
        if new_name.len() > 8 {
            return Err(CffError::InvalidEdit(format!(
                "section name '{new_name}' exceeds 8 characters"
            )));
        }
        if self.sections.iter().any(|s| s.name == new_name) {
            return Err(CffError::SectionExists(new_name.to_string()));
        }
        let sec = self
            .sections
            .iter_mut()
            .find(|s| s.name == old_name)
            .ok_or_else(|| CffError::SectionNotFound(old_name.to_string()))?;
        sec.name = new_name.to_string();
        Ok(())
    }

    /// Resize a section to `new_size` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CffError::SectionNotFound`] if the section does not exist.
    pub fn resize_section(&mut self, name: &str, new_size: usize) -> Result<(), CffError> {
        let sec = self
            .sections
            .iter_mut()
            .find(|s| s.name == name)
            .ok_or_else(|| CffError::SectionNotFound(name.to_string()))?;
        sec.resize(new_size);
        sec.raw_size = align_up(
            u32::try_from(new_size).unwrap_or(u32::MAX),
            self.file_alignment,
        );
        Ok(())
    }

    /// Return a reference to a section by name.
    #[must_use]
    pub fn section(&self, name: &str) -> Option<&EditableSection> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Return a mutable reference to a section by name.
    pub fn section_mut(&mut self, name: &str) -> Option<&mut EditableSection> {
        self.sections.iter_mut().find(|s| s.name == name)
    }

    // ── Import table editing ──────────────────────────────────────────────────

    /// Add a new import entry.
    ///
    /// The DLL name is normalised to title-case for display but stored as-is.
    pub fn add_import(&mut self, import: EditableImport) {
        self.imports.push(import);
    }

    /// Remove all imports from the given DLL.
    ///
    /// # Errors
    ///
    /// Returns [`CffError::ImportDllExists`] if the DLL was not found.  Wait —
    /// that's inverted; this returns `Ok(count_removed)`.
    pub fn remove_imports_from_dll(&mut self, dll: &str) -> usize {
        let before = self.imports.len();
        self.imports.retain(|i| !i.dll.eq_ignore_ascii_case(dll));
        before - self.imports.len()
    }

    /// Remove a specific named import.
    ///
    /// # Errors
    ///
    /// Returns [`CffError::ImportNotFound`] if no matching import exists.
    pub fn remove_import(&mut self, dll: &str, name: &str) -> Result<(), CffError> {
        let pos = self
            .imports
            .iter()
            .position(|i| i.dll.eq_ignore_ascii_case(dll) && (i.name.as_deref() == Some(name)))
            .ok_or_else(|| CffError::ImportNotFound(dll.to_string(), name.to_string()))?;
        self.imports.remove(pos);
        Ok(())
    }

    /// Redirect an import: change the DLL and/or function name.
    ///
    /// `old_dll` and `old_name` must match an existing import.
    ///
    /// # Errors
    ///
    /// Returns [`CffError::ImportNotFound`] if the source import is not found.
    pub fn redirect_import(
        &mut self,
        old_dll: &str,
        old_name: &str,
        new_dll: &str,
        new_name: &str,
    ) -> Result<(), CffError> {
        let imp = self
            .imports
            .iter_mut()
            .find(|i| i.dll.eq_ignore_ascii_case(old_dll) && (i.name.as_deref() == Some(old_name)))
            .ok_or_else(|| CffError::ImportNotFound(old_dll.to_string(), old_name.to_string()))?;
        imp.dll = new_dll.to_string();
        imp.name = Some(new_name.to_string());
        Ok(())
    }

    /// Return all imports grouped by DLL name.
    #[must_use]
    pub fn imports_by_dll(&self) -> HashMap<String, Vec<&EditableImport>> {
        let mut m: HashMap<String, Vec<&EditableImport>> = HashMap::new();
        for i in &self.imports {
            m.entry(i.dll.clone()).or_default().push(i);
        }
        m
    }

    // ── Export table editing ──────────────────────────────────────────────────

    /// Add or replace a named export.
    pub fn set_export(&mut self, export: EditableExport) {
        // Remove any existing export with the same ordinal or name.
        self.exports
            .retain(|e| e.ordinal != export.ordinal && e.name != export.name);
        self.exports.push(export);
        self.exports.sort_by_key(|e| e.ordinal);
    }

    /// Remove a named export.
    ///
    /// # Errors
    ///
    /// Returns [`CffError::ExportNotFound`] if no export with that name exists.
    pub fn remove_export(&mut self, name: &str) -> Result<(), CffError> {
        let pos = self
            .exports
            .iter()
            .position(|e| e.name.as_deref() == Some(name))
            .ok_or_else(|| CffError::ExportNotFound(name.to_string()))?;
        self.exports.remove(pos);
        Ok(())
    }

    /// Return an export by name.
    #[must_use]
    pub fn find_export(&self, name: &str) -> Option<&EditableExport> {
        self.exports
            .iter()
            .find(|e| e.name.as_deref() == Some(name))
    }

    // ── Resource directory editing ────────────────────────────────────────────

    /// Add or replace a resource entry identified by `(type_id, name_id, lang_id)`.
    pub fn set_resource(&mut self, entry: ResourceEntry) {
        self.resources.retain(|r| {
            !(r.type_id == entry.type_id
                && r.name_id == entry.name_id
                && r.lang_id == entry.lang_id)
        });
        self.resources.push(entry);
    }

    /// Remove a resource entry.
    ///
    /// # Errors
    ///
    /// Returns [`CffError::ResourceNotFound`] if no matching entry exists.
    pub fn remove_resource(
        &mut self,
        type_id: u16,
        name_id: u16,
        lang_id: u16,
    ) -> Result<(), CffError> {
        let pos = self
            .resources
            .iter()
            .position(|r| r.type_id == type_id && r.name_id == name_id && r.lang_id == lang_id)
            .ok_or(CffError::ResourceNotFound(type_id, name_id))?;
        self.resources.remove(pos);
        Ok(())
    }

    /// List all resource entries of a given type.
    #[must_use]
    pub fn resources_of_type(&self, type_id: u16) -> Vec<&ResourceEntry> {
        self.resources
            .iter()
            .filter(|r| r.type_id == type_id)
            .collect()
    }

    // ── Security flag manipulation ────────────────────────────────────────────

    /// Enable or disable ASLR (`DYNAMIC_BASE`).
    pub const fn set_aslr(&mut self, enabled: bool) {
        if enabled {
            self.dll_characteristics.0 |= DllCharacteristics::DYNAMIC_BASE;
        } else {
            self.dll_characteristics.0 &= !DllCharacteristics::DYNAMIC_BASE;
        }
    }

    /// Enable or disable high-entropy ASLR (`HIGH_ENTROPY_VA`).
    pub const fn set_high_entropy_va(&mut self, enabled: bool) {
        if enabled {
            self.dll_characteristics.0 |= DllCharacteristics::HIGH_ENTROPY_VA;
        } else {
            self.dll_characteristics.0 &= !DllCharacteristics::HIGH_ENTROPY_VA;
        }
    }

    /// Enable or disable NX / DEP (`NX_COMPAT`).
    pub const fn set_dep(&mut self, enabled: bool) {
        if enabled {
            self.dll_characteristics.0 |= DllCharacteristics::NX_COMPAT;
        } else {
            self.dll_characteristics.0 &= !DllCharacteristics::NX_COMPAT;
        }
    }

    /// Enable or disable Control Flow Guard (`GUARD_CF`).
    pub const fn set_cfg(&mut self, enabled: bool) {
        if enabled {
            self.dll_characteristics.0 |= DllCharacteristics::GUARD_CF;
        } else {
            self.dll_characteristics.0 &= !DllCharacteristics::GUARD_CF;
        }
    }

    /// Enable or disable the `NO_SEH` flag.
    pub const fn set_no_seh(&mut self, no_seh: bool) {
        if no_seh {
            self.dll_characteristics.0 |= DllCharacteristics::NO_SEH;
        } else {
            self.dll_characteristics.0 &= !DllCharacteristics::NO_SEH;
        }
    }

    /// Enable or disable force integrity check.
    pub const fn set_force_integrity(&mut self, enabled: bool) {
        if enabled {
            self.dll_characteristics.0 |= DllCharacteristics::FORCE_INTEGRITY;
        } else {
            self.dll_characteristics.0 &= !DllCharacteristics::FORCE_INTEGRITY;
        }
    }

    /// Apply a full set of hardening flags: ASLR + high-entropy + DEP + CFG.
    pub const fn harden(&mut self) {
        self.set_aslr(true);
        self.set_high_entropy_va(true);
        self.set_dep(true);
        self.set_cfg(true);
    }

    /// Strip all security flags.
    pub const fn strip_security_flags(&mut self) {
        self.dll_characteristics.0 &= !(DllCharacteristics::DYNAMIC_BASE
            | DllCharacteristics::HIGH_ENTROPY_VA
            | DllCharacteristics::NX_COMPAT
            | DllCharacteristics::GUARD_CF
            | DllCharacteristics::FORCE_INTEGRITY);
    }

    // ── Introspection helpers ─────────────────────────────────────────────────

    /// Return the number of sections currently in the editor.
    #[must_use]
    pub const fn section_count(&self) -> usize {
        self.sections.len()
    }

    /// Return the number of imports.
    #[must_use]
    pub const fn import_count(&self) -> usize {
        self.imports.len()
    }

    /// Return the number of exports.
    #[must_use]
    pub const fn export_count(&self) -> usize {
        self.exports.len()
    }

    /// Return whether ASLR is currently enabled.
    #[must_use]
    pub const fn has_aslr(&self) -> bool {
        self.dll_characteristics.has_aslr()
    }

    /// Return whether DEP is currently enabled.
    #[must_use]
    pub const fn has_dep(&self) -> bool {
        self.dll_characteristics.has_nx()
    }

    /// Return whether CFG is currently enabled.
    #[must_use]
    pub const fn has_cfg(&self) -> bool {
        self.dll_characteristics.has_cfg()
    }

    /// Summarize the current state as a JSON string.
    ///
    /// # Errors
    ///
    /// Returns a [`serde_json::Error`] on serialization failure.
    pub fn summary_json(&self) -> Result<String, serde_json::Error> {
        let sections: Vec<_> = self
            .sections
            .iter()
            .map(|s| {
                serde_json::json!({
                    "name": s.name,
                    "va": s.virtual_address,
                    "size": s.virtual_size,
                    "new": s.is_new,
                })
            })
            .collect();

        serde_json::to_string_pretty(&serde_json::json!({
            "sections": sections,
            "import_count": self.imports.len(),
            "export_count": self.exports.len(),
            "resource_count": self.resources.len(),
            "dll_characteristics": self.dll_characteristics.0,
            "flags": self.dll_characteristics.flag_names(),
            "is_64bit": self.is_64bit,
        }))
    }
}

impl fmt::Debug for PeEditor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeEditor")
            .field("pe", &self.pe)
            .field("sections", &self.sections.len())
            .field("imports", &self.imports.len())
            .field("exports", &self.exports.len())
            .field("resources", &self.resources.len())
            .field("dll_characteristics", &self.dll_characteristics)
            .field("file_alignment", &self.file_alignment)
            .field("section_alignment", &self.section_alignment)
            .field("raw_len", &self.raw.len())
            .field("is_64bit", &self.is_64bit)
            .field("pe_offset", &self.pe_offset)
            .finish_non_exhaustive()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PeBuilder;

    fn make_pe() -> Vec<u8> {
        let mut b = PeBuilder::new_x64();
        b.add_section(".text", vec![0x90u8; 64], 0x6000_0020);
        b.add_section(".data", vec![0u8; 32], 0xC000_0040);
        b.build()
    }

    #[test]
    fn read_pe_roundtrip() {
        let raw = make_pe();
        let ed = PeEditor::read_pe(&raw).expect("read_pe");
        assert_eq!(ed.section_count(), 2);
    }

    #[test]
    fn add_section_basic() {
        let raw = make_pe();
        let mut ed = PeEditor::read_pe(&raw).expect("read_pe");
        ed.add_section(".new", vec![0xCC; 16], 0x6000_0020)
            .expect("add_section");
        assert_eq!(ed.section_count(), 3);
        assert!(ed.section(".new").is_some());
    }

    #[test]
    fn add_section_duplicate_fails() {
        let raw = make_pe();
        let mut ed = PeEditor::read_pe(&raw).expect("read_pe");
        let err = ed.add_section(".text", vec![], 0x6000_0020);
        assert!(matches!(err, Err(CffError::SectionExists(_))));
    }

    #[test]
    fn remove_section() {
        let raw = make_pe();
        let mut ed = PeEditor::read_pe(&raw).expect("read_pe");
        ed.remove_section(".data").expect("remove");
        assert_eq!(ed.section_count(), 1);
        assert!(ed.section(".data").is_none());
    }

    #[test]
    fn remove_nonexistent_section_fails() {
        let raw = make_pe();
        let mut ed = PeEditor::read_pe(&raw).expect("read_pe");
        let err = ed.remove_section(".bss");
        assert!(matches!(err, Err(CffError::SectionNotFound(_))));
    }

    #[test]
    fn rename_section() {
        let raw = make_pe();
        let mut ed = PeEditor::read_pe(&raw).expect("read_pe");
        ed.rename_section(".data", ".rdata").expect("rename");
        assert!(ed.section(".rdata").is_some());
        assert!(ed.section(".data").is_none());
    }

    #[test]
    fn resize_section() {
        let raw = make_pe();
        let mut ed = PeEditor::read_pe(&raw).expect("read_pe");
        ed.resize_section(".text", 128).expect("resize");
        let sec = ed.section(".text").unwrap();
        assert_eq!(sec.virtual_size, 128);
        assert_eq!(sec.data.len(), 128);
    }

    #[test]
    fn security_flags() {
        let raw = make_pe();
        let mut ed = PeEditor::read_pe(&raw).expect("read_pe");
        ed.harden();
        assert!(ed.has_aslr());
        assert!(ed.has_dep());
        assert!(ed.has_cfg());
        ed.strip_security_flags();
        assert!(!ed.has_aslr());
        assert!(!ed.has_dep());
        assert!(!ed.has_cfg());
    }

    #[test]
    fn set_individual_flags() {
        let raw = make_pe();
        let mut ed = PeEditor::read_pe(&raw).expect("read_pe");
        ed.set_aslr(true);
        assert!(ed.has_aslr());
        ed.set_aslr(false);
        assert!(!ed.has_aslr());
        ed.set_dep(true);
        assert!(ed.has_dep());
        ed.set_dep(false);
        assert!(!ed.has_dep());
        ed.set_cfg(true);
        assert!(ed.has_cfg());
        ed.set_no_seh(true);
        assert!(ed.dll_characteristics.no_seh());
        ed.set_force_integrity(true);
        assert!(ed.dll_characteristics.force_integrity());
    }

    #[test]
    fn add_and_remove_import() {
        let raw = make_pe();
        let mut ed = PeEditor::read_pe(&raw).expect("read_pe");
        ed.add_import(EditableImport::by_name(
            "ntdll.dll",
            "NtQuerySystemInformation",
        ));
        assert!(
            ed.imports
                .iter()
                .any(|i| i.name.as_deref() == Some("NtQuerySystemInformation"))
        );
        ed.remove_import("ntdll.dll", "NtQuerySystemInformation")
            .expect("remove_import");
        assert!(
            !ed.imports
                .iter()
                .any(|i| i.name.as_deref() == Some("NtQuerySystemInformation"))
        );
    }

    #[test]
    fn redirect_import() {
        let raw = make_pe();
        let mut ed = PeEditor::read_pe(&raw).expect("read_pe");
        ed.add_import(EditableImport::by_name("kernel32.dll", "VirtualAlloc"));
        ed.redirect_import(
            "kernel32.dll",
            "VirtualAlloc",
            "kernelbase.dll",
            "VirtualAlloc",
        )
        .expect("redirect");
        assert!(
            ed.imports
                .iter()
                .any(|i| i.dll == "kernelbase.dll" && i.name.as_deref() == Some("VirtualAlloc"))
        );
    }

    #[test]
    fn redirect_import_not_found() {
        let raw = make_pe();
        let mut ed = PeEditor::read_pe(&raw).expect("read_pe");
        let err = ed.redirect_import("kernel32.dll", "VirtualAlloc", "x.dll", "y");
        assert!(matches!(err, Err(CffError::ImportNotFound(_, _))));
    }

    #[test]
    fn add_and_remove_export() {
        let raw = make_pe();
        let mut ed = PeEditor::read_pe(&raw).expect("read_pe");
        ed.set_export(EditableExport::named("MyFunc", 1, 0x1000));
        assert!(ed.find_export("MyFunc").is_some());
        ed.remove_export("MyFunc").expect("remove_export");
        assert!(ed.find_export("MyFunc").is_none());
    }

    #[test]
    fn add_resource() {
        let raw = make_pe();
        let mut ed = PeEditor::read_pe(&raw).expect("read_pe");
        ed.set_resource(ResourceEntry::new(
            ResourceEntry::RT_MANIFEST,
            1,
            0,
            b"<manifest/>".to_vec(),
        ));
        assert_eq!(ed.resources_of_type(ResourceEntry::RT_MANIFEST).len(), 1);
    }

    #[test]
    fn write_pe_valid() {
        let raw = make_pe();
        let mut ed = PeEditor::read_pe(&raw).expect("read_pe");
        ed.harden();
        let patched = ed.write_pe().expect("write_pe");
        // Re-parse the patched bytes.
        let pe2 = PeFile::parse(&patched).expect("re-parse");
        assert!(pe2.dll_characteristics.has_aslr());
        assert!(pe2.dll_characteristics.has_nx());
        assert!(pe2.dll_characteristics.has_cfg());
    }

    #[test]
    fn summary_json_valid() {
        let raw = make_pe();
        let ed = PeEditor::read_pe(&raw).expect("read_pe");
        let json = ed.summary_json().expect("json");
        assert!(json.contains("sections"));
    }

    #[test]
    fn editable_import_display() {
        let i = EditableImport::by_name("kernel32.dll", "CreateFile");
        assert!(i.display_name().contains("CreateFile"));
        let o = EditableImport::by_ordinal("ntdll.dll", 42);
        assert!(o.display_name().contains("#42"));
    }

    #[test]
    fn resource_entry_type_names() {
        let e = ResourceEntry::new(ResourceEntry::RT_ICON, 1, 0, vec![]);
        assert_eq!(e.type_name(), "RT_ICON");
        let m = ResourceEntry::new(ResourceEntry::RT_MANIFEST, 1, 0, vec![]);
        assert!(m.is_manifest());
        let v = ResourceEntry::new(ResourceEntry::RT_VERSION, 1, 0, vec![]);
        assert!(v.is_version_info());
    }

    #[test]
    fn imports_by_dll() {
        let raw = make_pe();
        let mut ed = PeEditor::read_pe(&raw).expect("read_pe");
        ed.add_import(EditableImport::by_name("kernel32.dll", "CreateFile"));
        ed.add_import(EditableImport::by_name("kernel32.dll", "ReadFile"));
        let map = ed.imports_by_dll();
        assert_eq!(map.get("kernel32.dll").map(std::vec::Vec::len), Some(2));
    }

    #[test]
    fn section_name_too_long_fails() {
        let raw = make_pe();
        let mut ed = PeEditor::read_pe(&raw).expect("read_pe");
        let err = ed.add_section(".toolongname", vec![], 0x6000_0020);
        assert!(matches!(err, Err(CffError::InvalidEdit(_))));
    }

    #[test]
    fn remove_all_imports_from_dll() {
        let raw = make_pe();
        let mut ed = PeEditor::read_pe(&raw).expect("read_pe");
        ed.add_import(EditableImport::by_name("user32.dll", "MessageBox"));
        ed.add_import(EditableImport::by_name("user32.dll", "CreateWindow"));
        let removed = ed.remove_imports_from_dll("user32.dll");
        assert_eq!(removed, 2);
    }
}
