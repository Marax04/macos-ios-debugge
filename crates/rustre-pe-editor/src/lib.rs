//! `rustre-pe-editor`
//!
//! PE binary editing — patch sections, modify imports, add/remove/resize
//! sections, edit exports, resources, header fields, encrypt/decrypt sections,
//! and scaffold PE signing operations.

pub mod certificate_editor;
pub mod import_editor;
pub mod overlay_editor;
pub mod pe_patcher;
pub mod pe_import_editor;
pub mod pe_resource_editor;
pub mod pe_section_editor;
pub mod pe_surgeon;
pub mod resource_editor;
pub mod section_editor;
pub mod pe_header_editor;
pub mod pe_certificate_table;
pub mod pe_debug_directory;


use std::collections::HashMap;
use std::fmt;

use parking_lot::RwLock;
use rustre_pe_tools::{PeError, PeFile};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by PE editing operations.
#[derive(Debug, Error)]
pub enum EditError {
    /// Underlying PE parse error.
    #[error("pe error: {0}")]
    Pe(#[from] PeError),
    /// Named section does not exist.
    #[error("section not found: {0}")]
    SectionNotFound(String),
    /// A patch extends beyond the end of the file buffer.
    #[error("patch out of bounds: offset={offset} len={len} file_size={file_size}")]
    PatchOutOfBounds {
        offset: usize,
        len: usize,
        file_size: usize,
    },
    /// Alignment constraint violated.
    #[error("invalid alignment: {0}")]
    InvalidAlignment(String),
    /// Encryption or decryption error.
    #[error("crypto error: {0}")]
    CryptoError(String),
    /// Import operation failed.
    #[error("import error: {0}")]
    ImportError(String),
    /// Export operation failed.
    #[error("export error: {0}")]
    ExportError(String),
    /// Resource operation failed.
    #[error("resource error: {0}")]
    ResourceError(String),
    /// Signing scaffold error.
    #[error("sign error: {0}")]
    SignError(String),
    /// The bytes at the given offset are not a branch this operation handles.
    #[error("not a conditional branch at offset {offset}: opcode {opcode:#04x}")]
    NotAConditionalBranch { offset: usize, opcode: u8 },
    /// I/O error wrapper.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// Patch / PatchSet
// ---------------------------------------------------------------------------

/// A byte-level patch to apply at a specific file offset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Patch {
    /// File byte offset at which to apply the replacement.
    pub offset: usize,
    /// Bytes that are expected to exist at `offset` before patching (for verification).
    pub original: Vec<u8>,
    /// Bytes to write at `offset`.
    pub replacement: Vec<u8>,
    /// Human-readable description of what this patch does.
    pub description: String,
}

impl Patch {
    /// Create a simple patch with no original-byte verification.
    #[must_use]
    pub const fn simple(offset: usize, replacement: Vec<u8>, description: String) -> Self {
        Self {
            offset,
            original: Vec::new(),
            replacement,
            description,
        }
    }

    /// Create a verified patch (original bytes checked before apply).
    #[must_use]
    pub const fn verified(
        offset: usize,
        original: Vec<u8>,
        replacement: Vec<u8>,
        description: String,
    ) -> Self {
        Self {
            offset,
            original,
            replacement,
            description,
        }
    }

    /// Length of the replacement in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.replacement.len()
    }

    /// Returns `true` if the replacement is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.replacement.is_empty()
    }

    /// Returns `true` if there are original bytes to verify.
    #[must_use]
    pub const fn has_verification(&self) -> bool {
        !self.original.is_empty()
    }
}

impl fmt::Display for Patch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Patch@{:#x}[{}]: {}",
            self.offset,
            self.replacement.len(),
            self.description
        )
    }
}

/// A named, ordered collection of [`Patch`] objects to apply together.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PatchSet {
    /// Ordered list of patches.
    pub patches: Vec<Patch>,
    /// Name / label for this patch set.
    pub name: String,
}

impl PatchSet {
    /// Create an empty patch set with the given name.
    #[must_use]
    pub const fn new(name: String) -> Self {
        Self {
            patches: vec![],
            name,
        }
    }

    /// Append a patch to the set.
    pub fn add(&mut self, patch: Patch) {
        self.patches.push(patch);
    }

    /// Number of patches in the set.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.patches.len()
    }

    /// Returns `true` if no patches have been added.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }

    /// Total replacement bytes across all patches.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.patches.iter().map(|p| p.replacement.len()).sum()
    }
}

impl fmt::Display for PatchSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PatchSet '{}' ({} patches)",
            self.name,
            self.patches.len()
        )
    }
}

// ---------------------------------------------------------------------------
// SectionEditor
// ---------------------------------------------------------------------------

/// Describes section characteristics.
pub mod section_chars {
    pub const CODE: u32 = 0x0000_0020;
    pub const INITIALIZED_DATA: u32 = 0x0000_0040;
    pub const UNINITIALIZED_DATA: u32 = 0x0000_0080;
    pub const MEM_DISCARDABLE: u32 = 0x0200_0000;
    pub const MEM_EXECUTE: u32 = 0x2000_0000;
    pub const MEM_READ: u32 = 0x4000_0000;
    pub const MEM_WRITE: u32 = 0x8000_0000;
}

/// A pending section modification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionEdit {
    /// Section name to target.
    pub name: String,
    /// New characteristics flags, if any.
    pub new_characteristics: Option<u32>,
    /// Bytes to append to the section.
    pub append_bytes: Vec<u8>,
    /// Bytes to prepend before the section.
    pub prepend_bytes: Vec<u8>,
    /// Whether to zero the entire section data.
    pub zero_out: bool,
}

impl SectionEdit {
    /// Create a characteristics-only edit.
    #[must_use]
    pub const fn set_chars(name: String, characteristics: u32) -> Self {
        Self {
            name,
            new_characteristics: Some(characteristics),
            append_bytes: Vec::new(),
            prepend_bytes: Vec::new(),
            zero_out: false,
        }
    }

    /// Create a zero-out edit.
    #[must_use]
    pub const fn zero(name: String) -> Self {
        Self {
            name,
            new_characteristics: None,
            append_bytes: Vec::new(),
            prepend_bytes: Vec::new(),
            zero_out: true,
        }
    }
}

/// Performs section-level edits on a PE buffer.
pub struct SectionEditor {
    data: Vec<u8>,
}

impl SectionEditor {
    /// Create a section editor from raw PE bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EditError`] if `data` is not a valid PE file.
    pub fn new(data: Vec<u8>) -> Result<Self, EditError> {
        PeFile::parse(&data).map_err(EditError::Pe)?;
        Ok(Self { data })
    }

    /// Rename a section (first 8 bytes of section header name field).
    ///
    /// # Errors
    ///
    /// Returns [`EditError::SectionNotFound`] if `old_name` is not present.
    pub fn rename_section(&mut self, old_name: &str, new_name: &str) -> Result<(), EditError> {
        let off = self.find_section_header(old_name)?;
        let name_bytes = new_name.as_bytes();
        let copy_len = name_bytes.len().min(8);
        self.data[off..off + copy_len].copy_from_slice(&name_bytes[..copy_len]);
        for b in &mut self.data[off + copy_len..off + 8] {
            *b = 0;
        }
        Ok(())
    }

    /// Set the characteristics flags of a named section.
    ///
    /// # Errors
    ///
    /// Returns [`EditError::SectionNotFound`] if the section is not present.
    pub fn set_characteristics(
        &mut self,
        name: &str,
        characteristics: u32,
    ) -> Result<(), EditError> {
        let off = self.find_section_header(name)?;
        self.data[off + 36..off + 40].copy_from_slice(&characteristics.to_le_bytes());
        Ok(())
    }

    /// Zero out the raw data of a named section.
    ///
    /// # Errors
    ///
    /// Returns [`EditError::SectionNotFound`] if the section is not present.
    pub fn zero_section(&mut self, name: &str) -> Result<(), EditError> {
        let (raw_off, raw_sz) = self.section_raw_range(name)?;
        if raw_off + raw_sz <= self.data.len() {
            self.data[raw_off..raw_off + raw_sz].fill(0);
        }
        Ok(())
    }

    /// Read raw data from a named section.
    ///
    /// # Errors
    ///
    /// Returns [`EditError::SectionNotFound`] if the section is not present.
    pub fn read_section(&self, name: &str) -> Result<&[u8], EditError> {
        let (raw_off, raw_sz) = self.section_raw_range(name)?;
        let end = (raw_off + raw_sz).min(self.data.len());
        Ok(&self.data[raw_off..end])
    }

    /// Write bytes into a named section at a relative offset within that section.
    ///
    /// # Errors
    ///
    /// Returns [`EditError::PatchOutOfBounds`] if the write exceeds the section raw size.
    pub fn write_into_section(
        &mut self,
        name: &str,
        section_offset: usize,
        bytes: &[u8],
    ) -> Result<(), EditError> {
        let (raw_off, raw_sz) = self.section_raw_range(name)?;
        let abs_off = raw_off + section_offset;
        if abs_off + bytes.len() > raw_off + raw_sz || abs_off + bytes.len() > self.data.len() {
            return Err(EditError::PatchOutOfBounds {
                offset: abs_off,
                len: bytes.len(),
                file_size: self.data.len(),
            });
        }
        self.data[abs_off..abs_off + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    /// Consume the editor and return the bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Borrow the current bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    // --- Internal helpers ---

    fn pe_header_offset(&self) -> Result<usize, EditError> {
        if self.data.len() < 64 {
            return Err(EditError::Pe(PeError::TooShort {
                needed: 64,
                got: self.data.len(),
            }));
        }
        let pe_offset =
            u32::from_le_bytes([self.data[60], self.data[61], self.data[62], self.data[63]])
                as usize;
        if pe_offset + 4 > self.data.len() {
            return Err(EditError::Pe(PeError::InvalidHeader(
                "PE offset out of range".to_string(),
            )));
        }
        Ok(pe_offset)
    }

    fn section_table_range(&self) -> Result<(usize, usize), EditError> {
        let pe_off = self.pe_header_offset()?;
        let n_sections =
            u16::from_le_bytes([self.data[pe_off + 6], self.data[pe_off + 7]]) as usize;
        let opt_hdr_size =
            u16::from_le_bytes([self.data[pe_off + 20], self.data[pe_off + 21]]) as usize;
        let sect_table_start = pe_off + 24 + opt_hdr_size;
        Ok((sect_table_start, n_sections))
    }

    fn find_section_header(&self, name: &str) -> Result<usize, EditError> {
        let (table_start, n_sections) = self.section_table_range()?;
        let name_bytes = name.as_bytes();
        for i in 0..n_sections {
            let off = table_start + i * 40;
            if off + 40 > self.data.len() {
                break;
            }
            let sec_name = &self.data[off..off + 8];
            let trimmed_len = sec_name.iter().position(|&b| b == 0).unwrap_or(8);
            if &sec_name[..trimmed_len] == name_bytes {
                return Ok(off);
            }
        }
        Err(EditError::SectionNotFound(name.to_string()))
    }

    fn section_raw_range(&self, name: &str) -> Result<(usize, usize), EditError> {
        let off = self.find_section_header(name)?;
        let raw_sz =
            u32::from_le_bytes(self.data[off + 16..off + 20].try_into().unwrap_or([0; 4])) as usize;
        let raw_off =
            u32::from_le_bytes(self.data[off + 20..off + 24].try_into().unwrap_or([0; 4])) as usize;
        Ok((raw_off, raw_sz))
    }
}

impl fmt::Debug for SectionEditor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SectionEditor {{ size: {} }}", self.data.len())
    }
}

// ---------------------------------------------------------------------------
// ImportEditor
// ---------------------------------------------------------------------------

/// Represents a single import entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEntry {
    /// DLL name.
    pub dll: String,
    /// Function name (empty for ordinal-only import).
    pub name: String,
    /// Ordinal (used when `name` is empty).
    pub ordinal: Option<u16>,
    /// Hint (ordinal hint for named imports).
    pub hint: u16,
}

impl ImportEntry {
    /// Create a named import.
    #[must_use]
    pub const fn named(dll: String, name: String, hint: u16) -> Self {
        Self {
            dll,
            name,
            ordinal: None,
            hint,
        }
    }

    /// Create an ordinal import.
    #[must_use]
    pub const fn ordinal(dll: String, ordinal: u16) -> Self {
        Self {
            dll,
            name: String::new(),
            ordinal: Some(ordinal),
            hint: 0,
        }
    }

    /// Returns `true` if imported by name.
    #[must_use]
    pub const fn is_named(&self) -> bool {
        !self.name.is_empty()
    }

    /// Display string for this import.
    #[must_use]
    pub fn display(&self) -> String {
        if self.is_named() {
            format!("{}!{}", self.dll, self.name)
        } else {
            format!("{}!#{}", self.dll, self.ordinal.unwrap_or(0))
        }
    }
}

impl fmt::Display for ImportEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display())
    }
}

/// Manages import additions and removals in a PE image.
pub struct ImportEditor {
    /// Pending imports to add.
    additions: Vec<ImportEntry>,
    /// DLL names whose entire import descriptor should be removed.
    removals: Vec<String>,
}

/// Build the import descriptor blob for `by_dll`, with RVAs relative to `section_rva`.
fn build_import_section_blob(
    by_dll: &std::collections::HashMap<String, Vec<&ImportEntry>>,
    section_rva: u32,
    is_pe32_plus: bool,
) -> Vec<u8> {
    let n_dlls = by_dll.len();
    let mut blob: Vec<u8> = vec![0u8; (n_dlls + 1) * 20];
    for (i, (dll, entries)) in by_dll.iter().enumerate() {
        let dll_name_off = blob.len();
        blob.extend_from_slice(dll.as_bytes());
        blob.push(0);
        if !blob.len().is_multiple_of(2) { blob.push(0); }
        let thunk_off = blob.len();
        let hint_name_base_off = thunk_off + (entries.len() + 1) * 8;
        let mut hint_name_cursor = hint_name_base_off;
        for e in entries {
            if e.is_named() {
                let hint_name_rva = section_rva.saturating_add(u32::try_from(hint_name_cursor).expect("hint name cursor fits in u32"));
                if is_pe32_plus {
                    blob.extend_from_slice(&u64::from(hint_name_rva).to_le_bytes());
                } else {
                    blob.extend_from_slice(&(hint_name_rva as u32).to_le_bytes());
                    blob.extend_from_slice(&[0u8; 4]);
                }
                let name_bytes = e.name.as_bytes();
                let entry_len = 2 + name_bytes.len() + 1;
                hint_name_cursor += entry_len + (entry_len % 2);
            } else {
                let ord_flag: u64 = if is_pe32_plus { 0x8000_0000_0000_0000 } else { 0x8000_0000 };
                let ord = ord_flag | u64::from(e.ordinal.unwrap_or(0));
                blob.extend_from_slice(&ord.to_le_bytes()[..if is_pe32_plus { 8 } else { 4 }]);
                if !is_pe32_plus { blob.extend_from_slice(&[0u8; 4]); }
            }
        }
        blob.extend_from_slice(&[0u8; 8]); // null terminator thunk
        for e in entries {
            if e.is_named() {
                let name_bytes = e.name.as_bytes();
                blob.extend_from_slice(&[0u8; 2]); // hint
                blob.extend_from_slice(name_bytes);
                blob.push(0);
                if !blob.len().is_multiple_of(2) { blob.push(0); }
            }
        }
        let desc_off = i * 20;
        let thunk_rva = section_rva.saturating_add(u32::try_from(thunk_off).expect("thunk offset fits in u32"));
        let dll_name_rva = section_rva.saturating_add(u32::try_from(dll_name_off).expect("dll name offset fits in u32"));
        blob[desc_off..desc_off + 4].copy_from_slice(&thunk_rva.to_le_bytes());
        blob[desc_off + 4..desc_off + 8].fill(0);
        blob[desc_off + 8..desc_off + 12].fill(0);
        blob[desc_off + 12..desc_off + 16].copy_from_slice(&dll_name_rva.to_le_bytes());
        blob[desc_off + 16..desc_off + 20].copy_from_slice(&thunk_rva.to_le_bytes());
    }
    blob
}

impl ImportEditor {
    /// Create an empty import editor.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            additions: Vec::new(),
            removals: Vec::new(),
        }
    }

    /// Queue an import addition.
    pub fn add_import(&mut self, entry: ImportEntry) {
        self.additions.push(entry);
    }

    /// Queue removal of all imports from a DLL.
    pub fn remove_dll(&mut self, dll_name: String) {
        self.removals.push(dll_name);
    }

    /// Number of pending additions.
    #[must_use]
    pub const fn pending_additions(&self) -> usize {
        self.additions.len()
    }

    /// Number of pending removals.
    #[must_use]
    pub const fn pending_removals(&self) -> usize {
        self.removals.len()
    }

    /// All pending additions.
    #[must_use]
    pub fn additions(&self) -> &[ImportEntry] {
        &self.additions
    }

    /// All pending removals.
    #[must_use]
    pub fn removals(&self) -> &[String] {
        &self.removals
    }

    /// Apply the pending edits to a PE image buffer.
    ///
    /// This is a best-effort operation: it serializes the new import directory
    /// into a new section appended to the image, then updates the data directory
    /// entry to point at it.
    ///
    /// # Errors
    ///
    /// Returns [`EditError::ImportError`] if the PE structure is too malformed.
    ///
    /// # Panics
    ///
    /// Panics if internal offset calculations overflow `u32` (PE file size must be < 4 GiB).
    pub fn apply(&self, pe_data: &mut Vec<u8>) -> Result<usize, EditError> {
        if self.additions.is_empty() {
            return Ok(0);
        }

        // Parse PE headers to find the section virtual address we will assign.
        if pe_data.len() < 64 {
            return Err(EditError::ImportError("PE too short".to_string()));
        }
        let e_lfanew = u32::from_le_bytes(
            pe_data[60..64].try_into().unwrap(),
        ) as usize;
        if e_lfanew + 24 > pe_data.len() {
            return Err(EditError::ImportError("PE header offset out of range".to_string()));
        }
        let num_sections = u16::from_le_bytes(
            pe_data[e_lfanew + 6..e_lfanew + 8].try_into().unwrap(),
        ) as usize;
        let opt_hdr_size = u16::from_le_bytes(
            pe_data[e_lfanew + 20..e_lfanew + 22].try_into().unwrap(),
        ) as usize;
        let opt_offset = e_lfanew + 24;
        if opt_offset + 2 > pe_data.len() {
            return Err(EditError::ImportError("no optional header".to_string()));
        }
        let magic = u16::from_le_bytes([pe_data[opt_offset], pe_data[opt_offset + 1]]);
        let is_pe32_plus = magic == 0x020B;

        // Compute the VA that a new appended section would receive.
        // These consts are declared early to satisfy items-after-statements.
        let sect_align_val: u32 = 0x1000;
        let file_align_val: u32 = 0x200;
        let sect_table_start = opt_offset + opt_hdr_size;
        let last_va_end: u32 = (0..num_sections)
            .filter_map(|i| {
                let off = sect_table_start + i * 40;
                if off + 40 <= pe_data.len() {
                    let va = u32::from_le_bytes(pe_data[off + 12..off + 16].try_into().unwrap_or([0; 4]));
                    let vsz = u32::from_le_bytes(pe_data[off + 8..off + 12].try_into().unwrap_or([0; 4]));
                    Some(va.saturating_add(vsz))
                } else {
                    None
                }
            })
            .max()
            .unwrap_or(sect_align_val);
        let section_rva = align_up_u32(last_va_end, sect_align_val);

        // Compute raw file offset where the new section data will start.
        if pe_data.len() > u32::MAX as usize {
            return Err(EditError::ImportError("PE data exceeds 4 GiB".to_string()));
        }
        let file_end = u32::try_from(pe_data.len()).expect("checked above");
        let raw_offset = align_up_u32(file_end, file_align_val);

        // Group additions by DLL
        let mut by_dll: HashMap<String, Vec<&ImportEntry>> = HashMap::new();
        for e in &self.additions {
            by_dll.entry(e.dll.clone()).or_default().push(e);
        }

        // Build a minimal import descriptor blob (one descriptor per DLL + null terminator).
        let blob = build_import_section_blob(&by_dll, section_rva, is_pe32_plus);

        let added = self.additions.len();

        // Pad pe_data to raw_offset and append blob
        let pad_before = (raw_offset as usize).saturating_sub(pe_data.len());
        pe_data.extend(std::iter::repeat_n(0u8, pad_before));
        pe_data.extend_from_slice(&blob);

        // Update DataDirectory[1] (Import Table) in the optional header:
        // For PE32:   DataDirectory starts at opt_offset + 96
        // For PE32+:  DataDirectory starts at opt_offset + 112
        let data_dir_base = if is_pe32_plus { opt_offset + 112 } else { opt_offset + 96 };
        let import_dir_off = data_dir_base + 8; // entry [1] = 2nd entry, 8 bytes each
        if import_dir_off + 8 <= pe_data.len() {
            pe_data[import_dir_off..import_dir_off + 4].copy_from_slice(&section_rva.to_le_bytes());
            let blob_size = u32::try_from(blob.len()).expect("blob size fits in u32");
            pe_data[import_dir_off + 4..import_dir_off + 8].copy_from_slice(&blob_size.to_le_bytes());
        }

        Ok(added)
    }

    /// Clear all pending operations.
    pub fn clear(&mut self) {
        self.additions.clear();
        self.removals.clear();
    }
}

impl Default for ImportEditor {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ImportEditor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ImportEditor {{ +{} -{} }}",
            self.additions.len(),
            self.removals.len()
        )
    }
}

// ---------------------------------------------------------------------------
// ExportEditor
// ---------------------------------------------------------------------------

/// A pending export addition or removal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEdit {
    /// Export name.
    pub name: String,
    /// Export ordinal.
    pub ordinal: u32,
    /// RVA of the exported symbol.
    pub rva: u32,
    /// Whether this is a removal (true) or addition (false).
    pub remove: bool,
}

impl ExportEdit {
    /// Create an add-export edit.
    #[must_use]
    pub const fn add(name: String, ordinal: u32, rva: u32) -> Self {
        Self {
            name,
            ordinal,
            rva,
            remove: false,
        }
    }

    /// Create a remove-export edit.
    #[must_use]
    pub const fn remove(name: String) -> Self {
        Self {
            name,
            ordinal: 0,
            rva: 0,
            remove: true,
        }
    }
}

impl fmt::Display for ExportEdit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.remove {
            write!(f, "Remove export: {}", self.name)
        } else {
            write!(
                f,
                "Add export: {} ord={} rva={:#x}",
                self.name, self.ordinal, self.rva
            )
        }
    }
}

/// Manages export additions and removals.
pub struct ExportEditor {
    dll_name: String,
    edits: Vec<ExportEdit>,
}

impl ExportEditor {
    /// Create a new export editor for the given DLL name.
    #[must_use]
    pub const fn new(dll_name: String) -> Self {
        Self {
            dll_name,
            edits: Vec::new(),
        }
    }

    /// Queue an export to add.
    pub fn add_export(&mut self, name: String, ordinal: u32, rva: u32) {
        self.edits.push(ExportEdit::add(name, ordinal, rva));
    }

    /// Queue an export to remove by name.
    pub fn remove_export(&mut self, name: String) {
        self.edits.push(ExportEdit::remove(name));
    }

    /// Number of pending edits.
    #[must_use]
    pub const fn pending_count(&self) -> usize {
        self.edits.len()
    }

    /// Additions pending.
    #[must_use]
    pub fn additions(&self) -> Vec<&ExportEdit> {
        self.edits.iter().filter(|e| !e.remove).collect()
    }

    /// Removals pending.
    #[must_use]
    pub fn removals(&self) -> Vec<&ExportEdit> {
        self.edits.iter().filter(|e| e.remove).collect()
    }

    /// DLL name for this editor.
    #[must_use]
    pub fn dll_name(&self) -> &str {
        &self.dll_name
    }

    /// Clear all pending edits.
    pub fn clear(&mut self) {
        self.edits.clear();
    }
}

impl fmt::Debug for ExportEditor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExportEditor {{ dll: {}, edits: {} }}",
            self.dll_name,
            self.edits.len()
        )
    }
}

// ---------------------------------------------------------------------------
// ResourceEditor
// ---------------------------------------------------------------------------

/// A resource type identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceType {
    /// Pre-defined RT_* type by integer ID.
    Id(u16),
    /// String name.
    Name(String),
}

impl fmt::Display for ResourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Id(id) => write!(f, "#{id}"),
            Self::Name(n) => write!(f, "{n}"),
        }
    }
}

/// Common pre-defined resource type IDs.
pub mod resource_types {
    pub const RT_CURSOR: u16 = 1;
    pub const RT_BITMAP: u16 = 2;
    pub const RT_ICON: u16 = 3;
    pub const RT_MENU: u16 = 4;
    pub const RT_DIALOG: u16 = 5;
    pub const RT_STRING: u16 = 6;
    pub const RT_VERSION: u16 = 16;
    pub const RT_MANIFEST: u16 = 24;
}

/// A resource entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceEntry {
    /// Resource type.
    pub resource_type: ResourceType,
    /// Resource ID or name.
    pub id: u32,
    /// Language ID.
    pub language: u16,
    /// Raw resource data.
    pub data: Vec<u8>,
}

impl ResourceEntry {
    /// Create a resource entry by type ID.
    #[must_use]
    pub const fn new(resource_type: u16, id: u32, language: u16, data: Vec<u8>) -> Self {
        Self {
            resource_type: ResourceType::Id(resource_type),
            id,
            language,
            data,
        }
    }

    /// Create a manifest resource.
    #[must_use]
    pub const fn manifest(data: Vec<u8>) -> Self {
        Self::new(resource_types::RT_MANIFEST, 1, 0x0409, data)
    }

    /// Data length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the resource has no data.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl fmt::Display for ResourceEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Resource({}) id={} lang={} size={}",
            self.resource_type,
            self.id,
            self.language,
            self.data.len()
        )
    }
}

/// Manages resource additions and removals.
pub struct ResourceEditor {
    additions: Vec<ResourceEntry>,
    removals: Vec<(ResourceType, u32)>,
}

impl ResourceEditor {
    /// Create a new resource editor.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            additions: Vec::new(),
            removals: Vec::new(),
        }
    }

    /// Queue a resource to add.
    pub fn add_resource(&mut self, entry: ResourceEntry) {
        self.additions.push(entry);
    }

    /// Queue a resource to remove by type and ID.
    pub fn remove_resource(&mut self, resource_type: ResourceType, id: u32) {
        self.removals.push((resource_type, id));
    }

    /// Number of pending additions.
    #[must_use]
    pub const fn pending_additions(&self) -> usize {
        self.additions.len()
    }

    /// Number of pending removals.
    #[must_use]
    pub const fn pending_removals(&self) -> usize {
        self.removals.len()
    }

    /// All pending additions.
    #[must_use]
    pub fn additions(&self) -> &[ResourceEntry] {
        &self.additions
    }

    /// Clear all pending operations.
    pub fn clear(&mut self) {
        self.additions.clear();
        self.removals.clear();
    }

    /// Total size in bytes of all pending addition data.
    #[must_use]
    pub fn total_data_size(&self) -> usize {
        self.additions.iter().map(|r| r.data.len()).sum()
    }
}

impl Default for ResourceEditor {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ResourceEditor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ResourceEditor {{ +{} -{} }}",
            self.additions.len(),
            self.removals.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Section encryption / decryption
// ---------------------------------------------------------------------------

/// XOR encryption/decryption of a section with a repeating key.
///
/// # Panics
///
/// Panics if `key` is empty.
pub fn xor_section(data: &mut [u8], key: &[u8]) {
    assert!(!key.is_empty(), "xor key must not be empty");
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

/// RC4 stream cipher (used for section encryption/decryption).
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Initialize RC4 with the given key.
    ///
    /// # Panics
    ///
    /// Panics if `key` is empty.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        assert!(!key.is_empty(), "RC4 key must not be empty");
        let mut s = [0u8; 256];
        for (i, b) in s.iter_mut().enumerate() {
            // i is always 0..=255, so this cast is safe.
            *b = u8::try_from(i).expect("i is 0..=255");
        }
        let mut j: u8 = 0;
        let klen = key.len();
        for i in 0u8..=255 {
            j = j
                .wrapping_add(s[i as usize])
                .wrapping_add(key[i as usize % klen]);
            s.swap(i as usize, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    /// Generate the next pseudo-random byte.
    pub const fn next_byte(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.s[self.i as usize]);
        self.s.swap(self.i as usize, self.j as usize);
        self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize]
    }

    /// Encrypt or decrypt `data` in-place.
    pub fn process(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            *byte ^= self.next_byte();
        }
    }
}

// ---------------------------------------------------------------------------
// PE signing scaffold
// ---------------------------------------------------------------------------

/// Stub certificate header for PE signing scaffold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateHeader {
    /// Total size of `WIN_CERTIFICATE` structure including data.
    pub dw_length: u32,
    /// Certificate revision (0x0200 = `WIN_CERT_REVISION_2_0`).
    pub w_revision: u16,
    /// Certificate type (0x0002 = `WIN_CERT_TYPE_PKCS_SIGNED_DATA`).
    pub w_certificate_type: u16,
}

impl CertificateHeader {
    /// Create a stub certificate header for a payload of `payload_len` bytes.
    #[must_use]
    pub const fn new(payload_len: u32) -> Self {
        Self {
            dw_length: 8 + payload_len,
            w_revision: 0x0200,
            w_certificate_type: 0x0002,
        }
    }

    /// Serialize to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0..4].copy_from_slice(&self.dw_length.to_le_bytes());
        out[4..6].copy_from_slice(&self.w_revision.to_le_bytes());
        out[6..8].copy_from_slice(&self.w_certificate_type.to_le_bytes());
        out
    }
}

/// Scaffold for PE Authenticode signing (does NOT perform actual cryptographic signing;
/// it sets up the structure for external PKCS#7 payload injection).
pub struct PeSigningScaffold {
    certificate_payload: Vec<u8>,
}

impl PeSigningScaffold {
    /// Create a scaffold with the given PKCS#7 DER-encoded payload.
    #[must_use]
    pub const fn new(certificate_payload: Vec<u8>) -> Self {
        Self {
            certificate_payload,
        }
    }

    /// Build the `WIN_CERTIFICATE` blob.
    ///
    /// # Panics
    /// Panics if `certificate_payload.len()` exceeds `u32::MAX`.
    #[must_use]
    pub fn build_certificate_blob(&self) -> Vec<u8> {
        let hdr = CertificateHeader::new(u32::try_from(self.certificate_payload.len()).expect("certificate payload fits in u32"));
        let mut out = hdr.to_bytes().to_vec();
        out.extend_from_slice(&self.certificate_payload);
        // Align to 8 bytes
        let pad = (8 - out.len() % 8) % 8;
        out.extend(std::iter::repeat_n(0u8, pad));
        out
    }

    /// Inject the certificate blob into `pe_data` and update `DataDirectory`[4].
    ///
    /// # Errors
    ///
    /// Returns [`EditError::SignError`] if the PE structure is too malformed.
    ///
    /// # Panics
    /// Panics if `pe_data.len()` or the certificate blob size exceeds `u32::MAX`.
    pub fn inject(&self, pe_data: &mut Vec<u8>) -> Result<(), EditError> {
        if pe_data.len() < 64 {
            return Err(EditError::SignError("PE too short".to_string()));
        }
        let pe_off =
            u32::from_le_bytes([pe_data[60], pe_data[61], pe_data[62], pe_data[63]]) as usize;
        if pe_off + 24 > pe_data.len() {
            return Err(EditError::SignError("PE header out of range".to_string()));
        }
        let opt_off = pe_off + 24;
        if opt_off + 2 > pe_data.len() {
            return Err(EditError::SignError("no optional header".to_string()));
        }
        let magic = u16::from_le_bytes([pe_data[opt_off], pe_data[opt_off + 1]]);
        let is_64bit = magic == 0x020B;

        let cert_blob = self.build_certificate_blob();
        let cert_rva = u32::try_from(pe_data.len()).expect("PE data fits in u32");
        let cert_size = u32::try_from(cert_blob.len()).expect("cert blob fits in u32");

        pe_data.extend_from_slice(&cert_blob);

        // Update DataDirectory[4] (security)
        let dd_off = if is_64bit {
            opt_off + 112
        } else {
            opt_off + 96
        };
        let security_dd_off = dd_off + 4 * 8;
        if security_dd_off + 8 <= pe_data.len() {
            pe_data[security_dd_off..security_dd_off + 4].copy_from_slice(&cert_rva.to_le_bytes());
            pe_data[security_dd_off + 4..security_dd_off + 8]
                .copy_from_slice(&cert_size.to_le_bytes());
        }

        Ok(())
    }

    /// Payload size.
    #[must_use]
    pub const fn payload_len(&self) -> usize {
        self.certificate_payload.len()
    }
}

// ---------------------------------------------------------------------------
// Header field editor
// ---------------------------------------------------------------------------

/// Pre-defined optional header fields that can be edited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HeaderField {
    /// `MajorLinkerVersion`.
    MajorLinkerVersion,
    /// `MinorLinkerVersion`.
    MinorLinkerVersion,
    /// `MajorOperatingSystemVersion`.
    MajorOsVersion,
    /// `MinorOperatingSystemVersion`.
    MinorOsVersion,
    /// `MajorImageVersion`.
    MajorImageVersion,
    /// `MinorImageVersion`.
    MinorImageVersion,
    /// `MajorSubsystemVersion`.
    MajorSubsystemVersion,
    /// `MinorSubsystemVersion`.
    MinorSubsystemVersion,
    /// `Win32VersionValue`.
    Win32VersionValue,
    /// `SizeOfStackReserve`.
    SizeOfStackReserve,
    /// `SizeOfStackCommit`.
    SizeOfStackCommit,
    /// `SizeOfHeapReserve`.
    SizeOfHeapReserve,
    /// `SizeOfHeapCommit`.
    SizeOfHeapCommit,
    /// Subsystem.
    Subsystem,
    /// `DllCharacteristics`.
    DllCharacteristics,
}

impl fmt::Display for HeaderField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ---------------------------------------------------------------------------
// PeEditor (main type)
// ---------------------------------------------------------------------------

/// In-memory PE binary editor.
pub struct PeEditor {
    data: Vec<u8>,
    applied_patches: Vec<Patch>,
    edit_log: RwLock<Vec<String>>,
}

/// Write the 40-byte section header fields into `data[off..]`.
fn write_pe_section_header_fields(
    data: &mut [u8],
    off: usize,
    name: &str,
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_offset: u32,
) {
    let name_bytes = name.as_bytes();
    let copy_len = name_bytes.len().min(8);
    data[off..off + copy_len].copy_from_slice(&name_bytes[..copy_len]);
    for b in &mut data[off + copy_len..off + 8] { *b = 0; }
    data[off + 8..off + 12].copy_from_slice(&virtual_size.to_le_bytes());
    data[off + 12..off + 16].copy_from_slice(&virtual_address.to_le_bytes());
    data[off + 16..off + 20].copy_from_slice(&raw_size.to_le_bytes());
    data[off + 20..off + 24].copy_from_slice(&raw_offset.to_le_bytes());
    for b in &mut data[off + 24..off + 36] { *b = 0; }
    // characteristics written by caller after this
}

/// Update section count and `SizeOfImage` after inserting a new section.
fn update_count_and_image_size(
    data: &mut [u8],
    num_sections_off: usize,
    opt_offset: usize,
    is_64bit: bool,
    new_image_size: u32,
    cur_sections: usize,
) {
    let new_count = u16::try_from(cur_sections + 1).expect("section count fits in u16");
    data[num_sections_off..num_sections_off + 2].copy_from_slice(&new_count.to_le_bytes());
    let min_opt_size = if is_64bit { 112usize } else { 96usize };
    let size_of_image_off = opt_offset + 56;
    if opt_offset + min_opt_size <= data.len() {
        data[size_of_image_off..size_of_image_off + 4].copy_from_slice(&new_image_size.to_le_bytes());
    }
}

impl PeEditor {
    /// Create a new editor from raw PE bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EditError`] if `data` is not a valid PE file.
    pub fn new(data: Vec<u8>) -> Result<Self, EditError> {
        PeFile::parse(&data).map_err(EditError::Pe)?;
        Ok(Self {
            data,
            applied_patches: vec![],
            edit_log: RwLock::new(Vec::new()),
        })
    }

    /// Apply a single patch.
    ///
    /// # Errors
    ///
    /// Returns [`EditError::PatchOutOfBounds`] if the replacement extends
    /// past the end of the file buffer.
    pub fn apply_patch(&mut self, patch: Patch) -> Result<(), EditError> {
        if patch.offset + patch.replacement.len() > self.data.len() {
            return Err(EditError::PatchOutOfBounds {
                offset: patch.offset,
                len: patch.replacement.len(),
                file_size: self.data.len(),
            });
        }
        // Optional verification
        if patch.has_verification() && !patch.original.is_empty() {
            let orig_end = patch.offset + patch.original.len();
            if orig_end > self.data.len() {
                return Err(EditError::PatchOutOfBounds {
                    offset: patch.offset,
                    len: patch.original.len(),
                    file_size: self.data.len(),
                });
            }
            let cur = &self.data[patch.offset..orig_end];
            if cur != patch.original.as_slice() {
                self.edit_log
                    .write()
                    .push(format!("verification mismatch at {:#x}", patch.offset));
            }
        }
        self.data[patch.offset..patch.offset + patch.replacement.len()]
            .copy_from_slice(&patch.replacement);
        self.edit_log.write().push(format!(
            "patch @ {:#x}: {}",
            patch.offset, patch.description
        ));
        self.applied_patches.push(patch);
        Ok(())
    }

    /// Apply all patches in a [`PatchSet`] in order.
    ///
    /// # Errors
    ///
    /// Returns [`EditError`] if any patch fails; prior patches are already applied.
    pub fn apply_patchset(&mut self, patchset: PatchSet) -> Result<(), EditError> {
        for p in patchset.patches {
            self.apply_patch(p)?;
        }
        Ok(())
    }

    /// Fill `len` bytes at `offset` with the x86 NOP opcode (0x90).
    ///
    /// # Errors
    ///
    /// Returns [`EditError::PatchOutOfBounds`] if the range extends past the buffer.
    pub fn nop_range(&mut self, offset: usize, len: usize) -> Result<(), EditError> {
        if offset + len > self.data.len() {
            return Err(EditError::PatchOutOfBounds {
                offset,
                len,
                file_size: self.data.len(),
            });
        }
        self.data[offset..offset + len].fill(0x90);
        self.edit_log
            .write()
            .push(format!("nop {len} bytes @ {offset:#x}"));
        Ok(())
    }

    /// Fill `len` bytes at `offset` with `0xCC` (INT3 breakpoints).
    ///
    /// # Errors
    ///
    /// Returns [`EditError::PatchOutOfBounds`] if the range extends past the buffer.
    pub fn int3_range(&mut self, offset: usize, len: usize) -> Result<(), EditError> {
        if offset + len > self.data.len() {
            return Err(EditError::PatchOutOfBounds {
                offset,
                len,
                file_size: self.data.len(),
            });
        }
        self.data[offset..offset + len].fill(0xCC);
        Ok(())
    }

    /// Write arbitrary bytes at an offset.
    ///
    /// # Errors
    ///
    /// Returns [`EditError::PatchOutOfBounds`] if the write extends past the buffer.
    pub fn write_bytes(&mut self, offset: usize, bytes: &[u8]) -> Result<(), EditError> {
        if offset + bytes.len() > self.data.len() {
            return Err(EditError::PatchOutOfBounds {
                offset,
                len: bytes.len(),
                file_size: self.data.len(),
            });
        }
        self.data[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    /// Read bytes from the PE buffer.
    ///
    /// # Errors
    ///
    /// Returns [`EditError::PatchOutOfBounds`] if the range is out of bounds.
    pub fn read_bytes(&self, offset: usize, len: usize) -> Result<&[u8], EditError> {
        if offset + len > self.data.len() {
            return Err(EditError::PatchOutOfBounds {
                offset,
                len,
                file_size: self.data.len(),
            });
        }
        Ok(&self.data[offset..offset + len])
    }

    /// Rewrite the entry-point RVA in the PE optional header.
    ///
    /// # Errors
    ///
    /// Returns [`EditError`] if the PE structure is malformed.
    pub fn patch_entry_point(&mut self, new_ep_rva: u32) -> Result<(), EditError> {
        let pe_offset = self.pe_header_offset()?;
        let opt_offset = pe_offset + 24;
        if opt_offset + 20 > self.data.len() {
            return Err(EditError::Pe(PeError::InvalidHeader(
                "optional header truncated".to_string(),
            )));
        }
        self.data[opt_offset + 16..opt_offset + 20].copy_from_slice(&new_ep_rva.to_le_bytes());
        self.edit_log
            .write()
            .push(format!("EP set to {new_ep_rva:#x}"));
        Ok(())
    }

    /// Zero out the PE checksum field in the optional header.
    ///
    /// # Errors
    ///
    /// Returns [`EditError`] if the PE structure is malformed.
    pub fn zero_checksum(&mut self) -> Result<(), EditError> {
        let pe_offset = self.pe_header_offset()?;
        let opt_offset = pe_offset + 24;
        if opt_offset + 68 > self.data.len() {
            return Err(EditError::Pe(PeError::InvalidHeader(
                "optional header too short for checksum".to_string(),
            )));
        }
        self.data[opt_offset + 64..opt_offset + 68].fill(0);
        Ok(())
    }

    /// Set the ASLR (`DYNAMIC_BASE`) bit in `DllCharacteristics`.
    ///
    /// # Errors
    ///
    /// Returns [`EditError`] if the PE structure is malformed.
    pub fn set_aslr(&mut self, enable: bool) -> Result<(), EditError> {
        self.set_dll_characteristic(0x0040, enable)
    }

    /// Set the NX (`NO_SEH`) bit in `DllCharacteristics`.
    ///
    /// # Errors
    ///
    /// Returns [`EditError`] if the PE structure is malformed.
    pub fn set_nx(&mut self, enable: bool) -> Result<(), EditError> {
        self.set_dll_characteristic(0x0100, enable)
    }

    /// Set or clear a specific `DllCharacteristics` bit.
    ///
    /// # Errors
    ///
    /// Returns [`EditError`] if the PE structure is malformed.
    pub fn set_dll_characteristic(&mut self, flag: u16, enable: bool) -> Result<(), EditError> {
        let pe_offset = self.pe_header_offset()?;
        let opt_offset = pe_offset + 24;
        if opt_offset + 2 > self.data.len() {
            return Err(EditError::Pe(PeError::InvalidHeader(
                "no opt header".to_string(),
            )));
        }
        let magic = u16::from_le_bytes([self.data[opt_offset], self.data[opt_offset + 1]]);
        // DllCharacteristics is at offset 70 for both PE32 (0x010B) and PE32+ (0x020B).
        // PE32 optional header standard size is 96 bytes; PE32+ is 112 bytes.
        let is_pe32_plus = magic == 0x020B;
        let min_opt_size = if is_pe32_plus { 112usize } else { 96usize };
        if opt_offset + min_opt_size > self.data.len() {
            return Err(EditError::Pe(PeError::InvalidHeader(
                "opt header too short for DllCharacteristics".to_string(),
            )));
        }
        let dll_chars_off = opt_offset + 70;
        if dll_chars_off + 2 > self.data.len() {
            return Err(EditError::Pe(PeError::InvalidHeader(
                "DllCharacteristics out of range".to_string(),
            )));
        }
        let mut dc = u16::from_le_bytes([self.data[dll_chars_off], self.data[dll_chars_off + 1]]);
        if enable {
            dc |= flag;
        } else {
            dc &= !flag;
        }
        self.data[dll_chars_off..dll_chars_off + 2].copy_from_slice(&dc.to_le_bytes());
        Ok(())
    }

    /// Set the `ImageBase` in the optional header.
    ///
    /// # Errors
    ///
    /// Returns [`EditError`] if the PE structure is malformed.
    ///
    /// # Panics
    /// Panics if `base` exceeds `u32::MAX` for a PE32 (32-bit) image.
    pub fn set_image_base(&mut self, base: u64) -> Result<(), EditError> {
        let pe_offset = self.pe_header_offset()?;
        let opt_offset = pe_offset + 24;
        if opt_offset + 2 > self.data.len() {
            return Err(EditError::Pe(PeError::InvalidHeader(
                "no opt header".to_string(),
            )));
        }
        let magic = u16::from_le_bytes([self.data[opt_offset], self.data[opt_offset + 1]]);
        let is_64bit = magic == 0x020B;
        if opt_offset + 32 > self.data.len() {
            return Err(EditError::Pe(PeError::InvalidHeader(
                "opt header too short".to_string(),
            )));
        }
        if is_64bit {
            self.data[opt_offset + 24..opt_offset + 32].copy_from_slice(&base.to_le_bytes());
        } else {
            self.data[opt_offset + 28..opt_offset + 32]
                .copy_from_slice(&u32::try_from(base).expect("image base fits in u32 for PE32").to_le_bytes());
        }
        Ok(())
    }

    /// Set the Subsystem field.
    ///
    /// # Errors
    ///
    /// Returns [`EditError`] if the PE structure is malformed.
    pub fn set_subsystem(&mut self, subsystem: u16) -> Result<(), EditError> {
        let pe_offset = self.pe_header_offset()?;
        let opt_offset = pe_offset + 24;
        if opt_offset + 2 > self.data.len() {
            return Err(EditError::Pe(PeError::InvalidHeader(
                "no opt header".to_string(),
            )));
        }
        let magic = u16::from_le_bytes([self.data[opt_offset], self.data[opt_offset + 1]]);
        // Subsystem is at offset 68 for both PE32 (0x010B) and PE32+ (0x020B).
        // PE32 optional header standard size is 96 bytes; PE32+ is 112 bytes.
        let is_pe32_plus = magic == 0x020B;
        let min_opt_size = if is_pe32_plus { 112usize } else { 96usize };
        if opt_offset + min_opt_size > self.data.len() {
            return Err(EditError::Pe(PeError::InvalidHeader(
                "opt header too short for Subsystem".to_string(),
            )));
        }
        let sub_off = opt_offset + 68;
        if sub_off + 2 > self.data.len() {
            return Err(EditError::Pe(PeError::InvalidHeader(
                "subsystem field out of range".to_string(),
            )));
        }
        self.data[sub_off..sub_off + 2].copy_from_slice(&subsystem.to_le_bytes());
        Ok(())
    }

    /// Encrypt the raw data of a named section using XOR with `key`.
    ///
    /// # Errors
    ///
    /// Returns [`EditError::SectionNotFound`] if the section is not present.
    ///
    /// # Panics
    ///
    /// Panics if `key` is empty.
    pub fn xor_encrypt_section(&mut self, section_name: &str, key: &[u8]) -> Result<(), EditError> {
        let (raw_off, raw_sz) = self.section_raw_range(section_name)?;
        let end = (raw_off + raw_sz).min(self.data.len());
        xor_section(&mut self.data[raw_off..end], key);
        self.edit_log
            .write()
            .push(format!("XOR-encrypted section {section_name}"));
        Ok(())
    }

    /// Decrypt the raw data of a named section using XOR with `key`.
    ///
    /// Since XOR is self-inverse, this is identical to `xor_encrypt_section`.
    ///
    /// # Errors
    ///
    /// Returns [`EditError::SectionNotFound`] if the section is not present.
    ///
    /// # Panics
    ///
    /// Panics if `key` is empty.
    pub fn xor_decrypt_section(&mut self, section_name: &str, key: &[u8]) -> Result<(), EditError> {
        self.xor_encrypt_section(section_name, key)
    }

    /// Encrypt the raw data of a named section using RC4 with `key`.
    ///
    /// # Errors
    ///
    /// Returns [`EditError::SectionNotFound`] if the section is not present.
    ///
    /// # Panics
    ///
    /// Panics if `key` is empty.
    pub fn rc4_encrypt_section(&mut self, section_name: &str, key: &[u8]) -> Result<(), EditError> {
        let (raw_off, raw_sz) = self.section_raw_range(section_name)?;
        let end = (raw_off + raw_sz).min(self.data.len());
        let mut rc4 = Rc4::new(key);
        rc4.process(&mut self.data[raw_off..end]);
        Ok(())
    }

    /// Append raw bytes as a new section.
    ///
    /// # Errors
    ///
    /// Returns [`EditError`] if there is no room for a new section header or on
    /// alignment issues.
    ///
    /// # Panics
    /// Panics if any computed RVA, size, or offset exceeds `u32::MAX`.
    pub fn add_section(
        &mut self,
        name: &str,
        data: &[u8],
        characteristics: u32,
    ) -> Result<(), EditError> {
        const FILE_ALIGN: u32 = 0x200;
        const SECT_ALIGN: u32 = 0x1000;

        let pe_offset = self.pe_header_offset()?;

        if pe_offset + 24 > self.data.len() {
            return Err(EditError::Pe(PeError::InvalidHeader(
                "COFF header truncated".to_string(),
            )));
        }
        let num_sections_offset = pe_offset + 6;
        let cur_sections = u16::from_le_bytes([
            self.data[num_sections_offset],
            self.data[num_sections_offset + 1],
        ]) as usize;
        let opt_hdr_size =
            u16::from_le_bytes([self.data[pe_offset + 20], self.data[pe_offset + 21]]) as usize;

        let opt_offset = pe_offset + 24;
        if opt_offset + 2 > self.data.len() {
            return Err(EditError::Pe(PeError::InvalidHeader(
                "no optional header".to_string(),
            )));
        }
        let magic = u16::from_le_bytes([self.data[opt_offset], self.data[opt_offset + 1]]);
        let is_64bit = magic == 0x020B;

        let sect_table_start = opt_offset + opt_hdr_size;
        let new_header_offset = sect_table_start + cur_sections * 40;

        let min_raw: usize = (0..cur_sections)
            .filter_map(|i| {
                let off = sect_table_start + i * 40;
                if off + 40 <= self.data.len() {
                    let ro = u32::from_le_bytes(
                        self.data[off + 20..off + 24].try_into().unwrap_or([0; 4]),
                    ) as usize;
                    if ro > 0 { Some(ro) } else { None }
                } else {
                    None
                }
            })
            .min()
            .unwrap_or(self.data.len());

        if new_header_offset + 40 > min_raw {
            return Err(EditError::InvalidAlignment(
                "no room for additional section header in header region".to_string(),
            ));
        }

        if self.data.len() > u32::MAX as usize {
            return Err(EditError::InvalidAlignment(
                "PE data exceeds 4 GiB; raw_offset would truncate".to_string(),
            ));
        }
        let cur_end = u32::try_from(self.data.len()).expect("checked above");
        let raw_offset = align_up_u32(cur_end, FILE_ALIGN);

        let last_va_end: u32 = (0..cur_sections)
            .filter_map(|i| {
                let off = sect_table_start + i * 40;
                if off + 40 <= self.data.len() {
                    let va = u32::from_le_bytes(
                        self.data[off + 12..off + 16].try_into().unwrap_or([0; 4]),
                    );
                    let vsz = u32::from_le_bytes(
                        self.data[off + 8..off + 12].try_into().unwrap_or([0; 4]),
                    );
                    Some(va.saturating_add(vsz))
                } else {
                    None
                }
            })
            .max()
            .unwrap_or(SECT_ALIGN);
        let virtual_address = align_up_u32(last_va_end, SECT_ALIGN);
        let virtual_size = u32::try_from(data.len()).expect("section data fits in u32");
        let raw_size = align_up_u32(virtual_size, FILE_ALIGN);

        write_pe_section_header_fields(
            &mut self.data,
            new_header_offset,
            name, virtual_size, virtual_address, raw_size, raw_offset,
        );
        self.data[new_header_offset + 36..new_header_offset + 40].copy_from_slice(&characteristics.to_le_bytes());
        let new_image_size = align_up_u32(virtual_address + align_up_u32(virtual_size, SECT_ALIGN), SECT_ALIGN);
        update_count_and_image_size(
            &mut self.data,
            num_sections_offset, opt_offset, is_64bit,
            new_image_size, cur_sections,
        );

        let pad_before = (raw_offset as usize).saturating_sub(self.data.len());
        self.data.extend(std::iter::repeat_n(0u8, pad_before));
        self.data.extend_from_slice(data);
        let pad_after = (raw_size as usize).saturating_sub(data.len());
        self.data.extend(std::iter::repeat_n(0u8, pad_after));

        self.edit_log.write().push(format!("added section {name}"));
        Ok(())
    }

    /// Remove the raw data of a named section (zero it out and reduce virtual size).
    ///
    /// Note: the section header is kept but data is zeroed.
    ///
    /// # Errors
    ///
    /// Returns [`EditError::SectionNotFound`] if the section is not present.
    pub fn zero_section(&mut self, name: &str) -> Result<(), EditError> {
        let (raw_off, raw_sz) = self.section_raw_range(name)?;
        if raw_off + raw_sz <= self.data.len() {
            self.data[raw_off..raw_off + raw_sz].fill(0);
        }
        Ok(())
    }

    /// Consume the editor and return the (possibly modified) bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Borrow the current bytes without consuming the editor.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// Slice of all successfully applied patches.
    #[must_use]
    pub fn applied_patches(&self) -> &[Patch] {
        &self.applied_patches
    }

    /// Re-parse the current state of the buffer as a [`PeFile`].
    ///
    /// # Errors
    ///
    /// Returns [`EditError`] if the current bytes are no longer a valid PE.
    pub fn parse_current(&self) -> Result<PeFile, EditError> {
        PeFile::parse(&self.data).map_err(EditError::Pe)
    }

    /// Current edit log entries.
    #[must_use]
    pub fn edit_log(&self) -> Vec<String> {
        self.edit_log.read().clone()
    }

    /// Number of applied patches.
    #[must_use]
    pub const fn applied_count(&self) -> usize {
        self.applied_patches.len()
    }

    /// Whether `rva` is within any section of the current PE.
    ///
    /// # Errors
    ///
    /// Returns [`EditError`] if parsing fails.
    pub fn rva_in_section(&self, rva: u32) -> Result<bool, EditError> {
        let pe = self.parse_current()?;
        Ok(pe.section_at_rva(rva).is_some())
    }

    // ---- internal helpers --------------------------------------------------

    fn pe_header_offset(&self) -> Result<usize, EditError> {
        if self.data.len() < 64 {
            return Err(EditError::Pe(PeError::TooShort {
                needed: 64,
                got: self.data.len(),
            }));
        }
        let pe_offset =
            u32::from_le_bytes([self.data[60], self.data[61], self.data[62], self.data[63]])
                as usize;
        if pe_offset + 4 > self.data.len() {
            return Err(EditError::Pe(PeError::InvalidHeader(
                "PE offset out of range".to_string(),
            )));
        }
        Ok(pe_offset)
    }

    fn section_table_range(&self) -> Result<(usize, usize), EditError> {
        let pe_off = self.pe_header_offset()?;
        let n_sections =
            u16::from_le_bytes([self.data[pe_off + 6], self.data[pe_off + 7]]) as usize;
        let opt_hdr_size =
            u16::from_le_bytes([self.data[pe_off + 20], self.data[pe_off + 21]]) as usize;
        let sect_table_start = pe_off + 24 + opt_hdr_size;
        Ok((sect_table_start, n_sections))
    }

    fn find_section_header(&self, name: &str) -> Result<usize, EditError> {
        let (table_start, n_sections) = self.section_table_range()?;
        let name_bytes = name.as_bytes();
        for i in 0..n_sections {
            let off = table_start + i * 40;
            if off + 40 > self.data.len() {
                break;
            }
            let sec_name = &self.data[off..off + 8];
            let trimmed: Vec<u8> = sec_name.iter().copied().take_while(|&b| b != 0).collect();
            if trimmed == name_bytes {
                return Ok(off);
            }
        }
        Err(EditError::SectionNotFound(name.to_string()))
    }

    fn section_raw_range(&self, name: &str) -> Result<(usize, usize), EditError> {
        let off = self.find_section_header(name)?;
        let raw_sz =
            u32::from_le_bytes(self.data[off + 16..off + 20].try_into().unwrap_or([0; 4])) as usize;
        let raw_off =
            u32::from_le_bytes(self.data[off + 20..off + 24].try_into().unwrap_or([0; 4])) as usize;
        Ok((raw_off, raw_sz))
    }
}

impl fmt::Debug for PeEditor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeEditor {{ size: {} }}", self.data.len())
    }
}

// ---------------------------------------------------------------------------
// PeParser — CFF-Explorer-equivalent header parsing
// ---------------------------------------------------------------------------

/// Full DOS header (`IMAGE_DOS_HEADER`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DosHeader {
    /// Magic number (0x5A4D = "MZ").
    pub e_magic: u16,
    /// Bytes on last page of file.
    pub e_cblp: u16,
    /// Pages in file.
    pub e_cp: u16,
    /// Relocations.
    pub e_crlc: u16,
    /// Size of header in paragraphs.
    pub e_cparhdr: u16,
    /// Minimum extra paragraphs needed.
    pub e_minalloc: u16,
    /// Maximum extra paragraphs needed.
    pub e_maxalloc: u16,
    /// Initial (relative) SS value.
    pub e_ss: u16,
    /// Initial SP value.
    pub e_sp: u16,
    /// Checksum.
    pub e_csum: u16,
    /// Initial IP value.
    pub e_ip: u16,
    /// Initial (relative) CS value.
    pub e_cs: u16,
    /// File address of relocation table.
    pub e_lfarlc: u16,
    /// Overlay number.
    pub e_ovno: u16,
    /// Reserved words (4 × u16).
    pub e_res: [u16; 4],
    /// OEM identifier.
    pub e_oemid: u16,
    /// OEM information.
    pub e_oeminfo: u16,
    /// Reserved words (10 × u16).
    pub e_res2: [u16; 10],
    /// File address of new exe header (PE offset).
    pub e_lfanew: u32,
}

/// COFF file header (`IMAGE_FILE_HEADER`) — follows the "PE\0\0" signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHeader {
    /// Target machine type.
    pub machine: u16,
    /// Number of sections.
    pub number_of_sections: u16,
    /// Time/date stamp.
    pub time_date_stamp: u32,
    /// File offset of COFF symbol table (deprecated, usually 0).
    pub pointer_to_symbol_table: u32,
    /// Number of symbols (deprecated, usually 0).
    pub number_of_symbols: u32,
    /// Size of optional header that follows.
    pub size_of_optional_header: u16,
    /// Characteristics flags.
    pub characteristics: u16,
}

/// Optional header for 64-bit PE (`IMAGE_OPTIONAL_HEADER64`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

/// A section header entry (`IMAGE_SECTION_HEADER`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionHeader {
    /// Up-to-8-byte name (NUL-padded).
    pub name: String,
    /// Virtual size (size in memory).
    pub virtual_size: u32,
    /// Virtual address (RVA).
    pub virtual_address: u32,
    /// Raw data size on disk.
    pub size_of_raw_data: u32,
    /// File offset of raw data.
    pub pointer_to_raw_data: u32,
    /// Pointer to relocations (object files).
    pub pointer_to_relocations: u32,
    /// Pointer to line numbers (deprecated).
    pub pointer_to_line_numbers: u32,
    /// Number of relocations.
    pub number_of_relocations: u16,
    /// Number of line numbers.
    pub number_of_line_numbers: u16,
    /// Section characteristics flags.
    pub characteristics: u32,
}

/// Error returned by [`PeParser`] functions.
#[derive(Debug, Error, Clone)]
pub enum ParseError {
    /// Buffer is shorter than the required minimum.
    #[error("buffer too short: need {needed} bytes, have {got}")]
    TooShort { needed: usize, got: usize },
    /// DOS magic bytes are wrong.
    #[error("invalid DOS magic: {0:#06x}")]
    InvalidDosMagic(u16),
    /// PE signature bytes are wrong.
    #[error("invalid PE signature")]
    InvalidPeSignature,
    /// A field value is out of range or inconsistent.
    #[error("malformed header: {0}")]
    MalformedHeader(String),
}

/// Low-level PE header parser (no dependency on `rustre_pe_tools`).
pub struct PeParser;

impl PeParser {
    /// Parse the DOS header from the beginning of `data`.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if `data` is shorter than 64 bytes or the MZ
    /// magic is wrong.
    pub fn parse_dos_header(data: &[u8]) -> Result<DosHeader, ParseError> {
        if data.len() < 64 {
            return Err(ParseError::TooShort {
                needed: 64,
                got: data.len(),
            });
        }
        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != 0x5A4D {
            return Err(ParseError::InvalidDosMagic(magic));
        }

        let mut res = [0u16; 4];
        for (i, r) in res.iter_mut().enumerate() {
            *r = u16::from_le_bytes([data[28 + i * 2], data[29 + i * 2]]);
        }
        let mut res2 = [0u16; 10];
        for (i, r) in res2.iter_mut().enumerate() {
            *r = u16::from_le_bytes([data[36 + i * 2], data[37 + i * 2]]);
        }

        Ok(DosHeader {
            e_magic: u16::from_le_bytes([data[0], data[1]]),
            e_cblp: u16::from_le_bytes([data[2], data[3]]),
            e_cp: u16::from_le_bytes([data[4], data[5]]),
            e_crlc: u16::from_le_bytes([data[6], data[7]]),
            e_cparhdr: u16::from_le_bytes([data[8], data[9]]),
            e_minalloc: u16::from_le_bytes([data[10], data[11]]),
            e_maxalloc: u16::from_le_bytes([data[12], data[13]]),
            e_ss: u16::from_le_bytes([data[14], data[15]]),
            e_sp: u16::from_le_bytes([data[16], data[17]]),
            e_csum: u16::from_le_bytes([data[18], data[19]]),
            e_ip: u16::from_le_bytes([data[20], data[21]]),
            e_cs: u16::from_le_bytes([data[22], data[23]]),
            e_lfarlc: u16::from_le_bytes([data[24], data[25]]),
            e_ovno: u16::from_le_bytes([data[26], data[27]]),
            e_res: res,
            e_oemid: u16::from_le_bytes([data[36], data[37]]),
            e_oeminfo: u16::from_le_bytes([data[38], data[39]]),
            e_res2: res2,
            e_lfanew: u32::from_le_bytes([data[60], data[61], data[62], data[63]]),
        })
    }

    /// Parse the COFF file header beginning at `offset` (after the PE signature).
    ///
    /// Caller is responsible for skipping the 4-byte "PE\0\0" signature so that
    /// `offset` points at the first byte of the COFF header.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooShort`] if the buffer is insufficient.
    pub fn parse_file_header(data: &[u8], offset: usize) -> Result<FileHeader, ParseError> {
        let needed = offset + 20;
        if data.len() < needed {
            return Err(ParseError::TooShort {
                needed,
                got: data.len(),
            });
        }
        let d = &data[offset..];
        Ok(FileHeader {
            machine: u16::from_le_bytes([d[0], d[1]]),
            number_of_sections: u16::from_le_bytes([d[2], d[3]]),
            time_date_stamp: u32::from_le_bytes([d[4], d[5], d[6], d[7]]),
            pointer_to_symbol_table: u32::from_le_bytes([d[8], d[9], d[10], d[11]]),
            number_of_symbols: u32::from_le_bytes([d[12], d[13], d[14], d[15]]),
            size_of_optional_header: u16::from_le_bytes([d[16], d[17]]),
            characteristics: u16::from_le_bytes([d[18], d[19]]),
        })
    }

    /// Parse the 64-bit optional header beginning at `offset`.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the buffer is too short or the magic is not
    /// `0x020B` (PE32+).
    pub fn parse_optional_header64(
        data: &[u8],
        offset: usize,
    ) -> Result<OptionalHeader64, ParseError> {
        let needed = offset + 112;
        if data.len() < needed {
            return Err(ParseError::TooShort {
                needed,
                got: data.len(),
            });
        }
        let d = &data[offset..];
        let magic = u16::from_le_bytes([d[0], d[1]]);
        if magic != 0x020B {
            return Err(ParseError::MalformedHeader(format!(
                "expected PE32+ magic 0x020B, got {magic:#06x}"
            )));
        }
        Ok(OptionalHeader64 {
            magic,
            major_linker_version: d[2],
            minor_linker_version: d[3],
            size_of_code: u32::from_le_bytes([d[4], d[5], d[6], d[7]]),
            size_of_initialized_data: u32::from_le_bytes([d[8], d[9], d[10], d[11]]),
            size_of_uninitialized_data: u32::from_le_bytes([d[12], d[13], d[14], d[15]]),
            address_of_entry_point: u32::from_le_bytes([d[16], d[17], d[18], d[19]]),
            base_of_code: u32::from_le_bytes([d[20], d[21], d[22], d[23]]),
            image_base: u64::from_le_bytes([
                d[24], d[25], d[26], d[27], d[28], d[29], d[30], d[31],
            ]),
            section_alignment: u32::from_le_bytes([d[32], d[33], d[34], d[35]]),
            file_alignment: u32::from_le_bytes([d[36], d[37], d[38], d[39]]),
            major_os_version: u16::from_le_bytes([d[40], d[41]]),
            minor_os_version: u16::from_le_bytes([d[42], d[43]]),
            major_image_version: u16::from_le_bytes([d[44], d[45]]),
            minor_image_version: u16::from_le_bytes([d[46], d[47]]),
            major_subsystem_version: u16::from_le_bytes([d[48], d[49]]),
            minor_subsystem_version: u16::from_le_bytes([d[50], d[51]]),
            win32_version_value: u32::from_le_bytes([d[52], d[53], d[54], d[55]]),
            size_of_image: u32::from_le_bytes([d[56], d[57], d[58], d[59]]),
            size_of_headers: u32::from_le_bytes([d[60], d[61], d[62], d[63]]),
            checksum: u32::from_le_bytes([d[64], d[65], d[66], d[67]]),
            subsystem: u16::from_le_bytes([d[68], d[69]]),
            dll_characteristics: u16::from_le_bytes([d[70], d[71]]),
            size_of_stack_reserve: u64::from_le_bytes([
                d[72], d[73], d[74], d[75], d[76], d[77], d[78], d[79],
            ]),
            size_of_stack_commit: u64::from_le_bytes([
                d[80], d[81], d[82], d[83], d[84], d[85], d[86], d[87],
            ]),
            size_of_heap_reserve: u64::from_le_bytes([
                d[88], d[89], d[90], d[91], d[92], d[93], d[94], d[95],
            ]),
            size_of_heap_commit: u64::from_le_bytes([
                d[96], d[97], d[98], d[99], d[100], d[101], d[102], d[103],
            ]),
            loader_flags: u32::from_le_bytes([d[104], d[105], d[106], d[107]]),
            number_of_rva_and_sizes: u32::from_le_bytes([d[108], d[109], d[110], d[111]]),
        })
    }

    /// Build a minimal valid PE64 stub (200 bytes) suitable for demo/testing.
    ///
    /// The returned buffer is a well-formed PE32+ image with no sections.
    /// It can be passed to [`parse_dos_header`], [`parse_file_header`] (offset 68),
    /// and [`parse_optional_header64`] (offset 88).
    #[must_use]
    pub fn minimal_pe64_stub() -> Vec<u8> {
        let mut buf = vec![0u8; 200];
        // DOS header: MZ magic + e_lfanew=64
        buf[0] = 0x4D;
        buf[1] = 0x5A;
        buf[60] = 0x40;
        // PE signature at offset 64
        buf[64] = 0x50;
        buf[65] = 0x45;
        // COFF header at offset 68
        buf[68] = 0x64; // Machine = AMD64 low byte
        buf[69] = 0x86; // Machine = AMD64 high byte
        buf[84] = 0x70; // SizeOfOptionalHeader = 112
        buf[86] = 0x22; // Characteristics
        // Optional header at offset 88: magic=0x020B (PE32+)
        buf[88] = 0x0B;
        buf[89] = 0x02;
        // SectionAlignment = 0x1000
        buf[88 + 32] = 0x00;
        buf[88 + 33] = 0x10;
        // FileAlignment = 0x200
        buf[88 + 36] = 0x00;
        buf[88 + 37] = 0x02;
        // SizeOfImage = 0x1000
        buf[88 + 56] = 0x00;
        buf[88 + 57] = 0x10;
        // SizeOfHeaders = 200
        buf[88 + 60] = 200;
        // NumberOfRvaAndSizes = 16
        buf[88 + 108] = 16;
        buf
    }

    /// Parse `count` section headers starting at `offset`.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::TooShort`] if `data` is too short for all headers.
    pub fn parse_sections(
        data: &[u8],
        offset: usize,
        count: u16,
    ) -> Result<Vec<SectionHeader>, ParseError> {
        let needed = offset + count as usize * 40;
        if data.len() < needed {
            return Err(ParseError::TooShort {
                needed,
                got: data.len(),
            });
        }
        let mut sections = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let base = offset + i * 40;
            let d = &data[base..];
            let raw_name = &d[0..8];
            let name_bytes: Vec<u8> = raw_name.iter().copied().take_while(|&b| b != 0).collect();
            let name = String::from_utf8_lossy(&name_bytes).into_owned();
            sections.push(SectionHeader {
                name,
                virtual_size: u32::from_le_bytes([d[8], d[9], d[10], d[11]]),
                virtual_address: u32::from_le_bytes([d[12], d[13], d[14], d[15]]),
                size_of_raw_data: u32::from_le_bytes([d[16], d[17], d[18], d[19]]),
                pointer_to_raw_data: u32::from_le_bytes([d[20], d[21], d[22], d[23]]),
                pointer_to_relocations: u32::from_le_bytes([d[24], d[25], d[26], d[27]]),
                pointer_to_line_numbers: u32::from_le_bytes([d[28], d[29], d[30], d[31]]),
                number_of_relocations: u16::from_le_bytes([d[32], d[33]]),
                number_of_line_numbers: u16::from_le_bytes([d[34], d[35]]),
                characteristics: u32::from_le_bytes([d[36], d[37], d[38], d[39]]),
            });
        }
        Ok(sections)
    }
}

// ---------------------------------------------------------------------------
// PeTreeBuilder — CFF Explorer-style tree view
// ---------------------------------------------------------------------------

/// A single named field in a PE header node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeField {
    /// Field name.
    pub name: String,
    /// Numeric value (displayed as hex).
    pub value: u64,
    /// Optional human-readable description.
    pub description: String,
}

impl PeField {
    /// Create a new PE field.
    #[must_use]
    pub fn new(name: impl Into<String>, value: u64, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value,
            description: description.into(),
        }
    }
}

impl fmt::Display for PeField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {:#x}  // {}",
            self.name, self.value, self.description
        )
    }
}

/// A tree node representing a structural region of the PE file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeTreeNode {
    /// Node label (e.g. "DOS Header", ".text").
    pub name: String,
    /// File offset where this region starts.
    pub raw_offset: usize,
    /// Size in bytes of this region.
    pub raw_size: usize,
    /// Parsed fields within this node.
    pub fields: Vec<PeField>,
    /// Child nodes (e.g. individual sections under "Sections").
    pub children: Vec<Self>,
}

impl PeTreeNode {
    /// Create a leaf node with no fields or children.
    #[must_use]
    pub fn leaf(name: impl Into<String>, raw_offset: usize, raw_size: usize) -> Self {
        Self {
            name: name.into(),
            raw_offset,
            raw_size,
            fields: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Total number of fields (recursive).
    #[must_use]
    pub fn total_fields(&self) -> usize {
        self.fields.len()
            + self
                .children
                .iter()
                .map(Self::total_fields)
                .sum::<usize>()
    }
}

impl fmt::Display for PeTreeNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} @ {:#x} ({}B)",
            self.name, self.raw_offset, self.raw_size
        )
    }
}

/// A parsed PE tree, equivalent to CFF Explorer's tree-view structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeTree {
    /// Top-level nodes of the PE tree.
    pub sections: Vec<PeTreeNode>,
}

impl PeTree {
    /// Find a top-level node by name.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&PeTreeNode> {
        self.sections.iter().find(|n| n.name == name)
    }
}

/// Build a [`PeTreeNode`] for a PE32+ optional header.
fn build_pe32plus_opt_node(opt_off: usize, oh: &OptionalHeader64) -> PeTreeNode {
    let mut opt = PeTreeNode::leaf("Optional Header (PE32+)", opt_off, 112);
    opt.fields.push(PeField::new("Magic", u64::from(oh.magic), "PE32+ = 0x020B"));
    opt.fields.push(PeField::new("AddressOfEntryPoint", u64::from(oh.address_of_entry_point), "EP RVA"));
    opt.fields.push(PeField::new("BaseOfCode", u64::from(oh.base_of_code), "code section RVA"));
    opt.fields.push(PeField::new("ImageBase", oh.image_base, "preferred load address"));
    opt.fields.push(PeField::new("SectionAlignment", u64::from(oh.section_alignment), "in-memory alignment"));
    opt.fields.push(PeField::new("FileAlignment", u64::from(oh.file_alignment), "on-disk alignment"));
    opt.fields.push(PeField::new("SizeOfImage", u64::from(oh.size_of_image), "total mapped size"));
    opt.fields.push(PeField::new("SizeOfHeaders", u64::from(oh.size_of_headers), "combined headers size"));
    opt.fields.push(PeField::new("CheckSum", u64::from(oh.checksum), "PE checksum"));
    opt.fields.push(PeField::new("Subsystem", u64::from(oh.subsystem), "Windows subsystem"));
    opt.fields.push(PeField::new("DllCharacteristics", u64::from(oh.dll_characteristics), "DLL flags"));
    opt.fields.push(PeField::new("SizeOfStackReserve", oh.size_of_stack_reserve, "stack reserve"));
    opt.fields.push(PeField::new("SizeOfStackCommit", oh.size_of_stack_commit, "stack commit"));
    opt.fields.push(PeField::new("SizeOfHeapReserve", oh.size_of_heap_reserve, "heap reserve"));
    opt.fields.push(PeField::new("SizeOfHeapCommit", oh.size_of_heap_commit, "heap commit"));
    opt.fields.push(PeField::new("NumberOfRvaAndSizes", u64::from(oh.number_of_rva_and_sizes), "data directory count"));
    opt
}

/// Builds a [`PeTree`] from raw PE bytes.
pub struct PeTreeBuilder;

impl PeTreeBuilder {
    /// Parse `data` and return a full PE tree.
    ///
    /// If parsing fails at any layer, the function returns a best-effort tree
    /// (it never panics or returns an `Err`).
    #[must_use]
    pub fn build_tree(data: &[u8]) -> PeTree {
        let mut nodes: Vec<PeTreeNode> = Vec::new();

        // DOS header node
        if let Ok(ref dos) = PeParser::parse_dos_header(data) {
            let node = Self::dos_header_node(dos);
            let pe_off = dos.e_lfanew as usize;
            nodes.push(node);

            // NT headers node
            let nt_node = Self::nt_headers_node(data, pe_off);
            nodes.push(nt_node);

            // Section headers node
            if pe_off + 24 <= data.len() {
                let coff_off = pe_off + 4;
                if let Ok(fh) = PeParser::parse_file_header(data, coff_off) {
                    let opt_size = fh.size_of_optional_header as usize;
                    let sect_off = pe_off + 24 + opt_size;
                    if let Ok(sections) =
                        PeParser::parse_sections(data, sect_off, fh.number_of_sections)
                    {
                        nodes.push(Self::sections_node(&sections));
                    }

                    // Data directories node
                    let opt_off = pe_off + 24;
                    nodes.push(Self::data_directories_node(data, opt_off));
                }
            }
        } else {
            // Return stub tree for unrecognised data.
            let mut stub = PeTreeNode::leaf("Unknown", 0, data.len());
            stub.fields.push(PeField::new(
                "raw_size",
                data.len() as u64,
                "total file size",
            ));
            nodes.push(stub);
        }

        PeTree { sections: nodes }
    }

    /// Build a tree node for the DOS header.
    #[must_use]
    pub fn dos_header_node(header: &DosHeader) -> PeTreeNode {
        let mut node = PeTreeNode::leaf("DOS Header", 0, 64);
        node.fields.push(PeField::new(
            "e_magic",
            u64::from(header.e_magic),
            "MZ signature",
        ));
        node.fields.push(PeField::new(
            "e_cblp",
            u64::from(header.e_cblp),
            "bytes on last page",
        ));
        node.fields
            .push(PeField::new("e_cp", u64::from(header.e_cp), "pages in file"));
        node.fields.push(PeField::new(
            "e_crlc",
            u64::from(header.e_crlc),
            "relocation count",
        ));
        node.fields.push(PeField::new(
            "e_cparhdr",
            u64::from(header.e_cparhdr),
            "header paragraphs",
        ));
        node.fields.push(PeField::new(
            "e_minalloc",
            u64::from(header.e_minalloc),
            "min extra paragraphs",
        ));
        node.fields.push(PeField::new(
            "e_maxalloc",
            u64::from(header.e_maxalloc),
            "max extra paragraphs",
        ));
        node.fields
            .push(PeField::new("e_ss", u64::from(header.e_ss), "initial SS"));
        node.fields
            .push(PeField::new("e_sp", u64::from(header.e_sp), "initial SP"));
        node.fields
            .push(PeField::new("e_csum", u64::from(header.e_csum), "checksum"));
        node.fields
            .push(PeField::new("e_ip", u64::from(header.e_ip), "initial IP"));
        node.fields
            .push(PeField::new("e_cs", u64::from(header.e_cs), "initial CS"));
        node.fields.push(PeField::new(
            "e_lfarlc",
            u64::from(header.e_lfarlc),
            "relocation table offset",
        ));
        node.fields.push(PeField::new(
            "e_ovno",
            u64::from(header.e_ovno),
            "overlay number",
        ));
        node.fields.push(PeField::new(
            "e_oemid",
            u64::from(header.e_oemid),
            "OEM identifier",
        ));
        node.fields.push(PeField::new(
            "e_oeminfo",
            u64::from(header.e_oeminfo),
            "OEM info",
        ));
        node.fields.push(PeField::new(
            "e_lfanew",
            u64::from(header.e_lfanew),
            "new exe header offset",
        ));
        node
    }

    /// Build a tree node for the NT headers (signature + COFF + optional header).
    #[must_use]
    pub fn nt_headers_node(data: &[u8], pe_offset: usize) -> PeTreeNode {
        let end = data.len().min(pe_offset + 264); // rough upper bound
        let mut node = PeTreeNode::leaf("NT Headers", pe_offset, end - pe_offset);

        // PE signature
        let mut sig = PeTreeNode::leaf("PE Signature", pe_offset, 4);
        if pe_offset + 4 <= data.len() {
            let sig_val =
                u32::from_le_bytes(data[pe_offset..pe_offset + 4].try_into().unwrap_or([0; 4]));
            sig.fields.push(PeField::new(
                "Signature",
                u64::from(sig_val),
                "should be 0x00004550 (PE\\0\\0)",
            ));
        }
        node.children.push(sig);

        // COFF file header
        let coff_off = pe_offset + 4;
        if let Ok(fh) = PeParser::parse_file_header(data, coff_off) {
            let mut coff = PeTreeNode::leaf("File Header (COFF)", coff_off, 20);
            coff.fields.push(PeField::new(
                "Machine",
                u64::from(fh.machine),
                "target architecture",
            ));
            coff.fields.push(PeField::new(
                "NumberOfSections",
                u64::from(fh.number_of_sections),
                "section count",
            ));
            coff.fields.push(PeField::new(
                "TimeDateStamp",
                u64::from(fh.time_date_stamp),
                "build timestamp",
            ));
            coff.fields.push(PeField::new(
                "PointerToSymbolTable",
                u64::from(fh.pointer_to_symbol_table),
                "COFF symbol table (deprecated)",
            ));
            coff.fields.push(PeField::new(
                "NumberOfSymbols",
                u64::from(fh.number_of_symbols),
                "symbol count (deprecated)",
            ));
            coff.fields.push(PeField::new(
                "SizeOfOptionalHeader",
                u64::from(fh.size_of_optional_header),
                "optional header size",
            ));
            coff.fields.push(PeField::new(
                "Characteristics",
                u64::from(fh.characteristics),
                "file characteristics flags",
            ));
            node.children.push(coff);

            // Optional header
            let opt_off = coff_off + 20;
            if opt_off + 2 <= data.len() {
                let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
                if magic == 0x020B {
                    if let Ok(oh) = PeParser::parse_optional_header64(data, opt_off) {
                        node.children.push(build_pe32plus_opt_node(opt_off, &oh));
                    }
                } else {
                    let mut opt = PeTreeNode::leaf(
                        "Optional Header (PE32)",
                        opt_off,
                        fh.size_of_optional_header as usize,
                    );
                    opt.fields
                        .push(PeField::new("Magic", u64::from(magic), "PE32 = 0x010B"));
                    node.children.push(opt);
                }
            }
        }

        node
    }

    /// Build a tree node representing the section table.
    #[must_use]
    pub fn sections_node(sections: &[SectionHeader]) -> PeTreeNode {
        let mut node = PeTreeNode::leaf("Section Table", 0, sections.len() * 40);
        for sec in sections {
            let raw_off = sec.pointer_to_raw_data as usize;
            let raw_sz = sec.size_of_raw_data as usize;
            let mut child = PeTreeNode::leaf(sec.name.clone(), raw_off, raw_sz);
            child.fields.push(PeField::new(
                "VirtualSize",
                u64::from(sec.virtual_size),
                "size in memory",
            ));
            child.fields.push(PeField::new(
                "VirtualAddress",
                u64::from(sec.virtual_address),
                "RVA",
            ));
            child.fields.push(PeField::new(
                "SizeOfRawData",
                u64::from(sec.size_of_raw_data),
                "on-disk size",
            ));
            child.fields.push(PeField::new(
                "PointerToRawData",
                u64::from(sec.pointer_to_raw_data),
                "file offset",
            ));
            child.fields.push(PeField::new(
                "Characteristics",
                u64::from(sec.characteristics),
                "section flags",
            ));
            node.children.push(child);
        }
        node
    }

    /// Build a tree node for the data directories.
    ///
    /// `opt_offset` should point at the first byte of the optional header.
    #[must_use]
    pub fn data_directories_node(data: &[u8], opt_offset: usize) -> PeTreeNode {
        const DIR_NAMES: &[&str] = &[
            "Export Table",
            "Import Table",
            "Resource Table",
            "Exception Table",
            "Certificate Table",
            "Base Relocation Table",
            "Debug",
            "Architecture",
            "Global Ptr",
            "TLS Table",
            "Load Config Table",
            "Bound Import",
            "IAT",
            "Delay Import Descriptor",
            "CLR Runtime Header",
            "Reserved",
        ];

        let mut node = PeTreeNode::leaf("Data Directories", opt_offset, 0);

        if opt_offset + 2 > data.len() {
            return node;
        }
        let magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
        let dd_base = if magic == 0x020B {
            opt_offset + 112 // PE32+ data directories start at offset 112
        } else {
            opt_offset + 96 // PE32 data directories start at offset 96
        };

        for (i, &dir_name) in DIR_NAMES.iter().enumerate() {
            let off = dd_base + i * 8;
            if off + 8 > data.len() {
                break;
            }
            let rva = u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]));
            let size = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap_or([0; 4]));
            let mut dd = PeTreeNode::leaf(dir_name, off, 8);
            dd.fields.push(PeField::new(
                "VirtualAddress",
                u64::from(rva),
                "RVA of the directory",
            ));
            dd.fields
                .push(PeField::new("Size", u64::from(size), "size in bytes"));
            node.children.push(dd);
        }

        node
    }
}

// ---------------------------------------------------------------------------
// PeEditor::recalculate_checksum — real PE checksum algorithm
// ---------------------------------------------------------------------------

impl PeEditor {
    /// Compute and write the PE checksum into the optional header.
    ///
    /// The algorithm mirrors the Windows loader's `MapFileAndCheckSum`:
    /// 1. Sum all 16-bit words in the file, treating the checksum field itself as 0.
    /// 2. Fold 32-bit accumulator to 16 bits.
    /// 3. Add the file size.
    ///
    /// # Errors
    ///
    /// Returns [`EditError`] if the PE structure is malformed.
    ///
    /// # Panics
    /// Panics if `self.data.len()` exceeds `u32::MAX`.
    pub fn recalculate_checksum(&mut self) -> Result<u32, EditError> {
        let pe_offset = self.pe_header_offset()?;
        let opt_offset = pe_offset + 24;
        if opt_offset + 68 > self.data.len() {
            return Err(EditError::Pe(PeError::InvalidHeader(
                "optional header too short for checksum field".to_string(),
            )));
        }
        // The checksum field is at optional_header + 64
        let checksum_file_offset = opt_offset + 64;

        // Zero the checksum field before computing so it doesn't count.
        let saved = u32::from_le_bytes(
            self.data[checksum_file_offset..checksum_file_offset + 4]
                .try_into()
                .unwrap_or([0; 4]),
        );
        self.data[checksum_file_offset..checksum_file_offset + 4].fill(0);

        // Sum all 16-bit words; handle odd-length files by treating the trailing
        // byte as a zero-extended word.
        let mut sum: u32 = 0;
        let len = self.data.len();
        let mut i = 0usize;
        while i < len {
            let word = if i + 1 < len {
                u32::from(u16::from_le_bytes([self.data[i], self.data[i + 1]]))
            } else {
                u32::from(self.data[i])
            };
            sum = sum.wrapping_add(word);
            // Carry folding every step keeps intermediate values bounded.
            if sum > 0xFFFF {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            i += 2;
        }

        // Final fold.
        sum = (sum & 0xFFFF) + (sum >> 16);
        sum = (sum & 0xFFFF) + (sum >> 16);

        let checksum = u32::try_from((u64::from(sum) + len as u64) & 0xFFFF_FFFF).expect("masked to 32 bits");

        // Write the new checksum.
        self.data[checksum_file_offset..checksum_file_offset + 4]
            .copy_from_slice(&checksum.to_le_bytes());

        let _ = saved; // previous value discarded intentionally
        self.edit_log
            .write()
            .push(format!("checksum recalculated: {checksum:#010x}"));
        Ok(checksum)
    }
}

// ---------------------------------------------------------------------------
// PeSection — section add / remove / rename / set-data (Cargo-level API)
// ---------------------------------------------------------------------------

/// High-level section management API layered on top of [`PeEditor`].
pub struct PeSection<'a> {
    editor: &'a mut PeEditor,
}

impl<'a> PeSection<'a> {
    /// Wrap a mutable reference to a [`PeEditor`].
    #[must_use]
    pub const fn new(editor: &'a mut PeEditor) -> Self {
        Self { editor }
    }

    /// Add a new section named `name` with the given `characteristics` and `data`.
    ///
    /// Delegates to [`PeEditor::add_section`].
    ///
    /// # Errors
    ///
    /// Returns [`EditError`] if there is no room for a new section header or on
    /// alignment issues.
    pub fn add_section(
        &mut self,
        name: &str,
        characteristics: u32,
        data: &[u8],
    ) -> Result<(), EditError> {
        self.editor
            .add_section(name, data, characteristics)
    }

    /// Remove the section named `name`.
    ///
    /// The section header slot is zeroed out and the `NumberOfSections` count
    /// is decremented.  The raw data in the file body is zeroed but the file
    /// size does not shrink (this mirrors what many PE tools do to avoid
    /// rewriting all subsequent offsets).
    ///
    /// Returns `true` if the section was found and removed, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`EditError`] if the PE structure is malformed.
    pub fn remove_section(&mut self, name: &str) -> Result<bool, EditError> {
        // Zero the raw data first.
        match self.editor.zero_section(name) {
            Ok(()) => {}
            Err(EditError::SectionNotFound(_)) => return Ok(false),
            Err(e) => return Err(e),
        }

        let (table_start, n_sections) = self.editor.section_table_range()?;
        let name_bytes = name.as_bytes();

        // Find the slot index.
        let mut slot: Option<usize> = None;
        for i in 0..n_sections {
            let off = table_start + i * 40;
            if off + 40 > self.editor.bytes().len() {
                break;
            }
            let sec_name = &self.editor.bytes()[off..off + 8];
            let trimmed: Vec<u8> = sec_name.iter().copied().take_while(|&b| b != 0).collect();
            if trimmed == name_bytes {
                slot = Some(i);
                break;
            }
        }

        let Some(idx) = slot else { return Ok(false) };

        // Zero the section header slot.
        let slot_off = table_start + idx * 40;
        // We need mutable access; use write_bytes via the editor.
        self.editor.write_bytes(slot_off, &[0u8; 40])?;

        // Shift subsequent headers left by one slot.
        let data = self.editor.bytes().to_vec();
        let remaining = n_sections - idx - 1;
        if remaining > 0 {
            let src_start = table_start + (idx + 1) * 40;
            let src_end = src_start + remaining * 40;
            if src_end <= data.len() {
                let shifted = data[src_start..src_end].to_vec();
                self.editor.write_bytes(slot_off, &shifted)?;
                // Zero the now-vacated last slot.
                let last_slot_off = table_start + (n_sections - 1) * 40;
                self.editor.write_bytes(last_slot_off, &[0u8; 40])?;
            }
        }

        // Decrement NumberOfSections in the COFF header.
        let pe_off = self.editor.pe_header_offset()?;
        let ns_off = pe_off + 6;
        let new_count = u16::try_from(n_sections).unwrap_or(u16::MAX).saturating_sub(1);
        self.editor.write_bytes(ns_off, &new_count.to_le_bytes())?;

        Ok(true)
    }

    /// Rename the section `old` to `new`.
    ///
    /// # Errors
    ///
    /// Returns [`EditError::SectionNotFound`] if `old` is not present.
    pub fn rename_section(&mut self, old: &str, new: &str) -> Result<(), EditError> {
        // Delegate to the SectionEditor-style rename implemented on PeEditor.
        let (table_start, n_sections) = self.editor.section_table_range()?;
        let old_bytes = old.as_bytes();
        for i in 0..n_sections {
            let off = table_start + i * 40;
            if off + 40 > self.editor.bytes().len() {
                break;
            }
            let sec_name = &self.editor.bytes()[off..off + 8];
            let trimmed: Vec<u8> = sec_name.iter().copied().take_while(|&b| b != 0).collect();
            if trimmed == old_bytes {
                let new_bytes = new.as_bytes();
                let copy_len = new_bytes.len().min(8);
                let mut name_field = [0u8; 8];
                name_field[..copy_len].copy_from_slice(&new_bytes[..copy_len]);
                self.editor.write_bytes(off, &name_field)?;
                return Ok(());
            }
        }
        Err(EditError::SectionNotFound(old.to_string()))
    }

    /// Replace the raw data of a section in-place.
    ///
    /// If `data.len()` exceeds `SizeOfRawData`, the write is truncated to the
    /// section's allocated raw size to avoid corrupting adjacent sections.
    /// The `VirtualSize` header field is updated to reflect the new size.
    ///
    /// # Errors
    ///
    /// Returns [`EditError::SectionNotFound`] if the section does not exist.
    ///
    /// # Panics
    /// Panics if `data.len()` exceeds `u32::MAX`.
    pub fn set_section_data(&mut self, name: &str, data: &[u8]) -> Result<(), EditError> {
        // Find header to get raw offset and raw size.
        let (table_start, n_sections) = self.editor.section_table_range()?;
        let name_bytes = name.as_bytes();
        let mut header_off: Option<usize> = None;
        for i in 0..n_sections {
            let off = table_start + i * 40;
            if off + 40 > self.editor.bytes().len() {
                break;
            }
            let sec_name = &self.editor.bytes()[off..off + 8];
            let trimmed: Vec<u8> = sec_name.iter().copied().take_while(|&b| b != 0).collect();
            if trimmed == name_bytes {
                header_off = Some(off);
                break;
            }
        }
        let hoff = header_off.ok_or_else(|| EditError::SectionNotFound(name.to_string()))?;

        let raw_sz = u32::from_le_bytes(
            self.editor.bytes()[hoff + 16..hoff + 20]
                .try_into()
                .unwrap_or([0; 4]),
        ) as usize;
        let raw_off = u32::from_le_bytes(
            self.editor.bytes()[hoff + 20..hoff + 24]
                .try_into()
                .unwrap_or([0; 4]),
        ) as usize;

        // Write as much as fits.
        let write_len = data.len().min(raw_sz);
        let file_len = self.editor.bytes().len();
        if raw_off + write_len > file_len {
            return Err(EditError::PatchOutOfBounds {
                offset: raw_off,
                len: write_len,
                file_size: file_len,
            });
        }
        self.editor.write_bytes(raw_off, &data[..write_len])?;

        // Zero remainder.
        if write_len < raw_sz && raw_off + raw_sz <= file_len {
            self.editor
                .write_bytes(raw_off + write_len, &vec![0u8; raw_sz - write_len])?;
        }

        // Update VirtualSize.
        let new_vsz = u32::try_from(write_len).expect("write length fits in u32");
        self.editor.write_bytes(hoff + 8, &new_vsz.to_le_bytes())?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PeEditor — new high-level operations (task additions)
// ---------------------------------------------------------------------------

/// Update the import data-directory entry and `SizeOfImage` after injecting an import blob.
fn update_import_dd_and_image_size(
    data: &mut [u8],
    opt_off: usize,
    is_64bit: bool,
    section_va: u32,
    blob_len: usize,
    sect_align: u32,
) {
    // Import descriptor is always at offset 0 in the blob; null-terminator at 20.
    let dd_base = if is_64bit { opt_off + 112 } else { opt_off + 96 };
    let import_dd_off = dd_base + 8;
    if import_dd_off + 8 <= data.len() {
        let existing_rva = u32::from_le_bytes(data[import_dd_off..import_dd_off + 4].try_into().unwrap_or([0; 4]));
        if existing_rva == 0 {
            // desc_off_val is always 0; null_desc_off_val is always 20.
            data[import_dd_off..import_dd_off + 4].copy_from_slice(&section_va.to_le_bytes());
            let import_table_size: u32 = 40; // 20 (null_desc_off_val) + 20
            data[import_dd_off + 4..import_dd_off + 8].copy_from_slice(&import_table_size.to_le_bytes());
        }
    }
    let size_of_image_off = opt_off + 56;
    if size_of_image_off + 4 <= data.len() {
        let new_image_size = align_up_u32(
            section_va + align_up_u32(u32::try_from(blob_len).expect("blob size fits in u32"), sect_align),
            sect_align,
        );
        data[size_of_image_off..size_of_image_off + 4].copy_from_slice(&new_image_size.to_le_bytes());
    }
}

impl PeEditor {
    /// Add a named import from `dll_name`!`function_name` to the image.
    ///
    /// This is a convenience wrapper around [`ImportEditor`] that serialises a
    /// minimal import blob (one `IMAGE_IMPORT_DESCRIPTOR` plus one thunk) into a
    /// new section appended to the image and returns the file offset at which
    /// the IAT slot was written.
    ///
    /// The returned value is the **file offset** of the first thunk entry for
    /// the newly-added function (not an RVA), which is useful for patching a
    /// call target or trampoline.
    ///
    /// # Errors
    ///
    /// Returns [`EditError::ImportError`] if the PE structure is too malformed
    /// to accept a new import blob.
    ///
    /// # Panics
    /// Panics if any RVA or size within the import blob exceeds `u32::MAX`.
    pub fn add_import(&mut self, dll_name: &str, function_name: &str) -> Result<u64, EditError> {
        // We build a self-contained blob:
        //   [0..19]   IMAGE_IMPORT_DESCRIPTOR for the new DLL   (20 bytes)
        //   [20..39]  null IMAGE_IMPORT_DESCRIPTOR terminator    (20 bytes)
        //   [40..47]  IAT thunk: pointer to hint/name table      (8 bytes)
        //   [48..55]  null thunk terminator                      (8 bytes)
        //   [56..57]  hint word (0x0000)                         (2 bytes)
        //   [58..]    function name (NUL-terminated, padded)
        //   [..]      dll name (NUL-terminated, padded)
        //
        // All RVAs stored in the descriptor are relative to the new section's
        // VirtualAddress, which we calculate from the current image layout.

        // Determine where the new section will start in virtual memory.
        let pe_off = self.pe_header_offset()?;
        let opt_off = pe_off + 24;
        if opt_off + 2 > self.data.len() {
            return Err(EditError::ImportError("no optional header".to_string()));
        }
        let magic = u16::from_le_bytes([self.data[opt_off], self.data[opt_off + 1]]);
        let is_64bit = magic == 0x020B;

        // File alignment.
        let _ = is_64bit;
        let file_align_off = opt_off + 36;
        let file_align = if file_align_off + 4 <= self.data.len() {
            u32::from_le_bytes(
                self.data[file_align_off..file_align_off + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            )
        } else {
            0x200
        };
        let file_align = if file_align == 0 { 0x200 } else { file_align };

        // Section alignment.
        let sect_align_off = opt_off + 32;
        let sect_align = if sect_align_off + 4 <= self.data.len() {
            u32::from_le_bytes(
                self.data[sect_align_off..sect_align_off + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            )
        } else {
            0x1000
        };
        let sect_align = if sect_align == 0 { 0x1000 } else { sect_align };

        // Find the highest VA end across all existing sections.
        let (table_start, n_sections) = self.section_table_range()?;
        let last_va_end: u32 = (0..n_sections)
            .filter_map(|i| {
                let off = table_start + i * 40;
                if off + 40 <= self.data.len() {
                    let va = u32::from_le_bytes(
                        self.data[off + 12..off + 16].try_into().unwrap_or([0; 4]),
                    );
                    let vsz = u32::from_le_bytes(
                        self.data[off + 8..off + 12].try_into().unwrap_or([0; 4]),
                    );
                    Some(va + vsz)
                } else {
                    None
                }
            })
            .max()
            .unwrap_or(sect_align);
        let section_va = align_up_u32(last_va_end, sect_align);

        // Layout offsets (relative to start of blob = relative to section_va):
        // These are declared as locals early to avoid items-after-statements.
        let desc_off_val: u32 = 0;    // import descriptor (20 bytes)
        let null_desc_off_val: u32 = 20; // null terminator descriptor (20 bytes)
        let thunk_off_val: u32 = 40;  // IAT / INT thunk array (first real entry + null)
        let hint_name_off_val: u32 = 56; // 2-byte hint + function name string

        // Suppress "unused variable" warnings — these offsets are used below.
        let _ = (desc_off_val, null_desc_off_val, thunk_off_val);

        // Build the blob.
        let fn_bytes = function_name.as_bytes();
        let hint_name_size = 2 + fn_bytes.len() + 1; // hint(2) + name + NUL
        let hint_name_size = hint_name_size + (hint_name_size % 2); // WORD-align
        let dll_name_off = hint_name_off_val + u32::try_from(hint_name_size).expect("hint name size fits in u32");

        let dll_bytes = dll_name.as_bytes();
        let dll_name_size = dll_bytes.len() + 1;

        let total_blob_size = (dll_name_off as usize + dll_name_size + 1) // +1 NUL pad
            .max(64);

        let mut blob = vec![0u8; total_blob_size];

        // Write IMAGE_IMPORT_DESCRIPTOR at desc_off_val.
        // OriginalFirstThunk (INT RVA) — same array we'll use as IAT:
        let int_rva = section_va + thunk_off_val;
        blob[desc_off_val as usize..desc_off_val as usize + 4].copy_from_slice(&int_rva.to_le_bytes());
        // TimeDateStamp = 0 (unbound)
        // ForwarderChain = 0xFFFFFFFF
        blob[desc_off_val as usize + 8..desc_off_val as usize + 12]
            .copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        // Name RVA
        let name_rva = section_va + dll_name_off;
        blob[desc_off_val as usize + 12..desc_off_val as usize + 16]
            .copy_from_slice(&name_rva.to_le_bytes());
        // FirstThunk (IAT) — same slot
        blob[desc_off_val as usize + 16..desc_off_val as usize + 20]
            .copy_from_slice(&int_rva.to_le_bytes());
        // null_desc_off_val is already zeroed.

        // Write thunk entry: points at hint_name_off_val.
        let hn_rva = section_va + hint_name_off_val;
        let thunk_val: u64 = u64::from(hn_rva); // low bit 0 = import by name
        blob[thunk_off_val as usize..thunk_off_val as usize + 8].copy_from_slice(&thunk_val.to_le_bytes());
        // Null thunk terminator at thunk_off_val+8 is already zero.

        // Write hint/name: hint=0 followed by function name.
        // hint word already 0.
        let hn_off = hint_name_off_val as usize;
        blob[hn_off + 2..hn_off + 2 + fn_bytes.len()].copy_from_slice(fn_bytes);
        // NUL terminator already zero.

        // Write DLL name.
        let dn_off = dll_name_off as usize;
        blob[dn_off..dn_off + dll_bytes.len()].copy_from_slice(dll_bytes);
        // NUL terminator already zero.

        // Record the file offset of the IAT thunk slot (before we append).
        let cur_file_end = self.data.len() as u64;
        let raw_offset = align_up_u32(u32::try_from(cur_file_end).expect("file end fits in u32"), file_align);
        let iat_file_offset: u64 = u64::from(raw_offset) + u64::from(thunk_off_val);

        // Pad to raw_offset.
        let pad_before = (raw_offset as usize).saturating_sub(self.data.len());
        self.data.extend(std::iter::repeat_n(0u8, pad_before));
        self.data.extend_from_slice(&blob);
        let raw_size = align_up_u32(u32::try_from(blob.len()).expect("blob size fits in u32"), file_align);
        let pad_after = (raw_size as usize).saturating_sub(blob.len());
        self.data.extend(std::iter::repeat_n(0u8, pad_after));

        // Update DataDirectory[1] (Import Table) and SizeOfImage.
        update_import_dd_and_image_size(
            &mut self.data, opt_off, is_64bit,
            section_va, blob.len(), sect_align,
        );

        self.edit_log.write().push(format!(
            "add_import: {dll_name}!{function_name} iat_slot@{iat_file_offset:#x}"
        ));
        Ok(iat_file_offset)
    }

    /// Set the entry point (`AddressOfEntryPoint`) in the optional header.
    ///
    /// `new_ep` is treated as a 32-bit RVA regardless of whether the image is
    /// PE32 or PE32+.  Values that exceed `u32::MAX` return
    /// [`EditError::ImportError`] (reusing the closest available variant).
    ///
    /// # Errors
    ///
    /// Returns [`EditError`] if the PE structure is malformed or `new_ep`
    /// exceeds `u32::MAX`.
    ///
    /// # Panics
    /// Panics if the internal `try_from` on a pre-checked value fails (should never occur).
    pub fn set_entry_point(&mut self, new_ep: u64) -> Result<(), EditError> {
        if new_ep > u64::from(u32::MAX) {
            return Err(EditError::ImportError(format!(
                "entry point RVA {new_ep:#x} exceeds u32::MAX; PE AddressOfEntryPoint is always 32-bit"
            )));
        }
        self.patch_entry_point(u32::try_from(new_ep).expect("checked above"))
    }

    /// Zero the debug data directory (entry index 6) and, if the debug
    /// directory data lies entirely within a section, zero those bytes too.
    ///
    /// Returns `&mut Self` so calls can be chained.
    ///
    /// # Errors (ignored internally)
    ///
    /// If the PE structure is malformed the method is a no-op and still returns
    /// `&mut Self`.
    pub fn strip_debug_directory(&mut self) -> &mut Self {
        let Ok(pe_off) = self.pe_header_offset() else {
            return self;
        };
        let opt_off = pe_off + 24;
        if opt_off + 2 > self.data.len() {
            return self;
        }
        let magic = u16::from_le_bytes([self.data[opt_off], self.data[opt_off + 1]]);
        let is_64bit = magic == 0x020B;

        let dd_base = if is_64bit {
            opt_off + 112
        } else {
            opt_off + 96
        };
        // Data directory index 6 = Debug directory.
        let debug_dd_off = dd_base + 6 * 8;
        if debug_dd_off + 8 > self.data.len() {
            return self;
        }

        let debug_rva = u32::from_le_bytes(
            self.data[debug_dd_off..debug_dd_off + 4]
                .try_into()
                .unwrap_or([0; 4]),
        );
        let debug_size = u32::from_le_bytes(
            self.data[debug_dd_off + 4..debug_dd_off + 8]
                .try_into()
                .unwrap_or([0; 4]),
        );

        // Zero the data directory entry itself.
        self.data[debug_dd_off..debug_dd_off + 8].fill(0);

        // If the debug directory has a non-zero RVA and size, attempt to zero
        // the actual debug data by converting RVA → file offset.
        if debug_rva != 0 && debug_size != 0 {
            // Find the section that contains debug_rva.
            if let Ok((table_start, n_sections)) = self.section_table_range() {
                for i in 0..n_sections {
                    let off = table_start + i * 40;
                    if off + 40 > self.data.len() {
                        break;
                    }
                    let va = u32::from_le_bytes(
                        self.data[off + 12..off + 16].try_into().unwrap_or([0; 4]),
                    );
                    let vsz = u32::from_le_bytes(
                        self.data[off + 8..off + 12].try_into().unwrap_or([0; 4]),
                    );
                    let raw_off = u32::from_le_bytes(
                        self.data[off + 20..off + 24].try_into().unwrap_or([0; 4]),
                    ) as usize;
                    let raw_size = u32::from_le_bytes(
                        self.data[off + 16..off + 20].try_into().unwrap_or([0; 4]),
                    ) as usize;
                    if debug_rva >= va && debug_rva < va.saturating_add(vsz) {
                        let delta = (debug_rva - va) as usize;
                        let file_off = raw_off + delta;
                        let zero_len = (debug_size as usize).min(raw_size.saturating_sub(delta));
                        if file_off + zero_len <= self.data.len() {
                            self.data[file_off..file_off + zero_len].fill(0);
                        }
                        break;
                    }
                }
            }
        }

        self.edit_log
            .write()
            .push("strip_debug_directory".to_string());
        self
    }

    /// Validate the PE structure and return a list of human-readable issues.
    ///
    /// An empty return value means no issues were detected.  Issues are
    /// non-fatal diagnostics (the PE may still load) unless noted otherwise.
    #[must_use]
    pub fn integrity_check(&self) -> Vec<String> {
        integrity_check_impl(&self.data)
    }
}

/// Checks optional-header alignment fields; returns `(ep, sect_align, file_align, size_of_image)`.
fn check_opt_header_alignment(
    data: &[u8],
    opt_off: usize,
    is_64bit: bool,
    issues: &mut Vec<String>,
) -> (u32, u32, u32, u32) {
    let ep = u32::from_le_bytes(data[opt_off + 16..opt_off + 20].try_into().unwrap_or([0; 4]));
    let image_base: u64 = if is_64bit {
        u64::from_le_bytes(data[opt_off + 24..opt_off + 32].try_into().unwrap_or([0; 8]))
    } else {
        u64::from(u32::from_le_bytes(data[opt_off + 28..opt_off + 32].try_into().unwrap_or([0; 4])))
    };
    if !image_base.is_multiple_of(0x10000) {
        issues.push(format!("ImageBase ({image_base:#x}) is not a multiple of 0x10000"));
    }
    let sect_align = u32::from_le_bytes(data[opt_off + 32..opt_off + 36].try_into().unwrap_or([0; 4]));
    let file_align = u32::from_le_bytes(data[opt_off + 36..opt_off + 40].try_into().unwrap_or([0; 4]));
    if sect_align == 0 || (sect_align & (sect_align - 1)) != 0 {
        issues.push(format!("SectionAlignment ({sect_align:#x}) is not a power of 2"));
    }
    if file_align == 0 || (file_align & (file_align - 1)) != 0 {
        issues.push(format!("FileAlignment ({file_align:#x}) is not a power of 2"));
    }
    if file_align < 512 && file_align != sect_align {
        issues.push(format!("FileAlignment ({file_align:#x}) < 512 and differs from SectionAlignment"));
    }
    let size_of_image = u32::from_le_bytes(data[opt_off + 56..opt_off + 60].try_into().unwrap_or([0; 4]));
    if sect_align > 0 && size_of_image % sect_align != 0 {
        issues.push(format!("SizeOfImage ({size_of_image:#x}) is not a multiple of SectionAlignment ({sect_align:#x})"));
    }
    let size_of_headers = u32::from_le_bytes(data[opt_off + 60..opt_off + 64].try_into().unwrap_or([0; 4]));
    if file_align > 0 && size_of_headers % file_align != 0 {
        issues.push(format!("SizeOfHeaders ({size_of_headers:#x}) is not aligned to FileAlignment ({file_align:#x})"));
    }
    if size_of_headers > size_of_image {
        issues.push(format!("SizeOfHeaders ({size_of_headers:#x}) exceeds SizeOfImage ({size_of_image:#x})"));
    }
    let checksum = u32::from_le_bytes(data[opt_off + 64..opt_off + 68].try_into().unwrap_or([0; 4]));
    if checksum == 0 {
        issues.push("Checksum is 0 (acceptable for most user-mode images, but drivers/boot files require a valid checksum)".to_string());
    }
    (ep, sect_align, file_align, size_of_image)
}

/// Checks section headers for alignment, bounds, and entry-point membership.
struct SectionCheckContext {
    sect_align: u32,
    file_align: u32,
    size_of_image: u32,
    ep: u32,
}

fn check_section_headers_integrity(
    data: &[u8],
    sect_table: usize,
    n_sections: usize,
    ctx: &SectionCheckContext,
    issues: &mut Vec<String>,
) {
    let sect_align = ctx.sect_align;
    let file_align = ctx.file_align;
    let size_of_image = ctx.size_of_image;
    let ep = ctx.ep;
    for i in 0..n_sections {
        let off = sect_table + i * 40;
        if off + 40 > data.len() {
            issues.push(format!("section header #{i} extends outside file"));
            break;
        }
        let raw_name = &data[off..off + 8];
        let name_str: String = raw_name.iter().copied().take_while(|&b| b != 0).map(|b| b as char).collect();
        let vsz = u32::from_le_bytes(data[off + 8..off + 12].try_into().unwrap_or([0; 4]));
        let va = u32::from_le_bytes(data[off + 12..off + 16].try_into().unwrap_or([0; 4]));
        let rsz = u32::from_le_bytes(data[off + 16..off + 20].try_into().unwrap_or([0; 4]));
        let roff = u32::from_le_bytes(data[off + 20..off + 24].try_into().unwrap_or([0; 4])) as usize;
        if sect_align > 0 && va % sect_align != 0 {
            issues.push(format!("section '{name_str}' VirtualAddress ({va:#x}) not aligned to SectionAlignment ({sect_align:#x})"));
        }
        if file_align > 0 && roff != 0 && !u32::try_from(roff).unwrap_or(u32::MAX).is_multiple_of(file_align) {
            issues.push(format!("section '{name_str}' PointerToRawData ({roff:#x}) not aligned to FileAlignment ({file_align:#x})"));
        }
        if roff + rsz as usize > data.len() {
            issues.push(format!("section '{name_str}' raw data [{roff:#x}..{:#x}] extends outside file (size={}))", roff + rsz as usize, data.len()));
        }
        if va + vsz > size_of_image {
            issues.push(format!("section '{name_str}' virtual extent ({va:#x}+{vsz:#x}) exceeds SizeOfImage ({size_of_image:#x})"));
        }
    }
    if ep != 0 {
        let ep_in_section = (0..n_sections).any(|i| {
            let off = sect_table + i * 40;
            if off + 40 > data.len() { return false; }
            let va = u32::from_le_bytes(data[off + 12..off + 16].try_into().unwrap_or([0; 4]));
            let vsz = u32::from_le_bytes(data[off + 8..off + 12].try_into().unwrap_or([0; 4]));
            let rsz = u32::from_le_bytes(data[off + 16..off + 20].try_into().unwrap_or([0; 4]));
            ep >= va && ep < va.saturating_add(vsz.max(rsz))
        });
        if !ep_in_section {
            issues.push(format!("AddressOfEntryPoint ({ep:#x}) does not fall within any section"));
        }
    }
}

/// Implementation of [`PeEditor::integrity_check`] operating on a raw byte slice.
fn integrity_check_impl(data: &[u8]) -> Vec<String> {
    let mut issues: Vec<String> = Vec::new();
    if data.len() < 64 {
        issues.push(format!("file too short: {} bytes (need at least 64 for DOS header)", data.len()));
        return issues;
    }
    let dos_magic = u16::from_le_bytes([data[0], data[1]]);
    if dos_magic != 0x5A4D {
        issues.push(format!("invalid DOS magic: {dos_magic:#06x} (expected 0x5A4D)"));
    }
    let pe_off = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if pe_off + 24 > data.len() {
        issues.push(format!("e_lfanew ({pe_off:#x}) places PE header outside file"));
        return issues;
    }
    let sig = u32::from_le_bytes(data[pe_off..pe_off + 4].try_into().unwrap_or([0; 4]));
    if sig != 0x0000_4550 {
        issues.push(format!("invalid PE signature: {sig:#010x} (expected 0x00004550)"));
    }
    let machine = u16::from_le_bytes([data[pe_off + 4], data[pe_off + 5]]);
    if machine == 0 {
        issues.push("Machine field is 0 (unknown architecture)".to_string());
    }
    let n_sections = u16::from_le_bytes([data[pe_off + 6], data[pe_off + 7]]) as usize;
    if n_sections > 96 {
        issues.push(format!("unusually high section count: {n_sections}"));
    }
    let opt_hdr_size = u16::from_le_bytes([data[pe_off + 20], data[pe_off + 21]]) as usize;
    if opt_hdr_size == 0 {
        issues.push("SizeOfOptionalHeader is 0 (no optional header; image cannot be loaded)".to_string());
    }
    let opt_off = pe_off + 24;
    if opt_off + 2 > data.len() {
        issues.push("optional header is missing or truncated".to_string());
        return issues;
    }
    let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
    let is_64bit = match magic {
        0x010B => false,
        0x020B => true,
        other => {
            issues.push(format!("unknown optional header magic: {other:#06x} (expected 0x010B or 0x020B)"));
            return issues;
        }
    };
    let min_opt = if is_64bit { 112 } else { 96 };
    if opt_off + min_opt > data.len() {
        issues.push("optional header truncated before data directories".to_string());
        return issues;
    }
    let (ep, sect_align, file_align, size_of_image) =
        check_opt_header_alignment(data, opt_off, is_64bit, &mut issues);
    let sect_table = opt_off + opt_hdr_size;
    check_section_headers_integrity(data, sect_table, n_sections, &SectionCheckContext { sect_align, file_align, size_of_image, ep }, &mut issues);
    issues
}

impl PeEditor {
    /// Rebuild the PE bytes, fixing the PE checksum, and return the resulting
    /// byte vector.
    ///
    /// The method:
    /// 1. Verifies the DOS magic and PE signature are correct.
    /// 2. Recalculates and writes the PE checksum.
    /// 3. Returns a clone of the internal buffer.
    ///
    /// # Errors
    ///
    /// Returns [`EditError`] if the PE structure is too malformed to compute a
    /// checksum (e.g., optional header is truncated).
    pub fn rebuild(&mut self) -> Result<Vec<u8>, EditError> {
        // Ensure DOS magic is correct.
        if self.data.len() >= 2 {
            let magic = u16::from_le_bytes([self.data[0], self.data[1]]);
            if magic != 0x5A4D {
                return Err(EditError::Pe(PeError::InvalidHeader(format!(
                    "invalid DOS magic {magic:#06x}; cannot rebuild"
                ))));
            }
        }

        // Ensure PE signature is correct.
        let pe_off = self.pe_header_offset()?;
        if pe_off + 4 <= self.data.len() {
            let sig =
                u32::from_le_bytes(self.data[pe_off..pe_off + 4].try_into().unwrap_or([0; 4]));
            if sig != 0x0000_4550 {
                return Err(EditError::Pe(PeError::InvalidHeader(format!(
                    "invalid PE signature {sig:#010x}; cannot rebuild"
                ))));
            }
        }

        // Recalculate and write checksum.
        self.recalculate_checksum()?;

        self.edit_log.write().push("rebuild".to_string());
        Ok(self.data.clone())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const fn align_up_u32(value: u32, align: u32) -> u32 {
    if align == 0 {
        return value;
    }
    value.saturating_add(align - 1) & !(align - 1)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_pe_tools::PeBuilder;

    fn make_x64_pe() -> Vec<u8> {
        let mut b = PeBuilder::new_x64();
        b.add_section(".text", vec![0x90u8; 64], 0x6000_0020);
        b.add_section(".data", vec![0xAAu8; 32], 0xC000_0040);
        b.build()
    }

    fn make_x86_pe() -> Vec<u8> {
        let mut b = PeBuilder::new_x86();
        b.add_section(".text", vec![0xCCu8; 16], 0x6000_0020);
        b.build()
    }

    // ---- EditError display -------------------------------------------------

    #[test]
    fn test_edit_error_section_not_found() {
        let e = EditError::SectionNotFound(".bss".to_string());
        assert!(e.to_string().contains(".bss"));
    }

    #[test]
    fn test_edit_error_patch_oob() {
        let e = EditError::PatchOutOfBounds {
            offset: 10,
            len: 5,
            file_size: 12,
        };
        assert!(e.to_string().contains("offset=10"));
    }

    #[test]
    fn test_edit_error_invalid_alignment() {
        let e = EditError::InvalidAlignment("bad".to_string());
        assert!(e.to_string().contains("bad"));
    }

    #[test]
    fn test_edit_error_crypto() {
        let e = EditError::CryptoError("key too short".to_string());
        assert!(e.to_string().contains("crypto"));
    }

    #[test]
    fn test_edit_error_import() {
        let e = EditError::ImportError("dup".to_string());
        assert!(e.to_string().contains("import"));
    }

    #[test]
    fn test_edit_error_export() {
        let e = EditError::ExportError("missing".to_string());
        assert!(e.to_string().contains("export"));
    }

    #[test]
    fn test_edit_error_resource() {
        let e = EditError::ResourceError("too big".to_string());
        assert!(e.to_string().contains("resource"));
    }

    #[test]
    fn test_edit_error_sign() {
        let e = EditError::SignError("cert invalid".to_string());
        assert!(e.to_string().contains("sign"));
    }

    // ---- PeEditor construction ---------------------------------------------

    #[test]
    fn test_new_valid() {
        let bytes = make_x64_pe();
        assert!(PeEditor::new(bytes).is_ok());
    }

    #[test]
    fn test_new_invalid() {
        assert!(PeEditor::new(vec![0u8; 10]).is_err());
    }

    // ---- apply_patch -------------------------------------------------------

    #[test]
    fn test_apply_patch_basic() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        let size = ed.bytes().len();
        let patch = Patch::simple(size - 4, vec![0xDE, 0xAD, 0xBE, 0xEF], "test".to_string());
        ed.apply_patch(patch).unwrap();
        let b = ed.bytes();
        assert_eq!(&b[size - 4..], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_apply_patch_oob() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        let size = ed.bytes().len();
        let patch = Patch::simple(size - 2, vec![1, 2, 3, 4], "oob".to_string());
        assert!(matches!(
            ed.apply_patch(patch),
            Err(EditError::PatchOutOfBounds { .. })
        ));
    }

    #[test]
    fn test_apply_patch_verified() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        let size = ed.bytes().len();
        let orig = ed.bytes()[size - 1];
        let patch = Patch::verified(size - 1, vec![orig], vec![0xEE], "verified".to_string());
        ed.apply_patch(patch).unwrap();
        assert_eq!(ed.bytes()[size - 1], 0xEE);
    }

    // ---- PatchSet ----------------------------------------------------------

    #[test]
    fn test_patchset_empty() {
        let ps = PatchSet::new("empty".to_string());
        assert!(ps.is_empty());
        assert_eq!(ps.len(), 0);
        assert!(ps.to_string().contains("empty"));
    }

    #[test]
    fn test_patchset_apply() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        let size = ed.bytes().len();
        let mut ps = PatchSet::new("set1".to_string());
        ps.add(Patch::simple(size - 1, vec![0xFF], "last byte".to_string()));
        assert_eq!(ps.len(), 1);
        ed.apply_patchset(ps).unwrap();
        assert_eq!(ed.bytes()[size - 1], 0xFF);
    }

    #[test]
    fn test_patchset_total_bytes() {
        let mut ps = PatchSet::new("t".to_string());
        ps.add(Patch::simple(0, vec![1, 2, 3], "a".to_string()));
        ps.add(Patch::simple(4, vec![4, 5], "b".to_string()));
        assert_eq!(ps.total_bytes(), 5);
    }

    // ---- nop_range / int3_range --------------------------------------------

    #[test]
    fn test_nop_range_valid() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        let size = ed.bytes().len();
        ed.nop_range(size - 8, 4).unwrap();
        assert!(ed.bytes()[size - 8..size - 4].iter().all(|&b| b == 0x90));
    }

    #[test]
    fn test_nop_range_oob() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        let size = ed.bytes().len();
        assert!(matches!(
            ed.nop_range(size - 2, 10),
            Err(EditError::PatchOutOfBounds { .. })
        ));
    }

    #[test]
    fn test_int3_range() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        let size = ed.bytes().len();
        ed.int3_range(size - 4, 4).unwrap();
        assert!(ed.bytes()[size - 4..].iter().all(|&b| b == 0xCC));
    }

    // ---- patch_entry_point -------------------------------------------------

    #[test]
    fn test_patch_entry_point_x64() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        ed.patch_entry_point(0x2000).unwrap();
        let pe = ed.parse_current().unwrap();
        assert_eq!(pe.entry_point, 0x2000);
    }

    #[test]
    fn test_patch_entry_point_x86() {
        let bytes = make_x86_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        ed.patch_entry_point(0x1500).unwrap();
        let pe = ed.parse_current().unwrap();
        assert_eq!(pe.entry_point, 0x1500);
    }

    // ---- zero_checksum -----------------------------------------------------

    #[test]
    fn test_zero_checksum() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        ed.zero_checksum().unwrap();
        let pe = ed.parse_current().unwrap();
        assert_eq!(pe.checksum, 0);
    }

    // ---- write_bytes / read_bytes ------------------------------------------

    #[test]
    fn test_write_read_bytes() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        let size = ed.bytes().len();
        ed.write_bytes(size - 4, &[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
        let read = ed.read_bytes(size - 4, 4).unwrap();
        assert_eq!(read, &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_read_bytes_oob() {
        let bytes = make_x64_pe();
        let ed = PeEditor::new(bytes).unwrap();
        let size = ed.bytes().len();
        assert!(ed.read_bytes(size - 2, 10).is_err());
    }

    // ---- into_bytes / bytes / applied_patches ------------------------------

    #[test]
    fn test_into_bytes_roundtrip() {
        let bytes = make_x64_pe();
        let len = bytes.len();
        let ed = PeEditor::new(bytes).unwrap();
        let out = ed.into_bytes();
        assert_eq!(out.len(), len);
    }

    #[test]
    fn test_applied_patches_count() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        let size = ed.bytes().len();
        ed.apply_patch(Patch::simple(size - 1, vec![0xAA], "p1".to_string()))
            .unwrap();
        ed.apply_patch(Patch::simple(size - 2, vec![0xBB], "p2".to_string()))
            .unwrap();
        assert_eq!(ed.applied_patches().len(), 2);
        assert_eq!(ed.applied_count(), 2);
    }

    // ---- parse_current -----------------------------------------------------

    #[test]
    fn test_parse_current() {
        let bytes = make_x64_pe();
        let ed = PeEditor::new(bytes).unwrap();
        let pe = ed.parse_current().unwrap();
        assert_eq!(pe.machine, rustre_pe_tools::PeMachine::Amd64);
    }

    // ---- add_section -------------------------------------------------------

    #[test]
    fn test_add_section() {
        let bytes = make_x64_pe();
        let orig_sections = PeFile::parse(&bytes).unwrap().sections.len();
        let mut ed = PeEditor::new(bytes).unwrap();
        ed.add_section(".new", &[0xBBu8; 16], 0x4000_0040)
            .unwrap();
        let pe = ed.parse_current().unwrap();
        assert_eq!(pe.sections.len(), orig_sections + 1);
        assert!(pe.section_by_name(".new").is_some());
    }

    #[test]
    fn test_add_section_x86() {
        let bytes = make_x86_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        ed.add_section(".extra", &[0x00u8; 8], 0xC000_0040)
            .unwrap();
        let pe = ed.parse_current().unwrap();
        assert!(pe.section_by_name(".extra").is_some());
    }

    // ---- zero_section ------------------------------------------------------

    #[test]
    fn test_zero_section() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        ed.zero_section(".text").unwrap();
        // Section data should be zeroed; PE header should survive
        ed.parse_current().unwrap();
    }

    // ---- xor_encrypt_section -----------------------------------------------

    #[test]
    fn test_xor_encrypt_decrypt() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        let key = b"secretkey";
        // Read original
        let orig = ed.bytes().to_vec();
        ed.xor_encrypt_section(".text", key).unwrap();
        // Decrypt
        ed.xor_decrypt_section(".text", key).unwrap();
        assert_eq!(ed.bytes(), orig.as_slice());
    }

    // ---- RC4 ---------------------------------------------------------------

    #[test]
    fn test_rc4_process() {
        let mut rc4_enc = Rc4::new(b"key");
        let mut rc4_dec = Rc4::new(b"key");
        let orig = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let mut data = orig.clone();
        rc4_enc.process(&mut data);
        rc4_dec.process(&mut data);
        assert_eq!(data, orig);
    }

    #[test]
    fn test_rc4_encrypt_section() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        ed.rc4_encrypt_section(".text", b"testkey").unwrap();
        // No crash
    }

    // ---- ImportEditor ------------------------------------------------------

    #[test]
    fn test_import_editor_add() {
        let mut ie = ImportEditor::new();
        ie.add_import(ImportEntry::named(
            "kernel32.dll".to_string(),
            "VirtualAlloc".to_string(),
            0,
        ));
        assert_eq!(ie.pending_additions(), 1);
    }

    #[test]
    fn test_import_editor_remove() {
        let mut ie = ImportEditor::new();
        ie.remove_dll("ntdll.dll".to_string());
        assert_eq!(ie.pending_removals(), 1);
    }

    #[test]
    fn test_import_editor_apply() {
        let bytes = make_x64_pe();
        let mut ie = ImportEditor::new();
        ie.add_import(ImportEntry::named(
            "kernel32.dll".to_string(),
            "LoadLibraryA".to_string(),
            1,
        ));
        let mut data = bytes;
        let added = ie.apply(&mut data).unwrap();
        assert_eq!(added, 1);
    }

    #[test]
    fn test_import_editor_clear() {
        let mut ie = ImportEditor::new();
        ie.add_import(ImportEntry::ordinal("ntdll.dll".to_string(), 10));
        ie.remove_dll("kernel32.dll".to_string());
        ie.clear();
        assert_eq!(ie.pending_additions(), 0);
        assert_eq!(ie.pending_removals(), 0);
    }

    #[test]
    fn test_import_entry_display() {
        let e = ImportEntry::named("kernel32.dll".to_string(), "VirtualAlloc".to_string(), 1);
        assert!(e.to_string().contains("VirtualAlloc"));
        assert!(e.is_named());
    }

    #[test]
    fn test_import_entry_ordinal_display() {
        let e = ImportEntry::ordinal("ntdll.dll".to_string(), 5);
        assert!(e.to_string().contains("#5"));
        assert!(!e.is_named());
    }

    // ---- ExportEditor ------------------------------------------------------

    #[test]
    fn test_export_editor_add_remove() {
        let mut ee = ExportEditor::new("test.dll".to_string());
        ee.add_export("Foo".to_string(), 1, 0x1000);
        ee.remove_export("Bar".to_string());
        assert_eq!(ee.pending_count(), 2);
        assert_eq!(ee.additions().len(), 1);
        assert_eq!(ee.removals().len(), 1);
    }

    #[test]
    fn test_export_editor_clear() {
        let mut ee = ExportEditor::new("d.dll".to_string());
        ee.add_export("X".to_string(), 1, 0x100);
        ee.clear();
        assert_eq!(ee.pending_count(), 0);
    }

    #[test]
    fn test_export_edit_display() {
        let add = ExportEdit::add("Alpha".to_string(), 1, 0x2000);
        assert!(add.to_string().contains("Add"));
        let rem = ExportEdit::remove("Beta".to_string());
        assert!(rem.to_string().contains("Remove"));
    }

    // ---- ResourceEditor ----------------------------------------------------

    #[test]
    fn test_resource_editor_add() {
        let mut re = ResourceEditor::new();
        re.add_resource(ResourceEntry::manifest(b"<manifest/>".to_vec()));
        assert_eq!(re.pending_additions(), 1);
        assert_eq!(re.total_data_size(), b"<manifest/>".len());
    }

    #[test]
    fn test_resource_editor_remove() {
        let mut re = ResourceEditor::new();
        re.remove_resource(ResourceType::Id(resource_types::RT_ICON), 1);
        assert_eq!(re.pending_removals(), 1);
    }

    #[test]
    fn test_resource_entry_display() {
        let r = ResourceEntry::manifest(vec![0u8; 128]);
        assert!(r.to_string().contains("128"));
    }

    #[test]
    fn test_resource_type_display() {
        assert_eq!(ResourceType::Id(6).to_string(), "#6");
        assert_eq!(ResourceType::Name("FOO".to_string()).to_string(), "FOO");
    }

    // ---- PeSigningScaffold -------------------------------------------------

    #[test]
    fn test_signing_scaffold_build() {
        let s = PeSigningScaffold::new(vec![0x30, 0x82, 0x00, 0x00]);
        let blob = s.build_certificate_blob();
        assert!(!blob.is_empty());
        assert_eq!(blob.len() % 8, 0); // aligned
        assert_eq!(s.payload_len(), 4);
    }

    #[test]
    fn test_signing_scaffold_inject() {
        let mut bytes = make_x64_pe();
        let s = PeSigningScaffold::new(vec![0u8; 16]);
        s.inject(&mut bytes).unwrap();
        // Verify the file grew
        assert!(bytes.len() > make_x64_pe().len());
    }

    #[test]
    fn test_certificate_header_bytes() {
        let hdr = CertificateHeader::new(100);
        let b = hdr.to_bytes();
        let len = u32::from_le_bytes(b[0..4].try_into().unwrap());
        assert_eq!(len, 108); // 8 + 100
    }

    // ---- SectionEditor ----------------------------------------------------

    #[test]
    fn test_section_editor_rename() {
        let bytes = make_x64_pe();
        let mut se = SectionEditor::new(bytes).unwrap();
        se.rename_section(".text", ".code").unwrap();
        let pe = PeFile::parse(se.bytes()).unwrap();
        assert!(pe.section_by_name(".code").is_some());
    }

    #[test]
    fn test_section_editor_set_characteristics() {
        let bytes = make_x64_pe();
        let mut se = SectionEditor::new(bytes).unwrap();
        se.set_characteristics(
            ".text",
            section_chars::MEM_READ | section_chars::MEM_EXECUTE,
        )
        .unwrap();
    }

    #[test]
    fn test_section_editor_zero() {
        let bytes = make_x64_pe();
        let mut se = SectionEditor::new(bytes).unwrap();
        se.zero_section(".text").unwrap();
    }

    #[test]
    fn test_section_editor_read() {
        let bytes = make_x64_pe();
        let se = SectionEditor::new(bytes).unwrap();
        let data = se.read_section(".text").unwrap();
        assert!(!data.is_empty());
    }

    #[test]
    fn test_section_editor_write_into() {
        let bytes = make_x64_pe();
        let mut se = SectionEditor::new(bytes).unwrap();
        se.write_into_section(".text", 0, &[0x90, 0x90, 0x90, 0x90])
            .unwrap();
        let data = se.read_section(".text").unwrap();
        assert_eq!(data[0], 0x90);
    }

    // ---- xor_section (free fn) ---------------------------------------------

    #[test]
    fn test_xor_section_roundtrip() {
        let mut data = vec![0xAA, 0xBB, 0xCC];
        let key = b"k";
        xor_section(&mut data, key);
        xor_section(&mut data, key);
        assert_eq!(data, vec![0xAA, 0xBB, 0xCC]);
    }

    // ---- align_up_u32 helper -----------------------------------------------

    #[test]
    fn test_align_up_u32() {
        assert_eq!(align_up_u32(0, 0x200), 0);
        assert_eq!(align_up_u32(1, 0x200), 0x200);
        assert_eq!(align_up_u32(0x200, 0x200), 0x200);
        assert_eq!(align_up_u32(0x201, 0x200), 0x400);
    }

    // ---- edit_log ----------------------------------------------------------

    #[test]
    fn test_edit_log() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        ed.patch_entry_point(0x3000).unwrap();
        let log = ed.edit_log();
        assert!(!log.is_empty());
    }

    // ---- error source chains -----------------------------------------------

    #[test]
    fn test_edit_error_pe_variant() {
        let e = EditError::Pe(PeError::ImportTableCorrupt);
        assert!(e.to_string().contains("pe error"));
    }

    // ---- rva_in_section ----------------------------------------------------

    #[test]
    fn test_rva_in_section() {
        let bytes = make_x64_pe();
        let ed = PeEditor::new(bytes).unwrap();
        let pe = ed.parse_current().unwrap();
        if let Some(sec) = pe.sections.first() {
            assert!(ed.rva_in_section(sec.virtual_address).unwrap());
            assert!(!ed.rva_in_section(0xFFFF_0000).unwrap());
        }
    }

    // ---- HeaderField display -----------------------------------------------

    #[test]
    fn test_header_field_display() {
        assert_eq!(HeaderField::Subsystem.to_string(), "Subsystem");
        assert_eq!(HeaderField::MajorOsVersion.to_string(), "MajorOsVersion");
    }

    // ---- Patch helper constructors -----------------------------------------

    #[test]
    fn test_patch_simple_has_no_verification() {
        let p = Patch::simple(0, vec![0x90], "nop".to_string());
        assert!(!p.has_verification());
        assert_eq!(p.len(), 1);
        assert!(!p.is_empty());
    }

    #[test]
    fn test_patch_display() {
        let p = Patch::simple(0x100, vec![0x90, 0x90], "nop2".to_string());
        assert!(p.to_string().contains("nop2"));
    }

    // ---- PeParser ----------------------------------------------------------

    #[test]
    fn test_parse_dos_header_valid() {
        let bytes = make_x64_pe();
        let dos = PeParser::parse_dos_header(&bytes).unwrap();
        assert_eq!(dos.e_magic, 0x5A4D);
        assert!(dos.e_lfanew > 0);
    }

    #[test]
    fn test_parse_dos_header_bad_magic() {
        let mut bytes = make_x64_pe();
        bytes[0] = 0x00;
        assert!(matches!(
            PeParser::parse_dos_header(&bytes),
            Err(ParseError::InvalidDosMagic(_))
        ));
    }

    #[test]
    fn test_parse_dos_header_too_short() {
        assert!(matches!(
            PeParser::parse_dos_header(&[0x4D, 0x5A]),
            Err(ParseError::TooShort { .. })
        ));
    }

    #[test]
    fn test_parse_file_header_valid() {
        let bytes = make_x64_pe();
        let dos = PeParser::parse_dos_header(&bytes).unwrap();
        let pe_off = dos.e_lfanew as usize;
        let fh = PeParser::parse_file_header(&bytes, pe_off + 4).unwrap();
        assert!(fh.number_of_sections > 0);
        // Machine: 0x8664 = AMD64
        assert_eq!(fh.machine, 0x8664);
    }

    #[test]
    fn test_parse_optional_header64_valid() {
        let bytes = make_x64_pe();
        let dos = PeParser::parse_dos_header(&bytes).unwrap();
        let pe_off = dos.e_lfanew as usize;
        let opt_off = pe_off + 24;
        let oh = PeParser::parse_optional_header64(&bytes, opt_off).unwrap();
        assert_eq!(oh.magic, 0x020B);
        assert!(oh.section_alignment > 0);
        assert!(oh.file_alignment > 0);
    }

    #[test]
    fn test_parse_optional_header64_wrong_magic() {
        let bytes = make_x86_pe();
        let dos = PeParser::parse_dos_header(&bytes).unwrap();
        let pe_off = dos.e_lfanew as usize;
        let opt_off = pe_off + 24;
        // x86 PE has magic 0x010B, not 0x020B
        assert!(matches!(
            PeParser::parse_optional_header64(&bytes, opt_off),
            Err(ParseError::MalformedHeader(_))
        ));
    }

    #[test]
    fn test_parse_sections_valid() {
        let bytes = make_x64_pe();
        let dos = PeParser::parse_dos_header(&bytes).unwrap();
        let pe_off = dos.e_lfanew as usize;
        let fh = PeParser::parse_file_header(&bytes, pe_off + 4).unwrap();
        let opt_off = pe_off + 24;
        let sect_off = opt_off + fh.size_of_optional_header as usize;
        let sections = PeParser::parse_sections(&bytes, sect_off, fh.number_of_sections).unwrap();
        assert!(!sections.is_empty());
        assert!(sections.iter().any(|s| s.name == ".text"));
    }

    // ---- PeTreeBuilder -----------------------------------------------------

    #[test]
    fn test_build_tree_x64() {
        let bytes = make_x64_pe();
        let tree = PeTreeBuilder::build_tree(&bytes);
        assert!(tree.find("DOS Header").is_some());
        assert!(tree.find("NT Headers").is_some());
        assert!(tree.find("Section Table").is_some());
        assert!(tree.find("Data Directories").is_some());
    }

    #[test]
    fn test_build_tree_dos_fields() {
        let bytes = make_x64_pe();
        let tree = PeTreeBuilder::build_tree(&bytes);
        let dos_node = tree.find("DOS Header").unwrap();
        assert!(!dos_node.fields.is_empty());
        assert!(dos_node.fields.iter().any(|f| f.name == "e_magic"));
    }

    #[test]
    fn test_build_tree_nt_children() {
        let bytes = make_x64_pe();
        let tree = PeTreeBuilder::build_tree(&bytes);
        let nt = tree.find("NT Headers").unwrap();
        assert!(!nt.children.is_empty());
    }

    #[test]
    fn test_build_tree_section_children() {
        let bytes = make_x64_pe();
        let tree = PeTreeBuilder::build_tree(&bytes);
        let sects = tree.find("Section Table").unwrap();
        assert!(sects.children.iter().any(|c| c.name == ".text"));
    }

    #[test]
    fn test_build_tree_data_dirs() {
        let bytes = make_x64_pe();
        let tree = PeTreeBuilder::build_tree(&bytes);
        let dd = tree.find("Data Directories").unwrap();
        assert!(!dd.children.is_empty());
        assert!(dd.children.iter().any(|c| c.name == "Export Table"));
    }

    #[test]
    fn test_build_tree_invalid_data() {
        let bytes = vec![0u8; 32];
        let tree = PeTreeBuilder::build_tree(&bytes);
        assert!(!tree.sections.is_empty()); // stub node
    }

    #[test]
    fn test_pe_field_display() {
        let f = PeField::new("e_magic", 0x5A4D, "MZ signature");
        assert!(f.to_string().contains("e_magic"));
        assert!(f.to_string().contains("0x5a4d"));
    }

    #[test]
    fn test_pe_tree_node_display() {
        let node = PeTreeNode::leaf("Foo", 0x100, 64);
        assert!(node.to_string().contains("Foo"));
    }

    #[test]
    fn test_pe_tree_node_total_fields() {
        let mut node = PeTreeNode::leaf("Parent", 0, 0);
        node.fields.push(PeField::new("a", 1, ""));
        let mut child = PeTreeNode::leaf("Child", 0, 0);
        child.fields.push(PeField::new("b", 2, ""));
        child.fields.push(PeField::new("c", 3, ""));
        node.children.push(child);
        assert_eq!(node.total_fields(), 3);
    }

    // ---- recalculate_checksum ----------------------------------------------

    #[test]
    fn test_recalculate_checksum_produces_u32() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        let cs = ed.recalculate_checksum().unwrap();
        // Checksum should be non-zero for a real PE.
        // Just check it's a valid u32 and was written back.
        let re_read = u32::from_le_bytes({
            let pe_off = u32::from_le_bytes([
                ed.bytes()[60],
                ed.bytes()[61],
                ed.bytes()[62],
                ed.bytes()[63],
            ]) as usize;
            let cs_off = pe_off + 24 + 64;
            ed.bytes()[cs_off..cs_off + 4].try_into().unwrap()
        });
        assert_eq!(re_read, cs);
    }

    #[test]
    fn test_recalculate_checksum_deterministic() {
        let bytes = make_x64_pe();
        let mut ed1 = PeEditor::new(bytes.clone()).unwrap();
        let mut ed2 = PeEditor::new(bytes).unwrap();
        assert_eq!(
            ed1.recalculate_checksum().unwrap(),
            ed2.recalculate_checksum().unwrap()
        );
    }

    #[test]
    fn test_recalculate_checksum_logged() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        ed.recalculate_checksum().unwrap();
        assert!(ed.edit_log().iter().any(|l| l.contains("checksum")));
    }

    // ---- PeSection ---------------------------------------------------------

    #[test]
    fn test_pe_section_add() {
        let bytes = make_x64_pe();
        let orig_count = PeFile::parse(&bytes).unwrap().sections.len();
        let mut ed = PeEditor::new(bytes).unwrap();
        {
            let mut ps = PeSection::new(&mut ed);
            ps.add_section(".extra", 0x4000_0040, &[0xBBu8; 32])
                .unwrap();
        }
        let pe = ed.parse_current().unwrap();
        assert_eq!(pe.sections.len(), orig_count + 1);
        assert!(pe.section_by_name(".extra").is_some());
    }

    #[test]
    fn test_pe_section_rename() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        {
            let mut ps = PeSection::new(&mut ed);
            ps.rename_section(".text", ".code").unwrap();
        }
        let pe = ed.parse_current().unwrap();
        assert!(pe.section_by_name(".code").is_some());
        assert!(pe.section_by_name(".text").is_none());
    }

    #[test]
    fn test_pe_section_rename_not_found() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        let mut ps = PeSection::new(&mut ed);
        assert!(matches!(
            ps.rename_section(".nonexistent", ".foo"),
            Err(EditError::SectionNotFound(_))
        ));
    }

    #[test]
    fn test_pe_section_remove() {
        let bytes = make_x64_pe();
        let orig_count = PeFile::parse(&bytes).unwrap().sections.len();
        let mut ed = PeEditor::new(bytes).unwrap();
        {
            let mut ps = PeSection::new(&mut ed);
            let removed = ps.remove_section(".text").unwrap();
            assert!(removed);
        }
        let pe = ed.parse_current().unwrap();
        assert_eq!(pe.sections.len(), orig_count - 1);
    }

    #[test]
    fn test_pe_section_remove_nonexistent() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        let mut ps = PeSection::new(&mut ed);
        let removed = ps.remove_section(".nonexistent").unwrap();
        assert!(!removed);
    }

    #[test]
    fn test_pe_section_set_data() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        {
            let mut ps = PeSection::new(&mut ed);
            ps.set_section_data(".text", &[0xCCu8; 16]).unwrap();
        }
        // Verify the data was written by reading the section.
        let se = SectionEditor::new(ed.into_bytes()).unwrap();
        let data = se.read_section(".text").unwrap();
        assert!(data[..16].iter().all(|&b| b == 0xCC));
    }

    #[test]
    fn test_pe_section_set_data_not_found() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        let mut ps = PeSection::new(&mut ed);
        assert!(matches!(
            ps.set_section_data(".nosuch", &[0u8; 4]),
            Err(EditError::SectionNotFound(_))
        ));
    }

    // ---- add_import (new) --------------------------------------------------

    #[test]
    fn test_add_import_returns_offset() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        let iat_off = ed.add_import("kernel32.dll", "VirtualAlloc").unwrap();
        // Offset must be within the (now-larger) file.
        assert!((iat_off as usize) < ed.bytes().len());
        // The 8 bytes at that offset should be a non-zero thunk (RVA of hint/name).
        let thunk = u64::from_le_bytes(
            ed.bytes()[iat_off as usize..iat_off as usize + 8]
                .try_into()
                .unwrap(),
        );
        assert_ne!(thunk, 0, "thunk entry should be non-zero");
    }

    #[test]
    fn test_add_import_grows_file() {
        let bytes = make_x64_pe();
        let original_size = bytes.len();
        let mut ed = PeEditor::new(bytes).unwrap();
        ed.add_import("ntdll.dll", "NtAllocateVirtualMemory")
            .unwrap();
        assert!(ed.bytes().len() > original_size);
    }

    // ---- set_entry_point (new) ---------------------------------------------

    #[test]
    fn test_set_entry_point_u64() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        ed.set_entry_point(0x1234).unwrap();
        let pe = ed.parse_current().unwrap();
        assert_eq!(pe.entry_point, 0x1234);
    }

    #[test]
    fn test_set_entry_point_exceeds_u32_is_err() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        let result = ed.set_entry_point(0x1_0000_0000u64);
        assert!(result.is_err());
    }

    // ---- strip_debug_directory (new) ---------------------------------------

    #[test]
    fn test_strip_debug_directory_zeroes_dd() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        ed.strip_debug_directory();
        // Verify data directory 6 is zeroed.
        let pe_off = u32::from_le_bytes([
            ed.bytes()[60],
            ed.bytes()[61],
            ed.bytes()[62],
            ed.bytes()[63],
        ]) as usize;
        let opt_off = pe_off + 24;
        let magic = u16::from_le_bytes([ed.bytes()[opt_off], ed.bytes()[opt_off + 1]]);
        let dd_base = if magic == 0x020B {
            opt_off + 112
        } else {
            opt_off + 96
        };
        let debug_dd_off = dd_base + 6 * 8;
        let rva = u32::from_le_bytes(
            ed.bytes()[debug_dd_off..debug_dd_off + 4]
                .try_into()
                .unwrap(),
        );
        let size = u32::from_le_bytes(
            ed.bytes()[debug_dd_off + 4..debug_dd_off + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(rva, 0, "debug dd RVA should be 0 after strip");
        assert_eq!(size, 0, "debug dd Size should be 0 after strip");
    }

    #[test]
    fn test_strip_debug_directory_chainable() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        // strip_debug_directory returns &mut Self — just confirm no panic.
        ed.strip_debug_directory().strip_debug_directory();
    }

    // ---- integrity_check (new) ---------------------------------------------

    #[test]
    fn test_integrity_check_clean_pe_no_ep_in_section_warning() {
        let bytes = make_x64_pe();
        let ed = PeEditor::new(bytes).unwrap();
        let issues = ed.integrity_check();
        // A freshly-built PE should have only the checksum-zero warning,
        // since PeBuilder doesn't compute a real checksum.
        // No "outside file" or magic errors.
        assert!(
            !issues.iter().any(|i| i.contains("invalid DOS magic")),
            "unexpected DOS magic issue: {issues:?}"
        );
        assert!(
            !issues.iter().any(|i| i.contains("extends outside file")),
            "section outside file: {issues:?}"
        );
    }

    #[test]
    fn test_integrity_check_bad_magic_detected() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        // Corrupt DOS magic.
        ed.write_bytes(0, &[0x00, 0x00]).unwrap();
        let issues = ed.integrity_check();
        assert!(issues.iter().any(|i| i.contains("invalid DOS magic")));
    }

    #[test]
    fn test_integrity_check_returns_vec() {
        let bytes = make_x64_pe();
        let ed = PeEditor::new(bytes).unwrap();
        let issues = ed.integrity_check();
        // Result is a Vec<String> — just checking the type and no panic.
        let _ = issues.len();
    }

    // ---- rebuild (new) -----------------------------------------------------

    #[test]
    fn test_rebuild_returns_valid_pe() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        let rebuilt = ed.rebuild().unwrap();
        // Must still parse as a valid PE.
        assert!(PeFile::parse(&rebuilt).is_ok());
    }

    #[test]
    fn test_rebuild_fixes_checksum() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        // Zero the checksum first.
        ed.zero_checksum().unwrap();
        let rebuilt = ed.rebuild().unwrap();
        // After rebuild, checksum should be non-zero.
        let pe_off =
            u32::from_le_bytes([rebuilt[60], rebuilt[61], rebuilt[62], rebuilt[63]]) as usize;
        let cs_off = pe_off + 24 + 64;
        let checksum = u32::from_le_bytes(rebuilt[cs_off..cs_off + 4].try_into().unwrap());
        assert_ne!(checksum, 0, "rebuild should produce a non-zero checksum");
    }

    #[test]
    fn test_rebuild_bad_magic_is_err() {
        let bytes = make_x64_pe();
        let mut ed = PeEditor::new(bytes).unwrap();
        ed.write_bytes(0, &[0x00, 0x00]).unwrap();
        assert!(ed.rebuild().is_err());
    }

    // ---- ParseError display ------------------------------------------------

    #[test]
    fn test_parse_error_too_short() {
        let e = ParseError::TooShort { needed: 64, got: 4 };
        assert!(e.to_string().contains("64"));
    }

    #[test]
    fn test_parse_error_invalid_magic() {
        let e = ParseError::InvalidDosMagic(0x1234);
        assert!(e.to_string().contains("0x1234"));
    }

    #[test]
    fn test_parse_error_malformed() {
        let e = ParseError::MalformedHeader("bad field".to_string());
        assert!(e.to_string().contains("bad field"));
    }
}
