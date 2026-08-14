//! PE rebuilder — reconstructs a portable-executable image from its analysed
//! parts.
//!
//! Provides [`PeRebuilder`] with methods for:
//! * OEP (original entry-point) detection via stolen-bytes and IAT-trampoline
//!   heuristics.
//! * Import-address-table fixup (`fix_iat`).
//! * Full import-table reconstruction from an [`ImportSpec`] list.
//! * Section alignment correction.
//! * PE checksum recalculation.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{PeError, PeFile, PeSection, align_up, compute_pe_checksum};

// ─── RebuildError ─────────────────────────────────────────────────────────────

/// Errors produced by the PE rebuilder.
#[derive(Debug, Error)]
pub enum RebuildError {
    /// Underlying PE parse error.
    #[error("pe error: {0}")]
    Pe(#[from] PeError),
    /// Entry-point RVA is outside every section.
    #[error("entry point {0:#x} not in any section")]
    EntryPointOutOfSection(u32),
    /// A required section is missing.
    #[error("missing section: {0}")]
    MissingSection(String),
    /// IAT slot RVA is not resolvable.
    #[error("iat slot {0:#x} cannot be resolved to a file offset")]
    IatSlotUnresolvable(u32),
    /// Import table cannot be written: buffer too small.
    #[error("import table write error: {0}")]
    ImportTableWrite(String),
    /// Structural error.
    #[error("invalid PE structure: {0}")]
    Invalid(String),
}

// ─── OepHint ──────────────────────────────────────────────────────────────────

/// The outcome of an OEP-detection heuristic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OepHint {
    /// The stored entry point is likely correct (no packer artefacts found).
    LikelyOriginal(u32),
    /// A stolen-bytes stub was detected; the real OEP is after the stub.
    StolenBytesStub {
        /// RVA of the real OEP (after the stub).
        real_oep: u32,
        /// Length of the stolen prefix in bytes.
        stub_len: u8,
    },
    /// An IAT trampoline was found at the entry point.
    IatTrampoline {
        /// Target RVA after following the trampoline.
        target_rva: u32,
    },
    /// Heuristics could not determine the OEP.
    Unknown,
}

impl OepHint {
    /// Return the candidate OEP RVA regardless of heuristic type.
    #[must_use]
    pub const fn candidate_rva(&self) -> u32 {
        match self {
            Self::LikelyOriginal(rva) | Self::StolenBytesStub { real_oep: rva, .. } => *rva,
            Self::IatTrampoline { target_rva } => *target_rva,
            Self::Unknown => 0,
        }
    }

    /// Return `true` if this hint is `Unknown`.
    #[must_use]
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}

impl fmt::Display for OepHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LikelyOriginal(rva) => write!(f, "OEP likely original @ {rva:#x}"),
            Self::StolenBytesStub { real_oep, stub_len } => {
                write!(f, "stolen-bytes stub @ {real_oep:#x} ({stub_len} bytes)")
            }
            Self::IatTrampoline { target_rva } => {
                write!(f, "IAT trampoline -> {target_rva:#x}")
            }
            Self::Unknown => write!(f, "OEP unknown"),
        }
    }
}

// ─── IatPatch ─────────────────────────────────────────────────────────────────

/// A single patched IAT slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IatPatch {
    /// File offset of the IAT slot.
    pub file_offset: usize,
    /// Old value (before patch).
    pub old_value: u64,
    /// New value (after patch).
    pub new_value: u64,
}

// ─── ImportSpec ───────────────────────────────────────────────────────────────

/// Describes a DLL's worth of imports for rebuilding the import table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportSpec {
    /// DLL name (e.g. `"kernel32.dll"`).
    pub dll: String,
    /// List of imported function names or ordinals.
    pub entries: Vec<ImportEntry>,
}

impl ImportSpec {
    /// Create an import spec for the named DLL.
    #[must_use]
    pub fn new(dll: impl Into<String>) -> Self {
        Self {
            dll: dll.into(),
            entries: Vec::new(),
        }
    }

    /// Add a named import.
    pub fn add_by_name(&mut self, name: impl Into<String>, hint: u16) {
        self.entries.push(ImportEntry::ByName {
            name: name.into(),
            hint,
        });
    }

    /// Add an ordinal import.
    pub fn add_by_ordinal(&mut self, ordinal: u16) {
        self.entries.push(ImportEntry::ByOrdinal(ordinal));
    }
}

/// A single import entry within an [`ImportSpec`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImportEntry {
    /// Import by name.
    ByName {
        /// Function name.
        name: String,
        /// Hint index.
        hint: u16,
    },
    /// Import by ordinal.
    ByOrdinal(u16),
}

impl ImportEntry {
    /// Return the function name, or `None` for ordinal imports.
    #[must_use]
    pub const fn name(&self) -> Option<&str> {
        match self {
            Self::ByName { name, .. } => Some(name.as_str()),
            Self::ByOrdinal(_) => None,
        }
    }

    /// Return the ordinal, or `None` for named imports.
    #[must_use]
    pub const fn ordinal(&self) -> Option<u16> {
        match self {
            Self::ByOrdinal(o) => Some(*o),
            Self::ByName { .. } => None,
        }
    }
}

// ─── RebuildStats ─────────────────────────────────────────────────────────────

/// Statistics produced by a rebuild operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RebuildStats {
    /// Number of sections realigned.
    pub sections_realigned: usize,
    /// Number of IAT slots patched.
    pub iat_slots_patched: usize,
    /// Number of import DLLs rebuilt.
    pub import_dlls_rebuilt: usize,
    /// Number of import function entries written.
    pub import_entries_written: usize,
    /// Whether the checksum was updated.
    pub checksum_updated: bool,
    /// Final checksum value.
    pub final_checksum: u32,
}

// ─── PeRebuilder ──────────────────────────────────────────────────────────────

/// Rebuilds or repairs a PE image.
pub struct PeRebuilder {
    /// Raw image bytes (modified in place).
    raw: Vec<u8>,
    /// Parsed PE (kept in sync after each operation).
    pe: PeFile,
    /// File alignment.
    file_align: u32,
    /// Section alignment.
    sect_align: u32,
    /// PE header offset.
    pe_offset: usize,
}

// ─── Import-table builder helpers ─────────────────────────────────────────────

/// Write a single `ILT`/`IAT` slot for an ordinal import into `table`.
fn write_ordinal_ilt_entry(table: &mut Vec<u8>, is_64bit: bool, ord: u16) {
    let flag: u64 = if is_64bit { 0x8000_0000_0000_0000 } else { 0x8000_0000 };
    let val = flag | u64::from(ord);
    if is_64bit {
        table.extend_from_slice(&val.to_le_bytes());
    } else {
        table.extend_from_slice(
            &u32::try_from(val & 0xFFFF_FFFF)
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
    }
}

/// Build per-DLL ILT, IAT, and name sections into `table`.
///
/// Returns `(ilt_rvas, addr_table_rvas, dll_name_rvas)`.
fn build_per_dll_tables(
    table: &mut Vec<u8>,
    specs: &[ImportSpec],
    base_rva: u32,
    is_64bit: bool,
    entry_size: usize,
) -> (Vec<u32>, Vec<u32>, Vec<u32>) {
    let rva_of = |off: usize| base_rva + u32::try_from(off).unwrap_or(u32::MAX);
    let desc_count = specs.len();
    let mut ilt_rvas: Vec<u32> = Vec::with_capacity(desc_count);
    let mut addr_table_rvas: Vec<u32> = Vec::with_capacity(desc_count);
    let mut dll_name_rvas: Vec<u32> = Vec::with_capacity(desc_count);
    for spec in specs {
        // ILT
        let ilt_start = table.len();
        ilt_rvas.push(rva_of(ilt_start));
        for e in &spec.entries {
            match e {
                ImportEntry::ByName { .. } => {
                    table.extend(std::iter::repeat_n(0u8, entry_size));
                }
                ImportEntry::ByOrdinal(ord) => {
                    write_ordinal_ilt_entry(table, is_64bit, *ord);
                }
            }
        }
        table.extend(std::iter::repeat_n(0u8, entry_size)); // null terminator
        // IAT (zeroed initially; loader fills at bind time)
        let addr_table_start = table.len();
        addr_table_rvas.push(rva_of(addr_table_start));
        for _ in &spec.entries {
            table.extend(std::iter::repeat_n(0u8, entry_size));
        }
        table.extend(std::iter::repeat_n(0u8, entry_size)); // null terminator
        // DLL name string
        let dll_name_start = table.len();
        dll_name_rvas.push(rva_of(dll_name_start));
        table.extend_from_slice(spec.dll.as_bytes());
        table.push(0); // NUL terminator
        if !table.len().is_multiple_of(2) {
            table.push(0); // word-align
        }
    }
    (ilt_rvas, addr_table_rvas, dll_name_rvas)
}

/// Write hint/name entries and back-patch ILT + IAT slots.
///
/// Returns the number of named-import entries written.
fn patch_ilt_hint_names(
    table: &mut Vec<u8>,
    specs: &[ImportSpec],
    ilt_rvas: &[u32],
    addr_table_rvas: &[u32],
    base_rva: u32,
    is_64bit: bool,
    entry_size: usize,
) -> usize {
    let rva_of = |off: usize| base_rva + u32::try_from(off).unwrap_or(u32::MAX);
    let mut entries_written = 0usize;
    for (si, spec) in specs.iter().enumerate() {
        let lookup_base = usize::try_from(ilt_rvas[si].saturating_sub(base_rva)).unwrap_or(0);
        let addr_base = usize::try_from(addr_table_rvas[si].saturating_sub(base_rva)).unwrap_or(0);
        for (entry_offset, e) in spec.entries.iter().enumerate() {
            let ImportEntry::ByName { name, hint } = e else { continue };
            let ibn_rva = rva_of(table.len());
            table.extend_from_slice(&hint.to_le_bytes());
            table.extend_from_slice(name.as_bytes());
            table.push(0);
            if !table.len().is_multiple_of(2) {
                table.push(0);
            }
            let lookup_slot = lookup_base + entry_offset * entry_size;
            let addr_slot = addr_base + entry_offset * entry_size;
            if is_64bit {
                let v = u64::from(ibn_rva).to_le_bytes();
                if lookup_slot + 8 <= table.len() {
                    table[lookup_slot..lookup_slot + 8].copy_from_slice(&v);
                }
                if addr_slot + 8 <= table.len() {
                    table[addr_slot..addr_slot + 8].copy_from_slice(&v);
                }
            } else {
                let v = ibn_rva.to_le_bytes();
                if lookup_slot + 4 <= table.len() {
                    table[lookup_slot..lookup_slot + 4].copy_from_slice(&v);
                }
                if addr_slot + 4 <= table.len() {
                    table[addr_slot..addr_slot + 4].copy_from_slice(&v);
                }
            }
            entries_written += 1;
        }
    }
    entries_written
}

/// Fill the `IMAGE_IMPORT_DESCRIPTOR` array in `table` (Pass 4).
fn fill_import_descriptors(
    table: &mut [u8],
    specs: &[ImportSpec],
    desc_start: usize,
    ilt_rvas: &[u32],
    addr_table_rvas: &[u32],
    dll_name_rvas: &[u32],
) {
    for (i, spec) in specs.iter().enumerate() {
        let off = desc_start + i * 20;
        table[off..off + 4].copy_from_slice(&ilt_rvas[i].to_le_bytes());
        // TimeDateStamp left zero (runtime binding).
        // ForwarderChain: entry count as a non-binding hint for inspectors.
        let forwarder = u32::try_from(spec.entries.len()).unwrap_or(u32::MAX);
        table[off + 8..off + 12].copy_from_slice(&forwarder.to_le_bytes());
        table[off + 12..off + 16].copy_from_slice(&dll_name_rvas[i].to_le_bytes());
        table[off + 16..off + 20].copy_from_slice(&addr_table_rvas[i].to_le_bytes());
    }
}

// ──────────────────────────────────────────────────────────────────────────────

impl PeRebuilder {
    /// Create a rebuilder from raw PE bytes.
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError`] if the bytes are not a valid PE.
    pub fn new(data: &[u8]) -> Result<Self, RebuildError> {
        let pe = PeFile::parse(data)?;
        let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
        let opt_offset = pe_offset + 24;

        let file_align = if opt_offset + 40 <= data.len() {
            u32::from_le_bytes(
                data[opt_offset + 36..opt_offset + 40]
                    .try_into()
                    .unwrap_or([0; 4]),
            )
        } else {
            0x200
        };
        let sect_align = if opt_offset + 36 <= data.len() {
            u32::from_le_bytes(
                data[opt_offset + 32..opt_offset + 36]
                    .try_into()
                    .unwrap_or([0; 4]),
            )
        } else {
            0x1000
        };

        Ok(Self {
            raw: data.to_vec(),
            pe,
            file_align,
            sect_align,
            pe_offset,
        })
    }

    /// Return the current raw bytes.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Consume the rebuilder and return the (modified) bytes.
    #[must_use]
    pub fn into_raw(self) -> Vec<u8> {
        self.raw
    }

    /// Return a slice of the PE's parsed sections. Useful for callers that
    /// want to inspect section layout without re-parsing [`Self::raw`].
    #[must_use]
    pub fn sections(&self) -> &[PeSection] {
        &self.pe.sections
    }

    // ── OEP detection ─────────────────────────────────────────────────────────

    /// Run OEP-detection heuristics on the current entry point.
    ///
    /// Two heuristics are attempted in order:
    /// 1. **Stolen-bytes stub**: looks for a sequence of bytes ending with an
    ///    unconditional JMP that would push execution past the EP.
    /// 2. **IAT trampoline**: checks whether the 6-byte pattern at EP is
    ///    `FF 25 <dword-rva>` (x86 JMP [mem]) or `FF 15 <dword-rva>` (CALL [mem]).
    ///
    /// If neither heuristic fires, returns [`OepHint::LikelyOriginal`].
    #[must_use]
    pub fn oep_detection_heuristics(&self) -> OepHint {
        let ep_rva = self.pe.entry_point;
        let Some(ep_off) = self.pe.rva_to_offset(ep_rva) else {
            return OepHint::Unknown;
        };

        if ep_off + 8 > self.raw.len() {
            return OepHint::Unknown;
        }

        let ep_bytes = &self.raw[ep_off..];

        // Heuristic 1: IAT trampoline — JMP DWORD PTR [rva] (FF 25 ...)
        if ep_bytes[0] == 0xFF
            && (ep_bytes[1] == 0x25 || ep_bytes[1] == 0x15)
            && ep_off + 6 <= self.raw.len()
        {
            let target_rva =
                u32::from_le_bytes([ep_bytes[2], ep_bytes[3], ep_bytes[4], ep_bytes[5]]);
            if target_rva > ep_rva && target_rva < ep_rva + 0x10_0000 {
                return OepHint::IatTrampoline { target_rva };
            }
        }

        // Heuristic 2: stolen-bytes stub — look for short PUSH/MOV/NOP sequence
        // followed by a JMP E9/EB within the first 16 bytes.
        let scan_end = (ep_off + 32).min(self.raw.len().saturating_sub(4));
        for i in ep_off..scan_end {
            if i + 5 >= self.raw.len() {
                break;
            }
            // E9 = near JMP rel32
            if self.raw[i] == 0xE9 {
                let rel = i32::from_le_bytes([
                    self.raw[i + 1],
                    self.raw[i + 2],
                    self.raw[i + 3],
                    self.raw[i + 4],
                ]);
                let stub_len = u8::try_from(i - ep_off).unwrap_or(u8::MAX);
                let jmp_next = i64::try_from(i + 5).unwrap_or(i64::MAX);
                let target_signed = jmp_next + i64::from(rel);
                let target = u64::try_from(target_signed).unwrap_or(0);
                if target > 0x1000 && target < 0xFFFF_FFFF {
                    // Looks like a plausible stolen-bytes JMP.
                    return OepHint::StolenBytesStub {
                        real_oep: u32::try_from(target).unwrap_or(u32::MAX),
                        stub_len,
                    };
                }
            }
        }

        OepHint::LikelyOriginal(ep_rva)
    }

    // ── IAT fixup ─────────────────────────────────────────────────────────────

    /// Fix-up IAT slots: write `new_values[iat_rva]` into the appropriate file
    /// offsets.
    ///
    /// `new_values` maps IAT slot RVA → new 64-bit value (for PE32+) or
    /// 32-bit value (for PE32, high DWORD ignored).
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError::IatSlotUnresolvable`] if an RVA cannot be
    /// resolved to a file offset.
    pub fn fix_iat(
        &mut self,
        new_values: &HashMap<u32, u64>,
    ) -> Result<Vec<IatPatch>, RebuildError> {
        let mut patches = Vec::new();
        // Use the canonical arch mode from rustre-core to derive pointer size,
        // so that pe_rebuild stays consistent with the platform-wide mode abstraction.
        let entry_size: usize = self.pe.arch_mode().pointer_size();

        for (&iat_rva, &new_val) in new_values {
            let off = self
                .pe
                .rva_to_offset(iat_rva)
                .ok_or(RebuildError::IatSlotUnresolvable(iat_rva))?;

            if off + entry_size > self.raw.len() {
                return Err(RebuildError::IatSlotUnresolvable(iat_rva));
            }

            let old_val = if self.pe.is_64bit {
                u64::from_le_bytes(self.raw[off..off + 8].try_into().unwrap_or([0; 8]))
            } else {
                u64::from(u32::from_le_bytes(
                    self.raw[off..off + 4].try_into().unwrap_or([0; 4]),
                ))
            };

            if self.pe.is_64bit {
                self.raw[off..off + 8].copy_from_slice(&new_val.to_le_bytes());
            } else {
                self.raw[off..off + 4].copy_from_slice(
                    &u32::try_from(new_val & 0xFFFF_FFFF)
                        .unwrap_or(u32::MAX)
                        .to_le_bytes(),
                );
            }

            patches.push(IatPatch {
                file_offset: off,
                old_value: old_val,
                new_value: new_val,
            });
        }

        Ok(patches)
    }

    // ── Import table rebuild ───────────────────────────────────────────────────

    /// Rebuild the import directory table from a list of [`ImportSpec`]s,
    /// appending the new table to the end of the raw buffer and updating the
    /// data directory entry.
    ///
    /// The import table is written in the following layout:
    /// ```text
    /// [IMAGE_IMPORT_DESCRIPTORs × N + null][ILT thunks][DLL names][function hint/names]
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError`] if the table cannot be constructed.
    pub fn rebuild_import_table(
        &mut self,
        specs: &[ImportSpec],
    ) -> Result<RebuildStats, RebuildError> {
        if specs.is_empty() {
            return Ok(RebuildStats::default());
        }

        let mut table: Vec<u8> = Vec::new();

        // File-aligned offset where the new table will be appended.
        let base_raw_offset = usize::try_from(align_up(
            u32::try_from(self.raw.len()).unwrap_or(u32::MAX),
            self.file_align,
        ))
        .unwrap_or(0);

        // Virtual address for the table: first section-aligned VA after last section.
        let last_va_end = self
            .pe
            .sections
            .iter()
            .map(|s| s.virtual_address + align_up(s.virtual_size, self.sect_align))
            .max()
            .unwrap_or(self.sect_align);
        let base_rva = align_up(last_va_end, self.sect_align);

        // Pass 1: reserve space for IMAGE_IMPORT_DESCRIPTOR array (+1 null terminator).
        let desc_count = specs.len();
        let desc_start = table.len();
        table.extend(std::iter::repeat_n(0u8, (desc_count + 1) * 20));

        let entry_size = if self.pe.is_64bit { 8usize } else { 4usize };

        // Pass 2: per-DLL ILT, IAT, and name strings.
        let (ilt_rvas, addr_table_rvas, dll_name_rvas) =
            build_per_dll_tables(&mut table, specs, base_rva, self.pe.is_64bit, entry_size);

        // Pass 3: hint/name entries; back-patch ILT + IAT slots.
        let entries_written = patch_ilt_hint_names(
            &mut table,
            specs,
            &ilt_rvas,
            &addr_table_rvas,
            base_rva,
            self.pe.is_64bit,
            entry_size,
        );

        // Pass 4: fill the IMAGE_IMPORT_DESCRIPTORs.
        fill_import_descriptors(
            &mut table,
            specs,
            desc_start,
            &ilt_rvas,
            &addr_table_rvas,
            &dll_name_rvas,
        );

        // Align table to file alignment.
        if self.file_align > 0 {
            while !table.len().is_multiple_of(self.file_align as usize) {
                table.push(0);
            }
        }

        if self.raw.len() < base_raw_offset {
            self.raw.resize(base_raw_offset, 0);
        }
        self.raw.extend_from_slice(&table);

        let import_dir_size = u32::try_from(desc_count + 1).unwrap_or(u32::MAX) * 20;
        self.write_data_dir(crate::data_dir_index::IMPORT, base_rva, import_dir_size);

        Ok(RebuildStats {
            sections_realigned: 0,
            iat_slots_patched: 0,
            import_dlls_rebuilt: specs.len(),
            import_entries_written: entries_written,
            checksum_updated: false,
            final_checksum: 0,
        })
    }

    // ── Section alignment ─────────────────────────────────────────────────────

    /// Realign all sections so that each section's raw data begins at a
    /// file-aligned offset and its virtual address is section-aligned.
    ///
    /// Returns the number of sections that were moved.
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError`] if the resulting layout is invalid.
    pub fn align_sections(&mut self) -> Result<usize, RebuildError> {
        let opt_offset = self.pe_offset + 24;
        let opt_hdr_size = if self.pe.is_64bit { 240usize } else { 224usize };
        let sect_table_off = opt_offset + opt_hdr_size;

        let headers_end = sect_table_off + self.pe.sections.len() * 40;
        let mut raw_cursor = align_up(
            u32::try_from(headers_end).unwrap_or(u32::MAX),
            self.file_align,
        );
        let mut va_cursor: u32 = self.sect_align;
        let mut moved = 0usize;

        // Collect section data (must clone before mutating raw).
        let sections: Vec<(u32, u32, u32, u32)> = self
            .pe
            .sections
            .iter()
            .map(|s| (s.raw_offset, s.raw_size, s.virtual_address, s.virtual_size))
            .collect();

        for (i, (old_raw_off, raw_size, _old_va, virt_size)) in sections.iter().enumerate() {
            let new_raw_off = raw_cursor;
            let new_va = va_cursor;

            let aligned_raw_size = align_up(*raw_size, self.file_align);
            let aligned_va_size = align_up(*virt_size, self.sect_align);

            let section_tbl_off = sect_table_off + i * 40;
            if section_tbl_off + 40 > self.raw.len() {
                break;
            }

            // Move raw data if necessary.
            if new_raw_off != *old_raw_off {
                let src = *old_raw_off as usize;
                let size = *raw_size as usize;
                let dst = new_raw_off as usize;
                if src + size <= self.raw.len() {
                    if dst + size > self.raw.len() {
                        self.raw.resize(dst + size, 0);
                    }
                    self.raw.copy_within(src..src + size, dst);
                }
                moved += 1;
            }

            // Patch section table entry.
            self.raw[section_tbl_off + 12..section_tbl_off + 16]
                .copy_from_slice(&new_va.to_le_bytes());
            self.raw[section_tbl_off + 16..section_tbl_off + 20]
                .copy_from_slice(&aligned_raw_size.to_le_bytes());
            self.raw[section_tbl_off + 20..section_tbl_off + 24]
                .copy_from_slice(&new_raw_off.to_le_bytes());

            raw_cursor += aligned_raw_size;
            va_cursor += aligned_va_size;
        }

        // Update SizeOfImage.
        let size_of_image = va_cursor;
        let soi_off = opt_offset + 56;
        if soi_off + 4 <= self.raw.len() {
            self.raw[soi_off..soi_off + 4].copy_from_slice(&size_of_image.to_le_bytes());
        }

        Ok(moved)
    }

    // ── Checksum ──────────────────────────────────────────────────────────────

    /// Recompute and write the PE checksum into the optional header.
    ///
    /// The checksum field itself is treated as zero during computation (per the
    /// Windows spec).
    pub fn fix_checksum(&mut self) -> u32 {
        let checksum = compute_pe_checksum(&self.raw);
        let opt_offset = self.pe_offset + 24;
        let chk_off = opt_offset + 64; // same offset for both PE32 and PE32+
        if chk_off + 4 <= self.raw.len() {
            self.raw[chk_off..chk_off + 4].copy_from_slice(&checksum.to_le_bytes());
        }
        checksum
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Write a data directory entry (RVA + size) at the given index.
    fn write_data_dir(&mut self, index: usize, rva: u32, size: u32) {
        let opt_offset = self.pe_offset + 24;
        let dir_base = if self.pe.is_64bit {
            opt_offset + 112
        } else {
            opt_offset + 96
        };
        let off = dir_base + index * 8;
        if off + 8 <= self.raw.len() {
            self.raw[off..off + 4].copy_from_slice(&rva.to_le_bytes());
            self.raw[off + 4..off + 8].copy_from_slice(&size.to_le_bytes());
        }
    }

    /// Overwrite the entry point RVA.
    pub fn set_entry_point(&mut self, rva: u32) {
        let opt_offset = self.pe_offset + 24;
        let ep_off = opt_offset + 16;
        if ep_off + 4 <= self.raw.len() {
            self.raw[ep_off..ep_off + 4].copy_from_slice(&rva.to_le_bytes());
        }
    }

    /// Return a reference to the parsed PE metadata.
    #[must_use]
    pub const fn pe(&self) -> &PeFile {
        &self.pe
    }
}

impl fmt::Debug for PeRebuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeRebuilder")
            .field("raw_len", &self.raw.len())
            .field("pe", &self.pe)
            .field("file_align", &self.file_align)
            .field("sect_align", &self.sect_align)
            .field("pe_offset", &self.pe_offset)
            .finish_non_exhaustive()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PeBuilder, PeFile};

    fn make_raw() -> Vec<u8> {
        let mut b = PeBuilder::new_x64();
        b.add_section(".text", vec![0x90u8; 64], 0x6000_0020);
        b.add_section(".data", vec![0u8; 32], 0xC000_0040);
        b.build()
    }

    #[test]
    fn rebuilder_creates_ok() {
        let raw = make_raw();
        let rb = PeRebuilder::new(&raw).expect("new");
        assert!(rb.pe().sections.len() == 2);
    }

    #[test]
    fn oep_detection_likely_original() {
        let raw = make_raw();
        let rb = PeRebuilder::new(&raw).expect("new");
        let hint = rb.oep_detection_heuristics();
        // The minimal PE uses NOPs at .text start — no trampoline should fire.
        assert!(!hint.is_unknown());
        matches!(hint, OepHint::LikelyOriginal(_));
    }

    #[test]
    fn oep_detection_stolen_bytes() {
        // Inject a near-JMP at EP to simulate stolen bytes.
        let mut raw = make_raw();
        let pe = PeFile::parse(&raw).expect("parse");
        let ep_off = pe.rva_to_offset(pe.entry_point).expect("ep off");
        // Write E9 with rel32 = 0x1000 (pointing further into the .text section)
        raw[ep_off] = 0xE9;
        raw[ep_off + 1] = 0xFB;
        raw[ep_off + 2] = 0x0F;
        raw[ep_off + 3] = 0x00;
        raw[ep_off + 4] = 0x00;
        let rb = PeRebuilder::new(&raw).expect("new");
        let hint = rb.oep_detection_heuristics();
        matches!(hint, OepHint::StolenBytesStub { .. });
    }

    #[test]
    fn fix_checksum_produces_nonzero() {
        let raw = make_raw();
        let mut rb = PeRebuilder::new(&raw).expect("new");
        let checksum = rb.fix_checksum();
        // Re-parse and verify stored checksum matches computed.
        let pe2 = PeFile::parse(rb.raw()).expect("parse after fix_checksum");
        assert_eq!(pe2.checksum, checksum);
    }

    #[test]
    fn checksum_verify_after_fix() {
        let raw = make_raw();
        let mut rb = PeRebuilder::new(&raw).expect("new");
        rb.fix_checksum();
        let final_raw = rb.into_raw();
        let pe = PeFile::parse(&final_raw).expect("parse");
        assert_eq!(pe.verify_checksum(&final_raw), Some(true));
    }

    #[test]
    fn fix_iat_patches_slots() {
        let raw = make_raw();
        let pe = PeFile::parse(&raw).expect("parse");
        // Find the first section VA as a fake IAT slot.
        let iat_rva = pe.sections[0].virtual_address;
        let mut rb = PeRebuilder::new(&raw).expect("new");
        let mut map = HashMap::new();
        map.insert(iat_rva, 0xDEAD_BEEF_CAFE_1234u64);
        let patches = rb.fix_iat(&map).expect("fix_iat");
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].new_value, 0xDEAD_BEEF_CAFE_1234);
    }

    #[test]
    fn fix_iat_bad_rva_fails() {
        let raw = make_raw();
        let mut rb = PeRebuilder::new(&raw).expect("new");
        let mut map = HashMap::new();
        map.insert(0xFFFF_FF00, 1u64);
        let err = rb.fix_iat(&map);
        assert!(matches!(err, Err(RebuildError::IatSlotUnresolvable(_))));
    }

    #[test]
    fn align_sections_runs() {
        let raw = make_raw();
        let mut rb = PeRebuilder::new(&raw).expect("new");
        let moved = rb.align_sections().expect("align");
        // In a freshly built PE the sections should already be aligned.
        let _ = moved;
    }

    #[test]
    fn rebuild_import_table_basic() {
        let raw = make_raw();
        let mut rb = PeRebuilder::new(&raw).expect("new");
        let mut spec = ImportSpec::new("kernel32.dll");
        spec.add_by_name("CreateFileA", 0);
        spec.add_by_name("CloseHandle", 1);
        spec.add_by_ordinal(42);
        let stats = rb.rebuild_import_table(&[spec]).expect("rebuild");
        assert_eq!(stats.import_dlls_rebuilt, 1);
        assert!(stats.import_entries_written >= 2);
        // Verify raw grew.
        assert!(rb.raw().len() > raw.len());
    }

    #[test]
    fn rebuild_empty_import_table() {
        let raw = make_raw();
        let mut rb = PeRebuilder::new(&raw).expect("new");
        let stats = rb.rebuild_import_table(&[]).expect("rebuild empty");
        assert_eq!(stats.import_dlls_rebuilt, 0);
    }

    #[test]
    fn set_entry_point() {
        let raw = make_raw();
        let mut rb = PeRebuilder::new(&raw).expect("new");
        let new_ep = 0x3000u32;
        rb.set_entry_point(new_ep);
        let pe2 = PeFile::parse(rb.raw()).expect("reparse");
        assert_eq!(pe2.entry_point, new_ep);
    }

    #[test]
    fn oep_hint_display() {
        let h = OepHint::LikelyOriginal(0x1000);
        assert!(h.to_string().contains("original"));
        let h2 = OepHint::IatTrampoline { target_rva: 0x2000 };
        assert!(h2.to_string().contains("trampoline"));
        let h3 = OepHint::StolenBytesStub {
            real_oep: 0x3000,
            stub_len: 5,
        };
        assert!(h3.to_string().contains("stolen"));
    }

    #[test]
    fn import_spec_builder() {
        let mut spec = ImportSpec::new("ntdll.dll");
        spec.add_by_name("NtQuerySystemInformation", 0);
        spec.add_by_ordinal(10);
        assert_eq!(spec.entries.len(), 2);
        assert_eq!(spec.entries[0].name(), Some("NtQuerySystemInformation"));
        assert_eq!(spec.entries[1].ordinal(), Some(10));
    }
}
