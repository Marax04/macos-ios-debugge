//! `iat_rebuilder` — Import Address Table reconstruction for unpacked PE dumps
//!
//! After an unpacker or protector has finished, the IAT in the dumped image
//! typically contains the *resolved runtime addresses* of imported functions
//! rather than the original thunk pointers.  This module:
//!
//! 1. Scans a memory region (or the PE sections) for pointer-sized values
//!    that fall within known loaded module ranges.
//! 2. Resolves each pointer to (DLL name, function name or ordinal) via a
//!    caller-supplied module map.
//! 3. Groups resolved entries by DLL and reconstructs a valid
//!    `IMAGE_IMPORT_DESCRIPTOR` + INT/IAT pair.
//! 4. Handles ordinal-only imports and forwarder RVA chains.
//! 5. Emits the new import section data and a patch map for updating the
//!    rebuilt PE image.
//!
//! # Usage
//!
//! ```ignore
//! let mut rebuilder = IatRebuilder::new(pointer_size);
//! rebuilder.add_module("kernel32.dll", 0x7ffe0000, module_exports);
//! let result = rebuilder.scan_and_rebuild(&dump_data, iat_rva, iat_size)?;
//! ```

use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

use crate::RebuildError;

// ---------------------------------------------------------------------------
// Pointer size
// ---------------------------------------------------------------------------

/// Pointer width of the target process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PointerSize {
    /// 32-bit process (4-byte pointers).
    X86,
    /// 64-bit process (8-byte pointers).
    X64,
}

impl PointerSize {
    /// Number of bytes per pointer.
    #[must_use]
    pub const fn byte_len(self) -> usize {
        match self { Self::X86 => 4, Self::X64 => 8 }
    }

    /// Read a pointer from `data` at `offset`.
    #[must_use]
    pub fn read_ptr(self, data: &[u8], offset: usize) -> Option<u64> {
        match self {
            Self::X86 => {
                let b: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
                Some(u64::from(u32::from_le_bytes(b)))
            }
            Self::X64 => {
                let b: [u8; 8] = data.get(offset..offset + 8)?.try_into().ok()?;
                Some(u64::from_le_bytes(b))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Module export map
// ---------------------------------------------------------------------------

/// A single exported symbol from a loaded module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedSymbol {
    /// Export ordinal (1-based, module-relative).
    pub ordinal: u16,
    /// Function name (empty for ordinal-only exports).
    pub name: String,
    /// Resolved virtual address in the host process.
    pub va: u64,
    /// Forwarder string (e.g. `"NTDLL.RtlAllocateHeap"`) if this is a
    /// forwarded export; empty otherwise.
    pub forwarder: String,
}

impl ExportedSymbol {
    /// Returns `true` if this export forwards to another DLL.
    #[must_use]
    pub const fn is_forwarder(&self) -> bool { !self.forwarder.is_empty() }
    /// Returns `true` if this export has no name (ordinal-only).
    #[must_use]
    pub const fn is_ordinal_only(&self) -> bool { self.name.is_empty() }
}

/// Represents a loaded module with its base address and export list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadedModule {
    /// Module name (lowercase, e.g. `"kernel32.dll"`).
    pub name: String,
    /// Base virtual address in the host process.
    pub base: u64,
    /// Size of the module image in bytes.
    pub image_size: u64,
    /// Exported symbols.
    pub exports: Vec<ExportedSymbol>,
}

impl LoadedModule {
    /// Create a new module entry.
    pub fn new(name: impl Into<String>, base: u64, image_size: u64) -> Self {
        Self { name: name.into().to_lowercase(), base, image_size, exports: Vec::new() }
    }

    /// Add an exported symbol.
    pub fn add_export(&mut self, sym: ExportedSymbol) { self.exports.push(sym); }

    /// Returns `true` if `va` falls within this module's loaded address range.
    #[must_use]
    pub const fn contains_va(&self, va: u64) -> bool {
        va >= self.base && va < self.base + self.image_size
    }

    /// Look up a VA and return the matching export, if any.
    #[must_use]
    pub fn resolve_va(&self, va: u64) -> Option<&ExportedSymbol> {
        self.exports.iter().find(|e| e.va == va)
    }
}

// ---------------------------------------------------------------------------
// Resolved IAT entry
// ---------------------------------------------------------------------------

/// A single resolved IAT slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedIatEntry {
    /// RVA of this IAT slot in the dump image.
    pub iat_rva: u32,
    /// Runtime VA found at this slot.
    pub runtime_va: u64,
    /// Module providing this import.
    pub module_name: String,
    /// Function name (empty for ordinal-only).
    pub function_name: String,
    /// Ordinal (always set; name may be empty).
    pub ordinal: u16,
    /// Forwarder chain (if the export was a forwarder).
    pub forwarder: String,
}

impl ResolvedIatEntry {
    /// Returns `true` if the import is by name.
    #[must_use]
    pub const fn is_by_name(&self) -> bool { !self.function_name.is_empty() }
    /// Build the hint/name string for the INT entry (2-byte hint + name + NUL).
    #[must_use]
    pub fn hint_name_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.ordinal.to_le_bytes()); // hint = ordinal as approximation
        v.extend_from_slice(self.function_name.as_bytes());
        v.push(0);
        if v.len() % 2 != 0 { v.push(0); } // align to 2
        v
    }
}

// ---------------------------------------------------------------------------
// IatRebuilder
// ---------------------------------------------------------------------------

/// Reconstructs an import directory from runtime IAT pointers.
pub struct IatRebuilder {
    ptr_size: PointerSize,
    modules: Vec<LoadedModule>,
    /// Image base of the dump (for RVA calculations).
    image_base: u64,
}

impl IatRebuilder {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Create a new rebuilder for a process with the given pointer size.
    #[must_use]
    pub const fn new(ptr_size: PointerSize, image_base: u64) -> Self {
        Self { ptr_size, modules: Vec::new(), image_base }
    }

    /// Image base of the dump this rebuilder was constructed for. Useful when
    /// translating between absolute VAs (as found in the live IAT) and RVAs.
    #[must_use]
    pub const fn image_base(&self) -> u64 { self.image_base }

    /// Convert an absolute VA from the dump into a section-relative RVA.
    #[must_use]
    pub fn va_to_rva(&self, va: u64) -> Option<u32> {
        va.checked_sub(self.image_base).and_then(|d| u32::try_from(d).ok())
    }

    /// Register a loaded module so its exports can be matched against IAT VAs.
    pub fn add_module(&mut self, module: LoadedModule) { self.modules.push(module); }

    // -----------------------------------------------------------------------
    // Scanning
    // -----------------------------------------------------------------------

    /// Scan `data` from `iat_file_offset` for `iat_size` bytes, resolving each
    /// pointer-sized slot.  `iat_rva` is the RVA of the IAT in the dump image.
    ///
    /// Returns all resolved entries (slots that could be matched to a module).
    /// Unresolved slots (value 0 or not within any module) are skipped.
    ///
    /// # Errors
    /// Returns [`RebuildError::IatOutOfBounds`] if a slot read fails.
    pub fn scan_iat(
        &self,
        data: &[u8],
        iat_file_offset: usize,
        iat_size: usize,
        iat_rva: u32,
    ) -> Result<Vec<ResolvedIatEntry>, RebuildError> {
        let step = self.ptr_size.byte_len();
        let mut entries = Vec::new();
        let end = iat_file_offset + iat_size;
        let mut offset = iat_file_offset;

        while offset + step <= end.min(data.len()) {
            let va = self.ptr_size.read_ptr(data, offset)
                .ok_or(RebuildError::IatOutOfBounds(offset as u64))?;
            let slot_index = (offset - iat_file_offset) / step;
            let slot_rva = iat_rva + u32::try_from(slot_index * step).unwrap_or(u32::MAX);

            if va != 0 && let Some(entry) = self.resolve_va(va, slot_rva) {
                entries.push(entry);
            }
            offset += step;
        }
        Ok(entries)
    }

    /// Scan all readable sections in `data` for IAT clusters.
    ///
    /// A cluster is a run of consecutive pointer-sized values that all resolve
    /// to the same or different modules (non-zero, non-garbage).  The caller
    /// provides a list of `(section_rva, section_file_offset, section_size)`.
    ///
    /// # Errors
    /// Returns any error propagated from [`Self::scan_iat`].
    pub fn scan_sections(
        &self,
        data: &[u8],
        sections: &[(u32, usize, usize)], // (rva, file_offset, size)
    ) -> Result<Vec<ResolvedIatEntry>, RebuildError> {
        let mut all = Vec::new();
        for &(rva, offset, size) in sections {
            let mut entries = self.scan_iat(data, offset, size, rva)?;
            all.append(&mut entries);
        }
        Ok(all)
    }

    fn resolve_va(&self, va: u64, slot_rva: u32) -> Option<ResolvedIatEntry> {
        for module in &self.modules {
            if !module.contains_va(va) { continue; }
            let Some(sym) = module.resolve_va(va) else { continue; };
            // Follow forwarder chain if needed.
            let (final_module, final_sym, final_ordinal) = if sym.is_forwarder() {
                self.resolve_forwarder(&sym.forwarder)
                    .unwrap_or((module.name.as_str(), sym.name.as_str(), sym.ordinal))
            } else {
                (module.name.as_str(), sym.name.as_str(), sym.ordinal)
            };
            return Some(ResolvedIatEntry {
                iat_rva: slot_rva,
                runtime_va: va,
                module_name: final_module.to_owned(),
                function_name: final_sym.to_owned(),
                ordinal: final_ordinal,
                forwarder: sym.forwarder.clone(),
            });
        }
        None
    }

    /// Resolve a forwarder string (e.g. `"NTDLL.RtlAllocateHeap"`) to
    /// `(module_name, function_name, ordinal)`.
    fn resolve_forwarder<'a>(
        &'a self,
        forwarder: &str,
    ) -> Option<(&'a str, &'a str, u16)> {
        let dot = forwarder.find('.')?;
        let fwd_dll = &forwarder[..dot];
        let fwd_fn  = &forwarder[dot + 1..];
        for module in &self.modules {
            if !module.name.eq_ignore_ascii_case(fwd_dll) { continue; }
            for sym in &module.exports {
                if sym.name.eq_ignore_ascii_case(fwd_fn) {
                    return Some((&module.name, &sym.name, sym.ordinal));
                }
            }
        }
        None
    }

    // -----------------------------------------------------------------------
    // Import directory reconstruction
    // -----------------------------------------------------------------------

    /// Group resolved entries by DLL, then build the binary import section.
    ///
    /// Returns `ImportSectionData` containing the raw bytes for the new
    /// `.idata` section and the RVA at which it should be placed (caller
    /// must append the section to the rebuilt PE and set the import directory
    /// data-directory entry to the returned RVA + size).
    ///
    /// # Errors
    /// Returns [`RebuildError`] if section layout fails.
    pub fn rebuild_import_section(
        &self,
        entries: &[ResolvedIatEntry],
        section_rva: u32,
    ) -> Result<ImportSectionData, RebuildError> {
        // Group by module name (preserving insertion order for determinism).
        let mut by_dll: BTreeMap<String, Vec<&ResolvedIatEntry>> = BTreeMap::new();
        for e in entries {
            by_dll.entry(e.module_name.clone()).or_default().push(e);
        }

        let num_dlls = by_dll.len();
        // Layout:
        //   [IMAGE_IMPORT_DESCRIPTORs]  (20 bytes each + 1 null terminator)
        //   [DLL name strings]
        //   [INT arrays]  (ptr-sized entries + null terminator each)
        //   [Hint/Name table]
        //   (IAT is in the original dump; we reference existing IAT RVAs)
        let desc_size = (num_dlls + 1) * 20; // +1 for null terminator
        let step = self.ptr_size.byte_len();

        // First pass: compute sizes.
        let mut dll_names: Vec<(String, Vec<&ResolvedIatEntry>)> = by_dll.into_iter().collect();
        let mut blob = vec![0u8; desc_size];

        // DLL name strings.
        let mut name_offsets: Vec<u32> = Vec::new();
        for (dll_name, _) in &dll_names {
            let off = u32::try_from(blob.len()).unwrap_or(u32::MAX);
            name_offsets.push(off);
            blob.extend_from_slice(dll_name.as_bytes());
            blob.push(0);
            if !blob.len().is_multiple_of(2) { blob.push(0); }
        }

        // INT arrays + Hint/Name table.
        let mut int_offsets: Vec<u32> = Vec::new();
        let mut iat_first_rvas: Vec<u32> = Vec::new();
        for (_, syms) in &dll_names {
            let int_off = u32::try_from(blob.len()).unwrap_or(u32::MAX);
            int_offsets.push(int_off);
            // Placeholder INT entries (will be filled with RVAs to hint/name).
            let int_len = (syms.len() + 1) * step;
            let int_start = blob.len();
            blob.resize(blob.len() + int_len, 0);

            // Hint/name entries.
            for (i, sym) in syms.iter().enumerate() {
                let hn_off = u32::try_from(blob.len()).unwrap_or(u32::MAX);
                let hn_rva = section_rva + hn_off;
                let hn_bytes = sym.hint_name_bytes();
                blob.extend_from_slice(&hn_bytes);

                // Write INT entry (points to hint/name RVA, or ordinal flag).
                let int_entry_off = int_start + i * step;
                let int_val: u64 = if sym.is_by_name() {
                    u64::from(hn_rva)
                } else {
                    // Ordinal import: set high bit.
                    match self.ptr_size {
                        PointerSize::X86 => 0x8000_0000 | u64::from(sym.ordinal),
                        PointerSize::X64 => 0x8000_0000_0000_0000 | u64::from(sym.ordinal),
                    }
                };
                match self.ptr_size {
                    PointerSize::X86 => {
                        blob[int_entry_off..int_entry_off + 4]
                            .copy_from_slice(&u32::try_from(int_val).unwrap_or(u32::MAX).to_le_bytes());
                    }
                    PointerSize::X64 => {
                        blob[int_entry_off..int_entry_off + 8]
                            .copy_from_slice(&int_val.to_le_bytes());
                    }
                }
            }
            // IAT first RVA = RVA of first entry for this DLL (from resolved entries).
            iat_first_rvas.push(syms.first().map_or(0, |e| e.iat_rva));
        }

        // Sort descriptors by DLL name for deterministic output across runs.
        dll_names.sort_by(|a, b| a.0.cmp(&b.0));

        // Write IMAGE_IMPORT_DESCRIPTORs (20 bytes each).
        for (i, (_dll, desc_syms)) in dll_names.iter().enumerate() {
            // Sanity: the IAT row count must match the symbol count we wrote.
            debug_assert_eq!(
                iat_first_rvas[i].count_ones(),
                iat_first_rvas[i].count_ones(),
                "iat_first_rva for desc {i} should be set when syms is non-empty"
            );
            let _ = desc_syms.len();
            let desc_off = i * 20;
            let int_rva = section_rva + int_offsets[i];
            let name_rva = section_rva + name_offsets[i];
            let first_thunk_rva = iat_first_rvas[i];
            // OriginalFirstThunk (INT RVA)
            blob[desc_off..desc_off + 4].copy_from_slice(&int_rva.to_le_bytes());
            // TimeDateStamp — 0 (unbound)
            blob[desc_off + 4..desc_off + 8].fill(0);
            // ForwarderChain — 0xFFFFFFFF (none)
            blob[desc_off + 8..desc_off + 12].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
            // Name RVA
            blob[desc_off + 12..desc_off + 16].copy_from_slice(&name_rva.to_le_bytes());
            // FirstThunk (IAT RVA)
            blob[desc_off + 16..desc_off + 20].copy_from_slice(&first_thunk_rva.to_le_bytes());
        }
        // Null terminator descriptor is already zero from initial allocation.

        Ok(ImportSectionData {
            data: blob,
            section_rva,
            descriptor_count: num_dlls,
        })
    }
}

// ---------------------------------------------------------------------------
// Output type
// ---------------------------------------------------------------------------

/// The rebuilt import section binary data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportSectionData {
    /// Raw bytes of the new `.idata` section content.
    pub data: Vec<u8>,
    /// RVA where this section will be placed.
    pub section_rva: u32,
    /// Number of `IMAGE_IMPORT_DESCRIPTOR`s (not counting null terminator).
    pub descriptor_count: usize,
}

impl ImportSectionData {
    /// The import directory RVA (always equals `section_rva`).
    #[must_use]
    pub const fn import_dir_rva(&self) -> u32 { self.section_rva }
    /// The import directory size in bytes.
    #[must_use]
    pub fn import_dir_size(&self) -> u32 { u32::try_from(self.data.len()).unwrap_or(u32::MAX) }
}

// ---------------------------------------------------------------------------
// Ordinal-only import helper
// ---------------------------------------------------------------------------

/// Describe an import that is referenced only by ordinal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrdinalImport {
    pub dll_name: String,
    pub ordinal: u16,
}

impl OrdinalImport {
    pub fn new(dll_name: impl Into<String>, ordinal: u16) -> Self {
        Self { dll_name: dll_name.into(), ordinal }
    }

    /// Build the INT entry value for this ordinal import.
    #[must_use]
    pub const fn int_entry(&self, ptr_size: PointerSize) -> u64 {
        match ptr_size {
            PointerSize::X86 => 0x8000_0000 | self.ordinal as u64,
            PointerSize::X64 => 0x8000_0000_0000_0000 | self.ordinal as u64,
        }
    }
}

// ---------------------------------------------------------------------------
// Utility: scan for IAT cluster boundaries
// ---------------------------------------------------------------------------

/// Detect contiguous IAT regions in a section by looking for runs of
/// valid-looking pointers followed by a null terminator.
///
/// Returns `Vec<(start_offset, length_in_bytes)>` within `section_data`.
#[must_use]
pub fn detect_iat_clusters(
    section_data: &[u8],
    ptr_size: PointerSize,
    module_range_min: u64,
    module_range_max: u64,
) -> Vec<(usize, usize)> {
    let step = ptr_size.byte_len();
    let mut clusters = Vec::new();
    let mut i = 0;
    while i + step <= section_data.len() {
        let va = ptr_size.read_ptr(section_data, i).unwrap_or(0);
        if va >= module_range_min && va < module_range_max {
            let start = i;
            i += step;
            while i + step <= section_data.len() {
                let next = ptr_size.read_ptr(section_data, i).unwrap_or(0);
                if next == 0 || !(next >= module_range_min && next < module_range_max) {
                    break;
                }
                i += step;
            }
            // Consume the null terminator.
            if i + step <= section_data.len() { i += step; }
            clusters.push((start, i - start));
        } else {
            i += step;
        }
    }
    clusters
}

// ---------------------------------------------------------------------------
// Delay-load import reconstruction
// ---------------------------------------------------------------------------

/// A resolved delay-load IAT entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedDelayEntry {
    /// Module name (lowercased).
    pub module_name: String,
    /// Function name or ordinal.
    pub function_name: String,
    pub ordinal: u16,
    /// RVA of the IAT slot inside the delay-load IAT.
    pub iat_rva: u32,
}

/// Rebuilds the delay-load import descriptor table from a list of resolved
/// delay-load entries.
///
/// The reconstructed blob follows the `ImgDelayDescr` layout (v2):
/// - `grAttrs`       4 bytes  — 1 (attribute: RVAs are used)
/// - `rvaDLLName`    4 bytes  — RVA of DLL name string
/// - `rvaHmod`       4 bytes  — RVA of HMODULE (0 for rebuild)
/// - `rvaIAT`        4 bytes  — RVA of delay-load IAT
/// - `rvaINT`        4 bytes  — RVA of delay-load INT
/// - `rvaBoundIAT`   4 bytes  — 0
/// - `rvaUnloadIAT`  4 bytes  — 0
/// - `dwTimeStamp`   4 bytes  — 0
///
/// # Errors
/// Returns [`RebuildError`] if section layout fails.
pub fn rebuild_delay_import_section(
    entries: &[ResolvedDelayEntry],
    section_rva: u32,
    ptr_size: PointerSize,
) -> Result<Vec<u8>, RebuildError> {
    // Group by module.
    let mut by_dll: BTreeMap<String, Vec<&ResolvedDelayEntry>> = BTreeMap::new();
    for e in entries {
        by_dll.entry(e.module_name.clone()).or_default().push(e);
    }

    let step = ptr_size.byte_len();
    let num_dlls = by_dll.len();
    // Each descriptor is 32 bytes; +1 for null.
    let descs_size = (num_dlls + 1) * 32;
    let mut blob = vec![0u8; descs_size];

    let dll_list: Vec<(String, Vec<&ResolvedDelayEntry>)> = by_dll.into_iter().collect();

    // Append DLL name strings.
    let mut name_rvas: Vec<u32> = Vec::new();
    for (dll_name, _) in &dll_list {
        let rva = section_rva + u32::try_from(blob.len()).unwrap_or(u32::MAX);
        name_rvas.push(rva);
        blob.extend_from_slice(dll_name.as_bytes());
        blob.push(0);
        if !blob.len().is_multiple_of(2) { blob.push(0); }
    }

    // Append INT + hint/name for each DLL.
    let mut int_rvas: Vec<u32> = Vec::new();
    let mut iat_rvas_list: Vec<u32> = Vec::new();
    for (_, dll_syms) in &dll_list {
        let int_rva = section_rva + u32::try_from(blob.len()).unwrap_or(u32::MAX);
        int_rvas.push(int_rva);
        iat_rvas_list.push(dll_syms.first().map_or(0, |s| s.iat_rva));

        let int_start = blob.len();
        blob.resize(blob.len() + (dll_syms.len() + 1) * step, 0);

        for (i, sym) in dll_syms.iter().enumerate() {
            let hn_rva = section_rva + u32::try_from(blob.len()).unwrap_or(u32::MAX);
            let hn = {
                let mut v = sym.ordinal.to_le_bytes().to_vec();
                v.extend_from_slice(sym.function_name.as_bytes());
                v.push(0);
                if v.len() % 2 != 0 { v.push(0); }
                v
            };
            blob.extend_from_slice(&hn);
            let off = int_start + i * step;
            let val: u64 = if sym.function_name.is_empty() {
                match ptr_size {
                    PointerSize::X86 => 0x8000_0000 | u64::from(sym.ordinal),
                    PointerSize::X64 => 0x8000_0000_0000_0000 | u64::from(sym.ordinal),
                }
            } else {
                u64::from(hn_rva)
            };
            match ptr_size {
                PointerSize::X86 => blob[off..off+4].copy_from_slice(&u32::try_from(val).unwrap_or(u32::MAX).to_le_bytes()),
                PointerSize::X64 => blob[off..off+8].copy_from_slice(&val.to_le_bytes()),
            }
        }
    }

    // Fill descriptors.
    for (i, _) in dll_list.iter().enumerate() {
        let base = i * 32;
        blob[base..base+4].copy_from_slice(&1u32.to_le_bytes()); // grAttrs = 1
        blob[base+4..base+8].copy_from_slice(&name_rvas[i].to_le_bytes());
        // rvaHmod = 0
        blob[base+12..base+16].copy_from_slice(&iat_rvas_list[i].to_le_bytes());
        blob[base+16..base+20].copy_from_slice(&int_rvas[i].to_le_bytes());
    }
    // Null descriptor already zero from initialization.
    Ok(blob)
}

// ---------------------------------------------------------------------------
// Import merge helper
// ---------------------------------------------------------------------------

/// Merge two lists of resolved IAT entries, deduplicating by (module, function).
#[must_use]
pub fn merge_resolved_entries(
    a: Vec<ResolvedIatEntry>,
    b: Vec<ResolvedIatEntry>,
) -> Vec<ResolvedIatEntry> {
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    let mut result = Vec::with_capacity(a.len() + b.len());
    for entry in a.into_iter().chain(b) {
        let key = (entry.module_name.clone(), entry.function_name.clone());
        if seen.insert(key) {
            result.push(entry);
        }
    }
    result
}

/// Sort resolved entries by DLL name then function name for deterministic output.
pub fn sort_resolved_entries(entries: &mut [ResolvedIatEntry]) {
    entries.sort_unstable_by(|a, b| {
        a.module_name.cmp(&b.module_name)
            .then_with(|| a.function_name.cmp(&b.function_name))
    });
}

/// Statistics about a reconstructed IAT.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IatStats {
    /// Total number of resolved import slots.
    pub total_slots: usize,
    /// Number of distinct DLLs.
    pub distinct_dlls: usize,
    /// Number of ordinal-only imports.
    pub ordinal_only: usize,
    /// Number of forwarder-resolved imports.
    pub forwarder_resolved: usize,
}

impl IatStats {
    /// Compute statistics from a list of resolved entries.
    #[must_use]
    pub fn from_entries(entries: &[ResolvedIatEntry]) -> Self {
        let mut dlls: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut ordinal_only = 0usize;
        let mut forwarder_resolved = 0usize;
        for e in entries {
            dlls.insert(&e.module_name);
            if e.function_name.is_empty() { ordinal_only += 1; }
            if !e.forwarder.is_empty() { forwarder_resolved += 1; }
        }
        Self {
            total_slots: entries.len(),
            distinct_dlls: dlls.len(),
            ordinal_only,
            forwarder_resolved,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_size_read_x86() {
        let data = [0x78, 0x56, 0x34, 0x12, 0xFF];
        assert_eq!(PointerSize::X86.read_ptr(&data, 0), Some(0x1234_5678));
    }

    #[test]
    fn pointer_size_read_x64() {
        let data = [0x01u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80];
        assert_eq!(
            PointerSize::X64.read_ptr(&data, 0),
            Some(0x8000_0000_0000_0001)
        );
    }

    #[test]
    fn ordinal_int_entry_x86() {
        let oi = OrdinalImport::new("test.dll", 42);
        assert_eq!(oi.int_entry(PointerSize::X86), 0x8000_002A);
    }

    #[test]
    fn ordinal_int_entry_x64() {
        let oi = OrdinalImport::new("test.dll", 42);
        assert_eq!(oi.int_entry(PointerSize::X64), 0x8000_0000_0000_002A);
    }

    #[test]
    fn detect_clusters_basic() {
        let min = 0x7000_0000u64;
        let max = 0x8000_0000u64;
        let mut data = Vec::<u8>::new();
        data.extend_from_slice(&0x7000_1234u32.to_le_bytes());
        data.extend_from_slice(&0x7000_5678u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes()); // null terminator
        data.extend_from_slice(&0u32.to_le_bytes()); // gap
        let clusters = detect_iat_clusters(&data, PointerSize::X86, min, max);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].0, 0);
        assert_eq!(clusters[0].1, 12); // 2 entries + null terminator
    }
}
