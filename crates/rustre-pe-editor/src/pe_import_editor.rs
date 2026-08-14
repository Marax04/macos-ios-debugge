//! `pe_import_editor` — PE import table editing.
//!
//! Add/remove/modify import descriptors, rename functions, rebuild the
//! complete Import Address Table (IAT) as a self-contained new section,
//! and insert forwarder stubs.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::EditError;

// ---------------------------------------------------------------------------
// ImportFunction
// ---------------------------------------------------------------------------

/// A single imported function entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportFunction {
    /// Ordinal hint (only used for named imports).
    pub hint: u16,
    /// Function name.  Empty for ordinal-only imports.
    pub name: String,
    /// Import ordinal (used when `name` is empty).
    pub ordinal: Option<u16>,
}

impl ImportFunction {
    /// Create a named import.
    #[must_use]
    pub fn named(name: impl Into<String>, hint: u16) -> Self {
        Self {
            hint,
            name: name.into(),
            ordinal: None,
        }
    }

    /// Create an ordinal import.
    #[must_use]
    pub const fn ordinal(ordinal: u16) -> Self {
        Self {
            hint: 0,
            name: String::new(),
            ordinal: Some(ordinal),
        }
    }

    /// Returns `true` if imported by name.
    #[must_use]
    pub const fn is_named(&self) -> bool {
        !self.name.is_empty()
    }

    /// Return a display string like `"DLL!FunctionName"` or `"DLL!#42"`.
    #[must_use]
    pub fn display_with_dll(&self, dll: &str) -> String {
        if self.is_named() {
            format!("{}!{}", dll, self.name)
        } else {
            format!("{}!#{}", dll, self.ordinal.unwrap_or(0))
        }
    }
}

impl fmt::Display for ImportFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_named() {
            write!(f, "{} (hint={})", self.name, self.hint)
        } else {
            write!(f, "#ord:{}", self.ordinal.unwrap_or(0))
        }
    }
}

// ---------------------------------------------------------------------------
// ImportDescriptor
// ---------------------------------------------------------------------------

/// A DLL import descriptor: one entry in the Import Directory Table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportDescriptor {
    /// DLL name (e.g. `"kernel32.dll"`).
    pub dll_name: String,
    /// Imported functions from this DLL.
    pub functions: Vec<ImportFunction>,
}

impl ImportDescriptor {
    /// Create a new descriptor with no imports.
    #[must_use]
    pub fn new(dll_name: impl Into<String>) -> Self {
        Self {
            dll_name: dll_name.into(),
            functions: Vec::new(),
        }
    }

    /// Add a named import.
    pub fn add_named(&mut self, name: impl Into<String>, hint: u16) {
        self.functions.push(ImportFunction::named(name, hint));
    }

    /// Add an ordinal import.
    pub fn add_ordinal(&mut self, ordinal: u16) {
        self.functions.push(ImportFunction::ordinal(ordinal));
    }

    /// Remove an import by name; returns `true` if found and removed.
    pub fn remove_named(&mut self, name: &str) -> bool {
        let before = self.functions.len();
        self.functions.retain(|f| f.name != name);
        self.functions.len() < before
    }

    /// Remove an import by ordinal; returns `true` if found and removed.
    pub fn remove_ordinal(&mut self, ordinal: u16) -> bool {
        let before = self.functions.len();
        self.functions.retain(|f| f.ordinal != Some(ordinal));
        self.functions.len() < before
    }

    /// Rename an imported function.  Returns `true` if found.
    pub fn rename_function(&mut self, old_name: &str, new_name: &str) -> bool {
        for f in &mut self.functions {
            if f.name == old_name {
                f.name = new_name.to_string();
                return true;
            }
        }
        false
    }

    /// Number of imported functions.
    #[must_use]
    pub const fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Returns `true` if this descriptor has no imports.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }
}

impl fmt::Display for ImportDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ImportDescriptor({}: {} funcs)", self.dll_name, self.functions.len())
    }
}

// ---------------------------------------------------------------------------
// IatSlot
// ---------------------------------------------------------------------------

/// A slot in the reconstructed IAT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IatSlot {
    /// DLL name.
    pub dll: String,
    /// Function name (empty for ordinal).
    pub function: String,
    /// Ordinal (if `function` is empty).
    pub ordinal: Option<u16>,
    /// Relative virtual address of this slot in the new import section.
    pub slot_rva: u32,
}

impl IatSlot {
    /// Returns a display identifier.
    #[must_use]
    pub fn identifier(&self) -> String {
        if self.function.is_empty() {
            format!("{}!#{}", self.dll, self.ordinal.unwrap_or(0))
        } else {
            format!("{}!{}", self.dll, self.function)
        }
    }
}

// ---------------------------------------------------------------------------
// IatBuildResult
// ---------------------------------------------------------------------------

/// Result of `ImportTableBuilder::build()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IatBuildResult {
    /// The raw bytes of the new import section (`.idata`-compatible).
    pub section_bytes: Vec<u8>,
    /// Base RVA to assign to the new section.
    pub suggested_section_rva: u32,
    /// Per-slot mapping of function → slot RVA.
    pub iat_slots: Vec<IatSlot>,
    /// Number of DLL descriptors encoded.
    pub descriptor_count: usize,
    /// Total number of thunk entries encoded.
    pub thunk_count: usize,
    /// RVA of the IAT region (`FirstThunk` array) inside the rebuilt section.
    pub iat_region_rva: u32,
    /// RVA of the hint/name table inside the rebuilt section.
    pub hint_name_region_rva: u32,
    /// RVA of the DLL name strings inside the rebuilt section.
    pub dll_name_region_rva: u32,
}

// ---------------------------------------------------------------------------
// ImportTableBuilder
// ---------------------------------------------------------------------------

/// Builds a new import table from a set of `ImportDescriptor`s.
///
/// The resulting byte blob can be injected into a PE as a new section and
/// the data-directory pointer updated.
#[derive(Debug, Default)]
pub struct ImportTableBuilder {
    descriptors: Vec<ImportDescriptor>,
    is_64bit: bool,
}

/// Pre-computed blob offsets used by [`fill_iat_blob`].
struct IatOffsets<'a> {
    orig_thunks: &'a [usize],
    first_thunks: &'a [usize],
    hint_names: &'a [Vec<usize>],
    dll_names: &'a [usize],
}

/// Fill a pre-allocated IAT blob with hint/name strings, thunks, and descriptor entries.
/// Returns the list of [`IatSlot`]s for the written thunks.
fn fill_iat_blob(
    blob: &mut [u8],
    base_rva: u32,
    is_64bit: bool,
    thunk_size: usize,
    descriptors: &[ImportDescriptor],
    offsets: &IatOffsets<'_>,
) -> Vec<IatSlot> {
    let (orig_thunk_offsets, first_thunk_offsets, hint_name_offsets, dll_name_offsets) =
        (offsets.orig_thunks, offsets.first_thunks, offsets.hint_names, offsets.dll_names);
    // Fill hint/name area.
    for (d_idx, desc) in descriptors.iter().enumerate() {
        for (f_idx, func) in desc.functions.iter().enumerate() {
            if func.is_named() {
                let off = hint_name_offsets[d_idx][f_idx];
                blob[off..off + 2].copy_from_slice(&func.hint.to_le_bytes());
                let name_bytes = func.name.as_bytes();
                blob[off + 2..off + 2 + name_bytes.len()].copy_from_slice(name_bytes);
            }
        }
    }
    // Fill DLL name strings.
    for (d_idx, desc) in descriptors.iter().enumerate() {
        let off = dll_name_offsets[d_idx];
        let bytes = desc.dll_name.as_bytes();
        blob[off..off + bytes.len()].copy_from_slice(bytes);
    }
    // Fill INT and IAT thunks.
    let mut iat_slots: Vec<IatSlot> = Vec::new();
    for (d_idx, desc) in descriptors.iter().enumerate() {
        let orig_thunk_off = orig_thunk_offsets[d_idx];
        let first_thunk_off = first_thunk_offsets[d_idx];
        for (f_idx, func) in desc.functions.iter().enumerate() {
            let thunk_val: u64 = if func.is_named() {
                u64::from(base_rva) + hint_name_offsets[d_idx][f_idx] as u64
            } else {
                let ord_flag: u64 = if is_64bit { 0x8000_0000_0000_0000 } else { 0x8000_0000 };
                ord_flag | u64::from(func.ordinal.unwrap_or(0))
            };
            let slot_orig_thunk = orig_thunk_off + f_idx * thunk_size;
            let slot_first_thunk = first_thunk_off + f_idx * thunk_size;
            if is_64bit {
                if slot_orig_thunk + 8 <= blob.len() { blob[slot_orig_thunk..slot_orig_thunk + 8].copy_from_slice(&thunk_val.to_le_bytes()); }
                if slot_first_thunk + 8 <= blob.len() { blob[slot_first_thunk..slot_first_thunk + 8].copy_from_slice(&thunk_val.to_le_bytes()); }
            } else {
                let val32 = u32::try_from(thunk_val).expect("32-bit thunk value fits in u32");
                if slot_orig_thunk + 4 <= blob.len() { blob[slot_orig_thunk..slot_orig_thunk + 4].copy_from_slice(&val32.to_le_bytes()); }
                if slot_first_thunk + 4 <= blob.len() { blob[slot_first_thunk..slot_first_thunk + 4].copy_from_slice(&val32.to_le_bytes()); }
            }
            iat_slots.push(IatSlot {
                dll: desc.dll_name.clone(),
                function: func.name.clone(),
                ordinal: func.ordinal,
                slot_rva: base_rva + u32::try_from(slot_first_thunk).expect("slot offset fits in u32"),
            });
        }
    }
    // Fill IMAGE_IMPORT_DESCRIPTORs.
    for (d_idx, _desc) in descriptors.iter().enumerate() {
        let desc_off = d_idx * 20;
        let orig_thunk_rva = base_rva + u32::try_from(orig_thunk_offsets[d_idx]).expect("orig thunk offset fits in u32");
        let first_thunk_rva = base_rva + u32::try_from(first_thunk_offsets[d_idx]).expect("first thunk offset fits in u32");
        let name_rva = base_rva + u32::try_from(dll_name_offsets[d_idx]).expect("dll name offset fits in u32");
        blob[desc_off..desc_off + 4].copy_from_slice(&orig_thunk_rva.to_le_bytes());
        blob[desc_off + 4..desc_off + 8].fill(0);
        blob[desc_off + 8..desc_off + 12].fill(0xFF);
        blob[desc_off + 12..desc_off + 16].copy_from_slice(&name_rva.to_le_bytes());
        blob[desc_off + 16..desc_off + 20].copy_from_slice(&first_thunk_rva.to_le_bytes());
    }
    iat_slots
}

impl ImportTableBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set 64-bit mode (thunks become 8-byte entries instead of 4-byte).
    #[must_use]
    pub const fn with_64bit(mut self, flag: bool) -> Self {
        self.is_64bit = flag;
        self
    }

    /// Add a descriptor.
    pub fn add_descriptor(&mut self, desc: ImportDescriptor) {
        self.descriptors.push(desc);
    }

    /// Remove a descriptor by DLL name (case-insensitive). Returns `true` if found.
    pub fn remove_descriptor(&mut self, dll_name: &str) -> bool {
        let before = self.descriptors.len();
        self.descriptors
            .retain(|d| !d.dll_name.eq_ignore_ascii_case(dll_name));
        self.descriptors.len() < before
    }

    /// Get mutable reference to a descriptor by DLL name.
    #[must_use]
    pub fn get_mut(&mut self, dll_name: &str) -> Option<&mut ImportDescriptor> {
        self.descriptors
            .iter_mut()
            .find(|d| d.dll_name.eq_ignore_ascii_case(dll_name))
    }

    /// Get or create a descriptor for `dll_name`.
    ///
    /// # Panics
    /// Panics if the newly-pushed descriptor cannot be retrieved (should never happen).
    pub fn ensure_descriptor(&mut self, dll_name: &str) -> &mut ImportDescriptor {
        if let Some(pos) = self
            .descriptors
            .iter()
            .position(|d| d.dll_name.eq_ignore_ascii_case(dll_name))
        {
            return &mut self.descriptors[pos];
        }
        self.descriptors.push(ImportDescriptor::new(dll_name));
        self.descriptors.last_mut().unwrap()
    }

    /// Number of descriptors.
    #[must_use]
    pub const fn descriptor_count(&self) -> usize {
        self.descriptors.len()
    }

    /// All descriptors (read-only view).
    #[must_use]
    pub fn descriptors(&self) -> &[ImportDescriptor] {
        &self.descriptors
    }

    /// Build the import section blob.
    ///
    /// Layout:
    /// 1. Import Directory Table (n+1 descriptors × 20 bytes, null-terminated).
    /// 2. INT (Import Name Table) thunks for each DLL.
    /// 3. IAT (same layout as INT, patched at load time).
    /// 4. Hint/Name entries (2-byte hint + NUL-terminated name).
    /// 5. DLL name strings.
    ///
    /// All RVAs within the blob are relative to `base_rva`.
    ///
    /// # Errors
    /// Returns `EditError::ImportError` if the descriptor list is empty.
    ///
    /// # Panics
    /// Panics if the total blob size exceeds `u32::MAX`.
    pub fn build(&self, base_rva: u32) -> Result<IatBuildResult, EditError> {
        if self.descriptors.is_empty() {
            return Err(EditError::ImportError(
                "no import descriptors to build".to_string(),
            ));
        }

        let thunk_size: usize = if self.is_64bit { 8 } else { 4 };
        let n_dlls = self.descriptors.len();

        // Step 1: Reserve space for IMAGE_IMPORT_DESCRIPTORs (20 bytes each) + null.
        let desc_table_size = (n_dlls + 1) * 20;

        // Step 2: Compute OriginalFirstThunk (INT) / FirstThunk (IAT) offsets for each DLL.
        // INT and IAT are laid out together; each function gets a thunk + null.
        let mut orig_thunk_offsets: Vec<usize> = Vec::with_capacity(n_dlls);
        let mut dll_func_counts: Vec<usize> = Vec::with_capacity(n_dlls);

        let mut cursor = desc_table_size;
        // INT thunks section:
        for desc in &self.descriptors {
            orig_thunk_offsets.push(cursor);
            let n = desc.functions.len() + 1; // +1 for null terminator
            dll_func_counts.push(n);
            cursor += n * thunk_size;
        }

        // IAT follows INT (same size).
        let iat_base = cursor;
        let mut first_thunk_offsets: Vec<usize> = Vec::with_capacity(n_dlls);
        for &n in &dll_func_counts {
            first_thunk_offsets.push(cursor);
            cursor += n * thunk_size;
        }

        // Step 3: Hint/Name entries.
        let mut hint_name_offsets: Vec<Vec<usize>> = Vec::with_capacity(n_dlls);
        let hint_name_base = cursor;
        let mut hint_name_map: HashMap<String, usize> = HashMap::new();
        for desc in &self.descriptors {
            let mut offsets = Vec::with_capacity(desc.functions.len());
            for func in &desc.functions {
                if func.is_named() {
                    let key = format!("{}-{}", func.hint, func.name);
                    let off = *hint_name_map.entry(key).or_insert_with(|| {
                        let o = cursor;
                        // 2-byte hint + name + NUL + optional pad.
                        cursor += 2 + func.name.len() + 1;
                        if !cursor.is_multiple_of(2) {
                            cursor += 1;
                        }
                        o
                    });
                    offsets.push(off);
                } else {
                    offsets.push(0); // placeholder for ordinal
                }
            }
            hint_name_offsets.push(offsets);
        }

        // Step 4: DLL name strings.
        let dll_name_base = cursor;
        let mut dll_name_offsets: Vec<usize> = Vec::with_capacity(n_dlls);
        let mut dll_name_dedup: HashMap<String, usize> = HashMap::new();
        for desc in &self.descriptors {
            let lo = desc.dll_name.to_ascii_lowercase();
            let off = *dll_name_dedup.entry(lo).or_insert_with(|| {
                let o = cursor;
                cursor += desc.dll_name.len() + 1;
                if !cursor.is_multiple_of(2) {
                    cursor += 1;
                }
                o
            });
            dll_name_offsets.push(off);
        }

        let total_size = cursor;
        let mut blob = vec![0u8; total_size];
        let iat_slots = fill_iat_blob(
            &mut blob, base_rva, self.is_64bit, thunk_size,
            &self.descriptors,
            &IatOffsets {
                orig_thunks: &orig_thunk_offsets,
                first_thunks: &first_thunk_offsets,
                hint_names: &hint_name_offsets,
                dll_names: &dll_name_offsets,
            },
        );
        let thunk_count: usize = self.descriptors.iter().map(|d| d.functions.len()).sum();
        Ok(IatBuildResult {
            section_bytes: blob,
            suggested_section_rva: base_rva,
            iat_slots,
            descriptor_count: n_dlls,
            thunk_count,
            iat_region_rva: base_rva + u32::try_from(iat_base).expect("iat base fits in u32"),
            hint_name_region_rva: base_rva + u32::try_from(hint_name_base).expect("hint name base fits in u32"),
            dll_name_region_rva: base_rva + u32::try_from(dll_name_base).expect("dll name base fits in u32"),
        })
    }
}

// ---------------------------------------------------------------------------
// PeImportEditor
// ---------------------------------------------------------------------------

/// High-level PE import editor.
///
/// Parses the existing import directory table (simplified), queues
/// additions/removals, and can rebuild the entire IAT blob.
#[derive(Debug)]
pub struct PeImportEditor {
    descriptors: BTreeMap<String, ImportDescriptor>,
    is_64bit: bool,
    next_hint: u16,
}

impl PeImportEditor {
    /// Create an empty editor for a 32-bit PE.
    #[must_use]
    pub const fn new_32bit() -> Self {
        Self {
            descriptors: BTreeMap::new(),
            is_64bit: false,
            next_hint: 0,
        }
    }

    /// Create an empty editor for a 64-bit PE.
    #[must_use]
    pub const fn new_64bit() -> Self {
        Self {
            descriptors: BTreeMap::new(),
            is_64bit: true,
            next_hint: 0,
        }
    }

    /// Add a new DLL descriptor (or get mutable reference if already present).
    pub fn ensure_dll(&mut self, dll_name: &str) -> &mut ImportDescriptor {
        let key = dll_name.to_ascii_lowercase();
        self.descriptors
            .entry(key)
            .or_insert_with(|| ImportDescriptor::new(dll_name))
    }

    /// Add a named import to a DLL (adding the DLL descriptor if needed).
    pub fn add_import(&mut self, dll: &str, function: &str) {
        let hint = self.next_hint;
        self.next_hint = self.next_hint.wrapping_add(1);
        self.ensure_dll(dll).add_named(function, hint);
    }

    /// Add an ordinal import to a DLL.
    pub fn add_ordinal_import(&mut self, dll: &str, ordinal: u16) {
        self.ensure_dll(dll).add_ordinal(ordinal);
    }

    /// Remove a named import from a DLL.  Returns `true` if found.
    pub fn remove_import(&mut self, dll: &str, function: &str) -> bool {
        let key = dll.to_ascii_lowercase();
        self.descriptors.get_mut(&key).is_some_and(|desc| desc.remove_named(function))
    }

    /// Remove all imports from a DLL (removes the descriptor entirely).
    pub fn remove_dll(&mut self, dll: &str) -> bool {
        let key = dll.to_ascii_lowercase();
        self.descriptors.remove(&key).is_some()
    }

    /// Rename an imported function within a DLL.
    pub fn rename_import(&mut self, dll: &str, old_name: &str, new_name: &str) -> bool {
        let key = dll.to_ascii_lowercase();
        self.descriptors.get_mut(&key).is_some_and(|desc| desc.rename_function(old_name, new_name))
    }

    /// Rename a DLL in the import directory.
    pub fn rename_dll(&mut self, old_dll: &str, new_dll: &str) -> bool {
        let old_key = old_dll.to_ascii_lowercase();
        if let Some(mut desc) = self.descriptors.remove(&old_key) {
            desc.dll_name = new_dll.to_string();
            let new_key = new_dll.to_ascii_lowercase();
            self.descriptors.insert(new_key, desc);
            true
        } else {
            false
        }
    }

    /// Number of DLL descriptors.
    #[must_use]
    pub fn dll_count(&self) -> usize {
        self.descriptors.len()
    }

    /// Total number of imported functions across all DLLs.
    #[must_use]
    pub fn total_import_count(&self) -> usize {
        self.descriptors.values().map(ImportDescriptor::function_count).sum()
    }

    /// Collect all descriptors as a sorted vec.
    #[must_use]
    pub fn all_descriptors(&self) -> Vec<&ImportDescriptor> {
        self.descriptors.values().collect()
    }

    /// Build the IAT section blob starting at `base_rva`.
    ///
    /// # Errors
    /// Returns `EditError::ImportError` if no descriptors are present.
    pub fn build_iat_section(&self, base_rva: u32) -> Result<IatBuildResult, EditError> {
        let mut builder = ImportTableBuilder::new().with_64bit(self.is_64bit);
        for desc in self.descriptors.values() {
            builder.add_descriptor(desc.clone());
        }
        builder.build(base_rva)
    }

    /// Check if `dll` (case-insensitive) is present.
    #[must_use]
    pub fn has_dll(&self, dll: &str) -> bool {
        self.descriptors.contains_key(&dll.to_ascii_lowercase())
    }

    /// Return all imported function names for a DLL.
    #[must_use]
    pub fn functions_for_dll(&self, dll: &str) -> Vec<String> {
        let key = dll.to_ascii_lowercase();
        self.descriptors
            .get(&key)
            .map(|d| d.functions.iter().map(|f| f.name.clone()).collect())
            .unwrap_or_default()
    }

    /// Remove DLLs that have zero imports (cleaning up after removes).
    pub fn purge_empty_dlls(&mut self) {
        self.descriptors.retain(|_, d| !d.is_empty());
    }

    /// Merge another editor's descriptors into this one.
    pub fn merge(&mut self, other: Self) {
        for (key, other_desc) in other.descriptors {
            let entry = self
                .descriptors
                .entry(key)
                .or_insert_with(|| ImportDescriptor::new(&other_desc.dll_name));
            for func in other_desc.functions {
                if !entry.functions.iter().any(|f| f.name == func.name && func.is_named()) {
                    entry.functions.push(func);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ImportPatchRecord
// ---------------------------------------------------------------------------

/// An import-level patch record for auditing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportPatchRecord {
    /// DLL name.
    pub dll: String,
    /// Old function name.
    pub old_name: String,
    /// New function name.
    pub new_name: String,
}

impl fmt::Display for ImportPatchRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "patch import {}!{} → {}",
            self.dll, self.old_name, self.new_name
        )
    }
}

// ---------------------------------------------------------------------------
// ImportRedirector
// ---------------------------------------------------------------------------

/// Redirect a set of imports from one DLL to another (e.g. API hooking stubs).
#[derive(Debug, Default)]
pub struct ImportRedirector {
    rules: Vec<(String, String, String, String)>, // (src_dll, src_fn, dst_dll, dst_fn)
}

impl ImportRedirector {
    /// Create an empty redirector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a redirection rule.
    pub fn redirect(
        &mut self,
        src_dll: impl Into<String>,
        src_fn: impl Into<String>,
        dst_dll: impl Into<String>,
        dst_fn: impl Into<String>,
    ) {
        self.rules.push((
            src_dll.into(),
            src_fn.into(),
            dst_dll.into(),
            dst_fn.into(),
        ));
    }

    /// Apply redirections to an `ImportTableBuilder`.
    ///
    /// For each rule: if `src_dll!src_fn` is present, remove it and add
    /// `dst_dll!dst_fn`.  Returns the number of rules applied.
    pub fn apply(&self, editor: &mut PeImportEditor) -> usize {
        let mut count = 0;
        for (src_dll, src_fn, dst_dll, dst_fn) in &self.rules {
            if editor.remove_import(src_dll, src_fn) {
                editor.add_import(dst_dll, dst_fn);
                count += 1;
            }
        }
        count
    }

    /// Number of redirect rules.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

// ---------------------------------------------------------------------------
// ImportSummary
// ---------------------------------------------------------------------------

/// Summary statistics about an import table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportSummary {
    /// Number of DLLs.
    pub dll_count: usize,
    /// Total named imports.
    pub named_imports: usize,
    /// Total ordinal imports.
    pub ordinal_imports: usize,
    /// DLLs that supply ≥ 1 import.
    pub dll_names: Vec<String>,
}

impl ImportSummary {
    /// Build a summary from an `ImportTableBuilder`.
    #[must_use]
    pub fn from_builder(builder: &ImportTableBuilder) -> Self {
        let mut named = 0usize;
        let mut ordinal = 0usize;
        let dll_names: Vec<String> = builder
            .descriptors()
            .iter()
            .map(|d| {
                for f in &d.functions {
                    if f.is_named() {
                        named += 1;
                    } else {
                        ordinal += 1;
                    }
                }
                d.dll_name.clone()
            })
            .collect();
        Self {
            dll_count: dll_names.len(),
            named_imports: named,
            ordinal_imports: ordinal,
            dll_names,
        }
    }

    /// Build from a `PeImportEditor`.
    #[must_use]
    pub fn from_editor(editor: &PeImportEditor) -> Self {
        let mut named = 0usize;
        let mut ordinal = 0usize;
        let dll_names: Vec<String> = editor
            .all_descriptors()
            .iter()
            .map(|d| {
                for f in &d.functions {
                    if f.is_named() {
                        named += 1;
                    } else {
                        ordinal += 1;
                    }
                }
                d.dll_name.clone()
            })
            .collect();
        Self {
            dll_count: dll_names.len(),
            named_imports: named,
            ordinal_imports: ordinal,
            dll_names,
        }
    }
}

impl fmt::Display for ImportSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Imports: {} DLLs, {} named, {} ordinal",
            self.dll_count, self.named_imports, self.ordinal_imports
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel32() -> ImportDescriptor {
        let mut d = ImportDescriptor::new("kernel32.dll");
        d.add_named("CreateFileA", 100);
        d.add_named("ReadFile", 200);
        d.add_ordinal(5);
        d
    }

    #[test]
    fn descriptor_counts() {
        let d = kernel32();
        assert_eq!(d.function_count(), 3);
        assert!(!d.is_empty());
    }

    #[test]
    fn descriptor_remove_named() {
        let mut d = kernel32();
        assert!(d.remove_named("ReadFile"));
        assert_eq!(d.function_count(), 2);
        assert!(!d.remove_named("NotPresent"));
    }

    #[test]
    fn descriptor_rename() {
        let mut d = kernel32();
        assert!(d.rename_function("ReadFile", "ReadFileEx"));
        assert!(d.functions.iter().any(|f| f.name == "ReadFileEx"));
    }

    #[test]
    fn descriptor_remove_ordinal() {
        let mut d = kernel32();
        assert!(d.remove_ordinal(5));
        assert_eq!(d.function_count(), 2);
    }

    #[test]
    fn import_function_display() {
        let f = ImportFunction::named("LoadLibraryA", 42);
        assert!(f.is_named());
        assert_eq!(f.display_with_dll("kernel32.dll"), "kernel32.dll!LoadLibraryA");
    }

    #[test]
    fn import_function_ordinal() {
        let f = ImportFunction::ordinal(7);
        assert!(!f.is_named());
        assert_eq!(f.display_with_dll("ntdll.dll"), "ntdll.dll!#7");
    }

    #[test]
    fn builder_empty_fails() {
        let builder = ImportTableBuilder::new();
        assert!(builder.build(0x2000).is_err());
    }

    #[test]
    fn builder_single_dll_32bit() {
        let mut builder = ImportTableBuilder::new().with_64bit(false);
        let mut d = ImportDescriptor::new("kernel32.dll");
        d.add_named("ExitProcess", 0);
        builder.add_descriptor(d);
        let result = builder.build(0x2000).unwrap();
        assert_eq!(result.descriptor_count, 1);
        assert_eq!(result.thunk_count, 1);
        assert!(!result.section_bytes.is_empty());
        // IAT slot should be populated.
        assert_eq!(result.iat_slots.len(), 1);
        assert_eq!(result.iat_slots[0].function, "ExitProcess");
    }

    #[test]
    fn builder_multiple_dlls() {
        let mut builder = ImportTableBuilder::new();
        let mut d1 = ImportDescriptor::new("kernel32.dll");
        d1.add_named("CreateFileA", 0);
        d1.add_named("CloseHandle", 1);
        let mut d2 = ImportDescriptor::new("user32.dll");
        d2.add_named("MessageBoxA", 0);
        builder.add_descriptor(d1);
        builder.add_descriptor(d2);
        let result = builder.build(0x4000).unwrap();
        assert_eq!(result.descriptor_count, 2);
        assert_eq!(result.thunk_count, 3);
    }

    #[test]
    fn editor_add_remove() {
        let mut editor = PeImportEditor::new_32bit();
        editor.add_import("kernel32.dll", "VirtualAlloc");
        editor.add_import("kernel32.dll", "VirtualFree");
        assert_eq!(editor.total_import_count(), 2);
        assert!(editor.remove_import("kernel32.dll", "VirtualFree"));
        assert_eq!(editor.total_import_count(), 1);
    }

    #[test]
    fn editor_remove_dll() {
        let mut editor = PeImportEditor::new_32bit();
        editor.add_import("ntdll.dll", "NtAllocateVirtualMemory");
        assert!(editor.has_dll("ntdll.dll"));
        assert!(editor.remove_dll("ntdll.dll"));
        assert!(!editor.has_dll("ntdll.dll"));
    }

    #[test]
    fn editor_rename_dll() {
        let mut editor = PeImportEditor::new_32bit();
        editor.add_import("kernel32.dll", "ExitProcess");
        assert!(editor.rename_dll("kernel32.dll", "kernel32_hook.dll"));
        assert!(editor.has_dll("kernel32_hook.dll"));
        assert!(!editor.has_dll("kernel32.dll"));
    }

    #[test]
    fn editor_build_iat() {
        let mut editor = PeImportEditor::new_32bit();
        editor.add_import("ntdll.dll", "NtQueryInformationProcess");
        let result = editor.build_iat_section(0x3000).unwrap();
        assert!(!result.section_bytes.is_empty());
        assert_eq!(result.iat_slots[0].dll, "ntdll.dll");
    }

    #[test]
    fn import_redirector_apply() {
        let mut editor = PeImportEditor::new_32bit();
        editor.add_import("kernel32.dll", "CreateFileA");
        let mut redir = ImportRedirector::new();
        redir.redirect("kernel32.dll", "CreateFileA", "myhook.dll", "MyCreateFileA");
        let count = redir.apply(&mut editor);
        assert_eq!(count, 1);
        assert!(editor.has_dll("myhook.dll"));
        assert!(!editor.functions_for_dll("kernel32.dll").contains(&"CreateFileA".to_string()));
    }

    #[test]
    fn import_summary_from_editor() {
        let mut editor = PeImportEditor::new_32bit();
        editor.add_import("k32.dll", "func1");
        editor.add_ordinal_import("k32.dll", 3);
        let summary = ImportSummary::from_editor(&editor);
        assert_eq!(summary.dll_count, 1);
        assert_eq!(summary.named_imports, 1);
        assert_eq!(summary.ordinal_imports, 1);
    }

    #[test]
    fn purge_empty_dlls() {
        let mut editor = PeImportEditor::new_32bit();
        editor.add_import("user32.dll", "MessageBoxA");
        editor.remove_import("user32.dll", "MessageBoxA");
        assert_eq!(editor.dll_count(), 1);
        editor.purge_empty_dlls();
        assert_eq!(editor.dll_count(), 0);
    }

    #[test]
    fn editor_merge() {
        let mut a = PeImportEditor::new_32bit();
        a.add_import("kernel32.dll", "FuncA");
        let mut b = PeImportEditor::new_32bit();
        b.add_import("kernel32.dll", "FuncB");
        b.add_import("ntdll.dll", "FuncC");
        a.merge(b);
        assert_eq!(a.total_import_count(), 3);
        assert!(a.has_dll("ntdll.dll"));
    }
}
