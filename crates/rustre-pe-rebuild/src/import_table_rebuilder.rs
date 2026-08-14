//! Rebuild the import table: scan code for indirect call/jmp patterns,
//! extract IAT addresses, resolve API names, reconstruct `IMAGE_IMPORT_DESCRIPTOR`.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// IatEntry — a single slot in the Import Address Table
// ─────────────────────────────────────────────────────────────────────────────

/// A single resolved IAT entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IatEntry {
    /// File offset (or RVA) of the IAT slot within the PE image.
    pub iat_rva: u32,
    /// Runtime virtual address stored in the slot (0 if unknown).
    pub runtime_va: u64,
    /// DLL name (lowercase, with extension).
    pub dll_name: String,
    /// Function name (empty if imported by ordinal).
    pub function_name: String,
    /// Ordinal number (0 if imported by name).
    pub ordinal: u16,
    /// Confidence that this entry is correctly resolved (0–100).
    pub confidence: u8,
}

impl IatEntry {
    /// Create a named IAT entry.
    #[must_use]
    pub const fn named(iat_rva: u32, dll_name: String, function_name: String) -> Self {
        Self {
            iat_rva,
            runtime_va: 0,
            dll_name,
            function_name,
            ordinal: 0,
            confidence: 80,
        }
    }

    /// Create an ordinal IAT entry.
    #[must_use]
    pub const fn by_ordinal(iat_rva: u32, dll_name: String, ordinal: u16) -> Self {
        Self {
            iat_rva,
            runtime_va: 0,
            dll_name,
            function_name: String::new(),
            ordinal,
            confidence: 70,
        }
    }

    /// Returns `true` if this entry has a function name.
    #[must_use]
    pub const fn has_name(&self) -> bool {
        !self.function_name.is_empty()
    }

    /// Returns a human-readable import description.
    #[must_use]
    pub fn description(&self) -> String {
        if self.has_name() {
            format!("{}!{}", self.dll_name, self.function_name)
        } else if self.ordinal != 0 {
            format!("{}!#{}", self.dll_name, self.ordinal)
        } else {
            format!("{}!<unknown>", self.dll_name)
        }
    }
}

impl fmt::Display for IatEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IAT[{:#x}] -> {}", self.iat_rva, self.description())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ImportHint — an indirect call site hinting at an IAT slot
// ─────────────────────────────────────────────────────────────────────────────

/// An indirect call or jump site that references an IAT slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportHint {
    /// Virtual address of the call/jmp instruction.
    pub insn_addr: u64,
    /// The IAT RVA referenced by this instruction.
    pub iat_rva: u32,
    /// Whether this is a call (true) or jump (false).
    pub is_call: bool,
    /// Whether the reference is RIP-relative (x64) or absolute (x86).
    pub is_rip_relative: bool,
}

impl ImportHint {
    /// Create a new import hint.
    #[must_use]
    pub const fn new(insn_addr: u64, iat_rva: u32, is_call: bool, is_rip_relative: bool) -> Self {
        Self { insn_addr, iat_rva, is_call, is_rip_relative }
    }
}

impl fmt::Display for ImportHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = if self.is_call { "CALL" } else { "JMP" };
        write!(f, "{}@{:#x} → IAT[{:#x}]", kind, self.insn_addr, self.iat_rva)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ThunkData — IMAGE_THUNK_DATA equivalent
// ─────────────────────────────────────────────────────────────────────────────

/// Represents an `IMAGE_THUNK_DATA64` or `IMAGE_THUNK_DATA32` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThunkData {
    /// The thunk value (name RVA or ordinal flag + ordinal).
    pub value: u64,
    /// Whether this is an import by ordinal.
    pub is_ordinal: bool,
    /// The ordinal, if imported by ordinal.
    pub ordinal: u16,
    /// The name RVA (pointing to `IMAGE_IMPORT_BY_NAME`), if imported by name.
    pub name_rva: u32,
}

impl ThunkData {
    /// Create a by-name thunk.
    #[must_use]
    pub const fn by_name(name_rva: u32) -> Self {
        Self {
            value: name_rva as u64,
            is_ordinal: false,
            ordinal: 0,
            name_rva,
        }
    }

    /// Create a by-ordinal thunk (64-bit).
    #[must_use]
    pub const fn by_ordinal64(ordinal: u16) -> Self {
        let value = 0x8000_0000_0000_0000u64 | ordinal as u64;
        Self { value, is_ordinal: true, ordinal, name_rva: 0 }
    }

    /// Create a by-ordinal thunk (32-bit).
    #[must_use]
    pub const fn by_ordinal32(ordinal: u16) -> Self {
        let value = 0x8000_0000u64 | ordinal as u64;
        Self { value, is_ordinal: true, ordinal, name_rva: 0 }
    }

    /// Serialise as 8 bytes (little-endian u64).
    #[must_use]
    pub const fn to_le_bytes(&self) -> [u8; 8] {
        self.value.to_le_bytes()
    }

    /// Serialise as 4 bytes (little-endian u32).
    #[must_use]
    pub const fn to_le_bytes32(&self) -> [u8; 4] {
        (self.value as u32).to_le_bytes()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ImportDescriptor — one IMAGE_IMPORT_DESCRIPTOR plus its entries
// ─────────────────────────────────────────────────────────────────────────────

/// Represents one `IMAGE_IMPORT_DESCRIPTOR` with its associated thunk array.
#[derive(Debug, Clone)]
pub struct ImportDescriptor {
    /// DLL name (e.g. `"kernel32.dll"`).
    pub dll_name: String,
    /// RVA of the original first thunk (INT).
    pub original_first_thunk: u32,
    /// RVA of the first thunk (IAT).
    pub first_thunk: u32,
    /// All thunk entries for this DLL.
    pub thunks: Vec<ThunkData>,
    /// Resolved function names / ordinals parallel to `thunks`.
    pub functions: Vec<IatEntry>,
}

impl ImportDescriptor {
    /// Create a new import descriptor for `dll_name` at IAT `rva`.
    #[must_use]
    pub const fn new(dll_name: String, first_thunk: u32) -> Self {
        Self {
            dll_name,
            original_first_thunk: 0,
            first_thunk,
            thunks: Vec::new(),
            functions: Vec::new(),
        }
    }

    /// Number of imported functions.
    #[must_use]
    pub const fn function_count(&self) -> usize {
        self.thunks.len()
    }

    /// Serialise the `IMAGE_IMPORT_DESCRIPTOR` (20 bytes) to `buf`.
    pub fn write_descriptor(&self, buf: &mut Vec<u8>) {
        let oft = self.original_first_thunk.to_le_bytes();
        let ts = 0u32.to_le_bytes();   // TimeDateStamp
        let fc = 0u32.to_le_bytes();   // ForwarderChain
        let name_rva = 0u32.to_le_bytes(); // placeholder; caller fills in
        let ft = self.first_thunk.to_le_bytes();
        buf.extend_from_slice(&oft);
        buf.extend_from_slice(&ts);
        buf.extend_from_slice(&fc);
        buf.extend_from_slice(&name_rva);
        buf.extend_from_slice(&ft);
    }
}

impl fmt::Display for ImportDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ImportDescriptor({} iat={:#x} {} funcs)",
            self.dll_name, self.first_thunk, self.thunks.len()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ImportRebuilder — scans code and rebuilds import table
// ─────────────────────────────────────────────────────────────────────────────

/// Options for the import table rebuilder.
#[derive(Debug, Clone)]
pub struct ImportRebuilderConfig {
    /// `true` if the image is 64-bit (x64 RIP-relative FF 15 calls).
    pub is_64bit: bool,
    /// Base address where the image is loaded in memory.
    pub image_base: u64,
    /// Minimum confidence to include a resolved entry.
    pub min_confidence: u8,
    /// Whether to scan for CALL patterns (FF 15).
    pub scan_calls: bool,
    /// Whether to scan for JMP patterns (FF 25).
    pub scan_jumps: bool,
}

impl Default for ImportRebuilderConfig {
    fn default() -> Self {
        Self {
            is_64bit: true,
            image_base: 0x0000_0001_4000_0000,
            min_confidence: 50,
            scan_calls: true,
            scan_jumps: true,
        }
    }
}

/// Rebuilds the import table for a PE image.
///
/// Algorithm:
/// 1. Scan the code section for indirect call (`FF 15 xx xx xx xx`) and
///    jmp (`FF 25 xx xx xx xx`) patterns to collect IAT hints.
/// 2. Resolve each IAT RVA to a DLL + function name using the provided
///    export table snapshot.
/// 3. Group by DLL name and reconstruct `IMAGE_IMPORT_DESCRIPTOR` entries.
#[derive(Debug, Clone)]
pub struct ImportRebuilder {
    config: ImportRebuilderConfig,
    /// Hints collected from code scanning.
    hints: Vec<ImportHint>,
    /// Resolved entries (IAT RVA → `IatEntry`).
    resolved: HashMap<u32, IatEntry>,
    /// Export snapshot: (`dll_name`, `function_name`) → runtime VA.
    export_snapshot: HashMap<u64, (String, String)>,
}

impl ImportRebuilder {
    /// Create a new rebuilder with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(ImportRebuilderConfig::default())
    }

    /// Create a rebuilder with custom configuration.
    #[must_use]
    pub fn with_config(config: ImportRebuilderConfig) -> Self {
        Self {
            config,
            hints: Vec::new(),
            resolved: HashMap::new(),
            export_snapshot: HashMap::new(),
        }
    }

    /// Register a known export: runtime VA → (`dll_name`, `function_name`).
    pub fn add_export(&mut self, va: u64, dll_name: String, function_name: String) {
        self.export_snapshot.insert(va, (dll_name, function_name));
    }

    /// Load many exports at once.
    pub fn load_exports(&mut self, exports: &[(u64, &str, &str)]) {
        for &(va, dll, func) in exports {
            self.export_snapshot.insert(va, (dll.to_owned(), func.to_owned()));
        }
    }

    // ── Code scanning ─────────────────────────────────────────────────────────

    /// Scan `code` for indirect call/jmp patterns and populate `hints`.
    ///
    /// `code_rva` is the RVA of the first byte of `code`.
    /// `next_insn_rva` for a RIP-relative ref at offset `i` is `code_rva + i + 6`.
    pub fn scan_code(&mut self, code: &[u8], code_rva: u32) {
        let len = code.len();
        let mut i = 0usize;
        while i + 5 < len {
            let b0 = code[i];
            let b1 = code[i + 1];

            // x64: CALL [RIP+disp32]  — FF 15 xx xx xx xx
            if b0 == 0xFF && b1 == 0x15 && self.config.scan_calls {
                let disp = i32::from_le_bytes([code[i+2], code[i+3], code[i+4], code[i+5]]);
                let next_rip = i64::from(code_rva) + i64::try_from(i).unwrap_or(i64::MAX) + 6;
                let target_rva = u32::try_from(next_rip + i64::from(disp)).unwrap_or(u32::MAX);
                self.hints.push(ImportHint::new(
                    self.config.image_base + u64::from(code_rva) + i as u64,
                    target_rva, true, true,
                ));
                i += 6;
                continue;
            }

            // x64: JMP [RIP+disp32]  — FF 25 xx xx xx xx
            if b0 == 0xFF && b1 == 0x25 && self.config.scan_jumps {
                let disp = i32::from_le_bytes([code[i+2], code[i+3], code[i+4], code[i+5]]);
                let next_rip = i64::from(code_rva) + i64::try_from(i).unwrap_or(i64::MAX) + 6;
                let target_rva = u32::try_from(next_rip + i64::from(disp)).unwrap_or(u32::MAX);
                self.hints.push(ImportHint::new(
                    self.config.image_base + u64::from(code_rva) + i as u64,
                    target_rva, false, true,
                ));
                i += 6;
                continue;
            }

            // x86: CALL [abs32]  — FF 15 xx xx xx xx (same encoding)
            // x86: JMP  [abs32]  — FF 25 xx xx xx xx
            // Handled above since encoding is identical; distinction is in is_rip_relative.

            i += 1;
        }
    }

    // ── IAT resolution ────────────────────────────────────────────────────────

    /// Resolve IAT entries from the hints using the loaded export snapshot.
    ///
    /// For each hint, reads the IAT slot from `image` at the hint's RVA and
    /// looks up the runtime VA in the export snapshot.
    pub fn resolve_from_image(&mut self, image: &[u8]) {
        let ptr_size = if self.config.is_64bit { 8usize } else { 4 };
        for hint in &self.hints {
            let off = hint.iat_rva as usize;
            if off + ptr_size > image.len() {
                continue;
            }
            let va = if ptr_size == 8 {
                u64::from_le_bytes(image[off..off + 8].try_into().unwrap_or([0; 8]))
            } else {
                u64::from(u32::from_le_bytes(image[off..off + 4].try_into().unwrap_or([0; 4])))
            };
            if va == 0 {
                continue;
            }
            if let Some((dll, func)) = self.export_snapshot.get(&va) {
                let conf = 85u8;
                let entry = IatEntry {
                    iat_rva: hint.iat_rva,
                    runtime_va: va,
                    dll_name: dll.clone(),
                    function_name: func.clone(),
                    ordinal: 0,
                    confidence: conf,
                };
                self.resolved.insert(hint.iat_rva, entry);
            } else if va != 0 {
                // Unresolved but still record as unknown.
                let entry = IatEntry {
                    iat_rva: hint.iat_rva,
                    runtime_va: va,
                    dll_name: "unknown.dll".to_owned(),
                    function_name: format!("sub_{va:x}"),
                    ordinal: 0,
                    confidence: 20,
                };
                self.resolved.insert(hint.iat_rva, entry);
            }
        }
    }

    /// Manually register a resolved IAT entry.
    pub fn register_entry(&mut self, entry: IatEntry) {
        self.resolved.insert(entry.iat_rva, entry);
    }

    // ── Descriptor generation ─────────────────────────────────────────────────

    /// Group resolved entries by DLL name and build `ImportDescriptor` list.
    #[must_use]
    pub fn build_descriptors(&self) -> Vec<ImportDescriptor> {
        // Group by dll_name.
        let mut by_dll: HashMap<String, Vec<&IatEntry>> = HashMap::new();
        for entry in self.resolved.values() {
            if entry.confidence >= self.config.min_confidence {
                by_dll.entry(entry.dll_name.clone()).or_default().push(entry);
            }
        }

        let mut descriptors: Vec<ImportDescriptor> = by_dll
            .into_iter()
            .map(|(dll_name, entries)| {
                let first_thunk = entries.iter().map(|e| e.iat_rva).min().unwrap_or(0);
                let mut desc = ImportDescriptor::new(dll_name, first_thunk);
                let mut sorted_entries = entries;
                sorted_entries.sort_by_key(|e| e.iat_rva);
                for e in sorted_entries {
                    let thunk = if e.has_name() {
                        ThunkData::by_name(e.iat_rva) // placeholder name RVA
                    } else if self.config.is_64bit {
                        ThunkData::by_ordinal64(e.ordinal)
                    } else {
                        ThunkData::by_ordinal32(e.ordinal)
                    };
                    desc.thunks.push(thunk);
                    desc.functions.push(e.clone());
                }
                desc
            })
            .collect();

        descriptors.sort_by(|a, b| a.dll_name.cmp(&b.dll_name));
        descriptors
    }

    /// Serialise all import descriptors into a binary `.idata` blob.
    ///
    /// The caller is responsible for placing this blob in the correct section
    /// and updating the `DataDirectory` entry.
    ///
    /// Returns `(idata_blob, import_dir_size)`.
    #[must_use]
    pub fn build_idata_blob(&self, section_rva: u32) -> (Vec<u8>, usize) {
        let descriptors = self.build_descriptors();
        if descriptors.is_empty() {
            return (Vec::new(), 0);
        }

        let ptr_size = if self.config.is_64bit { 8usize } else { 4 };
        let num_dlls = descriptors.len();
        // Layout:
        // [num_dlls + 1] * 20 bytes — descriptor table (incl. null terminator)
        // per DLL: [n+1] * ptr_size — thunk array (incl. null)
        //          [n] * (2+name_len+1) — IMAGE_IMPORT_BY_NAME entries
        //          dll_name + "\0"
        let dir_size = (num_dlls + 1) * 20;

        // Compute offsets for per-DLL data.
        let mut offsets: Vec<u32> = Vec::new();
        let mut pos = dir_size;
        for desc in &descriptors {
            offsets.push(section_rva + u32::try_from(pos).unwrap_or(u32::MAX));
            pos += (desc.thunks.len() + 1) * ptr_size; // thunk array + null
        }

        let mut out = vec![0u8; dir_size];

        // Fill descriptor table.
        for (i, desc) in descriptors.iter().enumerate() {
            let base = i * 20;
            // OriginalFirstThunk.
            out[base..base + 4].copy_from_slice(&offsets[i].to_le_bytes());
            // TimeDateStamp = 0.
            // ForwarderChain = 0.
            // Name RVA = placeholder 0 (caller should patch).
            // FirstThunk.
            out[base + 16..base + 20].copy_from_slice(&desc.first_thunk.to_le_bytes());
        }
        // Null descriptor terminator already zeroed.

        // Append thunk arrays.
        for (i, desc) in descriptors.iter().enumerate() {
            let _ = i;
            for thunk in &desc.thunks {
                if ptr_size == 8 {
                    out.extend_from_slice(&thunk.to_le_bytes());
                } else {
                    out.extend_from_slice(&thunk.to_le_bytes32());
                }
            }
            // Null terminator.
            if ptr_size == 8 {
                out.extend_from_slice(&[0u8; 8]);
            } else {
                out.extend_from_slice(&[0u8; 4]);
            }
        }

        // Append IMAGE_IMPORT_BY_NAME + DLL name strings.
        for desc in &descriptors {
            for (thunk, entry) in desc.thunks.iter().zip(desc.functions.iter()) {
                if !thunk.is_ordinal {
                    // IMAGE_IMPORT_BY_NAME: hint (u16) + name + null
                    out.extend_from_slice(&0u16.to_le_bytes()); // hint
                    out.extend_from_slice(entry.function_name.as_bytes());
                    out.push(0);
                    // Align to 2.
                    if !out.len().is_multiple_of(2) { out.push(0); }
                }
            }
            out.extend_from_slice(desc.dll_name.as_bytes());
            out.push(0);
        }

        let import_dir_size = dir_size;
        (out, import_dir_size)
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    /// Number of hints found during code scanning.
    #[must_use]
    pub const fn hint_count(&self) -> usize {
        self.hints.len()
    }

    /// Number of resolved IAT entries.
    #[must_use]
    pub fn resolved_count(&self) -> usize {
        self.resolved.len()
    }

    /// All resolved entries sorted by IAT RVA.
    #[must_use]
    pub fn resolved_entries(&self) -> Vec<&IatEntry> {
        let mut v: Vec<&IatEntry> = self.resolved.values().collect();
        v.sort_by_key(|e| e.iat_rva);
        v
    }

    /// Reference to config.
    #[must_use]
    pub const fn config(&self) -> &ImportRebuilderConfig {
        &self.config
    }
}

impl Default for ImportRebuilder {
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

    #[test]
    fn iat_entry_description_named() {
        let e = IatEntry::named(0x1000, "kernel32.dll".into(), "CreateFileA".into());
        assert_eq!(e.description(), "kernel32.dll!CreateFileA");
        assert!(e.has_name());
    }

    #[test]
    fn iat_entry_description_ordinal() {
        let e = IatEntry::by_ordinal(0x1008, "ws2_32.dll".into(), 10);
        assert_eq!(e.description(), "ws2_32.dll!#10");
        assert!(!e.has_name());
    }

    #[test]
    fn thunk_by_name_not_ordinal() {
        let t = ThunkData::by_name(0xABCD);
        assert!(!t.is_ordinal);
        assert_eq!(t.name_rva, 0xABCD);
    }

    #[test]
    fn thunk_by_ordinal64_flag() {
        let t = ThunkData::by_ordinal64(42);
        assert!(t.is_ordinal);
        assert_eq!(t.ordinal, 42);
        assert!(t.value & 0x8000_0000_0000_0000 != 0);
    }

    #[test]
    fn scan_code_finds_ff15() {
        // Build a fake code blob: FF 15 00 10 00 00 = CALL [RIP+0x1000]
        // Next instruction RVA = code_rva(0x1000) + offset(0) + 6 = 0x1006
        // Target RVA = 0x1006 + 0x1000 = 0x2006
        let code = vec![0xFF, 0x15, 0x00, 0x10, 0x00, 0x00];
        let mut rebuilder = ImportRebuilder::new();
        rebuilder.scan_code(&code, 0x1000);
        assert_eq!(rebuilder.hint_count(), 1);
        assert_eq!(rebuilder.hints[0].iat_rva, 0x2006);
        assert!(rebuilder.hints[0].is_call);
    }

    #[test]
    fn scan_code_finds_ff25() {
        let code = vec![0xFF, 0x25, 0x00, 0x10, 0x00, 0x00];
        let mut rebuilder = ImportRebuilder::new();
        rebuilder.scan_code(&code, 0x1000);
        assert_eq!(rebuilder.hint_count(), 1);
        assert!(!rebuilder.hints[0].is_call);
    }

    #[test]
    fn build_descriptors_groups_by_dll() {
        let mut rebuilder = ImportRebuilder::new();
        rebuilder.register_entry(IatEntry::named(0x3000, "kernel32.dll".into(), "VirtualAlloc".into()));
        rebuilder.register_entry(IatEntry::named(0x3008, "kernel32.dll".into(), "CreateThread".into()));
        rebuilder.register_entry(IatEntry::named(0x3010, "ntdll.dll".into(), "NtAllocateVirtualMemory".into()));
        let descs = rebuilder.build_descriptors();
        assert_eq!(descs.len(), 2);
        let k32 = descs.iter().find(|d| d.dll_name == "kernel32.dll").unwrap();
        assert_eq!(k32.thunks.len(), 2);
    }

    #[test]
    fn build_idata_non_empty() {
        let mut rebuilder = ImportRebuilder::new();
        rebuilder.register_entry(IatEntry::named(0x3000, "kernel32.dll".into(), "Sleep".into()));
        let (blob, dir_size) = rebuilder.build_idata_blob(0x4000);
        assert!(!blob.is_empty());
        assert_eq!(dir_size, 40); // 2 descriptors * 20 bytes (1 real + 1 null)
    }

    #[test]
    fn resolve_from_image_64bit() {
        let mut rebuilder = ImportRebuilder::new();
        // Register export: VA 0xDEAD_BEEF_1234 → kernel32.dll!Sleep
        rebuilder.add_export(0xDEAD_BEEF_1234, "kernel32.dll".into(), "Sleep".into());
        // Create a fake hint targeting IAT RVA 0.
        rebuilder.hints.push(ImportHint::new(0, 0, true, true));
        // Fake image: 8 bytes at offset 0 = the VA.
        let mut image = vec![0u8; 16];
        image[0..8].copy_from_slice(&0xDEAD_BEEF_1234u64.to_le_bytes());
        rebuilder.resolve_from_image(&image);
        assert_eq!(rebuilder.resolved_count(), 1);
        assert_eq!(rebuilder.resolved[&0].function_name, "Sleep");
    }
}
