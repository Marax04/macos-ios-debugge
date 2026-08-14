//! `scylla_IatRebuilder` — Scylla-style IAT (Import Address Table) rebuilder.
//!
//! Rebuilds the IAT of a memory-dumped PE by resolving thunks and
//! reconstructing the import directory.
//!
//! # Key types
//! * [`ScyllaIatRebuilder`] — main facade.
//! * [`IATEntry`]           — a single IAT slot (one imported function pointer).
//! * [`FunctionPointer`]    — a resolved or unresolved function pointer.
//! * [`ModuleMapping`]      — maps a DLL's load range to its name and exports.
//! * [`IatRebuilder`]      — low-level rebuilder that writes the new IAT.
//! * [`ScyllaReport`]       — summary of a rebuild run.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IatError {
    #[error("PE parse error: {0}")]
    PeParse(String),
    #[error("IAT entry at RVA {0:#x} is out of bounds")]
    OutOfBounds(u64),
    #[error("module not found for address {0:#x}")]
    ModuleNotFound(u64),
    #[error("function not found: {0}!{1}")]
    FunctionNotFound(String, String),
    #[error("IAT write out of bounds: off={offset} len={len} size={size}")]
    WriteOutOfBounds {
        offset: usize,
        len: usize,
        size: usize,
    },
    #[error("duplicate module mapping: {0}")]
    DuplicateModule(String),
    #[error("empty IAT section")]
    EmptyIat,
}

pub type IatResult<T> = Result<T, IatError>;

// ---------------------------------------------------------------------------
// FunctionPointer
// ---------------------------------------------------------------------------

/// Status of a resolved function pointer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PointerStatus {
    /// Successfully resolved to a known export.
    Resolved,
    /// Pointer is null/zero.
    Null,
    /// Pointer value does not fall inside any known module.
    Unresolved,
    /// Pointer was resolved by hint/ordinal only (no name available).
    ByOrdinal,
}

impl fmt::Display for PointerStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolved => write!(f, "resolved"),
            Self::Null => write!(f, "null"),
            Self::Unresolved => write!(f, "unresolved"),
            Self::ByOrdinal => write!(f, "by_ordinal"),
        }
    }
}

/// A concrete function pointer value with resolution metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionPointer {
    /// Raw virtual address value stored in the IAT slot.
    pub va: u64,
    /// The containing module (if resolved).
    pub module: Option<String>,
    /// The exported function name (if resolved by name).
    pub name: Option<String>,
    /// The exported ordinal.
    pub ordinal: Option<u16>,
    pub status: PointerStatus,
}

impl FunctionPointer {
    #[must_use]
    pub const fn null() -> Self {
        Self {
            va: 0,
            module: None,
            name: None,
            ordinal: None,
            status: PointerStatus::Null,
        }
    }

    #[must_use]
    pub const fn unresolved(va: u64) -> Self {
        Self {
            va,
            module: None,
            name: None,
            ordinal: None,
            status: PointerStatus::Unresolved,
        }
    }

    pub fn resolved(
        va: u64,
        module: impl Into<String>,
        name: impl Into<String>,
        ordinal: u16,
    ) -> Self {
        Self {
            va,
            module: Some(module.into()),
            name: Some(name.into()),
            ordinal: Some(ordinal),
            status: PointerStatus::Resolved,
        }
    }

    pub fn by_ordinal(va: u64, module: impl Into<String>, ordinal: u16) -> Self {
        Self {
            va,
            module: Some(module.into()),
            name: None,
            ordinal: Some(ordinal),
            status: PointerStatus::ByOrdinal,
        }
    }

    #[must_use]
    pub fn is_resolved(&self) -> bool {
        self.status == PointerStatus::Resolved || self.status == PointerStatus::ByOrdinal
    }
}

impl fmt::Display for FunctionPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.module, &self.name) {
            (Some(m), Some(n)) => write!(f, "{m}!{n} @ {:#x}", self.va),
            (Some(m), None) => write!(f, "{m}!#{} @ {:#x}", self.ordinal.unwrap_or(0), self.va),
            _ => write!(f, "<unresolved @ {:#x}>", self.va),
        }
    }
}

// ---------------------------------------------------------------------------
// IATEntry
// ---------------------------------------------------------------------------

/// A single slot in the Import Address Table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IATEntry {
    /// RVA within the image.
    pub rva: u32,
    /// The resolved function pointer.
    pub pointer: FunctionPointer,
    /// Whether this entry terminates a module's IAT block.
    pub is_terminator: bool,
}

impl IATEntry {
    #[must_use]
    pub const fn new(rva: u32, pointer: FunctionPointer) -> Self {
        Self {
            rva,
            pointer,
            is_terminator: false,
        }
    }

    #[must_use]
    pub fn terminator(rva: u32) -> Self {
        Self {
            rva,
            pointer: FunctionPointer::null(),
            is_terminator: true,
        }
    }

    #[must_use]
    pub const fn is_null(&self) -> bool {
        self.pointer.va == 0
    }
}

impl fmt::Display for IATEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_terminator {
            write!(f, "[{:#x}] <terminator>", self.rva)
        } else {
            write!(f, "[{:#x}] {}", self.rva, self.pointer)
        }
    }
}

// ---------------------------------------------------------------------------
// ModuleMapping
// ---------------------------------------------------------------------------

/// Describes a loaded DLL's virtual-address range and its exported symbols.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMapping {
    pub name: String,
    /// Start VA of the module in memory.
    pub base: u64,
    /// End VA (exclusive).
    pub end: u64,
    /// Map of exported function VA → (ordinal, name).
    pub exports: HashMap<u64, (u16, String)>,
}

impl ModuleMapping {
    pub fn new(name: impl Into<String>, base: u64, size: u64) -> Self {
        Self {
            name: name.into(),
            base,
            end: base + size,
            exports: HashMap::new(),
        }
    }

    /// Register an export.
    pub fn add_export(&mut self, va: u64, ordinal: u16, name: impl Into<String>) {
        self.exports.insert(va, (ordinal, name.into()));
    }

    /// Returns `true` if `va` falls within this module's range.
    #[must_use]
    pub const fn contains(&self, va: u64) -> bool {
        va >= self.base && va < self.end
    }

    /// Resolve `va` to a `FunctionPointer`.
    #[must_use]
    pub fn resolve(&self, va: u64) -> Option<FunctionPointer> {
        if !self.contains(va) {
            return None;
        }
        if let Some((ord, name)) = self.exports.get(&va) {
            Some(FunctionPointer::resolved(
                va,
                &self.name,
                name.clone(),
                *ord,
            ))
        } else {
            // Inside the module but not a known export — return by offset.
            let offset = va - self.base;
            Some(FunctionPointer::by_ordinal(va, &self.name, u16::try_from(offset).unwrap_or(u16::MAX)))
        }
    }

    /// Number of exports registered.
    #[must_use]
    pub fn export_count(&self) -> usize {
        self.exports.len()
    }
}

impl fmt::Display for ModuleMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} @ {:#x}..{:#x} ({} exports)",
            self.name,
            self.base,
            self.end,
            self.exports.len()
        )
    }
}

// ---------------------------------------------------------------------------
// IatRebuilder — low-level writer
// ---------------------------------------------------------------------------

/// Describes a single import descriptor entry to write.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportDescriptor {
    pub module: String,
    pub entries: Vec<IATEntry>,
}

/// Low-level rebuilder: writes new IAT bytes into a PE buffer.
#[derive(Debug, Clone)]
pub struct IatRebuilder {
    pub image_base: u64,
    pub iat_rva: u32,
    pub ptr_size: usize, // 4 or 8
}

impl IatRebuilder {
    #[must_use]
    pub const fn new_pe32(image_base: u64, iat_rva: u32) -> Self {
        Self {
            image_base,
            iat_rva,
            ptr_size: 4,
        }
    }

    #[must_use]
    pub const fn new_pe64(image_base: u64, iat_rva: u32) -> Self {
        Self {
            image_base,
            iat_rva,
            ptr_size: 8,
        }
    }

    /// Write IAT pointer values into `buf` starting at `iat_file_offset`.
    ///
    /// # Errors
    ///
    /// Returns [`IatError::WriteOutOfBounds`] if the buffer is too small.
    pub fn write_iat(
        &self,
        buf: &mut [u8],
        iat_file_offset: usize,
        entries: &[IATEntry],
    ) -> IatResult<usize> {
        let total = entries.len() * self.ptr_size;
        if iat_file_offset + total > buf.len() {
            return Err(IatError::WriteOutOfBounds {
                offset: iat_file_offset,
                len: total,
                size: buf.len(),
            });
        }
        let mut off = iat_file_offset;
        for entry in entries {
            let va = if entry.is_terminator {
                0
            } else {
                entry.pointer.va
            };
            match self.ptr_size {
                4 => {
                    let v = u32::try_from(va).unwrap_or(u32::MAX);
                    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
                }
                8 => {
                    buf[off..off + 8].copy_from_slice(&va.to_le_bytes());
                }
                _ => unreachable!(),
            }
            off += self.ptr_size;
        }
        Ok(total)
    }

    /// Grow the buffer to at least `required` bytes.
    pub fn ensure_capacity(buf: &mut Vec<u8>, required: usize) {
        if buf.len() < required {
            buf.resize(required, 0);
        }
    }
}

// ---------------------------------------------------------------------------
// ScyllaReport
// ---------------------------------------------------------------------------

/// Summary produced by a Scylla IAT rebuild run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScyllaReport {
    pub total_entries: usize,
    pub resolved: usize,
    pub unresolved: usize,
    pub null_entries: usize,
    pub modules_found: Vec<String>,
    pub unresolved_addresses: Vec<u64>,
    pub errors: Vec<String>,
    pub iat_written_bytes: usize,
}

impl ScyllaReport {
    #[must_use]
    pub const fn success(&self) -> bool {
        self.errors.is_empty()
    }

    #[must_use]
    pub fn resolution_rate(&self) -> f64 {
        let total = self.resolved + self.unresolved;
        if total == 0 {
            return 1.0;
        }
        f64::from(u32::try_from(self.resolved).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
    }
}

impl fmt::Display for ScyllaReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ScyllaReport: {}/{} resolved ({:.1}%), {} null, {} bytes written",
            self.resolved,
            self.total_entries,
            self.resolution_rate() * 100.0,
            self.null_entries,
            self.iat_written_bytes
        )
    }
}

// ---------------------------------------------------------------------------
// ScyllaIatRebuilder — main facade
// ---------------------------------------------------------------------------

/// Main facade: reconstructs the IAT from a snapshot of running memory.
#[derive(Debug)]
pub struct ScyllaIatRebuilder {
    /// Module database: name → mapping.
    pub modules: HashMap<String, ModuleMapping>,
    /// The collected raw IAT entries (VA values from the dumped image).
    pub raw_iat: Vec<(u32, u64)>, // (rva, va_value)
    pub image_base: u64,
    pub ptr_size: usize,
}

impl ScyllaIatRebuilder {
    #[must_use]
    pub fn new(image_base: u64, ptr_size: usize) -> Self {
        Self {
            modules: HashMap::new(),
            raw_iat: Vec::new(),
            image_base,
            ptr_size,
        }
    }

    #[must_use]
    pub fn new_pe32(image_base: u64) -> Self {
        Self::new(image_base, 4)
    }

    #[must_use]
    pub fn new_pe64(image_base: u64) -> Self {
        Self::new(image_base, 8)
    }

    /// Register a loaded module.
    ///
    /// # Errors
    ///
    /// Returns [`IatError::DuplicateModule`] if a module with the same name was already added.
    pub fn add_module(&mut self, mapping: ModuleMapping) -> IatResult<()> {
        let name = mapping.name.clone();
        if self.modules.contains_key(&name) {
            return Err(IatError::DuplicateModule(name));
        }
        self.modules.insert(name, mapping);
        Ok(())
    }

    /// Add a raw IAT entry (RVA, pointer-value).
    pub fn add_raw_entry(&mut self, rva: u32, va: u64) {
        self.raw_iat.push((rva, va));
    }

    /// Scan a byte slice as a flat-mapped IAT and add all entries.
    ///
    /// # Panics
    ///
    /// Panics if the byte slice has an odd length and `ptr_size` is 4.
    pub fn scan_flat_iat(&mut self, buf: &[u8], iat_rva: u32) {
        let stride = self.ptr_size;
        let mut off = 0usize;
        let mut rva = iat_rva;
        while off + stride <= buf.len() {
            let va = if stride == 4 {
                u64::from(u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()))
            } else {
                u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
            };
            self.raw_iat.push((rva, va));
            off += stride;
            rva += u32::try_from(stride).unwrap_or(u32::MAX);
        }
    }

    /// Resolve all raw IAT entries using the module database.
    #[must_use]
    pub fn resolve_all(&self) -> Vec<IATEntry> {
        let mut entries = Vec::with_capacity(self.raw_iat.len());
        for &(rva, va) in &self.raw_iat {
            if va == 0 {
                entries.push(IATEntry::terminator(rva));
                continue;
            }
            let pointer = self.resolve_pointer(va);
            entries.push(IATEntry::new(rva, pointer));
        }
        entries
    }

    fn resolve_pointer(&self, va: u64) -> FunctionPointer {
        for module in self.modules.values() {
            if let Some(fp) = module.resolve(va) {
                return fp;
            }
        }
        FunctionPointer::unresolved(va)
    }

    /// Group resolved entries by module.
    #[must_use]
    pub fn group_by_module<'a>(
        &self,
        entries: &'a [IATEntry],
    ) -> HashMap<String, Vec<&'a IATEntry>> {
        let mut map: HashMap<String, Vec<&'a IATEntry>> = HashMap::new();
        for e in entries {
            let key = e
                .pointer
                .module
                .clone()
                .unwrap_or_else(|| "<unknown>".into());
            map.entry(key).or_default().push(e);
        }
        map
    }

    /// Full rebuild: resolve, report, and optionally write IAT into `pe_buf`.
    ///
    /// # Errors
    ///
    /// Returns [`IatError`] if the IAT is empty or a write fails.
    pub fn rebuild(&self, pe_buf: &mut Vec<u8>, iat_file_offset: usize) -> IatResult<ScyllaReport> {
        if self.raw_iat.is_empty() {
            return Err(IatError::EmptyIat);
        }

        let entries = self.resolve_all();
        let mut report = ScyllaReport {
            total_entries: entries.iter().filter(|e| !e.is_terminator).count(),
            ..ScyllaReport::default()
        };

        let mut modules_set = std::collections::HashSet::new();
        for e in &entries {
            if e.is_terminator {
                continue;
            }
            match e.pointer.status {
                PointerStatus::Resolved | PointerStatus::ByOrdinal => {
                    report.resolved += 1;
                    if let Some(m) = &e.pointer.module {
                        modules_set.insert(m.clone());
                    }
                }
                PointerStatus::Unresolved => {
                    report.unresolved += 1;
                    report.unresolved_addresses.push(e.pointer.va);
                }
                PointerStatus::Null => report.null_entries += 1,
            }
        }
        report.modules_found = modules_set.into_iter().collect();
        report.modules_found.sort();

        // Write IAT.
        let iat_builder = if self.ptr_size == 4 {
            IatRebuilder::new_pe32(self.image_base, 0)
        } else {
            IatRebuilder::new_pe64(self.image_base, 0)
        };
        let required = iat_file_offset + entries.len() * self.ptr_size;
        IatRebuilder::ensure_capacity(pe_buf, required);
        let written = iat_builder.write_iat(pe_buf, iat_file_offset, &entries)?;
        report.iat_written_bytes = written;

        Ok(report)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_module(
        name: &str,
        base: u64,
        size: u64,
        exports: &[(u64, u16, &str)],
    ) -> ModuleMapping {
        let mut m = ModuleMapping::new(name, base, size);
        for &(va, ord, fname) in exports {
            m.add_export(va, ord, fname);
        }
        m
    }

    // --- FunctionPointer ---

    #[test]
    fn fp_null_is_null() {
        let fp = FunctionPointer::null();
        assert_eq!(fp.status, PointerStatus::Null);
        assert_eq!(fp.va, 0);
    }

    #[test]
    fn fp_resolved_display() {
        let fp = FunctionPointer::resolved(0x1234, "kernel32.dll", "CreateFileW", 42);
        let s = format!("{fp}");
        assert!(s.contains("kernel32.dll"));
        assert!(s.contains("CreateFileW"));
    }

    #[test]
    fn fp_unresolved_status() {
        let fp = FunctionPointer::unresolved(0xDEAD);
        assert_eq!(fp.status, PointerStatus::Unresolved);
        assert!(!fp.is_resolved());
    }

    #[test]
    fn fp_by_ordinal_is_resolved() {
        let fp = FunctionPointer::by_ordinal(0xBEEF, "ntdll.dll", 1);
        assert!(fp.is_resolved());
    }

    // --- IATEntry ---

    #[test]
    fn iat_entry_terminator() {
        let e = IATEntry::terminator(0x1000);
        assert!(e.is_null());
        assert!(e.is_terminator);
    }

    #[test]
    fn iat_entry_display() {
        let e = IATEntry::new(
            0x100,
            FunctionPointer::resolved(0x7FFF, "k32", "ReadFile", 10),
        );
        let s = format!("{e}");
        assert!(s.contains("0x100") || s.contains("100"));
    }

    // --- ModuleMapping ---

    #[test]
    fn module_contains() {
        let m = make_module("k32", 0x7000_0000, 0x100_000, &[]);
        assert!(m.contains(0x7000_0000));
        assert!(m.contains(0x7000_FFFF));
        assert!(!m.contains(0x6FFF_FFFF));
        assert!(!m.contains(0x7010_0000));
    }

    #[test]
    fn module_resolve_named_export() {
        let m = make_module("k32", 0x1000, 0x1000, &[(0x1100, 1, "Foo")]);
        let fp = m.resolve(0x1100).unwrap();
        assert_eq!(fp.status, PointerStatus::Resolved);
        assert_eq!(fp.name.as_deref(), Some("Foo"));
    }

    #[test]
    fn module_resolve_by_ordinal_fallback() {
        let m = make_module("k32", 0x1000, 0x1000, &[]);
        let fp = m.resolve(0x1500).unwrap();
        assert_eq!(fp.status, PointerStatus::ByOrdinal);
    }

    #[test]
    fn module_resolve_out_of_range() {
        let m = make_module("k32", 0x1000, 0x100, &[]);
        assert!(m.resolve(0x5000).is_none());
    }

    #[test]
    fn module_export_count() {
        let m = make_module("k32", 0x1000, 0x1000, &[(0x1100, 1, "A"), (0x1200, 2, "B")]);
        assert_eq!(m.export_count(), 2);
    }

    #[test]
    fn module_display() {
        let m = make_module("k32", 0x1000, 0x1000, &[]);
        assert!(format!("{m}").contains("k32"));
    }

    // --- IatRebuilder ---

    #[test]
    fn iat_rebuilder_write_pe32() {
        let mut buf = vec![0u8; 16];
        let rb = IatRebuilder::new_pe32(0x0040_0000, 0x1000);
        let entries = vec![
            IATEntry::new(0x1000, FunctionPointer::resolved(0xABCD, "k32", "A", 1)),
            IATEntry::terminator(0x1004),
        ];
        let written = rb.write_iat(&mut buf, 0, &entries).unwrap();
        assert_eq!(written, 8);
        assert_eq!(&buf[0..4], &0xABCDu32.to_le_bytes());
        assert_eq!(&buf[4..8], &[0, 0, 0, 0]);
    }

    #[test]
    fn iat_rebuilder_write_pe64() {
        let mut buf = vec![0u8; 32];
        let rb = IatRebuilder::new_pe64(0x0001_4000_0000, 0x2000);
        let entries = vec![IATEntry::new(
            0x2000,
            FunctionPointer::resolved(0xDEAD_BEEF_DEAD, "nt", "NtClose", 5),
        )];
        let written = rb.write_iat(&mut buf, 0, &entries).unwrap();
        assert_eq!(written, 8);
        assert_eq!(&buf[0..8], &0xDEAD_BEEF_DEAD_u64.to_le_bytes());
    }

    #[test]
    fn iat_rebuilder_write_out_of_bounds() {
        let mut buf = vec![0u8; 4];
        let rb = IatRebuilder::new_pe32(0, 0);
        let entries = vec![
            IATEntry::new(0, FunctionPointer::null()),
            IATEntry::new(4, FunctionPointer::null()),
        ];
        assert!(rb.write_iat(&mut buf, 0, &entries).is_err());
    }

    #[test]
    fn ensure_capacity_grows() {
        let mut buf = vec![0u8; 4];
        IatRebuilder::ensure_capacity(&mut buf, 16);
        assert_eq!(buf.len(), 16);
    }

    // --- ScyllaIatRebuilder ---

    #[test]
    fn scylla_basic_resolve() {
        let mut scylla = ScyllaIatRebuilder::new_pe32(0x0040_0000);
        let m = make_module(
            "k32",
            0x7000_0000,
            0x100_000,
            &[(0x7000_1000, 1, "ReadFile")],
        );
        scylla.add_module(m).unwrap();
        scylla.add_raw_entry(0x1000, 0x7000_1000);
        let entries = scylla.resolve_all();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].pointer.status, PointerStatus::Resolved);
    }

    #[test]
    fn scylla_unresolved_entry() {
        let scylla = ScyllaIatRebuilder::new_pe32(0x0040_0000);
        let entries = [(0x1000, 0xDEAD_0000u64)];
        let raw_entries: Vec<IATEntry> = entries
            .iter()
            .map(|&(rva, va)| IATEntry::new(rva, scylla.resolve_pointer(va)))
            .collect();
        assert_eq!(raw_entries[0].pointer.status, PointerStatus::Unresolved);
    }

    #[test]
    fn scylla_null_entry_becomes_terminator() {
        let mut scylla = ScyllaIatRebuilder::new_pe32(0x0040_0000);
        scylla.add_raw_entry(0x1000, 0);
        let entries = scylla.resolve_all();
        assert!(entries[0].is_terminator);
    }

    #[test]
    fn scylla_duplicate_module_error() {
        let mut scylla = ScyllaIatRebuilder::new_pe64(0x0001_4000_0000);
        let m = make_module("k32", 0x7000, 0x1000, &[]);
        scylla.add_module(m.clone()).unwrap();
        assert!(matches!(
            scylla.add_module(m),
            Err(IatError::DuplicateModule(_))
        ));
    }

    #[test]
    fn scylla_scan_flat_iat_pe32() {
        let mut scylla = ScyllaIatRebuilder::new_pe32(0);
        let buf: Vec<u8> = vec![
            0x00, 0x10, 0x00, 0x70, // entry 0: VA = 0x70001000
            0x00, 0x00, 0x00, 0x00, // entry 1: NULL
        ];
        scylla.scan_flat_iat(&buf, 0x2000);
        assert_eq!(scylla.raw_iat.len(), 2);
        assert_eq!(scylla.raw_iat[0].1, 0x7000_1000);
        assert_eq!(scylla.raw_iat[1].1, 0);
    }

    #[test]
    fn scylla_rebuild_writes_iat() {
        let mut scylla = ScyllaIatRebuilder::new_pe32(0x0040_0000);
        let m = make_module(
            "k32",
            0x7000_0000,
            0x100_000,
            &[(0x7000_1234, 1, "CreateFileW")],
        );
        scylla.add_module(m).unwrap();
        scylla.add_raw_entry(0x3000, 0x7000_1234);
        scylla.add_raw_entry(0x3004, 0);
        let mut buf = vec![0u8; 64];
        let report = scylla.rebuild(&mut buf, 0).unwrap();
        assert_eq!(report.resolved, 1);
        assert!(report.modules_found.contains(&"k32".to_string()));
        assert!(report.iat_written_bytes > 0);
    }

    #[test]
    fn scylla_rebuild_empty_error() {
        let scylla = ScyllaIatRebuilder::new_pe32(0);
        let mut buf = vec![];
        assert!(matches!(
            scylla.rebuild(&mut buf, 0),
            Err(IatError::EmptyIat)
        ));
    }

    #[test]
    fn scylla_group_by_module() {
        let mut scylla = ScyllaIatRebuilder::new_pe32(0);
        let m1 = make_module("k32", 0x1000, 0x1000, &[(0x1100, 1, "A")]);
        let m2 = make_module("ntdll", 0x2000, 0x1000, &[(0x2100, 1, "B")]);
        scylla.add_module(m1).unwrap();
        scylla.add_module(m2).unwrap();
        scylla.add_raw_entry(0x5000, 0x1100);
        scylla.add_raw_entry(0x5004, 0x2100);
        let entries = scylla.resolve_all();
        let groups = scylla.group_by_module(&entries);
        assert!(groups.contains_key("k32"));
        assert!(groups.contains_key("ntdll"));
    }

    #[test]
    fn report_resolution_rate_full() {
        let r = ScyllaReport {
            total_entries: 4,
            resolved: 4,
            unresolved: 0,
            ..Default::default()
        };
        assert!((r.resolution_rate() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn report_resolution_rate_partial() {
        let r = ScyllaReport {
            total_entries: 4,
            resolved: 2,
            unresolved: 2,
            ..Default::default()
        };
        assert!((r.resolution_rate() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn report_display() {
        let r = ScyllaReport {
            total_entries: 10,
            resolved: 8,
            unresolved: 2,
            iat_written_bytes: 40,
            ..Default::default()
        };
        let s = format!("{r}");
        assert!(s.contains("8/10"));
    }

    #[test]
    fn pointer_status_display() {
        assert_eq!(format!("{}", PointerStatus::Resolved), "resolved");
        assert_eq!(format!("{}", PointerStatus::Null), "null");
        assert_eq!(format!("{}", PointerStatus::Unresolved), "unresolved");
        assert_eq!(format!("{}", PointerStatus::ByOrdinal), "by_ordinal");
    }

    #[test]
    fn iat_entry_non_terminator() {
        let e = IATEntry::new(0x500, FunctionPointer::resolved(0xABCD, "m", "f", 0));
        assert!(!e.is_terminator);
        assert!(!e.is_null());
    }

    #[test]
    fn fp_null_va_zero() {
        let fp = FunctionPointer::null();
        assert_eq!(fp.va, 0);
    }

    #[test]
    fn fp_resolved_has_module_and_name() {
        let fp = FunctionPointer::resolved(0x1000, "ntdll.dll", "NtClose", 5);
        assert!(fp.module.is_some());
        assert!(fp.name.is_some());
        assert_eq!(fp.ordinal, Some(5));
    }

    #[test]
    fn module_add_export_increments_count() {
        let mut m = ModuleMapping::new("k32", 0x1000, 0x1000);
        m.add_export(0x1100, 1, "A");
        m.add_export(0x1200, 2, "B");
        assert_eq!(m.export_count(), 2);
    }

    #[test]
    fn iat_rebuilder_ensure_capacity_no_shrink() {
        let mut buf = vec![0u8; 16];
        IatRebuilder::ensure_capacity(&mut buf, 8);
        assert_eq!(buf.len(), 16); // already large enough
    }

    #[test]
    fn scylla_resolve_all_with_no_modules() {
        let mut scylla = ScyllaIatRebuilder::new_pe32(0);
        scylla.add_raw_entry(0, 0x1234);
        let entries = scylla.resolve_all();
        assert_eq!(entries[0].pointer.status, PointerStatus::Unresolved);
    }

    #[test]
    fn scylla_scan_flat_iat_pe64() {
        let mut scylla = ScyllaIatRebuilder::new_pe64(0);
        let buf: Vec<u8> = {
            let mut b = vec![0u8; 16];
            b[0..8].copy_from_slice(&0x7FFF_0000_1234u64.to_le_bytes());
            b
        };
        scylla.scan_flat_iat(&buf, 0x3000);
        assert_eq!(scylla.raw_iat.len(), 2);
        assert_eq!(scylla.raw_iat[0].1, 0x7FFF_0000_1234);
    }

    #[test]
    fn report_zero_total_rate_one() {
        let r = ScyllaReport::default();
        assert!((r.resolution_rate() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn iat_entry_display_non_terminator() {
        let fp = FunctionPointer::resolved(0x1234, "k32", "ReadFile", 1);
        let e = IATEntry::new(0x1000, fp);
        let s = format!("{e}");
        assert!(s.contains("ReadFile"));
    }

    #[test]
    fn scylla_report_success_no_errors() {
        let r = ScyllaReport::default();
        assert!(r.success());
    }

    #[test]
    fn scylla_report_success_with_errors() {
        let mut r = ScyllaReport::default();
        r.errors.push("err".into());
        assert!(!r.success());
    }

    #[test]
    fn module_mapping_display() {
        let m = make_module("kernel32.dll", 0x7000_0000, 0x100_000, &[]);
        let s = format!("{m}");
        assert!(s.contains("kernel32.dll"));
    }

    #[test]
    fn iat_rebuilder_zero_entries() {
        let mut buf = vec![0u8; 8];
        let rb = IatRebuilder::new_pe32(0, 0);
        let written = rb.write_iat(&mut buf, 0, &[]).unwrap();
        assert_eq!(written, 0);
    }
}
