//! Extended architecture registry: register by name/enum, lookup by magic bytes,
//! [`ArchRegistry`], [`ArchEntry`], [`ArchSelector`], [`ArchMeta`].

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use rustre_core::arch::{Architecture, Instruction, BranchInfo, CallingConvention, RegisterInfo};
use rustre_core::address::Address;
use rustre_core::endian::Endian;
use rustre_core::errors::CoreError;

// ─────────────────────────────────────────────────────────────────────────────
// ArchKind
// ─────────────────────────────────────────────────────────────────────────────

/// A well-known architecture enumeration used as an alternative key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArchKind {
    X86,
    X86_64,
    Arm,
    Arm64,
    Mips,
    Mips64,
    Ppc,
    Ppc64,
    RiscV32,
    RiscV64,
    Sparc,
    Sparc64,
    Msp430,
    Avr,
    MOS6502,
    Z80,
    M68K,
    Bpf,
    Wasm,
    Jvm,
    Cil,
    Custom(String),
}

impl ArchKind {
    /// Canonical string name for this architecture kind.
    #[must_use]
    pub const fn name(&self) -> &str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Arm => "arm",
            Self::Arm64 => "arm64",
            Self::Mips => "mips",
            Self::Mips64 => "mips64",
            Self::Ppc => "ppc",
            Self::Ppc64 => "ppc64",
            Self::RiscV32 => "riscv32",
            Self::RiscV64 => "riscv64",
            Self::Sparc => "sparc",
            Self::Sparc64 => "sparc64",
            Self::Msp430 => "msp430",
            Self::Avr => "avr",
            Self::MOS6502 => "6502",
            Self::Z80 => "z80",
            Self::M68K => "68k",
            Self::Bpf => "bpf",
            Self::Wasm => "wasm",
            Self::Jvm => "jvm",
            Self::Cil => "cil",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Parse an `ArchKind` from a canonical name string.
    #[must_use]
    pub fn from_name(s: &str) -> Self {
        match s {
            "x86" => Self::X86,
            "x86_64" => Self::X86_64,
            "arm" => Self::Arm,
            "arm64" => Self::Arm64,
            "mips" => Self::Mips,
            "mips64" => Self::Mips64,
            "ppc" => Self::Ppc,
            "ppc64" => Self::Ppc64,
            "riscv32" => Self::RiscV32,
            "riscv64" => Self::RiscV64,
            "sparc" => Self::Sparc,
            "sparc64" => Self::Sparc64,
            "msp430" => Self::Msp430,
            "avr" => Self::Avr,
            "6502" => Self::MOS6502,
            "z80" => Self::Z80,
            "68k" => Self::M68K,
            "bpf" => Self::Bpf,
            "wasm" => Self::Wasm,
            "jvm" => Self::Jvm,
            "cil" => Self::Cil,
            other => Self::Custom(other.to_owned()),
        }
    }
}

impl std::fmt::Display for ArchKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ArchMeta
// ─────────────────────────────────────────────────────────────────────────────

/// Rich metadata stored alongside an architecture backend in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchMeta {
    /// Human-readable description.
    pub description: String,
    /// Architecture kind enum.
    pub kind: ArchKind,
    /// Pointer size in bytes (4 or 8 typically).
    pub pointer_size: usize,
    /// Minimum instruction encoding size in bytes.
    pub min_instr_size: usize,
    /// Maximum instruction encoding size in bytes.
    pub max_instr_size: usize,
    /// Whether the ISA uses variable-length instructions.
    pub variable_length: bool,
    /// Magic byte prefixes that identify binaries for this architecture.
    /// Each entry is a `(offset, magic_bytes)` pair.
    pub magic_signatures: Vec<(usize, Vec<u8>)>,
    /// NOP instruction byte sequence.
    pub nop_bytes: Vec<u8>,
    /// Default endianness.
    pub default_endian: Endian,
    /// Tags for grouping (e.g. "risc", "cisc", "embedded", "vm").
    pub tags: Vec<String>,
}

impl ArchMeta {
    /// Build metadata for a simple fixed-width RISC architecture.
    #[must_use]
    pub fn risc(kind: ArchKind, instr_size: usize, nop: &[u8], endian: Endian, ptr_size: usize) -> Self {
        Self {
            description: format!("{} (RISC, fixed {}B insns)", kind.name(), instr_size),
            kind,
            pointer_size: ptr_size,
            min_instr_size: instr_size,
            max_instr_size: instr_size,
            variable_length: false,
            magic_signatures: vec![],
            nop_bytes: nop.to_vec(),
            default_endian: endian,
            tags: vec!["risc".into()],
        }
    }

    /// Build metadata for a variable-length CISC architecture.
    #[must_use]
    pub fn cisc(kind: ArchKind, min: usize, max: usize, nop: &[u8], ptr_size: usize) -> Self {
        Self {
            description: format!("{} (CISC, {}-{}B insns)", kind.name(), min, max),
            kind,
            pointer_size: ptr_size,
            min_instr_size: min,
            max_instr_size: max,
            variable_length: true,
            magic_signatures: vec![],
            nop_bytes: nop.to_vec(),
            default_endian: Endian::Little,
            tags: vec!["cisc".into()],
        }
    }

    /// Add a magic signature for binary detection.
    #[must_use]
    pub fn with_magic(mut self, offset: usize, magic: Vec<u8>) -> Self {
        self.magic_signatures.push((offset, magic));
        self
    }

    /// Add a tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Check whether `data` matches any registered magic signature.
    #[must_use]
    pub fn matches_magic(&self, data: &[u8]) -> bool {
        for (offset, magic) in &self.magic_signatures {
            let end = offset + magic.len();
            if data.len() >= end && &data[*offset..end] == magic.as_slice() {
                return true;
            }
        }
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ArchEntry
// ─────────────────────────────────────────────────────────────────────────────

/// An entry in the [`ArchSelector`] registry.
pub struct ArchEntry {
    /// The architecture backend.
    pub arch: Arc<dyn Architecture>,
    /// Rich metadata.
    pub meta: ArchMeta,
    /// Priority for conflict resolution (higher = preferred).
    pub priority: i32,
}

impl std::fmt::Debug for ArchEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchEntry")
            .field("name", &self.arch.name())
            .field("priority", &self.priority)
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ArchSelector
// ─────────────────────────────────────────────────────────────────────────────

/// Thread-safe registry of architecture backends with rich lookup capabilities.
///
/// Supports:
/// - Registration by name or [`ArchKind`] enum.
/// - Lookup by magic bytes (binary detection).
/// - Priority-based conflict resolution.
/// - Filtering by tags.
#[derive(Debug, Default)]
pub struct ArchSelector {
    entries: RwLock<Vec<ArchEntry>>,
    /// Secondary index: `ArchKind` → index in `entries`.
    kind_index: RwLock<HashMap<ArchKind, usize>>,
}

impl ArchSelector {
    /// Create an empty selector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an architecture with the given metadata and priority.
    ///
    /// If an architecture with the same name is already registered, the new entry
    /// replaces the old one only if `priority` is strictly greater.
    pub fn register(&self, arch: Arc<dyn Architecture>, meta: ArchMeta, priority: i32) {
        let name = arch.name().to_owned();

        // Check for existing entry with the same name.
        let update = {
            let entries = self.entries.read();
            entries.iter().position(|e| e.arch.name() == name).map(|pos| {
                (pos, entries[pos].priority, entries[pos].meta.kind.clone())
            })
        };

        if let Some((pos, existing_priority, old_kind)) = update {
            if priority > existing_priority {
                let new_kind = meta.kind.clone();
                {
                    let mut entries = self.entries.write();
                    entries[pos] = ArchEntry { arch, meta, priority };
                }
                let mut ki = self.kind_index.write();
                // Remove the stale old kind entry if it differs from the new one.
                if old_kind != new_kind {
                    ki.remove(&old_kind);
                }
                ki.insert(new_kind, pos);
            }
            return;
        }

        let idx = {
            let mut entries = self.entries.write();
            let idx = entries.len();
            entries.push(ArchEntry { arch, meta: meta.clone(), priority });
            idx
        };
        let mut ki = self.kind_index.write();
        ki.insert(meta.kind, idx);
    }

    /// Look up an architecture by name.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<Arc<dyn Architecture>> {
        self.entries
            .read()
            .iter()
            .find(|e| e.arch.name() == name)
            .map(|e| Arc::clone(&e.arch))
    }

    /// Look up an architecture by its [`ArchKind`] enum.
    #[must_use]
    pub fn find_by_kind(&self, kind: &ArchKind) -> Option<Arc<dyn Architecture>> {
        let idx = *self.kind_index.read().get(kind)?;
        self.entries.read().get(idx).map(|e| Arc::clone(&e.arch))
    }

    /// Detect the architecture from binary `data` by matching magic signatures.
    ///
    /// Returns the highest-priority matching backend, or `None` if no match is
    /// found.
    #[must_use]
    pub fn detect_from_magic(&self, data: &[u8]) -> Option<Arc<dyn Architecture>> {
        let entries = self.entries.read();
        entries
            .iter()
            .filter(|e| e.meta.matches_magic(data))
            .max_by_key(|e| e.priority)
            .map(|e| Arc::clone(&e.arch))
    }

    /// Return metadata for the named architecture.
    #[must_use]
    pub fn meta_for(&self, name: &str) -> Option<ArchMeta> {
        self.entries
            .read()
            .iter()
            .find(|e| e.arch.name() == name)
            .map(|e| e.meta.clone())
    }

    /// Return all architectures tagged with `tag`.
    #[must_use]
    pub fn find_by_tag(&self, tag: &str) -> Vec<Arc<dyn Architecture>> {
        self.entries
            .read()
            .iter()
            .filter(|e| e.meta.tags.iter().any(|t| t == tag))
            .map(|e| Arc::clone(&e.arch))
            .collect()
    }

    /// Return the names of all registered architectures.
    #[must_use]
    pub fn all_names(&self) -> Vec<String> {
        self.entries
            .read()
            .iter()
            .map(|e| e.arch.name().to_owned())
            .collect()
    }

    /// Return the kinds of all registered architectures.
    #[must_use]
    pub fn all_kinds(&self) -> Vec<ArchKind> {
        self.entries
            .read()
            .iter()
            .map(|e| e.meta.kind.clone())
            .collect()
    }

    /// Deregister an architecture by name. Returns `true` if it was present.
    pub fn remove(&self, name: &str) -> bool {
        let mut entries = self.entries.write();
        let before = entries.len();
        let removed_kind = entries
            .iter()
            .find(|e| e.arch.name() == name)
            .map(|e| e.meta.kind.clone());
        entries.retain(|e| e.arch.name() != name);
        if let Some(kind) = removed_kind {
            self.kind_index.write().remove(&kind);
        }
        entries.len() < before
    }

    /// Return the number of registered architectures.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Return `true` if no architectures are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Return all architectures with pointer size equal to `bits / 8`.
    #[must_use]
    pub fn find_by_pointer_size(&self, bits: usize) -> Vec<Arc<dyn Architecture>> {
        let bytes = bits / 8;
        self.entries
            .read()
            .iter()
            .filter(|e| e.meta.pointer_size == bytes)
            .map(|e| Arc::clone(&e.arch))
            .collect()
    }

    /// Return all architectures with default endianness `endian`.
    #[must_use]
    pub fn find_by_endian(&self, endian: Endian) -> Vec<Arc<dyn Architecture>> {
        self.entries
            .read()
            .iter()
            .filter(|e| e.meta.default_endian == endian)
            .map(|e| Arc::clone(&e.arch))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Global ArchSelector singleton
// ─────────────────────────────────────────────────────────────────────────────

/// Process-wide global [`ArchSelector`] singleton.
pub static GLOBAL_SELECTOR: std::sync::LazyLock<ArchSelector> =
    std::sync::LazyLock::new(ArchSelector::new);

/// Return a reference to the global [`ArchSelector`].
#[must_use]
pub fn global_selector() -> &'static ArchSelector {
    &GLOBAL_SELECTOR
}

// ─────────────────────────────────────────────────────────────────────────────
// Stub helper for tests
// ─────────────────────────────────────────────────────────────────────────────

/// A minimal stub architecture used for registry unit tests.
#[derive(Debug)]
pub struct StubRegistryArch {
    pub name: String,
    pub ptr_size: usize,
    pub endian: Endian,
}

impl Architecture for StubRegistryArch {
    fn name(&self) -> &str {
        &self.name
    }
    fn pointer_size(&self) -> usize {
        self.ptr_size
    }
    fn endian(&self) -> Endian {
        self.endian
    }
    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        if bytes.is_empty() {
            return Err(CoreError::unsupported("empty"));
        }
        Ok(Instruction::new(address, 1, "nop", bytes[..1].to_vec()))
    }
    fn get_branches(&self, _: &Instruction) -> Vec<BranchInfo> {
        vec![]
    }
    fn registers(&self) -> Vec<RegisterInfo> {
        vec![]
    }
    fn calling_conventions(&self) -> Vec<CallingConvention> {
        vec![]
    }
}

impl StubRegistryArch {
    /// Convenience constructor.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            name: name.into(),
            ptr_size: 8,
            endian: Endian::Little,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_meta(kind: ArchKind) -> ArchMeta {
        ArchMeta::cisc(kind, 1, 15, &[0x90], 8)
    }

    #[test]
    fn test_arch_kind_name_roundtrip() {
        let kinds = [
            ArchKind::X86,
            ArchKind::X86_64,
            ArchKind::Arm,
            ArchKind::Arm64,
            ArchKind::RiscV64,
        ];
        for k in &kinds {
            assert_eq!(ArchKind::from_name(k.name()), *k);
        }
    }

    #[test]
    fn test_arch_kind_custom() {
        let k = ArchKind::from_name("mytharch");
        assert_eq!(k.name(), "mytharch");
    }

    #[test]
    fn test_register_and_find_by_name() {
        let sel = ArchSelector::new();
        let arch = StubRegistryArch::new("test_arch");
        sel.register(arch, make_meta(ArchKind::Custom("test_arch".into())), 0);
        assert!(sel.find_by_name("test_arch").is_some());
        assert!(sel.find_by_name("nonexistent").is_none());
    }

    #[test]
    fn test_find_by_kind() {
        let sel = ArchSelector::new();
        let arch = StubRegistryArch::new("x86_64");
        sel.register(arch, make_meta(ArchKind::X86_64), 0);
        assert!(sel.find_by_kind(&ArchKind::X86_64).is_some());
    }

    #[test]
    fn test_priority_replacement() {
        let sel = ArchSelector::new();
        let a1 = StubRegistryArch::new("arch");
        let a2 = StubRegistryArch::new("arch");
        sel.register(a1, make_meta(ArchKind::Custom("arch".into())), 0);
        sel.register(a2, make_meta(ArchKind::Custom("arch".into())), 10);
        // After higher-priority registration, we should still find "arch".
        assert!(sel.find_by_name("arch").is_some());
        assert_eq!(sel.len(), 1);
    }

    #[test]
    fn test_detect_from_magic() {
        let sel = ArchSelector::new();
        let arch = StubRegistryArch::new("elf_x86");
        let meta = ArchMeta::cisc(ArchKind::X86, 1, 15, &[0x90], 4)
            .with_magic(0, b"\x7fELF".to_vec());
        sel.register(arch, meta, 0);
        let data = b"\x7fELF\x01\x01\x01\x00";
        assert!(sel.detect_from_magic(data).is_some());
        let not_elf = b"\x4D\x5A\x00\x00";
        assert!(sel.detect_from_magic(not_elf).is_none());
    }

    #[test]
    fn test_find_by_tag() {
        let sel = ArchSelector::new();
        let a = StubRegistryArch::new("arm_risc");
        sel.register(
            a,
            ArchMeta::risc(ArchKind::Arm, 4, &[0x00], Endian::Little, 4).with_tag("embedded"),
            0,
        );
        let results = sel.find_by_tag("risc");
        assert_eq!(results.len(), 1);
        let emb = sel.find_by_tag("embedded");
        assert_eq!(emb.len(), 1);
        let cisc = sel.find_by_tag("cisc");
        assert!(cisc.is_empty());
    }

    #[test]
    fn test_all_names() {
        let sel = ArchSelector::new();
        sel.register(StubRegistryArch::new("a"), make_meta(ArchKind::Custom("a".into())), 0);
        sel.register(StubRegistryArch::new("b"), make_meta(ArchKind::Custom("b".into())), 0);
        let names = sel.all_names();
        assert!(names.contains(&"a".to_string()));
        assert!(names.contains(&"b".to_string()));
    }

    #[test]
    fn test_remove() {
        let sel = ArchSelector::new();
        sel.register(StubRegistryArch::new("rem"), make_meta(ArchKind::Custom("rem".into())), 0);
        assert!(sel.remove("rem"));
        assert!(!sel.remove("rem"));
        assert!(sel.is_empty());
    }

    #[test]
    fn test_find_by_pointer_size() {
        let sel = ArchSelector::new();
        let mut m32 = make_meta(ArchKind::X86);
        m32.pointer_size = 4;
        let mut m64 = make_meta(ArchKind::X86_64);
        m64.pointer_size = 8;
        sel.register(StubRegistryArch::new("x86"), m32, 0);
        sel.register(StubRegistryArch::new("x86_64"), m64, 0);
        assert_eq!(sel.find_by_pointer_size(32).len(), 1);
        assert_eq!(sel.find_by_pointer_size(64).len(), 1);
    }

    #[test]
    fn test_meta_matches_magic() {
        let meta = ArchMeta::cisc(ArchKind::X86, 1, 15, &[0x90], 4)
            .with_magic(0, b"MZ".to_vec());
        assert!(meta.matches_magic(b"MZabcd"));
        assert!(!meta.matches_magic(b"NOTmz"));
    }

    #[test]
    fn test_arch_kind_display() {
        assert_eq!(ArchKind::X86_64.to_string(), "x86_64");
        assert_eq!(ArchKind::Custom("foo".into()).to_string(), "foo");
    }

    #[test]
    fn test_find_by_endian() {
        let sel = ArchSelector::new();
        let mut be_meta = make_meta(ArchKind::Sparc);
        be_meta.default_endian = Endian::Big;
        let mut le_meta = make_meta(ArchKind::X86);
        le_meta.default_endian = Endian::Little;
        sel.register(StubRegistryArch::new("sparc"), be_meta, 0);
        sel.register(StubRegistryArch::new("x86"), le_meta, 0);
        assert_eq!(sel.find_by_endian(Endian::Big).len(), 1);
        assert_eq!(sel.find_by_endian(Endian::Little).len(), 1);
    }
}
