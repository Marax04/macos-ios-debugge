//! `arch_registry_full` — Complete architecture registry with auto-detection,
//! capability queries, and compatibility scoring.
//!
//! # Key types
//! * [`ArchRegistryFull`]  — thread-safe registry of architecture entries.
//! * [`ArchEntry`]         — metadata record for a registered architecture.
//! * [`ArchCapabilities`]  — flags describing what an architecture backend supports.
//! * [`ArchScorer`]      — chooses the best architecture for a given binary.
//! * [`AutoDetect`]        — heuristically identifies the architecture of a byte slice.
//! * [`ArchCompatibility`] — compatibility score between two architecture entries.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use bitflags::bitflags;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryError {
    #[error("architecture '{0}' already registered")]
    AlreadyRegistered(String),
    #[error("architecture '{0}' not found")]
    NotFound(String),
    #[error("no architecture matches the provided hints")]
    NoMatch,
    #[error("ambiguous match: {0} candidates")]
    AmbiguousMatch(usize),
    #[error("detection failed: {0}")]
    DetectionFailed(String),
    #[error("incompatible architectures: {0} and {1}")]
    Incompatible(String, String),
}

pub type RegistryResult<T> = Result<T, RegistryError>;

// ---------------------------------------------------------------------------
// ArchCapabilities
// ---------------------------------------------------------------------------

bitflags! {
    /// Feature flags describing what an architecture backend supports.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ArchCapabilities: u32 {
        const DISASSEMBLE       = 1 << 0;
        const ASSEMBLE          = 1 << 1;
        const LIFT_TO_IL        = 1 << 2;
        const CALL_GRAPH        = 1 << 3;
        const CFG               = 1 << 4;
        const DATA_FLOW         = 1 << 5;
        const TYPE_RECOVERY     = 1 << 6;
        const DECOMPILE         = 1 << 7;
        const VTABLE_DETECTION  = 1 << 8;
        const RELOCATION_RESOLVE = 1 << 9;
        const EXCEPTION_UNWIND  = 1 << 10;
        const DEBUG_INFO        = 1 << 11;
        const PATCH_APPLY       = 1 << 12;
        const SYMBOLIC_EXECUTION = 1 << 13;
        const EMULATE           = 1 << 14;
        const FUZZING_SUPPORT   = 1 << 15;
    }
}

impl ArchCapabilities {
    /// All capabilities enabled.
    #[must_use]
    pub const fn full() -> Self {
        Self::all()
    }

    /// Only disassembly enabled.
    #[must_use]
    pub const fn disassemble_only() -> Self {
        Self::DISASSEMBLE
    }

    /// Count the number of enabled capabilities.
    #[must_use]
    pub const fn count_enabled(self) -> u32 {
        self.bits().count_ones()
    }
}

// ---------------------------------------------------------------------------
// ArchEntry
// ---------------------------------------------------------------------------

/// Byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endianness {
    Little,
    Big,
    Bi,
    Unknown,
}

impl fmt::Display for Endianness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Little => write!(f, "LE"),
            Self::Big => write!(f, "BE"),
            Self::Bi => write!(f, "bi-endian"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Architecture mode / ISA variant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArchMode {
    Default,
    Thumb,
    Thumb2,
    X86_16,
    X86_32,
    X86_64,
    Arm32,
    Arm64,
    Mips32,
    Mips64,
    Riscv32,
    Riscv64,
    Ppc32,
    Ppc64,
    Custom(String),
}

impl fmt::Display for ArchMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => write!(f, "default"),
            Self::Custom(s) => write!(f, "custom:{s}"),
            other => write!(f, "{other:?}"),
        }
    }
}

/// A complete metadata record for a registered architecture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchEntry {
    /// Unique identifier (e.g. "`x86_64`", "arm32").
    pub id: String,
    /// Human-readable name.
    pub display_name: String,
    /// Pointer / address width.
    pub address_size: u8, // 2, 4, or 8
    /// Default byte order.
    pub endianness: Endianness,
    /// Architecture family (e.g. "x86", "arm", "risc-v").
    pub family: String,
    /// Supported ISA modes.
    pub modes: Vec<ArchMode>,
    /// Capabilities of the backend.
    pub capabilities: ArchCapabilities,
    /// Priority hint when multiple architectures match (higher wins).
    pub priority: i32,
    /// Tags for categorisation / filtering (e.g. "embedded", "mobile", "desktop").
    pub tags: Vec<String>,
    /// Short description.
    pub description: String,
    /// Whether this entry is currently enabled.
    pub enabled: bool,
}

impl ArchEntry {
    pub fn new(
        id: impl Into<String>,
        display_name: impl Into<String>,
        address_size: u8,
        endianness: Endianness,
        family: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            display_name: display_name.into(),
            address_size,
            endianness,
            family: family.into(),
            modes: vec![ArchMode::Default],
            capabilities: ArchCapabilities::disassemble_only(),
            priority: 0,
            tags: Vec::new(),
            description: String::new(),
            enabled: true,
        }
    }

    #[must_use]
    pub const fn with_capabilities(mut self, caps: ArchCapabilities) -> Self {
        self.capabilities = caps;
        self
    }

    #[must_use]
    pub fn with_modes(mut self, modes: Vec<ArchMode>) -> Self {
        self.modes = modes;
        self
    }

    #[must_use]
    pub fn with_tags(mut self, tags: &[&str]) -> Self {
        self.tags = tags.iter().map(std::string::ToString::to_string).collect();
        self
    }

    #[must_use]
    pub const fn with_priority(mut self, p: i32) -> Self {
        self.priority = p;
        self
    }

    #[must_use]
    pub fn with_description(mut self, d: impl Into<String>) -> Self {
        self.description = d.into();
        self
    }

    /// Returns `true` if this entry supports the given mode.
    #[must_use]
    pub fn supports_mode(&self, mode: &ArchMode) -> bool {
        self.modes.contains(mode)
    }
}

impl fmt::Display for ArchEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({} / {} / {})",
            self.id,
            self.display_name,
            self.endianness,
            self.address_size * 8
        )
    }
}

// ---------------------------------------------------------------------------
// AutoDetect
// ---------------------------------------------------------------------------

/// A detection hint from the binary headers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DetectionHint {
    /// ELF `e_machine` value, if available.
    pub elf_machine: Option<u16>,
    /// PE COFF machine type, if available.
    pub pe_machine: Option<u16>,
    /// Mach-O cpu type, if available.
    pub macho_cpu: Option<u32>,
    /// Whether the binary is 64-bit.
    pub bits64: Option<bool>,
    /// Explicit architecture family name hint.
    pub family_hint: Option<String>,
    /// Explicit mode hint.
    pub mode_hint: Option<ArchMode>,
}

/// Heuristically detects architecture from binary header magic.
#[derive(Debug, Clone, Default)]
pub struct AutoDetect;

impl AutoDetect {
    /// Produce detection hints from a raw byte slice.
    #[must_use]
    pub fn probe(&self, buf: &[u8]) -> DetectionHint {
        let mut hint = DetectionHint::default();
        if buf.len() < 4 {
            return hint;
        }

        // ELF
        if &buf[0..4] == b"\x7FELF" {
            if buf.len() > 18 {
                // EI_CLASS
                hint.bits64 = Some(buf[4] == 2);
                // e_machine at offset 18, endianness per EI_DATA
                if buf.len() > 19 {
                    hint.elf_machine = Some(if buf[5] == 2 {
                        u16::from_be_bytes([buf[18], buf[19]])
                    } else {
                        u16::from_le_bytes([buf[18], buf[19]])
                    });
                }
            }
            return hint;
        }

        // MZ → PE
        if buf[0] == 0x4D && buf[1] == 0x5A && buf.len() > 0x40 {
            let lfanew = u32::from_le_bytes(buf[0x3C..0x40].try_into().unwrap_or([0; 4])) as usize;
            if lfanew.checked_add(6).is_some_and(|end| end <= buf.len()) && &buf[lfanew..lfanew + 4] == b"PE\0\0" {
                let machine = u16::from_le_bytes([buf[lfanew + 4], buf[lfanew + 5]]);
                hint.pe_machine = Some(machine);
                hint.bits64 = Some(machine == 0x8664 || machine == 0xAA64);
            }
            return hint;
        }

        // Mach-O
        let magic = u32::from_be_bytes(buf[0..4].try_into().unwrap_or([0; 4]));
        if magic == 0xFEED_FACE || magic == 0xFEED_FACF || magic == 0xCEFA_EDFE || magic == 0xCFFA_EDFE
        {
            hint.bits64 = Some(magic == 0xFEED_FACF || magic == 0xCFFA_EDFE);
            if buf.len() > 8 {
                let cpu_bytes = buf[4..8].try_into().unwrap_or([0; 4]);
                hint.macho_cpu = Some(if magic == 0xFEED_FACE || magic == 0xFEED_FACF {
                    u32::from_be_bytes(cpu_bytes)
                } else {
                    u32::from_le_bytes(cpu_bytes)
                });
            }
        }
        hint
    }

    /// Translate a `DetectionHint` into a suggested architecture ID.
    #[must_use]
    pub fn suggest_id(&self, hint: &DetectionHint) -> Option<String> {
        // ELF machine codes
        if let Some(em) = hint.elf_machine {
            return Some(match em {
                0x03 => "x86".into(),
                0x3E => "x86_64".into(),
                0x28 => {
                    if hint.bits64.unwrap_or(false) {
                        "arm64".into()
                    } else {
                        "arm32".into()
                    }
                }
                0xB7 => "arm64".into(),
                0x08 => "mips32".into(),
                0xF3 => {
                    if hint.bits64.unwrap_or(false) {
                        "riscv64".into()
                    } else {
                        "riscv32".into()
                    }
                }
                0x14 => "ppc32".into(),
                0x15 => "ppc64".into(),
                _ => return None,
            });
        }
        // PE machine codes
        if let Some(pm) = hint.pe_machine {
            return Some(match pm {
                0x014C => "x86".into(),
                0x8664 => "x86_64".into(),
                0x01C0 | 0x01C2 | 0x01C4 => "arm32".into(),
                0xAA64 => "arm64".into(),
                _ => return None,
            });
        }
        // Mach-O CPU types
        if let Some(cpu) = hint.macho_cpu {
            return Some(match cpu {
                7 => {
                    if hint.bits64.unwrap_or(false) {
                        "x86_64".into()
                    } else {
                        "x86".into()
                    }
                }
                12 => {
                    if hint.bits64.unwrap_or(false) {
                        "arm64".into()
                    } else {
                        "arm32".into()
                    }
                }
                _ => return None,
            });
        }
        hint.family_hint.clone()
    }
}

// ---------------------------------------------------------------------------
// ArchCompatibility
// ---------------------------------------------------------------------------

/// Compatibility score between two architecture entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchCompatibility {
    pub arch_a: String,
    pub arch_b: String,
    /// Score in [0.0, 1.0] where 1.0 = fully compatible.
    pub score: f64,
    /// Capabilities present in A but missing in B.
    pub a_only: Vec<String>,
    /// Capabilities present in B but missing in A.
    pub b_only: Vec<String>,
    /// Whether the two can interoperate for common analysis tasks.
    pub interoperable: bool,
}

impl ArchCompatibility {
    /// Compute compatibility between two entries.
    #[must_use]
    pub fn compute(a: &ArchEntry, b: &ArchEntry) -> Self {
        // Check each flag and compute score.
        let flag_names = [
            "disassemble",
            "assemble",
            "lift_to_il",
            "call_graph",
            "cfg",
            "data_flow",
            "type_recovery",
            "decompile",
            "vtable_detection",
            "relocation_resolve",
            "exception_unwind",
            "debug_info",
            "patch_apply",
            "symbolic_execution",
            "emulate",
            "fuzzing_support",
        ];
        let a_flags: Vec<bool> = cap_flags(a.capabilities);
        let b_flags: Vec<bool> = cap_flags(b.capabilities);

        let mut a_only = Vec::new();
        let mut b_only = Vec::new();
        let mut both = 0u32;
        let total = u32::try_from(flag_names.len()).unwrap_or(u32::MAX);

        for (i, name) in flag_names.iter().enumerate() {
            match (a_flags[i], b_flags[i]) {
                // Both have it, or both lack it — compatible in absence.
                (true, true) | (false, false) => both += 1,
                (true, false) => a_only.push(name.to_string()),
                (false, true) => b_only.push(name.to_string()),
            }
        }

        let score = f64::from(both) / f64::from(total);
        let interoperable = score >= 0.5
            && a.address_size == b.address_size
            && (a.endianness == b.endianness
                || a.endianness == Endianness::Bi
                || b.endianness == Endianness::Bi);

        Self {
            arch_a: a.id.clone(),
            arch_b: b.id.clone(),
            score,
            a_only,
            b_only,
            interoperable,
        }
    }
}

fn cap_flags(c: ArchCapabilities) -> Vec<bool> {
    use ArchCapabilities as AC;
    vec![
        c.contains(AC::DISASSEMBLE),
        c.contains(AC::ASSEMBLE),
        c.contains(AC::LIFT_TO_IL),
        c.contains(AC::CALL_GRAPH),
        c.contains(AC::CFG),
        c.contains(AC::DATA_FLOW),
        c.contains(AC::TYPE_RECOVERY),
        c.contains(AC::DECOMPILE),
        c.contains(AC::VTABLE_DETECTION),
        c.contains(AC::RELOCATION_RESOLVE),
        c.contains(AC::EXCEPTION_UNWIND),
        c.contains(AC::DEBUG_INFO),
        c.contains(AC::PATCH_APPLY),
        c.contains(AC::SYMBOLIC_EXECUTION),
        c.contains(AC::EMULATE),
        c.contains(AC::FUZZING_SUPPORT),
    ]
}

// ---------------------------------------------------------------------------
// ArchScorer
// ---------------------------------------------------------------------------

/// Criteria for architecture selection.
#[derive(Debug, Clone, Default)]
pub struct SelectionCriteria {
    pub required_capabilities: ArchCapabilities,
    pub preferred_family: Option<String>,
    pub preferred_mode: Option<ArchMode>,
    pub address_size: Option<u8>,
    pub endianness: Option<Endianness>,
    pub min_priority: Option<i32>,
    pub tags: Vec<String>,
}

/// Selects the best architecture from the registry.
#[derive(Debug, Clone, Default)]
pub struct ArchScorer;

impl ArchScorer {
    /// Score an entry against the criteria (0 = disqualified, higher = better).
    fn score(entry: &ArchEntry, criteria: &SelectionCriteria) -> Option<i64> {
        if !entry.enabled {
            return None;
        }

        // Check required capabilities.
        let req = criteria.required_capabilities;
        if !req.is_empty() && !entry.capabilities.contains(req) {
            return None;
        }

        // Address size filter.
        if let Some(sz) = criteria.address_size
            && entry.address_size != sz
        {
            return None;
        }

        // Endianness filter.
        if let Some(end) = criteria.endianness
            && end != Endianness::Unknown
            && entry.endianness != end
            && entry.endianness != Endianness::Bi
        {
            return None;
        }

        // Min priority filter.
        if let Some(min) = criteria.min_priority
            && entry.priority < min
        {
            return None;
        }

        let mut score: i64 = i64::from(entry.priority) * 100;

        // Family preference bonus.
        if let Some(fam) = &criteria.preferred_family
            && &entry.family == fam
        {
            score += 1000;
        }

        // Mode preference bonus.
        if let Some(mode) = &criteria.preferred_mode
            && entry.supports_mode(mode)
        {
            score += 500;
        }

        // Tag bonus.
        for tag in &criteria.tags {
            if entry.tags.contains(tag) {
                score += 200;
            }
        }

        // Capability score bonus.
        score += i64::from(entry.capabilities.count_enabled()) * 10;

        Some(score)
    }

    /// Select the best matching architecture.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::NoMatch`] if no entry satisfies the criteria.
    pub fn select<'a>(
        &self,
        entries: &'a [ArchEntry],
        criteria: &SelectionCriteria,
    ) -> RegistryResult<&'a ArchEntry> {
        entries
            .iter()
            .filter_map(|e| Self::score(e, criteria).map(|s| (e, s)))
            .max_by_key(|&(_, s)| s)
            .map(|(e, _)| e)
            .ok_or(RegistryError::NoMatch)
    }

    /// Return all matching architectures, sorted by score.
    #[must_use]
    pub fn select_all<'a>(
        &self,
        entries: &'a [ArchEntry],
        criteria: &SelectionCriteria,
    ) -> Vec<&'a ArchEntry> {
        let mut candidates: Vec<(&ArchEntry, i64)> = entries
            .iter()
            .filter_map(|e| Self::score(e, criteria).map(|s| (e, s)))
            .collect();
        candidates.sort_by_key(|b| std::cmp::Reverse(b.1));
        candidates.into_iter().map(|(e, _)| e).collect()
    }
}

// ---------------------------------------------------------------------------
// ArchRegistryFull
// ---------------------------------------------------------------------------

/// Thread-safe registry of architecture entries.
#[derive(Debug, Default, Clone)]
pub struct ArchRegistryFull {
    inner: Arc<RwLock<RegistryInner>>,
}

#[derive(Debug, Default)]
struct RegistryInner {
    entries: HashMap<String, ArchEntry>,
}

impl ArchRegistryFull {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create and populate with built-in architectures.
    #[must_use]
    pub fn with_builtins() -> Self {
        let r = Self::new();
        let builtins = builtin_entries();
        {
            let mut inner = r.inner.write();
            for e in builtins {
                inner.entries.insert(e.id.clone(), e);
            }
        }
        r
    }

    /// Register an architecture.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::AlreadyRegistered`] if an entry with the same
    /// id already exists.
    pub fn register(&self, entry: ArchEntry) -> RegistryResult<()> {
        let mut inner = self.inner.write();
        if inner.entries.contains_key(&entry.id) {
            return Err(RegistryError::AlreadyRegistered(entry.id));
        }
        inner.entries.insert(entry.id.clone(), entry);
        drop(inner);
        Ok(())
    }

    /// Unregister an architecture.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::NotFound`] if no entry with the given id exists.
    pub fn unregister(&self, id: &str) -> RegistryResult<()> {
        let mut inner = self.inner.write();
        inner
            .entries
            .remove(id)
            .map(|_| ())
            .ok_or_else(|| RegistryError::NotFound(id.into()))
    }

    /// Look up by ID.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<ArchEntry> {
        self.inner.read().entries.get(id).cloned()
    }

    /// All entries (cloned).
    #[must_use]
    pub fn all(&self) -> Vec<ArchEntry> {
        self.inner.read().entries.values().cloned().collect()
    }

    /// Entries by family.
    #[must_use]
    pub fn by_family(&self, family: &str) -> Vec<ArchEntry> {
        self.inner
            .read()
            .entries
            .values()
            .filter(|e| e.family == family)
            .cloned()
            .collect()
    }

    /// Number of registered architectures.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().entries.len()
    }

    /// Returns `true` if the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.read().entries.is_empty()
    }

    /// Enable or disable an entry.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::NotFound`] if no entry with the given id exists.
    pub fn set_enabled(&self, id: &str, enabled: bool) -> RegistryResult<()> {
        let mut inner = self.inner.write();
        inner
            .entries
            .get_mut(id)
            .ok_or_else(|| RegistryError::NotFound(id.into()))
            .map(|e| e.enabled = enabled)
    }

    /// Auto-detect architecture from binary bytes.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::DetectionFailed`] if the binary is not
    /// recognised, or [`RegistryError::NotFound`] if the detected
    /// architecture is not registered.
    pub fn auto_detect(&self, buf: &[u8]) -> RegistryResult<ArchEntry> {
        let detector = AutoDetect;
        let hint = detector.probe(buf);
        let id = detector
            .suggest_id(&hint)
            .ok_or_else(|| RegistryError::DetectionFailed("unrecognised binary".into()))?;
        self.get(&id).ok_or(RegistryError::NotFound(id))
    }

    /// Use the selector to pick the best architecture for the criteria.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::NoMatch`] if no entry satisfies the criteria.
    pub fn select(&self, criteria: &SelectionCriteria) -> RegistryResult<ArchEntry> {
        let entries = self.all();
        ArchScorer.select(&entries, criteria).cloned()
    }

    /// Compute compatibility between two registered architectures.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::NotFound`] if either id is not registered.
    pub fn compatibility(&self, id_a: &str, id_b: &str) -> RegistryResult<ArchCompatibility> {
        let a = self
            .get(id_a)
            .ok_or_else(|| RegistryError::NotFound(id_a.into()))?;
        let b = self
            .get(id_b)
            .ok_or_else(|| RegistryError::NotFound(id_b.into()))?;
        Ok(ArchCompatibility::compute(&a, &b))
    }
}

fn builtin_entries() -> Vec<ArchEntry> {
    let mut entries = builtin_x86_arm_entries();
    entries.extend(builtin_mips_riscv_ppc_entries());
    entries
}

fn builtin_x86_arm_entries() -> Vec<ArchEntry> {
    vec![
        ArchEntry::new("x86", "x86 (32-bit)", 4, Endianness::Little, "x86")
            .with_capabilities(
                ArchCapabilities::DISASSEMBLE
                    | ArchCapabilities::ASSEMBLE
                    | ArchCapabilities::LIFT_TO_IL
                    | ArchCapabilities::CFG
                    | ArchCapabilities::CALL_GRAPH
                    | ArchCapabilities::DATA_FLOW
                    | ArchCapabilities::TYPE_RECOVERY
                    | ArchCapabilities::DECOMPILE,
            )
            .with_modes(vec![ArchMode::X86_32, ArchMode::X86_16])
            .with_tags(&["desktop", "x86"])
            .with_priority(10)
            .with_description("Intel x86 32-bit ISA"),
        ArchEntry::new("x86_64", "x86-64", 8, Endianness::Little, "x86")
            .with_capabilities(ArchCapabilities::full())
            .with_modes(vec![ArchMode::X86_64, ArchMode::X86_32])
            .with_tags(&["desktop", "server", "x86"])
            .with_priority(20)
            .with_description("AMD64 / Intel EM64T"),
        ArchEntry::new("arm32", "ARM (32-bit)", 4, Endianness::Bi, "arm")
            .with_capabilities(
                ArchCapabilities::DISASSEMBLE
                    | ArchCapabilities::ASSEMBLE
                    | ArchCapabilities::LIFT_TO_IL
                    | ArchCapabilities::CFG
                    | ArchCapabilities::CALL_GRAPH
                    | ArchCapabilities::DATA_FLOW
                    | ArchCapabilities::TYPE_RECOVERY
                    | ArchCapabilities::DECOMPILE
                    | ArchCapabilities::EMULATE,
            )
            .with_modes(vec![ArchMode::Arm32, ArchMode::Thumb, ArchMode::Thumb2])
            .with_tags(&["mobile", "embedded", "arm"])
            .with_priority(15)
            .with_description("ARM 32-bit including Thumb/Thumb-2"),
        ArchEntry::new("arm64", "AArch64", 8, Endianness::Little, "arm")
            .with_capabilities(ArchCapabilities::full())
            .with_modes(vec![ArchMode::Arm64])
            .with_tags(&["mobile", "server", "desktop", "arm"])
            .with_priority(20)
            .with_description("ARM 64-bit (AArch64 / Apple Silicon)"),
    ]
}

fn builtin_mips_riscv_ppc_entries() -> Vec<ArchEntry> {
    vec![
        ArchEntry::new("mips32", "MIPS (32-bit)", 4, Endianness::Bi, "mips")
            .with_capabilities(
                ArchCapabilities::DISASSEMBLE
                    | ArchCapabilities::ASSEMBLE
                    | ArchCapabilities::LIFT_TO_IL
                    | ArchCapabilities::CFG
                    | ArchCapabilities::CALL_GRAPH,
            )
            .with_modes(vec![ArchMode::Mips32])
            .with_tags(&["embedded", "router", "mips"])
            .with_priority(8)
            .with_description("MIPS I/II/III/IV 32-bit"),
        ArchEntry::new("mips64", "MIPS (64-bit)", 8, Endianness::Bi, "mips")
            .with_capabilities(
                ArchCapabilities::DISASSEMBLE
                    | ArchCapabilities::LIFT_TO_IL
                    | ArchCapabilities::CFG,
            )
            .with_modes(vec![ArchMode::Mips64])
            .with_tags(&["mips"])
            .with_priority(5),
        ArchEntry::new(
            "riscv32",
            "RISC-V (32-bit)",
            4,
            Endianness::Little,
            "risc-v",
        )
        .with_capabilities(
            ArchCapabilities::DISASSEMBLE
                | ArchCapabilities::ASSEMBLE
                | ArchCapabilities::LIFT_TO_IL
                | ArchCapabilities::CFG,
        )
        .with_modes(vec![ArchMode::Riscv32])
        .with_tags(&["embedded", "risc-v"])
        .with_priority(7),
        ArchEntry::new(
            "riscv64",
            "RISC-V (64-bit)",
            8,
            Endianness::Little,
            "risc-v",
        )
        .with_capabilities(
            ArchCapabilities::DISASSEMBLE
                | ArchCapabilities::ASSEMBLE
                | ArchCapabilities::LIFT_TO_IL
                | ArchCapabilities::CFG
                | ArchCapabilities::CALL_GRAPH
                | ArchCapabilities::DATA_FLOW,
        )
        .with_modes(vec![ArchMode::Riscv64])
        .with_tags(&["risc-v", "server"])
        .with_priority(10),
        ArchEntry::new("ppc32", "PowerPC (32-bit)", 4, Endianness::Big, "ppc")
            .with_capabilities(
                ArchCapabilities::DISASSEMBLE
                    | ArchCapabilities::LIFT_TO_IL
                    | ArchCapabilities::CFG,
            )
            .with_modes(vec![ArchMode::Ppc32])
            .with_tags(&["console", "embedded", "ppc"])
            .with_priority(6),
        ArchEntry::new("ppc64", "PowerPC (64-bit)", 8, Endianness::Big, "ppc")
            .with_capabilities(
                ArchCapabilities::DISASSEMBLE
                    | ArchCapabilities::LIFT_TO_IL
                    | ArchCapabilities::CFG
                    | ArchCapabilities::CALL_GRAPH,
            )
            .with_modes(vec![ArchMode::Ppc64])
            .with_tags(&["server", "ppc"])
            .with_priority(8),
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(id: &str, family: &str, addr: u8, end: Endianness) -> ArchEntry {
        ArchEntry::new(id, id, addr, end, family)
    }

    // --- ArchCapabilities ---

    #[test]
    fn capabilities_count_enabled() {
        let c = ArchCapabilities::full();
        assert_eq!(c.count_enabled(), 16);
    }

    #[test]
    fn capabilities_disassemble_only_count() {
        let c = ArchCapabilities::disassemble_only();
        assert_eq!(c.count_enabled(), 1);
    }

    #[test]
    fn capabilities_default_count() {
        let c = ArchCapabilities::default();
        assert_eq!(c.count_enabled(), 0);
    }

    // --- ArchEntry ---

    #[test]
    fn arch_entry_supports_mode() {
        let e = make_entry("x86", "x86", 4, Endianness::Little)
            .with_modes(vec![ArchMode::X86_32, ArchMode::X86_16]);
        assert!(e.supports_mode(&ArchMode::X86_32));
        assert!(!e.supports_mode(&ArchMode::X86_64));
    }

    #[test]
    fn arch_entry_display() {
        let e = make_entry("arm64", "arm", 8, Endianness::Little);
        let s = format!("{e}");
        assert!(s.contains("arm64"));
    }

    // --- AutoDetect ---

    #[test]
    fn auto_detect_elf_x86_64() {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(b"\x7FELF");
        buf[4] = 2; // 64-bit
        buf[18] = 0x3E;
        buf[19] = 0x00; // EM_X86_64
        let hint = AutoDetect.probe(&buf);
        assert_eq!(hint.elf_machine, Some(0x3E));
        let id = AutoDetect.suggest_id(&hint);
        assert_eq!(id.as_deref(), Some("x86_64"));
    }

    #[test]
    fn auto_detect_pe_x86() {
        let mut buf = vec![0u8; 256];
        buf[0] = 0x4D;
        buf[1] = 0x5A;
        buf[0x3C] = 0x40;
        buf[0x40..0x44].copy_from_slice(b"PE\0\0");
        buf[0x44] = 0x4C;
        buf[0x45] = 0x01; // IMAGE_FILE_MACHINE_I386
        let hint = AutoDetect.probe(&buf);
        let id = AutoDetect.suggest_id(&hint);
        assert_eq!(id.as_deref(), Some("x86"));
    }

    #[test]
    fn auto_detect_pe_x64() {
        let mut buf = vec![0u8; 256];
        buf[0] = 0x4D;
        buf[1] = 0x5A;
        buf[0x3C] = 0x40;
        buf[0x40..0x44].copy_from_slice(b"PE\0\0");
        buf[0x44] = 0x64;
        buf[0x45] = 0x86; // IMAGE_FILE_MACHINE_AMD64
        let hint = AutoDetect.probe(&buf);
        let id = AutoDetect.suggest_id(&hint);
        assert_eq!(id.as_deref(), Some("x86_64"));
    }

    #[test]
    fn auto_detect_empty_buf_no_panic() {
        let hint = AutoDetect.probe(&[]);
        assert!(hint.elf_machine.is_none());
    }

    #[test]
    fn auto_detect_unknown_returns_none() {
        let buf = [0xDE, 0xAD, 0xBE, 0xEF];
        let hint = AutoDetect.probe(&buf);
        assert!(AutoDetect.suggest_id(&hint).is_none());
    }

    // --- ArchCompatibility ---

    #[test]
    fn compat_identical_entries_score_one() {
        let e = make_entry("x86", "x86", 4, Endianness::Little)
            .with_capabilities(ArchCapabilities::full());
        let c = ArchCompatibility::compute(&e, &e);
        assert!((c.score - 1.0).abs() < 1e-9);
        assert!(c.a_only.is_empty());
        assert!(c.b_only.is_empty());
    }

    #[test]
    fn compat_different_entries_lower_score() {
        let a =
            make_entry("a", "x", 4, Endianness::Little).with_capabilities(ArchCapabilities::full());
        let b = make_entry("b", "y", 4, Endianness::Little)
            .with_capabilities(ArchCapabilities::disassemble_only());
        let c = ArchCompatibility::compute(&a, &b);
        assert!(c.score < 1.0);
        // a has full capabilities, b has only `disassemble`; the missing
        // flags belong to b, so a_only (not b_only) is the populated side.
        assert!(!c.a_only.is_empty());
    }

    #[test]
    fn compat_different_addr_size_not_interoperable() {
        let a = make_entry("a", "x", 4, Endianness::Little);
        let b = make_entry("b", "x", 8, Endianness::Little);
        let c = ArchCompatibility::compute(&a, &b);
        assert!(!c.interoperable);
    }

    // --- ArchScorer ---

    #[test]
    fn selector_picks_best() {
        let e1 = make_entry("a", "x", 4, Endianness::Little).with_priority(5);
        let e2 = make_entry("b", "x", 4, Endianness::Little).with_priority(10);
        let entries = vec![e1, e2];
        let criteria = SelectionCriteria::default();
        let sel = ArchScorer.select(&entries, &criteria).unwrap();
        assert_eq!(sel.id, "b");
    }

    #[test]
    fn selector_no_match_error() {
        let entries: Vec<ArchEntry> = vec![];
        let criteria = SelectionCriteria::default();
        assert!(matches!(
            ArchScorer.select(&entries, &criteria),
            Err(RegistryError::NoMatch)
        ));
    }

    #[test]
    fn selector_filters_by_address_size() {
        let e32 = make_entry("a", "x", 4, Endianness::Little);
        let e64 = make_entry("b", "x", 8, Endianness::Little);
        let entries = vec![e32, e64];
        let criteria = SelectionCriteria {
            address_size: Some(8),
            ..Default::default()
        };
        let sel = ArchScorer.select(&entries, &criteria).unwrap();
        assert_eq!(sel.id, "b");
    }

    #[test]
    fn selector_family_preference() {
        let arm = make_entry("arm32", "arm", 4, Endianness::Little).with_priority(5);
        let mips = make_entry("mips32", "mips", 4, Endianness::Little).with_priority(10);
        let entries = vec![arm, mips];
        let criteria = SelectionCriteria {
            preferred_family: Some("arm".into()),
            ..Default::default()
        };
        let sel = ArchScorer.select(&entries, &criteria).unwrap();
        assert_eq!(sel.id, "arm32");
    }

    #[test]
    fn selector_disabled_entry_excluded() {
        let mut e = make_entry("a", "x", 4, Endianness::Little);
        e.enabled = false;
        let entries = vec![e];
        let criteria = SelectionCriteria::default();
        assert!(ArchScorer.select(&entries, &criteria).is_err());
    }

    // --- ArchRegistryFull ---

    #[test]
    fn registry_register_and_get() {
        let r = ArchRegistryFull::new();
        r.register(make_entry("x86_64", "x86", 8, Endianness::Little))
            .unwrap();
        assert!(r.get("x86_64").is_some());
    }

    #[test]
    fn registry_duplicate_register_error() {
        let r = ArchRegistryFull::new();
        r.register(make_entry("a", "x", 4, Endianness::Little))
            .unwrap();
        assert!(matches!(
            r.register(make_entry("a", "x", 4, Endianness::Little)),
            Err(RegistryError::AlreadyRegistered(_))
        ));
    }

    #[test]
    fn registry_unregister() {
        let r = ArchRegistryFull::new();
        r.register(make_entry("a", "x", 4, Endianness::Little))
            .unwrap();
        r.unregister("a").unwrap();
        assert!(r.get("a").is_none());
    }

    #[test]
    fn registry_unregister_not_found() {
        let r = ArchRegistryFull::new();
        assert!(matches!(
            r.unregister("nope"),
            Err(RegistryError::NotFound(_))
        ));
    }

    #[test]
    fn registry_builtins_populated() {
        let r = ArchRegistryFull::with_builtins();
        assert!(r.len() >= 10);
    }

    #[test]
    fn registry_by_family() {
        let r = ArchRegistryFull::with_builtins();
        let arm = r.by_family("arm");
        assert!(!arm.is_empty());
    }

    #[test]
    fn registry_auto_detect_elf() {
        let r = ArchRegistryFull::with_builtins();
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(b"\x7FELF");
        buf[4] = 2;
        buf[18] = 0x3E;
        buf[19] = 0x00; // x86_64
        let entry = r.auto_detect(&buf).unwrap();
        assert_eq!(entry.id, "x86_64");
    }

    #[test]
    fn registry_auto_detect_unknown_error() {
        let r = ArchRegistryFull::with_builtins();
        let buf = [0xDE, 0xAD, 0xBE, 0xEF];
        assert!(r.auto_detect(&buf).is_err());
    }

    #[test]
    fn registry_set_enabled() {
        let r = ArchRegistryFull::with_builtins();
        r.set_enabled("x86", false).unwrap();
        let e = r.get("x86").unwrap();
        assert!(!e.enabled);
    }

    #[test]
    fn registry_compatibility() {
        let r = ArchRegistryFull::with_builtins();
        let c = r.compatibility("x86", "x86_64").unwrap();
        assert_eq!(c.arch_a, "x86");
        assert_eq!(c.arch_b, "x86_64");
    }

    #[test]
    fn registry_select_x86_64() {
        let r = ArchRegistryFull::with_builtins();
        let criteria = SelectionCriteria {
            preferred_family: Some("x86".into()),
            address_size: Some(8),
            ..Default::default()
        };
        let sel = r.select(&criteria).unwrap();
        assert_eq!(sel.id, "x86_64");
    }

    #[test]
    fn endianness_display() {
        assert_eq!(format!("{}", Endianness::Little), "LE");
        assert_eq!(format!("{}", Endianness::Big), "BE");
        assert_eq!(format!("{}", Endianness::Bi), "bi-endian");
    }

    #[test]
    fn arch_mode_display() {
        assert_eq!(
            format!("{}", ArchMode::Custom("MyArch".into())),
            "custom:MyArch"
        );
    }

    #[test]
    fn registry_select_all_returns_sorted() {
        let r = ArchRegistryFull::with_builtins();
        let criteria = SelectionCriteria::default();
        let all_arches = r.all();
        let all = ArchScorer.select_all(&all_arches, &criteria);
        assert!(!all.is_empty());
        // Higher priority first
        if all.len() > 1 {
            assert!(
                all[0].priority >= all[1].priority
                    || all[0].capabilities.count_enabled() >= all[1].capabilities.count_enabled()
            );
        }
    }

    #[test]
    fn registry_by_family_mips() {
        let r = ArchRegistryFull::with_builtins();
        let mips = r.by_family("mips");
        assert!(!mips.is_empty());
        for e in &mips {
            assert_eq!(e.family, "mips");
        }
    }

    #[test]
    fn registry_by_family_ppc() {
        let r = ArchRegistryFull::with_builtins();
        let ppc = r.by_family("ppc");
        assert!(!ppc.is_empty());
    }

    #[test]
    fn auto_detect_elf_arm32() {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(b"\x7FELF");
        buf[4] = 1; // 32-bit
        buf[18] = 0x28;
        buf[19] = 0x00; // EM_ARM
        let hint = AutoDetect.probe(&buf);
        let id = AutoDetect.suggest_id(&hint);
        assert_eq!(id.as_deref(), Some("arm32"));
    }

    #[test]
    fn auto_detect_elf_arm64() {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(b"\x7FELF");
        buf[4] = 2; // 64-bit
        buf[18] = 0xB7;
        buf[19] = 0x00; // EM_AARCH64
        let hint = AutoDetect.probe(&buf);
        let id = AutoDetect.suggest_id(&hint);
        assert_eq!(id.as_deref(), Some("arm64"));
    }

    #[test]
    fn auto_detect_macho_x86_64() {
        let mut buf = vec![0u8; 32];
        // 64-bit LE Mach-O: 0xFEEDFACF
        buf[0..4].copy_from_slice(&0xFEED_FACF_u32.to_be_bytes());
        // BE magic 0xFEEDFACF: probe reads cpu_type big-endian. cpu_type 7
        // combined with the 64-bit magic resolves to x86_64.
        buf[4..8].copy_from_slice(&7u32.to_be_bytes()); // cpu_type=7 BE
        let hint = AutoDetect.probe(&buf);
        let id = AutoDetect.suggest_id(&hint);
        assert_eq!(id.as_deref(), Some("x86_64"));
    }

    #[test]
    fn detection_hint_family_fallback() {
        let hint = DetectionHint {
            family_hint: Some("risc-v".into()),
            ..Default::default()
        };
        let id = AutoDetect.suggest_id(&hint);
        assert_eq!(id.as_deref(), Some("risc-v"));
    }

    #[test]
    fn compat_bi_endian_interoperable() {
        let a = make_entry("arm32", "arm", 4, Endianness::Bi)
            .with_capabilities(ArchCapabilities::full());
        let b = make_entry("arm32be", "arm", 4, Endianness::Big)
            .with_capabilities(ArchCapabilities::full());
        let c = ArchCompatibility::compute(&a, &b);
        assert!(c.interoperable);
    }

    #[test]
    fn arch_entry_tags_stored() {
        let e = make_entry("x", "x", 4, Endianness::Little).with_tags(&["embedded", "arm"]);
        assert!(e.tags.contains(&"embedded".to_string()));
        assert!(e.tags.contains(&"arm".to_string()));
    }

    #[test]
    fn registry_all_returns_all() {
        let r = ArchRegistryFull::with_builtins();
        assert_eq!(r.all().len(), r.len());
    }

    #[test]
    fn selector_required_decompile_filters() {
        let r = ArchRegistryFull::with_builtins();
        let criteria = SelectionCriteria {
            required_capabilities: ArchCapabilities::DECOMPILE,
            ..Default::default()
        };
        let result = r.select(&criteria);
        if let Ok(e) = result {
            assert!(e.capabilities.contains(ArchCapabilities::DECOMPILE));
        }
    }

    #[test]
    fn arch_entry_description() {
        let e = make_entry("x", "x", 4, Endianness::Little).with_description("my desc");
        assert_eq!(e.description, "my desc");
    }
}
