//! `m68k_os_abi` — Motorola 68000 OS-level ABI analysis: Amiga OS, classic
//! Mac OS, trampoline patterns, A5 world relative offsets, and jump tables.
//!
//! Provides:
//! * [`AmigaABI`]            — Amiga OS library call patterns via A6
//! * [`MacOS68kABI`]         — Classic Mac OS A-Trap and toolbox patterns
//! * [`TrampolinePattern`]   — detect 68k trampoline stubs
//! * [`A5WorldRelative`]     — A5-relative data/code offsets (Mac OS)
//! * [`JumpTable`]           — jump table detection and analysis
//! * [`M68kOsAbi`]           — top-level facade

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

// ---------------------------------------------------------------------------
// Amiga ABI
// ---------------------------------------------------------------------------

/// An Amiga OS library function descriptor.
#[derive(Debug, Clone)]
pub struct AmigaLibFunc {
    /// LVO (Library Vector Offset) — negative offset from library base in A6.
    pub lvo: i16,
    /// Function name.
    pub name: String,
    /// Library this function belongs to.
    pub library: String,
}

/// Amiga OS ABI call pattern analyzer.
///
/// Amiga OS library calls follow the pattern:
/// ```asm
/// MOVEA.L  <lib_base>, A6
/// JSR      -<lvo>(A6)
/// ```
#[derive(Debug, Clone, Default)]
pub struct AmigaABI {
    /// Known library functions indexed by (`library_name`, `lvo`).
    known_functions: HashMap<(String, i16), String>,
    /// Detected library calls: address → `AmigaLibFunc`.
    pub detected_calls: Vec<(u64, AmigaLibFunc)>,
    /// Set of library names referenced.
    pub libraries: HashSet<String>,
}

impl AmigaABI {
    /// Create a new Amiga ABI detector with common library entries pre-loaded.
    #[must_use]
    pub fn new() -> Self {
        let mut this = Self::default();
        // exec.library
        this.register("exec", -6, "Supervisor");
        this.register("exec", -30, "OpenLibrary");
        this.register("exec", -36, "CloseLibrary");
        this.register("exec", -42, "FindTask");
        this.register("exec", -132, "AllocMem");
        this.register("exec", -138, "FreeMem");
        this.register("exec", -198, "ObtainSemaphore");
        this.register("exec", -204, "ReleaseSemaphore");
        this.register("exec", -228, "AddIntServer");
        this.register("exec", -234, "RemIntServer");
        // dos.library
        this.register("dos", -30, "Open");
        this.register("dos", -36, "Close");
        this.register("dos", -42, "Read");
        this.register("dos", -48, "Write");
        this.register("dos", -60, "DeleteFile");
        this.register("dos", -198, "Execute");
        // graphics.library
        this.register("graphics", -306, "BltBitMap");
        this.register("graphics", -324, "DrawEllipse");
        this
    }

    /// Register a library function LVO.
    pub fn register(&mut self, library: &str, lvo: i16, name: &str) {
        self.known_functions
            .insert((library.to_string(), lvo), name.to_string());
    }

    /// Attempt to identify a JSR to library call at `address`.
    /// `lvo` is the displacement from A6 (negative).
    /// Returns `Some(func_name)` if the LVO is known for `library`.
    #[must_use]
    pub fn identify_call(&self, library: &str, lvo: i16) -> Option<&str> {
        self.known_functions
            .get(&(library.to_string(), lvo))
            .map(String::as_str)
    }

    /// Record a detected Amiga library call.
    pub fn record_call(&mut self, address: u64, library: String, lvo: i16) {
        let name = self
            .known_functions
            .get(&(library.clone(), lvo))
            .cloned()
            .unwrap_or_else(|| format!("unknown_lvo_{lvo}"));
        self.libraries.insert(library.clone());
        self.detected_calls
            .push((address, AmigaLibFunc { lvo, name, library }));
    }

    /// Number of detected calls.
    #[must_use]
    pub const fn call_count(&self) -> usize {
        self.detected_calls.len()
    }

    /// Whether `exec.library` is used.
    #[must_use]
    pub fn uses_exec(&self) -> bool {
        self.libraries.contains("exec")
    }
}

// ---------------------------------------------------------------------------
// Mac OS 68k ABI
// ---------------------------------------------------------------------------

/// An A-Trap descriptor.
#[derive(Debug, Clone)]
pub struct ATrap {
    /// Trap word (0xA000–0xAFFF).
    pub trap_word: u16,
    /// Toolbox routine name.
    pub name: String,
    /// Whether it is an OS trap (bit 9 = 0) vs Toolbox trap (bit 9 = 1).
    pub is_toolbox: bool,
}

impl ATrap {
    /// Check whether `word` is an A-Trap.
    #[must_use]
    pub const fn is_trap(word: u16) -> bool {
        (word >> 12) == 0xA
    }

    /// Whether this trap is a Toolbox trap (bit 11 set in lower nibble context).
    #[must_use]
    pub const fn toolbox_flag(trap_word: u16) -> bool {
        (trap_word & 0x0800) != 0
    }
}

/// Classic Mac OS 68k ABI — A-Trap dispatcher.
#[derive(Debug, Clone, Default)]
pub struct MacOS68kABI {
    /// Known A-Trap descriptors keyed by trap word.
    known_traps: HashMap<u16, String>,
    /// Detected trap calls: (address, `ATrap`).
    pub detected_traps: Vec<(u64, ATrap)>,
}

impl MacOS68kABI {
    /// Create a Mac OS ABI analyzer with common traps pre-loaded.
    #[must_use]
    pub fn new() -> Self {
        let mut this = Self::default();
        // Common Toolbox traps
        this.register(0xA000, "_Open");
        this.register(0xA001, "_Close");
        this.register(0xA002, "_Read");
        this.register(0xA003, "_Write");
        this.register(0xA00C, "_GetFileInfo");
        this.register(0xA00D, "_SetFileInfo");
        this.register(0xA011, "_GetEOF");
        this.register(0xA012, "_SetEOF");
        this.register(0xA9EB, "_NewHandle");
        this.register(0xA9EC, "_HLock");
        this.register(0xA9ED, "_HUnlock");
        this.register(0xA9F2, "_DisposeHandle");
        this.register(0xA9C0, "_NewPtr");
        this.register(0xA01F, "_DisposePtr");
        this.register(0xA9B4, "_DrawString");
        this.register(0xA9A0, "_GetResource");
        this.register(0xA9A1, "_ReleaseResource");
        this.register(0xA87B, "_ExitToShell");
        this
    }

    /// Register a known A-Trap.
    pub fn register(&mut self, trap_word: u16, name: &str) {
        self.known_traps.insert(trap_word, name.to_string());
    }

    /// Identify a trap word.
    #[must_use]
    pub fn identify(&self, trap_word: u16) -> Option<&str> {
        self.known_traps.get(&trap_word).map(String::as_str)
    }

    /// Record a trap invocation.
    pub fn record_trap(&mut self, address: u64, trap_word: u16) {
        let name = self
            .known_traps
            .get(&trap_word)
            .cloned()
            .unwrap_or_else(|| format!("_Trap_{trap_word:#06x}"));
        let is_toolbox = ATrap::toolbox_flag(trap_word);
        self.detected_traps.push((
            address,
            ATrap {
                trap_word,
                name,
                is_toolbox,
            },
        ));
    }

    /// Number of recorded traps.
    #[must_use]
    pub const fn trap_count(&self) -> usize {
        self.detected_traps.len()
    }

    /// Whether any OS traps (non-Toolbox) were detected.
    #[must_use]
    pub fn has_os_traps(&self) -> bool {
        self.detected_traps.iter().any(|(_, t)| !t.is_toolbox)
    }
}

// ---------------------------------------------------------------------------
// Trampoline Pattern
// ---------------------------------------------------------------------------

/// A detected 68k trampoline stub.
#[derive(Debug, Clone)]
pub struct TrampolineStub {
    /// Address of the trampoline.
    pub address: u64,
    /// Target address the trampoline jumps to.
    pub target: u64,
    /// Trampoline variant.
    pub kind: TrampolineKind,
}

/// Trampoline variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrampolineKind {
    /// `JMP (target).l` — absolute long jump.
    AbsoluteJmp,
    /// `JSR (target).l` — absolute long call.
    AbsoluteJsr,
    /// A5-relative: `JMP <offset>(A5)`.
    A5Relative,
    /// Short branch chain.
    BranchChain,
}

impl fmt::Display for TrampolineKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::AbsoluteJmp => "absolute_jmp",
            Self::AbsoluteJsr => "absolute_jsr",
            Self::A5Relative => "a5_relative",
            Self::BranchChain => "branch_chain",
        };
        f.write_str(s)
    }
}

/// Trampoline pattern detector.
#[derive(Debug, Clone, Default)]
pub struct TrampolinePattern {
    /// Detected trampolines.
    pub trampolines: Vec<TrampolineStub>,
}

impl TrampolinePattern {
    /// Create a new trampoline detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt to detect a trampoline in 6–10 bytes.
    ///
    /// Patterns recognized (big-endian):
    /// - `4E F9 xx xx xx xx` — JMP (abs.l)
    /// - `4E B9 xx xx xx xx` — JSR (abs.l)
    #[must_use]
    pub fn detect(bytes: &[u8], address: u64) -> Option<TrampolineStub> {
        if bytes.len() < 6 {
            return None;
        }
        match (bytes[0], bytes[1]) {
            (0x4E, 0xF9) => {
                let target = u64::from(u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]));
                Some(TrampolineStub {
                    address,
                    target,
                    kind: TrampolineKind::AbsoluteJmp,
                })
            }
            (0x4E, 0xB9) => {
                let target = u64::from(u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]));
                Some(TrampolineStub {
                    address,
                    target,
                    kind: TrampolineKind::AbsoluteJsr,
                })
            }
            _ => None,
        }
    }

    /// Record a detected trampoline.
    pub fn record(&mut self, stub: TrampolineStub) {
        self.trampolines.push(stub);
    }

    /// Scan a code region for trampolines.
    pub fn scan(&mut self, bytes: &[u8], base: u64) {
        let mut off = 0;
        while off + 6 <= bytes.len() {
            if let Some(stub) = Self::detect(&bytes[off..], base + off as u64) {
                let advance = 6;
                self.record(stub);
                off += advance;
            } else {
                off += 2;
            }
        }
    }

    /// Number of detected trampolines.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.trampolines.len()
    }
}

// ---------------------------------------------------------------------------
// A5 World Relative
// ---------------------------------------------------------------------------

/// An A5-relative reference.
#[derive(Debug, Clone)]
pub struct A5Ref {
    /// Address of the instruction.
    pub instruction_addr: u64,
    /// Offset from A5.
    pub offset: i32,
    /// Whether it is negative (data below A5, jump table above).
    pub is_negative: bool,
    /// Whether it's a code reference (jump table entry) or data reference.
    pub is_code: bool,
}

/// A5-world relative data/code analysis for classic Mac OS.
///
/// In classic Mac OS, A5 points to the middle of the application global area.
/// - Above A5: jump table entries.
/// - Below A5: application globals and `QuickDraw` globals.
#[derive(Debug, Clone, Default)]
pub struct A5WorldRelative {
    /// A5 base address.
    pub a5_base: u64,
    /// Detected A5-relative references.
    pub references: Vec<A5Ref>,
    /// Detected jump table entries (above A5).
    pub jump_table: BTreeMap<i32, u64>,
}

impl A5WorldRelative {
    /// Create an A5 world analyzer.
    #[must_use]
    pub fn new(a5_base: u64) -> Self {
        Self {
            a5_base,
            ..Default::default()
        }
    }

    /// Record an A5-relative reference.
    pub fn record_reference(&mut self, instruction_addr: u64, offset: i32, is_code: bool) {
        let is_negative = offset < 0;
        self.references.push(A5Ref {
            instruction_addr,
            offset,
            is_negative,
            is_code,
        });
        if !is_negative && is_code {
            // Positive offsets → jump table
            let target = self.a5_base.wrapping_add_signed(i64::from(offset));
            self.jump_table.insert(offset, target);
        }
    }

    /// Absolute address of an A5-relative reference.
    #[must_use]
    pub fn absolute_addr(&self, offset: i32) -> u64 {
        self.a5_base.wrapping_add_signed(i64::from(offset))
    }

    /// Number of jump table entries.
    #[must_use]
    pub fn jump_table_size(&self) -> usize {
        self.jump_table.len()
    }

    /// Data references (negative offsets).
    #[must_use]
    pub fn data_refs(&self) -> Vec<&A5Ref> {
        self.references.iter().filter(|r| r.is_negative).collect()
    }

    /// Code references (positive offsets into jump table area).
    #[must_use]
    pub fn code_refs(&self) -> Vec<&A5Ref> {
        self.references
            .iter()
            .filter(|r| !r.is_negative && r.is_code)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Jump Table
// ---------------------------------------------------------------------------

/// A single jump table entry.
#[derive(Debug, Clone)]
pub struct JumpTableEntry {
    /// Index in the table.
    pub index: usize,
    /// Address of the table slot.
    pub slot_address: u64,
    /// Jump target.
    pub target: u64,
    /// Whether this entry has been resolved.
    pub resolved: bool,
}

/// Jump table (switch statement dispatch) detector for 68k code.
#[derive(Debug, Clone, Default)]
pub struct JumpTable {
    /// Base address of the table.
    pub base: u64,
    /// Entries.
    pub entries: Vec<JumpTableEntry>,
    /// Default case target (if detected).
    pub default_target: Option<u64>,
}

impl JumpTable {
    /// Create a new jump table at `base`.
    #[must_use]
    pub fn new(base: u64) -> Self {
        Self {
            base,
            ..Default::default()
        }
    }

    /// Add an entry to the jump table.
    pub fn add_entry(&mut self, slot_address: u64, target: u64) {
        let index = self.entries.len();
        self.entries.push(JumpTableEntry {
            index,
            slot_address,
            target,
            resolved: true,
        });
    }

    /// Parse a 68k word-sized jump table from bytes.
    /// Each 2-byte entry is a signed displacement from `base`.
    pub fn parse_word_table(&mut self, bytes: &[u8], base: u64, count: usize) {
        self.base = base;
        for i in 0..count {
            let off = i * 2;
            if off + 2 > bytes.len() {
                break;
            }
            let disp = i64::from(i16::from_be_bytes([bytes[off], bytes[off + 1]]));
            let target = base.wrapping_add_signed(disp);
            let slot_address = base + off as u64;
            self.add_entry(slot_address, target);
        }
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Unique target set.
    #[must_use]
    pub fn unique_targets(&self) -> HashSet<u64> {
        self.entries.iter().map(|e| e.target).collect()
    }
}

// ---------------------------------------------------------------------------
// Top-level facade
// ---------------------------------------------------------------------------

/// Analysis finding.
#[derive(Debug, Clone)]
pub struct OsAbiFinding {
    pub address: u64,
    pub message: String,
}

/// Top-level M68k OS ABI analysis facade.
#[derive(Debug, Clone)]
pub struct M68kOsAbi {
    /// Amiga OS ABI detector.
    pub amiga: AmigaABI,
    /// Mac OS ABI detector.
    pub macos: MacOS68kABI,
    /// Trampoline pattern detector.
    pub trampolines: TrampolinePattern,
    /// A5 world analyzer (Mac OS).
    pub a5_world: Option<A5WorldRelative>,
    /// Jump tables detected.
    pub jump_tables: Vec<JumpTable>,
    /// Findings.
    pub findings: Vec<OsAbiFinding>,
    /// Total instructions.
    pub total_instructions: usize,
}

impl Default for M68kOsAbi {
    fn default() -> Self {
        Self::new()
    }
}

impl M68kOsAbi {
    /// Create a new M68k OS ABI analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            amiga: AmigaABI::new(),
            macos: MacOS68kABI::new(),
            trampolines: TrampolinePattern::new(),
            a5_world: None,
            jump_tables: Vec::new(),
            findings: Vec::new(),
            total_instructions: 0,
        }
    }

    /// Enable Mac OS A5-world analysis with the given A5 base.
    pub fn enable_macos(&mut self, a5_base: u64) {
        self.a5_world = Some(A5WorldRelative::new(a5_base));
    }

    /// Record an A-Trap encounter.
    pub fn record_trap(&mut self, address: u64, trap_word: u16) {
        self.macos.record_trap(address, trap_word);
        let name = self
            .macos
            .identify(trap_word)
            .map_or_else(|| format!("{trap_word:#06x}"), str::to_string);
        self.findings.push(OsAbiFinding {
            address,
            message: format!("A-Trap {name}"),
        });
    }

    /// Record an Amiga library call.
    pub fn record_amiga_call(&mut self, address: u64, library: &str, lvo: i16) {
        let func = self
            .amiga
            .identify_call(library, lvo)
            .map_or_else(|| format!("lvo={lvo}"), str::to_string);
        self.amiga.record_call(address, library.to_string(), lvo);
        self.findings.push(OsAbiFinding {
            address,
            message: format!("{library}:{func}"),
        });
    }

    /// Add a detected jump table.
    pub fn add_jump_table(&mut self, jt: JumpTable) {
        self.findings.push(OsAbiFinding {
            address: jt.base,
            message: format!("jump table ({} entries)", jt.len()),
        });
        self.jump_tables.push(jt);
    }

    /// Whether Amiga OS patterns are detected.
    #[must_use]
    pub const fn is_amiga(&self) -> bool {
        !self.amiga.detected_calls.is_empty()
    }

    /// Whether Mac OS patterns are detected.
    #[must_use]
    pub const fn is_macos(&self) -> bool {
        !self.macos.detected_traps.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── AmigaABI ──────────────────────────────────────────────────────────────

    #[test]
    fn test_amiga_identify_known() {
        let abi = AmigaABI::new();
        assert_eq!(abi.identify_call("exec", -30), Some("OpenLibrary"));
        assert_eq!(abi.identify_call("exec", -132), Some("AllocMem"));
    }

    #[test]
    fn test_amiga_identify_unknown() {
        let abi = AmigaABI::new();
        assert!(abi.identify_call("exec", -999).is_none());
    }

    #[test]
    fn test_amiga_record_call() {
        let mut abi = AmigaABI::new();
        abi.record_call(0x1000, "exec".to_string(), -30);
        assert_eq!(abi.call_count(), 1);
        assert!(abi.uses_exec());
    }

    #[test]
    fn test_amiga_dos_identify() {
        let abi = AmigaABI::new();
        assert_eq!(abi.identify_call("dos", -30), Some("Open"));
        assert_eq!(abi.identify_call("dos", -36), Some("Close"));
    }

    #[test]
    fn test_amiga_custom_register() {
        let mut abi = AmigaABI::new();
        abi.register("custom", -12, "MyFunc");
        assert_eq!(abi.identify_call("custom", -12), Some("MyFunc"));
    }

    #[test]
    fn test_amiga_libraries_set() {
        let mut abi = AmigaABI::new();
        abi.record_call(0x1000, "exec".to_string(), -30);
        abi.record_call(0x1004, "dos".to_string(), -30);
        assert_eq!(abi.libraries.len(), 2);
    }

    // ── MacOS68kABI ───────────────────────────────────────────────────────────

    #[test]
    fn test_macos_identify_known_trap() {
        let abi = MacOS68kABI::new();
        assert_eq!(abi.identify(0xA9EB), Some("_NewHandle"));
    }

    #[test]
    fn test_macos_identify_unknown() {
        let abi = MacOS68kABI::new();
        assert!(abi.identify(0xA999).is_none());
    }

    #[test]
    fn test_macos_record_trap() {
        let mut abi = MacOS68kABI::new();
        abi.record_trap(0x2000, 0xA9EB);
        assert_eq!(abi.trap_count(), 1);
    }

    #[test]
    fn test_atrap_is_trap() {
        assert!(ATrap::is_trap(0xA000));
        assert!(ATrap::is_trap(0xAFFF));
        assert!(!ATrap::is_trap(0x4E75));
    }

    #[test]
    fn test_atrap_toolbox_flag() {
        assert!(!ATrap::toolbox_flag(0xA000));
        assert!(ATrap::toolbox_flag(0xA800));
    }

    #[test]
    fn test_macos_has_os_traps() {
        let mut abi = MacOS68kABI::new();
        abi.record_trap(0x1000, 0xA000); // OS trap (bit 11 = 0)
        assert!(abi.has_os_traps());
    }

    // ── TrampolinePattern ─────────────────────────────────────────────────────

    #[test]
    fn test_trampoline_detect_jmp() {
        let bytes = [0x4E, 0xF9, 0x00, 0x01, 0x00, 0x00];
        let stub = TrampolinePattern::detect(&bytes, 0x1000).unwrap();
        assert_eq!(stub.kind, TrampolineKind::AbsoluteJmp);
        assert_eq!(stub.target, 0x0001_0000);
    }

    #[test]
    fn test_trampoline_detect_jsr() {
        let bytes = [0x4E, 0xB9, 0x00, 0x02, 0x00, 0x00];
        let stub = TrampolinePattern::detect(&bytes, 0x1000).unwrap();
        assert_eq!(stub.kind, TrampolineKind::AbsoluteJsr);
        assert_eq!(stub.target, 0x0002_0000);
    }

    #[test]
    fn test_trampoline_detect_none() {
        let bytes = [0x4E, 0x75]; // RTS
        assert!(TrampolinePattern::detect(&bytes, 0x0).is_none());
    }

    #[test]
    fn test_trampoline_scan() {
        let mut tp = TrampolinePattern::new();
        let bytes = [
            0x4E, 0xF9, 0x00, 0x01, 0x00, 0x00, // JMP
            0x4E, 0xB9, 0x00, 0x02, 0x00, 0x00, // JSR
        ];
        tp.scan(&bytes, 0x0);
        assert_eq!(tp.count(), 2);
    }

    #[test]
    fn test_trampoline_kind_display() {
        assert_eq!(TrampolineKind::AbsoluteJmp.to_string(), "absolute_jmp");
        assert_eq!(TrampolineKind::A5Relative.to_string(), "a5_relative");
    }

    // ── A5WorldRelative ───────────────────────────────────────────────────────

    #[test]
    fn test_a5_absolute_addr_positive() {
        let a5 = A5WorldRelative::new(0x10000);
        assert_eq!(a5.absolute_addr(8), 0x10008);
    }

    #[test]
    fn test_a5_absolute_addr_negative() {
        let a5 = A5WorldRelative::new(0x10000);
        assert_eq!(a5.absolute_addr(-8), 0x0FFF8);
    }

    #[test]
    fn test_a5_record_data_ref() {
        let mut a5 = A5WorldRelative::new(0x10000);
        a5.record_reference(0x1000, -64, false);
        assert_eq!(a5.data_refs().len(), 1);
        assert_eq!(a5.code_refs().len(), 0);
    }

    #[test]
    fn test_a5_record_code_ref() {
        let mut a5 = A5WorldRelative::new(0x10000);
        a5.record_reference(0x1000, 32, true);
        assert_eq!(a5.code_refs().len(), 1);
        assert_eq!(a5.jump_table_size(), 1);
    }

    #[test]
    fn test_a5_jump_table_target() {
        let mut a5 = A5WorldRelative::new(0x10000);
        a5.record_reference(0x1000, 32, true);
        let target = *a5.jump_table.get(&32).unwrap();
        assert_eq!(target, 0x10020);
    }

    // ── JumpTable ─────────────────────────────────────────────────────────────

    #[test]
    fn test_jumptable_add_entry() {
        let mut jt = JumpTable::new(0x2000);
        jt.add_entry(0x2000, 0x3000);
        jt.add_entry(0x2002, 0x4000);
        assert_eq!(jt.len(), 2);
    }

    #[test]
    fn test_jumptable_parse_word_table() {
        let mut jt = JumpTable::new(0x2000);
        let bytes = [0x00, 0x10, 0x00, 0x20]; // disp +0x10, +0x20
        jt.parse_word_table(&bytes, 0x2000, 2);
        assert_eq!(jt.len(), 2);
        assert_eq!(jt.entries[0].target, 0x2010);
        assert_eq!(jt.entries[1].target, 0x2020);
    }

    #[test]
    fn test_jumptable_unique_targets() {
        let mut jt = JumpTable::new(0x2000);
        jt.add_entry(0x2000, 0x3000);
        jt.add_entry(0x2002, 0x3000); // duplicate target
        jt.add_entry(0x2004, 0x4000);
        assert_eq!(jt.unique_targets().len(), 2);
    }

    #[test]
    fn test_jumptable_is_empty() {
        let jt = JumpTable::new(0);
        assert!(jt.is_empty());
    }

    // ── M68kOsAbi ─────────────────────────────────────────────────────────────

    #[test]
    fn test_abi_record_trap() {
        let mut abi = M68kOsAbi::new();
        abi.record_trap(0x1000, 0xA9EB);
        assert!(abi.is_macos());
        assert_eq!(abi.findings.len(), 1);
    }

    #[test]
    fn test_abi_record_amiga_call() {
        let mut abi = M68kOsAbi::new();
        abi.record_amiga_call(0x1000, "exec", -30);
        assert!(abi.is_amiga());
        assert_eq!(abi.findings.len(), 1);
    }

    #[test]
    fn test_abi_add_jump_table() {
        let mut abi = M68kOsAbi::new();
        let mut jt = JumpTable::new(0x3000);
        jt.add_entry(0x3000, 0x4000);
        abi.add_jump_table(jt);
        assert_eq!(abi.jump_tables.len(), 1);
    }

    #[test]
    fn test_abi_enable_macos() {
        let mut abi = M68kOsAbi::new();
        abi.enable_macos(0x8000);
        assert!(abi.a5_world.is_some());
        assert_eq!(abi.a5_world.as_ref().unwrap().a5_base, 0x8000);
    }

    #[test]
    fn test_abi_default_not_amiga_not_macos() {
        let abi = M68kOsAbi::new();
        assert!(!abi.is_amiga());
        assert!(!abi.is_macos());
    }

    // ── Additional coverage ───────────────────────────────────────────────────

    #[test]
    fn test_amiga_graphics_identify() {
        let abi = AmigaABI::new();
        assert_eq!(abi.identify_call("graphics", -306), Some("BltBitMap"));
    }

    #[test]
    fn test_amiga_multiple_calls_count() {
        let mut abi = AmigaABI::new();
        abi.record_call(0x1000, "exec".to_string(), -30);
        abi.record_call(0x1004, "exec".to_string(), -132);
        abi.record_call(0x1008, "dos".to_string(), -30);
        assert_eq!(abi.call_count(), 3);
        assert_eq!(abi.libraries.len(), 2);
    }

    #[test]
    fn test_macos_register_and_identify() {
        let mut abi = MacOS68kABI::new();
        abi.register(0xA123, "_MyTrap");
        assert_eq!(abi.identify(0xA123), Some("_MyTrap"));
    }

    #[test]
    fn test_trampoline_detect_too_short() {
        assert!(TrampolinePattern::detect(&[0x4E], 0).is_none());
    }

    #[test]
    fn test_a5_multiple_refs() {
        let mut a5 = A5WorldRelative::new(0x10000);
        a5.record_reference(0x1000, -100, false);
        a5.record_reference(0x1002, -200, false);
        a5.record_reference(0x1004, 32, true);
        assert_eq!(a5.data_refs().len(), 2);
        assert_eq!(a5.code_refs().len(), 1);
    }

    #[test]
    fn test_jumptable_word_table_negative_disp() {
        let mut jt = JumpTable::new(0x2000);
        // Negative displacement: -16 = 0xFFF0 as big-endian i16
        let neg = (-16i16).to_be_bytes();
        let bytes = [neg[0], neg[1], 0x00, 0x10];
        jt.parse_word_table(&bytes, 0x2000, 2);
        assert_eq!(jt.len(), 2);
        assert_eq!(jt.entries[0].target, 0x1FF0); // 0x2000 - 16
    }

    #[test]
    fn test_abi_multiple_findings() {
        let mut abi = M68kOsAbi::new();
        abi.record_trap(0x1000, 0xA9EB);
        abi.record_trap(0x1002, 0xA9EC);
        abi.record_amiga_call(0x2000, "exec", -30);
        assert_eq!(abi.findings.len(), 3);
        assert!(abi.is_macos());
        assert!(abi.is_amiga());
    }
}
