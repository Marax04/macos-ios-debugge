//! AVR binary analysis: function detection, interrupt map, string scanning, and SREG liveness.

use crate::AvrArch;
use rustre_core::arch::{Architecture, InstrFlags};
use rustre_core::address::Address;

// ---------------------------------------------------------------------------
// Function detector
// ---------------------------------------------------------------------------

/// A detected AVR function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvrFunction {
    /// Byte address of the function entry point.
    pub entry: u32,
    /// How the function was found.
    pub source: FunctionSource,
}

/// How an AVR function was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FunctionSource {
    /// Entry point is the RESET vector (address 0).
    ResetVector,
    /// Called via a CALL or RCALL instruction.
    CallTarget,
    /// Detected by a PUSH R28/R29 prologue pattern.
    FrameSetup,
    /// Interrupt service routine (vector index).
    InterruptVector(usize),
}

/// Detects AVR function entry points from a flat binary image.
pub struct AvrFunctionDetector<'a> {
    arch: AvrArch,
    flash: &'a [u8],
    base: u32,
}

impl<'a> AvrFunctionDetector<'a> {
    /// Create a new detector for `flash` bytes starting at byte address `base`.
    #[must_use]
    pub fn new(flash: &'a [u8], base: u32) -> Self {
        Self {
            arch: AvrArch::default(),
            flash,
            base,
        }
    }

    /// Run full analysis and return all discovered functions.
    #[must_use]
    pub fn detect(&self) -> Vec<AvrFunction> {
        let mut funcs: Vec<AvrFunction> = Vec::new();
        // BTreeSet instead of HashSet: flash-derived addresses are attacker-controlled,
        // so a HashSet would be vulnerable to hash-collision DoS.
        let mut seen: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();

        // RESET vector at address 0 is always an entry point.
        self.add_func(0, FunctionSource::ResetVector, &mut funcs, &mut seen);

        // Scan for CALL/RCALL and PUSH R28/R29 patterns
        let mut offset = 0usize;
        while offset + 1 < self.flash.len() {
            let word = u16::from_le_bytes([self.flash[offset], self.flash[offset + 1]]);
            let pc = self.base + u32::try_from(offset).unwrap_or(u32::MAX);

            // RCALL k: 0xD000..0xDFFF → target is a function
            if (word & 0xF000) == 0xD000 {
                let k = sign_ext_12(word);
                let target = pc.wrapping_add(2).wrapping_add_signed(k * 2);
                self.add_func(target, FunctionSource::CallTarget, &mut funcs, &mut seen);
            }

            // CALL k (32-bit): 0x940E → target in next word
            if (word & 0xFE0E) == 0x940E && offset + 3 < self.flash.len() {
                let next = u16::from_le_bytes([self.flash[offset + 2], self.flash[offset + 3]]);
                let k_hi = u32::from((word & 0x01F0) >> 3) | u32::from(word & 1);
                let target = ((k_hi << 16) | u32::from(next)) * 2;
                self.add_func(target, FunctionSource::CallTarget, &mut funcs, &mut seen);
            }

            // PUSH R28 (0x920F with r=28 = 0x930F) or PUSH R29 = detect frame setup
            // PUSH Rr: 0xFE0F == 0x920F, r = (word>>4) & 0x1F
            if (word & 0xFE0F) == 0x920F {
                let r = ((word >> 4) & 0x1F) as u8;
                if r == 28 {
                    // Check if next instruction is also a PUSH with R29
                    if offset + 3 < self.flash.len() {
                        let next =
                            u16::from_le_bytes([self.flash[offset + 2], self.flash[offset + 3]]);
                        if (next & 0xFE0F) == 0x920F && ((next >> 4) & 0x1F) == 29 {
                            // If addr already seen (e.g. reset vector), update its source
                            if seen.contains(&pc) {
                                if let Some(f) = funcs.iter_mut().find(|f| f.entry == pc) {
                                    f.source = FunctionSource::FrameSetup;
                                }
                            } else {
                                self.add_func(pc, FunctionSource::FrameSetup, &mut funcs, &mut seen);
                            }
                        }
                    }
                }
            }

            offset += 2;
        }

        funcs.sort_by_key(|f| f.entry);
        funcs
    }

    fn add_func(
        &self,
        addr: u32,
        src: FunctionSource,
        funcs: &mut Vec<AvrFunction>,
        seen: &mut std::collections::BTreeSet<u32>,
    ) {
        let byte_len = u32::try_from(self.flash.len()).unwrap_or(u32::MAX);
        if addr >= byte_len {
            return;
        }
        if seen.insert(addr) {
            funcs.push(AvrFunction {
                entry: addr,
                source: src,
            });
        }
    }

    /// Linear disassembly of flash, returning all decoded instructions.
    #[must_use]
    pub fn disasm_all(&self) -> Vec<(u32, String, String)> {
        // Each AVR instruction is at least 2 bytes; pre-size to that upper bound.
        // Cap to 64 Ki entries so untrusted flash images cannot trigger an OOM
        // through Vec::with_capacity on the initial allocation.
        let mut result = Vec::with_capacity((self.flash.len() / 2).min(65536));
        let mut offset = 0usize;
        while offset < self.flash.len() {
            let pc = self.base + u32::try_from(offset).unwrap_or(u32::MAX);
            let remaining = &self.flash[offset..];
            match self
                .arch
                .disassemble(Address::new(u64::from(pc)), remaining)
            {
                Ok(instr) => {
                    result.push((pc, instr.mnemonic.clone(), instr.operands.clone()));
                    offset += instr.size;
                }
                Err(_) => {
                    offset += 2;
                }
            }
        }
        result
    }

    /// Linear scan returning the byte address of every instruction whose
    /// decoded `InstrFlags` intersect `mask` (e.g. CALL / BRANCH / RET).
    #[must_use]
    pub fn disasm_with_flags(&self, mask: InstrFlags) -> Vec<u32> {
        let mut result = Vec::new();
        let mut offset = 0usize;
        while offset < self.flash.len() {
            let pc = self.base + u32::try_from(offset).unwrap_or(u32::MAX);
            let remaining = &self.flash[offset..];
            match self
                .arch
                .disassemble(Address::new(u64::from(pc)), remaining)
            {
                Ok(instr) => {
                    if instr.flags.intersects(mask) {
                        result.push(pc);
                    }
                    offset += instr.size;
                }
                Err(_) => {
                    offset += 2;
                }
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Interrupt map
// ---------------------------------------------------------------------------

/// The AVR interrupt vector table layout.
///
/// On `ATmega328P` the reset/interrupt vectors start at word address 0 (byte 0).
/// Each vector occupies one instruction word (2 bytes).
#[derive(Debug, Clone)]
pub struct AvrInterruptMap {
    /// Extracted vector byte addresses (handler targets).
    pub vectors: Vec<AvrInterruptEntry>,
}

/// A single entry in the AVR interrupt map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvrInterruptEntry {
    /// Vector index (0 = RESET).
    pub index: usize,
    /// Name of this interrupt.
    pub name: &'static str,
    /// Byte address of the handler (0 means not installed).
    pub handler_addr: u32,
}

impl AvrInterruptMap {
    /// Extract the interrupt map from the first `vector_count` words of `flash`.
    ///
    /// Each vector is expected to be a `JMP target` (32-bit: 4 bytes) or
    /// `RJMP target` (2 bytes) instruction.
    #[must_use]
    pub fn extract(flash: &[u8], vector_count: usize) -> Self {
        let names = crate::avr_emulator::INT_VECTOR_NAMES;
        let mut vectors = Vec::new();
        for (i, &name) in names[..vector_count.min(names.len())].iter().enumerate() {
            let byte_off = i * 4; // ATmega328P uses JMP (4-byte vectors)
            let handler_addr = if flash.len() >= byte_off + 4 {
                let word0 = u16::from_le_bytes([flash[byte_off], flash[byte_off + 1]]);
                if (word0 & 0xFE0E) == 0x940C {
                    // JMP instruction: extract target
                    let word1 = u16::from_le_bytes([flash[byte_off + 2], flash[byte_off + 3]]);
                    let k_hi = u32::from((word0 & 0x01F0) >> 3) | u32::from(word0 & 1);
                    ((k_hi << 16) | u32::from(word1)) * 2
                } else if (word0 & 0xF000) == 0xC000 {
                    // RJMP instruction
                    let k = sign_ext_12(word0);
                    u32::try_from(byte_off).unwrap_or(u32::MAX).wrapping_add(2).wrapping_add_signed(k * 2)
                } else {
                    0
                }
            } else {
                0
            };
            vectors.push(AvrInterruptEntry {
                index: i,
                name,
                handler_addr,
            });
        }
        Self { vectors }
    }

    /// Return the handler address for a named interrupt, if found and non-zero.
    #[must_use]
    pub fn handler_for(&self, name: &str) -> Option<u32> {
        self.vectors
            .iter()
            .find(|e| e.name == name && e.handler_addr != 0)
            .map(|e| e.handler_addr)
    }
}

// ---------------------------------------------------------------------------
// String scanner
// ---------------------------------------------------------------------------

/// A null-terminated ASCII string found in flash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvrString {
    /// Byte address of the first character.
    pub address: u32,
    /// The string content (without the null terminator).
    pub content: String,
}

/// Scans flash memory for null-terminated ASCII strings.
pub struct AvrStringScanner;

impl AvrStringScanner {
    /// Scan `flash` for printable ASCII strings of at least `min_len` characters.
    ///
    /// Returns all found strings with their byte addresses.
    #[must_use]
    pub fn scan(flash: &[u8], min_len: usize) -> Vec<AvrString> {
        let mut result = Vec::new();
        let mut i = 0usize;

        while i < flash.len() {
            let start = i;
            let mut s = String::new();

            while i < flash.len() {
                let b = flash[i];
                if b == 0 {
                    // null terminator
                    i += 1;
                    break;
                }
                if b.is_ascii_graphic() || b == b' ' {
                    s.push(b as char);
                    i += 1;
                } else {
                    s.clear();
                    i += 1;
                    break;
                }
            }

            if s.len() >= min_len {
                result.push(AvrString {
                    address: u32::try_from(start).unwrap_or(u32::MAX),
                    content: s,
                });
            }
        }
        result
    }

    /// Scan for a specific string pattern and return the first match offset.
    #[must_use]
    pub fn find(flash: &[u8], pattern: &str) -> Option<u32> {
        let pat = pattern.as_bytes();
        flash
            .windows(pat.len())
            .position(|w| w == pat)
            .map(|i| u32::try_from(i).unwrap_or(u32::MAX))
    }
}

// ---------------------------------------------------------------------------
// SREG flag liveness
// ---------------------------------------------------------------------------

/// SREG flag bits tracked in liveness analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SregLiveness {
    pub c: bool, // Carry
    pub z: bool, // Zero
    pub n: bool, // Negative
    pub v: bool, // Overflow
    pub s: bool, // Sign
    pub h: bool, // Half-carry
    pub t: bool, // Bit-copy
    pub i: bool, // Global Interrupt Enable
}

impl SregLiveness {
    /// Return the combined SREG mask of all live flags.
    #[must_use]
    pub const fn mask(self) -> u8 {
        let mut m = 0u8;
        if self.c {
            m |= crate::avr_emulator::SREG_C;
        }
        if self.z {
            m |= crate::avr_emulator::SREG_Z;
        }
        if self.n {
            m |= crate::avr_emulator::SREG_N;
        }
        if self.v {
            m |= crate::avr_emulator::SREG_V;
        }
        if self.s {
            m |= crate::avr_emulator::SREG_S;
        }
        if self.h {
            m |= crate::avr_emulator::SREG_H;
        }
        if self.t {
            m |= crate::avr_emulator::SREG_T;
        }
        if self.i {
            m |= crate::avr_emulator::SREG_I;
        }
        m
    }

    /// All flags live.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            c: true,
            z: true,
            n: true,
            v: true,
            s: true,
            h: true,
            t: true,
            i: true,
        }
    }

    /// Merge two liveness sets (OR of live flags).
    #[must_use]
    pub const fn merge(self, other: Self) -> Self {
        Self {
            c: self.c || other.c,
            z: self.z || other.z,
            n: self.n || other.n,
            v: self.v || other.v,
            s: self.s || other.s,
            h: self.h || other.h,
            t: self.t || other.t,
            i: self.i || other.i,
        }
    }
}

/// A single liveness entry for one instruction.
#[derive(Debug, Clone)]
pub struct SregLivenessEntry {
    /// Byte address of the instruction.
    pub address: u32,
    /// Instruction mnemonic.
    pub mnemonic: String,
    /// Which SREG flags are potentially live (used) after this instruction.
    pub live_after: SregLiveness,
    /// Which SREG flags this instruction defines.
    pub defs: SregLiveness,
    /// Which SREG flags this instruction uses.
    pub uses: SregLiveness,
}

/// Performs a simplified forward SREG flag liveness analysis.
pub struct AvrSregAnalysis;

impl AvrSregAnalysis {
    /// Analyse SREG liveness across a sequence of `(address, mnemonic)` pairs
    /// (from a linear disassembly).
    ///
    /// This is a simplified forward-dataflow pass (not full dataflow).
    #[must_use]
    pub fn analyze(instrs: &[(u32, String, String)]) -> Vec<SregLivenessEntry> {
        let mut entries = Vec::with_capacity(instrs.len());
        for (addr, mnem, _ops) in instrs {
            let (defs, uses) = sreg_def_use(mnem);
            entries.push(SregLivenessEntry {
                address: *addr,
                mnemonic: mnem.clone(),
                live_after: defs, // simplified: live ≈ what is defined
                defs,
                uses,
            });
        }
        entries
    }

    /// Return all instructions that define any of the given SREG flags.
    #[must_use]
    pub fn instructions_defining(
        entries: &[SregLivenessEntry],
        mask: u8,
    ) -> Vec<&SregLivenessEntry> {
        entries
            .iter()
            .filter(|e| e.defs.mask() & mask != 0)
            .collect()
    }
}

/// Return (defs, uses) SREG flag sets for a mnemonic.
/// One bit of the AVR status register, used to name a single-bit liveness set.
#[derive(Clone, Copy)]
enum SregBitSel {
    /// Carry.
    C,
    /// Zero.
    Z,
    /// Negative.
    N,
    /// Two's-complement overflow.
    V,
    /// Sign.
    S,
    /// Half carry.
    H,
    /// Bit-copy storage.
    T,
    /// Global interrupt enable.
    I,
}

/// A liveness set containing exactly the named SREG bit.
fn only(bit: SregBitSel) -> SregLiveness {
    let mut l = SregLiveness::default();
    match bit {
        SregBitSel::C => l.c = true,
        SregBitSel::Z => l.z = true,
        SregBitSel::N => l.n = true,
        SregBitSel::V => l.v = true,
        SregBitSel::S => l.s = true,
        SregBitSel::H => l.h = true,
        SregBitSel::T => l.t = true,
        SregBitSel::I => l.i = true,
    }
    l
}

/// SREG bits written by the general arithmetic instructions.
fn arith_def() -> SregLiveness {
    SregLiveness {
        c: true,
        z: true,
        n: true,
        v: true,
        s: true,
        h: true,
        ..Default::default()
    }
}

/// SREG bits written by the logic/compare instructions (no half carry).
fn logic_def() -> SregLiveness {
    SregLiveness {
        c: true,
        z: true,
        n: true,
        v: true,
        s: true,
        ..Default::default()
    }
}

/// Conditional branches and the single SREG bit each one reads.
static BRANCH_FLAG_USE: &[(&str, SregBitSel)] = &[
    ("BRCS", SregBitSel::C),
    ("BRCC", SregBitSel::C),
    ("BREQ", SregBitSel::Z),
    ("BRNE", SregBitSel::Z),
    ("BRMI", SregBitSel::N),
    ("BRPL", SregBitSel::N),
    ("BRLT", SregBitSel::S),
    ("BRGE", SregBitSel::S),
    ("BRVS", SregBitSel::V),
    ("BRVC", SregBitSel::V),
    ("BRHS", SregBitSel::H),
    ("BRHC", SregBitSel::H),
    ("BRIE", SregBitSel::I),
    ("BRID", SregBitSel::I),
];

/// Instructions that write exactly one SREG bit and read none.
static SINGLE_BIT_DEF: &[(&str, SregBitSel)] = &[
    ("BST", SregBitSel::T),
    ("SEI", SregBitSel::I),
    ("CLI", SregBitSel::I),
    ("SEC", SregBitSel::C),
    ("CLC", SregBitSel::C),
];

/// Data-movement and control-transfer instructions that touch no SREG bit.
static SREG_NEUTRAL: &[&str] = &[
    "MOV", "LDI", "LD", "ST", "PUSH", "POP", "MOVW", "LDS", "STS", "NOP", "RET", "RETI", "CALL",
    "RCALL", "JMP", "RJMP", "IJMP", "ICALL", "SLEEP", "WDR", "BREAK",
];

/// SREG bits an instruction defines and uses, as `(def, use)`.
fn sreg_def_use(mnem: &str) -> (SregLiveness, SregLiveness) {
    let no_flags = SregLiveness::default();

    if let Some((_, bit)) = BRANCH_FLAG_USE.iter().find(|(m, _)| *m == mnem) {
        return (no_flags, only(*bit));
    }
    if let Some((_, bit)) = SINGLE_BIT_DEF.iter().find(|(m, _)| *m == mnem) {
        return (only(*bit), no_flags);
    }
    if SREG_NEUTRAL.contains(&mnem) {
        return (no_flags, no_flags);
    }

    match mnem {
        "ADD" | "SUB" | "SUBI" | "ADIW" | "SBIW" | "NEG" | "MUL" | "MULS" | "MULSU" => {
            (arith_def(), no_flags)
        }
        // Add-with-carry / subtract-with-carry: write arith flags AND read carry-in.
        "ADC" | "SBC" | "SBCI" => (arith_def(), only(SregBitSel::C)),
        "AND" | "ANDI" | "OR" | "ORI" | "EOR" | "COM" | "INC" | "DEC" | "CP" | "CPC" | "CPI" => {
            (logic_def(), no_flags)
        }
        "LSR" | "ROR" | "ASR" | "SWAP" => (logic_def(), only(SregBitSel::C)),
        "BLD" => (no_flags, only(SregBitSel::T)),
        // Any other conditional branch conservatively reads the arithmetic flags.
        _ if mnem.starts_with("BR") => (no_flags, logic_def()),
        _ => (no_flags, no_flags),
    }
}

fn sign_ext_12(raw: u16) -> i32 {
    let v = i32::from(raw & 0x0FFF);
    if v & 0x0800 != 0 { v - 0x1000 } else { v }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_detector_reset() {
        let flash = vec![0x00u8; 64]; // NOPs
        let detector = AvrFunctionDetector::new(&flash, 0);
        let funcs = detector.detect();
        assert!(!funcs.is_empty());
        assert_eq!(funcs[0].entry, 0);
        assert_eq!(funcs[0].source, FunctionSource::ResetVector);
    }

    #[test]
    fn test_function_detector_rcall() {
        // RCALL +4: k=2, 0xD002 LE=[0x02,0xD0] at offset 0 → target = 0+2+2*2=6
        let mut flash = vec![0x00u8; 64];
        flash[0] = 0x02;
        flash[1] = 0xD0;
        let detector = AvrFunctionDetector::new(&flash, 0);
        let funcs = detector.detect();
        assert!(
            funcs
                .iter()
                .any(|f| f.entry == 6 && f.source == FunctionSource::CallTarget)
        );
    }

    #[test]
    fn test_function_detector_frame_setup() {
        // Two consecutive PUSHes of R28 and R29
        // PUSH R28 = 0x930F → LE [0x0F, 0x93] … actually: 1001 001r rrrr 1111
        // r=28: 1001 0011 1100 1111 = 0x93CF LE=[0xCF,0x93]
        // r=29: 1001 0011 1101 1111 = 0x93DF LE=[0xDF,0x93]
        let mut flash = vec![0x00u8; 64];
        flash[0] = 0xCF;
        flash[1] = 0x93; // PUSH R28
        flash[2] = 0xDF;
        flash[3] = 0x93; // PUSH R29
        let detector = AvrFunctionDetector::new(&flash, 0);
        let funcs = detector.detect();
        assert!(funcs.iter().any(|f| f.source == FunctionSource::FrameSetup));
    }

    #[test]
    fn test_interrupt_map_rjmp() {
        // Place RJMP +0 (self-loop) at vector 0: word=0xCFFF LE=[0xFF,0xCF]
        let mut flash = vec![0u8; 128];
        flash[0] = 0xFF;
        flash[1] = 0xCF;
        let map = AvrInterruptMap::extract(&flash, 1);
        assert_eq!(map.vectors[0].name, "RESET");
    }

    #[test]
    fn test_interrupt_map_jmp() {
        // JMP 0x0100 at vector 0: JMP opcode 0x940C + second word 0x0080
        let mut flash = vec![0u8; 128];
        flash[0] = 0x0C;
        flash[1] = 0x94; // JMP opcode
        flash[2] = 0x80;
        flash[3] = 0x00; // target word 0x0080 → byte 0x0100
        let map = AvrInterruptMap::extract(&flash, 1);
        assert_eq!(map.vectors[0].handler_addr, 0x0100);
    }

    #[test]
    fn test_interrupt_map_handler_for() {
        let mut flash = vec![0u8; 128];
        // INT0 at byte offset 4 (vector 1) with JMP to 0x0200
        flash[4] = 0x0C;
        flash[5] = 0x94;
        flash[6] = 0x00;
        flash[7] = 0x01; // word 0x0100 → byte 0x0200
        let map = AvrInterruptMap::extract(&flash, 4);
        assert_eq!(map.handler_for("INT0"), Some(0x0200));
        assert_eq!(map.handler_for("RESET"), None);
    }

    #[test]
    fn test_string_scanner_finds_hello() {
        let flash: Vec<u8> = b"Hello\0World\0".to_vec();
        let strings = AvrStringScanner::scan(&flash, 3);
        assert!(strings.iter().any(|s| s.content == "Hello"));
        assert!(strings.iter().any(|s| s.content == "World"));
    }

    #[test]
    fn test_string_scanner_min_len() {
        let flash: Vec<u8> = b"Hi\0LongString\0".to_vec();
        let strings = AvrStringScanner::scan(&flash, 5);
        assert!(!strings.iter().any(|s| s.content == "Hi"));
        assert!(strings.iter().any(|s| s.content == "LongString"));
    }

    #[test]
    fn test_string_scanner_find() {
        let flash: Vec<u8> = b"ABCDEABCDE".to_vec();
        let pos = AvrStringScanner::find(&flash, "CDE").unwrap();
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_string_scanner_not_found() {
        let flash: Vec<u8> = b"HELLO".to_vec();
        assert!(AvrStringScanner::find(&flash, "XYZ").is_none());
    }

    #[test]
    fn test_sreg_liveness_add() {
        let (defs, _uses) = sreg_def_use("ADD");
        assert!(defs.c);
        assert!(defs.z);
        assert!(defs.n);
        assert!(defs.h);
    }

    #[test]
    fn test_sreg_liveness_breq() {
        let (_defs, uses) = sreg_def_use("BREQ");
        assert!(uses.z);
        assert!(!uses.c);
    }

    #[test]
    fn test_sreg_liveness_mov_no_flags() {
        let (defs, uses) = sreg_def_use("MOV");
        assert_eq!(defs.mask(), 0);
        assert_eq!(uses.mask(), 0);
    }

    #[test]
    fn test_sreg_liveness_merge() {
        let a = SregLiveness {
            c: true,
            z: false,
            ..Default::default()
        };
        let b = SregLiveness {
            c: false,
            z: true,
            ..Default::default()
        };
        let m = a.merge(b);
        assert!(m.c);
        assert!(m.z);
    }

    #[test]
    fn test_sreg_mask_all() {
        let all = SregLiveness::all();
        assert_eq!(all.mask(), 0xFF);
    }

    #[test]
    fn test_sreg_analysis_sequence() {
        let instrs = vec![
            (0u32, "ADD".to_string(), "R0,R1".to_string()),
            (2u32, "BREQ".to_string(), "$10".to_string()),
        ];
        let entries = AvrSregAnalysis::analyze(&instrs);
        assert_eq!(entries.len(), 2);
        assert!(entries[0].defs.z);
        assert!(entries[1].uses.z);
    }

    #[test]
    fn test_instructions_defining_carry() {
        let instrs = vec![
            (0u32, "ADD".to_string(), "R0,R1".to_string()),
            (2u32, "MOV".to_string(), "R2,R3".to_string()),
        ];
        let entries = AvrSregAnalysis::analyze(&instrs);
        let defining =
            AvrSregAnalysis::instructions_defining(&entries, crate::avr_emulator::SREG_C);
        assert_eq!(defining.len(), 1);
        assert_eq!(defining[0].mnemonic, "ADD");
    }

    #[test]
    fn test_disasm_all_nops() {
        let flash = vec![0x00u8; 8]; // 4 NOPs
        let det = AvrFunctionDetector::new(&flash, 0);
        let instrs = det.disasm_all();
        assert_eq!(instrs.len(), 4);
        assert!(instrs.iter().all(|(_, mn, _)| mn == "NOP"));
    }
}
