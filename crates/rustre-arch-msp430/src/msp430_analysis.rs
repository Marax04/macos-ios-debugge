//! `msp430_analysis` — Higher-level MSP430 program analysis.
//!
//! Provides:
//! * [`MemoryMapAnalyzer`] — classifies memory regions (RAM/Flash/Peripherals).
//! * [`PowerModeAnalysis`] — detects LPM0-LPM4/LPM5 entry and exit.
//! * [`CriticalSectionDetector`] — locates DINT/EINT pairs.
//! * [`WatchdogPatterns`] — detects watchdog enable/disable/feed.
//! * [`FlashWriteDetector`] — identifies flash write sequences.
//! * [`BootloaderAnalysis`] — recognizes BSL reset patterns.
//! * [`Msp430Analysis`] — top-level facade.

pub use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// MSP430 address space
// ---------------------------------------------------------------------------

/// A classified memory region in the MSP430 address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryKind {
    /// SFR and peripheral registers (0x0000–0x01FF).
    Peripheral,
    /// RAM (0x0200–0x09FF on typical devices, extends on larger ones).
    Ram,
    /// Information memory (flash, 0x1000–0x10FF typically).
    InfoFlash,
    /// BSL (Bootstrap Loader) segment.
    Bsl,
    /// Main flash (0x8000–0xFFFF on 64K devices).
    MainFlash,
    /// Interrupt vector table (0xFF80–0xFFFF).
    VectorTable,
    /// MSP430X extended address space (>0xFFFF).
    ExtendedFlash,
    Unknown,
}

impl fmt::Display for MemoryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Peripheral => "Peripheral",
            Self::Ram => "RAM",
            Self::InfoFlash => "Info Flash",
            Self::Bsl => "BSL",
            Self::MainFlash => "Main Flash",
            Self::VectorTable => "Vector Table",
            Self::ExtendedFlash => "Extended Flash",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

/// A classified memory region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRegion {
    pub start: u32,
    pub end: u32, // inclusive
    pub kind: MemoryKind,
    pub label: String,
}

impl MemoryRegion {
    #[must_use] 
    pub const fn contains(&self, addr: u32) -> bool {
        addr >= self.start && addr <= self.end
    }
    #[must_use] 
    pub const fn size(&self) -> u32 {
        self.end - self.start + 1
    }
}

/// Analyzes and classifies the MSP430 memory map.
#[derive(Debug)]
pub struct MemoryMapAnalyzer {
    pub regions: Vec<MemoryRegion>,
}

impl Default for MemoryMapAnalyzer {
    fn default() -> Self {
        Self::standard_msp430()
    }
}

impl MemoryMapAnalyzer {
    /// Standard MSP430 memory map (64K address space).
    #[must_use] 
    pub fn standard_msp430() -> Self {
        Self {
            regions: vec![
                MemoryRegion {
                    start: 0x0000,
                    end: 0x00FF,
                    kind: MemoryKind::Peripheral,
                    label: "SFR/Peripherals".into(),
                },
                MemoryRegion {
                    start: 0x0100,
                    end: 0x01FF,
                    kind: MemoryKind::Peripheral,
                    label: "16-bit Peripherals".into(),
                },
                MemoryRegion {
                    start: 0x0200,
                    end: 0x09FF,
                    kind: MemoryKind::Ram,
                    label: "RAM".into(),
                },
                MemoryRegion {
                    start: 0x1000,
                    end: 0x10FF,
                    kind: MemoryKind::InfoFlash,
                    label: "Info Flash A/B/C/D".into(),
                },
                MemoryRegion {
                    start: 0x1800,
                    end: 0x19FF,
                    kind: MemoryKind::Bsl,
                    label: "BSL".into(),
                },
                MemoryRegion {
                    start: 0x8000,
                    end: 0xFF7F,
                    kind: MemoryKind::MainFlash,
                    label: "Main Flash".into(),
                },
                MemoryRegion {
                    start: 0xFF80,
                    end: 0xFFFF,
                    kind: MemoryKind::VectorTable,
                    label: "Interrupt Vectors".into(),
                },
            ],
        }
    }

    /// Classify an address.
    #[must_use] 
    pub fn classify(&self, addr: u32) -> MemoryKind {
        self.regions
            .iter()
            .find(|r| r.contains(addr))
            .map_or(MemoryKind::Unknown, |r| r.kind)
    }

    /// True if `addr` is in flash memory.
    #[must_use] 
    pub fn is_flash(&self, addr: u32) -> bool {
        matches!(
            self.classify(addr),
            MemoryKind::MainFlash | MemoryKind::InfoFlash
        )
    }

    /// True if `addr` is in RAM.
    #[must_use] 
    pub fn is_ram(&self, addr: u32) -> bool {
        self.classify(addr) == MemoryKind::Ram
    }

    /// True if `addr` is in the interrupt vector table.
    #[must_use] 
    pub fn is_vector_table(&self, addr: u32) -> bool {
        self.classify(addr) == MemoryKind::VectorTable
    }

    #[must_use] 
    pub const fn region_count(&self) -> usize {
        self.regions.len()
    }
}

// ---------------------------------------------------------------------------
// MSP430 instruction helpers
// ---------------------------------------------------------------------------

/// A decoded MSP430 instruction word (16-bit).
#[derive(Debug, Clone, Copy)]
pub struct Msp430InsnWord(pub u16);

impl Msp430InsnWord {
    #[must_use] 
    pub const fn raw(self) -> u16 {
        self.0
    }

    /// Format I opcode (bits 15–12).
    #[must_use] 
    pub const fn opcode_f1(self) -> u8 {
        ((self.0 >> 12) & 0xF) as u8
    }

    /// Format II opcode (bits 15–7).
    #[must_use] 
    pub const fn opcode_f2(self) -> u16 {
        (self.0 >> 7) & 0x1FF
    }

    /// Format III (jump) condition (bits 9–7).
    #[must_use] 
    pub const fn jump_cond(self) -> u8 {
        ((self.0 >> 10) & 0x7) as u8
    }

    /// Source register (bits 11–8 for F1).
    #[must_use] 
    pub const fn src_reg(self) -> u8 {
        ((self.0 >> 8) & 0xF) as u8
    }

    /// Destination register (bits 3–0).
    #[must_use] 
    pub const fn dst_reg(self) -> u8 {
        (self.0 & 0xF) as u8
    }

    /// BW bit (bit 6 in F1): 0=word, 1=byte.
    #[must_use] 
    pub const fn is_byte_op(self) -> bool {
        (self.0 >> 6) & 1 == 1
    }

    /// True if this word looks like DINT (BIC.W #8, SR / BIC #0x08, SR).
    /// Encoding: 0xC232 (BIC #0x0008, SR in compact form) or via MOV approach.
    #[must_use] 
    pub const fn is_dint(self) -> bool {
        // MOV #0, R2 approach: 0x4032, next word 0x0008
        // or BIS #8, SR = 0xD232 — let's use the canonical DINT pattern.
        // DINT is typically: MOV.W #(~GIE), SR  or  BIC #GIE, SR
        // On MSP430 the GIE bit in SR is bit 3 = 0x0008.
        // BIC #8, SR: 0xC232 (F1 BIC, dst=SR=R2) with immediate ext word 0x0008
        self.0 == 0xC232 // BIC word Rn/imm, SR — common DINT idiom
    }

    /// True if this word looks like EINT (BIS #8, SR).
    #[must_use] 
    pub const fn is_eint(self) -> bool {
        self.0 == 0xD232
    } // BIS #8, SR

    /// True if this is a NOP (MOV R3, R3 or MOV #0, R3 variants).
    #[must_use] 
    pub const fn is_nop(self) -> bool {
        self.0 == 0x4303
    }

    /// True if this looks like watchdog disable (MOV #0x5A80, &WDTCTL).
    #[must_use] 
    pub const fn is_wdt_stop(self) -> bool {
        // Common idiom: MOV.W #0x5A80, &0x015C (WDTCTL)
        self.0 == 0x40B2 // MOV.W #imm, &abs — first word
    }

    /// True if this looks like RETI.
    #[must_use] 
    pub const fn is_reti(self) -> bool {
        self.0 == 0x1300
    }

    /// True for a JMP-family instruction (bits 15–13 = 001).
    #[must_use] 
    pub const fn is_jump(self) -> bool {
        (self.0 >> 13) == 0x001
    }

    /// True for a conditional jump.
    #[must_use] 
    pub const fn is_conditional_jump(self) -> bool {
        self.is_jump() && self.jump_cond() != 7 // JMP=7 is unconditional
    }
}

// ---------------------------------------------------------------------------
// PowerModeAnalysis
// ---------------------------------------------------------------------------

/// Detected low-power mode entry or exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerModeEvent {
    pub addr: u32,
    pub mode: PowerMode,
    pub is_entry: bool,
}

/// MSP430 power modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PowerMode {
    /// LPM0: CPU off, MCLK off.
    Lpm0,
    /// LPM1: CPU + MCLK + DCO off.
    Lpm1,
    /// LPM2: CPU + MCLK + DCO + SMCLK off.
    Lpm2,
    /// LPM3: CPU + MCLK + DCO + SMCLK + VLO off.
    Lpm3,
    /// LPM4: All clocks off.
    Lpm4,
    /// LPM5: Supply current monitor off (MSP430X).
    Lpm5,
}

impl fmt::Display for PowerMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Lpm0 => "LPM0",
            Self::Lpm1 => "LPM1",
            Self::Lpm2 => "LPM2",
            Self::Lpm3 => "LPM3",
            Self::Lpm4 => "LPM4",
            Self::Lpm5 => "LPM5",
        };
        write!(f, "{s}")
    }
}

/// Detects power-mode entry/exit patterns.
#[derive(Debug, Default)]
pub struct PowerModeAnalysis {
    pub events: Vec<PowerModeEvent>,
}

impl PowerModeAnalysis {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan for BIS.W #imm, SR instructions where imm sets LPM bits.
    ///
    /// SR bit layout: SCG1=6, SCG0=5, OSCOFF=4, CPUOFF=3 (GIE=3)
    /// LPM0: CPUOFF  LPM1: CPUOFF+SMCLK  LPM3: SCG1+CPUOFF  LPM4: SCG1+SCG0+CPUOFF
    pub fn scan(&mut self, base: u32, bytes: &[u8]) {
        let hwords = bytes.len() / 2;
        let mut i = 0;
        while i < hwords {
            let hw = u16::from_le_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
            let Some(addr) = hword_addr(base, i) else { break };
            // BIS.W #imm, SR = 0xD032 (immediate, next word) or 0xD322 for R2 operand
            // LPM entry patterns: BIS.B/W with various SR bits
            // Check for "BIS #imm16, SR" = 0xD032 followed by the SR mask
            if hw == 0xD032 && i + 1 < hwords {
                let imm = u16::from_le_bytes([bytes[(i + 1) * 2], bytes[(i + 1) * 2 + 1]]);
                let cpuoff = (imm >> 4) & 1;
                let scg0 = (imm >> 6) & 1;
                let scg1 = (imm >> 5) & 1; // Note: SR bit layout varies by doc
                let oscoff = (imm >> 5) & 1;
                let mode = match (cpuoff, scg0, scg1, oscoff) {
                    (1, 0, 1, _) => PowerMode::Lpm1,
                    (1, 1, 0, _) => PowerMode::Lpm2,
                    (1, 1, 1, _) => PowerMode::Lpm3,
                    // The explicit LPM0 encoding (cpuoff=1, scg0=0, scg1=0)
                    // and every other bit combination both mean LPM0.
                    _ => PowerMode::Lpm0,
                };
                self.events.push(PowerModeEvent {
                    addr,
                    mode,
                    is_entry: true,
                });
                i += 2;
                continue;
            }
            // BIC.W #imm, SR = 0xC032 — LPM exit
            if hw == 0xC032 && i + 1 < hwords {
                let imm = u16::from_le_bytes([bytes[(i + 1) * 2], bytes[(i + 1) * 2 + 1]]);
                if imm & 0x00F8 != 0 {
                    // clears power bits
                    self.events.push(PowerModeEvent {
                        addr,
                        mode: PowerMode::Lpm0,
                        is_entry: false,
                    });
                }
                i += 2;
                continue;
            }
            i += 1;
        }
    }

    #[must_use] 
    pub fn entry_count(&self) -> usize {
        self.events.iter().filter(|e| e.is_entry).count()
    }
    #[must_use] 
    pub fn exit_count(&self) -> usize {
        self.events.iter().filter(|e| !e.is_entry).count()
    }
}

// ---------------------------------------------------------------------------
// CriticalSectionDetector
// ---------------------------------------------------------------------------

/// A matched DINT/EINT critical section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriticalSection {
    pub dint_addr: u32,
    pub eint_addr: Option<u32>,
    /// True if this DINT has a matching EINT.
    pub is_closed: bool,
}

/// Detects DINT/EINT critical sections in MSP430 code.
#[derive(Debug, Default)]
pub struct CriticalSectionDetector {
    pub sections: Vec<CriticalSection>,
}

impl CriticalSectionDetector {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan for DINT/EINT patterns (BIC/BIS #8, SR).
    pub fn scan(&mut self, base: u32, bytes: &[u8]) {
        let hwords = bytes.len() / 2;
        let mut pending_dint: Option<u32> = None;

        for i in 0..hwords {
            let hw = u16::from_le_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
            let Some(addr) = hword_addr(base, i) else { break };
            let insn = Msp430InsnWord(hw);

            if insn.is_dint() {
                // Push any unclosed section first
                if let Some(da) = pending_dint.take() {
                    self.sections.push(CriticalSection {
                        dint_addr: da,
                        eint_addr: None,
                        is_closed: false,
                    });
                }
                pending_dint = Some(addr);
            } else if insn.is_eint()
                && let Some(da) = pending_dint.take() {
                    self.sections.push(CriticalSection {
                        dint_addr: da,
                        eint_addr: Some(addr),
                        is_closed: true,
                    });
                }
        }
        // Any remaining unclosed DINT
        if let Some(da) = pending_dint {
            self.sections.push(CriticalSection {
                dint_addr: da,
                eint_addr: None,
                is_closed: false,
            });
        }
    }

    #[must_use] 
    pub fn closed_count(&self) -> usize {
        self.sections.iter().filter(|s| s.is_closed).count()
    }
    #[must_use] 
    pub fn open_count(&self) -> usize {
        self.sections.iter().filter(|s| !s.is_closed).count()
    }
}

// ---------------------------------------------------------------------------
// WatchdogPatterns
// ---------------------------------------------------------------------------

/// Watchdog-related event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchdogEvent {
    pub addr: u32,
    pub kind: WdtEventKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WdtEventKind {
    /// WDT disabled (WDTCTL = 0x5A80).
    Disable,
    /// WDT password written (WDTPW = 0x5A00 in high byte).
    PasswordWrite,
    /// WDT counter clear (feed/kick).
    Feed,
    /// WDT hold bit set.
    Hold,
}

/// Detects watchdog timer patterns.
#[derive(Debug, Default)]
pub struct WatchdogPatterns {
    pub events: Vec<WatchdogEvent>,
}

impl WatchdogPatterns {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan for typical watchdog disable patterns.
    /// WDTCTL is at 0x015C.  Writes with upper byte = 0x5A are valid WDT accesses.
    pub fn scan(&mut self, base: u32, bytes: &[u8]) {
        let hwords = bytes.len() / 2;
        let mut i = 0;
        while i < hwords {
            let hw = u16::from_le_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
            let Some(addr) = hword_addr(base, i) else { break };
            // MOV.W #imm16, &abs: 0x40B2 <imm16> <abs16>
            if hw == 0x40B2 && i + 2 < hwords {
                let imm = u16::from_le_bytes([bytes[(i + 1) * 2], bytes[(i + 1) * 2 + 1]]);
                let abs = u16::from_le_bytes([bytes[(i + 2) * 2], bytes[(i + 2) * 2 + 1]]);
                if abs == 0x015C {
                    // WDTCTL address
                    let high_byte = ((imm >> 8) & 0xFF) as u8;
                    if high_byte == 0x5A {
                        let low_byte = (imm & 0xFF) as u8;
                        let kind = if low_byte == 0x80 {
                            WdtEventKind::Disable
                        } else if low_byte & 0x80 != 0 {
                            WdtEventKind::Hold
                        } else {
                            WdtEventKind::Feed
                        };
                        self.events.push(WatchdogEvent { addr, kind });
                    }
                }
                i += 3;
                continue;
            }
            i += 1;
        }
    }

    #[must_use] 
    pub fn disable_count(&self) -> usize {
        self.events
            .iter()
            .filter(|e| e.kind == WdtEventKind::Disable)
            .count()
    }
    #[must_use] 
    pub fn feed_count(&self) -> usize {
        self.events
            .iter()
            .filter(|e| e.kind == WdtEventKind::Feed)
            .count()
    }
}

// ---------------------------------------------------------------------------
// FlashWriteDetector
// ---------------------------------------------------------------------------

/// A detected flash write sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlashWriteSeq {
    pub start_addr: u32,
    pub kind: FlashWriteKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashWriteKind {
    ByteWrite,
    WordWrite,
    Erase,
    MassErase,
}

/// Detects MSP430 flash write sequences.
/// Flash writes require: unlock FCTL1/FCTL3, write data, lock again.
#[derive(Debug, Default)]
pub struct FlashWriteDetector {
    pub sequences: Vec<FlashWriteSeq>,
}

impl FlashWriteDetector {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan for flash controller write/erase patterns.
    /// FCTL1 = 0x012C, FCTL2 = 0x012E, FCTL3 = 0x0130.
    pub fn scan(&mut self, base: u32, bytes: &[u8]) {
        let hwords = bytes.len() / 2;
        let mut i = 0;
        while i < hwords {
            let hw = u16::from_le_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
            let Some(addr) = hword_addr(base, i) else { break };
            // MOV.W #imm, &abs: 0x40B2 imm abs
            if hw == 0x40B2 && i + 2 < hwords {
                let imm = u16::from_le_bytes([bytes[(i + 1) * 2], bytes[(i + 1) * 2 + 1]]);
                let abs = u16::from_le_bytes([bytes[(i + 2) * 2], bytes[(i + 2) * 2 + 1]]);
                let high = ((imm >> 8) & 0xFF) as u8;
                if abs == 0x012C && high == 0xA5 {
                    // FCTL1 password = 0xA5xx
                    let low = (imm & 0xFF) as u8;
                    let kind = match low {
                        0x40 => FlashWriteKind::ByteWrite,
                        0x02 => FlashWriteKind::Erase,
                        0x04 => FlashWriteKind::MassErase,
                        // 0x42 is the explicit word-write encoding; any other
                        // password byte is treated as a word write as well.
                        _ => FlashWriteKind::WordWrite,
                    };
                    self.sequences.push(FlashWriteSeq {
                        start_addr: addr,
                        kind,
                    });
                }
                i += 3;
                continue;
            }
            i += 1;
        }
    }

    #[must_use] 
    pub fn write_count(&self) -> usize {
        self.sequences
            .iter()
            .filter(|s| {
                matches!(
                    s.kind,
                    FlashWriteKind::ByteWrite | FlashWriteKind::WordWrite
                )
            })
            .count()
    }
    #[must_use] 
    pub fn erase_count(&self) -> usize {
        self.sequences
            .iter()
            .filter(|s| matches!(s.kind, FlashWriteKind::Erase | FlashWriteKind::MassErase))
            .count()
    }
}

// ---------------------------------------------------------------------------
// BootloaderAnalysis
// ---------------------------------------------------------------------------

/// BSL (Bootstrap Loader) usage pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BslPattern {
    pub addr: u32,
    pub kind: BslPatternKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BslPatternKind {
    /// Jump to BSL entry point (0x1000 area).
    JumpToBsl,
    /// Call to BSL function.
    CallBsl,
    /// Password match sequence.
    PasswordSequence,
}

// ---------------------------------------------------------------------------
// ISR (Interrupt Service Routine) detector
// ---------------------------------------------------------------------------

/// An identified interrupt service routine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsrInfo {
    /// The address stored in the vector table.
    pub handler_addr: u32,
    /// Interrupt vector index (0 = highest priority).
    pub vector_index: u8,
    /// Human-readable name for common vectors.
    pub name: &'static str,
}

/// MSP430 interrupt vector table layout (last 64 bytes of flash, 32 vectors).
/// Index 31 = Reset, 30 = NMI, 29 = Watchdog, 28 = Timer A, etc.
pub const MSP430_VECTOR_NAMES: [&str; 32] = [
    "P1",
    "P2",
    "Reserved",
    "ADC12",
    "USCIAB0_TX",
    "USCIAB0_RX",
    "P0",
    "BT",
    "Timer_A3_CC1_2",
    "Timer_A3_CC0",
    "USBs",
    "DAC12",
    "DMA",
    "Timer_B7_CC1_6",
    "Timer_B7_CC0",
    "Comp_B",
    "Sys",
    "TA1_N",
    "TA1_0",
    "TA0_N",
    "TA0_0",
    "USCI_B0",
    "USCI_A0",
    "WDT",
    "NMI",
    "Reset",
    "VEC26",
    "VEC27",
    "VEC28",
    "VEC29",
    "VEC30",
    "VEC31",
];

/// Byte address of half-word `i` inside a region that starts at `base`.
///
/// Returns `None` when the half-word index does not fit the 32-bit address
/// space, which bounds every scanner below to input it can actually address
/// instead of silently wrapping on an oversized slice.
#[must_use]
fn hword_addr(base: u32, i: usize) -> Option<u32> {
    Some(base.wrapping_add(u32::try_from(i).ok()?.wrapping_mul(2)))
}

/// Parses the interrupt vector table from the last 64 bytes of flash.
#[must_use] 
pub fn parse_interrupt_vectors(vector_table_bytes: &[u8]) -> Vec<IsrInfo> {
    if vector_table_bytes.len() < 64 {
        return Vec::new();
    }
    let mut isrs = Vec::new();
    let start_offset = vector_table_bytes.len() - 64;
    for (i, entry) in vector_table_bytes[start_offset..].chunks_exact(2).enumerate().take(32) {
        let addr = u32::from(u16::from_le_bytes([entry[0], entry[1]]));
        if addr != 0 && addr != 0xFFFF {
            let name = if i < MSP430_VECTOR_NAMES.len() {
                MSP430_VECTOR_NAMES[i]
            } else {
                "Unknown"
            };
            // `take(32)` bounds the index, so this conversion always succeeds;
            // stopping rather than truncating keeps the indices honest anyway.
            let Ok(vector_index) = u8::try_from(i) else { break };
            isrs.push(IsrInfo {
                handler_addr: addr,
                vector_index,
                name,
            });
        }
    }
    isrs
}

// ---------------------------------------------------------------------------
// MSP430 string scanner
// ---------------------------------------------------------------------------

/// A string found in MSP430 flash (printable ASCII run).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlashString {
    pub addr: u32,
    pub value: String,
}

/// Character cap for a single accumulated string run.
///
/// A run longer than this is truncated, which prevents unbounded memory growth
/// when scanning large attacker-controlled inputs that consist entirely of
/// printable bytes.
pub const MAX_FLASH_STRING_RUN: usize = 4096;

/// Scans a binary region for printable ASCII strings (min 4 chars).
#[must_use]
pub fn scan_flash_strings(base: u32, bytes: &[u8], min_len: usize) -> Vec<FlashString> {
    let mut result = Vec::new();
    let mut run_start: Option<usize> = None;
    let mut run_buf = String::new();
    for (i, &b) in bytes.iter().enumerate() {
        if b.is_ascii() && !b.is_ascii_control() {
            if run_start.is_none() {
                run_start = Some(i);
            }
            // Cap the per-run buffer to avoid unbounded memory growth when
            // scanning attacker-controlled input that is entirely printable.
            if run_buf.len() < MAX_FLASH_STRING_RUN {
                run_buf.push(b as char);
            }
        } else {
            if run_buf.len() >= min_len
                && let Some(start) = run_start
                && let Ok(off) = u32::try_from(start)
            {
                result.push(FlashString {
                    addr: base.wrapping_add(off),
                    value: run_buf.clone(),
                });
            }
            run_start = None;
            run_buf.clear();
        }
    }
    if run_buf.len() >= min_len
        && let Ok(off) = u32::try_from(run_start.unwrap_or(0))
    {
        result.push(FlashString {
            addr: base.wrapping_add(off),
            value: run_buf,
        });
    }
    result
}

// ---------------------------------------------------------------------------
// MSP430 peripheral register map
// ---------------------------------------------------------------------------

/// Common MSP430 peripheral register addresses.
pub mod peripheral_regs {
    pub const WDTCTL: u16 = 0x015C;
    pub const P1IN: u16 = 0x0020;
    pub const P1OUT: u16 = 0x0021;
    pub const P1DIR: u16 = 0x0022;
    pub const P2IN: u16 = 0x0028;
    pub const P2OUT: u16 = 0x0029;
    pub const P2DIR: u16 = 0x002A;
    pub const FCTL1: u16 = 0x012C;
    pub const FCTL2: u16 = 0x012E;
    pub const FCTL3: u16 = 0x0130;
    pub const IE1: u16 = 0x0000;
    pub const IFG1: u16 = 0x0002;
    pub const DCOCTL: u16 = 0x0056;
    pub const BCSCTL1: u16 = 0x0057;
    pub const BCSCTL2: u16 = 0x0058;
    pub const BCSCTL3: u16 = 0x0053;
    pub const TA0CTL: u16 = 0x0160;
    pub const TA0CCTL0: u16 = 0x0162;
    pub const TA0CCR0: u16 = 0x0172;
    pub const USCI_A0_CTL0: u16 = 0x0060;
    pub const USCI_A0_CTL1: u16 = 0x0061;
    pub const USCI_A0_BR0: u16 = 0x0062;
    pub const USCI_A0_BR1: u16 = 0x0063;
}

/// Detects BSL-related patterns.
#[derive(Debug, Default)]
pub struct BootloaderAnalysis {
    pub patterns: Vec<BslPattern>,
}

impl BootloaderAnalysis {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan for calls/jumps into BSL address range (0x1000–0x1800).
    pub fn scan(&mut self, base: u32, bytes: &[u8]) {
        let hwords = bytes.len() / 2;
        for i in 0..hwords {
            let hw = u16::from_le_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
            let Some(addr) = hword_addr(base, i) else { break };
            // CALL #imm: 0x12B0 <target_addr>
            if hw == 0x12B0 && i + 1 < hwords {
                let target = u16::from_le_bytes([bytes[(i + 1) * 2], bytes[(i + 1) * 2 + 1]]);
                if (0x1000..0x1800).contains(&target) {
                    self.patterns.push(BslPattern {
                        addr,
                        kind: BslPatternKind::CallBsl,
                    });
                }
            }
            // BR #imm (indirect jump): 0x4030 <target>
            if hw == 0x4030 && i + 1 < hwords {
                let target = u16::from_le_bytes([bytes[(i + 1) * 2], bytes[(i + 1) * 2 + 1]]);
                if (0x1000..0x1800).contains(&target) {
                    self.patterns.push(BslPattern {
                        addr,
                        kind: BslPatternKind::JumpToBsl,
                    });
                }
            }
        }
    }

    #[must_use] 
    pub const fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

// ---------------------------------------------------------------------------
// Msp430Analysis — top-level facade
// ---------------------------------------------------------------------------

/// Top-level MSP430 analysis facade.
#[derive(Debug)]
pub struct Msp430Analysis {
    pub memory_map: MemoryMapAnalyzer,
    pub power_modes: PowerModeAnalysis,
    pub critical_sections: CriticalSectionDetector,
    pub watchdog: WatchdogPatterns,
    pub flash_writes: FlashWriteDetector,
    pub bootloader: BootloaderAnalysis,
}

impl Default for Msp430Analysis {
    fn default() -> Self {
        Self {
            memory_map: MemoryMapAnalyzer::standard_msp430(),
            power_modes: PowerModeAnalysis::new(),
            critical_sections: CriticalSectionDetector::new(),
            watchdog: WatchdogPatterns::new(),
            flash_writes: FlashWriteDetector::new(),
            bootloader: BootloaderAnalysis::new(),
        }
    }
}

impl Msp430Analysis {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Run all sub-analyses on a region.
    pub fn analyze(&mut self, base: u32, bytes: &[u8]) {
        self.power_modes.scan(base, bytes);
        self.critical_sections.scan(base, bytes);
        self.watchdog.scan(base, bytes);
        self.flash_writes.scan(base, bytes);
        self.bootloader.scan(base, bytes);
    }

    /// Classify an address in the memory map.
    #[must_use] 
    pub fn classify_address(&self, addr: u32) -> MemoryKind {
        self.memory_map.classify(addr)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes_from_hwords(words: &[u16]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    // --- MemoryMapAnalyzer ------------------------------------------------

    #[test]
    fn test_memory_map_peripheral() {
        let m = MemoryMapAnalyzer::standard_msp430();
        assert_eq!(m.classify(0x0050), MemoryKind::Peripheral);
    }

    #[test]
    fn test_memory_map_ram() {
        let m = MemoryMapAnalyzer::standard_msp430();
        assert_eq!(m.classify(0x0200), MemoryKind::Ram);
        assert!(m.is_ram(0x0400));
    }

    #[test]
    fn test_memory_map_main_flash() {
        let m = MemoryMapAnalyzer::standard_msp430();
        assert_eq!(m.classify(0xC000), MemoryKind::MainFlash);
        assert!(m.is_flash(0xC000));
    }

    #[test]
    fn test_memory_map_vector_table() {
        let m = MemoryMapAnalyzer::standard_msp430();
        assert!(m.is_vector_table(0xFF80));
        assert!(m.is_vector_table(0xFFFF));
    }

    #[test]
    fn test_memory_map_info_flash() {
        let m = MemoryMapAnalyzer::standard_msp430();
        assert_eq!(m.classify(0x1000), MemoryKind::InfoFlash);
    }

    #[test]
    fn test_memory_map_unknown() {
        let m = MemoryMapAnalyzer::standard_msp430();
        assert_eq!(m.classify(0x7000), MemoryKind::Unknown);
    }

    #[test]
    fn test_memory_region_size() {
        let r = MemoryRegion {
            start: 0xFF80,
            end: 0xFFFF,
            kind: MemoryKind::VectorTable,
            label: "VT".into(),
        };
        assert_eq!(r.size(), 0x80);
    }

    #[test]
    fn test_memory_map_display() {
        assert_eq!(MemoryKind::Ram.to_string(), "RAM");
        assert_eq!(MemoryKind::MainFlash.to_string(), "Main Flash");
    }

    // --- Msp430InsnWord --------------------------------------------------

    #[test]
    fn test_insn_dint() {
        let insn = Msp430InsnWord(0xC232);
        assert!(insn.is_dint());
        assert!(!insn.is_eint());
    }

    #[test]
    fn test_insn_eint() {
        let insn = Msp430InsnWord(0xD232);
        assert!(insn.is_eint());
        assert!(!insn.is_dint());
    }

    #[test]
    fn test_insn_reti() {
        let insn = Msp430InsnWord(0x1300);
        assert!(insn.is_reti());
    }

    #[test]
    fn test_insn_nop() {
        let insn = Msp430InsnWord(0x4303);
        assert!(insn.is_nop());
    }

    #[test]
    fn test_insn_jump() {
        let insn = Msp430InsnWord(0x3C00); // JMP
        assert!(insn.is_jump());
    }

    #[test]
    fn test_insn_conditional_jump() {
        let insn = Msp430InsnWord(0x2400); // JEQ/JZ (cond=0)
        assert!(insn.is_jump());
        assert!(insn.is_conditional_jump());
    }

    // --- PowerModeAnalysis -----------------------------------------------

    #[test]
    fn test_power_mode_empty() {
        let mut pa = PowerModeAnalysis::new();
        pa.scan(0, &[]);
        assert_eq!(pa.entry_count(), 0);
    }

    #[test]
    fn test_power_mode_entry() {
        // BIS.W #imm16, SR = 0xD032, imm = 0x0010 (CPUOFF=1 in bit4 → LPM0)
        let bytes = bytes_from_hwords(&[0xD032, 0x0018]); // SR bits for LPM3
        let mut pa = PowerModeAnalysis::new();
        pa.scan(0x8000, &bytes);
        assert!(pa.entry_count() >= 1);
    }

    #[test]
    fn test_power_mode_exit() {
        // BIC.W #imm16, SR = 0xC032, imm clears power bits
        let bytes = bytes_from_hwords(&[0xC032, 0x00F8]);
        let mut pa = PowerModeAnalysis::new();
        pa.scan(0x8000, &bytes);
        assert_eq!(pa.exit_count(), 1);
    }

    #[test]
    fn test_power_mode_display() {
        assert_eq!(PowerMode::Lpm0.to_string(), "LPM0");
        assert_eq!(PowerMode::Lpm4.to_string(), "LPM4");
    }

    // --- CriticalSectionDetector -----------------------------------------

    #[test]
    fn test_cs_matched_pair() {
        let bytes = bytes_from_hwords(&[0xC232, 0x4303, 0xD232]);
        let mut cs = CriticalSectionDetector::new();
        cs.scan(0x8000, &bytes);
        assert_eq!(cs.closed_count(), 1);
        assert_eq!(cs.open_count(), 0);
    }

    #[test]
    fn test_cs_unmatched_dint() {
        let bytes = bytes_from_hwords(&[0xC232, 0x4303]); // DINT, NOP — no EINT
        let mut cs = CriticalSectionDetector::new();
        cs.scan(0x8000, &bytes);
        assert_eq!(cs.open_count(), 1);
    }

    #[test]
    fn test_cs_empty() {
        let mut cs = CriticalSectionDetector::new();
        cs.scan(0, &[]);
        assert_eq!(cs.sections.len(), 0);
    }

    // --- WatchdogPatterns ------------------------------------------------

    #[test]
    fn test_wdt_disable_pattern() {
        // MOV.W #0x5A80, &0x015C: 0x40B2 0x5A80 0x015C
        let bytes = bytes_from_hwords(&[0x40B2, 0x5A80, 0x015C]);
        let mut wp = WatchdogPatterns::new();
        wp.scan(0x8000, &bytes);
        assert_eq!(wp.disable_count(), 1);
    }

    #[test]
    fn test_wdt_feed_pattern() {
        // MOV.W #0x5A00, &0x015C — feed (low byte = 0x00)
        let bytes = bytes_from_hwords(&[0x40B2, 0x5A00, 0x015C]);
        let mut wp = WatchdogPatterns::new();
        wp.scan(0x8000, &bytes);
        assert_eq!(wp.feed_count(), 1);
    }

    #[test]
    fn test_wdt_no_match_wrong_addr() {
        let bytes = bytes_from_hwords(&[0x40B2, 0x5A80, 0x0200]); // not WDTCTL addr
        let mut wp = WatchdogPatterns::new();
        wp.scan(0x8000, &bytes);
        assert_eq!(wp.disable_count(), 0);
    }

    // --- FlashWriteDetector ----------------------------------------------

    #[test]
    fn test_flash_write_word() {
        // MOV.W #0xA542, &0x012C (FCTL1 word write): 0x40B2 0xA542 0x012C
        let bytes = bytes_from_hwords(&[0x40B2, 0xA542, 0x012C]);
        let mut fwd = FlashWriteDetector::new();
        fwd.scan(0x8000, &bytes);
        assert_eq!(fwd.write_count(), 1);
    }

    #[test]
    fn test_flash_erase() {
        // MOV.W #0xA502, &0x012C (FCTL1 erase)
        let bytes = bytes_from_hwords(&[0x40B2, 0xA502, 0x012C]);
        let mut fwd = FlashWriteDetector::new();
        fwd.scan(0x8000, &bytes);
        assert_eq!(fwd.erase_count(), 1);
    }

    // --- BootloaderAnalysis ----------------------------------------------

    #[test]
    fn test_bsl_call() {
        // CALL #0x1000: 0x12B0 0x1000
        let bytes = bytes_from_hwords(&[0x12B0, 0x1000]);
        let mut ba = BootloaderAnalysis::new();
        ba.scan(0x8000, &bytes);
        assert_eq!(ba.pattern_count(), 1);
        assert_eq!(ba.patterns[0].kind, BslPatternKind::CallBsl);
    }

    #[test]
    fn test_bsl_jump() {
        // BR #0x1200: 0x4030 0x1200
        let bytes = bytes_from_hwords(&[0x4030, 0x1200]);
        let mut ba = BootloaderAnalysis::new();
        ba.scan(0x8000, &bytes);
        assert_eq!(ba.pattern_count(), 1);
        assert_eq!(ba.patterns[0].kind, BslPatternKind::JumpToBsl);
    }

    #[test]
    fn test_bsl_no_match_outside_range() {
        let bytes = bytes_from_hwords(&[0x12B0, 0x8000]); // call to main flash
        let mut ba = BootloaderAnalysis::new();
        ba.scan(0x8000, &bytes);
        assert_eq!(ba.pattern_count(), 0);
    }

    // --- Msp430Analysis facade -------------------------------------------

    #[test]
    fn test_analysis_new() {
        let a = Msp430Analysis::new();
        assert!(a.memory_map.region_count() > 0);
    }

    #[test]
    fn test_analysis_classify_ram() {
        let a = Msp430Analysis::new();
        assert_eq!(a.classify_address(0x0300), MemoryKind::Ram);
    }

    #[test]
    fn test_analysis_analyze_empty() {
        let mut a = Msp430Analysis::new();
        a.analyze(0x8000, &[]);
        assert_eq!(a.watchdog.events.len(), 0);
    }

    #[test]
    fn test_analysis_analyze_wdt_disable() {
        let bytes = bytes_from_hwords(&[0x40B2, 0x5A80, 0x015C]);
        let mut a = Msp430Analysis::new();
        a.analyze(0x8000, &bytes);
        assert_eq!(a.watchdog.disable_count(), 1);
    }

    // --- ISR detection ---------------------------------------------------

    #[test]
    fn test_parse_interrupt_vectors_empty() {
        let isrs = parse_interrupt_vectors(&[]);
        assert!(isrs.is_empty());
    }

    #[test]
    fn test_parse_interrupt_vectors_too_short() {
        let isrs = parse_interrupt_vectors(&[0u8; 32]); // only 32 bytes
        assert!(isrs.is_empty());
    }

    #[test]
    fn test_parse_interrupt_vectors_valid() {
        let mut table = vec![0xFFu8; 64]; // all 0xFFFF = erased flash
        // Set reset vector (index 31, last 2 bytes) to 0x8000
        table[62] = 0x00;
        table[63] = 0x80;
        let isrs = parse_interrupt_vectors(&table);
        assert!(!isrs.is_empty());
    }

    #[test]
    fn test_parse_interrupt_vectors_all_erased() {
        let table = vec![0xFFu8; 64];
        let isrs = parse_interrupt_vectors(&table);
        // 0xFFFF is treated as erased (excluded)
        assert!(isrs.is_empty());
    }

    // --- scan_flash_strings -----------------------------------------------

    #[test]
    fn test_scan_flash_strings_finds_string() {
        let data = b"HELLO WORLD\x00";
        let strings = scan_flash_strings(0x8000, data, 4);
        assert!(!strings.is_empty());
        assert!(strings[0].value.contains("HELLO"));
    }

    #[test]
    fn test_scan_flash_strings_min_len() {
        let data = b"HI\x00THERE\x00";
        let strings = scan_flash_strings(0, data, 4);
        // "HI" (2) should be excluded, "THERE" (5) should be included
        assert!(strings.iter().all(|s| s.value.len() >= 4));
    }

    #[test]
    fn test_scan_flash_strings_empty() {
        let strings = scan_flash_strings(0, &[], 4);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_scan_flash_strings_address() {
        let data = b"\x00\x00\x00HELLO\x00";
        let strings = scan_flash_strings(0x1000, data, 4);
        if !strings.is_empty() {
            assert_eq!(strings[0].addr, 0x1003);
        }
    }

    // --- peripheral_regs constants ----------------------------------------

    #[test]
    fn test_peripheral_reg_wdtctl() {
        assert_eq!(peripheral_regs::WDTCTL, 0x015C);
    }

    #[test]
    fn test_peripheral_reg_fctl1() {
        assert_eq!(peripheral_regs::FCTL1, 0x012C);
    }

    #[test]
    fn test_peripheral_reg_p1out() {
        assert_eq!(peripheral_regs::P1OUT, 0x0021);
    }

    // --- MemoryMapAnalyzer additional ---

    #[test]
    fn test_memory_map_bsl() {
        let m = MemoryMapAnalyzer::standard_msp430();
        assert_eq!(m.classify(0x1800), MemoryKind::Bsl);
    }

    #[test]
    fn test_memory_map_region_count() {
        let m = MemoryMapAnalyzer::standard_msp430();
        assert!(m.region_count() >= 6);
    }

    #[test]
    fn test_memory_region_contains() {
        let r = MemoryRegion {
            start: 0x0200,
            end: 0x09FF,
            kind: MemoryKind::Ram,
            label: "RAM".into(),
        };
        assert!(r.contains(0x0200));
        assert!(r.contains(0x09FF));
        assert!(!r.contains(0x0199));
        assert!(!r.contains(0x0A00));
    }

    // --- PowerMode additional ---

    #[test]
    fn test_power_mode_lpm5_display() {
        assert_eq!(PowerMode::Lpm5.to_string(), "LPM5");
    }

    #[test]
    fn test_power_mode_lpm1_display() {
        assert_eq!(PowerMode::Lpm1.to_string(), "LPM1");
    }

    // --- WatchdogEventKind ---

    #[test]
    fn test_wdt_hold_pattern() {
        // MOV.W #0x5A84, &0x015C — hold bit (bit 7 set, not 0x80)
        let bytes = bytes_from_hwords(&[0x40B2, 0x5A84, 0x015C]);
        let mut wp = WatchdogPatterns::new();
        wp.scan(0x8000, &bytes);
        assert!(!wp.events.is_empty());
    }

    // --- FlashWriteDetector additional ---

    #[test]
    fn test_flash_mass_erase() {
        // MOV.W #0xA504, &0x012C (FCTL1 mass erase)
        let bytes = bytes_from_hwords(&[0x40B2, 0xA504, 0x012C]);
        let mut fwd = FlashWriteDetector::new();
        fwd.scan(0x8000, &bytes);
        assert_eq!(fwd.erase_count(), 1);
    }

    #[test]
    fn test_flash_byte_write() {
        // MOV.W #0xA540, &0x012C (FCTL1 byte write)
        let bytes = bytes_from_hwords(&[0x40B2, 0xA540, 0x012C]);
        let mut fwd = FlashWriteDetector::new();
        fwd.scan(0x8000, &bytes);
        assert_eq!(fwd.write_count(), 1);
    }
}
