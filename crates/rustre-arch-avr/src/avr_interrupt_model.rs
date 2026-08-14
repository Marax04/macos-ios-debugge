//! AVR interrupt model — 26 `ATmega` interrupt vectors, ISR detection,
//! interrupt priority, and critical section identification.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AvrInterruptError {
    #[error("invalid vector number {0}")]
    InvalidVector(u8),
    #[error("vector table base not set")]
    NoVectorTable,
    #[error("no ISR at address 0x{0:04x}")]
    NoIsrAtAddress(u16),
    #[error("critical section mismatch at 0x{0:04x}")]
    CriticalSectionMismatch(u16),
}

// ─── ATmega Interrupt Vectors ─────────────────────────────────────────────────

/// Single interrupt vector entry for `ATmega` series.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvrInterruptVector {
    /// Vector number (0-based index into the IVT).
    pub number: u8,
    /// Canonical name (e.g. `INT0_vect`).
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Priority: lower number = higher priority (vector 0 = reset, highest).
    pub priority: u8,
    /// Word address in flash for the JMP/RJMP instruction.
    pub word_address: u16,
    /// Resolved handler address (if analyzed).
    pub handler_addr: Option<u16>,
    /// Whether an ISR has been identified at the handler address.
    pub has_isr: bool,
}

impl AvrInterruptVector {
    #[must_use]
    const fn new(number: u8, name: &'static str, description: &'static str) -> Self {
        Self {
            number,
            name,
            description,
            priority: number,
            word_address: (number as u16) * 2, // each IVT slot is 4 bytes (2 words)
            handler_addr: None,
            has_isr: false,
        }
    }
}

/// All 26 interrupt vectors for the ATmega168/328 series.
#[must_use]
pub fn atmega328_vectors() -> Vec<AvrInterruptVector> {
    vec![
        AvrInterruptVector::new(
            0,
            "RESET_vect",
            "External Pin, Power-on Reset, Brown-out Reset and Watchdog System Reset",
        ),
        AvrInterruptVector::new(1, "INT0_vect", "External Interrupt Request 0"),
        AvrInterruptVector::new(2, "INT1_vect", "External Interrupt Request 1"),
        AvrInterruptVector::new(3, "PCINT0_vect", "Pin Change Interrupt Request 0"),
        AvrInterruptVector::new(4, "PCINT1_vect", "Pin Change Interrupt Request 1"),
        AvrInterruptVector::new(5, "PCINT2_vect", "Pin Change Interrupt Request 2"),
        AvrInterruptVector::new(6, "WDT_vect", "Watchdog Time-out Interrupt"),
        AvrInterruptVector::new(7, "TIMER2_COMPA_vect", "Timer/Counter2 Compare Match A"),
        AvrInterruptVector::new(8, "TIMER2_COMPB_vect", "Timer/Counter2 Compare Match B"),
        AvrInterruptVector::new(9, "TIMER2_OVF_vect", "Timer/Counter2 Overflow"),
        AvrInterruptVector::new(10, "TIMER1_CAPT_vect", "Timer/Counter1 Capture Event"),
        AvrInterruptVector::new(11, "TIMER1_COMPA_vect", "Timer/Counter1 Compare Match A"),
        AvrInterruptVector::new(12, "TIMER1_COMPB_vect", "Timer/Counter1 Compare Match B"),
        AvrInterruptVector::new(13, "TIMER1_OVF_vect", "Timer/Counter1 Overflow"),
        AvrInterruptVector::new(14, "TIMER0_COMPA_vect", "Timer/Counter0 Compare Match A"),
        AvrInterruptVector::new(15, "TIMER0_COMPB_vect", "Timer/Counter0 Compare Match B"),
        AvrInterruptVector::new(16, "TIMER0_OVF_vect", "Timer/Counter0 Overflow"),
        AvrInterruptVector::new(17, "SPI_STC_vect", "SPI Serial Transfer Complete"),
        AvrInterruptVector::new(18, "USART_RX_vect", "USART Rx Complete"),
        AvrInterruptVector::new(19, "USART_UDRE_vect", "USART Data Register Empty"),
        AvrInterruptVector::new(20, "USART_TX_vect", "USART Tx Complete"),
        AvrInterruptVector::new(21, "ADC_vect", "ADC Conversion Complete"),
        AvrInterruptVector::new(22, "EE_READY_vect", "EEPROM Ready"),
        AvrInterruptVector::new(23, "ANALOG_COMP_vect", "Analog Comparator"),
        AvrInterruptVector::new(24, "TWI_vect", "2-wire Serial Interface (I2C)"),
        AvrInterruptVector::new(25, "SPM_READY_vect", "Store Program Memory Ready"),
    ]
}

// ─── InterruptPriority ────────────────────────────────────────────────────────

/// Compares the priority of two interrupt vectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterruptPriority {
    pub vector_priorities: Vec<(u8, u8)>, // (vector_number, priority)
}

impl InterruptPriority {
    /// Build priority table from a vector list.
    #[must_use]
    pub fn from_vectors(vectors: &[AvrInterruptVector]) -> Self {
        let mut prios: Vec<(u8, u8)> = vectors.iter().map(|v| (v.number, v.priority)).collect();
        prios.sort_by_key(|&(_, p)| p);
        Self {
            vector_priorities: prios,
        }
    }

    /// Check if `a` has higher priority than `b` (lower number wins).
    #[must_use]
    pub fn higher_priority(&self, a: u8, b: u8) -> bool {
        let pa = self
            .vector_priorities
            .iter()
            .find(|&&(n, _)| n == a)
            .map_or(u8::MAX, |&(_, p)| p);
        let pb = self
            .vector_priorities
            .iter()
            .find(|&&(n, _)| n == b)
            .map_or(u8::MAX, |&(_, p)| p);
        pa < pb
    }

    /// The highest-priority vector (after reset).
    #[must_use]
    pub fn highest_non_reset(&self) -> Option<u8> {
        self.vector_priorities
            .iter()
            .filter(|&&(n, _)| n != 0)
            .min_by_key(|&&(_, p)| p)
            .map(|&(n, _)| n)
    }
}

// ─── ISR Detection ────────────────────────────────────────────────────────────

/// AVR ISR prologue / epilogue patterns.
///
/// A typical AVR ISR starts with `PUSH r0 / IN r0,SREG / PUSH r0 / ...`
/// and ends with `... / POP r0 / OUT SREG,r0 / POP r0 / RETI`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsrPattern {
    /// Correct ISR: saves SREG, restores SREG, ends with RETI.
    Compliant,
    /// Missing SREG save (SREG not pushed at entry).
    MissingSregSave,
    /// Missing SREG restore (SREG not popped before RETI).
    MissingSregRestore,
    /// Ends with RET instead of RETI (wrong for ISR).
    WrongReturn,
    /// Empty ISR — only RETI.
    Empty,
    /// Pattern not recognized.
    Unknown,
}

/// Detected ISR information for a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsrInfo {
    /// Function start address (word address).
    pub start_addr: u16,
    /// ISR compliance pattern.
    pub pattern: IsrPattern,
    /// Whether the ISR re-enables global interrupts inside (dangerous).
    pub enables_interrupts_inside: bool,
    /// Number of registers saved in the prologue.
    pub saved_register_count: u8,
    /// Estimated stack usage in bytes.
    pub stack_usage: u8,
}

impl IsrInfo {
    /// Classify ISR pattern from decoded mnemonics.
    #[must_use]
    pub fn classify(
        start_addr: u16,
        mnemonics: &[&str],
        saves_sreg: bool,
        restores_sreg: bool,
        enables_interrupts: bool,
        saved_regs: u8,
        stack_bytes: u8,
    ) -> Self {
        let pattern = if mnemonics.is_empty() {
            IsrPattern::Empty
        } else if !saves_sreg && !restores_sreg {
            if mnemonics.last() == Some(&"RETI") {
                if mnemonics.len() == 1 {
                    IsrPattern::Empty
                } else {
                    IsrPattern::MissingSregSave
                }
            } else if mnemonics.last() == Some(&"RET") {
                IsrPattern::WrongReturn
            } else {
                IsrPattern::Unknown
            }
        } else if !saves_sreg {
            IsrPattern::MissingSregSave
        } else if !restores_sreg {
            IsrPattern::MissingSregRestore
        } else if mnemonics.last() == Some(&"RET") {
            IsrPattern::WrongReturn
        } else if mnemonics.last() == Some(&"RETI") {
            IsrPattern::Compliant
        } else {
            IsrPattern::Unknown
        };
        Self {
            start_addr,
            pattern,
            enables_interrupts_inside: enables_interrupts,
            saved_register_count: saved_regs,
            stack_usage: stack_bytes,
        }
    }

    /// Whether this ISR is considered safe.
    #[must_use]
    pub const fn is_safe(&self) -> bool {
        matches!(self.pattern, IsrPattern::Compliant | IsrPattern::Empty)
            && !self.enables_interrupts_inside
    }
}

// ─── CriticalSection ─────────────────────────────────────────────────────────

/// A critical section identified by CLI/SEI pairs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalSection {
    /// Address of the CLI instruction.
    pub cli_addr: u16,
    /// Address of the matching SEI instruction (or None if unmatched).
    pub sei_addr: Option<u16>,
    /// Instructions between CLI and SEI.
    pub body_instruction_count: u16,
    /// Whether the critical section is nested inside another.
    pub is_nested: bool,
}

impl CriticalSection {
    /// Duration heuristic: size of protected body.
    #[must_use]
    pub const fn duration_cycles(&self) -> u32 {
        // Approximate: each AVR instruction averages ~1.5 cycles
        (self.body_instruction_count as u32 * 3) / 2
    }

    /// Whether the critical section is "small" (≤ 16 instructions).
    #[must_use]
    pub const fn is_small(&self) -> bool {
        self.body_instruction_count <= 16
    }
}

// ─── IvectorAnalyzer ─────────────────────────────────────────────────────────

/// Full AVR interrupt vector table analyzer.
#[derive(Debug)]
pub struct IvectorAnalyzer {
    pub vectors: Vec<AvrInterruptVector>,
    pub priority: InterruptPriority,
    // BTreeMap is used instead of HashMap so that attacker-controlled ISR
    // start addresses (parsed from untrusted flash) cannot trigger hash-collision
    // DoS via crafted key distributions.
    pub isrs: BTreeMap<u16, IsrInfo>,
    pub crit_sections: Vec<CriticalSection>,
    /// Base word address of the interrupt vector table in flash.
    pub ivt_base: u16,
}

impl IvectorAnalyzer {
    /// Create a new analyzer for ATmega328-series.
    #[must_use]
    pub fn new_atmega328() -> Self {
        let vectors = atmega328_vectors();
        let priority = InterruptPriority::from_vectors(&vectors);
        Self {
            vectors,
            priority,
            isrs: BTreeMap::new(),
            crit_sections: Vec::new(),
            ivt_base: 0x0000,
        }
    }

    /// Total number of interrupt vectors.
    #[must_use]
    pub const fn vector_count(&self) -> usize {
        self.vectors.len()
    }

    /// Resolve a vector's handler address.
    ///
    /// # Errors
    ///
    /// Returns `AvrInterruptError::InvalidVector` if `vector_num` is not in the table.
    pub fn resolve_handler(
        &mut self,
        vector_num: u8,
        handler_addr: u16,
    ) -> Result<(), AvrInterruptError> {
        self.vectors
            .iter_mut()
            .find(|v| v.number == vector_num)
            .ok_or(AvrInterruptError::InvalidVector(vector_num))
            .map(|v| {
                v.handler_addr = Some(handler_addr);
                v.has_isr = true;
            })
    }

    /// Register an ISR analysis result.
    pub fn register_isr(&mut self, isr: IsrInfo) {
        self.isrs.insert(isr.start_addr, isr);
    }

    /// All ISRs that are non-compliant.
    #[must_use]
    pub fn non_compliant_isrs(&self) -> Vec<&IsrInfo> {
        self.isrs
            .values()
            .filter(|i| !matches!(i.pattern, IsrPattern::Compliant | IsrPattern::Empty))
            .collect()
    }

    /// Identify critical sections from a sequence of `(addr, mnemonic)` pairs.
    pub fn find_critical_sections(&mut self, instructions: &[(u16, &str)]) {
        let mut cli_stack: Vec<u16> = Vec::new();
        let mut sections: Vec<CriticalSection> = Vec::new();

        for &(addr, mn) in instructions {
            match mn {
                "CLI" => {
                    cli_stack.push(addr);
                }
                "SEI" => {
                    if let Some(cli_addr) = cli_stack.pop() {
                        let body = ((addr - cli_addr).saturating_sub(2)) / 2;
                        sections.push(CriticalSection {
                            cli_addr,
                            sei_addr: Some(addr),
                            body_instruction_count: body,
                            is_nested: !cli_stack.is_empty(),
                        });
                    }
                }
                _ => {}
            }
        }
        // Any unmatched CLI → unmatched critical section
        for cli_addr in cli_stack {
            sections.push(CriticalSection {
                cli_addr,
                sei_addr: None,
                body_instruction_count: 0,
                is_nested: false,
            });
        }
        self.crit_sections.extend(sections);
    }

    /// Vectors that have no registered ISR handler.
    #[must_use]
    pub fn unhandled_vectors(&self) -> Vec<&AvrInterruptVector> {
        self.vectors
            .iter()
            .filter(|v| v.number != 0 && !v.has_isr)
            .collect()
    }

    /// Find the ISR for a specific vector.
    #[must_use]
    pub fn isr_for_vector(&self, vector_num: u8) -> Option<&IsrInfo> {
        let v = self.vectors.iter().find(|v| v.number == vector_num)?;
        let handler = v.handler_addr?;
        self.isrs.get(&handler)
    }

    /// Return all resolved handler addresses (deduplicated).
    ///
    /// Different vectors can share a single handler routine; this reflects the
    /// set of distinct ISR entry points referenced by the vector table.
    #[must_use]
    pub fn unique_handler_addrs(&self) -> HashSet<u16> {
        self.vectors.iter().filter_map(|v| v.handler_addr).collect()
    }

    /// Return vectors keyed by their number, ordered for deterministic iteration.
    #[must_use]
    pub fn vectors_by_number(&self) -> BTreeMap<u8, &AvrInterruptVector> {
        self.vectors.iter().map(|v| (v.number, v)).collect()
    }
}

// ─── AvrInterruptModel ────────────────────────────────────────────────────────

/// Top-level AVR interrupt model, tying analyzer and meta-data together.
#[derive(Debug)]
pub struct AvrInterruptModel {
    pub analyzer: IvectorAnalyzer,
    /// Global interrupt state at analysis start.
    pub global_interrupts_enabled: bool,
}

impl AvrInterruptModel {
    /// Create model for `ATmega328P`.
    #[must_use]
    pub fn new_atmega328p() -> Self {
        Self {
            analyzer: IvectorAnalyzer::new_atmega328(),
            global_interrupts_enabled: true,
        }
    }

    /// Check whether any ISR in the model is unsafe.
    #[must_use]
    pub fn has_unsafe_isrs(&self) -> bool {
        self.analyzer.isrs.values().any(|i| !i.is_safe())
    }

    /// Brief summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "ATmega328P: {} vectors, {} ISRs registered, {} critical sections",
            self.analyzer.vector_count(),
            self.analyzer.isrs.len(),
            self.analyzer.crit_sections.len(),
        )
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Vectors ─────────────────────────────────────────────────────────────

    #[test]
    fn test_atmega328_has_26_vectors() {
        let v = atmega328_vectors();
        assert_eq!(v.len(), 26);
    }

    #[test]
    fn test_vector_0_is_reset() {
        let v = atmega328_vectors();
        assert_eq!(v[0].name, "RESET_vect");
        assert_eq!(v[0].number, 0);
    }

    #[test]
    fn test_vector_names_unique() {
        let v = atmega328_vectors();
        let names: HashSet<_> = v.iter().map(|x| x.name).collect();
        assert_eq!(names.len(), 26);
    }

    #[test]
    fn test_vector_word_addresses_sequential() {
        let v = atmega328_vectors();
        for (i, vec) in v.iter().enumerate() {
            assert_eq!(vec.word_address, u16::try_from(i).unwrap_or(u16::MAX) * 2);
        }
    }

    #[test]
    fn test_vector_25_is_spm_ready() {
        let v = atmega328_vectors();
        assert_eq!(v[25].name, "SPM_READY_vect");
    }

    #[test]
    fn test_vector_no_handler_by_default() {
        let v = atmega328_vectors();
        for vec in &v {
            assert!(vec.handler_addr.is_none());
        }
    }

    // ── InterruptPriority ───────────────────────────────────────────────────

    #[test]
    fn test_priority_higher() {
        let v = atmega328_vectors();
        let p = InterruptPriority::from_vectors(&v);
        assert!(p.higher_priority(1, 2));
        assert!(!p.higher_priority(5, 1));
    }

    #[test]
    fn test_priority_highest_non_reset() {
        let v = atmega328_vectors();
        let p = InterruptPriority::from_vectors(&v);
        assert_eq!(p.highest_non_reset(), Some(1));
    }

    #[test]
    fn test_priority_table_sorted() {
        let v = atmega328_vectors();
        let p = InterruptPriority::from_vectors(&v);
        let prios: Vec<_> = p.vector_priorities.iter().map(|&(_, p)| p).collect();
        let mut sorted = prios.clone();
        sorted.sort_unstable();
        assert_eq!(prios, sorted);
    }

    // ── IsrInfo ─────────────────────────────────────────────────────────────

    #[test]
    fn test_isr_compliant_pattern() {
        let isr = IsrInfo::classify(
            0x100,
            &["PUSH", "IN", "PUSH", "NOP", "POP", "OUT", "POP", "RETI"],
            true,
            true,
            false,
            3,
            4,
        );
        assert_eq!(isr.pattern, IsrPattern::Compliant);
        assert!(isr.is_safe());
    }

    #[test]
    fn test_isr_missing_sreg_save() {
        let isr = IsrInfo::classify(0x100, &["NOP", "RETI"], false, false, false, 0, 0);
        assert_eq!(isr.pattern, IsrPattern::MissingSregSave);
        assert!(!isr.is_safe());
    }

    #[test]
    fn test_isr_wrong_return() {
        let isr = IsrInfo::classify(
            0x100,
            &["PUSH", "IN", "POP", "OUT", "RET"],
            true,
            true,
            false,
            1,
            2,
        );
        assert_eq!(isr.pattern, IsrPattern::WrongReturn);
    }

    #[test]
    fn test_isr_empty() {
        let isr = IsrInfo::classify(0x100, &["RETI"], false, false, false, 0, 0);
        assert_eq!(isr.pattern, IsrPattern::Empty);
    }

    #[test]
    fn test_isr_enables_interrupts_unsafe() {
        let isr = IsrInfo::classify(0x100, &["SEI", "NOP", "RETI"], true, true, true, 0, 0);
        assert!(!isr.is_safe());
    }

    // ── CriticalSection ─────────────────────────────────────────────────────

    #[test]
    fn test_critical_section_small() {
        let cs = CriticalSection {
            cli_addr: 0x100,
            sei_addr: Some(0x120),
            body_instruction_count: 8,
            is_nested: false,
        };
        assert!(cs.is_small());
    }

    #[test]
    fn test_critical_section_duration() {
        let cs = CriticalSection {
            cli_addr: 0x100,
            sei_addr: Some(0x120),
            body_instruction_count: 10,
            is_nested: false,
        };
        assert_eq!(cs.duration_cycles(), 15);
    }

    // ── IvectorAnalyzer ─────────────────────────────────────────────────────

    #[test]
    fn test_analyzer_resolve_handler() {
        let mut a = IvectorAnalyzer::new_atmega328();
        a.resolve_handler(1, 0x0100).unwrap();
        let v = a.vectors.iter().find(|v| v.number == 1).unwrap();
        assert_eq!(v.handler_addr, Some(0x0100));
    }

    #[test]
    fn test_analyzer_invalid_vector_error() {
        let mut a = IvectorAnalyzer::new_atmega328();
        assert!(a.resolve_handler(30, 0x100).is_err());
    }

    #[test]
    fn test_analyzer_unhandled_vectors() {
        let a = IvectorAnalyzer::new_atmega328();
        let unhandled = a.unhandled_vectors();
        // All non-reset vectors are unhandled by default.
        assert_eq!(unhandled.len(), 25);
    }

    #[test]
    fn test_analyzer_find_critical_sections() {
        let mut a = IvectorAnalyzer::new_atmega328();
        let instrs: Vec<(u16, &str)> = vec![
            (0x100, "NOP"),
            (0x102, "CLI"),
            (0x104, "STS"),
            (0x106, "STS"),
            (0x108, "SEI"),
            (0x10A, "RET"),
        ];
        a.find_critical_sections(&instrs);
        assert_eq!(a.crit_sections.len(), 1);
        assert_eq!(a.crit_sections[0].cli_addr, 0x102);
        assert_eq!(a.crit_sections[0].sei_addr, Some(0x108));
    }

    #[test]
    fn test_analyzer_unmatched_cli() {
        let mut a = IvectorAnalyzer::new_atmega328();
        let instrs: Vec<(u16, &str)> = vec![
            (0x100, "CLI"),
            (0x102, "NOP"),
            // No SEI
        ];
        a.find_critical_sections(&instrs);
        assert_eq!(a.crit_sections.len(), 1);
        assert!(a.crit_sections[0].sei_addr.is_none());
    }

    #[test]
    fn test_analyzer_non_compliant_isrs() {
        let mut a = IvectorAnalyzer::new_atmega328();
        a.resolve_handler(1, 0x100).unwrap();
        let isr = IsrInfo::classify(0x100, &["NOP", "RET"], false, false, false, 0, 0);
        a.register_isr(isr);
        assert_eq!(a.non_compliant_isrs().len(), 1);
    }

    // ── AvrInterruptModel ───────────────────────────────────────────────────

    #[test]
    fn test_model_creation() {
        let m = AvrInterruptModel::new_atmega328p();
        assert!(m.global_interrupts_enabled);
        assert_eq!(m.analyzer.vector_count(), 26);
    }

    #[test]
    fn test_model_summary_contains_count() {
        let m = AvrInterruptModel::new_atmega328p();
        let s = m.summary();
        assert!(s.contains("26 vectors"));
    }

    #[test]
    fn test_model_no_unsafe_isrs_by_default() {
        let m = AvrInterruptModel::new_atmega328p();
        assert!(!m.has_unsafe_isrs());
    }

    #[test]
    fn test_model_with_unsafe_isr() {
        let mut m = AvrInterruptModel::new_atmega328p();
        m.analyzer.resolve_handler(2, 0x200).unwrap();
        let bad_isr = IsrInfo::classify(0x200, &["NOP", "RET"], false, false, false, 0, 0);
        m.analyzer.register_isr(bad_isr);
        assert!(m.has_unsafe_isrs());
    }

    // ── Additional coverage ─────────────────────────────────────────────────

    #[test]
    fn test_vector_int0_is_number_1() {
        let v = atmega328_vectors();
        let int0 = v.iter().find(|x| x.name == "INT0_vect").unwrap();
        assert_eq!(int0.number, 1);
    }

    #[test]
    fn test_vector_usart_rx_is_18() {
        let v = atmega328_vectors();
        let rx = v.iter().find(|x| x.name == "USART_RX_vect").unwrap();
        assert_eq!(rx.number, 18);
    }

    #[test]
    fn test_isr_missing_restore() {
        let isr = IsrInfo::classify(
            0x100,
            &["PUSH", "IN", "PUSH", "NOP", "RETI"],
            true,
            false,
            false,
            2,
            4,
        );
        assert_eq!(isr.pattern, IsrPattern::MissingSregRestore);
    }

    #[test]
    fn test_critical_section_not_small() {
        let cs = CriticalSection {
            cli_addr: 0x100,
            sei_addr: Some(0x200),
            body_instruction_count: 100,
            is_nested: false,
        };
        assert!(!cs.is_small());
    }

    #[test]
    fn test_nested_critical_section() {
        let mut a = IvectorAnalyzer::new_atmega328();
        let instrs: Vec<(u16, &str)> = vec![
            (0x100, "CLI"),
            (0x102, "CLI"), // nested
            (0x104, "SEI"),
            (0x106, "SEI"),
        ];
        a.find_critical_sections(&instrs);
        // Both CLI/SEI pairs should form critical sections.
        assert!(a.crit_sections.len() >= 2);
    }

    #[test]
    fn test_priority_known_vector() {
        let v = atmega328_vectors();
        let p = InterruptPriority::from_vectors(&v);
        // Vector 0 should exist with priority 0.
        assert!(p.vector_priorities.iter().any(|&(n, _)| n == 0));
    }
}
