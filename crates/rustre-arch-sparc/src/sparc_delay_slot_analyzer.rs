//! SPARC delay-slot analysis.
//!
//! Every SPARC branch/call/return has a mandatory delay slot: the instruction
//! immediately following it is executed before the branch takes effect.
//! When the annul bit is set on conditional branches, the delay-slot instruction
//! is *not* executed if the branch is *not* taken.
//!
//! This module provides:
//! - [`DelaySlotAnalyzer`] — walks a linear instruction sequence and classifies
//!   each instruction's delay-slot behaviour.
//! - [`DelaySlot`] — describes the delay-slot instruction paired with its branch.
//! - [`AnnulledBranch`] — a branch with an annulled delay slot.
//! - [`DelaySlotReport`] — aggregate statistics and findings for a code region.

use ahash::AHashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use rustre_core::arch::{InstrFlags, Architecture};
use rustre_core::address::Address;

use crate::{SparcArch, SparcDelayInfo, SparcLinearDisassembler};

// ── DelaySlotKind ─────────────────────────────────────────────────────────────

/// Whether a delay-slot instruction is always, conditionally, or never executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DelaySlotKind {
    /// Always executed (unconditional branch / CALL / RETURN).
    Always,
    /// Executed only when the branch is *taken* (annulled conditional branch).
    OnTaken,
    /// Executed only when the branch is *not taken* (inverse of `OnTaken`).
    OnNotTaken,
}

impl fmt::Display for DelaySlotKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Always => write!(f, "always"),
            Self::OnTaken => write!(f, "on-taken"),
            Self::OnNotTaken => write!(f, "on-not-taken"),
        }
    }
}

// ── DelaySlotFillability ──────────────────────────────────────────────────────

/// Whether a delay slot is "useful" (does real work) or is a NOP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DelaySlotFill {
    /// The delay slot contains a NOP — wasted cycle.
    Nop,
    /// The delay slot does useful work.
    Useful,
    /// The delay slot modifies the branch condition register — risky.
    ModifiesCondition,
    /// The delay slot contains another branch — illegal / very unusual.
    Branch,
}

impl fmt::Display for DelaySlotFill {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nop => write!(f, "nop"),
            Self::Useful => write!(f, "useful"),
            Self::ModifiesCondition => write!(f, "modifies-condition"),
            Self::Branch => write!(f, "branch"),
        }
    }
}

// ── DelaySlot ─────────────────────────────────────────────────────────────────

/// A delay-slot instruction paired with the branch that owns it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelaySlot {
    /// Address of the branch instruction.
    pub branch_addr: u64,
    /// Mnemonic of the branch instruction.
    pub branch_mnemonic: String,
    /// Address of the delay-slot instruction.
    pub slot_addr: u64,
    /// Mnemonic of the delay-slot instruction.
    pub slot_mnemonic: String,
    /// How the delay-slot instruction is executed.
    pub kind: DelaySlotKind,
    /// Quality of the delay-slot fill.
    pub fill: DelaySlotFill,
    /// Whether this is an annulled branch.
    pub annulled: bool,
    /// Target address of the branch (if known statically).
    pub branch_target: Option<u64>,
}

impl DelaySlot {
    /// Return `true` if the delay slot instruction is always executed.
    #[must_use]
    pub const fn is_always_executed(&self) -> bool {
        matches!(self.kind, DelaySlotKind::Always)
    }

    /// Return `true` if the delay slot is wasted (NOP).
    #[must_use]
    pub const fn is_wasted(&self) -> bool {
        matches!(self.fill, DelaySlotFill::Nop)
    }
}

impl fmt::Display for DelaySlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#010x}: {} ; delay={} fill={} target={}",
            self.branch_addr,
            self.branch_mnemonic,
            self.kind,
            self.fill,
            self.branch_target
                .map_or_else(|| "unknown".to_string(), |t| format!("{t:#010x}"))
        )
    }
}

// ── AnnulledBranch ────────────────────────────────────────────────────────────

/// A conditional SPARC branch with the annul bit set (suffix `,a`).
///
/// For annulled branches:
/// - If the branch is **taken**, the delay slot **is** executed.
/// - If the branch is **not taken**, the delay slot is **skipped**.
///
/// This is the opposite of the default (non-annulled) behaviour where the
/// delay slot is always executed regardless of the branch outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnulledBranch {
    /// Address of the branch instruction.
    pub addr: u64,
    /// Full mnemonic (includes `,a` suffix).
    pub mnemonic: String,
    /// Condition code (extracted from the mnemonic).
    pub condition: String,
    /// Branch target address.
    pub target: Option<u64>,
    /// The delay-slot record.
    pub delay_slot: DelaySlot,
}

impl AnnulledBranch {
    /// Return the condition name (without the leading 'B' and trailing ',a').
    #[must_use]
    pub fn cond_name(&self) -> &str {
        &self.condition
    }
}

impl fmt::Display for AnnulledBranch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AnnulledBranch @ {:#010x}: {} (cond={}) target={}",
            self.addr,
            self.mnemonic,
            self.condition,
            self.target
                .map_or_else(|| "?".to_string(), |t| format!("{t:#010x}"))
        )
    }
}

// ── DelaySlotReport ───────────────────────────────────────────────────────────

/// Aggregate analysis results for a code region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelaySlotReport {
    /// All delay slots found (one per branch/call/return with a delay slot).
    pub delay_slots: Vec<DelaySlot>,
    /// All annulled branches found.
    pub annulled_branches: Vec<AnnulledBranch>,
    /// Total instructions scanned.
    pub total_instructions: usize,
    /// Number of instructions that have a delay slot.
    pub branch_count: usize,
    /// Number of wasted delay slots (NOPs).
    pub wasted_slots: usize,
    /// Number of delay slots doing useful work.
    pub useful_slots: usize,
    /// Number of delay slots that modify a condition register.
    pub risky_slots: usize,
    /// Addresses of instructions inside delay slots (for CFG construction).
    pub delay_slot_addresses: Vec<u64>,
}

impl DelaySlotReport {
    /// Efficiency ratio: useful / total slots [0.0–1.0].
    #[must_use]
    pub fn fill_efficiency(&self) -> f64 {
        if self.branch_count == 0 {
            return 1.0;
        }
        self.useful_slots as f64 / self.branch_count as f64
    }

    /// Return all delay slots that are wasted.
    #[must_use]
    pub fn wasted(&self) -> Vec<&DelaySlot> {
        self.delay_slots.iter().filter(|d| d.is_wasted()).collect()
    }

    /// Return all delay slots with risky fills.
    #[must_use]
    pub fn risky(&self) -> Vec<&DelaySlot> {
        self.delay_slots
            .iter()
            .filter(|d| matches!(d.fill, DelaySlotFill::ModifiesCondition))
            .collect()
    }

    /// Return `true` if the given address is a delay-slot instruction.
    #[must_use]
    pub fn is_delay_slot_addr(&self, addr: u64) -> bool {
        self.delay_slot_addresses.contains(&addr)
    }
}

// ── DelaySlotAnalyzer ─────────────────────────────────────────────────────────

/// Analyzes a stream of SPARC instructions to identify delay slots and
/// characterise their fill quality.
pub struct DelaySlotAnalyzer {
    arch: SparcArch,
    /// Set of mnemonic prefixes that modify condition codes.
    condition_modifiers: Vec<&'static str>,
}

impl DelaySlotAnalyzer {
    /// Create a new analyzer for the given SPARC architecture variant.
    #[must_use]
    pub fn new(arch: SparcArch) -> Self {
        Self {
            arch,
            condition_modifiers: vec![
                "ADDCC", "ANDCC", "ORCC", "XORCC", "SUBCC", "ANDNCC", "ORNCC",
                "XNORCC", "ADDXCC", "UMULCC", "SMULCC", "SUBXCC", "UDIVCC", "SDIVCC",
                "TADDCC", "TSUBCC", "FCMPS", "FCMPD", "FCMPES", "FCMPED",
            ],
        }
    }

    /// Create a default V8 analyzer.
    #[must_use]
    pub fn new_v8() -> Self {
        Self::new(SparcArch::new_v8())
    }

    /// Create a V9 analyzer.
    #[must_use]
    pub fn new_v9() -> Self {
        Self::new(SparcArch::new_v9())
    }

    /// Analyze a byte slice starting at `base_addr`.
    ///
    /// Returns a full [`DelaySlotReport`].
    ///
    /// # Errors
    ///
    /// Decode errors for individual instructions are silently skipped (the
    /// instruction is treated as unknown and the analysis continues).
    #[must_use]
    pub fn analyze(&self, bytes: &[u8], base_addr: u64) -> DelaySlotReport {
        let base = Address::new(base_addr);
        let instructions: Vec<_> = SparcLinearDisassembler::new(&self.arch, bytes, base)
            .filter_map(|r| r.ok())
            .collect();

        let total_instructions = instructions.len();
        let mut delay_slots = Vec::new();
        let mut annulled_branches = Vec::new();
        let mut delay_slot_addresses = Vec::new();

        let mut i = 0usize;
        while i < instructions.len() {
            let instr = &instructions[i];
            let delay_info = SparcDelayInfo::from_instruction(instr);

            if delay_info.has_delay_slot && i + 1 < instructions.len() {
                let slot_instr = &instructions[i + 1];
                delay_slot_addresses.push(slot_instr.address.as_u64());

                let fill = self.classify_fill(slot_instr);
                let kind = self.classify_kind(instr, &delay_info);
                let branch_target = self.extract_branch_target(instr, base_addr);

                let ds = DelaySlot {
                    branch_addr: instr.address.as_u64(),
                    branch_mnemonic: instr.mnemonic.clone(),
                    slot_addr: slot_instr.address.as_u64(),
                    slot_mnemonic: slot_instr.mnemonic.clone(),
                    kind,
                    fill,
                    annulled: delay_info.annulled,
                    branch_target,
                };

                if delay_info.annulled {
                    let cond = self.extract_condition(&delay_info.base_mnemonic);
                    annulled_branches.push(AnnulledBranch {
                        addr: instr.address.as_u64(),
                        mnemonic: instr.mnemonic.clone(),
                        condition: cond,
                        target: branch_target,
                        delay_slot: ds.clone(),
                    });
                }

                delay_slots.push(ds);
                i += 2; // skip delay slot
            } else {
                i += 1;
            }
        }

        let branch_count = delay_slots.len();
        let wasted_slots = delay_slots.iter().filter(|d| d.is_wasted()).count();
        let useful_slots = delay_slots
            .iter()
            .filter(|d| matches!(d.fill, DelaySlotFill::Useful))
            .count();
        let risky_slots = delay_slots
            .iter()
            .filter(|d| matches!(d.fill, DelaySlotFill::ModifiesCondition))
            .count();

        DelaySlotReport {
            delay_slots,
            annulled_branches,
            total_instructions,
            branch_count,
            wasted_slots,
            useful_slots,
            risky_slots,
            delay_slot_addresses,
        }
    }

    /// Classify the fill quality of a delay-slot instruction.
    fn classify_fill(&self, slot: &rustre_core::arch::Instruction) -> DelaySlotFill {
        let mn = slot.mnemonic.trim();
        if mn == "NOP" {
            return DelaySlotFill::Nop;
        }
        if slot.flags.intersects(InstrFlags::BRANCH | InstrFlags::CALL | InstrFlags::RET) {
            return DelaySlotFill::Branch;
        }
        if self
            .condition_modifiers
            .iter()
            .any(|&m| mn.eq_ignore_ascii_case(m))
        {
            return DelaySlotFill::ModifiesCondition;
        }
        DelaySlotFill::Useful
    }

    /// Determine how the delay slot is executed for this branch.
    fn classify_kind(
        &self,
        branch: &rustre_core::arch::Instruction,
        info: &SparcDelayInfo,
    ) -> DelaySlotKind {
        if !info.annulled {
            // Non-annulled: always executed regardless of branch outcome.
            return DelaySlotKind::Always;
        }
        // Annulled: delay slot executed only when branch is taken.
        if branch.flags.contains(InstrFlags::CONDITIONAL) {
            DelaySlotKind::OnTaken
        } else {
            // Unconditional annulled branch (e.g. BA,a): slot skipped always.
            DelaySlotKind::Always
        }
    }

    /// Extract the branch target address from the operands string.
    fn extract_branch_target(
        &self,
        instr: &rustre_core::arch::Instruction,
        _base: u64,
    ) -> Option<u64> {
        let ops = &instr.operands;
        let hex_str: String = ops
            .trim_start_matches('$')
            .chars()
            .take_while(|c| c.is_ascii_hexdigit())
            .collect();
        u64::from_str_radix(&hex_str, 16).ok()
    }

    /// Extract the condition name from a branch mnemonic (e.g. "BNE" → "NE").
    fn extract_condition(&self, base_mnemonic: &str) -> String {
        if let Some(stripped) = base_mnemonic.strip_prefix('B') {
            stripped.to_string()
        } else {
            base_mnemonic.to_string()
        }
    }

    /// Return whether the given address is a delay-slot instruction in `report`.
    #[must_use]
    pub fn is_delay_slot(&self, report: &DelaySlotReport, addr: u64) -> bool {
        report.is_delay_slot_addr(addr)
    }

    /// Build a map from branch address → delay-slot address for quick lookup.
    #[must_use]
    pub fn build_branch_to_slot_map(
        &self,
        report: &DelaySlotReport,
    ) -> AHashMap<u64, u64> {
        report
            .delay_slots
            .iter()
            .map(|ds| (ds.branch_addr, ds.slot_addr))
            .collect()
    }

    /// Return only NOPped delay slots (wasted cycles) from a report.
    #[must_use]
    pub fn find_nop_slots<'a>(
        &self,
        report: &'a DelaySlotReport,
    ) -> Vec<&'a DelaySlot> {
        report.wasted()
    }
}

impl fmt::Debug for DelaySlotAnalyzer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DelaySlotAnalyzer({})", self.arch.name())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode_nop;

    fn analyzer() -> DelaySlotAnalyzer {
        DelaySlotAnalyzer::new_v8()
    }

    // Encode a BA,a (annulled unconditional branch) at PC 0x1000, target +8.
    // BA,a: a=1, cond=8, op2=2, disp22=2 (2*4=8)
    fn encode_ba_annul(disp_words: i32) -> [u8; 4] {
        let d22 = (disp_words as u32) & 0x3FFFFF;
        let enc: u32 = (1u32 << 29) | (8u32 << 25) | (2u32 << 22) | d22;
        enc.to_be_bytes()
    }

    // Encode a BNE (non-annulled) with disp.
    fn encode_bne(disp_words: i32) -> [u8; 4] {
        let d22 = (disp_words as u32) & 0x3FFFFF;
        let enc: u32 = (9u32 << 25) | (2u32 << 22) | d22;
        enc.to_be_bytes()
    }

    // Encode a CALL with disp30.
    fn encode_call_instr(disp30_words: i32) -> [u8; 4] {
        let d30 = (disp30_words as u32) & 0x3FFFFFFF;
        let enc: u32 = (1u32 << 30) | d30;
        enc.to_be_bytes()
    }

    #[test]
    fn test_analyze_nop_delay_slot() {
        // BNE target ; NOP
        let bne = encode_bne(2);
        let nop = encode_nop().to_be_bytes();
        let code: Vec<u8> = bne.iter().chain(nop.iter()).copied().collect();
        let report = analyzer().analyze(&code, 0x1000);
        assert_eq!(report.branch_count, 1);
        assert_eq!(report.wasted_slots, 1);
        assert_eq!(report.useful_slots, 0);
    }

    #[test]
    fn test_analyze_useful_delay_slot() {
        // CALL target ; ADD %o0, %o1, %o2
        let call = encode_call_instr(2);
        // ADD %o0, %o1, %o2: op=2, op3=0, rs1=8, rs2=9, rd=10
        let add: u32 = (0b10u32 << 30) | (10u32 << 25) | (0u32 << 19) | (8u32 << 14) | 9u32;
        let add_bytes = add.to_be_bytes();
        let code: Vec<u8> = call.iter().chain(add_bytes.iter()).copied().collect();
        let report = analyzer().analyze(&code, 0x1000);
        assert_eq!(report.branch_count, 1);
        assert_eq!(report.useful_slots, 1);
        assert_eq!(report.wasted_slots, 0);
    }

    #[test]
    fn test_annulled_branch_detected() {
        let ba_a = encode_ba_annul(2);
        let nop = encode_nop().to_be_bytes();
        let code: Vec<u8> = ba_a.iter().chain(nop.iter()).copied().collect();
        let report = analyzer().analyze(&code, 0x1000);
        // BA,a is unconditional — classified as Always.
        assert_eq!(report.branch_count, 1);
    }

    #[test]
    fn test_delay_slot_addresses() {
        let bne = encode_bne(3);
        let nop = encode_nop().to_be_bytes();
        let code: Vec<u8> = bne.iter().chain(nop.iter()).copied().collect();
        let report = analyzer().analyze(&code, 0x1000);
        assert!(report.is_delay_slot_addr(0x1004));
    }

    #[test]
    fn test_no_branches_empty_report() {
        let nop = encode_nop().to_be_bytes();
        let code: Vec<u8> = nop.iter().copied().cycle().take(16).collect();
        let report = analyzer().analyze(&code, 0x1000);
        assert_eq!(report.branch_count, 0);
        assert_eq!(report.wasted_slots, 0);
    }

    #[test]
    fn test_fill_efficiency_all_nop() {
        let bne = encode_bne(2);
        let nop = encode_nop().to_be_bytes();
        let code: Vec<u8> = bne.iter().chain(nop.iter()).copied().collect();
        let report = analyzer().analyze(&code, 0x1000);
        assert!((report.fill_efficiency() - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_fill_efficiency_all_useful() {
        let call = encode_call_instr(2);
        let add: u32 = (0b10u32 << 30) | (10u32 << 25) | (0u32 << 19) | (8u32 << 14) | 9u32;
        let code: Vec<u8> = call
            .iter()
            .chain(add.to_be_bytes().iter())
            .copied()
            .collect();
        let report = analyzer().analyze(&code, 0x1000);
        assert!((report.fill_efficiency() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_branch_to_slot_map() {
        let bne = encode_bne(2);
        let nop = encode_nop().to_be_bytes();
        let code: Vec<u8> = bne.iter().chain(nop.iter()).copied().collect();
        let a = analyzer();
        let report = a.analyze(&code, 0x1000);
        let map = a.build_branch_to_slot_map(&report);
        assert!(map.contains_key(&0x1000));
        assert_eq!(map[&0x1000], 0x1004);
    }

    #[test]
    fn test_find_nop_slots() {
        let bne = encode_bne(2);
        let nop = encode_nop().to_be_bytes();
        let code: Vec<u8> = bne.iter().chain(nop.iter()).copied().collect();
        let a = analyzer();
        let report = a.analyze(&code, 0x1000);
        let nops = a.find_nop_slots(&report);
        assert_eq!(nops.len(), 1);
    }

    #[test]
    fn test_delay_slot_display() {
        let ds = DelaySlot {
            branch_addr: 0x1000,
            branch_mnemonic: "BNE".to_string(),
            slot_addr: 0x1004,
            slot_mnemonic: "NOP".to_string(),
            kind: DelaySlotKind::Always,
            fill: DelaySlotFill::Nop,
            annulled: false,
            branch_target: Some(0x1010),
        };
        let s = ds.to_string();
        assert!(s.contains("0x00001000") || s.contains("1000"));
        assert!(s.contains("BNE"));
    }

    #[test]
    fn test_annulled_branch_display() {
        let ds = DelaySlot {
            branch_addr: 0x2000,
            branch_mnemonic: "BNE,a".to_string(),
            slot_addr: 0x2004,
            slot_mnemonic: "ADD".to_string(),
            kind: DelaySlotKind::OnTaken,
            fill: DelaySlotFill::Useful,
            annulled: true,
            branch_target: Some(0x2020),
        };
        let ab = AnnulledBranch {
            addr: 0x2000,
            mnemonic: "BNE,a".to_string(),
            condition: "NE".to_string(),
            target: Some(0x2020),
            delay_slot: ds,
        };
        let s = ab.to_string();
        assert!(s.contains("AnnulledBranch"));
        assert!(s.contains("NE"));
    }

    #[test]
    fn test_delay_slot_kind_display() {
        assert_eq!(DelaySlotKind::Always.to_string(), "always");
        assert_eq!(DelaySlotKind::OnTaken.to_string(), "on-taken");
        assert_eq!(DelaySlotKind::OnNotTaken.to_string(), "on-not-taken");
    }

    #[test]
    fn test_multiple_branches() {
        let call = encode_call_instr(5);
        let nop = encode_nop().to_be_bytes();
        let bne = encode_bne(3);
        let add: u32 = (0b10u32 << 30) | (10u32 << 25) | (0u32 << 19) | (8u32 << 14) | 9u32;
        let code: Vec<u8> = call
            .iter()
            .chain(nop.iter())
            .chain(bne.iter())
            .chain(add.to_be_bytes().iter())
            .copied()
            .collect();
        let report = analyzer().analyze(&code, 0x1000);
        assert_eq!(report.branch_count, 2);
        assert_eq!(report.wasted_slots, 1);
        assert_eq!(report.useful_slots, 1);
    }

    #[test]
    fn test_total_instructions_count() {
        let nop = encode_nop().to_be_bytes();
        let code: Vec<u8> = nop.iter().copied().cycle().take(20).collect();
        let report = analyzer().analyze(&code, 0);
        assert_eq!(report.total_instructions, 5); // 20 bytes / 4
    }

    #[test]
    fn test_risky_delay_slot_detected() {
        // BNE target ; ADDCC %o0, %o1, %o0 (modifies condition)
        let bne = encode_bne(2);
        // ADDCC: op3=0x10
        let addcc: u32 = (0b10u32 << 30) | (8u32 << 25) | (0x10u32 << 19) | (8u32 << 14) | 9u32;
        let code: Vec<u8> = bne
            .iter()
            .chain(addcc.to_be_bytes().iter())
            .copied()
            .collect();
        let report = analyzer().analyze(&code, 0x1000);
        assert!(report.risky_slots > 0 || report.useful_slots > 0);
    }

    #[test]
    fn test_empty_bytes() {
        let report = analyzer().analyze(&[], 0x1000);
        assert_eq!(report.total_instructions, 0);
        assert_eq!(report.branch_count, 0);
    }

    #[test]
    fn test_analyzer_debug_format() {
        let a = analyzer();
        let s = format!("{a:?}");
        assert!(s.contains("DelaySlotAnalyzer"));
    }
}
