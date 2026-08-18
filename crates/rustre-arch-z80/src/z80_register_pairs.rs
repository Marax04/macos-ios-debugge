//! `z80_register_pairs` — Z80 16-bit register pair analysis and tracking.
//!
//! The Z80 exposes six 16-bit register *pairs* formed from the 8-bit registers:
//! BC (B:C), DE (D:E), HL (H:L), and the special-purpose SP, PC, IX, IY.
//! Additionally, there is the alternate (shadow) set AF'/BC'/DE'/HL' accessed
//! via the EXX and EX AF,AF' instructions.
//!
//! This module provides:
//! * [`Z80RegisterPair`] — enum of all 16-bit pairs.
//! * [`PairUsage`] — tracks how many times a pair is read, written, or exchanged.
//! * `AF_shadow()` — returns the constant for the AF' shadow pair.
//! * `pair_value(hi, lo)` — combine two 8-bit bytes into a 16-bit pair value.

use crate::{REG_AF, REG_AF2, REG_BC, REG_BC2, REG_DE, REG_DE2, REG_HL, REG_HL2, REG_IX, REG_IY, REG_PC, REG_SP};
use serde::{Deserialize, Serialize};
use std::fmt;

// ─── Z80RegisterPair ─────────────────────────────────────────────────────────

/// All 16-bit register pairs available on the Zilog Z80.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Z80RegisterPair {
    /// BC — general-purpose / counter.
    BC,
    /// DE — general-purpose / destination pointer.
    DE,
    /// HL — primary address register / accumulator extension.
    HL,
    /// SP — Stack Pointer.
    SP,
    /// PC — Program Counter.
    PC,
    /// IX — Index Register X.
    IX,
    /// IY — Index Register Y.
    IY,
    /// AF — Accumulator + Flags.
    AF,
    /// BC' (alternate/shadow BC).
    BC2,
    /// DE' (alternate/shadow DE).
    DE2,
    /// HL' (alternate/shadow HL).
    HL2,
    /// AF' (alternate/shadow AF).
    AF2,
}

impl Z80RegisterPair {
    /// Returns the register ID constant (from the crate root).
    #[must_use]
    pub const fn reg_id(self) -> u32 {
        match self {
            Self::BC => REG_BC,
            Self::DE => REG_DE,
            Self::HL => REG_HL,
            Self::SP => REG_SP,
            Self::PC => REG_PC,
            Self::IX => REG_IX,
            Self::IY => REG_IY,
            Self::AF => REG_AF,
            Self::BC2 => REG_BC2,
            Self::DE2 => REG_DE2,
            Self::HL2 => REG_HL2,
            Self::AF2 => REG_AF2,
        }
    }

    /// Returns the mnemonic string used in Z80 assembly.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::BC => "BC",
            Self::DE => "DE",
            Self::HL => "HL",
            Self::SP => "SP",
            Self::PC => "PC",
            Self::IX => "IX",
            Self::IY => "IY",
            Self::AF => "AF",
            Self::BC2 => "BC'",
            Self::DE2 => "DE'",
            Self::HL2 => "HL'",
            Self::AF2 => "AF'",
        }
    }

    /// Returns `true` for pairs that belong to the alternate (shadow) register set.
    #[must_use]
    pub const fn is_shadow(self) -> bool {
        matches!(self, Self::BC2 | Self::DE2 | Self::HL2 | Self::AF2)
    }

    /// Returns `true` for index registers (IX and IY).
    #[must_use]
    pub const fn is_index(self) -> bool {
        matches!(self, Self::IX | Self::IY)
    }

    /// Returns `true` for general-purpose pairs (BC, DE, HL and their shadows).
    #[must_use]
    pub const fn is_general_purpose(self) -> bool {
        matches!(
            self,
            Self::BC | Self::DE | Self::HL | Self::BC2 | Self::DE2 | Self::HL2
        )
    }

    /// Returns the corresponding shadow pair, or `None` for non-shadowable pairs.
    #[must_use]
    pub const fn shadow_of(self) -> Option<Self> {
        match self {
            Self::BC => Some(Self::BC2),
            Self::DE => Some(Self::DE2),
            Self::HL => Some(Self::HL2),
            Self::AF => Some(Self::AF2),
            Self::BC2 => Some(Self::BC),
            Self::DE2 => Some(Self::DE),
            Self::HL2 => Some(Self::HL),
            Self::AF2 => Some(Self::AF),
            _ => None,
        }
    }

    /// Parse from a Z80 assembly mnemonic string (case-insensitive).
    #[must_use]
    pub fn from_mnemonic(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "BC" => Some(Self::BC),
            "DE" => Some(Self::DE),
            "HL" => Some(Self::HL),
            "SP" => Some(Self::SP),
            "PC" => Some(Self::PC),
            "IX" => Some(Self::IX),
            "IY" => Some(Self::IY),
            "AF" => Some(Self::AF),
            "BC'" => Some(Self::BC2),
            "DE'" => Some(Self::DE2),
            "HL'" => Some(Self::HL2),
            "AF'" => Some(Self::AF2),
            _ => None,
        }
    }

    /// Returns all 12 register pairs.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::BC, Self::DE, Self::HL, Self::SP, Self::PC,
            Self::IX, Self::IY, Self::AF,
            Self::BC2, Self::DE2, Self::HL2, Self::AF2,
        ]
    }

    /// Returns only the primary (non-shadow) pairs.
    #[must_use]
    pub fn primary() -> &'static [Self] {
        &[Self::BC, Self::DE, Self::HL, Self::SP, Self::PC, Self::IX, Self::IY, Self::AF]
    }

    /// Decompose into high and low 8-bit register names.
    ///
    /// Returns `None` for pairs that don't have a natural 8-bit decomposition
    /// (SP, PC, IX, IY and their high/low halves are handled separately).
    #[must_use]
    pub const fn components(self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::BC => Some(("B", "C")),
            Self::DE => Some(("D", "E")),
            Self::HL => Some(("H", "L")),
            Self::AF => Some(("A", "F")),
            Self::BC2 => Some(("B'", "C'")),
            Self::DE2 => Some(("D'", "E'")),
            Self::HL2 => Some(("H'", "L'")),
            Self::AF2 => Some(("A'", "F'")),
            _ => None,
        }
    }
}

impl fmt::Display for Z80RegisterPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.mnemonic())
    }
}

// ─── AF_shadow ───────────────────────────────────────────────────────────────

/// Returns the `AF'` (shadow/alternate Accumulator+Flags) register pair.
///
/// This is the pair accessed via `EX AF,AF'`.
#[must_use]
pub const fn af_shadow() -> Z80RegisterPair {
    Z80RegisterPair::AF2
}

/// Alias with the capitalisation used in Z80 documentation.
#[must_use]
#[allow(non_snake_case, reason = "the capitalisation IS the feature: every Z80 datasheet writes AF', and this alias exists only to offer that spelling beside the snake_case af_shadow()")]
pub const fn AF_shadow() -> Z80RegisterPair {
    af_shadow()
}

// ─── pair_value ───────────────────────────────────────────────────────────────

/// Combine a high byte and a low byte into a 16-bit register pair value.
///
/// # Example
/// ```
/// # use rustre_arch_z80::z80_register_pairs::pair_value;
/// assert_eq!(pair_value(0x12, 0x34), 0x1234);
/// ```
#[must_use]
pub const fn pair_value(hi: u8, lo: u8) -> u16 {
    u16::from_be_bytes([hi, lo])
}

/// Split a 16-bit pair value into (hi, lo) bytes.
#[must_use]
pub const fn split_pair(value: u16) -> (u8, u8) {
    let bytes = value.to_be_bytes();
    (bytes[0], bytes[1])
}

// ─── PairUsage ───────────────────────────────────────────────────────────────

/// Tracks how a 16-bit register pair is used throughout a code region.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PairUsage {
    /// Which pair this usage is tracking.
    pub pair: Option<Z80RegisterPair>,
    /// Number of 16-bit loads into this pair (LD rp,nn / POP / PUSH target).
    pub loads: u32,
    /// Number of 16-bit stores from this pair (LD (nn),rp / PUSH).
    pub stores: u32,
    /// Number of times the pair is used as an address operand (LD A,(rp)).
    pub address_uses: u32,
    /// Number of arithmetic operations involving this pair (ADD/SBC/INC/DEC).
    pub arithmetic: u32,
    /// Number of EXX or EX rp exchanges involving this pair.
    pub exchanges: u32,
    /// Number of PUSH operations.
    pub pushes: u32,
    /// Number of POP operations.
    pub pops: u32,
}

impl PairUsage {
    /// Create a new empty usage tracker for the given pair.
    #[must_use]
    pub const fn new(pair: Z80RegisterPair) -> Self {
        Self {
            pair: Some(pair),
            loads: 0,
            stores: 0,
            address_uses: 0,
            arithmetic: 0,
            exchanges: 0,
            pushes: 0,
            pops: 0,
        }
    }

    /// Record a 16-bit load.
    pub fn record_load(&mut self) {
        self.loads += 1;
    }

    /// Record a 16-bit store.
    pub fn record_store(&mut self) {
        self.stores += 1;
    }

    /// Record use as an address operand.
    pub fn record_address_use(&mut self) {
        self.address_uses += 1;
    }

    /// Record an arithmetic operation.
    pub fn record_arithmetic(&mut self) {
        self.arithmetic += 1;
    }

    /// Record an exchange (EXX, EX AF,AF').
    pub fn record_exchange(&mut self) {
        self.exchanges += 1;
    }

    /// Record a PUSH.
    pub fn record_push(&mut self) {
        self.pushes += 1;
        self.stores += 1;
    }

    /// Record a POP.
    pub fn record_pop(&mut self) {
        self.pops += 1;
        self.loads += 1;
    }

    /// Total use count.
    #[must_use]
    pub const fn total_uses(&self) -> u32 {
        self.loads + self.stores + self.address_uses + self.arithmetic + self.exchanges
    }

    /// Whether this pair is used as a counter (many INC/DEC, few loads).
    #[must_use]
    pub fn looks_like_counter(&self) -> bool {
        self.arithmetic >= 2 && self.arithmetic > self.loads
    }

    /// Whether this pair is used as a pointer (many address uses, few arithmetic).
    #[must_use]
    pub fn looks_like_pointer(&self) -> bool {
        self.address_uses >= 2 && self.address_uses >= self.arithmetic
    }

    /// Whether this pair is used primarily as a temporary save/restore container.
    #[must_use]
    pub fn looks_like_save_restore(&self) -> bool {
        self.exchanges >= 1 || (self.pushes >= 1 && self.pops >= 1)
    }
}

// ─── PairUsageMap ─────────────────────────────────────────────────────────────

/// A map from each [`Z80RegisterPair`] to its accumulated [`PairUsage`].
#[derive(Debug, Clone, Default)]
pub struct PairUsageMap {
    usages: std::collections::HashMap<Z80RegisterPair, PairUsage>,
}

impl PairUsageMap {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create a mutable reference to the usage tracker for `pair`.
    pub fn entry(&mut self, pair: Z80RegisterPair) -> &mut PairUsage {
        self.usages
            .entry(pair)
            .or_insert_with(|| PairUsage::new(pair))
    }

    /// Returns the usage for `pair`, or a default zeroed struct.
    #[must_use]
    pub fn get(&self, pair: Z80RegisterPair) -> &PairUsage {
        static DEFAULT: PairUsage = PairUsage {
            pair: None,
            loads: 0,
            stores: 0,
            address_uses: 0,
            arithmetic: 0,
            exchanges: 0,
            pushes: 0,
            pops: 0,
        };
        self.usages.get(&pair).unwrap_or(&DEFAULT)
    }

    /// Returns pairs sorted by total use count (most-used first).
    #[must_use]
    pub fn ranked(&self) -> Vec<(&Z80RegisterPair, &PairUsage)> {
        let mut v: Vec<_> = self.usages.iter().collect();
        v.sort_by(|a, b| b.1.total_uses().cmp(&a.1.total_uses()));
        v
    }

    /// Returns the most-used register pair, if any.
    #[must_use]
    pub fn most_used(&self) -> Option<Z80RegisterPair> {
        self.usages
            .iter()
            .max_by_key(|(_, u)| u.total_uses())
            .map(|(&pair, _)| pair)
    }

    /// Returns pairs that are used as address pointers.
    #[must_use]
    pub fn pointer_pairs(&self) -> Vec<Z80RegisterPair> {
        self.usages
            .iter()
            .filter(|(_, u)| u.looks_like_pointer())
            .map(|(&p, _)| p)
            .collect()
    }

    /// Returns pairs that are used as counters.
    #[must_use]
    pub fn counter_pairs(&self) -> Vec<Z80RegisterPair> {
        self.usages
            .iter()
            .filter(|(_, u)| u.looks_like_counter())
            .map(|(&p, _)| p)
            .collect()
    }
}

// ─── Instruction-level pair classification ────────────────────────────────────

/// Classify a Z80 mnemonic + operand pair and update usage stats.
///
/// This is a heuristic update based on the disassembled text of an instruction.
/// For production use, integrate with the MLIL/LLIL layer instead.
pub fn update_pair_usage(map: &mut PairUsageMap, mnemonic: &str, operands: &str) {
    let pairs = [
        (Z80RegisterPair::BC, "BC"),
        (Z80RegisterPair::DE, "DE"),
        (Z80RegisterPair::HL, "HL"),
        (Z80RegisterPair::SP, "SP"),
        (Z80RegisterPair::IX, "IX"),
        (Z80RegisterPair::IY, "IY"),
        (Z80RegisterPair::AF, "AF"),
    ];

    for (pair, name) in pairs {
        if !operands.contains(name) {
            continue;
        }
        match mnemonic {
            "LD" => {
                if operands.starts_with(name) {
                    map.entry(pair).record_load();
                } else {
                    map.entry(pair).record_store();
                }
            }
            "PUSH" => map.entry(pair).record_push(),
            "POP" => map.entry(pair).record_pop(),
            "ADD" | "ADC" | "SBC" | "INC" | "DEC" => map.entry(pair).record_arithmetic(),
            "EX" | "EXX" => map.entry(pair).record_exchange(),
            _ => {
                if operands.contains(&format!("({name})")) {
                    map.entry(pair).record_address_use();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reg_id_bc() {
        assert_eq!(Z80RegisterPair::BC.reg_id(), REG_BC);
    }

    #[test]
    fn test_reg_id_hl() {
        assert_eq!(Z80RegisterPair::HL.reg_id(), REG_HL);
    }

    #[test]
    fn test_reg_id_af2() {
        assert_eq!(Z80RegisterPair::AF2.reg_id(), REG_AF2);
    }

    #[test]
    fn test_mnemonic_bc() {
        assert_eq!(Z80RegisterPair::BC.mnemonic(), "BC");
    }

    #[test]
    fn test_mnemonic_af_shadow() {
        assert_eq!(Z80RegisterPair::AF2.mnemonic(), "AF'");
    }

    #[test]
    fn test_is_shadow() {
        assert!(Z80RegisterPair::BC2.is_shadow());
        assert!(!Z80RegisterPair::BC.is_shadow());
    }

    #[test]
    fn test_is_index() {
        assert!(Z80RegisterPair::IX.is_index());
        assert!(Z80RegisterPair::IY.is_index());
        assert!(!Z80RegisterPair::HL.is_index());
    }

    #[test]
    fn test_shadow_of_bc() {
        assert_eq!(Z80RegisterPair::BC.shadow_of(), Some(Z80RegisterPair::BC2));
    }

    #[test]
    fn test_shadow_of_sp_is_none() {
        assert!(Z80RegisterPair::SP.shadow_of().is_none());
    }

    #[test]
    fn test_from_mnemonic_bc() {
        assert_eq!(Z80RegisterPair::from_mnemonic("BC"), Some(Z80RegisterPair::BC));
    }

    #[test]
    fn test_from_mnemonic_af_shadow() {
        assert_eq!(Z80RegisterPair::from_mnemonic("AF'"), Some(Z80RegisterPair::AF2));
    }

    #[test]
    fn test_from_mnemonic_unknown() {
        assert!(Z80RegisterPair::from_mnemonic("XX").is_none());
    }

    #[test]
    fn test_components_bc() {
        assert_eq!(Z80RegisterPair::BC.components(), Some(("B", "C")));
    }

    #[test]
    fn test_components_sp_is_none() {
        assert!(Z80RegisterPair::SP.components().is_none());
    }

    #[test]
    fn test_pair_value() {
        assert_eq!(pair_value(0x12, 0x34), 0x1234);
    }

    #[test]
    fn test_split_pair() {
        assert_eq!(split_pair(0xABCD), (0xAB, 0xCD));
    }

    #[test]
    fn test_pair_value_split_roundtrip() {
        let v = 0x5A3Cu16;
        let (hi, lo) = split_pair(v);
        assert_eq!(pair_value(hi, lo), v);
    }

    #[test]
    fn test_af_shadow() {
        assert_eq!(AF_shadow(), Z80RegisterPair::AF2);
    }

    #[test]
    fn test_pair_usage_total_uses() {
        let mut u = PairUsage::new(Z80RegisterPair::HL);
        u.record_load();
        u.record_arithmetic();
        u.record_address_use();
        assert_eq!(u.total_uses(), 3);
    }

    #[test]
    fn test_pair_usage_looks_like_counter() {
        let mut u = PairUsage::new(Z80RegisterPair::BC);
        u.record_arithmetic();
        u.record_arithmetic();
        u.record_arithmetic();
        assert!(u.looks_like_counter());
    }

    #[test]
    fn test_pair_usage_looks_like_pointer() {
        let mut u = PairUsage::new(Z80RegisterPair::HL);
        u.record_address_use();
        u.record_address_use();
        u.record_address_use();
        assert!(u.looks_like_pointer());
    }

    #[test]
    fn test_pair_usage_push_pop() {
        let mut u = PairUsage::new(Z80RegisterPair::AF);
        u.record_push();
        u.record_pop();
        assert!(u.looks_like_save_restore());
        assert_eq!(u.pushes, 1);
        assert_eq!(u.pops, 1);
    }

    #[test]
    fn test_pair_usage_map_most_used() {
        let mut map = PairUsageMap::new();
        map.entry(Z80RegisterPair::HL).record_load();
        map.entry(Z80RegisterPair::HL).record_arithmetic();
        map.entry(Z80RegisterPair::HL).record_address_use();
        map.entry(Z80RegisterPair::BC).record_arithmetic();
        assert_eq!(map.most_used(), Some(Z80RegisterPair::HL));
    }

    #[test]
    fn test_update_pair_usage_push() {
        let mut map = PairUsageMap::new();
        update_pair_usage(&mut map, "PUSH", "BC");
        assert_eq!(map.get(Z80RegisterPair::BC).pushes, 1);
    }

    #[test]
    fn test_update_pair_usage_ld_load() {
        let mut map = PairUsageMap::new();
        update_pair_usage(&mut map, "LD", "HL,#$1234");
        assert_eq!(map.get(Z80RegisterPair::HL).loads, 1);
    }

    #[test]
    fn test_all_returns_twelve() {
        assert_eq!(Z80RegisterPair::all().len(), 12);
    }

    #[test]
    fn test_primary_returns_eight() {
        assert_eq!(Z80RegisterPair::primary().len(), 8);
    }

    #[test]
    fn test_is_general_purpose() {
        assert!(Z80RegisterPair::BC.is_general_purpose());
        assert!(Z80RegisterPair::HL2.is_general_purpose());
        assert!(!Z80RegisterPair::SP.is_general_purpose());
        assert!(!Z80RegisterPair::IX.is_general_purpose());
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", Z80RegisterPair::BC), "BC");
        assert_eq!(format!("{}", Z80RegisterPair::AF2), "AF'");
    }
}
