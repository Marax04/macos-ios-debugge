//! PowerPC branch analyzer — classifies branches, decodes BO/BI fields,
//! finds function calls, and estimates branch prediction.

use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Branch types and targets
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchType {
    Unconditional,
    Conditional,
    Link,
    CounterReg,
    LinkReg,
    CondLink,
}

impl fmt::Display for BranchType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Unconditional => "unconditional",
            Self::Conditional   => "conditional",
            Self::Link          => "link (call)",
            Self::CounterReg    => "bcctr (CTR)",
            Self::LinkReg       => "bclr  (LR)",
            Self::CondLink      => "conditional-link",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchTarget {
    Absolute(u64),
    Relative(i64),
    /// The actual resolved address after adding PC.
    Resolved(u64),
    Register,
    Unknown,
}

impl fmt::Display for BranchTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absolute(a) | Self::Resolved(a) => write!(f, "{a:#x}"),
            Self::Relative(r)  => write!(f, "{r:+#x}"),
            Self::Register     => f.write_str("<register>"),
            Self::Unknown      => f.write_str("<unknown>"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Branch condition decode
// ─────────────────────────────────────────────────────────────────────────────

/// Decoded condition from BO and BI fields.
#[derive(Debug, Clone)]
pub struct BranchCondition {
    pub bo: u8,
    pub bi: u8,
    pub condition_meaning: String,
}

impl BranchCondition {
    #[must_use]
    pub fn new(bo: u8, bi: u8) -> Self {
        let meaning = decode_bo_meaning(bo, bi);
        Self { bo, bi, condition_meaning: meaning }
    }

    #[must_use]
    pub const fn is_always_taken(&self) -> bool {
        // BO[2] = 1 means branch regardless of condition
        // BO[4] = 1 means don't decrement CTR
        (self.bo & 0b00100) != 0 && (self.bo & 0b10000) != 0
    }

    #[must_use]
    pub const fn uses_ctr(&self) -> bool {
        // BO[2] = 0 means decrement and test CTR
        (self.bo & 0b00100) == 0
    }

    #[must_use]
    pub const fn tests_crt(&self) -> bool {
        // BO[0] = 0: test CR bit
        (self.bo & 0b00001) == 0 && (self.bo & 0b00100) != 0
    }

    #[must_use]
    pub const fn cr_field(&self) -> u8 {
        self.bi >> 2
    }

    #[must_use]
    pub const fn cr_bit_in_field(&self) -> u8 {
        self.bi & 3
    }

    /// Prediction hint from BO\[3\] (`+` = likely taken, `-` = likely not taken).
    #[must_use]
    pub const fn prediction_hint(&self) -> Option<&'static str> {
        // BO[1] = 0 and BO[3] = branch-prediction bit in some encodings
        // PowerPC uses '+'/'-' suffix for static prediction hints encoded in BO
        match (self.bo >> 1) & 1 {
            1 => Some("+"),
            _ => None,
        }
    }
}

/// Decode the BO field meaning into a human-readable string.
fn decode_bo_meaning(bo: u8, bi: u8) -> String {
    let decrement_ctr = (bo & 0b00100) == 0;
    let ctr_zero      = (bo & 0b00010) != 0;
    let ignore_cr     = (bo & 0b10000) != 0;
    let cr_true       = (bo & 0b01000) != 0;

    let cr_field = bi >> 2;
    let cr_bit   = bi & 3;
    let bit_name = match cr_bit {
        0 => "LT", 1 => "GT", 2 => "EQ", 3 => "SO", _ => "?",
    };

    match (decrement_ctr, ignore_cr) {
        (false, true) => {
            // Branch depends only on CTR
            if ctr_zero {
                "branch if CTR==0 (after decrement)".to_string()
            } else {
                "branch if CTR!=0 (after decrement)".to_string()
            }
        }
        (true, false) => {
            // Branch depends only on CR
            if cr_true {
                format!("branch if CR{cr_field}.{bit_name}=1")
            } else {
                format!("branch if CR{cr_field}.{bit_name}=0")
            }
        }
        (false, false) => {
            // Both CTR and CR
            let ctr_cond = if ctr_zero { "CTR==0" } else { "CTR!=0" };
            let cr_part = if cr_true {
                format!("CR{cr_field}.{bit_name}=1")
            } else {
                format!("CR{cr_field}.{bit_name}=0")
            };
            format!("branch if {ctr_cond} and {cr_part}")
        }
        (true, true) => "branch always".into(),
    }
}

/// Decode BI field into (CR field index, bit name).
#[must_use]
pub const fn decode_bi_field(bi: u8) -> (u8, &'static str) {
    let field = bi >> 2;
    let bit   = bi & 3;
    let name  = match bit {
        0 => "LT",
        1 => "GT",
        2 => "EQ",
        3 => "SO",
        _ => "?",
    };
    (field, name)
}

// ─────────────────────────────────────────────────────────────────────────────
// PpcBranch
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PpcBranch {
    pub addr: u64,
    pub target: BranchTarget,
    pub branch_type: BranchType,
    pub condition: Option<BranchCondition>,
    pub link: bool,
    pub raw: u32,
}

impl PpcBranch {
    #[must_use]
    pub const fn is_call(&self) -> bool {
        self.link
    }

    #[must_use]
    pub const fn is_return(&self) -> bool {
        matches!(self.branch_type, BranchType::LinkReg) && !self.link
    }

    #[must_use]
    pub const fn is_indirect(&self) -> bool {
        matches!(
            self.branch_type,
            BranchType::CounterReg | BranchType::LinkReg
        )
    }

    #[must_use]
    pub const fn resolved_target(&self) -> Option<u64> {
        match &self.target {
            BranchTarget::Absolute(a) | BranchTarget::Resolved(a) => Some(*a),
            BranchTarget::Relative(r)  => Some(self.addr.wrapping_add_signed(*r)),
            _ => None,
        }
    }
}

impl fmt::Display for PpcBranch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#010x}  {:<18}  target={:<16}  call={}  ret={}",
            self.addr,
            self.branch_type.to_string(),
            self.target,
            self.link,
            self.is_return()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bit helpers
// ─────────────────────────────────────────────────────────────────────────────

#[inline]
const fn bits(raw: u32, hi: u32, lo: u32) -> u32 {
    let width = hi - lo + 1;
    let mask = if width >= 32 { u32::MAX } else { (1u32 << width) - 1 };
    (raw >> lo) & mask
}

// ─────────────────────────────────────────────────────────────────────────────
// PpcBranchAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

pub struct PpcBranchAnalyzer {
    pub big_endian: bool,
}

impl PpcBranchAnalyzer {
    #[must_use]
    pub const fn new() -> Self {
        Self { big_endian: true }
    }

    /// Decode raw u32 as a PPC instruction and return a branch descriptor if
    /// it is any branch instruction; otherwise `None`.
    #[must_use]
    pub fn analyze_branch(&self, insn: u32, addr: u64) -> Option<PpcBranch> {
        let opcode = bits(insn, 31, 26);
        match opcode {
            18 => Some(Self::decode_b(insn, addr)),
            16 => Some(Self::decode_bc(insn, addr)),
            19 => Self::decode_op19(insn, addr),
            _  => None,
        }
    }

    // ── b / bl / ba / bla ─────────────────────────────────────────────────

    fn decode_b(insn: u32, addr: u64) -> PpcBranch {
        let li  = (insn << 6).cast_signed() >> 6; // sign-extend bits 25:2
        let li2 = (li >> 2) << 2;                 // clear lower 2 bits
        let aa  = (insn & 2) != 0;
        let lk  = (insn & 1) != 0;
        let target = if aa {
            BranchTarget::Absolute(i64::from(li2).cast_unsigned())
        } else {
            BranchTarget::Resolved(addr.wrapping_add_signed(i64::from(li2)))
        };
        PpcBranch {
            addr,
            target,
            branch_type: if lk { BranchType::Link } else { BranchType::Unconditional },
            condition: None,
            link: lk,
            raw: insn,
        }
    }

    // ── bc / bcl / bca / bcla ─────────────────────────────────────────────

    fn decode_bc(insn: u32, addr: u64) -> PpcBranch {
        let bo  = u8::try_from(bits(insn, 25, 21)).unwrap_or(u8::MAX);
        let bi  = u8::try_from(bits(insn, 20, 16)).unwrap_or(u8::MAX);
        let bd  = i64::from((insn & 0xFFFC).cast_signed() << 16 >> 16);
        let aa  = (insn & 2) != 0;
        let lk  = (insn & 1) != 0;
        let cond = BranchCondition::new(bo, bi);
        let always = cond.is_always_taken();
        let target = if aa {
            BranchTarget::Absolute(bd.cast_unsigned())
        } else {
            BranchTarget::Resolved(addr.wrapping_add_signed(bd))
        };
        PpcBranch {
            addr,
            target,
            branch_type: if always && lk {
                BranchType::Link
            } else if lk {
                BranchType::CondLink
            } else if always {
                BranchType::Unconditional
            } else {
                BranchType::Conditional
            },
            condition: Some(cond),
            link: lk,
            raw: insn,
        }
    }

    // ── opcode 19: bclr / bcctr ───────────────────────────────────────────

    fn decode_op19(insn: u32, addr: u64) -> Option<PpcBranch> {
        let xo = bits(insn, 10, 1);
        let bo = u8::try_from(bits(insn, 25, 21)).unwrap_or(u8::MAX);
        let bi = u8::try_from(bits(insn, 20, 16)).unwrap_or(u8::MAX);
        let lk = (insn & 1) != 0;
        let cond = BranchCondition::new(bo, bi);
        let always = cond.is_always_taken();
        match xo {
            16 => {
                // bclr / blrl
                let btype = if lk && !always {
                    BranchType::CondLink
                } else {
                    BranchType::LinkReg
                };
                Some(PpcBranch {
                    addr,
                    target: BranchTarget::Register,
                    branch_type: btype,
                    condition: if always { None } else { Some(cond) },
                    link: lk,
                    raw: insn,
                })
            }
            528 => {
                // bcctr / bctrl
                let btype = if !always {
                    BranchType::CondLink
                } else {
                    BranchType::CounterReg
                };
                Some(PpcBranch {
                    addr,
                    target: BranchTarget::Register,
                    branch_type: btype,
                    condition: if always { None } else { Some(cond) },
                    link: lk,
                    raw: insn,
                })
            }
            _ => None,
        }
    }

    // ── Batch analysis ─────────────────────────────────────────────────────

    /// Analyse a byte slice and return all branch instructions found.
    ///
    /// # Panics
    ///
    /// Panics if `data` is not aligned to 4-byte boundaries (internal invariant).
    #[must_use]
    pub fn find_all_branches(&self, data: &[u8], base_addr: u64) -> Vec<PpcBranch> {
        let mut out = Vec::new();
        let mut i = 0usize;
        while i + 4 <= data.len() {
            let bytes: [u8; 4] = data[i..i + 4].try_into().unwrap();
            let raw = if self.big_endian {
                u32::from_be_bytes(bytes)
            } else {
                u32::from_le_bytes(bytes)
            };
            if let Some(br) = self.analyze_branch(raw, base_addr.wrapping_add(i as u64)) {
                out.push(br);
            }
            i += 4;
        }
        out
    }

    /// Return only branches with the LK bit set (function calls).
    #[must_use]
    pub fn find_function_calls(&self, data: &[u8], base_addr: u64) -> Vec<PpcBranch> {
        self.find_all_branches(data, base_addr)
            .into_iter()
            .filter(|b| b.link)
            .collect()
    }

    /// Return branches to the CTR register (bctrl = indirect calls).
    #[must_use]
    pub fn find_indirect_calls(&self, data: &[u8], base_addr: u64) -> Vec<PpcBranch> {
        self.find_all_branches(data, base_addr)
            .into_iter()
            .filter(|b| matches!(b.branch_type, BranchType::CounterReg) && b.link)
            .collect()
    }

    /// Return bclr without LK (function returns).
    #[must_use]
    pub fn find_returns(&self, data: &[u8], base_addr: u64) -> Vec<PpcBranch> {
        self.find_all_branches(data, base_addr)
            .into_iter()
            .filter(PpcBranch::is_return)
            .collect()
    }

    /// Estimate branch-taken probability from BO field static hints.
    /// Returns a value in `[0.0, 1.0]`.
    #[must_use]
    pub const fn compute_branch_probability(bo: u8) -> f64 {
        // BO[3]=1 → '+' prediction (likely taken); BO[3]=0 → '-' (likely not taken)
        // Canonical encoding: BO & 0b01000 gives the prediction bit
        // but only meaningful when not "branch always" (BO[2]=1 & BO[4]=1)
        let always = (bo & 0b10100) == 0b10100; // BO4=1 (ignore CTR) and BO2=1 (ignore CR)
        if always {
            return 1.0;
        }
        // Static prediction: BO[3] encodes '+'/'-' in numeric BO values
        let predicted_taken = (bo & 0b01000) != 0;
        if predicted_taken { 0.90 } else { 0.10 }
    }

    /// Build a map from call-site address to target address for direct calls.
    #[must_use]
    pub fn call_map(&self, data: &[u8], base_addr: u64) -> Vec<(u64, u64)> {
        self.find_function_calls(data, base_addr)
            .iter()
            .filter_map(|b| b.resolved_target().map(|t| (b.addr, t)))
            .collect()
    }
}

impl Default for PpcBranchAnalyzer {
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

    fn analyzer() -> PpcBranchAnalyzer { PpcBranchAnalyzer::new() }

    fn b_insn(li: i32) -> u32 {
        // opcode 18, LK=0, AA=0
        let li_field = ((li & !3).cast_unsigned()) & 0x03FF_FFFC;
        (18 << 26) | li_field
    }

    fn bl_insn(li: i32) -> u32 {
        b_insn(li) | 1 // LK=1
    }

    #[test]
    fn test_b_forward() {
        let raw = b_insn(0x100);
        let br = analyzer().analyze_branch(raw, 0x4000).unwrap();
        assert_eq!(br.branch_type, BranchType::Unconditional);
        assert!(!br.link);
        assert_eq!(br.resolved_target(), Some(0x4100));
    }

    #[test]
    fn test_bl_is_call() {
        let raw = bl_insn(0x200);
        let br = analyzer().analyze_branch(raw, 0).unwrap();
        assert!(br.is_call());
        assert_eq!(br.branch_type, BranchType::Link);
    }

    #[test]
    fn test_b_absolute() {
        // b 0x8000 (AA=1)
        let raw: u32 = (18 << 26) | (0x8000 & !3) | 2; // AA=1
        let br = analyzer().analyze_branch(raw, 0x1000).unwrap();
        assert_eq!(br.resolved_target(), Some(0x8000));
    }

    #[test]
    fn test_bc_conditional() {
        // bc 4, 2, +8  (branch if CR0.EQ=0)
        let bo: u32 = 4;  // 0b00100 = branch if CR bit false, ignore CTR
        let bi: u32 = 2;  // CR0.EQ
        let bd: u32 = 8;
        let raw: u32 = (16 << 26) | (bo << 21) | (bi << 16) | bd;
        let br = analyzer().analyze_branch(raw, 0x100).unwrap();
        assert_eq!(br.branch_type, BranchType::Conditional);
        assert!(!br.link);
        assert_eq!(br.resolved_target(), Some(0x108));
    }

    #[test]
    fn test_bclr_is_return() {
        // bclr (blr): opcode=19, xo=16, BO=20 (always), BI=0, LK=0
        let raw: u32 = (19 << 26) | (20 << 21) | (16 << 1);
        let br = analyzer().analyze_branch(raw, 0x200).unwrap();
        assert!(br.is_return());
        assert!(!br.link);
    }

    #[test]
    fn test_bctrl_indirect_call() {
        // bctrl: opcode=19, xo=528, BO=20, BI=0, LK=1
        let raw: u32 = (19 << 26) | (20 << 21) | (528 << 1) | 1;
        let br = analyzer().analyze_branch(raw, 0x300).unwrap();
        assert!(br.link);
        assert!(br.is_indirect());
    }

    #[test]
    fn test_non_branch_returns_none() {
        // addi r3, r1, 8  (opcode 14 — not a branch)
        let raw: u32 = (14 << 26) | (3 << 21) | (1 << 16) | 8;
        assert!(analyzer().analyze_branch(raw, 0).is_none());
    }

    #[test]
    fn test_find_all_branches_slice() {
        let bl = bl_insn(0x100).to_be_bytes();
        let nop = (0x6000_0000_u32).to_be_bytes(); // ori 0,0,0
        let mut data = Vec::new();
        data.extend_from_slice(&bl);
        data.extend_from_slice(&nop);
        let branches = analyzer().find_all_branches(&data, 0);
        assert_eq!(branches.len(), 1);
        assert!(branches[0].is_call());
    }

    #[test]
    fn test_find_function_calls() {
        let bl = bl_insn(0x200).to_be_bytes();
        let b  = b_insn(0x100).to_be_bytes();
        let mut data = Vec::new();
        data.extend_from_slice(&bl);
        data.extend_from_slice(&b);
        let calls = analyzer().find_function_calls(&data, 0);
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn test_find_returns() {
        let blr: u32 = (19 << 26) | (20 << 21) | (16 << 1); // blr
        let mut data = blr.to_be_bytes().to_vec();
        let bl = bl_insn(0x100);
        data.extend_from_slice(&bl.to_be_bytes());
        let rets = analyzer().find_returns(&data, 0);
        assert_eq!(rets.len(), 1);
    }

    #[test]
    fn test_branch_probability_always() {
        let p = PpcBranchAnalyzer::compute_branch_probability(0b10100);
        assert!((p - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_branch_probability_not_taken() {
        // BO with prediction-not-taken (BO[3]=0), not always
        let p = PpcBranchAnalyzer::compute_branch_probability(0b00100);
        assert!(p < 0.5);
    }

    #[test]
    fn test_condition_always_taken() {
        let c = BranchCondition::new(0b10100, 0);
        assert!(c.is_always_taken());
    }

    #[test]
    fn test_decode_bi_field() {
        let (field, name) = decode_bi_field(8); // CR2.LT
        assert_eq!(field, 2);
        assert_eq!(name, "LT");
    }

    #[test]
    fn test_call_map() {
        let bl = bl_insn(0x1000).to_be_bytes();
        let data: Vec<u8> = bl.to_vec();
        let map = analyzer().call_map(&data, 0);
        assert_eq!(map.len(), 1);
        assert_eq!(map[0].0, 0); // from addr 0
        assert_eq!(map[0].1, 0x1000);
    }
}
