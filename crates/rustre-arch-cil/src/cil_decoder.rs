//! CIL Decoder definitions for CFG and call-graph analysis.

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Opcode {
    Nop,
    Br,
    BrS,
    Brtrue,
    BrtrueS,
    Brfalse,
    BrfalseS,
    Beq,
    BeqS,
    Bge,
    BgeS,
    BgeUn,
    BgeUnS,
    Bgt,
    BgtS,
    BgtUn,
    BgtUnS,
    Ble,
    BleS,
    BleUn,
    BleUnS,
    Blt,
    BltS,
    BltUn,
    BltUnS,
    Bne,
    BneUn,
    BneUnS,
    Switch,
    Leave,
    LeaveS,
    Ret,
    Throw,
    Rethrow,
    Endfinally,
    Tailprefix,
    Call,
    Callvirt,
    Calli,
    Newobj,
    Ldftn,
    Ldvirtftn,
    Ldloc,
    Stloc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operand {
    None,
    BranchTarget(u32),
    SwitchTargets(Vec<u32>),
    MethodToken(u32),
    Local(u32),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedCilInstr {
    pub offset: u32,
    pub size: u32,
    pub opcode: Opcode,
    pub operand: Operand,
}

impl DecodedCilInstr {
    #[must_use]
    pub const fn branch_target(&self) -> Option<u32> {
        match &self.operand {
            Operand::BranchTarget(tgt) => Some(*tgt),
            _ => None,
        }
    }

    #[must_use]
    pub fn switch_targets(&self) -> Vec<u32> {
        match &self.operand {
            Operand::SwitchTargets(targets) => targets.clone(),
            _ => Vec::new(),
        }
    }

    #[must_use]
    pub const fn local_load_index(&self) -> Option<u32> {
        match &self.operand {
            Operand::Local(idx) => Some(*idx),
            _ => None,
        }
    }

    #[must_use]
    pub const fn local_store_index(&self) -> Option<u32> {
        match &self.operand {
            Operand::Local(idx) => Some(*idx),
            _ => None,
        }
    }

    #[must_use]
    pub const fn method_token(&self) -> Option<u32> {
        match &self.operand {
            Operand::MethodToken(tok) => Some(*tok),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(opcode: Opcode, operand: Operand) -> DecodedCilInstr {
        DecodedCilInstr { offset: 0, size: 1, opcode, operand }
    }

    #[test]
    fn branch_target_present_and_absent() {
        let i = mk(Opcode::Br, Operand::BranchTarget(42));
        assert_eq!(i.branch_target(), Some(42));
        let j = mk(Opcode::Nop, Operand::None);
        assert_eq!(j.branch_target(), None);
    }

    #[test]
    fn branch_target_extremes() {
        let lo = mk(Opcode::BrS, Operand::BranchTarget(0));
        assert_eq!(lo.branch_target(), Some(0));
        let hi = mk(Opcode::BrS, Operand::BranchTarget(u32::MAX));
        assert_eq!(hi.branch_target(), Some(u32::MAX));
    }

    #[test]
    fn switch_targets_empty_and_full() {
        let empty = mk(Opcode::Switch, Operand::SwitchTargets(vec![]));
        assert!(empty.switch_targets().is_empty());
        let many: Vec<u32> = (0..1000).collect();
        let full = mk(Opcode::Switch, Operand::SwitchTargets(many.clone()));
        assert_eq!(full.switch_targets(), many);
        // Wrong operand variant -> empty vec
        let none = mk(Opcode::Nop, Operand::None);
        assert!(none.switch_targets().is_empty());
    }

    #[test]
    fn local_index_load_store_roundtrip() {
        let l = mk(Opcode::Ldloc, Operand::Local(7));
        assert_eq!(l.local_load_index(), Some(7));
        assert_eq!(l.local_store_index(), Some(7));
        let s = mk(Opcode::Stloc, Operand::Local(u32::MAX));
        assert_eq!(s.local_load_index(), Some(u32::MAX));
        // Mismatched operand
        let nope = mk(Opcode::Ldloc, Operand::None);
        assert_eq!(nope.local_load_index(), None);
        assert_eq!(nope.local_store_index(), None);
    }

    #[test]
    fn method_token_only_for_token_operand() {
        let c = mk(Opcode::Call, Operand::MethodToken(0xDEADBEEF));
        assert_eq!(c.method_token(), Some(0xDEADBEEF));
        let n = mk(Opcode::Call, Operand::None);
        assert_eq!(n.method_token(), None);
        let b = mk(Opcode::Call, Operand::BranchTarget(5));
        assert_eq!(b.method_token(), None);
    }

    #[test]
    fn opcode_equality_and_hash_distinct() {
        use std::collections::HashSet;
        let mut s: HashSet<Opcode> = HashSet::new();
        s.insert(Opcode::Br);
        s.insert(Opcode::BrS);
        s.insert(Opcode::Br);
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn clone_and_equality_independent() {
        let i = mk(Opcode::Switch, Operand::SwitchTargets(vec![1, 2, 3]));
        let c = i.clone();
        assert_eq!(c, i);
        let d = DecodedCilInstr { offset: 99, size: 5, ..i.clone() };
        assert_ne!(d, i);
    }
}
