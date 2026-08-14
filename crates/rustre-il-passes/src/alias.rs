//! Basic Steensgaard-style (unification-based, flow-insensitive) alias
//! analysis over an [`LlilFunction`].
//!
//! Every register-like variable gets an abstract-location node in a
//! union-find structure; each equivalence class carries at most one
//! *pointee* class. The classic Steensgaard rules are applied:
//!
//! - copy `x = y`            → `join(x, y)`
//! - load `x = *p`           → `join(x, deref(p))`
//! - store `*p = y`          → `join(deref(p), y)`
//! - arithmetic `x = a ⊕ b`  → `join(x, a)`, `join(x, b)` (field-insensitive:
//!   a pointer offset by anything still points into the same class)
//!
//! Constants used as addresses get their own nodes keyed by value, so two
//! distinct constant addresses with non-overlapping ranges can be proven
//! non-aliasing exactly.
//!
//! The analysis is near-linear (union-find) and sound as an
//! over-approximation: [`SteensgaardAnalysis::may_alias`] returning `false`
//! is a guarantee; returning `true` is "cannot rule it out".

use std::collections::HashMap;

use rustre_il_llil::{LlilExpr, LlilFunction, LlilInstruction, LlilRegister};

/// Union-find where each class optionally points to another class.
#[derive(Debug, Default, Clone)]
struct PointsToUf {
    parent: Vec<usize>,
    pointee: Vec<Option<usize>>,
}

impl PointsToUf {
    fn make(&mut self) -> usize {
        let n = self.parent.len();
        self.parent.push(n);
        self.pointee.push(None);
        n
    }

    fn find(&mut self, mut x: usize) -> usize {
        while self.parent[x] != x {
            self.parent[x] = self.parent[self.parent[x]];
            x = self.parent[x];
        }
        x
    }

    /// Unifies the classes of `a` and `b` (and, recursively, their pointees).
    fn join(&mut self, a: usize, b: usize) -> usize {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra == rb {
            return ra;
        }
        self.parent[rb] = ra;
        let pa = self.pointee[ra];
        let pb = self.pointee[rb];
        match (pa, pb) {
            (Some(x), Some(y)) => {
                let p = self.join(x, y);
                let ra2 = self.find(ra);
                self.pointee[ra2] = Some(p);
            }
            (None, Some(y)) => self.pointee[ra] = Some(y),
            _ => {}
        }
        ra
    }

    /// Returns (creating on demand) the pointee class of `x`.
    fn deref(&mut self, x: usize) -> usize {
        let r = self.find(x);
        if let Some(p) = self.pointee[r] {
            return self.find(p);
        }
        let p = self.make();
        let r = self.find(x);
        self.pointee[r] = Some(p);
        p
    }
}

/// Result of running Steensgaard analysis on one function.
#[derive(Debug, Clone)]
pub struct SteensgaardAnalysis {
    uf: PointsToUf,
    vars: HashMap<String, usize>,
    consts: HashMap<u64, usize>,
}

impl SteensgaardAnalysis {
    /// Runs the analysis over every instruction of `func`.
    #[must_use]
    pub fn build(func: &LlilFunction) -> Self {
        let mut a = Self {
            uf: PointsToUf::default(),
            vars: HashMap::new(),
            consts: HashMap::new(),
        };
        for block in &func.blocks {
            for ai in &block.instrs {
                a.process(&ai.instr);
            }
        }
        a
    }

    fn var_node(&mut self, name: &str) -> usize {
        if let Some(&n) = self.vars.get(name) {
            return n;
        }
        let n = self.uf.make();
        self.vars.insert(name.to_owned(), n);
        n
    }

    fn const_node(&mut self, value: u64) -> usize {
        if let Some(&n) = self.consts.get(&value) {
            return n;
        }
        let n = self.uf.make();
        self.consts.insert(value, n);
        n
    }

    /// Evaluates `expr` to an abstract-location class.
    fn eval(&mut self, expr: &LlilExpr) -> usize {
        match expr {
            LlilExpr::RegisterRef { reg, .. } => {
                let name = reg.name();
                self.var_node(&name)
            }
            LlilExpr::Register { id, .. } => self.var_node(&format!("vreg{id}")),
            LlilExpr::Const { value, .. } => self.const_node(*value),
            LlilExpr::Load { addr, .. } => {
                let p = self.eval(addr);
                self.uf.deref(p)
            }
            // Pointer arithmetic: result stays in the class of its operands
            // (field-insensitive).
            LlilExpr::AddT(x, y, _)
            | LlilExpr::SubT(x, y, _)
            | LlilExpr::Add { left: x, right: y, .. }
            | LlilExpr::Sub { left: x, right: y, .. }
            | LlilExpr::And(x, y, _)
            | LlilExpr::Or(x, y, _) => {
                // Offsetting by a *constant* keeps the base class without
                // dragging the constant's node in (constants used as plain
                // offsets are not addresses).
                match (x.is_const(), y.is_const()) {
                    (Some(_), None) => self.eval(y),
                    (None, Some(_)) => self.eval(x),
                    _ => {
                        let nx = self.eval(x);
                        let ny = self.eval(y);
                        self.uf.join(nx, ny)
                    }
                }
            }
            LlilExpr::ZeroExtend { expr, .. }
            | LlilExpr::SignExtend { expr, .. }
            | LlilExpr::LowPart { expr, .. } => self.eval(expr),
            // Anything else (mul/shift/cmp/float/undefined/...) is treated
            // as an opaque fresh value.
            _ => self.uf.make(),
        }
    }

    fn process(&mut self, instr: &LlilInstruction) {
        match instr {
            LlilInstruction::SetReg { dest, value, .. }
            | LlilInstruction::SetRegSplit {
                low: dest,
                src: value,
                ..
            } => {
                let v = self.eval(value);
                let d = self.var_node(&dest.name());
                self.uf.join(d, v);
            }
            LlilInstruction::SetRegister { dest, value, .. } => {
                let v = self.eval(value);
                let d = self.var_node(&format!("vreg{dest}"));
                self.uf.join(d, v);
            }
            LlilInstruction::Load { dest, addr, .. } => {
                let p = self.eval(addr);
                let pointee = self.uf.deref(p);
                let d = self.var_node(&dest.name());
                self.uf.join(d, pointee);
            }
            LlilInstruction::Store { addr, value, .. } => {
                let p = self.eval(addr);
                let pointee = self.uf.deref(p);
                let v = self.eval(value);
                self.uf.join(pointee, v);
            }
            _ => {}
        }
    }

    /// Returns `true` if the memory accessed through address expressions
    /// `a` (width `a_size` bytes) and `b` (width `b_size` bytes) may overlap.
    ///
    /// `false` is a sound "no alias" guarantee.
    pub fn may_alias(
        &mut self,
        a: &LlilExpr,
        a_size: usize,
        b: &LlilExpr,
        b_size: usize,
    ) -> bool {
        // Exact disambiguation for constant addresses.
        if let (Some(ca), Some(cb)) = (a.is_const(), b.is_const()) {
            let (lo, lo_sz, hi) = if ca <= cb {
                (ca, a_size as u64, cb)
            } else {
                (cb, b_size as u64, ca)
            };
            return lo.saturating_add(lo_sz) > hi;
        }
        let na = self.eval(a);
        let nb = self.eval(b);
        self.uf.find(na) == self.uf.find(nb)
    }

    /// Returns `true` if registers `a` and `b` may hold aliasing pointers.
    pub fn regs_may_alias(&mut self, a: &LlilRegister, b: &LlilRegister) -> bool {
        let na = self.var_node(&a.name());
        let nb = self.var_node(&b.name());
        self.uf.find(na) == self.uf.find(nb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::address::Address;
    use rustre_il_llil::{LlilAnnotatedInstr, LlilBasicBlock, Size, llil_const, llil_reg};

    fn func_of(instrs: Vec<LlilInstruction>) -> LlilFunction {
        let mut f = LlilFunction::new(Address::new(0x0));
        f.blocks = vec![LlilBasicBlock {
            start: Address::new(0x0),
            end: Address::new(0x0),
            instrs: instrs
                .into_iter()
                .map(|instr| LlilAnnotatedInstr {
                    address: Address::new(0x0),
                    size: 1,
                    instr,
                    length: 1,
                })
                .collect(),
            id: 0,
            successors: Vec::new(),
        }];
        f
    }

    fn set(reg: &str, value: LlilExpr) -> LlilInstruction {
        LlilInstruction::SetReg {
            dest: reg.into(),
            size: Size::QWord,
            value,
        }
    }

    #[test]
    fn copied_pointers_alias() {
        let f = func_of(vec![set("q", llil_reg("p", Size::QWord)), LlilInstruction::Ret]);
        let mut a = SteensgaardAnalysis::build(&f);
        assert!(a.regs_may_alias(&"p".into(), &"q".into()));
        assert!(a.may_alias(
            &llil_reg("p", Size::QWord),
            8,
            &llil_reg("q", Size::QWord),
            8
        ));
    }

    #[test]
    fn unrelated_pointers_do_not_alias() {
        let f = func_of(vec![
            set("a", llil_reg("p", Size::QWord)),
            set("b", llil_reg("q", Size::QWord)),
            LlilInstruction::Ret,
        ]);
        let mut an = SteensgaardAnalysis::build(&f);
        assert!(!an.regs_may_alias(&"a".into(), &"b".into()));
        assert!(!an.may_alias(
            &llil_reg("p", Size::QWord),
            8,
            &llil_reg("q", Size::QWord),
            8
        ));
    }

    #[test]
    fn constant_offset_keeps_base_class() {
        // q = p + 8 : q still points into p's region (may alias).
        let f = func_of(vec![
            set(
                "q",
                LlilExpr::AddT(
                    Box::new(llil_reg("p", Size::QWord)),
                    Box::new(llil_const(8, Size::QWord)),
                    Size::QWord,
                ),
            ),
            LlilInstruction::Ret,
        ]);
        let mut a = SteensgaardAnalysis::build(&f);
        assert!(a.regs_may_alias(&"p".into(), &"q".into()));
    }

    #[test]
    fn constant_addresses_disambiguated_exactly() {
        let f = func_of(vec![LlilInstruction::Ret]);
        let mut a = SteensgaardAnalysis::build(&f);
        // [0x1000..0x1008) vs [0x1008..0x1010): no overlap.
        assert!(!a.may_alias(
            &llil_const(0x1000, Size::QWord),
            8,
            &llil_const(0x1008, Size::QWord),
            8
        ));
        // [0x1000..0x1008) vs [0x1004..0x100c): overlap.
        assert!(a.may_alias(
            &llil_const(0x1000, Size::QWord),
            8,
            &llil_const(0x1004, Size::QWord),
            8
        ));
        // Same address, single byte.
        assert!(a.may_alias(
            &llil_const(0x2000, Size::QWord),
            1,
            &llil_const(0x2000, Size::QWord),
            1
        ));
    }

    #[test]
    fn store_then_load_unifies_pointees() {
        // *p = q ; x = *p  => x aliases q.
        let f = func_of(vec![
            LlilInstruction::Store {
                addr: llil_reg("p", Size::QWord),
                size: Size::QWord,
                value: llil_reg("q", Size::QWord),
            },
            LlilInstruction::Load {
                dest: "x".into(),
                size: Size::QWord,
                addr: llil_reg("p", Size::QWord),
            },
            LlilInstruction::Ret,
        ]);
        let mut a = SteensgaardAnalysis::build(&f);
        assert!(a.regs_may_alias(&"x".into(), &"q".into()));
    }

    #[test]
    fn loads_through_distinct_pointers_stay_distinct() {
        let f = func_of(vec![
            LlilInstruction::Load {
                dest: "x".into(),
                size: Size::QWord,
                addr: llil_reg("p", Size::QWord),
            },
            LlilInstruction::Load {
                dest: "y".into(),
                size: Size::QWord,
                addr: llil_reg("q", Size::QWord),
            },
            LlilInstruction::Ret,
        ]);
        let mut a = SteensgaardAnalysis::build(&f);
        assert!(!a.regs_may_alias(&"x".into(), &"y".into()));
    }

    #[test]
    fn join_merges_pointees_transitively() {
        // r = p (copy) then *p = a and *r = b : a and b unified.
        let f = func_of(vec![
            set("r", llil_reg("p", Size::QWord)),
            LlilInstruction::Store {
                addr: llil_reg("p", Size::QWord),
                size: Size::QWord,
                value: llil_reg("a", Size::QWord),
            },
            LlilInstruction::Store {
                addr: llil_reg("r", Size::QWord),
                size: Size::QWord,
                value: llil_reg("b", Size::QWord),
            },
            LlilInstruction::Ret,
        ]);
        let mut an = SteensgaardAnalysis::build(&f);
        assert!(an.regs_may_alias(&"a".into(), &"b".into()));
    }
}
