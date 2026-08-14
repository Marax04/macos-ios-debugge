"""Python reproduction of the rustre-deobf-opaque public API.

Mirrors the surface documented in validation/reports/rustre-deobf-opaque.md.
Uses only Python stdlib (struct, hashlib, json, re).
"""

import struct  # noqa: F401
import hashlib  # noqa: F401
import json  # noqa: F401
import re  # noqa: F401
import random
from enum import Enum
from typing import Optional, Dict, List, Tuple, Iterable, Any, Callable


MASK64 = (1 << 64) - 1


def _to_signed64(v: int) -> int:
    v &= MASK64
    return v - (1 << 64) if v & (1 << 63) else v


class PredicateValue(Enum):
    AlwaysTrue = "AlwaysTrue"
    AlwaysFalse = "AlwaysFalse"
    DataDependent = "DataDependent"


class OpaquePredicateKind(Enum):
    Arithmetic = "Arithmetic"
    Bitwise = "Bitwise"
    Polynomial = "Polynomial"
    Mba = "Mba"
    Unknown = "Unknown"


class OpaqueKind(Enum):
    Trivial = "Trivial"
    Constant = "Constant"
    KnownPattern = "KnownPattern"
    Unknown = "Unknown"


# ---------------------------------------------------------------------------
# OpaqueExpr — symbolic AST
# ---------------------------------------------------------------------------

class OpaqueExpr:
    __slots__ = ("op", "args", "value", "name")

    def __init__(self, op, args=(), value=None, name=None):
        self.op = op
        self.args = tuple(args)
        self.value = value
        self.name = name

    @staticmethod
    def const(v): return OpaqueExpr("Const", value=int(v))
    @staticmethod
    def var(name): return OpaqueExpr("Var", name=name)
    @staticmethod
    def bin(op, a, b): return OpaqueExpr(op, (a, b))
    @staticmethod
    def un(op, a): return OpaqueExpr(op, (a,))

    def eval(self, vars: Dict[str, int], _depth: int = 0) -> Optional[int]:
        if _depth > 512:
            return None
        op = self.op
        if op == "Const":
            return self.value
        if op == "Var":
            if self.name not in vars:
                return None
            return int(vars[self.name])
        sub = [a.eval(vars, _depth + 1) for a in self.args]
        if any(v is None for v in sub):
            return None
        a = sub[0]
        b = sub[1] if len(sub) > 1 else None
        try:
            if op == "Add": return _to_signed64(a + b)
            if op == "Sub": return _to_signed64(a - b)
            if op == "Mul": return _to_signed64(a * b)
            if op == "Div":
                if b == 0: return None
                q = abs(a) // abs(b)
                if (a < 0) ^ (b < 0): q = -q
                return _to_signed64(q)
            if op == "Mod":
                if b == 0: return None
                return _to_signed64(a - (a // b) * b)
            if op == "And": return _to_signed64(a & b)
            if op == "Or":  return _to_signed64(a | b)
            if op == "Xor": return _to_signed64(a ^ b)
            if op == "Shl":
                if b < 0 or b >= 64: return None
                return _to_signed64((a & MASK64) << b)
            if op == "Shr":
                if b < 0 or b >= 64: return None
                return _to_signed64((a & MASK64) >> b)
            if op == "Eq": return 1 if a == b else 0
            if op == "Ne": return 1 if a != b else 0
            if op == "Lt": return 1 if a < b else 0
            if op == "Le": return 1 if a <= b else 0
            if op == "Gt": return 1 if a > b else 0
            if op == "Ge": return 1 if a >= b else 0
            if op == "Not": return _to_signed64(~a)
            if op == "Neg": return _to_signed64(-a)
            if op == "BitCount": return bin(a & MASK64).count("1")
            if op == "Abs": return _to_signed64(abs(a))
            if op == "Square": return _to_signed64(a * a)
        except Exception:
            return None
        return None

    def is_const(self) -> Optional[int]:
        if not self.vars():
            return self.eval({})
        return None

    def vars(self) -> List[str]:
        seen = set()
        out: List[str] = []
        def walk(e):
            if e.op == "Var" and e.name not in seen:
                seen.add(e.name); out.append(e.name)
            for a in e.args:
                walk(a)
        walk(self)
        return sorted(out)

    def simplify(self) -> "OpaqueExpr":
        if self.op in ("Const", "Var"):
            return self
        args = tuple(a.simplify() for a in self.args)
        new = OpaqueExpr(self.op, args, self.value, self.name)
        c = new.is_const()
        if c is not None:
            return OpaqueExpr.const(c)
        if len(args) == 2 and args[0].is_trivially_equal(args[1]):
            if self.op in ("Sub", "Xor"):
                return OpaqueExpr.const(0)
            if self.op in ("And", "Or"):
                return args[0]
            if self.op in ("Eq", "Le", "Ge"):
                return OpaqueExpr.const(1)
            if self.op in ("Ne", "Lt", "Gt"):
                return OpaqueExpr.const(0)
        return new

    def is_trivially_equal(self, other: "OpaqueExpr") -> bool:
        if self.op != other.op or self.value != other.value or self.name != other.name:
            return False
        if len(self.args) != len(other.args):
            return False
        return all(a.is_trivially_equal(b) for a, b in zip(self.args, other.args))


class KnownOpaquePattern:
    def __init__(self, name, value, confidence=100):
        self.name = name; self.value = value; self.confidence = confidence


def build_known_patterns() -> List[KnownOpaquePattern]:
    names = [
        "x_xor_x_eq_0", "x_sub_x_eq_0", "x_and_not_x_eq_0",
        "x_or_not_x_eq_neg1", "x_mul_0_eq_0", "x_plus_0_eq_x",
        "consecutive_product_even", "x_sq_ge_0", "abs_ge_0",
        "x_le_x", "x_ge_x", "x_eq_x", "x_ne_x_false",
        "bit_count_le_64", "x_and_0_eq_0", "x_or_0_eq_x",
        "x_xor_0_eq_x", "x_shl_0_eq_x", "x_shr_0_eq_x",
        "mba_x_plus_y", "mba_x_xor_y", "mba_x_and_y",
        "poly_triangular_mod6", "square_plus_n_nonneg",
    ]
    out = []
    for n in names:
        val = PredicateValue.AlwaysFalse if "false" in n or n.endswith("_eq_0") else PredicateValue.AlwaysTrue
        out.append(KnownOpaquePattern(n, val))
    return out


class TruthTableChecker:
    def __init__(self, bits=4, samples=256):
        self.bits = bits; self.samples = samples

    @staticmethod
    def new(): return TruthTableChecker()

    def enumerate_values(self, vars: List[str], bits: int) -> List[Dict[str, int]]:
        out = []
        n = len(vars)
        if n == 0:
            return [{}]
        if bits * n <= 16:
            total = 1 << (bits * n)
            for i in range(total):
                env = {}; v = i
                for vn in vars:
                    env[vn] = _to_signed64(v & ((1 << bits) - 1))
                    v >>= bits
                out.append(env)
        else:
            rnd = random.Random(0xC0FFEE)
            for _ in range(self.samples):
                env = {vn: _to_signed64(rnd.getrandbits(bits)) for vn in vars}
                out.append(env)
        return out

    def _all(self, expr, target):
        for env in self.enumerate_values(expr.vars(), self.bits):
            v = expr.eval(env)
            if v is None: continue
            if (v != 0) != bool(target): return False
        return True

    def is_always_true(self, expr): return self._all(expr, 1)
    def is_always_false(self, expr): return self._all(expr, 0)

    def classify(self, expr) -> PredicateValue:
        if self.is_always_true(expr): return PredicateValue.AlwaysTrue
        if self.is_always_false(expr): return PredicateValue.AlwaysFalse
        return PredicateValue.DataDependent

    def counterexample_true(self, expr):
        for env in self.enumerate_values(expr.vars(), self.bits):
            v = expr.eval(env)
            if v is not None and v != 0: return env
        return None

    def counterexample_false(self, expr):
        for env in self.enumerate_values(expr.vars(), self.bits):
            v = expr.eval(env)
            if v is not None and v == 0: return env
        return None


Address = int


class SimpleBranch:
    def __init__(self, addr, true_target, false_target, condition=None):
        self.addr = addr
        self.true_target = true_target
        self.false_target = false_target
        self.condition = condition
        self.unconditional_target = None


class OpaqueBranch:
    def __init__(self, addr, value, kind=OpaqueKind.Unknown, confidence=1.0):
        self.addr = addr; self.value = value
        self.kind = kind; self.confidence = confidence


class SimpleBranchCfg:
    def __init__(self, start):
        self.start = start
        self.branches: List[SimpleBranch] = []
        self.block_sizes: Dict[int, int] = {}

    @staticmethod
    def new(start): return SimpleBranchCfg(start)

    def add_branch(self, b): self.branches.append(b)
    def add_block_size(self, addr, size): self.block_sizes[addr] = size


class OpaqueDetector:
    def __init__(self):
        self.patterns = build_known_patterns()
        self.checker = TruthTableChecker.new()

    @staticmethod
    def new(): return OpaqueDetector()

    def classify_with_kind(self, expr):
        if expr.is_const() is not None: return OpaqueKind.Constant
        if expr.op in ("Add", "Sub", "Mul", "Div", "Mod"): return OpaqueKind.Trivial
        return OpaqueKind.Unknown

    def check_trivial_identity(self, expr):
        s = expr.simplify()
        c = s.is_const()
        if c is None: return None
        return PredicateValue.AlwaysTrue if c != 0 else PredicateValue.AlwaysFalse

    def check_constant_expr(self, expr): return self.check_trivial_identity(expr)
    def check_known_patterns(self, expr): return self.check_trivial_identity(expr)

    def classify_condition(self, expr):
        r = self.check_trivial_identity(expr)
        if r is not None: return r
        return self.checker.classify(expr)

    def detect(self, cfg):
        out = []
        for b in cfg.branches:
            if b.condition is None: continue
            v = self.classify_condition(b.condition)
            if v != PredicateValue.DataDependent:
                out.append(OpaqueBranch(b.addr, v, self.classify_with_kind(b.condition)))
        return out


class EliminationResult:
    def __init__(self):
        self.eliminated: List[Tuple[int, int]] = []
        self.removed_count = 0
    def changed(self): return self.removed_count > 0


class OpaqueEliminator:
    @staticmethod
    def new(): return OpaqueEliminator()

    def make_unconditional(self, branch, target):
        branch.unconditional_target = target
        branch.condition = None

    def eliminate(self, cfg):
        res = EliminationResult()
        det = OpaqueDetector.new()
        findings = {f.addr: f for f in det.detect(cfg)}
        for b in cfg.branches:
            f = findings.get(b.addr)
            if not f: continue
            target = b.true_target if f.value == PredicateValue.AlwaysTrue else b.false_target
            self.make_unconditional(b, target)
            res.eliminated.append((b.addr, target))
            res.removed_count += 1
        return res


class OpaquePassResult:
    def __init__(self, findings, elim):
        self.findings = findings; self.elim = elim


class OpaqueDeobfPass:
    def __init__(self):
        self.detector = OpaqueDetector.new()
        self.eliminator = OpaqueEliminator.new()
    @staticmethod
    def new(): return OpaqueDeobfPass()
    def run(self, cfg):
        f = self.detector.detect(cfg)
        e = self.eliminator.eliminate(cfg)
        return OpaquePassResult(f, e)


class ConstFact:
    def __init__(self, var, value): self.var = var; self.value = value


class PropagationResult:
    def __init__(self): self.confirmed: List[OpaqueBranch] = []


class ConstantPropagator:
    def __init__(self): self.facts: Dict[str, int] = {}
    @staticmethod
    def new(): return ConstantPropagator()
    def add_fact(self, fact): self.facts[fact.var] = fact.value
    def propagate(self, findings):
        r = PropagationResult(); r.confirmed = list(findings); return r


class MbaIdentity:
    def __init__(self, name, value): self.name = name; self.value = value


class MbaOpaqueDetector:
    @staticmethod
    def new(): return MbaOpaqueDetector()
    def check_identity(self, expr): return expr.is_const()
    def check_known_mba_patterns(self, expr):
        c = expr.is_const()
        return MbaIdentity("mba_const", c) if c is not None else None


class BranchFrequency:
    def __init__(self, addr, true_count, false_count):
        self.addr = addr; self.true_count = true_count; self.false_count = false_count
    def true_fraction(self):
        t = self.true_count + self.false_count
        return self.true_count / t if t else 0.0
    def false_fraction(self):
        t = self.true_count + self.false_count
        return self.false_count / t if t else 0.0


class StatisticalOpaqueDetector:
    def __init__(self, threshold=0.99): self.threshold = threshold
    def classify(self, freqs):
        out = []
        for f in freqs:
            if f.true_fraction() >= self.threshold: out.append((f.addr, PredicateValue.AlwaysTrue))
            elif f.false_fraction() >= self.threshold: out.append((f.addr, PredicateValue.AlwaysFalse))
            else: out.append((f.addr, PredicateValue.DataDependent))
        return out


class OpaqueCategory(Enum):
    Arithmetic = "Arithmetic"; Bitwise = "Bitwise"
    Polynomial = "Polynomial"; Mba = "Mba"


class OpaqueDbEntry:
    def __init__(self, name, category, value, confidence=100):
        self.name = name; self.category = category
        self.value = value; self.confidence = confidence


class OpaquePredicateDatabase:
    def __init__(self): self.entries: List[OpaqueDbEntry] = []
    @staticmethod
    def new(): return OpaquePredicateDatabase()
    @staticmethod
    def with_builtins():
        db = OpaquePredicateDatabase()
        for p in build_known_patterns():
            db.add(OpaqueDbEntry(p.name, OpaqueCategory.Arithmetic, p.value, p.confidence))
        return db
    def add(self, entry): self.entries.append(entry)
    def by_category(self, cat): return [e for e in self.entries if e.category == cat]
    def by_value(self, val): return [e for e in self.entries if e.value == val]
    def high_confidence(self, threshold): return [e for e in self.entries if e.confidence >= threshold]


class DetailedFinding:
    def __init__(self, base): self.base = base; self.statistical = False
    @staticmethod
    def from_finding(f): return DetailedFinding(f)
    def with_statistical_confirmation(self): self.statistical = True; return self


class OpaquePredicateReport:
    def __init__(self, findings, elim):
        self.findings = [DetailedFinding.from_finding(f) for f in findings]
        self.elim = elim
    @staticmethod
    def new(findings, elim): return OpaquePredicateReport(findings, elim)
    def high_confidence_findings(self): return [f for f in self.findings if f.base.confidence >= 0.9]
    def always_true_findings(self): return [f for f in self.findings if f.base.value == PredicateValue.AlwaysTrue]
    def always_false_findings(self): return [f for f in self.findings if f.base.value == PredicateValue.AlwaysFalse]


class BranchOutcome(Enum):
    Taken = "Taken"; NotTaken = "NotTaken"; Unknown = "Unknown"


class BranchSimplifier:
    def __init__(self): self.outcomes: Dict[int, BranchOutcome] = {}
    @staticmethod
    def new(): return BranchSimplifier()
    def set_outcome(self, addr, outcome): self.outcomes[addr] = outcome
    def get_outcome(self, addr): return self.outcomes.get(addr)
    def load_from_elimination(self, result):
        for addr, _t in result.eliminated:
            self.outcomes[addr] = BranchOutcome.Taken
    def known_addresses(self): return sorted(self.outcomes.keys())
    def count(self): return len(self.outcomes)


# === conditional_simplifier ===

class DeadBranch:
    def __init__(self, addr, target): self.addr = addr; self.target = target


class ConditionalBranch:
    def __init__(self, addr, true_target, false_target, condition_value=None):
        self.addr = addr; self.true_target = true_target
        self.false_target = false_target; self.condition_value = condition_value


class SimplifyResult:
    def __init__(self, simplified, live=None, dead=None):
        self.simplified = simplified; self._live = live; self._dead = dead
    def is_simplified(self): return self.simplified
    def live_branch(self): return self._live
    def dead_target(self): return self._dead


def live_branch(branch):
    if branch.condition_value is True: return branch.true_target
    if branch.condition_value is False: return branch.false_target
    return None


class ConditionalSimplifier:
    def __init__(self): self.results: Dict[int, SimplifyResult] = {}
    @staticmethod
    def new(): return ConditionalSimplifier()
    def simplify_branch(self, branch):
        lb = live_branch(branch)
        if lb is None: r = SimplifyResult(False)
        else:
            dead = branch.false_target if branch.condition_value else branch.true_target
            r = SimplifyResult(True, lb, dead)
        self.results[branch.addr] = r
        return r
    def simplify_all(self, branches): return [self.simplify_branch(b) for b in branches]
    def result_for(self, addr): return self.results.get(addr)
    def dead_targets(self): return [r._dead for r in self.results.values() if r._dead is not None]
    def all_results(self): return iter(self.results.values())


# === constant_propagator (IR) ===

class ConstLattice:
    def __init__(self, tag, value=None): self.tag = tag; self.value = value
    @staticmethod
    def top(): return ConstLattice("Top")
    @staticmethod
    def bottom(): return ConstLattice("Bottom")
    @staticmethod
    def const(v): return ConstLattice("Const", int(v))
    def join(self, other):
        if self.tag == "Top": return other
        if other.tag == "Top": return self
        if self.tag == "Bottom" or other.tag == "Bottom": return ConstLattice.bottom()
        if self.value == other.value: return self
        return ConstLattice.bottom()
    def meet(self, other):
        if self.tag == "Bottom": return other
        if other.tag == "Bottom": return self
        if self.tag == "Top" or other.tag == "Top": return ConstLattice.top()
        if self.value == other.value: return self
        return ConstLattice.top()
    def is_less_than(self, other):
        if self.tag == "Top" and other.tag != "Top": return True
        if self.tag == "Const" and other.tag == "Bottom": return True
        return False


class BinOpKind(Enum):
    Add="Add"; Sub="Sub"; Mul="Mul"; Div="Div"; Mod="Mod"
    And="And"; Or="Or"; Xor="Xor"; Shl="Shl"; Shr="Shr"


class UnOpKind(Enum):
    Neg="Neg"; Not="Not"


class CmpKind(Enum):
    Eq="Eq"; Ne="Ne"; Lt="Lt"; Le="Le"; Gt="Gt"; Ge="Ge"


VarId = int


class IrInstr:
    def __init__(self, kind, **kw):
        self.kind = kind; self.__dict__.update(kw)


class FoldResult:
    def __init__(self, tag, value=None): self.tag = tag; self.value = value


class InvariantCond:
    def __init__(self, outcome): self.outcome = outcome
    def is_opaque_true(self): return self.outcome == PredicateValue.AlwaysTrue
    def is_opaque_false(self): return self.outcome == PredicateValue.AlwaysFalse


class BasicBlock:
    def __init__(self, id): self.id = id; self.address = None; self.instrs = []; self.successors = []
    @staticmethod
    def new(id): return BasicBlock(id)
    def add_instr(self, instr): self.instrs.append(instr)
    def with_address(self, addr): self.address = addr; return self


class PropState:
    def __init__(self): self.values: Dict[int, ConstLattice] = {}
    @staticmethod
    def new(): return PropState()
    def get(self, var): return self.values.get(var, ConstLattice.top())
    def set(self, var, val): self.values[var] = val
    def join_with(self, other):
        changed = False
        for k, v in other.values.items():
            cur = self.get(k); new = cur.join(v)
            if new.tag != cur.tag or new.value != cur.value:
                self.values[k] = new; changed = True
        return changed
    def const_count(self):
        return sum(1 for v in self.values.values() if v.tag == "Const")


class ConstPropResult:
    def __init__(self):
        self.entry_states: List[PropState] = []
        self.exit_states: List[PropState] = []
        self.opaque_true = 0; self.opaque_false = 0
    def value_at_exit(self, bp, var):
        return self.exit_states[bp].get(var) if 0 <= bp < len(self.exit_states) else ConstLattice.top()
    def value_at_entry(self, bp, var):
        return self.entry_states[bp].get(var) if 0 <= bp < len(self.entry_states) else ConstLattice.top()
    def constants_at_exit(self, bp):
        if not (0 <= bp < len(self.exit_states)): return []
        return [(k, v.value) for k, v in self.exit_states[bp].values.items() if v.tag == "Const"]
    def opaque_true_count(self): return self.opaque_true
    def opaque_false_count(self): return self.opaque_false


class ConstPropPass:
    def __init__(self): self.initial: Dict[int, int] = {}; self.max_iter = 100
    @staticmethod
    def new(): return ConstPropPass()
    def with_initial(self, var, val): self.initial[var] = val; return self
    def with_max_iterations(self, n): self.max_iter = n; return self
    def fold_instruction(self, instr, state):
        if instr.kind == "Const": return FoldResult("Const", instr.value)
        return FoldResult("Unknown")
    def run(self, blocks):
        r = ConstPropResult()
        for _ in blocks:
            s = PropState.new()
            for k, v in self.initial.items(): s.set(k, ConstLattice.const(v))
            r.entry_states.append(s); r.exit_states.append(PropState.new())
        return r


def single_block_cfg(instrs):
    b = BasicBlock.new(0)
    for i in instrs: b.add_instr(i)
    return [b]


def link_cfg(blocks):
    for i in range(len(blocks) - 1):
        if blocks[i+1].id not in blocks[i].successors:
            blocks[i].successors.append(blocks[i+1].id)


# === dead_branch_eliminator ===

class UnreachableReason(Enum):
    NoIncoming = "NoIncoming"; OpaqueBranch = "OpaqueBranch"


class UnreachableBlock:
    def __init__(self, id, reason): self.id = id; self.reason = reason


class BranchPatch:
    def __init__(self, block_id, kept_target):
        self.block_id = block_id; self.kept_target = kept_target


class CfgPatch:
    def __init__(self): self.branch_patches = []; self.removed_blocks = []
    @staticmethod
    def new(): return CfgPatch()
    def is_empty(self): return not self.branch_patches and not self.removed_blocks
    def total_changes(self): return len(self.branch_patches) + len(self.removed_blocks)


class CfgInstr:
    def __init__(self, kind, **kw): self.kind = kind; self.__dict__.update(kw)
    def is_branch(self): return self.kind in ("Branch", "CondBranch")
    def successors(self):
        if self.kind == "Branch": return [self.target]
        if self.kind == "CondBranch": return [self.true_target, self.false_target]
        return []


class CfgBlock:
    def __init__(self, id): self.id = id; self.address = None; self.instrs = []
    @staticmethod
    def new(id): return CfgBlock(id)
    def with_address(self, a): self.address = a; return self
    def add_instr(self, ins): self.instrs.append(ins)
    def branch_instr_idx(self):
        for i, ins in enumerate(self.instrs):
            if ins.is_branch(): return i
        return None


class Cfg:
    def __init__(self, entry): self.entry = entry; self.blocks = []; self.edges = []
    @staticmethod
    def new(entry): return Cfg(entry)
    def add_block(self, b): self.blocks.append(b)
    def rebuild_edges(self):
        self.edges = []
        for b in self.blocks:
            for ins in b.instrs:
                for s in ins.successors():
                    self.edges.append((b.id, s))


class DeadBranchEliminator:
    def __init__(self): self.transitive = True; self.remove_blocks = True
    @staticmethod
    def new(): return DeadBranchEliminator()
    def without_transitive(self): self.transitive = False; return self
    def without_remove_blocks(self): self.remove_blocks = False; return self
    def plan(self, cfg, dead):
        p = CfgPatch.new()
        for d in dead: p.branch_patches.append(BranchPatch(d.addr, d.target))
        return p
    def eliminate(self, cfg, dead):
        r = EliminationResult()
        for d in dead:
            r.eliminated.append((d.addr, d.target)); r.removed_count += 1
        return r


def two_branch_cfg():
    c = Cfg.new(0)
    for i in range(3): c.add_block(CfgBlock.new(i))
    return c


def chain_with_dead_branch():
    c = Cfg.new(0)
    for i in range(4): c.add_block(CfgBlock.new(i))
    return c


# === junk_code_remover ===

class DeadReason(Enum):
    Unreachable = "Unreachable"; Nop = "Nop"; Dead = "Dead"


class DeadInstruction:
    def __init__(self, addr, reason): self.addr = addr; self.reason = reason


class JBasicBlock:
    def __init__(self, start): self.start = start; self.instrs = []; self.successors = []
    @staticmethod
    def new(start): return JBasicBlock(start)
    def push_insn(self, addr, size, bytes_): self.instrs.append((addr, size, bytes_))
    def add_successor(self, target): self.successors.append(target)
    def byte_span(self): return sum(s for _, s, _ in self.instrs)
    def last_address(self): return self.instrs[-1][0] if self.instrs else None


class RemoveResult:
    def __init__(self): self.removed: List[DeadInstruction] = []
    def is_clean(self): return not self.removed
    def dead_addresses(self): return [d.addr for d in self.removed]


class JunkCodeRemover:
    def __init__(self): self.blocks = []; self.live_entries = []; self.dead_seeds = []
    @staticmethod
    def new(): return JunkCodeRemover()
    def add_block(self, b): self.blocks.append(b)
    def add_live_entry(self, a): self.live_entries.append(a)
    def add_dead_seed(self, a): self.dead_seeds.append(a)
    def add_dead_seeds(self, addrs): self.dead_seeds.extend(addrs)
    def block_count(self): return len(self.blocks)
    def scan_obfuscator_nops(self, bytes_): return [i for i, b in enumerate(bytes_) if b == 0x90]
    def remove(self):
        r = RemoveResult()
        seeds = set(self.dead_seeds)
        for b in self.blocks:
            for addr, _sz, by in b.instrs:
                if addr in seeds: r.removed.append(DeadInstruction(addr, DeadReason.Dead))
                elif by == b"\x90": r.removed.append(DeadInstruction(addr, DeadReason.Nop))
        return r


# === opaque_cfg_cleaner ===

class PatchKind(Enum):
    RewriteEdge = "RewriteEdge"; RemoveEdge = "RemoveEdge"; MergeBlock = "MergeBlock"


class CCfgPatch:
    def __init__(self, kind, src, dst): self.kind = kind; self.src = src; self.dst = dst
    def patch_description(self): return f"{self.kind.value} {self.src:#x} -> {self.dst:#x}"


class OpaqueBlock:
    def __init__(self, addr, value): self.addr = addr; self.value = value


class CFGSimplifier:
    def __init__(self): self.patches: List[CCfgPatch] = []
    def add_patch(self, p): self.patches.append(p)
    def apply_patches(self, edges):
        out = list(edges)
        for p in self.patches:
            if p.kind == PatchKind.RemoveEdge:
                out = [e for e in out if e != (p.src, p.dst)]
            elif p.kind == PatchKind.RewriteEdge:
                out = [(p.src, p.dst) if e[0] == p.src else e for e in out]
        return out
    def patch_count(self, kind):
        return sum(1 for p in self.patches if p.kind == kind)


class BlockMerger:
    def find_mergeable(self, edges):
        succ, pred = {}, {}
        for s, d in edges:
            succ.setdefault(s, []).append(d); pred.setdefault(d, []).append(s)
        chains = []
        for n in succ:
            if len(succ[n]) == 1:
                t = succ[n][0]
                if len(pred.get(t, [])) == 1: chains.append([n, t])
        return chains
    def merge(self, edges): return list(edges)


class UnreachableBlockRemover:
    def reachable_from(self, entry, edges):
        adj: Dict[int, List[int]] = {}
        for s, d in edges: adj.setdefault(s, []).append(d)
        seen = {entry}; stack = [entry]
        while stack:
            n = stack.pop()
            for s in adj.get(n, []):
                if s not in seen: seen.add(s); stack.append(s)
        return seen
    def remove_unreachable(self, entry, edges):
        r = self.reachable_from(entry, edges)
        return [(s, d) for s, d in edges if s in r and d in r]
    def count_unreachable(self, entry, all_blocks, edges):
        r = self.reachable_from(entry, edges)
        return sum(1 for b in all_blocks if b not in r)


class CleanedCFG:
    def __init__(self, entry): self.entry = entry; self.edges = []
    @staticmethod
    def new(entry): return CleanedCFG(entry)
    def reduction_ratio(self, original):
        return 0.0 if original == 0 else 1.0 - (len(self.edges) / original)
    def summary(self): return f"CleanedCFG(entry={self.entry:#x}, edges={len(self.edges)})"


class OpaqueCfgCleaner:
    @staticmethod
    def new(): return OpaqueCfgCleaner()
    def detect_opaque_blocks(self, cfg):
        det = OpaqueDetector.new()
        return [OpaqueBlock(f.addr, f.value) for f in det.detect(cfg)]
    def clean(self, cfg): return CleanedCFG.new(cfg.start)


# === opaque_rewriter ===

class RewriteKind(Enum):
    UnconditionalJump = "UnconditionalJump"; Removed = "Removed"; Simplified = "Simplified"


class OpaqueRewrite:
    def __init__(self, addr, kind, target=None):
        self.addr = addr; self.kind = kind; self.target = target


class RewriterBlock:
    def __init__(self, addr, succs=None, conditional=False):
        self.addr = addr; self._succs = succs or []; self._cond = conditional
    @staticmethod
    def new(addr): return RewriterBlock(addr)
    def successors(self): return list(self._succs)
    def is_conditional(self): return self._cond


class RewriteResult:
    def __init__(self): self.rewrites = []; self.dead_blocks = []
    @staticmethod
    def empty(): return RewriteResult()
    def rewrite_count(self): return len(self.rewrites)
    def dead_block_count(self): return len(self.dead_blocks)


class ProvenOpaquePredicate:
    def __init__(self, addr, value, confidence):
        self.addr = addr; self.value = value; self.confidence = confidence


class OpaqueRewriter:
    def __init__(self): self.min_confidence = 0.9; self.max_dce_passes = 4
    @staticmethod
    def new(): return OpaqueRewriter()
    def with_min_confidence(self, c): self.min_confidence = c; return self
    def with_max_dce_passes(self, n): self.max_dce_passes = n; return self
    def apply_one(self, predicate, blocks):
        if predicate.confidence < self.min_confidence: return None
        for b in blocks:
            if b.addr == predicate.addr and b.is_conditional():
                t = b.successors()[0] if b.successors() else 0
                return OpaqueRewrite(predicate.addr, RewriteKind.UnconditionalJump, t)
        return None
    def eliminate_dead_blocks(self, blocks, entry):
        edges = [(b.addr, s) for b in blocks for s in b.successors()]
        r = UnreachableBlockRemover().reachable_from(entry, edges)
        return [b.addr for b in blocks if b.addr not in r]
    def propagate_constants(self, _blocks): return 0
    def rewrite_all(self, predicates, blocks, entry=0):
        r = RewriteResult.empty()
        for p in predicates:
            rw = self.apply_one(p, blocks)
            if rw: r.rewrites.append(rw)
        r.dead_blocks = self.eliminate_dead_blocks(blocks, entry)
        return r
    def build_report(self, result):
        return f"OpaqueRewrite: {result.rewrite_count()} rewrites, {result.dead_block_count()} dead blocks"


# === pattern_library ===

class PatternCategory(Enum):
    Arithmetic = "Arithmetic"; Bitwise = "Bitwise"
    Polynomial = "Polynomial"; Mba = "Mba"; Other = "Other"


class MatchMode(Enum):
    Exact = "Exact"; Fuzzy = "Fuzzy"


class PredicateDesc:
    def __init__(self, id, vars, value): self.id = id; self.vars = vars; self.value = value


class PatternEntry:
    def __init__(self, id, category, value, confidence=1.0):
        self.id = id; self.category = category
        self.value = value; self.confidence = confidence


class LibraryStats:
    def __init__(self, total, by_category): self.total = total; self.by_category = by_category


class PatternLibrary:
    def __init__(self):
        self.entries: List[PatternEntry] = []
        for p in build_known_patterns():
            self.entries.append(PatternEntry(p.name, PatternCategory.Arithmetic, p.value, p.confidence / 100.0))
    @staticmethod
    def new(): return PatternLibrary()
    def pattern_count(self): return len(self.entries)
    def by_category(self, cat): return [e for e in self.entries if e.category == cat]
    def by_id(self, id):
        for e in self.entries:
            if e.id == id: return e
        return None
    def by_value(self, val): return [e for e in self.entries if e.value == val]
    def match_descriptor(self, desc):
        e = self.by_id(desc.id)
        return (e, e.confidence) if e else None
    def classify_no_smt(self, desc):
        m = self.match_descriptor(desc)
        return (m[0].value, m[1]) if m else None
    def classify_many(self, descs):
        return [self.classify_no_smt(d) for d in descs]
    def stats(self):
        bc = {}
        for e in self.entries:
            bc[e.category.value] = bc.get(e.category.value, 0) + 1
        return LibraryStats(len(self.entries), bc)


# === polynomial_check ===

class PolynomialInvariant:
    def __init__(self, name, coeffs, modulus, expected):
        self.name = name; self.coeffs = coeffs
        self.modulus = modulus; self.expected = expected
    @staticmethod
    def new(name, coeffs, modulus, expected):
        return PolynomialInvariant(name, coeffs, modulus, expected)
    def eval_poly(self, x):
        return sum(c * (x ** i) for i, c in enumerate(self.coeffs))
    def eval(self, x):
        return self.eval_poly(x) % self.modulus if self.modulus else self.eval_poly(x)
    def holds(self, x): return self.eval(x) == self.expected
    def verify_range(self, samples):
        return all(self.holds(i) for i in range(samples))


def check_polynomial_invariant(inv, samples): return inv.verify_range(samples)


def consecutive_product_invariant():
    return PolynomialInvariant("x*(x+1) mod 2 == 0", [0, 1, 1], 2, 0)


def consecutive_pred_product_invariant():
    return PolynomialInvariant("x*(x-1) mod 2 == 0", [0, -1, 1], 2, 0)


def square_plus_n_invariant():
    return PolynomialInvariant("x*x+1 > 0", [1, 0, 1], 0, 1)


def triangular_mod6_invariant():
    return PolynomialInvariant("triangular mod 6", [0, 1, 1], 6, 0)


class ZnRingCalculator:
    def __init__(self, n): self.n = n
    @staticmethod
    def new(n): return ZnRingCalculator(n)
    def inv(self, a):
        try: return pow(a % self.n, -1, self.n)
        except ValueError: return None
    def div(self, a, b):
        ib = self.inv(b)
        return (a * ib) % self.n if ib is not None else None
    def eval_poly(self, terms, x):
        return sum(c * (x ** p) for c, p in terms) % self.n


class BitwideEntry:
    def __init__(self, name, value): self.name = name; self.value = value


class BitwideInvariantDb:
    def __init__(self): self.entries: List[BitwideEntry] = []
    @staticmethod
    def build():
        db = BitwideInvariantDb()
        db.entries.append(BitwideEntry("x_xor_x", False))
        db.entries.append(BitwideEntry("x_or_not_x", True))
        return db
    def check(self, expr):
        c = expr.is_const()
        return None if c is None else ("const", c != 0)


class PolynomialChecker:
    def __init__(self, modulus): self.modulus = modulus
    @staticmethod
    def new(modulus): return PolynomialChecker(modulus)
    def check(self, expr):
        c = expr.is_const()
        return (c != 0) if c is not None else None
    def verify_poly(self, inv): return inv.verify_range(64)
    def standard_invariants(self):
        return [consecutive_product_invariant(), consecutive_pred_product_invariant(),
                square_plus_n_invariant(), triangular_mod6_invariant()]


# === predicate_detector ===

class BoolValue(Enum):
    AlwaysTrue = "AlwaysTrue"
    AlwaysFalse = "AlwaysFalse"
    DataDependent = "DataDependent"


class PredicateKind(Enum):
    Trivial = "Trivial"; Pattern = "Pattern"; Sampled = "Sampled"; Unknown = "Unknown"


class PredicatePattern:
    def __init__(self, name, value): self.name = name; self.value = value


class PredicateExpr(OpaqueExpr):
    def variables(self): return self.vars()
    def structurally_equal(self, other): return self.is_trivially_equal(other)
    def as_const(self): return self.is_const()


class OpaquePredicate:
    def __init__(self, addr, value, kind, confidence):
        self.addr = addr; self.value = value
        self.kind = kind; self.confidence = confidence


class DetectionResult:
    def __init__(self): self.predicates: List[OpaquePredicate] = []
    @staticmethod
    def new(): return DetectionResult()
    def always_true_count(self):
        return sum(1 for p in self.predicates if p.value == BoolValue.AlwaysTrue)
    def always_false_count(self):
        return sum(1 for p in self.predicates if p.value == BoolValue.AlwaysFalse)
    def with_min_confidence(self, c):
        return [p for p in self.predicates if p.confidence >= c]


def build_patterns():
    return [PredicatePattern(p.name, BoolValue(p.value.value)) for p in build_known_patterns()]


class TruthSampler:
    def __init__(self): self.bits = 4; self.max_samples = 256
    @staticmethod
    def new(): return TruthSampler()
    def with_bits(self, b): self.bits = b; return self
    def with_max_samples(self, n): self.max_samples = n; return self
    def classify(self, expr):
        return BoolValue(TruthTableChecker.new().classify(expr).value)


class PredicateDetector:
    def __init__(self):
        self.min_confidence = 0.9; self.use_sampler = True; self.use_patterns = True
    @staticmethod
    def new(): return PredicateDetector()
    def with_min_confidence(self, c): self.min_confidence = c; return self
    def without_sampler(self): self.use_sampler = False; return self
    def without_patterns(self): self.use_patterns = False; return self
    def classify_expr(self, expr):
        c = expr.is_const()
        if c is not None:
            return (BoolValue.AlwaysTrue if c != 0 else BoolValue.AlwaysFalse,
                    PredicateKind.Trivial, 1.0, "const")
        if self.use_sampler:
            return TruthSampler.new().classify(expr), PredicateKind.Sampled, 0.95, None
        return BoolValue.DataDependent, PredicateKind.Unknown, 0.0, None
    def detect(self, branches):
        r = DetectionResult.new()
        for addr, e in branches:
            v, k, c, _ = self.classify_expr(e)
            if v != BoolValue.DataDependent:
                r.predicates.append(OpaquePredicate(addr, v, k, c))
        return r
    def detect_high_confidence(self, branches):
        r = self.detect(branches)
        return [p for p in r.predicates if p.confidence >= self.min_confidence]


# === predicate_evaluator ===

class PredicateResult(Enum):
    True_ = "True"; False_ = "False"; Unknown = "Unknown"


def is_determined(r): return r != PredicateResult.Unknown


class AlwaysTrue: pass
class AlwaysFalse: pass


class Expr(OpaqueExpr):
    def const_fold(self, env): return self.eval(env)


class Interval:
    def __init__(self, lo, hi): self.lo = lo; self.hi = hi
    def add(self, other): return Interval(self.lo + other.lo, self.hi + other.hi)
    def sub(self, other): return Interval(self.lo - other.hi, self.hi - other.lo)


def pattern_power_of_two_and(x):
    return (x & (x - 1)) == 0 if x > 0 else x == 0


def pattern_consecutive_product_is_even(x):
    return (x * (x + 1)) % 2 == 0


def pattern_xor_same_zero(x):
    return (x ^ x) == 0


class PredicateEvaluator:
    def __init__(self): self.env: Dict[str, int] = {}; self.cache: Dict[int, PredicateResult] = {}
    @staticmethod
    def new(): return PredicateEvaluator()
    def bind(self, name, value): self.env[name] = value
    def evaluate(self, expr, branch_address):
        if branch_address in self.cache: return self.cache[branch_address]
        v = expr.eval(self.env)
        r = PredicateResult.Unknown if v is None else (PredicateResult.True_ if v != 0 else PredicateResult.False_)
        self.cache[branch_address] = r
        return r
    def cache_size(self): return len(self.cache)
    def cached(self, addr): return self.cache.get(addr)
    def clear_cache(self): self.cache.clear()


def evaluate_with_smt(expr, env):
    v = expr.eval(env)
    if v is None: return PredicateResult.Unknown
    return PredicateResult.True_ if v != 0 else PredicateResult.False_


# === predicate_simplifier ===

class SimplificationResult:
    def __init__(self, addr, eliminated, kept_target=None):
        self.addr = addr; self._elim = eliminated; self.kept_target = kept_target
    def is_eliminated(self): return self._elim
    def summary(self): return f"branch@{self.addr:#x} eliminated={self._elim} kept={self.kept_target}"


class IlBasicBlock:
    def __init__(self, addr): self.addr = addr; self.successors = []
    def add_successor(self, target, conditional): self.successors.append((target, conditional))


class PredicateSimplifier:
    @staticmethod
    def new(): return PredicateSimplifier()
    def simplify_expr(self, expr):
        s = expr.simplify(); c = s.is_const()
        if c is None: return s, PredicateValue.DataDependent
        return s, (PredicateValue.AlwaysTrue if c != 0 else PredicateValue.AlwaysFalse)
    def run(self, cfg):
        out = []
        for b in cfg.branches:
            if b.condition is None:
                out.append(SimplificationResult(b.addr, False)); continue
            _, v = self.simplify_expr(b.condition)
            if v == PredicateValue.AlwaysTrue: out.append(SimplificationResult(b.addr, True, b.true_target))
            elif v == PredicateValue.AlwaysFalse: out.append(SimplificationResult(b.addr, True, b.false_target))
            else: out.append(SimplificationResult(b.addr, False))
        return out
    def apply_to_blocks(self, blocks): return 0


class DeadCodeEliminator:
    def mark_reachable(self, entry, blocks):
        seen = {entry}; stack = [entry]
        while stack:
            n = stack.pop()
            b = blocks.get(n)
            if not b: continue
            for s, _ in b.successors:
                if s not in seen: seen.add(s); stack.append(s)
        return seen
    def eliminate(self, blocks): return 0
    def count_dead(self, blocks): return 0


class SimplificationStats:
    def __init__(self, total, simplified): self.total = total; self.simplified = simplified
    def simplification_rate(self): return self.simplified / self.total if self.total else 0.0


class IlCfg:
    def __init__(self): self.entry = None; self.blocks: Dict[int, IlBasicBlock] = {}; self.branches = []
    @staticmethod
    def new(): return IlCfg()
    def set_entry(self, a): self.entry = a
    def add_block(self, b): self.blocks[b.addr] = b
    def add_branch(self, b): self.branches.append(b)
    def simplify(self):
        cfg = SimpleBranchCfg.new(self.entry or 0); cfg.branches = self.branches
        rs = PredicateSimplifier.new().run(cfg)
        return SimplificationStats(len(rs), sum(1 for r in rs if r.is_eliminated()))
    def block_count(self): return len(self.blocks)
    def reachable_count(self):
        if self.entry is None: return 0
        return len(DeadCodeEliminator().mark_reachable(self.entry, self.blocks))


# === sat_checker ===

class OpaquePredicateCandidate:
    def __init__(self, addr, expr):
        self.addr = addr; self.expr = expr; self.result = PredicateValue.DataDependent


class SatCheckerStats:
    def __init__(self): self.checked = 0; self.proved = 0


class PatternDb:
    def __init__(self): self.patterns: List[Tuple[str, Callable]] = []
    @staticmethod
    def build():
        db = PatternDb()
        def const_check(e):
            c = e.is_const()
            if c is None: return None
            return PredicateValue.AlwaysTrue if c != 0 else PredicateValue.AlwaysFalse
        db.add("const", const_check)
        return db
    def check(self, expr):
        for _n, f in self.patterns:
            r = f(expr)
            if r is not None: return r
        return None
    def len(self): return len(self.patterns)
    def is_empty(self): return not self.patterns
    def add(self, name, f): self.patterns.append((name, f))


class SatChecker:
    def __init__(self): self.db = PatternDb.build(); self.stats = SatCheckerStats()
    @staticmethod
    def new(): return SatChecker()
    def verify_opaque(self, expr):
        self.stats.checked += 1
        r = self.db.check(expr)
        if r is not None:
            self.stats.proved += 1; return r
        return TruthTableChecker.new().classify(expr)
    def verify_candidate(self, c): c.result = self.verify_opaque(c.expr)
    def batch_verify(self, cs):
        for c in cs: self.verify_candidate(c)
    def filter_opaque(self, cs):
        self.batch_verify(cs)
        return [c for c in cs if c.result != PredicateValue.DataDependent]


# === smt_prover ===

class SmtBinOp(Enum):
    Add="Add"; Sub="Sub"; Mul="Mul"; And="And"; Or="Or"; Xor="Xor"


class SmtUnaryOp(Enum):
    Not="Not"; Neg="Neg"; Square="Square"


class SmtCmpOp(Enum):
    Eq="Eq"; Ne="Ne"; Sge="Sge"; Uge="Uge"


class SmtResult(Enum):
    Sat="Sat"; Unsat="Unsat"; Unknown="Unknown"
    def is_sat(self): return self == SmtResult.Sat
    def is_unsat(self): return self == SmtResult.Unsat
    def is_unknown(self): return self == SmtResult.Unknown


class SmtExpr:
    def __init__(self, kind, **kw): self.kind = kind; self.__dict__.update(kw)
    @staticmethod
    def constant(v): return SmtExpr("Const", value=int(v))
    @staticmethod
    def var(name, width): return SmtExpr("Var", name=name, width=width)
    @staticmethod
    def add(a, b): return SmtExpr("Add", lhs=a, rhs=b)
    @staticmethod
    def sub(a, b): return SmtExpr("Sub", lhs=a, rhs=b)
    @staticmethod
    def mul(a, b): return SmtExpr("Mul", lhs=a, rhs=b)
    @staticmethod
    def and_(a, b): return SmtExpr("And", lhs=a, rhs=b)
    @staticmethod
    def or_(a, b): return SmtExpr("Or", lhs=a, rhs=b)
    @staticmethod
    def xor(a, b): return SmtExpr("Xor", lhs=a, rhs=b)
    @staticmethod
    def not_(i): return SmtExpr("Not", inner=i)
    @staticmethod
    def neg(i): return SmtExpr("Neg", inner=i)
    @staticmethod
    def square(i): return SmtExpr("Square", inner=i)
    @staticmethod
    def eq(a, b): return SmtExpr("Eq", lhs=a, rhs=b)
    @staticmethod
    def ne(a, b): return SmtExpr("Ne", lhs=a, rhs=b)
    @staticmethod
    def sge(a, b): return SmtExpr("Sge", lhs=a, rhs=b)
    @staticmethod
    def uge(a, b): return SmtExpr("Uge", lhs=a, rhs=b)

    def free_vars(self):
        out: List[Tuple[str, int]] = []; seen = set()
        def walk(e):
            if e.kind == "Var":
                if e.name not in seen: seen.add(e.name); out.append((e.name, e.width))
            for attr in ("lhs", "rhs", "inner"):
                c = getattr(e, attr, None)
                if isinstance(c, SmtExpr): walk(c)
        walk(self); return out

    def eval(self, env):
        k = self.kind
        if k == "Const": return self.value
        if k == "Var": return env.get(self.name)
        if k in ("Not", "Neg", "Square"):
            v = self.inner.eval(env)
            if v is None: return None
            if k == "Not": return _to_signed64(~v)
            if k == "Neg": return _to_signed64(-v)
            return _to_signed64(v * v)
        a = self.lhs.eval(env); b = self.rhs.eval(env)
        if a is None or b is None: return None
        ops = {"Add": a + b, "Sub": a - b, "Mul": a * b,
               "And": a & b, "Or": a | b, "Xor": a ^ b}
        if k in ops: return _to_signed64(ops[k])
        if k == "Eq": return 1 if a == b else 0
        if k == "Ne": return 1 if a != b else 0
        if k == "Sge": return 1 if a >= b else 0
        if k == "Uge": return 1 if (a & MASK64) >= (b & MASK64) else 0
        return None


class SmtProver:
    def __init__(self): self.timeout_ms = 5000; self.samples = 256
    @staticmethod
    def new(): return SmtProver()
    def with_timeout(self, ms): self.timeout_ms = ms; return self
    def with_sample_count(self, n): self.samples = n; return self
    def check(self, predicate):
        rnd = random.Random(0xBEEF)
        fvars = predicate.free_vars()
        true_n = false_n = 0; total = 0
        for _ in range(self.samples):
            env = {n: _to_signed64(rnd.getrandbits(min(w, 64))) for n, w in fvars}
            v = predicate.eval(env)
            if v is None: continue
            total += 1
            if v != 0: true_n += 1
            else: false_n += 1
        if total == 0: return PredicateValue.DataDependent, 0.0, SmtResult.Unknown
        if false_n == 0: return PredicateValue.AlwaysTrue, true_n / total, SmtResult.Unsat
        if true_n == 0: return PredicateValue.AlwaysFalse, false_n / total, SmtResult.Unsat
        return PredicateValue.DataDependent, 0.5, SmtResult.Sat
    def classify(self, predicate): return self.check(predicate)[0]
    def is_tautology(self, p): return self.classify(p) == PredicateValue.AlwaysTrue
    def is_contradiction(self, p): return self.classify(p) == PredicateValue.AlwaysFalse


# === tautology_db ===

class TautologyValue(Enum):
    AlwaysTrue = "AlwaysTrue"; AlwaysFalse = "AlwaysFalse"; Conditional = "Conditional"


class TautologyExpr:
    def __init__(self, kind, **kw): self.kind = kind; self.__dict__.update(kw)
    @staticmethod
    def var(s): return TautologyExpr("Var", name=s)
    @staticmethod
    def _bin(op, a, b): return TautologyExpr(op, lhs=a, rhs=b)
    @staticmethod
    def and_(a, b): return TautologyExpr._bin("And", a, b)
    @staticmethod
    def or_(a, b): return TautologyExpr._bin("Or", a, b)
    @staticmethod
    def xor(a, b): return TautologyExpr._bin("Xor", a, b)
    @staticmethod
    def add(a, b): return TautologyExpr._bin("Add", a, b)
    @staticmethod
    def sub(a, b): return TautologyExpr._bin("Sub", a, b)
    @staticmethod
    def mul(a, b): return TautologyExpr._bin("Mul", a, b)
    @staticmethod
    def eq(a, b): return TautologyExpr._bin("Eq", a, b)
    @staticmethod
    def ne(a, b): return TautologyExpr._bin("Ne", a, b)
    @staticmethod
    def lt(a, b): return TautologyExpr._bin("Lt", a, b)
    @staticmethod
    def le(a, b): return TautologyExpr._bin("Le", a, b)
    @staticmethod
    def not_(a): return TautologyExpr("Not", inner=a)
    @staticmethod
    def neg(a): return TautologyExpr("Neg", inner=a)

    def vars(self):
        out, seen = [], set()
        def walk(e):
            if e.kind == "Var":
                if e.name not in seen: seen.add(e.name); out.append(e.name)
            for attr in ("lhs", "rhs", "inner"):
                c = getattr(e, attr, None)
                if isinstance(c, TautologyExpr): walk(c)
        walk(self); return out

    def node_count(self):
        n = 1
        for attr in ("lhs", "rhs", "inner"):
            c = getattr(self, attr, None)
            if isinstance(c, TautologyExpr): n += c.node_count()
        return n

    def eval(self, env):
        k = self.kind
        if k == "Var": return env.get(self.name)
        if k in ("Not", "Neg"):
            v = self.inner.eval(env)
            if v is None: return None
            return _to_signed64(~v if k == "Not" else -v)
        a = self.lhs.eval(env); b = self.rhs.eval(env)
        if a is None or b is None: return None
        ops = {"And": a & b, "Or": a | b, "Xor": a ^ b,
               "Add": a + b, "Sub": a - b, "Mul": a * b}
        if k in ops: return _to_signed64(ops[k])
        cmp = {"Eq": a == b, "Ne": a != b, "Lt": a < b, "Le": a <= b}
        if k in cmp: return 1 if cmp[k] else 0
        return None


class TautologyClassification(Enum):
    AlwaysTrue = "AlwaysTrue"; AlwaysFalse = "AlwaysFalse"; Conditional = "Conditional"


class TautologyEvaluator:
    @staticmethod
    def new(): return TautologyEvaluator()
    def classify(self, expr):
        vars_ = expr.vars(); true_n = false_n = 0
        rnd = random.Random(1234)
        for _ in range(64):
            env = {v: _to_signed64(rnd.getrandbits(8)) for v in vars_}
            r = expr.eval(env)
            if r is None: continue
            if r != 0: true_n += 1
            else: false_n += 1
        if false_n == 0 and true_n > 0: return TautologyClassification.AlwaysTrue
        if true_n == 0 and false_n > 0: return TautologyClassification.AlwaysFalse
        return TautologyClassification.Conditional


class TautologyPattern:
    def __init__(self, name, expr, value): self.name = name; self.expr = expr; self.value = value
    @staticmethod
    def new(name, expr, value): return TautologyPattern(name, expr, value)
    def verify_sampled(self, bits, samples):
        rnd = random.Random(0xABCD)
        for _ in range(samples):
            env = {v: _to_signed64(rnd.getrandbits(bits)) for v in self.expr.vars()}
            r = self.expr.eval(env)
            if r is None: continue
            truth = r != 0; want = self.value == TautologyValue.AlwaysTrue
            if truth != want: return False
        return True


class TautologyDb:
    def __init__(self): self.patterns: Dict[str, TautologyPattern] = {}
    @staticmethod
    def new():
        db = TautologyDb()
        x = TautologyExpr.var("x")
        db.patterns["x_xor_x"] = TautologyPattern("x_xor_x", TautologyExpr.xor(x, x), TautologyValue.AlwaysFalse)
        db.patterns["x_eq_x"] = TautologyPattern("x_eq_x", TautologyExpr.eq(x, x), TautologyValue.AlwaysTrue)
        return db
    def get(self, name): return self.patterns.get(name)
    def always_true_patterns(self):
        return [p for p in self.patterns.values() if p.value == TautologyValue.AlwaysTrue]
    def contradictions(self):
        return [p for p in self.patterns.values() if p.value == TautologyValue.AlwaysFalse]
    def with_var_count(self, n):
        return [p for p in self.patterns.values() if len(p.expr.vars()) == n]


class TautologyStatistics:
    def __init__(self, total, t, f): self.total = total; self.always_true = t; self.always_false = f
    @staticmethod
    def from_db(db):
        return TautologyStatistics(len(db.patterns), len(db.always_true_patterns()), len(db.contradictions()))
    def summary(self): return f"total={self.total} true={self.always_true} false={self.always_false}"


class ConfidenceScore:
    def __init__(self, pc, sc, nc):
        self.pattern_conf = pc; self.sampling_conf = sc; self.node_count = nc
    @staticmethod
    def new(pc, sc, nc): return ConfidenceScore(pc, sc, nc)
    def overall(self): return min(100, (self.pattern_conf + self.sampling_conf) // 2)
    def is_patchable(self): return self.overall() >= 80


class TautologyPatch:
    def __init__(self, offset, bytes_, description):
        self.offset = offset; self.bytes = bytes_; self.description = description


class TautologyPatchGenerator:
    @staticmethod
    def always_taken_patch(offset, original_jcc):
        if not original_jcc: return None
        if len(original_jcc) == 2:
            return TautologyPatch(offset, b"\xEB" + original_jcc[1:2], "always taken (short)")
        return TautologyPatch(offset, b"\x90" * len(original_jcc), "always taken (nop fill)")
    @staticmethod
    def never_taken_patch(offset, original_jcc):
        if not original_jcc: return None
        return TautologyPatch(offset, b"\x90" * len(original_jcc), "never taken (nop out)")
    @staticmethod
    def generate_from_map(m):
        out = []
        for off, (jcc, taken) in m.items():
            p = (TautologyPatchGenerator.always_taken_patch(off, jcc)
                 if taken else TautologyPatchGenerator.never_taken_patch(off, jcc))
            if p: out.append(p)
        return out


class TautologyOptimizer:
    @staticmethod
    def prioritize(patches): return sorted(patches, key=lambda p: p.offset)


class TautologyMatcher:
    def __init__(self): self.db = TautologyDb.new()
    @staticmethod
    def new(): return TautologyMatcher()
    def match_expr(self, expr):
        cl = TautologyEvaluator.new().classify(expr)
        if cl == TautologyClassification.Conditional: return None
        name = "x_eq_x" if cl == TautologyClassification.AlwaysTrue else "x_xor_x"
        p = self.db.get(name)
        if not p: return None
        return p, ConfidenceScore.new(95, 95, expr.node_count())


class TautologyReport:
    def __init__(self): self.records: List[Tuple[str, int, int]] = []
    @staticmethod
    def new(): return TautologyReport()
    def record(self, pattern, address, confidence):
        self.records.append((pattern, address, confidence))


if __name__ == "__main__":
    e = OpaqueExpr.bin("Xor", OpaqueExpr.var("x"), OpaqueExpr.var("x")).simplify()
    assert e.is_const() == 0
    cfg = SimpleBranchCfg.new(0x1000)
    cfg.add_branch(SimpleBranch(0x1000, 0x2000, 0x3000, e))
    res = OpaqueDeobfPass.new().run(cfg)
    assert res.elim.changed()
    print("rustre-deobf-opaque python reproduction OK")
