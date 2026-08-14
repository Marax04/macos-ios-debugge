"""rustre-deobf-mba — Python reference reproducing the documented public API.

Stdlib only. For each function in the report, a Python equivalent accepting the
same inputs and returning the same output types.

Crate: rustre-deobf-mba
"""
from __future__ import annotations

import math
import random
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple


# ============================================================
# lib.rs — MbaExpr AST
# ============================================================

class MbaExpr:
    """Minimal AST for MBA expressions."""
    def __init__(self, kind: str, value=None, children: list = None):
        self.kind = kind          # 'Const', 'Var', 'Add', 'Sub', 'Mul', 'Neg',
                                  # 'And', 'Or', 'Xor', 'Not'
        self.value = value        # int (Const) or str (Var)
        self.children = children or []

    # ---- constructors ----
    @staticmethod
    def mk_add(lhs: 'MbaExpr', rhs: 'MbaExpr') -> 'MbaExpr':
        return MbaExpr('Add', children=[lhs, rhs])

    @staticmethod
    def mk_sub(lhs: 'MbaExpr', rhs: 'MbaExpr') -> 'MbaExpr':
        return MbaExpr('Sub', children=[lhs, rhs])

    @staticmethod
    def mk_mul(lhs: 'MbaExpr', rhs: 'MbaExpr') -> 'MbaExpr':
        return MbaExpr('Mul', children=[lhs, rhs])

    @staticmethod
    def mk_neg(e: 'MbaExpr') -> 'MbaExpr':
        return MbaExpr('Neg', children=[e])

    @staticmethod
    def mk_and(lhs: 'MbaExpr', rhs: 'MbaExpr') -> 'MbaExpr':
        return MbaExpr('And', children=[lhs, rhs])

    @staticmethod
    def mk_or(lhs: 'MbaExpr', rhs: 'MbaExpr') -> 'MbaExpr':
        return MbaExpr('Or', children=[lhs, rhs])

    @staticmethod
    def mk_xor(lhs: 'MbaExpr', rhs: 'MbaExpr') -> 'MbaExpr':
        return MbaExpr('Xor', children=[lhs, rhs])

    @staticmethod
    def mk_not(e: 'MbaExpr') -> 'MbaExpr':
        return MbaExpr('Not', children=[e])

    # ---- instance methods ----
    def complexity(self) -> int:
        """Count AST nodes."""
        return 1 + sum(c.complexity() for c in self.children)

    def vars(self) -> List[str]:
        """List free variables (deduplicated, sorted)."""
        seen: Set[str] = set()
        self._collect_vars(seen)
        return sorted(seen)

    def _collect_vars(self, acc: Set[str]) -> None:
        if self.kind == 'Var':
            acc.add(self.value)
        for c in self.children:
            c._collect_vars(acc)

    def eval(self, env: Dict[str, int]) -> Optional[int]:
        """Evaluate expression under variable assignment."""
        if self.kind == 'Const':
            return self.value
        if self.kind == 'Var':
            return env.get(self.value)
        vals = [c.eval(env) for c in self.children]
        if any(v is None for v in vals):
            return None
        a, b = (vals[0], vals[1]) if len(vals) >= 2 else (vals[0], None)
        if self.kind == 'Add':  return a + b
        if self.kind == 'Sub':  return a - b
        if self.kind == 'Mul':  return a * b
        if self.kind == 'Neg':  return -a
        if self.kind == 'And':  return a & b
        if self.kind == 'Or':   return a | b
        if self.kind == 'Xor':  return a ^ b
        if self.kind == 'Not':  return ~a
        return None

    def substitute(self, var: str, repl: 'MbaExpr') -> 'MbaExpr':
        """Replace variable `var` with sub-expression `repl`."""
        if self.kind == 'Var' and self.value == var:
            return repl
        return MbaExpr(self.kind, self.value, [c.substitute(var, repl) for c in self.children])

    def is_linear(self) -> bool:
        """True if no Mul between two non-Const sub-expressions."""
        if self.kind == 'Mul':
            lhs, rhs = self.children
            if lhs.kind != 'Const' and rhs.kind != 'Const':
                return False
        return all(c.is_linear() for c in self.children)

    @staticmethod
    def parse(s: str) -> 'MbaExpr':
        """Parse a textual MBA expression."""
        return _parse_mba_expr(s.strip())


def _tokenize(s: str) -> List[str]:
    token_re = re.compile(r'\d+|[a-zA-Z_]\w*|[+\-*/&|^~()]')
    return token_re.findall(s)


class _Parser:
    def __init__(self, tokens: List[str]):
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> Optional[str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def consume(self) -> str:
        t = self.tokens[self.pos]; self.pos += 1; return t

    def parse_expr(self) -> MbaExpr:
        return self.parse_add()

    def parse_add(self) -> MbaExpr:
        node = self.parse_mul()
        while self.peek() in ('+', '-'):
            op = self.consume()
            rhs = self.parse_mul()
            node = MbaExpr.mk_add(node, rhs) if op == '+' else MbaExpr.mk_sub(node, rhs)
        return node

    def parse_mul(self) -> MbaExpr:
        node = self.parse_bitwise()
        while self.peek() == '*':
            self.consume()
            node = MbaExpr.mk_mul(node, self.parse_bitwise())
        return node

    def parse_bitwise(self) -> MbaExpr:
        node = self.parse_unary()
        while self.peek() in ('&', '|', '^'):
            op = self.consume()
            rhs = self.parse_unary()
            if op == '&': node = MbaExpr.mk_and(node, rhs)
            elif op == '|': node = MbaExpr.mk_or(node, rhs)
            else: node = MbaExpr.mk_xor(node, rhs)
        return node

    def parse_unary(self) -> MbaExpr:
        if self.peek() == '-':
            self.consume(); return MbaExpr.mk_neg(self.parse_primary())
        if self.peek() == '~':
            self.consume(); return MbaExpr.mk_not(self.parse_primary())
        return self.parse_primary()

    def parse_primary(self) -> MbaExpr:
        t = self.peek()
        if t == '(':
            self.consume()
            node = self.parse_expr()
            self.consume()  # ')'
            return node
        self.consume()
        if t and t.isdigit():
            return MbaExpr('Const', int(t))
        return MbaExpr('Var', t)


def _parse_mba_expr(s: str) -> MbaExpr:
    tokens = _tokenize(s)
    parser = _Parser(tokens)
    result = parser.parse_expr()
    if parser.pos != len(parser.tokens):
        raise ValueError(f"Unexpected token at position {parser.pos}")
    return result


# ---- SimplificationRule stub ----
class SimplificationRule:
    def __init__(self, name: str, pattern: str, replacement: str):
        self.name = name
        self.pattern = pattern
        self.replacement = replacement


def build_rule_database() -> List[SimplificationRule]:
    """Generate standard simplification rule database."""
    return [
        SimplificationRule("add_zero",    "x+0",  "x"),
        SimplificationRule("sub_zero",    "x-0",  "x"),
        SimplificationRule("mul_zero",    "x*0",  "0"),
        SimplificationRule("mul_one",     "x*1",  "x"),
        SimplificationRule("and_zero",    "x&0",  "0"),
        SimplificationRule("and_self",    "x&x",  "x"),
        SimplificationRule("or_zero",     "x|0",  "x"),
        SimplificationRule("or_self",     "x|x",  "x"),
        SimplificationRule("xor_self",    "x^x",  "0"),
        SimplificationRule("xor_zero",    "x^0",  "x"),
        SimplificationRule("not_not",     "~~x",  "x"),
        SimplificationRule("neg_neg",     "--x",  "x"),
        SimplificationRule("add_neg",     "x+(-x)", "0"),
        SimplificationRule("xor_add",     "(x^y)+(x&y)*2", "x+y"),
        SimplificationRule("not_xor",     "~(x^y)", "(~x)^y"),
        SimplificationRule("and_or_dist", "x&(x|y)", "x"),
        SimplificationRule("or_and_dist", "x|(x&y)", "x"),
    ]


# ---- VerificationResult ----
class VerificationResult:
    def __init__(self, equivalent: bool, confidence: float, counterexample=None):
        self.equivalent = equivalent
        self.confidence = confidence
        self.counterexample = counterexample  # Optional[Dict[str,int]]

    def __repr__(self):
        return f"VerificationResult(equivalent={self.equivalent}, confidence={self.confidence:.2f})"


# ---- MbaVerifier ----
class MbaVerifier:
    def __init__(self, samples: int = 64):
        self._samples = samples

    @staticmethod
    def new() -> 'MbaVerifier':
        return MbaVerifier()

    def _sample_env(self, var_names: List[str]) -> Dict[str, int]:
        return {v: random.randint(-128, 127) for v in var_names}

    def verify_equivalent(self, a: MbaExpr, b: MbaExpr) -> VerificationResult:
        """Verify semantic equivalence by random sampling."""
        var_names = sorted(set(a.vars()) | set(b.vars()))
        mismatches = 0
        last_env = None
        for _ in range(self._samples):
            env = self._sample_env(var_names)
            va, vb = a.eval(env), b.eval(env)
            if va != vb:
                mismatches += 1
                last_env = env
        if mismatches == 0:
            return VerificationResult(True, 1.0)
        return VerificationResult(False, 0.0, last_env)

    def is_always_zero(self, expr: MbaExpr) -> bool:
        var_names = expr.vars()
        for _ in range(self._samples):
            env = self._sample_env(var_names)
            if expr.eval(env) != 0:
                return False
        return True

    def is_always_const(self, expr: MbaExpr, c: int) -> bool:
        var_names = expr.vars()
        for _ in range(self._samples):
            env = self._sample_env(var_names)
            if expr.eval(env) != c:
                return False
        return True

    def find_counterexample(self, a: MbaExpr, b: MbaExpr) -> Optional[Dict[str, int]]:
        var_names = sorted(set(a.vars()) | set(b.vars()))
        for _ in range(self._samples):
            env = self._sample_env(var_names)
            if a.eval(env) != b.eval(env):
                return env
        return None


# ---- SimplificationResult ----
class SimplificationResult:
    def __init__(self, original: MbaExpr, simplified: MbaExpr, rules_applied: List[str], steps: int = 0):
        self.original = original
        self.simplified = simplified
        self.rules_applied = rules_applied
        self.steps = steps

    def reduction_ratio(self) -> float:
        orig_c = self.original.complexity()
        simp_c = self.simplified.complexity()
        if orig_c == 0:
            return 0.0
        return max(0.0, 1.0 - simp_c / orig_c)


# ---- MbaSimplifier ----
class MbaSimplifier:
    def __init__(self, rules: Optional[List[SimplificationRule]] = None):
        self._rules = rules or build_rule_database()

    @staticmethod
    def new() -> 'MbaSimplifier':
        return MbaSimplifier()

    def simplify(self, expr: MbaExpr) -> SimplificationResult:
        """Iterative bottom-up simplification to fixed point."""
        current = expr
        all_rules: List[str] = []
        steps = 0
        while True:
            next_expr, applied = self.simplify_once(current)
            if not applied and next_expr.complexity() == current.complexity():
                break
            all_rules.extend(applied)
            current = next_expr
            steps += 1
            if steps > 100:
                break
        return SimplificationResult(expr, current, all_rules, steps)

    def simplify_once(self, expr: MbaExpr) -> Tuple[MbaExpr, List[str]]:
        """Single rewrite pass, returning (new_expr, rules_applied)."""
        return self.apply_rules_bottomup(expr)

    def apply_rules_bottomup(self, expr: MbaExpr) -> Tuple[MbaExpr, List[str]]:
        """Post-order rule application."""
        new_children = []
        all_rules: List[str] = []
        for c in expr.children:
            nc, rules = self.apply_rules_bottomup(c)
            new_children.append(nc)
            all_rules.extend(rules)
        node = MbaExpr(expr.kind, expr.value, new_children)
        result = self.try_rules(node)
        if result is not None:
            simplified, rule_name = result
            all_rules.append(rule_name)
            return simplified, all_rules
        return node, all_rules

    def try_rules(self, expr: MbaExpr) -> Optional[Tuple[MbaExpr, str]]:
        """Try each rule and return first applicable one."""
        # Constant folding
        if expr.kind == 'Add' and expr.children[0].kind == 'Const' and expr.children[1].kind == 'Const':
            return MbaExpr('Const', expr.children[0].value + expr.children[1].value), "const_fold_add"
        if expr.kind == 'Sub' and expr.children[0].kind == 'Const' and expr.children[1].kind == 'Const':
            return MbaExpr('Const', expr.children[0].value - expr.children[1].value), "const_fold_sub"
        if expr.kind == 'Mul' and expr.children[0].kind == 'Const' and expr.children[1].kind == 'Const':
            return MbaExpr('Const', expr.children[0].value * expr.children[1].value), "const_fold_mul"
        if expr.kind in ('And', 'Or', 'Xor') and all(c.kind == 'Const' for c in expr.children):
            a, b = expr.children[0].value, expr.children[1].value
            v = a & b if expr.kind == 'And' else (a | b if expr.kind == 'Or' else a ^ b)
            return MbaExpr('Const', v), "const_fold_bitwise"
        if expr.kind == 'Neg' and expr.children[0].kind == 'Const':
            return MbaExpr('Const', -expr.children[0].value), "const_fold_neg"
        if expr.kind == 'Not' and expr.children[0].kind == 'Const':
            return MbaExpr('Const', ~expr.children[0].value), "const_fold_not"
        # Identity rules
        if expr.kind == 'Add' and expr.children[1].kind == 'Const' and expr.children[1].value == 0:
            return expr.children[0], "add_zero"
        if expr.kind == 'Sub' and expr.children[1].kind == 'Const' and expr.children[1].value == 0:
            return expr.children[0], "sub_zero"
        if expr.kind == 'Mul' and expr.children[1].kind == 'Const' and expr.children[1].value == 0:
            return MbaExpr('Const', 0), "mul_zero_r"
        if expr.kind == 'Mul' and expr.children[0].kind == 'Const' and expr.children[0].value == 0:
            return MbaExpr('Const', 0), "mul_zero_l"
        if expr.kind == 'Mul' and expr.children[1].kind == 'Const' and expr.children[1].value == 1:
            return expr.children[0], "mul_one_r"
        if expr.kind == 'And' and expr.children[1].kind == 'Const' and expr.children[1].value == 0:
            return MbaExpr('Const', 0), "and_zero"
        if expr.kind == 'Or' and expr.children[1].kind == 'Const' and expr.children[1].value == 0:
            return expr.children[0], "or_zero"
        if expr.kind == 'Xor' and expr.children[1].kind == 'Const' and expr.children[1].value == 0:
            return expr.children[0], "xor_zero"
        # x op x
        if expr.kind in ('And', 'Or') and len(expr.children) == 2:
            l, r = expr.children
            if l.kind == r.kind == 'Var' and l.value == r.value:
                return l, "self_bitwise"
        if expr.kind == 'Xor' and len(expr.children) == 2:
            l, r = expr.children
            if l.kind == r.kind == 'Var' and l.value == r.value:
                return MbaExpr('Const', 0), "xor_self"
        # ~~x
        if expr.kind == 'Not' and expr.children[0].kind == 'Not':
            return expr.children[0].children[0], "not_not"
        # --x
        if expr.kind == 'Neg' and expr.children[0].kind == 'Neg':
            return expr.children[0].children[0], "neg_neg"
        return None

    def simplify_tree(self, expr: MbaExpr) -> MbaExpr:
        """Recursive simplification without rule tracking."""
        result, _ = self.apply_rules_bottomup(expr)
        return result


# ---- MbaPattern / MbaPatternLibrary ----
class MbaPattern:
    def __init__(self, name: str, var_count: int, description: str = ""):
        self.name = name
        self.var_count = var_count
        self.description = description


class MbaPatternLibrary:
    def __init__(self, patterns: List[MbaPattern]):
        self._patterns = patterns

    @staticmethod
    def standard() -> 'MbaPatternLibrary':
        return MbaPatternLibrary([
            MbaPattern("xor_add",        2, "(x^y) + 2*(x&y) = x+y"),
            MbaPattern("or_and_sum",     2, "(x|y) + (x&y) = x+y"),
            MbaPattern("not_neg",        1, "~x = -x-1"),
            MbaPattern("xor_or_and",     2, "x^y = (x|y) - (x&y)"),
            MbaPattern("add_xor_and",    2, "x+y = (x^y) + 2*(x&y)"),
            MbaPattern("sub_xor_not",    2, "x-y = x + ~y + 1"),
            MbaPattern("neg_not",        1, "-x = ~x+1"),
            MbaPattern("linear_mba",     2, "a*x + b*y = linear_combination"),
        ])

    def match_pattern(self, expr: MbaExpr) -> Optional[MbaPattern]:
        """Return first pattern plausibly matching the expression."""
        has_xor = _has_op(expr, 'Xor')
        has_and = _has_op(expr, 'And')
        has_or  = _has_op(expr, 'Or')
        has_add = _has_op(expr, 'Add')
        if has_xor and has_and and has_add:
            return next((p for p in self._patterns if p.name == 'xor_add'), None)
        if has_or and has_and:
            return next((p for p in self._patterns if p.name == 'or_and_sum'), None)
        if has_xor and (has_or or has_and):
            return next((p for p in self._patterns if p.name == 'xor_or_and'), None)
        return None


def _has_op(expr: MbaExpr, kind: str) -> bool:
    if expr.kind == kind:
        return True
    return any(_has_op(c, kind) for c in expr.children)


# ---- MbaPassResult ----
class MbaPassResult:
    def __init__(self, results: List[SimplificationResult]):
        self.results = results

    @property
    def simplified_count(self) -> int:
        return sum(1 for r in self.results if r.reduction_ratio() > 0)


# ---- MbaAnalyzer ----
class MbaAnalyzer:
    def __init__(self):
        self._simplifier = MbaSimplifier.new()

    @staticmethod
    def new() -> 'MbaAnalyzer':
        return MbaAnalyzer()

    def analyze_expression(self, expr: MbaExpr) -> SimplificationResult:
        return self._simplifier.simplify(expr)

    def analyze_batch(self, exprs: List[MbaExpr]) -> MbaPassResult:
        return MbaPassResult([self.analyze_expression(e) for e in exprs])


# ============================================================
# deobf_mba_pass.rs
# ============================================================

class IrExpr:
    """Minimal IR expression stub."""
    def __init__(self, kind: str, value=None, children: list = None):
        self.kind = kind
        self.value = value
        self.children = children or []


def validator_translate_ir_to_mba(expr: IrExpr) -> MbaExpr:
    """Translate an IR expression into the MBA domain."""
    if expr.kind == 'Const':
        return MbaExpr('Const', expr.value)
    if expr.kind == 'Var':
        return MbaExpr('Var', expr.value)
    kids = [validator_translate_ir_to_mba(c) for c in expr.children]
    mapping = {
        'Add': MbaExpr.mk_add, 'Sub': MbaExpr.mk_sub, 'Mul': MbaExpr.mk_mul,
        'And': MbaExpr.mk_and, 'Or': MbaExpr.mk_or,   'Xor': MbaExpr.mk_xor,
    }
    if expr.kind in mapping and len(kids) == 2:
        return mapping[expr.kind](kids[0], kids[1])
    if expr.kind == 'Neg' and kids:
        return MbaExpr.mk_neg(kids[0])
    if expr.kind == 'Not' and kids:
        return MbaExpr.mk_not(kids[0])
    return MbaExpr('Var', f'ir_{expr.kind}')


def validator_translate_mba_to_ir(expr: MbaExpr) -> IrExpr:
    """Translate a simplified MBA expression back to IR."""
    if expr.kind == 'Const':
        return IrExpr('Const', expr.value)
    if expr.kind == 'Var':
        return IrExpr('Var', expr.value)
    kids = [validator_translate_mba_to_ir(c) for c in expr.children]
    return IrExpr(expr.kind, None, kids)


class IrMbaExpr:
    def __init__(self, ir_expr: IrExpr):
        self.ir_expr = ir_expr

    def complexity(self) -> int:
        def _count(e: IrExpr) -> int:
            return 1 + sum(_count(c) for c in e.children)
        return _count(self.ir_expr)

    def is_arithmetic(self) -> bool:
        def _check(e: IrExpr) -> bool:
            if e.kind in ('And', 'Or', 'Xor', 'Not'):
                return False
            return all(_check(c) for c in e.children)
        return _check(self.ir_expr)

    def vars(self) -> List[str]:
        seen: Set[str] = set()
        def _collect(e: IrExpr):
            if e.kind == 'Var':
                seen.add(e.value)
            for c in e.children:
                _collect(c)
        _collect(self.ir_expr)
        return sorted(seen)


class PassResult:
    def __init__(self, total: int, simplified: int):
        self.total = total
        self.simplified = simplified

    def simplification_rate(self) -> float:
        return self.simplified / self.total if self.total > 0 else 0.0


class PassConfig:
    def __init__(self, max_iterations: int = 10, use_z3: bool = False):
        self.max_iterations = max_iterations
        self.use_z3 = use_z3


class MbaDeobfPass:
    def __init__(self, config: Optional[PassConfig] = None):
        self._config = config or PassConfig()
        self._simplifier = MbaSimplifier.new()

    @staticmethod
    def new() -> 'MbaDeobfPass':
        return MbaDeobfPass()

    @staticmethod
    def with_config(config: PassConfig) -> 'MbaDeobfPass':
        return MbaDeobfPass(config)

    def simplify_expr(self, expr: IrExpr) -> Tuple[IrExpr, bool]:
        mba = validator_translate_ir_to_mba(expr)
        result = self._simplifier.simplify(mba)
        changed = result.reduction_ratio() > 0
        return validator_translate_mba_to_ir(result.simplified), changed

    def apply_pass_to_function(self, exprs: List[IrExpr]) -> Tuple[List[IrExpr], PassResult]:
        out = []
        simplified_count = 0
        for e in exprs:
            new_e, changed = self.simplify_expr(e)
            out.append(new_e)
            if changed:
                simplified_count += 1
        return out, PassResult(len(exprs), simplified_count)

    def verify_with_z3(self, original: IrExpr, simplified: IrExpr) -> bool:
        """Sampling-based fallback (Z3 not available in stdlib)."""
        mba_a = validator_translate_ir_to_mba(original)
        mba_b = validator_translate_ir_to_mba(simplified)
        verifier = MbaVerifier()
        return verifier.verify_equivalent(mba_a, mba_b).equivalent


# ============================================================
# mba_complexity_scorer.rs
# ============================================================

class TreeMetrics:
    def __init__(self, depth: int, node_count: int, leaf_count: int):
        self.depth = depth
        self.node_count = node_count
        self.leaf_count = leaf_count

    @staticmethod
    def of(expr: MbaExpr) -> 'TreeMetrics':
        def _stats(e: MbaExpr) -> Tuple[int, int, int]:
            if not e.children:
                return 0, 1, 1
            sub = [_stats(c) for c in e.children]
            d = 1 + max(s[0] for s in sub)
            n = 1 + sum(s[1] for s in sub)
            leaves = sum(s[2] for s in sub)
            return d, n, leaves
        d, n, lv = _stats(expr)
        return TreeMetrics(d, n, lv)


class OpProfile:
    def __init__(self, counts: Dict[str, int]):
        self.counts = counts  # op -> count

    @staticmethod
    def of(expr: MbaExpr) -> 'OpProfile':
        counts: Dict[str, int] = defaultdict(int)
        def _collect(e: MbaExpr):
            if e.kind not in ('Const', 'Var'):
                counts[e.kind] += 1
            for c in e.children:
                _collect(c)
        _collect(expr)
        return OpProfile(dict(counts))

    def distinct_ops(self) -> int:
        return len(self.counts)

    def mixing_ratio(self) -> float:
        bool_ops = {'And', 'Or', 'Xor', 'Not'}
        arith_ops = {'Add', 'Sub', 'Mul', 'Neg'}
        b = sum(v for k, v in self.counts.items() if k in bool_ops)
        a = sum(v for k, v in self.counts.items() if k in arith_ops)
        total = b + a
        return b / total if total > 0 else 0.0


class ComplexityScore:
    def __init__(self, score: float, metrics: TreeMetrics, profile: OpProfile):
        self.score = score
        self.metrics = metrics
        self.profile = profile

    @staticmethod
    def compute(expr: MbaExpr) -> 'ComplexityScore':
        m = TreeMetrics.of(expr)
        p = OpProfile.of(expr)
        mixing = p.mixing_ratio()
        score = m.node_count * (1 + mixing) * (1 + p.distinct_ops() * 0.1)
        return ComplexityScore(score, m, p)

    def is_likely_mba(self) -> bool:
        return self.score > 10 and self.profile.mixing_ratio() > 0.2

    def relative_to(self, other: 'ComplexityScore') -> float:
        return self.score / other.score if other.score != 0 else float('inf')


class ExprScoringResult:
    def __init__(self, expr: MbaExpr, score: ComplexityScore):
        self.expr = expr
        self.score = score
        self.is_mba = score.is_likely_mba()


class MbaComplexityScorer:
    @staticmethod
    def new() -> 'MbaComplexityScorer':
        return MbaComplexityScorer()

    def score(self, expr: MbaExpr) -> ExprScoringResult:
        return ExprScoringResult(expr, ComplexityScore.compute(expr))

    def score_batch(self, exprs: List[MbaExpr]) -> List[ExprScoringResult]:
        return [self.score(e) for e in exprs]

    def score_function(self, exprs: List[MbaExpr]) -> List[ExprScoringResult]:
        return self.score_batch(exprs)

    def filter_mba(self, exprs: List[MbaExpr]) -> List[ExprScoringResult]:
        return [r for r in self.score_batch(exprs) if r.is_mba]


def validator_score_function(exprs: List[MbaExpr]) -> List[ExprScoringResult]:
    return MbaComplexityScorer.new().score_function(exprs)


def validator_score_histogram(results: List[ExprScoringResult], bucket_size: int) -> Dict[int, int]:
    hist: Dict[int, int] = defaultdict(int)
    for r in results:
        bucket = int(r.score.score // bucket_size) * bucket_size
        hist[bucket] += 1
    return dict(hist)


class FunctionMbaProfile:
    def __init__(self, total: int, mba_count: int):
        self.total = total
        self.mba_count = mba_count

    def obfuscation_density(self) -> float:
        return self.mba_count / self.total if self.total > 0 else 0.0


# ============================================================
# mba_detector.rs
# ============================================================

class MbaScore:
    def __init__(self, value: float, details: Dict[str, float]):
        self.value = value
        self.details = details


class MbaAnalysis:
    def __init__(self, expr: MbaExpr, mba_type: str, score: float):
        self.expr = expr
        self.mba_type = mba_type
        self.score = score

    @staticmethod
    def analyze(expr: MbaExpr) -> 'MbaAnalysis':
        p = OpProfile.of(expr)
        mixing = p.mixing_ratio()
        n = TreeMetrics.of(expr).node_count
        if mixing > 0.4 and n > 5:
            mba_type = "mixed"
        elif mixing > 0.7:
            mba_type = "boolean_heavy"
        elif mixing < 0.1 and n > 4:
            mba_type = "linear"
        else:
            mba_type = "simple"
        score = mixing * n
        return MbaAnalysis(expr, mba_type, score)


class MbaDetectorPatternLibrary:
    def __init__(self, patterns: List[MbaPattern]):
        self._patterns = patterns

    @staticmethod
    def default_library() -> 'MbaDetectorPatternLibrary':
        lib = MbaPatternLibrary.standard()
        return MbaDetectorPatternLibrary(lib._patterns)

    def match_patterns(self, expr: MbaExpr, depth: int = 3) -> List[MbaPattern]:
        """All patterns matching up to given depth."""
        results = []
        lib = MbaPatternLibrary(self._patterns)
        p = lib.match_pattern(expr)
        if p:
            results.append(p)
        if depth > 1:
            for c in expr.children:
                results.extend(self.match_patterns(c, depth - 1))
        return results


class MbaScorer:
    @staticmethod
    def new() -> 'MbaScorer':
        return MbaScorer()

    def score(self, expr: MbaExpr) -> MbaScore:
        analysis = MbaAnalysis.analyze(expr)
        p = OpProfile.of(expr)
        details = {
            'mixing_ratio': p.mixing_ratio(),
            'node_count': float(TreeMetrics.of(expr).node_count),
            'distinct_ops': float(p.distinct_ops()),
        }
        return MbaScore(analysis.score, details)

    def batch_score(self, exprs: List[MbaExpr]) -> List[MbaScore]:
        return [self.score(e) for e in exprs]

    def top_obfuscated(self, exprs: List[MbaExpr], n: int) -> List[Tuple[MbaExpr, MbaScore]]:
        scored = [(e, self.score(e)) for e in exprs]
        scored.sort(key=lambda x: x[1].value, reverse=True)
        return scored[:n]


class MbaStatistics:
    def __init__(self, mean: float, maximum: float, distribution: Dict[str, int]):
        self.mean = mean
        self.maximum = maximum
        self.distribution = distribution

    @staticmethod
    def compute(scores: List[MbaScore]) -> 'MbaStatistics':
        if not scores:
            return MbaStatistics(0.0, 0.0, {})
        vals = [s.value for s in scores]
        mean = sum(vals) / len(vals)
        maximum = max(vals)
        buckets: Dict[str, int] = defaultdict(int)
        for v in vals:
            bucket = f"{int(v // 5) * 5}-{int(v // 5) * 5 + 4}"
            buckets[bucket] += 1
        return MbaStatistics(mean, maximum, dict(buckets))


# ============================================================
# mba_normalization.rs
# ============================================================

class MbaExprTree:
    """Alternative AST for normalization."""
    def __init__(self, kind: str, value=None, children: list = None):
        self.kind = kind
        self.value = value
        self.children = children or []

    @staticmethod
    def add(a: 'MbaExprTree', b: 'MbaExprTree') -> 'MbaExprTree':
        return MbaExprTree('Add', children=[a, b])

    @staticmethod
    def sub(a: 'MbaExprTree', b: 'MbaExprTree') -> 'MbaExprTree':
        return MbaExprTree('Sub', children=[a, b])

    @staticmethod
    def mul(a: 'MbaExprTree', b: 'MbaExprTree') -> 'MbaExprTree':
        return MbaExprTree('Mul', children=[a, b])

    @staticmethod
    def neg(a: 'MbaExprTree') -> 'MbaExprTree':
        return MbaExprTree('Neg', children=[a])

    @staticmethod
    def and_(a: 'MbaExprTree', b: 'MbaExprTree') -> 'MbaExprTree':
        return MbaExprTree('And', children=[a, b])

    @staticmethod
    def or_(a: 'MbaExprTree', b: 'MbaExprTree') -> 'MbaExprTree':
        return MbaExprTree('Or', children=[a, b])

    @staticmethod
    def xor(a: 'MbaExprTree', b: 'MbaExprTree') -> 'MbaExprTree':
        return MbaExprTree('Xor', children=[a, b])

    @staticmethod
    def not_(a: 'MbaExprTree') -> 'MbaExprTree':
        return MbaExprTree('Not', children=[a])

    def node_count(self) -> int:
        return 1 + sum(c.node_count() for c in self.children)

    def depth(self) -> int:
        if not self.children:
            return 0
        return 1 + max(c.depth() for c in self.children)

    def vars(self) -> List[str]:
        seen: Set[str] = set()
        def _col(e: 'MbaExprTree'):
            if e.kind == 'Var':
                seen.add(e.value)
            for c in e.children:
                _col(c)
        _col(self)
        return sorted(seen)

    def eval(self, env: Dict[str, int]) -> Optional[int]:
        if self.kind == 'Const': return self.value
        if self.kind == 'Var':   return env.get(self.value)
        vals = [c.eval(env) for c in self.children]
        if any(v is None for v in vals): return None
        a = vals[0]; b = vals[1] if len(vals) > 1 else None
        if self.kind == 'Add': return a + b
        if self.kind == 'Sub': return a - b
        if self.kind == 'Mul': return a * b
        if self.kind == 'Neg': return -a
        if self.kind == 'And': return a & b
        if self.kind == 'Or':  return a | b
        if self.kind == 'Xor': return a ^ b
        if self.kind == 'Not': return ~a
        return None


class StructuralSimplifier:
    @staticmethod
    def new() -> 'StructuralSimplifier':
        return StructuralSimplifier()

    def apply_once(self, expr: MbaExprTree) -> Optional[Tuple[MbaExprTree, str]]:
        # simple structural rules
        if expr.kind == 'Add' and expr.children[1].kind == 'Const' and expr.children[1].value == 0:
            return expr.children[0], "add_zero"
        if expr.kind == 'Sub' and expr.children[1].kind == 'Const' and expr.children[1].value == 0:
            return expr.children[0], "sub_zero"
        if expr.kind == 'Not' and expr.children[0].kind == 'Not':
            return expr.children[0].children[0], "not_not"
        if expr.kind == 'Neg' and expr.children[0].kind == 'Neg':
            return expr.children[0].children[0], "neg_neg"
        return None

    def simplify(self, expr: MbaExprTree) -> Tuple[MbaExprTree, List[str]]:
        rules: List[str] = []
        current = expr
        for _ in range(50):
            result = self.apply_once(current)
            if result is None:
                break
            current, rule = result
            rules.append(rule)
        return current, rules


class ConstantPropagator:
    def __init__(self):
        self._bindings: Dict[str, int] = {}

    @staticmethod
    def new() -> 'ConstantPropagator':
        return ConstantPropagator()

    def bind(self, var: str, value: int) -> None:
        self._bindings[var] = value

    def propagate(self, expr: MbaExprTree) -> MbaExprTree:
        if expr.kind == 'Var' and expr.value in self._bindings:
            return MbaExprTree('Const', self._bindings[expr.value])
        new_children = [self.propagate(c) for c in expr.children]
        node = MbaExprTree(expr.kind, expr.value, new_children)
        # fold constants
        if node.kind in ('Add', 'Sub', 'Mul', 'And', 'Or', 'Xor') and \
                all(c.kind == 'Const' for c in node.children):
            a, b = node.children[0].value, node.children[1].value
            ops = {'Add': a+b, 'Sub': a-b, 'Mul': a*b, 'And': a&b, 'Or': a|b, 'Xor': a^b}
            return MbaExprTree('Const', ops[node.kind])
        if node.kind in ('Neg', 'Not') and node.children[0].kind == 'Const':
            v = -node.children[0].value if node.kind == 'Neg' else ~node.children[0].value
            return MbaExprTree('Const', v)
        return node


class NormalForm:
    def __init__(self, expr: MbaExprTree, form_type: str = "canonical"):
        self.expr = expr
        self.form_type = form_type


class NormalFormConverter:
    def __init__(self, expr: MbaExprTree):
        self.expr = expr
        self._form = NormalForm(expr)

    @staticmethod
    def from_expr(expr: MbaExprTree) -> 'NormalFormConverter':
        return NormalFormConverter(expr)


class EquivalenceChecker:
    @staticmethod
    def new() -> 'EquivalenceChecker':
        return EquivalenceChecker()

    def check_equivalent(self, a: MbaExprTree, b: MbaExprTree, samples: int = 32) -> bool:
        var_names = sorted(set(a.vars()) | set(b.vars()))
        for _ in range(samples):
            env = {v: random.randint(-64, 63) for v in var_names}
            if a.eval(env) != b.eval(env):
                return False
        return True

    def is_constant(self, expr: MbaExprTree) -> bool:
        if expr.kind == 'Const':
            return True
        if expr.kind == 'Var':
            return False
        return all(self.is_constant(c) for c in expr.children)


class ExprComplexityMetrics:
    def __init__(self, node_count: int, depth: int, mixing: float):
        self.node_count = node_count
        self.depth = depth
        self.mixing = mixing

    @staticmethod
    def compute(expr: MbaExprTree) -> 'ExprComplexityMetrics':
        nc = expr.node_count()
        d = expr.depth()
        mba = MbaExpr(expr.kind, expr.value, [])
        mba_full = _tree_to_mba(expr)
        mixing = OpProfile.of(mba_full).mixing_ratio()
        return ExprComplexityMetrics(nc, d, mixing)

    def complexity_score(self) -> float:
        return self.node_count * (1 + self.mixing) * (1 + self.depth * 0.1)


def _tree_to_mba(t: MbaExprTree) -> MbaExpr:
    return MbaExpr(t.kind, t.value, [_tree_to_mba(c) for c in t.children])


class NormalizationResult:
    def __init__(self, modified: bool, rules: List[str]):
        self.modified = modified
        self.rules = rules


class MbaNormalizer:
    def __init__(self):
        self._propagator = ConstantPropagator.new()
        self._struct = StructuralSimplifier.new()

    @staticmethod
    def new() -> 'MbaNormalizer':
        return MbaNormalizer()

    def bind(self, var: str, value: int) -> None:
        self._propagator.bind(var, value)

    def normalize(self, expr: MbaExprTree) -> Tuple[NormalForm, bool, List[str]]:
        propagated = self._propagator.propagate(expr)
        simplified, rules = self._struct.simplify(propagated)
        modified = simplified.node_count() != expr.node_count()
        return NormalForm(simplified), modified, rules

    def complexity_ratio(self, original: MbaExprTree, simplified: MbaExprTree) -> float:
        o = original.node_count()
        s = simplified.node_count()
        return s / o if o > 0 else 1.0


# ============================================================
# mba_oracle.rs
# ============================================================

def validator_eval_masked(expr: MbaExpr, env: Dict[str, int], mask: int) -> Optional[int]:
    """Evaluate expression with bit mask for modular arithmetic."""
    v = expr.eval(env)
    return v & mask if v is not None else None


def validator_standard_templates() -> List['SynthesisTemplate']:
    return [
        SynthesisTemplate("zero",    MbaExpr('Const', 0),     []),
        SynthesisTemplate("identity",MbaExpr('Var', 'x'),     ['x']),
        SynthesisTemplate("neg_x",   MbaExpr.mk_neg(MbaExpr('Var', 'x')), ['x']),
        SynthesisTemplate("not_x",   MbaExpr.mk_not(MbaExpr('Var', 'x')), ['x']),
        SynthesisTemplate("x_plus_y",MbaExpr.mk_add(MbaExpr('Var','x'), MbaExpr('Var','y')), ['x','y']),
        SynthesisTemplate("x_xor_y", MbaExpr.mk_xor(MbaExpr('Var','x'), MbaExpr('Var','y')), ['x','y']),
        SynthesisTemplate("x_and_y", MbaExpr.mk_and(MbaExpr('Var','x'), MbaExpr('Var','y')), ['x','y']),
        SynthesisTemplate("x_or_y",  MbaExpr.mk_or(MbaExpr('Var','x'),  MbaExpr('Var','y')), ['x','y']),
    ]


class SynthesisTemplate:
    def __init__(self, name: str, expr: MbaExpr, variables: List[str]):
        self.name = name
        self.expr = expr
        self.variables = variables

    def sample(self, n_samples: int = 16) -> List[int]:
        results = []
        for _ in range(n_samples):
            env = {v: random.randint(-64, 63) for v in self.variables}
            v = self.expr.eval(env)
            if v is not None:
                results.append(v)
        return results

    def matches(self, candidate: MbaExpr) -> bool:
        if not self.variables:
            return (candidate.kind == 'Const' and candidate.value == self.expr.eval({}))
        for _ in range(32):
            env = {v: random.randint(-64, 63) for v in self.variables}
            cv = candidate.eval(env)
            tv = self.expr.eval(env)
            if cv != tv:
                return False
        return True


class OracleConfig:
    def __init__(self, samples: int = 32, mask: int = 0xFFFF):
        self.samples = samples
        self.mask = mask


class OracleResult:
    def __init__(self, original: MbaExpr, simplified: MbaExpr, template_name: str, confidence: float):
        self.original = original
        self.simplified = simplified
        self.template_name = template_name
        self.confidence = confidence


class MbaOracle:
    def __init__(self, config: OracleConfig):
        self._config = config
        self._templates = validator_standard_templates()

    @staticmethod
    def new(config: OracleConfig) -> 'MbaOracle':
        return MbaOracle(config)

    def add_template(self, t: SynthesisTemplate) -> None:
        self._templates.append(t)

    def simplify(self, expr: MbaExpr, variables: List[str]) -> Optional[OracleResult]:
        for t in self._templates:
            if set(t.variables) == set(variables) or not t.variables:
                if t.matches(expr):
                    return OracleResult(expr, t.expr, t.name, 0.95)
        return None

    def simplify_batch(self, exprs: List[MbaExpr], variables: List[str]) -> List[Optional[OracleResult]]:
        return [self.simplify(e, variables) for e in exprs]

    def confidence_score(self, result: OracleResult) -> float:
        return result.confidence


# ============================================================
# mba_rewriter.rs
# ============================================================

class RewriteRule:
    def __init__(self, name: str, from_pattern: str, to_pattern: str, verifier=None):
        self.name = name
        self.from_pattern = from_pattern
        self.to_pattern = to_pattern
        self._verifier = verifier

    @staticmethod
    def new(name: str, from_pattern: str, to_pattern: str, verifier=None) -> 'RewriteRule':
        return RewriteRule(name, from_pattern, to_pattern, verifier)

    def apply(self, expr: MbaExpr) -> Optional[MbaExpr]:
        """Structural matching — only handles simple constant-folding/identity rules."""
        simplifier = MbaSimplifier.new()
        result = simplifier.try_rules(expr)
        if result and result[1] == self.name:
            return result[0]
        return None


def validator_standard_rewrite_rules() -> List[RewriteRule]:
    return [RewriteRule(r.name, r.pattern, r.replacement) for r in build_rule_database()]


def validator_apply_rewrite(expr: MbaExpr) -> Optional['SimplifiedExpr']:
    simplifier = MbaSimplifier.new()
    result = simplifier.try_rules(expr)
    if result:
        return SimplifiedExpr(result[0], result[1])
    return None


class SimplifiedExpr:
    def __init__(self, expr: MbaExpr, rule_name: str):
        self.expr = expr
        self.rule_name = rule_name


class RewriteStep:
    def __init__(self, rule_name: str, before: MbaExpr, after: MbaExpr):
        self.rule_name = rule_name
        self.before = before
        self.after = after


class RewriteResult:
    def __init__(self, original: MbaExpr, rewritten: MbaExpr, steps: List[RewriteStep]):
        self.original = original
        self.rewritten = rewritten
        self.steps = steps


class MbaRewriter:
    def __init__(self, rules: Optional[List[RewriteRule]] = None):
        self._rules = rules or validator_standard_rewrite_rules()
        self._cache: Dict[int, MbaExpr] = {}

    @staticmethod
    def new() -> 'MbaRewriter':
        return MbaRewriter()

    @staticmethod
    def with_rules(rules: List[RewriteRule]) -> 'MbaRewriter':
        return MbaRewriter(rules)

    def rewrite(self, expr: MbaExpr) -> RewriteResult:
        steps = []
        current = expr
        for _ in range(50):
            new_expr, new_steps = self.single_pass(current)
            if not new_steps:
                break
            steps.extend(new_steps)
            current = new_expr
        return RewriteResult(expr, current, steps)

    def single_pass(self, expr: MbaExpr) -> Tuple[MbaExpr, List[RewriteStep]]:
        simplifier = MbaSimplifier.new()
        new_expr, rules = simplifier.apply_rules_bottomup(expr)
        steps = [RewriteStep(r, expr, new_expr) for r in rules]
        return new_expr, steps

    def rewrite_cached(self, expr: MbaExpr) -> MbaExpr:
        key = id(expr)
        if key in self._cache:
            return self._cache[key]
        result = self.rewrite(expr).rewritten
        self._cache[key] = result
        return result

    def apply_rule(self, name: str, expr: MbaExpr) -> Optional[MbaExpr]:
        rule = next((r for r in self._rules if r.name == name), None)
        if rule is None:
            return None
        return rule.apply(expr)


# ============================================================
# mba_simplifier.rs — Truth table-based simplifier
# ============================================================

class TruthTable:
    def __init__(self, entries: List[int]):
        self.entries = entries  # list of output values

    @staticmethod
    def build(expr: MbaExpr, var_names: List[str]) -> 'TruthTable':
        n = len(var_names)
        entries = []
        for i in range(2 ** n):
            env = {}
            for j, v in enumerate(var_names):
                env[v] = (i >> j) & 1
            entries.append(expr.eval(env) or 0)
        return TruthTable(entries)

    @staticmethod
    def build_masked(expr: MbaExpr, var_names: List[str], mask: int) -> 'TruthTable':
        tt = TruthTable.build(expr, var_names)
        tt.entries = [v & mask for v in tt.entries]
        return tt

    def matches(self, other: 'TruthTable') -> bool:
        return self.entries == other.entries

    def as_u8_key(self) -> int:
        result = 0
        for i, v in enumerate(self.entries[:8]):
            if v:
                result |= (1 << i)
        return result & 0xFF


def validator_standard_rules_tt() -> List[RewriteRule]:
    return validator_standard_rewrite_rules()


class TruthTableVerifier:
    def check(self, a: MbaExpr, b: MbaExpr) -> bool:
        var_names = sorted(set(a.vars()) | set(b.vars()))
        if len(var_names) > 8:
            var_names = var_names[:8]
        tt_a = TruthTable.build(a, var_names)
        tt_b = TruthTable.build(b, var_names)
        return tt_a.matches(tt_b)


class SimplifyResult:
    def __init__(self, original: MbaExpr, simplified: MbaExpr, rules: List[str]):
        self.original = original
        self.simplified = simplified
        self.rules = rules


class MbaExprSimplifier:
    @staticmethod
    def new() -> 'MbaExprSimplifier':
        return MbaExprSimplifier()

    def simplify(self, expr: MbaExpr) -> SimplifyResult:
        result = MbaSimplifier.new().simplify(expr)
        return SimplifyResult(expr, result.simplified, result.rules_applied)

    def apply_rules_once(self, expr: MbaExpr) -> Tuple[MbaExpr, List[str]]:
        return MbaSimplifier.new().apply_rules_bottomup(expr)

    def truth_table_simplify(self, expr: MbaExpr) -> Optional[MbaExpr]:
        """Try to find a simpler equivalent via truth table lookup."""
        var_names = expr.vars()
        if len(var_names) > 3:
            return None
        tt = TruthTable.build(expr, var_names)
        # try simple expressions
        candidates = [
            MbaExpr('Const', 0),
            MbaExpr('Const', 1),
        ]
        if var_names:
            candidates.append(MbaExpr('Var', var_names[0]))
            candidates.append(MbaExpr.mk_not(MbaExpr('Var', var_names[0])))
        for c in candidates:
            c_tt = TruthTable.build(c, var_names)
            if tt.matches(c_tt) and c.complexity() < expr.complexity():
                return c
        return None


# ============================================================
# mba_simplification.rs — High-level pipeline
# ============================================================

class MbaExprResult:
    def __init__(self, original_text: str, simplified: MbaExpr, ratio: float):
        self.original_text = original_text
        self.simplified = simplified
        self.ratio = ratio

    @staticmethod
    def from_simplification(original_text: str, result: SimplificationResult) -> 'MbaExprResult':
        return MbaExprResult(original_text, result.simplified, result.reduction_ratio())


class MbaReport:
    def __init__(self, results: List[MbaExprResult]):
        self.results = results

    @staticmethod
    def from_results(results: List[MbaExprResult]) -> 'MbaReport':
        return MbaReport(results)

    def markdown_summary(self) -> str:
        lines = ["# MBA Simplification Report", ""]
        for r in self.results:
            lines.append(f"- `{r.original_text}` → reduction {r.ratio:.1%}")
        return "\n".join(lines)


class SimbaResult:
    def __init__(self, original: str, simplified: MbaExpr, ratio: float):
        self.original = original
        self.simplified = simplified
        self.ratio = ratio


class SimbaSimplifier:
    @staticmethod
    def new() -> 'SimbaSimplifier':
        return SimbaSimplifier()

    def simplify(self, expr_text: str) -> SimbaResult:
        try:
            expr = MbaExpr.parse(expr_text)
        except Exception as e:
            raise ValueError(str(e))
        result = MbaSimplifier.new().simplify(expr)
        return SimbaResult(expr_text, result.simplified, result.reduction_ratio())


class VerifiedSimplification:
    def __init__(self, original: MbaExpr, simplified: MbaExpr, verified: bool, ratio: float):
        self.original = original
        self.simplified = simplified
        self.verified = verified
        self.ratio = ratio


class MbaPipeline:
    def __init__(self):
        self._simplifier = MbaSimplifier.new()
        self._verifier = MbaVerifier()

    @staticmethod
    def new() -> 'MbaPipeline':
        return MbaPipeline()

    def simplify_text(self, expr_text: str) -> VerifiedSimplification:
        try:
            expr = MbaExpr.parse(expr_text)
        except Exception as e:
            raise ValueError(str(e))
        result = self._simplifier.simplify(expr)
        verified = self._verifier.verify_equivalent(expr, result.simplified).equivalent
        return VerifiedSimplification(expr, result.simplified, verified, result.reduction_ratio())

    def simplify_batch(self, expressions: List[str]) -> MbaReport:
        results = []
        for t in expressions:
            try:
                vs = self.simplify_text(t)
                results.append(MbaExprResult(t, vs.simplified, vs.ratio))
            except Exception:
                pass
        return MbaReport.from_results(results)

    def simplify_and_filter(self, expressions: List[str]) -> List[VerifiedSimplification]:
        return [vs for t in expressions
                for vs in [self._try_simplify(t)] if vs and vs.ratio > 0]

    def _try_simplify(self, t: str) -> Optional[VerifiedSimplification]:
        try:
            return self.simplify_text(t)
        except Exception:
            return None

    def verify_identity(self, lhs_text: str, rhs_text: str) -> Optional[bool]:
        try:
            lhs = MbaExpr.parse(lhs_text)
            rhs = MbaExpr.parse(rhs_text)
            result = self._verifier.verify_equivalent(lhs, rhs)
            return result.equivalent
        except Exception:
            return None


class CachedMbaPipeline:
    def __init__(self):
        self._pipeline = MbaPipeline.new()
        self._cache: Dict[str, VerifiedSimplification] = {}

    @staticmethod
    def new() -> 'CachedMbaPipeline':
        return CachedMbaPipeline()

    def simplify(self, expr_text: str) -> VerifiedSimplification:
        if expr_text not in self._cache:
            self._cache[expr_text] = self._pipeline.simplify_text(expr_text)
        return self._cache[expr_text]

    def cache_size(self) -> int:
        return len(self._cache)

    def clear_cache(self) -> None:
        self._cache.clear()


# ============================================================
# boolean_algebra_simplifier.rs
# ============================================================

class BoolExpr:
    def __init__(self, kind: str, value=None, children: list = None):
        self.kind = kind
        self.value = value
        self.children = children or []

    @staticmethod
    def not_(e: 'BoolExpr') -> 'BoolExpr':
        return BoolExpr('Not', children=[e])

    @staticmethod
    def and_(l: 'BoolExpr', r: 'BoolExpr') -> 'BoolExpr':
        return BoolExpr('And', children=[l, r])

    @staticmethod
    def or_(l: 'BoolExpr', r: 'BoolExpr') -> 'BoolExpr':
        return BoolExpr('Or', children=[l, r])

    @staticmethod
    def xor(l: 'BoolExpr', r: 'BoolExpr') -> 'BoolExpr':
        return BoolExpr('Xor', children=[l, r])

    @staticmethod
    def var(name: str) -> 'BoolExpr':
        return BoolExpr('Var', name)

    def complexity(self) -> int:
        return 1 + sum(c.complexity() for c in self.children)

    def vars(self) -> List[str]:
        seen: Set[str] = set()
        def _col(e: 'BoolExpr'):
            if e.kind == 'Var': seen.add(e.value)
            for c in e.children: _col(c)
        _col(self)
        return sorted(seen)

    def eval(self, env: Dict[str, bool]) -> Optional[bool]:
        if self.kind == 'Const': return bool(self.value)
        if self.kind == 'Var':   return env.get(self.value)
        vals = [c.eval(env) for c in self.children]
        if any(v is None for v in vals): return None
        a = vals[0]; b = vals[1] if len(vals) > 1 else None
        if self.kind == 'Not': return not a
        if self.kind == 'And': return a and b
        if self.kind == 'Or':  return a or b
        if self.kind == 'Xor': return a ^ b
        return None


class BoolSimplResult:
    def __init__(self, original: BoolExpr, simplified: BoolExpr, rules: List[str]):
        self.original = original
        self.simplified = simplified
        self.rules = rules


class BoolSimplifier:
    @staticmethod
    def new() -> 'BoolSimplifier':
        return BoolSimplifier()

    def _try_rule(self, expr: BoolExpr) -> Optional[Tuple[BoolExpr, str]]:
        if expr.kind == 'Not' and expr.children[0].kind == 'Not':
            return expr.children[0].children[0], "not_not"
        if expr.kind == 'And':
            l, r = expr.children
            if l.kind == 'Var' and r.kind == 'Var' and l.value == r.value:
                return l, "and_self"
        if expr.kind == 'Or':
            l, r = expr.children
            if l.kind == 'Var' and r.kind == 'Var' and l.value == r.value:
                return l, "or_self"
        if expr.kind == 'Xor':
            l, r = expr.children
            if l.kind == 'Var' and r.kind == 'Var' and l.value == r.value:
                return BoolExpr('Const', False), "xor_self"
        if expr.kind == 'And':
            l, r = expr.children
            if l.kind == 'Const' and l.value == False:
                return BoolExpr('Const', False), "and_false_l"
            if r.kind == 'Const' and r.value == False:
                return BoolExpr('Const', False), "and_false_r"
        if expr.kind == 'Or':
            l, r = expr.children
            if l.kind == 'Const' and l.value == True:
                return BoolExpr('Const', True), "or_true_l"
            if r.kind == 'Const' and r.value == True:
                return BoolExpr('Const', True), "or_true_r"
        return None

    def _simplify_node(self, expr: BoolExpr) -> Tuple[BoolExpr, List[str]]:
        new_ch = []
        rules = []
        for c in expr.children:
            nc, r = self._simplify_node(c)
            new_ch.append(nc)
            rules.extend(r)
        node = BoolExpr(expr.kind, expr.value, new_ch)
        res = self._try_rule(node)
        if res:
            node, rule = res
            rules.append(rule)
        return node, rules

    def simplify(self, expr: BoolExpr) -> BoolSimplResult:
        current = expr
        all_rules: List[str] = []
        for _ in range(50):
            next_e, rules = self._simplify_node(current)
            if not rules:
                break
            all_rules.extend(rules)
            current = next_e
        return BoolSimplResult(expr, current, all_rules)

    def simplify_once(self, expr: BoolExpr) -> BoolSimplResult:
        simplified, rules = self._simplify_node(expr)
        return BoolSimplResult(expr, simplified, rules)


def validator_convert_to_normal_form(expr: BoolExpr, form: str) -> BoolExpr:
    if form == 'NNF': return validator_to_nnf(expr)
    if form == 'DNF': return validator_to_dnf(expr)
    if form == 'CNF': return validator_to_cnf(expr)
    return expr


def validator_to_nnf(expr: BoolExpr) -> BoolExpr:
    """Push Not inward (Negation Normal Form)."""
    if expr.kind == 'Not':
        inner = expr.children[0]
        if inner.kind == 'Not':
            return validator_to_nnf(inner.children[0])
        if inner.kind == 'And':
            return BoolExpr.or_(validator_to_nnf(BoolExpr.not_(inner.children[0])),
                                 validator_to_nnf(BoolExpr.not_(inner.children[1])))
        if inner.kind == 'Or':
            return BoolExpr.and_(validator_to_nnf(BoolExpr.not_(inner.children[0])),
                                  validator_to_nnf(BoolExpr.not_(inner.children[1])))
    return BoolExpr(expr.kind, expr.value, [validator_to_nnf(c) for c in expr.children])


def validator_to_dnf(expr: BoolExpr) -> BoolExpr:
    nnf = validator_to_nnf(expr)
    return _distribute_or_over_and(nnf)


def _distribute_or_over_and(expr: BoolExpr) -> BoolExpr:
    if expr.kind == 'And':
        l = _distribute_or_over_and(expr.children[0])
        r = _distribute_or_over_and(expr.children[1])
        if l.kind == 'Or':
            return BoolExpr.or_(_distribute_or_over_and(BoolExpr.and_(l.children[0], r)),
                                 _distribute_or_over_and(BoolExpr.and_(l.children[1], r)))
        if r.kind == 'Or':
            return BoolExpr.or_(_distribute_or_over_and(BoolExpr.and_(l, r.children[0])),
                                 _distribute_or_over_and(BoolExpr.and_(l, r.children[1])))
        return BoolExpr.and_(l, r)
    if expr.kind == 'Or':
        return BoolExpr.or_(_distribute_or_over_and(expr.children[0]),
                             _distribute_or_over_and(expr.children[1]))
    return expr


def validator_to_cnf(expr: BoolExpr) -> BoolExpr:
    nnf = validator_to_nnf(expr)
    return _distribute_and_over_or(nnf)


def _distribute_and_over_or(expr: BoolExpr) -> BoolExpr:
    if expr.kind == 'Or':
        l = _distribute_and_over_or(expr.children[0])
        r = _distribute_and_over_or(expr.children[1])
        if l.kind == 'And':
            return BoolExpr.and_(_distribute_and_over_or(BoolExpr.or_(l.children[0], r)),
                                  _distribute_and_over_or(BoolExpr.or_(l.children[1], r)))
        if r.kind == 'And':
            return BoolExpr.and_(_distribute_and_over_or(BoolExpr.or_(l, r.children[0])),
                                  _distribute_and_over_or(BoolExpr.or_(l, r.children[1])))
        return BoolExpr.or_(l, r)
    if expr.kind == 'And':
        return BoolExpr.and_(_distribute_and_over_or(expr.children[0]),
                              _distribute_and_over_or(expr.children[1]))
    return expr


class BoolEquivResult:
    def __init__(self, equivalent: bool, counterexample: Optional[Dict[str, bool]] = None):
        self.equivalent = equivalent
        self.counterexample = counterexample


def validator_bool_exprs_equivalent(a: BoolExpr, b: BoolExpr) -> BoolEquivResult:
    var_names = sorted(set(a.vars()) | set(b.vars()))
    for i in range(2 ** len(var_names)):
        env = {v: bool((i >> j) & 1) for j, v in enumerate(var_names)}
        if a.eval(env) != b.eval(env):
            return BoolEquivResult(False, env)
    return BoolEquivResult(True)


def validator_bool_exprs_equivalent_strict(a: BoolExpr, b: BoolExpr) -> bool:
    return validator_bool_exprs_equivalent(a, b).equivalent


# ============================================================
# boolean_normalization.rs
# ============================================================

class Literal:
    def __init__(self, var: str, positive: bool):
        self.var = var
        self.positive = positive

    @staticmethod
    def pos(var: str) -> 'Literal':
        return Literal(var, True)

    @staticmethod
    def neg(var: str) -> 'Literal':
        return Literal(var, False)

    def negate(self) -> 'Literal':
        return Literal(self.var, not self.positive)

    def display(self) -> str:
        return self.var if self.positive else f"~{self.var}"


class Clause:
    def __init__(self, literals: List[Literal]):
        self.literals = literals

    @staticmethod
    def unit(lit: Literal) -> 'Clause':
        return Clause([lit])

    def is_tautology(self) -> bool:
        vars_pos = {l.var for l in self.literals if l.positive}
        vars_neg = {l.var for l in self.literals if not l.positive}
        return bool(vars_pos & vars_neg)

    def display(self) -> str:
        return " | ".join(l.display() for l in self.literals)


class CnfFormula:
    def __init__(self, clauses: List[Clause]):
        self.clauses = clauses

    def simplify(self) -> None:
        self.clauses = [c for c in self.clauses if not c.is_tautology()]

    def display(self) -> str:
        return " & ".join(f"({c.display()})" for c in self.clauses)


class DnfFormula:
    def __init__(self, terms: List[List[Literal]]):
        self.terms = terms  # list of conjunctions

    def display(self) -> str:
        parts = []
        for term in self.terms:
            parts.append(" & ".join(l.display() for l in term))
        return " | ".join(f"({p})" for p in parts)

    def eval(self, assignment: Dict[str, bool]) -> bool:
        for term in self.terms:
            if all((assignment.get(l.var, False) == l.positive) for l in term):
                return True
        return False

    def size(self) -> int:
        return len(self.terms)


class TruthTableMatrix:
    def __init__(self, rows: List[Tuple[Dict[str, int], int]]):
        self.rows = rows

    @staticmethod
    def from_expr(expr: MbaExpr, variable_order: List[str]) -> 'TruthTableMatrix':
        rows = []
        n = len(variable_order)
        for i in range(2 ** n):
            env = {v: (i >> j) & 1 for j, v in enumerate(variable_order)}
            val = expr.eval(env) or 0
            rows.append((env, val))
        return TruthTableMatrix(rows)


def validator_mba_to_nnf(expr: MbaExpr) -> MbaExpr:
    """Push Not inward on MbaExpr (boolean part only)."""
    if expr.kind == 'Not':
        inner = expr.children[0]
        if inner.kind == 'Not':
            return validator_mba_to_nnf(inner.children[0])
        if inner.kind == 'And':
            return MbaExpr.mk_or(validator_mba_to_nnf(MbaExpr.mk_not(inner.children[0])),
                                  validator_mba_to_nnf(MbaExpr.mk_not(inner.children[1])))
        if inner.kind == 'Or':
            return MbaExpr.mk_and(validator_mba_to_nnf(MbaExpr.mk_not(inner.children[0])),
                                   validator_mba_to_nnf(MbaExpr.mk_not(inner.children[1])))
    return MbaExpr(expr.kind, expr.value, [validator_mba_to_nnf(c) for c in expr.children])


def validator_nnf_to_cnf(expr: MbaExpr) -> CnfFormula:
    """Convert NNF MbaExpr to CNF formula (boolean only)."""
    clauses: List[Clause] = []
    def _to_cnf(e: MbaExpr) -> List[Clause]:
        if e.kind == 'Var':
            return [Clause([Literal.pos(e.value)])]
        if e.kind == 'Not' and e.children[0].kind == 'Var':
            return [Clause([Literal.neg(e.children[0].value)])]
        if e.kind == 'And':
            return _to_cnf(e.children[0]) + _to_cnf(e.children[1])
        if e.kind == 'Or':
            lits_l = [l for c in _to_cnf(e.children[0]) for l in c.literals]
            lits_r = [l for c in _to_cnf(e.children[1]) for l in c.literals]
            return [Clause(lits_l + lits_r)]
        return []
    clauses = _to_cnf(expr)
    return CnfFormula(clauses)


def validator_nnf_to_dnf(expr: MbaExpr) -> DnfFormula:
    """Convert NNF MbaExpr to DNF formula."""
    def _to_dnf(e: MbaExpr) -> List[List[Literal]]:
        if e.kind == 'Var':
            return [[Literal.pos(e.value)]]
        if e.kind == 'Not' and e.children[0].kind == 'Var':
            return [[Literal.neg(e.children[0].value)]]
        if e.kind == 'Or':
            return _to_dnf(e.children[0]) + _to_dnf(e.children[1])
        if e.kind == 'And':
            l_terms = _to_dnf(e.children[0])
            r_terms = _to_dnf(e.children[1])
            return [lt + rt for lt in l_terms for rt in r_terms]
        return []
    return DnfFormula(_to_dnf(expr))


def validator_split_xor(expr: MbaExpr) -> MbaExpr:
    """Expand Xor: a^b -> (a|b)&~(a&b)."""
    if expr.kind == 'Xor':
        a, b = expr.children
        a2 = validator_split_xor(a)
        b2 = validator_split_xor(b)
        return MbaExpr.mk_and(MbaExpr.mk_or(a2, b2),
                               MbaExpr.mk_not(MbaExpr.mk_and(a2, b2)))
    return MbaExpr(expr.kind, expr.value, [validator_split_xor(c) for c in expr.children])


def validator_balance_and_or(expr: MbaExpr) -> MbaExpr:
    """Balance And/Or chains into balanced trees."""
    if expr.kind not in ('And', 'Or'):
        return MbaExpr(expr.kind, expr.value, [validator_balance_and_or(c) for c in expr.children])
    # Collect all operands of same op
    def _flatten(e: MbaExpr, op: str) -> List[MbaExpr]:
        if e.kind == op:
            return _flatten(e.children[0], op) + _flatten(e.children[1], op)
        return [e]
    operands = _flatten(expr, expr.kind)
    def _build(ops: List[MbaExpr], op: str) -> MbaExpr:
        if len(ops) == 1: return ops[0]
        mid = len(ops) // 2
        l = _build(ops[:mid], op)
        r = _build(ops[mid:], op)
        return MbaExpr(op, None, [l, r])
    return _build([validator_balance_and_or(o) for o in operands], expr.kind)


class BoolNormalizationResult:
    def __init__(self, rules: List[str], modified: bool):
        self.rules = rules
        self.modified = modified


class BoolNormalizer:
    @staticmethod
    def normalize(expr: MbaExpr) -> Tuple[MbaExpr, BoolNormalizationResult]:
        # NNF -> split xor -> balance
        rules = []
        nnf = validator_mba_to_nnf(expr)
        if nnf.complexity() != expr.complexity():
            rules.append("nnf")
        split = validator_split_xor(nnf)
        if split.complexity() != nnf.complexity():
            rules.append("split_xor")
        balanced = validator_balance_and_or(split)
        if balanced.complexity() != split.complexity():
            rules.append("balance")
        modified = balanced.complexity() != expr.complexity()
        return balanced, BoolNormalizationResult(rules, modified)


# ============================================================
# bitwise_arithmetic_folder.rs
# ============================================================

class FoldRule:
    def __init__(self, name: str):
        self.name = name


def validator_all_fold_rules() -> List[FoldRule]:
    names = [
        "const_fold_add", "const_fold_sub", "const_fold_mul",
        "const_fold_and", "const_fold_or", "const_fold_xor",
        "const_fold_neg", "const_fold_not",
        "add_zero", "sub_zero", "mul_one", "mul_zero",
        "and_zero", "and_all_ones", "or_zero", "or_all_ones",
        "xor_zero", "xor_self", "and_self", "or_self",
        "not_not", "neg_neg",
    ]
    return [FoldRule(n) for n in names]


class FoldResult:
    def __init__(self, original: MbaExpr, folded: MbaExpr, rules: List[str]):
        self.original = original
        self.folded = folded
        self.rules = rules


class BitwiseArithmeticFolder:
    @staticmethod
    def new() -> 'BitwiseArithmeticFolder':
        return BitwiseArithmeticFolder()

    def fold(self, expr: MbaExpr) -> FoldResult:
        current = expr
        all_rules: List[str] = []
        for _ in range(50):
            new_e, rules = self.fold_pass(current)
            if not rules:
                break
            all_rules.extend(rules)
            current = new_e
        return FoldResult(expr, current, all_rules)

    def fold_pass(self, expr: MbaExpr) -> Tuple[MbaExpr, List[str]]:
        return MbaSimplifier.new().apply_rules_bottomup(expr)

    def fold_constants_only(self, expr: MbaExpr) -> MbaExpr:
        """Only constant folding, no identity rules."""
        new_children = [self.fold_constants_only(c) for c in expr.children]
        node = MbaExpr(expr.kind, expr.value, new_children)
        if node.kind in ('Add','Sub','Mul','And','Or','Xor') and all(c.kind=='Const' for c in node.children):
            a, b = node.children[0].value, node.children[1].value
            ops = {'Add': a+b,'Sub': a-b,'Mul': a*b,'And': a&b,'Or': a|b,'Xor': a^b}
            return MbaExpr('Const', ops[node.kind])
        if node.kind in ('Neg','Not') and node.children[0].kind == 'Const':
            v = -node.children[0].value if node.kind == 'Neg' else ~node.children[0].value
            return MbaExpr('Const', v)
        return node


# ============================================================
# nonlinear_mba_solver.rs
# ============================================================

class Monomial:
    def __init__(self, vars_: Dict[str, int], coeff: int):
        # vars_: var -> power
        self.vars_ = vars_
        self.coeff = coeff

    @staticmethod
    def var(name: str, coeff: int) -> 'Monomial':
        return Monomial({name: 1}, coeff)

    def degree(self) -> int:
        return sum(self.vars_.values())

    def eval(self, vals: Dict[str, int]) -> int:
        result = self.coeff
        for v, power in self.vars_.items():
            result *= vals.get(v, 0) ** power
        return result

    def monomial_key(self) -> str:
        parts = sorted(f"{v}^{p}" if p != 1 else v for v, p in self.vars_.items())
        return "*".join(parts) if parts else "1"

    def multiply(self, other: 'Monomial') -> 'Monomial':
        new_vars: Dict[str, int] = dict(self.vars_)
        for v, p in other.vars_.items():
            new_vars[v] = new_vars.get(v, 0) + p
        return Monomial(new_vars, self.coeff * other.coeff)


class Polynomial:
    def __init__(self, terms: List[Monomial]):
        self.terms = terms

    @staticmethod
    def constant(c: int) -> 'Polynomial':
        return Polynomial([Monomial({}, c)])

    def normalize(self) -> 'Polynomial':
        combined: Dict[str, int] = defaultdict(int)
        for m in self.terms:
            combined[m.monomial_key()] += m.coeff
        new_terms = []
        for key, coeff in combined.items():
            if coeff == 0:
                continue
            if key == '1' or key == '':
                new_terms.append(Monomial({}, coeff))
            else:
                vars_: Dict[str, int] = {}
                for part in key.split('*'):
                    if '^' in part:
                        v, p = part.split('^')
                        vars_[v] = int(p)
                    else:
                        vars_[part] = 1
                new_terms.append(Monomial(vars_, coeff))
        return Polynomial(new_terms)

    def add(self, other: 'Polynomial') -> 'Polynomial':
        return Polynomial(self.terms + other.terms).normalize()

    def sub(self, other: 'Polynomial') -> 'Polynomial':
        neg = Polynomial([Monomial(m.vars_, -m.coeff) for m in other.terms])
        return self.add(neg)

    def mul(self, other: 'Polynomial') -> 'Polynomial':
        new_terms = [a.multiply(b) for a in self.terms for b in other.terms]
        return Polynomial(new_terms).normalize()

    def eval(self, vals: Dict[str, int]) -> int:
        return sum(m.eval(vals) for m in self.terms)

    def degree(self) -> int:
        if not self.terms:
            return 0
        return max(m.degree() for m in self.terms)

    def variables(self) -> List[str]:
        seen: Set[str] = set()
        for m in self.terms:
            seen.update(m.vars_.keys())
        return sorted(seen)


class KnownSimplifications:
    _DB: Dict[str, str] = {
        "x+y": "x+y",
        "x*1": "x",
        "x*0": "0",
        "x+0": "x",
        "x-x": "0",
        "x+(-x)": "0",
    }

    @staticmethod
    def standard() -> 'KnownSimplifications':
        return KnownSimplifications()

    def lookup(self, poly_str: str) -> Optional[str]:
        return self._DB.get(poly_str)


class SimplificationOutcome:
    def __init__(self, original: MbaExpr, simplified: Optional[MbaExpr],
                 polynomial_repr: str, verified: bool):
        self.original = original
        self.simplified = simplified
        self.polynomial_repr = polynomial_repr
        self.verified = verified


class NonlinearMbaSolver:
    @staticmethod
    def new() -> 'NonlinearMbaSolver':
        return NonlinearMbaSolver()

    def mba_to_polynomial(self, expr: MbaExpr) -> Polynomial:
        if expr.kind == 'Const':
            return Polynomial.constant(expr.value)
        if expr.kind == 'Var':
            return Polynomial([Monomial({expr.value: 1}, 1)])
        if expr.kind == 'Add':
            return self.mba_to_polynomial(expr.children[0]).add(
                   self.mba_to_polynomial(expr.children[1]))
        if expr.kind == 'Sub':
            return self.mba_to_polynomial(expr.children[0]).sub(
                   self.mba_to_polynomial(expr.children[1]))
        if expr.kind == 'Mul':
            return self.mba_to_polynomial(expr.children[0]).mul(
                   self.mba_to_polynomial(expr.children[1]))
        if expr.kind == 'Neg':
            p = self.mba_to_polynomial(expr.children[0])
            return Polynomial([Monomial(m.vars_, -m.coeff) for m in p.terms])
        # Boolean ops: treat as variables for polynomial purposes
        return Polynomial([Monomial({f"bool_{expr.kind}": 1}, 1)])

    def reduce_modulo_boolean_axioms(self, poly: Polynomial) -> Polynomial:
        """x^2 = x for bit variables (idempotency)."""
        new_terms = []
        for m in poly.terms:
            new_vars = {v: min(p, 1) for v, p in m.vars_.items()}
            new_terms.append(Monomial(new_vars, m.coeff))
        return Polynomial(new_terms).normalize()

    def groebner_reduce(self, poly: Polynomial) -> Polynomial:
        """Gröbner-style reduction (simplified: apply boolean axioms)."""
        return self.reduce_modulo_boolean_axioms(poly)

    def verify_equivalence_sampling(self, expr1: MbaExpr, expr2: MbaExpr) -> bool:
        verifier = MbaVerifier()
        return verifier.verify_equivalent(expr1, expr2).equivalent

    def refutation_counterexample(self, expr1: MbaExpr, expr2: MbaExpr) -> Optional[Dict[str, int]]:
        verifier = MbaVerifier()
        return verifier.find_counterexample(expr1, expr2)

    def simplify_nonlinear(self, expr: MbaExpr) -> SimplificationOutcome:
        poly = self.mba_to_polynomial(expr)
        reduced = self.groebner_reduce(poly)
        poly_str = " + ".join(
            (f"{m.coeff}*{m.monomial_key()}" if m.vars_ else str(m.coeff))
            for m in reduced.terms
        ) or "0"
        known = KnownSimplifications.standard()
        simplified_str = known.lookup(poly_str)
        simplified_expr = None
        verified = False
        if simplified_str:
            try:
                simplified_expr = MbaExpr.parse(simplified_str)
                verified = self.verify_equivalence_sampling(expr, simplified_expr)
            except Exception:
                pass
        if simplified_expr is None:
            simplified_expr = MbaSimplifier.new().simplify_tree(expr)
            verified = self.verify_equivalence_sampling(expr, simplified_expr)
        return SimplificationOutcome(expr, simplified_expr, poly_str, verified)


# ============================================================
# Validator entry-points (one per documented function/group)
# ============================================================

def validator_mk_add(lhs: MbaExpr, rhs: MbaExpr) -> MbaExpr:
    return MbaExpr.mk_add(lhs, rhs)

def validator_mk_sub(lhs: MbaExpr, rhs: MbaExpr) -> MbaExpr:
    return MbaExpr.mk_sub(lhs, rhs)

def validator_mk_mul(lhs: MbaExpr, rhs: MbaExpr) -> MbaExpr:
    return MbaExpr.mk_mul(lhs, rhs)

def validator_mk_neg(e: MbaExpr) -> MbaExpr:
    return MbaExpr.mk_neg(e)

def validator_mk_and(lhs: MbaExpr, rhs: MbaExpr) -> MbaExpr:
    return MbaExpr.mk_and(lhs, rhs)

def validator_mk_or(lhs: MbaExpr, rhs: MbaExpr) -> MbaExpr:
    return MbaExpr.mk_or(lhs, rhs)

def validator_mk_xor(lhs: MbaExpr, rhs: MbaExpr) -> MbaExpr:
    return MbaExpr.mk_xor(lhs, rhs)

def validator_mk_not(e: MbaExpr) -> MbaExpr:
    return MbaExpr.mk_not(e)

def validator_complexity(expr: MbaExpr) -> int:
    return expr.complexity()

def validator_vars(expr: MbaExpr) -> List[str]:
    return expr.vars()

def validator_eval(expr: MbaExpr, env: Dict[str, int]) -> Optional[int]:
    return expr.eval(env)

def validator_substitute(expr: MbaExpr, var: str, repl: MbaExpr) -> MbaExpr:
    return expr.substitute(var, repl)

def validator_is_linear(expr: MbaExpr) -> bool:
    return expr.is_linear()

def validator_parse(s: str) -> MbaExpr:
    return MbaExpr.parse(s)

def validator_build_rule_database() -> List[SimplificationRule]:
    return build_rule_database()

def validator_mba_verifier_new() -> MbaVerifier:
    return MbaVerifier.new()

def validator_verify_equivalent(a: MbaExpr, b: MbaExpr) -> VerificationResult:
    return MbaVerifier().verify_equivalent(a, b)

def validator_is_always_zero(expr: MbaExpr) -> bool:
    return MbaVerifier().is_always_zero(expr)

def validator_is_always_const(expr: MbaExpr, c: int) -> bool:
    return MbaVerifier().is_always_const(expr, c)

def validator_find_counterexample(a: MbaExpr, b: MbaExpr) -> Optional[Dict[str, int]]:
    return MbaVerifier().find_counterexample(a, b)

def validator_mba_simplifier_new() -> MbaSimplifier:
    return MbaSimplifier.new()

def validator_simplify(expr: MbaExpr) -> SimplificationResult:
    return MbaSimplifier.new().simplify(expr)

def validator_simplify_once(expr: MbaExpr) -> Tuple[MbaExpr, List[str]]:
    return MbaSimplifier.new().simplify_once(expr)

def validator_apply_rules_bottomup(expr: MbaExpr) -> Tuple[MbaExpr, List[str]]:
    return MbaSimplifier.new().apply_rules_bottomup(expr)

def validator_try_rules(expr: MbaExpr) -> Optional[Tuple[MbaExpr, str]]:
    return MbaSimplifier.new().try_rules(expr)

def validator_simplify_tree(expr: MbaExpr) -> MbaExpr:
    return MbaSimplifier.new().simplify_tree(expr)

def validator_pattern_library_standard() -> MbaPatternLibrary:
    return MbaPatternLibrary.standard()

def validator_match_pattern(expr: MbaExpr) -> Optional[MbaPattern]:
    return MbaPatternLibrary.standard().match_pattern(expr)

def validator_mba_analyzer_new() -> MbaAnalyzer:
    return MbaAnalyzer.new()

def validator_analyze_expression(expr: MbaExpr) -> SimplificationResult:
    return MbaAnalyzer.new().analyze_expression(expr)

def validator_analyze_batch(exprs: List[MbaExpr]) -> MbaPassResult:
    return MbaAnalyzer.new().analyze_batch(exprs)

def validator_tree_metrics_of(expr: MbaExpr) -> TreeMetrics:
    return TreeMetrics.of(expr)

def validator_op_profile_of(expr: MbaExpr) -> OpProfile:
    return OpProfile.of(expr)

def validator_distinct_ops(expr: MbaExpr) -> int:
    return OpProfile.of(expr).distinct_ops()

def validator_mixing_ratio(expr: MbaExpr) -> float:
    return OpProfile.of(expr).mixing_ratio()

def validator_complexity_score_compute(expr: MbaExpr) -> ComplexityScore:
    return ComplexityScore.compute(expr)

def validator_is_likely_mba(expr: MbaExpr) -> bool:
    return ComplexityScore.compute(expr).is_likely_mba()

def validator_relative_to(a: MbaExpr, b: MbaExpr) -> float:
    return ComplexityScore.compute(a).relative_to(ComplexityScore.compute(b))

def validator_mba_complexity_scorer_new() -> MbaComplexityScorer:
    return MbaComplexityScorer.new()

def validator_scorer_score(expr: MbaExpr) -> ExprScoringResult:
    return MbaComplexityScorer.new().score(expr)

def validator_score_batch(exprs: List[MbaExpr]) -> List[ExprScoringResult]:
    return MbaComplexityScorer.new().score_batch(exprs)

def validator_filter_mba(exprs: List[MbaExpr]) -> List[ExprScoringResult]:
    return MbaComplexityScorer.new().filter_mba(exprs)

def validator_obfuscation_density(total: int, mba_count: int) -> float:
    return FunctionMbaProfile(total, mba_count).obfuscation_density()

def validator_mba_analysis_analyze(expr: MbaExpr) -> MbaAnalysis:
    return MbaAnalysis.analyze(expr)

def validator_default_library() -> MbaDetectorPatternLibrary:
    return MbaDetectorPatternLibrary.default_library()

def validator_match_patterns(expr: MbaExpr, depth: int) -> List[MbaPattern]:
    return MbaDetectorPatternLibrary.default_library().match_patterns(expr, depth)

def validator_mba_scorer_new() -> MbaScorer:
    return MbaScorer.new()

def validator_mba_scorer_score(expr: MbaExpr) -> MbaScore:
    return MbaScorer.new().score(expr)

def validator_batch_score(exprs: List[MbaExpr]) -> List[MbaScore]:
    return MbaScorer.new().batch_score(exprs)

def validator_top_obfuscated(exprs: List[MbaExpr], n: int) -> List[Tuple[MbaExpr, MbaScore]]:
    return MbaScorer.new().top_obfuscated(exprs, n)

def validator_mba_statistics_compute(scores: List[MbaScore]) -> MbaStatistics:
    return MbaStatistics.compute(scores)

def validator_mba_expr_tree_add(a: MbaExprTree, b: MbaExprTree) -> MbaExprTree:
    return MbaExprTree.add(a, b)

def validator_mba_expr_tree_sub(a: MbaExprTree, b: MbaExprTree) -> MbaExprTree:
    return MbaExprTree.sub(a, b)

def validator_mba_expr_tree_mul(a: MbaExprTree, b: MbaExprTree) -> MbaExprTree:
    return MbaExprTree.mul(a, b)

def validator_mba_expr_tree_neg(a: MbaExprTree) -> MbaExprTree:
    return MbaExprTree.neg(a)

def validator_mba_expr_tree_and(a: MbaExprTree, b: MbaExprTree) -> MbaExprTree:
    return MbaExprTree.and_(a, b)

def validator_mba_expr_tree_or(a: MbaExprTree, b: MbaExprTree) -> MbaExprTree:
    return MbaExprTree.or_(a, b)

def validator_mba_expr_tree_xor(a: MbaExprTree, b: MbaExprTree) -> MbaExprTree:
    return MbaExprTree.xor(a, b)

def validator_mba_expr_tree_not(a: MbaExprTree) -> MbaExprTree:
    return MbaExprTree.not_(a)

def validator_node_count(t: MbaExprTree) -> int:
    return t.node_count()

def validator_tree_depth(t: MbaExprTree) -> int:
    return t.depth()

def validator_structural_simplifier_new() -> StructuralSimplifier:
    return StructuralSimplifier.new()

def validator_struct_simplify(expr: MbaExprTree) -> Tuple[MbaExprTree, List[str]]:
    return StructuralSimplifier.new().simplify(expr)

def validator_constant_propagator_new() -> ConstantPropagator:
    return ConstantPropagator.new()

def validator_propagate(expr: MbaExprTree, bindings: Dict[str, int]) -> MbaExprTree:
    cp = ConstantPropagator.new()
    for k, v in bindings.items():
        cp.bind(k, v)
    return cp.propagate(expr)

def validator_normal_form_converter(expr: MbaExprTree) -> NormalFormConverter:
    return NormalFormConverter.from_expr(expr)

def validator_equivalence_checker_new() -> EquivalenceChecker:
    return EquivalenceChecker.new()

def validator_check_equivalent_tree(a: MbaExprTree, b: MbaExprTree) -> bool:
    return EquivalenceChecker.new().check_equivalent(a, b)

def validator_is_constant_tree(expr: MbaExprTree) -> bool:
    return EquivalenceChecker.new().is_constant(expr)

def validator_expr_complexity_metrics(expr: MbaExprTree) -> ExprComplexityMetrics:
    return ExprComplexityMetrics.compute(expr)

def validator_complexity_score_tree(expr: MbaExprTree) -> float:
    return ExprComplexityMetrics.compute(expr).complexity_score()

def validator_mba_normalizer_new() -> MbaNormalizer:
    return MbaNormalizer.new()

def validator_normalize(expr: MbaExprTree) -> Tuple[NormalForm, bool, List[str]]:
    return MbaNormalizer.new().normalize(expr)

def validator_complexity_ratio(original: MbaExprTree, simplified: MbaExprTree) -> float:
    return MbaNormalizer.new().complexity_ratio(original, simplified)

def validator_oracle_new(config: OracleConfig) -> MbaOracle:
    return MbaOracle.new(config)

def validator_oracle_simplify(expr: MbaExpr, variables: List[str]) -> Optional[OracleResult]:
    return MbaOracle.new(OracleConfig()).simplify(expr, variables)

def validator_oracle_simplify_batch(exprs: List[MbaExpr], variables: List[str]) -> List[Optional[OracleResult]]:
    return MbaOracle.new(OracleConfig()).simplify_batch(exprs, variables)

def validator_confidence_score(result: OracleResult) -> float:
    return MbaOracle.new(OracleConfig()).confidence_score(result)

def validator_rewriter_new() -> MbaRewriter:
    return MbaRewriter.new()

def validator_rewrite(expr: MbaExpr) -> RewriteResult:
    return MbaRewriter.new().rewrite(expr)

def validator_single_pass(expr: MbaExpr) -> Tuple[MbaExpr, List[RewriteStep]]:
    return MbaRewriter.new().single_pass(expr)

def validator_rewrite_cached(expr: MbaExpr) -> MbaExpr:
    return MbaRewriter.new().rewrite_cached(expr)

def validator_apply_rule(name: str, expr: MbaExpr) -> Optional[MbaExpr]:
    return MbaRewriter.new().apply_rule(name, expr)

def validator_truth_table_build(expr: MbaExpr, var_names: List[str]) -> TruthTable:
    return TruthTable.build(expr, var_names)

def validator_truth_table_build_masked(expr: MbaExpr, var_names: List[str], mask: int) -> TruthTable:
    return TruthTable.build_masked(expr, var_names, mask)

def validator_truth_table_matches(a: TruthTable, b: TruthTable) -> bool:
    return a.matches(b)

def validator_as_u8_key(tt: TruthTable) -> int:
    return tt.as_u8_key()

def validator_truth_table_verifier_check(a: MbaExpr, b: MbaExpr) -> bool:
    return TruthTableVerifier().check(a, b)

def validator_mba_expr_simplifier_new() -> MbaExprSimplifier:
    return MbaExprSimplifier.new()

def validator_expr_simplify(expr: MbaExpr) -> SimplifyResult:
    return MbaExprSimplifier.new().simplify(expr)

def validator_apply_rules_once(expr: MbaExpr) -> Tuple[MbaExpr, List[str]]:
    return MbaExprSimplifier.new().apply_rules_once(expr)

def validator_truth_table_simplify(expr: MbaExpr) -> Optional[MbaExpr]:
    return MbaExprSimplifier.new().truth_table_simplify(expr)

def validator_mba_expr_result_from_simplification(text: str, result: SimplificationResult) -> MbaExprResult:
    return MbaExprResult.from_simplification(text, result)

def validator_mba_report_from_results(results: List[MbaExprResult]) -> MbaReport:
    return MbaReport.from_results(results)

def validator_markdown_summary(report: MbaReport) -> str:
    return report.markdown_summary()

def validator_simba_simplify(expr_text: str) -> SimbaResult:
    return SimbaSimplifier.new().simplify(expr_text)

def validator_reduction_ratio(result: SimplificationResult) -> float:
    return result.reduction_ratio()

def validator_pipeline_simplify_text(expr_text: str) -> VerifiedSimplification:
    return MbaPipeline.new().simplify_text(expr_text)

def validator_pipeline_simplify_batch(expressions: List[str]) -> MbaReport:
    return MbaPipeline.new().simplify_batch(expressions)

def validator_simplify_and_filter(expressions: List[str]) -> List[VerifiedSimplification]:
    return MbaPipeline.new().simplify_and_filter(expressions)

def validator_verify_identity(lhs: str, rhs: str) -> Optional[bool]:
    return MbaPipeline.new().verify_identity(lhs, rhs)

def validator_cached_pipeline_new() -> CachedMbaPipeline:
    return CachedMbaPipeline.new()

def validator_cached_simplify(pipe: CachedMbaPipeline, expr_text: str) -> VerifiedSimplification:
    return pipe.simplify(expr_text)

def validator_cache_size(pipe: CachedMbaPipeline) -> int:
    return pipe.cache_size()

def validator_clear_cache(pipe: CachedMbaPipeline) -> None:
    pipe.clear_cache()

def validator_bool_expr_not(e: BoolExpr) -> BoolExpr:
    return BoolExpr.not_(e)

def validator_bool_expr_and(l: BoolExpr, r: BoolExpr) -> BoolExpr:
    return BoolExpr.and_(l, r)

def validator_bool_expr_or(l: BoolExpr, r: BoolExpr) -> BoolExpr:
    return BoolExpr.or_(l, r)

def validator_bool_expr_xor(l: BoolExpr, r: BoolExpr) -> BoolExpr:
    return BoolExpr.xor(l, r)

def validator_bool_expr_var(name: str) -> BoolExpr:
    return BoolExpr.var(name)

def validator_bool_complexity(expr: BoolExpr) -> int:
    return expr.complexity()

def validator_bool_vars(expr: BoolExpr) -> List[str]:
    return expr.vars()

def validator_bool_eval(expr: BoolExpr, env: Dict[str, bool]) -> Optional[bool]:
    return expr.eval(env)

def validator_bool_simplifier_new() -> BoolSimplifier:
    return BoolSimplifier.new()

def validator_bool_simplify(expr: BoolExpr) -> BoolSimplResult:
    return BoolSimplifier.new().simplify(expr)

def validator_bool_simplify_once(expr: BoolExpr) -> BoolSimplResult:
    return BoolSimplifier.new().simplify_once(expr)

def validator_literal_pos(var: str) -> Literal:
    return Literal.pos(var)

def validator_literal_neg(var: str) -> Literal:
    return Literal.neg(var)

def validator_literal_negate(lit: Literal) -> Literal:
    return lit.negate()

def validator_literal_display(lit: Literal) -> str:
    return lit.display()

def validator_clause_unit(lit: Literal) -> Clause:
    return Clause.unit(lit)

def validator_clause_is_tautology(clause: Clause) -> bool:
    return clause.is_tautology()

def validator_clause_display(clause: Clause) -> str:
    return clause.display()

def validator_cnf_simplify(formula: CnfFormula) -> None:
    formula.simplify()

def validator_cnf_display(formula: CnfFormula) -> str:
    return formula.display()

def validator_dnf_display(formula: DnfFormula) -> str:
    return formula.display()

def validator_dnf_eval(formula: DnfFormula, assignment: Dict[str, bool]) -> bool:
    return formula.eval(assignment)

def validator_dnf_size(formula: DnfFormula) -> int:
    return formula.size()

def validator_truth_table_matrix(expr: MbaExpr, variable_order: List[str]) -> TruthTableMatrix:
    return TruthTableMatrix.from_expr(expr, variable_order)

def validator_bool_normalizer_normalize(expr: MbaExpr) -> Tuple[MbaExpr, BoolNormalizationResult]:
    return BoolNormalizer.normalize(expr)

def validator_all_fold_rules_fn() -> List[FoldRule]:
    return validator_all_fold_rules()

def validator_bitwise_folder_new() -> BitwiseArithmeticFolder:
    return BitwiseArithmeticFolder.new()

def validator_fold(expr: MbaExpr) -> FoldResult:
    return BitwiseArithmeticFolder.new().fold(expr)

def validator_fold_pass(expr: MbaExpr) -> Tuple[MbaExpr, List[str]]:
    return BitwiseArithmeticFolder.new().fold_pass(expr)

def validator_fold_constants_only(expr: MbaExpr) -> MbaExpr:
    return BitwiseArithmeticFolder.new().fold_constants_only(expr)

def validator_monomial_var(name: str, coeff: int) -> Monomial:
    return Monomial.var(name, coeff)

def validator_monomial_degree(m: Monomial) -> int:
    return m.degree()

def validator_monomial_eval(m: Monomial, vals: Dict[str, int]) -> int:
    return m.eval(vals)

def validator_monomial_key(m: Monomial) -> str:
    return m.monomial_key()

def validator_monomial_multiply(a: Monomial, b: Monomial) -> Monomial:
    return a.multiply(b)

def validator_polynomial_constant(c: int) -> Polynomial:
    return Polynomial.constant(c)

def validator_polynomial_normalize(p: Polynomial) -> Polynomial:
    return p.normalize()

def validator_polynomial_add(a: Polynomial, b: Polynomial) -> Polynomial:
    return a.add(b)

def validator_polynomial_sub(a: Polynomial, b: Polynomial) -> Polynomial:
    return a.sub(b)

def validator_polynomial_mul(a: Polynomial, b: Polynomial) -> Polynomial:
    return a.mul(b)

def validator_polynomial_eval(p: Polynomial, vals: Dict[str, int]) -> int:
    return p.eval(vals)

def validator_polynomial_degree(p: Polynomial) -> int:
    return p.degree()

def validator_polynomial_variables(p: Polynomial) -> List[str]:
    return p.variables()

def validator_known_simplifications_standard() -> KnownSimplifications:
    return KnownSimplifications.standard()

def validator_known_lookup(poly_str: str) -> Optional[str]:
    return KnownSimplifications.standard().lookup(poly_str)

def validator_nonlinear_solver_new() -> NonlinearMbaSolver:
    return NonlinearMbaSolver.new()

def validator_mba_to_polynomial(expr: MbaExpr) -> Polynomial:
    return NonlinearMbaSolver.new().mba_to_polynomial(expr)

def validator_reduce_modulo_boolean_axioms(poly: Polynomial) -> Polynomial:
    return NonlinearMbaSolver.new().reduce_modulo_boolean_axioms(poly)

def validator_groebner_reduce(poly: Polynomial) -> Polynomial:
    return NonlinearMbaSolver.new().groebner_reduce(poly)

def validator_verify_equivalence_sampling(expr1: MbaExpr, expr2: MbaExpr) -> bool:
    return NonlinearMbaSolver.new().verify_equivalence_sampling(expr1, expr2)

def validator_refutation_counterexample(expr1: MbaExpr, expr2: MbaExpr) -> Optional[Dict[str, int]]:
    return NonlinearMbaSolver.new().refutation_counterexample(expr1, expr2)

def validator_simplify_nonlinear(expr: MbaExpr) -> SimplificationOutcome:
    return NonlinearMbaSolver.new().simplify_nonlinear(expr)


# ============================================================
# Quick smoke test
# ============================================================
if __name__ == "__main__":
    x = MbaExpr('Var', 'x')
    y = MbaExpr('Var', 'y')
    zero = MbaExpr('Const', 0)

    # x + 0 -> x
    expr = MbaExpr.mk_add(x, zero)
    result = validator_simplify(expr)
    assert result.simplified.kind == 'Var', f"Expected Var, got {result.simplified.kind}"

    # x ^ x -> 0
    expr2 = MbaExpr.mk_xor(x, MbaExpr('Var', 'x'))
    result2 = validator_simplify(expr2)
    assert result2.simplified.kind == 'Const' and result2.simplified.value == 0

    # parse
    parsed = validator_parse("x+y")
    assert parsed.kind == 'Add'

    # pipeline
    vs = validator_pipeline_simplify_text("x+0")
    assert vs.ratio >= 0.0

    # bool normalizer
    mba_or = MbaExpr.mk_or(MbaExpr('Var','a'), MbaExpr('Var','b'))
    out, norm_res = validator_bool_normalizer_normalize(mba_or)
    assert isinstance(norm_res, BoolNormalizationResult)

    # nonlinear solver
    outcome = validator_simplify_nonlinear(MbaExpr.mk_add(x, MbaExpr('Const', 0)))
    assert isinstance(outcome, SimplificationOutcome)

    print("All smoke tests passed.")
