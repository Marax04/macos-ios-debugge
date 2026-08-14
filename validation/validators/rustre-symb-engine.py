#!/usr/bin/env python3
"""
Standalone validator for rustre-symb-engine.

Pure-Python reimplementation of the core abstractions exposed by the Rust
crate `rustre-symb-engine` (full symbolic execution layered on `rustre-symb`).
Used to cross-check the crate's behavior without depending on it.

Covered surface (mirrors lib.rs of the crate):
- StateManager worklist with ExplorationStrategy (DFS/BFS/Random)
- ExecutorConfig depth/state limits, HaltReason
- SymbolicAddress (concrete/expr)
- FunctionSummary apply
- VulnDetector: null deref, buffer overflow, integer overflow, UAF, format string
- ReachabilityQuery
- SymEngine: minimal SymOp interpreter (Const, Add, Sub, Mul, And, Or, Xor,
  Eq, Lt, Load, Store, Branch, Assign)
- SymbolicStore (concrete + symbolic + havoc + entry_count + entries_in_range)
- SymbolicInterpreterState (read_reg/write_reg/load/store)
- Pure helpers: check_satisfiable (linear constraints over ints),
  has_contradiction, simplify_constraints, expr_depth, expr_node_count,
  format_path_conditions, merge_states.

Public validator_* functions are the cross-check API; a small main()
runs smoke tests and dispatches JSON requests on stdin like the
other validators in this directory.

Usage:
  echo {"fn":"expr_depth","args":{"expr":["Add",["Const",1],["Const",2]]}} \
      | python rustre-symb-engine.py
  python rustre-symb-engine.py    # fixed-input smoke test
"""

import json
import os
import random
import sys


# ---------- Expression model ----------
# Expr := ("Const", int)
#       | ("Var", str)
#       | ("Sym", str)            # symbolic input variable
#       | (op, e1, e2)            # op in: Add Sub Mul And Or Xor Eq Lt Le Gt Ge Ne
#       | ("Not", e)
#       | ("Load", addr_expr)
#
# Stored as nested Python lists/tuples.


def _is_const(e):
    return isinstance(e, (list, tuple)) and len(e) == 2 and e[0] == "Const"


def _is_sym(e):
    return isinstance(e, (list, tuple)) and len(e) == 2 and e[0] in ("Sym", "Var")


def validator_expr_node_count(expr):
    if not isinstance(expr, (list, tuple)):
        return 1
    return 1 + sum(validator_expr_node_count(c) for c in expr[1:])


def validator_expr_depth(expr):
    if not isinstance(expr, (list, tuple)):
        return 1
    if len(expr) == 1:
        return 1
    return 1 + max((validator_expr_depth(c) for c in expr[1:]), default=0)


def _eval_concrete(expr, env):
    """Evaluate expr against env (Var/Sym -> int). Raise on unbound symbolic."""
    if isinstance(expr, int):
        return expr
    tag = expr[0]
    if tag == "Const":
        return int(expr[1])
    if tag in ("Var", "Sym"):
        name = expr[1]
        if name not in env:
            raise KeyError(name)
        return int(env[name])
    if tag == "Not":
        return 0 if _eval_concrete(expr[1], env) else 1
    a = _eval_concrete(expr[1], env)
    b = _eval_concrete(expr[2], env)
    if tag == "Add":
        return a + b
    if tag == "Sub":
        return a - b
    if tag == "Mul":
        return a * b
    if tag == "And":
        return a & b
    if tag == "Or":
        return a | b
    if tag == "Xor":
        return a ^ b
    if tag == "Eq":
        return 1 if a == b else 0
    if tag == "Ne":
        return 1 if a != b else 0
    if tag == "Lt":
        return 1 if a < b else 0
    if tag == "Le":
        return 1 if a <= b else 0
    if tag == "Gt":
        return 1 if a > b else 0
    if tag == "Ge":
        return 1 if a >= b else 0
    raise ValueError("unknown op " + str(tag))


def validator_eval_expr(expr, env):
    try:
        return _eval_concrete(expr, env)
    except KeyError:
        return None


def _simplify(expr):
    if not isinstance(expr, (list, tuple)):
        return expr
    tag = expr[0]
    if tag in ("Const", "Var", "Sym"):
        return tuple(expr)
    if tag == "Not":
        inner = _simplify(expr[1])
        if _is_const(inner):
            return ("Const", 0 if inner[1] else 1)
        return ("Not", inner)
    a = _simplify(expr[1])
    b = _simplify(expr[2])
    if _is_const(a) and _is_const(b):
        try:
            v = _eval_concrete((tag, a, b), {})
            return ("Const", v)
        except Exception:
            pass
    # Identities
    if tag == "Add":
        if _is_const(a) and a[1] == 0:
            return b
        if _is_const(b) and b[1] == 0:
            return a
    if tag == "Mul":
        if _is_const(a) and a[1] == 1:
            return b
        if _is_const(b) and b[1] == 1:
            return a
        if (_is_const(a) and a[1] == 0) or (_is_const(b) and b[1] == 0):
            return ("Const", 0)
    if tag == "Sub" and _is_const(b) and b[1] == 0:
        return a
    if tag == "And" and _is_const(b) and b[1] == 0:
        return ("Const", 0)
    if tag == "Or" and _is_const(b) and b[1] == 0:
        return a
    if tag == "Xor" and _is_const(b) and b[1] == 0:
        return a
    return (tag, a, b)


def validator_simplify_constraints(constraints):
    return [_simplify(c) for c in constraints]


def _collect_syms(expr, acc):
    if not isinstance(expr, (list, tuple)):
        return
    if expr[0] in ("Sym", "Var"):
        acc.add(expr[1])
        return
    for c in expr[1:]:
        _collect_syms(c, acc)


def validator_check_satisfiable(constraints, max_assignments=2048, bound=8):
    """Brute-force SAT over small integer domain [-bound, bound].

    Returns dict {sat: bool, model: {sym: int}|None}.
    Pure (no Z3) — used to cross-check that the Rust engine reports the same
    sat/unsat verdict on small problems.
    """
    syms = set()
    for c in constraints:
        _collect_syms(c, syms)
    syms = sorted(syms)
    if not syms:
        ok = all(_eval_concrete(c, {}) for c in constraints) if constraints else True
        return {"sat": bool(ok), "model": {} if ok else None}
    domain = list(range(-bound, bound + 1))
    tried = 0
    # Cartesian product, but bounded.
    def rec(i, env):
        nonlocal tried
        if tried >= max_assignments:
            return None
        if i == len(syms):
            tried += 1
            try:
                if all(_eval_concrete(c, env) for c in constraints):
                    return dict(env)
            except Exception:
                return None
            return None
        for v in domain:
            env[syms[i]] = v
            r = rec(i + 1, env)
            if r is not None:
                return r
            if tried >= max_assignments:
                return None
        return None
    model = rec(0, {})
    return {"sat": model is not None, "model": model}


def validator_has_contradiction(constraints):
    return not validator_check_satisfiable(constraints)["sat"]


def validator_format_path_conditions(constraints):
    return " AND ".join(_format(c) for c in constraints) if constraints else "TRUE"


def _format(e):
    if not isinstance(e, (list, tuple)):
        return str(e)
    tag = e[0]
    if tag == "Const":
        return str(e[1])
    if tag in ("Sym", "Var"):
        return str(e[1])
    if tag == "Not":
        return "!(" + _format(e[1]) + ")"
    return "(" + _format(e[1]) + " " + tag + " " + _format(e[2]) + ")"


# ---------- SymbolicStore ----------
class SymbolicStore:
    def __init__(self):
        # addr -> ("C", int) or ("E", expr)
        self.cells = {}

    def write_concrete(self, addr, value):
        self.cells[int(addr)] = ("C", int(value))

    def write_expr(self, addr, expr):
        self.cells[int(addr)] = ("E", expr)

    def symbolic_read(self, addr):
        c = self.cells.get(int(addr))
        if c is None:
            return ("Sym", "mem_{:x}".format(int(addr)))
        if c[0] == "C":
            return ("Const", c[1])
        return c[1]

    def havoc_address(self, addr):
        self.cells.pop(int(addr), None)

    def havoc_region(self, start, length):
        for a in list(self.cells.keys()):
            if start <= a < start + length:
                del self.cells[a]

    def entry_count(self):
        return len(self.cells)

    def entries_in_range(self, start, length):
        return [a for a in self.cells if start <= a < start + length]


def validator_store_roundtrip(ops):
    """Apply a list of ops to a SymbolicStore and return final state.

    ops: [["wc", addr, val], ["we", addr, expr], ["hv", addr],
          ["hvr", start, len], ["read", addr]]
    """
    s = SymbolicStore()
    reads = []
    for op in ops:
        kind = op[0]
        if kind == "wc":
            s.write_concrete(op[1], op[2])
        elif kind == "we":
            s.write_expr(op[1], op[2])
        elif kind == "hv":
            s.havoc_address(op[1])
        elif kind == "hvr":
            s.havoc_region(op[1], op[2])
        elif kind == "read":
            reads.append({"addr": op[1], "value": s.symbolic_read(op[1])})
    return {"entry_count": s.entry_count(), "reads": reads}


# ---------- SymbolicInterpreterState (registers + memory) ----------
class InterpState:
    def __init__(self):
        self.regs = {}
        self.store = SymbolicStore()
        self.constraints = []
        self.halted = False
        self.halt_reason = None

    def clone(self):
        n = InterpState()
        n.regs = dict(self.regs)
        n.store.cells = dict(self.store.cells)
        n.constraints = list(self.constraints)
        return n


def _resolve(op, st):
    if isinstance(op, int):
        return ("Const", op)
    if isinstance(op, str):
        return st.regs.get(op, ("Sym", op))
    return op


def _step(instr, st):
    """Execute one SymInstruction-like tuple against InterpState.
    Returns None or "branch_taken"/"branch_not_taken" for Branch.
    """
    if not instr:
        return None
    op = instr[0]
    if op == "Const":
        # ("Const", dst_reg, value)
        st.regs[instr[1]] = ("Const", int(instr[2]))
    elif op in ("Add", "Sub", "Mul", "And", "Or", "Xor"):
        # (op, dst, a, b)
        a = _resolve(instr[2], st)
        b = _resolve(instr[3], st)
        st.regs[instr[1]] = _simplify((op, a, b))
    elif op == "Assign":
        st.regs[instr[1]] = _resolve(instr[2], st)
    elif op == "Load":
        # ("Load", dst, addr)
        addr_expr = _resolve(instr[2], st)
        if _is_const(addr_expr):
            st.regs[instr[1]] = st.store.symbolic_read(addr_expr[1])
        else:
            st.regs[instr[1]] = ("Sym", "load_" + _format(addr_expr))
    elif op == "Store":
        # ("Store", addr, val)
        addr_expr = _resolve(instr[1], st)
        val = _resolve(instr[2], st)
        if _is_const(addr_expr):
            if _is_const(val):
                st.store.write_concrete(addr_expr[1], val[1])
            else:
                st.store.write_expr(addr_expr[1], val)
    elif op == "Branch":
        # ("Branch", cond)
        cond = _resolve(instr[1], st)
        st.constraints.append(cond)
        return ("branch", cond)
    elif op == "Halt":
        st.halted = True
        st.halt_reason = "Halt"
    return None


def validator_run_block(ops, initial_regs=None):
    st = InterpState()
    if initial_regs:
        for k, v in initial_regs.items():
            st.regs[k] = ("Const", int(v))
    for instr in ops:
        _step(instr, st)
        if st.halted:
            break
    return {
        "regs": {k: list(v) if isinstance(v, tuple) else v for k, v in st.regs.items()},
        "constraints": [list(c) if isinstance(c, tuple) else c for c in st.constraints],
        "halted": st.halted,
    }


# ---------- StateManager worklist ----------
class StateManager:
    def __init__(self):
        self.states = []

    def push(self, s):
        self.states.append(s)

    def pop(self, strategy="DFS", rng=None):
        if not self.states:
            return None
        if strategy == "DFS":
            return self.states.pop()
        if strategy == "BFS":
            return self.states.pop(0)
        if strategy == "Random":
            r = rng or random.Random(0)
            i = r.randrange(len(self.states))
            s = self.states[i]
            del self.states[i]
            return s
        return self.states.pop()

    def prune_infeasible(self):
        kept = []
        for s in self.states:
            if not validator_has_contradiction(s.get("constraints", [])):
                kept.append(s)
        self.states = kept

    def __len__(self):
        return len(self.states)


def validator_worklist_order(strategy, n=5):
    sm = StateManager()
    for i in range(n):
        sm.push({"id": i})
    order = []
    while len(sm) > 0:
        order.append(sm.pop(strategy)["id"])
    return order


# ---------- VulnDetector ----------
class VulnDetector:
    def __init__(self):
        self.findings = []
        self.freed = set()

    def check_null_deref(self, addr_expr, env=None):
        v = validator_eval_expr(addr_expr, env or {})
        if v == 0:
            self.findings.append({"kind": "NullDeref", "addr": 0})
            return True
        return False

    def check_buffer_overflow(self, index, size):
        if int(index) >= int(size) or int(index) < 0:
            self.findings.append({"kind": "BufferOverflow",
                                  "index": int(index), "size": int(size)})
            return True
        return False

    def check_integer_overflow(self, a, b, op="Add", width=32):
        a = int(a)
        b = int(b)
        if op == "Add":
            r = a + b
        elif op == "Sub":
            r = a - b
        elif op == "Mul":
            r = a * b
        else:
            return False
        lo = -(1 << (width - 1))
        hi = (1 << (width - 1)) - 1
        if r < lo or r > hi:
            self.findings.append({"kind": "IntegerOverflow",
                                  "op": op, "result": r, "width": width})
            return True
        return False

    def register_free(self, addr):
        self.freed.add(int(addr))

    def check_use_after_free(self, addr):
        if int(addr) in self.freed:
            self.findings.append({"kind": "UseAfterFree", "addr": int(addr)})
            return True
        return False

    def check_format_string(self, fmt):
        # Heuristic: tainted/symbolic format strings are unsafe
        if not isinstance(fmt, str):
            self.findings.append({"kind": "FormatString", "reason": "symbolic"})
            return True
        if "%n" in fmt:
            self.findings.append({"kind": "FormatString", "reason": "%n"})
            return True
        return False

    def drain_findings(self):
        out, self.findings = self.findings, []
        return out


def validator_vuln_scan(spec):
    """Run a sequence of vuln-detector ops described by spec.

    spec: [{"op": "null_deref", "addr": <expr>, "env": {}}, ...]
    """
    d = VulnDetector()
    for s in spec:
        op = s["op"]
        if op == "null_deref":
            d.check_null_deref(s["addr"], s.get("env", {}))
        elif op == "buf":
            d.check_buffer_overflow(s["index"], s["size"])
        elif op == "iov":
            d.check_integer_overflow(s["a"], s["b"],
                                     s.get("op2", "Add"),
                                     s.get("width", 32))
        elif op == "free":
            d.register_free(s["addr"])
        elif op == "uaf":
            d.check_use_after_free(s["addr"])
        elif op == "fmt":
            d.check_format_string(s["fmt"])
    return d.findings


# ---------- FunctionSummary ----------
def validator_apply_summary(summary, state):
    """Summary: {"writes": [[reg, value], ...],
                 "stores": [[addr, value], ...],
                 "constraints": [expr, ...]}"""
    st = dict(state.get("regs", {}))
    mem = dict(state.get("mem", {}))
    cs = list(state.get("constraints", []))
    for reg, val in summary.get("writes", []):
        st[reg] = val
    for addr, val in summary.get("stores", []):
        mem[int(addr)] = val
    cs.extend(summary.get("constraints", []))
    return {"regs": st, "mem": mem, "constraints": cs}


# ---------- ReachabilityQuery ----------
def validator_reachability(cfg, src, dst):
    """cfg: {node: [succ,...]}. BFS reachability."""
    seen = {src}
    queue = [src]
    while queue:
        n = queue.pop(0)
        if n == dst:
            return {"reachable": True, "via": list(seen)}
        for s in cfg.get(n, []):
            if s not in seen:
                seen.add(s)
                queue.append(s)
    return {"reachable": False, "via": list(seen)}


# ---------- merge_states ----------
def validator_merge_states(a, b):
    regs = {}
    for k in set(a.get("regs", {})) | set(b.get("regs", {})):
        va = a.get("regs", {}).get(k)
        vb = b.get("regs", {}).get(k)
        if va == vb:
            regs[k] = va
        else:
            regs[k] = ["Phi", va, vb]
    return {
        "regs": regs,
        "constraints": list(a.get("constraints", [])) + list(b.get("constraints", [])),
    }


# ---------- Dispatcher ----------
FUNCS = {
    "expr_node_count": lambda a: validator_expr_node_count(a["expr"]),
    "expr_depth": lambda a: validator_expr_depth(a["expr"]),
    "eval_expr": lambda a: validator_eval_expr(a["expr"], a.get("env", {})),
    "simplify_constraints": lambda a: validator_simplify_constraints(a["constraints"]),
    "check_satisfiable": lambda a: validator_check_satisfiable(
        a["constraints"], a.get("max", 2048), a.get("bound", 8)),
    "has_contradiction": lambda a: validator_has_contradiction(a["constraints"]),
    "format_path_conditions": lambda a: validator_format_path_conditions(a["constraints"]),
    "store_roundtrip": lambda a: validator_store_roundtrip(a["ops"]),
    "run_block": lambda a: validator_run_block(a["ops"], a.get("regs", {})),
    "worklist_order": lambda a: validator_worklist_order(a.get("strategy", "DFS"),
                                                         a.get("n", 5)),
    "vuln_scan": lambda a: validator_vuln_scan(a["spec"]),
    "apply_summary": lambda a: validator_apply_summary(a["summary"], a["state"]),
    "reachability": lambda a: validator_reachability(a["cfg"], a["src"], a["dst"]),
    "merge_states": lambda a: validator_merge_states(a["a"], a["b"]),
}


def main():
    if not sys.stdin.isatty():
        try:
            req = json.load(sys.stdin)
        except Exception:
            req = None
        if req:
            fn = req.get("fn")
            args = req.get("args", {})
            try:
                out = FUNCS[fn](args)
                json.dump({"ok": True, "result": out}, sys.stdout, default=str)
            except Exception as e:
                json.dump({"ok": False, "error": str(e)}, sys.stdout)
            return

    # Fixed-input smoke test
    add = ("Add", ("Const", 2), ("Const", 3))
    sym_eq = ("Eq", ("Sym", "x"), ("Const", 7))
    contradiction = [("Eq", ("Sym", "x"), ("Const", 1)),
                     ("Eq", ("Sym", "x"), ("Const", 2))]
    samples = {
        "expr_node_count(2+3)": validator_expr_node_count(add),
        "expr_depth(2+3)": validator_expr_depth(add),
        "eval(2+3)": validator_eval_expr(add, {}),
        "simplify(x+0)": validator_simplify_constraints(
            [("Add", ("Sym", "x"), ("Const", 0))]),
        "sat(x==7)": validator_check_satisfiable([sym_eq]),
        "unsat(x==1 && x==2)": validator_check_satisfiable(contradiction),
        "has_contradiction": validator_has_contradiction(contradiction),
        "format": validator_format_path_conditions([sym_eq]),
        "store": validator_store_roundtrip([
            ["wc", 0x1000, 42],
            ["we", 0x1008, ("Sym", "y")],
            ["read", 0x1000],
            ["read", 0x1008],
            ["read", 0x2000],
            ["hv", 0x1000],
            ["read", 0x1000],
        ]),
        "run_block": validator_run_block([
            ("Const", "r0", 5),
            ("Const", "r1", 3),
            ("Add", "r2", "r0", "r1"),
            ("Store", 0x100, "r2"),
            ("Load", "r3", 0x100),
        ]),
        "dfs": validator_worklist_order("DFS", 4),
        "bfs": validator_worklist_order("BFS", 4),
        "vuln": validator_vuln_scan([
            {"op": "null_deref", "addr": ("Const", 0)},
            {"op": "buf", "index": 10, "size": 8},
            {"op": "iov", "a": 2**30, "b": 2**30, "op2": "Add", "width": 32},
            {"op": "free", "addr": 0xdead},
            {"op": "uaf", "addr": 0xdead},
            {"op": "fmt", "fmt": "hello %n"},
        ]),
        "reach": validator_reachability(
            {"a": ["b"], "b": ["c"], "c": []}, "a", "c"),
        "merge": validator_merge_states(
            {"regs": {"r0": 1, "r1": 2}, "constraints": []},
            {"regs": {"r0": 1, "r1": 9}, "constraints": [("Sym", "x")]}),
    }
    print(json.dumps(samples, indent=2, default=str))


if __name__ == "__main__":
    main()
