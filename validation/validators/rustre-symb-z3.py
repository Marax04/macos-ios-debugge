#!/usr/bin/env python3
"""
Standalone validator for rustre-symb-z3.

Reimplements a minimal SymExpr IR + SMT-LIB2 emitter + concrete evaluator in
pure Python (stdlib only) to cross-check the Rust crate's outputs.

Public validator functions:
  validator_make_const(val, bits)             -> SymExpr dict
  validator_make_var(sym_id, bits, name)      -> SymExpr dict
  validator_bit_width(expr)                   -> int
  validator_collect_symbols(expr)             -> [SymId]
  validator_eval_concrete(expr, model)        -> int | None
  validator_emit_smtlib2(expr)                -> str
  validator_smtlib2_builder(logic, asserts)   -> str
  validator_parse_check_sat(text)             -> "Sat"|"Unsat"|"Unknown"
  validator_parse_model(text)                 -> { name: int }
  validator_prove_equivalent(a, b, bits)      -> bool  (concrete brute-force <=8 bits)
  validator_find_input(constraints, target, bits, want) -> {SymId: int} | None

SymExpr representation: a plain dict like
  {"op": "Add", "bits": 32, "args": [a, b]}
  {"op": "Const", "bits": 32, "value": 7}
  {"op": "Symbol", "bits": 32, "id": 1, "name": "x"}

Usage:
  echo {"fn":"emit_smtlib2","args":{"expr":{...}}} | python rustre-symb-z3.py
  python rustre-symb-z3.py            # runs main() smoke test
"""

import itertools
import json
import re
import sys


# ---------- SymExpr constructors ----------
def validator_make_const(val, bits):
    return {"op": "Const", "bits": int(bits), "value": int(val) & ((1 << bits) - 1)}


def validator_make_var(sym_id, bits, name):
    return {"op": "Symbol", "bits": int(bits), "id": int(sym_id), "name": str(name)}


def _bin(op, a, b, bits=None):
    if bits is None:
        bits = a["bits"]
    return {"op": op, "bits": bits, "args": [a, b]}


def _pred(op, a, b):
    return {"op": op, "bits": 1, "args": [a, b]}


# ---------- bit_width ----------
def validator_bit_width(expr):
    op = expr["op"]
    if op in ("Const", "Symbol"):
        return expr["bits"]
    if op == "Concat":
        return sum(validator_bit_width(p) for p in expr["args"])
    if op == "Extract":
        return expr["hi"] - expr["lo"] + 1
    if op in ("ZeroExt", "SignExt"):
        return expr["new_size"]
    if op in ("Eq", "Ne", "Ult", "Ule", "Ugt", "Uge", "Slt", "Sle", "Sgt", "Sge",
              "BoolAnd", "BoolOr", "BoolNot", "BoolXor", "BoolImplies", "BoolVal"):
        return 1
    return expr.get("bits", expr["args"][0]["bits"])


# ---------- collect_symbols ----------
def validator_collect_symbols(expr):
    out = []
    seen = set()

    def walk(e):
        op = e["op"]
        if op == "Symbol":
            sid = e["id"]
            if sid not in seen:
                seen.add(sid)
                out.append(sid)
            return
        for k in ("args",):
            if k in e:
                for c in e[k]:
                    walk(c)
        if "inner" in e:
            walk(e["inner"])
        if "cond" in e:
            walk(e["cond"]); walk(e["then"]); walk(e["else"])
    walk(expr)
    return out


# ---------- eval_concrete ----------
def _mask(bits):
    return (1 << bits) - 1


def _sx(v, bits):
    sign = 1 << (bits - 1)
    return (v & _mask(bits)) - ((v & sign) << 1)


def validator_eval_concrete(expr, model):
    """model is {sym_id: int}. Returns int or None."""
    op = expr["op"]
    bits = expr.get("bits")
    if op == "Const":
        return expr["value"] & _mask(bits)
    if op == "Symbol":
        v = model.get(expr["id"])
        if v is None:
            v = model.get(expr.get("name"))
        return None if v is None else (int(v) & _mask(bits))
    if op == "BoolVal":
        return 1 if expr.get("value") else 0
    args = [validator_eval_concrete(a, model) for a in expr.get("args", [])]
    if any(a is None for a in args):
        return None
    if op == "Add": return (args[0] + args[1]) & _mask(bits)
    if op == "Sub": return (args[0] - args[1]) & _mask(bits)
    if op == "Mul": return (args[0] * args[1]) & _mask(bits)
    if op == "UDiv": return 0 if args[1] == 0 else (args[0] // args[1]) & _mask(bits)
    if op == "URem": return 0 if args[1] == 0 else (args[0] % args[1]) & _mask(bits)
    if op == "SDiv":
        if args[1] == 0: return 0
        a, b = _sx(args[0], bits), _sx(args[1], bits)
        q = int(a / b) if (a < 0) ^ (b < 0) else a // b
        return q & _mask(bits)
    if op == "SRem":
        if args[1] == 0: return 0
        a, b = _sx(args[0], bits), _sx(args[1], bits)
        return (a - (int(a / b) if (a < 0) ^ (b < 0) else a // b) * b) & _mask(bits)
    if op == "Neg": return (-args[0]) & _mask(bits)
    if op == "And": return (args[0] & args[1]) & _mask(bits)
    if op == "Or":  return (args[0] | args[1]) & _mask(bits)
    if op == "Xor": return (args[0] ^ args[1]) & _mask(bits)
    if op == "Not": return (~args[0]) & _mask(bits)
    if op == "Shl": return (args[0] << (args[1] % bits)) & _mask(bits)
    if op == "LShr" or op == "Shr": return (args[0] >> (args[1] % bits)) & _mask(bits)
    if op == "AShr":
        return (_sx(args[0], bits) >> (args[1] % bits)) & _mask(bits)
    if op == "Eq":  return 1 if args[0] == args[1] else 0
    if op == "Ne":  return 1 if args[0] != args[1] else 0
    if op == "Ult": return 1 if args[0] < args[1] else 0
    if op == "Ule": return 1 if args[0] <= args[1] else 0
    if op == "Ugt": return 1 if args[0] > args[1] else 0
    if op == "Uge": return 1 if args[0] >= args[1] else 0
    if op == "Slt":
        ab = expr["args"][0]["bits"]
        return 1 if _sx(args[0], ab) < _sx(args[1], ab) else 0
    if op == "Sle":
        ab = expr["args"][0]["bits"]
        return 1 if _sx(args[0], ab) <= _sx(args[1], ab) else 0
    if op == "Sgt":
        ab = expr["args"][0]["bits"]
        return 1 if _sx(args[0], ab) > _sx(args[1], ab) else 0
    if op == "Sge":
        ab = expr["args"][0]["bits"]
        return 1 if _sx(args[0], ab) >= _sx(args[1], ab) else 0
    if op == "BoolAnd": return 1 if all(args) else 0
    if op == "BoolOr":  return 1 if any(args) else 0
    if op == "BoolNot": return 0 if args[0] else 1
    if op == "BoolXor": return reduce_xor(args)
    if op == "BoolImplies": return 0 if (args[0] and not args[1]) else 1
    if op == "ZeroExt":
        inner = validator_eval_concrete(expr["inner"], model)
        return None if inner is None else inner & _mask(expr["new_size"])
    if op == "SignExt":
        inner = validator_eval_concrete(expr["inner"], model)
        if inner is None: return None
        ib = expr["inner"]["bits"]
        return _sx(inner, ib) & _mask(expr["new_size"])
    if op == "Extract":
        inner = validator_eval_concrete(expr["inner"], model)
        if inner is None: return None
        lo, hi = expr["lo"], expr["hi"]
        return (inner >> lo) & _mask(hi - lo + 1)
    if op == "Concat":
        parts = [validator_eval_concrete(p, model) for p in expr["args"]]
        if any(p is None for p in parts): return None
        out = 0
        for p, e in zip(parts, expr["args"]):
            out = (out << e["bits"]) | p
        return out
    if op == "Ite":
        c = validator_eval_concrete(expr["cond"], model)
        if c is None: return None
        return validator_eval_concrete(expr["then"] if c else expr["else"], model)
    return None


def reduce_xor(args):
    r = 0
    for a in args:
        r ^= (1 if a else 0)
    return r


# ---------- SMT-LIB2 emitter ----------
def _smt(expr):
    op = expr["op"]
    if op == "Const":
        return f"(_ bv{expr['value']} {expr['bits']})"
    if op == "Symbol":
        return expr.get("name") or f"s{expr['id']}"
    if op == "BoolVal":
        return "true" if expr.get("value") else "false"
    mapping = {
        "Add": "bvadd", "Sub": "bvsub", "Mul": "bvmul",
        "UDiv": "bvudiv", "SDiv": "bvsdiv", "URem": "bvurem", "SRem": "bvsrem",
        "Neg": "bvneg",
        "And": "bvand", "Or": "bvor", "Xor": "bvxor", "Not": "bvnot",
        "Shl": "bvshl", "LShr": "bvlshr", "Shr": "bvlshr", "AShr": "bvashr",
        "Eq": "=", "Ne": "distinct",
        "Ult": "bvult", "Ule": "bvule", "Ugt": "bvugt", "Uge": "bvuge",
        "Slt": "bvslt", "Sle": "bvsle", "Sgt": "bvsgt", "Sge": "bvsge",
        "BoolAnd": "and", "BoolOr": "or", "BoolNot": "not",
        "BoolXor": "xor", "BoolImplies": "=>",
    }
    if op in mapping:
        args = " ".join(_smt(a) for a in expr["args"])
        return f"({mapping[op]} {args})"
    if op == "ZeroExt":
        diff = expr["new_size"] - expr["inner"]["bits"]
        return f"((_ zero_extend {diff}) {_smt(expr['inner'])})"
    if op == "SignExt":
        diff = expr["new_size"] - expr["inner"]["bits"]
        return f"((_ sign_extend {diff}) {_smt(expr['inner'])})"
    if op == "Extract":
        return f"((_ extract {expr['hi']} {expr['lo']}) {_smt(expr['inner'])})"
    if op == "Concat":
        if len(expr["args"]) == 2:
            return f"(concat {_smt(expr['args'][0])} {_smt(expr['args'][1])})"
        cur = _smt(expr["args"][0])
        for p in expr["args"][1:]:
            cur = f"(concat {cur} {_smt(p)})"
        return cur
    if op == "Ite":
        return f"(ite {_smt(expr['cond'])} {_smt(expr['then'])} {_smt(expr['else'])})"
    raise ValueError(f"Unsupported op for SMT emission: {op}")


def validator_emit_smtlib2(expr):
    return _smt(expr)


def validator_smtlib2_builder(logic, asserts):
    """Build a minimal SMT-LIB2 script. asserts: list of SymExpr (bool)."""
    out = [f"(set-logic {logic})"]
    seen = {}
    for a in asserts:
        for sid in validator_collect_symbols(a):
            seen[sid] = None
    # Walk to recover (name, bits) for each declared symbol.
    decls = {}

    def walk(e):
        if e["op"] == "Symbol":
            decls.setdefault(e["id"], (e.get("name") or f"s{e['id']}", e["bits"]))
            return
        for k in ("args",):
            if k in e:
                for c in e[k]:
                    walk(c)
        if "inner" in e:
            walk(e["inner"])
        if "cond" in e:
            walk(e["cond"]); walk(e["then"]); walk(e["else"])
    for a in asserts:
        walk(a)
    for sid, (name, bits) in decls.items():
        out.append(f"(declare-fun {name} () (_ BitVec {bits}))")
    for a in asserts:
        out.append(f"(assert {_smt(a)})")
    out.append("(check-sat)")
    return "\n".join(out) + "\n"


# ---------- SMT-LIB2 output parser ----------
def validator_parse_check_sat(text):
    t = text.strip().splitlines()
    for line in t:
        s = line.strip()
        if s == "sat": return "Sat"
        if s == "unsat": return "Unsat"
        if s.startswith("unknown"): return "Unknown"
    return "Unknown"


_MODEL_DEF = re.compile(
    r"\(define-fun\s+([A-Za-z_][A-Za-z0-9_]*)\s+\(\)\s+\(_\s+BitVec\s+\d+\)\s+"
    r"(?:#x([0-9a-fA-F]+)|#b([01]+)|\(_\s+bv(\d+)\s+\d+\))\s*\)"
)


def validator_parse_model(text):
    out = {}
    for m in _MODEL_DEF.finditer(text):
        name, hx, bn, dec = m.groups()
        if hx is not None:
            out[name] = int(hx, 16)
        elif bn is not None:
            out[name] = int(bn, 2)
        else:
            out[name] = int(dec)
    return out


# ---------- prove_equivalent (brute force, small bitwidths) ----------
def validator_prove_equivalent(a, b, bits):
    if bits > 10:
        return None  # refuse: too large for brute force
    syms = sorted(set(validator_collect_symbols(a)) | set(validator_collect_symbols(b)))
    for vals in itertools.product(range(1 << bits), repeat=len(syms)):
        model = dict(zip(syms, vals))
        va = validator_eval_concrete(a, model)
        vb = validator_eval_concrete(b, model)
        if va != vb:
            return False
    return True


# ---------- find_input (brute force) ----------
def validator_find_input(constraints, target, bits, want):
    if bits > 10:
        return None
    syms = set()
    for c in constraints:
        syms |= set(validator_collect_symbols(c))
    syms |= set(validator_collect_symbols(target))
    syms = sorted(syms)
    want = int(want)
    for vals in itertools.product(range(1 << bits), repeat=len(syms)):
        model = dict(zip(syms, vals))
        ok = True
        for c in constraints:
            if not validator_eval_concrete(c, model):
                ok = False
                break
        if not ok:
            continue
        if validator_eval_concrete(target, model) == want:
            return model
    return None


# ---------- Dispatcher ----------
FUNCS = {
    "make_const": lambda a: validator_make_const(a["value"], a["bits"]),
    "make_var": lambda a: validator_make_var(a["id"], a["bits"], a["name"]),
    "bit_width": lambda a: validator_bit_width(a["expr"]),
    "collect_symbols": lambda a: validator_collect_symbols(a["expr"]),
    "eval_concrete": lambda a: validator_eval_concrete(a["expr"], {int(k): v for k, v in a["model"].items()}),
    "emit_smtlib2": lambda a: validator_emit_smtlib2(a["expr"]),
    "smtlib2_builder": lambda a: validator_smtlib2_builder(a.get("logic", "QF_BV"), a["asserts"]),
    "parse_check_sat": lambda a: validator_parse_check_sat(a["text"]),
    "parse_model": lambda a: validator_parse_model(a["text"]),
    "prove_equivalent": lambda a: validator_prove_equivalent(a["a"], a["b"], a["bits"]),
    "find_input": lambda a: validator_find_input(a["constraints"], a["target"], a["bits"], a["want"]),
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
    x = validator_make_var(1, 8, "x")
    y = validator_make_var(2, 8, "y")
    c5 = validator_make_const(5, 8)
    add = _bin("Add", x, c5, 8)
    eq = _pred("Eq", add, y)

    samples = {
        "bit_width_add": validator_bit_width(add),
        "symbols_eq": validator_collect_symbols(eq),
        "eval_add_x3": validator_eval_concrete(add, {1: 3}),
        "smt_add": validator_emit_smtlib2(add),
        "smt_eq": validator_emit_smtlib2(eq),
        "smt_script": validator_smtlib2_builder("QF_BV", [eq]),
        "parse_sat": validator_parse_check_sat("sat\n"),
        "parse_unsat": validator_parse_check_sat("unsat\n"),
        "parse_model": validator_parse_model(
            "(model\n(define-fun x () (_ BitVec 8) #x07)\n"
            "(define-fun y () (_ BitVec 8) (_ bv12 8))\n)"
        ),
        # (x + 5) == (5 + x) over 4-bit values
        "equiv_add_comm": validator_prove_equivalent(
            _bin("Add", validator_make_var(1, 4, "x"), validator_make_const(5, 4), 4),
            _bin("Add", validator_make_const(5, 4), validator_make_var(1, 4, "x"), 4),
            4,
        ),
        # find x s.t. (x ^ 0xA) == 0x3
        "find_xor": validator_find_input(
            [],
            _bin("Xor", validator_make_var(1, 4, "x"), validator_make_const(0xA, 4), 4),
            4, 0x3,
        ),
    }
    print(json.dumps(samples, indent=2, default=str))


if __name__ == "__main__":
    main()
