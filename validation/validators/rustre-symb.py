#!/usr/bin/env python3
"""
Standalone validator for rustre-symb (symbolic execution core).

Pure-Python (stdlib only) reimplementation of the crate's deterministic,
solver-free surface, used as ground truth to cross-check the Rust output:

  - SymType.width
  - SymExpr constructors with constant folding (add/sub/mul/and/or/xor/not)
  - SymExpr.bit_width / expr_width
  - SymExprSimplifier: algebraic identities + constant folding
  - eval_concrete (numeric env) and SymExpr.evaluate (string env)
  - SymMemory: store/load concrete + symbolic
  - PathConstraint: add, as_conjunction, is_trivially_false
  - SymbolicState: new, fork, fork_pair, read/write_register,
                   add_path_condition, add_constraint, is_path_infeasible,
                   is_satisfiable, get_model, merge, assume

Public validator entry points are prefixed `validator_`.

Usage:
  echo {"fn":"simplify","args":{"expr":...}} | python rustre-symb.py
  python rustre-symb.py        # runs the smoke-test main()
"""

import json
import sys

# ---------- SymType ----------
def validator_sym_type_width(ty):
    """ty is dict like {'kind':'BitVec','width':32} or 'Bool', 'Pointer', or
    {'kind':'Array', ...}.
    Returns int width in bits or None."""
    if isinstance(ty, str):
        if ty == "Pointer":
            return 64
        return None
    if not isinstance(ty, dict):
        return None
    k = ty.get("kind")
    if k == "BitVec":
        return int(ty["width"])
    if k == "Pointer":
        return 64
    return None


# ---------- SymExpr (dict AST) ----------
# Node shape: {"op": "...", ...fields...}
#   ConstBv {value:int, width:int}
#   ConstBool {value:bool}
#   Var {name:str, width:int}
#   Add/Sub/Mul/And/Or/Xor/Shl/LShr/AShr/UDiv/SDiv/URem/SRem {a,b}
#   Not/Neg {a}
#   Concat {a,b}; Extract {a, hi, lo}; ZExt/SExt {a, width}
#   Eq/Ne/ULt/ULe/UGt/UGe/SLt/SLe/SGt/SGe {a,b}
#   BoolAnd/BoolOr {a,b}; BoolNot {a}; Ite {cond, then_, else_}

def _mask(w):
    return (1 << w) - 1


def _is_const_bv(e):
    return isinstance(e, dict) and e.get("op") == "ConstBv"


def _is_const_bool(e):
    return isinstance(e, dict) and e.get("op") == "ConstBool"


def _as_signed(v, w):
    v &= _mask(w)
    if v & (1 << (w - 1)):
        v -= 1 << w
    return v


def validator_expr_width(e):
    """Best-effort width like crate's expr_width."""
    if not isinstance(e, dict):
        return None
    op = e["op"]
    if op == "ConstBv":
        return int(e["width"])
    if op == "ConstBool":
        return 1
    if op == "Var":
        return int(e.get("width", 0))
    if op in ("Add", "Sub", "Mul", "And", "Or", "Xor", "Shl", "LShr", "AShr",
              "UDiv", "SDiv", "URem", "SRem"):
        return validator_expr_width(e["a"]) or validator_expr_width(e["b"])
    if op in ("Not", "Neg"):
        return validator_expr_width(e["a"])
    if op == "Concat":
        wa = validator_expr_width(e["a"]) or 0
        wb = validator_expr_width(e["b"]) or 0
        return wa + wb
    if op == "Extract":
        return int(e["hi"]) - int(e["lo"]) + 1
    if op in ("ZExt", "SExt"):
        return int(e["width"])
    if op in ("Eq", "Ne", "ULt", "ULe", "UGt", "UGe", "SLt", "SLe", "SGt",
              "SGe", "BoolAnd", "BoolOr", "BoolNot"):
        return 1
    if op == "Ite":
        return validator_expr_width(e["then_"]) or validator_expr_width(e["else_"])
    return None


# ---- Constructors with constant folding (sym_add/sub/mul/and/or/xor/not) ----
def _const_bv(val, w):
    return {"op": "ConstBv", "value": val & _mask(w), "width": w}


def validator_sym_add(a, b):
    if _is_const_bv(a) and _is_const_bv(b) and a["width"] == b["width"]:
        w = a["width"]
        return _const_bv(a["value"] + b["value"], w)
    return {"op": "Add", "a": a, "b": b}


def validator_sym_sub(a, b):
    if _is_const_bv(a) and _is_const_bv(b) and a["width"] == b["width"]:
        return _const_bv(a["value"] - b["value"], a["width"])
    return {"op": "Sub", "a": a, "b": b}


def validator_sym_mul(a, b):
    if _is_const_bv(a) and _is_const_bv(b) and a["width"] == b["width"]:
        return _const_bv(a["value"] * b["value"], a["width"])
    return {"op": "Mul", "a": a, "b": b}


def validator_sym_and(a, b):
    if _is_const_bv(a) and _is_const_bv(b) and a["width"] == b["width"]:
        return _const_bv(a["value"] & b["value"], a["width"])
    return {"op": "And", "a": a, "b": b}


def validator_sym_or(a, b):
    if _is_const_bv(a) and _is_const_bv(b) and a["width"] == b["width"]:
        return _const_bv(a["value"] | b["value"], a["width"])
    return {"op": "Or", "a": a, "b": b}


def validator_sym_xor(a, b):
    if _is_const_bv(a) and _is_const_bv(b) and a["width"] == b["width"]:
        return _const_bv(a["value"] ^ b["value"], a["width"])
    return {"op": "Xor", "a": a, "b": b}


def validator_sym_not(a):
    if _is_const_bv(a):
        return _const_bv(~a["value"], a["width"])
    if _is_const_bool(a):
        return {"op": "ConstBool", "value": not a["value"]}
    return {"op": "Not", "a": a}


# ---- Simplifier ----
def _eq_expr(a, b):
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def validator_simplify(e):
    if not isinstance(e, dict):
        return e
    op = e["op"]
    if op in ("ConstBv", "ConstBool", "Var"):
        return e

    if op == "BoolNot":
        a = validator_simplify(e["a"])
        if a.get("op") == "BoolNot":
            return a["a"]
        if _is_const_bool(a):
            return {"op": "ConstBool", "value": not a["value"]}
        return {"op": "BoolNot", "a": a}

    if op in ("Not", "Neg"):
        a = validator_simplify(e["a"])
        if op == "Not" and a.get("op") == "Not":
            return a["a"]
        if op == "Neg" and a.get("op") == "Neg":
            return a["a"]
        if op == "Not" and _is_const_bv(a):
            return _const_bv(~a["value"], a["width"])
        if op == "Neg" and _is_const_bv(a):
            return _const_bv(-a["value"], a["width"])
        return {"op": op, "a": a}

    if op == "Ite":
        c = validator_simplify(e["cond"])
        t = validator_simplify(e["then_"])
        f = validator_simplify(e["else_"])
        if _is_const_bool(c):
            return t if c["value"] else f
        return {"op": "Ite", "cond": c, "then_": t, "else_": f}

    if op in ("BoolAnd", "BoolOr"):
        a = validator_simplify(e["a"])
        b = validator_simplify(e["b"])
        if _eq_expr(a, b):
            return a
        if op == "BoolAnd":
            if _is_const_bool(a):
                return b if a["value"] else {"op": "ConstBool", "value": False}
            if _is_const_bool(b):
                return a if b["value"] else {"op": "ConstBool", "value": False}
        else:  # BoolOr
            if _is_const_bool(a):
                return {"op": "ConstBool", "value": True} if a["value"] else b
            if _is_const_bool(b):
                return {"op": "ConstBool", "value": True} if b["value"] else a
        return {"op": op, "a": a, "b": b}

    # Binary BV ops with algebraic identities
    if op in ("Add", "Sub", "Mul", "And", "Or", "Xor"):
        a = validator_simplify(e["a"])
        b = validator_simplify(e["b"])
        # Constant fold
        if _is_const_bv(a) and _is_const_bv(b) and a["width"] == b["width"]:
            w = a["width"]
            av, bv = a["value"], b["value"]
            if op == "Add":
                return _const_bv(av + bv, w)
            if op == "Sub":
                return _const_bv(av - bv, w)
            if op == "Mul":
                return _const_bv(av * bv, w)
            if op == "And":
                return _const_bv(av & bv, w)
            if op == "Or":
                return _const_bv(av | bv, w)
            if op == "Xor":
                return _const_bv(av ^ bv, w)
        # Identities
        zero_a = _is_const_bv(a) and a["value"] == 0
        zero_b = _is_const_bv(b) and b["value"] == 0
        one_a = _is_const_bv(a) and a["value"] == 1
        one_b = _is_const_bv(b) and b["value"] == 1
        if op == "Add":
            if zero_a:
                return b
            if zero_b:
                return a
        if op == "Sub":
            if zero_b:
                return a
            if _eq_expr(a, b):
                w = validator_expr_width(a) or 0
                return _const_bv(0, w)
        if op == "Mul":
            if zero_a or zero_b:
                w = validator_expr_width(a) or validator_expr_width(b) or 0
                return _const_bv(0, w)
            if one_a:
                return b
            if one_b:
                return a
        if op == "And":
            if zero_a or zero_b:
                w = validator_expr_width(a) or validator_expr_width(b) or 0
                return _const_bv(0, w)
            if _eq_expr(a, b):
                return a
        if op == "Or":
            if zero_a:
                return b
            if zero_b:
                return a
            if _eq_expr(a, b):
                return a
        if op == "Xor":
            if _eq_expr(a, b):
                w = validator_expr_width(a) or 0
                return _const_bv(0, w)
            if zero_a:
                return b
            if zero_b:
                return a
        return {"op": op, "a": a, "b": b}

    # Extract / ZExt / SExt / Concat constant folding
    if op == "Extract":
        a = validator_simplify(e["a"])
        hi = int(e["hi"]); lo = int(e["lo"])
        if _is_const_bv(a):
            v = (a["value"] >> lo) & _mask(hi - lo + 1)
            return _const_bv(v, hi - lo + 1)
        return {"op": "Extract", "a": a, "hi": hi, "lo": lo}
    if op == "ZExt":
        a = validator_simplify(e["a"])
        w = int(e["width"])
        if _is_const_bv(a):
            return _const_bv(a["value"] & _mask(a["width"]), w)
        return {"op": "ZExt", "a": a, "width": w}
    if op == "SExt":
        a = validator_simplify(e["a"])
        w = int(e["width"])
        if _is_const_bv(a):
            return _const_bv(_as_signed(a["value"], a["width"]), w)
        return {"op": "SExt", "a": a, "width": w}
    if op == "Concat":
        a = validator_simplify(e["a"])
        b = validator_simplify(e["b"])
        if _is_const_bv(a) and _is_const_bv(b):
            v = (a["value"] << b["width"]) | (b["value"] & _mask(b["width"]))
            return _const_bv(v, a["width"] + b["width"])
        return {"op": "Concat", "a": a, "b": b}

    # Div/Rem with const fold
    if op in ("UDiv", "SDiv", "URem", "SRem"):
        a = validator_simplify(e["a"])
        b = validator_simplify(e["b"])
        if _is_const_bv(a) and _is_const_bv(b) and b["value"] != 0:
            w = a["width"]
            if op == "UDiv":
                return _const_bv(a["value"] // b["value"], w)
            if op == "URem":
                return _const_bv(a["value"] % b["value"], w)
            sa = _as_signed(a["value"], w)
            sb = _as_signed(b["value"], w)
            # truncate-toward-zero
            q = int(sa / sb) if (sa * sb) >= 0 else -(-sa // sb) if sa < 0 < sb \
                else -(sa // -sb)
            if op == "SDiv":
                return _const_bv(q, w)
            return _const_bv(sa - q * sb, w)
        return {"op": op, "a": a, "b": b}

    # Comparisons constant fold
    if op in ("Eq", "Ne", "ULt", "ULe", "UGt", "UGe",
              "SLt", "SLe", "SGt", "SGe"):
        a = validator_simplify(e["a"])
        b = validator_simplify(e["b"])
        if _is_const_bv(a) and _is_const_bv(b):
            w = a["width"]
            av = a["value"] & _mask(w); bv = b["value"] & _mask(w)
            sa = _as_signed(av, w); sb = _as_signed(bv, w)
            tbl = {"Eq": av == bv, "Ne": av != bv,
                   "ULt": av < bv, "ULe": av <= bv,
                   "UGt": av > bv, "UGe": av >= bv,
                   "SLt": sa < sb, "SLe": sa <= sb,
                   "SGt": sa > sb, "SGe": sa >= sb}
            return {"op": "ConstBool", "value": tbl[op]}
        return {"op": op, "a": a, "b": b}

    return e


# ---- Evaluation ----
def validator_eval_concrete(expr, env):
    """env: dict[int -> int]  (SymId -> u64). Returns int or None.
    Matches the crate's `eval_concrete` semantics for arithmetic/logic."""
    if not isinstance(expr, dict):
        return None
    op = expr["op"]
    if op == "ConstBv":
        w = expr["width"]
        return expr["value"] & _mask(w)
    if op == "Var":
        # Var carries name "name_<id>" — try parse trailing id
        name = expr.get("name", "")
        if "_" in name:
            tail = name.rsplit("_", 1)[1]
            try:
                sid = int(tail)
                if sid in env:
                    return env[sid] & _mask(expr.get("width", 64))
            except ValueError:
                pass
        return None
    if op in ("Add", "Sub", "Mul", "And", "Or", "Xor"):
        a = validator_eval_concrete(expr["a"], env)
        b = validator_eval_concrete(expr["b"], env)
        if a is None or b is None:
            return None
        w = validator_expr_width(expr) or 64
        if op == "Add":
            return (a + b) & _mask(w)
        if op == "Sub":
            return (a - b) & _mask(w)
        if op == "Mul":
            return (a * b) & _mask(w)
        if op == "And":
            return (a & b) & _mask(w)
        if op == "Or":
            return (a | b) & _mask(w)
        if op == "Xor":
            return (a ^ b) & _mask(w)
    if op == "Not":
        a = validator_eval_concrete(expr["a"], env)
        if a is None:
            return None
        w = validator_expr_width(expr) or 64
        return (~a) & _mask(w)
    return None


def validator_evaluate(expr, env_str):
    """env_str: dict[str -> int]. Resolves Var by name match."""
    if not isinstance(expr, dict):
        return None
    op = expr["op"]
    if op == "ConstBv":
        return expr["value"] & _mask(expr["width"])
    if op == "Var":
        v = env_str.get(expr.get("name"))
        if v is None:
            return None
        return v & _mask(expr.get("width", 64))
    if op in ("Add", "Sub", "Mul", "And", "Or", "Xor"):
        a = validator_evaluate(expr["a"], env_str)
        b = validator_evaluate(expr["b"], env_str)
        if a is None or b is None:
            return None
        w = validator_expr_width(expr) or 64
        m = _mask(w)
        return {"Add": (a + b) & m, "Sub": (a - b) & m, "Mul": (a * b) & m,
                "And": a & b, "Or": a | b, "Xor": a ^ b}[op]
    return None


# ---------- SymMemory ----------
def validator_sym_memory_new():
    return {"base": {}, "symbolic": {}}


def validator_sym_memory_store_concrete(mem, addr, val):
    mem["base"][int(addr)] = val
    return mem


def validator_sym_memory_load_concrete(mem, addr):
    a = int(addr)
    if a in mem["base"]:
        return mem["base"][a]
    return {"op": "Var", "name": "mem_{}".format(a), "width": 64}


def validator_sym_memory_store_symbolic(mem, sym_id, val):
    mem["symbolic"][int(sym_id)] = val
    return mem


def validator_sym_memory_load_symbolic(mem, sym_id):
    return mem["symbolic"].get(int(sym_id))


# ---------- PathConstraint ----------
def validator_path_constraint_new():
    return {"terms": []}


def validator_path_constraint_add(pc, expr):
    pc["terms"].append(expr)
    return pc


def validator_path_constraint_as_conjunction(pc):
    terms = pc["terms"]
    if not terms:
        return {"op": "ConstBool", "value": True}
    acc = terms[0]
    for t in terms[1:]:
        acc = {"op": "BoolAnd", "a": acc, "b": t}
    return acc


def validator_path_constraint_is_trivially_false(pc):
    for t in pc["terms"]:
        s = validator_simplify(t)
        if _is_const_bool(s) and s["value"] is False:
            return True
    return False


# ---------- SymbolicState ----------
def validator_state_new():
    return {
        "registers": {},
        "memory": validator_sym_memory_new(),
        "path_condition": validator_path_constraint_new(),
        "constraints": [],
        "pc": 0,
        "depth": 0,
        "model": {},
    }


def validator_state_read_register(st, name):
    if name in st["registers"]:
        return st["registers"][name]
    return {"op": "Var", "name": "reg_{}".format(name), "width": 64}


def validator_state_write_register(st, name, val):
    st["registers"][name] = val
    return st


def validator_state_add_path_condition(st, cond):
    validator_path_constraint_add(st["path_condition"], cond)
    return st


def validator_state_add_constraint(st, cond):
    st["constraints"].append(cond)
    return st


def validator_state_is_path_infeasible(st):
    return validator_path_constraint_is_trivially_false(st["path_condition"])


def validator_state_all_constraints(st):
    return list(st["path_condition"]["terms"]) + list(st["constraints"])


def validator_state_is_satisfiable(st):
    for c in validator_state_all_constraints(st):
        s = validator_simplify(c)
        if _is_const_bool(s) and s["value"] is False:
            return False
    return True


def validator_state_get_model(st):
    model = {}
    # Seed any Var encountered in registers/constraints with 0
    def walk(e):
        if not isinstance(e, dict):
            return
        if e.get("op") == "Var":
            model.setdefault(e["name"], 0)
        for k in ("a", "b", "cond", "then_", "else_"):
            if k in e:
                walk(e[k])
    for v in st["registers"].values():
        walk(v)
    for c in validator_state_all_constraints(st):
        walk(c)
    return model


def _clone(obj):
    return json.loads(json.dumps(obj))


def validator_state_fork(st, branch_cond):
    new = _clone(st)
    validator_state_add_path_condition(new, branch_cond)
    new["depth"] = st["depth"] + 1
    return new


def validator_state_fork_pair(st, branch_cond):
    t = validator_state_fork(st, branch_cond)
    f = validator_state_fork(st, {"op": "BoolNot", "a": branch_cond})
    return [t, f]


def validator_state_assume(st, cond):
    s = validator_simplify(cond)
    if _is_const_bool(s) and s["value"] is False:
        return {"ok": False, "error": "Unsat"}
    validator_state_add_path_condition(st, s)
    return {"ok": True}


def validator_state_merge(a, b, cond):
    """ITE-merge registers, OR path conditions."""
    out = validator_state_new()
    # Registers: union of keys, ITE on mismatched
    keys = set(a["registers"].keys()) | set(b["registers"].keys())
    for k in keys:
        va = a["registers"].get(k)
        vb = b["registers"].get(k)
        if va is None:
            out["registers"][k] = vb
        elif vb is None:
            out["registers"][k] = va
        elif _eq_expr(va, vb):
            out["registers"][k] = va
        else:
            out["registers"][k] = {"op": "Ite", "cond": cond,
                                   "then_": va, "else_": vb}
    # Path condition: OR of conjunctions
    ca = validator_path_constraint_as_conjunction(a["path_condition"])
    cb = validator_path_constraint_as_conjunction(b["path_condition"])
    validator_path_constraint_add(out["path_condition"],
                                  {"op": "BoolOr", "a": ca, "b": cb})
    out["depth"] = max(a["depth"], b["depth"])
    return out


# ---------- Dispatcher ----------
FUNCS = {
    "sym_type_width": lambda a: validator_sym_type_width(a["ty"]),
    "expr_width": lambda a: validator_expr_width(a["expr"]),
    "sym_add": lambda a: validator_sym_add(a["a"], a["b"]),
    "sym_sub": lambda a: validator_sym_sub(a["a"], a["b"]),
    "sym_mul": lambda a: validator_sym_mul(a["a"], a["b"]),
    "sym_and": lambda a: validator_sym_and(a["a"], a["b"]),
    "sym_or": lambda a: validator_sym_or(a["a"], a["b"]),
    "sym_xor": lambda a: validator_sym_xor(a["a"], a["b"]),
    "sym_not": lambda a: validator_sym_not(a["a"]),
    "simplify": lambda a: validator_simplify(a["expr"]),
    "eval_concrete": lambda a: validator_eval_concrete(
        a["expr"], {int(k): int(v) for k, v in a["env"].items()}),
    "evaluate": lambda a: validator_evaluate(a["expr"], a["env"]),
    "path_constraint_as_conjunction":
        lambda a: validator_path_constraint_as_conjunction(a["pc"]),
    "path_constraint_is_trivially_false":
        lambda a: validator_path_constraint_is_trivially_false(a["pc"]),
    "state_new": lambda a: validator_state_new(),
    "state_is_satisfiable": lambda a: validator_state_is_satisfiable(a["state"]),
    "state_is_path_infeasible":
        lambda a: validator_state_is_path_infeasible(a["state"]),
    "state_merge": lambda a: validator_state_merge(a["a"], a["b"], a["cond"]),
    "state_fork": lambda a: validator_state_fork(a["state"], a["cond"]),
    "state_fork_pair": lambda a: validator_state_fork_pair(a["state"], a["cond"]),
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

    # ---- Smoke test ----
    bv32 = lambda v: {"op": "ConstBv", "value": v & _mask(32), "width": 32}
    var_x = {"op": "Var", "name": "x_1", "width": 32}
    samples = {
        "ty_bv_width": validator_sym_type_width({"kind": "BitVec", "width": 32}),
        "ty_ptr_width": validator_sym_type_width("Pointer"),
        "ty_bool_width": validator_sym_type_width("Bool"),
        "add_const": validator_sym_add(bv32(3), bv32(4)),
        "sub_xx": validator_simplify({"op": "Sub", "a": var_x, "b": var_x}),
        "mul_zero": validator_simplify({"op": "Mul", "a": var_x, "b": bv32(0)}),
        "and_xx": validator_simplify({"op": "And", "a": var_x, "b": var_x}),
        "xor_xx": validator_simplify({"op": "Xor", "a": var_x, "b": var_x}),
        "or_x0": validator_simplify({"op": "Or", "a": var_x, "b": bv32(0)}),
        "double_not": validator_simplify({"op": "Not",
                                          "a": {"op": "Not", "a": var_x}}),
        "ite_true": validator_simplify({"op": "Ite",
                                        "cond": {"op": "ConstBool", "value": True},
                                        "then_": bv32(1), "else_": bv32(2)}),
        "extract_const": validator_simplify({"op": "Extract",
                                             "a": bv32(0xDEADBEEF),
                                             "hi": 15, "lo": 0}),
        "concat_const": validator_simplify({"op": "Concat",
                                            "a": bv32(0xAA), "b": bv32(0xBB)}),
        "eq_const_true": validator_simplify({"op": "Eq",
                                             "a": bv32(7), "b": bv32(7)}),
        "eval_concrete_xpy": validator_eval_concrete(
            {"op": "Add", "a": var_x,
             "b": {"op": "Var", "name": "y_2", "width": 32}},
            {1: 10, 2: 5}),
        "evaluate_str": validator_evaluate(
            {"op": "Add", "a": var_x, "b": bv32(1)}, {"x_1": 41}),
    }
    # state ops
    st = validator_state_new()
    validator_state_write_register(st, "rax", bv32(0))
    validator_state_add_path_condition(st, {"op": "ConstBool", "value": True})
    samples["state_sat"] = validator_state_is_satisfiable(st)
    samples["state_infeas"] = validator_state_is_path_infeasible(st)
    samples["state_model_keys"] = list(validator_state_get_model(st).keys())
    forks = validator_state_fork_pair(st,
        {"op": "Eq", "a": var_x, "b": bv32(0)})
    samples["fork_pair_pc_terms"] = [len(f["path_condition"]["terms"])
                                     for f in forks]
    # merge
    a_st = validator_state_new()
    b_st = validator_state_new()
    validator_state_write_register(a_st, "rax", bv32(1))
    validator_state_write_register(b_st, "rax", bv32(2))
    merged = validator_state_merge(a_st, b_st,
        {"op": "Eq", "a": var_x, "b": bv32(0)})
    samples["merged_rax_op"] = merged["registers"]["rax"]["op"]

    print(json.dumps(samples, indent=2, default=str))


if __name__ == "__main__":
    main()
