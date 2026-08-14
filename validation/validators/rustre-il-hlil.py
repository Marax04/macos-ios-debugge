#!/usr/bin/env python3
"""
Standalone Python validator for crate rustre-il-hlil.

Reimplements the externally-verifiable semantics of the HLIL crate using
only Python stdlib, so its outputs can be diffed against the Rust crate's
behaviour on hand-constructed fixtures. No Rust import, no MCP calls.

Input model (mirrors the HLIL Rust types but as plain dicts):

  Type:
    {"kind":"int","signed":bool,"bits":int}
    {"kind":"ptr","pointee":Type,"bits":int}
    {"kind":"array","elem":Type,"len":int|None}
    {"kind":"float"} | {"kind":"double"} | {"kind":"void"} | {"kind":"bool"}
    {"kind":"struct","name":str} | {"kind":"unknown"}

  Expr:
    {"op":"const","value":int,"ty":Type}
    {"op":"var","name":str,"ty":Type}
    {"op":"add"|"sub"|"mul"|"div"|"and"|"or"|"xor"|"shl"|"shr",
        "lhs":Expr,"rhs":Expr,"ty":Type}
    {"op":"eq"|"ne"|"lt"|"le"|"gt"|"ge","lhs":Expr,"rhs":Expr}  # -> bool
    {"op":"sizeof","arg":Type}                                  # -> u64
    {"op":"call","callee":str,"args":[Expr],"ty":Type}
    {"op":"deref","arg":Expr,"ty":Type}
    {"op":"addr","arg":Expr,"ty":Type}

  Stmt:
    {"s":"return","value":Expr|None}
    {"s":"goto","target":int}
    {"s":"break"} | {"s":"continue"}
    {"s":"assign","var":Expr,"value":Expr}
    {"s":"expr","value":Expr}
    {"s":"if","cond":Expr,"then":[Stmt],"else":[Stmt]}
    {"s":"while","cond":Expr,"body":[Stmt]}
    {"s":"block","body":[Stmt]}
"""

import json
import sys
from collections import defaultdict


# ---------- Type ----------

def validator_type_byte_size(ty):
    k = ty.get("kind")
    if k == "int":
        return ty["bits"] // 8
    if k == "ptr":
        return ty["bits"] // 8
    if k == "float":
        return 4
    if k == "double":
        return 8
    if k == "bool":
        return 1
    if k == "void":
        return None
    if k == "array":
        if ty.get("len") is None:
            return None
        es = validator_type_byte_size(ty["elem"])
        if es is None:
            return None
        return es * ty["len"]
    return None  # struct, unknown


def validator_type_is_pointer(ty):
    return ty.get("kind") == "ptr"


def validator_type_is_integer(ty):
    return ty.get("kind") == "int"


def _make_int(signed, bits):
    return {"kind": "int", "signed": signed, "bits": bits}


def validator_type_i8():  return _make_int(True, 8)
def validator_type_i16(): return _make_int(True, 16)
def validator_type_i32(): return _make_int(True, 32)
def validator_type_i64(): return _make_int(True, 64)
def validator_type_u8():  return _make_int(False, 8)
def validator_type_u16(): return _make_int(False, 16)
def validator_type_u32(): return _make_int(False, 32)
def validator_type_u64(): return _make_int(False, 64)


def validator_type_ptr(pointee, bits=64):
    return {"kind": "ptr", "pointee": pointee, "bits": bits}


# ---------- Expr ----------

_BIN_ARITH = {"add", "sub", "mul", "div", "and", "or", "xor", "shl", "shr"}
_BIN_CMP = {"eq", "ne", "lt", "le", "gt", "ge"}


def validator_expr_type(expr):
    op = expr.get("op")
    if op in _BIN_CMP:
        return {"kind": "bool"}
    if op == "sizeof":
        return validator_type_u64()
    return expr.get("ty", {"kind": "unknown"})


def validator_expr_is_const(expr):
    if expr.get("op") == "const":
        return expr.get("value")
    return None


def validator_expr_is_const_zero(expr):
    v = validator_expr_is_const(expr)
    return v == 0


def _walk_expr_kids(expr):
    op = expr.get("op")
    if op in _BIN_ARITH or op in _BIN_CMP:
        yield expr["lhs"]
        yield expr["rhs"]
    elif op == "call":
        for a in expr.get("args", []):
            yield a
    elif op in ("deref", "addr"):
        yield expr["arg"]


def validator_expr_uses_var(expr, var_name, depth=0):
    if depth > 512:
        return False
    if expr.get("op") == "var" and expr.get("name") == var_name:
        return True
    for k in _walk_expr_kids(expr):
        if validator_expr_uses_var(k, var_name, depth + 1):
            return True
    return False


def validator_count_hlil_expr_nodes(expr):
    n = 1
    for k in _walk_expr_kids(expr):
        n += validator_count_hlil_expr_nodes(k)
    return n


def validator_expr_complexity(expr):
    return validator_count_hlil_expr_nodes(expr)


# expr_utils
def validator_exprutils_depth(expr):
    kids = list(_walk_expr_kids(expr))
    if not kids:
        return 1
    return 1 + max(validator_exprutils_depth(k) for k in kids)


def validator_exprutils_leaf_count(expr):
    kids = list(_walk_expr_kids(expr))
    if not kids:
        return 1
    return sum(validator_exprutils_leaf_count(k) for k in kids)


def validator_exprutils_is_constant(expr):
    return expr.get("op") == "const"


def validator_exprutils_is_variable(expr):
    return expr.get("op") == "var"


def validator_exprutils_is_simple(expr):
    # leaf or single-level op over leaves
    if expr.get("op") in ("const", "var"):
        return True
    kids = list(_walk_expr_kids(expr))
    return all(k.get("op") in ("const", "var") for k in kids)


# ---------- Constant folding ----------

def _fold_binop(op, a, b):
    if op == "add": return a + b
    if op == "sub": return a - b
    if op == "mul": return a * b
    if op == "div":
        if b == 0:
            return None
        # signed truncation toward zero (Rust i64 semantics)
        q = abs(a) // abs(b)
        return q if (a < 0) == (b < 0) else -q
    if op == "and": return a & b
    if op == "or":  return a | b
    if op == "xor": return a ^ b
    if op == "shl": return (a << b) & ((1 << 64) - 1)
    if op == "shr": return a >> b
    return None


def validator_fold_hlil_expr(expr):
    """Returns (folded_expr, rewrite_count)."""
    op = expr.get("op")
    rewrites = 0
    if op in _BIN_ARITH:
        l, rl = validator_fold_hlil_expr(expr["lhs"])
        r, rr = validator_fold_hlil_expr(expr["rhs"])
        rewrites = rl + rr
        if l.get("op") == "const" and r.get("op") == "const":
            v = _fold_binop(op, l["value"], r["value"])
            if v is not None:
                return ({"op": "const", "value": v,
                         "ty": expr.get("ty", validator_type_i64())},
                        rewrites + 1)
        return ({"op": op, "lhs": l, "rhs": r,
                 "ty": expr.get("ty", validator_type_i64())}, rewrites)
    if op in _BIN_CMP:
        l, rl = validator_fold_hlil_expr(expr["lhs"])
        r, rr = validator_fold_hlil_expr(expr["rhs"])
        return ({"op": op, "lhs": l, "rhs": r}, rl + rr)
    if op == "call":
        new_args = []
        for a in expr.get("args", []):
            fa, rc = validator_fold_hlil_expr(a)
            new_args.append(fa)
            rewrites += rc
        out = dict(expr)
        out["args"] = new_args
        return (out, rewrites)
    if op in ("deref", "addr"):
        a, rc = validator_fold_hlil_expr(expr["arg"])
        out = dict(expr)
        out["arg"] = a
        return (out, rc)
    return (expr, 0)


# ---------- Statements ----------

_TERMINATORS = {"return", "goto", "break", "continue"}


def validator_stmt_is_terminator(stmt):
    return stmt.get("s") in _TERMINATORS


def _stmt_children_lists(stmt):
    s = stmt.get("s")
    if s == "if":
        yield stmt.get("then", [])
        yield stmt.get("else", [])
    elif s == "while":
        yield stmt.get("body", [])
    elif s == "block":
        yield stmt.get("body", [])


def validator_stmt_contains_return(stmt):
    if stmt.get("s") == "return":
        return True
    for body in _stmt_children_lists(stmt):
        for c in body:
            if validator_stmt_contains_return(c):
                return True
    return False


def validator_body_always_returns(stmts):
    for st in stmts:
        if st.get("s") == "return":
            return True
        if st.get("s") == "if":
            t = st.get("then", [])
            e = st.get("else", [])
            if e and validator_body_always_returns(t) and validator_body_always_returns(e):
                return True
    return False


def validator_count_breaks_and_continues(stmts):
    br = co = 0
    for st in stmts:
        s = st.get("s")
        if s == "break":
            br += 1
        elif s == "continue":
            co += 1
        for body in _stmt_children_lists(st):
            b2, c2 = validator_count_breaks_and_continues(body)
            br += b2
            co += c2
    return (br, co)


def validator_collect_goto_targets(stmts):
    out = []
    for st in stmts:
        if st.get("s") == "goto":
            out.append(st["target"])
        for body in _stmt_children_lists(st):
            out.extend(validator_collect_goto_targets(body))
    return out


def validator_count_gotos(stmts):
    return len(validator_collect_goto_targets(stmts))


def validator_remove_dead_code_after_return(stmts):
    """Returns (new_stmts, removed_count). Removes statements after the first
    Return in the same block (non-recursive, matches the Rust pass which
    only operates on the top-level block passed to it)."""
    out = []
    removed = 0
    seen_return = False
    for st in stmts:
        if seen_return:
            removed += 1
            continue
        out.append(st)
        if st.get("s") == "return":
            seen_return = True
    return (out, removed)


def validator_remove_unreachable_after_terminator(stmts):
    out = []
    removed = 0
    seen = False
    for st in stmts:
        if seen:
            removed += 1
            continue
        out.append(st)
        if validator_stmt_is_terminator(st):
            seen = True
    return (out, removed)


# ---------- Function helpers ----------

def _walk_all_exprs(stmt):
    s = stmt.get("s")
    if s == "return" and stmt.get("value") is not None:
        yield stmt["value"]
    elif s in ("assign",):
        yield stmt["var"]
        yield stmt["value"]
    elif s == "expr":
        yield stmt["value"]
    elif s == "if":
        yield stmt["cond"]
    elif s == "while":
        yield stmt["cond"]


def _expr_collect_calls(expr, out):
    if expr.get("op") == "call":
        out.append(expr)
    for k in _walk_expr_kids(expr):
        _expr_collect_calls(k, out)


def _expr_collect_vars(expr, out):
    if expr.get("op") == "var":
        out.append(expr)
    for k in _walk_expr_kids(expr):
        _expr_collect_vars(k, out)


def _func_walk(stmts, fn):
    for st in stmts:
        for e in _walk_all_exprs(st):
            fn(e)
        for body in _stmt_children_lists(st):
            _func_walk(body, fn)


def validator_function_calls_made(func):
    calls = []
    _func_walk(func.get("body", []), lambda e: _expr_collect_calls(e, calls))
    return calls


def validator_function_vars_used(func):
    vs = []
    _func_walk(func.get("body", []), lambda e: _expr_collect_vars(e, vs))
    return vs


# ---------- Type submodule helpers ----------

def validator_array_total_size(elem_ty, length):
    if length is None:
        return None
    es = validator_type_byte_size(elem_ty)
    if es is None:
        return None
    return es * length


def validator_pointer_region_size(pointee_ty, count):
    es = validator_type_byte_size(pointee_ty)
    if es is None or count is None:
        return None
    return es * count


def validator_function_arity(params):
    return len(params)


def validator_function_call_compat(params, args, variadic=False):
    if variadic:
        return len(args) >= len(params)
    return len(args) == len(params)


# ---------- Graph algorithms (structuring) ----------

def validator_tarjan_scc(cfg):
    """cfg = {node: [succ, ...]}. Returns list of SCCs (lists of nodes).
    Order: Tarjan's iterative finish order (reverse topological)."""
    index = {}
    lowlink = {}
    on_stack = set()
    stack = []
    result = []
    counter = [0]

    def strongconnect(v):
        work = [(v, iter(cfg.get(v, [])))]
        index[v] = counter[0]
        lowlink[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on_stack.add(v)
        while work:
            node, it = work[-1]
            try:
                w = next(it)
                if w not in index:
                    index[w] = counter[0]
                    lowlink[w] = counter[0]
                    counter[0] += 1
                    stack.append(w)
                    on_stack.add(w)
                    work.append((w, iter(cfg.get(w, []))))
                elif w in on_stack:
                    lowlink[node] = min(lowlink[node], index[w])
            except StopIteration:
                work.pop()
                if lowlink[node] == index[node]:
                    comp = []
                    while True:
                        x = stack.pop()
                        on_stack.discard(x)
                        comp.append(x)
                        if x == node:
                            break
                    result.append(comp)
                if work:
                    parent = work[-1][0]
                    lowlink[parent] = min(lowlink[parent], lowlink[node])

    for v in list(cfg.keys()):
        if v not in index:
            strongconnect(v)
    return result


def validator_dominators(cfg, entry):
    """Cooper-Harvey-Kennedy iterative dominator algorithm.
    Returns {node: idom}. Entry's idom is itself."""
    # reverse postorder
    visited = set()
    order = []

    def dfs(u):
        stack = [(u, iter(cfg.get(u, [])))]
        visited.add(u)
        while stack:
            n, it = stack[-1]
            adv = False
            for w in it:
                if w not in visited:
                    visited.add(w)
                    stack.append((w, iter(cfg.get(w, []))))
                    adv = True
                    break
            if not adv:
                order.append(n)
                stack.pop()

    dfs(entry)
    rpo = list(reversed(order))
    rpo_index = {n: i for i, n in enumerate(rpo)}

    preds = defaultdict(list)
    for u, succs in cfg.items():
        for v in succs:
            preds[v].append(u)

    idom = {entry: entry}

    def intersect(b1, b2):
        finger1, finger2 = b1, b2
        while finger1 != finger2:
            while rpo_index[finger1] > rpo_index[finger2]:
                finger1 = idom[finger1]
            while rpo_index[finger2] > rpo_index[finger1]:
                finger2 = idom[finger2]
        return finger1

    changed = True
    while changed:
        changed = False
        for b in rpo:
            if b == entry:
                continue
            ps = [p for p in preds[b] if p in idom]
            if not ps:
                continue
            new_idom = ps[0]
            for p in ps[1:]:
                new_idom = intersect(p, new_idom)
            if idom.get(b) != new_idom:
                idom[b] = new_idom
                changed = True
    return idom


# ---------- Dispatcher ----------

DISPATCH = {
    "type_byte_size": lambda a: validator_type_byte_size(a["ty"]),
    "type_is_pointer": lambda a: validator_type_is_pointer(a["ty"]),
    "type_is_integer": lambda a: validator_type_is_integer(a["ty"]),
    "type_u32": lambda a: validator_type_u32(),
    "type_ptr": lambda a: validator_type_ptr(a["pointee"], a.get("bits", 64)),
    "expr_type": lambda a: validator_expr_type(a["expr"]),
    "expr_is_const": lambda a: validator_expr_is_const(a["expr"]),
    "expr_is_const_zero": lambda a: validator_expr_is_const_zero(a["expr"]),
    "expr_uses_var": lambda a: validator_expr_uses_var(a["expr"], a["var"]),
    "expr_complexity": lambda a: validator_expr_complexity(a["expr"]),
    "count_hlil_expr_nodes": lambda a: validator_count_hlil_expr_nodes(a["expr"]),
    "exprutils_depth": lambda a: validator_exprutils_depth(a["expr"]),
    "exprutils_leaf_count": lambda a: validator_exprutils_leaf_count(a["expr"]),
    "exprutils_is_constant": lambda a: validator_exprutils_is_constant(a["expr"]),
    "exprutils_is_variable": lambda a: validator_exprutils_is_variable(a["expr"]),
    "exprutils_is_simple": lambda a: validator_exprutils_is_simple(a["expr"]),
    "fold_hlil_expr": lambda a: validator_fold_hlil_expr(a["expr"]),
    "stmt_is_terminator": lambda a: validator_stmt_is_terminator(a["stmt"]),
    "stmt_contains_return": lambda a: validator_stmt_contains_return(a["stmt"]),
    "body_always_returns": lambda a: validator_body_always_returns(a["stmts"]),
    "count_breaks_and_continues": lambda a: validator_count_breaks_and_continues(a["stmts"]),
    "collect_goto_targets": lambda a: validator_collect_goto_targets(a["stmts"]),
    "count_gotos": lambda a: validator_count_gotos(a["stmts"]),
    "remove_dead_code_after_return": lambda a: validator_remove_dead_code_after_return(a["stmts"]),
    "remove_unreachable_after_terminator": lambda a: validator_remove_unreachable_after_terminator(a["stmts"]),
    "function_calls_made": lambda a: validator_function_calls_made(a["func"]),
    "function_vars_used": lambda a: validator_function_vars_used(a["func"]),
    "array_total_size": lambda a: validator_array_total_size(a["elem"], a.get("len")),
    "pointer_region_size": lambda a: validator_pointer_region_size(a["pointee"], a.get("count")),
    "function_arity": lambda a: validator_function_arity(a["params"]),
    "function_call_compat": lambda a: validator_function_call_compat(
        a["params"], a["args"], a.get("variadic", False)),
    "tarjan_scc": lambda a: validator_tarjan_scc(
        {int(k): v for k, v in a["cfg"].items()}),
    "dominators": lambda a: {str(k): v for k, v in validator_dominators(
        {int(k): v for k, v in a["cfg"].items()}, a["entry"]).items()},
}


def main():
    if not sys.stdin.isatty():
        try:
            payload = json.load(sys.stdin)
        except Exception:
            payload = None
        if payload:
            fn = payload.get("function")
            args = payload.get("input", {})
            if fn not in DISPATCH:
                print(json.dumps({"error": f"unknown function {fn}",
                                  "available": sorted(DISPATCH.keys())}))
                return
            out = DISPATCH[fn](args)
            print(json.dumps({"function": fn, "output": out}, default=str))
            return

    # Fixed self-test
    c2 = {"op": "const", "value": 2, "ty": validator_type_i64()}
    c3 = {"op": "const", "value": 3, "ty": validator_type_i64()}
    add = {"op": "add", "lhs": c2, "rhs": c3, "ty": validator_type_i64()}

    results = {
        "u32_byte_size": validator_type_byte_size(validator_type_u32()),
        "ptr64_byte_size": validator_type_byte_size(
            validator_type_ptr(validator_type_u8(), 64)),
        "array_u8_10_size": validator_type_byte_size(
            {"kind": "array", "elem": validator_type_u8(), "len": 10}),
        "fold_2_plus_3": validator_fold_hlil_expr(add),
        "node_count_add": validator_count_hlil_expr_nodes(add),
        "depth_add": validator_exprutils_depth(add),
        "leaves_add": validator_exprutils_leaf_count(add),
        "body_always_returns_ret": validator_body_always_returns(
            [{"s": "return", "value": None}]),
        "remove_after_return": validator_remove_dead_code_after_return([
            {"s": "return", "value": None},
            {"s": "expr", "value": c2},
        ]),
        "scc_simple": validator_tarjan_scc({0: [1], 1: [0], 2: [1]}),
        "dom_diamond": validator_dominators(
            {0: [1, 2], 1: [3], 2: [3], 3: []}, 0),
    }
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
