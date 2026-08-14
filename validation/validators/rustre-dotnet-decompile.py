#!/usr/bin/env python3
"""Independent validator for rustre-dotnet-decompile.

Validates pure data-in/data-out helpers documented in the report:
- is_closure_class
- infer_type_from_element (ECMA-335 ELEMENT_TYPE_*)
- stack_effect (subset of CIL opcodes)
- simplify_expr (whitespace/paren simplification)
- detect_linq_chains (basic chain detection from call sites)
- find_state_switch (locates 'switch' opcode in IL stream)
"""

import json
import sys


# --- ECMA-335 II.23.1.16 element types ---
ELEMENT_TYPES = {
    0x01: "Void", 0x02: "Boolean", 0x03: "Char",
    0x04: "I1", 0x05: "U1", 0x06: "I2", 0x07: "U2",
    0x08: "I4", 0x09: "U4", 0x0A: "I8", 0x0B: "U8",
    0x0C: "R4", 0x0D: "R8", 0x0E: "String", 0x0F: "Ptr",
    0x10: "ByRef", 0x11: "ValueType", 0x12: "Class",
    0x13: "Var", 0x14: "Array", 0x15: "GenericInst",
    0x16: "TypedByRef", 0x18: "I", 0x19: "U",
    0x1B: "FnPtr", 0x1C: "Object", 0x1D: "SzArray",
    0x1E: "MVar",
}


def infer_type_from_element(et):
    return ELEMENT_TYPES.get(et, "Unknown")


def is_closure_class(name):
    if not name:
        return False
    # Roslyn closure class naming
    return "<>c__DisplayClass" in name or name.startswith("<>c") or "<>c" in name


# CIL stack-effect table (subset). Format: (pop, push) or "var" for variable.
STACK_EFFECT = {
    "nop": (0, 0), "break": (0, 0),
    "ldarg.0": (0, 1), "ldarg.1": (0, 1), "ldarg.2": (0, 1), "ldarg.3": (0, 1),
    "ldarg": (0, 1), "ldarg.s": (0, 1), "ldarga": (0, 1), "ldarga.s": (0, 1),
    "starg": (1, 0), "starg.s": (1, 0),
    "ldloc.0": (0, 1), "ldloc.1": (0, 1), "ldloc.2": (0, 1), "ldloc.3": (0, 1),
    "ldloc": (0, 1), "ldloc.s": (0, 1), "ldloca": (0, 1), "ldloca.s": (0, 1),
    "stloc.0": (1, 0), "stloc.1": (1, 0), "stloc.2": (1, 0), "stloc.3": (1, 0),
    "stloc": (1, 0), "stloc.s": (1, 0),
    "ldnull": (0, 1),
    "ldc.i4.m1": (0, 1), "ldc.i4.0": (0, 1), "ldc.i4.1": (0, 1),
    "ldc.i4.2": (0, 1), "ldc.i4.3": (0, 1), "ldc.i4.4": (0, 1),
    "ldc.i4.5": (0, 1), "ldc.i4.6": (0, 1), "ldc.i4.7": (0, 1),
    "ldc.i4.8": (0, 1), "ldc.i4": (0, 1), "ldc.i4.s": (0, 1),
    "ldc.i8": (0, 1), "ldc.r4": (0, 1), "ldc.r8": (0, 1),
    "ldstr": (0, 1),
    "dup": (1, 2), "pop": (1, 0),
    "ret": (0, 0),  # variable, depends on signature; pure stack 0/0 baseline
    "add": (2, 1), "sub": (2, 1), "mul": (2, 1), "div": (2, 1),
    "div.un": (2, 1), "rem": (2, 1), "rem.un": (2, 1),
    "and": (2, 1), "or": (2, 1), "xor": (2, 1),
    "shl": (2, 1), "shr": (2, 1), "shr.un": (2, 1),
    "neg": (1, 1), "not": (1, 1),
    "ceq": (2, 1), "cgt": (2, 1), "cgt.un": (2, 1),
    "clt": (2, 1), "clt.un": (2, 1),
    "br": (0, 0), "br.s": (0, 0),
    "brfalse": (1, 0), "brfalse.s": (1, 0),
    "brtrue": (1, 0), "brtrue.s": (1, 0),
    "beq": (2, 0), "beq.s": (2, 0),
    "bne.un": (2, 0), "bne.un.s": (2, 0),
    "bge": (2, 0), "bge.s": (2, 0), "bgt": (2, 0), "bgt.s": (2, 0),
    "ble": (2, 0), "ble.s": (2, 0), "blt": (2, 0), "blt.s": (2, 0),
    "switch": (1, 0),
    "throw": (1, 0), "rethrow": (0, 0),
    "newobj": (0, 1),  # pops args, simplified
    "newarr": (1, 1),
    "ldlen": (1, 1),
    "ldelem.i1": (2, 1), "ldelem.i2": (2, 1), "ldelem.i4": (2, 1),
    "ldelem.i8": (2, 1), "ldelem.u1": (2, 1), "ldelem.u2": (2, 1),
    "ldelem.u4": (2, 1), "ldelem.r4": (2, 1), "ldelem.r8": (2, 1),
    "ldelem.ref": (2, 1), "ldelem": (2, 1), "ldelema": (2, 1),
    "stelem.i": (3, 0), "stelem.i1": (3, 0), "stelem.i2": (3, 0),
    "stelem.i4": (3, 0), "stelem.i8": (3, 0), "stelem.r4": (3, 0),
    "stelem.r8": (3, 0), "stelem.ref": (3, 0), "stelem": (3, 0),
    "ldfld": (1, 1), "ldflda": (1, 1), "stfld": (2, 0),
    "ldsfld": (0, 1), "ldsflda": (0, 1), "stsfld": (1, 0),
    "box": (1, 1), "unbox": (1, 1), "unbox.any": (1, 1),
    "castclass": (1, 1), "isinst": (1, 1),
    "conv.i1": (1, 1), "conv.i2": (1, 1), "conv.i4": (1, 1),
    "conv.i8": (1, 1), "conv.r4": (1, 1), "conv.r8": (1, 1),
    "conv.u1": (1, 1), "conv.u2": (1, 1), "conv.u4": (1, 1),
    "conv.u8": (1, 1), "conv.i": (1, 1), "conv.u": (1, 1),
    "ldtoken": (0, 1),
}


def stack_effect(opcode):
    return STACK_EFFECT.get(opcode.lower())


def simplify_expr(expr):
    s = " ".join(expr.split())
    # strip redundant outer parens
    while len(s) >= 2 and s.startswith("(") and s.endswith(")"):
        depth = 0
        balanced = True
        for i, c in enumerate(s):
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0 and i != len(s) - 1:
                    balanced = False
                    break
        if balanced:
            s = s[1:-1].strip()
        else:
            break
    return s


LINQ_METHODS = {
    "Select", "Where", "GroupBy", "OrderBy", "OrderByDescending",
    "ThenBy", "ThenByDescending", "Join", "GroupJoin", "SelectMany",
    "Distinct", "Skip", "Take", "Concat", "Union", "Intersect",
    "Except", "First", "FirstOrDefault", "Single", "SingleOrDefault",
    "Any", "All", "Count", "Sum", "Min", "Max", "Average",
    "ToList", "ToArray", "ToDictionary", "Aggregate",
}


def detect_linq_chains(call_sites):
    """call_sites: list of dicts with 'method' and 'receiver' (id) fields.
    Returns list of chains (lists of method names) where each call's receiver is the prev call id."""
    by_id = {c.get("id"): c for c in call_sites if "id" in c}
    # find chain heads: linq calls whose receiver is NOT another linq call
    chains = []
    used = set()
    # build forward index: receiver_id -> [calls]
    forward = {}
    for c in call_sites:
        r = c.get("receiver")
        forward.setdefault(r, []).append(c)

    def walk(node, acc):
        acc.append(node["method"])
        used.add(node.get("id"))
        for nxt in forward.get(node.get("id"), []):
            if nxt["method"] in LINQ_METHODS:
                walk(nxt, acc)
                return
        return

    for c in call_sites:
        if c.get("id") in used:
            continue
        if c["method"] not in LINQ_METHODS:
            continue
        parent = by_id.get(c.get("receiver"))
        if parent and parent.get("method") in LINQ_METHODS:
            continue  # not a head
        acc = []
        walk(c, acc)
        if len(acc) >= 1:
            chains.append(acc)
    return chains


def find_state_switch(insns):
    """insns: list of {'offset': int, 'op': str, 'targets': [int]} returns (idx, targets) or None."""
    for i, ins in enumerate(insns):
        if ins.get("op", "").lower() == "switch":
            return (i, list(ins.get("targets", [])))
    return None


# ---- self-tests ----
def run_tests():
    results = []

    def check(name, cond):
        results.append((name, bool(cond)))

    # element types
    check("et_void", infer_type_from_element(0x01) == "Void")
    check("et_i4", infer_type_from_element(0x08) == "I4")
    check("et_string", infer_type_from_element(0x0E) == "String")
    check("et_object", infer_type_from_element(0x1C) == "Object")
    check("et_unknown", infer_type_from_element(0xFF) == "Unknown")

    # closure
    check("closure_yes", is_closure_class("<>c__DisplayClass1_0"))
    check("closure_c", is_closure_class("<>c"))
    check("closure_no", not is_closure_class("MyClass"))
    check("closure_empty", not is_closure_class(""))

    # stack effect
    check("se_nop", stack_effect("nop") == (0, 0))
    check("se_add", stack_effect("add") == (2, 1))
    check("se_dup", stack_effect("dup") == (1, 2))
    check("se_pop", stack_effect("pop") == (1, 0))
    check("se_ldstr", stack_effect("ldstr") == (0, 1))
    check("se_unknown", stack_effect("bogus.op") is None)
    check("se_case", stack_effect("LDC.I4.0") == (0, 1))

    # simplify_expr
    check("simp_ws", simplify_expr("  a  +  b  ") == "a + b")
    check("simp_parens", simplify_expr("((x + y))") == "x + y")
    check("simp_nopar", simplify_expr("(a) + (b)") == "(a) + (b)")

    # linq chains
    cs = [
        {"id": 1, "method": "Where", "receiver": 0},
        {"id": 2, "method": "Select", "receiver": 1},
        {"id": 3, "method": "ToList", "receiver": 2},
        {"id": 4, "method": "Foo", "receiver": 0},
    ]
    chains = detect_linq_chains(cs)
    check("linq_one_chain", len(chains) == 1)
    check("linq_chain_order", chains[0] == ["Where", "Select", "ToList"])

    # state switch
    insns = [
        {"offset": 0, "op": "ldloc.0"},
        {"offset": 2, "op": "switch", "targets": [10, 20, 30]},
        {"offset": 12, "op": "ret"},
    ]
    fs = find_state_switch(insns)
    check("switch_found", fs is not None and fs[0] == 1 and fs[1] == [10, 20, 30])
    check("switch_none", find_state_switch([{"op": "nop"}]) is None)

    return results


def main():
    tests = run_tests()
    failed = [n for n, ok in tests if not ok]
    out = {
        "crate": "rustre-dotnet-decompile",
        "total": len(tests),
        "passed": len(tests) - len(failed),
        "failed": failed,
    }
    print(json.dumps(out, indent=2))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
