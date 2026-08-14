#!/usr/bin/env python3
"""Standalone Python validator for rustre-decompiler-type crate.

Reimplements the crate's pure-function semantics in stdlib Python so its
outputs can be compared against the Rust crate's outputs as ground truth.
No imports from the Rust crate, no MCP calls.
"""
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Optional


# -------- DecompType model --------

INT_WIDTHS = {"I8": (1, True), "I16": (2, True), "I32": (4, True), "I64": (8, True),
              "U8": (1, False), "U16": (2, False), "U32": (4, False), "U64": (8, False)}


@dataclass
class StructField:
    offset: int
    name: str
    ty: dict  # DecompType dict

    @staticmethod
    def new(offset, name, ty):
        return StructField(offset, name, ty)


@dataclass
class StructType:
    name: str
    fields: list
    total_size: int

    @staticmethod
    def new(name, fields, total_size):
        return StructType(name, fields, total_size)

    def field_at(self, offset: int) -> Optional[StructField]:
        for f in self.fields:
            sz = validator_byte_size(f.ty) or 0
            if sz == 0:
                continue
            if f.offset <= offset < f.offset + sz:
                return f
        return None

    def field_exact(self, offset: int) -> Optional[StructField]:
        for f in self.fields:
            if f.offset == offset:
                return f
        return None


# DecompType is encoded as a dict: {"kind": "Int", "width": "I32"} etc.

def _is_pointer(ty: dict) -> bool:
    return ty["kind"] in ("Ptr", "CStr", "FnPtr")


def validator_is_pointer(ty: dict) -> bool:
    return _is_pointer(ty)


def validator_pointee(ty: dict) -> Optional[dict]:
    if ty["kind"] == "Ptr":
        return ty["inner"]
    return None


def validator_byte_size(ty: dict) -> Optional[int]:
    return validator_byte_size_with_ptr_width(ty, 8)


def validator_byte_size_with_ptr_width(ty: dict, ptr_width: int) -> Optional[int]:
    k = ty["kind"]
    if k == "Void":
        return 0
    if k == "Bool":
        return 1
    if k == "Int":
        return INT_WIDTHS[ty["width"]][0]
    if k == "Float32":
        return 4
    if k == "Float64":
        return 8
    if k in ("Ptr", "CStr", "FnPtr"):
        return ptr_width
    if k == "Array":
        elem = validator_byte_size_with_ptr_width(ty["elem"], ptr_width)
        if elem is None:
            return None
        return elem * ty["n"]
    if k == "Struct":
        return ty["struct"].total_size
    if k == "Enum":
        return INT_WIDTHS[ty["backing"]][0]
    if k == "Unknown":
        return None
    return None


def validator_c_name(ty: dict) -> str:
    k = ty["kind"]
    if k == "Void":
        return "void"
    if k == "Bool":
        return "bool"
    if k == "Int":
        w = ty["width"]
        signed = INT_WIDTHS[w][1]
        bits = INT_WIDTHS[w][0] * 8
        return f"{'int' if signed else 'uint'}{bits}_t"
    if k == "Float32":
        return "float"
    if k == "Float64":
        return "double"
    if k == "Ptr":
        return f"{validator_c_name(ty['inner'])} *"
    if k == "Array":
        return f"{validator_c_name(ty['elem'])}[{ty['n']}]"
    if k == "Struct":
        return f"struct {ty['struct'].name}"
    if k == "FnPtr":
        return "void (*)(...)"
    if k == "CStr":
        return "char *"
    if k == "Enum":
        return f"enum {ty['name']}"
    if k == "Unknown":
        return "void *"
    return "?"


def validator_name_prefix(ty: dict) -> str:
    k = ty["kind"]
    if k == "Bool":
        return "b_"
    if k == "Int":
        return "i" if INT_WIDTHS[ty["width"]][1] else "u"
    if k == "Ptr":
        return "p_"
    if k == "CStr":
        return "sz_"
    if k in ("Float32", "Float64"):
        return "f_"
    if k == "Array":
        return "arr_"
    if k == "Struct":
        return "s_"
    if k == "FnPtr":
        return "pfn_"
    if k == "Enum":
        return "e_"
    return "v_"


# -------- TypeQualifier --------

NONE, CONST, VOLATILE, RESTRICT = 0, 1, 2, 4


def validator_qualifier_string(q: int) -> str:
    parts = []
    if q & CONST:
        parts.append("const")
    if q & VOLATILE:
        parts.append("volatile")
    if q & RESTRICT:
        parts.append("restrict")
    return " ".join(parts)


def validator_qualifier_predicates(q: int) -> dict:
    return {
        "is_const": bool(q & CONST),
        "is_volatile": bool(q & VOLATILE),
        "is_restrict": bool(q & RESTRICT),
    }


# -------- TypeEnvironment --------

class TypeEnvironment:
    def __init__(self):
        self.vars = {}
        self.structs = {}

    def set(self, var, ty):
        self.vars[var] = ty

    def get(self, var):
        return self.vars.get(var)

    def add_struct(self, s: StructType):
        self.structs[s.name] = s

    def struct_named(self, name):
        return self.structs.get(name)

    def resolve_struct(self, ty):
        if ty["kind"] == "Struct":
            return ty["struct"]
        return None


# -------- TypeAwareRenamer --------

class TypeAwareRenamer:
    def __init__(self):
        self.counters = {}

    def reset(self):
        self.counters = {}

    def rename(self, ty: dict) -> str:
        prefix = validator_name_prefix(ty)
        n = self.counters.get(prefix, 0)
        self.counters[prefix] = n + 1
        return f"{prefix}{n}"

    def rename_with_hint(self, hint: str, ty: dict) -> str:
        if hint.startswith("arg") or hint.startswith("param"):
            return hint
        return self.rename(ty)

    def rename_all(self, pairs):
        return {name: self.rename(ty) for name, ty in pairs}


def validator_rename_variables(code: str, env: TypeEnvironment) -> str:
    # Find all var_N identifiers
    vars_found = sorted(set(re.findall(r"\bvar_(\d+)\b", code)),
                        key=lambda x: -len(x))
    counter_idx = 0
    idx_chars = "ijklmnop"
    mapping = {}
    ptr_counter = 0
    for n in vars_found:
        name = f"var_{n}"
        ty = env.get(name)
        if ty is not None:
            new = TypeAwareRenamer().rename(ty)  # simplistic — single use
            mapping[name] = new
            continue
        # heuristics
        # malloc / new on RHS of assignment of this var
        if re.search(rf"\b{name}\s*=\s*(malloc\(|new\s)", code):
            mapping[name] = f"ptr_{ptr_counter}"
            ptr_counter += 1
            continue
        # ++/-- usage → loop index
        if re.search(rf"(\+\+|--){name}\b|\b{name}(\+\+|--)", code):
            ch = idx_chars[counter_idx % len(idx_chars)]
            mapping[name] = ch
            counter_idx += 1
            continue
        mapping[name] = f"v_{n}"
    out = code
    for old, new in sorted(mapping.items(), key=lambda kv: -len(kv[0])):
        out = re.sub(rf"\b{re.escape(old)}\b", new, out)
    return out


# -------- TypedExprEmitter (minimal subset) --------
# Expr node format: {"op": "...", ...}

def _const_str(v: int, width: int) -> str:
    if 0 <= v < 1000:
        return str(v)
    suffix = "ULL" if width == 64 else "U"
    return f"0x{v:X}{suffix}"


class TypedExprEmitter:
    def __init__(self, env: TypeEnvironment, ptr_size: int = 8):
        self.env = env
        self.ptr_size = ptr_size

    def emit(self, expr: dict) -> str:
        op = expr["op"]
        if op == "Var":
            return expr["name"]
        if op == "Const":
            return _const_str(expr["v"], expr.get("w", 64))
        if op == "Deref":
            inner = expr["inner"]
            if inner["op"] == "Var":
                ty = self.env.get(inner["name"])
                if ty and not _is_pointer(ty):
                    raise ValueError("DerefNonPointer")
            return f"*{self.emit(inner)}"
        if op == "AddrOf":
            return f"&{self.emit(expr['inner'])}"
        if op == "Neg":
            return f"-{self.emit(expr['inner'])}"
        if op == "Cast":
            return f"({expr['ty']}){self.emit(expr['inner'])}"
        if op == "Call":
            args = ",".join(self.emit(a) for a in expr["args"])
            return f"{expr['name']}({args})"
        if op == "Ternary":
            return f"({self.emit(expr['c'])} ? {self.emit(expr['t'])} : {self.emit(expr['f'])})"
        if op == "Phi":
            inc = ",".join(self.emit(a) for a in expr["incoming"])
            return f"phi({inc})"
        if op == "FieldAccess":
            base = expr["base"]
            off = expr["offset"]
            base_str = self.emit(base)
            if base["op"] == "Var":
                ty = self.env.get(base["name"])
                if ty:
                    st = self.env.resolve_struct(ty) if ty["kind"] == "Struct" else (
                        self.env.resolve_struct(ty["inner"]) if ty["kind"] == "Ptr" and ty["inner"]["kind"] == "Struct" else None)
                    if st:
                        f = st.field_exact(off)
                        if f is None:
                            raise ValueError("NoFieldAtOffset")
                        sep = "->" if ty["kind"] == "Ptr" else "."
                        return f"{base_str}{sep}{f.name}"
            return f"FIELD({base_str}, 0x{off:X})"
        if op == "Add":
            l, r = expr["l"], expr["r"]
            # var + const_offset
            if l["op"] == "Var" and r["op"] == "Const":
                ty = self.env.get(l["name"])
                off = r["v"]
                if off == 0:
                    return f"*{l['name']}"
                if ty and ty["kind"] == "Ptr" and ty["inner"]["kind"] == "Struct":
                    st = ty["inner"]["struct"]
                    f = st.field_exact(off)
                    if f is None and off == 0 and st.fields:
                        f = st.fields[0]
                    if f is not None:
                        return f"{l['name']}->{f.name}"
            # base + index*elem_size
            if l["op"] == "Var" and r["op"] == "Mul":
                ml, mr = r["l"], r["r"]
                if mr["op"] == "Const":
                    ty = self.env.get(l["name"])
                    if ty and ty["kind"] == "Ptr":
                        elem_sz = validator_byte_size(ty["inner"])
                        if elem_sz == mr["v"]:
                            return f"{l['name']}[{self.emit(ml)}]"
            if l["op"] == "Var" and r["op"] == "Shl":
                sl, sr = r["l"], r["r"]
                if sr["op"] == "Const":
                    ty = self.env.get(l["name"])
                    if ty and ty["kind"] == "Ptr":
                        elem_sz = validator_byte_size(ty["inner"])
                        if elem_sz == (1 << sr["v"]):
                            return f"{l['name']}[{self.emit(sl)}]"
            return f"({self.emit(l)} + {self.emit(r)})"
        if op == "Mul":
            return f"({self.emit(expr['l'])} * {self.emit(expr['r'])})"
        if op == "Shl":
            return f"({self.emit(expr['l'])} << {self.emit(expr['r'])})"
        return f"?{op}?"


# -------- main / test harness --------

def main():
    if not sys.stdin.isatty():
        try:
            req = json.load(sys.stdin)
        except Exception:
            req = {}
    else:
        req = {}

    results = {}

    # 1. byte_size table
    cases = [
        ({"kind": "Int", "width": "I32"}, 4),
        ({"kind": "Ptr", "inner": {"kind": "Void"}}, 8),
        ({"kind": "Array", "elem": {"kind": "Int", "width": "I32"}, "n": 10}, 40),
        ({"kind": "Float64"}, 8),
        ({"kind": "Enum", "name": "E", "variants": [], "backing": "U16"}, 2),
        ({"kind": "Bool"}, 1),
        ({"kind": "CStr"}, 8),
        ({"kind": "Unknown"}, None),
    ]
    results["byte_size"] = [
        {"in": str(t), "expected": exp, "got": validator_byte_size(t)}
        for t, exp in cases
    ]

    # 2. byte_size ptr_width=4
    results["byte_size_ptr4"] = validator_byte_size_with_ptr_width(
        {"kind": "Ptr", "inner": {"kind": "Void"}}, 4)

    # 3. c_name
    cname_cases = [
        ({"kind": "Int", "width": "I32"}, "int32_t"),
        ({"kind": "Ptr", "inner": {"kind": "Int", "width": "I32"}}, "int32_t *"),
        ({"kind": "Array", "elem": {"kind": "Int", "width": "I32"}, "n": 10}, "int32_t[10]"),
        ({"kind": "CStr"}, "char *"),
        ({"kind": "Unknown"}, "void *"),
    ]
    results["c_name"] = [
        {"expected": exp, "got": validator_c_name(t)} for t, exp in cname_cases
    ]

    # 4. StructType.field_at / field_exact
    i32 = {"kind": "Int", "width": "I32"}
    pvoid = {"kind": "Ptr", "inner": {"kind": "Void"}}
    st = StructType.new("Node", [
        StructField.new(0, "value", i32),
        StructField.new(8, "next", pvoid),
    ], 16)
    results["field_at"] = {
        "at_0": st.field_at(0).name if st.field_at(0) else None,
        "at_4": st.field_at(4).name if st.field_at(4) else None,  # within i32? size=4 so [0,4) → None
        "at_8": st.field_at(8).name if st.field_at(8) else None,
        "exact_0": st.field_exact(0).name if st.field_exact(0) else None,
        "exact_4": st.field_exact(4).name if st.field_exact(4) else None,
    }

    # 5. TypeQualifier
    results["qualifier"] = {
        "const_volatile": validator_qualifier_string(CONST | VOLATILE),
        "all": validator_qualifier_string(CONST | VOLATILE | RESTRICT),
        "preds_const": validator_qualifier_predicates(CONST),
    }

    # 6. TypeAwareRenamer
    r = TypeAwareRenamer()
    names = [r.rename(i32), r.rename(i32), r.rename(pvoid)]
    results["renamer"] = {
        "seq": names,
        "hint_arg": r.rename_with_hint("arg0", i32),
        "hint_other": r.rename_with_hint("foo", i32),
    }

    # 7. rename_variables
    env = TypeEnvironment()
    code = "var_0 = malloc(8); for(var_1=0; var_1<10; ++var_1) { f(var_0); }"
    results["rename_variables"] = validator_rename_variables(code, env)

    # 8. TypedExprEmitter
    env2 = TypeEnvironment()
    node_struct = StructType.new("Node", [
        StructField.new(0, "value", i32),
        StructField.new(8, "next", pvoid),
    ], 16)
    env2.add_struct(node_struct)
    node_ty = {"kind": "Ptr", "inner": {"kind": "Struct", "struct": node_struct}}
    env2.set("node", node_ty)
    arr_ty = {"kind": "Ptr", "inner": {"kind": "Int", "width": "I32"}}
    env2.set("arr", arr_ty)
    env2.set("p", arr_ty)
    em = TypedExprEmitter(env2)

    e_node_plus_8 = {"op": "Add", "l": {"op": "Var", "name": "node"},
                     "r": {"op": "Const", "v": 8, "w": 64}}
    e_arr_index = {"op": "Add", "l": {"op": "Var", "name": "arr"},
                   "r": {"op": "Mul",
                         "l": {"op": "Var", "name": "i"},
                         "r": {"op": "Const", "v": 4, "w": 64}}}
    e_deref = {"op": "Deref", "inner": {"op": "Var", "name": "p"}}
    e_call = {"op": "Call", "name": "foo",
              "args": [{"op": "Const", "v": 1, "w": 32},
                       {"op": "Var", "name": "x"}]}

    results["emitter"] = {
        "node_plus_8": em.emit(e_node_plus_8),
        "arr_plus_i_mul_4": em.emit(e_arr_index),
        "deref_p": em.emit(e_deref),
        "call": em.emit(e_call),
    }

    # DerefNonPointer
    env2.set("notptr", i32)
    try:
        em.emit({"op": "Deref", "inner": {"op": "Var", "name": "notptr"}})
        results["emitter"]["deref_nonptr"] = "no_error"
    except ValueError as e:
        results["emitter"]["deref_nonptr"] = str(e)

    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
