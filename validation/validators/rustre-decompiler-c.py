#!/usr/bin/env python3
"""
Independent Python validator for rustre-decompiler-c crate.
Reimplements golden string-formatting logic without calling the Rust crate or MCP.
"""
import json
import sys
from typing import List, Tuple, Optional, Dict, Any


# ---------------------------------------------------------------------------
# format_for_header(condition) -> str
#   - "init;cond;step" (exactly 3 parts) => "init; cond; step"
#   - else                                => "; <cond>; "
# ---------------------------------------------------------------------------
def validator_format_for_header(condition: str) -> str:
    parts = condition.split(";")
    if len(parts) == 3:
        return f"{parts[0]}; {parts[1]}; {parts[2]}"
    return f"; {condition}; "


# ---------------------------------------------------------------------------
# c_precedence_for_op(op) -> int
#   C operator precedence table (higher binds tighter).
# ---------------------------------------------------------------------------
_C_PRECEDENCE = {
    ",": 1,
    "=": 2, "+=": 2, "-=": 2, "*=": 2, "/=": 2, "%=": 2,
    "<<=": 2, ">>=": 2, "&=": 2, "^=": 2, "|=": 2,
    "?:": 3,
    "||": 4,
    "&&": 5,
    "|": 6,
    "^": 7,
    "&": 8,
    "==": 9, "!=": 9,
    "<": 10, "<=": 10, ">": 10, ">=": 10,
    "<<": 11, ">>": 11,
    "+": 12, "-": 12,
    "*": 13, "/": 13, "%": 13,
}


def validator_c_precedence_for_op(op: str) -> int:
    return _C_PRECEDENCE.get(op, 0)


# ---------------------------------------------------------------------------
# FunctionSignature::as_c_declaration
# ---------------------------------------------------------------------------
def validator_signature_as_c_declaration(
    name: str, return_type: str, params: List[Tuple[str, str]], variadic: bool = False
) -> str:
    params_str = ", ".join(f"{ty} {p}" for (p, ty) in params)
    if variadic:
        params_str = (params_str + ", ...") if params_str else "..."
    return f"{return_type} {name}({params_str})"


# ---------------------------------------------------------------------------
# VarDecl::as_c_declaration
# ---------------------------------------------------------------------------
def validator_vardecl_as_c_declaration(name: str, ty: str, init: Optional[str] = None) -> str:
    if init is None:
        return f"{ty} {name}"
    return f"{ty} {name} = {init}"


# ---------------------------------------------------------------------------
# CPrinter::emit_const(value, width, notation) -> str
#   - Decimal       : str(value)
#   - Hex           : "0x{X}"   (uppercase, no prefix mask)
#   - HexPrefixed   : "0x{X}"
#   - Auto          : 0..=999 decimal; negative i64 decimal; else width-masked hex + 'U'
# ---------------------------------------------------------------------------
_WIDTH_MASKS = {8: 0xFF, 16: 0xFFFF, 32: 0xFFFFFFFF, 64: 0xFFFFFFFFFFFFFFFF}


def validator_emit_const(value: int, width: int = 32, notation: str = "Auto") -> str:
    if notation == "Decimal":
        return str(value)
    if notation in ("Hex", "HexPrefixed"):
        # uppercase hex with 0x prefix
        v = value & _WIDTH_MASKS.get(width, 0xFFFFFFFF) if value < 0 else value
        return f"0x{v:X}"
    # Auto
    if 0 <= value <= 999:
        return str(value)
    if value < 0:
        return str(value)
    mask = _WIDTH_MASKS.get(width, 0xFFFFFFFF)
    return f"0x{(value & mask):X}U"


# ---------------------------------------------------------------------------
# emit_struct_def(name, fields=[(ty, field, offset)]) -> str
# ---------------------------------------------------------------------------
def validator_emit_struct_def(name: str, fields: List[Tuple[str, str, int]]) -> str:
    lines = [f"struct {name} {{"]
    for ty, fname, off in fields:
        lines.append(f"    {ty} {fname};  /* offset: 0x{off:X} */")
    lines.append("};")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CTypeDeclaration::emit_struct / emit_typedef / emit_enum
# ---------------------------------------------------------------------------
def validator_emit_struct(name: str, fields: List[Tuple[str, str]]) -> str:
    body = "".join(f"    {ty} {f};\n" for (ty, f) in fields)
    return f"struct {name} {{\n{body}}};"


def validator_emit_typedef(alias: str, ty: str) -> str:
    return f"typedef {ty} {alias};"


def validator_emit_enum(name: str, variants: List[Tuple[str, int]]) -> str:
    body = "".join(f"    {v} = {n},\n" for (v, n) in variants)
    return f"enum {name} {{\n{body}}};"


# ---------------------------------------------------------------------------
# CFlowEmitter — single control-flow constructs
# ---------------------------------------------------------------------------
def _ind(indent: int) -> str:
    return " " * indent


def validator_emit_if(cond: str, body: str, indent: int = 0) -> str:
    i = _ind(indent)
    return f"{i}if ({cond}) {{\n{body}\n{i}}}"


def validator_emit_if_else(cond: str, then_body: str, else_body: str, indent: int = 0) -> str:
    i = _ind(indent)
    return f"{i}if ({cond}) {{\n{then_body}\n{i}}} else {{\n{else_body}\n{i}}}"


def validator_emit_while(cond: str, body: str, indent: int = 0) -> str:
    i = _ind(indent)
    return f"{i}while ({cond}) {{\n{body}\n{i}}}"


def validator_emit_do_while(cond: str, body: str, indent: int = 0) -> str:
    i = _ind(indent)
    return f"{i}do {{\n{body}\n{i}}} while ({cond});"


def validator_emit_for(init: str, cond: str, step: str, body: str, indent: int = 0) -> str:
    i = _ind(indent)
    return f"{i}for ({init}; {cond}; {step}) {{\n{body}\n{i}}}"


def validator_emit_switch(expr: str, cases: List[Tuple[str, str]], indent: int = 0) -> str:
    i = _ind(indent)
    inner = "".join(f"{i}    case {k}:\n{v}\n{i}        break;\n" for (k, v) in cases)
    return f"{i}switch ({expr}) {{\n{inner}{i}}}"


# ---------------------------------------------------------------------------
# CMacroExpander — substring replace
# ---------------------------------------------------------------------------
def validator_macro_expand(defines: Dict[str, str], code: str) -> str:
    out = code
    for name, repl in defines.items():
        out = out.replace(name, repl)
    return out


# ---------------------------------------------------------------------------
# CIncludeManager — emit + add_for_function
# ---------------------------------------------------------------------------
_FN_HEADER_MAP = {
    "malloc": "stdlib.h", "free": "stdlib.h", "calloc": "stdlib.h", "realloc": "stdlib.h",
    "printf": "stdio.h", "fprintf": "stdio.h", "sprintf": "stdio.h", "puts": "stdio.h",
    "fopen": "stdio.h", "fclose": "stdio.h", "fread": "stdio.h", "fwrite": "stdio.h",
    "strlen": "string.h", "strcpy": "string.h", "strncpy": "string.h",
    "strcmp": "string.h", "strncmp": "string.h", "strcat": "string.h",
    "memcpy": "string.h", "memset": "string.h", "memmove": "string.h", "memcmp": "string.h",
    "open": "unistd.h", "close": "unistd.h", "read": "unistd.h", "write": "unistd.h",
}


def validator_header_for_function(fn: str) -> Optional[str]:
    return _FN_HEADER_MAP.get(fn)


def validator_include_emit(system: List[str], local: List[str]) -> str:
    parts = [f"#include <{h}>" for h in system] + [f'#include "{h}"' for h in local]
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# CStatement::render — recursive pretty-printer, 4-space indent, depth-guarded
# ---------------------------------------------------------------------------
MAX_RENDER_DEPTH = 256


def validator_render_cstatement(stmt: Dict[str, Any], indent: int = 0, depth: int = 0) -> str:
    if depth > MAX_RENDER_DEPTH:
        return _ind(indent) + "/* depth limit */"
    pad = "    " * indent
    kind = stmt.get("kind")
    if kind == "Break":
        return f"{pad}break;"
    if kind == "Continue":
        return f"{pad}continue;"
    if kind == "Return":
        v = stmt.get("value")
        return f"{pad}return{(' ' + v) if v else ''};"
    if kind == "Goto":
        return f"{pad}goto {stmt['label']};"
    if kind == "Label":
        return f"{pad}{stmt['name']}:"
    if kind == "ExprStmt":
        return f"{pad}{stmt['expr']};"
    if kind == "Assign":
        return f"{pad}{stmt['target']} = {stmt['value']};"
    if kind == "DeclAssign":
        return f"{pad}{stmt['ty']} {stmt['name']} = {stmt['value']};"
    if kind == "Raw":
        return f"{pad}{stmt['text']}"
    if kind == "Block":
        inner = "\n".join(
            validator_render_cstatement(s, indent + 1, depth + 1) for s in stmt.get("stmts", [])
        )
        return f"{pad}{{\n{inner}\n{pad}}}"
    if kind == "If":
        body = "\n".join(
            validator_render_cstatement(s, indent + 1, depth + 1) for s in stmt.get("then", [])
        )
        return f"{pad}if ({stmt['cond']}) {{\n{body}\n{pad}}}"
    if kind == "While":
        body = "\n".join(
            validator_render_cstatement(s, indent + 1, depth + 1) for s in stmt.get("body", [])
        )
        return f"{pad}while ({stmt['cond']}) {{\n{body}\n{pad}}}"
    if kind == "DoWhile":
        body = "\n".join(
            validator_render_cstatement(s, indent + 1, depth + 1) for s in stmt.get("body", [])
        )
        return f"{pad}do {{\n{body}\n{pad}}} while ({stmt['cond']});"
    if kind == "For":
        body = "\n".join(
            validator_render_cstatement(s, indent + 1, depth + 1) for s in stmt.get("body", [])
        )
        return f"{pad}for ({stmt['init']}; {stmt['cond']}; {stmt['step']}) {{\n{body}\n{pad}}}"
    return f"{pad}/* unknown stmt */"


# ---------------------------------------------------------------------------
# Brace-balance utility used by property tests on rendered output.
# ---------------------------------------------------------------------------
def validator_brace_balance(s: str) -> int:
    depth = 0
    for ch in s:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
    return depth


# ---------------------------------------------------------------------------
# main: JSON via stdin -> dispatch; or fixed self-tests if no stdin input.
# ---------------------------------------------------------------------------
DISPATCH = {
    "format_for_header": lambda a: validator_format_for_header(a["condition"]),
    "c_precedence_for_op": lambda a: validator_c_precedence_for_op(a["op"]),
    "signature_as_c_declaration": lambda a: validator_signature_as_c_declaration(
        a["name"], a["return_type"], [tuple(p) for p in a["params"]], a.get("variadic", False)
    ),
    "vardecl_as_c_declaration": lambda a: validator_vardecl_as_c_declaration(
        a["name"], a["ty"], a.get("init")
    ),
    "emit_const": lambda a: validator_emit_const(a["value"], a.get("width", 32), a.get("notation", "Auto")),
    "emit_struct_def": lambda a: validator_emit_struct_def(
        a["name"], [tuple(f) for f in a["fields"]]
    ),
    "emit_struct": lambda a: validator_emit_struct(a["name"], [tuple(f) for f in a["fields"]]),
    "emit_typedef": lambda a: validator_emit_typedef(a["alias"], a["ty"]),
    "emit_enum": lambda a: validator_emit_enum(a["name"], [tuple(v) for v in a["variants"]]),
    "emit_if": lambda a: validator_emit_if(a["cond"], a["body"], a.get("indent", 0)),
    "emit_if_else": lambda a: validator_emit_if_else(
        a["cond"], a["then_body"], a["else_body"], a.get("indent", 0)
    ),
    "emit_while": lambda a: validator_emit_while(a["cond"], a["body"], a.get("indent", 0)),
    "emit_do_while": lambda a: validator_emit_do_while(a["cond"], a["body"], a.get("indent", 0)),
    "emit_for": lambda a: validator_emit_for(
        a["init"], a["cond"], a["step"], a["body"], a.get("indent", 0)
    ),
    "emit_switch": lambda a: validator_emit_switch(
        a["expr"], [tuple(c) for c in a["cases"]], a.get("indent", 0)
    ),
    "macro_expand": lambda a: validator_macro_expand(a["defines"], a["code"]),
    "header_for_function": lambda a: validator_header_for_function(a["fn"]),
    "include_emit": lambda a: validator_include_emit(a.get("system", []), a.get("local", [])),
    "render_cstatement": lambda a: validator_render_cstatement(a["stmt"], a.get("indent", 0)),
    "brace_balance": lambda a: validator_brace_balance(a["s"]),
}


def _selftest() -> Dict[str, Any]:
    results = {}
    results["format_for_header_3"] = validator_format_for_header("int i=0;i<n;i++")
    results["format_for_header_1"] = validator_format_for_header("x < y")
    results["prec_plus"] = validator_c_precedence_for_op("+")
    results["prec_or"] = validator_c_precedence_for_op("||")
    results["prec_eq"] = validator_c_precedence_for_op("==")
    results["sig"] = validator_signature_as_c_declaration(
        "foo", "int", [("a", "int"), ("b", "char*")]
    )
    results["sig_variadic"] = validator_signature_as_c_declaration(
        "printf", "int", [("fmt", "const char*")], variadic=True
    )
    results["var_noinit"] = validator_vardecl_as_c_declaration("x", "int")
    results["var_init"] = validator_vardecl_as_c_declaration("x", "int", "42")
    results["const_dec"] = validator_emit_const(7, 32, "Auto")
    results["const_auto_big"] = validator_emit_const(0x1000, 32, "Auto")
    results["const_hex"] = validator_emit_const(255, 32, "Hex")
    results["const_neg"] = validator_emit_const(-1, 64, "Auto")
    results["struct_def"] = validator_emit_struct_def("S", [("int", "a", 0), ("char", "b", 4)])
    results["typedef"] = validator_emit_typedef("u32", "unsigned int")
    results["enum"] = validator_emit_enum("E", [("A", 0), ("B", 1)])
    results["if"] = validator_emit_if("x > 0", "    return x;")
    results["while"] = validator_emit_while("i < n", "    i++;")
    results["for"] = validator_emit_for("int i=0", "i<n", "i++", "    sum+=i;")
    results["macro"] = validator_macro_expand({"PI": "3.14"}, "x = PI * r;")
    results["hdr_malloc"] = validator_header_for_function("malloc")
    results["hdr_strlen"] = validator_header_for_function("strlen")
    results["include"] = validator_include_emit(["stdio.h", "stdlib.h"], ["foo.h"])
    results["render_break"] = validator_render_cstatement({"kind": "Break"}, 1)
    results["render_block"] = validator_render_cstatement(
        {"kind": "Block", "stmts": [{"kind": "Return", "value": "0"}]}
    )
    results["balance_ok"] = validator_brace_balance("{ { } }")
    return results


def main() -> None:
    data = sys.stdin.read().strip()
    if not data:
        print(json.dumps(_selftest(), indent=2))
        return
    req = json.loads(data)
    op = req.get("op")
    args = req.get("args", {})
    if op not in DISPATCH:
        print(json.dumps({"error": f"unknown op: {op}", "ops": sorted(DISPATCH)}))
        sys.exit(1)
    result = DISPATCH[op](args)
    print(json.dumps({"op": op, "result": result}))


if __name__ == "__main__":
    main()
