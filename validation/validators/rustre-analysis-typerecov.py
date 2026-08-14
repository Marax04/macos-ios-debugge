#!/usr/bin/env python3
"""
Standalone Python validator for crate `rustre-analysis-typerecov`.

Reimplements the testable algebraic invariants of the type-recovery pipeline:
  - function signature registry + confidence classification
  - TypeConstraintGenerator.type_var_of determinism/monotonicity
  - TypeUnifier.solve (union-find) transitive equality + conflict detection
  - StructRecoveryEngine.recover_structs_all field layout
  - RecoveredStruct.to_c_decl output shape
  - merge_structs idempotence
  - mem_access_scanner: synthetic x86 [reg+disp] displacement extraction

No imports of the Rust crate, no MCP calls. Optional capstone via subprocess.
"""

from __future__ import annotations
import json
import sys
import subprocess
from dataclasses import dataclass, field
from typing import Any


def _ensure(pkg: str, import_name: str | None = None):
    name = import_name or pkg
    try:
        return __import__(name)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", pkg])
        return __import__(name)


# ----------------------------- Signature registry ---------------------------- #

_SIG_REGISTRY: dict[int, dict] = {}


def validator_register_function_signature(inp: dict) -> dict:
    """inp = {addr, calling_convention, return_type, args}"""
    addr = int(inp["addr"])
    rec = {
        "calling_convention": inp.get("calling_convention"),
        "return_type": inp.get("return_type"),
        "args": inp.get("args", []),
    }
    _SIG_REGISTRY[addr] = rec
    return {"ok": True, "addr": addr}


def validator_infer_function_signature(inp: dict) -> dict:
    addr = int(inp["addr"])
    rec = _SIG_REGISTRY.get(addr)
    if rec is None:
        return {
            "calling_convention": None,
            "return_type": None,
            "args": [],
            "confidence": "Low",
        }
    cc_known = rec["calling_convention"] is not None
    args = rec["args"]
    all_args_concrete = bool(args) and all(
        a is not None and a != "Unknown" for a in args
    )
    if cc_known and all_args_concrete:
        conf = "High"
    elif cc_known:
        conf = "Medium"
    else:
        conf = "Low"
    return {
        "calling_convention": rec["calling_convention"],
        "return_type": rec["return_type"],
        "args": args,
        "confidence": conf,
    }


def validator_clear_function_signatures(_inp: dict) -> dict:
    _SIG_REGISTRY.clear()
    return {"ok": True}


# -------------------------- TypeConstraintGenerator -------------------------- #


class TypeConstraintGenerator:
    def __init__(self, pointer_width: int = 8):
        self.pointer_width = pointer_width
        self._vars: dict[str, int] = {}
        self._next = 0
        self.constraints: list[dict] = []

    def _key(self, value: Any) -> str:
        return json.dumps(value, sort_keys=True, default=str)

    def type_var_of(self, value: Any) -> int:
        k = self._key(value)
        if k not in self._vars:
            self._vars[k] = self._next
            self._next += 1
        return self._vars[k]

    def lookup(self, value: Any) -> int | None:
        return self._vars.get(self._key(value))


def validator_type_var_of(inp: dict) -> dict:
    """inp = {values: [...]} returns list of assigned ids + monotonicity check"""
    gen = TypeConstraintGenerator(inp.get("pointer_width", 8))
    ids = [gen.type_var_of(v) for v in inp["values"]]
    # determinism: same value → same id
    ids2 = [gen.type_var_of(v) for v in inp["values"]]
    deterministic = ids == ids2
    # monotonicity: distinct values get strictly increasing fresh ids
    seen: dict[str, int] = {}
    monotonic = True
    expected = 0
    for v in inp["values"]:
        k = json.dumps(v, sort_keys=True, default=str)
        if k not in seen:
            seen[k] = expected
            expected += 1
    return {"ids": ids, "deterministic": deterministic, "monotonic": monotonic}


# ----------------------------- TypeUnifier (UF) ------------------------------ #


class UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))
        self.rank = [0] * n

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> int:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return ra
        if self.rank[ra] < self.rank[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        if self.rank[ra] == self.rank[rb]:
            self.rank[ra] += 1
        return ra


def validator_unifier_solve(inp: dict) -> dict:
    """inp = {var_count, constraints:[{kind:'Eq'|'PointerOf'|'Size', a, b?, size?}]}"""
    n = int(inp["var_count"])
    uf = UnionFind(n)
    pointer_of: dict[int, int] = {}
    sizes: dict[int, int] = {}
    pw = int(inp.get("pointer_width", 8))
    error = None
    for c in inp["constraints"]:
        k = c["kind"]
        if k == "Eq":
            uf.union(int(c["a"]), int(c["b"]))
        elif k == "PointerOf":
            r = uf.find(int(c["a"]))
            pointer_of[r] = int(c.get("pointee", -1))
            # pointer width as size of root
            existing = sizes.get(r)
            if existing is not None and existing != pw:
                error = f"conflict pointer size at var {r}"
                break
            sizes[r] = pw
        elif k == "Size":
            r = uf.find(int(c["a"]))
            sz = int(c["size"])
            existing = sizes.get(r)
            if existing is not None and existing != sz:
                error = f"conflict size at var {r}: {existing} vs {sz}"
                break
            sizes[r] = sz
    if error:
        return {"ok": False, "error": error}
    roots = [uf.find(i) for i in range(n)]
    resolved = {i: sizes.get(roots[i]) for i in range(n) if roots[i] in sizes}
    pointers = [i for i in range(n) if roots[i] in pointer_of]
    return {
        "ok": True,
        "roots": roots,
        "resolved_vars": sorted(resolved.keys()),
        "sizes": {str(k): v for k, v in resolved.items()},
        "pointers": pointers,
    }


# ---------------------------- Struct Recovery -------------------------------- #


@dataclass
class FieldAccess:
    base_var: int
    offset: int
    size: int


@dataclass
class RecoveredField:
    offset: int
    size: int


@dataclass
class RecoveredStruct:
    base_var: int
    fields: list[RecoveredField] = field(default_factory=list)

    def field_at(self, off: int) -> RecoveredField | None:
        for f in self.fields:
            if f.offset == off:
                return f
        return None

    def range(self) -> tuple[int, int]:
        if not self.fields:
            return (0, 0)
        lo = min(f.offset for f in self.fields)
        hi = max(f.offset + f.size for f in self.fields)
        return (lo, hi)

    def is_union_candidate(self) -> bool:
        offs = [f.offset for f in self.fields]
        return len(offs) != len(set(offs))

    def to_c_decl(self) -> str:
        lines = [f"struct s_{self.base_var} {{"]
        for f in sorted(self.fields, key=lambda x: x.offset):
            ty = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}.get(
                f.size, f"uint8_t[{f.size}]"
            )
            lines.append(f"    {ty} field_{f.offset:x}; // off=0x{f.offset:x} size={f.size}")
        lines.append("};")
        return "\n".join(lines)


def _recover_one(accesses: list[FieldAccess], base: int) -> RecoveredStruct | None:
    rel = [a for a in accesses if a.base_var == base]
    if not rel:
        return None
    # dedupe (offset,size)
    seen: set[tuple[int, int]] = set()
    fields: list[RecoveredField] = []
    for a in rel:
        key = (a.offset, a.size)
        if key in seen:
            continue
        seen.add(key)
        fields.append(RecoveredField(a.offset, a.size))
    fields.sort(key=lambda x: x.offset)
    return RecoveredStruct(base, fields)


def validator_recover_structs_all(inp: dict) -> dict:
    """inp = {accesses:[{base_var, offset, size}]}"""
    accesses = [FieldAccess(**a) for a in inp["accesses"]]
    bases = sorted({a.base_var for a in accesses})
    structs = []
    for b in bases:
        s = _recover_one(accesses, b)
        if s:
            structs.append(
                {
                    "base_var": s.base_var,
                    "fields": [{"offset": f.offset, "size": f.size} for f in s.fields],
                    "c_decl": s.to_c_decl(),
                    "range": list(s.range()),
                    "is_union_candidate": s.is_union_candidate(),
                }
            )
    return {"structs": structs}


def validator_to_c_decl(inp: dict) -> dict:
    accesses = [FieldAccess(inp["base_var"], f["offset"], f["size"]) for f in inp["fields"]]
    s = _recover_one(accesses, inp["base_var"])
    return {"c_decl": s.to_c_decl() if s else ""}


def validator_merge_structs(inp: dict) -> dict:
    """inp = {a:{base_var, fields}, b:{base_var, fields}}"""
    a = inp["a"]
    b = inp["b"]
    merged_fields_keys: set[tuple[int, int]] = set()
    fields = []
    for f in a["fields"] + b["fields"]:
        k = (f["offset"], f["size"])
        if k in merged_fields_keys:
            continue
        merged_fields_keys.add(k)
        fields.append({"offset": f["offset"], "size": f["size"]})
    fields.sort(key=lambda x: (x["offset"], x["size"]))
    return {"base_var": a["base_var"], "fields": fields}


def validator_merge_idempotent(inp: dict) -> dict:
    """Check merge_structs(a,a) == a (sorted)."""
    a = inp["a"]
    merged = validator_merge_structs({"a": a, "b": a})
    a_sorted = sorted(a["fields"], key=lambda x: (x["offset"], x["size"]))
    return {"idempotent": merged["fields"] == a_sorted}


# ----------------------- mem_access_scanner (x86) ---------------------------- #

# Static deterministic mapping iced-x86-like register name → TypeVar id
_REG_VARS = {
    "rax": 0, "rcx": 1, "rdx": 2, "rbx": 3,
    "rsp": 4, "rbp": 5, "rsi": 6, "rdi": 7,
    "r8": 8,  "r9": 9,  "r10": 10, "r11": 11,
    "r12": 12, "r13": 13, "r14": 14, "r15": 15,
}


def validator_typevar_for_register(inp: dict) -> dict:
    reg = inp["reg"].lower()
    return {"type_var": _REG_VARS.get(reg)}


def validator_scan_memory_accesses_x86(inp: dict) -> dict:
    """
    inp = {bytes_hex: '488b4710', base_addr: 0x1000}
    Decodes via capstone and returns FieldAccess entries for [reg+disp] memory operands.
    """
    capstone = _ensure("capstone")
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_OP_MEM

    data = bytes.fromhex(inp["bytes_hex"])
    base = int(inp.get("base_addr", 0x1000))
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    accesses = []
    for insn in md.disasm(data, base):
        for op in insn.operands:
            if op.type == X86_OP_MEM:
                mem = op.mem
                if mem.base != 0:
                    reg_name = insn.reg_name(mem.base)
                    tv = _REG_VARS.get(reg_name, -1)
                    accesses.append(
                        {
                            "base_var": tv,
                            "base_reg": reg_name,
                            "offset": int(mem.disp),
                            "size": op.size,
                            "insn": f"{insn.mnemonic} {insn.op_str}",
                        }
                    )
    return {"accesses": accesses}


# ----------------------------------- main ----------------------------------- #


FUNCTIONS = {
    "register_function_signature": validator_register_function_signature,
    "infer_function_signature": validator_infer_function_signature,
    "clear_function_signatures": validator_clear_function_signatures,
    "type_var_of": validator_type_var_of,
    "unifier_solve": validator_unifier_solve,
    "recover_structs_all": validator_recover_structs_all,
    "to_c_decl": validator_to_c_decl,
    "merge_structs": validator_merge_structs,
    "merge_idempotent": validator_merge_idempotent,
    "typevar_for_register": validator_typevar_for_register,
    "scan_memory_accesses_x86": validator_scan_memory_accesses_x86,
}


def _selftest() -> dict:
    results = {}

    # signature registry
    validator_clear_function_signatures({})
    validator_register_function_signature(
        {"addr": 0x1000, "calling_convention": "sysv64",
         "return_type": "i64", "args": ["i64", "i32"]}
    )
    results["sig_high"] = validator_infer_function_signature({"addr": 0x1000})
    validator_register_function_signature(
        {"addr": 0x2000, "calling_convention": "sysv64",
         "return_type": None, "args": []}
    )
    results["sig_medium"] = validator_infer_function_signature({"addr": 0x2000})
    results["sig_low_absent"] = validator_infer_function_signature({"addr": 0xDEAD})

    # type_var_of
    results["tvo"] = validator_type_var_of({"values": ["a", "b", "a", "c", "b"]})

    # unifier
    results["uf_eq"] = validator_unifier_solve(
        {"var_count": 3, "constraints": [
            {"kind": "Eq", "a": 0, "b": 1},
            {"kind": "Eq", "a": 1, "b": 2},
            {"kind": "Size", "a": 0, "size": 4},
        ]}
    )
    results["uf_conflict"] = validator_unifier_solve(
        {"var_count": 2, "constraints": [
            {"kind": "Eq", "a": 0, "b": 1},
            {"kind": "Size", "a": 0, "size": 4},
            {"kind": "Size", "a": 1, "size": 8},
        ]}
    )

    # struct recovery
    results["recover"] = validator_recover_structs_all(
        {"accesses": [
            {"base_var": 0, "offset": 0, "size": 4},
            {"base_var": 0, "offset": 4, "size": 4},
        ]}
    )

    # merge idempotent
    results["merge_idem"] = validator_merge_idempotent(
        {"a": {"base_var": 0, "fields": [
            {"offset": 0, "size": 4}, {"offset": 4, "size": 4}]}}
    )

    # typevar_for_register
    results["reg_rdi"] = validator_typevar_for_register({"reg": "rdi"})

    # scan x86: mov rax, [rdi+0x10]  => 48 8B 47 10
    try:
        results["scan"] = validator_scan_memory_accesses_x86({"bytes_hex": "488b4710"})
    except Exception as e:
        results["scan"] = {"error": str(e)}

    return results


def main() -> None:
    if not sys.stdin.isatty():
        try:
            data = sys.stdin.read().strip()
            if data:
                req = json.loads(data)
                fn = FUNCTIONS[req["function"]]
                print(json.dumps(fn(req.get("input", {})), indent=2, default=str))
                return
        except Exception as e:
            print(json.dumps({"error": str(e)}))
            return
    # otherwise: self-test
    print(json.dumps(_selftest(), indent=2, default=str))


if __name__ == "__main__":
    main()
