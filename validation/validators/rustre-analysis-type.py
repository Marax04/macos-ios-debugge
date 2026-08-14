"""Independent Python validator for rustre-analysis-type.

Reimplements the crate's type-recovery semantics with pure stdlib so we can
cross-check the Rust implementation without importing it.
"""
import sys
import json
from collections import defaultdict


# --- TypeFact -----------------------------------------------------------
# Represented as tuples: ("Unknown",), ("Sized", n), ("Pointer", inner),
# ("Array", elem, len), ("Struct", [(off, fact), ...]),
# ("SignedInt", n), ("UnsignedInt", n), ("Float", n), ("Bool",), ("Char",)

def byte_size(tf):
    k = tf[0]
    if k == "Sized": return tf[1]
    if k in ("SignedInt", "UnsignedInt", "Float"): return tf[1]
    if k == "Bool": return 1
    if k == "Char": return 1
    if k == "Array":
        es = byte_size(tf[1])
        return es * tf[2] if es is not None else None
    return None  # Pointer, Struct, Unknown


def is_known(tf):
    return tf[0] != "Unknown"


def join(a, b):
    """Lattice meet: most specific, Unknown is top."""
    if a == b: return a
    if a[0] == "Unknown": return b
    if b[0] == "Unknown": return a
    # Sized(n) refines to any concrete type with same byte size
    if a[0] == "Sized":
        bs = byte_size(b)
        if bs == a[1]: return b
    if b[0] == "Sized":
        bs = byte_size(a)
        if bs == b[1]: return a
    return ("Unknown",)


def validator_byte_size(tf):
    return byte_size(tuple_of(tf))


def validator_is_known(tf):
    return is_known(tuple_of(tf))


def validator_join(a, b):
    return list_of(join(tuple_of(a), tuple_of(b)))


def tuple_of(x):
    if isinstance(x, str): return (x,)
    if isinstance(x, list):
        return tuple(tuple_of(e) if isinstance(e, (list,)) and e and isinstance(e[0], str)
                     else e for e in x)
    return x


def list_of(t):
    if isinstance(t, tuple):
        return [list_of(e) for e in t]
    return t


# --- TypeInferenceEngine (union-find) -----------------------------------

class Engine:
    def __init__(self):
        self.parent = {}
        self.fact = {}
        self.names = {}
        self.next_id = 0
        self.constraints = []

    def fresh(self):
        v = self.next_id
        self.next_id += 1
        self.parent[v] = v
        self.fact[v] = ("Unknown",)
        return v

    def var_for(self, name):
        if name not in self.names:
            self.names[name] = self.fresh()
        return self.names[name]

    def find(self, v):
        while self.parent[v] != v:
            self.parent[v] = self.parent[self.parent[v]]
            v = self.parent[v]
        return v

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra == rb: return
        self.parent[ra] = rb
        self.fact[rb] = join(self.fact[ra], self.fact[rb])

    def add(self, c): self.constraints.append(c)

    def solve(self):
        # iterate to fixed point
        for _ in range(100):
            changed = False
            for c in self.constraints:
                k = c[0]
                if k == "HasType":
                    v, t = c[1], tuple_of(c[2])
                    r = self.find(v)
                    new = join(self.fact[r], t)
                    if new != self.fact[r]:
                        self.fact[r] = new; changed = True
                elif k == "Equal":
                    a, b = c[1], c[2]
                    if self.find(a) != self.find(b):
                        self.union(a, b); changed = True
                elif k == "Deref":
                    ptr, pointee = c[1], c[2]
                    pf = self.fact[self.find(pointee)]
                    desired = ("Pointer", pf)
                    r = self.find(ptr)
                    new = join(self.fact[r], desired)
                    if new != self.fact[r]:
                        self.fact[r] = new; changed = True
            if not changed: break
        return {v: self.fact[self.find(v)] for v in self.parent}


def validator_solve(constraints, var_names=None):
    """constraints: list of dicts; var_names: list of names to allocate first."""
    e = Engine()
    if var_names:
        for n in var_names:
            e.var_for(n)
    parsed = []
    for c in constraints:
        k = c["kind"]
        if k == "HasType":
            v = e.var_for(c["var"]) if isinstance(c["var"], str) else c["var"]
            parsed.append(("HasType", v, c["type"]))
        elif k == "Equal":
            a = e.var_for(c["a"]) if isinstance(c["a"], str) else c["a"]
            b = e.var_for(c["b"]) if isinstance(c["b"], str) else c["b"]
            parsed.append(("Equal", a, b))
        elif k == "Deref":
            p = e.var_for(c["ptr"]) if isinstance(c["ptr"], str) else c["ptr"]
            x = e.var_for(c["pointee"]) if isinstance(c["pointee"], str) else c["pointee"]
            parsed.append(("Deref", p, x))
    e.constraints = parsed
    assignment = e.solve()
    return {
        "by_id": {str(v): list_of(t) for v, t in assignment.items()},
        "by_name": {n: list_of(assignment[e.find(v)]) for n, v in e.names.items()},
    }


# --- CallGraph: iterative DFS post-order --------------------------------

def validator_topological_order(nodes, edges):
    succ = defaultdict(list)
    for a, b in edges:
        succ[a].append(b)
    visited = set()
    order = []
    for root in nodes:
        if root in visited: continue
        stack = [(root, iter(succ[root]))]
        on = {root}
        while stack:
            node, it = stack[-1]
            nxt = next(it, None)
            if nxt is None:
                if node not in visited:
                    visited.add(node)
                    order.append(node)
                stack.pop()
            elif nxt not in visited and nxt not in on:
                on.add(nxt)
                stack.append((nxt, iter(succ[nxt])))
    return order  # callee before caller


# --- StructRecovery -----------------------------------------------------

def validator_struct_recover(accesses):
    """accesses: list of {base, offset, size}."""
    by_base = defaultdict(set)
    for a in accesses:
        by_base[a["base"]].add((a["offset"], a["size"]))
    out = {}
    for base, fields in by_base.items():
        sorted_fields = sorted(fields, key=lambda x: x[0])
        out[base] = ["Struct", [[off, ["Sized", sz]] for off, sz in sorted_fields]]
    return out


# --- WinApiTypeDb -------------------------------------------------------

WIN_TYPES = {"DWORD": 4, "BOOL": 4, "HANDLE": 8, "SIZE_T": 8, "OVERLAPPED": 32, "FILE_PTR": 8}

# 25 expected signatures: (name, dll, arity, return_kind, cc, variadic)
WINAPI_DB = [
    ("CreateFileA", "kernel32.dll", 7, ("Sized", 8), "MicrosoftX64", False),
    ("ReadFile", "kernel32.dll", 5, ("Sized", 4), "MicrosoftX64", False),
    ("WriteFile", "kernel32.dll", 5, ("Sized", 4), "MicrosoftX64", False),
    ("VirtualAlloc", "kernel32.dll", 4, ("Pointer", ("Unknown",)), "MicrosoftX64", False),
    ("VirtualFree", "kernel32.dll", 3, ("Sized", 4), "MicrosoftX64", False),
    ("VirtualProtect", "kernel32.dll", 4, ("Sized", 4), "MicrosoftX64", False),
    ("CreateThread", "kernel32.dll", 6, ("Sized", 8), "MicrosoftX64", False),
    ("WaitForSingleObject", "kernel32.dll", 2, ("UnsignedInt", 4), "MicrosoftX64", False),
    ("CloseHandle", "kernel32.dll", 1, ("Sized", 4), "MicrosoftX64", False),
    ("GetProcAddress", "kernel32.dll", 2, ("Pointer", ("Unknown",)), "MicrosoftX64", False),
    ("LoadLibraryA", "kernel32.dll", 1, ("Sized", 8), "MicrosoftX64", False),
    ("HeapAlloc", "kernel32.dll", 3, ("Pointer", ("Unknown",)), "MicrosoftX64", False),
    ("HeapFree", "kernel32.dll", 3, ("Sized", 4), "MicrosoftX64", False),
    ("memcpy", "msvcrt.dll", 3, ("Pointer", ("Unknown",)), "MicrosoftX64", False),
    ("memset", "msvcrt.dll", 3, ("Pointer", ("Unknown",)), "MicrosoftX64", False),
    ("malloc", "msvcrt.dll", 1, ("Pointer", ("Unknown",)), "MicrosoftX64", False),
    ("free", "msvcrt.dll", 1, ("Unknown",), "MicrosoftX64", False),
    ("strlen", "msvcrt.dll", 1, ("UnsignedInt", 8), "MicrosoftX64", False),
    ("strcpy", "msvcrt.dll", 2, ("Pointer", ("Char",)), "MicrosoftX64", False),
    ("strcmp", "msvcrt.dll", 2, ("SignedInt", 4), "MicrosoftX64", False),
    ("printf", "msvcrt.dll", 1, ("SignedInt", 4), "MicrosoftX64", True),
    ("fopen", "msvcrt.dll", 2, ("Pointer", ("Unknown",)), "MicrosoftX64", False),
    ("fread", "msvcrt.dll", 4, ("UnsignedInt", 8), "MicrosoftX64", False),
    ("fwrite", "msvcrt.dll", 4, ("UnsignedInt", 8), "MicrosoftX64", False),
    ("fclose", "msvcrt.dll", 1, ("SignedInt", 4), "MicrosoftX64", False),
]


def validator_winapi_lookup_by_name(name):
    nl = name.lower()
    for n, dll, arity, ret, cc, var in WINAPI_DB:
        if n.lower() == nl:
            return {"name": n, "dll": dll, "arity": arity, "return_type": list_of(ret),
                    "calling_convention": cc, "is_variadic": var}
    return None


def validator_winapi_count():
    return len(WINAPI_DB)


def validator_win_types():
    return dict(WIN_TYPES)


# --- collect_constraints ------------------------------------------------

def validator_collect_constraints(instrs):
    """instrs: list of {kind: 'Const'|'Assign'|'Load'|'Store'|'Add'|'Sub'|'Branch'|'Call'|'Return', ...}"""
    e = Engine()
    out = []
    for ins in instrs:
        k = ins["kind"]
        if k == "Const":
            v = e.var_for(ins["dst"])
            bytes_ = ins["bytes"]
            t = ("SignedInt", bytes_) if ins.get("signed") else ("UnsignedInt", bytes_)
            out.append({"kind": "HasType", "var": ins["dst"], "type": list_of(t)})
        elif k == "Assign":
            e.var_for(ins["dst"]); e.var_for(ins["src"])
            out.append({"kind": "Equal", "a": ins["dst"], "b": ins["src"]})
        elif k == "Load":
            e.var_for(ins["dst"]); e.var_for(ins["ptr"])
            out.append({"kind": "Deref", "ptr": ins["ptr"], "pointee": ins["dst"]})
        elif k == "Store":
            e.var_for(ins["ptr"]); e.var_for(ins["src"])
            out.append({"kind": "Deref", "ptr": ins["ptr"], "pointee": ins["src"]})
        elif k == "Branch":
            out.append({"kind": "IsCondition", "var": ins["cond"]})
    return out


# --- TypePropagator -----------------------------------------------------

def validator_propagate(call_graph, initial_envs):
    """call_graph: {fn: [callees...]}, initial_envs: {fn: {'return': type, 'args': [..]}}"""
    envs = {f: {"return": e.get("return", ["Unknown"]), "args": e.get("args", [])}
            for f, e in initial_envs.items()}
    for f in call_graph:
        envs.setdefault(f, {"return": ["Unknown"], "args": []})
        for c in call_graph[f]:
            envs.setdefault(c, {"return": ["Unknown"], "args": []})
    # bottom-up via topo order
    order = validator_topological_order(list(envs.keys()),
                                        [(a, b) for a, bs in call_graph.items() for b in bs])
    for _ in range(100):
        changed = False
        for caller in reversed(order):  # process callers after callees
            for callee in call_graph.get(caller, []):
                cret = tuple_of(envs[callee]["return"])
                cur = tuple_of(envs[caller]["return"])
                new = join(cur, cret)
                if list_of(new) != envs[caller]["return"]:
                    envs[caller]["return"] = list_of(new); changed = True
        if not changed: break
    return envs


# --- main ---------------------------------------------------------------

def main():
    if not sys.stdin.isatty():
        try:
            req = json.loads(sys.stdin.read() or "{}")
        except Exception:
            req = {}
    else:
        req = {}

    if req.get("fn"):
        fn = req["fn"]; args = req.get("args", [])
        f = globals().get(f"validator_{fn}")
        if not f:
            print(json.dumps({"error": f"unknown fn {fn}"})); return
        print(json.dumps({"result": f(*args)}, default=str)); return

    # default self-test
    results = {}
    results["byte_size_uint4"] = byte_size(("UnsignedInt", 4))            # 4
    results["byte_size_array_u32_3"] = byte_size(("Array", ("UnsignedInt", 4), 3))  # 12
    results["byte_size_pointer"] = byte_size(("Pointer", ("Unknown",)))   # None
    results["join_sized4_signed4"] = list_of(join(("Sized", 4), ("SignedInt", 4)))
    results["join_unknown_t"] = list_of(join(("Unknown",), ("Bool",)))
    results["join_commutative"] = (join(("Sized", 4), ("SignedInt", 4)) ==
                                   join(("SignedInt", 4), ("Sized", 4)))
    results["solve_equal_hastype"] = validator_solve([
        {"kind": "HasType", "var": "v0", "type": ["SignedInt", 4]},
        {"kind": "Equal", "a": "v0", "b": "v1"},
    ], ["v0", "v1"])
    results["solve_deref"] = validator_solve([
        {"kind": "HasType", "var": "x", "type": ["UnsignedInt", 4]},
        {"kind": "Deref", "ptr": "p", "pointee": "x"},
    ], ["p", "x"])
    results["topo_abc"] = validator_topological_order(["A", "B", "C"], [("A", "B"), ("B", "C")])
    results["struct_recover"] = validator_struct_recover([
        {"base": "o", "offset": 0, "size": 4},
        {"base": "o", "offset": 8, "size": 8},
    ])
    results["winapi_count"] = validator_winapi_count()
    results["winapi_strlen"] = validator_winapi_lookup_by_name("strlen")
    results["winapi_printf_variadic"] = validator_winapi_lookup_by_name("printf")["is_variadic"]
    results["winapi_createfilea"] = validator_winapi_lookup_by_name("CreateFileA")
    results["win_types"] = validator_win_types()
    results["collect_constraints_const"] = validator_collect_constraints([
        {"kind": "Const", "dst": "x", "bytes": 4, "signed": True},
    ])
    results["propagate"] = validator_propagate(
        {"caller": ["callee"]},
        {"callee": {"return": ["SignedInt", 4]}},
    )

    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
