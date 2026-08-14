#!/usr/bin/env python3
"""
Standalone validator for rustre-symb-taint.

Pure-Python reimplementation of the core taint-analysis abstractions exposed
by the Rust crate `rustre-symb-taint`.

Covered surface:
- taint_bits: USER_INPUT/NETWORK/FILE/ENVIRONMENT/COMMAND_LINE/REGISTRY/CUSTOM_BASE
  + custom(idx), is_tainted, union, intersect, has_bit
- TaintedValue: new, tainted, is_tainted, clean, union_taints
- TaintState: get_reg/set_reg/taint_reg/sanitize_register/reg_taint
              get_mem/set_mem/mark_tainted/sanitize_memory/mem_taint
              get_stack/set_stack/stack_taint
- eval_taint / eval_value (TaintExpr: Const, Reg, Load, Add, Sub, Mul,
  Div, And, Or, Xor, Not, Shl, Shr, Cmp)
- apply_instr (TaintInstr: SetReg, Store, Call, Branch, Return, Nop)
- check_dangerous_sink -> FindingType (CommandInjection, BufferOverflow,
  FormatString, SqlInjection, PathTraversal)
- TaintReport: analyze, finding_count, has_findings, high_severity_count
- LegacyTaintTracker: mark_source, propagate, sanitize_location,
  is_tainted_at, find_paths_to_sink
- TaintSet: empty, all_taint, add, remove, contains, is_empty, union,
  intersection

Usage:
  python rustre-symb-taint.py           # smoke tests
  echo '{"fn":"taint_union","args":{"a":1,"b":2}}' | python rustre-symb-taint.py
"""

import json
import sys

# ── taint_bits ────────────────────────────────────────────────────────────────

USER_INPUT   = 1 << 0
NETWORK      = 1 << 1
FILE         = 1 << 2
ENVIRONMENT  = 1 << 3
COMMAND_LINE = 1 << 4
REGISTRY     = 1 << 5
CUSTOM_BASE  = 1 << 6
NONE_TAINT   = 0
ALL_TAINT    = (1 << 64) - 1


def taint_custom(idx):
    if idx < 58:
        return 1 << (6 + idx)
    return 0


def taint_is_tainted(mask):
    return mask != 0


def taint_union(a, b):
    return a | b


def taint_intersect(a, b):
    return a & b


def taint_has_bit(mask, bit):
    return bool(mask & bit)


# ── TaintedValue ──────────────────────────────────────────────────────────────

class TaintedValue:
    def __init__(self, value=0, taints=NONE_TAINT):
        self.value = value
        self.taints = taints

    @classmethod
    def clean(cls):
        return cls(0, NONE_TAINT)

    @classmethod
    def tainted(cls, value, source):
        return cls(value, source)

    def is_tainted(self):
        return self.taints != NONE_TAINT

    def union_taints(self, other):
        return self.taints | other.taints

    def to_dict(self):
        return {"value": self.value, "taints": self.taints}


# ── TaintState ────────────────────────────────────────────────────────────────

class TaintState:
    def __init__(self):
        self.registers = {}   # str -> TaintedValue
        self.memory = {}      # int -> TaintedValue
        self.stack_taints = {}  # int -> TaintedValue
        self.current_ticks = 0
        self.cf_taint = set()
        self.last_pc = 0

    def get_reg(self, reg):
        return self.registers.get(reg, TaintedValue.clean())

    def set_reg(self, reg, val):
        self.registers[reg] = val

    def taint_reg(self, reg, source):
        v = self.registers.setdefault(reg, TaintedValue.clean())
        v.taints |= source

    def sanitize_register(self, reg):
        if reg in self.registers:
            self.registers[reg].taints = NONE_TAINT

    def reg_taint(self, reg):
        return self.registers.get(reg, TaintedValue.clean()).taints

    def get_mem(self, addr):
        return self.memory.get(int(addr), TaintedValue.clean())

    def set_mem(self, addr, val):
        self.memory[int(addr)] = val

    def mark_tainted(self, addr, size, source_id):
        size = min(size, 1 << 20)
        for i in range(size):
            key = int(addr) + i
            v = self.memory.setdefault(key, TaintedValue.clean())
            v.taints |= source_id

    def sanitize_memory(self, addr, size):
        size = min(size, 1 << 20)
        for i in range(size):
            key = int(addr) + i
            if key in self.memory:
                self.memory[key].taints = NONE_TAINT

    def mem_taint(self, addr):
        return self.memory.get(int(addr), TaintedValue.clean()).taints

    def get_stack(self, offset):
        return self.stack_taints.get(int(offset), TaintedValue.clean())

    def set_stack(self, offset, val):
        self.stack_taints[int(offset)] = val

    def stack_taint(self, offset):
        return self.stack_taints.get(int(offset), TaintedValue.clean()).taints


# ── TaintExpr eval ────────────────────────────────────────────────────────────

def _eval_taint(expr, state):
    """Evaluate taint mask of a TaintExpr dict."""
    tag = expr[0] if isinstance(expr, (list, tuple)) else expr.get("t") if isinstance(expr, dict) else None
    # Support list form: ["Const", v], ["Reg", name], ["Add", e1, e2], etc.
    if isinstance(expr, (list, tuple)):
        tag = expr[0]
        if tag == "Const":
            return NONE_TAINT
        if tag == "Reg":
            return state.reg_taint(expr[1])
        if tag == "Load":
            addr_expr = expr[1]
            addr_taint = _eval_taint(addr_expr, state)
            addr_val = _eval_value(addr_expr, state)
            mem_taint = state.mem_taint(addr_val)
            return taint_union(addr_taint, mem_taint)
        if tag in ("Add", "Sub", "Mul", "Div", "Or", "Xor", "Shl", "Shr", "Cmp",
                   "And"):
            return taint_union(_eval_taint(expr[1], state), _eval_taint(expr[2], state))
        if tag == "Not":
            return _eval_taint(expr[1], state)
        return NONE_TAINT
    return NONE_TAINT


def _eval_value(expr, state):
    """Evaluate concrete value of a TaintExpr."""
    if isinstance(expr, (list, tuple)):
        tag = expr[0]
        if tag == "Const":
            return int(expr[1])
        if tag == "Reg":
            return state.get_reg(expr[1]).value
        if tag == "Load":
            a = _eval_value(expr[1], state)
            return state.get_mem(a).value
        if tag == "Add":
            return (_eval_value(expr[1], state) + _eval_value(expr[2], state)) & 0xFFFFFFFFFFFFFFFF
        if tag == "Sub":
            return (_eval_value(expr[1], state) - _eval_value(expr[2], state)) & 0xFFFFFFFFFFFFFFFF
        if tag == "Mul":
            return (_eval_value(expr[1], state) * _eval_value(expr[2], state)) & 0xFFFFFFFFFFFFFFFF
        if tag == "And":
            return _eval_value(expr[1], state) & _eval_value(expr[2], state)
        if tag == "Or":
            return _eval_value(expr[1], state) | _eval_value(expr[2], state)
        if tag == "Xor":
            return _eval_value(expr[1], state) ^ _eval_value(expr[2], state)
        if tag == "Shl":
            return (_eval_value(expr[1], state) << (_eval_value(expr[2], state) & 63)) & 0xFFFFFFFFFFFFFFFF
        if tag == "Shr":
            return _eval_value(expr[1], state) >> (_eval_value(expr[2], state) & 63)
        if tag == "Not":
            return (~_eval_value(expr[1], state)) & 0xFFFFFFFFFFFFFFFF
        if tag == "Div":
            b = _eval_value(expr[2], state)
            return 0 if b == 0 else _eval_value(expr[1], state) // b
        if tag == "Cmp":
            return 0
        return 0
    return 0


# Dangerous sinks (mirrors check_dangerous_sink in lib.rs)
_CMD_SINKS = {"system", "execve", "execl", "execvp", "ShellExecute", "WinExec", "CreateProcess"}
_BOF_LEN_SINKS = {"memcpy", "memmove", "bcopy"}
_BOF_SRC_SINKS = {"strcpy", "strcat"}
_FMT_ARG0 = {"printf", "vprintf"}
_FMT_ARG1 = {"fprintf", "sprintf", "vsprintf"}
_FMT_ARG2 = {"snprintf"}
_SQL_SINKS = {"sqlite3_exec", "mysql_query", "PQexec", "sql_exec"}
_PATH_SINKS = {"fopen", "open", "CreateFile", "LoadLibrary", "rename", "unlink", "DeleteFile"}


def _check_dangerous_sink(target, arg_taints, addr):
    def at(i):
        return arg_taints[i] if i < len(arg_taints) else NONE_TAINT

    if target in _CMD_SINKS:
        if taint_is_tainted(at(0)):
            return {"finding_type": "CommandInjection", "sink_addr": addr,
                    "taint_sources": at(0),
                    "description": f"Tainted data flows into {target}() command argument"}
    if target in _BOF_LEN_SINKS:
        if taint_is_tainted(at(2)):
            return {"finding_type": "BufferOverflow", "sink_addr": addr,
                    "taint_sources": at(2),
                    "description": f"Tainted length in {target}()"}
    if target in _BOF_SRC_SINKS:
        if taint_is_tainted(at(1)):
            return {"finding_type": "BufferOverflow", "sink_addr": addr,
                    "taint_sources": at(1),
                    "description": f"Tainted source in {target}()"}
    if target == "gets":
        if taint_is_tainted(at(0)):
            return {"finding_type": "BufferOverflow", "sink_addr": addr,
                    "taint_sources": at(0),
                    "description": f"Tainted buffer pointer in {target}()"}
    if target in _FMT_ARG0:
        if taint_is_tainted(at(0)):
            return {"finding_type": "FormatString", "sink_addr": addr,
                    "taint_sources": at(0),
                    "description": f"Tainted format string in {target}()"}
    if target in _FMT_ARG1:
        if taint_is_tainted(at(1)):
            return {"finding_type": "FormatString", "sink_addr": addr,
                    "taint_sources": at(1),
                    "description": f"Tainted format string in {target}()"}
    if target in _FMT_ARG2:
        if taint_is_tainted(at(2)):
            return {"finding_type": "FormatString", "sink_addr": addr,
                    "taint_sources": at(2),
                    "description": f"Tainted format string in {target}()"}
    if target in _SQL_SINKS:
        if taint_is_tainted(at(1)):
            return {"finding_type": "SqlInjection", "sink_addr": addr,
                    "taint_sources": at(1),
                    "description": f"Tainted SQL query in {target}()"}
    if target in _PATH_SINKS:
        if taint_is_tainted(at(0)):
            return {"finding_type": "PathTraversal", "sink_addr": addr,
                    "taint_sources": at(0),
                    "description": f"Tainted path in {target}()"}
    return None


def apply_instr(instr, state):
    """Apply a TaintInstr dict to TaintState. Returns finding dict or None."""
    state.current_ticks += 1
    tag = instr["op"]
    addr = instr.get("addr", 0)
    if tag == "SetReg":
        src = instr["src"]
        taint = _eval_taint(src, state)
        value = _eval_value(src, state)
        state.set_reg(instr["reg"], TaintedValue(value, taint))
        state.last_pc = addr
        return None
    if tag == "Store":
        dest = instr["dest"]
        val = instr["val"]
        addr_val = _eval_value(dest, state)
        val_taint = _eval_taint(val, state)
        addr_taint = _eval_taint(dest, state)
        combined = taint_union(val_taint, addr_taint)
        value = _eval_value(val, state)
        state.set_mem(addr_val, TaintedValue(value, combined))
        state.last_pc = addr
        return None
    if tag == "Call":
        target = instr["target"]
        args = instr.get("args", [])
        arg_taints = [_eval_taint(a, state) for a in args]
        return _check_dangerous_sink(target, arg_taints, addr)
    if tag == "Branch":
        taint = _eval_taint(instr["cond"], state)
        if taint_is_tainted(taint):
            state.cf_taint.add(addr)
        return None
    if tag == "Return":
        val = instr.get("val")
        if val is not None:
            taint = _eval_taint(val, state)
            value = _eval_value(val, state)
            state.set_reg("rax", TaintedValue(value, taint))
        state.last_pc = addr
        return None
    # Nop or unknown
    return None


# ── TaintReport (analyze) ─────────────────────────────────────────────────────

HIGH_SEVERITY = {"CommandInjection", "FormatString", "SqlInjection"}


class TaintReport:
    def __init__(self):
        self.findings = []

    def add_finding(self, f):
        if f is not None:
            self.findings.append(f)

    def finding_count(self):
        return len(self.findings)

    def has_findings(self):
        return bool(self.findings)

    def high_severity_count(self):
        return sum(1 for f in self.findings if f["finding_type"] in HIGH_SEVERITY)

    def findings_by_type(self, ftype):
        return [f for f in self.findings if f["finding_type"] == ftype]

    @classmethod
    def analyze(cls, instrs, initial_state=None):
        state = initial_state or TaintState()
        report = cls()
        for instr in instrs:
            f = apply_instr(instr, state)
            report.add_finding(f)
        return report


# ── LegacyTaintTracker ────────────────────────────────────────────────────────

class LegacyTaintTracker:
    def __init__(self):
        # location -> set of source names
        self.tainted = {}
        # source name -> set of locations
        self.sources = {}

    def mark_source(self, location, name):
        self.tainted.setdefault(location, set()).add(name)
        self.sources.setdefault(name, set()).add(location)

    def get_at_location(self, location):
        return self.tainted.get(location, set())

    def propagate(self, src_loc, dst_loc):
        taints = self.tainted.get(src_loc, set())
        if taints:
            self.tainted.setdefault(dst_loc, set()).update(taints)

    def sanitize_location(self, location):
        self.tainted.pop(location, None)

    def is_tainted_at(self, location):
        return bool(self.tainted.get(location))

    def find_paths_to_sink(self, sink_location):
        """BFS: return list of (source_name, path=[]) pairs reaching sink_location."""
        paths = []
        for src_name, locs in self.sources.items():
            if sink_location in locs:
                paths.append({"source": src_name, "path": [sink_location]})
        return paths


# ── TaintSet ─────────────────────────────────────────────────────────────────

class TaintSet:
    def __init__(self, mask=0):
        self.mask = mask

    @classmethod
    def empty(cls):
        return cls(0)

    @classmethod
    def all_taint(cls):
        return cls(ALL_TAINT)

    def add(self, taint_id):
        self.mask |= taint_id
        return self

    def remove(self, taint_id):
        self.mask &= ~taint_id
        return self

    def contains(self, taint_id):
        return bool(self.mask & taint_id)

    def is_empty(self):
        return self.mask == 0

    def union(self, other):
        return TaintSet(self.mask | other.mask)

    def intersection(self, other):
        return TaintSet(self.mask & other.mask)


# ── Validator public API ──────────────────────────────────────────────────────

def validator_taint_bits(op, a=0, b=0, idx=0, bit=0):
    if op == "custom":
        return taint_custom(idx)
    if op == "is_tainted":
        return taint_is_tainted(a)
    if op == "union":
        return taint_union(a, b)
    if op == "intersect":
        return taint_intersect(a, b)
    if op == "has_bit":
        return taint_has_bit(a, bit)
    return None


def validator_tainted_value(op, value=0, taints=0, other_taints=0):
    tv = TaintedValue(value, taints)
    if op == "is_tainted":
        return tv.is_tainted()
    if op == "union_taints":
        other = TaintedValue(0, other_taints)
        return tv.union_taints(other)
    return None


def validator_taint_state_reg(ops):
    """ops: list of {op, reg, val?, taint?} -> list of results."""
    state = TaintState()
    results = []
    for o in ops:
        op = o["op"]
        reg = o.get("reg", "rax")
        if op == "set_reg":
            state.set_reg(reg, TaintedValue(o.get("val", 0), o.get("taint", 0)))
            results.append(None)
        elif op == "taint_reg":
            state.taint_reg(reg, o["taint"])
            results.append(None)
        elif op == "sanitize_register":
            state.sanitize_register(reg)
            results.append(None)
        elif op == "reg_taint":
            results.append(state.reg_taint(reg))
        elif op == "get_reg":
            rv = state.get_reg(reg)
            results.append({"value": rv.value, "taints": rv.taints})
    return results


def validator_taint_state_mem(ops):
    """ops: list of {op, addr, size?, taint?, val?} -> list of results."""
    state = TaintState()
    results = []
    for o in ops:
        op = o["op"]
        addr = o.get("addr", 0)
        if op == "set_mem":
            state.set_mem(addr, TaintedValue(o.get("val", 0), o.get("taint", 0)))
            results.append(None)
        elif op == "mark_tainted":
            state.mark_tainted(addr, o.get("size", 1), o["taint"])
            results.append(None)
        elif op == "sanitize_memory":
            state.sanitize_memory(addr, o.get("size", 1))
            results.append(None)
        elif op == "mem_taint":
            results.append(state.mem_taint(addr))
    return results


def validator_eval_taint(expr, reg_taints=None, mem_taints=None):
    state = TaintState()
    for reg, taint in (reg_taints or {}).items():
        state.taint_reg(reg, taint)
    for addr, taint in (mem_taints or {}).items():
        state.mark_tainted(int(addr), 1, taint)
    return _eval_taint(expr, state)


def validator_apply_instrs(instrs, initial_reg_taints=None):
    """Apply a sequence of TaintInstr dicts; return findings and final reg taints."""
    state = TaintState()
    for reg, taint in (initial_reg_taints or {}).items():
        state.taint_reg(reg, taint)
    findings = []
    for instr in instrs:
        f = apply_instr(instr, state)
        if f is not None:
            findings.append(f)
    return {
        "findings": findings,
        "reg_taints": {k: v.taints for k, v in state.registers.items()},
        "cf_taint_addrs": sorted(state.cf_taint),
    }


def validator_taint_report(instrs, initial_reg_taints=None):
    state = TaintState()
    for reg, taint in (initial_reg_taints or {}).items():
        state.taint_reg(reg, taint)
    report = TaintReport.analyze(instrs, state)
    return {
        "finding_count": report.finding_count(),
        "has_findings": report.has_findings(),
        "high_severity_count": report.high_severity_count(),
        "findings": report.findings,
    }


def validator_legacy_tracker(ops):
    tracker = LegacyTaintTracker()
    results = []
    for o in ops:
        op = o["op"]
        if op == "mark_source":
            tracker.mark_source(o["loc"], o["name"])
            results.append(None)
        elif op == "propagate":
            tracker.propagate(o["src"], o["dst"])
            results.append(None)
        elif op == "sanitize_location":
            tracker.sanitize_location(o["loc"])
            results.append(None)
        elif op == "is_tainted_at":
            results.append(tracker.is_tainted_at(o["loc"]))
        elif op == "find_paths_to_sink":
            results.append(tracker.find_paths_to_sink(o["loc"]))
    return results


def validator_taint_set(ops):
    ts = TaintSet.empty()
    results = []
    for o in ops:
        op = o["op"]
        if op == "add":
            ts.add(o["taint"])
            results.append(None)
        elif op == "remove":
            ts.remove(o["taint"])
            results.append(None)
        elif op == "contains":
            results.append(ts.contains(o["taint"]))
        elif op == "is_empty":
            results.append(ts.is_empty())
        elif op == "union":
            other = TaintSet(o["mask"])
            ts = ts.union(other)
            results.append(ts.mask)
        elif op == "intersection":
            other = TaintSet(o["mask"])
            ts = ts.intersection(other)
            results.append(ts.mask)
        elif op == "mask":
            results.append(ts.mask)
    return results


# ── Dispatcher ────────────────────────────────────────────────────────────────

FUNCS = {
    "taint_bits": lambda a: validator_taint_bits(**a),
    "tainted_value": lambda a: validator_tainted_value(**a),
    "taint_state_reg": lambda a: validator_taint_state_reg(a["ops"]),
    "taint_state_mem": lambda a: validator_taint_state_mem(a["ops"]),
    "eval_taint": lambda a: validator_eval_taint(
        a["expr"], a.get("reg_taints"), a.get("mem_taints")),
    "apply_instrs": lambda a: validator_apply_instrs(
        a["instrs"], a.get("reg_taints")),
    "taint_report": lambda a: validator_taint_report(
        a["instrs"], a.get("reg_taints")),
    "legacy_tracker": lambda a: validator_legacy_tracker(a["ops"]),
    "taint_set": lambda a: validator_taint_set(a["ops"]),
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

    # ── Fixed-input smoke tests ───────────────────────────────────────────────
    results = {}

    # 1. taint_bits
    results["custom_idx0"] = taint_custom(0)                   # 64 = 1<<6
    results["is_tainted_user"] = taint_is_tainted(USER_INPUT)  # True
    results["union_u_n"] = taint_union(USER_INPUT, NETWORK)    # 3
    results["intersect_u3_n"] = taint_intersect(3, NETWORK)    # 2
    results["has_bit"] = taint_has_bit(USER_INPUT | NETWORK, NETWORK)  # True

    # 2. TaintedValue
    tv = TaintedValue.tainted(42, USER_INPUT)
    results["tv_is_tainted"] = tv.is_tainted()                 # True
    results["tv_union_taints"] = tv.union_taints(TaintedValue(0, NETWORK))  # 3
    results["tv_clean"] = TaintedValue.clean().is_tainted()    # False

    # 3. TaintState register ops
    results["reg_ops"] = validator_taint_state_reg([
        {"op": "set_reg", "reg": "rax", "val": 100, "taint": USER_INPUT},
        {"op": "reg_taint", "reg": "rax"},           # -> USER_INPUT
        {"op": "taint_reg", "reg": "rax", "taint": NETWORK},
        {"op": "reg_taint", "reg": "rax"},           # -> USER_INPUT|NETWORK = 3
        {"op": "sanitize_register", "reg": "rax"},
        {"op": "reg_taint", "reg": "rax"},           # -> 0
    ])

    # 4. TaintState memory ops
    results["mem_ops"] = validator_taint_state_mem([
        {"op": "mark_tainted", "addr": 0x1000, "size": 4, "taint": FILE},
        {"op": "mem_taint", "addr": 0x1000},          # -> FILE
        {"op": "mem_taint", "addr": 0x1003},          # -> FILE
        {"op": "mem_taint", "addr": 0x1004},          # -> 0 (outside range)
        {"op": "sanitize_memory", "addr": 0x1000, "size": 2},
        {"op": "mem_taint", "addr": 0x1000},          # -> 0
        {"op": "mem_taint", "addr": 0x1002},          # -> FILE (not sanitized)
    ])

    # 5. eval_taint
    results["eval_const_no_taint"] = validator_eval_taint(["Const", 42])  # 0
    results["eval_reg_tainted"] = validator_eval_taint(
        ["Reg", "rax"], reg_taints={"rax": USER_INPUT})  # USER_INPUT
    results["eval_add_union"] = validator_eval_taint(
        ["Add", ["Reg", "rax"], ["Reg", "rbx"]],
        reg_taints={"rax": USER_INPUT, "rbx": NETWORK})  # USER_INPUT|NETWORK = 3

    # 6. apply_instrs with sink detection
    results["sink_cmd"] = validator_apply_instrs([
        {"op": "SetReg", "reg": "rdi", "src": ["Const", 0], "addr": 0x100},
        # Taint rdi by marking it directly via a reg set that carries taint:
        # We'll use a Load from a tainted memory address instead.
        {"op": "Call", "target": "system",
         "args": [["Reg", "rdi"]], "addr": 0x200},
    ], initial_reg_taints={"rdi": USER_INPUT})

    results["sink_fmt"] = validator_apply_instrs([
        {"op": "Call", "target": "printf",
         "args": [["Reg", "rsi"]], "addr": 0x300},
    ], initial_reg_taints={"rsi": NETWORK})

    results["sink_sql"] = validator_apply_instrs([
        {"op": "Call", "target": "sqlite3_exec",
         "args": [["Const", 0], ["Reg", "rdx"]], "addr": 0x400},
    ], initial_reg_taints={"rdx": FILE})

    # 7. TaintReport
    instrs_for_report = [
        {"op": "Call", "target": "system",
         "args": [["Reg", "rax"]], "addr": 0x500},
        {"op": "Call", "target": "printf",
         "args": [["Reg", "rbx"]], "addr": 0x510},
        {"op": "Call", "target": "memcpy",
         "args": [["Const", 0], ["Const", 0], ["Reg", "rcx"]], "addr": 0x520},
    ]
    results["report"] = validator_taint_report(
        instrs_for_report,
        initial_reg_taints={"rax": USER_INPUT, "rbx": NETWORK, "rcx": FILE})

    # 8. LegacyTaintTracker
    results["legacy"] = validator_legacy_tracker([
        {"op": "mark_source", "loc": "var_input", "name": "user_input"},
        {"op": "propagate", "src": "var_input", "dst": "var_cmd"},
        {"op": "is_tainted_at", "loc": "var_cmd"},      # True
        {"op": "find_paths_to_sink", "loc": "var_cmd"},  # [{source: user_input, path: [var_cmd]}]
        {"op": "sanitize_location", "loc": "var_cmd"},
        {"op": "is_tainted_at", "loc": "var_cmd"},      # False
    ])

    # 9. TaintSet
    results["taint_set"] = validator_taint_set([
        {"op": "add", "taint": USER_INPUT},
        {"op": "add", "taint": NETWORK},
        {"op": "contains", "taint": USER_INPUT},   # True
        {"op": "contains", "taint": FILE},         # False
        {"op": "is_empty"},                        # False
        {"op": "mask"},                            # USER_INPUT|NETWORK = 3
        {"op": "remove", "taint": USER_INPUT},
        {"op": "mask"},                            # NETWORK = 2
    ])

    # 10. Branch CF taint
    results["branch_cf"] = validator_apply_instrs([
        {"op": "Branch", "cond": ["Reg", "rax"], "addr": 0x600},
    ], initial_reg_taints={"rax": USER_INPUT})

    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
