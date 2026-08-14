#!/usr/bin/env python3
"""Rigorous ground-truth validation for all MCP tools prefixed with vsa_.

Reference implementations are derived directly from the Rust source in
crates/rustre-analysis-vsa/src/lib.rs — every algorithm is translated
inline here, no external libs are used beyond the Python stdlib.
"""
import json, subprocess, sys, math
from typing import Any, Optional

# ── MCP transport ────────────────────────────────────────────────────────────
EXE    = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"

proc = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    bufsize=0,
)

_rid = 0
def _send(req: dict):
    proc.stdin.write((json.dumps(req) + "\n").encode())
    proc.stdin.flush()

def _recv() -> dict:
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("MCP server died")
    return json.loads(line)

def _call(method: str, params: dict) -> dict:
    global _rid
    _rid += 1
    _send({"jsonrpc": "2.0", "id": _rid, "method": method, "params": params})
    return _recv()

# Handshake
_send({"jsonrpc":"2.0","id":0,"method":"initialize","params":{
    "protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"rigorous_vsa","version":"1"}}})
_recv()
_send({"jsonrpc":"2.0","method":"notifications/initialized"})

# Open project so server is initialised (needed for some tools to not fail)
r = _call("tools/call", {"name": "project.open", "arguments": {"path": TARGET}})

def tool_call(name: str, args: dict) -> dict:
    """Call an MCP tool and return parsed JSON result or error dict."""
    r = _call("tools/call", {"name": name, "arguments": args})
    if "error" in r:
        return {"__jsonrpc_error": str(r["error"])}
    content = r.get("result", {}).get("content", [])
    txt = content[0].get("text", "") if content else ""
    if r.get("result", {}).get("isError"):
        return {"__tool_error": txt}
    try:
        return json.loads(txt)
    except Exception:
        return {"__raw": txt}

# ── Python reference implementations ────────────────────────────────────────

U64_MAX = (1 << 64) - 1

def _gcd(a: int, b: int) -> int:
    """Matches Rust gcd: gcd(a,0) = max(a,1)"""
    if b == 0:
        return max(a, 1)
    return _gcd(b, a % b)

def _wrapping_add(a: int, b: int) -> int:
    return (a + b) & U64_MAX

def _wrapping_sub(a: int, b: int) -> int:
    return (a - b) & U64_MAX

# ─── StridedInterval reference ───────────────────────────────────────────────

class SI:
    BOTTOM_SENTINEL = (1, 0, 1)

    def __init__(self, lo: int, hi: int, stride: int):
        self.lo = lo
        self.hi = hi
        self.stride = stride

    @classmethod
    def bottom(cls) -> "SI":
        s = cls.__new__(cls)
        s.lo, s.hi, s.stride = 1, 0, 1
        return s

    @classmethod
    def top(cls) -> "SI":
        return cls(0, U64_MAX, 1)

    @classmethod
    def singleton(cls, v: int) -> "SI":
        return cls(v, v, 1)

    @classmethod
    def new(cls, lo: int, hi: int, stride: int) -> "SI":
        if lo > hi:
            return cls.bottom()
        stride = max(stride, 1)
        span = hi - lo
        hi2 = lo + (span // stride) * stride
        return cls(lo, hi2, stride)

    def is_bottom(self) -> bool:
        return self.lo > self.hi

    def is_top(self) -> bool:
        return self.lo == 0 and self.hi == U64_MAX and self.stride == 1

    def is_singleton(self) -> bool:
        return not self.is_bottom() and self.lo == self.hi

    def contains(self, v: int) -> bool:
        if self.is_bottom():
            return False
        return self.lo <= v <= self.hi and (v - self.lo) % self.stride == 0

    def join(self, other: "SI") -> "SI":
        if self.is_bottom():
            return SI(other.lo, other.hi, other.stride)
        if other.is_bottom():
            return SI(self.lo, self.hi, self.stride)
        lo = min(self.lo, other.lo)
        hi = max(self.hi, other.hi)
        diff = abs(other.lo - self.lo)
        stride = _gcd(_gcd(self.stride, other.stride), diff)
        return SI.new(lo, hi, max(stride, 1))

    def widen(self, new: "SI") -> "SI":
        if self.is_bottom():
            return SI(new.lo, new.hi, new.stride)
        if new.is_bottom():
            return SI(self.lo, self.hi, self.stride)
        lo = 0 if new.lo < self.lo else self.lo
        hi = U64_MAX if new.hi > self.hi else self.hi
        if lo == 0 and hi == U64_MAX:
            return SI.top()
        stride = min(self.stride * 2, U64_MAX)
        stride = max(stride, 1)
        return SI.new(lo, hi, stride)

    def add(self, rhs: "SI") -> "SI":
        if self.is_bottom() or rhs.is_bottom():
            return SI.bottom()
        lo = _wrapping_add(self.lo, rhs.lo)
        hi = _wrapping_add(self.hi, rhs.hi)
        # Overflow check: if hi wrapped below lo and neither operand was u64::MAX
        if hi < lo and not (self.hi == U64_MAX or rhs.hi == U64_MAX):
            return SI.top()
        stride = max(_gcd(self.stride, rhs.stride), 1)
        return SI.new(lo, hi, stride)

    def display(self) -> str:
        if self.is_bottom():
            return "⊥"
        if self.is_top():
            return "⊤"
        if self.is_singleton():
            return "{" + hex(self.lo) + "}"
        return f"[{hex(self.lo)}, {hex(self.hi)}]/{self.stride}"

    def as_dict(self):
        return {"lo": self.lo, "hi": self.hi, "stride": self.stride}

def ref_si_new(lo: int, hi: int, stride: int) -> SI:
    return SI.new(lo, hi, stride)

def ref_si_singleton(v: int) -> SI:
    return SI.singleton(v)

def ref_si_join(a_lo, a_hi, a_stride, b_lo, b_hi, b_stride) -> SI:
    a = SI.new(a_lo, a_hi, a_stride)
    b = SI.new(b_lo, b_hi, b_stride)
    return a.join(b)

def ref_si_add(a_lo, a_hi, a_stride, b_lo, b_hi, b_stride) -> SI:
    a = SI.new(a_lo, a_hi, a_stride)
    b = SI.new(b_lo, b_hi, b_stride)
    return a.add(b)

def ref_is_definitely_null(v: int) -> bool:
    si = SI.singleton(v)
    return si.is_singleton() and si.lo == 0

def ref_may_be_out_of_bounds(lo, hi, stride, base, limit) -> bool:
    si = SI.new(lo, hi, stride)
    if si.is_bottom():
        return False
    if si.is_top():
        return True
    return si.lo < base or si.hi >= limit

# ─── ValueSet reference ───────────────────────────────────────────────────────

MAX_CONCRETE = 32

class VS:
    """Python mirror of rustre_analysis_vsa::ValueSet."""

    def __init__(self, kind: str, **kw):
        # kind: 'bottom','top','concrete','range'
        self.kind = kind
        if kind == 'concrete':
            self.vals = sorted(kw['vals'])
        elif kind == 'range':
            self.lo = kw['lo']
            self.hi = kw['hi']
            self.stride = kw['stride']

    @classmethod
    def bottom(cls):
        return cls('bottom')

    @classmethod
    def top(cls):
        return cls('top')

    @classmethod
    def singleton(cls, v: int):
        return cls('concrete', vals=[v])

    @classmethod
    def interval(cls, lo: int, hi: int):
        if lo == hi:
            return cls.singleton(lo)
        return cls('range', lo=lo, hi=hi, stride=1)

    @classmethod
    def strided(cls, lo: int, hi: int, stride: int):
        stride = max(stride, 1)
        if lo == hi:
            return cls.singleton(lo)
        return cls('range', lo=lo, hi=hi, stride=stride)

    def is_bottom(self) -> bool:
        return self.kind == 'bottom'

    def is_top(self) -> bool:
        return self.kind == 'top'

    def contains(self, v: int) -> bool:
        if self.kind == 'bottom':
            return False
        if self.kind == 'top':
            return True
        if self.kind == 'concrete':
            return v in self.vals
        # range
        return self.lo <= v <= self.hi and (v - self.lo) % self.stride == 0

    def join(self, other: "VS") -> "VS":
        if self.is_bottom():
            return _vs_clone(other)
        if other.is_bottom():
            return _vs_clone(self)
        if self.is_top() or other.is_top():
            return VS.top()
        if self.kind == 'concrete' and other.kind == 'concrete':
            merged = list(self.vals)
            for v in other.vals:
                if v not in merged:
                    merged.append(v)
            if len(merged) > MAX_CONCRETE:
                lo = min(merged)
                hi = max(merged)
                return VS('range', lo=lo, hi=hi, stride=1)
            return VS('concrete', vals=sorted(merged))
        if self.kind == 'concrete' and other.kind == 'range':
            min_v = min(self.vals) if self.vals else U64_MAX
            max_v = max(self.vals) if self.vals else 0
            new_lo = min(other.lo, min_v)
            new_hi = max(other.hi, max_v)
            return VS('range', lo=new_lo, hi=new_hi, stride=_gcd(other.stride, 1))
        if self.kind == 'range' and other.kind == 'concrete':
            min_v = min(other.vals) if other.vals else U64_MAX
            max_v = max(other.vals) if other.vals else 0
            new_lo = min(self.lo, min_v)
            new_hi = max(self.hi, max_v)
            return VS('range', lo=new_lo, hi=new_hi, stride=_gcd(self.stride, 1))
        # range × range
        lo = min(self.lo, other.lo)
        hi = max(self.hi, other.hi)
        stride = _gcd(self.stride, other.stride)
        return VS('range', lo=lo, hi=hi, stride=stride)

    def widen(self, other: "VS") -> "VS":
        if self.is_bottom():
            return _vs_clone(other)
        if other.is_bottom():
            return _vs_clone(self)
        if self.is_top() or other.is_top():
            return VS.top()
        if self.kind == 'concrete' and other.kind == 'concrete':
            merged = list(self.vals)
            for v in other.vals:
                if v not in merged:
                    merged.append(v)
            if len(merged) > MAX_CONCRETE:
                lo = min(merged)
                hi = max(merged)
                return VS('range', lo=lo, hi=hi, stride=1)
            return VS('concrete', vals=sorted(merged))
        # promote to range
        def _bounds(vs):
            if vs.kind == 'range':
                return vs.lo, vs.hi
            return min(vs.vals), max(vs.vals)
        self_lo, self_hi = _bounds(self)
        other_lo, other_hi = _bounds(other)
        lo = 0 if other_lo < self_lo else self_lo
        hi = U64_MAX if other_hi > self_hi else self_hi
        if lo == 0 and hi == U64_MAX:
            return VS.top()
        return VS('range', lo=lo, hi=hi, stride=1)

    def concretize(self, limit: int) -> Optional[list]:
        if self.kind == 'bottom':
            return []
        if self.kind == 'top':
            return None
        if self.kind == 'concrete':
            return list(self.vals)
        # range
        vals = []
        v = self.lo
        while True:
            vals.append(v)
            if len(vals) > limit:
                return None
            if v >= self.hi:
                break
            v = v + self.stride
            if v > self.hi:
                break
        return vals

    def display(self) -> str:
        if self.kind == 'bottom':
            return "⊥"
        if self.kind == 'top':
            return "⊤"
        if self.kind == 'concrete':
            return "{" + ", ".join(hex(x) for x in self.vals) + "}"
        return f"[{hex(self.lo)}, {hex(self.hi)}]/{self.stride}"

def _vs_clone(vs: VS) -> VS:
    if vs.kind == 'concrete':
        return VS('concrete', vals=list(vs.vals))
    if vs.kind == 'range':
        return VS('range', lo=vs.lo, hi=vs.hi, stride=vs.stride)
    return VS(vs.kind)

# ── Test cases ───────────────────────────────────────────────────────────────

results = []
mismatches = []

def _record(tool: str, args: dict, actual: dict, expected: dict, field_checks: dict, status: str):
    entry = {"tool": tool, "args": args, "status": status,
             "expected_fields": expected, "actual": actual}
    results.append(entry)
    if status == "FAIL":
        mismatches.append({"tool": tool, "expected": expected, "actual": actual})

def check(tool: str, args: dict, field_checks: dict):
    """Call tool, compare field_checks against returned JSON. field_checks maps field->expected."""
    actual = tool_call(tool, args)
    if "__jsonrpc_error" in actual or "__tool_error" in actual:
        _record(tool, args, actual, field_checks, field_checks, "FAIL")
        return
    ok = True
    for field, exp in field_checks.items():
        got = actual.get(field)
        if isinstance(exp, float):
            if not (isinstance(got, (int, float)) and abs(got - exp) < 1e-9):
                ok = False
                break
        elif got != exp:
            ok = False
            break
    _record(tool, args, actual, field_checks, field_checks, "PASS" if ok else "FAIL")

# ── vsa_valueset_singleton ───────────────────────────────────────────────────
# singleton(42): Concrete([42]), is_top=false, is_bottom=false, contains_value=true
check("vsa_valueset_singleton", {"value": 42},
      {"is_top": False, "is_bottom": False, "contains_value": True})
# singleton(0)
check("vsa_valueset_singleton", {"value": 0},
      {"is_top": False, "is_bottom": False, "contains_value": True})

# ── vsa_strided_interval_new ─────────────────────────────────────────────────
# new(0, 10, 2): lo=0, hi=10, stride=2
ref = SI.new(0, 10, 2)
check("vsa_strided_interval_new", {"lo": 0, "hi": 10, "stride": 2},
      {"lo": ref.lo, "hi": ref.hi, "stride": ref.stride})

# new(5, 5, 1): singleton
ref2 = SI.new(5, 5, 1)
check("vsa_strided_interval_new", {"lo": 5, "hi": 5, "stride": 1},
      {"lo": ref2.lo, "hi": ref2.hi, "stride": ref2.stride, "is_singleton": ref2.is_singleton()})

# new(0, 100, 3): hi should be snapped to 99 (0 + 33*3=99)
ref3 = SI.new(0, 100, 3)
check("vsa_strided_interval_new", {"lo": 0, "hi": 100, "stride": 3},
      {"lo": ref3.lo, "hi": ref3.hi, "stride": ref3.stride})

# ── vsa_valueset_top ─────────────────────────────────────────────────────────
check("vsa_valueset_top", {},
      {"is_top": True, "is_bottom": False})

# ── vsa_valueset_bottom ──────────────────────────────────────────────────────
check("vsa_valueset_bottom", {},
      {"is_top": False, "is_bottom": True})

# ── vsa_valueset_interval_wire ───────────────────────────────────────────────
# interval(10, 20): Range{lo=10, hi=20, stride=1}, not top, not bottom, contains_lo=true
vs_iv = VS.interval(10, 20)
check("vsa_valueset_interval_wire", {"lo": 10, "hi": 20},
      {"is_top": vs_iv.is_top(), "is_bottom": vs_iv.is_bottom(), "contains_lo": vs_iv.contains(10)})

# interval(7, 7): singleton
vs_iv2 = VS.interval(7, 7)
check("vsa_valueset_interval_wire", {"lo": 7, "hi": 7},
      {"is_top": vs_iv2.is_top(), "is_bottom": vs_iv2.is_bottom(), "contains_lo": vs_iv2.contains(7)})

# ── vsa_valueset_join_intervals_wire ─────────────────────────────────────────
# join [0,10] and [20,30]: display should be a range [0x0, 0x1e]/1
a = VS.interval(0, 10)
b = VS.interval(20, 30)
j = a.join(b)
check("vsa_valueset_join_intervals_wire", {"a_lo": 0, "a_hi": 10, "b_lo": 20, "b_hi": 30},
      {"display": j.display()})

# join [5,10] and [5,20]: [5,20]/1
a2 = VS.interval(5, 10)
b2 = VS.interval(5, 20)
j2 = a2.join(b2)
check("vsa_valueset_join_intervals_wire", {"a_lo": 5, "a_hi": 10, "b_lo": 5, "b_hi": 20},
      {"display": j2.display()})

# ── vsa_valueset_widen_intervals_wire ────────────────────────────────────────
# widen [5,10] toward [5,20]: since 20>10 => hi=u64::MAX => top
aw = VS.interval(5, 10)
bw = VS.interval(5, 20)
w = aw.widen(bw)
check("vsa_valueset_widen_intervals_wire", {"a_lo": 5, "a_hi": 10, "b_lo": 5, "b_hi": 20},
      {"is_top": w.is_top()})

# widen [5,20] toward [5,20]: stable, is_top should be False
aw2 = VS.interval(5, 20)
bw2 = VS.interval(5, 20)
w2 = aw2.widen(bw2)
check("vsa_valueset_widen_intervals_wire", {"a_lo": 5, "a_hi": 20, "b_lo": 5, "b_hi": 20},
      {"is_top": w2.is_top()})

# ── vsa_valueset_concretize_strided_wire ─────────────────────────────────────
# strided(0, 10, 2), limit=10: should enumerate [0,2,4,6,8,10]
vs_cs = VS.strided(0, 10, 2)
conc = vs_cs.concretize(10)
check("vsa_valueset_concretize_strided_wire", {"lo": 0, "hi": 10, "stride": 2, "limit": 10},
      {"values": conc, "enumerated": conc is not None})

# strided(0, 100, 1), limit=3: should fail (>limit) => enumerated=false, values=null
vs_cs2 = VS.strided(0, 100, 1)
conc2 = vs_cs2.concretize(3)
check("vsa_valueset_concretize_strided_wire", {"lo": 0, "hi": 100, "stride": 1, "limit": 3},
      {"enumerated": conc2 is not None})

# ── vsa_strided_interval_join_wire ───────────────────────────────────────────
r_j1 = ref_si_join(0, 10, 2, 20, 30, 2)
check("vsa_strided_interval_join_wire",
      {"a_lo": 0, "a_hi": 10, "a_stride": 2, "b_lo": 20, "b_hi": 30, "b_stride": 2},
      {"lo": r_j1.lo, "hi": r_j1.hi, "stride": r_j1.stride})

r_j2 = ref_si_join(0, 0, 1, 0, 0, 1)
check("vsa_strided_interval_join_wire",
      {"a_lo": 0, "a_hi": 0, "a_stride": 1, "b_lo": 0, "b_hi": 0, "b_stride": 1},
      {"lo": r_j2.lo, "hi": r_j2.hi, "stride": r_j2.stride})

# ── vsa_strided_interval_add_wire ────────────────────────────────────────────
# add [0,10]/2 + [0,5]/1 => [0+0, 10+5]/gcd(2,1)=1 => [0,15]/1
r_a1 = ref_si_add(0, 10, 2, 0, 5, 1)
check("vsa_strided_interval_add_wire",
      {"a_lo": 0, "a_hi": 10, "a_stride": 2, "b_lo": 0, "b_hi": 5, "b_stride": 1},
      {"lo": r_a1.lo, "hi": r_a1.hi, "stride": r_a1.stride})

# add {5}/1 + {3}/1 => {8}/1
r_a2 = ref_si_add(5, 5, 1, 3, 3, 1)
check("vsa_strided_interval_add_wire",
      {"a_lo": 5, "a_hi": 5, "a_stride": 1, "b_lo": 3, "b_hi": 3, "b_stride": 1},
      {"lo": r_a2.lo, "hi": r_a2.hi})

# ── vsa_is_definitely_null_wire ───────────────────────────────────────────────
# value=0: singleton(0) => is_definitely_null=True
check("vsa_is_definitely_null_wire", {"value": 0},
      {"is_definitely_null": ref_is_definitely_null(0)})

# value=1: singleton(1) => is_definitely_null=False
check("vsa_is_definitely_null_wire", {"value": 1},
      {"is_definitely_null": ref_is_definitely_null(1)})

# ── vsa_may_be_out_of_bounds_wire ─────────────────────────────────────────────
# [5,10]/1, base=0, limit=100: lo>=0 and hi<100 => False
check("vsa_may_be_out_of_bounds_wire",
      {"lo": 5, "hi": 10, "stride": 1, "base": 0, "limit": 100},
      {"may_be_out_of_bounds": ref_may_be_out_of_bounds(5, 10, 1, 0, 100)})

# [0,100]/1, base=0, limit=50: hi=100 >= 50 => True
check("vsa_may_be_out_of_bounds_wire",
      {"lo": 0, "hi": 100, "stride": 1, "base": 0, "limit": 50},
      {"may_be_out_of_bounds": ref_may_be_out_of_bounds(0, 100, 1, 0, 50)})

# [3,5]/1, base=10, limit=100: lo=3 < base=10 => True
check("vsa_may_be_out_of_bounds_wire",
      {"lo": 3, "hi": 5, "stride": 1, "base": 10, "limit": 100},
      {"may_be_out_of_bounds": ref_may_be_out_of_bounds(3, 5, 1, 10, 100)})

# ── Shutdown & output ────────────────────────────────────────────────────────
proc.stdin.close()
proc.terminate()

# Tally
passed = sum(1 for r in results if r["status"] == "PASS")
failed = sum(1 for r in results if r["status"] == "FAIL")
skipped = 0

# Count unique tools tested
tools_seen = {}
for r in results:
    t = r["tool"]
    if t not in tools_seen:
        tools_seen[t] = "PASS"
    if r["status"] == "FAIL":
        tools_seen[t] = "FAIL"

tools_hardened = len(tools_seen)
tools_passed = sum(1 for v in tools_seen.values() if v == "PASS")
tools_failed = sum(1 for v in tools_seen.values() if v == "FAIL")

summary = {
    "category": "vsa",
    "tools_hardened": tools_hardened,
    "tools_passed": tools_passed,
    "tools_failed": tools_failed,
    "tools_skipped": skipped,
    "mismatches": mismatches,
    "detail": results,
}

OUT = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_vsa_v2.json"
with open(OUT, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)

print(json.dumps({
    "category": "vsa",
    "tools_hardened": tools_hardened,
    "tools_passed": tools_passed,
    "tools_failed": tools_failed,
    "tools_skipped": skipped,
    "mismatches": mismatches,
}))
