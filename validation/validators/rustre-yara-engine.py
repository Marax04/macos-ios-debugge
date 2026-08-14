"""Python equivalent of rustre-yara-engine public API.

Stdlib-only reproduction of function signatures from rustre-yara-engine.md.
Each function accepts inputs analogous to the Rust API and returns
equivalent Python types.
"""

import struct
import hashlib
import json
import re
import math
import os
import time
import base64 as _b64
from collections import defaultdict


# =====================================================================
# src/lib.rs
# =====================================================================

class YaraRule:
    def __init__(self, name):
        self.name = name
        self.namespace = "default"
        self.tags = []
        self.meta = {}
        self.strings = []
        self.condition = None

    @staticmethod
    def new(name):
        return YaraRule(name)

    def with_tag(self, tag):
        self.tags.append(tag); return self

    def with_meta(self, key, value):
        self.meta[key] = value; return self

    def with_string(self, s):
        self.strings.append(s); return self

    def with_condition(self, condition):
        self.condition = condition; return self


class YaraScanner:
    def __init__(self):
        self._rules = []

    @staticmethod
    def new():
        return YaraScanner()

    def add_rule(self, rule):
        self._rules.append(rule)

    def rule_count(self):
        return len(self._rules)

    def scan(self, data):
        return [{"rule": r.name, "offsets": []} for r in self._rules]

    def scan_names(self, data):
        return [r.name for r in self._rules]


class YaraParser:
    @staticmethod
    def new():
        return YaraParser()

    def parse_rule(self, text):
        m = re.search(r"rule\s+(\w+)", text)
        if not m:
            raise ValueError("no rule")
        return YaraRule(m.group(1))

    def parse_rules(self, text):
        return [YaraRule(n) for n in re.findall(r"rule\s+(\w+)", text)]


class YaraRuleDefinition:
    def __init__(self, id_, source):
        self.id = str(id_)
        self.source = str(source)
        self.namespace = "default"
        self.tags = []
        self.meta = {}

    @staticmethod
    def new(id_, source):
        return YaraRuleDefinition(id_, source)

    @staticmethod
    def parse_name_from_source(src):
        m = re.search(r"rule\s+(\w+)", src)
        return m.group(1) if m else None

    def with_namespace(self, ns):
        self.namespace = str(ns); return self

    def with_tag(self, tag):
        self.tags.append(str(tag)); return self

    def with_meta(self, key, value):
        self.meta[key] = str(value); return self


class YaraRuleSet:
    def __init__(self):
        self._sources = []
        self._compiled = False

    @staticmethod
    def new():
        return YaraRuleSet()

    def add_rule(self, source):
        self._sources.append(source)

    def add_file(self, path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        n = len(re.findall(r"rule\s+\w+", text))
        self._sources.append(text)
        return n

    def add_directory(self, dir_):
        count = 0
        for root, _, files in os.walk(dir_):
            for fn in files:
                if fn.endswith((".yar", ".yara")):
                    count += self.add_file(os.path.join(root, fn))
        return count

    def compile(self):
        self._compiled = True

    def len(self):
        return len(self._sources)

    def is_empty(self):
        return not self._sources

    def is_compiled(self):
        return self._compiled


class YaraEngineScanner:
    def __init__(self, ruleset):
        if not ruleset.is_compiled():
            ruleset.compile()
        self._ruleset = ruleset

    @staticmethod
    def new(ruleset):
        return YaraEngineScanner(ruleset)

    def scan_bytes(self, data):
        return []

    def scan_file(self, path):
        with open(path, "rb") as f:
            return self.scan_bytes(f.read())

    def scan_directory(self, dir_):
        out = {}
        for root, _, files in os.walk(dir_):
            for fn in files:
                p = os.path.join(root, fn)
                out[p] = self.scan_file(p)
        return out

    def scan_process(self, pid):
        return []

    def rules_arc(self):
        return self._ruleset


class RuleSetBuilder:
    def __init__(self):
        self._rules = {}
        self._enabled = set()

    @staticmethod
    def new():
        return RuleSetBuilder()

    def add(self, name, source):
        self._rules[name] = str(source); self._enabled.add(name); return self

    def enable(self, name):
        if name in self._rules: self._enabled.add(name)
        return self

    def disable(self, name):
        self._enabled.discard(name); return self

    def contains(self, name):
        return name in self._rules

    def len(self):
        return len(self._rules)

    def is_empty(self):
        return not self._rules

    def enabled_count(self):
        return len(self._enabled)

    def compile_enabled(self):
        rs = YaraRuleSet()
        for n in self._enabled:
            rs.add_rule(self._rules[n])
        rs.compile()
        return YaraEngineScanner(rs)

    @staticmethod
    def builtin_rules():
        b = RuleSetBuilder()
        b.add("builtin_dummy", "rule builtin_dummy { condition: true }")
        return b


class RegionScanResult:
    def __init__(self, region_id, matches):
        self.region_id = str(region_id)
        self.matches = list(matches)

    @staticmethod
    def new(region_id, matches):
        return RegionScanResult(region_id, matches)

    def has_matches(self):
        return bool(self.matches)

    def total_patterns(self):
        return len(self.matches)


class ScanConfig:
    def __init__(self):
        self.concurrency = 1
        self.max_region_size = 1 << 30
        self.min_region_size = 0

    def with_concurrency(self, n):
        self.concurrency = n; return self

    def with_max_region_size(self, sz):
        self.max_region_size = sz; return self

    def with_min_region_size(self, sz):
        self.min_region_size = sz; return self

    def should_scan(self, size):
        return self.min_region_size <= size <= self.max_region_size


class ExternalSymbol:
    def __init__(self, name, kind, value):
        self.name = str(name); self.kind = kind; self.value = value

    @staticmethod
    def bool(name, value):
        return ExternalSymbol(name, "bool", bool(value))

    @staticmethod
    def int(name, value):
        return ExternalSymbol(name, "int", int(value))

    @staticmethod
    def float(name, value):
        return ExternalSymbol(name, "float", float(value))

    @staticmethod
    def str(name, value):
        return ExternalSymbol(name, "str", str(value))


class PeInfo:
    def __init__(self):
        self.is_pe = False
        self.machine = 0

    @staticmethod
    def from_bytes(data):
        p = PeInfo()
        p.is_pe = len(data) > 2 and data[:2] == b"MZ"
        return p

    def to_external_symbols(self):
        return [ExternalSymbol.bool("pe.is_pe", self.is_pe),
                ExternalSymbol.int("pe.machine", self.machine)]


class ElfInfo:
    def __init__(self):
        self.is_elf = False

    @staticmethod
    def from_bytes(data):
        e = ElfInfo()
        e.is_elf = len(data) > 4 and data[:4] == b"\x7fELF"
        return e

    def to_external_symbols(self):
        return [ExternalSymbol.bool("elf.is_elf", self.is_elf)]


class MachoInfo:
    def __init__(self):
        self.is_macho = False

    @staticmethod
    def from_bytes(data):
        m = MachoInfo()
        if len(data) >= 4:
            magic = data[:4]
            m.is_macho = magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                                   b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
        return m

    def to_external_symbols(self):
        return [ExternalSymbol.bool("macho.is_macho", self.is_macho)]


def compute_entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


class RuleCache:
    def __init__(self):
        self._map = {}

    @staticmethod
    def new():
        return RuleCache()

    @staticmethod
    def hash_sources(sources):
        h = hashlib.sha256()
        for s in sources:
            h.update(s.encode("utf-8"))
            h.update(b"\x00")
        return int.from_bytes(h.digest()[:8], "little")

    def get(self, hash_):
        return self._map.get(hash_)

    def insert(self, hash_, rules):
        self._map[hash_] = rules

    def clear(self):
        self._map.clear()

    def len(self):
        return len(self._map)

    def is_empty(self):
        return not self._map

    def get_or_compile(self, sources):
        h = RuleCache.hash_sources(sources)
        if h in self._map:
            return self._map[h]
        rs = YaraRuleSet()
        for s in sources:
            rs.add_rule(s)
        rs.compile()
        self._map[h] = rs
        return rs


class ProcessRegion:
    def __init__(self, base, size, protection):
        self.base = base; self.size = size
        self.protection = str(protection); self.module = None

    @staticmethod
    def new(base, size, protection):
        return ProcessRegion(base, size, protection)

    def with_module(self, module):
        self.module = str(module); return self


class ProcessScanner:
    def __init__(self, ruleset):
        self._engine = YaraEngineScanner(ruleset)

    @staticmethod
    def new(ruleset):
        return ProcessScanner(ruleset)

    def scan_regions(self, regions):
        return [self.scan_region(r, d) for (r, d) in regions]

    def scan_region(self, region, data):
        matches = self._engine.scan_bytes(data)
        return RegionScanResult(str(region.base), matches)

    def engine_scanner(self):
        return self._engine


# =====================================================================
# src/yara_vm.rs
# =====================================================================

class StackValue:
    def __init__(self, kind, val):
        self.kind = kind; self.val = val

    def as_bool(self):
        return bool(self.val) if self.val is not None else False

    def as_int(self):
        try: return int(self.val)
        except: return 0

    def as_float(self):
        try: return float(self.val)
        except: return 0.0

    def is_undefined(self):
        return self.kind == "undefined"


class Stack:
    def __init__(self):
        self._s = []

    @staticmethod
    def new():
        return Stack()

    def push(self, val):
        self._s.append(val)

    def pop(self):
        if not self._s:
            raise IndexError("stack empty")
        return self._s.pop()

    def peek(self):
        return self._s[-1] if self._s else None

    def depth(self):
        return len(self._s)

    def is_empty(self):
        return not self._s


class Variables:
    def __init__(self):
        self._m = {}

    @staticmethod
    def new():
        return Variables()

    def load(self, name):
        return self._m.get(name, StackValue("undefined", None))

    def store(self, name, val):
        self._m[str(name)] = val

    def increment(self, name):
        v = self._m.get(name)
        if v is None:
            self._m[name] = StackValue("int", 1)
        else:
            v.val = v.as_int() + 1; v.kind = "int"

    def len(self):
        return len(self._m)

    def is_empty(self):
        return not self._m


class MatchState:
    def __init__(self, file_size):
        self.file_size = file_size
        self._m = {}

    @staticmethod
    def new(file_size):
        return MatchState(file_size)

    def set_matches(self, id_, offsets):
        self._m[str(id_)] = list(offsets)

    def matched(self, id_):
        return bool(self._m.get(id_))

    def count(self, id_):
        return len(self._m.get(id_, []))

    def offset(self, id_, n):
        lst = self._m.get(id_, [])
        return lst[n] if 0 <= n < len(lst) else None

    def all_matched(self):
        return bool(self._m) and all(self._m.values())

    def any_matched(self):
        return any(self._m.values())


class YaraVm:
    def __init__(self, limit=10000):
        self.limit = limit

    @staticmethod
    def new():
        return YaraVm()

    @staticmethod
    def with_limit(limit):
        return YaraVm(limit)

    def execute(self, program, match_state):
        return True

    def run(self, program, match_state):
        return self.execute(program, match_state)


class VmDebugger:
    def __init__(self):
        self._bp = set()
        self._trace = []

    @staticmethod
    def new():
        return VmDebugger()

    def set_breakpoint(self, ip):
        self._bp.add(ip)

    def clear_breakpoints(self):
        self._bp.clear()

    def trace_execute(self, program, match_state):
        self._trace = list(range(len(program)))
        return True

    @staticmethod
    def disassemble(program):
        return "\n".join(f"{i:04x}: {op}" for i, op in enumerate(program))

    def trace_len(self):
        return len(self._trace)


class OptimizedVm:
    def __init__(self):
        pass

    @staticmethod
    def new():
        return OptimizedVm()

    def execute(self, program, match_state):
        return True


def compile_any_of(patterns):
    return [("ANY_OF", list(patterns))]


def compile_all_of(patterns):
    return [("ALL_OF", list(patterns))]


def compile_filesize_gt(threshold):
    return [("FILESIZE_GT", int(threshold))]


# =====================================================================
# src/rule_compiler.rs
# =====================================================================

class MultiPatternBuilder:
    def __init__(self, patterns):
        self._patterns = [bytes(p) for p in patterns]

    @staticmethod
    def build(patterns):
        return MultiPatternBuilder(patterns)

    def search(self, data):
        out = []
        for pid, p in enumerate(self._patterns):
            if not p: continue
            i = 0
            while True:
                j = data.find(p, i)
                if j < 0: break
                out.append((j, pid))
                i = j + 1
        return out


class LiteralMatcher:
    def __init__(self, pattern):
        self._p = bytes(pattern)

    @staticmethod
    def from_literal(pattern):
        return LiteralMatcher(pattern)

    def run(self, data):
        out = []
        if not self._p: return out
        i = 0
        while True:
            j = data.find(self._p, i)
            if j < 0: break
            out.append(j); i = j + 1
        return out


class RuleCompiler:
    def __init__(self, options=None):
        self.options = options or {}

    @staticmethod
    def new():
        return RuleCompiler()

    @staticmethod
    def with_options(options):
        return RuleCompiler(options)

    def compile_rules(self, rules):
        return [self.compile_rule(r) for r in rules]

    def compile_rule(self, rule):
        return {"name": rule.name, "compiled": True}


def serialize_to_cache(rules):
    return json.dumps(rules, default=lambda o: getattr(o, "__dict__", str(o))).encode("utf-8")


def deserialize_from_cache(data):
    return json.loads(bytes(data).decode("utf-8"))


def parse_yara_text(source):
    return [YaraRule(n) for n in re.findall(r"rule\s+(\w+)", source)]


# =====================================================================
# src/performance_profiler.rs
# =====================================================================

class Timer:
    def __init__(self):
        self._start = None
        self._total = 0.0
        self._samples = 0

    @staticmethod
    def new():
        return Timer()

    def start(self):
        self._start = time.perf_counter()

    def stop(self):
        if self._start is None: return 0.0
        d = time.perf_counter() - self._start
        self._total += d; self._samples += 1
        self._start = None
        return d

    def total(self):
        return self._total

    def average(self):
        return self._total / self._samples if self._samples else 0.0

    def samples(self):
        return self._samples

    def reset(self):
        self._start = None; self._total = 0.0; self._samples = 0


class RuleProfile:
    def __init__(self, rule_name):
        self.rule_name = str(rule_name)
        self.total_ns = 0
        self.calls = 0
        self.matches = 0
        self.bytes_scanned = 0
        self.strings = {}

    @staticmethod
    def new(rule_name):
        return RuleProfile(rule_name)

    def avg_ns(self):
        return self.total_ns // self.calls if self.calls else 0

    def match_rate(self):
        return self.matches / self.calls if self.calls else 0.0

    def throughput_mb_s(self):
        if self.total_ns == 0: return 0.0
        return (self.bytes_scanned / (1024 * 1024)) / (self.total_ns / 1e9)

    def slowest_string(self):
        if not self.strings: return None
        k = max(self.strings, key=lambda x: self.strings[x])
        return (k, self.strings[k])

    def record_string(self, ident, elapsed_ns, matched):
        self.strings[ident] = self.strings.get(ident, 0) + elapsed_ns


class CacheStats:
    def __init__(self):
        self.hits = 0; self.misses = 0; self.size = 0; self.capacity = 1

    def hit_rate(self):
        t = self.hits + self.misses
        return self.hits / t if t else 0.0

    def fill_rate(self):
        return self.size / self.capacity if self.capacity else 0.0

    def record_hit(self):
        self.hits += 1

    def record_miss(self):
        self.misses += 1

    def reset(self):
        self.hits = 0; self.misses = 0


class HotString:
    def __init__(self, rule_name, ident, total_ns):
        self.rule_name = rule_name; self.ident = ident; self.total_ns = total_ns


class OptimizationSuggestion:
    def __init__(self, text):
        self.text = text


class PerformanceProfiler:
    def __init__(self):
        self.profiles = {}
        self.cache = CacheStats()
        self.session_ns = 0
        self.bytes_scanned = 0
        self._active = {}

    @staticmethod
    def new():
        return PerformanceProfiler()

    def begin_rule(self, rule_name):
        self._active[rule_name] = time.perf_counter_ns()

    def end_rule(self, rule_name, matched, bytes_):
        start = self._active.pop(rule_name, None)
        prof = self.profiles.setdefault(rule_name, RuleProfile(rule_name))
        if start is not None:
            prof.total_ns += time.perf_counter_ns() - start
        prof.calls += 1
        if matched: prof.matches += 1
        prof.bytes_scanned += bytes_

    def begin_string(self, rule_name, string_id):
        self._active[(rule_name, string_id)] = time.perf_counter_ns()

    def end_string(self, rule_name, string_id, matched):
        start = self._active.pop((rule_name, string_id), None)
        prof = self.profiles.setdefault(rule_name, RuleProfile(rule_name))
        elapsed = (time.perf_counter_ns() - start) if start is not None else 0
        prof.record_string(string_id, elapsed, matched)

    def cache_hit(self):
        self.cache.record_hit()

    def cache_miss(self):
        self.cache.record_miss()

    def set_cache_size(self, n):
        self.cache.size = n

    def record_file(self, bytes_):
        self.bytes_scanned += bytes_

    def set_session_ns(self, ns):
        self.session_ns = ns

    def slowest_rules(self, n):
        return sorted(self.profiles.values(), key=lambda p: p.total_ns, reverse=True)[:n]

    def hottest_strings(self, n):
        out = []
        for prof in self.profiles.values():
            for ident, ns in prof.strings.items():
                out.append(HotString(prof.rule_name, ident, ns))
        out.sort(key=lambda h: h.total_ns, reverse=True)
        return out[:n]

    def suggestions(self):
        s = []
        if self.cache.hit_rate() < 0.5:
            s.append(OptimizationSuggestion("low cache hit rate"))
        return s

    def session_throughput_mb_s(self):
        if self.session_ns == 0: return 0.0
        return (self.bytes_scanned / (1024 * 1024)) / (self.session_ns / 1e9)

    def summary_report(self):
        return f"rules={len(self.profiles)} bytes={self.bytes_scanned}"

    def reset(self):
        self.profiles.clear(); self.cache.reset()
        self.session_ns = 0; self.bytes_scanned = 0


class ProfilerSession:
    def __init__(self):
        self.profiler = PerformanceProfiler()

    @staticmethod
    def new():
        return ProfilerSession()

    def finish(self):
        return self.profiler


# =====================================================================
# src/string_match_engine.rs
# =====================================================================

class ModifierSet:
    NOCASE = 1; WIDE = 2; ASCII = 4; FULLWORD = 8; BASE64 = 16; XOR = 32

    def __init__(self, bits=0):
        self.bits = bits

    @staticmethod
    def new():
        return ModifierSet(0)

    def set(self, m):
        return ModifierSet(self.bits | (m.bits if isinstance(m, ModifierSet) else m))

    def has(self, m):
        b = m.bits if isinstance(m, ModifierSet) else m
        return (self.bits & b) == b

    def nocase(self):  return bool(self.bits & self.NOCASE)
    def wide(self):    return bool(self.bits & self.WIDE)
    def ascii(self):   return bool(self.bits & self.ASCII)
    def fullword(self):return bool(self.bits & self.FULLWORD)
    def base64(self):  return bool(self.bits & self.BASE64)
    def xor(self):     return bool(self.bits & self.XOR)


class HexClass:
    def __init__(self, lo=0, hi=0xFF, wild=False):
        self.lo = lo; self.hi = hi; self.wild = wild

    def to_flag(self):
        return ModifierSet(0)

    def matches(self, byte):
        return self.lo <= byte <= self.hi


class HexPattern:
    def __init__(self, classes):
        self.classes = classes

    @staticmethod
    def parse(src):
        toks = src.replace("{", "").replace("}", "").split()
        cls = []
        for t in toks:
            if t == "??":
                cls.append(HexClass(0, 0xFF, True))
            else:
                try:
                    v = int(t, 16); cls.append(HexClass(v, v))
                except ValueError:
                    raise ValueError(f"bad hex token: {t}")
        return HexPattern(cls)

    def match_at(self, data, offset):
        if offset + len(self.classes) > len(data):
            return None
        for i, c in enumerate(self.classes):
            if not c.matches(data[offset + i]):
                return None
        return len(self.classes)


class YaraString:
    def __init__(self, id_, kind, payload, mods):
        self.id = id_; self.kind = kind; self.payload = payload; self.mods = mods

    @staticmethod
    def new_text(id_, text, mods):
        return YaraString(id_, "text", str(text), mods)

    @staticmethod
    def new_hex(id_, pat, mods):
        return YaraString(id_, "hex", pat, mods)

    @staticmethod
    def new_regex(id_, regex, mods):
        return YaraString(id_, "regex", str(regex), mods)


class ContextWindow:
    def __init__(self, offset, before, after):
        self.offset = offset; self.before = before; self.after = after

    def extract(self, buf, match_len):
        start = max(0, self.offset - self.before)
        end = min(len(buf), self.offset + match_len + self.after)
        return buf[start:end]


class StringMatch:
    def __init__(self, offset, length, id_):
        self.offset = offset; self.length = length; self.id = id_


class StringMatchEngine:
    def __init__(self, max_matches=1 << 20):
        self.max_matches = max_matches

    @staticmethod
    def new():
        return StringMatchEngine()

    def with_max_matches(self, n):
        self.max_matches = n; return self

    def find_all(self, ys, data):
        out = []
        if ys.kind == "text":
            needle = ys.payload.encode("utf-8") if isinstance(ys.payload, str) else bytes(ys.payload)
            if ys.mods.nocase():
                d = data.lower(); n = needle.lower()
            else:
                d = data; n = needle
            i = 0
            while len(out) < self.max_matches:
                j = d.find(n, i)
                if j < 0: break
                out.append(StringMatch(j, len(n), ys.id))
                i = j + 1
        elif ys.kind == "hex":
            for i in range(len(data)):
                ml = ys.payload.match_at(data, i)
                if ml is not None:
                    out.append(StringMatch(i, ml, ys.id))
                    if len(out) >= self.max_matches: break
        elif ys.kind == "regex":
            flags = re.IGNORECASE if ys.mods.nocase() else 0
            for m in re.finditer(ys.payload.encode("utf-8"), data, flags):
                out.append(StringMatch(m.start(), m.end() - m.start(), ys.id))
                if len(out) >= self.max_matches: break
        return out

    def match_with_context(self, ys, data, before, after):
        matches = self.find_all(ys, data)
        return [(m, ContextWindow(m.offset, before, after).extract(data, m.length)) for m in matches]


class MultiStringMatcher:
    def __init__(self):
        self._strings = []
        self._engine = StringMatchEngine()

    @staticmethod
    def new():
        return MultiStringMatcher()

    def add_string(self, s):
        self._strings.append(s)

    def match_all(self, data):
        out = {}
        for s in self._strings:
            out[s.id] = self._engine.find_all(s, data)
        return out

    def total_matches(self, data):
        return sum(len(v) for v in self.match_all(data).values())

    def matched_ids(self, data):
        return [k for k, v in self.match_all(data).items() if v]


def parse_modifiers(keywords):
    bits = 0
    xor_range_v = None
    for kw in keywords:
        k = kw.lower()
        if k == "nocase": bits |= ModifierSet.NOCASE
        elif k == "wide": bits |= ModifierSet.WIDE
        elif k == "ascii": bits |= ModifierSet.ASCII
        elif k == "fullword": bits |= ModifierSet.FULLWORD
        elif k == "base64": bits |= ModifierSet.BASE64
        elif k.startswith("xor"):
            bits |= ModifierSet.XOR
            m = re.match(r"xor\((\d+)(?:-(\d+))?\)", k)
            if m:
                lo = int(m.group(1)); hi = int(m.group(2)) if m.group(2) else lo
                xor_range_v = (lo, hi)
        else:
            raise ValueError(f"unknown modifier: {kw}")
    return (ModifierSet(bits), xor_range_v)


# =====================================================================
# src/scan_engine.rs
# =====================================================================

class ScanEngine:
    def __init__(self, rules, options):
        self.rules = rules; self.options = options; self.progress = None

    @staticmethod
    def new(rules, options):
        return ScanEngine(rules, options)

    def with_progress(self, cb):
        self.progress = cb; return self

    def scan(self, targets):
        return {"targets": len(targets), "matches": []}


# =====================================================================
# src/rule_parser_ext.rs
# =====================================================================

class Token:
    def __init__(self, kind, value):
        self.kind = kind; self.value = value


class Lexer:
    def __init__(self, src):
        self.src = src; self.pos = 0

    @staticmethod
    def new(src):
        return Lexer(src)

    def next_token(self):
        while self.pos < len(self.src) and self.src[self.pos].isspace():
            self.pos += 1
        if self.pos >= len(self.src):
            return Token("EOF", "")
        ch = self.src[self.pos]
        if ch.isalpha() or ch == "_":
            j = self.pos
            while j < len(self.src) and (self.src[j].isalnum() or self.src[j] == "_"):
                j += 1
            tok = Token("IDENT", self.src[self.pos:j]); self.pos = j; return tok
        if ch.isdigit():
            j = self.pos
            while j < len(self.src) and self.src[j].isdigit():
                j += 1
            tok = Token("NUM", self.src[self.pos:j]); self.pos = j; return tok
        self.pos += 1
        return Token("PUNCT", ch)

    def tokenize(self):
        toks = []
        while True:
            t = self.next_token()
            toks.append(t)
            if t.kind == "EOF": break
        return toks


class RuleAst:
    def __init__(self, name, strings, condition):
        self.name = name; self.strings = strings; self.condition = condition

    def has_strings(self):
        return bool(self.strings)

    def is_trivial(self):
        return self.condition == "true"


class BytecodeEmitter:
    def __init__(self):
        pass

    @staticmethod
    def new():
        return BytecodeEmitter()

    @staticmethod
    def emit(cond, out):
        out.append(("EVAL", cond))

    def emit_rule(self, cond, out):
        out.append(("RULE_BEGIN", None))
        out.append(("EVAL", cond))
        out.append(("RULE_END", None))


class ExtendedParser:
    def __init__(self):
        pass

    @staticmethod
    def new():
        return ExtendedParser()

    def compile(self, src):
        m = re.search(r"rule\s+(\w+)", src)
        if not m: return ("err", "no rule")
        return ("ok", {"name": m.group(1)})

    def compile_all(self, src):
        return [("ok", {"name": n}) for n in re.findall(r"rule\s+(\w+)", src)]


# =====================================================================
# src/string_modifier_engine.rs
# =====================================================================

class ModifierContext:
    def __init__(self):
        self.nocase = False; self.wide = False; self.ascii_ = True
        self.fullword = False; self.xor = None; self.base64 = False

    @staticmethod
    def nocase():
        c = ModifierContext(); c.nocase = True; return c

    @staticmethod
    def wide():
        c = ModifierContext(); c.wide = True; c.ascii_ = False; return c

    @staticmethod
    def wide_ascii():
        c = ModifierContext(); c.wide = True; c.ascii_ = True; return c

    @staticmethod
    def fullword():
        c = ModifierContext(); c.fullword = True; return c

    @staticmethod
    def xor_all():
        c = ModifierContext(); c.xor = (0, 255); return c

    @staticmethod
    def xor_range(min_, max_):
        c = ModifierContext(); c.xor = (min_, max_); return c

    @staticmethod
    def base64():
        c = ModifierContext(); c.base64 = True; return c


class MatchCandidate:
    def __init__(self, bytes_, label):
        self.bytes = bytes_; self.label = label


def nocase_transform(bytes_):
    return bytes(b | 0x20 if 0x41 <= b <= 0x5A else b for b in bytes_)


def nocase_wide_transform(wide):
    out = bytearray(wide)
    for i in range(0, len(out) - 1, 2):
        b = out[i]
        if 0x41 <= b <= 0x5A:
            out[i] = b | 0x20
    return bytes(out)


def to_wide(ascii_):
    out = bytearray()
    for b in ascii_:
        out.append(b); out.append(0)
    return bytes(out)


def from_wide(wide):
    return bytes(wide[i] for i in range(0, len(wide), 2))


def xor_bytes(input_, key):
    return bytes(b ^ key for b in input_)


def all_xor_variants(input_):
    return [(k, xor_bytes(input_, k)) for k in range(256)]


def xor_range_variants(input_, min_, max_):
    return [(k, xor_bytes(input_, k)) for k in range(min_, max_ + 1)]


def detect_xor_key(plaintext, data):
    best_key, best_count = 0, 0
    for k in range(256):
        v = xor_bytes(plaintext, k)
        cnt = 0; i = 0
        while True:
            j = data.find(v, i)
            if j < 0: break
            cnt += 1; i = j + 1
        if cnt > best_count:
            best_count = cnt; best_key = k
    return (best_key, best_count)


def base64_encode(input_, variant, custom):
    if custom is None:
        return _b64.b64encode(bytes(input_))
    std = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    table = bytes.maketrans(std, bytes(custom))
    return _b64.b64encode(bytes(input_)).translate(table)


def base64_decode_standard(input_):
    try:
        return _b64.b64decode(bytes(input_), validate=False)
    except Exception:
        return None


def base64_decode(input_, alpha):
    std = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    table = bytes.maketrans(bytes(alpha), std)
    try:
        return _b64.b64decode(bytes(input_).translate(table), validate=False)
    except Exception:
        return None


def scan(data, pattern, nocase):
    if nocase:
        d = data.lower(); p = pattern.lower()
    else:
        d = data; p = pattern
    out = []
    if not p: return out
    i = 0
    while True:
        j = d.find(p, i)
        if j < 0: break
        out.append(j); i = j + 1
    return out


class ModifierEngine:
    @staticmethod
    def generate_candidates(raw_bytes, ctx):
        out = [MatchCandidate(bytes(raw_bytes), "raw")]
        if ctx.nocase:
            out.append(MatchCandidate(nocase_transform(raw_bytes), "nocase"))
        if ctx.wide:
            out.append(MatchCandidate(to_wide(raw_bytes), "wide"))
        if ctx.xor:
            for k, b in xor_range_variants(raw_bytes, ctx.xor[0], ctx.xor[1]):
                out.append(MatchCandidate(b, f"xor:{k}"))
        if ctx.base64:
            out.append(MatchCandidate(base64_encode(raw_bytes, 0, None), "b64"))
        return out

    @staticmethod
    def filter_fullword(matches, data):
        out = []
        for off, length in matches:
            l_ok = off == 0 or not chr(data[off - 1]).isalnum()
            r_ok = off + length >= len(data) or not chr(data[off + length]).isalnum()
            if l_ok and r_ok:
                out.append((off, length))
        return out


class ScanHit:
    def __init__(self, offset, key, label):
        self.offset = offset; self.key = key; self.label = label


class ModifierScanner:
    def __init__(self, ctx):
        self.ctx = ctx

    @staticmethod
    def new(ctx):
        return ModifierScanner(ctx)

    def scan_all(self, pattern, data):
        out = []
        for c in ModifierEngine.generate_candidates(pattern, self.ctx):
            for off in scan(data, c.bytes, False):
                out.append(ScanHit(off, None, c.label))
        return out

    def xor_key_count(self):
        if self.ctx.xor is None: return 0
        return self.ctx.xor[1] - self.ctx.xor[0] + 1


class ModifierStatistics:
    def __init__(self, variants, complexity):
        self.variants = variants; self.complexity = complexity

    @staticmethod
    def compute(pattern, ctx):
        v = 1
        if ctx.nocase: v *= 2
        if ctx.wide: v *= 2
        if ctx.xor: v *= (ctx.xor[1] - ctx.xor[0] + 1)
        if ctx.base64: v *= 3
        return ModifierStatistics(v, v * len(pattern))


# =====================================================================
# src/module_pe.rs
# =====================================================================

class PeMachine:
    def __init__(self, v):
        self.v = v

    @staticmethod
    def from_u16(v):
        return PeMachine(v)

    def name(self):
        return {0x14c: "I386", 0x8664: "AMD64", 0x1c0: "ARM", 0xaa64: "ARM64"}.get(self.v, "UNKNOWN")


class PeSubsystem:
    def __init__(self, v):
        self.v = v

    @staticmethod
    def from_u16(v):
        return PeSubsystem(v)

    def name(self):
        return {1: "NATIVE", 2: "GUI", 3: "CUI", 9: "WINCE_GUI"}.get(self.v, "UNKNOWN")


class PeSection:
    def __init__(self, name="", chars=0):
        self.name = name; self.characteristics = chars

    def is_executable(self):
        return bool(self.characteristics & 0x20000000)

    def is_writable(self):
        return bool(self.characteristics & 0x80000000)

    def is_readable(self):
        return bool(self.characteristics & 0x40000000)


class PeExport:
    def __init__(self, name, rva):
        self.name = name; self.rva = rva


class PeImport:
    def __init__(self, name):
        self.name = name


class PeModule:
    def __init__(self):
        self.machine = 0; self.subsystem = 0
        self.dll_characteristics = 0
        self.sections = []
        self.exports = []
        self.imports = {}

    @staticmethod
    def new():
        return PeModule()

    def parse(self, data):
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise ValueError("not PE")
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
            raise ValueError("bad PE sig")
        coff = e_lfanew + 4
        self.machine = struct.unpack_from("<H", data, coff)[0]
        n_sections = struct.unpack_from("<H", data, coff + 2)[0]
        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        opt = coff + 20
        if opt + 2 <= len(data):
            magic = struct.unpack_from("<H", data, opt)[0]
            if magic in (0x10b, 0x20b) and opt + 72 <= len(data):
                self.subsystem = struct.unpack_from("<H", data, opt + 68)[0]
                self.dll_characteristics = struct.unpack_from("<H", data, opt + 70)[0]
        sect = opt + opt_size
        for i in range(n_sections):
            off = sect + i * 40
            if off + 40 > len(data): break
            name = data[off:off+8].rstrip(b"\x00").decode("ascii", "replace")
            chars = struct.unpack_from("<I", data, off + 36)[0]
            self.sections.append(PeSection(name, chars))

    def machine_type(self):
        return PeMachine(self.machine)

    def subsystem_type(self):
        return PeSubsystem(self.subsystem)

    def has_aslr(self):
        return bool(self.dll_characteristics & 0x0040)

    def has_nx(self):
        return bool(self.dll_characteristics & 0x0100)

    def has_cfg(self):
        return bool(self.dll_characteristics & 0x4000)

    def export_by_name(self, name):
        for e in self.exports:
            if e.name == name: return e
        return None

    def imports_from_dll(self, dll):
        return self.imports.get(dll)

    def section_count(self):
        return len(self.sections)


# =====================================================================
# src/condition_evaluator.rs
# =====================================================================

class StringPattern:
    def __init__(self, pat):
        self.pat = pat
        rx = re.escape(pat).replace(r"\*", ".*").replace(r"\?", ".")
        self._rx = re.compile("^" + rx + "$")

    def matches(self, name):
        return bool(self._rx.match(name))


class EvaluationContext:
    def __init__(self, data, file_size, matches, strings=None):
        self.data = data; self.file_size = file_size
        self.matches = matches
        self.strings = strings or []

    @staticmethod
    def new(data, file_size, matches, strings=None):
        return EvaluationContext(data, file_size, matches, strings)

    def resolve_set(self, set_):
        if set_ == "them" or set_ == "*":
            return list(self.matches.keys())
        if isinstance(set_, str) and "*" in set_:
            sp = StringPattern(set_)
            return [k for k in self.matches if sp.matches(k)]
        if isinstance(set_, (list, tuple)):
            return list(set_)
        return [set_]

    def count(self, ident):
        return len(self.matches.get(ident, []))

    def present(self, ident):
        return bool(self.matches.get(ident))

    def at(self, ident, offset):
        return offset in self.matches.get(ident, [])

    def within(self, ident, lo, hi):
        return any(lo <= o <= hi for o in self.matches.get(ident, []))


class Value:
    def __init__(self, kind, val):
        self.kind = kind; self.val = val


class Evaluator:
    @staticmethod
    def eval(expr, ctx):
        v = Evaluator.eval_value(expr, ctx)
        if isinstance(v, Value):
            return bool(v.val)
        return bool(v)

    @staticmethod
    def eval_value(expr, ctx):
        if isinstance(expr, bool):
            return Value("bool", expr)
        if isinstance(expr, (int, float)):
            return Value("int", expr)
        if isinstance(expr, str):
            return Value("bool", ctx.present(expr))
        return Value("bool", False)

    @staticmethod
    def eval_legacy(expr, ctx):
        return Evaluator.eval(expr, ctx)


def eval_n_of(n, results):
    return sum(1 for r in results if r) >= n


def eval_for_n_of(n, results):
    return eval_n_of(n, results)


def eval_for_all_of(results):
    return all(results) if results else False


def eval_for_any_of(results):
    return any(results)


def eval_for_none_of(results):
    return not any(results)


def expand_wildcard(pattern, strings):
    return [s.id for s in strings if pattern.matches(s.id)]


class Conditions:
    @staticmethod
    def eval(expr, ctx):
        return Evaluator.eval(expr, ctx)


def at(ident, offset, ctx):
    return ctx.at(ident, offset)


def in_range(ident, lo, hi, ctx):
    return ctx.within(ident, lo, hi)


def offsets_in_range(offsets, lo, hi):
    return [o for o in offsets if lo <= o <= hi]


def compare(data_len, op, value):
    op = op.lower()
    if op in ("==", "eq"): return data_len == value
    if op in ("!=", "ne"): return data_len != value
    if op in ("<", "lt"):  return data_len < value
    if op in ("<=", "le"): return data_len <= value
    if op in (">", "gt"):  return data_len > value
    if op in (">=", "ge"): return data_len >= value
    return False


def parse_size(s):
    m = re.match(r"^\s*(\d+)\s*(KB|MB|GB|B)?\s*$", s, re.IGNORECASE)
    if not m: return None
    n = int(m.group(1))
    unit = (m.group(2) or "B").upper()
    return n * {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3}[unit]


# =====================================================================
# src/string_matcher.rs
# =====================================================================

class MatcherConfig:
    def __init__(self, ascii_=True, wide=False):
        self.ascii_ = ascii_; self.wide = wide

    @staticmethod
    def ascii_only():
        return MatcherConfig(True, False)

    @staticmethod
    def wide_and_ascii():
        return MatcherConfig(True, True)

    def describe(self):
        bits = []
        if self.ascii_: bits.append("ascii")
        if self.wide: bits.append("wide")
        return "+".join(bits) or "none"


class MatchResult:
    def __init__(self, offset, matched_bytes, string_id, xor_key=None):
        self.offset = offset
        self.matched_bytes = bytes(matched_bytes)
        self.string_id = str(string_id)
        self.xor_key = xor_key

    @staticmethod
    def new(offset, matched_bytes, string_id):
        return MatchResult(offset, matched_bytes, string_id)

    @staticmethod
    def xor_match(offset, matched_bytes, string_id, xor_key):
        return MatchResult(offset, matched_bytes, string_id, xor_key)


def is_wide_at(data, offset, len_):
    if offset + len_ * 2 > len(data): return False
    for i in range(len_):
        if data[offset + 2 * i + 1] != 0:
            return False
    return True


class MultiPatternMatcher:
    def __init__(self, patterns):
        self._patterns = [(name, bytes(pat)) for name, pat in patterns]

    @staticmethod
    def new(patterns):
        return MultiPatternMatcher(patterns)

    def find_all(self, data):
        out = []
        for name, pat in self._patterns:
            if not pat: continue
            i = 0
            while True:
                j = data.find(pat, i)
                if j < 0: break
                out.append((name, j))
                i = j + 1
        return out

    def pattern_count(self):
        return len(self._patterns)


class PatternMatch:
    def __init__(self, id_, offset, length):
        self.id = id_; self.offset = offset; self.length = length


class StringMatcher:
    def __init__(self):
        self._texts = []
        self._hexes = []
        self._regexes = []

    @staticmethod
    def new():
        return StringMatcher()

    def add_text(self, id_, text, nocase=False):
        b = text.encode("utf-8") if isinstance(text, str) else bytes(text)
        self._texts.append((id_, b, nocase))

    def add_hex(self, id_, pattern):
        if isinstance(pattern, str):
            pattern = HexPattern.parse(pattern)
        self._hexes.append((id_, pattern))

    def add_regex(self, id_, regex):
        self._regexes.append((id_, re.compile(regex.encode("utf-8") if isinstance(regex, str) else regex)))

    def scan(self, data):
        out = []
        for id_, b, nocase in self._texts:
            d = data.lower() if nocase else data
            n = b.lower() if nocase else b
            i = 0
            while True:
                j = d.find(n, i)
                if j < 0: break
                out.append(PatternMatch(id_, j, len(b))); i = j + 1
        for id_, pat in self._hexes:
            for i in range(len(data)):
                ml = pat.match_at(data, i)
                if ml is not None: out.append(PatternMatch(id_, i, ml))
        for id_, rx in self._regexes:
            for m in rx.finditer(data):
                out.append(PatternMatch(id_, m.start(), m.end() - m.start()))
        return out

    def scan_one(self, data, id_):
        return [m for m in self.scan(data) if m.id == id_]

    def string_count(self):
        return len(self._texts) + len(self._hexes) + len(self._regexes)


# =====================================================================
# src/distributed_scan.rs
# =====================================================================

class Priority:
    LOW = 0; NORMAL = 1; HIGH = 2


class ScanJob:
    _counter = 0

    def __init__(self, kind, payload, label):
        ScanJob._counter += 1
        self.id = ScanJob._counter
        self.kind = kind; self.payload = payload; self.label = label
        self.priority = Priority.NORMAL
        self.tags = {}
        self.created = time.time()
        self.ttl = None

    @staticmethod
    def new_memory(label, data):
        return ScanJob("memory", bytes(data), str(label))

    @staticmethod
    def new_file(path):
        return ScanJob("file", str(path), str(path))

    def with_priority(self, p):
        self.priority = p; return self

    def with_tag(self, key, value):
        self.tags[str(key)] = str(value); return self

    def is_expired(self):
        return self.ttl is not None and (time.time() - self.created) > self.ttl


class WorkerNode:
    def __init__(self, id_, address=None):
        self.id = str(id_); self.address = address

    @staticmethod
    def local(id_):
        return WorkerNode(id_, None)

    @staticmethod
    def remote(id_, address):
        return WorkerNode(id_, str(address))


class JobResult:
    def __init__(self, job_id, matches):
        self.job_id = job_id; self.matches = matches


class JobQueue:
    def __init__(self):
        self._q = []
        self._results = {}
        self.submitted = 0; self.completed = 0; self.expired = 0

    @staticmethod
    def new():
        return JobQueue()

    def submit(self, job):
        self._q.append(job); self.submitted += 1
        return job.id

    def drain_expired(self):
        before = len(self._q)
        self._q = [j for j in self._q if not j.is_expired()]
        drained = before - len(self._q)
        self.expired += drained
        return drained

    def pop(self):
        if not self._q: return None
        self._q.sort(key=lambda j: -j.priority)
        return self._q.pop(0)

    def record_result(self, result):
        self._results[result.job_id] = result
        self.completed += 1

    def get_result(self, job_id):
        return self._results.get(job_id)

    def pending(self):
        return len(self._q)

    def stats_snapshot(self):
        return (self.submitted, self.completed, self.expired)


class AggregatedReport:
    def __init__(self):
        self.results = []


class UniqueMatch:
    def __init__(self, key, count):
        self.key = key; self.count = count


class DistributedScanner:
    def __init__(self, rules, workers):
        self.rules = rules; self.workers = workers
        self.queue = JobQueue()
        self._shutdown = False

    @staticmethod
    def new(rules, workers):
        return DistributedScanner(rules, workers)

    def submit(self, job):
        if self._shutdown: return None
        return self.queue.submit(job)

    def submit_batch(self, jobs):
        acc = 0; rej = 0
        for j in jobs:
            if self.submit(j) is not None: acc += 1
            else: rej += 1
        return (acc, rej)

    def run_local(self):
        rep = AggregatedReport()
        while True:
            j = self.queue.pop()
            if j is None: break
            result = JobResult(j.id, [])
            self.queue.record_result(result)
            rep.results.append(result)
        return rep

    def get_result(self, job_id):
        return self.queue.get_result(job_id)

    def pending(self):
        return self.queue.pending()

    def shutdown(self):
        self._shutdown = True

    def is_shutdown(self):
        return self._shutdown


def deduplicate_results(results):
    counts = defaultdict(int)
    for r in results:
        for m in r.matches:
            counts[str(m)] += 1
    return [UniqueMatch(k, c) for k, c in counts.items()]


class RemoteWorkerClient:
    def __init__(self, base_url):
        self.base_url = str(base_url); self.api_key = None

    @staticmethod
    def new(base_url):
        return RemoteWorkerClient(base_url)

    def with_api_key(self, key):
        self.api_key = str(key); return self

    def submit_remote(self, job):
        return ("ok", job.id)

    def poll_result(self, job_id):
        return ("ok", None)


# =====================================================================
# src/match_context.rs
# =====================================================================

class SectionRange:
    def __init__(self, name, start, end, exec_=False, data_=False):
        self.name = name; self.start = start; self.end = end
        self.exec_ = exec_; self.data_ = data_

    def contains_offset(self, offset):
        return self.start <= offset < self.end

    def is_executable(self):
        return self.exec_

    def is_data(self):
        return self.data_


class MatchedBytes:
    def __init__(self, bytes_):
        self.bytes = bytes(bytes_)

    def as_utf8(self):
        try:
            return self.bytes.decode("utf-8")
        except UnicodeDecodeError:
            return None


class EntropyStats:
    def __init__(self, entropy=0.0, length=0):
        self.entropy = entropy; self.length = length

    @staticmethod
    def compute(data, offset, length):
        chunk = data[offset:offset + length]
        return EntropyStats(compute_entropy(chunk), len(chunk))

    def is_high_entropy_context(self):
        return self.entropy >= 7.0


class DisasmHint:
    def __init__(self, mnemonic, arch):
        self.mnemonic = mnemonic; self.arch = arch

    def display(self):
        return f"{self.arch}: {self.mnemonic}"


def disasm_hint(data, offset, arch):
    if offset >= len(data): return None
    return DisasmHint(f"db {data[offset]:#04x}", str(arch))


class CaptureGroup:
    def __init__(self, name, value):
        self.name = name; self.value = value


class MatchContext:
    def __init__(self):
        self.bytes = b""
        self.captures = []
        self.meta = {}
        self.section = None


class PeSectionRange(SectionRange):
    pass


def classify_pe_offset(sections, offset):
    for s in sections:
        if s.contains_offset(offset):
            return s
    return None


def parse_pe_sections(data):
    out = []
    try:
        pm = PeModule(); pm.parse(data)
        off = 0
        for s in pm.sections:
            out.append(PeSectionRange(s.name, off, off + 0x1000,
                                      s.is_executable(),
                                      not s.is_executable()))
            off += 0x1000
    except Exception:
        pass
    return out


class MatchContextBuilder:
    def __init__(self):
        self._mc = MatchContext()

    def build(self, data, offset, length):
        self._mc.bytes = bytes(data[offset:offset + length])
        return self._mc

    def add_capture(self, grp):
        self._mc.captures.append(grp)

    def set_meta(self, key, value):
        self._mc.meta[str(key)] = str(value)

    def is_in_code_section(self):
        return self._mc.section is not None and self._mc.section.is_executable()

    def is_in_overlay(self):
        return self._mc.section is None

    def summary(self):
        return f"bytes={len(self._mc.bytes)} captures={len(self._mc.captures)}"


class DisasmArch:
    X86 = "x86"; X64 = "x64"; ARM64 = "arm64"


class ContextEngine:
    def __init__(self, arch, sections=None):
        self.arch = arch
        self._sections = sections or []

    @staticmethod
    def for_pe(data, arch):
        return ContextEngine(arch, parse_pe_sections(data))

    @staticmethod
    def for_raw(arch):
        return ContextEngine(arch, [])

    def build(self, data, offset, length):
        b = MatchContextBuilder()
        mc = b.build(data, offset, length)
        mc.section = classify_pe_offset(self._sections, offset)
        return mc

    def sections(self):
        return self._sections


# =====================================================================
# src/condition_expr_eval.rs
# =====================================================================

class StringMatchState:
    def __init__(self):
        self._m = {}

    @staticmethod
    def new():
        return StringMatchState()

    def add_matches(self, id_, offsets):
        self._m.setdefault(id_, []).extend(offsets)

    def string_matched(self, id_):
        return bool(self._m.get(id_))

    def string_count(self, id_):
        return len(self._m.get(id_, []))

    def string_at(self, id_, offset):
        return offset in self._m.get(id_, [])

    def string_in(self, id_, from_, to):
        return any(from_ <= o <= to for o in self._m.get(id_, []))


class ExprValue:
    def __init__(self, kind, val):
        self.kind = kind; self.val = val

    def as_int(self):
        return int(self.val) if isinstance(self.val, (int, float)) else None

    def as_bool(self):
        return bool(self.val) if isinstance(self.val, bool) else None


class EvalResult:
    def __init__(self, value):
        self.value = value

    def as_bool(self):
        return bool(self.value) if isinstance(self.value, bool) else None

    def as_int(self):
        try: return int(self.value)
        except: return None

    def is_undefined(self):
        return self.value is None


class EvalContext:
    def __init__(self, file_size=0, matches=None):
        self.file_size = file_size
        self.matches = matches or StringMatchState()


class ConditionEvaluator:
    def __init__(self):
        self.file_bytes = b""

    @staticmethod
    def new():
        return ConditionEvaluator()

    def with_file_bytes(self, bytes_):
        self.file_bytes = bytes(bytes_); return self

    def eval(self, expr, ctx):
        if callable(expr):
            return EvalResult(expr(ctx))
        if isinstance(expr, bool):
            return EvalResult(expr)
        if isinstance(expr, str):
            return EvalResult(ctx.matches.string_matched(expr))
        return EvalResult(None)


class CompiledCondition:
    def __init__(self, rule_name, condition):
        self.rule_name = str(rule_name); self.condition = condition

    @staticmethod
    def new(rule_name, condition):
        return CompiledCondition(rule_name, condition)

    def evaluate(self, evaluator, ctx):
        r = evaluator.eval(self.condition, ctx)
        b = r.as_bool()
        return bool(b) if b is not None else False


# =====================================================================
if __name__ == "__main__":
    assert compute_entropy(b"abcabc") > 0
    assert YaraRuleDefinition.parse_name_from_source("rule foo { condition: true }") == "foo"
    assert parse_size("2KB") == 2048
    assert compare(10, ">", 5)
    print("OK")
