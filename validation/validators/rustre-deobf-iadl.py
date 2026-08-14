"""
Python validator reproducing the public API of rustre-deobf-iadl.

Stdlib only (struct, hashlib, json, re, math, time, collections, zlib).
Each Rust public function has a Python equivalent accepting the same
input shapes and returning the same output types.
"""

from __future__ import annotations

import json
import math
import re
import struct
import time
import zlib
import hashlib
from collections import deque, OrderedDict
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple


# =============================================================================
# lib.rs
# =============================================================================

class IadlState:
    def __init__(self, global_score: float, complexity: int):
        self.global_score = float(global_score)
        self.complexity = int(complexity)

    @classmethod
    def new(cls, global_score: float, complexity: int) -> "IadlState":
        return cls(global_score, complexity)


class TentativeState:
    def __init__(self, hypothesis_id: str, score: float, complexity: int, rationale: str):
        self.hypothesis_id = str(hypothesis_id)
        self.score = float(score)
        self.complexity = int(complexity)
        self.rationale = str(rationale)

    @classmethod
    def new(cls, hypothesis_id, score, complexity, rationale):
        return cls(str(hypothesis_id), score, complexity, str(rationale))


class Hypothesis:
    def id(self) -> str: raise NotImplementedError
    def prior(self, state: IadlState) -> float: return 0.5
    def apply(self, state: IadlState) -> TentativeState: raise NotImplementedError


class Scorer:
    def name(self) -> str: raise NotImplementedError
    def weight(self) -> float: raise NotImplementedError
    def score(self, tentative: TentativeState, baseline: IadlState) -> float: raise NotImplementedError


class IadlConfig:
    def __init__(self, max_iter: int = 16, min_delta: float = 1e-3, budget_ms: int = 1000):
        self.max_iter = max_iter
        self.min_delta = min_delta
        self.budget_ms = budget_ms


class CandidateEvaluation:
    def __init__(self, hypothesis_id: str, tentative: TentativeState, total_score: float):
        self.hypothesis_id = hypothesis_id
        self.tentative = tentative
        self.total_score = total_score


class IadlReport:
    def __init__(self):
        self.iterations: List[CandidateEvaluation] = []
        self.final_score: float = 0.0
        self.converged: bool = False


class IadlOrchestrator:
    def __init__(self, config: IadlConfig):
        self._config = config

    @classmethod
    def default_config(cls): return cls(IadlConfig())

    @classmethod
    def new(cls, config): return cls(config)

    def config(self): return self._config

    def evaluate_all(self, state, hypotheses, scorers):
        out = []
        for h in hypotheses:
            t = h.apply(state)
            total = wsum = 0.0
            for s in scorers:
                total += s.weight() * s.score(t, state)
                wsum += s.weight()
            if wsum > 0: total /= wsum
            out.append(CandidateEvaluation(h.id(), t, total))
        out.sort(key=lambda c: c.total_score, reverse=True)
        return out

    def run(self, state, hypotheses, scorers):
        rep = IadlReport()
        cur = state
        for _ in range(self._config.max_iter):
            cands = self.evaluate_all(cur, hypotheses, scorers)
            if not cands: break
            best = cands[0]
            delta = best.total_score - cur.global_score
            rep.iterations.append(best)
            if delta < self._config.min_delta:
                rep.converged = True
                break
            cur = IadlState(best.tentative.score, best.tentative.complexity)
        rep.final_score = cur.global_score
        return rep


class ProtectionLayer:
    KNOWN = {"upx": 10, "vmprotect": 80, "themida": 90, "aspack": 15,
             "antidebug": 5, "antivm": 5, "string_enc": 20, "cfg_flat": 50}

    def __init__(self, name_): self._name = name_
    def name(self): return self._name
    def removal_cost(self): return self.KNOWN.get(self._name, 25)


class BinaryIadlState:
    def __init__(self, binary_size, function_count):
        self.binary_size = int(binary_size)
        self.function_count = int(function_count)
        self.entropy_by_section: Dict[str, float] = {}
        self.has_upx = False
        self.has_anti_debug = False

    @classmethod
    def new(cls, binary_size, function_count): return cls(binary_size, function_count)

    def is_high_entropy(self, section): return self.entropy_by_section.get(section, 0.0) > 7.0
    def has_packer(self): return self.has_upx or any(v > 7.5 for v in self.entropy_by_section.values())


class BinaryTentativeState:
    def __init__(self, naturalness=0.0, complexity_reduction=0.0, description=""):
        self.naturalness = float(naturalness)
        self.complexity_reduction = float(complexity_reduction)
        self.description = description

    def combined_score(self): return 0.6 * self.naturalness + 0.4 * self.complexity_reduction


class BinaryHypothesis:
    def id(self): raise NotImplementedError
    def name(self): raise NotImplementedError
    def prior(self, state): raise NotImplementedError
    def apply(self, state): raise NotImplementedError
    def cost_estimate(self): raise NotImplementedError


class _BH(BinaryHypothesis):
    _ID = 0; _NAME = ""; _COST = 0.1
    def id(self): return self._ID
    def name(self): return self._NAME
    def cost_estimate(self): return self._COST


class UPXUnpackHypothesis(_BH):
    _ID, _NAME, _COST = 1, "upx_unpack", 0.5
    def prior(self, s): return 0.9 if s.has_upx else 0.05
    def apply(self, s): return BinaryTentativeState(0.7, 0.5, "upx unpack")


class CflFlatteningHypothesis(_BH):
    _ID, _NAME, _COST = 2, "cfl_flatten", 1.0
    def prior(self, s): return 0.4
    def apply(self, s): return BinaryTentativeState(0.5, 0.6, "cfl")


class OpaquePredicateHypothesis(_BH):
    _ID, _NAME, _COST = 3, "opaque_pred", 0.3
    def prior(self, s): return 0.5
    def apply(self, s): return BinaryTentativeState(0.4, 0.3, "opaque")


class StringDecryptHypothesis(_BH):
    _ID, _NAME, _COST = 4, "string_decrypt", 0.2
    def prior(self, s): return 0.6
    def apply(self, s): return BinaryTentativeState(0.6, 0.2, "string")


class AntiDebugHypothesis(_BH):
    _ID, _NAME, _COST = 5, "anti_debug", 0.1
    def prior(self, s): return 0.8 if s.has_anti_debug else 0.1
    def apply(self, s): return BinaryTentativeState(0.3, 0.1, "antidebug")


class VmObfuscationHypothesis(_BH):
    _ID, _NAME, _COST = 6, "vm_obfuscation", 2.0
    def prior(self, s): return 0.2
    def apply(self, s): return BinaryTentativeState(0.3, 0.7, "vm")


class NaturalnessScorer:
    @staticmethod
    def score(state): return state.naturalness


class BinaryIadlReport:
    def __init__(self):
        self.recommendations: List[str] = []
        self.iterations = 0
        self.improvement = 0.0

    def has_progress(self): return self.improvement > 0.0
    def top_recommendation(self): return self.recommendations[0] if self.recommendations else None

    def to_json(self):
        return json.dumps({"recommendations": self.recommendations,
                           "iterations": self.iterations, "improvement": self.improvement})

    @classmethod
    def from_json(cls, s):
        d = json.loads(s)
        r = cls()
        r.recommendations = d.get("recommendations", [])
        r.iterations = d.get("iterations", 0)
        r.improvement = d.get("improvement", 0.0)
        return r


class BinaryIadlOrchestrator:
    def __init__(self): self._hyps: List[BinaryHypothesis] = []

    @classmethod
    def new(cls): return cls()

    def register(self, hypothesis): self._hyps.append(hypothesis)

    def run_state(self, state):
        rep = BinaryIadlReport()
        scored = []
        for h in self._hyps:
            t = h.apply(state)
            scored.append((h.prior(state) * t.combined_score(), h.name()))
        scored.sort(reverse=True)
        rep.recommendations = [n for _, n in scored]
        rep.iterations = len(self._hyps)
        rep.improvement = scored[0][0] if scored else 0.0
        return rep

    def run(self, binary): return self.run_state(analyze_binary_for_protections(binary))


def _entropy(data):
    if not data: return 0.0
    counts = [0] * 256
    for b in data: counts[b] += 1
    n = len(data); e = 0.0
    for c in counts:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return e


def analyze_binary_for_protections(data):
    st = BinaryIadlState(len(data), 0)
    st.entropy_by_section["full"] = _entropy(data)
    st.has_upx = b"UPX!" in data[:4096] or b"UPX0" in data[:4096]
    st.has_anti_debug = b"IsDebuggerPresent" in data or b"CheckRemoteDebugger" in data
    fc = 0
    for i in range(len(data) - 2):
        if data[i] == 0x55 and data[i + 1] == 0x8B and data[i + 2] == 0xEC:
            fc += 1
    st.function_count = fc
    return st


class HashAlgorithm:
    DJB2, FNV1A, SDBM, CRC32, ADLER32, ROR, UNKNOWN = (
        "djb2", "fnv1a", "sdbm", "crc32", "adler32", "ror", "unknown")
    _KNOWN = {DJB2, FNV1A, SDBM, CRC32, ADLER32, ROR}

    def __init__(self, v): self.v = v
    def name(self): return self.v
    def is_known(self): return self.v in self._KNOWN


def _djb2(d):
    h = 5381
    for b in d: h = ((h * 33) + b) & 0xFFFFFFFFFFFFFFFF
    return h


def _fnv1a(d):
    h = 0xCBF29CE484222325
    for b in d: h = ((h ^ b) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def _sdbm(d):
    h = 0
    for b in d: h = (b + (h << 6) + (h << 16) - h) & 0xFFFFFFFFFFFFFFFF
    return h


def _ror_hash(d):
    h = 0
    for b in d:
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + b) & 0xFFFFFFFF
    return h


def compute_hash(data, algorithm):
    a = algorithm.v if isinstance(algorithm, HashAlgorithm) else algorithm
    if a == HashAlgorithm.DJB2: return _djb2(data)
    if a == HashAlgorithm.FNV1A: return _fnv1a(data)
    if a == HashAlgorithm.SDBM: return _sdbm(data)
    if a == HashAlgorithm.CRC32: return zlib.crc32(data) & 0xFFFFFFFF
    if a == HashAlgorithm.ADLER32: return zlib.adler32(data) & 0xFFFFFFFF
    if a == HashAlgorithm.ROR: return _ror_hash(data)
    return 0


class ApiHash:
    def __init__(self, hash_, algorithm, file_offset):
        self.hash = int(hash_); self.algorithm = algorithm; self.file_offset = int(file_offset)
        self.name = None; self.dll = None

    @classmethod
    def new(cls, hash_, algorithm, file_offset): return cls(hash_, algorithm, file_offset)
    def with_name(self, name): self.name = str(name); return self
    def with_dll(self, dll): self.dll = str(dll); return self
    def is_resolved(self): return self.name is not None
    def is_fully_resolved(self): return self.name is not None and self.dll is not None


class ApiResolution:
    def __init__(self, api_hash, call_site):
        self.api_hash = api_hash; self.call_site = int(call_site)
        self.address = None; self.confidence = 0

    @classmethod
    def new(cls, api_hash, call_site): return cls(api_hash, call_site)
    def with_address(self, addr): self.address = int(addr); return self
    def with_confidence(self, conf): self.confidence = int(conf); return self
    def is_high_confidence(self): return self.confidence >= 80


class IadlDetector:
    @classmethod
    def new(cls): return cls()

    def scan_hash_constants(self, data):
        out = []
        for i in range(0, len(data) - 4, 4):
            v = struct.unpack_from("<I", data, i)[0]
            if 0x10000000 <= v <= 0xFFFFFFFF and (v & 0xFF) != 0:
                out.append((v, i))
        return out

    def detect_loadlib_pattern(self, data):
        out = []
        for i in range(len(data) - 1):
            if data[i] == 0xFF and data[i + 1] in (0xD0, 0xD2, 0x15):
                out.append(i)
        return out

    def identify_algorithm(self, hashes):
        if not hashes:
            return (HashAlgorithm(HashAlgorithm.UNKNOWN), 0)
        avg = sum(hashes) / len(hashes)
        if avg > (1 << 40):
            return (HashAlgorithm(HashAlgorithm.FNV1A), len(hashes))
        return (HashAlgorithm(HashAlgorithm.DJB2), len(hashes))

    def analyze(self, data, call_base):
        out = []
        for h, off in self.scan_hash_constants(data)[:16]:
            ah = ApiHash.new(h, HashAlgorithm(HashAlgorithm.DJB2), off)
            out.append(ApiResolution.new(ah, call_base + off).with_confidence(50))
        return out


class HashTable:
    def __init__(self, algorithm):
        self.algorithm = algorithm; self._map: Dict[int, str] = {}

    @classmethod
    def new(cls, algorithm): return cls(algorithm)

    @classmethod
    def build(cls, names, algorithm):
        t = cls(algorithm)
        for n in names: t.insert(n)
        return t

    def insert(self, name):
        self._map[compute_hash(name.encode("utf-8"), self.algorithm)] = str(name)

    def resolve(self, hash_): return self._map.get(int(hash_))
    def len(self): return len(self._map)
    def is_empty(self): return not self._map
    def entries(self): return list(self._map.items())


class ChainStep:
    def __init__(self, offset, call_type):
        self.offset = int(offset); self.call_type = str(call_type); self.argument = None

    @classmethod
    def new(cls, offset, call_type): return cls(offset, call_type)
    def with_argument(self, arg): self.argument = str(arg); return self


class LoadLibraryChain:
    def __init__(self): self.steps: List[ChainStep] = []

    @classmethod
    def new(cls): return cls()
    def push(self, step): self.steps.append(step)
    def len(self): return len(self.steps)
    def is_empty(self): return not self.steps

    def is_complete(self):
        kinds = {s.call_type for s in self.steps}
        return "LoadLibrary" in kinds and "GetProcAddress" in kinds


class ComplexityScorer(Scorer):
    def __init__(self, weight): self._w = float(weight)
    @classmethod
    def new(cls, weight): return cls(weight)
    def name(self): return "complexity"
    def weight(self): return self._w
    def score(self, t, b):
        if b.complexity == 0: return 0.0
        return max(0.0, 1.0 - (t.complexity / max(1, b.complexity)))


class ImprovementScorer(Scorer):
    def __init__(self, weight): self._w = float(weight)
    @classmethod
    def new(cls, weight): return cls(weight)
    def name(self): return "improvement"
    def weight(self): return self._w
    def score(self, t, b): return max(0.0, t.score - b.global_score)


class ConstantHypothesis(Hypothesis):
    def __init__(self, id_, score, complexity, rationale):
        self._id = str(id_); self._score = float(score)
        self._complexity = int(complexity); self._rationale = str(rationale); self._prior = 0.5

    @classmethod
    def new(cls, id_, score, complexity, rationale): return cls(id_, score, complexity, rationale)
    def with_prior(self, prior): self._prior = float(prior); return self
    def id(self): return self._id
    def prior(self, state): return self._prior
    def apply(self, state):
        return TentativeState.new(self._id, self._score, self._complexity, self._rationale)


class IncrementalHypothesis(Hypothesis):
    def __init__(self, id_, factor): self._id = str(id_); self._factor = float(factor)
    @classmethod
    def new(cls, id_, factor): return cls(id_, factor)
    def id(self): return self._id
    def prior(self, state): return 0.5
    def apply(self, state):
        return TentativeState.new(self._id, state.global_score + self._factor,
                                  max(0, int(state.complexity * (1.0 - self._factor))), "incr")


class ResolutionStats:
    def __init__(self, total=0, resolved=0, high_conf=0):
        self.total = total; self.resolved = resolved; self.high_conf = high_conf

    @classmethod
    def from_resolutions(cls, resolutions):
        total = len(resolutions)
        res = sum(1 for r in resolutions if r.api_hash.is_resolved())
        hc = sum(1 for r in resolutions if r.is_high_confidence())
        return cls(total, res, hc)

    def is_good_coverage(self):
        return self.total > 0 and (self.resolved / self.total) > 0.7


class IadlDeobfPass:
    def __init__(self, name_, config): self._name = str(name_); self._config = config
    @classmethod
    def new(cls, name_, config): return cls(name_, config)
    def name(self): return self._name
    def run(self, initial_score, initial_complexity, hypotheses, scorers):
        return IadlOrchestrator.new(self._config).run(
            IadlState.new(initial_score, initial_complexity), hypotheses, scorers)


class HypothesisRegistry:
    def __init__(self): self._items: "OrderedDict[str, Hypothesis]" = OrderedDict()
    @classmethod
    def new(cls): return cls()
    def register(self, hypothesis):
        hid = hypothesis.id()
        if hid in self._items: return False
        self._items[hid] = hypothesis
        return True
    def ids(self): return list(self._items.keys())
    def len(self): return len(self._items)
    def is_empty(self): return not self._items
    def all(self): return list(self._items.values())


# =============================================================================
# strategy_selector.rs
# =============================================================================

class IadlStrategy:
    BRUTE = "brute"; SYMBOLIC = "symbolic"; PATTERN = "pattern"
    HEURISTIC = "heuristic"; LEARNED = "learned"
    _ALL = [BRUTE, SYMBOLIC, PATTERN, HEURISTIC, LEARNED]
    _COST = {BRUTE: 1.0, SYMBOLIC: 0.8, PATTERN: 0.3, HEURISTIC: 0.2, LEARNED: 0.5}
    _PREC = {BRUTE: 0.4, SYMBOLIC: 0.9, PATTERN: 0.7, HEURISTIC: 0.5, LEARNED: 0.8}

    def __init__(self, v): self.v = v
    def name(self): return self.v
    def base_cost(self): return self._COST.get(self.v, 0.5)
    def base_precision(self): return self._PREC.get(self.v, 0.5)
    @classmethod
    def all(cls): return [cls(v) for v in cls._ALL]
    def __hash__(self): return hash(self.v)
    def __eq__(self, o): return isinstance(o, IadlStrategy) and o.v == self.v


class ObservedFeatures:
    def __init__(self, entropy=0.0, indirect_calls=0, string_density=0.0, cfg_complexity=0.0):
        self.entropy = entropy; self.indirect_calls = indirect_calls
        self.string_density = string_density; self.cfg_complexity = cfg_complexity


class StrategyScore:
    def __init__(self, strategy, precision, cost):
        self.strategy = strategy; self.precision = precision; self.cost = cost
    def utility(self): return self.precision - 0.3 * self.cost


class StrategyScorer:
    @staticmethod
    def score_strategy(strategy, features):
        prec = strategy.base_precision(); cost = strategy.base_cost()
        if features.entropy > 7.0 and strategy.v == IadlStrategy.PATTERN: prec *= 0.7
        if features.indirect_calls > 50 and strategy.v == IadlStrategy.SYMBOLIC: prec *= 1.1
        return StrategyScore(strategy, min(prec, 1.0), cost)

    @staticmethod
    def score_all(features):
        return [StrategyScorer.score_strategy(s, features) for s in IadlStrategy.all()]


class StrategyRecord:
    def __init__(self, strategy, score, success, iteration):
        self.strategy = strategy; self.score = float(score)
        self.success = bool(success); self.iteration = int(iteration); self.duration = 0.0
    @classmethod
    def new(cls, strategy, score, success, iteration): return cls(strategy, score, success, iteration)
    def with_duration(self, d): self.duration = float(d); return self


class StrategyHistory:
    def __init__(self): self.records: List[StrategyRecord] = []
    @classmethod
    def new(cls): return cls()
    def push(self, record): self.records.append(record)
    def attempt_count(self, strategy): return sum(1 for r in self.records if r.strategy == strategy)
    def best_score(self, strategy):
        xs = [r.score for r in self.records if r.strategy == strategy]
        return max(xs) if xs else None
    def average_score(self, strategy):
        xs = [r.score for r in self.records if r.strategy == strategy]
        return sum(xs) / len(xs) if xs else None
    def last_strategy(self): return self.records[-1].strategy if self.records else None
    def untried_strategies(self):
        tried = {r.strategy for r in self.records}
        return [s for s in IadlStrategy.all() if s not in tried]
    def ranked_by_performance(self):
        agg: Dict[IadlStrategy, List[float]] = {}
        for r in self.records: agg.setdefault(r.strategy, []).append(r.score)
        ranked = [(s, sum(v) / len(v)) for s, v in agg.items()]
        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked
    def any_success(self): return any(r.success for r in self.records)
    def len(self): return len(self.records)
    def is_empty(self): return not self.records


class StrategySelector:
    def __init__(self, history_weight=0.5, scorer_weight=0.5, repeat_penalty=0.1):
        self.history_weight = history_weight
        self.scorer_weight = scorer_weight
        self.repeat_penalty = repeat_penalty
    @classmethod
    def new(cls): return cls()
    @classmethod
    def with_weights(cls, h, s, r): return cls(h, s, r)
    def rank(self, features, history):
        scores = {s.strategy: s.utility() for s in StrategyScorer.score_all(features)}
        ranked = []
        for s in IadlStrategy.all():
            base = scores.get(s, 0.0) * self.scorer_weight
            hist = (history.average_score(s) or 0.0) * self.history_weight
            penalty = history.attempt_count(s) * self.repeat_penalty
            ranked.append((s, base + hist - penalty))
        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked
    def select(self, features, history): return self.rank(features, history)[0][0]
    def top_n(self, features, history, n): return [s for s, _ in self.rank(features, history)[:n]]


class AdaptiveSelector:
    def __init__(self, stagnation_threshold):
        self.stagnation_threshold = int(stagnation_threshold)
        self.current = None
        self.history = StrategyHistory()
        self.no_progress_count = 0
        self._selector = StrategySelector.new()
    @classmethod
    def new(cls, stagnation_threshold): return cls(stagnation_threshold)
    def pick(self, features):
        s = self._selector.select(features, self.history); self.current = s; return s
    def current_or_pick(self, features):
        if self.current is not None and not self.is_stagnated(): return self.current
        return self.pick(features)
    def report_iteration(self, strategy, score, success, iteration):
        self.history.push(StrategyRecord.new(strategy, score, success, iteration))
        if not success: self.no_progress_count += 1
        else: self.no_progress_count = 0
    def performance_summary(self): return dict(self.history.ranked_by_performance())
    def is_stagnated(self): return self.no_progress_count >= self.stagnation_threshold


# =============================================================================
# perturbation.rs
# =============================================================================

class PerturbationType:
    BIT_FLIP = "bit_flip"; BYTE_SWAP = "byte_swap"; INSERT = "insert"
    DELETE = "delete"; XOR_MASK = "xor_mask"
    def __init__(self, v): self.v = v
    def name(self): return self.v
    def is_reversible(self):
        return self.v in (self.BIT_FLIP, self.BYTE_SWAP, self.XOR_MASK)
    def aggressiveness(self):
        return {"bit_flip": 1, "byte_swap": 2, "insert": 3, "delete": 4, "xor_mask": 2}.get(self.v, 1)


class Perturbation:
    def __init__(self, kind):
        self.kind = kind; self.applications: List[Tuple[int, float]] = []
    @classmethod
    def new(cls, kind): return cls(kind)
    def record_application(self, iteration, effect):
        self.applications.append((int(iteration), float(effect)))


class PerturbationEffect:
    def __init__(self, delta_entropy, delta_size):
        self.delta_entropy = float(delta_entropy); self.delta_size = int(delta_size)
    def is_beneficial(self): return self.delta_entropy < 0.0


def apply_perturbation(data, perturbation):
    if not data: return b""
    arr = bytearray(data); k = perturbation.kind.v
    if k == PerturbationType.BIT_FLIP: arr[0] ^= 1
    elif k == PerturbationType.BYTE_SWAP and len(arr) >= 2: arr[0], arr[1] = arr[1], arr[0]
    elif k == PerturbationType.INSERT: arr.insert(0, 0)
    elif k == PerturbationType.DELETE and len(arr) > 1: del arr[0]
    elif k == PerturbationType.XOR_MASK:
        for i in range(len(arr)): arr[i] ^= 0xAA
    return bytes(arr)


def measure_effect(data, perturbation):
    after = apply_perturbation(data, perturbation)
    return PerturbationEffect(_entropy(after) - _entropy(data), len(after) - len(data))


def rank_perturbations(data, perturbations):
    ranked = [(i, -measure_effect(data, p).delta_entropy) for i, p in enumerate(perturbations)]
    ranked.sort(key=lambda x: x[1], reverse=True)
    return ranked


# =============================================================================
# obfuscation_classifier.rs
# =============================================================================

class Confidence:
    def __init__(self, v): self._v = max(0.0, min(1.0, float(v)))
    @classmethod
    def new(cls, v): return cls(v)
    def value(self): return self._v
    def is_high(self): return self._v >= 0.75
    def is_medium(self): return 0.4 <= self._v < 0.75
    def is_low(self): return self._v < 0.4


class ObfuscationTechnique:
    def __init__(self, v): self.v = v
    def __hash__(self): return hash(self.v)
    def __eq__(self, o): return isinstance(o, ObfuscationTechnique) and o.v == self.v


class DeobfPass:
    def __init__(self, v): self.v = v


class TechniqueResult:
    def __init__(self, technique, confidence, evidence_count):
        self.technique = technique; self.confidence = confidence
        self.evidence_count = int(evidence_count)
        self.evidence_addrs: List[int] = []; self.suggested_passes: List[DeobfPass] = []
    @classmethod
    def new(cls, technique, confidence, evidence_count):
        return cls(technique, confidence, evidence_count)
    def add_evidence(self, addr): self.evidence_addrs.append(int(addr))
    def suggest(self, pass_): self.suggested_passes.append(pass_)


class ClassificationResult:
    def __init__(self): self.techniques: List[TechniqueResult] = []
    @classmethod
    def new(cls): return cls()
    def add_technique(self, tr): self.techniques.append(tr)
    def high_confidence_techniques(self):
        return [t for t in self.techniques if t.confidence.is_high()]
    def has_technique(self, tech):
        return any(t.technique == tech for t in self.techniques)


class FunctionMetrics:
    def __init__(self, addr):
        self.addr = int(addr); self.cyclomatic = 0; self.size = 0; self.calls = 0
    @classmethod
    def new(cls, addr): return cls(addr)


class BinaryStats:
    def __init__(self, function_count, binary_size):
        self.function_count = int(function_count); self.binary_size = int(binary_size)
    @classmethod
    def new(cls, function_count, binary_size): return cls(function_count, binary_size)


class ClassifierConfig:
    def __init__(self, min_confidence=0.3): self.min_confidence = min_confidence


class ObfuscationClassifier:
    def __init__(self, config): self.config = config
    @classmethod
    def new(cls): return cls(ClassifierConfig())
    @classmethod
    def with_config(cls, config): return cls(config)
    def classify(self, functions, stats):
        r = ClassificationResult.new()
        if not functions: return r
        avg = sum(f.cyclomatic for f in functions) / len(functions)
        if avg > 20:
            r.add_technique(TechniqueResult.new(
                ObfuscationTechnique("cfl_flatten"), Confidence.new(0.8), int(avg)))
        return r


class ObfuscationReport:
    def __init__(self): self.summary = ""; self.result = None
    @classmethod
    def build(cls, result, functions, stats):
        r = cls(); r.result = result
        r.summary = f"funcs={len(functions)} size={stats.binary_size} techniques={len(result.techniques)}"
        return r
    def summary_text(self): return self.summary


# =============================================================================
# loop_orchestrator.rs
# =============================================================================

class DeobfIteration:
    def __init__(self, index, strategy, score_before, complexity_before):
        self.index = int(index); self.strategy = str(strategy)
        self.score_before = float(score_before); self.complexity_before = int(complexity_before)
        self.score_after = None; self.complexity_after = None
    @classmethod
    def new(cls, index, strategy, score_before, complexity_before):
        return cls(index, strategy, score_before, complexity_before)
    def complete(self, score_after, complexity_after):
        self.score_after = float(score_after); self.complexity_after = int(complexity_after)
    def delta(self):
        return 0.0 if self.score_after is None else self.score_after - self.score_before
    def complexity_reduction(self):
        return 0 if self.complexity_after is None else self.complexity_before - self.complexity_after


class IterationResult:
    BENEFICIAL = "beneficial"; NEUTRAL = "neutral"; REGRESSION = "regression"; STOP = "stop"
    def __init__(self, kind, delta_=0.0): self.kind = kind; self._delta = float(delta_)
    def is_beneficial(self): return self.kind == self.BENEFICIAL
    def should_stop(self): return self.kind == self.STOP
    def delta(self): return self._delta


class QualityDelta:
    def __init__(self, before_score, after_score, before_complexity, after_complexity, strategy):
        self.before_score = float(before_score); self.after_score = float(after_score)
        self.before_complexity = int(before_complexity); self.after_complexity = int(after_complexity)
        self.strategy = str(strategy)
    @classmethod
    def new(cls, *args): return cls(*args)
    def is_improvement(self): return self.after_score > self.before_score
    def is_no_change(self): return abs(self.after_score - self.before_score) < 1e-9


class StrategySwitchReason:
    STAGNATION = "stagnation"; BUDGET = "budget"; EXPLORATION = "exploration"; REGRESSION = "regression"
    def __init__(self, v): self.v = v
    def label(self): return self.v


class OrchestratorStats:
    def __init__(self):
        self.iterations = 0; self.improvements = 0; self.total_delta = 0.0
        self.elapsed_us = 0; self.strategies: Dict[str, int] = {}
    @classmethod
    def new(cls): return cls()
    def total_improvement(self): return self.total_delta
    def improvement_rate(self):
        return 0.0 if self.iterations == 0 else self.improvements / self.iterations
    def record(self, result, strategy, elapsed_us):
        self.iterations += 1; self.elapsed_us += int(elapsed_us)
        self.strategies[strategy] = self.strategies.get(strategy, 0) + 1
        if result.is_beneficial():
            self.improvements += 1; self.total_delta += result.delta()
    def summary(self):
        return f"iters={self.iterations} improv={self.improvements} delta={self.total_delta:.4f}"


class LoopReport:
    def __init__(self):
        self.iterations: List[DeobfIteration] = []
        self.deltas: List[QualityDelta] = []
    @classmethod
    def new(cls): return cls()
    def best_strategy(self):
        if not self.deltas: return None
        return max(self.deltas, key=lambda d: d.after_score - d.before_score).strategy
    def record_iteration(self, iter_):
        self.iterations.append(iter_)
        if iter_.score_after is not None:
            self.deltas.append(QualityDelta.new(
                iter_.score_before, iter_.score_after,
                iter_.complexity_before, iter_.complexity_after or 0, iter_.strategy))
    def top_improvements(self, n):
        return sorted(self.deltas, key=lambda d: d.after_score - d.before_score, reverse=True)[:n]


class DeobfProgressTracker:
    def __init__(self):
        self.scores: List[float] = []; self.complexities: List[int] = []
        self.strategies: List[str] = []
    @classmethod
    def new(cls): return cls()
    def record(self, score, complexity, strategy):
        self.scores.append(float(score)); self.complexities.append(int(complexity))
        self.strategies.append(str(strategy))
    def total_improvement(self):
        return 0.0 if len(self.scores) < 2 else self.scores[-1] - self.scores[0]
    def improving_fraction(self):
        if len(self.scores) < 2: return 0.0
        imp = sum(1 for i in range(1, len(self.scores)) if self.scores[i] > self.scores[i-1])
        return imp / (len(self.scores) - 1)
    def is_converged(self, epsilon):
        if len(self.scores) < 3: return False
        r = self.scores[-3:]; return (max(r) - min(r)) < epsilon
    def len(self): return len(self.scores)
    def is_empty(self): return not self.scores


class IterationHistory:
    def __init__(self):
        self.scores: List[float] = []; self.complexities: List[int] = []; self.limit = None
    @classmethod
    def new(cls): return cls()
    def with_limit(self, n): self.limit = int(n); return self
    def record(self, score, complexity):
        self.scores.append(float(score)); self.complexities.append(int(complexity))
        if self.limit is not None and len(self.scores) > self.limit:
            self.scores.pop(0); self.complexities.pop(0)
    def mean_score(self): return sum(self.scores) / len(self.scores) if self.scores else 0.0
    def max_score(self): return max(self.scores) if self.scores else 0.0
    def min_score(self): return min(self.scores) if self.scores else 0.0
    def is_monotone(self, n):
        if len(self.scores) < n: return False
        tail = self.scores[-n:]
        return all(tail[i] <= tail[i+1] for i in range(len(tail) - 1))
    def len(self): return len(self.scores)
    def is_empty(self): return not self.scores


class StrategyBudget:
    def __init__(self, name_, budget):
        self.name = str(name_); self.budget = int(budget); self.used = 0
    @classmethod
    def new(cls, name_, budget): return cls(name_, budget)
    def consume(self):
        if self.used >= self.budget: return False
        self.used += 1; return True
    def reset(self): self.used = 0
    def is_exhausted(self): return self.used >= self.budget


class IterationScheduler:
    def __init__(self): self.budgets: List[StrategyBudget] = []
    @classmethod
    def new(cls): return cls()
    def add(self, name_, budget): self.budgets.append(StrategyBudget.new(name_, budget))
    def next_available(self):
        for b in self.budgets:
            if b.consume(): return b.name
        return None
    def reset_all(self):
        for b in self.budgets: b.reset()
    def all_exhausted(self): return all(b.is_exhausted() for b in self.budgets)
    def total_budget(self): return sum(b.budget for b in self.budgets)


class Strategy:
    def name(self): raise NotImplementedError
    def apply(self, state): raise NotImplementedError


class LoopState:
    def __init__(self, score, complexity):
        self.score = float(score); self.complexity = int(complexity); self.meta: Dict[str, float] = {}
    @classmethod
    def new(cls, score, complexity): return cls(score, complexity)
    def set_meta(self, key, value): self.meta[str(key)] = float(value)
    def get_meta(self, key): return self.meta.get(key)


class FixedDeltaStrategy(Strategy):
    def __init__(self, name_, score_delta, complexity_delta):
        self._name = str(name_); self.score_delta = float(score_delta)
        self.complexity_delta = int(complexity_delta)
    @classmethod
    def new(cls, name_, score_delta, complexity_delta):
        return cls(name_, score_delta, complexity_delta)
    def name(self): return self._name
    def apply(self, state):
        ns = LoopState.new(state.score + self.score_delta,
                           max(0, state.complexity + self.complexity_delta))
        ns.meta = dict(state.meta); return ns


class _LoopOrchConvergence:
    def __init__(self):
        self.window = 5; self.epsilon = 1e-3; self.deltas: deque = deque(); self._converged = False
    @classmethod
    def new(cls): return cls()
    def with_window(self, n): self.window = int(n); return self
    def with_epsilon(self, e): self.epsilon = float(e); return self
    def update(self, delta_):
        self.deltas.append(float(delta_))
        if len(self.deltas) > self.window: self.deltas.popleft()
        if len(self.deltas) >= self.window and self.mean_delta() < self.epsilon:
            self._converged = True
        return self._converged
    def is_converged(self): return self._converged
    def mean_delta(self): return sum(self.deltas) / len(self.deltas) if self.deltas else 0.0
    def reset(self): self.deltas.clear(); self._converged = False


class LoopOrchestrator:
    def __init__(self): self.max_iterations = 32; self.stagnation_threshold = 5
    @classmethod
    def new(cls): return cls()
    def with_max_iterations(self, n): self.max_iterations = int(n); return self
    def with_stagnation_threshold(self, n): self.stagnation_threshold = int(n); return self
    def run(self, strategies, initial_state):
        rep = LoopReport.new(); cur = initial_state; no_progress = 0
        for i in range(self.max_iterations):
            if not strategies: break
            s = strategies[i % len(strategies)]
            it = DeobfIteration.new(i, s.name(), cur.score, cur.complexity)
            ns = s.apply(cur); it.complete(ns.score, ns.complexity)
            rep.record_iteration(it)
            if it.delta() <= 1e-9:
                no_progress += 1
                if no_progress >= self.stagnation_threshold: break
            else: no_progress = 0
            cur = ns
        return rep


# =============================================================================
# loop_analysis.rs
# =============================================================================

class StateSnapshot:
    def __init__(self, iteration):
        self.iteration = int(iteration); self.metrics: Dict[str, float] = {}; self.entropy = 0.0
    @classmethod
    def zeroed(cls, iteration): return cls(iteration)
    def is_low_entropy(self): return self.entropy < 3.0
    def set_metric(self, name, value): self.metrics[str(name)] = float(value)
    def get_metric(self, name): return self.metrics.get(name)


class ProgressDelta:
    def __init__(self, delta_metrics): self.delta_metrics = delta_metrics
    @classmethod
    def compute(cls, before, after):
        d = {}; keys = set(before.metrics) | set(after.metrics)
        for k in keys: d[k] = after.metrics.get(k, 0.0) - before.metrics.get(k, 0.0)
        return cls(d)
    def has_progress(self): return any(v > 0 for v in self.delta_metrics.values())
    def score(self): return sum(self.delta_metrics.values())
    def is_monotone(self):
        vs = list(self.delta_metrics.values())
        return all(v >= 0 for v in vs) or all(v <= 0 for v in vs)


class LoopIteration:
    def __init__(self, index, before, after, strategy):
        self.index = int(index); self.before = before; self.after = after
        self.strategy = str(strategy); self.duration_ms_v = None
    @classmethod
    def new(cls, index, before, after, strategy): return cls(index, before, after, strategy)
    def made_progress(self): return ProgressDelta.compute(self.before, self.after).has_progress()
    def progress_score(self): return ProgressDelta.compute(self.before, self.after).score()
    def duration_ms(self): return self.duration_ms_v


class StagnationDetector:
    def __init__(self, window, min_progress_score=1e-3):
        self.window = int(window); self.min_progress_score = float(min_progress_score)
        self.scores: deque = deque()
    @classmethod
    def new(cls, window): return cls(window)
    @classmethod
    def with_threshold(cls, window, min_progress_score): return cls(window, min_progress_score)
    def record(self, score):
        self.scores.append(float(score))
        if len(self.scores) > self.window: self.scores.popleft()
        return self.is_stagnated()
    def is_stagnated(self):
        if len(self.scores) < self.window: return False
        return all(s < self.min_progress_score for s in self.scores)
    def reset(self): self.scores.clear()
    def average_score(self): return sum(self.scores) / len(self.scores) if self.scores else 0.0
    def best_recent_score(self): return max(self.scores) if self.scores else 0.0


class LoopAnalysisError(Exception): pass


class LoopBudget:
    def __init__(self, max_iter=None, max_time_s=None, max_memory=None):
        self.max_iter = max_iter; self.max_time_s = max_time_s; self.max_memory = max_memory
    @classmethod
    def unlimited(cls): return cls()
    def check_iterations(self, current):
        if self.max_iter is not None and current >= self.max_iter:
            raise LoopAnalysisError("iter budget")
    def check_time(self, start):
        if self.max_time_s is not None and (time.time() - start) >= self.max_time_s:
            raise LoopAnalysisError("time budget")
    def check_memory(self, current_bytes):
        if self.max_memory is not None and current_bytes >= self.max_memory:
            raise LoopAnalysisError("mem budget")


class LoopProgressAnalyzer:
    def __init__(self): self.iterations: List[LoopIteration] = []
    @classmethod
    def new(cls): return cls()
    def record(self, iter_): self.iterations.append(iter_)
    def iteration_count(self): return len(self.iterations)
    def last_n_no_progress(self, n):
        if len(self.iterations) < n: return False
        return all(not it.made_progress() for it in self.iterations[-n:])
    def best_iteration(self):
        return max(self.iterations, key=lambda i: i.progress_score()) if self.iterations else None
    def average_score(self):
        if not self.iterations: return 0.0
        return sum(i.progress_score() for i in self.iterations) / len(self.iterations)
    def last_snapshot(self): return self.iterations[-1].after if self.iterations else None
    def trend(self, window):
        tail = self.iterations[-window:]
        if len(tail) < 2: return 0.0
        scores = [i.progress_score() for i in tail]
        return scores[-1] - scores[0]
    def progressing_iterations(self): return [i for i in self.iterations if i.made_progress()]
    def stagnant_iterations(self): return [i for i in self.iterations if not i.made_progress()]
    def progress_ratio(self):
        if not self.iterations: return 0.0
        return len(self.progressing_iterations()) / len(self.iterations)


class LoopController:
    def __init__(self, budget, stagnation_window):
        self.budget = budget; self.stagnation = StagnationDetector.new(stagnation_window)
        self.start = time.time(); self.iteration = 0
    @classmethod
    def new(cls, budget, stagnation_window): return cls(budget, stagnation_window)
    def begin_iteration(self):
        self.budget.check_iterations(self.iteration); self.budget.check_time(self.start)
        self.iteration += 1; return self.iteration
    def end_iteration(self, score): return self.stagnation.record(score)
    def elapsed(self): return time.time() - self.start
    def summary(self): return f"iter={self.iteration} elapsed={self.elapsed():.3f}s"


# =============================================================================
# iadl_orchestrator.rs
# =============================================================================

class PhaseId:
    SCAN = "scan"; UNPACK = "unpack"; DECRYPT = "decrypt"; DEVIRT = "devirt"; CLEANUP = "cleanup"
    _DEFAULTS = {SCAN: 1, UNPACK: 4, DECRYPT: 8, DEVIRT: 16, CLEANUP: 4}
    def __init__(self, v): self.v = v
    def name(self): return self.v
    def default_max_iter(self): return self._DEFAULTS.get(self.v, 4)
    def __hash__(self): return hash(self.v)
    def __eq__(self, o): return isinstance(o, PhaseId) and o.v == self.v


class DeobfIterationOrch:
    def __init__(self, phase):
        self.phase = phase; self.score_before = 0.0; self.score_after = 0.0
    @classmethod
    def initial(cls, phase): return cls(phase)


class IterationResultOrch:
    def __init__(self):
        self.iterations: List[DeobfIterationOrch] = []; self.final_score = 0.0
    def is_good(self, threshold): return self.final_score >= threshold
    def phase_history(self, phase): return [i for i in self.iterations if i.phase == phase]
    def avg_improvement(self):
        ds = [i.score_after - i.score_before for i in self.iterations]
        return sum(ds) / len(ds) if ds else 0.0


class OrchConfig:
    def __init__(self): self.overrides: Dict[PhaseId, int] = {}
    def max_iter_for(self, phase):
        return self.overrides.get(phase, phase.default_max_iter())


class PhaseHandler:
    def run(self, score, complexity): raise NotImplementedError


def convergence_check(previous, current, threshold):
    return abs(current - previous) < threshold


def stall_check(history, stall_limit, threshold):
    if len(history) < stall_limit: return False
    tail = history[-stall_limit:]
    return (max(tail) - min(tail)) < threshold


class DeobfOrchestrator:
    def __init__(self, config):
        self._config = config
        self.phases: "OrderedDict[PhaseId, PhaseHandler]" = OrderedDict()
    @classmethod
    def new(cls, config): return cls(config)
    def register_phase(self, phase, handler): self.phases[phase] = handler
    def remove_phase(self, phase): return self.phases.pop(phase, None)
    def run(self, initial_score, initial_complexity):
        r = IterationResultOrch(); score = initial_score; complexity = initial_complexity
        for phase, handler in self.phases.items():
            for _ in range(self._config.max_iter_for(phase)):
                it = DeobfIterationOrch.initial(phase); it.score_before = score
                score, complexity = handler.run(score, complexity)
                it.score_after = score; r.iterations.append(it)
        r.final_score = score; return r
    def config(self): return self._config
    def config_mut(self): return self._config


# =============================================================================
# ir_transform.rs
# =============================================================================

class IrFunction:
    def __init__(self): self.instructions: List[str] = []


class TransformPass:
    def name(self): raise NotImplementedError
    def run(self, func): raise NotImplementedError


def _mkpass(nm):
    class P(TransformPass):
        def name(self): return nm
        def run(self, func): return 0
    P.__name__ = nm; return P


ConstantFoldingPass = _mkpass("ConstantFoldingPass")
DeadCodeElimination = _mkpass("DeadCodeElimination")
CopyPropagation = _mkpass("CopyPropagation")
CommonSubexpressionElim = _mkpass("CommonSubexpressionElim")
BooleanSimplification = _mkpass("BooleanSimplification")
XorChainSimplifier = _mkpass("XorChainSimplifier")
MbaSimplifier = _mkpass("MbaSimplifier")
OpaquePredicateElim = _mkpass("OpaquePredicateElim")
BlockMerging = _mkpass("BlockMerging")
PhiElimination = _mkpass("PhiElimination")


class PipelineStats:
    def __init__(self):
        self.changes_per_pass: Dict[str, int] = {}; self.total_changes = 0


class DeobfuscationPipeline:
    def __init__(self): self.passes: List[TransformPass] = []
    @classmethod
    def new(cls): return cls()
    def add_pass(self, p): self.passes.append(p); return self
    @classmethod
    def standard(cls):
        p = cls()
        for K in (ConstantFoldingPass, DeadCodeElimination, CopyPropagation,
                  CommonSubexpressionElim, BooleanSimplification, XorChainSimplifier,
                  MbaSimplifier, OpaquePredicateElim, BlockMerging, PhiElimination):
            p.add_pass(K())
        return p
    def run_all(self, func):
        st = PipelineStats()
        for p in self.passes:
            c = p.run(func)
            st.changes_per_pass[p.name()] = c
            st.total_changes += c
        return st


# =============================================================================
# adversarial_loop.rs
# =============================================================================

class ProgressMetric:
    def __init__(self, byte_diff=0, size_diff=0, patches=0):
        self.byte_diff = int(byte_diff); self.size_diff = int(size_diff); self.patches = int(patches)
    @classmethod
    def zero(cls): return cls()
    @classmethod
    def compute(cls, before, after, patches):
        bd = sum(1 for a, b in zip(before, after) if a != b)
        return cls(bd, len(after) - len(before), patches)
    def has_progress(self, threshold): return self.byte_diff > threshold or self.patches > 0


class IadlPass:
    def name(self): raise NotImplementedError
    def run(self, binary): raise NotImplementedError


class IadlLoopReport:
    def __init__(self): self.patches = 0; self.progressive = 0; self.iterations = 0
    def total_patches(self): return self.patches
    def progressive_iterations(self): return self.progressive
    def summary(self):
        return f"iter={self.iterations} patches={self.patches} progressive={self.progressive}"


class IadlLoopConfig:
    def __init__(self, max_iter=16, threshold=1.0):
        self.max_iter = max_iter; self.threshold = threshold


class IadlLoopError(Exception): pass


class IadlLoop:
    def __init__(self, config, passes):
        self.config = config; self.passes = passes; self.perturbations: List[Perturbation] = []
    @classmethod
    def new(cls, config, passes): return cls(config, passes)
    def add_perturbation(self, p): self.perturbations.append(p)
    def run(self, initial_binary):
        rep = IadlLoopReport(); cur = bytes(initial_binary)
        for _ in range(self.config.max_iter):
            rep.iterations += 1; before = cur
            for p in self.passes:
                cur = p.run(cur); rep.patches += 1
            m = ProgressMetric.compute(before, cur, rep.patches)
            if m.has_progress(self.config.threshold): rep.progressive += 1
            else: break
        return rep


# =============================================================================
# deobf_strategy_selector.rs
# =============================================================================

class StrategyFeature:
    def __init__(self, name_, value): self._name = str(name_); self.value = float(value)
    def name(self): return self._name
    def as_f64(self): return self.value


class FeatureVector:
    def __init__(self): self.features: List[StrategyFeature] = []
    @classmethod
    def new(cls): return cls()
    def push(self, feature): self.features.append(feature)
    def get_f64(self, name):
        for f in self.features:
            if f.name() == name: return f.as_f64()
        return None
    def iter(self): return iter(self.features)
    def len(self): return len(self.features)
    def is_empty(self): return not self.features
    def as_map(self): return {f.name(): f.as_f64() for f in self.features}


class DeobfStrategy:
    _ALL = ["fold", "dce", "copy_prop", "cse", "bool_simp", "mba", "opaque", "string"]
    def __init__(self, v): self.v = v
    def name(self): return self.v
    @classmethod
    def all(cls): return [cls(v) for v in cls._ALL]
    def __hash__(self): return hash(self.v)
    def __eq__(self, o): return isinstance(o, DeobfStrategy) and o.v == self.v


class DeobfStrategySelector:
    def __init__(self):
        self.rule_weight = 1.0; self.history: Dict[DeobfStrategy, List[float]] = {}
    @classmethod
    def new(cls): return cls()
    def set_rule_weight(self, w): self.rule_weight = float(w)
    def score_all(self, features):
        base = features.as_map().get("complexity", 0.5)
        return [StrategyScore(IadlStrategy(IadlStrategy.HEURISTIC),
                              self.rule_weight * base, 0.1) for _ in DeobfStrategy.all()]
    def select_best(self, features):
        scores = [(s, self.avg_outcome(s)) for s in DeobfStrategy.all()]
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[0][0]
    def select_top_n(self, features, n):
        scores = [(s, self.avg_outcome(s)) for s in DeobfStrategy.all()]
        scores.sort(key=lambda x: x[1], reverse=True)
        return [s for s, _ in scores[:n]]
    def record_outcome(self, strategy, outcome):
        self.history.setdefault(strategy, []).append(float(outcome))
    def avg_outcome(self, strategy):
        xs = self.history.get(strategy, [])
        return sum(xs) / len(xs) if xs else 0.0
    def reset_history(self): self.history.clear()


# =============================================================================
# adversarial_tester.rs
# =============================================================================

class MutationOp:
    BIT_FLIP = "bit_flip"; INSERT_BYTE = "insert_byte"
    REMOVE_BYTE = "remove_byte"; XOR = "xor"
    def __init__(self, v): self.v = v
    def apply(self, input_):
        arr = bytearray(input_)
        if not arr: return b""
        if self.v == self.BIT_FLIP: arr[0] ^= 0x80
        elif self.v == self.INSERT_BYTE: arr.append(0)
        elif self.v == self.REMOVE_BYTE and len(arr) > 1: arr.pop()
        elif self.v == self.XOR:
            for i in range(len(arr)): arr[i] ^= 0x5A
        return bytes(arr)


class TestCase:
    def __init__(self, id_, input_, expected_output, parent_id=None, mutation=None):
        self.id = int(id_); self.input = bytes(input_)
        self.expected_output = bytes(expected_output)
        self.parent_id = parent_id; self.mutation = mutation
    @classmethod
    def seed(cls, id_, input_, expected_output): return cls(id_, input_, expected_output)
    @classmethod
    def derived(cls, parent_id, id_, input_, expected_output, mutation):
        return cls(id_, input_, expected_output, parent_id, mutation)
    def input_len(self): return len(self.input)


class Equivalence:
    def __init__(self, test_case_id, passed, expected, actual):
        self.test_case_id = int(test_case_id); self.passed = bool(passed)
        self.expected = bytes(expected); self.actual = bytes(actual)
    @classmethod
    def pass_(cls, test_case_id, output): return cls(test_case_id, True, output, output)
    @classmethod
    def fail(cls, test_case_id, expected, actual):
        return cls(test_case_id, False, expected, actual)


def adversarial_score(verdicts):
    if not verdicts: return 0.0
    return sum(1 for v in verdicts if v.passed) / len(verdicts)


class AdversarialScore:
    def __init__(self, passed, failed): self.passed = passed; self.failed = failed
    @classmethod
    def from_verdicts(cls, verdicts):
        p = sum(1 for v in verdicts if v.passed)
        return cls(p, len(verdicts) - p)
    def summary(self):
        total = self.passed + self.failed
        rate = self.passed / total if total else 0.0
        return f"{self.passed}/{total} pass ({rate:.2%})"


class DeobfOracle:
    def evaluate(self, input_): raise NotImplementedError


class TesterConfig:
    def __init__(self, max_rounds=16, mutations_per_round=4):
        self.max_rounds = max_rounds; self.mutations_per_round = mutations_per_round


class AdversarialTester:
    def __init__(self, config):
        self.config = config; self.corpus: List[TestCase] = []
        self._history: List[AdversarialScore] = []; self._next_id = 0
    @classmethod
    def new(cls, config): return cls(config)
    def add_seed(self, input_, expected_output):
        self._next_id += 1
        self.corpus.append(TestCase.seed(self._next_id, input_, expected_output))
        return self._next_id
    def run_round(self, oracle):
        verdicts = []
        for tc in self.corpus:
            out = oracle.evaluate(tc.input)
            if out == tc.expected_output: verdicts.append(Equivalence.pass_(tc.id, out))
            else: verdicts.append(Equivalence.fail(tc.id, tc.expected_output, out))
        score = AdversarialScore.from_verdicts(verdicts)
        self._history.append(score)
        return score
    def run_until_pass(self, oracle):
        out = []
        for _ in range(self.config.max_rounds):
            s = self.run_round(oracle); out.append(s)
            if s.failed == 0: break
        return out
    def corpus_size(self): return len(self.corpus)
    def history(self): return self._history
    def reset(self): self.corpus.clear(); self._history.clear(); self._next_id = 0


# =============================================================================
# convergence_detector.rs
# =============================================================================

class ConvergenceState:
    CONTINUE = "continue"; CONVERGED = "converged"; MAX_ITER = "max_iter"; DIVERGED = "diverged"
    def __init__(self, v): self.v = v
    def should_continue(self): return self.v == self.CONTINUE
    def is_terminal(self): return self.v != self.CONTINUE


class ConvergenceConfig:
    def __init__(self, max_iterations=100, window=5, epsilon=1e-3):
        self.max_iterations = max_iterations; self.window = window; self.epsilon = epsilon


class ConvergenceDetector:
    def __init__(self, config): self._config = config; self.checks = 0
    @classmethod
    def new(cls, max_iterations):
        return cls(ConvergenceConfig(max_iterations=max_iterations))
    @classmethod
    def with_config(cls, config): return cls(config)
    def config(self): return self._config
    def reset(self): self.checks = 0
    def check_pure(self, history):
        h = list(history)
        if len(h) >= self._config.max_iterations:
            return ConvergenceState(ConvergenceState.MAX_ITER)
        if len(h) >= self._config.window:
            tail = h[-self._config.window:]
            if (max(tail) - min(tail)) < self._config.epsilon:
                return ConvergenceState(ConvergenceState.CONVERGED)
        return ConvergenceState(ConvergenceState.CONTINUE)
    def check(self, history):
        self.checks += 1
        return self.check_pure(history)


def find_plateau_start(history, window, threshold):
    for i in range(len(history) - window + 1):
        win = history[i:i + window]
        if (max(win) - min(win)) < threshold: return i
    return None


def moving_average(history, window):
    out = []
    for i in range(len(history)):
        lo = max(0, i - window + 1)
        chunk = history[lo:i + 1]
        out.append(sum(chunk) / len(chunk))
    return out


def exponential_moving_average(history, alpha):
    out = []; ema = 0.0
    for i, v in enumerate(history):
        ema = v if i == 0 else alpha * v + (1 - alpha) * ema
        out.append(ema)
    return out


def trend_slope(history):
    n = len(history)
    if n < 2: return 0.0
    xm = (n - 1) / 2; ym = sum(history) / n
    num = sum((i - xm) * (history[i] - ym) for i in range(n))
    den = sum((i - xm) ** 2 for i in range(n))
    return num / den if den else 0.0


# =============================================================================
# indirect_target_resolver.rs
# =============================================================================

class ValueSet:
    def __init__(self, kind, values=None, lower=0, upper=0, stride=1):
        self.kind = kind; self.values = values or set()
        self.lower = lower; self.upper = upper; self.stride = stride
    @classmethod
    def bottom(cls): return cls("bottom")
    @classmethod
    def top(cls): return cls("top")
    @classmethod
    def singleton(cls, v): return cls("set", values={int(v)})
    @classmethod
    def from_values(cls, vals): return cls("set", values={int(v) for v in vals})
    @classmethod
    def strided_interval(cls, lower, upper, stride):
        return cls("strided", lower=lower, upper=upper, stride=max(1, stride))
    def join(self, other):
        if self.kind == "bottom": return other
        if other.kind == "bottom": return self
        if self.kind == "top" or other.kind == "top": return ValueSet.top()
        return ValueSet.from_values(self.concrete_values() + other.concrete_values())
    def contains(self, v):
        if self.kind == "top": return True
        if self.kind == "bottom": return False
        if self.kind == "set": return int(v) in self.values
        if self.kind == "strided":
            return self.lower <= v <= self.upper and ((v - self.lower) % self.stride) == 0
        return False
    def concrete_values(self):
        if self.kind == "set": return sorted(self.values)
        if self.kind == "strided":
            return list(range(self.lower, self.upper + 1, self.stride))
        return []
    def is_empty(self):
        return self.kind == "bottom" or (self.kind == "set" and not self.values)
    def size(self):
        if self.kind == "top": return -1
        return len(self.concrete_values())


class TaintLabel:
    def __init__(self, v="user"): self.v = v


class TaintState:
    def __init__(self):
        self.regs: Dict[str, TaintLabel] = {}; self.mem: Dict[int, TaintLabel] = {}
    @classmethod
    def new(cls): return cls()
    def taint_register(self, reg, label): self.regs[str(reg)] = label
    def taint_memory(self, addr, label): self.mem[int(addr)] = label
    def is_register_tainted(self, reg): return reg in self.regs
    def is_memory_tainted(self, addr): return int(addr) in self.mem
    def propagate_reg_to_reg(self, src, dst):
        if src in self.regs: self.regs[str(dst)] = self.regs[src]
    def clear_register(self, reg): self.regs.pop(reg, None)
    def merge(self, other):
        self.regs.update(other.regs); self.mem.update(other.mem)


class VtableCandidate:
    def __init__(self, vtable_addr, slot_index, target_addr):
        self.vtable_addr = int(vtable_addr); self.slot_index = int(slot_index)
        self.target_addr = int(target_addr); self.symbol = None
        self.class_ = None; self.confidence = 0.5
    @classmethod
    def new(cls, vtable_addr, slot_index, target_addr):
        return cls(vtable_addr, slot_index, target_addr)
    def with_symbol(self, name): self.symbol = str(name); return self
    def with_class(self, c): self.class_ = str(c); return self
    def with_confidence(self, c): self.confidence = float(c); return self


class ResolutionMethod:
    DIRECT = "direct"; VTABLE = "vtable"; IAT = "iat"; HINT = "hint"; VSA = "vsa"
    def __init__(self, v): self.v = v


class IndirectTarget:
    def __init__(self, site_addr, is_call):
        self.site_addr = int(site_addr); self.is_call = bool(is_call)
        self.targets: List[Tuple[int, ResolutionMethod, float]] = []
    @classmethod
    def new(cls, site_addr, is_call): return cls(site_addr, is_call)
    def site_address(self): return self.site_addr
    def target_addresses(self): return [t[0] for t in self.targets]
    def add_target(self, addr, method, confidence):
        self.targets.append((int(addr), method, float(confidence)))
    def is_monomorphic(self): return len({t[0] for t in self.targets}) == 1
    def is_polymorphic(self): return len({t[0] for t in self.targets}) > 1


class RopChainAnalysis:
    def __init__(self, chain_start):
        self.chain_start = int(chain_start); self.gadgets: List[int] = []
    @classmethod
    def new(cls, chain_start): return cls(chain_start)
    def has_gadgets(self): return bool(self.gadgets)


class AbstractInstr:
    def __init__(self, addr, mnemonic):
        self.addr = int(addr); self.mnemonic = str(mnemonic).lower()
    @classmethod
    def new(cls, addr, mnemonic): return cls(addr, mnemonic)
    def is_indirect_transfer(self):
        m = self.mnemonic
        return m in ("call_indirect", "jmp_indirect") or \
               (m.startswith("call") and "[" in m) or \
               (m.startswith("jmp") and "[" in m)
    def is_const_move(self):
        return self.mnemonic.startswith("mov") or self.mnemonic == "li"


class ResolverConfig:
    def __init__(self, min_confidence=0.5): self.min_confidence = min_confidence


class IndirectTargetResolver:
    def __init__(self, config):
        self.config = config; self.instrs: List[AbstractInstr] = []
        self.vtables: Dict[int, List[Tuple[int, int]]] = {}
        self.iat: Dict[int, str] = {}; self.hints: Dict[int, List[int]] = {}
        self._results: Dict[int, IndirectTarget] = {}
    @classmethod
    def new(cls): return cls(ResolverConfig())
    @classmethod
    def with_config(cls, config): return cls(config)
    def load_instructions(self, instrs): self.instrs = list(instrs)
    def register_vtable(self, vtable_addr, slots):
        self.vtables[int(vtable_addr)] = list(slots)
    def register_iat_entry(self, iat_addr, symbol):
        self.iat[int(iat_addr)] = str(symbol)
    def add_external_hint(self, site, target):
        self.hints.setdefault(int(site), []).append(int(target))
    def resolve_site(self, site_addr, is_call):
        t = IndirectTarget.new(site_addr, is_call)
        for tgt in self.hints.get(int(site_addr), []):
            t.add_target(tgt, ResolutionMethod(ResolutionMethod.HINT), 0.6)
        return t
    def resolve_all(self):
        out = []
        for ins in self.instrs:
            if ins.is_indirect_transfer():
                t = self.resolve_site(ins.addr, True)
                self._results[ins.addr] = t; out.append(t)
        return out
    def results(self): return self._results
    def high_confidence_results(self):
        return [t for t in self._results.values()
                if any(c >= self.config.min_confidence for _, _, c in t.targets)]
    def statistics(self):
        total = len(self._results)
        resolved = sum(1 for t in self._results.values() if t.targets)
        hc = len(self.high_confidence_results())
        return ResolutionStats(total, resolved, hc)


# =============================================================================
# call_graph_builder.rs
# =============================================================================

class EdgeKind:
    DIRECT = "direct"; INDIRECT = "indirect"; TAIL = "tail"
    DYNAMIC = "dynamic"; STUB = "stub"
    def __init__(self, v): self.v = v


class CallEdge:
    def __init__(self, caller, callee, call_site, kind):
        self.caller = int(caller); self.callee = int(callee)
        self.call_site = int(call_site); self.kind = kind; self.confidence = 1.0
    @classmethod
    def new(cls, caller, callee, call_site, kind):
        return cls(caller, callee, call_site, kind)
    def with_confidence(self, c): self.confidence = float(c); return self
    def as_dynamic(self): self.kind = EdgeKind(EdgeKind.DYNAMIC); return self


class CallSite:
    def __init__(self, addr, function, kind):
        self.addr = int(addr); self.function = int(function); self.kind = kind
        self.targets: List[int] = []
    @classmethod
    def new(cls, addr, function, kind): return cls(addr, function, kind)
    def add_target(self, target): self.targets.append(int(target))
    def is_monomorphic(self): return len(set(self.targets)) == 1


class CallGraphMetrics:
    def __init__(self, nodes=0, edges=0): self.nodes = nodes; self.edges = edges


class CallGraph:
    def __init__(self):
        self.nodes: set = set(); self.edges: List[CallEdge] = []
        self.sites: List[CallSite] = []; self.symbols: Dict[int, str] = {}
        self.library_stubs: set = set(); self.unresolvable: set = set()
    @classmethod
    def new(cls): return cls()
    def add_node(self, addr): self.nodes.add(int(addr))
    def add_edge(self, edge):
        self.edges.append(edge); self.nodes.add(edge.caller); self.nodes.add(edge.callee)
    def add_call_site(self, site): self.sites.append(site)
    def set_symbol(self, addr, name): self.symbols[int(addr)] = str(name)
    def mark_library_stub(self, addr): self.library_stubs.add(int(addr))
    def mark_unresolvable(self, addr): self.unresolvable.add(int(addr))
    def callees_of(self, func): return [e for e in self.edges if e.caller == func]
    def callers_of(self, func): return [e for e in self.edges if e.callee == func]
    def fan_out(self, func): return len({e.callee for e in self.edges if e.caller == func})
    def fan_in(self, func): return len({e.caller for e in self.edges if e.callee == func})
    def node_count(self): return len(self.nodes)
    def edge_count(self): return len(self.edges)
    def name_of(self, addr): return self.symbols.get(int(addr), f"sub_{addr:x}")
    def metrics(self): return CallGraphMetrics(self.node_count(), self.edge_count())

    def compute_sccs(self):
        index_of: Dict[int, int] = {}; lowlink: Dict[int, int] = {}
        on_stack: set = set(); stack: List[int] = []; sccs: List[List[int]] = []
        idx = [0]; adj: Dict[int, List[int]] = {n: [] for n in self.nodes}
        for e in self.edges: adj.setdefault(e.caller, []).append(e.callee)

        def sc(v):
            index_of[v] = idx[0]; lowlink[v] = idx[0]; idx[0] += 1
            stack.append(v); on_stack.add(v)
            for w in adj.get(v, []):
                if w not in index_of:
                    sc(w); lowlink[v] = min(lowlink[v], lowlink[w])
                elif w in on_stack:
                    lowlink[v] = min(lowlink[v], index_of[w])
            if lowlink[v] == index_of[v]:
                comp = []
                while True:
                    w = stack.pop(); on_stack.discard(w); comp.append(w)
                    if w == v: break
                sccs.append(comp)

        for n in list(self.nodes):
            if n not in index_of: sc(n)
        return sccs

    def topological_order(self):
        in_deg: Dict[int, int] = {n: 0 for n in self.nodes}
        adj: Dict[int, List[int]] = {n: [] for n in self.nodes}
        for e in self.edges:
            adj.setdefault(e.caller, []).append(e.callee)
            in_deg[e.callee] = in_deg.get(e.callee, 0) + 1
        q = deque([n for n, d in in_deg.items() if d == 0]); out = []
        while q:
            n = q.popleft(); out.append(n)
            for m in adj.get(n, []):
                in_deg[m] -= 1
                if in_deg[m] == 0: q.append(m)
        return out

    def reachable_from(self, start):
        seen = set(); stack = [int(start)]
        adj: Dict[int, List[int]] = {}
        for e in self.edges: adj.setdefault(e.caller, []).append(e.callee)
        while stack:
            n = stack.pop()
            if n in seen: continue
            seen.add(n)
            for m in adj.get(n, []): stack.append(m)
        return seen

    def entry_points(self):
        callees = {e.callee for e in self.edges}
        return [n for n in self.nodes if n not in callees]

    def leaf_functions(self):
        callers = {e.caller for e in self.edges}
        return [n for n in self.nodes if n not in callers]

    def to_dot(self):
        lines = ["digraph cg {"]
        for n in self.nodes: lines.append(f'  "{self.name_of(n)}";')
        for e in self.edges:
            lines.append(f'  "{self.name_of(e.caller)}" -> "{self.name_of(e.callee)}";')
        lines.append("}")
        return "\n".join(lines)


class FunctionInfo:
    def __init__(self, start, size):
        self.start = int(start); self.size = int(size); self.name = None
    @classmethod
    def new(cls, start, size): return cls(start, size)
    def with_name(self, name): self.name = str(name); return self


class CallInstruction:
    def __init__(self, addr, targets, is_tail=False, is_indirect=False):
        self.addr = int(addr); self.targets = [int(t) for t in targets]
        self.is_tail = is_tail; self.is_indirect = is_indirect
    @classmethod
    def direct(cls, addr, target): return cls(addr, [target], False, False)
    @classmethod
    def indirect(cls, addr, targets): return cls(addr, targets, False, True)
    def tail(self): self.is_tail = True; return self


class DynamicHint:
    def __init__(self, site, target):
        self.site = int(site); self.target = int(target)


class CgBuilderConfig:
    def __init__(self, include_indirect=True): self.include_indirect = include_indirect


class CallGraphBuilder:
    def __init__(self, config):
        self.config = config; self.functions: List[FunctionInfo] = []
        self.iat_stubs: Dict[int, str] = {}; self.hints: List[DynamicHint] = []
        self.stub_ranges: List[Tuple[int, int]] = []
    @classmethod
    def new(cls): return cls(CgBuilderConfig())
    @classmethod
    def with_config(cls, config): return cls(config)
    def add_function(self, func): self.functions.append(func)
    def add_iat_stub(self, stub_addr, symbol): self.iat_stubs[int(stub_addr)] = str(symbol)
    def add_dynamic_hint(self, hint): self.hints.append(hint)
    def add_stub_range(self, start, end): self.stub_ranges.append((int(start), int(end)))
    def build(self):
        g = CallGraph.new()
        for f in self.functions:
            g.add_node(f.start)
            if f.name: g.set_symbol(f.start, f.name)
        for stub, sym in self.iat_stubs.items():
            g.add_node(stub); g.set_symbol(stub, sym); g.mark_library_stub(stub)
        for h in self.hints:
            g.add_edge(CallEdge.new(h.site, h.target, h.site, EdgeKind(EdgeKind.DYNAMIC)))
        return g


# =============================================================================
# constraint_propagation.rs
# =============================================================================

class ValueRange:
    def __init__(self, kind, lo=0, hi=0):
        self.kind = kind; self.lo = lo; self.hi = hi
    @classmethod
    def top(cls): return cls("top")
    @classmethod
    def bottom(cls): return cls("bottom")
    @classmethod
    def constant(cls, v): return cls("range", int(v), int(v))
    @classmethod
    def bounded(cls, lo, hi): return cls("range", int(lo), int(hi))
    def join(self, other):
        if self.kind == "bottom": return other
        if other.kind == "bottom": return self
        if self.kind == "top" or other.kind == "top": return ValueRange.top()
        return ValueRange.bounded(min(self.lo, other.lo), max(self.hi, other.hi))
    def meet(self, other):
        if self.kind == "top": return other
        if other.kind == "top": return self
        if self.kind == "bottom" or other.kind == "bottom": return ValueRange.bottom()
        lo = max(self.lo, other.lo); hi = min(self.hi, other.hi)
        if lo > hi: return ValueRange.bottom()
        return ValueRange.bounded(lo, hi)
    def is_constant(self): return self.kind == "range" and self.lo == self.hi
    def constant_value(self): return self.lo if self.is_constant() else None
    def contains(self, v):
        if self.kind == "top": return True
        if self.kind == "bottom": return False
        return self.lo <= v <= self.hi
    def width(self): return self.hi - self.lo if self.kind == "range" else None
    def add(self, rhs):
        if self.kind != "range" or rhs.kind != "range": return ValueRange.top()
        return ValueRange.bounded(self.lo + rhs.lo, self.hi + rhs.hi)


class DeobfConstraint:
    def __init__(self, var, expr): self.var = str(var); self.expr = expr
    def primary_var(self): return self.var
    def derive_range(self, env):
        if isinstance(self.expr, ValueRange): return self.expr
        if isinstance(self.expr, str): return env.get(self.expr)
        if isinstance(self.expr, int): return ValueRange.constant(self.expr)
        return None


class ConstraintGraph:
    def __init__(self): self.constraints: List[DeobfConstraint] = []
    def add(self, c): self.constraints.append(c); return len(self.constraints) - 1
    def constraints_for(self, var):
        return (i for i, c in enumerate(self.constraints) if c.primary_var() == var)
    def len(self): return len(self.constraints)
    def is_empty(self): return not self.constraints


class PropagationResult:
    def __init__(self, env, consistent):
        self.env = env; self.consistent = consistent
    def is_consistent(self): return self.consistent
    def range_of(self, var): return self.env.get(var, ValueRange.top())


class ConstraintSolver:
    def __init__(self, max_iterations=64): self.max_iterations = max_iterations
    @classmethod
    def new(cls): return cls()
    @classmethod
    def with_max_iterations(cls, n): return cls(int(n))
    def solve(self, graph, initial):
        env = dict(initial)
        for _ in range(self.max_iterations):
            changed = False
            for c in graph.constraints:
                d = c.derive_range(env)
                if d is None: continue
                cur = env.get(c.primary_var(), ValueRange.top())
                new_r = cur.meet(d)
                if new_r.kind == "bottom":
                    return PropagationResult(env, False)
                if (new_r.kind, new_r.lo, new_r.hi) != (cur.kind, cur.lo, cur.hi):
                    env[c.primary_var()] = new_r; changed = True
            if not changed: break
        return PropagationResult(env, True)


class ConstraintPropagation:
    def __init__(self): self._solver = ConstraintSolver.new()
    @classmethod
    def new(cls): return cls()
    def propagate(self, graph, initial): return self._solver.solve(graph, initial)
    def propagate_equality(self, var, value):
        return PropagationResult({var: ValueRange.constant(value)}, True)


if __name__ == "__main__":
    s = IadlState.new(0.5, 100)
    h = ConstantHypothesis.new("h1", 0.6, 90, "test")
    sc = ImprovementScorer.new(1.0)
    r = IadlOrchestrator.default_config().run(s, [h], [sc])
    print("iterations:", len(r.iterations), "converged:", r.converged)
    print("djb2 foo:", compute_hash(b"foo", HashAlgorithm(HashAlgorithm.DJB2)))
    print("trend:", trend_slope([1.0, 2.0, 3.0, 4.0]))
