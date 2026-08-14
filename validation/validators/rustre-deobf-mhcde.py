"""Python reproduction of rustre-deobf-mhcde public API.

Stdlib-only (struct, hashlib, json, re, math, collections). Each Rust function
in the report has an equivalent Python function with matching input/return
shape semantics.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import struct
from collections import Counter, defaultdict, deque


def _mk(**kw):
    return dict(kw)


# =============================================================================
# src/lib.rs
# =============================================================================

class OpaquePredicateDetector:
    @staticmethod
    def new():
        return OpaquePredicateDetector()

    def detect(self, data: bytes):
        out = []
        n = len(data)
        i = 0
        while i < n - 2:
            b = data[i]
            if b == 0x31 and i + 3 < n and data[i + 2] in (0x74, 0x0F):
                out.append(_mk(offset=i, length=4, kind="XorSelfJz"))
                i += 4
                continue
            if b == 0xB0 and i + 4 < n and data[i + 2] == 0x84:
                out.append(_mk(offset=i, length=5, kind="MovTestJz"))
                i += 5
                continue
            if b == 0xF9 and i + 1 < n and data[i + 1] == 0x72:
                out.append(_mk(offset=i, length=3, kind="StcJc"))
                i += 3
                continue
            i += 1
        return out

    def count_by_type(self, data: bytes):
        c = Counter()
        for p in self.detect(data):
            c[p["kind"]] += 1
        return dict(c)

    def total_patch_bytes(self, data: bytes) -> int:
        return sum(p["length"] for p in self.detect(data))


class JunkCodeDetector:
    @staticmethod
    def new():
        return JunkCodeDetector()

    def detect(self, data: bytes):
        out = []
        n = len(data)
        i = 0
        while i < n:
            b = data[i]
            if b == 0x90:
                j = i
                while j < n and data[j] == 0x90:
                    j += 1
                out.append(_mk(offset=i, length=j - i, kind="NopSled"))
                i = j
                continue
            if i + 1 < n and 0x50 <= b <= 0x57 and data[i + 1] == 0x58 + (b - 0x50):
                out.append(_mk(offset=i, length=2, kind="PushPop"))
                i += 2
                continue
            if b == 0x83 and i + 2 < n and data[i + 2] == 0x00:
                out.append(_mk(offset=i, length=3, kind="ArithZero"))
                i += 3
                continue
            if b == 0x66 and i + 1 < n and data[i + 1] == 0x90:
                out.append(_mk(offset=i, length=2, kind="MultiByteNop"))
                i += 2
                continue
            i += 1
        return out

    def total_junk_bytes(self, data: bytes) -> int:
        return sum(r["length"] for r in self.detect(data))

    def junk_density(self, data: bytes) -> float:
        if not data:
            return 0.0
        return self.total_junk_bytes(data) / len(data)


class ControlFlowFlattener:
    @staticmethod
    def new():
        return ControlFlowFlattener()

    def detect(self, data: bytes):
        dispatchers = []
        for i in range(len(data) - 1):
            if data[i] == 0xFF and data[i + 1] in (0x25, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7):
                dispatchers.append(i)
        if not dispatchers:
            return None
        return _mk(dispatcher_offset=dispatchers[0], state_var=None,
                   body_blocks=[], dispatcher_count=len(dispatchers))

    @staticmethod
    def dispatcher_fan_out(result) -> float:
        if not result:
            return 0.0
        return float(len(result.get("body_blocks", []))) or float(result.get("dispatcher_count", 0))


class BogusControlFlowRemover:
    @staticmethod
    def new():
        return BogusControlFlowRemover()

    def remove_bogus_blocks(self, blocks, junk_offsets):
        return [b for b in blocks if b.get("start") not in junk_offsets and not b.get("is_dispatcher")]

    @staticmethod
    def junk_offset_set(regions):
        s = set()
        for r in regions:
            for k in range(r["length"]):
                s.add(r["offset"] + k)
        return s

    def dispatcher_blocks(self, blocks):
        return [b for b in blocks if b.get("is_dispatcher")]


class DeadCodeEliminator:
    @staticmethod
    def new():
        return DeadCodeEliminator()

    def build_graph(self, blocks):
        nodes = {b["start"]: i for i, b in enumerate(blocks)}
        edges = []
        for b in blocks:
            for s in b.get("succs", []):
                if s in nodes:
                    edges.append((nodes[b["start"]], nodes[s]))
        return ({"nodes": nodes, "edges": edges}, nodes)

    def reachable_blocks(self, blocks, entry_offset):
        by_start = {b["start"]: b for b in blocks}
        seen = set()
        if entry_offset not in by_start:
            return seen
        q = deque([entry_offset])
        while q:
            cur = q.popleft()
            if cur in seen:
                continue
            seen.add(cur)
            for s in by_start[cur].get("succs", []):
                if s in by_start and s not in seen:
                    q.append(s)
        return seen

    def eliminate(self, blocks, entry_offset):
        reach = self.reachable_blocks(blocks, entry_offset)
        return [b for b in blocks if b["start"] in reach]

    def dead_blocks(self, blocks, entry_offset):
        reach = self.reachable_blocks(blocks, entry_offset)
        return [b for b in blocks if b["start"] not in reach]

    def bfs_order(self, blocks, entry_offset):
        by_start = {b["start"]: b for b in blocks}
        order, seen = [], set()
        if entry_offset not in by_start:
            return order
        q = deque([entry_offset])
        while q:
            cur = q.popleft()
            if cur in seen:
                continue
            seen.add(cur)
            order.append(cur)
            for s in by_start[cur].get("succs", []):
                if s in by_start and s not in seen:
                    q.append(s)
        return order

    def dead_block_ratio(self, blocks, entry_offset) -> float:
        if not blocks:
            return 0.0
        return len(self.dead_blocks(blocks, entry_offset)) / len(blocks)


class ConstantFoldingHeuristic:
    @staticmethod
    def new():
        return ConstantFoldingHeuristic()

    def try_fold(self, data: bytes, offset: int):
        if offset >= len(data):
            return None
        b = data[offset]
        if b == 0xB8 and offset + 5 <= len(data):
            val = struct.unpack_from("<I", data, offset + 1)[0]
            return _mk(offset=offset, length=5, value=val, op="MOV_EAX")
        if b == 0xB0 and offset + 2 <= len(data):
            return _mk(offset=offset, length=2, value=data[offset + 1], op="MOV_AL")
        if b == 0x31 and offset + 2 <= len(data) and data[offset + 1] == 0xC0:
            return _mk(offset=offset, length=2, value=0, op="XOR_EAX")
        return None

    def fold_all(self, data: bytes):
        out = {}
        i = 0
        while i < len(data):
            r = self.try_fold(data, i)
            if r:
                out[i] = r
                i += r["length"]
            else:
                i += 1
        return out


class EntropyAnalyzer:
    def __init__(self, window_size: int):
        self.window_size = window_size

    @staticmethod
    def new(window_size: int):
        return EntropyAnalyzer(window_size)

    @staticmethod
    def entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        n = len(data)
        h = 0.0
        for c in counts.values():
            p = c / n
            h -= p * math.log2(p)
        return h

    def analyze(self, data: bytes):
        out = []
        if not data or self.window_size == 0:
            return out
        for s in range(0, len(data), self.window_size):
            chunk = data[s:s + self.window_size]
            out.append(_mk(offset=s, length=len(chunk), entropy=self.entropy(chunk)))
        return out

    def high_entropy_windows(self, data, threshold):
        return [w for w in self.analyze(data) if w["entropy"] >= threshold]

    def low_entropy_windows(self, data, threshold):
        return [w for w in self.analyze(data) if w["entropy"] <= threshold]

    def mean_entropy(self, data) -> float:
        ws = self.analyze(data)
        if not ws:
            return 0.0
        return sum(w["entropy"] for w in ws) / len(ws)


class PatchApplicator:
    @staticmethod
    def new():
        return PatchApplicator()

    def apply_nop_patches(self, data: bytearray, plan) -> int:
        return self.apply_fill_patches(data, plan, 0x90)

    def apply_fill_patches(self, data: bytearray, plan, fill: int) -> int:
        n = 0
        for p in plan:
            off, length = p["offset"], p["length"]
            if off + length <= len(data):
                for i in range(length):
                    data[off + i] = fill
                n += length
        return n

    def patched_copy(self, data: bytes, plan) -> bytes:
        buf = bytearray(data)
        self.apply_nop_patches(buf, plan)
        return bytes(buf)

    @staticmethod
    def validate_plan(plan, data_len: int) -> bool:
        return all(p["offset"] + p["length"] <= data_len for p in plan)


class MhcdeScore:
    def __init__(self, confidence: float = 0.0, findings: int = 0):
        self.confidence = confidence
        self.findings = findings

    def is_highly_obfuscated(self) -> bool:
        return self.confidence >= 0.75 and self.findings >= 3

    def confidence_tier(self) -> str:
        c = self.confidence
        if c >= 0.9: return "very high"
        if c >= 0.75: return "high"
        if c >= 0.5: return "medium"
        if c > 0.0: return "low"
        return "none"


class MhcdeAnalysis:
    def __init__(self, score, patches):
        self.score = score
        self.patches = patches

    def total_findings(self) -> int:
        return len(self.patches)

    def is_clean(self) -> bool:
        return not self.patches

    def patch_offsets(self):
        return sorted(p["offset"] for p in self.patches)

    def high_confidence_patches(self, min_confidence):
        return [p for p in self.patches if p.get("confidence", 0.0) >= min_confidence]


class MhcdeOrchestrator:
    @staticmethod
    def new():
        return MhcdeOrchestrator()

    def analyze(self, data: bytes) -> MhcdeAnalysis:
        op = OpaquePredicateDetector.new().detect(data)
        jc = JunkCodeDetector.new().detect(data)
        patches = [_mk(offset=p["offset"], length=p["length"], confidence=0.8) for p in op + jc]
        conf = min(1.0, len(patches) / 10.0)
        return MhcdeAnalysis(MhcdeScore(conf, len(patches)), patches)

    def analyze_and_patch(self, data: bytes):
        an = self.analyze(data)
        buf = PatchApplicator.new().patched_copy(data, an.patches)
        return (buf, an)


class MhcdePass:
    NAME = "mhcde"
    DESCRIPTION = "Mixed Honig CFG & dead-code elimination"

    @staticmethod
    def new():
        return MhcdePass()

    def analyze(self, data): return MhcdeOrchestrator.new().analyze(data)
    def name(self): return self.NAME
    def description(self): return self.DESCRIPTION
    def is_applicable(self, ctx): return bool(ctx.get("data"))
    def run(self, ctx): return self.analyze(ctx["data"])


def naturalness_score(code: bytes) -> float:
    if not code:
        return 0.0
    h = EntropyAnalyzer.entropy(code)
    nop_ratio = code.count(0x90) / len(code)
    top = Counter(code).most_common(1)[0][1] / len(code)
    return max(0.0, min(1.0, (1.0 - abs(h - 6.0) / 8.0) * (1.0 - nop_ratio) * (1.0 - top * 0.5)))


def complexity_score(basic_blocks: int, edges: int) -> float:
    if basic_blocks == 0:
        return 0.0
    return (edges - basic_blocks + 2) / max(1, basic_blocks)


class HypothesisResult:
    def __init__(self, name, naturalness, complexity):
        self.name = str(name)
        self.naturalness = naturalness
        self.complexity = complexity
        self.transformed = b""
        self.meta = {}

    @staticmethod
    def new(name, naturalness, complexity):
        return HypothesisResult(name, naturalness, complexity)

    def with_transformed(self, b):
        self.transformed = bytes(b)
        return self

    def with_meta(self, key, value):
        self.meta[str(key)] = str(value)
        return self

    def combined_score(self) -> float:
        return math.sqrt(max(0.0, self.naturalness) * max(0.0, self.complexity))

    def is_viable(self) -> bool:
        return self.combined_score() >= 0.6


class IdentityHypothesis:
    def name(self): return "identity"
    def run(self, code):
        return HypothesisResult.new("identity", naturalness_score(code), 0.5).with_transformed(code)


class NopStripHypothesis:
    def name(self): return "nop_strip"
    def run(self, code):
        out = bytes(b for b in code if b != 0x90)
        return HypothesisResult.new("nop_strip", naturalness_score(out), 0.5).with_transformed(out)


class XorFixedKeyHypothesis:
    KEY = 0x42
    def name(self): return f"xor_{self.KEY:02x}"
    def run(self, code):
        out = bytes(b ^ self.KEY for b in code)
        return HypothesisResult.new(self.name(), naturalness_score(out), 0.5).with_transformed(out)


class XorBestKeyHypothesis:
    def name(self): return "xor_best"
    def run(self, code):
        best_k, best_score, best_out = 0, -1.0, code
        for k in range(256):
            out = bytes(b ^ k for b in code)
            s = naturalness_score(out)
            if s > best_score:
                best_score, best_k, best_out = s, k, out
        r = HypothesisResult.new("xor_best", best_score, 0.5).with_transformed(best_out)
        r.with_meta("key", str(best_k))
        return r


class HypothesisRunner:
    @staticmethod
    def new(): return HypothesisRunner()

    @staticmethod
    def run_all_in_parallel(code, hypotheses):
        return [h.run(code) for h in hypotheses]

    @staticmethod
    def run_parallel(code, hypotheses):
        return [h.run(code) for h in hypotheses]

    @staticmethod
    def select_best(results):
        return max(results, key=lambda r: r.combined_score()) if results else None

    @staticmethod
    def best(code, hypotheses):
        return HypothesisRunner.select_best(HypothesisRunner.run_all_in_parallel(code, hypotheses))

    @staticmethod
    def default_hypotheses():
        return [IdentityHypothesis(), NopStripHypothesis(), XorFixedKeyHypothesis(), XorBestKeyHypothesis()]

    @staticmethod
    def ranked(results):
        return sorted(results, key=lambda r: r.combined_score(), reverse=True)


# =============================================================================
# src/mhcde_passes.rs
# =============================================================================

class Confidence:
    LOW = "low"; MEDIUM = "medium"; HIGH = "high"
    def __init__(self, lvl="medium"): self.lvl = lvl
    def is_reliable(self): return self.lvl in ("medium", "high")


class PassTransform:
    def __init__(self, offset, length, description, conf):
        self.offset = offset; self.length = length
        self.description = description; self.conf = conf

    @staticmethod
    def nop(offset, length, description, conf):
        return PassTransform(offset, length, str(description), conf)

    def apply(self, buf: bytearray) -> bool:
        if self.offset + self.length > len(buf): return False
        for i in range(self.length):
            buf[self.offset + i] = 0x90
        return True


class PassResult:
    def __init__(self, pass_name):
        self.pass_name = str(pass_name)
        self.transforms = []; self.notes = []

    @staticmethod
    def new(pass_name): return PassResult(pass_name)

    def push(self, t): self.transforms.append(t)
    def note(self, s): self.notes.append(str(s))
    def total_bytes(self): return sum(t.length for t in self.transforms)


class OpaquePredicatePass:
    def run(self, data: bytes) -> PassResult:
        r = PassResult.new("opaque_predicate")
        for p in OpaquePredicateDetector.new().detect(data):
            r.push(PassTransform.nop(p["offset"], p["length"], p["kind"], Confidence(Confidence.HIGH)))
        return r


class HandlerCfgPass:
    def run(self, data, base):
        cff = ControlFlowFlattener.new().detect(data)
        if cff is None: return None
        return _mk(base=base, dispatcher=cff["dispatcher_offset"], handlers=[])


class UnflattenPass:
    def run(self, data, base):
        cff = ControlFlowFlattener.new().detect(data)
        if cff is None: return None
        return _mk(base=base, recovered_blocks=[], dispatcher=cff["dispatcher_offset"])


class JunkRemovalPass:
    def run(self, data: bytes) -> PassResult:
        r = PassResult.new("junk_removal")
        for j in JunkCodeDetector.new().detect(data):
            r.push(PassTransform.nop(j["offset"], j["length"], j["kind"], Confidence(Confidence.MEDIUM)))
        return r


class MhcdePipelineResult:
    def __init__(self, passes): self.passes = list(passes)
    def apply_all(self, buf: bytearray) -> int:
        n = 0
        for pr in self.passes:
            for t in pr.transforms:
                if t.apply(buf): n += t.length
        return n


def run_mhcde_pipeline(data: bytes, base: int = 0) -> MhcdePipelineResult:
    return MhcdePipelineResult([OpaquePredicatePass().run(data), JunkRemovalPass().run(data)])


# =============================================================================
# src/multi_stage_deobf.rs
# =============================================================================

class StageKind:
    XorSingle = "xor_single"; XorMulti = "xor_multi"; Add = "add"; Rot = "rot"
    @staticmethod
    def name(k): return k
    @staticmethod
    def is_xor_based(k): return k in (StageKind.XorSingle, StageKind.XorMulti)


class Stage:
    def __init__(self, name, kind, key, confidence):
        self.name = str(name); self.kind = kind
        self.key = bytes(key); self.confidence = confidence

    @staticmethod
    def new(name, kind, key, confidence): return Stage(name, kind, key, confidence)

    def apply(self, data: bytes):
        if not self.key: return None
        if StageKind.is_xor_based(self.kind):
            k = self.key
            return bytes(b ^ k[i % len(k)] for i, b in enumerate(data))
        if self.kind == StageKind.Add:
            d = self.key[0]
            return bytes((b - d) & 0xFF for b in data)
        if self.kind == StageKind.Rot:
            r = self.key[0] & 7
            return bytes(((b >> r) | (b << (8 - r))) & 0xFF for b in data)
        return None


class StageResult:
    def __init__(self, stage_name, input_b, output, confidence):
        self.stage_name = stage_name
        self.input_entropy = EntropyAnalyzer.entropy(input_b)
        self.output_entropy = EntropyAnalyzer.entropy(output)
        self.output = bytes(output); self.confidence = confidence

    @staticmethod
    def new(stage_name, input_b, output, confidence):
        return StageResult(stage_name, input_b, output, confidence)

    def looks_decoded(self) -> bool:
        return self.output_entropy < self.input_entropy - 0.5


class LayerStack:
    def __init__(self): self.stages = []
    @staticmethod
    def new(): return LayerStack()
    def push(self, r): self.stages.append(r)
    def final_bytes(self): return self.stages[-1].output if self.stages else b""
    def depth(self): return len(self.stages)
    def total_entropy_reduction(self):
        if not self.stages: return 0.0
        return self.stages[0].input_entropy - self.stages[-1].output_entropy


class StageDetector:
    @staticmethod
    def new(): return StageDetector()

    def detect(self, data: bytes):
        out = []
        best_k, best_score = 0, -1.0
        for k in range(1, 256):
            decoded = bytes(b ^ k for b in data[:256])
            score = sum(1 for b in decoded if 32 <= b < 127) / max(1, len(decoded))
            if score > best_score:
                best_score, best_k = score, k
        if best_score > 0.3:
            out.append(Stage.new(f"xor_{best_k:02x}", StageKind.XorSingle, bytes([best_k]), best_score))
        return out


class MultiStageDeobf:
    def __init__(self):
        self.max_depth = 4; self.min_confidence = 0.3

    @staticmethod
    def new(): return MultiStageDeobf()

    def with_max_depth(self, n): self.max_depth = n; return self
    def with_min_confidence(self, c): self.min_confidence = c; return self

    def apply_stage(self, data, stage):
        out = stage.apply(data)
        if out is None: return None
        return StageResult.new(stage.name, data, out, stage.confidence)

    def deobfuscate_auto(self, data: bytes):
        stack = LayerStack.new(); cur = data
        for _ in range(self.max_depth):
            stages = StageDetector.new().detect(cur)
            if not stages: break
            s = stages[0]
            if s.confidence < self.min_confidence: break
            r = self.apply_stage(cur, s)
            if r is None: break
            stack.push(r); cur = r.output
        return stack

    def deobfuscate_stages(self, data, stages):
        stack = LayerStack.new(); cur = data
        for s in stages:
            r = self.apply_stage(cur, s)
            if r is None: break
            stack.push(r); cur = r.output
        return stack

    @staticmethod
    def compute_hash(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()


class VtResult:
    def __init__(self, positives, total):
        self.positives = positives; self.total = total
    def detection_ratio(self):
        return self.positives / self.total if self.total else 0.0


class VtClient:
    def __init__(self):
        self.api_key = None; self.malicious = set()
    @staticmethod
    def new(): return VtClient()
    def with_api_key(self, key): self.api_key = str(key); return self
    def register_malicious(self, h): self.malicious.add(str(h))
    def check(self, data):
        h = hashlib.sha256(data).hexdigest()
        return VtResult(1 if h in self.malicious else 0, 1)


# =============================================================================
# src/hypothesis_validator.rs
# =============================================================================

class HypothesisKind:
    Xor = "xor"; Add = "add"; Rot = "rot"; Unknown = "unknown"
    @staticmethod
    def label(k): return k
    @staticmethod
    def base_prior(k):
        return {"xor": 0.4, "add": 0.2, "rot": 0.1, "unknown": 0.1}.get(k, 0.1)


class ValidationCriteria:
    def __init__(self, min_printable=0.3, max_entropy=7.0, min_quality=0.4):
        self.min_printable = min_printable
        self.max_entropy = max_entropy
        self.min_quality = min_quality

    @staticmethod
    def lenient(): return ValidationCriteria(0.1, 7.5, 0.2)
    @staticmethod
    def strict(): return ValidationCriteria(0.6, 6.5, 0.7)
    @staticmethod
    def for_kind(kind):
        if kind == HypothesisKind.Xor: return ValidationCriteria(0.4, 7.0, 0.5)
        return ValidationCriteria()


class ValidationResult:
    def __init__(self, quality, printable, entropy, criteria):
        self.quality = quality; self.printable = printable
        self.entropy = entropy; self.criteria = criteria

    def is_high_quality(self): return self.quality >= 0.75
    def is_acceptable(self):
        c = self.criteria
        return self.quality >= c.min_quality and self.printable >= c.min_printable and self.entropy <= c.max_entropy


def is_valid_code(data: bytes) -> bool:
    if not data: return False
    printable = sum(1 for b in data if 32 <= b < 127)
    return printable / len(data) > 0.05 or any(b in (0x55, 0x48, 0xC3) for b in data[:64])


def is_plausible_code(data: bytes) -> bool:
    if not data: return False
    e = EntropyAnalyzer.entropy(data)
    return 1.0 < e < 7.5


def quality_score(data: bytes) -> float:
    if not data: return 0.0
    printable = sum(1 for b in data if 32 <= b < 127) / len(data)
    e = EntropyAnalyzer.entropy(data)
    e_score = max(0.0, 1.0 - abs(e - 5.5) / 5.5)
    return 0.5 * printable + 0.5 * e_score


class HypothesisValidator:
    def __init__(self, criteria): self.criteria = criteria
    @staticmethod
    def new(criteria): return HypothesisValidator(criteria)
    @staticmethod
    def default(): return HypothesisValidator(ValidationCriteria())
    @staticmethod
    def for_kind(kind): return HypothesisValidator(ValidationCriteria.for_kind(kind))

    def validate(self, output: bytes, kind):
        q = quality_score(output)
        p = sum(1 for b in output if 32 <= b < 127) / max(1, len(output))
        e = EntropyAnalyzer.entropy(output)
        return ValidationResult(q, p, e, self.criteria)

    def select_best(self, outputs_kinds):
        best = None; best_q = -1.0
        for output, kind in outputs_kinds:
            r = self.validate(output, kind)
            if r.quality > best_q:
                best_q = r.quality; best = (output, kind, r)
        return best


class BatchValidator:
    def __init__(self, criteria=None): self.criteria = criteria or ValidationCriteria()
    @staticmethod
    def new(): return BatchValidator()
    @staticmethod
    def with_criteria(criteria): return BatchValidator(criteria)

    def validate_all(self, outputs_kinds):
        v = HypothesisValidator(self.criteria)
        return [v.validate(o, k) for o, k in outputs_kinds]

    def pass_count(self, results): return sum(1 for r in results if r.is_acceptable())
    def mean_quality(self, results):
        return sum(r.quality for r in results) / len(results) if results else 0.0


# =============================================================================
# src/hypothesis_manager.rs
# =============================================================================

class HypothesisState:
    Pending = "pending"; Running = "running"; Completed = "completed"; Failed = "failed"


class DeobfPassSpec:
    def __init__(self, name, category):
        self.name = str(name); self.category = str(category); self.params = {}
    @staticmethod
    def new(name, category): return DeobfPassSpec(name, category)
    def with_param(self, key, value):
        self.params[str(key)] = value; return self


class QualityMetrics:
    def __init__(self, entropy, printable, score):
        self.entropy = entropy; self.printable = printable; self.score = score
    @staticmethod
    def compute(output: bytes):
        e = EntropyAnalyzer.entropy(output)
        p = sum(1 for b in output if 32 <= b < 127) / max(1, len(output))
        return QualityMetrics(e, p, quality_score(output))
    def is_promising(self): return self.score >= 0.5


class ManagedHypothesis:
    def __init__(self, hid, passes):
        self.id = hid; self.passes = list(passes)
        self.state = HypothesisState.Pending
        self.output = None; self.error = None; self.metrics = None

    @staticmethod
    def new(hid, passes): return ManagedHypothesis(hid, passes)

    def fork(self, extra_pass, new_id):
        return ManagedHypothesis(new_id, self.passes + [extra_pass])

    def complete(self, output):
        self.output = bytes(output); self.metrics = QualityMetrics.compute(output)
        self.state = HypothesisState.Completed

    def fail(self, error):
        self.error = str(error); self.state = HypothesisState.Failed

    def composite_score(self):
        return self.metrics.score if self.metrics else 0.0


class HypothesisManager:
    def __init__(self, top_k, min_score):
        self.top_k = top_k; self.min_score = min_score
        self.items = {}; self._next_id = 1

    @staticmethod
    def new(top_k, min_score): return HypothesisManager(top_k, min_score)

    def create(self, passes):
        hid = self._next_id; self._next_id += 1
        self.items[hid] = ManagedHypothesis.new(hid, passes)
        return hid

    def fork(self, parent_id, extra_pass):
        if parent_id not in self.items: return None
        new_id = self._next_id; self._next_id += 1
        self.items[new_id] = self.items[parent_id].fork(extra_pass, new_id)
        return new_id

    def complete(self, hid, output):
        if hid not in self.items: return False
        self.items[hid].complete(output); return True

    def fail(self, hid, error):
        if hid not in self.items: return False
        self.items[hid].fail(error); return True

    def prune(self):
        removed = []
        for hid, h in list(self.items.items()):
            if h.state == HypothesisState.Completed and h.composite_score() < self.min_score:
                removed.append(hid); del self.items[hid]
        return removed

    def best(self):
        c = [h for h in self.items.values() if h.state == HypothesisState.Completed]
        return max(c, key=lambda h: h.composite_score()) if c else None

    def by_state(self, state): return [h for h in self.items.values() if h.state == state]
    def pending_ids(self): return [hid for hid, h in self.items.items() if h.state == HypothesisState.Pending]
    def status_summary(self): return dict(Counter(h.state for h in self.items.values()))


class HypothesisGenerator_Mgr:
    def generate(self, manager):
        return [manager.create([DeobfPassSpec.new(n, "decode")]) for n in ("xor", "add", "rot")]


# =============================================================================
# src/hypothesis_generator.rs
# =============================================================================

class GenHypothesis:
    def __init__(self, kind, prior):
        self.kind = kind; self.prior = prior
        self.parameters = {}; self.evidence = []; self.priority = 0
        self.posterior_value = prior

    @staticmethod
    def new(kind, prior=None):
        if prior is None: prior = HypothesisKind.base_prior(kind)
        return GenHypothesis(kind, prior)

    def with_parameter(self, param):
        if isinstance(param, tuple):
            self.parameters[str(param[0])] = param[1]
        else:
            self.parameters[str(len(self.parameters))] = param
        return self

    def with_evidence(self, ev): self.evidence.append(ev); return self
    def with_priority(self, p): self.priority = int(p); return self

    @staticmethod
    def posterior(prior, likelihood):
        num = prior * likelihood
        den = num + (1 - prior) * (1 - likelihood)
        return num / den if den else 0.0

    def is_viable(self): return self.posterior_value >= 0.3


class HypothesisGeneratorConfig:
    def __init__(self, max_hypotheses=8, min_prior=0.05):
        self.max_hypotheses = max_hypotheses
        self.min_prior = min_prior


class HypothesisGenerator:
    def __init__(self, config): self.config = config
    @staticmethod
    def new(config): return HypothesisGenerator(config)
    @staticmethod
    def default(): return HypothesisGenerator(HypothesisGeneratorConfig())

    def generate(self, data: bytes):
        out = []
        for kind in (HypothesisKind.Xor, HypothesisKind.Add, HypothesisKind.Rot):
            prior = HypothesisKind.base_prior(kind)
            if prior >= self.config.min_prior:
                out.append(GenHypothesis.new(kind, prior))
        return out[: self.config.max_hypotheses]

    def confidence_map(self, data):
        return {h.kind: h.prior for h in self.generate(data)}


def confidence_score(data: bytes) -> float:
    return EntropyAnalyzer.entropy(data) / 8.0


def top_hypothesis_kind(data):
    e = EntropyAnalyzer.entropy(data)
    if e > 6.0: return HypothesisKind.Xor
    if e > 3.0: return HypothesisKind.Add
    return HypothesisKind.Unknown


def viable_hypotheses(data):
    return [h for h in HypothesisGenerator.default().generate(data) if h.is_viable()]


# =============================================================================
# src/hypothesis_engine.rs
# =============================================================================

class Algorithm:
    def __init__(self, name, cost): self._name = str(name); self._cost = int(cost)
    def name(self): return self._name
    def cost_estimate(self): return self._cost


class ParamSet:
    def __init__(self): self.values = {}
    @staticmethod
    def new(): return ParamSet()
    def set_str(self, k, v): self.values[str(k)] = str(v)
    def set_int(self, k, v): self.values[str(k)] = int(v)
    def set_float(self, k, v): self.values[str(k)] = float(v)
    def get_float(self, k):
        v = self.values.get(k); return float(v) if isinstance(v, (int, float)) else None
    def get_int(self, k):
        v = self.values.get(k); return int(v) if isinstance(v, int) else None
    def get_str(self, k):
        v = self.values.get(k); return str(v) if isinstance(v, str) else None


class EngineHypothesis:
    def __init__(self, hid, label, algorithm, confidence):
        self.id = hid; self.label = label; self.algorithm = algorithm
        self.confidence = confidence; self.params = {}; self.evidence = []; self.generation = 0

    @staticmethod
    def new(hid, label, algorithm, confidence):
        return EngineHypothesis(hid, str(label), algorithm, confidence)

    def with_param(self, k, v): self.params[str(k)] = v; return self
    def with_evidence(self, tag): self.evidence.append(tag); return self
    def with_confidence(self, c): self.confidence = float(c); return self
    def with_generation(self, g): self.generation = int(g); return self
    def priority_score(self): return self.confidence / max(1, self.algorithm.cost_estimate())


class HypothesisEngineError(Exception): pass


class HypothesisPool:
    def __init__(self): self.items = {}; self._next_id = 1
    @staticmethod
    def new(): return HypothesisPool()

    def insert(self, h):
        if h.id in self.items: raise HypothesisEngineError(f"duplicate id {h.id}")
        self.items[h.id] = h

    def next_id(self):
        v = self._next_id; self._next_id += 1; return v

    def peek_best(self):
        return max(self.items.values(), key=lambda h: h.priority_score()) if self.items else None

    def pop_best(self):
        h = self.peek_best()
        if h is None: return None
        del self.items[h.id]; return h

    def top_n(self, n):
        return sorted(self.items.values(), key=lambda h: h.priority_score(), reverse=True)[:n]

    def len(self): return len(self.items)
    def is_empty(self): return not self.items

    def remove(self, hid):
        if hid in self.items: del self.items[hid]; return True
        return False

    def boost_confidence(self, hid, delta):
        if hid not in self.items: raise HypothesisEngineError(f"unknown id {hid}")
        self.items[hid].confidence += delta

    def all_sorted(self):
        return sorted(self.items.values(), key=lambda h: h.priority_score(), reverse=True)


class FeatureObservation:
    def __init__(self, entropy, printable_ratio, size):
        self.entropy = entropy; self.printable_ratio = printable_ratio; self.size = size
    @staticmethod
    def from_bytes(data: bytes):
        e = EntropyAnalyzer.entropy(data)
        p = sum(1 for b in data if 32 <= b < 127) / max(1, len(data))
        return FeatureObservation(e, p, len(data))


class HypothesisEngine:
    def __init__(self, min_confidence):
        self.min_confidence = min_confidence
        self._pool = HypothesisPool.new()
    @staticmethod
    def new(min_confidence): return HypothesisEngine(min_confidence)

    def add_hypothesis(self, label, algorithm, confidence):
        hid = self._pool.next_id()
        self._pool.insert(EngineHypothesis.new(hid, label, algorithm, confidence))
        return hid

    def generate_from_features(self, features):
        ids = []
        if features.entropy > 6.0:
            ids.append(self.add_hypothesis("xor_decode", Algorithm("xor", 1), 0.7))
        if features.printable_ratio < 0.2:
            ids.append(self.add_hypothesis("add_decode", Algorithm("add", 1), 0.4))
        return ids

    def combine_top_k(self, k):
        tops = self._pool.top_n(k)
        if not tops: raise HypothesisEngineError("empty pool")
        avg = sum(h.confidence for h in tops) / len(tops)
        return EngineHypothesis.new(self._pool.next_id(), "combined",
                                    Algorithm("combined", sum(h.algorithm.cost_estimate() for h in tops)), avg)

    def pool(self): return self._pool
    def pool_mut(self): return self._pool


# =============================================================================
# src/hypothesis_combiner.rs
# =============================================================================

class CombinedStrategy:
    def __init__(self, weights=None): self.weights = dict(weights or {})
    @staticmethod
    def uniform(names):
        if not names: return CombinedStrategy({})
        w = 1.0 / len(names)
        return CombinedStrategy({n: w for n in names})
    @staticmethod
    def from_map(m): return CombinedStrategy(m)

    def normalise(self):
        total = sum(self.weights.values())
        if total == 0: return
        for k in list(self.weights): self.weights[k] /= total

    def weight_for(self, name): return self.weights.get(name, 0.0)
    def active_names(self): return [n for n, w in self.weights.items() if w > 1e-9]
    def is_valid(self):
        s = sum(self.weights.values()); return abs(s - 1.0) < 1e-3 or s > 0
    def active_count(self): return len(self.active_names())


class CombinationConstraint:
    def __init__(self, strategy, min_w=None, max_w=None):
        self.strategy = strategy; self.min_w = min_w; self.max_w = max_w
    @staticmethod
    def min_weight(strategy, min_v): return CombinationConstraint(str(strategy), min_w=min_v)
    @staticmethod
    def max_weight(strategy, max_v): return CombinationConstraint(str(strategy), max_w=max_v)
    def is_satisfied(self, cs):
        w = cs.weight_for(self.strategy)
        if self.min_w is not None and w < self.min_w: return False
        if self.max_w is not None and w > self.max_w: return False
        return True


def validate_constraints(cs, constraints):
    return all(c.is_satisfied(cs) for c in constraints)


class EvaluationRecord:
    def __init__(self, weights, quality, accepted):
        self.weights = dict(weights); self.quality = quality; self.accepted = accepted


class EvaluationHistory:
    def __init__(self): self.records = []
    @staticmethod
    def new(): return EvaluationHistory()
    def push(self, weights, quality, accepted):
        self.records.append(EvaluationRecord(weights, quality, accepted))
    def len(self): return len(self.records)
    def is_empty(self): return not self.records
    def mean_quality(self):
        return sum(r.quality for r in self.records) / len(self.records) if self.records else 0.0
    def best_quality(self):
        return max(r.quality for r in self.records) if self.records else 0.0
    def accepted_count(self): return sum(1 for r in self.records if r.accepted)
    def sorted_by_quality(self):
        return sorted(self.records, key=lambda r: r.quality, reverse=True)


class Strategy:
    def __init__(self, name, weight):
        self.name = str(name); self.weight = weight; self.enabled = True
    @staticmethod
    def new(name, weight): return Strategy(name, weight)
    def disabled(self): self.enabled = False; return self
    def is_significant(self): return self.enabled and self.weight > 1e-3


class CombinedResult:
    def __init__(self, strategy, quality):
        self.strategy = strategy; self.quality = quality; self.per_strategy = {}
    @staticmethod
    def new(strategy, quality): return CombinedResult(strategy, quality)
    def set_strategy_quality(self, name, q): self.per_strategy[str(name)] = q
    def dominant_strategy(self):
        if not self.strategy.weights: return None
        return max(self.strategy.weights, key=self.strategy.weights.get)
    def summary(self): return f"quality={self.quality:.3f} weights={self.strategy.weights}"


class CombinedResultPool:
    def __init__(self): self.items = []
    @staticmethod
    def new(): return CombinedResultPool()
    def push(self, r): self.items.append(r)
    def best(self):
        return max(self.items, key=lambda r: r.quality) if self.items else None
    def len(self): return len(self.items)
    def is_empty(self): return not self.items
    def sorted_by_quality(self):
        return sorted(self.items, key=lambda r: r.quality, reverse=True)
    def above_threshold(self, t):
        return [r for r in self.items if r.quality >= t]


class BestCombination:
    def __init__(self): self.best = None
    @staticmethod
    def new(): return BestCombination()
    def update(self, result):
        if self.best is None or result.quality > self.best.quality:
            self.best = result; return True
        return False
    def best_quality(self): return self.best.quality if self.best else 0.0
    def has_result(self): return self.best is not None


class WeightMap:
    def __init__(self, entries): self.weights = dict(entries)
    @staticmethod
    def new(entries): return WeightMap(entries)
    def normalise(self):
        s = sum(self.weights.values())
        if s == 0: return
        for k in list(self.weights): self.weights[k] /= s
    def get(self, name): return self.weights.get(name, 0.0)
    def to_combined_strategy(self): return CombinedStrategy.from_map(self.weights)
    def l2_distance(self, other):
        keys = set(self.weights) | set(other.weights)
        return math.sqrt(sum((self.get(k) - other.get(k)) ** 2 for k in keys))


class StrategyMetric:
    def __init__(self, name): self.name = str(name); self.samples = []
    @staticmethod
    def new(name): return StrategyMetric(name)
    def record(self, q): self.samples.append(q)


class StrategyRegistry:
    def __init__(self): self.metrics = {}; self.recs = []
    @staticmethod
    def new(): return StrategyRegistry()
    def register(self, name):
        name = str(name)
        if name not in self.metrics: self.metrics[name] = StrategyMetric.new(name)
    def record(self, strategy, quality):
        self.register(strategy); self.metrics[strategy].record(quality)
    def update_recommendations(self):
        def avg(m): return sum(m.samples) / len(m.samples) if m.samples else 0
        ranked = sorted(self.metrics.values(), key=avg, reverse=True)
        self.recs = [m.name for m in ranked[:3]]
    def recommended(self): return list(self.recs)
    def best_strategy(self):
        if not self.metrics: return None
        def avg(m): return sum(m.samples) / len(m.samples) if m.samples else 0
        return max(self.metrics.values(), key=avg).name
    def len(self): return len(self.metrics)
    def is_empty(self): return not self.metrics


class CombinationHistory:
    def __init__(self): self.steps = []


class GridSearchSolver:
    def __init__(self, strategies, oracle):
        self.strategies = list(strategies); self.oracle = oracle
    @staticmethod
    def new(strategies, oracle): return GridSearchSolver(strategies, oracle)
    def find_best(self):
        if not self.strategies: return None
        best = None; best_seq = None
        for s in self.strategies:
            w = {x: 0.0 for x in self.strategies}; w[s] = 1.0
            cs = CombinedStrategy.from_map(w)
            r = CombinedResult.new(cs, self.oracle(cs))
            if best is None or r.quality > best.quality:
                best = r; best_seq = [s]
        return (best, best_seq) if best else None


class EvolutionarySolver:
    def __init__(self, strategies, oracle):
        self.strategies = list(strategies); self.oracle = oracle
    @staticmethod
    def new(strategies, oracle): return EvolutionarySolver(strategies, oracle)
    def evolve(self):
        if not self.strategies: return None
        cs = CombinedStrategy.uniform(self.strategies)
        return CombinedResult.new(cs, self.oracle(cs))


class HillClimber:
    def __init__(self, strategies, oracle):
        self.strategies = list(strategies); self.oracle = oracle
        self.step_size = 0.1; self.max_iterations = 100
    @staticmethod
    def new(strategies, oracle): return HillClimber(strategies, oracle)
    def with_step_size(self, s): self.step_size = s; return self
    def with_max_iterations(self, n): self.max_iterations = n; return self
    def run(self):
        best = BestCombination.new(); hist = CombinationHistory()
        if not self.strategies: return best, hist
        cs = CombinedStrategy.uniform(self.strategies)
        for _ in range(self.max_iterations):
            r = CombinedResult.new(cs, self.oracle(cs))
            hist.steps.append(r); best.update(r)
        return best, hist


class OracleEvaluator:
    def __init__(self, scorer): self.scorer = scorer
    def evaluate(self, strategy): return CombinedResult.new(strategy, self.scorer(strategy))
    def best_single_strategy(self): return None


# =============================================================================
# src/concurrent_deobf_executor.rs
# =============================================================================

class ExecutorConfig:
    def __init__(self, threads=4, top_n=8, min_quality=0.4):
        self.threads = threads; self.top_n = top_n; self.min_quality = min_quality


class ExecutionResult:
    def __init__(self, hypothesis, output, quality, kind="unknown"):
        self.hypothesis = hypothesis; self.output = bytes(output)
        self.quality = quality; self.kind = kind
    def is_high_quality(self): return self.quality >= 0.7


class BestResult:
    def __init__(self, results): self.results = list(results)
    def best_output(self, original):
        return max(self.results, key=lambda r: r.quality).output if self.results else original


class ConcurrentDeobfExecutor:
    def __init__(self, config): self.cfg = config
    @staticmethod
    def new(config): return ConcurrentDeobfExecutor(config)
    @staticmethod
    def default(): return ConcurrentDeobfExecutor(ExecutorConfig())
    def _run_one(self, data, h):
        out = bytes(b ^ 0x42 for b in data)
        return ExecutionResult(h, out, quality_score(out))
    def execute(self, data, hypotheses):
        return BestResult([self._run_one(data, h) for h in hypotheses])
    def execute_top_n(self, data, hypotheses):
        return BestResult([self._run_one(data, h) for h in hypotheses[: self.cfg.top_n]])
    def config(self): return self.cfg


def executor_pool(threads): return ConcurrentDeobfExecutor(ExecutorConfig(threads=threads))
def fast_executor(): return ConcurrentDeobfExecutor(ExecutorConfig(threads=8, top_n=4, min_quality=0.3))
def thorough_executor(): return ConcurrentDeobfExecutor(ExecutorConfig(threads=2, top_n=32, min_quality=0.6))


class ResultAggregator:
    def __init__(self): self.results = []
    @staticmethod
    def new(): return ResultAggregator()
    def push(self, r): self.results.append(r)
    def extend_from_best(self, best): self.results.extend(best.results)
    def best(self):
        return max(self.results, key=lambda r: r.quality) if self.results else None
    def viable(self): return [r for r in self.results if r.quality >= 0.4]
    def by_kind(self):
        out = defaultdict(list)
        for r in self.results: out[r.kind].append(r)
        return dict(out)
    def mean_score(self):
        return sum(r.quality for r in self.results) / len(self.results) if self.results else 0.0
    def len(self): return len(self.results)
    def is_empty(self): return not self.results
    def clear(self): self.results.clear()


# =============================================================================
# src/control_flow_graph_builder.rs
# =============================================================================

class TermKind:
    Fall = "fall"; Jmp = "jmp"; Branch = "branch"; Ret = "ret"; Call = "call"


class BasicBlock:
    def __init__(self, start, end, term):
        self.start = start; self.end = end; self.term = term; self.succs = []
    @staticmethod
    def new(start, end, term): return BasicBlock(start, end, term)
    def len(self): return self.end - self.start
    def is_entry(self): return self.start == 0
    def contains(self, addr): return self.start <= addr < self.end


class ControlFlowGraph:
    def __init__(self, blocks, edges):
        self.blocks = list(blocks); self.edges = list(edges)
    def size(self): return len(self.blocks)
    def iter_blocks(self): return iter(self.blocks)
    def block(self, addr):
        for b in self.blocks:
            if b.contains(addr): return b
        return None
    def back_edges(self):
        out = []
        rpo = self.reverse_post_order()
        order = {a: i for i, a in enumerate(rpo)}
        for src, dst in self.edges:
            if order.get(dst, len(order)) <= order.get(src, -1):
                out.append((src, dst))
        return out
    def dominates(self, a, b):
        if a == b: return True
        rpo = self.reverse_post_order()
        if a not in rpo or b not in rpo: return False
        return rpo.index(a) < rpo.index(b)
    def block_count(self): return len(self.blocks)
    def edge_count(self): return len(self.edges)
    def reverse_post_order(self):
        if not self.blocks: return []
        by_start = {b.start: b for b in self.blocks}
        visited = set(); order = []
        def dfs(addr):
            if addr in visited or addr not in by_start: return
            visited.add(addr)
            for s in by_start[addr].succs: dfs(s)
            order.append(addr)
        dfs(self.blocks[0].start)
        return list(reversed(order))


def estimate_len(data: bytes, off: int) -> int:
    if off >= len(data): return 0
    b = data[off]
    if b in (0xC3, 0x90): return 1
    if b in (0xEB, 0x74, 0x75): return 2
    if b in (0xE8, 0xE9): return 5
    return 1


def classify_terminator(data: bytes, off: int) -> str:
    if off >= len(data): return TermKind.Fall
    b = data[off]
    if b == 0xC3: return TermKind.Ret
    if b in (0xE9, 0xEB): return TermKind.Jmp
    if b in (0x74, 0x75, 0x7C, 0x7D, 0x7E, 0x7F): return TermKind.Branch
    if b == 0xE8: return TermKind.Call
    return TermKind.Fall


class CfgBuilder:
    def __init__(self, base): self.base = base
    @staticmethod
    def new(base): return CfgBuilder(base)
    def build(self, data, entry):
        term = classify_terminator(data, max(0, len(data) - 1))
        return ControlFlowGraph([BasicBlock.new(entry, entry + len(data), term)], [])


class Dominators:
    def __init__(self, dom): self.dom = dom
    @staticmethod
    def compute(cfg):
        if not cfg.blocks: return Dominators({})
        entry = cfg.blocks[0].start
        return Dominators({b.start: {entry, b.start} for b in cfg.blocks})


# =============================================================================
# src/deobf_orchestrator.rs
# =============================================================================

class PassCategory:
    Cleanup = "cleanup"; Decode = "decode"; Cfg = "cfg"; Heavy = "heavy"
    @staticmethod
    def cost(cat):
        return {"cleanup": 1, "decode": 3, "cfg": 5, "heavy": 10}.get(cat, 1)


class PassDescriptor:
    def __init__(self, spec, category):
        self.spec = spec; self.category = category
        self.prereq = None; self.gain = 0.0; self.max_repeats = 1
    @staticmethod
    def new(spec, category): return PassDescriptor(spec, category)
    def with_prereq(self, p): self.prereq = p; return self
    def with_gain(self, g): self.gain = g; return self
    def repeatable(self, m): self.max_repeats = int(m); return self


class PassRegistry:
    def __init__(self): self.passes = []
    @staticmethod
    def default_registry():
        r = PassRegistry()
        r.add(PassDescriptor.new(DeobfPassSpec.new("nop_strip", "cleanup"), PassCategory.Cleanup).with_gain(0.1))
        r.add(PassDescriptor.new(DeobfPassSpec.new("xor", "decode"), PassCategory.Decode).with_gain(0.5))
        return r
    def add(self, d): self.passes.append(d)
    def find(self, name):
        for d in self.passes:
            if d.spec.name == name: return d
        return None
    def sorted_by_gain(self):
        return sorted(self.passes, key=lambda d: d.gain, reverse=True)


class OrchestratorConfig:
    def __init__(self, max_passes=8, min_gain=0.05):
        self.max_passes = max_passes; self.min_gain = min_gain


class OrchestrationReport:
    def __init__(self, initial_score, final_score, applied):
        self.initial_score = initial_score; self.final_score = final_score
        self.applied = list(applied)
    def summary(self): return f"applied={len(self.applied)} delta={self.score_delta():.3f}"
    def score_delta(self): return self.final_score - self.initial_score


class DeobfOrchestrator:
    def __init__(self, config):
        self.config = config; self.registry = PassRegistry.default_registry()
    @staticmethod
    def new(config): return DeobfOrchestrator(config)
    def register_pass(self, d): self.registry.add(d)
    def run(self, initial_data: bytes):
        initial = quality_score(initial_data)
        applied = [d.spec.name for d in self.registry.sorted_by_gain()[: self.config.max_passes]]
        return OrchestrationReport(initial, quality_score(initial_data), applied)


# =============================================================================
# src/combination_solver.rs
# =============================================================================

class QualityMeasurement:
    def __init__(self, score, entropy, printable):
        self.score = score; self.entropy = entropy; self.printable = printable
    @staticmethod
    def from_bytes(data):
        return QualityMeasurement(quality_score(data), EntropyAnalyzer.entropy(data),
                                  sum(1 for b in data if 32 <= b < 127) / max(1, len(data)))
    def is_better_than(self, other): return self.score > other.score
    def improvement_over(self, other): return self.score - other.score


class CombinationResult:
    def __init__(self, initial, final, applied):
        self.initial = initial; self.final = final; self.applied = list(applied)
    def improved(self): return self.final.score > self.initial.score
    def summary(self): return f"applied={self.applied} delta={self.final.score - self.initial.score:.3f}"


class HypothesisApplier:
    def apply(self, data, hypothesis):
        key = 0x42
        params = getattr(hypothesis, "params", {})
        if "key" in params and isinstance(params["key"], int):
            key = params["key"] & 0xFF
        return bytes(b ^ key for b in data)


class CombinationSolver:
    def __init__(self, min_improvement=0.01, max_hypotheses=4):
        self.min_improvement = min_improvement; self.max_hypotheses = max_hypotheses
    @staticmethod
    def new(): return CombinationSolver()
    @staticmethod
    def with_settings(min_improvement, max_hypotheses):
        return CombinationSolver(min_improvement, max_hypotheses)
    def solve(self, data, hypotheses):
        applier = HypothesisApplier(); cur = data
        initial = QualityMeasurement.from_bytes(cur); applied = []
        for h in hypotheses[: self.max_hypotheses]:
            nxt = applier.apply(cur, h)
            if QualityMeasurement.from_bytes(nxt).improvement_over(QualityMeasurement.from_bytes(cur)) >= self.min_improvement:
                cur = nxt; applied.append(getattr(h, "label", "h"))
        return CombinationResult(initial, QualityMeasurement.from_bytes(cur), applied)
    def solve_exhaustive(self, data, hypotheses):
        n = min(len(hypotheses), self.max_hypotheses)
        best = None
        for mask in range(1 << n):
            applier = HypothesisApplier(); cur = data; applied = []
            for i in range(n):
                if mask & (1 << i):
                    cur = applier.apply(cur, hypotheses[i])
                    applied.append(getattr(hypotheses[i], "label", f"h{i}"))
            r = CombinationResult(QualityMeasurement.from_bytes(data),
                                  QualityMeasurement.from_bytes(cur), applied)
            if best is None or r.final.score > best.final.score: best = r
        return best
    def solve_windowed(self, data, hypotheses, window=64):
        return [(s, self.solve(data[s:s + window], hypotheses)) for s in range(0, len(data), window)]


# =============================================================================
# src/dataflow_propagator.rs
# =============================================================================

class VarId:
    def __init__(self, kind, name): self.kind = kind; self.name = name
    @staticmethod
    def reg(name): return VarId("reg", str(name))
    @staticmethod
    def stack(off): return VarId("stack", str(int(off)))
    def __hash__(self): return hash((self.kind, self.name))
    def __eq__(self, o): return isinstance(o, VarId) and (self.kind, self.name) == (o.kind, o.name)
    def __repr__(self): return f"VarId({self.kind},{self.name})"


class Lattice:
    TOP = "top"; BOT = "bot"
    def __init__(self, tag, value=None): self.tag = tag; self.value = value
    @staticmethod
    def top(): return Lattice(Lattice.TOP)
    @staticmethod
    def bot(): return Lattice(Lattice.BOT)
    @staticmethod
    def const(v): return Lattice("const", int(v))
    def meet(self, other):
        if self.tag == Lattice.TOP: return other
        if other.tag == Lattice.TOP: return self
        if self.tag == "const" and other.tag == "const" and self.value == other.value:
            return self
        return Lattice.bot()
    def is_const(self): return self.tag == "const"
    def const_val(self): return self.value if self.tag == "const" else None


class ReachingDefsBlock:
    def __init__(self, var):
        self.var = var; self.defs = set(); self.out = set()
    @staticmethod
    def new(var): return ReachingDefsBlock(var)
    def is_single_def(self): return len(self.defs) == 1
    def is_dead(self): return len(self.defs) == 0
    def constant_value(self):
        if len(self.defs) == 1:
            d = next(iter(self.defs))
            return d if isinstance(d, int) else None
        return None
    def compute_out(self): self.out = set(self.defs)
    def merge_predecessor(self, pred_out):
        before = len(self.defs)
        for s in pred_out.values(): self.defs |= s
        return len(self.defs) != before


class ReachingDefsAnalysis:
    def __init__(self): self.blocks = {}
    @staticmethod
    def analyze(blocks_by_addr, defs_per_block):
        a = ReachingDefsAnalysis()
        for addr, var_defs in defs_per_block.items():
            for var, ds in var_defs.items():
                rb = ReachingDefsBlock.new(var); rb.defs = set(ds); rb.compute_out()
                a.blocks[(addr, var)] = rb
        return a
    def reaching_defs_at(self, block, var):
        rb = self.blocks.get((block, var))
        return set(rb.defs) if rb else set()


class Expr:
    def __init__(self, kind, lhs=None, op=None, rhs=None, folded=None):
        self.kind = kind; self.lhs = lhs; self.op = op; self.rhs = rhs; self.folded = folded
    @staticmethod
    def binary(lhs, op, rhs): return Expr("binary", lhs=lhs, op=op, rhs=rhs)
    @staticmethod
    def unary(lhs, op): return Expr("unary", lhs=lhs, op=op)
    def with_folded(self, val): self.folded = int(val); return self
    def is_constant(self): return self.folded is not None
    def vars(self):
        out = []
        if self.lhs is not None: out.append(self.lhs)
        if self.rhs is not None: out.append(self.rhs)
        return out
    def __hash__(self):
        return hash((self.kind, getattr(self.lhs, "name", None), self.op,
                     getattr(self.rhs, "name", None), self.folded))
    def __eq__(self, o):
        return isinstance(o, Expr) and (self.kind, self.op, self.folded) == (o.kind, o.op, o.folded)


class AvailableExpressions:
    def __init__(self): self.out = {}
    def compute_out(self): pass
    @staticmethod
    def analyze(blocks_exprs):
        a = AvailableExpressions()
        for addr, exprs in blocks_exprs.items(): a.out[addr] = set(exprs)
        return a
    def available_at(self, block): return self.out.get(block, set())


class ConstantState:
    def __init__(self): self.values = {}
    def meet(self, other):
        out = ConstantState()
        for k in set(self.values) | set(other.values):
            a = self.values.get(k, Lattice.top()); b = other.values.get(k, Lattice.top())
            out.values[k] = a.meet(b)
        return out
    def set(self, var, val): self.values[var] = val
    def get(self, var): return self.values.get(var, Lattice.top())


class ConstantPropagation:
    def __init__(self): self.entry = {}
    @staticmethod
    def run(blocks_with_consts):
        c = ConstantPropagation()
        for addr, vals in blocks_with_consts.items():
            st = ConstantState()
            for v, n in vals.items(): st.set(v, Lattice.const(n))
            c.entry[addr] = st
        return c
    def constants_at_entry(self, block):
        st = self.entry.get(block)
        if not st: return []
        return [(v, l.const_val()) for v, l in st.values.items() if l.is_const()]


class LiveVariables:
    def __init__(self): self.live = {}; self.defs_per = {}
    def compute_live_in(self): pass
    @staticmethod
    def analyze(live_in_per_block, defs_per_block=None):
        lv = LiveVariables()
        lv.live = {a: set(s) for a, s in live_in_per_block.items()}
        lv.defs_per = defs_per_block or {}
        return lv
    def live_in(self, addr): return set(self.live.get(addr, set()))
    def dead_defs_in(self, addr):
        return [v for v in self.defs_per.get(addr, set()) if v not in self.live.get(addr, set())]


class DefUseChain:
    def __init__(self, var): self.var = var; self.defs = []; self.uses = []


class DefUseAnalysis:
    @staticmethod
    def run(defs_uses):
        chains = {}
        for var, (ds, us) in defs_uses.items():
            ch = DefUseChain(var); ch.defs = list(ds); ch.uses = list(us)
            chains[var] = ch
        return chains
    @staticmethod
    def build(defs_uses): return DefUseAnalysis.run(defs_uses)


def dead_variables(chains):
    return [v for v, ch in chains.items() if not ch.uses]


def single_const_defs(chains):
    return [(v, ch.defs[0]) for v, ch in chains.items()
            if len(ch.defs) == 1 and isinstance(ch.defs[0], int)]


# =============================================================================
# src/feature_extractor.rs
# =============================================================================

class FeatureVector:
    def __init__(self, values): self.values = list(values)
    def distance(self, other):
        return math.sqrt(sum((a - b) ** 2 for a, b in zip(self.values, other.values)))
    def cosine_similarity(self, other):
        dot = sum(a * b for a, b in zip(self.values, other.values))
        na = math.sqrt(sum(a * a for a in self.values))
        nb = math.sqrt(sum(b * b for b in other.values))
        return dot / (na * nb) if na and nb else 0.0
    def obfuscation_score(self):
        if not self.values: return 0.0
        return min(1.0, sum(abs(v) for v in self.values) / len(self.values))
    def to_table(self):
        return "\n".join(f"f{i}: {v:.4f}" for i, v in enumerate(self.values))


class FeatureNormalizer:
    def __init__(self, means=None, stds=None):
        self.means = list(means) if means else []
        self.stds = list(stds) if stds else []
    @staticmethod
    def identity(): return FeatureNormalizer()
    def normalize(self, v):
        if not self.means: return FeatureVector(list(v.values))
        out = []
        for i, x in enumerate(v.values):
            m = self.means[i] if i < len(self.means) else 0.0
            s = self.stds[i] if i < len(self.stds) else 1.0
            out.append((x - m) / (s if s else 1.0))
        return FeatureVector(out)
    @staticmethod
    def fit(vectors):
        if not vectors: return FeatureNormalizer.identity()
        dim = len(vectors[0].values)
        means = [sum(v.values[i] for v in vectors) / len(vectors) for i in range(dim)]
        stds = []
        for i in range(dim):
            var = sum((v.values[i] - means[i]) ** 2 for v in vectors) / len(vectors)
            stds.append(math.sqrt(var))
        return FeatureNormalizer(means, stds)


class FeatureExtractor:
    def __init__(self, normalizer=None):
        self.normalizer = normalizer or FeatureNormalizer.identity()
    @staticmethod
    def new(): return FeatureExtractor()
    @staticmethod
    def with_normalizer(normalizer): return FeatureExtractor(normalizer)
    def extract(self, data):
        return self.normalizer.normalize(FeatureExtractor.extract_raw(data))
    @staticmethod
    def extract_raw(data: bytes):
        if not data: return FeatureVector([0.0] * 5)
        e = EntropyAnalyzer.entropy(data)
        printable = sum(1 for b in data if 32 <= b < 127) / len(data)
        nop = data.count(0x90) / len(data)
        zero = data.count(0) / len(data)
        ff = data.count(0xFF) / len(data)
        return FeatureVector([e, printable, nop, zero, ff])


def extract_windows(data: bytes, window_size: int, step: int):
    if window_size == 0 or step == 0: return []
    return [FeatureExtractor.extract_raw(data[s:s + window_size])
            for s in range(0, max(1, len(data) - window_size + 1), step)]


def mean_feature_vector(vectors):
    if not vectors: return FeatureVector([])
    dim = len(vectors[0].values)
    return FeatureVector([sum(v.values[i] for v in vectors) / len(vectors) for i in range(dim)])


# =============================================================================
# src/deobf_oracle.rs
# =============================================================================

class XorStrategy:
    def __init__(self, key): self.key = key & 0xFF
    @staticmethod
    def new(key): return XorStrategy(key)
    def name(self): return f"xor_{self.key:02x}"
    def apply(self, data): return bytes(b ^ self.key for b in data)


class AddStrategy:
    def __init__(self, delta): self.delta = delta & 0xFF
    @staticmethod
    def new(delta): return AddStrategy(delta)
    def name(self): return f"add_{self.delta:02x}"
    def apply(self, data): return bytes((b + self.delta) & 0xFF for b in data)


class RotStrategy:
    def __init__(self, rotation): self.rotation = rotation & 7
    @staticmethod
    def new(rotation): return RotStrategy(rotation)
    def name(self): return f"rot_{self.rotation}"
    def apply(self, data):
        r = self.rotation
        return bytes(((b << r) | (b >> (8 - r))) & 0xFF for b in data)


class OracleResult:
    def __init__(self, strategy_name, output, score_value):
        self.strategy_name = strategy_name; self.output = bytes(output); self._score = score_value
    def score(self): return self._score
    def is_good(self, threshold): return self._score >= threshold


class OracleConfig:
    def __init__(self):
        self.min_quality = 0.0; self.top_k = None
    @staticmethod
    def unlimited(): return OracleConfig()
    def with_min_quality(self, q): self.min_quality = q; return self
    def with_top_k(self, k): self.top_k = int(k); return self


class DeobfOracle:
    def __init__(self):
        self.strategies = []
        self.cfg = OracleConfig.unlimited()
        self._scorer = EntropyScorer.new()
    @staticmethod
    def new():
        o = DeobfOracle(); o.register_defaults(); return o
    @staticmethod
    def empty(): return DeobfOracle()
    def with_config(self, cfg): self.cfg = cfg; return self
    def register(self, s): self.strategies.append(s)
    def register_defaults(self):
        for k in (0x42, 0xAA, 0xFF): self.register(XorStrategy.new(k))
        self.register(AddStrategy.new(1))
        self.register(RotStrategy.new(3))
    def query(self, input_b):
        out = []
        for s in self.strategies:
            decoded = s.apply(input_b)
            sc = quality_score(decoded)
            if sc >= self.cfg.min_quality:
                out.append(OracleResult(s.name(), decoded, sc))
        out.sort(key=lambda r: r.score(), reverse=True)
        if self.cfg.top_k is not None: out = out[: self.cfg.top_k]
        return out
    def best(self, input_b):
        rs = self.query(input_b)
        return rs[0] if rs else None
    def strategy_count(self): return len(self.strategies)
    def scorer(self): return self._scorer
    def config(self): return self.cfg


class CachedOracle:
    def __init__(self, capacity, oracle=None):
        self.capacity = capacity; self.cache = {}
        self.oracle_ = oracle or DeobfOracle.new()
    @staticmethod
    def new(capacity): return CachedOracle(capacity)
    @staticmethod
    def from_oracle(oracle, capacity): return CachedOracle(capacity, oracle)
    def best(self, input_b):
        key = hashlib.sha256(input_b).hexdigest()
        if key in self.cache: return self.cache[key]
        r = self.oracle_.best(input_b)
        if len(self.cache) >= self.capacity: self.cache.pop(next(iter(self.cache)))
        self.cache[key] = r
        return r
    def cache_size(self): return len(self.cache)
    def clear_cache(self): self.cache.clear()
    def oracle(self): return self.oracle_


# =============================================================================
# src/entropy_scorer.rs
# =============================================================================

class EntropyScorer:
    @staticmethod
    def new(): return EntropyScorer()
    @staticmethod
    def shannon_entropy(data): return EntropyAnalyzer.entropy(data)


class PrintableScorer:
    def __init__(self, target=0.7): self.target = target
    @staticmethod
    def new(): return PrintableScorer()
    @staticmethod
    def with_target(target_ratio): return PrintableScorer(target_ratio)
    @staticmethod
    def printable_count(data): return sum(1 for b in data if 32 <= b < 127)
    @staticmethod
    def printable_ratio(data):
        return PrintableScorer.printable_count(data) / len(data) if data else 0.0


class StructureHit:
    def __init__(self, offset, length, kind):
        self.offset = offset; self.length = length; self.kind = kind


class StructureScorer:
    @staticmethod
    def new(): return StructureScorer()
    @staticmethod
    def detect_structures(data: bytes):
        hits = []
        if data[:2] == b"MZ": hits.append(StructureHit(0, 2, "mz"))
        for m in re.finditer(b"PE\x00\x00", data):
            hits.append(StructureHit(m.start(), 4, "pe"))
        if data[:4] == b"\x7fELF": hits.append(StructureHit(0, 4, "elf"))
        return hits


class CompositeScore:
    def __init__(self, total, components):
        self.total = total; self.components = dict(components)
    def is_good(self, threshold): return self.total >= threshold
    def component(self, name): return self.components.get(name)
    def tier(self):
        if self.total >= 0.9: return "very high"
        if self.total >= 0.75: return "high"
        if self.total >= 0.5: return "medium"
        if self.total > 0.0: return "low"
        return "none"


class CompositeScorer:
    def __init__(self): self.metrics = []
    @staticmethod
    def new():
        s = CompositeScorer()
        s.add_metric(("entropy", lambda d: 1.0 - abs(EntropyAnalyzer.entropy(d) - 5.5) / 5.5))
        s.add_metric(("printable", lambda d: PrintableScorer.printable_ratio(d)))
        return s
    @staticmethod
    def empty(): return CompositeScorer()
    def add_metric(self, metric): self.metrics.append(metric)
    def score(self, data):
        comps = {}; total = 0.0
        for m in self.metrics:
            if isinstance(m, tuple):
                name, fn = m; v = float(fn(data))
            else:
                name = m.name() if callable(getattr(m, "name", None)) else "metric"
                v = float(m.score(data))
            comps[name] = v; total += v
        if self.metrics: total /= len(self.metrics)
        return CompositeScore(total, comps)
    def is_better(self, a, b): return self.score(a).total > self.score(b).total
    def metric_count(self): return len(self.metrics)


class ScoreHistory:
    def __init__(self, capacity): self.capacity = capacity; self.values = []
    @staticmethod
    def new(capacity): return ScoreHistory(capacity)
    def push(self, score):
        self.values.append(score)
        if len(self.values) > self.capacity: self.values.pop(0)
    def latest(self): return self.values[-1] if self.values else None
    def best(self): return max(self.values) if self.values else None
    def average(self):
        return sum(self.values) / len(self.values) if self.values else 0.0
    def is_improving(self):
        return len(self.values) >= 2 and self.values[-1] > self.values[-2]
    def is_stagnant(self, window, delta):
        if len(self.values) < window: return False
        recent = self.values[-window:]
        return (max(recent) - min(recent)) < delta
    def len(self): return len(self.values)
    def is_empty(self): return not self.values
    def clear(self): self.values.clear()
    def all(self): return list(self.values)


if __name__ == "__main__":
    sample = bytes(range(256)) * 4
    an = MhcdeOrchestrator.new().analyze(sample)
    print(json.dumps({
        "findings": an.total_findings(),
        "tier": an.score.confidence_tier(),
        "entropy": EntropyAnalyzer.entropy(sample),
        "natural": naturalness_score(sample),
    }, indent=2))
