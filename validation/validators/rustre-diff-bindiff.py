#!/usr/bin/env python3
"""Independent Python validator for crate rustre-diff-bindiff.

Reimplements pure-math logic from the crate using only stdlib so results can be
compared against the Rust implementation.

Usage:
  echo '{"fn":"hash_linear","input":{"block_count":5}}' | python rustre-diff-bindiff.py
  python rustre-diff-bindiff.py            # runs main() self-tests
"""
import json
import math
import sys
import zlib

# ---------- FNV-1a 64 ----------
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME = 0x100000001b3
MASK64 = (1 << 64) - 1


def fnv1a_u64(data: bytes) -> int:
    h = FNV_OFFSET
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & MASK64
    return h


def fnv1a_mix_u64(h: int, val: int) -> int:
    """Mimic Rust's Hasher::write_u64 for FNV: feed 8 little-endian bytes."""
    for i in range(8):
        h ^= (val >> (8 * i)) & 0xFF
        h = (h * FNV_PRIME) & MASK64
    return h


# ---------- CfgHasher ----------
def validator_hash_linear(input):
    """FNV-1a over the integer sequence 0..block_count (each as u64 LE)."""
    n = int(input["block_count"])
    h = FNV_OFFSET
    for i in range(n):
        h = fnv1a_mix_u64(h, i)
    return {"hash": h}


def _wl_hash(adjacency, iterations: int) -> int:
    # adjacency: list of [node_id, [succ_ids...]]
    # Initial labels: degree (out-degree as in crate)
    labels = {}
    succs = {}
    for entry in adjacency:
        nid, sl = entry[0], entry[1]
        succs[int(nid)] = [int(x) for x in sl]
        labels[int(nid)] = len(sl)

    for _ in range(iterations):
        new_labels = {}
        for nid in succs:
            neigh = sorted(labels.get(s, 0) for s in succs[nid])
            h = FNV_OFFSET
            h = fnv1a_mix_u64(h, labels[nid])
            for v in neigh:
                h = fnv1a_mix_u64(h, v)
            new_labels[nid] = h
        labels = new_labels

    # Final aggregation: sort labels and FNV-mix all of them
    final = FNV_OFFSET
    for v in sorted(labels.values()):
        final = fnv1a_mix_u64(final, v)
    return final


def validator_hash_cfg(input):
    return {"hash": _wl_hash(input["adjacency"], 3)}


def validator_wl_hash(input):
    return {"hash": _wl_hash(input["adjacency"], int(input["iterations"]))}


# ---------- FunctionFeatures.similarity ----------
def _ratio_prox(a: float, b: float) -> float:
    if a == 0 and b == 0:
        return 1.0
    mn, mx = min(a, b), max(a, b)
    if mx == 0:
        return 0.0
    return mn / mx


def validator_features_similarity(input):
    a = input["a"]
    b = input["b"]
    cfg_eq = 1.0 if a.get("cfg_hash") == b.get("cfg_hash") and a.get("cfg_hash") is not None else 0.0
    bb_prox = _ratio_prox(a.get("bb_count", 0), b.get("bb_count", 0))
    ins_prox = _ratio_prox(a.get("instr_count", 0), b.get("instr_count", 0))
    edge_prox = _ratio_prox(a.get("edge_count", 0), b.get("edge_count", 0))
    loop_eq = 1.0 if a.get("loop_count", 0) == b.get("loop_count", 0) else 0.0
    sa = set(a.get("strings", []))
    sb = set(b.get("strings", []))
    if not sa and not sb:
        jacc = 1.0
    else:
        u = sa | sb
        jacc = (len(sa & sb) / len(u)) if u else 0.0
    score = (0.40 * cfg_eq + 0.20 * bb_prox + 0.15 * ins_prox +
             0.10 * edge_prox + 0.10 * loop_eq + 0.05 * jacc)
    return {"similarity": max(0.0, min(1.0, score))}


def validator_can_match(input):
    a, b = input["a"], input["b"]
    def ratio_ok(x, y):
        if x == 0 and y == 0:
            return True
        if x == 0 or y == 0:
            return False
        return max(x, y) / min(x, y) <= 5.0
    ok = ratio_ok(a.get("bb_count", 0), b.get("bb_count", 0)) and \
         ratio_ok(a.get("instr_count", 0), b.get("instr_count", 0))
    return {"can_match": ok}


# ---------- MatchKind ----------
MATCHKIND_PRIORITY = {
    "ExactHash": 10,
    "NameMatch": 9,
    "CfgHash": 8,
    "ManualMatch": 7,
    "CallGraphPropagation": 5,
    "Heuristic": 1,
}
MATCHKIND_RELIABLE = {"ExactHash", "NameMatch"}


def validator_matchkind(input):
    k = input["kind"]
    return {
        "priority": MATCHKIND_PRIORITY[k],
        "is_reliable": k in MATCHKIND_RELIABLE,
    }


# ---------- FunctionMatch ----------
def validator_quality_label(input):
    sim = float(input["similarity"])
    conf = float(input.get("confidence", 1.0))
    if sim >= 0.99:
        label = "Identical"
    elif sim >= 0.75:
        label = "Good"
    elif sim >= 0.5:
        label = "Partial"
    else:
        label = "Poor"
    return {
        "label": label,
        "is_identical": sim >= 0.99,
        "is_good_match": sim >= 0.75 and conf >= 0.75,
    }


# ---------- Hungarian-matcher: md_index + similarity_score ----------
PRIMES_8 = [2, 3, 5, 7, 11, 13, 17, 19]


def validator_md_index_from_features(input):
    """md_index via prime-product over 8 features."""
    feats = [
        int(input.get("bb_count", 0)),
        int(input.get("instr_count", 0)),
        int(input.get("edge_count", 0)),
        int(input.get("loop_count", 0)),
        int(input.get("in_edges", 0)),
        int(input.get("out_edges", 0)),
        int(input.get("call_count", 0)),
        int(input.get("string_count", 0)),
    ]
    prod = 1.0
    for p, f in zip(PRIMES_8, feats):
        prod *= math.pow(p, f)
    return {"md_index": prod}


def _md_sim(a: float, b: float) -> float:
    if a <= 0 or b <= 0:
        return 0.0
    avg = (a + b) / 2.0
    rel = abs(a - b) / avg
    return math.exp(-rel * math.log(10.0))


def _cfg_topology_sim(a, b):
    parts = [
        _ratio_prox(a.get("in_edges", 0), b.get("in_edges", 0)),
        _ratio_prox(a.get("out_edges", 0), b.get("out_edges", 0)),
        _ratio_prox(a.get("bb_count", 0), b.get("bb_count", 0)),
    ]
    return sum(parts) / 3.0


def validator_similarity_score(input):
    a, b = input["a"], input["b"]
    name_eq = 1.0 if a.get("name") and a.get("name") == b.get("name") else 0.0
    crc_eq = 1.0 if a.get("bytes_crc32") is not None and a.get("bytes_crc32") == b.get("bytes_crc32") else 0.0
    cfg = _cfg_topology_sim(a, b)
    md = _md_sim(float(a.get("md_index", 0.0)), float(b.get("md_index", 0.0)))
    return {"score": 0.40 * name_eq + 0.30 * crc_eq + 0.20 * cfg + 0.10 * md}


def validator_cfg_topology_similarity(input):
    return {"score": _cfg_topology_sim(input["a"], input["b"])}


def validator_md_index_similarity(input):
    return {"score": _md_sim(float(input["a"]), float(input["b"]))}


def validator_bytes_crc32(input):
    data = bytes(input["bytes"])
    return {"crc32": zlib.crc32(data) & 0xFFFFFFFF}


# ---------- detailed_similarity (BinDiffer) ----------
def validator_detailed_similarity(input):
    base = validator_features_similarity(input)["similarity"]
    a, b = input["a"], input["b"]
    if a.get("byte_hash") is not None and a.get("byte_hash") == b.get("byte_hash"):
        base += 0.05
    cc_a = a.get("cyclomatic_complexity", 0)
    cc_b = b.get("cyclomatic_complexity", 0)
    if cc_a > 0 and cc_b > 0:
        ratio = max(cc_a, cc_b) / min(cc_a, cc_b)
        if ratio > 3.0:
            base -= 0.1
    return {"similarity": max(0.0, min(1.0, base))}


# ---------- dispatch ----------
DISPATCH = {
    "hash_linear": validator_hash_linear,
    "hash_cfg": validator_hash_cfg,
    "wl_hash": validator_wl_hash,
    "features_similarity": validator_features_similarity,
    "can_match": validator_can_match,
    "matchkind": validator_matchkind,
    "quality_label": validator_quality_label,
    "md_index_from_features": validator_md_index_from_features,
    "similarity_score": validator_similarity_score,
    "cfg_topology_similarity": validator_cfg_topology_similarity,
    "md_index_similarity": validator_md_index_similarity,
    "bytes_crc32": validator_bytes_crc32,
    "detailed_similarity": validator_detailed_similarity,
}


def main():
    if not sys.stdin.isatty():
        data = sys.stdin.read().strip()
        if data:
            req = json.loads(data)
            fn = req["fn"]
            out = DISPATCH[fn](req.get("input", {}))
            print(json.dumps(out))
            return

    # Self-tests with fixed inputs
    results = {
        "hash_linear(5)": validator_hash_linear({"block_count": 5}),
        "hash_cfg(triangle)": validator_hash_cfg({"adjacency": [[0, [1, 2]], [1, [2]], [2, []]]}),
        "wl_hash(triangle,1)": validator_wl_hash({"adjacency": [[0, [1, 2]], [1, [2]], [2, []]], "iterations": 1}),
        "features_sim_identical": validator_features_similarity({
            "a": {"cfg_hash": 1, "bb_count": 5, "instr_count": 20, "edge_count": 6, "loop_count": 1, "strings": ["x"]},
            "b": {"cfg_hash": 1, "bb_count": 5, "instr_count": 20, "edge_count": 6, "loop_count": 1, "strings": ["x"]},
        }),
        "can_match_5x": validator_can_match({"a": {"bb_count": 1, "instr_count": 1}, "b": {"bb_count": 6, "instr_count": 6}}),
        "matchkind_Exact": validator_matchkind({"kind": "ExactHash"}),
        "quality_label(0.99)": validator_quality_label({"similarity": 0.99}),
        "md_index": validator_md_index_from_features({"bb_count": 2, "instr_count": 3}),
        "similarity_score_name": validator_similarity_score({
            "a": {"name": "foo", "bytes_crc32": 1, "in_edges": 1, "out_edges": 2, "bb_count": 3, "md_index": 6.0},
            "b": {"name": "foo", "bytes_crc32": 1, "in_edges": 1, "out_edges": 2, "bb_count": 3, "md_index": 6.0},
        }),
        "md_sim_equal": validator_md_index_similarity({"a": 6.0, "b": 6.0}),
        "crc32_empty": validator_bytes_crc32({"bytes": []}),
    }
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
