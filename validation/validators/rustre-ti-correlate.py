"""
Validators for rustre-ti-correlate crate.
Each validator_NAME(input) -> output mirrors the documented public API.
Uses Python stdlib only.
"""

import math
import json
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Helpers / minimal data classes
# ---------------------------------------------------------------------------

def _jaccard(a: set, b: set) -> float:
    u = a | b
    if not u:
        return 0.0
    return len(a & b) / len(u)


def _mean(xs):
    if not xs:
        return 0.0
    return sum(xs) / len(xs)


def _std(xs):
    if len(xs) < 2:
        return 0.0
    m = _mean(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / len(xs))


# ---------------------------------------------------------------------------
# Free functions (pub fn at module level)
# ---------------------------------------------------------------------------

def validator_deduplicate_iocs(iocs: List[Dict]) -> List[Dict]:
    """Removes duplicate IoCs by type+value."""
    seen = set()
    result = []
    for ioc in iocs:
        key = (ioc.get("kind") or ioc.get("type", ""), ioc.get("value", ""))
        if key not in seen:
            seen.add(key)
            result.append(ioc)
    return result


def validator_correlate_across_sources(sources: List[List[Dict]]) -> Dict:
    """
    Correlates IoCs from multiple sources, computes overlap.
    Returns CorrelationResult: {ioc_counts: {key: count}, max_source_count: int}
    """
    counts: Dict[Tuple, int] = defaultdict(int)
    ioc_map: Dict[Tuple, Dict] = {}
    for source in sources:
        # deduplicate within each source before counting
        seen_in_source = set()
        for ioc in source:
            key = (ioc.get("kind") or ioc.get("type", ""), ioc.get("value", ""))
            if key not in seen_in_source:
                seen_in_source.add(key)
                counts[key] += 1
                ioc_map[key] = ioc
    max_count = max(counts.values(), default=0)
    return {
        "ioc_counts": {f"{k[0]}:{k[1]}": v for k, v in counts.items()},
        "iocs": list(ioc_map.values()),
        "max_source_count": max_count,
    }


def validator_cluster_by_campaign(iocs: List[Dict], ttps: List[Dict]) -> List[Dict]:
    """
    Groups IoCs into campaign clusters based on shared TTPs.
    Each IoC may carry 'ttps' list; clusters share at least one TTP.
    """
    ttp_ids = {t.get("id") or t.get("technique_id", "") for t in ttps}

    # Group IoCs by their TTP set intersection with provided TTPs
    clusters: Dict[frozenset, List[Dict]] = defaultdict(list)
    for ioc in iocs:
        ioc_ttps = frozenset(ioc.get("ttps", [])) & ttp_ids
        if not ioc_ttps:
            ioc_ttps = frozenset(["__uncategorised__"])
        clusters[ioc_ttps].append(ioc)

    result = []
    for ttp_set, members in clusters.items():
        result.append({
            "ttps": list(ttp_set),
            "iocs": members,
            "size": len(members),
        })
    return result


def validator_timeline(events: List[Dict], window_secs: int) -> List[Dict]:
    """
    Builds a timeline of threat events with temporal windowing.
    events: list of {timestamp: int, ...}
    Returns list of TimelineEntry {window_start, window_end, events}.
    """
    if not events:
        return []
    sorted_evts = sorted(events, key=lambda e: e.get("timestamp", 0))
    entries = []
    bucket: List[Dict] = []
    win_start = sorted_evts[0].get("timestamp", 0)
    for evt in sorted_evts:
        ts = evt.get("timestamp", 0)
        if ts <= win_start + window_secs:
            bucket.append(evt)
        else:
            entries.append({
                "window_start": win_start,
                "window_end": win_start + window_secs,
                "events": bucket,
            })
            win_start = ts
            bucket = [evt]
    if bucket:
        entries.append({
            "window_start": win_start,
            "window_end": win_start + window_secs,
            "events": bucket,
        })
    return entries


def validator_score_ioc(ioc: Dict, context: Dict) -> float:
    """
    Assigns a relevance score to an IoC in the current context.
    context keys: campaign_ids, known_actors, active_ttps.
    """
    score = 0.0
    ioc_campaigns = set(ioc.get("campaigns", []))
    ctx_campaigns = set(context.get("campaign_ids", []))
    if ioc_campaigns & ctx_campaigns:
        score += 0.4

    ioc_actors = set(ioc.get("actors", []))
    ctx_actors = set(context.get("known_actors", []))
    if ioc_actors & ctx_actors:
        score += 0.3

    ioc_ttps = set(ioc.get("ttps", []))
    ctx_ttps = set(context.get("active_ttps", []))
    if ioc_ttps & ctx_ttps:
        score += 0.3

    confidence = float(ioc.get("confidence", 1.0))
    return min(1.0, score * confidence)


def validator_build_campaign_timeline(campaign: Dict, samples: List[Dict]) -> Dict:
    """
    Builds the activity timeline for a campaign.
    campaign: {id, name}; samples: [{campaign_id, timestamp, ...}]
    Returns {campaign_id, events: [{timestamp, sample_id}]}
    """
    cid = campaign.get("id") or campaign.get("name", "")
    events = [
        {"timestamp": s.get("timestamp", 0), "sample_id": s.get("id", "")}
        for s in samples
        if s.get("campaign_id") == cid
    ]
    events.sort(key=lambda e: e["timestamp"])
    return {"campaign_id": cid, "events": events}


def validator_monthly_pulse(campaign: Dict, samples: List[Dict]) -> List[Tuple[str, int]]:
    """
    Returns monthly sample count for a campaign.
    Returns list of (YYYY-MM, count) sorted chronologically.
    """
    import datetime
    cid = campaign.get("id") or campaign.get("name", "")
    monthly: Dict[str, int] = defaultdict(int)
    for s in samples:
        if s.get("campaign_id") != cid:
            continue
        ts = s.get("timestamp", 0)
        dt = datetime.datetime.utcfromtimestamp(ts)
        key = f"{dt.year:04d}-{dt.month:02d}"
        monthly[key] += 1
    return sorted(monthly.items())


def validator_score_attribution(signals: List[Dict], actors: List[Dict]) -> List[Dict]:
    """
    Calculates aggregated attribution score given signals and actors.
    Returns list of {actor_id, score} sorted descending.
    """
    results = []
    for actor in actors:
        actor_ttps = set(actor.get("ttps", []))
        actor_families = set(actor.get("families", []))
        actor_iocs = set(actor.get("iocs", []))
        total = 0.0
        for sig in signals:
            w = float(sig.get("weight", 1.0))
            if sig.get("kind") == "ttp" and sig.get("value") in actor_ttps:
                total += 0.4 * w
            elif sig.get("kind") == "family" and sig.get("value") in actor_families:
                total += 0.35 * w
            elif sig.get("kind") == "ioc" and sig.get("value") in actor_iocs:
                total += 0.25 * w
        results.append({"actor_id": actor.get("id", ""), "score": total})
    results.sort(key=lambda x: x["score"], reverse=True)
    return results


def validator_pearson_correlation(ts_a: Dict, ts_b: Dict) -> float:
    """
    Pearson correlation coefficient between two time series.
    ts: {buckets: {timestamp: count}}
    """
    keys = sorted(set(ts_a.get("buckets", {}).keys()) | set(ts_b.get("buckets", {}).keys()))
    if len(keys) < 2:
        return 0.0
    xs = [float(ts_a["buckets"].get(k, 0)) for k in keys]
    ys = [float(ts_b["buckets"].get(k, 0)) for k in keys]
    mx, my = _mean(xs), _mean(ys)
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den = math.sqrt(sum((x - mx) ** 2 for x in xs) * sum((y - my) ** 2 for y in ys))
    if den == 0.0:
        return 0.0
    return num / den


def validator_cluster_by_ttps(reports: List[Dict], min_jaccard: float) -> Dict:
    """
    Groups reports into campaigns by Jaccard TTP similarity.
    Returns CampaignTracker: {campaigns: [{members, ttps}], ...}
    """
    n = len(reports)
    clusters: List[List[int]] = []
    assigned = [False] * n

    for i in range(n):
        if assigned[i]:
            continue
        cluster = [i]
        assigned[i] = True
        ttps_i = set(reports[i].get("ttps", []))
        for j in range(i + 1, n):
            if assigned[j]:
                continue
            ttps_j = set(reports[j].get("ttps", []))
            if _jaccard(ttps_i, ttps_j) >= min_jaccard:
                cluster.append(j)
                assigned[j] = True
        clusters.append(cluster)

    campaigns = []
    for cl in clusters:
        all_ttps: set = set()
        for idx in cl:
            all_ttps |= set(reports[idx].get("ttps", []))
        campaigns.append({
            "members": [reports[idx].get("id", str(idx)) for idx in cl],
            "ttps": list(all_ttps),
            "size": len(cl),
        })
    return {"campaigns": campaigns, "min_jaccard": min_jaccard}


def validator_label_propagation(graph: Dict, max_iter: int) -> Dict[str, int]:
    """
    Label propagation for community detection on IoC graph.
    graph: {nodes: [id,...], edges: [{src, dst},...]}
    Returns {node_id: community_label}.
    """
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    labels: Dict[str, int] = {n: i for i, n in enumerate(nodes)}
    adj: Dict[str, List[str]] = defaultdict(list)
    for e in edges:
        adj[e["src"]].append(e["dst"])
        adj[e["dst"]].append(e["src"])

    for _ in range(max_iter):
        changed = False
        for node in nodes:
            neighbors = adj[node]
            if not neighbors:
                continue
            freq: Dict[int, int] = defaultdict(int)
            for nb in neighbors:
                freq[labels[nb]] += 1
            best = max(freq, key=lambda k: freq[k])
            if labels[node] != best:
                labels[node] = best
                changed = True
        if not changed:
            break
    return labels


def validator_build_communities(graph: Dict, labels: Dict[str, int]) -> List[Dict]:
    """
    Builds Community structures from assigned labels.
    Returns list of {label, members}.
    """
    groups: Dict[int, List[str]] = defaultdict(list)
    for node, label in labels.items():
        groups[label].append(node)
    return [{"label": lbl, "members": mems, "size": len(mems)}
            for lbl, mems in sorted(groups.items())]


def validator_graph_stats(graph: Dict) -> Dict:
    """
    Aggregate statistics of the IoC graph (nodes, edges, density).
    graph: {nodes: [...], edges: [...]}
    """
    n = len(graph.get("nodes", []))
    e = len(graph.get("edges", []))
    max_edges = n * (n - 1) if n > 1 else 1
    density = e / max_edges if max_edges > 0 else 0.0
    return {"node_count": n, "edge_count": e, "density": density}


def validator_to_dot(graph: Dict) -> str:
    """
    Serializes the IoC graph to Graphviz DOT format.
    """
    lines = ["digraph ioc_graph {"]
    for node in graph.get("nodes", []):
        nid = str(node).replace('"', '\\"')
        lines.append(f'  "{nid}";')
    for edge in graph.get("edges", []):
        src = str(edge["src"]).replace('"', '\\"')
        dst = str(edge["dst"]).replace('"', '\\"')
        label = edge.get("label", "")
        lines.append(f'  "{src}" -> "{dst}" [label="{label}"];')
    lines.append("}")
    return "\n".join(lines)


def validator_tlsh_distance(hash_a: str, hash_b: str) -> Optional[int]:
    """
    TLSH distance between two fuzzy hashes; None if parse fails.
    Simplified: treats hashes as hex strings and computes nibble-wise distance.
    """
    try:
        if not hash_a or not hash_b:
            return None
        # Strip common TLSH prefix 'T1'
        a = hash_a.upper().lstrip("T1")
        b = hash_b.upper().lstrip("T1")
        if len(a) != len(b) or not a:
            return None
        dist = sum(abs(int(ca, 16) - int(cb, 16)) for ca, cb in zip(a, b))
        return dist
    except (ValueError, TypeError):
        return None


def validator_import_jaccard(imports_a: List[str], imports_b: List[str]) -> float:
    """Jaccard similarity of import sets of two samples."""
    return _jaccard(set(imports_a), set(imports_b))


def validator_section_entropy_similarity(entropy_a: List[float], entropy_b: List[float]) -> float:
    """
    Similarity between section entropy vectors.
    Uses cosine similarity; returns 0 if lengths differ or vectors are zero.
    """
    if len(entropy_a) != len(entropy_b) or not entropy_a:
        return 0.0
    dot = sum(a * b for a, b in zip(entropy_a, entropy_b))
    mag_a = math.sqrt(sum(x ** 2 for x in entropy_a))
    mag_b = math.sqrt(sum(x ** 2 for x in entropy_b))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


def validator_string_overlap_score(strings_a: List[str], strings_b: List[str]) -> float:
    """Overlap score for extracted strings of two samples (Jaccard)."""
    return _jaccard(set(strings_a), set(strings_b))


def validator_correlate_pair(sample_a: Dict, sample_b: Dict, weights: Dict) -> Dict:
    """
    Full correlation between two samples (TLSH + imphash + entropy + strings).
    weights: {tlsh, imphash, entropy, strings} (floats, should sum to 1.0)
    Returns SampleCorrelation: {score, tlsh_dist, imphash_match, entropy_sim, string_overlap}
    """
    w_tlsh = float(weights.get("tlsh", 0.3))
    w_imp = float(weights.get("imphash", 0.3))
    w_ent = float(weights.get("entropy", 0.2))
    w_str = float(weights.get("strings", 0.2))

    tlsh_dist = validator_tlsh_distance(
        sample_a.get("tlsh", ""), sample_b.get("tlsh", "")
    )
    tlsh_score = 0.0
    if tlsh_dist is not None:
        tlsh_score = max(0.0, 1.0 - tlsh_dist / 300.0)

    imphash_match = (
        sample_a.get("imphash", None) is not None
        and sample_a.get("imphash") == sample_b.get("imphash")
    )
    imp_score = 1.0 if imphash_match else 0.0

    entropy_sim = validator_section_entropy_similarity(
        sample_a.get("section_entropies", []),
        sample_b.get("section_entropies", []),
    )
    string_overlap = validator_string_overlap_score(
        sample_a.get("strings", []), sample_b.get("strings", [])
    )

    score = (
        w_tlsh * tlsh_score
        + w_imp * imp_score
        + w_ent * entropy_sim
        + w_str * string_overlap
    )
    return {
        "score": round(score, 6),
        "tlsh_dist": tlsh_dist,
        "imphash_match": imphash_match,
        "entropy_similarity": entropy_sim,
        "string_overlap": string_overlap,
    }


def validator_cluster_by_imphash(samples: List[Dict]) -> Dict[str, List[int]]:
    """Groups samples by identical imphash. Returns {imphash: [indices]}."""
    groups: Dict[str, List[int]] = defaultdict(list)
    for i, s in enumerate(samples):
        ih = s.get("imphash")
        if ih:
            groups[ih].append(i)
    return dict(groups)


def validator_cluster_samples(distance_matrix: List[List[float]], threshold: float) -> List[Dict]:
    """
    Hierarchical single-linkage clustering on distance matrix.
    Returns list of {members: [indices], max_dist: float}.
    """
    n = len(distance_matrix)
    assigned = [-1] * n
    clusters = []
    cluster_id = 0

    for i in range(n):
        if assigned[i] != -1:
            continue
        members = [i]
        assigned[i] = cluster_id
        queue = deque([i])
        while queue:
            cur = queue.popleft()
            for j in range(n):
                if assigned[j] == -1 and distance_matrix[cur][j] <= threshold:
                    assigned[j] = cluster_id
                    members.append(j)
                    queue.append(j)
        max_d = 0.0
        for a in members:
            for b in members:
                max_d = max(max_d, distance_matrix[a][b])
        clusters.append({"members": members, "max_dist": max_d})
        cluster_id += 1
    return clusters


def validator_correlate_samples(
    samples: List[Dict], weights: Dict
) -> Tuple[List[List[float]], List[Dict]]:
    """
    Full pipeline: distance matrix + clusters for a set of samples.
    Returns (distance_matrix, clusters).
    """
    n = len(samples)
    dm = [[0.0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            if i == j:
                dm[i][j] = 0.0
            elif j < i:
                dm[i][j] = dm[j][i]
            else:
                corr = validator_correlate_pair(samples[i], samples[j], weights)
                dm[i][j] = round(1.0 - corr["score"], 6)

    threshold = float(weights.get("cluster_threshold", 0.5))
    clusters = validator_cluster_samples(dm, threshold)
    return dm, clusters


def validator_features_from_ioc(ioc: Dict) -> List[Dict]:
    """
    Extracts behavioral features from an IoC for clustering.
    Returns list of {kind, value} behavioral features.
    """
    features = []
    kind = ioc.get("kind") or ioc.get("type", "")
    value = ioc.get("value", "")

    features.append({"kind": "ioc_type", "value": kind})

    for tag in ioc.get("tags", []):
        features.append({"kind": "tag", "value": tag})

    for ttp in ioc.get("ttps", []):
        features.append({"kind": "ttp", "value": ttp})

    for actor in ioc.get("actors", []):
        features.append({"kind": "actor", "value": actor})

    # Domain-level feature
    if kind in ("domain", "fqdn") and "." in value:
        tld = value.rsplit(".", 1)[-1]
        features.append({"kind": "tld", "value": tld})

    return features


# ---------------------------------------------------------------------------
# Struct-level methods (as standalone validators)
# ---------------------------------------------------------------------------

# --- ThreatCorrelator ---

def validator_ThreatCorrelator_add_ioc(state: Dict, ioc: Dict) -> Dict:
    """Adds an IoC to the correlator state."""
    state.setdefault("iocs", []).append(ioc)
    return state


def validator_ThreatCorrelator_add_report(state: Dict, report: Dict) -> Dict:
    """Ingests a threat report into the correlator state."""
    state.setdefault("reports", []).append(report)
    return state


def validator_ThreatCorrelator_correlate_all(state: Dict) -> List[Dict]:
    """Generates all available correlations from state."""
    iocs = state.get("iocs", [])
    correlations = []
    for i, a in enumerate(iocs):
        for j, b in enumerate(iocs):
            if j <= i:
                continue
            shared = set(a.get("tags", [])) & set(b.get("tags", []))
            shared |= set(a.get("ttps", [])) & set(b.get("ttps", []))
            if shared:
                correlations.append({
                    "ioc_a": a.get("value"),
                    "ioc_b": b.get("value"),
                    "shared": list(shared),
                    "confidence": min(100, len(shared) * 20),
                })
    return correlations


def validator_ThreatCorrelator_find_related(state: Dict, ioc: Dict) -> List[Dict]:
    """Finds correlations for a specific IoC."""
    all_corr = validator_ThreatCorrelator_correlate_all(state)
    val = ioc.get("value")
    return [c for c in all_corr if c["ioc_a"] == val or c["ioc_b"] == val]


def validator_ThreatCorrelator_cluster_by_family(state: Dict) -> Dict[str, List[Dict]]:
    """Groups IoCs by malware family."""
    groups: Dict[str, List[Dict]] = defaultdict(list)
    for ioc in state.get("iocs", []):
        family = ioc.get("family", "unknown")
        groups[family].append(ioc)
    return dict(groups)


def validator_ThreatCorrelator_high_confidence_correlations(
    state: Dict, min_confidence: int
) -> List[Dict]:
    """Filters correlations above confidence threshold."""
    return [
        c for c in validator_ThreatCorrelator_correlate_all(state)
        if c.get("confidence", 0) >= min_confidence
    ]


# --- CorrelationGraph ---

def validator_CorrelationGraph_new() -> Dict:
    """Creates an empty correlation graph."""
    return {"nodes": {}, "edges": []}


def validator_CorrelationGraph_add_correlation(graph: Dict, src: str, dst: str, rel: str) -> Dict:
    """Adds a correlation edge."""
    graph["nodes"][src] = True
    graph["nodes"][dst] = True
    graph["edges"].append({"src": src, "dst": dst, "relation": rel})
    return graph


def validator_CorrelationGraph_find_related(graph: Dict, key: str) -> List[str]:
    """BFS reachable nodes from key."""
    adj: Dict[str, List[str]] = defaultdict(list)
    for e in graph["edges"]:
        adj[e["src"]].append(e["dst"])
        adj[e["dst"]].append(e["src"])
    visited = set()
    queue = deque([key])
    while queue:
        cur = queue.popleft()
        if cur in visited:
            continue
        visited.add(cur)
        for nb in adj[cur]:
            if nb not in visited:
                queue.append(nb)
    visited.discard(key)
    return list(visited)


def validator_CorrelationGraph_export_dot(graph: Dict) -> str:
    """Serializes CorrelationGraph to DOT."""
    lines = ["digraph correlation {"]
    for node in graph["nodes"]:
        lines.append(f'  "{node}";')
    for e in graph["edges"]:
        lines.append(f'  "{e["src"]}" -> "{e["dst"]}" [label="{e.get("relation","")}"]; ')
    lines.append("}")
    return "\n".join(lines)


def validator_CorrelationGraph_node_count(graph: Dict) -> int:
    return len(graph["nodes"])


def validator_CorrelationGraph_edge_count(graph: Dict) -> int:
    return len(graph["edges"])


# --- MitreTechniqueMapper ---

_MITRE_DB = {
    "CreateRemoteThread": [("Execution", "T1055")],
    "VirtualAllocEx": [("Defense Evasion", "T1055")],
    "WriteProcessMemory": [("Defense Evasion", "T1055")],
    "RegSetValueEx": [("Persistence", "T1112")],
    "InternetOpenUrl": [("Command and Control", "T1071")],
    "CreateService": [("Persistence", "T1543")],
}

def validator_MitreTechniqueMapper_map_api_to_technique(api: str) -> List[Tuple[str, str]]:
    """Maps API name to MITRE techniques (tactic, technique)."""
    return _MITRE_DB.get(api, [])


def validator_MitreTechniqueMapper_map_apis_to_techniques(apis: List[str]) -> List[Tuple[str, str]]:
    """Batch mapping API -> MITRE."""
    results = []
    seen = set()
    for api in apis:
        for pair in validator_MitreTechniqueMapper_map_api_to_technique(api):
            if pair not in seen:
                seen.add(pair)
                results.append(pair)
    return results


def validator_MitreTechniqueMapper_classify(apis: List[str]) -> str:
    """Classifies a sample by predominant behaviour."""
    freq: Dict[str, int] = defaultdict(int)
    for api in apis:
        for tactic, _ in _MITRE_DB.get(api, []):
            freq[tactic] += 1
    if not freq:
        return "Unknown"
    return max(freq, key=lambda k: freq[k])


def validator_MitreTechniqueMapper_score_breakdown(apis: List[str]) -> List[Tuple[str, int]]:
    """Breakdown per tactic of behavioural score."""
    freq: Dict[str, int] = defaultdict(int)
    for api in apis:
        for tactic, _ in _MITRE_DB.get(api, []):
            freq[tactic] += 1
    return sorted(freq.items(), key=lambda x: x[1], reverse=True)


# --- CorrelationResult ---

def validator_CorrelationResult_filter_by_min_sources(
    result: Dict, min_sources: int
) -> List[Dict]:
    """IoCs present in at least N sources."""
    counts = result.get("ioc_counts", {})
    iocs = result.get("iocs", [])
    valid_keys = {k for k, v in counts.items() if v >= min_sources}
    return [
        ioc for ioc in iocs
        if f"{ioc.get('kind',ioc.get('type',''))}:{ioc.get('value','')}" in valid_keys
    ]


def validator_CorrelationResult_max_source_count(result: Dict) -> int:
    """Maximum number of sources for any IoC."""
    return result.get("max_source_count", 0)


# --- ThreatEvent ---

def validator_ThreatEvent_with_label(ioc: Dict, timestamp: int, label: str) -> Dict:
    """Constructor with annotated label."""
    return {"ioc": ioc, "timestamp": timestamp, "label": label}


def validator_ThreatEvent_ioc_types(event: Dict) -> List[str]:
    """IoC types associated with the event."""
    ioc = event.get("ioc", {})
    kind = ioc.get("kind") or ioc.get("type", "")
    return [kind] if kind else []


# --- IocNode / IocEdge / IocGraph ---

def validator_IocNode_new(kind: str, value: str) -> Dict:
    return {"kind": kind, "value": value, "confidence": None, "label": None}


def validator_IocNode_with_confidence(node: Dict, confidence: float) -> Dict:
    node = dict(node)
    node["confidence"] = confidence
    return node


def validator_IocNode_with_label(node: Dict, label: str) -> Dict:
    node = dict(node)
    node["label"] = label
    return node


def validator_IocNode_display_name(node: Dict) -> str:
    return node.get("label") or node.get("value", "")


def validator_IocEdge_new(kind: str) -> Dict:
    return {"kind": kind, "confidence": 1.0}


def validator_IocEdge_weight(edge: Dict) -> float:
    c = float(edge.get("confidence", 1.0))
    return 1.0 - c + 0.01


def validator_IocGraph_get_or_create_node(graph: Dict, kind: str, value: str) -> Tuple[Dict, str]:
    """Upsert node; returns (node, node_id)."""
    graph.setdefault("nodes", {})
    nid = f"{kind}::{value}"
    if nid not in graph["nodes"]:
        graph["nodes"][nid] = validator_IocNode_new(kind, value)
    return graph["nodes"][nid], nid


def validator_IocGraph_find_node(graph: Dict, kind: str, value: str) -> Optional[Dict]:
    nid = f"{kind}::{value}"
    return graph.get("nodes", {}).get(nid)


def validator_IocGraph_add_edge(graph: Dict, src_id: str, dst_id: str, edge: Dict) -> Dict:
    graph.setdefault("adj", {}).setdefault(src_id, []).append((dst_id, edge))
    return graph


def validator_IocGraph_neighbors_out(graph: Dict, node_id: str) -> List[str]:
    return [dst for dst, _ in graph.get("adj", {}).get(node_id, [])]


def validator_IocGraph_neighbors_in(graph: Dict, node_id: str) -> List[str]:
    result = []
    for src, neighbors in graph.get("adj", {}).items():
        for dst, _ in neighbors:
            if dst == node_id:
                result.append(src)
    return result


def validator_IocGraph_nodes_of_kind(graph: Dict, kind: str) -> List[Dict]:
    return [n for n in graph.get("nodes", {}).values() if n.get("kind") == kind]


def validator_IocGraph_bfs_distance(graph: Dict, src_id: str, dst_id: str) -> Optional[int]:
    adj = graph.get("adj", {})
    visited = {src_id}
    queue = deque([(src_id, 0)])
    while queue:
        cur, dist = queue.popleft()
        if cur == dst_id:
            return dist
        for nb, _ in adj.get(cur, []):
            if nb not in visited:
                visited.add(nb)
                queue.append((nb, dist + 1))
    return None


def validator_IocGraph_reachable(graph: Dict, src_id: str, max_hops: int) -> List[str]:
    adj = graph.get("adj", {})
    visited = {src_id}
    queue = deque([(src_id, 0)])
    while queue:
        cur, d = queue.popleft()
        if d >= max_hops:
            continue
        for nb, _ in adj.get(cur, []):
            if nb not in visited:
                visited.add(nb)
                queue.append((nb, d + 1))
    visited.discard(src_id)
    return list(visited)


# --- TemporalCorrelator ---

def validator_TemporalCorrelator_new() -> Dict:
    return {"events": [], "clusters": [], "config": {"window_secs": 3600}}


def validator_TemporalCorrelator_push(state: Dict, event: Dict) -> Dict:
    state.setdefault("events", []).append(event)
    return state


def validator_TemporalCorrelator_cluster(state: Dict) -> Dict:
    """Runs fixed-window temporal clustering."""
    window = state.get("config", {}).get("window_secs", 3600)
    entries = validator_timeline(state.get("events", []), window)
    state["clusters"] = entries
    return state


def validator_TemporalCorrelator_hottest_cluster(state: Dict) -> Optional[Dict]:
    clusters = state.get("clusters", [])
    if not clusters:
        return None
    return max(clusters, key=lambda c: len(c.get("events", [])))


def validator_TemporalCorrelator_summary(state: Dict) -> Dict:
    clusters = state.get("clusters", [])
    total_events = sum(len(c.get("events", [])) for c in clusters)
    return {
        "cluster_count": len(clusters),
        "total_events": total_events,
        "hottest": validator_TemporalCorrelator_hottest_cluster(state),
    }


# --- TimeSeries ---

def validator_TimeSeries_observe(ts: Dict, timestamp: int) -> Dict:
    bucket = timestamp - (timestamp % ts.get("bucket_secs", 3600))
    ts.setdefault("buckets", {})[str(bucket)] = (
        ts["buckets"].get(str(bucket), 0) + 1
    )
    return ts


def validator_TimeSeries_total(ts: Dict) -> int:
    return sum(ts.get("buckets", {}).values())


def validator_TimeSeries_mean(ts: Dict) -> float:
    vals = list(ts.get("buckets", {}).values())
    return _mean(vals)


def validator_TimeSeries_std_dev(ts: Dict) -> float:
    vals = list(ts.get("buckets", {}).values())
    return _std(vals)


# --- BurstDetector ---

def validator_BurstDetector_detect(ts: Dict, threshold: float = 2.0) -> List[Dict]:
    """Detects activity bursts (values > mean + threshold*std)."""
    vals = ts.get("buckets", {})
    counts = list(vals.values())
    m = _mean(counts)
    s = _std(counts)
    bursts = []
    for k, v in vals.items():
        if v > m + threshold * s:
            bursts.append({"bucket": k, "count": v, "z_score": (v - m) / s if s else 0})
    return sorted(bursts, key=lambda b: b["count"], reverse=True)


# --- CorrelationMatrix ---

def validator_CorrelationMatrix_compute(time_series_list: List[Dict]) -> List[List[float]]:
    """Pearson N×N matrix across multiple time series."""
    n = len(time_series_list)
    matrix = [[0.0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            if i == j:
                matrix[i][j] = 1.0
            elif j < i:
                matrix[i][j] = matrix[j][i]
            else:
                matrix[i][j] = round(validator_pearson_correlation(
                    time_series_list[i], time_series_list[j]
                ), 6)
    return matrix


def validator_CorrelationMatrix_high_correlation_pairs(
    matrix: List[List[float]], threshold: float
) -> List[Tuple[int, int, float]]:
    """Pairs with correlation > threshold."""
    n = len(matrix)
    pairs = []
    for i in range(n):
        for j in range(i + 1, n):
            if matrix[i][j] > threshold:
                pairs.append((i, j, matrix[i][j]))
    return sorted(pairs, key=lambda x: x[2], reverse=True)


# --- AttributionEngine (attribution_engine.rs) ---

def validator_AttributionEngine_register(engine: Dict, actor: Dict) -> Dict:
    engine.setdefault("actors", {})[actor["id"]] = actor
    return engine


def validator_AttributionEngine_score(engine: Dict, signals: List[Dict]) -> List[Dict]:
    return validator_score_attribution(signals, list(engine.get("actors", {}).values()))


def validator_AttributionEngine_top_n(engine: Dict, signals: List[Dict], n: int) -> List[Dict]:
    return validator_AttributionEngine_score(engine, signals)[:n]


def validator_AttributionEngine_get_actor(engine: Dict, actor_id: str) -> Optional[Dict]:
    return engine.get("actors", {}).get(actor_id)


# --- IocCorrelator ---

def validator_IocCorrelator_add_source(correlator: Dict, name: str, iocs: List[Dict]) -> Dict:
    correlator.setdefault("sources", {})[name] = iocs
    return correlator


def validator_IocCorrelator_correlate(correlator: Dict) -> Dict:
    sources = list(correlator.get("sources", {}).values())
    return validator_correlate_across_sources(sources)


def validator_IocCorrelator_lookup(correlator: Dict, kind: str, value: str) -> List[Dict]:
    results = []
    for ioc in [i for src in correlator.get("sources", {}).values() for i in src]:
        if (ioc.get("kind") or ioc.get("type", "")) == kind and ioc.get("value") == value:
            results.append(ioc)
    return results


# --- CampaignCorrelator ---

def validator_CampaignCorrelator_add_report(correlator: Dict, report: Dict) -> Dict:
    correlator.setdefault("reports", []).append(report)
    return correlator


def validator_CampaignCorrelator_correlate_all(correlator: Dict) -> List[Dict]:
    """Correlates campaigns by shared IoCs and TTPs."""
    reports = correlator.get("reports", [])
    n = len(reports)
    links = []
    for i in range(n):
        for j in range(i + 1, n):
            a, b = reports[i], reports[j]
            ioc_j = _jaccard(set(a.get("iocs", [])), set(b.get("iocs", [])))
            ttp_j = _jaccard(set(a.get("ttps", [])), set(b.get("ttps", [])))
            if ioc_j > 0 or ttp_j > 0:
                links.append({
                    "campaign_a": a.get("id", str(i)),
                    "campaign_b": b.get("id", str(j)),
                    "ioc_jaccard": ioc_j,
                    "ttp_jaccard": ttp_j,
                    "weight": (ioc_j + ttp_j) / 2,
                })
    correlator["links"] = links
    return links


def validator_CampaignCorrelator_significant_links(
    correlator: Dict, min_weight: float = 0.1
) -> List[Dict]:
    links = correlator.get("links") or validator_CampaignCorrelator_correlate_all(correlator)
    return [l for l in links if l["weight"] >= min_weight]


def validator_CampaignCorrelator_ioc_jaccard(
    correlator: Dict, cid_a: str, cid_b: str
) -> float:
    reports = {r.get("id", ""): r for r in correlator.get("reports", [])}
    a = reports.get(cid_a, {})
    b = reports.get(cid_b, {})
    return _jaccard(set(a.get("iocs", [])), set(b.get("iocs", [])))


# --- SimilarityMatrix (clustering.rs) ---

def validator_SimilarityMatrix_from_feature_sets(feature_sets: List[List[str]]) -> List[List[float]]:
    """Builds Jaccard similarity matrix from feature sets."""
    n = len(feature_sets)
    sets = [set(fs) for fs in feature_sets]
    matrix = [[0.0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            if i == j:
                matrix[i][j] = 1.0
            elif j < i:
                matrix[i][j] = matrix[j][i]
            else:
                matrix[i][j] = round(_jaccard(sets[i], sets[j]), 6)
    return matrix


def validator_SimilarityMatrix_pairs_above(
    matrix: List[List[float]], threshold: float
) -> List[Tuple[int, int, float]]:
    n = len(matrix)
    pairs = []
    for i in range(n):
        for j in range(i + 1, n):
            if matrix[i][j] >= threshold:
                pairs.append((i, j, matrix[i][j]))
    return pairs


# --- BehavioralClusterer ---

def validator_BehavioralClusterer_cluster(iocs: List[Dict], k: int = 3) -> List[Dict]:
    """
    Simple k-means-like clustering on behavioral features.
    Each cluster: {id, iocs, centroid_features}.
    """
    if not iocs or k <= 0:
        return []
    # Assign each IoC to a cluster by hash (deterministic mock k-means)
    clusters: Dict[int, List[Dict]] = defaultdict(list)
    for i, ioc in enumerate(iocs):
        clusters[i % k].append(ioc)
    return [{"id": cid, "iocs": members, "size": len(members)}
            for cid, members in clusters.items()]


# --- TtpAnalyzer ---

def validator_TtpAnalyzer_from_apis(apis: List[str]) -> List[Dict]:
    """Maps API calls to TTP entries."""
    ttps = []
    seen = set()
    for api in apis:
        for tactic, technique in _MITRE_DB.get(api, []):
            if technique not in seen:
                seen.add(technique)
                ttps.append({"technique_id": technique, "tactic": tactic, "source": api})
    return ttps


def validator_TtpAnalyzer_cluster_by_tactic(ttps: List[Dict]) -> Dict[str, List[Dict]]:
    """Clusters TTP entries by tactic."""
    groups: Dict[str, List[Dict]] = defaultdict(list)
    for t in ttps:
        groups[t.get("tactic", "Unknown")].append(t)
    return dict(groups)


# --- ActorTracker ---

def validator_ActorTracker_attribute_ioc(tracker: Dict, ioc: Dict) -> Optional[Dict]:
    """Attributes an IoC to the most probable actor with confidence."""
    best_actor = None
    best_score = 0.0
    for actor in tracker.get("profiles", {}).values():
        score = 0.0
        if ioc.get("value") in actor.get("iocs", []):
            score += 0.6
        for ttp in ioc.get("ttps", []):
            if ttp in actor.get("ttps", []):
                score += 0.1
        if score > best_score:
            best_score = score
            best_actor = actor.get("id")
    if best_actor is None:
        return None
    return {"actor_id": best_actor, "confidence": min(1.0, best_score)}


def validator_ActorTracker_find_by_techniques(
    tracker: Dict, technique_ids: List[str]
) -> List[Dict]:
    """Actors ordered by number of matching techniques."""
    technique_set = set(technique_ids)
    results = []
    for actor in tracker.get("profiles", {}).values():
        overlap = len(set(actor.get("ttps", [])) & technique_set)
        if overlap > 0:
            results.append({"actor_id": actor.get("id"), "overlap": overlap})
    return sorted(results, key=lambda x: x["overlap"], reverse=True)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

VALIDATORS = {
    # free functions
    "deduplicate_iocs": validator_deduplicate_iocs,
    "correlate_across_sources": validator_correlate_across_sources,
    "cluster_by_campaign": validator_cluster_by_campaign,
    "timeline": validator_timeline,
    "score_ioc": validator_score_ioc,
    "build_campaign_timeline": validator_build_campaign_timeline,
    "monthly_pulse": validator_monthly_pulse,
    "score_attribution": validator_score_attribution,
    "pearson_correlation": validator_pearson_correlation,
    "cluster_by_ttps": validator_cluster_by_ttps,
    "label_propagation": validator_label_propagation,
    "build_communities": validator_build_communities,
    "graph_stats": validator_graph_stats,
    "to_dot": validator_to_dot,
    "tlsh_distance": validator_tlsh_distance,
    "import_jaccard": validator_import_jaccard,
    "section_entropy_similarity": validator_section_entropy_similarity,
    "string_overlap_score": validator_string_overlap_score,
    "correlate_pair": validator_correlate_pair,
    "cluster_by_imphash": validator_cluster_by_imphash,
    "cluster_samples": validator_cluster_samples,
    "correlate_samples": validator_correlate_samples,
    "features_from_ioc": validator_features_from_ioc,
    # struct methods
    "ThreatCorrelator::add_ioc": validator_ThreatCorrelator_add_ioc,
    "ThreatCorrelator::add_report": validator_ThreatCorrelator_add_report,
    "ThreatCorrelator::correlate_all": validator_ThreatCorrelator_correlate_all,
    "ThreatCorrelator::find_related": validator_ThreatCorrelator_find_related,
    "ThreatCorrelator::cluster_by_family": validator_ThreatCorrelator_cluster_by_family,
    "ThreatCorrelator::high_confidence_correlations": validator_ThreatCorrelator_high_confidence_correlations,
    "CorrelationGraph::new": validator_CorrelationGraph_new,
    "CorrelationGraph::add_correlation": validator_CorrelationGraph_add_correlation,
    "CorrelationGraph::find_related": validator_CorrelationGraph_find_related,
    "CorrelationGraph::export_dot": validator_CorrelationGraph_export_dot,
    "CorrelationGraph::node_count": validator_CorrelationGraph_node_count,
    "CorrelationGraph::edge_count": validator_CorrelationGraph_edge_count,
    "MitreTechniqueMapper::map_api_to_technique": validator_MitreTechniqueMapper_map_api_to_technique,
    "MitreTechniqueMapper::map_apis_to_techniques": validator_MitreTechniqueMapper_map_apis_to_techniques,
    "MitreTechniqueMapper::classify": validator_MitreTechniqueMapper_classify,
    "MitreTechniqueMapper::score_breakdown": validator_MitreTechniqueMapper_score_breakdown,
    "CorrelationResult::filter_by_min_sources": validator_CorrelationResult_filter_by_min_sources,
    "CorrelationResult::max_source_count": validator_CorrelationResult_max_source_count,
    "ThreatEvent::with_label": validator_ThreatEvent_with_label,
    "ThreatEvent::ioc_types": validator_ThreatEvent_ioc_types,
    "IocNode::new": validator_IocNode_new,
    "IocNode::with_confidence": validator_IocNode_with_confidence,
    "IocNode::with_label": validator_IocNode_with_label,
    "IocNode::display_name": validator_IocNode_display_name,
    "IocEdge::new": validator_IocEdge_new,
    "IocEdge::weight": validator_IocEdge_weight,
    "IocGraph::get_or_create_node": validator_IocGraph_get_or_create_node,
    "IocGraph::find_node": validator_IocGraph_find_node,
    "IocGraph::add_edge": validator_IocGraph_add_edge,
    "IocGraph::neighbors_out": validator_IocGraph_neighbors_out,
    "IocGraph::neighbors_in": validator_IocGraph_neighbors_in,
    "IocGraph::nodes_of_kind": validator_IocGraph_nodes_of_kind,
    "IocGraph::bfs_distance": validator_IocGraph_bfs_distance,
    "IocGraph::reachable": validator_IocGraph_reachable,
    "TemporalCorrelator::new": validator_TemporalCorrelator_new,
    "TemporalCorrelator::push": validator_TemporalCorrelator_push,
    "TemporalCorrelator::cluster": validator_TemporalCorrelator_cluster,
    "TemporalCorrelator::hottest_cluster": validator_TemporalCorrelator_hottest_cluster,
    "TemporalCorrelator::summary": validator_TemporalCorrelator_summary,
    "TimeSeries::observe": validator_TimeSeries_observe,
    "TimeSeries::total": validator_TimeSeries_total,
    "TimeSeries::mean": validator_TimeSeries_mean,
    "TimeSeries::std_dev": validator_TimeSeries_std_dev,
    "BurstDetector::detect": validator_BurstDetector_detect,
    "CorrelationMatrix::compute": validator_CorrelationMatrix_compute,
    "CorrelationMatrix::high_correlation_pairs": validator_CorrelationMatrix_high_correlation_pairs,
    "AttributionEngine::register": validator_AttributionEngine_register,
    "AttributionEngine::score": validator_AttributionEngine_score,
    "AttributionEngine::top_n": validator_AttributionEngine_top_n,
    "AttributionEngine::get_actor": validator_AttributionEngine_get_actor,
    "IocCorrelator::add_source": validator_IocCorrelator_add_source,
    "IocCorrelator::correlate": validator_IocCorrelator_correlate,
    "IocCorrelator::lookup": validator_IocCorrelator_lookup,
    "CampaignCorrelator::add_report": validator_CampaignCorrelator_add_report,
    "CampaignCorrelator::correlate_all": validator_CampaignCorrelator_correlate_all,
    "CampaignCorrelator::significant_links": validator_CampaignCorrelator_significant_links,
    "CampaignCorrelator::ioc_jaccard": validator_CampaignCorrelator_ioc_jaccard,
    "SimilarityMatrix::from_feature_sets": validator_SimilarityMatrix_from_feature_sets,
    "SimilarityMatrix::pairs_above": validator_SimilarityMatrix_pairs_above,
    "BehavioralClusterer::cluster": validator_BehavioralClusterer_cluster,
    "TtpAnalyzer::from_apis": validator_TtpAnalyzer_from_apis,
    "TtpAnalyzer::cluster_by_tactic": validator_TtpAnalyzer_cluster_by_tactic,
    "ActorTracker::attribute_ioc": validator_ActorTracker_attribute_ioc,
    "ActorTracker::find_by_techniques": validator_ActorTracker_find_by_techniques,
}

FN_COUNT = len(VALIDATORS)
