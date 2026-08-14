"""
Validators for rustre-sandbox-extract crate (stdlib-only Python implementations).
Each validator_NAME(input) -> output mirrors the documented Rust API.
"""

import hashlib
import json
import math
import os
import re
import struct
from collections import defaultdict
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


VOWELS = set("aeiouAEIOU")
LOLBINS = {
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "wscript.exe", "cscript.exe", "bitsadmin.exe", "forfiles.exe",
    "pcalua.exe", "regasm.exe", "regsvcs.exe", "msiexec.exe",
    "wmic.exe", "installutil.exe", "ieexec.exe", "odbcconf.exe",
}


# ---------------------------------------------------------------------------
# Module-level free functions
# ---------------------------------------------------------------------------

def validator_file_op_histogram(events: list) -> dict:
    """
    file_op_histogram(events: &[NormalizedFileEvent]) -> HashMap<FileOp, usize>
    Count file operations by type.
    Input: list of dicts with 'op' key.
    """
    hist = defaultdict(int)
    for e in events:
        op = e.get("op", "Unknown")
        hist[op] += 1
    return dict(hist)


def validator_reg_op_histogram(events: list) -> dict:
    """
    reg_op_histogram(events: &[NormalizedRegistryEvent]) -> HashMap<RegOp, usize>
    Input: list of dicts with 'op' key.
    """
    hist = defaultdict(int)
    for e in events:
        op = e.get("op", "Unknown")
        hist[op] += 1
    return dict(hist)


def validator_classify_ip(s: str):
    """
    classify_ip(s: &str) -> Option<IpClass>
    Returns string class or None if not parsable.
    """
    import ipaddress
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return None
    if addr.is_loopback:
        return "Loopback"
    if addr.is_multicast:
        return "Multicast"
    # CGNAT: 100.64.0.0/10
    if isinstance(addr, ipaddress.IPv4Address):
        if ipaddress.IPv4Network("100.64.0.0/10").supernet_of(
                ipaddress.IPv4Network(f"{addr}/32")):
            return "CGNAT"
    if addr.is_private:
        return "Private"
    if addr.is_global:
        return "Public"
    return "Other"


def validator_group_paths_by_parent(paths: list) -> dict:
    """
    group_paths_by_parent(paths: &[PathBuf]) -> HashMap<PathBuf, Vec<PathBuf>>
    Input: list of path strings.
    Returns dict mapping parent dir -> list of paths.
    """
    groups = defaultdict(list)
    for p in paths:
        parent = str(Path(p).parent)
        groups[parent].append(p)
    return dict(groups)


def validator_extract_iocs(sandbox_result: dict) -> dict:
    """
    extract_iocs(sandbox_result: &SandboxResult) -> IocCollection
    High-level IOC extraction from a SandboxResult dict.
    Returns IocCollection dict with keys: ips, domains, urls, hashes, paths.
    """
    iocs = {"ips": set(), "domains": set(), "urls": set(), "hashes": set(), "paths": set()}

    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    domain_re = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
    url_re = re.compile(r"https?://[^\s\"'<>]+")
    hash_re = re.compile(r"\b[0-9a-fA-F]{32,64}\b")

    def _scan(text: str):
        iocs["urls"].update(url_re.findall(text))
        iocs["ips"].update(ip_re.findall(text))
        iocs["domains"].update(domain_re.findall(text))
        iocs["hashes"].update(hash_re.findall(text))

    for net in sandbox_result.get("network", []):
        if isinstance(net, dict):
            for v in net.values():
                if isinstance(v, str):
                    _scan(v)

    for f in sandbox_result.get("files", []):
        if isinstance(f, dict):
            p = f.get("path", "")
            if p:
                iocs["paths"].add(p)
            h = f.get("sha256", "")
            if h:
                iocs["hashes"].add(h)

    text_blob = json.dumps(sandbox_result)
    _scan(text_blob)

    return {k: sorted(v) for k, v in iocs.items()}


def validator_extract_config(family: str, memory_dump: bytes):
    """
    extract_config(family: &str, memory_dump: &[u8]) -> Option<MalwareConfig>
    Searches for known-family config patterns in raw memory.
    Returns MalwareConfig dict or None.
    """
    # Generic heuristic: look for C2-like strings near family name bytes
    family_b = family.lower().encode()
    if family_b not in memory_dump.lower():
        return None

    config = {"family": family, "c2_servers": [], "extra": {}}
    url_re = re.compile(rb"https?://[^\x00\s\"'<>]{4,64}")
    ip_port_re = re.compile(rb"(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})")

    for m in url_re.finditer(memory_dump):
        config["c2_servers"].append(m.group(0).decode(errors="replace"))
    for m in ip_port_re.finditer(memory_dump):
        config["c2_servers"].append(f"{m.group(1).decode()}:{m.group(2).decode()}")

    return config if config["c2_servers"] else None


def validator_collect_artifacts(report_dir: str) -> list:
    """
    collect_artifacts(report_dir: &Path) -> Result<Vec<SandboxArtifact>>
    Scans a directory and classifies artifacts by type.
    Returns list of SandboxArtifact dicts.
    """
    ext_map = {
        ".exe": "PE", ".dll": "PE", ".sys": "PE",
        ".elf": "ELF",
        ".py": "Script", ".ps1": "Script", ".bat": "Script", ".vbs": "Script",
        ".pcap": "Pcap", ".pcapng": "Pcap",
        ".json": "Report", ".xml": "Report",
        ".zip": "Archive", ".7z": "Archive", ".rar": "Archive",
        ".pdf": "PDF",
    }
    artifacts = []
    base = Path(report_dir)
    if not base.is_dir():
        return []
    for entry in base.iterdir():
        if entry.is_file():
            ext = entry.suffix.lower()
            kind = ext_map.get(ext, "Unknown")
            artifacts.append({
                "path": str(entry),
                "kind": kind,
                "size": entry.stat().st_size,
                "pid": None,
            })
    return artifacts


# ---------------------------------------------------------------------------
# sandbox_report_normalizer
# ---------------------------------------------------------------------------

def validator_normalized_report_summary(report: dict) -> str:
    """NormalizedReport::summary() — brief string of score, family, signatures."""
    score = report.get("score", 0)
    family = report.get("family", "unknown")
    sigs = report.get("signatures", [])
    sig_str = ", ".join(sigs[:3]) if sigs else "none"
    return f"score={score} family={family} sigs=[{sig_str}]"


def validator_normalized_report_has_signature_containing(report: dict, keyword: str) -> bool:
    """NormalizedReport::has_signature_containing()"""
    return any(keyword.lower() in s.lower() for s in report.get("signatures", []))


def validator_normalized_report_unique_dst_ips(report: dict) -> list:
    """NormalizedReport::unique_dst_ips()"""
    seen = set()
    result = []
    for conn in report.get("network", {}).get("connections", []):
        ip = conn.get("dst_ip", "")
        if ip and ip not in seen:
            seen.add(ip)
            result.append(ip)
    return result


def validator_normalized_report_dns_queries(report: dict) -> list:
    """NormalizedReport::dns_queries()"""
    return list({q.get("hostname", "") for q in report.get("network", {}).get("dns", []) if q.get("hostname")})


def validator_sandbox_normalizer_normalize(json_str: str):
    """SandboxNormalizer::normalize() — detect format and parse."""
    try:
        v = json.loads(json_str)
    except json.JSONDecodeError as e:
        return {"error": str(e)}

    if "info" in v and "behavior" in v:
        return validator_sandbox_normalizer_normalize_cuckoo(v)
    if "analysis" in v and "processes" in v:
        return validator_sandbox_normalizer_normalize_anyrun(v)
    if "sample" in v and "task" in v and "reports" in v:
        return validator_sandbox_normalizer_normalize_triage(v)
    if "analysis" in v and "generalinfo" in v:
        return validator_sandbox_normalizer_normalize_joe(v)
    if "submissions" in v and "last_analysis_results" in v:
        return validator_sandbox_normalizer_normalize_hybrid(v)
    if "data" in v and "attributes" in v.get("data", {}):
        return validator_sandbox_normalizer_normalize_vt_behavior(v)
    return validator_sandbox_normalizer_normalize_generic(v)


def validator_sandbox_normalizer_normalize_cuckoo(v: dict) -> dict:
    """SandboxNormalizer::normalize_cuckoo()"""
    info = v.get("info", {})
    sigs = [s.get("name", "") for s in v.get("signatures", [])]
    conns = []
    for c in v.get("network", {}).get("tcp", []):
        conns.append({"dst_ip": c.get("dst", ""), "dst_port": c.get("dport", 0)})
    dns = [{"hostname": d.get("request", "")} for d in v.get("network", {}).get("dns", [])]
    return {
        "source": "cuckoo",
        "score": info.get("score", 0),
        "family": info.get("category", "unknown"),
        "signatures": sigs,
        "network": {"connections": conns, "dns": dns},
    }


def validator_sandbox_normalizer_normalize_anyrun(v: dict) -> dict:
    """SandboxNormalizer::normalize_anyrun()"""
    analysis = v.get("analysis", {})
    return {
        "source": "anyrun",
        "score": analysis.get("scores", {}).get("verdict", {}).get("score", 0),
        "family": analysis.get("verdict", {}).get("name", "unknown"),
        "signatures": [t.get("name", "") for t in analysis.get("threats", [])],
        "network": {"connections": [], "dns": []},
    }


def validator_sandbox_normalizer_normalize_triage(v: dict) -> dict:
    """SandboxNormalizer::normalize_triage()"""
    reports = v.get("reports", [])
    sigs = []
    for r in reports:
        for sig in r.get("signatures", []):
            sigs.append(sig.get("name", ""))
    return {
        "source": "triage",
        "score": v.get("sample", {}).get("score", 0),
        "family": v.get("sample", {}).get("family", ["unknown"])[0] if v.get("sample", {}).get("family") else "unknown",
        "signatures": sigs,
        "network": {"connections": [], "dns": []},
    }


def validator_sandbox_normalizer_normalize_joe(v: dict) -> dict:
    """SandboxNormalizer::normalize_joe()"""
    info = v.get("analysis", {}).get("generalinfo", {})
    return {
        "source": "joe",
        "score": info.get("score", 0),
        "family": info.get("target", {}).get("sample", "unknown"),
        "signatures": [],
        "network": {"connections": [], "dns": []},
    }


def validator_sandbox_normalizer_normalize_hybrid(v: dict) -> dict:
    """SandboxNormalizer::normalize_hybrid()"""
    return {
        "source": "hybrid",
        "score": v.get("threat_score", 0),
        "family": v.get("vx_family", "unknown"),
        "signatures": v.get("signatures", []),
        "network": {"connections": [], "dns": []},
    }


def validator_sandbox_normalizer_normalize_vt_behavior(v: dict) -> dict:
    """SandboxNormalizer::normalize_vt_behavior()"""
    attrs = v.get("data", {}).get("attributes", {})
    return {
        "source": "virustotal",
        "score": attrs.get("reputation", 0),
        "family": "unknown",
        "signatures": list(attrs.get("sigma_analysis_results", {}).keys()),
        "network": {"connections": [], "dns": []},
    }


def validator_sandbox_normalizer_normalize_generic(v: dict) -> dict:
    """SandboxNormalizer::normalize_generic()"""
    return {
        "source": "generic",
        "score": v.get("score", v.get("threat_score", 0)),
        "family": v.get("family", v.get("malware_family", "unknown")),
        "signatures": v.get("signatures", v.get("detections", [])),
        "network": {"connections": [], "dns": []},
    }


def validator_threat_level_from_score(score: float) -> str:
    """ThreatLevel::from_score(score: f64) -> ThreatLevel"""
    if score >= 8.0:
        return "Critical"
    if score >= 6.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score >= 2.0:
        return "Low"
    return "Info"


def validator_file_op_from_str(s: str) -> str:
    """FileOp::from_str()"""
    s_lower = s.lower()
    if "write" in s_lower or "create" in s_lower:
        return "Write"
    if "read" in s_lower or "open" in s_lower:
        return "Read"
    if "delete" in s_lower or "remove" in s_lower:
        return "Delete"
    if "rename" in s_lower or "move" in s_lower:
        return "Rename"
    if "copy" in s_lower:
        return "Copy"
    return "Unknown"


def validator_reg_op_from_str(s: str) -> str:
    """RegOp::from_str()"""
    s_lower = s.lower()
    if "setvalue" in s_lower or "regset" in s_lower:
        return "Set"
    if "queryvalue" in s_lower or "regquery" in s_lower:
        return "Query"
    if "deletevalue" in s_lower or "regdelete" in s_lower:
        return "Delete"
    if "createkey" in s_lower or "regcreate" in s_lower:
        return "CreateKey"
    if "openkey" in s_lower or "regopen" in s_lower:
        return "OpenKey"
    return "Unknown"


# ---------------------------------------------------------------------------
# behavior_extractor
# ---------------------------------------------------------------------------

def validator_behavior_extractor_detect_format(json_str: str) -> str:
    """BehaviorExtractor::detect_format()"""
    try:
        v = json.loads(json_str)
    except Exception:
        return "Unknown"
    if "info" in v and "behavior" in v:
        return "Cuckoo"
    if "analysis" in v and "processes" in v:
        return "AnyRun"
    if "sample" in v and "task" in v:
        return "Triage"
    if "generalinfo" in v or ("analysis" in v and "generalinfo" in v.get("analysis", {})):
        return "JoeSandbox"
    return "Generic"


def validator_behavior_extractor_extract(json_str: str) -> dict:
    """BehaviorExtractor::extract() — detect and dispatch."""
    fmt = validator_behavior_extractor_detect_format(json_str)
    if fmt == "Cuckoo":
        return validator_behavior_extractor_parse_cuckoo_report(json_str)
    if fmt == "AnyRun":
        return validator_behavior_extractor_parse_anyrun_report(json_str)
    if fmt == "Triage":
        return validator_behavior_extractor_parse_triage_report(json_str)
    if fmt == "JoeSandbox":
        return validator_behavior_extractor_parse_joe_report(json_str)
    return validator_behavior_extractor_parse_generic_json(json_str)


def _make_extraction_report(artifacts: list, format_name: str) -> dict:
    return {"format": format_name, "artifacts": artifacts}


def validator_behavior_extractor_parse_cuckoo_report(json_str: str) -> dict:
    """BehaviorExtractor::parse_cuckoo_report()"""
    try:
        v = json.loads(json_str)
    except Exception:
        return _make_extraction_report([], "Cuckoo")
    artifacts = []
    for proc in v.get("behavior", {}).get("processes", []):
        for call in proc.get("calls", []):
            api = call.get("api", "")
            category = call.get("category", "")
            artifacts.append({"type": category or "api_call", "value": api, "confidence": 0.8})
    for net in v.get("network", {}).get("hosts", []):
        artifacts.append({"type": "network", "value": net, "confidence": 0.9})
    return _make_extraction_report(artifacts, "Cuckoo")


def validator_behavior_extractor_parse_anyrun_report(json_str: str) -> dict:
    """BehaviorExtractor::parse_anyrun_report()"""
    try:
        v = json.loads(json_str)
    except Exception:
        return _make_extraction_report([], "AnyRun")
    artifacts = []
    for conn in v.get("analysis", {}).get("network", {}).get("connections", []):
        artifacts.append({"type": "network", "value": conn.get("destination", ""), "confidence": 0.85})
    return _make_extraction_report(artifacts, "AnyRun")


def validator_behavior_extractor_parse_triage_report(json_str: str) -> dict:
    """BehaviorExtractor::parse_triage_report()"""
    try:
        v = json.loads(json_str)
    except Exception:
        return _make_extraction_report([], "Triage")
    artifacts = []
    for rep in v.get("reports", []):
        for ioc in rep.get("iocs", []):
            artifacts.append({"type": ioc.get("type", "ioc"), "value": ioc.get("value", ""), "confidence": 0.8})
    return _make_extraction_report(artifacts, "Triage")


def validator_behavior_extractor_parse_joe_report(json_str: str) -> dict:
    """BehaviorExtractor::parse_joe_report()"""
    try:
        v = json.loads(json_str)
    except Exception:
        return _make_extraction_report([], "JoeSandbox")
    artifacts = []
    contacted = v.get("analysis", {}).get("network", {}).get("hosts", {})
    if isinstance(contacted, dict):
        for host in contacted.get("host", []):
            val = host if isinstance(host, str) else host.get("ip", "")
            artifacts.append({"type": "network", "value": val, "confidence": 0.8})
    return _make_extraction_report(artifacts, "JoeSandbox")


def validator_behavior_extractor_parse_generic_json(json_str: str) -> dict:
    """BehaviorExtractor::parse_generic_json()"""
    url_re = re.compile(r"https?://[^\s\"'<>]+")
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    artifacts = []
    for url in url_re.findall(json_str):
        artifacts.append({"type": "network", "value": url, "confidence": 0.6})
    for ip in ip_re.findall(json_str):
        artifacts.append({"type": "network", "value": ip, "confidence": 0.5})
    return _make_extraction_report(artifacts, "Generic")


def validator_behavior_extractor_extract_network_iocs(artifacts: list) -> list:
    """BehaviorExtractor::extract_network_iocs()"""
    return [{"type": "network_ioc", "value": a["value"]} for a in artifacts if a.get("type") == "network"]


def validator_behavior_extractor_extract_file_iocs(artifacts: list) -> list:
    """BehaviorExtractor::extract_file_iocs()"""
    return [{"type": "file_ioc", "value": a["value"]} for a in artifacts if a.get("type") in ("file", "dropped_file")]


def validator_behavior_extractor_extract_persistence(artifacts: list) -> list:
    """BehaviorExtractor::extract_persistence()"""
    return [a for a in artifacts if a.get("type") in ("persistence", "registry_persistence", "startup")]


def validator_behavior_artifact_new(artifact_type: str, value: str, confidence: float) -> dict:
    """BehaviorArtifact::new()"""
    return {"type": artifact_type, "value": value, "confidence": confidence, "meta": {}}


def validator_behavior_artifact_with_meta(artifact: dict, key: str, val: str) -> dict:
    """BehaviorArtifact::with_meta()"""
    artifact = dict(artifact)
    artifact["meta"] = dict(artifact.get("meta", {}))
    artifact["meta"][key] = val
    return artifact


# ---------------------------------------------------------------------------
# c2_extractor
# ---------------------------------------------------------------------------

def validator_c2_channel_new(host: str, port: int, protocol: str) -> dict:
    """C2Channel::new()"""
    return {"host": host, "port": port, "protocol": protocol, "uri": None, "user_agent": None}


def validator_c2_channel_with_uri(ch: dict, uri: str) -> dict:
    ch = dict(ch)
    ch["uri"] = uri
    return ch


def validator_c2_channel_with_user_agent(ch: dict, ua: str) -> dict:
    ch = dict(ch)
    ch["user_agent"] = ua
    return ch


def validator_c2_channel_address(ch: dict) -> str:
    """C2Channel::address() -> 'host:port'"""
    return f"{ch['host']}:{ch['port']}"


def validator_c2_channel_is_ip(ch: dict) -> bool:
    """C2Channel::is_ip()"""
    import ipaddress
    try:
        ipaddress.ip_address(ch["host"])
        return True
    except ValueError:
        return False


def validator_c2_channel_is_domain(ch: dict) -> bool:
    """C2Channel::is_domain()"""
    return not validator_c2_channel_is_ip(ch)


def validator_c2_config_new(family: str) -> dict:
    """C2Config::new()"""
    return {"family": family, "channels": []}


def validator_c2_config_add_channel(config: dict, ch: dict):
    """C2Config::add_channel() — mutates in place."""
    config["channels"].append(ch)


def validator_c2_config_primary_channel(config: dict):
    """C2Config::primary_channel() -> Option<&C2Channel>"""
    return config["channels"][0] if config["channels"] else None


def validator_c2_config_domain_channels(config: dict) -> list:
    """C2Config::domain_channels()"""
    return [c for c in config["channels"] if validator_c2_channel_is_domain(c)]


def validator_c2_config_ip_channels(config: dict) -> list:
    """C2Config::ip_channels()"""
    return [c for c in config["channels"] if validator_c2_channel_is_ip(c)]


def validator_dga_detector_entropy(s: str) -> float:
    """DgaDetector::entropy()"""
    return _shannon_entropy(s.encode())


def validator_dga_detector_vowel_ratio(s: str) -> float:
    """DgaDetector::vowel_ratio()"""
    if not s:
        return 0.0
    alpha = [c for c in s if c.isalpha()]
    if not alpha:
        return 0.0
    return sum(1 for c in alpha if c in VOWELS) / len(alpha)


def validator_dga_detector_is_dga(domain: str) -> bool:
    """DgaDetector::is_dga()"""
    # Strip TLD
    parts = domain.rstrip(".").split(".")
    label = parts[0] if parts else domain
    if len(label) < 6:
        return False
    ent = validator_dga_detector_entropy(label)
    vr = validator_dga_detector_vowel_ratio(label)
    # DGA: low vowel ratio (consonant-heavy) OR high entropy; reject common words
    return vr < 0.25 or ent > 3.2


def validator_dga_detector_filter_dga(domains: list) -> list:
    """DgaDetector::filter_dga()"""
    return [d for d in domains if validator_dga_detector_is_dga(d)]


def validator_fast_flux_detector_new() -> dict:
    """FastFluxDetector::new()"""
    return {"records": defaultdict(list)}


def validator_fast_flux_detector_add_record(detector: dict, domain: str, ip: str, ttl: int):
    """FastFluxDetector::add_record()"""
    detector["records"][domain].append({"ip": ip, "ttl": ttl})


def validator_fast_flux_detector_ip_count(detector: dict, domain: str) -> int:
    """FastFluxDetector::ip_count()"""
    return len({r["ip"] for r in detector["records"].get(domain, [])})


def validator_fast_flux_detector_unique_ips(detector: dict, domain: str) -> list:
    """FastFluxDetector::unique_ips()"""
    return list({r["ip"] for r in detector["records"].get(domain, [])})


def validator_fast_flux_detector_is_fast_flux(detector: dict, domain: str) -> bool:
    """FastFluxDetector::is_fast_flux()"""
    records = detector["records"].get(domain, [])
    if not records:
        return False
    unique_ips = {r["ip"] for r in records}
    avg_ttl = sum(r["ttl"] for r in records) / len(records)
    return len(unique_ips) >= 4 and avg_ttl < 300


def validator_fast_flux_detector_fast_flux_domains(detector: dict) -> list:
    """FastFluxDetector::fast_flux_domains()"""
    return [d for d in detector["records"] if validator_fast_flux_detector_is_fast_flux(detector, d)]


def validator_extracted_string_new(value: str, offset: int, encoding: str) -> dict:
    """ExtractedString::new()"""
    return {"value": value, "offset": offset, "encoding": encoding}


def validator_extracted_string_looks_like_domain(es: dict) -> bool:
    """ExtractedString::looks_like_domain()"""
    v = es["value"]
    return bool(re.match(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', v)) and len(v) > 4


def validator_extracted_string_looks_like_ip(es: dict) -> bool:
    """ExtractedString::looks_like_ip()"""
    return bool(re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', es["value"]))


def validator_extracted_string_looks_like_url(es: dict) -> bool:
    """ExtractedString::looks_like_url()"""
    return es["value"].startswith(("http://", "https://", "ftp://"))


def validator_c2_extractor_extract_strings(data: bytes, min_len: int = 4) -> list:
    """C2Extractor::extract_strings() — ASCII strings."""
    result = []
    current = []
    for i, b in enumerate(data):
        if 0x20 <= b <= 0x7E:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                s = "".join(current)
                result.append(validator_extracted_string_new(s, i - len(current), "ASCII"))
            current = []
    if len(current) >= min_len:
        result.append(validator_extracted_string_new("".join(current), len(data) - len(current), "ASCII"))
    return result


def validator_c2_extractor_extract_utf16le(data: bytes) -> list:
    """C2Extractor::extract_utf16le()"""
    result = []
    i = 0
    current = []
    start = 0
    while i + 1 < len(data):
        w = struct.unpack_from("<H", data, i)[0]
        if 0x0020 <= w <= 0x007E:
            if not current:
                start = i
            current.append(chr(w))
            i += 2
        else:
            if len(current) >= 4:
                result.append(validator_extracted_string_new("".join(current), start, "UTF-16LE"))
            current = []
            i += 1
    if len(current) >= 4:
        result.append(validator_extracted_string_new("".join(current), start, "UTF-16LE"))
    return result


def validator_c2_extractor_try_xor_decode(data: bytes, key: int) -> bytes:
    """C2Extractor::try_xor_decode()"""
    return bytes(b ^ key for b in data)


def validator_c2_extractor_extract_xor_strings(data: bytes) -> list:
    """C2Extractor::extract_xor_strings() — try all 255 keys."""
    result = []
    for key in range(1, 256):
        decoded = validator_c2_extractor_try_xor_decode(data, key)
        for s in validator_c2_extractor_extract_strings(decoded):
            s = dict(s)
            s["xor_key"] = key
            result.append(s)
    return result


def validator_c2_extractor_extract_urls(text: str) -> list:
    """C2Extractor::extract_urls()"""
    return re.findall(r'(?:https?|ftp)://[^\s"\'<>]+', text)


def validator_c2_extractor_extract_ip_ports(text: str) -> list:
    """C2Extractor::extract_ip_ports() -> Vec<(String, u16)>"""
    result = []
    for m in re.finditer(r'(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})', text):
        port = int(m.group(2))
        if 1 <= port <= 65535:
            result.append((m.group(1), port))
    return result


def validator_c2_extractor_extract(data: bytes) -> dict:
    """C2Extractor::extract() -> Result<C2Config, C2Error>"""
    config = validator_c2_config_new("unknown")
    strings = validator_c2_extractor_extract_strings(data)
    text = " ".join(s["value"] for s in strings)
    for url in validator_c2_extractor_extract_urls(text):
        m = re.match(r'https?://([^/:]+)(?::(\d+))?', url)
        if m:
            host = m.group(1)
            port = int(m.group(2)) if m.group(2) else (443 if url.startswith("https") else 80)
            validator_c2_config_add_channel(config, validator_c2_channel_new(host, port, "HTTP"))
    for ip, port in validator_c2_extractor_extract_ip_ports(text):
        validator_c2_config_add_channel(config, validator_c2_channel_new(ip, port, "TCP"))
    return config


def validator_c2_extractor_detect_dga_channels(config: dict) -> list:
    """C2Extractor::detect_dga_channels()"""
    return [c for c in config["channels"] if validator_c2_channel_is_domain(c) and validator_dga_detector_is_dga(c["host"])]


# ---------------------------------------------------------------------------
# credential_harvester
# ---------------------------------------------------------------------------

HARVEST_API_SIGNATURES = {
    "CryptProtectData": ("DPAPI", "High"),
    "CryptUnprotectData": ("DPAPI", "High"),
    "LsaRetrievePrivateData": ("LSA", "Critical"),
    "SamQueryInformationUser": ("SAM", "Critical"),
    "NtlmGetCredentials": ("NTLM", "High"),
    "CredRead": ("CredentialManager", "Medium"),
    "CredEnumerate": ("CredentialManager", "Medium"),
}


def validator_harvest_event_new(kind: str, target: str, pid: int, api_name: str) -> dict:
    """HarvestEvent::new()"""
    return {"kind": kind, "target": target, "pid": pid, "api_name": api_name, "value": None, "tags": [], "severity": "Low"}


def validator_harvest_event_with_value(ev: dict, value: str) -> dict:
    ev = dict(ev)
    ev["value"] = value
    return ev


def validator_harvest_event_tag(ev: dict, t: str) -> dict:
    ev = dict(ev)
    ev["tags"] = list(ev.get("tags", [])) + [t]
    return ev


_SEV_ORDER = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def validator_harvest_event_at_least(ev: dict, min_sev: str) -> bool:
    """HarvestEvent::at_least()"""
    return _SEV_ORDER.get(ev.get("severity", "Low"), 0) >= _SEV_ORDER.get(min_sev, 0)


def validator_api_call_new(name: str, args: list) -> dict:
    """ApiCall::new()"""
    return {"name": name, "args": args}


def validator_credential_harvester_new() -> dict:
    """CredentialHarvester::new()"""
    return {"events": [], "signatures": HARVEST_API_SIGNATURES}


def validator_credential_harvester_process_call(harvester: dict, call: dict):
    """CredentialHarvester::process_call() — mutates harvester."""
    name = call.get("name", "")
    if name in harvester["signatures"]:
        kind, sev = harvester["signatures"][name]
        ev = validator_harvest_event_new(kind, "unknown", call.get("pid", 0), name)
        ev["severity"] = sev
        harvester["events"].append(ev)


def validator_credential_harvester_process_trace(harvester: dict, calls: list):
    """CredentialHarvester::process_trace()"""
    for call in calls:
        validator_credential_harvester_process_call(harvester, call)


def validator_credential_harvester_events(harvester: dict) -> list:
    """CredentialHarvester::events()"""
    return harvester["events"]


def validator_credential_harvester_events_at_least(harvester: dict, min_sev: str) -> list:
    """CredentialHarvester::events_at_least()"""
    return [e for e in harvester["events"] if validator_harvest_event_at_least(e, min_sev)]


def validator_credential_harvester_max_severity(harvester: dict):
    """CredentialHarvester::max_severity() -> Option<HarvestSeverity>"""
    if not harvester["events"]:
        return None
    return max(harvester["events"], key=lambda e: _SEV_ORDER.get(e.get("severity", "Low"), 0))["severity"]


def validator_credential_harvester_has_critical(harvester: dict) -> bool:
    """CredentialHarvester::has_critical()"""
    return any(e.get("severity") == "Critical" for e in harvester["events"])


def validator_credential_harvester_targeted_stores(harvester: dict) -> list:
    """CredentialHarvester::targeted_stores()"""
    return list({e["target"] for e in harvester["events"]})


def validator_credential_harvester_technique_counts(harvester: dict) -> dict:
    """CredentialHarvester::technique_counts()"""
    counts = defaultdict(int)
    for e in harvester["events"]:
        counts[e["kind"]] += 1
    return dict(counts)


def validator_credential_harvester_report(harvester: dict) -> str:
    """CredentialHarvester::report()"""
    counts = validator_credential_harvester_technique_counts(harvester)
    stores = validator_credential_harvester_targeted_stores(harvester)
    lines = ["Credential Harvest Report", "=" * 30]
    for tech, cnt in counts.items():
        lines.append(f"  {tech}: {cnt} event(s)")
    lines.append(f"Targeted stores: {', '.join(stores) or 'none'}")
    return "\n".join(lines)


def validator_harvester_report_from_harvester(harvester: dict) -> dict:
    """HarvesterReport::from_harvester()"""
    return {
        "events": harvester["events"],
        "technique_counts": validator_credential_harvester_technique_counts(harvester),
        "targeted_stores": validator_credential_harvester_targeted_stores(harvester),
        "max_severity": validator_credential_harvester_max_severity(harvester),
        "has_critical": validator_credential_harvester_has_critical(harvester),
    }


def validator_credential_scanner_scan(input_text: str) -> list:
    """CredentialScanner::scan() — regex-based credential finder."""
    candidates = []
    patterns = [
        ("password", r'(?i)(?:password|passwd|pwd)\s*[=:]\s*(\S+)'),
        ("api_key", r'(?i)(?:api[_-]?key|token)\s*[=:]\s*([A-Za-z0-9_\-]{16,})'),
        ("aws_key", r'AKIA[0-9A-Z]{16}'),
        ("bearer", r'Bearer\s+([A-Za-z0-9\-_\.]{20,})'),
    ]
    for kind, pattern in patterns:
        for m in re.finditer(pattern, input_text):
            candidates.append({"kind": kind, "value": m.group(0), "confidence": 0.7})
    return candidates


def validator_composite_harvester_new() -> dict:
    """CompositeHarvester::new()"""
    return {"harvester": validator_credential_harvester_new(), "scanner_results": []}


def validator_composite_harvester_high_confidence() -> dict:
    """CompositeHarvester::high_confidence()"""
    h = validator_composite_harvester_new()
    # Subset: only Critical signatures
    h["harvester"]["signatures"] = {
        k: v for k, v in HARVEST_API_SIGNATURES.items() if v[1] == "Critical"
    }
    return h


def validator_composite_harvester_ingest_api_calls(composite: dict, calls: list):
    """CompositeHarvester::ingest_api_calls()"""
    validator_credential_harvester_process_trace(composite["harvester"], calls)


def validator_composite_harvester_scan_strings(composite: dict, blobs: list) -> list:
    """CompositeHarvester::scan_strings()"""
    results = []
    for blob in blobs:
        results.extend(validator_credential_scanner_scan(blob))
    composite["scanner_results"] = results
    return results


def validator_composite_harvester_report(composite: dict) -> dict:
    """CompositeHarvester::report() -> HarvesterReport"""
    return validator_harvester_report_from_harvester(composite["harvester"])


def validator_composite_harvester_events(composite: dict) -> list:
    """CompositeHarvester::events()"""
    return composite["harvester"]["events"]


# ---------------------------------------------------------------------------
# crypto_key_finder
# ---------------------------------------------------------------------------

# AES Rijndael S-box (first 16 bytes) as detection marker
AES_SBOX_PREFIX = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
                         0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76])


def validator_found_crypto_key_add_meta(key: dict, k: str, value: str):
    """FoundCryptoKey::add_meta() — mutates in place."""
    key.setdefault("meta", {})[k] = value


def validator_aes_key_finder_find_aes128(data: bytes) -> list:
    """AesKeyFinder::find_aes128() — Rijndael key schedule detection."""
    results = []
    idx = data.find(AES_SBOX_PREFIX)
    while idx != -1:
        # Key typically precedes S-box by some offset; extract 16 bytes before
        if idx >= 16:
            candidate = data[idx - 16:idx]
            results.append({
                "algorithm": "AES-128",
                "offset": idx - 16,
                "length": 16,
                "key_bytes": candidate.hex(),
                "confidence": 0.7,
                "meta": {},
            })
        idx = data.find(AES_SBOX_PREFIX, idx + 1)
    return results


def validator_aes_key_finder_find_raw_aes_keys(data: bytes) -> list:
    """AesKeyFinder::find_raw_aes_keys() — entropy-based scan for 16/24/32 byte blocks."""
    results = []
    for size in (32, 24, 16):
        for i in range(0, len(data) - size, size):
            block = data[i:i + size]
            ent = _shannon_entropy(block)
            if ent > 7.0:
                results.append({
                    "algorithm": f"AES-{size * 8}?",
                    "offset": i,
                    "length": size,
                    "key_bytes": block.hex(),
                    "confidence": min(1.0, (ent - 7.0) / 1.0),
                    "meta": {},
                })
    return results


PEM_PRIVATE_MARKERS = [b"-----BEGIN RSA PRIVATE KEY-----", b"-----BEGIN PRIVATE KEY-----",
                       b"-----BEGIN EC PRIVATE KEY-----"]
PEM_PUBLIC_MARKERS = [b"-----BEGIN PUBLIC KEY-----", b"-----BEGIN CERTIFICATE-----"]


def validator_pem_key_finder_find_private_keys(data: bytes) -> list:
    """PemKeyFinder::find_private_keys()"""
    results = []
    for marker in PEM_PRIVATE_MARKERS:
        idx = data.find(marker)
        while idx != -1:
            end = data.find(b"-----END", idx + 1)
            end = data.find(b"-----", end + 5) + 5 if end != -1 else idx + 64
            results.append({
                "algorithm": "PEM-PrivateKey",
                "offset": idx,
                "length": end - idx,
                "key_bytes": data[idx:end].hex(),
                "confidence": 0.95,
                "meta": {},
            })
            idx = data.find(marker, idx + 1)
    return results


def validator_pem_key_finder_find_public_keys(data: bytes) -> list:
    """PemKeyFinder::find_public_keys()"""
    results = []
    for marker in PEM_PUBLIC_MARKERS:
        idx = data.find(marker)
        while idx != -1:
            end = data.find(b"-----END", idx + 1)
            end = data.find(b"-----", end + 5) + 5 if end != -1 else idx + 64
            results.append({
                "algorithm": "PEM-PublicKey",
                "offset": idx,
                "length": end - idx,
                "key_bytes": data[idx:end].hex(),
                "confidence": 0.9,
                "meta": {},
            })
            idx = data.find(marker, idx + 1)
    return results


def validator_crypto_key_finder_find(data: bytes) -> list:
    """CryptoKeyFinder::find() — multi-algorithm scanner."""
    results = []
    results.extend(validator_aes_key_finder_find_aes128(data))
    results.extend(validator_aes_key_finder_find_raw_aes_keys(data))
    results.extend(validator_pem_key_finder_find_private_keys(data))
    results.extend(validator_pem_key_finder_find_public_keys(data))
    return results


def validator_xor_key_recovery_recover_single_byte(data: bytes):
    """XorKeyRecovery::recover_single_byte() — frequency analysis."""
    if not data:
        return None
    # Most frequent byte XORed with 0x20 (space) is a common heuristic
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    most_common = max(freq, key=freq.__getitem__)
    key = most_common ^ 0x20
    return {
        "algorithm": "XOR-1byte",
        "offset": 0,
        "length": 1,
        "key_bytes": bytes([key]).hex(),
        "confidence": 0.6,
        "meta": {},
    }


def validator_xor_key_recovery_recover_key_of_length(data: bytes, key_len: int):
    """XorKeyRecovery::recover_key_of_length() — Index of Coincidence."""
    if len(data) < key_len * 2:
        return None
    key = bytearray()
    for i in range(key_len):
        chunk = bytes(data[j] for j in range(i, len(data), key_len))
        freq = defaultdict(int)
        for b in chunk:
            freq[b] += 1
        most_common = max(freq, key=freq.__getitem__)
        key.append(most_common ^ 0x65)  # 'e' most common English byte
    return {
        "algorithm": f"XOR-{key_len}byte",
        "offset": 0,
        "length": key_len,
        "key_bytes": bytes(key).hex(),
        "confidence": 0.5,
        "meta": {},
    }


def validator_xor_key_recovery_auto_recover(data: bytes):
    """XorKeyRecovery::auto_recover() — try lengths 1-32."""
    best = None
    best_conf = 0.0
    for l in range(1, 33):
        r = validator_xor_key_recovery_recover_key_of_length(data, l)
        if r and r["confidence"] > best_conf:
            best = r
            best_conf = r["confidence"]
    return best


def validator_xor_key_recovery_known_plaintext(ciphertext: bytes, plaintext: bytes):
    """XorKeyRecovery::known_plaintext()"""
    min_len = min(len(ciphertext), len(plaintext))
    if min_len == 0:
        return None
    key = bytes(ciphertext[i] ^ plaintext[i] for i in range(min_len))
    return list(key)


def validator_key_scan_pipeline_scan_all(data: bytes) -> list:
    """KeyScanPipeline::scan_all()"""
    return validator_crypto_key_finder_find(data)


def validator_key_scan_pipeline_scan_high_confidence(data: bytes, threshold: float) -> list:
    """KeyScanPipeline::scan_high_confidence()"""
    return [k for k in validator_key_scan_pipeline_scan_all(data) if k.get("confidence", 0) >= threshold]


def validator_key_scan_pipeline_summary(keys: list) -> str:
    """KeyScanPipeline::summary()"""
    lines = [f"{k['algorithm']} @ offset={k['offset']} len={k['length']} conf={k.get('confidence', 0):.2f}"
             for k in keys]
    return "\n".join(lines) if lines else "No keys found"


# ---------------------------------------------------------------------------
# dropper_analysis
# ---------------------------------------------------------------------------

MAGIC_MAP = {
    b"\x4d\x5a": "PE",
    b"\x7fELF": "ELF",
    b"PK\x03\x04": "ZIP",
    b"%PDF": "PDF",
    b"\x89PNG": "PNG",
    b"MZ": "PE",
}


def validator_encrypted_payload_new(offset: int, raw_bytes: bytes, scheme: str) -> dict:
    """EncryptedPayload::new()"""
    return {"offset": offset, "raw_bytes": raw_bytes, "scheme": scheme, "notes": []}


def validator_encrypted_payload_effective_len(payload: dict) -> int:
    """EncryptedPayload::effective_len()"""
    return len(payload["raw_bytes"])


def validator_encrypted_payload_add_note(payload: dict, note: str):
    """EncryptedPayload::add_note()"""
    payload["notes"].append(note)


def validator_dropped_file_new_dropper(path: str, content: bytes) -> dict:
    """dropper_analysis::DroppedFile::new()"""
    return {"path": path, "content": content}


def validator_dropped_file_sha256_hex(f: dict) -> str:
    return _sha256_hex(f["content"])


def validator_dropped_file_md5_hex(f: dict) -> str:
    return _md5_hex(f["content"])


def validator_dropped_process_new(image_path: str, command_line: str) -> dict:
    """DroppedProcess::new()"""
    return {"image_path": image_path, "command_line": command_line}


def validator_payload_type_from_magic(data: bytes) -> str:
    """PayloadType::from_magic()"""
    for magic, name in MAGIC_MAP.items():
        if data[:len(magic)] == magic:
            return name
    return "Unknown"


def validator_payload_finder_find_payloads(data: bytes) -> list:
    """PayloadFinder::find_payloads()"""
    payloads = []
    # Look for embedded PE (MZ header)
    i = 0
    while i < len(data) - 2:
        if data[i:i+2] == b"MZ":
            payloads.append(validator_encrypted_payload_new(i, data[i:i+256], "Raw-PE"))
        i += 1
    # Base64 blobs
    for m in re.finditer(rb'[A-Za-z0-9+/]{64,}={0,2}', data):
        payloads.append(validator_encrypted_payload_new(m.start(), m.group(0), "Base64"))
    return payloads


def validator_payload_finder_decrypt(payload: dict):
    """PayloadFinder::decrypt() — attempt in-place decryption (XOR scan)."""
    raw = payload["raw_bytes"]
    best_key = 0
    best_printable = 0
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in raw)
        printable = sum(1 for b in decoded if 0x20 <= b <= 0x7E)
        if printable > best_printable:
            best_printable = printable
            best_key = key
    if best_key:
        payload["decrypted"] = bytes(b ^ best_key for b in raw)
        payload["decrypt_key"] = best_key
        validator_encrypted_payload_add_note(payload, f"XOR key=0x{best_key:02x}")


def validator_dropper_analyzer_new() -> dict:
    """DropperAnalyzer::new()"""
    return {"sample_path": None}


def validator_dropper_analyzer_with_sample(analyzer: dict, path: str) -> dict:
    analyzer = dict(analyzer)
    analyzer["sample_path"] = path
    return analyzer


def validator_dropper_analyzer_analyse(analyzer: dict, data: bytes) -> dict:
    """DropperAnalyzer::analyse() -> DropperReport"""
    report = {
        "sample_path": analyzer.get("sample_path"),
        "payloads": [],
        "dropped_files": [],
        "dropped_processes": [],
        "persistence": False,
    }
    payloads = validator_payload_finder_find_payloads(data)
    for p in payloads:
        validator_payload_finder_decrypt(p)
    report["payloads"] = payloads
    return report


def validator_dropper_report_add_dropped_file(report: dict, f: dict):
    report["dropped_files"].append(f)


def validator_dropper_report_add_dropped_process(report: dict, proc: dict):
    report["dropped_processes"].append(proc)


def validator_dropper_report_is_high_risk(report: dict) -> bool:
    """DropperReport::is_high_risk()"""
    return bool(report["dropped_processes"]) or any(
        validator_payload_type_from_magic(f.get("content", b"")) in ("PE", "ELF")
        for f in report["dropped_files"]
    )


def validator_dropper_report_executable_count(report: dict) -> int:
    """DropperReport::executable_count()"""
    return sum(
        1 for f in report["dropped_files"]
        if validator_payload_type_from_magic(f.get("content", b"")) in ("PE", "ELF")
    )


def validator_dropper_report_has_persistence(report: dict) -> bool:
    return report.get("persistence", False)


def validator_dropper_report_summary(report: dict) -> str:
    return (f"DropperReport: payloads={len(report['payloads'])} "
            f"files={len(report['dropped_files'])} procs={len(report['dropped_processes'])} "
            f"high_risk={validator_dropper_report_is_high_risk(report)}")


def validator_dropper_report_to_json(report: dict) -> str:
    safe = {k: v for k, v in report.items() if k != "payloads"}
    safe["payload_count"] = len(report.get("payloads", []))
    return json.dumps(safe, default=str)


def validator_dropper_report_all_hashes(report: dict) -> list:
    return [validator_dropped_file_sha256_hex(f) for f in report["dropped_files"]]


# ---------------------------------------------------------------------------
# dropped_file_collector
# ---------------------------------------------------------------------------

def validator_dropped_file_type_detect(header: bytes, ext: str) -> str:
    """DroppedFileType::detect()"""
    if header[:2] == b"MZ":
        return "PE"
    if header[:4] == b"\x7fELF":
        return "ELF"
    if header[:4] == b"PK\x03\x04":
        return "ZIP"
    if header[:4] == b"%PDF":
        return "PDF"
    ext_map = {".ps1": "Script", ".py": "Script", ".bat": "Script", ".vbs": "Script",
               ".txt": "Text", ".log": "Text", ".pcap": "Pcap"}
    return ext_map.get(ext.lower(), "Unknown")


def validator_dropped_file_collector_new(path: str, pid: int, size: int, sha256: str, entropy: float) -> dict:
    """dropped_file_collector::DroppedFile::new()"""
    return {"path": path, "pid": pid, "size": size, "sha256": sha256,
            "entropy": entropy, "header": b"", "tags": [], "file_type": "Unknown"}


def validator_dropped_file_collector_set_header(f: dict, header: bytes):
    f["header"] = header
    f["file_type"] = validator_dropped_file_type_detect(header, os.path.splitext(f["path"])[1])


def validator_dropped_file_collector_extension(f: dict) -> str:
    return os.path.splitext(f["path"])[1]


def validator_dropped_file_collector_file_name(f: dict) -> str:
    return os.path.basename(f["path"])


def validator_dropped_file_collector_is_high_entropy(f: dict) -> bool:
    return f["entropy"] > 7.2


def validator_dropped_file_collector_tag(f: dict, t: str):
    f["tags"].append(t)


def validator_dropped_file_collector_has_tag(f: dict, t: str) -> bool:
    return t in f["tags"]


def validator_dropped_file_collector_collector_new(config: dict) -> dict:
    """DroppedFileCollector::new()"""
    return {"config": config, "files": [], "errors": {}}


def validator_dropped_file_collector_default_config() -> dict:
    """DroppedFileCollector::default_config()"""
    return {"exclude_exts": {".log", ".tmp", ".pf"}, "min_size": 0}


def validator_dropped_file_collector_ingest_raw(collector: dict, line: str):
    """DroppedFileCollector::ingest_raw() -> Result<bool, CollectorError>"""
    parts = line.strip().split("|")
    if len(parts) < 3:
        return (False, f"invalid line: {line!r}")
    path, sha256, size_str = parts[0], parts[1], parts[2]
    try:
        size = int(size_str)
    except ValueError:
        return (False, f"invalid size: {size_str!r}")
    ext = os.path.splitext(path)[1].lower()
    if ext in collector["config"].get("exclude_exts", set()):
        return (False, "excluded extension")
    f = validator_dropped_file_collector_new(path, 0, size, sha256, 0.0)
    collector["files"].append(f)
    return (True, None)


def validator_dropped_file_collector_collect(collector: dict) -> list:
    """DroppedFileCollector::collect()"""
    return list(collector["files"])


def validator_dropped_file_collector_ingest_log(collector: dict, log: str) -> dict:
    """DroppedFileCollector::ingest_log() -> HashMap<usize, CollectorError>"""
    errors = {}
    for i, line in enumerate(log.splitlines()):
        if not line.strip():
            continue
        ok, err = validator_dropped_file_collector_ingest_raw(collector, line)
        if err:
            errors[i] = err
    return errors


def validator_dropped_file_collector_ingest_directory(collector: dict, dir_path: str):
    """DroppedFileCollector::ingest_directory()"""
    base = Path(dir_path)
    if not base.is_dir():
        return {"error": f"not a directory: {dir_path}"}
    for entry in base.iterdir():
        if entry.is_file():
            content = entry.read_bytes()
            sha256 = _sha256_hex(content)
            f = validator_dropped_file_collector_new(
                str(entry), 0, entry.stat().st_size, sha256, _shannon_entropy(content)
            )
            validator_dropped_file_collector_set_header(f, content[:16])
            collector["files"].append(f)
    return None


# ---------------------------------------------------------------------------
# file_artifact_collector
# ---------------------------------------------------------------------------

def validator_artifact_kind_classify_by_path(path: str) -> str:
    """ArtifactKind::classify_by_path()"""
    ext = os.path.splitext(path)[1].lower()
    if ext in (".exe", ".dll", ".sys", ".ocx"):
        return "PE"
    if ext in (".ps1", ".py", ".bat", ".vbs", ".js", ".sh"):
        return "Script"
    if ext in (".json", ".xml", ".ini", ".cfg", ".conf"):
        return "Config"
    if ext in (".pcap", ".pcapng"):
        return "Pcap"
    return "Data"


def validator_file_artifact_new(path: str, kind: str, pid: int) -> dict:
    """FileArtifact::new()"""
    return {"path": path, "kind": kind, "pid": pid, "hash_sha256": None,
            "entropy": None, "magic": None, "tags": [], "is_exec": False}


def validator_file_artifact_detect_type_from_magic(magic: bytes) -> str:
    """FileArtifact::detect_type_from_magic()"""
    if magic[:2] == b"MZ":
        return "application/x-dosexec"
    if magic[:4] == b"\x7fELF":
        return "application/x-elf"
    if magic[:4] == b"PK\x03\x04":
        return "application/zip"
    if magic[:4] == b"%PDF":
        return "application/pdf"
    return "application/octet-stream"


def validator_file_artifact_populate_from_content(artifact: dict, content: bytes):
    """FileArtifact::populate_from_content()"""
    artifact["hash_sha256"] = _sha256_hex(content)
    artifact["entropy"] = _shannon_entropy(content)
    artifact["magic"] = validator_file_artifact_detect_type_from_magic(content[:8])
    artifact["is_exec"] = artifact["magic"] in (
        "application/x-dosexec", "application/x-elf"
    ) or artifact["kind"] == "Script"


def validator_file_artifact_add_tag(artifact: dict, tag: str):
    artifact["tags"].append(tag)


def validator_file_artifact_is_executable(artifact: dict) -> bool:
    return artifact.get("is_exec", False)


def validator_monitor_rule_include_prefix(prefix: str) -> dict:
    return {"type": "include", "prefix": prefix}


def validator_monitor_rule_exclude_prefix(prefix: str) -> dict:
    return {"type": "exclude", "prefix": prefix}


def _monitor_passes_rules(rules: list, path: str) -> bool:
    result = True
    for rule in rules:
        if rule["type"] == "exclude" and path.startswith(rule["prefix"]):
            result = False
        elif rule["type"] == "include" and path.startswith(rule["prefix"]):
            result = True
    return result


def validator_file_monitor_new() -> dict:
    return {"rules": [], "artifacts": []}


def validator_file_monitor_add_rule(monitor: dict, rule: dict):
    monitor["rules"].append(rule)


def validator_file_monitor_record(monitor: dict, artifact: dict):
    if _monitor_passes_rules(monitor["rules"], artifact["path"]):
        monitor["artifacts"].append(artifact)


def validator_file_monitor_record_drop(monitor: dict, path: str, pid: int, content: bytes):
    kind = validator_artifact_kind_classify_by_path(path)
    art = validator_file_artifact_new(path, kind, pid)
    validator_file_artifact_populate_from_content(art, content)
    validator_file_monitor_record(monitor, art)


def validator_file_monitor_artifacts(monitor: dict) -> list:
    return monitor["artifacts"]


def validator_file_monitor_count(monitor: dict) -> int:
    return len(monitor["artifacts"])


def validator_file_monitor_executables(monitor: dict) -> list:
    return [a for a in monitor["artifacts"] if validator_file_artifact_is_executable(a)]


def validator_file_monitor_scripts(monitor: dict) -> list:
    return [a for a in monitor["artifacts"] if a["kind"] == "Script"]


def validator_file_artifact_collector_new() -> dict:
    return {"monitors": []}


def validator_file_artifact_collector_add_windows_exclusions(collector: dict):
    mon = validator_file_monitor_new()
    for prefix in (r"C:\Windows\System32", r"C:\Windows\WinSxS",
                   r"C:\Windows\SysWOW64", r"C:\Windows\Temp"):
        validator_file_monitor_add_rule(mon, validator_monitor_rule_exclude_prefix(prefix))
    collector["monitors"].append(mon)


def validator_file_artifact_collector_add_monitor(collector: dict, monitor: dict):
    collector["monitors"].append(monitor)


def validator_file_artifact_collector_create_monitor(collector: dict) -> dict:
    mon = validator_file_monitor_new()
    collector["monitors"].append(mon)
    return mon


def validator_file_artifact_collector_collect(collector: dict) -> dict:
    all_artifacts = []
    for mon in collector["monitors"]:
        all_artifacts.extend(mon["artifacts"])
    return {"artifacts": all_artifacts}


def validator_artifact_report_pe_artifacts(report: dict) -> list:
    return [a for a in report["artifacts"] if a.get("kind") == "PE"]


def validator_artifact_report_with_tag(report: dict, tag: str) -> list:
    return [a for a in report["artifacts"] if tag in a.get("tags", [])]


# ---------------------------------------------------------------------------
# memory_artifact_dumper
# ---------------------------------------------------------------------------

def validator_memory_artifact_new(base_address: int, data: bytes, pid: int, prot: str) -> dict:
    """MemoryArtifact::new()"""
    return {"base_address": base_address, "data": data, "pid": pid, "prot": prot, "tags": []}


def validator_memory_artifact_shannon_entropy(data: bytes) -> float:
    return _shannon_entropy(data)


def validator_memory_artifact_detect_content(data: bytes) -> str:
    if data[:2] == b"MZ":
        return "PE header"
    if data[:4] == b"\x7fELF":
        return "ELF header"
    ent = _shannon_entropy(data)
    if ent > 7.5:
        return "encrypted/compressed"
    printable = sum(1 for b in data if 0x20 <= b <= 0x7E)
    if printable / max(len(data), 1) > 0.8:
        return "text/strings"
    return "binary blob"


def validator_memory_artifact_add_tag(artifact: dict, t: str):
    artifact["tags"].append(t)


def validator_memory_artifact_is_high_entropy(artifact: dict) -> bool:
    return _shannon_entropy(artifact["data"]) > 7.0


def validator_memory_artifact_is_executable_content(artifact: dict) -> bool:
    return "x" in artifact.get("prot", "") or artifact["data"][:2] == b"MZ" or artifact["data"][:4] == b"\x7fELF"


def validator_memory_artifact_read_cstring(artifact: dict, offset: int):
    data = artifact["data"]
    if offset >= len(data):
        return None
    end = data.find(b"\x00", offset)
    if end == -1:
        return None
    try:
        return data[offset:end].decode("utf-8", errors="replace")
    except Exception:
        return None


def validator_string_context_classify(s: str) -> str:
    if s.startswith(("http://", "https://", "ftp://")):
        return "URL"
    if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', s):
        return "IP"
    if re.match(r'^HKEY_', s) or s.startswith("HKLM\\") or s.startswith("HKCU\\"):
        return "RegistryKey"
    if re.match(r'^[A-Za-z]:\\', s) or s.startswith("/"):
        return "FilePath"
    try:
        import base64
        if len(s) > 8 and len(s) % 4 == 0:
            base64.b64decode(s)
            return "Base64"
    except Exception:
        pass
    return "Generic"


def validator_memory_dump_new(pid: int, process_name: str) -> dict:
    return {"pid": pid, "process_name": process_name, "regions": []}


def validator_memory_dump_add_region(dump: dict, region: dict):
    dump["regions"].append(region)


def validator_memory_dump_total_bytes(dump: dict) -> int:
    return sum(len(r["data"]) for r in dump["regions"])


def validator_memory_dump_executable_regions(dump: dict) -> list:
    return [r for r in dump["regions"] if validator_memory_artifact_is_executable_content(r)]


def validator_memory_artifact_dumper_new(config: dict) -> dict:
    return {"config": config, "dumps": {}}


def validator_memory_artifact_dumper_with_defaults() -> dict:
    return validator_memory_artifact_dumper_new({"min_size": 0x1000, "min_entropy": 6.5})


def validator_memory_artifact_dumper_ingest_region(dumper: dict, base: int, data: bytes, pid: int, prot: str):
    cfg = dumper["config"]
    if len(data) < cfg.get("min_size", 0):
        return None
    ent = _shannon_entropy(data)
    if ent < cfg.get("min_entropy", 0):
        return None
    artifact = validator_memory_artifact_new(base, data, pid, prot)
    dump = dumper["dumps"].setdefault(pid, validator_memory_dump_new(pid, f"pid_{pid}"))
    validator_memory_dump_add_region(dump, artifact)
    return artifact


def validator_memory_artifact_dumper_extract_strings(dumper: dict, artifact: dict) -> list:
    strings = validator_c2_extractor_extract_strings(artifact["data"])
    for s in strings:
        s["context"] = validator_string_context_classify(s["value"])
    return strings


def validator_memory_artifact_dumper_dumps(dumper: dict) -> list:
    return list(dumper["dumps"].values())


def validator_memory_artifact_dumper_dump_for_pid(dumper: dict, pid: int):
    return dumper["dumps"].get(pid)


def validator_memory_artifact_dumper_total_regions(dumper: dict) -> int:
    return sum(len(d["regions"]) for d in dumper["dumps"].values())


def validator_memory_artifact_dumper_build_summary(dumper: dict) -> str:
    procs = len(dumper["dumps"])
    regions = validator_memory_artifact_dumper_total_regions(dumper)
    total_bytes = sum(validator_memory_dump_total_bytes(d) for d in dumper["dumps"].values())
    high_ent = sum(
        1 for d in dumper["dumps"].values()
        for r in d["regions"] if validator_memory_artifact_is_high_entropy(r)
    )
    return (f"{procs} processes, {regions} regions, "
            f"{total_bytes} bytes total, {high_ent} high-entropy regions")


# ---------------------------------------------------------------------------
# network_artifact_extractor
# ---------------------------------------------------------------------------

def validator_network_artifact_new(kind: str, pid: int) -> dict:
    return {"kind": kind, "pid": pid, "payload": None, "tags": []}


def validator_network_artifact_with_payload(artifact: dict, payload: bytes) -> dict:
    artifact = dict(artifact)
    artifact["payload"] = payload
    return artifact


def validator_network_artifact_add_tag(artifact: dict, t: str):
    artifact["tags"].append(t)


def validator_c2_pattern_new(name: str, family: str) -> dict:
    return {"name": name, "family": family, "url_pattern": None, "ua_pattern": None,
            "host_pattern": None, "ports": set()}


def validator_c2_pattern_matches_url(pattern: dict, url: str) -> bool:
    p = pattern.get("url_pattern")
    return bool(re.search(p, url)) if p else False


def validator_c2_pattern_matches_ua(pattern: dict, ua: str) -> bool:
    p = pattern.get("ua_pattern")
    return bool(re.search(p, ua)) if p else False


def validator_c2_pattern_matches_host(pattern: dict, host: str) -> bool:
    p = pattern.get("host_pattern")
    return bool(re.search(p, host)) if p else False


def validator_c2_pattern_matches_port(pattern: dict, port: int) -> bool:
    return port in pattern.get("ports", set())


def validator_network_payload_detect_type(data: bytes):
    """NetworkPayload::detect_type() -> (&'static str, u8)"""
    if data[:4] in (b"HTTP", b"GET ", b"POST", b"HEAD"):
        return ("HTTP", 90)
    if data[:3] == b"\x16\x03":
        return ("TLS", 85)
    if len(data) >= 2 and data[0] == 0x17 and data[1] == 0x03:
        return ("TLS", 80)
    if len(data) >= 12 and data[2:4] in (b"\x01\x00", b"\x00\x00"):
        return ("DNS", 60)
    return ("Unknown", 0)


def validator_network_payload_new(session_id: int, direction: str, data: bytes, offset: int) -> dict:
    return {"session_id": session_id, "direction": direction, "data": data, "offset": offset}


def validator_network_artifact_extractor_new() -> dict:
    return {"artifacts": [], "c2_patterns": []}


def validator_network_artifact_extractor_add_c2_pattern(extractor: dict, p: dict):
    extractor["c2_patterns"].append(p)


def validator_network_artifact_extractor_add_default_patterns(extractor: dict):
    cs = validator_c2_pattern_new("CobaltStrike", "CobaltStrike")
    cs["ports"] = {443, 80, 8080, 8443}
    cs["ua_pattern"] = r"Mozilla/5\.0"
    extractor["c2_patterns"].append(cs)

    emotet = validator_c2_pattern_new("Emotet", "Emotet")
    emotet["ports"] = {80, 443, 7080, 8080, 8090}
    extractor["c2_patterns"].append(emotet)


def validator_network_artifact_extractor_record(extractor: dict, event: dict):
    extractor["artifacts"].append(event)


def validator_network_artifact_extractor_record_dns(extractor: dict, hostname: str, resolved: str, pid: int):
    art = validator_network_artifact_new("DNS", pid)
    art["hostname"] = hostname
    art["resolved"] = resolved
    validator_network_artifact_extractor_record(extractor, art)


def validator_network_artifact_extractor_record_tcp_connect(extractor: dict, dst_ip: str, dst_port: int, pid: int):
    art = validator_network_artifact_new("TCP", pid)
    art["dst_ip"] = dst_ip
    art["dst_port"] = dst_port
    validator_network_artifact_extractor_record(extractor, art)


def validator_network_artifact_extractor_record_http(extractor: dict, method: str, url: str, host: str, pid: int):
    art = validator_network_artifact_new("HTTP", pid)
    art["method"] = method
    art["url"] = url
    art["host"] = host
    validator_network_artifact_extractor_record(extractor, art)


def validator_network_artifact_extractor_build_report(extractor: dict) -> dict:
    c2_hits = []
    for art in extractor["artifacts"]:
        for pat in extractor["c2_patterns"]:
            port = art.get("dst_port", 0)
            host = art.get("host", art.get("dst_ip", ""))
            if (validator_c2_pattern_matches_port(pat, port) or
                    validator_c2_pattern_matches_host(pat, host)):
                c2_hits.append({"pattern": pat["name"], "artifact": art})
                break
    return {
        "artifacts": extractor["artifacts"],
        "c2_hits": c2_hits,
        "total": len(extractor["artifacts"]),
    }


# ---------------------------------------------------------------------------
# malware_config_db
# ---------------------------------------------------------------------------

BUILTIN_FAMILIES = ["AgentTesla", "Remcos", "NjRAT", "RedLine", "AsyncRAT",
                    "QuasarRAT", "NetWire", "Nanocore", "Lokibot", "FormBook"]


def validator_extracted_config_field(config: dict, name: str):
    """ExtractedConfig::field()"""
    return config.get("fields", {}).get(name)


def validator_extracted_config_unique_c2s(config: dict) -> list:
    """ExtractedConfig::unique_c2s()"""
    return list(set(config.get("c2_servers", [])))


def validator_config_db_new() -> dict:
    return {"extractors": BUILTIN_FAMILIES[:]}


def validator_config_db_extractor_count(db: dict) -> int:
    return len(db["extractors"])


def validator_config_db_family_names(db: dict) -> list:
    return list(db["extractors"])


def validator_config_db_identify(db: dict, data: bytes) -> list:
    text = data.lower()
    found = []
    for family in db["extractors"]:
        if family.lower().encode() in text:
            found.append(family)
    return found


def validator_config_db_extract_all(db: dict, data: bytes) -> list:
    results = []
    for family in db["extractors"]:
        result = validator_config_db_extract_for_family(db, family, data)
        results.append(result)
    return results


def validator_config_db_extract_for_family(db: dict, family: str, data: bytes) -> dict:
    """ConfigDb::extract_for_family()"""
    config = {"family": family, "fields": {}, "c2_servers": []}
    # Generic: pull URLs and IPs
    text = data.decode(errors="replace")
    urls = validator_c2_extractor_extract_urls(text)
    config["c2_servers"] = urls
    ip_ports = validator_c2_extractor_extract_ip_ports(text)
    if ip_ports:
        config["c2_servers"].extend(f"{ip}:{port}" for ip, port in ip_ports)
    return config


def validator_config_db_register(db: dict, family_name: str):
    """ConfigDb::register() — simplified: register by name string."""
    db["extractors"].append(family_name)


# ---------------------------------------------------------------------------
# ransomware_detector
# ---------------------------------------------------------------------------

RANSOM_API_PATTERNS = {
    "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "BCryptEncrypt",
    "NtQuerySystemInformation", "DeleteFile", "MoveFileEx",
    "CreateFileW", "WriteFile",
}
SHADOW_DELETE_CMDS = [
    r"vssadmin.*delete.*shadows",
    r"wmic.*shadowcopy.*delete",
    r"bcdedit.*recoveryenabled.*no",
    r"wbadmin.*delete.*catalog",
    r"Get-WmiObject.*Win32_ShadowCopy.*Delete",
]
RANSOM_STRING_PATTERNS = [
    r"your files.{0,50}encrypt",
    r"bitcoin",
    r"decrypt",
    r"\.(locky|ryuk|cerber|wannacry|petya|maze|conti|revil|lockbit)",
    r"\.onion",
    r"readme.*txt",
]

ENCRYPTED_EXTENSIONS = [
    r"\.(locky|zepto|odin|shit|thor|aesir|zzzzz)$",
    r"\.(cerber|cerber2|cerber3)$",
    r"\.(ryuk|RYK)$",
    r"\.(wannacry|wcry|wncry)$",
    r"\.(petya|petrwrap|notpetya)$",
    r"\.(maze|m4z3|MAZE)$",
    r"\.(conti|CONTI)$",
    r"\.(revil|sodinokibi|REvil)$",
    r"\.(lockbit|lock|LOCK)$",
    r"\.[a-z0-9]{4,8}$",  # generic random extension
]


def validator_ransomware_detector_analyze_strings(strings: list) -> dict:
    """RansomwareDetector::analyze_strings()"""
    hits = []
    for s in strings:
        for pat in RANSOM_STRING_PATTERNS:
            if re.search(pat, s, re.IGNORECASE):
                hits.append({"pattern": pat, "string": s})
    score = min(1.0, len(hits) / 5.0)
    return {"hits": hits, "score": score, "is_ransomware": score > 0.3}


def validator_ransomware_detector_analyze_binary(data: bytes) -> dict:
    """RansomwareDetector::analyze_binary()"""
    strings = [s["value"] for s in validator_c2_extractor_extract_strings(data)]
    return validator_ransomware_detector_analyze_strings(strings)


def validator_ransomware_detector_analyze_api_calls(api_names: list) -> dict:
    """RansomwareDetector::analyze_api_calls()"""
    hits = [a for a in api_names if a in RANSOM_API_PATTERNS]
    shadow = [a for a in api_names if "shadow" in a.lower() or "vssadmin" in a.lower()]
    score = min(1.0, (len(hits) + len(shadow) * 2) / 10.0)
    return {"api_hits": hits, "shadow_hits": shadow, "score": score, "is_ransomware": score > 0.3}


def validator_extension_patterns_encrypted_extension_patterns() -> list:
    return ENCRYPTED_EXTENSIONS


def validator_extension_patterns_matches_encrypted_extension(name: str) -> bool:
    for pat in ENCRYPTED_EXTENSIONS:
        if re.search(pat, name, re.IGNORECASE):
            return True
    return False


# ---------------------------------------------------------------------------
# ransomware_analysis
# ---------------------------------------------------------------------------

RANSOMWARE_FAMILIES_DB = {
    "Locky": [".locky", ".zepto", ".odin"],
    "Ryuk": [".ryuk", ".RYK"],
    "WannaCry": [".wannacry", ".wcry", ".wncry"],
    "Maze": [".maze"],
    "Conti": [".conti"],
    "REvil": [".revil", ".sodinokibi"],
    "LockBit": [".lockbit"],
}


def validator_ransomware_family_extensions(family_name: str) -> list:
    return RANSOMWARE_FAMILIES_DB.get(family_name, [])


def validator_encryption_detector_is_high_entropy(data: bytes) -> bool:
    return _shannon_entropy(data) > 7.5


def validator_encryption_detector_entropy(data: bytes) -> float:
    return _shannon_entropy(data)


def validator_encryption_detector_detect(api_calls: list, affected_files: list) -> dict:
    """EncryptionDetector::detect()"""
    crypto_apis = {"CryptEncrypt", "BCryptEncrypt", "CryptGenKey"}
    api_hits = [a for a in api_calls if a in crypto_apis]
    high_ent_files = [f for f in affected_files
                      if validator_encryption_detector_is_high_entropy(f.get("content", b""))]
    confidence = min(1.0, (len(api_hits) * 0.3 + len(high_ent_files) * 0.2))
    return {"api_hits": api_hits, "high_entropy_files": len(high_ent_files),
            "confidence": confidence, "detected": confidence > 0.2}


def validator_extension_change_detector_new(known_families: list, threshold: int) -> dict:
    return {"known_families": known_families, "threshold": threshold}


def validator_extension_change_detector_detect_changes(detector: dict, before: list, after: list) -> list:
    """ExtensionChangeDetector::detect_changes()"""
    before_map = {os.path.splitext(f)[0]: os.path.splitext(f)[1] for f in before}
    after_map = {os.path.splitext(f)[0]: os.path.splitext(f)[1] for f in after}
    changes = []
    for stem, old_ext in before_map.items():
        new_ext = after_map.get(stem)
        if new_ext and new_ext != old_ext:
            changes.append({"file": stem, "old_ext": old_ext, "new_ext": new_ext})
    return changes


def validator_extension_change_detector_extension_frequency(changes: list) -> dict:
    freq = defaultdict(int)
    for c in changes:
        freq[c["new_ext"]] += 1
    return dict(freq)


def validator_extension_change_detector_identify_family(changes: list):
    """ExtensionChangeDetector::identify_family()"""
    freq = validator_extension_change_detector_extension_frequency(changes)
    for ext in freq:
        for family, exts in RANSOMWARE_FAMILIES_DB.items():
            if ext.lower() in [e.lower() for e in exts]:
                return family
    return None


def validator_shadow_deletion_detector_detect_in_cmdlines(cmdlines: list) -> list:
    """ShadowDeletionDetector::detect_in_cmdlines()"""
    evidences = []
    for cmd in cmdlines:
        for pat in SHADOW_DELETE_CMDS:
            if re.search(pat, cmd, re.IGNORECASE):
                evidences.append({"cmdline": cmd, "pattern": pat, "confidence": "High"})
                break
    return evidences


def validator_shadow_deletion_evidence_high_confidence(cmdline: str, tool: str) -> dict:
    return {"cmdline": cmdline, "tool": tool, "confidence": "High"}


def validator_ransom_note_parser_new(content: str, source_path: str) -> dict:
    return {"content": content, "source_path": source_path}


def validator_ransom_note_parser_is_valid_format(parser: dict) -> bool:
    keywords = ["bitcoin", "decrypt", "contact", "payment", "wallet", "btc", "files"]
    text = parser["content"].lower()
    return sum(1 for kw in keywords if kw in text) >= 2


def validator_wallet_extractor_extract(strings: list) -> list:
    """WalletExtractor::extract()"""
    wallets = []
    btc_re = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
    eth_re = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
    xmr_re = re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b')
    for s in strings:
        for m in btc_re.finditer(s):
            wallets.append({"type": "Bitcoin", "address": m.group(0)})
        for m in eth_re.finditer(s):
            wallets.append({"type": "Ethereum", "address": m.group(0)})
        for m in xmr_re.finditer(s):
            wallets.append({"type": "Monero", "address": m.group(0)})
    return wallets


def validator_ransom_note_analyzer_new(notes: list, wallets: list, deadline_ts) -> dict:
    return {"notes": notes, "wallets": wallets, "deadline_ts": deadline_ts}


def validator_ransom_note_analyzer_has_deadline(analyzer: dict) -> bool:
    if analyzer["deadline_ts"] is not None:
        return True
    countdown_re = re.compile(r'\b\d+\s*(hour|day|minute)', re.IGNORECASE)
    return any(countdown_re.search(n.get("content", "")) for n in analyzer["notes"])


def validator_ransom_note_analyzer_mentions_data_leak(analyzer: dict) -> bool:
    keywords = ["publish", "leak", "expose", "release", "double extortion", "data site"]
    for n in analyzer["notes"]:
        text = n.get("content", "").lower()
        if any(kw in text for kw in keywords):
            return True
    return False


def validator_ransom_note_analyzer_summary(analyzer: dict) -> str:
    wallets = ", ".join(w["address"] for w in analyzer["wallets"]) or "none"
    deadline = str(analyzer["deadline_ts"]) if analyzer["deadline_ts"] else "unknown"
    leak = validator_ransom_note_analyzer_mentions_data_leak(analyzer)
    return f"wallets=[{wallets}] deadline={deadline} double_extortion={leak}"


def validator_ransomware_analysis_report_compute_confidence(report: dict):
    """RansomwareAnalysisReport::compute_confidence() — mutates in place."""
    signals = [
        report.get("encryption_detected", False),
        report.get("shadow_deletion", False),
        len(report.get("extension_changes", [])) > 5,
        bool(report.get("ransom_notes")),
        bool(report.get("wallets")),
    ]
    report["confidence"] = sum(signals) / len(signals)


def validator_ransomware_analysis_report_mock() -> dict:
    report = {
        "encryption_detected": True,
        "shadow_deletion": True,
        "extension_changes": ["file.docx -> file.locky"] * 10,
        "ransom_notes": ["YOUR FILES HAVE BEEN ENCRYPTED. Pay Bitcoin to decrypt."],
        "wallets": [{"type": "Bitcoin", "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf"}],
        "confidence": 0.0,
    }
    validator_ransomware_analysis_report_compute_confidence(report)
    return report


# ---------------------------------------------------------------------------
# lib.rs core types
# ---------------------------------------------------------------------------

def validator_lib_dropped_file_new(path: str, size: int, sha256: str) -> dict:
    return {"path": path, "size": size, "sha256": sha256, "magic": b""}


def validator_lib_dropped_file_extension(f: dict) -> str:
    return os.path.splitext(f["path"])[1]


def validator_lib_dropped_file_is_pe(f: dict) -> bool:
    return f.get("magic", b"")[:2] == b"MZ" or f["path"].lower().endswith((".exe", ".dll"))


def validator_lib_dropped_file_is_elf(f: dict) -> bool:
    return f.get("magic", b"")[:4] == b"\x7fELF" or f["path"].lower().endswith(".elf")


def validator_lib_dropped_file_is_zip(f: dict) -> bool:
    return f.get("magic", b"")[:4] == b"PK\x03\x04" or f["path"].lower().endswith(".zip")


def validator_lib_dropped_file_is_executable(f: dict) -> bool:
    return (validator_lib_dropped_file_is_pe(f) or validator_lib_dropped_file_is_elf(f)
            or f["path"].lower().endswith((".ps1", ".bat", ".vbs", ".sh", ".py")))


def validator_lib_dropped_file_preview_entropy(f: dict) -> float:
    return _shannon_entropy(f.get("magic", b""))


def validator_lib_memory_dump_new(pid: int, label: str, start_va: int, data: bytes) -> dict:
    return {"pid": pid, "label": label, "start_va": start_va, "data": data}


def validator_lib_memory_dump_has_pe_header(dump: dict) -> bool:
    return dump["data"][:2] == b"MZ"


def validator_lib_memory_dump_entropy(dump: dict) -> float:
    return _shannon_entropy(dump["data"])


def validator_lib_memory_dump_is_high_entropy(dump: dict) -> bool:
    return validator_lib_memory_dump_entropy(dump) > 7.0


def validator_lib_memory_dump_extract_strings(dump: dict, min_len: int) -> list:
    return [s["value"] for s in validator_c2_extractor_extract_strings(dump["data"], min_len)]


def validator_lib_network_capture_is_external(capture: dict) -> bool:
    dst = capture.get("dst_ip", "")
    cls = validator_classify_ip(dst)
    return cls == "Public"


def validator_lib_network_capture_is_likely_c2(capture: dict) -> bool:
    port = capture.get("dst_port", 0)
    c2_ports = {4444, 1337, 8080, 8443, 443, 80, 9999, 6666, 7777}
    return port in c2_ports or validator_lib_network_capture_is_external(capture)


def validator_lib_registry_op_is_persistence(op: dict) -> bool:
    PERSISTENCE_KEYS = [
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "SYSTEM\\CurrentControlSet\\Services",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    ]
    key = op.get("key", "")
    return any(pk.lower() in key.lower() for pk in PERSISTENCE_KEYS)


def validator_lib_process_spawn_is_shell(proc: dict) -> bool:
    image = os.path.basename(proc.get("image_path", "")).lower()
    return image in ("cmd.exe", "powershell.exe", "pwsh.exe")


def validator_lib_process_spawn_is_lolbin(proc: dict) -> bool:
    image = os.path.basename(proc.get("image_path", "")).lower()
    return image in LOLBINS


def validator_packer_layer_new(name: str, entropy: float, base_va: int, size: int) -> dict:
    return {"name": name, "entropy": entropy, "base_va": base_va, "size": size}


def validator_packer_layer_is_high_entropy(layer: dict) -> bool:
    return layer["entropy"] > 7.2


def validator_packer_detector_new() -> dict:
    return {"patterns": ["UPX", "Themida", "MPRESS", "ASPack"]}


def validator_packer_detector_detect(detector: dict, data: bytes) -> list:
    layers = []
    if b"UPX!" in data or b"UPX0" in data:
        layers.append(validator_packer_layer_new("UPX", _shannon_entropy(data), 0, len(data)))
    if b"Themida" in data or b"WinLicense" in data:
        layers.append(validator_packer_layer_new("Themida", _shannon_entropy(data), 0, len(data)))
    ent = _shannon_entropy(data)
    if ent > 7.5 and not layers:
        layers.append(validator_packer_layer_new("Unknown", ent, 0, len(data)))
    return layers


def validator_lib_extracted_config_new(family: str, source: str) -> dict:
    return {"family": family, "source": source, "fields": {}}


def validator_lib_extracted_config_add_field(config: dict, key: str, value: str):
    config["fields"][key] = value


def validator_lib_extracted_config_field(config: dict, key: str):
    return config["fields"].get(key)


def validator_config_extractor_extract_from_strings(strings: list, family_hint: str) -> dict:
    config = validator_lib_extracted_config_new(family_hint, "strings")
    for s in strings:
        if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}:\d+$', s):
            validator_lib_extracted_config_add_field(config, "c2", s)
        elif s.startswith(("http://", "https://")):
            validator_lib_extracted_config_add_field(config, "url", s)
    return config


def validator_config_extractor_extract_from_dump(dump: dict, family_hint: str) -> dict:
    strings = validator_lib_memory_dump_extract_strings(dump, 6)
    return validator_config_extractor_extract_from_strings(strings, family_hint)


def validator_artifact_new(kind: str, pid: int, desc: str) -> dict:
    return {"kind": kind, "pid": pid, "desc": desc}


def validator_sandbox_result_mock() -> dict:
    return {
        "artifacts": [], "files": [], "network": [], "registry": [],
        "processes": [], "memory_dumps": [], "credentials": [],
        "packer_layers": [], "configs": [],
    }


def validator_sandbox_result_add_artifact(result: dict, a: dict):
    result["artifacts"].append(a)


def validator_sandbox_result_add_file(result: dict, f: dict):
    result["files"].append(f)


def validator_sandbox_result_add_network(result: dict, n: dict):
    result["network"].append(n)


def validator_sandbox_result_add_registry(result: dict, r: dict):
    result["registry"].append(r)


def validator_sandbox_result_add_process(result: dict, p: dict):
    result["processes"].append(p)


def validator_sandbox_result_add_memory_dump(result: dict, d: dict):
    result["memory_dumps"].append(d)


def validator_sandbox_result_add_credential(result: dict, c: dict):
    result["credentials"].append(c)


def validator_sandbox_result_add_packer_layer(result: dict, l: dict):
    result["packer_layers"].append(l)


def validator_sandbox_result_add_config(result: dict, c: dict):
    result["configs"].append(c)


def validator_sandbox_result_external_connections(result: dict) -> list:
    return [n for n in result["network"] if validator_lib_network_capture_is_external(n)]


def validator_sandbox_result_dropped_executables(result: dict) -> list:
    return [f for f in result["files"] if validator_lib_dropped_file_is_executable(f)]


def validator_sandbox_result_persistence_ops(result: dict) -> list:
    return [r for r in result["registry"] if validator_lib_registry_op_is_persistence(r)]


def validator_sandbox_result_shell_spawns(result: dict) -> list:
    return [p for p in result["processes"] if validator_lib_process_spawn_is_shell(p)]


def validator_sandbox_result_lolbin_spawns(result: dict) -> list:
    return [p for p in result["processes"] if validator_lib_process_spawn_is_lolbin(p)]


def validator_sandbox_result_high_entropy_dumps(result: dict) -> list:
    return [d for d in result["memory_dumps"] if validator_lib_memory_dump_is_high_entropy(d)]


def validator_sandbox_result_pe_dumps(result: dict) -> list:
    return [d for d in result["memory_dumps"] if validator_lib_memory_dump_has_pe_header(d)]


def validator_lib_api_call_new(name: str, args: list) -> dict:
    return {"name": name, "args": args}


def validator_sandbox_session_new(sample_name: str, sha256: str) -> dict:
    return {"sample_name": sample_name, "sha256": sha256}


def validator_sandbox_session_mock() -> dict:
    return validator_sandbox_session_new("sample.exe", "a" * 64)


def validator_ioc_collection_new() -> dict:
    return {"ips": [], "domains": [], "urls": [], "hashes": [], "paths": []}


def validator_ioc_collection_deduplicate(col: dict):
    for k in col:
        col[k] = list(set(col[k]))


def validator_ioc_collection_merge(col: dict, other: dict):
    for k in col:
        col[k].extend(other.get(k, []))
    validator_ioc_collection_deduplicate(col)


def validator_ioc_collection_from_api_trace(calls: list) -> dict:
    col = validator_ioc_collection_new()
    for call in calls:
        for arg in call.get("args", []):
            if isinstance(arg, str):
                if arg.startswith(("http://", "https://")):
                    col["urls"].append(arg)
                elif re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', arg):
                    col["ips"].append(arg)
    validator_ioc_collection_deduplicate(col)
    return col


def validator_ioc_collection_from_network_pcap(pcap_bytes: bytes) -> dict:
    """Minimal pcap IOC extraction (stdlib only, no scapy)."""
    col = validator_ioc_collection_new()
    text = pcap_bytes.decode(errors="replace")
    for m in re.finditer(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text):
        col["ips"].append(m.group(0))
    for m in re.finditer(r'https?://[^\s"\'<>]+', text):
        col["urls"].append(m.group(0))
    validator_ioc_collection_deduplicate(col)
    return col


def validator_ioc_collection_from_dropped_files(files: list) -> dict:
    col = validator_ioc_collection_new()
    for f in files:
        col["hashes"].append(f.get("sha256", ""))
        col["paths"].append(f.get("path", ""))
    validator_ioc_collection_deduplicate(col)
    return col


def validator_malware_config_new(family: str) -> dict:
    return {"family": family, "c2_servers": [], "encryption_key": None, "extra": {}}


def validator_malware_config_add_c2(config: dict, server: str):
    config["c2_servers"].append(server)


def validator_malware_config_set_extra(config: dict, key: str, value: str):
    config["extra"][key] = value


def validator_malware_config_key_hex(config: dict):
    return config.get("encryption_key")


def validator_sandbox_artifact_new(path: str, kind: str, pid: int, size: int) -> dict:
    return {"path": path, "kind": kind, "pid": pid, "size": size}


def validator_sandbox_artifact_kind_from_extension(ext: str) -> str:
    mapping = {
        ".exe": "PE", ".dll": "PE", ".sys": "PE",
        ".ps1": "Script", ".bat": "Script", ".py": "Script",
        ".pcap": "Pcap", ".pcapng": "Pcap",
        ".json": "Report", ".xml": "Report",
        ".zip": "Archive",
    }
    return mapping.get(ext.lower(), "Unknown")


def validator_sandbox_event_new(ts_ms: int, pid: int, kind: str, detail: str) -> dict:
    return {"ts_ms": ts_ms, "pid": pid, "kind": kind, "detail": detail}


def validator_artifact_extractor_extract_dropped_files(events: list) -> list:
    return [{"path": e["detail"], "pid": e["pid"], "ts_ms": e["ts_ms"]}
            for e in events if "drop" in e.get("kind", "").lower()]


def validator_artifact_extractor_extract_network_payloads(events: list) -> list:
    return [{"data": e["detail"].encode(), "pid": e["pid"]}
            for e in events if "network" in e.get("kind", "").lower()]


def validator_artifact_extractor_extract_injected_code(events: list) -> list:
    return [{"data": e["detail"].encode(), "pid": e["pid"]}
            for e in events if "inject" in e.get("kind", "").lower()]


def validator_memory_region_new(pid: int, start_addr: int, size: int, perms: str) -> dict:
    return {"pid": pid, "start_addr": start_addr, "size": size, "perms": perms}


def validator_memory_region_is_executable(region: dict) -> bool:
    return "x" in region.get("perms", "")


def validator_memory_region_dump_executable_regions(regions: list, reader_fn) -> list:
    dumps = []
    for r in regions:
        if validator_memory_region_is_executable(r):
            data = reader_fn(r)
            dumps.append(validator_lib_memory_dump_new(r["pid"], f"0x{r['start_addr']:x}", r["start_addr"], data))
    return dumps


# ---------------------------------------------------------------------------
# Self-test / entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Quick smoke-test a subset of validators
    print("=== rustre-sandbox-extract validators smoke test ===")

    # file_op_histogram
    events = [{"op": "Write"}, {"op": "Read"}, {"op": "Write"}]
    assert validator_file_op_histogram(events) == {"Write": 2, "Read": 1}

    # classify_ip
    assert validator_classify_ip("127.0.0.1") == "Loopback"
    assert validator_classify_ip("8.8.8.8") == "Public"
    assert validator_classify_ip("192.168.1.1") == "Private"
    assert validator_classify_ip("not-an-ip") is None

    # threat_level_from_score
    assert validator_threat_level_from_score(9.0) == "Critical"
    assert validator_threat_level_from_score(3.0) == "Low"

    # dga_detector
    assert validator_dga_detector_is_dga("xqkzjvmnbp.com") is True
    assert validator_dga_detector_is_dga("google.com") is False

    # xor
    data = bytes([0x41 ^ 0xAA, 0x42 ^ 0xAA, 0x43 ^ 0xAA])
    assert validator_c2_extractor_try_xor_decode(data, 0xAA) == b"ABC"

    # sha256 / md5
    f = validator_dropped_file_new_dropper("/tmp/test.exe", b"MZ\x00\x00")
    assert len(validator_dropped_file_sha256_hex(f)) == 64

    # c2 channel
    ch = validator_c2_channel_new("192.168.1.100", 4444, "TCP")
    assert validator_c2_channel_address(ch) == "192.168.1.100:4444"
    assert validator_c2_channel_is_ip(ch) is True

    # packer detector
    det = validator_packer_detector_new()
    layers = validator_packer_detector_detect(det, b"UPX!" + b"\x00" * 100)
    assert any(l["name"] == "UPX" for l in layers)

    # ransomware note parser
    parser = validator_ransom_note_parser_new(
        "Your files have been encrypted. Send bitcoin to decrypt.", "/tmp/README.txt"
    )
    assert validator_ransom_note_parser_is_valid_format(parser) is True

    print("All smoke tests passed.")
    fn_count = sum(1 for name in dir() if name.startswith("validator_"))
    print(f"Total validator functions: {fn_count}")
