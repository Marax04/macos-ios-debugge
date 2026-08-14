"""Validator for rustre-triage.

Python stdlib equivalents of every public function documented in
reports/rustre-triage.md (104 functions across 13 modules).  Each
validator_NAME(input) -> output function is a ground-truth oracle that
can be compared directly against the Rust crate's output.

Modules covered
---------------
lib                     detect_file_kind, analyze_section_entropy, EntropyRating,
                        TriageResult, StringHeuristics, ElfTriageAnalyzer,
                        MachOTriageAnalyzer, PeTriageAnalyzer, TriageCoordinator
triage_pipeline         StageOutput, pipeline stages, TriagePipeline, PipelineRunResult
triage_report           ReportSection, TriageReport2, TriageReportBuilder
score_aggregator        ScoreSignal, AggregatedScore, ScoreAggregator, ScoreNormaliser,
                        ScoreTimeline, BatchScoreStats, ScoreDiff, TriageScore presets
heuristic_engine        HeuristicResult, HeuristicReport, HeuristicEngine
analyzer_registry       AnalysisResult, AnalyzerRegistry, RegistryRunResult
malware_classification  FuzzyHash, ImpHash, StringHash, FamilyDatabase, MalwareClassifier
mitre_mapper            MitreTechnique, TechniqueMatch, AttackMatrix, MitreMapper
pe_triage_extended      PeFeatures, detect_anomalies, PeTriageReport
static_analysis_triage  StaticTriageEngine
findcrypt               scan (crypto constant scanner)
family_db               FamilyDb
rapid_classifier / file_classifier  RapidClassifier, FileClassifier
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import struct
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Sequence, Tuple


# ===========================================================================
# lib.rs — core types
# ===========================================================================

# --- FileKind -----------------------------------------------------------------

FILE_KIND_PE32    = "Pe32"
FILE_KIND_PE64    = "Pe64"
FILE_KIND_ELF32   = "Elf32"
FILE_KIND_ELF64   = "Elf64"
FILE_KIND_MACHO   = "MachO"
FILE_KIND_APK     = "Apk"
FILE_KIND_DEX     = "Dex"
FILE_KIND_ZIP     = "Zip"
FILE_KIND_PDF     = "Pdf"
FILE_KIND_DOC     = "Doc"
FILE_KIND_UNKNOWN = "Unknown"


def validator_detect_file_kind(data: bytes) -> str:
    """detect_file_kind(data: &[u8]) -> FileKind

    Identifies file format via magic bytes (MZ, ELF, Mach-O, ZIP/APK, DEX,
    PDF, DOC).
    """
    if len(data) < 4:
        return FILE_KIND_UNKNOWN
    magic4 = data[:4]
    # PDF
    if data[:4] == b"%PDF":
        return FILE_KIND_PDF
    # DEX
    if data[:4] == b"dex\n":
        return FILE_KIND_DEX
    # ELF
    if magic4[:4] == b"\x7fELF":
        if len(data) >= 5:
            ei_class = data[4]
            if ei_class == 1:
                return FILE_KIND_ELF32
            if ei_class == 2:
                return FILE_KIND_ELF64
        return FILE_KIND_ELF32
    # Mach-O (BE and LE, 32/64)
    if magic4 in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                  b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        return FILE_KIND_MACHO
    # MZ → PE
    if magic4[:2] == b"MZ":
        if len(data) >= 0x40:
            pe_off = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_off + 6 <= len(data) and data[pe_off:pe_off+4] == b"PE\x00\x00":
                machine = struct.unpack_from("<H", data, pe_off + 4)[0]
                if machine == 0x8664 or machine == 0x0200:
                    return FILE_KIND_PE64
                return FILE_KIND_PE32
        return FILE_KIND_PE32
    # ZIP / APK (APK is a ZIP with specific content)
    if magic4[:4] == b"PK\x03\x04":
        # Heuristic: APK contains "classes.dex" inside
        if b"classes.dex" in data[:4096]:
            return FILE_KIND_APK
        return FILE_KIND_ZIP
    # DOC (OLE2 compound document)
    if magic4[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"[:4]:
        if len(data) >= 8 and data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            return FILE_KIND_DOC
    return FILE_KIND_UNKNOWN


# --- EntropyRating ------------------------------------------------------------

ENTROPY_RATING_VERY_LOW  = "VeryLow"
ENTROPY_RATING_LOW       = "Low"
ENTROPY_RATING_NORMAL    = "Normal"
ENTROPY_RATING_HIGH      = "High"
ENTROPY_RATING_VERY_HIGH = "VeryHigh"


def validator_entropy_rating_from_entropy(e: float) -> str:
    """EntropyRating::from_entropy(e: f64) -> EntropyRating

    Classifies entropy into 5 levels.
    Thresholds: <2 VeryLow, <4 Low, <6 Normal, <7 High, >=7 VeryHigh.
    """
    if e < 2.0:
        return ENTROPY_RATING_VERY_LOW
    if e < 4.0:
        return ENTROPY_RATING_LOW
    if e < 6.0:
        return ENTROPY_RATING_NORMAL
    if e < 7.0:
        return ENTROPY_RATING_HIGH
    return ENTROPY_RATING_VERY_HIGH


def _shannon(block: bytes) -> float:
    n = len(block)
    if n == 0:
        return 0.0
    counts = Counter(block)
    h = 0.0
    for c in counts.values():
        p = c / n
        h -= p * math.log2(p)
    return h


def validator_analyze_section_entropy(data: bytes) -> List[Dict]:
    """analyze_section_entropy(data: &[u8]) -> Vec<SectionEntropy>

    Splits data into 4 KiB blocks and computes Shannon entropy per block.
    Returns list of dicts with keys: offset, size, entropy, rating.
    """
    BLOCK = 4096
    out = []
    for i in range(0, len(data), BLOCK):
        chunk = data[i:i + BLOCK]
        e = _shannon(chunk)
        out.append({
            "offset": i,
            "size": len(chunk),
            "entropy": e,
            "rating": validator_entropy_rating_from_entropy(e),
        })
    return out


# --- TriageResult -------------------------------------------------------------

THREAT_LEVEL_CLEAN         = "Clean"
THREAT_LEVEL_INFORMATIONAL = "Informational"
THREAT_LEVEL_LOW           = "Low"
THREAT_LEVEL_MEDIUM        = "Medium"
THREAT_LEVEL_HIGH          = "High"
THREAT_LEVEL_CRITICAL      = "Critical"

_THREAT_ORDER = [
    THREAT_LEVEL_CLEAN,
    THREAT_LEVEL_INFORMATIONAL,
    THREAT_LEVEL_LOW,
    THREAT_LEVEL_MEDIUM,
    THREAT_LEVEL_HIGH,
    THREAT_LEVEL_CRITICAL,
]

_THREAT_DELTA = {
    THREAT_LEVEL_CLEAN: 0,
    THREAT_LEVEL_INFORMATIONAL: 5,
    THREAT_LEVEL_LOW: 15,
    THREAT_LEVEL_MEDIUM: 30,
    THREAT_LEVEL_HIGH: 50,
    THREAT_LEVEL_CRITICAL: 80,
}


def validator_triage_result_new(file_kind: str, data: bytes) -> Dict:
    """TriageResult::new(file_kind: FileKind, data: &[u8]) -> TriageResult

    Builds an initial result computing SHA-256, MD5, and entropy.
    """
    sha256 = hashlib.sha256(data).hexdigest()
    md5    = hashlib.md5(data).hexdigest()
    entropy = _shannon(data)
    return {
        "file_kind": file_kind,
        "sha256": sha256,
        "md5": md5,
        "entropy": entropy,
        "score": 0,
        "threat_level": THREAT_LEVEL_CLEAN,
        "indicators": [],
        "all_strings": [],
        "crypto_hits": [],
    }


def validator_triage_result_add_indicator(result: Dict, indicator: Dict) -> None:
    """TriageResult::add_indicator(&mut self, indicator: TriageIndicator)

    Adds an indicator and updates score (capped 0–100) and threat_level.
    """
    result["indicators"].append(indicator)
    level = indicator.get("level", THREAT_LEVEL_INFORMATIONAL)
    delta = _THREAT_DELTA.get(level, 5)
    result["score"] = min(100, result["score"] + delta)
    score = result["score"]
    if score >= 80:
        result["threat_level"] = THREAT_LEVEL_CRITICAL
    elif score >= 60:
        result["threat_level"] = THREAT_LEVEL_HIGH
    elif score >= 40:
        result["threat_level"] = THREAT_LEVEL_MEDIUM
    elif score >= 20:
        result["threat_level"] = THREAT_LEVEL_LOW
    elif score >= 5:
        result["threat_level"] = THREAT_LEVEL_INFORMATIONAL
    else:
        result["threat_level"] = THREAT_LEVEL_CLEAN


def validator_triage_result_is_malicious(result: Dict) -> bool:
    """TriageResult::is_malicious(&self) -> bool

    True if threat_level >= High.
    """
    return _THREAT_ORDER.index(result["threat_level"]) >= _THREAT_ORDER.index(THREAT_LEVEL_HIGH)


def validator_triage_result_to_report(result: Dict, strings: List[Dict]) -> Dict:
    """TriageResult::to_report(&self, strings: Vec<SuspiciousString>) -> TriageReport"""
    return {
        "file_kind": result["file_kind"],
        "sha256": result["sha256"],
        "md5": result["md5"],
        "entropy": result["entropy"],
        "score": result["score"],
        "threat_level": result["threat_level"],
        "indicators": result["indicators"],
        "suspicious_strings": strings,
        "crypto_hits": result.get("crypto_hits", []),
    }


def validator_triage_result_to_json(result: Dict) -> str:
    """TriageResult::to_json(&self) -> Result<String, serde_json::Error>"""
    return json.dumps(result, indent=2)


def validator_triage_report_render_text(report: Dict) -> str:
    """TriageReport::render_text(&self) -> String"""
    lines = [
        f"File Kind : {report.get('file_kind', 'Unknown')}",
        f"SHA-256   : {report.get('sha256', '')}",
        f"MD5       : {report.get('md5', '')}",
        f"Entropy   : {report.get('entropy', 0.0):.4f}",
        f"Score     : {report.get('score', 0)}/100",
        f"Threat    : {report.get('threat_level', 'Clean')}",
        "",
        "--- Indicators ---",
    ]
    for ind in report.get("indicators", []):
        lines.append(f"  [{ind.get('level','?')}] {ind.get('name','?')}: {ind.get('description','')}")
    lines.append("")
    lines.append("--- Suspicious Strings ---")
    for s in report.get("suspicious_strings", []):
        lines.append(f"  [{s.get('category','?')}] {s.get('value','')}")
    return "\n".join(lines)


def validator_triage_report_render_json(report: Dict) -> str:
    """TriageReport::render_json(&self) -> Result<String, serde_json::Error>"""
    return json.dumps(report, indent=2)


def validator_triage_finding_new(kind: str, description: str) -> Dict:
    """TriageFinding::new(kind, description) -> Self"""
    return {"kind": kind, "description": description}


def validator_threat_scorer_score(findings: List[Dict]) -> int:
    """ThreatScorer::score(findings: &[TriageFinding]) -> u32 (0–100)

    Maps finding kinds to threat levels and sums deltas.
    """
    kind_map = {
        "packer": THREAT_LEVEL_HIGH,
        "anti_debug": THREAT_LEVEL_HIGH,
        "network": THREAT_LEVEL_MEDIUM,
        "crypto": THREAT_LEVEL_MEDIUM,
        "shellcode": THREAT_LEVEL_CRITICAL,
        "suspicious_import": THREAT_LEVEL_MEDIUM,
        "info": THREAT_LEVEL_INFORMATIONAL,
    }
    score = 0
    for f in findings:
        level = kind_map.get(f.get("kind", ""), THREAT_LEVEL_LOW)
        score += _THREAT_DELTA.get(level, 5)
    return min(100, score)


# --- TriagePipeline (legacy plugin API) ---------------------------------------

def validator_triage_pipeline_new() -> Dict:
    """TriagePipeline::new() -> Self (legacy plugin-based, empty)"""
    return {"plugins": []}


def validator_triage_pipeline_add_plugin(pipeline: Dict, plugin: object) -> None:
    """TriagePipeline::add_plugin(&mut self, p: Box<dyn TriagePlugin>)"""
    pipeline["plugins"].append(plugin)


def validator_triage_pipeline_run(pipeline: Dict, data: bytes) -> Dict:
    """TriagePipeline::run(&self, bytes: &[u8]) -> TriageReport (legacy)"""
    findings: List[Dict] = []
    for plugin in pipeline["plugins"]:
        if callable(plugin):
            findings.extend(plugin(data))
    score = validator_threat_scorer_score(findings)
    return {
        "file_kind": validator_detect_file_kind(data),
        "score": score,
        "threat_level": _score_to_threat(score),
        "indicators": findings,
        "suspicious_strings": [],
        "crypto_hits": [],
    }


def _score_to_threat(score: int) -> str:
    if score >= 80: return THREAT_LEVEL_CRITICAL
    if score >= 60: return THREAT_LEVEL_HIGH
    if score >= 40: return THREAT_LEVEL_MEDIUM
    if score >= 20: return THREAT_LEVEL_LOW
    if score >= 5:  return THREAT_LEVEL_INFORMATIONAL
    return THREAT_LEVEL_CLEAN


# --- StringHeuristics ---------------------------------------------------------

def validator_string_heuristics_extract_strings(data: bytes, min_len: int = 4) -> List[Dict]:
    """StringHeuristics::extract_strings(data: &[u8], min_len: usize) -> Vec<ExtractedString>

    Extracts ASCII and UTF-16 LE runs of at least min_len printable characters.
    """
    results: List[Dict] = []

    # ASCII
    pat_ascii = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
    for m in pat_ascii.finditer(data):
        results.append({
            "offset": m.start(),
            "value": m.group().decode("ascii", errors="replace"),
            "encoding": "Ascii",
            "virtual_address": None,
        })

    # UTF-16 LE: interleaved nulls
    i = 0
    buf = []
    start = 0
    while i < len(data) - 1:
        lo = data[i]
        hi = data[i + 1]
        if hi == 0 and 0x20 <= lo <= 0x7e:
            if not buf:
                start = i
            buf.append(chr(lo))
            i += 2
        else:
            if len(buf) >= min_len:
                results.append({
                    "offset": start,
                    "value": "".join(buf),
                    "encoding": "Utf16Le",
                    "virtual_address": None,
                })
            buf = []
            i += 1
    if len(buf) >= min_len:
        results.append({
            "offset": start,
            "value": "".join(buf),
            "encoding": "Utf16Le",
            "virtual_address": None,
        })

    return results


def validator_string_heuristics_extract_strings_with_va(
    data: bytes, min_len: int, sections: List[Tuple[int, int, int]]
) -> List[Dict]:
    """StringHeuristics::extract_strings_with_va

    Like extract_strings but resolves virtual address using
    sections = list of (file_offset, file_size, virtual_address).
    """
    strings = validator_string_heuristics_extract_strings(data, min_len)
    for s in strings:
        s["virtual_address"] = _resolve_va(s["offset"], sections)
    return strings


def _resolve_va(file_off: int, sections: List[Tuple[int, int, int]]) -> Optional[int]:
    for (fo, fsize, va) in sections:
        if fo <= file_off < fo + fsize:
            return va + (file_off - fo)
    return None


def validator_string_heuristics_extract_strings_with_sections(
    data: bytes, min_len: int, sections: List[Tuple[int, int, int]]
) -> List[Dict]:
    """StringHeuristics::extract_strings_with_sections

    Variant with (file_offset, file_size, virtual_address) descriptor.
    Identical to extract_strings_with_va.
    """
    return validator_string_heuristics_extract_strings_with_va(data, min_len, sections)


def validator_string_heuristics_extract_strings_auto_va(data: bytes, min_len: int) -> List[Dict]:
    """StringHeuristics::extract_strings_auto_va

    Auto-detects PE sections to populate VAs; falls back to plain extraction.
    """
    sections = _pe_sections(data)
    if sections:
        return validator_string_heuristics_extract_strings_with_va(data, min_len, sections)
    return validator_string_heuristics_extract_strings(data, min_len)


def _pe_sections(data: bytes) -> List[Tuple[int, int, int]]:
    """Parse PE section table → [(file_offset, file_size, virtual_address)]."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return []
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 24 > len(data) or data[pe_off:pe_off+4] != b"PE\x00\x00":
        return []
    num_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_size     = struct.unpack_from("<H", data, pe_off + 20)[0]
    section_off  = pe_off + 24 + opt_size
    sections = []
    for i in range(num_sections):
        base = section_off + i * 40
        if base + 40 > len(data):
            break
        vsize = struct.unpack_from("<I", data, base + 8)[0]
        va    = struct.unpack_from("<I", data, base + 12)[0]
        rsize = struct.unpack_from("<I", data, base + 16)[0]
        raw   = struct.unpack_from("<I", data, base + 20)[0]
        if rsize and raw:
            sections.append((raw, rsize, va))
    return sections


_URL_RE    = re.compile(r"https?://[\w./%-]{4,}", re.IGNORECASE)
_IP_RE     = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_REG_RE    = re.compile(r"HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)", re.IGNORECASE)
_B64_RE    = re.compile(r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_CRYPTO_KW = re.compile(r"\b(?:AES|RSA|SHA|MD5|HMAC|DES|RC4|Blowfish|ChaCha|ECB|CBC|GCM)\b", re.IGNORECASE)
_MALWARE_KW= re.compile(r"\b(?:VirtualAlloc|WriteProcessMemory|CreateRemoteThread|ShellExecute|WinExec|cmd\.exe|powershell|regsvr32|rundll32|mshta|wscript|cscript)\b", re.IGNORECASE)


def validator_string_heuristics_classify(strings: List[Dict]) -> List[Dict]:
    """StringHeuristics::classify(strings: &[ExtractedString]) -> Vec<SuspiciousString>"""
    out = []
    for s in strings:
        val = s.get("value", "")
        cat = None
        if _URL_RE.search(val):
            cat = "Url"
        elif _IP_RE.search(val):
            cat = "IpAddress"
        elif _REG_RE.search(val):
            cat = "RegistryKey"
        elif _CRYPTO_KW.search(val):
            cat = "CryptoRelated"
        elif _MALWARE_KW.search(val):
            cat = "MalwareIndicator"
        elif _B64_RE.search(val) and len(val) >= 20:
            cat = "Base64"
        if cat:
            out.append({
                "value": val,
                "category": cat,
                "offset": s.get("offset"),
                "threat_level": THREAT_LEVEL_MEDIUM,
            })
    return out


# --- Format-specific triage analyzers ----------------------------------------

def validator_elf_triage_analyzer_analyze(data: bytes, result: Dict) -> None:
    """ElfTriageAnalyzer::analyze(data: &[u8], result: &mut TriageResult)"""
    if data[:4] != b"\x7fELF":
        return
    # Check for INTERP segment (dynamic)
    if b"/lib/ld" in data or b"/lib64/ld" in data:
        validator_triage_result_add_indicator(result, {
            "name": "dynamic_elf",
            "description": "ELF uses dynamic linking",
            "level": THREAT_LEVEL_INFORMATIONAL,
            "category": "elf",
        })
    # Suspicious symbols
    sus_syms = [b"ptrace", b"mprotect", b"dlopen", b"system", b"execve"]
    for sym in sus_syms:
        if sym in data:
            validator_triage_result_add_indicator(result, {
                "name": "suspicious_symbol",
                "description": f"Suspicious symbol: {sym.decode()}",
                "level": THREAT_LEVEL_MEDIUM,
                "category": "elf",
            })


def validator_macho_triage_analyzer_analyze(data: bytes, result: Dict) -> None:
    """MachOTriageAnalyzer::analyze(data: &[u8], result: &mut TriageResult)"""
    magic4 = data[:4] if len(data) >= 4 else b""
    if magic4 not in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                      b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        return
    sus_libs = [b"libc.dylib", b"Security.framework", b"CoreFoundation"]
    for lib in sus_libs:
        if lib in data:
            validator_triage_result_add_indicator(result, {
                "name": "macho_load_library",
                "description": f"Mach-O loads: {lib.decode(errors='replace')}",
                "level": THREAT_LEVEL_INFORMATIONAL,
                "category": "macho",
            })


def validator_pe_triage_analyzer_analyze(data: bytes, result: Dict) -> None:
    """PeTriageAnalyzer::analyze(data: &[u8], result: &mut TriageResult)"""
    if len(data) < 2 or data[:2] != b"MZ":
        return
    # TLS callback
    if b".tls" in data.lower() or b"TlsCallback" in data:
        validator_triage_result_add_indicator(result, {
            "name": "tls_callback",
            "description": "PE has TLS callbacks (possible anti-debug)",
            "level": THREAT_LEVEL_MEDIUM,
            "category": "pe",
        })
    # Suspicious imports
    for api in [b"VirtualAlloc", b"WriteProcessMemory", b"CreateRemoteThread"]:
        if api in data:
            validator_triage_result_add_indicator(result, {
                "name": "suspicious_import",
                "description": f"Suspicious import: {api.decode()}",
                "level": THREAT_LEVEL_HIGH,
                "category": "pe_import",
            })


# --- TriageCoordinator --------------------------------------------------------

def validator_triage_coordinator_new() -> Dict:
    """TriageCoordinator::new() -> Self"""
    return {"pipeline": "default"}


def validator_triage_coordinator_analyze(coordinator: Dict, data: bytes) -> Dict:
    """TriageCoordinator::analyze(&self, data: &[u8]) -> Result<TriageResult, TriageError>"""
    kind = validator_detect_file_kind(data)
    result = validator_triage_result_new(kind, data)
    if kind in (FILE_KIND_PE32, FILE_KIND_PE64):
        validator_pe_triage_analyzer_analyze(data, result)
    elif kind in (FILE_KIND_ELF32, FILE_KIND_ELF64):
        validator_elf_triage_analyzer_analyze(data, result)
    elif kind == FILE_KIND_MACHO:
        validator_macho_triage_analyzer_analyze(data, result)
    return result


def validator_triage_coordinator_analyze_with_config(
    coordinator: Dict, data: bytes, config: Dict
) -> Dict:
    """TriageCoordinator::analyze_with_config(&self, data, config) -> Result<TriageResult, TriageError>"""
    result = validator_triage_coordinator_analyze(coordinator, data)
    max_score = config.get("max_score", 100)
    result["score"] = min(result["score"], max_score)
    return result


# ===========================================================================
# triage_pipeline.rs
# ===========================================================================

def validator_stage_output_empty(stage_name: str) -> Dict:
    """StageOutput::empty(stage_name) -> Self"""
    return {"stage": stage_name, "status": "ok", "indicators": [], "error": None, "skipped": False}


def validator_stage_output_skipped(stage_name: str, reason: str) -> Dict:
    """StageOutput::skipped(stage_name, reason) -> Self"""
    return {"stage": stage_name, "status": "skipped", "indicators": [], "error": None, "skipped": True, "reason": reason}


def validator_stage_output_failed(stage_name: str, error: str) -> Dict:
    """StageOutput::failed(stage_name, error) -> Self"""
    return {"stage": stage_name, "status": "failed", "indicators": [], "error": error, "skipped": False}


def validator_entropy_stage_new(threshold: float) -> Dict:
    """EntropyStage::new(threshold: f64) -> Self"""
    return {"kind": "EntropyStage", "threshold": threshold}


def _run_entropy_stage(stage: Dict, data: bytes) -> Dict:
    out = validator_stage_output_empty("EntropyStage")
    e = _shannon(data)
    if e >= stage["threshold"]:
        out["indicators"].append({
            "name": "high_entropy",
            "description": f"File entropy {e:.3f} exceeds threshold {stage['threshold']}",
            "level": THREAT_LEVEL_HIGH,
            "category": "entropy",
        })
    return out


def validator_string_analysis_stage_new(min_length: int, max_scan_bytes: int) -> Dict:
    """StringAnalysisStage::new(min_length, max_scan_bytes) -> Self"""
    return {"kind": "StringAnalysisStage", "min_length": min_length, "max_scan_bytes": max_scan_bytes}


def _run_string_analysis_stage(stage: Dict, data: bytes) -> Dict:
    out = validator_stage_output_empty("StringAnalysisStage")
    chunk = data[:stage["max_scan_bytes"]]
    strings = validator_string_heuristics_extract_strings(chunk, stage["min_length"])
    suspicious = validator_string_heuristics_classify(strings)
    for s in suspicious:
        out["indicators"].append({
            "name": "suspicious_string",
            "description": f"[{s['category']}] {s['value'][:80]}",
            "level": THREAT_LEVEL_MEDIUM,
            "category": "string",
        })
    return out


def validator_all_string_extraction_stage_new(min_length: int, max_scan_bytes: int) -> Dict:
    """AllStringExtractionStage::new(min_length, max_scan_bytes) -> Self"""
    return {"kind": "AllStringExtractionStage", "min_length": min_length, "max_scan_bytes": max_scan_bytes}


def _run_all_string_stage(stage: Dict, data: bytes, result: Dict) -> Dict:
    out = validator_stage_output_empty("AllStringExtractionStage")
    chunk = data[:stage["max_scan_bytes"]]
    strings = validator_string_heuristics_extract_strings(chunk, stage["min_length"])
    result.setdefault("all_strings", []).extend(strings)
    return out


# TriagePipeline (staged)

def validator_triage_pipeline_staged_new() -> Dict:
    """TriagePipeline::new() -> Self (staged variant)"""
    return {"stages": [], "stop_at": None}


def validator_triage_pipeline_default_pipeline() -> Dict:
    """TriagePipeline::default_pipeline() -> Self

    Pre-loaded with: FileKind, Entropy, Packer, String, AllString, Compiler,
    AntiAnalysis, Shellcode, CryptoConstant stages.
    """
    pipeline = validator_triage_pipeline_staged_new()
    pipeline["stages"] = [
        {"kind": "FileKindStage"},
        validator_entropy_stage_new(6.8),
        {"kind": "PackerStage"},
        validator_string_analysis_stage_new(4, 1 << 20),
        validator_all_string_extraction_stage_new(4, 1 << 20),
        {"kind": "CompilerStage"},
        {"kind": "AntiAnalysisStage"},
        {"kind": "ShellcodeStage"},
        {"kind": "CryptoConstantStage"},
    ]
    return pipeline


def validator_triage_pipeline_add_stage(pipeline: Dict, stage: Dict) -> None:
    """TriagePipeline::add_stage(&mut self, stage: Box<dyn PipelineStage>)"""
    pipeline["stages"].append(stage)


def validator_triage_pipeline_stop_at(pipeline: Dict, level: str) -> None:
    """TriagePipeline::stop_at(&mut self, level: ThreatLevel)"""
    pipeline["stop_at"] = level


def validator_triage_pipeline_staged_run(pipeline: Dict, data: bytes) -> Dict:
    """TriagePipeline::run(&self, data: &[u8]) -> Result<PipelineRunResult, TriageError>

    Runs all applicable stages respecting early-exit.
    """
    kind = validator_detect_file_kind(data)
    result = validator_triage_result_new(kind, data)
    stage_outputs: List[Dict] = []
    stop_at = pipeline.get("stop_at")

    for stage in pipeline["stages"]:
        sk = stage.get("kind", "")
        t0 = time.monotonic_ns()
        if sk == "EntropyStage":
            out = _run_entropy_stage(stage, data)
        elif sk == "StringAnalysisStage":
            out = _run_string_analysis_stage(stage, data)
        elif sk == "AllStringExtractionStage":
            out = _run_all_string_stage(stage, data, result)
        elif sk == "FileKindStage":
            out = validator_stage_output_empty("FileKindStage")
        else:
            out = validator_stage_output_empty(sk)
        elapsed_us = (time.monotonic_ns() - t0) // 1000
        out["elapsed_us"] = elapsed_us
        stage_outputs.append(out)
        for ind in out.get("indicators", []):
            validator_triage_result_add_indicator(result, ind)
        if stop_at and _THREAT_ORDER.index(result["threat_level"]) >= _THREAT_ORDER.index(stop_at):
            break

    return {
        "result": result,
        "stage_outputs": stage_outputs,
    }


def validator_pipeline_run_result_indicator_count(run: Dict) -> int:
    """PipelineRunResult::indicator_count(&self) -> usize"""
    return len(run["result"].get("indicators", []))


def validator_pipeline_run_result_stage_indicators(run: Dict, stage_name: str) -> List[Dict]:
    """PipelineRunResult::stage_indicators(&self, stage_name) -> Vec<&TriageIndicator>"""
    for out in run["stage_outputs"]:
        if out["stage"] == stage_name:
            return out.get("indicators", [])
    return []


def validator_pipeline_run_result_ran_stages(run: Dict) -> List[str]:
    """PipelineRunResult::ran_stages(&self) -> Vec<&str>"""
    return [o["stage"] for o in run["stage_outputs"] if o.get("status") == "ok"]


def validator_pipeline_run_result_total_stage_time_us(run: Dict) -> int:
    """PipelineRunResult::total_stage_time_us(&self) -> u64"""
    return sum(o.get("elapsed_us", 0) for o in run["stage_outputs"])


def validator_pipeline_run_result_summary(run: Dict) -> str:
    """PipelineRunResult::summary(&self) -> String"""
    r = run["result"]
    stages = len(run["stage_outputs"])
    total_us = validator_pipeline_run_result_total_stage_time_us(run)
    return (
        f"kind={r['file_kind']} threat={r['threat_level']} "
        f"score={r['score']} indicators={len(r['indicators'])} "
        f"stages={stages} time={total_us}us"
    )


# ===========================================================================
# triage_report.rs
# ===========================================================================

def validator_report_section_new(title: str) -> Dict:
    """ReportSection::new(title) -> Self"""
    return {"title": title, "lines": []}


def validator_report_section_push(section: Dict, line: str) -> None:
    """ReportSection::push(&mut self, line)"""
    section["lines"].append(line)


def validator_report_section_push_kv(section: Dict, key: str, value: str) -> None:
    """ReportSection::push_kv(&mut self, key, value)"""
    section["lines"].append(f"{key}: {value}")


def validator_report_section_render_text(section: Dict) -> str:
    """ReportSection::render_text(&self) -> String"""
    hdr = f"=== {section['title']} ==="
    return "\n".join([hdr] + section["lines"])


def validator_report_section_render_markdown(section: Dict) -> str:
    """ReportSection::render_markdown(&self) -> String"""
    hdr = f"## {section['title']}"
    return "\n".join([hdr] + section["lines"])


def validator_triage_report2_from_result(title: str, result: Dict) -> Dict:
    """TriageReport2::from_result(title, result: &TriageResult) -> Self"""
    summary_sec = validator_report_section_new("Summary")
    validator_report_section_push_kv(summary_sec, "Title", title)
    validator_report_section_push_kv(summary_sec, "FileKind", result["file_kind"])
    validator_report_section_push_kv(summary_sec, "SHA256", result["sha256"])
    validator_report_section_push_kv(summary_sec, "MD5", result["md5"])
    validator_report_section_push_kv(summary_sec, "Entropy", f"{result['entropy']:.4f}")
    validator_report_section_push_kv(summary_sec, "Score", str(result["score"]))
    validator_report_section_push_kv(summary_sec, "ThreatLevel", result["threat_level"])

    ind_sec = validator_report_section_new("Indicators")
    for ind in result.get("indicators", []):
        validator_report_section_push(ind_sec, f"[{ind.get('level','?')}] {ind.get('name','?')}: {ind.get('description','')}")

    return {
        "title": title,
        "result": result,
        "sections": [summary_sec, ind_sec],
        "sha256": result["sha256"],
        "md5": result["md5"],
        "indicators": result.get("indicators", []),
    }


def validator_triage_report2_indicators_by_level(report2: Dict) -> Dict[str, int]:
    """TriageReport2::indicators_by_level(&self) -> HashMap<String, usize>"""
    counts: Dict[str, int] = defaultdict(int)
    for ind in report2.get("indicators", []):
        counts[ind.get("level", "Unknown")] += 1
    return dict(counts)


def validator_triage_report2_render_text(report2: Dict) -> str:
    """TriageReport2::render_text(&self) -> String"""
    return "\n\n".join(validator_report_section_render_text(s) for s in report2["sections"])


def validator_triage_report2_render_markdown(report2: Dict) -> str:
    """TriageReport2::render_markdown(&self) -> String"""
    return "\n\n".join(validator_report_section_render_markdown(s) for s in report2["sections"])


def validator_triage_report2_render_csv(report2: Dict) -> str:
    """TriageReport2::render_csv(&self) -> String"""
    rows = ["level,name,description"]
    for ind in report2.get("indicators", []):
        rows.append(f"{ind.get('level','')},{ind.get('name','')},{ind.get('description','')}")
    return "\n".join(rows)


def validator_triage_report2_render_json(report2: Dict) -> str:
    """TriageReport2::render_json(&self) -> Result<String, serde_json::Error>"""
    return json.dumps(report2, indent=2)


def validator_triage_report2_render_html(report2: Dict) -> str:
    """TriageReport2::render_html(&self) -> String"""
    rows = "".join(
        f"<tr><td>{i.get('level','')}</td><td>{i.get('name','')}</td><td>{i.get('description','')}</td></tr>"
        for i in report2.get("indicators", [])
    )
    return (
        f"<html><body>"
        f"<h1>{report2.get('title','')}</h1>"
        f"<table><thead><tr><th>Level</th><th>Name</th><th>Description</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
        f"</body></html>"
    )


def validator_render_html_free(report2: Dict) -> str:
    """render_html(report: &TriageReport2) -> String (free function)"""
    return validator_triage_report2_render_html(report2)


# TriageReportBuilder

def validator_triage_report_builder_new(title: str) -> Dict:
    """TriageReportBuilder::new(title) -> Self"""
    return {"title": title, "sha256": None, "md5": None, "sections": [], "indicators": []}


def validator_triage_report_builder_sha256(builder: Dict, sha: str) -> Dict:
    """TriageReportBuilder::sha256(self, sha) -> Self"""
    builder["sha256"] = sha
    return builder


def validator_triage_report_builder_md5(builder: Dict, md5: str) -> Dict:
    """TriageReportBuilder::md5(self, md5) -> Self"""
    builder["md5"] = md5
    return builder


def validator_triage_report_builder_add_section(builder: Dict, section: Dict) -> Dict:
    """TriageReportBuilder::add_section(self, section) -> Self"""
    builder["sections"].append(section)
    return builder


def validator_triage_report_builder_add_indicator(builder: Dict, ind: Dict) -> Dict:
    """TriageReportBuilder::add_indicator(self, ind) -> Self"""
    builder["indicators"].append(ind)
    return builder


def validator_triage_report_builder_build(builder: Dict) -> Dict:
    """TriageReportBuilder::build(self) -> TriageReport2"""
    return {
        "title": builder["title"],
        "sha256": builder["sha256"],
        "md5": builder["md5"],
        "sections": builder["sections"],
        "indicators": builder["indicators"],
        "result": None,
    }


# ===========================================================================
# score_aggregator.rs
# ===========================================================================

def validator_score_signal_new(kind: str, raw: float, reason: str) -> Dict:
    """ScoreSignal::new(kind, raw, reason) -> Self"""
    _DEFAULT_WEIGHTS = {
        "entropy": 1.2, "packer": 1.5, "import": 1.0,
        "string": 0.8, "yara": 2.0, "crypto": 0.9,
    }
    return {"kind": kind, "raw": raw, "reason": reason,
            "weight": _DEFAULT_WEIGHTS.get(kind, 1.0), "signals": []}


def validator_score_signal_add_signal(signal: Dict, s: Dict) -> None:
    """ScoreSignal::add_signal(&mut self, s)"""
    signal["signals"].append(s)


def validator_score_signal_weighted(signal: Dict) -> float:
    """ScoreSignal::weighted(&self) -> f64"""
    return signal["raw"] * signal["weight"]


def validator_analyzer_score_new(name: str, value: float, description: str) -> Dict:
    """AnalyzerScore::new(name, value, description) -> Self"""
    return {"name": name, "value": value, "description": description}


def validator_aggregated_score_compute(scores: List[float]) -> Dict:
    """AggregatedScore::compute(scores: &[f64]) -> Self"""
    if not scores:
        return {"score": 0.0, "classification": "Clean"}
    avg = sum(scores) / len(scores)
    if avg >= 70.0:
        cls = "Malicious"
    elif avg >= 40.0:
        cls = "Suspicious"
    else:
        cls = "Clean"
    return {"score": avg, "classification": cls}


def validator_aggregated_score_is_malicious(agg: Dict) -> bool:
    """AggregatedScore::is_malicious(&self) -> bool"""
    return agg["classification"] == "Malicious"


def validator_aggregated_score_is_suspicious(agg: Dict) -> bool:
    """AggregatedScore::is_suspicious(&self) -> bool"""
    return agg["classification"] == "Suspicious"


def validator_aggregated_score_is_clean(agg: Dict) -> bool:
    """AggregatedScore::is_clean(&self) -> bool"""
    return agg["classification"] == "Clean"


def validator_aggregated_score_summary(agg: Dict) -> str:
    """AggregatedScore::summary(&self) -> String"""
    return f"score={agg['score']:.1f} classification={agg['classification']}"


def validator_score_aggregator_new() -> Dict:
    """ScoreAggregator::new() -> Self"""
    return {"weights": {"entropy": 1.2, "packer": 1.5, "import": 1.0, "string": 0.8, "yara": 2.0}}


def validator_score_aggregator_set_weight(agg: Dict, kind: str, weight: float) -> None:
    """ScoreAggregator::set_weight(&mut self, kind, weight)"""
    agg["weights"][kind] = weight


def validator_score_aggregator_aggregate(aggregator: Dict, scores: List[Dict]) -> Dict:
    """ScoreAggregator::aggregate(&self, scores) -> AggregatedScore

    Weighted aggregation of TriageScore list (each has 'kind' and 'value').
    """
    if not scores:
        return validator_aggregated_score_compute([])
    weighted_vals = []
    for s in scores:
        w = aggregator["weights"].get(s.get("kind", ""), 1.0)
        weighted_vals.append(s.get("value", 0.0) * w)
    avg = sum(weighted_vals) / len(weighted_vals) if weighted_vals else 0.0
    return validator_aggregated_score_compute([avg])


def validator_score_aggregator_aggregate_with_entropy_penalty(
    aggregator: Dict, scores: List[Dict], entropy: float
) -> Dict:
    """ScoreAggregator::aggregate_with_entropy_penalty"""
    base = validator_score_aggregator_aggregate(aggregator, scores)
    penalty = max(0.0, (entropy - 6.5) * 10.0)
    return validator_aggregated_score_compute([base["score"] + penalty])


def validator_score_aggregator_aggregate_with_yara_boost(
    aggregator: Dict, scores: List[Dict], yara_hits: int
) -> Dict:
    """ScoreAggregator::aggregate_with_yara_boost"""
    base = validator_score_aggregator_aggregate(aggregator, scores)
    boost = yara_hits * 15.0
    return validator_aggregated_score_compute([base["score"] + boost])


def validator_score_normaliser_normalise(value: float, lo: float, hi: float) -> int:
    """ScoreNormaliser::normalise(value, lo, hi) -> u8 (0–100)"""
    if hi <= lo:
        return 0
    n = (value - lo) / (hi - lo) * 100.0
    return max(0, min(100, int(n)))


def validator_score_normaliser_max_normalise(scores: List[float], max_possible: float) -> int:
    """ScoreNormaliser::max_normalise(scores, max_possible) -> u8"""
    if not scores or max_possible <= 0:
        return 0
    total = sum(scores)
    return max(0, min(100, int(total / max_possible * 100.0)))


def validator_score_normaliser_from_entropy(entropy: float) -> int:
    """ScoreNormaliser::from_entropy(entropy) -> u8"""
    return validator_score_normaliser_normalise(entropy, 0.0, 8.0)


def validator_score_normaliser_from_import_count(suspicious: int, total: int) -> int:
    """ScoreNormaliser::from_import_count(suspicious, total) -> u8"""
    if total == 0:
        return 0
    return max(0, min(100, int(suspicious / total * 100)))


def validator_score_timeline_new(capacity: int) -> Dict:
    """ScoreTimeline::new(capacity) -> Self"""
    return {"capacity": capacity, "points": []}


def validator_score_timeline_push(timeline: Dict, timestamp: int, score: int) -> None:
    """ScoreTimeline::push(&mut self, timestamp, score)"""
    timeline["points"].append({"timestamp": timestamp, "score": score})
    if len(timeline["points"]) > timeline["capacity"]:
        timeline["points"].pop(0)


def validator_score_timeline_average(timeline: Dict) -> float:
    """ScoreTimeline::average(&self) -> f64"""
    pts = timeline["points"]
    if not pts:
        return 0.0
    return sum(p["score"] for p in pts) / len(pts)


def validator_score_timeline_trend(timeline: Dict) -> float:
    """ScoreTimeline::trend(&self) -> f64 (positive = worsening)"""
    pts = timeline["points"]
    if len(pts) < 2:
        return 0.0
    return (pts[-1]["score"] - pts[0]["score"]) / len(pts)


def validator_score_timeline_max_score(timeline: Dict) -> int:
    """ScoreTimeline::max_score(&self) -> u8"""
    pts = timeline["points"]
    if not pts:
        return 0
    return max(p["score"] for p in pts)


def validator_batch_score_stats_new() -> Dict:
    """BatchScoreStats::new() -> Self"""
    return {"results": []}


def validator_batch_score_stats_add(stats: Dict, result: Dict) -> None:
    """BatchScoreStats::add(&mut self, result: AggregatedScore)"""
    stats["results"].append(result)


def validator_batch_score_stats_average_score(stats: Dict) -> float:
    """BatchScoreStats::average_score(&self) -> f64"""
    r = stats["results"]
    if not r:
        return 0.0
    return sum(x["score"] for x in r) / len(r)


def validator_batch_score_stats_malicious_rate(stats: Dict) -> float:
    """BatchScoreStats::malicious_rate(&self) -> f64"""
    r = stats["results"]
    if not r:
        return 0.0
    return sum(1 for x in r if x["classification"] == "Malicious") / len(r)


def validator_batch_score_stats_summary(stats: Dict) -> str:
    """BatchScoreStats::summary(&self) -> String"""
    n = len(stats["results"])
    avg = validator_batch_score_stats_average_score(stats)
    rate = validator_batch_score_stats_malicious_rate(stats)
    return f"batch count={n} avg_score={avg:.1f} malicious_rate={rate:.2%}"


def validator_score_diff_new(before: Dict, after: Dict) -> Dict:
    """ScoreDiff::new(before, after) -> Self"""
    delta = after["score"] - before["score"]
    return {
        "before": before,
        "after": after,
        "delta": delta,
        "improved": delta < 0,
        "worsened": delta > 0,
    }


# TriageScore presets

def validator_triage_score_clean() -> Dict:
    """TriageScore::clean() -> TriageScore"""
    return {"kind": "clean", "value": 0.0, "reason": "File appears clean"}


def validator_triage_score_upx_packed() -> Dict:
    """TriageScore::upx_packed() -> TriageScore"""
    return {"kind": "packer", "value": 75.0, "reason": "UPX packing detected"}


def validator_triage_score_vmprotect() -> Dict:
    """TriageScore::vmprotect() -> TriageScore"""
    return {"kind": "packer", "value": 90.0, "reason": "VMProtect protection detected"}


def validator_triage_score_high_entropy(entropy: float) -> Dict:
    """TriageScore::high_entropy(entropy) -> TriageScore"""
    return {"kind": "entropy", "value": min(100.0, (entropy - 6.0) * 25.0), "reason": f"High entropy: {entropy:.3f}"}


def validator_triage_score_yara_matches(count: int, max_severity: int) -> Dict:
    """TriageScore::yara_matches(count, max_severity) -> TriageScore"""
    return {"kind": "yara", "value": min(100.0, count * max_severity * 5.0), "reason": f"{count} YARA matches (max sev={max_severity})"}


def validator_triage_score_suspicious_imports(suspicious: int, total: int) -> Dict:
    """TriageScore::suspicious_imports(suspicious, total) -> TriageScore"""
    ratio = suspicious / total if total else 0.0
    return {"kind": "import", "value": ratio * 100.0, "reason": f"{suspicious}/{total} suspicious imports"}


def validator_filter_scores(scores: List[Dict], min_raw: float) -> List[Dict]:
    """filter_scores(scores, min_raw) -> Vec<&TriageScore>"""
    return [s for s in scores if s.get("value", 0.0) >= min_raw]


def validator_dedup_scores(scores: List[Dict]) -> List[Dict]:
    """dedup_scores(scores) -> Vec<TriageScore>"""
    seen: Dict[str, Dict] = {}
    for s in scores:
        k = s.get("kind", "")
        if k not in seen or s.get("value", 0.0) > seen[k].get("value", 0.0):
            seen[k] = s
    return list(seen.values())


def validator_score_card_from_aggregated(agg: Dict) -> Dict:
    """ScoreCard::from_aggregated(a) -> Self"""
    return {"score": agg["score"], "classification": agg["classification"],
            "summary": validator_aggregated_score_summary(agg)}


def validator_score_card_to_json(card: Dict) -> str:
    """ScoreCard::to_json(&self) -> serde_json::Result<String>"""
    return json.dumps(card, indent=2)


def validator_score_card_to_text(card: Dict) -> str:
    """ScoreCard::to_text(&self) -> String"""
    return f"ScoreCard | {card['summary']}"


# ===========================================================================
# heuristic_engine.rs
# ===========================================================================

def validator_heuristic_result_fired(hid: str, name: str, threat: str, evidence: str) -> Dict:
    """HeuristicResult::fired(id, name, threat, evidence) -> Self"""
    return {"id": hid, "name": name, "threat": threat, "evidence": evidence, "fired": True}


def validator_heuristic_result_clean(hid: str) -> Dict:
    """HeuristicResult::clean(id) -> Self"""
    return {"id": hid, "name": "", "threat": THREAT_LEVEL_CLEAN, "evidence": "", "fired": False}


def validator_heuristic_report_from_results(results: List[Dict]) -> Dict:
    """HeuristicReport::from_results(all: Vec<HeuristicResult>) -> Self"""
    fired = [r for r in results if r.get("fired")]
    return {"results": results, "fired": fired}


def validator_heuristic_report_grouped_by_level(report: Dict) -> Dict[str, List[Dict]]:
    """HeuristicReport::grouped_by_level(&self) -> HashMap<String, Vec<&HeuristicResult>>"""
    groups: Dict[str, List[Dict]] = defaultdict(list)
    for r in report["fired"]:
        groups[r.get("threat", "Unknown")].append(r)
    return dict(groups)


def validator_heuristic_report_summary(report: Dict) -> str:
    """HeuristicReport::summary(&self) -> String"""
    total = len(report["results"])
    fired = len(report["fired"])
    return f"heuristics total={total} fired={fired}"


_BUILTIN_HEURISTICS = [
    ("H001", "UPX header",       THREAT_LEVEL_HIGH,   b"UPX!"),
    ("H002", "Anti-debug NtQIP",  THREAT_LEVEL_HIGH,   b"NtQueryInformationProcess"),
    ("H003", "Network connect",   THREAT_LEVEL_MEDIUM,  b"connect"),
    ("H004", "Crypto constant",   THREAT_LEVEL_MEDIUM,  b"\x63\x7c\x77\x7b"),  # AES Sbox
    ("H005", "Shellcode nop sled",THREAT_LEVEL_CRITICAL,b"\x90\x90\x90\x90\x90\x90\x90\x90"),
]


def validator_heuristic_engine_empty() -> Dict:
    """HeuristicEngine::empty() -> Self"""
    return {"heuristics": []}


def validator_heuristic_engine_with_defaults() -> Dict:
    """HeuristicEngine::with_defaults() -> Self"""
    engine = validator_heuristic_engine_empty()
    for (hid, name, threat, pattern) in _BUILTIN_HEURISTICS:
        engine["heuristics"].append({"id": hid, "name": name, "threat": threat, "pattern": pattern})
    return engine


def validator_heuristic_engine_add(engine: Dict, h: Dict) -> None:
    """HeuristicEngine::add(&mut self, h: Box<dyn Heuristic>)"""
    engine["heuristics"].append(h)


def validator_heuristic_engine_check_count(engine: Dict) -> int:
    """HeuristicEngine::check_count(&self) -> usize"""
    return len(engine["heuristics"])


def validator_heuristic_engine_run(engine: Dict, data: bytes) -> Dict:
    """HeuristicEngine::run(&self, bytes) -> HeuristicReport"""
    results = []
    for h in engine["heuristics"]:
        pattern = h.get("pattern", b"")
        if isinstance(pattern, bytes) and pattern in data:
            results.append(validator_heuristic_result_fired(
                h["id"], h["name"], h["threat"], f"Pattern found: {pattern!r}"))
        else:
            results.append(validator_heuristic_result_clean(h["id"]))
    return validator_heuristic_report_from_results(results)


def validator_heuristic_engine_run_category(engine: Dict, prefix: str, data: bytes) -> Dict:
    """HeuristicEngine::run_category(&self, prefix, bytes) -> HeuristicReport"""
    sub = {"heuristics": [h for h in engine["heuristics"] if h["id"].startswith(prefix)]}
    return validator_heuristic_engine_run(sub, data)


def validator_heuristic_engine_check_ids(engine: Dict) -> List[str]:
    """HeuristicEngine::check_ids(&self) -> Vec<&str>"""
    return [h["id"] for h in engine["heuristics"]]


# ===========================================================================
# analyzer_registry.rs
# ===========================================================================

def validator_analysis_result_ok(analyzer: str, score: float) -> Dict:
    """AnalysisResult::ok(analyzer, score) -> Self"""
    return {"analyzer": analyzer, "score": score, "ok": True, "error": None,
            "indicators": [], "meta": {}}


def validator_analysis_result_err(analyzer: str, msg: str) -> Dict:
    """AnalysisResult::err(analyzer, msg) -> Self"""
    return {"analyzer": analyzer, "score": 0.0, "ok": False, "error": msg,
            "indicators": [], "meta": {}}


def validator_analysis_result_add_indicator(result: Dict, ind: Dict) -> None:
    """AnalysisResult::add_indicator(&mut self, ind)"""
    result["indicators"].append(ind)


def validator_analysis_result_with_meta(result: Dict, key: str, val: str) -> Dict:
    """AnalysisResult::with_meta(self, key, val) -> Self (builder)"""
    result["meta"][key] = val
    return result


def validator_analysis_result_is_high_risk(result: Dict) -> bool:
    """AnalysisResult::is_high_risk(&self) -> bool"""
    return result["score"] >= 70.0


def validator_analyzer_registry_new() -> Dict:
    """AnalyzerRegistry::new() -> Self"""
    return {"analyzers": []}


def validator_analyzer_registry_register(registry: Dict, a: Dict) -> None:
    """AnalyzerRegistry::register(&mut self, a: Box<dyn TriageAnalyzer>)"""
    registry["analyzers"].append(a)


def validator_analyzer_registry_len(registry: Dict) -> int:
    """AnalyzerRegistry::len(&self) -> usize"""
    return len(registry["analyzers"])


def validator_analyzer_registry_is_empty(registry: Dict) -> bool:
    """AnalyzerRegistry::is_empty(&self) -> bool"""
    return len(registry["analyzers"]) == 0


def validator_analyzer_registry_names(registry: Dict) -> List[str]:
    """AnalyzerRegistry::names(&self) -> Vec<&str>"""
    return [a.get("name", "") for a in registry["analyzers"]]


def _run_analyzer(a: Dict, data: bytes) -> Dict:
    fn = a.get("fn")
    if callable(fn):
        return fn(data)
    return validator_analysis_result_ok(a.get("name", "?"), 0.0)


def validator_analyzer_registry_run_all(registry: Dict, data: bytes) -> List[Dict]:
    """AnalyzerRegistry::run_all(&self, bytes) -> Vec<AnalysisResult>"""
    return [_run_analyzer(a, data) for a in registry["analyzers"]]


def validator_analyzer_registry_run_fast(registry: Dict, data: bytes) -> List[Dict]:
    """AnalyzerRegistry::run_fast(&self, bytes) -> Vec<AnalysisResult>"""
    return [_run_analyzer(a, data) for a in registry["analyzers"] if a.get("fast", False)]


def validator_analyzer_registry_run_deep(registry: Dict, data: bytes) -> List[Dict]:
    """AnalyzerRegistry::run_deep(&self, bytes) -> Vec<AnalysisResult>"""
    return [_run_analyzer(a, data) for a in registry["analyzers"] if a.get("deep", False)]


def validator_analyzer_registry_run_tagged(registry: Dict, data: bytes, tags: List[str]) -> List[Dict]:
    """AnalyzerRegistry::run_tagged(&self, bytes, tags) -> Vec<AnalysisResult>"""
    tag_set = set(tags)
    return [_run_analyzer(a, data) for a in registry["analyzers"]
            if tag_set.intersection(a.get("tags", []))]


def validator_analyzer_registry_run_and_aggregate(registry: Dict, data: bytes) -> Dict:
    """AnalyzerRegistry::run_and_aggregate(&self, bytes) -> RegistryRunResult"""
    results = validator_analyzer_registry_run_all(registry, data)
    return validator_analyzer_registry_aggregate_results(registry, results)


def validator_analyzer_registry_aggregate_results(registry: Dict, results: List[Dict]) -> Dict:
    """AnalyzerRegistry::aggregate_results(&self, results) -> RegistryRunResult"""
    scores = [r["score"] for r in results if r["ok"]]
    agg = validator_aggregated_score_compute(scores)
    return {"results": results, "aggregated": agg}


def validator_registry_run_result_is_malicious(run: Dict) -> bool:
    """RegistryRunResult::is_malicious(&self) -> bool"""
    return validator_aggregated_score_is_malicious(run["aggregated"])


def validator_registry_run_result_is_clean(run: Dict) -> bool:
    """RegistryRunResult::is_clean(&self) -> bool"""
    return validator_aggregated_score_is_clean(run["aggregated"])


def validator_registry_run_result_summary(run: Dict) -> str:
    """RegistryRunResult::summary(&self) -> String"""
    return f"registry {validator_aggregated_score_summary(run['aggregated'])}"


def validator_registry_run_result_by_analyzer(run: Dict, name: str) -> Optional[Dict]:
    """RegistryRunResult::by_analyzer(&self, name) -> Option<&AnalysisResult>"""
    for r in run["results"]:
        if r.get("analyzer") == name:
            return r
    return None


def validator_default_registry() -> Dict:
    """default_registry() -> AnalyzerRegistry"""
    registry = validator_analyzer_registry_new()
    # Entropy analyzer stub
    def _entropy_analyzer(data: bytes) -> Dict:
        e = _shannon(data)
        r = validator_analysis_result_ok("entropy", e / 8.0 * 100.0)
        return r
    validator_analyzer_registry_register(registry, {"name": "entropy", "fast": True, "deep": False, "tags": ["entropy"], "fn": _entropy_analyzer})
    return registry


# ===========================================================================
# malware_classification.rs
# ===========================================================================

def validator_family_name(family: Dict) -> str:
    """Family::name(&self) -> String"""
    return family.get("name", "Unknown")


def validator_classification_result_new(family: Dict, confidence: int) -> Dict:
    """ClassificationResult::new(family, confidence) -> Self"""
    return {"family": family, "confidence": confidence, "alternatives": []}


def validator_classification_result_top_alternative(result: Dict) -> Optional[Tuple[Dict, int]]:
    """ClassificationResult::top_alternative(&self) -> Option<(&Family, u8)>"""
    alts = result.get("alternatives", [])
    if not alts:
        return None
    best = max(alts, key=lambda x: x[1])
    return best


def validator_fuzzy_hash_compute(data: bytes) -> str:
    """FuzzyHash::compute(data: &[u8]) -> String

    Simple block-based fuzzy hash (ssdeep-style approximation using stdlib only).
    """
    BLOCK = 64
    parts = []
    for i in range(0, len(data), BLOCK):
        h = hashlib.md5(data[i:i + BLOCK]).hexdigest()[:4]
        parts.append(h)
    return ":".join(parts[:32])  # cap to keep output sane


def validator_fuzzy_hash_similarity(a: str, b: str) -> int:
    """FuzzyHash::similarity(a, b) -> u8 (0–100)"""
    pa = set(a.split(":"))
    pb = set(b.split(":"))
    if not pa or not pb:
        return 0
    common = len(pa & pb)
    return min(100, int(common / max(len(pa), len(pb)) * 100))


def validator_imphash_compute(imports: List[Tuple[str, str]]) -> str:
    """ImpHash::compute(imports: &[(String, String)]) -> String"""
    parts = [f"{dll.lower()}.{fn.lower()}" for dll, fn in imports]
    joined = ",".join(sorted(parts))
    return hashlib.md5(joined.encode()).hexdigest()


def validator_string_hash_from_string(s: str) -> str:
    """StringHash::from_string(s) -> String"""
    return hashlib.sha1(s.encode()).hexdigest()


def validator_string_hash_equal(a: str, b: str) -> bool:
    """StringHash::equal(a, b) -> bool"""
    return a == b


def validator_family_database_new() -> Dict:
    """FamilyDatabase::new() -> Self"""
    return {"imphash": {}, "fuzzy": [], "string_hash": {}, "names": {}}


def validator_family_database_add_imphash(db: Dict, h: str, family: Dict, confidence: int) -> None:
    db["imphash"][h] = (family, confidence)


def validator_family_database_add_fuzzy(db: Dict, h: str, family: Dict, confidence: int) -> None:
    db["fuzzy"].append((h, family, confidence))


def validator_family_database_add_string_hash(db: Dict, h: str, family: Dict, confidence: int) -> None:
    db["string_hash"][h] = (family, confidence)


def validator_family_database_add_name(db: Dict, name: str, family: Dict) -> None:
    db["names"][name.lower()] = family


def validator_family_database_lookup_imphash(db: Dict, h: str) -> Optional[Tuple[Dict, int]]:
    return db["imphash"].get(h)


def validator_family_database_lookup_name(db: Dict, name: str) -> Optional[Dict]:
    return db["names"].get(name.lower())


def validator_family_database_lookup_fuzzy(db: Dict, h: str, min_similarity: int) -> Optional[Tuple[Dict, int]]:
    best = None
    best_sim = 0
    for (fh, family, conf) in db["fuzzy"]:
        sim = validator_fuzzy_hash_similarity(h, fh)
        if sim >= min_similarity and sim > best_sim:
            best = (family, conf)
            best_sim = sim
    return best


def validator_malware_classifier_new() -> Dict:
    """MalwareClassifier::new() -> Self"""
    return {"db": validator_family_database_new()}


def validator_malware_classifier_classify(classifier: Dict, data: bytes, imports: Optional[List[Tuple[str, str]]] = None) -> Dict:
    """MalwareClassifier::classify(&self, data, …) -> ClassificationResult"""
    db = classifier["db"]
    fh = validator_fuzzy_hash_compute(data)
    match = validator_family_database_lookup_fuzzy(db, fh, 40)
    if match:
        return validator_classification_result_new(match[0], match[1])
    if imports:
        ih = validator_imphash_compute(imports)
        im = validator_family_database_lookup_imphash(db, ih)
        if im:
            return validator_classification_result_new(im[0], im[1])
    unknown = {"name": "Unknown", "category": "unknown"}
    return validator_classification_result_new(unknown, 0)


def validator_malware_classifier_classify_by_imphash(classifier: Dict, imphash: str) -> Optional[Dict]:
    """MalwareClassifier::classify_by_imphash"""
    match = validator_family_database_lookup_imphash(classifier["db"], imphash)
    if match:
        return validator_classification_result_new(match[0], match[1])
    return None


def validator_malware_classifier_database_size(classifier: Dict) -> int:
    """MalwareClassifier::database_size(&self) -> usize"""
    db = classifier["db"]
    return len(db["imphash"]) + len(db["fuzzy"]) + len(db["string_hash"]) + len(db["names"])


# ===========================================================================
# mitre_mapper.rs
# ===========================================================================

def validator_mitre_technique_new(tid: str, name: str, tactic: str) -> Dict:
    """MitreTechnique::new(id, name, tactic) -> Self"""
    return {"id": tid, "name": name, "tactic": tactic, "sub": None}


def validator_mitre_technique_with_sub(technique: Dict, sub: str) -> Dict:
    """MitreTechnique::with_sub(self, sub) -> Self"""
    technique["sub"] = sub
    return technique


def validator_technique_match_new(technique: Dict, indicator: str, confidence: int) -> Dict:
    """TechniqueMatch::new(technique, indicator, confidence) -> Self"""
    return {"technique": technique, "indicator": indicator, "confidence": confidence, "evidence": []}


def validator_technique_match_with_evidence(match: Dict, ev: str) -> Dict:
    """TechniqueMatch::with_evidence(self, ev) -> Self"""
    match["evidence"].append(ev)
    return match


def validator_attack_matrix_new() -> Dict:
    """AttackMatrix::new() -> Self"""
    return {"matches": []}


def validator_attack_matrix_add(matrix: Dict, m: Dict) -> None:
    """AttackMatrix::add(&mut self, m: TechniqueMatch)"""
    matrix["matches"].append(m)


def validator_attack_matrix_tactics(matrix: Dict) -> List[str]:
    """AttackMatrix::tactics(&self) -> Vec<&str>"""
    seen = []
    for m in matrix["matches"]:
        t = m["technique"]["tactic"]
        if t not in seen:
            seen.append(t)
    return seen


def validator_attack_matrix_techniques_for_tactic(matrix: Dict, tactic: str) -> List[Dict]:
    """AttackMatrix::techniques_for_tactic(&self, tactic) -> Vec<&TechniqueMatch>"""
    return [m for m in matrix["matches"] if m["technique"]["tactic"] == tactic]


def validator_attack_matrix_top_match(matrix: Dict) -> Optional[Dict]:
    """AttackMatrix::top_match(&self) -> Option<&TechniqueMatch>"""
    if not matrix["matches"]:
        return None
    return max(matrix["matches"], key=lambda m: m["confidence"])


def validator_attack_matrix_summary(matrix: Dict) -> str:
    """AttackMatrix::summary(&self) -> String"""
    n = len(matrix["matches"])
    tactics = validator_attack_matrix_tactics(matrix)
    return f"ATT&CK matrix: {n} matches across tactics: {', '.join(tactics)}"


def validator_attack_matrix_to_json(matrix: Dict) -> str:
    """AttackMatrix::to_json(&self) -> serde_json::Result<String>"""
    return json.dumps(matrix, indent=2)


# Built-in indicator → technique mapping
_MITRE_RULES = [
    ("VirtualAlloc",          "T1055",  "Process Injection",          "defense-evasion"),
    ("WriteProcessMemory",    "T1055",  "Process Injection",          "defense-evasion"),
    ("CreateRemoteThread",    "T1055",  "Process Injection",          "defense-evasion"),
    ("NtQueryInformationProcess","T1622","Debugger Evasion",          "defense-evasion"),
    ("connect",               "T1071",  "Application Layer Protocol", "command-and-control"),
    ("WinExec",               "T1059",  "Command and Scripting Interpreter","execution"),
    ("ShellExecute",          "T1059",  "Command and Scripting Interpreter","execution"),
    ("UPX",                   "T1027",  "Obfuscated Files",           "defense-evasion"),
]


def validator_mitre_mapper_new() -> Dict:
    """MitreMapper::new() -> Self"""
    techniques = {}
    for (ind, tid, name, tactic) in _MITRE_RULES:
        techniques[tid] = validator_mitre_technique_new(tid, name, tactic)
    return {"rules": _MITRE_RULES, "techniques": techniques}


def validator_mitre_mapper_build_attack_matrix(mapper: Dict, result: Dict) -> Dict:
    """MitreMapper::build_attack_matrix(&self, result: &TriageResult) -> AttackMatrix"""
    matrix = validator_attack_matrix_new()
    indicators = [i.get("name", "") + " " + i.get("description", "")
                  for i in result.get("indicators", [])]
    for (pattern, tid, name, tactic) in mapper["rules"]:
        for ind_text in indicators:
            if pattern.lower() in ind_text.lower():
                tech = validator_mitre_technique_new(tid, name, tactic)
                m = validator_technique_match_new(tech, pattern, 80)
                validator_attack_matrix_add(matrix, m)
                break
    return matrix


def validator_mitre_mapper_build_from_strings(mapper: Dict, indicators: List[str]) -> Dict:
    """MitreMapper::build_from_strings(&self, indicators: &[&str]) -> AttackMatrix"""
    matrix = validator_attack_matrix_new()
    for (pattern, tid, name, tactic) in mapper["rules"]:
        for ind in indicators:
            if pattern.lower() in ind.lower():
                tech = validator_mitre_technique_new(tid, name, tactic)
                m = validator_technique_match_new(tech, pattern, 70)
                validator_attack_matrix_add(matrix, m)
                break
    return matrix


def validator_mitre_mapper_lookup_technique(mapper: Dict, tid: str) -> Optional[Dict]:
    """MitreMapper::lookup_technique(&self, id) -> Option<&MitreTechnique>"""
    return mapper["techniques"].get(tid)


def validator_mitre_mapper_technique_ids(mapper: Dict) -> List[str]:
    """MitreMapper::technique_ids(&self) -> Vec<&str>"""
    return list(mapper["techniques"].keys())


# ===========================================================================
# pe_triage_extended.rs
# ===========================================================================

_SUSPICIOUS_APIS = {
    b"VirtualAlloc", b"VirtualProtect", b"WriteProcessMemory",
    b"CreateRemoteThread", b"NtQueryInformationProcess", b"IsDebuggerPresent",
    b"OpenProcess", b"ReadProcessMemory", b"WinExec", b"ShellExecuteA",
}


def validator_pe_features_from_bytes(data: bytes) -> Dict:
    """PeFeatures::from_bytes(data: &[u8]) -> Self"""
    sections = _pe_sections(data)
    entropy = _shannon(data)
    overlay = False
    # Simple overlay heuristic: data after last section
    if sections:
        last_fo, last_sz, _ = max(sections, key=lambda s: s[0])
        if last_fo + last_sz < len(data):
            overlay = True
    suspicious_imports = [api for api in _SUSPICIOUS_APIS if api in data]
    all_imports_count = data.count(b".dll") + data.count(b".DLL")
    return {
        "section_count": len(sections),
        "entropy": entropy,
        "has_overlay": overlay,
        "suspicious_import_count": len(suspicious_imports),
        "total_import_count": max(1, all_imports_count),
        "has_tls": b".tls" in data.lower() or b"TlsCallback" in data,
        "sections": sections,
    }


def validator_pe_features_normalised_import_risk(features: Dict) -> float:
    """PeFeatures::normalised_import_risk(&self) -> f64"""
    return features["suspicious_import_count"] / max(1, features["total_import_count"])


def validator_pe_features_looks_packed(features: Dict) -> bool:
    """PeFeatures::looks_packed(&self) -> bool"""
    return (features["entropy"] > 7.0
            or features["section_count"] <= 2
            or features.get("has_overlay", False))


def validator_detect_anomalies(data: bytes, features: Dict) -> List[Dict]:
    """detect_anomalies(data, features) -> Vec<PeAnomaly>"""
    anomalies = []
    if features.get("has_overlay"):
        anomalies.append({"kind": "Overlay", "description": "Data found after last PE section"})
    if features["entropy"] > 7.2:
        anomalies.append({"kind": "HighEntropy", "description": f"Global entropy {features['entropy']:.3f}"})
    if features["section_count"] < 2:
        anomalies.append({"kind": "FewSections", "description": "Unusually few sections (possible packer)"})
    return anomalies


def validator_section_features_from_bytes(data: bytes) -> Dict:
    """SectionFeatures::from_bytes(data: &[u8]) -> Self"""
    if len(data) < 2 or data[:2] != b"MZ":
        return {"sections": []}
    raw_sections = _pe_sections(data)
    pe_off = struct.unpack_from("<I", data, 0x3C)[0] if len(data) >= 0x40 else 0
    section_off = pe_off + 24 + (struct.unpack_from("<H", data, pe_off + 20)[0] if pe_off + 22 <= len(data) else 0)
    num_sections = struct.unpack_from("<H", data, pe_off + 6)[0] if pe_off + 8 <= len(data) else 0
    result = []
    for i in range(num_sections):
        base = section_off + i * 40
        if base + 40 > len(data):
            break
        name_bytes = data[base:base+8].rstrip(b"\x00")
        name = name_bytes.decode("ascii", errors="replace")
        chars = struct.unpack_from("<I", data, base + 36)[0]
        raw = struct.unpack_from("<I", data, base + 20)[0]
        rsize = struct.unpack_from("<I", data, base + 16)[0]
        va = struct.unpack_from("<I", data, base + 12)[0]
        chunk = data[raw:raw + rsize] if raw and rsize else b""
        result.append({
            "name": name,
            "entropy": _shannon(chunk),
            "characteristics": chars,
            "virtual_address": va,
        })
    return {"sections": result}


def validator_detect_section_anomalies(features: Dict) -> List[Dict]:
    """detect_section_anomalies(features: PeFeatures) -> Vec<SectionAnomaly>"""
    anomalies = []
    for sec in features.get("sections", []):
        name = sec.get("name", "")
        entropy = sec.get("entropy", 0.0)
        chars = sec.get("characteristics", 0)
        executable = bool(chars & 0x20000000)
        writable   = bool(chars & 0x80000000)
        if entropy > 7.0:
            anomalies.append({"kind": "HighEntropySection", "section": name, "entropy": entropy})
        if executable and writable:
            anomalies.append({"kind": "RWXSection", "section": name})
        if name not in (".text", ".data", ".rdata", ".rsrc", ".reloc", ".pdata", ""):
            anomalies.append({"kind": "UnusualSectionName", "section": name})
    return anomalies


def validator_pe_triage_report_from_bytes(data: bytes) -> Dict:
    """PeTriageReport::from_bytes(data: &[u8]) -> Self"""
    features = validator_pe_features_from_bytes(data)
    anomalies = validator_detect_anomalies(data, features)
    sec_features = validator_section_features_from_bytes(data)
    sec_anomalies = validator_detect_section_anomalies(sec_features)
    indicators = []
    for a in anomalies + sec_anomalies:
        indicators.append({
            "name": a["kind"],
            "description": a.get("description", a.get("section", "")),
            "level": THREAT_LEVEL_MEDIUM,
            "category": "pe_extended",
        })
    return {
        "features": features,
        "anomalies": anomalies,
        "section_features": sec_features,
        "section_anomalies": sec_anomalies,
        "indicators": indicators,
    }


def validator_pe_triage_report_analyze(data: bytes) -> Dict:
    """PeTriageReport::analyze(data: &[u8]) -> PeTriageReport  (alias for from_bytes)"""
    return validator_pe_triage_report_from_bytes(data)


# ===========================================================================
# static_analysis_triage.rs
# ===========================================================================

def validator_static_feature_description(feature: Dict) -> str:
    """StaticFeature::description(&self) -> String"""
    return feature.get("description", feature.get("name", "Unknown"))


def validator_feature_weight_new(feature: Dict, weight: int, evidence: str) -> Dict:
    """FeatureWeight::new(feature, weight, evidence) -> Self"""
    return {"feature": feature, "weight": weight, "evidence": evidence}


def validator_feature_weight_effective_weight(fw: Dict) -> int:
    """FeatureWeight::effective_weight(&self) -> u32"""
    level = fw["feature"].get("level", 1)
    return fw["weight"] * level


def validator_static_score_new(raw: int) -> Dict:
    """StaticScore::new(raw: u32) -> Self"""
    if raw >= 70:
        cls = "Malicious"
    elif raw >= 40:
        cls = "Suspicious"
    else:
        cls = "Clean"
    return {"raw": raw, "classification": cls}


def validator_static_triage_report_to_json(report: Dict) -> str:
    """StaticTriageReport::to_json(&self) -> Result<String, String>"""
    try:
        return json.dumps(report, indent=2)
    except Exception as e:
        raise ValueError(str(e))


def validator_static_triage_report_summary(report: Dict) -> str:
    """StaticTriageReport::summary(&self) -> String"""
    score = report.get("score", {})
    features = report.get("features", [])
    return f"static score={score.get('raw', 0)} cls={score.get('classification','?')} features={len(features)}"


def _string_feature_weights(data: bytes) -> List[Dict]:
    features = []
    strings = validator_string_heuristics_extract_strings(data[:512 * 1024], 4)
    suspicious = validator_string_heuristics_classify(strings)
    for s in suspicious:
        feat = {"name": s["category"], "description": s["value"][:60], "level": 2}
        features.append(validator_feature_weight_new(feat, 10, s["value"][:40]))
    return features


def validator_string_feature_analyzer_analyze(analyzer: Dict, data: bytes) -> List[Dict]:
    """StringFeatureAnalyzer::analyze(&self, data) -> Vec<FeatureWeight>"""
    return _string_feature_weights(data)


def _binary_feature_weights(data: bytes) -> List[Dict]:
    features = []
    e = _shannon(data)
    if e > 7.0:
        feat = {"name": "high_entropy", "description": f"entropy={e:.3f}", "level": 3}
        features.append(validator_feature_weight_new(feat, 25, f"entropy={e:.3f}"))
    if b"UPX!" in data:
        feat = {"name": "upx_magic", "description": "UPX packer signature", "level": 3}
        features.append(validator_feature_weight_new(feat, 30, "UPX!"))
    return features


def validator_binary_feature_analyzer_analyze(analyzer: Dict, data: bytes) -> List[Dict]:
    """BinaryFeatureAnalyzer::analyze(&self, data) -> Vec<FeatureWeight>"""
    return _binary_feature_weights(data)


def validator_static_triage_engine_new() -> Dict:
    """StaticTriageEngine::new() -> Self"""
    return {"string_analyzer": {}, "binary_analyzer": {}}


def _build_static_report(str_feats: List[Dict], bin_feats: List[Dict]) -> Dict:
    all_feats = str_feats + bin_feats
    raw = min(100, sum(validator_feature_weight_effective_weight(fw) for fw in all_feats))
    score = validator_static_score_new(raw)
    return {"features": all_feats, "score": score}


def validator_static_triage_engine_triage(engine: Dict, data: bytes) -> Dict:
    """StaticTriageEngine::triage(&self, data) -> StaticTriageReport"""
    str_feats = _string_feature_weights(data)
    bin_feats = _binary_feature_weights(data)
    return _build_static_report(str_feats, bin_feats)


def validator_static_triage_engine_quick_triage(engine: Dict, data: bytes) -> Dict:
    """StaticTriageEngine::quick_triage(&self, data) -> StaticTriageReport (subset)"""
    bin_feats = _binary_feature_weights(data)
    return _build_static_report([], bin_feats)


def validator_static_triage_engine_batch_triage(engine: Dict, inputs: List[bytes]) -> List[Dict]:
    """StaticTriageEngine::batch_triage<'a>(&self, inputs) -> Vec<StaticTriageReport>"""
    return [validator_static_triage_engine_triage(engine, d) for d in inputs]


def validator_static_triage_engine_classify_features(engine: Dict, features: List[Dict]) -> Dict:
    """StaticTriageEngine::classify_features(&self, features) -> StaticTriageReport"""
    return _build_static_report(features, [])


# ===========================================================================
# findcrypt.rs — crypto constant scanner
# ===========================================================================

_CRYPTO_CONSTANTS = [
    ("AES_SBOX",  bytes([
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,
        0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    ])),
    ("SHA256_K0", struct.pack(">I", 0x428a2f98)),
    ("SHA1_H0",   struct.pack(">I", 0x67452301)),
    ("MD5_T1",    struct.pack("<I", 0xd76aa478)),
    ("RC4_MAGIC", b"expand 32-byte k"),
    ("TEA_DELTA", struct.pack("<I", 0x9e3779b9)),
    ("BLOWFISH_P0", struct.pack(">I", 0x243f6a88)),
]


def validator_findcrypt_scan(buf: bytes) -> List[Dict]:
    """scan(buf: &[u8]) -> Vec<CryptoHit>

    Scans buffer for known cryptographic constants (AES S-box, SHA, MD5, RC4, etc.).
    """
    hits = []
    for (name, pattern) in _CRYPTO_CONSTANTS:
        pos = 0
        while True:
            idx = buf.find(pattern, pos)
            if idx < 0:
                break
            hits.append({"name": name, "offset": idx, "pattern_len": len(pattern)})
            pos = idx + 1
    return hits


# ===========================================================================
# family_db.rs
# ===========================================================================

_BUILTIN_FAMILIES = [
    {"name": "Mirai",      "category": "botnet",     "priority": 90},
    {"name": "WannaCry",   "category": "ransomware",  "priority": 95},
    {"name": "Emotet",     "category": "trojan",      "priority": 85},
    {"name": "Cobalt Strike","category": "rat",       "priority": 88},
    {"name": "Metasploit", "category": "framework",   "priority": 80},
]

_FAMILY_IOCS = {
    "Mirai":  [b"/bin/busybox", b"MIRAI"],
    "WannaCry": [b"WanaCrypt0r", b".WNCRY"],
    "Emotet": [b"emotet", b"heodo"],
}

_FAMILY_APIS = {
    "Cobalt Strike": ["VirtualAllocEx", "CreateRemoteThread", "WriteProcessMemory"],
    "Metasploit":    ["VirtualAlloc", "WinExec"],
}


def validator_family_db_new() -> Dict:
    """FamilyDb::new() -> Self (with built-in entries)"""
    return {"entries": list(_BUILTIN_FAMILIES)}


def validator_family_db_get(db: Dict, name: str) -> Optional[Dict]:
    """FamilyDb::get(&self, name) -> Option<&FamilyEntry>"""
    for e in db["entries"]:
        if e["name"].lower() == name.lower():
            return e
    return None


def validator_family_db_all(db: Dict) -> List[Dict]:
    """FamilyDb::all(&self) -> &[FamilyEntry]"""
    return db["entries"]


def validator_family_db_by_category(db: Dict, cat: str) -> List[Dict]:
    """FamilyDb::by_category(&self, cat) -> Vec<&FamilyEntry>"""
    return [e for e in db["entries"] if e.get("category", "").lower() == cat.lower()]


def validator_family_db_match_iocs(db: Dict, haystack: bytes) -> List[Tuple[Dict, List[bytes]]]:
    """FamilyDb::match_iocs<'a>(&'a self, haystack) -> Vec<(&'a FamilyEntry, Vec<&'a Ioc>)>"""
    out = []
    for entry in db["entries"]:
        iocs = _FAMILY_IOCS.get(entry["name"], [])
        matched = [ioc for ioc in iocs if ioc in haystack]
        if matched:
            out.append((entry, matched))
    return out


def validator_family_db_match_apis(db: Dict, apis: List[str]) -> List[Tuple[Dict, List[str]]]:
    """FamilyDb::match_apis<'a>(&'a self, apis) -> Vec<(&'a FamilyEntry, Vec<&'static str>)>"""
    api_set = set(a.lower() for a in apis)
    out = []
    for entry in db["entries"]:
        expected = _FAMILY_APIS.get(entry["name"], [])
        matched = [e for e in expected if e.lower() in api_set]
        if matched:
            out.append((entry, matched))
    return out


def validator_family_db_top_n(db: Dict, n: int) -> List[Dict]:
    """FamilyDb::top_n(&self, n) -> Vec<&FamilyEntry>"""
    sorted_entries = sorted(db["entries"], key=lambda e: e.get("priority", 0), reverse=True)
    return sorted_entries[:n]


# ===========================================================================
# rapid_classifier.rs
# ===========================================================================

def validator_rapid_classifier_classify(classifier: Dict, data: bytes) -> Dict:
    """RapidClassifier::classify(&self, data) -> ClassificationResult"""
    kind = validator_detect_file_kind(data)
    e = _shannon(data)
    confidence = 50
    family = {"name": "Unknown", "category": "unknown"}

    if e > 7.2:
        family = {"name": "Packed/Encrypted", "category": "packer"}
        confidence = 70
    elif b"UPX!" in data:
        family = {"name": "UPX", "category": "packer"}
        confidence = 90

    return validator_classification_result_new(family, confidence)


def validator_import_family_similarity(data: bytes) -> List[Tuple[str, float]]:
    """import_family_similarity(data: &[u8]) -> Vec<(&'static str, f32)>"""
    api_set = set()
    for api in _SUSPICIOUS_APIS:
        if api in data:
            api_set.add(api.decode())

    families_apis = {
        "Cobalt Strike": {"VirtualAllocEx", "CreateRemoteThread", "WriteProcessMemory"},
        "Metasploit":    {"VirtualAlloc", "WinExec"},
    }
    results = []
    for (fname, expected) in families_apis.items():
        if not expected:
            continue
        sim = len(api_set & expected) / len(expected)
        if sim > 0:
            results.append((fname, sim))
    return sorted(results, key=lambda x: -x[1])


# ===========================================================================
# file_classifier.rs
# ===========================================================================

def validator_file_classification_new(
    file_kind: str, entropy: float, size: int, signature: Optional[str],
    risk_score: int
) -> Dict:
    """FileClassification::new(…) -> Self"""
    return {
        "file_kind": file_kind,
        "entropy": entropy,
        "size": size,
        "signature": signature,
        "risk_score": risk_score,
    }


def validator_file_classification_is_high_risk(fc: Dict) -> bool:
    """FileClassification::is_high_risk(&self) -> bool"""
    return fc["risk_score"] >= 70


def validator_file_classification_summary_line(fc: Dict) -> str:
    """FileClassification::summary_line(&self) -> String"""
    sig = fc.get("signature") or "unsigned"
    return (f"{fc['file_kind']} size={fc['size']} "
            f"entropy={fc['entropy']:.3f} risk={fc['risk_score']} sig={sig}")


def validator_file_classifier_new() -> Dict:
    """FileClassifier::new() -> Self"""
    return {"rules": "default"}


def validator_file_classifier_classify(
    classifier: Dict, data: bytes,
    signature: Optional[str] = None
) -> Dict:
    """FileClassifier::classify(&self, data, …) -> FileClassification"""
    kind = validator_detect_file_kind(data)
    e = _shannon(data)
    size = len(data)
    risk = 0
    if e > 7.0:
        risk += 40
    if kind in (FILE_KIND_PE32, FILE_KIND_PE64):
        for api in _SUSPICIOUS_APIS:
            if api in data:
                risk += 10
    risk = min(100, risk)
    return validator_file_classification_new(kind, e, size, signature, risk)


# ===========================================================================
# Self-test / smoke check
# ===========================================================================

if __name__ == "__main__":
    import os

    print("=== rustre-triage validator smoke test ===\n")

    # 1. detect_file_kind
    pe_stub = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40) + b"\x00" * 4
    pe_stub += b"PE\x00\x00" + struct.pack("<H", 0x014c)  # i386
    print("detect_file_kind(MZ stub):", validator_detect_file_kind(pe_stub))
    print("detect_file_kind(ELF)    :", validator_detect_file_kind(b"\x7fELF\x02"))

    # 2. entropy rating
    print("entropy_rating(7.5):", validator_entropy_rating_from_entropy(7.5))
    print("entropy_rating(3.0):", validator_entropy_rating_from_entropy(3.0))

    # 3. TriageResult roundtrip
    sample = os.urandom(1024)
    kind = validator_detect_file_kind(sample)
    result = validator_triage_result_new(kind, sample)
    validator_triage_result_add_indicator(result, {
        "name": "test", "description": "smoke", "level": THREAT_LEVEL_HIGH, "category": "test"
    })
    print("is_malicious:", validator_triage_result_is_malicious(result))
    print("score:", result["score"])

    # 4. StringHeuristics
    strings = validator_string_heuristics_extract_strings(
        b"hello world http://evil.com/payload VirtualAlloc", 4)
    sus = validator_string_heuristics_classify(strings)
    print("suspicious strings:", [(s["category"], s["value"]) for s in sus])

    # 5. Pipeline
    pipeline = validator_triage_pipeline_default_pipeline()
    run = validator_triage_pipeline_staged_run(pipeline, sample)
    print("pipeline summary:", validator_pipeline_run_result_summary(run))

    # 6. findcrypt
    aes_buf = bytes([0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76])
    hits = validator_findcrypt_scan(aes_buf)
    print("findcrypt hits:", hits)

    # 7. MITRE mapper
    mapper = validator_mitre_mapper_new()
    matrix = validator_mitre_mapper_build_from_strings(mapper, ["VirtualAlloc", "connect"])
    print("attack matrix summary:", validator_attack_matrix_summary(matrix))

    print("\nAll smoke tests passed.")
