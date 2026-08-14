"""Python validator reproducing the public API of crate `rustre-deobf-antianti`.

Each Rust public function has a Python equivalent (validator_NAME) with
matching input shape and output type. Implementations use only Python stdlib.
"""
from __future__ import annotations

import re
import struct
import hashlib
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Shared helpers / byte-pattern scanning
# ---------------------------------------------------------------------------

def _scan_pattern(data: bytes, pattern: bytes, mask: Optional[bytes] = None) -> List[int]:
    """Return all offsets where `pattern` matches (optionally with mask)."""
    offsets: List[int] = []
    plen = len(pattern)
    if plen == 0:
        return offsets
    for i in range(len(data) - plen + 1):
        if mask:
            if all((data[i + j] & mask[j]) == (pattern[j] & mask[j]) for j in range(plen)):
                offsets.append(i)
        else:
            if data[i:i + plen] == pattern:
                offsets.append(i)
    return offsets


def _nop_sled(length: int) -> bytes:
    return b'\x90' * length


def _xor_eax_eax_nops(total_len: int) -> bytes:
    """XOR EAX,EAX (2 bytes) + NOP padding."""
    if total_len < 2:
        return b'\x90' * total_len
    return b'\x31\xc0' + b'\x90' * (total_len - 2)


def _xor_rax_rax_nops(total_len: int) -> bytes:
    """XOR RAX,RAX (REX.W prefix, 3 bytes) + NOP padding."""
    if total_len < 3:
        return b'\x90' * total_len
    return b'\x48\x31\xc0' + b'\x90' * (total_len - 3)


# Known byte patterns for anti-debug / anti-VM techniques
_ISDBGPRESENT = bytes([0x64, 0x8b, 0x0d])          # FS:[0x18] / PEB
_NTQUERY_PORT = bytes([0x00, 0x00, 0x00, 0x00, 0x07])  # NtQueryInformationProcess ProcessDebugPort=7
_HEAP_NTGLOBALFLAG = bytes([0x68, 0x00, 0x00, 0x00])   # heap flags pattern (simplified)
_RDTSC = bytes([0x0f, 0x31])
_CPUID = bytes([0x0f, 0xa2])
_SLEEP_CALL = bytes([0xff, 0x15])                    # indirect CALL (import)
_SIDT = bytes([0x0f, 0x01, 0x0e])
_SGDT = bytes([0x0f, 0x01, 0x00])
_INT2E = bytes([0xcd, 0x2e])

_VM_STRINGS = [
    b'VMware', b'VirtualBox', b'VBOX', b'QEMU', b'Hyper-V',
    b'vmtoolsd', b'vboxservice', b'vboxdrv', b'vmhgfs',
    b'HKLM\\SOFTWARE\\VMware', b'HKLM\\SOFTWARE\\Oracle\\VirtualBox',
]

_VM_PRODUCT_NAMES = {
    0: 'VMware', 1: 'VirtualBox', 2: 'HyperV', 3: 'QEMU', 4: 'Xen',
}


# ---------------------------------------------------------------------------
# src/lib.rs — high-level scanner
# ---------------------------------------------------------------------------

def validator_signature_database() -> List[Dict]:
    """signature_database() -> Vec<TechniqueSignature>"""
    return [
        {"name": "IsDebuggerPresent", "pattern": list(_ISDBGPRESENT), "category": "anti_debug"},
        {"name": "RDTSC", "pattern": list(_RDTSC), "category": "timing"},
        {"name": "CPUID_hypervisor", "pattern": list(_CPUID), "category": "anti_vm"},
        {"name": "SIDT_redpill", "pattern": list(_SIDT), "category": "anti_vm"},
        {"name": "INT2E_syscall", "pattern": list(_INT2E), "category": "evasion"},
    ]


def validator_AntiAnalysisScanner_new() -> Dict:
    """AntiAnalysisScanner::new() -> Self"""
    return {"signatures": validator_signature_database(), "hits": []}


def validator_AntiAnalysisScanner_scan(scanner: Dict, data: bytes) -> List[Dict]:
    """AntiAnalysisScanner::scan(&self, data: &[u8]) -> Vec<AntiAnalysisHit>"""
    hits: List[Dict] = []
    for sig in scanner["signatures"]:
        pat = bytes(sig["pattern"])
        for off in _scan_pattern(data, pat):
            hits.append({"offset": off, "technique": sig["name"], "category": sig["category"],
                         "confidence": 80})
    return hits


def validator_generate_frida_script(hits: List[Dict]) -> str:
    """generate_frida_script(hits: &[AntiAnalysisHit]) -> String"""
    lines = ["'use strict';", "// Auto-generated anti-analysis bypass script"]
    for h in hits:
        lines.append(f"// Bypass {h['technique']} @ 0x{h['offset']:x}")
        lines.append(f"Interceptor.attach(ptr(0x{h['offset']:x}), {{ onEnter: function(args) {{")
        lines.append(f"  // neutralize {h['technique']}");
        lines.append("} });")
    return "\n".join(lines)


def validator_AntiDebugScanner_new(signatures: Optional[List] = None) -> Dict:
    """AntiDebugScanner::new(…) -> Self"""
    return {"signatures": signatures or [], "detections": []}


def validator_AntiDebugScanner_scan(scanner: Dict, data: bytes) -> List[Dict]:
    """AntiDebugScanner::scan(&self, data: &[u8]) -> Vec<AntiDebugDetection>"""
    detections: List[Dict] = []
    for off in _scan_pattern(data, _ISDBGPRESENT):
        detections.append({"offset": off, "technique": "IsDebuggerPresent", "confidence": 85})
    for off in _scan_pattern(data, _RDTSC):
        detections.append({"offset": off, "technique": "RDTSC_timing", "confidence": 70})
    return detections


def validator_AntiVmScanner_new(config: Optional[Dict] = None) -> Dict:
    """AntiVmScanner::new(…) -> Self"""
    return {"config": config or {}, "detections": []}


def validator_AntiVmScanner_scan(scanner: Dict, data: bytes) -> List[Dict]:
    """AntiVmScanner::scan(&self, data: &[u8]) -> Vec<AntiVmDetection>"""
    detections: List[Dict] = []
    for off in _scan_pattern(data, _CPUID):
        detections.append({"offset": off, "technique": "CPUID_hypervisor", "confidence": 75})
    for off in _scan_pattern(data, _SIDT):
        detections.append({"offset": off, "technique": "SIDT_redpill", "confidence": 80})
    for vm_str in _VM_STRINGS:
        for off in _scan_pattern(data, vm_str):
            detections.append({"offset": off, "technique": "VM_string_artifact",
                                "vm_product": vm_str.decode(errors='replace'), "confidence": 90})
    return detections


def validator_Bypass_new(offset: int, original: bytes, replacement: bytes,
                         label: str = "") -> Dict:
    """Bypass::new(…) -> Self"""
    return {"offset": offset, "original": list(original), "replacement": list(replacement),
            "label": label, "effectiveness": 50}


def validator_Bypass_with_effectiveness(bypass: Dict, eff: int) -> Dict:
    """Bypass::with_effectiveness(mut self, eff: u32) -> Self"""
    b = dict(bypass)
    b["effectiveness"] = max(0, min(100, eff))
    return b


def validator_Bypass_to_patch(bypass: Dict, original: bytes) -> Dict:
    """Bypass::to_patch(&self, original: Vec<u8>) -> Patch"""
    return {"offset": bypass["offset"], "original_bytes": list(original),
            "patch_bytes": bypass["replacement"]}


def validator_TimingBypassGenerator_new() -> Dict:
    """TimingBypassGenerator::new() -> Self"""
    return {"type": "TimingBypassGenerator"}


def validator_TimingBypassGenerator_frida_gettickcount_hook(gen: Dict) -> str:
    """TimingBypassGenerator::frida_gettickcount_hook(&self) -> String"""
    return (
        "'use strict';\n"
        "// Hook GetTickCount / GetTickCount64\n"
        "var gtc = Module.findExportByName('kernel32.dll', 'GetTickCount');\n"
        "if (gtc) { Interceptor.replace(gtc, new NativeCallback(function() { return 1; }, 'uint32', [])); }\n"
        "var gtc64 = Module.findExportByName('kernel32.dll', 'GetTickCount64');\n"
        "if (gtc64) { Interceptor.replace(gtc64, new NativeCallback(function() { return ptr(1); }, 'pointer', [])); }\n"
    )


def validator_TimingBypassGenerator_frida_rdtsc_stalker_snippet(gen: Dict) -> str:
    """TimingBypassGenerator::frida_rdtsc_stalker_snippet(&self) -> String"""
    return (
        "'use strict';\n"
        "// Frida Stalker snippet: NOP RDTSC deltas\n"
        "Stalker.follow(Process.getCurrentThreadId(), {\n"
        "  transform: function(iterator) {\n"
        "    var insn;\n"
        "    while ((insn = iterator.next()) !== null) {\n"
        "      if (insn.mnemonic === 'rdtsc') { iterator.putNop(); } else { iterator.keep(); }\n"
        "    }\n"
        "  }\n"
        "});\n"
    )


def validator_BypassRegistry_new() -> Dict:
    """BypassRegistry::new() -> Self"""
    return {"registry": {}}


def validator_BypassRegistry_register(reg: Dict, technique: str, bypass: Dict) -> None:
    """BypassRegistry::register(&mut self, technique, bypass)"""
    reg["registry"].setdefault(technique, []).append(bypass)


def validator_BypassRegistry_get(reg: Dict, technique: str) -> List[Dict]:
    """BypassRegistry::get(&self, technique: &str) -> &[Bypass]"""
    return reg["registry"].get(technique, [])


def validator_BypassRegistry_total(reg: Dict) -> int:
    """BypassRegistry::total(&self) -> usize"""
    return sum(len(v) for v in reg["registry"].values())


def validator_BypassRegistry_is_empty(reg: Dict) -> bool:
    """BypassRegistry::is_empty(&self) -> bool"""
    return validator_BypassRegistry_total(reg) == 0


def validator_BypassRegistry_techniques(reg: Dict) -> List[str]:
    """BypassRegistry::techniques(&self) -> Vec<&str>"""
    return list(reg["registry"].keys())


def validator_SleepBypassGenerator_scan_large_sleeps(gen: Dict, data: bytes,
                                                      threshold_ms: int = 500) -> List[Tuple[int, int]]:
    """SleepBypassGenerator::scan_large_sleeps(&self, data: &[u8]) -> Vec<(usize, u32)>"""
    results: List[Tuple[int, int]] = []
    # Pattern: PUSH imm32 before a CALL (E8 xx / FF 15 xx)
    for i in range(4, len(data) - 5):
        if data[i] == 0x68:  # PUSH imm32
            ms = struct.unpack_from('<I', data, i + 1)[0]
            if ms > threshold_ms:
                results.append((i, ms))
    return results


def validator_SleepBypassGenerator_generate_bypasses(gen: Dict, data: bytes) -> List[Dict]:
    """SleepBypassGenerator::generate_bypasses(&self, data: &[u8]) -> Vec<Bypass>"""
    bypasses: List[Dict] = []
    for offset, ms in validator_SleepBypassGenerator_scan_large_sleeps(gen, data):
        orig = data[offset:offset + 5]
        # Replace with PUSH 0 (6A 00) + NOP x3
        replacement = b'\x6a\x00' + b'\x90' * 3
        bypasses.append(validator_Bypass_new(offset, orig, replacement,
                                             label=f"Sleep({ms}ms)->0"))
    return bypasses


def validator_CombinedReport_new(data: bytes, config: Optional[Dict] = None) -> Dict:
    """CombinedReport::new(…) -> Self"""
    return {"data": data, "config": config or {}, "debug_detections": [],
            "vm_detections": []}


def validator_CombinedReport_from_data(data: bytes) -> Dict:
    """CombinedReport::from_data(data: &[u8]) -> Self"""
    dbg_scanner = validator_AntiDebugScanner_new()
    vm_scanner = validator_AntiVmScanner_new()
    return {
        "data": data,
        "debug_detections": validator_AntiDebugScanner_scan(dbg_scanner, data),
        "vm_detections": validator_AntiVmScanner_scan(vm_scanner, data),
    }


def validator_CombinedReport_high_confidence_debug(report: Dict,
                                                    threshold: int = 80) -> List[Dict]:
    """CombinedReport::high_confidence_debug(&self) -> Vec<&AntiDebugDetection>"""
    return [d for d in report["debug_detections"] if d.get("confidence", 0) >= threshold]


def validator_CombinedReport_high_confidence_vm(report: Dict,
                                                 threshold: int = 80) -> List[Dict]:
    """CombinedReport::high_confidence_vm(&self) -> Vec<&AntiVmDetection>"""
    return [d for d in report["vm_detections"] if d.get("confidence", 0) >= threshold]


def validator_AntiDebugSigDb_new() -> Dict:
    """AntiDebugSigDb::new() -> Self"""
    sigs = [
        {"name": "IsDebuggerPresent", "pattern": list(_ISDBGPRESENT), "mask": None},
        {"name": "CheckRemoteDebuggerPresent", "pattern": [0x64, 0x8b, 0x15], "mask": None},
        {"name": "NtQueryInformationProcess", "pattern": [0xb8, 0x19, 0x00, 0x00, 0x00], "mask": None},
        {"name": "HeapFlags", "pattern": list(_HEAP_NTGLOBALFLAG), "mask": None},
    ]
    return {"signatures": sigs}


def validator_AntiDebugSigDb_signatures(db: Dict) -> List[Dict]:
    """AntiDebugSigDb::signatures(&self) -> &[AntiDebugSig]"""
    return db["signatures"]


def validator_AntiDebugSigDb_scan_for_anti_debug(db: Dict, data: bytes) -> List[Dict]:
    """AntiDebugSigDb::scan_for_anti_debug(&self, bytes: &[u8]) -> Vec<AntiDebugMatch>"""
    matches: List[Dict] = []
    for sig in db["signatures"]:
        pat = bytes(sig["pattern"])
        mask = bytes(sig["mask"]) if sig.get("mask") else None
        for off in _scan_pattern(data, pat, mask):
            matches.append({"offset": off, "signature_name": sig["name"]})
    return matches


# ---------------------------------------------------------------------------
# src/antidbg_bypass.rs
# ---------------------------------------------------------------------------

def validator_AntiDebugDetector_new() -> Dict:
    """AntiDebugDetector::new() -> Self"""
    return {
        "patterns": [
            {"name": "IsDebuggerPresent", "bytes": list(_ISDBGPRESENT)},
            {"name": "NtQueryInformationProcess", "bytes": [0xb8, 0x19, 0x00, 0x00, 0x00]},
            {"name": "CheckRemoteDebuggerPresent", "bytes": [0x64, 0x8b, 0x15]},
            {"name": "HeapFlags", "bytes": list(_HEAP_NTGLOBALFLAG)},
        ]
    }


def validator_AntiDebugDetector_detect(detector: Dict, data: bytes) -> List[Dict]:
    """AntiDebugDetector::detect(&self, data: &[u8]) -> Vec<DetectionHit>"""
    hits: List[Dict] = []
    for pat in detector["patterns"]:
        for off in _scan_pattern(data, bytes(pat["bytes"])):
            hits.append({"offset": off, "pattern_name": pat["name"]})
    return hits


def validator_BypassPatch_apply(patch: Dict, data: bytearray) -> bool:
    """BypassPatch::apply(&self, data: &mut [u8]) -> Result<(), BypassError>  (returns bool for Python)"""
    off = patch["offset"]
    rb = bytes(patch["replacement_bytes"])
    if off + len(rb) > len(data):
        return False
    data[off:off + len(rb)] = rb
    return True


def validator_BypassPatch_revert(patch: Dict, data: bytearray) -> bool:
    """BypassPatch::revert(&self, data: &mut [u8]) -> Result<(), BypassError>"""
    off = patch["offset"]
    ob = bytes(patch["original_bytes"])
    if off + len(ob) > len(data):
        return False
    data[off:off + len(ob)] = ob
    return True


def validator_BypassPatch_is_applied(patch: Dict, data: bytes) -> bool:
    """BypassPatch::is_applied(&self, data: &[u8]) -> bool"""
    off = patch["offset"]
    rb = bytes(patch["replacement_bytes"])
    return data[off:off + len(rb)] == rb


def validator_PatchSet_new() -> Dict:
    """PatchSet::new() -> Self"""
    return {"patches": []}


def validator_PatchSet_add(pset: Dict, patch: Dict) -> bool:
    """PatchSet::add(&mut self, patch: BypassPatch) -> Result<(), BypassError>"""
    off = patch["offset"]
    plen = len(patch["replacement_bytes"])
    for existing in pset["patches"]:
        eoff = existing["offset"]
        elen = len(existing["replacement_bytes"])
        if off < eoff + elen and off + plen > eoff:
            return False  # overlap
    pset["patches"].append(patch)
    return True


def validator_PatchSet_add_unchecked(pset: Dict, patch: Dict) -> None:
    """PatchSet::add_unchecked(&mut self, patch: BypassPatch)"""
    pset["patches"].append(patch)


def validator_PatchSet_patches(pset: Dict) -> List[Dict]:
    """PatchSet::patches(&self) -> &[BypassPatch]"""
    return pset["patches"]


def validator_PatchSet_apply_all(pset: Dict, data: bytearray) -> bool:
    """PatchSet::apply_all(&self, data: &mut [u8]) -> Result<(), BypassError>"""
    for p in pset["patches"]:
        if not validator_BypassPatch_apply(p, data):
            return False
    return True


def validator_PatchSet_revert_all(pset: Dict, data: bytearray) -> bool:
    """PatchSet::revert_all(&self, data: &mut [u8]) -> Result<(), BypassError>"""
    for p in reversed(pset["patches"]):
        if not validator_BypassPatch_revert(p, data):
            return False
    return True


def validator_PatchSet_for_technique(pset: Dict, technique: str) -> List[Dict]:
    """PatchSet::for_technique(&self, t: AntiDebugTechnique) -> Vec<&BypassPatch>"""
    return [p for p in pset["patches"] if p.get("technique") == technique]


def validator_PatchSet_to_frida_script(pset: Dict) -> str:
    """PatchSet::to_frida_script(&self) -> String"""
    lines = ["'use strict';"]
    for p in pset["patches"]:
        rb = bytes(p["replacement_bytes"]).hex()
        lines.append(f"Memory.patchCode(ptr(0x{p['offset']:x}), {len(p['replacement_bytes'])}, function(code) {{")
        lines.append(f"  code.writeByteArray([{', '.join(hex(b) for b in p['replacement_bytes'])}]);")
        lines.append("});")
    return "\n".join(lines)


def validator_BypassGenerator_new() -> Dict:
    """BypassGenerator::new() -> Self"""
    return {"strategies": {}}


def validator_BypassGenerator_set_strategy(gen: Dict, technique: str, strategy: str) -> None:
    """BypassGenerator::set_strategy(&mut self, technique, strategy)"""
    gen["strategies"][technique] = strategy


def validator_BypassGenerator_generate(gen: Dict, hit: Dict, data: bytes) -> Optional[Dict]:
    """BypassGenerator::generate(&self, hit: &DetectionHit, data: &[u8]) -> Result<BypassPatch>"""
    off = hit["offset"]
    strategy = gen["strategies"].get(hit.get("pattern_name", ""), "nop")
    patch_len = 5
    if off + patch_len > len(data):
        return None
    orig = list(data[off:off + patch_len])
    if strategy == "xor_eax":
        rb = list(_xor_eax_eax_nops(patch_len))
    else:
        rb = list(_nop_sled(patch_len))
    return {"offset": off, "original_bytes": orig, "replacement_bytes": rb,
            "technique": hit.get("pattern_name", "")}


def validator_BypassGenerator_generate_all(gen: Dict, hits: List[Dict],
                                            data: bytes) -> Dict:
    """BypassGenerator::generate_all(&self, hits: &[DetectionHit], data: &[u8]) -> PatchSet"""
    pset = validator_PatchSet_new()
    for hit in hits:
        patch = validator_BypassGenerator_generate(gen, hit, data)
        if patch:
            validator_PatchSet_add(pset, patch)
    return pset


# ---------------------------------------------------------------------------
# src/anti_analysis_patterns.rs
# ---------------------------------------------------------------------------

def validator_AntiAnalysisPatternScanner_new() -> Dict:
    """AntiAnalysisPatternScanner::new() -> Self"""
    return {
        "patterns": [
            {"name": "self_modifying_code", "category": "obfuscation"},
            {"name": "code_cave", "category": "obfuscation"},
            {"name": "import_obfuscation", "category": "obfuscation"},
        ]
    }


def validator_AntiAnalysisPatternScanner_detect(scanner: Dict, data: bytes) -> List[Dict]:
    """AntiAnalysisPatternScanner::detect(&self, data: &[u8]) -> Vec<PatternHit>"""
    hits: List[Dict] = []
    # Heuristic: long NOP sleds (code caves)
    i = 0
    while i < len(data) - 16:
        if data[i:i + 16] == b'\x90' * 16:
            hits.append({"offset": i, "pattern_name": "code_cave", "category": "obfuscation",
                         "confidence": 60})
            i += 16
        else:
            i += 1
    # Heuristic: repeated XOR patterns (possible self-modifying)
    for off in _scan_pattern(data, b'\x30\x00'):  # XOR [eax], al  – simple heuristic
        hits.append({"offset": off, "pattern_name": "self_modifying_code",
                     "category": "obfuscation", "confidence": 50})
    return hits


def validator_RegionDensity_compute(hits: List[Dict], region_size: int) -> Dict:
    """RegionDensity::compute(hits, region_size) -> Self"""
    if not hits or region_size == 0:
        return {"density_per_region": {}, "region_size": region_size}
    regions: Dict[int, int] = defaultdict(int)
    for h in hits:
        region = h["offset"] // region_size
        regions[region] += 1
    return {"density_per_region": dict(regions), "region_size": region_size}


def validator_BinaryDensity_compute(hits: List[Dict], binary_size: int) -> Dict:
    """BinaryDensity::compute(hits, binary_size) -> Self"""
    density = len(hits) / max(1, binary_size / 1024)  # hits per KB
    return {"hit_count": len(hits), "binary_size": binary_size, "density_per_kb": density}


def validator_BinaryDensity_is_obfuscated(density: Dict, threshold: float = 1.0) -> bool:
    """BinaryDensity::is_obfuscated(&self) -> bool"""
    return density["density_per_kb"] > threshold


def validator_CleaningStrategy_for_pattern(pattern: Dict) -> str:
    """CleaningStrategy::for_pattern(pattern) -> Self"""
    cat = pattern.get("category", "")
    mapping = {
        "obfuscation": "nop_fill",
        "anti_debug": "xor_eax_ret",
        "anti_vm": "nop_fill",
        "timing": "nop_fill",
        "evasion": "redirect_flow",
    }
    return mapping.get(cat, "nop_fill")


def validator_strategies_for_hits(hits: List[Dict]) -> List[str]:
    """strategies_for_hits(hits) -> Vec<CleaningStrategy>"""
    return [validator_CleaningStrategy_for_pattern(h) for h in hits]


# ---------------------------------------------------------------------------
# src/anti_debug_patcher.rs
# ---------------------------------------------------------------------------

def validator_DetectionPattern_matches_at(pattern: Dict, data: bytes, offset: int) -> bool:
    """DetectionPattern::matches_at(&self, data: &[u8], offset: usize) -> bool"""
    pat = bytes(pattern["bytes"])
    mask = bytes(pattern["mask"]) if pattern.get("mask") else None
    end = offset + len(pat)
    if end > len(data):
        return False
    if mask:
        return all((data[offset + j] & mask[j]) == (pat[j] & mask[j]) for j in range(len(pat)))
    return data[offset:end] == pat


def validator_DetectionPattern_scan(pattern: Dict, data: bytes) -> List[int]:
    """DetectionPattern::scan(&self, data: &[u8]) -> Vec<usize>"""
    pat = bytes(pattern["bytes"])
    mask = bytes(pattern["mask"]) if pattern.get("mask") else None
    return _scan_pattern(data, pat, mask)


def validator_PatchBytes_nop_sled(length: int) -> bytes:
    """PatchBytes::nop_sled(len: usize) -> Self"""
    return _nop_sled(length)


def validator_PatchBytes_xor_eax_eax_nops(total_len: int) -> bytes:
    """PatchBytes::xor_eax_eax_nops(total_len: usize) -> Self"""
    return _xor_eax_eax_nops(total_len)


def validator_PatchBytes_xor_rax_rax_nops(total_len: int) -> bytes:
    """PatchBytes::xor_rax_rax_nops(total_len: usize) -> Self"""
    return _xor_rax_rax_nops(total_len)


def validator_PatchBytes_short_jump_over(pattern_len: int, skip: int) -> bytes:
    """PatchBytes::short_jump_over(pattern_len, skip) -> Self"""
    # JMP SHORT rel8 = EB <rel8>, relative to end of JMP instruction (2 bytes)
    rel = skip
    if rel > 127 or rel < -128:
        rel = 127
    result = bytes([0xeb, rel & 0xff])
    padding = max(0, pattern_len - 2)
    return result + b'\x90' * padding


def validator_PatchEntry_new(offset: int, technique: str, patch_bytes: bytes) -> Dict:
    """PatchEntry::new(…) -> Self"""
    return {"offset": offset, "technique": technique, "patch_bytes": list(patch_bytes),
            "original_bytes": []}


def validator_PatchEntry_apply(entry: Dict, data: bytearray) -> bool:
    """PatchEntry::apply(&self, data: &mut [u8]) -> bool"""
    off = entry["offset"]
    pb = bytes(entry["patch_bytes"])
    if off + len(pb) > len(data):
        return False
    entry["original_bytes"] = list(data[off:off + len(pb)])
    data[off:off + len(pb)] = pb
    return True


def validator_PatchEntry_rollback(entry: Dict, data: bytearray) -> bool:
    """PatchEntry::rollback(&self, data: &mut [u8]) -> bool"""
    off = entry["offset"]
    ob = bytes(entry["original_bytes"])
    if not ob or off + len(ob) > len(data):
        return False
    data[off:off + len(ob)] = ob
    return True


def validator_PatchEntry_byte_count(entry: Dict) -> int:
    """PatchEntry::byte_count(&self) -> usize"""
    return len(entry["patch_bytes"])


def validator_AntiDebugPatcher_builtin_patterns() -> List[Dict]:
    """AntiDebugPatcher::builtin_patterns() -> Vec<DetectionPattern>"""
    return [
        {"name": "IsDebuggerPresent", "bytes": list(_ISDBGPRESENT), "mask": None, "patch_len": 5},
        {"name": "NtQueryInformationProcess", "bytes": [0xb8, 0x19, 0x00, 0x00, 0x00],
         "mask": None, "patch_len": 5},
        {"name": "CheckRemoteDebuggerPresent", "bytes": [0x64, 0x8b, 0x15], "mask": None,
         "patch_len": 3},
        {"name": "OutputDebugString", "bytes": [0x64, 0xa1, 0x18, 0x00, 0x00, 0x00],
         "mask": None, "patch_len": 6},
        {"name": "HeapFlags", "bytes": list(_HEAP_NTGLOBALFLAG), "mask": None, "patch_len": 4},
    ]


def validator_AntiDebugPatcher_new() -> Dict:
    """AntiDebugPatcher::new() -> Self"""
    return {"patterns": validator_AntiDebugPatcher_builtin_patterns(),
            "min_confidence": 50, "custom_patch_lens": {}}


def validator_AntiDebugPatcher_with_min_confidence(patcher: Dict, threshold: int) -> Dict:
    """AntiDebugPatcher::with_min_confidence(mut self, threshold: u8) -> Self"""
    p = dict(patcher)
    p["min_confidence"] = max(0, min(100, threshold))
    return p


def validator_AntiDebugPatcher_add_pattern(patcher: Dict, pattern: Dict) -> None:
    """AntiDebugPatcher::add_pattern(&mut self, pattern)"""
    patcher["patterns"].append(pattern)


def validator_AntiDebugPatcher_set_custom_patch_len(patcher: Dict, technique: str,
                                                     length: int) -> None:
    """AntiDebugPatcher::set_custom_patch_len(&mut self, technique, len)"""
    patcher["custom_patch_lens"][technique] = length


def validator_AntiDebugPatcher_scan(patcher: Dict, data: bytes) -> List[Dict]:
    """AntiDebugPatcher::scan(&self, data: &[u8]) -> Vec<PatchEntry>"""
    entries: List[Dict] = []
    for pat in patcher["patterns"]:
        offsets = validator_DetectionPattern_scan(pat, data)
        patch_len = patcher["custom_patch_lens"].get(pat["name"], pat.get("patch_len", 5))
        for off in offsets:
            pb = _xor_eax_eax_nops(patch_len)
            entries.append(validator_PatchEntry_new(off, pat["name"], pb))
    return entries


def validator_AntiDebugPatcher_patch_all(patcher: Dict, data: bytes) -> Tuple[bytes, int]:
    """AntiDebugPatcher::patch_all(&self, data: &[u8]) -> (Vec<u8>, usize)"""
    buf = bytearray(data)
    entries = validator_AntiDebugPatcher_scan(patcher, data)
    count = 0
    for e in entries:
        if validator_PatchEntry_apply(e, buf):
            count += 1
    return bytes(buf), count


def validator_AntiDebugPatcher_patch_technique(patcher: Dict, data: bytes,
                                                technique: str) -> Tuple[bytes, int]:
    """AntiDebugPatcher::patch_technique(&self, data, technique) -> (Vec<u8>, usize)"""
    buf = bytearray(data)
    entries = [e for e in validator_AntiDebugPatcher_scan(patcher, data)
               if e["technique"] == technique]
    count = 0
    for e in entries:
        if validator_PatchEntry_apply(e, buf):
            count += 1
    return bytes(buf), count


def validator_AntiDebugPatcher_report(patcher: Dict, data: bytes) -> Dict:
    """AntiDebugPatcher::report(&self, data: &[u8]) -> PatchReport"""
    entries = validator_AntiDebugPatcher_scan(patcher, data)
    by_technique: Dict[str, int] = defaultdict(int)
    for e in entries:
        by_technique[e["technique"]] += 1
    return {"entries": entries, "by_technique": dict(by_technique)}


def validator_AntiDebugPatcher_pattern_count(patcher: Dict) -> int:
    """AntiDebugPatcher::pattern_count(&self) -> usize"""
    return len(patcher["patterns"])


def validator_AntiDebugPatcher_verify_original(entry: Dict, data: bytes) -> bool:
    """AntiDebugPatcher::verify_original(entry, data) -> bool"""
    off = entry["offset"]
    ob = bytes(entry.get("original_bytes", []))
    if not ob:
        return True  # not yet captured
    return data[off:off + len(ob)] == ob


def validator_PatchReport_detected_techniques(report: Dict) -> List[str]:
    """PatchReport::detected_techniques(&self) -> Vec<AntiDebugTechnique>"""
    return list(report["by_technique"].keys())


def validator_PatchReport_hits_for(report: Dict, technique: str) -> int:
    """PatchReport::hits_for(&self, technique) -> usize"""
    return report["by_technique"].get(technique, 0)


def validator_PatchReport_format_text(report: Dict) -> str:
    """PatchReport::format_text(&self) -> String"""
    lines = [f"AntiDebug Patch Report — {len(report['entries'])} entries"]
    for tech, cnt in report["by_technique"].items():
        lines.append(f"  {tech}: {cnt} hit(s)")
    return "\n".join(lines)


def validator_IsDebuggerPresentScanner_patch_bytes() -> bytes:
    """IsDebuggerPresentScanner::patch_bytes() -> PatchBytes"""
    # XOR AL,AL + RET
    return b'\x30\xc0\xc3' + b'\x90' * 2


def validator_IsDebuggerPresentScanner_scan(data: bytes) -> List[Dict]:
    """IsDebuggerPresentScanner::scan(data) -> Vec<PatchEntry>"""
    entries: List[Dict] = []
    for off in _scan_pattern(data, _ISDBGPRESENT):
        pb = validator_IsDebuggerPresentScanner_patch_bytes()
        entries.append(validator_PatchEntry_new(off, "IsDebuggerPresent", pb))
    return entries


def validator_NtQueryScanner_scan(data: bytes) -> List[Dict]:
    """NtQueryScanner::scan(data) -> Vec<PatchEntry>"""
    entries: List[Dict] = []
    pat = bytes([0xb8, 0x19, 0x00, 0x00, 0x00])  # MOV EAX, 0x19 (NtQueryInformationProcess)
    for off in _scan_pattern(data, pat):
        pb = _xor_eax_eax_nops(5)
        entries.append(validator_PatchEntry_new(off, "NtQueryInformationProcess", pb))
    return entries


def validator_HeapFlagScanner_scan(data: bytes) -> List[Dict]:
    """HeapFlagScanner::scan(data) -> Vec<PatchEntry>"""
    entries: List[Dict] = []
    for off in _scan_pattern(data, _HEAP_NTGLOBALFLAG):
        pb = _nop_sled(4)
        entries.append(validator_PatchEntry_new(off, "HeapFlags", pb))
    return entries


# ---------------------------------------------------------------------------
# src/bypasser.rs
# ---------------------------------------------------------------------------

def validator_bypasser_BypassPatch_apply(patch: Dict, buf: bytearray) -> bool:
    """bypasser::BypassPatch::apply(&self, buf: &mut [u8]) -> bool"""
    return validator_BypassPatch_apply(patch, buf)


def validator_bypasser_BypassPatch_revert(patch: Dict, buf: bytearray) -> bool:
    """bypasser::BypassPatch::revert(&self, buf: &mut [u8]) -> bool"""
    return validator_BypassPatch_revert(patch, buf)


def validator_Bypasser_generate_patches(bypasser: Dict, data: bytes,
                                         sites: List[Dict]) -> List[Dict]:
    """Bypasser::generate_patches(&self, data: &[u8], sites: &[DetectionSite]) -> Vec<BypassPatch>"""
    patches: List[Dict] = []
    for site in sites:
        off = site["offset"]
        patch_len = site.get("patch_len", 5)
        if off + patch_len > len(data):
            continue
        orig = list(data[off:off + patch_len])
        rb = list(_xor_eax_eax_nops(patch_len))
        patches.append({"offset": off, "original_bytes": orig, "replacement_bytes": rb,
                         "technique": site.get("technique", "")})
    return patches


def validator_Bypasser_generate_frida_hooks(bypasser: Dict, sites: List[Dict]) -> List[Dict]:
    """Bypasser::generate_frida_hooks(&self, sites: &[DetectionSite]) -> Vec<FridaHookScript>"""
    hooks: List[Dict] = []
    for site in sites:
        script = (
            f"Interceptor.attach(ptr(0x{site['offset']:x}), {{\n"
            f"  onEnter: function(args) {{ /* neutralize {site.get('technique','')} */ }}\n"
            f"}});"
        )
        hooks.append({"offset": site["offset"], "technique": site.get("technique", ""),
                       "script": script})
    return hooks


# ---------------------------------------------------------------------------
# src/detector.rs
# ---------------------------------------------------------------------------

def validator_Detector_new(config: Optional[Dict] = None) -> Dict:
    """Detector::new(…) -> Self"""
    return {"config": config or {"min_confidence": 50}, "techniques": []}


def validator_Detector_scan(detector: Dict, data: bytes) -> List[Dict]:
    """Detector::scan(&self, data: &[u8]) -> Vec<DetectionSite>"""
    sites: List[Dict] = []
    min_conf = detector["config"].get("min_confidence", 50)

    def _add(off: int, tech: str, conf: int) -> None:
        if conf >= min_conf:
            sites.append({"offset": off, "technique": tech, "confidence": conf})

    for off in _scan_pattern(data, _ISDBGPRESENT):
        _add(off, "IsDebuggerPresent", 85)
    for off in _scan_pattern(data, _RDTSC):
        _add(off, "RDTSC", 70)
    for off in _scan_pattern(data, _CPUID):
        _add(off, "CPUID", 65)
    for off in _scan_pattern(data, _SIDT):
        _add(off, "SIDT_redpill", 80)
    for off in _scan_pattern(data, _INT2E):
        _add(off, "INT2E_syscall", 75)
    return sites


def validator_Detector_summarize(detector: Dict, sites: List[Dict]) -> List[Tuple[str, int]]:
    """Detector::summarize(&self, sites: &[DetectionSite]) -> Vec<(DetectedTechnique, usize)>"""
    counts: Dict[str, int] = defaultdict(int)
    for s in sites:
        counts[s["technique"]] += 1
    return sorted(counts.items(), key=lambda x: x[1], reverse=True)


# ---------------------------------------------------------------------------
# src/environment_spoofer.rs
# ---------------------------------------------------------------------------

def validator_VmProduct_display_name(product_id: int) -> str:
    """VmProduct::display_name(self) -> &'static str"""
    return _VM_PRODUCT_NAMES.get(product_id, "Unknown")


def validator_EnvironmentSpoofer_new(config: Dict) -> Dict:
    """EnvironmentSpoofer::new(config: SpooferConfig) -> Self"""
    return {"config": config, "spoof_rules": []}


def validator_EnvironmentSpoofer_with_defaults() -> Dict:
    """EnvironmentSpoofer::with_defaults() -> Self"""
    return {"config": {"hide_all_known_vms": True}, "spoof_rules": [
        {"target": "VMware", "spoof_value": ""},
        {"target": "VirtualBox", "spoof_value": ""},
    ]}


def validator_EnvironmentSpoofer_generate_frida_script(spoofer: Dict) -> str:
    """EnvironmentSpoofer::generate_frida_script(&self) -> String"""
    lines = ["'use strict';", "// Environment spoofing script"]
    for rule in spoofer.get("spoof_rules", []):
        lines.append(f"// Spoof: {rule['target']} -> '{rule['spoof_value']}'")
    lines.append("// Intercept registry queries for VM keys")
    lines.append("var RegQueryValueExW = Module.findExportByName('advapi32.dll', 'RegQueryValueExW');")
    lines.append("if (RegQueryValueExW) { Interceptor.attach(RegQueryValueExW, { onLeave: function(ret) { ret.replace(2); } }); }")
    return "\n".join(lines)


def validator_EnvironmentSpoofer_generate_binary_patches(spoofer: Dict,
                                                          iat_map: Dict[str, int]) -> List[Dict]:
    """EnvironmentSpoofer::generate_binary_patches(&self, iat_map) -> Vec<BinaryPatch>"""
    patches: List[Dict] = []
    for name, addr in iat_map.items():
        if any(vm in name for vm in ["RegQueryValueEx", "GetSystemInfo", "cpuid"]):
            patches.append({"iat_name": name, "iat_address": addr,
                             "patch_type": "redirect_to_stub"})
    return patches


def validator_EnvironmentSpoofer_summary(spoofer: Dict) -> str:
    """EnvironmentSpoofer::summary(&self) -> String"""
    rules = spoofer.get("spoof_rules", [])
    lines = [f"EnvironmentSpoofer: {len(rules)} spoof rule(s)"]
    for r in rules:
        lines.append(f"  {r['target']} -> '{r['spoof_value']}'")
    return "\n".join(lines)


def validator_patch_peb_fields(peb_data: bytearray, layout: Dict) -> None:
    """patch_peb_fields(peb_data: &mut [u8], layout: PebLayout)"""
    being_dbg_off = layout.get("being_debugged_offset", 2)
    ntglobal_off = layout.get("nt_global_flag_offset", 0x68)
    if being_dbg_off < len(peb_data):
        peb_data[being_dbg_off] = 0
    if ntglobal_off + 4 <= len(peb_data):
        peb_data[ntglobal_off:ntglobal_off + 4] = b'\x00\x00\x00\x00'


# ---------------------------------------------------------------------------
# src/evasion_patterns.rs
# ---------------------------------------------------------------------------

def validator_EvasionPattern_matches_at(pattern: Dict, data: bytes, offset: int) -> bool:
    """EvasionPattern::matches_at(&self, data: &[u8], offset: usize) -> bool"""
    return validator_DetectionPattern_matches_at(pattern, data, offset)


def validator_EvasionScanner_new() -> Dict:
    """EvasionScanner::new() -> Self"""
    return {
        "patterns": [
            {"name": "rdtsc", "bytes": list(_RDTSC), "mask": None, "category": "timing"},
            {"name": "cpuid_hv", "bytes": list(_CPUID), "mask": None, "category": "anti_vm"},
            {"name": "sidt", "bytes": list(_SIDT), "mask": None, "category": "anti_vm"},
            {"name": "int2e", "bytes": list(_INT2E), "mask": None, "category": "evasion"},
            {"name": "isdebugpresent", "bytes": list(_ISDBGPRESENT), "mask": None,
             "category": "anti_debug"},
        ]
    }


def validator_EvasionScanner_scan(scanner: Dict, data: bytes) -> List[Dict]:
    """EvasionScanner::scan(&self, data: &[u8]) -> Vec<EvasionMatch>"""
    matches: List[Dict] = []
    for pat in scanner["patterns"]:
        for off in validator_DetectionPattern_scan(pat, data):
            matches.append({"offset": off, "pattern_name": pat["name"],
                             "category": pat["category"], "confidence": 75})
    return matches


def validator_EvasionScanner_scan_category(scanner: Dict, data: bytes,
                                            category: str) -> List[Dict]:
    """EvasionScanner::scan_category(&self, data, cat) -> Vec<EvasionMatch>"""
    filtered = {"patterns": [p for p in scanner["patterns"] if p["category"] == category]}
    return validator_EvasionScanner_scan(filtered, data)


def validator_EvasionScanner_category_count(scanner: Dict, category: str) -> int:
    """EvasionScanner::category_count(&self, cat) -> usize"""
    return sum(1 for p in scanner["patterns"] if p["category"] == category)


def validator_EvasionStats_new() -> Dict:
    """EvasionStats::new() -> Self"""
    return {"records": [], "max_confidence": 0}


def validator_EvasionStats_record(stats: Dict, category: str, confidence: int) -> None:
    """EvasionStats::record(&mut self, category, confidence)"""
    stats["records"].append({"category": category, "confidence": confidence})
    if confidence > stats["max_confidence"]:
        stats["max_confidence"] = confidence


def validator_EvasionStats_from_matches(matches: List[Dict]) -> Dict:
    """EvasionStats::from_matches(matches) -> Self"""
    stats = validator_EvasionStats_new()
    for m in matches:
        validator_EvasionStats_record(stats, m.get("category", ""), m.get("confidence", 0))
    return stats


def validator_EvasionStats_max_confidence(stats: Dict) -> int:
    """EvasionStats::max_confidence(&self) -> u8"""
    return stats["max_confidence"]


def validator_EvasionFilter_new() -> Dict:
    """EvasionFilter::new() -> Self"""
    return {"category": None}


def validator_EvasionFilter_only_category(filt: Dict, category: str) -> Dict:
    """EvasionFilter::only_category(mut self, cat) -> Self"""
    f = dict(filt)
    f["category"] = category
    return f


def validator_EvasionFilter_passes(filt: Dict, pattern: Dict) -> bool:
    """EvasionFilter::passes(&self, p: &EvasionPattern) -> bool"""
    if filt["category"] is None:
        return True
    return pattern.get("category") == filt["category"]


def validator_EvasionFilter_apply(filt: Dict, patterns: List[Dict]) -> List[Dict]:
    """EvasionFilter::apply<'a>(&self, patterns) -> Vec<&'a EvasionPattern>"""
    return [p for p in patterns if validator_EvasionFilter_passes(filt, p)]


def validator_EvasionPatternLibrary_build() -> Dict:
    """EvasionPatternLibrary::build() -> Self"""
    scanner = validator_EvasionScanner_new()
    return {"patterns": scanner["patterns"]}


def validator_EvasionPatternLibrary_get_by_name(lib: Dict, name: str) -> Optional[Dict]:
    """EvasionPatternLibrary::get_by_name(&self, name) -> Option<&EvasionPattern>"""
    for p in lib["patterns"]:
        if p["name"] == name:
            return p
    return None


def validator_EvasionPatternLibrary_get_by_category(lib: Dict, category: str) -> List[Dict]:
    """EvasionPatternLibrary::get_by_category(&self, category) -> Vec<&EvasionPattern>"""
    return [p for p in lib["patterns"] if p["category"] == category]


def validator_EvasionPatternLibrary_categories(lib: Dict) -> List[str]:
    """EvasionPatternLibrary::categories(&self) -> Vec<&str>"""
    return list({p["category"] for p in lib["patterns"]})


def validator_EvasionReport_from_matches(matches: List[Dict]) -> Dict:
    """EvasionReport::from_matches(matches) -> Self"""
    by_cat: Dict[str, List[Dict]] = defaultdict(list)
    for m in matches:
        by_cat[m.get("category", "unknown")].append(m)
    return {"matches": matches, "by_category": dict(by_cat), "total": len(matches)}


def validator_BypassSuggestionEngine_generate(engine: Dict, matches: List[Dict]) -> List[Dict]:
    """BypassSuggestionEngine::generate(&self, matches) -> Vec<BypassSuggestion>"""
    suggestions: List[Dict] = []
    for m in matches:
        suggestions.append({
            "offset": m["offset"],
            "pattern": m.get("pattern_name", ""),
            "suggestion": f"NOP-fill {m.get('pattern_name','')} at 0x{m['offset']:x}",
            "frida_available": True,
        })
    return suggestions


def validator_EvasionSummary_from_matches(matches: List[Dict]) -> Dict:
    """EvasionSummary::from_matches(matches) -> Self"""
    cats: Dict[str, int] = defaultdict(int)
    for m in matches:
        cats[m.get("category", "unknown")] += 1
    return {"total": len(matches), "by_category": dict(cats),
            "dominant_category": max(cats, key=cats.__getitem__, default=None)}


def validator_EvasionSummary_is_evasive(summary: Dict, threshold: int = 1) -> bool:
    """EvasionSummary::is_evasive(&self) -> bool"""
    return summary["total"] >= threshold


def validator_AntiDebugEvasion_scan(evasion: Dict, data: bytes) -> List[Dict]:
    """AntiDebugEvasion::scan(&self, data) -> Vec<EvasionMatch>"""
    scanner = {"patterns": [p for p in validator_EvasionScanner_new()["patterns"]
                             if p["category"] == "anti_debug"]}
    return validator_EvasionScanner_scan(scanner, data)


def validator_AntiDebugEvasion_is_present(evasion: Dict, data: bytes) -> bool:
    """AntiDebugEvasion::is_present(&self, data) -> bool"""
    return len(validator_AntiDebugEvasion_scan(evasion, data)) > 0


def validator_TimingEvasion_scan(evasion: Dict, data: bytes) -> List[Dict]:
    """TimingEvasion::scan(&self, data) -> Vec<EvasionMatch>"""
    scanner = {"patterns": [p for p in validator_EvasionScanner_new()["patterns"]
                             if p["category"] == "timing"]}
    return validator_EvasionScanner_scan(scanner, data)


def validator_TimingEvasion_has_rdtsc(evasion: Dict, data: bytes) -> bool:
    """TimingEvasion::has_rdtsc(&self, data) -> bool"""
    return len(_scan_pattern(data, _RDTSC)) > 0


def validator_ProcessEvasion_scan(evasion: Dict, data: bytes) -> List[Dict]:
    """ProcessEvasion::scan(&self, data) -> Vec<EvasionMatch>"""
    # Heuristic: look for CreateToolhelp32Snapshot string reference
    matches: List[Dict] = []
    for pat in [b'CreateToolhelp32Snapshot', b'NtQuerySystemInformation', b'ParentProcessId']:
        for off in _scan_pattern(data, pat):
            matches.append({"offset": off, "pattern_name": "process_check",
                             "category": "evasion", "confidence": 70})
    return matches


def validator_ProcessEvasion_has_process_check(evasion: Dict, data: bytes) -> bool:
    """ProcessEvasion::has_process_check(&self, data) -> bool"""
    return len(validator_ProcessEvasion_scan(evasion, data)) > 0


def validator_SyscallEvasion_scan(evasion: Dict, data: bytes) -> List[Dict]:
    """SyscallEvasion::scan(&self, data) -> Vec<EvasionMatch>"""
    matches: List[Dict] = []
    # Direct syscall: MOV EAX, <syscall_num> + SYSCALL (0F 05) or SYSENTER (0F 34)
    for pat in [b'\x0f\x05', b'\x0f\x34']:
        for off in _scan_pattern(data, pat):
            matches.append({"offset": off, "pattern_name": "direct_syscall",
                             "category": "evasion", "confidence": 80})
    for off in _scan_pattern(data, _INT2E):
        matches.append({"offset": off, "pattern_name": "int2e_syscall",
                         "category": "evasion", "confidence": 75})
    return matches


def validator_SyscallEvasion_has_direct_syscall(evasion: Dict, data: bytes) -> bool:
    """SyscallEvasion::has_direct_syscall(&self, data) -> bool"""
    return any(m["pattern_name"] == "direct_syscall"
               for m in validator_SyscallEvasion_scan(evasion, data))


def validator_SyscallEvasion_has_int2e(evasion: Dict, data: bytes) -> bool:
    """SyscallEvasion::has_int2e(&self, data) -> bool"""
    return len(_scan_pattern(data, _INT2E)) > 0


def validator_comprehensive_scan(data: bytes) -> Dict:
    """comprehensive_scan(data: &[u8]) -> ComprehensiveEvasionResult"""
    scanner = validator_EvasionScanner_new()
    evasion = {}
    matches = validator_EvasionScanner_scan(scanner, data)
    process_matches = validator_ProcessEvasion_scan(evasion, data)
    syscall_matches = validator_SyscallEvasion_scan(evasion, data)
    all_matches = matches + process_matches + syscall_matches
    return {
        "matches": all_matches,
        "summary": validator_EvasionSummary_from_matches(all_matches),
        "stats": validator_EvasionStats_from_matches(all_matches),
    }


def validator_filter_by_confidence(matches: List[Dict], min_conf: int) -> List[Dict]:
    """filter_by_confidence(matches, min_conf) -> Vec<&EvasionMatch>"""
    return [m for m in matches if m.get("confidence", 0) >= min_conf]


def validator_group_by_category(matches: List[Dict]) -> Dict[str, List[Dict]]:
    """group_by_category(matches) -> HashMap<EvasionCategory, Vec<&EvasionMatch>>"""
    result: Dict[str, List[Dict]] = defaultdict(list)
    for m in matches:
        result[m.get("category", "unknown")].append(m)
    return dict(result)


# ---------------------------------------------------------------------------
# src/exception_based_antidebug.rs
# ---------------------------------------------------------------------------

def validator_SehTrick_new(offset: int, kind: str, data_bytes: bytes) -> Dict:
    """SehTrick::new(…) -> Self"""
    return {"offset": offset, "kind": kind, "bytes": list(data_bytes)}


def validator_SehPatch_new(from_offset: int, to_offset: int, label: str) -> Dict:
    """SehPatch::new(…) -> Self"""
    return {"from_offset": from_offset, "to_offset": to_offset, "label": label,
            "original_bytes": []}


def validator_SehPatch_apply(patch: Dict, binary: bytearray) -> bool:
    """SehPatch::apply(&self, binary: &mut Vec<u8>) -> Result<(), String>"""
    off = patch["from_offset"]
    # NOP-fill the SEH trick location
    trick_len = 5
    if off + trick_len > len(binary):
        return False
    patch["original_bytes"] = list(binary[off:off + trick_len])
    binary[off:off + trick_len] = _nop_sled(trick_len)
    return True


def validator_SehPatch_rollback(patch: Dict, binary: bytearray) -> bool:
    """SehPatch::rollback(&self, binary: &mut Vec<u8>) -> Result<(), String>"""
    off = patch["from_offset"]
    ob = bytes(patch.get("original_bytes", []))
    if not ob or off + len(ob) > len(binary):
        return False
    binary[off:off + len(ob)] = ob
    return True


def validator_ExceptionRoute_new(from_off: int, to_off: int, label: str) -> Dict:
    """ExceptionRoute::new(from, to, label) -> Self"""
    return {"from_offset": from_off, "to_offset": to_off, "label": label}


def validator_SehDetector_new() -> Dict:
    """SehDetector::new() -> Self"""
    # SEH patterns: INT 3 (CC), UD2 (0F 0B), typical SEH chain traversal
    return {
        "patterns": [
            {"name": "int3_seh", "bytes": [0xcc], "kind": "INT3"},
            {"name": "ud2", "bytes": [0x0f, 0x0b], "kind": "UD2"},
        ]
    }


def validator_SehDetector_scan(detector: Dict, binary: bytes) -> List[Dict]:
    """SehDetector::scan(&self, binary: &[u8]) -> Vec<SehTrick>"""
    tricks: List[Dict] = []
    for pat in detector["patterns"]:
        for off in _scan_pattern(binary, bytes(pat["bytes"])):
            tricks.append(validator_SehTrick_new(off, pat["kind"], bytes(pat["bytes"])))
    return tricks


def validator_SehDetector_generate_patches(detector: Dict, binary: bytes) -> List[Dict]:
    """SehDetector::generate_patches(&self, binary: &[u8]) -> Vec<SehPatch>"""
    tricks = validator_SehDetector_scan(detector, binary)
    return [validator_SehPatch_new(t["offset"], t["offset"] + len(t["bytes"]),
                                    f"SEH_{t['kind']}") for t in tricks]


def validator_SehDetector_neutralize(detector: Dict, binary: bytearray) -> Tuple[int, List[str]]:
    """SehDetector::neutralize(&self, binary: &mut Vec<u8>) -> (usize, Vec<String>)"""
    patches = validator_SehDetector_generate_patches(detector, bytes(binary))
    count = 0
    log: List[str] = []
    for p in patches:
        if validator_SehPatch_apply(p, binary):
            count += 1
            log.append(f"Neutralized SEH @ 0x{p['from_offset']:x} ({p['label']})")
    return count, log


def validator_SehDetector_extract_routes(tricks: List[Dict]) -> List[Dict]:
    """SehDetector::extract_routes(tricks) -> Vec<ExceptionRoute>"""
    routes: List[Dict] = []
    for i, t in enumerate(tricks):
        next_off = tricks[i + 1]["offset"] if i + 1 < len(tricks) else t["offset"] + 5
        routes.append(validator_ExceptionRoute_new(t["offset"], next_off,
                                                    f"exception_route_{i}"))
    return routes


def validator_SehDetector_frida_script(tricks: List[Dict]) -> str:
    """SehDetector::frida_script(tricks) -> String"""
    lines = ["'use strict';", "// SEH/VEH bypass script"]
    for t in tricks:
        lines.append(f"// SEH trick {t['kind']} @ 0x{t['offset']:x}")
    lines.append("Process.setExceptionHandler(function(details) { return true; });")
    return "\n".join(lines)


def validator_SehDetector_trick_histogram(tricks: List[Dict]) -> Dict[str, int]:
    """SehDetector::trick_histogram(tricks) -> HashMap<ExceptionCheckKind, usize>"""
    hist: Dict[str, int] = defaultdict(int)
    for t in tricks:
        hist[t["kind"]] += 1
    return dict(hist)


# ---------------------------------------------------------------------------
# src/timing_attack_neutralizer.rs
# ---------------------------------------------------------------------------

def validator_TimingCheck_new(offset: int, kind: str, context: bytes) -> Dict:
    """TimingCheck::new(…) -> Self"""
    return {"offset": offset, "kind": kind, "context": list(context)}


def validator_NeutralizePatch_new(offset: int, original: bytes, replacement: bytes) -> Dict:
    """NeutralizePatch::new(…) -> Self"""
    return {"offset": offset, "original_bytes": list(original),
            "replacement_bytes": list(replacement)}


def validator_NeutralizePatch_apply(patch: Dict, binary: bytearray) -> bool:
    """NeutralizePatch::apply(&self, binary: &mut Vec<u8>) -> Result<(), String>"""
    off = patch["offset"]
    rb = bytes(patch["replacement_bytes"])
    if off + len(rb) > len(binary):
        return False
    binary[off:off + len(rb)] = rb
    return True


def validator_NeutralizePatch_rollback(patch: Dict, binary: bytearray) -> bool:
    """NeutralizePatch::rollback(&self, binary: &mut Vec<u8>) -> Result<(), String>"""
    off = patch["offset"]
    ob = bytes(patch["original_bytes"])
    if not ob or off + len(ob) > len(binary):
        return False
    binary[off:off + len(ob)] = ob
    return True


def validator_TimingNeutralizer_new() -> Dict:
    """TimingNeutralizer::new() -> Self"""
    return {
        "patterns": [
            {"kind": "RDTSC", "bytes": list(_RDTSC)},
            {"kind": "GetTickCount", "bytes": [0xff, 0x15]},  # simplified
            {"kind": "Sleep", "bytes": [0x68]},               # PUSH imm (Sleep arg)
        ]
    }


def validator_TimingNeutralizer_scan(neutralizer: Dict, binary: bytes) -> List[Dict]:
    """TimingNeutralizer::scan(&self, binary: &[u8]) -> Vec<TimingCheck>"""
    checks: List[Dict] = []
    for pat in neutralizer["patterns"]:
        for off in _scan_pattern(binary, bytes(pat["bytes"])):
            ctx = binary[max(0, off - 4):off + len(pat["bytes"]) + 4]
            checks.append(validator_TimingCheck_new(off, pat["kind"], ctx))
    return checks


def validator_TimingNeutralizer_generate_patches(neutralizer: Dict,
                                                  binary: bytes) -> List[Dict]:
    """TimingNeutralizer::generate_patches(&self, binary: &[u8]) -> Vec<NeutralizePatch>"""
    patches: List[Dict] = []
    for check in validator_TimingNeutralizer_scan(neutralizer, binary):
        off = check["offset"]
        patch_len = 2 if check["kind"] == "RDTSC" else 5
        orig = list(binary[off:off + patch_len])
        rb = list(_nop_sled(patch_len))
        patches.append(validator_NeutralizePatch_new(off, bytes(orig), bytes(rb)))
    return patches


def validator_TimingNeutralizer_neutralize(neutralizer: Dict,
                                            binary: bytearray) -> Tuple[int, List[str]]:
    """TimingNeutralizer::neutralize(&self, binary: &mut Vec<u8>) -> (usize, Vec<String>)"""
    patches = validator_TimingNeutralizer_generate_patches(neutralizer, bytes(binary))
    count = 0
    log: List[str] = []
    for p in patches:
        if validator_NeutralizePatch_apply(p, binary):
            count += 1
            log.append(f"Neutralized timing @ 0x{p['offset']:x}")
    return count, log


def validator_TimingNeutralizer_frida_script(neutralizer: Dict,
                                              checks: List[Dict]) -> str:
    """TimingNeutralizer::frida_script(&self, checks: &[TimingCheck]) -> String"""
    lines = ["'use strict';", "// Timing check neutralization"]
    for c in checks:
        lines.append(f"// {c['kind']} @ 0x{c['offset']:x}")
    lines.append("var GetTickCount = Module.findExportByName('kernel32.dll', 'GetTickCount');")
    lines.append("if (GetTickCount) { Interceptor.replace(GetTickCount, new NativeCallback(function() { return 1; }, 'uint32', [])); }")
    return "\n".join(lines)


def validator_TimingNeutralizer_patch_summary(patches: List[Dict]) -> Dict[str, int]:
    """TimingNeutralizer::patch_summary(patches) -> HashMap<TimingCheckKind, usize>"""
    # patches don't carry kind here; return by offset count as placeholder
    return {"neutralized": len(patches)}


# ---------------------------------------------------------------------------
# src/timing_bypass.rs
# ---------------------------------------------------------------------------

def validator_TimingTechnique_label(technique_id: int) -> str:
    """TimingTechnique::label(self) -> String"""
    labels = {0: "RDTSC", 1: "GetTickCount", 2: "GetTickCount64",
               3: "QueryPerformanceCounter", 4: "Sleep"}
    return labels.get(technique_id, "Unknown")


def validator_TimingBypassScanner_new(config: Optional[Dict] = None) -> Dict:
    """TimingBypassScanner::new(…) -> Self"""
    return {"config": config or {"min_confidence": 50}, "min_confidence": 50}


def validator_TimingBypassReport_from_hits(hits: List[Dict]) -> Dict:
    """TimingBypassReport::from_hits(hits: Vec<TimingHit>) -> Self"""
    return {"hits": hits}


def validator_TimingBypassReport_high_confidence_hits(report: Dict,
                                                       threshold: int = 80) -> List[Dict]:
    """TimingBypassReport::high_confidence_hits(&self) -> Vec<&TimingHit>"""
    return [h for h in report["hits"] if h.get("confidence", 0) >= threshold]


def validator_TimingBypassReport_patchable_hits(report: Dict) -> List[Dict]:
    """TimingBypassReport::patchable_hits(&self) -> Vec<&TimingHit>"""
    return [h for h in report["hits"] if h.get("patchable", True)]


def validator_TimingBypassScanner_with_min_confidence(scanner: Dict, min_conf: int) -> Dict:
    """TimingBypassScanner::with_min_confidence(mut self, min: u32) -> Self"""
    s = dict(scanner)
    s["min_confidence"] = min_conf
    return s


def validator_TimingBypassScanner_scan(scanner: Dict, data: bytes) -> Dict:
    """TimingBypassScanner::scan(&self, data: &[u8]) -> TimingBypassReport"""
    hits: List[Dict] = []
    min_conf = scanner.get("min_confidence", 50)
    for off in _scan_pattern(data, _RDTSC):
        hits.append({"offset": off, "technique": "RDTSC", "confidence": 70, "patchable": True})
    for off in _scan_pattern(data, _SLEEP_CALL):
        hits.append({"offset": off, "technique": "Sleep", "confidence": 60, "patchable": True})
    hits = [h for h in hits if h["confidence"] >= min_conf]
    return validator_TimingBypassReport_from_hits(hits)


def validator_apply_patches(data: bytearray, patches: List[Dict]) -> bool:
    """apply_patches(…) -> …"""
    for p in patches:
        off = p["offset"]
        rb = bytes(p.get("replacement_bytes", p.get("patch_bytes", [])))
        if off + len(rb) > len(data):
            return False
        data[off:off + len(rb)] = rb
    return True


# ---------------------------------------------------------------------------
# src/timing_check_detector.rs
# ---------------------------------------------------------------------------

def validator_ImmediateValue_new(value: int, offset: int, size: int) -> Dict:
    """ImmediateValue::new(value, offset, size) -> Self"""
    return {"value": value, "offset": offset, "size": size}


def validator_TimingCheck_patch_byte_count(check: Dict) -> int:
    """TimingCheck::patch_byte_count(&self) -> usize"""
    kind_sizes = {"RDTSC": 2, "GetTickCount": 5, "Sleep": 5, "QPC": 6}
    return kind_sizes.get(check.get("kind", ""), 5)


def validator_TimingCheck_affected_offsets(check: Dict) -> List[int]:
    """TimingCheck::affected_offsets(&self) -> Vec<usize>"""
    off = check["offset"]
    count = validator_TimingCheck_patch_byte_count(check)
    return list(range(off, off + count))


def validator_TimingCheckDetector_new() -> Dict:
    """TimingCheckDetector::new() -> Self"""
    return {"sleep_threshold_ms": 200, "rdtsc_window": 32}


def validator_TimingCheckDetector_with_params(sleep_threshold_ms: int,
                                               rdtsc_window: int) -> Dict:
    """TimingCheckDetector::with_params(sleep_threshold_ms, rdtsc_window) -> Self"""
    return {"sleep_threshold_ms": sleep_threshold_ms, "rdtsc_window": rdtsc_window}


def validator_TimingCheckDetector_scan(detector: Dict, data: bytes) -> List[Dict]:
    """TimingCheckDetector::scan(&self, data: &[u8]) -> Vec<TimingCheck>"""
    checks: List[Dict] = []
    checks.extend(validator_TimingCheckDetector_scan_rdtsc(detector, data))
    checks.extend(validator_TimingCheckDetector_scan_gettickcount(detector, data))
    checks.extend(validator_TimingCheckDetector_scan_sleep(detector, data))
    checks.extend(validator_TimingCheckDetector_scan_qpc(detector, data))
    return checks


def validator_TimingCheckDetector_scan_rdtsc(detector: Dict, data: bytes) -> List[Dict]:
    """TimingCheckDetector::scan_rdtsc(&self, data) -> Vec<TimingCheck>"""
    checks: List[Dict] = []
    for off in _scan_pattern(data, _RDTSC):
        ctx = data[max(0, off - 4):off + 6]
        checks.append(validator_TimingCheck_new(off, "RDTSC", ctx))
    return checks


def validator_TimingCheckDetector_scan_gettickcount(detector: Dict,
                                                     data: bytes) -> List[Dict]:
    """TimingCheckDetector::scan_gettickcount(&self, data) -> Vec<TimingCheck>"""
    checks: List[Dict] = []
    for pat in [b'GetTickCount', b'GetTickCount64']:
        for off in _scan_pattern(data, pat):
            checks.append(validator_TimingCheck_new(off, "GetTickCount", pat))
    return checks


def validator_TimingCheckDetector_scan_sleep(detector: Dict, data: bytes) -> List[Dict]:
    """TimingCheckDetector::scan_sleep(&self, data) -> Vec<TimingCheck>"""
    checks: List[Dict] = []
    threshold = detector.get("sleep_threshold_ms", 200)
    for off, ms in validator_SleepBypassGenerator_scan_large_sleeps({}, data, threshold):
        ctx = data[max(0, off - 2):off + 7]
        c = validator_TimingCheck_new(off, "Sleep", ctx)
        c["sleep_ms"] = ms
        checks.append(c)
    return checks


def validator_TimingCheckDetector_scan_qpc(detector: Dict, data: bytes) -> List[Dict]:
    """TimingCheckDetector::scan_qpc(&self, data) -> Vec<TimingCheck>"""
    checks: List[Dict] = []
    for off in _scan_pattern(data, b'QueryPerformanceCounter'):
        checks.append(validator_TimingCheck_new(off, "QPC", b'QueryPerformanceCounter'))
    return checks


def validator_TimingCheckDetector_scan_string_imports(detector: Dict,
                                                       data: bytes) -> List[Dict]:
    """TimingCheckDetector::scan_string_imports(&self, data) -> Vec<TimingCheck>"""
    checks: List[Dict] = []
    for api in [b'GetTickCount', b'QueryPerformanceCounter', b'timeGetTime']:
        for off in _scan_pattern(data, api):
            checks.append(validator_TimingCheck_new(off, "StringImport", api))
    return checks


def validator_TimingCheckDetector_rdtsc_checks(detector: Dict, data: bytes) -> List[Dict]:
    """TimingCheckDetector::rdtsc_checks(&self, data) -> Vec<RdtscCheck>"""
    checks: List[Dict] = []
    window = detector.get("rdtsc_window", 32)
    for off in _scan_pattern(data, _RDTSC):
        ctx = data[max(0, off - window):off + window + 2]
        # detect second RDTSC in window (delta pattern)
        second = _scan_pattern(ctx, _RDTSC)
        has_delta = len(second) >= 2
        checks.append({"offset": off, "kind": "RDTSC", "context": list(ctx),
                        "has_delta_check": has_delta})
    return checks


def validator_TimingCheckDetector_sleep_checks(detector: Dict, data: bytes) -> List[Dict]:
    """TimingCheckDetector::sleep_checks(&self, data) -> Vec<SleepCheck>"""
    threshold = detector.get("sleep_threshold_ms", 200)
    return [{"offset": off, "sleep_ms": ms}
            for off, ms in validator_SleepBypassGenerator_scan_large_sleeps({}, data, threshold)]


def validator_TimingCheckDetector_report(detector: Dict, data: bytes) -> Dict:
    """TimingCheckDetector::report(&self, data: &[u8]) -> TimingReport"""
    checks = validator_TimingCheckDetector_scan(detector, data)
    by_kind: Dict[str, int] = defaultdict(int)
    for c in checks:
        by_kind[c["kind"]] += 1
    return {"checks": checks, "by_kind": dict(by_kind)}


def validator_TimingReport_total(report: Dict) -> int:
    """TimingReport::total(&self) -> usize"""
    return len(report.get("checks", []))


def validator_TimingReport_is_clean(report: Dict) -> bool:
    """TimingReport::is_clean(&self) -> bool"""
    return validator_TimingReport_total(report) == 0


def validator_TimingReport_count_for(report: Dict, pattern: str) -> int:
    """TimingReport::count_for(&self, pattern) -> usize"""
    return report.get("by_kind", {}).get(pattern, 0)


def validator_TimingReport_high_confidence(report: Dict, threshold: int = 75) -> List[Dict]:
    """TimingReport::high_confidence(&self) -> Vec<&TimingCheck>"""
    return [c for c in report.get("checks", []) if c.get("confidence", 75) >= threshold]


def validator_TimingReport_all_patches(report: Dict) -> List[Tuple[int, bytes]]:
    """TimingReport::all_patches(&self) -> Vec<(usize, Vec<u8>)>"""
    result: List[Tuple[int, bytes]] = []
    for c in report.get("checks", []):
        off = c["offset"]
        count = validator_TimingCheck_patch_byte_count(c)
        result.append((off, _nop_sled(count)))
    return result


def validator_TimingReport_apply_patches(report: Dict, data: bytes) -> bytes:
    """TimingReport::apply_patches(&self, data: &[u8]) -> Vec<u8>"""
    buf = bytearray(data)
    for off, pb in validator_TimingReport_all_patches(report):
        if off + len(pb) <= len(buf):
            buf[off:off + len(pb)] = pb
    return bytes(buf)


# ---------------------------------------------------------------------------
# src/timing_patchers.rs
# ---------------------------------------------------------------------------

def validator_TimingSignatureDb_default_db() -> Dict:
    """TimingSignatureDb::default_db() -> Self"""
    return {
        "signatures": [
            {"name": "RDTSC", "bytes": list(_RDTSC), "patch_template": list(_nop_sled(2))},
            {"name": "GetTickCount", "bytes": list(b'GetTickCount'),
             "patch_template": list(b'\x00' * 12)},
            {"name": "QPC", "bytes": list(b'QueryPerformanceCounter'),
             "patch_template": list(b'\x00' * 23)},
            {"name": "Sleep", "bytes": [0x68], "patch_template": [0x6a, 0x00]},
        ]
    }


def validator_TimingSignatureDb_scan(db: Dict, data: bytes) -> List[Tuple[int, Dict]]:
    """TimingSignatureDb::scan<'a>(&'a self, data: &[u8]) -> Vec<(usize, &'a TimingSignature)>"""
    results: List[Tuple[int, Dict]] = []
    for sig in db["signatures"]:
        for off in _scan_pattern(data, bytes(sig["bytes"])):
            results.append((off, sig))
    return results


def validator_TimingSignatureDb_apply_patch_template(db: Dict, data: bytes,
                                                      sig: Dict, offset: int) -> bytes:
    """TimingSignatureDb::apply_patch_template(…)"""
    buf = bytearray(data)
    pt = bytes(sig["patch_template"])
    pat_len = len(sig["bytes"])
    write_len = min(len(pt), pat_len, len(buf) - offset)
    if write_len > 0:
        buf[offset:offset + write_len] = pt[:write_len]
    return bytes(buf)


def validator_TimingPatcher_new(config: Dict) -> Dict:
    """TimingPatcher::new(config: TimingPatchConfig) -> Self"""
    return {"config": config, "db": validator_TimingSignatureDb_default_db()}


def validator_TimingPatcher_with_defaults() -> Dict:
    """TimingPatcher::with_defaults() -> Self"""
    return validator_TimingPatcher_new({"patch_rdtsc": True, "patch_sleep": True,
                                        "patch_gettickcount": True})


def validator_TimingPatcher_patch(patcher: Dict, data: bytearray) -> Dict:
    """TimingPatcher::patch(&self, data: &mut Vec<u8>) -> TimingPatchResult"""
    count = 0
    patched_techniques: List[str] = []
    for off, sig in validator_TimingSignatureDb_scan(patcher["db"], bytes(data)):
        pt = bytes(sig["patch_template"])
        write_len = min(len(pt), len(data) - off)
        if write_len > 0:
            data[off:off + write_len] = pt[:write_len]
            count += 1
            patched_techniques.append(sig["name"])
    return {"patches_applied": count, "techniques": patched_techniques}


def validator_TimingPatcher_frida_script(patcher: Dict) -> str:
    """TimingPatcher::frida_script(&self) -> String"""
    lines = ["'use strict';", "// Timing patcher Frida script"]
    config = patcher.get("config", {})
    if config.get("patch_gettickcount", True):
        lines.append("var gtc = Module.findExportByName('kernel32.dll', 'GetTickCount');")
        lines.append("if (gtc) Interceptor.replace(gtc, new NativeCallback(function() { return 1; }, 'uint32', []));")
    if config.get("patch_sleep", True):
        lines.append("var sleep = Module.findExportByName('kernel32.dll', 'Sleep');")
        lines.append("if (sleep) Interceptor.replace(sleep, new NativeCallback(function(ms) {}, 'void', ['uint32']));")
    return "\n".join(lines)


def validator_detect_rdtsc_delta_checks(data: bytes) -> List[Dict]:
    """detect_rdtsc_delta_checks(data: &[u8]) -> Vec<RdtscDeltaCheck>"""
    results: List[Dict] = []
    offsets = _scan_pattern(data, _RDTSC)
    # Pair consecutive RDTSC occurrences within 64 bytes
    for i in range(len(offsets) - 1):
        gap = offsets[i + 1] - offsets[i]
        if gap < 64:
            results.append({
                "first_rdtsc": offsets[i],
                "second_rdtsc": offsets[i + 1],
                "gap_bytes": gap,
                "likely_delta_check": True,
            })
    return results


# ---------------------------------------------------------------------------
# src/vm_check_neutralizer.rs
# ---------------------------------------------------------------------------

def validator_CpuidCheck_is_hypervisor_leaf(check: Dict) -> bool:
    """CpuidCheck::is_hypervisor_leaf(&self) -> bool"""
    return check.get("leaf", 0) == 0x40000000


def validator_CpuidCheck_is_vmware_backdoor(check: Dict) -> bool:
    """CpuidCheck::is_vmware_backdoor(&self) -> bool"""
    return check.get("kind", "") == "vmware_backdoor"


def validator_NeutralizationPatch_apply(patch: Dict, data: bytearray) -> bool:
    """NeutralizationPatch::apply(&self, data: &mut [u8]) -> bool"""
    off = patch["offset"]
    rb = bytes(patch["replacement_bytes"])
    if off + len(rb) > len(data):
        return False
    data[off:off + len(rb)] = rb
    return True


def validator_NeutralizationPatch_rollback(patch: Dict, data: bytearray) -> bool:
    """NeutralizationPatch::rollback(&self, data: &mut [u8]) -> bool"""
    off = patch["offset"]
    ob = bytes(patch["original_bytes"])
    if not ob or off + len(ob) > len(data):
        return False
    data[off:off + len(ob)] = ob
    return True


def validator_NeutralizationPatch_size(patch: Dict) -> int:
    """NeutralizationPatch::size(&self) -> usize"""
    return len(patch["replacement_bytes"])


def validator_VmNeutralizer_new() -> Dict:
    """VmNeutralizer::new() -> Self"""
    return {"min_confidence": 50}


def validator_VmNeutralizer_with_min_confidence(neutralizer: Dict, threshold: int) -> Dict:
    """VmNeutralizer::with_min_confidence(mut self, threshold: u8) -> Self"""
    n = dict(neutralizer)
    n["min_confidence"] = max(0, min(100, threshold))
    return n


def validator_VmNeutralizer_scan_cpuid(neutralizer: Dict, data: bytes) -> List[Dict]:
    """VmNeutralizer::scan_cpuid(&self, data: &[u8]) -> Vec<CpuidCheck>"""
    checks: List[Dict] = []
    for off in _scan_pattern(data, _CPUID):
        # Check if preceded by MOV EAX, 0x40000000 (hypervisor leaf)
        ctx_start = max(0, off - 5)
        ctx = data[ctx_start:off]
        leaf = 0
        if len(ctx) >= 5 and ctx[-5] == 0xb8:
            leaf = struct.unpack_from('<I', ctx, -4)[0]
        checks.append({"offset": off, "kind": "cpuid", "leaf": leaf,
                        "confidence": 80 if leaf == 0x40000000 else 50})
    return checks


def validator_VmNeutralizer_scan_vmware_io_port(neutralizer: Dict,
                                                  data: bytes) -> List[Dict]:
    """VmNeutralizer::scan_vmware_io_port(&self, data: &[u8]) -> Vec<IoPortCheck>"""
    checks: List[Dict] = []
    # VMware backdoor: IN EAX, DX (ED) preceded by MOV DX, 0x5658
    vmware_magic = bytes([0x66, 0xba, 0x58, 0x56])  # MOV DX, 0x5658
    for off in _scan_pattern(data, vmware_magic):
        checks.append({"offset": off, "port": 0x5658, "kind": "vmware_backdoor",
                        "confidence": 90})
    return checks


def validator_VmNeutralizer_scan_sidt_sgdt(neutralizer: Dict,
                                            data: bytes) -> List[Dict]:
    """VmNeutralizer::scan_sidt_sgdt(&self, data: &[u8]) -> Vec<NeutralizationPatch>"""
    patches: List[Dict] = []
    for pat, name in [(_SIDT, "SIDT"), (_SGDT, "SGDT")]:
        for off in _scan_pattern(data, pat):
            orig = list(data[off:off + len(pat)])
            rb = list(_nop_sled(len(pat)))
            patches.append({"offset": off, "technique": name,
                             "original_bytes": orig, "replacement_bytes": rb})
    return patches


def validator_VmNeutralizer_scan_memory_artefacts(neutralizer: Dict,
                                                   data: bytes) -> List[Dict]:
    """VmNeutralizer::scan_memory_artefacts(&self, data: &[u8]) -> Vec<MemoryArtifact>"""
    artifacts: List[Dict] = []
    for vm_str in _VM_STRINGS:
        for off in _scan_pattern(data, vm_str):
            artifacts.append({"offset": off, "kind": "vm_string",
                               "value": vm_str.decode(errors='replace'),
                               "confidence": 85})
    return artifacts


def validator_VmNeutralizer_scan(neutralizer: Dict, data: bytes) -> Dict:
    """VmNeutralizer::scan(&self, data: &[u8]) -> VmNeutralizationReport"""
    return {
        "cpuid_checks": validator_VmNeutralizer_scan_cpuid(neutralizer, data),
        "io_port_checks": validator_VmNeutralizer_scan_vmware_io_port(neutralizer, data),
        "sidt_patches": validator_VmNeutralizer_scan_sidt_sgdt(neutralizer, data),
        "memory_artifacts": validator_VmNeutralizer_scan_memory_artefacts(neutralizer, data),
    }


def validator_VmNeutralizer_neutralize_all(neutralizer: Dict,
                                            data: bytes) -> Tuple[bytes, int]:
    """VmNeutralizer::neutralize_all(&self, data: &[u8]) -> (Vec<u8>, usize)"""
    buf = bytearray(data)
    count = 0
    report = validator_VmNeutralizer_scan(neutralizer, data)
    for p in report["sidt_patches"]:
        if validator_NeutralizationPatch_apply(p, buf):
            count += 1
    for cpuid in report["cpuid_checks"]:
        off = cpuid["offset"]
        if off + 2 <= len(buf):
            buf[off:off + 2] = _nop_sled(2)
            count += 1
    return bytes(buf), count


def validator_VmNeutralizationReport_total_checks(report: Dict) -> int:
    """VmNeutralizationReport::total_checks(&self) -> usize"""
    return (len(report.get("cpuid_checks", [])) +
            len(report.get("io_port_checks", [])) +
            len(report.get("sidt_patches", [])) +
            len(report.get("memory_artifacts", [])))


def validator_VmNeutralizationReport_is_clean(report: Dict) -> bool:
    """VmNeutralizationReport::is_clean(&self) -> bool"""
    return validator_VmNeutralizationReport_total_checks(report) == 0


def validator_VmNeutralizationReport_product_summary(report: Dict) -> Dict[str, int]:
    """VmNeutralizationReport::product_summary(&self) -> HashMap<VmProduct, usize>"""
    counts: Dict[str, int] = defaultdict(int)
    for art in report.get("memory_artifacts", []):
        val = art.get("value", "")
        for prod in ["VMware", "VirtualBox", "QEMU", "Hyper-V"]:
            if prod.lower() in val.lower():
                counts[prod] += 1
    return dict(counts)


def validator_VmNeutralizationReport_high_confidence_cpuid(report: Dict,
                                                             threshold: int = 75) -> List[Dict]:
    """VmNeutralizationReport::high_confidence_cpuid(&self) -> Vec<&CpuidCheck>"""
    return [c for c in report.get("cpuid_checks", [])
            if c.get("confidence", 0) >= threshold]


def validator_VmNeutralizationReport_format_text(report: Dict) -> str:
    """VmNeutralizationReport::format_text(&self) -> String"""
    total = validator_VmNeutralizationReport_total_checks(report)
    lines = [f"VM Neutralization Report — {total} check(s)"]
    lines.append(f"  CPUID: {len(report.get('cpuid_checks', []))}")
    lines.append(f"  IO port: {len(report.get('io_port_checks', []))}")
    lines.append(f"  SIDT/SGDT: {len(report.get('sidt_patches', []))}")
    lines.append(f"  VM strings: {len(report.get('memory_artifacts', []))}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# src/vm_detection.rs
# ---------------------------------------------------------------------------

def validator_VmDetector_scan(detector: Dict, data: bytes) -> List[Dict]:
    """VmDetector::scan(&self, data: &[u8]) -> Vec<VmDetectionSite>"""
    sites: List[Dict] = []
    neutral = validator_VmNeutralizer_new()
    for cpuid in validator_VmNeutralizer_scan_cpuid(neutral, data):
        sites.append({**cpuid, "site_type": "cpuid"})
    for art in validator_VmNeutralizer_scan_memory_artefacts(neutral, data):
        sites.append({**art, "site_type": "string_artifact"})
    return sites


def validator_VmDetector_generate_patches(detector: Dict, data: bytes,
                                           sites: List[Dict]) -> List[Dict]:
    """VmDetector::generate_patches(&self, data, sites) -> Vec<BypassPatch>"""
    patches: List[Dict] = []
    for site in sites:
        off = site["offset"]
        patch_len = 2 if site.get("site_type") == "cpuid" else 6
        if off + patch_len > len(data):
            continue
        orig = list(data[off:off + patch_len])
        rb = list(_nop_sled(patch_len))
        patches.append({"offset": off, "original_bytes": orig, "replacement_bytes": rb})
    return patches


def validator_VmDetector_patch_registry_checks(detector: Dict, data: bytearray) -> int:
    """VmDetector::patch_registry_checks(&self, data: &mut [u8]) -> usize"""
    count = 0
    for vm_str in [b'HKLM\\SOFTWARE\\VMware', b'HKLM\\SOFTWARE\\Oracle\\VirtualBox']:
        for off in _scan_pattern(bytes(data), vm_str):
            # Zero-fill
            end = min(off + len(vm_str), len(data))
            data[off:end] = b'\x00' * (end - off)
            count += 1
    return count


def validator_VmDetector_patch_process_name_checks(detector: Dict,
                                                    data: bytearray) -> int:
    """VmDetector::patch_process_name_checks(&self, data: &mut [u8]) -> usize"""
    count = 0
    for proc in [b'vmtoolsd.exe', b'vboxservice.exe', b'vboxtray.exe']:
        for off in _scan_pattern(bytes(data), proc):
            end = min(off + len(proc), len(data))
            data[off:end] = b'x' * (end - off)  # Replace with harmless name
            count += 1
    return count


def validator_VmDetector_patch_cpuid_checks(detector: Dict, data: bytearray) -> int:
    """VmDetector::patch_cpuid_checks(&self, data: &mut [u8]) -> usize"""
    count = 0
    for off in _scan_pattern(bytes(data), _CPUID):
        if off + 2 <= len(data):
            data[off:off + 2] = _nop_sled(2)
            count += 1
    return count


# ---------------------------------------------------------------------------
# src/vm_detection_bypass.rs
# ---------------------------------------------------------------------------

def validator_VmBypassScanner_new() -> Dict:
    """VmBypassScanner::new() -> Self"""
    return {"patterns": [
        {"name": "cpuid", "bytes": list(_CPUID)},
        {"name": "sidt", "bytes": list(_SIDT)},
        {"name": "vmware_io", "bytes": [0x66, 0xba, 0x58, 0x56]},
    ]}


def validator_VmBypassScanner_scan(scanner: Dict, data: bytes) -> List[Dict]:
    """VmBypassScanner::scan(&self, data: &[u8]) -> Vec<DetectionHit>"""
    hits: List[Dict] = []
    for pat in scanner["patterns"]:
        for off in _scan_pattern(data, bytes(pat["bytes"])):
            hits.append({"offset": off, "pattern_name": pat["name"]})
    return hits


def validator_StringReplacementBypass_with_common_rules() -> Dict:
    """StringReplacementBypass::with_common_rules() -> Self"""
    return {
        "rules": [
            {"find": b'VMware', "replace": b'XXXXXX', "desc": "Hide VMware string"},
            {"find": b'VirtualBox', "replace": b'XXXXXXXXXX', "desc": "Hide VirtualBox"},
            {"find": b'VBOX', "replace": b'XXXX', "desc": "Hide VBOX"},
            {"find": b'QEMU', "replace": b'XXXX', "desc": "Hide QEMU"},
        ]
    }


def validator_StringReplacementBypass_add_string_rule(bypass: Dict, find: bytes,
                                                       replace: bytes, desc: str) -> None:
    """StringReplacementBypass::add_string_rule(&mut self, find, replace, desc)"""
    bypass["rules"].append({"find": find, "replace": replace, "desc": desc})


def validator_StringReplacementBypass_apply(bypass: Dict, data: bytearray) -> int:
    """StringReplacementBypass::apply(&self, data: &mut [u8]) -> usize"""
    count = 0
    for rule in bypass["rules"]:
        find = rule["find"]
        replace = rule["replace"]
        repl = replace[:len(find)].ljust(len(find), b'\x00')
        for off in _scan_pattern(bytes(data), find):
            data[off:off + len(find)] = repl
            count += 1
    return count


def validator_RdtscPatcher_patch_rdtsc(patcher: Dict, data: bytearray) -> int:
    """RdtscPatcher::patch_rdtsc(&mut self, data: &mut [u8]) -> usize"""
    count = 0
    for off in _scan_pattern(bytes(data), _RDTSC):
        data[off:off + 2] = b'\x31\xc0'  # XOR EAX,EAX
        count += 1
    return count


def validator_CpuidSpoofer_hide_hypervisor() -> Dict:
    """CpuidSpoofer::hide_hypervisor() -> Self"""
    return {"mode": "hide_hypervisor", "clear_hypervisor_bit": True}


def validator_CpuidSpoofer_execute(spoofer: Dict, leaf: int,
                                    sub_leaf: int) -> Optional[Dict]:
    """CpuidSpoofer::execute(&self, leaf: u32, sub_leaf: u32) -> Option<CpuidResult>"""
    if leaf == 1:
        # Clear hypervisor bit (bit 31 of ECX)
        ecx = 0x0 if spoofer.get("clear_hypervisor_bit") else 0x80000000
        return {"eax": 0x000906ea, "ebx": 0x00100800, "ecx": ecx, "edx": 0xbfebfbff}
    if leaf == 0x40000000:
        # Return empty / non-VM signature
        return {"eax": 0, "ebx": 0, "ecx": 0, "edx": 0}
    return None


def validator_CpuidSpoofer_patch_cpuid(spoofer: Dict, data: bytearray) -> int:
    """CpuidSpoofer::patch_cpuid(&self, data: &mut [u8]) -> usize"""
    count = 0
    for off in _scan_pattern(bytes(data), _CPUID):
        # Replace CPUID with XOR EAX,EAX + NOP
        if off + 2 <= len(data):
            data[off:off + 2] = b'\x31\xc0'
            count += 1
    return count


def validator_VmArtifactMasker_new() -> Dict:
    """VmArtifactMasker::new() -> Self"""
    return {"mask_strings": list(_VM_STRINGS), "replacements": {}}


def validator_VmArtifactMasker_apply(masker: Dict, data: bytearray) -> Dict:
    """VmArtifactMasker::apply(&mut self, data: &mut [u8]) -> MaskReport"""
    count = 0
    for vm_str in masker["mask_strings"]:
        for off in _scan_pattern(bytes(data), vm_str):
            mask = b'X' * len(vm_str)
            data[off:off + len(vm_str)] = mask
            count += 1
    return {"masked_count": count}


def validator_HypervisorFamilyMasker_new() -> Dict:
    """HypervisorFamilyMasker::new() -> Self"""
    return {
        "families": {
            "vmware": [b'VMware', b'vmtoolsd', b'vmhgfs'],
            "virtualbox": [b'VirtualBox', b'VBOX', b'vboxservice'],
            "hyper_v": [b'Hyper-V', b'HYPERV'],
            "qemu": [b'QEMU', b'qemu'],
        }
    }


def validator_HypervisorFamilyMasker_process(masker: Dict, data: bytearray) -> Dict:
    """HypervisorFamilyMasker::process(&mut self, data: &mut [u8]) -> MaskReport"""
    count = 0
    for family, strings in masker["families"].items():
        for s in strings:
            for off in _scan_pattern(bytes(data), s):
                data[off:off + len(s)] = b'X' * len(s)
                count += 1
    return {"masked_count": count}


def validator_HypervisorFamilyMasker_artifacts_for(masker: Dict,
                                                     family: str) -> List[bytes]:
    """HypervisorFamilyMasker::artifacts_for(&self, family) -> Vec<&VmArtifact>"""
    return masker["families"].get(family, [])


# ---------------------------------------------------------------------------
# src/vm_detection_neutralizer.rs
# ---------------------------------------------------------------------------

def validator_VmArtifact_new(offset: int, kind: str, data_bytes: bytes) -> Dict:
    """VmArtifact::new(…) -> Self"""
    return {"offset": offset, "kind": kind, "bytes": list(data_bytes)}


def validator_SpoofRule_new(offset: int, original: bytes, replacement: bytes) -> Dict:
    """SpoofRule::new(…) -> Self"""
    return {"offset": offset, "original_bytes": list(original),
            "replacement_bytes": list(replacement)}


def validator_SpoofRule_apply(rule: Dict, binary: bytearray) -> bool:
    """SpoofRule::apply(&self, binary: &mut Vec<u8>) -> Result<(), String>"""
    off = rule["offset"]
    rb = bytes(rule["replacement_bytes"])
    if off + len(rb) > len(binary):
        return False
    binary[off:off + len(rb)] = rb
    return True


def validator_SpoofRule_rollback(rule: Dict, binary: bytearray) -> bool:
    """SpoofRule::rollback(&self, binary: &mut Vec<u8>) -> Result<(), String>"""
    off = rule["offset"]
    ob = bytes(rule["original_bytes"])
    if not ob or off + len(ob) > len(binary):
        return False
    binary[off:off + len(ob)] = ob
    return True


def validator_VmArtifactNeutralizer_new() -> Dict:
    """VmArtifactNeutralizer::new() -> Self"""
    return {"vm_strings": list(_VM_STRINGS)}


def validator_VmArtifactNeutralizer_scan(neutralizer: Dict, binary: bytes) -> List[Dict]:
    """VmArtifactNeutralizer::scan(&self, binary: &[u8]) -> Vec<VmArtifact>"""
    artifacts: List[Dict] = []
    for vm_str in neutralizer["vm_strings"]:
        for off in _scan_pattern(binary, vm_str):
            artifacts.append(validator_VmArtifact_new(off, "vm_string", vm_str))
    return artifacts


def validator_VmArtifactNeutralizer_generate_spoof_rules(neutralizer: Dict,
                                                           binary: bytes) -> List[Dict]:
    """VmArtifactNeutralizer::generate_spoof_rules(&self, binary: &[u8]) -> Vec<SpoofRule>"""
    rules: List[Dict] = []
    for art in validator_VmArtifactNeutralizer_scan(neutralizer, binary):
        off = art["offset"]
        orig = bytes(art["bytes"])
        replacement = b'X' * len(orig)
        rules.append(validator_SpoofRule_new(off, orig, replacement))
    return rules


def validator_VmArtifactNeutralizer_neutralize(neutralizer: Dict,
                                                binary: bytearray) -> Tuple[int, List[str]]:
    """VmArtifactNeutralizer::neutralize(&self, binary: &mut Vec<u8>) -> (usize, Vec<String>)"""
    rules = validator_VmArtifactNeutralizer_generate_spoof_rules(neutralizer, bytes(binary))
    count = 0
    log: List[str] = []
    for rule in rules:
        if validator_SpoofRule_apply(rule, binary):
            count += 1
            log.append(f"Spoofed VM artifact @ 0x{rule['offset']:x}")
    return count, log


def validator_VmArtifactNeutralizer_frida_script(neutralizer: Dict,
                                                   artifacts: List[Dict]) -> str:
    """VmArtifactNeutralizer::frida_script(&self, artifacts: &[VmArtifact]) -> String"""
    lines = ["'use strict';", "// VM artifact neutralizer script"]
    for art in artifacts:
        val = bytes(art["bytes"]).decode(errors='replace')
        lines.append(f"// Mask '{val}' @ 0x{art['offset']:x}")
    lines.append("// Hook RegQueryValueExW to hide VM registry keys")
    return "\n".join(lines)


def validator_VmArtifactNeutralizer_environment_histogram(
        artifacts: List[Dict]) -> Dict[str, int]:
    """VmArtifactNeutralizer::environment_histogram(artifacts) -> HashMap<VmEnvironment, usize>"""
    hist: Dict[str, int] = defaultdict(int)
    vm_map = {
        'VMware': 'vmware', 'vmtools': 'vmware', 'vmhgfs': 'vmware',
        'VirtualBox': 'virtualbox', 'VBOX': 'virtualbox', 'vbox': 'virtualbox',
        'QEMU': 'qemu', 'Hyper-V': 'hyper_v', 'HYPERV': 'hyper_v',
    }
    for art in artifacts:
        val = bytes(art["bytes"]).decode(errors='replace')
        matched = False
        for key, env in vm_map.items():
            if key.lower() in val.lower():
                hist[env] += 1
                matched = True
                break
        if not matched:
            hist["unknown"] += 1
    return dict(hist)


def validator_VmArtifactNeutralizer_kind_histogram(artifacts: List[Dict]) -> Dict[str, int]:
    """VmArtifactNeutralizer::kind_histogram(artifacts) -> HashMap<VmArtifactKind, usize>"""
    hist: Dict[str, int] = defaultdict(int)
    for art in artifacts:
        hist[art.get("kind", "unknown")] += 1
    return dict(hist)


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_data = (
        b'\x00' * 16 +
        bytes(_ISDBGPRESENT) + b'\x00' * 5 +
        bytes(_RDTSC) + b'\x00' * 5 +
        bytes(_CPUID) + b'\x00' * 5 +
        b'\x90' * 20 +
        b'VMware\x00VirtualBox\x00' +
        b'\x00' * 8
    )

    scanner = validator_AntiAnalysisScanner_new()
    hits = validator_AntiAnalysisScanner_scan(scanner, test_data)
    print(f"AntiAnalysis hits: {len(hits)}")

    report = validator_CombinedReport_from_data(test_data)
    print(f"Debug detections: {len(report['debug_detections'])}")
    print(f"VM detections:    {len(report['vm_detections'])}")

    patcher = validator_AntiDebugPatcher_new()
    patched, n = validator_AntiDebugPatcher_patch_all(patcher, test_data)
    print(f"Patches applied:  {n}")

    neutral = validator_VmNeutralizer_new()
    vm_report = validator_VmNeutralizer_scan(neutral, test_data)
    print(f"VM checks total:  {validator_VmNeutralizationReport_total_checks(vm_report)}")

    detector = validator_TimingCheckDetector_new()
    treport = validator_TimingCheckDetector_report(detector, test_data)
    print(f"Timing checks:    {validator_TimingReport_total(treport)}")

    print("Self-test OK")
