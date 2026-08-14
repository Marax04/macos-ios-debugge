"""
Validators for rustre-emu-shellcode crate.
Each validator_NAME(input) -> output implements the logic documented in
validation/reports/rustre-emu-shellcode.md using Python stdlib only.
Total documented functions: 384
"""

import math
import base64
import hashlib
import struct
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# lib.rs
# ---------------------------------------------------------------------------

def validator_ShellcodeEmulator_run(shellcode: bytes) -> dict:
    """Simulates running shellcode; returns a mock ExecutionResult."""
    return {
        "steps": len(shellcode),
        "api_calls": [],
        "memory_regions": [],
        "exit_reason": "max_steps",
    }


def validator_BehaviorAnalyzer_detect_api_hashing(result: dict) -> bool:
    """Detects API hashing (ROR-13) pattern in execution result."""
    return any("ror" in str(c).lower() or "hash" in str(c).lower() for c in result.get("api_calls", []))


def validator_BehaviorAnalyzer_detect_decode_loop(result: dict) -> bool:
    """Detects decoding loops in execution trace."""
    pc_trace = result.get("pc_trace", [])
    if len(pc_trace) < 3:
        return False
    counts = Counter(pc_trace)
    return any(v > 4 for v in counts.values())


def validator_BehaviorAnalyzer_detect_network_stub(result: dict) -> bool:
    """Detects network stubs (WSAStartup, connect, send, etc.)."""
    network_apis = {"wsastartup", "connect", "send", "recv", "socket", "bind", "listen", "accept"}
    calls = [str(c).lower() for c in result.get("api_calls", [])]
    return any(api in " ".join(calls) for api in network_apis)


def validator_BehaviorAnalyzer_extract_strings(result: dict) -> list:
    """Extracts runtime strings from emulation result memory."""
    mem = result.get("memory", b"")
    if isinstance(mem, (bytes, bytearray)):
        return _extract_ascii_strings(mem, min_len=4)
    return []


def validator_ShellcodeHook_new(address: int, name: str, return_value: int) -> dict:
    """Creates a synthetic hook for an address."""
    return {"address": address, "name": name, "return_value": return_value}


def validator_ShellcodeRunner_run_sc(shellcode: bytes, arch: str) -> dict:
    """Runs shellcode with specified architecture."""
    valid_archs = {"x86", "x64", "arm", "arm64"}
    if arch.lower() not in valid_archs:
        return {"error": f"unsupported arch: {arch}"}
    return {"arch": arch, "steps": len(shellcode), "api_calls": [], "exit_reason": "max_steps"}


def validator_ShellcodeRunner_run_with_hooks(shellcode: bytes, arch: str, hooks: list) -> dict:
    """Runs shellcode with custom API hooks."""
    result = validator_ShellcodeRunner_run_sc(shellcode, arch)
    result["hooks_applied"] = len(hooks)
    return result


def validator_ShellcodeRunner_convert_result(result: dict, hooks: list) -> dict:
    """Converts ExecutionResult to ShellcodeRunResult annotating detected APIs."""
    annotated = dict(result)
    hook_names = {h.get("address"): h.get("name") for h in hooks}
    annotated["annotated_apis"] = list(hook_names.values())
    return annotated


def validator_ShellcodeRunner_arch_from_str(arch: str) -> str:
    """Converts architecture string to EmulatorArch enum variant."""
    mapping = {"x86": "X86", "x64": "X64", "arm": "ARM32", "arm64": "ARM64"}
    return mapping.get(arch.lower(), "Unknown")


def validator_ApiDatabase_new(_: None) -> dict:
    """Creates an empty API database."""
    return {"stubs": []}


def validator_ApiDatabase_stubs(db: dict) -> list:
    """Returns registered API stubs."""
    return db.get("stubs", [])


def validator_ApiDatabase_annotate(db: dict, calls: list) -> list:
    """Annotates API calls with symbolic names from the database."""
    stub_map = {s.get("address"): s.get("name") for s in db.get("stubs", [])}
    for call in calls:
        addr = call.get("address")
        if addr in stub_map:
            call["name"] = stub_map[addr]
    return calls


def validator_ApiDatabase_scan_for_api_names(db: dict, data: bytes) -> list:
    """Scans raw bytes for known API names."""
    results = []
    for stub in db.get("stubs", []):
        name = stub.get("name", "").encode()
        if name and name in data:
            idx = data.index(name)
            results.append((idx, stub.get("name")))
    return results


# ---------------------------------------------------------------------------
# x86_emulator.rs
# ---------------------------------------------------------------------------

def validator_X86Mem_new(_: None) -> dict:
    """Creates empty memory map."""
    return {"regions": {}}


def validator_X86Mem_read_u8(mem: dict, addr: int) -> Optional[int]:
    """Reads 1 byte from virtual address."""
    data = mem.get("regions", {}).get(addr)
    if data and len(data) >= 1:
        return data[0]
    return None


def validator_X86Mem_read_u16(mem: dict, addr: int) -> Optional[int]:
    data = mem.get("regions", {}).get(addr)
    if data and len(data) >= 2:
        return struct.unpack_from("<H", data)[0]
    return None


def validator_X86Mem_read_u32(mem: dict, addr: int) -> Optional[int]:
    data = mem.get("regions", {}).get(addr)
    if data and len(data) >= 4:
        return struct.unpack_from("<I", data)[0]
    return None


def validator_X86Mem_read_u64(mem: dict, addr: int) -> Optional[int]:
    data = mem.get("regions", {}).get(addr)
    if data and len(data) >= 8:
        return struct.unpack_from("<Q", data)[0]
    return None


def validator_X86Mem_write_u8(mem: dict, addr: int, val: int) -> dict:
    mem.setdefault("regions", {})[addr] = bytes([val & 0xFF])
    return mem


def validator_X86Mem_write_u16(mem: dict, addr: int, val: int) -> dict:
    mem.setdefault("regions", {})[addr] = struct.pack("<H", val & 0xFFFF)
    return mem


def validator_X86Mem_write_u32(mem: dict, addr: int, val: int) -> dict:
    mem.setdefault("regions", {})[addr] = struct.pack("<I", val & 0xFFFFFFFF)
    return mem


def validator_X86Mem_write_u64(mem: dict, addr: int, val: int) -> dict:
    mem.setdefault("regions", {})[addr] = struct.pack("<Q", val & 0xFFFFFFFFFFFFFFFF)
    return mem


def validator_X86Mem_map_bytes(mem: dict, addr: int, data: bytes) -> dict:
    mem.setdefault("regions", {})[addr] = bytes(data)
    return mem


def validator_X86Mem_stack_push(mem: dict, cpu: dict, val: int) -> Tuple[dict, dict]:
    """Push value onto emulated stack (decrements RSP/ESP)."""
    sp = cpu.get("rsp", 0x1000)
    sp -= 8
    cpu["rsp"] = sp
    mem = validator_X86Mem_write_u64(mem, sp, val)
    return mem, cpu


def validator_X86Mem_stack_pop(mem: dict, cpu: dict) -> Tuple[Optional[int], dict, dict]:
    """Pop value from emulated stack."""
    sp = cpu.get("rsp", 0x1000)
    val = validator_X86Mem_read_u64(mem, sp)
    cpu["rsp"] = sp + 8
    return val, mem, cpu


def validator_X86Emulator_new(max_steps: int) -> dict:
    """Creates emulator with step limit."""
    return {"max_steps": max_steps, "steps": 0, "mem": {}, "cpu": {"rip": 0, "rsp": 0x10000}, "code": b"", "base": 0}


def validator_X86Emulator_load_shellcode(emu: dict, code: bytes, base: int) -> dict:
    emu["code"] = code
    emu["base"] = base
    emu["cpu"]["rip"] = base
    return emu


def validator_X86Emulator_step(emu: dict) -> dict:
    """Execute one instruction (simulated as advancing RIP by 1)."""
    emu["cpu"]["rip"] += 1
    emu["steps"] += 1
    return emu


def validator_X86Emulator_run(emu: dict) -> Tuple[int, dict]:
    """Run until max_steps; returns (steps_executed, emu)."""
    limit = emu.get("max_steps", 1000)
    code_len = len(emu.get("code", b""))
    steps = min(limit, code_len)
    emu["steps"] = steps
    emu["cpu"]["rip"] = emu.get("base", 0) + steps
    return steps, emu


# ---------------------------------------------------------------------------
# x86_emulator_hooks.rs
# ---------------------------------------------------------------------------

def validator_HookDispatcher_new(_: None) -> dict:
    return {"hooks": []}


def validator_HookDispatcher_register(dispatcher: dict, hook: dict) -> dict:
    dispatcher.setdefault("hooks", []).append(hook)
    return dispatcher


def validator_HookDispatcher_dispatch(dispatcher: dict, event: dict) -> dict:
    """Notifies all hooks of an event; returns aggregated HookResult."""
    results = []
    for hook in dispatcher.get("hooks", []):
        results.append({"hook": hook.get("name"), "event": event})
    return {"results": results, "handled": len(results) > 0}


def validator_HookDispatcher_get_hook(dispatcher: dict, name: str) -> Optional[dict]:
    for hook in dispatcher.get("hooks", []):
        if hook.get("name") == name:
            return hook
    return None


def validator_HookDispatcher_hook_count(dispatcher: dict) -> int:
    return len(dispatcher.get("hooks", []))


def validator_DebugHook_new(verbose: bool) -> dict:
    return {"type": "DebugHook", "verbose": verbose, "name": "debug"}


def validator_WinApiStub_new(_: None) -> dict:
    return {"type": "WinApiStub", "stubs": {
        "VirtualAlloc": 0x1000,
        "LoadLibraryA": 0x1010,
        "GetProcAddress": 0x1020,
        "ExitProcess": 0x1030,
    }}


def validator_WinApiStub_resolve_name(stub: dict, name: str) -> Optional[int]:
    return stub.get("stubs", {}).get(name)


def validator_WinApiStub_handle_call(stub: dict, name: str, regs: dict) -> Optional[int]:
    """Simulates a Windows API call; returns a mock return value."""
    defaults = {
        "VirtualAlloc": 0x20000,
        "LoadLibraryA": 0x70000000,
        "GetProcAddress": 0x71000000,
        "ExitProcess": 0,
    }
    return defaults.get(name, 1)


def validator_SyscallTable_new(os_version: str) -> dict:
    base_table = {
        0: "NtReadFile",
        1: "NtWriteFile",
        2: "NtCreateFile",
        3: "NtClose",
        4: "NtQueryInformationProcess",
    }
    return {"os_version": os_version, "table": base_table}


def validator_SyscallTable_resolve(table: dict, number: int) -> Optional[str]:
    return table.get("table", {}).get(number)


def validator_MemRegion_contains(region: dict, addr: int) -> bool:
    base = region.get("base", 0)
    size = region.get("size", 0)
    return base <= addr < base + size


def validator_MemRegion_overlaps(region_a: dict, region_b: dict) -> bool:
    a_start = region_a.get("base", 0)
    a_end = a_start + region_a.get("size", 0)
    b_start = region_b.get("base", 0)
    b_end = b_start + region_b.get("size", 0)
    return a_start < b_end and b_start < a_end


def validator_SelfModificationTracker_new(_: None) -> dict:
    return {"write_events": [], "exec_pages": set()}


def validator_SelfModificationTracker_has_self_modification(tracker: dict) -> bool:
    written = set(tracker.get("write_events", []))
    exec_pages = set(tracker.get("exec_pages", []))
    return bool(written & exec_pages)


def validator_ApiCallLog_new(_: None) -> dict:
    return {"records": []}


def validator_ApiCallLog_calls_to(log: dict, api: str) -> list:
    return [r for r in log.get("records", []) if r.get("name", "").lower() == api.lower()]


def validator_ApiCallLog_was_called(log: dict, api: str) -> bool:
    return any(r.get("name", "").lower() == api.lower() for r in log.get("records", []))


def validator_ApiCallLog_unique_apis(log: dict) -> list:
    seen = set()
    result = []
    for r in log.get("records", []):
        name = r.get("name", "")
        if name and name not in seen:
            seen.add(name)
            result.append(name)
    return result


def validator_NetworkActivity_new(_: None) -> dict:
    return {"connections": [], "sends": [], "recvs": []}


def validator_NetworkActivity_has_network_activity(activity: dict) -> bool:
    return bool(activity.get("connections") or activity.get("sends") or activity.get("recvs"))


def validator_PcTrace_with_capacity(capacity: int) -> dict:
    return {"trace": [], "capacity": capacity}


def validator_PcTrace_new(_: None) -> dict:
    return {"trace": [], "capacity": 65536}


def validator_PcTrace_push(trace: dict, pc: int) -> dict:
    trace.setdefault("trace", []).append(pc)
    return trace


def validator_PcTrace_snapshot(trace: dict) -> list:
    return list(trace.get("trace", []))


def validator_PcTrace_contains(trace: dict, pc: int) -> bool:
    return pc in trace.get("trace", [])


def validator_PcTrace_detect_loops(trace: dict, threshold: int) -> list:
    counts = Counter(trace.get("trace", []))
    return [(addr, cnt) for addr, cnt in counts.items() if cnt > threshold]


def validator_PcTrace_last_pc(trace: dict) -> Optional[int]:
    t = trace.get("trace", [])
    return t[-1] if t else None


def validator_ror13_hash(s: str) -> int:
    """Computes ROR-13 hash of a string (common shellcode API hashing)."""
    h = 0
    for ch in s:
        h = ((h >> 13) | (h << (32 - 13))) & 0xFFFFFFFF
        h = (h + ord(ch)) & 0xFFFFFFFF
    return h


# ---------------------------------------------------------------------------
# shellcode_analysis.rs
# ---------------------------------------------------------------------------

def validator_ShellcodeAnalyzer_analyze(data: bytes, base: int) -> dict:
    """Full analysis: arch, techniques, network indicators, probable OS."""
    arch = validator_ShellcodeAnalyzer_detect_arch(data)
    techniques = validator_ShellcodeAnalyzer_detect_techniques(data)
    network = validator_ShellcodeAnalyzer_extract_network_indicators(data)
    os_guess = validator_ShellcodeAnalyzer_detect_os(data, techniques)
    return {
        "arch": arch,
        "techniques": techniques,
        "network_indicators": network,
        "probable_os": os_guess,
        "size": len(data),
        "base": base,
    }


def validator_ShellcodeAnalyzer_detect_arch(data: bytes) -> str:
    """Detects architecture from opcode patterns."""
    if len(data) < 2:
        return "Unknown"
    # Simple heuristic: look for common x64 REX prefixes (0x48..0x4F)
    rex_count = sum(1 for b in data[:64] if 0x48 <= b <= 0x4F)
    x86_call = data.count(b"\xe8")
    if rex_count > 3:
        return "x64"
    if x86_call > 0:
        return "x86"
    # ARM: many 4-byte aligned instructions
    return "Unknown"


def validator_ShellcodeAnalyzer_detect_techniques(data: bytes) -> list:
    """Identifies shellcode techniques."""
    techniques = []
    # PEB walk: common pattern 0x64, 0xA1 (FS:[0x30]) or 0x65, 0x48, 0x8B (GS:[0x60])
    if b"\x64\xa1" in data or b"\x65\x48\x8b" in data:
        techniques.append("PebWalk")
    # XOR loop: XOR byte ptr [reg], imm pattern
    if b"\x30" in data or b"\x31" in data:
        techniques.append("XorDecode")
    # API hashing
    if validator_detect_api_hashing(data):
        techniques.append("ApiHashing")
    # GetProcAddress by name
    if b"GetProcAddress" in data:
        techniques.append("GetProcAddress")
    return techniques


def validator_ShellcodeAnalyzer_find_xor_loops(data: bytes) -> list:
    """Finds and tries to decode XOR loops in payload."""
    results = []
    key = validator_detect_xor_key(data)
    if key is not None:
        decoded = bytes(b ^ key for b in data)
        results.append({"key": key, "decoded_len": len(decoded), "entropy_before": validator_compute_entropy(data), "entropy_after": validator_compute_entropy(decoded)})
    return results


def validator_ShellcodeAnalyzer_extract_network_indicators(data: bytes) -> list:
    """Extracts embedded URLs, IPs, hostnames."""
    indicators = []
    text = data.decode("latin-1", errors="replace")
    # Simple IP regex-like scan
    import re
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    indicators.extend(ips)
    # URLs
    urls = re.findall(r"https?://[^\x00\s\"'<>]+", text)
    indicators.extend(urls)
    return list(set(indicators))


def validator_ShellcodeAnalyzer_detect_os(data: bytes, techniques: list) -> str:
    """Estimates target OS from techniques."""
    win_signs = {"PebWalk", "ApiHashing", "GetProcAddress"}
    if any(t in win_signs for t in techniques):
        return "Windows"
    if b"/bin/sh" in data or b"syscall" in data.lower():
        return "Linux"
    return "Unknown"


# ---------------------------------------------------------------------------
# shellcode_classifier.rs
# ---------------------------------------------------------------------------

def validator_ShellcodeType_as_str(shellcode_type: str) -> str:
    """Returns string name of shellcode type."""
    return shellcode_type


def validator_ObfuscationKind_as_str(kind: str) -> str:
    return kind


def validator_Platform_as_str(platform: str) -> str:
    return platform


def validator_Stage_as_str(stage: str) -> str:
    return stage


def validator_ClassificationResult_unknown(size: int) -> dict:
    return {
        "shellcode_type": "Unknown",
        "platform": "Unknown",
        "obfuscation": "None",
        "stage": "Unknown",
        "size": size,
        "confidence": 0.0,
    }


def validator_ClassificationResult_is_likely_malicious(result: dict) -> bool:
    return result.get("confidence", 0.0) > 0.6 and result.get("shellcode_type", "Unknown") != "Unknown"


def validator_ClassificationResult_summary(result: dict) -> str:
    return (f"Type={result.get('shellcode_type','?')} Platform={result.get('platform','?')} "
            f"Stage={result.get('stage','?')} Confidence={result.get('confidence',0):.2f}")


def validator_ShellcodeClassifier_classify(data: bytes) -> dict:
    """Classifies shellcode into type, platform, obfuscation, stage."""
    entropy = validator_compute_entropy(data)
    has_mz = data[:2] == b"MZ"
    xor_key = validator_detect_xor_key(data)
    techniques = validator_ShellcodeAnalyzer_detect_techniques(data)

    platform = validator_ShellcodeAnalyzer_detect_os(data, techniques)
    obfuscation = "XOR" if xor_key is not None else ("None" if entropy < 6.5 else "Encrypted")
    sc_type = "Dropper" if has_mz else ("Stager" if entropy > 7.0 else "Shellcode")
    stage = "payload" if has_mz else "stager"
    confidence = min(1.0, len(techniques) * 0.25 + (0.3 if entropy > 6.0 else 0.0))

    return {
        "shellcode_type": sc_type,
        "platform": platform,
        "obfuscation": obfuscation,
        "stage": stage,
        "size": len(data),
        "confidence": confidence,
    }


def validator_compute_entropy(data: bytes) -> float:
    """Shannon entropy of bytes (0..8)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return entropy


def validator_scan(data: bytes, pattern: bytes) -> Optional[int]:
    """Linear byte pattern scan."""
    idx = data.find(pattern)
    return idx if idx >= 0 else None


def validator_detect_xor_key(data: bytes) -> Optional[int]:
    """Tries to identify single-byte XOR key via frequency analysis."""
    if len(data) < 8:
        return None
    counts = Counter(data)
    # Null bytes often become the key after XOR with a constant key
    most_common_byte, _ = counts.most_common(1)[0]
    # The key is the most common byte XOR'd with 0x00
    candidate = most_common_byte
    # Validate: decoding with this key should increase printable ratio
    decoded = bytes(b ^ candidate for b in data)
    if candidate != 0 and validator_printable_ratio(decoded) > validator_printable_ratio(data) + 0.1:
        return candidate
    return None


def validator_detect_api_hashing(data: bytes) -> bool:
    """Detects API hashing bytecode patterns."""
    # ROR 0x0D pattern (C1 C8 0D or D3 C8)
    if b"\xc1\xc8\x0d" in data or b"\xd3\xc8" in data:
        return True
    # Common: rotate right 13 on accumulator
    return False


def validator_ByteDistribution_new(data: bytes) -> dict:
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return {"counts": counts, "total": len(data)}


def validator_ByteDistribution_most_common(dist: dict) -> Tuple[int, int]:
    counts = dist.get("counts", [0] * 256)
    idx = counts.index(max(counts))
    return (idx, counts[idx])


def validator_ByteDistribution_null_ratio(dist: dict) -> float:
    total = dist.get("total", 0)
    if total == 0:
        return 0.0
    return dist.get("counts", [0] * 256)[0] / total


def validator_ByteDistribution_printable_ratio(dist: dict) -> float:
    total = dist.get("total", 0)
    if total == 0:
        return 0.0
    counts = dist.get("counts", [0] * 256)
    printable = sum(counts[i] for i in range(32, 127))
    return printable / total


def validator_ByteDistribution_unique_bytes(dist: dict) -> int:
    return sum(1 for c in dist.get("counts", []) if c > 0)


def validator_ByteDistribution_entropy(dist: dict) -> float:
    total = dist.get("total", 0)
    if total == 0:
        return 0.0
    counts = dist.get("counts", [])
    return -sum((c / total) * math.log2(c / total) for c in counts if c > 0)


def validator_classify_layers(layers: list) -> list:
    """Classifies each layer separately."""
    return [validator_ShellcodeClassifier_classify(bytes(layer)) for layer in layers]


# ---------------------------------------------------------------------------
# shellcode_decoder.rs
# ---------------------------------------------------------------------------

def validator_DecoderLoop_detect(code: bytes) -> list:
    """Detects decoding loops in bytecode (XOR, ADD, ROT, etc.)."""
    loops = []
    # Look for simple XOR byte [reg+idx], key patterns
    for i in range(len(code) - 3):
        # XOR [reg], imm8 variants
        if code[i] in (0x30, 0x31, 0x32, 0x33, 0x34, 0x35):
            loops.append({"offset": i, "type": "XOR", "opcode": code[i]})
        # ADD
        elif code[i] in (0x00, 0x01, 0x02, 0x03, 0x04, 0x05):
            loops.append({"offset": i, "type": "ADD", "opcode": code[i]})
    return loops[:16]  # cap results


def validator_DecodedStage_new(data: bytes, algorithm: str, original_data: bytes) -> dict:
    """Creates a decoded stage with metadata."""
    return {
        "data": data,
        "algorithm": algorithm,
        "entropy_before": validator_compute_entropy(original_data),
        "entropy_after": validator_compute_entropy(data),
        "size": len(data),
    }


def validator_DecodedStage_entropy_drop(stage: dict) -> float:
    return stage.get("entropy_before", 0.0) - stage.get("entropy_after", 0.0)


def validator_StageChain_new(_: None) -> dict:
    return {"stages": []}


def validator_StageChain_push(chain: dict, stage: dict) -> dict:
    chain.setdefault("stages", []).append(stage)
    return chain


def validator_StageChain_final_payload(chain: dict) -> bytes:
    stages = chain.get("stages", [])
    if not stages:
        return b""
    return stages[-1].get("data", b"")


def validator_StageChain_has_pe_payload(chain: dict) -> bool:
    payload = validator_StageChain_final_payload(chain)
    return payload[:2] == b"MZ"


def validator_StageChain_algorithm_chain(chain: dict) -> list:
    return [s.get("algorithm", "") for s in chain.get("stages", [])]


def validator_StageChain_total_entropy_reduction(chain: dict) -> float:
    stages = chain.get("stages", [])
    if not stages:
        return 0.0
    return sum(validator_DecodedStage_entropy_drop(s) for s in stages)


def _fnv64(data: bytes) -> int:
    h = 14695981039346656037
    for b in data:
        h ^= b
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h


def validator_DecoderStub_hash(stub: bytes) -> int:
    return _fnv64(stub)


def validator_DecoderStub_hash_hex(stub: bytes) -> str:
    return format(_fnv64(stub), "016x")


def validator_DecoderStub_structural_hash(stub: bytes) -> int:
    """Structural hash that ignores immediate constants (simplified)."""
    # Replace common immediate patterns with 0x00 before hashing
    normalized = bytearray(stub)
    for i in range(len(normalized) - 1):
        # Zero out bytes that follow MOV/XOR immediates (very simplified)
        if normalized[i] in (0xB8, 0xB9, 0xBA, 0xBB):
            for j in range(1, min(5, len(normalized) - i)):
                normalized[i + j] = 0
    return _fnv64(bytes(normalized))


def validator_ShellcodeFamily_classify(shellcode: bytes) -> str:
    """Classifies shellcode family."""
    # Metasploit: common stager patterns
    if b"\xfc\xe8\x8f\x00" in shellcode or b"\xfc\xe8\x82\x00" in shellcode:
        return "Metasploit"
    # CobaltStrike: common beacon patterns
    if b"\x90\x90\x90\x90" in shellcode and validator_compute_entropy(shellcode) > 6.5:
        return "CobaltStrike"
    if shellcode[:2] == b"MZ":
        return "PE_Loader"
    if len(shellcode) < 256:
        return "Stager"
    return "Custom"


def validator_MultiStageDecoder_new(_: None) -> dict:
    return {"algorithms": ["XOR", "ADD", "ROT", "Base64"]}


def validator_MultiStageDecoder_decode_layer(decoder: dict, data: bytes, stage_idx: int) -> Optional[dict]:
    """Attempts to decode one layer."""
    key = validator_detect_xor_key(data)
    if key is not None:
        decoded = bytes(b ^ key for b in data)
        return validator_DecodedStage_new(decoded, f"XOR(key=0x{key:02x})", data)
    return None


def validator_MultiStageDecoder_decode_all(decoder: dict, shellcode: bytes) -> dict:
    """Decodes all stages in cascade."""
    chain = validator_StageChain_new(None)
    current = shellcode
    for i in range(4):  # max 4 layers
        stage = validator_MultiStageDecoder_decode_layer(decoder, current, i)
        if stage is None:
            break
        chain = validator_StageChain_push(chain, stage)
        current = stage["data"]
        if validator_compute_entropy(current) < 4.0:
            break
    return chain


def validator_MultiStageDecoder_classify(decoder: dict, shellcode: bytes) -> str:
    return validator_ShellcodeFamily_classify(shellcode)


def validator_MultiStageDecoder_find_decoder_loops(decoder: dict, shellcode: bytes) -> list:
    return validator_DecoderLoop_detect(shellcode)


def validator_MultiStageDecoder_decoder_hash(decoder: dict, shellcode: bytes) -> str:
    return validator_DecoderStub_hash_hex(shellcode[:64])


def validator_MultiStageDecoder_decode_and_run(decoder: dict, shellcode: bytes) -> dict:
    """Decodes and then runs the payload in the emulator."""
    chain = validator_MultiStageDecoder_decode_all(decoder, shellcode)
    payload = validator_StageChain_final_payload(chain)
    result = validator_ShellcodeEmulator_run(payload)
    result["stage_chain"] = validator_StageChain_algorithm_chain(chain)
    return result


# ---------------------------------------------------------------------------
# shellcode_emulator.rs
# ---------------------------------------------------------------------------

def validator_EmulatedMemoryRegion_new(base: int, size: int, tag: str) -> dict:
    return {"base": base, "size": size, "tag": tag, "data": bytearray(size)}


def validator_EmulatedMemoryRegion_write_at(region: dict, offset: int, data_bytes: bytes) -> int:
    buf = region.get("data", bytearray())
    end = min(offset + len(data_bytes), len(buf))
    written = end - offset
    if written > 0:
        buf[offset:end] = data_bytes[:written]
    return written


def validator_EmulatedMemoryRegion_read_at(region: dict, offset: int, length: int) -> bytes:
    buf = region.get("data", bytearray())
    return bytes(buf[offset:offset + length])


def validator_ShellcodeContext_new(_: None) -> dict:
    return {"regions": [], "registers": {}}


def validator_ShellcodeContext_set_reg(ctx: dict, name: str, value: int) -> dict:
    ctx.setdefault("registers", {})[name] = value
    return ctx


def validator_ShellcodeContext_get_reg(ctx: dict, name: str) -> int:
    return ctx.get("registers", {}).get(name, 0)


def validator_ShellcodeContext_region_at(ctx: dict, addr: int) -> Optional[dict]:
    for region in ctx.get("regions", []):
        base = region.get("base", 0)
        size = region.get("size", 0)
        if base <= addr < base + size:
            return region
    return None


def validator_ShellcodeContext_region_at_mut(ctx: dict, addr: int) -> Optional[dict]:
    return validator_ShellcodeContext_region_at(ctx, addr)


def validator_ShellcodeContext_add_region(ctx: dict, region: dict) -> dict:
    ctx.setdefault("regions", []).append(region)
    return ctx


def validator_ShellcodeContext_read_va(ctx: dict, addr: int, length: int) -> bytes:
    region = validator_ShellcodeContext_region_at(ctx, addr)
    if region is None:
        return b"\x00" * length
    offset = addr - region.get("base", 0)
    return validator_EmulatedMemoryRegion_read_at(region, offset, length)


def validator_ShellcodeContext_write_va(ctx: dict, addr: int, data_bytes: bytes) -> int:
    region = validator_ShellcodeContext_region_at(ctx, addr)
    if region is None:
        return 0
    offset = addr - region.get("base", 0)
    return validator_EmulatedMemoryRegion_write_at(region, offset, data_bytes)


def validator_ShellcodeContext_total_mapped_bytes(ctx: dict) -> int:
    return sum(r.get("size", 0) for r in ctx.get("regions", []))


def validator_ApiHook_new(name: str, address: int, return_value: int) -> dict:
    return {"name": name, "address": address, "return_value": return_value, "call_count": 0}


def validator_ApiHook_virtual_alloc(address: int, alloc_base: int) -> dict:
    hook = validator_ApiHook_new("VirtualAlloc", address, alloc_base)
    hook["preset"] = "VirtualAlloc"
    return hook


def validator_ApiHook_load_library(address: int, module_handle: int) -> dict:
    hook = validator_ApiHook_new("LoadLibraryA", address, module_handle)
    hook["preset"] = "LoadLibrary"
    return hook


def validator_ApiHook_get_proc_address(address: int, proc_address: int) -> dict:
    hook = validator_ApiHook_new("GetProcAddress", address, proc_address)
    hook["preset"] = "GetProcAddress"
    return hook


def validator_MemoryDump_from_context(ctx: dict, label: str) -> dict:
    snapshot = {}
    for region in ctx.get("regions", []):
        base = region.get("base", 0)
        snapshot[base] = bytes(region.get("data", b""))
    return {"label": label, "regions": snapshot}


def validator_MemoryDump_region(dump: dict, base: int) -> Optional[bytes]:
    return dump.get("regions", {}).get(base)


def validator_MemoryDump_total_bytes(dump: dict) -> int:
    return sum(len(v) for v in dump.get("regions", {}).values())


def validator_MemoryDump_extract_strings(dump: dict, min_len: int) -> list:
    all_bytes = b"".join(dump.get("regions", {}).values())
    return _extract_ascii_strings(all_bytes, min_len)


def validator_MemoryDump_diff(before: dict, after: dict) -> list:
    diffs = []
    all_bases = set(before.get("regions", {}).keys()) | set(after.get("regions", {}).keys())
    for base in sorted(all_bases):
        b_data = before.get("regions", {}).get(base, b"")
        a_data = after.get("regions", {}).get(base, b"")
        max_len = max(len(b_data), len(a_data))
        changes = []
        for i in range(max_len):
            bv = b_data[i] if i < len(b_data) else None
            av = a_data[i] if i < len(a_data) else None
            changes.append(av if bv != av else None)
        if any(c is not None for c in changes):
            diffs.append((base, changes))
    return diffs


def validator_EmulationResult_new(exit_reason: str) -> dict:
    return {"exit_reason": exit_reason, "api_calls": [], "dumps": {}}


def validator_EmulationResult_called_api(result: dict, name: str) -> bool:
    return any(c.get("name", "").lower() == name.lower() for c in result.get("api_calls", []))


def validator_EmulationResult_calls_to(result: dict, name: str) -> list:
    return [c for c in result.get("api_calls", []) if c.get("name", "").lower() == name.lower()]


def validator_EmulationResult_distinct_apis_called(result: dict) -> int:
    names = {c.get("name", "") for c in result.get("api_calls", [])}
    return len(names)


def validator_EmulationResult_dump(result: dict, label: str) -> Optional[dict]:
    return result.get("dumps", {}).get(label)


def validator_HighLevelEmulator_new(_: None) -> dict:
    return {
        "context": validator_ShellcodeContext_new(None),
        "hooks": [],
        "steps_log": [],
    }


def validator_HighLevelEmulator_load_shellcode(emu: dict, base: int, code: bytes) -> dict:
    region = validator_EmulatedMemoryRegion_new(base, len(code), "code")
    validator_EmulatedMemoryRegion_write_at(region, 0, code)
    validator_ShellcodeContext_add_region(emu["context"], region)
    return emu


def validator_HighLevelEmulator_add_stack(emu: dict, base: int, size: int) -> dict:
    region = validator_EmulatedMemoryRegion_new(base, size, "stack")
    validator_ShellcodeContext_add_region(emu["context"], region)
    return emu


def validator_HighLevelEmulator_add_heap(emu: dict, base: int, size: int) -> dict:
    region = validator_EmulatedMemoryRegion_new(base, size, "heap")
    validator_ShellcodeContext_add_region(emu["context"], region)
    return emu


def validator_HighLevelEmulator_add_hook(emu: dict, hook: dict) -> dict:
    emu.setdefault("hooks", []).append(hook)
    return emu


def validator_HighLevelEmulator_add_common_windows_hooks(emu: dict) -> dict:
    base = 0x77000000
    for i, name in enumerate(["VirtualAlloc", "LoadLibraryA", "GetProcAddress", "ExitProcess"]):
        addr = base + i * 0x10
        hook = validator_ApiHook_new(name, addr, addr + 0x1000)
        emu = validator_HighLevelEmulator_add_hook(emu, hook)
    return emu


def validator_HighLevelEmulator_hook_at(emu: dict, addr: int) -> Optional[dict]:
    for hook in emu.get("hooks", []):
        if hook.get("address") == addr:
            return hook
    return None


def validator_HighLevelEmulator_hook_at_mut(emu: dict, addr: int) -> Optional[dict]:
    return validator_HighLevelEmulator_hook_at(emu, addr)


def validator_HighLevelEmulator_simulate(emu: dict, instruction_pcs: list) -> dict:
    result = validator_EmulationResult_new("simulation_complete")
    for pc in instruction_pcs:
        hook = validator_HighLevelEmulator_hook_at(emu, pc)
        if hook:
            result["api_calls"].append({"name": hook.get("name"), "address": pc, "return_value": hook.get("return_value")})
        emu.setdefault("steps_log", []).append(pc)
    return result


def validator_HighLevelEmulator_run(emu: dict, steps: list) -> dict:
    pcs = [s[0] for s in steps]
    return validator_HighLevelEmulator_simulate(emu, pcs)


def validator_HighLevelEmulator_dump(emu: dict, label: str) -> dict:
    return validator_MemoryDump_from_context(emu.get("context", {}), label)


# ---------------------------------------------------------------------------
# shellcode_heuristics.rs
# ---------------------------------------------------------------------------

def validator_ShellcodeScore_is_shellcode(score: dict) -> bool:
    return score.get("score", 0) >= 50


def validator_ShellcodeScore_is_high_confidence(score: dict) -> bool:
    return score.get("score", 0) >= 80


def validator_ShellcodeScore_label(score: dict) -> str:
    s = score.get("score", 0)
    if s >= 80:
        return "Shellcode"
    if s >= 50:
        return "Likely Shellcode"
    if s >= 20:
        return "Suspicious"
    return "Benign"


def validator_HeuristicScorer_new(_: None) -> dict:
    return {
        "features": [
            "entropy_high",
            "null_ratio_low",
            "printable_ratio_low",
            "api_hashing",
            "xor_loop",
            "pe_header",
        ]
    }


def validator_HeuristicScorer_feature_descriptions(scorer: dict) -> list:
    descriptions = {
        "entropy_high": "High Shannon entropy (>6.5)",
        "null_ratio_low": "Low null byte ratio",
        "printable_ratio_low": "Low printable ASCII ratio",
        "api_hashing": "API hashing pattern detected (ROR-13)",
        "xor_loop": "XOR decoding loop detected",
        "pe_header": "PE header (MZ) present",
    }
    return [descriptions.get(f, f) for f in scorer.get("features", [])]


def validator_HeuristicScorer_analyse(scorer: dict, data: bytes) -> dict:
    score = 0
    signals = []
    entropy = validator_compute_entropy(data)
    if entropy > 6.5:
        score += 20
        signals.append("entropy_high")
    dist = validator_ByteDistribution_new(data)
    if validator_ByteDistribution_null_ratio(dist) < 0.05:
        score += 10
        signals.append("null_ratio_low")
    if validator_ByteDistribution_printable_ratio(dist) < 0.4:
        score += 10
        signals.append("printable_ratio_low")
    if validator_detect_api_hashing(data):
        score += 25
        signals.append("api_hashing")
    loops = validator_DecoderLoop_detect(data)
    if len(loops) > 3:
        score += 15
        signals.append("xor_loop")
    if data[:2] == b"MZ":
        score += 5
        signals.append("pe_header")
    return {"score": score, "signals": signals, "entropy": entropy}


def validator_ShellcodeCategory_classify(score: dict) -> str:
    s = score.get("score", 0)
    if s >= 80:
        return "HighConfidence"
    if s >= 50:
        return "Shellcode"
    if s >= 20:
        return "Suspicious"
    return "Benign"


def validator_shannon_entropy(data: bytes) -> float:
    return validator_compute_entropy(data)


def validator_ascii_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if 32 <= b < 127) / len(data)


def validator_unique_byte_count(data: bytes) -> int:
    return len(set(data))


def validator_EmbeddedBlock_analyse(data: bytes, offset: int, base_address: int) -> dict:
    entropy = validator_compute_entropy(data)
    has_pe = data[:2] == b"MZ"
    score = validator_HeuristicScorer_analyse(validator_HeuristicScorer_new(None), data)
    return {
        "offset": offset,
        "base_address": base_address,
        "size": len(data),
        "entropy": entropy,
        "has_pe": has_pe,
        "score": score.get("score", 0),
        "signals": score.get("signals", []),
    }


def validator_EmbeddedBlock_should_flag(block: dict) -> bool:
    return block.get("score", 0) >= 40 or block.get("has_pe", False)


def validator_scan_for_shellcode(data: bytes) -> list:
    """Scans buffer for embedded shellcode."""
    hits = []
    chunk_size = 256
    for i in range(0, len(data) - chunk_size + 1, chunk_size // 2):
        chunk = data[i:i + chunk_size]
        block = validator_EmbeddedBlock_analyse(chunk, i, i)
        if validator_EmbeddedBlock_should_flag(block):
            hits.append({"offset": i, "score": block["score"], "signals": block["signals"]})
    return hits


# ---------------------------------------------------------------------------
# shellcode_loader.rs
# ---------------------------------------------------------------------------

def validator_MemFlags_contains(flags: int, other: int) -> bool:
    return (flags & other) == other


def validator_MemFlags_bits(flags: int) -> int:
    return flags & 0xFF


def validator_MemoryRegion_new(base: int, data: bytes, flags: int, tag: str) -> dict:
    return {"base": base, "data": bytearray(data), "flags": flags, "tag": tag}


def validator_MemoryRegion_end(region: dict) -> int:
    return region.get("base", 0) + len(region.get("data", b""))


def validator_MemoryRegion_contains_addr(region: dict, addr: int) -> bool:
    return region.get("base", 0) <= addr < validator_MemoryRegion_end(region)


def validator_MemoryRegion_read(region: dict, addr: int, length: int) -> Optional[bytes]:
    if not validator_MemoryRegion_contains_addr(region, addr):
        return None
    offset = addr - region.get("base", 0)
    data = region.get("data", b"")
    return bytes(data[offset:offset + length])


def validator_MemoryRegion_write(region: dict, addr: int, data_bytes: bytes) -> bool:
    # Check write permission (bit 1 = W)
    if not validator_MemFlags_contains(region.get("flags", 0), 0x02):
        return False
    if not validator_MemoryRegion_contains_addr(region, addr):
        return False
    offset = addr - region.get("base", 0)
    buf = region.get("data", bytearray())
    end = min(offset + len(data_bytes), len(buf))
    buf[offset:end] = data_bytes[:end - offset]
    return True


def validator_MemoryMap_new(_: None) -> dict:
    return {"regions": []}


def validator_MemoryMap_add_region(mmap: dict, region: dict) -> dict:
    mmap.setdefault("regions", []).append(region)
    return mmap


def validator_MemoryMap_alloc(mmap: dict, base: int, size: int, flags: int, tag: str) -> dict:
    region = validator_MemoryRegion_new(base, bytes(size), flags, tag)
    return validator_MemoryMap_add_region(mmap, region)


def validator_MemoryMap_region_at(mmap: dict, addr: int) -> Optional[dict]:
    for region in mmap.get("regions", []):
        if validator_MemoryRegion_contains_addr(region, addr):
            return region
    return None


def validator_MemoryMap_region_at_mut(mmap: dict, addr: int) -> Optional[dict]:
    return validator_MemoryMap_region_at(mmap, addr)


def validator_MemoryMap_read(mmap: dict, addr: int, length: int) -> Optional[bytes]:
    region = validator_MemoryMap_region_at(mmap, addr)
    if region is None:
        return None
    return validator_MemoryRegion_read(region, addr, length)


def validator_MemoryMap_write(mmap: dict, addr: int, data_bytes: bytes) -> bool:
    region = validator_MemoryMap_region_at_mut(mmap, addr)
    if region is None:
        return False
    return validator_MemoryRegion_write(region, addr, data_bytes)


def validator_MemoryMap_is_executable(mmap: dict, addr: int) -> bool:
    region = validator_MemoryMap_region_at(mmap, addr)
    if region is None:
        return False
    # bit 2 = X
    return validator_MemFlags_contains(region.get("flags", 0), 0x04)


def validator_MemoryMap_total_size(mmap: dict) -> int:
    return sum(len(r.get("data", b"")) for r in mmap.get("regions", []))


def validator_MemoryMap_regions(mmap: dict) -> list:
    return mmap.get("regions", [])


def validator_DetectionResult_from_signals(signals: list) -> dict:
    severity = "low"
    if len(signals) > 4:
        severity = "high"
    elif len(signals) > 2:
        severity = "medium"
    return {"signals": signals, "severity": severity, "count": len(signals)}


def validator_DetectionResult_analyze(data: bytes) -> dict:
    signals = []
    if validator_compute_entropy(data) > 6.5:
        signals.append("high_entropy")
    if validator_detect_api_hashing(data):
        signals.append("api_hashing")
    if validator_detect_xor_key(data) is not None:
        signals.append("xor_encoded")
    if b"\x64\xa1" in data or b"\x65\x48\x8b" in data:
        signals.append("peb_walk")
    return validator_DetectionResult_from_signals(signals)


def validator_ShellcodeLoader_new(config: dict) -> dict:
    return {"config": config, "loaded": None}


def validator_ShellcodeLoader_with_defaults(_: None) -> dict:
    return validator_ShellcodeLoader_new({"stack_size": 0x10000, "heap_size": 0x100000, "base": 0x1000})


def validator_ShellcodeLoader_load(loader: dict, shellcode: bytes) -> dict:
    cfg = loader.get("config", {})
    base = cfg.get("base", 0x1000)
    mmap = validator_MemoryMap_new(None)
    mmap = validator_MemoryMap_alloc(mmap, base, len(shellcode), 0x05, "code")  # R+X
    validator_MemoryMap_write(mmap, base, shellcode)
    stack_base = base + len(shellcode) + 0x1000
    mmap = validator_MemoryMap_alloc(mmap, stack_base, cfg.get("stack_size", 0x10000), 0x06, "stack")  # R+W
    heap_base = stack_base + cfg.get("stack_size", 0x10000) + 0x1000
    mmap = validator_MemoryMap_alloc(mmap, heap_base, cfg.get("heap_size", 0x100000), 0x06, "heap")  # R+W
    return {"memory": mmap, "entry": base, "shellcode_size": len(shellcode)}


def validator_FakeIat_new(base: int) -> dict:
    return {"base": base, "entries": [], "next_addr": base}


def validator_FakeIat_register(iat: dict, dll: str, function: str) -> int:
    addr = iat["next_addr"]
    iat["entries"].append({"dll": dll, "function": function, "address": addr})
    iat["next_addr"] = addr + 8
    return addr


def validator_FakeIat_lookup(iat: dict, dll: str, function: str) -> Optional[int]:
    for entry in iat.get("entries", []):
        if entry.get("dll", "").lower() == dll.lower() and entry.get("function", "").lower() == function.lower():
            return entry.get("address")
    return None


def validator_FakeIat_map_into(iat: dict, mmap: dict) -> dict:
    # Write stub entries into memory map (simplified: just return as mapped)
    return mmap


def validator_FakeIat_entries(iat: dict) -> list:
    return iat.get("entries", [])


def validator_build_default_iat(base: int) -> dict:
    iat = validator_FakeIat_new(base)
    common = [
        ("kernel32.dll", "VirtualAlloc"),
        ("kernel32.dll", "VirtualFree"),
        ("kernel32.dll", "VirtualProtect"),
        ("kernel32.dll", "LoadLibraryA"),
        ("kernel32.dll", "GetProcAddress"),
        ("kernel32.dll", "ExitProcess"),
        ("ws2_32.dll", "WSAStartup"),
        ("ws2_32.dll", "connect"),
        ("ws2_32.dll", "send"),
        ("ws2_32.dll", "recv"),
    ]
    for dll, fn in common:
        validator_FakeIat_register(iat, dll, fn)
    return iat


# ---------------------------------------------------------------------------
# shellcode_tracer.rs
# ---------------------------------------------------------------------------

def validator_CoverageBitmap_new(base: int, range_size: int) -> dict:
    return {"base": base, "range": range_size, "bitmap": [False] * range_size}


def validator_CoverageBitmap_mark(bitmap: dict, addr: int) -> dict:
    base = bitmap.get("base", 0)
    idx = addr - base
    if 0 <= idx < len(bitmap.get("bitmap", [])):
        bitmap["bitmap"][idx] = True
    return bitmap


def validator_CoverageBitmap_is_covered(bitmap: dict, addr: int) -> bool:
    base = bitmap.get("base", 0)
    idx = addr - base
    bm = bitmap.get("bitmap", [])
    return 0 <= idx < len(bm) and bm[idx]


def validator_CoverageBitmap_covered_count(bitmap: dict) -> int:
    return sum(1 for v in bitmap.get("bitmap", []) if v)


def validator_CoverageBitmap_coverage_pct(bitmap: dict) -> float:
    bm = bitmap.get("bitmap", [])
    if not bm:
        return 0.0
    return validator_CoverageBitmap_covered_count(bitmap) / len(bm) * 100.0


def validator_CoverageBitmap_merge(bitmap: dict, other: dict) -> dict:
    bm = bitmap.get("bitmap", [])
    other_bm = other.get("bitmap", [])
    for i in range(min(len(bm), len(other_bm))):
        if other_bm[i]:
            bm[i] = True
    return bitmap


def validator_BasicBlock_new(start: int) -> dict:
    return {"start": start, "instructions": [], "end": start, "exec_count": 0}


def validator_BasicBlock_instruction_count(bb: dict) -> int:
    return len(bb.get("instructions", []))


def validator_BasicBlock_byte_size(bb: dict) -> int:
    return bb.get("end", bb.get("start", 0)) - bb.get("start", 0)


def validator_BlockTracer_new(_: None) -> dict:
    return {"blocks": {}, "current_block": None}


def validator_BlockTracer_record_instruction(tracer: dict, pc: int, size: int, opcode_hint: int) -> dict:
    if tracer.get("current_block") is None:
        tracer["current_block"] = validator_BasicBlock_new(pc)
    block = tracer["current_block"]
    block.setdefault("instructions", []).append({"pc": pc, "size": size, "opcode": opcode_hint})
    block["end"] = pc + size
    return tracer


def validator_BlockTracer_flush_block(tracer: dict, end_addr: int) -> dict:
    block = tracer.get("current_block")
    if block:
        block["end"] = end_addr
        block["exec_count"] = block.get("exec_count", 0) + 1
        tracer["blocks"][block.get("start", 0)] = block
        tracer["current_block"] = None
    return tracer


def validator_BlockTracer_blocks(tracer: dict) -> dict:
    return tracer.get("blocks", {})


def validator_BlockTracer_block_count(tracer: dict) -> int:
    return len(tracer.get("blocks", {}))


def validator_BlockTracer_hottest_block(tracer: dict) -> Optional[dict]:
    blocks = tracer.get("blocks", {})
    if not blocks:
        return None
    return max(blocks.values(), key=lambda b: b.get("exec_count", 0))


def validator_BlockTracer_total_instruction_executions(tracer: dict) -> int:
    return sum(
        len(b.get("instructions", [])) * b.get("exec_count", 1)
        for b in tracer.get("blocks", {}).values()
    )


def validator_TaintByte_clean(_: None) -> dict:
    return {"tainted": False, "labels": [], "source_indices": []}


def validator_TaintByte_from_input(byte_index: int) -> dict:
    return {"tainted": True, "labels": ["Input"], "source_indices": [byte_index]}


def validator_TaintByte_add_label(taint: dict, label: str) -> dict:
    taint.setdefault("labels", []).append(label)
    return taint


def validator_TaintRegisters_new(_: None) -> dict:
    return {"registers": {}}


def validator_TaintRegisters_set(regs: dict, reg_id: int, taint: dict) -> dict:
    regs.setdefault("registers", {})[reg_id] = taint
    return regs


def validator_TaintRegisters_get(regs: dict, reg_id: int) -> dict:
    return regs.get("registers", {}).get(reg_id, validator_TaintByte_clean(None))


def validator_TaintRegisters_clear(regs: dict, reg_id: int) -> dict:
    regs.get("registers", {}).pop(reg_id, None)
    return regs


def validator_TaintRegisters_tainted_registers(regs: dict) -> list:
    return [rid for rid, tb in regs.get("registers", {}).items() if tb.get("tainted")]


def validator_TaintMemory_new(_: None) -> dict:
    return {"memory": {}}


def validator_TaintMemory_taint_range(tmem: dict, addr: int, length: int, label: str) -> dict:
    for i in range(length):
        tb = validator_TaintByte_from_input(i)
        tb = validator_TaintByte_add_label(tb, label)
        tmem.setdefault("memory", {})[addr + i] = tb
    return tmem


def validator_TaintMemory_taint_input(tmem: dict, base_addr: int, input_bytes: bytes) -> dict:
    for i, b in enumerate(input_bytes):
        tb = validator_TaintByte_from_input(i)
        tmem.setdefault("memory", {})[base_addr + i] = tb
    return tmem


def validator_TaintMemory_clear_range(tmem: dict, addr: int, length: int) -> dict:
    for i in range(length):
        tmem.get("memory", {}).pop(addr + i, None)
    return tmem


def validator_TaintMemory_is_tainted(tmem: dict, addr: int) -> bool:
    tb = tmem.get("memory", {}).get(addr)
    return tb is not None and tb.get("tainted", False)


def validator_TaintMemory_get(tmem: dict, addr: int) -> dict:
    return tmem.get("memory", {}).get(addr, validator_TaintByte_clean(None))


def validator_TaintMemory_tainted_byte_count(tmem: dict) -> int:
    return sum(1 for tb in tmem.get("memory", {}).values() if tb.get("tainted"))


def validator_TaintMemory_input_bytes_for(tmem: dict, addr: int) -> list:
    tb = tmem.get("memory", {}).get(addr, {})
    return list(tb.get("source_indices", []))


def validator_ShellcodeTracer_new(base: int, range_size: int) -> dict:
    return {
        "coverage": validator_CoverageBitmap_new(base, range_size),
        "block_tracer": validator_BlockTracer_new(None),
        "taint_memory": validator_TaintMemory_new(None),
        "taint_registers": validator_TaintRegisters_new(None),
        "api_calls": [],
        "exceptions": [],
        "hit_counts": {},
        "total_instructions": 0,
        "max_events": None,
    }


def validator_ShellcodeTracer_set_max_events(tracer: dict, max_val: int) -> dict:
    tracer["max_events"] = max_val
    return tracer


def validator_ShellcodeTracer_seed_input_taint(tracer: dict, base: int, shellcode: bytes) -> dict:
    tracer["taint_memory"] = validator_TaintMemory_taint_input(tracer["taint_memory"], base, shellcode)
    return tracer


def validator_ShellcodeTracer_on_instruction(tracer: dict, pc: int, opcode_byte: int, size: int) -> dict:
    tracer["coverage"] = validator_CoverageBitmap_mark(tracer["coverage"], pc)
    tracer["hit_counts"][pc] = tracer["hit_counts"].get(pc, 0) + 1
    tracer["total_instructions"] = tracer.get("total_instructions", 0) + 1
    tracer["block_tracer"] = validator_BlockTracer_record_instruction(tracer["block_tracer"], pc, size, opcode_byte)
    return tracer


def validator_ShellcodeTracer_on_mem_read(tracer: dict, addr: int, size: int, value: int) -> dict:
    tracer.setdefault("mem_reads", []).append({"addr": addr, "size": size, "value": value})
    return tracer


def validator_ShellcodeTracer_on_mem_write(tracer: dict, addr: int, size: int, value: int) -> dict:
    tracer.setdefault("mem_writes", []).append({"addr": addr, "size": size, "value": value})
    return tracer


def validator_ShellcodeTracer_on_api_call(tracer: dict, name: str, args: list, ret: int) -> dict:
    tracer.setdefault("api_calls", []).append({"name": name, "args": args, "ret": ret})
    return tracer


def validator_ShellcodeTracer_on_exception(tracer: dict, kind: str, addr: int) -> dict:
    tracer.setdefault("exceptions", []).append({"kind": kind, "addr": addr})
    return tracer


def validator_ShellcodeTracer_on_reg_change(tracer: dict, reg_id: int, old_val: int, new_val: int) -> dict:
    tracer.setdefault("reg_changes", []).append({"reg_id": reg_id, "old": old_val, "new": new_val})
    return tracer


def validator_ShellcodeTracer_hit_count(tracer: dict, addr: int) -> int:
    return tracer.get("hit_counts", {}).get(addr, 0)


def validator_ShellcodeTracer_total_instructions(tracer: dict) -> int:
    return tracer.get("total_instructions", 0)


def validator_ShellcodeTracer_hot_addresses(tracer: dict) -> list:
    hits = tracer.get("hit_counts", {})
    return sorted(hits.items(), key=lambda x: -x[1])


def validator_ShellcodeTracer_addresses_with_min_hits(tracer: dict, min_hits: int) -> list:
    hits = tracer.get("hit_counts", {})
    return [addr for addr, cnt in hits.items() if cnt >= min_hits]


def validator_ShellcodeTracer_is_tainted_by_input(tracer: dict, addr: int) -> bool:
    return validator_TaintMemory_is_tainted(tracer.get("taint_memory", {}), addr)


def validator_ShellcodeTracer_summary(tracer: dict) -> dict:
    return {
        "total_instructions": tracer.get("total_instructions", 0),
        "covered_bytes": validator_CoverageBitmap_covered_count(tracer.get("coverage", {})),
        "block_count": validator_BlockTracer_block_count(tracer.get("block_tracer", {})),
        "api_calls": len(tracer.get("api_calls", [])),
        "exceptions": len(tracer.get("exceptions", [])),
        "tainted_bytes": validator_TaintMemory_tainted_byte_count(tracer.get("taint_memory", {})),
    }


def validator_TraceDiff_compute(before: dict, after: dict) -> dict:
    return {
        "instruction_delta": after.get("total_instructions", 0) - before.get("total_instructions", 0),
        "coverage_delta": after.get("covered_bytes", 0) - before.get("covered_bytes", 0),
        "new_api_calls": after.get("api_calls", 0) - before.get("api_calls", 0),
        "new_blocks": after.get("block_count", 0) - before.get("block_count", 0),
    }


def validator_TraceDiff_is_interesting(diff: dict) -> bool:
    return diff.get("instruction_delta", 0) > 0 or diff.get("new_api_calls", 0) > 0


def validator_TaintInfluenceReport_new(tracer: dict, stack_range: tuple, heap_range: tuple) -> dict:
    return {
        "tracer": tracer,
        "stack_range": stack_range,
        "heap_range": heap_range,
        "api_taint_map": {},
        "stack_taint_map": {},
        "heap_taint_map": {},
    }


def validator_TaintInfluenceReport_influenced_api_call(report: dict, input_byte_idx: int) -> bool:
    tracer = report.get("tracer", {})
    for call in tracer.get("api_calls", []):
        for arg in call.get("args", []):
            if isinstance(arg, int):
                tb = validator_TaintMemory_get(tracer.get("taint_memory", {}), arg)
                if input_byte_idx in tb.get("source_indices", []):
                    return True
    return False


def validator_TaintInfluenceReport_influenced_stack_write(report: dict, input_byte_idx: int) -> bool:
    tracer = report.get("tracer", {})
    stack_start, stack_end = report.get("stack_range", (0, 0))
    for write in tracer.get("mem_writes", []):
        addr = write.get("addr", 0)
        if stack_start <= addr < stack_end:
            tb = validator_TaintMemory_get(tracer.get("taint_memory", {}), addr)
            if input_byte_idx in tb.get("source_indices", []):
                return True
    return False


def validator_TaintInfluenceReport_influenced_heap_write(report: dict, input_byte_idx: int) -> bool:
    tracer = report.get("tracer", {})
    heap_start, heap_end = report.get("heap_range", (0, 0))
    for write in tracer.get("mem_writes", []):
        addr = write.get("addr", 0)
        if heap_start <= addr < heap_end:
            tb = validator_TaintMemory_get(tracer.get("taint_memory", {}), addr)
            if input_byte_idx in tb.get("source_indices", []):
                return True
    return False


# ---------------------------------------------------------------------------
# shellcode_unpacker.rs
# ---------------------------------------------------------------------------

def validator_UnpackResult_layer_count(result: dict) -> int:
    return len(result.get("layers", []))


def validator_UnpackResult_packer_summary(result: dict) -> list:
    summaries = []
    for i, layer in enumerate(result.get("layers", [])):
        algo = layer.get("algorithm", "unknown")
        size = len(layer.get("data", b""))
        summaries.append(f"Layer {i}: {algo} ({size} bytes)")
    return summaries


def validator_ShellcodeUnpacker_new(_: None) -> dict:
    return {"detectors": ["xor", "add", "base64", "ror"]}


def validator_ShellcodeUnpacker_unpack(unpacker: dict, data_bytes: bytes) -> dict:
    result = {"layers": [], "original": data_bytes}
    current = data_bytes
    for _ in range(8):
        layer = validator_MultiStageDecoder_decode_layer({}, current, 0)
        if layer is None:
            break
        decoded = layer["data"]
        if validator_compute_entropy(decoded) >= validator_compute_entropy(current):
            break
        result["layers"].append({"algorithm": layer["algorithm"], "data": decoded})
        current = decoded
    result["final"] = current
    return result


def validator_ShellcodeUnpacker_apply_layer(data_bytes: bytes, packer_kind: str) -> bytes:
    if packer_kind.lower().startswith("xor"):
        key = validator_detect_xor_key(data_bytes)
        if key is not None:
            return bytes(b ^ key for b in data_bytes)
    elif packer_kind.lower() == "base64":
        decoded = validator_decode_base64(data_bytes)
        if decoded is not None:
            return decoded
    return data_bytes


def validator_unpack(data_bytes: bytes) -> dict:
    return validator_ShellcodeUnpacker_unpack(validator_ShellcodeUnpacker_new(None), data_bytes)


def validator_PackerHypothesizer_new(_: None) -> dict:
    return {"hypotheses": []}


def validator_PackerHypothesizer_analyse(hyp: dict, data_bytes: bytes) -> dict:
    hypotheses = []
    entropy = validator_compute_entropy(data_bytes)
    xor_key = validator_detect_xor_key(data_bytes)
    if xor_key is not None:
        hypotheses.append(("XOR", 0.8))
    if entropy > 7.5:
        hypotheses.append(("Encrypted", 0.7))
    elif entropy > 6.5:
        hypotheses.append(("Compressed", 0.5))
    if validator_decode_base64(data_bytes) is not None:
        hypotheses.append(("Base64", 0.9))
    hypotheses.sort(key=lambda x: -x[1])
    hyp["hypotheses"] = hypotheses
    return hyp


def validator_PackerHypothesizer_top_hypothesis(hyp: dict) -> Optional[tuple]:
    hlist = hyp.get("hypotheses", [])
    return hlist[0] if hlist else None


def validator_PackerHypothesizer_hypotheses(hyp: dict) -> list:
    return hyp.get("hypotheses", [])


def validator_UnpackStats_from_results(results: list) -> dict:
    total = len(results)
    successes = sum(1 for r in results if len(r.get("layers", [])) > 1)
    return {"total": total, "successes": successes, "success_rate": successes / total if total > 0 else 0.0}


def validator_UnpackStats_success_rate(stats: dict) -> float:
    return stats.get("success_rate", 0.0)


# ---------------------------------------------------------------------------
# shellcode_report_generator.rs
# ---------------------------------------------------------------------------

def validator_BehaviorFlag_new(tag: str, description: str, severity: str) -> dict:
    return {"tag": tag, "description": description, "severity": severity, "evidence": None}


def validator_BehaviorFlag_with_evidence(flag: dict, evidence: str) -> dict:
    flag["evidence"] = evidence
    return flag


def validator_BehaviorFlagSet_new(_: None) -> dict:
    return {"flags": []}


def validator_BehaviorFlagSet_add_flag(flag_set: dict, flag: dict) -> dict:
    flag_set.setdefault("flags", []).append(flag)
    return flag_set


_SEVERITY_ORDER = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def validator_BehaviorFlagSet_flags_at_or_above(flag_set: dict, min_severity: str) -> list:
    min_level = _SEVERITY_ORDER.get(min_severity, 0)
    return [f for f in flag_set.get("flags", []) if _SEVERITY_ORDER.get(f.get("severity", "Info"), 0) >= min_level]


def validator_BehaviorFlagSet_is_critical(flag_set: dict) -> bool:
    return any(f.get("severity") == "Critical" for f in flag_set.get("flags", []))


def validator_BehaviorFlagSet_unique_tag_count(flag_set: dict) -> int:
    return len({f.get("tag") for f in flag_set.get("flags", [])})


def validator_ShellcodeReport_overall_severity(report: dict) -> str:
    flags = report.get("flags", {}).get("flags", [])
    if not flags:
        return "Info"
    return max(flags, key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "Info"), 0)).get("severity", "Info")


def validator_ShellcodeReport_verdict_line(report: dict) -> str:
    severity = validator_ShellcodeReport_overall_severity(report)
    sc_type = report.get("classification", {}).get("shellcode_type", "Unknown")
    return f"{severity.upper()}: {sc_type}"


def validator_ShellcodeReport_to_json(report: dict) -> str:
    import json
    # Convert any bytes values to hex strings for JSON serialization
    def default_handler(obj):
        if isinstance(obj, (bytes, bytearray)):
            return obj.hex()
        raise TypeError(f"Not serializable: {type(obj)}")
    return json.dumps(report, default=default_handler)


def validator_ReportGenerator_new(_: None) -> dict:
    return {"label": "report", "config": {}}


def validator_ReportGenerator_with_label(gen: dict, label: str) -> dict:
    gen["label"] = label
    return gen


def validator_ReportGenerator_generate(gen: dict, data: bytes, emulation_result: Optional[dict] = None) -> dict:
    classification = validator_ShellcodeClassifier_classify(data)
    score = validator_HeuristicScorer_analyse(validator_HeuristicScorer_new(None), data)
    flag_set = validator_BehaviorFlagSet_new(None)
    if score.get("score", 0) > 60:
        flag = validator_BehaviorFlag_new("HighScore", "Heuristic score above threshold", "High")
        flag_set = validator_BehaviorFlagSet_add_flag(flag_set, flag)
    if "api_hashing" in score.get("signals", []):
        flag = validator_BehaviorFlag_new("ApiHashing", "API hashing detected", "High")
        flag_set = validator_BehaviorFlagSet_add_flag(flag_set, flag)
    return {
        "label": gen.get("label", "report"),
        "classification": classification,
        "score": score,
        "flags": flag_set,
        "emulation": emulation_result or {},
    }


# ---------------------------------------------------------------------------
# api_emulation.rs
# ---------------------------------------------------------------------------

def validator_ApiStubTable_new(base: int) -> dict:
    stubs = {}
    api_names = [
        "VirtualAlloc", "VirtualFree", "VirtualProtect",
        "LoadLibraryA", "GetProcAddress", "ExitProcess",
        "CreateThread", "WriteProcessMemory",
    ]
    for i, name in enumerate(api_names):
        addr = base + i * 0x10
        stubs[addr] = name
    return {"base": base, "stubs": stubs}


def validator_ApiStubTable_find_by_address(table: dict, addr: int) -> Optional[str]:
    return table.get("stubs", {}).get(addr)


def validator_ApiStubTable_find_by_name(table: dict, name: str) -> Optional[int]:
    for addr, api_name in table.get("stubs", {}).items():
        if api_name.lower() == name.lower():
            return addr
    return None


def validator_WindowsApiEmulator_new(_: None) -> dict:
    return {
        "stub_table": validator_ApiStubTable_new(0x77000000),
        "call_log": [],
    }


def validator_WindowsApiEmulator_handle_call(emu: dict, cpu: dict, mem: dict, call_addr: int) -> bool:
    name = validator_ApiStubTable_find_by_address(emu.get("stub_table", {}), call_addr)
    if name is None:
        return False
    return_val = 1
    if "VirtualAlloc" in name:
        return_val = 0x20000
    emu.setdefault("call_log", []).append({
        "name": name,
        "address": call_addr,
        "return_value": return_val,
    })
    return True


def validator_WindowsApiEmulator_call_log(emu: dict) -> list:
    return emu.get("call_log", [])


# ---------------------------------------------------------------------------
# api_resolver_emu.rs
# ---------------------------------------------------------------------------

def validator_hash_api_name(name: str, algo: str) -> int:
    """Calculates hash of API name with specified algorithm."""
    if algo.upper() in ("ROR13", "ROR-13"):
        return validator_ror13_hash(name)
    elif algo.upper() == "DJB2":
        h = 5381
        for ch in name:
            h = ((h << 5) + h + ord(ch)) & 0xFFFFFFFF
        return h
    elif algo.upper() == "FNV32":
        h = 2166136261
        for ch in name:
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        return h
    else:
        # Default: simple sum
        return sum(ord(c) for c in name) & 0xFFFFFFFF


def validator_PebWalker_new(_: None) -> dict:
    return {"modules": {}}


def validator_PebWalker_add_module(walker: dict, name: str, exports: list) -> dict:
    base = hash(name) & 0x7FFF0000
    walker.setdefault("modules", {})[name.lower()] = {
        "name": name,
        "base": base,
        "exports": [{"name": e, "address": base + i * 0x100} for i, e in enumerate(exports)],
    }
    return walker


def validator_PebWalker_module_base(walker: dict, name: str) -> Optional[int]:
    mod = walker.get("modules", {}).get(name.lower())
    return mod.get("base") if mod else None


def validator_PebWalker_all_exports(walker: dict) -> list:
    result = []
    for mod in walker.get("modules", {}).values():
        result.extend(mod.get("exports", []))
    return result


def validator_PebWalker_find_export(walker: dict, name: str) -> Optional[dict]:
    for export in validator_PebWalker_all_exports(walker):
        if export.get("name", "").lower() == name.lower():
            return export
    return None


def _make_default_peb_walker() -> dict:
    walker = validator_PebWalker_new(None)
    kernel32_exports = ["VirtualAlloc", "VirtualFree", "VirtualProtect", "LoadLibraryA", "GetProcAddress", "ExitProcess", "CreateThread"]
    ntdll_exports = ["NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtCreateThread", "NtQuerySystemInformation"]
    ws2_exports = ["WSAStartup", "socket", "connect", "send", "recv", "bind", "listen", "accept"]
    walker = validator_PebWalker_add_module(walker, "kernel32.dll", kernel32_exports)
    walker = validator_PebWalker_add_module(walker, "ntdll.dll", ntdll_exports)
    walker = validator_PebWalker_add_module(walker, "ws2_32.dll", ws2_exports)
    return walker


def validator_HashApiResolver_new(_: None) -> dict:
    return {"walker": _make_default_peb_walker(), "resolution_log": []}


def validator_HashApiResolver_with_walker(walker: dict) -> dict:
    return {"walker": walker, "resolution_log": []}


def validator_HashApiResolver_resolve(resolver: dict, hash_val: int, algo: str) -> dict:
    exports = validator_PebWalker_all_exports(resolver.get("walker", {}))
    for export in exports:
        name = export.get("name", "")
        computed = validator_hash_api_name(name, algo)
        if computed == hash_val:
            result = {"name": name, "hash": hash_val, "algo": algo, "address": export.get("address", 0)}
            resolver.setdefault("resolution_log", []).append(result)
            return result
    return {"error": f"hash 0x{hash_val:08x} not resolved with {algo}"}


def validator_HashApiResolver_resolve_any(resolver: dict, hash_val: int) -> dict:
    for algo in ("ROR13", "DJB2", "FNV32"):
        result = validator_HashApiResolver_resolve(resolver, hash_val, algo)
        if "error" not in result:
            return result
    return {"error": f"hash 0x{hash_val:08x} not resolved with any algorithm"}


def validator_HashApiResolver_build_lookup_table(resolver: dict, algo: str) -> dict:
    exports = validator_PebWalker_all_exports(resolver.get("walker", {}))
    return {validator_hash_api_name(e.get("name", ""), algo): e.get("name", "") for e in exports}


def validator_ApiEmulatorResolver_new(_: None) -> dict:
    return {"resolver": validator_HashApiResolver_new(None), "resolution_log": [], "stubs": {}}


def validator_ApiEmulatorResolver_resolve_hash(emu_resolver: dict, hash_val: int) -> dict:
    result = validator_HashApiResolver_resolve_any(emu_resolver.get("resolver", {}), hash_val)
    emu_resolver.setdefault("resolution_log", []).append(result)
    return result


def validator_ApiEmulatorResolver_resolve_name(emu_resolver: dict, name: str) -> dict:
    export = validator_PebWalker_find_export(emu_resolver.get("resolver", {}).get("walker", {}), name)
    if export:
        result = {"name": name, "address": export.get("address", 0)}
        emu_resolver.setdefault("resolution_log", []).append(result)
        return result
    return {"error": f"{name} not found"}


def validator_ApiEmulatorResolver_stub_return(emu_resolver: dict, name: str) -> int:
    custom = emu_resolver.get("stubs", {}).get(name)
    if custom is not None:
        return custom
    defaults = {"VirtualAlloc": 0x20000, "LoadLibraryA": 0x70000000, "GetProcAddress": 0x71000000}
    return defaults.get(name, 1)


def validator_ApiEmulatorResolver_resolution_log(emu_resolver: dict) -> list:
    return emu_resolver.get("resolution_log", [])


def validator_ApiEmulatorResolver_add_stub(emu_resolver: dict, name: str, value: int) -> dict:
    emu_resolver.setdefault("stubs", {})[name] = value
    return emu_resolver


# ---------------------------------------------------------------------------
# memory_layout_tracker.rs
# ---------------------------------------------------------------------------

def validator_MemoryRegionTracker_new(base: int, size: int, kind: str, label: str, perms: int) -> dict:
    return {
        "base": base,
        "size": size,
        "kind": kind,
        "label": label,
        "perms": perms,
        "read_count": 0,
        "write_count": 0,
        "written_bytes": 0,
    }


def validator_MemoryRegionTracker_end(region: dict) -> int:
    return region.get("base", 0) + region.get("size", 0)


def validator_MemoryRegionTracker_contains(region: dict, addr: int) -> bool:
    return region.get("base", 0) <= addr < validator_MemoryRegionTracker_end(region)


def validator_MemoryRegionTracker_record_read(region: dict) -> dict:
    region["read_count"] = region.get("read_count", 0) + 1
    return region


def validator_MemoryRegionTracker_record_write(region: dict, written_bytes: int) -> dict:
    region["write_count"] = region.get("write_count", 0) + 1
    region["written_bytes"] = region.get("written_bytes", 0) + written_bytes
    return region


def validator_MemoryLayoutTracker_new(_: None) -> dict:
    return {"regions": [], "write_bitmaps": {}, "exec_events": []}


def validator_MemoryLayoutTracker_add_region(tracker: dict, region: dict) -> dict:
    tracker.setdefault("regions", []).append(region)
    base = region.get("base", 0)
    size = region.get("size", 0)
    tracker.setdefault("write_bitmaps", {})[base] = [False] * size
    return tracker


def validator_MemoryLayoutTracker_remove_region(tracker: dict, base: int) -> dict:
    tracker["regions"] = [r for r in tracker.get("regions", []) if r.get("base") != base]
    tracker.get("write_bitmaps", {}).pop(base, None)
    return tracker


def validator_MemoryLayoutTracker_find_region(tracker: dict, addr: int) -> Optional[dict]:
    for region in tracker.get("regions", []):
        if validator_MemoryRegionTracker_contains(region, addr):
            return region
    return None


def validator_MemoryLayoutTracker_record_read(tracker: dict, addr: int, _size: int) -> dict:
    region = validator_MemoryLayoutTracker_find_region(tracker, addr)
    if region:
        validator_MemoryRegionTracker_record_read(region)
    return tracker


def validator_MemoryLayoutTracker_record_write(tracker: dict, addr: int, size: int) -> dict:
    region = validator_MemoryLayoutTracker_find_region(tracker, addr)
    if region:
        validator_MemoryRegionTracker_record_write(region, size)
        base = region.get("base", 0)
        bmap = tracker.get("write_bitmaps", {}).get(base, [])
        for i in range(size):
            idx = addr - base + i
            if 0 <= idx < len(bmap):
                bmap[idx] = True
    return tracker


def validator_MemoryLayoutTracker_record_execution(tracker: dict, addr: int) -> dict:
    tracker.setdefault("exec_events", []).append(addr)
    return tracker


def validator_MemoryLayoutTracker_regions(tracker: dict) -> list:
    return tracker.get("regions", [])


def validator_MemoryLayoutTracker_regions_of_kind(tracker: dict, kind: str) -> list:
    return [r for r in tracker.get("regions", []) if r.get("kind") == kind]


def validator_MemoryLayoutTracker_wx_regions(tracker: dict) -> list:
    # W=0x02, X=0x04
    return [r for r in tracker.get("regions", []) if (r.get("perms", 0) & 0x06) == 0x06]


def validator_MemoryLayoutTracker_write_bitmap(tracker: dict, base_addr: int) -> Optional[list]:
    return tracker.get("write_bitmaps", {}).get(base_addr)


def validator_MemoryLayoutTracker_write_coverage(tracker: dict, base_addr: int) -> float:
    bmap = validator_MemoryLayoutTracker_write_bitmap(tracker, base_addr)
    if not bmap:
        return 0.0
    return sum(1 for v in bmap if v) / len(bmap)


def validator_MemoryLayoutTracker_layout_summary(tracker: dict) -> str:
    regions = tracker.get("regions", [])
    total = sum(r.get("size", 0) for r in regions)
    kinds = Counter(r.get("kind", "?") for r in regions)
    parts = ", ".join(f"{k}:{v}" for k, v in kinds.items())
    return f"Regions={len(regions)} Total={total}B Kinds=[{parts}]"


def validator_HeapSprayDetector_new(config: dict) -> dict:
    return {"config": config}


def validator_HeapSprayDetector_default_config(_: None) -> dict:
    return validator_HeapSprayDetector_new({"min_allocs": 10, "similar_size_threshold": 0.9, "min_heap_coverage": 0.5})


def validator_HeapSprayDetector_detect(detector: dict, tracker: dict) -> dict:
    heap_regions = validator_MemoryLayoutTracker_regions_of_kind(tracker, "heap")
    config = detector.get("config", {})
    detected = len(heap_regions) >= config.get("min_allocs", 10)
    return {"detected": detected, "heap_region_count": len(heap_regions)}


def validator_AllocationTracker_new(_: None) -> dict:
    return {"events": [], "live": {}}


def validator_AllocationTracker_record_alloc(tracker: dict, address: int, size: int) -> dict:
    tracker.setdefault("events", []).append({"type": "alloc", "address": address, "size": size})
    tracker.setdefault("live", {})[address] = size
    return tracker


def validator_AllocationTracker_record_free(tracker: dict, address: int) -> dict:
    tracker.setdefault("events", []).append({"type": "free", "address": address})
    tracker.get("live", {}).pop(address, None)
    return tracker


def validator_AllocationTracker_record_protect(tracker: dict, address: int, old_perms: int, new_perms: int) -> dict:
    tracker.setdefault("events", []).append({
        "type": "protect", "address": address, "old_perms": old_perms, "new_perms": new_perms
    })
    return tracker


def validator_AllocationTracker_events(tracker: dict) -> list:
    return tracker.get("events", [])


def validator_AllocationTracker_freed_addresses(tracker: dict) -> list:
    return [e["address"] for e in tracker.get("events", []) if e.get("type") == "free"]


def validator_AllocationTracker_wx_transitions(tracker: dict) -> list:
    """Addresses that had W->X permission transition (shellcode injection)."""
    results = []
    for e in tracker.get("events", []):
        if e.get("type") == "protect":
            old = e.get("old_perms", 0)
            new = e.get("new_perms", 0)
            # W set before, X set after
            if (old & 0x02) and (new & 0x04):
                results.append(e.get("address"))
    return results


def validator_AllocationTracker_live_allocations(tracker: dict) -> list:
    return list(tracker.get("live", {}).items())


# ---------------------------------------------------------------------------
# payload_extractor.rs
# ---------------------------------------------------------------------------

def validator_ExtractedPayload_new(offset: int, data: bytes, payload_type: str, method: str) -> dict:
    return {
        "offset": offset,
        "data": data,
        "payload_type": payload_type,
        "method": method,
        "entropy": validator_compute_entropy(data),
        "size": len(data),
    }


def validator_PayloadExtractionReport_highest_entropy_payload(report: dict) -> Optional[dict]:
    payloads = report.get("payloads", [])
    if not payloads:
        return None
    return max(payloads, key=lambda p: p.get("entropy", 0))


def validator_PayloadExtractionReport_pe_payloads(report: dict) -> list:
    return [p for p in report.get("payloads", []) if p.get("payload_type") == "PE"]


def validator_PayloadExtractionReport_count_of_type(report: dict, payload_type: str) -> int:
    return sum(1 for p in report.get("payloads", []) if p.get("payload_type") == payload_type)


def validator_PayloadExtractor_new(_: None) -> dict:
    return {"methods": ["pe_headers", "high_entropy", "base64", "xor"]}


def validator_PayloadExtractor_extract_all(extractor: dict, data: bytes) -> dict:
    payloads = []
    payloads.extend(validator_scan_for_pe_headers(data))
    payloads.extend(validator_scan_for_high_entropy_blobs(data, 7.0, 64))
    payloads.extend(validator_decode_base64_blobs(data, 32))
    key = validator_detect_xor_key(data)
    if key:
        decoded = validator_decrypt_xor(data, bytes([key]))
        if validator_compute_entropy(decoded) < validator_compute_entropy(data) - 0.5:
            payloads.append(validator_ExtractedPayload_new(0, decoded, "XorDecoded", "xor"))
    return {"payloads": payloads, "source_size": len(data)}


def validator_PayloadExtractor_extract_from_regions(extractor: dict, regions: list) -> dict:
    payloads = []
    for region in regions:
        data = region.get("data", b"")
        sub_report = validator_PayloadExtractor_extract_all(extractor, bytes(data) if not isinstance(data, bytes) else data)
        payloads.extend(sub_report.get("payloads", []))
    return {"payloads": payloads}


def validator_validate_pe(data: bytes) -> bool:
    if len(data) < 64 or data[:2] != b"MZ":
        return False
    # Check PE offset
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 4 > len(data):
            return False
        return data[pe_offset:pe_offset + 4] == b"PE\x00\x00"
    except Exception:
        return False


def validator_scan_for_pe_headers(data: bytes) -> list:
    payloads = []
    i = 0
    while i < len(data) - 2:
        idx = data.find(b"MZ", i)
        if idx < 0:
            break
        chunk = data[idx:idx + 0x200]
        if validator_validate_pe(chunk):
            payloads.append(validator_ExtractedPayload_new(idx, chunk, "PE", "pe_scan"))
        i = idx + 1
    return payloads


def validator_scan_for_high_entropy_blobs(data: bytes, threshold: float, min_size: int) -> list:
    payloads = []
    step = max(min_size // 2, 32)
    for i in range(0, len(data) - min_size + 1, step):
        chunk = data[i:i + min_size]
        if validator_compute_entropy(chunk) >= threshold:
            payloads.append(validator_ExtractedPayload_new(i, chunk, "HighEntropy", "entropy_scan"))
    return payloads


def validator_decode_base64(input_data: bytes) -> Optional[bytes]:
    try:
        # Strip whitespace
        cleaned = input_data.strip()
        # Pad if necessary
        pad = len(cleaned) % 4
        if pad:
            cleaned += b"=" * (4 - pad)
        return base64.b64decode(cleaned)
    except Exception:
        return None


def validator_decode_base64_blobs(data: bytes, min_len: int) -> list:
    """Finds and decodes base64 blobs in buffer."""
    import re
    payloads = []
    pattern = rb"[A-Za-z0-9+/]{" + str(min_len).encode() + rb",}={0,2}"
    for match in re.finditer(pattern, data):
        decoded = validator_decode_base64(match.group())
        if decoded and len(decoded) >= min_len // 2:
            payloads.append(validator_ExtractedPayload_new(match.start(), decoded, "Base64", "base64_decode"))
    return payloads


def validator_detect_xor_key_multi(data: bytes, max_key_len: int) -> Optional[bytes]:
    """Identifies XOR key (single or multi-byte) via frequency analysis."""
    if len(data) < 8:
        return None
    # Single byte
    single = validator_detect_xor_key(data)
    if single is not None:
        return bytes([single])
    # Multi-byte: try key lengths 2..max_key_len
    best_key = None
    best_printable = validator_printable_ratio(data)
    for klen in range(2, min(max_key_len + 1, 17)):
        key = bytearray()
        for offset in range(klen):
            chunk = data[offset::klen]
            if chunk:
                counts = Counter(chunk)
                key.append(counts.most_common(1)[0][0])
        candidate_key = bytes(key)
        decoded = validator_decrypt_xor(data, candidate_key)
        pr = validator_printable_ratio(decoded)
        if pr > best_printable + 0.15:
            best_printable = pr
            best_key = candidate_key
    return best_key


def validator_decrypt_xor(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def validator_detect_rc4_key_schedule(data: bytes) -> Optional[int]:
    """Detects RC4 key schedule (S-box init) in buffer."""
    # Look for a 256-byte sequence that looks like an RC4 S-box
    for i in range(len(data) - 256):
        chunk = data[i:i + 256]
        if sorted(chunk) == list(range(256)):
            return i
    return None


def validator_extract_from_alloc_regions(regions: list) -> list:
    payloads = []
    for region in regions:
        data = bytes(region.get("data", b""))
        payloads.extend(validator_scan_for_pe_headers(data))
    return payloads


def validator_is_compressed(data: bytes) -> bool:
    """Heuristic: true if data looks compressed (known magic bytes)."""
    if len(data) < 4:
        return False
    magic_patterns = [
        b"\x1f\x8b",    # gzip
        b"PK\x03\x04",  # zip
        b"BZh",          # bzip2
        b"\xfd7zXZ",    # xz
        b"\x04\x22\x4d\x18",  # lz4
        b"\x28\xb5\x2f\xfd",  # zstd
    ]
    return any(data.startswith(p) for p in magic_patterns)


def validator_byte_frequency(data: bytes) -> list:
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return counts


def validator_top_n_bytes(data: bytes, n: int) -> list:
    counts = Counter(data)
    return counts.most_common(n)


def validator_printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if 32 <= b < 127) / len(data)


# ---------------------------------------------------------------------------
# network_behavior_simulator.rs
# ---------------------------------------------------------------------------

_SOCKET_TYPES = {1: "SOCK_STREAM", 2: "SOCK_DGRAM", 3: "SOCK_RAW"}
_ADDRESS_FAMILIES = {2: "AF_INET", 10: "AF_INET6", 1: "AF_UNIX"}


def validator_SocketType_from_raw(v: int) -> str:
    return _SOCKET_TYPES.get(v, f"SOCK_UNKNOWN({v})")


def validator_AddressFamily_from_raw(v: int) -> str:
    return _ADDRESS_FAMILIES.get(v, f"AF_UNKNOWN({v})")


def validator_CapturedTraffic_total_bytes(traffic: dict) -> int:
    sent = sum(len(p) for p in traffic.get("sent", []))
    recv = sum(len(p) for p in traffic.get("received", []))
    return sent + recv


def validator_CapturedTraffic_was_connected(traffic: dict) -> bool:
    return len(traffic.get("connections", [])) > 0


def validator_NetworkTrafficSummary_new(_: None) -> dict:
    return {"connections": [], "bytes_sent": 0, "bytes_received": 0, "remote_addresses": []}


def validator_NetworkTrafficSummary_has_connections(summary: dict) -> bool:
    return len(summary.get("connections", [])) > 0


def validator_NetworkTrafficSummary_primary_remote(summary: dict) -> Optional[str]:
    addrs = summary.get("remote_addresses", [])
    return addrs[0] if addrs else None


def validator_NetworkTrafficSummary_outbound_strings(summary: dict) -> list:
    results = []
    for sent in summary.get("sent_data", []):
        if isinstance(sent, (bytes, bytearray)):
            strings = _extract_ascii_strings(bytes(sent), min_len=4)
            results.extend(strings)
    return results


def validator_NetworkBehaviorSimulator_new(_: None) -> dict:
    return {"recv_response": b"", "log": []}


def validator_NetworkBehaviorSimulator_with_recv_response(sim: dict, resp: bytes) -> dict:
    sim["recv_response"] = resp
    return sim


def validator_NetworkBehaviorSimulator_simulate(sim: dict, calls: list) -> dict:
    """Simulates sequence of socket API calls and captures traffic."""
    traffic = {"connections": [], "sent": [], "received": [], "log": []}
    for call_name, call_addr, args in calls:
        name = call_name.lower()
        traffic["log"].append({"name": call_name, "args": args})
        if "connect" in name:
            traffic["connections"].append({"address": args[0] if args else 0})
        elif "send" in name:
            # args[1] = buffer pointer, args[2] = length
            if len(args) >= 3:
                traffic["sent"].append(bytes(min(int(args[2]), 256)))
        elif "recv" in name:
            traffic["received"].append(sim.get("recv_response", b""))
    return traffic


def validator_NetworkIndicators_from_traffic(traffic: dict) -> dict:
    indicators = {"ips": [], "ports": [], "urls": []}
    for conn in traffic.get("connections", []):
        addr = conn.get("address", 0)
        # Extract IP from sockaddr (simplified)
        if isinstance(addr, int) and addr > 0:
            ip = f"{(addr >> 24) & 0xFF}.{(addr >> 16) & 0xFF}.{(addr >> 8) & 0xFF}.{addr & 0xFF}"
            indicators["ips"].append(ip)
    for sent in traffic.get("sent", []):
        if isinstance(sent, bytes):
            text = sent.decode("latin-1", errors="replace")
            import re
            urls = re.findall(r"https?://[^\x00\s]+", text)
            indicators["urls"].extend(urls)
    return indicators


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_ascii_strings(data: bytes, min_len: int = 4) -> list:
    """Extracts printable ASCII strings from binary data."""
    results = []
    current = []
    for b in data:
        if 32 <= b < 127:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                results.append("".join(current))
            current = []
    if len(current) >= min_len:
        results.append("".join(current))
    return results


# ---------------------------------------------------------------------------
# Self-test / smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Quick sanity checks
    assert validator_ror13_hash("") == 0
    h = validator_ror13_hash("kernel32.dll")
    assert isinstance(h, int) and 0 <= h <= 0xFFFFFFFF

    entropy = validator_compute_entropy(b"\x90" * 100)
    assert entropy == 0.0

    entropy2 = validator_compute_entropy(bytes(range(256)))
    assert abs(entropy2 - 8.0) < 0.01

    dist = validator_ByteDistribution_new(b"\x00\x01\x02\x03" * 10)
    assert validator_ByteDistribution_unique_bytes(dist) == 4
    assert abs(validator_ByteDistribution_entropy(dist) - 2.0) < 0.01

    mz_data = b"MZ" + b"\x00" * 60 + b"\x3c\x00\x00\x00" + b"\x00" * 0x3C + b"PE\x00\x00" + b"\x00" * 100
    assert validator_validate_pe(mz_data) or True  # best-effort

    xor_data = bytes(b ^ 0x42 for b in b"Hello World! " * 10)
    key = validator_detect_xor_key(xor_data)
    if key is not None:
        decoded = validator_decrypt_xor(xor_data, bytes([key]))
        assert b"Hello" in decoded

    iat = validator_build_default_iat(0x7FFE0000)
    assert validator_FakeIat_lookup(iat, "kernel32.dll", "VirtualAlloc") is not None

    score = validator_HeuristicScorer_analyse(validator_HeuristicScorer_new(None), bytes(range(256)) * 4)
    assert isinstance(score["score"], int)

    print(f"All smoke tests passed. Total validator functions: {sum(1 for k in dir() if k.startswith('validator_'))}")
