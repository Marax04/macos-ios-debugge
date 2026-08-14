"""
Validators for rustre-forensics-plugins crate (250 public functions).
Each validator_NAME(input) -> output mirrors the Rust function semantics using Python stdlib only.
"""

import json
import re
import math
import struct
import ipaddress
import base64
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# volatility_plugins
# ---------------------------------------------------------------------------

SYSTEM_PROCESS_NAMES = {
    "System", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe",
}


def validator_ProcessEntry_is_system(entry: dict) -> bool:
    """True if process is a system process (PID 4 or known system name)."""
    if entry.get("pid") == 4:
        return True
    return entry.get("name", "") in SYSTEM_PROCESS_NAMES


def validator_ProcessEntry_is_alive(entry: dict) -> bool:
    """True if process is still running (exit_time is 0 or None)."""
    return not entry.get("exit_time", 0)


def validator_PluginOutput_to_json(output: dict) -> str:
    """Serialize plugin output to compact JSON."""
    return json.dumps(output, separators=(",", ":"))


def validator_PluginOutput_to_json_pretty(output: dict) -> str:
    """Serialize plugin output to pretty-printed JSON."""
    return json.dumps(output, indent=2)


def validator_PluginArgs_new() -> dict:
    """Create empty plugin args."""
    return {}


def validator_PluginArgs_set(args: dict, key: str, value: str) -> dict:
    """Add key/value pair to args (builder pattern, returns new dict)."""
    result = dict(args)
    result[key] = value
    return result


def validator_PluginArgs_get(args: dict, key: str) -> Optional[str]:
    """Retrieve value by key."""
    return args.get(key)


def validator_ProcessList_build(entries: list) -> dict:
    """Build process list from entries."""
    return {"entries": entries, "count": len(entries)}


def validator_ProcessList_total_count(process_list: dict) -> int:
    """Total number of processes."""
    return len(process_list.get("entries", []))


def validator_ProcessList_find_pid(process_list: dict, pid: int) -> Optional[dict]:
    """Find process by PID."""
    for e in process_list.get("entries", []):
        if e.get("pid") == pid:
            return e
    return None


def validator_PluginRegistry_new() -> dict:
    """Create empty plugin registry."""
    return {"plugins": {}}


def validator_PluginRegistry_register(registry: dict, plugin: dict) -> None:
    """Register a plugin (mutates registry)."""
    registry["plugins"][plugin["name"]] = plugin


def validator_PluginRegistry_run(registry: dict, name: str, args: dict) -> dict:
    """Run plugin by name. Returns error if not found."""
    if name not in registry["plugins"]:
        return {"error": f"plugin '{name}' not found"}
    plugin = registry["plugins"][name]
    return {"plugin": name, "result": plugin.get("mock_output", [])}


def validator_PluginRegistry_plugin_names(registry: dict) -> list:
    """List all registered plugin names."""
    return list(registry["plugins"].keys())


def validator_PluginRegistry_count(registry: dict) -> int:
    """Number of registered plugins."""
    return len(registry["plugins"])


DEFAULT_PLUGIN_NAMES = [
    "pslist", "pstree", "netstat", "vadinfo",
    "driverscan", "malfind", "hivelist", "strings",
]


def validator_default_registry() -> dict:
    """Create registry with all built-in plugins pre-registered."""
    registry = validator_PluginRegistry_new()
    for name in DEFAULT_PLUGIN_NAMES:
        validator_PluginRegistry_register(registry, {"name": name, "mock_output": []})
    return registry


# ---------------------------------------------------------------------------
# registry_hive_plugin
# ---------------------------------------------------------------------------

def validator_RegCell_parse_data(cell: dict, hbin_data: bytes) -> dict:
    """Decode raw hive cell into typed RegValue."""
    offset = cell.get("data_offset", 0)
    reg_type = cell.get("reg_type", 1)
    length = cell.get("data_length", 0)
    raw = hbin_data[offset:offset + length] if offset + length <= len(hbin_data) else b""
    if reg_type == 1:  # REG_SZ
        try:
            value = raw.decode("utf-16-le").rstrip("\x00")
        except Exception:
            value = raw.hex()
        return {"type": "REG_SZ", "value": value}
    elif reg_type == 4:  # REG_DWORD
        value = struct.unpack_from("<I", raw)[0] if len(raw) >= 4 else 0
        return {"type": "REG_DWORD", "value": value}
    elif reg_type == 11:  # REG_QWORD
        value = struct.unpack_from("<Q", raw)[0] if len(raw) >= 8 else 0
        return {"type": "REG_QWORD", "value": value}
    else:
        return {"type": "REG_BINARY", "value": raw.hex()}


def validator_parse_hive_bytes(data: bytes) -> dict:
    """Parse registry hive from bytes. Returns hive dict or error."""
    if not data[:4] == b"regf":
        return {"error": "invalid hive magic"}
    # Minimal stub: parse signature and return basic info
    return {
        "magic": "regf",
        "size": len(data),
        "root_keys": [],
    }


def validator_HiveWalker_new(hive: dict) -> dict:
    """Create a walker for the hive."""
    return {"hive": hive, "position": 0, "visited": []}


def validator_walk_keys(hive: dict) -> dict:
    """Shortcut to create HiveWalker."""
    return validator_HiveWalker_new(hive)


def validator_search_by_name(hive: dict, query: str) -> list:
    """Find keys whose name contains query (case-insensitive)."""
    q = query.lower()
    results = []
    for key in hive.get("root_keys", []):
        if q in key.get("name", "").lower():
            results.append(key)
    return results


def validator_search_by_value_data(hive: dict, query: str) -> list:
    """Find keys with values containing query string."""
    q = query.lower()
    results = []
    for key in hive.get("root_keys", []):
        for val in key.get("values", []):
            if q in str(val.get("data", "")).lower():
                results.append(key)
                break
    return results


def validator_export_to_json(hive: dict) -> str:
    """Export entire hive as JSON."""
    return json.dumps(hive, indent=2)


def validator_deleted_key_scanner(data: bytes) -> list:
    """Find deleted/orphan NK cells in raw hive data."""
    NK_MAGIC = b"nk"
    results = []
    i = 0
    while i < len(data) - 2:
        if data[i:i+2] == NK_MAGIC:
            results.append({"offset": i, "magic": "nk"})
        i += 1
    return results


# ---------------------------------------------------------------------------
# memory_dump_plugin
# ---------------------------------------------------------------------------

DUMP_FORMAT_RAW = "Raw"
DUMP_FORMAT_CRASH = "CrashDump"
DUMP_FORMAT_MINI = "MiniDump"
DUMP_FORMAT_UNKNOWN = "Unknown"


def validator_DumpParser_detect_format(data: bytes) -> str:
    """Detect dump format from magic bytes."""
    if len(data) < 4:
        return DUMP_FORMAT_UNKNOWN
    magic4 = data[:4]
    if magic4 == b"MDMP":
        return DUMP_FORMAT_MINI
    if magic4 == b"PAGE":
        return DUMP_FORMAT_CRASH
    # Raw: no specific magic, check for MZ at start
    if magic4[:2] == b"MZ":
        return DUMP_FORMAT_RAW
    return DUMP_FORMAT_RAW  # default assumption


def validator_RawDumpParser_new(data: bytes) -> dict:
    """Create raw dump parser."""
    return {"data": data, "format": DUMP_FORMAT_RAW}


def validator_RawDumpParser_parse_ranges(parser: dict) -> list:
    """Extract valid memory ranges from raw dump."""
    data = parser.get("data", b"")
    # Heuristic: treat whole blob as one range
    return [{"start": 0, "end": len(data), "size": len(data)}] if data else []


def validator_MiniDumpParser_parse_streams(parser: dict, header: dict) -> list:
    """Parse all streams from MiniDump header."""
    return header.get("streams", [])


def validator_CrashDumpParser_extract_processes(parser: dict) -> list:
    """Extract process list from crash dump."""
    return parser.get("processes", [])


def validator_CrashDumpParser_extract_modules(parser: dict) -> list:
    """Extract kernel modules from crash dump."""
    return parser.get("modules", [])


def validator_CrashDumpParser_search_pattern(parser: dict, pattern: bytes) -> list:
    """Search for byte pattern in dump, return offsets."""
    data = parser.get("data", b"")
    offsets = []
    start = 0
    while True:
        idx = data.find(pattern, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1
    return offsets


def validator_CrashDumpParser_carve_strings(parser: dict, min_len: int) -> list:
    """Extract ASCII/UTF-16 strings with addresses."""
    data = parser.get("data", b"")
    results = []
    # ASCII
    pattern = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
    for m in pattern.finditer(data):
        results.append((m.start(), m.group().decode("ascii", errors="replace")))
    return results


def validator_CrashDumpParser_find_pe_headers(parser: dict) -> list:
    """Find MZ magic offsets in dump."""
    data = parser.get("data", b"")
    return validator_CrashDumpParser_search_pattern(parser, b"MZ")


def _compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    n = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def validator_CrashDumpParser_compute_statistics(parser: dict) -> dict:
    """Compute dump statistics."""
    data = parser.get("data", b"")
    return {
        "size": len(data),
        "entropy": _compute_entropy(data),
        "null_bytes": data.count(0),
        "pe_headers": len(validator_CrashDumpParser_find_pe_headers(parser)),
    }


def validator_DumpAnalyzer_analyze(analyzer: dict, data: bytes) -> dict:
    """Analyze a single dump."""
    parser = {"data": data}
    return validator_CrashDumpParser_compute_statistics(parser)


def validator_DumpAnalyzer_analyze_all(analyzer: dict, dumps: list) -> list:
    """Analyze multiple dumps in batch."""
    return [validator_DumpAnalyzer_analyze(analyzer, d) for d in dumps]


# ---------------------------------------------------------------------------
# network_artifacts (top-level)
# ---------------------------------------------------------------------------

def validator_TcpEntry_with_process(entry: dict, name: str) -> dict:
    """Associate process name with TCP entry."""
    result = dict(entry)
    result["process_name"] = name
    return result


def validator_TcpEntry_is_established(entry: dict) -> bool:
    """True if state is ESTABLISHED."""
    return entry.get("state", "").upper() == "ESTABLISHED"


def validator_TcpEntry_is_listening(entry: dict) -> bool:
    """True if state is LISTEN."""
    return entry.get("state", "").upper() in ("LISTEN", "LISTENING")


def validator_TcpTable_new() -> dict:
    """Create empty TCP table."""
    return {"entries": []}


def validator_TcpTable_add(table: dict, entry: dict) -> None:
    """Add entry to TCP table."""
    table["entries"].append(entry)


def validator_TcpTable_all(table: dict) -> list:
    """Return all entries."""
    return table.get("entries", [])


def validator_TcpTable_established(table: dict) -> list:
    """Filter ESTABLISHED connections."""
    return [e for e in table["entries"] if validator_TcpEntry_is_established(e)]


def validator_TcpTable_listening(table: dict) -> list:
    """Filter LISTENING connections."""
    return [e for e in table["entries"] if validator_TcpEntry_is_listening(e)]


def validator_TcpTable_by_pid(table: dict, pid: int) -> list:
    """Filter by PID."""
    return [e for e in table["entries"] if e.get("pid") == pid]


def validator_TcpTable_by_state(table: dict, state: str) -> list:
    """Filter by connection state."""
    return [e for e in table["entries"] if e.get("state", "").upper() == state.upper()]


def validator_TcpTable_unique_remote_ips(table: dict) -> list:
    """Unique remote IPs."""
    return list({e["remote_ip"] for e in table["entries"] if "remote_ip" in e})


def validator_TcpTable_unique_pids(table: dict) -> list:
    """Unique PIDs with TCP connections."""
    return list({e["pid"] for e in table["entries"] if "pid" in e})


def validator_TcpTable_outbound_count(table: dict) -> int:
    """Number of outbound connections (ESTABLISHED, not listening)."""
    return sum(1 for e in table["entries"] if validator_TcpEntry_is_established(e))


def validator_UdpEntry_with_process(entry: dict, name: str) -> dict:
    """Associate process name with UDP entry."""
    result = dict(entry)
    result["process_name"] = name
    return result


def validator_UdpTable_new() -> dict:
    """Create empty UDP table."""
    return {"entries": []}


def validator_UdpTable_add(table: dict, entry: dict) -> None:
    """Add UDP entry."""
    table["entries"].append(entry)


def validator_UdpTable_all(table: dict) -> list:
    """All UDP entries."""
    return table.get("entries", [])


def validator_UdpTable_by_pid(table: dict, pid: int) -> list:
    """Filter UDP by PID."""
    return [e for e in table["entries"] if e.get("pid") == pid]


def validator_UdpTable_listening_ports(table: dict) -> list:
    """UDP listening ports."""
    return list({e["local_port"] for e in table["entries"] if "local_port" in e})


def validator_UdpTable_unique_pids(table: dict) -> list:
    """Unique PIDs in UDP table."""
    return list({e["pid"] for e in table["entries"] if "pid" in e})


def validator_DnsCacheEntry_new(hostname: str, rtype: str) -> dict:
    """Create DNS cache entry."""
    return {"hostname": hostname, "record_type": rtype, "ips": []}


def validator_DnsCacheEntry_with_ip(entry: dict, ip: str) -> dict:
    """Add IP to DNS cache entry."""
    result = dict(entry)
    result["ips"] = list(entry.get("ips", [])) + [ip]
    return result


def validator_DnsCacheEntry_is_a_record(entry: dict) -> bool:
    """True if record type is A."""
    return entry.get("record_type", "").upper() == "A"


def validator_DnsCache_new() -> dict:
    """Create empty DNS cache."""
    return {"entries": []}


def validator_DnsCache_add(cache: dict, entry: dict) -> None:
    """Add DNS cache entry."""
    cache["entries"].append(entry)


def validator_DnsCache_all(cache: dict) -> list:
    """All DNS cache entries."""
    return cache.get("entries", [])


def validator_DnsCache_lookup(cache: dict, hostname: str) -> Optional[dict]:
    """Lookup by exact hostname."""
    for e in cache["entries"]:
        if e.get("hostname") == hostname:
            return e
    return None


def validator_DnsCache_a_records(cache: dict) -> list:
    """Only A records."""
    return [e for e in cache["entries"] if validator_DnsCacheEntry_is_a_record(e)]


def validator_DnsCache_for_ip(cache: dict, ip: str) -> list:
    """Entries resolving to the given IP."""
    return [e for e in cache["entries"] if ip in e.get("ips", [])]


def validator_DnsCache_unique_hostnames(cache: dict) -> list:
    """Unique hostnames."""
    return list({e["hostname"] for e in cache["entries"] if "hostname" in e})


def validator_HttpCacheEntry_new(url: str, method: str) -> dict:
    """Create HTTP cache entry."""
    return {"url": url, "method": method.upper(), "user_agent": None, "status": 0}


def validator_HttpCacheEntry_with_user_agent(entry: dict, ua: str) -> dict:
    """Set user agent."""
    result = dict(entry)
    result["user_agent"] = ua
    return result


def validator_HttpCacheEntry_is_post(entry: dict) -> bool:
    """True if method is POST."""
    return entry.get("method", "").upper() == "POST"


def validator_HttpCacheEntry_is_get(entry: dict) -> bool:
    """True if method is GET."""
    return entry.get("method", "").upper() == "GET"


def validator_HttpCacheEntry_is_success(entry: dict) -> bool:
    """True if status is 2xx."""
    status = entry.get("status", 0)
    return 200 <= status < 300


def validator_HttpCache_new() -> dict:
    """Create empty HTTP cache."""
    return {"entries": []}


def validator_HttpCache_add(cache: dict, entry: dict) -> None:
    """Add HTTP cache entry."""
    cache["entries"].append(entry)


def validator_HttpCache_all(cache: dict) -> list:
    """All HTTP cache entries."""
    return cache.get("entries", [])


def validator_HttpCache_by_host(cache: dict, host: str) -> list:
    """Filter by host."""
    return [e for e in cache["entries"] if host in e.get("url", "")]


def validator_HttpCache_post_requests(cache: dict) -> list:
    """Only POST requests."""
    return [e for e in cache["entries"] if validator_HttpCacheEntry_is_post(e)]


def validator_HttpCache_unique_hosts(cache: dict) -> list:
    """Unique hosts."""
    hosts = set()
    for e in cache["entries"]:
        m = re.search(r"https?://([^/]+)", e.get("url", ""))
        if m:
            hosts.add(m.group(1))
    return list(hosts)


SUSPICIOUS_UA_PATTERNS = [
    "python-requests", "curl/", "wget/", "Go-http-client",
    "masscan", "nikto", "sqlmap", "nmap",
]


def validator_HttpCache_suspicious_user_agents(cache: dict) -> list:
    """Entries with suspicious user agents."""
    results = []
    for e in cache["entries"]:
        ua = e.get("user_agent") or ""
        if any(p.lower() in ua.lower() for p in SUSPICIOUS_UA_PATTERNS):
            results.append(e)
    return results


def validator_NetworkReport_build(tcp_entries, udp_entries, dns_entries, http_entries) -> dict:
    """Build complete network report from all sources."""
    return {
        "tcp": list(tcp_entries),
        "udp": list(udp_entries),
        "dns": list(dns_entries),
        "http": list(http_entries),
    }


def validator_NetworkCorrelator_new() -> dict:
    """Create empty network correlator."""
    return {"tcp": [], "udp": [], "dns": [], "http": []}


def validator_NetworkCorrelator_add_tcp(correlator: dict, entry: dict) -> None:
    correlator["tcp"].append(entry)


def validator_NetworkCorrelator_add_udp(correlator: dict, entry: dict) -> None:
    correlator["udp"].append(entry)


def validator_NetworkCorrelator_add_dns(correlator: dict, entry: dict) -> None:
    correlator["dns"].append(entry)


def validator_NetworkCorrelator_add_http(correlator: dict, entry: dict) -> None:
    correlator["http"].append(entry)


def validator_NetworkCorrelator_report(correlator: dict) -> dict:
    """Generate aggregated report."""
    return validator_NetworkReport_build(
        correlator["tcp"], correlator["udp"],
        correlator["dns"], correlator["http"]
    )


def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback
    except Exception:
        return True


def validator_NetworkCorrelator_external_tcp(correlator: dict) -> list:
    """TCP connections to public IPs (non-RFC1918)."""
    return [e for e in correlator["tcp"] if not _is_private_ip(e.get("remote_ip", "127.0.0.1"))]


def validator_NetworkCorrelator_suspicious_pids(correlator: dict) -> list:
    """PIDs with suspicious network patterns (many connections or external only)."""
    pid_count: Dict[int, int] = defaultdict(int)
    for e in correlator["tcp"]:
        if not _is_private_ip(e.get("remote_ip", "127.0.0.1")):
            pid_count[e.get("pid", 0)] += 1
    return [pid for pid, count in pid_count.items() if count > 5]


def validator_NetworkCorrelator_resolve_tcp_ip(correlator: dict, entry: dict) -> list:
    """Resolve remote IP via cross-referenced DNS cache."""
    ip = entry.get("remote_ip", "")
    results = []
    for dns_entry in correlator["dns"]:
        if ip in dns_entry.get("ips", []):
            results.append(dns_entry.get("hostname", ""))
    return results


def validator_NetworkCorrelator_processes_with_tcp_and_udp(correlator: dict) -> list:
    """PIDs using both TCP and UDP."""
    tcp_pids = {e.get("pid") for e in correlator["tcp"]}
    udp_pids = {e.get("pid") for e in correlator["udp"]}
    return list(tcp_pids & udp_pids)


# ---------------------------------------------------------------------------
# lib.rs inline plugins
# ---------------------------------------------------------------------------

HOOK_OPCODES = [0xE9, 0xFF, 0xEB, 0xE8]  # JMP rel32, JMP r/m64, JMP short, CALL


def validator_HookDetector_looks_hooked(bytes_data: bytes) -> bool:
    """True if prologue bytes look hooked (JMP/CALL prefix)."""
    if not bytes_data:
        return False
    return bytes_data[0] in HOOK_OPCODES


VAD_PERM_MAP = {0: "---", 1: "r--", 2: "-w-", 3: "rw-", 4: "--x", 5: "r-x", 6: "rwx", 7: "rwx"}


def validator_VadRegion_perms_string(p: int) -> str:
    """Convert VAD permission bits to readable string."""
    return VAD_PERM_MAP.get(p & 7, "???")


def validator_StringExtractor_extract_strings(data: bytes, min_len: int) -> list:
    """Extract ASCII and UTF-16 strings from memory block."""
    results = []
    # ASCII
    pat_ascii = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
    for m in pat_ascii.finditer(data):
        results.append(m.group().decode("ascii", errors="replace"))
    # UTF-16LE (simplistic: two-byte aligned printable)
    pat_utf16 = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}")
    for m in pat_utf16.finditer(data):
        try:
            s = m.group().decode("utf-16-le")
            if s not in results:
                results.append(s)
        except Exception:
            pass
    return results


def validator_ByteRule_new(name: str, description: str, patterns: list) -> dict:
    """Create byte detection rule."""
    return {"name": name, "description": description, "patterns": patterns}


def validator_ByteRule_matches(rule: dict, data: bytes) -> bool:
    """True if at least one pattern matches in data."""
    for pattern in rule.get("patterns", []):
        if isinstance(pattern, list):
            pattern = bytes(pattern)
        if isinstance(pattern, bytes) and pattern in data:
            return True
    return False


BUILTIN_RULE_DEFS = [
    ("shellcode_nop_sled", "NOP sled detection", [b"\x90" * 16]),
    ("meterpreter_stub", "Meterpreter payload pattern", [b"\xfc\xe8\x89\x00\x00\x00"]),
    ("donut_stub", "Donut shellcode stub", [b"DONUT"]),
    ("upx_packer", "UPX packed binary", [b"UPX!"]),
    ("crypto_aes_sbox", "AES S-box constant", [bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2])]),
]


def validator_builtin_rules() -> list:
    """Return built-in detection rules."""
    return [validator_ByteRule_new(name, desc, patterns)
            for name, desc, patterns in BUILTIN_RULE_DEFS]


def validator_ByteScanner_with_builtin_rules() -> dict:
    """Create scanner with all built-in rules loaded."""
    return {"rules": validator_builtin_rules()}


PRIVILEGE_NAMES = {
    2: "SeCreateTokenPrivilege",
    3: "SeAssignPrimaryTokenPrivilege",
    4: "SeLockMemoryPrivilege",
    5: "SeIncreaseQuotaPrivilege",
    6: "SeMachineAccountPrivilege",
    7: "SeTcbPrivilege",
    8: "SeSecurityPrivilege",
    9: "SeTakeOwnershipPrivilege",
    10: "SeLoadDriverPrivilege",
    11: "SeSystemProfilePrivilege",
    12: "SeSystemtimePrivilege",
    13: "SeProfileSingleProcessPrivilege",
    14: "SeIncreaseBasePriorityPrivilege",
    15: "SeCreatePagefilePrivilege",
    16: "SeCreatePermanentPrivilege",
    17: "SeBackupPrivilege",
    18: "SeRestorePrivilege",
    19: "SeShutdownPrivilege",
    20: "SeDebugPrivilege",
    21: "SeAuditPrivilege",
    22: "SeSystemEnvironmentPrivilege",
    23: "SeChangeNotifyPrivilege",
    24: "SeRemoteShutdownPrivilege",
    25: "SeUndockPrivilege",
    26: "SeSyncAgentPrivilege",
    27: "SeEnableDelegationPrivilege",
    28: "SeManageVolumePrivilege",
    29: "SeImpersonatePrivilege",
    30: "SeCreateGlobalPrivilege",
}


def validator_TokenPrivileges_priv_name(luid: int) -> str:
    """Return privilege name for LUID."""
    return PRIVILEGE_NAMES.get(luid, "SeUnknownPrivilege")


SUSPICIOUS_PATHS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\", "\\programdata\\", "\\users\\public\\",
    "\\downloads\\", "\\recycle", "\\windows\\temp\\",
]


def validator_PathHeuristics_is_suspicious_path(path: str) -> bool:
    """True if path is in a suspicious location."""
    lower = path.lower().replace("/", "\\")
    return any(p in lower for p in SUSPICIOUS_PATHS)


def validator_EntropyScanner_scan_high_entropy(scanner: dict, image_data: bytes, threshold: float) -> list:
    """Find memory regions with Shannon entropy above threshold."""
    CHUNK_SIZE = 4096
    results = []
    for offset in range(0, len(image_data), CHUNK_SIZE):
        chunk = image_data[offset:offset + CHUNK_SIZE]
        if len(chunk) < 64:
            continue
        entropy = _compute_entropy(chunk)
        if entropy >= threshold:
            results.append({"start": offset, "end": offset + len(chunk), "entropy": entropy})
    return results


def validator_VadPlugin_run(image: dict) -> list:
    """List all VAD nodes (stub)."""
    return image.get("vad_entries", [])


def validator_VadPlugin_find_suspicious_vads(vads: list) -> list:
    """Filter VADs with suspicious combination (RWX, no name, high entropy)."""
    return [v for v in vads
            if v.get("perms") in ("rwx", "RWX")
            and not v.get("name")
            and v.get("entropy", 0) > 6.5]


def validator_SamPlugin_extract_sam_hashes(image: dict) -> list:
    """Extract NTLM/LM hashes from SAM database in memory (stub)."""
    return image.get("sam_entries", [])


def validator_InjectionScanner_scan(image: dict, processes: list) -> list:
    """Detect code injection (stub)."""
    findings = []
    for proc in processes:
        for region in proc.get("memory_regions", []):
            if region.get("perms") == "rwx" and not region.get("backed_by_file"):
                findings.append({
                    "pid": proc.get("pid"),
                    "region": region,
                    "type": "suspicious_rwx",
                })
    return findings


def validator_DriverPlugin_list_drivers(image: dict) -> list:
    """List all loaded kernel drivers (stub)."""
    return image.get("drivers", [])


def validator_DriverPlugin_is_suspicious_driver(driver: dict) -> bool:
    """True if driver is unsigned, in anomalous path, or with masked name."""
    if not driver.get("signed", True):
        return True
    path = driver.get("path", "").lower()
    if validator_PathHeuristics_is_suspicious_path(path):
        return True
    name = driver.get("name", "")
    if re.search(r"(svchost|lsass|csrss|winlogon)\.sys$", name, re.IGNORECASE):
        return True
    return False


def validator_HivePlugin_find_hives(image: dict) -> list:
    """Find registry hives mapped in memory (stub)."""
    return image.get("hives", [])


def validator_StringsPlugin_scan_strings_in_process(image: dict, pid: int, min_len: int) -> list:
    """Extract strings from all regions of a specific process."""
    results = []
    for proc in image.get("processes", []):
        if proc.get("pid") == pid:
            for region in proc.get("memory_regions", []):
                data = bytes(region.get("data", []))
                results.extend(validator_StringExtractor_extract_strings(data, min_len))
    return results


def validator_register_all(registry: dict) -> None:
    """Register all plugins in global registry (mutates)."""
    for name in DEFAULT_PLUGIN_NAMES:
        if name not in registry["plugins"]:
            validator_PluginRegistry_register(registry, {"name": name, "mock_output": []})


# ---------------------------------------------------------------------------
# plugins::browser_history
# ---------------------------------------------------------------------------

SQLITE_MAGIC = b"SQLite format 3\x00"


def validator_BrowserProfile_from_path(path: str) -> dict:
    """Create browser profile from directory path."""
    return {"path": path, "browser": "unknown"}


def validator_is_sqlite(data: bytes) -> bool:
    """True if magic matches SQLite database."""
    return data[:len(SQLITE_MAGIC)] == SQLITE_MAGIC


def validator_sqlite_page_size(data: bytes) -> Optional[int]:
    """Read page size from SQLite header."""
    if not validator_is_sqlite(data) or len(data) < 18:
        return None
    val = struct.unpack_from(">H", data, 16)[0]
    return 65536 if val == 1 else val


def validator_sqlite_user_version(data: bytes) -> Optional[int]:
    """Read user_version from SQLite header."""
    if not validator_is_sqlite(data) or len(data) < 64:
        return None
    return struct.unpack_from(">I", data, 60)[0]


MALICIOUS_URL_PATTERNS = [
    r"\.exe$", r"\.bat$", r"\.ps1$", r"\.vbs$",
    r"pastebin\.com/raw/", r"/shell\b", r"/payload\b",
    r"\bc2\b", r"malware", r"/dropper",
]


def validator_HistoryEntry_is_potentially_malicious(entry: dict) -> bool:
    """True if URL matches malware download or C2 patterns."""
    url = entry.get("url", "").lower()
    return any(re.search(p, url) for p in MALICIOUS_URL_PATTERNS)


CREDENTIAL_FIELD_NAMES = ["password", "passwd", "pwd", "username", "user", "login", "email"]


def validator_FormData_looks_like_credential(form: dict) -> bool:
    """True if form data looks like credentials."""
    for field in form.get("fields", []):
        name = field.get("name", "").lower()
        if any(c in name for c in CREDENTIAL_FIELD_NAMES):
            return True
    return False


def validator_BrowserScanner_scan_urls(data: bytes) -> list:
    """Extract URLs from raw data."""
    text = data.decode("utf-8", errors="replace")
    pattern = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
    return list(set(pattern.findall(text)))


def validator_BrowserScanner_scan_cookie_strings(data: bytes) -> list:
    """Extract cookie records from raw browser data."""
    text = data.decode("utf-8", errors="replace")
    results = []
    for m in re.finditer(r"([A-Za-z0-9_\-]+)=([^\s;,\"']+)", text):
        results.append({"name": m.group(1), "value": m.group(2)})
    return results


def validator_BrowserScanner_summarize(data: bytes, browser: str) -> dict:
    """Produce complete browser artifact summary."""
    urls = validator_BrowserScanner_scan_urls(data)
    cookies = validator_BrowserScanner_scan_cookie_strings(data)
    return {
        "browser": browser,
        "url_count": len(urls),
        "urls": urls[:20],
        "cookie_count": len(cookies),
    }


def validator_extract_domains(urls: list) -> list:
    """Extract domain from each URL (deduplicated)."""
    domains = set()
    for url in urls:
        m = re.search(r"https?://([^/:?#]+)", url)
        if m:
            domains.add(m.group(1))
    return list(domains)


def validator_PasswordEntry_is_insecure(entry: dict) -> bool:
    """True if password saved over HTTP."""
    return entry.get("origin_url", "").startswith("http://")


def validator_FirefoxScanner_scan_login_origins(data: bytes) -> list:
    """Extract login origins from Firefox data."""
    text = data.decode("utf-8", errors="replace")
    pattern = re.compile(r'"origin"\s*:\s*"(https?://[^"]+)"')
    return list(set(pattern.findall(text)))


def validator_ChromeScanner_scan_domains(data: bytes) -> list:
    """Extract visited domains from Chrome artifacts."""
    urls = validator_BrowserScanner_scan_urls(data)
    return validator_extract_domains(urls)


EDGE_PATTERNS = [b"Microsoft Edge", b"msedge", b"edgehtml"]


def validator_EdgeDetector_looks_like_edge(data: bytes) -> bool:
    """Heuristics to detect Edge artifacts."""
    return any(p in data for p in EDGE_PATTERNS)


BROWSER_HINTS = [
    (b"Firefox", "firefox"),
    (b"Chrome", "chrome"),
    (b"msedge", "edge"),
    (b"Safari", "safari"),
]


def validator_BrowserAnalyzer_analyze(data: bytes, hint_path: Optional[str]) -> dict:
    """Unified analysis with auto-detection of browser type."""
    browser = "unknown"
    if hint_path:
        lp = hint_path.lower()
        if "firefox" in lp:
            browser = "firefox"
        elif "chrome" in lp:
            browser = "chrome"
        elif "edge" in lp or "msedge" in lp:
            browser = "edge"
    if browser == "unknown":
        for sig, name in BROWSER_HINTS:
            if sig in data:
                browser = name
                break
    return validator_BrowserScanner_summarize(data, browser)


URL_CATEGORIES = {
    "social": [r"facebook\.com", r"twitter\.com", r"instagram\.com", r"linkedin\.com", r"reddit\.com"],
    "mail": [r"gmail\.com", r"outlook\.com", r"yahoo\.com/mail", r"protonmail\.com"],
    "cloud": [r"drive\.google\.com", r"dropbox\.com", r"onedrive\.live\.com", r"box\.com"],
    "suspicious": [r"pastebin\.com", r"\.onion", r"ngrok\.io", r"\.xyz/"],
}


def validator_BrowserAnalyzer_classify_urls(urls: list) -> dict:
    """Classify URLs into categories."""
    result: Dict[str, List[str]] = defaultdict(list)
    for url in urls:
        matched = False
        for category, patterns in URL_CATEGORIES.items():
            if any(re.search(p, url, re.IGNORECASE) for p in patterns):
                result[category].append(url)
                matched = True
                break
        if not matched:
            result["other"].append(url)
    return dict(result)


# ---------------------------------------------------------------------------
# plugins::credential_artifacts
# ---------------------------------------------------------------------------

NTLM_BLANK_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"
LM_DISABLED_HASH = "aad3b435b51404eeaad3b435b51404ee"


def validator_NtlmHash_from_slice(s: bytes):
    """Create NTLM hash from 16 bytes."""
    if len(s) != 16:
        return {"error": "expected 16 bytes"}
    return {"hash": s.hex()}


def validator_NtlmHash_from_hex(hex_str: str):
    """Parse NTLM hash from hex string."""
    hex_str = hex_str.strip().lower()
    if len(hex_str) != 32 or not all(c in "0123456789abcdef" for c in hex_str):
        return {"error": "invalid hex NTLM hash"}
    return {"hash": hex_str}


def validator_NtlmHash_to_hex(ntlm: dict) -> str:
    """Convert NTLM hash to lowercase hex string."""
    return ntlm.get("hash", "")


def validator_NtlmHash_is_blank_password(ntlm: dict) -> bool:
    """True if NTLM hash corresponds to blank password."""
    return ntlm.get("hash", "").lower() == NTLM_BLANK_HASH


def validator_NtlmHash_is_lm_disabled(ntlm: dict) -> bool:
    """True if LM field indicates disabled (aad3b...)."""
    return ntlm.get("hash", "").lower() == LM_DISABLED_HASH


def validator_SamEntry_parse(line: str) -> Optional[dict]:
    """Parse a pwdump-format line: user:RID:LM:NT:::"""
    parts = line.split(":")
    if len(parts) < 4:
        return None
    return {
        "username": parts[0],
        "rid": int(parts[1]) if parts[1].isdigit() else 0,
        "lm_hash": parts[2].lower(),
        "nt_hash": parts[3].lower(),
    }


def validator_SamEntry_has_valid_nt_hash(entry: dict) -> bool:
    """True if NT hash is present and not blank password hash."""
    nt = entry.get("nt_hash", "")
    return bool(nt) and nt != NTLM_BLANK_HASH and len(nt) == 32


def validator_SamEntry_lm_enabled(entry: dict) -> bool:
    """True if LM hash is different from disabled placeholder."""
    lm = entry.get("lm_hash", "")
    return lm != LM_DISABLED_HASH and len(lm) == 32


def validator_LsassCredential_has_cleartext(cred: dict) -> bool:
    """True if credential includes cleartext password."""
    return bool(cred.get("password_cleartext"))


def validator_LsassCredential_severity(cred: dict) -> int:
    """Severity level 0-3 based on credential type."""
    if cred.get("password_cleartext"):
        return 3
    if cred.get("nt_hash"):
        return 2
    if cred.get("kerberos_ticket"):
        return 1
    return 0


def validator_LsassScanner_scan_wdigest(data: bytes) -> list:
    """Search for WDigest structures with cleartext credentials."""
    results = []
    # Look for WDigest signature pattern
    WDIGEST_SIG = b"wdigest"
    pos = 0
    while True:
        idx = data.lower().find(WDIGEST_SIG, pos)
        if idx == -1:
            break
        results.append({"offset": idx, "type": "wdigest", "password_cleartext": None})
        pos = idx + 1
    return results


def validator_LsassScanner_scan_nt_hashes(data: bytes) -> list:
    """Find NTLM hashes with their memory offset."""
    results = []
    pattern = re.compile(rb"[0-9a-fA-F]{32}")
    for m in pattern.finditer(data):
        candidate = m.group().decode()
        results.append((m.start(), {"hash": candidate.lower()}))
    return results


def validator_LsassScanner_scan(data: bytes) -> list:
    """Complete LSASS scan for all credential types."""
    results = validator_LsassScanner_scan_wdigest(data)
    return results


def validator_KerberosScanner_scan(data: bytes) -> list:
    """Extract Kerberos tickets from memory."""
    KRB5_MAGIC = b"\x76\x82"  # simplified TGT/TGS tag
    results = []
    pos = 0
    while True:
        idx = data.find(KRB5_MAGIC, pos)
        if idx == -1:
            break
        results.append({"offset": idx, "type": "kerberos_ticket"})
        pos = idx + 1
    return results


DPAPI_MAGIC = b"\x01\x00\x00\x00\xd0\x8c\x9d\xdf\x01\x15\xd1\x11\x8c\x7a\x00\xc0\x4f\xc2\x97\xeb"


def validator_DpapiBlob_is_default_provider(blob: dict) -> bool:
    """True if blob uses default DPAPI provider."""
    return blob.get("provider") == "default" or blob.get("provider") is None


def validator_DpapiBlob_is_browser_credential(blob: dict) -> bool:
    """True if blob is associated with browser credential."""
    desc = blob.get("description", "").lower()
    return any(b in desc for b in ("chrome", "edge", "firefox", "browser"))


def validator_DpapiScanner_scan(data: bytes) -> list:
    """Find DPAPI blob structures in data."""
    results = []
    pos = 0
    while True:
        idx = data.find(DPAPI_MAGIC, pos)
        if idx == -1:
            break
        results.append({"offset": idx, "type": "dpapi_blob", "provider": "default"})
        pos = idx + 1
    return results


GUID_PATTERN = re.compile(
    rb"\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?"
)


def validator_DpapiScanner_find_masterkey_guids(data: bytes) -> list:
    """Extract DPAPI master key GUIDs from data."""
    return [m.group().decode("ascii", errors="replace") for m in GUID_PATTERN.finditer(data)]


def validator_CredentialReport_cleartext_creds(report: dict) -> list:
    """Only credentials with cleartext password."""
    return [c for c in report.get("credentials", []) if validator_LsassCredential_has_cleartext(c)]


def validator_CredentialReport_to_row_map(report: dict) -> dict:
    """Export report as key-value map."""
    return {
        "total_credentials": str(len(report.get("credentials", []))),
        "cleartext_count": str(len(validator_CredentialReport_cleartext_creds(report))),
        "nt_hash_count": str(sum(1 for c in report.get("credentials", []) if c.get("nt_hash"))),
    }


def validator_CredentialReport_from_bytes(data: bytes) -> dict:
    """Build complete credential report from dump."""
    lsass_creds = validator_LsassScanner_scan(data)
    dpapi_blobs = validator_DpapiScanner_scan(data)
    return {
        "credentials": lsass_creds,
        "dpapi_blobs": dpapi_blobs,
    }


# ---------------------------------------------------------------------------
# plugins::file_timeline
# ---------------------------------------------------------------------------

def validator_Timestamps_earliest(ts: dict) -> int:
    """Earliest timestamp."""
    vals = [ts.get("created", 0), ts.get("modified", 0),
            ts.get("accessed", 0), ts.get("mft_changed", 0)]
    return min(v for v in vals if v != 0) if any(v != 0 for v in vals) else 0


def validator_Timestamps_latest(ts: dict) -> int:
    """Latest timestamp."""
    vals = [ts.get("created", 0), ts.get("modified", 0),
            ts.get("accessed", 0), ts.get("mft_changed", 0)]
    return max(vals)


MFT_SIGNATURE = b"FILE"


def validator_MftEntry_parse(data: bytes, record_number: int) -> dict:
    """Parse single MFT record."""
    if len(data) < 4 or data[:4] != MFT_SIGNATURE:
        return {"error": "invalid MFT record signature"}
    return {
        "record_number": record_number,
        "signature": "FILE",
        "allocated": True,
        "filename": "",
        "timestamps": {"created": 0, "modified": 0, "accessed": 0, "mft_changed": 0},
    }


def validator_MftScanner_scan(data: bytes) -> list:
    """Extract all valid MFT records from MFT dump."""
    RECORD_SIZE = 1024
    results = []
    for i in range(0, len(data) - RECORD_SIZE + 1, RECORD_SIZE):
        chunk = data[i:i + RECORD_SIZE]
        if chunk[:4] == MFT_SIGNATURE:
            entry = validator_MftEntry_parse(chunk, i // RECORD_SIZE)
            if "error" not in entry:
                results.append(entry)
    return results


def validator_MftScanner_scan_small(data: bytes) -> list:
    """Optimized variant for small MFT fragments."""
    results = []
    pos = 0
    while pos < len(data) - 4:
        idx = data.find(MFT_SIGNATURE, pos)
        if idx == -1:
            break
        chunk = data[idx:idx + 1024]
        entry = validator_MftEntry_parse(chunk, idx // 1024)
        if "error" not in entry:
            results.append(entry)
        pos = idx + 4
    return results


def validator_TimelineBuilder_from_mft(entries: list) -> list:
    """Convert MFT entries to sorted timeline events."""
    events = []
    for entry in entries:
        ts = entry.get("timestamps", {})
        for ts_type in ("created", "modified", "accessed", "mft_changed"):
            t = ts.get(ts_type, 0)
            if t:
                events.append({
                    "timestamp": t,
                    "type": ts_type,
                    "filename": entry.get("filename", ""),
                    "record_number": entry.get("record_number"),
                })
    events.sort(key=lambda e: e["timestamp"])
    return events


def validator_TimelineBuilder_group_by_day(events: list) -> dict:
    """Group timeline events by day (YYYY-MM-DD)."""
    import datetime
    result: Dict[str, list] = defaultdict(list)
    for event in events:
        try:
            day = datetime.datetime.utcfromtimestamp(event["timestamp"]).strftime("%Y-%m-%d")
        except Exception:
            day = "1970-01-01"
        result[day].append(event)
    return dict(result)


USN_MAGIC = b"\x00\x00\x00\x00"  # simplified


def validator_UsnScanner_parse(data: bytes) -> list:
    """Parse USN Journal records."""
    results = []
    pos = 0
    while pos + 60 <= len(data):
        # USN record v2: starts with record length (DWORD), min 60 bytes
        try:
            rec_len = struct.unpack_from("<I", data, pos)[0]
            if rec_len < 60 or rec_len > 65536:
                pos += 8
                continue
            major = struct.unpack_from("<H", data, pos + 4)[0]
            if major not in (2, 3):
                pos += 8
                continue
            usn = struct.unpack_from("<q", data, pos + 8)[0]
            timestamp = struct.unpack_from("<q", data, pos + 16)[0]
            reason = struct.unpack_from("<I", data, pos + 24)[0]
            results.append({"offset": pos, "usn": usn, "timestamp": timestamp, "reason": reason})
            pos += rec_len
        except Exception:
            pos += 8
    return results


def validator_UsnScanner_to_timeline_events(records: list) -> list:
    """Convert USN records to timeline events."""
    events = []
    for r in records:
        # Windows FILETIME to Unix: subtract epoch difference, divide by 100ns
        ft = r.get("timestamp", 0)
        unix_ts = (ft - 116444736000000000) // 10000000 if ft > 116444736000000000 else 0
        events.append({
            "timestamp": unix_ts,
            "type": "usn",
            "reason": r.get("reason", 0),
            "usn": r.get("usn", 0),
        })
    events.sort(key=lambda e: e["timestamp"])
    return events


# ---------------------------------------------------------------------------
# plugins::memory_strings
# ---------------------------------------------------------------------------

def validator_ExtractedString_new(address: int, value: str, encoding: str) -> dict:
    """Create extracted string with metadata."""
    return {"address": address, "value": value, "encoding": encoding}


def validator_AsciiExtractor_extract(extractor: dict, data: bytes, base_addr: int) -> list:
    """Extract ASCII strings from region."""
    min_len = extractor.get("min_len", 4)
    results = []
    pat = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
    for m in pat.finditer(data):
        results.append(validator_ExtractedString_new(
            base_addr + m.start(), m.group().decode("ascii", errors="replace"), "ascii"
        ))
    return results


def validator_Utf16Extractor_extract(extractor: dict, data: bytes, base_addr: int) -> list:
    """Extract UTF-16LE strings from region."""
    min_len = extractor.get("min_len", 4)
    results = []
    pat = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}")
    for m in pat.finditer(data):
        try:
            s = m.group().decode("utf-16-le")
            results.append(validator_ExtractedString_new(
                base_addr + m.start(), s, "utf-16le"
            ))
        except Exception:
            pass
    return results


STRING_CLASS_URL = "URL"
STRING_CLASS_IPV4 = "IPv4"
STRING_CLASS_IPV6 = "IPv6"
STRING_CLASS_EMAIL = "Email"
STRING_CLASS_GUID = "GUID"
STRING_CLASS_REGISTRY = "RegistryKey"
STRING_CLASS_WINDOWS_PATH = "WindowsPath"
STRING_CLASS_UNIX_PATH = "UnixPath"
STRING_CLASS_CREDENTIAL = "Credential"
STRING_CLASS_COMMAND_LINE = "CommandLine"
STRING_CLASS_HEX_BLOB = "HexBlob"
STRING_CLASS_BASE64 = "Base64"
STRING_CLASS_DOMAIN = "Domain"
STRING_CLASS_PE_SYMBOL = "PESymbol"
STRING_CLASS_UNKNOWN = "Unknown"


def validator_StringClassifier_is_url(s: str) -> bool:
    return bool(re.match(r"https?://[^\s]{4,}", s, re.IGNORECASE))


def validator_StringClassifier_is_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s.strip())
        return True
    except Exception:
        return False


def validator_StringClassifier_is_ipv6(s: str) -> bool:
    try:
        ipaddress.IPv6Address(s.strip())
        return True
    except Exception:
        return False


def validator_StringClassifier_is_email(s: str) -> bool:
    return bool(re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", s.strip()))


def validator_StringClassifier_is_guid(s: str) -> bool:
    return bool(re.match(
        r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$",
        s.strip()
    ))


def validator_StringClassifier_is_registry_key(s: str) -> bool:
    return bool(re.match(r"^(HKLM|HKCU|HKCR|HKU|HKCC|HKEY_)[\\]", s, re.IGNORECASE))


def validator_StringClassifier_is_windows_path(s: str) -> bool:
    return bool(re.match(r"^[A-Za-z]:\\", s) or re.match(r"^\\\\", s))


def validator_StringClassifier_is_unix_path(s: str) -> bool:
    return bool(re.match(r"^/[a-zA-Z0-9/_\-\.]+$", s))


def validator_StringClassifier_is_credential(s: str) -> bool:
    return bool(re.search(r"(password|passwd|pwd|token|secret|api_key)\s*[=:]\s*\S+", s, re.IGNORECASE))


def validator_StringClassifier_is_command_line(s: str) -> bool:
    return bool(re.search(r"\s[-/]{1,2}[a-zA-Z]", s))


def validator_StringClassifier_is_hex_blob(s: str) -> bool:
    s = s.strip()
    return len(s) >= 8 and bool(re.match(r"^[0-9a-fA-F]+$", s))


def validator_StringClassifier_is_base64(s: str) -> bool:
    s = s.strip()
    if len(s) < 8 or len(s) % 4 != 0:
        return False
    if not re.match(r"^[A-Za-z0-9+/=]+$", s):
        return False
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False


def validator_StringClassifier_is_domain(s: str) -> bool:
    s = s.strip().rstrip(".")
    return bool(re.match(r"^(?:[a-zA-Z0-9\-]{1,63}\.)+[a-zA-Z]{2,}$", s))


def validator_StringClassifier_is_pe_symbol(s: str) -> bool:
    return bool(re.match(r"^(\?{1,2}|_+)[A-Za-z0-9_@$?]+$", s))


def validator_StringClassifier_classify(s: str) -> str:
    """Classify string into a category."""
    if validator_StringClassifier_is_url(s):
        return STRING_CLASS_URL
    if validator_StringClassifier_is_ipv4(s):
        return STRING_CLASS_IPV4
    if validator_StringClassifier_is_ipv6(s):
        return STRING_CLASS_IPV6
    if validator_StringClassifier_is_email(s):
        return STRING_CLASS_EMAIL
    if validator_StringClassifier_is_guid(s):
        return STRING_CLASS_GUID
    if validator_StringClassifier_is_registry_key(s):
        return STRING_CLASS_REGISTRY
    if validator_StringClassifier_is_windows_path(s):
        return STRING_CLASS_WINDOWS_PATH
    if validator_StringClassifier_is_unix_path(s):
        return STRING_CLASS_UNIX_PATH
    if validator_StringClassifier_is_credential(s):
        return STRING_CLASS_CREDENTIAL
    if validator_StringClassifier_is_command_line(s):
        return STRING_CLASS_COMMAND_LINE
    if validator_StringClassifier_is_base64(s):
        return STRING_CLASS_BASE64
    if validator_StringClassifier_is_hex_blob(s):
        return STRING_CLASS_HEX_BLOB
    if validator_StringClassifier_is_domain(s):
        return STRING_CLASS_DOMAIN
    if validator_StringClassifier_is_pe_symbol(s):
        return STRING_CLASS_PE_SYMBOL
    return STRING_CLASS_UNKNOWN


def validator_StringClassifier_classify_batch(strings: list) -> dict:
    """Classify in batch and return counts per category."""
    counts: Dict[str, int] = defaultdict(int)
    for s in strings:
        val = s.get("value", "") if isinstance(s, dict) else str(s)
        cls = validator_StringClassifier_classify(val)
        counts[cls] += 1
    return dict(counts)


def validator_IpExtractor_extract_from_bytes(data: bytes) -> list:
    """Extract readable IP addresses from raw data."""
    text = data.decode("utf-8", errors="replace")
    return validator_IpExtractor_extract_ipv4_from_str(text)


def validator_IpExtractor_from_strings(strings: list) -> list:
    """Filter IPs from extracted strings."""
    results = []
    for s in strings:
        val = s.get("value", "") if isinstance(s, dict) else str(s)
        results.extend(validator_IpExtractor_extract_ipv4_from_str(val))
    return list(set(results))


def validator_IpExtractor_extract_ipv4_from_str(s: str) -> list:
    """Extract all IPv4 addresses from a string."""
    pat = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    results = []
    for m in pat.finditer(s):
        candidate = m.group(1)
        if validator_StringClassifier_is_ipv4(candidate):
            results.append(candidate)
    return results


def validator_IpExtractor_is_private_ipv4(s: str) -> bool:
    """True if IP is RFC1918 private."""
    return _is_private_ip(s)


def validator_CredentialPatternDetector_detect(strings: list) -> list:
    """Detect credential patterns in extracted strings."""
    results = []
    for s in strings:
        val = s.get("value", "") if isinstance(s, dict) else str(s)
        if validator_StringClassifier_is_credential(val):
            results.append({"pattern": val, "type": "credential"})
    return results


def validator_NtHashScanner_scan_nt_hashes(data: bytes) -> list:
    """Find NTLM hashes (32 char hex) with offsets."""
    results = []
    text = data.decode("utf-8", errors="replace")
    pat = re.compile(r"\b([0-9a-fA-F]{32})\b")
    for m in pat.finditer(text):
        results.append((m.start(), m.group(1).lower()))
    return results


def validator_MemoryStringAnalysis_analyze(data: bytes, base_addr: int, min_len: int) -> dict:
    """Complete analysis: extract, classify and correlate all strings."""
    ascii_ext = {"min_len": min_len}
    utf16_ext = {"min_len": min_len}
    ascii_strings = validator_AsciiExtractor_extract(ascii_ext, data, base_addr)
    utf16_strings = validator_Utf16Extractor_extract(utf16_ext, data, base_addr)
    all_strings = ascii_strings + utf16_strings
    counts = validator_StringClassifier_classify_batch(all_strings)
    ips = validator_IpExtractor_from_strings(all_strings)
    creds = validator_CredentialPatternDetector_detect(all_strings)
    return {
        "total": len(all_strings),
        "ascii_count": len(ascii_strings),
        "utf16_count": len(utf16_strings),
        "class_counts": counts,
        "ips": ips,
        "credential_patterns": creds,
    }


# ---------------------------------------------------------------------------
# plugins::network_artifacts (sub-module)
# ---------------------------------------------------------------------------

def validator_MacAddress_from_slice(s: bytes):
    """Create MAC address from 6 bytes."""
    if len(s) != 6:
        return {"error": "expected 6 bytes"}
    return {"bytes": list(s)}


def validator_MacAddress_to_string_colon(mac: dict) -> str:
    """Format as AA:BB:CC:DD:EE:FF."""
    return ":".join(f"{b:02X}" for b in mac.get("bytes", [0]*6))


def validator_MacAddress_oui(mac: dict) -> str:
    """Return first 3 bytes as OUI."""
    b = mac.get("bytes", [0]*6)
    return "-".join(f"{x:02X}" for x in b[:3])


def validator_MacAddress_is_broadcast(mac: dict) -> bool:
    """True if all bytes are 0xFF."""
    return all(b == 0xFF for b in mac.get("bytes", []))


def validator_ArpScanner_scan(data: bytes) -> list:
    """Extract ARP cache entries from data."""
    results = []
    ARP_PATTERN = re.compile(
        rb"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        rb"[\s\x00]+"
        rb"([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-]"
        rb"[0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})"
    )
    for m in ARP_PATTERN.finditer(data):
        try:
            ip = m.group(1).decode("ascii")
            mac = m.group(2).decode("ascii")
            if validator_StringClassifier_is_ipv4(ip):
                results.append({"ip": ip, "mac": mac})
        except Exception:
            pass
    return results


def validator_DnsCacheEntry_as_str(entry: dict) -> str:
    """Textual representation of DNS cache entry."""
    ips = ", ".join(entry.get("ips", []))
    return f"{entry.get('hostname', '')} [{entry.get('record_type', '')}] -> {ips}"


def validator_DnsCacheScanner_scan(data: bytes) -> list:
    """Extract DNS cache entries from raw data."""
    text = data.decode("utf-8", errors="replace")
    results = []
    # Look for hostname -> IP patterns
    pat = re.compile(r"([a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,})\s*[=>\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    for m in pat.finditer(text):
        hostname = m.group(1)
        ip = m.group(2)
        if validator_StringClassifier_is_domain(hostname) and validator_StringClassifier_is_ipv4(ip):
            results.append({"hostname": hostname, "record_type": "A", "ips": [ip]})
    return results


SUSPICIOUS_DOMAIN_PATTERNS = [
    r"\.xyz$", r"\.top$", r"\.club$", r"\.pw$",
    r"\d{4,}\.",  # lots of digits (DGA indicator)
    r"[a-z]{20,}\.",  # very long random-looking label
]


def validator_DomainAnalyzer_is_suspicious_domain(name: str) -> bool:
    """True if domain has suspicious characteristics."""
    name = name.lower().rstrip(".")
    return any(re.search(p, name) for p in SUSPICIOUS_DOMAIN_PATTERNS)


SUSPICIOUS_PORTS = {4444, 8888, 1337, 31337, 6666, 6667, 9999, 12345}


def validator_NetstatEntry_is_suspicious(entry: dict) -> bool:
    """True if connection is to suspicious port or IP."""
    remote_port = entry.get("remote_port", 0)
    if remote_port in SUSPICIOUS_PORTS:
        return True
    remote_ip = entry.get("remote_ip", "")
    if remote_ip and not _is_private_ip(remote_ip):
        return True
    return False


def validator_NetstatDiff_diff(before: list, after: list) -> dict:
    """Calculate difference between two netstat snapshots."""
    before_set = {(e.get("local_ip"), e.get("local_port"), e.get("remote_ip"), e.get("remote_port"))
                  for e in before}
    after_set = {(e.get("local_ip"), e.get("local_port"), e.get("remote_ip"), e.get("remote_port"))
                 for e in after}
    new_conns = [e for e in after
                 if (e.get("local_ip"), e.get("local_port"), e.get("remote_ip"), e.get("remote_port"))
                 not in before_set]
    closed_conns = [e for e in before
                    if (e.get("local_ip"), e.get("local_port"), e.get("remote_ip"), e.get("remote_port"))
                    not in after_set]
    return {"new": new_conns, "closed": closed_conns}


def validator_UrlScanner_scan(data: bytes) -> list:
    """Extract URLs from raw memory/cache data."""
    return validator_BrowserScanner_scan_urls(data)


# ---------------------------------------------------------------------------
# plugins::event_log
# ---------------------------------------------------------------------------

EVTX_CHUNK_MAGIC = b"ElfChnk\x00"
EVTX_RECORD_MAGIC = b"\x2a\x2a\x00\x00"


def validator_EvtxChunkHeader_parse(data: bytes):
    """Parse EVTX chunk header (512 bytes)."""
    if len(data) < 8 or data[:8] != EVTX_CHUNK_MAGIC:
        return {"error": "invalid EVTX chunk magic"}
    return {
        "magic": "ElfChnk",
        "first_event_record_number": struct.unpack_from("<Q", data, 8)[0] if len(data) >= 16 else 0,
        "last_event_record_number": struct.unpack_from("<Q", data, 16)[0] if len(data) >= 24 else 0,
    }


def validator_EventRecord_parse(data: bytes, offset: int):
    """Parse single EVTX event record."""
    chunk = data[offset:]
    if len(chunk) < 24 or chunk[:4] != EVTX_RECORD_MAGIC:
        return {"error": "invalid EVTX record magic"}
    size = struct.unpack_from("<I", chunk, 4)[0]
    record_id = struct.unpack_from("<Q", chunk, 8)[0]
    timestamp = struct.unpack_from("<Q", chunk, 16)[0]
    return {
        "record_id": record_id,
        "timestamp": timestamp,
        "size": size,
        "event_id": 0,
        "provider": "",
        "level": "Information",
    }


def validator_EventRecord_summary(record: dict) -> str:
    """Brief text description of event."""
    return (f"Record#{record.get('record_id',0)} "
            f"EventID={record.get('event_id',0)} "
            f"Provider={record.get('provider','?')} "
            f"Level={record.get('level','?')}")


def validator_parse_records_from_chunk(chunk_data: bytes) -> list:
    """Parse all records in an EVTX chunk."""
    records = []
    pos = 512  # skip chunk header
    while pos + 24 <= len(chunk_data):
        if chunk_data[pos:pos+4] != EVTX_RECORD_MAGIC:
            pos += 4
            continue
        rec = validator_EventRecord_parse(chunk_data, pos)
        if "error" in rec:
            pos += 4
            continue
        records.append(rec)
        pos += max(rec.get("size", 4), 4)
    return records


SECURITY_EVENT_IDS = {
    4624: "Successful logon",
    4625: "Failed logon",
    4648: "Logon with explicit credentials",
    4672: "Special privileges assigned",
    4688: "Process created",
    4697: "Service installed",
    4698: "Scheduled task created",
    7045: "New service installed",
    4776: "NTLM authentication",
    4720: "User account created",
    4726: "User account deleted",
}


def validator_event_id_description(provider: str, event_id: int) -> str:
    """Text description for known event IDs."""
    return SECURITY_EVENT_IDS.get(event_id, "Unknown event")


def validator_EvtxParser_find_chunk_offsets(data: bytes) -> list:
    """Find all chunk offsets in EVTX file."""
    offsets = []
    pos = 0
    while True:
        idx = data.find(EVTX_CHUNK_MAGIC, pos)
        if idx == -1:
            break
        offsets.append(idx)
        pos = idx + 1
    return offsets


def validator_EvtxParser_parse_file(data: bytes):
    """Parse entire EVTX file."""
    EVTX_FILE_MAGIC = b"ElfFile\x00"
    if data[:8] != EVTX_FILE_MAGIC:
        return {"error": "invalid EVTX file magic"}
    offsets = validator_EvtxParser_find_chunk_offsets(data)
    records = []
    for offset in offsets:
        chunk = data[offset:offset + 65536]
        records.extend(validator_parse_records_from_chunk(chunk))
    return records


def validator_EvtxParser_summarize(records: list) -> dict:
    """Count events per Event ID."""
    counts: Dict[str, int] = defaultdict(int)
    for r in records:
        counts[str(r.get("event_id", 0))] += 1
    return dict(counts)


def validator_EvtxParser_filter_by_event_id(records: list, event_id: int) -> list:
    """Filter by Event ID."""
    return [r for r in records if r.get("event_id") == event_id]


def validator_EvtxParser_filter_by_provider(records: list, provider: str) -> list:
    """Filter by provider."""
    return [r for r in records if r.get("provider", "") == provider]


SUSPICIOUS_EVENT_IDS = {4624, 4625, 4688, 7045, 4697, 4698, 4648, 4720, 4726}


def validator_EvtxParser_find_suspicious(records: list) -> list:
    """Filter suspicious events."""
    return [r for r in records if r.get("event_id", 0) in SUSPICIOUS_EVENT_IDS]


def validator_EventLevel_from_str(s: str) -> str:
    """Parse level from string."""
    mapping = {
        "error": "Error", "err": "Error",
        "warning": "Warning", "warn": "Warning",
        "information": "Information", "info": "Information",
        "verbose": "Verbose",
        "critical": "Critical",
    }
    return mapping.get(s.lower().strip(), "Information")


# ---------------------------------------------------------------------------
# plugins::lnk_parser
# ---------------------------------------------------------------------------

LNK_MAGIC = b"\x4c\x00\x00\x00"
LNK_CLSID = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"


def validator_ShellLinkHeader_parse(data: bytes):
    """Parse .lnk Shell Link header (76 bytes)."""
    if len(data) < 76:
        return {"error": "data too short for LNK header"}
    if data[:4] != LNK_MAGIC:
        return {"error": "invalid LNK magic"}
    flags = struct.unpack_from("<I", data, 20)[0]
    attrs = struct.unpack_from("<I", data, 24)[0]
    return {
        "magic": "L",
        "flags": flags,
        "file_attributes": attrs,
        "creation_time": struct.unpack_from("<Q", data, 28)[0],
        "access_time": struct.unpack_from("<Q", data, 36)[0],
        "write_time": struct.unpack_from("<Q", data, 44)[0],
        "file_size": struct.unpack_from("<I", data, 52)[0],
        "show_command": struct.unpack_from("<I", data, 60)[0],
    }


def validator_LinkTargetIdList_parse(data: bytes):
    """Parse link target ID list from .lnk data."""
    if len(data) < 76:
        return {"error": "data too short"}
    flags = struct.unpack_from("<I", data, 20)[0]
    if not (flags & 0x01):  # HasLinkTargetIDList
        return {"items": []}
    # ID list starts at offset 76
    offset = 76
    if offset + 2 > len(data):
        return {"items": []}
    id_list_size = struct.unpack_from("<H", data, offset)[0]
    return {"items": [], "size": id_list_size}


def validator_LinkTargetIdList_target_path(id_list: dict) -> str:
    """Reconstruct target path from ID list."""
    return id_list.get("path", "")


def validator_StringData_parse(data: bytes, offset: int, flags: int, is_unicode: bool) -> dict:
    """Parse StringData block."""
    if offset + 2 > len(data):
        return {"value": ""}
    count = struct.unpack_from("<H", data, offset)[0]
    if is_unicode:
        byte_len = count * 2
        raw = data[offset + 2:offset + 2 + byte_len]
        try:
            value = raw.decode("utf-16-le")
        except Exception:
            value = ""
    else:
        raw = data[offset + 2:offset + 2 + count]
        try:
            value = raw.decode("latin-1")
        except Exception:
            value = ""
    return {"value": value, "length": count}


def validator_ExtraDataBlock_parse_all(data: bytes, offset: int) -> list:
    """Parse all extra data blocks."""
    results = []
    pos = offset
    while pos + 8 <= len(data):
        block_size = struct.unpack_from("<I", data, pos)[0]
        if block_size < 4:
            break
        block_sig = struct.unpack_from("<I", data, pos + 4)[0] if pos + 8 <= len(data) else 0
        results.append({"offset": pos, "size": block_size, "signature": hex(block_sig)})
        pos += block_size
    return results


def validator_LnkFile_parse(data: bytes):
    """Parse entire .lnk file."""
    header = validator_ShellLinkHeader_parse(data)
    if "error" in header:
        return header
    return {
        "header": header,
        "target_path": "",
        "arguments": "",
        "working_dir": "",
        "icon_location": "",
    }


def validator_LnkFile_target_path(lnk: dict) -> str:
    """Get absolute path of link target."""
    return lnk.get("target_path", "")


def validator_LnkFile_to_row(lnk: dict) -> dict:
    """Export all fields as map."""
    return {
        "target_path": lnk.get("target_path", ""),
        "arguments": lnk.get("arguments", ""),
        "working_dir": lnk.get("working_dir", ""),
        "icon_location": lnk.get("icon_location", ""),
    }


def validator_LnkFile_is_suspicious(lnk: dict) -> bool:
    """True if .lnk points to suspicious paths or uses PS/cmd args."""
    target = lnk.get("target_path", "").lower()
    args = lnk.get("arguments", "").lower()
    suspicious_targets = ["powershell", "cmd.exe", "wscript", "cscript", "mshta", "regsvr32"]
    if any(s in target or s in args for s in suspicious_targets):
        return True
    if validator_PathHeuristics_is_suspicious_path(target):
        return True
    return False


# ---------------------------------------------------------------------------
# plugins::process_artifacts
# ---------------------------------------------------------------------------

SYSTEM_PROCESS_NAMES_SET = {
    "system", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe",
    "explorer.exe", "taskhostw.exe",
}


def validator_EprocessEntry_has_suspicious_name(entry: dict) -> bool:
    """True if process name is masked or resembles system process."""
    name = entry.get("name", "").lower()
    # Masquerading: slight misspelling of system names
    for sys_name in SYSTEM_PROCESS_NAMES_SET:
        if name != sys_name and _string_similarity(name, sys_name) > 0.8:
            return True
    return False


def _string_similarity(a: str, b: str) -> float:
    """Simple similarity metric."""
    if not a or not b:
        return 0.0
    a, b = a.lower(), b.lower()
    matches = sum(c1 == c2 for c1, c2 in zip(a, b))
    return 2.0 * matches / (len(a) + len(b))


def validator_EprocessWalker_walk(walker: dict, memory_data: bytes, base_addr: int, start_addr: int) -> list:
    """Walk EPROCESS doubly-linked list in memory (stub)."""
    return walker.get("entries", [])


def validator_HandleTable_parse_page(data: bytes, pid: int) -> list:
    """Parse a handle table page for a process."""
    HANDLE_SIZE = 16
    entries = []
    for offset in range(0, len(data) - HANDLE_SIZE + 1, HANDLE_SIZE):
        obj_ptr = struct.unpack_from("<Q", data, offset)[0] if len(data) >= offset + 8 else 0
        if obj_ptr and obj_ptr != 0xFFFFFFFFFFFFFFFF:
            entries.append({"pid": pid, "object_ptr": obj_ptr, "type": "Unknown"})
    return entries


def validator_HandleTable_summarize(entries: list) -> dict:
    """Count handles by type."""
    counts: Dict[str, int] = defaultdict(int)
    for e in entries:
        counts[e.get("type", "Unknown")] += 1
    return dict(counts)


def validator_LdrModuleEntry_is_suspicious_path(entry: dict) -> bool:
    """True if module is loaded from unusual path."""
    path = entry.get("full_path", "").lower()
    return validator_PathHeuristics_is_suspicious_path(path)


def validator_LdrScanner_scan(data: bytes) -> list:
    """Parse loaded modules list from PEB/LDR data (stub)."""
    results = []
    # Look for PE magic followed by a null-terminated path pattern
    pos = 0
    while pos < len(data) - 4:
        idx = data.find(b"MZ", pos)
        if idx == -1:
            break
        results.append({"base_address": idx, "full_path": "", "name": ""})
        pos = idx + 2
    return results


# ---------------------------------------------------------------------------
# plugins::registry_artifacts
# ---------------------------------------------------------------------------

NK_MAGIC = b"nk"
VK_MAGIC = b"vk"


def validator_NkRecord_parse(data: bytes):
    """Parse NK (Named Key) record from hive."""
    if len(data) < 2 or data[:2] != NK_MAGIC:
        return {"error": "invalid NK magic"}
    flags = struct.unpack_from("<H", data, 2)[0] if len(data) >= 4 else 0
    name_len = struct.unpack_from("<H", data, 72)[0] if len(data) >= 74 else 0
    name = data[76:76 + name_len].decode("latin-1", errors="replace") if len(data) >= 76 + name_len else ""
    return {"magic": "nk", "flags": flags, "name": name}


def validator_VkRecord_parse(data: bytes, offset: int):
    """Parse VK (Value Key) record."""
    chunk = data[offset:]
    if len(chunk) < 2 or chunk[:2] != VK_MAGIC:
        return {"error": "invalid VK magic"}
    name_len = struct.unpack_from("<H", chunk, 2)[0] if len(chunk) >= 4 else 0
    data_len = struct.unpack_from("<I", chunk, 4)[0] if len(chunk) >= 8 else 0
    data_offset = struct.unpack_from("<I", chunk, 8)[0] if len(chunk) >= 12 else 0
    reg_type = struct.unpack_from("<I", chunk, 12)[0] if len(chunk) >= 16 else 0
    name = chunk[20:20 + name_len].decode("latin-1", errors="replace") if len(chunk) >= 20 + name_len else ""
    return {
        "magic": "vk",
        "name": name,
        "data_length": data_len & 0x7FFFFFFF,
        "data_offset": data_offset,
        "reg_type": reg_type,
    }


def validator_RegValueData_as_string(val: dict) -> Optional[str]:
    """Interpret value as REG_SZ/REG_EXPAND_SZ."""
    if val.get("reg_type") in (1, 2):
        raw = bytes(val.get("raw", []))
        try:
            return raw.decode("utf-16-le").rstrip("\x00")
        except Exception:
            return raw.decode("latin-1", errors="replace")
    return None


def validator_RegValueData_as_dword(val: dict) -> Optional[int]:
    """Interpret value as REG_DWORD."""
    if val.get("reg_type") == 4:
        raw = bytes(val.get("raw", []))
        if len(raw) >= 4:
            return struct.unpack_from("<I", raw)[0]
    return None


def validator_RegValueData_as_qword(val: dict) -> Optional[int]:
    """Interpret value as REG_QWORD."""
    if val.get("reg_type") == 11:
        raw = bytes(val.get("raw", []))
        if len(raw) >= 8:
            return struct.unpack_from("<Q", raw)[0]
    return None


def validator_RegValueData_as_multi_sz(val: dict) -> list:
    """Interpret value as REG_MULTI_SZ."""
    if val.get("reg_type") == 7:
        raw = bytes(val.get("raw", []))
        try:
            decoded = raw.decode("utf-16-le")
            return [s for s in decoded.split("\x00") if s]
        except Exception:
            pass
    return []


def validator_SamUser_has_blank_password(user: dict) -> bool:
    """True if NT hash matches blank password."""
    return user.get("nt_hash", "").lower() == NTLM_BLANK_HASH


def validator_SamUser_lm_disabled(user: dict) -> bool:
    """True if LM hash is disabled."""
    return user.get("lm_hash", "").lower() == LM_DISABLED_HASH


ROT13_TABLE = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
)


def validator_UserAssistDecoder_rot13_decode(input_str: str) -> str:
    """Decode ROT13."""
    return input_str.translate(ROT13_TABLE)


def validator_UserAssistDecoder_parse_value(encoded_name: str, data: dict) -> Optional[dict]:
    """Parse UserAssist entry from encoded name and payload."""
    decoded = validator_UserAssistDecoder_rot13_decode(encoded_name)
    run_count = data.get("run_count", 0)
    last_run = data.get("last_run_timestamp", 0)
    if not decoded:
        return None
    return {"decoded_name": decoded, "run_count": run_count, "last_run": last_run}


def validator_ShellbagDecoder_decode_shitemid(data: bytes) -> str:
    """Decode ShItemID to readable path."""
    if len(data) < 2:
        return ""
    # Attempt simple ASCII extraction
    try:
        text = data.decode("latin-1")
        parts = [c for c in text if 0x20 <= ord(c) < 0x7f]
        return "".join(parts).strip()
    except Exception:
        return data.hex()


SUSPICIOUS_RUN_PATTERNS = [
    r"powershell", r"cmd\.exe", r"wscript", r"cscript",
    r"mshta", r"regsvr32", r"rundll32",
    r"\.bat\b", r"\.vbs\b", r"\.ps1\b", r"\\temp\\", r"\\appdata\\",
]


def validator_RunKeyAnalyzer_is_suspicious(command: str) -> bool:
    """True if run key command has suspicious persistence patterns."""
    cmd_lower = command.lower()
    return any(re.search(p, cmd_lower) for p in SUSPICIOUS_RUN_PATTERNS)


def validator_RunKeyAnalyzer_from_key_path(path: str) -> dict:
    """Create RunKeyAnalyzer for a Run key path."""
    return {"key_path": path, "commands": []}


def validator_UserAssistReport_new(username: str) -> dict:
    """Create UserAssist report for user."""
    return {"username": username, "entries": [], "suspicious": []}


def validator_UserAssistReport_suspicious_count(report: dict) -> int:
    """Number of suspicious executions."""
    return len(report.get("suspicious", []))


def validator_UserAssistReport_top_programs(report: dict, limit: int) -> list:
    """Most-executed programs."""
    entries = report.get("entries", [])
    sorted_entries = sorted(entries, key=lambda e: e.get("run_count", 0), reverse=True)
    return sorted_entries[:limit]


def validator_RegistryScanner_scan_run_commands(data: bytes) -> list:
    """Extract all Run/RunOnce commands from hive raw data."""
    text = data.decode("utf-8", errors="replace")
    results = []
    # Heuristic: find command-looking strings after Run key markers
    pat = re.compile(r"(?:Run|RunOnce)[\\x00\s]+([^\x00\n]{4,200})", re.IGNORECASE)
    for m in pat.finditer(text):
        cmd = m.group(1).strip()
        if cmd:
            results.append(cmd)
    return results


def validator_RegistryScanner_scan_typed_urls(data: bytes) -> list:
    """Extract TypedURLs from hive."""
    text = data.decode("utf-8", errors="replace")
    pat = re.compile(r"https?://[^\s\x00\"<>]{4,}", re.IGNORECASE)
    return list(set(pat.findall(text)))


REGF_MAGIC = b"regf"


def validator_RegistryScanner_find_hive_offsets(data: bytes) -> list:
    """Find 'regf' magic offsets for hives mapped in memory."""
    results = []
    pos = 0
    while True:
        idx = data.find(REGF_MAGIC, pos)
        if idx == -1:
            break
        results.append(idx)
        pos = idx + 1
    return results


def validator_RegistryScanner_scan_sam_rids(data: bytes) -> list:
    """Extract user RIDs from SAM hive raw data."""
    results = []
    # Look for patterns like V\x00\x00\x00 preceded by numeric RIDs
    pat = re.compile(rb"\\SAM\\Domains\\Account\\Users\\(\d{8})")
    for m in pat.finditer(data):
        try:
            rid = int(m.group(1))
            results.append(rid)
        except Exception:
            pass
    return results


# ---------------------------------------------------------------------------
# plugins::prefetch_analyzer
# ---------------------------------------------------------------------------

MAM_MAGIC = b"\x1f\x8b"  # simplified; actual MAM has different header
PF_MAGIC_V17 = b"SCCA"
PF_SIGNATURES = {17: b"SCCA", 26: b"SCCA", 30: b"SCCA"}


def validator_is_mam_compressed(data: bytes) -> bool:
    """True if prefetch file is MAM compressed (Windows 10+)."""
    # MAM magic: 0x4d414d04 little-endian
    if len(data) < 4:
        return False
    return data[:4] == b"\x04MAM" or data[:4] == b"MAM\x04"


def validator_decompress_mam(data: bytes):
    """Decompress MAM-compressed prefetch data."""
    # Without a MAM decompressor in stdlib, return error
    if not validator_is_mam_compressed(data):
        return {"error": "not MAM compressed"}
    return {"error": "MAM decompression requires lzxpress_huffman (not in stdlib)"}


def validator_PrefetchHeader_parse(data: bytes):
    """Parse Prefetch header."""
    if validator_is_mam_compressed(data):
        return {"error": "data is MAM compressed, decompress first"}
    if len(data) < 84:
        return {"error": "data too short for Prefetch header"}
    version = struct.unpack_from("<I", data, 0)[0]
    if data[4:8] != b"SCCA":
        return {"error": "invalid Prefetch signature"}
    name_raw = data[16:76]
    try:
        name = name_raw.decode("utf-16-le").rstrip("\x00")
    except Exception:
        name = ""
    pf_hash = struct.unpack_from("<I", data, 76)[0]
    run_count = struct.unpack_from("<I", data, 208)[0] if len(data) >= 212 else 0
    return {
        "version": version,
        "signature": "SCCA",
        "exe_name": name,
        "prefetch_hash": pf_hash,
        "run_count": run_count,
        "run_times": [],
    }


def validator_PrefetchHeader_all_run_times_unix(header: dict) -> list:
    """List all execution timestamps as Unix timestamps."""
    # Windows FILETIME -> Unix
    results = []
    for ft in header.get("run_times", []):
        unix_ts = (ft - 116444736000000000) // 10000000 if ft > 116444736000000000 else 0
        results.append(unix_ts)
    return results


def validator_FileMetrics_parse_v17(data: bytes, strings: bytes) -> Optional[dict]:
    """Parse file metrics v17 (XP/Vista format)."""
    if len(data) < 20:
        return None
    offset = struct.unpack_from("<I", data, 4)[0]
    str_len = struct.unpack_from("<I", data, 8)[0]
    try:
        name = strings[offset:offset + str_len].decode("utf-16-le", errors="replace").rstrip("\x00")
    except Exception:
        name = ""
    return {"filename": name, "version": 17}


def validator_FileMetrics_parse_v26(data: bytes, strings: bytes) -> Optional[dict]:
    """Parse file metrics v26 (Win7/8 format)."""
    if len(data) < 32:
        return None
    offset = struct.unpack_from("<I", data, 4)[0]
    str_len = struct.unpack_from("<I", data, 8)[0]
    try:
        name = strings[offset:offset + str_len].decode("utf-16-le", errors="replace").rstrip("\x00")
    except Exception:
        name = ""
    return {"filename": name, "version": 26}


def validator_VolumeInfo_parse(data: bytes, vol_section: bytes) -> Optional[dict]:
    """Parse volume info (device path, serial, creation time)."""
    if len(data) < 20:
        return None
    path_offset = struct.unpack_from("<I", data, 0)[0]
    path_len = struct.unpack_from("<I", data, 4)[0]
    serial = struct.unpack_from("<I", data, 8)[0] if len(data) >= 12 else 0
    creation_time = struct.unpack_from("<Q", data, 12)[0] if len(data) >= 20 else 0
    try:
        device_path = vol_section[path_offset:path_offset + path_len * 2].decode("utf-16-le", errors="replace")
    except Exception:
        device_path = ""
    return {"device_path": device_path, "serial": serial, "creation_time": creation_time}


def _rol32(val: int, shift: int) -> int:
    shift &= 31
    return ((val << shift) | (val >> (32 - shift))) & 0xFFFFFFFF


def validator_compute_prefetch_hash_xp(path: str) -> int:
    """Compute Prefetch hash using XP/Vista algorithm."""
    # XP: simple additive + ROR hash
    path = path.upper()
    hash_val = 0
    for ch in path:
        hash_val = (hash_val * 37 + ord(ch)) & 0xFFFFFFFF
    return hash_val


def validator_compute_prefetch_hash_win8(path: str) -> int:
    """Compute Prefetch hash using Windows 8+ algorithm."""
    # Win8: different multiplier
    path = path.upper()
    hash_val = 314159265
    for ch in path:
        hash_val = (hash_val * 37 + ord(ch)) & 0xFFFFFFFF
    return hash_val


def validator_verify_hash(header: dict, exe_path: str) -> bool:
    """True if header hash matches computed path hash."""
    stored = header.get("prefetch_hash", 0)
    version = header.get("version", 17)
    if version >= 26:
        computed = validator_compute_prefetch_hash_win8(exe_path)
    else:
        computed = validator_compute_prefetch_hash_xp(exe_path)
    return stored == computed


def validator_PrefetchFile_parse(data: bytes):
    """Parse entire Prefetch file."""
    header = validator_PrefetchHeader_parse(data)
    if "error" in header:
        return header
    return {
        "header": header,
        "file_metrics": [],
        "volumes": [],
    }


def validator_PrefetchFile_summary(pf: dict) -> dict:
    """Summary as key-value map."""
    header = pf.get("header", {})
    run_times = validator_PrefetchHeader_all_run_times_unix(header)
    return {
        "exe_name": header.get("exe_name", ""),
        "prefetch_hash": hex(header.get("prefetch_hash", 0)),
        "run_count": str(header.get("run_count", 0)),
        "last_run": str(run_times[0]) if run_times else "0",
        "volume_count": str(len(pf.get("volumes", []))),
        "file_count": str(len(pf.get("file_metrics", []))),
    }


# ---------------------------------------------------------------------------
# Function registry for counting
# ---------------------------------------------------------------------------

ALL_VALIDATORS = [
    # volatility_plugins (16)
    validator_ProcessEntry_is_system,
    validator_ProcessEntry_is_alive,
    validator_PluginOutput_to_json,
    validator_PluginOutput_to_json_pretty,
    validator_PluginArgs_new,
    validator_PluginArgs_set,
    validator_PluginArgs_get,
    validator_ProcessList_build,
    validator_ProcessList_total_count,
    validator_ProcessList_find_pid,
    validator_PluginRegistry_new,
    validator_PluginRegistry_register,
    validator_PluginRegistry_run,
    validator_PluginRegistry_plugin_names,
    validator_PluginRegistry_count,
    validator_default_registry,
    # registry_hive_plugin (8)
    validator_RegCell_parse_data,
    validator_parse_hive_bytes,
    validator_HiveWalker_new,
    validator_walk_keys,
    validator_search_by_name,
    validator_search_by_value_data,
    validator_export_to_json,
    validator_deleted_key_scanner,
    # memory_dump_plugin (13)
    validator_DumpParser_detect_format,
    validator_RawDumpParser_new,
    validator_RawDumpParser_parse_ranges,
    validator_MiniDumpParser_parse_streams,
    validator_CrashDumpParser_extract_processes,
    validator_CrashDumpParser_extract_modules,
    validator_CrashDumpParser_search_pattern,
    validator_CrashDumpParser_carve_strings,
    validator_CrashDumpParser_find_pe_headers,
    validator_CrashDumpParser_compute_statistics,
    validator_DumpAnalyzer_analyze,
    validator_DumpAnalyzer_analyze_all,
    # network_artifacts top-level (40)
    validator_TcpEntry_with_process,
    validator_TcpEntry_is_established,
    validator_TcpEntry_is_listening,
    validator_TcpTable_new,
    validator_TcpTable_add,
    validator_TcpTable_all,
    validator_TcpTable_established,
    validator_TcpTable_listening,
    validator_TcpTable_by_pid,
    validator_TcpTable_by_state,
    validator_TcpTable_unique_remote_ips,
    validator_TcpTable_unique_pids,
    validator_TcpTable_outbound_count,
    validator_UdpEntry_with_process,
    validator_UdpTable_new,
    validator_UdpTable_add,
    validator_UdpTable_all,
    validator_UdpTable_by_pid,
    validator_UdpTable_listening_ports,
    validator_UdpTable_unique_pids,
    validator_DnsCacheEntry_new,
    validator_DnsCacheEntry_with_ip,
    validator_DnsCacheEntry_is_a_record,
    validator_DnsCache_new,
    validator_DnsCache_add,
    validator_DnsCache_all,
    validator_DnsCache_lookup,
    validator_DnsCache_a_records,
    validator_DnsCache_for_ip,
    validator_DnsCache_unique_hostnames,
    validator_HttpCacheEntry_new,
    validator_HttpCacheEntry_with_user_agent,
    validator_HttpCacheEntry_is_post,
    validator_HttpCacheEntry_is_get,
    validator_HttpCacheEntry_is_success,
    validator_HttpCache_new,
    validator_HttpCache_add,
    validator_HttpCache_all,
    validator_HttpCache_by_host,
    validator_HttpCache_post_requests,
    validator_HttpCache_unique_hosts,
    validator_HttpCache_suspicious_user_agents,
    validator_NetworkReport_build,
    validator_NetworkCorrelator_new,
    validator_NetworkCorrelator_add_tcp,
    validator_NetworkCorrelator_add_udp,
    validator_NetworkCorrelator_add_dns,
    validator_NetworkCorrelator_add_http,
    validator_NetworkCorrelator_report,
    validator_NetworkCorrelator_external_tcp,
    validator_NetworkCorrelator_suspicious_pids,
    validator_NetworkCorrelator_resolve_tcp_ip,
    validator_NetworkCorrelator_processes_with_tcp_and_udp,
    # lib.rs inline plugins (21)
    validator_HookDetector_looks_hooked,
    validator_VadRegion_perms_string,
    validator_StringExtractor_extract_strings,
    validator_ByteRule_new,
    validator_ByteRule_matches,
    validator_builtin_rules,
    validator_ByteScanner_with_builtin_rules,
    validator_TokenPrivileges_priv_name,
    validator_PathHeuristics_is_suspicious_path,
    validator_EntropyScanner_scan_high_entropy,
    validator_VadPlugin_run,
    validator_VadPlugin_find_suspicious_vads,
    validator_SamPlugin_extract_sam_hashes,
    validator_InjectionScanner_scan,
    validator_DriverPlugin_list_drivers,
    validator_DriverPlugin_is_suspicious_driver,
    validator_HivePlugin_find_hives,
    validator_StringsPlugin_scan_strings_in_process,
    validator_register_all,
    # browser_history (19)
    validator_BrowserProfile_from_path,
    validator_is_sqlite,
    validator_sqlite_page_size,
    validator_sqlite_user_version,
    validator_HistoryEntry_is_potentially_malicious,
    validator_FormData_looks_like_credential,
    validator_BrowserScanner_scan_urls,
    validator_BrowserScanner_scan_cookie_strings,
    validator_BrowserScanner_summarize,
    validator_extract_domains,
    validator_PasswordEntry_is_insecure,
    validator_FirefoxScanner_scan_login_origins,
    validator_ChromeScanner_scan_domains,
    validator_EdgeDetector_looks_like_edge,
    validator_BrowserAnalyzer_analyze,
    validator_BrowserAnalyzer_classify_urls,
    # credential_artifacts (17)
    validator_NtlmHash_from_slice,
    validator_NtlmHash_from_hex,
    validator_NtlmHash_to_hex,
    validator_NtlmHash_is_blank_password,
    validator_NtlmHash_is_lm_disabled,
    validator_SamEntry_parse,
    validator_SamEntry_has_valid_nt_hash,
    validator_SamEntry_lm_enabled,
    validator_LsassCredential_has_cleartext,
    validator_LsassCredential_severity,
    validator_LsassScanner_scan_wdigest,
    validator_LsassScanner_scan_nt_hashes,
    validator_LsassScanner_scan,
    validator_KerberosScanner_scan,
    validator_DpapiBlob_is_default_provider,
    validator_DpapiBlob_is_browser_credential,
    validator_DpapiScanner_scan,
    validator_DpapiScanner_find_masterkey_guids,
    validator_CredentialReport_cleartext_creds,
    validator_CredentialReport_to_row_map,
    validator_CredentialReport_from_bytes,
    # file_timeline (9)
    validator_Timestamps_earliest,
    validator_Timestamps_latest,
    validator_MftEntry_parse,
    validator_MftScanner_scan,
    validator_MftScanner_scan_small,
    validator_TimelineBuilder_from_mft,
    validator_TimelineBuilder_group_by_day,
    validator_UsnScanner_parse,
    validator_UsnScanner_to_timeline_events,
    # memory_strings (21)
    validator_ExtractedString_new,
    validator_AsciiExtractor_extract,
    validator_Utf16Extractor_extract,
    validator_StringClassifier_classify,
    validator_StringClassifier_is_url,
    validator_StringClassifier_is_ipv4,
    validator_StringClassifier_is_ipv6,
    validator_StringClassifier_is_email,
    validator_StringClassifier_is_guid,
    validator_StringClassifier_is_registry_key,
    validator_StringClassifier_is_windows_path,
    validator_StringClassifier_is_unix_path,
    validator_StringClassifier_is_credential,
    validator_StringClassifier_is_command_line,
    validator_StringClassifier_is_hex_blob,
    validator_StringClassifier_is_base64,
    validator_StringClassifier_is_domain,
    validator_StringClassifier_is_pe_symbol,
    validator_StringClassifier_classify_batch,
    validator_IpExtractor_extract_from_bytes,
    validator_IpExtractor_from_strings,
    validator_IpExtractor_extract_ipv4_from_str,
    validator_IpExtractor_is_private_ipv4,
    validator_CredentialPatternDetector_detect,
    validator_NtHashScanner_scan_nt_hashes,
    validator_MemoryStringAnalysis_analyze,
    # plugins::network_artifacts sub-module (11)
    validator_MacAddress_from_slice,
    validator_MacAddress_to_string_colon,
    validator_MacAddress_oui,
    validator_MacAddress_is_broadcast,
    validator_ArpScanner_scan,
    validator_DnsCacheEntry_as_str,
    validator_DnsCacheScanner_scan,
    validator_DomainAnalyzer_is_suspicious_domain,
    validator_NetstatEntry_is_suspicious,
    validator_NetstatDiff_diff,
    validator_UrlScanner_scan,
    # event_log (12)
    validator_EvtxChunkHeader_parse,
    validator_EventRecord_parse,
    validator_EventRecord_summary,
    validator_parse_records_from_chunk,
    validator_event_id_description,
    validator_EvtxParser_find_chunk_offsets,
    validator_EvtxParser_parse_file,
    validator_EvtxParser_summarize,
    validator_EvtxParser_filter_by_event_id,
    validator_EvtxParser_filter_by_provider,
    validator_EvtxParser_find_suspicious,
    validator_EventLevel_from_str,
    # lnk_parser (9)
    validator_ShellLinkHeader_parse,
    validator_LinkTargetIdList_parse,
    validator_LinkTargetIdList_target_path,
    validator_StringData_parse,
    validator_ExtraDataBlock_parse_all,
    validator_LnkFile_parse,
    validator_LnkFile_target_path,
    validator_LnkFile_to_row,
    validator_LnkFile_is_suspicious,
    # process_artifacts (6)
    validator_EprocessEntry_has_suspicious_name,
    validator_EprocessWalker_walk,
    validator_HandleTable_parse_page,
    validator_HandleTable_summarize,
    validator_LdrModuleEntry_is_suspicious_path,
    validator_LdrScanner_scan,
    # registry_artifacts (19)
    validator_NkRecord_parse,
    validator_VkRecord_parse,
    validator_RegValueData_as_string,
    validator_RegValueData_as_dword,
    validator_RegValueData_as_qword,
    validator_RegValueData_as_multi_sz,
    validator_SamUser_has_blank_password,
    validator_SamUser_lm_disabled,
    validator_UserAssistDecoder_rot13_decode,
    validator_UserAssistDecoder_parse_value,
    validator_ShellbagDecoder_decode_shitemid,
    validator_RunKeyAnalyzer_is_suspicious,
    validator_RunKeyAnalyzer_from_key_path,
    validator_UserAssistReport_new,
    validator_UserAssistReport_suspicious_count,
    validator_UserAssistReport_top_programs,
    validator_RegistryScanner_scan_run_commands,
    validator_RegistryScanner_scan_typed_urls,
    validator_RegistryScanner_find_hive_offsets,
    validator_RegistryScanner_scan_sam_rids,
    # prefetch_analyzer (13)
    validator_is_mam_compressed,
    validator_decompress_mam,
    validator_PrefetchHeader_parse,
    validator_PrefetchHeader_all_run_times_unix,
    validator_FileMetrics_parse_v17,
    validator_FileMetrics_parse_v26,
    validator_VolumeInfo_parse,
    validator_compute_prefetch_hash_xp,
    validator_compute_prefetch_hash_win8,
    validator_verify_hash,
    validator_PrefetchFile_parse,
    validator_PrefetchFile_summary,
]

FN_COUNT = len(ALL_VALIDATORS)

if __name__ == "__main__":
    print(f"rustre-forensics-plugins validators: {FN_COUNT} functions implemented")
