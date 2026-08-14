#!/usr/bin/env python3
"""Independent stdlib-only validator for rustre-pe-tools.

Reimplements testable logic from the crate (entropy, checksums, Rich header,
RVA->offset, machine/subsystem maps, DLL characteristics flag names,
SecuritySummary score, manifest XML parsing, OID decode, string scan/classify,
overlay/SFX detection, basic PE parsing) using only the Python standard library
so outputs can be diff-checked against the Rust implementation.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import struct
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from typing import Any


# ---------- entropy / histogram ----------
def validator_byte_histogram(data: bytes) -> list[int]:
    h = [0] * 256
    for b in data:
        h[b] += 1
    return h


def validator_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    h = 0.0
    for c in Counter(data).values():
        p = c / n
        h -= p * math.log2(p)
    return h


def validator_most_common_byte(data: bytes) -> tuple[int, int]:
    if not data:
        return (0, 0)
    h = validator_byte_histogram(data)
    idx = max(range(256), key=lambda i: h[i])
    return (idx, h[idx])


def validator_is_likely_packed(data: bytes) -> bool:
    return validator_shannon_entropy(data) >= 7.2


# ---------- machine / subsystem ----------
_MACHINE = {
    0x014C: "I386",
    0x8664: "Amd64",
    0x01C0: "Arm",
    0xAA64: "Arm64",
    0x0166: "Mips32",
    0x5032: "Riscv32",
    0x5064: "Riscv64",
    0x0200: "Ia64",
}


def validator_machine_from_value(v: int) -> str:
    return _MACHINE.get(v, "Unknown")


def validator_machine_pointer_size(v: int) -> int:
    name = validator_machine_from_value(v)
    return 8 if name in ("Amd64", "Arm64", "Riscv64", "Ia64") else 4


def validator_machine_is_64bit(v: int) -> bool:
    return validator_machine_pointer_size(v) == 8


_SUBSYSTEM = {
    1: "Native",
    2: "WindowsGui",
    3: "WindowsCui",
    7: "PosixCui",
    10: "EfiApplication",
    11: "EfiBootDriver",
    12: "EfiRuntimeDriver",
    14: "Xbox",
}


def validator_subsystem_from_value(v: int) -> str:
    return _SUBSYSTEM.get(v, "Unknown")


def validator_subsystem_is_console(v: int) -> bool:
    return v in (3, 7)


def validator_subsystem_is_efi(v: int) -> bool:
    return v in (10, 11, 12)


# ---------- DLL characteristics ----------
_DLLCHAR_FLAGS = [
    (0x0020, "HIGH_ENTROPY_VA"),
    (0x0040, "DYNAMIC_BASE"),
    (0x0080, "FORCE_INTEGRITY"),
    (0x0100, "NX_COMPAT"),
    (0x0200, "NO_ISOLATION"),
    (0x0400, "NO_SEH"),
    (0x0800, "NO_BIND"),
    (0x1000, "APPCONTAINER"),
    (0x2000, "WDM_DRIVER"),
    (0x4000, "GUARD_CF"),
    (0x8000, "TERMINAL_SERVER_AWARE"),
]


def validator_dllchar_flag_names(v: int) -> list[str]:
    return [name for bit, name in _DLLCHAR_FLAGS if v & bit]


def validator_has_aslr(v: int) -> bool:
    return bool(v & 0x0040)


def validator_has_high_entropy_va(v: int) -> bool:
    return bool(v & 0x0020)


def validator_has_nx(v: int) -> bool:
    return bool(v & 0x0100)


def validator_has_cfg(v: int) -> bool:
    return bool(v & 0x4000)


def validator_no_seh(v: int) -> bool:
    return bool(v & 0x0400)


def validator_force_integrity(v: int) -> bool:
    return bool(v & 0x0080)


def validator_is_appcontainer(v: int) -> bool:
    return bool(v & 0x1000)


# ---------- security score (0-10) ----------
def validator_security_score(
    aslr: bool,
    high_entropy_va: bool,
    nx: bool,
    cfg: bool,
    no_seh: bool,
    force_integrity: bool,
    appcontainer: bool,
    is_signed: bool,
    has_tls: bool,
    is_dotnet: bool,
) -> int:
    s = 0
    if aslr:
        s += 2
    if high_entropy_va:
        s += 1
    if nx:
        s += 2
    if cfg:
        s += 2
    if no_seh:
        s += 1
    if force_integrity:
        s += 1
    if appcontainer:
        s += 1
    if is_signed:
        s += 1
    # has_tls / is_dotnet informational; cap at 10
    return min(s, 10)


# ---------- PE checksum (imagehlp-style) ----------
def validator_compute_pe_checksum(data: bytes, checksum_field_offset: int | None = None) -> int:
    """Imagehlp-style PE checksum. If checksum_field_offset is given, those 4 bytes
    are treated as zero in the sum (matching the in-file calculation)."""
    n = len(data)
    total = 0
    # process as 16-bit words, little-endian
    pairs = n // 2
    i = 0
    for w in range(pairs):
        off = w * 2
        if checksum_field_offset is not None and checksum_field_offset <= off < checksum_field_offset + 4:
            val = 0
        else:
            val = data[off] | (data[off + 1] << 8)
        total += val
        total = (total & 0xFFFF) + (total >> 16)
    if n & 1:
        total += data[n - 1]
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    total = total & 0xFFFF
    return (total + n) & 0xFFFFFFFF


# ---------- Rich header ----------
def validator_decode_rich_header(data: bytes) -> dict | None:
    """Locate and decode the Rich header within the PE DOS stub region."""
    # Search first 0x400 bytes
    region = data[:0x400]
    rich_idx = region.find(b"Rich")
    if rich_idx < 0 or rich_idx + 8 > len(region):
        return None
    xor_key = struct.unpack_from("<I", region, rich_idx + 4)[0]
    # Search backward for DanS (which is "DanS" ^ key)
    dans_marker = struct.pack("<I", 0x536E6144 ^ xor_key)  # "DanS"
    start = region.rfind(dans_marker, 0, rich_idx)
    if start < 0:
        return None
    # Entries follow DanS + 3 padding dwords; each entry is two dwords
    p = start + 16
    entries = []
    while p + 8 <= rich_idx:
        a = struct.unpack_from("<I", region, p)[0] ^ xor_key
        b = struct.unpack_from("<I", region, p + 4)[0] ^ xor_key
        product_id = (a >> 16) & 0xFFFF
        build_number = a & 0xFFFF
        count = b
        entries.append({
            "product_id": product_id,
            "build_number": build_number,
            "count": count,
        })
        p += 8
    return {"xor_key": xor_key, "entries": entries}


# ---------- RVA -> file offset ----------
def validator_rva_to_offset(rva: int, sections: list[dict]) -> int | None:
    for s in sections:
        va = s["virtual_address"]
        vsz = s.get("virtual_size") or s.get("raw_size", 0)
        if va <= rva < va + vsz:
            return s["raw_offset"] + (rva - va)
    return None


# ---------- overlay ----------
def validator_find_overlay_offset(sections: list[dict], file_size: int) -> int | None:
    if not sections:
        return None
    end = max(s["raw_offset"] + s["raw_size"] for s in sections)
    return end if end < file_size else None


_SFX_MAGICS = {
    b"7z\xbc\xaf\x27\x1c": "7zip",
    b"PK\x03\x04": "zip",
    b"Rar!\x1a\x07\x00": "rar",
    b"Rar!\x1a\x07\x01\x00": "rar5",
    b"MSCF": "cab",
}


def validator_detect_sfx_kind(data: bytes) -> str:
    window = data[: 4 * 1024 * 1024]
    for magic, kind in _SFX_MAGICS.items():
        if magic in window:
            return kind
    if b"Nullsoft" in window or b"NSIS" in window:
        return "nsis"
    if b"Inno Setup" in window:
        return "inno"
    return "none"


def validator_find_embedded_pe_offsets(data: bytes, skip_first: bool = True) -> list[int]:
    out = []
    i = 0
    first = True
    while True:
        i = data.find(b"MZ", i)
        if i < 0:
            break
        # check e_lfanew points to "PE\0\0"
        if i + 0x40 <= len(data):
            elfanew = struct.unpack_from("<I", data, i + 0x3C)[0]
            off = i + elfanew
            if 0 < elfanew < 0x10000 and off + 4 <= len(data) and data[off:off + 4] == b"PE\x00\x00":
                if not (first and skip_first):
                    out.append(i)
                first = False
        i += 1
    return out


# ---------- strings (ascii / utf16le) ----------
def validator_is_printable_ascii(b: int) -> bool:
    return 0x20 <= b < 0x7F or b == 0x09


def validator_extract_ascii_strings(data: bytes, min_len: int = 6) -> list[dict]:
    out = []
    start = None
    for i, b in enumerate(data):
        if validator_is_printable_ascii(b):
            if start is None:
                start = i
        else:
            if start is not None and i - start >= min_len:
                out.append({
                    "offset": start,
                    "value": data[start:i].decode("ascii", "replace"),
                    "encoding": "ascii",
                })
            start = None
    if start is not None and len(data) - start >= min_len:
        out.append({
            "offset": start,
            "value": data[start:].decode("ascii", "replace"),
            "encoding": "ascii",
        })
    return out


def validator_extract_utf16le_strings(data: bytes, min_len: int = 6) -> list[dict]:
    out = []
    start = None
    i = 0
    n = len(data) - 1
    while i < n:
        lo, hi = data[i], data[i + 1]
        if hi == 0 and validator_is_printable_ascii(lo):
            if start is None:
                start = i
            i += 2
        else:
            if start is not None:
                length = (i - start) // 2
                if length >= min_len:
                    s = data[start:i].decode("utf-16le", "replace")
                    out.append({"offset": start, "value": s, "encoding": "utf16le"})
            start = None
            i += 1
    if start is not None:
        length = (len(data) - start) // 2
        if length >= min_len:
            s = data[start : start + length * 2].decode("utf-16le", "replace")
            out.append({"offset": start, "value": s, "encoding": "utf16le"})
    return out


_STRING_CATEGORIES = [
    ("Url", re.compile(r"^(https?|ftp)://", re.I)),
    ("PathWin", re.compile(r"^[A-Za-z]:\\")),
    ("PathUnix", re.compile(r"^/(usr|etc|var|home|tmp)/")),
    ("Registry", re.compile(r"^(HKEY_|SOFTWARE\\|SYSTEM\\)", re.I)),
    ("Email", re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")),
    ("Guid", re.compile(r"\{[0-9A-Fa-f-]{36}\}")),
    ("Ip", re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")),
]


def validator_classify_string(s: str) -> str:
    for tag, rx in _STRING_CATEGORIES:
        if rx.search(s):
            return tag
    return "Other"


# ---------- API classification ----------
_API_CATEGORIES = {
    "Crypto": {
        "CryptAcquireContextA", "CryptAcquireContextW", "CryptEncrypt", "CryptDecrypt",
        "CryptHashData", "CryptCreateHash", "BCryptEncrypt", "BCryptDecrypt",
    },
    "Network": {
        "WSAStartup", "socket", "send", "recv", "connect", "bind", "listen",
        "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "HttpOpenRequestA",
        "WinHttpOpen", "WinHttpConnect",
    },
    "Process": {
        "CreateProcessA", "CreateProcessW", "OpenProcess", "TerminateProcess",
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "WriteProcessMemory",
        "ReadProcessMemory", "CreateRemoteThread",
    },
    "File": {
        "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "DeleteFileA",
        "DeleteFileW", "MoveFileA", "CopyFileA", "FindFirstFileA", "FindNextFileA",
    },
    "Registry": {
        "RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegSetValueExW",
        "RegQueryValueExA", "RegCreateKeyExA", "RegDeleteKeyA",
    },
    "Antidebug": {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugStringA", "GetTickCount", "QueryPerformanceCounter",
    },
}


def validator_classify_api(name: str) -> str:
    for cat, names in _API_CATEGORIES.items():
        if name in names:
            return cat
    return "Other"


# ---------- DLL / function name normalisation ----------
def validator_normalise_dll_name(dll: str) -> str:
    s = dll.lower()
    for ext in (".dll", ".ocx", ".sys"):
        if s.endswith(ext):
            s = s[: -len(ext)]
            break
    return s


# ---------- OID decode (ASN.1 DER) ----------
def validator_decode_oid(data: bytes) -> str:
    if not data:
        return ""
    first = data[0]
    parts = [str(first // 40), str(first % 40)]
    val = 0
    for b in data[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(str(val))
            val = 0
    return ".".join(parts)


_KNOWN_OIDS = {
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.7.1": "data",
    "1.2.840.113549.1.7.2": "signedData",
    "1.2.840.113549.1.9.3": "contentType",
    "1.2.840.113549.1.9.4": "messageDigest",
    "1.2.840.113549.1.9.5": "signingTime",
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "1.3.6.1.4.1.311.2.1.4": "spcIndirectDataContext",
    "1.3.6.1.4.1.311.2.1.11": "spcStatementType",
    "1.3.6.1.4.1.311.2.1.12": "spcSpOpusInfo",
}


def validator_known_oid_name(oid: str) -> str | None:
    return _KNOWN_OIDS.get(oid)


# ---------- manifest XML parsing ----------
def validator_parse_manifest_xml(xml_text: str) -> dict:
    out: dict[str, Any] = {
        "execution_level": None,
        "ui_access": None,
        "dpi_aware": None,
        "long_path_aware": None,
        "dependencies": [],
        "supported_os": [],
    }
    # strip namespaces for simple xpath
    text = re.sub(r"\sxmlns(:\w+)?=\"[^\"]+\"", "", xml_text)
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return out
    rl = root.find(".//requestedExecutionLevel")
    if rl is not None:
        out["execution_level"] = rl.get("level")
        ui = rl.get("uiAccess")
        if ui is not None:
            out["ui_access"] = ui.lower() == "true"
    dpi = root.find(".//dpiAware")
    if dpi is not None and dpi.text:
        out["dpi_aware"] = dpi.text.strip()
    lpa = root.find(".//longPathAware")
    if lpa is not None and lpa.text:
        out["long_path_aware"] = lpa.text.strip().lower() == "true"
    for dep in root.findall(".//dependency/dependentAssembly/assemblyIdentity"):
        out["dependencies"].append({
            "name": dep.get("name"),
            "version": dep.get("version"),
            "type": dep.get("type"),
            "processor_architecture": dep.get("processorArchitecture"),
            "public_key_token": dep.get("publicKeyToken"),
        })
    for os_elem in root.findall(".//supportedOS"):
        if os_elem.get("Id"):
            out["supported_os"].append(os_elem.get("Id"))
    return out


# ---------- section characteristics ----------
def validator_section_permission_string(characteristics: int) -> str:
    r = "r" if characteristics & 0x40000000 else "-"
    w = "w" if characteristics & 0x80000000 else "-"
    x = "x" if characteristics & 0x20000000 else "-"
    return r + w + x


def validator_section_contains_code(characteristics: int) -> bool:
    return bool(characteristics & 0x00000020)


def validator_section_contains_initialized_data(characteristics: int) -> bool:
    return bool(characteristics & 0x00000040)


def validator_section_is_executable(characteristics: int) -> bool:
    return bool(characteristics & 0x20000000)


def validator_section_is_writable(characteristics: int) -> bool:
    return bool(characteristics & 0x80000000)


def validator_section_is_readable(characteristics: int) -> bool:
    return bool(characteristics & 0x40000000)


# ---------- basic PE parse (stdlib only) ----------
def validator_parse_pe_basic(path: str) -> dict[str, Any]:
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("not a PE")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("missing PE signature")
    fh_off = e_lfanew + 4
    machine, num_sections, time_stamp, _sp, _sn, size_opt, characteristics = struct.unpack_from(
        "<HHIIIHH", data, fh_off
    )
    opt_off = fh_off + 20
    magic = struct.unpack_from("<H", data, opt_off)[0]
    is_64 = magic == 0x20B
    if is_64:
        # PE32+
        (_magic, _mlj, _mln, _scode, _sidata, _sudata, entry_point,
         _bcode, image_base) = struct.unpack_from("<HBBIIIIIQ", data, opt_off)
        sub_off = opt_off + 68
        subsystem = struct.unpack_from("<H", data, sub_off)[0]
        dllchar = struct.unpack_from("<H", data, sub_off + 2)[0]
        num_rva_off = opt_off + 108
    else:
        (_magic, _mlj, _mln, _scode, _sidata, _sudata, entry_point,
         _bcode, _bdata, image_base) = struct.unpack_from("<HBBIIIIIII", data, opt_off)
        sub_off = opt_off + 68
        subsystem = struct.unpack_from("<H", data, sub_off)[0]
        dllchar = struct.unpack_from("<H", data, sub_off + 2)[0]
        num_rva_off = opt_off + 92
    checksum = struct.unpack_from("<I", data, opt_off + 64)[0]
    num_rva_sizes = struct.unpack_from("<I", data, num_rva_off)[0]
    dd_off = num_rva_off + 4
    data_dirs = []
    for k in range(num_rva_sizes):
        rva, size = struct.unpack_from("<II", data, dd_off + k * 8)
        data_dirs.append({"rva": rva, "size": size})
    sec_off = opt_off + size_opt
    sections = []
    for i in range(num_sections):
        s = sec_off + i * 40
        name = data[s:s + 8].rstrip(b"\x00").decode("utf-8", "replace")
        vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, s + 8)
        chars = struct.unpack_from("<I", data, s + 36)[0]
        sections.append({
            "name": name,
            "virtual_address": vaddr,
            "virtual_size": vsize,
            "raw_offset": raddr,
            "raw_size": rsize,
            "characteristics": chars,
        })
    return {
        "machine": machine,
        "subsystem": subsystem,
        "image_base": image_base,
        "entry_point": entry_point,
        "is_dll": bool(characteristics & 0x2000),
        "is_64bit": is_64,
        "time_stamp": time_stamp,
        "checksum": checksum,
        "dll_characteristics": dllchar,
        "sections": sections,
        "data_dirs": data_dirs,
        "size": len(data),
    }


# ---------- dispatch ----------
_DISPATCH = {
    "byte_histogram": lambda i: validator_byte_histogram(bytes.fromhex(i["data_hex"])),
    "shannon_entropy": lambda i: validator_shannon_entropy(bytes.fromhex(i["data_hex"])),
    "most_common_byte": lambda i: validator_most_common_byte(bytes.fromhex(i["data_hex"])),
    "is_likely_packed": lambda i: validator_is_likely_packed(bytes.fromhex(i["data_hex"])),
    "machine_from_value": lambda i: validator_machine_from_value(i["value"]),
    "machine_pointer_size": lambda i: validator_machine_pointer_size(i["value"]),
    "machine_is_64bit": lambda i: validator_machine_is_64bit(i["value"]),
    "subsystem_from_value": lambda i: validator_subsystem_from_value(i["value"]),
    "subsystem_is_console": lambda i: validator_subsystem_is_console(i["value"]),
    "subsystem_is_efi": lambda i: validator_subsystem_is_efi(i["value"]),
    "dllchar_flag_names": lambda i: validator_dllchar_flag_names(i["value"]),
    "has_aslr": lambda i: validator_has_aslr(i["value"]),
    "has_high_entropy_va": lambda i: validator_has_high_entropy_va(i["value"]),
    "has_nx": lambda i: validator_has_nx(i["value"]),
    "has_cfg": lambda i: validator_has_cfg(i["value"]),
    "no_seh": lambda i: validator_no_seh(i["value"]),
    "force_integrity": lambda i: validator_force_integrity(i["value"]),
    "is_appcontainer": lambda i: validator_is_appcontainer(i["value"]),
    "security_score": lambda i: validator_security_score(
        i.get("aslr", False), i.get("high_entropy_va", False), i.get("nx", False),
        i.get("cfg", False), i.get("no_seh", False), i.get("force_integrity", False),
        i.get("appcontainer", False), i.get("is_signed", False),
        i.get("has_tls", False), i.get("is_dotnet", False),
    ),
    "compute_pe_checksum": lambda i: validator_compute_pe_checksum(
        bytes.fromhex(i["data_hex"]), i.get("checksum_field_offset")
    ),
    "decode_rich_header": lambda i: validator_decode_rich_header(bytes.fromhex(i["data_hex"])),
    "rva_to_offset": lambda i: validator_rva_to_offset(i["rva"], i["sections"]),
    "find_overlay_offset": lambda i: validator_find_overlay_offset(i["sections"], i["file_size"]),
    "detect_sfx_kind": lambda i: validator_detect_sfx_kind(bytes.fromhex(i["data_hex"])),
    "find_embedded_pe_offsets": lambda i: validator_find_embedded_pe_offsets(
        bytes.fromhex(i["data_hex"]), i.get("skip_first", True)
    ),
    "extract_ascii_strings": lambda i: validator_extract_ascii_strings(
        bytes.fromhex(i["data_hex"]), i.get("min_len", 6)
    ),
    "extract_utf16le_strings": lambda i: validator_extract_utf16le_strings(
        bytes.fromhex(i["data_hex"]), i.get("min_len", 6)
    ),
    "classify_string": lambda i: validator_classify_string(i["s"]),
    "classify_api": lambda i: validator_classify_api(i["name"]),
    "normalise_dll_name": lambda i: validator_normalise_dll_name(i["dll"]),
    "decode_oid": lambda i: validator_decode_oid(bytes.fromhex(i["data_hex"])),
    "known_oid_name": lambda i: validator_known_oid_name(i["oid"]),
    "parse_manifest_xml": lambda i: validator_parse_manifest_xml(i["xml"]),
    "section_permission_string": lambda i: validator_section_permission_string(i["value"]),
    "section_contains_code": lambda i: validator_section_contains_code(i["value"]),
    "section_contains_initialized_data": lambda i: validator_section_contains_initialized_data(i["value"]),
    "section_is_executable": lambda i: validator_section_is_executable(i["value"]),
    "section_is_writable": lambda i: validator_section_is_writable(i["value"]),
    "section_is_readable": lambda i: validator_section_is_readable(i["value"]),
    "parse_pe_basic": lambda i: validator_parse_pe_basic(i["path"]),
}


def main() -> None:
    if not sys.stdin.isatty():
        try:
            req = json.load(sys.stdin)
        except Exception:
            req = None
        if req:
            fn = req.get("function")
            inp = req.get("input", {})
            if fn not in _DISPATCH:
                print(json.dumps({"error": f"unknown function {fn}",
                                   "available": sorted(_DISPATCH)}))
                return
            out = _DISPATCH[fn](inp)
            print(json.dumps({"function": fn, "output": out}, default=str))
            return

    # smoke tests
    sample = b"Hello, World!\x00\x00\x00This is a test string for validator."
    print(json.dumps({
        "entropy": validator_shannon_entropy(sample),
        "most_common_byte": validator_most_common_byte(sample),
        "machine_amd64": validator_machine_from_value(0x8664),
        "subsystem_gui": validator_subsystem_from_value(2),
        "dllchar_flags": validator_dllchar_flag_names(0x4160),
        "security_score": validator_security_score(
            True, True, True, True, False, False, False, True, False, False
        ),
        "rich": validator_decode_rich_header(b"MZ" + b"\x00" * 40 + b"DanS\x00\x00\x00\x00" * 4 + b"Rich\x00\x00\x00\x00"),
        "classify_url": validator_classify_string("https://example.com"),
        "classify_api": validator_classify_api("CreateFileA"),
        "normalise_dll": validator_normalise_dll_name("KERNEL32.DLL"),
        "oid_rsa": validator_decode_oid(bytes.fromhex("2a864886f70d010101")),
        "oid_name": validator_known_oid_name("1.2.840.113549.1.1.1"),
        "sfx_zip": validator_detect_sfx_kind(b"PK\x03\x04somezipdata"),
        "perm": validator_section_permission_string(0x60000020),
        "ascii": validator_extract_ascii_strings(sample, 5),
        "manifest": validator_parse_manifest_xml(
            "<assembly><trustInfo><security><requestedPrivileges>"
            "<requestedExecutionLevel level='asInvoker' uiAccess='false'/>"
            "</requestedPrivileges></security></trustInfo></assembly>"
        ),
    }, indent=2, default=str))


if __name__ == "__main__":
    main()
