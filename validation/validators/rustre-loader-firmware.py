"""
Validators for rustre-loader-firmware crate.
Each validator_NAME(input) -> output mirrors the documented Rust function.
Uses Python stdlib only.
"""

import math
import struct
import re
from enum import Enum, auto
from typing import Optional, List, Tuple, Dict, Any

# ---------------------------------------------------------------------------
# Enums / simple types
# ---------------------------------------------------------------------------

class FirmwareKind(Enum):
    Raw = "raw"
    Elf = "elf"
    Pe = "pe"
    UBoot = "uboot"
    UBootFit = "uboot_fit"
    Uefi = "uefi"
    IHex = "ihex"
    Srec = "srec"
    Uf2 = "uf2"
    Unknown = "unknown"

class BinaryArch(Enum):
    X86 = "x86"
    X86_64 = "x86_64"
    Arm = "arm"
    Arm64 = "arm64"
    Mips = "mips"
    RiscV = "riscv"
    PowerPc = "powerpc"
    Unknown = "unknown"

class Endian(Enum):
    Little = "little"
    Big = "big"

class RtosKind(Enum):
    FreeRTOS = "FreeRTOS"
    VxWorks = "VxWorks"
    ThreadX = "ThreadX"
    Zephyr = "Zephyr"
    RTEMS = "RTEMS"
    Contiki = "Contiki"

class StringCategory(Enum):
    Url = "url"
    Ip = "ip"
    Credential = "credential"
    Path = "path"
    Generic = "generic"

class EntropyClass(Enum):
    Zero = 0
    VeryLow = 1
    Low = 2
    Medium = 3
    High = 4
    VeryHigh = 5

class FwRisk(Enum):
    Info = "info"
    Low = "low"
    Medium = "medium"
    High = "high"
    Critical = "critical"

class FilesystemType(Enum):
    SquashFS = "squashfs"
    CramFS = "cramfs"
    Jffs2 = "jffs2"
    Ext2 = "ext2"
    Fat = "fat"

class SignatureCategory(Enum):
    Kernel = "kernel"
    Filesystem = "filesystem"
    Bootloader = "bootloader"
    Uefi = "uefi"
    Compressed = "compressed"
    Unknown = "unknown"

# ---------------------------------------------------------------------------
# lib.rs — detection helpers
# ---------------------------------------------------------------------------

MAGIC_ELF = b'\x7fELF'
MAGIC_PE_DOS = b'MZ'
MAGIC_UBOOT = b'\x27\x05\x19\x56'
MAGIC_FDT = b'\xd0\x0d\xfe\xed'
MAGIC_UEFI_FV = b'_FVH'
MAGIC_IHEX_START = ord(':')
MAGIC_SQUASHFS_LE = b'sqsh'
MAGIC_SQUASHFS_BE = b'hsqs'
MAGIC_JFFS2 = b'\x85\x19'
MAGIC_UF2 = b'UF2\n'

def validator_detect_firmware_kind(data: bytes) -> FirmwareKind:
    """Identify firmware kind from magic bytes."""
    if data[:4] == MAGIC_ELF:
        return FirmwareKind.Elf
    if data[:2] == MAGIC_PE_DOS:
        return FirmwareKind.Pe
    if data[:4] == MAGIC_UBOOT:
        return FirmwareKind.UBoot
    if data[:4] == MAGIC_FDT:
        return FirmwareKind.UBootFit
    if MAGIC_UEFI_FV in data[:64]:
        return FirmwareKind.Uefi
    if len(data) > 0 and data[0] == MAGIC_IHEX_START:
        return FirmwareKind.IHex
    if data[:2] in (b'S0', b'S1', b'S2', b'S3'):
        return FirmwareKind.Srec
    if data[:4] == MAGIC_UF2:
        return FirmwareKind.Uf2
    return FirmwareKind.Raw

KNOWN_SIGS = [
    (b'\x1f\x8b', "gzip", SignatureCategory.Compressed),
    (b'BZh', "bzip2", SignatureCategory.Compressed),
    (b'\xfd7zXZ\x00', "xz", SignatureCategory.Compressed),
    (b'sqsh', "squashfs_le", SignatureCategory.Filesystem),
    (b'hsqs', "squashfs_be", SignatureCategory.Filesystem),
    (b'\x85\x19', "jffs2", SignatureCategory.Filesystem),
    (b'\x19\x85', "jffs2_be", SignatureCategory.Filesystem),
    (b'\x27\x05\x19\x56', "uboot_legacy", SignatureCategory.Bootloader),
    (b'\xd0\x0d\xfe\xed', "fdt_blob", SignatureCategory.Bootloader),
    (b'\x7fELF', "elf", SignatureCategory.Kernel),
    (b'_FVH', "uefi_fv", SignatureCategory.Uefi),
]

def validator_scan_embedded_signatures(data: bytes) -> list:
    """Scan for known embedded signatures, return list of dicts."""
    results = []
    for magic, name, category in KNOWN_SIGS:
        offset = 0
        while True:
            idx = data.find(magic, offset)
            if idx == -1:
                break
            results.append({"name": name, "offset": idx, "category": category.value})
            offset = idx + 1
    return results

ARCH_PATTERNS = {
    BinaryArch.X86_64: [b'\x48\x89', b'\x48\x8b', b'\x55\x48\x89\xe5'],
    BinaryArch.X86: [b'\x55\x89\xe5', b'\x8b\x55\x08'],
    BinaryArch.Arm: [b'\x00\x00\x2d\xe9', b'\xf0\x4f\x2d\xe9'],
    BinaryArch.Arm64: [b'\xfd\x7b\xbf\xa9', b'\x1f\x20\x03\xd5'],
    BinaryArch.Mips: [b'\x27\xbd\xff', b'\x3c\x1c\x00'],
    BinaryArch.RiscV: [b'\x13\x01\x01', b'\x93\x08\x10'],
    BinaryArch.PowerPc: [b'\x94\x21\xff', b'\x7c\x08\x02\xa6'],
}

def validator_detect_binary_arch(data: bytes) -> BinaryArch:
    """Estimate CPU arch via heuristic byte patterns."""
    scores: Dict[BinaryArch, int] = {a: 0 for a in BinaryArch}
    sample = data[:min(65536, len(data))]
    for arch, patterns in ARCH_PATTERNS.items():
        for p in patterns:
            scores[arch] += sample.count(p)
    best = max(scores, key=lambda a: scores[a])
    if scores[best] == 0:
        return BinaryArch.Unknown
    return best

def validator_detect_raw_endian(arch: BinaryArch) -> Optional[Endian]:
    """Return typical endianness for a given arch."""
    big_endian_arches = {BinaryArch.Mips, BinaryArch.PowerPc}
    little_endian_arches = {BinaryArch.X86, BinaryArch.X86_64, BinaryArch.Arm,
                             BinaryArch.Arm64, BinaryArch.RiscV}
    if arch in big_endian_arches:
        return Endian.Big
    if arch in little_endian_arches:
        return Endian.Little
    return None

RTOS_MARKERS = {
    RtosKind.FreeRTOS: [b'FreeRTOS', b'vTaskDelay', b'xTaskCreate'],
    RtosKind.VxWorks: [b'VxWorks', b'Wind River', b'taskSpawn'],
    RtosKind.ThreadX: [b'ThreadX', b'tx_thread_create'],
    RtosKind.Zephyr: [b'Zephyr', b'ZEPHYR_VERSION'],
    RtosKind.RTEMS: [b'RTEMS', b'rtems_task_create'],
    RtosKind.Contiki: [b'Contiki', b'PROCESS_BEGIN'],
}

def validator_detect_rtos(data: bytes) -> Optional[RtosKind]:
    """Detect RTOS by searching known strings."""
    for rtos, markers in RTOS_MARKERS.items():
        for m in markers:
            if m in data:
                return rtos
    return None

ARCH_HINT_STRINGS = {
    'arm': BinaryArch.Arm,
    'aarch64': BinaryArch.Arm64,
    'x86_64': BinaryArch.X86_64,
    'i686': BinaryArch.X86,
    'mips': BinaryArch.Mips,
    'riscv': BinaryArch.RiscV,
    'powerpc': BinaryArch.PowerPc,
}

def validator_detect_arch_hint(data: bytes) -> Optional[str]:
    """Extract architecture hint from readable strings."""
    text = data.decode('latin-1', errors='replace').lower()
    for hint, arch in ARCH_HINT_STRINGS.items():
        if hint in text:
            return arch.value
    return None

def validator_detect_endian_hint(data: bytes) -> Optional[str]:
    """Extract endianness hint from diagnostic strings."""
    text = data.decode('latin-1', errors='replace').lower()
    if 'little-endian' in text or 'little endian' in text:
        return 'little'
    if 'big-endian' in text or 'big endian' in text:
        return 'big'
    return None

BOOT_SECTION_TYPES = [
    (b'\xea\x00\x00\xea', 'reset_vector'),   # ARM reset
    (b'\xe9', 'jmp_entry'),                   # x86 jmp
    (b'\x27\x05\x19\x56', 'uboot_header'),
    (b'\x7fELF', 'elf_entry'),
]

def validator_detect_boot_sections(data: bytes, base: int) -> list:
    """Identify boot sections (entry point, reset vector, etc.)."""
    results = []
    for magic, sec_type in BOOT_SECTION_TYPES:
        idx = data.find(magic)
        if idx != -1:
            results.append({"offset": base + idx, "type": sec_type})
    return results

def validator_classify_string(s: str) -> StringCategory:
    """Classify a string by category."""
    if re.match(r'https?://', s) or re.match(r'ftp://', s):
        return StringCategory.Url
    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s):
        return StringCategory.Ip
    if any(kw in s.lower() for kw in ('password', 'passwd', 'secret', 'token', 'apikey', 'api_key')):
        return StringCategory.Credential
    if s.startswith('/') or re.match(r'^[A-Za-z]:\\', s):
        return StringCategory.Path
    return StringCategory.Generic

def validator_extract_firmware_strings(data: bytes, min_len: int) -> list:
    """Extract printable ASCII/UTF-8 strings of minimum length."""
    results = []
    pattern = re.compile(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}')
    for m in pattern.finditer(data):
        s = m.group().decode('ascii', errors='replace')
        results.append({"offset": m.start(), "value": s, "length": len(s)})
    return results

# ---------------------------------------------------------------------------
# entropy_analysis.rs
# ---------------------------------------------------------------------------

def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h

def validator_entropy_class_from_entropy(e: float) -> EntropyClass:
    if e == 0.0:
        return EntropyClass.Zero
    if e < 1.0:
        return EntropyClass.VeryLow
    if e < 3.0:
        return EntropyClass.Low
    if e < 5.5:
        return EntropyClass.Medium
    if e < 7.0:
        return EntropyClass.High
    return EntropyClass.VeryHigh

def validator_entropy_class_is_high(cls: EntropyClass) -> bool:
    return cls in (EntropyClass.High, EntropyClass.VeryHigh)

def validator_entropy_class_label(cls: EntropyClass) -> str:
    labels = {
        EntropyClass.Zero: "zero",
        EntropyClass.VeryLow: "very_low",
        EntropyClass.Low: "low",
        EntropyClass.Medium: "medium",
        EntropyClass.High: "high",
        EntropyClass.VeryHigh: "very_high",
    }
    return labels[cls]

def validator_entropy_class_typical_entropy(cls: EntropyClass) -> float:
    typical = {
        EntropyClass.Zero: 0.0,
        EntropyClass.VeryLow: 0.5,
        EntropyClass.Low: 2.0,
        EntropyClass.Medium: 4.5,
        EntropyClass.High: 6.5,
        EntropyClass.VeryHigh: 7.8,
    }
    return typical[cls]

def validator_entropy_region_end_offset(region: dict) -> int:
    return region["start"] + region["size"]

def validator_entropy_region_overlaps(region: dict, start: int, end: int) -> bool:
    r_start = region["start"]
    r_end = r_start + region["size"]
    return r_start < end and r_end > start

def validator_entropy_heatmap_peak(heatmap: list) -> Optional[Tuple[int, float]]:
    """heatmap: list of (offset, entropy) tuples."""
    if not heatmap:
        return None
    return max(heatmap, key=lambda x: x[1])

def validator_entropy_heatmap_trough(heatmap: list) -> Optional[Tuple[int, float]]:
    if not heatmap:
        return None
    return min(heatmap, key=lambda x: x[1])

def validator_entropy_heatmap_average(heatmap: list) -> float:
    if not heatmap:
        return 0.0
    return sum(e for _, e in heatmap) / len(heatmap)

def validator_entropy_heatmap_fraction_above(heatmap: list, threshold: float) -> float:
    if not heatmap:
        return 0.0
    above = sum(1 for _, e in heatmap if e >= threshold)
    return above / len(heatmap)

def validator_entropy_heatmap_samples_of_class(heatmap: list, cls: EntropyClass) -> list:
    return [(off, e) for off, e in heatmap
            if validator_entropy_class_from_entropy(e) == cls]

def validator_entropy_heatmap_ascii_bar(heatmap: list, width: int) -> str:
    if not heatmap:
        return ' ' * width
    chars = ' ░▒▓█'
    result = []
    step = max(1, len(heatmap) // width)
    for i in range(width):
        idx = i * step
        if idx < len(heatmap):
            e = heatmap[idx][1]
            level = min(4, int(e / 8.0 * 5))
            result.append(chars[level])
        else:
            result.append(' ')
    return ''.join(result)

def validator_entropy_analyzer_new(window_size: int, step_size: int, min_region_bytes: int) -> dict:
    return {"window_size": window_size, "step_size": step_size,
            "min_region_bytes": min_region_bytes}

def validator_entropy_analyzer_block_entropy(data: bytes) -> float:
    return _shannon_entropy(data)

def validator_entropy_analyzer_classify(e: float) -> EntropyClass:
    return validator_entropy_class_from_entropy(e)

def validator_entropy_analyzer_classify_block(analyzer: dict, data: bytes) -> EntropyClass:
    return validator_entropy_class_from_entropy(_shannon_entropy(data))

def validator_entropy_analyzer_sliding_entropy(analyzer: dict, data: bytes) -> list:
    ws = analyzer["window_size"]
    ss = analyzer["step_size"]
    results = []
    offset = 0
    while offset + ws <= len(data):
        e = _shannon_entropy(data[offset:offset + ws])
        results.append((offset, e))
        offset += ss
    return results

def validator_entropy_analyzer_heatmap(analyzer: dict, data: bytes) -> list:
    return validator_entropy_analyzer_sliding_entropy(analyzer, data)

def validator_entropy_analyzer_find_regions(analyzer: dict, data: bytes) -> list:
    heatmap = validator_entropy_analyzer_sliding_entropy(analyzer, data)
    min_bytes = analyzer["min_region_bytes"]
    regions = []
    current = None
    for off, e in heatmap:
        if validator_entropy_class_is_high(validator_entropy_class_from_entropy(e)):
            if current is None:
                current = {"start": off, "size": analyzer["window_size"]}
            else:
                current["size"] = (off - current["start"]) + analyzer["window_size"]
        else:
            if current and current["size"] >= min_bytes:
                regions.append(current)
            current = None
    if current and current["size"] >= min_bytes:
        regions.append(current)
    return regions

def validator_entropy_analyzer_class_distribution(analyzer: dict, data: bytes) -> list:
    heatmap = validator_entropy_analyzer_sliding_entropy(analyzer, data)
    dist = [0] * 6
    for _, e in heatmap:
        cls = validator_entropy_class_from_entropy(e)
        dist[cls.value] += 1
    return dist

def validator_entropy_analyzer_compressed_fraction(analyzer: dict, data: bytes) -> float:
    heatmap = validator_entropy_analyzer_sliding_entropy(analyzer, data)
    if not heatmap:
        return 0.0
    high = sum(1 for _, e in heatmap
               if validator_entropy_class_is_high(validator_entropy_class_from_entropy(e)))
    return high / len(heatmap)

def validator_entropy_analyzer_highest_entropy_offset(analyzer: dict, data: bytes) -> Optional[int]:
    heatmap = validator_entropy_analyzer_sliding_entropy(analyzer, data)
    if not heatmap:
        return None
    return max(heatmap, key=lambda x: x[1])[0]

def validator_entropy_analyzer_lowest_entropy_offset(analyzer: dict, data: bytes) -> Optional[int]:
    heatmap = validator_entropy_analyzer_sliding_entropy(analyzer, data)
    if not heatmap:
        return None
    return min(heatmap, key=lambda x: x[1])[0]

def validator_entropy_analyzer_is_high_entropy_blob(data: bytes) -> bool:
    e = _shannon_entropy(data)
    return e >= 7.0

def validator_entropy_report_analyse(data: bytes) -> dict:
    analyzer = validator_entropy_analyzer_new(256, 256, 512)
    heatmap = validator_entropy_analyzer_heatmap(analyzer, data)
    regions = validator_entropy_analyzer_find_regions(analyzer, data)
    overall = _shannon_entropy(data)
    return {
        "overall_entropy": overall,
        "entropy_class": validator_entropy_class_from_entropy(overall).value,
        "heatmap": heatmap,
        "high_entropy_regions": regions,
        "compressed_fraction": validator_entropy_analyzer_compressed_fraction(analyzer, data),
    }

# ---------------------------------------------------------------------------
# srec_parser.rs
# ---------------------------------------------------------------------------

class SrecType(Enum):
    S0 = 0
    S1 = 1
    S2 = 2
    S3 = 3
    S5 = 5
    S7 = 7
    S8 = 8
    S9 = 9

def validator_srec_type_from_char(c: int) -> SrecType:
    return SrecType(c - ord('0'))

def validator_srec_type_to_char(t: SrecType) -> int:
    return ord('0') + t.value

def validator_srec_type_addr_bytes(t: SrecType) -> int:
    if t in (SrecType.S1, SrecType.S9):
        return 2
    if t in (SrecType.S2, SrecType.S8):
        return 3
    return 4  # S0, S3, S7

def validator_srec_type_is_data(t: SrecType) -> bool:
    return t in (SrecType.S1, SrecType.S2, SrecType.S3)

def validator_srec_type_is_terminator(t: SrecType) -> bool:
    return t in (SrecType.S7, SrecType.S8, SrecType.S9)

def validator_srec_type_name(t: SrecType) -> str:
    names = {
        SrecType.S0: "header", SrecType.S1: "data_16", SrecType.S2: "data_24",
        SrecType.S3: "data_32", SrecType.S5: "record_count",
        SrecType.S7: "end_32", SrecType.S8: "end_24", SrecType.S9: "end_16",
    }
    return names.get(t, "unknown")

def _srec_parse_line(line: bytes) -> Optional[dict]:
    """Parse one SREC line, return dict or None on error."""
    if len(line) < 4 or line[0] != ord('S'):
        return None
    try:
        rec_type = SrecType(line[1] - ord('0'))
        byte_count = int(line[2:4], 16)
        body_hex = line[4:4 + byte_count * 2]
        body = bytes.fromhex(body_hex.decode('ascii'))
        # checksum = ~(sum of byte_count byte + body bytes) & 0xFF
        total = byte_count + sum(body[:-1])
        expected_cs = (~total) & 0xFF
        actual_cs = body[-1]
        addr_len = validator_srec_type_addr_bytes(rec_type)
        if addr_len == 2:
            addr = struct.unpack_from('>H', body)[0]
        elif addr_len == 3:
            addr = (body[0] << 16) | (body[1] << 8) | body[2]
        else:
            addr = struct.unpack_from('>I', body)[0]
        data_bytes = body[addr_len:-1]
        return {
            "rec_type": rec_type,
            "address": addr,
            "data": data_bytes,
            "checksum_valid": expected_cs == actual_cs,
        }
    except Exception:
        return None

def validator_srec_record_parse_line(line: bytes) -> dict:
    """Returns parsed record dict or raises ValueError."""
    result = _srec_parse_line(line)
    if result is None:
        raise ValueError(f"Invalid SREC line: {line!r}")
    return result

def validator_srec_record_to_srec_string(rec: dict) -> str:
    """Serialize an SREC record dict back to text."""
    t = rec["rec_type"]
    addr = rec["address"]
    data = rec["data"]
    addr_len = validator_srec_type_addr_bytes(t)
    if addr_len == 2:
        addr_bytes = struct.pack('>H', addr & 0xFFFF)
    elif addr_len == 3:
        addr_bytes = bytes([(addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF])
    else:
        addr_bytes = struct.pack('>I', addr & 0xFFFFFFFF)
    payload = addr_bytes + bytes(data)
    byte_count = len(payload) + 1
    cs = (~(byte_count + sum(payload))) & 0xFF
    hex_body = payload.hex().upper() + f"{cs:02X}"
    return f"S{t.value}{byte_count:02X}{hex_body}"

def validator_srec_segment_end_addr(seg: dict) -> int:
    return seg["address"] + len(seg["data"])

def validator_srec_segment_size(seg: dict) -> int:
    return len(seg["data"])

def validator_srec_segment_extend(seg: dict, extra: bytes) -> None:
    seg["data"] = seg["data"] + extra

def validator_srec_image_parse(data: bytes) -> dict:
    """Parse a complete SREC file."""
    lines = data.splitlines()
    records = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        rec = _srec_parse_line(line)
        if rec:
            records.append(rec)
    # Build segments
    segments = []
    entry = None
    for rec in records:
        if validator_srec_type_is_data(rec["rec_type"]):
            if segments and validator_srec_segment_end_addr(segments[-1]) == rec["address"]:
                segments[-1]["data"] += rec["data"]
            else:
                segments.append({"address": rec["address"], "data": bytearray(rec["data"])})
        elif validator_srec_type_is_terminator(rec["rec_type"]):
            entry = rec["address"]
    return {"segments": segments, "entry": entry, "records": records}

def validator_srec_image_build_binary_image(image: dict, base: Optional[int], fill_byte: int) -> bytes:
    segs = image["segments"]
    if not segs:
        return b''
    min_addr = min(s["address"] for s in segs)
    max_addr = max(s["address"] + len(s["data"]) for s in segs)
    if base is not None:
        min_addr = base
    size = max_addr - min_addr
    buf = bytearray([fill_byte] * size)
    for s in segs:
        off = s["address"] - min_addr
        data = bytes(s["data"])
        buf[off:off + len(data)] = data
    return bytes(buf)

def validator_srec_image_total_data_bytes(image: dict) -> int:
    return sum(len(s["data"]) for s in image["segments"])

def validator_srec_image_min_address(image: dict) -> Optional[int]:
    if not image["segments"]:
        return None
    return min(s["address"] for s in image["segments"])

def validator_srec_image_max_address(image: dict) -> Optional[int]:
    if not image["segments"]:
        return None
    return max(s["address"] + len(s["data"]) for s in image["segments"])

def validator_srec_image_gap_count(image: dict) -> int:
    segs = sorted(image["segments"], key=lambda s: s["address"])
    count = 0
    for i in range(1, len(segs)):
        if segs[i]["address"] > segs[i-1]["address"] + len(segs[i-1]["data"]):
            count += 1
    return count

def validator_srec_image_total_gap_bytes(image: dict) -> int:
    segs = sorted(image["segments"], key=lambda s: s["address"])
    total = 0
    for i in range(1, len(segs)):
        gap = segs[i]["address"] - (segs[i-1]["address"] + len(segs[i-1]["data"]))
        if gap > 0:
            total += gap
    return total

def validator_srec_image_effective_entry(image: dict) -> Optional[int]:
    return image.get("entry")

def validator_srec_image_has_32bit_addresses(image: dict) -> bool:
    for rec in image.get("records", []):
        if rec["rec_type"] in (SrecType.S3, SrecType.S7):
            return True
    return False

def validator_encode_to_srec(data: bytes, base_address: int, bytes_per_record: int) -> str:
    """Encode binary buffer to SREC text."""
    lines = []
    # S0 header
    header_payload = struct.pack('>H', 0) + b'HDR\x00'
    bc = len(header_payload) + 1
    cs = (~(bc + sum(header_payload))) & 0xFF
    lines.append(f"S0{bc:02X}{header_payload.hex().upper()}{cs:02X}")
    for i in range(0, len(data), bytes_per_record):
        chunk = data[i:i + bytes_per_record]
        addr = base_address + i
        addr_bytes = struct.pack('>I', addr & 0xFFFFFFFF)
        payload = addr_bytes + chunk
        bc2 = len(payload) + 1
        cs2 = (~(bc2 + sum(payload))) & 0xFF
        lines.append(f"S3{bc2:02X}{payload.hex().upper()}{cs2:02X}")
    # S7 terminator
    term_payload = struct.pack('>I', base_address)
    bc3 = len(term_payload) + 1
    cs3 = (~(bc3 + sum(term_payload))) & 0xFF
    lines.append(f"S7{bc3:02X}{term_payload.hex().upper()}{cs3:02X}")
    return '\n'.join(lines)

# ---------------------------------------------------------------------------
# intel_hex.rs
# ---------------------------------------------------------------------------

class IHexRecordType(Enum):
    Data = 0
    EOF = 1
    ExtSeg = 2
    StartSeg = 3
    ExtLinear = 4
    StartLinear = 5

def validator_ihex_record_type_from_byte(b: int) -> IHexRecordType:
    return IHexRecordType(b)

def validator_ihex_record_type_to_byte(t: IHexRecordType) -> int:
    return t.value

def validator_ihex_record_type_name(t: IHexRecordType) -> str:
    names = {
        IHexRecordType.Data: "data",
        IHexRecordType.EOF: "eof",
        IHexRecordType.ExtSeg: "ext_segment",
        IHexRecordType.StartSeg: "start_segment",
        IHexRecordType.ExtLinear: "ext_linear",
        IHexRecordType.StartLinear: "start_linear",
    }
    return names[t]

def _ihex_parse_line(line: bytes) -> Optional[dict]:
    line = line.strip()
    if not line or line[0] != ord(':'):
        return None
    try:
        hex_str = line[1:].decode('ascii')
        raw = bytes.fromhex(hex_str)
        byte_count = raw[0]
        address = struct.unpack_from('>H', raw, 1)[0]
        rec_type = IHexRecordType(raw[3])
        data = raw[4:4 + byte_count]
        checksum = raw[4 + byte_count]
        total = sum(raw[:4 + byte_count]) & 0xFF
        cs_valid = ((total + checksum) & 0xFF) == 0
        return {"rec_type": rec_type, "address": address,
                "data": data, "checksum_valid": cs_valid}
    except Exception:
        return None

def validator_ihex_record_parse_line(line: bytes) -> dict:
    result = _ihex_parse_line(line)
    if result is None:
        raise ValueError(f"Invalid Intel HEX line: {line!r}")
    return result

def validator_ihex_record_to_hex_string(rec: dict) -> str:
    data = bytes(rec["data"])
    addr = rec["address"]
    rec_type = rec["rec_type"]
    raw = bytes([len(data)]) + struct.pack('>H', addr & 0xFFFF) + bytes([rec_type.value]) + data
    cs = (-(sum(raw))) & 0xFF
    return ':' + (raw + bytes([cs])).hex().upper()

def validator_ihex_segment_end_addr(seg: dict) -> int:
    return seg["address"] + len(seg["data"])

def validator_ihex_segment_contains(seg: dict, addr: int) -> bool:
    return seg["address"] <= addr < seg["address"] + len(seg["data"])

def validator_ihex_segment_extend(seg: dict, extra: bytes) -> None:
    seg["data"] = seg["data"] + extra

def validator_ihex_segment_size(seg: dict) -> int:
    return len(seg["data"])

def validator_ihex_image_parse(data: bytes) -> dict:
    lines = data.splitlines()
    segments = []
    entry = None
    base_linear = 0
    base_seg = 0
    for line in lines:
        rec = _ihex_parse_line(line)
        if rec is None:
            continue
        t = rec["rec_type"]
        if t == IHexRecordType.Data:
            addr = base_linear + base_seg + rec["address"]
            if segments and validator_ihex_segment_end_addr(segments[-1]) == addr:
                segments[-1]["data"] += rec["data"]
            else:
                segments.append({"address": addr, "data": bytearray(rec["data"])})
        elif t == IHexRecordType.ExtLinear:
            base_linear = struct.unpack_from('>H', rec["data"])[0] << 16
        elif t == IHexRecordType.ExtSeg:
            base_seg = struct.unpack_from('>H', rec["data"])[0] << 4
        elif t == IHexRecordType.StartLinear:
            entry = struct.unpack_from('>I', rec["data"])[0]
        elif t == IHexRecordType.StartSeg:
            cs = struct.unpack_from('>H', rec["data"])[0]
            ip = struct.unpack_from('>H', rec["data"], 2)[0]
            entry = (cs << 4) + ip
    return {"segments": segments, "entry": entry}

def validator_ihex_image_build_binary_image(image: dict, base: Optional[int], fill_byte: int) -> bytes:
    segs = image["segments"]
    if not segs:
        return b''
    min_addr = min(s["address"] for s in segs) if base is None else base
    max_addr = max(s["address"] + len(s["data"]) for s in segs)
    buf = bytearray([fill_byte] * (max_addr - min_addr))
    for s in segs:
        off = s["address"] - min_addr
        d = bytes(s["data"])
        buf[off:off + len(d)] = d
    return bytes(buf)

def validator_ihex_image_min_address(image: dict) -> Optional[int]:
    if not image["segments"]:
        return None
    return min(s["address"] for s in image["segments"])

def validator_ihex_image_max_address(image: dict) -> Optional[int]:
    if not image["segments"]:
        return None
    return max(s["address"] + len(s["data"]) for s in image["segments"])

def validator_ihex_image_total_data_bytes(image: dict) -> int:
    return sum(len(s["data"]) for s in image["segments"])

def validator_ihex_image_gap_count(image: dict) -> int:
    segs = sorted(image["segments"], key=lambda s: s["address"])
    count = 0
    for i in range(1, len(segs)):
        if segs[i]["address"] > segs[i-1]["address"] + len(segs[i-1]["data"]):
            count += 1
    return count

def validator_ihex_image_total_gap_bytes(image: dict) -> int:
    segs = sorted(image["segments"], key=lambda s: s["address"])
    total = 0
    for i in range(1, len(segs)):
        gap = segs[i]["address"] - (segs[i-1]["address"] + len(segs[i-1]["data"]))
        if gap > 0:
            total += gap
    return total

def validator_ihex_image_entry_point(image: dict) -> Optional[int]:
    return image.get("entry")

def validator_ihex_checksum(body: bytes) -> int:
    return (-(sum(body))) & 0xFF

def validator_encode_to_ihex(data: bytes, base_address: int, bytes_per_record: int) -> str:
    lines = []
    # Extended Linear Address record if needed
    upper = (base_address >> 16) & 0xFFFF
    if upper:
        addr_bytes = struct.pack('>H', upper)
        raw = bytes([2, 0, 0, 4]) + addr_bytes
        cs = (-(sum(raw))) & 0xFF
        lines.append(':' + (raw + bytes([cs])).hex().upper())
    for i in range(0, len(data), bytes_per_record):
        chunk = data[i:i + bytes_per_record]
        addr = (base_address + i) & 0xFFFF
        raw = bytes([len(chunk)]) + struct.pack('>H', addr) + bytes([0]) + chunk
        cs = (-(sum(raw))) & 0xFF
        lines.append(':' + (raw + bytes([cs])).hex().upper())
    lines.append(':00000001FF')
    return '\n'.join(lines)

# ---------------------------------------------------------------------------
# uboot_parser.rs
# ---------------------------------------------------------------------------

class UBootOsType(Enum):
    Invalid = 0
    OpenBSD = 1
    NetBSD = 2
    FreeBSD = 3
    BSD4_4 = 4
    Linux = 5
    Svr4 = 6
    Esix = 7
    Solaris = 8
    Irix = 9
    Sco = 10
    Dell = 11
    Ncr = 12
    LynxOS = 13
    VxWorks = 14
    Psos = 15
    QNX = 16
    UBoot = 17
    RTEMS = 18
    ARTOS = 19
    Unity = 20
    INTEGRITY = 21

def validator_uboot_os_type_from_byte(b: int) -> UBootOsType:
    try:
        return UBootOsType(b)
    except ValueError:
        return UBootOsType.Invalid

def validator_uboot_os_type_as_str(t: UBootOsType) -> str:
    names = {
        UBootOsType.Invalid: "invalid", UBootOsType.Linux: "linux",
        UBootOsType.VxWorks: "vxworks", UBootOsType.FreeBSD: "freebsd",
        UBootOsType.NetBSD: "netbsd", UBootOsType.RTEMS: "rtems",
        UBootOsType.QNX: "qnx", UBootOsType.UBoot: "u-boot",
    }
    return names.get(t, t.name.lower())

class UBootArchType(Enum):
    Invalid = 0
    Alpha = 1
    Arm = 2
    X86 = 3
    IA64 = 4
    Mips = 5
    Mips64 = 6
    Ppc = 7
    S390 = 8
    Sh = 9
    Sparc = 10
    Sparc64 = 11
    M68k = 12
    Nios = 13
    MicroBlaze = 14
    Nios2 = 15
    Blackfin = 16
    Avr32 = 17
    St200 = 18
    Sandbox = 19
    Nlm = 20
    Mor1kx = 21
    Microblaze = 22
    Arm64 = 22
    X86_64 = 23
    Xtensa = 24
    Nios2b = 25

def validator_uboot_arch_type_from_byte(b: int) -> UBootArchType:
    try:
        return UBootArchType(b)
    except ValueError:
        return UBootArchType.Invalid

def validator_uboot_arch_type_as_str(t: UBootArchType) -> str:
    names = {
        UBootArchType.Arm: "arm", UBootArchType.Arm64: "arm64",
        UBootArchType.X86: "x86", UBootArchType.X86_64: "x86_64",
        UBootArchType.Mips: "mips", UBootArchType.Ppc: "powerpc",
    }
    return names.get(t, t.name.lower())

class UBootImageType(Enum):
    Invalid = 0
    Standalone = 1
    Kernel = 2
    Ramdisk = 3
    Multi = 4
    Firmware = 5
    Script = 6
    Filesystem = 7
    FlatDt = 8
    Kwbimage = 9
    Imximage = 10
    Ubootsdk = 11

def validator_uboot_image_type_from_byte(b: int) -> UBootImageType:
    try:
        return UBootImageType(b)
    except ValueError:
        return UBootImageType.Invalid

def validator_uboot_image_type_as_str(t: UBootImageType) -> str:
    names = {
        UBootImageType.Standalone: "standalone",
        UBootImageType.Kernel: "kernel",
        UBootImageType.Ramdisk: "ramdisk",
        UBootImageType.Multi: "multi",
        UBootImageType.Firmware: "firmware",
        UBootImageType.Script: "script",
        UBootImageType.Filesystem: "filesystem",
        UBootImageType.FlatDt: "flat_dt",
    }
    return names.get(t, t.name.lower())

class UBootCompressionType(Enum):
    NoCompression = 0
    Gzip = 1
    Bzip2 = 2
    Lzma = 3
    Lzo = 4
    Lz4 = 5
    Zstd = 6

def validator_uboot_compression_type_from_byte(b: int) -> UBootCompressionType:
    try:
        return UBootCompressionType(b)
    except ValueError:
        return UBootCompressionType.NoCompression

def validator_uboot_compression_type_as_str(t: UBootCompressionType) -> str:
    names = {
        UBootCompressionType.NoCompression: "none",
        UBootCompressionType.Gzip: "gzip",
        UBootCompressionType.Bzip2: "bzip2",
        UBootCompressionType.Lzma: "lzma",
        UBootCompressionType.Lzo: "lzo",
        UBootCompressionType.Lz4: "lz4",
        UBootCompressionType.Zstd: "zstd",
    }
    return names.get(t, "unknown")

UBOOT_LEGACY_MAGIC = 0x27051956
UBOOT_HEADER_SIZE = 64

def validator_uboot_legacy_header_parse(data: bytes) -> dict:
    if len(data) < UBOOT_HEADER_SIZE:
        raise ValueError("Data too short for U-Boot header")
    magic = struct.unpack_from('>I', data, 0)[0]
    if magic != UBOOT_LEGACY_MAGIC:
        raise ValueError(f"Bad U-Boot magic: {magic:#x}")
    hcrc   = struct.unpack_from('>I', data, 4)[0]
    time   = struct.unpack_from('>I', data, 8)[0]
    size   = struct.unpack_from('>I', data, 12)[0]
    load   = struct.unpack_from('>I', data, 16)[0]
    ep     = struct.unpack_from('>I', data, 20)[0]
    dcrc   = struct.unpack_from('>I', data, 24)[0]
    os     = validator_uboot_os_type_from_byte(data[28])
    arch   = validator_uboot_arch_type_from_byte(data[29])
    img    = validator_uboot_image_type_from_byte(data[30])
    comp   = validator_uboot_compression_type_from_byte(data[31])
    name   = data[32:64].split(b'\x00')[0].decode('latin-1')
    return {
        "magic": magic, "hcrc": hcrc, "timestamp": time,
        "data_size": size, "load_addr": load, "entry_point": ep,
        "data_crc": dcrc, "os": os, "arch": arch,
        "image_type": img, "compression": comp, "name": name,
    }

def validator_uboot_legacy_header_payload(header: dict, data: bytes) -> Optional[bytes]:
    size = header["data_size"]
    if len(data) >= UBOOT_HEADER_SIZE + size:
        return data[UBOOT_HEADER_SIZE:UBOOT_HEADER_SIZE + size]
    return None

def validator_uboot_legacy_header_total_size(header: dict) -> int:
    return UBOOT_HEADER_SIZE + header["data_size"]

def validator_fdt_property_as_str(prop: dict) -> Optional[str]:
    try:
        return prop["data"].rstrip(b'\x00').decode('utf-8')
    except Exception:
        return None

def validator_fdt_property_as_u32_be(prop: dict) -> Optional[int]:
    if len(prop["data"]) >= 4:
        return struct.unpack_from('>I', prop["data"])[0]
    return None

def validator_fdt_property_as_u64_be(prop: dict) -> Optional[int]:
    if len(prop["data"]) >= 8:
        return struct.unpack_from('>Q', prop["data"])[0]
    return None

def validator_fdt_node_prop(node: dict, name: str) -> Optional[dict]:
    return node.get("properties", {}).get(name)

def validator_fdt_node_data_prop(node: dict) -> Optional[bytes]:
    p = validator_fdt_node_prop(node, "data")
    if p:
        return p["data"]
    return None

def validator_fdt_node_child(node: dict, name: str) -> Optional[dict]:
    for child in node.get("children", []):
        if child.get("name") == name:
            return child
    return None

def validator_fdt_node_full_name(node: dict) -> str:
    return node.get("name", "/")

FDT_MAGIC = 0xD00DFEED

def validator_fdt_parser_new(data: bytes) -> dict:
    if len(data) < 8:
        raise ValueError("Data too short for FDT")
    magic = struct.unpack_from('>I', data, 0)[0]
    if magic != FDT_MAGIC:
        raise ValueError(f"Bad FDT magic: {magic:#x}")
    total_size = struct.unpack_from('>I', data, 4)[0]
    return {"data": data, "total_size": total_size}

def validator_fdt_parser_parse_tree(parser: dict) -> dict:
    """Stub: return minimal tree root."""
    return {"name": "/", "properties": {}, "children": []}

def validator_fit_image_bundle_parse(data: bytes) -> dict:
    """Parse FIT image (FDT-based), stub returning minimal structure."""
    if len(data) < 8:
        raise ValueError("Data too short")
    magic = struct.unpack_from('>I', data, 0)[0]
    if magic != FDT_MAGIC:
        raise ValueError("Not a FIT image")
    return {"images": {}, "configurations": {}, "kernel": None,
            "ramdisk": None, "fdt": None}

def validator_fit_image_bundle_kernel(bundle: dict) -> Optional[dict]:
    return bundle.get("kernel")

def validator_fit_image_bundle_ramdisk(bundle: dict) -> Optional[dict]:
    return bundle.get("ramdisk")

def validator_fit_image_bundle_fdt(bundle: dict) -> Optional[dict]:
    return bundle.get("fdt")

def validator_uboot_image_parse(data: bytes) -> dict:
    if len(data) >= 8 and struct.unpack_from('>I', data, 0)[0] == FDT_MAGIC:
        bundle = validator_fit_image_bundle_parse(data)
        return {"is_fit": True, "fit": bundle, "legacy": None}
    header = validator_uboot_legacy_header_parse(data)
    return {"is_fit": False, "fit": None, "legacy": header}

def validator_uboot_image_is_fit(image: dict) -> bool:
    return image["is_fit"]

def validator_uboot_image_is_legacy(image: dict) -> bool:
    return not image["is_fit"]

def validator_uboot_image_entry_point(image: dict) -> Optional[int]:
    if image["is_fit"]:
        return None
    if image["legacy"]:
        return image["legacy"]["entry_point"]
    return None

def validator_uboot_image_load_address(image: dict) -> Optional[int]:
    if image["is_fit"]:
        return None
    if image["legacy"]:
        return image["legacy"]["load_addr"]
    return None

# ---------------------------------------------------------------------------
# uefi_analysis.rs
# ---------------------------------------------------------------------------

Guid = Tuple[int, int, int, bytes]  # (data1, data2, data3, data4[8])

def validator_format_guid(g: tuple) -> str:
    """Format GUID as {8-4-4-4-12}."""
    d1, d2, d3, d4 = g
    d4_hex = d4.hex()
    return (f"{{{d1:08X}-{d2:04X}-{d3:04X}-"
            f"{d4_hex[:4].upper()}-{d4_hex[4:].upper()}}}")

def validator_guid_database_new() -> dict:
    return {"entries": {}}

STANDARD_GUIDS = {
    (0x8BE4DF61, 0x93CA, 0x11D2, bytes.fromhex('AA0D00E098032B8C')): "EFI_GLOBAL_VARIABLE",
    (0x7739F24C, 0x93D7, 0x11D4, bytes.fromhex('9A3800905A4F197F')): "EFI_HOB_LIST_GUID",
}

def validator_guid_database_load_standard() -> dict:
    db = validator_guid_database_new()
    for guid, name in STANDARD_GUIDS.items():
        db["entries"][guid] = name
    return db

def validator_guid_database_insert(db: dict, guid: tuple, name: str) -> None:
    db["entries"][guid] = name

def validator_guid_database_lookup(db: dict, guid: tuple) -> Optional[str]:
    return db["entries"].get(guid)

def validator_guid_database_len(db: dict) -> int:
    return len(db["entries"])

def validator_guid_database_is_empty(db: dict) -> bool:
    return len(db["entries"]) == 0

class FfsFileType(Enum):
    All = 0x00
    Raw = 0x01
    FreeForm = 0x02
    SecurityCore = 0x03
    PeiCore = 0x04
    DxeCore = 0x05
    Peim = 0x06
    Driver = 0x07
    CombinedPeimDriver = 0x08
    Application = 0x09
    SmmCore = 0x0D
    Unknown = 0xFF

def validator_ffs_file_type_from_u8(v: int) -> FfsFileType:
    try:
        return FfsFileType(v)
    except ValueError:
        return FfsFileType.Unknown

def validator_ffs_file_type_is_executable(t: FfsFileType) -> bool:
    return t in (FfsFileType.Driver, FfsFileType.Application, FfsFileType.DxeCore,
                 FfsFileType.PeiCore, FfsFileType.Peim, FfsFileType.SmmCore,
                 FfsFileType.CombinedPeimDriver)

class HiiPackageType(Enum):
    TypeAll = 0x00
    Guid = 0x01
    Strings = 0x04
    Fonts = 0x05
    Images = 0x06
    SimpleFonts = 0x07
    DevicePath = 0x08
    Keyboard = 0x09
    Handles = 0x0A
    Animation = 0x0C
    Forms = 0x02
    Unknown = 0xFF

def validator_hii_package_type_from_u8(v: int) -> HiiPackageType:
    try:
        return HiiPackageType(v)
    except ValueError:
        return HiiPackageType.Unknown

def validator_hii_package_type_is_user_visible(t: HiiPackageType) -> bool:
    return t in (HiiPackageType.Forms, HiiPackageType.Strings, HiiPackageType.Images)

def validator_hii_package_new(pkg_type: HiiPackageType, data: bytes) -> dict:
    return {"pkg_type": pkg_type, "data": data}

EFI_FVH_MAGIC = b'_FVH'

def validator_efi_fv_header_verify_header(hdr_data: bytes) -> dict:
    magic = hdr_data[40:44] if len(hdr_data) >= 44 else b''
    fv_length = struct.unpack_from('<Q', hdr_data, 32)[0] if len(hdr_data) >= 40 else 0
    return {"magic": magic, "fv_length": fv_length,
            "valid": magic == EFI_FVH_MAGIC and fv_length > 0}

def validator_efi_fv_header_is_valid(header: dict) -> bool:
    return header.get("valid", False)

def validator_efi_ffs_new(guid: tuple, file_type: FfsFileType, size: int) -> dict:
    return {"guid": guid, "file_type": file_type, "size": size, "sections": []}

def validator_efi_ffs_guid_str(ffs: dict) -> str:
    return validator_format_guid(ffs["guid"])

class EfiSectionType(Enum):
    Compression = 0x01
    GuidDefined = 0x02
    Disposable = 0x19
    Pe32 = 0x10
    Pic = 0x11
    Te = 0x12
    DxeDepex = 0x13
    Version = 0x14
    UserInterface = 0x15
    Compatibility16 = 0x16
    FirmwareVolumeImage = 0x17
    FreeformSubtypeGuid = 0x18
    Raw = 0x19
    PeiDepex = 0x1B
    SmmDepex = 0x1C
    Unknown = 0xFF

def validator_efi_section_type_from_u8(v: int) -> EfiSectionType:
    try:
        return EfiSectionType(v)
    except ValueError:
        return EfiSectionType.Unknown

def validator_efi_section_type_is_executable(t: EfiSectionType) -> bool:
    return t in (EfiSectionType.Pe32, EfiSectionType.Te)

def validator_efi_section_type_is_dependency(t: EfiSectionType) -> bool:
    return t in (EfiSectionType.DxeDepex, EfiSectionType.PeiDepex, EfiSectionType.SmmDepex)

def validator_efi_section_new(section_type: EfiSectionType, raw_data: bytes) -> dict:
    return {"section_type": section_type, "raw_data": raw_data}

def validator_efi_ffs_find_section(ffs: dict, sec_type: EfiSectionType) -> Optional[dict]:
    for sec in ffs.get("sections", []):
        if sec["section_type"] == sec_type:
            return sec
    return None

def validator_efi_ffs_has_pe(ffs: dict) -> bool:
    return validator_efi_ffs_find_section(ffs, EfiSectionType.Pe32) is not None or \
           validator_efi_ffs_find_section(ffs, EfiSectionType.Te) is not None

def validator_efi_firmware_volume_parse(data: bytes, offset: int) -> dict:
    hdr = validator_efi_fv_header_verify_header(data[offset:offset + 72] if len(data) > offset + 72 else b'')
    return {"header": hdr, "files": [], "offset": offset}

def validator_efi_firmware_volume_find_file(fv: dict, guid: tuple) -> Optional[dict]:
    for f in fv["files"]:
        if f["guid"] == guid:
            return f
    return None

def validator_efi_firmware_volume_executable_files(fv: dict) -> list:
    return [f for f in fv["files"] if validator_ffs_file_type_is_executable(f["file_type"])]

def validator_efi_firmware_volume_pe_files(fv: dict) -> list:
    return [f for f in fv["files"] if validator_efi_ffs_has_pe(f)]

def validator_depex_expression_new() -> dict:
    return {"ops": []}

DEPEX_TRUE = 0x06
DEPEX_FALSE = 0x07
DEPEX_PUSH_GUID = 0x02
DEPEX_END = 0x08

def validator_depex_expression_parse(data: bytes) -> dict:
    ops = []
    guids = []
    i = 0
    while i < len(data):
        op = data[i]
        if op == DEPEX_PUSH_GUID and i + 17 <= len(data):
            raw = data[i+1:i+17]
            d1 = struct.unpack_from('<I', raw, 0)[0]
            d2 = struct.unpack_from('<H', raw, 4)[0]
            d3 = struct.unpack_from('<H', raw, 6)[0]
            d4 = raw[8:16]
            guids.append((d1, d2, d3, d4))
            ops.append({"op": "push_guid", "guid": (d1, d2, d3, d4)})
            i += 17
        elif op == DEPEX_TRUE:
            ops.append({"op": "true"})
            i += 1
        elif op == DEPEX_FALSE:
            ops.append({"op": "false"})
            i += 1
        elif op == DEPEX_END:
            ops.append({"op": "end"})
            break
        else:
            ops.append({"op": f"unknown_{op:#x}"})
            i += 1
    return {"ops": ops, "guids": guids}

def validator_depex_expression_referenced_guids(expr: dict) -> list:
    return expr.get("guids", [])

def validator_depex_expression_is_always_true(expr: dict) -> bool:
    ops = expr.get("ops", [])
    return len(ops) == 2 and ops[0].get("op") == "true" and ops[1].get("op") == "end"

def validator_depex_expression_len(expr: dict) -> int:
    return len(expr.get("ops", []))

def validator_depex_expression_is_empty(expr: dict) -> bool:
    return len(expr.get("ops", [])) == 0

def validator_efi_fv_block_map_entry_new(num_blocks: int, block_length: int) -> dict:
    return {"num_blocks": num_blocks, "block_length": block_length}

def validator_efi_fv_block_map_entry_total_bytes(entry: dict) -> int:
    return entry["num_blocks"] * entry["block_length"]

def validator_efi_fv_block_map_entry_is_terminator(entry: dict) -> bool:
    return entry["num_blocks"] == 0 and entry["block_length"] == 0

def validator_parse_fv_block_map(data: bytes) -> list:
    entries = []
    i = 0
    while i + 8 <= len(data):
        nb = struct.unpack_from('<I', data, i)[0]
        bl = struct.unpack_from('<I', data, i + 4)[0]
        entry = validator_efi_fv_block_map_entry_new(nb, bl)
        entries.append(entry)
        if validator_efi_fv_block_map_entry_is_terminator(entry):
            break
        i += 8
    return entries

def validator_pei_module_new(name: str, guid: tuple) -> dict:
    return {"name": name, "guid": guid, "dependencies": []}

def validator_pei_module_dependency_count(module: dict) -> int:
    return len(module.get("dependencies", []))

def validator_dxe_driver_new(name: str, guid: tuple) -> dict:
    return {"name": name, "guid": guid, "protocols": [], "is_smm": False}

def validator_dxe_driver_protocol_count(driver: dict) -> int:
    return len(driver.get("protocols", []))

def validator_dxe_driver_is_smm_driver(driver: dict) -> bool:
    return driver.get("is_smm", False)

EFI_VARIABLE_NV = 0x00000001
EFI_VARIABLE_RT = 0x00000002
EFI_VARIABLE_AUTH = 0x00000010

def validator_efi_variable_attribs_is_non_volatile(attrs: int) -> bool:
    return bool(attrs & EFI_VARIABLE_NV)

def validator_efi_variable_attribs_is_runtime(attrs: int) -> bool:
    return bool(attrs & EFI_VARIABLE_RT)

def validator_efi_variable_attribs_is_authenticated(attrs: int) -> bool:
    return bool(attrs & EFI_VARIABLE_AUTH)

def validator_efi_variable_new(name: str, guid: tuple, attrs: int, data: bytes) -> dict:
    return {"name": name, "guid": guid, "attrs": attrs, "data": data}

def validator_efi_variable_data_size(var: dict) -> int:
    return len(var["data"])

SECURE_BOOT_VARS = {"PK", "KEK", "db", "dbx"}

def validator_efi_variable_is_secure_boot_related(var: dict) -> bool:
    return var["name"] in SECURE_BOOT_VARS

def validator_efi_variable_store_new() -> dict:
    return {"variables": []}

def validator_efi_variable_store_add(store: dict, v: dict) -> None:
    store["variables"].append(v)

def validator_efi_variable_store_find_by_name(store: dict, name: str) -> Optional[dict]:
    for v in store["variables"]:
        if v["name"] == name:
            return v
    return None

def validator_efi_variable_store_runtime_variables(store: dict) -> list:
    return [v for v in store["variables"]
            if validator_efi_variable_attribs_is_runtime(v["attrs"])]

def validator_efi_variable_store_secure_boot_variables(store: dict) -> list:
    return [v for v in store["variables"]
            if validator_efi_variable_is_secure_boot_related(v)]

def validator_uefi_security_profile_build(analysis: dict) -> dict:
    smm = validator_uefi_analysis_smm_drivers(analysis)
    risk = min(100, len(smm) * 10 + (10 if not analysis.get("secure_boot") else 0))
    return {"risk_score": risk, "smm_driver_count": len(smm)}

def validator_uefi_security_profile_is_high_risk(profile: dict) -> bool:
    return profile["risk_score"] >= 50

def validator_uefi_analysis_new() -> dict:
    return {"fvs": [], "pei_modules": [], "dxe_drivers": [],
            "guid_db": validator_guid_database_new(), "secure_boot": False}

def validator_uefi_analysis_add_fv(analysis: dict, fv: dict) -> None:
    analysis["fvs"].append(fv)

def validator_uefi_analysis_add_pei_module(analysis: dict, module: dict) -> None:
    analysis["pei_modules"].append(module)

def validator_uefi_analysis_add_dxe_driver(analysis: dict, driver: dict) -> None:
    analysis["dxe_drivers"].append(driver)

def validator_uefi_analysis_name_for_guid(analysis: dict, guid: tuple) -> Optional[str]:
    return validator_guid_database_lookup(analysis["guid_db"], guid)

def validator_uefi_analysis_total_ffs_files(analysis: dict) -> int:
    return sum(len(fv["files"]) for fv in analysis["fvs"])

def validator_uefi_analysis_smm_drivers(analysis: dict) -> list:
    return [d for d in analysis["dxe_drivers"] if validator_dxe_driver_is_smm_driver(d)]

def validator_uefi_analysis_find_pei_module(analysis: dict, guid: tuple) -> Optional[dict]:
    for m in analysis["pei_modules"]:
        if m["guid"] == guid:
            return m
    return None

def validator_uefi_analysis_total_pe_files(analysis: dict) -> int:
    count = 0
    for fv in analysis["fvs"]:
        count += len(validator_efi_firmware_volume_pe_files(fv))
    return count

def validator_uefi_boot_services_profile_new() -> dict:
    return {"risky_calls": [], "risk_level": 0}

def validator_uefi_boot_services_profile_risk_level(profile: dict) -> int:
    return profile.get("risk_level", 0)

def validator_uefi_boot_services_profile_is_secure(profile: dict) -> bool:
    return len(profile.get("risky_calls", [])) == 0

def validator_efi_memory_descriptor_new(mem_type: int, phys: int, pages: int) -> dict:
    return {"mem_type": mem_type, "phys_start": phys, "pages": pages}

def validator_efi_memory_descriptor_size_bytes(desc: dict) -> int:
    return desc["pages"] * 4096

def validator_efi_memory_descriptor_end_address(desc: dict) -> int:
    return desc["phys_start"] + desc["pages"] * 4096

EFI_CONVENTIONAL_MEMORY = 7

def validator_efi_memory_descriptor_is_conventional(desc: dict) -> bool:
    return desc["mem_type"] == EFI_CONVENTIONAL_MEMORY

def validator_efi_memory_descriptor_is_runtime(desc: dict) -> bool:
    return desc["mem_type"] >= 10  # EfiRuntimeServicesCode/Data

class GptPartitionType(Enum):
    Unused = 0
    EfiSystem = 1
    BiosBoot = 2
    MicrosoftBasicData = 3
    LinuxData = 4
    Unknown = 0xFF

def validator_gpt_partition_type_from_u16(v: int) -> GptPartitionType:
    try:
        return GptPartitionType(v)
    except ValueError:
        return GptPartitionType.Unknown

GPT_MAGIC = b'EFI PART'

def validator_gpt_partition_entry_parse_header(data: bytes) -> Optional[dict]:
    if len(data) < 92:
        return None
    sig = data[0:8]
    if sig != GPT_MAGIC:
        return None
    first_lba = struct.unpack_from('<Q', data, 40)[0]
    last_lba = struct.unpack_from('<Q', data, 48)[0]
    part_start = struct.unpack_from('<Q', data, 72)[0]
    part_count = struct.unpack_from('<I', data, 80)[0]
    return {"first_usable_lba": first_lba, "last_usable_lba": last_lba,
            "partition_entry_lba": part_start, "num_partition_entries": part_count}

def validator_gpt_partition_entry_is_end(entry: dict) -> bool:
    return entry.get("num_partition_entries", 0) == 0

def validator_gpt_header_parse(data: bytes) -> Optional[dict]:
    return validator_gpt_partition_entry_parse_header(data)

def validator_gpt_header_usable_lba_count(header: dict) -> int:
    return header["last_usable_lba"] - header["first_usable_lba"] + 1

# ---------------------------------------------------------------------------
# uefi_analysis.rs — utility functions
# ---------------------------------------------------------------------------

def validator_read_cstring(data: bytes, offset: int) -> Optional[str]:
    if offset >= len(data):
        return None
    end = data.find(b'\x00', offset)
    if end == -1:
        return None
    return data[offset:end].decode('latin-1', errors='replace')

def validator_align_up(val: int, align: int) -> int:
    if align == 0:
        return val
    return (val + align - 1) & ~(align - 1)

def validator_align_down(val: int, align: int) -> int:
    if align == 0:
        return val
    return val & ~(align - 1)

def validator_is_power_of_two(val: int) -> bool:
    return val > 0 and (val & (val - 1)) == 0

def validator_byte_entropy(data: bytes) -> float:
    return _shannon_entropy(data)

def validator_le_u16(data: bytes, off: int) -> int:
    return struct.unpack_from('<H', data, off)[0]

def validator_le_u32(data: bytes, off: int) -> int:
    return struct.unpack_from('<I', data, off)[0]

def validator_le_u64(data: bytes, off: int) -> int:
    return struct.unpack_from('<Q', data, off)[0]

def validator_be_u32(data: bytes, off: int) -> int:
    return struct.unpack_from('>I', data, off)[0]

def validator_adler32(data: bytes) -> int:
    MOD = 65521
    a = 1
    b = 0
    for byte in data:
        a = (a + byte) % MOD
        b = (b + a) % MOD
    return (b << 16) | a

def validator_find_bytes(haystack: bytes, needle: bytes) -> Optional[int]:
    idx = haystack.find(needle)
    return idx if idx >= 0 else None

def validator_count_bytes(haystack: bytes, needle: bytes) -> int:
    count = 0
    start = 0
    while True:
        idx = haystack.find(needle, start)
        if idx == -1:
            break
        count += 1
        start = idx + 1
    return count

def validator_try_slice(data: bytes, offset: int, length: int) -> Optional[bytes]:
    if offset + length <= len(data):
        return data[offset:offset + length]
    return None

def validator_is_zeroed(data: bytes) -> bool:
    return all(b == 0 for b in data)

def validator_reverse_bytes(data: bytearray) -> None:
    data.reverse()

def validator_xor_bytes(data: bytearray, key: int) -> None:
    for i in range(len(data)):
        data[i] ^= key

def validator_rol32(val: int, n: int) -> int:
    n = n % 32
    return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF

def validator_ror32(val: int, n: int) -> int:
    n = n % 32
    return ((val >> n) | (val << (32 - n))) & 0xFFFFFFFF

_CRC32_TABLE = None

def _build_crc32_table():
    global _CRC32_TABLE
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
        table.append(crc)
    _CRC32_TABLE = table

def validator_crc32(data: bytes) -> int:
    global _CRC32_TABLE
    if _CRC32_TABLE is None:
        _build_crc32_table()
    crc = 0xFFFFFFFF
    for b in data:
        crc = (crc >> 8) ^ _CRC32_TABLE[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFFFFFF

def validator_fnv1a32(data: bytes) -> int:
    FNV_PRIME = 0x01000193
    FNV_OFFSET = 0x811C9DC5
    h = FNV_OFFSET
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFF
    return h

def validator_murmur3_32(data: bytes, seed: int) -> int:
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    h1 = seed & 0xFFFFFFFF
    length = len(data)
    num_blocks = length // 4
    for i in range(num_blocks):
        k1 = struct.unpack_from('<I', data, i * 4)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = validator_rol32(k1, 15)
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = validator_rol32(h1, 13)
        h1 = ((h1 * 5) + 0xE6546B64) & 0xFFFFFFFF
    tail = data[num_blocks * 4:]
    k1 = 0
    tail_len = len(tail)
    if tail_len >= 3:
        k1 ^= tail[2] << 16
    if tail_len >= 2:
        k1 ^= tail[1] << 8
    if tail_len >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = validator_rol32(k1, 15)
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1

# ---------------------------------------------------------------------------
# signature_db.rs
# ---------------------------------------------------------------------------

def validator_signature_database_new() -> dict:
    entries = []
    for magic, name, cat in KNOWN_SIGS:
        entries.append({"magic": magic, "name": name, "category": cat,
                        "confidence": 90, "offset": 0})
    return {"entries": entries}

def validator_signature_database_len(db: dict) -> int:
    return len(db["entries"])

def validator_signature_database_is_empty(db: dict) -> bool:
    return len(db["entries"]) == 0

def validator_signature_database_by_category(db: dict, category: SignatureCategory) -> list:
    return [e for e in db["entries"] if e["category"] == category]

def validator_signature_database_by_name(db: dict, name: str) -> Optional[dict]:
    for e in db["entries"]:
        if e["name"] == name:
            return e
    return None

def validator_signature_database_scan_with_min_confidence(db: dict, data: bytes, min_conf: int) -> list:
    results = []
    for entry in db["entries"]:
        if entry["confidence"] < min_conf:
            continue
        magic = entry["magic"]
        idx = data.find(magic)
        if idx >= 0:
            results.append({"entry": entry, "offset": idx,
                            "confidence": entry["confidence"]})
    return results

def validator_signature_database_scan(db: dict, data: bytes) -> list:
    return validator_signature_database_scan_with_min_confidence(db, data, 0)

def validator_signature_database_best_match(db: dict, data: bytes) -> Optional[dict]:
    matches = validator_signature_database_scan(db, data)
    if not matches:
        return None
    return max(matches, key=lambda m: m["confidence"])

def validator_signature_database_root_matches(db: dict, data: bytes) -> list:
    return [m for m in validator_signature_database_scan(db, data) if m["offset"] == 0]

def validator_signature_database_add_entry(db: dict, entry: dict) -> None:
    db["entries"].append(entry)

# ---------------------------------------------------------------------------
# filesystem_extraction.rs
# ---------------------------------------------------------------------------

def validator_filesystem_type_as_str(fs_type: FilesystemType) -> str:
    return fs_type.value

def validator_fs_node_is_file(node: dict) -> bool:
    return node.get("kind") == "file"

def validator_fs_node_is_dir(node: dict) -> bool:
    return node.get("kind") == "dir"

def validator_fs_node_is_symlink(node: dict) -> bool:
    return node.get("kind") == "symlink"

def validator_extracted_filesystem_find(fs: dict, path: str) -> Optional[dict]:
    for node in fs.get("nodes", []):
        if node.get("path") == path:
            return node
    return None

def validator_extracted_filesystem_list_dir(fs: dict, dir_path: str) -> list:
    results = []
    for node in fs.get("nodes", []):
        p = node.get("path", "")
        parent = p.rsplit('/', 1)[0] if '/' in p else ""
        if parent == dir_path and p != dir_path:
            results.append(node)
    return results

def validator_extracted_filesystem_all_files(fs: dict) -> list:
    return [node["path"] for node in fs.get("nodes", [])
            if node.get("kind") == "file"]

SQUASHFS_MAGIC_LE = 0x73717368
SQUASHFS_MAGIC_BE = 0x68737173

def validator_squashfs_superblock_compression_name(sb: dict) -> str:
    comps = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}
    return comps.get(sb.get("compression", 0), "unknown")

def validator_squashfs_superblock_detect(data: bytes, offset: int) -> Optional[dict]:
    if offset + 4 > len(data):
        return None
    magic = struct.unpack_from('<I', data, offset)[0]
    if magic not in (SQUASHFS_MAGIC_LE, SQUASHFS_MAGIC_BE):
        return None
    comp = data[offset + 20] if offset + 21 <= len(data) else 1
    return {"offset": offset, "magic": magic, "compression": comp}

def validator_squashfs_extractor_extract(data: bytes, offset: int) -> dict:
    sb = validator_squashfs_superblock_detect(data, offset)
    return {"fs_type": FilesystemType.SquashFS, "offset": offset,
            "superblock": sb, "nodes": [], "success": sb is not None}

def validator_squashfs_scanner_scan(data: bytes) -> list:
    offsets = []
    i = 0
    while i + 4 <= len(data):
        magic = struct.unpack_from('<I', data, i)[0]
        if magic in (SQUASHFS_MAGIC_LE, SQUASHFS_MAGIC_BE):
            offsets.append(i)
        i += 4
    return offsets

CRAMFS_MAGIC = 0x28CD3D45

def validator_cramfs_superblock_detect(data: bytes, offset: int) -> Optional[dict]:
    if offset + 4 > len(data):
        return None
    magic = struct.unpack_from('<I', data, offset)[0]
    if magic != CRAMFS_MAGIC:
        return None
    size = struct.unpack_from('<I', data, offset + 4)[0] if offset + 8 <= len(data) else 0
    return {"offset": offset, "magic": magic, "size": size}

def validator_cramfs_extractor_extract(data: bytes, offset: int) -> dict:
    sb = validator_cramfs_superblock_detect(data, offset)
    return {"fs_type": FilesystemType.CramFS, "offset": offset,
            "superblock": sb, "nodes": [], "success": sb is not None}

JFFS2_MAGIC = 0x1985

def validator_jffs2_scanner_detect(data: bytes, offset: int) -> bool:
    if offset + 2 > len(data):
        return False
    magic = struct.unpack_from('<H', data, offset)[0]
    return magic == JFFS2_MAGIC

def validator_jffs2_scanner_scan_nodes(data: bytes, base_offset: int) -> list:
    nodes = []
    i = base_offset
    while i + 12 <= len(data):
        if struct.unpack_from('<H', data, i)[0] == JFFS2_MAGIC:
            node_type = struct.unpack_from('<H', data, i + 2)[0]
            node_len = struct.unpack_from('<I', data, i + 4)[0]
            if node_len < 12 or node_len > 65536:
                i += 4
                continue
            nodes.append({"offset": i, "type": node_type, "length": node_len})
            i += max(4, node_len)
        else:
            i += 4
    return nodes

def validator_jffs2_extractor_extract(data: bytes, offset: int) -> dict:
    detected = validator_jffs2_scanner_detect(data, offset)
    nodes = validator_jffs2_scanner_scan_nodes(data, offset) if detected else []
    return {"fs_type": FilesystemType.Jffs2, "offset": offset,
            "nodes_found": len(nodes), "jffs2_nodes": nodes,
            "fs_nodes": [], "success": detected}

EXT2_MAGIC = 0xEF53

def validator_ext2_superblock_detect(data: bytes, offset: int) -> Optional[dict]:
    sb_off = offset + 1024
    if sb_off + 88 > len(data):
        return None
    magic = struct.unpack_from('<H', data, sb_off + 56)[0]
    if magic != EXT2_MAGIC:
        return None
    block_size = 1024 << struct.unpack_from('<I', data, sb_off + 24)[0]
    return {"offset": offset, "magic": magic, "block_size": block_size}

def validator_ext2_extractor_extract(data: bytes, offset: int) -> dict:
    sb = validator_ext2_superblock_detect(data, offset)
    return {"fs_type": FilesystemType.Ext2, "offset": offset,
            "superblock": sb, "nodes": [], "success": sb is not None}

def validator_fat_boot_sector_detect(data: bytes, offset: int) -> Optional[dict]:
    if offset + 512 > len(data):
        return None
    sig = struct.unpack_from('<H', data, offset + 510)[0]
    if sig != 0xAA55:
        return None
    oem = data[offset + 3:offset + 11].decode('latin-1', errors='replace').strip()
    return {"offset": offset, "signature": sig, "oem_name": oem}

def validator_fat_extractor_extract(data: bytes, offset: int) -> dict:
    bs = validator_fat_boot_sector_detect(data, offset)
    return {"fs_type": FilesystemType.Fat, "offset": offset,
            "boot_sector": bs, "nodes": [], "success": bs is not None}

def validator_filesystem_extractor_new() -> dict:
    return {"results": []}

def validator_filesystem_extractor_extract(extractor: dict, data: bytes) -> None:
    # SquashFS
    for off in validator_squashfs_scanner_scan(data):
        extractor["results"].append(validator_squashfs_extractor_extract(data, off))
    # CramFS
    for i in range(0, len(data) - 4, 4):
        sb = validator_cramfs_superblock_detect(data, i)
        if sb:
            extractor["results"].append(validator_cramfs_extractor_extract(data, i))
    # JFFS2
    if validator_jffs2_scanner_detect(data, 0):
        extractor["results"].append(validator_jffs2_extractor_extract(data, 0))
    # Ext2
    sb = validator_ext2_superblock_detect(data, 0)
    if sb:
        extractor["results"].append(validator_ext2_extractor_extract(data, 0))
    # FAT
    bs = validator_fat_boot_sector_detect(data, 0)
    if bs:
        extractor["results"].append(validator_fat_extractor_extract(data, 0))

def validator_filesystem_extractor_summary(extractor: dict) -> str:
    results = extractor["results"]
    success = [r for r in results if r.get("success")]
    return (f"Found {len(results)} filesystem(s), "
            f"{len(success)} successfully extracted.")

def validator_filesystem_extractor_successful(extractor: dict) -> list:
    return [r for r in extractor["results"] if r.get("success")]

def validator_filesystem_extractor_by_type(extractor: dict, fs_type: FilesystemType) -> list:
    return [r for r in extractor["results"] if r.get("fs_type") == fs_type]

# ---------------------------------------------------------------------------
# firmware_analysis_report.rs
# ---------------------------------------------------------------------------

def validator_os_fingerprint_detect(data: bytes) -> dict:
    text = data.decode('latin-1', errors='replace')
    is_linux = any(s in text for s in ('Linux version', 'linux kernel', '/proc/', 'vmlinuz'))
    is_rtos = validator_detect_rtos(data) is not None
    os_name = "linux" if is_linux else ("rtos" if is_rtos else "bare_metal")
    return {"os": os_name, "is_linux": is_linux, "is_rtos": is_rtos}

def validator_os_fingerprint_is_linux_based(fp: dict) -> bool:
    return fp.get("is_linux", False)

def validator_os_fingerprint_is_rtos(fp: dict) -> bool:
    return fp.get("is_rtos", False)

COMPRESSION_MAGICS = {
    b'\x1f\x8b': "gzip",
    b'BZh': "bzip2",
    b'\xfd7zXZ\x00': "xz",
    b'\x5d\x00\x00': "lzma",
    b'\x04\x22\x4d\x18': "lz4",
    b'\x28\xb5\x2f\xfd': "zstd",
}

def validator_compression_info_detect(data: bytes) -> Optional[dict]:
    for magic, name in COMPRESSION_MAGICS.items():
        if data[:len(magic)] == magic:
            return {"algorithm": name}
    return None

def validator_fs_node_is_config_file(node: dict) -> bool:
    path = node.get("path", "")
    return any(path.endswith(ext) for ext in ('.conf', '.cfg', '.ini', '.json', '.xml', '.yaml'))

def validator_fs_node_is_world_writable(node: dict) -> bool:
    mode = node.get("mode", 0)
    return bool(mode & 0o002)

def validator_fs_node_is_setuid(node: dict) -> bool:
    mode = node.get("mode", 0)
    return bool(mode & 0o4000)

def validator_fs_tree_find_prefix(tree: dict, prefix: str) -> list:
    return [n for n in tree.get("nodes", []) if n.get("path", "").startswith(prefix)]

def validator_fs_tree_setuid_files(tree: dict) -> list:
    return [n for n in tree.get("nodes", []) if validator_fs_node_is_setuid(n)]

def validator_fs_tree_world_writable(tree: dict) -> list:
    return [n for n in tree.get("nodes", []) if validator_fs_node_is_world_writable(n)]

def validator_crypto_key_is_high_confidence(key: dict) -> bool:
    return key.get("confidence", 0) >= 80

PRIVATE_IP_RANGES = [
    (0x0A000000, 0x0AFFFFFF),  # 10.x.x.x
    (0xAC100000, 0xAC1FFFFF),  # 172.16-31.x.x
    (0xC0A80000, 0xC0A8FFFF),  # 192.168.x.x
]

def _ip_to_int(ip: str) -> Optional[int]:
    parts = ip.split('.')
    if len(parts) != 4:
        return None
    try:
        return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))
    except ValueError:
        return None

def validator_network_endpoint_is_private_ip(ep: dict) -> bool:
    ip = ep.get("ip")
    if not ip:
        return False
    val = _ip_to_int(ip)
    if val is None:
        return False
    return any(lo <= val <= hi for lo, hi in PRIVATE_IP_RANGES)

def validator_network_endpoint_is_unencrypted(ep: dict) -> bool:
    proto = ep.get("protocol", "").lower()
    return proto in ("http", "telnet", "ftp", "tftp")

def validator_network_endpoint_scan(data: bytes) -> list:
    text = data.decode('latin-1', errors='replace')
    endpoints = []
    for m in re.finditer(r'https?://([^\s/"\'<>]+)', text):
        endpoints.append({"url": m.group(0), "protocol": m.group(0).split(':')[0],
                          "offset": m.start()})
    for m in re.finditer(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text):
        endpoints.append({"ip": m.group(1), "protocol": "raw_ip", "offset": m.start()})
    return endpoints

def validator_vulnerable_component_is_high_risk(vc: dict) -> bool:
    return vc.get("cvss_score", 0.0) >= 7.0

def validator_vulnerable_component_is_critical(vc: dict) -> bool:
    return vc.get("cvss_score", 0.0) >= 9.0

def validator_firmware_analysis_report_mock() -> dict:
    return {
        "firmware_kind": FirmwareKind.Raw.value,
        "arch": BinaryArch.Arm.value,
        "os_fingerprint": {"os": "linux", "is_linux": True, "is_rtos": False},
        "entropy": 5.5,
        "crypto_keys": [{"type": "rsa_private", "confidence": 90}],
        "vulnerable_components": [{"name": "openssl", "version": "1.0.1",
                                   "cvss_score": 9.8, "cve": "CVE-2014-0160"}],
        "network_endpoints": [{"ip": "192.168.1.1", "protocol": "http"}],
        "security_findings": [],
    }

def validator_firmware_analysis_report_compute_risk_score(report: dict) -> float:
    score = 0.0
    if report.get("crypto_keys"):
        score += 30.0
    for vc in report.get("vulnerable_components", []):
        score += min(40.0, vc.get("cvss_score", 0.0) * 4)
    score += len(report.get("security_findings", [])) * 2.0
    return min(100.0, score)

def validator_firmware_analysis_report_private_keys(report: dict) -> list:
    return [k for k in report.get("crypto_keys", [])
            if "private" in k.get("type", "")]

def validator_firmware_analysis_report_critical_vulnerabilities(report: dict) -> list:
    return [vc for vc in report.get("vulnerable_components", [])
            if validator_vulnerable_component_is_critical(vc)]

def validator_firmware_analysis_report_summary(report: dict) -> str:
    kind = report.get("firmware_kind", "unknown")
    arch = report.get("arch", "unknown")
    n_keys = len(validator_firmware_analysis_report_private_keys(report))
    n_crit = len(validator_firmware_analysis_report_critical_vulnerabilities(report))
    risk = validator_firmware_analysis_report_compute_risk_score(report)
    return (f"Firmware: {kind} / {arch} | "
            f"private_keys={n_keys} critical_vulns={n_crit} "
            f"risk_score={risk:.1f}")

# ---------------------------------------------------------------------------
# firmware_security.rs
# ---------------------------------------------------------------------------

def validator_firmware_finding_new(category: str, description: str, risk: FwRisk) -> dict:
    return {"category": category, "description": description,
            "risk": risk, "offset": None, "evidence": None}

def validator_firmware_finding_with_offset(finding: dict, offset: int) -> dict:
    f = dict(finding)
    f["offset"] = offset
    return f

def validator_firmware_finding_with_evidence(finding: dict, evidence: str) -> dict:
    f = dict(finding)
    f["evidence"] = evidence
    return f

# Credential scanner
CREDENTIAL_PATTERNS = [
    (rb'password\s*[:=]\s*\S+', "password"),
    (rb'passwd\s*[:=]\s*\S+', "password"),
    (rb'api[_-]?key\s*[:=]\s*\S+', "api_key"),
    (rb'secret\s*[:=]\s*\S+', "secret"),
    (rb'token\s*[:=]\s*\S+', "token"),
]

def validator_credential_scanner_new() -> dict:
    return {"findings": [], "matches": []}

def validator_credential_scanner_scan(scanner: dict, data: bytes) -> None:
    text = data.decode('latin-1', errors='replace').encode('latin-1')
    for pattern, kind in CREDENTIAL_PATTERNS:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            match = {"kind": kind, "offset": m.start(),
                     "value": m.group().decode('latin-1', errors='replace')}
            scanner["matches"].append(match)
            finding = validator_firmware_finding_new(
                "credential", f"Found {kind} at offset {m.start()}", FwRisk.High)
            scanner["findings"].append(finding)

def validator_credential_scanner_findings(scanner: dict) -> list:
    return scanner["findings"]

def validator_credential_scanner_has_credentials(scanner: dict) -> bool:
    return len(scanner["matches"]) > 0

def validator_credential_scanner_matches_of_kind(scanner: dict, kind: str) -> list:
    return [m for m in scanner["matches"] if m["kind"] == kind]

# Crypto scanner
WEAK_CRYPTO_PATTERNS = [
    (rb'MD5', "MD5"), (rb'DES', "DES"), (rb'RC4', "RC4"),
    (rb'SHA1', "SHA1"), (rb'3DES', "3DES"),
]

def validator_crypto_scanner_new() -> dict:
    return {"findings": [], "algorithms": []}

def validator_crypto_scanner_scan(scanner: dict, data: bytes) -> None:
    for pattern, name in WEAK_CRYPTO_PATTERNS:
        if re.search(pattern, data):
            if name not in scanner["algorithms"]:
                scanner["algorithms"].append(name)
            scanner["findings"].append(
                validator_firmware_finding_new("crypto", f"Weak crypto: {name}", FwRisk.Medium))

def validator_crypto_scanner_findings(scanner: dict) -> list:
    return scanner["findings"]

def validator_crypto_scanner_algorithm_names(scanner: dict) -> list:
    return scanner["algorithms"]

# Debug interface scanner
DEBUG_PATTERNS = [
    (rb'JTAG', "JTAG"), (rb'UART', "UART"), (rb'SWD', "SWD"),
    (rb'OpenOCD', "JTAG"), (rb'GDB stub', "GDB"),
]

def validator_debug_interface_scanner_new() -> dict:
    return {"findings": [], "interfaces": set()}

def validator_debug_interface_scanner_scan(scanner: dict, data: bytes) -> None:
    for pattern, iface in DEBUG_PATTERNS:
        if re.search(pattern, data, re.IGNORECASE):
            scanner["interfaces"].add(iface)
            scanner["findings"].append(
                validator_firmware_finding_new("debug", f"Debug interface: {iface}", FwRisk.Medium))

def validator_debug_interface_scanner_findings(scanner: dict) -> list:
    return scanner["findings"]

def validator_debug_interface_scanner_has_interface(scanner: dict, iface: str) -> bool:
    return iface in scanner["interfaces"]

# Shell scanner
SHELL_PATTERNS = [b'/bin/sh', b'/bin/bash', b'/bin/ash', b'# ', b'$ ',
                  b'busybox', b'dropbear']

def validator_shell_scanner_new() -> dict:
    return {"findings": [], "has_prompt": False}

def validator_shell_scanner_scan(scanner: dict, data: bytes) -> None:
    for pattern in SHELL_PATTERNS:
        if pattern in data:
            scanner["findings"].append(
                validator_firmware_finding_new(
                    "shell", f"Shell indicator: {pattern!r}", FwRisk.High))
    if b'# ' in data or b'$ ' in data:
        scanner["has_prompt"] = True

def validator_shell_scanner_findings(scanner: dict) -> list:
    return scanner["findings"]

def validator_shell_scanner_has_shell_prompt(scanner: dict) -> bool:
    return scanner["has_prompt"]

# Network service scanner
NET_SERVICE_PATTERNS = [
    (b'telnetd', "telnetd"), (b'httpd', "httpd"), (b'ftpd', "ftpd"),
    (b'dropbear', "sshd"), (b'nginx', "nginx"), (b'lighttpd', "httpd"),
]

def validator_network_service_scanner_new() -> dict:
    return {"findings": [], "services": []}

def validator_network_service_scanner_scan(scanner: dict, data: bytes) -> None:
    for pattern, name in NET_SERVICE_PATTERNS:
        if pattern in data:
            if name not in scanner["services"]:
                scanner["services"].append(name)
            risk = FwRisk.High if name == "telnetd" else FwRisk.Medium
            scanner["findings"].append(
                validator_firmware_finding_new("network_service",
                                               f"Service found: {name}", risk))

def validator_network_service_scanner_findings(scanner: dict) -> list:
    return scanner["findings"]

def validator_network_service_scanner_has_telnetd(scanner: dict) -> bool:
    return "telnetd" in scanner["services"]

# FirmwareSecurity aggregator
def validator_firmware_security_new() -> dict:
    return {
        "credential": validator_credential_scanner_new(),
        "crypto": validator_crypto_scanner_new(),
        "debug": validator_debug_interface_scanner_new(),
        "shell": validator_shell_scanner_new(),
        "network": validator_network_service_scanner_new(),
    }

def validator_firmware_security_analyse(sec: dict, data: bytes) -> None:
    validator_credential_scanner_scan(sec["credential"], data)
    validator_crypto_scanner_scan(sec["crypto"], data)
    validator_debug_interface_scanner_scan(sec["debug"], data)
    validator_shell_scanner_scan(sec["shell"], data)
    validator_network_service_scanner_scan(sec["network"], data)

def validator_firmware_security_all_findings(sec: dict) -> list:
    all_f = []
    for key in ("credential", "crypto", "debug", "shell", "network"):
        scanner = sec[key]
        all_f.extend(scanner.get("findings", []))
    return all_f

RISK_ORDER = [FwRisk.Info, FwRisk.Low, FwRisk.Medium, FwRisk.High, FwRisk.Critical]

def validator_firmware_security_max_risk(sec: dict) -> Optional[FwRisk]:
    findings = validator_firmware_security_all_findings(sec)
    if not findings:
        return None
    risks = [f["risk"] for f in findings]
    return max(risks, key=lambda r: RISK_ORDER.index(r))

def validator_firmware_security_has_risk(sec: dict, risk: FwRisk) -> bool:
    return any(f["risk"] == risk for f in validator_firmware_security_all_findings(sec))

def validator_firmware_security_finding_count(sec: dict) -> int:
    return len(validator_firmware_security_all_findings(sec))

# FirmwareStringExtractor
def validator_firmware_string_extractor_new() -> dict:
    return {"min_length": 4}

def validator_firmware_string_extractor_with_min_length(extractor: dict, length: int) -> dict:
    return {"min_length": length}

def validator_firmware_string_extractor_extract(extractor: dict, data: bytes) -> list:
    return validator_extract_firmware_strings(data, extractor["min_length"])

def validator_firmware_string_extractor_find_containing(extractor: dict,
                                                         data: bytes, substr: str) -> list:
    all_strings = validator_firmware_string_extractor_extract(extractor, data)
    return [s for s in all_strings if substr in s["value"]]

# SecurityScore
def validator_security_score_score(sec: dict) -> float:
    findings = validator_firmware_security_all_findings(sec)
    risk_weights = {FwRisk.Info: 0, FwRisk.Low: 5, FwRisk.Medium: 15,
                    FwRisk.High: 30, FwRisk.Critical: 50}
    total_penalty = sum(risk_weights.get(f["risk"], 0) for f in findings)
    return max(0.0, 100.0 - total_penalty)

def validator_security_score_label(score: float) -> str:
    if score >= 90:
        return "Secure"
    if score >= 70:
        return "Low Risk"
    if score >= 50:
        return "Medium Risk"
    if score >= 25:
        return "High Risk"
    return "Critical"

# ServiceScanner
SERVICE_NAMES = [b'sshd', b'telnetd', b'ftpd', b'httpd', b'snmpd',
                 b'ntpd', b'crond', b'init', b'udhcpd']

def validator_service_scanner_new() -> dict:
    return {"services": []}

def validator_service_scanner_scan(scanner: dict, data: bytes) -> None:
    for name in SERVICE_NAMES:
        if name in data:
            svc = name.decode('ascii')
            if svc not in scanner["services"]:
                scanner["services"].append(svc)

def validator_service_scanner_service_names(scanner: dict) -> list:
    return scanner["services"]

# ---------------------------------------------------------------------------
# extractor.rs
# ---------------------------------------------------------------------------

def validator_firmware_extractor_new() -> dict:
    return {"config": {"entropy_window": 256, "entropy_step": 256,
                       "min_region_bytes": 512, "scan_filesystems": True}}

def validator_firmware_extractor_with_config(config: dict) -> dict:
    return {"config": config}

def validator_firmware_extractor_extract(extractor: dict, data: bytes) -> list:
    results = []
    # Signature scan
    db = validator_signature_database_new()
    for match in validator_signature_database_scan(db, data):
        results.append({"kind": "signature", "offset": match["offset"],
                        "name": match["entry"]["name"]})
    # Filesystem scan
    fs_ext = validator_filesystem_extractor_new()
    validator_filesystem_extractor_extract(fs_ext, data)
    for fs in validator_filesystem_extractor_successful(fs_ext):
        results.append({"kind": "filesystem", "offset": fs["offset"],
                        "fs_type": fs["fs_type"].value})
    return results

def validator_firmware_extractor_extract_at(extractor: dict, data: bytes,
                                             offset: int, kind: str) -> list:
    chunk = data[offset:]
    results = validator_firmware_extractor_extract(extractor, chunk)
    for r in results:
        r["offset"] += offset
    return results

def validator_firmware_extractor_detect_entropy_regions(extractor: dict, data: bytes) -> list:
    cfg = extractor["config"]
    analyzer = validator_entropy_analyzer_new(
        cfg.get("entropy_window", 256),
        cfg.get("entropy_step", 256),
        cfg.get("min_region_bytes", 512))
    regions = validator_entropy_analyzer_find_regions(analyzer, data)
    return [{"kind": "entropy_region", "offset": r["start"],
             "size": r["size"]} for r in regions]

def validator_firmware_extractor_full_extract(extractor: dict, data: bytes) -> list:
    results = validator_firmware_extractor_extract(extractor, data)
    results += validator_firmware_extractor_detect_entropy_regions(extractor, data)
    return results

def validator_firmware_extractor_summarize(results: list) -> dict:
    kinds: Dict[str, int] = {}
    for r in results:
        k = r.get("kind", "unknown")
        kinds[k] = kinds.get(k, 0) + 1
    return {"total": len(results), "by_kind": kinds}


# ---------------------------------------------------------------------------
# Self-test / smoke
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    sample = (b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 56 +
              b'FreeRTOS' + b'/bin/sh' + b'password=secret' +
              b'\x27\x05\x19\x56' + b'\x1f\x8b' + b'sqsh' +
              b'S305' + b':10000000102030405060708090A0B0C0D0E0F00D\n')

    print("detect_firmware_kind:", validator_detect_firmware_kind(sample[:8]).value)
    print("detect_rtos:", validator_detect_rtos(sample))
    ea = validator_entropy_analyzer_new(32, 32, 64)
    print("block_entropy:", round(validator_entropy_analyzer_block_entropy(sample), 3))
    print("compressed_fraction:", round(validator_entropy_analyzer_compressed_fraction(ea, sample), 3))
    print("crc32:", hex(validator_crc32(b"hello")))
    print("fnv1a32:", hex(validator_fnv1a32(b"hello")))
    print("murmur3_32:", hex(validator_murmur3_32(b"hello", 0)))
    print("adler32:", hex(validator_adler32(b"hello")))
    enc = validator_encode_to_ihex(b'\xDE\xAD\xBE\xEF', 0x1000, 4)
    print("ihex encode (first line):", enc.split('\n')[0])
    sec = validator_firmware_security_new()
    validator_firmware_security_analyse(sec, sample)
    print("security findings:", validator_firmware_security_finding_count(sec))
    report = validator_firmware_analysis_report_mock()
    print("report summary:", validator_firmware_analysis_report_summary(report))
    print("GUID format:", validator_format_guid((0x8BE4DF61, 0x93CA, 0x11D2,
                                                  bytes.fromhex('AA0D00E098032B8C'))))
    print("All OK")
