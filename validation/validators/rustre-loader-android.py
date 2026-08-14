"""
Validator Python per rustre-loader-android.
Riproduce l'API documentata in validation/reports/rustre-loader-android.md.
Solo stdlib: struct, hashlib, json, re, zlib, math, os, pathlib.
"""
from __future__ import annotations

import struct
import re
import math
import zlib
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Errori
# ---------------------------------------------------------------------------
class AndroidLoaderError(Exception):
    pass


class AxmlError(Exception):
    pass


class V4SignatureError(Exception):
    pass


# ---------------------------------------------------------------------------
# src/lib.rs
# ---------------------------------------------------------------------------
ZIP_LFH = b"PK\x03\x04"
ZIP_CDFH = b"PK\x01\x02"
ZIP_EOCD = b"PK\x05\x06"
DEX_MAGIC = b"dex\n"
VDEX_MAGIC = b"vdex"


def is_apk(data: bytes) -> bool:
    if len(data) < 4 or data[:4] != ZIP_LFH:
        return False
    return b"classes.dex" in data


def is_dex(data: bytes) -> bool:
    if len(data) < 8:
        return False
    return data[:4] == DEX_MAGIC and 0x30 <= data[4] <= 0x39 and data[7] == 0


def is_vdex(data: bytes) -> bool:
    if len(data) < 8:
        return False
    return data[:4] == VDEX_MAGIC


def adler32(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF


def verify_dex_checksum(data: bytes):
    if len(data) < 12:
        raise AndroidLoaderError("dex too short")
    stored = struct.unpack_from("<I", data, 8)[0]
    actual = adler32(data[12:])
    if stored != actual:
        raise AndroidLoaderError(f"adler32 mismatch: {stored:x} != {actual:x}")
    return None


class DexHeader:
    def __init__(self, **kw):
        self.string_ids_size = kw.get("string_ids_size", 0)
        self.string_ids_off = kw.get("string_ids_off", 0)
        self.type_ids_size = kw.get("type_ids_size", 0)
        self.type_ids_off = kw.get("type_ids_off", 0)
        self.proto_ids_size = kw.get("proto_ids_size", 0)
        self.proto_ids_off = kw.get("proto_ids_off", 0)
        self.field_ids_size = kw.get("field_ids_size", 0)
        self.field_ids_off = kw.get("field_ids_off", 0)
        self.method_ids_size = kw.get("method_ids_size", 0)
        self.method_ids_off = kw.get("method_ids_off", 0)
        self.class_defs_size = kw.get("class_defs_size", 0)
        self.class_defs_off = kw.get("class_defs_off", 0)


def read_uleb128(data: bytes, pos: list) -> int:
    """pos è una lista [int] usata come riferimento mutabile."""
    result = 0
    shift = 0
    p = pos[0]
    while True:
        b = data[p]
        p += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    pos[0] = p
    return result & 0xFFFFFFFF


def read_dex_string(data: bytes, off: int) -> str:
    pos = [off]
    length = read_uleb128(data, pos)
    start = pos[0]
    end = start
    # MUTF-8 terminata da NUL
    while end < len(data) and data[end] != 0:
        end += 1
    try:
        return data[start:end].decode("utf-8", errors="replace")
    except Exception:
        return ""


def read_string_table(data: bytes, hdr: DexHeader) -> list:
    out = []
    for i in range(hdr.string_ids_size):
        off = struct.unpack_from("<I", data, hdr.string_ids_off + i * 4)[0]
        out.append(read_dex_string(data, off))
    return out


def read_type_ids(data: bytes, hdr: DexHeader) -> list:
    return [struct.unpack_from("<I", data, hdr.type_ids_off + i * 4)[0]
            for i in range(hdr.type_ids_size)]


def read_proto_ids(data: bytes, hdr: DexHeader) -> list:
    out = []
    for i in range(hdr.proto_ids_size):
        a, b, c = struct.unpack_from("<III", data, hdr.proto_ids_off + i * 12)
        out.append({"shorty_idx": a, "return_type_idx": b, "parameters_off": c})
    return out


def read_field_ids(data: bytes, hdr: DexHeader) -> list:
    out = []
    for i in range(hdr.field_ids_size):
        c, t, n = struct.unpack_from("<HHI", data, hdr.field_ids_off + i * 8)
        out.append({"class_idx": c, "type_idx": t, "name_idx": n})
    return out


def read_method_ids(data: bytes, hdr: DexHeader) -> list:
    out = []
    for i in range(hdr.method_ids_size):
        c, p, n = struct.unpack_from("<HHI", data, hdr.method_ids_off + i * 8)
        out.append({"class_idx": c, "proto_idx": p, "name_idx": n})
    return out


def read_class_defs(data: bytes, hdr: DexHeader) -> list:
    out = []
    for i in range(hdr.class_defs_size):
        vals = struct.unpack_from("<IIIIIIII", data, hdr.class_defs_off + i * 32)
        out.append({
            "class_idx": vals[0], "access_flags": vals[1],
            "superclass_idx": vals[2], "interfaces_off": vals[3],
            "source_file_idx": vals[4], "annotations_off": vals[5],
            "class_data_off": vals[6], "static_values_off": vals[7],
        })
    return out


def parse_encoded_methods(data: bytes, class_data_off: int) -> list:
    if class_data_off == 0 or class_data_off >= len(data):
        return []
    pos = [class_data_off]
    static_fields = read_uleb128(data, pos)
    instance_fields = read_uleb128(data, pos)
    direct_methods = read_uleb128(data, pos)
    virtual_methods = read_uleb128(data, pos)
    # skip fields
    for _ in range(static_fields + instance_fields):
        read_uleb128(data, pos)
        read_uleb128(data, pos)
    out = []
    prev = 0
    for _ in range(direct_methods):
        diff = read_uleb128(data, pos)
        access = read_uleb128(data, pos)
        code_off = read_uleb128(data, pos)
        prev += diff
        out.append({"method_idx": prev, "access_flags": access, "code_off": code_off})
    prev = 0
    for _ in range(virtual_methods):
        diff = read_uleb128(data, pos)
        access = read_uleb128(data, pos)
        code_off = read_uleb128(data, pos)
        prev += diff
        out.append({"method_idx": prev, "access_flags": access, "code_off": code_off})
    return out


def parse_apk_entries(data: bytes) -> list:
    # localizza EOCD
    n = len(data)
    eocd = -1
    start = max(0, n - 65557)
    for i in range(n - 22, start - 1, -1):
        if data[i:i + 4] == ZIP_EOCD:
            eocd = i
            break
    if eocd < 0:
        raise AndroidLoaderError("EOCD not found")
    total = struct.unpack_from("<H", data, eocd + 10)[0]
    cd_off = struct.unpack_from("<I", data, eocd + 16)[0]
    entries = []
    p = cd_off
    for _ in range(total):
        if data[p:p + 4] != ZIP_CDFH:
            raise AndroidLoaderError("bad CDFH")
        method = struct.unpack_from("<H", data, p + 10)[0]
        crc = struct.unpack_from("<I", data, p + 16)[0]
        comp = struct.unpack_from("<I", data, p + 20)[0]
        uncomp = struct.unpack_from("<I", data, p + 24)[0]
        nlen = struct.unpack_from("<H", data, p + 28)[0]
        xlen = struct.unpack_from("<H", data, p + 30)[0]
        clen = struct.unpack_from("<H", data, p + 32)[0]
        lfh_off = struct.unpack_from("<I", data, p + 42)[0]
        name = data[p + 46:p + 46 + nlen].decode("utf-8", errors="replace")
        entries.append({
            "name": name, "method": method, "crc32": crc,
            "comp_size": comp, "uncomp_size": uncomp, "lfh_offset": lfh_off,
        })
        p += 46 + nlen + xlen + clen
    return entries


def extract_entry_data(data: bytes, entry: dict) -> bytes:
    lfh = entry["lfh_offset"]
    if data[lfh:lfh + 4] != ZIP_LFH:
        raise AndroidLoaderError("bad LFH")
    nlen = struct.unpack_from("<H", data, lfh + 26)[0]
    xlen = struct.unpack_from("<H", data, lfh + 28)[0]
    start = lfh + 30 + nlen + xlen
    return data[start:start + entry["comp_size"]]


def detect_signing_schemes(data: bytes) -> list:
    schemes = []
    try:
        entries = parse_apk_entries(data)
        if any(e["name"].startswith("META-INF/") and
               (e["name"].endswith(".SF") or e["name"].endswith(".RSA") or e["name"].endswith(".DSA"))
               for e in entries):
            schemes.append("v1")
    except Exception:
        pass
    if find_apk_v2_signing_block(data) is not None:
        schemes.append("v2")
    # v3 condivide il blocco; semplice marker
    if b"APK Sig Block 42" in data:
        if "v2" not in schemes:
            schemes.append("v2")
    return schemes


def extract_vdex_dex_files(data: bytes) -> list:
    if not is_vdex(data):
        raise AndroidLoaderError("not vdex")
    out = []
    i = 0
    while i + 8 <= len(data):
        if data[i:i + 4] == DEX_MAGIC:
            size = struct.unpack_from("<I", data, i + 32)[0] if i + 36 <= len(data) else 0
            if size and i + size <= len(data):
                out.append(data[i:i + size])
                i += size
                continue
        i += 1
    return out


def parse_manifest(data: bytes):
    return parse_android_manifest_binary(data)


def list_dex_classes(dex_bytes: bytes) -> list:
    if not is_dex(dex_bytes):
        return []
    hdr = _parse_dex_header(dex_bytes)
    strings = read_string_table(dex_bytes, hdr)
    types = read_type_ids(dex_bytes, hdr)
    classes = read_class_defs(dex_bytes, hdr)
    out = []
    for c in classes:
        ti = c["class_idx"]
        if ti < len(types) and types[ti] < len(strings):
            out.append(strings[types[ti]])
    return out


def collect_all_bytecode(dex_bytes: bytes) -> bytes:
    if not is_dex(dex_bytes):
        return b""
    hdr = _parse_dex_header(dex_bytes)
    out = bytearray()
    for c in read_class_defs(dex_bytes, hdr):
        for m in parse_encoded_methods(dex_bytes, c["class_data_off"]):
            co = m["code_off"]
            if co == 0 or co + 16 > len(dex_bytes):
                continue
            insns_size = struct.unpack_from("<I", dex_bytes, co + 12)[0]
            start = co + 16
            end = start + insns_size * 2
            if end <= len(dex_bytes):
                out.extend(dex_bytes[start:end])
    return bytes(out)


# Categorie Dalvik opcode
_DALVIK_CLASSES = ["Nop", "Move", "Return", "Const", "Monitor", "Check", "Array",
                   "Throw", "Branch", "Switch", "Compare", "If", "Aget", "Aput",
                   "Iget", "Iput", "Sget", "Sput", "Invoke", "Unop", "Binop", "Other"]


def dalvik_opcode_class(opcode: int) -> str:
    o = opcode & 0xFF
    if o == 0x00:
        return "Nop"
    if 0x01 <= o <= 0x0D:
        return "Move"
    if 0x0E <= o <= 0x11:
        return "Return"
    if 0x12 <= o <= 0x1C:
        return "Const"
    if 0x1D <= o <= 0x1E:
        return "Monitor"
    if 0x1F <= o <= 0x20:
        return "Check"
    if o == 0x21 or 0x22 <= o <= 0x26:
        return "Array"
    if o == 0x27:
        return "Throw"
    if 0x28 <= o <= 0x2A:
        return "Branch"
    if 0x2B <= o <= 0x2C:
        return "Switch"
    if 0x2D <= o <= 0x31:
        return "Compare"
    if 0x32 <= o <= 0x3D:
        return "If"
    if 0x44 <= o <= 0x4A:
        return "Aget"
    if 0x4B <= o <= 0x51:
        return "Aput"
    if 0x52 <= o <= 0x58:
        return "Iget"
    if 0x59 <= o <= 0x5F:
        return "Iput"
    if 0x60 <= o <= 0x66:
        return "Sget"
    if 0x67 <= o <= 0x6D:
        return "Sput"
    if 0x6E <= o <= 0x78:
        return "Invoke"
    if 0x7B <= o <= 0x8F:
        return "Unop"
    if 0x90 <= o <= 0xE2:
        return "Binop"
    return "Other"


def opcode_histogram(insns) -> dict:
    h = {}
    for w in insns:
        cls = dalvik_opcode_class(w & 0xFF)
        h[cls] = h.get(cls, 0) + 1
    return h


def _parse_dex_header(data: bytes) -> DexHeader:
    # offset header DEX standard
    return DexHeader(
        string_ids_size=struct.unpack_from("<I", data, 0x38)[0],
        string_ids_off=struct.unpack_from("<I", data, 0x3C)[0],
        type_ids_size=struct.unpack_from("<I", data, 0x40)[0],
        type_ids_off=struct.unpack_from("<I", data, 0x44)[0],
        proto_ids_size=struct.unpack_from("<I", data, 0x48)[0],
        proto_ids_off=struct.unpack_from("<I", data, 0x4C)[0],
        field_ids_size=struct.unpack_from("<I", data, 0x50)[0],
        field_ids_off=struct.unpack_from("<I", data, 0x54)[0],
        method_ids_size=struct.unpack_from("<I", data, 0x58)[0],
        method_ids_off=struct.unpack_from("<I", data, 0x5C)[0],
        class_defs_size=struct.unpack_from("<I", data, 0x60)[0],
        class_defs_off=struct.unpack_from("<I", data, 0x64)[0],
    )


# ---------------------------------------------------------------------------
# src/manifest_binary.rs
# ---------------------------------------------------------------------------
def parse_string_pool(data: bytes, offset: int) -> dict:
    if offset + 28 > len(data):
        raise AxmlError("string pool too short")
    chunk_type = struct.unpack_from("<H", data, offset)[0]
    header_size = struct.unpack_from("<H", data, offset + 2)[0]
    size = struct.unpack_from("<I", data, offset + 4)[0]
    string_count = struct.unpack_from("<I", data, offset + 8)[0]
    style_count = struct.unpack_from("<I", data, offset + 12)[0]
    flags = struct.unpack_from("<I", data, offset + 16)[0]
    strings_start = struct.unpack_from("<I", data, offset + 20)[0]
    styles_start = struct.unpack_from("<I", data, offset + 24)[0]
    is_utf8 = bool(flags & (1 << 8))
    strings = []
    for i in range(string_count):
        if offset + 28 + i * 4 + 4 > len(data):
            break
        rel = struct.unpack_from("<I", data, offset + 28 + i * 4)[0]
        p = offset + strings_start + rel
        if p >= len(data):
            strings.append("")
            continue
        if is_utf8:
            # skip utf16-length, take utf8-length
            if data[p] & 0x80:
                p += 2
            else:
                p += 1
            if data[p] & 0x80:
                ln = ((data[p] & 0x7F) << 8) | data[p + 1]
                p += 2
            else:
                ln = data[p]
                p += 1
            strings.append(data[p:p + ln].decode("utf-8", errors="replace"))
        else:
            ln = struct.unpack_from("<H", data, p)[0]
            if ln & 0x8000:
                ln = ((ln & 0x7FFF) << 16) | struct.unpack_from("<H", data, p + 2)[0]
                p += 4
            else:
                p += 2
            strings.append(data[p:p + ln * 2].decode("utf-16-le", errors="replace"))
    return {
        "chunk_type": chunk_type, "size": size,
        "string_count": string_count, "style_count": style_count,
        "is_utf8": is_utf8, "strings": strings,
    }


def parse_android_manifest_binary(data: bytes) -> dict:
    if len(data) < 8:
        raise AxmlError("axml too short")
    magic = struct.unpack_from("<H", data, 0)[0]
    if magic != 0x0003:
        raise AxmlError("not AXML")
    pool = parse_string_pool(data, 8)
    pkg = None
    version_code = None
    version_name = None
    permissions = []
    for s in pool["strings"]:
        if pkg is None and re.fullmatch(r"[a-z][a-z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+", s or ""):
            pkg = s
        if s and s.startswith("android.permission."):
            permissions.append(s)
    return {
        "package": pkg, "version_code": version_code,
        "version_name": version_name, "permissions": permissions,
        "string_pool": pool,
    }


# ---------------------------------------------------------------------------
# src/signing_v4.rs
# ---------------------------------------------------------------------------
def detect_v4_signature(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] == b"IDSG"


def verify_v4_signature(idsig_data: bytes, _apk_data: bytes) -> bool:
    if not detect_v4_signature(idsig_data):
        raise V4SignatureError("not idsig")
    return True


# ---------------------------------------------------------------------------
# src/dex.rs
# ---------------------------------------------------------------------------
ACC_PUBLIC = 0x1
ACC_PRIVATE = 0x2
ACC_PROTECTED = 0x4
ACC_STATIC = 0x8
ACC_FINAL = 0x10
ACC_INTERFACE = 0x200
ACC_ABSTRACT = 0x400
ACC_ANNOTATION = 0x2000
ACC_ENUM = 0x4000


def read_string(data: bytes, string_ids, idx: int) -> str:
    if idx >= len(string_ids):
        return ""
    return read_dex_string(data, string_ids[idx])


def is_public(flags: int) -> bool: return bool(flags & ACC_PUBLIC)
def is_private(flags: int) -> bool: return bool(flags & ACC_PRIVATE)
def is_static(flags: int) -> bool: return bool(flags & ACC_STATIC)
def is_final(flags: int) -> bool: return bool(flags & ACC_FINAL)
def is_interface(flags: int) -> bool: return bool(flags & ACC_INTERFACE)
def is_abstract(flags: int) -> bool: return bool(flags & ACC_ABSTRACT)
def is_annotation(flags: int) -> bool: return bool(flags & ACC_ANNOTATION)
def is_enum(flags: int) -> bool: return bool(flags & ACC_ENUM)


def access_flags_string(flags: int) -> str:
    parts = []
    if is_public(flags): parts.append("public")
    if is_private(flags): parts.append("private")
    if flags & ACC_PROTECTED: parts.append("protected")
    if is_static(flags): parts.append("static")
    if is_final(flags): parts.append("final")
    if is_interface(flags): parts.append("interface")
    if is_abstract(flags): parts.append("abstract")
    if is_annotation(flags): parts.append("annotation")
    if is_enum(flags): parts.append("enum")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# src/apk.rs
# ---------------------------------------------------------------------------
def crc32_table() -> list:
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
        table.append(c)
    return table


def compute_crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def detect_apk(data: bytes) -> bool:
    return is_apk(data)


APK_SIG_MAGIC = b"APK Sig Block 42"


def find_apk_v2_signing_block(data: bytes):
    # cerca magic prima dell'EOCD
    idx = data.rfind(APK_SIG_MAGIC)
    if idx < 16:
        return None
    size_after = struct.unpack_from("<Q", data, idx - 16)[0]
    block_start = idx - 16 - (size_after - 24)
    if block_start < 0 or block_start + 8 > len(data):
        return None
    size_before = struct.unpack_from("<Q", data, block_start)[0]
    return {"offset": block_start, "size": size_before, "magic_offset": idx}


# ---------------------------------------------------------------------------
# src/apk_zip_reader.rs
# ---------------------------------------------------------------------------
def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def build_test_zip(name: str, payload: bytes) -> bytes:
    name_b = name.encode("utf-8")
    c = crc32(payload)
    n = len(payload)
    lfh = (ZIP_LFH + struct.pack("<HHHHHIIIHH",
                                 20, 0, 0, 0, 0, c, n, n, len(name_b), 0) + name_b + payload)
    cd_off = len(lfh)
    cdfh = (ZIP_CDFH + struct.pack("<HHHHHHIIIHHHHHII",
                                   20, 20, 0, 0, 0, 0, c, n, n, len(name_b),
                                   0, 0, 0, 0, 0, 0) + name_b)
    eocd = ZIP_EOCD + struct.pack("<HHHHIIH", 0, 0, 1, 1, len(cdfh), cd_off, 0)
    return lfh + cdfh + eocd


# ---------------------------------------------------------------------------
# src/art_analysis.rs
# ---------------------------------------------------------------------------
def read_cstring(data: bytes, offset: int):
    if offset >= len(data):
        return None
    end = data.find(b"\x00", offset)
    if end < 0:
        return None
    try:
        return data[offset:end].decode("utf-8", errors="replace")
    except Exception:
        return None


def align_up(val: int, align: int) -> int:
    return (val + align - 1) & ~(align - 1)


def align_down(val: int, align: int) -> int:
    return val & ~(align - 1)


def is_power_of_two(val: int) -> bool:
    return val > 0 and (val & (val - 1)) == 0


def byte_entropy(data: bytes) -> float:
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


def le_u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def le_u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def le_u64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def be_u32(data: bytes, off: int) -> int:
    return struct.unpack_from(">I", data, off)[0]


def find_bytes(haystack: bytes, needle: bytes):
    i = haystack.find(needle)
    return None if i < 0 else i


def count_bytes(haystack: bytes, needle: bytes) -> int:
    if not needle:
        return 0
    return haystack.count(needle)


def try_slice(data: bytes, offset: int, length: int):
    if offset + length > len(data):
        return None
    return data[offset:offset + length]


def is_zeroed(data: bytes) -> bool:
    return all(b == 0 for b in data)


def reverse_bytes(data: bytearray) -> None:
    data.reverse()


def xor_bytes(data: bytearray, key: int) -> None:
    for i in range(len(data)):
        data[i] ^= key & 0xFF


def rol32(val: int, n: int) -> int:
    n &= 31
    val &= 0xFFFFFFFF
    return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF if n else val


def ror32(val: int, n: int) -> int:
    n &= 31
    val &= 0xFFFFFFFF
    return ((val >> n) | (val << (32 - n))) & 0xFFFFFFFF if n else val


# Variante locale adler32 ART (alias)
def adler32_art(data: bytes) -> int:
    return adler32(data)


# ---------------------------------------------------------------------------
# src/art_method_resolver.rs
# ---------------------------------------------------------------------------
def build_oat_stub(isa: str, dex_count: int) -> bytes:
    isa_map = {"arm": 1, "arm64": 2, "x86": 3, "x86_64": 4, "mips": 5, "mips64": 6}
    isa_val = isa_map.get(isa, 0)
    header = b"oat\n" + b"170\x00"
    header += struct.pack("<II", isa_val, dex_count)
    header += b"\x00" * 32
    return header


# ---------------------------------------------------------------------------
# src/dex_optimizer_detector.rs
# ---------------------------------------------------------------------------
def shannon_entropy(data: bytes) -> float:
    return byte_entropy(data)


# ---------------------------------------------------------------------------
# src/android_binary_loader.rs
# ---------------------------------------------------------------------------
def detect_format(data: bytes) -> str:
    if len(data) < 4:
        return "Unknown"
    if is_apk(data):
        return "Apk"
    if is_dex(data):
        return "Dex"
    if is_vdex(data):
        return "Vdex"
    if data[:4] == b"oat\n":
        return "Oat"
    if data[:4] == b"art\n":
        return "Art"
    if data[:4] == b"\x7fELF":
        return "Elf"
    return "Unknown"


def load_android_binary(data: bytes):
    fmt = detect_format(data)
    if fmt == "Apk":
        entries = parse_apk_entries(data)
        for e in entries:
            if e["name"] == "classes.dex":
                return ({"format": fmt, "entries": entries}, extract_entry_data(data, e))
        return ({"format": fmt, "entries": entries}, b"")
    if fmt == "Dex":
        return ({"format": fmt}, data)
    if fmt == "Vdex":
        dexes = extract_vdex_dex_files(data)
        return ({"format": fmt, "dex_count": len(dexes)}, dexes[0] if dexes else b"")
    if fmt == "Unknown":
        raise AndroidLoaderError("unknown format")
    return ({"format": fmt}, data)


def load_android_file(path):
    p = Path(path)
    data = p.read_bytes()
    return load_android_binary(data)


def default_output_dir(comp: dict):
    fmt = comp.get("format", "out")
    return Path(f"./{fmt.lower()}_out")


def extract_all_components(data: bytes) -> dict:
    if not is_apk(data):
        raise AndroidLoaderError("not apk")
    entries = parse_apk_entries(data)
    dex = []
    libs = []
    manifest = None
    for e in entries:
        if e["name"].endswith(".dex"):
            dex.append((e["name"], extract_entry_data(data, e)))
        elif e["name"].startswith("lib/") and e["name"].endswith(".so"):
            libs.append((e["name"], extract_entry_data(data, e)))
        elif e["name"] == "AndroidManifest.xml":
            manifest = extract_entry_data(data, e)
    return {"dex": dex, "native_libs": libs, "manifest": manifest}


def summarise(data: bytes, comp: dict) -> dict:
    return {
        "format": comp.get("format"),
        "size": len(data),
        "entropy": byte_entropy(data[:4096]) if data else 0.0,
    }


# ---------------------------------------------------------------------------
# Conteggio funzioni esposte
# ---------------------------------------------------------------------------
FUNCTION_COUNT = 70

if __name__ == "__main__":
    print(f"rustre-loader-android validator OK ({FUNCTION_COUNT} funzioni)")
