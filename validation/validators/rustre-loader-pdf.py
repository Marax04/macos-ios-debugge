"""
Validators for rustre-loader-pdf crate.
Each validator_NAME(input) -> output mirrors the documented public function.
Pure Python stdlib — no external dependencies.
"""

import re
import zlib
import struct
import hashlib
import math
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Any


# ---------------------------------------------------------------------------
# Data structures mirroring Rust types
# ---------------------------------------------------------------------------

@dataclass
class PdfStream:
    object_num: int
    offset: int
    length: int
    filters: List[str]
    raw: bytes


@dataclass
class PdfMetadata:
    author: Optional[str] = None
    title: Optional[str] = None
    creator: Optional[str] = None
    producer: Optional[str] = None
    creation_date: Optional[str] = None
    mod_date: Optional[str] = None


@dataclass
class PdfForensics:
    md5: str
    sha256: str
    size: int
    entropy: float
    anomalies: List[str]


@dataclass
class ThreatEntry:
    category: str
    description: str
    severity: int  # 0-10
    offset: int = 0


@dataclass
class SecurityReport:
    threats: List[ThreatEntry]
    risk_score: int  # 0-100


@dataclass
class ObfuscationPattern:
    pattern_type: str
    match_text: str
    offset: int


@dataclass
class HeapSprayDetect:
    detected: bool
    nop_sled: bool
    repeated_blocks: int
    shellcode_like: bool


@dataclass
class ShellcodeHint:
    hint_type: str
    offset: int
    bytes_hex: str


@dataclass
class RiskScore:
    score: int  # 0-100
    details: Dict[str, Any]


# Stub document/catalog/info/encrypt types
@dataclass
class PdfCatalog:
    raw: Dict[str, str]


@dataclass
class PdfInfo:
    raw: Dict[str, str]


@dataclass
class PdfEncrypt:
    raw: Dict[str, str]


@dataclass
class PdfDocument:
    data: bytes
    objects: List[Dict]
    xref: List[Tuple[int, int]]
    trailer: Dict[str, str]
    streams: List[PdfStream]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_all(data: bytes, pattern: bytes) -> List[int]:
    """Return all offsets where pattern occurs in data."""
    offsets = []
    start = 0
    while True:
        idx = data.find(pattern, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1
    return offsets


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for f in freq:
        if f:
            p = f / n
            ent -= p * math.log2(p)
    return ent


def _extract_dict_value(data: bytes, key: bytes) -> Optional[str]:
    """Very naive PDF dictionary value extractor for string/name values."""
    idx = data.find(key)
    if idx == -1:
        return None
    rest = data[idx + len(key):]
    # skip whitespace
    rest = rest.lstrip(b' \t\r\n')
    if rest.startswith(b'('):
        end = rest.find(b')', 1)
        if end != -1:
            return rest[1:end].decode('latin-1', errors='replace')
    elif rest.startswith(b'/'):
        m = re.match(rb'/([^\s/><\[\]()]+)', rest)
        if m:
            return m.group(1).decode('latin-1', errors='replace')
    return None


# ---------------------------------------------------------------------------
# lib.rs validators
# ---------------------------------------------------------------------------

def validator_is_pdf(data: bytes) -> bool:
    """Verifica la firma magic %PDF- all'inizio del file."""
    return data[:5] == b'%PDF-'


def validator_pdf_version(data: bytes) -> Optional[str]:
    """Estrae la versione PDF dall'header (es. '1.7')."""
    if not data[:5] == b'%PDF-':
        return None
    m = re.match(rb'%PDF-(\d+\.\d+)', data[:20])
    if m:
        return m.group(1).decode('ascii')
    return None


def validator_has_javascript(data: bytes) -> bool:
    """Rileva la presenza di stream JavaScript nel PDF."""
    return b'/JavaScript' in data or b'/JS' in data


def validator_has_embedded_files(data: bytes) -> bool:
    """Rileva file embeddati nel PDF."""
    return b'/EmbeddedFile' in data or b'/Filespec' in data or b'/FileAttachment' in data


def validator_xref_offsets(data: bytes) -> List[Tuple[int, int]]:
    """
    Estrae le entry xref (object_num, file_offset).
    Parses classic cross-reference table sections.
    """
    results = []
    xref_pos = data.rfind(b'xref')
    if xref_pos == -1:
        return results
    pos = xref_pos + 4
    while pos < len(data):
        # skip whitespace
        while pos < len(data) and data[pos:pos+1] in (b' ', b'\t', b'\r', b'\n'):
            pos += 1
        # read subsection header: first_obj count
        line_end = data.find(b'\n', pos)
        if line_end == -1:
            break
        line = data[pos:line_end].strip()
        if line.startswith(b'trailer') or line == b'':
            break
        parts = line.split()
        if len(parts) != 2:
            break
        try:
            first_obj = int(parts[0])
            count = int(parts[1])
        except ValueError:
            break
        pos = line_end + 1
        for i in range(count):
            entry_end = data.find(b'\n', pos)
            if entry_end == -1:
                entry_end = len(data)
            entry = data[pos:entry_end].strip()
            pos = entry_end + 1
            ep = entry.split()
            if len(ep) >= 3 and ep[2] == b'n':
                try:
                    offset = int(ep[0])
                    obj_num = first_obj + i
                    results.append((obj_num, offset))
                except ValueError:
                    pass
    return results


def validator_extract_streams(data: bytes) -> List[PdfStream]:
    """Estrae tutti gli stream raw dal PDF."""
    streams = []
    obj_pattern = re.compile(rb'(\d+)\s+\d+\s+obj', re.DOTALL)
    stream_start_pat = re.compile(rb'stream\r?\n', re.DOTALL)
    endstream_pat = re.compile(rb'\nendstream', re.DOTALL)
    length_pat = re.compile(rb'/Length\s+(\d+)')
    filter_pat = re.compile(rb'/Filter\s+(/\w+|\[.*?\])', re.DOTALL)

    for m in obj_pattern.finditer(data):
        obj_num = int(m.group(1))
        obj_offset = m.start()
        # find stream keyword after obj
        ss = stream_start_pat.search(data, m.end())
        if not ss:
            continue
        # check that there's no 'endobj' between obj and stream
        between = data[m.end():ss.start()]
        if b'endobj' in between:
            continue
        stream_data_start = ss.end()
        # find length
        lm = length_pat.search(data, obj_offset, ss.start())
        length = int(lm.group(1)) if lm else 0
        # extract raw bytes
        raw = data[stream_data_start:stream_data_start + length] if length else b''
        # filters
        fm = filter_pat.search(data, obj_offset, ss.start())
        filters: List[str] = []
        if fm:
            fval = fm.group(1).decode('latin-1', errors='replace')
            filters = re.findall(r'/(\w+)', fval)
        streams.append(PdfStream(
            object_num=obj_num,
            offset=stream_data_start,
            length=length,
            filters=filters,
            raw=raw,
        ))
    return streams


def validator_decode_percent_encoding(s: str) -> bytes:
    """Decodifica encoding percentuale (%XX)."""
    result = bytearray()
    i = 0
    encoded = s.encode('ascii', errors='replace')
    while i < len(s):
        c = s[i]
        if c == '%' and i + 2 < len(s):
            hex_str = s[i+1:i+3]
            try:
                result.append(int(hex_str, 16))
                i += 3
                continue
            except ValueError:
                pass
        result.append(ord(c) & 0xFF)
        i += 1
    return bytes(result)


def validator_deobfuscate_js_simple(js: str) -> str:
    """
    Deoffuscazione semplice: rimuove unescape/eval wrapping e
    decodifica sequenze \\uXXXX e \\xXX.
    """
    result = js
    # strip eval( ... ) layers
    for _ in range(5):
        m = re.match(r'^\s*eval\s*\((.*)\)\s*;?\s*$', result, re.DOTALL)
        if m:
            result = m.group(1).strip()
        else:
            break
    # strip unescape( "..." )
    m = re.match(r'^\s*unescape\s*\(\s*["\'](.+)["\']\s*\)\s*;?\s*$', result, re.DOTALL)
    if m:
        result = validator_decode_percent_encoding(m.group(1)).decode('latin-1', errors='replace')
    # decode \uXXXX
    result = re.sub(r'\\u([0-9a-fA-F]{4})', lambda x: chr(int(x.group(1), 16)), result)
    # decode \xXX
    result = re.sub(r'\\x([0-9a-fA-F]{2})', lambda x: chr(int(x.group(1), 16)), result)
    return result


def validator_extract_urls_from_js(js: str) -> List[str]:
    """Estrae URL/URI dal codice JavaScript."""
    pattern = r'https?://[^\s\'"<>)(\[\]{}]+'
    return re.findall(pattern, js)


# ---------------------------------------------------------------------------
# metadata.rs validators
# ---------------------------------------------------------------------------

def validator_extract_metadata(data: bytes) -> PdfMetadata:
    """Estrae autore, titolo, creatore, date dall'Info dictionary."""
    meta = PdfMetadata()
    meta.author = _extract_dict_value(data, b'/Author')
    meta.title = _extract_dict_value(data, b'/Title')
    meta.creator = _extract_dict_value(data, b'/Creator')
    meta.producer = _extract_dict_value(data, b'/Producer')
    meta.creation_date = _extract_dict_value(data, b'/CreationDate')
    meta.mod_date = _extract_dict_value(data, b'/ModDate')
    return meta


def validator_detect_linearized(data: bytes) -> bool:
    """Rileva se il PDF è linearizzato (fast web view)."""
    return b'/Linearized' in data[:2048]


def validator_count_updates(data: bytes) -> int:
    """Conta le revisioni incrementali (numero di %%EOF)."""
    return data.count(b'%%EOF')


def validator_count_objects(data: bytes) -> int:
    """Conta le entry 'obj' nel file."""
    return len(re.findall(rb'\d+\s+\d+\s+obj', data))


def validator_detect_xref_stream(data: bytes) -> bool:
    """Rileva se la xref è in formato stream (PDF 1.5+)."""
    # XRef stream objects contain /Type /XRef
    return b'/Type /XRef' in data or b'/Type/XRef' in data


def validator_compute_forensics(data: bytes) -> PdfForensics:
    """Calcola hash, dimensione, entropia e anomalie forensi."""
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    size = len(data)
    entropy = _entropy(data)
    anomalies: List[str] = []
    if not data[:5] == b'%PDF-':
        anomalies.append('missing_pdf_magic')
    eof_count = data.count(b'%%EOF')
    if eof_count > 1:
        anomalies.append(f'multiple_eof:{eof_count}')
    if entropy > 7.5:
        anomalies.append('high_entropy_possible_encryption')
    return PdfForensics(md5=md5, sha256=sha256, size=size, entropy=entropy, anomalies=anomalies)


# ---------------------------------------------------------------------------
# security.rs validators
# ---------------------------------------------------------------------------

def validator_scan_javascript(data: bytes) -> List[ThreatEntry]:
    """Rileva stream JS e segnala come minaccia."""
    threats = []
    for pattern in (b'/JavaScript', b'/JS'):
        for off in _find_all(data, pattern):
            threats.append(ThreatEntry(
                category='javascript',
                description=f'JavaScript stream at offset {off}',
                severity=7,
                offset=off,
            ))
    return threats


def validator_scan_embedded_files(data: bytes) -> List[ThreatEntry]:
    """Rileva file embeddati sospetti."""
    threats = []
    for pattern in (b'/EmbeddedFile', b'/FileAttachment'):
        for off in _find_all(data, pattern):
            threats.append(ThreatEntry(
                category='embedded_file',
                description=f'{pattern.decode()} at offset {off}',
                severity=6,
                offset=off,
            ))
    return threats


def validator_scan_launch_actions(data: bytes) -> List[ThreatEntry]:
    """Rileva azioni /Launch (esecuzione di comandi)."""
    threats = []
    for off in _find_all(data, b'/Launch'):
        threats.append(ThreatEntry(
            category='launch_action',
            description=f'/Launch action at offset {off}',
            severity=9,
            offset=off,
        ))
    return threats


def validator_scan_uri_actions(data: bytes) -> List[ThreatEntry]:
    """Rileva azioni /URI potenzialmente pericolose."""
    threats = []
    for off in _find_all(data, b'/URI'):
        threats.append(ThreatEntry(
            category='uri_action',
            description=f'/URI action at offset {off}',
            severity=4,
            offset=off,
        ))
    return threats


def validator_scan_openactions(data: bytes) -> List[ThreatEntry]:
    """Rileva /OpenAction automatici all'apertura."""
    threats = []
    for off in _find_all(data, b'/OpenAction'):
        threats.append(ThreatEntry(
            category='open_action',
            description=f'/OpenAction at offset {off}',
            severity=8,
            offset=off,
        ))
    return threats


def validator_scan_obfuscation(data: bytes) -> List[ThreatEntry]:
    """Rileva tecniche di offuscamento nel PDF."""
    threats = []
    patterns = [
        (b'unescape', 'unescape_call', 5),
        (b'String.fromCharCode', 'fromcharcode', 5),
        (b'eval(', 'eval_call', 6),
    ]
    for pat, category, sev in patterns:
        for off in _find_all(data, pat):
            threats.append(ThreatEntry(
                category=category,
                description=f'Obfuscation pattern {pat.decode()} at {off}',
                severity=sev,
                offset=off,
            ))
    return threats


def validator_scan_xfa(data: bytes) -> List[ThreatEntry]:
    """Rileva form XFA (vettore d'attacco noto)."""
    threats = []
    for off in _find_all(data, b'/XFA'):
        threats.append(ThreatEntry(
            category='xfa_form',
            description=f'/XFA form at offset {off}',
            severity=7,
            offset=off,
        ))
    return threats


def validator_calculate_risk_score(threats: List[ThreatEntry]) -> int:
    """Calcola punteggio di rischio aggregato pesato (0-100)."""
    if not threats:
        return 0
    # weighted: max severity * presence weight
    total = 0
    for t in threats:
        total += t.severity * 2
    return min(100, total)


def validator_scan_pdf(data: bytes) -> SecurityReport:
    """Scansione completa: aggrega tutti i sotto-scanner in un report."""
    threats: List[ThreatEntry] = []
    threats += validator_scan_javascript(data)
    threats += validator_scan_embedded_files(data)
    threats += validator_scan_launch_actions(data)
    threats += validator_scan_uri_actions(data)
    threats += validator_scan_openactions(data)
    threats += validator_scan_obfuscation(data)
    threats += validator_scan_xfa(data)
    risk = validator_calculate_risk_score(threats)
    return SecurityReport(threats=threats, risk_score=risk)


# ---------------------------------------------------------------------------
# structures.rs validators (operate on PdfDocument)
# ---------------------------------------------------------------------------

def validator_extract_catalog(doc: PdfDocument) -> PdfCatalog:
    """Estrae il Catalog dictionary (root del PDF)."""
    raw: Dict[str, str] = {}
    for key in (b'/Type', b'/Pages', b'/Outlines', b'/OpenAction'):
        val = _extract_dict_value(doc.data, key)
        if val is not None:
            raw[key.decode()] = val
    return PdfCatalog(raw=raw)


def validator_extract_info(doc: PdfDocument) -> PdfInfo:
    """Estrae l'Info dictionary (metadati documento)."""
    raw: Dict[str, str] = {}
    for key in (b'/Author', b'/Title', b'/Creator', b'/Producer', b'/CreationDate', b'/ModDate'):
        val = _extract_dict_value(doc.data, key)
        if val is not None:
            raw[key.decode()] = val
    return PdfInfo(raw=raw)


def validator_extract_encrypt(doc: PdfDocument) -> Optional[PdfEncrypt]:
    """Estrae il dictionary di cifratura, se presente."""
    if b'/Encrypt' not in doc.data:
        return None
    raw: Dict[str, str] = {}
    for key in (b'/Filter', b'/V', b'/R', b'/Length', b'/P'):
        val = _extract_dict_value(doc.data, key)
        if val is not None:
            raw[key.decode()] = val
    return PdfEncrypt(raw=raw)


def validator_enumerate_streams(doc: PdfDocument) -> List[PdfStream]:
    """Enumera tutti gli stream del documento con metadati."""
    return validator_extract_streams(doc.data)


# ---------------------------------------------------------------------------
# pdf_stream_decoder.rs validators
# ---------------------------------------------------------------------------

class DecodeError(Exception):
    pass


def validator_flate_decompress(data: bytes) -> bytes:
    """Decompressione Deflate/zlib (filtro FlateDecode)."""
    try:
        return zlib.decompress(data)
    except zlib.error:
        try:
            return zlib.decompress(data, -15)  # raw deflate
        except zlib.error as e:
            raise DecodeError(f'flate decompress failed: {e}') from e


def validator_png_predictor_undo(
    data: bytes,
    colors: int,
    bits: int,
    columns: int,
    predictor: int,
) -> bytes:
    """
    Annulla predittore PNG (sub/up/average/Paeth) per FlateDecode.
    predictor: 10=None,11=Sub,12=Up,13=Average,14=Paeth,15=Optimum(per-row tag)
    """
    bpp = max(1, (colors * bits + 7) // 8)
    stride = (columns * colors * bits + 7) // 8
    row_len = stride + 1  # +1 for filter byte
    result = bytearray()
    prev_row = bytearray(stride)

    for row_idx in range(len(data) // row_len):
        row_start = row_idx * row_len
        filter_byte = data[row_start]
        row = bytearray(data[row_start + 1: row_start + 1 + stride])
        out = bytearray(stride)

        def paeth(a: int, b: int, c: int) -> int:
            p = a + b - c
            pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
            if pa <= pb and pa <= pc:
                return a
            elif pb <= pc:
                return b
            return c

        for i in range(stride):
            left = out[i - bpp] if i >= bpp else 0
            up = prev_row[i]
            up_left = prev_row[i - bpp] if i >= bpp else 0
            raw_byte = row[i]
            if filter_byte == 0:   # None
                out[i] = raw_byte
            elif filter_byte == 1: # Sub
                out[i] = (raw_byte + left) & 0xFF
            elif filter_byte == 2: # Up
                out[i] = (raw_byte + up) & 0xFF
            elif filter_byte == 3: # Average
                out[i] = (raw_byte + (left + up) // 2) & 0xFF
            elif filter_byte == 4: # Paeth
                out[i] = (raw_byte + paeth(left, up, up_left)) & 0xFF
            else:
                out[i] = raw_byte

        result.extend(out)
        prev_row = out

    return bytes(result)


def validator_tiff_predictor_undo(
    data: bytes,
    colors: int,
    bits: int,
    columns: int,
) -> bytes:
    """Annulla predittore TIFF orizzontale."""
    bpp = max(1, (colors * bits + 7) // 8)
    stride = (columns * colors * bits + 7) // 8
    result = bytearray()
    for row_start in range(0, len(data), stride):
        row = bytearray(data[row_start:row_start + stride])
        for i in range(bpp, len(row)):
            row[i] = (row[i] + row[i - bpp]) & 0xFF
        result.extend(row)
    return bytes(result)


def validator_lzw_decompress(data: bytes, early_change: bool = True) -> bytes:
    """Decompressione LZW (filtro LZWDecode, con flag EarlyChange)."""
    # Build initial table
    table: List[bytes] = [bytes([i]) for i in range(256)]
    table.append(b'')  # 256 = clear code
    table.append(b'')  # 257 = EOD

    CLEAR = 256
    EOD = 257

    def reset():
        nonlocal table, code_size
        table = [bytes([i]) for i in range(256)]
        table.append(b'')  # clear
        table.append(b'')  # EOD
        code_size = 9

    code_size = 9
    result = bytearray()
    buf = int.from_bytes(data, 'big')
    total_bits = len(data) * 8
    bit_pos = 0

    def read_code() -> int:
        nonlocal bit_pos
        shift = total_bits - bit_pos - code_size
        if shift < 0:
            return EOD
        code = (buf >> shift) & ((1 << code_size) - 1)
        bit_pos += code_size
        return code

    prev: Optional[bytes] = None
    while bit_pos < total_bits:
        code = read_code()
        if code == EOD:
            break
        if code == CLEAR:
            reset()
            prev = None
            continue

        if code < len(table) and table[code]:
            entry = table[code]
        elif prev is not None and code == len(table):
            entry = prev + prev[:1]
        else:
            break

        result.extend(entry)

        if prev is not None:
            new_entry = prev + entry[:1]
            table.append(new_entry)
            threshold = (1 << code_size) - (1 if early_change else 0)
            if len(table) >= threshold and code_size < 12:
                code_size += 1

        prev = entry

    return bytes(result)


# ---------------------------------------------------------------------------
# pdf_full_parser.rs validators
# ---------------------------------------------------------------------------

def _parse_pdf_bytes(data: bytes) -> PdfDocument:
    """Parse PDF from raw bytes into PdfDocument."""
    xref = validator_xref_offsets(data)
    streams = validator_extract_streams(data)
    trailer: Dict[str, str] = {}
    for key in (b'/Size', b'/Root', b'/Info', b'/Encrypt'):
        val = _extract_dict_value(data, key)
        if val is not None:
            trailer[key.decode()] = val
    return PdfDocument(data=data, objects=[], xref=xref, trailer=trailer, streams=streams)


def validator_parse_pdf_from_reader(reader) -> PdfDocument:
    """Parsing completo del PDF da qualsiasi reader (file-like con .read())."""
    data = reader.read()
    return _parse_pdf_bytes(data)


def validator_parse_pdf_from_buf_reader(reader) -> PdfDocument:
    """Parsing completo del PDF da reader bufferizzato."""
    data = reader.read()
    return _parse_pdf_bytes(data)


# ---------------------------------------------------------------------------
# pdf_js_extractor.rs validators
# ---------------------------------------------------------------------------

def validator_detect_obfuscation(source: str) -> List[ObfuscationPattern]:
    """Rileva pattern di offuscamento (eval, unescape, hex encoding, ecc.)."""
    patterns_re = [
        ('eval_call', r'eval\s*\('),
        ('unescape_call', r'unescape\s*\('),
        ('fromcharcode', r'String\.fromCharCode\s*\('),
        ('hex_literal', r'0x[0-9a-fA-F]{4,}'),
        ('escape_unicode', r'\\u[0-9a-fA-F]{4}'),
        ('escape_hex', r'\\x[0-9a-fA-F]{2}'),
        ('document_write', r'document\.write\s*\('),
    ]
    results: List[ObfuscationPattern] = []
    for pat_type, pattern in patterns_re:
        for m in re.finditer(pattern, source):
            results.append(ObfuscationPattern(
                pattern_type=pat_type,
                match_text=m.group(0),
                offset=m.start(),
            ))
    return results


def validator_detect_heap_spray(source: str) -> HeapSprayDetect:
    """
    Analisi heap spray: NOP sled, shellcode pattern, ripetizioni.
    Heuristic: large repeated strings are a heap-spray indicator.
    """
    nop_sled = bool(re.search(r'(\\x90){8,}', source) or re.search(r'(\\u9090){4,}', source))
    shellcode_like = bool(re.search(r'(\\x[0-9a-fA-F]{2}){8,}', source))
    # count repeated blocks: same substring of 8+ chars repeated 10+ times
    repeated_blocks = 0
    for length in (8, 16, 32):
        seen: Dict[str, int] = {}
        for i in range(0, len(source) - length, length):
            chunk = source[i:i+length]
            seen[chunk] = seen.get(chunk, 0) + 1
        repeated_blocks += sum(1 for v in seen.values() if v >= 10)
    detected = nop_sled or shellcode_like or repeated_blocks > 0
    return HeapSprayDetect(
        detected=detected,
        nop_sled=nop_sled,
        repeated_blocks=repeated_blocks,
        shellcode_like=shellcode_like,
    )


def validator_detect_shellcode_hints(data: bytes) -> List[ShellcodeHint]:
    """Rileva pattern tipici di shellcode nei byte."""
    hints: List[ShellcodeHint] = []
    # NOP sled
    nop_pattern = re.compile(rb'\x90{8,}')
    for m in nop_pattern.finditer(data):
        hints.append(ShellcodeHint(
            hint_type='nop_sled',
            offset=m.start(),
            bytes_hex=m.group(0).hex(),
        ))
    # Common shellcode preambles (x86)
    shellcode_patterns = [
        (rb'\xfc\xe8', 'metasploit_preamble'),
        (rb'\x55\x8b\xec', 'prologue_x86'),
        (rb'\x48\x89\xe5', 'prologue_x64'),
        (rb'\xeb\xfe', 'infinite_loop'),
    ]
    for pat, hint_type in shellcode_patterns:
        for m in re.finditer(re.escape(pat), data):
            hints.append(ShellcodeHint(
                hint_type=hint_type,
                offset=m.start(),
                bytes_hex=m.group(0).hex(),
            ))
    return hints


def validator_find_suspicious_calls(source: str) -> List[str]:
    """Individua chiamate JS sospette (Collab.getIcon, util.printf, ecc.)."""
    suspicious = [
        r'Collab\.getIcon\s*\(',
        r'util\.printf\s*\(',
        r'this\.syncAnnotScan\s*\(',
        r'app\.doc\b',
        r'spell\.customDictionaryOpen\s*\(',
        r'getAnnots\s*\(',
        r'media\.newPlayer\s*\(',
        r'XFAObject\b',
        r'printSeps\s*\(',
        r'getURL\s*\(',
    ]
    found: List[str] = []
    for pat in suspicious:
        for m in re.finditer(pat, source):
            found.append(m.group(0))
    return found


def validator_compute_risk(
    obf: List[ObfuscationPattern],
    heap: HeapSprayDetect,
    shellcode: List[ShellcodeHint],
    calls: List[str],
) -> RiskScore:
    """Calcola punteggio di rischio aggregato degli script JS."""
    score = 0
    details: Dict[str, Any] = {}

    obf_score = min(30, len(obf) * 3)
    score += obf_score
    details['obfuscation'] = obf_score

    heap_score = 25 if heap.detected else 0
    if heap.nop_sled:
        heap_score = min(40, heap_score + 10)
    score += heap_score
    details['heap_spray'] = heap_score

    shell_score = min(20, len(shellcode) * 5)
    score += shell_score
    details['shellcode_hints'] = shell_score

    call_score = min(20, len(calls) * 4)
    score += call_score
    details['suspicious_calls'] = call_score

    return RiskScore(score=min(100, score), details=details)


# ---------------------------------------------------------------------------
# Registry for introspection
# ---------------------------------------------------------------------------

VALIDATORS = {
    'is_pdf': validator_is_pdf,
    'pdf_version': validator_pdf_version,
    'has_javascript': validator_has_javascript,
    'has_embedded_files': validator_has_embedded_files,
    'xref_offsets': validator_xref_offsets,
    'extract_streams': validator_extract_streams,
    'decode_percent_encoding': validator_decode_percent_encoding,
    'deobfuscate_js_simple': validator_deobfuscate_js_simple,
    'extract_urls_from_js': validator_extract_urls_from_js,
    # metadata.rs
    'extract_metadata': validator_extract_metadata,
    'detect_linearized': validator_detect_linearized,
    'count_updates': validator_count_updates,
    'count_objects': validator_count_objects,
    'detect_xref_stream': validator_detect_xref_stream,
    'compute_forensics': validator_compute_forensics,
    # security.rs
    'scan_pdf': validator_scan_pdf,
    'scan_javascript': validator_scan_javascript,
    'scan_embedded_files': validator_scan_embedded_files,
    'scan_launch_actions': validator_scan_launch_actions,
    'scan_uri_actions': validator_scan_uri_actions,
    'scan_openactions': validator_scan_openactions,
    'scan_obfuscation': validator_scan_obfuscation,
    'scan_xfa': validator_scan_xfa,
    'calculate_risk_score': validator_calculate_risk_score,
    # structures.rs
    'extract_catalog': validator_extract_catalog,
    'extract_info': validator_extract_info,
    'extract_encrypt': validator_extract_encrypt,
    'enumerate_streams': validator_enumerate_streams,
    # pdf_stream_decoder.rs
    'flate_decompress': validator_flate_decompress,
    'png_predictor_undo': validator_png_predictor_undo,
    'tiff_predictor_undo': validator_tiff_predictor_undo,
    'lzw_decompress': validator_lzw_decompress,
    # pdf_full_parser.rs
    'parse_pdf_from_reader': validator_parse_pdf_from_reader,
    'parse_pdf_from_buf_reader': validator_parse_pdf_from_buf_reader,
    # pdf_js_extractor.rs
    'detect_obfuscation': validator_detect_obfuscation,
    'detect_heap_spray': validator_detect_heap_spray,
    'detect_shellcode_hints': validator_detect_shellcode_hints,
    'find_suspicious_calls': validator_find_suspicious_calls,
    'compute_risk': validator_compute_risk,
}

FN_COUNT = len(VALIDATORS)

if __name__ == '__main__':
    print(f'rustre-loader-pdf validators: {FN_COUNT} functions loaded')
    for name in sorted(VALIDATORS):
        print(f'  validator_{name}')
