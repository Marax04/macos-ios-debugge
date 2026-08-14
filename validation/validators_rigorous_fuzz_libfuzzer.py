#!/usr/bin/env python3
"""
Rigorous validator for fuzz_libfuzzer MCP tools.
Computes ground truth independently via Python and compares against MCP output.
"""

import json
import subprocess
import sys
import time
import struct
from typing import Any, Dict, List, Optional, Tuple

MCP_PROCESS = None
MCP_ID_COUNTER = 1
MCP_BINARY = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
REPORT_PATH = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_fuzz_libfuzzer.json"


# ─── Python ground-truth helpers ─────────────────────────────────────────────

def xorshift64(state: int) -> int:
    """Single step of xorshift64 (Marsaglia 2003) — same as SimpleRng / XorShiftRng."""
    x = state & 0xFFFFFFFFFFFFFFFF
    x ^= (x << 13) & 0xFFFFFFFFFFFFFFFF
    x ^= (x >> 7)  & 0xFFFFFFFFFFFFFFFF
    x ^= (x << 17) & 0xFFFFFFFFFFFFFFFF
    return x


def simple_rng_sequence(seed: int, count: int) -> List[int]:
    """Reproduce SimpleRng::new(seed).next_u64() × count."""
    # If seed == 0 use fallback (same as Rust)
    state = seed if seed != 0 else 0xcafe_babe_dead_beef
    vals = []
    for _ in range(count):
        state = xorshift64(state)
        vals.append(state)
    return vals


def bucket_hit_count(b: int) -> int:
    """AFL hit-count bucketing — mirrors Rust coverage_feedback::bucket_hit_count."""
    if b == 0:   return 0
    if b == 1:   return 1
    if b == 2:   return 2
    if b == 3:   return 4
    if b <= 7:   return 8
    if b <= 15:  return 16
    if b <= 31:  return 32
    if b <= 127: return 64
    return 128


def bucket_bitmap(data: bytes) -> bytes:
    return bytes(bucket_hit_count(b) for b in data)


def count_new_bits_bucketed(global_bytes: bytes, current_bytes: bytes) -> int:
    """Mirror Rust count_new_bits_bucketed: edges where bucket(cur)!=0 and bucket(cur)>global[i]."""
    count = 0
    for g, c in zip(global_bytes, current_bytes):
        bc = bucket_hit_count(c)
        if bc != 0 and bc > g:
            count += 1
    return count


def structured_serialize(fields: List[Tuple[str, bytes]]) -> bytes:
    """Serialize StructuredInput: for each field, u16-LE length + data."""
    out = bytearray()
    for _name, data in fields:
        length = len(data)
        out += struct.pack('<H', length)
        out += data
    return bytes(out)


def structured_deserialize_field_count(blob: bytes) -> Optional[int]:
    """Count fields in a StructuredInput blob, or None if malformed."""
    pos = 0
    count = 0
    while pos + 2 <= len(blob):
        length = struct.unpack_from('<H', blob, pos)[0]
        pos += 2
        if pos + length > len(blob):
            return None
        pos += length
        count += 1
    if pos != len(blob):
        return None
    return count


def input_splice(a: bytes, b: bytes, seed: int) -> bytes:
    """Reproduce InputSplicer::splice with XorShiftRng(seed)."""
    if not a and not b:
        return b""
    if not a:
        return bytes(b)
    if not b:
        return bytes(a)
    # XorShiftRng default for 0 is 0xdead_beef_cafe_babe
    state = seed if seed != 0 else 0xdead_beef_cafe_babe
    state = xorshift64(state)
    split_a = state % len(a)
    state = xorshift64(state)
    split_b = state % len(b)
    return a[:split_a] + b[split_b:]


def parse_sanitizer_kind(output: str) -> str:
    """Mirror Rust parse_sanitizer_output for the kind string."""
    lower = output.lower()
    if 'heap-use-after-free' in lower:       return 'UseAfterFree'
    if 'heap-buffer-overflow' in lower:      return 'HeapOverflow'
    if 'stack-buffer-overflow' in lower:     return 'StackBufferOverflow'
    if 'global-buffer-overflow' in lower:    return 'GlobalBufferOverflow'
    if 'stack-overflow' in lower:            return 'StackOverflow'
    if 'double-free' in lower:              return 'DoubleFree'
    if 'use-after-return' in lower:          return 'UseAfterFree'
    if 'null' in lower and ('read' in lower or 'write' in lower):
        return 'NullDeref'
    if 'out-of-bounds' in lower and 'write' in lower:
        return 'OutOfBounds_write'
    if 'out-of-bounds' in lower:
        return 'OutOfBounds_read'
    if 'integer overflow' in lower or 'signed integer overflow' in lower:
        return 'IntegerOverflow'
    if 'division by zero' in lower:         return 'DivisionByZero'
    if 'reached unreachable code' in lower:  return 'UnreachableCode'
    if 'assertion' in lower or 'assert' in lower:
        return 'Assertion'
    if 'abort' in lower:                     return 'Abort'
    return 'Unknown'


def extract_fault_addr(output: str) -> Optional[int]:
    """Mirror Rust extract_fault_addr: find token starting with 0x with >=4 hex digits."""
    for part in output.split():
        for prefix in ('0x', '0X'):
            if part.startswith(prefix):
                hex_part = ''
                for ch in part[len(prefix):]:
                    if ch in '0123456789abcdefABCDEF':
                        hex_part += ch
                    else:
                        break
                if len(hex_part) >= 4:
                    try:
                        return int(hex_part, 16)
                    except ValueError:
                        pass
    return None


# ─── MCP helpers ─────────────────────────────────────────────────────────────

def start_mcp():
    global MCP_PROCESS
    MCP_PROCESS = subprocess.Popen(
        [MCP_BINARY],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding='utf-8',
        errors='replace',
        bufsize=1,
    )
    time.sleep(0.5)


def mcp_send_and_receive(msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        MCP_PROCESS.stdin.write(json.dumps(msg) + '\n')
        MCP_PROCESS.stdin.flush()
        line = MCP_PROCESS.stdout.readline()
        return json.loads(line) if line.strip() else None
    except Exception as e:
        print(f'    [comm error] {e}')
        return None


def mcp_initialize() -> bool:
    global MCP_ID_COUNTER
    resp = mcp_send_and_receive({
        'jsonrpc': '2.0', 'id': MCP_ID_COUNTER, 'method': 'initialize',
        'params': {
            'protocolVersion': '2024-11-05',
            'capabilities': {},
            'clientInfo': {'name': 'rigorous-validator', 'version': '1.0'},
        },
    })
    MCP_ID_COUNTER += 1
    if resp and 'result' in resp:
        MCP_PROCESS.stdin.write(json.dumps({
            'jsonrpc': '2.0', 'method': 'notifications/initialized', 'params': {}
        }) + '\n')
        MCP_PROCESS.stdin.flush()
        time.sleep(0.2)
        return True
    return False


def mcp_call_tool(name: str, args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    global MCP_ID_COUNTER
    resp = mcp_send_and_receive({
        'jsonrpc': '2.0', 'id': MCP_ID_COUNTER,
        'method': 'tools/call',
        'params': {'name': name, 'arguments': args},
    })
    MCP_ID_COUNTER += 1
    return resp


def extract_json(resp) -> Optional[Dict]:
    """Extract and parse the JSON text payload from an MCP tool response."""
    try:
        content = resp['result']['content'][0]['text']
        return json.loads(content)
    except Exception:
        return None


def get_tool_names() -> List[str]:
    global MCP_ID_COUNTER
    resp = mcp_send_and_receive({
        'jsonrpc': '2.0', 'id': MCP_ID_COUNTER,
        'method': 'tools/list', 'params': {},
    })
    MCP_ID_COUNTER += 1
    if resp and 'result' in resp:
        return [t['name'] for t in resp['result'].get('tools', [])]
    return []


# ─── Individual rigorous test cases ──────────────────────────────────────────

def test_bucket_bitmap() -> Tuple[bool, Dict]:
    """bucket_bitmap: known input → known output hex."""
    # Use bytes covering all bucket ranges
    inp = bytes([0, 1, 2, 3, 5, 9, 17, 33, 128, 200])
    expected = bytes([bucket_hit_count(b) for b in inp])
    expected_hex = expected.hex().upper()
    bitmap_hex = inp.hex()

    resp = mcp_call_tool('fuzz_libfuzzer_bucket_bitmap', {'bitmap_hex': bitmap_hex})
    if not resp:
        return False, {'note': 'MCP call failed'}
    data = extract_json(resp)
    if not data:
        return False, {'note': f'Bad response: {resp}'}

    got_hex = data.get('bucketed_hex', '')
    got_len = data.get('len', -1)
    match = got_hex == expected_hex and got_len == len(inp)
    return match, {
        'input_hex': bitmap_hex,
        'truth_hex': expected_hex,
        'mcp_hex': got_hex,
        'truth_len': len(inp),
        'mcp_len': got_len,
        'note': 'bucket_bitmap exact match' if match else f'MISMATCH: got {got_hex!r} want {expected_hex!r}',
    }


def test_count_new_bits_bucketed_all_new() -> Tuple[bool, Dict]:
    """count_new_bits_bucketed: global=all-zeros, current=all-ones → all 32 edges new."""
    n = 32
    global_hex = ('00' * n)
    current_hex = ('ff' * n)
    # bucket(0xff=255) = 128, 128 > 0 for every byte → all n bits new
    expected = n

    resp = mcp_call_tool('fuzz_libfuzzer_count_new_bits_bucketed',
                         {'global_hex': global_hex, 'current_hex': current_hex})
    if not resp:
        return False, {'note': 'MCP call failed'}
    data = extract_json(resp)
    if not data:
        return False, {'note': f'Bad response: {resp}'}

    got = data.get('new_bits', -1)
    match = got == expected
    return match, {
        'truth': expected, 'mcp': got,
        'note': 'count_new_bits all-new' if match else f'MISMATCH: got {got} want {expected}',
    }


def test_count_new_bits_bucketed_partial() -> Tuple[bool, Dict]:
    """count_new_bits_bucketed: partial overlap — only bytes where bucket(cur)>global are new."""
    # global has byte=1 (bucket=1) for positions 0-3, byte=0 elsewhere
    # current has byte=3 (bucket=4) for positions 0-1, byte=0 elsewhere
    # positions 0,1: bucket(3)=4 > 1 → new
    # positions 2,3: bucket(0)=0 → not new
    global_data = bytes([1, 1, 1, 1] + [0] * 4)
    current_data = bytes([3, 3, 0, 0] + [0] * 4)
    expected = count_new_bits_bucketed(global_data, current_data)

    resp = mcp_call_tool('fuzz_libfuzzer_count_new_bits_bucketed', {
        'global_hex': global_data.hex(),
        'current_hex': current_data.hex(),
    })
    if not resp:
        return False, {'note': 'MCP call failed'}
    data = extract_json(resp)
    if not data:
        return False, {'note': f'Bad response: {resp}'}

    got = data.get('new_bits', -1)
    match = got == expected
    return match, {
        'truth': expected, 'mcp': got,
        'note': 'count_new_bits partial' if match else f'MISMATCH: got {got} want {expected}',
    }


def test_parse_sanitizer_heap_overflow() -> Tuple[bool, Dict]:
    """parse_sanitizer_output: heap-buffer-overflow with known fault address."""
    text = 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000001234 at pc 0x...'
    expected_kind_str = 'HeapOverflow'
    expected_addr = extract_fault_addr(text)  # 0x602000001234

    resp = mcp_call_tool('fuzz_libfuzzer_parse_sanitizer_output', {'text': text})
    if not resp:
        return False, {'note': 'MCP call failed'}
    data = extract_json(resp)
    if not data:
        return False, {'note': f'Bad response: {resp}'}

    got_kind = data.get('kind', '')
    got_addr = data.get('fault_addr')
    kind_match = got_kind == expected_kind_str
    addr_match = got_addr == expected_addr
    match = kind_match and addr_match
    return match, {
        'truth_kind': expected_kind_str, 'mcp_kind': got_kind,
        'truth_addr': expected_addr, 'mcp_addr': got_addr,
        'note': 'parse_sanitizer heap-overflow OK' if match else f'MISMATCH kind={got_kind!r}/{expected_kind_str!r} addr={got_addr}/{expected_addr}',
    }


def test_parse_sanitizer_uaf() -> Tuple[bool, Dict]:
    """parse_sanitizer_output: heap-use-after-free."""
    text = 'heap-use-after-free READ size 8 at 0x60200000ef80'
    expected_kind_str = 'UseAfterFree'

    resp = mcp_call_tool('fuzz_libfuzzer_parse_sanitizer_output', {'text': text})
    if not resp:
        return False, {'note': 'MCP call failed'}
    data = extract_json(resp)
    if not data:
        return False, {'note': f'Bad response: {resp}'}

    got_kind = data.get('kind', '')
    match = got_kind == expected_kind_str
    return match, {
        'truth_kind': expected_kind_str, 'mcp_kind': got_kind,
        'note': 'parse_sanitizer UAF OK' if match else f'MISMATCH: {got_kind!r} vs {expected_kind_str!r}',
    }


def test_parse_sanitizer_division_by_zero() -> Tuple[bool, Dict]:
    """parse_sanitizer_output: UBSan division by zero, no address."""
    text = 'runtime error: division by zero in fuzz_target'
    expected_kind_str = 'DivisionByZero'

    resp = mcp_call_tool('fuzz_libfuzzer_parse_sanitizer_output', {'text': text})
    if not resp:
        return False, {'note': 'MCP call failed'}
    data = extract_json(resp)
    if not data:
        return False, {'note': f'Bad response: {resp}'}

    got_kind = data.get('kind', '')
    match = got_kind == expected_kind_str
    return match, {
        'truth_kind': expected_kind_str, 'mcp_kind': got_kind,
        'note': 'parse_sanitizer DivByZero OK' if match else f'MISMATCH: {got_kind!r} vs {expected_kind_str!r}',
    }


def test_structured_serialize() -> Tuple[bool, Dict]:
    """structured_serialize: known fields → exact hex output."""
    fields_spec = [
        ('alpha', bytes.fromhex('deadbeef')),
        ('beta',  bytes.fromhex('0102')),
    ]
    expected_blob = structured_serialize(fields_spec)
    expected_hex = expected_blob.hex().upper()
    expected_len = len(expected_blob)

    mcp_fields = [{'name': name, 'hex': data.hex()} for name, data in fields_spec]
    resp = mcp_call_tool('fuzz_libfuzzer_structured_serialize', {'fields': mcp_fields})
    if not resp:
        return False, {'note': 'MCP call failed'}
    data = extract_json(resp)
    if not data:
        return False, {'note': f'Bad response: {resp}'}

    got_hex = data.get('hex', '')
    got_len = data.get('len', -1)
    got_fc = data.get('field_count', -1)
    match = got_hex == expected_hex and got_len == expected_len and got_fc == 2
    return match, {
        'truth_hex': expected_hex, 'mcp_hex': got_hex,
        'truth_len': expected_len, 'mcp_len': got_len,
        'note': 'structured_serialize exact' if match else f'MISMATCH hex={got_hex!r}/{expected_hex!r} len={got_len}/{expected_len}',
    }


def test_structured_deserialize() -> Tuple[bool, Dict]:
    """structured_deserialize: blob from known fields → exact field_count."""
    fields_spec = [
        ('f0', b'hello'),
        ('f1', b'world!'),
        ('f2', bytes(range(16))),
    ]
    blob = structured_serialize(fields_spec)
    expected_fc = 3

    resp = mcp_call_tool('fuzz_libfuzzer_structured_deserialize', {'hex': blob.hex()})
    if not resp:
        return False, {'note': 'MCP call failed'}
    data = extract_json(resp)
    if not data:
        return False, {'note': f'Bad response: {resp}'}

    ok = data.get('ok', False)
    got_fc = data.get('field_count', -1)
    match = ok and got_fc == expected_fc
    return match, {
        'truth_field_count': expected_fc, 'mcp_field_count': got_fc, 'ok': ok,
        'note': 'structured_deserialize OK' if match else f'MISMATCH fc={got_fc}/{expected_fc} ok={ok}',
    }


def test_simple_rng_values() -> Tuple[bool, Dict]:
    """simple_rng: known seed and count → exact xorshift64 sequence."""
    seed = 0xDEAD_BEEF_1234_5678
    count = 5
    expected = simple_rng_sequence(seed, count)

    resp = mcp_call_tool('fuzz_libfuzzer_simple_rng', {'seed': seed, 'count': count})
    if not resp:
        return False, {'note': 'MCP call failed'}
    data = extract_json(resp)
    if not data:
        return False, {'note': f'Bad response: {resp}'}

    got_vals = data.get('values', [])
    got_count = data.get('count', -1)
    match = got_vals == expected and got_count == count
    return match, {
        'truth': expected, 'mcp': got_vals,
        'note': 'simple_rng exact sequence' if match else f'MISMATCH vals={got_vals} vs {expected}',
    }


def test_simple_rng_zero_seed() -> Tuple[bool, Dict]:
    """simple_rng: seed=0 uses fallback 0xcafe_babe_dead_beef (same as Rust)."""
    seed = 0
    count = 3
    expected = simple_rng_sequence(seed, count)  # uses 0xcafe_babe_dead_beef

    resp = mcp_call_tool('fuzz_libfuzzer_simple_rng', {'seed': seed, 'count': count})
    if not resp:
        return False, {'note': 'MCP call failed'}
    data = extract_json(resp)
    if not data:
        return False, {'note': f'Bad response: {resp}'}

    got_vals = data.get('values', [])
    match = got_vals == expected
    return match, {
        'truth': expected, 'mcp': got_vals,
        'note': 'simple_rng zero_seed fallback' if match else f'MISMATCH: {got_vals} vs {expected}',
    }


def test_input_splice() -> Tuple[bool, Dict]:
    """input_splice: known a, b, seed → exact spliced hex."""
    a = b'AAAA_BBBB_CCCC'
    b_ = b'XXXX_YYYY_ZZZZ'
    seed = 42
    expected = input_splice(a, b_, seed)
    expected_hex = expected.hex().upper()

    resp = mcp_call_tool('fuzz_libfuzzer_input_splice', {
        'a_hex': a.hex(), 'b_hex': b_.hex(), 'seed': seed
    })
    if not resp:
        return False, {'note': 'MCP call failed'}
    data = extract_json(resp)
    if not data:
        return False, {'note': f'Bad response: {resp}'}

    got_hex = data.get('hex', '')
    got_len = data.get('len', -1)
    match = got_hex == expected_hex and got_len == len(expected)
    return match, {
        'truth_hex': expected_hex, 'mcp_hex': got_hex,
        'truth_len': len(expected), 'mcp_len': got_len,
        'note': 'input_splice exact' if match else f'MISMATCH hex={got_hex!r}/{expected_hex!r}',
    }


def test_crash_handler_inject() -> Tuple[bool, Dict]:
    """crash_handler_inject: inject known signals → deterministic state."""
    signals = [11, 6, 8]
    # After injecting 3 signals: total_crashes=3, last_signal=8, is_crashed=true
    expected_total = len(signals)
    expected_last = signals[-1]
    expected_crashed = True

    resp = mcp_call_tool('fuzz_libfuzzer_crash_handler_inject', {'signals': signals})
    if not resp:
        return False, {'note': 'MCP call failed'}
    data = extract_json(resp)
    if not data:
        return False, {'note': f'Bad response: {resp}'}

    got_total = data.get('total_crashes', -1)
    got_last = data.get('last_signal')
    got_crashed = data.get('is_crashed', False)
    match = (got_total == expected_total and got_last == expected_last
             and got_crashed == expected_crashed)
    return match, {
        'truth_total': expected_total, 'mcp_total': got_total,
        'truth_last': expected_last, 'mcp_last': got_last,
        'truth_crashed': expected_crashed, 'mcp_crashed': got_crashed,
        'note': 'crash_handler_inject OK' if match else f'MISMATCH total={got_total}/{expected_total} last={got_last}/{expected_last} crashed={got_crashed}/{expected_crashed}',
    }


def test_persistent_harness_run() -> Tuple[bool, Dict]:
    """persistent_harness_run: known max_iterations and advances → deterministic output."""
    max_it = 5
    advances = 3
    # start(): active=true, iterations=0
    # advance() ×3: iterations becomes 3, all return true (3 < 5), kept_going=3
    # progress = 3/5 = 0.6 (before stop)
    # iterations = 3
    expected_iters = 3
    expected_kept = 3
    expected_progress = 3.0 / 5.0

    resp = mcp_call_tool('fuzz_libfuzzer_persistent_harness_run', {
        'max_iterations': max_it, 'advances': advances
    })
    if not resp:
        return False, {'note': 'MCP call failed'}
    data = extract_json(resp)
    if not data:
        return False, {'note': f'Bad response: {resp}'}

    got_iters = data.get('iterations', -1)
    got_kept = data.get('kept_going_count', -1)
    got_progress = data.get('progress', -1.0)
    match = (got_iters == expected_iters and got_kept == expected_kept
             and abs(got_progress - expected_progress) < 1e-9)
    return match, {
        'truth_iters': expected_iters, 'mcp_iters': got_iters,
        'truth_kept': expected_kept, 'mcp_kept': got_kept,
        'truth_progress': expected_progress, 'mcp_progress': got_progress,
        'note': 'persistent_harness_run OK' if match else f'MISMATCH iters={got_iters}/{expected_iters} kept={got_kept}/{expected_kept} progress={got_progress}/{expected_progress}',
    }


# ─── Main ────────────────────────────────────────────────────────────────────

ALL_TESTS = [
    # (tool_name, label, test_fn)
    ('fuzz_libfuzzer_bucket_bitmap',             'bucket_bitmap exact',               test_bucket_bitmap),
    ('fuzz_libfuzzer_count_new_bits_bucketed',   'count_new_bits all-new',            test_count_new_bits_bucketed_all_new),
    ('fuzz_libfuzzer_count_new_bits_bucketed',   'count_new_bits partial',            test_count_new_bits_bucketed_partial),
    ('fuzz_libfuzzer_parse_sanitizer_output',    'parse_sanitizer heap-overflow',     test_parse_sanitizer_heap_overflow),
    ('fuzz_libfuzzer_parse_sanitizer_output',    'parse_sanitizer UAF',               test_parse_sanitizer_uaf),
    ('fuzz_libfuzzer_parse_sanitizer_output',    'parse_sanitizer div-by-zero',       test_parse_sanitizer_division_by_zero),
    ('fuzz_libfuzzer_structured_serialize',      'structured_serialize exact',        test_structured_serialize),
    ('fuzz_libfuzzer_structured_deserialize',    'structured_deserialize field_count', test_structured_deserialize),
    ('fuzz_libfuzzer_simple_rng',               'simple_rng exact sequence',         test_simple_rng_values),
    ('fuzz_libfuzzer_simple_rng',               'simple_rng zero seed fallback',     test_simple_rng_zero_seed),
    ('fuzz_libfuzzer_input_splice',             'input_splice exact',                test_input_splice),
    ('fuzz_libfuzzer_crash_handler_inject',     'crash_handler_inject state',        test_crash_handler_inject),
    ('fuzz_libfuzzer_persistent_harness_run',   'persistent_harness_run progress',   test_persistent_harness_run),
]

# Tools hardened = unique tool names with a rigorous truth (not any_valid)
TOOLS_HARDENED = len({t for t, _, _ in ALL_TESTS})


def main():
    print('[*] Starting MCP server...')
    start_mcp()

    print('[*] Initializing MCP...')
    if not mcp_initialize():
        print('[!] Initialize failed — aborting')
        sys.exit(1)

    available = set(get_tool_names())
    print(f'[*] MCP exposes {len(available)} tools total')

    checks_passed = 0
    checks_failed = 0
    mismatches = []

    for tool_name, label, test_fn in ALL_TESTS:
        if tool_name not in available:
            print(f'    SKIP  {label}  (tool not present)')
            continue

        print(f'[*] {label}...', end=' ', flush=True)
        try:
            passed, details = test_fn()
        except Exception as exc:
            passed = False
            details = {'note': f'exception: {exc}'}

        if passed:
            checks_passed += 1
            print('PASS')
        else:
            checks_failed += 1
            note = details.get('note', '') if details else ''
            print(f'FAIL  {note}')
            mismatches.append({
                'tool': tool_name,
                'label': label,
                'details': details,
            })

    # ── Report ────────────────────────────────────────────────────────────────
    report = {
        'module': 'fuzz_libfuzzer',
        'tools_hardened': TOOLS_HARDENED,
        'checks_passed': checks_passed,
        'checks_failed': checks_failed,
        'mismatches': mismatches,
    }

    print('\n' + '=' * 60)
    print(f'Module     : fuzz_libfuzzer')
    print(f'Hardened   : {TOOLS_HARDENED} tools')
    print(f'Checks     : {checks_passed} passed / {checks_failed} failed')
    print(f'Mismatches : {len(mismatches)}')
    print('=' * 60)

    with open(REPORT_PATH, 'w', encoding='utf-8') as fh:
        json.dump(report, fh, indent=2)
    print(f'[*] Report: {REPORT_PATH}')

    if MCP_PROCESS:
        try:
            MCP_PROCESS.terminate()
            MCP_PROCESS.wait(timeout=3)
        except Exception:
            try:
                MCP_PROCESS.kill()
            except Exception:
                pass

    return report


if __name__ == '__main__':
    report = main()
    sys.exit(0 if report['checks_failed'] == 0 else 1)
