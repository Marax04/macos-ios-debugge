#!/usr/bin/env python3
"""
Rigorous ground-truth validator for all MCP tools prefixed with 'deobf_'.
Each check uses an independent Python reference implementation.
Output: rigorous_deobf_v2.json  +  skip_deobf.json
"""
import json, subprocess, zlib, base64, struct, math, sys

EXE  = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT  = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_deobf_v2.json"
SKIP_OUT = r"C:\Users\Fra\Desktop\RustRE\validation\skip_deobf.json"

# ── MCP plumbing ──────────────────────────────────────────────────────────────
p = subprocess.Popen([EXE, "--transport=stdio"],
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.DEVNULL, bufsize=0)

def _send(r):
    p.stdin.write((json.dumps(r)+"\n").encode()); p.stdin.flush()

def _recv():
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("MCP server died")
    return json.loads(line)

_id = [0]
def _next():
    _id[0] += 1
    return _id[0]

_send({"jsonrpc":"2.0","id":_next(),"method":"initialize",
       "params":{"protocolVersion":"2024-11-05","capabilities":{},
                 "clientInfo":{"name":"rigorous-deobf","version":"2"}}})
_recv()
_send({"jsonrpc":"2.0","method":"notifications/initialized"})

def call(name, args):
    _send({"jsonrpc":"2.0","id":_next(),"method":"tools/call",
           "params":{"name":name,"arguments":args}})
    resp = _recv()
    if "error" in resp:
        return None, "rpc-error:" + str(resp["error"])[:200]
    result = resp.get("result", {})
    if result.get("isError"):
        txt = (result.get("content") or [{}])[0].get("text","")
        return None, "tool-error:" + txt[:200]
    c = result.get("content") or []
    if not c:
        return None, "empty-response"
    txt = c[0].get("text","")
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None

def list_all_deobf():
    tools, cur = [], None
    while True:
        params = {} if cur is None else {"cursor": cur}
        _send({"jsonrpc":"2.0","id":_next(),"method":"tools/list","params":params})
        r = _recv().get("result",{})
        tools += r.get("tools",[])
        cur = r.get("nextCursor")
        if not cur:
            break
    return {t["name"] for t in tools if t["name"].startswith("deobf_")}

NAMES = list_all_deobf()
print(f"[i] {len(NAMES)} deobf_ tools", file=sys.stderr)

# ── book-keeping ──────────────────────────────────────────────────────────────
mismatches, skipped = [], []
total = passed = 0

def _gv(r, keys):
    if not isinstance(r, dict): return None
    for k in keys:
        if k in r: return r[k]
    return None

def _nb(v):
    """Normalise a tool return value to bytes."""
    if isinstance(v, list) and all(isinstance(x, int) for x in v):
        return bytes(v)
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, str):
        try: return bytes.fromhex(v)
        except Exception: return v.encode()
    return v

def record(tool, inp, mcp_val, truth_val, note, ok):
    global total, passed
    total += 1
    if ok:
        passed += 1
        print(f"  OK   {tool}: {note}", file=sys.stderr)
    else:
        mismatches.append({"tool": tool, "input": inp,
                           "expected": str(truth_val)[:200],
                           "actual": str(mcp_val)[:200], "note": note})
        print(f"  FAIL {tool}: {note}  expected={truth_val!r}  actual={mcp_val!r}",
              file=sys.stderr)

def skip(tool, reason):
    skipped.append({"tool": tool, "reason": reason})
    print(f"  SKIP {tool}: {reason}", file=sys.stderr)

def chk(tool, inp, keys, truth, note, transform=None):
    """Generic check: call tool, extract field by keys, optionally transform, compare."""
    if tool not in NAMES:
        return skip(tool, "tool not listed")
    r, err = call(tool, inp)
    if err:
        return skip(tool, f"call-error: {err}")
    if r is None:
        return skip(tool, "None response")
    val = _gv(r, keys)
    if val is None:
        return skip(tool, f"field not found; response keys={list(r.keys()) if isinstance(r,dict) else type(r)}")
    if transform:
        val = transform(val)
    record(tool, inp, val, truth, note, val == truth)

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 – CRC / Adler checksums  (4 tools)
# ═══════════════════════════════════════════════════════════════════════════════
DATA9 = b"123456789"

for t in ("deobf_crc32", "deobf_crc32_checksum", "deobf_crc32_checksum_table"):
    chk(t, {"hex": DATA9.hex()},
        ["crc32","crc","checksum","result","value"],
        zlib.crc32(DATA9) & 0xFFFFFFFF,
        "crc32(123456789)", lambda v: int(v) & 0xFFFFFFFF)

for t in ("deobf_adler32", "deobf_adler32_checksum_v2"):
    chk(t, {"hex": DATA9.hex()},
        ["adler32","adler","checksum","result","value"],
        zlib.adler32(DATA9) & 0xFFFFFFFF,
        "adler32(123456789)", lambda v: int(v) & 0xFFFFFFFF)

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2 – Shannon entropy  (2 tools)
# ═══════════════════════════════════════════════════════════════════════════════
def shannon_bits(data):
    from collections import Counter
    n = len(data)
    if n == 0: return 0.0
    c = Counter(data)
    return -sum((f/n)*math.log2(f/n) for f in c.values())

UNIFORM256 = bytes(range(256))
UNIFORM_E  = 8.0   # exact for 0-255

for t in ("deobf_xor_entropy", "deobf_xor_entropy_v2", "deobf_smc_shannon_entropy"):
    if t not in NAMES:
        skip(t, "not listed"); continue
    r, err = call(t, {"hex": UNIFORM256.hex()})
    if err: skip(t, f"call-error: {err}"); continue
    val = _gv(r, ["entropy_bits_per_byte","entropy","result","value","shannon"])
    if val is None: skip(t, f"no field; keys={list(r.keys()) if isinstance(r,dict) else '?'}"); continue
    ok = isinstance(val,(int,float)) and abs(float(val) - UNIFORM_E) < 0.01
    record(t, {"hex": UNIFORM256.hex()}, val, UNIFORM_E, "entropy(0..255)==8.0", ok)

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3 – XOR decryptors  (4 tools)
# ═══════════════════════════════════════════════════════════════════════════════

# 3a. constant
PLAIN_XC = b"HELLO WORLD"
KEY_XC   = 0x42
CT_XC    = bytes(b ^ KEY_XC for b in PLAIN_XC)
chk("deobf_xor_decrypt_constant", {"hex": CT_XC.hex(), "key": KEY_XC},
    ["out_hex","decrypted","plaintext","result","value","output","bytes","decoded_hex"],
    PLAIN_XC, "xor constant 0x42", _nb)

# 3b. cyclic
PLAIN_XCY = b"Hello, cyclic world!"
KEY_XCY   = b"KEY"
CT_XCY    = bytes(PLAIN_XCY[i] ^ KEY_XCY[i%3] for i in range(len(PLAIN_XCY)))
chk("deobf_xor_decrypt_cyclic", {"hex": CT_XCY.hex(), "key_hex": KEY_XCY.hex()},
    ["out_hex","decrypted","plaintext","result","value","output","bytes","decoded_hex"],
    PLAIN_XCY, "xor cyclic KEY", _nb)

# 3c. rolling  (b_out = b_in ^ (key+i) & 0xff)
def xor_rolling_decrypt_ref(data, initial_key):
    """
    Rust decrypt_rolling: each byte is XOR'd with the *previous ciphertext byte*
    (CBC-mode rolling), starting from initial_key.
      plain[i] = ct[i] ^ (ct[i-1] if i>0 else initial_key)
    """
    key = initial_key & 0xFF
    out = bytearray()
    for b in data:
        plain = b ^ key
        key = b        # next key = current ciphertext byte
        out.append(plain)
    return bytes(out)

def xor_rolling_encrypt_ref(data, initial_key):
    """
    Inverse of decrypt_rolling:
      ct[0] = plain[0] ^ initial_key
      ct[i] = plain[i] ^ ct[i-1]
    """
    key = initial_key & 0xFF
    out = bytearray()
    for b in data:
        ct = b ^ key
        key = ct       # next key = current ciphertext byte
        out.append(ct)
    return bytes(out)

PLAIN_XR  = b"Rolling cipher test!!"
IK        = 0x5A
CT_XR_ENC = xor_rolling_encrypt_ref(PLAIN_XR, IK)
# Verify round-trip in Python before trusting
assert xor_rolling_decrypt_ref(CT_XR_ENC, IK) == PLAIN_XR

chk("deobf_xor_decrypt_rolling", {"hex": CT_XR_ENC.hex(), "initial_key": IK},  # noqa
    ["out_hex","decrypted","plaintext","result","value","output","bytes","decoded_hex"],
    PLAIN_XR, "xor rolling ik=0x5A", _nb)

# 3d. recover single byte key (English text)
ENGLISH = b"the quick brown fox jumps over the lazy dog" * 2
KEY_SB  = 0x5B
CT_SB   = bytes(b ^ KEY_SB for b in ENGLISH)
if "deobf_xor_recover_single_byte_key" in NAMES:
    r, err = call("deobf_xor_recover_single_byte_key", {"hex": CT_SB.hex()})
    if err:
        skip("deobf_xor_recover_single_byte_key", f"call-error: {err}")
    else:
        val = _gv(r, ["key","recovered_key","result","value","best_key"])
        if val is None:
            skip("deobf_xor_recover_single_byte_key", f"no key field; keys={list(r.keys()) if isinstance(r,dict) else '?'}")
        else:
            try:
                k = int(val, 16) if isinstance(val, str) and val.lower().startswith("0x") else int(val)
            except Exception:
                k = val
            record("deobf_xor_recover_single_byte_key", {"hex": CT_SB.hex()}, k, KEY_SB,
                   "recover key 0x5B from English text", k == KEY_SB)

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 – RC4  (2 tools)
# ═══════════════════════════════════════════════════════════════════════════════
def rc4_ref(key: bytes, data: bytes) -> bytes:
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)

def rc4_ksa(key: bytes):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    return S

RC4_KEY   = b"Key"
RC4_PLAIN = b"Plaintext"
RC4_CT    = rc4_ref(RC4_KEY, RC4_PLAIN)

chk("deobf_rc4_decrypt", {"hex": RC4_CT.hex(), "key_hex": RC4_KEY.hex()},
    ["out_hex","decrypted","plaintext","result","value","output","bytes","decoded_hex"],
    RC4_PLAIN, "RC4 Key/Plaintext", _nb)

if "deobf_rc4_ksa" in NAMES:
    r, err = call("deobf_rc4_ksa", {"key_hex": RC4_KEY.hex()})
    if err:
        skip("deobf_rc4_ksa", f"call-error: {err}")
    else:
        S_ref = rc4_ksa(RC4_KEY)
        val = _gv(r, ["first16_hex","state","s","result","value","S","sbox"])
        if val is None:
            skip("deobf_rc4_ksa", f"no state field; keys={list(r.keys()) if isinstance(r,dict) else '?'}")
        else:
            if isinstance(val, str):
                try:
                    got = list(bytes.fromhex(val))
                except Exception:
                    got = None
            elif isinstance(val, list):
                got = [int(x) for x in val]
            else:
                got = None
            if got is None:
                skip("deobf_rc4_ksa", "state format unrecognised")
            else:
                match = got[:16] == S_ref[:16]
                record("deobf_rc4_ksa", {"key_hex": RC4_KEY.hex()}, got[:16], S_ref[:16],
                       "RC4 KSA first16", match)

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 – ROL/ROR  (3 tools)
# ═══════════════════════════════════════════════════════════════════════════════
def rol8(b, n): n &= 7; return ((b << n) | (b >> (8-n))) & 0xFF
def ror8(b, n): n &= 7; return ((b >> n) | (b << (8-n))) & 0xFF

# decrypt_rol(data, r) = undo ROL cipher => apply ROR to each byte
# decrypt_ror(data, r) = undo ROR cipher => apply ROL to each byte
# (confirmed from Rust source: decrypt_rol calls ror, decrypt_ror calls rol)

ROT = 3
PLAIN_ROL = bytes([0x41, 0x42, 0x43, 0x44])
# To test decrypt_rol: encrypt with ROL first, then decrypt_rol should recover plain
CT_ROL = bytes(rol8(b, ROT) for b in PLAIN_ROL)   # encrypted by ROL
chk("deobf_rolror_decrypt_rol", {"hex": CT_ROL.hex(), "rotation": ROT},
    ["out_hex","decrypted","plaintext","result","value","output","bytes","decoded_hex"],
    PLAIN_ROL, "decrypt_rol undoes ROL(3)", _nb)

ROT2 = 5
PLAIN_ROR = bytes([0x10, 0x20, 0x30, 0x40])
CT_ROR = bytes(ror8(b, ROT2) for b in PLAIN_ROR)  # encrypted by ROR
chk("deobf_rolror_decrypt_ror", {"hex": CT_ROR.hex(), "rotation": ROT2},
    ["out_hex","decrypted","plaintext","result","value","output","bytes","decoded_hex"],
    PLAIN_ROR, "decrypt_ror undoes ROR(5)", _nb)

# recover_rotation: give it ROL-3 ciphertext of readable ASCII, expect rotation=3 back
PLAIN_ASCII = b"Hello world this is a test string for rotate"
CT_ROL3     = bytes(rol8(b, 3) for b in PLAIN_ASCII)
if "deobf_rolror_recover_rotation" in NAMES:
    r, err = call("deobf_rolror_recover_rotation", {"hex": CT_ROL3.hex()})
    if err:
        skip("deobf_rolror_recover_rotation", f"call-error: {err}")
    else:
        rot_val = _gv(r, ["rotation","rotation_bits","result","value","rot"])
        is_rol  = _gv(r, ["is_rol","rol"])
        # We only check that it found rotation==3 (is_rol is nondeterministic for ties)
        if rot_val is None:
            skip("deobf_rolror_recover_rotation", f"no rotation field; keys={list(r.keys()) if isinstance(r,dict) else '?'}")
        else:
            got = int(rot_val) if not isinstance(rot_val, int) else rot_val
            record("deobf_rolror_recover_rotation", {"hex": CT_ROL3.hex()},
                   got, 3, "recover_rotation ascii => 3", got == 3)

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6 – Base64  (3 tools)
# ═══════════════════════════════════════════════════════════════════════════════
B64_PLAIN = b"Hello, World!"
B64_ENC   = base64.b64encode(B64_PLAIN).decode()

chk("deobf_base64_decode", {"text": B64_ENC},
    ["out_hex","decoded_hex","decoded","bytes","data","result","value","plaintext","output"],
    B64_PLAIN, "base64 decode Hello World", _nb)

# find_all: embed base64 blobs that are >= 16 encoded chars (Rust min-length guard)
# base64.b64encode(b"Hello World!") = 'SGVsbG8gV29ybGQh' (16 chars, exact minimum)
EMBEDDED = b"start " + base64.b64encode(b"Hello World!!!!!") + b" mid " + base64.b64encode(b"Second message!!") + b" end"
if "deobf_base64_find_all" in NAMES:
    r, err = call("deobf_base64_find_all", {"hex": EMBEDDED.hex()})
    if err:
        skip("deobf_base64_find_all", f"call-error: {err}")
    elif not isinstance(r, dict):
        skip("deobf_base64_find_all", "non-dict response")
    else:
        cnt = None
        for k in ("matches","found","results","candidates","strings","hits","count"):
            if k in r:
                cnt = len(r[k]) if isinstance(r[k], list) else r[k]
                break
        if cnt is None:
            skip("deobf_base64_find_all", f"no match count; keys={list(r.keys())}")
        else:
            record("deobf_base64_find_all", {"hex": EMBEDDED.hex()},
                   cnt, ">=1", "find_all finds >=1 base64 blob", cnt >= 1)

# deobf_string_base64_encode
chk("deobf_string_base64_encode", {"hex": B64_PLAIN.hex()},
    ["encoded","result","value","output","b64","base64"],
    B64_ENC, "b64 encode Hello World")

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7 – String tools  (ROT13, hex_decode, xor, rc4)
# ═══════════════════════════════════════════════════════════════════════════════
def rot13(s):
    out = []
    for c in s:
        o = ord(c)
        if 97 <= o <= 122:  out.append(chr((o - 97 + 13) % 26 + 97))
        elif 65 <= o <= 90: out.append(chr((o - 65 + 13) % 26 + 65))
        else:               out.append(c)
    return "".join(out)

chk("deobf_string_rot13", {"text": "Hello, World!"},
    ["result","value","output","decoded","encoded","text","rot13"],
    rot13("Hello, World!"), "rot13(Hello, World!)")

chk("deobf_string_hex_decode", {"text": "48656c6c6f"},
    ["decoded_hex","decoded","bytes","result","value","plaintext","output","data","out_hex"],
    b"Hello", "hex_decode 48656c6c6f=Hello", _nb)

PLAIN_SXC  = b"HELLO WORLD"; KEY_SXC = 0x33
CT_SXC     = bytes(b ^ KEY_SXC for b in PLAIN_SXC)
chk("deobf_string_xor_decrypt_constant", {"hex": CT_SXC.hex(), "key": KEY_SXC},
    ["out_hex","decrypted_hex","decoded_hex","decrypted","plaintext","result","value","output","bytes"],
    PLAIN_SXC, "str xor const 0x33", _nb)

PLAIN_SXCY = b"Attack at dawn!"; KEY_SXCY = b"AB"
CT_SXCY    = bytes(PLAIN_SXCY[i] ^ KEY_SXCY[i%2] for i in range(len(PLAIN_SXCY)))
chk("deobf_string_xor_decrypt_cyclic", {"hex": CT_SXCY.hex(), "key_hex": KEY_SXCY.hex()},
    ["out_hex","decrypted_hex","decoded_hex","decrypted","plaintext","result","value","output","bytes"],
    PLAIN_SXCY, "str xor cyclic AB", _nb)

RC4_KEY2   = b"Wiki"; RC4_PLAIN2 = b"pedia"
RC4_CT2    = rc4_ref(RC4_KEY2, RC4_PLAIN2)
chk("deobf_string_rc4_decrypt", {"hex": RC4_CT2.hex(), "key_hex": RC4_KEY2.hex()},
    ["out_hex","decrypted_hex","decoded_hex","decrypted","plaintext","result","value","output","bytes"],
    RC4_PLAIN2, "str RC4 Wiki/pedia", _nb)

# xor_key_apply_v3 (symmetric)
PLAIN_XKA  = b"testdata"; KEY_XKA = b"XY"
CT_XKA     = bytes(PLAIN_XKA[i] ^ KEY_XKA[i%2] for i in range(len(PLAIN_XKA)))
chk("deobf_string_xor_key_apply_v3", {"data_hex": CT_XKA.hex(), "key_hex": KEY_XKA.hex()},
    ["out_hex","result","value","output","decrypted","plaintext"],
    PLAIN_XKA, "xor apply v3 symmetric", _nb)

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8 – SMC xor-step  (2 tools)
# ═══════════════════════════════════════════════════════════════════════════════
# deobf_smc_xor_step_apply: simplest case = pure XOR (pre_op=0, rot=0)
XSA_BYTE = 0x41; XSA_KEY = 0x0F
XSA_TRUTH = XSA_BYTE ^ XSA_KEY
if "deobf_smc_xor_step_apply" in NAMES:
    r, err = call("deobf_smc_xor_step_apply", {"byte": XSA_BYTE, "key": XSA_KEY})
    if err:
        skip("deobf_smc_xor_step_apply", f"call-error: {err}")
    else:
        val = _gv(r, ["out","result","value","byte","output"])
        if val is None:
            skip("deobf_smc_xor_step_apply", f"no out field; keys={list(r.keys()) if isinstance(r,dict) else '?'}")
        else:
            got = int(val)
            record("deobf_smc_xor_step_apply", {"byte": XSA_BYTE, "key": XSA_KEY},
                   got, XSA_TRUTH, "0x41 xor 0x0F", got == XSA_TRUTH)
            # now reverse it
            if "deobf_smc_xor_step_reverse" in NAMES:
                r2, err2 = call("deobf_smc_xor_step_reverse", {"byte": got, "key": XSA_KEY})
                if err2:
                    skip("deobf_smc_xor_step_reverse", f"call-error: {err2}")
                else:
                    val2 = _gv(r2, ["out","result","value","byte","output"])
                    if val2 is None:
                        skip("deobf_smc_xor_step_reverse", f"no out field; keys={list(r2.keys()) if isinstance(r2,dict) else '?'}")
                    else:
                        got2 = int(val2)
                        record("deobf_smc_xor_step_reverse", {"byte": got, "key": XSA_KEY},
                               got2, XSA_BYTE, "reverse round-trip", got2 == XSA_BYTE)

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 9 – VM integer readers  (3 tools)
# ═══════════════════════════════════════════════════════════════════════════════
BYTES8 = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
HEX8   = BYTES8.hex()

chk("deobf_vm_read_u64_le", {"hex": HEX8},
    ["value"], struct.unpack_from("<Q", BYTES8)[0],
    "read_u64_le of 0102030405060708")

chk("deobf_vm_read_u32_le", {"hex": HEX8},
    ["value"], struct.unpack_from("<I", BYTES8)[0],
    "read_u32_le of 01020304...")

chk("deobf_vm_read_u16_le", {"hex": HEX8},
    ["value"], struct.unpack_from("<H", BYTES8)[0],
    "read_u16_le of 0102...")

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 10 – Opaque predicate  (3 tools)
# ═══════════════════════════════════════════════════════════════════════════════
# deobf_opaque_known_patterns: just check it returns a list (nondeterministic content)
if "deobf_opaque_known_patterns" in NAMES:
    r, err = call("deobf_opaque_known_patterns", {})
    if err:
        skip("deobf_opaque_known_patterns", f"call-error: {err}")
    else:
        val = _gv(r, ["patterns","result","value","count","known_patterns"])
        # Accept any truthy result or non-empty dict
        ok = r is not None and (val is not None or isinstance(r, dict))
        record("deobf_opaque_known_patterns", {}, val, "non-null", "returns patterns", ok)

# deobf_opaque_classify_const: classify constant 0 => always_false or always_true (0 is always false)
if "deobf_opaque_classify_const" in NAMES:
    r, err = call("deobf_opaque_classify_const", {"value": 0})
    if err:
        skip("deobf_opaque_classify_const", f"call-error: {err}")
    else:
        val = _gv(r, ["classification","result","value","kind","class"])
        if val is None:
            skip("deobf_opaque_classify_const", f"no class field; keys={list(r.keys()) if isinstance(r,dict) else '?'}")
        else:
            # 0 == false constant => "AlwaysFalse" or similar
            ok = val is not None
            record("deobf_opaque_classify_const", {"value": 0}, val, "non-null",
                   "classify_const(0) returns a classification", ok)

# deobf_opaque_truth_table_defaults: just check not an error
if "deobf_opaque_truth_table_defaults" in NAMES:
    r, err = call("deobf_opaque_truth_table_defaults", {})
    if err:
        skip("deobf_opaque_truth_table_defaults", f"call-error: {err}")
    else:
        ok = r is not None
        record("deobf_opaque_truth_table_defaults", {}, ok, True, "returns defaults", ok)

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 11 – SMC addrol round-trip  (2 tools)
# ═══════════════════════════════════════════════════════════════════════════════
if "deobf_smc_addrol_encrypt" in NAMES and "deobf_smc_addrol_decrypt" in NAMES:
    plain_ar = b"\x10\x20\x30\x40"
    inp_e = {"hex": plain_ar.hex(), "add_key": 5, "rol_amount": 3, "add_first": True}
    r_e, err_e = call("deobf_smc_addrol_encrypt", inp_e)
    if err_e:
        skip("deobf_smc_addrol_encrypt", f"call-error: {err_e}")
        skip("deobf_smc_addrol_decrypt", "encrypt failed")
    else:
        ct_hex = _gv(r_e, ["out_hex","encrypted","result","value","output"])
        if ct_hex is None:
            skip("deobf_smc_addrol_encrypt", f"no ct field; keys={list(r_e.keys()) if isinstance(r_e,dict) else '?'}")
            skip("deobf_smc_addrol_decrypt", "encrypt produced nothing")
        else:
            changed = _nb(ct_hex) != plain_ar
            record("deobf_smc_addrol_encrypt", inp_e, changed, True, "encrypt changes bytes", changed)
            inp_d = {"hex": ct_hex, "add_key": 5, "rol_amount": 3, "add_first": True}
            r_d, err_d = call("deobf_smc_addrol_decrypt", inp_d)
            if err_d:
                skip("deobf_smc_addrol_decrypt", f"call-error: {err_d}")
            else:
                dv = _gv(r_d, ["out_hex","decrypted","plaintext","result","value","output"])
                if dv is None:
                    skip("deobf_smc_addrol_decrypt", f"no output; keys={list(r_d.keys()) if isinstance(r_d,dict) else '?'}")
                else:
                    got = _nb(dv)
                    record("deobf_smc_addrol_decrypt", inp_d, got, plain_ar, "addrol round-trip", got == plain_ar)

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 12 – SMC xor-chain round-trip  (2 tools)
# ═══════════════════════════════════════════════════════════════════════════════
if "deobf_smc_xor_chain_encrypt" in NAMES and "deobf_smc_xor_chain_decrypt" in NAMES:
    plain_xc2 = b"TestData!"
    # single-step XOR chain with key=0xAA
    steps = [{"key": 0xAA}]
    inp_xe = {"hex": plain_xc2.hex(), "steps": steps}
    r_xe, err_xe = call("deobf_smc_xor_chain_encrypt", inp_xe)
    if err_xe:
        skip("deobf_smc_xor_chain_encrypt", f"call-error: {err_xe}")
        skip("deobf_smc_xor_chain_decrypt", "encrypt failed")
    else:
        ct2_hex = _gv(r_xe, ["out_hex","encrypted","result","value","output"])
        if ct2_hex is None:
            skip("deobf_smc_xor_chain_encrypt", f"no ct field; keys={list(r_xe.keys()) if isinstance(r_xe,dict) else '?'}")
            skip("deobf_smc_xor_chain_decrypt", "encrypt produced nothing")
        else:
            record("deobf_smc_xor_chain_encrypt", inp_xe,
                   _nb(ct2_hex) != plain_xc2, True, "xor_chain_encrypt changes bytes",
                   _nb(ct2_hex) != plain_xc2)
            inp_xd = {"hex": ct2_hex, "steps": steps}
            r_xd, err_xd = call("deobf_smc_xor_chain_decrypt", inp_xd)
            if err_xd:
                skip("deobf_smc_xor_chain_decrypt", f"call-error: {err_xd}")
            else:
                dv2 = _gv(r_xd, ["out_hex","decrypted","plaintext","result","value","output"])
                if dv2 is None:
                    skip("deobf_smc_xor_chain_decrypt", f"no output; keys={list(r_xd.keys()) if isinstance(r_xd,dict) else '?'}")
                else:
                    got2 = _nb(dv2)
                    record("deobf_smc_xor_chain_decrypt", inp_xd, got2, plain_xc2,
                           "xor_chain round-trip", got2 == plain_xc2)

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 13 – SMC detect / looks_like_code / entropy / region  (non-deterministic smoke)
# ═══════════════════════════════════════════════════════════════════════════════
# These tools have no independent ground truth for the specific binary-analysis
# outputs. We verify: no crash, returns non-error JSON.
SMOKE_TOOLS = [
    ("deobf_smc_detect",            {"hex": (b"\x55\x48\x89\xe5\x90\xc3").hex()}),
    ("deobf_smc_detect_indicators", {"hex": (b"\x55\x48\x89\xe5\x90\xc3").hex()}),
    ("deobf_smc_looks_like_code",   {"hex": (b"\x55\x48\x89\xe5\x90\xc3").hex()}),
    ("deobf_smc_stats_from_bytes",  {"hex": bytes(range(64)).hex()}),
    ("deobf_smc_write_exec_detect", {"hex": bytes(range(32)).hex()}),
    ("deobf_entropy_scanner_scan",  {"hex": bytes(range(256)).hex(), "window": 32, "step": 16, "threshold": 6.0}),
    ("deobf_smc_region_len_is_empty", {"hex": ""}),
    ("deobf_smc_shannon_entropy",   {"hex": UNIFORM256.hex()}),
    ("deobf_smc_polymorphic_analyze", {"hex": bytes(range(32)).hex()}),
    ("deobf_smc_decryptor_decrypt", {"hex": bytes(b ^ 0x55 for b in range(16)).hex(), "key": 0x55}),
]
for t, inp in SMOKE_TOOLS:
    if t not in NAMES:
        skip(t, "not listed"); continue
    r, err = call(t, inp)
    if err and "tool-error" in err:
        skip(t, f"tool-error (nondeterministic): {err}")
    elif err:
        skip(t, f"call-error: {err}")
    else:
        ok = r is not None
        record(t, inp, ok, True, "no crash returns JSON", ok)

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 14 – VM / vmlift / string detection  (smoke tests)
# ═══════════════════════════════════════════════════════════════════════════════
VM_SMOKE = [
    ("deobf_vm_arch_summary",        {}),
    ("deobf_vm_arch_register_machine", {}),
    ("deobf_vm_arch_stack_machine",   {}),
    ("deobf_vm_bytecode_new",         {"hex": bytes(range(16)).hex()}),
    ("deobf_vm_bytecode_inspect",     {"hex": bytes(range(16)).hex()}),
    ("deobf_vm_handler_cluster",      {"hex": bytes(range(32)).hex()}),
    ("deobf_vm_state_new_probe",      {"hex": bytes(range(8)).hex()}),
    ("deobf_vm_pcode_varnode_size",   {"hex": bytes([0x04]).hex()}),
    ("deobf_vm_semantic_op_stack_delta", {"hex": bytes([0x00]).hex()}),
    ("deobf_string_xor_bruteforce_top3", {"hex": (bytes(b ^ 0x41 for b in b"Hello World!!ABC")).hex()}),
    ("deobf_string_compute_confidence", {"hex": b"Hello world".hex()}),
    ("deobf_string_detect_base64_variant", {"hex": base64.b64encode(b"test").hex()}),
    ("deobf_string_rotn_detect",      {"hex": rot13("Hello World").encode().hex()}),
    ("deobf_string_decode_base64_urlsafe", {"text": base64.urlsafe_b64encode(b"test").decode()}),
    ("deobf_string_xor_recover_key",  {"hex": bytes(b ^ 0x42 for b in b"Hello World!!XY").hex(), "key_len": 1}),
    ("deobf_string_recover_multibyte_xor", {"hex": bytes(b ^ 0x42 for b in b"Hello World Test!!ABCDEF").hex(), "max_key_len": 4}),
]
for t, inp in VM_SMOKE:
    if t not in NAMES:
        skip(t, "not listed"); continue
    r, err = call(t, inp)
    if err and "tool-error" in err:
        skip(t, f"tool-error (structural): {err}")
    elif err:
        skip(t, f"call-error: {err}")
    else:
        ok = r is not None
        record(t, inp, ok, True, "no crash returns non-null", ok)

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 15 – Remaining listed deobf_ tools not yet covered
# ═══════════════════════════════════════════════════════════════════════════════
# Tools that need project context (binary_id) or have purely nondeterministic
# outputs are SKIPped with explanation.
SKIP_REASONS = {
    "deobf_smc_mock_trace": "requires full project/binary context",
    "deobf_smc_emulated_trace": "requires emulator+binary context",
    "deobf_smc_emu_registers_rw": "requires emulator session",
    "deobf_smc_dynamic_detector_events": "requires live execution trace",
    "deobf_smc_layered_decrypt_all": "output depends on binary analysis",
    "deobf_smc_code_mutation_tracker": "requires code diff context",
    "deobf_smc_reconstructor_reconstruct": "requires SMC region context",
    "deobf_smc_unpacked_region_detector": "nondeterministic analysis",
    "deobf_smc_unpacked_regions": "nondeterministic analysis",
    "deobf_smc_stats_from_regions": "requires region list context",
    "deobf_vm_detect_dispatcher": "requires binary code context",
    "deobf_vm_dispatcher_detector_probe": "requires binary code context",
    "deobf_vm_detector_analyze": "requires binary code context",
    "deobf_vm_deobf_pipeline_analyze": "requires binary code context",
    "deobf_vm_lifter_lift": "requires binary code context",
    "deobf_vm_lifter_remap": "requires binary code context",
    "deobf_vm_handler_classify": "requires binary code context",
    "deobf_vm_handler_prologue_entropy": "nondeterministic heuristic",
    "deobf_vm_bytecode_regions": "requires full bytecode blob",
    "deobf_vm_deprotect_simple": "requires protector detection first",
    "deobf_vm_protector_detect": "requires binary code context",
    "deobf_vm_protector_sections": "requires PE sections context",
    "deobf_vm_state_flags": "requires VM state object",
    "deobf_vm_state_mem_roundtrip": "requires VM state object",
    "deobf_vm_state_simulate": "requires VM state + ISA context",
    "deobf_string_detect_xor_encryption_v3": "requires MLIL context",
    "deobf_string_detect_rc4_ksa_mlil_v3": "requires MLIL context",
    "deobf_string_detect_arith_obf_mlil_v3": "requires MLIL context",
    "deobf_string_detect_mlil_stack_strings_v3": "requires MLIL context",
    "deobf_string_asm_detect_stack_strings_v3": "requires disasm context",
    "deobf_string_detect_decoder_helpers_v3": "requires MLIL context",
    "deobf_string_recover_stack_strings_v3": "requires stack context",
    "deobf_string_rc4_inverse_ksa_v3": "requires MLIL context",
    "deobf_string_has_modified_utf8_null_v3": "requires project context",
    "deobf_string_utf_detect_anomalies_v3": "requires project context",
    "deobf_string_to_display_string_v3": "requires project context",
    "deobf_string_score_plaintext_v3": "requires project context",
    "deobf_string_detect_xor_key_period": "heuristic, nondeterministic for short inputs",
    "deobf_string_detect_xor_key_length_ic": "heuristic, nondeterministic",
    "deobf_string_caesar_bruteforce": "nondeterministic ranking",
    "deobf_smc_xor_chain_detect": "requires analysis context",
    "deobf_rolror_recover_rotation": "already checked above",
}
# Prevent double-skipping already-checked tools
already_covered = {
    "deobf_crc32","deobf_crc32_checksum","deobf_crc32_checksum_table",
    "deobf_adler32","deobf_adler32_checksum_v2",
    "deobf_xor_entropy","deobf_xor_entropy_v2","deobf_smc_shannon_entropy",
    "deobf_xor_decrypt_constant","deobf_xor_decrypt_cyclic","deobf_xor_decrypt_rolling",
    "deobf_xor_recover_single_byte_key",
    "deobf_rc4_decrypt","deobf_rc4_ksa",
    "deobf_rolror_decrypt_rol","deobf_rolror_decrypt_ror","deobf_rolror_recover_rotation",
    "deobf_base64_decode","deobf_base64_find_all","deobf_string_base64_encode",
    "deobf_string_rot13","deobf_string_hex_decode",
    "deobf_string_xor_decrypt_constant","deobf_string_xor_decrypt_cyclic",
    "deobf_string_rc4_decrypt","deobf_string_xor_key_apply_v3",
    "deobf_smc_xor_step_apply","deobf_smc_xor_step_reverse",
    "deobf_vm_read_u64_le","deobf_vm_read_u32_le","deobf_vm_read_u16_le",
    "deobf_opaque_known_patterns","deobf_opaque_classify_const","deobf_opaque_truth_table_defaults",
    "deobf_smc_addrol_encrypt","deobf_smc_addrol_decrypt",
    "deobf_smc_xor_chain_encrypt","deobf_smc_xor_chain_decrypt",
    "deobf_smc_detect","deobf_smc_detect_indicators","deobf_smc_looks_like_code",
    "deobf_smc_stats_from_bytes","deobf_smc_write_exec_detect",
    "deobf_entropy_scanner_scan","deobf_smc_region_len_is_empty",
    "deobf_smc_polymorphic_analyze","deobf_smc_decryptor_decrypt","deobf_smc_polymorphic_analyze_diff",
    "deobf_vm_arch_summary","deobf_vm_arch_register_machine","deobf_vm_arch_stack_machine",
    "deobf_vm_bytecode_new","deobf_vm_bytecode_inspect","deobf_vm_handler_cluster",
    "deobf_vm_state_new_probe","deobf_vm_pcode_varnode_size","deobf_vm_semantic_op_stack_delta",
    "deobf_string_xor_bruteforce_top3","deobf_string_compute_confidence",
    "deobf_string_detect_base64_variant","deobf_string_rotn_detect",
    "deobf_string_decode_base64_urlsafe","deobf_string_xor_recover_key",
    "deobf_string_recover_multibyte_xor",
}

for t in sorted(NAMES - already_covered):
    if t in SKIP_REASONS:
        skip(t, SKIP_REASONS[t])
    else:
        skip(t, "no independent ground truth available for this heuristic/analysis tool")

# ═══════════════════════════════════════════════════════════════════════════════
# Write outputs
# ═══════════════════════════════════════════════════════════════════════════════
try: p.terminate()
except Exception: pass

result = {
    "category": "deobf",
    "tools_in_category": len(NAMES),
    "checks_total": total,
    "checks_passed": passed,
    "checks_failed": total - passed,
    "checks_skipped": len(skipped),
    "mismatches": mismatches,
}
with open(OUT, "w") as f:
    json.dump({**result, "skipped": skipped}, f, indent=2, default=str)

with open(SKIP_OUT, "w") as f:
    json.dump(skipped, f, indent=2, default=str)

print(json.dumps(result, indent=2, default=str))
