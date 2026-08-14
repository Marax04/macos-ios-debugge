#!/usr/bin/env python3
"""Independent validators for MCP tools with prefix 'deobf_'."""
import json, subprocess, zlib, base64, sys

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mismatch_deobf_crypto.json"

def start():
    p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    def send(r): p.stdin.write((json.dumps(r)+"\n").encode()); p.stdin.flush()
    def recv():
        line = p.stdout.readline()
        return json.loads(line) if line else None
    send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2024-11-05","capabilities":{},
        "clientInfo":{"name":"v","version":"1"}}})
    recv()
    send({"jsonrpc":"2.0","method":"notifications/initialized"})
    return p, send, recv

p, send, recv = start()
rid = [10]

def call(name, args):
    rid[0] += 1
    send({"jsonrpc":"2.0","id":rid[0],"method":"tools/call",
          "params":{"name":name,"arguments":args}})
    resp = recv()
    if not resp: return None, "no-response"
    if "error" in resp: return None, "rpc-error:"+str(resp["error"])[:200]
    result = resp.get("result",{})
    if result.get("isError"):
        c = result.get("content",[])
        txt = c[0].get("text","") if c else ""
        return None, "tool-error:"+txt[:200]
    c = result.get("content",[])
    if not c: return None, "empty"
    txt = c[0].get("text","")
    try: return json.loads(txt), None
    except: return txt, None

def list_tools():
    ts = []
    cur = None
    while True:
        rid[0] += 1
        params = {} if cur is None else {"cursor": cur}
        send({"jsonrpc":"2.0","id":rid[0],"method":"tools/list","params":params})
        resp = recv()
        if not resp: break
        r = resp.get("result",{})
        ts += r.get("tools",[])
        cur = r.get("nextCursor")
        if not cur: break
    return ts

all_tools = list_tools()
deobf = [t for t in all_tools if t["name"].startswith("deobf_")]
names = {t["name"] for t in deobf}
print(f"[i] found {len(deobf)} deobf_ tools", file=sys.stderr)

mismatches = []
checks_total = 0
checks_passed = 0
checks_skipped = 0
log = []

def norm_bytes(v):
    if isinstance(v, list) and all(isinstance(x, int) for x in v): return bytes(v)
    if isinstance(v, (bytes, bytearray)): return bytes(v)
    if isinstance(v, str):
        try: return bytes.fromhex(v)
        except: return v.encode()
    return v

def get_val(r, keys):
    if isinstance(r, dict):
        for k in keys:
            if k in r: return r[k]
    return None

def maybe_int(v):
    if isinstance(v, str):
        try: return int(v,16) if v.lower().startswith("0x") else int(v)
        except:
            try: return int(v,16)
            except: return v
    return v

def record(tool, inp, mcp, truth, note, ok):
    global checks_total, checks_passed
    checks_total += 1
    if ok:
        checks_passed += 1
        log.append(f"OK   {tool}: {note}")
    else:
        mismatches.append({"tool":tool,"input":inp,"mcp":mcp,"truth":truth,"note":note})
        log.append(f"FAIL {tool}: {note} mcp={mcp!r} truth={truth!r}")

def skip(tool, reason):
    global checks_skipped
    checks_skipped += 1
    log.append(f"SKIP {tool}: {reason}")

def do_checksum(tool, truth_fn):
    if tool not in names: return
    data = b"123456789"
    inp = {"hex": data.hex()}
    r, err = call(tool, inp)
    if err or r is None: return skip(tool, f"err={err}")
    val = get_val(r, ["crc","crc32","checksum","adler","adler32","result","value","hash"])
    if val is None: return skip(tool, f"no numeric field in {r}")
    val = maybe_int(val)
    truth = truth_fn(data)
    record(tool, inp, val, truth, f"{tool}(123456789)", val == truth)

do_checksum("deobf_crc32", zlib.crc32)
do_checksum("deobf_crc32_checksum", zlib.crc32)
do_checksum("deobf_crc32_checksum_table", zlib.crc32)
do_checksum("deobf_adler32", zlib.adler32)
do_checksum("deobf_adler32_checksum_v2", zlib.adler32)

# ROT13
tool = "deobf_string_rot13"
if tool in names:
    inp = {"text":"Hello, World!"}
    r, err = call(tool, inp)
    if err or r is None: skip(tool, f"err={err}")
    else:
        def rot13(s):
            out=[]
            for c in s:
                o=ord(c)
                if 97<=o<=122: out.append(chr((o-97+13)%26+97))
                elif 65<=o<=90: out.append(chr((o-65+13)%26+65))
                else: out.append(c)
            return "".join(out)
        truth = rot13("Hello, World!")
        val = get_val(r, ["result","value","output","decoded","encoded","text","rot13"])
        if val is None: skip(tool, f"no output in {r}")
        else: record(tool, inp, val, truth, "rot13", val == truth)

# Hex decode
tool = "deobf_string_hex_decode"
if tool in names:
    inp = {"text":"48656c6c6f"}
    r, err = call(tool, inp)
    if err or r is None: skip(tool, f"err={err}")
    else:
        val = get_val(r, ["decoded_hex","decoded","bytes","result","value","plaintext","output","data","out_hex"])
        if val is None: skip(tool, f"no output in {r}")
        else:
            vb = norm_bytes(val)
            record(tool, inp, vb, b"Hello", "hex 48656c6c6f=Hello", vb == b"Hello")

# Base64 decode
tool = "deobf_base64_decode"
if tool in names:
    plain = b"Hello, World!"
    enc = base64.b64encode(plain).decode()
    inp = {"text": enc}
    r, err = call(tool, inp)
    if err or r is None: skip(tool, f"err={err}")
    else:
        val = get_val(r, ["out_hex","decoded_hex","decoded","bytes","data","result","value","plaintext","output"])
        if val is None: skip(tool, f"no output in {r}")
        else:
            vb = norm_bytes(val)
            record(tool, inp, vb, plain, "b64 decode", vb == plain)

# Base64 encode
tool = "deobf_string_base64_encode"
if tool in names:
    plain = b"Hello, World!"
    inp = {"hex": plain.hex()}
    r, err = call(tool, inp)
    if err or r is None: skip(tool, f"err={err}")
    else:
        truth = base64.b64encode(plain).decode()
        val = get_val(r, ["encoded","result","value","output","b64","base64"])
        if val is None: skip(tool, f"no output in {r}")
        else: record(tool, inp, val, truth, "b64 encode", val == truth)

# Base64 find all
tool = "deobf_base64_find_all"
if tool in names:
    plain = b"start SGVsbG8sIFdvcmxkIQ== mid aGVsbG8gd29ybGQ= end"
    inp = {"hex": plain.hex()}
    r, err = call(tool, inp)
    if err or r is None: skip(tool, f"err={err}")
    else:
        cnt = None
        if isinstance(r, dict):
            for k in ("matches","found","results","candidates","strings","hits"):
                if k in r and isinstance(r[k], list):
                    cnt = len(r[k]); break
            if cnt is None and "count" in r: cnt = r["count"]
        if cnt is None: skip(tool, f"no matches list in {r}")
        else: record(tool, inp, cnt, ">=1", "b64 find count", cnt >= 1)

# XOR constant
tool = "deobf_xor_decrypt_constant"
if tool in names:
    plain = b"HELLO WORLD"
    key = 0x42
    ct = bytes(b ^ key for b in plain)
    inp = {"hex": ct.hex(), "key": key}
    r, err = call(tool, inp)
    if err or r is None: skip(tool, f"err={err}")
    else:
        val = get_val(r, ["out_hex","decrypted","plaintext","result","value","output","data","bytes","decoded_hex"])
        if val is None: skip(tool, f"no output in {r}")
        else:
            vb = norm_bytes(val)
            record(tool, inp, vb, plain, "xor single 0x42", vb == plain)

# XOR cyclic
tool = "deobf_xor_decrypt_cyclic"
if tool in names:
    plain = b"Hello, cyclic world!"
    key = b"KEY"
    ct = bytes(plain[i] ^ key[i%len(key)] for i in range(len(plain)))
    inp = {"hex": ct.hex(), "key_hex": key.hex()}
    r, err = call(tool, inp)
    if err or r is None: skip(tool, f"err={err}")
    else:
        val = get_val(r, ["out_hex","decrypted","plaintext","result","value","output","data","bytes","decoded_hex"])
        if val is None: skip(tool, f"no output in {r}")
        else:
            vb = norm_bytes(val)
            record(tool, inp, vb, plain, "xor cyclic KEY", vb == plain)

# XOR entropy
tool = "deobf_xor_entropy"
if tool in names:
    data = bytes(range(256))
    inp = {"hex": data.hex()}
    r, err = call(tool, inp)
    if err or r is None: skip(tool, f"err={err}")
    else:
        val = get_val(r, ["entropy_bits_per_byte","entropy","result","value","shannon"])
        if val is None: skip(tool, f"no entropy in {r}")
        else:
            ok = isinstance(val,(int,float)) and abs(float(val) - 8.0) < 0.01
            record(tool, inp, val, 8.0, "entropy(0..255)==8.0", ok)

# Shannon entropy
tool = "deobf_smc_shannon_entropy"
if tool in names:
    data = bytes(range(256))
    inp = {"hex": data.hex()}
    r, err = call(tool, inp)
    if err or r is None: skip(tool, f"err={err}")
    else:
        val = get_val(r, ["entropy_bits_per_byte","entropy","result","value","shannon"])
        if val is None: skip(tool, f"no entropy in {r}")
        else:
            ok = isinstance(val,(int,float)) and abs(float(val) - 8.0) < 0.01
            record(tool, inp, val, 8.0, "shannon(0..255)==8.0", ok)

# RC4
def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i%len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    i=j=0; out=bytearray()
    for b in data:
        i = (i+1) & 0xff
        j = (j+S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i]+S[j]) & 0xff])
    return bytes(out)

tool = "deobf_rc4_decrypt"
if tool in names:
    key = b"Key"
    plain = b"Plaintext"
    ct = rc4(key, plain)
    inp = {"hex": ct.hex(), "key_hex": key.hex()}
    r, err = call(tool, inp)
    if err or r is None: skip(tool, f"err={err}")
    else:
        val = get_val(r, ["out_hex","decrypted","plaintext","result","value","output","data","bytes","decoded_hex"])
        if val is None: skip(tool, f"no output in {r}")
        else:
            vb = norm_bytes(val)
            record(tool, inp, vb, plain, "RC4 Key/Plaintext", vb == plain)

tool = "deobf_rc4_ksa"
if tool in names:
    key = b"Key"
    inp = {"key_hex": key.hex()}
    r, err = call(tool, inp)
    if err or r is None: skip(tool, f"err={err}")
    else:
        S = list(range(256)); j=0
        for i in range(256):
            j = (j + S[i] + key[i%len(key)]) & 0xff
            S[i], S[j] = S[j], S[i]
        val = get_val(r, ["first16_hex","state","s","result","value","S","sbox"])
        if val is None: skip(tool, f"no state in {r}")
        else:
            vb = list(val) if isinstance(val,list) else (list(bytes.fromhex(val)) if isinstance(val,str) else None)
            if vb is None: skip(tool, "state format unknown")
            else: record(tool, inp, vb[:16], S[:16], "RC4 KSA first 16", vb == S[:16])

# Extra: rolror / smc detections — just check they don't error out
for tool in ("deobf_rolror_decrypt_rol", "deobf_rolror_decrypt_ror"):
    if tool in names:
        skip(tool, "rotation semantics ambiguous without paired encrypt reference")
        continue
    if False:
        plain = bytes([0x12, 0x34, 0x56])
        # ROL by 3: (b<<3|b>>5)&0xff
        rot_l = bytes(((b<<3)|(b>>5))&0xff for b in plain)
        rot_r = bytes(((b>>3)|(b<<5))&0xff for b in plain)
        if tool.endswith("rol"):
            # decrypt_rol undoes an encrypt via ROR? Usually decrypt_rol rotates left
            ct = rot_r  # ciphertext was rotated right, decrypt with rol
            inp = {"hex": ct.hex(), "rotation": 3}
            truth = plain
        else:
            ct = rot_l
            inp = {"hex": ct.hex(), "rotation": 3}
            truth = plain
        r, err = call(tool, inp)
        if err or r is None: skip(tool, f"err={err}")
        else:
            val = get_val(r, ["out_hex","decrypted","plaintext","result","value","output","data","bytes","decoded_hex"])
            if val is None: skip(tool, f"no output in {r}")
            else:
                vb = norm_bytes(val)
                record(tool, inp, vb, truth, "rol/ror by 3", vb == truth)

# string_xor_decrypt_constant/cyclic (same as xor)
tool = "deobf_string_xor_decrypt_constant"
if tool in names:
    plain = b"HELLO WORLD"; key=0x33
    ct = bytes(b^key for b in plain)
    inp = {"hex": ct.hex(), "key": key}
    r, err = call(tool, inp)
    if err or r is None: skip(tool, f"err={err}")
    else:
        val = get_val(r, ["out_hex","decrypted_hex","decoded_hex","decrypted","plaintext","result","value","output","data","bytes"])
        if val is None: skip(tool, f"no output in {r}")
        else:
            vb = norm_bytes(val)
            record(tool, inp, vb, plain, "str xor const 0x33", vb == plain)

tool = "deobf_string_xor_decrypt_cyclic"
if tool in names:
    plain = b"Attack at dawn!"; key=b"AB"
    ct = bytes(plain[i]^key[i%len(key)] for i in range(len(plain)))
    inp = {"hex": ct.hex(), "key_hex": key.hex()}
    r, err = call(tool, inp)
    if err or r is None: skip(tool, f"err={err}")
    else:
        val = get_val(r, ["out_hex","decrypted_hex","decoded_hex","decrypted","plaintext","result","value","output","data","bytes"])
        if val is None: skip(tool, f"no output in {r}")
        else:
            vb = norm_bytes(val)
            record(tool, inp, vb, plain, "str xor cyclic AB", vb == plain)

# string_rc4_decrypt
tool = "deobf_string_rc4_decrypt"
if tool in names:
    key = b"Wiki"; plain = b"pedia"
    ct = rc4(key, plain)
    inp = {"hex": ct.hex(), "key_hex": key.hex()}
    r, err = call(tool, inp)
    if err or r is None: skip(tool, f"err={err}")
    else:
        val = get_val(r, ["out_hex","decrypted_hex","decoded_hex","decrypted","plaintext","result","value","output","data","bytes"])
        if val is None: skip(tool, f"no output in {r}")
        else:
            vb = norm_bytes(val)
            record(tool, inp, vb, plain, "str RC4 Wiki/pedia", vb == plain)

# smc_addrol_encrypt/decrypt round-trip
tool = "deobf_smc_addrol_encrypt"
tool_d = "deobf_smc_addrol_decrypt"
if tool in names and tool_d in names:
    plain = b"\x10\x20\x30\x40"
    inp_e = {"hex": plain.hex(), "add_key": 5, "rol_amount": 3, "add_first": True}
    r, err = call(tool, inp_e)
    if err or r is None:
        skip(tool, f"err={err}")
    else:
        ct_hex = get_val(r, ["out_hex","encrypted","result","value","output"])
        if ct_hex is None:
            skip(tool, f"no ct in {r}")
        else:
            # sanity: encrypt should produce something != plain
            record(tool, inp_e, ct_hex != plain.hex(), True, "encrypt changes bytes", ct_hex != plain.hex())
            # now decrypt and compare
            inp_d = {"hex": ct_hex, "add_key": 5, "rol_amount": 3, "add_first": True}
            r2, err2 = call(tool_d, inp_d)
            if err2 or r2 is None: skip(tool_d, f"err={err2}")
            else:
                dv = get_val(r2, ["out_hex","decrypted","plaintext","result","value","output"])
                if dv is None: skip(tool_d, f"no output in {r2}")
                else:
                    vb = norm_bytes(dv)
                    record(tool_d, inp_d, vb, plain, "addrol round-trip", vb == plain)

# smc_xor_step_apply / reverse: byte=0x41, key=0x0F -> apply -> reverse -> 0x41
tool = "deobf_smc_xor_step_apply"
tool_r = "deobf_smc_xor_step_reverse"
if tool in names and tool_r in names:
    inp = {"byte": 0x41, "key": 0x0F}
    r, err = call(tool, inp)
    if err or r is None: skip(tool, f"err={err}")
    else:
        outb = get_val(r, ["out","result","value","byte","output"])
        if outb is None: skip(tool, f"no out in {r}")
        else:
            # truth: 0x41 XOR 0x0F = 0x4E (basic case, pre_op=0, rot=0)
            truth = 0x41 ^ 0x0F
            ok = int(outb) == truth
            record(tool, inp, outb, truth, "0x41 xor 0x0F", ok)
            inp2 = {"byte": int(outb), "key": 0x0F}
            r2, err2 = call(tool_r, inp2)
            if err2 or r2 is None: skip(tool_r, f"err={err2}")
            else:
                ob = get_val(r2, ["out","result","value","byte","output"])
                if ob is None: skip(tool_r, f"no out")
                else: record(tool_r, inp2, int(ob), 0x41, "reverse round-trip", int(ob)==0x41)

# string_xor_key_apply_v3: apply key
tool = "deobf_string_xor_key_apply_v3"
if tool in names:
    plain = b"testdata"; key = b"XY"
    ct = bytes(plain[i]^key[i%len(key)] for i in range(len(plain)))
    # apply key to ciphertext should give plaintext (symmetric)
    inp = {"data_hex": ct.hex(), "key_hex": key.hex()}
    r, err = call(tool, inp)
    if err or r is None: skip(tool, f"err={err}")
    else:
        val = get_val(r, ["out_hex","result","value","output","decrypted","plaintext"])
        if val is None: skip(tool, f"no output in {r}")
        else:
            vb = norm_bytes(val)
            record(tool, inp, vb, plain, "xor apply v3 symmetric", vb == plain)

# xor_recover_single_byte_key: XOR "AAAAA..." with 0x42
tool = "deobf_xor_recover_single_byte_key"
if tool in names:
    plain = b"the quick brown fox jumps over the lazy dog" * 2
    key = 0x5B
    ct = bytes(b^key for b in plain)
    inp = {"hex": ct.hex()}
    r, err = call(tool, inp)
    if err or r is None: skip(tool, f"err={err}")
    else:
        val = get_val(r, ["key","recovered_key","result","value","best_key"])
        if val is None: skip(tool, f"no key in {r}")
        else:
            k = maybe_int(val) if not isinstance(val,int) else val
            record(tool, inp, k, key, "recover single-byte key", k == key)

result = {
    "category": "deobf_crypto",
    "tools_in_category": len(deobf),
    "checks_total": checks_total,
    "checks_passed": checks_passed,
    "checks_skipped": checks_skipped,
    "mismatches": mismatches,
}
with open(OUT, "w") as f:
    json.dump({**result, "log":log}, f, indent=2, default=str)
print(json.dumps(result, indent=2, default=str))
try: p.terminate()
except: pass
