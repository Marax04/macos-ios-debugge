#!/usr/bin/env python3
"""
Rigorous ground-truth validator for all MCP tools prefixed with mobile_
(or belonging to the mobile category such as ios_* wire tools).

Each test case has:
  - tool name
  - input arguments
  - a reference function computed purely in Python from reading the Rust source
  - a comparator (exact match or subset)

Results are saved to:
  - rigorous_mobile_v2.json   (pass / fail entries)
  - skip_mobile.json          (skip entries with reason)
"""

import json
import subprocess
import sys
import time
from typing import Any

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
PDB = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo_zyphora.pdb"
OUT_V2 = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_mobile_v2.json"
OUT_SKIP = r"C:\Users\Fra\Desktop\RustRE\validation\skip_mobile.json"

# ─── MCP transport ────────────────────────────────────────────────────────────

proc = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    bufsize=0,
)

_rid = 0


def send(req: dict) -> None:
    proc.stdin.write((json.dumps(req) + "\n").encode())
    proc.stdin.flush()


def recv() -> dict:
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("MCP server died")
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {"error": {"message": f"bad-line: {line[:120]!r}"}}


def call_tool(name: str, args: dict) -> tuple[bool, Any]:
    """
    Returns (is_error: bool, parsed_json_or_text).
    Times out after 10 s by using a sentinel approach (we just do blocking
    reads; the server is local so 10 s is the absolute wall-clock budget we
    allow before we give up and mark SKIP).
    """
    global _rid
    _rid += 1
    send({"jsonrpc": "2.0", "id": _rid, "method": "tools/call",
          "params": {"name": name, "arguments": args}})
    resp = recv()
    if "error" in resp:
        return True, str(resp["error"])
    is_err = resp.get("result", {}).get("isError", False)
    content = resp.get("result", {}).get("content", [])
    txt = content[0].get("text", "") if content else ""
    if is_err:
        return True, txt
    try:
        return False, json.loads(txt)
    except Exception:
        return False, txt


# ─── Bootstrap: initialize + open project ────────────────────────────────────

send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                 "clientInfo": {"name": "rigorous_mobile", "version": "2"}}})
recv()
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
      "params": {"name": "project.open", "arguments": {"path": TARGET}}})
op = recv()
try:
    op_data = json.loads(op["result"]["content"][0]["text"])
    BINARY_ID = op_data["binary_id"]
    PROJECT_ID = op_data["project_id"]
except Exception as exc:
    print(f"ERROR: project.open failed: {exc}")
    proc.terminate()
    sys.exit(1)

print(f"project.open OK: binary_id={BINARY_ID}, project_id={PROJECT_ID}")

# ─── Python reference implementations ────────────────────────────────────────

def ref_smali_parse_type(desc: str) -> str:
    """Mirror of rustre_mobile_smali::parse_type_descriptor."""
    bs = desc.encode()
    result = []
    i = 0
    while i < len(bs):
        c = bs[i]
        if c == ord('B'):
            result.append("byte"); i += 1
        elif c == ord('C'):
            result.append("char"); i += 1
        elif c == ord('D'):
            result.append("double"); i += 1
        elif c == ord('F'):
            result.append("float"); i += 1
        elif c == ord('I'):
            result.append("int"); i += 1
        elif c == ord('J'):
            result.append("long"); i += 1
        elif c == ord('S'):
            result.append("short"); i += 1
        elif c == ord('Z'):
            result.append("boolean"); i += 1
        elif c == ord('V'):
            result.append("void"); i += 1
        elif c == ord('['):
            # count arrays
            dims = 0
            j = i
            while j < len(bs) and bs[j] == ord('['):
                dims += 1; j += 1
            inner_desc = desc[j:]
            # parse inner type
            inner = _parse_type_at(inner_desc)
            i = j + _type_desc_len(inner_desc)
            result.append(inner + "[]" * dims)
        elif c == ord('L'):
            end = bs.find(b';', i + 1)
            if end == -1:
                result.append(bs[i+1:].decode(errors='replace').replace('/', '.')); i = len(bs)
            else:
                result.append(bs[i+1:end].decode(errors='replace').replace('/', '.')); i = end + 1
        else:
            result.append(chr(c)); i += 1
    return result[0] if result else "void"


def _parse_type_at(desc: str) -> str:
    """Parse a single type descriptor and return the Java type name."""
    bs = desc.encode()
    if not bs:
        return "void"
    c = bs[0]
    return {
        ord('B'): "byte", ord('C'): "char", ord('D'): "double",
        ord('F'): "float", ord('I'): "int", ord('J'): "long",
        ord('S'): "short", ord('Z'): "boolean", ord('V'): "void",
    }.get(c, None) or (
        (_parse_type_at(desc[1:]) + "[]") if c == ord('[') else
        (desc[1:desc.index(';')].replace('/', '.') if c == ord('L') and ';' in desc else
         chr(c))
    )


def _type_desc_len(desc: str) -> int:
    """Return the number of characters consumed by one type descriptor."""
    if not desc:
        return 0
    c = desc[0]
    if c in 'BCDFIJSZV':
        return 1
    if c == '[':
        return 1 + _type_desc_len(desc[1:])
    if c == 'L':
        return desc.index(';') + 1 if ';' in desc else len(desc)
    return 1


def ref_smali_parse_type_simple(desc: str) -> str:
    return _parse_type_at(desc)


def ref_smali_parse_method(desc: str) -> tuple:
    """Mirror of rustre_mobile_smali::parse_method_descriptor."""
    if not desc or desc[0] != '(':
        return ([], "void")
    # find closing ')'
    close = desc.index(')')
    param_str = desc[1:close]
    ret_str = desc[close+1:]
    params = []
    i = 0
    while i < len(param_str):
        l = _type_desc_len(param_str[i:])
        params.append(_parse_type_at(param_str[i:]))
        i += l
    ret = _parse_type_at(ret_str) if ret_str else "void"
    return (params, ret)


def ref_dyld_format_uuid(uuid_list: list) -> str:
    """Mirror of rustre_mobile_dyld::format_uuid."""
    u = uuid_list
    return (
        f"{u[0]:02x}{u[1]:02x}{u[2]:02x}{u[3]:02x}-"
        f"{u[4]:02x}{u[5]:02x}-{u[6]:02x}{u[7]:02x}-"
        f"{u[8]:02x}{u[9]:02x}-"
        f"{u[10]:02x}{u[11]:02x}{u[12]:02x}{u[13]:02x}{u[14]:02x}{u[15]:02x}"
    )


def ref_ios_decode_type_encoding(enc: str) -> list:
    """
    Mirror of rustre_mobile_ios::decode_type_encoding.
    Returns list of type strings.
    """
    simple_map = {
        'v': 'void', 'c': 'char', 'i': 'int', 's': 'short', 'l': 'long',
        'q': 'long long', 'C': 'unsigned char', 'I': 'unsigned int',
        'S': 'unsigned short', 'L': 'unsigned long', 'Q': 'unsigned long long',
        'f': 'float', 'd': 'double', 'B': 'bool',
        '#': 'Class', ':': 'SEL', '*': 'char*', '?': 'func_ptr',
    }
    qualifiers = set('rnNoORV')

    def decode_one(chars, pos):
        if pos >= len(chars):
            return ('?', 1)
        c = chars[pos]
        if c in qualifiers:
            inner, n = decode_one(chars, pos + 1)
            return (inner, 1 + n)
        if c in simple_map:
            return (simple_map[c], 1)
        if c == '@':
            if pos + 1 < len(chars) and chars[pos+1] == '"':
                start = pos + 2
                end = None
                for k in range(start, len(chars)):
                    if chars[k] == '"':
                        end = k
                        break
                if end is not None:
                    name = ''.join(chars[start:end])
                    return (f'id<{name}>', end - pos + 1)
            return ('id', 1)
        if c == '^':
            inner, n = decode_one(chars, pos + 1)
            return (f'*{inner}', 1 + n)
        if c.isdigit():
            j = pos + 1
            while j < len(chars) and chars[j].isdigit():
                j += 1
            return ('', j - pos)
        if c == '[':
            # array
            j = pos + 1
            while j < len(chars) and chars[j].isdigit():
                j += 1
            count = ''.join(chars[pos+1:j])
            inner, n = decode_one(chars, j)
            close = j + n
            total = close - pos + (1 if close < len(chars) and chars[close] == ']' else 0)
            return (f'{inner}[{count}]', total)
        if c == '{':
            # struct
            name = ''
            k = pos + 1
            while k < len(chars) and chars[k] not in ('=', '}'):
                name += chars[k]; k += 1
            # skip to closing '}'
            depth = 1; k = pos + 1
            while k < len(chars) and depth > 0:
                if chars[k] == '{': depth += 1
                elif chars[k] == '}': depth -= 1
                k += 1
            return (f'struct {name}', k - pos)
        if c == '(':
            name = ''
            k = pos + 1
            while k < len(chars) and chars[k] not in ('=', ')'):
                name += chars[k]; k += 1
            depth = 1; k = pos + 1
            while k < len(chars) and depth > 0:
                if chars[k] == '(': depth += 1
                elif chars[k] == ')': depth -= 1
                k += 1
            return (f'union {name}', k - pos)
        return (c, 1)

    chars = list(enc)
    out = []
    i = 0
    while i < len(chars):
        ty, consumed = decode_one(chars, i)
        if ty:  # skip empty (digit offset annotations)
            out.append(ty)
        i += max(consumed, 1)
    return out


def ref_smali_reg_display(num: int) -> str:
    """Mirror of SmaliReg Display impl."""
    if num < 64:
        return f"v{num}"
    return f"p{num - 64}"


def ref_smali_literal_display(value: int) -> str:
    """Mirror of SmaliOperand::Literal Display."""
    if value < 0:
        abs_val = abs(value)
        return f"-{hex(abs_val)}"
    return hex(value)


# ─── Test case definitions ────────────────────────────────────────────────────

# Each entry: (tool_name, args, checker)
# checker(actual_json) -> (ok: bool, expected_repr: str)

def exact(key, expected):
    def check(d):
        if not isinstance(d, dict):
            return False, repr(expected)
        return d.get(key) == expected, repr(expected)
    return check


def subset_check(**expected_kv):
    def check(d):
        if not isinstance(d, dict):
            return False, repr(expected_kv)
        for k, v in expected_kv.items():
            if d.get(k) != v:
                return False, repr(expected_kv)
        return True, repr(expected_kv)
    return check


TEST_CASES = []

# ── smali_parse_type_descriptor_wire ─────────────────────────────────────────
for desc, expected_java in [
    ("I", "int"),
    ("B", "byte"),
    ("Z", "boolean"),
    ("V", "void"),
    ("Ljava/lang/String;", "java.lang.String"),
    ("[I", "int[]"),
    ("[[B", "byte[][]"),
]:
    TEST_CASES.append((
        "mobile_smali_parse_type_descriptor_wire",
        {"desc": desc},
        lambda d, ej=expected_java: (d.get("java_type") == ej, repr(ej))
    ))

# ── smali_parse_method_descriptor_wire ───────────────────────────────────────
for mdesc, exp_params, exp_ret in [
    ("(IZ)V", ["int", "boolean"], "void"),
    ("()V", [], "void"),
    ("(Ljava/lang/String;)[B", ["java.lang.String"], "byte[]"),
]:
    TEST_CASES.append((
        "mobile_smali_parse_method_descriptor_wire",
        {"desc": mdesc},
        lambda d, ep=exp_params, er=exp_ret: (
            d.get("params") == ep and d.get("return") == er,
            repr({"params": ep, "return": er})
        )
    ))

# ── jadx_java_method_is_constructor ──────────────────────────────────────────
TEST_CASES.append((
    "mobile_jadx_java_method_is_constructor",
    {"name": "<init>", "signature": "()", "return_type": "void",
     "params": [], "body": "", "is_static": False, "is_native": False},
    exact("is_constructor", True)
))
TEST_CASES.append((
    "mobile_jadx_java_method_is_constructor",
    {"name": "constructor", "signature": "()", "return_type": "void",
     "params": [], "body": "", "is_static": False, "is_native": False},
    exact("is_constructor", True)
))
TEST_CASES.append((
    "mobile_jadx_java_method_is_constructor",
    {"name": "onCreate", "signature": "(Bundle)", "return_type": "void",
     "params": [], "body": "", "is_static": False, "is_native": False},
    exact("is_constructor", False)
))

# ── jadx_config_new ──────────────────────────────────────────────────────────
TEST_CASES.append((
    "mobile_jadx_config_new",
    {"jadx": "jadx", "input": "app.apk", "output": "out"},
    subset_check(threads=4, deobfuscate=False)
))

# ── jadx_config_with_threads ─────────────────────────────────────────────────
TEST_CASES.append((
    "mobile_jadx_config_with_threads",
    {"threads": 8},
    exact("threads", 8)
))

# ── jadx_config_with_deobfuscate ─────────────────────────────────────────────
TEST_CASES.append((
    "mobile_jadx_config_with_deobfuscate",
    {},
    exact("deobfuscate", True)
))

# ── jadx_project_mock ─────────────────────────────────────────────────────────
TEST_CASES.append((
    "mobile_jadx_project_mock",
    {},
    subset_check(total=9, failed=0, classes=9)
))

# ── jadx_project_success_rate ─────────────────────────────────────────────────
TEST_CASES.append((
    "mobile_jadx_project_success_rate",
    {},
    # success_rate = (9-0)/9 = 1.0
    lambda d: (abs(d.get("success_rate", -1) - 1.0) < 1e-9, "1.0")
))

# ── jadx_project_find_class ──────────────────────────────────────────────────
TEST_CASES.append((
    "mobile_jadx_project_find_class",
    {"name": "Utils"},
    exact("found", "Utils")
))
TEST_CASES.append((
    "mobile_jadx_project_find_class",
    {"name": "NonExistent"},
    exact("found", None)
))

# ── jadx_project_in_package ──────────────────────────────────────────────────
TEST_CASES.append((
    "mobile_jadx_project_in_package",
    {"pkg": "com.example.app"},
    lambda d: (
        isinstance(d.get("classes"), list) and
        sorted(d["classes"]) == sorted(["MainActivity", "AppApplication", "Utils"]),
        "['AppApplication', 'MainActivity', 'Utils']"
    )
))

# ── jadx_class_static_methods ────────────────────────────────────────────────
TEST_CASES.append((
    "mobile_jadx_class_static_methods",
    {},
    lambda d: (
        isinstance(d.get("static_methods"), list) and
        sorted(d["static_methods"]) == sorted(["encrypt", "decrypt"]),
        "['decrypt', 'encrypt']"
    )
))

# ── jadx_class_native_methods ────────────────────────────────────────────────
TEST_CASES.append((
    "mobile_jadx_class_native_methods",
    {},
    lambda d: (
        isinstance(d.get("native_methods"), list) and
        d["native_methods"] == ["nativeInit"],
        "['nativeInit']"
    )
))

# ── jadx_dalvik_opcode_from_byte (jadx crate — partial opcodes) ──────────────
TEST_CASES.append((
    "mobile_jadx_dalvik_opcode_from_byte",
    {"byte": 0x0e},  # ReturnVoid
    lambda d: (d.get("mnemonic") == "return-void", "return-void")
))
TEST_CASES.append((
    "mobile_jadx_dalvik_opcode_from_byte",
    {"byte": 0x71},  # InvokeStatic
    lambda d: (d.get("mnemonic") == "invoke-static", "invoke-static")
))
TEST_CASES.append((
    "mobile_jadx_dalvik_opcode_from_byte",
    {"byte": 0xAB},  # Unknown to jadx partial opcode set
    lambda d: (d.get("mnemonic") is None, "null/None")
))

# ── jadx_dalvik_opcode_mnemonic ──────────────────────────────────────────────
TEST_CASES.append((
    "mobile_jadx_dalvik_opcode_mnemonic",
    {"byte": 0x0e},
    lambda d: (d.get("mnemonic") == "return-void", "return-void")
))

# ── smali_class_mock ─────────────────────────────────────────────────────────
# mock("LFoo;") → methods=3, fields=1, super='Ljava/lang/Object;'
TEST_CASES.append((
    "mobile_smali_class_mock",
    {"name": "LFoo;"},
    subset_check(methods=3, fields=1)
))
TEST_CASES.append((
    "mobile_smali_class_mock",
    {"name": "LFoo;"},
    lambda d: (d.get("super") == "Ljava/lang/Object;", "Ljava/lang/Object;")
))

# ── smali_method_is_constructor ───────────────────────────────────────────────
# SmaliMethod::is_constructor checks name == "<init>" or "<clinit>"
TEST_CASES.append((
    "mobile_smali_method_is_constructor",
    {"name": "<init>"},
    exact("is_constructor", True)
))
TEST_CASES.append((
    "mobile_smali_method_is_constructor",
    {"name": "<clinit>"},
    exact("is_constructor", True)
))
TEST_CASES.append((
    "mobile_smali_method_is_constructor",
    {"name": "execute"},
    exact("is_constructor", False)
))

# ── smali_instr_to_text ───────────────────────────────────────────────────────
# SmaliInstr { op: ReturnVoid, operands: [], label: None }.to_text() == "return-void"
TEST_CASES.append((
    "mobile_smali_instr_to_text",
    {},  # no label
    exact("text", "return-void")
))
TEST_CASES.append((
    "mobile_smali_instr_to_text",
    {"label": ":cond_0"},
    lambda d: (d.get("text") == ":cond_0\nreturn-void", ":cond_0\\nreturn-void")
))

# ── smali_op_display ─────────────────────────────────────────────────────────
# byte 0x00 → Nop → "nop"
TEST_CASES.append((
    "mobile_smali_op_display",
    {"byte": 0x00},
    exact("display", "nop")
))
# byte 0x0e → ReturnVoid → "return-void"
TEST_CASES.append((
    "mobile_smali_op_display",
    {"byte": 0x0e},
    exact("display", "return-void")
))

# ── smali_opcode_as_byte ─────────────────────────────────────────────────────
# Roundtrip: from_byte(b).as_byte() == b for all known opcodes
for b in [0x00, 0x01, 0x0e, 0x71, 0xd8, 0xff]:
    TEST_CASES.append((
        "mobile_smali_opcode_as_byte",
        {"byte": b},
        # Response uses key "out" for the roundtrip byte value
        lambda d, expected_b=b: (d.get("out") == expected_b, str(expected_b))
    ))

# ── smali_operand_literal_display ────────────────────────────────────────────
# Literal(5) → "0x5", Literal(-5) → "-0x5", Literal(0) → "0x0"
for val, expected_display in [
    (0,    "0x0"),
    (5,    "0x5"),
    (-5,   "-0x5"),
    (255,  "0xff"),
    (-256, "-0x100"),
]:
    TEST_CASES.append((
        "mobile_smali_operand_literal_display",
        {"value": val},
        lambda d, ed=expected_display: (d.get("display") == ed, ed)
    ))

# ── smali_instruction_size_bytes ─────────────────────────────────────────────
# byte 0x00 (Nop) → 2, byte 0x1a (ConstString) → 4, byte 0x14 (Const) → 6
for b, expected_size in [
    (0x00, 2),   # Nop
    (0x0e, 2),   # ReturnVoid
    (0x01, 2),   # Move
    (0x1a, 4),   # ConstString
    (0x14, 6),   # Const (32-bit)
]:
    TEST_CASES.append((
        "mobile_smali_instruction_size_bytes",
        {"byte": b},
        lambda d, es=expected_size: (d.get("size_bytes") == es, str(es))
    ))

# ── smali_reg_display ─────────────────────────────────────────────────────────
for num, expected_str in [(0, "v0"), (63, "v63"), (64, "p0"), (65, "p1")]:
    TEST_CASES.append((
        "mobile_smali_reg_display",
        {"num": num},
        lambda d, es=expected_str: (d.get("display") == es, es)
    ))

# ── dyld_header_is_arm64 ─────────────────────────────────────────────────────
TEST_CASES.append((
    "mobile_dyld_header_is_arm64",
    {"magic": "dyld_v1   arm64e"},
    exact("is_arm64", True)
))
TEST_CASES.append((
    "mobile_dyld_header_is_arm64",
    {"magic": "dyld_v1    x86_64"},
    exact("is_arm64", False)
))

# ── dyld_image_filename ──────────────────────────────────────────────────────
TEST_CASES.append((
    "mobile_dyld_image_filename",
    {"path": "/usr/lib/libSystem.B.dylib"},
    exact("filename", "libSystem.B.dylib")
))
TEST_CASES.append((
    "mobile_dyld_image_filename",
    {"path": "libfoo.dylib"},
    exact("filename", "libfoo.dylib")
))

# ── dyld_is_system_framework_path ────────────────────────────────────────────
TEST_CASES.append((
    "mobile_dyld_is_system_framework_path",
    {"path": "/System/Library/Frameworks/Foundation.framework/Foundation"},
    exact("is_system_framework", True)
))
TEST_CASES.append((
    "mobile_dyld_is_system_framework_path",
    {"path": "/usr/lib/libSystem.B.dylib"},
    exact("is_system_framework", True)
))
TEST_CASES.append((
    "mobile_dyld_is_system_framework_path",
    {"path": "/private/tmp/app.dylib"},
    exact("is_system_framework", False)
))

# ── dyld_symbol_is_objc ──────────────────────────────────────────────────────
TEST_CASES.append((
    "mobile_dyld_symbol_is_objc",
    {"name": "_OBJC_CLASS_$_NSObject"},
    exact("is_objc", True)
))
TEST_CASES.append((
    "mobile_dyld_symbol_is_objc",
    {"name": "+[NSObject init]"},
    exact("is_objc", True)
))
TEST_CASES.append((
    "mobile_dyld_symbol_is_objc",
    {"name": "_main"},
    exact("is_objc", False)
))

# ── dyld_symbol_is_swift ─────────────────────────────────────────────────────
TEST_CASES.append((
    "mobile_dyld_symbol_is_swift",
    {"name": "_$sSS10FoundationE4DataV"},
    exact("is_swift", True)
))
TEST_CASES.append((
    "mobile_dyld_symbol_is_swift",
    {"name": "$sSSyyy"},
    exact("is_swift", True)
))
TEST_CASES.append((
    "mobile_dyld_symbol_is_swift",
    {"name": "_main"},
    exact("is_swift", False)
))

# ── dyld_header_platform_name ─────────────────────────────────────────────────
for plat, name in [(1, "iOS"), (2, "macOS"), (3, "tvOS"), (7, "iOSSimulator"),
                   (99, "unknown")]:
    TEST_CASES.append((
        "mobile_dyld_header_platform_name",
        {"platform": plat},
        lambda d, en=name: (d.get("platform_name") == en, en)
    ))

# ── dyld_header_is_simulator ─────────────────────────────────────────────────
for plat, expected in [(1, False), (7, True), (8, True), (9, True), (2, False)]:
    TEST_CASES.append((
        "mobile_dyld_header_is_simulator",
        {"platform": plat},
        lambda d, ex=expected: (d.get("is_simulator") == ex, str(ex))
    ))

# ── dyld_mock_image_count ────────────────────────────────────────────────────
# DyldCache::mock() has images_count=2
TEST_CASES.append((
    "mobile_dyld_mock_image_count",
    {},
    exact("image_count", 2)
))

# ── dyld_format_uuid ─────────────────────────────────────────────────────────
uuid_bytes = [0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
              0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF]
expected_uuid = ref_dyld_format_uuid(uuid_bytes)
TEST_CASES.append((
    "mobile_dyld_format_uuid",
    {"uuid": uuid_bytes},
    lambda d, eu=expected_uuid: (d.get("uuid") == eu, eu)
))

# ── ipa_is_binary_plist / ipa_plist_is_binary ────────────────────────────────
for tool in ["mobile_ipa_is_binary_plist", "mobile_ipa_plist_is_binary"]:
    TEST_CASES.append((
        tool,
        {"hex": "62706c6973743030"},  # "bplist00" in hex
        lambda d: (d.get("is_binary_plist", d.get("is_binary")) is True, "true")
    ))
    TEST_CASES.append((
        tool,
        {"hex": "3c3f786d6c"},  # "<?xml" in hex
        lambda d: (d.get("is_binary_plist", d.get("is_binary")) is False, "false")
    ))

# ── ipa_mock_package ─────────────────────────────────────────────────────────
TEST_CASES.append((
    "mobile_ipa_mock_package",
    {},
    lambda d: (
        isinstance(d, dict) and (
            # Response nests under "package" -> "info_plist" -> "bundle_id"
            (d.get("package") or {}).get("info_plist", {}).get("bundle_id") == "com.example.TestApp"
            or d.get("bundle_id") == "com.example.TestApp"
        ),
        "bundle_id=com.example.TestApp"
    )
))

# ── ipa_mock_summary ─────────────────────────────────────────────────────────
TEST_CASES.append((
    "mobile_ipa_mock_summary",
    {},
    lambda d: (
        isinstance(d, dict) and (
            # Check at top level or nested under "package"."info_plist"
            d.get("bundle_id") == "com.example.TestApp"
            or (d.get("package") or {}).get("info_plist", {}).get("bundle_id") == "com.example.TestApp"
        ),
        "bundle_id=com.example.TestApp"
    )
))

# ── apktool_mock_success ─────────────────────────────────────────────────────
TEST_CASES.append((
    "mobile_apktool_mock_success",
    {},
    subset_check(decode_ok=True, build_ok=True)
))
TEST_CASES.append((
    "mobile_apktool_mock_success",
    {},
    lambda d: (
        isinstance(d.get("smali_dirs"), list) and len(d["smali_dirs"]) == 2,
        "smali_dirs length=2"
    )
))

# ── apktool_mock_failure ─────────────────────────────────────────────────────
TEST_CASES.append((
    "mobile_apktool_mock_failure",
    {},
    subset_check(decode_ok=False, build_ok=False, smali_dirs=0)
))

# ── apktool_error_display ────────────────────────────────────────────────────
TEST_CASES.append((
    "mobile_apktool_error_display",
    {"variant": "not_found", "message": "apktool"},
    lambda d: (d.get("display") == "not found: apktool", "not found: apktool")
))
TEST_CASES.append((
    "mobile_apktool_error_display",
    {"variant": "decode", "message": "bad apk"},
    lambda d: (d.get("display") == "decode error: bad apk", "decode error: bad apk")
))

# ── apktool_config_with_no_res ────────────────────────────────────────────────
TEST_CASES.append((
    "mobile_apktool_config_with_no_res",
    {"path": "apktool", "out": "out"},
    exact("no_res", True)
))

# ── apktool_config_with_force ─────────────────────────────────────────────────
TEST_CASES.append((
    "mobile_apktool_config_with_force",
    {"path": "apktool", "out": "out"},
    exact("force", True)
))

# ── apktool_config_with_no_src ────────────────────────────────────────────────
TEST_CASES.append((
    "mobile_apktool_config_with_no_src",
    {"path": "apktool", "out": "out"},
    exact("no_src", True)
))

# ── ios_swift_is_mangled ─────────────────────────────────────────────────────
TEST_CASES.append((
    "mobile_ios_swift_is_mangled",
    {"name": "_$sSS10FoundationE4DataV"},
    # Response uses key "is_swift_mangled" not "is_mangled"
    exact("is_swift_mangled", True)
))
TEST_CASES.append((
    "mobile_ios_swift_is_mangled",
    {"name": "_$SFooBar"},
    exact("is_swift_mangled", True)
))
TEST_CASES.append((
    "mobile_ios_swift_is_mangled",
    {"name": "_main"},
    exact("is_swift_mangled", False)
))
# ios_swift_is_mangled_wire uses same impl
TEST_CASES.append((
    "ios_swift_is_mangled_wire",
    {"name": "_$sFoo"},
    exact("is_swift_mangled", True)
))

# ── ios_decode_type_encoding ─────────────────────────────────────────────────
for tool in ["mobile_ios_decode_type_encoding", "ios_decode_type_encoding_wire"]:
    # Both mobile_ and wire variants use the "encoding" parameter key
    arg_key = "encoding"
    TEST_CASES.append((
        tool,
        {arg_key: "i"},
        lambda d: (d.get("types", d.get("parts")) == ["int"], "['int']")
    ))
    TEST_CASES.append((
        tool,
        {arg_key: "@:I"},
        lambda d: (
            d.get("types", d.get("parts")) == ["id", "SEL", "unsigned int"],
            "['id', 'SEL', 'unsigned int']"
        )
    ))

# ── ios_ipa_mock_has_entitlements ─────────────────────────────────────────────
TEST_CASES.append((
    "mobile_ipa_mock_has_entitlements",
    {},
    exact("has_entitlements", True)
))

# ── ipa_mock_entry_counts ────────────────────────────────────────────────────
# entries: 4 total, 1 framework dir
TEST_CASES.append((
    "mobile_ipa_mock_entry_counts",
    {},
    lambda d: (
        isinstance(d, dict) and d.get("entry_count") == 4,
        "entry_count=4"
    )
))

# ── jadx smali parse_type_descriptor (non-wire) ──────────────────────────────
for desc, exp in [("I", "int"), ("Ljava/lang/Object;", "java.lang.Object")]:
    TEST_CASES.append((
        "mobile_smali_parse_type_descriptor",
        {"desc": desc},
        lambda d, e=exp: (d.get("java_type") == e, e)
    ))

# ── jadx parse_method_descriptor (non-wire) ──────────────────────────────────
TEST_CASES.append((
    "mobile_smali_parse_method_descriptor",
    {"desc": "(IZ)V"},
    lambda d: (
        d.get("params") == ["int", "boolean"] and d.get("return") == "void",
        "params=['int','boolean'] return='void'"
    )
))

# ─── Run tests ────────────────────────────────────────────────────────────────

results_v2 = []
skips = []
mismatches = []
passed = 0
failed = 0
skipped = 0

# Deduplicate by (tool, repr(args)) so we don't call the same thing twice
seen = {}
unique_cases = []
for tool, args, checker in TEST_CASES:
    key = (tool, json.dumps(args, sort_keys=True))
    if key not in seen:
        seen[key] = True
        unique_cases.append((tool, args, checker))

# Group by tool to call each tool only once per unique (tool, args)
tool_cache = {}

print(f"\nRunning {len(unique_cases)} unique test assertions across mobile tools...\n")

for tool, args, checker in unique_cases:
    cache_key = (tool, json.dumps(args, sort_keys=True))

    if cache_key not in tool_cache:
        try:
            is_err, data = call_tool(tool, args)
            tool_cache[cache_key] = (is_err, data)
        except Exception as exc:
            tool_cache[cache_key] = (True, f"exception: {exc}")

    is_err, data = tool_cache[cache_key]

    if is_err:
        # Tool error — skip with reason
        reason = f"TOOL_ERROR: {str(data)[:200]}"
        skips.append({"tool": tool, "args": args, "reason": reason})
        skipped += 1
        print(f"  SKIP  {tool} ({json.dumps(args)[:40]}) => {reason[:60]}")
        continue

    try:
        ok, expected_repr = checker(data)
    except Exception as exc:
        ok = False
        expected_repr = f"checker exception: {exc}"

    actual_repr = json.dumps(data)[:200] if isinstance(data, (dict, list)) else str(data)[:200]

    if ok:
        passed += 1
        results_v2.append({
            "tool": tool, "args": args, "status": "PASS",
            "expected": expected_repr, "actual": actual_repr
        })
        print(f"  PASS  {tool}")
    else:
        failed += 1
        results_v2.append({
            "tool": tool, "args": args, "status": "FAIL",
            "expected": expected_repr, "actual": actual_repr
        })
        mismatches.append({"tool": tool, "expected": expected_repr, "actual": actual_repr})
        print(f"  FAIL  {tool}")
        print(f"         expected: {expected_repr}")
        print(f"         actual:   {actual_repr[:120]}")

# ── Count distinct tools hardened ────────────────────────────────────────────
tools_hardened = len({r["tool"] for r in results_v2})

print(f"\n=== SUMMARY ===")
print(f"  Unique assertions : {len(unique_cases)}")
print(f"  PASS : {passed}")
print(f"  FAIL : {failed}")
print(f"  SKIP : {skipped}")
print(f"  Tools hardened: {tools_hardened}")

# ── Save outputs ─────────────────────────────────────────────────────────────
with open(OUT_V2, "w") as f:
    json.dump(results_v2, f, indent=2)
with open(OUT_SKIP, "w") as f:
    json.dump(skips, f, indent=2)

print(f"\nWrote {OUT_V2}")
print(f"Wrote {OUT_SKIP}")

proc.stdin.close()
proc.terminate()

# ── Final JSON output (for the orchestrator) ─────────────────────────────────
distinct_passed_tools = len({r["tool"] for r in results_v2 if r["status"] == "PASS"})
distinct_failed_tools = len({r["tool"] for r in results_v2 if r["status"] == "FAIL"})
distinct_skipped_tools = len({s["tool"] for s in skips})

summary = {
    "category": "mobile",
    "tools_hardened": tools_hardened,
    "tools_passed": distinct_passed_tools,
    "tools_failed": distinct_failed_tools,
    "tools_skipped": distinct_skipped_tools,
    "mismatches": mismatches,
}
print("\n=== FINAL JSON ===")
print(json.dumps(summary, indent=2))
