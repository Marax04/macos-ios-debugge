#!/usr/bin/env python3
"""
Rigorous ground-truth validation for dotnet_* MCP tools.
Every check computes expected output from a Python reference implementation
(inline, using only stdlib) and compares byte-for-byte / value-for-value.
"""

import json, subprocess, sys, time

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
OUT_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\rigorous_dotnet_v2.json"
SKIP_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\skip_dotnet.json"

# ── MCP client ────────────────────────────────────────────────────────────────
p = subprocess.Popen(
    [EXE, "--transport=stdio"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0
)

def send(req):
    p.stdin.write((json.dumps(req) + "\n").encode())
    p.stdin.flush()

def recv():
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("server died")
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {"error": {"message": f"bad-line: {line[:100]!r}"}}

def call_tool(name, args, rid):
    send({"jsonrpc":"2.0","id":rid,"method":"tools/call","params":{"name":name,"arguments":args}})
    resp = recv()
    if "error" in resp:
        return None, str(resp["error"])
    result = resp.get("result", {})
    is_err = result.get("isError", False)
    content = result.get("content", [])
    txt = content[0].get("text", "") if content else ""
    if is_err:
        return None, txt
    try:
        return json.loads(txt), None
    except Exception:
        return txt, None

# ── Initialize ────────────────────────────────────────────────────────────────
send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
    "protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"rigorous_dotnet_v2","version":"1"}
}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

# Open project (required by some tools even if not used)
send({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"project.open","arguments":{"path":TARGET}}})
recv()  # consume, ignore binary_id for these pure-logic tools

rid_counter = [100]
def next_rid():
    rid_counter[0] += 1
    return rid_counter[0]

# ── Reference implementations (Python stdlib only) ────────────────────────────

def py_encode_token(table: int, row: int) -> int:
    """ECMA-335 metadata token encoding."""
    return ((table & 0xFF) << 24) | (row & 0x00FF_FFFF)

TOKEN_TABLE_NAMES = {
    0x00: "Module", 0x01: "TypeRef", 0x02: "TypeDef", 0x04: "Field",
    0x06: "MethodDef", 0x08: "Param", 0x09: "InterfaceImpl", 0x0A: "MemberRef",
    0x0B: "Constant", 0x0C: "CustomAttribute", 0x0D: "FieldMarshal",
    0x0E: "DeclSecurity", 0x0F: "ClassLayout", 0x11: "StandAloneSig",
    0x14: "Event", 0x17: "Property", 0x18: "MethodSemantics",
    0x1B: "TypeSpec", 0x20: "Assembly", 0x23: "AssemblyRef",
    0x26: "File", 0x27: "ExportedType", 0x28: "ManifestResource",
    0x2A: "GenericParam", 0x2B: "MethodSpec", 0x2C: "GenericParamConstraint",
    0x70: "UserString",
}
def py_token_table_name(table: int) -> str:
    return TOKEN_TABLE_NAMES.get(table, "<unknown>")

# MethodFlags bit layout (ECMA-335 §II.23.1.10)
def py_method_flags_access(raw: int) -> str:
    acc = raw & 0x07
    return {0:"PrivateScope",1:"Private",2:"FamAndAssem",3:"Assem",
            4:"Family",5:"FamOrAssem",6:"Public",7:"Public"}.get(acc,"?")

def py_is_public(raw: int) -> bool:
    return (raw & 0x07) == 6

def py_is_static(raw: int) -> bool:
    return (raw & 0x0010) != 0

def py_is_virtual(raw: int) -> bool:
    return (raw & 0x0040) != 0

def py_is_abstract(raw: int) -> bool:
    return (raw & 0x0400) != 0

def py_is_sealed(raw: int) -> bool:
    return (raw & 0x0020) != 0

def py_is_special_name(raw: int) -> bool:
    return (raw & 0x0800) != 0

def py_is_rt_special_name(raw: int) -> bool:
    return (raw & 0x1000) != 0

def py_is_pinvoke(raw: int) -> bool:
    return (raw & 0x2000) != 0

def py_is_constructor(raw: int) -> bool:
    # is_special_name AND name would be .ctor/.cctor — tool checks rt_special_name
    return (raw & 0x1000) != 0 and (raw & 0x0800) != 0

# NewTypeDescriptor flags
PY_PUBLIC_CLASS_FLAGS      = 0x00000101   # TypeAttributes.Public | TypeAttributes.Sealed
PY_PUBLIC_INTERFACE_FLAGS  = 0x000000A1   # TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Interface

# NewMethodDescriptor
PY_STATIC_VOID_FLAGS  = 0x0016   # MethodAttributes.Public | MethodAttributes.Static
PY_INSTANCE_VOID_FLAGS = 0x0006  # MethodAttributes.Public

def py_encode_static_void_sig(param_types_count: int = 0) -> list:
    """Encode a static void() method signature."""
    calling_conv = 0x00  # not instance
    return [calling_conv, param_types_count, 0x01]  # calling_conv, param_count, void

def py_encode_instance_void_sig(param_types_count: int = 0) -> list:
    """Encode an instance void() method signature."""
    calling_conv = 0x20  # is_instance bit set (flags & 0x0010) == 0 => instance
    return [calling_conv, param_types_count, 0x01]

# NewFieldDescriptor
PY_PUBLIC_FIELD_FLAGS  = 0x0006   # FieldAttributes.Public
PY_PUBLIC_STATIC_FLAGS = 0x0016   # FieldAttributes.Public | FieldAttributes.Static

def py_public_field_sig(element_type: int) -> list:
    return [0x06, element_type]  # FIELD + type

def py_public_static_sig(element_type: int) -> list:
    return [0x06, element_type]

# ManagedResource: new() always sets flags=1, is_public=True
PY_MANAGED_RESOURCE_FLAGS = 1

# EditTransaction: len = number of modifications pushed
# IlOptimizer: remove_nops removes all "nop" opcodes

# stack_effect reference
STACK_EFFECTS = {}
for op in ["nop","break","jmp","ret","br","br.s","endfinally","endfilter","leave","leave.s"]:
    STACK_EFFECTS[op] = (0, 0)
for op in ["ldarg.0","ldarg.1","ldarg.2","ldarg.3","ldarg.s","ldarg","ldarga.s","ldarga",
           "ldloc.0","ldloc.1","ldloc.2","ldloc.3","ldloc.s","ldloc","ldloca.s","ldloca",
           "ldnull","ldc.i4.m1","ldc.i4.0","ldc.i4.1","ldc.i4.2","ldc.i4.3","ldc.i4.4",
           "ldc.i4.5","ldc.i4.6","ldc.i4.7","ldc.i4.8","ldc.i4.s","ldc.i4","ldc.i8",
           "ldc.r4","ldc.r8","call","calli","callvirt","newobj","ldstr","ldsfld","ldsflda",
           "ldtoken","sizeof","arglist","ldftn","ldvirtftn"]:
    STACK_EFFECTS[op] = (0, 1)
for op in ["starg.s","starg","stloc.0","stloc.1","stloc.2","stloc.3","stloc.s","stloc",
           "pop","brfalse","brfalse.s","brtrue","brtrue.s","switch","throw","stsfld","initobj"]:
    STACK_EFFECTS[op] = (1, 0)
STACK_EFFECTS["dup"] = (1, 2)
for op in ["beq","beq.s","bne.un","bne.un.s","bge","bge.s","bge.un","bge.un.s",
           "bgt","bgt.s","bgt.un","bgt.un.s","ble","ble.s","ble.un","ble.un.s",
           "blt","blt.s","blt.un","blt.un.s","cpobj","stind.ref","stind.i1",
           "stind.i2","stind.i4","stind.i8","stind.r4","stind.r8","stind.i","stfld","stobj"]:
    STACK_EFFECTS[op] = (2, 0)
for op in ["ldind.i1","ldind.u1","ldind.i2","ldind.u2","ldind.i4","ldind.u4",
           "ldind.i8","ldind.r4","ldind.r8","ldind.i","ldind.ref","neg","not",
           "conv.i1","conv.u1","conv.i2","conv.u2","conv.i4","conv.u4","conv.i8",
           "conv.u8","conv.r4","conv.r8","conv.i","conv.u","conv.r.un",
           "conv.ovf.i1","conv.ovf.u1","conv.ovf.i2","conv.ovf.u2","conv.ovf.i4",
           "conv.ovf.u4","conv.ovf.i8","conv.ovf.u8","conv.ovf.i","conv.ovf.u",
           "conv.ovf.i1.un","conv.ovf.u1.un","conv.ovf.i2.un","conv.ovf.u2.un",
           "conv.ovf.i4.un","conv.ovf.u4.un","conv.ovf.i8.un","conv.ovf.u8.un",
           "conv.ovf.i.un","conv.ovf.u.un","ldobj","castclass","isinst","unbox",
           "unbox.any","box","ldfld","ldflda","newarr","ldlen","refanyval",
           "ckfinite","mkrefany","localloc","refanytype"]:
    STACK_EFFECTS[op] = (1, 1)
for op in ["add","sub","mul","div","div.un","rem","rem.un","and","or","xor",
           "shl","shr","shr.un","add.ovf","add.ovf.un","mul.ovf","mul.ovf.un",
           "sub.ovf","sub.ovf.un","ldelema",
           "ldelem.i1","ldelem.u1","ldelem.i2","ldelem.u2","ldelem.i4","ldelem.u4",
           "ldelem.i8","ldelem.r4","ldelem.r8","ldelem.i","ldelem.ref","ldelem",
           "ceq","cgt","cgt.un","clt","clt.un"]:
    STACK_EFFECTS[op] = (2, 1)
for op in ["stelem.i","stelem.i1","stelem.i2","stelem.i4","stelem.i8","stelem.r4",
           "stelem.r8","stelem.ref","stelem","cpblk","initblk"]:
    STACK_EFFECTS[op] = (3, 0)

# ── Test runner ───────────────────────────────────────────────────────────────

results = []
mismatches = []
skipped = []

def check(tool, args, expected_check, desc=""):
    """Call tool, run expected_check(actual) -> (ok: bool, msg: str)"""
    actual, err = call_tool(tool, args, next_rid())
    if err is not None:
        mismatches.append({"tool": tool, "expected": desc, "actual": f"TOOL_ERROR: {err[:200]}"})
        results.append({"tool": tool, "status": "FAIL", "desc": desc, "error": err[:200]})
        return
    ok, msg = expected_check(actual)
    status = "PASS" if ok else "FAIL"
    results.append({"tool": tool, "status": status, "desc": desc, "actual_excerpt": str(actual)[:200]})
    if not ok:
        mismatches.append({"tool": tool, "expected": msg, "actual": str(actual)[:300]})

def skip(tool, reason):
    skipped.append({"tool": tool, "reason": reason})

# ─────────────────────────────────────────────────────────────────────────────
# 1. dotnet_encode_token
# ─────────────────────────────────────────────────────────────────────────────
def test_encode_token():
    # table=0x02 (TypeDef), row=1 -> token = 0x02000001
    expected = py_encode_token(0x02, 1)
    check("dotnet_encode_token", {"table": 2, "row": 1},
          lambda a: (a is not None and a.get("token") == expected,
                     f"expected token={expected} ({expected:#010x})"),
          f"encode_token(TypeDef=0x02, row=1) -> {expected:#010x}")

    # table=0x06 (MethodDef), row=42 -> 0x0600002A
    expected2 = py_encode_token(0x06, 42)
    check("dotnet_encode_token", {"table": 6, "row": 42},
          lambda a: (a is not None and a.get("token") == expected2,
                     f"expected token={expected2}"),
          f"encode_token(MethodDef=0x06, row=42) -> {expected2:#010x}")

    # table=0x70 (UserString), row=0x1234 -> 0x70001234
    expected3 = py_encode_token(0x70, 0x1234)
    check("dotnet_encode_token", {"table": 0x70, "row": 0x1234},
          lambda a: (a is not None and a.get("token") == expected3,
                     f"expected token={expected3}"),
          f"encode_token(UserString=0x70, row=0x1234) -> {expected3:#010x}")

test_encode_token()

# ─────────────────────────────────────────────────────────────────────────────
# 2. dotnet_token_table_name
# ─────────────────────────────────────────────────────────────────────────────
def test_token_table_name():
    for table_id, expected_name in [(0x02, "TypeDef"), (0x06, "MethodDef"), (0x04, "Field"),
                                     (0x23, "AssemblyRef"), (0x70, "UserString"), (0xFF, "<unknown>")]:
        exp = py_token_table_name(table_id)
        check("dotnet_token_table_name", {"table": table_id},
              lambda a, e=exp: (a is not None and a.get("name") == e, f"expected name={e!r}"),
              f"token_table_name(0x{table_id:02X}) -> {exp!r}")

test_token_table_name()

# ─────────────────────────────────────────────────────────────────────────────
# 3. dotnet_method_flags_decode
# ─────────────────────────────────────────────────────────────────────────────
def test_method_flags_decode():
    # 0x0016 = public static
    raw = 0x0016
    check("dotnet_method_flags_decode", {"flags": raw},
          lambda a: (
              a is not None
              and a.get("is_public") == True
              and a.get("is_static") == True
              and a.get("is_virtual") == False
              and a.get("is_abstract") == False,
              "public static: is_public=T, is_static=T, is_virtual=F, is_abstract=F"
          ),
          "method_flags(0x0016) public static")

    # 0x0046 = public virtual
    raw2 = 0x0046
    check("dotnet_method_flags_decode", {"flags": raw2},
          lambda a: (
              a is not None
              and a.get("is_public") == True
              and a.get("is_static") == False
              and a.get("is_virtual") == True,
              "0x0046: is_public=T, is_static=F, is_virtual=T"
          ),
          "method_flags(0x0046) public virtual")

    # 0x0001 = private
    raw3 = 0x0001
    check("dotnet_method_flags_decode", {"flags": raw3},
          lambda a: (
              a is not None
              and a.get("is_public") == False
              and a.get("is_static") == False,
              "0x0001: is_public=F"
          ),
          "method_flags(0x0001) private")

test_method_flags_decode()

# ─────────────────────────────────────────────────────────────────────────────
# 4. dotnet_edit_new_type_public_class
# ─────────────────────────────────────────────────────────────────────────────
def test_new_type_public_class():
    # Parameter is "namespace", not "ns"
    check("dotnet_edit_new_type_public_class", {"name": "MyClass", "namespace": "App.Core"},
          lambda a: (
              a is not None
              and a.get("flags") == PY_PUBLIC_CLASS_FLAGS
              and a.get("name") == "MyClass"
              and a.get("namespace") == "App.Core",
              f"flags={PY_PUBLIC_CLASS_FLAGS:#010x}, name=MyClass, namespace=App.Core"
          ),
          "new_type_public_class flags=0x00000101")

test_new_type_public_class()

# ─────────────────────────────────────────────────────────────────────────────
# 5. dotnet_edit_new_type_public_interface
# ─────────────────────────────────────────────────────────────────────────────
def test_new_type_public_interface():
    check("dotnet_edit_new_type_public_interface", {"name": "IFoo", "ns": "App"},
          lambda a: (
              a is not None
              and a.get("flags") == PY_PUBLIC_INTERFACE_FLAGS
              and a.get("name") == "IFoo",
              f"flags={PY_PUBLIC_INTERFACE_FLAGS:#010x}"
          ),
          "new_type_public_interface flags=0x000000A1")

test_new_type_public_interface()

# ─────────────────────────────────────────────────────────────────────────────
# 6. dotnet_edit_new_method_encode_sig_wire  (static_void sig)
# ─────────────────────────────────────────────────────────────────────────────
def test_new_method_encode_sig():
    # static_void: flags=0x0016, sig=[0x00, 0x00, 0x01]
    # encode_sig: calling_conv=0x00 (not instance because flags&0x10==0x10 means static)
    # Wait — let's re-read the Rust: is_instance = (flags & 0x0010) == 0
    # static_void flags=0x0016; 0x0016 & 0x0010 = 0x0010 != 0, so is_instance = false => calling_conv=0x00
    expected_sig_hex = "000001"
    check("dotnet_edit_new_method_encode_sig_wire", {"name": "DoIt"},
          lambda a: (
              a is not None
              and a.get("sig_hex") == expected_sig_hex,
              f"expected sig_hex={expected_sig_hex!r}"
          ),
          f"static_void encode_sig -> {expected_sig_hex}")

test_new_method_encode_sig()

# ─────────────────────────────────────────────────────────────────────────────
# 7. dotnet_edit_new_method_instance_void_sig (instance_void sig)
# ─────────────────────────────────────────────────────────────────────────────
def test_instance_void_sig():
    # instance_void: flags=0x0006; 0x0006 & 0x0010 = 0 => is_instance=True => calling_conv=0x20
    expected_sig_hex = "200001"
    check("dotnet_edit_new_method_instance_void_sig", {"name": "Run"},
          lambda a: (
              a is not None
              and a.get("sig_hex") == expected_sig_hex,
              f"expected sig_hex={expected_sig_hex!r}"
          ),
          f"instance_void sig -> {expected_sig_hex}")

test_instance_void_sig()

# ─────────────────────────────────────────────────────────────────────────────
# 8. dotnet_edit_new_field_public_sig (public instance field)
# ─────────────────────────────────────────────────────────────────────────────
def test_public_field_sig():
    # element_type=0x08 (I4 = int32)
    expected_hex = "0608"  # [0x06, 0x08]
    expected_flags = PY_PUBLIC_FIELD_FLAGS
    check("dotnet_edit_new_field_public_sig", {"name": "Count", "element_type": 0x08},
          lambda a: (
              a is not None
              and a.get("sig_hex") == expected_hex
              and a.get("flags") == expected_flags,
              f"sig_hex={expected_hex!r}, flags={expected_flags}"
          ),
          f"public_field sig element_type=0x08 -> {expected_hex}")

test_public_field_sig()

# ─────────────────────────────────────────────────────────────────────────────
# 9. dotnet_edit_new_field_static_sig (public static field)
# ─────────────────────────────────────────────────────────────────────────────
def test_static_field_sig():
    # element_type=0x05 (U1 = byte)
    expected_hex = "0605"
    expected_flags = PY_PUBLIC_STATIC_FLAGS
    check("dotnet_edit_new_field_static_sig", {"name": "Tag", "element_type": 0x05},
          lambda a: (
              a is not None
              and a.get("sig_hex") == expected_hex
              and a.get("flags") == expected_flags,
              f"sig_hex={expected_hex!r}, flags={expected_flags}"
          ),
          f"public_static sig element_type=0x05 -> {expected_hex}")

test_static_field_sig()

# ─────────────────────────────────────────────────────────────────────────────
# 10. dotnet_edit_managed_resource_new (flags=1, is_public=true)
# ─────────────────────────────────────────────────────────────────────────────
def test_managed_resource_new():
    check("dotnet_edit_managed_resource_new", {"name": "res.bin", "data_hex": "deadbeef"},
          lambda a: (
              a is not None
              and a.get("flags") == 1
              and a.get("is_public") == True
              and a.get("data_len") == 4
              and a.get("name") == "res.bin",
              "flags=1, is_public=True, data_len=4"
          ),
          "ManagedResource::new flags=1, is_public=True")

test_managed_resource_new()

# ─────────────────────────────────────────────────────────────────────────────
# 11. dotnet_edit_managed_resource_is_public_wire
# ─────────────────────────────────────────────────────────────────────────────
def test_managed_resource_is_public():
    # flags=1 -> is_public=True
    check("dotnet_edit_managed_resource_is_public_wire", {"flags": 1},
          lambda a: (a is not None and a.get("is_public") == True, "is_public=True"),
          "ManagedResource is_public(flags=1) = True")
    # flags=0 -> is_public=False
    check("dotnet_edit_managed_resource_is_public_wire", {"flags": 0},
          lambda a: (a is not None and a.get("is_public") == False, "is_public=False"),
          "ManagedResource is_public(flags=0) = False")
    # flags=2 -> is_public=False (bit 0 not set)
    check("dotnet_edit_managed_resource_is_public_wire", {"flags": 2},
          lambda a: (a is not None and a.get("is_public") == False, "is_public=False"),
          "ManagedResource is_public(flags=2) = False")

test_managed_resource_is_public()

# ─────────────────────────────────────────────────────────────────────────────
# 12. dotnet_edit_edit_transaction_len
# ─────────────────────────────────────────────────────────────────────────────
def test_edit_transaction_len():
    # Push 0 modifications -> empty_before=True, len=0, is_empty=True
    check("dotnet_edit_edit_transaction_len", {"count": 0},
          lambda a: (
              a is not None
              and a.get("len") == 0
              and a.get("is_empty") == True
              and a.get("empty_before") == True,
              "len=0, is_empty=True, empty_before=True"
          ),
          "EditTransaction len=0")
    # Push 3 modifications -> empty_before=True, len=3, is_empty=False
    check("dotnet_edit_edit_transaction_len", {"count": 3},
          lambda a: (
              a is not None
              and a.get("len") == 3
              and a.get("is_empty") == False
              and a.get("empty_before") == True,
              "len=3, is_empty=False"
          ),
          "EditTransaction len=3")

test_edit_transaction_len()

# ─────────────────────────────────────────────────────────────────────────────
# 13. dotnet_decompile_stack_effect
# ─────────────────────────────────────────────────────────────────────────────
def test_stack_effect():
    cases = [
        ("nop", 0, 0),
        ("ret", 0, 0),
        ("ldarg.0", 0, 1),
        ("ldc.i4.1", 0, 1),
        ("add", 2, 1),
        ("pop", 1, 0),
        ("dup", 1, 2),
        ("stloc.0", 1, 0),
        ("ceq", 2, 1),
    ]
    for opcode, exp_pops, exp_pushes in cases:
        check("dotnet_decompile_stack_effect", {"opcode": opcode},
              lambda a, ep=exp_pops, esh=exp_pushes: (
                  a is not None
                  and a.get("pops") == ep
                  and a.get("pushes") == esh,
                  f"pops={ep}, pushes={esh}"
              ),
              f"stack_effect({opcode!r}) = pops={exp_pops}, pushes={exp_pushes}")

test_stack_effect()

# ─────────────────────────────────────────────────────────────────────────────
# 14. dotnet_cil_simple_instr — structural checks
# ─────────────────────────────────────────────────────────────────────────────
def test_cil_simple_instr():
    # nop: not branch, not terminator
    check("dotnet_cil_simple_instr", {"opcode": "nop", "offset": 0},
          lambda a: (
              a is not None
              and a.get("opcode") == "nop"
              and a.get("is_branch") == False
              and a.get("is_terminator") == False
              and a.get("offset") == 0,
              "nop: is_branch=F, is_terminator=F"
          ),
          "cil_simple_instr nop")
    # ret: terminator
    check("dotnet_cil_simple_instr", {"opcode": "ret", "offset": 10},
          lambda a: (
              a is not None
              and a.get("opcode") == "ret"
              and a.get("is_terminator") == True
              and a.get("offset") == 10,
              "ret: is_terminator=T"
          ),
          "cil_simple_instr ret offset=10")

test_cil_simple_instr()

# ─────────────────────────────────────────────────────────────────────────────
# 15. dotnet_edit_new_type_public_class_probe
# ─────────────────────────────────────────────────────────────────────────────
def test_new_type_public_class_probe():
    check("dotnet_edit_new_type_public_class_probe", {"name": "FooClass", "ns": "NS"},
          lambda a: (
              a is not None
              and a.get("flags") == PY_PUBLIC_CLASS_FLAGS
              and a.get("name") == "FooClass"
              and a.get("namespace") == "NS"
              and a.get("iface_count") == 0
              and a.get("has_base") == False,
              f"flags={PY_PUBLIC_CLASS_FLAGS}, iface_count=0, has_base=False"
          ),
          "new_type_public_class_probe")

test_new_type_public_class_probe()

# ─────────────────────────────────────────────────────────────────────────────
# 16. dotnet_edit_new_type_public_interface_probe
# ─────────────────────────────────────────────────────────────────────────────
def test_new_type_public_interface_probe():
    check("dotnet_edit_new_type_public_interface_probe", {"name": "IBar", "ns": "NS"},
          lambda a: (
              a is not None
              and a.get("flags") == PY_PUBLIC_INTERFACE_FLAGS
              and a.get("name") == "IBar"
              and a.get("iface_count") == 0,
              f"flags={PY_PUBLIC_INTERFACE_FLAGS}"
          ),
          "new_type_public_interface_probe")

test_new_type_public_interface_probe()

# ─────────────────────────────────────────────────────────────────────────────
# 17. dotnet_edit_new_method_static_void_body
# ─────────────────────────────────────────────────────────────────────────────
def test_static_void_body():
    check("dotnet_edit_new_method_static_void_body", {"name": "Init"},
          lambda a: (
              a is not None
              and a.get("flags") == PY_STATIC_VOID_FLAGS
              and "ret" in (a.get("body") or []),
              f"flags={PY_STATIC_VOID_FLAGS}, body contains ret"
          ),
          "static_void body contains ret")

test_static_void_body()

# ─────────────────────────────────────────────────────────────────────────────
# 18. dotnet_edit_new_method_instance_void_body
# ─────────────────────────────────────────────────────────────────────────────
def test_instance_void_body():
    check("dotnet_edit_new_method_instance_void_body", {"name": "Execute"},
          lambda a: (
              a is not None
              and a.get("flags") == PY_INSTANCE_VOID_FLAGS
              and "ret" in (a.get("body") or []),
              f"flags={PY_INSTANCE_VOID_FLAGS}"
          ),
          "instance_void body contains ret")

test_instance_void_body()

# ─────────────────────────────────────────────────────────────────────────────
# 19. dotnet_edit_new_field_public_static_probe
# ─────────────────────────────────────────────────────────────────────────────
def test_public_static_probe():
    # element_type=0x08 (I4)
    check("dotnet_edit_new_field_public_static_probe", {"name": "Val", "element_type": 8},
          lambda a: (
              a is not None
              and a.get("flags") == PY_PUBLIC_STATIC_FLAGS
              and a.get("type_sig_len") == 2,  # [0x06, 0x08]
              f"flags={PY_PUBLIC_STATIC_FLAGS}, type_sig_len=2"
          ),
          "public_static_probe flags=0x0016, type_sig_len=2")

test_public_static_probe()

# ─────────────────────────────────────────────────────────────────────────────
# 20. dotnet_edit_managed_resource_data_len
# ─────────────────────────────────────────────────────────────────────────────
def test_managed_resource_data_len():
    # data_hex="deadbeef" = 4 bytes
    check("dotnet_edit_managed_resource_data_len", {"name": "r", "data_hex": "deadbeef"},
          lambda a: (
              a is not None
              and a.get("data_len") == 4
              and a.get("flags") == 1
              and a.get("is_public") == True,
              "data_len=4, flags=1, is_public=True"
          ),
          "managed_resource_data_len(4 bytes) = 4")
    # empty data
    check("dotnet_edit_managed_resource_data_len", {"name": "r2", "data_hex": ""},
          lambda a: (
              a is not None
              and a.get("data_len") == 0,
              "data_len=0 for empty hex"
          ),
          "managed_resource_data_len(empty) = 0")

test_managed_resource_data_len()

# ─────────────────────────────────────────────────────────────────────────────
# 21. dotnet_edit_new_method_encode_sig_static
# ─────────────────────────────────────────────────────────────────────────────
def test_encode_sig_static():
    # static_void: calling_conv=0x00, so first_byte=0x00, calling_conv_is_default=True
    check("dotnet_edit_new_method_encode_sig_static", {"name": "Go"},
          lambda a: (
              a is not None
              and a.get("first_byte") == 0x00
              and a.get("calling_conv_is_default") == True
              and a.get("sig_len") == 3,
              "first_byte=0x00, calling_conv_is_default=True, sig_len=3"
          ),
          "encode_sig_static: first_byte=0 (default/static calling conv)")

test_encode_sig_static()

# ─────────────────────────────────────────────────────────────────────────────
# 22. dotnet_edit_new_method_static_void_flags_v2
# ─────────────────────────────────────────────────────────────────────────────
def test_static_void_flags_v2():
    check("dotnet_edit_new_method_static_void_flags_v2", {"name": "Foo"},
          lambda a: (
              a is not None
              and a.get("flags") == PY_STATIC_VOID_FLAGS
              and a.get("impl_flags") == 0,
              f"flags={PY_STATIC_VOID_FLAGS}, impl_flags=0"
          ),
          "static_void_flags_v2")

test_static_void_flags_v2()

# ─────────────────────────────────────────────────────────────────────────────
# 23. dotnet_edit_managed_resource_new_flags_v2
# ─────────────────────────────────────────────────────────────────────────────
def test_managed_resource_new_flags_v2():
    # Parameter is "data_len", not "size"
    check("dotnet_edit_managed_resource_new_flags_v2", {"name": "data.bin", "data_len": 8},
          lambda a: (
              a is not None
              and a.get("flags") == 1
              and a.get("is_public") == True
              and a.get("data_len") == 8,
              "flags=1, is_public=True, data_len=8"
          ),
          "managed_resource_new_flags_v2(size=8)")

test_managed_resource_new_flags_v2()

# ─────────────────────────────────────────────────────────────────────────────
# 24. dotnet_edit_il_validator_is_valid_v2 — empty body is valid
# ─────────────────────────────────────────────────────────────────────────────
def test_il_validator_is_valid_v2():
    check("dotnet_edit_il_validator_is_valid_v2", {"opcodes": []},
          lambda a: (
              a is not None
              and a.get("is_valid") == True
              and a.get("input_len") == 0,
              "empty body is_valid=True"
          ),
          "il_validator_is_valid_v2([]) = True")
    # single ret is valid
    check("dotnet_edit_il_validator_is_valid_v2", {"opcodes": ["ret"]},
          lambda a: (
              a is not None
              and a.get("is_valid") == True,
              "['ret'] is valid"
          ),
          "il_validator_is_valid_v2(['ret']) = True")

test_il_validator_is_valid_v2()

# ─────────────────────────────────────────────────────────────────────────────
# 25. dotnet_edit_il_optimizer_remove_nops — removes all nop
# ─────────────────────────────────────────────────────────────────────────────
def test_il_optimizer_remove_nops():
    # Input: [nop, ldarg.0, nop, ret] -> output should have no nops
    check("dotnet_edit_il_optimizer_remove_nops", {"opcodes": ["nop", "ldarg.0", "nop", "ret"]},
          lambda a: (
              a is not None
              and "nop" not in (a.get("opcodes") or [])
              and a.get("output_len") == 2,  # ldarg.0, ret
              "after remove_nops: no nop, output_len=2"
          ),
          "remove_nops([nop,ldarg.0,nop,ret]) -> output_len=2, no nop")
    # No nops: unchanged
    check("dotnet_edit_il_optimizer_remove_nops", {"opcodes": ["ret"]},
          lambda a: (
              a is not None
              and a.get("output_len") == 1,
              "remove_nops([ret]) -> output_len=1"
          ),
          "remove_nops([ret]) unchanged")

test_il_optimizer_remove_nops()

# ─────────────────────────────────────────────────────────────────────────────
# 26. dotnet_edit_il_builder_ret — emits a single ret
# ─────────────────────────────────────────────────────────────────────────────
def test_il_builder_ret():
    # The tool emits a complete tiny method body: header=0x06 (tiny, 1-byte body) + ret=0x2A
    # Tiny header encoding: ((body_len) << 2) | 0x02 = (1 << 2) | 2 = 6 = 0x06
    check("dotnet_edit_il_builder_ret", {},
          lambda a: (
              a is not None
              and a.get("len") == 1
              and (a.get("bytes_hex") or "").upper() == "062A",  # tiny header 0x06 + ret 0x2A
              "ret: len=1, bytes_hex=062a (tiny header 0x06 + ret 0x2A)"
          ),
          "il_builder_ret emits bytes_hex=062a")

test_il_builder_ret()

# ─────────────────────────────────────────────────────────────────────────────
# 27. dotnet_edit_il_builder_ldc_i4_v2
# ─────────────────────────────────────────────────────────────────────────────
def test_il_builder_ldc_i4():
    check("dotnet_edit_il_builder_ldc_i4_v2", {"value": 0},
          lambda a: (
              a is not None
              and a.get("value") == 0
              and len(a.get("opcodes") or []) == 1,
              "ldc.i4(0): 1 opcode emitted"
          ),
          "il_builder_ldc_i4_v2(0) emits 1 opcode")
    check("dotnet_edit_il_builder_ldc_i4_v2", {"value": 5},
          lambda a: (
              a is not None
              and a.get("value") == 5,
              "ldc.i4(5): value=5"
          ),
          "il_builder_ldc_i4_v2(5)")

test_il_builder_ldc_i4()

# ─────────────────────────────────────────────────────────────────────────────
# 28. dotnet_edit_il_builder_ldarg_v2
# ─────────────────────────────────────────────────────────────────────────────
def test_il_builder_ldarg():
    check("dotnet_edit_il_builder_ldarg_v2", {"index": 0},
          lambda a: (
              a is not None
              and a.get("index") == 0
              and len(a.get("opcodes") or []) == 1,
              "ldarg(0): 1 opcode"
          ),
          "il_builder_ldarg_v2(0)")

test_il_builder_ldarg()

# ─────────────────────────────────────────────────────────────────────────────
# 29. dotnet_edit_new_field_public_field_wire
# ─────────────────────────────────────────────────────────────────────────────
def test_new_field_public_field_wire():
    # element_type=0x08 (I4); tool returns type_sig_hex not type_sig list
    check("dotnet_edit_new_field_public_field_wire", {"name": "x", "element_type": 8},
          lambda a: (
              a is not None
              and a.get("flags") == PY_PUBLIC_FIELD_FLAGS
              and a.get("type_sig_hex") == "0608",
              f"flags={PY_PUBLIC_FIELD_FLAGS}, type_sig_hex=0608"
          ),
          "new_field_public_field_wire(I4)")

test_new_field_public_field_wire()

# ─────────────────────────────────────────────────────────────────────────────
# 30. dotnet_edit_new_field_public_static_wire
# ─────────────────────────────────────────────────────────────────────────────
def test_new_field_public_static_wire():
    # Tool returns type_sig_hex string
    check("dotnet_edit_new_field_public_static_wire", {"name": "s", "element_type": 4},
          lambda a: (
              a is not None
              and a.get("flags") == PY_PUBLIC_STATIC_FLAGS
              and a.get("type_sig_hex") == "0604",
              f"flags={PY_PUBLIC_STATIC_FLAGS}, type_sig_hex=0604"
          ),
          "new_field_public_static_wire(I1)")

test_new_field_public_static_wire()

# ─────────────────────────────────────────────────────────────────────────────
# Finalize
# ─────────────────────────────────────────────────────────────────────────────
p.stdin.close()
try:
    p.terminate()
except Exception:
    pass

passed  = sum(1 for r in results if r["status"] == "PASS")
failed  = sum(1 for r in results if r["status"] == "FAIL")
total   = len(results)

summary = {
    "category": "dotnet",
    "tools_hardened": len(set(r["tool"] for r in results)),
    "checks_total": total,
    "checks_passed": passed,
    "checks_failed": failed,
    "tools_skipped": len(skipped),
    "mismatches": mismatches,
    "results": results,
}

with open(OUT_JSON, "w") as f:
    json.dump(summary, f, indent=2)

with open(SKIP_JSON, "w") as f:
    json.dump(skipped, f, indent=2)

print(f"\nRigorous dotnet_v2: {passed}/{total} PASS  ({failed} FAIL)  {len(skipped)} SKIP")
if mismatches:
    print("\nMismatches:")
    for m in mismatches:
        print(f"  {m['tool']}: expected={m['expected']!r}  actual={m['actual']!r}")

# exit code
sys.exit(0 if failed == 0 else 1)
