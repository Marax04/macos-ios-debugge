"""
rustre-loader-java — Python validator reproducing the documented API.

Stdlib only (struct, hashlib, json, re, zipfile, io, collections).
Each public Rust function in the report has a Python equivalent with matching
input/output types (best-effort, using dicts/lists/tuples where Rust uses
structs/Vec/HashMap).
"""

from __future__ import annotations

import io
import json
import re
import struct
import zipfile
from collections import defaultdict
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Constants / opcodes
# ---------------------------------------------------------------------------

CAFEBABE = b"\xCA\xFE\xBA\xBE"

CP_UTF8 = 1
CP_INTEGER = 3
CP_FLOAT = 4
CP_LONG = 5
CP_DOUBLE = 6
CP_CLASS = 7
CP_STRING = 8
CP_FIELDREF = 9
CP_METHODREF = 10
CP_INTERFACE_METHODREF = 11
CP_NAME_AND_TYPE = 12
CP_METHOD_HANDLE = 15
CP_METHOD_TYPE = 16
CP_DYNAMIC = 17
CP_INVOKE_DYNAMIC = 18
CP_MODULE = 19
CP_PACKAGE = 20

# Subset of opcodes sufficient for the validator semantics.
OPCODES: Dict[int, Tuple[str, int]] = {
    0x00: ("nop", 1), 0x01: ("aconst_null", 1),
    0x10: ("bipush", 2), 0x11: ("sipush", 3),
    0x12: ("ldc", 2), 0x13: ("ldc_w", 3), 0x14: ("ldc2_w", 3),
    0x15: ("iload", 2), 0x19: ("aload", 2),
    0x36: ("istore", 2), 0x3A: ("astore", 2),
    0xB2: ("getstatic", 3), 0xB3: ("putstatic", 3),
    0xB4: ("getfield", 3), 0xB5: ("putfield", 3),
    0xB6: ("invokevirtual", 3), 0xB7: ("invokespecial", 3),
    0xB8: ("invokestatic", 3), 0xB9: ("invokeinterface", 5),
    0xBA: ("invokedynamic", 5),
    0xBB: ("new", 3), 0xC0: ("checkcast", 3), 0xC1: ("instanceof", 3),
    0x99: ("ifeq", 3), 0x9A: ("ifne", 3), 0xA7: ("goto", 3),
    0xAC: ("ireturn", 1), 0xB0: ("areturn", 1), 0xB1: ("return", 1),
    0xA8: ("jsr", 3), 0xA9: ("ret", 2),
    0xC4: ("wide", 0),  # variable
    0xAA: ("tableswitch", 0), 0xAB: ("lookupswitch", 0),
}

BRANCH_OPCODES = {0x99, 0x9A, 0xA7, 0xA8,
                  0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
                  0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6}


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class JavaLoaderError(Exception): pass
class ClassParseError(Exception): pass
class ParseError(Exception): pass
class DescriptorError(Exception): pass
class BytecodeError(Exception): pass
class JarError(Exception): pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _u1(d: bytes, o: int) -> int: return d[o]
def _u2(d: bytes, o: int) -> int: return struct.unpack(">H", d[o:o+2])[0]
def _u4(d: bytes, o: int) -> int: return struct.unpack(">I", d[o:o+4])[0]
def _i4(d: bytes, o: int) -> int: return struct.unpack(">i", d[o:o+4])[0]


# ---------------------------------------------------------------------------
# Constant pool parsing
# ---------------------------------------------------------------------------

def _parse_cp(data: bytes, start: int, count: int) -> Tuple[List[Optional[dict]], int]:
    """Returns (cp_entries with 1-based indices, offset after CP).
    cp[0] is None; long/double take two slots."""
    cp: List[Optional[dict]] = [None]
    o = start
    i = 1
    while i < count:
        if o >= len(data):
            raise ClassParseError("truncated constant pool")
        tag = data[o]; o += 1
        if tag == CP_UTF8:
            ln = _u2(data, o); o += 2
            s = data[o:o+ln].decode("utf-8", errors="replace"); o += ln
            cp.append({"tag": tag, "value": s})
        elif tag == CP_INTEGER:
            v = _i4(data, o); o += 4
            cp.append({"tag": tag, "value": v})
        elif tag == CP_FLOAT:
            v = struct.unpack(">f", data[o:o+4])[0]; o += 4
            cp.append({"tag": tag, "value": v})
        elif tag == CP_LONG:
            v = struct.unpack(">q", data[o:o+8])[0]; o += 8
            cp.append({"tag": tag, "value": v}); cp.append(None); i += 1
        elif tag == CP_DOUBLE:
            v = struct.unpack(">d", data[o:o+8])[0]; o += 8
            cp.append({"tag": tag, "value": v}); cp.append(None); i += 1
        elif tag in (CP_CLASS, CP_STRING, CP_METHOD_TYPE, CP_MODULE, CP_PACKAGE):
            idx = _u2(data, o); o += 2
            cp.append({"tag": tag, "name_index": idx})
        elif tag in (CP_FIELDREF, CP_METHODREF, CP_INTERFACE_METHODREF):
            ci = _u2(data, o); nti = _u2(data, o+2); o += 4
            cp.append({"tag": tag, "class_index": ci, "name_and_type_index": nti})
        elif tag == CP_NAME_AND_TYPE:
            ni = _u2(data, o); di = _u2(data, o+2); o += 4
            cp.append({"tag": tag, "name_index": ni, "descriptor_index": di})
        elif tag == CP_METHOD_HANDLE:
            kind = data[o]; ref = _u2(data, o+1); o += 3
            cp.append({"tag": tag, "kind": kind, "reference_index": ref})
        elif tag in (CP_DYNAMIC, CP_INVOKE_DYNAMIC):
            bsm = _u2(data, o); nti = _u2(data, o+2); o += 4
            cp.append({"tag": tag, "bootstrap_method_attr_index": bsm,
                       "name_and_type_index": nti})
        else:
            raise ClassParseError(f"unknown CP tag {tag}")
        i += 1
    return cp, o


def _cp_utf8(cp: List[Optional[dict]], idx: int) -> Optional[str]:
    if idx <= 0 or idx >= len(cp): return None
    e = cp[idx]
    if e is None or e.get("tag") != CP_UTF8: return None
    return e["value"]


def _cp_class_name(cp: List[Optional[dict]], idx: int) -> Optional[str]:
    if idx <= 0 or idx >= len(cp): return None
    e = cp[idx]
    if e is None or e.get("tag") != CP_CLASS: return None
    return _cp_utf8(cp, e["name_index"])


# ---------------------------------------------------------------------------
# Core class parsing
# ---------------------------------------------------------------------------

def _parse_class(data: bytes) -> dict:
    if len(data) < 10 or data[:4] != CAFEBABE:
        raise ClassParseError("bad magic")
    minor = _u2(data, 4); major = _u2(data, 6)
    cp_count = _u2(data, 8)
    cp, o = _parse_cp(data, 10, cp_count)
    access = _u2(data, o); o += 2
    this_c = _u2(data, o); o += 2
    super_c = _u2(data, o); o += 2
    ic = _u2(data, o); o += 2
    interfaces = [_u2(data, o + 2*k) for k in range(ic)]
    o += 2*ic

    def _attrs(off: int) -> Tuple[List[dict], int]:
        n = _u2(data, off); off += 2
        out = []
        for _ in range(n):
            name_i = _u2(data, off); ln = _u4(data, off+2); off += 6
            out.append({"name_index": name_i, "info": data[off:off+ln]})
            off += ln
        return out, off

    def _members(off: int) -> Tuple[List[dict], int]:
        n = _u2(data, off); off += 2
        out = []
        for _ in range(n):
            ac = _u2(data, off); ni = _u2(data, off+2); di = _u2(data, off+4); off += 6
            attrs, off = _attrs(off)
            out.append({"access_flags": ac, "name_index": ni,
                        "descriptor_index": di, "attributes": attrs})
        return out, off

    fields, o = _members(o)
    methods, o = _members(o)
    attrs, o = _attrs(o)

    return {
        "minor_version": minor, "major_version": major,
        "constant_pool": cp,
        "access_flags": access,
        "this_class": this_c, "super_class": super_c,
        "interfaces": interfaces,
        "fields": fields, "methods": methods,
        "attributes": attrs,
        "raw": data,
    }


# ---------------------------------------------------------------------------
# Public API — lib.rs equivalents
# ---------------------------------------------------------------------------

def is_class(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] == CAFEBABE


def is_jar(data: bytes) -> bool:
    if not data.startswith(b"PK"):
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            return any(n.endswith(".class") for n in z.namelist())
    except zipfile.BadZipFile:
        return False


class JavaClass:
    def __init__(self, parsed: dict): self._p = parsed

    @classmethod
    def parse(cls, data: bytes) -> "JavaClass":
        return cls(_parse_class(data))

    def string_literals(self) -> List[str]:
        return [e["value"] for e in self._p["constant_pool"] if e and e.get("tag") == CP_UTF8]

    def method_calls(self) -> List[str]:
        out = []
        cp = self._p["constant_pool"]
        for e in cp:
            if e and e.get("tag") in (CP_METHODREF, CP_INTERFACE_METHODREF):
                cn = _cp_class_name(cp, e["class_index"]) or "?"
                nt = cp[e["name_and_type_index"]]
                nm = _cp_utf8(cp, nt["name_index"]) or "?"
                desc = _cp_utf8(cp, nt["descriptor_index"]) or "?"
                out.append(f"{cn}.{nm}{desc}")
        return out

    def uses_reflection(self) -> bool:
        return any("java/lang/reflect" in s for s in self.string_literals())

    def uses_crypto(self) -> bool:
        return any(("javax/crypto" in s) or ("java/security" in s) for s in self.string_literals())

    def obfuscation_score(self) -> float:
        names = self.string_literals()
        if not names: return 0.0
        short = sum(1 for s in names if 0 < len(s) <= 2)
        nonascii = sum(1 for s in names if any(ord(c) > 127 for c in s))
        return min(1.0, (short + nonascii) / max(1, len(names)))

    def is_obfuscated(self) -> bool:
        return self.obfuscation_score() > 0.4


# ---------------------------------------------------------------------------
# JVM disassembler
# ---------------------------------------------------------------------------

def instruction_width(code: bytes, pc: int) -> int:
    if pc >= len(code): return 0
    op = code[pc]
    if op == 0xC4:  # wide
        if pc+1 < len(code) and code[pc+1] == 0x84: return 6  # iinc
        return 4
    if op == 0xAA:  # tableswitch
        pad = (4 - ((pc + 1) % 4)) % 4
        base = pc + 1 + pad
        if base + 12 > len(code): return len(code) - pc
        low = _i4(code, base+4); high = _i4(code, base+8)
        n = high - low + 1
        return (base + 12 + n*4) - pc
    if op == 0xAB:  # lookupswitch
        pad = (4 - ((pc + 1) % 4)) % 4
        base = pc + 1 + pad
        if base + 8 > len(code): return len(code) - pc
        n = _i4(code, base+4)
        return (base + 8 + n*8) - pc
    name_w = OPCODES.get(op)
    if name_w: return name_w[1] or 1
    return 1


def decode_at(code: bytes, pc: int) -> Optional[dict]:
    if pc >= len(code): return None
    op = code[pc]
    w = instruction_width(code, pc)
    name, _ = OPCODES.get(op, (f"op_{op:02x}", w))
    operand_cp = None
    branch = None
    if op in (0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xBB, 0xC0, 0xC1,
              0x13, 0x14):
        if pc+2 < len(code):
            operand_cp = _u2(code, pc+1)
    if op == 0x12 and pc+1 < len(code):  # ldc
        operand_cp = code[pc+1]
    if op == 0xB9 and pc+2 < len(code):
        operand_cp = _u2(code, pc+1)
    if op == 0xBA and pc+2 < len(code):
        operand_cp = _u2(code, pc+1)
    if op in BRANCH_OPCODES and pc+2 < len(code):
        off = struct.unpack(">h", code[pc+1:pc+3])[0]
        branch = pc + off
    return {"pc": pc, "opcode": op, "mnemonic": name, "width": w,
            "cp_index": operand_cp, "branch_target": branch}


def disassemble(bytecode: bytes) -> List[dict]:
    out = []
    pc = 0
    while pc < len(bytecode):
        ins = decode_at(bytecode, pc)
        if ins is None: break
        out.append(ins)
        pc += max(1, ins["width"])
    return out


def build_pc_map(instrs: List[dict]) -> Dict[int, int]:
    return {ins["pc"]: i for i, ins in enumerate(instrs)}


class JvmInstruction(dict):
    @staticmethod
    def cp_index(self) -> Optional[int]:
        return self.get("cp_index") if isinstance(self, dict) else None


class JvmDisassembler:
    def disassemble(self, code: bytes) -> List[dict]:
        return disassemble(code)


# ---------------------------------------------------------------------------
# Type system
# ---------------------------------------------------------------------------

_PRIMITIVE = {"B": "byte", "C": "char", "D": "double", "F": "float",
              "I": "int", "J": "long", "S": "short", "Z": "boolean", "V": "void"}


def _parse_type_at(desc: str, i: int) -> Tuple[Optional[dict], int]:
    if i >= len(desc): return None, i
    c = desc[i]
    if c in _PRIMITIVE:
        return {"kind": "primitive", "name": _PRIMITIVE[c], "desc": c}, i+1
    if c == "[":
        inner, j = _parse_type_at(desc, i+1)
        if inner is None: return None, i
        return {"kind": "array", "element": inner,
                "desc": "[" + inner["desc"]}, j
    if c == "L":
        end = desc.find(";", i+1)
        if end == -1: return None, i
        name = desc[i+1:end]
        return {"kind": "ref", "name": name, "desc": f"L{name};"}, end+1
    return None, i


class JavaTypeParser:
    def parse_field(self, desc: str) -> Optional[dict]:
        t, j = _parse_type_at(desc, 0)
        if t is None or j != len(desc): return None
        return t

    def parse_method(self, desc: str) -> Optional[Tuple[List[dict], dict]]:
        if not desc.startswith("("): return None
        end = desc.find(")")
        if end == -1: return None
        params: List[dict] = []
        i = 1
        while i < end:
            t, i = _parse_type_at(desc, i)
            if t is None: return None
            params.append(t)
        ret, j = _parse_type_at(desc, end+1)
        if ret is None or j != len(desc): return None
        return params, ret


def java_type_simple_name(t: dict) -> str:
    if t["kind"] == "primitive": return t["name"]
    if t["kind"] == "array": return java_type_simple_name(t["element"]) + "[]"
    return t["name"].rsplit("/", 1)[-1]


def java_type_to_descriptor(t: dict) -> str:
    return t["desc"]


class FieldDescriptor(dict):
    def to_descriptor(self) -> str: return self["desc"]


class MethodDescriptor(dict):
    def to_descriptor(self) -> str:
        return "(" + "".join(p["desc"] for p in self["params"]) + ")" + self["ret"]["desc"]

    def param_slots(self) -> int:
        n = 0
        for p in self["params"]:
            n += 2 if p["desc"] in ("J", "D") else 1
        return n


class DescriptorParser:
    @staticmethod
    def parse_field(desc: str) -> FieldDescriptor:
        p = JavaTypeParser().parse_field(desc)
        if p is None: raise DescriptorError(desc)
        return FieldDescriptor(p)

    @staticmethod
    def parse_method(desc: str) -> MethodDescriptor:
        p = JavaTypeParser().parse_method(desc)
        if p is None: raise DescriptorError(desc)
        return MethodDescriptor({"params": p[0], "ret": p[1]})


class TypeRegistry:
    def __init__(self):
        self.classes: Dict[str, dict] = {}

    def add_class(self, name: str, super_name: Optional[str] = None,
                  interfaces: Optional[List[str]] = None) -> None:
        self.classes[name] = {"super": super_name,
                              "interfaces": list(interfaces or [])}

    def ancestors(self, class_name: str) -> List[str]:
        out: List[str] = []
        cur = class_name
        seen: Set[str] = set()
        while cur in self.classes and cur not in seen:
            seen.add(cur)
            sup = self.classes[cur]["super"]
            if not sup: break
            out.append(sup)
            cur = sup
        return out

    def is_subclass_of(self, child: str, ancestor: str) -> bool:
        return ancestor in self.ancestors(child)

    def implements(self, class_name: str, iface: str) -> bool:
        for c in [class_name] + self.ancestors(class_name):
            if c in self.classes and iface in self.classes[c]["interfaces"]:
                return True
        return False

    def common_ancestor(self, a: str, b: str) -> Optional[str]:
        anc_a = set([a] + self.ancestors(a))
        chain_b = [b] + self.ancestors(b)
        for c in chain_b:
            if c in anc_a: return c
        return None

    def direct_subclasses(self, parent: str) -> List[str]:
        return [n for n, info in self.classes.items() if info["super"] == parent]


# ---------------------------------------------------------------------------
# Manifest parser
# ---------------------------------------------------------------------------

class ManifestSection(dict):
    @classmethod
    def new(cls) -> "ManifestSection":
        return cls({"name": None, "attrs": {}})

    @classmethod
    def named(cls, name: str) -> "ManifestSection":
        return cls({"name": name, "attrs": {}})

    def get(self, key: str) -> Optional[str]:
        return self["attrs"].get(key)

    def insert(self, key: str, value: str) -> None:
        self["attrs"][key] = value


class Manifest(dict):
    @classmethod
    def new(cls) -> "Manifest":
        return cls({"main": ManifestSection.new(), "sections": []})

    def get_main_class(self) -> Optional[str]:
        return self["main"].get("Main-Class")

    def main_class(self) -> Optional[str]:
        return self.get_main_class()

    def get_class_path(self) -> List[str]:
        cp = self["main"].get("Class-Path")
        return cp.split() if cp else []

    def get_sealed(self) -> bool:
        return (self["main"].get("Sealed") or "").lower() == "true"

    def manifest_version(self) -> Optional[str]:
        return self["main"].get("Manifest-Version")

    def implementation_version(self) -> Optional[str]:
        return self["main"].get("Implementation-Version")


class SignatureBundle(dict):
    @classmethod
    def stub(cls, subject: str) -> "SignatureBundle":
        return cls({"subject": subject, "signers": [], "verified": False})


def _parse_manifest_text(text: str) -> Manifest:
    # Unfold continuation lines (line starting with space).
    lines = text.replace("\r\n", "\n").split("\n")
    unfolded: List[str] = []
    for line in lines:
        if line.startswith(" ") and unfolded:
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)
    sections: List[List[str]] = [[]]
    for line in unfolded:
        if line == "":
            if sections[-1]:
                sections.append([])
        else:
            sections[-1].append(line)
    if not sections[-1]:
        sections.pop()
    m = Manifest.new()
    for i, sec in enumerate(sections):
        target = m["main"] if i == 0 else ManifestSection.new()
        for line in sec:
            if ":" not in line: continue
            k, v = line.split(":", 1)
            target.insert(k.strip(), v.strip())
        if i > 0:
            target["name"] = target.get("Name")
            m["sections"].append(target)
    return m


class ManifestParser:
    def parse_manifest(self, data: bytes) -> Manifest:
        return _parse_manifest_text(data.decode("utf-8", errors="replace"))

    def parse_manifest_str(self, text: str) -> Manifest:
        return _parse_manifest_text(text)

    def verify_signature_file(self, sf_data: bytes) -> List[dict]:
        m = self.parse_manifest(sf_data)
        return [{"name": s["name"], "attrs": s["attrs"]} for s in m["sections"]]

    def parse_meta_inf(self, files: Dict[str, bytes]) -> dict:
        out: Dict[str, Any] = {"manifest": None, "sf": [], "signatures": []}
        for name, data in files.items():
            up = name.upper()
            if up.endswith("MANIFEST.MF"):
                out["manifest"] = self.parse_manifest(data)
            elif up.endswith(".SF"):
                out["sf"].append({"name": name,
                                  "entries": self.verify_signature_file(data)})
            elif up.endswith(".RSA") or up.endswith(".DSA") or up.endswith(".EC"):
                out["signatures"].append(name)
        return out

    def analyse(self, files: Dict[str, bytes]) -> dict:
        info = self.parse_meta_inf(files)
        signed = bool(info["sf"]) and bool(info["signatures"])
        main_class = info["manifest"].get_main_class() if info["manifest"] else None
        return {"signed": signed, "main_class": main_class, "info": info}

    def extract_entries(self, manifest: Manifest) -> List[dict]:
        return [{"name": s["name"], "attrs": s["attrs"]} for s in manifest["sections"]]


# ---------------------------------------------------------------------------
# Attribute / Bytecode helpers (class_file_parser, bytecode_analyzer ...)
# ---------------------------------------------------------------------------

def _find_attr(attrs: List[dict], cp: List[Optional[dict]], name: str) -> Optional[bytes]:
    for a in attrs:
        if _cp_utf8(cp, a["name_index"]) == name:
            return a["info"]
    return None


def _parse_code_attribute(data: bytes) -> dict:
    if len(data) < 8: raise ClassParseError("code too short")
    max_stack = _u2(data, 0); max_locals = _u2(data, 2)
    code_len = _u4(data, 4)
    code = data[8:8+code_len]
    o = 8 + code_len
    et_len = _u2(data, o); o += 2
    exc = []
    for _ in range(et_len):
        exc.append({"start_pc": _u2(data, o), "end_pc": _u2(data, o+2),
                    "handler_pc": _u2(data, o+4), "catch_type": _u2(data, o+6)})
        o += 8
    attrs_n = _u2(data, o); o += 2
    sub_attrs = []
    for _ in range(attrs_n):
        ni = _u2(data, o); ln = _u4(data, o+2); o += 6
        sub_attrs.append({"name_index": ni, "info": data[o:o+ln]})
        o += ln
    return {"max_stack": max_stack, "max_locals": max_locals,
            "code": code, "exception_table": exc, "attributes": sub_attrs}


class AttributeParser:
    @staticmethod
    def parse_code_attribute(data: bytes, cp: List[Optional[dict]]) -> dict:
        return _parse_code_attribute(data)

    @staticmethod
    def parse_exceptions_attribute(data: bytes, cp: List[Optional[dict]]) -> List[str]:
        n = _u2(data, 0)
        out = []
        for k in range(n):
            ci = _u2(data, 2 + 2*k)
            nm = _cp_class_name(cp, ci)
            if nm: out.append(nm)
        return out

    @staticmethod
    def parse_inner_classes(data: bytes, cp: List[Optional[dict]]) -> List[dict]:
        n = _u2(data, 0)
        out = []
        for k in range(n):
            o = 2 + 8*k
            inner_ci = _u2(data, o); outer_ci = _u2(data, o+2)
            name_i = _u2(data, o+4); flags = _u2(data, o+6)
            out.append({
                "inner_class": _cp_class_name(cp, inner_ci),
                "outer_class": _cp_class_name(cp, outer_ci),
                "inner_name": _cp_utf8(cp, name_i),
                "access_flags": flags,
            })
        return out

    @staticmethod
    def parse_signature_attribute(data: bytes, cp: List[Optional[dict]]) -> str:
        idx = _u2(data, 0)
        s = _cp_utf8(cp, idx)
        if s is None: raise ClassParseError("bad signature")
        return s


class BytecodeScanner:
    @staticmethod
    def find_string_usage(code_attr: dict, cp: List[Optional[dict]]) -> List[dict]:
        out = []
        for ins in disassemble(code_attr["code"]):
            if ins["opcode"] in (0x12, 0x13) and ins["cp_index"] is not None:
                e = cp[ins["cp_index"]] if 0 < ins["cp_index"] < len(cp) else None
                if e and e.get("tag") == CP_STRING:
                    s = _cp_utf8(cp, e["name_index"])
                    if s is not None:
                        out.append({"pc": ins["pc"], "value": s})
        return out

    @staticmethod
    def find_method_calls(code_attr: dict, cp: List[Optional[dict]]) -> List[dict]:
        out = []
        for ins in disassemble(code_attr["code"]):
            if ins["opcode"] in (0xB6, 0xB7, 0xB8, 0xB9) and ins["cp_index"]:
                e = cp[ins["cp_index"]]
                if e and e.get("tag") in (CP_METHODREF, CP_INTERFACE_METHODREF):
                    cn = _cp_class_name(cp, e["class_index"])
                    nt = cp[e["name_and_type_index"]]
                    nm = _cp_utf8(cp, nt["name_index"])
                    desc = _cp_utf8(cp, nt["descriptor_index"])
                    out.append({"pc": ins["pc"], "class": cn, "name": nm, "desc": desc})
        return out

    @staticmethod
    def find_field_accesses(code_attr: dict, cp: List[Optional[dict]]) -> List[dict]:
        out = []
        for ins in disassemble(code_attr["code"]):
            if ins["opcode"] in (0xB2, 0xB3, 0xB4, 0xB5) and ins["cp_index"]:
                e = cp[ins["cp_index"]]
                if e and e.get("tag") == CP_FIELDREF:
                    cn = _cp_class_name(cp, e["class_index"])
                    nt = cp[e["name_and_type_index"]]
                    nm = _cp_utf8(cp, nt["name_index"])
                    desc = _cp_utf8(cp, nt["descriptor_index"])
                    out.append({"pc": ins["pc"], "kind": ins["mnemonic"],
                                "class": cn, "name": nm, "desc": desc})
        return out


# ---------------------------------------------------------------------------
# ClassFile (class_file_parser.rs / classfile_parser.rs / class_parser_full.rs)
# ---------------------------------------------------------------------------

class ClassFile:
    def __init__(self, parsed: dict): self._p = parsed

    @classmethod
    def parse(cls, data: bytes) -> "ClassFile":
        return cls(_parse_class(data))

    # constant pool accessors
    @property
    def constant_pool(self): return self._p["constant_pool"]

    def resolve_utf8(self, idx: int) -> str:
        s = _cp_utf8(self._p["constant_pool"], idx)
        if s is None: raise ClassParseError("not utf8")
        return s

    def resolve_class_name(self) -> str:
        return _cp_class_name(self._p["constant_pool"], self._p["this_class"]) or ""

    def resolve_super_name(self) -> str:
        return _cp_class_name(self._p["constant_pool"], self._p["super_class"]) or ""

    def this_class_name(self) -> Optional[str]:
        return _cp_class_name(self._p["constant_pool"], self._p["this_class"])

    def super_class_name(self) -> Optional[str]:
        return _cp_class_name(self._p["constant_pool"], self._p["super_class"])

    def class_name(self) -> Optional[str]: return self.this_class_name()
    def super_name(self) -> Optional[str]: return self.super_class_name()

    def java_version(self) -> str:
        major = self._p["major_version"]
        # 45 = Java 1.1; Java N = major - 44 for N>=5 (49=Java 5)
        if major <= 48: return f"Java 1.{major - 44}"
        return f"Java {major - 44}"

    def interface_names(self) -> List[str]:
        cp = self._p["constant_pool"]
        return [n for n in (_cp_class_name(cp, i) for i in self._p["interfaces"]) if n]

    def source_file(self) -> Optional[str]:
        cp = self._p["constant_pool"]
        info = _find_attr(self._p["attributes"], cp, "SourceFile")
        if info is None or len(info) < 2: return None
        return _cp_utf8(cp, _u2(info, 0))

    def signature(self) -> Optional[str]:
        cp = self._p["constant_pool"]
        info = _find_attr(self._p["attributes"], cp, "Signature")
        if info is None or len(info) < 2: return None
        return _cp_utf8(cp, _u2(info, 0))

    def string_literals(self) -> List[str]:
        return [e["value"] for e in self._p["constant_pool"]
                if e and e.get("tag") == CP_UTF8]

    def method_refs(self) -> List[str]:
        return JavaClass(self._p).method_calls()

    def referenced_classes(self) -> Dict[int, str]:
        out = {}
        cp = self._p["constant_pool"]
        for i, e in enumerate(cp):
            if e and e.get("tag") == CP_CLASS:
                nm = _cp_utf8(cp, e["name_index"])
                if nm: out[i] = nm
        return out

    def cp_tag_histogram(self) -> Dict[int, int]:
        h: Dict[int, int] = defaultdict(int)
        for e in self._p["constant_pool"]:
            if e: h[e["tag"]] += 1
        return dict(h)

    def obfuscation_score(self) -> float:
        return JavaClass(self._p).obfuscation_score()

    def is_record(self) -> bool:
        return (self._p["access_flags"] & 0x10000) != 0  # ACC_RECORD-ish (rough)

    def bootstrap_methods(self) -> List[dict]:
        cp = self._p["constant_pool"]
        info = _find_attr(self._p["attributes"], cp, "BootstrapMethods")
        if info is None or len(info) < 2: return []
        n = _u2(info, 0); o = 2
        out = []
        for _ in range(n):
            bm_ref = _u2(info, o); nargs = _u2(info, o+2); o += 4
            args = [_u2(info, o + 2*k) for k in range(nargs)]
            o += 2*nargs
            out.append({"method_ref": bm_ref, "args": args})
        return out

    def inner_classes(self) -> List[dict]:
        cp = self._p["constant_pool"]
        info = _find_attr(self._p["attributes"], cp, "InnerClasses")
        if info is None: return []
        return AttributeParser.parse_inner_classes(info, cp)

    def nest_members(self) -> List[int]:
        cp = self._p["constant_pool"]
        info = _find_attr(self._p["attributes"], cp, "NestMembers")
        if info is None: return []
        n = _u2(info, 0)
        return [_u2(info, 2 + 2*k) for k in range(n)]

    def permitted_subclasses(self) -> List[int]:
        cp = self._p["constant_pool"]
        info = _find_attr(self._p["attributes"], cp, "PermittedSubclasses")
        if info is None: return []
        n = _u2(info, 0)
        return [_u2(info, 2 + 2*k) for k in range(n)]

    def record_components(self) -> List[dict]:
        return []  # stub

    def visible_annotations(self) -> List[dict]:
        return []  # stub

    def find_method(self, name: str, descriptor: str) -> Optional[dict]:
        cp = self._p["constant_pool"]
        for m in self._p["methods"]:
            if (_cp_utf8(cp, m["name_index"]) == name and
                _cp_utf8(cp, m["descriptor_index"]) == descriptor):
                return m
        return None

    @staticmethod
    def parse_code_attribute(data: bytes) -> dict:
        return _parse_code_attribute(data)


class ClassParserBuilder:
    def __init__(self, data: Optional[bytes] = None): self.data = data
    def with_data(self, data: bytes) -> "ClassParserBuilder":
        self.data = data; return self
    def parse(self) -> ClassFile:
        if self.data is None: raise ClassParseError("no data")
        return ClassFile.parse(self.data)


# member-name helpers
def field_name(field: dict, cp: List[Optional[dict]]) -> str:
    return _cp_utf8(cp, field["name_index"]) or ""

def field_descriptor(field: dict, cp: List[Optional[dict]]) -> str:
    return _cp_utf8(cp, field["descriptor_index"]) or ""

def method_name(m: dict, cp: List[Optional[dict]]) -> str:
    return _cp_utf8(cp, m["name_index"]) or ""

def method_descriptor(m: dict, cp: List[Optional[dict]]) -> str:
    return _cp_utf8(cp, m["descriptor_index"]) or ""

def method_code_attribute_raw(m: dict, cp: List[Optional[dict]]) -> Optional[bytes]:
    return _find_attr(m["attributes"], cp, "Code")

def method_code(m: dict, cp: List[Optional[dict]]) -> Optional[dict]:
    raw = method_code_attribute_raw(m, cp)
    return _parse_code_attribute(raw) if raw is not None else None

def method_checked_exceptions(m: dict, cp: List[Optional[dict]]) -> List[int]:
    info = _find_attr(m["attributes"], cp, "Exceptions")
    if info is None: return []
    n = _u2(info, 0)
    return [_u2(info, 2 + 2*k) for k in range(n)]

def method_signature(m: dict, cp: List[Optional[dict]]) -> Optional[str]:
    info = _find_attr(m["attributes"], cp, "Signature")
    if info is None or len(info) < 2: return None
    return _cp_utf8(cp, _u2(info, 0))

def method_visible_annotations(m: dict, cp: List[Optional[dict]]) -> List[dict]:
    return []  # stub


# ---------------------------------------------------------------------------
# ConstantPool wrapper (decompiler / bytecode_analyzer)
# ---------------------------------------------------------------------------

class ConstantPool:
    def __init__(self, entries: List[Optional[dict]]): self._e = entries

    def get(self, index: int) -> Optional[dict]:
        if 0 < index < len(self._e): return self._e[index]
        return None

    def utf8(self, index: int) -> Optional[str]:
        return _cp_utf8(self._e, index)

    def class_name(self, index: int) -> Optional[str]:
        return _cp_class_name(self._e, index)

    def iter(self) -> Iterator[Tuple[int, dict]]:
        for i, e in enumerate(self._e):
            if e is not None: yield (i, e)

    def all_strings(self) -> List[str]:
        return [e["value"] for e in self._e if e and e.get("tag") == CP_UTF8]

    def utf8_strings(self) -> List[str]: return self.all_strings()

    def utf8_at(self, idx: int) -> str:
        s = self.utf8(idx)
        if s is None: raise BytecodeError("not utf8")
        return s

    def referenced_classes(self) -> List[str]:
        out = []
        for e in self._e:
            if e and e.get("tag") == CP_CLASS:
                nm = _cp_utf8(self._e, e["name_index"])
                if nm: out.append(nm)
        return out

    def method_refs(self) -> List[str]:
        out = []
        for e in self._e:
            if e and e.get("tag") in (CP_METHODREF, CP_INTERFACE_METHODREF):
                cn = _cp_class_name(self._e, e["class_index"])
                nt = self._e[e["name_and_type_index"]]
                nm = _cp_utf8(self._e, nt["name_index"])
                desc = _cp_utf8(self._e, nt["descriptor_index"])
                out.append(f"{cn}.{nm}{desc}")
        return out

    def integer_constants(self) -> List[int]:
        return [e["value"] for e in self._e if e and e.get("tag") == CP_INTEGER]

    def search_strings(self, pattern: str) -> List[str]:
        rx = re.compile(pattern)
        return [s for s in self.all_strings() if rx.search(s)]

    def stats(self) -> dict:
        tags: Dict[int, int] = defaultdict(int)
        for e in self._e:
            if e: tags[e["tag"]] += 1
        return {"total": sum(tags.values()), "by_tag": dict(tags)}


class CpInfo:
    @staticmethod
    def parse(data: bytes) -> Tuple[dict, int]:
        cp, off = _parse_cp(data, 0, 2)
        if len(cp) < 2: raise BytecodeError("empty CP entry")
        return cp[1], off


# ---------------------------------------------------------------------------
# Bytecode analysis (CFG, etc.)
# ---------------------------------------------------------------------------

def build_cfg(code: bytes, exc_table: List[dict]) -> Dict[int, dict]:
    leaders: Set[int] = {0}
    instrs = disassemble(code)
    pcs = [ins["pc"] for ins in instrs]
    pc_set = set(pcs)
    for ins in instrs:
        if ins["branch_target"] is not None and ins["branch_target"] in pc_set:
            leaders.add(ins["branch_target"])
            nxt = ins["pc"] + ins["width"]
            if nxt in pc_set: leaders.add(nxt)
        if ins["opcode"] in (0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xBF):
            nxt = ins["pc"] + ins["width"]
            if nxt in pc_set: leaders.add(nxt)
    for e in exc_table:
        leaders.add(e["handler_pc"])
    blocks: Dict[int, dict] = {}
    sorted_leaders = sorted(leaders)
    for i, start in enumerate(sorted_leaders):
        end = sorted_leaders[i+1] if i+1 < len(sorted_leaders) else (pcs[-1] + instrs[-1]["width"] if pcs else 0)
        blocks[start] = {"start_pc": start, "end_pc": end,
                         "instructions": [ins for ins in instrs if start <= ins["pc"] < end],
                         "stack_depth": 0}
    return blocks


def compute_stack_depths(blocks: Dict[int, dict], code: bytes) -> None:
    depth = 0
    for start in sorted(blocks):
        blocks[start]["stack_depth"] = depth


def reconstruct_try_catch(exc_table: List[dict]) -> List[dict]:
    return [{"try_start": e["start_pc"], "try_end": e["end_pc"],
             "handler": e["handler_pc"], "catch_type": e["catch_type"]}
            for e in exc_table]


def find_subroutines(code: bytes) -> List[dict]:
    subs = []
    for ins in disassemble(code):
        if ins["opcode"] == 0xA8:  # jsr
            subs.append({"call_pc": ins["pc"], "target": ins["branch_target"]})
    return subs


def collect_narrowing_hints(blocks: Dict[int, dict], cp_class_names: Dict[int, str]) -> List[dict]:
    hints = []
    for blk in blocks.values():
        for ins in blk["instructions"]:
            if ins["opcode"] in (0xC0, 0xC1) and ins["cp_index"] in cp_class_names:
                hints.append({"pc": ins["pc"], "type": cp_class_names[ins["cp_index"]],
                              "op": ins["mnemonic"]})
    return hints


class MethodCfg:
    def __init__(self, blocks: Dict[int, dict], handlers: List[int]):
        self.blocks = blocks
        self.handlers = handlers

    @classmethod
    def analyze(cls, code_attr: dict, cp_class_names: Dict[int, str]) -> "MethodCfg":
        blocks = build_cfg(code_attr["code"], code_attr["exception_table"])
        compute_stack_depths(blocks, code_attr["code"])
        return cls(blocks, [e["handler_pc"] for e in code_attr["exception_table"]])

    def largest_block(self) -> Optional[dict]:
        if not self.blocks: return None
        return max(self.blocks.values(),
                   key=lambda b: len(b["instructions"]))

    def handler_pcs(self) -> List[int]:
        return list(self.handlers)


# ---------------------------------------------------------------------------
# Bytecode disassembler / analyzer (other modules)
# ---------------------------------------------------------------------------

def jvm_insn_resolve_cp_operand(insn: dict, classfile: ClassFile) -> Optional[dict]:
    if insn.get("cp_index") is None: return None
    cp = classfile.constant_pool
    idx = insn["cp_index"]
    if 0 < idx < len(cp): return cp[idx]
    return None


def jvm_insn_branch_target(insn: dict) -> Optional[int]:
    return insn.get("branch_target")


class BytecodeDisassembler:
    def disassemble_code(self, code: bytes) -> List[dict]:
        return disassemble(code)

    def format_instruction(self, insn: dict) -> str:
        s = f"{insn['pc']:04x}: {insn['mnemonic']}"
        if insn.get("cp_index") is not None: s += f" #{insn['cp_index']}"
        if insn.get("branch_target") is not None: s += f" -> {insn['branch_target']:04x}"
        return s

    def detect_try_catch_blocks(self, exc_table: List[dict]) -> List[dict]:
        return reconstruct_try_catch(exc_table)

    def branch_targets(self, insns: List[dict]) -> List[int]:
        return [i["branch_target"] for i in insns if i.get("branch_target") is not None]


class CodeAttribute:
    def __init__(self, raw: dict): self._r = raw

    @staticmethod
    def parse_code_attribute(data: bytes) -> dict:
        return _parse_code_attribute(data)

    def instruction_count(self) -> int:
        return len(disassemble(self._r["code"]))


class CallSiteCollector:
    def collect(self, code: bytes) -> List[dict]:
        out = []
        for ins in disassemble(code):
            if ins["opcode"] in (0xB6, 0xB7, 0xB8, 0xB9, 0xBA):
                out.append({"pc": ins["pc"], "op": ins["mnemonic"],
                            "cp_index": ins["cp_index"]})
        return out


class ClassAnalysis:
    def __init__(self, classfile: ClassFile):
        self.classfile = classfile

    @classmethod
    def parse(cls, data: bytes) -> "ClassAnalysis":
        return cls(ClassFile.parse(data))

    def all_call_sites(self) -> List[dict]:
        cp = self.classfile.constant_pool
        out = []
        for m in self.classfile._p["methods"]:
            raw = _find_attr(m["attributes"], cp, "Code")
            if raw is None: continue
            ca = _parse_code_attribute(raw)
            for cs in CallSiteCollector().collect(ca["code"]):
                cs["method"] = _cp_utf8(cp, m["name_index"])
                out.append(cs)
        return out

    def methods_named(self, name: str) -> List[dict]:
        cp = self.classfile.constant_pool
        return [m for m in self.classfile._p["methods"]
                if _cp_utf8(cp, m["name_index"]) == name]


# ---------------------------------------------------------------------------
# Method body + decompiler
# ---------------------------------------------------------------------------

class MethodBody:
    def __init__(self, code: bytes, instrs: List[dict]):
        self.code = code
        self.instrs = instrs

    @classmethod
    def from_bytecode(cls, code: bytes) -> "MethodBody":
        return cls(code, disassemble(code))

    def basic_block_count(self) -> int:
        return len(build_cfg(self.code, []))

    def has_calls(self) -> bool:
        return any(i["opcode"] in (0xB6, 0xB7, 0xB8, 0xB9, 0xBA) for i in self.instrs)

    def cyclomatic_complexity(self) -> int:
        branches = sum(1 for i in self.instrs
                       if i["opcode"] in BRANCH_OPCODES or i["opcode"] in (0xAA, 0xAB))
        return branches + 1

    def callee_cp_indices(self) -> List[int]:
        return [i["cp_index"] for i in self.instrs
                if i["opcode"] in (0xB6, 0xB7, 0xB8, 0xB9, 0xBA) and i["cp_index"] is not None]


class AnnotationParser:
    @staticmethod
    def parse(data: bytes, cp: List[Optional[dict]]) -> List[dict]:
        if len(data) < 2: return []
        n = _u2(data, 0)
        # simplified: don't deeply parse element pairs.
        return [{"index": k} for k in range(n)]


class AnnotationUtil:
    @staticmethod
    def is_deprecated(annotations: List[dict]) -> bool:
        return any(a.get("type", "").endswith("Deprecated") for a in annotations)

    @staticmethod
    def filter_by_type(annotations: List[dict], type_name: str) -> List[dict]:
        return [a for a in annotations if a.get("type") == type_name]


class InnerClassInfo(dict):
    @classmethod
    def new(cls, inner: str, outer: Optional[str], name: Optional[str],
            access: int) -> "InnerClassInfo":
        return cls({"inner_class": inner, "outer_class": outer,
                    "inner_name": name, "access_flags": access})


class InnerClassParser:
    @staticmethod
    def parse(data: bytes, cp: List[Optional[dict]]) -> List[dict]:
        return AttributeParser.parse_inner_classes(data, cp)


class JarDisassembler:
    def disassemble(self, jc: JavaClass) -> str:
        cp = jc._p["constant_pool"]
        lines = []
        for m in jc._p["methods"]:
            name = _cp_utf8(cp, m["name_index"])
            raw = _find_attr(m["attributes"], cp, "Code")
            lines.append(f"method {name}:")
            if raw:
                ca = _parse_code_attribute(raw)
                for ins in disassemble(ca["code"]):
                    lines.append("  " + BytecodeDisassembler().format_instruction(ins))
        return "\n".join(lines)

    def disassemble_code(self, code: bytes) -> str:
        return "\n".join(BytecodeDisassembler().format_instruction(i)
                         for i in disassemble(code))

    @staticmethod
    def render_instruction(insn: dict) -> str:
        return BytecodeDisassembler().format_instruction(insn)

    def opcode_histogram(self, code: bytes) -> Dict[str, int]:
        h: Dict[str, int] = defaultdict(int)
        for ins in disassemble(code):
            h[ins["mnemonic"]] += 1
        return dict(h)


class DecompiledClass(dict): pass


class JarDecompiler:
    def __init__(self):
        self.classes: Dict[str, DecompiledClass] = {}

    def add_class(self, jc: JavaClass) -> None:
        name = JavaClass(jc._p) and (_cp_class_name(jc._p["constant_pool"],
                                                    jc._p["this_class"]) or "?")
        self.classes[name] = DecompiledClass({
            "name": name,
            "complexity": sum(MethodBody.from_bytecode(
                _parse_code_attribute(_find_attr(m["attributes"], jc._p["constant_pool"], "Code") or b"\x00"*8).get("code", b""))
                              .cyclomatic_complexity()
                              for m in jc._p["methods"]
                              if _find_attr(m["attributes"], jc._p["constant_pool"], "Code")),
            "external_refs": JavaClass(jc._p).method_calls(),
        })

    def add_class_bytes(self, name: str, data: bytes) -> None:
        self.add_class(JavaClass.parse(data))

    def get_class(self, name: str) -> Optional[DecompiledClass]:
        return self.classes.get(name)

    def class_names(self) -> List[str]:
        return list(self.classes.keys())

    def all_external_refs(self) -> List[str]:
        out = []
        for c in self.classes.values():
            out.extend(c.get("external_refs", []))
        return out

    def most_complex_class(self) -> Optional[DecompiledClass]:
        if not self.classes: return None
        return max(self.classes.values(), key=lambda c: c.get("complexity", 0))


# ---------------------------------------------------------------------------
# Class hierarchy / patterns
# ---------------------------------------------------------------------------

class ClassHierarchy:
    def __init__(self): self.classes: Dict[str, dict] = {}

    @classmethod
    def build_hierarchy(cls, classes: List[ClassFile]) -> "ClassHierarchy":
        h = cls()
        for cf in classes:
            name = cf.this_class_name() or "?"
            h.classes[name] = {"super": cf.super_class_name(),
                               "interfaces": cf.interface_names()}
        return h

    def is_subclass_of(self, class_name: str, target: str) -> bool:
        cur = class_name
        seen = set()
        while cur and cur not in seen:
            seen.add(cur)
            info = self.classes.get(cur)
            if not info: return False
            if info["super"] == target: return True
            cur = info["super"]
        return False

    def find_implementations(self, interface: str) -> List[str]:
        return [n for n, info in self.classes.items() if interface in info["interfaces"]]


class DesignPattern(dict): pass


class PatternDetector:
    @staticmethod
    def detect_singleton(cf: ClassFile) -> bool:
        cp = cf.constant_pool
        has_priv_ctor = False
        has_static_inst = False
        for m in cf._p["methods"]:
            name = _cp_utf8(cp, m["name_index"]) or ""
            if name == "<init>" and (m["access_flags"] & 0x0002):
                has_priv_ctor = True
        for f in cf._p["fields"]:
            if (f["access_flags"] & 0x0008) and (f["access_flags"] & 0x0002):
                has_static_inst = True
        return has_priv_ctor and has_static_inst

    @staticmethod
    def detect_factory(cf: ClassFile) -> bool:
        cp = cf.constant_pool
        for m in cf._p["methods"]:
            name = _cp_utf8(cp, m["name_index"]) or ""
            if (m["access_flags"] & 0x0008) and name.startswith(("create", "newInstance", "of")):
                return True
        return False

    @staticmethod
    def detect_builder(cf: ClassFile) -> bool:
        n = (cf.this_class_name() or "").lower()
        return n.endswith("builder")

    @staticmethod
    def detect_observer(cf: ClassFile) -> bool:
        ifaces = [i.lower() for i in cf.interface_names()]
        return any("observer" in i or "listener" in i for i in ifaces)

    @staticmethod
    def detect_decorator(cf: ClassFile) -> bool:
        n = (cf.this_class_name() or "").lower()
        return "decorator" in n or "wrapper" in n

    @staticmethod
    def detect_design_patterns(cf: ClassFile) -> List[DesignPattern]:
        out = []
        if PatternDetector.detect_singleton(cf): out.append(DesignPattern({"name": "Singleton"}))
        if PatternDetector.detect_factory(cf): out.append(DesignPattern({"name": "Factory"}))
        if PatternDetector.detect_builder(cf): out.append(DesignPattern({"name": "Builder"}))
        if PatternDetector.detect_observer(cf): out.append(DesignPattern({"name": "Observer"}))
        if PatternDetector.detect_decorator(cf): out.append(DesignPattern({"name": "Decorator"}))
        return out


# ---------------------------------------------------------------------------
# JAR loading and analysis
# ---------------------------------------------------------------------------

class JarEntry(dict): pass


class JarLoader:
    def __init__(self, entries: Dict[str, bytes]):
        self._entries = entries

    @classmethod
    def from_bytes(cls, data: bytes) -> "JarLoader":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            entries = {n: z.read(n) for n in z.namelist() if not n.endswith("/")}
        return cls(entries)

    def entries(self) -> List[JarEntry]:
        return [JarEntry({"name": n, "size": len(d)}) for n, d in self._entries.items()]

    def get(self, path: str) -> Optional[bytes]:
        return self._entries.get(path)

    def class_entries(self) -> List[JarEntry]:
        return [JarEntry({"name": n, "size": len(d)}) for n, d in self._entries.items()
                if n.endswith(".class")]


class JarReport(dict): pass


class JarAnalyzer:
    def __init__(self, data: bytes):
        self._data = data
        self._zip = zipfile.ZipFile(io.BytesIO(data))

    @classmethod
    def new(cls, data: bytes) -> "JarAnalyzer":
        return cls(data)

    @staticmethod
    def analyze(jar: JarLoader) -> JarReport:
        return JarReport({
            "entry_count": len(jar.entries()),
            "class_count": len(jar.class_entries()),
        })

    def list_entries(self) -> List[dict]:
        return [{"name": i.filename, "size": i.file_size}
                for i in self._zip.infolist()]

    def class_files(self) -> List[dict]:
        return [e for e in self.list_entries() if e["name"].endswith(".class")]

    def resources(self) -> List[dict]:
        return [e for e in self.list_entries()
                if not e["name"].endswith(".class") and not e["name"].startswith("META-INF/")]

    def meta_inf_entries(self) -> List[dict]:
        return [e for e in self.list_entries() if e["name"].startswith("META-INF/")]

    def manifest(self) -> Manifest:
        try:
            data = self._zip.read("META-INF/MANIFEST.MF")
        except KeyError:
            raise JarError("no manifest")
        return ManifestParser().parse_manifest(data)

    def entry_data(self, name: str) -> Optional[bytes]:
        try: return self._zip.read(name)
        except KeyError: return None

    def entry_count(self) -> int:
        return len(self._zip.namelist())


class JarManifest(Manifest):
    @classmethod
    def parse(cls, data: bytes) -> "JarManifest":
        m = ManifestParser().parse_manifest(data)
        out = cls(m); return out

    def effective_module_name(self) -> Optional[str]:
        return self["main"].get("Automatic-Module-Name") or self.get_main_class()


class JpmsModule(dict):
    @classmethod
    def parse(cls, data: bytes) -> "JpmsModule":
        # very rough — just acknowledge module-info.class shape.
        if not is_class(data): raise JarError("not a class")
        return cls({"provides": [], "uses": []})

    def provided_services(self) -> List[str]: return list(self["provides"])
    def used_services(self) -> List[str]: return list(self["uses"])


class ServiceScanner:
    @staticmethod
    def scan(analyzer: JarAnalyzer) -> List[dict]:
        out = []
        for e in analyzer.list_entries():
            if e["name"].startswith("META-INF/services/"):
                svc = e["name"].split("/", 2)[-1]
                data = analyzer.entry_data(e["name"]) or b""
                impls = [l.strip() for l in data.decode("utf-8", "replace").splitlines()
                         if l.strip() and not l.startswith("#")]
                out.append({"service": svc, "providers": impls})
        return out


# ---------------------------------------------------------------------------
# Security analysis
# ---------------------------------------------------------------------------

class RiskLevel:
    LOW = 0; MEDIUM = 1; HIGH = 2; CRITICAL = 3


def _make_finding(level: int, **kw) -> dict:
    return {"risk": level, **kw}


class DeserializationFinding(dict):
    def is_unchecked(self) -> bool: return bool(self.get("unchecked", False))

class ReflectionFinding(dict):
    def can_bypass_access(self) -> bool: return bool(self.get("set_accessible", False))

class NativeCodeFinding(dict):
    def is_gadget(self) -> bool: return bool(self.get("gadget", False))

class CommandInjectionFinding(dict):
    def is_injection(self) -> bool: return bool(self.get("dynamic_input", False))

class ClassLoaderFinding(dict):
    def can_load_arbitrary_code(self) -> bool: return bool(self.get("arbitrary", False))


class JarSecurityReport(dict):
    @classmethod
    def mock(cls) -> "JarSecurityReport":
        return cls({"class": "Mock", "findings": [], "score": 0})

    def findings_at_or_above(self, level: int) -> List[dict]:
        return [f for f in self.get("findings", []) if f.get("risk", 0) >= level]

    def high_risk_count(self) -> int:
        return len(self.findings_at_or_above(RiskLevel.HIGH))

    def has_critical(self) -> bool:
        return any(f.get("risk", 0) >= RiskLevel.CRITICAL for f in self.get("findings", []))

    def affected_classes(self) -> List[str]:
        return sorted({f.get("class", "") for f in self.get("findings", []) if f.get("class")})

    def recompute_risk(self) -> None:
        self["score"] = sum(f.get("risk", 0) for f in self.get("findings", []))


class JarSecurityAnalyzer:
    def analyze_class_bytes(self, class_name: str, data: bytes) -> JarSecurityReport:
        findings: List[dict] = []
        try:
            jc = JavaClass.parse(data)
        except JavaLoaderError:
            return JarSecurityReport({"class": class_name, "findings": [], "score": 0})
        strs = jc.string_literals()
        if any("readObject" in s or "ObjectInputStream" in s for s in strs):
            findings.append({"class": class_name, "risk": RiskLevel.HIGH,
                             "kind": "deserialization", "unchecked": True})
        if any("setAccessible" in s for s in strs):
            findings.append({"class": class_name, "risk": RiskLevel.MEDIUM,
                             "kind": "reflection", "set_accessible": True})
        if any("Runtime" in s and "exec" in s for s in jc.method_calls()):
            findings.append({"class": class_name, "risk": RiskLevel.HIGH,
                             "kind": "command_injection", "dynamic_input": True})
        if any("defineClass" in s or "URLClassLoader" in s for s in strs):
            findings.append({"class": class_name, "risk": RiskLevel.CRITICAL,
                             "kind": "classloader", "arbitrary": True})
        if any("System.loadLibrary" in s or "loadLibrary" in s for s in strs):
            findings.append({"class": class_name, "risk": RiskLevel.HIGH,
                             "kind": "native", "gadget": True})
        rep = JarSecurityReport({"class": class_name, "findings": findings, "score": 0})
        rep.recompute_risk()
        return rep


# ---------------------------------------------------------------------------
# JarMetadata / Classpath / DependencyGraph / Jar
# ---------------------------------------------------------------------------

class JarMetadata(dict):
    def main_class(self) -> Optional[str]: return self.get("Main-Class")
    def class_path(self) -> List[str]:
        cp = self.get("Class-Path"); return cp.split() if cp else []
    def is_sealed(self) -> bool: return (self.get("Sealed") or "").lower() == "true"
    def spec_version(self) -> Optional[str]: return self.get("Specification-Version")
    def impl_version(self) -> Optional[str]: return self.get("Implementation-Version")
    def manifest_version(self) -> Optional[str]: return self.get("Manifest-Version")


class ClasspathEntry(dict): pass


class Classpath:
    def __init__(self):
        self.in_jar: List[str] = []
        self.external: List[str] = []
        self.index: Dict[str, ClasspathEntry] = {}

    def add_in_jar(self, path: str) -> None:
        self.in_jar.append(path)
        cls = path[:-6].replace("/", ".") if path.endswith(".class") else path
        self.index[cls] = ClasspathEntry({"path": path, "kind": "in_jar"})

    def add_external(self, path: str) -> None:
        self.external.append(path)

    def find_class(self, binary_name: str) -> Optional[ClasspathEntry]:
        return self.index.get(binary_name) or self.index.get(binary_name.replace(".", "/"))


class DependencyGraph:
    def __init__(self):
        self.nodes: Set[str] = set()
        self.edges: Dict[str, Set[str]] = defaultdict(set)

    def add_class(self, name: str) -> None:
        self.nodes.add(name)

    def add_dep(self, frm: str, to: str) -> None:
        self.nodes.add(frm); self.nodes.add(to)
        self.edges[frm].add(to)

    def transitive_deps(self, root: str) -> Set[str]:
        out: Set[str] = set()
        stack = [root]
        while stack:
            cur = stack.pop()
            for n in self.edges.get(cur, set()):
                if n not in out:
                    out.add(n); stack.append(n)
        return out

    def roots(self) -> List[str]:
        incoming: Set[str] = set()
        for tos in self.edges.values(): incoming.update(tos)
        return [n for n in self.nodes if n not in incoming]


class Jar:
    def __init__(self, data: bytes, target_version: int = 0):
        self._target = target_version
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            self._entries = {n: z.read(n) for n in z.namelist() if not n.endswith("/")}
        try:
            m = ManifestParser().parse_manifest(self._entries["META-INF/MANIFEST.MF"])
        except KeyError:
            m = Manifest.new()
        self.manifest = m
        self.classes: Dict[str, ClassFile] = {}
        for name, content in self._entries.items():
            if name.endswith(".class"):
                try:
                    cf = ClassFile.parse(content)
                    bn = cf.this_class_name() or name[:-6]
                    self.classes[bn] = cf
                except ClassParseError:
                    pass

    @classmethod
    def parse(cls, data: bytes, target_version: int = 0) -> "Jar":
        return cls(data, target_version)

    def main_class(self) -> Optional[str]:
        return self.manifest.get_main_class()

    def class_(self, binary_name: str) -> Optional[ClassFile]:
        return self.classes.get(binary_name) or self.classes.get(binary_name.replace(".", "/"))

    # `class` is reserved; expose both
    def __getattr__(self, item):
        if item == "class": return self.class_
        raise AttributeError(item)

    def class_names(self) -> List[str]:
        return list(self.classes.keys())

    def all_string_literals(self) -> List[Tuple[str, List[str]]]:
        return [(n, cf.string_literals()) for n, cf in self.classes.items()]

    def package_stats(self) -> Dict[str, int]:
        out: Dict[str, int] = defaultdict(int)
        for n in self.classes:
            pkg = n.rsplit("/", 1)[0] if "/" in n else ""
            out[pkg] += 1
        return dict(out)

    def is_signed(self) -> bool:
        return any(n.startswith("META-INF/") and n.endswith(".SF") for n in self._entries)

    def resources(self) -> List[str]:
        return [n for n in self._entries if not n.endswith(".class")]

    def spi_providers(self) -> Dict[str, List[str]]:
        out: Dict[str, List[str]] = {}
        for n, d in self._entries.items():
            if n.startswith("META-INF/services/"):
                svc = n.split("/", 2)[-1]
                impls = [l.strip() for l in d.decode("utf-8", "replace").splitlines()
                         if l.strip() and not l.startswith("#")]
                out[svc] = impls
        return out


# ---------------------------------------------------------------------------
# Sanity self-test when run directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Minimal CAFEBABE header to exercise is_class / parse failure path.
    fake = CAFEBABE + b"\x00\x00\x00\x34\x00\x01"  # cp_count = 1 (empty)
    print(json.dumps({
        "is_class": is_class(fake),
        "is_jar": is_jar(fake),
        "parse_field_I": JavaTypeParser().parse_field("I"),
        "parse_field_String": JavaTypeParser().parse_field("Ljava/lang/String;"),
        "parse_method": JavaTypeParser().parse_method("(ILjava/lang/String;)V"),
        "disasm_empty": disassemble(b""),
    }, default=str, indent=2))
