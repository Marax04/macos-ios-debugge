#!/usr/bin/env python3
"""Independent Python validator for rustre-analysis-vtable.

Stdlib-only. Does NOT import the Rust crate or call MCP.
Implements minimal versions of vtable detection, RTTI decoding (Itanium &
MSVC), demangling helpers, and a vtable database, then exercises them on
synthetic data and reports per-function results.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

CRATE = "rustre-analysis-vtable"
OUTPUT_PATH = r"C:\Users\Fra\Desktop\RustRE\validation\out\rustre-analysis-vtable.json"


# ---------- Data model ----------
@dataclass
class Section:
    name: str
    base_address: int
    data: bytes
    executable: bool = False
    writable: bool = False
    readable: bool = True


@dataclass
class VtableEntry:
    offset: int
    target_address: int
    function_name: Optional[str] = None


@dataclass
class Vtable:
    base_address: int
    entries: List[VtableEntry] = field(default_factory=list)
    class_name: Optional[str] = None
    offset_to_top: int = 0


@dataclass
class RttiInfo:
    type_name: str
    base_classes: List[str]
    rtti_address: int
    abi: str  # "Itanium" | "Msvc" | "Unknown"


# ---------- Helpers ----------
def read_ptr(data: bytes, offset: int, ptr_size: int) -> Optional[int]:
    if offset + ptr_size > len(data):
        return None
    fmt = "<Q" if ptr_size == 8 else "<I"
    return struct.unpack_from(fmt, data, offset)[0]


def section_contains(sec: Section, addr: int) -> bool:
    return sec.base_address <= addr < sec.base_address + len(sec.data)


def is_in_any_code(addr: int, code_sections: List[Section]) -> bool:
    return any(s.executable and section_contains(s, addr) for s in code_sections)


# ---------- VtableDetector ----------
class VtableDetector:
    def __init__(self, ptr_size: int):
        if ptr_size not in (4, 8):
            raise ValueError("ptr_size must be 4 or 8")
        self.ptr_size = ptr_size

    def detect(self, data_section: Section, code_sections: List[Section]) -> List[Vtable]:
        results: List[Vtable] = []
        ps = self.ptr_size
        data = data_section.data
        i = 0
        while i + ps <= len(data):
            entries: List[VtableEntry] = []
            j = i
            while j + ps <= len(data):
                ptr = read_ptr(data, j, ps)
                if ptr is None or not is_in_any_code(ptr, code_sections):
                    break
                entries.append(
                    VtableEntry(
                        offset=j - i,
                        target_address=ptr,
                    )
                )
                j += ps
                if len(entries) >= 1024:
                    break
            if len(entries) >= 2:
                results.append(
                    Vtable(
                        base_address=data_section.base_address + i,
                        entries=entries,
                    )
                )
                i = j
            else:
                i += ps
        return results


# ---------- Itanium RTTI ----------
class ItaniumRttiDecoder:
    @staticmethod
    def _read_cstr(sec: Section, addr: int) -> Optional[str]:
        if not section_contains(sec, addr):
            return None
        off = addr - sec.base_address
        end = sec.data.find(b"\x00", off)
        if end < 0:
            return None
        try:
            return sec.data[off:end].decode("ascii", errors="replace")
        except Exception:
            return None

    @classmethod
    def decode(
        cls,
        addr: int,
        ro_section: Section,
        ptr_size: int,
        known_names: Dict[int, str],
        depth: int = 0,
    ) -> RttiInfo:
        if depth > 32:
            raise RecursionError("RTTI recursion too deep")
        if not section_contains(ro_section, addr):
            raise ValueError(f"RTTI addr {addr:#x} not in ro section")
        off = addr - ro_section.base_address
        # layout: [vtable_ptr][name_ptr]([base_ptr])
        name_ptr = read_ptr(ro_section.data, off + ptr_size, ptr_size)
        if name_ptr is None:
            raise ValueError("cannot read name_ptr")
        type_name = (
            cls._read_cstr(ro_section, name_ptr)
            or known_names.get(name_ptr, f"<unk@{name_ptr:#x}>")
        )
        bases: List[str] = []
        base_ptr = read_ptr(ro_section.data, off + 2 * ptr_size, ptr_size)
        if base_ptr and section_contains(ro_section, base_ptr):
            try:
                base = cls.decode(base_ptr, ro_section, ptr_size, known_names, depth + 1)
                bases.append(base.type_name)
            except Exception:
                pass
        return RttiInfo(type_name=type_name, base_classes=bases, rtti_address=addr, abi="Itanium")


# ---------- MSVC RTTI ----------
class MsvcRttiDecoder:
    @staticmethod
    def demangle_msvc(name: str) -> str:
        s = name
        for prefix in (".?AV", ".?AU"):
            if s.startswith(prefix):
                s = s[len(prefix):]
                break
        if s.endswith("@@"):
            s = s[:-2]
        return s.replace("@", "::")


# ---------- Demangler stubs ----------
def is_itanium_mangled(s: str) -> bool:
    return s.startswith("_Z")


def is_msvc_mangled(s: str) -> bool:
    return s.startswith("?")


def demangle_msvc(s: str) -> str:
    # very small stub: handle .?AV<Name>@@ form
    return MsvcRttiDecoder.demangle_msvc(s)


def demangle_itanium(s: str) -> str:
    # toy: _ZN3foo3barEv -> foo::bar
    if not s.startswith("_ZN"):
        return s
    rest = s[3:]
    parts = []
    while rest and rest[0].isdigit():
        n = 0
        while rest and rest[0].isdigit():
            n = n * 10 + int(rest[0])
            rest = rest[1:]
        parts.append(rest[:n])
        rest = rest[n:]
    return "::".join(parts) if parts else s


# ---------- VtableDatabase ----------
class VtableDatabase:
    def __init__(self):
        self.vtables: Dict[int, Vtable] = {}
        self.rtti: Dict[int, RttiInfo] = {}
        self.vtable_to_rtti: Dict[int, int] = {}

    def add_vtable(self, v: Vtable) -> None:
        self.vtables[v.base_address] = v

    def add_rtti(self, r: RttiInfo) -> None:
        self.rtti[r.rtti_address] = r

    def link_vtable_rtti(self, vtable_addr: int, rtti_addr: int) -> bool:
        if vtable_addr in self.vtables and rtti_addr in self.rtti:
            self.vtable_to_rtti[vtable_addr] = rtti_addr
            self.vtables[vtable_addr].class_name = self.rtti[rtti_addr].type_name
            return True
        return False

    def rtti_for_vtable(self, vtable_addr: int) -> Optional[RttiInfo]:
        ra = self.vtable_to_rtti.get(vtable_addr)
        return self.rtti.get(ra) if ra is not None else None

    def find_by_class(self, class_name: str) -> List[Vtable]:
        return [v for v in self.vtables.values() if v.class_name == class_name]


# ---------- PureVirtualDetector ----------
class PureVirtualDetector:
    def __init__(self):
        self.stubs = set()

    def add_stub_address(self, addr: int) -> None:
        self.stubs.add(addr)

    def is_pure_virtual(self, entry: VtableEntry) -> bool:
        return entry.target_address in self.stubs

    def annotate(self, vt: Vtable) -> int:
        n = 0
        for e in vt.entries:
            if self.is_pure_virtual(e):
                e.function_name = "__cxa_pure_virtual"
                n += 1
        return n

    def count_in_database(self, db: VtableDatabase) -> int:
        return sum(self.annotate(v) for v in db.vtables.values())


# ---------- VtableComparer ----------
class VtableComparer:
    @staticmethod
    def diff(orig: Vtable, patched: Vtable) -> List[Tuple[int, int, int]]:
        out = []
        for a, b in zip(orig.entries, patched.entries):
            if a.target_address != b.target_address:
                out.append((a.offset, a.target_address, b.target_address))
        return out

    @staticmethod
    def is_identical(a: Vtable, b: Vtable) -> bool:
        if len(a.entries) != len(b.entries):
            return False
        return all(x.target_address == y.target_address for x, y in zip(a.entries, b.entries))


# ---------- Helper builders ----------
def make_ptr_section(base: int, ptrs: List[int], executable: bool, ptr_size: int = 8) -> Section:
    fmt = "<Q" if ptr_size == 8 else "<I"
    data = b"".join(struct.pack(fmt, p) for p in ptrs)
    return Section(name=".data", base_address=base, data=data, executable=executable)


def make_str_section(base: int, s: str) -> Section:
    return Section(name=".rodata", base_address=base, data=s.encode("ascii") + b"\x00")


# ---------- Tests ----------
def test_vtable_detector() -> Tuple[bool, str]:
    code = Section(".text", 0x401000, b"\x90" * 0x1000, executable=True)
    data = make_ptr_section(0x500000, [0x401000, 0x401010, 0x401020, 0xDEADBEEF], executable=False)
    det = VtableDetector(8)
    vts = det.detect(data, [code])
    if len(vts) == 1 and len(vts[0].entries) == 3:
        return True, f"detected 1 vtable with 3 entries"
    return False, f"got {len(vts)} vtables: {vts}"


def test_msvc_demangle() -> Tuple[bool, str]:
    out = MsvcRttiDecoder.demangle_msvc(".?AVFoo@bar@@")
    ok = out == "Foo::bar"
    return ok, f"demangle_msvc -> {out!r}"


def test_itanium_demangle() -> Tuple[bool, str]:
    out = demangle_itanium("_ZN3foo3barEv")
    ok = out == "foo::bar"
    return ok, f"demangle_itanium -> {out!r}"


def test_itanium_rtti_decode() -> Tuple[bool, str]:
    # Build .rodata: at 0x600000 type_info struct: [vtbl_ptr=0][name_ptr=0x600100]
    ro_base = 0x600000
    name_addr = ro_base + 0x100
    rtti_addr = ro_base + 0x00
    struct_bytes = struct.pack("<QQ", 0, name_addr).ljust(0x100, b"\x00")
    name_bytes = b"MyClass\x00"
    data = bytearray(0x200)
    data[0:len(struct_bytes)] = struct_bytes
    data[0x100:0x100 + len(name_bytes)] = name_bytes
    ro = Section(".rodata", ro_base, bytes(data))
    info = ItaniumRttiDecoder.decode(rtti_addr, ro, 8, {})
    ok = info.type_name == "MyClass" and info.abi == "Itanium"
    return ok, f"itanium decode -> {info}"


def test_vtable_database_link() -> Tuple[bool, str]:
    db = VtableDatabase()
    vt = Vtable(base_address=0x500000, entries=[VtableEntry(0, 0x401000)])
    rtti = RttiInfo(type_name="Foo", base_classes=["Bar"], rtti_address=0x600000, abi="Itanium")
    db.add_vtable(vt)
    db.add_rtti(rtti)
    linked = db.link_vtable_rtti(0x500000, 0x600000)
    found = db.find_by_class("Foo")
    ok = linked and len(found) == 1 and db.rtti_for_vtable(0x500000).type_name == "Foo"
    return ok, f"linked={linked} found={len(found)}"


def test_pure_virtual_detector() -> Tuple[bool, str]:
    pvd = PureVirtualDetector()
    pvd.add_stub_address(0x401000)
    vt = Vtable(0x500000, [VtableEntry(0, 0x401000), VtableEntry(8, 0x401010)])
    n = pvd.annotate(vt)
    ok = n == 1 and vt.entries[0].function_name == "__cxa_pure_virtual"
    return ok, f"annotated {n}"


def test_vtable_comparer() -> Tuple[bool, str]:
    a = Vtable(0x500000, [VtableEntry(0, 0x401000), VtableEntry(8, 0x401010)])
    b = Vtable(0x500000, [VtableEntry(0, 0x401000), VtableEntry(8, 0x401020)])
    d = VtableComparer.diff(a, b)
    ok = len(d) == 1 and d[0] == (8, 0x401010, 0x401020) and not VtableComparer.is_identical(a, b)
    return ok, f"diff={d}"


def main() -> None:
    tests = [
        ("VtableDetector.detect", test_vtable_detector),
        ("MsvcRttiDecoder.demangle_msvc", test_msvc_demangle),
        ("demangler.demangle_itanium", test_itanium_demangle),
        ("ItaniumRttiDecoder.decode", test_itanium_rtti_decode),
        ("VtableDatabase.link_vtable_rtti", test_vtable_database_link),
        ("PureVirtualDetector.annotate", test_pure_virtual_detector),
        ("VtableComparer.diff", test_vtable_comparer),
    ]
    functions = []
    for name, fn in tests:
        try:
            ok, detail = fn()
            functions.append({"name": name, "ok": bool(ok), "detail": detail})
        except Exception as e:
            functions.append({"name": name, "ok": False, "detail": f"exception: {e!r}"})

    result = {"crate": CRATE, "saved": False, "functions": functions}

    saved = False
    try:
        import os
        os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
        with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        saved = True
    except Exception as e:
        result["save_error"] = repr(e)
    result["saved"] = saved
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
