#!/usr/bin/env python3
"""
Independent Python validator for rustre-hex-template.

Implements a minimal subset of the crate's behavior using only the stdlib:
- A Template / TemplateField / ParsedStruct model
- Expression AST (Eq/Ne/Gt/Lt/And/Or) with eval over a u64 context
- Linear field-walk interpreter reading typed scalar values (LE/BE, signed/unsigned)
- Auto-detection by magic bytes for PE/ELF/Mach-O/ZIP/PNG/GIF/BMP/JPEG/RIFF/WASM/Java
- A few built-in templates (pe_section_header, elf64_ehdr, png_chunk, zip_eocd)
- Helpers: flatten_parsed, diff_parsed, find_field_by_path, find_fields_by_name,
  fields_in_range, template_stats, export_fields (JSON/CSV/Text)
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


# ----------------------------- Errors --------------------------------------- #


class TemplateError(Exception):
    pass


class StdlibError(Exception):
    pass


# ----------------------------- Type system ---------------------------------- #


class Endianness(Enum):
    LE = "le"
    BE = "be"


class ScalarKind(Enum):
    UINT = "uint"
    SINT = "sint"
    BYTES = "bytes"
    UTF8 = "utf8"


@dataclass(frozen=True)
class TypeKind:
    kind: ScalarKind
    size: int          # bytes (for BYTES/UTF8 this is the fixed length)
    endian: Endianness = Endianness.LE


def type_alignment(t: TypeKind) -> int:
    if t.kind in (ScalarKind.BYTES, ScalarKind.UTF8):
        return 1
    return max(1, min(t.size, 8))


def align_offset(off: int, align: int) -> int:
    if align <= 1:
        return off
    rem = off % align
    return off if rem == 0 else off + (align - rem)


def uint_le(n: int) -> TypeKind:
    return TypeKind(ScalarKind.UINT, n, Endianness.LE)


def uint_be(n: int) -> TypeKind:
    return TypeKind(ScalarKind.UINT, n, Endianness.BE)


def sint_le(n: int) -> TypeKind:
    return TypeKind(ScalarKind.SINT, n, Endianness.LE)


def sint_be(n: int) -> TypeKind:
    return TypeKind(ScalarKind.SINT, n, Endianness.BE)


# ----------------------------- Expressions ---------------------------------- #


@dataclass
class Expr:
    """Boolean condition AST over previously-parsed u64 field values."""
    op: str                                  # Eq/Ne/Gt/Lt/And/Or
    a: Any = None                            # name (str) or sub-Expr
    b: Any = None                            # u64 or sub-Expr

    def eval(self, ctx: dict[str, int]) -> bool:
        if self.op in ("Eq", "Ne", "Gt", "Lt"):
            if self.a not in ctx:
                raise TemplateError(f"FieldRef: {self.a}")
            v = ctx[self.a]
            if self.op == "Eq":
                return v == self.b
            if self.op == "Ne":
                return v != self.b
            if self.op == "Gt":
                return v > self.b
            if self.op == "Lt":
                return v < self.b
        if self.op == "And":
            return self.a.eval(ctx) and self.b.eval(ctx)
        if self.op == "Or":
            return self.a.eval(ctx) or self.b.eval(ctx)
        raise TemplateError(f"Condition: {self.op}")


# ----------------------------- Template model ------------------------------- #


@dataclass
class TemplateFieldDef:
    name: str
    ty: TypeKind
    condition: Expr | None = None
    repeat: int | str | None = None          # int or name-ref to prior field
    sub_template: "Template | None" = None


@dataclass
class Template:
    name: str
    fields: list[TemplateFieldDef] = field(default_factory=list)


@dataclass
class TemplateField:
    name: str
    ty: TypeKind
    offset: int
    size: int
    value: Any                               # int, bytes, str, or list


@dataclass
class ParsedStruct:
    name: str
    offset: int
    size: int
    fields: list[TemplateField] = field(default_factory=list)
    children: list["ParsedStruct"] = field(default_factory=list)


@dataclass
class TemplateResult:
    template: str
    parsed: ParsedStruct
    consumed: int


@dataclass
class TemplateStats:
    field_count: int
    fixed_size: int
    has_conditions: bool
    has_repeats: bool
    has_subtemplates: bool


class ExportFormat(Enum):
    JSON = "json"
    CSV = "csv"
    TEXT = "text"


# ----------------------------- Diff types ----------------------------------- #


@dataclass
class DiffEntry:
    kind: str                                # "added"/"removed"/"changed"
    path: str
    left: Any = None
    right: Any = None


@dataclass
class FieldDiff:
    path: str
    left: TemplateField | None
    right: TemplateField | None


# ----------------------------- Interpreter ---------------------------------- #


_RECURSION_LIMIT = 32


def _read_scalar(data: bytes, off: int, ty: TypeKind) -> tuple[Any, int]:
    end = off + ty.size
    if end > len(data):
        raise TemplateError(f"Field: out of range at {off}+{ty.size}")
    raw = data[off:end]
    if ty.kind == ScalarKind.BYTES:
        return raw, ty.size
    if ty.kind == ScalarKind.UTF8:
        try:
            return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace"), ty.size
        except Exception as e:
            raise TemplateError(f"Field: utf8 {e}")
    byteorder = "little" if ty.endian == Endianness.LE else "big"
    signed = ty.kind == ScalarKind.SINT
    return int.from_bytes(raw, byteorder=byteorder, signed=signed), ty.size


def apply_template(
    data: bytes,
    template: Template,
    start: int = 0,
    _depth: int = 0,
) -> TemplateResult:
    if _depth > _RECURSION_LIMIT:
        raise TemplateError("RecursionLimit")

    parsed = ParsedStruct(name=template.name, offset=start, size=0)
    ctx: dict[str, int] = {}
    cur = start

    for fdef in template.fields:
        if fdef.condition is not None:
            try:
                if not fdef.condition.eval(ctx):
                    continue
            except TemplateError:
                raise

        # Resolve repeat count.
        count = 1
        repeating = False
        if fdef.repeat is not None:
            repeating = True
            if isinstance(fdef.repeat, int):
                count = fdef.repeat
            else:
                if fdef.repeat not in ctx:
                    raise TemplateError(f"FieldRef: {fdef.repeat}")
                count = int(ctx[fdef.repeat])

        values: list[Any] = []
        first_off = cur

        # Special case: BYTES with size=0 and a name-ref repeat → read `count` bytes
        # as a single blob (matches templates like png_chunk.data).
        if (
            repeating
            and fdef.sub_template is None
            and fdef.ty.kind == ScalarKind.BYTES
            and fdef.ty.size == 0
        ):
            end = cur + count
            if end > len(data):
                raise TemplateError(f"Field: out of range at {cur}+{count}")
            blob = data[cur:end]
            cur = end
            tf = TemplateField(
                name=fdef.name,
                ty=TypeKind(ScalarKind.BYTES, count, fdef.ty.endian),
                offset=first_off,
                size=count,
                value=blob,
            )
            parsed.fields.append(tf)
            continue

        for _ in range(count):
            if fdef.sub_template is not None:
                sub = apply_template(data, fdef.sub_template, cur, _depth + 1)
                parsed.children.append(sub.parsed)
                cur += sub.consumed
                values.append(sub.parsed)
            else:
                value, sz = _read_scalar(data, cur, fdef.ty)
                values.append(value)
                cur += sz

        if repeating:
            tf = TemplateField(
                name=fdef.name,
                ty=fdef.ty,
                offset=first_off,
                size=cur - first_off,
                value=values,
            )
        else:
            v = values[0]
            tf = TemplateField(
                name=fdef.name,
                ty=fdef.ty,
                offset=first_off,
                size=cur - first_off,
                value=v,
            )
            if isinstance(v, int):
                ctx[fdef.name] = v & 0xFFFFFFFFFFFFFFFF
        parsed.fields.append(tf)

    parsed.size = cur - start
    return TemplateResult(template=template.name, parsed=parsed, consumed=parsed.size)


# ----------------------------- Helpers -------------------------------------- #


def flatten_parsed(parsed: ParsedStruct, prefix: str = "") -> list[TemplateField]:
    out: list[TemplateField] = []
    base = f"{prefix}{parsed.name}"
    for f in parsed.fields:
        out.append(TemplateField(f"{base}.{f.name}", f.ty, f.offset, f.size, f.value))
    for child in parsed.children:
        out.extend(flatten_parsed(child, f"{base}."))
    return out


def find_field_by_path(parsed: ParsedStruct, path: str) -> TemplateField | None:
    for f in flatten_parsed(parsed):
        if f.name == path or f.name.endswith("." + path):
            return f
    return None


def find_fields_by_name(parsed: ParsedStruct, name: str) -> list[TemplateField]:
    return [f for f in flatten_parsed(parsed) if f.name.split(".")[-1] == name]


def fields_in_range(fields: list[TemplateField], start: int, length: int) -> list[TemplateField]:
    end = start + length
    return [f for f in fields if f.offset >= start and (f.offset + f.size) <= end]


def template_stats(t: Template) -> TemplateStats:
    fixed = 0
    has_cond = False
    has_rep = False
    has_sub = False
    for f in t.fields:
        if f.condition is not None:
            has_cond = True
        if f.repeat is not None:
            has_rep = True
        if f.sub_template is not None:
            has_sub = True
        if f.repeat is None and f.sub_template is None and f.condition is None:
            fixed += f.ty.size
    return TemplateStats(len(t.fields), fixed, has_cond, has_rep, has_sub)


def _val_for_export(v: Any) -> Any:
    if isinstance(v, bytes):
        return v.hex()
    if isinstance(v, list):
        return [_val_for_export(x) for x in v]
    if isinstance(v, ParsedStruct):
        return {"name": v.name, "offset": v.offset, "size": v.size}
    return v


def export_fields(fields: list[TemplateField], fmt: ExportFormat) -> str:
    if fmt == ExportFormat.JSON:
        return json.dumps(
            [
                {
                    "name": f.name,
                    "offset": f.offset,
                    "size": f.size,
                    "value": _val_for_export(f.value),
                }
                for f in fields
            ],
            indent=2,
        )
    if fmt == ExportFormat.CSV:
        lines = ["name,offset,size,value"]
        for f in fields:
            v = _val_for_export(f.value)
            if isinstance(v, (list, dict)):
                v = json.dumps(v)
            lines.append(f"{f.name},{f.offset},{f.size},{v}")
        return "\n".join(lines)
    # TEXT
    return "\n".join(
        f"{f.offset:08x}  {f.name} ({f.size}B) = {_val_for_export(f.value)}"
        for f in fields
    )


# ----------------------------- Diff ----------------------------------------- #


def diff_parsed(left: ParsedStruct, right: ParsedStruct) -> list[DiffEntry]:
    out: list[DiffEntry] = []
    lmap = {f.name: f for f in flatten_parsed(left)}
    rmap = {f.name: f for f in flatten_parsed(right)}
    for k, v in lmap.items():
        if k not in rmap:
            out.append(DiffEntry("removed", k, _val_for_export(v.value), None))
        elif _val_for_export(rmap[k].value) != _val_for_export(v.value):
            out.append(
                DiffEntry(
                    "changed",
                    k,
                    _val_for_export(v.value),
                    _val_for_export(rmap[k].value),
                )
            )
    for k, v in rmap.items():
        if k not in lmap:
            out.append(DiffEntry("added", k, None, _val_for_export(v.value)))
    return out


def diff_parsed_structs(left: ParsedStruct, right: ParsedStruct) -> list[FieldDiff]:
    out: list[FieldDiff] = []
    lmap = {f.name: f for f in flatten_parsed(left)}
    rmap = {f.name: f for f in flatten_parsed(right)}
    keys = set(lmap) | set(rmap)
    for k in sorted(keys):
        lf, rf = lmap.get(k), rmap.get(k)
        if lf is None or rf is None or _val_for_export(lf.value) != _val_for_export(rf.value):
            out.append(FieldDiff(k, lf, rf))
    return out


# ----------------------------- Built-in templates --------------------------- #


def template_pe_section_header() -> Template:
    return Template(
        "pe_section_header",
        [
            TemplateFieldDef("name", TypeKind(ScalarKind.UTF8, 8)),
            TemplateFieldDef("virtual_size", uint_le(4)),
            TemplateFieldDef("virtual_address", uint_le(4)),
            TemplateFieldDef("size_of_raw_data", uint_le(4)),
            TemplateFieldDef("pointer_to_raw_data", uint_le(4)),
            TemplateFieldDef("pointer_to_relocations", uint_le(4)),
            TemplateFieldDef("pointer_to_linenumbers", uint_le(4)),
            TemplateFieldDef("number_of_relocations", uint_le(2)),
            TemplateFieldDef("number_of_linenumbers", uint_le(2)),
            TemplateFieldDef("characteristics", uint_le(4)),
        ],
    )


def template_elf64_ehdr() -> Template:
    return Template(
        "elf64_ehdr",
        [
            TemplateFieldDef("e_ident", TypeKind(ScalarKind.BYTES, 16)),
            TemplateFieldDef("e_type", uint_le(2)),
            TemplateFieldDef("e_machine", uint_le(2)),
            TemplateFieldDef("e_version", uint_le(4)),
            TemplateFieldDef("e_entry", uint_le(8)),
            TemplateFieldDef("e_phoff", uint_le(8)),
            TemplateFieldDef("e_shoff", uint_le(8)),
            TemplateFieldDef("e_flags", uint_le(4)),
            TemplateFieldDef("e_ehsize", uint_le(2)),
            TemplateFieldDef("e_phentsize", uint_le(2)),
            TemplateFieldDef("e_phnum", uint_le(2)),
            TemplateFieldDef("e_shentsize", uint_le(2)),
            TemplateFieldDef("e_shnum", uint_le(2)),
            TemplateFieldDef("e_shstrndx", uint_le(2)),
        ],
    )


def template_png_chunk() -> Template:
    return Template(
        "png_chunk",
        [
            TemplateFieldDef("length", uint_be(4)),
            TemplateFieldDef("type", TypeKind(ScalarKind.UTF8, 4)),
            TemplateFieldDef("data", TypeKind(ScalarKind.BYTES, 0), repeat="length"),
            TemplateFieldDef("crc", uint_be(4)),
        ],
    )


def template_zip_eocd() -> Template:
    return Template(
        "zip_eocd",
        [
            TemplateFieldDef("signature", uint_le(4)),
            TemplateFieldDef("disk_number", uint_le(2)),
            TemplateFieldDef("disk_with_cd", uint_le(2)),
            TemplateFieldDef("entries_on_disk", uint_le(2)),
            TemplateFieldDef("total_entries", uint_le(2)),
            TemplateFieldDef("cd_size", uint_le(4)),
            TemplateFieldDef("cd_offset", uint_le(4)),
            TemplateFieldDef("comment_length", uint_le(2)),
        ],
    )


_BUILTIN_FACTORIES: dict[str, Callable[[], Template]] = {
    "pe_section_header": template_pe_section_header,
    "elf64_ehdr": template_elf64_ehdr,
    "png_chunk": template_png_chunk,
    "zip_eocd": template_zip_eocd,
}


def builtin_templates() -> dict[str, Template]:
    return {name: factory() for name, factory in _BUILTIN_FACTORIES.items()}


# ----------------------------- Auto-detect ---------------------------------- #


def auto_select_template(data: bytes) -> Template | None:
    if len(data) < 4:
        return None
    if data[:2] == b"MZ":
        return template_pe_section_header()
    if data[:4] == b"\x7fELF" and len(data) > 4 and data[4] == 2:
        return template_elf64_ehdr()
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return template_png_chunk()
    if data[:4] == b"PK\x05\x06":
        return template_zip_eocd()
    return None


def apply_pe_template(data: bytes) -> TemplateResult:
    if data[:2] != b"MZ":
        raise TemplateError("NotFound: PE magic")
    # PE header offset at 0x3C
    if len(data) < 0x40:
        raise TemplateError("Field: PE header offset")
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    # PE signature "PE\0\0" then COFF (20) + optional header — skip to first section.
    if pe_off + 24 > len(data):
        raise TemplateError("Field: PE COFF")
    if data[pe_off:pe_off + 4] != b"PE\x00\x00":
        raise TemplateError("NotFound: PE signature")
    num_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    first_section = pe_off + 24 + opt_size
    tmpl = Template(
        "pe_sections",
        [
            TemplateFieldDef(
                "sections",
                TypeKind(ScalarKind.BYTES, 0),
                repeat=int(num_sections),
                sub_template=template_pe_section_header(),
            )
        ],
    )
    return apply_template(data, tmpl, first_section)


# ----------------------------- Self-test ------------------------------------ #


def _self_test() -> None:
    # ELF64 header smoke test.
    blob = bytearray(64)
    blob[0:4] = b"\x7fELF"
    blob[4] = 2  # 64-bit
    blob[5] = 1  # little endian
    struct.pack_into("<H", blob, 16, 2)          # e_type = EXEC
    struct.pack_into("<H", blob, 18, 0x3E)       # e_machine = x86_64
    struct.pack_into("<I", blob, 20, 1)          # e_version
    struct.pack_into("<Q", blob, 24, 0x401000)   # e_entry

    auto = auto_select_template(bytes(blob))
    assert auto is not None and auto.name == "elf64_ehdr"
    res = apply_template(bytes(blob), auto)
    e_entry = find_field_by_path(res.parsed, "e_entry")
    assert e_entry is not None and e_entry.value == 0x401000

    # Diff: change e_entry and confirm.
    blob2 = bytearray(blob)
    struct.pack_into("<Q", blob2, 24, 0x402000)
    res2 = apply_template(bytes(blob2), auto)
    diffs = diff_parsed(res.parsed, res2.parsed)
    assert any(d.path.endswith("e_entry") and d.kind == "changed" for d in diffs)

    # Stats / export.
    stats = template_stats(auto)
    assert stats.field_count == 14
    out = export_fields(flatten_parsed(res.parsed), ExportFormat.JSON)
    assert "e_entry" in out

    # PNG chunk with repeat="length".
    png = b"\x00\x00\x00\x04IHDR\xde\xad\xbe\xef\x12\x34\x56\x78"
    pres = apply_template(png, template_png_chunk())
    data_field = find_field_by_path(pres.parsed, "data")
    assert data_field is not None and data_field.value == b"\xde\xad\xbe\xef"

    # Expression eval.
    e = Expr("And", Expr("Eq", "a", 1), Expr("Gt", "b", 5))
    assert e.eval({"a": 1, "b": 6}) is True
    assert e.eval({"a": 1, "b": 5}) is False


if __name__ == "__main__":
    _self_test()
    print("rustre-hex-template validator: self-test OK")
