#!/usr/bin/env python3
"""
Standalone validator for the `rustre-demangle` crate.

Implements the same logic as the Rust crate in pure Python (stdlib + optional
external CLIs like `c++filt`, `undname.exe`, `swift demangle`) so results can
be cross-checked against the crate / MCP tool output.

Usage:
    # JSON-on-stdin mode
    echo '{"function":"demangle","input":"_ZN3std2io5stdio6_print17h..."}' \
        | python rustre-demangle.py
    # Self-test
    python rustre-demangle.py --self-test
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Pure helpers — direct ports of the trivial public functions
# ---------------------------------------------------------------------------

_ITANIUM_NESTED_RE = re.compile(r"_ZN.*?([CD][0-9])")
_ITANIUM_CTOR_RE = re.compile(r"_ZN.*C[123]E")
_ITANIUM_DTOR_RE = re.compile(r"_ZN.*D[012]E")

_STD_SUBST = {
    "St": "std",
    "Sa": "std::allocator",
    "Sb": "std::basic_string",
    "Ss": "std::string",
    "Si": "std::istream",
    "So": "std::ostream",
    "Sd": "std::iostream",
}

_MSVC_CC = {
    "A": "Cdecl",      # __cdecl near
    "B": "Cdecl",      # __cdecl far
    "C": "Pascal",
    "D": "Pascal",
    "E": "Thiscall",
    "F": "Thiscall",
    "G": "Stdcall",
    "H": "Stdcall",
    "I": "Fastcall",
    "J": "Fastcall",
    "K": "Unknown",
    "L": "Unknown",
    "M": "Clrcall",
    "N": "Clrcall",
    "O": "Vectorcall",
    "P": "Vectorcall",
    "Q": "Clrcall",
    "R": "Clrcall",
}

_MSVC_RTTI_KIND = {
    "0": "Type Descriptor",
    "1": "Base Class Descriptor",
    "2": "Base Class Array",
    "3": "Class Hierarchy Descriptor",
    "4": "Complete Object Locator",
}


def validator_is_constructor(mangled: str) -> bool:
    return bool(_ITANIUM_CTOR_RE.search(mangled))


def validator_is_destructor(mangled: str) -> bool:
    return bool(_ITANIUM_DTOR_RE.search(mangled))


def validator_is_vtable(mangled: str) -> bool:
    return mangled.startswith("_ZTV")


def validator_is_typeinfo(mangled: str) -> bool:
    return mangled.startswith("_ZTI") or mangled.startswith("_ZTS")


def validator_standard_substitution(code: str) -> Optional[str]:
    return _STD_SUBST.get(code)


def validator_msvc_calling_convention(code: str) -> str:
    if isinstance(code, int):
        code = chr(code)
    return _MSVC_CC.get(code, "Unknown")


def validator_normalize_type(ty: str) -> str:
    """Collapse whitespace, normalise pointer/ref qualifier spacing. Idempotent."""
    s = re.sub(r"\s+", " ", ty.strip())
    s = re.sub(r"\s*([*&,<>()])\s*", r"\1", s)
    s = re.sub(r",", ", ", s)
    s = re.sub(r"\bconst\b", "const", s)
    return s.strip()


# ---------------------------------------------------------------------------
# ABI detection (mirrors AutoDemangler::detect dispatch)
# ---------------------------------------------------------------------------

def _detect_abi(s: str) -> Optional[str]:
    if not s:
        return None
    if s.startswith("_R"):
        return "rust-v0"
    if s.startswith("_ZN") and "17h" in s and s.endswith("E"):
        # Legacy rust hash suffix
        return "rust-legacy"
    if s.startswith("_Z") or s.startswith("__Z"):
        return "itanium"
    if s.startswith("?") or s.startswith(".?"):
        return "msvc"
    if s.startswith("$s") or s.startswith("$S") or s.startswith("_T0") or s.startswith("_$s"):
        return "swift"
    if s.startswith("_D") and len(s) > 2 and s[2].isdigit():
        return "d"
    if s.startswith("-[") or s.startswith("+["):
        return "objc"
    return None


# ---------------------------------------------------------------------------
# Demangling via external oracle CLIs
# ---------------------------------------------------------------------------

def _run(cmd: list[str], inp: Optional[str] = None) -> Optional[str]:
    try:
        r = subprocess.run(
            cmd, input=inp, capture_output=True, text=True, timeout=10
        )
        if r.returncode != 0:
            return None
        return r.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _cppfilt(sym: str) -> Optional[str]:
    exe = shutil.which("c++filt") or shutil.which("c++filt.exe")
    if not exe:
        return None
    out = _run([exe, "-n", sym])
    if out and out != sym:
        return out
    return None


def _undname(sym: str) -> Optional[str]:
    exe = shutil.which("undname") or shutil.which("undname.exe")
    if not exe:
        return None
    out = _run([exe, sym])
    if not out:
        return None
    # undname prints lines like:  is :- "demangled name"
    m = re.search(r'is :- "(.*)"', out)
    if m:
        return m.group(1)
    return out


def _swift_demangle(sym: str) -> Optional[str]:
    exe = shutil.which("swift-demangle") or shutil.which("swift")
    if not exe:
        return None
    if exe.endswith("swift") or exe.endswith("swift.exe"):
        out = _run([exe, "demangle", "-compact", sym])
    else:
        out = _run([exe, "-compact", sym])
    if not out:
        return None
    m = re.search(r"-+>\s*(.*)", out)
    return m.group(1).strip() if m else out


# ---------------------------------------------------------------------------
# Pure-python Itanium / Rust-legacy partial parser
# ---------------------------------------------------------------------------

def _parse_itanium_nested(s: str) -> Optional[dict[str, Any]]:
    """
    Parse a `_ZN <len><name>...E` symbol into namespace components.
    Returns None on parse failure. Doesn't try to handle templates/args.
    """
    if not s.startswith("_ZN"):
        return None
    i = 3
    parts: list[str] = []
    while i < len(s) and s[i] != "E":
        j = i
        while j < len(s) and s[j].isdigit():
            j += 1
        if j == i:
            break
        try:
            n = int(s[i:j])
        except ValueError:
            return None
        i = j
        if i + n > len(s):
            return None
        parts.append(s[i:i + n])
        i += n
    if not parts:
        return None
    return {
        "namespace": "::".join(parts[:-1]) if len(parts) > 1 else "",
        "class": parts[-2] if len(parts) >= 2 else "",
        "function": parts[-1],
        "components": parts,
    }


def _strip_rust_hash(name: str) -> str:
    return re.sub(r"::h[0-9a-f]{16}$", "", name)


def validator_demangle(mangled: str) -> Optional[dict[str, Any]]:
    abi = _detect_abi(mangled)
    if abi is None:
        return None

    demangled: Optional[str] = None
    if abi in ("rust-legacy", "itanium"):
        demangled = _cppfilt(mangled)
        if demangled is None:
            parsed = _parse_itanium_nested(mangled)
            if parsed:
                demangled = "::".join(parsed["components"])
        if demangled and abi == "rust-legacy":
            demangled = _strip_rust_hash(demangled)
    elif abi == "rust-v0":
        demangled = _cppfilt(mangled) or mangled
    elif abi == "msvc":
        demangled = _undname(mangled)
    elif abi == "swift":
        demangled = _swift_demangle(mangled)
    elif abi == "objc":
        demangled = mangled  # already readable

    if demangled is None:
        return None

    parsed = _parse_itanium_nested(mangled) or {}
    return {
        "original": mangled,
        "demangled": demangled,
        "abi": abi,
        "namespace": parsed.get("namespace", ""),
        "class": parsed.get("class", ""),
        "function": parsed.get("function", ""),
        "args": None,
        "return_type": None,
    }


def validator_demangle_msvc_rtti(mangled: str) -> Optional[str]:
    m = re.match(r"\?\?_R([0-4])(.*)", mangled)
    if not m:
        return None
    kind = _MSVC_RTTI_KIND.get(m.group(1), "Unknown")
    rest = m.group(2)
    type_name = _undname("??_R0?AV" + rest) or rest
    return f"RTTI {kind}: {type_name}"


def validator_batch_demangle(symbols: list[str]) -> list[dict[str, Any]]:
    return [validator_demangle(s) or {"original": s, "demangled": None, "abi": None}
            for s in symbols]


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

FUNCTIONS = {
    "demangle": lambda inp: validator_demangle(inp["mangled"]),
    "batch_demangle": lambda inp: validator_batch_demangle(inp["symbols"]),
    "batch_demangle_parallel": lambda inp: validator_batch_demangle(inp["symbols"]),
    "is_constructor": lambda inp: validator_is_constructor(inp["mangled"]),
    "is_destructor": lambda inp: validator_is_destructor(inp["mangled"]),
    "is_vtable": lambda inp: validator_is_vtable(inp["mangled"]),
    "is_typeinfo": lambda inp: validator_is_typeinfo(inp["mangled"]),
    "standard_substitution": lambda inp: validator_standard_substitution(inp["code"]),
    "msvc_calling_convention": lambda inp: validator_msvc_calling_convention(inp["code"]),
    "demangle_msvc_rtti": lambda inp: validator_demangle_msvc_rtti(inp["mangled"]),
    "normalize_type": lambda inp: validator_normalize_type(inp["ty"]),
}


def main() -> int:
    if "--self-test" in sys.argv:
        report: dict[str, Any] = {}
        report["is_vtable(_ZTV3Foo)"] = validator_is_vtable("_ZTV3Foo")
        report["is_typeinfo(_ZTI3Foo)"] = validator_is_typeinfo("_ZTI3Foo")
        report["is_constructor(_ZN3FooC1Ev)"] = validator_is_constructor("_ZN3FooC1Ev")
        report["is_destructor(_ZN3FooD0Ev)"] = validator_is_destructor("_ZN3FooD0Ev")
        report["std_sub(St)"] = validator_standard_substitution("St")
        report["std_sub(Sx)"] = validator_standard_substitution("Sx")
        report["msvc_cc(A)"] = validator_msvc_calling_convention("A")
        report["msvc_cc(I)"] = validator_msvc_calling_convention("I")
        report["normalize_type"] = validator_normalize_type("const  std::string  *  ")
        report["parse_itanium"] = _parse_itanium_nested("_ZN3std2io5stdioE")
        report["demangle_v0"] = _detect_abi("_RNvCs1234_5crate3foo")
        print(json.dumps(report, indent=2))
        return 0

    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"invalid json: {e}"}))
        return 1

    fname = payload.get("function")
    inp = payload.get("input", {})
    fn = FUNCTIONS.get(fname)
    if fn is None:
        print(json.dumps({"error": f"unknown function {fname!r}",
                          "available": list(FUNCTIONS)}))
        return 1
    try:
        result = fn(inp)
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"error": f"{type(e).__name__}: {e}"}))
        return 1
    print(json.dumps({"function": fname, "output": result}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
