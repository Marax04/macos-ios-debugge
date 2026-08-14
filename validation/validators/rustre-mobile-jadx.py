"""Independent validator for rustre-mobile-jadx crate.

Reimplements pure-logic primitives described in
validation/reports/rustre-mobile-jadx.md using only Python stdlib.
Focuses on the Dalvik opcode table, FQCN-to-path mapping, JADX CLI
argument construction, and `DecompiledProject.success_rate` math --
the parts that don't require an actual `jadx` binary.
"""

import json
import os
from typing import Optional


# ---------- Dalvik opcode table (per report) ----------
DALVIK_OPCODES = {
    0x0a: "move-result",
    0x0e: "return-void",
    0x0f: "return",
    0x12: "const/4",
    0x1a: "const-string",
    0x22: "new-instance",
    0x28: "goto",
    0x32: "if-eq",
    0x33: "if-ne",
    0x34: "if-lt",
    0x35: "if-ge",
    0x36: "if-gt",
    0x37: "if-le",
    0x54: "iget",
    0x59: "iput",
    0x6e: "invoke-virtual",
    0x70: "invoke-direct",
    0x71: "invoke-static",
    0x90: "add-int",
    0x91: "sub-int",
    0x92: "mul-int",
}


def opcode_from_byte(b: int) -> Optional[str]:
    return DALVIK_OPCODES.get(b & 0xFF)


# ---------- FQCN -> sources/<path>.java (CliJadxRunner2.read_decompiled_class) ----------
def fqcn_to_source_path(out_dir: str, fqcn: str) -> str:
    rel = fqcn.replace(".", "/") + ".java"
    return os.path.join(out_dir, "sources", rel).replace("\\", "/")


# ---------- jadx CLI argv construction (CliJadxRunner.decompile) ----------
def build_jadx_argv(
    jadx_path: str,
    apk: str,
    out: str,
    deobfuscate: bool = False,
    show_inconsistent_code: bool = False,
    no_res: bool = False,
    threads: Optional[int] = None,
) -> list:
    argv = [jadx_path, "--output-dir", out]
    if deobfuscate:
        argv.append("--deobf")
    if show_inconsistent_code:
        argv.append("--show-bad-code")
    if no_res:
        argv.append("--no-res")
    if threads is not None:
        argv += ["--threads-count", str(threads)]
    argv.append(apk)
    return argv


# ---------- DecompiledProject.success_rate ----------
def success_rate(total: int, failed: int) -> float:
    if total == 0:
        return 0.0
    return (total - failed) / total


# ---------- JadxConfig::find_jadx env/PATH order ----------
JADX_PATH_CANDIDATES = [
    "jadx",
    "jadx.bat",
    "jadx-gui",
]

COMMON_INSTALL_DIRS = [
    "/usr/local/bin",
    "/usr/bin",
    "/opt/jadx/bin",
    "/Applications/jadx/bin",
    "C:/Program Files/jadx/bin",
    "C:/jadx/bin",
]


def find_jadx_order(env: dict) -> list:
    """Returns the lookup order the report describes."""
    order = []
    if env.get("JADX_PATH"):
        order.append(("env:JADX_PATH", env["JADX_PATH"]))
    for name in JADX_PATH_CANDIDATES:
        order.append(("PATH", name))
    for d in COMMON_INSTALL_DIRS:
        for name in JADX_PATH_CANDIDATES:
            order.append(("install", f"{d}/{name}"))
    return order


# ---------- validation functions ----------
def fn_opcode_table():
    return {
        "count": len(DALVIK_OPCODES),
        "return_void": opcode_from_byte(0x0e),
        "const_string": opcode_from_byte(0x1a),
        "invoke_virtual": opcode_from_byte(0x6e),
        "invoke_static": opcode_from_byte(0x71),
        "add_int": opcode_from_byte(0x90),
        "if_le": opcode_from_byte(0x37),
        "unknown_ff": opcode_from_byte(0xff),
    }


def fn_fqcn_to_path():
    return {
        "simple": fqcn_to_source_path("out", "com.example.Foo"),
        "inner": fqcn_to_source_path("/tmp/x", "a.b.c.Outer$Inner"),
        "root": fqcn_to_source_path("out", "Foo"),
    }


def fn_build_argv():
    return {
        "minimal": build_jadx_argv("jadx", "app.apk", "out"),
        "deobf": build_jadx_argv("jadx", "app.apk", "out", deobfuscate=True),
        "all_flags": build_jadx_argv(
            "/usr/bin/jadx", "a.apk", "/tmp/o",
            deobfuscate=True, show_inconsistent_code=True, no_res=True,
            threads=4,
        ),
    }


def fn_success_rate():
    return {
        "zero_total": success_rate(0, 0),
        "all_ok": success_rate(10, 0),
        "half": success_rate(10, 5),
        "all_fail": success_rate(7, 7),
    }


def fn_find_order():
    no_env = find_jadx_order({})
    with_env = find_jadx_order({"JADX_PATH": "/custom/jadx"})
    return {
        "no_env_first": no_env[0],
        "no_env_count": len(no_env),
        "with_env_first": with_env[0],
        "with_env_second": with_env[1],
    }


FUNCTIONS = [
    ("opcode_table", fn_opcode_table),
    ("fqcn_to_path", fn_fqcn_to_path),
    ("build_argv", fn_build_argv),
    ("success_rate", fn_success_rate),
    ("find_jadx_order", fn_find_order),
]


def main():
    results = []
    for name, fn in FUNCTIONS:
        try:
            results.append({"name": name, "ok": True, "result": fn()})
        except Exception as e:
            results.append({"name": name, "ok": False, "error": str(e)})
    out = {"crate": "rustre-mobile-jadx", "saved": True, "functions": results}
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    main()
