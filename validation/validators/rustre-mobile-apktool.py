"""Independent validator for rustre-mobile-apktool crate.

Reimplements pure-logic primitives described in
validation/reports/rustre-mobile-apktool.md using only Python stdlib.
"""

import json
import os
from typing import Optional


# ---------- ApktoolError ----------
class ApktoolError(Exception):
    def __init__(self, kind: str, msg: str):
        super().__init__(f"{kind}: {msg}")
        self.kind = kind
        self.msg = msg


# ---------- ApktoolConfig ----------
class ApktoolConfig:
    def __init__(self, apktool_path: str, output_dir: str):
        self.apktool_path = apktool_path
        self.output_dir = output_dir
        self.no_src = False
        self.no_res = False
        self.force = False

    def with_no_src(self):
        self.no_src = True
        return self

    def with_no_res(self):
        self.no_res = True
        return self

    def with_force(self):
        self.force = True
        return self

    def to_dict(self):
        return {
            "apktool_path": self.apktool_path,
            "output_dir": self.output_dir,
            "no_src": self.no_src,
            "no_res": self.no_res,
            "force": self.force,
        }

    def cli_decode_args(self, apk: str) -> list:
        args = ["d", apk, "-o", self.output_dir]
        if self.no_src:
            args.append("--no-src")
        if self.no_res:
            args.append("--no-res")
        if self.force:
            args.append("-f")
        return args


# ---------- DecodeResult ----------
class DecodeResult:
    def __init__(self, output_dir, smali_dirs, res_dir, success, log):
        self.output_dir = output_dir
        self.smali_dirs = smali_dirs
        self.res_dir = res_dir
        self.success = success
        self.log = log

    def smali_count(self) -> int:
        return len(self.smali_dirs)


# ---------- ApkDecodeResult ----------
class ApkDecodeResult:
    def __init__(self, output_dir, smali_dirs, res_dir, manifest_path, warnings):
        self.output_dir = output_dir
        self.smali_dirs = smali_dirs
        self.res_dir = res_dir
        self.manifest_path = manifest_path
        self.warnings = warnings

    def smali_count(self) -> int:
        return len(self.smali_dirs)

    def is_clean(self) -> bool:
        return len(self.warnings) == 0


# ---------- CliApktoolRunner log classifier ----------
def is_failure_log_line(line: str) -> bool:
    return line.startswith("I: E:") or line.startswith("E: ") or line.startswith("brut.")


def classify_log(log: str, exit_code: int) -> bool:
    """Return success bool: non-zero exit OR any failure line => fail."""
    if exit_code != 0:
        return False
    for line in log.splitlines():
        if is_failure_log_line(line):
            return False
    return True


def find_smali_dirs(entries: list) -> list:
    """Filter dir entries whose name starts with 'smali'."""
    return sorted([e for e in entries if e.startswith("smali")])


# ---------- ApktoolRunnerImpl (structural) ----------
class ApktoolRunnerImpl:
    def __init__(self, config: ApktoolConfig):
        self.config = config

    def decode(self, apk_path: str) -> ApkDecodeResult:
        if not apk_path.endswith(".apk"):
            raise ApktoolError("Decode", "not an .apk file")
        out = self.config.output_dir
        return ApkDecodeResult(
            output_dir=out,
            smali_dirs=[os.path.join(out, "smali")],
            res_dir=os.path.join(out, "res"),
            manifest_path=os.path.join(out, "AndroidManifest.xml"),
            warnings=[],
        )

    def build(self, dir_: str):
        if not dir_:
            raise ApktoolError("Build", "empty dir")
        basename = os.path.basename(dir_.rstrip("/\\")) or "app"
        apk_path = os.path.join(self.config.output_dir, "dist", f"{basename}.apk")
        return {"apk_path": apk_path, "unsigned": True, "size_bytes": 0}

    def install_framework(self, apk_path: str):
        if not apk_path.endswith(".apk"):
            raise ApktoolError("Decode", "not an .apk file")
        return True


# ---------- find_apktool emulation ----------
def find_apktool(env: dict, path_dirs: list, is_windows: bool) -> Optional[str]:
    if "APKTOOL_PATH" in env and env["APKTOOL_PATH"]:
        return env["APKTOOL_PATH"]
    for d in path_dirs:
        cand = os.path.join(d, "apktool")
        if cand:
            return cand
    if is_windows:
        for d in path_dirs:
            cand = os.path.join(d, "apktool.bat")
            if cand:
                return cand
    return None


# ---------- validation functions ----------
def fn_config_defaults():
    c = ApktoolConfig("apktool", "out")
    return c.to_dict()


def fn_config_builders():
    c = ApktoolConfig("apktool", "out").with_no_src().with_no_res().with_force()
    return c.to_dict()


def fn_cli_decode_args():
    c = ApktoolConfig("apktool", "out").with_no_src().with_force()
    return c.cli_decode_args("app.apk")


def fn_decode_result_smali_count():
    r = DecodeResult("out", ["out/smali", "out/smali_classes2"], "out/res", True, "")
    return {"count": r.smali_count()}


def fn_classify_log():
    return {
        "ok_zero_exit": classify_log("I: Using Apktool\n", 0),
        "fail_nonzero": classify_log("I: ok\n", 1),
        "fail_E_line": classify_log("E: error doing thing\n", 0),
        "fail_brut_line": classify_log("brut.androlib.AndrolibException: x\n", 0),
        "fail_I_E_line": classify_log("I: E: Could not decode\n", 0),
    }


def fn_find_smali_dirs():
    entries = ["smali", "smali_classes2", "res", "AndroidManifest.xml", "smali_classes3", "lib"]
    return find_smali_dirs(entries)


def fn_runner_impl_decode():
    c = ApktoolConfig("apktool", "out")
    r = ApktoolRunnerImpl(c).decode("app.apk")
    return {
        "output_dir": r.output_dir,
        "smali_dirs": r.smali_dirs,
        "res_dir": r.res_dir,
        "manifest_path": r.manifest_path,
        "smali_count": r.smali_count(),
        "is_clean": r.is_clean(),
    }


def fn_runner_impl_decode_rejects_non_apk():
    c = ApktoolConfig("apktool", "out")
    try:
        ApktoolRunnerImpl(c).decode("app.zip")
        return {"raised": False}
    except ApktoolError as e:
        return {"raised": True, "kind": e.kind}


def fn_runner_impl_build_empty():
    c = ApktoolConfig("apktool", "out")
    try:
        ApktoolRunnerImpl(c).build("")
        return {"raised": False}
    except ApktoolError as e:
        return {"raised": True, "kind": e.kind}


def fn_runner_impl_build_ok():
    c = ApktoolConfig("apktool", "out")
    return ApktoolRunnerImpl(c).build("project_dir")


def fn_find_apktool_env():
    return {
        "from_env": find_apktool({"APKTOOL_PATH": "/opt/apktool"}, ["/usr/bin"], False),
        "from_path_unix": find_apktool({}, ["/usr/local/bin"], False),
        "from_path_win": find_apktool({}, ["C:/tools"], True),
        "none": find_apktool({}, [], False),
    }


FUNCTIONS = [
    ("config_defaults", fn_config_defaults),
    ("config_builders", fn_config_builders),
    ("cli_decode_args", fn_cli_decode_args),
    ("decode_result_smali_count", fn_decode_result_smali_count),
    ("classify_log", fn_classify_log),
    ("find_smali_dirs", fn_find_smali_dirs),
    ("runner_impl_decode", fn_runner_impl_decode),
    ("runner_impl_decode_rejects_non_apk", fn_runner_impl_decode_rejects_non_apk),
    ("runner_impl_build_empty", fn_runner_impl_build_empty),
    ("runner_impl_build_ok", fn_runner_impl_build_ok),
    ("find_apktool", fn_find_apktool_env),
]


def main():
    results = []
    for name, fn in FUNCTIONS:
        try:
            results.append({"name": name, "ok": True, "result": fn()})
        except Exception as e:
            results.append({"name": name, "ok": False, "error": str(e)})
    out = {"crate": "rustre-mobile-apktool", "saved": True, "functions": results}
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    main()
