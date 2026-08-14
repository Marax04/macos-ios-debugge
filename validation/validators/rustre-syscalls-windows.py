"""Independent validator for rustre-syscalls-windows crate.

Reimplements pure-logic primitives described in
validation/reports/rustre-syscalls-windows.md using only Python stdlib,
producing expected results to compare against the Rust crate.
"""

import json


# ---------- NTSTATUS table (subset of common values) ----------
NTSTATUS_NAMES = {
    0x00000000: "STATUS_SUCCESS",
    0x00000001: "STATUS_WAIT_1",
    0x00000080: "STATUS_ABANDONED",
    0x000000C0: "STATUS_USER_APC",
    0x00000102: "STATUS_TIMEOUT",
    0x00000103: "STATUS_PENDING",
    0x80000005: "STATUS_BUFFER_OVERFLOW",
    0x8000000D: "STATUS_PARTIAL_COPY",
    0xC0000001: "STATUS_UNSUCCESSFUL",
    0xC0000002: "STATUS_NOT_IMPLEMENTED",
    0xC0000005: "STATUS_ACCESS_VIOLATION",
    0xC000000D: "STATUS_INVALID_PARAMETER",
    0xC0000022: "STATUS_ACCESS_DENIED",
    0xC0000023: "STATUS_BUFFER_TOO_SMALL",
    0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
    0xC0000035: "STATUS_OBJECT_NAME_COLLISION",
    0xC000003A: "STATUS_OBJECT_PATH_NOT_FOUND",
    0xC0000061: "STATUS_PRIVILEGE_NOT_HELD",
    0xC00000BB: "STATUS_NOT_SUPPORTED",
}

WINSOCK_ERRORS = {
    10004: "WSAEINTR",
    10013: "WSAEACCES",
    10014: "WSAEFAULT",
    10022: "WSAEINVAL",
    10024: "WSAEMFILE",
    10035: "WSAEWOULDBLOCK",
    10036: "WSAEINPROGRESS",
    10038: "WSAENOTSOCK",
    10048: "WSAEADDRINUSE",
    10049: "WSAEADDRNOTAVAIL",
    10050: "WSAENETDOWN",
    10051: "WSAENETUNREACH",
    10053: "WSAECONNABORTED",
    10054: "WSAECONNRESET",
    10060: "WSAETIMEDOUT",
    10061: "WSAECONNREFUSED",
}

DANGEROUS_PRIVILEGES = {
    "SeDebugPrivilege",
    "SeTcbPrivilege",
    "SeLoadDriverPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeRestorePrivilege",
    "SeBackupPrivilege",
    "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeCreateTokenPrivilege",
}

PERSISTENCE_KEYS = [
    r"\software\microsoft\windows\currentversion\run",
    r"\software\microsoft\windows\currentversion\runonce",
    r"\software\microsoft\windows nt\currentversion\winlogon",
    r"\system\currentcontrolset\services",
    r"\software\microsoft\windows\currentversion\explorer\shell folders",
    r"\software\microsoft\windows nt\currentversion\image file execution options",
]

SYSTEM_PATH_PREFIXES = [
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows\winsxs",
    r"c:\windows\system",
    r"c:\program files",
    r"c:\program files (x86)",
]

# ACCESS_MASK flags (file)
FILE_ACCESS_FLAGS = [
    (0x00000001, "FILE_READ_DATA"),
    (0x00000002, "FILE_WRITE_DATA"),
    (0x00000004, "FILE_APPEND_DATA"),
    (0x00000008, "FILE_READ_EA"),
    (0x00000010, "FILE_WRITE_EA"),
    (0x00000020, "FILE_EXECUTE"),
    (0x00000080, "FILE_READ_ATTRIBUTES"),
    (0x00000100, "FILE_WRITE_ATTRIBUTES"),
    (0x00010000, "DELETE"),
    (0x00020000, "READ_CONTROL"),
    (0x00040000, "WRITE_DAC"),
    (0x00080000, "WRITE_OWNER"),
    (0x00100000, "SYNCHRONIZE"),
    (0x10000000, "GENERIC_ALL"),
    (0x20000000, "GENERIC_EXECUTE"),
    (0x40000000, "GENERIC_WRITE"),
    (0x80000000, "GENERIC_READ"),
]

ALLOC_TYPE_FLAGS = [
    (0x00001000, "MEM_COMMIT"),
    (0x00002000, "MEM_RESERVE"),
    (0x00004000, "MEM_DECOMMIT"),
    (0x00008000, "MEM_RELEASE"),
    (0x00010000, "MEM_FREE"),
    (0x00020000, "MEM_PRIVATE"),
    (0x00040000, "MEM_MAPPED"),
    (0x00080000, "MEM_RESET"),
    (0x00100000, "MEM_TOP_DOWN"),
    (0x00200000, "MEM_WRITE_WATCH"),
    (0x00400000, "MEM_PHYSICAL"),
    (0x20000000, "MEM_LARGE_PAGES"),
]

CLEAN_X64_STUB_PREFIX = bytes([0x4C, 0x8B, 0xD1])  # mov r10, rcx


# ---------- helpers ----------
def format_ntstatus(code: int) -> str:
    name = NTSTATUS_NAMES.get(code & 0xFFFFFFFF, "UNKNOWN")
    return f"0x{code & 0xFFFFFFFF:X} ({name})"


def decode_ntstatus(code: int) -> str:
    return NTSTATUS_NAMES.get(code & 0xFFFFFFFF, "UNKNOWN")


def ntstatus_name(code: int):
    return NTSTATUS_NAMES.get(code & 0xFFFFFFFF)


def winsock_error_name(code: int):
    return WINSOCK_ERRORS.get(code)


def nt_to_win32_path(nt_path: str) -> str:
    if nt_path.startswith(r"\??\\"):
        return nt_path[4:]
    if nt_path.startswith(r"\??\\"[:-1] + "\\"):
        return nt_path[4:]
    if nt_path.startswith(r"\??\\"[:4]):
        return nt_path[4:]
    if nt_path.startswith(r"\DosDevices\\"):
        return nt_path[len(r"\DosDevices\\") - 1:]
    if nt_path.startswith(r"\SystemRoot"):
        return r"C:\Windows" + nt_path[len(r"\SystemRoot"):]
    return nt_path


def nt_to_win32_reg_path(nt_path: str) -> str:
    p = nt_path
    if p.startswith(r"\REGISTRY\MACHINE"):
        return "HKLM" + p[len(r"\REGISTRY\MACHINE"):]
    if p.startswith(r"\REGISTRY\USER"):
        return "HKU" + p[len(r"\REGISTRY\USER"):]
    if p.startswith(r"\Registry\Machine"):
        return "HKLM" + p[len(r"\Registry\Machine"):]
    if p.startswith(r"\Registry\User"):
        return "HKU" + p[len(r"\Registry\User"):]
    return p


def is_system_path(path: str) -> bool:
    low = path.lower()
    return any(low.startswith(p) for p in SYSTEM_PATH_PREFIXES)


def is_dangerous_privilege(name: str) -> bool:
    return name in DANGEROUS_PRIVILEGES


def is_persistence_registry_key(path: str) -> bool:
    low = path.lower()
    return any(k in low for k in PERSISTENCE_KEYS)


def decode_file_access(access: int) -> str:
    flags = [name for bit, name in FILE_ACCESS_FLAGS if access & bit]
    return " | ".join(flags) if flags else "0"


def decode_alloc_type(alloc_type: int) -> str:
    flags = [name for bit, name in ALLOC_TYPE_FLAGS if alloc_type & bit]
    return " | ".join(flags) if flags else "0"


def is_clean_x64_stub(stub: bytes, expected_ssn: int) -> bool:
    # 4C 8B D1 B8 <ssn:u32-le>
    if len(stub) < 8:
        return False
    if stub[:3] != CLEAN_X64_STUB_PREFIX:
        return False
    if stub[3] != 0xB8:
        return False
    ssn = stub[4] | (stub[5] << 8) | (stub[6] << 16) | (stub[7] << 24)
    return ssn == expected_ssn


def is_clean_x86_stub(stub: bytes, expected_ssn: int) -> bool:
    # B8 <ssn:u32-le> ...
    if len(stub) < 5:
        return False
    if stub[0] != 0xB8:
        return False
    ssn = stub[1] | (stub[2] << 8) | (stub[3] << 16) | (stub[4] << 24)
    return ssn == expected_ssn


def detect_hook_type(stub: bytes) -> str:
    if len(stub) == 0:
        return "Unknown"
    b0 = stub[0]
    # Common inline hook opcodes
    if b0 in (0xE9, 0xEB):
        return "InlineHook"   # JMP rel32 / short
    if b0 == 0xFF and len(stub) > 1 and stub[1] in (0x25, 0x15):
        return "IatHook"      # JMP [mem] / CALL [mem]
    if b0 == 0x68:
        return "InlineHook"   # PUSH imm32 + RET trick
    if b0 == 0x4C and len(stub) >= 3 and stub[1] == 0x8B and stub[2] == 0xD1:
        return "Clean"
    if b0 == 0xB8:
        return "Clean"
    return "Unknown"


# ---------- validation functions ----------
def fn_format_ntstatus():
    return {
        "success": format_ntstatus(0x00000000),
        "access_violation": format_ntstatus(0xC0000005),
        "access_denied": format_ntstatus(0xC0000022),
        "unknown": format_ntstatus(0xDEADBEEF),
    }


def fn_decode_ntstatus():
    return {
        "0x0": decode_ntstatus(0x0),
        "0xC0000005": decode_ntstatus(0xC0000005),
        "0xC0000034": decode_ntstatus(0xC0000034),
    }


def fn_ntstatus_name():
    return {
        "success": ntstatus_name(0),
        "pending": ntstatus_name(0x103),
        "unknown_none": ntstatus_name(0x12345678),
    }


def fn_winsock_error_name():
    return {
        "WSAEINTR": winsock_error_name(10004),
        "WSAECONNRESET": winsock_error_name(10054),
        "unknown_none": winsock_error_name(99999),
    }


def fn_nt_to_win32_path():
    return {
        "dos": nt_to_win32_path(r"\??\C:\Windows\System32\cmd.exe"),
        "systemroot": nt_to_win32_path(r"\SystemRoot\System32\ntdll.dll"),
        "passthrough": nt_to_win32_path(r"C:\foo"),
    }


def fn_nt_to_win32_reg_path():
    return {
        "hklm": nt_to_win32_reg_path(r"\REGISTRY\MACHINE\Software\Microsoft"),
        "hku": nt_to_win32_reg_path(r"\REGISTRY\USER\S-1-5-21"),
        "passthrough": nt_to_win32_reg_path(r"HKLM\foo"),
    }


def fn_is_system_path():
    return {
        "system32": is_system_path(r"C:\Windows\System32\kernel32.dll"),
        "progfiles": is_system_path(r"C:\Program Files\App\app.exe"),
        "userdir": is_system_path(r"C:\Users\Foo\Desktop\evil.exe"),
    }


def fn_is_dangerous_privilege():
    return {
        "SeDebugPrivilege": is_dangerous_privilege("SeDebugPrivilege"),
        "SeTcbPrivilege": is_dangerous_privilege("SeTcbPrivilege"),
        "SeShutdownPrivilege": is_dangerous_privilege("SeShutdownPrivilege"),
    }


def fn_is_persistence_registry_key():
    return {
        "run": is_persistence_registry_key(
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"),
        "services": is_persistence_registry_key(
            r"HKLM\System\CurrentControlSet\Services\evil"),
        "benign": is_persistence_registry_key(r"HKLM\Software\Foo\Bar"),
    }


def fn_decode_file_access():
    return {
        "read_write": decode_file_access(0x00000001 | 0x00000002),
        "generic_read": decode_file_access(0x80000000),
        "zero": decode_file_access(0),
    }


def fn_decode_alloc_type():
    return {
        "commit_reserve": decode_alloc_type(0x1000 | 0x2000),
        "large_pages": decode_alloc_type(0x20000000),
        "zero": decode_alloc_type(0),
    }


def fn_is_clean_x64_stub():
    # 4C 8B D1 B8 55 00 00 00 -> SSN=0x55
    stub = bytes([0x4C, 0x8B, 0xD1, 0xB8, 0x55, 0x00, 0x00, 0x00, 0x0F, 0x05])
    return {
        "match": is_clean_x64_stub(stub, 0x55),
        "mismatch": is_clean_x64_stub(stub, 0x99),
        "too_short": is_clean_x64_stub(b"\x4C\x8B", 0x55),
        "bad_prefix": is_clean_x64_stub(b"\xE9\x00\x00\x00\x00\x00\x00\x00", 0x55),
    }


def fn_is_clean_x86_stub():
    stub = bytes([0xB8, 0x55, 0x00, 0x00, 0x00, 0xBA, 0x00, 0x03, 0xFE, 0x7F])
    return {
        "match": is_clean_x86_stub(stub, 0x55),
        "mismatch": is_clean_x86_stub(stub, 0x99),
        "too_short": is_clean_x86_stub(b"\xB8", 0x55),
        "bad_prefix": is_clean_x86_stub(b"\xE9\x00\x00\x00\x00", 0x55),
    }


def fn_detect_hook_type():
    return {
        "jmp_rel32": detect_hook_type(b"\xE9\x00\x00\x00\x00"),
        "short_jmp": detect_hook_type(b"\xEB\x10"),
        "iat_jmp": detect_hook_type(b"\xFF\x25\x00\x00\x00\x00"),
        "push_ret": detect_hook_type(b"\x68\x00\x00\x00\x00\xC3"),
        "clean_x64": detect_hook_type(b"\x4C\x8B\xD1\xB8\x55\x00\x00\x00"),
        "clean_x86": detect_hook_type(b"\xB8\x55\x00\x00\x00"),
        "empty": detect_hook_type(b""),
    }


FUNCTIONS = [
    ("format_ntstatus", fn_format_ntstatus),
    ("decode_ntstatus", fn_decode_ntstatus),
    ("ntstatus_name", fn_ntstatus_name),
    ("winsock_error_name", fn_winsock_error_name),
    ("nt_to_win32_path", fn_nt_to_win32_path),
    ("nt_to_win32_reg_path", fn_nt_to_win32_reg_path),
    ("is_system_path", fn_is_system_path),
    ("is_dangerous_privilege", fn_is_dangerous_privilege),
    ("is_persistence_registry_key", fn_is_persistence_registry_key),
    ("decode_file_access", fn_decode_file_access),
    ("decode_alloc_type", fn_decode_alloc_type),
    ("is_clean_x64_stub", fn_is_clean_x64_stub),
    ("is_clean_x86_stub", fn_is_clean_x86_stub),
    ("detect_hook_type", fn_detect_hook_type),
]


def main():
    results = []
    for name, fn in FUNCTIONS:
        try:
            results.append({"name": name, "ok": True, "result": fn()})
        except Exception as e:
            results.append({"name": name, "ok": False, "error": str(e)})
    out = {
        "crate": "rustre-syscalls-windows",
        "saved": True,
        "functions": results,
    }
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    main()
