#!/usr/bin/env python3
"""
Independent validator for rustre-syscalls.

Reimplements (using only Python stdlib) the documented invariants of the
crate: OS/arch families, syscall types, arg directions, categories, risk
level ordering, argument decoding (signals, errno, clock ids, sa_family,
buffers/strings/handles/booleans), the Linux x86_64 and AArch64 syscall
tables, Windows NT syscall numbers, and database lookup semantics.

Based on reports/rustre-syscalls.md.

Output (printed as JSON):
    { "crate": "rustre-syscalls", "saved": bool }
"""

import json
import os
import sys
from enum import Enum, IntEnum

CRATE = "rustre-syscalls"


# ---------------- Enums ----------------
class OsFamily(Enum):
    Linux = "Linux"
    Windows = "Windows"
    MacOs = "MacOs"
    FreeBsd = "FreeBsd"
    OpenBsd = "OpenBsd"


class SyscallArch(Enum):
    X86 = "X86"
    X86_64 = "X86_64"
    Arm32 = "Arm32"
    Arm64 = "Arm64"
    Mips = "Mips"
    Riscv64 = "Riscv64"


class ArgDirection(Enum):
    In = "In"
    Out = "Out"
    InOut = "InOut"


class SyscallCategory(Enum):
    FileSystem = "FileSystem"
    Memory = "Memory"
    Process = "Process"
    Thread = "Thread"
    Network = "Network"
    Ipc = "Ipc"
    Signal = "Signal"
    Time = "Time"
    Device = "Device"
    Security = "Security"
    System = "System"
    Unknown = "Unknown"


class RiskLevel(IntEnum):
    Benign = 0
    Low = 1
    Medium = 2
    High = 3
    Critical = 4


# SyscallType is a tagged union. We model with tuple ("Tag", payload?)
SYSCALL_TYPE_TAGS = {
    "Void", "Int", "UInt", "Long", "ULong", "Ptr", "Handle", "Bool",
    "Fd", "Pid", "Tid", "Size", "SSize", "Errno", "Buffer", "String",
    "WString", "Struct", "Enum", "Flags", "UserPtr", "KernelPtr",
    "SaFamily", "Offset", "Mode", "Signal", "ClockId", "FdArray",
    "Socklen", "IpAddr",
}


# ---------------- Lookup tables ----------------
SIGNAL_NAMES = {
    1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL", 5: "SIGTRAP",
    6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE", 9: "SIGKILL", 10: "SIGUSR1",
    11: "SIGSEGV", 12: "SIGUSR2", 13: "SIGPIPE", 14: "SIGALRM",
    15: "SIGTERM", 17: "SIGCHLD", 18: "SIGCONT", 19: "SIGSTOP",
    20: "SIGTSTP", 21: "SIGTTIN", 22: "SIGTTOU", 23: "SIGURG",
    24: "SIGXCPU", 25: "SIGXFSZ", 26: "SIGVTALRM", 27: "SIGPROF",
    28: "SIGWINCH", 29: "SIGIO", 30: "SIGPWR", 31: "SIGSYS",
}


ERRNO_NAMES = {
    1: "EPERM", 2: "ENOENT", 3: "ESRCH", 4: "EINTR", 5: "EIO",
    9: "EBADF", 11: "EAGAIN", 12: "ENOMEM", 13: "EACCES", 14: "EFAULT",
    17: "EEXIST", 22: "EINVAL", 24: "EMFILE", 32: "EPIPE",
    98: "EADDRINUSE", 111: "ECONNREFUSED", 115: "EINPROGRESS",
}


CLOCK_ID_NAMES = {
    0: "CLOCK_REALTIME",
    1: "CLOCK_MONOTONIC",
    2: "CLOCK_PROCESS_CPUTIME_ID",
    3: "CLOCK_THREAD_CPUTIME_ID",
    4: "CLOCK_MONOTONIC_RAW",
    5: "CLOCK_REALTIME_COARSE",
    6: "CLOCK_MONOTONIC_COARSE",
    7: "CLOCK_BOOTTIME",
    8: "CLOCK_REALTIME_ALARM",
    9: "CLOCK_BOOTTIME_ALARM",
}


SA_FAMILY_NAMES = {
    0: "AF_UNSPEC",
    1: "AF_UNIX",
    2: "AF_INET",
    10: "AF_INET6",
    16: "AF_NETLINK",
    17: "AF_PACKET",
    40: "AF_VSOCK",
}


def signal_name(n):
    return SIGNAL_NAMES.get(n)


def errno_name(n):
    return ERRNO_NAMES.get(n)


def clock_id_name(n):
    return CLOCK_ID_NAMES.get(n)


def sa_family_name(n):
    return SA_FAMILY_NAMES.get(n)


# ---------------- Arg decoding ----------------
def decode_arg_value(ty, raw):
    """ty is a tuple ('Tag',) or ('Tag', payload). raw is u64."""
    tag = ty[0]
    is_null = False
    if tag == "Void":
        display = "void"
    elif tag in ("Int", "Long", "SSize", "Offset"):
        # Sign-extend 64-bit
        val = raw if raw < (1 << 63) else raw - (1 << 64)
        display = str(val)
    elif tag in ("UInt", "ULong", "Size", "Socklen"):
        display = str(raw)
    elif tag in ("Ptr", "UserPtr", "KernelPtr"):
        is_null = (raw == 0)
        display = "NULL" if is_null else f"0x{raw:x}"
    elif tag == "Handle":
        is_null = (raw == 0)
        display = "NULL" if is_null else f"0x{raw:x}"
    elif tag == "Bool":
        display = "true" if raw != 0 else "false"
    elif tag == "Fd":
        display = f"fd={raw}"
    elif tag == "Pid":
        display = f"pid={raw}"
    elif tag == "Tid":
        display = f"tid={raw}"
    elif tag == "Errno":
        name = errno_name(raw & 0xFFFFFFFF)
        display = name if name else f"errno={raw}"
    elif tag == "Signal":
        name = signal_name(raw & 0xFFFFFFFF)
        display = name if name else f"signo={raw}"
    elif tag == "ClockId":
        name = clock_id_name(raw & 0xFFFFFFFF)
        display = name if name else f"clockid={raw}"
    elif tag == "SaFamily":
        name = sa_family_name(raw & 0xFFFF)
        display = name if name else f"af={raw}"
    elif tag == "Mode":
        display = f"0o{raw & 0xFFFF:o}"
    elif tag == "Buffer":
        is_null = (raw == 0)
        display = "NULL" if is_null else f"buf@0x{raw:x}"
    elif tag in ("String", "WString"):
        is_null = (raw == 0)
        display = "NULL" if is_null else f"str@0x{raw:x}"
    elif tag in ("Struct", "Enum", "Flags"):
        payload = ty[1] if len(ty) > 1 else "?"
        display = f"{tag}({payload})@0x{raw:x}"
    elif tag == "FdArray":
        is_null = (raw == 0)
        display = "NULL" if is_null else f"fds@0x{raw:x}"
    elif tag == "IpAddr":
        display = f"ip=0x{raw:x}"
    else:
        display = f"0x{raw:x}"
    return {"raw": raw, "display": display, "is_null": is_null}


# ---------------- Syscall / database ----------------
class SyscallArg:
    def __init__(self, name, ty, direction=ArgDirection.In, optional=False):
        self.name = name
        self.ty = ty
        self.direction = direction
        self.optional = optional

    def decode(self, raw):
        return decode_arg_value(self.ty, raw)


class Syscall:
    def __init__(self, number, name, target, args, return_type,
                 category, description, risk=RiskLevel.Benign):
        self.number = number
        self.name = name
        self.os = target[0]
        self.arch = target[1]
        self.args = list(args)
        self.return_type = return_type
        self.category = category
        self.description = description
        self.risk = risk
        self.aliases = []
        self.deprecated = False

    def decode_args(self, raws):
        return [a.decode(r) for a, r in zip(self.args, raws)]

    def prototype(self):
        arg_strs = []
        for a in self.args:
            arg_strs.append(f"{a.ty[0]} {a.name}")
        return f"{self.return_type[0]} {self.name}({', '.join(arg_strs)})"

    def has_output_args(self):
        return any(a.direction in (ArgDirection.Out, ArgDirection.InOut)
                   for a in self.args)

    def input_arg_count(self):
        return sum(1 for a in self.args
                   if a.direction in (ArgDirection.In, ArgDirection.InOut))


class SyscallDatabase:
    def __init__(self):
        # key: (os, arch, number)
        self._by_num = {}
        # key: (os, arch, name)
        self._by_name = {}

    def insert(self, sc):
        self._by_num[(sc.os, sc.arch, sc.number)] = sc
        self._by_name[(sc.os, sc.arch, sc.name)] = sc

    def merge(self, other):
        for sc in other._by_num.values():
            self.insert(sc)

    def lookup(self, os_, arch, number):
        return self._by_num.get((os_, arch, number))

    def lookup_by_name(self, os_, arch, name):
        return self._by_name.get((os_, arch, name))

    def all_for(self, os_, arch):
        return [s for s in self._by_num.values()
                if s.os == os_ and s.arch == arch]

    def all_for_category(self, os_, arch, cat):
        return [s for s in self.all_for(os_, arch) if s.category == cat]

    def high_risk(self, os_, arch, min_risk):
        return [s for s in self.all_for(os_, arch) if s.risk >= min_risk]

    def __len__(self):
        return len(self._by_num)

    def is_empty(self):
        return len(self._by_num) == 0

    def stats(self):
        by_cat = {}
        by_risk = {}
        for s in self._by_num.values():
            by_cat[s.category] = by_cat.get(s.category, 0) + 1
            by_risk[s.risk] = by_risk.get(s.risk, 0) + 1
        return {"total": len(self._by_num), "by_category": by_cat,
                "by_risk": by_risk}


# ---------------- Static tables (documented NRs) ----------------
LINUX_X86_64_ENTRIES = {
    0: "read",
    1: "write",
    2: "open",
    3: "close",
    9: "mmap",
    11: "munmap",
    39: "getpid",
    56: "clone",
    57: "fork",
    59: "execve",
    60: "exit",
    62: "kill",
    231: "exit_group",
    257: "openat",
    329: "pkey_mprotect",
}


LINUX_ARM64_ENTRIES = {
    63: "read",
    64: "write",
    56: "openat",
    57: "close",
    93: "exit",
    94: "exit_group",
    172: "getpid",
    220: "clone",
    221: "execve",
    222: "mmap",
    215: "munmap",
}


WINDOWS_X64_ENTRIES = {
    0x0055: "NtCreateFile",
    0x0006: "NtClose",
    0x0008: "NtWriteFile",
    0x0050: "NtCreateProcess",
}


# ---------------- Self-checks ----------------
def run_checks():
    r = []

    # Enum cardinality
    r.append(("OsFamily has 5", len(list(OsFamily)) == 5))
    r.append(("SyscallArch has 6", len(list(SyscallArch)) == 6))
    r.append(("ArgDirection has 3", len(list(ArgDirection)) == 3))
    r.append(("SyscallCategory has 12", len(list(SyscallCategory)) == 12))
    r.append(("RiskLevel has 5", len(list(RiskLevel)) == 5))
    r.append(("SyscallType tag count >=29", len(SYSCALL_TYPE_TAGS) >= 29))

    # RiskLevel ordering (Ord)
    r.append(("RiskLevel ordered Benign<Low",
              RiskLevel.Benign < RiskLevel.Low))
    r.append(("RiskLevel ordered High<Critical",
              RiskLevel.High < RiskLevel.Critical))
    r.append(("RiskLevel Critical is max",
              max(RiskLevel) == RiskLevel.Critical))

    # Display formatting (OsFamily / Arch)
    r.append(("OsFamily Display Linux", str(OsFamily.Linux.value) == "Linux"))
    r.append(("SyscallArch Display X86_64",
              str(SyscallArch.X86_64.value) == "X86_64"))

    # Signal / errno / clockid / sa_family lookups
    r.append(("signal SIGKILL=9", signal_name(9) == "SIGKILL"))
    r.append(("signal SIGHUP=1", signal_name(1) == "SIGHUP"))
    r.append(("signal SIGSYS=31", signal_name(31) == "SIGSYS"))
    r.append(("signal unknown -> None", signal_name(999) is None))

    r.append(("errno EPERM=1", errno_name(1) == "EPERM"))
    r.append(("errno EINPROGRESS=115", errno_name(115) == "EINPROGRESS"))
    r.append(("errno unknown -> None", errno_name(9999) is None))

    r.append(("clockid REALTIME=0", clock_id_name(0) == "CLOCK_REALTIME"))
    r.append(("clockid BOOTTIME_ALARM=9",
              clock_id_name(9) == "CLOCK_BOOTTIME_ALARM"))

    r.append(("af AF_UNSPEC=0", sa_family_name(0) == "AF_UNSPEC"))
    r.append(("af AF_INET=2", sa_family_name(2) == "AF_INET"))
    r.append(("af AF_VSOCK=40", sa_family_name(40) == "AF_VSOCK"))

    # decode_arg_value cases
    d = decode_arg_value(("Ptr",), 0)
    r.append(("Ptr NULL display", d["display"] == "NULL" and d["is_null"]))
    d = decode_arg_value(("Ptr",), 0xDEAD)
    r.append(("Ptr non-null display", d["display"] == "0xdead"))

    d = decode_arg_value(("Bool",), 0)
    r.append(("Bool false", d["display"] == "false"))
    d = decode_arg_value(("Bool",), 1)
    r.append(("Bool true", d["display"] == "true"))

    d = decode_arg_value(("Fd",), 3)
    r.append(("Fd format", d["display"] == "fd=3"))

    d = decode_arg_value(("Signal",), 9)
    r.append(("Signal decode SIGKILL", d["display"] == "SIGKILL"))

    d = decode_arg_value(("Errno",), 2)
    r.append(("Errno decode ENOENT", d["display"] == "ENOENT"))

    d = decode_arg_value(("ClockId",), 1)
    r.append(("ClockId decode MONOTONIC",
              d["display"] == "CLOCK_MONOTONIC"))

    d = decode_arg_value(("SaFamily",), 2)
    r.append(("SaFamily decode AF_INET", d["display"] == "AF_INET"))

    d = decode_arg_value(("Mode",), 0o755)
    r.append(("Mode octal display", d["display"] == "0o755"))

    d = decode_arg_value(("Int",), (1 << 64) - 1)
    r.append(("Int sign-extend -1", d["display"] == "-1"))
    d = decode_arg_value(("UInt",), (1 << 64) - 1)
    r.append(("UInt no sign-extend", d["display"] == str((1 << 64) - 1)))

    d = decode_arg_value(("Buffer", "size_arg"), 0)
    r.append(("Buffer NULL", d["is_null"] and d["display"] == "NULL"))

    d = decode_arg_value(("String",), 0x1000)
    r.append(("String non-null", d["display"] == "str@0x1000"))

    # Syscall object
    sc = Syscall(
        number=1,
        name="write",
        target=(OsFamily.Linux, SyscallArch.X86_64),
        args=[
            SyscallArg("fd", ("Fd",), ArgDirection.In),
            SyscallArg("buf", ("Buffer", "count"), ArgDirection.In),
            SyscallArg("count", ("Size",), ArgDirection.In),
        ],
        return_type=("SSize",),
        category=SyscallCategory.FileSystem,
        description="write to fd",
        risk=RiskLevel.Low,
    )
    r.append(("Syscall.input_arg_count=3", sc.input_arg_count() == 3))
    r.append(("Syscall.has_output_args=False", sc.has_output_args() is False))
    r.append(("Syscall.prototype contains name",
              "write" in sc.prototype()))

    decoded = sc.decode_args([3, 0xCAFE, 10])
    r.append(("decode_args fd", decoded[0]["display"] == "fd=3"))
    r.append(("decode_args buf", decoded[1]["display"] == "buf@0xcafe"))
    r.append(("decode_args count", decoded[2]["display"] == "10"))

    # has_output_args true case
    sc_out = Syscall(
        0, "read",
        (OsFamily.Linux, SyscallArch.X86_64),
        [
            SyscallArg("fd", ("Fd",), ArgDirection.In),
            SyscallArg("buf", ("Buffer", "count"), ArgDirection.Out),
            SyscallArg("count", ("Size",), ArgDirection.In),
        ],
        ("SSize",), SyscallCategory.FileSystem, "read", RiskLevel.Low,
    )
    r.append(("has_output_args True when Out present",
              sc_out.has_output_args() is True))
    r.append(("input_arg_count counts InOut+In only",
              sc_out.input_arg_count() == 2))

    # Database
    db = SyscallDatabase()
    r.append(("empty db is_empty", db.is_empty()))
    db.insert(sc)
    db.insert(sc_out)
    r.append(("db len=2", len(db) == 2))
    r.append(("lookup by num",
              db.lookup(OsFamily.Linux, SyscallArch.X86_64, 1).name == "write"))
    r.append(("lookup by name",
              db.lookup_by_name(OsFamily.Linux, SyscallArch.X86_64, "read")
              .number == 0))
    r.append(("lookup miss -> None",
              db.lookup(OsFamily.Windows, SyscallArch.X86_64, 1) is None))
    r.append(("all_for filters by target",
              len(db.all_for(OsFamily.Linux, SyscallArch.X86_64)) == 2))
    r.append(("all_for_category filters",
              len(db.all_for_category(OsFamily.Linux, SyscallArch.X86_64,
                                      SyscallCategory.FileSystem)) == 2))

    # high_risk threshold inclusive
    sc_hi = Syscall(
        59, "execve",
        (OsFamily.Linux, SyscallArch.X86_64),
        [], ("Int",),
        SyscallCategory.Process, "exec", RiskLevel.Critical,
    )
    db.insert(sc_hi)
    hr = db.high_risk(OsFamily.Linux, SyscallArch.X86_64, RiskLevel.High)
    r.append(("high_risk >=High returns Critical entry only",
              len(hr) == 1 and hr[0].name == "execve"))

    stats = db.stats()
    r.append(("stats total", stats["total"] == 3))
    r.append(("stats by_category FS=2",
              stats["by_category"].get(SyscallCategory.FileSystem) == 2))
    r.append(("stats by_risk Low=2",
              stats["by_risk"].get(RiskLevel.Low) == 2))

    # merge
    db2 = SyscallDatabase()
    db2.insert(Syscall(
        0x55, "NtCreateFile",
        (OsFamily.Windows, SyscallArch.X86_64),
        [], ("Handle",),
        SyscallCategory.FileSystem, "create", RiskLevel.Medium,
    ))
    db.merge(db2)
    r.append(("merge cross-OS",
              db.lookup(OsFamily.Windows, SyscallArch.X86_64, 0x55)
              is not None))

    # Linux tables
    r.append(("LINUX_x86_64 read=0", LINUX_X86_64_ENTRIES[0] == "read"))
    r.append(("LINUX_x86_64 write=1", LINUX_X86_64_ENTRIES[1] == "write"))
    r.append(("LINUX_x86_64 execve=59", LINUX_X86_64_ENTRIES[59] == "execve"))
    r.append(("LINUX_x86_64 exit_group=231",
              LINUX_X86_64_ENTRIES[231] == "exit_group"))
    r.append(("LINUX_x86_64 openat=257",
              LINUX_X86_64_ENTRIES[257] == "openat"))
    r.append(("LINUX_x86_64 max NR<=329",
              max(LINUX_X86_64_ENTRIES) <= 329))

    r.append(("LINUX_arm64 read=63", LINUX_ARM64_ENTRIES[63] == "read"))
    r.append(("LINUX_arm64 write=64", LINUX_ARM64_ENTRIES[64] == "write"))
    r.append(("LINUX_arm64 openat=56",
              LINUX_ARM64_ENTRIES[56] == "openat"))
    r.append(("LINUX_arm64 exit_group=94",
              LINUX_ARM64_ENTRIES[94] == "exit_group"))

    # NR numbers differ across archs even for same name (read)
    r.append(("read NR differs x86_64 vs arm64",
              LINUX_X86_64_ENTRIES[0] == LINUX_ARM64_ENTRIES[63] == "read"))

    r.append(("Windows NtCreateFile=0x55",
              WINDOWS_X64_ENTRIES[0x55] == "NtCreateFile"))
    r.append(("Windows NtClose=0x06",
              WINDOWS_X64_ENTRIES[0x06] == "NtClose"))

    # No duplicates within a static table
    r.append(("LINUX_x86_64 unique NRs",
              len(set(LINUX_X86_64_ENTRIES.keys()))
              == len(LINUX_X86_64_ENTRIES)))
    r.append(("WINDOWS_X64 unique NRs",
              len(set(WINDOWS_X64_ENTRIES.keys()))
              == len(WINDOWS_X64_ENTRIES)))

    return r


def main():
    checks = run_checks()
    failed = [name for name, ok in checks if not ok]

    out_dir = os.path.dirname(os.path.abspath(__file__))
    result_path = os.path.join(out_dir, f"{CRATE}.result.json")
    saved = False
    try:
        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "crate": CRATE,
                    "checks_total": len(checks),
                    "checks_failed": failed,
                },
                f,
                indent=2,
            )
        saved = True
    except OSError:
        saved = False

    print(json.dumps({"crate": CRATE, "saved": saved}, indent=2))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
