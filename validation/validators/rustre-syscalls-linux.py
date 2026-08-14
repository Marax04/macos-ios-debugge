"""Independent validator for rustre-syscalls-linux.

Pure-stdlib reimplementation of portable surfaces documented in
reports/rustre-syscalls-linux.md:

  * x86_64 / aarch64 syscall name<->number lookup (a small curated subset
    matching the canonical Linux ABI numbers)
  * errno_name / signal_name / af_name
  * decode_open_flags / decode_mmap_prot / decode_mmap_flags / decode_flags
  * parse_proc_maps / parse_proc_status
  * AT_FDCWD constant

ptrace/seccomp/interception code paths require a live Linux kernel and are
out of scope for a stdlib validator.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

AT_FDCWD = -100


# ---------------------------------------------------------------------------
# Syscall tables (curated subset, canonical Linux ABI)
# ---------------------------------------------------------------------------

_X86_64_SYSCALLS: Dict[int, str] = {
    0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat",
    6: "lstat", 7: "poll", 8: "lseek", 9: "mmap", 10: "mprotect",
    11: "munmap", 12: "brk", 13: "rt_sigaction", 14: "rt_sigprocmask",
    15: "rt_sigreturn", 16: "ioctl", 17: "pread64", 18: "pwrite64",
    19: "readv", 20: "writev", 21: "access", 22: "pipe", 23: "select",
    24: "sched_yield", 25: "mremap", 26: "msync", 27: "mincore",
    28: "madvise", 56: "clone", 57: "fork", 58: "vfork", 59: "execve",
    60: "exit", 61: "wait4", 62: "kill", 231: "exit_group",
    257: "openat",
}

_AARCH64_SYSCALLS: Dict[int, str] = {
    56: "openat", 57: "close", 63: "read", 64: "write", 93: "exit",
    94: "exit_group", 129: "kill", 215: "munmap", 222: "mmap",
    226: "mprotect", 220: "clone", 221: "execve",
}

AARCH64_SPECIFIC_SYSCALLS: Tuple[str, ...] = (
    "renameat2", "memfd_secret",
)


def x86_64_syscall_name(nr: int) -> Optional[str]:
    return _X86_64_SYSCALLS.get(nr)


def x86_64_syscall_nr(name: str) -> Optional[int]:
    for k, v in _X86_64_SYSCALLS.items():
        if v == name:
            return k
    return None


def aarch64_syscall_name(nr: int) -> Optional[str]:
    return _AARCH64_SYSCALLS.get(nr)


aarch64_syscall_name_v2 = aarch64_syscall_name


def aarch64_syscall_nr(name: str) -> Optional[int]:
    for k, v in _AARCH64_SYSCALLS.items():
        if v == name:
            return k
    return None


def lookup_x86_64_entry(nr: int) -> Optional[Dict[str, object]]:
    name = x86_64_syscall_name(nr)
    if name is None:
        return None
    return {"nr": nr, "name": name}


# ---------------------------------------------------------------------------
# Names: errno / signal / af / ioctl / sockopt / ptrace
# ---------------------------------------------------------------------------

_ERRNO = {
    1: "EPERM", 2: "ENOENT", 3: "ESRCH", 4: "EINTR", 5: "EIO", 9: "EBADF",
    11: "EAGAIN", 12: "ENOMEM", 13: "EACCES", 14: "EFAULT", 17: "EEXIST",
    22: "EINVAL", 24: "EMFILE", 32: "EPIPE",
}
_SIGNAL = {
    1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL", 6: "SIGABRT",
    8: "SIGFPE", 9: "SIGKILL", 11: "SIGSEGV", 13: "SIGPIPE", 14: "SIGALRM",
    15: "SIGTERM", 17: "SIGCHLD", 19: "SIGSTOP",
}
_AF = {
    0: "AF_UNSPEC", 1: "AF_UNIX", 2: "AF_INET", 10: "AF_INET6",
    16: "AF_NETLINK", 17: "AF_PACKET",
}


def errno_name(e: int) -> Optional[str]:
    return _ERRNO.get(e)


errno_name_v2 = errno_name


def signal_name(s: int) -> Optional[str]:
    return _SIGNAL.get(s)


signal_name_v2 = signal_name


def af_name(a: int) -> Optional[str]:
    return _AF.get(a)


def ioctl_name(req: int) -> str:
    return f"ioctl(0x{req:x})"


def ptrace_request_name(req: int) -> str:
    table = {0: "PTRACE_TRACEME", 16: "PTRACE_ATTACH", 17: "PTRACE_DETACH",
             24: "PTRACE_SYSCALL", 7: "PTRACE_CONT"}
    return table.get(req, f"PTRACE_{req}")


def sockopt_name(opt: int) -> str:
    return f"SO_{opt}"


# ---------------------------------------------------------------------------
# Flag decoders
# ---------------------------------------------------------------------------

_O_FLAGS = [
    (0o1, "O_WRONLY"), (0o2, "O_RDWR"), (0o100, "O_CREAT"),
    (0o200, "O_EXCL"), (0o1000, "O_TRUNC"), (0o2000, "O_APPEND"),
    (0o4000, "O_NONBLOCK"), (0o400000, "O_DIRECTORY"), (0o2000000, "O_CLOEXEC"),
]
_PROT = [(0x1, "PROT_READ"), (0x2, "PROT_WRITE"), (0x4, "PROT_EXEC")]
_MAP = [(0x01, "MAP_SHARED"), (0x02, "MAP_PRIVATE"), (0x10, "MAP_FIXED"),
        (0x20, "MAP_ANONYMOUS")]


def decode_flags(value: int, table) -> List[str]:
    out = []
    for bit, name in table:
        if value & bit:
            out.append(name)
    return out


def decode_flags_by_name(value: int, name: str) -> List[str]:
    tables = {"open": _O_FLAGS, "prot": _PROT, "mmap": _MAP}
    return decode_flags(value, tables.get(name, []))


def decode_open_flags(v: int) -> List[str]:
    out = []
    if v & 0o3 == 0:
        out.append("O_RDONLY")
    out.extend(decode_flags(v, _O_FLAGS))
    return out


def decode_mmap_prot(v: int) -> List[str]:
    if v == 0:
        return ["PROT_NONE"]
    return decode_flags(v, _PROT)


def decode_mmap_flags(v: int) -> List[str]:
    return decode_flags(v, _MAP)


def format_open_flags(v: int) -> str:
    return "|".join(decode_open_flags(v)) or "0"


def format_mmap_args(prot: int, flags: int) -> str:
    return f"prot={'|'.join(decode_mmap_prot(prot)) or '0'} flags={'|'.join(decode_mmap_flags(flags)) or '0'}"


def format_retval(rv: int) -> str:
    if rv < 0:
        n = errno_name(-rv)
        return f"-1 {n}" if n else str(rv)
    return str(rv)


# ---------------------------------------------------------------------------
# Proc parsers
# ---------------------------------------------------------------------------

@dataclass
class MapsEntry:
    start: int
    end: int
    perms: str
    offset: int
    dev: str
    inode: int
    pathname: Optional[str] = None


def parse_proc_maps(content: str) -> List[MapsEntry]:
    out: List[MapsEntry] = []
    for line in content.splitlines():
        if not line.strip():
            continue
        parts = line.split(None, 5)
        if len(parts) < 5:
            continue
        try:
            lo_s, hi_s = parts[0].split("-", 1)
            start = int(lo_s, 16)
            end = int(hi_s, 16)
            offset = int(parts[2], 16)
            inode = int(parts[4])
        except (ValueError, IndexError):
            continue
        pathname = parts[5].strip() if len(parts) >= 6 and parts[5].strip() else None
        out.append(MapsEntry(start, end, parts[1], offset, parts[3], inode, pathname))
    return out


@dataclass
class ProcStatus:
    name: Optional[str] = None
    pid: Optional[int] = None
    ppid: Optional[int] = None
    uid: Optional[int] = None
    state: Optional[str] = None


def parse_proc_status(content: str) -> ProcStatus:
    st = ProcStatus()
    for line in content.splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        v = v.strip()
        k = k.strip()
        try:
            if k == "Name":
                st.name = v
            elif k == "Pid":
                st.pid = int(v)
            elif k == "PPid":
                st.ppid = int(v)
            elif k == "Uid":
                st.uid = int(v.split()[0])
            elif k == "State":
                st.state = v
        except ValueError:
            continue
    return st


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def _self_test() -> None:
    assert x86_64_syscall_name(0) == "read"
    assert x86_64_syscall_name(1) == "write"
    assert x86_64_syscall_name(257) == "openat"
    assert x86_64_syscall_nr("execve") == 59
    assert x86_64_syscall_name(99999) is None
    assert lookup_x86_64_entry(60)["name"] == "exit"

    assert aarch64_syscall_name(64) == "write"
    assert aarch64_syscall_name(93) == "exit"
    assert aarch64_syscall_nr("openat") == 56

    assert errno_name(2) == "ENOENT"
    assert signal_name(9) == "SIGKILL"
    assert af_name(2) == "AF_INET"
    assert ptrace_request_name(0) == "PTRACE_TRACEME"

    assert "O_CREAT" in decode_open_flags(0o100 | 0o2)
    assert "O_RDWR" in decode_open_flags(0o2)
    assert "O_RDONLY" in decode_open_flags(0)
    assert decode_mmap_prot(0) == ["PROT_NONE"]
    assert set(decode_mmap_prot(0x3)) == {"PROT_READ", "PROT_WRITE"}
    assert "MAP_PRIVATE" in decode_mmap_flags(0x22)
    assert decode_flags_by_name(0x1, "prot") == ["PROT_READ"]
    assert format_retval(-2) == "-1 ENOENT"
    assert format_retval(42) == "42"
    assert "prot=PROT_READ" in format_mmap_args(1, 2)

    sample = (
        "55a1b2c3d000-55a1b2c40000 r-xp 00000000 08:01 12345 /usr/bin/cat\n"
        "7ffd1234a000-7ffd1234c000 rw-p 00000000 00:00 0 [stack]\n"
        "garbage\n"
    )
    maps = parse_proc_maps(sample)
    assert len(maps) == 2
    assert maps[0].pathname == "/usr/bin/cat"
    assert maps[0].inode == 12345
    assert maps[1].pathname == "[stack]"

    status = parse_proc_status(
        "Name:\tbash\nPid:\t1234\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\nState:\tR (running)\n"
    )
    assert status.name == "bash"
    assert status.pid == 1234
    assert status.ppid == 1
    assert status.uid == 1000
    assert status.state.startswith("R")

    assert AT_FDCWD == -100
    assert "renameat2" in AARCH64_SPECIFIC_SYSCALLS


if __name__ == "__main__":
    _self_test()
    print("rustre-syscalls-linux validator: OK")
