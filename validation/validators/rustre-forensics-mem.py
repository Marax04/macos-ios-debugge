#!/usr/bin/env python3
"""Independent Python validator for rustre-forensics-mem.

Implements signature-driven scanning of mock memory images for Windows
and Linux artifacts (processes, modules, network connections, registry
hives, kernel info, PE headers, stack canaries, NT heap entries, UTF-16
strings). Uses only the standard library.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Tuple

MAX_REGION_READ = 64 * 1024 * 1024
MAX_HIVE_DATA = 16 * 1024 * 1024


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class ThreadInfo:
    tid: int
    start_addr: int
    teb: int
    state: str


@dataclass
class ProcessInfo:
    pid: int
    ppid: int
    name: str
    base: int
    size: int
    threads: List[ThreadInfo] = field(default_factory=list)
    modules: List["ModuleInfo"] = field(default_factory=list)
    handle_count: int = 0
    create_time: int = 0

    def name_matches(self, pattern: str) -> bool:
        return pattern.lower() in self.name.lower()


@dataclass
class ModuleInfo:
    name: str
    base: int
    size: int
    path: str


@dataclass
class NetworkConnection:
    protocol: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    pid: int


@dataclass
class RegistryHive:
    name: str
    base: int
    size: int
    data: bytes


@dataclass
class WindowsVersion:
    major: int
    minor: int
    build: int

    def display(self) -> str:
        return f"{self.major}.{self.minor}.{self.build}"


@dataclass
class WindowsKernelInfo:
    kdbg: Optional[int]
    ntoskrnl_base: int
    version: WindowsVersion
    arch: str  # "x86" or "x64"


@dataclass
class HeapAllocation:
    addr: int
    size: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

THREAD_STATES = [
    "Initialized", "Ready", "Running", "Standby", "Terminated",
    "Wait", "Transition", "DeferredReady",
]


def thread_state_from_u8(v: int) -> str:
    if 0 <= v < len(THREAD_STATES):
        return THREAD_STATES[v]
    return "Unknown"


CONN_STATES = [
    "Closed", "Listen", "SynSent", "SynReceived", "Established",
    "FinWait1", "FinWait2", "CloseWait", "LastAck", "TimeWait",
]


def conn_state_from_u8(v: int) -> str:
    if 0 <= v < len(CONN_STATES):
        return CONN_STATES[v]
    return "Unknown"


PROTOCOLS = {0: "TcpV4", 1: "TcpV6", 2: "UdpV4", 3: "UdpV6"}


def bytes_to_ip_v4(data: bytes) -> str:
    return ".".join(str(b) for b in data[:4])


def bytes_to_ip_v6(data: bytes) -> str:
    groups = []
    for i in range(0, 16, 2):
        groups.append(f"{(data[i] << 8) | data[i+1]:x}")
    return ":".join(groups)


def decode_name(buf: bytes) -> str:
    nul = buf.find(b"\x00")
    if nul >= 0:
        buf = buf[:nul]
    return buf.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Windows analyzer
# ---------------------------------------------------------------------------

class WindowsAnalyzer:
    EPRC_SIG = b"EPRC"
    EPRC_LEN = 56
    LDRM_SIG = b"LDRM"
    LDRM_LEN = 116
    NCON_SIG = b"NCON"
    NCON_LEN = 48
    HIVE_SIG = b"HIVE"
    HIVE_LEN = 52
    KDBG_SIG = b"KDBG"

    @classmethod
    def find_processes(cls, image: bytes) -> List[ProcessInfo]:
        out: List[ProcessInfo] = []
        n = min(len(image), MAX_REGION_READ)
        i = 0
        while i + cls.EPRC_LEN <= n:
            if image[i:i+4] == cls.EPRC_SIG:
                rec = image[i:i+cls.EPRC_LEN]
                try:
                    # layout: sig(4) pid(u32) ppid(u32) base(u64) size(u64)
                    #         handles(u32) create_time(u64) name(16) pad(4)
                    pid, ppid = struct.unpack_from("<II", rec, 4)
                    base, size = struct.unpack_from("<QQ", rec, 12)
                    handles = struct.unpack_from("<I", rec, 28)[0]
                    create_time = struct.unpack_from("<Q", rec, 32)[0]
                    name = decode_name(rec[40:56])
                    out.append(ProcessInfo(
                        pid=pid, ppid=ppid, name=name, base=base, size=size,
                        handle_count=handles, create_time=create_time,
                    ))
                    i += cls.EPRC_LEN
                    continue
                except struct.error:
                    pass
            i += 4
        return out

    @classmethod
    def try_find_processes(cls, image: Optional[bytes]) -> List[ProcessInfo]:
        if image is None or len(image) == 0:
            raise ValueError("InvalidAddress: no regions")
        return cls.find_processes(image)

    @classmethod
    def find_modules(cls, image: bytes, pid: int) -> List[ModuleInfo]:
        out: List[ModuleInfo] = []
        n = min(len(image), MAX_REGION_READ)
        i = 0
        while i + cls.LDRM_LEN <= n:
            if image[i:i+4] == cls.LDRM_SIG:
                rec = image[i:i+cls.LDRM_LEN]
                try:
                    rec_pid = struct.unpack_from("<I", rec, 4)[0]
                    base, size = struct.unpack_from("<QQ", rec, 8)
                    name = decode_name(rec[24:56])
                    path = decode_name(rec[56:116])
                    if rec_pid == pid:
                        out.append(ModuleInfo(name=name, base=base, size=size, path=path))
                    i += cls.LDRM_LEN
                    continue
                except struct.error:
                    pass
            i += 4
        return out

    @classmethod
    def find_network_connections(cls, image: bytes) -> List[NetworkConnection]:
        out: List[NetworkConnection] = []
        n = min(len(image), MAX_REGION_READ)
        i = 0
        while i + cls.NCON_LEN <= n:
            if image[i:i+4] == cls.NCON_SIG:
                rec = image[i:i+cls.NCON_LEN]
                try:
                    proto = rec[4]
                    state = rec[5]
                    lport, rport = struct.unpack_from("<HH", rec, 6)
                    laddr = rec[10:26]
                    raddr = rec[26:42]
                    pid = struct.unpack_from("<I", rec, 42)[0]
                    proto_str = PROTOCOLS.get(proto, "TcpV4")
                    is_v6 = proto in (1, 3)
                    out.append(NetworkConnection(
                        protocol=proto_str,
                        local_addr=bytes_to_ip_v6(laddr) if is_v6 else bytes_to_ip_v4(laddr),
                        local_port=lport,
                        remote_addr=bytes_to_ip_v6(raddr) if is_v6 else bytes_to_ip_v4(raddr),
                        remote_port=rport,
                        state=conn_state_from_u8(state),
                        pid=pid,
                    ))
                    i += cls.NCON_LEN
                    continue
                except struct.error:
                    pass
            i += 4
        return out

    @classmethod
    def extract_registry_hives(cls, image: bytes) -> List[RegistryHive]:
        out: List[RegistryHive] = []
        n = min(len(image), MAX_REGION_READ)
        i = 0
        while i + cls.HIVE_LEN <= n:
            if image[i:i+4] == cls.HIVE_SIG:
                rec = image[i:i+cls.HIVE_LEN]
                try:
                    base, size = struct.unpack_from("<QQ", rec, 4)
                    name = decode_name(rec[20:52])
                    capped = min(size, MAX_HIVE_DATA)
                    start = min(base, len(image))
                    end = min(start + capped, len(image))
                    out.append(RegistryHive(
                        name=name, base=base, size=size, data=image[start:end],
                    ))
                    i += cls.HIVE_LEN
                    continue
                except struct.error:
                    pass
            i += 4
        return out

    @classmethod
    def find_kernel_info(cls, image: bytes) -> Optional[WindowsKernelInfo]:
        n = min(len(image), MAX_REGION_READ)
        idx = image.find(cls.KDBG_SIG, 0, n)
        if idx < 0 or idx + 28 > n:
            return None
        try:
            ntoskrnl = struct.unpack_from("<Q", image, idx + 4)[0]
            major, minor, build = struct.unpack_from("<III", image, idx + 12)
            arch_b = image[idx + 24]
            arch = "x64" if arch_b == 64 else "x86"
            return WindowsKernelInfo(
                kdbg=idx, ntoskrnl_base=ntoskrnl,
                version=WindowsVersion(major, minor, build),
                arch=arch,
            )
        except struct.error:
            return None


# ---------------------------------------------------------------------------
# Linux analyzer
# ---------------------------------------------------------------------------

class LinuxAnalyzer:
    TSKB_SIG = b"TSKB"
    TSKB_LEN = 56
    KMOD_SIG = b"KMOD"
    KMOD_LEN = 80

    @classmethod
    def find_processes(cls, image: bytes) -> List[ProcessInfo]:
        out: List[ProcessInfo] = []
        n = min(len(image), MAX_REGION_READ)
        i = 0
        while i + cls.TSKB_LEN <= n:
            if image[i:i+4] == cls.TSKB_SIG:
                rec = image[i:i+cls.TSKB_LEN]
                try:
                    pid, ppid = struct.unpack_from("<II", rec, 4)
                    base, size = struct.unpack_from("<QQ", rec, 12)
                    name = decode_name(rec[28:56])
                    out.append(ProcessInfo(
                        pid=pid, ppid=ppid, name=name, base=base, size=size,
                    ))
                    i += cls.TSKB_LEN
                    continue
                except struct.error:
                    pass
            i += 4
        return out

    @classmethod
    def find_modules(cls, image: bytes) -> List[ModuleInfo]:
        out: List[ModuleInfo] = []
        n = min(len(image), MAX_REGION_READ)
        i = 0
        while i + cls.KMOD_LEN <= n:
            if image[i:i+4] == cls.KMOD_SIG:
                rec = image[i:i+cls.KMOD_LEN]
                try:
                    base, size = struct.unpack_from("<QQ", rec, 4)
                    name = decode_name(rec[20:52])
                    path = decode_name(rec[52:80])
                    out.append(ModuleInfo(name=name, base=base, size=size, path=path))
                    i += cls.KMOD_LEN
                    continue
                except struct.error:
                    pass
            i += 4
        return out

    @classmethod
    def find_sockets(cls, image: bytes) -> List[NetworkConnection]:
        return WindowsAnalyzer.find_network_connections(image)


# ---------------------------------------------------------------------------
# Raw memory scanners
# ---------------------------------------------------------------------------

class MemoryForensicsScanner:
    @staticmethod
    def scan_pe_headers(memory: bytes, base_addr: int) -> List[int]:
        out: List[int] = []
        n = len(memory)
        i = 0
        while i + 0x40 <= n:
            if memory[i:i+2] == b"MZ":
                e_lfanew = struct.unpack_from("<I", memory, i + 0x3C)[0]
                if 0x40 <= e_lfanew <= 0x1000:
                    p = i + e_lfanew
                    if p + 4 <= n and memory[p:p+4] == b"PE\x00\x00":
                        out.append(base_addr + i)
            i += 4
        return out

    CANARIES = {
        0xDEADBEEF, 0xABABABAB, 0xFEEEFEEE, 0xCDCDCDCD, 0xBAADF00D,
    }

    @classmethod
    def scan_stack_canaries(cls, memory: bytes) -> List[int]:
        out: List[int] = []
        n = len(memory) & ~3
        for i in range(0, n, 4):
            v = struct.unpack_from("<I", memory, i)[0]
            if v in cls.CANARIES:
                out.append(i)
        return out

    @staticmethod
    def scan_heap_allocations(memory: bytes) -> List[HeapAllocation]:
        out: List[HeapAllocation] = []
        n = len(memory)
        i = 0
        while i + 8 <= n:
            size_g = struct.unpack_from("<H", memory, i)[0]
            flags = memory[i + 5]
            if (flags & 0x01) and size_g > 0:
                out.append(HeapAllocation(addr=i, size=size_g * 8))
            i += 8
        return out

    @staticmethod
    def find_unicode_strings(memory: bytes, min_len: int) -> List[Tuple[int, str]]:
        out: List[Tuple[int, str]] = []
        n = len(memory)
        i = 0
        while i + 2 <= n:
            start = i
            chars: List[str] = []
            while i + 2 <= n:
                lo = memory[i]
                hi = memory[i + 1]
                if hi == 0 and 0x20 <= lo < 0x7F:
                    chars.append(chr(lo))
                    i += 2
                else:
                    break
            if len(chars) >= min_len:
                out.append((start, "".join(chars)))
            if i == start:
                i += 2
        return out


# ---------------------------------------------------------------------------
# Mock image builder
# ---------------------------------------------------------------------------

def build_mock_image(os_type: str = "windows") -> bytes:
    """Build a 4 KiB mock image with embedded structures."""
    img = bytearray(4096)

    # KDBG at offset 0x100
    off = 0x100
    img[off:off+4] = b"KDBG"
    struct.pack_into("<Q", img, off + 4, 0xFFFFF80000000000)
    struct.pack_into("<III", img, off + 12, 10, 0, 19041)
    img[off + 24] = 64

    if os_type == "windows":
        # Process 1 at 0x200
        off = 0x200
        img[off:off+4] = b"EPRC"
        struct.pack_into("<II", img, off + 4, 4, 0)
        struct.pack_into("<QQ", img, off + 12, 0xFFFFF80001000000, 0x1000)
        struct.pack_into("<I", img, off + 28, 100)
        struct.pack_into("<Q", img, off + 32, 0)
        name = b"System\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        img[off + 40:off + 56] = name[:16]

        # Process 2
        off = 0x300
        img[off:off+4] = b"EPRC"
        struct.pack_into("<II", img, off + 4, 1000, 4)
        struct.pack_into("<QQ", img, off + 12, 0x00007FF600000000, 0x10000)
        struct.pack_into("<I", img, off + 28, 50)
        struct.pack_into("<Q", img, off + 32, 0)
        name = b"explorer.exe\x00\x00\x00\x00"
        img[off + 40:off + 56] = name[:16]

        # Module
        off = 0x400
        img[off:off+4] = b"LDRM"
        struct.pack_into("<I", img, off + 4, 1000)
        struct.pack_into("<QQ", img, off + 8, 0x00007FF700000000, 0x50000)
        mname = b"kernel32.dll".ljust(32, b"\x00")
        img[off + 24:off + 56] = mname
        mpath = b"C:\\Windows\\System32\\kernel32.dll".ljust(60, b"\x00")
        img[off + 56:off + 116] = mpath

        # Connection
        off = 0x600
        img[off:off+4] = b"NCON"
        img[off + 4] = 0  # TcpV4
        img[off + 5] = 4  # Established
        struct.pack_into("<HH", img, off + 6, 443, 8080)
        img[off + 10:off + 14] = bytes([192, 168, 1, 1])
        img[off + 26:off + 30] = bytes([10, 0, 0, 1])
        struct.pack_into("<I", img, off + 42, 1000)

        # Hive
        off = 0x700
        img[off:off+4] = b"HIVE"
        struct.pack_into("<QQ", img, off + 4, 0x800, 0x100)
        hname = b"SOFTWARE".ljust(32, b"\x00")
        img[off + 20:off + 52] = hname

    else:  # linux
        off = 0x200
        img[off:off+4] = b"TSKB"
        struct.pack_into("<II", img, off + 4, 1, 0)
        struct.pack_into("<QQ", img, off + 12, 0xFFFF800000000000, 0x1000)
        name = b"init".ljust(28, b"\x00")
        img[off + 28:off + 56] = name

        off = 0x400
        img[off:off+4] = b"KMOD"
        struct.pack_into("<QQ", img, off + 4, 0xFFFFFFFFC0000000, 0x10000)
        mname = b"ext4".ljust(32, b"\x00")
        img[off + 20:off + 52] = mname
        mpath = b"/lib/modules/ext4.ko".ljust(28, b"\x00")
        img[off + 52:off + 80] = mpath

    return bytes(img)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _selftest() -> bool:
    img = build_mock_image("windows")
    procs = WindowsAnalyzer.find_processes(img)
    assert len(procs) == 2, procs
    assert procs[0].pid == 4 and procs[0].name == "System"
    assert procs[1].name_matches("EXPLORER")

    mods = WindowsAnalyzer.find_modules(img, 1000)
    assert len(mods) == 1 and mods[0].name == "kernel32.dll"

    conns = WindowsAnalyzer.find_network_connections(img)
    assert len(conns) == 1
    assert conns[0].protocol == "TcpV4"
    assert conns[0].local_addr == "192.168.1.1"
    assert conns[0].state == "Established"

    hives = WindowsAnalyzer.extract_registry_hives(img)
    assert len(hives) == 1 and hives[0].name == "SOFTWARE"

    ki = WindowsAnalyzer.find_kernel_info(img)
    assert ki is not None and ki.version.build == 19041 and ki.arch == "x64"
    assert ki.version.display() == "10.0.19041"

    limg = build_mock_image("linux")
    lprocs = LinuxAnalyzer.find_processes(limg)
    assert len(lprocs) == 1 and lprocs[0].name == "init"
    lmods = LinuxAnalyzer.find_modules(limg)
    assert len(lmods) == 1 and lmods[0].name == "ext4"

    # PE scanner
    pe = bytearray(0x200)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\x00\x00"
    hits = MemoryForensicsScanner.scan_pe_headers(bytes(pe), 0x1000)
    assert hits == [0x1000]

    # Canaries
    can = struct.pack("<I", 0xDEADBEEF) + b"\x00" * 4 + struct.pack("<I", 0xBAADF00D)
    cs = MemoryForensicsScanner.scan_stack_canaries(can)
    assert cs == [0, 8]

    # Unicode
    us = "Hello".encode("utf-16le") + b"\x00\x00\x00"
    found = MemoryForensicsScanner.find_unicode_strings(us, 4)
    assert any(s == "Hello" for _, s in found)

    # try_find_processes empty -> raises
    try:
        WindowsAnalyzer.try_find_processes(b"")
        return False
    except ValueError:
        pass

    return True


if __name__ == "__main__":
    ok = _selftest()
    print("rustre-forensics-mem validator:", "OK" if ok else "FAIL")
