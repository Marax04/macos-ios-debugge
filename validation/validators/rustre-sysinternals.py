"""Independent stdlib validator for rustre-sysinternals.

Models the pure-data + builder/trait surface documented in
reports/rustre-sysinternals.md: error variants, enums, bitflags,
info structs, ProcessTree (cycle-safe), AutorunDiff, in-memory
SystemMonitor, builtin SHA-256/MD5, and PE signature parsing.
"""

import json
import struct
from enum import Enum
from typing import Optional


# -----------------------------------------------------------------------------
# Errors
# -----------------------------------------------------------------------------

class SysinternalsError(Exception):
    @staticmethod
    def access_denied():
        return SysinternalsError("AccessDenied")

    @staticmethod
    def unsupported():
        return SysinternalsError("Unsupported")

    @staticmethod
    def io(msg):
        return SysinternalsError(f"Io({msg})")

    @staticmethod
    def process_not_found(pid):
        return SysinternalsError(f"ProcessNotFound({pid})")

    @staticmethod
    def invalid_data(msg):
        return SysinternalsError(f"InvalidData({msg})")

    @staticmethod
    def timeout():
        return SysinternalsError("Timeout")

    @staticmethod
    def not_found(name):
        return SysinternalsError(f"NotFound({name})")


# -----------------------------------------------------------------------------
# Bitflags / Enums
# -----------------------------------------------------------------------------

class DriverFlags:
    NONE = 0
    LOADED = 1 << 0
    UNLOADABLE = 1 << 1
    KERNEL_MODE = 1 << 2
    FS_FILTER = 1 << 3

    def __init__(self, bits=0):
        self.bits = bits

    def contains(self, flag):
        return (self.bits & flag) == flag and flag != 0 or (flag == 0 and self.bits == 0)

    def __str__(self):
        if self.bits == 0:
            return "NONE"
        parts = []
        for name, val in (
            ("LOADED", self.LOADED),
            ("UNLOADABLE", self.UNLOADABLE),
            ("KERNEL_MODE", self.KERNEL_MODE),
            ("FS_FILTER", self.FS_FILTER),
        ):
            if self.bits & val:
                parts.append(name)
        return "|".join(parts)


class ThreadState(Enum):
    Running = "Running"
    Waiting = "Waiting"
    Ready = "Ready"
    Terminated = "Terminated"
    Unknown = "Unknown"


class ProcessStatus(Enum):
    Running = "Running"
    Sleeping = "Sleeping"
    Stopped = "Stopped"
    Zombie = "Zombie"
    Unknown = "Unknown"


class NetworkProtocol(Enum):
    Tcp = "Tcp"
    Udp = "Udp"
    Tcp6 = "Tcp6"
    Udp6 = "Udp6"
    Raw = "Raw"


class TcpState(Enum):
    Listen = "Listen"
    Established = "Established"
    TimeWait = "TimeWait"
    CloseWait = "CloseWait"
    Closed = "Closed"
    SynSent = "SynSent"
    SynReceived = "SynReceived"
    FinWait1 = "FinWait1"
    FinWait2 = "FinWait2"
    LastAck = "LastAck"
    Closing = "Closing"
    Unknown = "Unknown"


class RegistryDataType(Enum):
    RegSz = "RegSz"
    RegExpandSz = "RegExpandSz"
    RegBinary = "RegBinary"
    RegDword = "RegDword"
    RegQword = "RegQword"
    RegMultiSz = "RegMultiSz"


AUTORUN_CATEGORIES = (
    "LogonRegistry", "RunOnce", "Services", "ScheduledTasks", "StartupFolder",
    "BrowserExtension", "WmiSubscription", "BootExecute", "ImageFileExecution",
    "AppCertDlls", "LsaNotifications", "Winlogon", "ShellExecuteHooks",
    "PrintMonitors", "NetworkProviders",
)


# -----------------------------------------------------------------------------
# Info structs
# -----------------------------------------------------------------------------

class MemoryStats:
    def __init__(self, working_set=0, private_bytes=0, virtual_size=0, peak_working_set=0):
        self.working_set = working_set
        self.private_bytes = private_bytes
        self.virtual_size = virtual_size
        self.peak_working_set = peak_working_set


class MemoryInfo:
    def __init__(self, vss=0, rss=0, peak_rss=0, shared=0, private=0, page_faults=0):
        self.vss = vss
        self.rss = rss
        self.peak_rss = peak_rss
        self.shared = shared
        self.private = private
        self.page_faults = page_faults

    def rss_vss_ratio(self) -> float:
        if self.vss == 0:
            return 0.0
        return self.rss / self.vss


class ModuleInfo:
    def __init__(self, base, size, name, path):
        self.base = base
        self.size = size
        self.name = name
        self.path = path

    def contains_addr(self, addr) -> bool:
        return self.base <= addr < self.base + self.size


class ThreadInfo:
    def __init__(self, tid, pid, start_address, priority, state):
        self.tid = tid
        self.pid = pid
        self.start_address = start_address
        self.priority = priority
        self.state = state


class ProcessInfo:
    def __init__(self, pid, parent_pid, process_name):
        self.pid = pid
        self.parent_pid = parent_pid
        self.process_name = process_name
        self.image_path = ""
        self.env = {}

    def get_env(self, key) -> Optional[str]:
        return self.env.get(key)

    def in_temp_dir(self) -> bool:
        p = self.image_path.lower()
        return "\\temp\\" in p or "/tmp/" in p or "\\appdata\\local\\temp" in p

    def is_system32(self) -> bool:
        p = self.image_path.lower()
        return "\\system32\\" in p or "/system32/" in p

    def to_csv_row(self) -> str:
        return f"{self.pid},{self.parent_pid},{self.process_name}"

    def to_json(self) -> str:
        try:
            return json.dumps({
                "pid": self.pid,
                "parent_pid": self.parent_pid,
                "process_name": self.process_name,
            })
        except Exception as e:
            raise SysinternalsError.invalid_data(str(e))


class DriverInfo:
    def __init__(self, base, size, path, name, flags):
        self.base = base
        self.size = size
        self.path = path
        self.name = name
        self.flags = flags


class HandleInfo:
    def __init__(self, handle, pid, type_name, object_address, access_mask):
        self.handle = handle
        self.pid = pid
        self.type_name = type_name
        self.object_address = object_address
        self.access_mask = access_mask


class RegistryValue:
    def __init__(self, hive, key_path, value_name, data_type, data):
        self.hive = hive
        self.key_path = key_path
        self.value_name = value_name
        self.data_type = data_type
        self.data = data


class NetworkEndpoint:
    def __init__(self, pid, protocol, local_addr, local_port, remote_addr, remote_port, state):
        self.pid = pid
        self.protocol = protocol
        self.local_addr = local_addr
        self.local_port = local_port
        self.remote_addr = remote_addr
        self.remote_port = remote_port
        self.state = state


class NetworkConnection:
    def __init__(self, pid, process_name, protocol, local_addr, local_port,
                 remote_addr, remote_port, state):
        self.pid = pid
        self.process_name = process_name
        self.protocol = protocol
        self.local_addr = local_addr
        self.local_port = local_port
        self.remote_addr = remote_addr
        self.remote_port = remote_port
        self.state = state

    @staticmethod
    def new_tcp(pid, process_name, local_addr, local_port, remote_addr, remote_port, state):
        return NetworkConnection(pid, process_name, NetworkProtocol.Tcp,
                                 local_addr, local_port, remote_addr, remote_port, state)

    def is_established(self) -> bool:
        return self.state == TcpState.Established

    def is_listening(self) -> bool:
        return self.state == TcpState.Listen

    def to_csv_row(self) -> str:
        return (f"{self.pid},{self.process_name},{self.protocol.value},"
                f"{self.local_addr}:{self.local_port},"
                f"{self.remote_addr}:{self.remote_port},{self.state.value}")


class SystemSnapshot:
    def __init__(self):
        self.processes = []
        self.drivers = []
        self.handles = []
        self.connections = []

    @staticmethod
    def empty():
        return SystemSnapshot()


# -----------------------------------------------------------------------------
# SystemMonitor trait + InMemory impl
# -----------------------------------------------------------------------------

class InMemorySystemMonitor:
    def __init__(self):
        self._procs = []
        self._drivers = []
        self._handles = []
        self._endpoints = []

    def add_process(self, p):
        self._procs.append(p)

    def add_driver(self, d):
        self._drivers.append(d)

    def add_handle(self, h):
        self._handles.append(h)

    def add_endpoint(self, e):
        self._endpoints.append(e)

    def list_processes(self):
        return list(self._procs)

    def list_drivers(self):
        return list(self._drivers)

    def list_handles(self, pid=None):
        if pid is None:
            return list(self._handles)
        return [h for h in self._handles if h.pid == pid]

    def network_connections(self):
        return list(self._endpoints)

    def snapshot(self):
        s = SystemSnapshot()
        s.processes = list(self._procs)
        s.drivers = list(self._drivers)
        s.handles = list(self._handles)
        s.connections = list(self._endpoints)
        return s


# -----------------------------------------------------------------------------
# ProcessTree (cycle-safe)
# -----------------------------------------------------------------------------

class ProcessNode:
    def __init__(self, info, depth=0):
        self.info = info
        self.children = []
        self._depth = depth

    def depth(self):
        return self._depth


class ProcessTree:
    def __init__(self, roots):
        self.roots = roots  # list[ProcessNode]

    @staticmethod
    def from_list(processes):
        # Build pid -> info map
        by_pid = {p.pid: p for p in processes}
        # Detect cycles: process where ancestors loop
        def has_cycle(pid):
            seen = set()
            cur = pid
            while cur in by_pid:
                if cur in seen:
                    return True
                seen.add(cur)
                parent = by_pid[cur].parent_pid
                if parent == cur:
                    return True
                if parent not in by_pid:
                    return False
                cur = parent
            return False

        # Find roots (parent not in pid map) and skip cyclic entries
        roots = []
        children_map = {}
        for p in processes:
            if has_cycle(p.pid):
                continue
            children_map.setdefault(p.parent_pid, []).append(p)

        def build(info, depth):
            node = ProcessNode(info, depth)
            for ch in children_map.get(info.pid, []):
                node.children.append(build(ch, depth + 1))
            return node

        for p in processes:
            if has_cycle(p.pid):
                continue
            if p.parent_pid not in by_pid or p.parent_pid == p.pid:
                roots.append(build(p, 0))
        return ProcessTree(roots)

    def find(self, pid):
        def walk(node):
            if node.info.pid == pid:
                return node
            for c in node.children:
                hit = walk(c)
                if hit is not None:
                    return hit
            return None
        for r in self.roots:
            hit = walk(r)
            if hit is not None:
                return hit
        return None

    def depth_first_iter(self):
        stack = list(reversed(self.roots))
        while stack:
            n = stack.pop()
            yield n
            for c in reversed(n.children):
                stack.append(c)

    def to_text(self, indent=2):
        lines = []

        def walk(node, level):
            pad = " " * (indent * level)
            lines.append(f"{pad}{node.info.pid} {node.info.process_name}")
            for c in node.children:
                walk(c, level + 1)
        for r in self.roots:
            walk(r, 0)
        return "\n".join(lines)

    def count(self):
        n = 0
        for _ in self.depth_first_iter():
            n += 1
        return n

    def max_depth(self):
        m = 0
        for node in self.depth_first_iter():
            if node._depth > m:
                m = node._depth
        return m


# -----------------------------------------------------------------------------
# ProcessScanner
# -----------------------------------------------------------------------------

class ProcessScanner:
    def __init__(self, refresh_interval_secs):
        self.refresh_interval_secs = refresh_interval_secs
        self._cache = {}
        self._last_refresh = 0

    @staticmethod
    def scan():
        return []  # stub

    @staticmethod
    def get_process(pid):
        raise SysinternalsError.process_not_found(pid)

    @staticmethod
    def find_by_name(name):
        return []  # stub

    @staticmethod
    def process_tree_from(processes):
        return ProcessTree.from_list(processes)

    @staticmethod
    def process_tree():
        return ProcessTree([])

    @staticmethod
    def orphaned_processes(tree):
        # In stubbed empty-scan model, return []
        return []

    def needs_refresh(self):
        # Always true if interval is 0; otherwise based on a simple flag
        return self._last_refresh == 0

    def update_cache(self, processes):
        self._cache = {p.pid: p for p in processes}
        self._last_refresh = 1

    def cached(self, pid):
        return self._cache.get(pid)


# -----------------------------------------------------------------------------
# Autoruns
# -----------------------------------------------------------------------------

class AutorunEntry:
    def __init__(self, category, location, name, image_path, launch_string):
        self.category = category
        self.location = location
        self.name = name
        self.image_path = image_path
        self.launch_string = launch_string
        self.signed = True

    def is_suspicious_path(self) -> bool:
        p = self.image_path.lower()
        return ("\\temp\\" in p or "\\appdata\\" in p or "/tmp/" in p
                or p.startswith("\\\\") or p.startswith("c:\\users\\public"))

    def is_unsigned(self) -> bool:
        return not self.signed

    def to_csv_row(self) -> str:
        return f"{self.category},{self.location},{self.name},{self.image_path}"


class AutorunDiff:
    def __init__(self, added=None, removed=None, modified=None):
        self.added = added or []
        self.removed = removed or []
        self.modified = modified or []

    def is_clean(self) -> bool:
        return not (self.added or self.removed or self.modified)

    def total_changes(self) -> int:
        return len(self.added) + len(self.removed) + len(self.modified)


class AutorunScanner:
    @staticmethod
    def scan_all():
        return []

    @staticmethod
    def scan_category(cat):
        return []

    @staticmethod
    def filter_suspicious(entries):
        return [e for e in entries if e.is_suspicious_path()]

    @staticmethod
    def filter_unsigned(entries):
        return [e for e in entries if e.is_unsigned()]

    @staticmethod
    def diff(baseline, current):
        b_keys = {(e.category, e.location, e.name): e for e in baseline}
        c_keys = {(e.category, e.location, e.name): e for e in current}
        added = [v for k, v in c_keys.items() if k not in b_keys]
        removed = [v for k, v in b_keys.items() if k not in c_keys]
        modified = [c_keys[k] for k in b_keys.keys() & c_keys.keys()
                    if b_keys[k].image_path != c_keys[k].image_path]
        return AutorunDiff(added, removed, modified)


# -----------------------------------------------------------------------------
# Signature checking
# -----------------------------------------------------------------------------

class CertInfo:
    def __init__(self, subject, issuer, serial, not_before, not_after, is_root):
        self.subject = subject
        self.issuer = issuer
        self.serial = serial
        self.not_before = not_before
        self.not_after = not_after
        self.is_root = is_root

    def valid_at(self, unix_ts) -> bool:
        return self.not_before <= unix_ts <= self.not_after


class SignatureInfo:
    def __init__(self, path, signed=False, certs=None):
        self.path = path
        self.signed = signed
        self.certs = certs or []

    @staticmethod
    def unsigned(path):
        return SignatureInfo(path, signed=False, certs=[])

    def has_root_cert(self) -> bool:
        return any(c.is_root for c in self.certs)


class FileSignatureChecker:
    @staticmethod
    def has_pe_signature(data: bytes) -> bool:
        if len(data) < 0x40 or data[:2] != b"MZ":
            return False
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_off + 4 > len(data):
            return False
        return data[pe_off:pe_off + 4] == b"PE\x00\x00"

    @staticmethod
    def check(path):
        # Stub: returns unsigned for any path (real impl parses PE security dir)
        return SignatureInfo.unsigned(path)

    @staticmethod
    def hash_sha256(path):
        import hashlib
        h = hashlib.sha256()
        with open(path, "rb") as f:
            h.update(f.read())
        return h.hexdigest()

    @staticmethod
    def hash_md5(path):
        import hashlib
        h = hashlib.md5()
        with open(path, "rb") as f:
            h.update(f.read())
        return h.hexdigest()


# -----------------------------------------------------------------------------
# NetworkMonitor
# -----------------------------------------------------------------------------

class NetworkMonitor:
    @staticmethod
    def snapshot():
        return []

    @staticmethod
    def connections_for_pid(pid):
        return []

    @staticmethod
    def listening_ports():
        return []

    @staticmethod
    def connections_to_addr(addr):
        return []

    @staticmethod
    def filter_listening(conns):
        return [c for c in conns if c.is_listening()]

    @staticmethod
    def filter_established(conns):
        return [c for c in conns if c.is_established()]

    @staticmethod
    def group_by_pid(conns):
        out = {}
        for c in conns:
            out.setdefault(c.pid, []).append(c)
        return out

    @staticmethod
    def to_csv(conns):
        header = "pid,process,protocol,local,remote,state"
        return "\n".join([header] + [c.to_csv_row() for c in conns]) + "\n"


class ResourceUsage:
    def __init__(self, pid, cpu_percent=0.0, memory_bytes=0):
        self.pid = pid
        self.cpu_percent = cpu_percent
        self.memory_bytes = memory_bytes


# -----------------------------------------------------------------------------
# Self-tests
# -----------------------------------------------------------------------------

def _run_tests():
    # DriverFlags
    f = DriverFlags(DriverFlags.LOADED | DriverFlags.KERNEL_MODE)
    s = str(f)
    assert "LOADED" in s and "KERNEL_MODE" in s
    assert str(DriverFlags(0)) == "NONE"

    # Enum sanity
    assert AUTORUN_CATEGORIES[0] == "LogonRegistry"
    assert len(AUTORUN_CATEGORIES) == 15

    # MemoryInfo ratio
    mi = MemoryInfo(vss=1000, rss=500)
    assert mi.rss_vss_ratio() == 0.5
    assert MemoryInfo().rss_vss_ratio() == 0.0

    # ModuleInfo.contains_addr
    m = ModuleInfo(0x1000, 0x100, "x.dll", "/x.dll")
    assert m.contains_addr(0x1050) and not m.contains_addr(0x1100)

    # ProcessInfo flags
    p = ProcessInfo(10, 1, "evil.exe")
    p.image_path = "C:\\Windows\\Temp\\evil.exe"
    assert p.in_temp_dir()
    p2 = ProcessInfo(11, 1, "svchost.exe")
    p2.image_path = "C:\\Windows\\System32\\svchost.exe"
    assert p2.is_system32() and not p2.in_temp_dir()
    js = p2.to_json()
    assert json.loads(js)["pid"] == 11
    assert p2.to_csv_row() == "11,1,svchost.exe"
    p2.env["FOO"] = "BAR"
    assert p2.get_env("FOO") == "BAR" and p2.get_env("missing") is None

    # NetworkConnection
    c = NetworkConnection.new_tcp(7, "svc", "0.0.0.0", 80, "0.0.0.0", 0, TcpState.Listen)
    assert c.is_listening() and not c.is_established()
    c2 = NetworkConnection.new_tcp(7, "svc", "10.0.0.1", 5000, "1.2.3.4", 80, TcpState.Established)
    assert c2.is_established()
    csv = NetworkMonitor.to_csv([c, c2])
    assert "Listen" in csv and "Established" in csv
    grouped = NetworkMonitor.group_by_pid([c, c2])
    assert grouped[7] == [c, c2]
    assert NetworkMonitor.filter_listening([c, c2]) == [c]
    assert NetworkMonitor.filter_established([c, c2]) == [c2]

    # InMemorySystemMonitor
    mon = InMemorySystemMonitor()
    mon.add_process(p2)
    mon.add_driver(DriverInfo(0, 0, "/d", "d", DriverFlags(DriverFlags.LOADED)))
    mon.add_handle(HandleInfo(1, 11, "File", 0xdead, 0x1))
    mon.add_handle(HandleInfo(2, 99, "Mutex", 0xbeef, 0x2))
    mon.add_endpoint(NetworkEndpoint(11, NetworkProtocol.Tcp, "0", 1, "0", 2, TcpState.Listen))
    assert len(mon.list_handles()) == 2
    assert len(mon.list_handles(pid=11)) == 1
    snap = mon.snapshot()
    assert len(snap.processes) == 1 and len(snap.drivers) == 1

    # ProcessTree: parent/child + cycle-safe
    procs = [
        ProcessInfo(1, 0, "init"),
        ProcessInfo(2, 1, "child"),
        ProcessInfo(3, 2, "grand"),
        ProcessInfo(100, 101, "cyc_a"),  # cyclic with 101
        ProcessInfo(101, 100, "cyc_b"),
    ]
    tree = ProcessTree.from_list(procs)
    assert tree.count() == 3  # cycle pair dropped
    assert tree.max_depth() == 2
    n = tree.find(3)
    assert n is not None and n.depth() == 2
    txt = tree.to_text(indent=2)
    assert "init" in txt and "grand" in txt

    # Orphan/no-op
    assert ProcessScanner.orphaned_processes(tree) == []
    sc = ProcessScanner(refresh_interval_secs=60)
    assert sc.needs_refresh()
    sc.update_cache(procs)
    assert not sc.needs_refresh()
    assert sc.cached(1).process_name == "init"
    assert sc.cached(999) is None
    try:
        ProcessScanner.get_process(42)
        raise AssertionError("expected error")
    except SysinternalsError as e:
        assert "ProcessNotFound" in str(e)

    # Autoruns
    a1 = AutorunEntry("Services", "HKLM\\...", "svc1", "C:\\Windows\\System32\\svc1.exe", "")
    a2 = AutorunEntry("RunOnce", "HKCU\\...", "bad", "C:\\Users\\x\\AppData\\Local\\Temp\\bad.exe", "")
    a2.signed = False
    assert not a1.is_suspicious_path()
    assert a2.is_suspicious_path() and a2.is_unsigned()
    assert AutorunScanner.filter_suspicious([a1, a2]) == [a2]
    assert AutorunScanner.filter_unsigned([a1, a2]) == [a2]

    a2b = AutorunEntry("RunOnce", "HKCU\\...", "bad", "C:\\different.exe", "")
    a3 = AutorunEntry("Services", "HKLM\\...", "new", "C:\\n.exe", "")
    diff = AutorunScanner.diff([a1, a2], [a1, a2b, a3])
    assert len(diff.added) == 1 and diff.added[0].name == "new"
    assert len(diff.modified) == 1 and diff.modified[0].image_path == "C:\\different.exe"
    assert not diff.is_clean()
    assert diff.total_changes() == 2
    assert AutorunDiff().is_clean()

    # CertInfo
    cert = CertInfo("CN=A", "CN=Root", "01", 100, 200, True)
    assert cert.valid_at(150) and not cert.valid_at(300)

    # SignatureInfo
    si = SignatureInfo.unsigned("/x")
    assert not si.signed and not si.has_root_cert()
    si.certs = [cert]
    assert si.has_root_cert()

    # PE signature parsing
    # Minimal MZ + PE header
    pe = bytearray(0x100)
    pe[:2] = b"MZ"
    pe_off = 0x80
    struct.pack_into("<I", pe, 0x3C, pe_off)
    pe[pe_off:pe_off + 4] = b"PE\x00\x00"
    assert FileSignatureChecker.has_pe_signature(bytes(pe))
    assert not FileSignatureChecker.has_pe_signature(b"not pe")
    assert not FileSignatureChecker.has_pe_signature(b"MZ" + b"\x00" * 10)

    # FileSignatureChecker.check stub
    res = FileSignatureChecker.check("anything")
    assert not res.signed

    # Hashes against a tempfile
    import tempfile, hashlib
    with tempfile.NamedTemporaryFile(delete=False) as t:
        t.write(b"abc")
        path = t.name
    try:
        assert FileSignatureChecker.hash_sha256(path) == hashlib.sha256(b"abc").hexdigest()
        assert FileSignatureChecker.hash_md5(path) == hashlib.md5(b"abc").hexdigest()
    finally:
        import os
        os.unlink(path)

    # Error variants
    for ctor, ok in (
        (SysinternalsError.access_denied(), "AccessDenied"),
        (SysinternalsError.unsupported(), "Unsupported"),
        (SysinternalsError.io("x"), "Io"),
        (SysinternalsError.timeout(), "Timeout"),
        (SysinternalsError.not_found("y"), "NotFound"),
        (SysinternalsError.invalid_data("z"), "InvalidData"),
    ):
        assert ok in str(ctor)

    # SystemSnapshot.empty
    e = SystemSnapshot.empty()
    assert e.processes == [] and e.connections == []

    print("OK rustre-sysinternals validator: all tests passed")


if __name__ == "__main__":
    _run_tests()
