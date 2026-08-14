"""Independent stdlib validator for rustre-forensics-fs.

Models a minimal MemFs / MemoryFs virtual tree for forensic memory images,
including export-to-disk with path-traversal sanitization, DFS walkers,
CSV escaping, and FUSE-mount stub behavior.
"""

import json
import os
from pathlib import Path


# -----------------------------------------------------------------------------
# Sanitization helpers
# -----------------------------------------------------------------------------

def sanitize_filename(name: str) -> str:
    """Keep [A-Za-z0-9._-], replace the rest with '_'."""
    out = []
    for ch in name:
        if ch.isalnum() or ch in "._-":
            out.append(ch)
        else:
            out.append("_")
    return "".join(out)


def sanitize_export_name(name: str) -> str:
    """Stricter: forbid path traversal and separators."""
    if name in (".", ".."):
        return "_"
    bad = ("/", "\\", "\0")
    out = []
    for ch in name:
        if ch in bad:
            out.append("_")
        else:
            out.append(ch)
    return "".join(out)


# -----------------------------------------------------------------------------
# V1: MemFsNode (Directory / File / LazyFile)
# -----------------------------------------------------------------------------

class MemFsNode:
    __slots__ = ("kind", "children", "data", "lazy")

    def __init__(self, kind, children=None, data=None, lazy=None):
        self.kind = kind  # "dir" | "file" | "lazy"
        self.children = children  # list[(name, MemFsNode)] for dirs
        self.data = data  # bytes for file
        self.lazy = lazy  # callable -> bytes for lazy

    @staticmethod
    def directory(entries):
        return MemFsNode("dir", children=list(entries))

    @staticmethod
    def file(data: bytes):
        return MemFsNode("file", data=bytes(data))

    @staticmethod
    def lazy_file(producer):
        return MemFsNode("lazy", lazy=producer)

    def is_dir(self) -> bool:
        return self.kind == "dir"

    def is_file(self) -> bool:
        return self.kind in ("file", "lazy")

    def read_bytes(self):
        if self.kind == "file":
            return self.data
        if self.kind == "lazy":
            return self.lazy()  # invoked every call, no caching
        return None

    def children_names(self):
        if not self.is_dir():
            return None
        return [n for n, _ in self.children]

    def child(self, name):
        if not self.is_dir():
            return None
        for n, c in self.children:
            if n == name:
                return c
        return None


# -----------------------------------------------------------------------------
# V2: MemFsNodeV2 (named, with inode + timestamps)
# -----------------------------------------------------------------------------

class MemFsNodeV2:
    __slots__ = ("name", "kind", "content", "inode", "created", "modified")

    def __init__(self, name, kind, content, inode, created=0, modified=0):
        self.name = name
        self.kind = kind  # "file" | "dir"
        self.content = content  # bytes for file, list[MemFsNodeV2] for dir
        self.inode = inode
        self.created = created
        self.modified = modified

    @staticmethod
    def new_file(name, content: bytes, inode: int):
        return MemFsNodeV2(str(name), "file", bytes(content), inode)

    @staticmethod
    def new_dir(name, inode: int):
        return MemFsNodeV2(str(name), "dir", [], inode)

    def is_dir(self) -> bool:
        return self.kind == "dir"

    def is_file(self) -> bool:
        return self.kind == "file"

    def add_child(self, child):
        if not self.is_dir():
            raise ValueError("cannot add_child to file node")
        self.content.append(child)

    def find_child(self, name):
        if not self.is_dir():
            return None
        for c in self.content:
            if c.name == name:
                return c
        return None

    def size(self) -> int:
        if self.is_file():
            return len(self.content)
        return 0

    def find_by_inode(self, ino: int):
        if self.inode == ino:
            return self
        if self.is_dir():
            for c in self.content:
                hit = c.find_by_inode(ino)
                if hit is not None:
                    return hit
        return None

    def readdir_entries(self):
        if not self.is_dir():
            return []
        return [(c.inode, c.name, c.is_dir()) for c in self.content]


# -----------------------------------------------------------------------------
# CSV helpers
# -----------------------------------------------------------------------------

def csv_escape(field: str) -> str:
    s = str(field)
    if any(ch in s for ch in (",", '"', "\n", "\r")):
        return '"' + s.replace('"', '""') + '"'
    return s


def csv_row(fields) -> str:
    return ",".join(csv_escape(f) for f in fields)


# -----------------------------------------------------------------------------
# Mock domain types
# -----------------------------------------------------------------------------

class ProcessInfo:
    def __init__(self, pid, name, cmdline="", handle_count=0, memory_regions=None):
        self.pid = pid
        self.name = name
        self.cmdline = cmdline
        self.handle_count = handle_count
        self.memory_regions = memory_regions or []  # list of (start, end)


class ModuleInfo:
    def __init__(self, name, base=0, size=0):
        self.name = name
        self.base = base
        self.size = size


class NetworkConnection:
    def __init__(self, local, remote, state):
        self.local = local
        self.remote = remote
        self.state = state


class MemoryImage:
    def __init__(self, os_type, processes, modules, connections, kernel_modules):
        self.os_type = os_type  # "windows" | "linux"
        self.processes = processes
        self.modules = modules
        self.connections = connections
        self.kernel_modules = kernel_modules

    def read(self, start, length):
        return bytes((i & 0xFF) for i in range(start, start + length))


# -----------------------------------------------------------------------------
# MemoryFs (V2 tree)
# -----------------------------------------------------------------------------

class MemoryFs:
    def __init__(self):
        self._next_inode = 2
        self._root = MemFsNodeV2.new_dir("", 1)

    def _alloc(self):
        i = self._next_inode
        self._next_inode += 1
        return i

    def root(self):
        return self._root

    def into_root(self):
        return self._root

    @staticmethod
    def build_process_tree(processes, modules):
        fs = MemoryFs()
        procs = MemFsNodeV2.new_dir("processes", fs._alloc())
        for p in processes:
            dname = f"{p.pid}_{sanitize_filename(p.name)}"
            pdir = MemFsNodeV2.new_dir(dname, fs._alloc())
            info_txt = f"pid={p.pid}\nname={p.name}\nhandles={p.handle_count}\n"
            pdir.add_child(MemFsNodeV2.new_file("info.txt", info_txt.encode(), fs._alloc()))
            mdir = MemFsNodeV2.new_dir("modules", fs._alloc())
            # Attaches all modules to every process (no per-PID filter).
            for m in modules:
                mname = sanitize_filename(m.name) + ".txt"
                mtxt = f"name={m.name}\nbase=0x{m.base:x}\nsize={m.size}\n"
                mdir.add_child(MemFsNodeV2.new_file(mname, mtxt.encode(), fs._alloc()))
            pdir.add_child(mdir)
            pdir.add_child(MemFsNodeV2.new_file(
                "handles.csv",
                MemoryFs._build_handles_csv(p).encode(),
                fs._alloc(),
            ))
            procs.add_child(pdir)
        fs._root.add_child(procs)
        return fs

    @staticmethod
    def _build_handles_csv(proc):
        lines = [csv_row(("handle", "type", "name"))]
        # Placeholder: up to 8 synthetic rows derived from handle_count.
        n = min(8, max(0, proc.handle_count))
        for i in range(n):
            lines.append(csv_row((str(i), "File", f"synthetic_{i}")))
        return "\n".join(lines) + "\n"


# -----------------------------------------------------------------------------
# MemFs (V1 tree)
# -----------------------------------------------------------------------------

class MemFs:
    def __init__(self, root):
        self._root = root

    def root(self):
        return self._root

    @staticmethod
    def build(image):
        processes_children = []
        for p in image.processes:
            dname = f"{p.pid}_{sanitize_filename(p.name)}"
            entries = []
            # info.json (serde_json::to_vec_pretty equivalent)
            try:
                payload = {
                    "pid": p.pid,
                    "name": p.name,
                    "handle_count": p.handle_count,
                }
                info_bytes = json.dumps(payload, indent=2).encode()
            except Exception as e:  # textual fallback
                info_bytes = f"pid={p.pid} name={p.name} (serialization error: {e})".encode()
            entries.append(("info.json", MemFsNode.file(info_bytes)))
            # cmdline.txt synthesised from process name.
            cmdline = p.cmdline or p.name
            entries.append(("cmdline.txt", MemFsNode.file(cmdline.encode())))
            # modules.csv
            mod_lines = [csv_row(("name", "base", "size"))]
            for m in image.modules:
                mod_lines.append(csv_row((m.name, f"0x{m.base:x}", str(m.size))))
            entries.append(("modules.csv", MemFsNode.file(("\n".join(mod_lines) + "\n").encode())))
            # memory/<start>_<end>.bin (eagerly materialised)
            mem_entries = []
            for (start, end) in p.memory_regions:
                data = image.read(start, end - start)
                mem_entries.append((f"{start}_{end}.bin", MemFsNode.file(data)))
            entries.append(("memory", MemFsNode.directory(mem_entries)))
            processes_children.append((dname, MemFsNode.directory(entries)))

        # /network/connections.csv
        net_lines = [csv_row(("local", "remote", "state"))]
        for c in image.connections:
            net_lines.append(csv_row((c.local, c.remote, c.state)))
        net = MemFsNode.directory([
            ("connections.csv", MemFsNode.file(("\n".join(net_lines) + "\n").encode())),
        ])

        # /kernel/modules.csv
        k_lines = [csv_row(("name", "base", "size"))]
        for m in image.kernel_modules:
            k_lines.append(csv_row((m.name, f"0x{m.base:x}", str(m.size))))
        kernel = MemFsNode.directory([
            ("modules.csv", MemFsNode.file(("\n".join(k_lines) + "\n").encode())),
        ])

        root = MemFsNode.directory([
            ("processes", MemFsNode.directory(processes_children)),
            ("network", net),
            ("kernel", kernel),
        ])
        return MemFs(root)

    def resolve(self, path: str):
        node = self._root
        for part in [p for p in path.split("/") if p]:
            if not node.is_dir():
                return None
            nxt = node.child(part)
            if nxt is None:
                return None
            node = nxt
        return node

    def read_file(self, path: str):
        n = self.resolve(path)
        if n is None or not n.is_file():
            return None
        return n.read_bytes()

    def list_dir(self, path: str):
        n = self.resolve(path)
        if n is None or not n.is_dir():
            return None
        return n.children_names()

    def export(self, real_path: Path):
        real_path = Path(real_path)
        real_path.mkdir(parents=True, exist_ok=True)
        self._export_node(self._root, real_path)

    def _export_node(self, node, base: Path):
        if node.is_dir():
            for name, child in node.children:
                safe = sanitize_export_name(name)
                target = base / safe
                if child.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    self._export_node(child, target)
                else:
                    target.write_bytes(child.read_bytes() or b"")


# -----------------------------------------------------------------------------
# to_export_dir for V2 tree
# -----------------------------------------------------------------------------

def to_export_dir(node: MemFsNodeV2, base: Path):
    base = Path(base)
    base.mkdir(parents=True, exist_ok=True)
    if node.is_dir():
        for child in node.content:
            safe = sanitize_export_name(child.name) if child.name else None
            if safe is None:
                # root with empty name: recurse into base directly
                to_export_dir(child, base)
                continue
            target = base / safe
            if child.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                to_export_dir(child, target)
            else:
                target.write_bytes(child.content)


# -----------------------------------------------------------------------------
# DFS Walkers yielding (path, is_dir)
# -----------------------------------------------------------------------------

class MemFsWalker:
    def __init__(self, fs: MemFs):
        self._stack = [("", fs.root())]

    def __iter__(self):
        return self

    def __next__(self):
        if not self._stack:
            raise StopIteration
        path, node = self._stack.pop()
        if node.is_dir():
            # push children in reverse for deterministic DFS order
            for name, child in reversed(node.children):
                child_path = f"{path}/{name}" if path else f"/{name}"
                self._stack.append((child_path, child))
            return (path if path else "/", True)
        return (path, False)


class MemFsV2Walker:
    def __init__(self, fs: MemoryFs):
        self._stack = [("", fs.root())]

    def __iter__(self):
        return self

    def __next__(self):
        if not self._stack:
            raise StopIteration
        path, node = self._stack.pop()
        if node.is_dir():
            for child in reversed(node.content):
                child_path = f"{path}/{child.name}" if path else (f"/{child.name}" if child.name else path)
                self._stack.append((child_path, child))
            return (path if path else "/", True)
        return (path, False)


# -----------------------------------------------------------------------------
# FUSE stub: non-Unix returns error
# -----------------------------------------------------------------------------

def mount_memory_fs(fs_root: MemFsNodeV2, mountpoint: Path):
    """Non-Unix stub matching the Rust API surface."""
    if os.name == "nt":
        raise RuntimeError("FUSE filesystem requires Linux or macOS")
    raise RuntimeError("FUSE filesystem requires Linux or macOS")


# -----------------------------------------------------------------------------
# Mock builder mirroring rustre_forensics_mem::build_mock_image(Windows)
# -----------------------------------------------------------------------------

def build_mock_image_windows() -> MemoryImage:
    procs = [
        ProcessInfo(4, "System", "System", handle_count=12,
                    memory_regions=[(0x1000, 0x1010)]),
        ProcessInfo(1234, "explorer.exe", "C:\\Windows\\explorer.exe",
                    handle_count=3, memory_regions=[(0x2000, 0x2020)]),
    ]
    mods = [
        ModuleInfo("ntdll.dll", base=0x77000000, size=0x100000),
        ModuleInfo("kernel32.dll", base=0x76000000, size=0x80000),
    ]
    conns = [
        NetworkConnection("127.0.0.1:139", "0.0.0.0:0", "LISTEN"),
    ]
    kmods = [ModuleInfo("ntoskrnl.exe", base=0xFFFFF80000000000, size=0x800000)]
    return MemoryImage("windows", procs, mods, conns, kmods)


# -----------------------------------------------------------------------------
# Self-tests
# -----------------------------------------------------------------------------

def _run_tests():
    import tempfile

    # sanitize_filename
    assert sanitize_filename("a b/c") == "a_b_c"
    assert sanitize_filename("name.ext-1_2") == "name.ext-1_2"

    # sanitize_export_name
    assert sanitize_export_name("..") == "_"
    assert sanitize_export_name(".") == "_"
    assert sanitize_export_name("a/b") == "a_b"
    assert sanitize_export_name("a\\b\0c") == "a_b_c"

    # MemFsNode helpers
    f = MemFsNode.file(b"hello")
    assert f.is_file() and not f.is_dir() and f.read_bytes() == b"hello"
    d = MemFsNode.directory([("x", f)])
    assert d.is_dir() and d.children_names() == ["x"]
    assert d.child("x") is f and d.child("nope") is None

    # LazyFile invoked on every call
    counter = [0]
    def producer():
        counter[0] += 1
        return b"L"
    lz = MemFsNode.lazy_file(producer)
    assert lz.read_bytes() == b"L" and lz.read_bytes() == b"L"
    assert counter[0] == 2

    # MemFsNodeV2
    root = MemFsNodeV2.new_dir("", 1)
    sub = MemFsNodeV2.new_dir("sub", 2)
    leaf = MemFsNodeV2.new_file("a.txt", b"abc", 3)
    sub.add_child(leaf)
    root.add_child(sub)
    assert leaf.size() == 3
    assert root.find_child("sub") is sub
    assert root.find_by_inode(3) is leaf
    entries = sub.readdir_entries()
    assert entries == [(3, "a.txt", False)]
    try:
        leaf.add_child(MemFsNodeV2.new_file("x", b"", 9))
        raise AssertionError("expected ValueError")
    except ValueError:
        pass

    # CSV escaping
    assert csv_row(("a", "b,c")) == 'a,"b,c"'
    assert csv_row(('he said "hi"', "ok")) == '"he said ""hi""",ok'

    # MemFs::build layout + reads
    img = build_mock_image_windows()
    fs = MemFs.build(img)
    assert fs.list_dir("/") == ["processes", "network", "kernel"]
    procs = fs.list_dir("/processes")
    assert procs and any(p.startswith("4_") for p in procs)
    info = fs.read_file("/processes/4_System/info.json")
    assert info is not None
    parsed = json.loads(info.decode())
    assert parsed["pid"] == 4 and parsed["name"] == "System"
    cmd = fs.read_file("/processes/4_System/cmdline.txt")
    assert cmd == b"System"
    mods_csv = fs.read_file("/processes/4_System/modules.csv").decode()
    assert mods_csv.startswith("name,base,size")
    assert "ntdll.dll" in mods_csv
    net_csv = fs.read_file("/network/connections.csv").decode()
    assert net_csv.startswith("local,remote,state")
    assert "127.0.0.1:139" in net_csv
    k_csv = fs.read_file("/kernel/modules.csv").decode()
    assert "ntoskrnl.exe" in k_csv

    # Memory region eagerly materialised
    bin_data = fs.read_file("/processes/4_System/memory/4096_4112.bin")
    assert bin_data is not None and len(bin_data) == 16

    # Walker
    paths = [(p, d) for (p, d) in MemFsWalker(fs)]
    assert ("/", True) in paths
    assert any(p.endswith("/info.json") and not d for (p, d) in paths)

    # MemoryFs::build_process_tree
    mfs = MemoryFs.build_process_tree(img.processes, img.modules)
    r = mfs.root()
    procs_dir = r.find_child("processes")
    assert procs_dir is not None
    children = [c.name for c in procs_dir.content]
    assert any(n.startswith("1234_explorer") for n in children)
    # all modules attached to every process
    for c in procs_dir.content:
        mdir = c.find_child("modules")
        assert mdir is not None
        assert len(mdir.content) == len(img.modules)
    # handles.csv synthetic rows derived from handle_count
    sysproc = next(c for c in procs_dir.content if c.name.startswith("4_"))
    handles = sysproc.find_child("handles.csv")
    assert handles is not None
    hcsv = handles.content.decode()
    # 12 capped to 8 synthetic rows + header => 9 lines
    assert hcsv.count("\n") == 9
    explorer = next(c for c in procs_dir.content if c.name.startswith("1234_"))
    h2 = explorer.find_child("handles.csv").content.decode()
    assert h2.count("\n") == 4  # 3 rows + header

    # V2 walker
    v2_paths = [p for p, _ in MemFsV2Walker(mfs)]
    assert any("info.txt" in p for p in v2_paths)

    # to_export_dir with traversal-laden names
    evil = MemFsNodeV2.new_dir("export_root", 100)
    evil.add_child(MemFsNodeV2.new_file("..", b"bad", 101))
    evil.add_child(MemFsNodeV2.new_file("a/b", b"x", 102))
    evil.add_child(MemFsNodeV2.new_file("ok.txt", b"hi", 103))
    with tempfile.TemporaryDirectory() as td:
        to_export_dir(evil, Path(td))
        listed = sorted(os.listdir(td))
        assert "ok.txt" in listed
        assert "_" in listed  # ".." sanitised
        assert "a_b" in listed
        assert (Path(td) / "ok.txt").read_bytes() == b"hi"

    # MemFs::export
    with tempfile.TemporaryDirectory() as td:
        fs.export(Path(td))
        assert (Path(td) / "processes").is_dir()
        assert (Path(td) / "network" / "connections.csv").is_file()

    # mount_memory_fs non-Unix error
    try:
        mount_memory_fs(mfs.root(), Path("/tmp/x"))
        raise AssertionError("expected RuntimeError")
    except RuntimeError as e:
        assert "FUSE" in str(e)

    print("OK rustre-forensics-fs validator: all tests passed")


if __name__ == "__main__":
    _run_tests()
