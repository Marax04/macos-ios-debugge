"""Independent validator for rustre-debug-linux based on the report analysis.

Reimplements (in pure Python stdlib) the two parsers that are platform-independent
in the crate:

  * ProcMapsParser.parse_line / parse  -> /proc/<pid>/maps lines
  * parse_proc_maps                    -> richer ProcMapsEntry alternative

These are the only fully testable surfaces without a Linux ptrace runtime.
Everything else (LinuxDebugger trait ops) requires Linux/ptrace and is out of
scope for a stdlib validator.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# MemoryMap (mirrors rustre_debug::MemoryMap shape needed by the parser)
# ---------------------------------------------------------------------------

@dataclass
class MemoryMap:
    base: int
    size: int
    readable: bool
    writable: bool
    executable: bool
    name: Optional[str] = None
    file_path: Optional[str] = None
    file_offset: int = 0


# ---------------------------------------------------------------------------
# ProcMapsParser
# ---------------------------------------------------------------------------

class ProcMapsParser:
    """Parses /proc/<pid>/maps into MemoryMap records."""

    @staticmethod
    def parse(content: str) -> List[MemoryMap]:
        out: List[MemoryMap] = []
        for line in content.splitlines():
            entry = ProcMapsParser.parse_line(line)
            if entry is not None:
                out.append(entry)
        return out

    @staticmethod
    def parse_line(line: str) -> Optional[MemoryMap]:
        # format: addr_lo-addr_hi perms offset dev inode [pathname]
        line = line.rstrip("\n")
        if not line.strip():
            return None
        parts = line.split(None, 5)
        if len(parts) < 5:
            return None
        addr_range = parts[0]
        perms = parts[1]
        offset_s = parts[2]
        # parts[3] = dev, parts[4] = inode
        pathname = parts[5].strip() if len(parts) >= 6 else ""

        if "-" not in addr_range:
            return None
        lo_s, hi_s = addr_range.split("-", 1)
        try:
            lo = int(lo_s, 16)
            hi = int(hi_s, 16)
            offset = int(offset_s, 16)
        except ValueError:
            return None
        if hi < lo:
            return None

        if len(perms) < 3:
            return None
        readable = perms[0] == "r"
        writable = perms[1] == "w"
        executable = perms[2] == "x"

        name: Optional[str] = None
        file_path: Optional[str] = None
        if pathname:
            if pathname.startswith("[") and pathname.endswith("]"):
                name = pathname
            else:
                file_path = pathname
                name = os.path.basename(pathname) or pathname

        return MemoryMap(
            base=lo,
            size=hi - lo,
            readable=readable,
            writable=writable,
            executable=executable,
            name=name,
            file_path=file_path,
            file_offset=offset,
        )


# ---------------------------------------------------------------------------
# parse_proc_maps -> ProcMapsEntry (richer variant)
# ---------------------------------------------------------------------------

@dataclass
class ProcMapsEntry:
    start: int
    end: int
    perms: str
    offset: int
    dev: str
    inode: int
    pathname: Optional[str] = None


def parse_proc_maps(content: str) -> List[ProcMapsEntry]:
    out: List[ProcMapsEntry] = []
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
            perms = parts[1]
            offset = int(parts[2], 16)
            dev = parts[3]
            inode = int(parts[4])
        except (ValueError, IndexError):
            continue
        pathname = parts[5].strip() if len(parts) >= 6 and parts[5].strip() else None
        out.append(ProcMapsEntry(start, end, perms, offset, dev, inode, pathname))
    return out


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def _self_test() -> None:
    sample = (
        "55a1b2c3d000-55a1b2c40000 r-xp 00000000 08:01 12345 /usr/bin/cat\n"
        "7ffd1234a000-7ffd1234c000 rw-p 00000000 00:00 0 [stack]\n"
        "7f0000000000-7f0000001000 r--p 00001000 00:00 0 [vdso]\n"
        "garbage line\n"
        "\n"
    )
    maps = ProcMapsParser.parse(sample)
    assert len(maps) == 3, maps
    m0 = maps[0]
    assert m0.base == 0x55a1b2c3d000
    assert m0.size == 0x3000
    assert m0.readable and not m0.writable and m0.executable
    assert m0.file_path == "/usr/bin/cat"
    assert m0.name == "cat"
    assert m0.file_offset == 0

    m1 = maps[1]
    assert m1.name == "[stack]"
    assert m1.file_path is None
    assert m1.writable and not m1.executable

    m2 = maps[2]
    assert m2.name == "[vdso]"
    assert m2.file_offset == 0x1000

    entries = parse_proc_maps(sample)
    assert len(entries) == 3
    assert entries[0].pathname == "/usr/bin/cat"
    assert entries[0].inode == 12345
    assert entries[1].pathname == "[stack]"

    # Garbage / partial lines -> None
    assert ProcMapsParser.parse_line("") is None
    assert ProcMapsParser.parse_line("not a maps line") is None
    assert ProcMapsParser.parse_line("zzzz-yyyy r-xp 0 00:00 0") is None


if __name__ == "__main__":
    _self_test()
    print("rustre-debug-linux validator: OK")
