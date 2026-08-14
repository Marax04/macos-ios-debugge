#!/usr/bin/env python3
"""Independent validator for rustre-dotnet-metadata: parses .NET CLI metadata (ECMA-335)."""
import json, struct, sys, os

class R:
    def __init__(self, data, o=0):
        self.d = data; self.o = o
    def u8(self):  v = self.d[self.o]; self.o += 1; return v
    def u16(self): v = struct.unpack_from("<H", self.d, self.o)[0]; self.o += 2; return v
    def u32(self): v = struct.unpack_from("<I", self.d, self.o)[0]; self.o += 4; return v
    def take(self, n): v = self.d[self.o:self.o+n]; self.o += n; return v

def parse_pe(data):
    if data[:2] != b"MZ": raise ValueError("not PE")
    pe_off = struct.unpack_from("<I", data, 0x3c)[0]
    if data[pe_off:pe_off+4] != b"PE\0\0": raise ValueError("no PE sig")
    coff = pe_off + 4
    nsec = struct.unpack_from("<H", data, coff+2)[0]
    opt_size = struct.unpack_from("<H", data, coff+16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    pe32p = (magic == 0x20b)
    # CLI header is data directory index 14
    dd_off = opt + (112 if pe32p else 96)
    cli_rva = struct.unpack_from("<I", data, dd_off + 14*8)[0]
    cli_size = struct.unpack_from("<I", data, dd_off + 14*8 + 4)[0]
    sections = []
    sh = opt + opt_size
    for i in range(nsec):
        s = sh + i*40
        vs = struct.unpack_from("<I", data, s+8)[0]
        va = struct.unpack_from("<I", data, s+12)[0]
        rs = struct.unpack_from("<I", data, s+16)[0]
        ro = struct.unpack_from("<I", data, s+20)[0]
        sections.append((va, vs, ro, rs))
    def rva2off(rva):
        for va, vs, ro, rs in sections:
            if va <= rva < va + max(vs, rs):
                return ro + (rva - va)
        return None
    return cli_rva, cli_size, rva2off

def parse_metadata(data):
    cli_rva, cli_size, rva2off = parse_pe(data)
    if cli_rva == 0:
        return {"managed": False}
    cli_off = rva2off(cli_rva)
    # CLI header: cb(4), MajRT(2), MinRT(2), Metadata RVA(4), Metadata size(4), ...
    md_rva = struct.unpack_from("<I", data, cli_off+8)[0]
    md_off = rva2off(md_rva)
    # Metadata root: signature 0x424A5342
    sig = struct.unpack_from("<I", data, md_off)[0]
    if sig != 0x424A5342:
        raise ValueError(f"bad md sig {sig:#x}")
    r = R(data, md_off + 12)
    ver_len = r.u32()
    version = r.take(ver_len).rstrip(b"\0").decode("utf-8", "replace")
    # pad to 4
    r.o = (r.o + 3) & ~3
    r.u16()  # flags
    n_streams = r.u16()
    streams = {}
    for _ in range(n_streams):
        off = r.u32(); sz = r.u32()
        name = b""
        while True:
            c = r.u8()
            if c == 0: break
            name += bytes([c])
        # align to 4
        r.o = (r.o + 3) & ~3
        streams[name.decode()] = (md_off + off, sz)
    return {
        "managed": True,
        "version": version,
        "streams": list(streams.keys()),
        "has_tables": "#~" in streams or "#-" in streams,
        "has_strings": "#Strings" in streams,
        "has_blob": "#Blob" in streams,
        "has_guid": "#GUID" in streams,
        "has_us": "#US" in streams,
    }

def decode_method_sig(blob):
    """Minimal ECMA-335 method signature stringifier."""
    if not blob: return "<empty>"
    r = R(blob)
    cc = r.u8()
    parts = [f"cc=0x{cc:02x}"]
    if cc & 0x10:
        parts.append(f"gen={r.u8()}")
    pcount = r.u8()
    parts.append(f"params={pcount}")
    return " ".join(parts)

def main():
    out = {"crate": "rustre-dotnet-metadata", "saved": True}
    # smoke: try a known assembly if present
    candidates = [
        r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorlib.dll",
    ]
    for p in candidates:
        if os.path.exists(p):
            try:
                with open(p, "rb") as f: data = f.read()
                info = parse_metadata(data)
                out["sample"] = {"path": p, **{k: info[k] for k in info if k != "streams"}}
                break
            except Exception as e:
                out["error"] = str(e)
    # signature smoke
    out["sig_demo"] = decode_method_sig(bytes([0x20, 0x01, 0x02, 0x01, 0x08]))
    print(json.dumps(out))

if __name__ == "__main__":
    main()
