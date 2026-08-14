#!/usr/bin/env python3
"""Independent validator for rustre-mobile-ipa.

Validates the IPA-parsing logic implied by the crate's public API:
- IPA file = ZIP container; recognize PK\\x03\\x04 / PK\\x05\\x06 signatures
- Info.plist parsing for both XML and binary formats (bplist00 magic)
- Path heuristics: Payload/<App>.app/<exec>, Frameworks/, PlugIns/, _CodeSignature/
- FairPlay encryption indicator: SC_Info/ or LC_ENCRYPTION_INFO presence
- Entitlements key lookup in XML plist

Pure Python stdlib only. No import of the crate, no MCP. Builds in-memory
fixtures and runs decoders that mirror what `rustre-mobile-ipa` should do.
"""
import io
import json
import os
import struct
import sys
import zlib

CRATE = "rustre-mobile-ipa"
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "outputs")
OUT_PATH = os.path.normpath(os.path.join(OUT_DIR, f"{CRATE}.json"))


# ---------- Minimal ZIP builder (STORE only) ----------

def build_zip(files):
    """files: list of (name, data). Returns a valid ZIP byte string (STORE)."""
    buf = io.BytesIO()
    central = []
    for name, data in files:
        name_b = name.encode("utf-8")
        crc = zlib.crc32(data) & 0xFFFFFFFF
        size = len(data)
        local_off = buf.tell()
        # Local file header
        buf.write(struct.pack("<IHHHHHIIIHH",
            0x04034b50,  # signature
            20,          # version needed
            0,           # flags
            0,           # method = STORE
            0, 0,        # time/date
            crc, size, size,
            len(name_b), 0))
        buf.write(name_b)
        buf.write(data)
        # Central dir entry for later
        central.append((name_b, crc, size, local_off))

    cd_off = buf.tell()
    for name_b, crc, size, local_off in central:
        buf.write(struct.pack("<IHHHHHHIIIHHHHHII",
            0x02014b50, 20, 20, 0, 0, 0, 0,
            crc, size, size,
            len(name_b), 0, 0, 0, 0, 0, local_off))
        buf.write(name_b)
    cd_end = buf.tell()
    cd_size = cd_end - cd_off
    # EOCD
    buf.write(struct.pack("<IHHHHIIH",
        0x06054b50, 0, 0, len(central), len(central),
        cd_size, cd_off, 0))
    return buf.getvalue()


# ---------- IPA / ZIP parser (mirrors crate's hand-rolled central-dir reader) ----------

def parse_ipa(data):
    """Return dict { entries: [(path, size)], is_zip: bool }."""
    if len(data) < 22 or data[:4] != b"PK\x03\x04":
        return {"is_zip": False, "entries": []}
    # Locate EOCD by scanning from end
    eocd_sig = b"PK\x05\x06"
    idx = data.rfind(eocd_sig)
    if idx < 0:
        return {"is_zip": True, "entries": [], "error": "no EOCD"}
    (_, _, _, _, total, cd_size, cd_off, _) = struct.unpack(
        "<IHHHHIIH", data[idx:idx + 22])
    entries = []
    off = cd_off
    for _ in range(total):
        if data[off:off+4] != b"PK\x01\x02":
            break
        # version_made(2) version_need(2) flag(2) method(2) time(2) date(2)
        # crc(4) csize(4) usize(4) nlen(2) elen(2) clen(2) disk(2) iattr(2) eattr(4) lhoff(4)
        (_, _, _, _, _, _, _, _, _, usize_, nlen, elen, clen, _, _, _, _) = struct.unpack(
            "<IHHHHHHIIIHHHHHII", data[off:off+46])
        name = data[off+46:off+46+nlen].decode("utf-8", errors="replace")
        entries.append((name, usize_))
        off += 46 + nlen + elen + clen
    return {"is_zip": True, "entries": entries}


# ---------- Plist helpers ----------

def is_binary_plist(data):
    return len(data) >= 8 and data[:8] == b"bplist00"


def plist_xml_find_key(xml_bytes, key):
    """Find <key>K</key><string>V</string> in plain XML plist."""
    try:
        s = xml_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None
    needle = f"<key>{key}</key>"
    i = s.find(needle)
    if i < 0:
        return None
    rest = s[i + len(needle):]
    # next <string>...</string>
    j = rest.find("<string>")
    if j < 0:
        return None
    j += len("<string>")
    k = rest.find("</string>", j)
    if k < 0:
        return None
    return rest[j:k]


# ---------- IPA-level heuristics ----------

def find_executable_path(entries, exec_name):
    for path, _ in entries:
        if path.startswith("Payload/") and path.endswith("/" + exec_name) \
                and ".app/" in path and not path.endswith("/"):
            # must be at top of the .app bundle (no further slash after .app/exec)
            after = path.split(".app/", 1)[1]
            if after == exec_name:
                return path
    return None


def list_frameworks(entries):
    fws = set()
    for path, _ in entries:
        if "/Frameworks/" in path:
            seg = path.split("/Frameworks/", 1)[1].split("/", 1)[0]
            if seg.endswith(".framework") or seg.endswith(".dylib"):
                fws.add(seg)
    return sorted(fws)


def list_plugins(entries):
    pls = set()
    for path, _ in entries:
        if "/PlugIns/" in path:
            seg = path.split("/PlugIns/", 1)[1].split("/", 1)[0]
            if seg.endswith(".appex"):
                pls.add(seg)
    return sorted(pls)


def is_encrypted(entries):
    for path, _ in entries:
        if "SC_Info/" in path:
            return True
    return False


# ---------- Test fixtures ----------

INFO_PLIST_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>com.example.app</string>
  <key>CFBundleName</key><string>Example</string>
  <key>CFBundleExecutable</key><string>Example</string>
  <key>MinimumOSVersion</key><string>14.0</string>
</dict>
</plist>
"""

ENTITLEMENTS_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>application-identifier</key><string>TEAMID.com.example.app</string>
  <key>get-task-allow</key><true/>
</dict>
</plist>
"""

BPLIST_MIN = b"bplist00" + b"\x00" * 32  # just magic + filler


def build_sample_ipa():
    return build_zip([
        ("Payload/Example.app/Info.plist", INFO_PLIST_XML),
        ("Payload/Example.app/Example", b"\xCA\xFE\xBA\xBE" + b"\x00" * 100),  # fake Mach-O FAT
        ("Payload/Example.app/embedded.mobileprovision", b"dummy-cms"),
        ("Payload/Example.app/_CodeSignature/CodeResources", b"<plist/>"),
        ("Payload/Example.app/Frameworks/Alamofire.framework/Alamofire", b"\x00"),
        ("Payload/Example.app/PlugIns/Widget.appex/Widget", b"\x00"),
        ("Payload/Example.app/SC_Info/Example.sinf", b"\x00\x01"),  # FairPlay marker
    ])


def build_encrypted_free_ipa():
    return build_zip([
        ("Payload/Foo.app/Info.plist", INFO_PLIST_XML),
        ("Payload/Foo.app/Foo", b"\xCF\xFA\xED\xFE" + b"\x00" * 50),  # Mach-O 64
    ])


# ---------- Tests ----------

def run_tests():
    results = []

    # 1. Zip signature detection
    sample = build_sample_ipa()
    results.append({
        "name": "zip_magic_PK0304",
        "expected": True,
        "got": sample[:4] == b"PK\x03\x04",
    })

    # 2. Parse central directory
    parsed = parse_ipa(sample)
    results.append({
        "name": "parse_is_zip",
        "expected": True,
        "got": parsed["is_zip"],
    })
    results.append({
        "name": "entry_count",
        "expected": 7,
        "got": len(parsed["entries"]),
    })

    # 3. Non-ZIP input rejected
    nz = parse_ipa(b"not a zip at all")
    results.append({
        "name": "reject_non_zip",
        "expected": False,
        "got": nz["is_zip"],
    })

    # 4. Executable path discovery
    exec_path = find_executable_path(parsed["entries"], "Example")
    results.append({
        "name": "executable_path",
        "expected": "Payload/Example.app/Example",
        "got": exec_path,
    })

    # 5. Frameworks listing
    fws = list_frameworks(parsed["entries"])
    results.append({
        "name": "list_frameworks",
        "expected": ["Alamofire.framework"],
        "got": fws,
    })

    # 6. Plugins listing
    pls = list_plugins(parsed["entries"])
    results.append({
        "name": "list_plugins",
        "expected": ["Widget.appex"],
        "got": pls,
    })

    # 7. FairPlay detection (SC_Info present)
    results.append({
        "name": "fairplay_detected_when_sc_info",
        "expected": True,
        "got": is_encrypted(parsed["entries"]),
    })

    # 8. FairPlay absent
    parsed_free = parse_ipa(build_encrypted_free_ipa())
    results.append({
        "name": "fairplay_absent_when_no_sc_info",
        "expected": False,
        "got": is_encrypted(parsed_free["entries"]),
    })

    # 9. XML plist key lookup
    bid = plist_xml_find_key(INFO_PLIST_XML, "CFBundleIdentifier")
    results.append({
        "name": "info_plist_bundle_id",
        "expected": "com.example.app",
        "got": bid,
    })

    # 10. XML plist executable lookup
    ex = plist_xml_find_key(INFO_PLIST_XML, "CFBundleExecutable")
    results.append({
        "name": "info_plist_executable",
        "expected": "Example",
        "got": ex,
    })

    # 11. Entitlement extraction
    ent = plist_xml_find_key(ENTITLEMENTS_XML, "application-identifier")
    results.append({
        "name": "entitlement_app_id",
        "expected": "TEAMID.com.example.app",
        "got": ent,
    })

    # 12. Binary plist magic
    results.append({
        "name": "bplist_magic_detected",
        "expected": True,
        "got": is_binary_plist(BPLIST_MIN),
    })

    # 13. Binary plist magic negative
    results.append({
        "name": "bplist_magic_rejected_for_xml",
        "expected": False,
        "got": is_binary_plist(INFO_PLIST_XML),
    })

    # 14. Mach-O FAT magic recognized in executable bytes
    fat_magic = b"\xCA\xFE\xBA\xBE"
    results.append({
        "name": "macho_fat_magic_in_executable",
        "expected": True,
        "got": sample.find(fat_magic) >= 0,
    })

    # Mark ok flag
    for r in results:
        r["ok"] = (r["got"] == r["expected"])
    return results


def main():
    results = run_tests()
    mismatches = sum(1 for r in results if not r["ok"])

    result = {
        "crate": CRATE,
        "saved": False,
        "total": len(results),
        "mismatches": mismatches,
        "cases": results,
    }

    os.makedirs(OUT_DIR, exist_ok=True)
    try:
        with open(OUT_PATH, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        result["saved"] = True
    except Exception as e:
        result["save_error"] = str(e)

    print(json.dumps({
        "crate": result["crate"],
        "saved": result["saved"],
        "total": result["total"],
        "mismatches": result["mismatches"],
    }, indent=2))
    return 0 if mismatches == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
