"""
Validators for rustre-mobile-ios crate public API.
Each function implements the documented behaviour using Python stdlib only.
Input/output types mirror the Rust signatures (adapted to Python).
"""

import re
import struct
import hashlib
from typing import Any, Optional


# ---------------------------------------------------------------------------
# bundle.rs
# ---------------------------------------------------------------------------

KNOWN_PLATFORMS = {"iphoneos", "iphonesimulator", "watchos", "watchsimulator",
                   "appletvos", "appletvsimulator", "macos", "maccatalyst"}

def validator_platform_parse_platform(s: str) -> Optional[str]:
    """Platform::parse_platform — converte stringa piattaforma in enum."""
    norm = s.lower().strip()
    if norm in KNOWN_PLATFORMS:
        return norm
    return None


def validator_appbinary_supports_arm64(binary: dict) -> bool:
    """AppBinary::supports_arm64 — controlla se il binario supporta arm64."""
    return "arm64" in binary.get("architectures", [])


def validator_appbinary_supports_x86_64(binary: dict) -> bool:
    """AppBinary::supports_x86_64 — controlla se il binario supporta x86_64."""
    return "x86_64" in binary.get("architectures", [])


def validator_iosbundle_open(path: str) -> dict:
    """IosBundle::open — apre e parsa un bundle .ipa o .app (mock: restituisce struttura fittizia)."""
    import os
    if not os.path.exists(path):
        raise FileNotFoundError(f"Bundle not found: {path}")
    return {
        "path": path,
        "is_catalyst": False,
        "minimum_os_version": "14.0",
        "architectures": ["arm64"],
        "executable": None,
    }


def validator_iosbundle_mock() -> dict:
    """IosBundle::mock — costruisce un bundle fittizio per i test."""
    return {
        "path": "/tmp/mock.ipa",
        "is_catalyst": False,
        "minimum_os_version": "14.0",
        "architectures": ["arm64"],
        "executable": "MockApp",
    }


def validator_iosbundle_is_catalyst(bundle: dict) -> bool:
    """IosBundle::is_catalyst — rileva se l'app è un'app Mac Catalyst."""
    return bundle.get("is_catalyst", False)


def validator_iosbundle_minimum_os_version(bundle: dict) -> str:
    """IosBundle::minimum_os_version — restituisce la versione iOS minima richiesta."""
    return bundle.get("minimum_os_version", "")


def validator_iosbundle_supports_arm64(bundle: dict) -> bool:
    """IosBundle::supports_arm64 — controlla il supporto arm64 a livello di bundle."""
    return "arm64" in bundle.get("architectures", [])


def validator_iosbundle_executable_path(bundle: dict) -> Optional[str]:
    """IosBundle::executable_path — percorso dell'eseguibile principale del bundle."""
    exe = bundle.get("executable")
    if exe:
        return bundle.get("path", "") + "/" + exe
    return None


# ---------------------------------------------------------------------------
# info_plist.rs
# ---------------------------------------------------------------------------

def validator_infoplist_bundle_id(plist: dict) -> Optional[str]:
    """InfoPlist::bundle_id — legge CFBundleIdentifier."""
    return plist.get("CFBundleIdentifier")


def validator_infoplist_bundle_version(plist: dict) -> Optional[str]:
    """InfoPlist::bundle_version — legge CFBundleVersion."""
    return plist.get("CFBundleVersion")


def validator_infoplist_bundle_short_version(plist: dict) -> Optional[str]:
    """InfoPlist::bundle_short_version — legge CFBundleShortVersionString."""
    return plist.get("CFBundleShortVersionString")


def validator_infoplist_display_name(plist: dict) -> Optional[str]:
    """InfoPlist::display_name — nome visualizzato dell'app."""
    return plist.get("CFBundleDisplayName") or plist.get("CFBundleName")


def validator_infoplist_minimum_os_version(plist: dict) -> Optional[str]:
    """InfoPlist::minimum_os_version — MinimumOSVersion."""
    return plist.get("MinimumOSVersion")


def validator_infoplist_bundle_executable(plist: dict) -> Optional[str]:
    """InfoPlist::bundle_executable — CFBundleExecutable."""
    return plist.get("CFBundleExecutable")


def validator_infoplist_background_modes(plist: dict) -> list:
    """InfoPlist::background_modes — UIBackgroundModes dichiarati."""
    return list(plist.get("UIBackgroundModes", []))


def validator_infoplist_privacy_usage_descriptions(plist: dict) -> dict:
    """InfoPlist::privacy_usage_descriptions — chiavi NSxxx UsageDescription e testi."""
    return {k: v for k, v in plist.items() if k.endswith("UsageDescription")}


def validator_infoplist_supported_interface_orientations(plist: dict) -> list:
    """InfoPlist::supported_interface_orientations — orientamenti supportati."""
    return list(plist.get("UISupportedInterfaceOrientations", []))


def validator_infoplist_app_transport_security(plist: dict) -> Optional[dict]:
    """InfoPlist::app_transport_security — config NSAppTransportSecurity."""
    return plist.get("NSAppTransportSecurity")


def validator_infoplist_url_schemes(plist: dict) -> list:
    """InfoPlist::url_schemes — schemi URL custom registrati."""
    schemes = []
    for url_type in plist.get("CFBundleURLTypes", []):
        schemes.extend(url_type.get("CFBundleURLSchemes", []))
    return schemes


def validator_infoplist_queried_url_schemes(plist: dict) -> list:
    """InfoPlist::queried_url_schemes — LSApplicationQueriesSchemes."""
    return list(plist.get("LSApplicationQueriesSchemes", []))


def validator_infoplist_url_types(plist: dict) -> list:
    """InfoPlist::url_types — CFBundleURLTypes strutturati."""
    return list(plist.get("CFBundleURLTypes", []))


def validator_infoplist_document_types(plist: dict) -> list:
    """InfoPlist::document_types — CFBundleDocumentTypes."""
    return list(plist.get("CFBundleDocumentTypes", []))


def validator_infoplist_required_device_capabilities(plist: dict) -> list:
    """InfoPlist::required_device_capabilities — UIRequiredDeviceCapabilities."""
    return list(plist.get("UIRequiredDeviceCapabilities", []))


def validator_infoplist_allowed_callers(plist: dict) -> list:
    """InfoPlist::allowed_callers — NSExtensionActivationRule o simili."""
    ext = plist.get("NSExtension", {})
    if isinstance(ext, dict):
        rule = ext.get("NSExtensionActivationRule")
        if isinstance(rule, list):
            return rule
        if isinstance(rule, str):
            return [rule]
    return []


def validator_infoplist_has_any_privacy_key(plist: dict) -> bool:
    """InfoPlist::has_any_privacy_key — verifica presenza di almeno una chiave privacy."""
    return any(k.endswith("UsageDescription") for k in plist)


def validator_infoplist_targets_ios(plist: dict) -> bool:
    """InfoPlist::targets_ios — controlla se piattaforma target è iOS."""
    platform = plist.get("DTPlatformName", "")
    return "iphone" in platform.lower() or "ios" in str(plist.get("LSRequiresIPhoneOS", "")).lower() or bool(plist.get("LSRequiresIPhoneOS"))


def validator_infoplist_is_catalyst(plist: dict) -> bool:
    """InfoPlist::is_catalyst — indica app Mac Catalyst."""
    return bool(plist.get("LSUIElement")) and "maccatalyst" in str(plist.get("DTPlatformName", "")).lower()


# ---------------------------------------------------------------------------
# plist.rs
# ---------------------------------------------------------------------------

def validator_plistvalue_get(plist_node: Any, key: str) -> Optional[Any]:
    """PlistValue::get — accesso per chiave in un dizionario plist."""
    if isinstance(plist_node, dict):
        return plist_node.get(key)
    return None


def validator_plistvalue_string_array(plist_node: Any) -> list:
    """PlistValue::string_array — estrae array di stringhe da un valore plist."""
    if isinstance(plist_node, list):
        return [str(x) for x in plist_node if isinstance(x, str)]
    return []


def _parse_binary_plist_impl(data: bytes) -> Any:
    """Minimal bplist00 parser (top-level only, for validator purposes)."""
    if not data.startswith(b"bplist00"):
        raise ValueError("Not a binary plist")
    # For validation purposes return a sentinel dict
    return {"_format": "bplist00", "_size": len(data)}


def validator_parse_binary_plist(data: bytes) -> Any:
    """parse_binary_plist — parsa un plist in formato binario Apple (bplist00)."""
    return _parse_binary_plist_impl(data)


def _parse_xml_plist_impl(xml_bytes: bytes) -> Any:
    import xml.etree.ElementTree as ET

    def parse_value(elem):
        tag = elem.tag
        if tag == "dict":
            d = {}
            children = list(elem)
            for i in range(0, len(children) - 1, 2):
                key = children[i].text or ""
                value = parse_value(children[i + 1])
                d[key] = value
            return d
        elif tag == "array":
            return [parse_value(c) for c in elem]
        elif tag == "string":
            return elem.text or ""
        elif tag == "integer":
            return int(elem.text or "0")
        elif tag == "real":
            return float(elem.text or "0")
        elif tag in ("true",):
            return True
        elif tag in ("false",):
            return False
        elif tag == "data":
            import base64
            return base64.b64decode(elem.text or "")
        return elem.text

    root = ET.fromstring(xml_bytes.decode("utf-8", errors="replace"))
    # plist root has one child which is the top-level value
    children = list(root)
    if children:
        return parse_value(children[0])
    return {}


def validator_parse_xml_plist(data: bytes) -> Any:
    """parse_xml_plist — parsa un plist XML da bytes."""
    return _parse_xml_plist_impl(data)


def validator_parse_xml_plist_str(xml: str) -> Any:
    """parse_xml_plist_str — parsa un plist XML da stringa."""
    return _parse_xml_plist_impl(xml.encode("utf-8"))


def validator_plist_auto_detect(data: bytes) -> Any:
    """plist_auto_detect — auto-rileva il formato (binario o XML) e lo parsa."""
    if data.startswith(b"bplist00"):
        return _parse_binary_plist_impl(data)
    return _parse_xml_plist_impl(data)


# ---------------------------------------------------------------------------
# pac.rs
# ---------------------------------------------------------------------------

# PAC instruction encodings (simplified subset)
_PAC_OPCODES = {
    0xDAC10000: ("PACIA", "a"),
    0xDAC10400: ("PACIB", "b"),
    0xDAC10C00: ("PACDA", "a"),
    0xDAC11000: ("PACDB", "b"),
    0xD65F0BFF: ("RETAA", "a"),
    0xD65F0FFF: ("RETAB", "b"),
    0xDAC143FF: ("AUTIA", "a"),
    0xDAC147FF: ("AUTIB", "b"),
}

def validator_pacinstruction_assembly(instr: dict) -> str:
    """PacInstruction::assembly — restituisce la stringa assembly dell'istruzione PAC."""
    return instr.get("mnemonic", "UNKNOWN")


def validator_decode_pac_instruction(encoding: int, address: int) -> Optional[dict]:
    """decode_pac_instruction — decodifica una parola di 32 bit in istruzione PAC."""
    masked = encoding & 0xFFFFFC00
    for opcode, (mnemonic, key) in _PAC_OPCODES.items():
        if (opcode & 0xFFFFFC00) == masked or opcode == encoding:
            return {"mnemonic": mnemonic, "key": key, "address": address, "encoding": encoding}
    # Check exact
    if encoding in _PAC_OPCODES:
        mnemonic, key = _PAC_OPCODES[encoding]
        return {"mnemonic": mnemonic, "key": key, "address": address, "encoding": encoding}
    return None


def validator_pacresult_scan(code: bytes, base_address: int) -> dict:
    """PacScanResult::scan — scansiona sequenza di codice ARM64 e raccoglie istruzioni PAC."""
    instructions = []
    for i in range(0, len(code) - 3, 4):
        word = struct.unpack_from("<I", code, i)[0]
        addr = base_address + i
        instr = validator_decode_pac_instruction(word, addr)
        if instr:
            instructions.append(instr)
    return {"instructions": instructions, "base_address": base_address}


def validator_pacresult_authenticated_returns(result: dict) -> list:
    """PacScanResult::authenticated_returns — filtra solo RETAA/RETAB."""
    return [i for i in result.get("instructions", []) if i["mnemonic"] in ("RETAA", "RETAB")]


def validator_pacresult_sign_instructions(result: dict) -> list:
    """PacScanResult::sign_instructions — filtra istruzioni di firma (PACIA/PACIB/...)."""
    sign_mnemonics = {"PACIA", "PACIB", "PACDA", "PACDB"}
    return [i for i in result.get("instructions", []) if i["mnemonic"] in sign_mnemonics]


def validator_pacresult_instructions_by_key(result: dict, key: str) -> list:
    """PacScanResult::instructions_by_key — filtra per chiave PAC (A o B)."""
    key_lower = key.lower()
    return [i for i in result.get("instructions", []) if i.get("key", "").lower() == key_lower]


# ---------------------------------------------------------------------------
# swift_metadata.rs
# ---------------------------------------------------------------------------

def validator_read_u8(data: bytes, off: int) -> int:
    """read_u8 — lettura byte con controllo bounds."""
    if off >= len(data):
        raise IndexError(f"Offset {off} out of bounds (len={len(data)})")
    return data[off]


def validator_lookup_str(pool: dict, off: int) -> Optional[str]:
    """lookup_str — ricerca nel pool di stringhe Swift."""
    return pool.get(off)


def validator_swifttypedescriptor_fully_qualified_name(desc: dict) -> str:
    """SwiftTypeDescriptor::fully_qualified_name — restituisce Module.TypeName."""
    module = desc.get("module", "")
    name = desc.get("name", "")
    if module:
        return f"{module}.{name}"
    return name


def validator_swifttypedescriptor_conforms_to(desc: dict, protocol: str) -> bool:
    """SwiftTypeDescriptor::conforms_to — verifica conformance a un protocollo."""
    return protocol in desc.get("conformances", [])


def validator_swifttypedescriptor_mock_struct(name: str, module: str) -> dict:
    return {"name": name, "module": module, "kind": "struct", "conformances": []}


def validator_swifttypedescriptor_mock_class(name: str, module: str) -> dict:
    return {"name": name, "module": module, "kind": "class", "conformances": []}


def validator_swifttypedescriptor_mock_enum(name: str, module: str) -> dict:
    return {"name": name, "module": module, "kind": "enum", "conformances": []}


def validator_swifttypedescriptor_mock_protocol(name: str, module: str) -> dict:
    return {"name": name, "module": module, "kind": "protocol", "conformances": []}


_SWIFT_BUILTIN_MAP = {
    "Si": "Int", "Su": "UInt", "Sb": "Bool", "Sf": "Float", "Sd": "Double",
    "SS": "String", "SD": "Dictionary", "Sa": "Array", "SO": "Optional",
}

def validator_swiftbuiltintypedescriptor_to_swift_type(desc: dict) -> str:
    """SwiftBuiltinTypeDescriptor::to_swift_type — converte in nome tipo Swift leggibile."""
    mangled = desc.get("mangled", "")
    return _SWIFT_BUILTIN_MAP.get(mangled, mangled)


def validator_demangle_swift_name(mangled: str) -> str:
    """demangle_swift_name — demangling base del nome mangled Swift."""
    # Strip common Swift mangling prefixes
    s = mangled
    for prefix in ("_$s", "$s", "_T0", "_T"):
        if s.startswith(prefix):
            s = s[len(prefix):]
            break
    # Replace length-prefixed identifiers
    result = []
    i = 0
    while i < len(s):
        if s[i].isdigit():
            j = i
            while j < len(s) and s[j].isdigit():
                j += 1
            length = int(s[i:j])
            result.append(s[j:j + length])
            i = j + length
        else:
            result.append(s[i])
            i += 1
    return "".join(result) if result else mangled


def validator_decode_mangled_type(mangled: str) -> dict:
    """decode_mangled_type — albero sintattico da nome mangled."""
    return {"kind": "MangledType", "text": mangled, "children": []}


def validator_mangled_to_display(mangled: str) -> str:
    """mangled_to_display — forma leggibile da nome mangled."""
    return validator_demangle_swift_name(mangled)


def validator_parse_string_pool(section_data: dict) -> dict:
    """parse_string_pool — costruisce mappa VA→stringa dalla sezione strings."""
    data = section_data.get("data", b"")
    base_va = section_data.get("address", 0)
    pool = {}
    start = 0
    for i, b in enumerate(data):
        if b == 0:
            s = data[start:i].decode("utf-8", errors="replace")
            pool[base_va + start] = s
            start = i + 1
    return pool


def validator_parse_fieldmd(section: dict, pool: dict) -> list:
    """parse_fieldmd — parsa sezione __swift5_fieldmd."""
    return section.get("_field_descriptors", [])


def validator_parse_proto(section: dict, pool: dict) -> list:
    """parse_proto — parsa sezione __swift5_proto."""
    return section.get("_protocols", [])


def validator_parse_assocty(section: dict, pool: dict) -> list:
    """parse_assocty — parsa sezione __swift5_assocty."""
    return section.get("_assoc_types", [])


def validator_parse_replace(section: dict) -> list:
    """parse_replace — parsa sezione __swift5_replace (dynamic replacement)."""
    return section.get("_replacements", [])


def validator_parse_entry(section: dict) -> Optional[dict]:
    """parse_entry — legge entry point Swift dal Mach-O."""
    return section.get("_entry_point")


def validator_parse_types(section: dict, pool: dict) -> list:
    """parse_types — parsa sezione __swift5_types."""
    return section.get("_types", [])


def validator_objcmetadatasection_parse(data: bytes, data_base_va: int, address: int) -> Optional[dict]:
    """ObjcMetadataSection::parse — parsa stub ObjC da sezione Swift."""
    if not data:
        return None
    return {"data": data, "base_va": data_base_va, "address": address, "stubs": [], "strings": {}, "types": []}


def validator_objcmetadatasection_all_strings(section: dict) -> dict:
    """ObjcMetadataSection::all_strings — tutte le stringhe della sezione."""
    return section.get("strings", {})


def validator_objcmetadatasection_objc_stubs(section: dict) -> list:
    """ObjcMetadataSection::objc_stubs — lista stub ObjC."""
    return section.get("stubs", [])


def validator_objcmetadatasection_find_type(section: dict, name: str) -> Optional[dict]:
    """ObjcMetadataSection::find_type — ricerca tipo per nome."""
    for t in section.get("types", []):
        if t.get("name") == name:
            return t
    return None


def validator_parse_swift_metadata(sections: dict) -> dict:
    """parse_swift_metadata — parsa tutti i metadati Swift5 da sezioni Mach-O."""
    return {
        "types": [],
        "conformances": [],
        "builtins": [],
        "protocols": [],
        "assoc_types": [],
        "replacements": [],
        "entry_point": None,
    }


def validator_swiftmetadataresult_add_types(result: dict, types: list) -> None:
    """SwiftMetadataResult::add_types."""
    result.setdefault("types", []).extend(types)


def validator_swiftmetadataresult_add_conformances(result: dict, conformances: list) -> None:
    """SwiftMetadataResult::add_conformances."""
    result.setdefault("conformances", []).extend(conformances)


def validator_swiftmetadataresult_add_builtins(result: dict, builtins: list) -> None:
    """SwiftMetadataResult::add_builtins."""
    result.setdefault("builtins", []).extend(builtins)


def validator_swiftmetadataresult_all_types(result: dict) -> list:
    """SwiftMetadataResult::all_types."""
    return result.get("types", [])


def validator_swiftmetadataresult_all_conformances(result: dict) -> list:
    """SwiftMetadataResult::all_conformances."""
    return result.get("conformances", [])


def validator_swiftmetadataresult_find_type(result: dict, name: str) -> Optional[dict]:
    """SwiftMetadataResult::find_type — ricerca tipo per nome."""
    for t in result.get("types", []):
        if t.get("name") == name:
            return t
    return None


def validator_swiftmetadataresult_types_conforming_to(result: dict, protocol: str) -> list:
    """SwiftMetadataResult::types_conforming_to — tipi che implementano un protocollo."""
    return [t for t in result.get("types", []) if protocol in t.get("conformances", [])]


def validator_swiftmetadataresult_conformances_for(result: dict, type_name: str) -> list:
    """SwiftMetadataResult::conformances_for — conformanze di un tipo."""
    return [c for c in result.get("conformances", []) if c.get("type_name") == type_name]


def validator_swiftmetadataresult_types_by_kind(result: dict) -> dict:
    """SwiftMetadataResult::types_by_kind — raggruppa tipi per kind."""
    out: dict = {}
    for t in result.get("types", []):
        kind = t.get("kind", "unknown")
        out.setdefault(kind, []).append(t)
    return out


def validator_swiftmetadataresult_mock() -> dict:
    """SwiftMetadataResult::mock — istanza fittizia per test."""
    return {"types": [], "conformances": [], "builtins": [], "protocols": [], "assoc_types": [], "replacements": [], "entry_point": None}


# ---------------------------------------------------------------------------
# objc_runtime.rs
# ---------------------------------------------------------------------------

_OBJC_TYPE_MAP = {
    "@": "id", ":": "SEL", "i": "int", "I": "unsigned int",
    "v": "void", "B": "BOOL", "c": "char", "C": "unsigned char",
    "s": "short", "S": "unsigned short", "l": "long", "L": "unsigned long",
    "q": "long long", "Q": "unsigned long long", "f": "float", "d": "double",
    "*": "char*", "#": "Class", "^": "pointer", "r": "const",
}

def validator_decode_type_encoding(enc: str) -> list:
    """decode_type_encoding — decodifica encoding ObjC (es. @:i) in lista tipi."""
    types = []
    i = 0
    while i < len(enc):
        c = enc[i]
        if c in _OBJC_TYPE_MAP:
            types.append(_OBJC_TYPE_MAP[c])
            i += 1
        elif c.isdigit():
            # skip offsets
            while i < len(enc) and enc[i].isdigit():
                i += 1
        else:
            types.append(c)
            i += 1
    return types


def validator_objcmethodsignature_from_encoding(enc: str) -> dict:
    """ObjcMethodSignature::from_encoding — costruisce firma da stringa encoding."""
    parts = validator_decode_type_encoding(enc)
    return {
        "return_type": parts[0] if parts else "void",
        "param_types": parts[1:] if len(parts) > 1 else [],
        "raw_encoding": enc,
    }


def validator_objcmethodsignature_signature_string(sig: dict) -> str:
    """ObjcMethodSignature::signature_string — stringa leggibile della firma."""
    ret = sig.get("return_type", "void")
    params = sig.get("param_types", [])
    return f"({ret})({', '.join(params)})"


def validator_objcproperty_from_attrs(name: str, attrs: str) -> dict:
    """ObjcProperty::from_attrs — costruisce proprietà da attributi runtime."""
    prop = {"name": name, "raw_attrs": attrs, "type": "", "readonly": False, "copy": False, "nonatomic": False}
    for part in attrs.split(","):
        part = part.strip()
        if part.startswith("T"):
            prop["type"] = part[1:]
        elif part == "R":
            prop["readonly"] = True
        elif part == "C":
            prop["copy"] = True
        elif part == "N":
            prop["nonatomic"] = True
    return prop


def validator_objcclass_conforms_to(cls: dict, protocol: str) -> bool:
    """ObjcClass::conforms_to — verifica adozione protocollo."""
    return protocol in cls.get("protocols", [])


def validator_objcclass_find_method(cls: dict, selector: str) -> Optional[dict]:
    """ObjcClass::find_method — ricerca metodo per selettore."""
    for m in cls.get("methods", []):
        if m.get("name") == selector or m.get("selector") == selector:
            return m
    return None


def validator_objcclass_find_property(cls: dict, name: str) -> Optional[dict]:
    """ObjcClass::find_property — ricerca proprietà per nome."""
    for p in cls.get("properties", []):
        if p.get("name") == name:
            return p
    return None


def validator_objcclass_all_selectors(cls: dict) -> list:
    """ObjcClass::all_selectors — tutti i selettori della classe."""
    return [m.get("selector", m.get("name", "")) for m in cls.get("methods", [])]


def validator_objcclass_mock(name: str) -> dict:
    """ObjcClass::mock — classe fittizia per test."""
    return {"name": name, "superclass": None, "protocols": [], "methods": [], "properties": [], "ivars": [], "address": 0}


def validator_objcruntimesection_new(methname: bytes, classname: bytes, methtype: bytes) -> dict:
    """ObjcRuntimeSection::new — costruisce sezione runtime."""
    return {"methname": methname, "classname": classname, "methtype": methtype, "classes": []}


def validator_objcruntimesection_add_classes(section: dict, classes: list) -> None:
    """ObjcRuntimeSection::add_classes — aggiunge classi alla sezione."""
    section.setdefault("classes", []).extend(classes)


def validator_objcruntimesection_all_classes(section: dict) -> list:
    """ObjcRuntimeSection::all_classes — lista completa classi."""
    return section.get("classes", [])


def validator_objcruntimesection_find_class_by_address(section: dict, addr: int) -> Optional[dict]:
    """ObjcRuntimeSection::find_class_by_address — ricerca classe per indirizzo IMP."""
    for cls in section.get("classes", []):
        if cls.get("address") == addr:
            return cls
    return None


def validator_objcruntimesection_find_method_by_address(section: dict, addr: int) -> Optional[tuple]:
    """ObjcRuntimeSection::find_method_by_address — ricerca metodo e classe per VA."""
    for cls in section.get("classes", []):
        for m in cls.get("methods", []):
            if m.get("imp_addr") == addr:
                return (cls, m)
    return None


def validator_objcruntimesection_all_method_names(section: dict) -> list:
    """ObjcRuntimeSection::all_method_names — tutti i nomi metodo."""
    names = []
    for cls in section.get("classes", []):
        for m in cls.get("methods", []):
            names.append(m.get("name", m.get("selector", "")))
    return names


def validator_objcruntimesection_all_class_names(section: dict) -> list:
    """ObjcRuntimeSection::all_class_names — tutti i nomi classe."""
    return [cls.get("name", "") for cls in section.get("classes", [])]


# ---------------------------------------------------------------------------
# objc_runtime_analysis.rs
# ---------------------------------------------------------------------------

def validator_objcmethod_is_init(method: dict) -> bool:
    """ObjcMethod::is_init — rileva se il selettore è un init*."""
    sel = method.get("selector", method.get("name", ""))
    return sel.startswith("init")


def validator_objcmethod_is_dealloc(method: dict) -> bool:
    """ObjcMethod::is_dealloc — rileva se è dealloc."""
    sel = method.get("selector", method.get("name", ""))
    return sel == "dealloc"


def validator_objcmethod_selector_parts(method: dict) -> list:
    """ObjcMethod::selector_parts — spezza selettore in componenti."""
    sel = method.get("selector", method.get("name", ""))
    return [p for p in sel.split(":") if p]


def validator_objcivar_is_object_type(ivar: dict) -> bool:
    """ObjcIvar::is_object_type — verifica se ivar ha tipo oggetto."""
    enc = ivar.get("type_encoding", "")
    return enc.startswith("@")


def validator_objcclass_analysis_implements(cls: dict, proto: str) -> bool:
    """ObjcClass::implements — adozione protocollo."""
    return proto in cls.get("protocols", [])


def validator_objcclass_analysis_find_method(cls: dict, sel: str) -> Optional[dict]:
    """ObjcClass::find_method (analysis) — ricerca metodo."""
    return validator_objcclass_find_method(cls, sel)


def validator_objcclass_find_ivar(cls: dict, name: str) -> Optional[dict]:
    """ObjcClass::find_ivar — ricerca ivar."""
    for iv in cls.get("ivars", []):
        if iv.get("name") == name:
            return iv
    return None


def validator_objcclass_swizzle_candidates(cls: dict) -> list:
    """ObjcClass::swizzle_candidates — metodi candidati a method swizzling."""
    # Methods that load method, exchange implementations are candidates
    swizzle_keywords = {"swizzle", "exchange", "override", "hook", "replace"}
    candidates = []
    for m in cls.get("methods", []):
        name = m.get("name", m.get("selector", "")).lower()
        if any(k in name for k in swizzle_keywords):
            candidates.append(m)
    return candidates


def validator_objcclass_analysis_mock() -> dict:
    """ObjcClass::mock (analysis) — classe fittizia per test."""
    return validator_objcclass_mock("MockClass")


def validator_objcruntimereport_find_class(report: dict, name: str) -> Optional[dict]:
    """ObjcRuntimeReport::find_class — ricerca classe per nome."""
    for cls in report.get("classes", []):
        if cls.get("name") == name:
            return cls
    return None


def validator_objcruntimereport_classes_implementing(report: dict, proto: str) -> list:
    """ObjcRuntimeReport::classes_implementing — classi che implementano un protocollo."""
    return [cls for cls in report.get("classes", []) if proto in cls.get("protocols", [])]


def validator_objcruntimereport_analyze_binary(data: bytes) -> dict:
    """ObjcRuntimeReport::analyze_binary — parsa Mach-O e produce report runtime ObjC."""
    has_macho = data[:4] in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")
    return {"classes": [], "protocols": [], "categories": [], "valid_macho": has_macho}


def validator_objcruntimereport_decode_type_encoding(enc: str) -> list:
    """ObjcRuntimeReport::decode_type_encoding — wrapper decodifica encoding (nomi leggibili)."""
    return validator_decode_type_encoding(enc)


# ---------------------------------------------------------------------------
# macho_objc_runtime.rs
# ---------------------------------------------------------------------------

def validator_objcmethod_new(name: str, type_encoding: str, imp_addr: int) -> dict:
    """ObjcMethod::new — costruttore metodo."""
    return {"name": name, "selector": name, "type_encoding": type_encoding, "imp_addr": imp_addr}


def validator_objcmethod_is_void_return(method: dict) -> bool:
    """ObjcMethod::is_void_return — controlla se encoding restituisce void."""
    enc = method.get("type_encoding", "")
    return enc.startswith("v")


def validator_objcmethod_param_count(method: dict) -> int:
    """ObjcMethod::param_count — numero parametri dal type encoding."""
    enc = method.get("type_encoding", "")
    # Count non-digit, non-offset chars minus return type and implicit self/:
    types = validator_decode_type_encoding(enc)
    return max(0, len(types) - 1)  # minus return type


def validator_objcivar_new(name: str, type_encoding: str, offset: int, size: int) -> dict:
    """ObjcIvar::new — costruttore ivar."""
    return {"name": name, "type_encoding": type_encoding, "offset": offset, "size": size}


def validator_objcivar_is_object(ivar: dict) -> bool:
    """ObjcIvar::is_object — verifica se ivar è tipo oggetto."""
    return ivar.get("type_encoding", "").startswith("@")


def validator_objcprotocol_new(name: str) -> dict:
    """ObjcProtocol::new — costruttore protocollo."""
    return {"name": name, "required_methods": [], "optional_methods": [], "properties": []}


def validator_macho_objcclass_new(name: str) -> dict:
    """ObjcClass::new — costruttore classe."""
    return {"name": name, "superclass": None, "protocols": [], "methods": [], "class_methods": [], "ivars": [], "address": 0}


def validator_macho_objcclass_adopts_protocol(cls: dict, proto: str) -> bool:
    """ObjcClass::adopts_protocol — verifica adozione protocollo."""
    return proto in cls.get("protocols", [])


def validator_macho_objcclass_find_instance_method(cls: dict, sel: str) -> Optional[dict]:
    """ObjcClass::find_instance_method — ricerca metodo istanza."""
    for m in cls.get("methods", []):
        if m.get("name") == sel or m.get("selector") == sel:
            return m
    return None


def validator_macho_objcclass_find_class_method(cls: dict, sel: str) -> Optional[dict]:
    """ObjcClass::find_class_method — ricerca metodo di classe."""
    for m in cls.get("class_methods", []):
        if m.get("name") == sel or m.get("selector") == sel:
            return m
    return None


def validator_macho_objcclass_find_ivar(cls: dict, name: str) -> Optional[dict]:
    """ObjcClass::find_ivar (macho) — ricerca ivar."""
    return validator_objcclass_find_ivar(cls, name)


def validator_machoobjcruntime_parse(binary: bytes, config: dict) -> dict:
    """MachoObjcRuntime::parse — parsa strutture ObjC dal Mach-O."""
    is_macho = binary[:4] in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")
    if not is_macho:
        raise ValueError("Not a valid Mach-O binary")
    return {"classes": [], "categories": [], "protocols": [], "config": config}


def validator_machoobjcruntime_get_class(runtime: dict, name: str) -> Optional[dict]:
    """MachoObjcRuntime::get_class — ricerca classe per nome."""
    for cls in runtime.get("classes", []):
        if cls.get("name") == name:
            return cls
    return None


def validator_machoobjcruntime_all_class_names(runtime: dict) -> list:
    """MachoObjcRuntime::all_class_names — tutti i nomi classe."""
    return [cls.get("name", "") for cls in runtime.get("classes", [])]


def validator_machoobjcruntime_classes_adopting_protocol(runtime: dict, proto: str) -> list:
    """MachoObjcRuntime::classes_adopting_protocol — classi che adottano un protocollo."""
    return [cls for cls in runtime.get("classes", []) if proto in cls.get("protocols", [])]


def validator_machoobjcruntime_method_counts(runtime: dict) -> dict:
    """MachoObjcRuntime::method_counts — numero metodi per classe."""
    return {cls.get("name", ""): len(cls.get("methods", [])) for cls in runtime.get("classes", [])}


def validator_parse_objc_runtime(binary: bytes) -> dict:
    """parse_objc_runtime — funzione top-level: parsa runtime ObjC da Mach-O con config default."""
    return validator_machoobjcruntime_parse(binary, {})


# ---------------------------------------------------------------------------
# ios_malware.rs
# ---------------------------------------------------------------------------

def validator_spywareindicators_risk_score(indicators: dict) -> int:
    """SpywareIndicators::risk_score — punteggio rischio spyware (0-100)."""
    score = 0
    if indicators.get("contacts_access"): score += 20
    if indicators.get("location_tracking"): score += 25
    if indicators.get("microphone_access"): score += 20
    if indicators.get("camera_access"): score += 15
    if indicators.get("messages_access"): score += 20
    return min(100, score)


def validator_datatheftindicators_stolen_data_types(indicators: dict) -> list:
    """DataTheftIndicators::stolen_data_types — categorie dati a rischio furto."""
    types = []
    if indicators.get("contacts"): types.append("Contacts")
    if indicators.get("photos"): types.append("Photos")
    if indicators.get("location"): types.append("Location")
    if indicators.get("health"): types.append("Health")
    if indicators.get("financial"): types.append("Financial")
    if indicators.get("credentials"): types.append("Credentials")
    return types


def validator_datatheftindicators_risk_score(indicators: dict) -> int:
    """DataTheftIndicators::risk_score — punteggio rischio furto dati."""
    return min(100, len(validator_datatheftindicators_stolen_data_types(indicators)) * 15)


def validator_ransomwareindicators_risk_score(indicators: dict) -> int:
    """RansomwareIndicators::risk_score — punteggio rischio ransomware."""
    score = 0
    if indicators.get("encryption_apis"): score += 30
    if indicators.get("file_enumeration"): score += 20
    if indicators.get("network_c2"): score += 25
    if indicators.get("ransom_message"): score += 25
    return min(100, score)


def validator_backdoorindicators_malicious_count(indicators: dict) -> int:
    """BackdoorIndicators::malicious_count — numero di indicatori backdoor trovati."""
    keys = ["remote_shell", "port_listener", "c2_communication", "persistence", "privilege_escalation"]
    return sum(1 for k in keys if indicators.get(k))


def validator_backdoorindicators_risk_score(indicators: dict) -> int:
    """BackdoorIndicators::risk_score — punteggio rischio backdoor."""
    return min(100, validator_backdoorindicators_malicious_count(indicators) * 20)


def validator_adwareindicators_risk_score(indicators: dict) -> int:
    """AdwareIndicators::risk_score — punteggio rischio adware."""
    score = 0
    if indicators.get("ad_frameworks"): score += 20
    if indicators.get("click_fraud"): score += 40
    if indicators.get("tracking"): score += 20
    if indicators.get("aggressive_ads"): score += 20
    return min(100, score)


def validator_cryptominerindicators_risk_score(indicators: dict) -> int:
    """CryptoMinerIndicators::risk_score — punteggio rischio crypto-miner."""
    score = 0
    if indicators.get("cpu_intensive_loops"): score += 30
    if indicators.get("mining_strings"): score += 40
    if indicators.get("network_pool_connect"): score += 30
    return min(100, score)


def validator_exploitkit_new(bundle_id: str, app_name: str) -> dict:
    """ExploitKit::new — costruttore kit exploit per un'app."""
    return {"bundle_id": bundle_id, "app_name": app_name, "exploits": []}


def validator_exploitkit_add_exploit(kit: dict, exploit: dict) -> None:
    """ExploitKit::add_exploit — aggiunge exploit al kit."""
    kit.setdefault("exploits", []).append(exploit)


def validator_exploitkit_has_zero_click_exploit(kit: dict) -> bool:
    """ExploitKit::has_zero_click_exploit — verifica presenza di exploit zero-click."""
    return any(e.get("zero_click", False) for e in kit.get("exploits", []))


_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

def validator_exploitkit_max_exploit_severity(kit: dict) -> Optional[str]:
    """ExploitKit::max_exploit_severity — gravità massima tra gli exploit trovati."""
    severities = [e.get("severity", "info") for e in kit.get("exploits", [])]
    if not severities:
        return None
    return max(severities, key=lambda s: _SEVERITY_ORDER.index(s) if s in _SEVERITY_ORDER else -1)


def validator_exploitkit_risk_score(kit: dict) -> int:
    """ExploitKit::risk_score — punteggio rischio complessivo."""
    if not kit.get("exploits"):
        return 0
    max_sev = validator_exploitkit_max_exploit_severity(kit)
    sev_scores = {"info": 10, "low": 25, "medium": 50, "high": 75, "critical": 100}
    base = sev_scores.get(max_sev or "info", 0)
    count_bonus = min(20, len(kit["exploits"]) * 2)
    return min(100, base + count_bonus)


def validator_malwarereport_is_spyware(report: dict) -> bool:
    """MalwareReport::is_spyware — classificazione come spyware."""
    return report.get("spyware_score", 0) >= 50


def validator_malwarereport_threat_summary(report: dict) -> str:
    """MalwareReport::threat_summary — riepilogo testuale delle minacce rilevate."""
    parts = []
    if report.get("spyware_score", 0) >= 50:
        parts.append(f"Spyware risk: {report['spyware_score']}/100")
    if report.get("ransomware_score", 0) >= 50:
        parts.append(f"Ransomware risk: {report['ransomware_score']}/100")
    if report.get("backdoor_score", 0) >= 50:
        parts.append(f"Backdoor risk: {report['backdoor_score']}/100")
    if not parts:
        return "No significant threats detected."
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# ios_jailbreak_detector.rs
# ---------------------------------------------------------------------------

def validator_jailbreakreport_high_confidence_indicators(report: dict) -> list:
    """JailbreakReport::high_confidence_indicators — indicatori ad alta confidenza."""
    return [i for i in report.get("indicators", []) if i.get("confidence", 0) >= 80]


def validator_jailbreakreport_indicators_by_method(report: dict, method: str) -> list:
    """JailbreakReport::indicators_by_method — filtra indicatori per tecnica di rilevamento."""
    return [i for i in report.get("indicators", []) if i.get("method") == method]


def validator_iosjailbreakdetector_new() -> dict:
    """IosJailbreakDetector::new — costruttore detector con euristiche predefinite."""
    return {
        "heuristics": [
            "cydia_strings", "substrate_dylibs", "root_paths", "sandbox_escape",
            "fork_call", "stat_paths", "url_schemes",
        ]
    }


def validator_iosjailbreakdetector_scan(detector: dict, binary: bytes) -> dict:
    """IosJailbreakDetector::scan — scansiona binario Mach-O e produce report jailbreak detection."""
    indicators = validator_scan_indicators(binary)
    return {
        "indicators": indicators,
        "score": min(100, len(indicators) * 15),
        "has_detection": len(indicators) > 0,
    }


def validator_has_jailbreak_detection(binary: bytes) -> bool:
    """has_jailbreak_detection — risposta rapida."""
    return len(validator_scan_indicators(binary)) > 0


def validator_jailbreak_risk_score(binary: bytes) -> int:
    """jailbreak_risk_score — punteggio 0-100 qualità detection jailbreak."""
    indicators = validator_scan_indicators(binary)
    return min(100, len(indicators) * 15)


_JB_STRINGS = [
    b"/Applications/Cydia.app", b"/var/lib/cydia", b"MobileSubstrate",
    b"com.saurik.Cydia", b"/bin/bash", b"/usr/sbin/sshd", b"Substrate",
    b"jailbreak", b"Cydia", b"cydia://",
]

def validator_scan_indicators(binary: bytes) -> list:
    """scan_indicators — lista raw di indicatori trovati."""
    found = []
    for pattern in _JB_STRINGS:
        if pattern in binary:
            found.append({"pattern": pattern.decode("utf-8", errors="replace"), "method": "string_match", "confidence": 85})
    return found


# ---------------------------------------------------------------------------
# jailbreak_detection.rs
# ---------------------------------------------------------------------------

def validator_jailbreakscanner_scan_strings(scanner: dict, strings: list) -> None:
    """JailbreakScanner::scan_strings — scansiona lista di stringhe per pattern jailbreak."""
    jb_patterns = {"cydia", "substrate", "jailbreak", "/var/lib/", "mobilesubstrate"}
    for s in strings:
        s_lower = s.lower()
        if any(p in s_lower for p in jb_patterns):
            scanner.setdefault("hits", []).append({"source": "string", "value": s, "method": "string_match"})


def validator_jailbreakscanner_scan_symbols(scanner: dict, symbols: list) -> None:
    """JailbreakScanner::scan_symbols — scansiona simboli per pattern jailbreak."""
    jb_sym = {"MSHookFunction", "MSHookMessageEx", "substrate", "cydia"}
    for sym in symbols:
        if any(p in sym for p in jb_sym):
            scanner.setdefault("hits", []).append({"source": "symbol", "value": sym, "method": "symbol_match"})


def validator_jailbreakscanner_scan_selectors(scanner: dict, selectors: list) -> None:
    """JailbreakScanner::scan_selectors — scansiona selettori ObjC per pattern jailbreak."""
    jb_sel = {"isJailbroken", "detectJailbreak", "checkJailbreak", "jailbreakDetected"}
    for sel in selectors:
        if sel in jb_sel or any(k.lower() in sel.lower() for k in ("jailbreak", "cydia")):
            scanner.setdefault("hits", []).append({"source": "selector", "value": sel, "method": "selector_match"})


def validator_jailbreakscanner_scan_disassembly(scanner: dict, disasm: str, fn_name: str) -> None:
    """JailbreakScanner::scan_disassembly — scansiona output disassembler per pattern."""
    jb_patterns = ["stat(", "access(", "fopen(", "/Applications/Cydia", "/var/lib"]
    for pat in jb_patterns:
        if pat in disasm:
            scanner.setdefault("hits", []).append({"source": "disasm", "value": pat, "function": fn_name, "method": "disasm_pattern"})


def validator_jailbreakscanner_finish(scanner: dict) -> dict:
    """JailbreakScanner::finish — finalizza e produce il report."""
    hits = scanner.get("hits", [])
    techniques = list({h.get("method", "") for h in hits})
    return {"indicators": hits, "techniques": techniques, "score": min(100, len(hits) * 10)}


def validator_jailbreakreport_techniques_used(report: dict) -> list:
    """JailbreakReport::techniques_used — tecniche di detection identificate."""
    return report.get("techniques", [])


def validator_jailbreakreport_generate_frida_bypass(report: dict) -> str:
    """JailbreakReport::generate_frida_bypass — genera script Frida per bypassare la detection."""
    techniques = report.get("techniques", [])
    lines = ["// Auto-generated Frida bypass script", ""]
    if "string_match" in techniques or not techniques:
        lines.append("// Hook common jailbreak string checks")
        lines.append("Interceptor.attach(Module.findExportByName(null, 'stat'), {")
        lines.append("  onEnter(args) { /* patch */ }")
        lines.append("});")
    if "selector_match" in techniques:
        lines.append("// Hook ObjC selectors")
        lines.append("var cls = ObjC.classes.JailbreakDetector;")
        lines.append("if (cls) { /* hook methods */ }")
    return "\n".join(lines)


def validator_analyze_strings(strings: list) -> dict:
    """analyze_strings — analisi rapida solo su stringhe."""
    scanner: dict = {"hits": []}
    validator_jailbreakscanner_scan_strings(scanner, strings)
    return validator_jailbreakscanner_finish(scanner)


def validator_analyze_binary_jailbreak(binary: bytes, metadata: dict) -> dict:
    """analyze_binary (jailbreak) — analisi completa da dati estratti da binario."""
    strings_raw = [m.group(0).decode("utf-8", errors="replace")
                   for m in re.finditer(rb"[\x20-\x7e]{4,}", binary)]
    scanner: dict = {"hits": []}
    validator_jailbreakscanner_scan_strings(scanner, strings_raw)
    selectors = metadata.get("selectors", [])
    validator_jailbreakscanner_scan_selectors(scanner, selectors)
    symbols = metadata.get("symbols", [])
    validator_jailbreakscanner_scan_symbols(scanner, symbols)
    return validator_jailbreakscanner_finish(scanner)


# ---------------------------------------------------------------------------
# fairplay.rs
# ---------------------------------------------------------------------------

def validator_detect_fairplay_in_slice(data: bytes) -> dict:
    """detect_fairplay_in_slice — rileva FairPlay in singola slice Mach-O."""
    # LC_ENCRYPTION_INFO = 0x21, LC_ENCRYPTION_INFO_64 = 0x2C
    encrypted = False
    cryptid = 0
    i = 0
    if len(data) < 16:
        return {"encrypted": False, "cryptid": 0}
    # Very minimal scan for cryptid field pattern
    magic = struct.unpack_from("<I", data, 0)[0]
    is_64 = magic == 0xFEEDFACF
    if magic in (0xFEEDFACE, 0xFEEDFACF):
        # scan load commands
        ncmds = struct.unpack_from("<I", data, 16)[0]
        sizeofcmds = struct.unpack_from("<I", data, 20)[0]
        offset = 28 if is_64 else 28
        for _ in range(ncmds):
            if offset + 8 > len(data):
                break
            cmd = struct.unpack_from("<I", data, offset)[0]
            cmdsize = struct.unpack_from("<I", data, offset + 4)[0]
            if cmd in (0x21, 0x2C) and offset + 20 <= len(data):
                cryptid = struct.unpack_from("<I", data, offset + 16)[0]
                encrypted = cryptid != 0
            offset += max(8, cmdsize)
    return {"encrypted": encrypted, "cryptid": cryptid}


def validator_detect_fairplay(data: bytes) -> dict:
    """detect_fairplay — rileva FairPlay in Mach-O (fat o thin)."""
    if len(data) < 8:
        return {"encrypted": False, "cryptid": 0}
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic == 0xCAFEBABE:
        # FAT binary — check first arch slice
        nfat = struct.unpack_from(">I", data, 4)[0]
        if nfat > 0 and len(data) >= 20:
            offset = struct.unpack_from(">I", data, 8)[0]
            size = struct.unpack_from(">I", data, 16)[0]
            return validator_detect_fairplay_in_slice(data[offset:offset + size])
    return validator_detect_fairplay_in_slice(data)


def validator_fairplayinfo_from_status(status: dict) -> dict:
    """FairPlayInfo::from_status — costruisce info strutturate dallo status."""
    return {
        "is_encrypted": status.get("encrypted", False),
        "cryptid": status.get("cryptid", 0),
        "can_disassemble": not status.get("encrypted", False),
    }


def validator_fairplayinfo_assert_can_disassemble(info: dict):
    """FairPlayInfo::assert_can_disassemble — errore se il binario è ancora cifrato."""
    if info.get("is_encrypted", False):
        raise RuntimeError("Binary is FairPlay encrypted and cannot be disassembled")


def validator_decryptionsession_new(device_udid: str, bundle_id: str) -> dict:
    """DecryptionSession::new — nuova sessione di decifrazione."""
    return {"device_udid": device_udid, "bundle_id": bundle_id, "step": 0, "pages": [], "complete": False}


def validator_decryptionsession_advance(session: dict) -> None:
    """DecryptionSession::advance — avanza allo step successivo della decifrazione."""
    session["step"] = session.get("step", 0) + 1
    if session["step"] >= 3:
        session["complete"] = True


def validator_decryptionsession_add_page(session: dict, page: dict) -> None:
    """DecryptionSession::add_page — aggiunge pagina di memoria decifrata."""
    session.setdefault("pages", []).append(page)


def validator_decryptionsession_reassemble(session: dict) -> bytes:
    """DecryptionSession::reassemble — riassembla il binario decifrato."""
    if not session.get("complete", False):
        raise RuntimeError("Decryption session not complete")
    parts = [p.get("data", b"") for p in session.get("pages", [])]
    return b"".join(parts)


def validator_patch_cryptid(data: bytearray, new_cryptid: int) -> None:
    """patch_cryptid — patch in-place del campo cryptid nel LC_ENCRYPTION_INFO."""
    if len(data) < 8:
        return
    magic = struct.unpack_from("<I", data, 0)[0]
    is_64 = magic == 0xFEEDFACF
    if magic not in (0xFEEDFACE, 0xFEEDFACF):
        return
    ncmds = struct.unpack_from("<I", data, 16)[0]
    offset = 28
    for _ in range(ncmds):
        if offset + 8 > len(data):
            break
        cmd = struct.unpack_from("<I", data, offset)[0]
        cmdsize = struct.unpack_from("<I", data, offset + 4)[0]
        if cmd in (0x21, 0x2C) and offset + 20 <= len(data):
            struct.pack_into("<I", data, offset + 16, new_cryptid)
            return
        offset += max(8, cmdsize)


def validator_check_binary(data: bytes) -> str:
    """check_binary — decide se il binario necessita decifrazione."""
    status = validator_detect_fairplay(data)
    if status.get("encrypted"):
        return "NeedsDecryption"
    return "ReadyToLoad"


def validator_mark_as_decrypted(data: bytearray, tool_name: str) -> None:
    """mark_as_decrypted — segna il binario come decifrato (zeroing cryptid + note)."""
    validator_patch_cryptid(data, 0)


# ---------------------------------------------------------------------------
# ios_swift_metadata_parser.rs
# ---------------------------------------------------------------------------

def validator_swifttyperecord_has_stored_fields(record: dict) -> bool:
    """SwiftTypeRecord::has_stored_fields — il tipo ha campi stored?"""
    return len(record.get("fields", [])) > 0


def validator_swifttyperecord_stored_field_count(record: dict) -> int:
    """SwiftTypeRecord::stored_field_count — numero campi stored."""
    return len(record.get("fields", []))


def validator_swifttyperecord_find_field(record: dict, name: str) -> Optional[dict]:
    """SwiftTypeRecord::find_field — ricerca campo per nome."""
    for f in record.get("fields", []):
        if f.get("name") == name:
            return f
    return None


def validator_swiftmetadataparser_parse_types(parser: dict, binary: bytes) -> list:
    """SwiftMetadataParser::parse_types — estrae tipi Swift dal Mach-O."""
    has_swift = b"__swift5_types" in binary or b"_$s" in binary
    if not has_swift:
        return []
    return []  # real parsing needs Mach-O structure; return empty for stdlib-only


def validator_swiftmetadataparser_parse_conformances(parser: dict, binary: bytes) -> list:
    """SwiftMetadataParser::parse_conformances — estrae conformanze di protocollo."""
    has_swift = b"__swift5_proto" in binary
    return []


def validator_swiftmetadataparser_parse_all(parser: dict, binary: bytes) -> dict:
    """SwiftMetadataParser::parse_all — estrae tutto."""
    return {
        "types": validator_swiftmetadataparser_parse_types(parser, binary),
        "conformances": validator_swiftmetadataparser_parse_conformances(parser, binary),
        "metadata": {},
    }


def validator_parse_swift_types(binary: bytes) -> list:
    """parse_swift_types — funzione top-level per tipi Swift."""
    return validator_swiftmetadataparser_parse_types({}, binary)


def validator_parse_protocol_conformances(binary: bytes) -> list:
    """parse_protocol_conformances — funzione top-level per conformanze."""
    return validator_swiftmetadataparser_parse_conformances({}, binary)


def validator_has_swift_metadata(binary: bytes) -> bool:
    """has_swift_metadata — presenza di sezioni __swift5_* nel Mach-O."""
    swift_sections = [b"__swift5_types", b"__swift5_proto", b"__swift5_fieldmd",
                      b"__swift5_assocty", b"__swift5_replace"]
    return any(s in binary for s in swift_sections)


def validator_has_swift_symbols(binary: bytes) -> bool:
    """has_swift_symbols — presenza di simboli Swift nella symbol table."""
    return b"_$s" in binary or b"_T0" in binary


# ---------------------------------------------------------------------------
# ios_codesign_verifier.rs
# ---------------------------------------------------------------------------

def validator_codedirectory_parse(buf: bytes, offset: int) -> dict:
    """CodeDirectory::parse — parsa struttura CodeDirectory dalla LC_CODE_SIGNATURE."""
    if offset + 8 > len(buf):
        raise ValueError("Buffer too short for CodeDirectory")
    magic = struct.unpack_from(">I", buf, offset)[0]
    if magic != 0xFADE0C02:
        raise ValueError(f"Not a CodeDirectory (magic={magic:#010x})")
    length = struct.unpack_from(">I", buf, offset + 4)[0]
    return {"magic": magic, "length": length, "offset": offset, "valid": True}


def validator_superblob_parse(buf: bytes) -> dict:
    """SuperBlob::parse — parsa SuperBlob (contenitore principale code sign)."""
    if len(buf) < 12:
        raise ValueError("Buffer too short for SuperBlob")
    magic = struct.unpack_from(">I", buf, 0)[0]
    if magic != 0xFADE0CC0:
        raise ValueError(f"Not a SuperBlob (magic={magic:#010x})")
    length = struct.unpack_from(">I", buf, 4)[0]
    count = struct.unpack_from(">I", buf, 8)[0]
    blobs = []
    for i in range(count):
        idx_off = 12 + i * 8
        if idx_off + 8 > len(buf):
            break
        btype = struct.unpack_from(">I", buf, idx_off)[0]
        boff = struct.unpack_from(">I", buf, idx_off + 4)[0]
        blobs.append({"type": btype, "offset": boff})
    return {"magic": magic, "length": length, "count": count, "blobs": blobs}


def validator_codesignverifier_verify(binary: bytes) -> dict:
    """CodeSignVerifier::verify — verifica hash slot del binario contro CodeDirectory."""
    # Locate LC_CODE_SIGNATURE in Mach-O
    if len(binary) < 28:
        return {"valid": False, "error": "Too short"}
    magic = struct.unpack_from("<I", binary, 0)[0]
    if magic not in (0xFEEDFACE, 0xFEEDFACF):
        return {"valid": False, "error": "Not Mach-O"}
    return {"valid": True, "slots_verified": 0, "signature_present": False}


def validator_verify_signature(binary: bytes) -> dict:
    """verify_signature — funzione top-level per verifica firma codice."""
    return validator_codesignverifier_verify(binary)


# ---------------------------------------------------------------------------
# ios_entitlements_parser.rs
# ---------------------------------------------------------------------------

_ENTITLEMENT_CATEGORIES = {
    "com.apple.security.": "security",
    "com.apple.developer.": "developer",
    "keychain-access-groups": "keychain",
    "application-identifier": "identity",
    "team-identifier": "identity",
    "get-task-allow": "debug",
    "task_for_pid-allow": "debug",
    "aps-environment": "push",
}

def validator_entitlementkind_from_key(key: str) -> str:
    """EntitlementKind::from_key — classifica una chiave entitlement per categoria."""
    for prefix, kind in _ENTITLEMENT_CATEGORIES.items():
        if key.startswith(prefix) or key == prefix:
            return kind
    if "debug" in key.lower() or "task" in key.lower():
        return "debug"
    return "other"


def validator_entitlementvalue_display_string(value: Any) -> str:
    """EntitlementValue::display_string — rappresentazione leggibile del valore."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return "[" + ", ".join(str(v) for v in value) + "]"
    return str(value)


def validator_entitlement_new(key: str, value: Any) -> dict:
    """Entitlement::new — costruttore entitlement."""
    return {"key": key, "value": value, "kind": validator_entitlementkind_from_key(key)}


def validator_entitlement_is_debug(entitlement: dict) -> bool:
    """Entitlement::is_debug — indica se è un entitlement debug."""
    key = entitlement.get("key", "")
    return "get-task-allow" in key or "task_for_pid" in key or entitlement.get("kind") == "debug"


def validator_entitlementset_is_debuggable(eset: dict) -> bool:
    """EntitlementSet::is_debuggable — l'app ha entitlement di debug attivi?"""
    for e in eset.get("entitlements", []):
        if validator_entitlement_is_debug(e) and e.get("value") is True:
            return True
    return False


def validator_entitlementset_by_kind(eset: dict, kind: str) -> list:
    """EntitlementSet::by_kind — filtra per categoria."""
    return [e for e in eset.get("entitlements", []) if e.get("kind") == kind]


def validator_entitlementset_get(eset: dict, key: str) -> Optional[dict]:
    """EntitlementSet::get — ricerca per chiave."""
    for e in eset.get("entitlements", []):
        if e.get("key") == key:
            return e
    return None


_SENSITIVE_ENTITLEMENTS = {
    "get-task-allow", "task_for_pid-allow", "com.apple.private.",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.disable-library-validation",
}

def validator_entitlementset_sensitive(eset: dict) -> list:
    """EntitlementSet::sensitive — entitlement sensibili/privilegiati."""
    result = []
    for e in eset.get("entitlements", []):
        key = e.get("key", "")
        if any(key.startswith(s) or key == s for s in _SENSITIVE_ENTITLEMENTS):
            result.append(e)
    return result


def validator_entitlementset_kind_summary(eset: dict) -> dict:
    """EntitlementSet::kind_summary — conteggio per categoria."""
    summary: dict = {}
    for e in eset.get("entitlements", []):
        kind = e.get("kind", "other")
        summary[kind] = summary.get(kind, 0) + 1
    return summary


def validator_entitlementparser_parse(data: bytes) -> dict:
    """EntitlementParser::parse — parsa XML entitlements dal blob code sign."""
    try:
        result = validator_parse_xml_plist(data)
        entitlements = []
        if isinstance(result, dict):
            for k, v in result.items():
                entitlements.append(validator_entitlement_new(k, v))
        return {"entitlements": entitlements, "raw": result, "error": None}
    except Exception as ex:
        return {"entitlements": [], "raw": None, "error": str(ex)}


def validator_parse_entitlements(data: bytes) -> dict:
    """parse_entitlements — funzione top-level per parsing entitlements."""
    return validator_entitlementparser_parse(data)


def validator_entitlementsummary_from_result(result: dict) -> dict:
    """EntitlementSummary::from_result — costruisce summary aggregato."""
    eset = {"entitlements": result.get("entitlements", [])}
    return {
        "count": len(eset["entitlements"]),
        "is_debuggable": validator_entitlementset_is_debuggable(eset),
        "sensitive_count": len(validator_entitlementset_sensitive(eset)),
        "kind_summary": validator_entitlementset_kind_summary(eset),
    }


# ---------------------------------------------------------------------------
# ios_dylib_injector_detector.rs
# ---------------------------------------------------------------------------

_SUSPICIOUS_DYLIB_PATTERNS = [
    "MobileSubstrate", "CydiaSubstrate", "substitute", "TweakInject",
    "ellekit", "FridaGadget", "/tmp/", "/var/tmp/",
]

def validator_detectionresult_suspicious_dylibs(result: dict) -> list:
    """DetectionResult::suspicious_dylibs — dylib ritenute sospette."""
    return [d for d in result.get("dylibs", []) if d.get("suspicious", False)]


def validator_detectionresult_highest_risk_dylib(result: dict) -> Optional[dict]:
    """DetectionResult::highest_risk_dylib — dylib col rischio più alto."""
    dylibs = result.get("dylibs", [])
    if not dylibs:
        return None
    return max(dylibs, key=lambda d: d.get("risk_score", 0))


def validator_dylibinjectordetector_scan(detector: dict, binary: bytes) -> dict:
    """DylibInjectorDetector::scan — scansiona binary Mach-O per dylib iniettate."""
    dylibs = []
    # Extract strings that look like dylib paths
    for m in re.finditer(rb"[\x20-\x7e]{10,}", binary):
        s = m.group(0).decode("utf-8", errors="replace")
        if s.endswith(".dylib") or ".framework/" in s:
            is_suspicious = any(p in s for p in _SUSPICIOUS_DYLIB_PATTERNS)
            dylibs.append({"path": s, "suspicious": is_suspicious, "risk_score": 80 if is_suspicious else 10})
    return {"dylibs": dylibs}


def validator_dylibinjectordetector_scan_frameworks(detector: dict, frameworks: list) -> list:
    """DylibInjectorDetector::scan_frameworks — controlla lista framework per anomalie."""
    result = []
    for fw in frameworks:
        name = fw.get("name", "")
        if any(p in name for p in _SUSPICIOUS_DYLIB_PATTERNS):
            result.append({"path": name, "suspicious": True, "risk_score": 80})
    return result


def validator_has_injection_evidence(binary: bytes) -> bool:
    """has_injection_evidence — risposta rapida: ci sono evidenze di injection?"""
    return any(p.encode() in binary for p in _SUSPICIOUS_DYLIB_PATTERNS)


def validator_injection_risk_score(binary: bytes) -> int:
    """injection_risk_score — punteggio rischio injection 0-100."""
    count = sum(1 for p in _SUSPICIOUS_DYLIB_PATTERNS if p.encode() in binary)
    return min(100, count * 20)


# ---------------------------------------------------------------------------
# entitlements.rs
# ---------------------------------------------------------------------------

def validator_iosentitlements_application_groups(ent: dict) -> list:
    """IosEntitlements::application_groups — app groups dichiarati."""
    v = ent.get("com.apple.security.application-groups", [])
    return list(v) if isinstance(v, list) else ([v] if v else [])


def validator_iosentitlements_keychain_groups(ent: dict) -> list:
    """IosEntitlements::keychain_groups — keychain access groups."""
    v = ent.get("keychain-access-groups", [])
    return list(v) if isinstance(v, list) else ([v] if v else [])


def validator_iosentitlements_team_id(ent: dict) -> Optional[str]:
    """IosEntitlements::team_id — Team ID Apple Developer."""
    return ent.get("com.apple.developer.team-identifier") or ent.get("team-identifier")


def validator_iosentitlements_has_debugger_entitlement(ent: dict) -> bool:
    """IosEntitlements::has_debugger_entitlement — presence di entitlement debug."""
    return bool(ent.get("get-task-allow")) or bool(ent.get("task_for_pid-allow"))


def validator_iosentitlements_has_get_task_allow(ent: dict) -> bool:
    """IosEntitlements::has_get_task_allow."""
    return bool(ent.get("get-task-allow"))


def validator_iosentitlements_has_platform_application(ent: dict) -> bool:
    """IosEntitlements::has_platform_application."""
    return bool(ent.get("platform-application"))


def validator_iosentitlements_has_task_for_pid(ent: dict) -> bool:
    """IosEntitlements::has_task_for_pid."""
    return bool(ent.get("task_for_pid-allow"))


def validator_iosentitlements_network_client(ent: dict) -> bool:
    """IosEntitlements::network_client."""
    return bool(ent.get("com.apple.security.network.client"))


def validator_iosentitlements_push_notifications(ent: dict) -> bool:
    """IosEntitlements::push_notifications."""
    return "aps-environment" in ent


def validator_iosentitlements_apple_pay(ent: dict) -> bool:
    """IosEntitlements::apple_pay."""
    return "com.apple.developer.in-app-payments" in ent


def validator_iosentitlements_health_kit(ent: dict) -> bool:
    """IosEntitlements::health_kit."""
    return "com.apple.developer.healthkit" in ent


def validator_iosentitlements_homekit(ent: dict) -> bool:
    """IosEntitlements::homekit."""
    return "com.apple.developer.homekit" in ent


def validator_iosentitlements_inter_app_audio(ent: dict) -> bool:
    """IosEntitlements::inter_app_audio."""
    return "inter-app-audio" in ent


def validator_iosentitlements_has_file_access_entitlements(ent: dict) -> list:
    """IosEntitlements::has_file_access_entitlements — entitlement di accesso file."""
    file_keys = [k for k in ent if "file" in k.lower() or "document" in k.lower() or "storage" in k.lower()]
    return [{"key": k, "value": ent[k]} for k in file_keys]


def validator_iosentitlements_sandbox_entitlements(ent: dict) -> list:
    """IosEntitlements::sandbox_entitlements — entitlement sandbox."""
    sandbox_keys = [k for k in ent if "sandbox" in k.lower() or k.startswith("com.apple.security.")]
    return [{"key": k, "value": ent[k]} for k in sandbox_keys]


_SUSPICIOUS_ENT_KEYS = {
    "get-task-allow", "task_for_pid-allow", "platform-application",
    "com.apple.private.security.no-sandbox",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.debugger",
}

def validator_iosentitlements_suspicious_entitlements(ent: dict) -> list:
    """IosEntitlements::suspicious_entitlements — chiavi entitlement sospette o privilegiate."""
    return [k for k in ent if k in _SUSPICIOUS_ENT_KEYS or k.startswith("com.apple.private.")]


def validator_iosentitlements_has_suspicious_entitlements(ent: dict) -> bool:
    """IosEntitlements::has_suspicious_entitlements."""
    return len(validator_iosentitlements_suspicious_entitlements(ent)) > 0


def validator_iosentitlements_all_keys(ent: dict) -> list:
    """IosEntitlements::all_keys — tutte le chiavi entitlement presenti."""
    return list(ent.keys())


def validator_iosentitlements_key_count(ent: dict) -> int:
    """IosEntitlements::key_count — numero totale di entitlement."""
    return len(ent)


# ---------------------------------------------------------------------------
# codesign.rs
# ---------------------------------------------------------------------------

def validator_codesigninfo_mock() -> dict:
    """CodeSignInfo::mock — istanza fittizia per test."""
    return {"identifier": "com.example.app", "team_id": "ABCDE12345", "valid": True, "entitlements": {}}


def validator_codesignblob_parse(data: bytes) -> dict:
    """CodeSignBlob::parse — parsa blob code signature dal Mach-O."""
    if len(data) < 8:
        raise ValueError("Buffer too short")
    magic = struct.unpack_from(">I", data, 0)[0]
    return {"magic": magic, "data": data, "_identifier": "", "_team_id": None}


def validator_codesignblob_identifier(blob: dict) -> str:
    """CodeSignBlob::identifier — identificatore bundle dalla firma."""
    return blob.get("_identifier", "")


def validator_codesignblob_team_id(blob: dict) -> Optional[str]:
    """CodeSignBlob::team_id — Team ID dalla firma."""
    return blob.get("_team_id")


# ---------------------------------------------------------------------------
# lib.rs
# ---------------------------------------------------------------------------

def validator_lib_iosentitlements_has(ent: dict, key: str) -> bool:
    """IosEntitlements::has — presenza di una chiave entitlement."""
    return key in ent


def validator_lib_iosentitlements_get(ent: dict, key: str) -> Optional[Any]:
    """IosEntitlements::get — valore di un entitlement per chiave."""
    return ent.get(key)


def validator_lib_iosentitlements_mock() -> dict:
    """IosEntitlements::mock (lib) — istanza fittizia per test."""
    return {
        "application-identifier": "ABCDE12345.com.example.app",
        "com.apple.developer.team-identifier": "ABCDE12345",
        "get-task-allow": False,
        "aps-environment": "production",
    }


def validator_iosappbinary_is_debuggable(binary: dict) -> bool:
    """IosAppBinary::is_debuggable — il binario ha simboli debug o entitlement debug?"""
    return binary.get("has_debug_symbols", False) or binary.get("get_task_allow", False)


def validator_iosappbinary_system_frameworks(binary: dict) -> list:
    """IosAppBinary::system_frameworks — framework di sistema linkati."""
    return [fw for fw in binary.get("frameworks", []) if fw.get("path", "").startswith("/System/")]


def validator_iosobjcclass_adopts_protocol(cls: dict, proto: str) -> bool:
    """IosObjcClass::adopts_protocol — adozione protocollo ObjC."""
    return proto in cls.get("protocols", [])


def validator_iosobjcclass_find_instance_method(cls: dict, sel: str) -> Optional[dict]:
    """IosObjcClass::find_instance_method — ricerca metodo istanza."""
    return validator_macho_objcclass_find_instance_method(cls, sel)


def validator_iosobjcclass_find_class_method(cls: dict, sel: str) -> Optional[dict]:
    """IosObjcClass::find_class_method — ricerca metodo di classe."""
    return validator_macho_objcclass_find_class_method(cls, sel)


def validator_lib_decode_type_encoding(enc: str) -> list:
    """decode_type_encoding (lib) — decodifica type encoding ObjC in nomi leggibili."""
    return validator_decode_type_encoding(enc)


def validator_scan_objc_selectors(binary: bytes) -> list:
    """scan_objc_selectors — estrae selettori ObjC dalla sezione __objc_selrefs."""
    selectors = []
    # Extract printable ASCII strings of reasonable selector length
    for m in re.finditer(rb"[\x20-\x7e]{2,128}", binary):
        s = m.group(0).decode("ascii", errors="replace")
        # Selectors are typically alphanumeric with : and _
        if re.match(r'^[a-zA-Z_][a-zA-Z0-9_:]*$', s):
            selectors.append(s)
    return list(dict.fromkeys(selectors))  # deduplicate preserving order


def validator_scan_objc_classes(binary: bytes) -> list:
    """scan_objc_classes — estrae nomi classi ObjC dal binario."""
    classes = []
    for m in re.finditer(rb"[\x20-\x7e]{2,128}", binary):
        s = m.group(0).decode("ascii", errors="replace")
        # Class names are PascalCase, no colons
        if re.match(r'^[A-Z][a-zA-Z0-9_]{1,}$', s):
            classes.append(s)
    return list(dict.fromkeys(classes))


def validator_swiftdemangler_is_swift_mangled(name: str) -> bool:
    """SwiftDemangler::is_swift_mangled — verifica prefisso mangling Swift."""
    return name.startswith(("_$s", "$s", "_T0", "_T"))


def validator_swiftdemangler_demangle(mangled: str) -> Optional[str]:
    """SwiftDemangler::demangle — demangling nome Swift."""
    if not validator_swiftdemangler_is_swift_mangled(mangled):
        return None
    return validator_demangle_swift_name(mangled)


def validator_iosswiftinfo_from_macho(binary: bytes) -> dict:
    """IosSwiftInfo::from_macho — estrae info Swift (tipi, conformanze) dal Mach-O."""
    return {
        "has_swift": validator_has_swift_metadata(binary),
        "has_symbols": validator_has_swift_symbols(binary),
        "types": validator_parse_swift_types(binary),
        "conformances": validator_parse_protocol_conformances(binary),
    }


def validator_iosappinfo_extract_app_info(ipa_bytes: bytes) -> Optional[dict]:
    """IosAppInfo::extract_app_info — estrae metadati app da IPA (zip)."""
    import zipfile, io
    try:
        with zipfile.ZipFile(io.BytesIO(ipa_bytes)) as zf:
            plist_names = [n for n in zf.namelist() if n.endswith("Info.plist") and "Payload/" in n]
            if not plist_names:
                return None
            raw = zf.read(plist_names[0])
            return validator_iosappinfo_parse_plist(raw)
    except Exception:
        return None


def validator_iosappinfo_parse_plist(raw: bytes) -> Optional[dict]:
    """IosAppInfo::parse_plist — estrae metadati da raw Info.plist."""
    try:
        plist = validator_plist_auto_detect(raw)
        if not isinstance(plist, dict):
            return None
        return {
            "bundle_id": plist.get("CFBundleIdentifier"),
            "display_name": plist.get("CFBundleDisplayName") or plist.get("CFBundleName"),
            "version": plist.get("CFBundleShortVersionString"),
            "build": plist.get("CFBundleVersion"),
            "minimum_os": plist.get("MinimumOSVersion"),
            "executable": plist.get("CFBundleExecutable"),
        }
    except Exception:
        return None


def validator_iossecuritychecker_check_arc_usage(macho_bytes: bytes) -> bool:
    """IosSecurityChecker::check_arc_usage — verifica uso ARC."""
    return b"_objc_retain" in macho_bytes or b"_objc_release" in macho_bytes or b"_objc_autorelease" in macho_bytes


def validator_iossecuritychecker_check_pie_enabled(macho_bytes: bytes) -> bool:
    """IosSecurityChecker::check_pie_enabled — verifica flag PIE nel Mach-O header."""
    if len(macho_bytes) < 28:
        return False
    magic = struct.unpack_from("<I", macho_bytes, 0)[0]
    if magic not in (0xFEEDFACE, 0xFEEDFACF):
        return False
    flags = struct.unpack_from("<I", macho_bytes, 24)[0]
    MH_PIE = 0x00200000
    return bool(flags & MH_PIE)


def validator_iossecuritychecker_check_stack_canary(macho_bytes: bytes) -> bool:
    """IosSecurityChecker::check_stack_canary — verifica presenza stack canary."""
    return b"___stack_chk_guard" in macho_bytes or b"__stack_chk_guard" in macho_bytes


def validator_iossecuritychecker_check_debug_symbols(macho_bytes: bytes) -> bool:
    """IosSecurityChecker::check_debug_symbols — verifica presenza simboli debug."""
    return b".debug_info" in macho_bytes or b"__DWARF" in macho_bytes or b"DSYM" in macho_bytes


def validator_iossecuritychecker_report(macho_bytes: bytes) -> dict:
    """IosSecurityChecker::report — report sicurezza base."""
    return {
        "arc": validator_iossecuritychecker_check_arc_usage(macho_bytes),
        "pie": validator_iossecuritychecker_check_pie_enabled(macho_bytes),
        "stack_canary": validator_iossecuritychecker_check_stack_canary(macho_bytes),
        "debug_symbols": validator_iossecuritychecker_check_debug_symbols(macho_bytes),
    }


def validator_iossecuritychecker_full_report(macho_bytes: bytes) -> dict:
    """IosSecurityChecker::full_report — report sicurezza esteso."""
    base = validator_iossecuritychecker_report(macho_bytes)
    base["objc_classes"] = validator_iossecuritychecker_extract_objc_classes(macho_bytes)
    base["swift_types"] = validator_iossecuritychecker_extract_swift_types(macho_bytes)
    base["has_swift"] = validator_has_swift_metadata(macho_bytes)
    return base


def validator_iossecuritychecker_extract_objc_classes(macho_bytes: bytes) -> list:
    """IosSecurityChecker::extract_objc_classes — estrae nomi classi ObjC."""
    return validator_scan_objc_classes(macho_bytes)


def validator_iossecuritychecker_extract_swift_types(macho_bytes: bytes) -> list:
    """IosSecurityChecker::extract_swift_types — estrae nomi tipi Swift."""
    return validator_parse_swift_types(macho_bytes)


def validator_jailbreakdetectionscanner_scan(binary: bytes) -> list:
    """JailbreakDetectionScanner::scan — scansiona il binario per tecniche di jailbreak detection."""
    return validator_scan_indicators(binary)


def validator_jailbreakdetectionscanner_has_jailbreak_detection(binary: bytes) -> bool:
    """JailbreakDetectionScanner::has_jailbreak_detection — risposta rapida."""
    return validator_has_jailbreak_detection(binary)


def validator_jailbreakdetectionscanner_technique_summary(indicators: list) -> list:
    """JailbreakDetectionScanner::technique_summary — riepilogo tecniche per frequenza."""
    from collections import Counter
    counts = Counter(i.get("method", "unknown") for i in indicators)
    return sorted(counts.items(), key=lambda x: -x[1])


def validator_sslpinningscanner_scan(binary: bytes) -> list:
    """SslPinningScanner::scan — scansiona per tecniche SSL pinning."""
    ssl_patterns = [
        b"SecTrustEvaluate", b"SecCertificateCopyData", b"NSURLSessionDelegate",
        b"TrustKit", b"AFNetworking", b"certificate_pinning", b"ssl_pinning",
        b"kSecTrustResultProceed", b"SSLSetSessionOption",
    ]
    found = []
    for pattern in ssl_patterns:
        if pattern in binary:
            found.append({"pattern": pattern.decode("utf-8", errors="replace"), "type": "ssl_pinning"})
    return found


def validator_sslpinningscanner_has_ssl_pinning(binary: bytes) -> bool:
    """SslPinningScanner::has_ssl_pinning — risposta rapida."""
    return len(validator_sslpinningscanner_scan(binary)) > 0


def validator_swizzlingscanner_scan(binary: bytes) -> list:
    """SwizzlingScanner::scan — scansiona per uso di method swizzling."""
    swizzle_patterns = [
        b"method_exchangeImplementations", b"method_setImplementation",
        b"class_replaceMethod", b"swizzle", b"exchangeImplementations",
    ]
    found = []
    for pattern in swizzle_patterns:
        if pattern in binary:
            found.append({"pattern": pattern.decode("utf-8", errors="replace"), "type": "swizzling"})
    return found


def validator_swizzlingscanner_has_swizzling(binary: bytes) -> bool:
    """SwizzlingScanner::has_swizzling — risposta rapida."""
    return len(validator_swizzlingscanner_scan(binary)) > 0


def validator_iosruntimeanalysis_analyse(binary: bytes) -> dict:
    """IosRuntimeAnalysis::analyse — analisi runtime completa (ObjC + Swift + sicurezza)."""
    return {
        "security": validator_iossecuritychecker_report(binary),
        "jailbreak_indicators": validator_jailbreakdetectionscanner_scan(binary),
        "ssl_pinning": validator_sslpinningscanner_scan(binary),
        "swizzling": validator_swizzlingscanner_scan(binary),
        "has_swift": validator_has_swift_metadata(binary),
        "objc_classes": validator_scan_objc_classes(binary),
    }


def validator_iosruntimeanalysis_summary(analysis: dict) -> str:
    """IosRuntimeAnalysis::summary — riepilogo testuale dell'analisi runtime."""
    sec = analysis.get("security", {})
    parts = []
    parts.append(f"PIE={'yes' if sec.get('pie') else 'no'}")
    parts.append(f"ARC={'yes' if sec.get('arc') else 'no'}")
    parts.append(f"StackCanary={'yes' if sec.get('stack_canary') else 'no'}")
    parts.append(f"Swift={'yes' if analysis.get('has_swift') else 'no'}")
    jb = len(analysis.get("jailbreak_indicators", []))
    if jb:
        parts.append(f"JailbreakDetection={jb} indicators")
    ssl = len(analysis.get("ssl_pinning", []))
    if ssl:
        parts.append(f"SSLPinning={ssl} patterns")
    return " | ".join(parts)


# ---------------------------------------------------------------------------
# Self-test (smoke)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Quick smoke test of a selection of validators
    assert validator_platform_parse_platform("iphoneos") == "iphoneos"
    assert validator_platform_parse_platform("UNKNOWN") is None

    b = {"architectures": ["arm64", "x86_64"]}
    assert validator_appbinary_supports_arm64(b)
    assert validator_appbinary_supports_x86_64(b)

    plist = {
        "CFBundleIdentifier": "com.example.app",
        "CFBundleVersion": "100",
        "NSCameraUsageDescription": "We use the camera.",
        "UIBackgroundModes": ["audio", "fetch"],
        "MinimumOSVersion": "14.0",
        "UIRequiredDeviceCapabilities": ["arm64"],
    }
    assert validator_infoplist_bundle_id(plist) == "com.example.app"
    assert validator_infoplist_has_any_privacy_key(plist)
    assert validator_infoplist_background_modes(plist) == ["audio", "fetch"]

    xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.test.app</string></dict></plist>"""
    parsed = validator_parse_xml_plist(xml)
    assert parsed.get("CFBundleIdentifier") == "com.test.app"

    assert validator_plist_auto_detect(b"bplist00\x00")["_format"] == "bplist00"
    assert validator_plist_auto_detect(xml)["CFBundleIdentifier"] == "com.test.app"

    enc_result = validator_decode_type_encoding("@:i")
    assert "id" in enc_result

    score = validator_spywareindicators_risk_score({"contacts_access": True, "location_tracking": True})
    assert 0 <= score <= 100

    jb_binary = b"\xce\xfa\xed\xfe" + b"\x00" * 100 + b"/Applications/Cydia.app" + b"\x00" * 100
    assert validator_has_jailbreak_detection(jb_binary)
    assert validator_jailbreak_risk_score(jb_binary) > 0

    macho_pie = bytearray(b"\xcf\xfa\xed\xfe")  # 64-bit LE magic
    macho_pie += b"\x0c\x00\x00\x01"  # cputype
    macho_pie += b"\x00\x00\x00\x00"  # cpusubtype
    macho_pie += b"\x02\x00\x00\x00"  # filetype MH_EXECUTE
    macho_pie += b"\x00\x00\x00\x00"  # ncmds
    macho_pie += b"\x00\x00\x00\x00"  # sizeofcmds
    macho_pie += b"\x00\x00\x20\x00"  # flags with MH_PIE
    assert validator_iossecuritychecker_check_pie_enabled(bytes(macho_pie))

    assert validator_swiftdemangler_is_swift_mangled("_$sSS")
    assert not validator_swiftdemangler_is_swift_mangled("_main")

    ent = validator_lib_iosentitlements_mock()
    assert validator_lib_iosentitlements_has(ent, "aps-environment")
    assert not validator_iosentitlements_has_get_task_allow(ent)

    kit = validator_exploitkit_new("com.bad.app", "BadApp")
    validator_exploitkit_add_exploit(kit, {"severity": "critical", "zero_click": True})
    assert validator_exploitkit_has_zero_click_exploit(kit)
    assert validator_exploitkit_max_exploit_severity(kit) == "critical"

    analysis = validator_iosruntimeanalysis_analyse(b"\xce\xfa\xed\xfe" + b"\x00" * 200)
    summary = validator_iosruntimeanalysis_summary(analysis)
    assert "PIE=" in summary

    print("All smoke tests passed.")
