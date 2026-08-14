#!/usr/bin/env python3
"""V3 final: open project FIRST, then exercise all tools in correct order."""
import json, subprocess
from collections import Counter

EXE = r"C:\Users\Fra\Desktop\RustRE\target\release\rustre-mcp.exe"
TARGET = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo-zyphora.exe"
PDB = r"C:\Users\Fra\Desktop\Zyphora\target\release\cargo_zyphora.pdb"
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mcp_outputs\R30v3_full.json"

p = subprocess.Popen([EXE, "--transport=stdio"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
def send(req):
    p.stdin.write((json.dumps(req)+"\n").encode())
    p.stdin.flush()
def recv():
    line = p.stdout.readline()
    if not line:
        raise RuntimeError("server died")
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {"error":{"message":f"bad-line: {line[:100]!r}"}}

send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"v3","version":"1"}}})
recv()
send({"jsonrpc":"2.0","method":"notifications/initialized"})

# Open project FIRST
send({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"project.open","arguments":{"path":TARGET}}})
op = recv()
op_data = json.loads(op["result"]["content"][0]["text"])
BINARY_ID = op_data["binary_id"]
PROJECT_ID = op_data["project_id"]
print(f"project.open: binary_id={BINARY_ID}, project_id={PROJECT_ID}")

# Get tools
send({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}})
tools = recv()["result"]["tools"]

# Open a debug session for debug.* tools
SESSION_ID = "dbg-0001"
try:
    send({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"debug.attach","arguments":{"pid":0,"binary_path":TARGET}}})
    r = recv()
    d = json.loads(r["result"]["content"][0]["text"])
    SESSION_ID = d.get("session_id", "dbg-0001")
except: pass

def make_input(name, schema):
    props = (schema or {}).get("properties", {}) or {}
    req = (schema or {}).get("required", []) or []
    args = {}
    for pname, spec in props.items():
        t = spec.get("type")
        if pname == "binary_id": args[pname] = BINARY_ID
        elif pname == "project_id": args[pname] = PROJECT_ID
        elif pname == "session_id": args[pname] = SESSION_ID
        elif pname in ("path","pe_path","binary_path","exe_path"): args[pname] = TARGET
        elif pname == "pdb_path": args[pname] = PDB
        elif pname in ("address","addr","va","start"):
            # For byte-slice tools, "start" is a byte index, not a virtual address
            if name in ("script_bytes_slice",):
                args[pname] = 0
            else:
                args[pname] = 5368771180
        elif pname == "end":
            # For byte-slice tools, "end" is a byte index (capped at a small buffer length)
            if name in ("script_bytes_slice",):
                args[pname] = 4
            else:
                args[pname] = 5368771260
        elif pname == "func_addr": args[pname] = 5368771180
        elif pname == "function_address": args[pname] = 5368771180
        elif pname in ("hex","bytes","data","key_hex","data_hex") and (name.startswith("hex_tplx_") or name.startswith("hex_tply_")):
            # Template tools need enough bytes to cover a full struct (MZ DOS header = 64 bytes)
            args[pname] = "4d5a" + "00" * 126  # MZ magic + 126 zero bytes = 128-byte buffer
        elif pname in ("hex","bytes","data","key_hex","data_hex") and (name.startswith("hex_pattern_") or name.startswith("kgdb_")):
            # These tools require `bytes` as a byte-array, not a hex string.
            args[pname] = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33]
        elif pname in ("hex","bytes","data","key_hex","data_hex"): args[pname] = "deadbeef001122334455667788990011"  # 16 bytes (32 hex chars) — UUID tools need ≥16 bytes
        elif pname == "bytes_hex": args[pname] = "4889c0"  # MOV RAX, RAX â€” a valid x86-64 NOP-equivalent
        elif pname == "buffer_hex": args[pname] = "deadbeef00112233"  # 8-byte buffer for write_typed_at_hex
        elif pname in ("mangled","symbol"): args[pname] = "_RNvNtCs6CKzx_3foo3bar4baz"
        elif pname == "name" and (name.startswith("hex_tplx_") or name.startswith("hex_tply_")):
            # Template tools need a valid builtin template name, not "main"
            args[pname] = "MZ"
        elif pname == "name":
            # Prefer first enum value when schema constrains name to an enum (e.g. agent_prompts_registry_render).
            _name_enum = spec.get("enum", [])
            args[pname] = _name_enum[0] if _name_enum else "main"
        elif pname == "count": args[pname] = 5
        elif pname == "bits": args[pname] = 64
        elif pname in ("size","length","len"):
            # Prefer first enum value when schema constrains to an enum (e.g. HwBpSize).
            _size_enum = spec.get("enum", [])
            args[pname] = _size_enum[0] if _size_enum else 16
        elif pname == "page_size": args[pname] = 4096  # must be a power of two and non-zero
        elif pname == "addrs": args[pname] = [0x1000, 0x2000, 0x3000]  # sample address list for bulk page tools
        elif pname == "offset": args[pname] = 0
        elif pname == "expression": args[pname] = "(x & y) + (x | y)"
        elif pname == "prologue": args[pname] = "55 48 89 E5"  # push rbp; mov rbp,rsp — valid x86-64 function prologue for SignaturePattern
        elif pname == "mask": args[pname] = "ffffffffffffffffffffffffffffffff"  # 16 0xFF bytes — same length as default data_hex/bytes 16-byte buffer
        elif pname == "json" and "pattern" in name:
            # hex_pattern_from_json expects a fully serde-serialised Pattern struct
            # Pattern fields: bytes, name, tags, captures, comment
            args[pname] = '{"bytes":[{"Exact":222},{"Exact":173},{"Exact":190},{"Exact":239}],"name":null,"tags":[],"captures":[],"comment":""}'
        elif pname == "pattern": args[pname] = "de ad be ef"  # space-separated hex pairs for BytePattern::parse
        elif pname == "pat": args[pname] = "de ad be ef"  # short alias used by hex_pattern_to_hex_string_v3 / to_masked_v3
        elif pname == "pattern_hex": args[pname] = "deadbeef"  # hex-encoded pattern for mem/hex search tools
        elif pname == "ch": args[pname] = "f"  # single STABS type-descriptor char for stabs_type_code_from_char
        elif pname in ("hi_hex", "lo_hex", "base_hex", "patch_hex"): args[pname] = "deadbeef00112233"  # mem composite/patched tools
        elif pname == "mask_hex": args[pname] = "ffffffff"  # mask for mem_search_bytes_with_mask_v5
        elif pname == "query": args[pname] = "SELECT * FROM functions LIMIT 5"
        elif pname == "type_str": args[pname] = "int"
        elif pname == "var_name": args[pname] = "x"
        elif pname == "direction": args[pname] = "backward"
        elif pname == "addresses":
            # Some tools want [{address: int}] objects; others want plain ints.
            items_schema = spec.get("items", {})
            if isinstance(items_schema, dict) and items_schema.get("type") == "object":
                args[pname] = [{"address": 5368771180}]
            else:
                args[pname] = [5368771180]
        elif pname in ("width", "ret_width"):
            # Some tools (symb_*) declare width as integer; others (decompiler_type) as string.
            if t in ("integer", "number"):
                args[pname] = 32
            else:
                args[pname] = "i32"
        elif pname == "new_size":
            # zero_extend new_size must be >= bits (default bits=64); use 128 to be safe
            if t in ("integer", "number"):
                args[pname] = 128
        elif pname == "algorithm":
            # Pick first enum value if available, else "djb2" (valid for iadl_compute_hash and similar tools)
            enum_vals = spec.get("enum", [])
            args[pname] = enum_vals[0] if enum_vals else "djb2"
        elif pname == "blocks":
            # Must be non-empty; send a single trivial block
            args[pname] = [{"id": 0, "successors": []}]
        elif pname == "type" and t == "object":
            # DecompType tree â€” provide a minimal valid int type
            args[pname] = {"kind": "int", "width": "i32"}
        elif pname in ("a","b"):
            # Use integer default when schema says integer, string width for string, else object
            if t in ("integer","number"):
                args[pname] = 8
            elif t == "string":
                # If the schema lists an enum, use the first valid value; otherwise fall back to "i32"
                enum_vals = spec.get("enum", [])
                args[pname] = enum_vals[0] if enum_vals else "i32"
            else:
                args[pname] = {"name":"x","bytes":"deadbeef"}
        elif pname in ("ptr","result","dst","src","lhs","rhs","var","alias") and t == "string":
            args[pname] = pname  # use param name as a sensible string placeholder
        elif pname == "yaml":
            # Provide a minimal valid protocol YAML for fuzz_net_protocol_* tools
            args[pname] = "initial_state: start\nstates:\n  - name: start\n    transitions:\n      - to: done\n        message: HELLO\n  - name: done\n"
        elif pname == "target" and name == "fuzz_net_protocol_drive_path":
            args[pname] = "done"
        elif pname == "old_hex": args[pname] = "4142434445464748"
        elif pname == "delta_hex":
            # Pre-computed valid RRDF delta: identity patch for old=b"ABCDEFGH" (8 bytes)
            args[pname] = ("525244460100080000000000000008000000000000009ac2197d9258257b1ae8463e4214e4cd0a578bc1"
                           "517f2415928b91be4283fc489ac2197d9258257b1ae8463e4214e4cd0a578bc1517f2415928b91be4283"
                           "fc48010000000100000000000000000800000000000000")
        elif pname == "rule": args[pname] = 'rule test { strings: $a = "test" condition: $a }'
        elif pname == "source" and name.startswith("yara_"):
            # YARA tools require a valid rule source; provide a minimal well-formed rule with meta fields.
            args[pname] = 'rule test { meta: author = "tester" date = "2024-01-01" description = "test rule" strings: $a = "test" condition: $a }'
        elif pname == "body" and name.startswith("yara_"):
            # parse_condition_section expects the text between { } that includes "condition: <expr>"
            args[pname] = "condition: true"
        elif pname == "arch" and t == "string":
            # Emulator/disasm arch parameter — "x86_64" is universally valid
            args[pname] = "x86_64"
        elif pname == "mode" and t == "string":
            # Unicorn emulator mode — X86_64 is the most common valid value
            args[pname] = "X86_64"
        elif pname == "os" and t == "string":
            # Qiling OS target — "linux" is the default
            args[pname] = "linux"
        elif pname == "insn" and t == "string":
            # Unicorn hook insn kind — SYSCALL is always valid
            args[pname] = "SYSCALL"
        elif pname == "kind" and t == "string" and name.startswith("emu_qiling_syscall"):
            # SyscallResult kind discriminant
            args[pname] = "ok"
        elif pname == "data_base64": args[pname] = "AQIDBA=="  # 4 non-empty bytes, valid for debug.write_memory
        elif pname == "target" and "unicorn" in name: args[pname] = "python"  # debug_unicorn_script_gen requires non-empty target
        elif pname == "bp_id": args[pname] = "bp-0001"
        elif pname == "v" and t in ("integer","number"):
            # Generic numeric discriminant; 1 is valid for 1-indexed enums (e.g. MispThreatLevelId 1..=4)
            args[pname] = 1
        elif pname == "response" and t == "string":
            # kgdb_parse_thread_list expects GDB RSP wire-format thread list, not JSON
            if "thread_list" in name or ("thread" in name.lower() and "kgdb" in name.lower()):
                args[pname] = "m1,2,3"
            else:
                # Provide a valid JSON-containing response for extract_json/parse_renames tools
                args[pname] = '{"sub_0": "init_globals", "sub_1": "parse_args"}'
        elif pname in req:
            # If the property has an enum, use the first valid value
            enum_vals = spec.get("enum", [])
            if enum_vals:
                args[pname] = enum_vals[0]
            elif t == "string":
                # Smart defaults by param name — many wrappers require specific enum-like strings
                # even though the JSON schema advertises plain "string".
                _n = pname.lower()
                if _n == "kind": args[pname] = "Call"
                elif _n == "edge_kind": args[pname] = "Fallthrough"
                elif _n == "level": args[pname] = "Info"
                elif _n == "variant": args[pname] = "M68000"
                elif _n == "mnemonic": args[pname] = "nop"
                elif _n == "arch": args[pname] = "x86_64"
                elif _n in ("value", "text", "input", "src", "content", "msg", "message"): args[pname] = "test"
                elif _n == "path": args[pname] = "test.bin"
                elif _n in ("bytes", "buffer_hex", "hex", "data_hex", "input_hex", "buffer"): args[pname] = "deadbeef00112233"
                elif _n == "fact": args[pname] = "Unknown"
                elif _n == "a" or _n == "b": args[pname] = "test"
                elif _n == "pattern": args[pname] = "de ad be ef"
                elif _n == "role": args[pname] = "assistant"
                elif _n == "name": args[pname] = "test"
                else: args[pname] = ""
            elif t in ("integer","number"):
                # Respect schema minimum (e.g. capacity:{minimum:1}) so tools that reject 0 don't panic.
                mn = spec.get("minimum")
                args[pname] = mn if isinstance(mn, (int, float)) else 0
            elif t == "boolean": args[pname] = False
            elif t == "array":
                # Non-empty defaults by param name — many wrappers reject empty arrays.
                _n = pname.lower()
                if _n in ("bytes", "data", "a", "b", "buffer", "input", "src", "needle"):
                    args[pname] = [0xde, 0xad, 0xbe, 0xef]
                else:
                    args[pname] = []
            elif t == "object": args[pname] = {}
    return args

# Per-tool argument overrides for protocol parsers that need specific byte sequences.
# Values are hex-encoded bytes of the minimum valid protocol header for each parser.
TOOL_ARG_OVERRIDES = {
    # Ethernet II: dst(6)+src(6)+ethertype(2)+2-byte payload = 16 bytes
    "net_parse_ethernet_v2": {"data": "ffffffffffff" + "aabbccddeeff" + "0800" + "0000"},
    # IPv4: ver=4,ihl=5,tos=0,len=20,id=0,flags=0,ttl=64,proto=6,cksum=0,src=127.0.0.1,dst=127.0.0.1
    "net_parse_ipv4_v2": {"data": "4500001400000000400600007f0000017f000001"},
    # IPv6: ver+tc+flow,plen=0,next=59(no-next-hdr),hop=64,src=::1,dst=::1 (40 bytes)
    "net_parse_ipv6_v2": {"data": "6000000000003b40" + "00" * 15 + "01" + "00" * 15 + "01"},
    # TCP: src_port=80,dst_port=80,seq=0,ack=0,data_offset=5+SYN,win=0,cksum=0,urg=0 (20 bytes)
    "net_parse_tcp_v2": {"data": "005000500000000000000000500200000000000000000000"},
    # ARP: htype=1,ptype=0x0800,hlen=6,plen=4,op=1(req),sha,spa,tha,tpa (28 bytes)
    "net_parse_arp_v2": {"data": "00010800060400010000000000000000000000000000000000000000"},
    # HTTP chunked: b"5\r\nhello\r\n0\r\n\r\n" (15 bytes)
    "net_decode_chunked_v2": {"data": "350d0a68656c6c6f0d0a300d0a0d0a"},
    # DieCondition must be a valid externally-tagged enum variant, not an empty object.
    # StringPresent("MZ") checks for a DOS magic string — works on any non-empty byte slice.
    "triage_die_match_condition_single": {"condition": {"StringPresent": "MZ"}, "hex": "4d5a"},

    # PE editor: provide the 200-byte minimal_pe64_stub bytes so each parser has enough data.
    # Stub layout: DOS header at 0 (64 bytes), PE sig at 64, COFF at 68, optional at 88.
    # Generated from rustre_pe_editor::PeParser::minimal_pe64_stub().
    "pe_editor_parse_dos_header": {"data_hex": "4d5a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000005045000064860000000000000000000000000000700022000b0200000000000000000000000000000000000000000000000000000000000000100000000200000000000000000000000000000000000000100000c8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000"},
    "pe_editor_parse_file_header": {"data_hex": "4d5a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000005045000064860000000000000000000000000000700022000b0200000000000000000000000000000000000000000000000000000000000000100000000200000000000000000000000000000000000000100000c8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000", "offset": 68},
    "pe_editor_parse_optional_header64": {"data_hex": "4d5a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000005045000064860000000000000000000000000000700022000b0200000000000000000000000000000000000000000000000000000000000000100000000200000000000000000000000000000000000000100000c8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000", "offset": 88},

    # adf chain tools require n > 0 (make_input defaults to 0 without a schema minimum).
    "adf_compute_dominators_chain": {"n": 3},
    "adf_postorder_chain": {"n": 3},

    # Hungarian assignment: non-empty 2x2 cost / similarity matrix.
    "diff_bindiff_hungarian_solve": {"cost_matrix": [[1.0, 0.0], [0.0, 1.0]]},
    "diff_bindiff_hungarian_from_similarity": {"similarity_matrix": [[1.0, 0.0], [0.0, 1.0]]},

    # Unicorn script gen: kind must be "hello", "trace", or "watchpoint".
    "debug_unicorn_script_gen": {"arch": "x86_64", "target": "python", "kind": "hello"},

    # kgdb u64 hex field must be exactly 16 hex chars (8 bytes little-endian).
    "kgdb_read_u64_le_hex": {"hex": "deadbeefcafebabe"},

    # decompiler type tools: 'bytes' is an integer (access size in bytes), not a hex string.
    "decompiler_type_recovery_from_access_size_wp": {"addr": 5368771180, "bytes": 4},
    "decompiler_type_access_width_sizer_wp": {"var": "x", "bytes": 4, "signed": False},

    # ByteMask specificity: mask and value are plain integers, not hex strings.
    "hex_pattern_byte_mask_specificity_v3": {"mask": 255, "value": 170},

    # mem_diff_span_len_v5: old_hex and new_hex must have the same byte length.
    "mem_diff_span_len_v5": {"start": 0, "old_hex": "4142434445464748", "new_hex": "4849504142434445"},

    # EMPTY_PATTERN: pat/pattern_hex fall through to "" in make_input; supply non-empty values.
    "hex_pattern_to_hex_string_v3": {"pat": "de ad be ef"},
    "hex_pattern_to_masked_v3": {"pat": "de ad be ef"},
    "mem_search_bytes_hex_v2": {"hex": "deadbeef00112233", "pattern_hex": "deadbeef"},
    "mem_find_bytes_provider_v5": {"addr": 0, "hex": "deadbeef00112233", "pattern_hex": "deadbeef"},

    # INVALID_JSON fixes: these tools expect JSON-serialised structs as string params.
    # Minimal valid PCode JSON array (empty).
    "ghidra_pcode_parser_parse_json": {"json": "[]"},

    # Minimal valid rules JSON array (empty list of net rules).
    "net_rules_import_rules_json": {"json": "[]"},

    # --- UNKNOWN_VARIANT / UNKNOWN_KIND fixes ---

    # XrefKind tools: "Call" is not a valid XrefKind; valid values are e.g. "CodeCall".
    "analysis_xref_kind_is_code": {"kind": "CodeCall"},
    "analysis_xref_kind_is_data": {"kind": "DataRead"},
    "analysis_xref_kind_is_import": {"kind": "ImportByName"},
    "analysis_xref_kind_classify": {"kind": "CodeCall"},

    # MacosStopReason kind: valid values are "breakpoint", "single_step", "exception", "exited", "signal".
    "debug_macos_stop_reason_address": {"kind": "breakpoint"},
    "debug_macos_stop_reason_is_exit": {"kind": "breakpoint"},

    # FaultKind: valid values include "bit_flip", "mem_read_replace", "mem_read_fault", etc.
    "debug_unicorn_fault_injector_fire_v2": {"address": 0x1000, "kind": "bit_flip", "param": 0, "probe": 0x1000},
    "debug_unicorn_fault_rule_should_fire_v2": {"address": 0x1000, "kind": "bit_flip", "param": 0, "probe": 0x1000},

    # MatchKind for bindiff: valid values are "ExactHash", "CfgHash", "CallGraphPropagation", etc.
    "diff_bindiff_match_kind_is_reliable": {"kind": "ExactHash"},
    "diff_bindiff_match_kind_priority": {"kind": "ExactHash"},
    "diff_bindiff_match_kind_display": {"kind": "ExactHash"},

    # fuzz_mutate_input: strategy must be one of the known MutationStrategy names.
    "fuzz_mutate_input": {"data_hex": "deadbeef001122334455667788990011", "strategy": "bit_flip"},

    # il_lift_level_at_least_pair_r7: a and b must be valid LiftLevel names (Raw/Llil/MlilSsa/Hlil).
    "il_lift_level_at_least_pair_r7": {"a": "Raw", "b": "Llil"},

    # m68k_variant_info: valid variant strings are "68000", "68010", "68020", "68030", "68040", "68060", "ColdFire".
    "m68k_variant_info": {"variant": "68000"},

    # mem typed read/write: kind must be a valid type tag like "u8", "u32_le", etc.
    "mem_read_typed_at_hex": {"buffer_hex": "deadbeef001122334455667788990011", "kind": "u32_le"},
    "mem_write_typed_at_hex": {"buffer_hex": "deadbeef001122334455667788990011", "kind": "u32_le", "value": 42},

    # pe_editor_header_field_debug: valid field names from HeaderField enum.
    "pe_editor_header_field_debug": {"field": "MajorLinkerVersion"},

    # script_error_is_recoverable: variant must be a valid ScriptError variant name.
    "script_error_is_recoverable": {"variant": "RuntimeError"},

    # symbols_symbol_source_priority: source must be a valid SymbolSource name (lowercase).
    "symbols_symbol_source_priority": {"source": "pdb"},

    # threatintel IoCType kind: valid values are "ip", "domain", "url", "email", "md5", "sha1", "sha256".
    "threatintel_x_ioc_new_network_flag": {"value": "1.2.3.4", "kind": "ip"},
    "threatintel_x_ioc_new_hash_flag": {"value": "deadbeef", "kind": "md5"},

    # threatintel_group_link_ioc: group must be a pre-populated group name in ThreatGroupTracker.
    "threatintel_group_link_ioc": {"group": "APT28", "ioc_id": 1},

    # threatintel IocType display tools: valid ioc_type/variant strings.
    "threatintel_ioc_type_display_w3": {"ioc_type": "md5"},
    "threatintel_ioc_type_display": {"variant": "md5"},
    "threatintel_ext_ioc_type_stix_pattern": {"ioc_type": "md5", "value": "deadbeef"},

    # trace_event_type_name_wt1: valid kind values are "instruction", "call", "return", etc.
    "trace_event_type_name_wt1": {"kind": "instruction"},

    # trace_navigate_access_kind_from_str_x: valid values are "read" or "write".
    "trace_navigate_access_kind_from_str_x": {"kind": "read"},

    # triage_die RuleCondition: must be a valid externally-tagged enum variant.
    "triage_die_match_rule_condition": {"rule": {"Any": [{"StringPresent": "MZ"}]}, "hex": "4d5a"},
    "triage_die_match_rule_condition_single": {"rule": {"Any": [{"StringPresent": "MZ"}]}, "hex": "4d5a"},

    # windbg_kdnet_packet_type_id: valid kind values are "breakpoint", "statechange", "debug", etc.
    "windbg_kdnet_packet_type_id": {"kind": "breakpoint"},

    # agent_llm_estimate_cost: model_id must be a known model in the builtin catalogue (e.g. "gpt-4o").
    "agent_llm_estimate_cost": {"model_id": "gpt-4o", "input_tokens": 100, "output_tokens": 50},

    # agent_llm_llm_model_display: valid variant names are Gpt4, Gpt35Turbo, Claude3Opus, etc.
    "agent_llm_llm_model_display": {"variant": "Gpt4"},

    # analysis_typerecov_*: "ty" is a serde-serialised RecoveredType; "Unknown" is the unit variant.
    "analysis_typerecov_display_name": {"ty": "Unknown"},
    "analysis_typerecov_is_pointer":   {"ty": "Unknown"},
    "analysis_typerecov_is_struct":    {"ty": "Unknown"},
    "analysis_typerecov_pointee":      {"ty": "Unknown"},

    # decompiler_expr_*: "expr"/"a"/"b" are serde-serialised Expr; {"Var":"x"} is the simplest variant.
    "decompiler_expr_simplify":         {"expr": {"Var": "x"}},
    "decompiler_expr_normalize":        {"expr": {"Var": "x"}},
    "decompiler_expr_print":            {"expr": {"Var": "x"}},
    "decompiler_expr_has_side_effects": {"expr": {"Var": "x"}},
    "decompiler_expr_safe_to_inline":   {"expr": {"Var": "x"}},
    "decompiler_expr_depth":            {"expr": {"Var": "x"}},
    "decompiler_expr_node_count":       {"expr": {"Var": "x"}},
    "decompiler_expr_referenced_vars":  {"expr": {"Var": "x"}},
    "decompiler_expr_equivalent":       {"a": {"Var": "x"}, "b": {"Var": "y"}},
    "decompiler_expr_similarity":       {"a": {"Var": "x"}, "b": {"Var": "y"}},
}

# DATA_TOO_SHORT fixes for binary-format tools that need minimum-size valid headers.

# LNK header (76 bytes): magic=0x4C LE, CLSID={00021401-0000-0000-C000-000000000046},
# flags=0, file_attrs=0, times=0, show_command=1 at offset 60, rest zeroed.
_LNK_HEX = (
    "4c0000000114020000000000c0000000000000460000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000001000000000000000000000000000000"
)

# Prefetch header (84 bytes): version=17 (V17), magic="SCCA", file_size=84, rest zeroed.
_PREFETCH_HEX = (
    "11000000"  # version = 17
    "53434341"  # magic = "SCCA"
    "00000000"  # unknown0
    "54000000"  # file_size = 84 (0x54)
    + "00" * 60  # exe_name (60 zero bytes)
    + "00000000"  # prefetch_hash
    + "00000000"  # unknown1
)

# PCAP global header (24 bytes): magic=d4c3b2a1 (LE), version=2.4, snaplen=0xffffffff, linktype=1.
# Both bytes and hex overridden: make_input generates bytes=16-byte default which args_to_bytes uses first.
_PCAP_HEX = "d4c3b2a1020004000000000000000000ffffffff01000000"

TOOL_ARG_OVERRIDES.update({
    # Forensics LNK tools need ≥76 bytes of valid LNK header (as hex string for 'data').
    "forensics_fs_lnk_analyzer_summary":  {"path": "test.lnk", "data": _LNK_HEX},
    "forensics_fs_lnk_file_target_path":  {"path": "test.lnk", "data": _LNK_HEX},
    # Forensics Prefetch tools need ≥84 bytes of valid Prefetch header.
    "forensics_fs_prefetch_analyzer_report":       {"path": "test.pf", "data": _PREFETCH_HEX},
    "forensics_fs_prefetch_pattern_matcher_risk":  {"path": "test.pf", "data": _PREFETCH_HEX},
    "forensics_fs_prefetch_file_loaded_modules":   {"path": "test.pf", "data": _PREFETCH_HEX},
    # Net PCAP tools need a valid 24-byte PCAP global header.
    "net_pcap_file_parse_info":    {"hex": _PCAP_HEX, "bytes": _PCAP_HEX},
    "net_pcap_split_by_count":     {"hex": _PCAP_HEX, "bytes": _PCAP_HEX, "max_packets": 1},
    "net_pcap_split_by_time":      {"hex": _PCAP_HEX, "bytes": _PCAP_HEX, "window_secs": 1},
})

# Minimal CoverageRun / CoverageData JSON strings shared across many trace tools.
_COV_RUN  = '{"name":"test","bb_hits":{},"edge_hits":{},"timestamp":0,"source_tag":""}'
_COV_DATA = '{"runs":[],"label":"test"}'

TOOL_ARG_OVERRIDES.update({
    # trace_cov.rs tools — 'records' / 'run' / 'data' params expect JSON strings.
    "trace_coverage_to_lcov_string_v2":           {"records": "[]"},
    "trace_coverage_lighthouse_from_run_v2":      {"run": _COV_RUN},
    "trace_coverage_heatmap_build_v2":            {"run": _COV_RUN},
    "trace_coverage_block_colors_v2":             {"run": _COV_RUN, "addrs": []},
    "trace_coverage_diff_compute_v2":             {"a": _COV_RUN, "b": _COV_RUN},
    "trace_coverage_merge_all_runs_v2":           {"data": _COV_DATA},
    "trace_coverage_html_report_v2":              {"run": _COV_RUN, "functions": "[]"},
    # wire_tools.rs trace coverage tools
    "trace_coverage_compute_function_stats_v2":   {"run_json": _COV_RUN, "functions_json": "[]"},
    "trace_coverage_to_custom_binary":            {"run_json": _COV_RUN},
    "trace_coverage_merge_runs":                  {"a_json": _COV_RUN, "b_json": _COV_RUN, "name": "merged"},
    "trace_coverage_run_hot_bbs":                 {"run": _COV_RUN},
    "trace_coverage_run_summary":                 {"run": _COV_RUN},
    "trace_coverage_run_visit_at":                {"run": _COV_RUN, "addr": 0},
    "trace_coverage_data_stats":                  {"data": _COV_DATA},
    "trace_coverage_heatmap_hottest":             {"run": _COV_RUN},
    "trace_coverage_lighthouse_roundtrip":        {"run": _COV_RUN},
})

# Minimal valid .NET metadata blob (BSJB signature + 3 empty streams: #Strings, #GUID, #Blob).
# Built using the same algorithm as rustre_dotnet_metadata::build_test_metadata_blob.
_DOTNET_META_HEX = (
    "42534a4201000100000000000c00000076342e302e333033313900000000030054000000170000002353"
    "7472696e6773000000006b0000000000000023475549440000006b0000000000000023426c6f62000000"
    "0048656c6c6f54797065004d794e616d65737061636500"
)
_DOTNET_OVERRIDES = {
    "dotnet_metadata_parse_direct_summary": {"data_hex": _DOTNET_META_HEX},
    "dotnet_metadata_type_full_names": {"data_hex": _DOTNET_META_HEX},
    "dotnet_metadata_all_method_names": {"data_hex": _DOTNET_META_HEX},
    "dotnet_metadata_find_type": {"data_hex": _DOTNET_META_HEX, "type_name": "HelloType"},
    "dotnet_metadata_table_summary": {"data_hex": _DOTNET_META_HEX},
    "dotnet_metadata_validate": {"data_hex": _DOTNET_META_HEX},
    "dotnet_metadata_assembly_manifest": {"data_hex": _DOTNET_META_HEX},
    "dotnet_metadata_all_module_names": {"data_hex": _DOTNET_META_HEX},
    "dotnet_metadata_exported_type_names": {"data_hex": _DOTNET_META_HEX},
    "dotnet_metadata_resource_names": {"data_hex": _DOTNET_META_HEX},
    "dotnet_metadata_file_names": {"data_hex": _DOTNET_META_HEX},
    "dotnet_metadata_has_entry_point": {"data_hex": _DOTNET_META_HEX},
    "dotnet_metadata_find_methods_by_name": {"data_hex": _DOTNET_META_HEX, "method_name": "Main"},
    "dotnet_metadata_method_index": {"data_hex": _DOTNET_META_HEX},
    "dotnet_metadata_methods_for_type": {"data_hex": _DOTNET_META_HEX, "type_index": 0},
    "dotnet_metadata_fields_for_type": {"data_hex": _DOTNET_META_HEX, "type_index": 0},
    "dotnet_metadata_type_is_abstract": {"data_hex": _DOTNET_META_HEX, "type_index": 0},
    "dotnet_metadata_type_is_sealed": {"data_hex": _DOTNET_META_HEX, "type_index": 0},
    # DATA_TOO_SHORT fixes: these tools use 'image_hex' (not 'data_hex') and need the meta blob.
    # empty-table metadata is sufficient for enumeration tools (returns empty lists -> OK)
    "dotnet_metadata_all_type_names_basic":  {"image_hex": _DOTNET_META_HEX},
    "dotnet_metadata_all_field_names":       {"image_hex": _DOTNET_META_HEX},
    "dotnet_metadata_assembly_ref_names":    {"image_hex": _DOTNET_META_HEX},
    # token-lookup tools need actual TypeDef/MethodDef rows — use rich metadata below
    # (overridden again after _DOTNET_RICH_META_HEX is defined)
    "dotnet_metadata_find_type_def_row":     {"image_hex": _DOTNET_META_HEX, "name": "HelloType"},
    "dotnet_metadata_get_type_view":         {"image_hex": _DOTNET_META_HEX, "token": 0x02000001},
    "dotnet_metadata_get_method_view":       {"image_hex": _DOTNET_META_HEX, "token": 0x06000001},
    "dotnet_metadata_resolve_token":         {"image_hex": _DOTNET_META_HEX, "token": 0},
    "dotnet_metadata_type_def_by_index":     {"image_hex": _DOTNET_META_HEX, "index": 1},
    "dotnet_metadata_method_def_by_index":   {"image_hex": _DOTNET_META_HEX, "index": 1},
    # DATA_TOO_SHORT fixes: blob-only parsers need specific blob_hex content (not empty string).
    # FIELD sig: 0x06 (FIELD) + 0x08 (I4)
    "dotnet_metadata_parse_field_sig_blob":     {"blob_hex": "0608"},
    # LocalVarSig: 0x07 (LOCAL_SIG) + 0x00 (0 locals)
    "dotnet_metadata_parse_local_var_sig":       {"blob_hex": "0700"},
    # MethodSig: 0x00 (Default CC) + 0x00 (0 params) + 0x01 (VOID return)
    "dotnet_metadata_parse_method_sig_blob":     {"blob_hex": "000001"},
    # TypeSig: 0x01 = VOID
    "dotnet_metadata_pretty_print_type_sig":     {"blob_hex": "01"},
    # ArrayShape: rank=1 + numSizes=0 + numLoBounds=0 (all compressed u32 = single byte each)
    "dotnet_metadata_parse_array_shape":         {"blob_hex": "010000"},
    # CustomAttribute: prolog=0x0001 + numNamed=0x0000
    "dotnet_metadata_parse_custom_attribute_blob": {"blob_hex": "01000000"},
    # CIL method body: tiny header (code_size=1, bits=0b00000110) + ret (0x2a)
    "dotnet_metadata_parse_method_body":         {"image_hex": "062a", "file_offset": 0},
    # parse_ca_typed: same prolog + no fixed arg types
    "dotnet_metadata_parse_ca_typed":            {"blob_hex": "01000000", "fixed_arg_types": []},
}
TOOL_ARG_OVERRIDES.update(_DOTNET_OVERRIDES)

# Minimal valid PE64 image: MZ + e_lfanew=0x40 + PE\0\0 + COFF(AMD64, 1 section) +
# OptHdr64(image_base=0x140000000) + section ".text"(VirtAddr=0x1000, RawOff=0x200).
# VA 0x140001000 falls in .text.  Built lazily with struct so the layout is always correct.
import struct as _struct
def _make_pe64():
    buf = bytearray(1024)
    buf[0:2] = b'MZ'
    _struct.pack_into('<I', buf, 0x3C, 0x40)          # e_lfanew
    buf[0x40:0x44] = b'PE\x00\x00'
    _struct.pack_into('<H', buf, 0x44, 0x8664)         # machine = AMD64
    _struct.pack_into('<H', buf, 0x46, 1)              # num_sections
    _struct.pack_into('<H', buf, 0x54, 0xF0)           # opt_header_size
    _struct.pack_into('<H', buf, 0x56, 0x0022)         # characteristics
    opt = 0x58
    _struct.pack_into('<H', buf, opt, 0x020B)          # PE64 magic
    _struct.pack_into('<Q', buf, opt+24, 0x140000000)  # image_base
    _struct.pack_into('<I', buf, opt+32, 0x1000)       # section_alignment
    _struct.pack_into('<I', buf, opt+36, 0x200)        # file_alignment
    _struct.pack_into('<I', buf, opt+56, 0x2000)       # size_of_image
    _struct.pack_into('<I', buf, opt+60, 0x400)        # size_of_headers
    sect = opt + 0xF0                                   # section table (0x148)
    buf[sect:sect+8] = b'.text\x00\x00\x00'
    _struct.pack_into('<I', buf, sect+8,  0x1000)      # virt_size
    _struct.pack_into('<I', buf, sect+12, 0x1000)      # virt_addr
    _struct.pack_into('<I', buf, sect+16, 0x200)       # raw_size
    _struct.pack_into('<I', buf, sect+20, 0x200)       # raw_ptr
    return buf.hex()
_MINIMAL_PE64_HEX = _make_pe64()

# Rich .NET metadata blob: TypeDef("MyNs.MyType") + MethodDef("MyMethod") tables.
# Enables token-lookup tools that fail when tables are empty.
# Generated with build_metadata() — see session notes.
_DOTNET_RICH_META_HEX = (
    "42534a4201000100000000000c00000076342e302e333033313900000000040060000000160000002353"
    "7472696e67730000000076000000000000002347554944000000760000000500000023426c6f62000000"
    "7b0000003c000000237e0000004d7954797065004d794e73004d794d6574686f640000030000010000"
    "000002000001440000000000000044000000000000000100000001000000010010000100080000000100"
    "010000200000000096000d0001000100"
)
TOOL_ARG_OVERRIDES.update({
    # Override token-lookup tools with metadata that has actual TypeDef(1) and MethodDef(1) rows.
    "dotnet_metadata_find_type_def_row":     {"image_hex": _DOTNET_RICH_META_HEX, "name": "MyType"},
    "dotnet_metadata_get_type_view":         {"image_hex": _DOTNET_RICH_META_HEX, "token": 0x02000001},
    "dotnet_metadata_get_method_view":       {"image_hex": _DOTNET_RICH_META_HEX, "token": 0x06000001},
    "dotnet_metadata_resolve_token":         {"image_hex": _DOTNET_RICH_META_HEX, "token": 0x02000001},
    "dotnet_metadata_type_def_by_index":     {"image_hex": _DOTNET_RICH_META_HEX, "index": 1},
    "dotnet_metadata_method_def_by_index":   {"image_hex": _DOTNET_RICH_META_HEX, "index": 1},
    # dotnet_edit_nop_fill_range: needs non-empty opcodes with valid start/end offsets.
    "dotnet_edit_nop_fill_range": {"opcodes": ["nop", "ret"], "start_offset": 0, "end_offset": 1},
    # patch_pe_va_to_file_offset: needs a valid PE64 image and a VA inside the .text section.
    "patch_pe_va_to_file_offset": {"image_hex": _MINIMAL_PE64_HEX, "va": 0x140001000},
    # script_value_len_builtin: 'value' must be a collection (list/map/str/bytes); use a list.
    "script_value_len_builtin": {"value": [1, 2, 3]},
    # trace_open_trace_file: ":memory:" opens an in-memory SQLite store (no real file needed).
    "trace_open_trace_file": {"path": ":memory:"},
})

# ---------------------------------------------------------------------------
# INVALID_FORMAT fixes: all validator-side — correct input values per tool.
# ---------------------------------------------------------------------------

import os as _os, tempfile as _tempfile, struct as _struct2

# --- Shared binary blobs ---

# DRcov text (UTF-8, hex-encoded) — used by all fuzz_cov drcov tools.
_DRCOV_TEXT = (
    "DRCOV VERSION: 2\n"
    "DRCOV FLAVOR: drcov\n"
    "Module Table: version 2, count 0\n"
    "BB Table: 0 bbs\n"
)
_DRCOV_HEX = _DRCOV_TEXT.encode("utf-8").hex()

# Minimal ELF64 relocatable: 64-byte ELF header + 64-byte null section header.
# Precomputed (128 bytes): e_shoff=64, e_shentsize=64, e_shnum=1, rest zeroed.
_ELF64_REL_HEX = "7f454c4602010100000000000000000001003e00010000000000000000000000000000000000000040000000000000000000000040003800000040000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

# Minimal Mach-O 64-bit object (32 bytes, magic + cputype + etc., ncmds=0).
_MACHO64_HEX = "cffaedfe07000001030000000100000000000000000000000000000000000000"

# Minimal PE (use existing _MINIMAL_PE64_HEX computed earlier in the file; also use data_hex).
# We re-use the pe_editor data_hex from above which is already in TOOL_ARG_OVERRIDES.

# ADB CNXN wire message (24 bytes): cmd=CNXN, arg0=version, arg1=maxdata, data_len=0, crc=0.
# magic = command(0x4e584e43) ^ 0xffffffff = 0xb1a7b1bc  → LE bytes: bc b1 a7 b1
_ADB_CNXN_HEX = "434e584e00000001000010000000000000000000bcb1a7b1"

# FLIRT .sig minimal header: IDASGN magic (6 bytes) + version 8 + padding to 41 bytes.
_FLIRT_SIG_HEX = "49444153474e08" + "00" * 34

# ELF64 relocatable with .symtab + .strtab + .shstrtab (372 bytes).
# Used by flirt_gen_elf_parse (needs a symtab to avoid "no symtab (elf64)" error).
def _make_elf64_with_symtab():
    import struct as _s
    shstrtab = b'\x00.symtab\x00.strtab\x00.shstrtab\x00'  # 27 bytes
    strtab   = b'\x00'                                       #  1 byte
    symtab_d = b'\x00' * 24                                  # 24 bytes (null entry)
    sh_off       = 0x40
    shstrtab_off = 0x140
    strtab_off   = shstrtab_off + len(shstrtab)
    symtab_off   = strtab_off   + len(strtab)
    total        = symtab_off   + len(symtab_d)
    buf = bytearray(total)
    buf[0:4] = b'\x7fELF'; buf[4]=2; buf[5]=1; buf[6]=1
    _s.pack_into('<H', buf, 16, 1); _s.pack_into('<H', buf, 18, 0x3e)
    _s.pack_into('<I', buf, 20, 1); _s.pack_into('<Q', buf, 40, sh_off)
    _s.pack_into('<H', buf, 52, 64); _s.pack_into('<H', buf, 54, 56)
    _s.pack_into('<H', buf, 58, 64); _s.pack_into('<H', buf, 60, 4); _s.pack_into('<H', buf, 62, 3)
    def _sh(idx, name, typ, off, sz, lnk, inf, align, esz):
        b = sh_off + idx*64
        _s.pack_into('<I', buf, b,    name); _s.pack_into('<I', buf, b+4,  typ)
        _s.pack_into('<Q', buf, b+24, off);  _s.pack_into('<Q', buf, b+32, sz)
        _s.pack_into('<I', buf, b+40, lnk);  _s.pack_into('<I', buf, b+44, inf)
        _s.pack_into('<Q', buf, b+48, align);_s.pack_into('<Q', buf, b+56, esz)
    _sh(1, 1,  2, symtab_off,   len(symtab_d), 2, 1, 8, 24)
    _sh(2, 9,  3, strtab_off,   len(strtab),   0, 0, 1, 0)
    _sh(3, 17, 3, shstrtab_off, len(shstrtab), 0, 0, 1, 0)
    buf[shstrtab_off:shstrtab_off+len(shstrtab)] = shstrtab
    buf[strtab_off:strtab_off+len(strtab)]       = strtab
    buf[symtab_off:symtab_off+len(symtab_d)]     = symtab_d
    return buf.hex()
_ELF64_WITH_SYMTAB_HEX = _make_elf64_with_symtab()

# dyld shared cache header v1 (256 bytes): 'dyld_v1   x86_64' + zeros.
_DYLD_MAGIC = b"dyld_v1   x86_64"
_DYLD_HEX = _DYLD_MAGIC.hex() + "00" * 240

# OLE2 compound file — minimal 512-byte sector-0 header.
def _make_ole2_header():
    buf = bytearray(512)
    buf[0:8] = bytes([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])
    _struct2.pack_into("<HH", buf, 8, 0x003e, 3)    # minor, major version
    _struct2.pack_into("<H", buf, 12, 0xfffe)        # byte order LE
    _struct2.pack_into("<HH", buf, 14, 9, 6)         # sector size 2^9, mini 2^6
    _struct2.pack_into("<I", buf, 44, 1)             # num_fat_sectors = 1
    _struct2.pack_into("<I", buf, 48, 1)             # first_dir_sector = 1
    _struct2.pack_into("<I", buf, 56, 4096)          # mini stream cutoff
    _struct2.pack_into("<I", buf, 60, 0xFFFFFFFE)    # first_mini_fat = FREESECT
    _struct2.pack_into("<I", buf, 68, 0xFFFFFFFE)    # first_difat = FREESECT
    _struct2.pack_into("<I", buf, 76, 0)             # DIFAT[0] = sector 0 is FAT
    for i in range(1, 109):
        _struct2.pack_into("<I", buf, 76 + i * 4, 0xFFFFFFFE)
    return buf.hex()
_OLE2_HEX = _make_ole2_header()

# Lua 5.1 header (12 bytes): ESC L u a version format endian int_size ptr_size instr_size num_size integral
_LUA_HEADER_HEX = "1b4c75615100010404040800"

# Wasm minimal module (8 bytes): magic + version 1.
_WASM_HEX = "0061736d01000000"

# Create temp files for tools that read from the filesystem.
def _write_temp(suffix, data_hex):
    fd, path = _tempfile.mkstemp(suffix=suffix)
    try:
        _os.write(fd, bytes.fromhex(data_hex))
    finally:
        _os.close(fd)
    return path

_TEMP_WASM = _write_temp(".wasm", _WASM_HEX)
_TEMP_ELF  = _write_temp(".o",    _ELF64_REL_HEX.replace("\n", ""))

# Prefetch and LNK temp files re-use the hex constants defined earlier in the script.
# (they are defined as _PREFETCH_HEX / _LNK_HEX strings above)
_TEMP_PF  = _write_temp(".pf",  _PREFETCH_HEX)
_TEMP_LNK = _write_temp(".lnk", _LNK_HEX)

# YARA minimal valid rule
_YARA_RULE = 'rule test { condition: true }'

# Minimal CodeView S_END symbol record: length=2, type=0x0006
_CV_SYMBOLS_HEX = "02000600"

TOOL_ARG_OVERRIDES.update({
    # --- ADB tools ---
    "adb_decode_message":  {"hex": _ADB_CNXN_HEX},
    "adb_filter_by_level": {"output": "I/MyTag(1234): hello\n", "min_level": "I"},
    "adb_msg_write":       {"command": 1, "data": {"hex": "deadbeef"}},
    "adb_msg_auth":        {"auth_type": 1, "data": {"hex": "deadbeef"}},
    "adb_log_level_display": {"line": "I/MyTag( 1234): hello world"},

    # --- Agent prompts ---
    "agent_prompts_registry_render": {
        "name": "explain_code",
        "vars": {"code": "nop", "language": "asm"},
    },

    # --- Analysis type ---
    "analysis_type_fact_join": {"a": "Unknown", "b": "Unknown"},

    # --- Arch JVM ---
    # bytes array takes priority over hex in args_to_bytes; override both.
    "arch_jvm_decode":    {"bytes": [0x03], "hex": "03"},   # iconst_0 (opcode 0x03)
    "arch_jvm_decode_at": {"bytes": [0x03], "hex": "03"},

    # --- Arch Wasm ---
    "arch_wasm_function_stats_from_bytes": {"hex": _WASM_HEX},

    # --- CodeView ---
    # make_input sets 'bytes' as a hex string; args_to_bytes reads 'bytes' before 'hex',
    # so we must null it out to ensure the 'hex' override is used.
    "codeview_parse_symbols":      {"hex": _CV_SYMBOLS_HEX, "bytes": None},
    "codeview_parse_type_records": {"hex": _CV_SYMBOLS_HEX, "bytes": None},
    "codeview_symbol_filter_count": {"hex": _CV_SYMBOLS_HEX, "bytes": None, "kind": "S_END"},

    # --- Debug Unicorn ---
    "debug_unicorn_watchpoint_probe":          {"address": 0x1000, "size": 4, "kind": "read"},
    "debug_unicorn_hook_record_describe":       {"hook_type": "code"},
    "debug_unicorn_coverage_granularity_align": {"granularity": "instruction", "addr": 0x1000},
    "debug_unicorn_fault_rule_should_fire":     {"address": 0x1000, "kind": "bit_flip", "probe_addr": 0x1000},
    "debug_unicorn_v2_config_presets":          {"preset": "x86_64"},
    "debug_unicorn_coverage_granularity_align_v2": {"granularity": "instruction", "addr": 0x1000},
    "debug_unicorn_region_perms_flags_v2":      {"preset": "rwx"},
    "debug_unicorn_watch_kind_matches_v2":      {
        "addr": 0x1000, "size": 4, "kind": "read",
        "probe_addr": 0x1000, "probe_kind": "read",
    },

    # --- Deobf ---
    "deobf_string_hex_decode":            {"text": "deadbeef"},
    "deobf_string_rc4_inverse_ksa_v3":    {"s_final": list(range(256))},
    # Tool uses input_hex (hex of base64-encoded bytes), not 'data'.
    # "41414141" = hex of "AAAA" which is valid base64 with the standard alphabet.
    "deobf_string_decode_base64_custom_v3": {
        "input_hex": "41414141",
        "alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    },

    # --- Diff ---
    "diff_bindiff_hungarian_dims": {"cost_matrix": [[1.0, 0.0], [0.0, 1.0]]},

    # --- Emu Qiling ---
    "emu_qiling_syscall_ctx_args": {"nr": 1, "args": [0, 0, 0, 0, 0, 0]},

    # --- Events ---
    "events_kind_subscription": {"kind": "View"},

    # --- FLIRT ---
    # make_input sets 'bytes' as a hex string; null it so 'hex' override takes effect.
    "flirt_parse_sig_header": {"hex": _FLIRT_SIG_HEX, "bytes": None},
    # _TEMP_ELF has no symtab; use an ELF with .symtab + .strtab.
    "flirt_gen_elf_parse":    {"path": _write_temp(".o", _ELF64_WITH_SYMTAB_HEX)},

    # --- Forensics (path-based) ---
    "forensics_fs_prefetch_parse":   {"path": _TEMP_PF},
    "forensics_fs_prefetch_summary": {"path": _TEMP_PF},
    "forensics_fs_lnk_parse":        {"path": _TEMP_LNK},

    # --- Fuzz cov drcov (data_hex = hex-encoded UTF-8 text) ---
    "fuzz_cov_drcov_parse":            {"data_hex": _DRCOV_HEX},
    "fuzz_cov_drcov_header_parse":     {"data_hex": _DRCOV_HEX},
    "fuzz_cov_drcov_blocks_per_module": {"data_hex": _DRCOV_HEX, "module": ""},

    # --- Fuzz cov sets (arrays of u64) ---
    "fuzz_cov_diff_jaccard":      {"a": [0x1000, 0x2000], "b": [0x1000, 0x3000]},
    "fuzz_cov_coverage_run_merge": {"a": [0x1000, 0x2000], "b": [0x1000, 0x3000]},

    # --- Hex pattern ---
    "hex_pattern_import_ida_pat":        {"text": "---\n"},
    "hex_pattern_masked_new":            {"bytes": [0xde, 0xad, 0xbe, 0xef], "mask": [0xff, 0xff, 0xff, 0xff]},
    "hex_pattern_masked_matches_at":     {"bytes": [0xde, 0xad, 0xbe, 0xef], "mask": [0xff, 0xff, 0xff, 0xff],
                                          "data_hex": "deadbeef", "offset": 0},
    # v4 tools: data_hex must be a string, not array
    "hex_pattern_regex_search_v4":       {"pat": "de ad be ef", "data_hex": "deadbeef"},
    "hex_pattern_group_compile_v4":      {"patterns": ["de ad be ef"], "data_hex": "deadbeef"},
    "hex_pattern_group_any_matches_v4":  {"patterns": ["de ad be ef"], "data_hex": "deadbeef"},
    "hex_pattern_signature_matches_v4":  {"pat": "de ad be ef", "data_hex": "deadbeef"},
    # v3 EMPTY_PATTERN (already in base dict but repeated here for clarity — update is idempotent)
    "hex_pattern_to_hex_string_v3":      {"pat": "de ad be ef"},
    "hex_pattern_to_masked_v3":          {"pat": "de ad be ef"},

    # --- Loader ---
    # loader_lua_read_string: bytes=size_t(4)+string; "00000000" = length 0 (null string, valid).
    # Must override both 'bytes' AND 'hex' because args_to_bytes checks 'bytes' first.
    "loader_lua_read_string":    {"bytes": "00000000", "hex": "00000000", "size_t_size": 4},
    "loader_ole_list_streams":   {"bytes": _OLE2_HEX, "hex": _OLE2_HEX},
    "loader_wasm_parse":         {"path": _TEMP_WASM},
    "loader_wasm_stats":         {"path": _TEMP_WASM},
    "loader_elf_info_summary":   {"bytes": _ELF64_REL_HEX.replace("\n", ""), "hex": _ELF64_REL_HEX.replace("\n", "")},
    "loader_macho_parse_summary": {"bytes": _MACHO64_HEX, "hex": _MACHO64_HEX},
    "loader_elf_parse_info":     {"bytes": _ELF64_REL_HEX.replace("\n", ""), "hex": _ELF64_REL_HEX.replace("\n", "")},
    "loader_elf_plt_entries":    {"bytes": _ELF64_REL_HEX.replace("\n", ""), "hex": _ELF64_REL_HEX.replace("\n", "")},
    "loader_macho_parse":        {"bytes": _MACHO64_HEX, "hex": _MACHO64_HEX},
    "loader_pe_parse_info":      {"bytes": _MINIMAL_PE64_HEX, "hex": _MINIMAL_PE64_HEX},
    "loader_pe_imports_from_dll": {"bytes": _MINIMAL_PE64_HEX, "hex": _MINIMAL_PE64_HEX, "dll_name": "kernel32.dll"},

    # --- Lua header ---
    # Must override both 'bytes' AND 'hex': args_to_bytes checks 'bytes' first.
    "lua_loader_lua_header_is_official_format_wx1": {"bytes": _LUA_HEADER_HEX, "hex": _LUA_HEADER_HEX},

    # --- Mem ---
    "mem_perms_from_rwx":             {"s": "rwx"},
    "mem_search_bytes_range_hex":     {"buffer_hex": "deadbeef001122334455", "pattern_hex": "deadbeef"},
    "mem_shannon_entropy_max_block_wire":  {"hex": "deadbeef001122334455", "block_size": 4},
    "mem_shannon_entropy_min_block_wire":  {"hex": "deadbeef001122334455", "block_size": 4},
    "mem_shannon_entropy_mean_block_wire": {"hex": "deadbeef001122334455", "block_size": 4},
    "mem_perms_from_rwx_v5":          {"rwx": "rwx"},
    "mem_search_bytes_with_mask_v5":  {
        "addr": 0, "hex": "deadbeef001122334455", "pattern_hex": "dead", "mask_hex": "ffff"
    },
    "mem_composite_first_wins_v5": {"addr": 0, "hi_hex": "deadbeef", "lo_hex": "12345678"},
    # patch_hex must be non-empty and <= base_hex length; both 4 bytes here.
    "mem_patched_read_v5":         {"addr": 0, "base_hex": "deadbeef", "patch_hex": "deadbeef"},
    # re-affirm v2/v5 pattern fixes from base dict
    "mem_search_bytes_hex_v2":    {"hex": "deadbeef00112233", "pattern_hex": "deadbeef"},
    "mem_find_bytes_provider_v5": {"addr": 0, "hex": "deadbeef00112233", "pattern_hex": "deadbeef"},

    # --- Mobile apktool ---
    # Tool uses 'apk' + 'out' parameters (not 'path'). Lib validates .apk extension then
    # returns a mock result without invoking real apktool.
    "mobile_apktool_apk_decode_smali_count": {"apk": "dummy_test.apk", "out": "out"},
    "mobile_apktool_impl_build":             {"dir": "C:\\Windows\\Temp"},

    # --- Mobile dyld ---
    "mobile_dyld_header_parse":      {"hex": _DYLD_HEX},
    "mobile_dyld_parse_dyld_magic":  {"data_hex": _DYLD_HEX},
    "mobile_dyld_format_uuid":       {"uuid": list(range(16))},
    "mobile_dyld_header_uuid_string": {"uuid": list(range(16))},

    # --- Net ---
    "net_parse_ipv6_full":   {"hex": "6000000000003b40" + "00" * 15 + "01" + "00" * 15 + "01"},
    "net_is_multicast_addr_v2": {"addr": "224.0.0.1"},
    "net_proxy_http_request_line_parse":     {"line": "GET / HTTP/1.1"},
    "net_proxy_http_request_line_is_http11": {"line": "GET / HTTP/1.1"},
    "net_proxy_http_request_line_is_http2":  {"line": "GET / HTTP/2"},
    "net_proxy_http_status_line_parse":       {"line": "HTTP/1.1 200 OK"},
    "net_proxy_http_status_line_is_success":  {"line": "HTTP/1.1 200 OK"},
    "net_proxy_http_status_line_is_redirect": {"line": "HTTP/1.1 301 Moved"},
    "net_proxy_http_status_line_is_client_error": {"line": "HTTP/1.1 404 Not Found"},
    "net_proxy_http_status_line_is_server_error": {"line": "HTTP/1.1 500 Internal Server Error"},
    "net_rules_ip_spec_matches":   {"spec": "192.168.0.0/24", "addr": "192.168.0.1"},
    "net_rules_port_spec_matches": {"spec": "80", "port": 80},

    # --- Plugin Lua ---
    "plugin_lua_load_inline": {"source": "return {name='test', version='1.0'}"},

    # --- Sandbox report ---
    "sandbox_report_severity_parse":    {"severity": "high"},
    "sandbox_report_severity_score":    {"severity": "high"},
    "sandbox_report_format_extension":  {"format": "json"},

    # --- Script bytes slice ---
    "script_bytes_slice": {"bytes_hex": "deadbeef", "start": 0, "end": 2},

    # --- Stabs ---
    "stabs_type_code_from_char": {"ch": "f"},

    # --- Trace navigate ---
    "trace_navigate_access_kind_display": {"kind": "read"},

    # --- Trace PT --- (no override needed: tool works fine without bytes_hex)

    # --- TTD ---
    "ttd_trace_position_from_u128": {"value": "0"},
    "ttd_replay_memory_state_apply_write": {
        "address": 0x1000, "data_hex": {"hex": "deadbeef"}
    },
    "ttd_replay_delta_compressor_roundtrip": {
        "before_hex": {"hex": "deadbeef"}, "after_hex": {"hex": "deadbeef"}
    },
    "ttd_replayer_query_execute_tick": {"query": "max_tick"},

    # --- VmLift ---
    # bytes array takes priority over hex in args_to_bytes; override both.
    # 0x07 = Halt opcode in the default VmLifter ISA (0 operand bytes).
    "vmlift_lift_to_pseudo_il": {"bytes": [0x07], "hex": "07"},

    # --- YARA ---
    "yara_engine_parse_rule": {"text": _YARA_RULE},
})

# ---------------------------------------------------------------------------
# MISSING_PARAM fixes: make_input() systematic gaps.
# All fixes are validator-side only; no Rust changes needed.
# ---------------------------------------------------------------------------
_MISSING_PARAM_OVERRIDES = {
    "analysis_type_fact_byte_size":    {"fact": "Unknown"},
    "analysis_type_fact_is_known":     {"fact": "Unknown"},
    "analysis_type_fact_display_name": {"fact": "Unknown"},
    "analysis_type_fact_display":      {"fact": "Unknown"},
    "analysis_type_environment_merge": {
        "a": {"types": {}, "arg_types": [], "return_type": "Unknown"},
        "b": {"types": {}, "arg_types": [], "return_type": "Unknown"},
    },
    "analysis_type_infer_signature": {
        "env": {"types": {}, "arg_types": [], "return_type": "Unknown"},
    },
    "arch68k_size_bytes":  {"size": "B"},
    "arch68k_size_suffix": {"size": "B"},
    "debug_macos_vm_region_contains": {"address": 0x1000, "size": 0x1000, "query": 0x1000},
    "debug_macos_macho_section_contains": {
        "segment": "__TEXT", "section": "__text",
        "addr": 0x1000, "size": 0x1000, "query": 0x1000,
    },
    # functions must be a list of integer addresses (tool calls .as_u64() on each element).
    "diff_bindiff_binary_snapshot_call_graph": {
        "functions": [0x140001000],
        "calls": [],
        "query": 0x140001000,
    },
    "diff_simple_hash": {"data": [0xde, 0xad, 0xbe, 0xef]},
    "diff_lcs_similarity":            {"a": [0xde, 0xad, 0xbe, 0xef], "b": [0xde, 0xad, 0xbe, 0xef]},
    "diff_byte_histogram_similarity": {"a": [0xde, 0xad, 0xbe, 0xef], "b": [0xde, 0xad, 0xbe, 0xef]},
    "diff_ngram_jaccard_similarity":  {"a": [0xde, 0xad, 0xbe, 0xef], "b": [0xde, 0xad, 0xbe, 0xef]},
    "diff_combined_byte_similarity":  {"a": [0xde, 0xad, 0xbe, 0xef], "b": [0xde, 0xad, 0xbe, 0xef]},
    "diff_semantic_matcher_similarity":        {"hex_a": "deadbeef", "hex_b": "deadbeef"},
    "diff_semantic_matcher_are_equivalent":    {"hex_a": "deadbeef", "hex_b": "deadbeef"},
    "diff_semantic_differ_diff_function_pair": {"hex_a": "deadbeef", "hex_b": "deadbeef"},
    "fuzz_cov_drcov_header_parse_v2": {
        "text": (
            "DRCOV VERSION: 2\n"
            "DRCOV FLAVOR: drcov\n"
            "Module Table: version 2, count 1\n"
            "Columns: id, base, end, entry, checksum, timestamp, path\n"
            " 0, 0x0000000000001000, 0x0000000000002000, "
            "0x0000000000001000, 0x00000000, 0x00000000, /test/mod\n"
            "BB Table: 0 bbs\n"
        )
    },
    "fuzz_san_stack_edit_distance": {"a": ["func1", "func2"], "b": ["func1"]},
    "hex_pattern_nfa_find_all_v3":         {"pat": "de ad be ef", "data_hex": "deadbeef"},
    "hex_pattern_nfa_find_first_v3":       {"pat": "de ad be ef", "data_hex": "deadbeef"},
    "hex_pattern_dfa_search_v3":           {"pat": "de ad be ef", "data_hex": "deadbeef"},
    "hex_pattern_multi_matcher_search_v3": {"patterns": ["de ad be ef"], "data_hex": "deadbeef"},
    "hex_pattern_sequence_search_v3":      {"entries": [{"offset": 0, "pattern": "de ad be ef"}], "data_hex": "deadbeef"},
    "kgdb_hex_to_bytes":       {"hex": "deadbeef"},
    "kgdb_hex_to_bytes_v2":    {"hex": "deadbeef"},
    "kgdb_hex_le_to_u64":      {"hex": "deadbeef00000000"},
    "kgdb_decode_hex_buf":     {"hex": "deadbeef"},
    "kgdb_rle_encode":         {"data": "hello"},
    "kgdb_rle_decode":         {"data": "hello"},
    "kgdb_rsp_checksum":       {"data": "hello"},
    "kgdb_gdb_packet_to_wire": {"data": "OK"},
    "kgdb_gdb_packet_parse":   {"wire": "$OK#9a"},
    # YaraRuleSet requires created_at (u64 Unix timestamp) — no serde(default).
    "malpedia_check_ruleset_quality": {
        "ruleset": {"name": "test", "rules": [], "tags": [], "created_at": 0, "scan_count": 0}
    },
    "net_is_private_addr": {"addr": "192.168.1.1"},
    "net_proxy_rate_limiter_check": {
        "bytes_per_sec": 1000, "max_connections": 10, "now_ms": 0, "bytes": 100
    },
    "rlib_dec_symbol_map_from_flirt_pairs": {"pairs": []},
    "rlib_dec_typeprop_set_get":            {"var": "x", "ty": "int"},
    "rlib_dec_cfs_detect_loop":             {"lines": ["for (int i=0;i<10;i++) {", "  x++;", "}"]},
    "rlib_dec2_symbol_map_extend_pairs": {"pairs": [{"addr": 0x1000, "name": "main"}]},
    "rlib_dec2_name_recovery_pass":      {"addr": 0x1000, "name": "main"},
    "rlib_dec2_diagnostic_from_pass":    {"msg": "test error"},
    "rustre_symbols_ext_cross_ref_index_ops": {
        "edges": [[0x1000, 0x2000]], "query": 0x2000
    },
    "script_bytes_concat": {"a": [0xde, 0xad], "b": [0xbe, 0xef]},
    "script_bytes_find":   {"haystack": [0xde, 0xad, 0xbe, 0xef], "needle": [0xde, 0xad]},
    "script_lua_template_patch_pattern": {"from": [0xde, 0xad], "to": [0xbe, 0xef]},
    "script_python_pure_value_classify":   {"value": 42},
    "script_python_pyvalue_is_truthy":     {"value": 42},
    "script_python_pyvalue_len":           {"value": [1, 2, 3]},
    "script_python_pyvalue_as_int":        {"value": 42},
    "script_python_pyscriptvalue_display": {"value": "hello"},
    "symbols_stabs_record_parse_all_be": {"stab_hex": "000000000000000000000000"},
    "symbols_stabs_provider_from_bytes": {"stab_hex": "000000000000000000000000"},
    "symbols_stabs_parse_all":           {"stab_hex": "000000000000000000000000"},
    "symbols_discover_pdb_for_binary":   {"binary_path": TARGET},
    "trace_coverage_afl_new_edges_v2":     {"a": [0] * 8, "b": [1, 0, 0, 0, 0, 0, 0, 0]},
    "trace_coverage_afl_bitmap_count":     {"bytes": [0, 1, 2, 3]},
    "trace_coverage_afl_new_coverage":     {"a": [0] * 8, "b": [1, 0, 0, 0, 0, 0, 0, 0]},
    "trace_coverage_parse_custom_binary":  {"bytes": [0] * 16},
    "trace_coverage_afl_jaccard":          {"a": [0] * 8, "b": [1, 0, 0, 0, 0, 0, 0, 0]},
    "trace_coverage_covbitmap_ops":        {"a": [0xde, 0xad, 0xbe, 0xef], "b": [0xde, 0xad, 0xbe, 0xef]},
    "trace_coverage_diff_overlap_pct":     {"a": [0x1000, 0x2000], "b": [0x1000, 0x3000]},
    "trace_coverage_covbitmap_clear_bits": {"bytes": [0, 0, 0, 0, 1, 1, 0, 0]},
    "trace_navigate_insn_entry_v2": {
        "idx": 0, "pc": 5368771180, "tid": 1, "disasm": "nop"
    },
    "trace_navigate_call_entry": {
        "idx": 0, "pc": 5368771180, "tid": 1,
        "target": 5368771180, "ret_addr": 5368771192,
    },
    "trace_navigate_ret_entry": {
        "idx": 0, "pc": 5368771180, "tid": 1, "target": 5368771180
    },
    "trace_navigate_stackframe_display_name": {"fn_addr": 5368771180},
    "trace_navigate_bookmark_with_note": {
        "name": "my_bookmark", "idx": 0, "pc": 5368771180, "note": "test"
    },
    "trace_navigate_step_window":      {"cap": 10, "moves": []},
    "trace_navigate_idx_for_tsc":      {"entries": [{"pc": 0x1000, "tsc": 100}], "tsc": 100},
    "trace_navigate_mem_access_index": {"writes": [], "reads": []},
}
TOOL_ARG_OVERRIDES.update(_MISSING_PARAM_OVERRIDES)

# ---------------------------------------------------------------------------
# Round-5 overrides: WASM tools, demangle tools, diff.compare
# ---------------------------------------------------------------------------

# Valid minimal WASM module: magic + version + type section with one functype (i32)->i32
_WASM_MODULE_HEX = "0061736d0100000001050160017f017f"
# Individual WASM encodings for single-structure parsers
_WASM_LIMITS_HEX   = "0000"        # min-only limits, min=0 (LEB128)
_WASM_FUNCTYPE_HEX = "60017f017f"  # functype marker + 1 param i32 + 1 result i32
_WASM_MEMORY_HEX   = "0000"        # MemoryType = limits{min=0}
_WASM_TABLE_HEX    = "700000"      # TableType  = funcref (0x70) + limits{min=0}
_WASM_GLOBAL_HEX   = "7f00"        # GlobalType = i32 (0x7f) + immutable (0x00)
_WASM_INSN_HEX     = "0b"          # Wasm "end" instruction — valid single opcode
# FC/FD/FE bytes: these decode functions expect bytes[0] = prefix byte, bytes[1..] = sub-opcode + operands
# FC sub=0 = i32.trunc_sat_f32_s (no memarg), FD sub=0 = v128.load (memarg), FE sub=0 = memory.atomic.notify (memarg)
_WASM_FC_HEX = "fc000000"   # FC prefix + sub=0 (i32.trunc_sat_f32_s, no operands) + padding
_WASM_FD_HEX = "fd000000"   # FD prefix + sub=0 (v128.load) + align=0 + offset=0
_WASM_FE_HEX = "fe000200"   # FE prefix + sub=0 (memory.atomic.notify) + align=2 + offset=0

TOOL_ARG_OVERRIDES.update({
    # --- WASM binary parsers ---
    "arch_wasm_module_header_parse":  {"hex": "0061736d01000000"},
    "arch_wasm_functype_decode":      {"hex": _WASM_FUNCTYPE_HEX},
    "arch_wasm_limits_decode":        {"hex": _WASM_LIMITS_HEX},
    "arch_wasm_disassemble":          {"hex": _WASM_INSN_HEX},
    "arch_wasm_memory_type_decode":   {"hex": _WASM_MEMORY_HEX},
    "arch_wasm_table_type_decode":    {"hex": _WASM_TABLE_HEX},
    "arch_wasm_global_type_decode":   {"hex": _WASM_GLOBAL_HEX},
    "arch_wasm_function_stats":       {"hex": _WASM_INSN_HEX},
    "arch_wasm_decode_fc_prefix":     {"hex": _WASM_FC_HEX},
    "arch_wasm_decode_fd_prefix":     {"hex": _WASM_FD_HEX},
    "arch_wasm_decode_fe_prefix":     {"hex": _WASM_FE_HEX},
    "arch_wasm_decode_func_type":     {"bytes_hex": _WASM_FUNCTYPE_HEX},
    "arch_wasm_functype_arity":       {"bytes_hex": _WASM_FUNCTYPE_HEX},

    # --- Demangle tools: use symbol strings that each demangler can actually handle ---
    # Rust v0 new-style mangled name: _RNvCs<hash>_<crate><path>
    "demangle_rust_v0_wire":     {"symbol": "_RNvCs4doaA3_3foo3bar"},
    # Rust legacy mangled name (Itanium-style _ZN...hXXXE suffix)
    "demangle_rust_legacy_wire": {"symbol": "_ZN4core3fmt5write17hb52bd1a25d234addE"},
    # Rust auto-detect: use a well-known Rust v0 symbol
    "demangle_rust_auto_wire":   {"symbol": "_RNvNtCs6CKzx_3foo3bar4baz"},
    # C++ Itanium ABI: constructor of class foo
    "demangle_cpp_itanium_wire": {"symbol": "_ZN3fooC1Ev"},
    # MSVC C++ mangled name: int __cdecl foo(void)
    "demangle_cpp_msvc_wire":    {"symbol": "?foo@@YAHXZ"},
    # C++ auto-detect: prefer Itanium
    "demangle_cpp_auto_wire":    {"symbol": "_ZN3fooC1Ev"},
})

# diff.compare uses a_id / b_id pointing to already-loaded binaries.
# BINARY_ID is set at script start after project.open; apply the override here
# so it picks up the runtime value.
TOOL_ARG_OVERRIDES["diff.compare"] = {"a_id": BINARY_ID, "b_id": BINARY_ID}

# Also update the output path to R5_full.json as required by the task
OUT = r"C:\Users\Fra\Desktop\RustRE\validation\mcp_outputs\R5_full.json"

results = []
rid = 100
# Process in defined order: project tools first (already done), then everything else
non_project_tools = [t for t in tools if not t["name"].startswith("project.")]
results.append({"tool":"project.open","status":"OK","output_excerpt":op["result"]["content"][0]["text"][:300]})

for tool in non_project_tools:
    name = tool["name"]
    schema = tool.get("inputSchema", {})
    args = make_input(name, schema)
    # Apply per-tool overrides for protocol parsers that need specific inputs
    if name in TOOL_ARG_OVERRIDES:
        args.update(TOOL_ARG_OVERRIDES[name])
    rid += 1
    send({"jsonrpc":"2.0","id":rid,"method":"tools/call","params":{"name":name,"arguments":args}})
    try:
        resp = recv()
    except RuntimeError as e:
        import sys
        print(f"\n!!! SERVER DIED calling tool: {name}\n    input: {str(args)[:400]}", file=sys.stderr)
        sys.stderr.flush()
        raise
    if "error" in resp:
        status, excerpt = "JSONRPC_ERROR", str(resp["error"])[:300]
    else:
        is_err = resp.get("result",{}).get("isError", False)
        content = resp.get("result",{}).get("content",[])
        txt = content[0].get("text","") if content else ""
        if is_err:
            status = "TOOL_ERROR"
            excerpt = txt[:300]
        elif not txt or txt == "{}":
            status = "EMPTY"
            excerpt = ""
        else:
            try:
                parsed = json.loads(txt)
                # A stub is a wrapper that returns {"stub": true} without doing real work.
                # Tools whose NAME contains "stub" or "generate_stub" (e.g. plugin_python_generate_stub)
                # legitimately produce a "stub" field in their output — that's their job, not a placeholder.
                is_real_stub = (
                    isinstance(parsed, dict)
                    and parsed.get("stub")
                    and "stub" not in name.lower()
                )
                status = "STUB" if is_real_stub else "OK"
            except:
                status = "OK_TEXT"
            excerpt = txt[:300]
    results.append({"tool":name,"status":status,"input":args,"output_excerpt":excerpt})

# project.close and list at end
for closing in [t for t in tools if t["name"].startswith("project.") and t["name"] != "project.open"]:
    name = closing["name"]
    schema = closing.get("inputSchema", {})
    args = make_input(name, schema)
    rid += 1
    send({"jsonrpc":"2.0","id":rid,"method":"tools/call","params":{"name":name,"arguments":args}})
    resp = recv()
    is_err = resp.get("result",{}).get("isError", False)
    content = resp.get("result",{}).get("content",[])
    txt = content[0].get("text","") if content else ""
    status = "TOOL_ERROR" if is_err else ("EMPTY" if not txt else "OK")
    results.append({"tool":name,"status":status,"output_excerpt":txt[:300]})

p.stdin.close(); p.terminate()
with open(OUT,"w") as f: json.dump(results, f, indent=2)

counts = Counter(r["status"] for r in results)
print(f"\nFINAL: {dict(counts)}")
print(f"Total: {len(results)}")

# Show remaining errors
print(f"\n=== Remaining TOOL_ERROR ===")
for r in results:
    if r["status"] == "TOOL_ERROR":
        print(f"  {r['tool']:<45} -> {r['output_excerpt'][:90]}")
