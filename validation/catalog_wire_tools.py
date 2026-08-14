"""
catalog_wire_tools.py
Reads wire_tools.rs, catalogs all pub struct XxxTool; declarations,
groups by prefix, writes JSON manifest and saves orchestrator portion.
"""
import re
import json
import os

INPUT_FILE = r"C:\Users\Fra\Desktop\RustRE\crates\rustre-mcp-tools\src\wire_tools.rs"
OUTPUT_JSON = r"C:\Users\Fra\Desktop\RustRE\validation\wire_tools_catalog.json"
OUTPUT_ORCH = r"C:\Users\Fra\Desktop\RustRE\validation\wire_tools_orchestrator_original.txt"

# Compound prefixes (longest match wins — sort by token count desc, then alpha)
COMPOUND_PREFIXES = [
    "il_lift","pe_editor","arch_wasm","symb_z3","emu_unicorn","dotnet_edit","dotnet_metadata",
    "triage_entropy","triage_die","ti_misp","ti_malpedia","ti_vt","ti_opencti","ti_otx",
    "decomp2","decompiler_type","hex_pattern","hex_template","hex_tplx","hex_tply","hex_view",
    "trace_navigate","trace_coverage","trace_pt","trace_cov","debug_macos","debug_unicorn",
    "debug_windows","debug_windbg","fuzz_cov","fuzz_afl","fuzz_libfuzzer","fuzz_net",
    "fuzz_san","forensics_fs","forensics_mem","rs_sym","rustre_symb","rustre_symbols_core",
    "rustre_symbols_ext","rustre_symbols_v3","rustre_decompiler","rustre_vsa","rustre_analysis",
    "arch_x86","arch_riscv","arch_sparc","arch_mips","arch_z80","arch_avr","arch_msp430",
    "arch_ppc","arch_arm","arch_arm64","arch_m68k","arch_bpf","arch_lua","arch_luajit",
    "arch_jvm","arch_dex","arch_cil","arch_6502","arch_68k","script_lua","script_python",
    "script_rhai","an_cfg","analysis_cfg","ghidra_pcode","ghidra_backend","ttd_query",
    "ttd_recorder","ttd_replay","ttd_replayer","net_dns","net_dissect","net_pcap","net_proxy",
    "net_rules","mem_diff","mem_ma","mem_kx7","mobile_apktool","mobile_dyld","mobile_ios",
    "mobile_ipa","mobile_jadx","mobile_smali","sandbox_report","symbols_pdb","symbols_v6",
    "symbols_v7","symbols_stabs","syscalls_linux","syscalls_windows","threatintel_group",
    "threatintel_indicator","threatintel_ioc","flirt_apply","flirt_gen","il_passes","il_llil",
    "rlib_dec","rlib_dec2","db_base_migrations",
]
# Sort by length descending so longest prefix matches first
COMPOUND_PREFIXES_SORTED = sorted(COMPOUND_PREFIXES, key=lambda x: -len(x))


def camel_to_snake(name: str) -> str:
    """Convert CamelCase to snake_case."""
    # Insert underscore before uppercase letters that follow lowercase or digits
    s = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', name)
    # Handle sequences like 'CRC32' -> 'CRC_32' -> already handled above partially
    s = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', s)
    return s.lower()


def get_prefix(snake: str) -> str:
    for cp in COMPOUND_PREFIXES_SORTED:
        if snake.startswith(cp + "_") or snake == cp:
            return cp
    # First underscore-token
    return snake.split("_")[0]


def main():
    with open(INPUT_FILE, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    tools = []
    orchestrator_start = None

    i = 0
    while i < len(lines):
        line = lines[i].rstrip("\n")

        # Check for orchestrator
        if "pub fn all_wire_handlers" in line and orchestrator_start is None:
            orchestrator_start = i

        # Match: pub struct XxxTool;
        m = re.match(r'^pub struct (\w+Tool);', line)
        if m:
            struct_name = m.group(1)
            # Strip trailing 'Tool'
            base_name = struct_name[:-4]  # remove 'Tool'
            snake = camel_to_snake(base_name)
            prefix = get_prefix(snake)
            start_line = i + 1  # 1-based

            # Find end_line: scan forward until blank line or next pub struct
            end_line = i + 1
            j = i + 1
            while j < len(lines):
                stripped = lines[j].strip()
                if stripped == "":
                    end_line = j  # blank line terminates this block
                    break
                if re.match(r'^pub struct \w+Tool;', lines[j]):
                    end_line = j  # next tool starts
                    break
                j += 1
            else:
                end_line = j

            tools.append({
                "name": struct_name,
                "snake": snake,
                "prefix": prefix,
                "start_line": start_line,
                "end_line": end_line,
            })

        i += 1

    # Build prefixes dict
    prefixes: dict = {}
    for t in tools:
        p = t["prefix"]
        if p not in prefixes:
            prefixes[p] = {"count": 0, "tools": []}
        prefixes[p]["count"] += 1
        prefixes[p]["tools"].append({
            "name": t["name"],
            "snake": t["snake"],
            "start_line": t["start_line"],
            "end_line": t["end_line"],
        })

    catalog = {
        "total_tools": len(tools),
        "prefixes": prefixes,
    }

    os.makedirs(os.path.dirname(OUTPUT_JSON), exist_ok=True)
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2)

    # Save orchestrator portion
    if orchestrator_start is not None:
        orch_text = "".join(lines[orchestrator_start:])
    else:
        orch_text = "(pub fn all_wire_handlers not found in file)\n"

    with open(OUTPUT_ORCH, "w", encoding="utf-8") as f:
        f.write(orch_text)

    print(f"total_tools: {len(tools)}")
    print(f"prefixes_count: {len(prefixes)}")
    top10 = sorted(prefixes.items(), key=lambda x: -x[1]['count'])[:10]
    for p, v in top10:
        print(f"  {p}: {v['count']}")
    print(f"catalog: {OUTPUT_JSON}")
    print(f"orchestrator_saved: {orchestrator_start is not None}")


if __name__ == "__main__":
    main()
