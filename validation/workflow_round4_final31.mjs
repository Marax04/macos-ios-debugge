export const meta = {
  name: 'round4-final-31-tool-errors',
  description: 'Fix the last 31 TOOL_ERROR — all validator-side: add realistic minimal headers for PE/ELF/Mach-O/OLE/pcap/CV/FLIRT/JVM/Lua tests.',
  phases: [
    { title: 'FixTargeted', detail: '5 parallel agents targeting 5 groups of tools' },
    { title: 'Verify', detail: 'exercise_v3 fresh, must be 0 error 0 stub' },
  ],
}

const CWD = 'C:/Users/Fra/Desktop/RustRE'
const BANNED = 'rustre-decompiler, rustre-decompiler-type, rustre-decompiler-ghidra, rustre-rlib-dec, rustre-rlib-dec2'

const GROUPS = [
  {
    name: 'loader_pe_elf_macho_ole',
    tools: [
      'loader_elf_info_summary','loader_macho_parse_summary','loader_elf_parse_info',
      'loader_elf_plt_entries','loader_macho_parse','loader_pe_parse_info',
      'loader_pe_imports_from_dll','loader_ole_list_streams','loader_lua_read_string',
      'mobile_dyld_parse_dyld_magic','lua_loader_lua_header_is_official_format_wx1',
    ],
    hint: 'These need valid minimal file headers. Add to TOOL_ARG_OVERRIDES in exercise_v3.py: for PE use hex "4d5a" + "00"*58 + "40000000" + "50450000" + "8664" + "0"*40 (MZ + e_lfanew=0x40 + PE\\0\\0 + IMAGE_FILE_MACHINE_AMD64). For ELF: "7f454c46020101" + "00"*57 (ELF64 header). For Mach-O 64: "cffaedfe07000001030000800200000005000000" + "50000000" + "0"*24 (MH_MAGIC_64 + cputype x86_64 + ncmds=5). For OLE: "d0cf11e0a1b11ae1" + "0"*504 (OLE compound file magic). For Lua: "\\x1bLua" + "\\x54" + "\\x00" (Lua 5.4 header prefix).',
  },
  {
    name: 'codeview_flirt',
    tools: [
      'codeview_parse_symbols','codeview_parse_type_records','codeview_symbol_filter_count',
      'flirt_parse_sig_header','flirt_gen_elf_parse',
    ],
    hint: 'CV symbol/type records: use a valid minimal Object stream with S_END (0x0006 0x0000 0x00). FLIRT sig header magic: "49 44 41 53 47 4E" + 6 zero bytes ("IDASGN"). Add to TOOL_ARG_OVERRIDES.',
  },
  {
    name: 'net_pcap_hex_pattern',
    tools: [
      'net_pcap_file_parse_info','net_pcap_split_by_count','net_pcap_split_by_time',
      'hex_pattern_import_ida_pat','hex_pattern_sequence_search_v3',
      'trace_pt_decoder_remaining_bytes',
    ],
    hint: 'pcap: use magic "d4c3b2a1" + version 0x0002 0x0004 + timezone 0x00000000 + sigfigs 0x00000000 + snaplen 0xffffffff + linktype 0x00000001 = 24-byte header. Add for net_pcap_split_by_time: {window_secs: 1}. For hex_pattern_import_ida_pat: real IDA .pat text "ABCD01 05 100A 100C :0000 func_name\\n---\\n". For hex_pattern_sequence_search_v3: valid entries array. For trace_pt_decoder_remaining_bytes: bytes=[0]*4.',
  },
  {
    name: 'arch_jvm_deobf_diff_vmlift',
    tools: [
      'arch_jvm_decode','arch_jvm_decode_at','deobf_string_decode_base64_custom_v3',
      'diff_bindiff_binary_snapshot_call_graph','vmlift_lift_to_pseudo_il',
      'malpedia_check_ruleset_quality','mem_patched_read_v5','adb_decode_message',
      'mobile_apktool_apk_decode_smali_count',
    ],
    hint: 'JVM opcode: use valid opcodes like [0x00,0x01,0x03,0xb1] (nop, aconst_null, iconst_0, return). Base64 custom: valid base64 "SGVsbG8=". diff bindiff call_graph: use a valid func addr like 0x140001000. vmlift bytecode: use known valid opcodes for the mock ISA. malpedia ruleset: add stub {created_at:"2024-01-01",name:"test",author:"t",rules:[]}. mem_patched_read: needs valid inputs (data + patches). adb_decode_message: valid ADB packet header. mobile_apktool: needs .apk extension in path override.',
  },
]

phase('FixTargeted')
const fixes = await parallel(GROUPS.map(g => () =>
  agent(
    `Fix TOOL_ERRORs for group "${g.name}" (${g.tools.length} tools).
Failing tools: ${g.tools.join(', ')}
Hint: ${g.hint}

Steps:
1. Read ${CWD}/validation/exercise_v3.py — find the TOOL_ARG_OVERRIDES dict and make_input dispatcher.
2. For each of the ${g.tools.length} tools, add an appropriate entry to TOOL_ARG_OVERRIDES with the minimal valid input following the hint above.
3. If the fix requires wrapper defensive code (e.g. tool crashes on truncated input), add the guard in ${CWD}/crates/rustre-mcp-tools/src/tools/<prefix>.rs.
4. cargo check --release -p rustre-mcp-tools (Bash timeout 300000ms) if any Rust file changed.
5. Restart MCP if you changed Rust (kill, rebuild -p rustre-mcp -p rustre-mcp-server).
6. Run exercise_v3 focused: filter for JUST these tools, verify they now return OK.
7. Return JSON {group:"${g.name}",tools_targeted:${g.tools.length},tools_fixed:int,files_changed:[string],summary:string,still_broken:[string]}.

RULES: never touch decompiler crates (${BANNED}). Never delete code. Never add #[allow]. Never panic!/todo!/unimplemented!. Always --release.
Time budget: 25 minutes.`,
    { label: `fix:${g.name}`, phase: 'FixTargeted', agentType: 're-validator', schema: {
      type: 'object',
      properties: {
        group:{type:'string'},
        tools_targeted:{type:'integer'},
        tools_fixed:{type:'integer'},
        files_changed:{type:'array', items:{type:'string'}},
        summary:{type:'string'},
        still_broken:{type:'array', items:{type:'string'}},
      },
      required:['group','tools_fixed']
    }}
  )
))

const totalFixed = fixes.filter(Boolean).reduce((s,r)=>s+(r.tools_fixed||0),0)

phase('Verify')
const verify = await agent(
  `Final verification.
1. cd ${CWD} && cargo build --release -p rustre-mcp -p rustre-mcp-server (Bash timeout 1800000ms).
2. taskkill /F /IM rustre-mcp.exe.
3. cd ${CWD}/validation && python3 exercise_v3.py > /tmp/r4_v.log 2>&1 (Bash timeout 600000ms).
4. Parse FINAL. Target: OK=4130 / TOOL_ERROR=0 / STUB=0.
5. If still errors: list them.
6. Report {ok:int, tool_error:int, stub:int, remaining_error_tools:[string], verdict:string}.`,
  { label: 'verify-final', agentType: 're-validator', schema: {
    type: 'object',
    properties: {
      ok:{type:'integer'},
      tool_error:{type:'integer'},
      stub:{type:'integer'},
      remaining_error_tools:{type:'array', items:{type:'string'}},
      verdict:{type:'string'},
    },
    required:['verdict']
  }}
)

return { status:'round4-attempt', fixes_count:totalFixed, verify }
