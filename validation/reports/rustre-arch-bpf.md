# rustre-arch-bpf

## Scopo
Implementazione architettura eBPF / cBPF per la suite RustRE: decodifica istruzioni eBPF (ALU32/64, JMP/JMP32, load/store, BPF_CALL, BPF_EXIT, BPF_LD_DW_IMM), decoder cBPF classico, tabella helper (200+), tipi BPF map, parser BTF, simulazione verifier kernel, CO-RE relocation, analisi CFG/loop/security, disassembler lineare.

## Moduli
- `lib.rs` — decoder core, opcode tables, helper map
- `bpf_analysis.rs` — BpfProgType inference, MapAccessPattern, HelperCallAnalysis, BpfCfg, LoopBound, BpfSecurity, BpfAnalysis facade
- `bpf_verifier.rs` — BpfVerifier, VerifierState, RegisterType, BoundsCheck, SafetyProperty, VerifierError, VerifierTrace
- `bpf_verifier_sim.rs` — simulazione registri/stack, pointer arithmetic, packet bounds, helper arg check
- `btf_parser.rs` — parser sezione .BTF ELF, ricostruzione tipi C, recupero prototipi funzione
- `bpf_co_re.rs` — BTF types, CoReReloc, CoReApplier, KernelBtf
- `cbpf_to_ebpf.rs` — conversione cBPF -> eBPF
- `ebpf_jit_analyzer.rs`, `ebpf_verifier.rs` — analisi JIT, verifier alternativo

## Public API (firme principali)
### lib.rs
- `pub fn disasm_instr<S: BuildHasher>(...) -> Result<(mnemonic, operands, flags), BpfDecodeError>` — disassembla istruzione decodificata
- `pub fn known_helpers() -> HashMap<i32, &'static str>` — mapping numero helper -> nome
- `BpfInstruction::from_bytes(bytes: &[u8]) -> Option<Self>` — decodifica 8/16 byte
- enum: `BpfClass`, `BpfSize`, `BpfMode`, `BpfAluOp`, `BpfJmpOp`, `BpfMapType`, `BpfProgType`, `BpfDecodeError`

### bpf_analysis.rs
- `BpfProgType::infer_from_helpers(helpers: &[u32]) -> Self`
- `MapAccessPattern::{new, record, access_kind, map_count}`
- `HelperCallAnalysis::{new, record, total_calls, unique_helpers, call_count, uses_helper, top_helpers}`
- `BpfSecurity::from_analysis(a: &BpfAnalysis) -> Self`
- `BpfCfg::{new, build(insns), exit_block_count}`
- `LoopAnalyzer::analyze(&self, insns) -> Vec<LoopBound>`
- `BpfAnalysis::analyze(bytes: &[u8]) -> Self`
- `format_insn(insn, idx) -> String`, `print_all(insns) -> String`

### bpf_verifier.rs / verifier_sim.rs
- `check_bounds(base, len, offset, size) -> BoundsCheck`
- `BpfVerifier::{new(config), verify(program) -> Result<(), Vec<VerifierError>>, is_safe, reset}`
- `VerifierState::{entry, reg, write_stack, read_stack, is_init}`
- `VerifierTrace::{new, push}`
- `RegisterType::{scalar, ctx, map_value}`
- Sim: `sim_alu64_reg`, `sim_ldx`, `sim_stx`, `sim_helper_call`, `sim_exit`, `state_report`
- Helpers test: `minimal_program()`, `helper_call_program(id)`

### btf_parser.rs / bpf_co_re.rs
- `BtfParser::parse(data: &[u8]) -> Result<Self, BtfError>`
- `get_type(id)`, `resolve(id)`, `size_of(id)`, `to_c_type(id) -> String`
- `function_prototypes() -> Vec<(u32, String)>`, `find_by_name`, `kind_counts`
- `BtfType::{new, find_member, field_byte_offset, has_field}`
- `BtfTypes::{add_type, add_int, add_struct, add_ptr, get_type, get_type_by_name, type_ids, resolve_type}`
- `CoReReloc::{new, parse_access_indices, is_field_offset}`
- `CoReApplier::{apply, apply_all}`
- `KernelBtf::{with_common_types, get_type, field_offset, field_exists}`

## Input/Output
- Input: byte slice di programma eBPF (multipli di 8 byte) o sezione `.BTF` ELF
- Output: istruzioni decodificate, CFG, analisi helper/map, risultato verifier, tipi BTF ricostruiti

## Ground Truth verificabile esternamente
- **Linux kernel uapi**: `include/uapi/linux/bpf.h` (opcode encoding BPF_CLASS/SIZE/MODE/ALU/JMP) e `bpf_common.h`
- **Helper IDs**: confronto con `include/uapi/linux/bpf.h` enum `bpf_func_id` (>200 helper attuali)
- **llvm-objdump -d --no-show-raw-insn --section=...** su .o eBPF: confronto disassembly
- **bpftool prog dump xlated**: confronto mnemonici/operandi
- **pahole -F btf vmlinux** o `bpftool btf dump`: confronto struct/field offsets da to_c_type
- **bpftool prog load + verifier log** del kernel: confronto trace simulato
- Tool ufficiali: `clang -target bpf` + `llvm-objdump`, `libbpf`, `bpftool`

## Tool MCP esistenti
Nessun tool MCP specifico per BPF. Tool MCP generici riutilizzabili:
- `mcp__rustre-mcp__binary_info` / `binary_hexdump` su .o ELF
- `mcp__rustre-mcp__analysis_disasm_at_path` (architetture x64/arm64/etc., **no BPF dedicato**)
- `mcp__rustre-mcp__analyze_strings`, `analyze_imports`
- Nessun `disasm_at_path_bpf` esposto -> **gap MCP: wrapping di rustre-arch-bpf non presente**

## Testabilità
Sì: ha cartella `tests/`, decodifica deterministica byte->insn confrontabile con `bpftool`/`llvm-objdump`, parser BTF confrontabile con `pahole`, helper map confrontabile con header kernel.
