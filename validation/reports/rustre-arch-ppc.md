# rustre-arch-ppc

## Scopo
Implementazione architettura PowerPC 32/64-bit per la suite RustRE: istruzioni fixed-width 4 byte big-endian.
Copre: decoder primario/esteso (opcode 31), disassembler lineare, lifter a IL, register file (GPR/FPR/CR/SPR/VSR/XER/MSR), AltiVec/VMX, SPE (e500), VLE (variable-length encoding), Book-E embedded, calling convention (SysV EABI / PowerOpen / ELFv2), TOC section, analisi prologo/epilogo, branch analyzer, CFG, call graph, idiom recognition, eccezioni vettorizzate, PMC events.

Dipendenze: `rustre-core` (Address, Instruction), `ahash`.

## Moduli
- `lib.rs` — PpcArch facade, encoders, idiom detection, lookup tables (SPR/MSR/exception/PMC/AltiVec/instr-ref), lifter LLIL, CFG
- `ppc_decoder.rs` — PpcDecoder, PpcInstr, PpcForm, PpcPrimary/Extended, PpcOperand, iter
- `ppc_disassembler.rs` — PpcDisassembler, PpcInsn, PpcOperand
- `ppc_lifter.rs` — PpcLifter, PpcILExpr, PpcILInsn, LiftedInsn
- `ppc_registers.rs` — PpcGpr/Fpr/Cr/Vsr, PpcSpr enum, CrBit, XerState, MsrState, PpcRegFile
- `ppc_spr_map.rs` — PpcSprMap, SprEntry, SprAccess, SprCategory, spr_name/spr_number
- `ppc_calling_conv.rs` + `ppc_calling_convention.rs` — PpcAbi, ParamAllocator, StackFrame, LinkageArea, ResolvedSignature
- `ppc_branch_analyzer.rs` — PpcBranchAnalyzer, BranchType, BranchTarget, BranchCondition
- `ppc_altivec.rs` — AltiVecDecoder, AltiVecLifter, VmxRegister/RegFile, VSCR, AltiVecInsn, AltivecIlNode
- `ppc_analysis.rs` — PpcAnalysis facade: EabiCalling, BookE, VleMode, PpcSPE, TOCSection, PpcFinding

## Public functions principali
- `lookup_spr(u16) -> Option<&PpcSprEntry>`
- `lookup_ppc_reg_role(u8) -> Option<&PpcRegRole>`
- `lookup_msr_bit(&str) -> Option<&PpcMsrBit>`
- `lookup_ppc_exception(u32) -> Option<&PpcExceptionEntry>`
- `lookup_altivec(&str) / lookup_altivec_v2(&str)`
- `lookup_ppc_instr_ref(&str) -> Option<&PpcInstrRef>`
- `lookup_pmc_event(u16) -> Option<&PpcPmcEvent>`
- `spr_name(u16) -> String`, `spr_number(&str) -> Option<u16>`
- Encoders: `encode_b/bl/bclr/li/lis/addi/stw/lwz/stwu/mfspr/mtspr/lfs/stfs/cmpwi/cmplwi/rlwinm/srawi/lbz/lhz/lha/stb/sth/twi/mfsr/mtsr` -> `u32`
- Analisi: `detect_ppc_prologue(&[Instruction]) -> Option<i32>`, `detect_ppc_epilogue(&[Instruction]) -> bool`, `detect_ppc_preamble(&[u8]) -> Option<&'static str>`
- `identify_ppc_idiom(&Instruction) -> PpcIdiom`
- `ppc_format(&Instruction) -> String`, `ppc_format_with_addr(&Instruction) -> String`
- `disassemble_annotated(...) -> Vec<AnnotatedPpcInstr>`
- `extract_ppc_branch_targets(&[Instruction]) -> Vec<(Address, Address)>`
- `ppc_cfg_text(&[PpcBasicBlock]) -> String`
- `ppc_build_call_graph(&PpcArch, &[u8], Address) -> Vec<PpcCallEdge>`
- `ppc_lift(&Instruction) -> Vec<PpcLlilOp>`
- `ppc_param_locations(&[bool]) -> Vec<PpcParamLocation>`
- `ppc_find_dependencies(&[Instruction]) -> Vec<PpcRegDep>`
- `AltiVecDecoder::execute<S>(...)`

## Input / Output
- Input: word u32 big-endian (1 istruzione), `&[u8]` codice + base `Address`, `&[Instruction]` per analisi macro, mnemonici/numeri SPR per lookup.
- Output: `PpcInstr`/`PpcInsn` (decoded), `LiftedInsn`/`PpcLlilOp` (IL), `PpcBasicBlock`/`PpcCallEdge`/`PpcRegDep` (analisi), u32 encoded word, stringhe formattate.

## Ground truth verificabile esternamente
- **Encoders**: confronto bit-exact con tabelle PowerISA v2.07/v3.1 (IBM) e con GNU `as -mppc` + `objdump -d`.
- **Decoder/disassembler**: confronto contro Capstone (`cs_disasm` mode PPC big-endian), Ghidra PPC processor module, IDA Pro PowerPC.
- **SPR/MSR/exception tables**: PowerISA Book III, Freescale e500 Reference Manual.
- **AltiVec mnemonici**: AltiVec PIM (Motorola/Freescale) e PowerISA v2.07 Vector Facility.
- **Calling convention**: SysV PPC EABI spec, PowerOpen ABI, ELFv2 ABI (Linux PPC64LE).
- **Test binari**: PowerPC ELF (Linux/PS3/Xbox360/Wii) — comparabili con `readelf` e disassembly Ghidra.
- **PMC events**: Freescale e500 / IBM POWER PMU docs.
- **Prologue/epilogue detection**: GCC `-mcpu=powerpc` output noto.

## Tool MCP esistenti rilevanti
- `mcp__rustre-mcp__analysis_disasm_at_path` (architettura selezionabile)
- `mcp__rustre-mcp__analysis_fn_detect_functions_path`
- `mcp__rustre-mcp__analysis_fn_cfg_path`
- `mcp__rustre-mcp__analysis_callgraph_path`
- `mcp__rustre-mcp__decompile_function_path`
- `mcp__rustre-mcp__analysis_xref_*`
- Nessun tool MCP specifico per PPC (es. `analysis_disasm_at_path_ppc`) presente nel server — gap rispetto alle varianti `_arm64/_mips/_riscv/_wasm/_cil/_jvm`.

## Testabile
Sì — tests presenti (`tests/blitz.rs`, `tests/blitz2.rs`), encoders deterministici round-trippabili con decoder, lookup tables confrontabili con docs ufficiali.
