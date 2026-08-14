# rustre-deobf-vmlift — Public API Surface

Scope: rilevamento di codice virtualizzato (VMProtect/Themida/Tigress/custom), recupero ISA, classificazione handler, lifting bytecode -> IR/LLIL, ottimizzazione IR. Solo signature pubbliche (free fn + impl methods), niente codice.

Conteggio totale: **367 funzioni pubbliche** distribuite su 18 moduli.

---

## bytecode_finder.rs (9)
Rilevamento regioni di bytecode VM tramite entropia/header.

- `shannon_entropy(data: &[u8]) -> f64` — calcolo entropia di Shannon su buffer.
- `BytecodeRegion::end(&self) -> usize` — offset fine regione.
- `BytecodeRegion::overlaps(&self, other: &Self) -> bool` — test sovrapposizione regioni.
- `BytecodeRegion::is_high_entropy(&self) -> bool` — flag entropia elevata.
- `BytecodeFinder::new() -> Self` — costruttore default.
- `BytecodeFinder::with_min_region_size(self, size: usize) -> Self` — soglia minima regione.
- `BytecodeFinder::with_block_size(self, size: usize) -> Self` — granularità blocco analisi.
- `BytecodeFinder::without_header_check(self) -> Self` — disabilita filtro header.
- `BytecodeFinder::find(&self, data: &[u8]) -> Vec<BytecodeRegion>` — esegue ricerca regioni.

## custom_vm_identifier.rs (12)
Identificazione VM custom (JIT, trampoline, fetch-decode-execute).

- `CustomVmResult::unknown() -> Self` — risultato vuoto.
- `CustomVmIdentifier::new() -> Self`
- `CustomVmIdentifier::with_min_confidence(self, t: f32) -> Self`
- `CustomVmIdentifier::with_ptr_size(self, n: u8) -> Self`
- `CustomVmIdentifier::with_code_range(self, min: u64, max: u64) -> Self`
- `CustomVmIdentifier::detect_jit(&self, bytes: &[u8]) -> (bool, f32)` — rileva pattern JIT.
- `CustomVmIdentifier::detect_trampoline(&self, bytes: &[u8]) -> (bool, f32)` — rileva trampolini.
- `CustomVmIdentifier::find_fde_loop(&self, bytes: &[u8], base_address: u64) -> Option<FetchDecodeExecutePattern>` — localizza loop fetch-decode-execute.
- `CustomVmIdentifier::find_handler_tables(&self, ...) -> ...` — cerca tabelle handler.
- `CustomVmIdentifier::infer_opcode_width(&self, bytes: &[u8]) -> u8` — stima ampiezza opcode.
- `CustomVmIdentifier::detect_threaded(&self, bytes: &[u8]) -> bool` — pattern threaded code.
- `CustomVmIdentifier::identify(&self, bytes: &[u8], base_address: u64) -> CustomVmResult` — pipeline completa.

## dispatcher_detector.rs (7)
Rilevamento dispatcher VM su byte raw.

- `VmRegister::new(index: u8, width_bits: u8, role: RegisterRole) -> Self`
- `VmDispatcher::has_virtual_ip(&self) -> bool`
- `VmDispatcher::has_virtual_sp(&self) -> bool`
- `DispatcherDetector::new() -> Self`
- `DispatcherDetector::with_min_confidence(self, min: u8) -> Self`
- `DispatcherDetector::with_deep_scan(self) -> Self`
- `DispatcherDetector::detect(&self, data: &[u8]) -> Vec<VmDispatcher>` — scansione completa.

## handler_inferrer.rs (6)
Inferenza semantica degli handler.

- `HandlerSemantic::is_branch(&self) -> bool`
- `HandlerSemantic::is_terminal(&self) -> bool`
- `HandlerInferrer::new() -> Self`
- `HandlerInferrer::with_max_insn(self, n: usize) -> Self`
- `HandlerInferrer::infer(&self, offset: usize, handler: &[u8]) -> HandlerSemantic` — inferisce semantica per un handler.
- `HandlerInferrer::infer_all(&self, handlers: &[(usize, Vec<u8>)]) -> Vec<HandlerSemantic>`

## handler_semantic_db.rs (26)
Database semantiche handler (pattern matching + storage).

- `SemanticHandler::new(...) -> Self`, `with_alt(self, sig: Vec<u8>) -> Self`, `with_tag(self, tag) -> Self`, `matches_bytes(&self, bytes: &[u8]) -> bool`.
- `HandlerDb::new() -> Self`, `builtin() -> Self`, `register(&mut self, h: SemanticHandler)`, `by_id(&self, id: u32) -> Option<&SemanticHandler>`, `by_category(&self, cat: HandlerCategory) -> Vec<&SemanticHandler>`, `by_tag(&self, tag: &str) -> Vec<&SemanticHandler>`, `by_opcode_prefix(&self, prefix: &str) -> Vec<&SemanticHandler>`, `len(&self) -> usize`, `is_empty(&self) -> bool`.
- `DbMatcher::new(db: &HandlerDb) -> Self`, `find(&self, bytes, mode: MatchMode) -> Vec<&SemanticHandler>`, `best_match(&self, bytes, mode) -> Option<&SemanticHandler>`.
- `SemanticMap::new()`, `insert(&mut self, address: u64, handler_id: u32, semantic: HandlerSemantic)`, `get(&self, address: u64) -> Option<&HandlerSemantic>`, `handler_id(&self, address: u64) -> Option<u32>`, `addresses(&self) -> Vec<u64>`, `len()`, `is_empty()`, `remove(&mut self, address: u64)`, `merge(&mut self, other: SemanticMap)`, `by_semantic_kind(&self) -> HashMap<String, Vec<u64>>`.

## isa_synthesizer.rs (11)
Sintesi ISA virtuale a partire da semantiche handler.

- `VmInstructionDef::from_semantic(opcode: u32, sem: &HandlerSemantic) -> Self`
- `VmIsa::new() -> Self`, `sorted_instructions(&self) -> Vec<&VmInstructionDef>`, `instructions_by_class(&self, class: &HandlerClass) -> Vec<&VmInstructionDef>`, `has_halt(&self) -> bool`, `has_branches(&self) -> bool`, `disassembly_listing(&self) -> String`.
- `IsaSynthesizer::new() -> Self`, `with_first_opcode(self, opcode: u32) -> Self`, `with_opcode_stride(self, stride: u32) -> Self`, `synthesize(&self, semantics: &[HandlerSemantic]) -> VmIsa` — produce ISA finale.

## lib.rs (23)
API top-level: lifting orchestration, dispatcher detect, pipeline end-to-end.

- `lift_to_instructions(bytecode: &[u8]) -> Result<Vec<GuestInstruction>, &'static str>`
- `to_pseudo_il(instrs: &[GuestInstruction]) -> Vec<String>` — pseudo-IL human readable.
- `detect_in_bytes(code: &[u8], base: u64) -> Vec<VmDispatcher>`
- `extract_jump_table_entries(...) -> ...`
- `GuestInstruction::is_control_flow(&self) -> bool`, `accesses_memory(&self) -> bool`, `suggest_mnemonic(&self) -> &'static str`.
- `VmInstructionDef::new(opcode: u8, semantic: HandlerSemantic) -> Self`
- `IsaTable::new()`, `register(&mut self, def: VmInstructionDef)`, `lookup(&self, opcode: u8) -> Option<&VmInstructionDef>`, `sorted_handlers(&self) -> Vec<&VmInstructionDef>`, `listing(&self) -> String`, `len()`, `is_empty()`, `suggest_mnemonic(sem: &HandlerSemantic) -> &'static str` (associated), `default_lifter_isa() -> Self`, `disassemble(...) -> ...`, `to_text(instrs: &[VmInstruction]) -> String`.
- `detect_and_report(code: &[u8], base: u64) -> VmLiftReport` — analisi + report.
- `full_pipeline(code: &[u8], base: u64, bytecode: &[u8]) -> Result<Vec<String>>` — pipeline completa.
- `suggest_mnemonic(sem: &HandlerSemantic) -> &'static str` (free fn).
- `run_pass()` — entry pass.

## lifted_ir_optimizer.rs (21)
Ottimizzazioni su IR liftato (cost-fold, DCE, peephole).

- `Operand::is_const(&self) -> bool`, `as_const(&self) -> Option<Const>`.
- `BinOp::eval(self, lhs: u64, rhs: u64) -> u64`, `identity(self) -> Option<u64>`, `absorbing(self) -> Option<u64>`.
- `UnOp::eval(self, v: u64) -> u64`.
- `Instr::dst(&self) -> Option<VReg>`, `uses(&self) -> Vec<VReg>`.
- `BasicBlock::new(id: u32, address: u64) -> Self`, `live_defs(&self) -> HashSet<VReg>`.
- `IrFunction::new(entry: u32) -> Self`, `fresh_vreg(&mut self) -> VReg`, `block_order(&self) -> Vec<u32>`.
- `ConstFolding::run(func: &mut IrFunction) -> u32`
- `DeadCodeElimination::run(func: &mut IrFunction) -> u32`
- `CopyPropagation::run(func: &mut IrFunction) -> u32`
- `PeepholePass::run(func: &mut IrFunction) -> u32`
- `BlockMerger::run(func: &mut IrFunction) -> u32`
- `Optimizer::new() -> Self`, `with_config(config: OptimizerConfig) -> Self`, `optimize(&self, func: &mut IrFunction) -> OptStats` — driver completo.

## lifter_to_llil.rs (16)
Lifting da virtual-ISA verso LLIL (Low-Level IL).

- `VirtualInsn::new(opcode: u16, address: u64, size: usize, kind: HandlerSemanticsKind) -> Self`, `mnemonic(&self) -> String`, `disasm(&self) -> String`.
- `Operand::size(&self) -> u8`.
- `LlilStmt::display(&self) -> String`.
- `LlilBlock::new(start: u64) -> Self`, `push(&mut self, stmt: LlilStmt, end_addr: u64)`, `add_successor(&mut self, addr: u64)`.
- `LlilFunction::new(entry: u64, vm_type: VmType) -> Self`, `block_count(&self) -> usize`.
- `Lifter::new(isa: IsaTable) -> Self`, `set_max_instructions(&mut self, max: usize)`, `set_operand_size(&mut self, size: u8)`, `lift_virtual_function(...) -> ...` (method + free fn), `isa(&self) -> &IsaTable`.

## protector_patterns.rs (26)
Pattern signature per protettori noti (VMProtect/Themida/Tigress…).

- `ProtectorPattern::name(self) -> &'static str`, `min_confidence(self) -> u8`.
- `BytePattern::exact(bytes: &[u8]) -> Self`, `wildcard(bytes: &[Option<u8>]) -> Self`, `len()`, `is_empty()`, `matches_at(&self, data: &[u8], offset: usize) -> bool`, `find_all(&self, data: &[u8]) -> Vec<usize>`, `find_first(&self, data: &[u8]) -> Option<usize>`.
- `PatternSignature::new(...) -> Self`, `matches(&self, data: &[u8]) -> bool`, `find_all(&self, data: &[u8]) -> Vec<usize>`.
- `DetectedProtector::is_confident(&self) -> bool`.
- `PatternDb::new()`, `builtin()`, `register(&mut self, sig: PatternSignature)`, `len()`, `is_empty()`, `for_protector(&self, p: ProtectorPattern) -> Vec<&PatternSignature>`, `of_kind(&self, kind: SignatureKind) -> Vec<&PatternSignature>`.
- `ProtectorDetector::new()`, `with_db(db: PatternDb) -> Self`, `detect(&self, data: &[u8]) -> Vec<DetectedProtector>`, `detect_min_confidence(&self, data, min_confidence: u8) -> Vec<DetectedProtector>`, `is_protected(&self, data: &[u8]) -> bool`, `best_match(&self, data: &[u8]) -> Option<DetectedProtector>`.

## tigress_lifter.rs (16)
Lifter specifico per VM Tigress.

- `TigressConfig::default_x64() -> Self`.
- `LlilExpr::reg(name) -> Self`, `constant(v: u64) -> Self`, `add(lhs, rhs) -> Self`, `sub(lhs, rhs) -> Self`, `xor(lhs, rhs) -> Self`, `load(inner, width: u8) -> Self`.
- `TigressLifter::new()`, `with_min_confidence(self, t: f32) -> Self`, `detect_dispatch_mode(&self, bytes: &[u8]) -> (TigressDispatchMode, f32)`, `locate_handler_table(&self, bytes: &[u8], base_address: u64) -> Option<u64>`, `infer_register_file(&self, handlers: &[TigressHandler]) -> TigressRegisterFile`, `identify_handler_semantic(&self, body: &[u8]) -> Option<(String, f32)>`, `extract_handlers(...) -> ...`, `lift_to_llil(...) -> ...`, `lift(...) -> ...` — pipeline completa Tigress.

## virtualized_function.rs (50)
Modello dati centrale: entry/exit VM, dispatcher shape, CFG handler, opcode stats, identificazione protettori, analisi.

- `detect_vm_entries(code: &[u8], base: u64) -> Vec<VmEntry>` (free fn).
- `detect_vm_exits(code: &[u8], base: u64) -> Vec<VmExit>` (free fn).
- `Addr::new(v: u64) -> Self`, `as_u64(self) -> u64`.
- `VmEntry::new(...)`, `with_confidence(self, c: u8)`, `with_opcode(self, op: u64)`, `is_high_confidence(&self) -> bool`.
- `VmExit::new(address: Addr, kind: VmExitKind) -> Self`, `with_confidence(self, c: u8)`.
- `Dispatcher::new(address: Addr, shape: DispatcherShape) -> Self`, `is_strong_match(&self) -> bool`.
- `HandlerNode::new(address: Addr, opcode: u8, mnemonic) -> Self`.
- `HandlerCfg::new()`, `add_node(&mut self, node: HandlerNode)`, `add_edge(&mut self, from: Addr, to: Addr, cond: Option<bool>)`, `successors(&self, addr: Addr) -> Vec<(Addr, Option<bool>)>`, `predecessors(&self, addr: Addr) -> Vec<Addr>`, `bfs_order(&self) -> Vec<Addr>`, `node_count()`, `edge_count()`, `is_empty()`.
- `VirtualBB::new(index: usize, start_addr: Addr) -> Self`, `push_opcode(&mut self, op: u8)`.
- `BlockList::new()`, `push(&mut self, block: VirtualBB)`, `len()`, `is_empty()`, `total_opcodes() -> usize`, `get(&self, index: usize) -> Option<&VirtualBB>`.
- `VirtualizedFunction::new(native_address: Addr) -> Self`, `is_lifted(&self) -> bool`, `confidence(&self) -> u8`, `summary(&self) -> String`.
- `Devirtualization::new(source: VirtualizedFunction) -> Self`, `line_count(&self) -> usize`, `has_output(&self) -> bool`.
- `OpcodeStats::new()`, `analyze(&self, bytecode: &[u8]) -> Vec<OpcodeFrequency>`, `most_frequent(&self, bytecode) -> Option<OpcodeFrequency>`, `above_threshold(&self, bytecode, threshold: f32) -> Vec<OpcodeFrequency>`, `opcode_entropy(&self, bytecode: &[u8]) -> f64`.
- `VmProtectionFamily::label(self) -> &'static str`.
- `ProtectorIdentifier::new()`, `identify(&self, code: &[u8]) -> (VmProtectionFamily, u8)`.
- `Devirtualizer::new()`, `note(&mut self, msg)`, `best_function(&self) -> Option<&VirtualizedFunction>`.
- `VmAnalyzer::new()`, `analyze(&self, code: &[u8], base: u64) -> VmAnalysisResult` — pipeline completa.

## vm_bytecode_lifter.rs (23)
Lifter generico bytecode VM -> sequenza LiftedInsn.

- `VmBytecode::new(bytes: Vec<u8>, base_address: u64) -> Self`, `with_name(self, name) -> Self`, `len()`, `is_empty()`.
- `LiftedInsn::new(offset, raw_opcode: u8, op: LiftedOp, operands: Vec<LiftedOperand>, encoded_width: usize) -> Self`, `annotate(&mut self, note)`, `is_control_flow() -> bool`, `accesses_memory() -> bool`.
- `OpcodeTable::new()`, `register(&mut self, opcode: u8, op: LiftedOp, operand_bytes: usize)`, `lookup(&self, opcode: u8) -> Option<(&LiftedOp, usize)>`, `default_lifter_table() -> Self`, `len()`, `is_empty()`.
- `VmBytecodeLifter::new()`, `with_table(table: OpcodeTable) -> Self`, `strict(self) -> Self`, `lift(&self, bc: &VmBytecode) -> Result<Vec<LiftedInsn>, LiftError>`, `lift_bytes(&self, bytes: &[u8]) -> Result<Vec<LiftedInsn>, LiftError>`.
- `LiftedInsn::to_text(insns: &[LiftedInsn]) -> String` (assoc), `control_flow_insns(insns: &[LiftedInsn]) -> Vec<&LiftedInsn>`, `offset_map(insns: &[LiftedInsn]) -> HashMap<usize, usize>`.
- `lift_vm_function(bytecode: &VmBytecode) -> Result<LiftResult, LiftError>` (free fn).

## vm_dispatcher_finder.rs (15)
Trova tabelle dispatch e promuove a siti dispatch.

- `DispatchPattern::uses_jump_table(&self) -> bool`, `max_handlers(&self) -> usize`.
- `DispatchTable::new(offset, virtual_address: u64, pattern: DispatchPattern, confidence: u8) -> Self`, `add_entry(&mut self, addr: u64)`, `set_handler_count(&mut self, n: usize)`, `add_note(&mut self, note)`, `is_confident(&self, min: u8) -> bool`.
- `DispatcherFinder::new()`, `with_base(self, base: u64) -> Self`, `with_min_confidence(self, c: u8) -> Self`, `find(&self, code: &[u8]) -> Vec<DispatchTable>`.
- `DispatcherFinder::group_by_pattern(tables: &[DispatchTable]) -> HashMap<String, Vec<&DispatchTable>>` (assoc).
- `DispatcherFinder::summarize(tables: &[DispatchTable]) -> Vec<(DispatchPattern, usize, u8)>` (assoc).
- `DispatchSite::from_table(table: DispatchTable, is_primary: bool) -> Self`.
- `promote_to_sites(tables: Vec<DispatchTable>) -> Vec<DispatchSite>` (free fn).

## vm_handler_analyzer.rs (30)
Classificazione e analisi handler VM.

- `HandlerKind::is_control_flow()`, `accesses_memory()`, `mnemonic() -> &'static str`.
- `VmHandler::new(opcode: u8, offset, size, kind: HandlerKind) -> Self`, `with_confidence(self, confidence: u8) -> Self`, `with_operand_bytes(self, n: usize) -> Self`, `add_note(&mut self, note)`, `is_confident(&self, min: u8) -> bool`.
- `HandlerPattern::new(...) -> Self`, `matches(&self, data: &[u8], offset: usize) -> bool`, `score(&self, body: &[u8]) -> u8`.
- `HandlerAnalyzer::new()`, `with_min_size(self, n)`, `with_max_size(self, n)`, `with_min_confidence(self, c: u8)`, `analyze(&self, code: &[u8]) -> Vec<VmHandler>`, `classify(...) -> ...`.
- `HandlerAnalyzer::summarize(handlers: &[VmHandler]) -> HashMap<HandlerKind, usize>` (assoc), `filter_by_kind(handlers, kind) -> Vec<&VmHandler>` (assoc).
- `HandlerCatalog::new()`, `from_handlers(handlers: Vec<VmHandler>) -> Self`, `insert(&mut self, handler: VmHandler)`, `get(&self, opcode: u8) -> Option<&VmHandler>`, `sorted(&self) -> Vec<&VmHandler>`, `len()`, `is_empty()`, `listing(&self) -> String`, `kind_counts(&self) -> HashMap<String, usize>`, `high_confidence(&self) -> Vec<&VmHandler>`.
- `classify_handler(code: &[u8], offset: usize, size: usize) -> (HandlerKind, u8)` (free fn).

## vm_isa_complete.rs (41)
Modello completo: opcode, operandi, basic blocks, CFG VM, funzioni, programma.

- `OperandSpec::new(name, kind: OperandKind, width: OperandWidth) -> Self`, `optional(...) -> Self`, `encoded_bytes(&self) -> usize`.
- `Mnemonic/Class::label(self) -> &'static str`.
- `VmOpcode::new(...) -> Self`, `describe(&self) -> String`.
- `DecodedInsn::new(offset, opcode: u8, mnemonic) -> Self`, `display(&self) -> String`.
- `VmBasicBlock::new(id: u32, start_offset: usize) -> Self`, `push(&mut self, insn: DecodedInsn)`, `len()`, `is_empty()`, `byte_size(&self) -> usize`.
- `VmCfg::new()`, `new_block(&mut self, start_offset: usize) -> u32`, `block_mut(&mut self, id: u32) -> Option<&mut VmBasicBlock>`, `block(&self, id: u32) -> Option<&VmBasicBlock>`, `add_edge(&mut self, from: u32, to: u32)`, `block_count()`, `total_instructions() -> usize`, `entry_candidates(&self) -> Vec<u32>`, `digraph(&self) -> &DiGraph<u32, ()>`.
- `VmFunction::new(address: u64) -> Self`, `instruction_count(&self) -> usize`.
- `VmProgram::new()`, `push(&mut self, func: VmFunction)`, `len()`, `is_empty()`, `total_instructions()`, `find_by_address(&self, addr: u64) -> Option<&VmFunction>`, `iter(&self) -> impl Iterator<Item = &VmFunction>`, `coverage_percent(&self) -> String`, `summary(&self) -> String`.
- `VmIsaCompleteEngine::new()`, `register_opcode(&mut self, opcode: VmOpcode)`, `lookup(&self, byte: u8) -> Option<&VmOpcode>`, `isa_size(&self) -> usize`, `decode_to_cfg(&mut self, bytecode: &[u8], start_address: u64) -> VmFunction`, `lift_all(&mut self, functions: &[(u64, Vec<u8>)])`, `populate_default_isa(&mut self)`, `report(&self) -> VmIsaReport`.

## vm_isa_recovery.rs (19)
Recupero ISA virtuale a partire da dispatch table + handler.

- `HandlerSemantics::new(kind: HandlerSemanticsKind, description) -> Self`, `is_control_flow(&self) -> bool`.
- `VirtualOpcode::unanalysed(id: u16, handler_addr: u64) -> Self`, `mnemonic(&self) -> String`.
- `DispatchTable::parse(...) -> ...`, `handler_for(&self, opcode: u16) -> Option<u64>`, `unique_handler_count(&self) -> usize`.
- `VirtualIsa::new(native_arch) -> Self`, `add_opcode(&mut self, opcode: VirtualOpcode)`, `get_opcode(&self, id: u16) -> Option<&VirtualOpcode>`, `opcode_count()`, `analysed_count()`, `coverage_pct(&self) -> f64`, `sorted_opcodes(&self) -> Vec<&VirtualOpcode>`, `control_flow_opcodes(&self) -> Vec<&VirtualOpcode>`.
- `IsaRecovery::new()`, `with_config(config: IsaRecoveryConfig) -> Self`, `recover(...) -> ...` — pipeline recovery.
- `recover_isa(...) -> ...` (free fn) — entry point principale.

## vm_protection_analysis.rs (16)
Analisi VM-protection (regioni protette, scoring, priorità deobf).

- `Confidence::score(self) -> u8`, `from_score(s: u8) -> Self`.
- `ProtectedRegion::new(original_address: u64, vm_entry: u64) -> Self`, `has_known_protector(&self) -> bool`, `native_size_estimate(&self) -> usize`.
- `Complexity::from_complexity(c: &VmComplexity) -> Self`, `name(self) -> &'static str`.
- `EscapedCodeFinder::find_escaped(...) -> ...` — trova codice non virtualizzato lasciato in chiaro.
- `VmProtectionSummary::new()`, `add_region(&mut self, region: ProtectedRegion)`, `finalize(&mut self)`, `region_count() -> usize`, `is_vm_protected(&self) -> bool`.
- `VmProtectionAnalyzer::new()`, `analyze(code: &[u8], base_addr: u64) -> VmProtectionSummary` (assoc), `prioritize(summary: &VmProtectionSummary) -> Vec<(&ProtectedRegion, DeobfPriority)>` (assoc).
