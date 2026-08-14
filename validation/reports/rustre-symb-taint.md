# rustre-symb-taint — Documentazione API

**Crate:** `rustre-symb-taint` v0.1.0  
**Dipendenze principali:** `rustre-core`, `rustre-symb`, `petgraph`, `serde`, `thiserror`  
**Scopo:** Analisi taint simbolica per reverse engineering binario. Fornisce propagazione del taint a livello di istruzione, rilevamento di sink/source/sanitizer, analisi interprocedurale, tracciamento heap e generazione di report di vulnerabilità con classificazione CWE.

---

## Riepilogo moduli

| File | Responsabilità |
|------|----------------|
| `lib.rs` | Core: TaintId, TaintedValue, TaintState, TaintInstr, TaintFinding, TaintEngine, LegacyTaintTracker |
| `taint_policy.rs` | Policy: TaintSource, TaintSink, Sanitizer, PropagationRule, TaintPolicy |
| `taint_propagator.rs` | Propagazione con regole, TaintTransfer, DataFlowTaintMap |
| `taint_propagation_rules.rs` | Regole di trasferimento taint per opcode, TaintRuleSet, TaintTransferRule |
| `taint_graph.rs` | Grafo diretto sorgente→sink, shortest path, BFS, TaintFlow |
| `taint_sinks.rs` | Definizioni sink (TaintSinkDef), TaintSinkRegistry, match per chiamata |
| `taint_sinks_full.rs` | Catalogo sink esteso con categoria, piattaforma, criticità |
| `taint_sink_detector.rs` | Rilevamento runtime: check_call, check_branch_condition, check_memory_write |
| `sanitizer_detector.rs` | Riconoscimento sanitizer per nome/prefisso, SanitizerDetector, pattern builtins |
| `taint_summary.rs` | Sommario per funzione (FunctionTaintSummary), TaintSummary, TaintPath |
| `taint_report_generator.rs` | Generazione report (testo/JSON/Markdown), ReportEntry, TaintReportConfig |
| `taint_report_extended.rs` | Report esteso: VulnerabilityReport, TaintDFG, TaintedApiCall, TaintAnalysisReport |
| `data_flow_tracker.rs` | DataFlowTracker: propagazione binop/load/store/call, backward slice, source→sink paths |
| `dataflow_taint.rs` | Analisi dataflow su CFG a blocchi base, fixpoint iterativo, TaintLattice |
| `interprocedural.rs` | IpaTaintAnalyzer: analisi interprocedurale, call graph, topo order, FuncTaintSummary |
| `heap_taint.rs` | HeapTaintTracker: alloc/free/taint/UAF, HeapSprayDetector, HeapPass |
| `vuln_reporter.rs` | VulnReporter: report per tipo (SQLi, CMDi, BOF, UAF, …), CweEntry, VulnReport |

---

## Funzioni pubbliche (584 totali)

### lib.rs — Core taint primitives

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `Taint::custom(idx: u8)` | indice 0–63 | `u64` | Crea bit-mask per taint personalizzato |
| `Taint::is_tainted(mask: u64)` | maschera | `bool` | Verifica se almeno un bit è settato |
| `Taint::union(a, b: u64)` | due maschere | `u64` | OR bit a bit (unione sorgenti) |
| `Taint::intersect(a, b: u64)` | due maschere | `u64` | AND bit a bit |
| `Taint::has_bit(mask, bit: u64)` | maschera + bit | `bool` | Verifica bit singolo |
| `TaintSource::new(id, name, description)` | TaintId, str, str | `TaintSource` | Costruttore sorgente taint |
| `TaintSource::user_input/network/file/environment/command_line/registry()` | — | `TaintSource` | Sorgenti predefinite |
| `TaintedValue::new(value, taints)` | u64, TaintId | `TaintedValue` | Valore con maschera taint |
| `TaintedValue::tainted(value, source)` | u64, TaintId | `TaintedValue` | Valore marcato come tainted |
| `TaintedValue::is_tainted/clean/union_taints` | — | bool/TaintId | Interrogazione e composizione |
| `TaintState::new()` | — | `TaintState` | Stato vuoto (registri + memoria + stack) |
| `TaintState::get_reg/set_reg/taint_reg/sanitize_register/reg_taint` | nome registro | vario | Gestione taint su registri |
| `TaintState::get_mem/set_mem/mark_tainted/sanitize_memory/mem_taint` | indirizzo, size | vario | Gestione taint su memoria |
| `TaintState::get_stack/set_stack/stack_taint` | offset i64 | vario | Gestione taint su stack |
| `eval_taint(expr, state)` | `&TaintExpr`, `&TaintState` | `TaintId` | Valuta espressione taint nello stato |
| `eval_value(expr, state)` | `&TaintExpr`, `&TaintState` | `u64` | Valuta valore concreto dell'espressione |
| `apply_instr(instr, state)` | `&TaintInstr`, `&mut TaintState` | `Option<TaintFinding>` | Applica un'istruzione taint allo stato; emette finding se colpisce un sink |
| `TaintReport::new/add_finding/finding_count/has_findings/findings_by_type/high_severity_count` | vario | vario | Raccolta e query sui finding |
| `TaintReport::analyze(instrs, initial_state)` | slice di TaintInstr, TaintState | `TaintReport` | Analisi completa di una sequenza di istruzioni |
| `FindingType::category/default_risk/to_taint_id` | — | &str / u8 / TaintId | Metadati sul tipo di vulnerability |
| `TaintLocation::is_register/is_memory/is_variable` | — | `bool` | Tipo di location |
| `TaintInstr::is_transitive/may_sanitize` | — | `bool` | Proprietà dell'istruzione |
| `LegacyTaintedValue::new/merge_sources/propagate/sanitize/is_tainted/source_count/propagation_depth` | vario | vario | Modello taint legacy con catena di propagazione |
| `LegacyTaintTracker::new/mark_source/get_at_location/propagate/sanitize_location/is_tainted_at/find_paths_to_sink` | vario | vario | Tracker legacy con BFS per path to sink |
| `TaintConfig::new/add_source/add_sink/add_sanitizer/is_sink/is_sanitizer` | vario | vario | Configurazione analisi |
| `CallSummary::new/with_name/taint_return_from_args/mark_sink` | vario | `CallSummary` | Sommario taint per chiamata esterna |
| `InterproceduralTaintGraph::new/add_summary/add_call_edge/propagate_through_call/is_tainted_path` | vario | vario | Grafo IPA semplice |
| `TaintEngine::new/mark_tainted/mark_register_tainted/sanitize_register/sanitize_memory/run/get_report` | vario | vario | Engine principale: esegue istruzioni e raccoglie report |
| `TaintSet::empty/all/add/remove/contains/is_empty/union/intersection` | TaintId | vario | Set di TaintId (bitmask wrapper) |

### taint_policy.rs — Policy sorgenti/sink/sanitizer

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `SourceKind::taint_bit(self)` | — | `TaintId` | Bit predefinito per il tipo di sorgente |
| `TaintSource::new/with_api/with_output_arg/with_description` | vario | `TaintSource` | Builder per sorgente taint |
| `TaintSink::new/with_api/with_sensitive_arg/dangerous_if/is_dangerous` | vario | bool/TaintSink | Builder e verifica pericolosità sink |
| `Sanitizer::new/clearing/with_api/when/apply` | TaintId | `TaintId` | Sanitizer che azzera bit di taint specificati |
| `PropagationRule::apply(operands)` | `&[TaintId]` | `TaintId` | Applica regola di propagazione |
| `TaintPolicy::new/default_c_policy` | — | `TaintPolicy` | Policy vuota o predefinita per C |
| `TaintPolicy::add_source/add_sink/add_sanitizer/set_rule` | vario | — | Mutatori policy |
| `TaintPolicy::source_for_api/sinks_for_api/sanitizer_for_api` | `&str` | `Option<&TaintSource>` ecc. | Lookup per nome API |
| `TaintPolicy::propagate(op_class, operands)` | `OperationClass`, `&[TaintId]` | `TaintId` | Calcola taint risultante dell'operazione |
| `TaintPolicy::sanitize(name, taint)` | `&str`, `TaintId` | `TaintId` | Applica sanitizer per nome |
| `TaintPolicy::all_source_apis/all_sink_apis` | — | `HashSet<&str>` | Tutti i nomi API registrati |

### taint_propagator.rs — Propagazione a basso livello

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `TaintTransfer::new/is_tainted` | vario | vario | Record di un trasferimento taint |
| `PropagationRule::union_all/sanitize/masked/applies_to/apply` | vario | `TaintId` | Regole built-in per operazioni comuni |
| `TaintPropagator::new/with_default_rules/add_rule` | — | `TaintPropagator` | Motore di propagazione |
| `TaintPropagator::propagate(op, dest, operands, state)` | vario | `Option<TaintTransfer>` | Propaga taint per una operazione |
| `TaintPropagator::compute_result/history/clear_history/rules_for` | vario | vario | Query e manutenzione |
| `TaintPropagator::propagate_with_path_condition` | taint, condition_taint | `TaintId` | Propagazione condizionale |
| `DataFlowTaintMap::new/mark_tainted/sanitize/taint_of/is_tainted/apply_op/tainted_locations/location_count/snapshot/merge` | vario | vario | Mappa location→TaintId con operazioni di merge |
| `DataFlowSummary::from_map/has_taint` | `&DataFlowTaintMap` | `DataFlowSummary` | Snapshot immutabile |

### taint_propagation_rules.rs — Regole per opcode

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `TaintTransferRule::apply(inputs, concrete_vals)` | `&[TaintId]`, `&[u64]` | `TaintId` | Applica regola di trasferimento per opcode specifico |
| `SanitizerSpec::apply(inputs, concrete_vals)` | `&[TaintId]`, `&[u64]` | `TaintId` | Applica spec sanitizer |
| `SanitizerSpec::clean_return(name, description)` | str, str | `SanitizerSpec` | Spec che ritorna sempre pulito |
| `TaintRuleSet::new/get_rule/get_sanitizer/apply_rule/eval_expr_taint/apply_instr_with_rules/rule_count/sanitizer_count` | vario | vario | Set di regole indicizzate per opcode; evalua espressioni TaintExpr |

### taint_graph.rs — Grafo taint

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `TaintNodeData::new/source/sink/is_tainted` | vario | `TaintNodeData` | Nodo del grafo (sorgente, intermedio, sink) |
| `TaintFlow::new/hop_count/is_direct` | vario | `TaintFlow` | Flusso sorgente→sink con numero di hop |
| `TaintGraph::new/add_node/ensure_node/node_index/node_data` | vario | vario | Costruzione grafo |
| `TaintGraph::mark_source/mark_sink/sanitize/add_edge` | `&TaintLocation`, TaintId | — | Annotazione nodi e archi |
| `TaintGraph::has_path/reachable_from/predecessors_of/shortest_path` | `&TaintLocation` | bool/Vec | Query di raggiungibilità e path |
| `TaintGraph::source_nodes/sink_nodes/source_to_sink_flows` | — | `Vec<&TaintNodeData>` / `Vec<TaintFlow>` | Tutti i flussi sorgente→sink |
| `TaintGraph::node_count/edge_count/is_dag/tainted_node_count/tainted_locations/compute_depths` | — | vario | Statistiche e preprocessing |

### taint_sinks.rs — Registry sink

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `SinkSeverity::as_str` | — | `&'static str` | Nome leggibile della severità |
| `TaintSinkSpec::is_triggered/triggering_taint` | `&[TaintId]` | bool/TaintId | Verifica se gli arg tainted scatenano il sink |
| `TaintSinkDef::new/with_cwe/with_tags/match_call` | vario | `Option<TaintFinding>` | Definizione completa di un sink con CWE e match su chiamata |
| `TaintSinkRegistry::new/with_all_sinks/insert/get/match_sink/sink_names/total_defs/sinks_by_severity` | vario | vario | Registry globale di definizioni sink |

### taint_sinks_full.rs — Catalogo sink esteso

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `SinkEntry::new/with_description/with_platforms/is_critical/affects_arg/is_windows_only/is_linux_only` | vario | vario | Entry del catalogo con metadati piattaforma |
| `TaintFlowRecord::new/at` | vario | `TaintFlowRecord` | Record di un flusso taint rilevato a runtime |
| `TaintSinkChecker::new/check_call/critical_flows/flows_of_category/total_flows` | vario | vario | Checker runtime su TaintSinksFull |
| `TaintSinksFull::new/get/len/is_empty/sinks_of_category/critical_sinks/all_names/contains` | vario | vario | Catalogo completo ~200+ sink C/POSIX/Win32 |

### taint_sink_detector.rs — Rilevamento runtime

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `SinkKind::as_str/severity/to_finding_type` | — | vario | Classificazione sink |
| `TaintedSink::new/with_arg/is_critical/source_name` | vario | `TaintedSink` | Sink raggiunto da taint con metadati |
| `SinkReport::new/add/count/is_empty/critical_sinks/by_kind/max_severity/severity_counts/sinks_at_address/summary_text` | vario | vario | Raccolta e query dei sink rilevati |
| `SinkDetector::new/with_standard_sinks/register_sink/remove_sink` | vario | — | Configurazione detector |
| `SinkDetector::check_call(callee_name, arg_taints, addr)` | `&str`, `&[TaintId]`, u64 | `Vec<TaintedSink>` | Controlla se la chiamata colpisce un sink |
| `SinkDetector::check_branch_condition(taint, addr)` | `TaintId`, u64 | `Option<TaintedSink>` | Rileva branch controllato da taint |
| `SinkDetector::check_memory_write(addr_taint, val_taint, pc)` | TaintId, TaintId, u64 | `Option<TaintedSink>` | Rileva scrittura su indirizzo/valore tainted |
| `SinkDetector::report/take_report/spec_count/is_sink` | — | vario | Accesso al report e metadati |

### sanitizer_detector.rs — Riconoscimento sanitizer

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `SanitizerEffect::fully_removes_taint/label` | — | bool/&str | Effetto del sanitizer sul taint |
| `SanitizerPattern::for_function/for_prefix` | nome, kind, effect | `SanitizerPattern` | Pattern su nome esatto o prefisso |
| `SanitizerPattern::with_in_args/with_out_args/with_confidence/matches` | vario | `SanitizerPattern`/bool | Builder e match |
| `SanitizerMatch::removes_taint/resulting_taint` | — | bool/TaintId | Risultato di un match |
| `SanitizerDetector::new/with_builtins/add_pattern/load_builtins` | — | `SanitizerDetector` | Costruzione con pattern builtins (snprintf, strncpy, …) |
| `SanitizerDetector::check_call(name, arg_taints, return_taint, addr)` | vario | `Option<SanitizerMatch>` | Verifica se la chiamata è un sanitizer |
| `SanitizerDetector::is_sanitizer_call_site/history/call_site_count/patterns/patterns_by_kind/reset_history` | — | vario | Accesso a storico e pattern |
| `SanitizerDetector::effective_return_taint/apply_to_locations/summary` | vario | TaintId/SanitizerSummary | Calcolo taint effettivo post-sanitizzazione |
| `SanitizerSummary::any_detected/dominant_kind` | — | bool/Option<&str> | Riepilogo sanitizzazione |
| `SanitizerPatternSet::new/into_detector/add/len/is_empty/matching_patterns` | vario | vario | Set builder di pattern |

### taint_summary.rs — Sommari per funzione

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `TaintPath::new/add_step/depth/passes_through/is_direct/all_locations` | vario | vario | Path sorgente→sink con step intermedi |
| `SanitizerRecord::as_str` | — | `&str` | Nome del sanitizer applicato |
| `FunctionTaintSummary::new/with_name/propagates_arg_to_return/mark_as_source/mark_as_sink/compute_return_taint/sanitizes/add_path/add_sanitizer/display_name` | vario | vario | Sommario taint di una funzione singola |
| `TaintSummary::new/insert/by_address/by_name/sources/sinks/sanitizing_functions/propagate_call/all_paths/all_source_taints` | vario | vario | Database di sommari per funzione |
| `TaintReport::from_summary/has_critical_paths/format_text` | `&TaintSummary` | vario | Report derivato da sommari |
| `TaintSummaryBuilder::new/add_sanitizer_name/add_source/add_function/auto_classify/build` | vario | `TaintSummary` | Builder con auto-classificazione source/sink |

### taint_report_generator.rs — Generazione report

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `default_severity(t: &FindingType)` | `&FindingType` | `ReportSeverity` | Severità predefinita per tipo di finding |
| `taint_source_names(taint: TaintId)` | `TaintId` | `Vec<String>` | Nomi leggibili delle sorgenti attive nel taint |
| `cwe_for_finding_type(t: &FindingType)` | `&FindingType` | `Option<&'static str>` | CWE ID per tipo di finding |
| `ReportEntry::new/with_severity/with_note/as_duplicate/summary_line` | vario | `ReportEntry`/String | Entry di report singolo finding |
| `TaintFlow::new/with_sanitizer/display` | vario | String | Flusso taint con eventuale sanitizer |
| `TaintReportConfig::verbose/ci_gate` | — | `TaintReportConfig` | Configurazioni predefinite |
| `TaintReportGenerator::new/add_finding/add_findings/set_cf_taints/set_state_snapshot/add_flow/set_analysis_time_ms/set_total_instructions/generate` | vario | `GeneratedReport` | Accumula dati e genera report |
| `TaintReportGenerator::ingest_taint_report/reset/format_text/format_json/format_markdown` | vario | String | Ingestione e formattazione |
| `GeneratedReport::has_findings/is_critical/entries_by_severity/sinks_for_type` | vario | vario | Query sul report generato |

### taint_report_extended.rs — Report esteso

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `SeverityLevel::score/from_finding` | vario | f32/SeverityLevel | Punteggio numerico della severità |
| `cwe_for(t: &FindingType)` | `&FindingType` | `&'static str` | CWE per tipo di finding |
| `TaintPath::new/add_step/length/addresses/is_long/summary` | vario | vario | Path con step dettagliati |
| `TaintPathStep::new/with_note` | vario | `TaintPathStep` | Singolo step del path |
| `TaintDFG::new/node_for/add_edge/mark_source/mark_sink/find_source_sink_paths/node_count/edge_count/location_of/reachable/all_edges/has_edges` | vario | vario | Grafo di flusso dati per il report |
| `TaintedApiCall::new/add_arg/combined_arg_taint/has_tainted_args/classify` | vario | vario | Chiamata API con argomenti tainted |
| `VulnerabilityReport::from_finding/add_path/add_call/is_severe/path_count/source_categories` | vario | vario | Report per singola vulnerabilità |
| `TaintAnalysisReport::new/add_vulnerability/add_path/add_call/vulnerability_count/severe_count/max_severity/by_severity/dangerous_calls/sink_apis/summary/build_dfg_from_paths` | vario | vario | Report aggregato dell'intera analisi |
| `TaintAnalysisSession::new/record_flow/finalize/summary/most_severe` | vario | vario | Sessione di analisi con finalizzazione |
| `TaintPathFilter::by_source_category/by_min_length/unsanitized/to_sink/count_by_type` | vario | Vec/HashMap | Filtri statici su slice di TaintPath |

### data_flow_tracker.rs — Data flow tracker

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `TaintLabel::new/union` | TaintId, ProgramPoint, str | `TaintLabel` | Etichetta taint con origine |
| `TaintLabelMap::new/get_register/set_register/clear_register/get_memory_range/set_memory_range/clear_memory_range/get_stack_slot/set_stack_slot/tainted_cell_count` | vario | vario | Mappa registri/memoria/stack → TaintLabel |
| `LibraryModel::compute_output_taint(arg_taints)` | `&[TaintId]` | `TaintId` | Modello di propagazione per funzioni di libreria |
| `builtin_library_models()` | — | `HashMap<String, LibraryModel>` | Modelli predefiniti (memcpy, strcpy, sprintf, …) |
| `FunctionTaintModel::new/compute_return_taint` | u64, `&[TaintId]` | `TaintId` | Modello di una singola funzione |
| `DataFlowTracker::new/with_default_config` | `DataFlowConfig`, `TaintPolicy` | `DataFlowTracker` | Costruzione tracker |
| `DataFlowTracker::mark_source_register/mark_source_memory` | nome/indirizzo, TaintId | — | Marcatura sorgenti |
| `DataFlowTracker::propagate_binop/propagate_load/propagate_store/propagate_call` | vario | `Option<TaintFinding>` | Propagazione per tipo di operazione |
| `DataFlowTracker::backward_slice(sink)` | `ProgramPoint` | `Vec<ProgramPoint>` | Slice backward da un sink |
| `DataFlowTracker::find_source_to_sink_paths` | — | `Vec<(ProgramPoint, ProgramPoint)>` | Tutti i path sorgente→sink |
| `DataFlowTracker::check_sink_call/register_function_summary/register_sink_point` | vario | vario | Configurazione sink e sommari |
| `DataFlowTracker::state/state_mut/edge_count/source_count` | — | vario | Accesso allo stato interno |

### dataflow_taint.rs — Analisi dataflow su CFG

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `BlockTaintState::new/get_in/get_out/set_in/set_out/merge_in/in_out_equal` | vario | vario | Stato taint IN/OUT per blocco base |
| `BasicBlock::new/add_successor/add_predecessor` | vario | `BasicBlock` | Nodo CFG con istruzioni taint |
| `ControlFlowGraph::new/add_block/add_edge/block_ids/len/is_empty` | vario | vario | Grafo CFG |
| `TaintTransferFunction::apply/apply_block` | `TaintInstr`/`BasicBlock`, `&mut TaintState` | vario | Funzione di trasferimento per istruzione e blocco |
| `TaintDependencyGraph::new/node_key/add_edge/successors/has_path/node_count/edge_count/reachable_from` | vario | vario | Grafo di dipendenza taint tra variabili |
| `DataflowTaintSolver::new/solve(cfg, initial)` | vario | `HashMap<BlockId, BlockTaintState>` | Solver fixpoint iterativo (worklist) |
| `FixpointTaintAnalyzer::new/analyze/tainted_at_exit` | vario | vario | Analisi fixpoint su CFG con query sull'uscita |

### interprocedural.rs — Analisi interprocedurale

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `FuncTaintSummary::stub/clean_return/propagate/check_sinks/display_name` | vario | `TaintId`/Vec | Sommario funzione: propagazione e verifica sink |
| `CallGraph::new/ensure_node/add_function/add_call_edge/build_from_bodies/callees/callers/function_count/has_direct_call/topo_order/transitive_callees` | vario | vario | Call graph interprocedurale con topo sort |
| `IpaTaintAnalyzer::new/with_config/register_external/populate_from_binary_view/resolve_target_name/add_function/build_call_graph/analyze(entry_points)` | vario | `Result<(), IpaError>` | Analisi IPA: scansione bottom-up del call graph |
| `IpaTaintAnalyzer::findings/summary_for/find_transitive_flows` | vario | `Vec<TaintFinding>`/Option/Vec | Risultati dell'analisi |
| `ExternalSummaryLibrary::new/register/get/apply_to/len/is_empty/with_libc` | vario | vario | Libreria di sommari esterni (libc predefinita) |

### heap_taint.rs — Tracciamento heap

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `AllocationSite::new/malloc/calloc/new_op/new_array` | u64 | `AllocationSite` | Sito di allocazione heap |
| `HeapObject::new/taint_range/sanitize_range/range_taint/total_taint/is_tainted/mark_freed/tainted_byte_count/taint_coverage` | vario | vario | Oggetto heap con taint per range di byte |
| `UseAfterFreeDetector::check/scan_freed_objects` | `&HeapTaintTracker`, u64 | `Option<TaintFinding>`/Vec | Rilevamento UAF |
| `HeapSprayDetector::new/detect/spray_groups` | usize, bool | bool/HashMap | Rilevamento heap spray |
| `HeapTaintTracker::new/alloc/free/taint_range/taint_ptr/sanitize_range/propagate_copy/get_object/get_object_mut/query_taint/tainted_ptrs/tainted_sites/live_count/freed_count/check_accesses/uaf_scan/detect_spray/spray_groups` | vario | vario | Tracker completo per oggetti heap |
| `HeapPass::run(events)` | `Vec<HeapEvent>` | `HeapPassResult` | Simulazione pass heap da lista di eventi |

### vuln_reporter.rs — Reporter vulnerabilità

| Funzione | Input | Output | Descrizione |
|----------|-------|--------|-------------|
| `CweEntry::new/command_injection/sql_injection/format_string/buffer_overflow/heap_overflow/stack_overflow/use_after_free/integer_overflow/path_traversal/null_deref/tainted_network_data/uncontrolled_memory_alloc` | vario | `CweEntry` | Entry CWE predefinite |
| `VulnReport::new/summary/source_names` | vario | String/Vec | Report di una singola vulnerabilità |
| `VulnReporter::new/with_default_config/report_command_injection/report_sql_injection/report_format_string/report_buffer_overflow/report_use_after_free/report_integer_overflow/report_path_traversal/classify_sink_alert` | vario | — | Reporter con metodi specializzati per tipo |
| `VulnReporter::reports/take_reports/total/by_severity/by_cwe/cwe_counts/text_summary/json_summary` | vario | Vec/usize/String | Accesso e serializzazione dei report |

---

## Note tecniche

- **TaintId** e `TaintedValue::taints` sono bitmask `u64` (max 64 sorgenti distinte); ogni bit rappresenta una sorgente.
- La propagazione usa `union` (OR) per operazioni binarie e `sanitize` (AND NOT) per sanitizzazione.
- Il motore primario (`TaintEngine::run`) itera su `TaintInstr`, chiama `apply_instr` per ogni istruzione e accumula `TaintFinding` nel `TaintReport`.
- L'analisi interprocedurale (`IpaTaintAnalyzer`) usa ordine topologico inverso (bottom-up) per propagare i sommari di funzione.
- Il dataflow su CFG usa un solver fixpoint iterativo con worklist (algoritmo classico MFP).
- I sink sono organizzati su tre livelli: `TaintSinkDef` (spec con CWE), `SinkDetector` (runtime match), `TaintSinksFull` (catalogo completo ~200+ funzioni).
