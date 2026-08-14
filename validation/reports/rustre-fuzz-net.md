# rustre-fuzz-net — Public Function Inventory

Crate: `rustre-fuzz-net` — Network/stateful protocol fuzzer (Boofuzz-inspired). Describe a protocol as a state-machine with typed fields; drive the state machine while mutating fuzz-marked fields.

Totale funzioni pubbliche: **484**

---

## `lib.rs` — Core API (root crate)

### FieldDef (typed protocol field)
- `pub fn new(name: impl Into<String>, field_type: FieldType, fuzz: bool) -> Self` — costruisce un campo definito di un messaggio.

### MessageDef (messaggio composto da campi)
- `pub fn new(name: impl Into<String>, fields: Vec<FieldDef>) -> Self` — nuovo messaggio.
- `pub fn serialise(&self) -> Result<Vec<u8>, FuzzNetError>` — serializza i campi in byte.
- `pub fn mutate(&mut self, rng: &mut dyn RngCore)` — applica mutazioni casuali ai campi marcati fuzz.
- `pub fn estimated_len(&self) -> usize` — lunghezza stimata serializzata.
- `pub fn fuzz_field_count(&self) -> usize` — numero di campi fuzzabili.
- `pub fn field(&self, name: &str) -> Option<&FieldDef>` / `field_mut(...) -> Option<&mut FieldDef>` — accesso campo per nome.

### ProtocolDef (definizione protocollo come grafo di stati)
- `pub fn new(initial_state: impl Into<String>, states: HashMap<String, ProtocolState>) -> Self` — protocollo da stati.
- `pub fn state_names(&self) -> Vec<&str>` / `state_count() -> usize` / `edges() -> Vec<(&str, &str)>` — introspezione grafo.
- `pub fn validate(&self) -> Vec<String>` — restituisce errori strutturali del protocollo.

### TcpTransport / UdpTransport
- `pub fn new(addr: impl Into<String>) -> Self` — costruttore transport TCP/UDP.

### CrashLog
- `pub fn new() -> Self`
- `pub fn log(&mut self, input: Vec<u8>, reason: impl Into<String>, state: impl Into<String>)` — registra crash.
- `pub fn unique_reasons(&self) -> Vec<&str>`
- `pub fn by_reason(&self, reason: &str) -> Vec<&CrashEntry>` / `by_state(state) -> Vec<&CrashEntry>`
- `pub fn clear(&mut self)` / `dedup(&mut self)` / `summary(&self) -> String`

### FuzzSession (sessione principale)
- `pub fn new(protocol: ProtocolDef, transport: Box<dyn Transport>) -> Self`
- `pub fn reset(&mut self)` / `current_state(&self) -> &str`
- `pub async fn run_once(&mut self) -> Result<(), FuzzNetError>` — singola iterazione.
- `pub async fn run(&mut self, count: u64) -> Result<(), FuzzNetError>` — N iterazioni.
- `pub fn stats(&self) -> SessionStats` / `most_visited_state() -> Option<&str>`

### NetFuzzer (wrapper alto livello)
- `pub fn new(protocol: ProtocolDef, transport: Box<dyn Transport>) -> Self`
- `pub async fn fuzz(&mut self, count: u64) -> Result<(), FuzzNetError>`
- `pub fn stats(&self) -> SessionStats`

### ProtocolBuilder (builder fluente del protocollo)
- `pub fn new(initial_state: impl Into<String>) -> Self`
- `pub fn add_terminal(self, name: impl Into<String>) -> Self`
- `pub fn add_transition(...) -> Self` (firma con from/to/message)
- `pub fn add_transition_with_expect(...) -> Self`
- `pub fn build(self) -> ProtocolDef`

### MessageBuilder (builder fluente del messaggio)
- `pub fn new(name: impl Into<String>) -> Self`
- `pub fn static_bytes(self, name, data: Vec<u8>) -> Self`
- `pub fn fuzz_blob(self, name, data: Vec<u8>) -> Self`
- `pub fn fuzz_u8/u16/u32(self, name, value) -> Self`
- `pub fn fuzz_random(self, name, min: usize, max: usize) -> Self`
- `pub fn fuzz_string(self, name, max_len: usize) -> Self`
- `pub fn size_of(self, name, target_field: impl Into<String>) -> Self` — campo lunghezza dinamica.
- `pub fn build(self) -> MessageDef`

### Helpers globali
- `pub fn apply_strategy(msg: &mut MessageDef, strategy: MutationStrategy, rng: &mut dyn RngCore)` — applica strategia.
- `pub fn frame_u32_le/be(payload: &[u8]) -> Result<Vec<u8>, FuzzNetError>` — incornicia payload con header lunghezza u32.
- `pub fn decode_frame_u32_le/be(buf: &[u8]) -> Option<(usize, Vec<u8>)>` — decodifica frame u32.
- `pub fn xor_checksum(data: &[u8]) -> u8` / `add_checksum(data: &[u8]) -> u8` — checksum semplici.
- `pub fn interesting_int_mutation(current: i64, size_bytes: u8, rng: &mut dyn RngCore) -> i64` — mutazione su valori "interesting" (boundary).

### CoverageMap (lib.rs)
- `pub fn new() -> Self`
- `pub fn record(&mut self, state: impl Into<String>, transition_idx: usize)`
- `pub fn coverage_pct(&self, total_transitions: usize) -> f64`
- `pub fn is_covered(&self, state: &str, transition_idx: usize) -> bool`

### Pattern matching
- `pub fn matches(&self, buf: &[u8]) -> bool` — controlla pattern in risposta.
- `pub fn find(&self, buf: &[u8]) -> Option<usize>`

### Corpus (lib.rs)
- `pub fn new() -> Self`
- `pub fn add(&mut self, data: Vec<u8>, tag: impl Into<String>, state: impl Into<String>)`
- `pub fn pick(&self, rng: &mut dyn RngCore) -> Option<&CorpusEntry>`
- `pub fn by_tag(&self, tag: &str) -> Vec<&CorpusEntry>` / `dedup(&mut self)`

### ReplaySession (lib.rs)
- `pub fn new(inputs: Vec<Vec<u8>>, transport: Box<dyn Transport>) -> Self`
- `pub async fn run(&mut self) -> Result<ReplayResult, FuzzNetError>`

### Stack/queue input
- `pub fn new(max_depth: usize) -> Self` / `push(&mut self, msg: &MessageDef)` / `pop(&mut self) -> Option<MessageDef>`

### Loader YAML
- `pub fn load_from_yaml(yaml: &str) -> Result<Self, FuzzNetError>` — costruisce ProtocolDef da YAML.
- `pub fn load_from_file(path: &Path) -> Result<Self, FuzzNetError>`

### StateMachineDriver (lib.rs)
- `pub fn new(protocol: ProtocolDef) -> Self`
- `pub fn current_state(&self) -> &str` / `transition_history() -> &[String]`
- `pub fn drive_to_state(&mut self, target: &str) -> Result<(), FuzzNetError>` — naviga verso uno stato.
- `pub fn reset(&mut self)` / `can_advance(&self) -> bool`

### Classificatore crash
- `pub fn classify(response: &[u8], expected: &[u8]) -> CrashKind`
- `pub fn classify_reason(reason: &str) -> CrashKind`
- `pub fn is_interesting(kind: CrashKind) -> bool`

---

## `protocol_model.rs` — Modello protocollo riusabile

### MessageField
- `name() -> &str`, `is_fuzz_target() -> bool`, `default_bytes() -> Vec<u8>` — accessori metadati campo.

### MessageType
- `new(name, fields: Vec<MessageField>) -> Self`, `with_magic(magic: Vec<u8>) -> Self`
- `field_count() / fuzz_field_count() -> usize`, `get_field(name: &str) -> Option<&MessageField>`
- `validate(&self, data: &[u8]) -> bool` — controlla che bytes rispettino il tipo.
- `default_bytes(&self) -> Vec<u8>` — bytes di base.

### ProtocolConstraint (vincolo di forma)
- `check(&self, data: &[u8]) -> bool` — soddisfatto?
- `enforce(&self, data: &mut Vec<u8>) -> bool` — modifica per soddisfarlo.

### ProtocolGenerator
- `new(seed: u64) -> Self`
- `generate(&mut self, msg_type: &MessageType) -> Vec<u8>` — istanza valida.
- `generate_many(msg_type, count) -> Vec<Vec<u8>>`
- `mutate(&mut self, data: &[u8], msg_type: &MessageType) -> Vec<u8>` — mutazione tipata.

### ConstraintValidator
- `new(constraints: Vec<ProtocolConstraint>) -> Self`, `auto_fix(...) -> Self`
- `is_valid(data) -> bool`, `fix_or_check(data: &mut Vec<u8>) -> bool`
- `filter(messages) -> Vec<Vec<u8>>`, `filter_and_fix(messages) -> Vec<Vec<u8>>`

### ProtocolModel (collezione di MessageType)
- `new(name) -> Self`, `add_type(msg)`, `get_type(name) -> Option<&MessageType>`, `type_count()`
- `to_json/from_json/save_to_file/load_from_file` — serializzazione.
- `type_names() -> Vec<&str>`, `validate() -> Vec<String>`

### ModelFuzzer
- `new(model, seed) -> Self`, `set_constraints(...)`, `generate(type_name, count) -> Vec<Vec<u8>>`
- `mutate(type_name, data) -> Vec<u8>`, `validity_ratio() -> f64` — metrica validità.

---

## `mutation_engine.rs` — Motore mutazioni

- `ProtocolMutation::apply(&self, data: &mut Vec<u8>, rng: &mut dyn RngCore)` — applica una specifica mutazione.
- `dedup_key(&self) -> String` — chiave per deduplica.
- `MutationHistory::new(max_records: usize)`, `record(mut, before, after) -> bool`, `unique_count() -> usize`, `clear()`, `novel_records() -> Vec<&MutationRecord>` — tracker storico.
- `MutationEngine::new(strategy)`, `generate_mutation(data) -> Option<ProtocolMutation>`, `mutate(data) -> Option<bool>`, `mutate_n(data, n)`, `total_bytes_mutated() -> usize`.

---

## `crash_detector.rs` — Rilevamento crash

- `CrashSignal::severity() -> u8`, `name() -> &'static str` — severità del segnale.
- `CrashReport::new(...)`, `severity() -> u8`.
- Free fns: `bucket_hash(signal, input) -> u64`, `detect_sanitizer_output(text) -> Option<String>`, `detect_crash_string(data) -> Option<(String, usize)>`.
- `CrashDetector::new(config) / with_default_config()`, `analyse(...)`, `unique_crashes()/total_crashes()/total_inputs()/crash_rate()`, `reports() -> impl Iterator`, `reports_by_severity()`, `clear()`.
- `HangDetector::new(timeout)`, `register() -> u64`, `complete(id)`, `tick()`, `hang_count()`, `hangs()`.
- `ReproductionResult::reproduced(...)/not_reproduced(...)`, `is_confirmed() -> bool`.
- `Minimiser::new(max_iterations)`, `minimise<F>(input, predicate) -> Vec<u8>` — minimizza input crash.
- `CrashSummary::from_reports(reports) -> Self`.

---

## `crash_analyzer.rs` — Analisi/categorizzazione crash

- `CrashType::from_reason(reason) -> Self` — classifica un crash da una stringa motivo.
- `CrashRecord::from_reason(...)`, `is_critical() -> bool`.
- `CrashDeduplicator::new()`, `submit(record) -> bool`, `iter() -> impl Iterator`, `clear()`, `by_type(ct) -> Vec<&CrashRecord>`.
- `CrashReport::from_deduplicator(dedup, total) -> Self`, `has_critical() -> bool`, `count_for(type_name) -> u64`.
- `CrashAnalyzer::new()`, `submit_crash(...)`, `classify(reason) -> CrashType`, `generate_report() -> CrashReport`, `crashes_of_type(ct)`, `reset()`.

---

## `network_harness.rs` — Harness TCP/UDP

- `AttemptResult::is_crash() -> bool`.
- `ResponseScorer::new()`, `add_error_pattern(...)`, `feed_baseline(response)`, `score(response) -> u32`, `describe_anomaly(response) -> Option<String>`.
- `ConnectionPool::new(addr, max_size, connect_timeout_ms)`, `async acquire() -> Result<TcpStream, HarnessError>`, `release(conn)`, `pool_size()`, `reuse_count()`.
- `TcpFuzzHarness::new(config)`, `async attempt(input) -> AttemptResult`, `async run<F>(count, generator)`, `stats()`, `feed_baseline_response(...)`.
- `UdpFuzzHarness::new(config)`, `async attempt(input)`, `async run<F>(count, generator)`, `stats()`.
- `HarnessStats::crash_rate() -> f64`, `success_rate() -> f64`.
- `CrashDeduplicator::new()`, `is_new(result) -> bool`, `unique_crashes() -> usize`.
- `InputGenerator::new(seed: Vec<u8>)`, `generate(n: u64) -> Vec<u8>`.

---

## `network_state_machine.rs` — FSM di rete

- `State::new(id, name)`, `name() -> String`.
- `FieldType::generate(rng) -> Vec<u8>`, `mutate(rng)` — generazione/mutazione campo.
- `MessageTemplate::new(name)`, `add_field(field)`, `generate(rng) -> Vec<u8>`, `generate_mutated(rng) -> Vec<u8>`.
- `Transition::new(from, to, label, message)`, `check_guard(current, msg) -> bool`, `execute_action(msg) -> Option<Vec<u8>>`.
- `NetworkStateMachine::new(initial_state)`, `add_transition(t)`, `available_transitions() -> Vec<&Transition>`, `step(rng) -> Option<Vec<u8>>`, `reset()`.
- `StateExplorer::new()`, `explore_bfs(fsm)`, `state_names() -> Vec<String>`.
- `FuzzSessionRunner::run_session() -> Vec<Vec<u8>>`, `run_sessions(n) -> usize`, `unique_messages() -> Vec<&Vec<u8>>`.
- `pub fn http_like_state_machine() -> NetworkStateMachine` — costruisce FSM HTTP-like predefinita.

---

## `protocol_state_machine.rs` — FSM tipato

- `Transition::send_payload() -> Option<&[u8]>`, `expected_response() -> Option<&[u8]>`.
- `Transition::silent(name, to)`, `send(name, to, payload)`, `send_recv(...)`, `with_description(desc)`.
- `State::new(name)`, `add_transition(t)`, `transition_by_name(name)`, `transition_to(dest)`, `total_weight() -> u32`, `weighted_pick(rnd) -> Option<&Transition>` — selezione probabilistica.
- `StateGraph::new()`, `add_state(state) -> Result<...>`, `state(name)`, `state_mut(name)`, `len()/is_empty()`, `states() -> impl Iterator`, `state_names() -> Vec<&str>`, `edges() -> Vec<(&str, &str)>`, `validate() -> Vec<String>`, `topo_sort() -> Result<Vec<String>, ...>`, `reachable_from(start) -> Vec<String>`.
- `ProtocolStateMachine::new(...)`, `current_state() -> &str`, `current() -> &State`, `is_terminal()`, `reset()/full_reset()`, `advance_to(dest) -> Result<&Transition, ...>`, `advance_random(rnd) -> Option<&Transition>`, `history() -> &[String]`, `visit_counts() -> HashMap<String, usize>`, `next_state(transition_name) -> Result<&str, ...>`, `reachable() -> Vec<String>`.
- `StateMachineBuilder::new()`, `initial(name)`, `add_state(state)`, `try_add_state(state) -> Result<...>`, `build() -> Result<ProtocolStateMachine, ...>`.
- `pub fn next_state(graph: &StateGraph, from_state, transition_name) -> Option<&str>` — helper standalone.

---

## `protocol_state_fuzzer.rs` — Fuzzer state-aware

- `ProtocolState::new(id, description)`, `terminal()`, `add_transition(target_id)`.
- `StateTransition::new(...)`, `with_response(resp)`, `mutated_message(rng) -> Vec<u8>`.
- `CoverageTracker::new()`, `record_state(state)`, `record_transition(from, to)`, `state_coverage_pct(total) -> f64`, `transition_coverage_pct(total) -> f64`, `has_reached(state_id) -> bool`, `most_visited() -> Option<&str>`.
- `FuzzSequence::new(iteration)`, `push_step(from, to, label, msg)`, `total_bytes() -> usize`, `depth() -> usize`.
- `StateFuzzer::new(...)`, `outgoing(state_id) -> Vec<&StateTransition>`, `find_path(start, target) -> Option<Vec<String>>` — pathfinding.
- `generate_sequence() -> FuzzSequence`, `run(count: u64)`, `state_coverage_pct() / transition_coverage_pct() -> f64`, `violation_count() -> usize`, `validate() -> Vec<String>`, `uncovered_transitions() -> Vec<&StateTransition>`, `stats() -> FuzzerStats`.
- `StateFuzzerBuilder::new(initial)`, `add_state(state)`, `add_transition(from, to, label, template)`, `build() -> StateFuzzer`.

---

## `protocol_fuzzer.rs` — Fuzzer di protocollo generico

- `FuzzTarget::tcp(host, port)/udp(host, port)/tls(host, port, verify_peer)`, `address() -> String`.
- `FieldFuzzer::new()`, `mutate(msg, rng) -> Vec<FieldMutationRecord>`, `mutate_field(...)`.
- `StateContext::new(protocol)`, `reset()`, `current_state()`, `advance(to)`, `available_transitions() -> &[Transition]`, `is_terminal()`, `pick_transition(rng) -> Option<&'a Transition>`, `history()`, `from_edge_map(...)`.
- `MessageFuzzer::new()`, `choose_and_mutate(...)`, `valid_messages(machine) -> Vec<&MessageDef>`.
- `SessionReplay::new(note)`, `record(data, state)`, `total_bytes()`, `matches(expected: &[Vec<u8>]) -> bool`, `to_hex_dump() -> String`.
- `ProtocolFuzzer::new(protocol, target)`, `run_iteration() -> Vec<FieldMutationRecord>`, `last_replay() -> Option<&SessionReplay>`, `throttle() -> Duration` — rate limit.

---

## `packet_mutator.rs` — Mutazioni a livello byte/pacchetto

Free fns: `flip_bit`, `substitute_byte`, `insert_bytes`, `delete_bytes`, `overwrite_range`, `http_inject_header`, `dns_label_overflow`, `tls_version_confusion` — operazioni atomiche su `&[u8] -> Vec<u8>`.

- `FieldMutation::new(field_name, offset, len, op)`, `apply(data) -> Vec<u8>`.
- `ChecksumCorrupter::new(kind, offset)`, `corrupt(data) -> Vec<u8>`, `fix(data) -> Vec<u8>`.
- `LengthFieldCorrupter::new(offset, field_bytes, strategy)`, `corrupt(data) -> Vec<u8>`.
- `MutatorStep::apply(data) -> Vec<u8>`, `name() -> &'static str`.
- `PacketMutator::new(label)`, `add_step(step) -> &mut Self`, `with_step(step) -> Self`, `apply(data) -> Vec<u8>`, `label()`, `step_count()`.
- Helpers: `all_bit_flips(data) -> Vec<(usize, Vec<u8>)>`, `interesting_int_variants(data) -> Vec<Vec<u8>>`.
- `MutatorChain::new()`, `add(mutator, weight)`, `select(seed) -> Option<&PacketMutator>`, `apply_random(data, seed) -> Option<(&str, Vec<u8>)>`, `mutator_count()`, `apply_count() -> u64`, `apply_all(data) -> Vec<(&str, Vec<u8>)>`.
- Costruttori predefiniti: `http_chain()`, `dns_chain()`, `tls_chain()`.
- `Stats::record(step_name, output_len)`, `top_n(n) -> Vec<(&str, u64)>`.

---

## `coverage_guided_fuzzer.rs` — Fuzzer guidato dalla coverage

- `CoverageBitmap::new()`, `reset()`, `has_new_bits(virgin_map) -> bool`, `update_virgin_map(virgin_map) -> u32`, `count_bits() -> usize`, `edge_count() -> u64`, `merge(other)`, `classify_counts()`.
- `CorpusEntry::new(id, data, coverage, unique_bits)`, `compute_score()`, `is_favored() -> bool`.
- `Corpus::new()`, `add_initial(data, coverage)`, `add_from_mutation(data, coverage, parent_id, depth) -> Option<u64>`, `next_entry() -> Option<&mut CorpusEntry>`, `coverage_percentage() -> f64`, `stats() -> CorpusStats`.
- `EnergyScheduler::new()`, `compute_energy(entry, queue_cycle) -> u32`.
- `Minimizer::new()`, `minimize<F>(data, test_fn) -> Vec<u8>`.
- `SimpleRng::new(seed)`, `next_u64/usize/u8/bool/u16/u32` — RNG locale leggero.
- `CoverageFuzzer::new(config)`, `add_seed(data, coverage)`, `mutate(entry_data) -> Vec<Vec<u8>>`, `record_crash(data, crash_type, parent_id)`, `stats() -> FuzzerStats`.
- `TokenDictionary::new(tokens)`, `insert_token(data, pos, rng) -> Vec<u8>`, `overwrite_token(data, pos, rng) -> Vec<u8>`.

---

## `grammar_fuzzer.rs` — Generazione grammar-based

- `GrammarNode::lit(s)/nt(name)/optional()/repeat(min, max)` — costruttori di nodi.
- `pub fn lit(s: &str) -> GrammarNode` — helper standalone.
- `Grammar::new(start)`, `rule(name, node) -> Self`, `start_node() -> Option<&GrammarNode>`, `rule_count() -> usize`.
- `GrammarFuzzer::new(max_depth, max_length)`, `generate() -> Vec<u8>`, `generate_n(n) -> Vec<Vec<u8>>`, `generate_string() -> String`.
- Grammatiche predefinite: `http11_grammar() -> Grammar`, `json_grammar() -> Grammar`, `xml_grammar() -> Grammar`, `tls_client_hello_grammar() -> Grammar`.

---

## `dns_fuzzer.rs` — Fuzzer DNS

- `DnsQType::as_u16(self) -> u16`, `DnsRCode::as_u16(self) -> u16`, `DnsFlags::to_u16(self) -> u16` — encoding enum DNS.
- `DnsQuestion::new(name, qtype)`, `serialize() -> Vec<u8>`.
- `DnsPacket::new_query(id, question)`, `serialize() -> Vec<u8>`.
- Free fns: `encode_dns_name(name) -> Vec<u8>`, `build_edns0(udp_payload_size, dnssec_ok, options) -> Vec<u8>`.
- `DnsMutation::new(bytes, label, mutation)`.
- `pub fn apply_dns_mutation(...)` — applica mutazione DNS specifica.
- `DnsFuzzOutcome::is_anomalous() -> bool`.
- `DnsFuzzer::new(target: SocketAddr)`, `set_base_name(name)`, `set_recv_timeout_ms(ms)`, `add_mutation(m)`, `async run_all() -> Vec<(DnsPacket, DnsFuzzOutcome)>`, `results() -> &[(DnsPacket, DnsFuzzOutcome)]`, `anomalous_results() -> Vec<&(...)>`, `stats() -> DnsFuzzStats`.

---

## `tls_fuzzer.rs` — Fuzzer TLS

- `TlsVersion::name(self) -> &'static str`.
- `TlsExtension::new(ext_type, data)`, `serialize() -> Vec<u8>`, `server_name(hostname) -> Self`, `alpn(protocols) -> Self`, `supported_versions(versions) -> Self`.
- `ClientHelloBuilder::new() / default()`, `legacy_version(v)`, `random(r: [u8; 32])`, `session_id(id)`, `cipher_suites(cs)`, `compression_methods(cm)`, `add_extension(ext)`, `build_payload() -> Vec<u8>`, `build_record() -> Vec<u8>`.
- Free fns: `build_handshake_record(msg_type, body, version) -> Vec<u8>`, `fragment_record(record, fragment_size) -> Vec<Vec<u8>>`.
- `TlsFuzzStrategy::apply(base) -> Vec<MutatedRecord>` — strategie di mutazione TLS.
- `TlsFuzzResult::is_anomalous() -> bool`.
- `TlsFuzzer::new(target)`, `add_strategy(s)`, `async run_all() -> Vec<(String, TlsFuzzResult)>`, `results() -> &[...]`, `anomalous_results() -> Vec<&(...)>`.

---

## `replay_engine.rs` — Engine di replay

- `PacketSpec::new(payload)`, `with_label(label)`, `has_response() -> bool`, `response_str() -> String`.
- `ReplaySession::tcp(name, target) / udp(name, target)`, `add_packet(spec)`, `success_count() / failure_count() -> usize`, `all_responses() -> Vec<&[u8]>`, `mean_rtt_us() -> u64`, `run_tcp() -> Result<(), ReplayError>`, `run_udp() -> Result<(), ReplayError>`.
- `ReplayEngine::new()`, `add_session(session)`, `session_count()`, `run_all() -> Result<usize, ReplayError>`, `run_one(index) -> Result<(), ReplayError>`, `aggregate_stats() -> ReplayStats`.
- `pub fn replay_sequence(...)` — riproduce una sequenza completa di pacchetti.

---

## Note di dominio

- Crate orientato a fuzzing di protocolli di rete con tre direttrici:
  1. **Modello del messaggio** (`MessageDef`, `MessageType`, `FieldType`) con costruzione fluente e serializzazione.
  2. **Modello dello stato** (`ProtocolDef`, `ProtocolStateMachine`, `NetworkStateMachine`, `StateFuzzer`) per pilotare protocolli stateful.
  3. **Motori di mutazione** (bit-level su byte, livello campo, livello strategia tipata, grammar-based, coverage-guided).
- Tre fuzzer specializzati (DNS, TLS, HTTP-grammar) e harness async TCP/UDP con pool connessioni.
- Rilevamento crash con bucketing, dedup, repro, minimizzazione e classificazione semantica.
- Engine di replay per riproducibilità delle sessioni.
