# rustre-sandbox-report — Public API

Crate scope: parsing of sandbox behavior records, classification of malicious indicators, IOC extraction, multi-format report rendering (JSON / HTML / Markdown / PDF / CSV), threat scoring, and MITRE ATT&CK mapping.

Total public functions: **347** across 13 modules.

---

## `lib.rs` — core types and orchestration

### `Severity`
- `score(&self) -> u8` — numeric weight (Info=0 … Critical=100).
- `parse(s: &str) -> Result<Self, ReportError>` — case-insensitive string parse.

### `Ioc`
- `new(kind: IocKind, value: impl Into<String>, confidence: u8, context: impl Into<String>) -> Self` — constructor; clamps confidence at 100.
- `is_confident(&self, threshold: u8) -> bool` — confidence threshold check.

### `IocSet`
- `new() -> Self` / `Default`
- `add(&mut self, ioc: Ioc)`
- `by_kind(&self, kind: &IocKind) -> Vec<&Ioc>` — filter by IOC kind.
- `confident(&self, threshold: u8) -> Vec<&Ioc>` — filter by minimum confidence.
- `deduplicate(&mut self)` — remove duplicates by (kind, value).
- `len(&self) -> usize`, `is_empty(&self) -> bool`
- `mock() -> Self` — preset test set.

### `AttackTechnique`
- `full_id(&self) -> &str` — sub-id if present, otherwise top-level id.

### `AttackMapping`
- `new() -> Self` / `Default`
- `add(&mut self, t: AttackTechnique)`
- `by_tactic(&self, tactic: &AttackTactic) -> Vec<&AttackTechnique>`
- `tactics_present(&self) -> Vec<String>` — sorted, deduped tactic names.
- `technique_ids(&self) -> Vec<&str>`
- `high_confidence(&self) -> Vec<&AttackTechnique>` — confidence ≥ 80.
- `from_behaviors(tags: &[&str]) -> Self` — build mapping from behavior tag list.

### `Indicator`
- `new(name, desc, severity: Severity, category: IndicatorCategory) -> Self`
- `with_ioc(self, ioc: impl Into<String>) -> Self` — builder; attach IOC string.
- `with_technique(self, id: impl Into<String>) -> Self` — builder; attach ATT&CK id.

### `Behavior`
- `new(name, desc, severity: Severity, category) -> Self`
- `with_api(self, api: impl Into<String>) -> Self` — builder; append API name.

### `ReportSection`
- `new(title, content, order: u32) -> Self`

### `ScoreEngine`
- `new() -> Self` / `Default` — default category weights.
- `compute(&self, indicators: &[Indicator]) -> u32` — weighted score, capped at 100.
- `verdict(&self, score: u32) -> Verdict` — score → verdict mapping.
- `has_critical(indicators: &[Indicator]) -> bool` — any Critical indicator present.

### `BehaviorClassifier`
- `new() -> Self`
- `classify(&self, api_calls: &[&str]) -> (Vec<Indicator>, Vec<Behavior>)` — API call list → behaviors/indicators.
- `infer_family(indicators: &[Indicator]) -> &'static str` — guess family (ransomware/spyware/trojan/…).

### `ReportRenderer`
- `new() -> Self` / `Default`
- `render_json(&self, report: &SandboxReport) -> Result<String, ReportError>`
- `render_markdown(&self, report: &SandboxReport) -> String`
- `render_html(&self, report: &SandboxReport) -> String`

### `SandboxReport`
- `new(sample, sha256) -> Self`
- `add_indicator / add_behavior / add_ttp / add_section / add_tag(&mut self, …)`
- `compute_score(&mut self)` — sets `score` and `verdict`.
- `build_attack_mapping(&mut self)` — populate ATT&CK from tags.
- `infer_family(&mut self)`
- `critical_indicators(&self) -> Vec<&Indicator>`
- `indicators_by_category(&self, cat: &IndicatorCategory) -> Vec<&Indicator>`
- `to_json(&self) -> Result<String, ReportError>`
- `to_markdown(&self) -> String`, `to_html(&self) -> String`
- `mock() -> Self`

### `ReportFormat`
- `extension(&self) -> &'static str`
- `from_extension(ext: &str) -> Result<Self, ReportError>`

### `IocCollection` (local mirror)
- `new() -> Self`, `total(&self) -> usize`, `is_empty(&self) -> bool`
- `summary_text(&self) -> String`, `to_csv(&self) -> String`
- `mock() -> Self`

### `MultiFormatRenderer`
- `new(result: SandboxReport) -> Self`
- `add_iocs(&mut self, iocs: IocCollection) -> &mut Self`
- `add_ttp_map(&mut self, ttps: HashMap<String, Vec<String>>) -> &mut Self`
- `report(&self) -> &SandboxReport`, `iocs(&self) -> Option<&IocCollection>`
- `build_json(&self) -> String`
- `build_markdown(&self) -> String`
- `build_html(&self) -> String`
- `build_csv(&self) -> String`

### Persistence helpers (free functions)
- `save(report: &str, _format: ReportFormat, path: &Path) -> Result<()>` — write report string to file.
- `load(path: &Path) -> Result<String>` — read report file.
- `save_and_reload(report: &str, format: ReportFormat, path: &Path) -> Result<String>`

### `SandboxEvent`
- `new(ts_ms, pid, kind: SandboxEventKind, detail) -> Self`

### `TimelineRenderer<'a>`
- `report(&self) -> &'a SandboxReport`
- `new(report: &'a SandboxReport) -> Self`
- `render_html(&self, report: &SandboxReport) -> String`
- `render_markdown(&self, report: &SandboxReport) -> String`
- `render_json(&self, report: &SandboxReport) -> String`

### `SandboxTimeline`
- `build(events: &[SandboxEvent]) -> Self`
- `events(&self) -> &[SandboxEvent]`
- `len(&self) -> usize`, `is_empty(&self) -> bool`
- `summary(&self) -> String`
- `start_ms(&self) -> u64`, `end_ms(&self) -> u64`, `duration_ms(&self) -> u64`

---

## `report_generator_extended.rs` — extended generator (HTML/PDF/JSON variants)

### `Verdict` (local)
- `from_score(score: u32) -> Self`
- `label(self) -> &'static str`, `html_color(self) -> &'static str`

### Serde helpers
- `serialize<S: Serializer>(s: &&'static str, ser: S) -> Result<S::Ok, S::Error>`
- `deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<&'static str, D::Error>`

### `ReportData`
- `new(name, sha256, score: u32) -> Self`
- `is_malicious(&self) -> bool`, `network_ioc_count(&self) -> usize`
- `unique_tactics(&self) -> Vec<&str>`

### `ExecSummary`
- `generate(data: &ReportData) -> Self`

### `HtmlGenerator`
- `render(data: &ReportData) -> Result<String, ReportExtError>`

### `PdfGenerator`
- `export(_data: &ReportData, _output_path: &str) -> Result<(), ReportExtError>` (placeholder)
- `pdf_html(data: &ReportData) -> Result<String, ReportExtError>`

### `JsonGenerator`
- `render(data: &ReportData) -> Result<String, ReportExtError>`
- `summary_json(data: &ReportData) -> Result<String, ReportExtError>`

### `MarkdownGenerator`
- `render(data: &ReportData) -> Result<String, ReportExtError>`

### `MultiFormatGenerator`
- `generate_all(data: &ReportData) -> HashMap<&'static str, String>`
- `html(data: &ReportData) -> Result<String, ReportExtError>`
- `json(data: &ReportData) -> Result<String, ReportExtError>`

---

## `pdf_export.rs` — low-level PDF emission

### `PdfMetadata`
- `new(...) -> Self`
- `with_subject(self, subject: impl Into<String>) -> Self`
- `with_keywords(self, kw: Vec<String>) -> Self`

### `PdfSection`
- `new(title, content) -> Self`
- `with_page_break(self) -> Self`
- `char_count(&self) -> usize`

### `PdfReport`
- `new(metadata: PdfMetadata) -> Self`
- `add_section(&mut self, section: PdfSection)`
- `section_count(&self) -> usize`, `total_chars(&self) -> usize`

### `PdfExporter`
- `new() -> Self`
- `export(&self, report: &PdfReport) -> Vec<u8>` — emit raw PDF bytes.

---

## `process_tree_render.rs` — process tree analysis

### `SuspiciousProcess`
- `new(pid: u32, name: String, cmdline: String, reasons: Vec<SuspiciousReason>) -> Self`

### Free
- `detect_lolbin(name: &str) -> Option<(SuspiciousLevel, &'static str)>` — Living-Off-the-Land binary lookup.

### `ProcessNode`
- `new(...) -> Self`
- `is_suspicious(&self) -> bool`
- `max_severity(&self) -> Option<SuspiciousLevel>`
- `descendant_count(&self) -> usize`

### `ProcessTree`
- `build(nodes: Vec<ProcessNode>) -> Self`
- `suspicious_processes(&self) -> Vec<SuspiciousProcess>`
- `render_text(&self) -> String`, `render_html(&self) -> String`
- `to_json(&self) -> Result<String, ProcessTreeError>`
- `total_count(&self) -> usize`

---

## `report_builder.rs` — HTML report composition (sections, fragments)

### `ReportSectionKind`
- `default_order(&self) -> u32`

### `ReportSectionV2`
- `new(kind: ReportSectionKind, html_body: impl Into<String>) -> Self`
- `with_title(self, t: impl Into<String>) -> Self`
- `collapsed(self) -> Self`, `not_collapsible(self) -> Self`

### Renderers (associated)
- `render(severity: &Severity) -> String` — severity badge HTML.
- `render_verdict(verdict: &Verdict) -> String`
- `render_score(score: u32) -> String`

### `HtmlReportBuilder` (V2)
- `new(report: SandboxReport) -> Self`
- `with_css(self, css: impl Into<String>) -> Self`
- `with_print_styles(self) -> Self`
- `add_network_entries / add_fs_entries / add_reg_entries(&mut self, entries: Vec<HashMap<String,String>>)`
- `add_process_rows(&mut self, rows: Vec<(u32,u32,u32,String,String)>)`
- `add_screenshots(&mut self, shots: Vec<(String,String)>)`
- `build(&self) -> String` — full HTML doc.
- `build_fragment(&self) -> String` — body fragment only.

### Free fragment builders
- `behavior_row_html(b: &Behavior) -> String`
- `indicator_row_html(i: &Indicator) -> String`
- `attack_mapping_by_tactic_html(mapping: &AttackMapping, tactic: &AttackTactic) -> String`
- `ioc_set_section_html(kind: &IocKind, set: &IocSet) -> String`

---

## `ioc_extractor.rs` — IOC extraction from raw text/logs

### `IocExtractorFlags`
- `defaults() -> Self`
- `with_emails(self) -> Self`
- `with_private_ips(self) -> Self`

### `IocExtractorConfig`
- `new() -> Self`
- `with_min_confidence(self, c: u8) -> Self`
- `include_private_ips(self) -> Self`

### `IocExtractor`
- `new() -> Self`
- `with_config(config: IocExtractorConfig) -> Self`
- `extract(&self, text: &str) -> Result<IocSet, IocExtractorError>` — regex-based IOC extraction.
- `extract_from_sources(&self, sources: &[&str]) -> Result<IocSet, IocExtractorError>`
- `extract_from_api_log(&self, log: &str) -> IocSet`

### `ExtractionStats`
- `from_ioc_set(set: &IocSet) -> Self`

### `IocExtractionPipeline`
- `new() -> Self`
- `with_config(config: IocExtractorConfig) -> Self`
- `add_source(&mut self, label: impl Into<String>, text: impl Into<String>)`
- `run(&self) -> (IocSet, ExtractionStats)`

---

## `html_report_builder.rs` — themed HTML report

### `HtmlTheme`
- `as_str(self) -> &'static str`

### `HtmlSectionFlags`
- `all() -> Self`
- `without_toc(self) -> Self`, `without_heatmap(self) -> Self`

### `HtmlReportConfig`
- `new() -> Self`
- `with_theme(self, t: HtmlTheme) -> Self`
- `with_toc(self, toc: bool) -> Self`
- `with_attack_heatmap(self, map: bool) -> Self`

### `HtmlReportBuilder`
- `new() -> Self`
- `with_config(config: HtmlReportConfig) -> Self`
- `build(&self, report: &SandboxReport) -> String`

### Free helpers
- `build_html_report(report: &SandboxReport) -> String`
- `build_html_report_themed(report: &SandboxReport, theme: HtmlTheme) -> String`
- `build_behaviors_section(behaviors: &[Behavior]) -> String`
- `build_indicators_section(indicators: &[Indicator]) -> String`
- `build_ioc_set_section(set: &IocSet) -> String`
- `attack_tactic_heading(tactic: &AttackTactic) -> String`

---

## `json_report_builder.rs` — structured JSON output + STIX

### `JsonReportFormat` helper
- `as_str(self) -> &'static str`

### `JsonMetadata`
- `new(report_id, duration_ms: u64) -> Self`
- `with_timestamp(self, ts: impl Into<String>) -> Self`

### `JsonSampleInfo`
- `new(name, sha256) -> Self`
- `with_hashes(self, sha1: Option<String>, md5: Option<String>) -> Self`
- `with_file_info(self, ...) -> Self`
- `from_report(report: &SandboxReport) -> Self`

### Entry constructors
- `JsonIndicatorEntry::from_indicator(ind: &Indicator) -> Self`
- `JsonBehaviorEntry::from_behavior(b: &Behavior) -> Self`
- `JsonAttackEntry::from_technique(t: &AttackTechnique) -> Self`

### `JsonVerdict`
- `compute(indicators: &[Indicator]) -> Self`

### `JsonReport`
- `from_sandbox_report(report: &SandboxReport) -> Self`
- `to_json_pretty(&self) -> Result<String, JsonReportError>`
- `to_json_compact(&self) -> Result<String, JsonReportError>`
- `high_critical_count(&self) -> usize`
- `unique_tactics(&self) -> Vec<String>`
- `iocs_of_type(&self, ioc_type: &str) -> Vec<&str>`
- `to_stix_bundle(&self) -> Result<String, JsonReportError>` — STIX 2.1 bundle.

### `JsonReportDiff`
- `compute(before: &JsonReport, after: &JsonReport) -> Self`
- `has_changes(&self) -> bool`
- `summary(&self) -> String`

### `JsonReportBuilder`
- `new() -> Self`
- `metadata / sample / verdict(self, …) -> Self`
- `add_indicator / add_behavior / add_ioc / add_attack_technique / add_section(self, …) -> Self`
- `with_score_breakdown(self) -> Self`
- `build(self) -> Result<JsonReport, JsonReportError>`

### Free
- `build_json_report(report: &SandboxReport) -> Result<String, JsonReportError>`
- `build_json_report_compact(report: &SandboxReport) -> Result<String, JsonReportError>`
- `attack_mapping_summary_line(mapping: &AttackMapping) -> String`
- `indicator_category_counts(indicators: &[Indicator]) -> HashMap<String, usize>`
- `ioc_set_total(set: &IocSet) -> usize`

---

## `mitre_mapping_full.rs` — full MITRE ATT&CK knowledge base

### `Tactic`
- `name(&self) -> &'static str`

### `SubTechnique`
- `new(...) -> Self`
- `with_indicator(self, ind: impl Into<String>) -> Self`

### `Technique`
- `new(...) -> Self`
- `with_indicator(self, ind: impl Into<String>) -> Self`
- `with_sub(self, sub: SubTechnique) -> Self`
- `with_platform(self, p: impl Into<String>) -> Self`
- `find_sub(&self, id: &str) -> Option<&SubTechnique>`

### `TechniqueEvidence`
- `new(technique_id, confidence: u8, source) -> Self`
- `add(&mut self, ev: impl Into<String>)`

### `TechniqueDb`
- `new() -> Self`
- `add(&mut self, t: Technique)`
- `get(&self, id: &str) -> Option<&Technique>`
- `by_tactic(&self, tactic: &Tactic) -> Vec<&Technique>`
- `len(&self) -> usize`, `is_empty(&self) -> bool`
- `search(&self, query: &str) -> Vec<&Technique>`
- `all_ids(&self) -> Vec<&str>`
- `build() -> Self` — preload bundled MITRE techniques.

### `AttackMatcher`
- `match_evidence(&self, api_calls: &[&str]) -> Vec<TechniqueEvidence>` — API → matched techniques.
- `techniques_for_tactic(&self, tactic: &Tactic) -> Vec<&Technique>`
- `get(&self, id: &str) -> Option<&Technique>`
- `total_count(&self) -> usize`

---

## `html_reporter.rs` — full HTML reporter with theme, screenshots, timeline

### `HtmlTheme`
- `to_css(&self) -> String`

### `ScreenshotEntry`
- `new(timestamp_ms: u64, data_base64, caption) -> Self`
- `to_html_figure(&self) -> String`

### `TimelineEvent`
- `new(...) -> Self`
- `severity_class(&self) -> &'static str`

### `HtmlReportOptions`
- `all() -> Self`

### `HtmlReporter`
- `new() -> Self`
- `with_theme(self, theme: HtmlTheme) -> Self`
- `with_options(self, opts: HtmlReportOptions) -> Self`
- `with_screenshots(self, screenshots: Vec<ScreenshotEntry>) -> Self`
- `with_timeline(self, events: Vec<TimelineEvent>) -> Self`
- `with_ioc_collection(self, iocs: IocCollection) -> Self`
- `with_ttp_map(self, map: HashMap<String, Vec<String>>) -> Self`
- `render(&self, report: &SandboxReport) -> String`

### `HtmlReporterBuilder`
- `new() -> Self`
- `report(self, r: SandboxReport) -> Self`
- `theme / options / screenshots / timeline / ioc_collection / ttp_map(self, …) -> Self`
- `build(self) -> String`

### Free fragment helpers
- `render_timeline_event_badge(event: &TimelineEvent) -> String`
- `render_behavior_li(behavior: &Behavior) -> String`
- `render_indicator_fragment(indicator: &Indicator) -> String`
- `render_ioc_set_summary(kind: &IocKind, set: &IocSet) -> String`
- `render_attack_mapping(mapping: &AttackMapping, technique: &AttackTechnique) -> String`

---

## `network_timeline.rs` — network event timeline

### `Protocol`
- `as_str(self) -> &'static str`
- `from_port(port: u16) -> Self`

### `NetworkEvent`
- `tcp(...) -> Self` — TCP event constructor.
- `dns(timestamp_ms: u64, src_ip, query) -> Self`
- `is_dns(&self) -> bool`, `is_https(&self) -> bool`
- `total_bytes(&self) -> u64`

### `NetworkTimeline`
- `new() -> Self`
- `add(&mut self, event: NetworkEvent)`
- `extend(&mut self, events: impl IntoIterator<Item = NetworkEvent>)`
- `events(&self) -> &[NetworkEvent]`
- `len(&self) -> usize`, `is_empty(&self) -> bool`
- `dns_events(&self) -> Vec<&NetworkEvent>`, `https_events(&self) -> Vec<&NetworkEvent>`
- `in_window(&self, start_ms: u64, end_ms: u64) -> Vec<&NetworkEvent>`
- `unique_dst_ips(&self) -> Vec<&str>`
- `total_bytes(&self) -> u64`
- `by_protocol(&self) -> HashMap<String, Vec<&NetworkEvent>>`
- `connection_map(&self) -> ConnectionMap`
- `dns_map(&self) -> DnsResolutionMap`
- `chart_data_json(&self, bucket_ms: u64) -> String` — bucketed traffic chart data.

### `ConnectionMap`
- `from_timeline(timeline: &NetworkTimeline) -> Self`
- `unique_endpoints(&self) -> Vec<&str>`
- `len(&self) -> usize`, `is_empty(&self) -> bool`
- `on_port(&self, port: u16) -> Vec<&str>`
- `contact_count(&self, endpoint: &str) -> usize`

### `DnsResolutionMap`
- `from_timeline(timeline: &NetworkTimeline) -> Self`
- `domains(&self) -> Vec<&str>`
- `contains(&self, domain: &str) -> bool`
- `len(&self) -> usize`, `is_empty(&self) -> bool`

---

## `json_reporter.rs` — Cuckoo / AnyRun / Native JSON formats

### `JsonAttackTechnique`
- `from_attack_technique(t: &AttackTechnique) -> Self`
- `to_json(&self) -> Value`

### `JsonReporter`
- `new(format: JsonReportFormat) -> Self`
- `cuckoo() -> Self`, `any_run() -> Self`, `native() -> Self`
- `pretty(self, v: bool) -> Self`
- `with_ioc_collection(self, iocs: IocCollection) -> Self`
- `with_analysis_id(self, id: impl Into<String>) -> Self`
- `platform(self, p: impl Into<String>) -> Self`
- `serialize(&self, report: &SandboxReport) -> Result<String, serde_json::Error>` — dispatch on format.

### Free
- `serialize_attack_mapping(mapping: &AttackMapping) -> Value`
- `serialize_iocs_flat(...) -> Value`

### `AttackReportGenerator`
- `new() -> Self`
- `add_evidence(&mut self, technique_id, evidence)`
- `generate_attack_report(&self, report: &SandboxReport) -> Value`

### Free converters
- `behavior_to_json(b: &Behavior) -> Value`
- `indicator_to_json(i: &Indicator) -> Value`
- `tactic_to_string(t: &AttackTactic) -> String`

---

## `pdf_reporter.rs` — text / paginated PDF text reporter

### `BorderChar`
- `char(self) -> char`

### `PdfSectionFlags`
- `all() -> Self`, `none() -> Self`
- `without_toc(self) -> Self`

### `TextReportOptions`
- `include_header_box / include_toc / include_indicators / include_behaviors / include_iocs / include_attack / include_dropped / include_sections(&self) -> bool`

### `TextAlign`
- `right(self) -> Self`

### `PdfTextReporter`
- `new() -> Self`
- `with_options(self, opts: TextReportOptions) -> Self`
- `with_ioc_collection(self, iocs: IocCollection) -> Self`
- `render(&self, report: &SandboxReport) -> String` — formatted text report.

### `PaginatedPdfReporter`
- `new(reporter: PdfTextReporter) -> Self`
- `page_size(self, n: usize) -> Self`
- `render_paginated(&self, report: &SandboxReport) -> Vec<String>` — one string per page.
- `render(&self, report: &SandboxReport) -> String`
- `write_to_file(&self, report: &SandboxReport, path: &Path) -> std::io::Result<()>`

### `SeverityCounter`
- `new(label, severity: Severity, count: usize) -> Self`
- `to_line(&self) -> String`
