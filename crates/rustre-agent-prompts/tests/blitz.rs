//! Blitz test suite for `rustre-agent-prompts`.
//! Exercises public surfaces of lib.rs core types and a few helper modules.

use std::collections::HashMap;

use rustre_agent_prompts::{
    analysis_prompt_builder::{format_disasm_snippet, format_hex_dump},
    builtin_prompt_templates,
    engine,
    prompt_chain::{extract_json_field, retry_with_backoff, ChainError},
    result_parser::{
        AiMitreTechnique, AiResult, ConfidenceScore, EntityKind, ExtractedEntity, ParseConfig,
        ResultParser,
    },
    ChainStep, ContextBuilder, FewShotDatabase, FewShotExample, PromptChain, PromptError,
    PromptRegistry, PromptRenderer, PromptTemplate, SpecPromptError, SpecPromptTemplate,
    TemplateRegistry, TemplateVar,
};

// ──────────────────────────────────────────────────────────────────────────
// PromptRenderer
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn render_empty_template() {
    let out = PromptRenderer::render("", &HashMap::new()).unwrap();
    assert_eq!(out, "");
}

#[test]
fn render_template_with_only_text() {
    let out = PromptRenderer::render("just text, no vars", &HashMap::new()).unwrap();
    assert_eq!(out, "just text, no vars");
}

#[test]
fn render_unclosed_placeholder_yields_error() {
    let err = PromptRenderer::render("hello {{name", &HashMap::new()).unwrap_err();
    assert!(matches!(err, PromptError::MissingVariable(_)));
}

#[test]
fn render_substitutes_value_with_braces_inside() {
    // value contains "{{" — renderer must not re-substitute the value.
    let mut vars = HashMap::new();
    vars.insert("a".to_string(), "{{b}}".to_string());
    vars.insert("b".to_string(), "should-not-appear".to_string());
    let out = PromptRenderer::render("{{a}}", &vars).unwrap();
    assert_eq!(out, "{{b}}", "value-substitution must not recurse");
}

#[test]
fn render_trims_whitespace_in_key() {
    let mut vars = HashMap::new();
    vars.insert("foo".to_string(), "bar".to_string());
    let out = PromptRenderer::render("{{  foo  }}", &vars).unwrap();
    assert_eq!(out, "bar");
}

#[test]
fn render_pairs_missing_returns_error() {
    let err = PromptRenderer::render_pairs("{{x}}", &[]).unwrap_err();
    match err {
        PromptError::MissingVariable(name) => assert_eq!(name, "x"),
        e => panic!("unexpected: {e:?}"),
    }
}

#[test]
fn render_adjacent_placeholders() {
    let out = PromptRenderer::render_pairs("{{a}}{{b}}", &[("a", "X"), ("b", "Y")]).unwrap();
    assert_eq!(out, "XY");
}

// ──────────────────────────────────────────────────────────────────────────
// PromptTemplate / TemplateRegistry / builtin_prompt_templates
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn template_serde_roundtrip() {
    let t = PromptTemplate::new("name", "body {{x}}", vec!["x".to_string()], "sys");
    let json = serde_json::to_string(&t).unwrap();
    let back: PromptTemplate = serde_json::from_str(&json).unwrap();
    assert_eq!(back.name, "name");
    assert_eq!(back.variables, vec!["x".to_string()]);
}

#[test]
fn builtin_templates_all_render_with_declared_vars() {
    for tmpl in builtin_prompt_templates() {
        let mut vars = HashMap::new();
        for v in &tmpl.variables {
            vars.insert(v.clone(), format!("VAL_{v}"));
        }
        let rendered = tmpl
            .render(&vars)
            .unwrap_or_else(|e| panic!("template {} failed to render: {e}", tmpl.name));
        for v in &tmpl.variables {
            assert!(
                rendered.contains(&format!("VAL_{v}")),
                "rendered body for {} missing var {v}",
                tmpl.name
            );
        }
        // No leftover {{ }} placeholders
        assert!(
            !rendered.contains("{{") || !rendered.contains("}}"),
            "leftover placeholder in {} -> {rendered}",
            tmpl.name
        );
    }
}

#[test]
fn template_registry_default_is_empty() {
    let reg: TemplateRegistry = TemplateRegistry::default();
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);
}

#[test]
fn template_registry_overwrite_register() {
    let mut reg = TemplateRegistry::new();
    reg.register(PromptTemplate::new("x", "a", vec![], ""));
    reg.register(PromptTemplate::new("x", "b", vec![], ""));
    assert_eq!(reg.len(), 1);
    assert_eq!(reg.get("x").unwrap().template, "b");
}

// ──────────────────────────────────────────────────────────────────────────
// ContextBuilder
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn context_builder_strings_join_newline() {
    let ctx = ContextBuilder::new()
        .strings(&["a".to_string(), "b".to_string(), "c".to_string()])
        .build();
    assert!(ctx.contains("a\nb\nc"));
}

#[test]
fn context_builder_empty_strings_slice() {
    let ctx = ContextBuilder::new().strings(&[]).build();
    assert!(ctx.contains("=== Strings ==="));
}

#[test]
fn context_builder_multiple_sections_order_preserved() {
    let ctx = ContextBuilder::new()
        .section("A", "1")
        .section("B", "2")
        .build();
    let a_pos = ctx.find("=== A ===").unwrap();
    let b_pos = ctx.find("=== B ===").unwrap();
    assert!(a_pos < b_pos);
}

// ──────────────────────────────────────────────────────────────────────────
// FewShotDatabase
// ──────────────────────────────────────────────────────────────────────────

fn mk_ex(task: &str, input: &str) -> FewShotExample {
    FewShotExample {
        task_type: task.into(),
        input: input.into(),
        output: "out".into(),
        explanation: "expl".into(),
    }
}

#[test]
fn fewshot_db_in_memory_starts_empty() {
    let db = FewShotDatabase::in_memory().unwrap();
    assert_eq!(db.count().unwrap(), 0);
    assert!(db.get_by_task("anything", 10).unwrap().is_empty());
}

#[test]
fn fewshot_db_limit_respected() {
    let db = FewShotDatabase::in_memory().unwrap();
    for i in 0..10 {
        db.insert(&mk_ex("t", &format!("in{i}"))).unwrap();
    }
    let got = db.get_by_task("t", 3).unwrap();
    assert_eq!(got.len(), 3);
    let got_all = db.get_by_task("t", 100).unwrap();
    assert_eq!(got_all.len(), 10);
}

#[test]
fn fewshot_db_delete_by_task_returns_count() {
    let db = FewShotDatabase::in_memory().unwrap();
    for _ in 0..3 {
        db.insert(&mk_ex("a", "x")).unwrap();
    }
    db.insert(&mk_ex("b", "y")).unwrap();
    assert_eq!(db.delete_by_task("a").unwrap(), 3);
    assert_eq!(db.count().unwrap(), 1);
    assert_eq!(db.delete_by_task("nonexistent").unwrap(), 0);
}

#[test]
fn fewshot_db_find_similar_returns_topk() {
    let db = FewShotDatabase::in_memory().unwrap();
    let id1 = db.insert(&mk_ex("t", "one")).unwrap();
    let id2 = db.insert(&mk_ex("t", "two")).unwrap();
    let id3 = db.insert(&mk_ex("t", "three")).unwrap();
    db.embed_example(&id1.to_string(), vec![1.0, 0.0, 0.0]);
    db.embed_example(&id2.to_string(), vec![0.9, 0.1, 0.0]);
    db.embed_example(&id3.to_string(), vec![0.0, 0.0, 1.0]);
    let query = vec![1.0, 0.0, 0.0];
    let results = db.find_similar(&query, 2);
    assert_eq!(results.len(), 2);
    // Most similar should be id1
    assert_eq!(results[0].input, "one");
}

#[test]
fn fewshot_db_find_similar_skips_unembedded() {
    let db = FewShotDatabase::in_memory().unwrap();
    db.insert(&mk_ex("t", "no-embedding")).unwrap();
    let results = db.find_similar(&[1.0, 0.0], 5);
    assert!(results.is_empty());
}

#[test]
fn fewshot_db_find_similar_mismatched_lengths_zero_score() {
    let db = FewShotDatabase::in_memory().unwrap();
    let id = db.insert(&mk_ex("t", "x")).unwrap();
    db.embed_example(&id.to_string(), vec![1.0, 0.0, 0.0]);
    // mismatched length -> similarity 0; example still returned (k>=1).
    let results = db.find_similar(&[1.0], 1);
    assert_eq!(results.len(), 1);
}

#[test]
fn fewshot_db_error_display_includes_message() {
    let e = PromptError::DbError("boom".into());
    assert!(e.to_string().contains("boom"));
}

// ──────────────────────────────────────────────────────────────────────────
// PromptChain
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn prompt_chain_default_is_empty_and_executes_no_steps() {
    let chain = PromptChain::default();
    let out = chain.execute(HashMap::new(), |_| "x".into()).unwrap();
    assert!(out.is_empty());
}

#[test]
fn prompt_chain_propagates_step_error_with_index() {
    let mut chain = PromptChain::new();
    chain.push(
        PromptTemplate::new("ok", "no vars", vec![], ""),
        Some("y".into()),
    );
    chain.push(
        PromptTemplate::new("bad", "{{missing}}", vec!["missing".into()], ""),
        None,
    );
    let err = chain.execute(HashMap::new(), |_| "out".into()).unwrap_err();
    match err {
        PromptError::ChainError { step, .. } => assert_eq!(step, 1),
        e => panic!("unexpected: {e:?}"),
    }
}

#[test]
fn chain_step_clone() {
    let step = ChainStep {
        template: PromptTemplate::new("t", "x", vec![], ""),
        inject_output_as: Some("k".into()),
    };
    let _c = step.clone();
}

// ──────────────────────────────────────────────────────────────────────────
// SpecPromptTemplate / PromptRegistry / TemplateVar
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn template_var_required_and_optional() {
    let r = TemplateVar::required("a");
    assert!(r.required && r.default.is_none());
    let o = TemplateVar::optional("b", "def");
    assert!(!o.required && o.default.as_deref() == Some("def"));
}

#[test]
fn spec_template_optional_uses_default_when_absent() {
    let t = SpecPromptTemplate::new("t", "{{x}}").with_var(TemplateVar::optional("x", "DEF"));
    assert_eq!(t.render(&HashMap::new()).unwrap(), "DEF");
}

#[test]
fn spec_template_required_missing_errors() {
    let t = SpecPromptTemplate::new("t", "{{x}}").with_var(TemplateVar::required("x"));
    let err = t.render(&HashMap::new()).unwrap_err();
    match err {
        SpecPromptError::MissingVar(n) => assert_eq!(n, "x"),
        e => panic!("unexpected: {e:?}"),
    }
}

#[test]
fn spec_template_ad_hoc_var_substituted() {
    // Undeclared placeholders are substituted in the second pass.
    let t = SpecPromptTemplate::new("t", "{{adhoc}}");
    let mut vars = HashMap::new();
    vars.insert("adhoc".into(), "VAL".into());
    assert_eq!(t.render(&vars).unwrap(), "VAL");
}

#[test]
fn prompt_registry_builtins_count_and_get() {
    let reg = PromptRegistry::new();
    assert_eq!(reg.count(), 6);
    for name in [
        "disassembly_analysis",
        "decompile_review",
        "malware_classify",
        "vuln_analysis",
        "explain_code",
        "suggest_name",
    ] {
        assert!(reg.get(name).is_some(), "missing builtin {name}");
    }
}

#[test]
fn prompt_registry_list_names_sorted() {
    let reg = PromptRegistry::new();
    let names = reg.list_names();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
}

// ──────────────────────────────────────────────────────────────────────────
// engine::builtin_prompts (rich templates)
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn engine_builtin_prompts_have_required_ids() {
    let list = engine::builtin_prompts();
    let ids: Vec<&str> = list.iter().map(|t| t.id.as_str()).collect();
    for needed in ["analyze_function", "name_variables", "identify_algorithm"] {
        assert!(ids.contains(&needed), "missing builtin id {needed}");
    }
}

#[test]
fn engine_prompt_variable_constructors() {
    let r = engine::PromptVariable::required("code", "the code");
    assert!(r.required && r.default.is_none());
    let o = engine::PromptVariable::optional("k", "desc", "d");
    assert!(!o.required);
    assert_eq!(o.default.as_deref(), Some("d"));
}

// ──────────────────────────────────────────────────────────────────────────
// prompt_chain helpers
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn extract_json_field_string() {
    let v = extract_json_field(r#"{"a":"hello"}"#, "a").unwrap();
    assert_eq!(v, "hello");
}

#[test]
fn extract_json_field_nested() {
    let v = extract_json_field(r#"{"a":{"b":42}}"#, "a.b").unwrap();
    assert_eq!(v, "42");
}

#[test]
fn extract_json_field_missing() {
    let err = extract_json_field(r#"{"a":1}"#, "b").unwrap_err();
    assert!(matches!(err, ChainError::JsonFieldNotFound(_)));
}

#[test]
fn extract_json_field_invalid_json() {
    let err = extract_json_field("not json", "a").unwrap_err();
    assert!(matches!(err, ChainError::InvalidJsonOutput(_)));
}

#[test]
fn extract_json_field_null_and_bool() {
    assert_eq!(extract_json_field(r#"{"a":null}"#, "a").unwrap(), "null");
    assert_eq!(extract_json_field(r#"{"a":true}"#, "a").unwrap(), "true");
}

#[test]
fn retry_with_backoff_succeeds_on_third_attempt() {
    let mut calls = 0;
    let r: Result<&'static str, &'static str> = retry_with_backoff(
        |_attempt| {
            calls += 1;
            if calls < 3 { Err("nope") } else { Ok("ok") }
        },
        5,
        1,
        2,
    );
    assert_eq!(r.unwrap(), "ok");
    assert_eq!(calls, 3);
}

#[test]
fn retry_with_backoff_propagates_after_max() {
    let mut calls = 0;
    let r: Result<(), &'static str> = retry_with_backoff(
        |_| {
            calls += 1;
            Err("fail")
        },
        2,
        1,
        2,
    );
    assert!(r.is_err());
    // max_retries=2 means attempts 0,1,2 -> 3 calls.
    assert_eq!(calls, 3);
}

// ──────────────────────────────────────────────────────────────────────────
// result_parser
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn confidence_score_clamps() {
    assert_eq!(ConfidenceScore::new(-1.0).value(), 0.0);
    assert_eq!(ConfidenceScore::new(2.0).value(), 1.0);
    assert_eq!(ConfidenceScore::new(0.5).value(), 0.5);
}

#[test]
fn confidence_score_labels() {
    assert_eq!(ConfidenceScore::new(0.95).label(), "high");
    assert_eq!(ConfidenceScore::new(0.7).label(), "medium");
    assert_eq!(ConfidenceScore::new(0.4).label(), "low");
    assert_eq!(ConfidenceScore::new(0.1).label(), "very_low");
}

#[test]
fn confidence_score_display_format() {
    let s = format!("{}", ConfidenceScore::new(0.9));
    assert!(s.contains("90%"));
    assert!(s.contains("high"));
}

#[test]
fn entity_kind_display_strings() {
    assert_eq!(EntityKind::FunctionName.to_string(), "function_name");
    assert_eq!(EntityKind::CveId.to_string(), "cve_id");
    assert_eq!(EntityKind::Custom.to_string(), "custom");
}

#[test]
fn extracted_entity_high_confidence_threshold() {
    let e = ExtractedEntity::new(EntityKind::Custom, "x", ConfidenceScore::new(0.8));
    assert!(e.is_high_confidence());
    let e2 = ExtractedEntity::new(EntityKind::Custom, "x", ConfidenceScore::new(0.5));
    assert!(!e2.is_high_confidence());
}

#[test]
fn extracted_entity_builder_methods() {
    let e = ExtractedEntity::new(EntityKind::Custom, "v", ConfidenceScore::high())
        .with_meta("k", "v")
        .with_range(2, 5);
    assert_eq!(e.metadata.get("k").unwrap(), "v");
    assert_eq!(e.source_range, Some((2, 5)));
}

#[test]
fn ai_mitre_technique_clamps_confidence() {
    let t = AiMitreTechnique::new("T1055", "name", "tactic", 5.0, "ev");
    assert_eq!(t.confidence, 1.0);
    let t2 = AiMitreTechnique::new("T1055", "name", "tactic", -1.0, "ev");
    assert_eq!(t2.confidence, 0.0);
}

#[test]
fn ai_result_iocs_filter() {
    let mut r = AiResult::new("t", "raw");
    r.add_entity(ExtractedEntity::new(
        EntityKind::NetworkIndicator,
        "1.2.3.4",
        ConfidenceScore::high(),
    ));
    r.add_entity(ExtractedEntity::new(
        EntityKind::FunctionName,
        "foo",
        ConfidenceScore::high(),
    ));
    let iocs = r.iocs();
    assert_eq!(iocs.len(), 1);
    assert_eq!(iocs[0].value, "1.2.3.4");
}

#[test]
fn result_parser_parses_mitre_ids() {
    let p = ResultParser::new();
    let r = p.parse("t", "Uses T1059.001 PowerShell and T1027.");
    let ids: Vec<&str> = r
        .mitre_techniques
        .iter()
        .map(|m| m.technique_id.as_str())
        .collect();
    assert!(ids.contains(&"T1059.001"));
    assert!(ids.contains(&"T1027"));
}

#[test]
fn result_parser_extracts_ip() {
    let p = ResultParser::new();
    let r = p.parse("t", "Connected to 10.0.0.1 over HTTP");
    let iocs = r.iocs();
    assert!(iocs.iter().any(|e| e.value == "10.0.0.1"));
}

#[test]
fn result_parser_extract_vuln_keyword() {
    let p = ResultParser::new();
    let r = p.parse("t", "There is a use-after-free in free_buf().");
    assert!(r.vulnerability_description.is_some());
}

#[test]
fn result_parser_validate_json_array_ok() {
    let p = ResultParser::new();
    assert!(p.validate_json_output("[1,2,3]").is_ok());
}

#[test]
fn result_parser_validate_json_unbalanced_braces() {
    let p = ResultParser::new();
    let res = p.validate_json_output("{ \"a\": { }");
    assert!(res.is_err());
}

#[test]
fn result_parser_normalize_collapses_blank_runs() {
    let p = ResultParser::new();
    let out = p.normalize_output("a\n\n\n\n\nb");
    assert_eq!(out, "a\n\nb");
}

#[test]
fn result_parser_disabled_extraction_skips_function_name() {
    let cfg = ParseConfig {
        extract_function_names: false,
        ..ParseConfig::default()
    };
    let p = ResultParser::new().with_config(cfg);
    let r = p.parse("t", "suggested_name: decrypt_payload");
    assert!(r.suggested_function_name.is_none());
}

// ──────────────────────────────────────────────────────────────────────────
// analysis_prompt_builder helpers
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn hex_dump_empty() {
    assert!(format_hex_dump(&[], 0).is_empty());
}

#[test]
fn hex_dump_short_line_pads_and_renders_ascii() {
    let out = format_hex_dump(b"AB", 0x1000);
    assert!(out.contains("00001000"));
    assert!(out.contains("41 42"));
    assert!(out.contains("|AB|"));
}

#[test]
fn hex_dump_two_full_lines_increment_address() {
    let bytes: Vec<u8> = (0..32u8).collect();
    let out = format_hex_dump(&bytes, 0);
    assert!(out.contains("00000000"));
    assert!(out.contains("00000010"));
}

#[test]
fn hex_dump_non_ascii_byte_renders_dot() {
    let out = format_hex_dump(&[0x00], 0);
    assert!(out.contains("|.|"));
}

#[test]
fn disasm_snippet_formats_lines() {
    let lines = vec![
        (0x1000u64, "55".into(), "push rbp".into()),
        (0x1001u64, "48 89 e5".into(), "mov rbp, rsp".into()),
    ];
    let out = format_disasm_snippet(&lines);
    assert!(out.contains("0000000000001000"));
    assert!(out.contains("push rbp"));
    assert!(out.contains("mov rbp, rsp"));
    // Numbered
    assert!(out.starts_with("   1"));
}

#[test]
fn disasm_snippet_empty() {
    assert!(format_disasm_snippet(&[]).is_empty());
}
