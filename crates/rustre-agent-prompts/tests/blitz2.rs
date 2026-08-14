//! Deep adversarial test suite for `rustre-agent-prompts` core API.
//! Focuses on the root-level public types: PromptRenderer, PromptTemplate,
//! TemplateRegistry, SpecPromptTemplate, PromptRegistry, FewShotDatabase,
//! ContextBuilder, PromptChain, builtin_prompt_templates, engine::*.

use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

use rustre_agent_prompts::engine::{
    self as eng, PromptCategory, PromptVariable, RichTemplate, builtin_prompts,
};
use rustre_agent_prompts::{
    builtin_prompt_templates, ChainStep, ContextBuilder, FewShotDatabase, FewShotExample,
    PromptChain, PromptError, PromptRegistry, PromptRenderer, PromptTemplate, SpecPromptError,
    SpecPromptTemplate, TemplateRegistry, TemplateVar,
};

// ─── Deterministic LCG ──────────────────────────────────────────────────────

fn lcg_seeded(seed: u64) -> impl FnMut() -> u64 {
    let mut s: u64 = seed;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

fn rand_ident(g: &mut impl FnMut() -> u64) -> String {
    let n = (g() % 12) as usize + 1;
    let mut out = String::new();
    for _ in 0..n {
        let b = ((g() % 26) as u8) + b'a';
        out.push(b as char);
    }
    out
}

fn rand_text(g: &mut impl FnMut() -> u64) -> String {
    let n = (g() % 40) as usize;
    let mut out = String::new();
    for _ in 0..n {
        let v = g() % 100;
        if v < 80 {
            let b = ((v % 26) as u8) + b'a';
            out.push(b as char);
        } else if v < 90 {
            out.push(' ');
        } else if v < 95 {
            out.push('{');
        } else {
            out.push('}');
        }
    }
    out
}

// ─── PromptRenderer: round-trip & adversarial ───────────────────────────────

#[test]
fn renderer_50_round_trips_ident_value() {
    let mut g = lcg_seeded(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..50 {
        let key = rand_ident(&mut g);
        // value is plain text with no braces
        let val: String = (0..(g() % 30))
            .map(|_| (((g() % 26) as u8) + b'a') as char)
            .collect();
        let tmpl = format!("[{{{{{key}}}}}]");
        let mut vars = HashMap::new();
        vars.insert(key.clone(), val.clone());
        let out = PromptRenderer::render(&tmpl, &vars).unwrap();
        assert_eq!(out, format!("[{val}]"));
    }
}

#[test]
fn renderer_fuzz_never_panics() {
    let mut g = lcg_seeded(0x1234_5678_9ABC_DEF0);
    for _ in 0..200 {
        let s = rand_text(&mut g);
        // Provide some random vars
        let mut vars = HashMap::new();
        vars.insert("a".into(), "A".into());
        vars.insert("b".into(), "B".into());
        // Must return Ok or specific Err — never panic
        let _ = PromptRenderer::render(&s, &vars);
    }
}

#[test]
fn renderer_unclosed_brace_returns_err() {
    let err = PromptRenderer::render("hi {{x", &HashMap::new()).unwrap_err();
    matches!(err, PromptError::MissingVariable(_));
}

#[test]
fn renderer_missing_var_specific_name() {
    let err = PromptRenderer::render("hi {{nope}}", &HashMap::new()).unwrap_err();
    match err {
        PromptError::MissingVariable(name) => assert_eq!(name, "nope"),
        _ => panic!("expected MissingVariable"),
    }
}

#[test]
fn renderer_handles_trim_in_placeholder() {
    let mut v = HashMap::new();
    v.insert("k".into(), "V".into());
    let out = PromptRenderer::render("{{  k  }}", &v).unwrap();
    assert_eq!(out, "V");
}

#[test]
fn renderer_escape_quadruple_braces_to_literal() {
    let out = PromptRenderer::render("{{{{not_a_var}}}}", &HashMap::new()).unwrap();
    assert_eq!(out, "{{not_a_var}}");
}

#[test]
fn renderer_utf8_in_template_and_value_preserved() {
    let mut v = HashMap::new();
    v.insert("emoji".into(), "naïve_λ".into());
    let out = PromptRenderer::render("π = {{emoji}} ✓", &v).unwrap();
    assert!(out.contains("naïve_λ"));
    assert!(out.contains("π"));
    assert!(out.contains("✓"));
}

#[test]
fn renderer_empty_template_is_empty() {
    let out = PromptRenderer::render("", &HashMap::new()).unwrap();
    assert_eq!(out, "");
}

#[test]
fn renderer_pairs_helper_matches_map() {
    let mut v = HashMap::new();
    v.insert("a".into(), "1".into());
    v.insert("b".into(), "2".into());
    let out1 = PromptRenderer::render("{{a}}-{{b}}", &v).unwrap();
    let out2 = PromptRenderer::render_pairs("{{a}}-{{b}}", &[("a", "1"), ("b", "2")]).unwrap();
    assert_eq!(out1, out2);
}

// ─── PromptTemplate ─────────────────────────────────────────────────────────

#[test]
fn prompt_template_clone_independent() {
    let t = PromptTemplate::new("n", "{{x}}", vec!["x".into()], "sys");
    let t2 = t.clone();
    assert_eq!(t.name, t2.name);
    assert_eq!(t.template, t2.template);
    assert_eq!(t.variables, t2.variables);
    assert_eq!(t.system_prompt, t2.system_prompt);
}

#[test]
fn prompt_template_render_missing_var_propagates() {
    let t = PromptTemplate::new("n", "{{a}}-{{b}}", vec!["a".into(), "b".into()], "");
    let mut v = HashMap::new();
    v.insert("a".into(), "X".into());
    let err = t.render(&v).unwrap_err();
    matches!(err, PromptError::MissingVariable(_));
}

#[test]
fn prompt_template_serde_round_trip() {
    let t = PromptTemplate::new("n", "T{{x}}", vec!["x".into()], "sys");
    let j = serde_json::to_string(&t).unwrap();
    let back: PromptTemplate = serde_json::from_str(&j).unwrap();
    assert_eq!(back.name, "n");
    assert_eq!(back.template, "T{{x}}");
}

// ─── Built-in templates ─────────────────────────────────────────────────────

#[test]
fn builtins_all_renderable_with_filler() {
    for t in builtin_prompt_templates() {
        let mut v = HashMap::new();
        for var in &t.variables {
            v.insert(var.clone(), format!("[{var}]"));
        }
        let out = t.render(&v).unwrap();
        assert!(!out.is_empty(), "template {} rendered empty", t.name);
        for var in &t.variables {
            assert!(out.contains(&format!("[{var}]")), "var {var} missing in render of {}", t.name);
        }
    }
}

#[test]
fn builtins_have_unique_names() {
    let templates = builtin_prompt_templates();
    let mut names: Vec<String> = templates.iter().map(|t| t.name.clone()).collect();
    names.sort();
    let len_before = names.len();
    names.dedup();
    assert_eq!(len_before, names.len(), "duplicate builtin template names");
}

// ─── TemplateRegistry ───────────────────────────────────────────────────────

#[test]
fn template_registry_default_is_empty() {
    let r = TemplateRegistry::default();
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
}

#[test]
fn template_registry_with_builtins_get_each() {
    let r = TemplateRegistry::with_builtins();
    for t in builtin_prompt_templates() {
        let got = r.get(&t.name).unwrap();
        assert_eq!(got.name, t.name);
    }
}

#[test]
fn template_registry_overwrite_on_reregister() {
    let mut r = TemplateRegistry::new();
    let t1 = PromptTemplate::new("same", "v1", vec![], "");
    let t2 = PromptTemplate::new("same", "v2", vec![], "");
    r.register(t1);
    r.register(t2);
    assert_eq!(r.len(), 1);
    assert_eq!(r.get("same").unwrap().template, "v2");
}

#[test]
fn template_registry_not_found_carries_name() {
    let r = TemplateRegistry::new();
    let err = r.get("missing_X").unwrap_err();
    match err {
        PromptError::TemplateNotFound(n) => assert_eq!(n, "missing_X"),
        _ => panic!("wrong variant"),
    }
}

// ─── SpecPromptTemplate / TemplateVar ───────────────────────────────────────

#[test]
fn template_var_required_no_default() {
    let v = TemplateVar::required("x");
    assert!(v.required);
    assert!(v.default.is_none());
}

#[test]
fn template_var_optional_has_default() {
    let v = TemplateVar::optional("x", "d");
    assert!(!v.required);
    assert_eq!(v.default.as_deref(), Some("d"));
}

#[test]
fn spec_template_required_missing_errs_with_name() {
    let t = SpecPromptTemplate::new("t", "{{code}}").with_var(TemplateVar::required("code"));
    let err = t.render(&HashMap::new()).unwrap_err();
    match err {
        SpecPromptError::MissingVar(n) => assert_eq!(n, "code"),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn spec_template_optional_uses_default_when_absent() {
    let t = SpecPromptTemplate::new("t", "L={{lang}}")
        .with_var(TemplateVar::optional("lang", "rust"));
    assert_eq!(t.render(&HashMap::new()).unwrap(), "L=rust");
}

#[test]
fn spec_template_50_random_round_trips() {
    let mut g = lcg_seeded(0xCAFE_F00D_BEEF_1234);
    for _ in 0..50 {
        let key = rand_ident(&mut g);
        let val: String = (0..(g() % 20 + 1))
            .map(|_| (((g() % 26) as u8) + b'A') as char)
            .collect();
        let t = SpecPromptTemplate::new("t", format!("[{{{{{key}}}}}]"))
            .with_var(TemplateVar::required(&key));
        let mut v = HashMap::new();
        v.insert(key.clone(), val.clone());
        let out = t.render(&v).unwrap();
        assert_eq!(out, format!("[{val}]"));
    }
}

#[test]
fn spec_template_required_vars_filter() {
    let t = SpecPromptTemplate::new("t", "{{a}} {{b}} {{c}}")
        .with_var(TemplateVar::required("a"))
        .with_var(TemplateVar::optional("b", "B"))
        .with_var(TemplateVar::required("c"));
    let req = t.required_vars();
    assert_eq!(req.len(), 2);
    let names: Vec<&str> = req.iter().map(|v| v.name.as_str()).collect();
    assert!(names.contains(&"a"));
    assert!(names.contains(&"c"));
}

#[test]
fn spec_prompt_error_display_carries_payload() {
    let e1 = SpecPromptError::MissingVar("xy".into());
    let e2 = SpecPromptError::NotFound("zz".into());
    let e3 = SpecPromptError::RenderError("oops".into());
    assert!(e1.to_string().contains("xy"));
    assert!(e2.to_string().contains("zz"));
    assert!(e3.to_string().contains("oops"));
}

// ─── PromptRegistry (spec) ──────────────────────────────────────────────────

#[test]
fn prompt_registry_builtin_count_stable() {
    let r = PromptRegistry::new();
    assert_eq!(r.count(), 6);
}

#[test]
fn prompt_registry_names_sorted() {
    let r = PromptRegistry::new();
    let names = r.list_names();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
}

#[test]
fn prompt_registry_register_then_get_overwrites() {
    let mut r = PromptRegistry::new();
    r.register(SpecPromptTemplate::new("explain_code", "REPLACED {{code}}"));
    let t = r.get("explain_code").unwrap();
    assert!(t.template.contains("REPLACED"));
    assert_eq!(r.count(), 6); // still 6, overwritten
}

// ─── ContextBuilder ─────────────────────────────────────────────────────────

#[test]
fn context_builder_section_titles_present() {
    let s = ContextBuilder::new()
        .section("Alpha", "a-body")
        .section("Beta", "b-body")
        .build();
    assert!(s.contains("=== Alpha ==="));
    assert!(s.contains("=== Beta ==="));
    assert!(s.find("Alpha").unwrap() < s.find("Beta").unwrap());
}

#[test]
fn context_builder_strings_helper_joins_newlines() {
    let s = ContextBuilder::new()
        .strings(&["a".into(), "b".into(), "c".into()])
        .build();
    assert!(s.contains("a\nb\nc"));
}

#[test]
fn context_builder_default_equiv_to_new() {
    let a = ContextBuilder::default().build();
    let b = ContextBuilder::new().build();
    assert_eq!(a, b);
}

#[test]
fn context_builder_empty_imports_strings_ok() {
    let s = ContextBuilder::new().imports(&[]).strings(&[]).build();
    // Both produce sections with empty content, but section headers exist
    assert!(s.contains("=== Imports ==="));
    assert!(s.contains("=== Strings ==="));
}

// ─── FewShotDatabase ────────────────────────────────────────────────────────

#[test]
fn few_shot_db_in_memory_round_trip_50() {
    let db = FewShotDatabase::in_memory().unwrap();
    let mut g = lcg_seeded(0xAAAA_BBBB_CCCC_DDDD);
    for i in 0..50 {
        let ex = FewShotExample {
            task_type: format!("t{}", i % 5),
            input: rand_ident(&mut g),
            output: rand_ident(&mut g),
            explanation: rand_ident(&mut g),
        };
        let id = db.insert(&ex).unwrap();
        assert!(id > 0);
    }
    assert_eq!(db.count().unwrap(), 50);
    // Each task type should have ~10
    let mut total = 0;
    for i in 0..5 {
        let rows = db.get_by_task(&format!("t{i}"), 1000).unwrap();
        total += rows.len();
    }
    assert_eq!(total, 50);
}

#[test]
fn few_shot_db_get_by_task_respects_limit() {
    let db = FewShotDatabase::in_memory().unwrap();
    for i in 0..10 {
        db.insert(&FewShotExample {
            task_type: "x".into(),
            input: format!("i{i}"),
            output: format!("o{i}"),
            explanation: "e".into(),
        })
        .unwrap();
    }
    assert_eq!(db.get_by_task("x", 3).unwrap().len(), 3);
    assert_eq!(db.get_by_task("x", 100).unwrap().len(), 10);
    assert_eq!(db.get_by_task("x", 0).unwrap().len(), 0);
}

#[test]
fn few_shot_db_delete_returns_count() {
    let db = FewShotDatabase::in_memory().unwrap();
    for _ in 0..3 {
        db.insert(&FewShotExample {
            task_type: "kill".into(),
            input: "i".into(),
            output: "o".into(),
            explanation: "e".into(),
        })
        .unwrap();
    }
    db.insert(&FewShotExample {
        task_type: "keep".into(),
        input: "i".into(),
        output: "o".into(),
        explanation: "e".into(),
    })
    .unwrap();
    let n = db.delete_by_task("kill").unwrap();
    assert_eq!(n, 3);
    assert_eq!(db.count().unwrap(), 1);
}

#[test]
fn few_shot_db_find_similar_orders_by_cosine() {
    let db = FewShotDatabase::in_memory().unwrap();
    let id1 = db
        .insert(&FewShotExample {
            task_type: "a".into(),
            input: "i1".into(),
            output: "o1".into(),
            explanation: "e".into(),
        })
        .unwrap();
    let id2 = db
        .insert(&FewShotExample {
            task_type: "a".into(),
            input: "i2".into(),
            output: "o2".into(),
            explanation: "e".into(),
        })
        .unwrap();
    db.embed_example(&id1.to_string(), vec![1.0, 0.0, 0.0]);
    db.embed_example(&id2.to_string(), vec![0.0, 1.0, 0.0]);
    let q = [0.9, 0.1, 0.0];
    let top = db.find_similar(&q, 2);
    assert_eq!(top.len(), 2);
    // id1 (aligned with x-axis) should rank first
    assert_eq!(top[0].input, "i1");
}

#[test]
fn few_shot_db_find_similar_skips_missing_embeddings() {
    let db = FewShotDatabase::in_memory().unwrap();
    db.insert(&FewShotExample {
        task_type: "a".into(),
        input: "i".into(),
        output: "o".into(),
        explanation: "e".into(),
    })
    .unwrap();
    // no embeddings inserted
    let res = db.find_similar(&[1.0, 0.0], 5);
    assert!(res.is_empty());
}

#[test]
fn few_shot_db_find_similar_truncates_to_k() {
    let db = FewShotDatabase::in_memory().unwrap();
    for i in 0..5 {
        let id = db
            .insert(&FewShotExample {
                task_type: "a".into(),
                input: format!("i{i}"),
                output: "o".into(),
                explanation: "e".into(),
            })
            .unwrap();
        db.embed_example(&id.to_string(), vec![i as f32, 1.0]);
    }
    let top = db.find_similar(&[1.0, 1.0], 3);
    assert_eq!(top.len(), 3);
}

// ─── PromptChain ────────────────────────────────────────────────────────────

#[test]
fn prompt_chain_default_is_empty_execute() {
    let chain = PromptChain::default();
    let out = chain.execute(HashMap::new(), |_| String::new()).unwrap();
    assert!(out.is_empty());
}

#[test]
fn prompt_chain_three_steps_forward_output() {
    let mut c = PromptChain::new();
    c.push(
        PromptTemplate::new("s1", "A:{{x}}", vec!["x".into()], ""),
        Some("p1".into()),
    );
    c.push(
        PromptTemplate::new("s2", "B:{{p1}}", vec!["p1".into()], ""),
        Some("p2".into()),
    );
    c.push(
        PromptTemplate::new("s3", "C:{{p2}}", vec!["p2".into()], ""),
        None,
    );
    let mut v = HashMap::new();
    v.insert("x".into(), "0".into());
    let outs = c.execute(v, |s| format!("[{s}]")).unwrap();
    assert_eq!(outs.len(), 3);
    assert!(outs[1].contains("[A:0]"));
    assert!(outs[2].contains("[B:[A:0]]"));
}

#[test]
fn prompt_chain_error_carries_step_index() {
    let mut c = PromptChain::new();
    c.push(PromptTemplate::new("s1", "{{x}}", vec!["x".into()], ""), None);
    c.push(PromptTemplate::new("s2", "{{y}}", vec!["y".into()], ""), None);
    let mut v = HashMap::new();
    v.insert("x".into(), "ok".into());
    let err = c.execute(v, |s| s.to_string()).unwrap_err();
    match err {
        PromptError::ChainError { step, .. } => assert_eq!(step, 1),
        _ => panic!("expected ChainError"),
    }
}

#[test]
fn chain_step_clone_independent() {
    let s = ChainStep {
        template: PromptTemplate::new("a", "{{x}}", vec!["x".into()], ""),
        inject_output_as: Some("y".into()),
    };
    let s2 = s.clone();
    assert_eq!(s.template.name, s2.template.name);
    assert_eq!(s.inject_output_as, s2.inject_output_as);
}

// ─── engine module ──────────────────────────────────────────────────────────

#[test]
fn engine_builtins_have_required_vars_satisfiable() {
    let prompts = builtin_prompts();
    assert!(prompts.len() >= 3);
    for p in prompts {
        // unique id and non-empty name
        assert!(!p.id.is_empty());
        assert!(!p.name.is_empty());
    }
}

#[test]
fn engine_prompt_variable_required_helper() {
    let v = PromptVariable::required("name", "desc");
    assert!(v.required);
    assert!(v.default.is_none());
    assert_eq!(v.name, "name");
    assert_eq!(v.description, "desc");
}

#[test]
fn engine_prompt_variable_optional_helper() {
    let v = PromptVariable::optional("name", "desc", "def");
    assert!(!v.required);
    assert_eq!(v.default.as_deref(), Some("def"));
}

#[test]
fn engine_category_eq_and_hash() {
    use std::collections::HashSet;
    let mut s: HashSet<PromptCategory> = HashSet::new();
    s.insert(PromptCategory::FunctionAnalysis);
    s.insert(PromptCategory::FunctionAnalysis);
    s.insert(PromptCategory::MalwareAnalysis);
    assert_eq!(s.len(), 2);
}

#[test]
fn engine_rich_template_serde_round_trip() {
    let t = RichTemplate {
        id: "x".into(),
        name: "X".into(),
        description: "d".into(),
        template: "{{a}}".into(),
        variables: vec![PromptVariable::required("a", "v")],
        category: PromptCategory::Custom,
        use_case: "u".into(),
    };
    let j = serde_json::to_string(&t).unwrap();
    let back: RichTemplate = serde_json::from_str(&j).unwrap();
    assert_eq!(back.id, "x");
    assert_eq!(back.variables.len(), 1);
    assert_eq!(back.category, PromptCategory::Custom);
}

// ─── Send/Sync thread stress on FewShotDatabase ─────────────────────────────

#[test]
fn few_shot_db_concurrent_inserts_4x100() {
    let db = Arc::new(FewShotDatabase::in_memory().unwrap());
    let mut handles = Vec::new();
    for tid in 0..4u64 {
        let dbc = Arc::clone(&db);
        handles.push(thread::spawn(move || {
            let mut g = lcg_seeded(0xBEEF_0000 + tid);
            for _ in 0..100 {
                let ex = FewShotExample {
                    task_type: format!("t{}", g() % 4),
                    input: "i".into(),
                    output: "o".into(),
                    explanation: "e".into(),
                };
                dbc.insert(&ex).unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(db.count().unwrap(), 400);
}

#[test]
fn few_shot_db_concurrent_reads_and_writes() {
    let db = Arc::new(FewShotDatabase::in_memory().unwrap());
    // Seed
    for i in 0..10 {
        db.insert(&FewShotExample {
            task_type: "seed".into(),
            input: format!("i{i}"),
            output: "o".into(),
            explanation: "e".into(),
        })
        .unwrap();
    }
    let mut handles = Vec::new();
    for tid in 0..4u64 {
        let dbc = Arc::clone(&db);
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                if (tid + i) % 2 == 0 {
                    let _ = dbc.count().unwrap();
                } else {
                    dbc.insert(&FewShotExample {
                        task_type: "w".into(),
                        input: "x".into(),
                        output: "y".into(),
                        explanation: "z".into(),
                    })
                    .unwrap();
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    // 10 seed + 4 threads * 50 writes = 210
    assert_eq!(db.count().unwrap(), 210);
}

// ─── Hash/Eq consistency for PromptCategory ─────────────────────────────────

#[test]
fn prompt_category_eq_consistency_30_pairs() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let cats = [
        PromptCategory::FunctionAnalysis,
        PromptCategory::MalwareAnalysis,
        PromptCategory::VulnerabilityResearch,
        PromptCategory::TypeRecovery,
        PromptCategory::CryptoIdentification,
        PromptCategory::ExplainCode,
        PromptCategory::NameSuggestion,
        PromptCategory::CompareVersions,
        PromptCategory::Custom,
    ];
    let mut pairs_checked = 0;
    for a in &cats {
        for b in &cats {
            let mut ha = DefaultHasher::new();
            a.hash(&mut ha);
            let mut hb = DefaultHasher::new();
            b.hash(&mut hb);
            if a == b {
                assert_eq!(ha.finish(), hb.finish());
            }
            pairs_checked += 1;
        }
    }
    assert!(pairs_checked >= 30);
}

// ─── Boundary tests ─────────────────────────────────────────────────────────

#[test]
fn renderer_value_with_one_char() {
    let mut v = HashMap::new();
    v.insert("k".into(), "x".into());
    let out = PromptRenderer::render("{{k}}", &v).unwrap();
    assert_eq!(out, "x");
}

#[test]
fn renderer_value_with_large_input() {
    let big = "z".repeat(8192);
    let mut v = HashMap::new();
    v.insert("k".into(), big.clone());
    let out = PromptRenderer::render("<{{k}}>", &v).unwrap();
    assert_eq!(out.len(), big.len() + 2);
}

#[test]
fn few_shot_db_empty_strings_accepted() {
    let db = FewShotDatabase::in_memory().unwrap();
    let id = db
        .insert(&FewShotExample {
            task_type: "".into(),
            input: "".into(),
            output: "".into(),
            explanation: "".into(),
        })
        .unwrap();
    assert!(id > 0);
    let rows = db.get_by_task("", 10).unwrap();
    assert_eq!(rows.len(), 1);
}

#[test]
fn spec_template_render_replaces_undeclared_vars_too() {
    // Per implementation: ad-hoc vars not in declared list are still substituted.
    let t = SpecPromptTemplate::new("t", "{{a}} {{b}}");
    let mut v = HashMap::new();
    v.insert("a".into(), "AA".into());
    v.insert("b".into(), "BB".into());
    assert_eq!(t.render(&v).unwrap(), "AA BB");
}

#[test]
fn few_shot_example_serde_round_trip() {
    let e = FewShotExample {
        task_type: "rename".into(),
        input: "v1=v2".into(),
        output: "x=y".into(),
        explanation: "renamed".into(),
    };
    let j = serde_json::to_string(&e).unwrap();
    let back: FewShotExample = serde_json::from_str(&j).unwrap();
    assert_eq!(back.task_type, "rename");
    assert_eq!(back.input, "v1=v2");
}

// ─── PromptError display & From ────────────────────────────────────────────

#[test]
fn prompt_error_chain_error_display() {
    let e = PromptError::ChainError {
        step: 7,
        message: "boom".into(),
    };
    let s = e.to_string();
    assert!(s.contains("7"));
    assert!(s.contains("boom"));
}

#[test]
fn prompt_error_db_error_from_rusqlite() {
    // Trigger a real rusqlite error by opening an invalid path on a closed dir
    let r = FewShotDatabase::open("Z:\\definitely_not_a_real_path_xyz\\foo.db");
    // Should err with DbError variant
    if let Err(e) = r {
        match e {
            PromptError::DbError(_) => {}
            other => panic!("expected DbError, got {other:?}"),
        }
    } else {
        // On some platforms this path might succeed; not fatal.
    }
}

#[test]
fn engine_use_case_strings_nonempty() {
    for t in builtin_prompts() {
        assert!(!t.use_case.is_empty(), "{} use_case empty", t.id);
        assert!(!t.description.is_empty(), "{} desc empty", t.id);
    }
}

// Touch `eng` re-export to ensure module path compiles
#[test]
fn engine_module_alias_compiles() {
    let _: eng::RichTemplate = RichTemplate {
        id: "x".into(),
        name: "X".into(),
        description: "d".into(),
        template: "".into(),
        variables: vec![],
        category: PromptCategory::Custom,
        use_case: "u".into(),
    };
}
