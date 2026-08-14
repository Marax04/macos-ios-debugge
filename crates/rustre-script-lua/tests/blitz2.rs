//! Deep adversarial tests for the core LuaEngine/LuaValue/LuaContext API.

use rustre_script_lua::{
    BinOp, LuaContext, LuaEngine, LuaError, LuaExpr, LuaStmt, LuaValue, UnOp,
};

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

// ── LuaValue basics ─────────────────────────────────────────────────────────

#[test]
fn value_type_name() {
    assert_eq!(LuaValue::Nil.type_name(), "nil");
    assert_eq!(LuaValue::Bool(true).type_name(), "boolean");
    assert_eq!(LuaValue::Int(0).type_name(), "number");
    assert_eq!(LuaValue::Float(0.0).type_name(), "number");
    assert_eq!(LuaValue::String("x".into()).type_name(), "string");
    assert_eq!(LuaValue::Table(vec![]).type_name(), "table");
    assert_eq!(LuaValue::Function("f".into()).type_name(), "function");
}

#[test]
fn value_truthy_rules() {
    assert!(!LuaValue::Nil.is_truthy());
    assert!(!LuaValue::Bool(false).is_truthy());
    assert!(LuaValue::Bool(true).is_truthy());
    assert!(LuaValue::Int(0).is_truthy()); // 0 is truthy in Lua
    assert!(LuaValue::Int(-1).is_truthy());
    assert!(LuaValue::Float(0.0).is_truthy());
    assert!(LuaValue::String(String::new()).is_truthy());
    assert!(LuaValue::Table(vec![]).is_truthy());
}

#[test]
fn value_as_int_conversions() {
    assert_eq!(LuaValue::Int(42).as_int(), Some(42));
    assert_eq!(LuaValue::Int(i64::MAX).as_int(), Some(i64::MAX));
    assert_eq!(LuaValue::Int(i64::MIN).as_int(), Some(i64::MIN));
    assert_eq!(LuaValue::Float(3.7).as_int(), Some(3));
    assert_eq!(LuaValue::Float(-3.7).as_int(), Some(-3));
    assert_eq!(LuaValue::Nil.as_int(), None);
    assert_eq!(LuaValue::String("5".into()).as_int(), None);
    assert_eq!(LuaValue::Bool(true).as_int(), None);
}

#[test]
fn value_as_str() {
    assert_eq!(LuaValue::String("hi".into()).as_str(), Some("hi"));
    assert_eq!(LuaValue::Int(5).as_str(), None);
    assert_eq!(LuaValue::Nil.as_str(), None);
}

#[test]
fn value_display() {
    assert_eq!(LuaValue::Nil.to_string(), "nil");
    assert_eq!(LuaValue::Bool(true).to_string(), "true");
    assert_eq!(LuaValue::Bool(false).to_string(), "false");
    assert_eq!(LuaValue::Int(-7).to_string(), "-7");
    assert_eq!(LuaValue::String("abc".into()).to_string(), "abc");
    assert_eq!(
        LuaValue::Table(vec![(LuaValue::Int(1), LuaValue::Int(2))]).to_string(),
        "table[1]"
    );
    assert_eq!(LuaValue::Function("f".into()).to_string(), "function:f");
}

// ── LuaContext ─────────────────────────────────────────────────────────────

#[test]
fn context_default_has_stdlib() {
    let ctx = LuaContext::new();
    assert!(matches!(ctx.get("print"), LuaValue::Function(_)));
    assert!(matches!(ctx.get("math"), LuaValue::Table(_)));
    assert!(matches!(ctx.get("rustre"), LuaValue::Table(_)));
    assert!(matches!(ctx.get("re"), LuaValue::Table(_)));
    assert!(matches!(ctx.get("dbg"), LuaValue::Table(_)));
}

#[test]
fn context_missing_returns_nil() {
    let ctx = LuaContext::new();
    assert!(matches!(ctx.get("__no_such_global__"), LuaValue::Nil));
}

#[test]
fn context_set_get_roundtrip() {
    let mut ctx = LuaContext::new();
    for i in 0..50i64 {
        ctx.set(format!("v{i}"), LuaValue::Int(i));
    }
    for i in 0..50 {
        assert_eq!(ctx.get(&format!("v{i}")).as_int(), Some(i));
    }
}

#[test]
fn context_output_text_empty() {
    let ctx = LuaContext::new();
    assert_eq!(ctx.output_text(), "");
}

// ── Engine: arithmetic ─────────────────────────────────────────────────────

fn eval(src: &str) -> Result<LuaValue, LuaError> {
    let mut e = LuaEngine::new();
    let mut ctx = LuaContext::new();
    e.execute(src, &mut ctx)
}

#[test]
fn arith_add_sub_mul() {
    assert_eq!(eval("return 1 + 2").unwrap().as_int(), Some(3));
    assert_eq!(eval("return 10 - 4").unwrap().as_int(), Some(6));
    assert_eq!(eval("return 6 * 7").unwrap().as_int(), Some(42));
}

#[test]
fn arith_division_is_float() {
    let v = eval("return 10 / 4").unwrap();
    assert!(matches!(v, LuaValue::Float(_)));
    if let LuaValue::Float(f) = v {
        assert!((f - 2.5).abs() < 1e-9);
    }
}

#[test]
fn arith_division_by_zero_int_errors() {
    let r = eval("return 1 / 0");
    assert!(matches!(r, Err(LuaError::RuntimeError(_))));
}

#[test]
fn arith_modulo_by_zero_int_errors() {
    let r = eval("return 5 % 0");
    assert!(matches!(r, Err(LuaError::RuntimeError(_))));
}

#[test]
fn arith_wrapping_int_overflow() {
    // i64::MAX + 1 should wrap, not panic
    let src = format!("return {} + 1", i64::MAX);
    let v = eval(&src).unwrap();
    assert_eq!(v.as_int(), Some(i64::MIN));
}

#[test]
fn arith_wrapping_int_underflow() {
    // Construct i64::MIN as -(i64::MAX) - 1 to avoid the parser needing to
    // accept a positive literal equal to i64::MAX + 1.
    let src = format!("local m = -{} - 1\nreturn m - 1", i64::MAX);
    let v = eval(&src).unwrap();
    assert_eq!(v.as_int(), Some(i64::MAX));
}

#[test]
fn arith_negation() {
    assert_eq!(eval("return -5").unwrap().as_int(), Some(-5));
    assert_eq!(eval("local x = 7\nreturn -x").unwrap().as_int(), Some(-7));
}

// ── Comparison & boolean ───────────────────────────────────────────────────

#[test]
fn cmp_lt_le_gt_ge() {
    assert!(matches!(eval("return 1 < 2").unwrap(), LuaValue::Bool(true)));
    assert!(matches!(eval("return 2 <= 2").unwrap(), LuaValue::Bool(true)));
    assert!(matches!(eval("return 3 > 2").unwrap(), LuaValue::Bool(true)));
    assert!(matches!(eval("return 2 >= 3").unwrap(), LuaValue::Bool(false)));
}

#[test]
fn cmp_eq_ne_across_types() {
    assert!(matches!(eval("return 1 == 1").unwrap(), LuaValue::Bool(true)));
    assert!(matches!(eval("return 1 ~= 2").unwrap(), LuaValue::Bool(true)));
    assert!(matches!(
        eval("return \"a\" == \"a\"").unwrap(),
        LuaValue::Bool(true)
    ));
    assert!(matches!(
        eval("return nil == false").unwrap(),
        LuaValue::Bool(false)
    ));
}

#[test]
fn logical_and_or_short_circuit() {
    // and returns first falsy or last
    assert!(matches!(eval("return false and 5").unwrap(), LuaValue::Bool(false)));
    assert_eq!(eval("return 1 and 2").unwrap().as_int(), Some(2));
    // or returns first truthy
    assert_eq!(eval("return nil or 7").unwrap().as_int(), Some(7));
    assert_eq!(eval("return 3 or 4").unwrap().as_int(), Some(3));
}

#[test]
fn logical_not() {
    assert!(matches!(eval("return not nil").unwrap(), LuaValue::Bool(true)));
    assert!(matches!(eval("return not 0").unwrap(), LuaValue::Bool(false)));
    assert!(matches!(eval("return not false").unwrap(), LuaValue::Bool(true)));
}

// ── Strings ────────────────────────────────────────────────────────────────

#[test]
fn string_concat() {
    let v = eval(r#"return "foo" .. "bar""#).unwrap();
    assert_eq!(v.as_str(), Some("foobar"));
}

#[test]
fn string_concat_with_number() {
    let v = eval(r#"return "x=" .. 42"#).unwrap();
    assert_eq!(v.as_str(), Some("x=42"));
}

#[test]
fn string_length_operator() {
    let v = eval(r#"return #"hello""#).unwrap();
    assert_eq!(v.as_int(), Some(5));
}

#[test]
fn string_escape_sequences() {
    let v = eval(r#"return "a\nb""#).unwrap();
    assert_eq!(v.as_str(), Some("a\nb"));
    let v = eval(r#"return "x\ty""#).unwrap();
    assert_eq!(v.as_str(), Some("x\ty"));
}

#[test]
fn string_single_quotes() {
    let v = eval("return 'hi'").unwrap();
    assert_eq!(v.as_str(), Some("hi"));
}

#[test]
fn string_unterminated_is_syntax_error() {
    let r = eval(r#"return "oops"#);
    assert!(matches!(r, Err(LuaError::SyntaxError { .. })));
}

// ── Control flow ───────────────────────────────────────────────────────────

#[test]
fn if_then_else() {
    let v = eval(
        "local x = 5\nif x > 3 then return 1 else return 0 end",
    )
    .unwrap();
    assert_eq!(v.as_int(), Some(1));
}

#[test]
fn if_else_branch_taken() {
    let v = eval(
        "local x = 1\nif x > 3 then return 1 else return 99 end",
    )
    .unwrap();
    assert_eq!(v.as_int(), Some(99));
}

#[test]
fn while_loop_counts() {
    let v = eval(
        "local i = 0\nwhile i < 10 do i = i + 1 end\nreturn i",
    )
    .unwrap();
    assert_eq!(v.as_int(), Some(10));
}

#[test]
fn for_loop_sum() {
    let v = eval(
        "local s = 0\nfor i = 1, 10 do s = s + i end\nreturn s",
    )
    .unwrap();
    assert_eq!(v.as_int(), Some(55));
}

#[test]
fn for_loop_with_step() {
    let v = eval(
        "local s = 0\nfor i = 0, 10, 2 do s = s + i end\nreturn s",
    )
    .unwrap();
    assert_eq!(v.as_int(), Some(30));
}

#[test]
fn for_loop_negative_step() {
    let v = eval(
        "local s = 0\nfor i = 10, 1, -1 do s = s + i end\nreturn s",
    )
    .unwrap();
    assert_eq!(v.as_int(), Some(55));
}

#[test]
fn for_loop_zero_step_terminates() {
    let v = eval("local s = 0\nfor i = 1, 10, 0 do s = s + 1 end\nreturn s").unwrap();
    assert_eq!(v.as_int(), Some(0));
}

#[test]
fn break_exits_while() {
    let v = eval(
        "local i = 0\nwhile i < 100 do i = i + 1 if i == 5 then break end end\nreturn i",
    )
    .unwrap();
    assert_eq!(v.as_int(), Some(5));
}

#[test]
fn break_exits_for() {
    let v = eval(
        "local last = 0\nfor i = 1, 100 do last = i if i == 7 then break end end\nreturn last",
    )
    .unwrap();
    assert_eq!(v.as_int(), Some(7));
}

#[test]
fn do_block_executes() {
    let v = eval("do local x = 9 return x end").unwrap();
    assert_eq!(v.as_int(), Some(9));
}

// ── Functions ──────────────────────────────────────────────────────────────

#[test]
fn function_def_and_call() {
    let v = eval(
        "function add(a, b) return a + b end\nreturn add(3, 4)",
    )
    .unwrap();
    assert_eq!(v.as_int(), Some(7));
}

#[test]
fn function_recursion_factorial() {
    let v = eval(
        "function fact(n) if n <= 1 then return 1 else return n * fact(n - 1) end end\nreturn fact(6)",
    )
    .unwrap();
    assert_eq!(v.as_int(), Some(720));
}

#[test]
fn function_stack_overflow() {
    let r = eval(
        "function f(n) return f(n + 1) end\nreturn f(0)",
    );
    // Either StackOverflow or Timeout (step limit). Must not panic / segfault.
    assert!(matches!(
        r,
        Err(LuaError::StackOverflow) | Err(LuaError::Timeout)
    ));
}

// ── Builtins ───────────────────────────────────────────────────────────────

#[test]
fn builtin_print_captures_output() {
    let mut e = LuaEngine::new();
    let mut ctx = LuaContext::new();
    e.execute(r#"print("hello")"#, &mut ctx).unwrap();
    assert_eq!(ctx.output_text(), "hello");
}

#[test]
fn builtin_print_multiple_args_tab_joined() {
    let mut e = LuaEngine::new();
    let mut ctx = LuaContext::new();
    e.execute(r#"print("a", "b", 3)"#, &mut ctx).unwrap();
    assert_eq!(ctx.output_text(), "a\tb\t3");
}

#[test]
fn builtin_tostring_nil() {
    assert_eq!(
        eval("return tostring(nil)").unwrap().as_str(),
        Some("nil")
    );
}

#[test]
fn builtin_type_returns_name() {
    assert_eq!(eval("return type(1)").unwrap().as_str(), Some("number"));
    assert_eq!(eval("return type(nil)").unwrap().as_str(), Some("nil"));
    assert_eq!(
        eval(r#"return type("x")"#).unwrap().as_str(),
        Some("string")
    );
    assert_eq!(
        eval("return type(true)").unwrap().as_str(),
        Some("boolean")
    );
}

#[test]
fn builtin_assert_truthy_passes() {
    let v = eval("return assert(7)").unwrap();
    assert_eq!(v.as_int(), Some(7));
}

#[test]
fn builtin_assert_falsy_errors() {
    let r = eval(r#"return assert(false, "boom")"#);
    assert!(matches!(r, Err(LuaError::RuntimeError(_))));
}

#[test]
fn builtin_error_raises() {
    let r = eval(r#"error("nope")"#);
    assert!(matches!(r, Err(LuaError::RuntimeError(_))));
}

#[test]
fn builtin_undefined_function_errors() {
    let r = eval("return nope_does_not_exist(1)");
    assert!(matches!(r, Err(LuaError::UndefinedVariable(_))));
}

// ── rustre.* helpers (pure) ────────────────────────────────────────────────

#[test]
fn rustre_hex_to_dec_round_trip() {
    for i in 0..50i64 {
        let n = i * 137;
        let src = format!(
            "return rustre.hex_to_dec(rustre.dec_to_hex({n}))"
        );
        let v = eval(&src).unwrap();
        assert_eq!(v.as_int(), Some(n));
    }
}

#[test]
fn rustre_entropy_empty() {
    let v = eval(r#"return rustre.entropy("")"#).unwrap();
    if let LuaValue::Float(f) = v {
        assert_eq!(f, 0.0);
    } else {
        panic!("expected float");
    }
}

#[test]
fn rustre_entropy_uniform_high() {
    let v = eval(r#"return rustre.entropy("abcdefghABCDEFGH01234567")"#).unwrap();
    if let LuaValue::Float(f) = v {
        assert!(f > 3.0, "expected entropy > 3, got {f}");
    } else {
        panic!("expected float");
    }
}

#[test]
fn rustre_xor_bytes_involution() {
    // (x XOR k) XOR k == x for single-byte key
    let v = eval(
        r#"return rustre.xor_bytes(rustre.xor_bytes("hello", 42), 42)"#,
    )
    .unwrap();
    assert_eq!(v.as_str(), Some("hello"));
}

// ── Parser fuzz: must never panic ──────────────────────────────────────────

#[test]
fn parser_fuzz_random_bytes_never_panics() {
    let mut g = lcg();
    for _ in 0..200 {
        let len = (g() as usize) % 64;
        let mut s = String::new();
        for _ in 0..len {
            let c = (g() as u8) & 0x7f;
            if c >= 0x20 && c != 0x7f {
                s.push(c as char);
            } else {
                s.push(' ');
            }
        }
        let e = LuaEngine::new();
        let _ = e.parse(&s); // Ok or Err, no panic
    }
}

#[test]
fn execute_fuzz_random_short_programs_never_panic() {
    let mut g = lcg();
    let snippets = [
        "return ",
        "local x = ",
        "if then end",
        "for i = 1, do end",
        "while do end",
        "function f() end",
        "1 + ",
        ".. ",
        "\"unterm",
        "-- comment\n",
    ];
    for _ in 0..200 {
        let a = &snippets[(g() as usize) % snippets.len()];
        let b = &snippets[(g() as usize) % snippets.len()];
        let combined = format!("{a}{b}");
        let mut e = LuaEngine::new();
        let mut ctx = LuaContext::new();
        let _ = e.execute(&combined, &mut ctx);
    }
}

// ── Step limit & timeout ───────────────────────────────────────────────────

#[test]
fn execute_step_limit_triggers_timeout() {
    let mut e = LuaEngine::new();
    e.set_max_steps(50);
    let mut ctx = LuaContext::new();
    let r = e.execute(
        "local i = 0\nwhile i < 1000000 do i = i + 1 end\nreturn i",
        &mut ctx,
    );
    assert!(matches!(r, Err(LuaError::Timeout)));
}

#[test]
fn step_count_increases() {
    let mut e = LuaEngine::new();
    let mut ctx = LuaContext::new();
    assert_eq!(e.step_count(), 0);
    e.execute("local x = 1 + 2 + 3", &mut ctx).unwrap();
    assert!(e.step_count() > 0);
}

// ── Tables ─────────────────────────────────────────────────────────────────

#[test]
fn table_constructor_array_style() {
    let v = eval("local t = {1, 2, 3}\nreturn t[1]").unwrap();
    assert_eq!(v.as_int(), Some(1));
}

#[test]
fn table_index_missing_returns_nil() {
    let v = eval("local t = {1, 2}\nreturn t[99]").unwrap();
    assert!(matches!(v, LuaValue::Nil));
}

#[test]
fn table_index_on_non_table_errors() {
    let r = eval("local x = 5\nreturn x[1]");
    assert!(matches!(r, Err(LuaError::TypeError { .. })));
}

// ── LuaError Display ───────────────────────────────────────────────────────

#[test]
fn error_display_formats() {
    let e = LuaError::SyntaxError {
        line: 3,
        message: "boom".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("line 3"));
    assert!(s.contains("boom"));

    let e = LuaError::RuntimeError("x".to_string());
    assert!(e.to_string().contains("runtime error"));
    assert_eq!(LuaError::Timeout.to_string(), "execution timeout");
    assert_eq!(LuaError::StackOverflow.to_string(), "stack overflow");
}

// ── Send/Sync threaded stress ──────────────────────────────────────────────

#[test]
fn engine_per_thread_stress() {
    // LuaEngine + LuaContext are owned per-thread; verify we can run
    // independent engines in parallel without panics or data races.
    let handles: Vec<_> = (0..4)
        .map(|tid| {
            std::thread::spawn(move || {
                let mut total: i64 = 0;
                for i in 0..100i64 {
                    let mut e = LuaEngine::new();
                    let mut ctx = LuaContext::new();
                    let src = format!("return {tid} * {i} + {i}");
                    let v = e.execute(&src, &mut ctx).unwrap();
                    total = total.wrapping_add(v.as_int().unwrap());
                }
                total
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

// ── AST construction sanity ────────────────────────────────────────────────

#[test]
fn ast_types_constructable() {
    // Smoke test: enum variants compile and match.
    let _e = LuaExpr::BinOp {
        op: BinOp::Add,
        left: Box::new(LuaExpr::Int(1)),
        right: Box::new(LuaExpr::Int(2)),
    };
    let _e = LuaExpr::UnOp {
        op: UnOp::Neg,
        operand: Box::new(LuaExpr::Int(5)),
    };
    let _s = LuaStmt::Break;
    let _s = LuaStmt::Return(LuaExpr::Nil);
}

#[test]
fn parse_then_inspect_returns_statements() {
    let e = LuaEngine::new();
    let stmts = e.parse("local x = 1\nreturn x").unwrap();
    assert!(stmts.len() >= 2);
}
