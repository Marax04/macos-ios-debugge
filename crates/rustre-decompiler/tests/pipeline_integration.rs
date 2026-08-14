//! Phase E integration tests for the rustre-decompiler pipeline.
//!
//! These tests lock in the current pipeline behavior end-to-end: building
//! synthetic x86_64 instruction sequences, running them through
//! `DefaultPipelineFactory::standard` + `run_with_structured_emit`, and
//! asserting on the resulting pseudo-C string.
//!
//! The passes in this crate operate on textual `Instruction` mnemonic /
//! operand fields rather than raw machine bytes, so the helpers below build
//! `Instruction` values directly. The `bytes` field is populated with the
//! corresponding encoding so the data is still meaningful to downstream
//! byte-level consumers.

use rustre_core::address::Address;
use rustre_core::arch::{InstrFlags, Instruction};
use rustre_decompiler::{DecompOptions, DefaultPipelineFactory};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build a single `Instruction` at `addr` with the given mnemonic, operands,
/// and raw bytes.
fn instr(addr: u64, bytes: &[u8], mnem: &str, ops: &str) -> Instruction {
    let mut i = Instruction::new(Address::new(addr), bytes.len(), mnem.to_string(), bytes.to_vec());
    i.operands = ops.to_string();
    i.flags = InstrFlags::NONE;
    i
}

/// Lay out instructions sequentially starting at `base`, deriving each
/// instruction's address from the cumulative byte length of its predecessors.
fn assemble(items: &[(&[u8], &str, &str)], base: u64) -> Vec<Instruction> {
    let mut out = Vec::with_capacity(items.len());
    let mut cur = base;
    for (bytes, mnem, ops) in items {
        out.push(instr(cur, bytes, mnem, ops));
        cur = cur.wrapping_add(u64::try_from(bytes.len()).unwrap_or(0));
    }
    out
}

/// Run a sequence of instructions through the standard pipeline (with
/// structured emit) and return the resulting pseudo-C string.
fn decompile_bytes(items: &[(&[u8], &str, &str)], base: u64) -> String {
    let instructions = assemble(items, base);
    let pipeline = DefaultPipelineFactory::standard(DecompOptions::default());
    let func = pipeline
        .run_with_structured_emit(base, "test_fn", &instructions)
        .expect("pipeline run should succeed");
    func.pseudo_code
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Linear arithmetic
// ─────────────────────────────────────────────────────────────────────────────
//
//   mov eax, ecx       ; 89 c8
//   add eax, edx       ; 01 d0
//   imul eax, eax, 3   ; 6b c0 03
//   ret                ; c3

#[test]
fn linear_arithmetic_emits_structured_c() {
    let prog: &[(&[u8], &str, &str)] = &[
        (&[0x89, 0xc8], "mov", "eax, ecx"),
        (&[0x01, 0xd0], "add", "eax, edx"),
        (&[0x6b, 0xc0, 0x03], "imul", "eax, eax, 3"),
        (&[0xc3], "ret", ""),
    ];
    let code = decompile_bytes(prog, 0x1000);

    assert!(!code.is_empty(), "pseudo-C output must not be empty");
    assert!(
        !code.contains("// raw disasm"),
        "structured output should not contain raw-disasm fallback marker: {code}"
    );
    assert!(
        code.contains("return"),
        "structured C should contain a `return` somewhere: {code}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Conditional branch
// ─────────────────────────────────────────────────────────────────────────────
//
//   test ecx, ecx      ; 85 c9
//   je   L1            ; 74 05
//   mov  eax, 1        ; b8 01 00 00 00
//   ret                ; c3
// L1:
//   xor  eax, eax      ; 31 c0
//   ret                ; c3

#[test]
fn conditional_branch_emits_if_or_return_value() {
    let prog: &[(&[u8], &str, &str)] = &[
        (&[0x85, 0xc9], "test", "ecx, ecx"),
        // Target the `xor` instruction boundary (0x100a), where L1 actually
        // begins given the byte layout below.
        (&[0x74, 0x05], "je", "0x100a"),
        (&[0xb8, 0x01, 0x00, 0x00, 0x00], "mov", "eax, 1"),
        (&[0xc3], "ret", ""),
        (&[0x31, 0xc0], "xor", "eax, eax"),
        (&[0xc3], "ret", ""),
    ];
    let code = decompile_bytes(prog, 0x1000);

    assert!(code.contains("if ("), "expected an `if` construct, got: {code}");
    assert!(
        !code.contains("goto "),
        "if/else should be fully structured, no residual goto: {code}"
    );
    // `je` jumps to the `xor eax, eax` arm, so the taken branch must be the
    // zero one. A successor-ordering bug previously inverted this.
    let then_zero = code
        .split_once("if (a1 == 0)")
        .and_then(|(_, rest)| rest.split_once("else"))
        .is_some_and(|(then_arm, _)| then_arm.contains("result = 0"));
    assert!(then_zero, "the `a1 == 0` arm must set result to 0, got: {code}");
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. While loop
// ─────────────────────────────────────────────────────────────────────────────
//
//   xor  eax, eax      ; 31 c0
// L:
//   cmp  eax, ecx      ; 39 c8
//   jge  done          ; 7d 03
//   inc  eax           ; ff c0
//   jmp  L             ; eb f9
// done:
//   ret                ; c3

#[test]
fn while_loop_emits_loop_construct() {
    let prog: &[(&[u8], &str, &str)] = &[
        (&[0x31, 0xc0], "xor", "eax, eax"),
        (&[0x39, 0xc8], "cmp", "eax, ecx"),
        // Target the `ret` boundary (0x100a = `done`) per the byte layout.
        (&[0x7d, 0x03], "jge", "0x100a"),
        (&[0xff, 0xc0], "inc", "eax"),
        (&[0xeb, 0xf9], "jmp", "0x1002"),
        (&[0xc3], "ret", ""),
    ];
    let code = decompile_bytes(prog, 0x1000);

    // The back edge must be recovered as a real loop construct, not as goto
    // soup: the CFG splitter builds the cycle and the structurer folds it.
    let has_loop = code.contains("while (") || code.contains("for (") || code.contains("do {");
    assert!(has_loop, "expected a loop construct, got: {code}");
    assert!(
        !code.contains("goto "),
        "loop should be fully structured, no residual goto: {code}"
    );

    // The loop body must survive: `inc eax` is the induction step. An earlier
    // structurer bug dropped the body entirely and emitted `do { return; }`.
    // It is folded to the C increment operator, as Hex-Rays does.
    assert!(
        code.contains("++result"),
        "the induction step must be preserved and folded to `++result`: {code}"
    );

    // The exit test `jge` guards leaving the loop, so the loop condition is its
    // negation, inverted in place rather than wrapped in `!(…)`.
    assert!(
        code.contains("result < a1"),
        "expected the exit condition inverted in place to `result < a1`: {code}"
    );

    // `ecx` is the low half of the first argument register, so the comparison
    // must resolve to the parameter and the signature must declare it. Only the
    // 32-bit halves (`eax`/`ecx`) are touched, so the width narrows to `int` —
    // exactly what Hex-Rays emits, not `__int64`.
    assert!(code.contains("test_fn(int a1)"), "expected `int a1` in the signature: {code}");

    // The declaration block must match what the body uses: `result` declared as
    // `int` (narrowed), no leftover register-named placeholder.
    assert!(code.contains("int result;"), "`result` must be declared as int: {code}");
    assert!(!code.contains("r_eax"), "no register-named placeholder decl: {code}");

    // The initializer is hoisted into the `for` header, so the whole loop reads
    // exactly as Hex-Rays would emit it.
    assert!(
        code.contains("for (result = 0; result < a1; ++result)"),
        "expected the Hex-Rays-identical for header: {code}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Function call
// ─────────────────────────────────────────────────────────────────────────────
//
//   sub  rsp, 0x28                  ; 48 83 ec 28
//   call 0x2000                     ; e8 cb 0f 00 00
//   add  rsp, 0x28                  ; 48 83 c4 28
//   ret                             ; c3

#[test]
fn function_call_emits_call_expression() {
    let prog: &[(&[u8], &str, &str)] = &[
        (&[0x48, 0x83, 0xec, 0x28], "sub", "rsp, 0x28"),
        (&[0xe8, 0xcb, 0x0f, 0x00, 0x00], "call", "0x2000"),
        (&[0x48, 0x83, 0xc4, 0x28], "add", "rsp, 0x28"),
        (&[0xc3], "ret", ""),
    ];
    let code = decompile_bytes(prog, 0x1000);

    assert!(!code.is_empty(), "pseudo-C output must not be empty");
    assert!(
        code.contains('(') && code.contains(')'),
        "output should contain `(` and `)` indicating a call expression: {code}"
    );
    // A void function must not `return` a value: the tail call keeps its side
    // effect but loses the `return`, which is what a C compiler would demand.
    if code.trim_start().starts_with("void") {
        assert!(
            !code.contains("return sub_"),
            "void function must not return a value: {code}"
        );
        assert!(code.contains("sub_2000();"), "the call must survive: {code}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. mainCRTStartup-style: two calls then ret
// ─────────────────────────────────────────────────────────────────────────────
//
//   sub  rsp, 0x28                  ; 48 83 ec 28
//   call 0x2000   ; _security_init_cookie ; e8 cb 0f 00 00
//   call 0x3000   ; _scrt_common_main_seh ; e8 c6 1f 00 00
//   add  rsp, 0x28                  ; 48 83 c4 28
//   ret                             ; c3

#[test]
fn maincrtstartup_style_emits_two_call_patterns() {
    let prog: &[(&[u8], &str, &str)] = &[
        (&[0x48, 0x83, 0xec, 0x28], "sub", "rsp, 0x28"),
        (&[0xe8, 0xcb, 0x0f, 0x00, 0x00], "call", "0x2000"),
        (&[0xe8, 0xc6, 0x1f, 0x00, 0x00], "call", "0x3000"),
        (&[0x48, 0x83, 0xc4, 0x28], "add", "rsp, 0x28"),
        (&[0xc3], "ret", ""),
    ];
    let code = decompile_bytes(prog, 0x1000);

    assert!(!code.is_empty(), "pseudo-C output must not be empty");

    // Two distinct call-site references. The CallSitePass records direct call
    // targets, and `build_cfg` emits one CFG block per unique call site, so
    // both target addresses should be visible in the structured output as
    // either `0x2000`/`0x3000` literals or `sub_2000`/`sub_3000` labels.
    let target_2000 = code.contains("0x2000") || code.contains("sub_2000") || code.contains("2000");
    let target_3000 = code.contains("0x3000") || code.contains("sub_3000") || code.contains("3000");
    assert!(
        target_2000 && target_3000,
        "expected two distinct call-target references (0x2000 and 0x3000) in output: {code}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Call with reconstructed arguments
// ─────────────────────────────────────────────────────────────────────────────
//
//   mov ecx, 10          ; b9 0a 00 00 00
//   mov edx, 20          ; ba 14 00 00 00
//   call 0x2000          ; e8 00 10 00 00
//   ret                  ; c3

#[test]
fn call_reconstructs_argument_list() {
    let prog: &[(&[u8], &str, &str)] = &[
        (&[0xb9, 0x0a, 0x00, 0x00, 0x00], "mov", "ecx, 0xa"),
        (&[0xba, 0x14, 0x00, 0x00, 0x00], "mov", "edx, 0x14"),
        (&[0xe8, 0x00, 0x10, 0x00, 0x00], "call", "0x2000"),
        (&[0xc3], "ret", ""),
    ];
    let code = decompile_bytes(prog, 0x1000);

    // The two 32-bit arg-register loads (`ecx`, `edx`) must fold into the call's
    // argument list, decimalized, with their setup assignments removed.
    assert!(code.contains("sub_2000(10, 20)"), "expected `sub_2000(10, 20)`: {code}");
    // No leftover argument-register assignments.
    assert!(!code.contains("= 10;") && !code.contains("= 20;"), "arg setup must be folded away: {code}");
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Stack-local slot: [rbp-4] used as a local variable
// ─────────────────────────────────────────────────────────────────────────────
//
//   mov [rbp-4], ecx     ; 89 4d fc
//   mov eax, [rbp-4]     ; 8b 45 fc
//   add eax, 5           ; 83 c0 05
//   mov [rbp-4], eax     ; 89 45 fc
//   mov eax, [rbp-4]     ; 8b 45 fc
//   ret                  ; c3

#[test]
fn stack_slot_becomes_named_local() {
    let prog: &[(&[u8], &str, &str)] = &[
        (&[0x89, 0x4d, 0xfc], "mov", "[rbp-4], ecx"),
        (&[0x8b, 0x45, 0xfc], "mov", "eax, [rbp-4]"),
        (&[0x83, 0xc0, 0x05], "add", "eax, 5"),
        (&[0x89, 0x45, 0xfc], "mov", "[rbp-4], eax"),
        (&[0x8b, 0x45, 0xfc], "mov", "eax, [rbp-4]"),
        (&[0xc3], "ret", ""),
    ];
    let code = decompile_bytes(prog, 0x1000);

    // No raw frame reference and no undeclared frame-pointer deref survives.
    assert!(!code.contains("rbp"), "no raw rbp reference should remain: {code}");
    assert!(!code.contains("*(v"), "no undeclared frame-pointer deref: {code}");

    // Store-to-load forwarding collapses the whole function: `[rbp-4]` was just
    // a temporary for `a1`, and the intermediate `result` forwards into the
    // return, so the body is `return a1 + 5;` — byte-identical to Hex-Rays.
    assert!(!code.contains("v_4") && !code.contains("var_4"), "slot must be forwarded away: {code}");
    assert!(code.contains("return a1 + 5;"), "must fully forward to `return a1 + 5;`: {code}");
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Nested if / else-if chain
// ─────────────────────────────────────────────────────────────────────────────
//
//   cmp ecx, 10          ; 83 f9 0a
//   jle L1 (0x100b)      ; 7e 06
//   mov eax, 1 ; ret
// L1:
//   cmp ecx, 5           ; 83 f9 05
//   jle L2 (0x1016)      ; 7e 06
//   mov eax, 2 ; ret
// L2:
//   mov eax, 3 ; ret

#[test]
fn nested_if_recovers_structure_and_hexrays_types() {
    let prog: &[(&[u8], &str, &str)] = &[
        (&[0x83, 0xf9, 0x0a], "cmp", "ecx, 0xa"),
        (&[0x7e, 0x06], "jle", "0x100b"),
        (&[0xb8, 0x01, 0x00, 0x00, 0x00], "mov", "eax, 1"),
        (&[0xc3], "ret", ""),
        (&[0x83, 0xf9, 0x05], "cmp", "ecx, 0x5"),
        (&[0x7e, 0x06], "jle", "0x1016"),
        (&[0xb8, 0x02, 0x00, 0x00, 0x00], "mov", "eax, 2"),
        (&[0xc3], "ret", ""),
        (&[0xb8, 0x03, 0x00, 0x00, 0x00], "mov", "eax, 3"),
        (&[0xc3], "ret", ""),
    ];
    let code = decompile_bytes(prog, 0x1000);

    // Two nested conditionals, no residual goto.
    assert_eq!(code.matches("if (").count(), 2, "expected two nested `if`s: {code}");
    assert!(!code.contains("goto "), "must be fully structured: {code}");

    // A signed compare (`jle`) must NOT be typed `size_t`; only 32-bit halves
    // are touched → `int a1`.
    assert!(code.contains("test_fn(int a1)"), "expected `int a1`: {code}");
    assert!(!code.contains("size_t"), "signed compare must not yield size_t: {code}");

    // Small compare constants print as decimal, like Hex-Rays.
    assert!(code.contains("a1 <= 10"), "expected decimal `a1 <= 10`: {code}");
    assert!(code.contains("a1 <= 5"), "expected decimal `a1 <= 5`: {code}");
    assert!(!code.contains("0xa") && !code.contains("0x5"), "no small hex left: {code}");

    // Each arm returns its own constant.
    for v in ["result = 1", "result = 2", "result = 3"] {
        assert!(code.contains(v), "missing arm `{v}`: {code}");
    }
}
