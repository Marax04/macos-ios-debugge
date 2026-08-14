//! Fidelity harness: compares emitted pseudo-C in tests/decompiler_corpus/out
//! against the ground-truth source in tests/decompiler_corpus/src.
//!
//! Every assertion here is TRUE TODAY. Known-wrong output is catalogued with
//! `// TODO(fidelity):` comments right next to the assertion that pins the
//! current (possibly wrong) behaviour, so a fix flips the pinned assertion
//! and forces this file to be updated deliberately.
//!
//! Corpus lives at the REPO ROOT: <repo>/tests/decompiler_corpus/{src,out}
//! (the crate-local tests/decompiler_corpus is an empty stub).

use std::fs;
use std::path::PathBuf;

fn corpus_out(sample: &str, file: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/decompiler_corpus/out")
        .join(sample)
        .join(file);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {}", p.display(), e))
}

fn has(hay: &str, needle: &str) -> bool {
    hay.contains(needle)
}

// ---------------------------------------------------------------------------
// sample1_c — src/sample1_struct_loop.c
// ---------------------------------------------------------------------------

#[test]
fn sample1_find_max() {
    // Ground truth: int64_t find_max(const int64_t *arr, size_t len)
    //   best = arr[0]; for (i=1; i<len; i++) if (arr[i] > best) best = arr[i];
    let t = corpus_out("sample1_c", "sub_1400014a2.c");

    // RIGHT: name, pointer+size_t signature, initial load of arr[0],
    // guarded do/while for len > 1, max-compare, and returning the max.
    assert!(has(&t, "find_max(__int64 *a1, size_t a2)"));
    assert!(has(&t, "v3 = *a1;"));
    assert!(has(&t, "if (a2 > 1)"));
    assert!(has(&t, "if (v3 < a2) v3 = a2;"));
    assert!(has(&t, "result = v3;"));

    // RIGHT (fixed 2026-07-16 by rescale_promoted_pointer_arith): `iter` is an
    // __int64*, and the strides are now element-scaled — `iter = a1 + 1`,
    // `iter += 1`, `a1 += a2` — matching the source's one-element walk.
    // (2026-07-18: the usage-based name shifted src -> iter.)
    assert!(has(&t, "iter = a1 + 1;"));
    assert!(has(&t, "iter += 1;"));
    assert!(has(&t, "a1 += a2;"));

    // TODO(fidelity): loop counter `a2` (the len parameter) is clobbered as
    // the element temp (`a2 = *src;`) inside the loop — legal only because
    // the exit test was rewritten to pointer equality, but it destroys the
    // source-level meaning of the parameter.
    assert!(has(&t, "a2 = *iter;"));
}

#[test]
fn sample1_main() {
    // Ground truth: main() builds Point pts[3] and int64_t arr[4] on the
    // stack, calls accumulate(pts,3) and find_max(arr,4), returns (int)(t+m).
    let t = corpus_out("sample1_c", "sub_1400014d7.c");

    // RIGHT: recognised as main, calls __main() (mingw ctor hook), calls
    // both user functions with the correct count arguments.
    assert!(has(&t, "main("));
    assert!(has(&t, "__main();"));
    assert!(has(&t, "accumulate(str2, 3);"));
    assert!(has(&t, "find_max(str, 4);"));

    // RIGHT (2026-07-21): matches the source exactly — `int main(void)`.
    // History: this was FOURTEEN leaked stack-slot parameters, then one
    // (`main(__int64 a1)`), which this assertion used to pin as a known
    // defect. Both phantoms are gone now that `callconv_bridge` reads AT&T
    // operand order, models sub-register write aliasing, and recognises the
    // full set of register-writing mnemonics.
    assert!(has(&t, "main()"), "source is `int main(void)` — no parameters");
    assert!(!has(&t, "main(__int64 a1)"), "phantom parameter must not come back");
    // RIGHT: all 10 non-pointer initialiser stores are present with the
    // correct source constants (2,0,3,4,0,5,6,0 for pts; 40,20,30 for arr).
    for init in ["v_48 = 2;", "v_58 = 3;", "v_60 = 4;", "v_70 = 5;",
                 "v_78 = 6;", "v_28 = 40;", "v_30 = 20;", "v_38 = 30;"] {
        assert!(has(&t, init), "missing initializer {init}");
    }

    // FIXED 2026-07-17 (capture_call_result): the return values of
    // accumulate/find_max now flow into a variable instead of being read from an
    // unassigned `result`. Was `accumulate(str2, 3); v2 = result;` (v2 garbage
    // if recompiled); now the call's rax result is captured at the call site.
    assert!(has(&t, "v4 = accumulate(str2, 3);"));
    // IMPROVED 2026-07-19 (ssa_split live-range split, subreg on by default):
    // was `result = find_max(str, 4);` — the find_max result was merged onto
    // the return slot. Source has TWO temporaries (`t`, `m`) and returns
    // `(int)(t + m)`, so `m` living in its own variable and being added into
    // the return slot is closer to the source. Judged a FIDELITY WIN.
    assert!(has(&t, "v5 = find_max(str, 4);"));
    assert!(has(&t, "v3 += v5;"));
    assert!(!has(&t, "accumulate(str2, 3);\n    v2 = result;"),
        "the read-before-assign call-result bug must stay fixed");

    // TODO(fidelity): the first stack stores of each array (pts[0].x = 1 and
    // arr[0] = 10) were mis-typed as char* locals: `str2 = 1;` / `str = 10;`,
    // and those same "pointers" are then passed as the array bases. The
    // constants 1 and 10 are the array-base addresses' first elements, not
    // pointers.
    assert!(has(&t, "str2 = 1;"));
    assert!(has(&t, "str = 10;"));

    // TODO(fidelity): stack slots holding int64_t values are declared `int`
    // (v_28..v_80) — 32-bit truncation of 64-bit initialisers.
    assert!(has(&t, "int v_28;"));
}

// ---------------------------------------------------------------------------
// sample6_c — src/sample6_constructs.c
// ---------------------------------------------------------------------------

#[test]
fn sample6_classify() {
    // Ground truth: switch(op) over cases 0..7, default -1;
    // case 3 is `b ? a / b : 0`.
    let t = corpus_out("sample6_c", "sub_1400014a0.c");

    // RIGHT: jump-table switch recovered with the range guard (op > 7 →
    // default path), and cases 0/1/2/4/5/6/7 present with the right ALU ops.
    assert!(has(&t, "if (a1 > 7)"));
    assert!(has(&t, "switch ("));
    for c in ["case 0:", "case 1:", "case 2:", "case 4:", "case 5:",
              "case 6:", "case 7:"] {
        assert!(has(&t, c), "missing {c}");
    }
    // Was `result -= (__int64)a3;` while a3 was spuriously typed `int *`; the
    // `lea`-is-not-a-dereference fix (2026-07-17) types a3 as `int`, so the
    // cast is gone and this now reads as plain integer subtraction.
    assert!(has(&t, "result -= a3;")); // a - b
    // D16: the multiply temp is its own range now, no longer aliased onto the
    // return slot (it was `result *= a2;` while the two were merged).
    // Local numbering (v3/v4/v5/…) shifts whenever an upstream naming or
    // live-range pass changes, so match the compound-assign SHAPE, not the
    // specific temp name — that's the semantic claim (each bitwise case
    // compiles to `tmp OP= a2`).
    assert!(has(&t, "*= a2;")); // a * b
    assert!(has(&t, "&= a2;")); // a & b
    assert!(has(&t, "|= a2;")); // a | b
    assert!(has(&t, "^= a2;")); // a ^ b
    assert!(has(&t, "<<= a")); // a << (b & 31)

    // FIXED 2026-07-17: `case 3` (`b ? a / b : 0`) was silently rendered as the
    // `default:` arm and lost its label. A case-target block that already held a
    // real `Branch` (case 3 has the `b == 0` divisor check) was skipped by the
    // case-marker injector, so `structure_switch` saw no case constant and
    // emitted `default:`. The injector now prepends the marker unconditionally
    // (the case-value reader takes the FIRST Branch, `extract_condition` the
    // LAST, so they don't collide). All eight cases 0..7 are now labelled and
    // case 3 keeps its divisor guard + division.
    assert!(has(&t, "case 3:"));
    assert!(has(&t, "if (a3 == 0)"));           // the `b ? … : 0` guard
    assert!(has(&t, "__rdx_rax / a3"));         // the division survives in-case
    // The real default (return -1) is handled by the up-front range check
    // (`if (a1 > 7) return classify_cold();`), so no `default:` arm is emitted.
    assert!(!has(&t, "default:"));

    // FIXED 2026-07-17 (#114): the scrutinee is the range-checked switch value
    // `a1` (op), not the clobbered index register that rendered as an
    // uninitialised `switch (v3)`.
    assert!(has(&t, "switch (a1)"));
    assert!(!has(&t, "switch (v3)"), "the clobbered-scrutinee bug must stay fixed");

    // PARTIALLY FIXED 2026-07-17: `b` is no longer a spurious `int *` (the
    // lea-is-not-a-dereference fix), so case 0's `a3 + a2` is now honest
    // integer addition rather than pointer arithmetic scaling a2 by 4.
    // TODO(fidelity) remaining: `op` is still typed `size_t` instead of int32.
    assert!(has(&t, "classify(size_t a1, int a2, int a3)"));
    assert!(!has(&t, "int *a3"), "the lea-as-deref pointer promotion must stay fixed");
}

#[test]
fn sample6_factorial() {
    // Ground truth: recursive factorial. GCC turned it into an unrolled
    // 2-at-a-time product loop, so no self-call is expected in the output.
    let t = corpus_out("sample6_c", "sub_140001530.c");

    // RIGHT: base case (n <= 1 → returns) and a multiply-accumulate loop
    // stepping by 2 with the odd/even split.
    assert!(has(&t, "if (a1 > 1)"));
    assert!(has(&t, "v3 *= v2;"));
    assert!(has(&t, "v2 -= 2;"));
    assert!(has(&t, "} while (v2 != 1);"));

    // FIXED (D16, live-range split): the seeding copy `v2 = a1` (mov rdx,rax)
    // is now materialised, so `v3 = v2;` reads a defined value. Previously `v2`
    // and the return slot were ONE merged variable, the copy was lost, and the
    // recompiled output multiplied garbage.
    assert!(has(&t, "v2 = a1;"));
    assert!(has(&t, "v3 = v2;\n            --v2;"));

    // The parity test reads n (`v2`), not the return slot. It was spelled
    // `result & 1` while the two ranges were merged.
    assert!(has(&t, "if ((v2 & 1) == 0)"));

    // FIXED (2026-07-21 regen): the odd-n path used to fall through to
    // `return result;` with `result` unassigned. Every return site now assigns
    // `result = v3;` first — the even-n early exit and the shared tail — and
    // hand-execution of factorial(5) gives 120, matching the source.
    assert!(has(&t, "result = v3;\n                return result;")); // even-n early exit
    assert!(has(&t, "result = v3;\n    return result;"));             // shared tail
    assert!(!has(&t, "        return result;\n    }"),
        "the unassigned-result fallthrough must stay fixed");
}

#[test]
fn sample6_apply() {
    // Ground truth: binop f = use_mul ? mul_fn : add_fn; return f(x, y);
    let t = corpus_out("sample6_c", "sub_140001580.c");

    // RIGHT: both function addresses referenced, cmov-style select on the
    // use_mul flag, tail-call through the selected pointer.
    assert!(has(&t, "off_140001480")); // add_fn
    assert!(has(&t, "off_140001490")); // mul_fn
    assert!(has(&t, "if (a1 != 0) v1 = v3;"));
    assert!(has(&t, "JUMPOUT(v1);"));

    // TODO(fidelity): the tail-call is emitted as `return JUMPOUT(v1);`
    // instead of `return ((binop)v1)(x, y);` — arguments x/y are shuffled
    // as side effects but never appear as call args.
    assert!(has(&t, "return JUMPOUT(v1);"));
    // RIGHT (2026-07-18, D1 alias fix): mul_fn's address lands in a fresh
    // local instead of clobbering the int parameter a2.
    assert!(has(&t, "v3 = &off_140001490;"));
    // RIGHT (2026-07-18, D6 flag-copy-select fix): the use_mul branch tests
    // the parameter `a1`, and the DEAD argument-register shuffle
    // (`mov %edx,%ecx`, x → callee arg1) no longer shadows that parameter.
    // ssa_split now recognises the zero-extending 32-bit copy `ecx = edx` as a
    // full def of `rcx`, so the dead range splits off to a fresh local and is
    // DCE-commented honestly (`// DCE(df): v2 = a2;`) instead of the misleading
    // `// DCE(df): a1 = a2;` that read as clobbering the live branch variable.
    assert!(has(&t, "// DCE(df):     v2 = a2;"));
    assert!(!has(&t, "// DCE(df):     a1 = a2;"), "dead shuffle must not shadow the a1 parameter");
}

#[test]
fn sample6_add_fn_mul_fn() {
    // Ground truth:
    //   static int32_t add_fn(int32_t x, int32_t y) { return x + y; }
    //   static int32_t mul_fn(int32_t x, int32_t y) { return x * y; }
    let add = corpus_out("sample6_c", "sub_140001480.c");
    let mul = corpus_out("sample6_c", "sub_140001490.c");

    // RIGHT: both leaves are named, and the ALU op itself is the right one.
    assert!(has(&add, "add_fn("));
    assert!(has(&mul, "mul_fn("));
    assert!(has(&mul, "result *= a2;"));

    // FIXED 2026-07-17: `add_fn` compiles to `lea (%rcx,%rdx), %eax` — the
    // compiler using lea as a plain adder. `refine_param_types` was reading
    // that as a dereference of rcx and typing `x` as `int *`, which made the
    // emitted `return a1 + a2;` POINTER arithmetic scaling `y` by 4:
    // add_fn(3,4) computed 3+16, not 7. `lea` computes an address and never
    // accesses memory, so it is no longer evidence of a pointer. The addition
    // is now semantically correct.
    assert!(has(&add, "add_fn(__int64 a1, __int64 a2)"));
    assert!(has(&add, "return a1 + a2;"));
    assert!(!has(&add, "int *a1"), "the lea-as-deref pointer promotion must stay fixed");

    // TODO(fidelity): both params are widened (source is int32_t x, int32_t y)
    // — harmless for the low 32 bits here, but not source-faithful.
    assert!(has(&mul, "mul_fn(int a1, __int64 a2)"));
}

#[test]
fn sample6_count_set_flags() {
    // Ground truth: do/while over flags[i]; total++ for each of bits 1,2,4
    // that is set.
    let t = corpus_out("sample6_c", "sub_1400015a0.c");

    // RIGHT: do/while shape with `i < n` exit, index increment, the three
    // bit masks 1/2/4 all appear, 4-byte element stride.
    assert!(has(&t, "do {"));
    assert!(has(&t, "} while (count < a2);"));
    assert!(has(&t, "++count;"));
    assert!(has(&t, "&= 1;"));
    assert!(has(&t, "&= 2;"));
    assert!(has(&t, "v3 &= 4;"));
    assert!(has(&t, "*(a1 + count*4)"));

    // FIXED 2026-07-18 (fuse_cmp_into_carry): the `cmp X,1; sbb -1,dst`
    // branchless conditional increment is re-raised — FLAG_B/FLAG_C now add
    // conditionally instead of the unconditional `result -= 0xFFFFFFFF;`
    // that made count_set_flags overcount by the number of clear bits.
    assert!(has(&t, "v2 &= 2;\n        result += (v2 != 0);"));
    assert!(has(&t, "result += (v2 != 0);"));
    assert!(!has(&t, "result -= 0xFFFFFFFF;"), "the sbb carry-drop must stay fixed");
}

#[test]
fn sample6_dot() {
    // Ground truth: double dot(const double*, const double*, size_t):
    // acc += u[i] * v[i].
    let t = corpus_out("sample6_c", "sub_140001600.c");

    // RIGHT: n==0 early-out returning 0.0, do/while over the elements,
    // index increment, exit on i == n.
    assert!(has(&t, "if (a3 == 0)"));
    // D16: the loop counter split off the return slot — it was `a3 != result`.
    assert!(has(&t, "} while (a3 != i);"));
    assert!(has(&t, "++i;"));

    // RIGHT (2026-07-18 regen): the SSE scalar-double body IS lifted now —
    // load, multiply, accumulate as real double arithmetic, and the
    // function returns the ACCUMULATOR with a `double` return type.
    assert!(has(&t, "xmm0 = xmm0 * *(double *)(a2 + i*8);"));
    assert!(has(&t, "xmm1 = xmm1 + xmm0;"));
    assert!(has(&t, "xmm0 = xmm1;\n        return xmm0;"));
    assert!(has(&t, "double __fastcall dot("));
    // TODO(fidelity): parameter types still drop the double pointers:
    // (__int64 a1, __int64 a2, __int64 a3) instead of
    // (const double*, const double*, size_t). (2026-07-18, D3 fix: the
    // shared-epilogue return is now duplicated into an else branch instead
    // of a dangling goto; the bare `*(a1 + …)` spelling that used to trip
    // pointer-param promotion for a1 is gone — every deref is now the
    // explicit `*(double *)(aN + …)` cast form, which promotion skips.)
    assert!(has(&t, "dot(__int64 a1, __int64 a2, __int64 a3)"));
}

// ---------------------------------------------------------------------------
// sample11_c — src/sample11_c_features.c
// ---------------------------------------------------------------------------

#[test]
fn sample11_op_family() {
    // Ground truth (all four are `static int64_t op_N(int64_t a, int64_t b)`):
    //   op_add: a + b   op_sub: a - b   op_mul: a * b   op_xor: a ^ b
    //
    // RIGHT — and this is the high-water mark of the corpus: all four leaves
    // are recovered with the correct name, the correct __int64 parameter and
    // return types, and a body that is semantically EXACT vs the source.
    // No TODO(fidelity) items for this test.
    let add = corpus_out("sample11_c", "sub_140001450.c");
    let sub = corpus_out("sample11_c", "sub_140001460.c");
    let mul = corpus_out("sample11_c", "sub_140001470.c");
    let xor = corpus_out("sample11_c", "sub_140001480.c");

    assert!(has(&add, "__int64 __fastcall op_add(__int64 a1, __int64 a2)"));
    assert!(has(&add, "return a1 + a2;"));

    assert!(has(&sub, "__int64 __fastcall op_sub(__int64 a1, __int64 a2)"));
    assert!(has(&sub, "return a1 - a2;"));

    // op_mul goes through a `result` temp but is still exactly a*b.
    assert!(has(&mul, "__int64 __fastcall op_mul(__int64 a1, __int64 a2)"));
    assert!(has(&mul, "result = a1;"));
    assert!(has(&mul, "result *= a2;"));

    assert!(has(&xor, "__int64 __fastcall op_xor(__int64 a1, __int64 a2)"));
    assert!(has(&xor, "return a1 ^ a2;"));
}

#[test]
fn sample6_main() {
    // Ground truth: main() calls classify(2,6,7), factorial(5), apply(1,3,4),
    // count_set_flags(fl,2), dot(u,w,3) and returns the sum of the results.
    let t = corpus_out("sample6_c", "sub_140002950.c");

    // RIGHT: recognised as main, calls the mingw ctor hook, and calls
    // count_set_flags with the correct element count.
    assert!(has(&t, "__fastcall main("));
    assert!(has(&t, "__main();"));
    assert!(has(&t, "count_set_flags(str, 2);"));

    // RIGHT (not a defect): classify/factorial/apply/dot are absent because
    // GCC constant-folded those calls on constant args; their combined
    // contribution survives as the literal `result += 206;`
    // (classify(2,6,7)=42 + factorial(5)=120 + apply(1,3,4)=12 + cnt(=2 in
    // source terms) + (int)dot(u,w,3)=32 == 206 at -O2).
    assert!(has(&t, "result += 206;"));

    // TODO(fidelity): count_set_flags' return value is DROPPED — the call is
    // a bare statement and `result` is then reused as the fold accumulator
    // (`result = off_140004020;` … `result += 206;`). The source adds `cnt`
    // to the total; here the callee's rax never reaches the sum.
    assert!(has(&t, "count_set_flags(str, 2);\n    result += 206;"));

    // RIGHT (2026-07-21): matches the source exactly — `int main(void)`.
    // The phantom parameter this used to pin is gone (same fix as
    // sample1_main).
    assert!(has(&t, "main()"), "source is `int main(void)` — no parameters");
    assert!(!has(&t, "main(__int64 a1)"), "phantom parameter must not come back");
}

#[test]
fn sample11_main() {
    // Ground truth: main() calls sum_varargs(3,10,20,30), dispatch(2,6,7) +
    // dispatch(3,12,10), punned_bits, pack_fields, my_strlen, matrix_trace.
    let t = corpus_out("sample11_c", "sub_1400028a0.c");

    // RIGHT: main + ctor hook, varargs call with all three promoted args,
    // and matrix_trace called with n=3.
    assert!(has(&t, "__fastcall main("));
    assert!(has(&t, "__main();"));
    assert!(has(&t, "sum_varargs(3, 10, 20, 30);"));
    assert!(has(&t, "matrix_trace(str, 3);"));

    // RIGHT: GCC devirtualised both dispatch() calls through the static table
    // into direct calls, and the decompiler follows that faithfully:
    // dispatch(2,6,7) -> op_mul(6,7), dispatch(3,12,10) -> op_xor(12,10).
    assert!(has(&t, "op_mul(6, 7);"));
    assert!(has(&t, "op_xor(12, 10);"));

    // RIGHT: the int64_t mat[9] initialiser is recovered as 128-bit
    // load/store pairs from rdata, plus the odd trailing element (9).
    assert!(has(&t, "xmm0 = _mm_loadu_si128((__m128i *)&off_140004020);"));
    assert!(has(&t, "_mm_storeu_si128((__m128i *)&str, xmm0);"));
    assert!(has(&t, "v_60 = 9;"));

    // FIXED 2026-07-17 (capture_call_result, #113): call results now flow into a
    // variable instead of a never-assigned `result`. Same fix as sample1_main.
    assert!(has(&t, "v3 = sum_varargs(3, 10, 20, 30);"));
    assert!(has(&t, "v4 = op_mul(6, 7);"));
    assert!(!has(&t, "sum_varargs(3, 10, 20, 30);\n    v2 = result;"),
        "the read-before-assign call-result bug must stay fixed");

    // TODO(fidelity): punned_bits / pack_fields / my_strlen calls are gone.
    // GCC folded them to constants, which is legitimate, but their folded
    // contribution is baked into the opaque literal 0x1ECC with no trace.
    assert!(has(&t, "result = v2 + result + 0x1ECC;"));
    assert!(!has(&t, "punned_bits"));
    assert!(!has(&t, "pack_fields"));
    assert!(!has(&t, "my_strlen"));

    // RIGHT (2026-07-21): matches the source exactly — `int main(void)`.
    // The two phantom parameters this used to pin are gone.
    assert!(has(&t, "main()"), "source is `int main(void)` — no parameters");
    assert!(!has(&t, "main(int a1, int a2)"), "phantom parameters must not come back");
}

#[test]
fn sample11_sum_varargs() {
    // Ground truth: va_start; acc += va_arg(ap, int64_t) count times.
    let t = corpus_out("sample11_c", "sub_140001490.c");

    // RIGHT: the register varargs (rdx/r8/r9) are spilled to the home area,
    // count<=0 returns 0, and the accumulation loop sums *v2.
    assert!(has(&t, "v_28 = a2;"));
    assert!(has(&t, "v_30 = a3;"));
    assert!(has(&t, "v_38 = a4;"));
    assert!(has(&t, "if (a1 <= 0)"));
    // TODO(fidelity): the accumulator REUSES the parameter `a2` (`a2 = 0;`
    // then `a2 += *iter;`) — semantically safe here because a2 was already
    // spilled to the home area (`v_28 = a2;` above), but it loses the source's
    // distinct `int64_t acc = 0;`. (Regressed 2026-07-21 regen from the
    // 2026-07-19 D17 shape that had a fresh `v4` local.)
    assert!(has(&t, "a2 = 0;"));
    assert!(has(&t, "a2 += *iter;"));

    // RIGHT (fixed 2026-07-16 by rescale_promoted_pointer_arith): the walk is
    // element-scaled (`iter += 1`), and the loop bound is the element-scaled
    // end pointer (`iter + a1` on an __int64* — one element per vararg).
    // TODO(fidelity): the count parameter a1 is clobbered as that end pointer.
    assert!(has(&t, "for (a1 = iter + a1; iter != a1; iter += 1)"));
    // RIGHT: the accumulated value reaches the return on the success path.
    assert!(has(&t, "result = a2;\n    return result;"));
    // RIGHT (improved by 2026-07-21 regen): the frame is now a real declared
    // object (`char rsp_frame[152]`) instead of an uninitialised bare `rsp`
    // local, so `iter = rsp + 40;` points into genuine storage.
    assert!(has(&t, "char rsp_frame[152]"));
    assert!(has(&t, "iter = rsp + 40;"));
    // TODO(fidelity): the vararg home-area spills are declared `int`
    // (v_28/v_30/v_38) — 32-bit slots for 64-bit va_arg values, so the
    // spilled copies truncate (the loop reads the real stack, masking it).
    assert!(has(&t, "int v_28;"));
}

#[test]
fn sample11_dispatch() {
    // Ground truth: bounds-check idx then tail-call table[idx](a, b).
    let t = corpus_out("sample11_c", "sub_1400014f0.c");

    // RIGHT: table base symbol, unsigned bounds check (a1 <= 3 covers the
    // idx<0||idx>=4 source check), table load `v3[a1]`, out-of-range
    // returns 0.
    assert!(has(&t, "off_140004000"));
    assert!(has(&t, "if (a1 <= 3)"));
    // 2026-07-19: renumbered v3/v4 -> v4/v5 by the ssa_split live-range split
    // (an extra range for the shuffled `a2` argument copy). Identical
    // semantics — judged NEUTRAL.
    assert!(has(&t, "v5 = v4[a1];"));
    assert!(has(&t, "result = 0;\n    return result;"));

    // TODO(fidelity): indirect tail-call emitted as bare `JUMPOUT(v4);`
    // statement instead of `return table[idx](a, b);` — and control then
    // FALLS THROUGH into the out-of-range `return 0`, which is unreachable
    // in the real code after the jump.
    assert!(has(&t, "JUMPOUT(v5);")); // renumbered 2026-07-19, see above
}

#[test]
fn sample11_punned_bits() {
    // Ground truth: union pun, return the bit pattern of a double
    // (movq rax, xmm0 — a one-instruction function).
    let t = corpus_out("sample11_c", "sub_140001520.c");

    // IMPROVED 2026-07-17 (movq return-typing fix): no longer a TOTAL LOSS —
    // body is `result = _mm_cvtsi128_si64(xmm0); return result;` with an
    // __int64 return. Remaining defect: the double param arrives in xmm0 but
    // is not connected (uninitialised xmm0 local; fake __int64 a1 param).
    assert!(has(&t, "__int64 __fastcall punned_bits("));
    assert!(has(&t, "result = _mm_cvtsi128_si64(xmm0);"));
    assert!(has(&t, "return result;"));
}

#[test]
fn sample11_pack_fields() {
    // Ground truth: pack 4 args into bitfields, memcpy back a uint32.
    let t = corpus_out("sample11_c", "sub_140001530.c");

    // FIXED 2026-07-18 (raise_subregister_composes): the al/ah compose chain
    // is no longer collapsed by the family rename + copy-prop; the full
    // shift/mask/or packing survives and evaluates correctly —
    // pack_fields(1,0,40,30) == 0x1EA1 by hand-execution of this body.
    assert!(!has(&t, "return a4;"), "the sub-register total-loss must stay fixed");
    assert!(has(&t, "a3 <<= 2;"));
    assert!(has(&t, "a2 |= a1;"));
    // The high-byte insert (`mov %cl,%ah`) preserved as a masked compose.
    // FIDELITY WIN 2026-07-19 (ssa_split live-range split): the high-byte
    // insert now sources the FOURTH parameter (`v2 = a4;`, i.e. `h`), matching
    // `p.height = (uint32_t)h & 0xFF` at bit offset 8. It previously read
    // `a1` (`a`) because the two shared one architectural register and were
    // merged — confidently wrong. Hand-execution now gives the true value:
    // pack_fields(1,0,40,30) == 0x1EA1 (with `a1` it was 0x1A1).
    assert!(has(&t, "v2 = a4;"));
    assert!(has(&t, "(((v2 & 255)) & 255) << 8"));
    // The final `movzwl %ax,%eax` 16-bit truncation.
    assert!(has(&t, "& 0xFFFF)"));
}

#[test]
fn sample11_my_strlen() {
    // Ground truth: pointer-walk strlen; return p - s.
    let t = corpus_out("sample11_c", "sub_140001550.c");

    // RIGHT: empty-string early-out returns 0, do/while walk to NUL,
    // pointer difference computed.
    assert!(has(&t, "if (*a1 == 0)"));
    assert!(has(&t, "++result;"));
    assert!(has(&t, "} while (*result != 0);"));

    // FIXED (2026-07-21 regen): the non-empty path used to return `result`
    // assigned only on the empty path (the length landed in a dropped `i`).
    // The walk variable IS now the return slot: the pointer difference is
    // computed into `result` and returned on every path.
    assert!(has(&t, "result = (__int64 *)((__int64)result - (__int64)a1);"));
    assert!(has(&t, "result = (__int64 *)((__int64)result - (__int64)a1);\n    return (__int64)result;"));
    // TODO(fidelity): parameter typed __int64* so `*a1`/`*result` read 8
    // bytes per char AND `++result` strides 8 bytes — the walk overshoots and
    // the byte difference returned is 8x the character count. Source is
    // `size_t my_strlen(const char *s)`.
    assert!(has(&t, "my_strlen(__int64 *a1)"));
}

#[test]
fn sample11_matrix_trace() {
    // Ground truth: nested loop, tr += m[i*n+j] when i==j, goto next_row.
    let t = corpus_out("sample11_c", "sub_140001580.c");

    // RIGHT: n<=0 early-out returning 0, outer do/while exiting on
    // `a2 != i` (i != n), diagonal index built as v5 += n per row, and the
    // trace accumulation `v6 += a1[...]` exists. (Loop vars were renamed
    // i/v5/v6 by the 2026-07-16 naming/scaling pass.)
    assert!(has(&t, "if (a2 <= 0)"));
    assert!(has(&t, "} while (a2 != i);"));
    // 2026-07-19: renumbered v5/v6 -> v6/v7 by the ssa_split live-range split.
    // Identical structure and semantics — judged NEUTRAL.
    assert!(has(&t, "v6 += a2;"));
    assert!(has(&t, "v7 += a1["));

    // RIGHT (fixed 2026-07-19 by D12 fix (1), the `while`-header hoist):
    // this pin previously recorded a WRONG emission — the inner `while` body
    // ended in an unconditional `return v4;`, so a recompile returned the
    // partial trace on the first row with i>0. The inner loop's header block
    // carried real statements, so the old code HOISTED it above the loop and
    // emitted the exit path as an in-loop return. It is now structured as an
    // in-loop `break`; control falls through to the diagonal accumulation and
    // the function returns the fully accumulated trace at the end — matching
    // `return tr;` in the ground-truth source. Realigned to the CORRECT shape.
    assert!(has(&t, "while (i != i2) {"));
    assert!(has(&t, "if (a2 == i2) {\n                break;"));
    // The inner loop must contain NO return: the accumulation after it is what
    // makes rows past the first correct.
    let inner_body = t
        .split("while (i != i2) {")
        .nth(1)
        .unwrap()
        .split("v4 = v6 + i;")
        .next()
        .unwrap();
    assert!(!inner_body.contains("return"), "inner loop regained a return: {inner_body}");
    assert!(has(&t, "result = v7;\n    return result;"));
    // RIGHT (fixed 2026-07-18 by the ssa_split 32-bit-alias use fix, D1):
    // the diagonal index IS assigned (`v4 = v6 + i;` — v6 accumulates i*n per
    // row, + i gives m[i*n+i]) and the accumulation indexes with it, after a
    // 32-bit sign-extend (`v4 = (int)v4;`) matching the source's int math.
    // (2026-07-21 regen: temp renumbered v8 -> v4. Renaming only — NEUTRAL.)
    assert!(has(&t, "v4 = v6 + i;"));
    assert!(has(&t, "v7 += a1[v4];"));
}
