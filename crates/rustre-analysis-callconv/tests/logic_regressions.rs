//! Regression tests for logic defects found by the wave-1 semantic audit.
//!
//! Written BEFORE their fixes and confirmed to fail against the then-current
//! code, with the exact output the audit predicted.

use rustre_analysis_callconv::{
    get_arg_types, ArgType, CallingConvDef, CcStackCleanup, FunctionInfo,
};

/// Build a convention that differs from the real ones only where this test
/// cares: the name of the integer return register.
fn cc(name: &'static str, int_ret_reg: &'static str) -> CallingConvDef {
    CallingConvDef {
        name,
        int_arg_regs: &[],
        float_arg_regs: &[],
        int_ret_reg,
        float_ret_reg: "",
        callee_saved: &[],
        stack_cleanup: CcStackCleanup::Caller,
        stack_align: 16,
        has_this_ptr: false,
        shadow_space: 0,
    }
}

fn stack_offsets(cc: &CallingConvDef, count: u32) -> Vec<u32> {
    let mut f = FunctionInfo::new(0x1000, cc.name);
    f.stack_arg_count = count;
    get_arg_types(&f, cc)
        .into_iter()
        .filter_map(|a| match a {
            ArgType::Stack { offset, .. } => Some(offset),
            _ => None,
        })
        .collect()
}

/// The stack-slot size was guessed from whether the integer return register
/// name starts with `'r'`. That is exactly INVERTED for ARM32 (`r0` is a
/// 32-bit register, so the guess says 8 bytes) and wrong for every non-x86
/// 64-bit ABI (`x0`, `v0`, `a0` do not start with `r`, so the guess says 4).
/// It only happened to be right for x86 (`eax` → 4) and x86-64 (`rax` → 8).
#[test]
fn arm64_stack_slots_are_eight_bytes() {
    // AAPCS64: x0 is the integer return register, pointers are 8 bytes.
    let aapcs64 = cc("aapcs64", "x0");
    assert_eq!(
        stack_offsets(&aapcs64, 3),
        vec![0, 8, 16],
        "a 64-bit ABI has 8-byte stack slots even though its return register \
         is not named `r…`"
    );
}

#[test]
fn arm32_stack_slots_are_four_bytes() {
    // AAPCS32: r0 is the integer return register, pointers are 4 bytes.
    let aapcs32 = cc("aapcs32", "r0");
    assert_eq!(
        stack_offsets(&aapcs32, 3),
        vec![0, 4, 8],
        "a 32-bit ABI has 4-byte stack slots even though its return register \
         IS named `r…`"
    );
}

/// The two x86 cases were right by accident and must stay right.
#[test]
fn x86_stack_slots_are_unchanged() {
    assert_eq!(stack_offsets(&cc("cdecl", "eax"), 3), vec![0, 4, 8]);
    assert_eq!(stack_offsets(&cc("sysv_amd64", "rax"), 3), vec![0, 8, 16]);
}

/// Shadow space still shifts every slot, and slots stay evenly spaced.
#[test]
fn shadow_space_offsets_all_slots() {
    let mut ms_x64 = cc("ms_x64", "rax");
    ms_x64.shadow_space = 32;
    assert_eq!(stack_offsets(&ms_x64, 3), vec![32, 40, 48]);
}

/// The general property: consecutive stack slots are exactly one pointer
/// apart, whatever the ABI is called.
#[test]
fn stack_slots_are_evenly_spaced_by_the_pointer_width() {
    for (ret_reg, width) in [("x0", 8u32), ("r0", 4), ("rax", 8), ("eax", 4), ("a0", 8)] {
        let c = cc("probe", ret_reg);
        let offs = stack_offsets(&c, 4);
        for w in offs.windows(2) {
            assert_eq!(
                w[1] - w[0],
                width,
                "return register {ret_reg}: slots must be {width} bytes apart, got {offs:?}"
            );
        }
    }
}

// ── VariadicDetector::detect_by_name ───────────────────────────────────────

use rustre_analysis_callconv::variadic::{is_printf_family, VariadicDetection};

/// The `v*` printf functions take a `va_list`, not a variable argument list:
/// `vprintf(const char *fmt, va_list ap)` has exactly TWO fixed parameters and
/// is not variadic at all. Listing them in the printf-family table made
/// `detect_by_name` report them variadic with confidence 99 and a fixed-arg
/// count of 1 — confidently wrong on both counts.
#[test]
fn va_list_taking_functions_are_not_variadic() {
    let d = VariadicDetection::default();
    for name in ["vprintf", "vfprintf", "vsprintf", "vsnprintf"] {
        let r = d.detect_by_name(0x1000, name);
        assert!(
            !r.is_variadic,
            "{name} takes a va_list and is not variadic; got {r:?}"
        );
    }
}

/// `OutputDebugStringA(LPCSTR)` takes exactly one argument and has no format
/// string at all.
#[test]
fn output_debug_string_is_not_variadic() {
    let d = VariadicDetection::default();
    let r = d.detect_by_name(0x1000, "OutputDebugStringA");
    assert!(!r.is_variadic, "OutputDebugStringA takes a single string");
}

/// The genuinely variadic members must keep being detected, with the right
/// fixed-argument counts.
#[test]
fn real_printf_family_members_stay_variadic() {
    let d = VariadicDetection::default();
    for (name, fixed) in [
        ("printf", 1usize),
        ("fprintf", 2),
        ("sprintf", 2),
        ("snprintf", 3),
    ] {
        let r = d.detect_by_name(0x2000, name);
        assert!(r.is_variadic, "{name} is variadic");
        assert_eq!(
            r.fixed_arg_count, fixed,
            "{name} has {fixed} fixed arguments"
        );
    }
}

/// Format-string knowledge must be preserved for the `v*` functions — they DO
/// have a format string, which other crates rely on; only the variadic claim
/// was wrong.
#[test]
fn format_string_knowledge_is_kept_for_va_list_functions() {
    for name in ["vprintf", "vfprintf", "vsnprintf"] {
        assert!(
            is_printf_family(name),
            "{name} still belongs to the printf family for format-string purposes"
        );
    }
}

// ── ReturnTypeAnalyzer: hidden struct pointer ──────────────────────────────

use rustre_analysis_callconv::return_type_analyzer::{
    ReturnInstr, ReturnInstrKind, ReturnType, ReturnTypeAnalyzer,
};

fn ins(kind: ReturnInstrKind) -> ReturnInstr {
    ReturnInstr { address: 0, kind }
}

/// A hidden struct-return pointer is a register the function READS on entry —
/// it is an incoming argument. WRITING rdi/rcx is ordinary argument setup
/// before a call, and says nothing about the return type. Treating any write
/// as the hidden pointer short-circuited the whole inference ahead of every
/// RAX-based signal, so `mov edi, …; mov eax, 42; ret` was reported as
/// returning a struct by pointer.
#[test]
fn writing_an_argument_register_is_not_a_hidden_struct_pointer() {
    let a = ReturnTypeAnalyzer::new(64);
    let r = a.analyze(&[
        ins(ReturnInstrKind::RegWrite {
            reg: "rdi".into(),
            width_bits: 64,
        }),
        ins(ReturnInstrKind::MovImm {
            reg: "eax".into(),
            imm: 42,
        }),
        ins(ReturnInstrKind::Ret { imm: 0 }),
    ]);

    assert_ne!(
        r.primary,
        ReturnType::StructByPointer,
        "setting up an argument then returning 42 is an int return, got {r:?}"
    );
}

/// The same for rcx on the Microsoft x64 side.
#[test]
fn writing_rcx_is_not_a_hidden_struct_pointer() {
    let a = ReturnTypeAnalyzer::new(64);
    let r = a.analyze(&[
        ins(ReturnInstrKind::RegWrite {
            reg: "rcx".into(),
            width_bits: 64,
        }),
        ins(ReturnInstrKind::MovImm {
            reg: "eax".into(),
            imm: 7,
        }),
        ins(ReturnInstrKind::Ret { imm: 0 }),
    ]);
    assert_ne!(r.primary, ReturnType::StructByPointer);
}

/// The capability must remain reachable: a register READ before any write is
/// a live-in, and that IS the hidden-pointer signal.
#[test]
fn a_live_in_pointer_register_still_signals_struct_return() {
    let a = ReturnTypeAnalyzer::new(64);
    let r = a.analyze(&[
        ins(ReturnInstrKind::RegRead { reg: "rdi".into() }),
        ins(ReturnInstrKind::RegWrite {
            reg: "rax".into(),
            width_bits: 64,
        }),
        ins(ReturnInstrKind::Ret { imm: 0 }),
    ]);
    assert_eq!(
        r.primary,
        ReturnType::StructByPointer,
        "rdi read before being written is an incoming hidden pointer"
    );
}

/// A register written first and read later is NOT a live-in.
#[test]
fn a_register_written_before_being_read_is_not_live_in() {
    let a = ReturnTypeAnalyzer::new(64);
    let r = a.analyze(&[
        ins(ReturnInstrKind::RegWrite {
            reg: "rdi".into(),
            width_bits: 64,
        }),
        ins(ReturnInstrKind::RegRead { reg: "rdi".into() }),
        ins(ReturnInstrKind::MovImm {
            reg: "eax".into(),
            imm: 1,
        }),
        ins(ReturnInstrKind::Ret { imm: 0 }),
    ]);
    assert_ne!(r.primary, ReturnType::StructByPointer);
}
