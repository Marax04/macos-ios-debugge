//! Blitz integration tests for the public API of `rustre-emu-shellcode`.

use std::collections::HashMap;

use rustre_emu::{EmulatorArch, EmulatorError, x86_regs};
use rustre_emu_shellcode::{
    ApiCall, ApiCallInterceptor, ApiStub, ExecutionLog, ExecutionResult, ExitReason, HEAP_BASE,
    HEAP_SIZE, MemAccess, MemWrite, ScExitReason, SHELLCODE_BASE, STACK_BASE, STACK_SIZE,
    ShellcodeAnalysis, ShellcodeHook, ShellcodeRunResult, ShellcodeRunner,
};

// ── Constants ───────────────────────────────────────────────────────────────

#[test]
fn const_shellcode_base() {
    assert_eq!(SHELLCODE_BASE, 0x0000_1000);
}

#[test]
fn const_stack_layout() {
    assert_eq!(STACK_BASE, 0x0010_0000);
    assert_eq!(STACK_SIZE, 0x0010_0000);
}

#[test]
fn const_heap_layout() {
    assert_eq!(HEAP_BASE, 0x0020_0000);
    assert_eq!(HEAP_SIZE, 0x0040_0000);
}

// ── ShellcodeRunner basic ───────────────────────────────────────────────────

fn runner() -> ShellcodeRunner {
    ShellcodeRunner::new(EmulatorArch::X86_64)
        .with_max_instructions(50_000)
        .with_timeout_ms(2_000)
}

#[test]
fn runner_new_defaults() {
    let r = ShellcodeRunner::new(EmulatorArch::X86_64);
    assert_eq!(r.memory_size, 0x1000);
    assert_eq!(r.max_instructions, 100_000);
    assert_eq!(r.timeout_ms, 5_000);
    assert_eq!(r.arch, EmulatorArch::X86_64);
}

#[test]
fn runner_builder_chain() {
    let r = ShellcodeRunner::new(EmulatorArch::X86_32)
        .with_max_instructions(7)
        .with_timeout_ms(11)
        .with_memory_size(0x4000);
    assert_eq!(r.max_instructions, 7);
    assert_eq!(r.timeout_ms, 11);
    assert_eq!(r.memory_size, 0x4000);
    assert_eq!(r.arch, EmulatorArch::X86_32);
}

#[test]
fn runner_clone_is_independent() {
    let a = runner();
    let b = a.clone().with_max_instructions(1);
    assert_ne!(a.max_instructions, b.max_instructions);
}

#[test]
fn runner_empty_shellcode_returns_invalid_arg() {
    let r = runner();
    match r.run(&[]) {
        Err(EmulatorError::InvalidArg(msg)) => assert!(msg.contains("empty")),
        other => panic!("expected InvalidArg, got {other:?}"),
    }
}

#[test]
fn runner_single_hlt_terminates() {
    let r = runner();
    let res = r.run(&[0xF4]).unwrap();
    assert!(matches!(
        res.exit_reason,
        ExitReason::RetInstruction | ExitReason::MaxInstructions
    ));
    assert_ne!(res.exit_reason, ExitReason::Timeout);
}

#[test]
fn runner_mov_eax_imm_sets_rax() {
    let r = runner();
    let code = [0xB8u8, 0xEF, 0xBE, 0xAD, 0xDE, 0xF4]; // MOV EAX, 0xDEADBEEF; HLT
    let res = r.run(&code).unwrap();
    let rax = res.final_regs.get(&x86_regs::RAX).copied().unwrap_or(0);
    assert_eq!(rax, 0xDEAD_BEEF);
}

#[test]
fn runner_nop_sled_counts_instructions() {
    let r = runner();
    let mut code = vec![0x90u8; 16];
    code.push(0xF4);
    let res = r.run(&code).unwrap();
    assert!(res.log.instructions_executed >= 16);
}

#[test]
fn runner_tight_loop_hits_max_instructions() {
    let r = ShellcodeRunner::new(EmulatorArch::X86_64)
        .with_max_instructions(10)
        .with_timeout_ms(2_000);
    let res = r.run(&[0xEBu8, 0xFE]).unwrap(); // JMP -2
    assert_eq!(res.exit_reason, ExitReason::MaxInstructions);
}

#[test]
fn runner_push_records_memory_write() {
    let r = runner();
    let res = r.run(&[0x6Au8, 0x41, 0xF4]).unwrap(); // PUSH 0x41; HLT
    assert!(!res.log.memory_writes.is_empty());
}

#[test]
fn runner_snapshot_contains_shellcode_region() {
    let r = runner();
    let res = r.run(&[0xF4]).unwrap();
    assert!(
        res.memory_snapshot
            .iter()
            .any(|(b, _)| *b == SHELLCODE_BASE)
    );
}

#[test]
fn runner_x86_32_uses_esp() {
    let r = ShellcodeRunner::new(EmulatorArch::X86_32).with_max_instructions(100);
    let res = r.run(&[0xF4]).unwrap();
    assert!(res.final_regs.contains_key(&x86_regs::ESP));
}

// ── ShellcodeAnalysis ───────────────────────────────────────────────────────

fn empty_result() -> ExecutionResult {
    ExecutionResult {
        log: ExecutionLog::default(),
        final_regs: HashMap::new(),
        memory_snapshot: vec![],
        exit_reason: ExitReason::RetInstruction,
    }
}

#[test]
fn analysis_decode_loop_negative_empty() {
    assert!(!ShellcodeAnalysis::detect_decode_loop(&empty_result()));
}

#[test]
fn analysis_decode_loop_positive_linear_writes() {
    let mut log = ExecutionLog::default();
    for i in 0u64..20 {
        log.memory_writes.push(MemAccess {
            address: 0x3000 + i,
            size: 1,
            value: vec![0],
            pc: 0,
        });
    }
    let r = ExecutionResult {
        log,
        ..empty_result()
    };
    assert!(ShellcodeAnalysis::detect_decode_loop(&r));
}

#[test]
fn analysis_decode_loop_below_threshold() {
    // 7 writes — under the 8-threshold floor.
    let mut log = ExecutionLog::default();
    for i in 0u64..7 {
        log.memory_writes.push(MemAccess {
            address: 0x3000 + i,
            size: 1,
            value: vec![0],
            pc: 0,
        });
    }
    let r = ExecutionResult {
        log,
        ..empty_result()
    };
    assert!(!ShellcodeAnalysis::detect_decode_loop(&r));
}

#[test]
fn analysis_api_hashing_negative_empty() {
    assert!(!ShellcodeAnalysis::detect_api_hashing(&empty_result()));
}

#[test]
fn analysis_api_hashing_positive_clustered_reads() {
    let mut log = ExecutionLog::default();
    for i in 0..12u64 {
        log.memory_reads.push(MemAccess {
            address: 0x5000 + i * 4,
            size: 4,
            value: vec![0; 4],
            pc: 0,
        });
    }
    let r = ExecutionResult {
        log,
        ..empty_result()
    };
    assert!(ShellcodeAnalysis::detect_api_hashing(&r));
}

#[test]
fn analysis_api_hashing_few_reads_negative() {
    let mut log = ExecutionLog::default();
    for i in 0..5u64 {
        log.memory_reads.push(MemAccess {
            address: 0x5000 + i,
            size: 1,
            value: vec![0],
            pc: 0,
        });
    }
    let r = ExecutionResult {
        log,
        ..empty_result()
    };
    assert!(!ShellcodeAnalysis::detect_api_hashing(&r));
}

#[test]
fn analysis_network_stub_by_name() {
    let mut log = ExecutionLog::default();
    log.calls.push(ApiCall {
        address: 0x1234,
        name: Some("WSASocket".into()),
        args: vec![],
        ret: 0,
    });
    let r = ExecutionResult {
        log,
        ..empty_result()
    };
    assert!(ShellcodeAnalysis::detect_network_stub(&r));
}

#[test]
fn analysis_network_stub_by_syscall_number() {
    let mut log = ExecutionLog::default();
    log.calls.push(ApiCall {
        address: 41, // socket on Linux x86_64
        name: None,
        args: vec![],
        ret: 0,
    });
    let r = ExecutionResult {
        log,
        ..empty_result()
    };
    assert!(ShellcodeAnalysis::detect_network_stub(&r));
}

#[test]
fn analysis_network_stub_case_insensitive() {
    let mut log = ExecutionLog::default();
    log.calls.push(ApiCall {
        address: 0,
        name: Some("CONNECT".into()),
        args: vec![],
        ret: 0,
    });
    let r = ExecutionResult {
        log,
        ..empty_result()
    };
    assert!(ShellcodeAnalysis::detect_network_stub(&r));
}

#[test]
fn analysis_network_stub_negative() {
    assert!(!ShellcodeAnalysis::detect_network_stub(&empty_result()));
}

#[test]
fn analysis_extract_strings_finds_ascii() {
    let snap = vec![(
        0x1000u64,
        b"\x00\x00Hello World\x00garbage\x01\x02BYE\x00ThisIsLong".to_vec(),
    )];
    let r = ExecutionResult {
        memory_snapshot: snap,
        ..empty_result()
    };
    let strings = ShellcodeAnalysis::extract_strings(&r);
    assert!(strings.iter().any(|s| s == "Hello World"));
    assert!(strings.iter().any(|s| s == "ThisIsLong"));
    // "BYE" is only 3 chars — should be excluded.
    assert!(!strings.iter().any(|s| s == "BYE"));
}

#[test]
fn analysis_extract_strings_dedup_sorted() {
    let snap = vec![
        (0u64, b"AAAA\x00BBBB".to_vec()),
        (0x1000, b"BBBB\x00AAAA".to_vec()),
    ];
    let r = ExecutionResult {
        memory_snapshot: snap,
        ..empty_result()
    };
    let s = ShellcodeAnalysis::extract_strings(&r);
    assert_eq!(s, vec!["AAAA".to_string(), "BBBB".to_string()]);
}

#[test]
fn analysis_extract_strings_empty() {
    assert!(ShellcodeAnalysis::extract_strings(&empty_result()).is_empty());
}

// ── ExitReason / ScExitReason derives ───────────────────────────────────────

#[test]
fn exit_reason_eq_and_clone() {
    let a = ExitReason::Timeout;
    let b = a.clone();
    assert_eq!(a, b);
    assert_ne!(ExitReason::Timeout, ExitReason::MaxInstructions);
}

#[test]
fn sc_exit_reason_apicall_variant_eq() {
    let a = ScExitReason::ApiCall("foo".into());
    let b = ScExitReason::ApiCall("foo".into());
    let c = ScExitReason::ApiCall("bar".into());
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn exit_reason_debug_nonempty() {
    let s = format!("{:?}", ExitReason::RetInstruction);
    assert!(s.contains("RetInstruction"));
}

// ── ShellcodeHook ───────────────────────────────────────────────────────────

#[test]
fn hook_new_fields() {
    let h = ShellcodeHook::new(0xDEAD, "VirtualAlloc", 0x4242);
    assert_eq!(h.address, 0xDEAD);
    assert_eq!(h.name, "VirtualAlloc");
    assert_eq!(h.return_value, 0x4242);
}

#[test]
fn hook_clone() {
    let h = ShellcodeHook::new(1, "x", 2);
    let h2 = h.clone();
    assert_eq!(h.address, h2.address);
    assert_eq!(h.name, h2.name);
}

// ── run_sc / run_with_hooks / convert_result ────────────────────────────────

#[test]
fn run_sc_x86_64_basic() {
    let res = ShellcodeRunner::run_sc(&[0x90u8, 0xF4], "x86_64").unwrap();
    assert!(res.instructions_executed >= 1);
}

#[test]
fn run_sc_empty_errors() {
    let r = ShellcodeRunner::run_sc(&[], "x86_64");
    assert!(r.is_err());
}

#[test]
fn run_with_hooks_empty_hooks_returns_no_calls() {
    let r = ShellcodeRunner::run_with_hooks(&[0xF4u8], "x86_64", &[]).unwrap();
    assert!(r.api_calls.is_empty());
}

#[test]
fn run_with_hooks_empty_shellcode_errors() {
    let r = ShellcodeRunner::run_with_hooks(&[], "x86_64", &[]);
    assert!(matches!(r, Err(EmulatorError::InvalidArg(_))));
}

#[test]
fn run_with_hooks_unreachable_hook_is_not_recorded() {
    let hooks = vec![ShellcodeHook::new(0xDEAD_BEEF, "VirtualAlloc", HEAP_BASE)];
    let r = ShellcodeRunner::run_with_hooks(&[0x90u8, 0xF4], "x86_64", &hooks).unwrap();
    assert!(
        !r.api_calls
            .iter()
            .any(|c| c.name.as_deref() == Some("VirtualAlloc"))
    );
}

#[test]
fn convert_result_maps_register_ids_to_names() {
    let mut regs = HashMap::new();
    regs.insert(x86_regs::RAX, 0x1111);
    regs.insert(x86_regs::RIP, 0x2222);
    let exec = ExecutionResult {
        log: ExecutionLog::default(),
        final_regs: regs,
        memory_snapshot: vec![],
        exit_reason: ExitReason::RetInstruction,
    };
    let r = ShellcodeRunner::convert_result(exec, &[]);
    assert_eq!(r.final_registers.get("rax").copied(), Some(0x1111));
    assert_eq!(r.final_registers.get("rip").copied(), Some(0x2222));
    assert_eq!(r.exit_reason, ScExitReason::Normal);
}

#[test]
fn convert_result_exit_reason_mapping() {
    for (er, sr) in [
        (ExitReason::MaxInstructions, ScExitReason::MaxInstructions),
        (ExitReason::InvalidInstruction, ScExitReason::InvalidInstruction),
        (ExitReason::InvalidMemoryAccess, ScExitReason::AccessViolation),
        (ExitReason::RetInstruction, ScExitReason::Normal),
        (ExitReason::Timeout, ScExitReason::Timeout),
    ] {
        let exec = ExecutionResult {
            log: ExecutionLog::default(),
            final_regs: HashMap::new(),
            memory_snapshot: vec![],
            exit_reason: er,
        };
        let r = ShellcodeRunner::convert_result(exec, &[]);
        assert_eq!(r.exit_reason, sr);
    }
}

#[test]
fn convert_result_injects_unmatched_hooks() {
    let exec = ExecutionResult {
        log: ExecutionLog::default(),
        final_regs: HashMap::new(),
        memory_snapshot: vec![],
        exit_reason: ExitReason::RetInstruction,
    };
    let hooks = vec![ShellcodeHook::new(0xABCD, "WinExec", 32)];
    let r = ShellcodeRunner::convert_result(exec, &hooks);
    assert_eq!(r.api_calls.len(), 1);
    assert_eq!(r.api_calls[0].name.as_deref(), Some("WinExec"));
    assert_eq!(r.api_calls[0].ret, 32);
    assert_eq!(r.api_calls[0].address, 0xABCD);
}

#[test]
fn convert_result_does_not_duplicate_named_hooks() {
    let mut log = ExecutionLog::default();
    log.calls.push(ApiCall {
        address: 0xABCD,
        name: Some("WinExec".into()),
        args: vec![],
        ret: 99,
    });
    let exec = ExecutionResult {
        log,
        final_regs: HashMap::new(),
        memory_snapshot: vec![],
        exit_reason: ExitReason::RetInstruction,
    };
    let hooks = vec![ShellcodeHook::new(0xABCD, "WinExec", 32)];
    let r = ShellcodeRunner::convert_result(exec, &hooks);
    let count = r
        .api_calls
        .iter()
        .filter(|c| c.name.as_deref() == Some("WinExec"))
        .count();
    assert_eq!(count, 1);
}

// ── arch_from_str ───────────────────────────────────────────────────────────

#[test]
fn arch_from_str_variants() {
    assert_eq!(ShellcodeRunner::arch_from_str("x86"), EmulatorArch::X86_32);
    assert_eq!(ShellcodeRunner::arch_from_str("i386"), EmulatorArch::X86_32);
    assert_eq!(ShellcodeRunner::arch_from_str("i686"), EmulatorArch::X86_32);
    assert_eq!(ShellcodeRunner::arch_from_str("X86_32"), EmulatorArch::X86_32);
    assert_eq!(ShellcodeRunner::arch_from_str("X86_64"), EmulatorArch::X86_64);
    assert_eq!(ShellcodeRunner::arch_from_str("amd64"), EmulatorArch::X86_64);
    assert_eq!(ShellcodeRunner::arch_from_str("x64"), EmulatorArch::X86_64);
    assert_eq!(ShellcodeRunner::arch_from_str("8086"), EmulatorArch::X86_16);
    assert_eq!(ShellcodeRunner::arch_from_str("x86_16"), EmulatorArch::X86_16);
}

#[test]
fn arch_from_str_unknown_defaults_x86_64() {
    assert_eq!(ShellcodeRunner::arch_from_str(""), EmulatorArch::X86_64);
    assert_eq!(ShellcodeRunner::arch_from_str("mips"), EmulatorArch::X86_64);
    assert_eq!(ShellcodeRunner::arch_from_str("arm64"), EmulatorArch::X86_64);
}

// ── ApiCallInterceptor ──────────────────────────────────────────────────────

#[test]
fn interceptor_default_eq_new() {
    let a = ApiCallInterceptor::new();
    let b = ApiCallInterceptor::default();
    assert_eq!(a.stubs().len(), b.stubs().len());
}

#[test]
fn interceptor_has_expected_stubs() {
    let ic = ApiCallInterceptor::new();
    let names: Vec<&str> = ic.stubs().iter().map(|s| s.name).collect();
    for expected in [
        "VirtualAlloc",
        "VirtualProtect",
        "LoadLibraryA",
        "GetProcAddress",
        "CreateThread",
        "socket",
        "connect",
        "send",
        "recv",
        "WSAStartup",
        "InternetOpenA",
    ] {
        assert!(names.contains(&expected), "missing {expected}");
    }
}

#[test]
fn interceptor_stub_count_min() {
    assert!(ApiCallInterceptor::new().stubs().len() >= 20);
}

#[test]
fn interceptor_scan_finds_and_sorts() {
    let ic = ApiCallInterceptor::new();
    let buf = b"....LoadLibraryA....VirtualAlloc....socket....";
    let hits = ic.scan_for_api_names(buf);
    assert!(!hits.is_empty());
    for w in hits.windows(2) {
        assert!(w[0].0 <= w[1].0);
    }
    let names: Vec<&str> = hits.iter().map(|(_, n)| *n).collect();
    assert!(names.contains(&"LoadLibraryA"));
    assert!(names.contains(&"VirtualAlloc"));
    assert!(names.contains(&"socket"));
}

#[test]
fn interceptor_scan_empty_buffer_is_empty() {
    assert!(ApiCallInterceptor::new().scan_for_api_names(&[]).is_empty());
}

#[test]
fn interceptor_scan_no_match_is_empty() {
    let ic = ApiCallInterceptor::new();
    let hits = ic.scan_for_api_names(b"nothing interesting here at all");
    assert!(hits.is_empty());
}

#[test]
fn interceptor_annotate_fills_zero_ret() {
    let ic = ApiCallInterceptor::new();
    let mut calls = vec![ApiCall {
        address: 0,
        name: Some("VirtualAlloc".into()),
        args: vec![],
        ret: 0,
    }];
    ic.annotate(&mut calls);
    assert_eq!(calls[0].ret, HEAP_BASE);
}

#[test]
fn interceptor_annotate_preserves_nonzero_ret() {
    let ic = ApiCallInterceptor::new();
    let mut calls = vec![ApiCall {
        address: 0,
        name: Some("LoadLibraryA".into()),
        args: vec![],
        ret: 0x1234,
    }];
    ic.annotate(&mut calls);
    assert_eq!(calls[0].ret, 0x1234);
}

#[test]
fn interceptor_annotate_unknown_name_unchanged() {
    let ic = ApiCallInterceptor::new();
    let mut calls = vec![ApiCall {
        address: 0,
        name: Some("NoSuchApi".into()),
        args: vec![],
        ret: 0,
    }];
    ic.annotate(&mut calls);
    assert_eq!(calls[0].ret, 0);
}

#[test]
fn interceptor_annotate_case_insensitive() {
    let ic = ApiCallInterceptor::new();
    let mut calls = vec![ApiCall {
        address: 0,
        name: Some("virtualalloc".into()),
        args: vec![],
        ret: 0,
    }];
    ic.annotate(&mut calls);
    assert_eq!(calls[0].ret, HEAP_BASE);
}

#[test]
fn api_stub_fields_accessible() {
    let ic = ApiCallInterceptor::new();
    let vp = ic
        .stubs()
        .iter()
        .find(|s| s.name == "VirtualProtect")
        .unwrap();
    assert_eq!(vp.default_return, 1);
    assert!(!vp.description.is_empty());
    // Field access via direct struct construction.
    let _ = ApiStub {
        name: "test",
        default_return: 7,
        description: "d",
    };
}

// ── Serde round-trips ───────────────────────────────────────────────────────

#[test]
fn serde_apicall_round_trip() {
    let c = ApiCall {
        address: 0x1000,
        name: Some("foo".into()),
        args: vec![1, 2, 3],
        ret: 0x42,
    };
    let s = serde_json::to_string(&c).unwrap();
    let back: ApiCall = serde_json::from_str(&s).unwrap();
    assert_eq!(back.address, c.address);
    assert_eq!(back.name, c.name);
    assert_eq!(back.args, c.args);
    assert_eq!(back.ret, c.ret);
}

#[test]
fn serde_memaccess_round_trip() {
    let m = MemAccess {
        address: 0x2000,
        size: 4,
        value: vec![1, 2, 3, 4],
        pc: 0x1234,
    };
    let s = serde_json::to_string(&m).unwrap();
    let back: MemAccess = serde_json::from_str(&s).unwrap();
    assert_eq!(back.address, m.address);
    assert_eq!(back.size, m.size);
    assert_eq!(back.value, m.value);
    assert_eq!(back.pc, m.pc);
}

#[test]
fn serde_memwrite_round_trip() {
    let m = MemWrite {
        addr: 0x3000,
        size: 2,
        data: vec![0xAA, 0xBB],
    };
    let s = serde_json::to_string(&m).unwrap();
    let back: MemWrite = serde_json::from_str(&s).unwrap();
    assert_eq!(back.addr, m.addr);
    assert_eq!(back.size, m.size);
    assert_eq!(back.data, m.data);
}

#[test]
fn serde_exit_reason_round_trip() {
    for er in [
        ExitReason::RetInstruction,
        ExitReason::MaxInstructions,
        ExitReason::Timeout,
        ExitReason::InvalidMemoryAccess,
        ExitReason::InvalidInstruction,
    ] {
        let s = serde_json::to_string(&er).unwrap();
        let back: ExitReason = serde_json::from_str(&s).unwrap();
        assert_eq!(back, er);
    }
}

#[test]
fn serde_sc_exit_reason_round_trip() {
    let a = ScExitReason::ApiCall("openme".into());
    let s = serde_json::to_string(&a).unwrap();
    let back: ScExitReason = serde_json::from_str(&s).unwrap();
    assert_eq!(back, a);
}

#[test]
fn serde_execution_log_default() {
    let log = ExecutionLog::default();
    assert_eq!(log.instructions_executed, 0);
    assert!(log.calls.is_empty());
    let s = serde_json::to_string(&log).unwrap();
    let back: ExecutionLog = serde_json::from_str(&s).unwrap();
    assert_eq!(back.instructions_executed, 0);
}

#[test]
fn serde_shellcode_run_result_round_trip() {
    let r = ShellcodeRunResult {
        instructions_executed: 5,
        final_registers: {
            let mut m = HashMap::new();
            m.insert("rax".into(), 1);
            m
        },
        api_calls: vec![],
        memory_writes: vec![],
        exit_reason: ScExitReason::Normal,
    };
    let s = serde_json::to_string(&r).unwrap();
    let back: ShellcodeRunResult = serde_json::from_str(&s).unwrap();
    assert_eq!(back.instructions_executed, 5);
    assert_eq!(back.final_registers.get("rax").copied(), Some(1));
    assert_eq!(back.exit_reason, ScExitReason::Normal);
}

// ── Send + Sync bounds ──────────────────────────────────────────────────────

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn types_are_send_sync() {
    assert_send_sync::<ShellcodeRunner>();
    assert_send_sync::<ExecutionLog>();
    assert_send_sync::<ExecutionResult>();
    assert_send_sync::<ShellcodeRunResult>();
    assert_send_sync::<ApiCall>();
    assert_send_sync::<MemAccess>();
    assert_send_sync::<MemWrite>();
    assert_send_sync::<ShellcodeHook>();
    assert_send_sync::<ExitReason>();
    assert_send_sync::<ScExitReason>();
    assert_send_sync::<ApiStub>();
    assert_send_sync::<ApiCallInterceptor>();
}
