//! End-to-end proof that `AppleDebugger` drives a `debugserver` correctly —
//! run from a Windows host, with no Mac involved.
//!
//! What makes this a real test rather than a mock handshake: the object under
//! test is the **production** `AppleDebugger`, reached through the **production**
//! `rustre_debug::Debugger` trait, speaking the **real** Remote Serial Protocol
//! (checksums verified, packets reassembled from 5-byte fragments) to a
//! debugserver simulator that executes actual A64 instruction encodings. The
//! only thing that is not real is the socket.
//!
//! The cycle exercised is the one an actual debugging session performs:
//! attach → read registers → set a breakpoint → continue → hit it →
//! read memory → backtrace → detach.

use std::sync::Arc;

use rustre_core::address::Address;
use rustre_debug::symbol_resolver::{FrameSymbolResolver, ResolvedFrameSymbol};
use rustre_debug::{
    BreakpointKind, DebugError, Debugger, LaunchOptions, ProcessId, StopReason, ThreadId,
};
use rustre_debug::ios::apple_debugger::LoopbackFactory;
use rustre_debug::ios::mock_debugserver::MockDebugserver;
use rustre_debug::ios::{AppleDebugger, TargetArch};

const PID: u32 = 0x1234;
const TEXT_BASE: u64 = 0x1_0000_8000;

/// Offsets into [`program`], named so an assertion says what it means.
const CALLER_ENTRY: u64 = 0x00;
const CALL_SITE: u64 = 0x08;
const RETURN_SITE: u64 = 0x0C;
const CALLEE_ENTRY: u64 = 0x18;
const CALLEE_BODY: u64 = 0x20;

/// A caller that establishes an AAPCS64 frame, calls a callee that establishes
/// its own, and returns. Both prologues matter: the backtrace assertion below
/// is only meaningful if the callee's frame record actually exists on the
/// stack.
///
/// ```text
/// +0x00  stp  x29, x30, [sp, #-16]!
/// +0x04  mov  x29, sp
/// +0x08  bl   +0x10            -> +0x18
/// +0x0c  ldp  x29, x30, [sp], #16
/// +0x10  ret
/// +0x14  brk  #0
/// +0x18  stp  x29, x30, [sp, #-16]!
/// +0x1c  mov  x29, sp
/// +0x20  movz x0, #0x2a
/// +0x24  ldp  x29, x30, [sp], #16
/// +0x28  ret
/// ```
fn program() -> Vec<u32> {
    vec![
        0xA9BF_7BFD,
        0x9100_03FD,
        0x9400_0004,
        0xA8C1_7BFD,
        0xD65F_03C0,
        0xD420_0000,
        0xA9BF_7BFD,
        0x9100_03FD,
        0xD280_0540,
        0xA8C1_7BFD,
        0xD65F_03C0,
    ]
}

fn debugger() -> AppleDebugger {
    let server = MockDebugserver::with_program(PID, TEXT_BASE, &program());
    // 5 bytes per read: the client must reassemble every reply from fragments,
    // which is precisely what the workspace's other RSP client gets wrong.
    AppleDebugger::new(Arc::new(LoopbackFactory::new(server, 5)))
}

/// A trivial resolver, to prove `set_symbol_resolver` is actually consulted
/// (the trait's default is a silent no-op, so an unforwarded resolver would
/// otherwise look like "no symbols available").
struct FixedResolver;

impl FrameSymbolResolver for FixedResolver {
    fn resolve_frame(&self, pc: u64) -> Option<ResolvedFrameSymbol> {
        let name = match pc - TEXT_BASE {
            CALLEE_BODY => "callee",
            RETURN_SITE => "caller",
            _ => return None,
        };
        Some(ResolvedFrameSymbol {
            function: Some(name.to_string()),
            file: Some("fixture.c".to_string()),
            line: Some(42),
            // Field added to `ResolvedFrameSymbol` by a concurrent edit; this
            // canned resolver states a definite symbol, so `true` is truthful.
            bounded: true,
            // The fixture knows where each canned symbol begins, so a frame can
            // be checked as `callee+N` and not merely as `callee`.
            start: Some(TEXT_BASE + if name == "callee" { CALLEE_BODY } else { RETURN_SITE }),
        })
    }
}

#[tokio::test]
async fn full_debug_cycle_over_rsp() {
    let dbg = debugger();
    dbg.set_symbol_resolver(Arc::new(FixedResolver))
        .expect("the Apple backend holds a resolver, so installing one must succeed");

    // -- 1. attach ---------------------------------------------------------
    assert!(!dbg.is_attached());
    dbg.attach(ProcessId(PID)).await.expect("attach");
    assert!(dbg.is_attached());
    assert_eq!(dbg.target_pid(), Some(ProcessId(PID)));
    // The architecture was discovered from qProcessInfo, not assumed.
    assert_eq!(dbg.target_arch(), Some(TargetArch::Arm64e));
    assert_eq!(dbg.name(), "apple");

    let threads = dbg.threads().await.expect("threads");
    assert_eq!(threads, vec![ThreadId(1)], "the fixture has one thread");
    let tid = dbg.current_thread().await.expect("current thread");
    assert_eq!(tid, ThreadId(1));

    // -- 2. read registers -------------------------------------------------
    let regs = dbg.get_registers(tid).await.expect("get_registers");
    assert_eq!(regs.pc, TEXT_BASE + CALLER_ENTRY, "parked at the entry point");
    assert!(regs.sp != 0, "stack pointer must be live");
    assert_eq!(regs.get_pc(), Address::new(TEXT_BASE + CALLER_ENTRY));
    // Names come from the stub's own qRegisterInfo table.
    assert!(regs.get("x0").is_some() && regs.get("x28").is_some());
    let start_sp = regs.sp;

    // A single named register goes through `p`, a different path from `g`.
    assert_eq!(dbg.get_register(tid, "pc").await.unwrap(), regs.pc);

    // -- 3. set a breakpoint ----------------------------------------------
    let bp_addr = Address::new(TEXT_BASE + CALLEE_BODY);
    dbg.set_breakpoint(bp_addr, BreakpointKind::Software)
        .await
        .expect("set_breakpoint");
    let listed = dbg.breakpoints().await.expect("breakpoints");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].address, bp_addr);
    assert_eq!(listed[0].kind, BreakpointKind::Software);
    assert!(listed[0].enabled);
    assert_eq!(listed[0].hit_count, 0);

    // -- 4. continue, and hit it ------------------------------------------
    let event = dbg.continue_execution().await.expect("continue");
    assert_eq!(event.pid, ProcessId(PID));
    match &event.reason {
        StopReason::Breakpoint { address, bp } => {
            assert_eq!(*address, bp_addr, "stopped at the requested address");
            assert_eq!(bp.hit_count, 1, "the hit was counted");
        }
        other => panic!("expected a breakpoint stop, got {other}"),
    }
    // The target really executed: PC moved from the entry point into the
    // callee, through a `bl`.
    let stopped = dbg.get_registers(tid).await.expect("registers at stop");
    assert_eq!(stopped.pc, TEXT_BASE + CALLEE_BODY);
    assert_eq!(
        stopped.lr,
        Some(TEXT_BASE + RETURN_SITE),
        "the `bl` left the return address in x30"
    );
    assert!(
        stopped.sp < start_sp,
        "two prologues must have pushed frames (sp {:#x} -> {:#x})",
        start_sp,
        stopped.sp
    );

    // -- 5. read memory ----------------------------------------------------
    // Code: the instruction the breakpoint sits on is still the original one
    // (the stub owns the trap, so nothing was patched into the image).
    let insn = dbg.read_memory(bp_addr, 4).await.expect("read code");
    assert_eq!(
        u32::from_le_bytes(insn.try_into().unwrap()),
        program()[(CALLEE_BODY / 4) as usize],
        "movz x0, #0x2a"
    );
    // Stack: the callee's frame record — saved x29 then saved x30.
    let frame_record = dbg
        .read_memory(Address::new(stopped.fp.expect("fp")), 16)
        .await
        .expect("read frame record");
    let saved_fp = u64::from_le_bytes(frame_record[..8].try_into().unwrap());
    let saved_lr = u64::from_le_bytes(frame_record[8..].try_into().unwrap());
    assert_eq!(saved_lr, TEXT_BASE + RETURN_SITE, "callee saved the caller's x30");
    assert_ne!(saved_fp, 0, "callee saved the caller's x29");

    // Writes land, and unmapped addresses fail loudly instead of returning zeroes.
    let scratch = Address::new(stopped.sp - 128);
    assert_eq!(dbg.write_memory(scratch, b"\xde\xad\xbe\xef").await.unwrap(), 4);
    assert_eq!(dbg.read_memory(scratch, 4).await.unwrap(), b"\xde\xad\xbe\xef");
    assert!(matches!(
        dbg.read_memory(Address::new(0xFFFF_0000_0000), 8).await,
        Err(DebugError::MemoryError(..))
    ));

    // -- 6. backtrace ------------------------------------------------------
    let frames = dbg.backtrace(tid).await.expect("backtrace");
    assert!(
        frames.len() >= 2,
        "the callee and its caller must both be recovered, got {frames:#?}"
    );
    assert_eq!(frames[0].index, 0);
    assert_eq!(frames[0].pc, bp_addr);
    assert_eq!(
        frames[1].pc,
        Address::new(TEXT_BASE + RETURN_SITE),
        "frame 1 is the instruction after the `bl`"
    );
    // Frames are ordered innermost-first and the stack grows the right way.
    assert!(frames[1].sp.as_u64() > frames[0].sp.as_u64());
    // The resolver was forwarded rather than dropped on the floor.
    assert_eq!(frames[0].function_name.as_deref(), Some("callee"));
    assert_eq!(frames[1].function_name.as_deref(), Some("caller"));
    assert_eq!(frames[0].source_line, Some(42));

    // -- 7. modules and maps still answer from the live target -------------
    let modules = dbg.modules().await.expect("modules");
    assert_eq!(modules.len(), 1);
    assert_eq!(modules[0].base, Address::new(TEXT_BASE));
    assert_eq!(modules[0].size, program().len() as u64 * 4);

    let maps = dbg.memory_maps().await.expect("memory_maps");
    let text = maps
        .iter()
        .find(|m| m.base == Address::new(TEXT_BASE))
        .expect("__TEXT must appear in the map");
    assert!(text.executable && !text.writable);
    assert!(
        maps.iter().any(|m| m.writable && !m.executable),
        "the stack must appear as a writable non-executable region"
    );

    // -- 8. detach ---------------------------------------------------------
    dbg.detach().await.expect("detach");
    assert!(!dbg.is_attached());
    assert!(dbg.target_pid().is_none());
    assert!(
        dbg.breakpoints().await.unwrap().is_empty(),
        "breakpoints belong to the departed process"
    );
    // Post-detach calls fail with NotAttached, not with a stale success.
    assert!(matches!(
        dbg.get_registers(tid).await,
        Err(DebugError::NotAttached)
    ));
    assert!(matches!(dbg.continue_execution().await, Err(DebugError::NotAttached)));
}

/// Stepping is driven the same way a UI would: one instruction at a time
/// through the call, then out of it. This covers `single_step`, `step_over`
/// (which must plant a temporary breakpoint at the return site) and
/// `step_out` (which routes through the hub crate's shared loop decision).
#[tokio::test]
async fn stepping_traverses_the_call_the_same_way_a_ui_would() {
    let dbg = debugger();
    dbg.attach(ProcessId(PID)).await.expect("attach");
    let tid = dbg.current_thread().await.unwrap();

    // Two single steps take us through the prologue to the `bl`.
    for expected in [0x04u64, CALL_SITE] {
        let ev = dbg.single_step(tid).await.expect("single_step");
        assert!(matches!(ev.reason, StopReason::SingleStep { .. }), "{}", ev.reason);
        assert_eq!(dbg.get_registers(tid).await.unwrap().pc, TEXT_BASE + expected);
    }

    // Step INTO the call, to have a frame to step out of.
    dbg.single_step(tid).await.expect("step into");
    assert_eq!(
        dbg.get_registers(tid).await.unwrap().pc,
        TEXT_BASE + CALLEE_ENTRY
    );

    // Step out: run until the callee returns to the instruction after the `bl`.
    dbg.step_out(tid).await.expect("step_out");
    assert_eq!(
        dbg.get_registers(tid).await.unwrap().pc,
        TEXT_BASE + RETURN_SITE,
        "step_out must land on the return site"
    );

    // Now re-run the call from the call site with step_over, which must skip
    // the whole callee in one operation and leave no breakpoint behind.
    dbg.set_register(tid, "pc", TEXT_BASE + CALL_SITE).await.unwrap();
    dbg.step_over(tid).await.expect("step_over");
    assert_eq!(
        dbg.get_registers(tid).await.unwrap().pc,
        TEXT_BASE + RETURN_SITE
    );
    assert!(
        dbg.breakpoints().await.unwrap().is_empty(),
        "the temporary return-site breakpoint must be removed"
    );

    dbg.detach().await.unwrap();
}

/// A launch drives the same stack through the `A` packet path instead of
/// `vAttach`, and the options this backend cannot honour are refused rather
/// than silently ignored.
#[tokio::test]
async fn launch_path_and_its_documented_limits() {
    let dbg = debugger();
    let opts = LaunchOptions::new("/usr/bin/fixture").with_args(vec!["--flag".to_string()]);
    let pid = dbg.launch(opts).await.expect("launch");
    assert_eq!(pid, ProcessId(PID));
    assert!(dbg.is_attached());

    // The launched target is immediately drivable.
    let tid = dbg.current_thread().await.unwrap();
    assert_eq!(
        dbg.get_registers(tid).await.unwrap().pc,
        TEXT_BASE + CALLER_ENTRY
    );

    // pause() is a documented gap, and says so instead of pretending.
    assert!(matches!(dbg.pause().await, Err(DebugError::Unsupported(_))));
    dbg.detach().await.unwrap();

    // A second launch with unsupported options is rejected before any
    // connection is made.
    let dbg2 = debugger();
    let mut bad = LaunchOptions::new("/usr/bin/fixture");
    bad.redirect.stdout = true;
    assert!(matches!(dbg2.launch(bad).await, Err(DebugError::Unsupported(_))));
    assert!(!dbg2.is_attached());
}

/// The runtime-inspection and symbol paths wired in iters 257-262, driven
/// end-to-end through the PRODUCTION `AppleDebugger` for the first time.
///
/// Each of those iterations added unit tests, but nothing ever exercised them
/// together through the real backend: the existing cycle test installs a
/// hand-written `FixedResolver` and never touches `Symbolicator`,
/// `load_symbols_from_target`, the unwind-image loader, or the ObjC/Swift
/// describe paths. That is precisely the gap that hides integration mistakes
/// — iter 259 lost a build cycle to an `add_image`/`with_image` API confusion
/// that no unit test could have caught.
#[tokio::test]
async fn runtime_inspection_paths_work_through_the_production_backend() {
    let dbg = debugger();
    dbg.attach(ProcessId(PID)).await.expect("attach");

    // -- Objective-C describe, with no target memory involved --------------
    //
    // A tagged pointer carries its value in the pointer itself, so this
    // exercises the whole chain — production backend -> ReaderMemory adapter
    // -> ObjcRuntime -> tagged decoder — without depending on what the
    // simulator happens to have mapped.
    //
    // arm64 layout: bit 63 marks a tagged pointer, bits 60..62 select the
    // class (3 = NSNumber), and the payload's low nibble is the number's type
    // (3 = 32-bit int) with the value above it. 42 << 4 | 3 = 0x2A3.
    const TAGGED_NSNUMBER_42: u64 = (1 << 63) | (3 << 60) | 0x2A3;
    let described = dbg
        .describe_objc_object(TAGGED_NSNUMBER_42)
        .await
        .expect("describing a tagged pointer must not need target memory");
    assert!(
        described.contains("42"),
        "the tagged NSNumber's value never reached the description: {described}"
    );
    assert!(
        described.contains("Number"),
        "the description should name the class it decoded: {described}"
    );

    // A pointer that is NOT tagged must be attempted against real memory and
    // fail honestly rather than being decoded as though it were tagged.
    let err = dbg.describe_objc_object(0x1).await;
    assert!(
        err.is_err(),
        "an unreadable plain pointer must be an error, not an invented object: {err:?}"
    );

    // -- symbol loading from the target's own images -----------------------
    //
    // Zero usable images is a legitimate answer against a simulator that
    // serves no Mach-O; what matters is that the path runs and reports a
    // count instead of erroring or panicking.
    let count = dbg
        .load_symbols_from_target()
        .await
        .expect("loading symbols from the target must not fail outright");
    assert!(count <= 64, "implausible image count {count}");

    // -- backtrace with the unwind-image loader active ---------------------
    //
    // Since iter 259 `backtrace` builds the unwinder WITH the target's
    // images. That code path never ran end-to-end before this test.
    let tid = dbg.current_thread().await.expect("current_thread");
    let frames = dbg.backtrace(tid).await.expect("backtrace");
    assert!(!frames.is_empty(), "a live thread must produce at least one frame");
    assert_eq!(frames[0].index, 0, "frames must be ordered from the innermost");

    dbg.detach().await.expect("detach");
}
