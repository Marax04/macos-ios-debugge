//! Blitz integration tests for rustre-debug.
//!
//! Targets public APIs across multiple modules from the outside.
//! Goal: surface bugs, exercise edges, integrate the dead-code surface.

use rustre_core::address::Address;
use rustre_debug::*;

use rustre_debug::conditional_breakpoint::{
    BreakpointCondition, ConditionError, ConditionOperand, ConditionOperator,
    ConditionalBreakpoint, ConditionalBreakpointSet, MapEvalContext, evaluate_condition,
};
use rustre_debug::memory_search::{
    MemoryRegion, MemorySearch, SearchError, SearchOptions, SearchPattern, search_all_regions,
};
use rustre_debug::source_map::{
    SourceLocation, SourceMap, SourceMapError, SourceRootMapper, StdOpcode, ExtOpcode,
};
use rustre_debug::watchpoint_manager::{
    AccessEvent, AccessKind, Watchpoint, WatchpointId, WatchpointKind, WatchpointManager,
    check_access,
};

use std::path::PathBuf;

// ───────────────────────────────────────────────────────────────
// Top-level lib.rs types
// ───────────────────────────────────────────────────────────────

#[test]
fn pid_tid_ord_and_hash() {
    use std::collections::HashSet;
    assert!(ProcessId(1) < ProcessId(2));
    assert!(ThreadId(5) > ThreadId(4));
    let mut set: HashSet<ProcessId> = HashSet::new();
    set.insert(ProcessId(42));
    set.insert(ProcessId(42));
    assert_eq!(set.len(), 1);
}

#[test]
fn breakpoint_kind_equality() {
    assert_eq!(BreakpointKind::Software, BreakpointKind::Software);
    assert_ne!(BreakpointKind::Software, BreakpointKind::Hardware);
}

#[test]
fn register_set_default_is_empty() {
    let r = RegisterSet::default();
    assert_eq!(r.pc, 0);
    assert_eq!(r.sp, 0);
    assert!(r.fp.is_none());
    assert!(r.lr.is_none());
    assert!(r.all_names().is_empty());
}

#[test]
fn register_set_overwrite_preserves_count() {
    let mut r = RegisterSet::new();
    r.set("rax", 1);
    r.set("rax", 2);
    r.set("rax", 3);
    assert_eq!(r.get("rax"), Some(3));
    assert_eq!(r.all_names().len(), 1);
}

#[test]
fn stop_reason_address_for_each_variant() {
    let a = Address::new(0xAA);
    assert_eq!(
        StopReason::SingleStep { address: a }.address(),
        Some(a)
    );
    assert_eq!(
        StopReason::AccessViolation {
            address: a,
            is_write: true
        }
        .address(),
        Some(a)
    );
    assert_eq!(
        StopReason::LibraryLoad {
            path: "x".into(),
            base: a
        }
        .address(),
        Some(a)
    );
    assert_eq!(
        StopReason::Signal {
            signum: 1,
            signame: "S".into(),
            address: None
        }
        .address(),
        None
    );
    assert_eq!(
        StopReason::Unknown {
            description: "z".into()
        }
        .address(),
        None
    );
}

#[test]
fn stop_reason_display_variants() {
    let a = Address::new(0x1234);
    assert!(
        StopReason::LibraryLoad {
            path: "/lib/x.so".into(),
            base: a,
        }
        .to_string()
        .contains("library")
    );
    assert!(StopReason::LibraryUnload { path: "x".into() }
        .to_string()
        .contains("unloaded"));
    assert!(StopReason::ThreadCreate { tid: ThreadId(7) }
        .to_string()
        .contains("thread"));
    assert!(
        StopReason::ThreadExit {
            tid: ThreadId(2),
            exit_code: 0,
        }
        .to_string()
        .contains("exited")
    );
    assert!(StopReason::ProcessCreate { pid: ProcessId(99) }
        .to_string()
        .contains("99"));
    let av = StopReason::AccessViolation {
        address: a,
        is_write: false,
    };
    assert!(av.to_string().contains("read"));
}

#[test]
fn debug_session_concurrent_safety_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DebugSession>();
}

#[test]
fn debug_session_breakpoint_replace_on_same_addr() {
    let s = DebugSession::new();
    let mut bp = Breakpoint::new_software(Address::new(0x1000));
    bp.label = Some("first".into());
    s.add_breakpoint(bp);
    let mut bp2 = Breakpoint::new_software(Address::new(0x1000));
    bp2.label = Some("second".into());
    s.add_breakpoint(bp2);
    assert_eq!(s.all_breakpoints().len(), 1);
    assert_eq!(
        s.get_breakpoint(Address::new(0x1000)).unwrap().label,
        Some("second".into())
    );
}

#[test]
fn launch_options_defaults() {
    let opts = LaunchOptions::new("/bin/true");
    assert!(!opts.stop_at_entry);
    assert!(!opts.follow_forks);
    assert!(!opts.redirect.stdout);
    assert!(!opts.redirect.stderr);
    assert!(opts.args.is_empty());
    assert!(opts.env.is_empty());
}

#[test]
fn launch_options_with_env_chains() {
    let opts = LaunchOptions::new("/bin/x")
        .with_env("A", "1")
        .with_env("B", "2");
    assert_eq!(opts.env.len(), 2);
    assert_eq!(opts.env["A"], "1");
}

// ───────────────────────────────────────────────────────────────
// with_timeout
// ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn with_timeout_returns_value() {
    let v: Result<u32, DebugError> = with_timeout(std::time::Duration::from_secs(1), async {
        Ok(42)
    })
    .await;
    assert_eq!(v.unwrap(), 42);
}

#[tokio::test]
async fn with_timeout_times_out() {
    let r: Result<u32, DebugError> = with_timeout(std::time::Duration::from_millis(10), async {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        Ok(0)
    })
    .await;
    assert!(matches!(r, Err(DebugError::Timeout)));
}

// ───────────────────────────────────────────────────────────────
// RegisterSchema
// ───────────────────────────────────────────────────────────────

#[test]
fn register_schema_x86_64_aliases() {
    let s = RegisterSchema::x86_64();
    assert!(s.get("rax").is_some());
    // eax is an alias of rax
    let rax_via_alias = s.get("eax").expect("alias should resolve");
    assert_eq!(rax_via_alias.name, "rax");
    // SSE registers
    assert!(s.get("xmm0").is_some());
    // segment register
    assert!(s.get("cs").is_some());
    assert!(!s.is_empty());
}

#[test]
fn register_schema_aarch64() {
    let s = RegisterSchema::aarch64();
    assert!(s.get("x0").is_some());
    assert!(s.get("w0").is_some()); // alias
    assert!(s.get("sp").is_some());
    assert!(s.get("pc").is_some());
    assert!(s.get("v31").is_some());
    assert!(s.get("q31").is_some());
}

#[test]
fn register_schema_by_group() {
    let s = RegisterSchema::x86_64();
    let gp = s.by_group(&RegisterGroup::GeneralPurpose);
    assert!(!gp.is_empty());
    let vec = s.by_group(&RegisterGroup::Vector);
    assert!(!vec.is_empty());
}

#[test]
fn register_group_display() {
    assert_eq!(RegisterGroup::GeneralPurpose.to_string(), "general-purpose");
    assert_eq!(RegisterGroup::FloatingPoint.to_string(), "floating-point");
    assert_eq!(RegisterGroup::Vector.to_string(), "vector");
    assert_eq!(RegisterGroup::System.to_string(), "system");
    assert_eq!(RegisterGroup::Custom("nx".into()).to_string(), "nx");
}

#[test]
fn register_info_builder() {
    let info = RegisterInfo::new("foo", 64, RegisterGroup::GeneralPurpose)
        .with_alias("f")
        .with_dwarf_id(7)
        .with_description("test");
    assert_eq!(info.bit_width, 64);
    assert_eq!(info.dwarf_id, Some(7));
    assert_eq!(info.aliases, vec!["f"]);
    assert_eq!(info.description, "test");
}

// ───────────────────────────────────────────────────────────────
// Memory search adversarial cases
// ───────────────────────────────────────────────────────────────

#[test]
fn hex_pattern_rejects_odd_length() {
    let err = SearchPattern::hex("ABC").unwrap_err();
    assert!(matches!(err, SearchError::InvalidPattern(_)));
}

#[test]
fn hex_pattern_rejects_non_hex() {
    let err = SearchPattern::hex("ZZ").unwrap_err();
    assert!(matches!(err, SearchError::InvalidPattern(_)));
}

#[test]
fn hex_pattern_allows_double_wildcard() {
    let p = SearchPattern::hex("?? ?? AA").unwrap();
    let data = [0x00u8, 0x01, 0xAA, 0xBB];
    let s = MemorySearch::default_options();
    let results = s.search_buffer(&data, 0, &p, 0, None).unwrap();
    assert_eq!(results.len(), 1);
}

#[test]
fn search_buffer_short_data_returns_empty() {
    let data = [0xAA];
    let p = SearchPattern::bytes(vec![0xAA, 0xBB]).unwrap();
    let s = MemorySearch::default_options();
    let results = s.search_buffer(&data, 0, &p, 0, None).unwrap();
    assert!(results.is_empty());
}

#[test]
fn search_buffer_empty_data() {
    let data: [u8; 0] = [];
    let p = SearchPattern::bytes(vec![0xAA]).unwrap();
    let s = MemorySearch::default_options();
    let results = s.search_buffer(&data, 0, &p, 0, None).unwrap();
    assert!(results.is_empty());
}

#[test]
fn search_xor_empty_pattern_errors() {
    let p = SearchPattern::Xor {
        pattern: vec![],
        key: 0,
    };
    let data = [0u8; 4];
    let s = MemorySearch::default_options();
    let r = s.search_buffer(&data, 0, &p, 0, None);
    assert!(matches!(r, Err(SearchError::EmptyPattern)));
}

#[test]
fn search_pattern_string_empty_errors() {
    assert!(matches!(
        SearchPattern::string(""),
        Err(SearchError::EmptyPattern)
    ));
}

#[test]
fn search_all_regions_skips_region_out_of_buffer() {
    // Region's address is beyond the buffer length: should silently skip.
    let mem = vec![0xAAu8; 16];
    let region = MemoryRegion::readable(100, 16, None);
    let p = SearchPattern::bytes(vec![0xAA]).unwrap();
    let results = search_all_regions(&mem, &[region], &p).unwrap();
    assert!(results.is_empty());
}

#[test]
fn search_all_regions_truncates_at_buffer_end() {
    // Region claims to be 32 bytes but mem only has 16.
    let mem = vec![0xAAu8; 16];
    let region = MemoryRegion::readable(0, 32, None);
    let p = SearchPattern::bytes(vec![0xAA]).unwrap();
    let results = search_all_regions(&mem, &[region], &p).unwrap();
    // Only the 16 real bytes get scanned.
    assert_eq!(results.len(), 16);
}

#[test]
fn search_max_results_zero_means_unlimited() {
    let data = vec![0xAAu8; 10];
    let p = SearchPattern::bytes(vec![0xAA]).unwrap();
    let s = MemorySearch::new(SearchOptions::default().with_max_results(0));
    let results = s.search_buffer(&data, 0, &p, 0, None).unwrap();
    assert_eq!(results.len(), 10);
}

#[test]
fn search_alignment_8() {
    let data = vec![0xCCu8; 32];
    let p = SearchPattern::bytes(vec![0xCC]).unwrap();
    let s = MemorySearch::new(SearchOptions::default().aligned(8));
    let results = s.search_buffer(&data, 0, &p, 0, None).unwrap();
    assert_eq!(results.len(), 4); // 0, 8, 16, 24
    for r in &results {
        assert_eq!(r.address % 8, 0);
    }
}

#[test]
fn search_executable_only_skips_non_executable() {
    let mem = vec![0xAAu8; 16];
    let mut region = MemoryRegion::readable(0, 16, None);
    region.executable = false;
    let p = SearchPattern::bytes(vec![0xAA]).unwrap();
    let s = MemorySearch::new(SearchOptions::default().executable_only());
    let results = s.search_all_regions(&mem, &[region], &p).unwrap();
    assert!(results.is_empty());
}

#[test]
fn memory_region_end_and_range() {
    let r = MemoryRegion::readable(0x4000, 0x100, Some("test".into()));
    assert_eq!(r.end(), 0x4100);
    assert_eq!(r.range(), 0x4000..0x4100);
}

#[test]
fn search_pattern_min_len_utf16le() {
    let p = SearchPattern::Utf16Le("AB".into());
    assert_eq!(p.min_len(), 4);
}

#[test]
fn search_pattern_display_round_trip() {
    let p = SearchPattern::Bytes(vec![0xDE, 0xAD]);
    assert_eq!(p.to_string(), p.description());
}

// ───────────────────────────────────────────────────────────────
// Conditional breakpoint
// ───────────────────────────────────────────────────────────────

#[test]
fn evaluate_condition_basic_ops() {
    let mut ctx = MapEvalContext::new();
    ctx.set_reg("a", 10);
    for (op, expected) in [
        (ConditionOperator::Eq, false),
        (ConditionOperator::Ne, true),
        (ConditionOperator::Lt, true),
        (ConditionOperator::Le, true),
        (ConditionOperator::Gt, false),
        (ConditionOperator::Ge, false),
    ] {
        let cond = BreakpointCondition::new(
            ConditionOperand::Register("a".into()),
            op,
            ConditionOperand::Literal(20),
        );
        assert_eq!(evaluate_condition(&cond, &ctx).unwrap(), expected);
    }
}

#[test]
fn evaluate_bitand_bitor() {
    let mut ctx = MapEvalContext::new();
    ctx.set_reg("flags", 0b1010);
    let cand = BreakpointCondition::new(
        ConditionOperand::Register("flags".into()),
        ConditionOperator::BitAnd,
        ConditionOperand::Literal(0b1000),
    );
    assert!(evaluate_condition(&cand, &ctx).unwrap());
    let cnor = BreakpointCondition::new(
        ConditionOperand::Register("flags".into()),
        ConditionOperator::BitAnd,
        ConditionOperand::Literal(0b0100),
    );
    assert!(!evaluate_condition(&cnor, &ctx).unwrap());
}

#[test]
fn memory_read_error_when_unmapped() {
    let cond = BreakpointCondition::new(
        ConditionOperand::Memory {
            addr: 0xDEAD,
            width: 4,
        },
        ConditionOperator::Eq,
        ConditionOperand::Literal(0),
    );
    let ctx = MapEvalContext::new();
    let err = evaluate_condition(&cond, &ctx).unwrap_err();
    assert!(matches!(err, ConditionError::MemoryReadError { addr: 0xDEAD }));
}

#[test]
fn unknown_variable_returns_error() {
    let cond = BreakpointCondition::new(
        ConditionOperand::Variable("x".into()),
        ConditionOperator::Eq,
        ConditionOperand::Literal(0),
    );
    let ctx = MapEvalContext::new();
    assert!(matches!(
        evaluate_condition(&cond, &ctx),
        Err(ConditionError::UnknownVariable(_))
    ));
}

#[test]
fn condition_error_display() {
    let e = ConditionError::DivisionByZero;
    assert!(e.to_string().contains("division"));
    let e2 = ConditionError::MemoryReadError { addr: 0xCAFE };
    assert!(e2.to_string().contains("cafe") || e2.to_string().contains("CAFE"));
}

#[test]
fn cond_bp_set_remove_index_bounds() {
    let mut set = ConditionalBreakpointSet::new();
    assert!(set.is_empty());
    let i = set.add(ConditionalBreakpoint::at(Address::from(0x1000_u64)));
    assert_eq!(i, 0);
    assert_eq!(set.len(), 1);
    assert!(set.remove(99).is_none());
    assert!(set.remove(0).is_some());
    assert!(set.is_empty());
}

#[test]
fn cond_bp_pass_count_one_fires_every_time() {
    let mut bp = ConditionalBreakpoint::at(Address::from(0x1000_u64));
    bp.pass_count = 1;
    let ctx = MapEvalContext::new();
    assert!(bp.should_break(&ctx).unwrap());
    assert!(bp.should_break(&ctx).unwrap());
    assert!(bp.should_break(&ctx).unwrap());
    assert_eq!(bp.hit_count, 3);
}

// ───────────────────────────────────────────────────────────────
// Watchpoint manager
// ───────────────────────────────────────────────────────────────

#[test]
fn watchpoint_zero_size_does_not_cover() {
    let wp = Watchpoint::new(
        WatchpointId(0),
        Address::from(0x1000_u64),
        0,
        WatchpointKind::Write,
    );
    assert!(!wp.covers(Address::from(0x1000_u64)));
}

#[test]
fn watchpoint_overlap_boundary() {
    let wp = Watchpoint::new(
        WatchpointId(0),
        Address::from(0x1000_u64),
        4,
        WatchpointKind::Write,
    );
    // Access [0x0FFC..0x1000) — touches boundary but does not overlap.
    assert!(!wp.overlaps(Address::from(0x0FFC_u64), 4));
    // Access [0x0FFC..0x1004) — overlaps.
    assert!(wp.overlaps(Address::from(0x0FFC_u64), 8));
    // Access [0x1004..0x1008) — boundary, does not overlap.
    assert!(!wp.overlaps(Address::from(0x1004_u64), 4));
}

#[test]
fn watchpoint_value_change_fires_first_time_then_only_on_change() {
    let mut wp = Watchpoint::new(
        WatchpointId(1),
        Address::from(0x100_u64),
        4,
        WatchpointKind::ValueChange,
    );
    let ev1 = AccessEvent::write(Address::from(0x100_u64), 4, 1);
    assert!(check_access(&mut wp, &ev1));
    let ev_same = AccessEvent::write(Address::from(0x100_u64), 4, 1);
    assert!(!check_access(&mut wp, &ev_same));
    let ev_diff = AccessEvent::write(Address::from(0x100_u64), 4, 2);
    assert!(check_access(&mut wp, &ev_diff));
}

#[test]
fn watchpoint_value_equals_ignores_reads() {
    // ValueEquals checks current_value regardless of access kind in code path,
    // so let's verify behavior on reads.
    let mut wp = Watchpoint::new(
        WatchpointId(1),
        Address::from(0x100_u64),
        4,
        WatchpointKind::ValueEquals,
    );
    wp.compare_value = Some(0xAA);
    // A read with matching value: implementation does not gate on access kind.
    let ev = AccessEvent::read(Address::from(0x100_u64), 4, 0xAA);
    let fired = check_access(&mut wp, &ev);
    // Document behavior: should fire even on read with matching value.
    assert!(fired);
}

#[test]
fn watchpoint_manager_disable_reenable() {
    let mut m = WatchpointManager::new();
    let id = m.add(Address::from(0x100_u64), 4, WatchpointKind::Write);
    assert!(m.set_enabled(id, false));
    let ev = AccessEvent::write(Address::from(0x100_u64), 4, 0);
    assert!(m.process_access(&ev).is_empty());
    assert!(m.set_enabled(id, true));
    assert!(!m.process_access(&ev).is_empty());
}

#[test]
fn watchpoint_manager_set_enabled_unknown_returns_false() {
    let mut m = WatchpointManager::new();
    assert!(!m.set_enabled(WatchpointId(99), true));
}

#[test]
fn watchpoint_manager_clear_and_counts() {
    let mut m = WatchpointManager::new();
    let id = m.add(Address::from(0x100_u64), 4, WatchpointKind::Write);
    let _ = m.process_access(&AccessEvent::write(Address::from(0x100_u64), 4, 0));
    m.reset_all_counts();
    assert_eq!(m.get(id).unwrap().hit_count, 0);
    m.clear();
    assert!(m.is_empty());
}

#[test]
fn watchpoint_id_display() {
    assert_eq!(WatchpointId(7).to_string(), "WP#7");
}

#[test]
fn access_kind_display() {
    assert_eq!(AccessKind::Read.to_string(), "Read");
    assert_eq!(AccessKind::Write.to_string(), "Write");
}

#[test]
fn watchpoint_builder_chain() {
    let wp = Watchpoint::new(
        WatchpointId(0),
        Address::from(0x100_u64),
        4,
        WatchpointKind::Write,
    )
    .with_label("guard")
    .with_compare_value(0xDEAD)
    .with_max_hits(3);
    assert_eq!(wp.label.as_deref(), Some("guard"));
    assert_eq!(wp.compare_value, Some(0xDEAD));
    assert_eq!(wp.max_hits, 3);
}

#[test]
fn watchpoint_manager_insert_preserves_fields() {
    let mut m = WatchpointManager::new();
    let wp = Watchpoint::new(
        WatchpointId(999), // will be overridden
        Address::from(0x500_u64),
        4,
        WatchpointKind::Read,
    )
    .with_label("foo");
    let id = m.insert(wp);
    let stored = m.get(id).unwrap();
    assert_eq!(stored.label.as_deref(), Some("foo"));
    assert_ne!(stored.id, WatchpointId(999));
    assert_eq!(stored.id, id);
}

// ───────────────────────────────────────────────────────────────
// Source map
// ───────────────────────────────────────────────────────────────

#[test]
fn source_location_display_with_column_and_func() {
    let loc = SourceLocation::new(PathBuf::from("main.c"), 42)
        .with_column(8)
        .with_function("main");
    let s = loc.to_string();
    assert!(s.contains("main.c"));
    assert!(s.contains("42"));
    assert!(s.contains(":8"));
    assert!(s.contains("(in main)"));
}

#[test]
fn source_location_display_no_column() {
    let loc = SourceLocation::new(PathBuf::from("a.c"), 10);
    let s = loc.to_string();
    assert!(s.contains(":10"));
    assert!(!s.contains(":0"));
}

#[test]
fn source_map_empty_returns_none() {
    let sm = SourceMap::empty(PathBuf::from("/tmp"), SourceRootMapper::new());
    assert!(sm.addr_to_source(0x1000).is_none());
    assert!(sm.source_to_addr("x.c", 1).is_none());
    assert_eq!(sm.entry_count(), 0);
    assert!(sm.function_at(0x1000).is_none());
}

#[test]
fn source_root_mapper_remap_no_match() {
    let mut m = SourceRootMapper::new();
    m.add_mapping("/build", "/local");
    let p = m.remap(std::path::Path::new("/other/file.c"));
    assert_eq!(p, PathBuf::from("/other/file.c"));
}

#[test]
fn source_root_mapper_remap_match() {
    let mut m = SourceRootMapper::new();
    m.add_mapping("/build", "/local");
    let p = m.remap(std::path::Path::new("/build/src/x.c"));
    assert_eq!(p, PathBuf::from("/local/src/x.c"));
}

#[test]
fn std_opcode_round_trip() {
    for op in [
        StdOpcode::Copy,
        StdOpcode::AdvancePc,
        StdOpcode::AdvanceLine,
        StdOpcode::SetFile,
        StdOpcode::SetColumn,
        StdOpcode::NegateStmt,
        StdOpcode::SetBasicBlock,
        StdOpcode::ConstAddPc,
        StdOpcode::FixedAdvancePc,
        StdOpcode::SetPrologueEnd,
        StdOpcode::SetEpilogueBegin,
        StdOpcode::SetIsa,
    ] {
        let b = op.as_u8();
        assert_eq!(StdOpcode::from_u8(b), Some(op));
    }
    assert!(StdOpcode::from_u8(0xFF).is_none());
}

#[test]
fn ext_opcode_round_trip() {
    for op in [
        ExtOpcode::EndSequence,
        ExtOpcode::SetAddress,
        ExtOpcode::DefineFile,
        ExtOpcode::SetDiscrim,
        ExtOpcode::LoUser,
        ExtOpcode::HiUser,
    ] {
        let b = op.as_u8();
        assert_eq!(ExtOpcode::from_u8(b), Some(op));
    }
    assert!(ExtOpcode::LoUser.is_user());
    assert!(ExtOpcode::HiUser.is_user());
    assert!(!ExtOpcode::SetAddress.is_user());
}

#[test]
fn source_map_error_display() {
    let e = SourceMapError::NoLinetableForAddress(0xABCD);
    assert!(e.to_string().contains("abcd"));
    let e2 = SourceMapError::NoAddressForLine {
        file: "x.c".into(),
        line: 5,
    };
    assert!(e2.to_string().contains("x.c"));
    assert!(e2.to_string().contains('5'));
}

// ───────────────────────────────────────────────────────────────
// v2 module
// ───────────────────────────────────────────────────────────────

#[test]
fn v2_session_ids_are_unique_and_increasing() {
    use rustre_debug::v2::{BreakpointKind as K, DebugSession};
    let mut s = DebugSession::new(1);
    let mut ids = Vec::new();
    for i in 0..10 {
        ids.push(s.add_breakpoint(0x1000 + i, K::Software));
    }
    // All distinct.
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 10);
    // Strictly increasing.
    for w in ids.windows(2) {
        assert!(w[0] < w[1]);
    }
}

#[test]
fn v2_mock_debugger_write_out_of_range_errors() {
    use rustre_debug::v2::{DebugError, DebugSession, Debugger, MockDebugger};
    let mut m = MockDebugger::new("t");
    m.mem.insert(0x1000, vec![0u8; 4]);
    let s = DebugSession::new(1);
    let r = m.write_memory(&s, 0x1000, &[0; 100]);
    assert!(matches!(r, Err(DebugError::MemWrite(0x1000))));
}

#[test]
fn v2_breakpoint_kind_display_strings() {
    use rustre_debug::v2::BreakpointKind as K;
    assert_eq!(K::WatchReadWrite.to_string(), "watch-read-write");
}
