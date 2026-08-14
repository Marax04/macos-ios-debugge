pub mod access_log;
pub mod arena;
pub mod cache;
pub mod cache_layer;
pub mod composite_memory;
pub mod cow;
pub mod emulated_memory;
pub mod fault;
pub mod file_memory;
pub mod memory_provider;
pub mod null_memory;
pub mod patched_memory;
pub mod permissions_model;
pub mod phys;
pub mod process_memory;
pub mod provider;
pub mod region;
pub mod search;
pub mod snapshot;
pub mod snapshot_diff;
pub mod sparse;
pub mod trace_memory;
pub mod vmmap;

/// Virtual (in-memory) memory provider for synthetic/reconstructed views.
pub mod virtual_memory;

/// Entropy analysis utilities.
pub mod entropy;

/// Memory diff utilities (standalone helpers complementing snapshot_diff).
pub mod diff;

/// Helper read/write functions exposed at crate level.
pub mod helpers;

/// Enhanced composite provider with priority layers, WriteStrategy, and CoW overlay.
pub mod composite_provider;

/// TTD-style trace provider: TracePosition, MemorySnapshot, SnapshotCache, DeltaReplay.
pub mod trace_provider;

/// PatchedMemoryProvider with Patch, PatchConflict, PatchOverlay, PatchExport.
pub mod patched_provider;

pub use access_log::{AccessKind, AccessLog, AccessRecord, LoggingMemoryProvider};
pub use arena::{ArenaAlloc, ArenaError, ArenaMark, ArenaStats, MemoryArena};
pub use cache::{CacheStats, PageCache};
pub use composite_memory::CompositeMemoryProvider;
pub use cow::CowMemoryProvider;
pub use fault::{
    FaultError, FaultKind, FaultPolicy, FaultRule, FaultStats, FaultingMemoryProvider,
};
pub use file_memory::FileMemoryProvider;
pub use memory_provider::{
    MemError, MemoryProvider, MemoryProviderExt, MemoryRegion, MemoryStats as ProviderMemoryStats,
    ReadOnlyWrapper, RegionSource, SnapshotId, find_bytes, read_cstring, read_u16_le, read_u32_be,
    read_u32_le, read_u64_be, read_u64_le,
};
pub use null_memory::NullMemoryProvider;
pub use patched_memory::{Patch, PatchedMemoryProvider};
pub use permissions_model::{
    ExtendedPerms, PermissionAuditLog, PermissionChange, RelroStatus, infer_relro_status,
};
pub use phys::{
    FlatPhysMemory, MemMap, MemMapError, PageFlags, PageInfo, PhysAddr, PhysicalMemory, VirtAddr,
};
pub use provider::{
    EmulatedMemoryProvider, ProcessMemoryProvider, TraceMemoryProvider, TraceTickMemory,
};
pub use region::{
    ExtendedRegion, RegionAttributes, RegionKind, RegionSet, page_align_down, page_align_up,
    page_containing, page_index, page_range_indices,
};
pub use search::{BytePattern, MemorySearcher, PatternByte, SearchResult, search_with_context};
pub use snapshot::{SnapshotDiff as SnapshotDelta, SnapshotRecord, SnapshotStore, diff_snapshots};
pub use snapshot_diff::{
    MemoryChange, MemorySnapshot, MemoryStats, SnapshotDiff, diff_memory, diff_memory_lenient,
};
pub use sparse::{LargeWindowProvider, SparseMemoryProvider};

pub use emulated_memory::{
    EmulatedMemoryProvider as StandaloneEmulatedMemoryProvider, EmulatedRegion, PERM_EXEC,
    PERM_READ, PERM_WRITE,
};
pub use process_memory::{MemRegion, ProcessMemoryProvider as StandaloneProcessMemoryProvider};
pub use trace_memory::{TraceMemoryProvider as StandaloneTraceMemoryProvider, TraceSnapshot};

pub use virtual_memory::VirtualMemoryProvider;

// composite_provider re-exports.
pub use composite_provider::{
    CompositeMemoryProvider as EnhancedCompositeProvider, LayerOverlap, ProviderLayer,
    RegionMerger, WriteStrategy,
};

// trace_provider re-exports.
pub use trace_provider::{
    DeltaReplay, MemoryDelta, MemorySnapshot as TraceMemorySnapshot, SnapshotCache,
    TraceMemoryProvider as EnhancedTraceMemoryProvider, TracePosition,
};

// patched_provider re-exports.
pub use patched_provider::{
    Patch as EnhancedPatch, PatchConflict as EnhancedPatchConflict, PatchDiffEntry, PatchExport,
    PatchOverlay, PatchedMemoryProvider as EnhancedPatchedMemoryProvider,
};
/// Memory analysis: MemoryAnalysis, RegionClassifier, EntropyRegion,
/// StringScanner, PointerScanner, PatternScanner, MemoryReport.
pub mod memory_analysis;

/// Memory diff: MemoryDiff, DiffEntry, DiffRegion, diff_snapshots(), apply_diff().
pub mod memory_diff;

/// Memory access log: MemoryAccessLog, AccessEntry, AccessKind, log_access(), replay_accesses().
pub mod memory_access_log;

/// Memory layout analyzer: MemoryLayoutAnalyzer, MemoryRegion, LayoutReport, analyze_layout().
pub mod memory_layout_analyzer;

pub use diff::{DiffSpan, diff_providers};
pub use entropy::{EntropyBlock, shannon_entropy};
pub use helpers::{
    read_f32_le_at, read_f64_le_at, read_i8_at, read_i16_le_at, read_i32_le_at, read_i64_le_at,
    read_u8_at, read_u16_be_at, read_u16_le_at, read_u32_be_at, read_u32_le_at, read_u64_be_at,
    read_u64_le_at, search_bytes_with_mask, write_u8_at, write_u16_le_at, write_u32_le_at,
    write_u64_le_at,
};

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::address::{Address, AddressRange};
    use rustre_core::permissions::Permissions;

    // ── VirtualMemoryProvider ─────────────────────────────────────────────────

    #[test]
    fn virtual_provider_read_write() {
        let mut provider = VirtualMemoryProvider::new();
        provider.map(
            Address::new(0x1000),
            vec![0u8; 0x100],
            Permissions::READ | Permissions::WRITE,
        );
        provider
            .write(Address::new(0x1000), &[0xDE, 0xAD, 0xBE, 0xEF])
            .unwrap();
        let data = provider.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(data, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn virtual_provider_read_unmapped_returns_error() {
        let provider = VirtualMemoryProvider::new();
        assert!(provider.read(Address::new(0xDEAD0000), 4).is_err());
    }

    #[test]
    fn virtual_provider_write_readonly_returns_error() {
        let mut provider = VirtualMemoryProvider::new();
        provider.map(Address::new(0x1000), vec![0u8; 0x10], Permissions::READ);
        assert!(provider.write(Address::new(0x1000), &[0xAA]).is_err());
    }

    #[test]
    fn virtual_provider_regions_empty() {
        let provider = VirtualMemoryProvider::new();
        assert!(provider.regions().is_empty());
    }

    #[test]
    fn virtual_provider_regions_non_empty() {
        let mut provider = VirtualMemoryProvider::new();
        provider.map(
            Address::new(0x1000),
            vec![0u8; 0x200],
            Permissions::READ | Permissions::EXECUTE,
        );
        provider.map(
            Address::new(0x2000),
            vec![0u8; 0x100],
            Permissions::READ | Permissions::WRITE,
        );
        let regions = provider.regions();
        assert_eq!(regions.len(), 2);
    }

    #[test]
    fn virtual_provider_unmap() {
        let mut provider = VirtualMemoryProvider::new();
        provider.map(
            Address::new(0x1000),
            vec![0u8; 0x100],
            Permissions::READ | Permissions::WRITE,
        );
        assert_eq!(provider.regions().len(), 1);
        provider.unmap(Address::new(0x1000));
        assert_eq!(provider.regions().len(), 0);
    }

    #[test]
    fn virtual_provider_read_u32_le() {
        let mut provider = VirtualMemoryProvider::new();
        provider.map(
            Address::new(0x1000),
            vec![0u8; 0x10],
            Permissions::READ | Permissions::WRITE,
        );
        provider
            .write(Address::new(0x1000), &[0x78, 0x56, 0x34, 0x12])
            .unwrap();
        assert_eq!(provider.read_u32_le(Address::new(0x1000)), Some(0x12345678));
    }

    #[test]
    fn virtual_provider_read_u64_le() {
        let mut provider = VirtualMemoryProvider::new();
        provider.map(
            Address::new(0x1000),
            vec![0u8; 0x10],
            Permissions::READ | Permissions::WRITE,
        );
        let bytes = 0xDEADBEEFCAFEBABEu64.to_le_bytes();
        provider.write(Address::new(0x1000), &bytes).unwrap();
        assert_eq!(
            provider.read_u64_le(Address::new(0x1000)),
            Some(0xDEADBEEFCAFEBABE)
        );
    }

    // ── Entropy ───────────────────────────────────────────────────────────────

    #[test]
    fn entropy_all_zeros_is_zero() {
        let data = vec![0u8; 256];
        let result = shannon_entropy(&data);
        assert!((result - 0.0).abs() < 1e-9);
    }

    #[test]
    fn entropy_random_data_is_near_eight() {
        // 256 distinct bytes exactly once → entropy = 8.0 bits.
        let data: Vec<u8> = (0u8..=255).collect();
        let result = shannon_entropy(&data);
        assert!((result - 8.0).abs() < 0.01, "entropy = {result}");
    }

    #[test]
    fn entropy_single_byte_is_zero() {
        let data = vec![0xAAu8; 1024];
        let result = shannon_entropy(&data);
        assert!((result - 0.0).abs() < 1e-9);
    }

    #[test]
    fn entropy_two_equal_bytes_is_one() {
        let data = vec![0u8, 1, 0, 1, 0, 1, 0, 1];
        let result = shannon_entropy(&data);
        assert!((result - 1.0).abs() < 0.01, "entropy = {result}");
    }

    #[test]
    fn entropy_empty_is_zero() {
        let result = shannon_entropy(&[]);
        assert_eq!(result, 0.0);
    }

    // ── EntropyBlock (provider-level entropy) ─────────────────────────────────

    #[test]
    fn entropy_blocks_from_provider() {
        let mut provider = VirtualMemoryProvider::new();
        // Zero-filled block at 0x1000.
        provider.map(
            Address::new(0x1000),
            vec![0u8; 0x100],
            Permissions::READ | Permissions::WRITE,
        );
        // Random-ish block at 0x2000.
        let data: Vec<u8> = (0u8..=255).collect();
        provider.map(
            Address::new(0x2000),
            data,
            Permissions::READ | Permissions::WRITE,
        );

        let blocks = entropy::entropy_blocks(&provider, 0x100);
        assert_eq!(blocks.len(), 2);
        let zero_block = blocks
            .iter()
            .find(|b| b.address == Address::new(0x1000))
            .unwrap();
        let rand_block = blocks
            .iter()
            .find(|b| b.address == Address::new(0x2000))
            .unwrap();
        assert!((zero_block.entropy - 0.0).abs() < 1e-9);
        assert!((rand_block.entropy - 8.0).abs() < 0.01);
    }

    // ── Memory diff ───────────────────────────────────────────────────────────

    #[test]
    fn diff_identical_providers() {
        let mut a = VirtualMemoryProvider::new();
        let mut b = VirtualMemoryProvider::new();
        a.map(
            Address::new(0x1000),
            vec![0xAAu8; 64],
            Permissions::READ | Permissions::WRITE,
        );
        b.map(
            Address::new(0x1000),
            vec![0xAAu8; 64],
            Permissions::READ | Permissions::WRITE,
        );
        let diffs = diff_providers(
            &a,
            &b,
            AddressRange::new(Address::new(0x1000), Address::new(0x1040)),
        );
        assert!(diffs.is_empty());
    }

    #[test]
    fn diff_different_providers() {
        let mut a = VirtualMemoryProvider::new();
        let mut b = VirtualMemoryProvider::new();
        a.map(
            Address::new(0x1000),
            vec![0u8; 64],
            Permissions::READ | Permissions::WRITE,
        );
        b.map(
            Address::new(0x1000),
            vec![0u8; 64],
            Permissions::READ | Permissions::WRITE,
        );
        b.write(Address::new(0x1010), &[0xFF, 0xFF]).unwrap();
        let diffs = diff_providers(
            &a,
            &b,
            AddressRange::new(Address::new(0x1000), Address::new(0x1040)),
        );
        assert!(!diffs.is_empty());
        // The diff must cover 0x1010–0x1012.
        let covers = diffs.iter().any(|d| d.range.contains(Address::new(0x1010)));
        assert!(covers);
    }

    #[test]
    fn diff_span_length() {
        let span = DiffSpan {
            range: AddressRange::new(Address::new(0x100), Address::new(0x110)),
            old_bytes: vec![0u8; 16],
            new_bytes: vec![0xFFu8; 16],
        };
        assert_eq!(span.len(), 16);
    }

    // ── Helper functions ──────────────────────────────────────────────────────

    #[test]
    fn read_u8_helper() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x100),
            vec![0xABu8; 4],
            Permissions::READ | Permissions::WRITE,
        );
        assert_eq!(read_u8_at(&p, Address::new(0x100)), Some(0xAB));
    }

    #[test]
    fn read_u16_le_helper() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x100),
            vec![0u8; 4],
            Permissions::READ | Permissions::WRITE,
        );
        p.write(Address::new(0x100), &[0x34, 0x12]).unwrap();
        assert_eq!(read_u16_le_at(&p, Address::new(0x100)), Some(0x1234));
    }

    #[test]
    fn read_u16_be_helper() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x100),
            vec![0u8; 4],
            Permissions::READ | Permissions::WRITE,
        );
        p.write(Address::new(0x100), &[0x12, 0x34]).unwrap();
        assert_eq!(read_u16_be_at(&p, Address::new(0x100)), Some(0x1234));
    }

    #[test]
    fn read_u32_le_helper() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x100),
            vec![0u8; 8],
            Permissions::READ | Permissions::WRITE,
        );
        p.write(Address::new(0x100), &[0x78, 0x56, 0x34, 0x12])
            .unwrap();
        assert_eq!(read_u32_le_at(&p, Address::new(0x100)), Some(0x12345678));
    }

    #[test]
    fn read_u32_be_helper() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x100),
            vec![0u8; 8],
            Permissions::READ | Permissions::WRITE,
        );
        p.write(Address::new(0x100), &[0x12, 0x34, 0x56, 0x78])
            .unwrap();
        assert_eq!(read_u32_be_at(&p, Address::new(0x100)), Some(0x12345678));
    }

    #[test]
    fn read_u64_le_helper() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x100),
            vec![0u8; 16],
            Permissions::READ | Permissions::WRITE,
        );
        let val: u64 = 0xDEADBEEFCAFEBABE;
        p.write(Address::new(0x100), &val.to_le_bytes()).unwrap();
        assert_eq!(read_u64_le_at(&p, Address::new(0x100)), Some(val));
    }

    #[test]
    fn read_u64_be_helper() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x100),
            vec![0u8; 16],
            Permissions::READ | Permissions::WRITE,
        );
        let val: u64 = 0xDEADBEEFCAFEBABE;
        p.write(Address::new(0x100), &val.to_be_bytes()).unwrap();
        assert_eq!(read_u64_be_at(&p, Address::new(0x100)), Some(val));
    }

    #[test]
    fn read_i8_helper() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x100),
            vec![0xFFu8; 4],
            Permissions::READ | Permissions::WRITE,
        );
        assert_eq!(read_i8_at(&p, Address::new(0x100)), Some(-1i8));
    }

    #[test]
    fn read_i16_le_helper() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x100),
            vec![0u8; 4],
            Permissions::READ | Permissions::WRITE,
        );
        p.write(Address::new(0x100), &(-1i16).to_le_bytes())
            .unwrap();
        assert_eq!(read_i16_le_at(&p, Address::new(0x100)), Some(-1i16));
    }

    #[test]
    fn read_i32_le_helper() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x100),
            vec![0u8; 8],
            Permissions::READ | Permissions::WRITE,
        );
        p.write(Address::new(0x100), &(-42i32).to_le_bytes())
            .unwrap();
        assert_eq!(read_i32_le_at(&p, Address::new(0x100)), Some(-42i32));
    }

    #[test]
    fn read_i64_le_helper() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x100),
            vec![0u8; 16],
            Permissions::READ | Permissions::WRITE,
        );
        p.write(Address::new(0x100), &(-1i64).to_le_bytes())
            .unwrap();
        assert_eq!(read_i64_le_at(&p, Address::new(0x100)), Some(-1i64));
    }

    #[test]
    fn read_f32_le_helper() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x100),
            vec![0u8; 8],
            Permissions::READ | Permissions::WRITE,
        );
        let val = std::f32::consts::PI;
        p.write(Address::new(0x100), &val.to_le_bytes()).unwrap();
        let got = read_f32_le_at(&p, Address::new(0x100)).unwrap();
        assert!((got - val).abs() < 1e-6);
    }

    #[test]
    fn read_f64_le_helper() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x100),
            vec![0u8; 16],
            Permissions::READ | Permissions::WRITE,
        );
        let val = std::f64::consts::E;
        p.write(Address::new(0x100), &val.to_le_bytes()).unwrap();
        let got = read_f64_le_at(&p, Address::new(0x100)).unwrap();
        assert!((got - val).abs() < 1e-15);
    }

    #[test]
    fn write_u8_helper() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x100),
            vec![0u8; 4],
            Permissions::READ | Permissions::WRITE,
        );
        assert!(write_u8_at(&mut p, Address::new(0x100), 0xCC).is_ok());
        assert_eq!(read_u8_at(&p, Address::new(0x100)), Some(0xCC));
    }

    #[test]
    fn write_u16_le_helper() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x100),
            vec![0u8; 4],
            Permissions::READ | Permissions::WRITE,
        );
        write_u16_le_at(&mut p, Address::new(0x100), 0xABCD).unwrap();
        assert_eq!(read_u16_le_at(&p, Address::new(0x100)), Some(0xABCD));
    }

    #[test]
    fn write_u32_le_helper() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x100),
            vec![0u8; 8],
            Permissions::READ | Permissions::WRITE,
        );
        write_u32_le_at(&mut p, Address::new(0x100), 0xDEADBEEF).unwrap();
        assert_eq!(read_u32_le_at(&p, Address::new(0x100)), Some(0xDEADBEEF));
    }

    #[test]
    fn write_u64_le_helper() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x100),
            vec![0u8; 16],
            Permissions::READ | Permissions::WRITE,
        );
        write_u64_le_at(&mut p, Address::new(0x100), 0xDEADBEEFCAFEBABE).unwrap();
        assert_eq!(
            read_u64_le_at(&p, Address::new(0x100)),
            Some(0xDEADBEEFCAFEBABE)
        );
    }

    // ── search_bytes_with_mask ────────────────────────────────────────────────

    #[test]
    fn search_bytes_with_mask_found() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x1000),
            vec![0u8; 32],
            Permissions::READ | Permissions::WRITE,
        );
        p.write(Address::new(0x1010), &[0xDE, 0xAD, 0xBE, 0xEF])
            .unwrap();
        let range = AddressRange::new(Address::new(0x1000), Address::new(0x1020));
        let matches = search_bytes_with_mask(
            &p,
            &[0xDE, 0xAD, 0xBE, 0xEF],
            &[0xFF, 0xFF, 0xFF, 0xFF],
            range,
        );
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], Address::new(0x1010));
    }

    #[test]
    fn search_bytes_with_mask_wildcard() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x1000),
            vec![0u8; 32],
            Permissions::READ | Permissions::WRITE,
        );
        p.write(Address::new(0x1010), &[0xDE, 0xAD]).unwrap();
        p.write(Address::new(0x1018), &[0xDE, 0xBE]).unwrap();
        let range = AddressRange::new(Address::new(0x1000), Address::new(0x1020));
        // Match 0xDE, wildcard (mask=0x00 matches any byte)
        let matches = search_bytes_with_mask(
            &p,
            &[0xDE, 0x00],
            &[0xFF, 0x00], // second byte is wildcard
            range,
        );
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn search_bytes_with_mask_not_found() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x1000),
            vec![0xAAu8; 32],
            Permissions::READ | Permissions::WRITE,
        );
        let range = AddressRange::new(Address::new(0x1000), Address::new(0x1020));
        let matches = search_bytes_with_mask(&p, &[0xBB, 0xBB], &[0xFF, 0xFF], range);
        assert!(matches.is_empty());
    }

    // ── NullMemoryProvider ────────────────────────────────────────────────────

    #[test]
    fn null_provider_read_fails() {
        let p = NullMemoryProvider::new();
        assert!(p.read(Address::new(0x1000), 4).is_err());
    }

    #[test]
    fn null_provider_regions_empty() {
        let p = NullMemoryProvider::new();
        assert!(p.regions().is_empty());
    }

    // ── PatchedMemoryProvider ─────────────────────────────────────────────────

    #[test]
    fn patched_provider_intercepts_reads() {
        let mut base = VirtualMemoryProvider::new();
        base.map(
            Address::new(0x1000),
            vec![0xAAu8; 16],
            Permissions::READ | Permissions::WRITE,
        );
        let mut patched = PatchedMemoryProvider::new(base);
        patched.add_patch(Address::new(0x1000), vec![0xBB, 0xBB, 0xBB, 0xBB], None);
        let data = patched.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(data, [0xBB, 0xBB, 0xBB, 0xBB]);
    }

    #[test]
    fn patched_provider_passthrough_outside_patch() {
        let mut base = VirtualMemoryProvider::new();
        base.map(
            Address::new(0x1000),
            vec![0xCCu8; 16],
            Permissions::READ | Permissions::WRITE,
        );
        let mut patched = PatchedMemoryProvider::new(base);
        patched.add_patch(Address::new(0x1000), vec![0xDD], None);
        // Read outside the patch.
        let data = patched.read(Address::new(0x1004), 4).unwrap();
        assert_eq!(data, [0xCC, 0xCC, 0xCC, 0xCC]);
    }

    // ── MemoryRegion overlap detection ────────────────────────────────────────

    #[test]
    fn memory_region_contains() {
        let region = MemoryRegion {
            range: AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
            perms: Permissions::READ,
            name: None,
            source: RegionSource::Anonymous,
        };
        assert!(region.range.contains(Address::new(0x1500)));
        assert!(!region.range.contains(Address::new(0x2000)));
    }

    #[test]
    fn memory_region_overlaps() {
        let r1 = AddressRange::new(Address::new(0x1000), Address::new(0x2000));
        let r2 = AddressRange::new(Address::new(0x1800), Address::new(0x3000));
        assert!(r1.overlaps(&r2));
    }

    #[test]
    fn memory_region_no_overlap() {
        let r1 = AddressRange::new(Address::new(0x1000), Address::new(0x2000));
        let r2 = AddressRange::new(Address::new(0x2000), Address::new(0x3000));
        assert!(!r1.overlaps(&r2));
    }

    // ── CompositeMemoryProvider ───────────────────────────────────────────────

    #[test]
    fn composite_provider_first_wins() {
        let mut primary = VirtualMemoryProvider::new();
        primary.map(
            Address::new(0x1000),
            vec![0xAAu8; 4],
            Permissions::READ | Permissions::WRITE,
        );

        let mut secondary = VirtualMemoryProvider::new();
        secondary.map(
            Address::new(0x1000),
            vec![0xBBu8; 4],
            Permissions::READ | Permissions::WRITE,
        );

        let mut composite = CompositeMemoryProvider::new();
        composite.add_provider(Box::new(primary), 10);
        composite.add_provider(Box::new(secondary), 5);

        let data = composite.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(data, [0xAA, 0xAA, 0xAA, 0xAA]);
    }

    #[test]
    fn composite_provider_fallback() {
        let primary = VirtualMemoryProvider::new(); // empty

        let mut secondary = VirtualMemoryProvider::new();
        secondary.map(
            Address::new(0x1000),
            vec![0xCCu8; 4],
            Permissions::READ | Permissions::WRITE,
        );

        let mut composite = CompositeMemoryProvider::new();
        composite.add_provider(Box::new(primary), 10);
        composite.add_provider(Box::new(secondary), 5);

        let data = composite.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(data, [0xCC, 0xCC, 0xCC, 0xCC]);
    }

    // ── SnapshotId ────────────────────────────────────────────────────────────

    #[test]
    fn snapshot_id_is_opaque() {
        let id1 = SnapshotId(1);
        let id2 = SnapshotId(2);
        assert_ne!(id1, id2);
        assert_eq!(id1, SnapshotId(1));
    }

    // ── MemError ──────────────────────────────────────────────────────────────

    #[test]
    fn mem_error_not_mapped() {
        let e = MemError::NotMapped(Address::new(0xDEAD));
        assert!(e.to_string().contains("not mapped") || e.to_string().contains("0xdead"));
    }

    #[test]
    fn mem_error_permission_denied() {
        let e = MemError::PermissionDenied(Address::new(0x1000));
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn mem_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let mem_err = MemError::from(io_err);
        assert!(matches!(mem_err, MemError::Io(_)));
    }

    // ── Permissions ───────────────────────────────────────────────────────────

    #[test]
    fn permissions_from_str_rwx() {
        let p = Permissions::from_rwx_string("rwx").unwrap();
        assert!(p.is_readable());
        assert!(p.is_writable());
        assert!(p.is_executable());
    }

    #[test]
    fn permissions_from_str_r_only() {
        let p = Permissions::from_rwx_string("r--").unwrap();
        assert!(p.is_readable());
        assert!(!p.is_writable());
        assert!(!p.is_executable());
    }

    // ── CachedMemoryProvider (via PageCache) ──────────────────────────────────

    #[test]
    fn page_cache_basic_usage() {
        // PageCache requires page_size (power-of-two) and capacity.
        let mut cache = PageCache::new(4096, 2); // 4 KiB pages, capacity 2 pages
        assert!(cache.is_empty());
        // Read via fetch_page callback.
        let result = cache.read::<String, _>(Address::new(0x1000), 4, |_page_start, page_size| {
            Ok(vec![0xAAu8; page_size])
        });
        assert_eq!(result.unwrap(), [0xAAu8; 4]);
        assert_eq!(cache.len(), 1);
    }

    // ── Additional VirtualMemoryProvider tests ────────────────────────────────

    #[test]
    fn virtual_provider_large_read() {
        let mut p = VirtualMemoryProvider::new();
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        p.map(
            Address::new(0x1000),
            data.clone(),
            Permissions::READ | Permissions::WRITE,
        );
        let read_back = p.read(Address::new(0x1000), 4096).unwrap();
        assert_eq!(read_back, data);
    }

    #[test]
    fn virtual_provider_write_at_end_of_region() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x1000),
            vec![0u8; 16],
            Permissions::READ | Permissions::WRITE,
        );
        // Write the last 4 bytes.
        p.write(Address::new(0x100C), &[0x01, 0x02, 0x03, 0x04])
            .unwrap();
        let data = p.read(Address::new(0x100C), 4).unwrap();
        assert_eq!(data, [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn virtual_provider_out_of_bounds_write_fails() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x1000),
            vec![0u8; 4],
            Permissions::READ | Permissions::WRITE,
        );
        // Write beyond the mapped range.
        assert!(p.write(Address::new(0x1000), &[0u8; 8]).is_err());
    }

    #[test]
    fn find_bytes_in_provider() {
        let mut p = VirtualMemoryProvider::new();
        let mut data = vec![0u8; 64];
        data[32] = 0xDE;
        data[33] = 0xAD;
        data[34] = 0xBE;
        data[35] = 0xEF;
        p.map(
            Address::new(0x1000),
            data,
            Permissions::READ | Permissions::WRITE,
        );
        let found = p.find_bytes(&[0xDE, 0xAD, 0xBE, 0xEF], Address::new(0x1000));
        assert_eq!(found, Some(Address::new(0x1020)));
    }

    #[test]
    fn find_bytes_not_found() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x1000),
            vec![0xAAu8; 64],
            Permissions::READ | Permissions::WRITE,
        );
        let found = p.find_bytes(&[0xBB, 0xCC], Address::new(0x1000));
        assert!(found.is_none());
    }

    #[test]
    fn stats_aggregation() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x1000),
            vec![0u8; 0x1000],
            Permissions::READ | Permissions::EXECUTE,
        );
        p.map(
            Address::new(0x2000),
            vec![0u8; 0x1000],
            Permissions::READ | Permissions::WRITE,
        );
        let stats = p.stats();
        assert_eq!(stats.total_mapped, 0x2000);
        assert_eq!(stats.readable_bytes, 0x2000);
        assert_eq!(stats.executable_bytes, 0x1000);
        assert_eq!(stats.writable_bytes, 0x1000);
    }
}
