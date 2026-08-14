//! Bridge to the [`rustre_mem`] crate.
//!
//! `rustre-emu` defines its own thin `MemRegion`/`MemPerms` types for the
//! `Emulator` trait, but real workloads — fuzzing replay, snapshot diffing,
//! patched / composite / virtual memory views — need the richer provider
//! model from `rustre-mem`. This module re-exports that model under the
//! `Emu*` prefix so emulator clients can build layered memory views without
//! taking a direct dep on `rustre-mem`.
//!
//! The primary public exports of `rustre-mem` are:
//! * [`MemoryProvider`] — the core trait every backing store implements.
//! * [`VirtualMemoryProvider`] — synthetic / reconstructed in-memory store.
//! * [`CompositeMemoryProvider`] — priority-ordered overlay of providers.
//!
//! These three cover the read/write/regions surface the emulator needs to
//! initialise from disassembled images, layered patches, and process dumps.

pub use rustre_mem::memory_provider::MemoryProvider as EmuMemoryProvider;
pub use rustre_mem::virtual_memory::VirtualMemoryProvider as EmuVirtualMemoryProvider;
pub use rustre_mem::composite_memory::CompositeMemoryProvider as EmuCompositeMemoryProvider;

/// Static description of a wired backing-memory provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemProviderDescriptor {
    /// Short identifier (e.g. `"virtual"`).
    pub name: &'static str,
    /// Originating crate.
    pub crate_name: &'static str,
    /// Fully qualified primary type.
    pub primary_type: &'static str,
}

/// All memory providers wired into the emu hub.
pub const ALL: &[MemProviderDescriptor] = &[
    MemProviderDescriptor {
        name: "virtual",
        crate_name: "rustre-mem",
        primary_type: "rustre_mem::virtual_memory::VirtualMemoryProvider",
    },
    MemProviderDescriptor {
        name: "composite",
        crate_name: "rustre-mem",
        primary_type: "rustre_mem::composite_memory::CompositeMemoryProvider",
    },
];

/// Construct a fresh empty virtual memory provider — the default backing
/// store for newly created emulator sessions.
#[must_use]
pub fn new_virtual() -> EmuVirtualMemoryProvider {
    EmuVirtualMemoryProvider::new()
}

/// Construct a fresh empty composite memory provider for layering multiple
/// backing stores (image, patches, fuzz overlay) under a single view.
#[must_use]
pub fn new_composite() -> EmuCompositeMemoryProvider {
    EmuCompositeMemoryProvider::new()
}

/// Look up a memory-provider descriptor by its short name.
#[must_use]
pub fn find(name: &str) -> Option<&'static MemProviderDescriptor> {
    ALL.iter().find(|d| d.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptors_contain_virtual_and_composite() {
        assert!(find("virtual").is_some());
        assert!(find("composite").is_some());
    }

    #[test]
    fn new_virtual_returns_empty_provider() {
        let p = new_virtual();
        // Just ensure the constructor is wired; behaviour is covered in rustre-mem tests.
        let _ = p;
    }

    #[test]
    fn new_composite_returns_empty_provider() {
        let p = new_composite();
        let _ = p;
    }
}
