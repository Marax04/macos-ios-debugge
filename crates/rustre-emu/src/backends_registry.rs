//! Aggregated registry of all emulator back-end sub-crates wired into the
//! `rustre-emu` hub.
//!
//! Each entry exposes the sub-crate's primary user-facing emulator type via a
//! re-export plus a [`BackendDescriptor`] record so callers can enumerate the
//! available back-ends at runtime without depending on every sub-crate
//! individually.

// Sub-crate re-exports are gated out: the corresponding crates are not
// part of the current workspace build. Descriptors below stay as
// metadata so callers can still enumerate by name.

/// Static description of a wired emulator back-end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendDescriptor {
    /// Short identifier (e.g. `"qiling"`).
    pub name: &'static str,
    /// Originating sub-crate (e.g. `"rustre-emu-qiling"`).
    pub crate_name: &'static str,
    /// Fully qualified primary type exposed by the sub-crate.
    pub primary_type: &'static str,
}

/// All emulator back-ends wired into the hub.
pub const ALL: &[BackendDescriptor] = &[
    BackendDescriptor {
        name: "qiling",
        crate_name: "rustre-emu-qiling",
        primary_type: "rustre_emu_qiling::QilingEmulator",
    },
    BackendDescriptor {
        name: "shellcode",
        crate_name: "rustre-emu-shellcode",
        primary_type: "rustre_emu_shellcode::ShellcodeRunner",
    },
    BackendDescriptor {
        name: "unicorn",
        crate_name: "rustre-emu-unicorn",
        primary_type: "rustre_emu_unicorn::UnicornEmu",
    },
];

/// Enumerate all wired back-end descriptors.
#[must_use]
pub const fn all() -> &'static [BackendDescriptor] {
    ALL
}

/// Look up a back-end descriptor by its short name.
#[must_use]
pub fn find(name: &str) -> Option<&'static BackendDescriptor> {
    ALL.iter().find(|b| b.name == name)
}
