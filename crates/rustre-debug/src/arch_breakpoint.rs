//! Architecture-dependent facts about software breakpoint traps.
//!
//! Pure data and arithmetic: no syscalls, no process handles, so it compiles
//! and is testable on every host regardless of the target being debugged.
//!
//! **This module is deliberately not wired into any OS backend.** The three
//! debuggers share a frozen set of methods that implant a one-byte `int3` and
//! rewind the program counter by one; changing them is out of scope here. What
//! is provided is the knowledge those backends need in order to stop being
//! x86-only, in one place, with tests — so the eventual wiring is a lookup
//! rather than a second guess at the constants.

/// Architecture a software breakpoint is being implanted for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BpArch {
    /// x86-64: one-byte `int3`.
    X86_64,
    /// AArch64: four-byte `BRK #0`.
    Arm64,
}

/// `int3`, taken from the single encoder rather than typed again here.
const X86_TRAP: &[u8] = &[crate::ios::arm64::X86_64_INT3];

/// `BRK #0`, DERIVED from the crate's one AArch64 encoder.
///
/// It used to be the literal `[0x00, 0x00, 0x20, 0xD4]`. Correct — and a third
/// independent copy of a fact this crate already holds twice
/// (`ios::arm64::brk_bytes`, and `trap_implant` which derives from it). Three
/// copies of an encoding is how the ARM64 watchpoint control word drifted in
/// iteration 441: the value is right until the day one of them is edited.
/// Deriving costs nothing and removes the possibility.
const ARM64_TRAP: &[u8] = &ARM64_TRAP_BYTES;
const ARM64_TRAP_BYTES: [u8; 4] = crate::ios::arm64::brk_bytes(0);

/// Bytes to write over the instruction at the breakpoint address.
#[must_use]
pub const fn trap_bytes(arch: BpArch) -> &'static [u8] {
    match arch {
        BpArch::X86_64 => X86_TRAP,
        BpArch::Arm64 => ARM64_TRAP,
    }
}

/// How many original bytes must be saved before implanting, and restored after.
///
/// The single most damaging thing a naive port does is save one byte on ARM64:
/// removing the breakpoint would then leave three bytes of `BRK` behind,
/// corrupting the instruction stream permanently.
#[must_use]
pub const fn trap_len(arch: BpArch) -> usize {
    trap_bytes(arch).len()
}

/// Program counter of the trapping instruction, given the PC reported on trap.
///
/// x86 reports the address *after* the executed `int3`, so the breakpoint
/// address is one byte back. AArch64 reports the address *of* the `BRK`, so no
/// adjustment is applied — subtracting there would silently point one
/// instruction earlier and resume execution at the wrong place.
///
/// Saturating on x86 so an implausible `pc == 0` cannot wrap to `u64::MAX`.
#[must_use]
pub const fn pc_after_trap(pc: u64, arch: BpArch) -> u64 {
    match arch {
        BpArch::X86_64 => pc.saturating_sub(1),
        BpArch::Arm64 => pc,
    }
}

/// May a trap be implanted at `addr`?
///
/// AArch64 instructions are four bytes and four-byte aligned: an unaligned
/// implant would straddle two instructions and destroy both. x86 instructions
/// have no alignment requirement.
#[must_use]
pub const fn is_aligned_for_trap(addr: u64, arch: BpArch) -> bool {
    match arch {
        BpArch::X86_64 => true,
        BpArch::Arm64 => addr % 4 == 0,
    }
}

/// The [`BpArch`] this build targets, or `None` on an architecture this crate
/// has no trap encoding for.
///
/// A debugger's LOCAL backends drive processes on this machine through the
/// local kernel interface, so the trap they will find is the one they were
/// compiled for. Remote backends (`ios::AppleDebugger` over RSP) must not use
/// this: they are told the target's architecture by the stub.
///
/// `Option`, with an explicit "anything else" arm, rather than a two-way match
/// that quietly picks a side. This crate has already been bitten three times by
/// a hand-written platform list that forgot an entry and compiled anyway.
#[must_use]
pub const fn host() -> Option<BpArch> {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        Some(BpArch::X86_64)
    }
    #[cfg(target_arch = "aarch64")]
    {
        Some(BpArch::Arm64)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ARM64 trap is `BRK #0`, checked against the encoding rule.
    ///
    /// Written as arithmetic on purpose: a hand-typed constant is exactly how
    /// a wrong register table shipped in an earlier iteration of this crate.
    #[test]
    fn arm64_trap_is_brk_zero_little_endian() {
        let brk0: u32 = 0xD420_0000 | (0u32 << 5);
        assert_eq!(trap_bytes(BpArch::Arm64), brk0.to_le_bytes());
        assert_eq!(trap_bytes(BpArch::Arm64), &[0x00, 0x00, 0x20, 0xD4]);
        assert_eq!(trap_bytes(BpArch::X86_64), &[0xCC]);
    }

    /// Trap width differs, and saving the wrong number of bytes is unrecoverable.
    #[test]
    fn trap_len_is_four_on_arm64_and_one_on_x86() {
        assert_eq!(trap_len(BpArch::X86_64), 1);
        assert_eq!(
            trap_len(BpArch::Arm64),
            4,
            "saving one byte on ARM64 would leave three bytes of BRK behind on removal"
        );
        assert_eq!(trap_len(BpArch::Arm64), trap_bytes(BpArch::Arm64).len());
    }

    /// Only x86 rewinds the PC after a trap.
    #[test]
    fn pc_is_rewound_on_x86_and_left_alone_on_arm64() {
        assert_eq!(pc_after_trap(0x1401_0005, BpArch::X86_64), 0x1401_0004);
        assert_eq!(
            pc_after_trap(0x1401_0004, BpArch::Arm64),
            0x1401_0004,
            "AArch64 reports the address OF the BRK; rewinding would resume one \
             instruction too early"
        );
        // Never wrap.
        assert_eq!(pc_after_trap(0, BpArch::X86_64), 0);
    }

    /// ARM64 implants must be 4-byte aligned; x86 has no such rule.
    #[test]
    fn arm64_traps_must_be_four_byte_aligned() {
        assert!(is_aligned_for_trap(0x1000, BpArch::Arm64));
        assert!(!is_aligned_for_trap(0x1001, BpArch::Arm64));
        assert!(!is_aligned_for_trap(0x1002, BpArch::Arm64));
        assert!(!is_aligned_for_trap(0x1003, BpArch::Arm64));
        assert!(is_aligned_for_trap(0x1004, BpArch::Arm64));
        for a in 0x1000..0x1008u64 {
            assert!(is_aligned_for_trap(a, BpArch::X86_64));
        }
    }

    /// This module and `trap_implant` must state the SAME facts.
    ///
    /// Both describe how to implant a software breakpoint — trap bytes, how
    /// many original bytes to save, the alignment rule, whether the reported
    /// PC sits past the trap — and both are, by their own doc comments,
    /// deliberately unwired. Two unwired tables mean nothing can notice when
    /// they drift, and the first backend to be ported would pick one of them
    /// at random.
    ///
    /// This is a test of AGREEMENT: it does not check either module against
    /// the ARM manual (their own tests do that), it checks that they cannot
    /// answer the same question differently.
    #[test]
    fn the_two_trap_tables_agree_on_every_fact() {
        use crate::register_context::Architecture;
        use crate::trap_implant::for_arch;

        for (bp_arch, ti_arch, name) in [
            (BpArch::X86_64, Architecture::X86_64, "x86-64"),
            (BpArch::Arm64, Architecture::Arm64, "aarch64"),
        ] {
            let spec = for_arch(ti_arch).expect("both modules model this architecture");
            assert_eq!(
                trap_bytes(bp_arch),
                spec.patch(),
                "{name}: the two modules disagree on the trap encoding"
            );
            assert_eq!(
                trap_len(bp_arch),
                spec.read_len(),
                "{name}: they disagree on how many original bytes must be saved — the one
                 defect that cannot be undone, because removal writes back the wrong width"
            );
            // Alignment: `is_aligned_for_trap` and `TrapSpec::align` must
            // accept and reject the same addresses.
            for addr in [0x1000u64, 0x1001, 0x1002, 0x1003, 0x1004, 0x1006] {
                let here = is_aligned_for_trap(addr, bp_arch);
                let there = addr % spec.align() == 0;
                assert_eq!(here, there, "{name}: they disagree on whether {addr:#x} can hold a trap");
            }
            // PC adjustment: a rewind happens exactly when the reported PC is
            // past the trap.
            let pc = 0x1401_0008u64;
            let rewound = pc_after_trap(pc, bp_arch) != pc;
            assert_eq!(
                rewound,
                spec.pc_advances_past_trap(),
                "{name}: one module rewinds the PC after a trap and the other does not"
            );
        }
    }

}
