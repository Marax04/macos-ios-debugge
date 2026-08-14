//! Architecture-aware software-breakpoint implant primitives.
//!
//! Every OS backend in this crate implants a software breakpoint by writing the
//! literal x86 byte `0xCC` (`int3`). That is correct on x86/x86-64 and *silently
//! catastrophic* on AArch64, where it overwrites one quarter of a 4-byte
//! instruction: the target does not trap, it executes corrupted code with no
//! error reported anywhere (iter 332).
//!
//! This module holds the arch-dependent facts a correct implant needs — the
//! patch bytes, the alignment rule, and whether the trap advances the PC — as
//! pure functions over [`Architecture`]. There is no I/O, no `Debugger`, no
//! `cfg`: it compiles and is tested on every host, which is exactly the property
//! the three backends lack.
//!
//! It is deliberately **not yet wired into the backends**. `set_breakpoint` and
//! friends are inside the frozen set guarded by
//! `the_logic_shared_by_the_three_backends_stays_identical`, so switching them
//! over is a single atomic change across all three files plus the type of their
//! `breakpoints` map. This module is the shared infrastructure that change will
//! stand on; see the module tests for the round-trip contract it must honour.

use crate::ios::arm64;
use crate::register_context::Architecture;

/// The AArch64 `BRK #0` encoding, little-endian, derived from the already-tested
/// [`arm64::brk_bytes`] rather than re-spelled as a magic constant.
const BRK0_BYTES: [u8; 4] = arm64::brk_bytes(0);

/// The x86 `int3` patch, one byte.
const INT3_BYTES: [u8; 1] = [arm64::X86_64_INT3];

/// The largest patch any supported architecture needs.
pub const MAX_PATCH_LEN: usize = 4;

/// What it takes to implant a software breakpoint on one architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrapSpec {
    patch: &'static [u8],
    align: u64,
    pc_advances_past_trap: bool,
}

impl TrapSpec {
    /// The bytes to write at the breakpoint address.
    #[must_use]
    pub const fn patch(&self) -> &'static [u8] {
        self.patch
    }

    /// How many bytes must be saved and restored.
    #[must_use]
    pub const fn read_len(&self) -> usize {
        self.patch.len()
    }

    /// Required address alignment (1 on x86, 4 on A64).
    #[must_use]
    pub const fn align(&self) -> u64 {
        self.align
    }

    /// Does the PC point *past* the trap when the target reports the stop?
    ///
    /// True on x86/x86-64 (`int3` is a trap, the saved RIP is the byte after
    /// it). False on AArch64: `BRK` is a fault, ELR_EL1 holds the address *of*
    /// the `BRK` itself.
    #[must_use]
    pub const fn pc_advances_past_trap(&self) -> bool {
        self.pc_advances_past_trap
    }
}

/// The trap specification for `arch`, or `None` when this crate cannot implant
/// a breakpoint there.
///
/// Only the architectures the crate can actually service are listed. ARM32 and
/// RISC-V have well-known trap encodings, but committing an unused constant
/// table is precisely the mistake iter 342 punished (seven of eight CodeView
/// AMD64 registers were wrong and nothing noticed, because nothing read them).
#[must_use]
pub const fn for_arch(arch: Architecture) -> Option<TrapSpec> {
    match arch {
        Architecture::X86_64 | Architecture::X86 => Some(TrapSpec {
            patch: &INT3_BYTES,
            align: 1,
            pc_advances_past_trap: true,
        }),
        Architecture::Arm64 => Some(TrapSpec {
            patch: &BRK0_BYTES,
            align: arm64::INSTRUCTION_SIZE,
            pc_advances_past_trap: false,
        }),
        _ => None,
    }
}

/// The architecture this binary was compiled for, when it is one the crate
/// models.
///
/// Backends should gate on this instead of on `cfg(target_os = ...)`: the
/// defect of iter 332 was exactly an OS check standing in for an arch check.
#[must_use]
pub const fn host_arch() -> Option<Architecture> {
    if cfg!(target_arch = "x86_64") {
        Some(Architecture::X86_64)
    } else if cfg!(target_arch = "x86") {
        Some(Architecture::X86)
    } else if cfg!(target_arch = "aarch64") {
        Some(Architecture::Arm64)
    } else if cfg!(target_arch = "arm") {
        Some(Architecture::Arm32)
    } else if cfg!(target_arch = "riscv64") {
        Some(Architecture::Riscv64)
    } else {
        None
    }
}

/// Why an implant cannot be planned or completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrapError {
    /// No trap encoding is modelled for this architecture.
    UnsupportedArch(Architecture),
    /// The address cannot hold an instruction on this architecture.
    Misaligned { addr: u64, align: u64 },
    /// The bytes read back do not match the length the plan asked for.
    ShortRead { expected: usize, got: usize },
}

impl core::fmt::Display for TrapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedArch(a) => {
                write!(f, "no software-breakpoint encoding is known for {a}")
            }
            Self::Misaligned { addr, align } => write!(
                f,
                "breakpoint address {addr:#x} is not {align}-byte aligned; it does not \
                 start an instruction"
            ),
            Self::ShortRead { expected, got } => write!(
                f,
                "saved {got} original byte(s) but the implant patches {expected}"
            ),
        }
    }
}

impl std::error::Error for TrapError {}

/// A validated implant: what to read, what to write, where.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImplantPlan {
    arch: Architecture,
    addr: u64,
    spec: TrapSpec,
}

impl ImplantPlan {
    /// Target architecture.
    #[must_use]
    pub const fn arch(&self) -> Architecture {
        self.arch
    }
    /// Breakpoint address.
    #[must_use]
    pub const fn addr(&self) -> u64 {
        self.addr
    }
    /// Bytes to save before patching — and to write back on removal.
    #[must_use]
    pub const fn read_len(&self) -> usize {
        self.spec.read_len()
    }
    /// Bytes to write at [`Self::addr`].
    #[must_use]
    pub const fn patch(&self) -> &'static [u8] {
        self.spec.patch()
    }
    /// The full specification.
    #[must_use]
    pub const fn spec(&self) -> TrapSpec {
        self.spec
    }
}

/// Plan an implant of `arch`'s trap instruction at `addr`.
///
/// # Errors
/// [`TrapError::UnsupportedArch`] if the architecture has no modelled trap;
/// [`TrapError::Misaligned`] if `addr` cannot start an instruction there.
pub fn plan_implant(arch: Architecture, addr: u64) -> Result<ImplantPlan, TrapError> {
    let spec = for_arch(arch).ok_or(TrapError::UnsupportedArch(arch))?;
    if matches!(arch, Architecture::Arm64) {
        // Delegate to the already-tested rule rather than keeping a second copy
        // of "must be a multiple of 4" that can drift out of step with it.
        arm64::check_instruction_alignment(addr).map_err(|_| TrapError::Misaligned {
            addr,
            align: spec.align,
        })?;
    }
    Ok(ImplantPlan { arch, addr, spec })
}

/// The original bytes displaced by an implant.
///
/// Fixed-size and `Copy` on purpose: a backend's `HashMap<u64, u8>` becomes
/// `HashMap<u64, SavedCode>` with no allocation and no `Vec` per breakpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SavedCode {
    bytes: [u8; MAX_PATCH_LEN],
    len: u8,
}

impl SavedCode {
    /// The saved bytes, exactly as read from the target.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// How many bytes were saved.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Is this an empty save? (Never true for a value produced by [`save`].)
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Record the bytes `read_back` from the target before patching.
///
/// # Errors
/// [`TrapError::ShortRead`] when `read_back` is not exactly
/// [`ImplantPlan::read_len`] long — so a backend that reads one byte and
/// believes it plants four cannot build a valid round-trip.
pub fn save(plan: &ImplantPlan, read_back: &[u8]) -> Result<SavedCode, TrapError> {
    let expected = plan.read_len();
    if read_back.len() != expected {
        return Err(TrapError::ShortRead {
            expected,
            got: read_back.len(),
        });
    }
    let mut bytes = [0u8; MAX_PATCH_LEN];
    bytes[..expected].copy_from_slice(read_back);
    Ok(SavedCode {
        bytes,
        len: expected as u8,
    })
}

/// The bytes to write back to undo an implant.
#[must_use]
pub fn restore_bytes(saved: &SavedCode) -> &[u8] {
    saved.bytes()
}

/// Do these bytes already hold this architecture's trap instruction?
///
/// Used to keep `set_breakpoint` idempotent: without it a second call at the
/// same address reads back the trap it planted itself and records *that* as the
/// "original" code, permanently corrupting the target on removal.
#[must_use]
pub fn is_already_trapped(arch: Architecture, bytes: &[u8]) -> bool {
    match arch {
        Architecture::X86_64 | Architecture::X86 => {
            bytes.first() == Some(&arm64::X86_64_INT3)
        }
        Architecture::Arm64 => arm64::word_from_le(bytes).is_some_and(arm64::is_brk),
        _ => false,
    }
}

/// Map a reported stop PC back to the breakpoint address.
///
/// `pc - 1` on x86/x86-64, because `int3` is a trap and the saved RIP points
/// past it; `pc` unchanged on AArch64, because `BRK` is a fault and the saved
/// PC is the address of the `BRK` itself.
///
/// **Honesty note:** this function has no callers today, and it is not fixing a
/// live bug. `linux_debugger.rs` rewinds with `rip.wrapping_sub(1)`, which is
/// unconditional — but that file cannot compile on aarch64 at all (it reads
/// `regs.rip` of `libc::user_regs_struct`, a field that does not exist there),
/// so the wrong rewind is unreachable rather than latent. This is the correct
/// primitive for the port that will make those files compile on AArch64; it
/// should not be presented as a defect fix.
#[must_use]
pub const fn trap_pc_to_breakpoint_addr(arch: Architecture, pc: u64) -> u64 {
    match for_arch(arch) {
        Some(spec) if spec.pc_advances_past_trap => pc.wrapping_sub(spec.patch.len() as u64),
        _ => pc,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Passo 1: the table agrees with the module that is already tested ─────

    #[test]
    fn arm64_patch_is_the_brk_zero_the_arm64_module_encodes() {
        let spec = for_arch(Architecture::Arm64).expect("arm64 must be supported");
        assert_eq!(
            spec.patch(),
            &arm64::brk_bytes(0),
            "the trap table must not re-spell the BRK encoding by hand"
        );
        let word = arm64::word_from_le(spec.patch()).expect("4 bytes");
        assert_eq!(
            arm64::decode_brk(word),
            Some(0),
            "the patch must decode as BRK #0 through the already-tested decoder"
        );
        assert_eq!(spec.read_len(), 4);
        assert_eq!(spec.align(), 4);
        assert!(!spec.pc_advances_past_trap(), "BRK does not advance the PC");
    }

    #[test]
    fn x86_patch_is_the_single_int3_byte() {
        for arch in [Architecture::X86_64, Architecture::X86] {
            let spec = for_arch(arch).expect("x86 must be supported");
            assert_eq!(spec.patch(), &[0xCC], "{arch}");
            assert_eq!(spec.read_len(), 1, "{arch}");
            assert_eq!(spec.align(), 1, "{arch}");
            assert!(spec.pc_advances_past_trap(), "{arch}: int3 traps past itself");
        }
    }

    #[test]
    fn the_build_host_can_always_plant_a_breakpoint() {
        let host = host_arch().expect("host architecture must be modelled");
        assert!(
            for_arch(host).is_some(),
            "{host}: the crate would refuse to plant a breakpoint on its own build host"
        );
    }

    #[test]
    fn unmodelled_architectures_are_refused_rather_than_guessed() {
        for arch in [
            Architecture::Arm32,
            Architecture::Mips32,
            Architecture::Mips64,
            Architecture::Riscv32,
            Architecture::Riscv64,
        ] {
            assert_eq!(for_arch(arch), None, "{arch} has no verified trap encoding");
        }
    }

    // ── Passo 2: planning and alignment ─────────────────────────────────────

    #[test]
    fn arm64_refuses_an_address_that_cannot_start_an_instruction() {
        for bad in [0x1001u64, 0x1002, 0x1003] {
            assert_eq!(
                plan_implant(Architecture::Arm64, bad),
                Err(TrapError::Misaligned {
                    addr: bad,
                    align: 4
                }),
                "{bad:#x}"
            );
        }
        let plan = plan_implant(Architecture::Arm64, 0x1000).expect("aligned");
        assert_eq!(plan.read_len(), 4);
        assert_eq!(plan.addr(), 0x1000);
    }

    #[test]
    fn x86_has_no_alignment_constraint() {
        let plan = plan_implant(Architecture::X86_64, 0x1001).expect("x86 is byte-addressed");
        assert_eq!(plan.read_len(), 1);
        assert_eq!(plan.patch(), &[0xCC]);
    }

    #[test]
    fn planning_for_an_unmodelled_arch_is_an_error_not_a_default() {
        assert_eq!(
            plan_implant(Architecture::Mips64, 0x1000),
            Err(TrapError::UnsupportedArch(Architecture::Mips64))
        );
    }

    // ── Passo 3: the round-trip that is the whole point ─────────────────────

    /// The property the backends get wrong: an implant must disturb exactly the
    /// bytes of the instruction it replaces, and restore must be byte-exact.
    fn round_trip(arch: Architecture, offset: usize) {
        const ORIGINAL: [u8; 8] = [11, 22, 33, 44, 55, 66, 77, 88];
        let mut buf = ORIGINAL;

        let plan = plan_implant(arch, offset as u64).expect("planned");
        let n = plan.read_len();

        let saved = save(&plan, &buf[offset..offset + n]).expect("saved");
        assert_eq!(saved.bytes(), &ORIGINAL[offset..offset + n]);

        buf[offset..offset + n].copy_from_slice(plan.patch());

        assert!(
            is_already_trapped(arch, &buf[offset..]),
            "{arch}: the planted patch must be recognised as a trap"
        );
        assert_eq!(
            &buf[..offset],
            &ORIGINAL[..offset],
            "{arch}: bytes before the breakpoint must be untouched"
        );
        assert_eq!(
            &buf[offset + n..],
            &ORIGINAL[offset + n..],
            "{arch}: bytes after the breakpoint must be untouched"
        );

        buf[offset..offset + n].copy_from_slice(restore_bytes(&saved));
        assert_eq!(buf, ORIGINAL, "{arch}: restore must be byte-exact");
    }

    #[test]
    fn x86_implant_touches_exactly_one_byte_and_restores() {
        round_trip(Architecture::X86_64, 2);
    }

    #[test]
    fn arm64_implant_touches_exactly_four_bytes_and_restores() {
        round_trip(Architecture::Arm64, 4);
    }

    #[test]
    fn saving_the_wrong_number_of_bytes_is_refused() {
        let plan = plan_implant(Architecture::Arm64, 0x2000).unwrap();
        // A backend that reads one byte and believes it plants four.
        assert_eq!(
            save(&plan, &[0xAA]),
            Err(TrapError::ShortRead {
                expected: 4,
                got: 1
            })
        );
        assert_eq!(
            save(&plan, &[0xAA; 5]),
            Err(TrapError::ShortRead {
                expected: 4,
                got: 5
            })
        );
    }

    #[test]
    fn untrapped_code_is_not_mistaken_for_a_breakpoint() {
        assert!(!is_already_trapped(Architecture::X86_64, &[0x90]));
        // `ret` on A64 — a real instruction, not a BRK.
        assert!(!is_already_trapped(
            Architecture::Arm64,
            &0xD65F_03C0u32.to_le_bytes()
        ));
        // A one-byte read on arm64 cannot decide anything, and must not say yes.
        assert!(!is_already_trapped(Architecture::Arm64, &[0x00]));
        // An x86 int3 byte is NOT an arm64 breakpoint — the iter-332 defect.
        assert!(!is_already_trapped(Architecture::Arm64, &[0xCC; 4]));
    }

    // ── Passo 4: PC rewind ──────────────────────────────────────────────────

    #[test]
    fn stop_pc_maps_back_to_the_breakpoint_address() {
        assert_eq!(
            trap_pc_to_breakpoint_addr(Architecture::X86_64, 0x1001),
            0x1000
        );
        assert_eq!(trap_pc_to_breakpoint_addr(Architecture::X86, 0x1001), 0x1000);
        assert_eq!(
            trap_pc_to_breakpoint_addr(Architecture::Arm64, 0x1000),
            0x1000,
            "BRK is a fault: the reported PC already IS the breakpoint address"
        );
        assert_eq!(
            trap_pc_to_breakpoint_addr(Architecture::Arm64, 0x1004),
            0x1004
        );
        // No modelled trap → no rewind invented.
        assert_eq!(
            trap_pc_to_breakpoint_addr(Architecture::Mips64, 0x1004),
            0x1004
        );
    }
}
