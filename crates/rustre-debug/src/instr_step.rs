//! Architecture-aware "address of the next instruction" and program-counter
//! naming — the two pieces of arithmetic every single-step / step-over
//! implementation needs, factored out so they cannot be written once per
//! backend against a hardcoded x86-64 assumption.
//!
//! ## Why this module exists
//!
//! The three live backends compute a step-over return address by decoding the
//! instruction at the PC with the x86 length decoder
//! (`rustre_arch_x86::length::instr_length`) and adding its length. That is
//! correct on x86-64 and structurally wrong on AArch64, where **every** A64
//! instruction is exactly 4 bytes and the x86 decoder is reading unrelated
//! bytes. See [`next_pc`]'s tests: feeding `RET` (`0xD65F03C0`) to the x86
//! decoder does not yield 4.
//!
//! This module is the shared, arch-correct primitive. It is compiled on every
//! platform (no `cfg`), so its behaviour is testable everywhere. Wiring it into
//! the backends is deliberately NOT done here: `step_over` is one of the
//! methods frozen by the
//! `the_logic_shared_by_the_three_backends_stays_identical` guard, so the
//! change has to land in all three at once, in a session allowed to touch
//! those files.
//!
//! ## Discipline
//!
//! Neither function guesses. `next_pc` returns `None` when it cannot know the
//! answer — a misaligned AArch64 PC, or an x86 byte sequence the length
//! decoder rejects. In particular there is no `unwrap_or(1)`: silently
//! advancing by one byte past an undecodable instruction places a breakpoint
//! in the middle of a real instruction.

use rustre_arch_x86::length::instr_length;

/// The instruction-set architecture a step is being computed for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StepArch {
    /// x86-64 (AMD64), 64-bit mode. Variable-length instructions.
    X86_64,
    /// 32-bit x86 (IA-32). Variable-length instructions.
    X86,
    /// `AArch64` / ARM64, A64 instruction set. Fixed 4-byte instructions.
    Aarch64,
}

/// Fixed size, in bytes, of every A64 instruction (ARM ARM, C1.1: "A64
/// instructions all have a fixed length of 32 bits"). Mirrors
/// `ios::arm64::INSTRUCTION_SIZE`.
pub const A64_INSTRUCTION_SIZE: u64 = 4;

impl StepArch {
    /// `true` when instructions are a fixed width on this architecture, i.e.
    /// the next PC can be computed without decoding anything.
    #[must_use]
    pub const fn is_fixed_width(self) -> bool {
        matches!(self, Self::Aarch64)
    }

    /// Operand size, in bits, handed to the x86 length decoder — `None` for
    /// architectures that do not use it.
    #[must_use]
    pub const fn x86_bits(self) -> Option<u32> {
        match self {
            Self::X86_64 => Some(64),
            Self::X86 => Some(32),
            Self::Aarch64 => None,
        }
    }
}

/// Address of the instruction following the one at `pc`.
///
/// * `Aarch64` — always `pc + 4`; `bytes` is ignored entirely, because A64
///   instructions are fixed-width. Returns `None` if `pc` is not 4-byte
///   aligned: an unaligned A64 PC is not a valid instruction address at all
///   (the same discipline as `ios::arm64::check_instruction_alignment`), and
///   `pc + 4` from it would name another unaligned address.
/// * `X86_64` / `X86` — decodes `bytes` with the workspace x86 length decoder
///   and returns `pc + len`. Returns `None` when the decoder cannot decode the
///   bytes, or when the addition would overflow the address space.
#[must_use]
pub fn next_pc(arch: StepArch, pc: u64, bytes: &[u8]) -> Option<u64> {
    match arch {
        StepArch::Aarch64 => {
            if !pc.is_multiple_of(A64_INSTRUCTION_SIZE) {
                return None;
            }
            pc.checked_add(A64_INSTRUCTION_SIZE)
        }
        StepArch::X86_64 | StepArch::X86 => {
            let bits = arch.x86_bits()?;
            let len = instr_length(bytes, bits).ok()?;
            // A zero-length decode would make a step-over breakpoint land on
            // the instruction it is meant to step past — an infinite loop.
            if len == 0 {
                return None;
            }
            pc.checked_add(len as u64)
        }
    }
}

/// Name of the program-counter entry in a register map for `arch`.
///
/// Matches the vocabulary the rest of the crate already uses:
/// `cross_platform_debug::ThreadRegisters::PC_NAMES` is `["rip", "pc", "eip"]`,
/// and the ARM64 register schema / minidump CONTEXT decoder both use `"pc"`.
#[must_use]
pub const fn pc_key(arch: StepArch) -> &'static str {
    match arch {
        StepArch::X86_64 => "rip",
        StepArch::X86 => "eip",
        StepArch::Aarch64 => "pc",
    }
}

/// Name of the stack-pointer entry in a register map for `arch`.
#[must_use]
pub const fn sp_key(arch: StepArch) -> &'static str {
    match arch {
        StepArch::X86_64 => "rsp",
        StepArch::X86 => "esp",
        StepArch::Aarch64 => "sp",
    }
}

/// Name of the frame-pointer entry in a register map for `arch`.
///
/// The missing third of the set: `pc_key` and `sp_key` existed, so anything
/// needing the frame pointer by name had to spell it out again.
#[must_use]
pub const fn fp_key(arch: StepArch) -> &'static str {
    match arch {
        StepArch::X86_64 => "rbp",
        StepArch::X86 => "ebp",
        StepArch::Aarch64 => "x29",
    }
}

/// Every architecture this crate can describe registers for.
///
/// Written as an array rather than left implicit so that the
/// architecture-independent predicates below cannot silently forget a variant
/// when one is added: adding a `StepArch` without extending this array is a
/// non-exhaustive-match error at the one place that builds it.
pub const ALL_STEP_ARCHES: [StepArch; 3] = [StepArch::X86_64, StepArch::X86, StepArch::Aarch64];

/// Does `name` denote the program counter on ANY architecture?
///
/// The target's architecture is not always the host's. A debugger driving an
/// arm64 iOS device from an `x86_64` host receives a register map whose program
/// counter is spelled `pc`, and asking `pc_key(native_arch())` there answers
/// `rip` — the host's spelling, about a machine that is not the host. These
/// names do not collide across architectures, so recognising all of them is
/// both sufficient and safer than guessing which one applies.
#[must_use]
pub fn is_pc_name(name: &str) -> bool {
    ALL_STEP_ARCHES.iter().any(|a| name == pc_key(*a))
}

/// Does `name` denote the stack pointer on ANY architecture? See [`is_pc_name`].
#[must_use]
pub fn is_sp_name(name: &str) -> bool {
    ALL_STEP_ARCHES.iter().any(|a| name == sp_key(*a))
}

/// Does `name` denote the frame pointer on ANY architecture? See [`is_pc_name`].
///
/// Includes the `AArch64` role spelling `fp` alongside the architectural `x29`,
/// because both are in live use — the same reason [`is_fp_name`] does.
#[must_use]
pub fn is_fp_name_any(name: &str) -> bool {
    ALL_STEP_ARCHES.iter().any(|a| is_fp_name(*a, name))
}

/// Name of the link register (return address) on `arch`, when it has one.
///
/// `Option`, not a string, because the x86 family genuinely has no link
/// register: the return address lives on the stack. Answering `""` or `"lr"`
/// there would make [`is_ra_name_any`] claim a register the target does not
/// have.
#[must_use]
pub const fn ra_key(arch: StepArch) -> Option<&'static str> {
    match arch {
        StepArch::X86_64 | StepArch::X86 => None,
        StepArch::Aarch64 => Some("x30"),
    }
}

/// Does `name` denote the link register on ANY architecture? See [`is_pc_name`].
///
/// Both `AArch64` spellings, for the same reason [`is_fp_name`] takes both: the
/// role name `lr` and the architectural name `x30` are both in live use in this
/// crate — `apple_debugger`'s `decode` resolves the typed `lr` field through
/// `GenericRole::Ra` while `unwind` reads `get("x30").or_else(get("lr"))`.
#[must_use]
pub fn is_ra_name_any(name: &str) -> bool {
    name == "lr" || ALL_STEP_ARCHES.iter().any(|a| ra_key(*a) == Some(name))
}

/// Does `name` denote the frame pointer on `arch`?
///
/// The frame pointer is the one register this crate names TWO ways, and the two
/// names are both in live use: the macOS backend writes `regs.set("fp", …)` and
/// `regs.set("x29", …)` on the same read, and reads back with
/// `get("x29").or_else(|| get("fp"))`. Matching only [`fp_key`] therefore
/// answered "no" to half the names the crate itself produces — so a caller that
/// wrote the frame pointer as `"fp"` on an `AArch64` build updated the map and
/// left the typed `RegisterSet::fp` untouched, and `backtrace`/`step_out`,
/// which the crate's own comment says read the typed fields, saw no frame
/// pointer at all.
///
/// This deliberately does NOT pick which of the two names is canonical. That
/// question is open and is not this function's to answer: `RegisterSchema`
/// canonicalises `AArch64` frame pointer to `x29` (with `fp` as the alias) while
/// `register_context::arm64_regs` canonicalises it to `fp` (with `x29` as the
/// alias) — two tables in this crate that disagree about the same register.
/// Recognising both names is correct under either resolution.
#[must_use]
pub fn is_fp_name(arch: StepArch, name: &str) -> bool {
    name == fp_key(arch) || (matches!(arch, StepArch::Aarch64) && name == "fp")
}

/// The architecture this build actually runs on.
///
/// Chosen at compile time, so an ARM64 build of the crate (an Apple Silicon
/// Mac, an aarch64 Linux) can never reach the x86 length decoder by accident.
#[must_use]
pub const fn native_arch() -> StepArch {
    #[cfg(target_arch = "aarch64")]
    {
        StepArch::Aarch64
    }
    #[cfg(target_arch = "x86")]
    {
        StepArch::X86
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86")))]
    {
        StepArch::X86_64
    }
}

/// Address a `step_over` must break on to catch the return from a call at
/// `pc`, given the instruction bytes there.
///
/// This is the single entry point the three live backends share, so the arch
/// decision is made once instead of once per backend. `None` means the length
/// is not knowable from `bytes` — the caller must refuse, not guess: the
/// previous `unwrap_or(1)` planted the return breakpoint one byte into the
/// instruction being stepped over.
#[must_use]
pub fn step_over_return_addr(pc: u64, bytes: &[u8]) -> Option<u64> {
    next_pc(native_arch(), pc, bytes)
}

/// Is the instruction at the start of `bytes` a CALL?
///
/// `step_over` needs this and had no way to ask. It decided with
///
///     if after.sp >= before.sp { return Ok(event); }
///
/// i.e. "the stack grew, so it must have been a call". **The stack pointer is
/// not a call detector.** A `push %rbp` lowers it exactly like a `call` does,
/// and so does `sub $N,%rsp` — the two instructions that open every function
/// compiled at `-O0`. Stepping over either one made the backend believe it had
/// entered a call, plant the return breakpoint at an address the program would
/// never reach, and release the process, which then ran to exit:
///
///     step_over over `push %rbp` at 0x401869 ran the fixture to EXIT.
///
/// (measured 2026-08-31, with no breakpoint planted anywhere).
///
/// Note what the old heuristic got right, because it explains why it survived:
/// every call DOES lower the stack. It is the converse that is false, and the
/// converse is what the code relied on.
///
/// Arch-aware for the same reason [`step_over_return_addr`] is: an x86 opcode
/// table applied to A64 words answers about bytes that mean something else
/// entirely. On `AArch64` the calls are `BL` (immediate) and `BLR` (register).
/// `BLRAA`/`BLRAB` (pointer-authenticated calls) are deliberately NOT matched
/// here: they are a distinct encoding and claiming them without a test on
/// hardware that emits them would be a guess, which is the failure this
/// function exists to end.
#[must_use]
pub fn instruction_is_call(bytes: &[u8]) -> bool {
    match native_arch() {
        StepArch::X86_64 | StepArch::X86 => {
            rustre_arch_x86::branch::classify_branch(bytes).is_call()
        }
        StepArch::Aarch64 => {
            let Some(w) = bytes.get(..4) else { return false };
            let word = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
            // BL  imm26 : 100101xx ...
            // BLR Rn    : 1101011000111111000000xxxxx00000
            (word & 0xFC00_0000) == 0x9400_0000 || (word & 0xFFFF_FC1F) == 0xD63F_0000
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The instructions that open every `-O0` function must NOT be mistaken
    /// for calls.
    ///
    /// This is the whole defect in one assertion. `step_over` used to decide
    /// with `after.sp >= before.sp`, and both of these lower the stack exactly
    /// as a `call` does, so both were treated as calls and the process was
    /// released to run to exit.
    ///
    /// The negative half is the half that matters: a detector that answers
    /// "yes" to a real call proves nothing on its own — `is_call` returning
    /// `true` unconditionally would pass that half.
    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    fn the_prologue_is_not_a_call() {
        // push %rbp
        assert!(!instruction_is_call(&[0x55]), "`push %rbp` is not a call");
        // sub $0x10,%rsp
        assert!(
            !instruction_is_call(&[0x48, 0x83, 0xEC, 0x10]),
            "`sub $0x10,%rsp` is not a call"
        );
        // mov %rsp,%rbp — moves nothing onto the stack, must also be no
        assert!(!instruction_is_call(&[0x48, 0x89, 0xE5]), "`mov %rsp,%rbp` is not a call");
        // A jump moves `pc` without touching `sp`; the old heuristic got this
        // one right, so it is kept as a regression witness.
        assert!(!instruction_is_call(&[0xEB, 0x10]), "a short jump is not a call");
        // ret
        assert!(!instruction_is_call(&[0xC3]), "`ret` is not a call");

        // And the positive half, so the detector is not simply "always no".
        assert!(
            instruction_is_call(&[0xE8, 0x00, 0x00, 0x00, 0x00]),
            "`call rel32` IS a call"
        );
        assert!(
            instruction_is_call(&[0xFF, 0xD0]),
            "`call *%rax` IS a call"
        );

        // Empty input must not panic and must not claim a call.
        assert!(!instruction_is_call(&[]), "no bytes is not a call");
    }

    // ── The wiring this module used to lack ─────────────────────────────────

    /// The three live backends must compute their step-over return address
    /// through [`step_over_return_addr`], not by calling the x86 length decoder
    /// themselves with `unwrap_or(1)`.
    ///
    /// Both halves matter and neither is cosmetic:
    /// * the decoder call is *structurally* wrong on an ARM64 build — it
    ///   measures A64 bytes as if they were x86, giving a different wrong
    ///   length per instruction (see the test below), which on an Apple Silicon
    ///   Mac makes every `step_over` past a call plant its breakpoint inside
    ///   the following instruction;
    /// * `unwrap_or(1)` is the fabricated answer this module's own doc comment
    ///   forbids: an undecodable instruction became "one byte long", and the
    ///   return breakpoint landed in the middle of the call being stepped over.
    ///
    /// A guard rather than a live test because the defect only *fires* on a
    /// platform this host cannot execute — exactly where a silent defect
    /// survives longest.
    #[test]
    fn the_three_backends_route_step_over_through_the_arch_correct_primitive() {
        // `include_str!`, not `fs::read_to_string` — the source is embedded at
        // COMPILE time, not looked up at run time.
        //
        // It used to read `"src/windows_debugger.rs"` and friends from disk by
        // relative path, which works only when the test binary happens to run
        // with the crate root as its working directory. It does not on the iOS
        // Simulator, where `simctl spawn` runs the binary in its own sandbox
        // with no repository anywhere near it:
        //
        //   cannot read src/windows_debugger.rs: No such file or directory
        //
        // Measured on the macos-14 runner, 2026-08-15, the first time this
        // crate'''s suite was executed for an Apple triple. Every other guard in
        // this crate already embeds its input; this one was the exception.
        for (file, src) in [
            ("src/windows_debugger.rs", include_str!("windows_debugger.rs")),
            ("src/linux_debugger.rs", include_str!("linux_debugger.rs")),
            ("src/macos_debugger.rs", include_str!("macos_debugger.rs")),
        ] {
            assert!(
                src.contains("instr_step::step_over_return_addr(before.pc, &bytes)"),
                "{file} does not compute its step-over return address through \
                 instr_step::step_over_return_addr, so it is back to assuming x86"
            );
            assert!(
                !src.contains("instr_length(&bytes, 64).unwrap_or(1)"),
                "{file} still decodes the step-over instruction as x86-64 and \
                 falls back to a fabricated length of 1"
            );
        }
    }

    /// The native primitive is the native arch — no silent third behaviour.
    #[test]
    fn step_over_return_addr_is_next_pc_for_the_arch_this_build_targets() {
        let bytes = [0x90u8, 0, 0, 0]; // x86 NOP; ignored on a fixed-width ISA.
        assert_eq!(
            step_over_return_addr(0x1000, &bytes),
            next_pc(native_arch(), 0x1000, &bytes)
        );
        // And the arch is the one the compiler is building for.
        #[cfg(target_arch = "aarch64")]
        assert_eq!(native_arch(), StepArch::Aarch64);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(native_arch(), StepArch::X86_64);
    }

    // ── AArch64: fixed width ────────────────────────────────────────────────

    /// Two A64 instructions with completely different encodings must both
    /// advance the PC by exactly 4 — that is the whole point of a fixed-width
    /// ISA, and the property the x86 path cannot provide.
    #[test]
    fn arm64_next_pc_is_always_four_bytes_regardless_of_the_encoding() {
        // RET (x30) and NOP — unrelated encodings, identical length.
        assert_eq!(
            next_pc(StepArch::Aarch64, 0x1000, &0xD65F_03C0u32.to_le_bytes()),
            Some(0x1004)
        );
        assert_eq!(
            next_pc(StepArch::Aarch64, 0x1000, &0xD503_201Fu32.to_le_bytes()),
            Some(0x1004)
        );
        // …and the bytes are genuinely ignored: no bytes at all works too.
        assert_eq!(next_pc(StepArch::Aarch64, 0x1000, &[]), Some(0x1004));
    }

    #[test]
    fn arm64_next_pc_refuses_a_misaligned_pc() {
        for bad in [0x1001u64, 0x1002, 0x1003] {
            assert_eq!(
                next_pc(StepArch::Aarch64, bad, &[0; 4]),
                None,
                "pc {bad:#x} is not 4-byte aligned"
            );
        }
        assert_eq!(next_pc(StepArch::Aarch64, 0x1004, &[0; 4]), Some(0x1008));
    }

    #[test]
    fn arm64_next_pc_does_not_wrap_at_the_top_of_the_address_space() {
        assert_eq!(next_pc(StepArch::Aarch64, u64::MAX - 3, &[]), None);
    }

    // ── The defect this module documents ────────────────────────────────────

    /// Numeric proof that reusing the x86 length decoder on A64 bytes is
    /// wrong. If this ever asserted 4, the shared `step_over` implementation
    /// would be accidentally correct on ARM64 and this module unnecessary.
    ///
    /// Measured (2026-08-04, `rustre_arch_x86::length::instr_length(.., 64)`):
    /// A64 `RET` (`D6 5F 03 C0`, little-endian bytes `C0 03 5F D6`) decodes as
    /// `Ok(3)`, and A64 `NOP` (`1F 20 03 D5`) as `Ok(1)`. Not merely wrong —
    /// wrong by a *different* amount per instruction, so no constant fixup
    /// exists. A step-over using either length plants its breakpoint inside
    /// the following instruction.
    #[test]
    fn the_x86_decoder_would_have_produced_a_wrong_length_for_a64_bytes() {
        let a64_ret = 0xD65F_03C0u32.to_le_bytes();
        let x86_says = instr_length(&a64_ret, 64);
        assert_ne!(
            x86_says.as_ref().copied().ok(),
            Some(4),
            "x86 decoder on A64 RET returned {x86_says:?}, which would make the \
             shared step-over path accidentally right"
        );
        // And this module gets it right for the same bytes.
        assert_eq!(next_pc(StepArch::Aarch64, 0x2000, &a64_ret), Some(0x2004));
    }

    // ── x86: still decodes, and still refuses to guess ──────────────────────

    #[test]
    fn x86_64_next_pc_uses_the_real_decoded_length() {
        // NOP (1 byte), RET (1 byte), PUSH imm8 (2 bytes), JMP rel8 (2 bytes).
        assert_eq!(next_pc(StepArch::X86_64, 0x400, &[0x90]), Some(0x401));
        assert_eq!(next_pc(StepArch::X86_64, 0x400, &[0xC3]), Some(0x401));
        assert_eq!(next_pc(StepArch::X86_64, 0x400, &[0x6A, 0x04]), Some(0x402));
        assert_eq!(next_pc(StepArch::X86_64, 0x400, &[0xEB, 0x10]), Some(0x402));
        // Unlike AArch64, an odd address is perfectly legal on x86.
        assert_eq!(next_pc(StepArch::X86_64, 0x401, &[0x90]), Some(0x402));
    }

    #[test]
    fn x86_next_pc_returns_none_instead_of_guessing_one_byte() {
        // Truncated: a prefix byte with nothing after it cannot be decoded.
        assert_eq!(next_pc(StepArch::X86_64, 0x400, &[]), None);
        assert_eq!(next_pc(StepArch::X86_64, 0x400, &[0x0F]), None);
    }

    // ── Register naming ─────────────────────────────────────────────────────

    #[test]
    fn pc_key_never_invents_an_x86_name_for_arm64() {
        assert_eq!(pc_key(StepArch::Aarch64), "pc");
        assert_eq!(pc_key(StepArch::X86_64), "rip");
        assert_eq!(pc_key(StepArch::X86), "eip");
        assert_eq!(sp_key(StepArch::Aarch64), "sp");
        assert_eq!(sp_key(StepArch::X86_64), "rsp");
        assert_eq!(sp_key(StepArch::X86), "esp");
    }

    /// The names produced here must be resolvable in the corresponding
    /// register schema — otherwise a backend using them would silently miss.
    #[test]
    fn the_keys_resolve_in_the_matching_register_schema() {
        let a = crate::RegisterSchema::aarch64();
        assert!(a.get(pc_key(StepArch::Aarch64)).is_some());
        assert!(a.get(sp_key(StepArch::Aarch64)).is_some());
        let x = crate::RegisterSchema::x86_64();
        assert!(x.get(pc_key(StepArch::X86_64)).is_some());
        assert!(x.get(sp_key(StepArch::X86_64)).is_some());
        // Cross-check: the ARM names are not x86 names and vice versa.
        assert!(x.get(pc_key(StepArch::Aarch64)).is_none());
        assert!(a.get(pc_key(StepArch::X86_64)).is_none());
    }

    #[test]
    fn fixed_width_flag_matches_the_arch() {
        assert!(StepArch::Aarch64.is_fixed_width());
        assert!(!StepArch::X86_64.is_fixed_width());
        assert_eq!(StepArch::X86_64.x86_bits(), Some(64));
        assert_eq!(StepArch::X86.x86_bits(), Some(32));
        assert_eq!(StepArch::Aarch64.x86_bits(), None);
    }
}
