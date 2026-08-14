//! Pure Mach-O image-size arithmetic, extracted from `macos_debugger.rs`.
//!
//! # Why this is its own module
//!
//! `macos_debugger.rs` is `#![cfg(target_os = "macos")]`, so *everything* in
//! it — including its `#[cfg(test)] mod tests` — is invisible on a non-macOS
//! host. Those tests were never compiled, never run, and never could fail.
//! This module has **no** `cfg` gate: it is compiled and its tests execute on
//! Windows and Linux, which is the only way the segment-summing arithmetic
//! gets real coverage in this environment.
//!
//! It is deliberately host-independent: it operates on an in-memory byte
//! slice (a Mach-O header + its load commands), never on a live task. The
//! live-process side (`mach_o_image_size_at`, which needs `task_t` and Mach
//! VM reads) stays in `macos_debugger.rs`.
//!
//! # Why `Result`, not `Option`
//!
//! The original returned `Option<u64>` and the caller did `.unwrap_or(0)`,
//! so a bad magic, a truncated buffer, and a genuinely empty image all
//! collapsed into the same silent `0` — and `walk_dyld_images` then reported
//! a module with `size: 0` with no trace of *why*. Distinct error variants
//! let the caller log which failure actually happened.

/// Why a Mach-O header + load-command buffer could not be summed.
///
/// Variants are distinct on purpose: a corrupt magic (we are not looking at
/// a Mach-O at all) and a short read (we are, but did not get all of it) call
/// for different diagnoses, and the previous `Option` return made them
/// indistinguishable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachoSizeError {
    /// The buffer is smaller than a `mach_header_64` (32 bytes), so not even
    /// the magic and `sizeofcmds` fields could be read.
    TooShort {
        /// Bytes actually available.
        len: usize,
    },
    /// The first four bytes are not `MH_MAGIC_64`. Carries what was found so
    /// a caller can tell a 32-bit / fat / byte-swapped image from garbage.
    BadMagic {
        /// The little-endian `u32` read at offset 0.
        found: u32,
    },
    /// The header claims `sizeofcmds` bytes of load commands but the buffer
    /// ends before them — a short/partial read, not a malformed image.
    TruncatedLoadCommands {
        /// Bytes the header says the load commands occupy.
        expected: usize,
        /// Bytes actually available after the 32-byte header.
        available: usize,
    },
    /// The header parsed cleanly but contributed no mappable footprint: no
    /// `LC_SEGMENT_64` at all, or only `__PAGEZERO` (which is excluded — it
    /// is an unmapped reservation, not real image size). Reported instead of
    /// `Ok(0)` because a zero total is otherwise indistinguishable from a
    /// failed read at the call site.
    NoSegments,
}

impl std::fmt::Display for MachoSizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { len } => {
                write!(f, "buffer of {len} bytes is shorter than mach_header_64 ({MACH_HEADER_64_SIZE})")
            }
            Self::BadMagic { found } => write!(f, "not MH_MAGIC_64: found {found:#010x}"),
            Self::TruncatedLoadCommands {
                expected,
                available,
            } => write!(
                f,
                "load commands truncated: header claims {expected} bytes, {available} available"
            ),
            Self::NoSegments => {
                write!(f, "no mappable LC_SEGMENT_64 (empty, or __PAGEZERO only)")
            }
        }
    }
}

impl std::error::Error for MachoSizeError {}

/// `mach_header_64` size in bytes: magic/cputype/cpusubtype/filetype/ncmds/
/// sizeofcmds/flags/reserved, all `u32` — 8 fields × 4 bytes.
pub(crate) const MACH_HEADER_64_SIZE: usize = 32;
/// 64-bit Mach-O magic, little-endian host order.
pub(crate) const MH_MAGIC_64: u32 = 0xfeed_facf;
/// `LC_SEGMENT_64` load-command tag.
pub(crate) const LC_SEGMENT_64: u32 = 0x19;

/// Sum the `vmsize` of every `LC_SEGMENT_64` load command in a Mach-O
/// header + load-command byte buffer, skipping `__PAGEZERO` (a huge
/// unmapped reservation, not real image footprint).
///
/// Never reads past `MACH_HEADER_64_SIZE + sizeofcmds`, even for a header
/// whose `ncmds` is wildly larger than the load commands actually present:
/// the loop bails the moment a command would cross that boundary.
/// Size of a `segment_command_64` carrying zero sections — the smallest one
/// that can exist. Each `section_64` adds a further 80 bytes.
const SEGMENT_COMMAND_64_MIN_SIZE: usize = 72;

pub(crate) fn parse_mach_o_segments_total_size(buf: &[u8]) -> Result<u64, MachoSizeError> {
    if buf.len() < MACH_HEADER_64_SIZE {
        return Err(MachoSizeError::TooShort { len: buf.len() });
    }
    // Every indexing below is bounds-checked by the two length guards, so the
    // `try_into` conversions cannot fail; `unwrap_or_default` keeps the
    // function total without an `unwrap`.
    let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap_or_default());
    if magic != MH_MAGIC_64 {
        return Err(MachoSizeError::BadMagic { found: magic });
    }
    let ncmds = u32::from_le_bytes(buf[16..20].try_into().unwrap_or_default()) as usize;
    let sizeofcmds = u32::from_le_bytes(buf[20..24].try_into().unwrap_or_default()) as usize;

    let cmds_end =
        MACH_HEADER_64_SIZE
            .checked_add(sizeofcmds)
            .ok_or(MachoSizeError::TruncatedLoadCommands {
                expected: sizeofcmds,
                available: buf.len().saturating_sub(MACH_HEADER_64_SIZE),
            })?;
    if buf.len() < cmds_end {
        return Err(MachoSizeError::TruncatedLoadCommands {
            expected: sizeofcmds,
            available: buf.len().saturating_sub(MACH_HEADER_64_SIZE),
        });
    }
    let mut total = 0u64;
    let mut counted_segments = 0usize;
    let mut offset = MACH_HEADER_64_SIZE;
    for _ in 0..ncmds {
        if offset + 8 > cmds_end {
            break;
        }
        let cmd = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap_or_default());
        let cmdsize =
            u32::from_le_bytes(buf[offset + 4..offset + 8].try_into().unwrap_or_default()) as usize;
        if cmdsize < 8 || offset + cmdsize > cmds_end {
            break;
        }
        if cmd == LC_SEGMENT_64 {
            // segment_command_64: cmd/cmdsize (8) + segname[16] (8..24) +
            // vmaddr(8) (24..32) + vmsize(8) (32..40) + ... — vmsize is the
            // SECOND u64 after segname, not the first (that's vmaddr).
            // `cmdsize` is checked as well as `cmds_end`, for the same reason
            // the LC_MAIN arm of `parse_mach_o_entry_offset` is (iteration
            // 517): a command declaring less than it needs would have its
            // fields read out of the NEXT command. Here that does not merely
            // return a wrong number, it ADDS one to the image size, so the
            // total stays plausible and no caller can tell. A
            // `segment_command_64` is 72 bytes even with zero sections, so
            // anything shorter is malformed by definition — not just short of
            // the 40 bytes this code happens to read.
            if SEGMENT_COMMAND_64_MIN_SIZE <= cmdsize
                && offset + 40 <= cmds_end
                && let Ok(segname_bytes) = buf[offset + 8..offset + 24].try_into()
            {
                let segname_bytes: [u8; 16] = segname_bytes;
                // Compare all 16 bytes, NUL padding included. `segname` is a
                // fixed-width, NUL-padded field, so a 10-byte prefix test
                // also matched any LONGER segment name that merely starts
                // with "__PAGEZERO" — e.g. a "__PAGEZERO_2" segment would be
                // mistaken for the unmapped reservation and its vmsize
                // silently dropped from the image total.
                let is_pagezero = segname_bytes == *b"__PAGEZERO\0\0\0\0\0\0";
                if !is_pagezero
                    && let Ok(vmsize_bytes) = buf[offset + 32..offset + 40].try_into()
                {
                    total = total.saturating_add(u64::from_le_bytes(vmsize_bytes));
                    counted_segments += 1;
                }
            }
        }
        offset += cmdsize;
    }
    if counted_segments == 0 {
        return Err(MachoSizeError::NoSegments);
    }
    Ok(total)
}

/// `LC_MAIN` — carries `entryoff`, the entry point as a file offset from the
/// image's base. The high bit (`LC_REQ_DYLD`) is part of the tag itself.
pub(crate) const LC_MAIN: u32 = 0x8000_0028;
/// `LC_UNIXTHREAD` — the pre-10.8 entry-point form, carrying a full initial
/// thread state instead of an offset. Still emitted for `dyld` itself and for
/// static executables, so both forms have to be handled.
pub(crate) const LC_UNIXTHREAD: u32 = 0x5;
/// `x86_THREAD_STATE64` flavour tag inside an `LC_UNIXTHREAD` command.
const X86_THREAD_STATE64_FLAVOUR: u32 = 4;
/// Index of `rip` within `x86_thread_state64_t`, counted in `u64` slots:
/// rax, rbx, rcx, rdx, rdi, rsi, rbp, rsp, r8..r15 (16 slots), then rip.
const X86_THREAD_STATE64_RIP_SLOT: usize = 16;
/// `ARM_THREAD_STATE64` flavour tag inside an `LC_UNIXTHREAD` command.
///
/// Only the x86 flavour was handled, so on Apple Silicon every image carrying
/// the pre-10.8 entry-point form — `dyld` itself and static executables —
/// answered `None`, leaving `ModuleInfo::entry_point` empty on exactly the
/// platform this function was written to fix. Same shape as the ARM64 crash
/// address missing from `minidump_analysis` (iteration 465): a feature that
/// works, and silently answers nothing, on one architecture.
const ARM_THREAD_STATE64_FLAVOUR: u32 = 6;
/// Index of `pc` within `arm_thread_state64_t`, counted in `u64` slots:
/// `__x[29]` occupies slots 0..=28, then `fp` (29), `lr` (30), `sp` (31) and
/// `pc` (32).
const ARM_THREAD_STATE64_PC_SLOT: usize = 32;

/// `CPU_TYPE_X86_64` — `CPU_TYPE_X86 (7) | CPU_ARCH_ABI64 (0x0100_0000)`.
pub(crate) const CPU_TYPE_X86_64: u32 = 0x0100_0007;
/// `CPU_TYPE_ARM64` — `CPU_TYPE_ARM (12) | CPU_ARCH_ABI64 (0x0100_0000)`.
pub(crate) const CPU_TYPE_ARM64: u32 = 0x0100_000c;

/// Where the program counter sits, in `u64` slots, inside the thread state
/// identified by (`cputype`, `flavour`) — or `None` if that pair is not a
/// general-purpose 64-bit thread state this module models.
///
/// A flavour tag is meaningless on its own: the numbers are per-architecture
/// and they COLLIDE. 6 is `ARM_THREAD_STATE64` on arm64 but
/// `x86_EXCEPTION_STATE64` on x86_64; 4 is `x86_THREAD_STATE64` on x86_64 but
/// `ARM_DEBUG_STATE` on arm64. Reading a fixed slot out of the wrong layout
/// does not fail visibly — it returns whatever register or fault address lies
/// at that offset, as a confident entry point no caller can tell from a real
/// one. That is exactly the failure the unmodelled-flavour arm below exists to
/// prevent, so the flavours that DO collide must be resolved by `cputype` too.
///
/// An architecture this module does not model yields `None` for the same
/// reason an unmodelled flavour does: no guess is better than no answer.
fn thread_state_pc_slot(cputype: u32, flavour: u32) -> Option<usize> {
    match (cputype, flavour) {
        (CPU_TYPE_X86_64, X86_THREAD_STATE64_FLAVOUR) => Some(X86_THREAD_STATE64_RIP_SLOT),
        (CPU_TYPE_ARM64, ARM_THREAD_STATE64_FLAVOUR) => Some(ARM_THREAD_STATE64_PC_SLOT),
        _ => None,
    }
}

/// Extract an image's entry point (as an offset from its base) from a Mach-O
/// header + load-command buffer.
///
/// macOS was the only backend leaving `ModuleInfo::entry_point` as `None` —
/// Windows fills it from the PE optional header, Linux from the ELF header —
/// so on macOS "where does this module start executing?" had no answer at all,
/// even though the load commands carrying it were already being parsed one
/// function away for the image size.
///
/// Returns `None`, never a guess, when neither `LC_MAIN` nor a usable
/// `LC_UNIXTHREAD` is present, or when the buffer is truncated: a wrong entry
/// point is worse than no entry point, since a caller cannot tell it is wrong.
///
/// The two forms differ in kind, not just encoding:
/// * `LC_MAIN.entryoff` is an OFFSET from the image base — the caller adds the
///   base.
/// * `LC_UNIXTHREAD` carries an absolute `rip` in its thread state. It is
///   returned relative to `image_base` so both forms hand back the same thing;
///   an `rip` below the base (a malformed or foreign-slid image) yields `None`
///   rather than a wrapped offset. The command holds a *sequence* of
///   `(flavour, count, state)` triples, each walked via its own `count`, and
///   the flavour is resolved against the header's `cputype` — the tags collide
///   between architectures.
pub(crate) fn parse_mach_o_entry_offset(buf: &[u8], image_base: u64) -> Option<u64> {
    if buf.len() < MACH_HEADER_64_SIZE {
        return None;
    }
    if u32::from_le_bytes(buf[0..4].try_into().ok()?) != MH_MAGIC_64 {
        return None;
    }
    // Needed before any thread state can be read: a flavour tag only names a
    // layout together with the architecture it belongs to (see
    // `thread_state_pc_slot`).
    let cputype = u32::from_le_bytes(buf[4..8].try_into().ok()?);
    let ncmds = u32::from_le_bytes(buf[16..20].try_into().ok()?) as usize;
    let sizeofcmds = u32::from_le_bytes(buf[20..24].try_into().ok()?) as usize;
    let cmds_end = MACH_HEADER_64_SIZE.checked_add(sizeofcmds)?;
    if buf.len() < cmds_end {
        return None;
    }

    let mut offset = MACH_HEADER_64_SIZE;
    for _ in 0..ncmds {
        if offset + 8 > cmds_end {
            break;
        }
        let cmd = u32::from_le_bytes(buf[offset..offset + 4].try_into().ok()?);
        let cmdsize = u32::from_le_bytes(buf[offset + 4..offset + 8].try_into().ok()?) as usize;
        if cmdsize < 8 || offset + cmdsize > cmds_end {
            break;
        }
        match cmd {
            // entry_point_command: cmd/cmdsize (8) + entryoff u64 (8..16) +
            // stacksize u64 (16..24).
            // `cmdsize` is checked as well as `cmds_end`: a malformed LC_MAIN
            // declaring a cmdsize too small to hold its own `entryoff` would
            // otherwise read the first 8 bytes of the NEXT load command and
            // hand them back as an entry point. The LC_UNIXTHREAD arm below
            // already bounded its read by `offset + cmdsize`; this one did not,
            // so the same buffer was trusted to two different extents in two
            // arms of one match.
            LC_MAIN if offset + 16 <= cmds_end && 16 <= cmdsize => {
                return Some(u64::from_le_bytes(buf[offset + 8..offset + 16].try_into().ok()?));
            }
            // thread_command: cmd/cmdsize (8), then a SEQUENCE of
            // `(flavour u32, count u32, state[count] u32)` triples filling the
            // rest of the command — not one triple. `dyld` and static
            // executables really do emit a float or exception state ahead of
            // the general-purpose one, and only the first was ever inspected,
            // so those images reported no entry point at all while the state
            // carrying it sat a few bytes further on.
            //
            // `count` is the field that makes the walk possible, and it was
            // never read: it says both where the next triple begins and how
            // far THIS state legitimately extends. Bounding the pc read by
            // `cmdsize` alone (the whole command) let a state too short to
            // contain its own pc have that slot read out of a LATER triple's
            // registers — a wrong answer indistinguishable from a right one.
            LC_UNIXTHREAD => {
                let cmd_end = offset + cmdsize;
                let mut pair = offset + 8;
                while pair + 8 <= cmd_end {
                    let flavour = u32::from_le_bytes(buf[pair..pair + 4].try_into().ok()?);
                    let count =
                        u32::from_le_bytes(buf[pair + 4..pair + 8].try_into().ok()?) as usize;
                    let state = pair + 8;
                    // A `count` whose state would run past the command is
                    // malformed: stop rather than read the next command's
                    // bytes as registers.
                    let Some(state_end) = count.checked_mul(4).and_then(|n| state.checked_add(n))
                    else {
                        break;
                    };
                    if state_end > cmd_end {
                        break;
                    }
                    if let Some(slot) = thread_state_pc_slot(cputype, flavour) {
                        let pc_end = slot
                            .checked_mul(8)
                            .and_then(|o| state.checked_add(o))
                            .and_then(|at| at.checked_add(8));
                        // Only within this state's OWN `count` words. A
                        // truncated state is skipped, not read past — a later
                        // triple may still carry the real thread state.
                        if let Some(pc_end) = pc_end
                            && pc_end <= state_end
                            && let Ok(pc_bytes) = buf[pc_end - 8..pc_end].try_into()
                        {
                            return u64::from_le_bytes(pc_bytes).checked_sub(image_base);
                        }
                    }
                    // `state_end >= pair + 8`, so the walk always advances and
                    // a `count` of 0 cannot spin.
                    pair = state_end;
                }
            }
            _ => {}
        }
        offset += cmdsize;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `segment_command_64` with zero sections, byte-for-byte per Apple's
    /// published layout.
    fn segment_cmd(name: &str, vmaddr: u64, vmsize: u64) -> Vec<u8> {
        let mut segname = [0u8; 16];
        let name_bytes = name.as_bytes();
        segname[..name_bytes.len()].copy_from_slice(name_bytes);
        let mut buf = Vec::new();
        buf.extend_from_slice(&LC_SEGMENT_64.to_le_bytes()); // cmd
        buf.extend_from_slice(&72u32.to_le_bytes()); // cmdsize (0 sections)
        buf.extend_from_slice(&segname);
        buf.extend_from_slice(&vmaddr.to_le_bytes());
        buf.extend_from_slice(&vmsize.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes()); // fileoff
        buf.extend_from_slice(&vmsize.to_le_bytes()); // filesize
        buf.extend_from_slice(&0u32.to_le_bytes()); // maxprot
        buf.extend_from_slice(&0u32.to_le_bytes()); // initprot
        buf.extend_from_slice(&0u32.to_le_bytes()); // nsects
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        assert_eq!(buf.len(), 72, "segment_command_64 with 0 sections is 72 bytes");
        buf
    }

    /// Assemble a `mach_header_64` followed by `cmds`, with an overridable
    /// `ncmds` so hostile headers can be built. Defaults to an `x86_64`
    /// `cputype`: a thread-state flavour has no meaning without one (flavour
    /// 6 is `ARM_THREAD_STATE64` on arm64 and `x86_EXCEPTION_STATE64` on
    /// x86_64), so a header claiming no architecture cannot carry a readable
    /// `LC_UNIXTHREAD` entry point.
    fn header_with(ncmds: u32, cmds: &[u8]) -> Vec<u8> {
        header_with_cpu(CPU_TYPE_X86_64, ncmds, cmds)
    }

    /// `header_with`, with the `cputype` field spelled out.
    fn header_with_cpu(cputype: u32, ncmds: u32, cmds: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&MH_MAGIC_64.to_le_bytes()); // magic
        buf.extend_from_slice(&cputype.to_le_bytes()); // cputype
        buf.extend_from_slice(&0u32.to_le_bytes()); // cpusubtype
        buf.extend_from_slice(&0u32.to_le_bytes()); // filetype
        buf.extend_from_slice(&ncmds.to_le_bytes()); // ncmds
        buf.extend_from_slice(&(cmds.len() as u32).to_le_bytes()); // sizeofcmds
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
        assert_eq!(buf.len(), MACH_HEADER_64_SIZE);
        buf.extend_from_slice(cmds);
        buf
    }

    #[test]
    fn parse_mach_o_segments_sums_real_segments_and_skips_pagezero() {
        let mut cmds = segment_cmd("__PAGEZERO", 0, 0x1_0000_0000);
        cmds.extend_from_slice(&segment_cmd("__TEXT", 0x1_0000_0000, 0x4000));
        cmds.extend_from_slice(&segment_cmd("__DATA", 0x1_0000_4000, 0x1000));
        let buf = header_with(3, &cmds);

        let total =
            parse_mach_o_segments_total_size(&buf).expect("should parse a well-formed header");
        assert_eq!(
            total,
            0x4000 + 0x1000,
            "should sum __TEXT+__DATA, excluding the __PAGEZERO reservation"
        );
    }

    #[test]
    fn parse_mach_o_segments_rejects_bad_magic() {
        let mut buf = vec![0u8; MACH_HEADER_64_SIZE];
        buf[0..4].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        assert!(parse_mach_o_segments_total_size(&buf).is_err());
    }

    #[test]
    fn parse_mach_o_segments_rejects_truncated_buffer() {
        assert!(parse_mach_o_segments_total_size(&[0u8; 10]).is_err());
    }

    /// The defect the `Option` signature made unfixable: a wrong-magic buffer
    /// and a too-short buffer both returned `None`, so no caller could ever
    /// tell "this is not a Mach-O" from "I did not read enough bytes".
    #[test]
    fn bad_magic_is_distinguishable_from_truncation() {
        let mut bad_magic = vec![0u8; 40];
        bad_magic[0..4].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        let short = vec![0u8; 10];

        let e_magic = parse_mach_o_segments_total_size(&bad_magic).unwrap_err();
        let e_short = parse_mach_o_segments_total_size(&short).unwrap_err();

        assert_eq!(e_magic, MachoSizeError::BadMagic { found: 0xdead_beef });
        assert_eq!(e_short, MachoSizeError::TooShort { len: 10 });
        assert_ne!(
            e_magic, e_short,
            "the two failures must be distinguishable — that is the whole point of Result here"
        );
    }

    /// A header carrying only `__PAGEZERO` sums to 0 because `__PAGEZERO` is
    /// excluded by design. Returning `Ok(0)` would be indistinguishable from
    /// a read failure once the caller applies `unwrap_or(0)`, so it must be
    /// an explicit `NoSegments`.
    #[test]
    fn image_with_only_pagezero_is_an_error_not_zero() {
        let cmds = segment_cmd("__PAGEZERO", 0, 0x1_0000_0000);
        let buf = header_with(1, &cmds);
        assert_eq!(
            parse_mach_o_segments_total_size(&buf).unwrap_err(),
            MachoSizeError::NoSegments
        );
    }

    /// A header with no load commands at all is also `NoSegments`, not 0.
    #[test]
    fn header_with_no_load_commands_is_no_segments() {
        let buf = header_with(0, &[]);
        assert_eq!(
            parse_mach_o_segments_total_size(&buf).unwrap_err(),
            MachoSizeError::NoSegments
        );
    }

    /// A header whose `sizeofcmds` promises more bytes than were read is a
    /// truncation, reported as such rather than silently summing what is
    /// there (which would under-report the image size as if it were real).
    #[test]
    fn sizeofcmds_beyond_the_buffer_is_truncation() {
        let cmds = segment_cmd("__TEXT", 0x1000, 0x4000);
        let mut buf = header_with(1, &cmds);
        // Claim twice as many load-command bytes as are present.
        let lying = (cmds.len() as u32) * 2;
        buf[20..24].copy_from_slice(&lying.to_le_bytes());
        assert_eq!(
            parse_mach_o_segments_total_size(&buf).unwrap_err(),
            MachoSizeError::TruncatedLoadCommands {
                expected: lying as usize,
                available: cmds.len(),
            }
        );
    }

    /// Property (fuzz-lite): for ~200 deterministically generated hostile
    /// headers — absurd `ncmds`, zero/huge/misaligned `cmdsize`, truncated
    /// tails — the parser must neither panic nor read past `cmds_end`.
    /// Any out-of-bounds index would panic in safe Rust, so "no panic over
    /// the whole grid" IS the no-over-read proof.
    #[test]
    fn ncmds_larger_than_sizeofcmds_does_not_over_read() {
        let mut checked = 0usize;
        for ncmds in [0u32, 1, 2, 7, 255, 4096, u32::MAX] {
            for cmdsize in [0u32, 1, 7, 8, 16, 72, 71, 73, 0xFFFF, u32::MAX] {
                for tail_trim in [0usize, 1, 8, 40, 71] {
                    let mut cmds = segment_cmd("__TEXT", 0x1000, 0x4000);
                    // Overwrite the cmdsize field with the hostile value.
                    cmds[4..8].copy_from_slice(&cmdsize.to_le_bytes());
                    let mut buf = header_with(ncmds, &cmds);
                    // Trim the tail WITHOUT touching sizeofcmds, so most of
                    // these are also truncation cases.
                    let keep = buf.len().saturating_sub(tail_trim);
                    buf.truncate(keep);
                    // Must return, never panic. Value is unconstrained; the
                    // property under test is termination + memory safety.
                    let _ = parse_mach_o_segments_total_size(&buf);
                    checked += 1;
                }
            }
        }
        assert!(checked >= 200, "expected a meaningful grid, ran {checked}");
    }

    /// `__PAGEZERO` must be matched on the FULL 16-byte, NUL-padded `segname`
    /// field, not on a 10-byte prefix.
    ///
    /// A prefix test treats any longer segment whose name merely *begins*
    /// with "__PAGEZERO" as the unmapped reservation and drops its `vmsize`
    /// from the image total. This test pairs the two cases that a prefix
    /// comparison cannot tell apart:
    ///   - real `__PAGEZERO` -> still excluded (no regression on the
    ///     behaviour the exclusion exists for), and
    ///   - `__PAGEZERO_2`    -> a distinct, genuinely mapped segment whose
    ///     size must be counted.
    ///
    /// Fails before the fix: the second header sums to 0x4000 (the
    /// `__PAGEZERO_2` segment silently swallowed) and, because it is then
    /// the only counted segment that remains, the parser reports only
    /// `__TEXT`.
    #[test]
    fn pagezero_is_matched_on_the_full_16_byte_segname() {
        // Baseline: the genuine __PAGEZERO is excluded.
        let mut cmds = segment_cmd("__PAGEZERO", 0, 0x1_0000_0000);
        cmds.extend_from_slice(&segment_cmd("__TEXT", 0x1_0000_0000, 0x4000));
        let buf = header_with(2, &cmds);
        assert_eq!(
            parse_mach_o_segments_total_size(&buf).unwrap(),
            0x4000,
            "the real __PAGEZERO must stay excluded"
        );

        // A different segment that merely shares the first 10 bytes is NOT
        // __PAGEZERO and must be counted.
        let mut cmds = segment_cmd("__PAGEZERO_2", 0x2_0000_0000, 0x9000);
        cmds.extend_from_slice(&segment_cmd("__TEXT", 0x1_0000_0000, 0x4000));
        let buf = header_with(2, &cmds);
        assert_eq!(
            parse_mach_o_segments_total_size(&buf).unwrap(),
            0x4000 + 0x9000,
            "__PAGEZERO_2 is a distinct mapped segment; only an exact 16-byte \
             match may exclude a segment from the image size"
        );
    }
    /// `entry_point_command` (`LC_MAIN`), 24 bytes.
    fn lc_main(entryoff: u64) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&LC_MAIN.to_le_bytes());
        b.extend_from_slice(&24u32.to_le_bytes());
        b.extend_from_slice(&entryoff.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes()); // stacksize
        b
    }

    /// `LC_UNIXTHREAD` carrying an `x86_THREAD_STATE64` with `rip` set.
    fn lc_unixthread(rip: u64) -> Vec<u8> {
        // 21 u64 registers = 42 u32 words, per x86_thread_state64_t.
        let words = 42u32;
        let cmdsize = 16 + (words as usize) * 4;
        let mut b = Vec::new();
        b.extend_from_slice(&LC_UNIXTHREAD.to_le_bytes());
        b.extend_from_slice(&(cmdsize as u32).to_le_bytes());
        b.extend_from_slice(&4u32.to_le_bytes()); // flavour x86_THREAD_STATE64
        b.extend_from_slice(&words.to_le_bytes());
        let mut state = vec![0u64; 21];
        state[16] = rip; // rip is the 17th u64 slot
        for w in state {
            b.extend_from_slice(&w.to_le_bytes());
        }
        assert_eq!(b.len(), cmdsize);
        b
    }

    /// The same rule as the LC_MAIN test below, on the size path — where the
    /// consequence is worse.
    ///
    /// A truncated `LC_SEGMENT_64` had its `segname` and `vmsize` read out of
    /// the FOLLOWING command. That does not just return a wrong number: it
    /// ADDS a phantom segment to the image total, which stays plausible and
    /// which no caller can distinguish from a real one. The size constants
    /// are fixed by the format: 72 bytes with zero sections, +80 per section.
    #[test]
    fn a_segment_command_shorter_than_the_format_allows_adds_no_phantom_size() {
        // Truncated LC_SEGMENT_64 (cmdsize 8) followed by one real 0x9000
        // segment. The bytes the short command would have read as `vmsize`
        // are part of the real segment's header, so the bad total is not
        // merely large — it looks like an ordinary image size.
        let mut cmds = Vec::new();
        cmds.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
        cmds.extend_from_slice(&8u32.to_le_bytes());
        cmds.extend_from_slice(&segment_cmd("__TEXT", 0x1000, 0x9000));

        let buf = header_with(2, &cmds);
        assert_eq!(
            parse_mach_o_segments_total_size(&buf).unwrap(),
            0x9000,
            "only the well-formed segment may contribute to the image size"
        );

        // 40 bytes is what the code happens to READ; 72 is what the format
        // requires. A command between the two is still malformed and must not
        // be counted, or the guard would only be as strict as the current
        // implementation rather than as strict as the format.
        let mut cmds = Vec::new();
        cmds.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
        cmds.extend_from_slice(&48u32.to_le_bytes());
        cmds.extend_from_slice(&[0u8; 40]);
        cmds.extend_from_slice(&segment_cmd("__DATA", 0x1000, 0x4000));
        let buf = header_with(2, &cmds);
        assert_eq!(parse_mach_o_segments_total_size(&buf).unwrap(), 0x4000);
    }

    /// A load command may not be trusted past its own declared `cmdsize`.
    ///
    /// `LC_MAIN` is 24 bytes by definition. One declaring less than 16 cannot
    /// contain its own `entryoff`, so the bytes at that position belong to the
    /// NEXT command — reading them yields a confident, wrong entry point that
    /// no caller can tell from a real one. `LC_UNIXTHREAD` already bounded its
    /// read by `offset + cmdsize`; this asserts `LC_MAIN` does too.
    #[test]
    fn an_lc_main_shorter_than_its_own_payload_is_not_read_past_its_end() {
        // A truncated LC_MAIN (cmdsize 8, no room for entryoff) followed by a
        // real LC_MAIN. The bytes right after the short command are the next
        // command's cmd+cmdsize word — 0x8000_0028 | (24 << 32) — which the
        // unbounded read would have returned as the entry point.
        let mut cmds = Vec::new();
        cmds.extend_from_slice(&LC_MAIN.to_le_bytes());
        cmds.extend_from_slice(&8u32.to_le_bytes()); // too small to hold entryoff
        let poisoned = u64::from(LC_MAIN) | (24u64 << 32);
        cmds.extend_from_slice(&lc_main(0x3f10));

        let buf = header_with(2, &cmds);
        let got = parse_mach_o_entry_offset(&buf, 0x1_0000_0000);
        assert_ne!(
            got,
            Some(poisoned),
            "the short LC_MAIN's `entryoff` was read out of the following command"
        );
        assert_eq!(
            got,
            Some(0x3f10),
            "the truncated command is skipped and the well-formed one answers"
        );
    }

    #[test]
    fn lc_main_yields_the_entry_offset_and_lc_unixthread_yields_rip_minus_base() {
        // macOS was the ONLY backend leaving ModuleInfo::entry_point as None.
        // The two encodings mean different things and both must land on the
        // same answer: an offset from the image base.
        let buf = header_with(1, &lc_main(0x3f10));
        assert_eq!(parse_mach_o_entry_offset(&buf, 0x1_0000_0000), Some(0x3f10));

        // LC_UNIXTHREAD's rip is ABSOLUTE, so the base must be subtracted.
        let buf = header_with(1, &lc_unixthread(0x1_0000_3f10));
        assert_eq!(parse_mach_o_entry_offset(&buf, 0x1_0000_0000), Some(0x3f10));

        // An entry point BELOW the image base cannot be an offset into it:
        // None, not a wrapped u64 near the top of the address space.
        let buf = header_with(1, &lc_unixthread(0x1000));
        assert_eq!(parse_mach_o_entry_offset(&buf, 0x1_0000_0000), None);
    }

    #[test]
    fn an_entry_point_command_is_found_after_other_load_commands() {
        // Real images put __PAGEZERO/__TEXT first; the scan must walk past
        // them via cmdsize rather than only inspecting the first command.
        let mut cmds = segment_cmd("__PAGEZERO", 0, 0x1_0000_0000);
        cmds.extend_from_slice(&segment_cmd("__TEXT", 0x1_0000_0000, 0x4000));
        cmds.extend_from_slice(&lc_main(0x1234));
        let buf = header_with(3, &cmds);
        assert_eq!(parse_mach_o_entry_offset(&buf, 0x1_0000_0000), Some(0x1234));
    }

    #[test]
    fn an_image_with_no_entry_point_command_reports_none_rather_than_zero() {
        // A dylib has no entry point at all. `Some(0)` would read as "entry
        // at the image base", a plausible-looking lie; None says nothing.
        let cmds = segment_cmd("__TEXT", 0x1_0000_0000, 0x4000);
        let buf = header_with(1, &cmds);
        assert_eq!(parse_mach_o_entry_offset(&buf, 0x1_0000_0000), None);

        // Truncated / non-Mach-O buffers are also None, never a guess.
        assert_eq!(parse_mach_o_entry_offset(&[0u8; 8], 0), None);
        assert_eq!(parse_mach_o_entry_offset(&[0u8; 64], 0), None);
    }

    /// `LC_UNIXTHREAD` carrying an `ARM_THREAD_STATE64` with `pc` set.
    ///
    /// Layout: `__x[29]` (slots 0..=28), `fp` (29), `lr` (30), `sp` (31),
    /// `pc` (32), then `cpsr` + `pad` as two u32 words.
    fn lc_unixthread_arm64(pc: u64) -> Vec<u8> {
        let words = 68u32; // 33 u64 registers = 66 u32 words, + cpsr + pad
        let cmdsize = 16 + (words as usize) * 4;
        let mut b = Vec::new();
        b.extend_from_slice(&LC_UNIXTHREAD.to_le_bytes());
        b.extend_from_slice(&(cmdsize as u32).to_le_bytes());
        b.extend_from_slice(&6u32.to_le_bytes()); // flavour ARM_THREAD_STATE64
        b.extend_from_slice(&words.to_le_bytes());
        let mut state = vec![0u64; 33];
        state[32] = pc;
        for w in state {
            b.extend_from_slice(&w.to_le_bytes());
        }
        b.extend_from_slice(&0u32.to_le_bytes()); // cpsr
        b.extend_from_slice(&0u32.to_le_bytes()); // pad
        assert_eq!(b.len(), cmdsize);
        b
    }

    /// On Apple Silicon the pre-10.8 entry-point form carries an ARM thread
    /// state, and only the x86 flavour was handled.
    ///
    /// So `dyld` itself and every static executable answered `None`, leaving
    /// `ModuleInfo::entry_point` empty on exactly the platform this function
    /// exists to serve — the same shape as the ARM64 crash address missing
    /// from the minidump reader in iteration 465.
    #[test]
    fn an_arm64_thread_state_yields_its_pc_relative_to_the_image_base() {
        // An ARM thread state lives in an arm64 image: the flavour tag alone
        // does not identify it (6 is x86_EXCEPTION_STATE64 on x86_64).
        let buf = header_with_cpu(CPU_TYPE_ARM64, 1, &lc_unixthread_arm64(0x1_0000_3f10));
        assert_eq!(parse_mach_o_entry_offset(&buf, 0x1_0000_0000), Some(0x3f10));

        // Below the base is not an offset into the image: None, never a
        // wrapped value near the top of the address space.
        let buf = header_with_cpu(CPU_TYPE_ARM64, 1, &lc_unixthread_arm64(0x1000));
        assert_eq!(parse_mach_o_entry_offset(&buf, 0x1_0000_0000), None);

        // The x86 form still works: this is an addition, not a swap.
        let buf = header_with(1, &lc_unixthread(0x1_0000_2222));
        assert_eq!(parse_mach_o_entry_offset(&buf, 0x1_0000_0000), Some(0x2222));
    }

    /// Spell a `u64` register file out as the `u32` words a thread state is
    /// actually counted in — `count` is a word count, not a register count.
    fn state_words(slots: &[u64]) -> Vec<u32> {
        let mut words = Vec::with_capacity(slots.len() * 2);
        for s in slots {
            words.push(*s as u32);
            words.push((*s >> 32) as u32);
        }
        words
    }

    /// A `thread_command` carrying an ARBITRARY SEQUENCE of
    /// `(flavour, count, state[count])` triples — which is what the format
    /// permits, and what `dyld` and static executables actually emit. The
    /// single-pair `lc_unixthread` helpers above are the degenerate case.
    fn lc_unixthread_pairs(pairs: &[(u32, Vec<u32>)]) -> Vec<u8> {
        let mut payload = Vec::new();
        for (flavour, words) in pairs {
            payload.extend_from_slice(&flavour.to_le_bytes());
            payload.extend_from_slice(&(words.len() as u32).to_le_bytes());
            for w in words {
                payload.extend_from_slice(&w.to_le_bytes());
            }
        }
        let mut b = Vec::new();
        b.extend_from_slice(&LC_UNIXTHREAD.to_le_bytes());
        b.extend_from_slice(&((8 + payload.len()) as u32).to_le_bytes());
        b.extend_from_slice(&payload);
        b
    }

    /// A `thread_command` holds a SEQUENCE of `(flavour, count, state)`
    /// triples, not one.
    ///
    /// Only the first was ever examined, so an image whose thread command
    /// opens with any other state — `x86_FLOAT_STATE64` here, which real
    /// linkers do emit ahead of the general-purpose state — reported no entry
    /// point at all, even though the general-purpose state sat right behind
    /// it. The `count` field, which is the only way to find where the next
    /// triple starts, was never read.
    #[test]
    fn a_thread_command_is_scanned_past_its_first_flavour_count_pair() {
        let mut rip_state = vec![0u64; 21];
        rip_state[16] = 0x1_0000_3f10;
        let cmd = lc_unixthread_pairs(&[
            // x86_FLOAT_STATE64 = 5: present, unmodelled, and NOT the end of
            // the command.
            (5, state_words(&vec![0u64; 8])),
            (X86_THREAD_STATE64_FLAVOUR, state_words(&rip_state)),
        ]);
        let buf = header_with_cpu(CPU_TYPE_X86_64, 1, &cmd);
        assert_eq!(
            parse_mach_o_entry_offset(&buf, 0x1_0000_0000),
            Some(0x3f10),
            "the general-purpose state is the SECOND triple; stopping at the \
             first one loses the entry point of every image that emits a \
             float state ahead of it"
        );
    }

    /// `count` bounds a thread state; `cmdsize` does not.
    ///
    /// The read was bounded only by `offset + cmdsize`, i.e. by the whole
    /// command, so a flavour whose `count` is too small to reach `rip` had
    /// that slot read out of a LATER triple's registers. The value comes back
    /// as a confident entry point that no caller can tell from a real one —
    /// here `0xdead`, which lives in the second triple's `r13`.
    #[test]
    fn a_state_shorter_than_its_own_pc_slot_is_not_read_past_its_count() {
        let mut real = vec![0u64; 21];
        real[16] = 0x1_0000_3f10; // the true rip
        // Byte offset 16 + 16*8 = 144 from the command start — what the
        // unbounded read takes as `rip` — lands on slot 11 of this state.
        real[11] = 0x1_0000_dead;
        let cmd = lc_unixthread_pairs(&[
            // Claims x86_THREAD_STATE64 but carries only 8 words: malformed,
            // and far too short to contain rip at slot 16.
            (X86_THREAD_STATE64_FLAVOUR, vec![0u32; 8]),
            (X86_THREAD_STATE64_FLAVOUR, state_words(&real)),
        ]);
        let buf = header_with_cpu(CPU_TYPE_X86_64, 1, &cmd);
        assert_eq!(
            parse_mach_o_entry_offset(&buf, 0x1_0000_0000),
            Some(0x3f10),
            "a state's pc may only be read within its own `count` words"
        );
    }

    /// A flavour number means nothing without the header's `cputype`.
    ///
    /// 6 is `ARM_THREAD_STATE64` on arm64 and `x86_EXCEPTION_STATE64` on
    /// x86_64; 4 is `x86_THREAD_STATE64` on x86_64 and `ARM_DEBUG_STATE` on
    /// arm64. Interpreting the tag alone reads a fixed slot out of a state
    /// with a completely different layout and hands the result back as an
    /// entry point — the exact failure the unmodelled-flavour arm exists to
    /// prevent, reintroduced for the flavours that DO collide.
    #[test]
    fn a_thread_flavour_is_interpreted_according_to_the_headers_cputype() {
        let mut arm = vec![0u64; 33];
        arm[32] = 0x1_0000_3f10;
        let arm_cmd = lc_unixthread_pairs(&[(ARM_THREAD_STATE64_FLAVOUR, state_words(&arm))]);

        let buf = header_with_cpu(CPU_TYPE_ARM64, 1, &arm_cmd);
        assert_eq!(
            parse_mach_o_entry_offset(&buf, 0x1_0000_0000),
            Some(0x3f10),
            "flavour 6 in an arm64 image IS the thread state"
        );
        let buf = header_with_cpu(CPU_TYPE_X86_64, 1, &arm_cmd);
        assert_eq!(
            parse_mach_o_entry_offset(&buf, 0x1_0000_0000),
            None,
            "the identical bytes in an x86_64 image are an EXCEPTION state; \
             slot 32 of it is not a pc"
        );

        let mut x86 = vec![0u64; 21];
        x86[16] = 0x1_0000_2222;
        let x86_cmd = lc_unixthread_pairs(&[(X86_THREAD_STATE64_FLAVOUR, state_words(&x86))]);

        let buf = header_with_cpu(CPU_TYPE_X86_64, 1, &x86_cmd);
        assert_eq!(
            parse_mach_o_entry_offset(&buf, 0x1_0000_0000),
            Some(0x2222),
            "flavour 4 in an x86_64 image IS the thread state"
        );
        let buf = header_with_cpu(CPU_TYPE_ARM64, 1, &x86_cmd);
        assert_eq!(
            parse_mach_o_entry_offset(&buf, 0x1_0000_0000),
            None,
            "flavour 4 in an arm64 image is ARM_DEBUG_STATE, not a thread state"
        );

        // An architecture this module does not model is skipped rather than
        // guessed at, for the same reason an unmodelled flavour is.
        let buf = header_with_cpu(0, 1, &x86_cmd);
        assert_eq!(parse_mach_o_entry_offset(&buf, 0x1_0000_0000), None);
    }

    /// Property (fuzz-lite) for the triple walk: hostile `cmdsize`/`count`
    /// combinations must neither panic nor spin.
    ///
    /// Walking `(flavour, count, state)` triples means the loop's stride comes
    /// from attacker-controlled bytes, so termination is a real obligation:
    /// `count == 0` must still advance (it does — by the 8-byte triple header)
    /// and a `count` that overflows the buffer must stop. A hang here would be
    /// worse than a wrong answer, since it takes the debugger with it.
    #[test]
    fn hostile_thread_command_triples_terminate_without_panicking() {
        let mut checked = 0usize;
        for cputype in [CPU_TYPE_X86_64, CPU_TYPE_ARM64, 0] {
            for count in [0u32, 1, 2, 8, 42, 68, 0xFFFF, u32::MAX] {
                for flavour in [0u32, 4, 5, 6, 99] {
                    for cmdsize_delta in [-8i64, -1, 0, 1, 8] {
                        let mut cmd = lc_unixthread_pairs(&[
                            (flavour, vec![0xdeu32; 8]),
                            (flavour, vec![0xadu32; 8]),
                        ]);
                        // Overwrite the FIRST triple's count with the hostile
                        // value and skew cmdsize away from the truth.
                        cmd[12..16].copy_from_slice(&count.to_le_bytes());
                        let skewed = (cmd.len() as i64 + cmdsize_delta).max(0) as u32;
                        cmd[4..8].copy_from_slice(&skewed.to_le_bytes());
                        let buf = header_with_cpu(cputype, 1, &cmd);
                        // Must return, never panic, never loop forever.
                        let _ = parse_mach_o_entry_offset(&buf, 0x1_0000_0000);
                        checked += 1;
                    }
                }
            }
        }
        assert!(checked >= 200, "expected a meaningful grid, ran {checked}");
    }

    /// A flavour this module does not model must be SKIPPED, not read at a
    /// fixed slot: the layout is unknown, so whatever sits there is another
    /// register, and returning it would be a confident wrong entry point.
    #[test]
    fn an_unmodelled_thread_flavour_yields_none() {
        let mut cmd = lc_unixthread_arm64(0x1_0000_3f10);
        // Flavour field sits at bytes 8..12 of the command.
        cmd[8..12].copy_from_slice(&99u32.to_le_bytes());
        let buf = header_with(1, &cmd);
        assert_eq!(parse_mach_o_entry_offset(&buf, 0x1_0000_0000), None);
    }

}
