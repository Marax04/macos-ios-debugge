//! Memory-access scanner for `x86/x86_64`.
//!
//! Decodes a byte slice and extracts `[base + displacement]` memory operands,
//! mapping each base register to a [`crate::TypeVar`] and emitting one
//! [`FieldAccess`] per access.  This is the bridge between raw instruction
//! bytes and the [`StructRecoveryEngine`].
//!
//! Designed to mirror what IDA Pro's `tinfo_t` propagation pass does when it
//! synthesises struct layouts from `[rcx+8]`, `[rcx+0x10]`, `[rcx+0x18]`
//! access patterns inside a function.

use iced_x86::{
    Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register,
};

use crate::struct_recovery_engine::FieldAccess;
use crate::TypeVar;

/// One indexed memory access — `[base + index*scale + disp]`.
///
/// # Why this exists, and why it is separate from [`FieldAccess`]
///
/// [`scan_memory_accesses_x86`] deliberately keeps only `[base + disp]`, which is
/// the right shape for struct fields but throws away the **scale** — and the
/// scale is the single strongest piece of evidence about the size of an array
/// element. Measured consequence in the corpus: `count_set_flags(const uint32_t*)`
/// is emitted as
///
/// ```c
/// int count_set_flags(__int64 *a1, __int64 a2) { v3 = *(a1 + count*4); ... }
/// ```
///
/// — pointee recovered 8 bytes wide while the index math assumes a 4-byte stride,
/// so every iteration past the first reads 32 bytes ahead of where it should.
/// The behavioural harness catches it (`[7,7,7,7]` → reference 12, emitted 4) and
/// `find_max` crashes outright from the same cause. The `*4` needed to type that
/// pointer was present in the instruction all along; nothing recorded it.
///
/// Kept as a separate type rather than a field on `FieldAccess` because that
/// struct is consumed by other crates: additive here means nothing downstream has
/// to change before it can benefit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArrayAccess {
    /// Type variable of the base pointer register.
    pub base_var: TypeVar,
    /// Scale factor of the index register: 1, 2, 4 or 8.
    pub stride: u8,
    /// Width in bytes of the value actually loaded or stored.
    pub size_bytes: u8,
    /// Constant displacement, if any — the offset of a field *within* the element.
    pub disp: u32,
    /// Whether the access wrote to memory.
    pub is_write: bool,
    /// Address of the instruction performing the access.
    pub address: u64,
    /// True when this came from an address computation (`lea`) rather than a
    /// dereference, in which case `size_bytes` is 0: there is stride evidence but
    /// no access-width evidence.
    ///
    /// These carry the loop bound in optimised code — `find_max`'s end pointer is
    /// `lea (%rcx,%rdx,8),%r8` — so skipping them (as a size-0 operand) discards
    /// the stride for exactly the functions that walk an array to a computed end.
    pub is_address_calc: bool,
    /// True when the base register was loaded by a `lea reg, [rip+disp]` earlier
    /// in this slice — i.e. it points at a constant in `.rdata`, not at a
    /// caller-supplied object.
    ///
    /// This flag exists because the stride evidence is otherwise actively
    /// misleading. `_gnu_exception_handler` contains
    ///
    /// ```text
    ///   lea    0x2420(%rip),%rdx      # -> .rdata
    ///   movslq (%rdx,%rax,4),%rax
    ///   add    %rdx,%rax
    ///   jmp    *%rax
    /// ```
    ///
    /// which is the canonical GCC jump table: the `*4` is the width of a table
    /// ENTRY and says nothing about any parameter's pointee. A first pass at
    /// estimating this bug's blast radius counted 5 "strong candidates"; reading
    /// the disassembly showed 4 of them were this shape, leaving 1 real case.
    /// Wiring stride evidence into type recovery without this filter would
    /// mistype every function containing a `switch` — fixing one bug by
    /// introducing another.
    pub base_is_rip_derived: bool,
    /// Type variable of the *index* register, when it maps to one.
    ///
    /// A register used as a scaled index is an integer COUNT or INDEX, never a
    /// pointer. That is the direct contradiction of `find_max`'s emitted
    /// `size_t *a2`, where the length parameter was promoted to a pointer and the
    /// `*8` scaling lost — the function then walks off the end of the array and
    /// crashes. Recorded so a consumer can refuse the promotion.
    pub index_var: Option<TypeVar>,
}

impl ArrayAccess {
    /// True when stride and access width agree, i.e. this indexes a flat array of
    /// scalars and the element type is `size_bytes` wide.
    ///
    /// When they disagree the access is a field inside an array of structs
    /// (`Point[i].y` → stride 24, width 8), which is equally useful evidence but a
    /// different conclusion — hence a predicate rather than a silent assumption.
    #[must_use]
    pub const fn is_scalar_array(self) -> bool {
        self.size_bytes != 0 && self.stride == self.size_bytes
    }
}

/// Type variables that a scaled index proves are integers, not pointers.
///
/// Returns `(index_var, stride)` pairs. A register used as `index*scale` inside
/// an address is by construction a count or an index; promoting it to a pointer —
/// as the corpus does for `find_max`'s `size_t *a2` — produces code that computes
/// a nonsense end address and walks off the array. Callers use this to *veto* a
/// pointer promotion, which is why it reports evidence rather than a type.
///
/// Deliberately does NOT filter out `base_is_rip_derived` accesses, unlike
/// [`infer_element_size`]. The two ask different questions of the same
/// instruction: a jump table says nothing about the *base*'s pointee type, but
/// its *index* register is still unambiguously an integer. Dropping it here
/// would discard true evidence out of symmetry with a filter that exists for an
/// unrelated reason.
#[must_use]
pub fn index_count_evidence(accesses: &[ArrayAccess]) -> Vec<(TypeVar, u8)> {
    let mut out: Vec<(TypeVar, u8)> = Vec::new();
    for a in accesses {
        if let Some(iv) = a.index_var {
            if !out.iter().any(|(v, s)| *v == iv && *s == a.stride) {
                out.push((iv, a.stride));
            }
        }
    }
    out
}

/// Element size implied by a set of accesses through the same base pointer.
///
/// `None` when there is no evidence or the evidence conflicts. Conflicting
/// strides mean the base is used as more than one array type, and guessing which
/// one wins is how a confidently-wrong pointer type gets emitted — the caller is
/// told "unknown" instead.
#[must_use]
pub fn infer_element_size(accesses: &[ArrayAccess]) -> Option<u8> {
    let mut found: Option<u8> = None;
    // Jump-table entries are excluded: their stride is the table's entry width,
    // which is unrelated to any pointee type. Including them would type every
    // `switch`-containing function from its jump table.
    for a in accesses.iter().filter(|a| a.stride > 0 && !a.base_is_rip_derived) {
        match found {
            None => found = Some(a.stride),
            Some(s) if s == a.stride => {}
            Some(_) => return None,
        }
    }
    found
}

/// Decode `bytes` and return one [`ArrayAccess`] per **indexed** memory operand.
///
/// Complements [`scan_memory_accesses_x86`]: that one answers "what fields does
/// this pointer have", this one answers "what is this pointer an array *of*".
#[must_use]
pub fn scan_array_accesses_x86(bytes: &[u8], base_va: u64, bits: u32) -> Vec<ArrayAccess> {
    let mut out = Vec::new();
    let mut decoder = Decoder::with_ip(bits, bytes, base_va, DecoderOptions::NONE);
    let mut insn = Instruction::default();
    // Registers currently holding a `[rip+disp]` address. Deliberately a local,
    // straight-line approximation — no branches, no merges: it only has to
    // recognise the jump-table shape, where the `lea` sits a few instructions
    // above its use. A register written by anything else is removed, so the flag
    // errs towards NOT claiming rip-derivation.
    let mut rip_regs: Vec<Register> = Vec::new();

    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            continue;
        }
        let ip = insn.ip();

        if insn.mnemonic() == Mnemonic::Lea
            && matches!(insn.memory_base(), Register::RIP | Register::EIP)
            && insn.op0_kind() == OpKind::Register
        {
            let dst = insn.op0_register().full_register();
            if !rip_regs.contains(&dst) {
                rip_regs.push(dst);
            }
        } else if insn.op_count() > 0 && insn.op0_kind() == OpKind::Register {
            // Any other write to the register invalidates what we knew about it.
            let dst = insn.op0_register().full_register();
            rip_regs.retain(|r| *r != dst);
        }

        for op_i in 0..insn.op_count() {
            if insn.op_kind(op_i) != OpKind::Memory {
                continue;
            }
            let base_reg = insn.memory_base();
            let index_reg = insn.memory_index();
            // An indexed access needs BOTH a base and an index; `[rip+x]` and
            // plain `[rcx+8]` are the other scanner's job.
            if index_reg == Register::None
                || base_reg == Register::None
                || base_reg == Register::RIP
                || base_reg == Register::EIP
            {
                continue;
            }
            // Stack frames index differently (locals, spill slots); an array on
            // the stack is not evidence about a parameter's pointee type.
            let full = base_reg.full_register();
            if full == Register::RSP || full == Register::RBP {
                continue;
            }
            let Some(tv) = typevar_for_register(base_reg) else { continue; };

            // `lea` has a memory OPERAND but performs no access, so iced reports
            // no memory size. Treated as stride-only evidence rather than
            // discarded: see `is_address_calc`.
            let is_lea = insn.mnemonic() == Mnemonic::Lea;
            let size = memsize_bytes(&insn);
            if size == 0 && !is_lea {
                continue;
            }
            let scale = insn.memory_index_scale();
            if !matches!(scale, 1 | 2 | 4 | 8) {
                continue;
            }
            let disp = if bits == 64 {
                insn.memory_displacement64() as i64
            } else {
                i64::from(insn.memory_displacement32() as i32)
            };
            if disp < 0 || disp > i64::from(u32::MAX) {
                continue;
            }

            out.push(ArrayAccess {
                base_var: tv,
                stride: scale as u8,
                size_bytes: if is_lea { 0 } else { size },
                disp: disp as u32,
                is_write: !is_lea && op_i == 0 && is_store_mnemonic(&insn),
                address: ip,
                is_address_calc: is_lea,
                base_is_rip_derived: rip_regs.contains(&base_reg.full_register()),
                index_var: typevar_for_register(index_reg),
            });
        }
    }
    out
}

/// Pick a stable `TypeVar` id for a base register.
///
/// We map each `x86_64` GPR to a fixed slot so that two independent disasm
/// passes over the same function produce identical type-vars, enabling
/// cross-function struct merging in [`scan_function_to_engine`].
#[must_use]
pub fn typevar_for_register(reg: Register) -> Option<TypeVar> {
    // Normalise sub-registers to their full 64-bit parent.
    let full = reg.full_register();
    let id: u32 = match full {
        Register::RAX => 1,
        Register::RCX => 2,
        Register::RDX => 3,
        Register::RBX => 4,
        Register::RSP => 5,
        Register::RBP => 6,
        Register::RSI => 7,
        Register::RDI => 8,
        Register::R8 => 9,
        Register::R9 => 10,
        Register::R10 => 11,
        Register::R11 => 12,
        Register::R12 => 13,
        Register::R13 => 14,
        Register::R14 => 15,
        Register::R15 => 16,
        // No 32-bit arms here: `full_register()` above already maps every
        // sub-register to its 64-bit parent — verified for EAX, AL, AX, R8D and
        // SPL, i.e. all four width families, not just the 32-bit one.
        //
        // Eight `Register::EAX => 1`-style arms used to follow and were
        // unreachable. Worse than redundant: they implied only the 32-bit
        // aliases were handled, inviting someone to "complete" the list with
        // R8D..R15D or the byte registers, which `full_register()` already
        // covers.
        _ => return None,
    };
    Some(TypeVar::new(id))
}

/// Width in bytes of an `iced_x86::MemorySize`.
fn memsize_bytes(insn: &Instruction) -> u8 {
    let sz = insn.memory_size().size();
    // Clamp to reasonable field widths.
    if sz == 0 { return 0; }
    if sz > 64 { return 64; }
    sz as u8
}

/// Decode `bytes` starting at virtual address `base_va` and return one
/// [`FieldAccess`] per `[base+disp]` memory operand.
///
/// Skips RSP-relative accesses unless `include_stack` is true — stack
/// locals normally belong to the stack-frame recovery pass, not the
/// generic struct-recovery engine.
#[must_use]
pub fn scan_memory_accesses_x86(
    bytes: &[u8],
    base_va: u64,
    bits: u32,
    include_stack: bool,
) -> Vec<FieldAccess> {
    let mut accesses = Vec::new();
    let mut decoder = Decoder::with_ip(bits, bytes, base_va, DecoderOptions::NONE);
    let mut insn = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            continue;
        }
        let ip = insn.ip();

        for op_i in 0..insn.op_count() {
            if insn.op_kind(op_i) != OpKind::Memory {
                continue;
            }
            // Skip [rip+disp] (constant pool / global), no struct base.
            let base_reg = insn.memory_base();
            if base_reg == Register::None
                || base_reg == Register::RIP
                || base_reg == Register::EIP
            {
                continue;
            }
            if !include_stack {
                let full = base_reg.full_register();
                if full == Register::RSP || full == Register::RBP {
                    continue;
                }
            }
            let Some(tv) = typevar_for_register(base_reg) else { continue; };

            // Only positive offsets are struct fields.  Negative offsets on
            // RBP are stack locals, handled separately.  In 64-bit mode iced
            // sign-extends the displacement to 64 bits; in 16/32-bit mode the
            // displacement is a 32-bit two's-complement value that must be
            // sign-extended here (else `[ecx-4]` reads as offset 0xFFFF_FFFC).
            let disp = if bits == 64 {
                insn.memory_displacement64() as i64
            } else {
                i64::from(insn.memory_displacement32() as i32)
            };
            if disp < 0 || disp > i64::from(u32::MAX) {
                continue;
            }
            let offset = disp as u32;

            let size = memsize_bytes(&insn);
            if size == 0 {
                continue;
            }

            // Heuristic: writes are detected by op-0 being the memory operand
            // on the common store mnemonics (mov, add, sub, and, or, xor).
            let is_write = op_i == 0 && is_store_mnemonic(&insn);

            let acc = if is_write {
                FieldAccess::write(tv, offset, size, ip)
            } else {
                FieldAccess::read(tv, offset, size, ip)
            };
            accesses.push(acc);
        }
    }

    accesses
}

/// True when `insn` is a mnemonic that writes its destination operand
/// (op 0) — the canonical x86 store family.
fn is_store_mnemonic(insn: &Instruction) -> bool {
    use iced_x86::Mnemonic as M;
    matches!(
        insn.mnemonic(),
        M::Mov
            | M::Movsx
            | M::Movzx
            | M::Add
            | M::Sub
            | M::And
            | M::Or
            | M::Xor
            | M::Inc
            | M::Dec
            | M::Shl
            | M::Shr
            | M::Sar
            | M::Neg
            | M::Not
            | M::Lea
    )
}

/// Decode `bytes` and feed all extracted accesses into a fresh
/// [`StructRecoveryEngine`], then run recovery.
///
/// This is the one-call front door used by both the per-function MCP tool
/// and the cross-function aggregator.
#[must_use]
pub fn scan_function_to_engine(
    bytes: &[u8],
    base_va: u64,
    bits: u32,
) -> Vec<crate::struct_recovery_engine::RecoveredStruct> {
    let accesses = scan_memory_accesses_x86(bytes, base_va, bits, false);
    let mut engine = if bits == 64 {
        crate::struct_recovery_engine::StructRecoveryEngine::new_64bit()
    } else {
        crate::struct_recovery_engine::StructRecoveryEngine::new_32bit()
    };
    // require at least 2 distinct accesses per base register to count as a struct.
    engine.min_access_count = 2;
    engine.record_all(accesses);
    engine.recover_structs_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The corpus case this was written for: a `uint32_t` array walked with a
    /// scale-4 index. `mov eax, [rcx+rax*4]` = 8b 04 81.
    ///
    /// Recovering stride 4 here is what distinguishes `uint32_t *` from the
    /// `__int64 *` the decompiler currently emits for `count_set_flags`.
    #[test]
    fn indexed_load_records_scale_four() {
        let bytes: &[u8] = &[0x8B, 0x04, 0x81];
        let acc = scan_array_accesses_x86(bytes, 0x1000, 64);
        assert_eq!(acc.len(), 1, "expected one indexed access, got {acc:?}");
        assert_eq!(acc[0].stride, 4);
        assert_eq!(acc[0].size_bytes, 4);
        assert!(acc[0].is_scalar_array(), "stride == width ⇒ array of uint32");
        assert_eq!(infer_element_size(&acc), Some(4));
    }

    /// `mov rax, [rcx+rdx*8]` = 48 8b 04 d1 — an array of 8-byte scalars.
    #[test]
    fn indexed_load_records_scale_eight() {
        let acc = scan_array_accesses_x86(&[0x48, 0x8B, 0x04, 0xD1], 0x1000, 64);
        assert_eq!(acc.len(), 1);
        assert_eq!(acc[0].stride, 8);
        assert_eq!(acc[0].size_bytes, 8);
        assert!(acc[0].is_scalar_array());
    }

    /// A scale that does not match the access width is an array of STRUCTS, not
    /// an array of scalars: `mov rax, [rcx+rdx*8+16]` reads an 8-byte field at
    /// offset 16. Reporting that as element size 8 would invent a flat array.
    #[test]
    fn field_within_element_is_not_a_scalar_array() {
        // mov eax, [rcx+rdx*8+16]  = 8b 44 d1 10  (4-byte read, 8-byte stride)
        let acc = scan_array_accesses_x86(&[0x8B, 0x44, 0xD1, 0x10], 0x1000, 64);
        assert_eq!(acc.len(), 1);
        assert_eq!(acc[0].stride, 8);
        assert_eq!(acc[0].size_bytes, 4);
        assert!(!acc[0].is_scalar_array());
        assert_eq!(acc[0].disp, 16);
    }

    /// Non-indexed accesses belong to the field scanner and must not appear here,
    /// or every struct field would be misread as a stride-1 array.
    #[test]
    fn plain_displacement_access_is_not_an_array_access() {
        assert!(scan_array_accesses_x86(&[0x48, 0x8B, 0x41, 0x08], 0x1000, 64).is_empty());
    }

    /// Conflicting evidence must yield `None`, never a pick. A base used with two
    /// different strides is exactly where a confident wrong pointer type comes
    /// from.
    #[test]
    fn conflicting_strides_infer_nothing() {
        let mut acc = scan_array_accesses_x86(&[0x8B, 0x04, 0x81], 0x1000, 64);
        acc.extend(scan_array_accesses_x86(&[0x48, 0x8B, 0x04, 0xD1], 0x2000, 64));
        assert_eq!(acc.len(), 2);
        assert_eq!(infer_element_size(&acc), None);
    }

    /// Stack-relative indexing is a local array, not evidence about a pointer
    /// parameter's pointee.
    #[test]
    fn stack_indexed_access_is_skipped() {
        // mov eax, [rsp+rax*4] = 8b 04 84
        assert!(scan_array_accesses_x86(&[0x8B, 0x04, 0x84], 0x1000, 64).is_empty());
    }

    #[test]
    fn no_evidence_infers_nothing() {
        assert_eq!(infer_element_size(&[]), None);
    }

    /// The real loop body of `count_set_flags` from `sample6_c.exe`, verbatim.
    ///
    /// Hand-assembled bytes prove the scanner decodes what I *think* the compiler
    /// emits; these prove it decodes what the compiler *actually* emitted for the
    /// function that is measurably wrong in the corpus. The distinction matters:
    /// a fix validated only against invented input can still miss the real case.
    ///
    /// `mov (%rcx,%r9,4),%r8d` at `0x1400015c0` — base rcx, index r9, scale 4,
    /// 32-bit load. That `*4` is the whole ground truth for `const uint32_t *`,
    /// and it was being discarded.
    #[test]
    fn real_corpus_loop_yields_stride_four() {
        let bytes: &[u8] = &[
            0x46, 0x8B, 0x04, 0x89,             // mov  (%rcx,%r9,4),%r8d
            0x45, 0x89, 0xC2,                   // mov  %r8d,%r10d
            0x41, 0x83, 0xE2, 0x01,             // and  $0x1,%r10d
            0x44, 0x01, 0xD0,                   // add  %r10d,%eax
            0x45, 0x89, 0xC2,                   // mov  %r8d,%r10d
            0x41, 0x83, 0xE2, 0x02,             // and  $0x2,%r10d
            0x41, 0x83, 0xFA, 0x01,             // cmp  $0x1,%r10d
            0x83, 0xD8, 0xFF,                   // sbb  $-1,%eax
            0x41, 0x83, 0xE0, 0x04,             // and  $0x4,%r8d
            0x41, 0x83, 0xF8, 0x01,             // cmp  $0x1,%r8d
            0x83, 0xD8, 0xFF,                   // sbb  $-1,%eax
            0x49, 0x83, 0xC1, 0x01,             // add  $0x1,%r9
            0x49, 0x39, 0xD1,                   // cmp  %rdx,%r9
            0x72, 0xD0,                         // jb   loop
            0xC3,                               // ret
        ];
        let acc = scan_array_accesses_x86(bytes, 0x1400015c0, 64);
        assert_eq!(acc.len(), 1, "one indexed load in this loop, got {acc:?}");
        assert_eq!(acc[0].stride, 4, "the *4 scale must survive");
        assert_eq!(acc[0].size_bytes, 4, "r8d is a 32-bit destination");
        assert!(acc[0].is_scalar_array());
        assert_eq!(acc[0].base_var, typevar_for_register(Register::RCX).unwrap());
        assert_eq!(
            infer_element_size(&acc),
            Some(4),
            "element size 4 ⇒ `uint32_t *`, not the emitted `__int64 *`"
        );
    }

    /// The real end-pointer computation from `find_max` in `sample1.exe`:
    /// `lea (%rcx,%rdx,8),%r8` at `0x140001509` = 4c 8d 04 d1.
    ///
    /// Two distinct facts live in this one instruction, and BOTH were being
    /// dropped — it is a `lea`, so there is no access width, and a size-0 operand
    /// used to be skipped outright:
    ///
    ///   * `rcx` is an array of 8-byte elements (stride 8);
    ///   * `rdx` is a COUNT, because a scaled index cannot be a pointer.
    ///
    /// The emitted code gets both wrong — `find_max(__int64 *a1, size_t *a2)`
    /// with `v4 = (__int64)a1 + (__int64)a2` — and the resulting walk off the end
    /// of the array is the corpus's only outright CRASH under the behavioural
    /// harness.
    #[test]
    fn real_find_max_lea_yields_stride_and_count_evidence() {
        let acc = scan_array_accesses_x86(&[0x4C, 0x8D, 0x04, 0xD1], 0x140001509, 64);
        assert_eq!(acc.len(), 1, "the lea must not be skipped: {acc:?}");
        let a = acc[0];
        assert!(a.is_address_calc, "lea computes an address, it does not access");
        assert_eq!(a.stride, 8, "element stride 8 ⇒ int64_t array");
        assert_eq!(a.size_bytes, 0, "no dereference ⇒ no width evidence");
        assert!(!a.is_scalar_array(), "stride alone must not claim a scalar array");
        assert_eq!(a.base_var, typevar_for_register(Register::RCX).unwrap());
        assert_eq!(a.index_var, typevar_for_register(Register::RDX));
        assert!(!a.is_write, "a lea writes a register, not memory");

        assert_eq!(
            index_count_evidence(&acc),
            vec![(typevar_for_register(Register::RDX).unwrap(), 8)],
            "rdx is used as a scaled index ⇒ it is a count, NOT the `size_t *` emitted"
        );
    }

    /// The real jump table from `_gnu_exception_handler` in `sample6_c.exe`:
    ///
    /// ```text
    ///   140001f19: 48 8d 15 20 24 00 00   lea    0x2420(%rip),%rdx   # .rdata
    ///   140001f20: 48 63 04 82            movslq (%rdx,%rax,4),%rax
    /// ```
    ///
    /// Scale 4 with a 4-byte load — indistinguishable from `count_set_flags`'s
    /// `uint32_t` array on shape alone, which is exactly the trap. It must be
    /// excluded from element-size inference, or every `switch` gets its pointer
    /// types decided by a jump table.
    #[test]
    fn real_jump_table_is_flagged_and_excluded() {
        let bytes: &[u8] = &[
            0x48, 0x8D, 0x15, 0x20, 0x24, 0x00, 0x00,   // lea 0x2420(%rip),%rdx
            0x48, 0x63, 0x04, 0x82,                     // movslq (%rdx,%rax,4),%rax
        ];
        let acc = scan_array_accesses_x86(bytes, 0x140001f19, 64);
        assert_eq!(acc.len(), 1, "expected the table read, got {acc:?}");
        assert!(acc[0].base_is_rip_derived, "base came from lea [rip+disp]");
        assert_eq!(acc[0].stride, 4);
        assert_eq!(
            infer_element_size(&acc),
            None,
            "a jump table must contribute NO element-size evidence"
        );
    }

    /// The rip-derived filter applies to element size, NOT to count evidence, and
    /// this pins that asymmetry down so it is not "tidied up" later.
    ///
    /// In `movslq (%rdx,%rax,4),%rax` with `%rdx` from `.rdata`: the table says
    /// nothing about what `%rdx` points to, but `%rax` is indisputably an integer
    /// index. Filtering it here would throw away a true fact for the sake of
    /// symmetry with a filter that exists for an entirely different reason.
    #[test]
    fn jump_table_index_is_still_count_evidence() {
        let bytes: &[u8] = &[
            0x48, 0x8D, 0x15, 0x20, 0x24, 0x00, 0x00,   // lea 0x2420(%rip),%rdx
            0x48, 0x63, 0x04, 0x82,                     // movslq (%rdx,%rax,4),%rax
        ];
        let acc = scan_array_accesses_x86(bytes, 0x140001f19, 64);
        assert!(acc[0].base_is_rip_derived);
        assert_eq!(infer_element_size(&acc), None, "no pointee evidence");
        assert_eq!(
            index_count_evidence(&acc),
            vec![(typevar_for_register(Register::RAX).unwrap(), 4)],
            "the index register is an integer regardless of what the base points at"
        );
    }

    /// The exclusion must not swallow genuine array evidence: an ordinary indexed
    /// load, with no rip-relative `lea` in sight, still counts.
    #[test]
    fn ordinary_indexed_load_is_not_rip_derived() {
        let acc = scan_array_accesses_x86(&[0x8B, 0x04, 0x81], 0x1000, 64);
        assert_eq!(acc.len(), 1);
        assert!(!acc[0].base_is_rip_derived);
        assert_eq!(infer_element_size(&acc), Some(4));
    }

    /// Overwriting the register after the `lea` must clear the flag, or a stale
    /// belief would suppress real evidence later in the same function.
    #[test]
    fn reassigned_base_loses_rip_derivation() {
        let bytes: &[u8] = &[
            0x48, 0x8D, 0x15, 0x20, 0x24, 0x00, 0x00,   // lea 0x2420(%rip),%rdx
            0x48, 0x89, 0xCA,                           // mov %rcx,%rdx   <- now a param
            0x8B, 0x04, 0x82,                           // mov (%rdx,%rax,4),%eax
        ];
        let acc = scan_array_accesses_x86(bytes, 0x1000, 64);
        assert_eq!(acc.len(), 1);
        assert!(!acc[0].base_is_rip_derived, "rdx was overwritten from rcx");
        assert_eq!(infer_element_size(&acc), Some(4));
    }

    /// A real dereference must stay distinguishable from an address computation,
    /// or the two kinds of evidence get conflated.
    #[test]
    fn dereference_is_not_flagged_as_address_calc() {
        let acc = scan_array_accesses_x86(&[0x8B, 0x04, 0x81], 0x1000, 64);
        assert_eq!(acc.len(), 1);
        assert!(!acc[0].is_address_calc);
        assert_eq!(acc[0].size_bytes, 4);
    }

    /// Pins down WHERE the second half of the pointee-width bug lives.
    ///
    /// `my_strlen` is emitted with an `__int64 *` walking pointer, so `++result`
    /// steps 8 bytes and the loop stops at the first 8-byte zero chunk (measured:
    /// `"a"` → 48 instead of 1). Unlike `count_set_flags`, there is no index or
    /// scale here to lose — the only evidence is the width of the dereference.
    ///
    /// This asserts that evidence IS captured: `cmp byte ptr [rax], 0` is
    /// recorded as a 1-byte access at offset 0. So the byte-width case is not a
    /// scanner gap; whatever chooses the pointee type downstream is discarding a
    /// signal it already has. Worth a test precisely because it prevents "fix"
    /// effort being aimed at this file, where there is nothing wrong.
    #[test]
    fn byte_deref_width_is_captured_evidence_exists() {
        // cmp byte ptr [rax], 0  = 80 38 00
        let acc = scan_memory_accesses_x86(&[0x80, 0x38, 0x00], 0x1000, 64, false);
        assert_eq!(acc.len(), 1, "expected the byte deref to be recorded: {acc:?}");
        assert_eq!(acc[0].size_bytes, 1, "1-byte access width must survive");
        assert_eq!(acc[0].byte_offset, 0);
    }

    /// mov rax, [rcx+8]   ; 48 8b 41 08
    /// mov rdx, [rcx+0x10]; 48 8b 51 10
    /// mov [rcx+0x18], rax; 48 89 41 18
    #[test]
    fn scan_extracts_three_fields_from_rcx() {
        let bytes: &[u8] = &[
            0x48, 0x8B, 0x41, 0x08,
            0x48, 0x8B, 0x51, 0x10,
            0x48, 0x89, 0x41, 0x18,
        ];
        let acc = scan_memory_accesses_x86(bytes, 0x1000, 64, false);
        assert_eq!(acc.len(), 3, "expected 3 [rcx+*] accesses, got {acc:?}");
        let rcx = typevar_for_register(Register::RCX).unwrap();
        assert!(acc.iter().all(|a| a.base_var == rcx));
        let mut offsets: Vec<u32> = acc.iter().map(|a| a.byte_offset).collect();
        offsets.sort_unstable();
        assert_eq!(offsets, vec![8, 16, 24]);
        // last one is a store
        assert!(acc.iter().any(|a| a.byte_offset == 24 && a.is_write));
    }

    #[test]
    fn scan_skips_rip_relative() {
        // mov rax, [rip+0x10] ; 48 8b 05 10 00 00 00
        let bytes: &[u8] = &[0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00];
        let acc = scan_memory_accesses_x86(bytes, 0x1000, 64, false);
        assert!(acc.is_empty(), "RIP-relative must be skipped: {acc:?}");
    }

    /// In 32-bit mode a negative displacement is a 32-bit two's-complement
    /// value (e.g. `[ecx-4]` encodes disp 0xFFFF_FFFC).  It must be treated
    /// as negative and skipped, not as a bogus ~4 GB struct-field offset.
    #[test]
    fn scan_skips_negative_disp_in_32bit_mode() {
        // mov eax, [ecx-4] ; 8B 41 FC (32-bit mode)
        let bytes: &[u8] = &[0x8B, 0x41, 0xFC];
        let acc = scan_memory_accesses_x86(bytes, 0x1000, 32, false);
        assert!(
            acc.is_empty(),
            "negative 32-bit displacement must be skipped: {acc:?}"
        );
    }

    #[test]
    fn engine_recovers_struct_from_bytes() {
        let bytes: &[u8] = &[
            0x48, 0x8B, 0x41, 0x08, // mov rax, [rcx+8]
            0x48, 0x8B, 0x51, 0x10, // mov rdx, [rcx+0x10]
            0x48, 0x89, 0x41, 0x18, // mov [rcx+0x18], rax
        ];
        let structs = scan_function_to_engine(bytes, 0x1000, 64);
        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].fields.len(), 3);
        assert!(structs[0].total_size >= 32);
    }
}
