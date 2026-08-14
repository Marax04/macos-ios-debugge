//! CodeView symbol record type codes (`SYM_ENUM_e` from `cvinfo.h`).
//!
//! This is the single source of truth for the crate. Several modules used to
//! carry private copies of this table with wrong values for `S_LPROC32` and
//! `S_LDATA32` (0x1108 / 0x1107 — which are actually `S_UDT` and
//! `S_CONSTANT`), which silently dropped every `static` function and
//! file-static variable while mis-parsing real `S_UDT` / `S_CONSTANT` records
//! as procedures and data.

// ── 0x11xx block ─────────────────────────────────────────────────────────────

/// `S_OBJNAME`: object file name.
pub const S_OBJNAME: u16 = 0x1101;
/// `S_THUNK32`: thunk start.
pub const S_THUNK32: u16 = 0x1102;
/// `S_BLOCK32`: lexical block start.
pub const S_BLOCK32: u16 = 0x1103;
/// `S_WITH32`: Pascal `with` start.
pub const S_WITH32: u16 = 0x1104;
/// `S_LABEL32`: code label.
pub const S_LABEL32: u16 = 0x1105;
/// `S_REGISTER`: register variable.
pub const S_REGISTER: u16 = 0x1106;
/// `S_CONSTANT`: constant symbol.
pub const S_CONSTANT: u16 = 0x1107;
/// `S_UDT`: user-defined type alias.
pub const S_UDT: u16 = 0x1108;
/// `S_COBOLUDT`: COBOL user-defined type.
pub const S_COBOLUDT: u16 = 0x1109;
/// `S_MANYREG`: multiple-register variable.
pub const S_MANYREG: u16 = 0x110A;
/// `S_BPREL32`: BP-relative local.
pub const S_BPREL32: u16 = 0x110B;
/// `S_LDATA32`: module-local (file `static`) data.
pub const S_LDATA32: u16 = 0x110C;
/// `S_GDATA32`: global data.
pub const S_GDATA32: u16 = 0x110D;
/// `S_PUB32`: public symbol.
pub const S_PUB32: u16 = 0x110E;
/// `S_LPROC32`: module-local (`static`) procedure.
pub const S_LPROC32: u16 = 0x110F;
/// `S_GPROC32`: global procedure.
pub const S_GPROC32: u16 = 0x1110;
/// `S_REGREL32`: register-relative local.
pub const S_REGREL32: u16 = 0x1111;
/// `S_LTHREAD32`: module-local thread-local data.
pub const S_LTHREAD32: u16 = 0x1112;
/// `S_GTHREAD32`: global thread-local data.
pub const S_GTHREAD32: u16 = 0x1113;

// ── Reference records (global stream) ────────────────────────────────────────

/// `S_PROCREF`: reference to a global procedure in a module stream.
pub const S_PROCREF: u16 = 0x1125;
/// `S_DATAREF`: reference to a data symbol in a module stream.
pub const S_DATAREF: u16 = 0x1126;
/// `S_LPROCREF`: reference to a local procedure in a module stream.
pub const S_LPROCREF: u16 = 0x1127;

// ── ID-stream procedure variants ─────────────────────────────────────────────

/// `S_LPROC32_ID`: `S_LPROC32` with an IPI type index.
pub const S_LPROC32_ID: u16 = 0x1146;
/// `S_GPROC32_ID`: `S_GPROC32` with an IPI type index.
pub const S_GPROC32_ID: u16 = 0x1147;

#[cfg(test)]
mod tests {
    use super::*;

    /// Values asserted directly against the `cvinfo.h` `SYM_ENUM_e` literals —
    /// deliberately not round-tripped through any encoder in this crate, so a
    /// wrong constant cannot hide behind a matching synthetic fixture.
    #[test]
    fn constants_match_cvinfo_h() {
        assert_eq!(S_LABEL32, 0x1105);
        assert_eq!(S_REGISTER, 0x1106);
        assert_eq!(S_CONSTANT, 0x1107);
        assert_eq!(S_UDT, 0x1108);
        assert_eq!(S_COBOLUDT, 0x1109);
        assert_eq!(S_MANYREG, 0x110A);
        assert_eq!(S_BPREL32, 0x110B);
        assert_eq!(S_LDATA32, 0x110C);
        assert_eq!(S_GDATA32, 0x110D);
        assert_eq!(S_PUB32, 0x110E);
        assert_eq!(S_LPROC32, 0x110F);
        assert_eq!(S_GPROC32, 0x1110);
        assert_eq!(S_REGREL32, 0x1111);
        assert_eq!(S_LTHREAD32, 0x1112);
        assert_eq!(S_GTHREAD32, 0x1113);
        assert_eq!(S_PROCREF, 0x1125);
        assert_eq!(S_DATAREF, 0x1126);
        assert_eq!(S_LPROCREF, 0x1127);
    }

    /// The historical bug: `S_LPROC32` collided with `S_UDT` and `S_LDATA32`
    /// with `S_CONSTANT`, so procedure/data parsing swallowed type records.
    #[test]
    fn proc_and_data_codes_are_distinct_from_udt_and_constant() {
        assert_ne!(S_LPROC32, S_UDT);
        assert_ne!(S_LDATA32, S_CONSTANT);
        let all = [
            S_CONSTANT, S_UDT, S_LDATA32, S_GDATA32, S_PUB32, S_LPROC32, S_GPROC32,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b, "duplicate symbol code {a:#06x}");
            }
        }
    }
}
