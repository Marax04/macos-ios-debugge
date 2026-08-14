//! MSVC extras: calling conventions and RTTI symbol decoding.

use serde::{Deserialize, Serialize};

// ── Calling conventions (MSVC) ─────────────────────────────────────────────────

/// A function calling convention as encoded in MSVC mangled names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallingConvention {
    /// `__cdecl` — caller cleans the stack (the C default).
    Cdecl,
    /// `__pascal` — callee cleans the stack, left-to-right ordering.
    Pascal,
    /// `__thiscall` — `this` passed in a register, callee cleans the stack.
    Thiscall,
    /// `__stdcall` — callee cleans the stack.
    Stdcall,
    /// `__fastcall` — first arguments passed in registers.
    Fastcall,
    /// `__vectorcall` — vector arguments passed in SIMD registers.
    Vectorcall,
    /// `__clrcall` — managed (CLR) calling convention.
    Clrcall,
}

impl CallingConvention {
    /// The canonical keyword spelling of this calling convention.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cdecl => "__cdecl",
            Self::Pascal => "__pascal",
            Self::Thiscall => "__thiscall",
            Self::Stdcall => "__stdcall",
            Self::Fastcall => "__fastcall",
            Self::Vectorcall => "__vectorcall",
            Self::Clrcall => "__clrcall",
        }
    }
}

/// Decode an MSVC calling-convention code byte (the letter following the
/// access/storage class in a mangled function name) into a
/// [`CallingConvention`].
///
/// MSVC encodes the convention as pairs of consecutive letters (the second
/// of each pair marks an `__export`ed variant), so both letters of a pair map
/// to the same convention.
#[must_use]
pub const fn msvc_calling_convention(code: u8) -> CallingConvention {
    match code {
        b'C' | b'D' => CallingConvention::Pascal,
        b'E' | b'F' => CallingConvention::Thiscall,
        b'G' | b'H' => CallingConvention::Stdcall,
        b'I' | b'J' => CallingConvention::Fastcall,
        b'Q' | b'R' => CallingConvention::Vectorcall,
        b'M' | b'N' => CallingConvention::Clrcall,
        // Anything unrecognised (including b'A' | b'B') defaults to the C convention.
        _ => CallingConvention::Cdecl,
    }
}

// ── MSVC RTTI ───────────────────────────────────────────────────────────────

/// The kind of an MSVC RTTI (run-time type information) symbol, identified by
/// the `??_R<n>` discriminator that follows the `??_R` prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MsvcRttiKind {
    /// `??_R0` — Type Descriptor.
    TypeDescriptor,
    /// `??_R1` — Base Class Descriptor.
    BaseClassDescriptor,
    /// `??_R2` — Base Class Array.
    BaseClassArray,
    /// `??_R3` — Class Hierarchy Descriptor.
    ClassHierarchyDescriptor,
    /// `??_R4` — Complete Object Locator.
    CompleteObjectLocator,
}

impl MsvcRttiKind {
    /// Map the RTTI discriminator digit (`'0'`..=`'4'`) to its kind.
    #[must_use]
    pub const fn from_digit(d: char) -> Option<Self> {
        match d {
            '0' => Some(Self::TypeDescriptor),
            '1' => Some(Self::BaseClassDescriptor),
            '2' => Some(Self::BaseClassArray),
            '3' => Some(Self::ClassHierarchyDescriptor),
            '4' => Some(Self::CompleteObjectLocator),
            _ => None,
        }
    }

    /// Human-readable description of this RTTI symbol kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TypeDescriptor => "RTTI Type Descriptor",
            Self::BaseClassDescriptor => "RTTI Base Class Descriptor",
            Self::BaseClassArray => "RTTI Base Class Array",
            Self::ClassHierarchyDescriptor => "RTTI Class Hierarchy Descriptor",
            Self::CompleteObjectLocator => "RTTI Complete Object Locator",
        }
    }
}

/// Demangle an MSVC RTTI symbol of the form `??_R<n>...`.
///
/// Renders in the form `msvc-demangler`/`undname` use — the qualified type
/// name, then the RTTI kind as a back-quoted special member, e.g.
/// ``class type_info::`RTTI Type Descriptor'`` and
/// ``type_info::`RTTI Base Class Descriptor at (0,-1,0,64)'``. Returns `None`
/// if `mangled` is not a well-formed RTTI symbol.
///
/// Each discriminator has a distinct grammar after `??_R<n>`:
///   * `0` — a full type (`?A<key><name>@@`): the class key (`class`/`struct`)
///     is kept, since the descriptor names a *type*, not a scope.
///   * `1` — four signed MSVC numbers (the `(mdisp, pdisp, vdisp, attributes)`
///     of the base) followed by the base class name.
///   * `2`, `3` — a bare qualified name.
///   * `4` — a qualified name followed by a cv byte (`6` = const), which
///     prefixes the rendering as it does for a vftable.
#[must_use]
pub fn demangle_msvc_rtti(mangled: &str) -> Option<String> {
    let rest = mangled.strip_prefix("??_R")?;
    let mut chars = rest.chars();
    let digit = chars.next()?;
    let kind = MsvcRttiKind::from_digit(digit)?;
    let body = &rest[digit.len_utf8()..];

    match kind {
        MsvcRttiKind::TypeDescriptor => {
            // `?A<key><name>@@` — a type. Keep the class key.
            let after = body.strip_prefix("?A").unwrap_or(body);
            let mut b = after.bytes();
            let key = match b.next()? {
                b'V' => "class ",
                b'U' => "struct ",
                b'T' => "union ",
                b'W' => "enum ",
                _ => return None,
            };
            let (name, rest) = parse_rtti_qualified_name(&after[1..])?;
            // `??_R0` REQUIRES the storage suffix; `msvc-demangler` rejects the
            // bare form. The other descriptors accept it.
            rtti_tail_is_complete(kind, rest).then(|| format!("{key}{name}::`{}'", kind.as_str()))
        }
        MsvcRttiKind::BaseClassDescriptor => {
            // Four signed numbers, then the base class name.
            let mut cur = body;
            let mut fields = [0i64; 4];
            for f in &mut fields {
                let (v, next) = parse_rtti_number(cur)?;
                *f = v;
                cur = next;
            }
            let (name, rest) = parse_rtti_qualified_name(cur)?;
            if !rtti_tail_is_complete(kind, rest) {
                return None;
            }
            let [a, b, c, d] = fields;
            Some(format!(
                "{name}::`{} at ({a},{b},{c},{d})'",
                kind.as_str()
            ))
        }
        MsvcRttiKind::BaseClassArray | MsvcRttiKind::ClassHierarchyDescriptor => {
            let (name, rest) = parse_rtti_qualified_name(body)?;
            rtti_tail_is_complete(kind, rest).then(|| format!("{name}::`{}'", kind.as_str()))
        }
        MsvcRttiKind::CompleteObjectLocator => {
            let (name, rest) = parse_rtti_qualified_name(body)?;
            let cv = match rest.bytes().next() {
                Some(b'6') => "const ",
                Some(b'7') => "volatile ",
                Some(b'8') => "const volatile ",
                _ => "",
            };
            rtti_tail_is_complete(kind, rest).then(|| format!("{cv}{name}::`{}'", kind.as_str()))
        }
    }
}

/// Whether what follows an RTTI descriptor's name is its complete storage
/// suffix and nothing else.
///
/// These are DATA symbols, and MSVC ends them with a storage encoding the RTTI
/// parser never modelled — it took the name and discarded the remainder, so
/// anything at all could follow:
///
/// ```text
///   ??_R2type_info@@8         =>  type_info::`RTTI Base Class Array'
///   ??_R2type_info@@8GARBAGE  =>  type_info::`RTTI Base Class Array'
/// ```
///
/// Two distinct linker symbols rendering as one is exactly what this crate
/// forbids for D and Itanium (`tests/trailing_input.rs`); MSVC was never held
/// to it.
///
/// **The rule is per kind**, which matters: a shared one conflated the plain
/// data suffix `@8` with the table form `8@` (marker `8`, no cv, closing `@`),
/// so appending a single `@` to a base-class array still parsed. Each
/// descriptor kind admits exactly one shape, and that removes the ambiguity.
///
/// Empty is allowed where `msvc-demangler` allows it — it accepts `??_R2Foo@@`,
/// `??_R4Foo@@` and `??_7Foo@@` bare, and rejects `??_R0?AVFoo@@`. That is the
/// oracle's call, not a guess; on trailing *garbage* it cannot arbitrate,
/// because it absorbs it in all 42 cases tried.
fn rtti_tail_is_complete(kind: MsvcRttiKind, rest: &str) -> bool {
    match kind {
        // `??_R0` requires the suffix.
        MsvcRttiKind::TypeDescriptor => rest == "@8",
        MsvcRttiKind::BaseClassDescriptor
        | MsvcRttiKind::BaseClassArray
        | MsvcRttiKind::ClassHierarchyDescriptor => rest.is_empty() || rest == "8",
        MsvcRttiKind::CompleteObjectLocator => is_table_suffix(rest),
    }
}

/// `<marker><cv?>@`, the suffix of a table-valued data symbol — or empty.
fn is_table_suffix(rest: &str) -> bool {
    if rest.is_empty() {
        return true;
    }
    let Some(after_marker) = rest.strip_prefix(['6', '7', '8']) else {
        return false;
    };
    let after_cv = after_marker.strip_prefix(['A', 'B', 'C', 'D']).unwrap_or(after_marker);
    after_cv == "@"
}

/// Parse an MSVC qualified name (`Foo@ns@@`) into `ns::Foo`, returning the
/// remainder after the terminating `@@`.
///
/// Components are `@`-separated and stored innermost-first, so they are
/// reversed. Terminated by an empty component (the second `@` of `@@`).
fn parse_rtti_qualified_name(s: &str) -> Option<(String, &str)> {
    let mut parts: Vec<&str> = Vec::new();
    let mut rest = s;
    loop {
        let end = rest.find('@')?;
        let component = &rest[..end];
        rest = &rest[end + 1..];
        if component.is_empty() {
            // Empty component: the `@@` terminator (or a leading `@`).
            break;
        }
        parts.push(component);
    }
    if parts.is_empty() {
        return None;
    }
    parts.reverse();
    Some((parts.join("::"), rest))
}

/// Parse one signed MSVC-encoded number, returning `(value, remainder)`.
///
/// A leading `?` marks a negative value. `1..=10` are the single digits
/// `0`..`9` (value `digit + 1`); everything else is base-16 in the letters
/// `A`(0)..`P`(15) terminated by `@`, with `A@` meaning zero.
fn parse_rtti_number(s: &str) -> Option<(i64, &str)> {
    let (negative, rest) = s.strip_prefix('?').map_or((false, s), |r| (true, r));
    let mut bytes = rest.bytes();
    let first = bytes.next()?;
    let (magnitude, consumed) = if first.is_ascii_digit() {
        (i64::from(first - b'0') + 1, 1)
    } else {
        // Base-16 letters A..P, terminated by '@'.
        let mut value = 0i64;
        let mut n = 0usize;
        for b in rest.bytes() {
            n += 1;
            if b == b'@' {
                break;
            }
            if !(b'A'..=b'P').contains(&b) {
                return None;
            }
            value = value * 16 + i64::from(b - b'A');
        }
        (value, n)
    };
    let remainder = &rest[consumed..];
    Some((if negative { -magnitude } else { magnitude }, remainder))
}
