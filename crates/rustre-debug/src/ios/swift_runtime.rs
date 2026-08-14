//! Swift runtime introspection: reading type metadata, nominal type
//! descriptors, existential containers and the representation of the basic
//! Swift value types out of a *live* process.
//!
//! # Why this reads through a trait
//!
//! Every fact this module needs lives in the target's address space, not in
//! the Mach-O file: generic metadata is instantiated at runtime, class
//! metadata is patched by the `ObjC` runtime on realization, and a `String`'s
//! payload may be heap-allocated. Static parsers (`swift_metadata.rs` in
//! `rustre-mobile-ios`) therefore cannot answer these questions. Everything
//! here is expressed against [`SwiftMemoryReader`], so the logic is pure
//! address arithmetic over bytes and is fully exercised on any host with
//! [`crate::ios::objc_runtime::SparseMemory`] — no macOS, no attached process, no `cfg(target_os)`.
//!
//! # Honesty rules
//!
//! Layouts below are ABI-stable since Swift 5 for 64-bit little-endian Apple
//! platforms (`arm64`/arm64e/x86_64). Anything outside that envelope — 32-bit,
//! big-endian, foreign (bridged `NSString`) or shared string storage, or an
//! enum whose discriminator lives in spare bits we cannot compute without the
//! value-witness table — returns a typed error rather than a plausible-looking
//! wrong answer.

use std::collections::BTreeMap;
use std::fmt;

use rustre_demangle::swift_demangler::swift_demangle;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failures of Swift runtime introspection.
///
/// Deliberately fine-grained: "the address was unreadable" and "the value is
/// laid out in a form this code does not decode" are different findings for a
/// caller, and collapsing them would hide the second behind the first.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SwiftRuntimeError {
    /// The target refused or could not satisfy a read.
    #[error("cannot read {len} byte(s) at {addr:#x}: {reason}")]
    Read {
        /// Address that failed.
        addr: u64,
        /// Requested length.
        len: usize,
        /// Backend-supplied reason.
        reason: String,
    },

    /// A pointer that must be non-null was null.
    #[error("null {what} pointer at {addr:#x}")]
    NullPointer {
        /// What was expected there.
        what: &'static str,
        /// Address holding the null.
        addr: u64,
    },

    /// The metadata kind word does not correspond to any known kind.
    #[error("unknown Swift metadata kind {raw:#x} at {addr:#x}")]
    UnknownMetadataKind {
        /// Raw kind word.
        raw: u64,
        /// Metadata address.
        addr: u64,
    },

    /// The operation is only defined for nominal types (struct/enum/class).
    #[error("metadata at {addr:#x} has kind {kind} which carries no nominal type descriptor")]
    NotNominal {
        /// Metadata address.
        addr: u64,
        /// Kind actually found.
        kind: SwiftMetadataKind,
    },

    /// A context descriptor kind byte we do not model.
    #[error("unknown context descriptor kind {raw} at {addr:#x}")]
    UnknownContextKind {
        /// Low 5 bits of the flags word.
        raw: u8,
        /// Descriptor address.
        addr: u64,
    },

    /// Bytes that must be UTF-8 were not.
    #[error("non-UTF-8 bytes at {addr:#x}")]
    NotUtf8 {
        /// Address of the offending bytes.
        addr: u64,
    },

    /// A C string ran past the scan limit without a NUL.
    #[error("unterminated C string at {addr:#x} (scanned {limit} bytes)")]
    UnterminatedString {
        /// Start address.
        addr: u64,
        /// Bytes scanned.
        limit: usize,
    },

    /// Walking parent contexts exceeded the cycle guard.
    #[error("context descriptor chain at {addr:#x} exceeded depth {limit} (cycle?)")]
    ChainTooDeep {
        /// Descriptor the walk started from.
        addr: u64,
        /// Depth limit hit.
        limit: usize,
    },

    /// A `String` whose recorded length is beyond what we will materialise.
    ///
    /// The count word comes from target memory, so a corrupt or hostile
    /// header can claim up to 2^48-1 bytes. Reported rather than clamped: a
    /// truncated string looks like data, an error does not.
    #[error("Swift.String at {addr:#x} claims {count} bytes, above the {limit}-byte cap")]
    StringTooLong {
        /// Address of the string header.
        addr: u64,
        /// Count recorded in the header.
        count: usize,
        /// Cap that was exceeded.
        limit: usize,
    },

    /// A `String` form this module deliberately does not decode.
    ///
    /// Emitted instead of returning garbage; the caller can decide whether to
    /// fall back to calling into the target's own runtime.
    #[error("unsupported Swift.String form: {form}")]
    UnsupportedStringForm {
        /// Human-readable form name (`foreign`, `shared`, ...).
        form: &'static str,
    },

    /// A value whose tag cannot be recovered without its value-witness table.
    #[error("cannot decode {ty} without its value witness table")]
    NeedsValueWitness {
        /// Type being decoded.
        ty: &'static str,
    },
}

/// Convenience result alias.
pub type SwiftResult<T> = Result<T, SwiftRuntimeError>;

// ---------------------------------------------------------------------------
// Memory access abstraction
// ---------------------------------------------------------------------------

/// Word size assumed throughout this module.
///
/// Swift's 32-bit metadata layout differs in more than pointer width (the
/// relative-pointer bases and the class metadata prefix both change), so
/// rather than silently mis-decoding, 32-bit targets are simply out of scope
/// and callers should not route them here.
pub const POINTER_SIZE: usize = 8;

/// Read-only access to the target's address space.
///
/// Only [`read_bytes`](SwiftMemoryReader::read_bytes) is required; the typed
/// accessors are provided so every implementation decodes little-endian words
/// identically. Implementors that can validate mappings cheaply should also
/// override [`is_readable`](SwiftMemoryReader::is_readable).
pub trait SwiftMemoryReader {
    /// Read exactly `len` bytes at `addr`, or fail.
    ///
    /// # Errors
    /// [`SwiftRuntimeError::Read`] if the range is not fully readable.
    fn read_bytes(&self, addr: u64, len: usize) -> SwiftResult<Vec<u8>>;

    /// Cheap probe used to avoid noisy failures when following a suspect
    /// pointer. The default is optimistic: a full read decides.
    fn is_readable(&self, _addr: u64, _len: usize) -> bool {
        true
    }

    /// Read one byte.
    ///
    /// # Errors
    /// See [`read_bytes`](SwiftMemoryReader::read_bytes).
    fn read_u8(&self, addr: u64) -> SwiftResult<u8> {
        Ok(self.read_bytes(addr, 1)?[0])
    }

    /// Read a little-endian `u32`.
    ///
    /// # Errors
    /// See [`read_bytes`](SwiftMemoryReader::read_bytes).
    fn read_u32(&self, addr: u64) -> SwiftResult<u32> {
        let b = self.read_bytes(addr, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a little-endian `i32` (relative-pointer offsets are signed).
    ///
    /// # Errors
    /// See [`read_bytes`](SwiftMemoryReader::read_bytes).
    fn read_i32(&self, addr: u64) -> SwiftResult<i32> {
        Ok(self.read_u32(addr)?.cast_signed())
    }

    /// Read a little-endian `u64`.
    ///
    /// # Errors
    /// See [`read_bytes`](SwiftMemoryReader::read_bytes).
    fn read_u64(&self, addr: u64) -> SwiftResult<u64> {
        let b = self.read_bytes(addr, 8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Read a pointer-sized word.
    ///
    /// # Errors
    /// See [`read_bytes`](SwiftMemoryReader::read_bytes).
    fn read_pointer(&self, addr: u64) -> SwiftResult<u64> {
        self.read_u64(addr)
    }

    /// Read a NUL-terminated UTF-8 string, scanning at most `limit` bytes.
    ///
    /// Reads in chunks rather than byte-at-a-time: over a remote-protocol
    /// transport a per-byte packet round trip dominates everything else.
    ///
    /// The chunk size backs off on failure. A bulk read that runs off the end
    /// of the mapped region fails as a whole — both here and for a real
    /// `m addr,len` packet — so a string terminating just before a mapping
    /// edge would otherwise be unreadable purely because of how we batched it.
    ///
    /// # Errors
    /// [`SwiftRuntimeError::UnterminatedString`] if no NUL appears within
    /// `limit`, or [`SwiftRuntimeError::NotUtf8`] if the bytes are not UTF-8.
    fn read_cstring(&self, addr: u64, limit: usize) -> SwiftResult<String> {
        const CHUNK: usize = 64;
        let mut out: Vec<u8> = Vec::new();
        while out.len() < limit {
            let at = addr + out.len() as u64;
            let mut want = CHUNK.min(limit - out.len());
            let chunk = loop {
                match self.read_bytes(at, want) {
                    Ok(c) => break c,
                    // A single byte that cannot be read is a real failure.
                    Err(e) if want == 1 => return Err(e),
                    Err(_) => want /= 2,
                }
            };
            if let Some(pos) = chunk.iter().position(|&b| b == 0) {
                out.extend_from_slice(&chunk[..pos]);
                return String::from_utf8(out).map_err(|_| SwiftRuntimeError::NotUtf8 { addr });
            }
            out.extend_from_slice(&chunk);
        }
        Err(SwiftRuntimeError::UnterminatedString { addr, limit })
    }
}

/// In-memory sparse address space.
///
/// Not a test-only fixture: it is also the natural target when replaying a
/// core file or a recorded trace, where "memory" is a set of disjoint chunks
/// rather than a live process. Reads that straddle a hole fail, which is
/// exactly the behaviour a real backend has.
#[derive(Debug, Default, Clone)]
pub struct SparseMemory {
    chunks: BTreeMap<u64, Vec<u8>>,
}

impl SparseMemory {
    /// Empty address space.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Map `bytes` at `addr`, replacing any chunk with the same start.
    pub fn write(&mut self, addr: u64, bytes: impl Into<Vec<u8>>) {
        self.chunks.insert(addr, bytes.into());
    }

    /// Map a little-endian `u64` at `addr`.
    pub fn write_u64(&mut self, addr: u64, value: u64) {
        self.write(addr, value.to_le_bytes().to_vec());
    }

    /// Map a little-endian `u32` at `addr`.
    pub fn write_u32(&mut self, addr: u64, value: u32) {
        self.write(addr, value.to_le_bytes().to_vec());
    }

    /// Map a NUL-terminated string at `addr`.
    pub fn write_cstring(&mut self, addr: u64, s: &str) {
        let mut v = s.as_bytes().to_vec();
        v.push(0);
        self.write(addr, v);
    }

    /// Byte at `addr`, if mapped.
    fn byte_at(&self, addr: u64) -> Option<u8> {
        // Highest chunk whose start is <= addr; only that one can contain it.
        let (start, data) = self.chunks.range(..=addr).next_back()?;
        let off = usize::try_from(addr - start).ok()?;
        data.get(off).copied()
    }
}

impl SwiftMemoryReader for SparseMemory {
    fn read_bytes(&self, addr: u64, len: usize) -> SwiftResult<Vec<u8>> {
        let mut out = Vec::with_capacity(len);
        for i in 0..len {
            let a = addr.wrapping_add(i as u64);
            match self.byte_at(a) {
                Some(b) => out.push(b),
                None => {
                    return Err(SwiftRuntimeError::Read {
                        addr,
                        len,
                        reason: format!("unmapped at {a:#x}"),
                    });
                }
            }
        }
        Ok(out)
    }

    fn is_readable(&self, addr: u64, len: usize) -> bool {
        (0..len).all(|i| self.byte_at(addr.wrapping_add(i as u64)).is_some())
    }
}

/// Adapter letting any [`ObjcMemory`](crate::ios::objc_runtime::ObjcMemory) back
/// the Swift reader.
///
/// A debugger session has exactly one way to read the target; `ObjC` and Swift
/// introspection must not each demand their own. The two traits stay separate
/// (their error types are module-local by design) and this one-line bridge
/// joins them, so a backend implements `ObjcMemory` once and gets both.
#[derive(Debug, Clone, Copy)]
pub struct ObjcMemoryAdapter<'m, M: crate::ios::objc_runtime::ObjcMemory + ?Sized>(pub &'m M);

impl<M: crate::ios::objc_runtime::ObjcMemory + ?Sized> SwiftMemoryReader for ObjcMemoryAdapter<'_, M> {
    fn read_bytes(&self, addr: u64, len: usize) -> SwiftResult<Vec<u8>> {
        self.0.read(addr, len).map_err(|e| SwiftRuntimeError::Read {
            addr,
            len,
            reason: e.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Pointer hygiene
// ---------------------------------------------------------------------------

/// Bits an `arm64e` pointer-authentication code can occupy.
///
/// The authentic address space on Darwin `arm64` is 47 bits; everything above is
/// signature or tag. Stripping is idempotent and harmless on `x86_64`, where
/// those bits are zero for user pointers anyway.
const PAC_STRIP_MASK: u64 = 0x0000_007F_FFFF_FFFF;

/// Remove an `arm64e` pointer-authentication signature.
///
/// Note this is the *stripping* operation only — it cannot tell an
/// authenticated pointer from a corrupt one, it just yields the address bits.
#[must_use]
pub const fn strip_pac(ptr: u64) -> u64 {
    ptr & PAC_STRIP_MASK
}

/// Mask a Swift/ObjC object reference down to its address.
///
/// Swift's `BridgeObject` and the `ObjC` `isa` field both store flags in the
/// high bits and, on `arm64e`, a PAC as well. This clears both.
#[must_use]
pub const fn strip_object_bits(ptr: u64) -> u64 {
    strip_pac(ptr)
}

// ---------------------------------------------------------------------------
// Metadata kinds
// ---------------------------------------------------------------------------

/// Flag bit set on every metadata kind that is not a heap object.
const METADATA_KIND_IS_NON_HEAP: u64 = 0x200;
/// Largest raw value that is *not* a kind at all but an `ObjC` `isa` pointer.
///
/// The Swift ABI reserves kinds below this so that a class metadata record can
/// keep a real `ObjC` class pointer in its first word.
const METADATA_KIND_LAST_ENUMERATED: u64 = 0x7FF;

/// Kind of a Swift type metadata record.
///
/// Values are from `swift/ABI/MetadataKind.def`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SwiftMetadataKind {
    /// A Swift or `ObjC` class. Raw word is either 0 or an `isa` pointer.
    Class,
    /// `struct`.
    Struct,
    /// `enum` other than `Optional`.
    Enum,
    /// `Optional<T>` — its own kind, which is what makes `nil` detectable.
    Optional,
    /// A non-Swift (CF-style) class.
    ForeignClass,
    /// A foreign reference type (`@_extern` C++ interop).
    ForeignReferenceType,
    /// Opaque, e.g. `Builtin.NativeObject`.
    Opaque,
    /// Tuple.
    Tuple,
    /// Function or closure.
    Function,
    /// Protocol existential (`any P`, `Any`).
    Existential,
    /// `T.Type`.
    Metatype,
    /// Wrapper around a pure `ObjC` class.
    ObjCClassWrapper,
    /// `any P.Type`.
    ExistentialMetatype,
    /// Extended existential shape.
    ExtendedExistential,
    /// Heap-allocated local (closure box).
    HeapLocalVariable,
    /// Generic heap-allocated local.
    HeapGenericLocalVariable,
    /// Boxed `Error`.
    ErrorObject,
    /// `Task` (concurrency runtime).
    Task,
    /// `Job` (concurrency runtime).
    Job,
}

impl SwiftMetadataKind {
    /// Decode the first word of a metadata record.
    ///
    /// Anything at or below a pointer-looking value is a class: that is the
    /// `ObjC` `isa` slot, not a kind.
    #[must_use]
    pub const fn from_raw(raw: u64) -> Option<Self> {
        if raw > METADATA_KIND_LAST_ENUMERATED {
            // An isa pointer: by definition a class.
            return Some(Self::Class);
        }
        Some(match raw {
            0 => Self::Class,
            0x200 => Self::Struct,
            0x201 => Self::Enum,
            0x202 => Self::Optional,
            0x203 => Self::ForeignClass,
            0x204 => Self::ForeignReferenceType,
            0x300 => Self::Opaque,
            0x301 => Self::Tuple,
            0x302 => Self::Function,
            0x303 => Self::Existential,
            0x304 => Self::Metatype,
            0x305 => Self::ObjCClassWrapper,
            0x306 => Self::ExistentialMetatype,
            0x307 => Self::ExtendedExistential,
            0x400 => Self::HeapLocalVariable,
            0x500 => Self::HeapGenericLocalVariable,
            0x501 => Self::ErrorObject,
            0x502 => Self::Task,
            0x503 => Self::Job,
            _ => return None,
        })
    }

    /// Does this kind carry a nominal type descriptor?
    #[must_use]
    pub const fn is_nominal(self) -> bool {
        matches!(self, Self::Class | Self::Struct | Self::Enum | Self::Optional)
    }

    /// Is this metadata for a heap-allocated (reference-counted) object?
    #[must_use]
    pub const fn is_heap(self) -> bool {
        matches!(
            self,
            Self::Class
                | Self::ForeignClass
                | Self::ObjCClassWrapper
                | Self::HeapLocalVariable
                | Self::HeapGenericLocalVariable
                | Self::ErrorObject
                | Self::Task
                | Self::Job
        )
    }

    /// Raw kind word this variant is stored as (`Class` reports 0, the
    /// canonical value for a pure Swift class with no `ObjC` `isa`).
    #[must_use]
    pub const fn raw(self) -> u64 {
        match self {
            Self::Class => 0,
            Self::Struct => 0x200,
            Self::Enum => 0x201,
            Self::Optional => 0x202,
            Self::ForeignClass => 0x203,
            Self::ForeignReferenceType => 0x204,
            Self::Opaque => 0x300,
            Self::Tuple => 0x301,
            Self::Function => 0x302,
            Self::Existential => 0x303,
            Self::Metatype => 0x304,
            Self::ObjCClassWrapper => 0x305,
            Self::ExistentialMetatype => 0x306,
            Self::ExtendedExistential => 0x307,
            Self::HeapLocalVariable => 0x400,
            Self::HeapGenericLocalVariable => 0x500,
            Self::ErrorObject => 0x501,
            Self::Task => 0x502,
            Self::Job => 0x503,
        }
    }

    /// Is the non-heap flag set for this kind's raw value?
    #[must_use]
    pub const fn is_non_heap_flagged(self) -> bool {
        self.raw() & METADATA_KIND_IS_NON_HEAP != 0
    }
}

impl fmt::Display for SwiftMetadataKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Class => "class",
            Self::Struct => "struct",
            Self::Enum => "enum",
            Self::Optional => "optional",
            Self::ForeignClass => "foreign class",
            Self::ForeignReferenceType => "foreign reference type",
            Self::Opaque => "opaque",
            Self::Tuple => "tuple",
            Self::Function => "function",
            Self::Existential => "existential",
            Self::Metatype => "metatype",
            Self::ObjCClassWrapper => "objc class wrapper",
            Self::ExistentialMetatype => "existential metatype",
            Self::ExtendedExistential => "extended existential",
            Self::HeapLocalVariable => "heap local variable",
            Self::HeapGenericLocalVariable => "heap generic local variable",
            Self::ErrorObject => "error object",
            Self::Task => "task",
            Self::Job => "job",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// Type metadata
// ---------------------------------------------------------------------------

/// Offset from a struct/enum metadata record to its nominal type descriptor.
const STRUCT_DESCRIPTOR_OFFSET: u64 = 8;
/// Offset from a class metadata record to its nominal type descriptor.
///
/// Class metadata carries the `ObjC`-compatible prefix (`isa`, superclass, two
/// cache words, rodata) plus Swift's flags/size words before the descriptor.
const CLASS_DESCRIPTOR_OFFSET: u64 = 64;
/// Offset from any metadata record *back* to its value-witness table pointer.
const VALUE_WITNESS_OFFSET: i64 = -8;

/// A Swift type metadata record read from the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeMetadata {
    /// Address of the metadata record (the "address point", not the
    /// allocation start — the value-witness pointer sits *before* it).
    pub address: u64,
    /// Decoded kind.
    pub kind: SwiftMetadataKind,
    /// Raw first word; for a class this is the `ObjC` `isa` (possibly 0).
    pub raw_kind: u64,
    /// Nominal type descriptor address, for kinds that have one.
    pub descriptor: Option<u64>,
}

impl TypeMetadata {
    /// Read the metadata record at `address`.
    ///
    /// # Errors
    /// Read failures, or [`SwiftRuntimeError::UnknownMetadataKind`] when the
    /// kind word is in the reserved range but matches no known kind.
    pub fn read<R: SwiftMemoryReader + ?Sized>(reader: &R, address: u64) -> SwiftResult<Self> {
        let address = strip_pac(address);
        if address == 0 {
            return Err(SwiftRuntimeError::NullPointer {
                what: "metadata",
                addr: 0,
            });
        }
        let raw_kind = reader.read_u64(address)?;
        let kind = SwiftMetadataKind::from_raw(raw_kind)
            .ok_or(SwiftRuntimeError::UnknownMetadataKind { raw: raw_kind, addr: address })?;

        let descriptor = if kind.is_nominal() {
            let off = if kind == SwiftMetadataKind::Class {
                CLASS_DESCRIPTOR_OFFSET
            } else {
                STRUCT_DESCRIPTOR_OFFSET
            };
            let raw = strip_pac(reader.read_pointer(address + off)?);
            (raw != 0).then_some(raw)
        } else {
            None
        };

        Ok(Self { address, kind, raw_kind, descriptor })
    }

    /// Address of this type's value-witness table.
    ///
    /// # Errors
    /// Read failures.
    pub fn value_witness_table<R: SwiftMemoryReader + ?Sized>(&self, reader: &R) -> SwiftResult<u64> {
        let at = self.address.wrapping_add(VALUE_WITNESS_OFFSET.cast_unsigned());
        Ok(strip_pac(reader.read_pointer(at)?))
    }

    /// Nominal type descriptor, or an error explaining why there is none.
    ///
    /// # Errors
    /// [`SwiftRuntimeError::NotNominal`] for non-nominal kinds,
    /// [`SwiftRuntimeError::NullPointer`] if the slot is null.
    pub fn require_descriptor(&self) -> SwiftResult<u64> {
        if !self.kind.is_nominal() {
            return Err(SwiftRuntimeError::NotNominal { addr: self.address, kind: self.kind });
        }
        self.descriptor.ok_or(SwiftRuntimeError::NullPointer {
            what: "nominal type descriptor",
            addr: self.address,
        })
    }
}

// ---------------------------------------------------------------------------
// Context / nominal type descriptors
// ---------------------------------------------------------------------------

/// Kind of a context descriptor (low 5 bits of its flags word).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ContextDescriptorKind {
    /// A module (the root of every qualified name).
    Module,
    /// An `extension` block.
    Extension,
    /// An anonymous context (function body, closure).
    Anonymous,
    /// A protocol.
    Protocol,
    /// An opaque return type (`some P`).
    OpaqueType,
    /// A class.
    Class,
    /// A struct.
    Struct,
    /// An enum.
    Enum,
}

impl ContextDescriptorKind {
    /// Decode the low 5 bits of a context descriptor flags word.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Option<Self> {
        Some(match raw {
            0 => Self::Module,
            1 => Self::Extension,
            2 => Self::Anonymous,
            3 => Self::Protocol,
            4 => Self::OpaqueType,
            16 => Self::Class,
            17 => Self::Struct,
            18 => Self::Enum,
            _ => return None,
        })
    }

    /// Does this kind have `Name` and `AccessFunction` fields, i.e. is it a
    /// type context rather than a module/extension/anonymous scope?
    #[must_use]
    pub const fn is_type(self) -> bool {
        matches!(self, Self::Class | Self::Struct | Self::Enum)
    }

    /// Does this descriptor carry a name at offset 8?
    ///
    /// Modules do (their name is the module name); extensions and anonymous
    /// contexts do not, which is why they contribute nothing to a qualified
    /// name.
    #[must_use]
    pub const fn has_name(self) -> bool {
        matches!(self, Self::Module | Self::Protocol | Self::Class | Self::Struct | Self::Enum)
    }
}

impl fmt::Display for ContextDescriptorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Module => "module",
            Self::Extension => "extension",
            Self::Anonymous => "anonymous",
            Self::Protocol => "protocol",
            Self::OpaqueType => "opaque type",
            Self::Class => "class",
            Self::Struct => "struct",
            Self::Enum => "enum",
        };
        f.write_str(s)
    }
}

/// Field offsets inside `TargetContextDescriptor` / `TargetTypeContextDescriptor`.
const CTX_FLAGS_OFFSET: u64 = 0;
const CTX_PARENT_OFFSET: u64 = 4;
const CTX_NAME_OFFSET: u64 = 8;
const CTX_ACCESS_FUNCTION_OFFSET: u64 = 12;
const CTX_FIELDS_OFFSET: u64 = 16;

/// Cycle guard for parent-context walks. A legitimate chain is a handful of
/// links (module → type → nested type); anything deeper means the descriptor
/// graph is corrupt or we are following an unrelated pointer.
const MAX_CONTEXT_DEPTH: usize = 32;

/// Longest name a descriptor may carry before we assume the pointer is wrong.
const MAX_NAME_LEN: usize = 4096;

/// A decoded nominal type / context descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NominalTypeDescriptor {
    /// Address of the descriptor.
    pub address: u64,
    /// Raw flags word.
    pub flags: u32,
    /// Decoded kind.
    pub kind: ContextDescriptorKind,
    /// Whether the type is generic.
    pub is_generic: bool,
    /// Whether the descriptor is unique (not a duplicate emitted per-TU).
    pub is_unique: bool,
    /// ABI version byte.
    pub version: u8,
    /// Kind-specific flags (high 16 bits).
    pub kind_specific_flags: u16,
    /// Unqualified name, if this kind carries one.
    pub name: Option<String>,
    /// Parent context descriptor address, if any.
    pub parent: Option<u64>,
    /// Field descriptor address (reflection metadata), for type contexts.
    pub field_descriptor: Option<u64>,
    /// Metadata access function address, for type contexts.
    pub access_function: Option<u64>,
}

/// Resolve a *direct* relative pointer stored at `at`.
///
/// Swift stores 32-bit signed displacements relative to the field's own
/// address, which is what makes metadata position-independent.
///
/// # Errors
/// Read failures.
pub fn read_relative_pointer<R: SwiftMemoryReader + ?Sized>(
    reader: &R,
    at: u64,
) -> SwiftResult<Option<u64>> {
    let off = reader.read_i32(at)?;
    if off == 0 {
        return Ok(None);
    }
    Ok(Some(at.wrapping_add(i64::from(off).cast_unsigned())))
}

/// Resolve a relative pointer whose low bit means "the target is itself a
/// pointer to dereference" (`RelativeIndirectablePointer`).
///
/// # Errors
/// Read failures.
pub fn read_relative_indirectable_pointer<R: SwiftMemoryReader + ?Sized>(
    reader: &R,
    at: u64,
) -> SwiftResult<Option<u64>> {
    let raw = reader.read_i32(at)?;
    if raw == 0 {
        return Ok(None);
    }
    let indirect = raw & 1 != 0;
    let target = at.wrapping_add(i64::from(raw & !1).cast_unsigned());
    if indirect {
        let deref = strip_pac(reader.read_pointer(target)?);
        return Ok((deref != 0).then_some(deref));
    }
    Ok(Some(target))
}

impl NominalTypeDescriptor {
    /// Read the context descriptor at `address`.
    ///
    /// # Errors
    /// Read failures, or [`SwiftRuntimeError::UnknownContextKind`].
    pub fn read<R: SwiftMemoryReader + ?Sized>(reader: &R, address: u64) -> SwiftResult<Self> {
        let address = strip_pac(address);
        if address == 0 {
            return Err(SwiftRuntimeError::NullPointer { what: "context descriptor", addr: 0 });
        }
        let flags = reader.read_u32(address + CTX_FLAGS_OFFSET)?;
        let raw_kind = (flags & 0x1F) as u8;
        let kind = ContextDescriptorKind::from_raw(raw_kind)
            .ok_or(SwiftRuntimeError::UnknownContextKind { raw: raw_kind, addr: address })?;

        let parent = read_relative_indirectable_pointer(reader, address + CTX_PARENT_OFFSET)?;

        let name = if kind.has_name() {
            match read_relative_pointer(reader, address + CTX_NAME_OFFSET)? {
                Some(p) => Some(reader.read_cstring(p, MAX_NAME_LEN)?),
                None => None,
            }
        } else {
            None
        };

        let (access_function, field_descriptor) = if kind.is_type() {
            (
                read_relative_pointer(reader, address + CTX_ACCESS_FUNCTION_OFFSET)?,
                read_relative_pointer(reader, address + CTX_FIELDS_OFFSET)?,
            )
        } else {
            (None, None)
        };

        Ok(Self {
            address,
            flags,
            kind,
            is_generic: flags & (1 << 7) != 0,
            is_unique: flags & (1 << 6) != 0,
            version: ((flags >> 8) & 0xFF) as u8,
            kind_specific_flags: (flags >> 16) as u16,
            name,
            parent,
            field_descriptor,
            access_function,
        })
    }
}

/// Build the fully-qualified name for a nominal type descriptor by walking
/// its parent chain (`MyModule.Outer.Inner`).
///
/// Contexts that carry no name — extensions, anonymous scopes — are skipped
/// rather than rendered, matching how Swift itself prints nested types.
///
/// # Errors
/// Read failures or [`SwiftRuntimeError::ChainTooDeep`].
pub fn qualified_type_name<R: SwiftMemoryReader + ?Sized>(
    reader: &R,
    descriptor: u64,
) -> SwiftResult<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut cursor = Some(descriptor);
    let mut depth = 0usize;

    while let Some(addr) = cursor {
        depth += 1;
        if depth > MAX_CONTEXT_DEPTH {
            return Err(SwiftRuntimeError::ChainTooDeep { addr: descriptor, limit: MAX_CONTEXT_DEPTH });
        }
        let desc = NominalTypeDescriptor::read(reader, addr)?;
        if let Some(n) = desc.name {
            parts.push(n);
        }
        cursor = desc.parent;
    }

    parts.reverse();
    Ok(parts.join("."))
}

/// Fully-qualified name of the type whose metadata is at `metadata`.
///
/// # Errors
/// Read failures, or [`SwiftRuntimeError::NotNominal`] for kinds with no
/// descriptor (tuples, functions, existentials — those have structural, not
/// nominal, names and must be rendered by the caller).
pub fn type_name<R: SwiftMemoryReader + ?Sized>(reader: &R, metadata: u64) -> SwiftResult<String> {
    let md = TypeMetadata::read(reader, metadata)?;
    qualified_type_name(reader, md.require_descriptor()?)
}

/// Demangle a Swift symbol/type name if it looks mangled, otherwise return it
/// unchanged.
///
/// Names stored in metadata are usually *already* human-readable (they are the
/// source identifier), but names recovered from the symbol table are mangled,
/// and callers frequently mix the two. Routing both through here means neither
/// path needs to care.
#[must_use]
pub fn demangle_if_mangled(name: &str) -> String {
    if is_mangled_swift(name) {
        let out = swift_demangle(name);
        if out.is_empty() { name.to_string() } else { out }
    } else {
        name.to_string()
    }
}

/// Does `name` use one of the Swift mangling prefixes?
///
/// `$s`/`_$s` are Swift 5+, `$S`/`_$S` Swift 4.2, `_T0` Swift 4, `_T` Swift 3.
#[must_use]
pub fn is_mangled_swift(name: &str) -> bool {
    const PREFIXES: [&str; 6] = ["$s", "_$s", "$S", "_$S", "_T0", "_T"];
    PREFIXES.iter().any(|p| name.starts_with(p))
}

// ---------------------------------------------------------------------------
// Existentials
// ---------------------------------------------------------------------------

/// Number of words of inline storage in an opaque existential container.
///
/// Values up to three words wide (and trivially movable) live inline; anything
/// larger is boxed, and the first word is then a pointer to the box.
pub const EXISTENTIAL_INLINE_WORDS: usize = 3;

/// Offset of the metadata pointer in an opaque existential container.
const EXISTENTIAL_METADATA_OFFSET: u64 = (EXISTENTIAL_INLINE_WORDS * POINTER_SIZE) as u64;

/// A decoded opaque existential container (`Any`, `any P`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistentialContainer {
    /// Address of the container.
    pub address: u64,
    /// Address of the three-word inline buffer (== `address`).
    pub buffer: u64,
    /// Dynamic type metadata of the wrapped value.
    pub metadata: u64,
    /// Witness table pointers, one per conformance in the existential's type.
    pub witness_tables: Vec<u64>,
}

impl ExistentialContainer {
    /// Read an opaque existential container.
    ///
    /// `num_witness_tables` comes from the *static* type (`Any` has 0,
    /// `any P` has 1, `any P & Q` has 2); it cannot be recovered from the
    /// container itself, which is why it is a parameter rather than a guess.
    ///
    /// # Errors
    /// Read failures.
    pub fn read<R: SwiftMemoryReader + ?Sized>(
        reader: &R,
        address: u64,
        num_witness_tables: usize,
    ) -> SwiftResult<Self> {
        let address = strip_pac(address);
        let metadata = strip_pac(reader.read_pointer(address + EXISTENTIAL_METADATA_OFFSET)?);
        let mut witness_tables = Vec::with_capacity(num_witness_tables);
        for i in 0..num_witness_tables {
            let at = address + EXISTENTIAL_METADATA_OFFSET + ((i + 1) * POINTER_SIZE) as u64;
            witness_tables.push(strip_pac(reader.read_pointer(at)?));
        }
        Ok(Self { address, buffer: address, metadata, witness_tables })
    }

    /// Where the wrapped value actually lives.
    ///
    /// Whether the payload is inline or boxed is a property of the *dynamic*
    /// type's value witness table, which this module does not decode; the
    /// caller supplies the answer (from the VWT's flags) and gets the right
    /// address back. Returning an address unconditionally without this input
    /// would be the classic silently-wrong result.
    ///
    /// # Errors
    /// Read failures when the payload is boxed.
    pub fn payload_address<R: SwiftMemoryReader + ?Sized>(
        &self,
        reader: &R,
        boxed: bool,
    ) -> SwiftResult<u64> {
        if boxed {
            // A boxed payload's first word points at a heap box; the value
            // begins after the box's object header (isa + refcount).
            let box_ptr = strip_object_bits(reader.read_pointer(self.buffer)?);
            if box_ptr == 0 {
                return Err(SwiftRuntimeError::NullPointer { what: "existential box", addr: self.buffer });
            }
            Ok(box_ptr + 2 * POINTER_SIZE as u64)
        } else {
            Ok(self.buffer)
        }
    }

    /// Fully-qualified name of the dynamic type, when it is nominal.
    ///
    /// # Errors
    /// See [`type_name`].
    pub fn dynamic_type_name<R: SwiftMemoryReader + ?Sized>(&self, reader: &R) -> SwiftResult<String> {
        type_name(reader, self.metadata)
    }
}

/// A class existential (`any AnyObject & P`): one object word followed by the
/// witness tables — no inline buffer, because the value is already a reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassExistentialContainer {
    /// Address of the container.
    pub address: u64,
    /// The referenced object.
    pub object: u64,
    /// Witness table pointers.
    pub witness_tables: Vec<u64>,
}

impl ClassExistentialContainer {
    /// Read a class existential container.
    ///
    /// # Errors
    /// Read failures.
    pub fn read<R: SwiftMemoryReader + ?Sized>(
        reader: &R,
        address: u64,
        num_witness_tables: usize,
    ) -> SwiftResult<Self> {
        let address = strip_pac(address);
        let object = strip_object_bits(reader.read_pointer(address)?);
        let mut witness_tables = Vec::with_capacity(num_witness_tables);
        for i in 0..num_witness_tables {
            let at = address + ((i + 1) * POINTER_SIZE) as u64;
            witness_tables.push(strip_pac(reader.read_pointer(at)?));
        }
        Ok(Self { address, object, witness_tables })
    }

    /// Metadata of the referenced object, read from its `isa`.
    ///
    /// # Errors
    /// Read failures, or a null object.
    pub fn dynamic_metadata<R: SwiftMemoryReader + ?Sized>(&self, reader: &R) -> SwiftResult<u64> {
        if self.object == 0 {
            return Err(SwiftRuntimeError::NullPointer { what: "class existential object", addr: self.address });
        }
        Ok(strip_object_bits(reader.read_pointer(self.object)?))
    }
}

// ---------------------------------------------------------------------------
// Swift.String
// ---------------------------------------------------------------------------

/// Discriminator bit: the string is stored inline in its own 16 bytes.
const STR_DISC_SMALL: u8 = 0x20;
/// Discriminator bit: the string is foreign (bridged `NSString`), i.e. it does
/// not provide contiguous UTF-8 and must be read via the `ObjC` runtime.
const STR_DISC_FOREIGN: u8 = 0x10;
/// Discriminator bit: large storage is *shared*, not a native `__StringStorage`.
const STR_DISC_SHARED: u8 = 0x08;
/// Discriminator bit: an immortal (literal) string.
const STR_DISC_IMMORTAL: u8 = 0x80;
/// Mask selecting the count nibble of a small string's discriminator.
const STR_SMALL_COUNT_MASK: u8 = 0x0F;
/// Mask selecting the count out of `_countAndFlagsBits` for a large string.
const STR_LARGE_COUNT_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;
/// Byte offset of the UTF-8 payload inside a native `__StringStorage` object.
///
/// Header is `isa`, refcount, `_realCapacityAndFlags`, `_countAndFlags` — four
/// words — after which the code units are tail-allocated.
const NATIVE_STRING_STORAGE_HEADER: u64 = 32;
/// Bytes of inline capacity in a small string (16 minus the discriminator byte).
const SMALL_STRING_CAPACITY: usize = 15;

/// Largest native `Swift.String` payload [`SwiftString::contents`] will read.
///
/// `SwiftArray` already caps its element count through a `max_elements`
/// argument; strings had no equivalent, so a corrupt count word turned into
/// an unbounded `read_bytes` (and an unbounded `Vec::with_capacity` inside
/// every reader).
pub const MAX_STRING_BYTES: usize = 1024 * 1024;

/// Which representation a `Swift.String` is using.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SwiftStringForm {
    /// Up to 15 UTF-8 bytes stored inline in the two-word struct.
    Small,
    /// Heap-allocated native `__StringStorage`.
    NativeLarge,
    /// Shared storage (e.g. a slice of another buffer).
    Shared,
    /// Bridged `NSString`; no contiguous UTF-8 guarantee.
    Foreign,
}

/// A decoded `Swift.String` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwiftString {
    /// Address of the two-word `String` struct.
    pub address: u64,
    /// Raw first word (`_countAndFlagsBits`).
    pub count_and_flags: u64,
    /// Raw second word (`_object`, a `BridgeObject`).
    pub object: u64,
    /// Which representation is in use.
    pub form: SwiftStringForm,
    /// UTF-8 length in bytes.
    pub count: usize,
    /// Whether this is an immortal (literal) string.
    pub is_immortal: bool,
}

impl SwiftString {
    /// Read the header words of a `Swift.String` at `address`.
    ///
    /// This never touches the heap payload, so it succeeds even for forms
    /// whose contents cannot be decoded — inspect [`form`](SwiftString::form)
    /// before calling [`contents`](SwiftString::contents).
    ///
    /// # Errors
    /// Read failures.
    pub fn read<R: SwiftMemoryReader + ?Sized>(reader: &R, address: u64) -> SwiftResult<Self> {
        let address = strip_pac(address);
        let count_and_flags = reader.read_u64(address)?;
        let object = reader.read_u64(address + 8)?;
        let disc = (object >> 56) as u8;

        let form = if disc & STR_DISC_SMALL != 0 {
            SwiftStringForm::Small
        } else if disc & STR_DISC_FOREIGN != 0 {
            SwiftStringForm::Foreign
        } else if disc & STR_DISC_SHARED != 0 {
            SwiftStringForm::Shared
        } else {
            SwiftStringForm::NativeLarge
        };

        let count = if form == SwiftStringForm::Small {
            (disc & STR_SMALL_COUNT_MASK) as usize
        } else {
            usize::try_from(count_and_flags & STR_LARGE_COUNT_MASK).unwrap_or(usize::MAX)
        };

        Ok(Self {
            address,
            count_and_flags,
            object,
            form,
            count,
            is_immortal: disc & STR_DISC_IMMORTAL != 0,
        })
    }

    /// Address of the first UTF-8 code unit, for large native strings.
    ///
    /// # Errors
    /// [`SwiftRuntimeError::UnsupportedStringForm`] for any other form.
    pub const fn utf8_start(&self) -> SwiftResult<u64> {
        match self.form {
            SwiftStringForm::NativeLarge => {
                let obj = strip_object_bits(self.object);
                if obj == 0 {
                    return Err(SwiftRuntimeError::NullPointer { what: "string storage", addr: self.address });
                }
                Ok(obj + NATIVE_STRING_STORAGE_HEADER)
            }
            SwiftStringForm::Small => Err(SwiftRuntimeError::UnsupportedStringForm { form: "small (inline, no address)" }),
            SwiftStringForm::Shared => Err(SwiftRuntimeError::UnsupportedStringForm { form: "shared" }),
            SwiftStringForm::Foreign => Err(SwiftRuntimeError::UnsupportedStringForm { form: "foreign (bridged NSString)" }),
        }
    }

    /// Decode the string's contents.
    ///
    /// # Errors
    /// Read failures, [`SwiftRuntimeError::NotUtf8`], or
    /// [`SwiftRuntimeError::UnsupportedStringForm`] for shared/foreign
    /// storage, which needs the target's own runtime to resolve.
    pub fn contents<R: SwiftMemoryReader + ?Sized>(&self, reader: &R) -> SwiftResult<String> {
        let bytes = match self.form {
            SwiftStringForm::Small => {
                if self.count > SMALL_STRING_CAPACITY {
                    return Err(SwiftRuntimeError::UnsupportedStringForm { form: "small with impossible count" });
                }
                // The 16 raw bytes *are* the storage, in memory order.
                let raw = reader.read_bytes(self.address, 16)?;
                raw[..self.count].to_vec()
            }
            SwiftStringForm::NativeLarge => {
                if self.count > MAX_STRING_BYTES {
                    return Err(SwiftRuntimeError::StringTooLong {
                        addr: self.address,
                        count: self.count,
                        limit: MAX_STRING_BYTES,
                    });
                }
                reader.read_bytes(self.utf8_start()?, self.count)?
            }
            SwiftStringForm::Shared => {
                return Err(SwiftRuntimeError::UnsupportedStringForm { form: "shared" });
            }
            SwiftStringForm::Foreign => {
                return Err(SwiftRuntimeError::UnsupportedStringForm { form: "foreign (bridged NSString)" });
            }
        };
        String::from_utf8(bytes).map_err(|_| SwiftRuntimeError::NotUtf8 { addr: self.address })
    }
}

// ---------------------------------------------------------------------------
// Swift.Array
// ---------------------------------------------------------------------------

/// Offset of `count` inside `_ContiguousArrayStorage` (after `isa` + refcount).
const ARRAY_COUNT_OFFSET: u64 = 16;
/// Offset of `_capacityAndFlags`.
const ARRAY_CAPACITY_OFFSET: u64 = 24;
/// Offset of the first element, for elements of word alignment or less.
const ARRAY_ELEMENTS_OFFSET: u64 = 32;

/// A decoded `Swift.Array` value.
///
/// An `Array<T>` is a single word: a reference to its buffer object. The empty
/// array is a shared singleton, so a zero count is normal and not an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwiftArray {
    /// Address of the one-word `Array` struct.
    pub address: u64,
    /// Buffer object address, PAC- and flag-stripped.
    pub storage: u64,
    /// Element count.
    pub count: usize,
    /// Capacity as recorded in the buffer header (flag bits included).
    pub capacity_and_flags: u64,
    /// Address of element 0.
    pub elements: u64,
}

impl SwiftArray {
    /// Read the array at `address`.
    ///
    /// # Errors
    /// Read failures, or a null buffer pointer.
    pub fn read<R: SwiftMemoryReader + ?Sized>(reader: &R, address: u64) -> SwiftResult<Self> {
        let address = strip_pac(address);
        let storage = strip_object_bits(reader.read_pointer(address)?);
        if storage == 0 {
            return Err(SwiftRuntimeError::NullPointer { what: "array buffer", addr: address });
        }
        let count = reader.read_u64(storage + ARRAY_COUNT_OFFSET)?;
        let capacity_and_flags = reader.read_u64(storage + ARRAY_CAPACITY_OFFSET)?;
        Ok(Self {
            address,
            storage,
            count: usize::try_from(count).unwrap_or(usize::MAX),
            capacity_and_flags,
            elements: storage + ARRAY_ELEMENTS_OFFSET,
        })
    }

    /// Address of element `index` given `stride` bytes per element.
    ///
    /// `stride` (not size) is correct here: Swift arrays lay elements out at
    /// stride intervals, and for types with tail padding the two differ.
    #[must_use]
    pub const fn element_address(&self, index: usize, stride: usize) -> u64 {
        self.elements + (index * stride) as u64
    }

    /// Read the raw bytes of every element.
    ///
    /// `max_elements` bounds the work: a corrupt count in a live process would
    /// otherwise ask the transport for gigabytes.
    ///
    /// # Errors
    /// Read failures.
    pub fn element_bytes<R: SwiftMemoryReader + ?Sized>(
        &self,
        reader: &R,
        stride: usize,
        max_elements: usize,
    ) -> SwiftResult<Vec<Vec<u8>>> {
        let n = self.count.min(max_elements);
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            out.push(reader.read_bytes(self.element_address(i, stride), stride)?);
        }
        Ok(out)
    }

    /// Read every element as a pointer-sized word (arrays of class references,
    /// `Int`, `String` halves, ...).
    ///
    /// # Errors
    /// Read failures.
    pub fn element_words<R: SwiftMemoryReader + ?Sized>(
        &self,
        reader: &R,
        max_elements: usize,
    ) -> SwiftResult<Vec<u64>> {
        let n = self.count.min(max_elements);
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            out.push(reader.read_u64(self.element_address(i, POINTER_SIZE))?);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Optional
// ---------------------------------------------------------------------------

/// State of an `Optional<T>` whose payload is a reference or pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionalPointer {
    /// `.none`, represented by the all-zero extra inhabitant.
    None,
    /// `.some(ptr)`.
    Some(u64),
}

impl OptionalPointer {
    /// Is this `.none`?
    #[must_use]
    pub const fn is_none(self) -> bool {
        matches!(self, Self::None)
    }

    /// Unwrap the payload, if any.
    #[must_use]
    pub const fn payload(self) -> Option<u64> {
        match self {
            Self::None => None,
            Self::Some(p) => Some(p),
        }
    }
}

/// Decode an `Optional<T>` where `T` is a reference type or pointer.
///
/// This case — and only this case — is decidable without the value-witness
/// table, because the null pointer is a guaranteed extra inhabitant. For
/// payloads with no spare representation (`Int?`, `Bool?`, multi-payload
/// enums) Swift appends a separate tag byte whose offset is the payload's
/// *size*, which we do not know here; use
/// [`read_optional_with_tag`] when the caller can supply it.
///
/// # Errors
/// Read failures.
pub fn read_optional_pointer<R: SwiftMemoryReader + ?Sized>(
    reader: &R,
    address: u64,
) -> SwiftResult<OptionalPointer> {
    let raw = reader.read_pointer(strip_pac(address))?;
    if raw == 0 {
        Ok(OptionalPointer::None)
    } else {
        Ok(OptionalPointer::Some(strip_object_bits(raw)))
    }
}

/// Decode an `Optional<T>` that uses an out-of-line tag byte placed just after
/// a `payload_size`-byte payload.
///
/// Returns `Ok(None)` for `.none` and `Ok(Some(payload_bytes))` for `.some`.
/// The tag convention is: 0 means `.some`, non-zero means `.none`.
///
/// # Errors
/// Read failures. A caller that cannot supply `payload_size` should get
/// [`SwiftRuntimeError::NeedsValueWitness`] from its own layer rather than
/// guessing — see [`optional_needs_value_witness`].
pub fn read_optional_with_tag<R: SwiftMemoryReader + ?Sized>(
    reader: &R,
    address: u64,
    payload_size: usize,
) -> SwiftResult<Option<Vec<u8>>> {
    let address = strip_pac(address);
    let tag = reader.read_u8(address + payload_size as u64)?;
    if tag == 0 {
        Ok(Some(reader.read_bytes(address, payload_size)?))
    } else {
        Ok(None)
    }
}

/// The error to return when an `Optional`'s layout cannot be determined.
///
/// Exists so that every caller reports this the same way instead of inventing
/// a plausible default.
#[must_use]
pub const fn optional_needs_value_witness() -> SwiftRuntimeError {
    SwiftRuntimeError::NeedsValueWitness { ty: "Optional" }
}

// ---------------------------------------------------------------------------
// Value formatting
// ---------------------------------------------------------------------------

/// What the caller believes a memory location holds.
///
/// The debugger gets this from DWARF, from a field descriptor, or from the
/// user; the runtime cannot infer it from an untyped address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SwiftTypeHint {
    /// `Swift.String`.
    String,
    /// `Swift.Array` of pointer-sized elements.
    ArrayOfWords,
    /// `Optional<T>` where `T` is a reference/pointer.
    OptionalPointer,
    /// `Any` / `any P` opaque existential with the given witness-table count.
    Existential(usize),
    /// A class reference; formatted as its dynamic type name.
    ClassReference,
    /// `Swift.Int`.
    Int,
    /// `Swift.Bool`.
    Bool,
}

/// Cap on how many array elements a summary line renders.
const SUMMARY_ELEMENT_LIMIT: usize = 8;

/// Render a human-readable summary of the value at `address`.
///
/// This is the layer that turns a debugger from a register viewer into
/// something that shows values. Failures are reported, never papered over:
/// an unreadable or undecodable value yields `Err`, not `"<unknown>"`.
///
/// # Errors
/// Any of the decode errors of the underlying readers.
pub fn format_value<R: SwiftMemoryReader + ?Sized>(
    reader: &R,
    address: u64,
    hint: SwiftTypeHint,
) -> SwiftResult<String> {
    match hint {
        SwiftTypeHint::String => {
            let s = SwiftString::read(reader, address)?;
            Ok(format!("{:?}", s.contents(reader)?))
        }
        SwiftTypeHint::ArrayOfWords => {
            let a = SwiftArray::read(reader, address)?;
            let words = a.element_words(reader, SUMMARY_ELEMENT_LIMIT)?;
            let mut parts: Vec<String> = words.iter().map(|w| format!("{w:#x}")).collect();
            if a.count > words.len() {
                parts.push(format!("… {} more", a.count - words.len()));
            }
            Ok(format!("[{}]", parts.join(", ")))
        }
        SwiftTypeHint::OptionalPointer => match read_optional_pointer(reader, address)? {
            OptionalPointer::None => Ok("nil".to_string()),
            OptionalPointer::Some(p) => Ok(format!("Optional({p:#x})")),
        },
        SwiftTypeHint::Existential(n) => {
            let c = ExistentialContainer::read(reader, address, n)?;
            let name = c
                .dynamic_type_name(reader)
                .unwrap_or_else(|_| format!("<metadata {:#x}>", c.metadata));
            Ok(format!("{} (existential)", demangle_if_mangled(&name)))
        }
        SwiftTypeHint::ClassReference => {
            let obj = strip_object_bits(reader.read_pointer(strip_pac(address))?);
            if obj == 0 {
                return Ok("nil".to_string());
            }
            let isa = strip_object_bits(reader.read_pointer(obj)?);
            let name = type_name(reader, isa).unwrap_or_else(|_| format!("<isa {isa:#x}>"));
            Ok(format!("{} @ {obj:#x}", demangle_if_mangled(&name)))
        }
        SwiftTypeHint::Int => {
            let v = reader.read_u64(strip_pac(address))?;
            Ok(format!("{}", v.cast_signed()))
        }
        SwiftTypeHint::Bool => {
            let v = reader.read_u8(strip_pac(address))?;
            Ok(if v == 0 { "false".into() } else { "true".into() })
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Compose a context-descriptor flags word.
    fn ctx_flags(kind: u8, generic: bool) -> u32 {
        u32::from(kind) | if generic { 1 << 7 } else { 0 }
    }

    /// Write a relative pointer at `at` aiming at `target`.
    fn rel(mem: &mut SparseMemory, at: u64, target: u64) {
        let off = i64::try_from(target).unwrap() - i64::try_from(at).unwrap();
        mem.write_u32(at, i32::try_from(off).unwrap() as u32);
    }

    /// Build a module descriptor named `name` at `at`.
    fn module_descriptor(mem: &mut SparseMemory, at: u64, name_at: u64, name: &str) {
        mem.write_u32(at + CTX_FLAGS_OFFSET, ctx_flags(0, false));
        mem.write_u32(at + CTX_PARENT_OFFSET, 0);
        rel(mem, at + CTX_NAME_OFFSET, name_at);
        mem.write_cstring(name_at, name);
    }

    /// Build a struct descriptor with `parent`.
    fn struct_descriptor(
        mem: &mut SparseMemory,
        at: u64,
        parent: u64,
        name_at: u64,
        name: &str,
    ) {
        mem.write_u32(at + CTX_FLAGS_OFFSET, ctx_flags(17, false));
        rel(mem, at + CTX_PARENT_OFFSET, parent);
        rel(mem, at + CTX_NAME_OFFSET, name_at);
        mem.write_u32(at + CTX_ACCESS_FUNCTION_OFFSET, 0);
        mem.write_u32(at + CTX_FIELDS_OFFSET, 0);
        mem.write_cstring(name_at, name);
    }

    #[test]
    fn sparse_memory_reads_and_reports_holes() {
        let mut m = SparseMemory::new();
        m.write(0x1000, vec![1, 2, 3, 4]);
        assert_eq!(m.read_bytes(0x1000, 4).unwrap(), vec![1, 2, 3, 4]);
        assert_eq!(m.read_bytes(0x1001, 2).unwrap(), vec![2, 3]);
        assert!(m.read_bytes(0x1000, 5).is_err());
        assert!(!m.is_readable(0x1000, 5));
        assert!(m.is_readable(0x1000, 4));
    }

    #[test]
    fn cstring_spans_chunk_boundary() {
        let mut m = SparseMemory::new();
        let long = "a".repeat(100);
        m.write_cstring(0x2000, &long);
        assert_eq!(m.read_cstring(0x2000, 1024).unwrap(), long);
    }

    #[test]
    fn cstring_without_terminator_errors() {
        let mut m = SparseMemory::new();
        m.write(0x3000, vec![b'x'; 32]);
        assert!(matches!(
            m.read_cstring(0x3000, 32),
            Err(SwiftRuntimeError::UnterminatedString { .. })
        ));
    }

    #[test]
    fn metadata_kind_decoding() {
        assert_eq!(SwiftMetadataKind::from_raw(0), Some(SwiftMetadataKind::Class));
        assert_eq!(SwiftMetadataKind::from_raw(0x200), Some(SwiftMetadataKind::Struct));
        assert_eq!(SwiftMetadataKind::from_raw(0x202), Some(SwiftMetadataKind::Optional));
        assert_eq!(SwiftMetadataKind::from_raw(0x303), Some(SwiftMetadataKind::Existential));
        // An isa pointer means class, not an unknown kind.
        assert_eq!(
            SwiftMetadataKind::from_raw(0x0000_0001_0AB0_1234),
            Some(SwiftMetadataKind::Class)
        );
        // Reserved-but-undefined value in the enumerated range.
        assert_eq!(SwiftMetadataKind::from_raw(0x2FF), None);
    }

    #[test]
    fn metadata_kind_properties() {
        assert!(SwiftMetadataKind::Struct.is_nominal());
        assert!(!SwiftMetadataKind::Tuple.is_nominal());
        assert!(SwiftMetadataKind::Class.is_heap());
        assert!(!SwiftMetadataKind::Struct.is_heap());
        assert!(SwiftMetadataKind::Struct.is_non_heap_flagged());
        assert_eq!(SwiftMetadataKind::Enum.raw(), 0x201);
        assert_eq!(SwiftMetadataKind::Optional.to_string(), "optional");
    }

    #[test]
    fn struct_metadata_finds_its_descriptor() {
        let mut m = SparseMemory::new();
        m.write_u64(0x4000, SwiftMetadataKind::Struct.raw());
        m.write_u64(0x4000 + STRUCT_DESCRIPTOR_OFFSET, 0x5000);
        let md = TypeMetadata::read(&m, 0x4000).unwrap();
        assert_eq!(md.kind, SwiftMetadataKind::Struct);
        assert_eq!(md.descriptor, Some(0x5000));
        assert_eq!(md.require_descriptor().unwrap(), 0x5000);
    }

    #[test]
    fn class_metadata_uses_the_class_descriptor_offset() {
        let mut m = SparseMemory::new();
        // A realized class keeps an isa pointer in word 0.
        m.write_u64(0x6000, 0x0000_0000_7FF0_0000);
        m.write_u64(0x6000 + CLASS_DESCRIPTOR_OFFSET, 0x7000);
        let md = TypeMetadata::read(&m, 0x6000).unwrap();
        assert_eq!(md.kind, SwiftMetadataKind::Class);
        assert_eq!(md.descriptor, Some(0x7000));
    }

    #[test]
    fn value_witness_table_sits_before_the_address_point() {
        let mut m = SparseMemory::new();
        m.write_u64(0x8000 - 8, 0xDEAD_0000);
        m.write_u64(0x8000, SwiftMetadataKind::Struct.raw());
        m.write_u64(0x8000 + STRUCT_DESCRIPTOR_OFFSET, 0);
        let md = TypeMetadata::read(&m, 0x8000).unwrap();
        assert_eq!(md.value_witness_table(&m).unwrap(), 0xDEAD_0000);
        // Null descriptor is reported, not silently treated as absent-but-fine.
        assert!(matches!(
            md.require_descriptor(),
            Err(SwiftRuntimeError::NullPointer { .. })
        ));
    }

    #[test]
    fn non_nominal_metadata_refuses_a_descriptor() {
        let mut m = SparseMemory::new();
        m.write_u64(0x9000, SwiftMetadataKind::Tuple.raw());
        let md = TypeMetadata::read(&m, 0x9000).unwrap();
        assert_eq!(md.descriptor, None);
        assert!(matches!(
            md.require_descriptor(),
            Err(SwiftRuntimeError::NotNominal { kind: SwiftMetadataKind::Tuple, .. })
        ));
    }

    #[test]
    fn unknown_metadata_kind_is_an_error_not_a_guess() {
        let mut m = SparseMemory::new();
        m.write_u64(0xA000, 0x2FF);
        assert!(matches!(
            TypeMetadata::read(&m, 0xA000),
            Err(SwiftRuntimeError::UnknownMetadataKind { raw: 0x2FF, .. })
        ));
    }

    #[test]
    fn relative_pointers_resolve_forward_and_backward() {
        let mut m = SparseMemory::new();
        rel(&mut m, 0x1_0000, 0x1_0100);
        assert_eq!(read_relative_pointer(&m, 0x1_0000).unwrap(), Some(0x1_0100));
        rel(&mut m, 0x1_0200, 0x1_0100);
        assert_eq!(read_relative_pointer(&m, 0x1_0200).unwrap(), Some(0x1_0100));
        m.write_u32(0x1_0300, 0);
        assert_eq!(read_relative_pointer(&m, 0x1_0300).unwrap(), None);
    }

    #[test]
    fn indirectable_relative_pointer_dereferences_when_tagged() {
        let mut m = SparseMemory::new();
        // Direct: offset +0x40, low bit clear.
        m.write_u32(0x2_0000, 0x40);
        assert_eq!(
            read_relative_indirectable_pointer(&m, 0x2_0000).unwrap(),
            Some(0x2_0040)
        );
        // Indirect: offset +0x40 with low bit set -> read the pointer there.
        m.write_u32(0x2_1000, 0x41);
        m.write_u64(0x2_1040, 0xCAFE_0000);
        assert_eq!(
            read_relative_indirectable_pointer(&m, 0x2_1000).unwrap(),
            Some(0xCAFE_0000)
        );
    }

    #[test]
    fn qualified_name_walks_the_parent_chain() {
        let mut m = SparseMemory::new();
        module_descriptor(&mut m, 0x3_0000, 0x3_0800, "MyApp");
        struct_descriptor(&mut m, 0x3_1000, 0x3_0000, 0x3_1800, "Outer");
        struct_descriptor(&mut m, 0x3_2000, 0x3_1000, 0x3_2800, "Inner");
        assert_eq!(
            qualified_type_name(&m, 0x3_2000).unwrap(),
            "MyApp.Outer.Inner"
        );
    }

    /// The module could only be reached from a live target TRANSITIVELY,
    /// through `ObjcMemoryAdapter` over an `ObjcMemory` — and until iter 261
    /// the only `ObjcMemory` was an in-process test container. This walks the
    /// whole live-shaped chain: a closure (what a debugger supplies) ->
    /// `ReaderMemory` -> `ObjcMemoryAdapter` -> `type_name`.
    #[test]
    fn type_name_resolves_through_a_live_shaped_reader_chain() {
        use crate::ios::objc_runtime::ReaderMemory;

        // The same fixture `type_name_from_metadata` uses, but reached the way
        // a real session would rather than by handing over the store itself.
        let mut store = SparseMemory::new();
        module_descriptor(&mut store, 0x4_0000, 0x4_0800, "Demo");
        struct_descriptor(&mut store, 0x4_1000, 0x4_0000, 0x4_1800, "Point");
        store.write_u64(0x4_2000, SwiftMetadataKind::Struct.raw());
        store.write_u64(0x4_2000 + STRUCT_DESCRIPTOR_OFFSET, 0x4_1000);
        // An instance whose first word points at that metadata.
        store.write_u64(0x9_0000, 0x4_2000);

        let mem = ReaderMemory(|addr: u64, len: usize| {
            SwiftMemoryReader::read_bytes(&store, addr, len).ok()
        });
        let reader = ObjcMemoryAdapter(&mem);

        let metadata = reader.read_u64(0x9_0000).expect("instance's first word");
        assert_eq!(metadata, 0x4_2000);
        assert_eq!(
            type_name(&reader, metadata).unwrap(),
            "Demo.Point",
            "the Swift runtime did not resolve through the live-shaped reader chain"
        );
    }

    #[test]
    fn type_name_from_metadata() {
        let mut m = SparseMemory::new();
        module_descriptor(&mut m, 0x4_0000, 0x4_0800, "Demo");
        struct_descriptor(&mut m, 0x4_1000, 0x4_0000, 0x4_1800, "Point");
        m.write_u64(0x4_2000, SwiftMetadataKind::Struct.raw());
        m.write_u64(0x4_2000 + STRUCT_DESCRIPTOR_OFFSET, 0x4_1000);
        assert_eq!(type_name(&m, 0x4_2000).unwrap(), "Demo.Point");
    }

    #[test]
    fn descriptor_flags_are_decoded() {
        let mut m = SparseMemory::new();
        m.write_u32(0x5_0000 + CTX_FLAGS_OFFSET, ctx_flags(18, true) | (1 << 6) | (3 << 8));
        m.write_u32(0x5_0000 + CTX_PARENT_OFFSET, 0);
        rel(&mut m, 0x5_0000 + CTX_NAME_OFFSET, 0x5_0800);
        m.write_u32(0x5_0000 + CTX_ACCESS_FUNCTION_OFFSET, 0);
        m.write_u32(0x5_0000 + CTX_FIELDS_OFFSET, 0);
        m.write_cstring(0x5_0800, "Color");
        let d = NominalTypeDescriptor::read(&m, 0x5_0000).unwrap();
        assert_eq!(d.kind, ContextDescriptorKind::Enum);
        assert!(d.is_generic);
        assert!(d.is_unique);
        assert_eq!(d.version, 3);
        assert_eq!(d.name.as_deref(), Some("Color"));
        assert!(d.parent.is_none());
    }

    #[test]
    fn unknown_context_kind_is_rejected() {
        let mut m = SparseMemory::new();
        m.write_u32(0x6_0000, 9); // no such context kind
        assert!(matches!(
            NominalTypeDescriptor::read(&m, 0x6_0000),
            Err(SwiftRuntimeError::UnknownContextKind { raw: 9, .. })
        ));
    }

    #[test]
    fn context_cycle_is_caught() {
        let mut m = SparseMemory::new();
        // Two struct descriptors pointing at each other.
        struct_descriptor(&mut m, 0x7_0000, 0x7_1000, 0x7_0800, "A");
        struct_descriptor(&mut m, 0x7_1000, 0x7_0000, 0x7_1800, "B");
        assert!(matches!(
            qualified_type_name(&m, 0x7_0000),
            Err(SwiftRuntimeError::ChainTooDeep { .. })
        ));
    }

    #[test]
    fn context_kind_classification() {
        assert!(ContextDescriptorKind::Struct.is_type());
        assert!(!ContextDescriptorKind::Module.is_type());
        assert!(ContextDescriptorKind::Module.has_name());
        assert!(!ContextDescriptorKind::Extension.has_name());
        assert_eq!(ContextDescriptorKind::from_raw(31), None);
        assert_eq!(ContextDescriptorKind::Class.to_string(), "class");
    }

    #[test]
    fn opaque_existential_exposes_metadata_and_witnesses() {
        let mut m = SparseMemory::new();
        m.write_u64(0x8_0000, 0x11);
        m.write_u64(0x8_0008, 0x22);
        m.write_u64(0x8_0010, 0x33);
        m.write_u64(0x8_0018, 0x9_0000); // metadata
        m.write_u64(0x8_0020, 0xAA_0000); // witness table 0
        let c = ExistentialContainer::read(&m, 0x8_0000, 1).unwrap();
        assert_eq!(c.metadata, 0x9_0000);
        assert_eq!(c.witness_tables, vec![0xAA_0000]);
        assert_eq!(c.payload_address(&m, false).unwrap(), 0x8_0000);
    }

    #[test]
    fn boxed_existential_payload_skips_the_object_header() {
        let mut m = SparseMemory::new();
        m.write_u64(0x8_1000, 0xB0_0000); // box pointer
        m.write_u64(0x8_1018, 0);
        let c = ExistentialContainer::read(&m, 0x8_1000, 0).unwrap();
        assert_eq!(c.payload_address(&m, true).unwrap(), 0xB0_0000 + 16);
    }

    #[test]
    fn existential_dynamic_type_name() {
        let mut m = SparseMemory::new();
        module_descriptor(&mut m, 0x9_0000, 0x9_0800, "Lib");
        struct_descriptor(&mut m, 0x9_1000, 0x9_0000, 0x9_1800, "Widget");
        m.write_u64(0x9_2000, SwiftMetadataKind::Struct.raw());
        m.write_u64(0x9_2000 + STRUCT_DESCRIPTOR_OFFSET, 0x9_1000);
        for i in 0..3u64 {
            m.write_u64(0x9_3000 + i * 8, 0);
        }
        m.write_u64(0x9_3018, 0x9_2000);
        let c = ExistentialContainer::read(&m, 0x9_3000, 0).unwrap();
        assert_eq!(c.dynamic_type_name(&m).unwrap(), "Lib.Widget");
    }

    #[test]
    fn class_existential_reads_object_and_isa() {
        let mut m = SparseMemory::new();
        m.write_u64(0xA_0000, 0xA_1000); // object
        m.write_u64(0xA_0008, 0xA_2000); // witness table
        m.write_u64(0xA_1000, 0xA_3000); // isa
        let c = ClassExistentialContainer::read(&m, 0xA_0000, 1).unwrap();
        assert_eq!(c.object, 0xA_1000);
        assert_eq!(c.witness_tables, vec![0xA_2000]);
        assert_eq!(c.dynamic_metadata(&m).unwrap(), 0xA_3000);
    }

    #[test]
    fn null_class_existential_is_reported() {
        let mut m = SparseMemory::new();
        m.write_u64(0xB_0000, 0);
        let c = ClassExistentialContainer::read(&m, 0xB_0000, 0).unwrap();
        assert!(matches!(
            c.dynamic_metadata(&m),
            Err(SwiftRuntimeError::NullPointer { .. })
        ));
    }

    /// Lay out a small `Swift.String` holding `s` at `at`.
    fn small_string(mem: &mut SparseMemory, at: u64, s: &str) {
        assert!(s.len() <= SMALL_STRING_CAPACITY);
        let mut raw = [0u8; 16];
        raw[..s.len()].copy_from_slice(s.as_bytes());
        // Discriminator: small (0x20) | count nibble, in the top byte.
        raw[15] = STR_DISC_SMALL | u8::try_from(s.len()).unwrap();
        mem.write(at, raw.to_vec());
    }

    #[test]
    fn small_string_round_trip() {
        let mut m = SparseMemory::new();
        small_string(&mut m, 0xC_0000, "hello");
        let s = SwiftString::read(&m, 0xC_0000).unwrap();
        assert_eq!(s.form, SwiftStringForm::Small);
        assert_eq!(s.count, 5);
        assert_eq!(s.contents(&m).unwrap(), "hello");
        assert!(s.utf8_start().is_err());
    }

    #[test]
    fn native_large_string_with_absurd_count_is_refused_not_allocated() {
        let mut m = SparseMemory::new();
        // Header: count word claims ~2^47 bytes, object word is a plain
        // native-large pointer (no discriminator bits set).
        m.write_u64(0xD_0000, 0x0000_7FFF_FFFF_FFFF);
        m.write_u64(0xD_0008, 0xE_0000);
        let s = SwiftString::read(&m, 0xD_0000).unwrap();
        assert_eq!(s.form, SwiftStringForm::NativeLarge);
        assert!(matches!(
            s.contents(&m),
            Err(SwiftRuntimeError::StringTooLong { .. })
        ));
    }

    #[test]
    fn small_string_at_capacity() {
        let mut m = SparseMemory::new();
        let fifteen = "abcdefghijklmno";
        small_string(&mut m, 0xC_1000, fifteen);
        let s = SwiftString::read(&m, 0xC_1000).unwrap();
        assert_eq!(s.count, SMALL_STRING_CAPACITY);
        assert_eq!(s.contents(&m).unwrap(), fifteen);
    }

    #[test]
    fn empty_small_string() {
        let mut m = SparseMemory::new();
        small_string(&mut m, 0xC_2000, "");
        let s = SwiftString::read(&m, 0xC_2000).unwrap();
        assert_eq!(s.count, 0);
        assert_eq!(s.contents(&m).unwrap(), "");
    }

    #[test]
    fn large_native_string_reads_from_storage() {
        let mut m = SparseMemory::new();
        let text = "a rather longer string than fifteen bytes";
        let storage = 0xD_0000u64;
        m.write_u64(0xD_8000, text.len() as u64); // _countAndFlagsBits
        m.write_u64(0xD_8008, storage); // _object, native discriminator = 0
        m.write(storage + NATIVE_STRING_STORAGE_HEADER, text.as_bytes().to_vec());
        let s = SwiftString::read(&m, 0xD_8000).unwrap();
        assert_eq!(s.form, SwiftStringForm::NativeLarge);
        assert_eq!(s.count, text.len());
        assert_eq!(s.utf8_start().unwrap(), storage + 32);
        assert_eq!(s.contents(&m).unwrap(), text);
    }

    #[test]
    fn foreign_and_shared_strings_error_explicitly() {
        let mut m = SparseMemory::new();
        m.write_u64(0xE_0000, 10);
        m.write_u64(0xE_0008, u64::from(STR_DISC_FOREIGN) << 56 | 0x1234);
        let s = SwiftString::read(&m, 0xE_0000).unwrap();
        assert_eq!(s.form, SwiftStringForm::Foreign);
        assert!(matches!(
            s.contents(&m),
            Err(SwiftRuntimeError::UnsupportedStringForm { .. })
        ));

        m.write_u64(0xE_1000, 10);
        m.write_u64(0xE_1008, u64::from(STR_DISC_SHARED) << 56 | 0x1234);
        let s2 = SwiftString::read(&m, 0xE_1000).unwrap();
        assert_eq!(s2.form, SwiftStringForm::Shared);
        assert!(s2.contents(&m).is_err());
    }

    #[test]
    fn immortal_flag_is_surfaced() {
        let mut m = SparseMemory::new();
        m.write_u64(0xE_2000, 4);
        m.write_u64(0xE_2008, u64::from(STR_DISC_IMMORTAL) << 56 | 0x5000);
        let s = SwiftString::read(&m, 0xE_2000).unwrap();
        assert!(s.is_immortal);
        assert_eq!(s.form, SwiftStringForm::NativeLarge);
    }

    #[test]
    fn array_header_and_elements() {
        let mut m = SparseMemory::new();
        let storage = 0xF_0000u64;
        m.write_u64(0xF_8000, storage);
        m.write_u64(storage + ARRAY_COUNT_OFFSET, 3);
        m.write_u64(storage + ARRAY_CAPACITY_OFFSET, 8);
        for (i, v) in [10u64, 20, 30].into_iter().enumerate() {
            m.write_u64(storage + ARRAY_ELEMENTS_OFFSET + (i as u64) * 8, v);
        }
        let a = SwiftArray::read(&m, 0xF_8000).unwrap();
        assert_eq!(a.count, 3);
        assert_eq!(a.capacity_and_flags, 8);
        assert_eq!(a.elements, storage + 32);
        assert_eq!(a.element_words(&m, 16).unwrap(), vec![10, 20, 30]);
        // The cap really caps.
        assert_eq!(a.element_words(&m, 2).unwrap(), vec![10, 20]);
        assert_eq!(a.element_address(2, 8), storage + 32 + 16);
    }

    #[test]
    fn array_element_bytes_uses_stride() {
        let mut m = SparseMemory::new();
        let storage = 0x10_0000u64;
        m.write_u64(0x10_8000, storage);
        m.write_u64(storage + ARRAY_COUNT_OFFSET, 2);
        m.write_u64(storage + ARRAY_CAPACITY_OFFSET, 2);
        m.write(storage + ARRAY_ELEMENTS_OFFSET, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let a = SwiftArray::read(&m, 0x10_8000).unwrap();
        assert_eq!(
            a.element_bytes(&m, 4, 16).unwrap(),
            vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]]
        );
    }

    #[test]
    fn null_array_buffer_errors() {
        let mut m = SparseMemory::new();
        m.write_u64(0x11_0000, 0);
        assert!(matches!(
            SwiftArray::read(&m, 0x11_0000),
            Err(SwiftRuntimeError::NullPointer { .. })
        ));
    }

    #[test]
    fn optional_pointer_none_and_some() {
        let mut m = SparseMemory::new();
        m.write_u64(0x12_0000, 0);
        m.write_u64(0x12_0008, 0xABCD);
        assert_eq!(read_optional_pointer(&m, 0x12_0000).unwrap(), OptionalPointer::None);
        assert!(read_optional_pointer(&m, 0x12_0000).unwrap().is_none());
        assert_eq!(
            read_optional_pointer(&m, 0x12_0008).unwrap(),
            OptionalPointer::Some(0xABCD)
        );
        assert_eq!(
            read_optional_pointer(&m, 0x12_0008).unwrap().payload(),
            Some(0xABCD)
        );
    }

    #[test]
    fn optional_with_out_of_line_tag() {
        let mut m = SparseMemory::new();
        // .some(0x2A) as an Int? : 8 payload bytes then tag 0.
        m.write_u64(0x13_0000, 42);
        m.write(0x13_0008, vec![0u8]);
        assert_eq!(
            read_optional_with_tag(&m, 0x13_0000, 8).unwrap(),
            Some(42u64.to_le_bytes().to_vec())
        );
        // .none : tag non-zero.
        m.write_u64(0x13_1000, 0);
        m.write(0x13_1008, vec![1u8]);
        assert_eq!(read_optional_with_tag(&m, 0x13_1000, 8).unwrap(), None);
    }

    #[test]
    fn value_witness_requirement_is_a_named_error() {
        assert!(matches!(
            optional_needs_value_witness(),
            SwiftRuntimeError::NeedsValueWitness { ty: "Optional" }
        ));
    }

    #[test]
    fn pac_stripping_is_idempotent() {
        let signed = 0x8A3F_0000_1234_5678u64;
        let stripped = strip_pac(signed);
        assert_eq!(stripped, 0x0000_0000_1234_5678);
        assert_eq!(strip_pac(stripped), stripped);
        // x86_64 user pointers survive untouched.
        assert_eq!(strip_pac(0x0000_0001_0000_4000), 0x0000_0001_0000_4000);
    }

    #[test]
    fn metadata_read_strips_pac_from_the_address() {
        let mut m = SparseMemory::new();
        m.write_u64(0x14_0000, SwiftMetadataKind::Struct.raw());
        m.write_u64(0x14_0008, 0);
        let md = TypeMetadata::read(&m, 0x9900_0000_0014_0000).unwrap();
        assert_eq!(md.address, 0x14_0000);
    }

    #[test]
    fn mangled_names_are_detected_and_routed_to_the_shared_demangler() {
        assert!(is_mangled_swift("$s4main3FooV"));
        assert!(is_mangled_swift("_$s4main3FooV"));
        assert!(is_mangled_swift("_T0"));
        assert!(!is_mangled_swift("main.Foo"));
        // A plain name passes through untouched.
        assert_eq!(demangle_if_mangled("main.Foo"), "main.Foo");
        // A mangled one must not come back empty, whatever the demangler makes of it.
        assert!(!demangle_if_mangled("$s4main3FooV").is_empty());
    }

    #[test]
    fn format_value_renders_a_string() {
        let mut m = SparseMemory::new();
        small_string(&mut m, 0x15_0000, "hi");
        assert_eq!(
            format_value(&m, 0x15_0000, SwiftTypeHint::String).unwrap(),
            "\"hi\""
        );
    }

    #[test]
    fn format_value_renders_arrays_with_a_more_marker() {
        let mut m = SparseMemory::new();
        let storage = 0x16_0000u64;
        m.write_u64(0x16_8000, storage);
        m.write_u64(storage + ARRAY_COUNT_OFFSET, 10);
        m.write_u64(storage + ARRAY_CAPACITY_OFFSET, 10);
        for i in 0..10u64 {
            m.write_u64(storage + ARRAY_ELEMENTS_OFFSET + i * 8, i);
        }
        let out = format_value(&m, 0x16_8000, SwiftTypeHint::ArrayOfWords).unwrap();
        assert!(out.starts_with("[0x0, 0x1"), "{out}");
        assert!(out.contains("2 more"), "{out}");
    }

    #[test]
    fn format_value_renders_optional_and_scalars() {
        let mut m = SparseMemory::new();
        m.write_u64(0x17_0000, 0);
        assert_eq!(
            format_value(&m, 0x17_0000, SwiftTypeHint::OptionalPointer).unwrap(),
            "nil"
        );
        m.write_u64(0x17_0008, 0x40);
        assert_eq!(
            format_value(&m, 0x17_0008, SwiftTypeHint::OptionalPointer).unwrap(),
            "Optional(0x40)"
        );
        m.write_u64(0x17_0010, (-7i64) as u64);
        assert_eq!(format_value(&m, 0x17_0010, SwiftTypeHint::Int).unwrap(), "-7");
        m.write(0x17_0018, vec![0u8]);
        assert_eq!(format_value(&m, 0x17_0018, SwiftTypeHint::Bool).unwrap(), "false");
        m.write(0x17_0019, vec![1u8]);
        assert_eq!(format_value(&m, 0x17_0019, SwiftTypeHint::Bool).unwrap(), "true");
    }

    #[test]
    fn format_value_renders_a_class_reference_by_dynamic_type() {
        let mut m = SparseMemory::new();
        module_descriptor(&mut m, 0x18_0000, 0x18_0800, "App");
        struct_descriptor(&mut m, 0x18_1000, 0x18_0000, 0x18_1800, "Model");
        // Class metadata whose descriptor slot points at the type descriptor.
        m.write_u64(0x18_2000, 0x1_0000_0000); // isa-looking word => Class
        m.write_u64(0x18_2000 + CLASS_DESCRIPTOR_OFFSET, 0x18_1000);
        m.write_u64(0x18_3000, 0x18_2000); // object's isa
        m.write_u64(0x18_4000, 0x18_3000); // the variable holding the reference
        let out = format_value(&m, 0x18_4000, SwiftTypeHint::ClassReference).unwrap();
        assert_eq!(out, "App.Model @ 0x183000");
    }

    #[test]
    fn format_value_on_a_null_class_reference_is_nil() {
        let mut m = SparseMemory::new();
        m.write_u64(0x19_0000, 0);
        assert_eq!(
            format_value(&m, 0x19_0000, SwiftTypeHint::ClassReference).unwrap(),
            "nil"
        );
    }

    #[test]
    fn format_value_renders_an_existential() {
        let mut m = SparseMemory::new();
        module_descriptor(&mut m, 0x1A_0000, 0x1A_0800, "Core");
        struct_descriptor(&mut m, 0x1A_1000, 0x1A_0000, 0x1A_1800, "Token");
        m.write_u64(0x1A_2000, SwiftMetadataKind::Struct.raw());
        m.write_u64(0x1A_2000 + STRUCT_DESCRIPTOR_OFFSET, 0x1A_1000);
        for i in 0..3u64 {
            m.write_u64(0x1A_3000 + i * 8, 0);
        }
        m.write_u64(0x1A_3018, 0x1A_2000);
        m.write_u64(0x1A_3020, 0x1A_9000); // witness table
        let out = format_value(&m, 0x1A_3000, SwiftTypeHint::Existential(1)).unwrap();
        assert_eq!(out, "Core.Token (existential)");
    }

    #[test]
    fn format_value_propagates_read_failures_instead_of_masking_them() {
        let m = SparseMemory::new();
        assert!(format_value(&m, 0x1B_0000, SwiftTypeHint::Int).is_err());
    }
}
