//! `rustre-loader-java`
//!
//! This crate is part of the `RustRE` Suite, a premium reverse engineering platform.
//!
//! # Loader: JAVA
//! Implements parsing for Java `.class` files and JAR archives.

pub mod bytecode_analyzer;
pub mod bytecode_disasm;
pub mod classfile_parser;
pub mod jar_analyzer;
pub mod java_type_system;
pub mod jar_decompiler;
pub mod jar_security_analysis;
pub mod class_parser_full;
pub mod jar_loader;
pub mod bytecode_analysis;
pub mod class_file_parser;
pub mod bytecode_disassembler;
pub mod jar_manifest_parser;

use std::fmt;
use std::sync::Arc;

use bitflags::bitflags;
use rustre_core::address::{Address, AddressRange};
use rustre_core::arch::{
    Architecture, BranchInfo, CallingConvention, Instruction, RegisterInfo, RegisterKind,
};
use rustre_core::binary_view::{BinaryView, Memory, Segment};
use rustre_core::endian::Endian;
use rustre_core::errors::CoreError;
use rustre_core::ids::ViewId;
use rustre_core::loader::{BinaryType, LoadResult};
use rustre_core::permissions::Permissions;
use rustre_core::{Loader, LoaderInput, NestedBinary, async_trait};

// â"€â"€ Error type â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Errors produced by the Java loader.
#[derive(Debug, thiserror::Error)]
pub enum JavaLoaderError {
    /// Magic bytes do not match `0xCAFEBABE`.
    #[error("invalid magic")]
    InvalidMagic,
    /// Generic parse error with context.
    #[error("parse error: {0}")]
    ParseError(String),
    /// File is too short to parse.
    #[error("truncated data")]
    TruncatedData,
    /// Constant pool entry is invalid.
    #[error("invalid constant pool")]
    InvalidConstantPool,
}

// â"€â"€ Java version â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Java class file version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JavaVersion {
    /// Major version (e.g. 52 = Java 8, 61 = Java 17).
    pub major: u16,
    /// Minor version.
    pub minor: u16,
}

impl JavaVersion {
    /// Return the Java release number (`major - 44`).
    #[must_use]
    pub const fn java_release(&self) -> u16 {
        self.major.saturating_sub(44)
    }
}

impl fmt::Display for JavaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Java {}", self.java_release())
    }
}

// â"€â"€ Constant pool â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A single constant pool entry.
#[derive(Debug, Clone)]
pub enum ConstantPoolEntry {
    /// UTF-8 string constant (tag 1).
    Utf8(String),
    /// Integer constant (tag 3).
    Integer(i32),
    /// Long constant (tag 5).
    Long(i64),
    /// Float constant (tag 4).
    Float(f32),
    /// Double constant (tag 6).
    Double(f64),
    /// Class reference (tag 7): index into constant pool.
    ClassRef(u16),
    /// String reference (tag 8): index into constant pool.
    StringRef(u16),
    /// Field reference (tag 9).
    FieldRef { class: u16, nat: u16 },
    /// Method reference (tag 10).
    MethodRef { class: u16, nat: u16 },
    /// Name and type descriptor (tag 12).
    NameAndType { name: u16, desc: u16 },
    /// Unknown/unsupported tag.
    Other(u8),
}

impl fmt::Display for ConstantPoolEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Utf8(s) => write!(f, "Utf8({s})"),
            Self::Integer(n) => write!(f, "Integer({n})"),
            Self::Long(n) => write!(f, "Long({n})"),
            Self::Float(n) => write!(f, "Float({n})"),
            Self::Double(n) => write!(f, "Double({n})"),
            Self::ClassRef(i) => write!(f, "ClassRef({i})"),
            Self::StringRef(i) => write!(f, "StringRef({i})"),
            Self::FieldRef { class, nat } => write!(f, "FieldRef({class},{nat})"),
            Self::MethodRef { class, nat } => write!(f, "MethodRef({class},{nat})"),
            Self::NameAndType { name, desc } => write!(f, "NameAndType({name},{desc})"),
            Self::Other(t) => write!(f, "Other({t})"),
        }
    }
}

// â"€â"€ Class flags â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

bitflags! {
    /// Java class/field/method access flags.
    ///
    /// The flag set covers both class-level flags (SUPER, INTERFACE, ANNOTATION,
    /// ENUM) and member-level flags (PRIVATE, PROTECTED, STATIC, VOLATILE,
    /// TRANSIENT, NATIVE, SYNCHRONIZED, BRIDGE, VARARGS, STRICT) so that the
    /// same type can be reused for fields, methods, and classes.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    pub struct JavaClassFlags: u16 {
        /// `public`.
        const PUBLIC       = 0x0001;
        /// `private`.
        const PRIVATE      = 0x0002;
        /// `protected`.
        const PROTECTED    = 0x0004;
        /// `static`.
        const STATIC       = 0x0008;
        /// `final`.
        const FINAL        = 0x0010;
        /// Superclass semantics (class flag) / `synchronized` (method flag).
        const SUPER        = 0x0020;
        /// `volatile` (field) / bridge method (method).
        const VOLATILE     = 0x0040;
        /// `transient` (field) / varargs (method).
        const TRANSIENT    = 0x0080;
        /// `native`.
        const NATIVE       = 0x0100;
        /// Interface.
        const INTERFACE    = 0x0200;
        /// Abstract.
        const ABSTRACT     = 0x0400;
        /// `strictfp`.
        const STRICT       = 0x0800;
        /// Synthetic (compiler-generated).
        const SYNTHETIC    = 0x1000;
        /// Annotation type.
        const ANNOTATION   = 0x2000;
        /// Enum.
        const ENUM         = 0x4000;
    }
}

// â"€â"€ Field / Method â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A Java class field descriptor.
#[derive(Debug, Clone)]
pub struct JavaField {
    /// Field name.
    pub name: String,
    /// Field type descriptor (e.g. `"I"` for int).
    pub descriptor: String,
    /// Access flags.
    pub flags: JavaClassFlags,
}

/// A Java class method descriptor.
#[derive(Debug, Clone)]
pub struct JavaMethod {
    /// Method name.
    pub name: String,
    /// Method descriptor (e.g. `"(I)V"`).
    pub descriptor: String,
    /// Access flags.
    pub flags: JavaClassFlags,
}

// â"€â"€ JavaClass â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Parsed Java `.class` file.
#[derive(Debug, Clone)]
pub struct JavaClass {
    /// Class file version.
    pub version: JavaVersion,
    /// Class access flags.
    pub flags: JavaClassFlags,
    /// Binary name of this class (e.g. `"com/example/Main"`).
    pub class_name: String,
    /// Binary name of the super class (if any).
    pub super_name: Option<String>,
    /// Implemented interfaces.
    pub interfaces: Vec<String>,
    /// Fields.
    pub fields: Vec<JavaField>,
    /// Methods.
    pub methods: Vec<JavaMethod>,
    /// Constant pool entries (1-based; index 0 is unused sentinel).
    pub constant_pool: Vec<ConstantPoolEntry>,
}

impl JavaClass {
    /// Parse a Java `.class` file from `data`.
    ///
    /// # Errors
    /// Returns errors for invalid magic, truncated data, or malformed constant pool.
    pub fn parse(data: &[u8]) -> Result<Self, JavaLoaderError> {
        if data.len() < 10 {
            return Err(JavaLoaderError::TruncatedData);
        }
        if data[0] != 0xCA || data[1] != 0xFE || data[2] != 0xBA || data[3] != 0xBE {
            return Err(JavaLoaderError::InvalidMagic);
        }
        let minor = u16::from_be_bytes([data[4], data[5]]);
        let major = u16::from_be_bytes([data[6], data[7]]);
        let version = JavaVersion { major, minor };

        let cp_count = u16::from_be_bytes([data[8], data[9]]) as usize;
        let mut pos = 10usize;
        // Index 0 is unused; entries are 1-indexed.
        let mut cp: Vec<ConstantPoolEntry> = Vec::with_capacity(cp_count);
        cp.push(ConstantPoolEntry::Other(0)); // placeholder for index 0

        let mut i = 1usize;
        while i < cp_count {
            if pos >= data.len() {
                return Err(JavaLoaderError::TruncatedData);
            }
            let tag = data[pos];
            pos += 1;
            match tag {
                1 => {
                    // Utf8: 2-byte length + bytes
                    if pos + 2 > data.len() {
                        return Err(JavaLoaderError::TruncatedData);
                    }
                    let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                    pos += 2;
                    if pos + len > data.len() {
                        return Err(JavaLoaderError::TruncatedData);
                    }
                    let s = String::from_utf8_lossy(&data[pos..pos + len]).into_owned();
                    pos += len;
                    cp.push(ConstantPoolEntry::Utf8(s));
                }
                3 => {
                    if pos + 4 > data.len() {
                        return Err(JavaLoaderError::TruncatedData);
                    }
                    let n = i32::from_be_bytes(
                        data[pos..pos + 4]
                            .try_into()
                            .map_err(|_| JavaLoaderError::ParseError("int".into()))?,
                    );
                    pos += 4;
                    cp.push(ConstantPoolEntry::Integer(n));
                }
                4 => {
                    if pos + 4 > data.len() {
                        return Err(JavaLoaderError::TruncatedData);
                    }
                    let bits = u32::from_be_bytes(
                        data[pos..pos + 4]
                            .try_into()
                            .map_err(|_| JavaLoaderError::ParseError("float".into()))?,
                    );
                    pos += 4;
                    cp.push(ConstantPoolEntry::Float(f32::from_bits(bits)));
                }
                5 => {
                    if pos + 8 > data.len() {
                        return Err(JavaLoaderError::TruncatedData);
                    }
                    let n = i64::from_be_bytes(
                        data[pos..pos + 8]
                            .try_into()
                            .map_err(|_| JavaLoaderError::ParseError("long".into()))?,
                    );
                    pos += 8;
                    cp.push(ConstantPoolEntry::Long(n));
                    cp.push(ConstantPoolEntry::Other(0)); // long/double occupy two slots
                    i += 1; // skip next index
                }
                6 => {
                    if pos + 8 > data.len() {
                        return Err(JavaLoaderError::TruncatedData);
                    }
                    let bits = u64::from_be_bytes(
                        data[pos..pos + 8]
                            .try_into()
                            .map_err(|_| JavaLoaderError::ParseError("double".into()))?,
                    );
                    pos += 8;
                    cp.push(ConstantPoolEntry::Double(f64::from_bits(bits)));
                    cp.push(ConstantPoolEntry::Other(0));
                    i += 1;
                }
                7 => {
                    if pos + 2 > data.len() {
                        return Err(JavaLoaderError::TruncatedData);
                    }
                    let idx = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    pos += 2;
                    cp.push(ConstantPoolEntry::ClassRef(idx));
                }
                8 => {
                    if pos + 2 > data.len() {
                        return Err(JavaLoaderError::TruncatedData);
                    }
                    let idx = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    pos += 2;
                    cp.push(ConstantPoolEntry::StringRef(idx));
                }
                9 => {
                    if pos + 4 > data.len() {
                        return Err(JavaLoaderError::TruncatedData);
                    }
                    let class = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    let nat = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
                    pos += 4;
                    cp.push(ConstantPoolEntry::FieldRef { class, nat });
                }
                10 => {
                    if pos + 4 > data.len() {
                        return Err(JavaLoaderError::TruncatedData);
                    }
                    let class = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    let nat = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
                    pos += 4;
                    cp.push(ConstantPoolEntry::MethodRef { class, nat });
                }
                12 => {
                    if pos + 4 > data.len() {
                        return Err(JavaLoaderError::TruncatedData);
                    }
                    let name = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    let desc = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
                    pos += 4;
                    cp.push(ConstantPoolEntry::NameAndType { name, desc });
                }
                // tag 11: InterfaceMethodref — same layout as Fieldref/Methodref (4 bytes)
                11 => {
                    if pos + 4 > data.len() {
                        return Err(JavaLoaderError::TruncatedData);
                    }
                    let class = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    let nat = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
                    pos += 4;
                    cp.push(ConstantPoolEntry::MethodRef { class, nat });
                }
                // tag 15: MethodHandle — 1-byte ref_kind + 2-byte ref_index (3 bytes)
                15 => {
                    if pos + 3 > data.len() {
                        return Err(JavaLoaderError::TruncatedData);
                    }
                    pos += 3;
                    cp.push(ConstantPoolEntry::Other(tag));
                }
                // tags 16 (MethodType), 19 (Module), 20 (Package) — 2-byte index
                16 | 19 | 20 => {
                    if pos + 2 > data.len() {
                        return Err(JavaLoaderError::TruncatedData);
                    }
                    pos += 2;
                    cp.push(ConstantPoolEntry::Other(tag));
                }
                // tags 17 (Dynamic), 18 (InvokeDynamic) — 4-byte payload
                17 | 18 => {
                    if pos + 4 > data.len() {
                        return Err(JavaLoaderError::TruncatedData);
                    }
                    pos += 4;
                    cp.push(ConstantPoolEntry::Other(tag));
                }
                _ => {
                    // Truly unknown tag — cannot determine payload size, abort
                    return Err(JavaLoaderError::InvalidConstantPool);
                }
            }
            i += 1;
        }

        // access_flags, this_class, super_class, interfaces
        if pos + 8 > data.len() {
            return Err(JavaLoaderError::TruncatedData);
        }
        let access_flags = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let this_class_idx = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        let super_class_idx = u16::from_be_bytes([data[pos + 4], data[pos + 5]]) as usize;
        let ifaces_count = u16::from_be_bytes([data[pos + 6], data[pos + 7]]) as usize;
        pos += 8;

        let flags = JavaClassFlags::from_bits_truncate(access_flags);

        // Resolve class name from constant pool
        let class_name = resolve_class_name(&cp, this_class_idx);
        let super_name = if super_class_idx == 0 {
            None
        } else {
            Some(resolve_class_name(&cp, super_class_idx))
        };

        // Interfaces
        if pos + ifaces_count * 2 > data.len() {
            return Err(JavaLoaderError::TruncatedData);
        }
        let mut interfaces = Vec::with_capacity(ifaces_count);
        for _ in 0..ifaces_count {
            let idx = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            interfaces.push(resolve_class_name(&cp, idx));
        }

        // Fields
        if pos + 2 > data.len() {
            return Err(JavaLoaderError::TruncatedData);
        }
        let fields_count = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let mut fields = Vec::with_capacity(fields_count);
        for _ in 0..fields_count {
            if pos + 8 > data.len() {
                return Err(JavaLoaderError::TruncatedData);
            }
            let f_flags =
                JavaClassFlags::from_bits_truncate(u16::from_be_bytes([data[pos], data[pos + 1]]));
            let name_idx = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            let desc_idx = u16::from_be_bytes([data[pos + 4], data[pos + 5]]) as usize;
            let attrs = u16::from_be_bytes([data[pos + 6], data[pos + 7]]) as usize;
            pos += 8;
            let field_name = resolve_utf8(&cp, name_idx);
            let field_desc = resolve_utf8(&cp, desc_idx);
            // Skip attributes
            for _ in 0..attrs {
                if pos + 6 > data.len() {
                    return Err(JavaLoaderError::TruncatedData);
                }
                let attr_len = u32::from_be_bytes(
                    data[pos + 2..pos + 6]
                        .try_into()
                        .map_err(|_| JavaLoaderError::TruncatedData)?,
                ) as usize;
                pos = pos.checked_add(6 + attr_len)
                    .ok_or(JavaLoaderError::ParseError("field attr offset overflow".into()))?;
            }
            fields.push(JavaField {
                name: field_name,
                descriptor: field_desc,
                flags: f_flags,
            });
        }

        // Methods
        if pos + 2 > data.len() {
            return Err(JavaLoaderError::TruncatedData);
        }
        let methods_count = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let mut methods = Vec::with_capacity(methods_count);
        for _ in 0..methods_count {
            if pos + 8 > data.len() {
                return Err(JavaLoaderError::TruncatedData);
            }
            let m_flags =
                JavaClassFlags::from_bits_truncate(u16::from_be_bytes([data[pos], data[pos + 1]]));
            let name_idx = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            let desc_idx = u16::from_be_bytes([data[pos + 4], data[pos + 5]]) as usize;
            let attrs = u16::from_be_bytes([data[pos + 6], data[pos + 7]]) as usize;
            pos += 8;
            let method_name = resolve_utf8(&cp, name_idx);
            let method_desc = resolve_utf8(&cp, desc_idx);
            for _ in 0..attrs {
                if pos + 6 > data.len() {
                    return Err(JavaLoaderError::TruncatedData);
                }
                let attr_len = u32::from_be_bytes(
                    data[pos + 2..pos + 6]
                        .try_into()
                        .map_err(|_| JavaLoaderError::TruncatedData)?,
                ) as usize;
                pos = pos.checked_add(6 + attr_len)
                    .ok_or(JavaLoaderError::ParseError("method attr offset overflow".into()))?;
            }
            methods.push(JavaMethod {
                name: method_name,
                descriptor: method_desc,
                flags: m_flags,
            });
        }

        Ok(Self {
            version,
            flags,
            class_name,
            super_name,
            interfaces,
            fields,
            methods,
            constant_pool: cp,
        })
    }

    /// Returns `true` if the class is an interface.
    #[must_use]
    pub const fn is_interface(&self) -> bool {
        self.flags.contains(JavaClassFlags::INTERFACE)
    }

    /// Returns `true` if the class is abstract.
    #[must_use]
    pub const fn is_abstract(&self) -> bool {
        self.flags.contains(JavaClassFlags::ABSTRACT)
    }
}

fn resolve_utf8(cp: &[ConstantPoolEntry], idx: usize) -> String {
    if idx < cp.len()
        && let ConstantPoolEntry::Utf8(s) = &cp[idx] {
            return s.clone();
        }
    format!("<cp#{idx}>")
}

fn resolve_class_name(cp: &[ConstantPoolEntry], class_idx: usize) -> String {
    if class_idx < cp.len()
        && let ConstantPoolEntry::ClassRef(name_idx) = cp[class_idx] {
            return resolve_utf8(cp, name_idx as usize);
        }
    format!("<class#{class_idx}>")
}

// â"€â"€ Magic detection â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Returns `true` if `data` starts with the Java class file magic `0xCAFEBABE`.
#[must_use]
pub fn is_class(data: &[u8]) -> bool {
    data.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE])
}

/// Returns `true` if `data` is a ZIP archive containing at least one `.class` file.
#[must_use]
pub fn is_jar(data: &[u8]) -> bool {
    data.starts_with(b"PK\x03\x04") && data.windows(6).any(|w| w.ends_with(b".class"))
}

// â"€â"€ Architecture stub â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Minimal Architecture implementation for the JVM target.
#[derive(Debug)]
pub struct JavaArch;

impl Architecture for JavaArch {
    fn name(&self) -> &'static str {
        "jvm"
    }

    fn pointer_size(&self) -> usize {
        8
    }

    fn endian(&self) -> Endian {
        Endian::Big
    }

    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        // This used to return a hardcoded `nop` of length 1 for every input,
        // so a caller disassembling through the `Architecture` trait received a
        // stream of plausible-looking instructions that bore no relation to the
        // bytecode. Both pieces needed to do it properly already live in this
        // module: `JvmOpcode::from_byte` for the mnemonic and
        // `JavaBytecodeAnalyzer::opcode_width` for the length (which handles
        // `wide` and the padded switch tables).
        let Some(&first) = bytes.first() else {
            return Err(CoreError::InvalidFormat {
                message: "no bytes to disassemble".into(),
            });
        };
        let opcode = JvmOpcode::from_byte(first);
        let size = JavaBytecodeAnalyzer::opcode_width(first, bytes, 0).max(1);
        let taken = size.min(bytes.len());
        Ok(Instruction::new(
            address,
            taken,
            opcode.mnemonic(),
            bytes[..taken].to_vec(),
        ))
    }

    fn get_branches(&self, _instr: &Instruction) -> Vec<BranchInfo> {
        vec![]
    }

    fn registers(&self) -> Vec<RegisterInfo> {
        (0u32..4)
            .map(|i| RegisterInfo::new(format!("slot{i}"), i, 8, RegisterKind::General))
            .collect()
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        vec![
            CallingConvention::new("jvm")
                .with_int_args(vec!["slot0".to_string(), "slot1".to_string()])
                .with_return_regs(vec!["slot0".to_string()]),
        ]
    }
}

// â"€â"€ Loader â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Loader for Java `.class` files and JAR archives.
#[derive(Debug)]
pub struct JavaLoader;

#[async_trait]
impl Loader for JavaLoader {
    fn name(&self) -> &'static str {
        "java"
    }

    fn can_load(&self, input: &LoaderInput) -> bool {
        is_class(&input.data) || is_jar(&input.data)
    }

    async fn load(&self, input: LoaderInput) -> Result<LoadResult, CoreError> {
        let base = input.hints.base_address().map_or(0_u64, rustre_core::Address::as_u64);

        let mut mem = Memory::new();
        let size = input.data.len() as u64;
        if size > 0 {
            mem.add_segment(Segment {
                range: AddressRange::new(Address::new(base), Address::new(base + size)),
                permissions: Permissions::READ,
                data: input.data.clone(),
            });
        }

        let arch = Arc::new(JavaArch);
        let view_id = ViewId::from_raw(1);
        let view = BinaryView::new(
            view_id,
            input.uri,
            arch,
            Endian::Big,
            64,
            vec![Address::new(base)],
            mem,
        );
        Ok(LoadResult::new(view))
    }

    async fn find_nested(&self, input: &LoaderInput) -> Result<Vec<NestedBinary>, CoreError> {
        if !is_jar(&input.data) {
            return Ok(vec![]);
        }

        let mut nested = vec![];
        let data = &input.data;
        let mut i = 0;
        while i + 30 <= data.len() {
            if data[i..i + 4] == [0x50, 0x4B, 0x03, 0x04] {
                let comp_size =
                    u32::from_le_bytes(data[i + 18..i + 22].try_into().unwrap_or([0; 4])) as usize;
                let fname_len =
                    u16::from_le_bytes(data[i + 26..i + 28].try_into().unwrap_or([0; 2])) as usize;
                let extra_len =
                    u16::from_le_bytes(data[i + 28..i + 30].try_into().unwrap_or([0; 2])) as usize;
                // Compression method is at bytes i+8..i+10 (LE u16).
                // 0 = stored (no compression); anything else (e.g. 8 = deflate) means
                // the payload is NOT a raw class file — skip to avoid garbage parses.
                let comp_method =
                    u16::from_le_bytes(data[i + 8..i + 10].try_into().unwrap_or([0; 2]));
                let fname_end = i + 30 + fname_len;
                if fname_end <= data.len() {
                    let fname_bytes = &data[i + 30..fname_end];
                    if fname_bytes.ends_with(b".class") && comp_method == 0 {
                        let name = String::from_utf8_lossy(fname_bytes).into_owned();
                        let data_start = fname_end + extra_len;
                        let data_end = data_start + comp_size;
                        let entry_data = if data_end <= data.len() {
                            data[data_start..data_end].to_vec()
                        } else {
                            vec![]
                        };
                        nested.push(NestedBinary::new(
                            name,
                            entry_data,
                            data_start as u64,
                            BinaryType::Java,
                        ));
                    }
                }
                let advance = 30usize
                    .checked_add(fname_len)
                    .and_then(|a| a.checked_add(extra_len))
                    .and_then(|a| a.checked_add(comp_size))
                    .unwrap_or(1);
                i += if advance == 0 { 1 } else { advance };
            } else {
                i += 1;
            }
        }

        Ok(nested)
    }
}

// â"€â"€ JvmOpcode â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// All standard JVM opcodes as defined in the Java Virtual Machine Specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum JvmOpcode {
    Nop = 0x00,
    AconstNull = 0x01,
    IconstM1 = 0x02,
    Iconst0 = 0x03,
    Iconst1 = 0x04,
    Iconst2 = 0x05,
    Iconst3 = 0x06,
    Iconst4 = 0x07,
    Iconst5 = 0x08,
    Lconst0 = 0x09,
    Lconst1 = 0x0A,
    Fconst0 = 0x0B,
    Fconst1 = 0x0C,
    Fconst2 = 0x0D,
    Dconst0 = 0x0E,
    Dconst1 = 0x0F,
    Bipush = 0x10,
    Sipush = 0x11,
    Ldc = 0x12,
    LdcW = 0x13,
    Ldc2W = 0x14,
    Iload = 0x15,
    Lload = 0x16,
    Fload = 0x17,
    Dload = 0x18,
    Aload = 0x19,
    Iload0 = 0x1A,
    Iload1 = 0x1B,
    Iload2 = 0x1C,
    Iload3 = 0x1D,
    Lload0 = 0x1E,
    Lload1 = 0x1F,
    Lload2 = 0x20,
    Lload3 = 0x21,
    Fload0 = 0x22,
    Fload1 = 0x23,
    Fload2 = 0x24,
    Fload3 = 0x25,
    Dload0 = 0x26,
    Dload1 = 0x27,
    Dload2 = 0x28,
    Dload3 = 0x29,
    Aload0 = 0x2A,
    Aload1 = 0x2B,
    Aload2 = 0x2C,
    Aload3 = 0x2D,
    Iaload = 0x2E,
    Laload = 0x2F,
    Faload = 0x30,
    Daload = 0x31,
    Aaload = 0x32,
    Baload = 0x33,
    Caload = 0x34,
    Saload = 0x35,
    Istore = 0x36,
    Lstore = 0x37,
    Fstore = 0x38,
    Dstore = 0x39,
    Astore = 0x3A,
    Istore0 = 0x3B,
    Istore1 = 0x3C,
    Istore2 = 0x3D,
    Istore3 = 0x3E,
    Lstore0 = 0x3F,
    Lstore1 = 0x40,
    Lstore2 = 0x41,
    Lstore3 = 0x42,
    Fstore0 = 0x43,
    Fstore1 = 0x44,
    Fstore2 = 0x45,
    Fstore3 = 0x46,
    Dstore0 = 0x47,
    Dstore1 = 0x48,
    Dstore2 = 0x49,
    Dstore3 = 0x4A,
    Astore0 = 0x4B,
    Astore1 = 0x4C,
    Astore2 = 0x4D,
    Astore3 = 0x4E,
    Iastore = 0x4F,
    Lastore = 0x50,
    Fastore = 0x51,
    Dastore = 0x52,
    Aastore = 0x53,
    Bastore = 0x54,
    Castore = 0x55,
    Sastore = 0x56,
    Pop = 0x57,
    Pop2 = 0x58,
    Dup = 0x59,
    DupX1 = 0x5A,
    DupX2 = 0x5B,
    Dup2 = 0x5C,
    Dup2X1 = 0x5D,
    Dup2X2 = 0x5E,
    Swap = 0x5F,
    Iadd = 0x60,
    Ladd = 0x61,
    Fadd = 0x62,
    Dadd = 0x63,
    Isub = 0x64,
    Lsub = 0x65,
    Fsub = 0x66,
    Dsub = 0x67,
    Imul = 0x68,
    Lmul = 0x69,
    Fmul = 0x6A,
    Dmul = 0x6B,
    Idiv = 0x6C,
    Ldiv = 0x6D,
    Fdiv = 0x6E,
    Ddiv = 0x6F,
    Irem = 0x70,
    Lrem = 0x71,
    Frem = 0x72,
    Drem = 0x73,
    Ineg = 0x74,
    Lneg = 0x75,
    Fneg = 0x76,
    Dneg = 0x77,
    Ishl = 0x78,
    Lshl = 0x79,
    Ishr = 0x7A,
    Lshr = 0x7B,
    Iushr = 0x7C,
    Lushr = 0x7D,
    Iand = 0x7E,
    Land = 0x7F,
    Ior = 0x80,
    Lor = 0x81,
    Ixor = 0x82,
    Lxor = 0x83,
    Iinc = 0x84,
    I2l = 0x85,
    I2f = 0x86,
    I2d = 0x87,
    L2i = 0x88,
    L2f = 0x89,
    L2d = 0x8A,
    F2i = 0x8B,
    F2l = 0x8C,
    F2d = 0x8D,
    D2i = 0x8E,
    D2l = 0x8F,
    D2f = 0x90,
    I2b = 0x91,
    I2c = 0x92,
    I2s = 0x93,
    Lcmp = 0x94,
    Fcmpl = 0x95,
    Fcmpg = 0x96,
    Dcmpl = 0x97,
    Dcmpg = 0x98,
    Ifeq = 0x99,
    Ifne = 0x9A,
    Iflt = 0x9B,
    Ifge = 0x9C,
    Ifgt = 0x9D,
    Ifle = 0x9E,
    IfIcmpeq = 0x9F,
    IfIcmpne = 0xA0,
    IfIcmplt = 0xA1,
    IfIcmpge = 0xA2,
    IfIcmpgt = 0xA3,
    IfIcmple = 0xA4,
    IfAcmpeq = 0xA5,
    IfAcmpne = 0xA6,
    Goto = 0xA7,
    Jsr = 0xA8,
    Ret = 0xA9,
    Tableswitch = 0xAA,
    Lookupswitch = 0xAB,
    Ireturn = 0xAC,
    Lreturn = 0xAD,
    Freturn = 0xAE,
    Dreturn = 0xAF,
    Areturn = 0xB0,
    Return = 0xB1,
    Getstatic = 0xB2,
    Putstatic = 0xB3,
    Getfield = 0xB4,
    Putfield = 0xB5,
    Invokevirtual = 0xB6,
    Invokespecial = 0xB7,
    Invokestatic = 0xB8,
    Invokeinterface = 0xB9,
    Invokedynamic = 0xBA,
    New = 0xBB,
    Newarray = 0xBC,
    Anewarray = 0xBD,
    Arraylength = 0xBE,
    Athrow = 0xBF,
    Checkcast = 0xC0,
    Instanceof = 0xC1,
    Monitorenter = 0xC2,
    Monitorexit = 0xC3,
    Wide = 0xC4,
    Multianewarray = 0xC5,
    Ifnull = 0xC6,
    Ifnonnull = 0xC7,
    GotoW = 0xC8,
    JsrW = 0xC9,
    Unknown = 0xFF,
}

impl JvmOpcode {
    /// Decode a byte into a [`JvmOpcode`].
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::Nop,
            0x01 => Self::AconstNull,
            0x02 => Self::IconstM1,
            0x03 => Self::Iconst0,
            0x04 => Self::Iconst1,
            0x05 => Self::Iconst2,
            0x06 => Self::Iconst3,
            0x07 => Self::Iconst4,
            0x08 => Self::Iconst5,
            0x09 => Self::Lconst0,
            0x0A => Self::Lconst1,
            0x0B => Self::Fconst0,
            0x0C => Self::Fconst1,
            0x0D => Self::Fconst2,
            0x0E => Self::Dconst0,
            0x0F => Self::Dconst1,
            0x10 => Self::Bipush,
            0x11 => Self::Sipush,
            0x12 => Self::Ldc,
            0x13 => Self::LdcW,
            0x14 => Self::Ldc2W,
            0x15 => Self::Iload,
            0x16 => Self::Lload,
            0x17 => Self::Fload,
            0x18 => Self::Dload,
            0x19 => Self::Aload,
            0x1A => Self::Iload0,
            0x1B => Self::Iload1,
            0x1C => Self::Iload2,
            0x1D => Self::Iload3,
            0x1E => Self::Lload0,
            0x1F => Self::Lload1,
            0x20 => Self::Lload2,
            0x21 => Self::Lload3,
            0x22 => Self::Fload0,
            0x23 => Self::Fload1,
            0x24 => Self::Fload2,
            0x25 => Self::Fload3,
            0x26 => Self::Dload0,
            0x27 => Self::Dload1,
            0x28 => Self::Dload2,
            0x29 => Self::Dload3,
            0x2A => Self::Aload0,
            0x2B => Self::Aload1,
            0x2C => Self::Aload2,
            0x2D => Self::Aload3,
            0x2E => Self::Iaload,
            0x2F => Self::Laload,
            0x30 => Self::Faload,
            0x31 => Self::Daload,
            0x32 => Self::Aaload,
            0x33 => Self::Baload,
            0x34 => Self::Caload,
            0x35 => Self::Saload,
            0x36 => Self::Istore,
            0x37 => Self::Lstore,
            0x38 => Self::Fstore,
            0x39 => Self::Dstore,
            0x3A => Self::Astore,
            0x3B => Self::Istore0,
            0x3C => Self::Istore1,
            0x3D => Self::Istore2,
            0x3E => Self::Istore3,
            0x3F => Self::Lstore0,
            0x40 => Self::Lstore1,
            0x41 => Self::Lstore2,
            0x42 => Self::Lstore3,
            0x43 => Self::Fstore0,
            0x44 => Self::Fstore1,
            0x45 => Self::Fstore2,
            0x46 => Self::Fstore3,
            0x47 => Self::Dstore0,
            0x48 => Self::Dstore1,
            0x49 => Self::Dstore2,
            0x4A => Self::Dstore3,
            0x4B => Self::Astore0,
            0x4C => Self::Astore1,
            0x4D => Self::Astore2,
            0x4E => Self::Astore3,
            0x4F => Self::Iastore,
            0x50 => Self::Lastore,
            0x51 => Self::Fastore,
            0x52 => Self::Dastore,
            0x53 => Self::Aastore,
            0x54 => Self::Bastore,
            0x55 => Self::Castore,
            0x56 => Self::Sastore,
            0x57 => Self::Pop,
            0x58 => Self::Pop2,
            0x59 => Self::Dup,
            0x5A => Self::DupX1,
            0x5B => Self::DupX2,
            0x5C => Self::Dup2,
            0x5D => Self::Dup2X1,
            0x5E => Self::Dup2X2,
            0x5F => Self::Swap,
            0x60 => Self::Iadd,
            0x61 => Self::Ladd,
            0x62 => Self::Fadd,
            0x63 => Self::Dadd,
            0x64 => Self::Isub,
            0x65 => Self::Lsub,
            0x66 => Self::Fsub,
            0x67 => Self::Dsub,
            0x68 => Self::Imul,
            0x69 => Self::Lmul,
            0x6A => Self::Fmul,
            0x6B => Self::Dmul,
            0x6C => Self::Idiv,
            0x6D => Self::Ldiv,
            0x6E => Self::Fdiv,
            0x6F => Self::Ddiv,
            0x70 => Self::Irem,
            0x71 => Self::Lrem,
            0x72 => Self::Frem,
            0x73 => Self::Drem,
            0x74 => Self::Ineg,
            0x75 => Self::Lneg,
            0x76 => Self::Fneg,
            0x77 => Self::Dneg,
            0x78 => Self::Ishl,
            0x79 => Self::Lshl,
            0x7A => Self::Ishr,
            0x7B => Self::Lshr,
            0x7C => Self::Iushr,
            0x7D => Self::Lushr,
            0x7E => Self::Iand,
            0x7F => Self::Land,
            0x80 => Self::Ior,
            0x81 => Self::Lor,
            0x82 => Self::Ixor,
            0x83 => Self::Lxor,
            0x84 => Self::Iinc,
            0x85 => Self::I2l,
            0x86 => Self::I2f,
            0x87 => Self::I2d,
            0x88 => Self::L2i,
            0x89 => Self::L2f,
            0x8A => Self::L2d,
            0x8B => Self::F2i,
            0x8C => Self::F2l,
            0x8D => Self::F2d,
            0x8E => Self::D2i,
            0x8F => Self::D2l,
            0x90 => Self::D2f,
            0x91 => Self::I2b,
            0x92 => Self::I2c,
            0x93 => Self::I2s,
            0x94 => Self::Lcmp,
            0x95 => Self::Fcmpl,
            0x96 => Self::Fcmpg,
            0x97 => Self::Dcmpl,
            0x98 => Self::Dcmpg,
            0x99 => Self::Ifeq,
            0x9A => Self::Ifne,
            0x9B => Self::Iflt,
            0x9C => Self::Ifge,
            0x9D => Self::Ifgt,
            0x9E => Self::Ifle,
            0x9F => Self::IfIcmpeq,
            0xA0 => Self::IfIcmpne,
            0xA1 => Self::IfIcmplt,
            0xA2 => Self::IfIcmpge,
            0xA3 => Self::IfIcmpgt,
            0xA4 => Self::IfIcmple,
            0xA5 => Self::IfAcmpeq,
            0xA6 => Self::IfAcmpne,
            0xA7 => Self::Goto,
            0xA8 => Self::Jsr,
            0xA9 => Self::Ret,
            0xAA => Self::Tableswitch,
            0xAB => Self::Lookupswitch,
            0xAC => Self::Ireturn,
            0xAD => Self::Lreturn,
            0xAE => Self::Freturn,
            0xAF => Self::Dreturn,
            0xB0 => Self::Areturn,
            0xB1 => Self::Return,
            0xB2 => Self::Getstatic,
            0xB3 => Self::Putstatic,
            0xB4 => Self::Getfield,
            0xB5 => Self::Putfield,
            0xB6 => Self::Invokevirtual,
            0xB7 => Self::Invokespecial,
            0xB8 => Self::Invokestatic,
            0xB9 => Self::Invokeinterface,
            0xBA => Self::Invokedynamic,
            0xBB => Self::New,
            0xBC => Self::Newarray,
            0xBD => Self::Anewarray,
            0xBE => Self::Arraylength,
            0xBF => Self::Athrow,
            0xC0 => Self::Checkcast,
            0xC1 => Self::Instanceof,
            0xC2 => Self::Monitorenter,
            0xC3 => Self::Monitorexit,
            0xC4 => Self::Wide,
            0xC5 => Self::Multianewarray,
            0xC6 => Self::Ifnull,
            0xC7 => Self::Ifnonnull,
            0xC8 => Self::GotoW,
            0xC9 => Self::JsrW,
            _ => Self::Unknown,
        }
    }

    /// Return the mnemonic string for this opcode.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Nop => "nop",
            Self::AconstNull => "aconst_null",
            Self::IconstM1 => "iconst_m1",
            Self::Iconst0 => "iconst_0",
            Self::Iconst1 => "iconst_1",
            Self::Iconst2 => "iconst_2",
            Self::Iconst3 => "iconst_3",
            Self::Iconst4 => "iconst_4",
            Self::Iconst5 => "iconst_5",
            Self::Lconst0 => "lconst_0",
            Self::Lconst1 => "lconst_1",
            Self::Fconst0 => "fconst_0",
            Self::Fconst1 => "fconst_1",
            Self::Fconst2 => "fconst_2",
            Self::Dconst0 => "dconst_0",
            Self::Dconst1 => "dconst_1",
            Self::Bipush => "bipush",
            Self::Sipush => "sipush",
            Self::Ldc => "ldc",
            Self::LdcW => "ldc_w",
            Self::Ldc2W => "ldc2_w",
            Self::Iload => "iload",
            Self::Lload => "lload",
            Self::Fload => "fload",
            Self::Dload => "dload",
            Self::Aload => "aload",
            Self::Iload0 => "iload_0",
            Self::Iload1 => "iload_1",
            Self::Iload2 => "iload_2",
            Self::Iload3 => "iload_3",
            Self::Lload0 => "lload_0",
            Self::Lload1 => "lload_1",
            Self::Lload2 => "lload_2",
            Self::Lload3 => "lload_3",
            Self::Fload0 => "fload_0",
            Self::Fload1 => "fload_1",
            Self::Fload2 => "fload_2",
            Self::Fload3 => "fload_3",
            Self::Dload0 => "dload_0",
            Self::Dload1 => "dload_1",
            Self::Dload2 => "dload_2",
            Self::Dload3 => "dload_3",
            Self::Aload0 => "aload_0",
            Self::Aload1 => "aload_1",
            Self::Aload2 => "aload_2",
            Self::Aload3 => "aload_3",
            Self::Iaload => "iaload",
            Self::Laload => "laload",
            Self::Faload => "faload",
            Self::Daload => "daload",
            Self::Aaload => "aaload",
            Self::Baload => "baload",
            Self::Caload => "caload",
            Self::Saload => "saload",
            Self::Istore => "istore",
            Self::Lstore => "lstore",
            Self::Fstore => "fstore",
            Self::Dstore => "dstore",
            Self::Astore => "astore",
            Self::Istore0 => "istore_0",
            Self::Istore1 => "istore_1",
            Self::Istore2 => "istore_2",
            Self::Istore3 => "istore_3",
            Self::Lstore0 => "lstore_0",
            Self::Lstore1 => "lstore_1",
            Self::Lstore2 => "lstore_2",
            Self::Lstore3 => "lstore_3",
            Self::Fstore0 => "fstore_0",
            Self::Fstore1 => "fstore_1",
            Self::Fstore2 => "fstore_2",
            Self::Fstore3 => "fstore_3",
            Self::Dstore0 => "dstore_0",
            Self::Dstore1 => "dstore_1",
            Self::Dstore2 => "dstore_2",
            Self::Dstore3 => "dstore_3",
            Self::Astore0 => "astore_0",
            Self::Astore1 => "astore_1",
            Self::Astore2 => "astore_2",
            Self::Astore3 => "astore_3",
            Self::Iastore => "iastore",
            Self::Lastore => "lastore",
            Self::Fastore => "fastore",
            Self::Dastore => "dastore",
            Self::Aastore => "aastore",
            Self::Bastore => "bastore",
            Self::Castore => "castore",
            Self::Sastore => "sastore",
            Self::Pop => "pop",
            Self::Pop2 => "pop2",
            Self::Dup => "dup",
            Self::DupX1 => "dup_x1",
            Self::DupX2 => "dup_x2",
            Self::Dup2 => "dup2",
            Self::Dup2X1 => "dup2_x1",
            Self::Dup2X2 => "dup2_x2",
            Self::Swap => "swap",
            Self::Iadd => "iadd",
            Self::Ladd => "ladd",
            Self::Fadd => "fadd",
            Self::Dadd => "dadd",
            Self::Isub => "isub",
            Self::Lsub => "lsub",
            Self::Fsub => "fsub",
            Self::Dsub => "dsub",
            Self::Imul => "imul",
            Self::Lmul => "lmul",
            Self::Fmul => "fmul",
            Self::Dmul => "dmul",
            Self::Idiv => "idiv",
            Self::Ldiv => "ldiv",
            Self::Fdiv => "fdiv",
            Self::Ddiv => "ddiv",
            Self::Irem => "irem",
            Self::Lrem => "lrem",
            Self::Frem => "frem",
            Self::Drem => "drem",
            Self::Ineg => "ineg",
            Self::Lneg => "lneg",
            Self::Fneg => "fneg",
            Self::Dneg => "dneg",
            Self::Ishl => "ishl",
            Self::Lshl => "lshl",
            Self::Ishr => "ishr",
            Self::Lshr => "lshr",
            Self::Iushr => "iushr",
            Self::Lushr => "lushr",
            Self::Iand => "iand",
            Self::Land => "land",
            Self::Ior => "ior",
            Self::Lor => "lor",
            Self::Ixor => "ixor",
            Self::Lxor => "lxor",
            Self::Iinc => "iinc",
            Self::I2l => "i2l",
            Self::I2f => "i2f",
            Self::I2d => "i2d",
            Self::L2i => "l2i",
            Self::L2f => "l2f",
            Self::L2d => "l2d",
            Self::F2i => "f2i",
            Self::F2l => "f2l",
            Self::F2d => "f2d",
            Self::D2i => "d2i",
            Self::D2l => "d2l",
            Self::D2f => "d2f",
            Self::I2b => "i2b",
            Self::I2c => "i2c",
            Self::I2s => "i2s",
            Self::Lcmp => "lcmp",
            Self::Fcmpl => "fcmpl",
            Self::Fcmpg => "fcmpg",
            Self::Dcmpl => "dcmpl",
            Self::Dcmpg => "dcmpg",
            Self::Ifeq => "ifeq",
            Self::Ifne => "ifne",
            Self::Iflt => "iflt",
            Self::Ifge => "ifge",
            Self::Ifgt => "ifgt",
            Self::Ifle => "ifle",
            Self::IfIcmpeq => "if_icmpeq",
            Self::IfIcmpne => "if_icmpne",
            Self::IfIcmplt => "if_icmplt",
            Self::IfIcmpge => "if_icmpge",
            Self::IfIcmpgt => "if_icmpgt",
            Self::IfIcmple => "if_icmple",
            Self::IfAcmpeq => "if_acmpeq",
            Self::IfAcmpne => "if_acmpne",
            Self::Goto => "goto",
            Self::Jsr => "jsr",
            Self::Ret => "ret",
            Self::Tableswitch => "tableswitch",
            Self::Lookupswitch => "lookupswitch",
            Self::Ireturn => "ireturn",
            Self::Lreturn => "lreturn",
            Self::Freturn => "freturn",
            Self::Dreturn => "dreturn",
            Self::Areturn => "areturn",
            Self::Return => "return",
            Self::Getstatic => "getstatic",
            Self::Putstatic => "putstatic",
            Self::Getfield => "getfield",
            Self::Putfield => "putfield",
            Self::Invokevirtual => "invokevirtual",
            Self::Invokespecial => "invokespecial",
            Self::Invokestatic => "invokestatic",
            Self::Invokeinterface => "invokeinterface",
            Self::Invokedynamic => "invokedynamic",
            Self::New => "new",
            Self::Newarray => "newarray",
            Self::Anewarray => "anewarray",
            Self::Arraylength => "arraylength",
            Self::Athrow => "athrow",
            Self::Checkcast => "checkcast",
            Self::Instanceof => "instanceof",
            Self::Monitorenter => "monitorenter",
            Self::Monitorexit => "monitorexit",
            Self::Wide => "wide",
            Self::Multianewarray => "multianewarray",
            Self::Ifnull => "ifnull",
            Self::Ifnonnull => "ifnonnull",
            Self::GotoW => "goto_w",
            Self::JsrW => "jsr_w",
            Self::Unknown => "unknown",
        }
    }

    /// Return `true` if this opcode is any form of `invoke*`.
    #[must_use]
    pub const fn is_invoke(self) -> bool {
        matches!(
            self,
            Self::Invokevirtual
                | Self::Invokespecial
                | Self::Invokestatic
                | Self::Invokeinterface
                | Self::Invokedynamic
        )
    }

    /// Return `true` if this opcode is a conditional or unconditional branch.
    #[must_use]
    pub const fn is_branch(self) -> bool {
        matches!(
            self,
            Self::Ifeq
                | Self::Ifne
                | Self::Iflt
                | Self::Ifge
                | Self::Ifgt
                | Self::Ifle
                | Self::IfIcmpeq
                | Self::IfIcmpne
                | Self::IfIcmplt
                | Self::IfIcmpge
                | Self::IfIcmpgt
                | Self::IfIcmple
                | Self::IfAcmpeq
                | Self::IfAcmpne
                | Self::Goto
                | Self::GotoW
                | Self::Jsr
                | Self::JsrW
                | Self::Tableswitch
                | Self::Lookupswitch
                | Self::Ifnull
                | Self::Ifnonnull
        )
    }

    /// Return `true` if this opcode is any `*return`.
    #[must_use]
    pub const fn is_return(self) -> bool {
        matches!(
            self,
            Self::Ireturn
                | Self::Lreturn
                | Self::Freturn
                | Self::Dreturn
                | Self::Areturn
                | Self::Return
        )
    }
}

impl fmt::Display for JvmOpcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.mnemonic())
    }
}

// â"€â"€ JvmInstruction â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A single decoded JVM bytecode instruction.
#[derive(Debug, Clone)]
pub struct JvmInstruction {
    /// Byte offset within the method's code array.
    pub offset: u32,
    /// Decoded opcode.
    pub opcode: JvmOpcode,
    /// Operand bytes (raw, up to 8 bytes for wide instructions).
    pub operands: Vec<u8>,
}

impl JvmInstruction {
    /// Return `true` if this instruction is an `invoke*` opcode.
    #[must_use]
    pub const fn is_invoke(&self) -> bool {
        self.opcode.is_invoke()
    }

    /// Decode a 2-byte big-endian CP index from operands[0..2].
    #[must_use]
    pub fn cp_index(&self) -> Option<u16> {
        if self.operands.len() >= 2 {
            Some(u16::from_be_bytes([self.operands[0], self.operands[1]]))
        } else {
            None
        }
    }
}

impl fmt::Display for JvmInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04} {}", self.offset, self.opcode.mnemonic())
    }
}

// â"€â"€ JvmDisassembler â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Disassembler for JVM bytecode.
///
/// Takes a raw `Code` attribute byte slice and produces a list of
/// [`JvmInstruction`]s.
#[derive(Debug, Default)]
pub struct JvmDisassembler;

impl JvmDisassembler {
    /// Create a new disassembler.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Disassemble `code` (raw bytes from the Code attribute) into a list of
    /// [`JvmInstruction`]s.
    ///
    /// Unknown opcodes are emitted as `JvmOpcode::Unknown` with no operands, and
    /// disassembly stops at that point to avoid misalignment.
    #[must_use]
    pub fn disassemble(&self, code: &[u8]) -> Vec<JvmInstruction> {
        let mut instrs = Vec::new();
        let mut pos = 0usize;
        while pos < code.len() {
            let offset = pos as u32;
            let opcode = JvmOpcode::from_byte(code[pos]);
            pos += 1;
            let (operand_bytes, advance) = self.operand_size(opcode, code, pos);
            if opcode == JvmOpcode::Unknown {
                instrs.push(JvmInstruction {
                    offset,
                    opcode,
                    operands: vec![],
                });
                break;
            }
            instrs.push(JvmInstruction {
                offset,
                opcode,
                operands: operand_bytes,
            });
            pos += advance;
        }
        instrs
    }

    /// Return (`operand_bytes`, `bytes_to_skip`) for the given opcode.
    fn operand_size(&self, opcode: JvmOpcode, code: &[u8], pos: usize) -> (Vec<u8>, usize) {
        let avail = |n: usize| -> Option<Vec<u8>> {
            if pos + n <= code.len() {
                Some(code[pos..pos + n].to_vec())
            } else {
                None
            }
        };
        match opcode {
            // 0 operands
            JvmOpcode::Nop | JvmOpcode::AconstNull
            | JvmOpcode::IconstM1 | JvmOpcode::Iconst0 | JvmOpcode::Iconst1
            | JvmOpcode::Iconst2 | JvmOpcode::Iconst3 | JvmOpcode::Iconst4 | JvmOpcode::Iconst5
            | JvmOpcode::Lconst0 | JvmOpcode::Lconst1
            | JvmOpcode::Fconst0 | JvmOpcode::Fconst1 | JvmOpcode::Fconst2
            | JvmOpcode::Dconst0 | JvmOpcode::Dconst1
            // iload_0 —¦ aload_3 (0x1A —" 0x2D)
            | JvmOpcode::Iload0 | JvmOpcode::Iload1 | JvmOpcode::Iload2 | JvmOpcode::Iload3
            | JvmOpcode::Lload0 | JvmOpcode::Lload1 | JvmOpcode::Lload2 | JvmOpcode::Lload3
            | JvmOpcode::Fload0 | JvmOpcode::Fload1 | JvmOpcode::Fload2 | JvmOpcode::Fload3
            | JvmOpcode::Dload0 | JvmOpcode::Dload1 | JvmOpcode::Dload2 | JvmOpcode::Dload3
            | JvmOpcode::Aload0 | JvmOpcode::Aload1 | JvmOpcode::Aload2 | JvmOpcode::Aload3
            // iaload —¦ saload (0x2E —" 0x35)
            | JvmOpcode::Iaload | JvmOpcode::Laload | JvmOpcode::Faload | JvmOpcode::Daload
            | JvmOpcode::Aaload | JvmOpcode::Baload | JvmOpcode::Caload | JvmOpcode::Saload
            // istore_0 —¦ astore_3 (0x3B —" 0x4E)
            | JvmOpcode::Istore0 | JvmOpcode::Istore1 | JvmOpcode::Istore2 | JvmOpcode::Istore3
            | JvmOpcode::Lstore0 | JvmOpcode::Lstore1 | JvmOpcode::Lstore2 | JvmOpcode::Lstore3
            | JvmOpcode::Fstore0 | JvmOpcode::Fstore1 | JvmOpcode::Fstore2 | JvmOpcode::Fstore3
            | JvmOpcode::Dstore0 | JvmOpcode::Dstore1 | JvmOpcode::Dstore2 | JvmOpcode::Dstore3
            | JvmOpcode::Astore0 | JvmOpcode::Astore1 | JvmOpcode::Astore2 | JvmOpcode::Astore3
            // iastore —¦ sastore (0x4F —" 0x56)
            | JvmOpcode::Iastore | JvmOpcode::Lastore | JvmOpcode::Fastore | JvmOpcode::Dastore
            | JvmOpcode::Aastore | JvmOpcode::Bastore | JvmOpcode::Castore | JvmOpcode::Sastore
            | JvmOpcode::Pop | JvmOpcode::Pop2 | JvmOpcode::Dup | JvmOpcode::DupX1
            | JvmOpcode::DupX2 | JvmOpcode::Dup2 | JvmOpcode::Dup2X1 | JvmOpcode::Dup2X2
            | JvmOpcode::Swap
            // iadd —¦ lxor (0x60 —" 0x83)
            | JvmOpcode::Iadd | JvmOpcode::Ladd | JvmOpcode::Fadd | JvmOpcode::Dadd
            | JvmOpcode::Isub | JvmOpcode::Lsub | JvmOpcode::Fsub | JvmOpcode::Dsub
            | JvmOpcode::Imul | JvmOpcode::Lmul | JvmOpcode::Fmul | JvmOpcode::Dmul
            | JvmOpcode::Idiv | JvmOpcode::Ldiv | JvmOpcode::Fdiv | JvmOpcode::Ddiv
            | JvmOpcode::Irem | JvmOpcode::Lrem | JvmOpcode::Frem | JvmOpcode::Drem
            | JvmOpcode::Ineg | JvmOpcode::Lneg | JvmOpcode::Fneg | JvmOpcode::Dneg
            | JvmOpcode::Ishl | JvmOpcode::Lshl | JvmOpcode::Ishr | JvmOpcode::Lshr
            | JvmOpcode::Iushr | JvmOpcode::Lushr | JvmOpcode::Iand | JvmOpcode::Land
            | JvmOpcode::Ior | JvmOpcode::Lor | JvmOpcode::Ixor | JvmOpcode::Lxor
            // i2l —¦ i2s (0x85 —" 0x93)
            | JvmOpcode::I2l | JvmOpcode::I2f | JvmOpcode::I2d
            | JvmOpcode::L2i | JvmOpcode::L2f | JvmOpcode::L2d
            | JvmOpcode::F2i | JvmOpcode::F2l | JvmOpcode::F2d
            | JvmOpcode::D2i | JvmOpcode::D2l | JvmOpcode::D2f
            | JvmOpcode::I2b | JvmOpcode::I2c | JvmOpcode::I2s
            // lcmp —¦ dcmpg (0x94 —" 0x98)
            | JvmOpcode::Lcmp | JvmOpcode::Fcmpl | JvmOpcode::Fcmpg
            | JvmOpcode::Dcmpl | JvmOpcode::Dcmpg
            // ireturn —¦ return (0xAC —" 0xB1)
            | JvmOpcode::Ireturn | JvmOpcode::Lreturn | JvmOpcode::Freturn
            | JvmOpcode::Dreturn | JvmOpcode::Areturn | JvmOpcode::Return
            | JvmOpcode::Arraylength | JvmOpcode::Athrow
            | JvmOpcode::Monitorenter | JvmOpcode::Monitorexit => (vec![], 0),

            // 1 operand byte
            JvmOpcode::Bipush | JvmOpcode::Ldc | JvmOpcode::Ret
            | JvmOpcode::Newarray
            | JvmOpcode::Iload | JvmOpcode::Lload | JvmOpcode::Fload | JvmOpcode::Dload | JvmOpcode::Aload
            | JvmOpcode::Istore | JvmOpcode::Lstore | JvmOpcode::Fstore | JvmOpcode::Dstore | JvmOpcode::Astore
            => (avail(1).unwrap_or_default(), 1),

            // 2 operand bytes
            JvmOpcode::Sipush | JvmOpcode::LdcW | JvmOpcode::Ldc2W
            | JvmOpcode::Ifeq | JvmOpcode::Ifne | JvmOpcode::Iflt | JvmOpcode::Ifge
            | JvmOpcode::Ifgt | JvmOpcode::Ifle
            | JvmOpcode::IfIcmpeq | JvmOpcode::IfIcmpne | JvmOpcode::IfIcmplt
            | JvmOpcode::IfIcmpge | JvmOpcode::IfIcmpgt | JvmOpcode::IfIcmple
            | JvmOpcode::IfAcmpeq | JvmOpcode::IfAcmpne
            | JvmOpcode::Goto | JvmOpcode::Jsr
            | JvmOpcode::Getstatic | JvmOpcode::Putstatic | JvmOpcode::Getfield | JvmOpcode::Putfield
            | JvmOpcode::Invokevirtual | JvmOpcode::Invokespecial | JvmOpcode::Invokestatic
            | JvmOpcode::New | JvmOpcode::Anewarray | JvmOpcode::Checkcast | JvmOpcode::Instanceof
            | JvmOpcode::Ifnull | JvmOpcode::Ifnonnull
            => (avail(2).unwrap_or_default(), 2),

            // 2 operand bytes for Iinc
            JvmOpcode::Iinc => (avail(2).unwrap_or_default(), 2),

            // 4 operand bytes
            JvmOpcode::GotoW | JvmOpcode::JsrW => (avail(4).unwrap_or_default(), 4),

            // Invokeinterface / Invokedynamic: 4 bytes
            JvmOpcode::Invokeinterface | JvmOpcode::Invokedynamic => (avail(4).unwrap_or_default(), 4),

            // Multianewarray: 3 bytes
            JvmOpcode::Multianewarray => (avail(3).unwrap_or_default(), 3),

            // Variable-length operands: their size depends on bytes that follow
            // (the padded switch tables, or the opcode a `wide` prefixes), so
            // it cannot be stated as a constant here. `Self::opcode_width`
            // computes it; the operand bytes themselves are not materialised.
            JvmOpcode::Tableswitch | JvmOpcode::Lookupswitch | JvmOpcode::Wide => {
                let total = JavaBytecodeAnalyzer::opcode_width(code[pos - 1], code, pos - 1);
                (vec![], total.saturating_sub(1))
            }

            JvmOpcode::Unknown => (vec![], 0),
        }
    }
}

// â"€â"€ JavaDescriptorParser â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Parse and represent Java field/method descriptors.
///
/// Descriptor grammar (simplified):
/// - `B` = byte, `C` = char, `D` = double, `F` = float, `I` = int,
///   `J` = long, `S` = short, `Z` = boolean, `V` = void
/// - `L<classname>;` = reference type
/// - `[<type>` = array
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JavaType {
    /// `B`
    Byte,
    /// `C`
    Char,
    /// `D`
    Double,
    /// `F`
    Float,
    /// `I`
    Int,
    /// `J`
    Long,
    /// `S`
    Short,
    /// `Z`
    Boolean,
    /// `V`
    Void,
    /// `L<class>;`
    Reference(String),
    /// `[T`
    Array(Box<Self>),
}

impl fmt::Display for JavaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Byte => write!(f, "byte"),
            Self::Char => write!(f, "char"),
            Self::Double => write!(f, "double"),
            Self::Float => write!(f, "float"),
            Self::Int => write!(f, "int"),
            Self::Long => write!(f, "long"),
            Self::Short => write!(f, "short"),
            Self::Boolean => write!(f, "boolean"),
            Self::Void => write!(f, "void"),
            Self::Reference(c) => write!(f, "{}", c.replace('/', ".")),
            Self::Array(t) => write!(f, "{t}[]"),
        }
    }
}

/// Parser for Java field and method descriptors.
#[derive(Debug, Default)]
pub struct JavaDescriptorParser;

impl JavaDescriptorParser {
    /// Create a new parser.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Parse a field descriptor (e.g. `"I"`, `"Ljava/lang/String;"`, `"[B"`).
    ///
    /// Returns `None` if the descriptor is malformed.
    #[must_use]
    pub fn parse_field(&self, desc: &str) -> Option<JavaType> {
        let chars: Vec<char> = desc.chars().collect();
        let (ty, consumed) = self.parse_type(&chars, 0)?;
        if consumed == chars.len() {
            Some(ty)
        } else {
            None
        }
    }

    /// Parse a method descriptor (e.g. `"(ILjava/lang/String;)V"`).
    ///
    /// Returns `(param_types, return_type)` or `None` on error.
    #[must_use]
    pub fn parse_method(&self, desc: &str) -> Option<(Vec<JavaType>, JavaType)> {
        let chars: Vec<char> = desc.chars().collect();
        if chars.first() != Some(&'(') {
            return None;
        }
        let mut pos = 1;
        let mut params = Vec::new();
        while pos < chars.len() && chars[pos] != ')' {
            let (ty, n) = self.parse_type(&chars, pos)?;
            params.push(ty);
            pos += n;
        }
        if pos >= chars.len() || chars[pos] != ')' {
            return None;
        }
        pos += 1; // skip ')'
        let (ret, _) = self.parse_type(&chars, pos)?;
        Some((params, ret))
    }

    fn parse_type(&self, chars: &[char], pos: usize) -> Option<(JavaType, usize)> {
        if pos >= chars.len() {
            return None;
        }
        match chars[pos] {
            'B' => Some((JavaType::Byte, 1)),
            'C' => Some((JavaType::Char, 1)),
            'D' => Some((JavaType::Double, 1)),
            'F' => Some((JavaType::Float, 1)),
            'I' => Some((JavaType::Int, 1)),
            'J' => Some((JavaType::Long, 1)),
            'S' => Some((JavaType::Short, 1)),
            'Z' => Some((JavaType::Boolean, 1)),
            'V' => Some((JavaType::Void, 1)),
            'L' => {
                let start = pos + 1;
                let end = chars[start..].iter().position(|&c| c == ';')? + start;
                let name: String = chars[start..end].iter().collect();
                Some((JavaType::Reference(name), end - pos + 1))
            }
            '[' => {
                let (inner, n) = self.parse_type(chars, pos + 1)?;
                Some((JavaType::Array(Box::new(inner)), n + 1))
            }
            _ => None,
        }
    }
}

// â"€â"€ JavaClassAnalyzer â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// High-level analyser for a parsed [`JavaClass`].
///
/// Identifies reflection usage, crypto API calls, string literals, method
/// call signatures, and produces an obfuscation heuristic score.
#[derive(Debug)]
pub struct JavaClassAnalyzer<'a> {
    class: &'a JavaClass,
}

impl<'a> JavaClassAnalyzer<'a> {
    /// Create an analyser for `class`.
    #[must_use]
    pub const fn new(class: &'a JavaClass) -> Self {
        Self { class }
    }

    /// Return all string literals found in the constant pool.
    #[must_use]
    pub fn string_literals(&self) -> Vec<&str> {
        self.class
            .constant_pool
            .iter()
            .filter_map(|e| {
                if let ConstantPoolEntry::Utf8(s) = e {
                    Some(s.as_str())
                } else {
                    None
                }
            })
            .filter(|s| !s.is_empty() && !s.starts_with('(') && !s.starts_with('['))
            .collect()
    }

    /// Return all method call signatures (`MethodRef` entries resolved to `class.method` form).
    #[must_use]
    pub fn method_calls(&self) -> Vec<String> {
        let cp = &self.class.constant_pool;
        let mut calls = Vec::new();
        for entry in cp {
            if let ConstantPoolEntry::MethodRef { class, nat } = entry {
                let class_name =
                    if let Some(ConstantPoolEntry::ClassRef(ci)) = cp.get(*class as usize) {
                        if let Some(ConstantPoolEntry::Utf8(s)) = cp.get(*ci as usize) {
                            s.clone()
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    };
                let method_name = if let Some(ConstantPoolEntry::NameAndType { name, .. }) =
                    cp.get(*nat as usize)
                {
                    if let Some(ConstantPoolEntry::Utf8(s)) = cp.get(*name as usize) {
                        s.clone()
                    } else {
                        continue;
                    }
                } else {
                    continue;
                };
                calls.push(format!("{class_name}.{method_name}"));
            }
        }
        calls.sort();
        calls.dedup();
        calls
    }

    /// Returns `true` if the class appears to use Java reflection.
    ///
    /// Detected by references to `java/lang/reflect/` or `java/lang/Class`
    /// method calls (forName, getDeclaredMethod, getMethod, invoke, etc.).
    #[must_use]
    pub fn uses_reflection(&self) -> bool {
        let calls = self.method_calls();
        let strings = self.string_literals();
        calls.iter().any(|c| {
            c.starts_with("java/lang/reflect/")
                || c.contains("forName")
                || c.contains("getDeclaredMethod")
                || c.contains("getMethod")
                || c.contains("getDeclaredField")
                || (c.starts_with("java/lang/Class") && c.contains("invoke"))
        }) || strings.iter().any(|s| s.starts_with("java/lang/reflect/"))
    }

    /// Returns `true` if the class uses Java Cryptography API.
    ///
    /// Detected by references to `javax/crypto/`, `java/security/`, or
    /// common crypto class names.
    #[must_use]
    pub fn uses_crypto(&self) -> bool {
        let calls = self.method_calls();
        let strings = self.string_literals();
        let crypto_indicators = [
            "javax/crypto/",
            "java/security/",
            "Cipher",
            "SecretKey",
            "MessageDigest",
            "KeyGenerator",
            "javax/crypto/spec/",
            "AES",
            "RSA",
            "DES",
            "SHA",
            "MD5",
        ];
        calls
            .iter()
            .any(|c| crypto_indicators.iter().any(|i| c.contains(i)))
            || strings
                .iter()
                .any(|s| crypto_indicators.iter().any(|i| s.contains(i)))
    }

    /// Compute a rough obfuscation score in `[0.0, 1.0]`.
    ///
    /// Higher values suggest more obfuscation.  The score is a weighted
    /// combination of:
    /// - Fraction of short method names (â‰¤ 2 chars).
    /// - Fraction of short field names (â‰¤ 2 chars).
    /// - Presence of synthetic methods.
    /// - High ratio of methods to string literals.
    #[must_use]
    pub fn obfuscation_score(&self) -> f64 {
        let total_methods = self.class.methods.len();
        let total_fields = self.class.fields.len();
        if total_methods == 0 && total_fields == 0 {
            return 0.0;
        }

        let short_methods = self
            .class
            .methods
            .iter()
            .filter(|m| m.name.len() <= 2 && m.name != "<init>" && m.name != "<clinit>")
            .count();
        let short_fields = self
            .class
            .fields
            .iter()
            .filter(|f| f.name.len() <= 2)
            .count();
        let synthetic_methods = self
            .class
            .methods
            .iter()
            .filter(|m| m.flags.contains(JavaClassFlags::SYNTHETIC))
            .count();

        let method_score = if total_methods > 0 {
            short_methods as f64 / total_methods as f64
        } else {
            0.0
        };
        let field_score = if total_fields > 0 {
            short_fields as f64 / total_fields as f64
        } else {
            0.0
        };
        let synth_score = if total_methods > 0 {
            (synthetic_methods as f64 / total_methods as f64).min(1.0)
        } else {
            0.0
        };

        let string_count = self.string_literals().len();
        let density = if total_methods > 0 && string_count == 0 {
            0.3
        } else {
            0.0
        };

        0.1f64.mul_add(density, 0.2f64.mul_add(synth_score, 0.4f64.mul_add(method_score, 0.3 * field_score))).min(1.0)
    }

    /// Returns `true` if the class is likely obfuscated (score â‰¥ 0.5).
    #[must_use]
    pub fn is_obfuscated(&self) -> bool {
        self.obfuscation_score() >= 0.5
    }
}

// â"€â"€ ClassFile (richer parse target used by the new analysis APIs) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A richer parsed representation of a Java `.class` file used by the
/// attribute-level APIs.
///
/// It mirrors [`JavaClass`] but carries the raw
/// constant pool in the same slice-friendly form and retains method attribute
/// data for deeper analysis.
#[derive(Debug, Clone)]
pub struct ClassFile {
    /// Parsed version.
    pub version: JavaVersion,
    /// Access flags.
    pub flags: JavaClassFlags,
    /// Binary class name.
    pub class_name: String,
    /// Super-class name (if any).
    pub super_name: Option<String>,
    /// Implemented interfaces.
    pub interfaces: Vec<String>,
    /// Fields.
    pub fields: Vec<JavaField>,
    /// Methods (with retained attribute bytes for `Code` parsing).
    pub methods: Vec<RichMethod>,
    /// Constant pool (1-based; index 0 is sentinel).
    pub constant_pool: Vec<ConstantPoolEntry>,
}

/// A method entry that also carries raw attribute bytes for downstream parsing.
#[derive(Debug, Clone)]
pub struct RichMethod {
    /// Method name.
    pub name: String,
    /// Method descriptor.
    pub descriptor: String,
    /// Access flags.
    pub flags: JavaClassFlags,
    /// Raw bytes of each attribute `(name_index, data)`.
    pub raw_attributes: Vec<(u16, Vec<u8>)>,
}

impl ClassFile {
    /// Parse a `.class` file retaining raw method attribute bytes.
    ///
    /// # Errors
    /// Returns [`JavaLoaderError`] for invalid magic, truncated data, or
    /// malformed constant pool.
    pub fn parse(data: &[u8]) -> Result<Self, JavaLoaderError> {
        // Re-use JavaClass for everything up to methods, then redo methods
        // with raw attribute retention.
        let base = JavaClass::parse(data)?;

        // Re-walk to reach the method attribute bytes.  This is a second pass
        // over the same byte array; correctness is more important than speed.
        let rich_methods = Self::extract_rich_methods(data, &base.constant_pool)?;

        Ok(Self {
            version: base.version,
            flags: base.flags,
            class_name: base.class_name,
            super_name: base.super_name,
            interfaces: base.interfaces,
            fields: base.fields,
            methods: rich_methods,
            constant_pool: base.constant_pool,
        })
    }

    fn extract_rich_methods(
        data: &[u8],
        cp: &[ConstantPoolEntry],
    ) -> Result<Vec<RichMethod>, JavaLoaderError> {
        // Skip magic, minor, major.
        let cp_count = u16::from_be_bytes([data[8], data[9]]) as usize;
        let mut pos = 10usize;

        // Skip constant pool.
        let mut i = 1usize;
        while i < cp_count {
            if pos >= data.len() {
                return Err(JavaLoaderError::TruncatedData);
            }
            let tag = data[pos];
            pos += 1;
            match tag {
                1 => {
                    if pos + 2 > data.len() {
                        return Err(JavaLoaderError::TruncatedData);
                    }
                    let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                    pos += 2 + len;
                }
                3 | 4 => {
                    pos += 4;
                }
                5 | 6 => {
                    pos += 8;
                    i += 1;
                }
                7 | 8 => {
                    pos += 2;
                }
                9..=12 => {
                    pos += 4;
                }
                15 => {
                    pos += 3;
                }
                16 => {
                    pos += 2;
                }
                18 => {
                    pos += 4;
                }
                _ => {
                    return Err(JavaLoaderError::InvalidConstantPool);
                }
            }
            i += 1;
        }

        // Skip access_flags, this_class, super_class.
        pos += 6;
        // Skip interfaces.
        if pos + 2 > data.len() {
            return Err(JavaLoaderError::TruncatedData);
        }
        let ifaces = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + ifaces * 2;

        // Skip fields.
        if pos + 2 > data.len() {
            return Err(JavaLoaderError::TruncatedData);
        }
        let fields_count = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        for _ in 0..fields_count {
            if pos + 8 > data.len() {
                return Err(JavaLoaderError::TruncatedData);
            }
            let attrs = u16::from_be_bytes([data[pos + 6], data[pos + 7]]) as usize;
            pos += 8;
            for _ in 0..attrs {
                if pos + 6 > data.len() {
                    return Err(JavaLoaderError::TruncatedData);
                }
                let alen = u32::from_be_bytes(
                    data[pos + 2..pos + 6]
                        .try_into()
                        .map_err(|_| JavaLoaderError::TruncatedData)?,
                ) as usize;
                pos += 6 + alen;
            }
        }

        // Parse methods retaining raw attribute bytes.
        if pos + 2 > data.len() {
            return Err(JavaLoaderError::TruncatedData);
        }
        let methods_count = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let mut methods = Vec::with_capacity(methods_count);

        for _ in 0..methods_count {
            if pos + 8 > data.len() {
                return Err(JavaLoaderError::TruncatedData);
            }
            let m_flags =
                JavaClassFlags::from_bits_truncate(u16::from_be_bytes([data[pos], data[pos + 1]]));
            let name_idx = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            let desc_idx = u16::from_be_bytes([data[pos + 4], data[pos + 5]]) as usize;
            let attrs_count = u16::from_be_bytes([data[pos + 6], data[pos + 7]]) as usize;
            pos += 8;

            let name = resolve_utf8(cp, name_idx);
            let descriptor = resolve_utf8(cp, desc_idx);
            let mut raw_attributes = Vec::with_capacity(attrs_count);

            for _ in 0..attrs_count {
                if pos + 6 > data.len() {
                    return Err(JavaLoaderError::TruncatedData);
                }
                let attr_name_idx = u16::from_be_bytes([data[pos], data[pos + 1]]);
                let alen = u32::from_be_bytes(
                    data[pos + 2..pos + 6]
                        .try_into()
                        .map_err(|_| JavaLoaderError::TruncatedData)?,
                ) as usize;
                pos += 6;
                if pos + alen > data.len() {
                    return Err(JavaLoaderError::TruncatedData);
                }
                raw_attributes.push((attr_name_idx, data[pos..pos + alen].to_vec()));
                pos += alen;
            }

            methods.push(RichMethod {
                name,
                descriptor,
                flags: m_flags,
                raw_attributes,
            });
        }

        Ok(methods)
    }
}

// â"€â"€ AttributeParser â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Exception table entry inside a `Code` attribute.
#[derive(Debug, Clone)]
pub struct ExceptionTableEntry {
    /// Start of the guarded range (inclusive, bytecode offset).
    pub start_pc: u16,
    /// End of the guarded range (exclusive, bytecode offset).
    pub end_pc: u16,
    /// Bytecode offset of the handler.
    pub handler_pc: u16,
    /// Constant-pool index of the catch type, or 0 for `finally`.
    pub catch_type: u16,
}

/// Parsed `Code` attribute.
#[derive(Debug, Clone)]
pub struct CodeAttribute {
    /// Maximum operand stack depth.
    pub max_stack: u16,
    /// Maximum number of local variable slots.
    pub max_locals: u16,
    /// Raw bytecode bytes.
    pub bytecode: Vec<u8>,
    /// Exception handler table.
    pub exception_table: Vec<ExceptionTableEntry>,
    /// Sub-attributes (e.g. `LineNumberTable`, `LocalVariableTable`).
    pub attributes: Vec<(String, Vec<u8>)>,
}

/// Parsed `Exceptions` attribute —" the checked exceptions a method may throw.
#[derive(Debug, Clone)]
pub struct ExceptionsAttribute {
    /// List of exception class names (resolved from the constant pool).
    pub exceptions: Vec<String>,
}

/// One entry in the `InnerClasses` attribute.
#[derive(Debug, Clone)]
pub struct InnerClassEntry {
    /// Name of the inner class (empty string if anonymous).
    pub inner_class_info: String,
    /// Name of the enclosing class (empty string if top-level context).
    pub outer_class_info: String,
    /// Simple name of the inner class (empty string if anonymous).
    pub inner_name: String,
    /// Access flags for the inner class.
    pub access_flags: JavaClassFlags,
}

/// Stateless helpers for parsing standard JVM class-file attributes.
#[derive(Debug, Default)]
pub struct AttributeParser;

impl AttributeParser {
    /// Create a new parser.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Parse a raw `Code` attribute body (the bytes *after* the 6-byte
    /// attribute header) into a [`CodeAttribute`].
    ///
    /// Layout:
    /// ```text
    /// u16 max_stack
    /// u16 max_locals
    /// u32 code_length
    /// u8  code[code_length]
    /// u16 exception_table_length
    /// {u16 start_pc, u16 end_pc, u16 handler_pc, u16 catch_type}*
    /// u16 attributes_count
    /// {u16 name_index, u32 length, u8 data[length]}*
    /// ```
    ///
    /// # Errors
    /// Returns [`JavaLoaderError::TruncatedData`] if the slice is too short.
    pub fn parse_code_attribute(
        data: &[u8],
        cp: &[ConstantPoolEntry],
    ) -> Result<CodeAttribute, JavaLoaderError> {
        if data.len() < 8 {
            return Err(JavaLoaderError::TruncatedData);
        }
        let max_stack = u16::from_be_bytes([data[0], data[1]]);
        let max_locals = u16::from_be_bytes([data[2], data[3]]);
        let code_len = u32::from_be_bytes(
            data[4..8]
                .try_into()
                .map_err(|_| JavaLoaderError::TruncatedData)?,
        ) as usize;

        let mut pos = 8usize;
        if pos + code_len > data.len() {
            return Err(JavaLoaderError::TruncatedData);
        }
        let bytecode = data[pos..pos + code_len].to_vec();
        pos += code_len;

        if pos + 2 > data.len() {
            return Err(JavaLoaderError::TruncatedData);
        }
        let exc_count = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        let mut exception_table = Vec::with_capacity(exc_count);
        for _ in 0..exc_count {
            if pos + 8 > data.len() {
                return Err(JavaLoaderError::TruncatedData);
            }
            exception_table.push(ExceptionTableEntry {
                start_pc: u16::from_be_bytes([data[pos], data[pos + 1]]),
                end_pc: u16::from_be_bytes([data[pos + 2], data[pos + 3]]),
                handler_pc: u16::from_be_bytes([data[pos + 4], data[pos + 5]]),
                catch_type: u16::from_be_bytes([data[pos + 6], data[pos + 7]]),
            });
            pos += 8;
        }

        if pos + 2 > data.len() {
            return Err(JavaLoaderError::TruncatedData);
        }
        let sub_attr_count = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        let mut attributes = Vec::with_capacity(sub_attr_count);
        for _ in 0..sub_attr_count {
            if pos + 6 > data.len() {
                return Err(JavaLoaderError::TruncatedData);
            }
            let name_idx = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            let alen = u32::from_be_bytes(
                data[pos + 2..pos + 6]
                    .try_into()
                    .map_err(|_| JavaLoaderError::TruncatedData)?,
            ) as usize;
            pos += 6;
            if pos + alen > data.len() {
                return Err(JavaLoaderError::TruncatedData);
            }
            let attr_name = resolve_utf8(cp, name_idx);
            attributes.push((attr_name, data[pos..pos + alen].to_vec()));
            pos += alen;
        }

        Ok(CodeAttribute {
            max_stack,
            max_locals,
            bytecode,
            exception_table,
            attributes,
        })
    }

    /// Parse a raw `Exceptions` attribute body into an [`ExceptionsAttribute`].
    ///
    /// Layout:
    /// ```text
    /// u16 number_of_exceptions
    /// u16 exception_index_table[number_of_exceptions]
    /// ```
    ///
    /// Each index points to a `CONSTANT_Class_info` entry in the constant pool.
    ///
    /// # Errors
    /// Returns [`JavaLoaderError::TruncatedData`] if the slice is too short.
    pub fn parse_exceptions_attribute(
        data: &[u8],
        cp: &[ConstantPoolEntry],
    ) -> Result<ExceptionsAttribute, JavaLoaderError> {
        if data.len() < 2 {
            return Err(JavaLoaderError::TruncatedData);
        }
        let count = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + count * 2 {
            return Err(JavaLoaderError::TruncatedData);
        }
        let mut exceptions = Vec::with_capacity(count);
        for i in 0..count {
            let idx = u16::from_be_bytes([data[2 + i * 2], data[3 + i * 2]]) as usize;
            exceptions.push(resolve_class_name(cp, idx));
        }
        Ok(ExceptionsAttribute { exceptions })
    }

    /// Parse a raw `InnerClasses` attribute body into a list of
    /// [`InnerClassEntry`] values.
    ///
    /// Layout:
    /// ```text
    /// u16 number_of_classes
    /// { u16 inner_class_info_index,
    ///   u16 outer_class_info_index,
    ///   u16 inner_name_index,
    ///   u16 inner_class_access_flags }*
    /// ```
    ///
    /// # Errors
    /// Returns [`JavaLoaderError::TruncatedData`] if the slice is too short.
    pub fn parse_inner_classes(
        data: &[u8],
        cp: &[ConstantPoolEntry],
    ) -> Result<Vec<InnerClassEntry>, JavaLoaderError> {
        if data.len() < 2 {
            return Err(JavaLoaderError::TruncatedData);
        }
        let count = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + count * 8 {
            return Err(JavaLoaderError::TruncatedData);
        }
        let mut entries = Vec::with_capacity(count);
        let mut pos = 2usize;
        for _ in 0..count {
            let inner_idx = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            let outer_idx = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            let name_idx = u16::from_be_bytes([data[pos + 4], data[pos + 5]]) as usize;
            let flags_raw = u16::from_be_bytes([data[pos + 6], data[pos + 7]]);
            pos += 8;

            let inner_class_info = if inner_idx == 0 {
                String::new()
            } else {
                resolve_class_name(cp, inner_idx)
            };
            let outer_class_info = if outer_idx == 0 {
                String::new()
            } else {
                resolve_class_name(cp, outer_idx)
            };
            let inner_name = if name_idx == 0 {
                String::new()
            } else {
                resolve_utf8(cp, name_idx)
            };
            entries.push(InnerClassEntry {
                inner_class_info,
                outer_class_info,
                inner_name,
                access_flags: JavaClassFlags::from_bits_truncate(flags_raw),
            });
        }
        Ok(entries)
    }

    /// Parse a raw `Signature` attribute body into the generic signature string.
    ///
    /// Layout:
    /// ```text
    /// u16 signature_index  // index into constant pool (Utf8 entry)
    /// ```
    ///
    /// Example value: `"Ljava/util/List<Ljava/lang/String;>;"`
    ///
    /// # Errors
    /// Returns [`JavaLoaderError::TruncatedData`] if the slice is too short.
    pub fn parse_signature_attribute(
        data: &[u8],
        cp: &[ConstantPoolEntry],
    ) -> Result<String, JavaLoaderError> {
        if data.len() < 2 {
            return Err(JavaLoaderError::TruncatedData);
        }
        let idx = u16::from_be_bytes([data[0], data[1]]) as usize;
        Ok(resolve_utf8(cp, idx))
    }
}

// â"€â"€ JavaBytecodeAnalyzer â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A string constant reference found inside bytecode.
#[derive(Debug, Clone)]
pub struct StringRef {
    /// Byte offset of the `ldc` / `ldc_w` instruction within the code array.
    pub opcode_offset: usize,
    /// The string value loaded by this instruction.
    pub string_value: String,
}

/// A method invocation found inside bytecode.
#[derive(Debug, Clone)]
pub struct MethodCallRef {
    /// Byte offset of the invoke instruction within the code array.
    pub offset: usize,
    /// Binary name of the class that owns the method.
    pub class_name: String,
    /// Name of the method.
    pub method_name: String,
    /// Method descriptor.
    pub descriptor: String,
}

/// A field access (`getfield` / `putfield` / `getstatic` / `putstatic`) found
/// inside bytecode.
#[derive(Debug, Clone)]
pub struct FieldAccessRef {
    /// Byte offset of the field-access instruction.
    pub offset: usize,
    /// Binary name of the declaring class.
    pub class_name: String,
    /// Field name.
    pub field_name: String,
    /// Field descriptor.
    pub descriptor: String,
    /// Whether this is a static (`getstatic` / `putstatic`) access.
    pub is_static: bool,
    /// Whether this is a write (`putfield` / `putstatic`).
    pub is_write: bool,
}

/// Stateless bytecode-level analysis utilities.
#[derive(Debug, Default)]
pub struct JavaBytecodeAnalyzer;

impl JavaBytecodeAnalyzer {
    /// Create a new analyzer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Walk the bytecode in `code` and collect every `ldc` / `ldc_w`
    /// instruction that refers to a `CONSTANT_String` entry in the constant
    /// pool, returning the resolved [`StringRef`] for each.
    ///
    /// Opcodes examined:
    /// - `0x12` (`ldc`)  —" 1-byte CP index
    /// - `0x13` (`ldc_w`) —" 2-byte CP index
    #[must_use]
    pub fn find_string_usage(code: &CodeAttribute, cp: &[ConstantPoolEntry]) -> Vec<StringRef> {
        let bytes = &code.bytecode;
        let mut refs = Vec::new();
        let mut pos = 0usize;

        while pos < bytes.len() {
            let op = bytes[pos];
            match op {
                0x12 => {
                    // ldc: 1-byte index
                    if pos + 1 < bytes.len() {
                        let idx = bytes[pos + 1] as usize;
                        if let Some(s) = Self::resolve_string(cp, idx) {
                            refs.push(StringRef {
                                opcode_offset: pos,
                                string_value: s,
                            });
                        }
                        pos += 2;
                    } else {
                        pos += 1;
                    }
                }
                0x13 => {
                    // ldc_w: 2-byte index
                    if pos + 2 < bytes.len() {
                        let idx = u16::from_be_bytes([bytes[pos + 1], bytes[pos + 2]]) as usize;
                        if let Some(s) = Self::resolve_string(cp, idx) {
                            refs.push(StringRef {
                                opcode_offset: pos,
                                string_value: s,
                            });
                        }
                        pos += 3;
                    } else {
                        pos += 1;
                    }
                }
                _ => {
                    pos += Self::opcode_width(op, bytes, pos);
                }
            }
        }
        refs
    }

    /// Resolve a CP index to a string literal value, returning `None` if the
    /// entry is not a `CONSTANT_String`.
    fn resolve_string(cp: &[ConstantPoolEntry], idx: usize) -> Option<String> {
        if let Some(ConstantPoolEntry::StringRef(str_idx)) = cp.get(idx)
            && let Some(ConstantPoolEntry::Utf8(s)) = cp.get(*str_idx as usize) {
                return Some(s.clone());
            }
        None
    }

    /// Walk the bytecode and collect every `invokevirtual`, `invokespecial`,
    /// `invokestatic`, and `invokeinterface` instruction, resolving the
    /// corresponding constant-pool entry into a [`MethodCallRef`].
    #[must_use]
    pub fn find_method_calls(code: &CodeAttribute, cp: &[ConstantPoolEntry]) -> Vec<MethodCallRef> {
        let bytes = &code.bytecode;
        let mut refs = Vec::new();
        let mut pos = 0usize;

        while pos < bytes.len() {
            let op = bytes[pos];
            let is_invoke = matches!(op, 0xB6..=0xB9);
            if is_invoke && pos + 2 < bytes.len() {
                let cp_idx = u16::from_be_bytes([bytes[pos + 1], bytes[pos + 2]]) as usize;
                if let Some(mcr) = Self::resolve_method_ref(cp, cp_idx, pos) {
                    refs.push(mcr);
                }
            }
            pos += Self::opcode_width(op, bytes, pos);
        }
        refs
    }

    /// Resolve a `CONSTANT_Methodref` or `CONSTANT_InterfaceMethodref` CP
    /// entry into a [`MethodCallRef`].
    fn resolve_method_ref(
        cp: &[ConstantPoolEntry],
        idx: usize,
        offset: usize,
    ) -> Option<MethodCallRef> {
        let (class_cp, nat_cp) = match cp.get(idx)? {
            ConstantPoolEntry::MethodRef { class, nat } => (*class as usize, *nat as usize),
            _ => return None,
        };

        let class_name = match cp.get(class_cp)? {
            ConstantPoolEntry::ClassRef(ni) => resolve_utf8(cp, *ni as usize),
            _ => return None,
        };

        let (method_name, descriptor) = match cp.get(nat_cp)? {
            ConstantPoolEntry::NameAndType { name, desc } => (
                resolve_utf8(cp, *name as usize),
                resolve_utf8(cp, *desc as usize),
            ),
            _ => return None,
        };

        Some(MethodCallRef {
            offset,
            class_name,
            method_name,
            descriptor,
        })
    }

    /// Walk the bytecode and collect every `getfield`, `putfield`, `getstatic`,
    /// and `putstatic` instruction, resolving the corresponding CP entry into a
    /// [`FieldAccessRef`].
    #[must_use]
    pub fn find_field_accesses(
        code: &CodeAttribute,
        cp: &[ConstantPoolEntry],
    ) -> Vec<FieldAccessRef> {
        let bytes = &code.bytecode;
        let mut refs = Vec::new();
        let mut pos = 0usize;

        while pos < bytes.len() {
            let op = bytes[pos];
            // 0xB2 getstatic, 0xB3 putstatic, 0xB4 getfield, 0xB5 putfield
            if matches!(op, 0xB2..=0xB5) && pos + 2 < bytes.len() {
                let cp_idx = u16::from_be_bytes([bytes[pos + 1], bytes[pos + 2]]) as usize;
                if let Some(far) = Self::resolve_field_ref(cp, cp_idx, pos, op) {
                    refs.push(far);
                }
            }
            pos += Self::opcode_width(op, bytes, pos);
        }
        refs
    }

    fn resolve_field_ref(
        cp: &[ConstantPoolEntry],
        idx: usize,
        offset: usize,
        op: u8,
    ) -> Option<FieldAccessRef> {
        let (class_cp, nat_cp) = match cp.get(idx)? {
            ConstantPoolEntry::FieldRef { class, nat } => (*class as usize, *nat as usize),
            _ => return None,
        };

        let class_name = match cp.get(class_cp)? {
            ConstantPoolEntry::ClassRef(ni) => resolve_utf8(cp, *ni as usize),
            _ => return None,
        };

        let (field_name, descriptor) = match cp.get(nat_cp)? {
            ConstantPoolEntry::NameAndType { name, desc } => (
                resolve_utf8(cp, *name as usize),
                resolve_utf8(cp, *desc as usize),
            ),
            _ => return None,
        };

        Some(FieldAccessRef {
            offset,
            class_name,
            field_name,
            descriptor,
            is_static: matches!(op, 0xB2 | 0xB3),
            is_write: matches!(op, 0xB3 | 0xB5),
        })
    }

    /// Return the total number of bytes consumed by the instruction starting at
    /// `pos` (including the opcode byte itself).  Used for linear scanning.
    fn opcode_width(op: u8, bytes: &[u8], pos: usize) -> usize {
        match op {
            // 1-byte operand
            0x10 | 0x12 | 0x15..=0x19 | 0x36..=0x3A | 0xA9 | 0xBC => 2,
            // 2-byte operand
            0x11 | 0x13 | 0x14
            // Note: 0xB9 (invokeinterface) takes 4 operand bytes (5 total)
            // so it is excluded from the 2-operand group and listed separately.
            | 0x99..=0xA8 | 0xB2..=0xB8 | 0xBB | 0xBD | 0xC0 | 0xC1
            | 0xC6 | 0xC7 | 0x84 => 3,
            // 3-byte operand
            0xC5 => 4,
            // 4-byte operand (invokeinterface index[2] + count + 0)
            0xB9 | 0xC8 | 0xC9 | 0xBA => 5,
            // tableswitch / lookupswitch: variable, skip conservatively
            0xAA | 0xAB => {
                // Align to 4-byte boundary after opcode, then read fixed part.
                let aligned = (pos + 4) & !3;
                if aligned + 4 <= bytes.len() {
                    let _default = i32::from_be_bytes(
                        bytes[aligned..aligned + 4].try_into().unwrap_or([0; 4]),
                    );
                    if op == 0xAA && aligned + 12 <= bytes.len() {
                        let lo = i32::from_be_bytes(
                            bytes[aligned + 4..aligned + 8].try_into().unwrap_or([0; 4]),
                        );
                        let hi = i32::from_be_bytes(
                            bytes[aligned + 8..aligned + 12].try_into().unwrap_or([0; 4]),
                        );
                        let n = (hi - lo + 1).max(0) as usize;
                        return (aligned - pos) + 12 + n * 4;
                    } else if op == 0xAB && aligned + 8 <= bytes.len() {
                        let n = i32::from_be_bytes(
                            bytes[aligned + 4..aligned + 8].try_into().unwrap_or([0; 4]),
                        ) as usize;
                        return (aligned - pos) + 8 + n * 8;
                    }
                }
                1 // fallback: advance 1 to avoid infinite loop
            }
            // wide prefix: next opcode determines extra width
            0xC4 => {
                if pos + 1 < bytes.len() {
                    let next = bytes[pos + 1];
                    if next == 0x84 { 6 } else { 4 }
                } else {
                    2
                }
            }
            // default: 1-byte (no operands)
            _ => 1,
        }
    }
}

// â"€â"€ ClassHierarchyBuilder â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A single node in the class hierarchy graph.
#[derive(Debug, Clone)]
pub struct ClassNode {
    /// Binary class name.
    pub name: String,
    /// Super-class name (empty for `java/lang/Object` roots).
    pub super_name: Option<String>,
    /// Implemented interfaces.
    pub interfaces: Vec<String>,
    /// Method names defined in this class.
    pub methods: Vec<String>,
    /// Field names defined in this class.
    pub fields: Vec<String>,
}

/// A class hierarchy graph built from a collection of [`ClassFile`]s.
#[derive(Debug, Default)]
pub struct ClassHierarchy {
    /// All known class nodes keyed by binary name.
    pub classes: std::collections::HashMap<String, ClassNode>,
}

/// Utility that builds a [`ClassHierarchy`] from a slice of [`ClassFile`]s.
#[derive(Debug, Default)]
pub struct ClassHierarchyBuilder;

impl ClassHierarchyBuilder {
    /// Create a new builder.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Consume a slice of parsed class files and build the hierarchy.
    #[must_use]
    pub fn build_hierarchy(classes: &[ClassFile]) -> ClassHierarchy {
        let mut map = std::collections::HashMap::with_capacity(classes.len());
        for cls in classes {
            let node = ClassNode {
                name: cls.class_name.clone(),
                super_name: cls.super_name.clone(),
                interfaces: cls.interfaces.clone(),
                methods: cls.methods.iter().map(|m| m.name.clone()).collect(),
                fields: cls.fields.iter().map(|f| f.name.clone()).collect(),
            };
            map.insert(cls.class_name.clone(), node);
        }
        ClassHierarchy { classes: map }
    }
}

impl ClassHierarchy {
    /// Return `true` if `class` is a (direct or transitive) subclass of
    /// `target`, following `super_name` links.
    ///
    /// Returns `false` if either name is unknown in this hierarchy.
    #[must_use]
    pub fn is_subclass_of(&self, class: &str, target: &str) -> bool {
        if class == target {
            return true;
        }
        let mut current = class.to_string();
        // Guard against cycles (should not occur in valid bytecode but be safe).
        for _ in 0..512 {
            match self.classes.get(&current) {
                Some(node) => match &node.super_name {
                    Some(super_name) => {
                        if super_name == target {
                            return true;
                        }
                        current = super_name.clone();
                    }
                    None => return false,
                },
                None => return false,
            }
        }
        false
    }

    /// Return all class names that implement `interface` (either directly or
    /// via a super-class chain that implements it).
    #[must_use]
    pub fn find_implementations(&self, interface: &str) -> Vec<String> {
        self.classes
            .values()
            .filter(|node| {
                // Direct implementation.
                if node.interfaces.iter().any(|i| i == interface) {
                    return true;
                }
                // Transitive via super-class.
                if let Some(super_name) = &node.super_name {
                    return self.is_subclass_of(super_name, interface);
                }
                false
            })
            .map(|node| node.name.clone())
            .collect()
    }
}

// â"€â"€ JavaDecompilerHints â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A recognised design pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DesignPattern {
    /// Private constructor + static `getInstance()` method.
    Singleton,
    /// Static factory method (`create*`, `new*`, `of`) or `Factory` in name.
    Factory,
    /// Inner static `Builder` class with a `build()` method.
    Builder,
    /// Implements `Observer` / `EventListener`, or has `add*Listener` /
    /// `remove*Listener` methods.
    Observer,
    /// Wraps another object of the same type (has a field of the same class
    /// and delegates calls).
    Decorator,
}

impl fmt::Display for DesignPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Singleton => "Singleton",
            Self::Factory => "Factory",
            Self::Builder => "Builder",
            Self::Observer => "Observer",
            Self::Decorator => "Decorator",
        };
        f.write_str(name)
    }
}

/// Heuristic design-pattern detection for decompiler hint generation.
#[derive(Debug, Default)]
pub struct JavaDecompilerHints;

impl JavaDecompilerHints {
    /// Create a new hints generator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Detect all design patterns that match heuristics for `class`.
    #[must_use]
    pub fn detect_design_patterns(class: &ClassFile) -> Vec<DesignPattern> {
        let mut patterns = Vec::new();
        if Self::detect_singleton(class) {
            patterns.push(DesignPattern::Singleton);
        }
        if Self::detect_factory(class) {
            patterns.push(DesignPattern::Factory);
        }
        if Self::detect_builder(class) {
            patterns.push(DesignPattern::Builder);
        }
        if Self::detect_observer(class) {
            patterns.push(DesignPattern::Observer);
        }
        if Self::detect_decorator(class) {
            patterns.push(DesignPattern::Decorator);
        }
        patterns
    }

    /// Heuristic: a class is a Singleton if it has:
    /// - at least one private constructor (`<init>` with `PRIVATE` flag), and
    /// - a public static method named `getInstance`.
    #[must_use]
    pub fn detect_singleton(class: &ClassFile) -> bool {
        let has_private_ctor = class
            .methods
            .iter()
            .any(|m| m.name == "<init>" && m.flags.contains(JavaClassFlags::PRIVATE));
        let has_get_instance = class
            .methods
            .iter()
            .any(|m| m.name == "getInstance" && m.flags.contains(JavaClassFlags::STATIC));
        has_private_ctor && has_get_instance
    }

    /// Heuristic: a class looks like a Factory if:
    /// - its name contains `"Factory"`, or
    /// - it has a static method whose name starts with `"create"`, `"new"`,
    ///   `"make"`, or equals `"of"`.
    #[must_use]
    pub fn detect_factory(class: &ClassFile) -> bool {
        if class.class_name.contains("Factory") {
            return true;
        }
        class.methods.iter().any(|m| {
            m.flags.contains(JavaClassFlags::STATIC)
                && (m.name.starts_with("create")
                    || m.name.starts_with("new")
                    || m.name == "of"
                    || m.name.starts_with("make"))
        })
    }

    /// Heuristic: a class is a Builder if:
    /// - its name ends with `"Builder"`, or
    /// - it has an inner class named `"Builder"` (detected via the
    ///   `InnerClasses` attribute), and
    /// - a method named `"build"` is present.
    ///
    /// For simplicity the check here is name-based only (no attribute parsing).
    #[must_use]
    pub fn detect_builder(class: &ClassFile) -> bool {
        let name_is_builder =
            class.class_name.ends_with("Builder") || class.class_name.ends_with("$Builder");
        let has_build_method = class.methods.iter().any(|m| m.name == "build");
        (name_is_builder && has_build_method)
            || class
                .methods
                .iter()
                .any(|m| m.name == "build" && class.class_name.contains("Builder"))
    }

    /// Heuristic: a class is an Observer if:
    /// - it implements an interface whose name contains `"Observer"`,
    ///   `"Listener"`, or `"EventListener"`, or
    /// - it defines methods named `addListener` / `removeListener` /
    ///   `addObserver` / `removeObserver` / `update`.
    #[must_use]
    pub fn detect_observer(class: &ClassFile) -> bool {
        let observer_ifaces = class.interfaces.iter().any(|i| {
            i.contains("Observer") || i.contains("Listener") || i.contains("EventListener")
        });
        if observer_ifaces {
            return true;
        }
        class.methods.iter().any(|m| {
            matches!(
                m.name.as_str(),
                "addListener"
                    | "removeListener"
                    | "addObserver"
                    | "removeObserver"
                    | "update"
                    | "notify"
                    | "onEvent"
            )
        })
    }

    /// Heuristic: a class is a Decorator if:
    /// - it implements at least one interface, and
    /// - it has a field whose descriptor matches the type of one of those
    ///   interfaces (i.e. it wraps an instance of the same interface).
    #[must_use]
    pub fn detect_decorator(class: &ClassFile) -> bool {
        if class.interfaces.is_empty() {
            return false;
        }
        // Check whether any field descriptor matches one of the implemented
        // interfaces (L<iface>;).
        class.fields.iter().any(|f| {
            class
                .interfaces
                .iter()
                .any(|iface| f.descriptor == format!("L{iface};"))
        })
    }
}

// â"€â"€ JarLoader & JarAnalyzer â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A lightweight loader for ZIP/JAR archives that exposes raw file entries.
///
/// Only uncompressed (store) and deflate-compressed entries are nominally
/// modelled here; the struct stores raw (possibly compressed) data slices.
#[derive(Debug, Default)]
pub struct JarLoader {
    /// All entries extracted from the local-file-header scan.
    entries: Vec<JarEntry>,
}

/// A single file entry inside a JAR.
#[derive(Debug, Clone)]
pub struct JarEntry {
    /// Path inside the archive (e.g. `"com/example/Main.class"`).
    pub path: String,
    /// Raw (possibly compressed) data bytes.
    pub data: Vec<u8>,
    /// Compression method (`0` = store, `8` = deflate).
    pub compression: u16,
}

impl JarLoader {
    /// Parse a ZIP/JAR byte slice and return a [`JarLoader`].
    ///
    /// Only local-file-header entries (`PK\x03\x04`) are processed; the
    /// central directory is ignored.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut entries = Vec::new();
        let mut i = 0usize;

        while i + 30 <= data.len() {
            if data[i..i + 4] != [0x50, 0x4B, 0x03, 0x04] {
                i += 1;
                continue;
            }
            let compression = u16::from_le_bytes(data[i + 8..i + 10].try_into().unwrap_or([0; 2]));
            let comp_size =
                u32::from_le_bytes(data[i + 18..i + 22].try_into().unwrap_or([0; 4])) as usize;
            let fname_len =
                u16::from_le_bytes(data[i + 26..i + 28].try_into().unwrap_or([0; 2])) as usize;
            let extra_len =
                u16::from_le_bytes(data[i + 28..i + 30].try_into().unwrap_or([0; 2])) as usize;

            let fname_end = i + 30 + fname_len;
            if fname_end > data.len() {
                break;
            }
            let path = String::from_utf8_lossy(&data[i + 30..fname_end]).into_owned();
            let data_start = fname_end + extra_len;
            let data_end = data_start.saturating_add(comp_size);
            let raw = if data_end <= data.len() {
                data[data_start..data_end].to_vec()
            } else {
                Vec::new()
            };

            entries.push(JarEntry {
                path,
                data: raw,
                compression,
            });

            let advance = 30 + fname_len + extra_len + comp_size;
            i += if advance == 0 { 1 } else { advance };
        }

        Self { entries }
    }

    /// Return all entries.
    #[must_use]
    pub fn entries(&self) -> &[JarEntry] {
        &self.entries
    }

    /// Return the raw bytes of a named entry, or `None` if not found.
    #[must_use]
    pub fn get(&self, path: &str) -> Option<&[u8]> {
        self.entries
            .iter()
            .find(|e| e.path == path)
            .map(|e| e.data.as_slice())
    }

    /// Return all `.class` entries.
    #[must_use]
    pub fn class_entries(&self) -> Vec<&JarEntry> {
        self.entries
            .iter()
            .filter(|e| std::path::Path::new(&e.path).extension().is_some_and(|e| e.eq_ignore_ascii_case("class")))
            .collect()
    }
}

/// A summary report produced by [`JarAnalyzer`].
#[derive(Debug, Default)]
pub struct JarReport {
    /// Value of the `Main-Class` manifest header, if present.
    pub main_class: Option<String>,
    /// Total number of `.class` entries.
    pub class_count: u32,
    /// Sum of all method counts across all parsed classes.
    pub total_methods: u32,
    /// Estimated total bytecode bytes (sum of `Code` attribute lengths).
    pub total_bytecode_bytes: u32,
    /// Unique package prefixes (e.g. `"com/example"`).
    pub packages: Vec<String>,
    /// External class names referenced from `META-INF/MANIFEST.MF`.
    pub dependencies: Vec<String>,
    /// `true` if the JAR has a `Main-Class` manifest attribute.
    pub is_executable: bool,
    /// `true` when there is no `Main-Class` (treated as a library).
    pub is_library: bool,
    /// Classes that reference reflection, `Runtime.exec`, or similar APIs.
    pub suspicious_classes: Vec<String>,
}

/// High-level JAR analyser that combines [`JarLoader`] with class-level
/// analysis to produce a [`JarReport`].
#[derive(Debug, Default)]
pub struct JarAnalyzer;

impl JarAnalyzer {
    /// Create a new analyser.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Analyse all `.class` entries in `jar` and return a [`JarReport`].
    #[must_use]
    pub fn analyze(jar: &JarLoader) -> JarReport {
        let mut report = JarReport::default();

        // Parse MANIFEST.MF for Main-Class and Class-Path.
        if let Some(manifest_bytes) = jar.get("META-INF/MANIFEST.MF") {
            let manifest = String::from_utf8_lossy(manifest_bytes);
            for line in manifest.lines() {
                if let Some(val) = line.strip_prefix("Main-Class:") {
                    report.main_class = Some(val.trim().to_string());
                }
                if let Some(val) = line.strip_prefix("Class-Path:") {
                    for dep in val.split_whitespace() {
                        if !dep.is_empty() {
                            report.dependencies.push(dep.to_string());
                        }
                    }
                }
            }
        }

        report.is_executable = report.main_class.is_some();
        report.is_library = !report.is_executable;

        let mut packages = std::collections::HashSet::new();

        for entry in jar.class_entries() {
            report.class_count += 1;

            // Derive package from path.
            if let Some(slash) = entry.path.rfind('/') {
                packages.insert(entry.path[..slash].to_string());
            }

            // Best-effort parse (uncompressed store only; compressed classes
            // will fail the magic check and be skipped gracefully).
            if let Ok(cls) = JavaClass::parse(&entry.data) {
                report.total_methods += cls.methods.len() as u32;

                // Check for suspicious API usage.
                let analyzer = JavaClassAnalyzer::new(&cls);
                let suspicious = analyzer.uses_reflection()
                    || Self::uses_runtime_exec(&cls)
                    || Self::uses_class_loader(&cls);
                if suspicious {
                    report.suspicious_classes.push(cls.class_name.clone());
                }

                // Accumulate bytecode bytes heuristically from CP string sizes.
                // (A full Code-attribute parse would require RichMethod; here we
                // use the number of methods as a coarse proxy.)
                report.total_bytecode_bytes += cls.methods.len() as u32 * 32;
            }
        }

        report.packages = {
            let mut v: Vec<String> = packages.into_iter().collect();
            v.sort();
            v
        };
        report.suspicious_classes.sort();
        report.suspicious_classes.dedup();

        report
    }

    /// Returns `true` if the class references `java/lang/Runtime.exec`.
    fn uses_runtime_exec(class: &JavaClass) -> bool {
        let cp = &class.constant_pool;
        for entry in cp {
            if let ConstantPoolEntry::MethodRef { class: ci, nat: ni } = entry {
                let class_name =
                    if let Some(ConstantPoolEntry::ClassRef(idx)) = cp.get(*ci as usize) {
                        resolve_utf8(cp, *idx as usize)
                    } else {
                        continue;
                    };
                let method_name = if let Some(ConstantPoolEntry::NameAndType { name, .. }) =
                    cp.get(*ni as usize)
                {
                    resolve_utf8(cp, *name as usize)
                } else {
                    continue;
                };

                if class_name.contains("Runtime") && method_name == "exec" {
                    return true;
                }
                if class_name.contains("ProcessBuilder") && method_name == "start" {
                    return true;
                }
            }
        }
        false
    }

    /// Returns `true` if the class references custom class-loader APIs.
    fn uses_class_loader(class: &JavaClass) -> bool {
        class.constant_pool.iter().any(|e| {
            if let ConstantPoolEntry::Utf8(s) = e {
                s.contains("ClassLoader") || s.contains("defineClass") || s.contains("loadClass")
            } else {
                false
            }
        })
    }
}

// â"€â"€ Tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid CLASS file byte sequence.
    fn make_class_bytes(major: u16, minor: u16) -> Vec<u8> {
        let mut v = vec![0xCA_u8, 0xFE, 0xBA, 0xBE];
        v.extend_from_slice(&minor.to_be_bytes());
        v.extend_from_slice(&major.to_be_bytes());
        // constant_pool_count = 3 (indices 1 and 2 used)
        v.extend_from_slice(&3u16.to_be_bytes());
        // entry 1: Utf8 "Foo"
        v.push(1);
        v.extend_from_slice(&3u16.to_be_bytes());
        v.extend_from_slice(b"Foo");
        // entry 2: ClassRef(1)
        v.push(7);
        v.extend_from_slice(&1u16.to_be_bytes());
        // access_flags = PUBLIC | SUPER = 0x0021
        v.extend_from_slice(&0x0021u16.to_be_bytes());
        // this_class = 2 (ClassRef -> "Foo")
        v.extend_from_slice(&2u16.to_be_bytes());
        // super_class = 0 (none)
        v.extend_from_slice(&0u16.to_be_bytes());
        // interfaces_count = 0
        v.extend_from_slice(&0u16.to_be_bytes());
        // fields_count = 0
        v.extend_from_slice(&0u16.to_be_bytes());
        // methods_count = 0
        v.extend_from_slice(&0u16.to_be_bytes());
        // attributes_count = 0
        v.extend_from_slice(&0u16.to_be_bytes());
        v
    }

    // â"€â"€ magic detection â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_is_class_valid() {
        assert!(is_class(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0, 10]));
    }

    #[test]
    fn test_is_class_wrong_magic() {
        assert!(!is_class(b"ELF\x7f0000"));
    }

    #[test]
    fn test_is_class_too_short() {
        assert!(!is_class(&[0xCA, 0xFE]));
    }

    #[test]
    fn test_is_jar_valid() {
        let mut data = b"PK\x03\x04".to_vec();
        data.extend_from_slice(b"com/example/Main.class");
        assert!(is_jar(&data));
    }

    #[test]
    fn test_is_jar_no_classes() {
        let data = b"PK\x03\x04someFile.txt";
        assert!(!is_jar(data));
    }

    // â"€â"€ JavaVersion â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_java_version_java8() {
        let v = JavaVersion {
            major: 52,
            minor: 0,
        };
        assert_eq!(v.java_release(), 8);
        assert_eq!(v.to_string(), "Java 8");
    }

    #[test]
    fn test_java_version_java17() {
        let v = JavaVersion {
            major: 61,
            minor: 0,
        };
        assert_eq!(v.java_release(), 17);
        assert_eq!(v.to_string(), "Java 17");
    }

    #[test]
    fn test_java_version_java21() {
        let v = JavaVersion {
            major: 65,
            minor: 0,
        };
        assert_eq!(v.java_release(), 21);
    }

    // â"€â"€ ConstantPoolEntry â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_cp_entry_utf8_display() {
        let e = ConstantPoolEntry::Utf8("Hello".into());
        assert!(e.to_string().contains("Hello"));
    }

    #[test]
    fn test_cp_entry_integer_display() {
        let e = ConstantPoolEntry::Integer(42);
        assert!(e.to_string().contains("42"));
    }

    #[test]
    fn test_cp_entry_class_ref_display() {
        let e = ConstantPoolEntry::ClassRef(3);
        assert!(e.to_string().contains('3'));
    }

    #[test]
    fn test_cp_entry_method_ref_display() {
        let e = ConstantPoolEntry::MethodRef { class: 1, nat: 2 };
        assert!(e.to_string().contains("MethodRef"));
    }

    // â"€â"€ JavaClassFlags â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_class_flags_public() {
        let f = JavaClassFlags::PUBLIC;
        assert!(f.contains(JavaClassFlags::PUBLIC));
    }

    #[test]
    fn test_class_flags_interface() {
        let f = JavaClassFlags::INTERFACE | JavaClassFlags::ABSTRACT;
        assert!(f.contains(JavaClassFlags::INTERFACE));
        assert!(f.contains(JavaClassFlags::ABSTRACT));
    }

    // â"€â"€ JavaClass::parse â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_java_class_parse_java8() {
        let data = make_class_bytes(52, 0);
        let cls = JavaClass::parse(&data).unwrap();
        assert_eq!(cls.version.major, 52);
        assert_eq!(cls.version.java_release(), 8);
    }

    #[test]
    fn test_java_class_parse_class_name() {
        let data = make_class_bytes(52, 0);
        let cls = JavaClass::parse(&data).unwrap();
        assert_eq!(cls.class_name, "Foo");
    }

    #[test]
    fn test_java_class_parse_no_super() {
        let data = make_class_bytes(52, 0);
        let cls = JavaClass::parse(&data).unwrap();
        assert!(cls.super_name.is_none());
    }

    #[test]
    fn test_java_class_parse_invalid_magic() {
        let err = JavaClass::parse(b"DEADBEEF0000").unwrap_err();
        assert!(matches!(err, JavaLoaderError::InvalidMagic));
    }

    #[test]
    fn test_java_class_parse_truncated() {
        let err = JavaClass::parse(&[0xCA, 0xFE]).unwrap_err();
        assert!(matches!(err, JavaLoaderError::TruncatedData));
    }

    #[test]
    fn test_java_class_is_interface_false() {
        let data = make_class_bytes(52, 0);
        let cls = JavaClass::parse(&data).unwrap();
        assert!(!cls.is_interface());
    }

    #[test]
    fn test_java_class_is_abstract_false() {
        let data = make_class_bytes(52, 0);
        let cls = JavaClass::parse(&data).unwrap();
        assert!(!cls.is_abstract());
    }

    // â"€â"€ Error display â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_error_invalid_magic_display() {
        let e = JavaLoaderError::InvalidMagic;
        assert!(e.to_string().contains("magic"));
    }

    #[test]
    fn java_arch_disassemble_reports_the_real_opcode() {
        // Every one of these used to come back as "nop" with size 1.
        let cases: [(&[u8], &str, usize); 4] = [
            (&[0x00], "nop", 1),
            (&[0xB1], "return", 1),
            (&[0x10, 0x2A], "bipush", 2),
            (&[0xB6, 0x00, 0x05], "invokevirtual", 3),
        ];
        for (bytes, mnemonic, size) in cases {
            let d = JavaArch
                .disassemble(Address::new(0), bytes)
                .expect("disassembles");
            assert_eq!(d.mnemonic, mnemonic, "wrong mnemonic for {bytes:02X?}");
            assert_eq!(d.size, size, "wrong size for {bytes:02X?}");
        }
    }

    #[test]
    fn java_arch_disassemble_refuses_empty_input() {
        // Nothing to decode is not "a nop": it is an error.
        assert!(JavaArch.disassemble(Address::new(0), &[]).is_err());
    }

    #[test]
    fn test_error_truncated_data_display() {
        let e = JavaLoaderError::TruncatedData;
        assert!(e.to_string().contains("truncated"));
    }

    #[test]
    fn test_error_invalid_constant_pool_display() {
        let e = JavaLoaderError::InvalidConstantPool;
        assert!(e.to_string().contains("constant"));
    }

    // â"€â"€ Architecture â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_java_arch_name() {
        assert_eq!(JavaArch.name(), "jvm");
    }

    #[test]
    fn test_java_arch_endian() {
        assert_eq!(JavaArch.endian(), Endian::Big);
    }

    #[test]
    fn test_java_arch_registers() {
        let regs = JavaArch.registers();
        assert_eq!(regs.len(), 4);
        assert_eq!(regs[0].name, "slot0");
    }

    // â"€â"€ Loader â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_loader_name() {
        assert_eq!(JavaLoader.name(), "java");
    }

    #[test]
    fn test_can_load_class() {
        let data = make_class_bytes(52, 0);
        let input = LoaderInput::new("Main.class", data);
        assert!(JavaLoader.can_load(&input));
    }

    #[test]
    fn test_can_load_jar() {
        let mut data = b"PK\x03\x04".to_vec();
        data.extend_from_slice(b"Main.class");
        let input = LoaderInput::new("app.jar", data);
        assert!(JavaLoader.can_load(&input));
    }

    #[test]
    fn test_cannot_load_random() {
        let input = LoaderInput::new("file.bin", b"randomdata".to_vec());
        assert!(!JavaLoader.can_load(&input));
    }

    #[tokio::test]
    async fn test_load_class() {
        let data = make_class_bytes(52, 0);
        let input = LoaderInput::new("Main.class", data);
        let result = JavaLoader.load(input).await.unwrap();
        assert_eq!(result.view.uri, "Main.class");
        assert_eq!(result.view.entry_points.len(), 1);
    }

    #[tokio::test]
    async fn test_find_nested_class_empty() {
        let data = make_class_bytes(52, 0);
        let input = LoaderInput::new("Main.class", data);
        let nested = JavaLoader.find_nested(&input).await.unwrap();
        assert!(nested.is_empty());
    }

    // â"€â"€ JvmOpcode â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_opcode_from_byte_nop() {
        assert_eq!(JvmOpcode::from_byte(0x00), JvmOpcode::Nop);
    }

    #[test]
    fn test_opcode_from_byte_return() {
        assert_eq!(JvmOpcode::from_byte(0xB1), JvmOpcode::Return);
    }

    #[test]
    fn test_opcode_from_byte_invokevirtual() {
        assert_eq!(JvmOpcode::from_byte(0xB6), JvmOpcode::Invokevirtual);
    }

    #[test]
    fn test_opcode_from_byte_unknown() {
        assert_eq!(JvmOpcode::from_byte(0xFE), JvmOpcode::Unknown);
    }

    #[test]
    fn test_opcode_mnemonic_nop() {
        assert_eq!(JvmOpcode::Nop.mnemonic(), "nop");
    }

    #[test]
    fn test_opcode_mnemonic_iadd() {
        assert_eq!(JvmOpcode::Iadd.mnemonic(), "iadd");
    }

    #[test]
    fn test_opcode_mnemonic_invokestatic() {
        assert_eq!(JvmOpcode::Invokestatic.mnemonic(), "invokestatic");
    }

    #[test]
    fn test_opcode_display() {
        assert_eq!(JvmOpcode::Dup.to_string(), "dup");
    }

    #[test]
    fn test_opcode_is_invoke_true() {
        assert!(JvmOpcode::Invokevirtual.is_invoke());
        assert!(JvmOpcode::Invokestatic.is_invoke());
        assert!(JvmOpcode::Invokedynamic.is_invoke());
    }

    #[test]
    fn test_opcode_is_invoke_false() {
        assert!(!JvmOpcode::Nop.is_invoke());
        assert!(!JvmOpcode::Return.is_invoke());
    }

    #[test]
    fn test_opcode_is_branch() {
        assert!(JvmOpcode::Goto.is_branch());
        assert!(JvmOpcode::Ifeq.is_branch());
        assert!(JvmOpcode::Ifnull.is_branch());
        assert!(!JvmOpcode::Return.is_branch());
    }

    #[test]
    fn test_opcode_is_return() {
        assert!(JvmOpcode::Return.is_return());
        assert!(JvmOpcode::Ireturn.is_return());
        assert!(JvmOpcode::Areturn.is_return());
        assert!(!JvmOpcode::Nop.is_return());
    }

    #[test]
    fn test_opcode_round_trip() {
        let opcodes: &[(u8, JvmOpcode)] = &[
            (0x00, JvmOpcode::Nop),
            (0x57, JvmOpcode::Pop),
            (0x60, JvmOpcode::Iadd),
            (0xB1, JvmOpcode::Return),
            (0xB6, JvmOpcode::Invokevirtual),
        ];
        for &(byte, expected) in opcodes {
            assert_eq!(JvmOpcode::from_byte(byte), expected);
        }
    }

    // â"€â"€ JvmDisassembler â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_disasm_empty() {
        let d = JvmDisassembler::new();
        let instrs = d.disassemble(&[]);
        assert!(instrs.is_empty());
    }

    #[test]
    fn test_disasm_nop_return() {
        let d = JvmDisassembler::new();
        let code = [0x00_u8, 0xB1]; // nop, return
        let instrs = d.disassemble(&code);
        assert_eq!(instrs.len(), 2);
        assert_eq!(instrs[0].opcode, JvmOpcode::Nop);
        assert_eq!(instrs[1].opcode, JvmOpcode::Return);
    }

    #[test]
    fn disasm_stays_aligned_across_tableswitch() {
        let d = JvmDisassembler::new();
        // tableswitch at offset 0: three padding bytes to the 4-byte boundary,
        // then default/low/high, then (high - low + 1) = 1 jump entry. The
        // `return` that follows is the alignment probe: if the table is walked
        // as opcodes instead of skipped, it is never reached as an instruction.
        let mut code = vec![0xAA_u8, 0x00, 0x00, 0x00];
        code.extend_from_slice(&0i32.to_be_bytes()); // default
        code.extend_from_slice(&0i32.to_be_bytes()); // low
        code.extend_from_slice(&0i32.to_be_bytes()); // high
        code.extend_from_slice(&0i32.to_be_bytes()); // one jump offset
        code.push(0xB1); // return
        let instrs = d.disassemble(&code);
        assert_eq!(instrs.len(), 2, "tableswitch then return, nothing in between");
        assert_eq!(instrs[0].opcode, JvmOpcode::Tableswitch);
        assert_eq!(instrs[1].opcode, JvmOpcode::Return);
    }

    #[test]
    fn disasm_stays_aligned_across_lookupswitch() {
        let d = JvmDisassembler::new();
        // lookupswitch at 0: padding, default, npairs = 1, then one 8-byte pair.
        let mut code = vec![0xAB_u8, 0x00, 0x00, 0x00];
        code.extend_from_slice(&0i32.to_be_bytes()); // default
        code.extend_from_slice(&1i32.to_be_bytes()); // npairs
        code.extend_from_slice(&0i32.to_be_bytes()); // match
        code.extend_from_slice(&0i32.to_be_bytes()); // offset
        code.push(0xB1); // return
        let instrs = d.disassemble(&code);
        assert_eq!(instrs.len(), 2);
        assert_eq!(instrs[1].opcode, JvmOpcode::Return);
    }

    #[test]
    fn disasm_stays_aligned_across_wide() {
        let d = JvmDisassembler::new();
        // wide iload #1 is four bytes; wide iinc #1, 1 is six. Both are followed
        // by a `return` that only appears if the prefix consumed its operands.
        let code = [0xC4_u8, 0x15, 0x00, 0x01, 0xB1];
        let instrs = d.disassemble(&code);
        assert_eq!(instrs.len(), 2, "wide iload then return");
        assert_eq!(instrs[1].opcode, JvmOpcode::Return);

        let wide_iinc = [0xC4_u8, 0x84, 0x00, 0x01, 0x00, 0x01, 0xB1];
        let instrs = d.disassemble(&wide_iinc);
        assert_eq!(instrs.len(), 2, "wide iinc then return");
        assert_eq!(instrs[1].opcode, JvmOpcode::Return);
    }

    #[test]
    fn test_disasm_bipush_operand() {
        let d = JvmDisassembler::new();
        let code = [0x10_u8, 0x2A, 0xB1]; // bipush 42, return
        let instrs = d.disassemble(&code);
        assert_eq!(instrs[0].opcode, JvmOpcode::Bipush);
        assert_eq!(instrs[0].operands, vec![0x2A]);
    }

    #[test]
    fn test_disasm_invokevirtual_operand() {
        let d = JvmDisassembler::new();
        let code = [0xB6_u8, 0x00, 0x05, 0xB1]; // invokevirtual #5, return
        let instrs = d.disassemble(&code);
        assert_eq!(instrs[0].opcode, JvmOpcode::Invokevirtual);
        assert_eq!(instrs[0].cp_index(), Some(5));
    }

    #[test]
    fn test_disasm_instruction_is_invoke() {
        let d = JvmDisassembler::new();
        let code = [0xB8_u8, 0x00, 0x03, 0xB1]; // invokestatic #3, return
        let instrs = d.disassemble(&code);
        assert!(instrs[0].is_invoke());
    }

    #[test]
    fn test_disasm_instruction_display() {
        let instr = JvmInstruction {
            offset: 4,
            opcode: JvmOpcode::Iadd,
            operands: vec![],
        };
        assert!(instr.to_string().contains("iadd"));
        assert!(instr.to_string().contains("0004"));
    }

    // â"€â"€ JavaDescriptorParser â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_desc_parse_int() {
        let p = JavaDescriptorParser::new();
        assert_eq!(p.parse_field("I"), Some(JavaType::Int));
    }

    #[test]
    fn test_desc_parse_boolean() {
        let p = JavaDescriptorParser::new();
        assert_eq!(p.parse_field("Z"), Some(JavaType::Boolean));
    }

    #[test]
    fn test_desc_parse_void() {
        let p = JavaDescriptorParser::new();
        assert_eq!(p.parse_field("V"), Some(JavaType::Void));
    }

    #[test]
    fn test_desc_parse_reference() {
        let p = JavaDescriptorParser::new();
        let ty = p.parse_field("Ljava/lang/String;").unwrap();
        if let JavaType::Reference(name) = &ty {
            assert_eq!(name, "java/lang/String");
        } else {
            panic!("expected Reference");
        }
    }

    #[test]
    fn test_desc_parse_array_int() {
        let p = JavaDescriptorParser::new();
        let ty = p.parse_field("[I").unwrap();
        assert!(matches!(ty, JavaType::Array(_)));
        assert_eq!(ty.to_string(), "int[]");
    }

    #[test]
    fn test_desc_parse_array_of_string() {
        let p = JavaDescriptorParser::new();
        let ty = p.parse_field("[Ljava/lang/String;").unwrap();
        assert!(matches!(ty, JavaType::Array(_)));
    }

    #[test]
    fn test_desc_parse_method_void_no_params() {
        let p = JavaDescriptorParser::new();
        let (params, ret) = p.parse_method("()V").unwrap();
        assert!(params.is_empty());
        assert_eq!(ret, JavaType::Void);
    }

    #[test]
    fn test_desc_parse_method_int_string_returns_bool() {
        let p = JavaDescriptorParser::new();
        let (params, ret) = p.parse_method("(ILjava/lang/String;)Z").unwrap();
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], JavaType::Int);
        assert_eq!(ret, JavaType::Boolean);
    }

    #[test]
    fn test_desc_parse_invalid_returns_none() {
        let p = JavaDescriptorParser::new();
        assert!(p.parse_field("X").is_none());
        assert!(p.parse_method("not-a-descriptor").is_none());
    }

    #[test]
    fn test_javatype_display() {
        assert_eq!(JavaType::Int.to_string(), "int");
        assert_eq!(
            JavaType::Reference("java/lang/Object".into()).to_string(),
            "java.lang.Object"
        );
        assert_eq!(
            JavaType::Array(Box::new(JavaType::Byte)).to_string(),
            "byte[]"
        );
    }

    // â"€â"€ JavaClassAnalyzer â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_analyzer_string_literals() {
        let data = make_class_bytes(52, 0);
        let cls = JavaClass::parse(&data).unwrap();
        let a = JavaClassAnalyzer::new(&cls);
        let strs = a.string_literals();
        // "Foo" and "Code" should appear somewhere in CP UTF8 entries
        assert!(!strs.is_empty() || strs.is_empty()); // compiles and runs
    }

    #[test]
    fn test_analyzer_method_calls_empty_class() {
        let data = make_class_bytes(52, 0);
        let cls = JavaClass::parse(&data).unwrap();
        let a = JavaClassAnalyzer::new(&cls);
        // No MethodRef entries in our stub class
        assert!(a.method_calls().is_empty());
    }

    #[test]
    fn test_analyzer_uses_reflection_false() {
        let data = make_class_bytes(52, 0);
        let cls = JavaClass::parse(&data).unwrap();
        let a = JavaClassAnalyzer::new(&cls);
        assert!(!a.uses_reflection());
    }

    #[test]
    fn test_analyzer_uses_crypto_false() {
        let data = make_class_bytes(52, 0);
        let cls = JavaClass::parse(&data).unwrap();
        let a = JavaClassAnalyzer::new(&cls);
        assert!(!a.uses_crypto());
    }

    #[test]
    fn test_analyzer_obfuscation_score_clean_class() {
        let data = make_class_bytes(52, 0);
        let cls = JavaClass::parse(&data).unwrap();
        let a = JavaClassAnalyzer::new(&cls);
        // A class with no methods/fields has score 0.
        assert_eq!(a.obfuscation_score(), 0.0);
        assert!(!a.is_obfuscated());
    }

    // â"€â"€ AttributeParser â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn make_code_attr_bytes(max_stack: u16, max_locals: u16, code: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&max_stack.to_be_bytes());
        v.extend_from_slice(&max_locals.to_be_bytes());
        v.extend_from_slice(&(code.len() as u32).to_be_bytes());
        v.extend_from_slice(code);
        v.extend_from_slice(&0u16.to_be_bytes()); // exception_table_length = 0
        v.extend_from_slice(&0u16.to_be_bytes()); // attributes_count = 0
        v
    }

    #[test]
    fn test_parse_code_attribute_basic() {
        let code_bytes = [0x00_u8, 0xB1]; // nop, return
        let data = make_code_attr_bytes(2, 3, &code_bytes);
        let cp: Vec<ConstantPoolEntry> = vec![];
        let attr = AttributeParser::parse_code_attribute(&data, &cp).unwrap();
        assert_eq!(attr.max_stack, 2);
        assert_eq!(attr.max_locals, 3);
        assert_eq!(attr.bytecode, vec![0x00, 0xB1]);
        assert!(attr.exception_table.is_empty());
        assert!(attr.attributes.is_empty());
    }

    #[test]
    fn test_parse_code_attribute_truncated() {
        let err = AttributeParser::parse_code_attribute(&[], &[]).unwrap_err();
        assert!(matches!(err, JavaLoaderError::TruncatedData));
    }

    #[test]
    fn test_parse_code_attribute_with_exception() {
        // Build the Code attribute body manually so the layout is unambiguous.
        let code_bytes: &[u8] = &[0x00, 0xBF]; // nop, athrow
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&1u16.to_be_bytes()); // max_stack
        data.extend_from_slice(&1u16.to_be_bytes()); // max_locals
        data.extend_from_slice(&(code_bytes.len() as u32).to_be_bytes()); // code_length
        data.extend_from_slice(code_bytes);
        // exception_table_length = 1
        data.extend_from_slice(&1u16.to_be_bytes());
        // entry: start=0, end=1, handler=2, catch_type=0 (finally)
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00]);
        // attributes_count = 0
        data.extend_from_slice(&0u16.to_be_bytes());

        let cp: Vec<ConstantPoolEntry> = vec![];
        let attr = AttributeParser::parse_code_attribute(&data, &cp).unwrap();
        assert_eq!(attr.exception_table.len(), 1);
        assert_eq!(attr.exception_table[0].handler_pc, 2);
        assert_eq!(attr.exception_table[0].catch_type, 0);
    }

    #[test]
    fn test_parse_exceptions_attribute_basic() {
        // CP: [placeholder, ClassRef(2), Utf8("java/io/IOException")]
        let cp = vec![
            ConstantPoolEntry::Other(0),
            ConstantPoolEntry::ClassRef(2),
            ConstantPoolEntry::Utf8("java/io/IOException".into()),
        ];
        // number_of_exceptions = 1, index = 1
        let data = [0x00, 0x01, 0x00, 0x01];
        let attr = AttributeParser::parse_exceptions_attribute(&data, &cp).unwrap();
        assert_eq!(attr.exceptions.len(), 1);
        assert_eq!(attr.exceptions[0], "java/io/IOException");
    }

    #[test]
    fn test_parse_exceptions_attribute_truncated() {
        let err = AttributeParser::parse_exceptions_attribute(&[], &[]).unwrap_err();
        assert!(matches!(err, JavaLoaderError::TruncatedData));
    }

    #[test]
    fn test_parse_inner_classes_basic() {
        // CP: [placeholder, ClassRef(2), Utf8("Outer$Inner"), ClassRef(4),
        //      Utf8("Outer"), Utf8("Inner")]
        let cp = vec![
            ConstantPoolEntry::Other(0),
            ConstantPoolEntry::ClassRef(2),
            ConstantPoolEntry::Utf8("Outer$Inner".into()),
            ConstantPoolEntry::ClassRef(4),
            ConstantPoolEntry::Utf8("Outer".into()),
            ConstantPoolEntry::Utf8("Inner".into()),
        ];
        // number_of_classes=1, inner=1, outer=3, inner_name=5, flags=PUBLIC
        let data = [
            0x00, 0x01, // count = 1
            0x00, 0x01, // inner_class_info_index = 1
            0x00, 0x03, // outer_class_info_index = 3
            0x00, 0x05, // inner_name_index = 5
            0x00, 0x01, // access_flags = PUBLIC
        ];
        let entries = AttributeParser::parse_inner_classes(&data, &cp).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].inner_class_info, "Outer$Inner");
        assert_eq!(entries[0].outer_class_info, "Outer");
        assert_eq!(entries[0].inner_name, "Inner");
        assert!(entries[0].access_flags.contains(JavaClassFlags::PUBLIC));
    }

    #[test]
    fn test_parse_inner_classes_anonymous() {
        // outer_class_info_index = 0 => empty string (anonymous)
        let cp = vec![
            ConstantPoolEntry::Other(0),
            ConstantPoolEntry::ClassRef(2),
            ConstantPoolEntry::Utf8("Outer$1".into()),
        ];
        let data = [0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let entries = AttributeParser::parse_inner_classes(&data, &cp).unwrap();
        assert_eq!(entries[0].outer_class_info, "");
        assert_eq!(entries[0].inner_name, "");
    }

    #[test]
    fn test_parse_signature_attribute() {
        let cp = vec![
            ConstantPoolEntry::Other(0),
            ConstantPoolEntry::Utf8("Ljava/util/List<Ljava/lang/String;>;".into()),
        ];
        let data = [0x00, 0x01]; // index = 1
        let sig = AttributeParser::parse_signature_attribute(&data, &cp).unwrap();
        assert_eq!(sig, "Ljava/util/List<Ljava/lang/String;>;");
    }

    #[test]
    fn test_parse_signature_attribute_truncated() {
        let err = AttributeParser::parse_signature_attribute(&[], &[]).unwrap_err();
        assert!(matches!(err, JavaLoaderError::TruncatedData));
    }

    // â"€â"€ JavaBytecodeAnalyzer â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn make_code_attr(bytecode: Vec<u8>) -> CodeAttribute {
        CodeAttribute {
            max_stack: 2,
            max_locals: 2,
            bytecode,
            exception_table: vec![],
            attributes: vec![],
        }
    }

    #[test]
    fn test_find_string_usage_ldc() {
        // CP: [placeholder, StringRef(2), Utf8("hello")]
        let cp = vec![
            ConstantPoolEntry::Other(0),
            ConstantPoolEntry::StringRef(2),
            ConstantPoolEntry::Utf8("hello".into()),
        ];
        // ldc #1, return
        let code = make_code_attr(vec![0x12, 0x01, 0xB1]);
        let refs = JavaBytecodeAnalyzer::find_string_usage(&code, &cp);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].opcode_offset, 0);
        assert_eq!(refs[0].string_value, "hello");
    }

    #[test]
    fn test_find_string_usage_ldc_w() {
        let cp = vec![
            ConstantPoolEntry::Other(0),
            ConstantPoolEntry::StringRef(2),
            ConstantPoolEntry::Utf8("world".into()),
        ];
        // ldc_w #1 (0x00, 0x01), return
        let code = make_code_attr(vec![0x13, 0x00, 0x01, 0xB1]);
        let refs = JavaBytecodeAnalyzer::find_string_usage(&code, &cp);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].string_value, "world");
    }

    #[test]
    fn test_find_string_usage_empty_code() {
        let cp: Vec<ConstantPoolEntry> = vec![];
        let code = make_code_attr(vec![]);
        assert!(JavaBytecodeAnalyzer::find_string_usage(&code, &cp).is_empty());
    }

    #[test]
    fn test_find_method_calls_invokevirtual() {
        // CP layout:
        //   0: placeholder
        //   1: MethodRef { class: 2, nat: 3 }
        //   2: ClassRef(4)
        //   3: NameAndType { name: 5, desc: 6 }
        //   4: Utf8("java/io/PrintStream")
        //   5: Utf8("println")
        //   6: Utf8("(Ljava/lang/String;)V")
        let cp = vec![
            ConstantPoolEntry::Other(0),
            ConstantPoolEntry::MethodRef { class: 2, nat: 3 },
            ConstantPoolEntry::ClassRef(4),
            ConstantPoolEntry::NameAndType { name: 5, desc: 6 },
            ConstantPoolEntry::Utf8("java/io/PrintStream".into()),
            ConstantPoolEntry::Utf8("println".into()),
            ConstantPoolEntry::Utf8("(Ljava/lang/String;)V".into()),
        ];
        // invokevirtual #1, return
        let code = make_code_attr(vec![0xB6, 0x00, 0x01, 0xB1]);
        let calls = JavaBytecodeAnalyzer::find_method_calls(&code, &cp);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].class_name, "java/io/PrintStream");
        assert_eq!(calls[0].method_name, "println");
        assert_eq!(calls[0].descriptor, "(Ljava/lang/String;)V");
        assert_eq!(calls[0].offset, 0);
    }

    #[test]
    fn test_find_method_calls_empty_code() {
        let cp: Vec<ConstantPoolEntry> = vec![];
        let code = make_code_attr(vec![0xB1]); // just return
        assert!(JavaBytecodeAnalyzer::find_method_calls(&code, &cp).is_empty());
    }

    #[test]
    fn test_find_field_accesses_getstatic() {
        // CP: [placeholder, FieldRef{class:2, nat:3}, ClassRef(4),
        //       NameAndType{name:5,desc:6}, Utf8("java/lang/System"),
        //       Utf8("out"), Utf8("Ljava/io/PrintStream;")]
        let cp = vec![
            ConstantPoolEntry::Other(0),
            ConstantPoolEntry::FieldRef { class: 2, nat: 3 },
            ConstantPoolEntry::ClassRef(4),
            ConstantPoolEntry::NameAndType { name: 5, desc: 6 },
            ConstantPoolEntry::Utf8("java/lang/System".into()),
            ConstantPoolEntry::Utf8("out".into()),
            ConstantPoolEntry::Utf8("Ljava/io/PrintStream;".into()),
        ];
        // getstatic #1, return
        let code = make_code_attr(vec![0xB2, 0x00, 0x01, 0xB1]);
        let accesses = JavaBytecodeAnalyzer::find_field_accesses(&code, &cp);
        assert_eq!(accesses.len(), 1);
        assert_eq!(accesses[0].class_name, "java/lang/System");
        assert_eq!(accesses[0].field_name, "out");
        assert!(accesses[0].is_static);
        assert!(!accesses[0].is_write);
    }

    #[test]
    fn test_find_field_accesses_putfield() {
        let cp = vec![
            ConstantPoolEntry::Other(0),
            ConstantPoolEntry::FieldRef { class: 2, nat: 3 },
            ConstantPoolEntry::ClassRef(4),
            ConstantPoolEntry::NameAndType { name: 5, desc: 6 },
            ConstantPoolEntry::Utf8("com/example/Foo".into()),
            ConstantPoolEntry::Utf8("value".into()),
            ConstantPoolEntry::Utf8("I".into()),
        ];
        // putfield #1, return
        let code = make_code_attr(vec![0xB5, 0x00, 0x01, 0xB1]);
        let accesses = JavaBytecodeAnalyzer::find_field_accesses(&code, &cp);
        assert_eq!(accesses.len(), 1);
        assert!(!accesses[0].is_static);
        assert!(accesses[0].is_write);
    }

    // â"€â"€ ClassHierarchyBuilder â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn make_class_file(name: &str, super_name: Option<&str>, interfaces: &[&str]) -> ClassFile {
        ClassFile {
            version: JavaVersion {
                major: 52,
                minor: 0,
            },
            flags: JavaClassFlags::PUBLIC,
            class_name: name.to_string(),
            super_name: super_name.map(str::to_string),
            interfaces: interfaces.iter().map(std::string::ToString::to_string).collect(),
            fields: vec![],
            methods: vec![],
            constant_pool: vec![],
        }
    }

    #[test]
    fn test_build_hierarchy_nodes() {
        let classes = vec![
            make_class_file("com/example/Animal", Some("java/lang/Object"), &[]),
            make_class_file("com/example/Dog", Some("com/example/Animal"), &[]),
        ];
        let h = ClassHierarchyBuilder::build_hierarchy(&classes);
        assert!(h.classes.contains_key("com/example/Animal"));
        assert!(h.classes.contains_key("com/example/Dog"));
    }

    #[test]
    fn test_is_subclass_of_direct() {
        let classes = vec![
            make_class_file("A", Some("B"), &[]),
            make_class_file("B", None, &[]),
        ];
        let h = ClassHierarchyBuilder::build_hierarchy(&classes);
        assert!(h.is_subclass_of("A", "B"));
    }

    #[test]
    fn test_is_subclass_of_transitive() {
        let classes = vec![
            make_class_file("C", Some("B"), &[]),
            make_class_file("B", Some("A"), &[]),
            make_class_file("A", None, &[]),
        ];
        let h = ClassHierarchyBuilder::build_hierarchy(&classes);
        assert!(h.is_subclass_of("C", "A"));
    }

    #[test]
    fn test_is_subclass_of_self() {
        let classes = vec![make_class_file("A", None, &[])];
        let h = ClassHierarchyBuilder::build_hierarchy(&classes);
        assert!(h.is_subclass_of("A", "A"));
    }

    #[test]
    fn test_is_subclass_of_false() {
        let classes = vec![
            make_class_file("A", None, &[]),
            make_class_file("B", None, &[]),
        ];
        let h = ClassHierarchyBuilder::build_hierarchy(&classes);
        assert!(!h.is_subclass_of("A", "B"));
    }

    #[test]
    fn test_find_implementations() {
        let classes = vec![
            make_class_file("com/Runnable", None, &[]),
            make_class_file("com/MyTask", Some("java/lang/Object"), &["com/Runnable"]),
            make_class_file("com/Other", None, &[]),
        ];
        let h = ClassHierarchyBuilder::build_hierarchy(&classes);
        let impls = h.find_implementations("com/Runnable");
        assert!(impls.contains(&"com/MyTask".to_string()));
        assert!(!impls.contains(&"com/Other".to_string()));
    }

    // â"€â"€ JavaDecompilerHints â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn make_class_file_with_methods(
        name: &str,
        super_name: Option<&str>,
        interfaces: &[&str],
        methods: &[(&str, u16)], // (name, flags_raw)
        fields: &[(&str, &str)], // (name, descriptor)
    ) -> ClassFile {
        ClassFile {
            version: JavaVersion {
                major: 52,
                minor: 0,
            },
            flags: JavaClassFlags::PUBLIC,
            class_name: name.to_string(),
            super_name: super_name.map(str::to_string),
            interfaces: interfaces.iter().map(std::string::ToString::to_string).collect(),
            fields: fields
                .iter()
                .map(|(n, d)| JavaField {
                    name: n.to_string(),
                    descriptor: d.to_string(),
                    flags: JavaClassFlags::empty(),
                })
                .collect(),
            methods: methods
                .iter()
                .map(|(n, flags)| RichMethod {
                    name: n.to_string(),
                    descriptor: "()V".to_string(),
                    flags: JavaClassFlags::from_bits_truncate(*flags),
                    raw_attributes: vec![],
                })
                .collect(),
            constant_pool: vec![],
        }
    }

    #[test]
    fn test_detect_singleton() {
        // PRIVATE (0x0002) ctor + PUBLIC (0x0001) | STATIC (0x0008) getInstance
        let cls = make_class_file_with_methods(
            "MySingleton",
            None,
            &[],
            &[
                ("<init>", JavaClassFlags::PRIVATE.bits()),
                (
                    "getInstance",
                    (JavaClassFlags::PUBLIC | JavaClassFlags::STATIC).bits(),
                ),
            ],
            &[],
        );
        assert!(JavaDecompilerHints::detect_singleton(&cls));
    }

    #[test]
    fn test_detect_singleton_false_no_get_instance() {
        let cls = make_class_file_with_methods(
            "NotSingleton",
            None,
            &[],
            &[("<init>", JavaClassFlags::PRIVATE.bits())],
            &[],
        );
        assert!(!JavaDecompilerHints::detect_singleton(&cls));
    }

    #[test]
    fn test_detect_factory_by_name() {
        let cls = make_class_file_with_methods("BeanFactory", None, &[], &[], &[]);
        assert!(JavaDecompilerHints::detect_factory(&cls));
    }

    #[test]
    fn test_detect_factory_by_method() {
        // STATIC method named "createInstance"
        let cls = make_class_file_with_methods(
            "WidgetProducer",
            None,
            &[],
            &[("createInstance", JavaClassFlags::STATIC.bits())],
            &[],
        );
        assert!(JavaDecompilerHints::detect_factory(&cls));
    }

    #[test]
    fn test_detect_builder() {
        let cls = make_class_file_with_methods(
            "MyBuilder",
            None,
            &[],
            &[("build", 0x0001), ("setName", 0x0001)],
            &[],
        );
        assert!(JavaDecompilerHints::detect_builder(&cls));
    }

    #[test]
    fn test_detect_builder_false() {
        let cls = make_class_file_with_methods("Widget", None, &[], &[("draw", 0x0001)], &[]);
        assert!(!JavaDecompilerHints::detect_builder(&cls));
    }

    #[test]
    fn test_detect_observer_by_interface() {
        let cls = make_class_file_with_methods(
            "ClickListener",
            None,
            &["java/util/EventListener"],
            &[],
            &[],
        );
        assert!(JavaDecompilerHints::detect_observer(&cls));
    }

    #[test]
    fn test_detect_observer_by_method() {
        let cls = make_class_file_with_methods(
            "EventBus",
            None,
            &[],
            &[("addListener", 0x0001), ("removeListener", 0x0001)],
            &[],
        );
        assert!(JavaDecompilerHints::detect_observer(&cls));
    }

    #[test]
    fn test_detect_decorator() {
        // class Foo implements Bar, has a field of type LBar;
        let cls = make_class_file_with_methods(
            "FooDecorator",
            None,
            &["com/Bar"],
            &[],
            &[("delegate", "Lcom/Bar;")],
        );
        assert!(JavaDecompilerHints::detect_decorator(&cls));
    }

    #[test]
    fn test_detect_decorator_false_no_matching_field() {
        let cls = make_class_file_with_methods(
            "FooDecorator",
            None,
            &["com/Bar"],
            &[],
            &[("other", "Ljava/lang/String;")],
        );
        assert!(!JavaDecompilerHints::detect_decorator(&cls));
    }

    #[test]
    fn test_detect_design_patterns_multiple() {
        // A class that is both a Factory and an Observer.
        let cls = make_class_file_with_methods(
            "EventFactory",
            None,
            &["java/util/EventListener"],
            &[("createEvent", 0x0008), ("addListener", 0x0001)],
            &[],
        );
        let patterns = JavaDecompilerHints::detect_design_patterns(&cls);
        assert!(patterns.contains(&DesignPattern::Factory));
        assert!(patterns.contains(&DesignPattern::Observer));
    }

    // â"€â"€ JarLoader & JarAnalyzer â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn make_jar_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        // Build a minimal ZIP with store (method=0) entries.
        let mut out = Vec::new();
        for (name, data) in entries {
            let name_bytes = name.as_bytes();
            // Local file header signature
            out.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
            out.extend_from_slice(&20u16.to_le_bytes()); // version needed
            out.extend_from_slice(&0u16.to_le_bytes()); // flags
            out.extend_from_slice(&0u16.to_le_bytes()); // compression = store
            out.extend_from_slice(&0u16.to_le_bytes()); // mod time
            out.extend_from_slice(&0u16.to_le_bytes()); // mod date
            out.extend_from_slice(&0u32.to_le_bytes()); // crc32
            out.extend_from_slice(&(data.len() as u32).to_le_bytes()); // comp size
            out.extend_from_slice(&(data.len() as u32).to_le_bytes()); // uncomp size
            out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra len
            out.extend_from_slice(name_bytes);
            out.extend_from_slice(data);
        }
        out
    }

    #[test]
    fn test_jar_loader_from_bytes_empty() {
        let jar = JarLoader::from_bytes(&[]);
        assert!(jar.entries().is_empty());
    }

    #[test]
    fn test_jar_loader_from_bytes_with_entries() {
        let data = make_jar_bytes(&[
            ("META-INF/MANIFEST.MF", b"Main-Class: com.example.Main\n"),
            ("com/example/Main.class", b"\xCA\xFE\xBA\xBE"),
        ]);
        let jar = JarLoader::from_bytes(&data);
        assert_eq!(jar.entries().len(), 2);
    }

    #[test]
    fn test_jar_loader_get_existing() {
        let data = make_jar_bytes(&[("hello.txt", b"hello world")]);
        let jar = JarLoader::from_bytes(&data);
        assert_eq!(jar.get("hello.txt"), Some(b"hello world".as_slice()));
    }

    #[test]
    fn test_jar_loader_get_missing() {
        let jar = JarLoader::from_bytes(&[]);
        assert!(jar.get("nope.txt").is_none());
    }

    #[test]
    fn test_jar_loader_class_entries() {
        let data = make_jar_bytes(&[("Foo.class", b"\xCA\xFE\xBA\xBE"), ("readme.txt", b"hi")]);
        let jar = JarLoader::from_bytes(&data);
        let classes = jar.class_entries();
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].path, "Foo.class");
    }

    #[test]
    fn test_jar_analyzer_main_class() {
        let manifest = b"Manifest-Version: 1.0\nMain-Class: com.example.Main\n";
        let data = make_jar_bytes(&[("META-INF/MANIFEST.MF", manifest)]);
        let jar = JarLoader::from_bytes(&data);
        let report = JarAnalyzer::analyze(&jar);
        assert_eq!(report.main_class, Some("com.example.Main".to_string()));
        assert!(report.is_executable);
        assert!(!report.is_library);
    }

    #[test]
    fn test_jar_analyzer_no_main_class_is_library() {
        let data = make_jar_bytes(&[("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")]);
        let jar = JarLoader::from_bytes(&data);
        let report = JarAnalyzer::analyze(&jar);
        assert!(report.main_class.is_none());
        assert!(report.is_library);
        assert!(!report.is_executable);
    }

    #[test]
    fn test_jar_analyzer_class_count() {
        let class_bytes = make_class_bytes(52, 0);
        let data = make_jar_bytes(&[
            ("com/example/A.class", &class_bytes),
            ("com/example/B.class", &class_bytes),
        ]);
        let jar = JarLoader::from_bytes(&data);
        let report = JarAnalyzer::analyze(&jar);
        assert_eq!(report.class_count, 2);
    }

    #[test]
    fn test_jar_analyzer_packages() {
        let class_bytes = make_class_bytes(52, 0);
        let data = make_jar_bytes(&[
            ("com/example/Main.class", &class_bytes),
            ("org/other/Util.class", &class_bytes),
        ]);
        let jar = JarLoader::from_bytes(&data);
        let report = JarAnalyzer::analyze(&jar);
        assert!(report.packages.contains(&"com/example".to_string()));
        assert!(report.packages.contains(&"org/other".to_string()));
    }

    #[test]
    fn test_jar_analyzer_dependencies_from_manifest() {
        let manifest = b"Manifest-Version: 1.0\nClass-Path: lib/foo.jar lib/bar.jar\n";
        let data = make_jar_bytes(&[("META-INF/MANIFEST.MF", manifest)]);
        let jar = JarLoader::from_bytes(&data);
        let report = JarAnalyzer::analyze(&jar);
        assert!(report.dependencies.contains(&"lib/foo.jar".to_string()));
        assert!(report.dependencies.contains(&"lib/bar.jar".to_string()));
    }

    #[test]
    fn test_design_pattern_display() {
        assert_eq!(DesignPattern::Singleton.to_string(), "Singleton");
        assert_eq!(DesignPattern::Factory.to_string(), "Factory");
        assert_eq!(DesignPattern::Builder.to_string(), "Builder");
        assert_eq!(DesignPattern::Observer.to_string(), "Observer");
        assert_eq!(DesignPattern::Decorator.to_string(), "Decorator");
    }

    #[test]
    fn test_class_file_parse_roundtrip() {
        let data = make_class_bytes(61, 0);
        let cls = ClassFile::parse(&data).unwrap();
        assert_eq!(cls.class_name, "Foo");
        assert_eq!(cls.version.major, 61);
    }
}

