//! JVM bytecode analysis: constant pool, method analysis, call-site collection.
//!
//! Provides [`BytecodeAnalyzer`], [`ConstantPool`], [`MethodAnalyzer`],
//! [`InstructionStream`], and [`CallSiteCollector`] for deep inspection of
//! `Code` attribute bytecode.

pub use std::collections::HashMap;
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors produced by bytecode analysis.
#[derive(Debug, Error)]
pub enum BytecodeError {
    #[error("truncated data at offset {0}")]
    Truncated(usize),
    #[error("invalid constant pool tag {tag} at index {index}")]
    InvalidCpTag { tag: u8, index: usize },
    #[error("constant pool index {0} out of range")]
    CpIndexOutOfRange(usize),
    #[error("bad magic bytes")]
    BadMagic,
    #[error("unsupported class version {major}.{minor}")]
    UnsupportedVersion { major: u16, minor: u16 },
}

// ── ConstantPool ──────────────────────────────────────────────────────────────

/// All 18 `cp_info` tag variants from the JVM specification.
#[derive(Debug, Clone)]
pub enum CpInfo {
    /// Tag 1 — Modified UTF-8 string.
    Utf8(String),
    /// Tag 3 — 32-bit integer.
    Integer(i32),
    /// Tag 4 — 32-bit float.
    Float(f32),
    /// Tag 5 — 64-bit integer (occupies two slots).
    Long(i64),
    /// Tag 6 — 64-bit float (occupies two slots).
    Double(f64),
    /// Tag 7 — Class reference (`name_index`).
    Class { name_index: u16 },
    /// Tag 8 — String reference (`string_index`).
    String { string_index: u16 },
    /// Tag 9 — Field reference.
    Fieldref {
        class_index: u16,
        name_and_type_index: u16,
    },
    /// Tag 10 — Method reference.
    Methodref {
        class_index: u16,
        name_and_type_index: u16,
    },
    /// Tag 11 — Interface method reference.
    InterfaceMethodref {
        class_index: u16,
        name_and_type_index: u16,
    },
    /// Tag 12 — Name and type descriptor.
    NameAndType {
        name_index: u16,
        descriptor_index: u16,
    },
    /// Tag 15 — Method handle.
    MethodHandle {
        reference_kind: u8,
        reference_index: u16,
    },
    /// Tag 16 — Method type.
    MethodType { descriptor_index: u16 },
    /// Tag 17 — Dynamic constant (`invokedynamic` constant pool entry).
    Dynamic {
        bootstrap_method_attr_index: u16,
        name_and_type_index: u16,
    },
    /// Tag 18 — `invokedynamic` bootstrap specifier.
    InvokeDynamic {
        bootstrap_method_attr_index: u16,
        name_and_type_index: u16,
    },
    /// Tag 19 — Module name.
    Module { name_index: u16 },
    /// Tag 20 — Package name.
    Package { name_index: u16 },
    /// Placeholder for the second slot occupied by Long / Double.
    Unusable,
}

/// A fully-parsed JVM constant pool.
///
/// Entries are 1-based; index 0 is always `CpInfo::Unusable`.
#[derive(Debug, Clone)]
pub struct ConstantPool {
    entries: Vec<CpInfo>,
}

impl ConstantPool {
    /// Parse a constant pool from the start of a class file body (after magic +
    /// version bytes).
    ///
    /// `data` must point at the `cp_count` field.
    ///
    /// Returns `(pool, bytes_consumed)`.
    pub fn parse(data: &[u8]) -> Result<(Self, usize), BytecodeError> {
        if data.len() < 2 {
            return Err(BytecodeError::Truncated(0));
        }
        let cp_count = u16::from_be_bytes([data[0], data[1]]) as usize;
        let mut entries = vec![CpInfo::Unusable]; // index 0
        let mut pos = 2usize;
        let mut i = 1usize;

        while i < cp_count {
            if pos >= data.len() {
                return Err(BytecodeError::Truncated(pos));
            }
            let tag = data[pos];
            pos += 1;

            macro_rules! need {
                ($n:expr) => {
                    if pos + $n > data.len() {
                        return Err(BytecodeError::Truncated(pos));
                    }
                };
            }
            macro_rules! u16be {
                ($off:expr) => {
                    u16::from_be_bytes([data[$off], data[$off + 1]])
                };
            }

            let entry = match tag {
                1 => {
                    need!(2);
                    let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                    pos += 2;
                    need!(len);
                    let s = String::from_utf8_lossy(&data[pos..pos + len]).into_owned();
                    pos += len;
                    CpInfo::Utf8(s)
                }
                3 => {
                    need!(4);
                    let v = i32::from_be_bytes(data[pos..pos + 4].try_into().unwrap());
                    pos += 4;
                    CpInfo::Integer(v)
                }
                4 => {
                    need!(4);
                    let bits = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap());
                    pos += 4;
                    CpInfo::Float(f32::from_bits(bits))
                }
                5 => {
                    need!(8);
                    let v = i64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
                    pos += 8;
                    entries.push(CpInfo::Long(v));
                    entries.push(CpInfo::Unusable);
                    i += 2;
                    continue;
                }
                6 => {
                    need!(8);
                    let bits = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
                    pos += 8;
                    entries.push(CpInfo::Double(f64::from_bits(bits)));
                    entries.push(CpInfo::Unusable);
                    i += 2;
                    continue;
                }
                7 => {
                    need!(2);
                    let ni = u16be!(pos);
                    pos += 2;
                    CpInfo::Class { name_index: ni }
                }
                8 => {
                    need!(2);
                    let si = u16be!(pos);
                    pos += 2;
                    CpInfo::String { string_index: si }
                }
                9 => {
                    need!(4);
                    let ci = u16be!(pos);
                    let nti = u16be!(pos + 2);
                    pos += 4;
                    CpInfo::Fieldref {
                        class_index: ci,
                        name_and_type_index: nti,
                    }
                }
                10 => {
                    need!(4);
                    let ci = u16be!(pos);
                    let nti = u16be!(pos + 2);
                    pos += 4;
                    CpInfo::Methodref {
                        class_index: ci,
                        name_and_type_index: nti,
                    }
                }
                11 => {
                    need!(4);
                    let ci = u16be!(pos);
                    let nti = u16be!(pos + 2);
                    pos += 4;
                    CpInfo::InterfaceMethodref {
                        class_index: ci,
                        name_and_type_index: nti,
                    }
                }
                12 => {
                    need!(4);
                    let ni = u16be!(pos);
                    let di = u16be!(pos + 2);
                    pos += 4;
                    CpInfo::NameAndType {
                        name_index: ni,
                        descriptor_index: di,
                    }
                }
                15 => {
                    need!(3);
                    let kind = data[pos];
                    let ri = u16be!(pos + 1);
                    pos += 3;
                    CpInfo::MethodHandle {
                        reference_kind: kind,
                        reference_index: ri,
                    }
                }
                16 => {
                    need!(2);
                    let di = u16be!(pos);
                    pos += 2;
                    CpInfo::MethodType {
                        descriptor_index: di,
                    }
                }
                17 => {
                    need!(4);
                    let bmai = u16be!(pos);
                    let nti = u16be!(pos + 2);
                    pos += 4;
                    CpInfo::Dynamic {
                        bootstrap_method_attr_index: bmai,
                        name_and_type_index: nti,
                    }
                }
                18 => {
                    need!(4);
                    let bmai = u16be!(pos);
                    let nti = u16be!(pos + 2);
                    pos += 4;
                    CpInfo::InvokeDynamic {
                        bootstrap_method_attr_index: bmai,
                        name_and_type_index: nti,
                    }
                }
                19 => {
                    need!(2);
                    let ni = u16be!(pos);
                    pos += 2;
                    CpInfo::Module { name_index: ni }
                }
                20 => {
                    need!(2);
                    let ni = u16be!(pos);
                    pos += 2;
                    CpInfo::Package { name_index: ni }
                }
                other => {
                    return Err(BytecodeError::InvalidCpTag {
                        tag: other,
                        index: i,
                    });
                }
            };

            entries.push(entry);
            i += 1;
        }

        Ok((Self { entries }, pos))
    }

    /// Retrieve entry at 1-based `index`.
    #[must_use] 
    pub fn get(&self, index: usize) -> Option<&CpInfo> {
        self.entries.get(index)
    }

    /// Resolve a Utf8 entry to `&str`.
    #[must_use] 
    pub fn utf8(&self, index: usize) -> Option<&str> {
        match self.entries.get(index)? {
            CpInfo::Utf8(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Resolve a Class entry to its name string.
    #[must_use] 
    pub fn class_name(&self, index: usize) -> Option<&str> {
        match self.entries.get(index)? {
            CpInfo::Class { name_index } => self.utf8(*name_index as usize),
            _ => None,
        }
    }

    /// Number of entries (including index-0 placeholder).
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the pool is empty (only placeholder).
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.entries.len() <= 1
    }

    /// Iterate over all entries with their 1-based indices.
    pub fn iter(&self) -> impl Iterator<Item = (usize, &CpInfo)> {
        self.entries.iter().enumerate()
    }

    /// Collect all Utf8 string values in the pool.
    #[must_use] 
    pub fn all_strings(&self) -> Vec<&str> {
        self.entries
            .iter()
            .filter_map(|e| {
                if let CpInfo::Utf8(s) = e {
                    Some(s.as_str())
                } else {
                    None
                }
            })
            .collect()
    }
}

// ── ExceptionTableEntry ───────────────────────────────────────────────────────

/// One row in the `Code` attribute's exception table.
#[derive(Debug, Clone)]
pub struct ExceptionTableEntry {
    pub start_pc: u16,
    pub end_pc: u16,
    pub handler_pc: u16,
    /// Index into the constant pool for the caught type, or 0 for `finally`.
    pub catch_type: u16,
}

// ── LocalVariableEntry ────────────────────────────────────────────────────────

/// One entry from the `LocalVariableTable` attribute.
#[derive(Debug, Clone)]
pub struct LocalVariableEntry {
    pub start_pc: u16,
    pub length: u16,
    pub name: String,
    pub descriptor: String,
    pub slot: u16,
}

// ── StackMapFrame ─────────────────────────────────────────────────────────────

/// A stack map frame tag (simplified).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackMapFrameKind {
    Same,
    SameLocals1Stack,
    Chop,
    Append,
    Full,
}

/// A simplified stack map frame record.
#[derive(Debug, Clone)]
pub struct StackMapFrame {
    pub offset_delta: u16,
    pub kind: StackMapFrameKind,
}

// ── MethodAnalyzer ────────────────────────────────────────────────────────────

/// Per-method analysis result.
#[derive(Debug, Clone)]
pub struct MethodAnalysis {
    pub name: String,
    pub descriptor: String,
    pub max_stack: u16,
    pub max_locals: u16,
    pub code: Vec<u8>,
    pub exception_table: Vec<ExceptionTableEntry>,
    pub local_variables: Vec<LocalVariableEntry>,
    pub stack_map_frames: Vec<StackMapFrame>,
}

impl MethodAnalysis {
    /// Number of bytecode instructions (naive: counts instruction bytes).
    #[must_use] 
    pub fn instruction_count(&self) -> usize {
        InstructionStream::new(&self.code).count()
    }
}

/// Analyses a single method's `Code` attribute.
pub struct MethodAnalyzer<'a> {
    cp: &'a ConstantPool,
}

impl<'a> MethodAnalyzer<'a> {
    #[must_use] 
    pub const fn new(cp: &'a ConstantPool) -> Self {
        Self { cp }
    }

    /// Parse the raw bytes of a `Code` attribute and extract all sub-tables.
    #[must_use] 
    pub fn parse_code_attribute(
        &self,
        name: &str,
        desc: &str,
        attr_data: &[u8],
    ) -> Option<MethodAnalysis> {
        if attr_data.len() < 8 {
            return None;
        }
        let max_stack = u16::from_be_bytes([attr_data[0], attr_data[1]]);
        let max_locals = u16::from_be_bytes([attr_data[2], attr_data[3]]);
        let code_len = u32::from_be_bytes(attr_data[4..8].try_into().ok()?) as usize;
        let mut pos = 8;
        if pos + code_len > attr_data.len() {
            return None;
        }
        let code = attr_data[pos..pos + code_len].to_vec();
        pos += code_len;

        // Exception table
        if pos + 2 > attr_data.len() {
            return None;
        }
        let exc_count = u16::from_be_bytes([attr_data[pos], attr_data[pos + 1]]) as usize;
        pos += 2;
        let mut exception_table = Vec::with_capacity(exc_count);
        for _ in 0..exc_count {
            if pos + 8 > attr_data.len() {
                break;
            }
            exception_table.push(ExceptionTableEntry {
                start_pc: u16::from_be_bytes([attr_data[pos], attr_data[pos + 1]]),
                end_pc: u16::from_be_bytes([attr_data[pos + 2], attr_data[pos + 3]]),
                handler_pc: u16::from_be_bytes([attr_data[pos + 4], attr_data[pos + 5]]),
                catch_type: u16::from_be_bytes([attr_data[pos + 6], attr_data[pos + 7]]),
            });
            pos += 8;
        }

        // Code sub-attributes
        let mut local_variables = Vec::new();
        let mut stack_map_frames = Vec::new();

        if pos + 2 <= attr_data.len() {
            let attr_count = u16::from_be_bytes([attr_data[pos], attr_data[pos + 1]]) as usize;
            pos += 2;
            for _ in 0..attr_count {
                if pos + 6 > attr_data.len() {
                    break;
                }
                let name_idx = u16::from_be_bytes([attr_data[pos], attr_data[pos + 1]]) as usize;
                let alen =
                    u32::from_be_bytes(attr_data[pos + 2..pos + 6].try_into().ok()?) as usize;
                pos += 6;
                let sub_end = pos + alen;
                let sub = attr_data
                    .get(pos..sub_end.min(attr_data.len()))
                    .unwrap_or(&[]);

                let sub_name = self.cp.utf8(name_idx).unwrap_or("");
                match sub_name {
                    "LocalVariableTable" => {
                        local_variables = Self::parse_local_variable_table(sub, self.cp);
                    }
                    "StackMapTable" => {
                        stack_map_frames = Self::parse_stack_map_table(sub);
                    }
                    _ => {}
                }
                pos = sub_end.min(attr_data.len());
            }
        }

        Some(MethodAnalysis {
            name: name.to_owned(),
            descriptor: desc.to_owned(),
            max_stack,
            max_locals,
            code,
            exception_table,
            local_variables,
            stack_map_frames,
        })
    }

    fn parse_local_variable_table(data: &[u8], cp: &ConstantPool) -> Vec<LocalVariableEntry> {
        let mut entries = Vec::new();
        if data.len() < 2 {
            return entries;
        }
        let count = u16::from_be_bytes([data[0], data[1]]) as usize;
        let mut pos = 2;
        for _ in 0..count {
            if pos + 10 > data.len() {
                break;
            }
            let start_pc = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let length = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
            let name_idx = u16::from_be_bytes([data[pos + 4], data[pos + 5]]) as usize;
            let desc_idx = u16::from_be_bytes([data[pos + 6], data[pos + 7]]) as usize;
            let slot = u16::from_be_bytes([data[pos + 8], data[pos + 9]]);
            pos += 10;
            entries.push(LocalVariableEntry {
                start_pc,
                length,
                name: cp.utf8(name_idx).unwrap_or("").to_owned(),
                descriptor: cp.utf8(desc_idx).unwrap_or("").to_owned(),
                slot,
            });
        }
        entries
    }

    fn parse_stack_map_table(data: &[u8]) -> Vec<StackMapFrame> {
        let mut frames = Vec::new();
        if data.len() < 2 {
            return frames;
        }
        let count = u16::from_be_bytes([data[0], data[1]]) as usize;
        let mut pos = 2;
        for _ in 0..count {
            if pos >= data.len() {
                break;
            }
            let frame_type = data[pos];
            pos += 1;
            let (kind, offset_delta) = match frame_type {
                0..=63 => (StackMapFrameKind::Same, u16::from(frame_type)),
                64..=127 => {
                    // same_locals_1_stack_item: skip one verification_type_info
                    if pos < data.len() {
                        pos += 1;
                    } // simplified skip
                    (
                        StackMapFrameKind::SameLocals1Stack,
                        u16::from(frame_type - 64),
                    )
                }
                247 => {
                    if pos + 2 > data.len() {
                        break;
                    }
                    let od = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    pos += 2;
                    if pos < data.len() {
                        pos += 1;
                    }
                    (StackMapFrameKind::SameLocals1Stack, od)
                }
                248..=250 => {
                    if pos + 2 > data.len() {
                        break;
                    }
                    let od = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    pos += 2;
                    (StackMapFrameKind::Chop, od)
                }
                251 => {
                    if pos + 2 > data.len() {
                        break;
                    }
                    let od = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    pos += 2;
                    (StackMapFrameKind::Same, od)
                }
                252..=254 => {
                    if pos + 2 > data.len() {
                        break;
                    }
                    let od = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    pos += 2;
                    let extra = (frame_type - 251) as usize;
                    pos += extra; // simplified skip
                    (StackMapFrameKind::Append, od)
                }
                255 => {
                    if pos + 2 > data.len() {
                        break;
                    }
                    let od = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    pos += 2;
                    // Skip locals and stack items (simplified)
                    (StackMapFrameKind::Full, od)
                }
                _ => continue,
            };
            frames.push(StackMapFrame { offset_delta, kind });
        }
        frames
    }
}

// ── InstructionStream ─────────────────────────────────────────────────────────

/// An iterator over raw JVM bytecode instructions.
///
/// Each `next()` call returns `(offset, opcode_byte, operand_bytes)`.
pub struct InstructionStream<'a> {
    code: &'a [u8],
    pos: usize,
}

impl<'a> InstructionStream<'a> {
    #[must_use] 
    pub const fn new(code: &'a [u8]) -> Self {
        Self { code, pos: 0 }
    }
}

/// A single decoded instruction from the stream.
#[derive(Debug, Clone)]
pub struct RawInstruction {
    pub offset: usize,
    pub opcode: u8,
    pub operands: Vec<u8>,
}

impl Iterator for InstructionStream<'_> {
    type Item = RawInstruction;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.code.len() {
            return None;
        }
        let offset = self.pos;
        let opcode = self.code[self.pos];
        self.pos += 1;

        let operands = self.decode_operands(opcode);
        Some(RawInstruction {
            offset,
            opcode,
            operands,
        })
    }
}

impl InstructionStream<'_> {
    fn decode_operands(&mut self, opcode: u8) -> Vec<u8> {
        let take = |code: &[u8], pos: &mut usize, n: usize| -> Vec<u8> {
            let end = (*pos + n).min(code.len());
            let bytes = code[*pos..end].to_vec();
            *pos = end;
            bytes
        };

        match opcode {
            // 0 operands
            0x00
            | 0x01..=0x0F
            | 0x1A..=0x35
            | 0x3B..=0x83
            | 0x85..=0x98
            | 0xAC..=0xB1
            | 0xBE
            | 0xBF
            | 0xC2
            | 0xC3 => vec![],
            // 1 operand
            0x10 | 0x12 | 0x15..=0x19 | 0x36..=0x3A | 0xA9 | 0xBC => {
                take(self.code, &mut self.pos, 1)
            }
            // 2 operands
            0x11
            | 0x13
            | 0x14
            | 0x84
            | 0x99..=0xA8
            | 0xB2..=0xB8
            | 0xBB
            | 0xBD
            | 0xC6
            | 0xC7
            | 0xC8
            | 0xC9 => take(self.code, &mut self.pos, 2),
            // 3 operands (multianewarray)
            0xC5 => take(self.code, &mut self.pos, 3),
            // 4 operands (invokeinterface, invokedynamic)
            0xB9 | 0xBA => take(self.code, &mut self.pos, 4),
            // wide
            0xC4 => {
                if self.pos < self.code.len() {
                    let sub = self.code[self.pos];
                    self.pos += 1;
                    let mut ops = vec![sub];
                    let extra = if sub == 0x84 { 4 } else { 2 };
                    ops.extend_from_slice(&take(self.code, &mut self.pos, extra));
                    ops
                } else {
                    vec![]
                }
            }
            // tableswitch / lookupswitch: variable; skip conservatively
            0xAA | 0xAB => vec![],
            _ => vec![],
        }
    }
}

// ── CallSiteCollector ────────────────────────────────────────────────────────

/// Invoke kind for a call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvokeKind {
    Virtual,
    Special,
    Static,
    Interface,
    Dynamic,
}

/// A single call site detected in bytecode.
#[derive(Debug, Clone)]
pub struct CallSite {
    /// Byte offset in the Code array.
    pub offset: usize,
    /// Kind of invoke.
    pub kind: InvokeKind,
    /// Resolved class name (from CP), or empty for invokedynamic.
    pub class_name: String,
    /// Resolved method name (from CP).
    pub method_name: String,
    /// Resolved descriptor (from CP).
    pub descriptor: String,
    /// Raw CP index.
    pub cp_index: u16,
}

/// Scans a method's bytecode for all invoke* instructions.
pub struct CallSiteCollector<'a> {
    cp: &'a ConstantPool,
}

impl<'a> CallSiteCollector<'a> {
    #[must_use] 
    pub const fn new(cp: &'a ConstantPool) -> Self {
        Self { cp }
    }

    /// Collect all call sites from raw `Code` bytes.
    #[must_use] 
    pub fn collect(&self, code: &[u8]) -> Vec<CallSite> {
        let mut sites = Vec::new();
        for instr in InstructionStream::new(code) {
            let kind = match instr.opcode {
                0xB6 => InvokeKind::Virtual,
                0xB7 => InvokeKind::Special,
                0xB8 => InvokeKind::Static,
                0xB9 => InvokeKind::Interface,
                0xBA => InvokeKind::Dynamic,
                _ => continue,
            };

            if instr.operands.len() < 2 {
                continue;
            }
            let cp_index = u16::from_be_bytes([instr.operands[0], instr.operands[1]]) as usize;

            let (class_name, method_name, descriptor) = self.resolve_call(kind, cp_index);
            sites.push(CallSite {
                offset: instr.offset,
                kind,
                class_name,
                method_name,
                descriptor,
                cp_index: cp_index as u16,
            });
        }
        sites
    }

    fn resolve_call(&self, kind: InvokeKind, cp_idx: usize) -> (String, String, String) {
        if kind == InvokeKind::Dynamic {
            // invokedynamic — CP entry is InvokeDynamic
            if let Some(CpInfo::InvokeDynamic {
                name_and_type_index,
                ..
            }) = self.cp.get(cp_idx)
            {
                let (mn, desc) = self.resolve_name_and_type(*name_and_type_index as usize);
                return (String::new(), mn, desc);
            }
            return (String::new(), String::new(), String::new());
        }

        let (class_idx, nat_idx) = match self.cp.get(cp_idx) {
            Some(CpInfo::Methodref {
                class_index,
                name_and_type_index,
            }) => (*class_index as usize, *name_and_type_index as usize),
            Some(CpInfo::InterfaceMethodref {
                class_index,
                name_and_type_index,
            }) => (*class_index as usize, *name_and_type_index as usize),
            _ => return (String::new(), String::new(), String::new()),
        };

        let cn = self.cp.class_name(class_idx).unwrap_or("").to_owned();
        let (mn, desc) = self.resolve_name_and_type(nat_idx);
        (cn, mn, desc)
    }

    fn resolve_name_and_type(&self, idx: usize) -> (String, String) {
        match self.cp.get(idx) {
            Some(CpInfo::NameAndType {
                name_index,
                descriptor_index,
            }) => {
                let name = self.cp.utf8(*name_index as usize).unwrap_or("").to_owned();
                let desc = self
                    .cp
                    .utf8(*descriptor_index as usize)
                    .unwrap_or("")
                    .to_owned();
                (name, desc)
            }
            _ => (String::new(), String::new()),
        }
    }
}

// ── BytecodeAnalyzer ──────────────────────────────────────────────────────────

/// High-level analyser for a Java `.class` file.
///
/// Parses the full constant pool, collects all methods with their `Code`
/// attributes, and provides convenient accessors.
pub struct BytecodeAnalyzer {
    pub cp: ConstantPool,
    pub methods: Vec<MethodAnalysis>,
}

impl BytecodeAnalyzer {
    /// Parse a `.class` file and build the analyser.
    pub fn parse(data: &[u8]) -> Result<Self, BytecodeError> {
        if data.len() < 10 {
            return Err(BytecodeError::Truncated(0));
        }
        if data[0..4] != [0xCA, 0xFE, 0xBA, 0xBE] {
            return Err(BytecodeError::BadMagic);
        }
        let minor = u16::from_be_bytes([data[4], data[5]]);
        let major = u16::from_be_bytes([data[6], data[7]]);
        if !(45..=70).contains(&major) {
            return Err(BytecodeError::UnsupportedVersion { major, minor });
        }

        let (cp, mut pos) = ConstantPool::parse(&data[8..])?;
        pos += 8; // adjust for the offset we passed to ConstantPool::parse

        // Skip access_flags, this_class, super_class
        if pos + 6 > data.len() {
            return Err(BytecodeError::Truncated(pos));
        }
        pos += 6;

        // Skip interfaces
        let iface_count = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + iface_count * 2;

        // Skip fields
        pos = Self::skip_members(data, pos)?;
        // Parse methods
        let (methods, new_pos) = Self::parse_methods(data, pos, &cp)?;
        let _ = new_pos;

        Ok(Self { cp, methods })
    }

    fn skip_members(data: &[u8], mut pos: usize) -> Result<usize, BytecodeError> {
        if pos + 2 > data.len() {
            return Err(BytecodeError::Truncated(pos));
        }
        let count = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        for _ in 0..count {
            if pos + 8 > data.len() {
                return Err(BytecodeError::Truncated(pos));
            }
            let attrs = u16::from_be_bytes([data[pos + 6], data[pos + 7]]) as usize;
            pos += 8;
            for _ in 0..attrs {
                if pos + 6 > data.len() {
                    return Err(BytecodeError::Truncated(pos));
                }
                let alen = u32::from_be_bytes(data[pos + 2..pos + 6].try_into().unwrap()) as usize;
                pos += 6 + alen;
            }
        }
        Ok(pos)
    }

    fn parse_methods(
        data: &[u8],
        mut pos: usize,
        cp: &ConstantPool,
    ) -> Result<(Vec<MethodAnalysis>, usize), BytecodeError> {
        if pos + 2 > data.len() {
            return Err(BytecodeError::Truncated(pos));
        }
        let count = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let mut methods = Vec::new();
        let analyzer = MethodAnalyzer::new(cp);

        for _ in 0..count {
            if pos + 8 > data.len() {
                return Err(BytecodeError::Truncated(pos));
            }
            let name_idx = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            let desc_idx = u16::from_be_bytes([data[pos + 4], data[pos + 5]]) as usize;
            let attrs_count = u16::from_be_bytes([data[pos + 6], data[pos + 7]]) as usize;
            let name = cp.utf8(name_idx).unwrap_or("").to_owned();
            let desc = cp.utf8(desc_idx).unwrap_or("").to_owned();
            pos += 8;

            for _ in 0..attrs_count {
                if pos + 6 > data.len() {
                    return Err(BytecodeError::Truncated(pos));
                }
                let attr_name_idx = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                let alen = u32::from_be_bytes(data[pos + 2..pos + 6].try_into().unwrap()) as usize;
                pos += 6;
                let attr_end = (pos + alen).min(data.len());
                let attr_data = &data[pos..attr_end];

                let attr_name = cp.utf8(attr_name_idx).unwrap_or("");
                if attr_name == "Code"
                    && let Some(ma) = analyzer.parse_code_attribute(&name, &desc, attr_data) {
                        methods.push(ma);
                    }
                pos = attr_end;
            }
        }

        Ok((methods, pos))
    }

    /// Collect all call sites across all methods.
    #[must_use] 
    pub fn all_call_sites(&self) -> Vec<CallSite> {
        let collector = CallSiteCollector::new(&self.cp);
        self.methods
            .iter()
            .flat_map(|m| collector.collect(&m.code))
            .collect()
    }

    /// Return methods by name.
    #[must_use] 
    pub fn methods_named(&self, name: &str) -> Vec<&MethodAnalysis> {
        self.methods.iter().filter(|m| m.name == name).collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_utf8_cp_entry(s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        let mut v = vec![1u8]; // tag 1 = Utf8
        v.push((bytes.len() >> 8) as u8);
        v.push((bytes.len() & 0xFF) as u8);
        v.extend_from_slice(bytes);
        v
    }

    fn make_cp_bytes(entries: &[Vec<u8>]) -> Vec<u8> {
        let count = entries.len() + 1; // 1-based
        let mut v = vec![(count >> 8) as u8, (count & 0xFF) as u8];
        for e in entries {
            v.extend_from_slice(e);
        }
        v
    }

    #[test]
    fn test_cp_parse_utf8() {
        let entry = make_utf8_cp_entry("Hello");
        let cp_bytes = make_cp_bytes(&[entry]);
        let (cp, _) = ConstantPool::parse(&cp_bytes).unwrap();
        assert_eq!(cp.utf8(1), Some("Hello"));
    }

    #[test]
    fn test_cp_all_strings() {
        let e1 = make_utf8_cp_entry("Foo");
        let e2 = make_utf8_cp_entry("Bar");
        let cp_bytes = make_cp_bytes(&[e1, e2]);
        let (cp, _) = ConstantPool::parse(&cp_bytes).unwrap();
        let strs = cp.all_strings();
        assert!(strs.contains(&"Foo"));
        assert!(strs.contains(&"Bar"));
    }

    #[test]
    fn test_cp_integer_entry() {
        let mut entry = vec![3u8]; // tag 3 = Integer
        entry.extend_from_slice(&42i32.to_be_bytes());
        let cp_bytes = make_cp_bytes(&[entry]);
        let (cp, _) = ConstantPool::parse(&cp_bytes).unwrap();
        assert!(matches!(cp.get(1), Some(CpInfo::Integer(42))));
    }

    #[test]
    fn test_cp_long_two_slots() {
        let mut entry = vec![5u8]; // tag 5 = Long
        entry.extend_from_slice(&100i64.to_be_bytes());
        let cp_bytes = make_cp_bytes(&[entry]);
        let (cp, _) = ConstantPool::parse(&cp_bytes).unwrap();
        assert!(matches!(cp.get(1), Some(CpInfo::Long(100))));
        // Slot 2 should be Unusable
        assert!(matches!(cp.get(2), Some(CpInfo::Unusable)));
    }

    #[test]
    fn test_cp_double_two_slots() {
        let mut entry = vec![6u8]; // tag 6 = Double
        entry.extend_from_slice(&3.14f64.to_bits().to_be_bytes());
        let cp_bytes = make_cp_bytes(&[entry]);
        let (cp, _) = ConstantPool::parse(&cp_bytes).unwrap();
        assert!(matches!(cp.get(1), Some(CpInfo::Double(_))));
    }

    #[test]
    fn test_cp_class_entry() {
        let utf8_entry = make_utf8_cp_entry("java/lang/Object");
        let class_entry = vec![7u8, 0, 1]; // Class referencing index 1
        let cp_bytes = make_cp_bytes(&[utf8_entry, class_entry]);
        let (cp, _) = ConstantPool::parse(&cp_bytes).unwrap();
        assert_eq!(cp.class_name(2), Some("java/lang/Object"));
    }

    #[test]
    fn test_cp_string_entry() {
        let utf8_entry = make_utf8_cp_entry("hello");
        let str_entry = vec![8u8, 0, 1]; // String referencing index 1
        let cp_bytes = make_cp_bytes(&[utf8_entry, str_entry]);
        let (cp, _) = ConstantPool::parse(&cp_bytes).unwrap();
        assert!(matches!(cp.get(2), Some(CpInfo::String { .. })));
    }

    #[test]
    fn test_cp_methodref_entry() {
        let cls_utf8 = make_utf8_cp_entry("Foo");
        let cls_entry = vec![7u8, 0, 1];
        let nat_name = make_utf8_cp_entry("bar");
        let nat_desc = make_utf8_cp_entry("()V");
        let nat_entry = vec![12u8, 0, 3, 0, 4]; // NameAndType
        let mref = vec![10u8, 0, 2, 0, 5]; // Methodref
        let cp_bytes = make_cp_bytes(&[cls_utf8, cls_entry, nat_name, nat_desc, nat_entry, mref]);
        let (cp, _) = ConstantPool::parse(&cp_bytes).unwrap();
        assert!(matches!(cp.get(6), Some(CpInfo::Methodref { .. })));
    }

    #[test]
    fn test_bytecode_analyzer_bad_magic() {
        let result = BytecodeAnalyzer::parse(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        assert!(result.is_err());
    }

    #[test]
    fn test_bytecode_analyzer_truncated() {
        let result = BytecodeAnalyzer::parse(b"\xca\xfe\xba\xbe");
        assert!(result.is_err());
    }

    #[test]
    fn test_instruction_stream_nop() {
        let code = [0x00u8]; // nop
        let mut stream = InstructionStream::new(&code);
        let instr = stream.next().unwrap();
        assert_eq!(instr.opcode, 0x00);
        assert_eq!(instr.offset, 0);
        assert!(instr.operands.is_empty());
    }

    #[test]
    fn test_instruction_stream_bipush() {
        let code = [0x10u8, 0x2A]; // bipush 42
        let mut stream = InstructionStream::new(&code);
        let instr = stream.next().unwrap();
        assert_eq!(instr.opcode, 0x10);
        assert_eq!(instr.operands, vec![0x2A]);
    }

    #[test]
    fn test_instruction_stream_multiple() {
        let code = [0x00, 0x00, 0x00]; // three nops
        let count = InstructionStream::new(&code).count();
        assert_eq!(count, 3);
    }

    #[test]
    fn test_instruction_stream_empty() {
        let count = InstructionStream::new(&[]).count();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_call_site_collector_empty() {
        let utf8 = make_utf8_cp_entry("test");
        let cp_bytes = make_cp_bytes(&[utf8]);
        let (cp, _) = ConstantPool::parse(&cp_bytes).unwrap();
        let collector = CallSiteCollector::new(&cp);
        // Code with no invoke instructions
        let code = [0x00u8, 0x00, 0xB1]; // nop, nop, return
        let sites = collector.collect(&code);
        assert!(sites.is_empty());
    }

    #[test]
    fn test_invoke_kind_display() {
        let kinds = [
            InvokeKind::Virtual,
            InvokeKind::Special,
            InvokeKind::Static,
            InvokeKind::Interface,
            InvokeKind::Dynamic,
        ];
        // Just verify they can be created and compared
        assert_ne!(kinds[0], kinds[1]);
    }

    #[test]
    fn test_exception_table_entry() {
        let e = ExceptionTableEntry {
            start_pc: 0,
            end_pc: 10,
            handler_pc: 20,
            catch_type: 0,
        };
        assert_eq!(e.handler_pc, 20);
        assert_eq!(e.catch_type, 0); // finally-style
    }

    #[test]
    fn test_local_variable_entry() {
        let lv = LocalVariableEntry {
            start_pc: 0,
            length: 5,
            name: "x".into(),
            descriptor: "I".into(),
            slot: 1,
        };
        assert_eq!(lv.name, "x");
        assert_eq!(lv.descriptor, "I");
    }

    #[test]
    fn test_stack_map_frame_same() {
        let frame = StackMapFrame {
            offset_delta: 5,
            kind: StackMapFrameKind::Same,
        };
        assert_eq!(frame.kind, StackMapFrameKind::Same);
        assert_eq!(frame.offset_delta, 5);
    }

    #[test]
    fn test_cp_is_empty() {
        let cp_bytes = vec![0u8, 1]; // count = 1, empty pool
        let (cp, _) = ConstantPool::parse(&cp_bytes).unwrap();
        assert!(cp.is_empty());
    }

    #[test]
    fn test_cp_len() {
        let e = make_utf8_cp_entry("abc");
        let cp_bytes = make_cp_bytes(&[e]);
        let (cp, _) = ConstantPool::parse(&cp_bytes).unwrap();
        assert_eq!(cp.len(), 2); // index 0 (placeholder) + index 1
    }

    #[test]
    fn test_raw_instruction_fields() {
        let instr = RawInstruction {
            offset: 10,
            opcode: 0xB6,
            operands: vec![0x00, 0x05],
        };
        assert_eq!(instr.offset, 10);
        assert_eq!(instr.opcode, 0xB6);
        assert_eq!(instr.operands.len(), 2);
    }

    #[test]
    fn test_cp_method_handle_entry() {
        let utf8 = make_utf8_cp_entry("foo");
        let cls_entry = vec![7u8, 0, 1];
        let mh_entry = vec![15u8, 6, 0, 2]; // MethodHandle kind=6 (invokespecial)
        let cp_bytes = make_cp_bytes(&[utf8, cls_entry, mh_entry]);
        let (cp, _) = ConstantPool::parse(&cp_bytes).unwrap();
        assert!(matches!(
            cp.get(3),
            Some(CpInfo::MethodHandle {
                reference_kind: 6,
                ..
            })
        ));
    }

    #[test]
    fn test_cp_module_package_entries() {
        let utf8 = make_utf8_cp_entry("com/example");
        let mod_entry = vec![19u8, 0, 1]; // Module
        let pkg_entry = vec![20u8, 0, 1]; // Package
        let cp_bytes = make_cp_bytes(&[utf8, mod_entry, pkg_entry]);
        let (cp, _) = ConstantPool::parse(&cp_bytes).unwrap();
        assert!(matches!(cp.get(2), Some(CpInfo::Module { .. })));
        assert!(matches!(cp.get(3), Some(CpInfo::Package { .. })));
    }

    #[test]
    fn test_cp_dynamic_entry() {
        let utf8 = make_utf8_cp_entry("()V");
        let nat_name = make_utf8_cp_entry("bootstrap");
        let nat_entry = vec![12u8, 0, 2, 0, 1];
        let dyn_entry = vec![17u8, 0, 0, 0, 3]; // Dynamic bsm_idx=0 nat=3
        let cp_bytes = make_cp_bytes(&[utf8, nat_name, nat_entry, dyn_entry]);
        let (cp, _) = ConstantPool::parse(&cp_bytes).unwrap();
        assert!(matches!(cp.get(4), Some(CpInfo::Dynamic { .. })));
    }
}
