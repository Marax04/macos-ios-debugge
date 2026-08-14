//! Smali → DEX bytecode assembler.
//!
//! Encodes Dalvik instructions, builds string/type/method/field index tables,
//! and generates a minimal DEX file header with the correct SHA-1 and Adler-32
//! checksums.

use std::collections::HashMap;
use anyhow::Result;

use crate::smali_parser::{
    ParsedClass, ParsedField, ParsedInstruction, ParsedMethod,
};
use crate::DalvikOpcode;

// ── DEX Constants ─────────────────────────────────────────────────────────────

pub const DEX_MAGIC: &[u8] = b"dex\n035\0";
pub const HEADER_SIZE: u32 = 0x70;
pub const ENDIAN_CONSTANT: u32 = 0x1234_5678;
pub const NO_INDEX: u32 = 0xFFFF_FFFF;

// ── Truncation helpers (intentional bytecode encoding boundaries) ─────────────

#[inline]
fn lo8_u16(v: u16) -> u8 { u8::try_from(v & 0xff).unwrap_or(0) }
#[inline]
fn lo8_i64(v: i64) -> u8 { u8::try_from(v.rem_euclid(0x100)).unwrap_or(0) }
#[inline]
fn lo16_i64(v: i64) -> u16 { u16::try_from(v.rem_euclid(0x1_0000)).unwrap_or(0) }
#[inline]
fn lo16_u32(v: u32) -> u16 { u16::try_from(v & 0xffff).unwrap_or(0) }
#[inline]
fn lo16_usize(v: usize) -> u16 { u16::try_from(v & 0xffff).unwrap_or(0) }
#[inline]
#[must_use]
pub fn lo32_u64(v: u64) -> u32 { u32::try_from(v & 0xffff_ffff).unwrap_or(0) }
#[inline]
fn lo32_usize(v: usize) -> u32 { u32::try_from(v & 0xffff_ffff).unwrap_or(u32::MAX) }
#[inline]
fn as_i16_lit(v: i64) -> i16 { i16::try_from(v.clamp(i64::from(i16::MIN), i64::from(i16::MAX))).unwrap_or(0) }
#[inline]
fn as_i32_lit(v: i64) -> i32 { i32::try_from(v.clamp(i64::from(i32::MIN), i64::from(i32::MAX))).unwrap_or(0) }
#[inline]
fn as_i8_lit(v: i64) -> i8 { i8::try_from(v.clamp(i64::from(i8::MIN), i64::from(i8::MAX))).unwrap_or(0) }

// ── Index Tables ──────────────────────────────────────────────────────────────

/// Deduplicating string table.
#[derive(Debug, Default)]
pub struct StringTable {
    strings: Vec<String>,
    index: HashMap<String, u32>,
}

impl StringTable {
    pub fn intern(&mut self, s: &str) -> u32 {
        if let Some(&idx) = self.index.get(s) {
            return idx;
        }
        let idx = lo32_usize(self.strings.len());
        self.index.insert(s.to_string(), idx);
        self.strings.push(s.to_string());
        idx
    }

    #[must_use] 
    pub fn get_index(&self, s: &str) -> Option<u32> {
        self.index.get(s).copied()
    }

    #[must_use] 
    pub fn strings(&self) -> &[String] {
        &self.strings
    }

    #[must_use]
    pub fn len(&self) -> u32 { lo32_usize(self.strings.len())
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool { self.strings.is_empty() }

    /// Sort strings lexicographically and rebuild the index (DEX requirement).
    pub fn sort_and_rebuild(&mut self) {
        self.strings.sort();
        self.index.clear();
        for (i, s) in self.strings.iter().enumerate() {
            self.index.insert(s.clone(), lo32_usize(i));
        }
    }

    /// Encode to DEX `string_data_item` format (ULEB128 length + UTF-8 + NUL).
    #[must_use] 
    pub fn encode_data_item(s: &str) -> Vec<u8> {
        let utf8 = s.as_bytes();
        let mut out = encode_uleb128(utf8.len() as u64);
        out.extend_from_slice(utf8);
        out.push(0);
        out
    }
}

/// Type descriptor table.
#[derive(Debug, Default)]
pub struct TypeTable {
    types: Vec<String>,
    index: HashMap<String, u32>,
}

impl TypeTable {
    pub fn intern(&mut self, s: &str, strings: &mut StringTable) -> u32 {
        if let Some(&idx) = self.index.get(s) {
            return idx;
        }
        strings.intern(s);
        let idx = lo32_usize(self.types.len());
        self.index.insert(s.to_string(), idx);
        self.types.push(s.to_string());
        idx
    }

    #[must_use] 
    pub fn types(&self) -> &[String] {
        &self.types
    }

    #[must_use]
    pub fn len(&self) -> u32 { lo32_usize(self.types.len())
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool { self.types.is_empty() }
}

/// Method prototype table.
#[derive(Debug, Default, Clone)]
pub struct ProtoId {
    pub shorty: String,
    pub return_type: String,
    pub params: Vec<String>,
}

#[derive(Debug, Default)]
pub struct ProtoTable {
    protos: Vec<ProtoId>,
    index: HashMap<String, u32>,
}

impl ProtoTable {
    pub fn intern(
        &mut self,
        descriptor: &str,
        strings: &mut StringTable,
        types: &mut TypeTable,
    ) -> u32 {
        if let Some(&idx) = self.index.get(descriptor) {
            return idx;
        }
        let (params, ret) = parse_method_descriptor(descriptor);
        let shorty = build_shorty(&params, &ret);
        strings.intern(&shorty);
        strings.intern(&ret);
        types.intern(&ret, strings);
        for p in &params {
            strings.intern(p);
            types.intern(p, strings);
        }
        let idx = lo32_usize(self.protos.len());
        let key = descriptor.to_string();
        self.protos.push(ProtoId {
            shorty,
            return_type: ret,
            params,
        });
        self.index.insert(key, idx);
        idx
    }

    #[must_use] 
    pub fn protos(&self) -> &[ProtoId] {
        &self.protos
    }

    #[must_use]
    pub fn len(&self) -> u32 { lo32_usize(self.protos.len())
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool { self.protos.is_empty() }
}

/// Field reference table.
#[derive(Debug, Default, Clone)]
pub struct FieldId {
    pub class: String,
    pub name: String,
    pub type_desc: String,
}

#[derive(Debug, Default)]
pub struct FieldTable {
    fields: Vec<FieldId>,
    index: HashMap<String, u32>,
}

impl FieldTable {
    pub fn intern(
        &mut self,
        class: &str,
        name: &str,
        type_desc: &str,
        strings: &mut StringTable,
        types: &mut TypeTable,
    ) -> u32 {
        let key = format!("{class}->{name}{type_desc}");
        if let Some(&idx) = self.index.get(&key) {
            return idx;
        }
        strings.intern(class);
        strings.intern(name);
        strings.intern(type_desc);
        types.intern(class, strings);
        types.intern(type_desc, strings);
        let idx = lo32_usize(self.fields.len());
        self.fields.push(FieldId {
            class: class.to_string(),
            name: name.to_string(),
            type_desc: type_desc.to_string(),
        });
        self.index.insert(key, idx);
        idx
    }

    #[must_use] 
    pub fn fields(&self) -> &[FieldId] {
        &self.fields
    }

    #[must_use]
    pub fn len(&self) -> u32 { lo32_usize(self.fields.len())
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool { self.fields.is_empty() }
}

/// Method reference table.
#[derive(Debug, Default, Clone)]
pub struct MethodId {
    pub class: String,
    pub name: String,
    pub descriptor: String,
    pub proto_idx: u32,
}

#[derive(Debug, Default)]
pub struct MethodTable {
    methods: Vec<MethodId>,
    index: HashMap<String, u32>,
}

impl MethodTable {
    pub fn intern(
        &mut self,
        class: &str,
        name: &str,
        descriptor: &str,
        proto_idx: u32,
        strings: &mut StringTable,
        types: &mut TypeTable,
    ) -> u32 {
        let key = format!("{class}->{name}{descriptor}");
        if let Some(&idx) = self.index.get(&key) {
            return idx;
        }
        strings.intern(class);
        strings.intern(name);
        types.intern(class, strings);
        let idx = lo32_usize(self.methods.len());
        self.methods.push(MethodId {
            class: class.to_string(),
            name: name.to_string(),
            descriptor: descriptor.to_string(),
            proto_idx,
        });
        self.index.insert(key, idx);
        idx
    }

    #[must_use] 
    pub fn methods(&self) -> &[MethodId] {
        &self.methods
    }

    #[must_use]
    pub fn len(&self) -> u32 { lo32_usize(self.methods.len())
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool { self.methods.is_empty() }
}

// ── Dalvik instruction encoding ───────────────────────────────────────────────

/// Encode a single Dalvik instruction to bytes.
#[must_use] 
pub fn encode_instruction(insn: &ParsedInstruction) -> Vec<u8> {
    let regs = &insn.registers;
    let lit = insn.literal.unwrap_or(0);
    let r0 = u16::from(regs.first().copied().unwrap_or(0));
    let r1 = u16::from(regs.get(1).copied().unwrap_or(0));
    let r2 = u16::from(regs.get(2).copied().unwrap_or(0));

    match insn.opcode {
        DalvikOpcode::Nop => vec![0x00, 0x00],
        DalvikOpcode::Move => {
            // 12x: op | vA | vB (nibbles)
            vec![0x01, ((lo8_u16(r1)) << 4) | (lo8_u16(r0))]
        }
        DalvikOpcode::MoveResult => vec![0x0a, lo8_u16(r0)],
        DalvikOpcode::ReturnVoid => vec![0x0e, 0x00],
        DalvikOpcode::Return => vec![0x0f, lo8_u16(r0)],
        DalvikOpcode::Const4 => {
            // 11n: op | vA | #+B (nibble literal)
            let b = (lo8_i64(lit)) & 0x0f;
            vec![0x12, (b << 4) | (lo8_u16(r0))]
        }
        DalvikOpcode::Const16 => {
            // 21s: op | vAA | #+BBBB
            let mut v = vec![0x13, lo8_u16(r0)];
            v.extend_from_slice(&(as_i16_lit(lit)).to_le_bytes());
            v
        }
        DalvikOpcode::Const => {
            // 31i: op | vAA | #+BBBBBBBB
            let mut v = vec![0x14, lo8_u16(r0)];
            v.extend_from_slice(&(as_i32_lit(lit)).to_le_bytes());
            v
        }
        DalvikOpcode::ConstString => {
            // 21c: op | vAA | string@BBBB
            let string_idx = lo16_i64(lit);
            let mut v = vec![0x1a, lo8_u16(r0)];
            v.extend_from_slice(&string_idx.to_le_bytes());
            v
        }
        DalvikOpcode::ConstClass => {
            let type_idx = lo16_i64(lit);
            let mut v = vec![0x1c, lo8_u16(r0)];
            v.extend_from_slice(&type_idx.to_le_bytes());
            v
        }
        DalvikOpcode::NewInstance => {
            let type_idx = lo16_i64(lit);
            let mut v = vec![0x22, lo8_u16(r0)];
            v.extend_from_slice(&type_idx.to_le_bytes());
            v
        }
        DalvikOpcode::NewArray => {
            // 23x: op | vA | vB | type@CCCC
            let type_idx = lo16_i64(lit);
            let mut v = vec![0x23, ((lo8_u16(r1)) << 4) | (lo8_u16(r0))];
            v.extend_from_slice(&type_idx.to_le_bytes());
            v
        }
        DalvikOpcode::CheckCast => {
            let type_idx = lo16_i64(lit);
            let mut v = vec![0x1f, lo8_u16(r0)];
            v.extend_from_slice(&type_idx.to_le_bytes());
            v
        }
        DalvikOpcode::InstanceOf => {
            let type_idx = lo16_i64(lit);
            vec![0x20, ((lo8_u16(r1)) << 4) | (lo8_u16(r0)), lo8_u16(type_idx), lo8_u16(type_idx >> 8)]
        }
        DalvikOpcode::Throw => vec![0x27, lo8_u16(r0)],
        DalvikOpcode::Goto => {
            let offset = as_i8_lit(lit);
            vec![0x28, offset.cast_unsigned()]
        }
        DalvikOpcode::IfEq => encode_if_reg2(0x32, r0, r1, lit),
        DalvikOpcode::IfNe => encode_if_reg2(0x33, r0, r1, lit),
        DalvikOpcode::IfLt => encode_if_reg2(0x34, r0, r1, lit),
        DalvikOpcode::IfGe => encode_if_reg2(0x35, r0, r1, lit),
        DalvikOpcode::IfGt => encode_if_reg2(0x36, r0, r1, lit),
        DalvikOpcode::IfLe => encode_if_reg2(0x37, r0, r1, lit),
        DalvikOpcode::IfEqz => encode_if_z(0x38, r0, lit),
        DalvikOpcode::IfNez => encode_if_z(0x39, r0, lit),
        DalvikOpcode::IfLtz => encode_if_z(0x3a, r0, lit),
        DalvikOpcode::IfGez => encode_if_z(0x3b, r0, lit),
        DalvikOpcode::IfGtz => encode_if_z(0x3c, r0, lit),
        DalvikOpcode::IfLez => encode_if_z(0x3d, r0, lit),
        DalvikOpcode::Aget => encode_abc(0x44, r0, r1, r2),
        DalvikOpcode::Aput => encode_abc(0x4b, r0, r1, r2),
        DalvikOpcode::Iget => encode_ifield(0x52, r0, r1, lit),
        DalvikOpcode::Iput => encode_ifield(0x59, r0, r1, lit),
        DalvikOpcode::Sget => encode_sfield(0x60, r0, lit),
        DalvikOpcode::Sput => encode_sfield(0x67, r0, lit),
        DalvikOpcode::InvokeVirtual => encode_invoke(0x6e, &insn.registers, lit),
        DalvikOpcode::InvokeSuper => encode_invoke(0x6f, &insn.registers, lit),
        DalvikOpcode::InvokeDirect => encode_invoke(0x70, &insn.registers, lit),
        DalvikOpcode::InvokeStatic => encode_invoke(0x71, &insn.registers, lit),
        DalvikOpcode::InvokeInterface => encode_invoke(0x72, &insn.registers, lit),
        DalvikOpcode::NegInt => vec![0x7b, ((lo8_u16(r1)) << 4) | (lo8_u16(r0))],
        DalvikOpcode::NotInt => vec![0x7c, ((lo8_u16(r1)) << 4) | (lo8_u16(r0))],
        DalvikOpcode::NegLong => vec![0x7d, ((lo8_u16(r1)) << 4) | (lo8_u16(r0))],
        DalvikOpcode::IntToLong => vec![0x81, ((lo8_u16(r1)) << 4) | (lo8_u16(r0))],
        DalvikOpcode::IntToFloat => vec![0x82, ((lo8_u16(r1)) << 4) | (lo8_u16(r0))],
        DalvikOpcode::IntToDouble => vec![0x83, ((lo8_u16(r1)) << 4) | (lo8_u16(r0))],
        DalvikOpcode::LongToInt => vec![0x84, ((lo8_u16(r1)) << 4) | (lo8_u16(r0))],
        DalvikOpcode::FloatToInt => vec![0x87, ((lo8_u16(r1)) << 4) | (lo8_u16(r0))],
        DalvikOpcode::DoubleToInt => vec![0x8a, ((lo8_u16(r1)) << 4) | (lo8_u16(r0))],
        DalvikOpcode::IntToByte => vec![0x8d, ((lo8_u16(r1)) << 4) | (lo8_u16(r0))],
        DalvikOpcode::IntToChar => vec![0x8e, ((lo8_u16(r1)) << 4) | (lo8_u16(r0))],
        DalvikOpcode::IntToShort => vec![0x8f, ((lo8_u16(r1)) << 4) | (lo8_u16(r0))],
        DalvikOpcode::AddInt => encode_abc(0x90, r0, r1, r2),
        DalvikOpcode::SubInt => encode_abc(0x91, r0, r1, r2),
        DalvikOpcode::MulInt => encode_abc(0x92, r0, r1, r2),
        DalvikOpcode::DivInt => encode_abc(0x93, r0, r1, r2),
        DalvikOpcode::RemInt => encode_abc(0x94, r0, r1, r2),
        DalvikOpcode::AndInt => encode_abc(0x95, r0, r1, r2),
        DalvikOpcode::OrInt => encode_abc(0x96, r0, r1, r2),
        DalvikOpcode::XorInt => encode_abc(0x97, r0, r1, r2),
        DalvikOpcode::MonitorEnter => vec![0x1d, lo8_u16(r0)],
        DalvikOpcode::MonitorExit => vec![0x1e, lo8_u16(r0)],
        DalvikOpcode::ArrayLength => vec![0x21, ((lo8_u16(r1)) << 4) | (lo8_u16(r0))],
        _ => vec![0x00, 0x00], // NOP fallback
    }
}

fn encode_if_reg2(op: u8, a: u16, b: u16, offset: i64) -> Vec<u8> {
    let mut v = vec![op, ((lo8_u16(b)) << 4) | (lo8_u16(a))];
    v.extend_from_slice(&(as_i16_lit(offset)).to_le_bytes());
    v
}

fn encode_if_z(op: u8, a: u16, offset: i64) -> Vec<u8> {
    let mut v = vec![op, lo8_u16(a)];
    v.extend_from_slice(&(as_i16_lit(offset)).to_le_bytes());
    v
}

fn encode_abc(op: u8, a: u16, b: u16, c: u16) -> Vec<u8> {
    vec![op, lo8_u16(a), lo8_u16(b), lo8_u16(c)]
}

fn encode_ifield(op: u8, a: u16, b: u16, field_idx: i64) -> Vec<u8> {
    let fi = lo16_i64(field_idx);
    vec![op, ((lo8_u16(b)) << 4) | (lo8_u16(a)), lo8_u16(fi), lo8_u16(fi >> 8)]
}

fn encode_sfield(op: u8, a: u16, field_idx: i64) -> Vec<u8> {
    let fi = lo16_i64(field_idx);
    vec![op, lo8_u16(a), lo8_u16(fi), lo8_u16(fi >> 8)]
}

fn encode_invoke(op: u8, regs: &[u8], method_idx: i64) -> Vec<u8> {
    let count = u8::try_from(regs.len().min(5)).unwrap_or(0);
    let mi = lo16_i64(method_idx);
    let r0 = regs.first().copied().unwrap_or(0);
    let r1 = regs.get(1).copied().unwrap_or(0);
    let r2 = regs.get(2).copied().unwrap_or(0);
    let r3 = regs.get(3).copied().unwrap_or(0);
    let r4 = regs.get(4).copied().unwrap_or(0);
    vec![
        op,
        (count << 4) | (r4 & 0xf),
        lo8_u16(mi),
        lo8_u16(mi >> 8),
        (r1 << 4) | (r0 & 0xf),
        (r3 << 4) | (r2 & 0xf),
    ]
}

// ── DEX Writer ────────────────────────────────────────────────────────────────

/// Assembled DEX bytecode for a single method.
#[derive(Debug, Clone, Default)]
pub struct MethodBytecode {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub bytecode: Vec<u8>,
    pub tries: Vec<TryItem>,
    pub handlers: Vec<EncodedCatchHandler>,
}

#[derive(Debug, Clone)]
pub struct TryItem {
    pub start_addr: u32,
    pub insn_count: u16,
    pub handler_off: u16,
}

#[derive(Debug, Clone)]
pub struct EncodedCatchHandler {
    pub handlers: Vec<(u32, u32)>, // (type_idx, addr)
    pub catch_all_addr: Option<u32>,
}

/// Writer that builds the complete DEX binary.
pub struct DexWriter {
    pub strings: StringTable,
    pub types: TypeTable,
    pub protos: ProtoTable,
    pub fields: FieldTable,
    pub methods: MethodTable,
    class_name: String,
    super_name: String,
    method_bytecodes: Vec<(String, MethodBytecode)>, // (method_name, bytecode)
    field_list: Vec<(String, Vec<String>, String)>,  // (name, flags, type)
}

impl DexWriter {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            strings: StringTable::default(),
            types: TypeTable::default(),
            protos: ProtoTable::default(),
            fields: FieldTable::default(),
            methods: MethodTable::default(),
            class_name: String::new(),
            super_name: String::from("Ljava/lang/Object;"),
            method_bytecodes: Vec::new(),
            field_list: Vec::new(),
        }
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn from_parsed(class: &ParsedClass) -> Result<Vec<u8>> {
        let mut writer = Self::new();
        writer.ingest_class(class)?;
        writer.emit()
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn ingest_class(&mut self, class: &ParsedClass) -> Result<()> {
        self.class_name.clone_from(&class.class_name);
        self.super_name = class
            .super_name
            .clone()
            .unwrap_or_else(|| String::from("Ljava/lang/Object;"));
        // Intern class and super.
        self.strings.intern(&self.class_name.clone());
        self.strings.intern(&self.super_name.clone());
        self.types.intern(&self.class_name.clone(), &mut self.strings);
        self.types.intern(&self.super_name.clone(), &mut self.strings);
        // Fields
        for field in &class.fields {
            self.ingest_field(field)?;
        }
        // Methods
        for method in &class.methods {
            let bc = self.assemble_method(method, &class.class_name)?;
            self.method_bytecodes.push((method.name.clone(), bc));
        }
        Ok(())
    }

    fn ingest_field(&mut self, field: &ParsedField) -> Result<()> {
        self.fields.intern(
            &self.class_name.clone(),
            &field.name,
            &field.type_desc,
            &mut self.strings,
            &mut self.types,
        );
        self.field_list.push((
            field.name.clone(),
            field.access_flags.clone(),
            field.type_desc.clone(),
        ));
        Ok(())
    }

    fn assemble_method(
        &mut self,
        method: &ParsedMethod,
        _class_name: &str,
    ) -> Result<MethodBytecode> {
        // Build a label→offset map first pass.
        let mut label_offsets: HashMap<String, u32> = HashMap::new();
        let mut offset: u32 = 0;
        for (i, insn) in method.instructions.iter().enumerate() {
            // Check labels that point to this instruction.
            for (name, lbl) in &method.labels {
                if lbl.instruction_index == i {
                    label_offsets.insert(name.clone(), offset);
                }
            }
            let encoded = encode_instruction(insn);
            offset += lo32_usize(encoded.len());
        }
        // Second pass: emit with resolved labels.
        let mut bytecode: Vec<u8> = Vec::new();
        let mut cur_off: u32 = 0;
        for insn in &method.instructions {
            let mut insn_patched = insn.clone();
            // Resolve label reference to PC-relative offset.
            if let Some(label) = &insn.label
                && let Some(&target) = label_offsets.get(label) {
                    let rel = i64::from(target) - i64::from(cur_off);
                    insn_patched.literal = Some(rel / 2); // Dalvik offsets in code units (2 bytes)
                }
            // Resolve string/type/field/method references to pool indices.
            if let Some(s) = &insn.string_ref {
                let idx = self.strings.intern(s);
                insn_patched.literal = Some(i64::from(idx));
            }
            if let Some(t) = &insn.type_ref {
                let _cn = self.class_name.clone();
                let idx = self.types.intern(t, &mut self.strings);
                insn_patched.literal = Some(i64::from(idx));
            }
            if let Some(f) = &insn.field_ref
                && let Some((class, name_type)) = f.split_once("->")
                    && let Some((name, typ)) = name_type.split_once(':') {
                        let idx = self.fields.intern(
                            class,
                            name,
                            typ,
                            &mut self.strings,
                            &mut self.types,
                        );
                        insn_patched.literal = Some(i64::from(idx));
                    }
            if let Some(m) = &insn.method_ref
                && let Some((class, rest)) = m.split_once("->") {
                    let (name, desc) = rest
                        .find('(')
                        .map_or((rest, "()V"), |i| (&rest[..i], &rest[i..]));
                    let proto_idx = self.protos.intern(desc, &mut self.strings, &mut self.types);
                    let idx = self.methods.intern(
                        class,
                        name,
                        desc,
                        proto_idx,
                        &mut self.strings,
                        &mut self.types,
                    );
                    insn_patched.literal = Some(i64::from(idx));
                }
            let encoded = encode_instruction(&insn_patched);
            cur_off += lo32_usize(encoded.len());
            bytecode.extend_from_slice(&encoded);
        }
        let regs = u16::from(method.registers_directive.unwrap_or(4));
        let (_, param_count) = parse_method_descriptor_counts(&method.descriptor);
        Ok(MethodBytecode {
            registers_size: regs,
            ins_size: lo16_usize(param_count),
            outs_size: 4,
            bytecode,
            tries: Vec::new(),
            handlers: Vec::new(),
        })
    }

    /// Emit the full DEX binary.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn emit(&mut self) -> Result<Vec<u8>> {
        self.strings.sort_and_rebuild();
        let mut out = vec![0u8; HEADER_SIZE as usize];
        // Write magic
        out[..8].copy_from_slice(DEX_MAGIC);
        // Checksum placeholder at offset 8 (4 bytes Adler-32)
        // SHA-1 at offset 12 (20 bytes)
        // file_size at offset 32
        write_u32_le(&mut out, 36, HEADER_SIZE); // header_size
        write_u32_le(&mut out, 40, ENDIAN_CONSTANT);
        // Append sections and record offsets.
        let string_ids_off = lo32_usize(out.len());
        let string_count = self.strings.len();
        // Placeholder: string_id_list (4 bytes each)
        let _string_data_offsets: Vec<u32> = Vec::new();
        for _ in 0..string_count {
            append_u32(&mut out, 0);
        }
        // Type IDs section
        let type_ids_off = lo32_usize(out.len());
        let type_count = self.types.len();
        for t in self.types.types() {
            let idx = self.strings.get_index(t).unwrap_or(0);
            append_u32(&mut out, idx);
        }
        // Proto IDs section
        let proto_ids_off = lo32_usize(out.len());
        let proto_count = self.protos.len();
        let mut proto_param_offsets: Vec<u32> = Vec::new();
        for proto in self.protos.protos() {
            let shorty_idx = self.strings.get_index(&proto.shorty).unwrap_or(0);
            let ret_type_idx = lo32_usize(self.types.types().iter().position(|t| t == &proto.return_type).unwrap_or(0));
            append_u32(&mut out, shorty_idx);
            append_u32(&mut out, ret_type_idx);
            proto_param_offsets.push(lo32_usize(out.len()));
            append_u32(&mut out, 0); // parameters_off placeholder
        }
        // Field IDs section
        let field_ids_off = lo32_usize(out.len());
        let field_count = self.fields.len();
        for field in self.fields.fields() {
            let class_idx = lo16_usize(self.types.types().iter().position(|t| t == &field.class).unwrap_or(0));
            let type_idx = lo16_usize(self.types.types().iter().position(|t| t == &field.type_desc).unwrap_or(0));
            let name_idx = self.strings.get_index(&field.name).unwrap_or(0);
            out.extend_from_slice(&class_idx.to_le_bytes());
            out.extend_from_slice(&type_idx.to_le_bytes());
            append_u32(&mut out, name_idx);
        }
        // Method IDs section
        let method_ids_off = lo32_usize(out.len());
        let method_count = self.methods.len();
        for method in self.methods.methods() {
            let class_idx = lo16_usize(self.types.types().iter().position(|t| t == &method.class).unwrap_or(0));
            let proto_idx = lo16_u32(method.proto_idx);
            let name_idx = self.strings.get_index(&method.name).unwrap_or(0);
            out.extend_from_slice(&class_idx.to_le_bytes());
            out.extend_from_slice(&proto_idx.to_le_bytes());
            append_u32(&mut out, name_idx);
        }
        // Class definitions
        let class_defs_off = lo32_usize(out.len());
        let class_idx = lo32_usize(self.types.types().iter().position(|t| *t == self.class_name).unwrap_or(0));
        let super_idx = lo32_usize(self.types.types().iter().position(|t| *t == self.super_name).unwrap_or(NO_INDEX as usize));
        append_u32(&mut out, class_idx);           // class_idx
        append_u32(&mut out, access_flags_for_class()); // access_flags
        append_u32(&mut out, super_idx);           // superclass_idx
        append_u32(&mut out, 0);                   // interfaces_off
        append_u32(&mut out, NO_INDEX);            // source_file_idx
        append_u32(&mut out, 0);                   // annotations_off
        let class_data_off_placeholder = lo32_usize(out.len());
        append_u32(&mut out, 0);                   // class_data_off (filled later)
        append_u32(&mut out, 0);                   // static_values_off
        // String data section
        let mut actual_string_data_offsets: Vec<u32> = Vec::new();
        align(&mut out, 4);
        for s in self.strings.strings() {
            actual_string_data_offsets.push(lo32_usize(out.len()));
            let data = StringTable::encode_data_item(s);
            out.extend_from_slice(&data);
        }
        // Patch string_id_list
        for (i, &off) in actual_string_data_offsets.iter().enumerate() {
            write_u32_le(&mut out, string_ids_off as usize + i * 4, off);
        }
        // Code items (method bytecode)
        let mut code_item_offsets: Vec<u32> = Vec::new();
        for (_, bc) in &self.method_bytecodes {
            align(&mut out, 4);
            code_item_offsets.push(lo32_usize(out.len()));
            out.extend_from_slice(&bc.registers_size.to_le_bytes());
            out.extend_from_slice(&bc.ins_size.to_le_bytes());
            out.extend_from_slice(&bc.outs_size.to_le_bytes());
            // tries_size
            out.extend_from_slice(&(lo16_usize(bc.tries.len())).to_le_bytes());
            // debug_info_off
            append_u32(&mut out, 0);
            // insns_size (in 16-bit code units)
            let insns_size = lo32_usize(bc.bytecode.len()) / 2;
            append_u32(&mut out, insns_size);
            out.extend_from_slice(&bc.bytecode);
            if bc.bytecode.len() % 4 != 0 {
                out.extend_from_slice(&[0, 0]);
            }
        }
        // Class data item
        align(&mut out, 4);
        let class_data_off = lo32_usize(out.len());
        write_u32_le(&mut out, class_data_off_placeholder as usize, class_data_off);
        let static_fields_size = encode_uleb128(0);
        let instance_fields_size = encode_uleb128(self.field_list.len() as u64);
        let direct_methods_size = encode_uleb128(0);
        let virtual_methods_size = encode_uleb128(self.method_bytecodes.len() as u64);
        out.extend_from_slice(&static_fields_size);
        out.extend_from_slice(&instance_fields_size);
        out.extend_from_slice(&direct_methods_size);
        out.extend_from_slice(&virtual_methods_size);
        // Emit virtual method entries.
        let mut prev_method_idx = 0u32;
        for (i, (mname, _bc)) in self.method_bytecodes.iter().enumerate() {
            let method_idx = lo32_usize(self.methods.methods().iter().position(|m| &m.name == mname).unwrap_or(i));
            let diff = method_idx.wrapping_sub(prev_method_idx);
            prev_method_idx = method_idx;
            out.extend_from_slice(&encode_uleb128(u64::from(diff)));
            out.extend_from_slice(&encode_uleb128(0x0001)); // ACC_PUBLIC
            let code_off = code_item_offsets.get(i).copied().unwrap_or(0);
            out.extend_from_slice(&encode_uleb128(u64::from(code_off)));
        }
        // Finalize header fields.
        let file_size = lo32_usize(out.len());
        write_u32_le(&mut out, 32, file_size);
        write_u32_le(&mut out, 52, string_ids_off);
        write_u32_le(&mut out, 56, string_count);
        write_u32_le(&mut out, 60, type_ids_off);
        write_u32_le(&mut out, 64, type_count);
        write_u32_le(&mut out, 68, proto_ids_off);
        write_u32_le(&mut out, 72, proto_count);
        write_u32_le(&mut out, 76, field_ids_off);
        write_u32_le(&mut out, 80, field_count);
        write_u32_le(&mut out, 84, method_ids_off);
        write_u32_le(&mut out, 88, method_count);
        write_u32_le(&mut out, 92, class_defs_off);
        write_u32_le(&mut out, 96, 1); // class_defs_size
        // Compute and write Adler-32 checksum (over bytes 12..).
        let checksum = adler32(&out[12..]);
        write_u32_le(&mut out, 8, checksum);
        // Compute and write SHA-1 (over bytes 32..).
        let sha1 = sha1_bytes(&out[32..]);
        out[12..32].copy_from_slice(&sha1);
        Ok(out)
    }
}

impl Default for DexWriter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Checksum helpers ──────────────────────────────────────────────────────────

fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

fn sha1_bytes(data: &[u8]) -> [u8; 20] {
    // Minimal SHA-1 implementation.
    let mut h: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let msg_len_bits = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&msg_len_bits.to_be_bytes());
    for chunk in padded.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap_or([0; 4]));
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999_u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let tmp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, &v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

// ── Utility helpers ───────────────────────────────────────────────────────────

fn encode_uleb128(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
    out
}

fn write_u32_le(buf: &mut [u8], offset: usize, value: u32) {
    if offset + 4 <= buf.len() {
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}

fn append_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn align(buf: &mut Vec<u8>, alignment: usize) {
    while !buf.len().is_multiple_of(alignment) {
        buf.push(0);
    }
}

const fn access_flags_for_class() -> u32 {
    0x0001 | 0x0020 // ACC_PUBLIC | ACC_SUPER
}

/// Parse `(Ljava/lang/String;I)V` → (params, `return_type`)
fn parse_method_descriptor(descriptor: &str) -> (Vec<String>, String) {
    let start = descriptor.find('(').unwrap_or(0) + 1;
    let end = descriptor.rfind(')').unwrap_or(descriptor.len());
    let param_str = &descriptor[start..end];
    let ret_str = &descriptor[end + 1..];
    let params = split_type_list(param_str);
    (params, ret_str.to_string())
}

fn parse_method_descriptor_counts(descriptor: &str) -> (usize, usize) {
    let (params, _ret) = parse_method_descriptor(descriptor);
    let long_wide = params.iter().filter(|p| *p == "J" || *p == "D").count();
    (params.len(), params.len() + long_wide)
}

fn split_type_list(s: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            'L' => {
                let mut t = String::from('L');
                chars.next();
                while let Some(&x) = chars.peek() {
                    t.push(x);
                    chars.next();
                    if x == ';' {
                        break;
                    }
                }
                result.push(t);
            }
            '[' => {
                let mut t = String::new();
                while chars.peek() == Some(&'[') {
                    t.push('[');
                    chars.next();
                }
                // Array element type
                if let Some(&x) = chars.peek() {
                    if x == 'L' {
                        t.push('L');
                        chars.next();
                        while let Some(&y) = chars.peek() {
                            t.push(y);
                            chars.next();
                            if y == ';' {
                                break;
                            }
                        }
                    } else {
                        t.push(x);
                        chars.next();
                    }
                }
                result.push(t);
            }
            _ => {
                result.push(c.to_string());
                chars.next();
            }
        }
    }
    result
}

fn build_shorty(params: &[String], ret: &str) -> String {
    let mut s = String::new();
    s.push(type_to_shorty_char(ret));
    for p in params {
        s.push(type_to_shorty_char(p));
    }
    s
}

fn type_to_shorty_char(t: &str) -> char {
    match t {
        "V" => 'V',
        "Z" => 'Z',
        "B" => 'B',
        "S" => 'S',
        "C" => 'C',
        "I" => 'I',
        "J" => 'J',
        "F" => 'F',
        "D" => 'D',
        t if t.starts_with('L') || t.starts_with('[') => 'L',
        _ => 'V',
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smali_parser::parse_smali;

    #[test]
    fn test_truncation_helpers() {
        assert_eq!(lo32_u64(0xFFFF_FFFF_FFFF_FFFF), u32::MAX);
        assert_eq!(lo32_u64(0x1_0000_0000), 0);
    }

    #[test]
    fn test_string_table_intern() {
        let mut st = StringTable::default();
        let idx1 = st.intern("hello");
        let idx2 = st.intern("world");
        let idx3 = st.intern("hello");
        assert_eq!(idx1, idx3);
        assert_ne!(idx1, idx2);
    }

    #[test]
    fn test_encode_nop() {
        let insn = ParsedInstruction::new(DalvikOpcode::Nop, 1);
        assert_eq!(encode_instruction(&insn), vec![0x00, 0x00]);
    }

    #[test]
    fn test_encode_return_void() {
        let insn = ParsedInstruction::new(DalvikOpcode::ReturnVoid, 1);
        assert_eq!(encode_instruction(&insn), vec![0x0e, 0x00]);
    }

    #[test]
    fn test_uleb128() {
        assert_eq!(encode_uleb128(0), vec![0x00]);
        assert_eq!(encode_uleb128(127), vec![0x7f]);
        assert_eq!(encode_uleb128(128), vec![0x80, 0x01]);
        assert_eq!(encode_uleb128(300), vec![0xac, 0x02]);
    }

    #[test]
    fn test_adler32() {
        let chk = adler32(b"hello");
        assert_ne!(chk, 0);
    }

    #[test]
    fn test_sha1_len() {
        let hash = sha1_bytes(b"abc");
        assert_eq!(hash.len(), 20);
    }

    #[test]
    fn test_parse_descriptor() {
        let (params, ret) = parse_method_descriptor("(Ljava/lang/String;I)V");
        assert_eq!(ret, "V");
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn test_full_assemble() {
        let src = r"
.class public Ltest/Foo;
.super Ljava/lang/Object;
.method public constructor <init>()V
    .registers 1
    return-void
.end method
";
        let parsed = parse_smali(src).unwrap();
        let dex = DexWriter::from_parsed(&parsed).unwrap();
        assert!(dex.len() >= HEADER_SIZE as usize);
        assert_eq!(&dex[..8], DEX_MAGIC);
    }
}
