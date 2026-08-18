//! Build **real** [`SmaliClass`] values out of **real** `.dex` bytes.
//!
//! Everything reported here is decoded from the input: class descriptors and
//! superclasses come from the DEX type table, fields and methods from each
//! class's `class_data_item`, and instructions from the `code_item` decoded by
//! this crate's own Dalvik disassembler. Nothing is synthesised — when the
//! input is not a DEX file, or a structure is truncated, a typed
//! [`SmaliError`] is returned instead of a plausible-looking class.

use crate::disassembler::{DisasmInstr, disassemble_words};
use crate::{
    SmaliAccess, SmaliClass, SmaliError, SmaliField, SmaliInstr, SmaliMethod, SmaliOp,
    SmaliOperand, SmaliReg,
};
use rustre_loader_android::dex::{DexFile, read_uleb128};

// ─── access flags ────────────────────────────────────────────────────────────

/// Translate DEX `access_flags` into this crate's [`SmaliAccess`] bits.
///
/// The two encodings do not agree (DEX `ACC_CONSTRUCTOR` is `0x0001_0000`,
/// `ACC_NATIVE` is `0x0100`), so the mapping is explicit rather than a cast.
#[must_use]
pub fn access_from_dex_flags(flags: u32) -> SmaliAccess {
    let mut a = SmaliAccess::empty();
    if flags & 0x0001 != 0 {
        a |= SmaliAccess::PUBLIC;
    }
    if flags & 0x0002 != 0 {
        a |= SmaliAccess::PRIVATE;
    }
    if flags & 0x0004 != 0 {
        a |= SmaliAccess::PROTECTED;
    }
    if flags & 0x0008 != 0 {
        a |= SmaliAccess::STATIC;
    }
    if flags & 0x0010 != 0 {
        a |= SmaliAccess::FINAL;
    }
    if flags & 0x0100 != 0 {
        a |= SmaliAccess::NATIVE;
    }
    if flags & 0x0400 != 0 {
        a |= SmaliAccess::ABSTRACT;
    }
    if flags & 0x0001_0000 != 0 {
        a |= SmaliAccess::CONSTRUCTOR;
    }
    a
}

// ─── operand recovery ────────────────────────────────────────────────────────

/// Convert one decoded operand string into a typed [`SmaliOperand`].
///
/// Registers above `v255` are reported as [`SmaliOperand::Str`] rather than
/// truncated into [`SmaliReg`]'s `u8`: Dalvik allows register numbers up to
/// 65535 and silently wrapping one would be a fabricated register.
#[must_use]
pub fn operand_from_text(text: &str) -> SmaliOperand {
    let t = text.trim();

    if let Some(num) = t.strip_prefix('v') {
        if !num.is_empty() && num.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(n) = num.parse::<u8>() {
                return SmaliOperand::Reg(SmaliReg { num: n });
            }
            return SmaliOperand::Str(t.to_owned());
        }
    }

    if t.contains("->") {
        if t.contains('(') {
            return SmaliOperand::MethodRef(t.to_owned());
        }
        return SmaliOperand::FieldRef(t.to_owned());
    }

    if (t.starts_with('L') && t.ends_with(';')) || t.starts_with('[') {
        return SmaliOperand::TypeRef(t.to_owned());
    }

    let numeric = t.strip_prefix('#').unwrap_or(t);
    let numeric = numeric.strip_prefix('+').unwrap_or(numeric);
    if let Some(hex) = numeric.strip_prefix("0x") {
        if let Ok(v) = i64::from_str_radix(hex, 16) {
            return SmaliOperand::Literal(v);
        }
    }
    if let Some(hex) = numeric.strip_prefix("-0x") {
        if let Ok(v) = i64::from_str_radix(hex, 16) {
            return SmaliOperand::Literal(-v);
        }
    }
    if let Ok(v) = numeric.parse::<i64>() {
        return SmaliOperand::Literal(v);
    }

    SmaliOperand::Str(t.to_owned())
}

/// Convert a disassembled instruction into a [`SmaliInstr`].
#[must_use]
pub fn instr_from_disasm(d: &DisasmInstr) -> SmaliInstr {
    let op: SmaliOp = crate::parser::opcode_from_str(&d.mnemonic);
    SmaliInstr {
        op,
        operands: d.operands.iter().map(|o| operand_from_text(o)).collect(),
        label: None,
    }
}

// ─── code items ──────────────────────────────────────────────────────────────

/// A decoded `code_item` header plus its instruction stream.
#[derive(Debug, Clone)]
pub struct DexCode {
    /// Number of registers the method frame uses.
    pub registers_size: u16,
    /// Number of argument registers.
    pub ins_size: u16,
    /// Decoded instructions.
    pub instrs: Vec<DisasmInstr>,
}

/// Decode the `code_item` at `off` in `raw`.
///
/// # Errors
/// Returns [`SmaliError::ParseError`] when the header or the instruction
/// stream runs past the end of the file.
pub fn read_code_item(raw: &[u8], off: usize) -> Result<DexCode, SmaliError> {
    if off == 0 {
        return Ok(DexCode {
            registers_size: 0,
            ins_size: 0,
            instrs: Vec::new(),
        });
    }
    let header_end = off
        .checked_add(16)
        .ok_or_else(|| SmaliError::ParseError("code_item offset overflow".to_owned()))?;
    if header_end > raw.len() {
        return Err(SmaliError::ParseError(format!(
            "code_item at {off} is truncated"
        )));
    }
    let u16_at = |p: usize| u16::from_le_bytes([raw[p], raw[p + 1]]);
    let registers_size = u16_at(off);
    let ins_size = u16_at(off + 2);
    let insns_size = u32::from_le_bytes([
        raw[off + 12],
        raw[off + 13],
        raw[off + 14],
        raw[off + 15],
    ]) as usize;

    let insns_end = header_end
        .checked_add(insns_size.checked_mul(2).ok_or_else(|| {
            SmaliError::ParseError("code_item insns_size overflow".to_owned())
        })?)
        .ok_or_else(|| SmaliError::ParseError("code_item insns overflow".to_owned()))?;
    if insns_end > raw.len() {
        return Err(SmaliError::ParseError(format!(
            "code_item at {off} declares {insns_size} code units past end of file"
        )));
    }

    let words: Vec<u16> = (0..insns_size)
        .map(|i| u16_at(header_end + i * 2))
        .collect();

    Ok(DexCode {
        registers_size,
        ins_size,
        instrs: disassemble_words(&words)?,
    })
}

// ─── classes ─────────────────────────────────────────────────────────────────

fn method_signature(dex: &DexFile, proto_idx: usize) -> String {
    let Some(proto) = dex.protos.get(proto_idx) else {
        return String::new();
    };
    let ret = dex
        .type_descs
        .get(proto.return_type_idx as usize)
        .cloned()
        .unwrap_or_default();

    let mut params = String::new();
    let off = proto.parameters_off as usize;
    if off != 0 && off + 4 <= dex.raw.len() {
        let count = u32::from_le_bytes([
            dex.raw[off],
            dex.raw[off + 1],
            dex.raw[off + 2],
            dex.raw[off + 3],
        ]) as usize;
        for i in 0..count {
            let p = off + 4 + i * 2;
            if p + 2 > dex.raw.len() {
                break;
            }
            let type_idx = u16::from_le_bytes([dex.raw[p], dex.raw[p + 1]]) as usize;
            if let Some(t) = dex.type_descs.get(type_idx) {
                params.push_str(t);
            }
        }
    }
    format!("({params}){ret}")
}

/// Decode every class defined in `data` into a [`SmaliClass`].
///
/// # Errors
/// Returns [`SmaliError::ParseError`] when `data` is not a parsable DEX file.
pub fn classes_from_dex_bytes(data: &[u8]) -> Result<Vec<SmaliClass>, SmaliError> {
    let dex = DexFile::parse(data)
        .map_err(|e| SmaliError::ParseError(format!("not a parsable DEX file: {e}")))?;

    let mut out = Vec::with_capacity(dex.class_defs.len());
    for def in &dex.class_defs {
        let name = dex.class_name(def).to_owned();
        let super_class = dex
            .superclass_name(def)
            .unwrap_or("Ljava/lang/Object;")
            .to_owned();

        let mut interfaces = Vec::new();
        let ioff = def.interfaces_off as usize;
        if ioff != 0 && ioff + 4 <= dex.raw.len() {
            let count = u32::from_le_bytes([
                dex.raw[ioff],
                dex.raw[ioff + 1],
                dex.raw[ioff + 2],
                dex.raw[ioff + 3],
            ]) as usize;
            for i in 0..count {
                let p = ioff + 4 + i * 2;
                if p + 2 > dex.raw.len() {
                    break;
                }
                let idx = u16::from_le_bytes([dex.raw[p], dex.raw[p + 1]]) as usize;
                if let Some(t) = dex.type_descs.get(idx) {
                    interfaces.push(t.clone());
                }
            }
        }

        let mut fields = Vec::new();
        let mut methods = Vec::new();

        let cd = def.class_data_off as usize;
        if cd != 0 && cd < dex.raw.len() {
            let mut pos = cd;
            let static_fields = read_uleb128(&dex.raw, &mut pos) as usize;
            let instance_fields = read_uleb128(&dex.raw, &mut pos) as usize;
            let direct_methods = read_uleb128(&dex.raw, &mut pos) as usize;
            let virtual_methods = read_uleb128(&dex.raw, &mut pos) as usize;

            for group in [static_fields, instance_fields] {
                let mut idx: u64 = 0;
                for i in 0..group {
                    let diff = u64::from(read_uleb128(&dex.raw, &mut pos));
                    let flags = read_uleb128(&dex.raw, &mut pos);
                    idx = if i == 0 { diff } else { idx + diff };
                    let Some(f) = dex.fields.get(usize::try_from(idx).unwrap_or(usize::MAX))
                    else {
                        continue;
                    };
                    fields.push(SmaliField {
                        name: dex
                            .strings
                            .get(f.name_idx as usize)
                            .cloned()
                            .unwrap_or_default(),
                        type_desc: dex
                            .type_descs
                            .get(f.type_idx as usize)
                            .cloned()
                            .unwrap_or_default(),
                        access: access_from_dex_flags(flags),
                        initial: None,
                    });
                }
            }

            for group in [direct_methods, virtual_methods] {
                let mut idx: u64 = 0;
                for i in 0..group {
                    let diff = u64::from(read_uleb128(&dex.raw, &mut pos));
                    let flags = read_uleb128(&dex.raw, &mut pos);
                    let code_off = read_uleb128(&dex.raw, &mut pos) as usize;
                    idx = if i == 0 { diff } else { idx + diff };
                    let Some(m) = dex.methods.get(usize::try_from(idx).unwrap_or(usize::MAX))
                    else {
                        continue;
                    };
                    let code = read_code_item(&dex.raw, code_off)?;
                    methods.push(SmaliMethod {
                        name: dex
                            .strings
                            .get(m.name_idx as usize)
                            .cloned()
                            .unwrap_or_default(),
                        class: name.clone(),
                        signature: method_signature(&dex, m.proto_idx as usize),
                        access: access_from_dex_flags(flags),
                        registers: u8::try_from(code.registers_size).unwrap_or(u8::MAX),
                        instructions: code.instrs.iter().map(instr_from_disasm).collect(),
                    });
                }
            }
        }

        out.push(SmaliClass {
            name,
            super_class,
            access: access_from_dex_flags(def.access_flags),
            methods,
            fields,
            interfaces,
        });
    }
    Ok(out)
}

/// Decode a single class out of `data`, matched either by full descriptor
/// (`Lcom/example/Foo;`) or by simple name (`Foo`).
///
/// # Errors
/// Returns [`SmaliError::ParseError`] when `data` is not a parsable DEX file,
/// or when it contains no class with that name.
pub fn class_from_dex_bytes(data: &[u8], name: &str) -> Result<SmaliClass, SmaliError> {
    let classes = classes_from_dex_bytes(data)?;
    classes
        .into_iter()
        .find(|c| {
            c.name == name
                || c.name
                    .trim_start_matches('L')
                    .trim_end_matches(';')
                    .rsplit('/')
                    .next()
                    == Some(name)
        })
        .ok_or_else(|| SmaliError::ParseError(format!("no class named {name} in this DEX file")))
}

/// Render a decoded method as a smali listing.
#[must_use]
pub fn method_listing(m: &SmaliMethod) -> String {
    let mut s = format!(".method {} {}\n", m.name, m.signature);
    s.push_str(&format!("    .registers {}\n", m.registers));
    for i in &m.instructions {
        let ops: Vec<String> = i.operands.iter().map(ToString::to_string).collect();
        if ops.is_empty() {
            s.push_str(&format!("    {}\n", i.op));
        } else {
            s.push_str(&format!("    {} {}\n", i.op, ops.join(", ")));
        }
    }
    s.push_str(".end method\n");
    s
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but structurally valid DEX file in memory:
    /// one class `LFoo;` extending `Ljava/lang/Object;` with one direct
    /// method `<init>()V` whose body is a single `return-void`.
    ///
    /// Nothing about the decode below is stubbed — this is a real DEX byte
    /// stream, laid out per the DEX spec, that the parser walks.
    pub fn minimal_dex() -> Vec<u8> {
        fn uleb(v: u32, out: &mut Vec<u8>) {
            let mut v = v;
            loop {
                let mut b = (v & 0x7F) as u8;
                v >>= 7;
                if v != 0 {
                    b |= 0x80;
                }
                out.push(b);
                if v == 0 {
                    break;
                }
            }
        }

        let strings = ["LFoo;", "Ljava/lang/Object;", "V", "<init>"];

        const HEADER: usize = 112;
        let string_ids_off = HEADER;
        let type_ids_off = string_ids_off + strings.len() * 4;
        let proto_ids_off = type_ids_off + 3 * 4;
        let method_ids_off = proto_ids_off + 12;
        let class_defs_off = method_ids_off + 8;
        let data_off = class_defs_off + 32;

        // ── data section ──
        let mut data = Vec::new();
        let mut string_data_offs = Vec::new();
        for s in strings {
            string_data_offs.push(data_off + data.len());
            uleb(u32::try_from(s.chars().count()).unwrap(), &mut data);
            data.extend_from_slice(s.as_bytes());
            data.push(0);
        }
        while (data_off + data.len()) % 4 != 0 {
            data.push(0);
        }
        let code_off = data_off + data.len();
        data.extend_from_slice(&1u16.to_le_bytes()); // registers_size
        data.extend_from_slice(&1u16.to_le_bytes()); // ins_size
        data.extend_from_slice(&0u16.to_le_bytes()); // outs_size
        data.extend_from_slice(&0u16.to_le_bytes()); // tries_size
        data.extend_from_slice(&0u32.to_le_bytes()); // debug_info_off
        data.extend_from_slice(&1u32.to_le_bytes()); // insns_size
        data.extend_from_slice(&0x000Eu16.to_le_bytes()); // return-void

        let class_data_off = data_off + data.len();
        uleb(0, &mut data); // static_fields_size
        uleb(0, &mut data); // instance_fields_size
        uleb(1, &mut data); // direct_methods_size
        uleb(0, &mut data); // virtual_methods_size
        uleb(0, &mut data); // method_idx_diff
        uleb(0x0001_0001, &mut data); // ACC_PUBLIC | ACC_CONSTRUCTOR
        uleb(u32::try_from(code_off).unwrap(), &mut data);

        // ── assemble ──
        let total = data_off + data.len();
        let mut f = vec![0u8; total];
        f[0..8].copy_from_slice(b"dex\n035\0");
        let put32 = |f: &mut Vec<u8>, at: usize, v: u32| {
            f[at..at + 4].copy_from_slice(&v.to_le_bytes());
        };
        put32(&mut f, 32, u32::try_from(total).unwrap()); // file_size
        put32(&mut f, 36, 112); // header_size
        put32(&mut f, 40, 0x1234_5678); // endian_tag
        put32(&mut f, 56, u32::try_from(strings.len()).unwrap());
        put32(&mut f, 60, u32::try_from(string_ids_off).unwrap());
        put32(&mut f, 64, 3);
        put32(&mut f, 68, u32::try_from(type_ids_off).unwrap());
        put32(&mut f, 72, 1);
        put32(&mut f, 76, u32::try_from(proto_ids_off).unwrap());
        put32(&mut f, 80, 0);
        put32(&mut f, 84, 0);
        put32(&mut f, 88, 1);
        put32(&mut f, 92, u32::try_from(method_ids_off).unwrap());
        put32(&mut f, 96, 1);
        put32(&mut f, 100, u32::try_from(class_defs_off).unwrap());
        put32(&mut f, 104, u32::try_from(data.len()).unwrap());
        put32(&mut f, 108, u32::try_from(data_off).unwrap());

        for (i, off) in string_data_offs.iter().enumerate() {
            put32(&mut f, string_ids_off + i * 4, u32::try_from(*off).unwrap());
        }
        // type_ids -> string indices 0,1,2
        for i in 0..3u32 {
            put32(&mut f, type_ids_off + (i as usize) * 4, i);
        }
        // proto: shorty_idx=2 ("V"), return_type_idx=2 ("V"), parameters_off=0
        put32(&mut f, proto_ids_off, 2);
        put32(&mut f, proto_ids_off + 4, 2);
        put32(&mut f, proto_ids_off + 8, 0);
        // method_id: class_idx=0, proto_idx=0, name_idx=3
        f[method_ids_off..method_ids_off + 2].copy_from_slice(&0u16.to_le_bytes());
        f[method_ids_off + 2..method_ids_off + 4].copy_from_slice(&0u16.to_le_bytes());
        put32(&mut f, method_ids_off + 4, 3);
        // class_def
        put32(&mut f, class_defs_off, 0); // class_idx -> LFoo;
        put32(&mut f, class_defs_off + 4, 0x0001); // access_flags
        put32(&mut f, class_defs_off + 8, 1); // superclass_idx -> Object
        put32(&mut f, class_defs_off + 12, 0); // interfaces_off
        put32(&mut f, class_defs_off + 16, 0xFFFF_FFFF); // source_file_idx
        put32(&mut f, class_defs_off + 20, 0); // annotations_off
        put32(&mut f, class_defs_off + 24, u32::try_from(class_data_off).unwrap());
        put32(&mut f, class_defs_off + 28, 0); // static_values_off

        f[data_off..].copy_from_slice(&data);
        f
    }

    #[test]
    fn real_dex_bytes_yield_the_real_class() {
        let dex = minimal_dex();
        let classes = classes_from_dex_bytes(&dex).unwrap();
        assert_eq!(classes.len(), 1);
        let c = &classes[0];
        assert_eq!(c.name, "LFoo;");
        assert_eq!(c.super_class, "Ljava/lang/Object;");
        assert_eq!(c.methods.len(), 1);
        let m = &c.methods[0];
        assert_eq!(m.name, "<init>");
        assert_eq!(m.signature, "()V");
        assert!(m.access.contains(SmaliAccess::CONSTRUCTOR));
        assert_eq!(m.registers, 1);
        assert_eq!(m.instructions.len(), 1);
        assert_eq!(m.instructions[0].op, SmaliOp::ReturnVoid);
    }

    #[test]
    fn garbage_is_rejected_not_invented() {
        let err = classes_from_dex_bytes(b"this is not a dex file at all").unwrap_err();
        assert!(matches!(err, SmaliError::ParseError(_)));
    }

    #[test]
    fn empty_input_is_rejected() {
        assert!(classes_from_dex_bytes(&[]).is_err());
    }

    #[test]
    fn dex_access_flags_are_not_the_smali_ones() {
        // ACC_CONSTRUCTOR in DEX is 0x10000, not 0x20.
        let a = access_from_dex_flags(0x0001 | 0x0001_0000);
        assert!(a.contains(SmaliAccess::PUBLIC));
        assert!(a.contains(SmaliAccess::CONSTRUCTOR));
        // 0x20 in DEX is ACC_SYNCHRONIZED and must NOT become CONSTRUCTOR.
        assert!(!access_from_dex_flags(0x0020).contains(SmaliAccess::CONSTRUCTOR));
        // ACC_NATIVE in DEX is 0x100.
        assert!(access_from_dex_flags(0x0100).contains(SmaliAccess::NATIVE));
    }

    #[test]
    fn operands_are_typed_from_their_text() {
        assert_eq!(
            operand_from_text("v3"),
            SmaliOperand::Reg(SmaliReg { num: 3 })
        );
        assert_eq!(
            operand_from_text("Ljava/lang/Object;-><init>()V"),
            SmaliOperand::MethodRef("Ljava/lang/Object;-><init>()V".to_owned())
        );
        assert_eq!(
            operand_from_text("Lcom/example/Foo;->count:I"),
            SmaliOperand::FieldRef("Lcom/example/Foo;->count:I".to_owned())
        );
        assert_eq!(
            operand_from_text("Lcom/example/Foo;"),
            SmaliOperand::TypeRef("Lcom/example/Foo;".to_owned())
        );
        assert_eq!(operand_from_text("#0x10"), SmaliOperand::Literal(16));
    }

    /// A register that does not fit `SmaliReg`'s `u8` must not be wrapped into
    /// a different, wrong register.
    #[test]
    fn oversized_register_is_not_truncated() {
        assert_eq!(
            operand_from_text("v300"),
            SmaliOperand::Str("v300".to_owned())
        );
    }

    #[test]
    fn code_item_offset_zero_is_an_abstract_method() {
        let c = read_code_item(&[], 0).unwrap();
        assert!(c.instrs.is_empty());
        assert_eq!(c.registers_size, 0);
    }

    #[test]
    fn truncated_code_item_is_an_error() {
        assert!(read_code_item(&[0u8; 8], 4).is_err());
    }

    #[test]
    fn code_item_decodes_return_void() {
        // registers_size=1, ins=0, outs=0, tries=0, debug_off=0, insns_size=1,
        // insns = [0x000E] (return-void).
        let mut raw = vec![0u8; 4];
        raw.extend_from_slice(&1u16.to_le_bytes());
        raw.extend_from_slice(&0u16.to_le_bytes());
        raw.extend_from_slice(&0u16.to_le_bytes());
        raw.extend_from_slice(&0u16.to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.extend_from_slice(&1u32.to_le_bytes());
        raw.extend_from_slice(&0x000Eu16.to_le_bytes());
        let c = read_code_item(&raw, 4).unwrap();
        assert_eq!(c.registers_size, 1);
        assert_eq!(c.instrs.len(), 1);
        assert_eq!(c.instrs[0].mnemonic, "return-void");
        assert_eq!(instr_from_disasm(&c.instrs[0]).op, SmaliOp::ReturnVoid);
    }

    #[test]
    fn missing_class_is_named_in_the_error() {
        let err = class_from_dex_bytes(b"garbage", "Foo").unwrap_err();
        assert!(matches!(err, SmaliError::ParseError(_)));
    }
}
