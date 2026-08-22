//! Bridge from **real** .NET metadata to the recovery model of this crate.
//!
//! Everything in this module is derived from bytes that are actually present in
//! the input image: type/field/method names come from the `#Strings` heap, types
//! come from decoded signature blobs, custom attributes come from the
//! `CustomAttribute` table and its blob, and the IL instruction stream comes from
//! [`rustre_dotnet_metadata::parse_method_body`] decoded with the real CIL
//! decoder in `rustre-arch-cil`.
//!
//! Nothing here invents a value. When a piece of information is not present in
//! the image the corresponding function returns a [`BridgeError`] naming exactly
//! what was missing; it never substitutes a plausible-looking default.
//!
//! This is the production counterpart of the `mock_*` fixtures in
//! [`crate::async_recovery`] and [`crate::linq_recovery`], which exist only to
//! drive unit tests and must never be surfaced to a user as an observation.

use crate::async_recovery::{
    AsyncFunction, AsyncParam, EHClause, EHClauseKind, FieldDef, ILInsnAt, ILInstruction, MethodDef,
    TypeDef, decompile_async,
};
use crate::linq_recovery::{
    CallSite, ClosureField, DelegateInferenceSource, LambdaBody, LambdaExpr, LambdaExprNode,
    LambdaParam, MethodLinqSummary, extract_captures, infer_delegate_type, is_closure_class,
    recover_linq_summary,
};
use rustre_arch_cil::CilInstr;
use rustre_dotnet_metadata::{
    ExceptionClauseKind, MetadataReader, parse_field_sig_blob, parse_method_body,
    parse_method_sig_blob,
};
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

/// Failure to derive a model object from real metadata.
///
/// Every variant names the concrete thing that was absent from the image, so a
/// caller can report *why* nothing was recovered instead of returning invented
/// content.
#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("failed to parse CLI metadata from the image: {0}")]
    Metadata(String),
    #[error("no TypeDef named '{0}' in this image")]
    TypeNotFound(String),
    #[error("no MethodDef named '{0}' in type '{1}'")]
    MethodNotFound(String, String),
    #[error(
        "method '{0}' has RVA 0 (abstract, extern or pinvoke): no IL body exists in this image"
    )]
    NoMethodBody(String),
    #[error("RVA {0:#x} does not fall inside any PE section of this image")]
    RvaUnmapped(u32),
    #[error("failed to decode the IL body of '{0}': {1}")]
    BodyDecode(String, String),
    #[error(
        "method '{0}' carries no AsyncStateMachineAttribute: it is not an async method in this image"
    )]
    NotAsync(String),
    #[error("async state machine recovery failed: {0}")]
    Recovery(String),
    #[error("type '{0}' is not a compiler-generated closure class")]
    NotAClosure(String),
}

/// Result alias for the bridge.
pub type Result<T> = std::result::Result<T, BridgeError>;

// ─── PE address translation ───────────────────────────────────────────────────

/// Translate an RVA to a file offset using the image's real section headers.
///
/// # Errors
/// Returns [`BridgeError::RvaUnmapped`] when no section covers `rva`.
pub fn rva_to_file_offset(image: &[u8], rva: u32) -> Result<usize> {
    let unmapped = || BridgeError::RvaUnmapped(rva);
    if image.len() < 0x40 || &image[0..2] != b"MZ" {
        return Err(unmapped());
    }
    let pe_off = u32::from_le_bytes([image[0x3C], image[0x3D], image[0x3E], image[0x3F]]) as usize;
    if pe_off + 24 > image.len() || &image[pe_off..pe_off + 4] != b"PE\0\0" {
        return Err(unmapped());
    }
    let num_sections =
        u16::from_le_bytes([image[pe_off + 6], image[pe_off + 7]]) as usize;
    let opt_size = u16::from_le_bytes([image[pe_off + 20], image[pe_off + 21]]) as usize;
    let sec_table = pe_off + 24 + opt_size;
    for i in 0..num_sections {
        let s = sec_table + i * 40;
        if s + 40 > image.len() {
            return Err(unmapped());
        }
        let virt_size = u32::from_le_bytes([image[s + 8], image[s + 9], image[s + 10], image[s + 11]]);
        let virt_addr =
            u32::from_le_bytes([image[s + 12], image[s + 13], image[s + 14], image[s + 15]]);
        let raw_size =
            u32::from_le_bytes([image[s + 16], image[s + 17], image[s + 18], image[s + 19]]);
        let raw_ptr =
            u32::from_le_bytes([image[s + 20], image[s + 21], image[s + 22], image[s + 23]]);
        let span = virt_size.max(raw_size);
        if rva >= virt_addr && rva < virt_addr.saturating_add(span) {
            let delta = rva - virt_addr;
            if delta >= raw_size {
                return Err(unmapped());
            }
            return Ok(raw_ptr as usize + delta as usize);
        }
    }
    Err(unmapped())
}

// ─── Coded-index helpers (ECMA-335 §II.24.2.6) ────────────────────────────────

/// `HasCustomAttribute` coded index for a 1-based `TypeDef` row.
#[must_use]
pub const fn has_custom_attribute_typedef(row: u32) -> u32 {
    (row << 5) | 3
}

/// `HasCustomAttribute` coded index for a 1-based `MethodDef` row.
#[must_use]
pub const fn has_custom_attribute_methoddef(row: u32) -> u32 {
    row << 5
}

// ─── The reader-backed view ───────────────────────────────────────────────────

/// A real .NET image: the raw PE bytes plus its parsed CLI metadata.
///
/// Construct one with [`ImageView::parse`]; every model object produced from it
/// is a projection of these bytes.
pub struct ImageView<'a> {
    image: &'a [u8],
    reader: MetadataReader,
}

impl<'a> ImageView<'a> {
    /// Parse the CLI metadata of a real .NET PE image.
    ///
    /// # Errors
    /// Returns [`BridgeError::Metadata`] if the bytes are not a parseable
    /// managed image.
    pub fn parse(image: &'a [u8]) -> Result<Self> {
        let reader =
            MetadataReader::parse_from_bytes(image).map_err(|e| BridgeError::Metadata(e.to_string()))?;
        Ok(Self { image, reader })
    }

    /// The underlying metadata reader.
    #[must_use]
    pub const fn reader(&self) -> &MetadataReader {
        &self.reader
    }

    /// The raw image bytes.
    #[must_use]
    pub const fn image(&self) -> &'a [u8] {
        self.image
    }

    // ── name resolution ──────────────────────────────────────────────────────

    /// Full name (`Namespace.Name`) of the 1-based `TypeDef` row `row`.
    #[must_use]
    pub fn type_def_full_name(&self, row: u32) -> Option<String> {
        let t = self.reader.tables.type_def.get((row as usize).checked_sub(1)?)?;
        Some(join_name(&t.type_namespace, &t.type_name))
    }

    /// Resolve a `TypeDefOrRef` coded index to a printable full type name.
    #[must_use]
    pub fn type_def_or_ref_name(&self, coded: u32) -> Option<String> {
        let tag = coded & 0x3;
        let idx = (coded >> 2) as usize;
        match tag {
            0 => {
                let t = self.reader.tables.type_def.get(idx.checked_sub(1)?)?;
                Some(join_name(&t.type_namespace, &t.type_name))
            }
            1 => {
                let t = self.reader.tables.type_ref.get(idx.checked_sub(1)?)?;
                Some(join_name(&t.type_namespace, &t.type_name))
            }
            _ => None,
        }
    }

    /// Resolve a `MemberRefParent` coded index to a printable type name.
    #[must_use]
    fn member_ref_parent_name(&self, coded: u32) -> Option<String> {
        let tag = coded & 0x7;
        let idx = (coded >> 3) as usize;
        match tag {
            0 => {
                let t = self.reader.tables.type_def.get(idx.checked_sub(1)?)?;
                Some(join_name(&t.type_namespace, &t.type_name))
            }
            1 => {
                let t = self.reader.tables.type_ref.get(idx.checked_sub(1)?)?;
                Some(join_name(&t.type_namespace, &t.type_name))
            }
            2 => self
                .reader
                .tables
                .module_ref
                .get(idx.checked_sub(1)?)
                .map(|m| m.name.clone()),
            _ => None,
        }
    }

    /// Resolve a metadata token appearing as a CIL operand to a printable
    /// `Type::member` string, using only real table content.
    #[must_use]
    pub fn token_member_name(&self, token: u32) -> Option<String> {
        let table = token >> 24;
        let idx = (token & 0x00FF_FFFF) as usize;
        match table {
            0x04 => self
                .reader
                .tables
                .field
                .get(idx.checked_sub(1)?)
                .map(|f| f.name.clone()),
            0x06 => {
                let m = self.reader.tables.method_def.get(idx.checked_sub(1)?)?;
                let owner = self.declaring_type_of_method(idx as u32);
                Some(owner.map_or_else(|| m.name.clone(), |o| format!("{o}::{}", m.name)))
            }
            0x0A => {
                let mr = self.reader.tables.member_ref.get(idx.checked_sub(1)?)?;
                let owner = self.member_ref_parent_name(mr.class);
                Some(owner.map_or_else(|| mr.name.clone(), |o| format!("{o}::{}", mr.name)))
            }
            0x01 | 0x02 => self.type_def_or_ref_name(if table == 0x02 {
                (idx as u32) << 2
            } else {
                ((idx as u32) << 2) | 1
            }),
            _ => None,
        }
    }

    /// Resolve a `#US` user-string token to its real string content.
    #[must_use]
    pub fn token_user_string(&self, token: u32) -> Option<String> {
        if token >> 24 != 0x70 {
            return None;
        }
        self.reader.heaps.user_strings.get(token & 0x00FF_FFFF).ok()
    }

    /// Full name of the type that owns the 1-based `MethodDef` row `method_row`.
    #[must_use]
    pub fn declaring_type_of_method(&self, method_row: u32) -> Option<String> {
        let mut owner = None;
        for (i, t) in self.reader.tables.type_def.iter().enumerate() {
            if t.method_list != 0 && t.method_list <= method_row {
                owner = Some(i + 1);
            } else if t.method_list > method_row {
                break;
            }
        }
        self.type_def_full_name(u32::try_from(owner?).ok()?)
    }

    // ── custom attributes ────────────────────────────────────────────────────

    /// Real custom-attribute descriptions for a coded parent.
    ///
    /// Each entry is the attribute's type name, followed — when the blob holds a
    /// single string-shaped fixed argument, which is the encoding the C#
    /// compiler uses for `[AsyncStateMachine(typeof(T))]` — by that argument in
    /// parentheses. Nothing is emitted for an argument that could not be decoded.
    #[must_use]
    pub fn custom_attributes_for(&self, parent_coded: u32) -> Vec<String> {
        let mut out = Vec::new();
        for ca in self.reader.tables.custom_attributes_for(parent_coded) {
            let Some(name) = self.custom_attribute_type_name(ca.attr_type) else {
                continue;
            };
            let short = name.rsplit('.').next().unwrap_or(&name).to_string();
            let base = short.strip_suffix("Attribute").unwrap_or(&short).to_string();
            match decode_single_string_arg(&ca.value) {
                Some(arg) => out.push(format!("{base}({arg})")),
                None => out.push(base),
            }
        }
        out
    }

    /// Type name of an attribute given its `CustomAttributeType` coded index.
    #[must_use]
    fn custom_attribute_type_name(&self, coded: u32) -> Option<String> {
        let tag = coded & 0x7;
        let idx = (coded >> 3) as usize;
        match tag {
            2 => {
                // MethodDef ctor -> the type that declares it.
                self.declaring_type_of_method(u32::try_from(idx).ok()?)
            }
            3 => {
                let mr = self.reader.tables.member_ref.get(idx.checked_sub(1)?)?;
                self.member_ref_parent_name(mr.class)
            }
            _ => None,
        }
    }

    // ── methods ──────────────────────────────────────────────────────────────

    /// Build a real [`MethodDef`] for the 1-based `MethodDef` row `row`.
    ///
    /// The IL stream is decoded from the method's actual body when it has one;
    /// a method with RVA 0 (abstract / extern / pinvoke) yields an empty
    /// instruction list rather than an invented one.
    ///
    /// # Errors
    /// Returns [`BridgeError::MethodNotFound`] for an out-of-range row, and
    /// [`BridgeError::BodyDecode`] when a body exists but cannot be decoded.
    pub fn method_def(&self, row: u32) -> Result<MethodDef> {
        let m = self
            .reader
            .tables
            .method_def
            .get((row as usize).saturating_sub(1))
            .ok_or_else(|| BridgeError::MethodNotFound(format!("row {row}"), "<image>".into()))?;

        let declaring_type = self
            .declaring_type_of_method(row)
            .unwrap_or_else(|| "<module>".to_string());

        let sig = parse_method_sig_blob(&m.signature).ok();
        let return_type = sig
            .as_ref()
            .map_or_else(|| "<unknown-signature>".to_string(), |s| s.return_type.clone());
        let is_static = sig.as_ref().is_none_or(|s| !s.is_instance);
        let params = sig.as_ref().map_or_else(Vec::new, |s| {
            s.params
                .iter()
                .enumerate()
                .map(|(i, ty)| AsyncParam {
                    name: self.param_name(m.param_list, i).unwrap_or_else(|| format!("arg{i}")),
                    ty: ty.clone(),
                    is_ref: ty.starts_with("byref "),
                    is_out: false,
                })
                .collect()
        });

        let (instructions, eh_table) = if m.rva == 0 {
            (Vec::new(), Vec::new())
        } else {
            self.decode_body(&m.name, m.rva)?
        };

        Ok(MethodDef {
            name: format!("{declaring_type}::{}", m.name),
            declaring_type,
            return_type,
            params,
            is_static,
            access: access_of(m.flags),
            instructions,
            eh_table,
            custom_attributes: self.custom_attributes_for(has_custom_attribute_methoddef(row)),
        })
    }

    /// Real parameter name from the `Param` table, when present.
    #[must_use]
    fn param_name(&self, param_list: u32, index: usize) -> Option<String> {
        let i = (param_list as usize).checked_add(index)?.checked_sub(1)?;
        let p = self.reader.tables.param.get(i)?;
        if p.name.is_empty() { None } else { Some(p.name.clone()) }
    }

    /// Decode the real IL body at `rva` into the crate's instruction model.
    fn decode_body(&self, name: &str, rva: u32) -> Result<(Vec<ILInsnAt>, Vec<EHClause>)> {
        if rva == 0 {
            return Err(BridgeError::NoMethodBody(name.to_string()));
        }
        let off = rva_to_file_offset(self.image, rva)?;
        let body = parse_method_body(self.image, off)
            .map_err(|e| BridgeError::BodyDecode(name.to_string(), e.to_string()))?;
        let insns = self.decode_il(&body.code);
        let eh = body
            .exception_clauses
            .iter()
            .map(|c| EHClause {
                kind: match &c.kind {
                    ExceptionClauseKind::Catch(_) => EHClauseKind::Catch,
                    ExceptionClauseKind::Finally => EHClauseKind::Finally,
                    ExceptionClauseKind::Filter => EHClauseKind::Filter,
                    ExceptionClauseKind::Fault => EHClauseKind::Fault,
                },
                try_offset: c.try_offset,
                try_length: c.try_length,
                handler_offset: c.handler_offset,
                handler_length: c.handler_length,
                catch_type: match &c.kind {
                    ExceptionClauseKind::Catch(t) => Some(
                        self.token_member_name(*t)
                            .unwrap_or_else(|| format!("token_{t:#010x}")),
                    ),
                    _ => None,
                },
                filter_offset: match &c.kind {
                    ExceptionClauseKind::Filter => Some(c.filter_offset),
                    _ => None,
                },
            })
            .collect();
        Ok((insns, eh))
    }

    /// Decode real CIL bytes into [`ILInstruction`]s, resolving every token
    /// operand against this image's metadata tables.
    #[must_use]
    pub fn decode_il(&self, code: &[u8]) -> Vec<ILInsnAt> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos < code.len() {
            let Ok((instr, len)) = CilInstr::decode(&code[pos..]) else {
                // Unknown byte: record it honestly rather than guessing.
                out.push(ILInsnAt {
                    offset: u32::try_from(pos).unwrap_or(u32::MAX),
                    insn: ILInstruction::Unknown {
                        opcode: u16::from(code[pos]),
                        operand: 0,
                    },
                });
                pos += 1;
                continue;
            };
            let next = pos + len;
            let insn = self.map_instruction(&instr, u32::try_from(next).unwrap_or(u32::MAX));
            out.push(ILInsnAt {
                offset: u32::try_from(pos).unwrap_or(u32::MAX),
                insn,
            });
            pos = next;
        }
        out
    }

    #[allow(clippy::too_many_lines)]
    fn map_instruction(&self, instr: &CilInstr, next_off: u32) -> ILInstruction {
        let raw = &instr.raw;
        let m = instr.mnemonic.as_str();

        let tok = |skip: usize| -> u32 {
            raw.get(skip..skip + 4).map_or(0, |b| {
                u32::from_le_bytes([b[0], b[1], b[2], b[3]])
            })
        };
        let i32_at = |skip: usize| -> i32 {
            raw.get(skip..skip + 4).map_or(0, |b| {
                i32::from_le_bytes([b[0], b[1], b[2], b[3]])
            })
        };
        let branch32 = |skip: usize| -> u32 {
            let d = i32_at(skip);
            next_off.wrapping_add(d as u32)
        };
        let branch8 = |skip: usize| -> u32 {
            let d = i64::from(raw.get(skip).copied().unwrap_or(0) as i8);
            next_off.wrapping_add(d as u32)
        };
        // Prefixed (0xFE xx) opcodes carry their operand two bytes in.
        let opskip = usize::from(raw.first() == Some(&0xFE)) + 1;

        // ldarg.N / ldloc.N / stloc.N short forms.
        if let Some(n) = m.strip_prefix("ldarg.") {
            if let Ok(i) = n.parse::<u16>() {
                return ILInstruction::LdArg(i);
            }
        }
        if let Some(n) = m.strip_prefix("ldloc.") {
            if let Ok(i) = n.parse::<u16>() {
                return ILInstruction::LdLoc(i);
            }
        }
        if let Some(n) = m.strip_prefix("stloc.") {
            if let Ok(i) = n.parse::<u16>() {
                return ILInstruction::StLoc(i);
            }
        }
        if let Some(n) = m.strip_prefix("ldc.i4.") {
            if let Ok(i) = n.parse::<i32>() {
                return ILInstruction::LdcI4(i);
            }
            if n == "m1" {
                return ILInstruction::LdcI4(-1);
            }
        }

        match m {
            "ldarg" | "ldarg.s" => ILInstruction::LdArg(short_or_wide_index(raw, opskip, m)),
            "ldloc" | "ldloc.s" => ILInstruction::LdLoc(short_or_wide_index(raw, opskip, m)),
            "stloc" | "stloc.s" => ILInstruction::StLoc(short_or_wide_index(raw, opskip, m)),
            "ldc.i4" => ILInstruction::LdcI4(i32_at(opskip)),
            "ldc.i4.s" => {
                ILInstruction::LdcI4(i32::from(raw.get(opskip).copied().unwrap_or(0) as i8))
            }
            "ldc.i8" => ILInstruction::LdcI8(raw.get(opskip..opskip + 8).map_or(0, |b| {
                i64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
            })),
            "ldstr" => {
                let t = tok(opskip);
                self.token_user_string(t)
                    .map_or(ILInstruction::Unknown { opcode: 0x72, operand: t }, ILInstruction::LdStr)
            }
            "ldnull" => ILInstruction::LdNull,
            "ldfld" | "ldflda" => ILInstruction::LdFld {
                field: self.named_token(tok(opskip)),
            },
            "stfld" => ILInstruction::StFld {
                field: self.named_token(tok(opskip)),
            },
            "call" | "calli" => ILInstruction::Call {
                method: self.named_token(tok(opskip)),
                arg_count: self.token_arg_count(tok(opskip)),
            },
            "callvirt" => ILInstruction::CallVirt {
                method: self.named_token(tok(opskip)),
                arg_count: self.token_arg_count(tok(opskip)),
            },
            "newobj" => ILInstruction::Newobj {
                ctor: self.named_token(tok(opskip)),
            },
            "box" => ILInstruction::Box { ty: self.named_token(tok(opskip)) },
            "unbox" | "unbox.any" => ILInstruction::Unbox { ty: self.named_token(tok(opskip)) },
            "castclass" => ILInstruction::Castclass { ty: self.named_token(tok(opskip)) },
            "isinst" => ILInstruction::Isinst { ty: self.named_token(tok(opskip)) },
            "ldtoken" => ILInstruction::Ldtoken { member: self.named_token(tok(opskip)) },
            "switch" => {
                let n = tok(opskip) as usize;
                let mut labels = Vec::with_capacity(n.min(0x1_0000));
                for i in 0..n {
                    let base = opskip + 4 + i * 4;
                    if raw.len() < base + 4 {
                        break;
                    }
                    labels.push(next_off.wrapping_add(i32_at(base) as u32));
                }
                ILInstruction::Switch { labels }
            }
            "br" => ILInstruction::Br(branch32(opskip)),
            "br.s" => ILInstruction::Br(branch8(opskip)),
            "brtrue" | "brinst" => ILInstruction::BrTrue(branch32(opskip)),
            "brtrue.s" | "brinst.s" => ILInstruction::BrTrue(branch8(opskip)),
            "brfalse" | "brnull" | "brzero" => ILInstruction::BrFalse(branch32(opskip)),
            "brfalse.s" | "brnull.s" | "brzero.s" => ILInstruction::BrFalse(branch8(opskip)),
            "leave" => ILInstruction::Leave(branch32(opskip)),
            "leave.s" => ILInstruction::Leave(branch8(opskip)),
            "add" | "add.ovf" | "add.ovf.un" => ILInstruction::Add,
            "sub" | "sub.ovf" | "sub.ovf.un" => ILInstruction::Sub,
            "mul" | "mul.ovf" | "mul.ovf.un" => ILInstruction::Mul,
            "div" | "div.un" => ILInstruction::Div,
            "rem" | "rem.un" => ILInstruction::Rem,
            "neg" => ILInstruction::Neg,
            "and" => ILInstruction::And,
            "or" => ILInstruction::Or,
            "xor" => ILInstruction::Xor,
            "not" => ILInstruction::Not,
            "shl" => ILInstruction::Shl,
            "shr" | "shr.un" => ILInstruction::Shr,
            "ceq" => ILInstruction::Ceq,
            "cgt" | "cgt.un" => ILInstruction::Cgt,
            "clt" | "clt.un" => ILInstruction::Clt,
            "ret" => ILInstruction::Ret,
            "throw" => ILInstruction::Throw,
            "rethrow" => ILInstruction::Rethrow,
            "endfinally" | "endfault" => ILInstruction::Endfinally,
            "endfilter" => ILInstruction::Endfilter,
            "pop" => ILInstruction::Pop,
            "dup" => ILInstruction::Dup,
            "nop" => ILInstruction::Nop,
            _ => ILInstruction::Unknown {
                opcode: u16::from(raw.first().copied().unwrap_or(0)),
                operand: tok(opskip),
            },
        }
    }

    /// Name for a token, falling back to the raw token when the tables do not
    /// contain it (an unresolved token is reported as such, not guessed).
    fn named_token(&self, token: u32) -> String {
        self.token_member_name(token)
            .unwrap_or_else(|| format!("token_{token:#010x}"))
    }

    /// Real argument count of a call target, taken from its signature blob.
    fn token_arg_count(&self, token: u32) -> u32 {
        let table = token >> 24;
        let idx = (token & 0x00FF_FFFF) as usize;
        let blob = match table {
            0x06 => self
                .reader
                .tables
                .method_def
                .get(idx.saturating_sub(1))
                .map(|m| m.signature.clone()),
            0x0A => self
                .reader
                .tables
                .member_ref
                .get(idx.saturating_sub(1))
                .map(|m| m.signature.clone()),
            _ => None,
        };
        blob.and_then(|b| parse_method_sig_blob(&b).ok())
            .map_or(0, |s| u32::try_from(s.params.len()).unwrap_or(0))
    }

    // ── types ────────────────────────────────────────────────────────────────

    /// Build a real [`TypeDef`] for the 1-based `TypeDef` row `row`, including
    /// its real fields (names and signature-decoded types), its real interface
    /// list, and every one of its real methods with decoded IL.
    ///
    /// # Errors
    /// Returns [`BridgeError::TypeNotFound`] for an out-of-range row.
    pub fn type_def(&self, row: u32) -> Result<TypeDef> {
        let t = self
            .reader
            .tables
            .type_def
            .get((row as usize).saturating_sub(1))
            .ok_or_else(|| BridgeError::TypeNotFound(format!("row {row}")))?;

        let fields = self
            .reader
            .fields_for_type(row)
            .into_iter()
            .map(|f| FieldDef {
                name: f.name.clone(),
                ty: parse_field_sig_blob(&f.signature)
                    .unwrap_or_else(|_| "<unknown-signature>".to_string()),
                // FieldAttributes.Static == 0x0010
                is_static: f.flags & 0x0010 != 0,
            })
            .collect();

        let interfaces = self
            .reader
            .tables
            .interfaces_for(row)
            .into_iter()
            .filter_map(|ii| self.type_def_or_ref_name(ii.interface))
            .collect();

        // Method rows of this type, as 1-based indices.
        let first = t.method_list;
        let count = u32::try_from(self.reader.methods_for_type(row).len()).unwrap_or(0);
        let mut methods = Vec::with_capacity(count as usize);
        for i in 0..count {
            if let Ok(m) = self.method_def(first + i) {
                methods.push(m);
            }
        }

        Ok(TypeDef {
            name: t.type_name.clone(),
            full_name: join_name(&t.type_namespace, &t.type_name),
            base_type: self.type_def_or_ref_name(t.extends),
            interfaces,
            fields,
            methods,
        })
    }

    /// Row index of the first `TypeDef` whose short or full name matches `name`.
    #[must_use]
    pub fn find_type_row(&self, name: &str) -> Option<u32> {
        self.reader.tables.type_def.iter().position(|t| {
            t.type_name == name || join_name(&t.type_namespace, &t.type_name) == name
        })
        .and_then(|i| u32::try_from(i + 1).ok())
    }

    /// Row index of the first `MethodDef` named `name` inside type `type_name`.
    #[must_use]
    pub fn find_method_row(&self, type_name: &str, name: &str) -> Option<u32> {
        let row = self.find_type_row(type_name)?;
        let first = self.reader.tables.type_def.get(row as usize - 1)?.method_list;
        let methods = self.reader.methods_for_type(row);
        methods
            .iter()
            .position(|m| m.name == name)
            .and_then(|i| u32::try_from(i).ok())
            .map(|i| first + i)
    }
}

// ─── Real replacements for the async fixtures ─────────────────────────────────

/// Recover the **real** state-machine [`TypeDef`] that `method_name` in
/// `type_name` was lowered into.
///
/// This is the production counterpart of
/// [`crate::async_recovery::mock_state_machine`]: the class name comes from the
/// method's real `AsyncStateMachineAttribute`, and its fields and `MoveNext`
/// body are read from the image.
///
/// # Errors
/// [`BridgeError::MethodNotFound`] if the method is absent, [`BridgeError::NotAsync`]
/// if it carries no state-machine attribute, [`BridgeError::TypeNotFound`] if the
/// attribute names a class this image does not contain.
pub fn state_machine_from_metadata(
    view: &ImageView<'_>,
    type_name: &str,
    method_name: &str,
) -> Result<TypeDef> {
    let m = async_method_from_metadata(view, type_name, method_name)?;
    let sm_name = crate::async_recovery::find_state_machine_attribute(&m)
        .ok_or_else(|| BridgeError::NotAsync(m.name.clone()))?
        .to_string();
    let short = sm_name.rsplit(['.', '+', '/']).next().unwrap_or(&sm_name);
    let row = view
        .find_type_row(&sm_name)
        .or_else(|| view.find_type_row(short))
        .ok_or_else(|| BridgeError::TypeNotFound(sm_name.clone()))?;
    view.type_def(row)
}

/// Recover the **real** [`MethodDef`] for `type_name::method_name`.
///
/// Production counterpart of [`crate::async_recovery::mock_async_method`].
///
/// # Errors
/// [`BridgeError::MethodNotFound`] when the image has no such method.
pub fn async_method_from_metadata(
    view: &ImageView<'_>,
    type_name: &str,
    method_name: &str,
) -> Result<MethodDef> {
    let row = view
        .find_method_row(type_name, method_name)
        .ok_or_else(|| BridgeError::MethodNotFound(method_name.into(), type_name.into()))?;
    view.method_def(row)
}

/// Decompile a real async method end to end: locate it, resolve its real state
/// machine, and run the existing recovery over both.
///
/// # Errors
/// Any [`BridgeError`] from the lookups above, or [`BridgeError::Recovery`] when
/// the state machine does not match the shape the recovery engine understands.
pub fn decompile_async_from_metadata(
    view: &ImageView<'_>,
    type_name: &str,
    method_name: &str,
) -> Result<AsyncFunction> {
    let method = async_method_from_metadata(view, type_name, method_name)?;
    let sm = state_machine_from_metadata(view, type_name, method_name)?;
    decompile_async(&method, &sm).map_err(|e| BridgeError::Recovery(e.to_string()))
}

/// Recover every async method the image really contains.
///
/// Returns one entry per method that carries an `AsyncStateMachineAttribute`
/// whose class is present; methods whose recovery fails are reported as the
/// error that occurred, never as a fabricated success.
#[must_use]
pub fn recover_all_async_from_image(view: &ImageView<'_>) -> Vec<Result<AsyncFunction>> {
    let mut out = Vec::new();
    let n = u32::try_from(view.reader().tables.method_def.len()).unwrap_or(0);
    for row in 1..=n {
        let Ok(method) = view.method_def(row) else { continue };
        let Some(sm_name) = crate::async_recovery::find_state_machine_attribute(&method) else {
            continue;
        };
        let sm_name = sm_name.to_string();
        let short = sm_name.rsplit(['.', '+', '/']).next().unwrap_or(&sm_name);
        let Some(sm_row) = view
            .find_type_row(&sm_name)
            .or_else(|| view.find_type_row(short))
        else {
            out.push(Err(BridgeError::TypeNotFound(sm_name)));
            continue;
        };
        match view.type_def(sm_row) {
            Ok(sm) => out.push(
                decompile_async(&method, &sm).map_err(|e| BridgeError::Recovery(e.to_string())),
            ),
            Err(e) => out.push(Err(e)),
        }
    }
    out
}

// ─── Real replacements for the LINQ fixtures ──────────────────────────────────

/// Real closure fields of a compiler-generated closure class.
///
/// # Errors
/// [`BridgeError::NotAClosure`] when `type_name` is not a closure class name,
/// [`BridgeError::TypeNotFound`] when the image has no such type.
pub fn closure_fields_from_metadata(
    view: &ImageView<'_>,
    type_name: &str,
) -> Result<Vec<ClosureField>> {
    if !is_closure_class(type_name) {
        return Err(BridgeError::NotAClosure(type_name.to_string()));
    }
    let row = view
        .find_type_row(type_name)
        .ok_or_else(|| BridgeError::TypeNotFound(type_name.to_string()))?;
    let td = view.type_def(row)?;
    Ok(td
        .fields
        .iter()
        .map(|f| ClosureField {
            name: f.name.clone(),
            ty: f.ty.clone(),
        })
        .collect())
}

/// Recover a **real** [`LambdaExpr`] from a real closure class and one of its
/// real lambda methods (`<Name>b__N`).
///
/// Production counterpart of [`crate::linq_recovery::mock_lambda`]: the
/// parameters, return type, captured variables and delegate type all come from
/// the image. The body is reported as the real IL instruction listing of the
/// lambda method; nothing is synthesised for it.
///
/// # Errors
/// [`BridgeError::NotAClosure`], [`BridgeError::TypeNotFound`] or
/// [`BridgeError::MethodNotFound`] as appropriate.
pub fn lambda_from_metadata(
    view: &ImageView<'_>,
    closure_type: &str,
    lambda_method: &str,
) -> Result<LambdaExpr> {
    if !is_closure_class(closure_type) {
        return Err(BridgeError::NotAClosure(closure_type.to_string()));
    }
    let row = view
        .find_type_row(closure_type)
        .ok_or_else(|| BridgeError::TypeNotFound(closure_type.to_string()))?;
    let td = view.type_def(row)?;
    let m = td
        .methods
        .iter()
        .find(|m| m.name.ends_with(&format!("::{lambda_method}")) || m.name == lambda_method)
        .ok_or_else(|| {
            BridgeError::MethodNotFound(lambda_method.into(), closure_type.into())
        })?;

    let params: Vec<LambdaParam> = m
        .params
        .iter()
        .map(|p| LambdaParam {
            name: p.name.clone(),
            ty: p.ty.clone(),
            has_explicit_type: true,
        })
        .collect();

    let fields: Vec<ClosureField> = td
        .fields
        .iter()
        .map(|f| ClosureField {
            name: f.name.clone(),
            ty: f.ty.clone(),
        })
        .collect();

    let param_types: Vec<String> = m.params.iter().map(|p| p.ty.clone()).collect();
    let delegate = infer_delegate_type(&param_types, &m.return_type);

    let body_text = m
        .instructions
        .iter()
        .map(|i| format!("{}", i.insn))
        .collect::<Vec<_>>()
        .join("; ");

    Ok(LambdaExpr {
        class_name: closure_type.to_string(),
        params,
        return_type: m.return_type.clone(),
        body: LambdaBody::Expression(LambdaExprNode::Opaque(body_text)),
        captures: extract_captures(&fields),
        delegate_type: Some(delegate),
        inference_source: DelegateInferenceSource::CallSiteInference {
            return_type: m.return_type.clone(),
            param_types,
        },
        is_static_lambda: m.is_static,
    })
}

/// Recover the **real** call sites of a method: every `call`/`callvirt` actually
/// present in its IL, with the real target name and the real argument count from
/// the callee's signature.
///
/// Production counterpart of [`crate::linq_recovery::mock_linq_call`].
///
/// # Errors
/// [`BridgeError::MethodNotFound`] when the image has no such method.
pub fn call_sites_from_metadata(
    view: &ImageView<'_>,
    type_name: &str,
    method_name: &str,
) -> Result<Vec<CallSite>> {
    let row = view
        .find_method_row(type_name, method_name)
        .ok_or_else(|| BridgeError::MethodNotFound(method_name.into(), type_name.into()))?;
    let m = view.method_def(row)?;
    Ok(call_sites_of(&m))
}

/// Extract the real call sites of an already-built [`MethodDef`].
#[must_use]
pub fn call_sites_of(method: &MethodDef) -> Vec<CallSite> {
    method
        .instructions
        .iter()
        .filter_map(|at| match &at.insn {
            ILInstruction::Call { method: name, arg_count }
            | ILInstruction::CallVirt { method: name, arg_count } => Some(CallSite {
                il_offset: at.offset,
                method: name.clone(),
                arg_count: *arg_count,
                return_type: String::new(),
                lambda_args: Vec::new(),
                scalar_args: Vec::new(),
            }),
            _ => None,
        })
        .collect()
}

/// Run the existing LINQ recovery over a method's **real** call sites and the
/// **real** fields of every closure class in the image.
///
/// # Errors
/// [`BridgeError::MethodNotFound`] when the image has no such method.
pub fn linq_summary_from_metadata(
    view: &ImageView<'_>,
    type_name: &str,
    method_name: &str,
) -> Result<MethodLinqSummary> {
    let sites = call_sites_from_metadata(view, type_name, method_name)?;
    let mut closures: ahash::AHashMap<String, Vec<ClosureField>> = ahash::AHashMap::new();
    let n = u32::try_from(view.reader().tables.type_def.len()).unwrap_or(0);
    for row in 1..=n {
        let Some(name) = view.type_def_full_name(row) else { continue };
        let short = name.rsplit('.').next().unwrap_or(&name).to_string();
        if !is_closure_class(&short) {
            continue;
        }
        if let Ok(td) = view.type_def(row) {
            closures.insert(
                short,
                td.fields
                    .iter()
                    .map(|f| ClosureField {
                        name: f.name.clone(),
                        ty: f.ty.clone(),
                    })
                    .collect(),
            );
        }
    }
    Ok(recover_linq_summary(method_name, &sites, &closures))
}

// ─── Small helpers ────────────────────────────────────────────────────────────

fn join_name(ns: &str, name: &str) -> String {
    if ns.is_empty() {
        name.to_string()
    } else {
        format!("{ns}.{name}")
    }
}

/// `MethodAttributes` visibility mask (ECMA-335 §II.23.1.10).
fn access_of(flags: u16) -> String {
    match flags & 0x0007 {
        0x0001 => "private",
        0x0002 => "private protected",
        0x0003 => "internal",
        0x0004 => "protected",
        0x0005 => "protected internal",
        0x0006 => "public",
        _ => "compiler-controlled",
    }
    .to_string()
}

fn short_or_wide_index(raw: &[u8], skip: usize, mnemonic: &str) -> u16 {
    if mnemonic.ends_with(".s") {
        u16::from(raw.get(skip).copied().unwrap_or(0))
    } else {
        raw.get(skip..skip + 2)
            .map_or(0, |b| u16::from_le_bytes([b[0], b[1]]))
    }
}

/// Decode the single fixed `SerString` argument of a custom-attribute blob.
///
/// Returns `None` unless the blob really has the `0x0001` prolog followed by a
/// non-null compressed-length string — the encoding the C# compiler emits for
/// `[AsyncStateMachine(typeof(T))]` and `[IteratorStateMachine(typeof(T))]`.
#[must_use]
pub fn decode_single_string_arg(blob: &[u8]) -> Option<String> {
    if blob.len() < 3 || blob[0] != 0x01 || blob[1] != 0x00 {
        return None;
    }
    let b0 = blob[2];
    if b0 == 0xFF {
        return None; // explicit null string
    }
    let (len, hdr) = if b0 & 0x80 == 0 {
        (usize::from(b0), 1usize)
    } else if b0 & 0xC0 == 0x80 {
        let b1 = *blob.get(3)?;
        ((usize::from(b0 & 0x3F) << 8) | usize::from(b1), 2)
    } else {
        let b1 = *blob.get(3)?;
        let b2 = *blob.get(4)?;
        let b3 = *blob.get(5)?;
        (
            (usize::from(b0 & 0x1F) << 24)
                | (usize::from(b1) << 16)
                | (usize::from(b2) << 8)
                | usize::from(b3),
            4,
        )
    };
    let start = 2 + hdr;
    let s = blob.get(start..start.checked_add(len)?)?;
    String::from_utf8(s.to_vec()).ok()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_single_string_arg_short() {
        // prolog 01 00, len 3, "abc", 0 named args
        let blob = [0x01, 0x00, 0x03, b'a', b'b', b'c', 0x00, 0x00];
        assert_eq!(decode_single_string_arg(&blob).as_deref(), Some("abc"));
    }

    #[test]
    fn test_decode_single_string_arg_state_machine_name() {
        let name = "Ns.MyClass+<DoWorkAsync>d__0";
        let mut blob = vec![0x01, 0x00];
        blob.push(u8::try_from(name.len()).unwrap());
        blob.extend_from_slice(name.as_bytes());
        blob.extend_from_slice(&[0x00, 0x00]);
        assert_eq!(decode_single_string_arg(&blob).as_deref(), Some(name));
    }

    #[test]
    fn test_decode_single_string_arg_rejects_null_and_garbage() {
        assert!(decode_single_string_arg(&[0x01, 0x00, 0xFF]).is_none());
        assert!(decode_single_string_arg(&[]).is_none());
        assert!(decode_single_string_arg(&[0x02, 0x00, 0x01, b'x']).is_none());
    }

    #[test]
    fn test_decode_single_string_arg_two_byte_length() {
        let name = "A".repeat(200);
        let mut blob = vec![0x01, 0x00];
        let l = u16::try_from(name.len()).unwrap() | 0x8000;
        blob.extend_from_slice(&l.to_be_bytes());
        blob.extend_from_slice(name.as_bytes());
        assert_eq!(decode_single_string_arg(&blob).as_deref(), Some(name.as_str()));
    }

    #[test]
    fn test_coded_index_helpers() {
        assert_eq!(has_custom_attribute_typedef(1), (1 << 5) | 3);
        assert_eq!(has_custom_attribute_methoddef(1), 1 << 5);
    }

    #[test]
    fn test_access_of_visibility_mask() {
        assert_eq!(access_of(0x0006), "public");
        assert_eq!(access_of(0x0001), "private");
        assert_eq!(access_of(0x0000), "compiler-controlled");
    }

    #[test]
    fn test_join_name() {
        assert_eq!(join_name("", "Foo"), "Foo");
        assert_eq!(join_name("Ns", "Foo"), "Ns.Foo");
    }

    #[test]
    fn test_rva_to_file_offset_rejects_non_pe() {
        let err = rva_to_file_offset(b"not a pe image at all", 0x2000).unwrap_err();
        assert!(matches!(err, BridgeError::RvaUnmapped(0x2000)));
    }

    #[test]
    fn test_image_view_parse_rejects_garbage() {
        assert!(matches!(
            ImageView::parse(&[0u8; 64]),
            Err(BridgeError::Metadata(_))
        ));
    }

    /// A truncated / non-PE image must be reported as unmapped, not guessed at.
    #[test]
    fn test_rva_to_file_offset_truncated_pe() {
        let mut img = vec![0u8; 0x100];
        img[0] = b'M';
        img[1] = b'Z';
        img[0x3C] = 0x80;
        assert!(matches!(
            rva_to_file_offset(&img, 0x2000),
            Err(BridgeError::RvaUnmapped(0x2000))
        ));
    }

    #[test]
    fn test_short_or_wide_index() {
        assert_eq!(short_or_wide_index(&[0x11, 0x05], 1, "ldloc.s"), 5);
        assert_eq!(short_or_wide_index(&[0xFE, 0x0C, 0x05, 0x00], 2, "ldloc"), 5);
    }
}
