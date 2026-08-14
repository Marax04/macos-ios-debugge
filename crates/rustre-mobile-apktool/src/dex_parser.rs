use serde::{Serialize, Deserialize};
use anyhow::{Result, bail};

// ── DEX file format constants ────────────────────────────────────────────────

const DEX_MAGIC: &[u8; 4] = b"dex\n";
const CDEX_MAGIC: &[u8; 4] = b"cdex";
const _ENDIAN_CONSTANT: u32 = 0x1234_5678;
const _REVERSE_ENDIAN_CONSTANT: u32 = 0x7856_3412;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DexVersion { V035 = 35, V037 = 37, V038 = 38, V039 = 39, V040 = 40 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexHeader {
    pub magic: [u8; 8],
    pub checksum: u32,
    pub sha1: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_off: u32,
    pub map_off: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexStringId { pub string_data_off: u32 }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexTypeId { pub descriptor_idx: u32 }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexProtoId {
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub parameters_off: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexFieldId {
    pub class_idx: u16,
    pub type_idx: u16,
    pub name_idx: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexMethodId {
    pub class_idx: u16,
    pub proto_idx: u16,
    pub name_idx: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexClassDef {
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: u32,
    pub interfaces_off: u32,
    pub source_file_idx: u32,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexClassData {
    pub static_fields: Vec<DexEncodedField>,
    pub instance_fields: Vec<DexEncodedField>,
    pub direct_methods: Vec<DexEncodedMethod>,
    pub virtual_methods: Vec<DexEncodedMethod>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexEncodedField {
    pub field_idx_diff: u32,
    pub access_flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexEncodedMethod {
    pub method_idx_diff: u32,
    pub access_flags: u32,
    pub code_off: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexCodeItem {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub tries_size: u16,
    pub debug_info_off: u32,
    pub insns_size: u32,
    pub insns: Vec<u16>,
    pub tries: Vec<DexTryItem>,
    pub handlers: Vec<DexCatchHandler>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexTryItem {
    pub start_addr: u32,
    pub insn_count: u16,
    pub handler_off: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexCatchHandler {
    pub handlers: Vec<(u32, u32)>, // (type_idx, addr)
    pub catch_all_addr: Option<u32>,
}

// ── Dalvik opcode set (simplified) ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DalvikInsn {
    pub offset: usize,
    pub opcode: u16,
    pub mnemonic: String,
    pub operands: String,
    pub raw_words: Vec<u16>,
    pub length: usize,
}

#[must_use] 
pub fn disassemble_dalvik(insns: &[u16]) -> Vec<DalvikInsn> {
    let mut result = Vec::new();
    let mut pc = 0usize;
    while pc < insns.len() {
        let raw = insns[pc];
        let op = (raw & 0xFF) as u8;
        let (mnemonic, length, operands) = decode_dalvik_op(op, &insns[pc..]);
        let raw_words = insns[pc..pc.saturating_add(length).min(insns.len())].to_vec();
        result.push(DalvikInsn { offset: pc * 2, opcode: u16::from(op), mnemonic, operands, raw_words, length });
        pc += length.max(1);
    }
    result
}

fn decode_dalvik_op(op: u8, words: &[u16]) -> (String, usize, String) {
    let w0 = words.first().copied().unwrap_or(0);
    let aa = u8::try_from(w0 >> 8).unwrap_or(u8::MAX);
    let a = aa & 0x0F;
    let b = u8::try_from(w0 >> 12).unwrap_or(0) & 0x0F;

    let w1 = words.get(1).copied().unwrap_or(0);
    let bbbb = w1;
    let cccc = words.get(2).copied().unwrap_or(0);

    match op {
        0x00 => ("nop".into(), 1, String::new()),
        0x01 => ("move".into(), 1, format!("v{a}, v{b}")),
        0x02 => ("move/from16".into(), 2, format!("v{aa:#02x}, v{bbbb:#04x}")),
        0x03 => ("move/16".into(), 3, format!("v{bbbb:#04x}, v{cccc:#04x}")),
        0x04 => ("move-wide".into(), 1, format!("v{a}, v{b}")),
        0x05 => ("move-wide/from16".into(), 2, format!("v{aa:#02x}, v{bbbb:#04x}")),
        0x07 => ("move-object".into(), 1, format!("v{a}, v{b}")),
        0x08 => ("move-object/from16".into(), 2, format!("v{aa:#02x}, v{bbbb:#04x}")),
        0x0A => ("move-result".into(), 1, format!("v{aa}")),
        0x0B => ("move-result-wide".into(), 1, format!("v{aa}")),
        0x0C => ("move-result-object".into(), 1, format!("v{aa}")),
        0x0D => ("move-exception".into(), 1, format!("v{aa}")),
        0x0E => ("return-void".into(), 1, String::new()),
        0x0F => ("return".into(), 1, format!("v{aa}")),
        0x10 => ("return-wide".into(), 1, format!("v{aa}")),
        0x11 => ("return-object".into(), 1, format!("v{aa}")),
        0x12 => ("const/4".into(), 1, format!("v{}, #{}", a, b.cast_signed() >> 4)),
        0x13 => ("const/16".into(), 2, format!("v{:#02x}, #{}", aa, bbbb.cast_signed())),
        0x14 => {
            let val = u32::from(w1) | (u32::from(cccc) << 16);
            ("const".into(), 3, format!("v{aa:#02x}, #{val:#010x}"))
        }
        0x15 => ("const/high16".into(), 2, format!("v{aa:#02x}, #{bbbb:#04x}0000")),
        0x1A => ("const-string".into(), 2, format!("v{aa:#02x}, string@{bbbb:#04x}")),
        0x1B => {
            let idx = u32::from(w1) | (u32::from(cccc) << 16);
            ("const-string/jumbo".into(), 3, format!("v{aa:#02x}, string@{idx:#08x}"))
        }
        0x1C => ("const-class".into(), 2, format!("v{aa:#02x}, type@{bbbb:#04x}")),
        0x1D => ("monitor-enter".into(), 1, format!("v{aa}")),
        0x1E => ("monitor-exit".into(), 1, format!("v{aa}")),
        0x1F => ("check-cast".into(), 2, format!("v{aa:#02x}, type@{bbbb:#04x}")),
        0x20 => ("instance-of".into(), 2, format!("v{a}, v{b}, type@{bbbb:#04x}")),
        0x21 => ("array-length".into(), 1, format!("v{a}, v{b}")),
        0x22 => ("new-instance".into(), 2, format!("v{aa:#02x}, type@{bbbb:#04x}")),
        0x23 => ("new-array".into(), 2, format!("v{a}, v{b}, type@{bbbb:#04x}")),
        0x28 => ("goto".into(), 1, format!("+{}", aa.cast_signed())),
        0x29 => ("goto/16".into(), 2, format!("+{}", bbbb.cast_signed())),
        0x2A => {
            let off = u32::from(w1) | (u32::from(cccc) << 16);
            ("goto/32".into(), 3, format!("+{off:#08x}"))
        }
        0x32 => ("if-eq".into(), 2, format!("v{}, v{}, +{}", a, b, bbbb.cast_signed())),
        0x33 => ("if-ne".into(), 2, format!("v{}, v{}, +{}", a, b, bbbb.cast_signed())),
        0x34 => ("if-lt".into(), 2, format!("v{}, v{}, +{}", a, b, bbbb.cast_signed())),
        0x35 => ("if-ge".into(), 2, format!("v{}, v{}, +{}", a, b, bbbb.cast_signed())),
        0x36 => ("if-gt".into(), 2, format!("v{}, v{}, +{}", a, b, bbbb.cast_signed())),
        0x37 => ("if-le".into(), 2, format!("v{}, v{}, +{}", a, b, bbbb.cast_signed())),
        0x38 => ("if-eqz".into(), 2, format!("v{:#02x}, +{}", aa, bbbb.cast_signed())),
        0x39 => ("if-nez".into(), 2, format!("v{:#02x}, +{}", aa, bbbb.cast_signed())),
        0x3A => ("if-ltz".into(), 2, format!("v{:#02x}, +{}", aa, bbbb.cast_signed())),
        0x3B => ("if-gez".into(), 2, format!("v{:#02x}, +{}", aa, bbbb.cast_signed())),
        0x3C => ("if-gtz".into(), 2, format!("v{:#02x}, +{}", aa, bbbb.cast_signed())),
        0x3D => ("if-lez".into(), 2, format!("v{:#02x}, +{}", aa, bbbb.cast_signed())),
        0x44 => ("aget".into(), 2, format!("v{}, v{:#02x}, v{:#04x}", aa, u8::try_from(bbbb & 0xff).unwrap_or(u8::MAX), u8::try_from(cccc & 0xff).unwrap_or(u8::MAX))),
        0x4B => ("aput".into(), 2, format!("v{}, v{:#02x}, v{:#04x}", aa, u8::try_from(bbbb & 0xff).unwrap_or(u8::MAX), u8::try_from(cccc & 0xff).unwrap_or(u8::MAX))),
        0x52 => ("iget".into(), 2, format!("v{a}, v{b}, field@{bbbb:#04x}")),
        0x59 => ("iput".into(), 2, format!("v{a}, v{b}, field@{bbbb:#04x}")),
        0x60 => ("sget".into(), 2, format!("v{aa:#02x}, field@{bbbb:#04x}")),
        0x67 => ("sput".into(), 2, format!("v{aa:#02x}, field@{bbbb:#04x}")),
        0x6E => {
            let vcount = u8::try_from(w0 >> 12).unwrap_or(0);
            ("invoke-virtual".into(), 3, format!("{{{vcount} args}}, method@{bbbb:#04x}"))
        }
        0x6F => {
            let vcount = u8::try_from(w0 >> 12).unwrap_or(0);
            ("invoke-super".into(), 3, format!("{{{vcount} args}}, method@{bbbb:#04x}"))
        }
        0x70 => {
            let vcount = u8::try_from(w0 >> 12).unwrap_or(0);
            ("invoke-direct".into(), 3, format!("{{{vcount} args}}, method@{bbbb:#04x}"))
        }
        0x71 => {
            let vcount = u8::try_from(w0 >> 12).unwrap_or(0);
            ("invoke-static".into(), 3, format!("{{{vcount} args}}, method@{bbbb:#04x}"))
        }
        0x72 => {
            let vcount = u8::try_from(w0 >> 12).unwrap_or(0);
            ("invoke-interface".into(), 3, format!("{{{vcount} args}}, method@{bbbb:#04x}"))
        }
        0x74 => ("invoke-virtual/range".into(), 3, format!("{{v{}..v{}}}, method@{:#04x}", cccc, cccc.saturating_add(bbbb).saturating_sub(1), bbbb)),
        0x78 => ("invoke-interface/range".into(), 3, format!("{{v{}..v{}}}, method@{:#04x}", cccc, cccc.saturating_add(bbbb).saturating_sub(1), bbbb)),
        0x90 => ("add-int".into(), 2, format!("v{}, v{:#02x}, v{:#04x}", aa, u8::try_from(bbbb & 0xff).unwrap_or(u8::MAX), u8::try_from(cccc & 0xff).unwrap_or(u8::MAX))),
        0x91 => ("sub-int".into(), 2, format!("v{}, v{:#02x}, v{:#04x}", aa, u8::try_from(bbbb & 0xff).unwrap_or(u8::MAX), u8::try_from(cccc & 0xff).unwrap_or(u8::MAX))),
        0x92 => ("mul-int".into(), 2, format!("v{}, v{:#02x}, v{:#04x}", aa, u8::try_from(bbbb & 0xff).unwrap_or(u8::MAX), u8::try_from(cccc & 0xff).unwrap_or(u8::MAX))),
        0x93 => ("div-int".into(), 2, format!("v{}, v{:#02x}, v{:#04x}", aa, u8::try_from(bbbb & 0xff).unwrap_or(u8::MAX), u8::try_from(cccc & 0xff).unwrap_or(u8::MAX))),
        0x94 => ("rem-int".into(), 2, format!("v{}, v{:#02x}, v{:#04x}", aa, u8::try_from(bbbb & 0xff).unwrap_or(u8::MAX), u8::try_from(cccc & 0xff).unwrap_or(u8::MAX))),
        0x95 => ("and-int".into(), 2, format!("v{}, v{:#02x}, v{:#04x}", aa, u8::try_from(bbbb & 0xff).unwrap_or(u8::MAX), u8::try_from(cccc & 0xff).unwrap_or(u8::MAX))),
        0x96 => ("or-int".into(), 2, format!("v{}, v{:#02x}, v{:#04x}", aa, u8::try_from(bbbb & 0xff).unwrap_or(u8::MAX), u8::try_from(cccc & 0xff).unwrap_or(u8::MAX))),
        0x97 => ("xor-int".into(), 2, format!("v{}, v{:#02x}, v{:#04x}", aa, u8::try_from(bbbb & 0xff).unwrap_or(u8::MAX), u8::try_from(cccc & 0xff).unwrap_or(u8::MAX))),
        0x98 => ("shl-int".into(), 2, format!("v{}, v{:#02x}, v{:#04x}", aa, u8::try_from(bbbb & 0xff).unwrap_or(u8::MAX), u8::try_from(cccc & 0xff).unwrap_or(u8::MAX))),
        0x99 => ("shr-int".into(), 2, format!("v{}, v{:#02x}, v{:#04x}", aa, u8::try_from(bbbb & 0xff).unwrap_or(u8::MAX), u8::try_from(cccc & 0xff).unwrap_or(u8::MAX))),
        0x9A => ("ushr-int".into(), 2, format!("v{}, v{:#02x}, v{:#04x}", aa, u8::try_from(bbbb & 0xff).unwrap_or(u8::MAX), u8::try_from(cccc & 0xff).unwrap_or(u8::MAX))),
        0xD0 => ("add-int/lit16".into(), 2, format!("v{}, v{}, #{}", a, b, bbbb.cast_signed())),
        0xD8 => ("add-int/lit8".into(), 2, format!("v{:#02x}, v{:#02x}, #{}", aa, u8::try_from(bbbb & 0xff).unwrap_or(u8::MAX), u8::try_from(bbbb >> 8).unwrap_or(u8::MAX).cast_signed())),
        _ => (format!("{op:#04x}"), 1, format!("aa={aa:#02x}")),
    }
}

// ── DEX parser ────────────────────────────────────────────────────────────────

pub struct DexParser {
    data: Vec<u8>,
    pos: usize,
}

impl DexParser {
    #[must_use] 
    pub const fn new(data: Vec<u8>) -> Self { Self { data, pos: 0 } }

    /// Load a DEX file from disk.
    ///
    /// # Errors
    /// Returns an error when the file cannot be read.
    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        Ok(Self::new(data))
    }

    fn read_u8(&mut self) -> Result<u8> {
        let b = *self.data.get(self.pos).ok_or_else(|| anyhow::anyhow!("EOF"))?;
        self.pos += 1;
        Ok(b)
    }
    fn read_u16(&mut self) -> Result<u16> {
        if self.pos + 2 > self.data.len() {
            return Err(anyhow::anyhow!("EOF reading u16 at pos {}", self.pos));
        }
        let v = u16::from_le_bytes(self.data[self.pos..self.pos+2].try_into()?);
        self.pos += 2;
        Ok(v)
    }
    fn read_u32(&mut self) -> Result<u32> {
        if self.pos + 4 > self.data.len() {
            return Err(anyhow::anyhow!("EOF reading u32 at pos {}", self.pos));
        }
        let v = u32::from_le_bytes(self.data[self.pos..self.pos+4].try_into()?);
        self.pos += 4;
        Ok(v)
    }
    fn read_uleb128(&mut self) -> Result<u32> {
        let mut result = 0u32;
        let mut shift = 0u32;
        loop {
            if shift > 28 {
                return Err(anyhow::anyhow!("ULEB128 overflow: too many continuation bytes"));
            }
            let byte = self.read_u8()?;
            result |= u32::from(byte & 0x7F) << shift;
            shift += 7;
            if byte & 0x80 == 0 { return Ok(result); }
        }
    }
    fn read_sleb128(&mut self) -> Result<i32> {
        let mut result = 0i32;
        let mut shift = 0u32;
        let mut byte;
        loop {
            if shift > 28 {
                return Err(anyhow::anyhow!("SLEB128 overflow: too many continuation bytes"));
            }
            byte = self.read_u8()?;
            result |= i32::from(byte & 0x7F) << shift;
            shift += 7;
            if byte & 0x80 == 0 { break; }
        }
        if shift < 32 && (byte & 0x40 != 0) {
            result |= !0 << shift;
        }
        Ok(result)
    }
    const fn seek(&mut self, off: u32) { self.pos = off as usize; }
    fn _at(&self, off: u32) -> &[u8] {
        let idx = off as usize;
        if idx < self.data.len() { &self.data[idx..] } else { &[] }
    }

    #[must_use] 
    pub fn check_magic(&self) -> bool {
        self.data.starts_with(DEX_MAGIC) || self.data.starts_with(CDEX_MAGIC)
    }

    /// Parse the DEX header from the current data buffer.
    ///
    /// # Errors
    /// Returns an error when the buffer is too short or any header field cannot be read.
    pub fn parse_header(&mut self) -> Result<DexHeader> {
        if self.data.len() < 8 {
            bail!("DEX file too short to contain header magic");
        }
        self.pos = 0;
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&self.data[0..8]);
        self.pos = 8;
        let checksum = self.read_u32()?;
        if self.pos + 20 > self.data.len() {
            bail!("DEX file too short to read SHA-1 (need {} bytes, have {})", self.pos + 20, self.data.len());
        }
        let mut sha1 = [0u8; 20];
        sha1.copy_from_slice(&self.data[self.pos..self.pos + 20]);
        self.pos += 20;
        Ok(DexHeader {
            magic, checksum, sha1,
            file_size: self.read_u32()?,
            header_size: self.read_u32()?,
            endian_tag: self.read_u32()?,
            link_size: self.read_u32()?,
            link_off: self.read_u32()?,
            map_off: self.read_u32()?,
            string_ids_size: self.read_u32()?,
            string_ids_off: self.read_u32()?,
            type_ids_size: self.read_u32()?,
            type_ids_off: self.read_u32()?,
            proto_ids_size: self.read_u32()?,
            proto_ids_off: self.read_u32()?,
            field_ids_size: self.read_u32()?,
            field_ids_off: self.read_u32()?,
            method_ids_size: self.read_u32()?,
            method_ids_off: self.read_u32()?,
            class_defs_size: self.read_u32()?,
            class_defs_off: self.read_u32()?,
            data_size: self.read_u32()?,
            data_off: self.read_u32()?,
        })
    }

    #[must_use] 
    pub fn read_string(&self, string_ids_off: u32, idx: u32) -> String {
        let Some(id_off) = string_ids_off.checked_add(idx.saturating_mul(4)) else { return String::new() };
        if id_off as usize + 4 > self.data.len() { return String::new(); }
        let data_off = u32::from_le_bytes(self.data[id_off as usize..id_off as usize + 4].try_into().unwrap_or([0;4]));
        if data_off as usize >= self.data.len() { return String::new(); }
        // Read ULEB128 length, then UTF-8 string
        let mut pos = data_off as usize;
        let mut len = 0usize;
        let mut shift = 0;
        loop {
            if pos >= self.data.len() { return String::new(); }
            let b = self.data[pos];
            pos += 1;
            len |= ((b & 0x7F) as usize) << shift;
            shift += 7;
            if b & 0x80 == 0 { break; }
        }
        let bytes = &self.data[pos..pos.saturating_add(len).min(self.data.len())];
        String::from_utf8_lossy(bytes).to_string()
    }

    /// Parse a single `class_def_item` at the given offset.
    ///
    /// # Errors
    /// Returns an error when any of the constituent u32 fields cannot be read.
    pub fn parse_class_def(&mut self, off: u32) -> Result<DexClassDef> {
        self.seek(off);
        Ok(DexClassDef {
            class_idx: self.read_u32()?,
            access_flags: self.read_u32()?,
            superclass_idx: self.read_u32()?,
            interfaces_off: self.read_u32()?,
            source_file_idx: self.read_u32()?,
            annotations_off: self.read_u32()?,
            class_data_off: self.read_u32()?,
            static_values_off: self.read_u32()?,
        })
    }

    /// Parse a `class_data_item` at the given offset.
    ///
    /// # Errors
    /// Returns an error when item counts exceed the safety limit or any encoded field/method cannot be read.
    pub fn parse_class_data(&mut self, off: u32) -> Result<DexClassData> {
        const MAX_ITEMS: usize = 1_000_000;
        self.seek(off);
        let static_fields_size = self.read_uleb128()? as usize;
        let instance_fields_size = self.read_uleb128()? as usize;
        let direct_methods_size = self.read_uleb128()? as usize;
        let virtual_methods_size = self.read_uleb128()? as usize;
        for (name, count) in [
            ("static_fields", static_fields_size),
            ("instance_fields", instance_fields_size),
            ("direct_methods", direct_methods_size),
            ("virtual_methods", virtual_methods_size),
        ] {
            if count > MAX_ITEMS {
                bail!("class_data {name} count {count} exceeds limit {MAX_ITEMS}");
            }
        }

        let mut static_fields = Vec::with_capacity(static_fields_size);
        for _ in 0..static_fields_size {
            static_fields.push(DexEncodedField {
                field_idx_diff: self.read_uleb128()?,
                access_flags: self.read_uleb128()?,
            });
        }
        let mut instance_fields = Vec::with_capacity(instance_fields_size);
        for _ in 0..instance_fields_size {
            instance_fields.push(DexEncodedField {
                field_idx_diff: self.read_uleb128()?,
                access_flags: self.read_uleb128()?,
            });
        }
        let mut direct_methods = Vec::with_capacity(direct_methods_size);
        for _ in 0..direct_methods_size {
            direct_methods.push(DexEncodedMethod {
                method_idx_diff: self.read_uleb128()?,
                access_flags: self.read_uleb128()?,
                code_off: self.read_uleb128()?,
            });
        }
        let mut virtual_methods = Vec::with_capacity(virtual_methods_size);
        for _ in 0..virtual_methods_size {
            virtual_methods.push(DexEncodedMethod {
                method_idx_diff: self.read_uleb128()?,
                access_flags: self.read_uleb128()?,
                code_off: self.read_uleb128()?,
            });
        }
        Ok(DexClassData { static_fields, instance_fields, direct_methods, virtual_methods })
    }

    /// Parse a `code_item` at the given offset.
    ///
    /// # Errors
    /// Returns an error when `insns_size` exceeds remaining buffer capacity or any field cannot be read.
    pub fn parse_code_item(&mut self, off: u32) -> Result<DexCodeItem> {
        self.seek(off);
        let registers_size = self.read_u16()?;
        let ins_size = self.read_u16()?;
        let outs_size = self.read_u16()?;
        let tries_size = self.read_u16()?;
        let debug_info_off = self.read_u32()?;
        let insns_size = self.read_u32()?;
        // Each instruction word is 2 bytes; cap against remaining buffer to avoid OOM.
        let remaining_words = (self.data.len().saturating_sub(self.pos)) / 2;
        if insns_size as usize > remaining_words {
            bail!("insns_size {insns_size} exceeds remaining buffer capacity {remaining_words}");
        }
        let mut insns = Vec::with_capacity(insns_size as usize);
        for _ in 0..insns_size {
            insns.push(self.read_u16()?);
        }
        // Pad to 4-byte alignment if tries follow and insns_size is odd
        if tries_size > 0 && insns_size % 2 != 0 {
            self.read_u16()?;
        }
        let mut tries = Vec::new();
        let mut handlers = Vec::new();
        if tries_size > 0 {
            // Read try item array: each is 8 bytes (u32 start_addr, u16 insn_count, u16 handler_off)
            for _ in 0..tries_size {
                let start_addr = self.read_u32()?;
                let insn_count = self.read_u16()?;
                let handler_off = self.read_u16()?;
                tries.push(DexTryItem { start_addr, insn_count, handler_off });
            }
            // Read encoded catch handler list
            let handler_count = self.read_sleb128()?;
            let abs_handler_count = handler_count.unsigned_abs() as usize;
            for _ in 0..abs_handler_count {
                let size = self.read_sleb128()?;
                let abs_size = size.unsigned_abs() as usize;
                let mut type_addr_pairs = Vec::new();
                for _ in 0..abs_size {
                    let type_idx = self.read_uleb128()?;
                    let addr = self.read_uleb128()?;
                    type_addr_pairs.push((type_idx, addr));
                }
                let catch_all_addr = if size <= 0 {
                    Some(self.read_uleb128()?)
                } else {
                    None
                };
                handlers.push(DexCatchHandler { handlers: type_addr_pairs, catch_all_addr });
            }
        }
        Ok(DexCodeItem { registers_size, ins_size, outs_size, tries_size, debug_info_off, insns_size, insns, tries, handlers })
    }
}

pub struct DexFile {
    pub header: DexHeader,
    pub strings: Vec<String>,
    pub types: Vec<String>,
    pub methods: Vec<DexMethodEntry>,
    pub classes: Vec<DexClassEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexMethodEntry {
    pub class_name: String,
    pub method_name: String,
    pub proto: String,
    pub access_flags: u32,
    pub instructions: Vec<DalvikInsn>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexClassEntry {
    pub name: String,
    pub superclass: String,
    pub access_flags: u32,
    pub source_file: Option<String>,
    pub methods: Vec<String>,
    pub fields: Vec<String>,
}

impl DexClassEntry {
    #[must_use] 
    pub const fn is_public(&self) -> bool { self.access_flags & 0x0001 != 0 }
    #[must_use] 
    pub const fn is_abstract(&self) -> bool { self.access_flags & 0x0400 != 0 }
    #[must_use] 
    pub const fn is_interface(&self) -> bool { self.access_flags & 0x0200 != 0 }
}

/// Parse a complete DEX file from its raw bytes.
///
/// # Errors
/// Returns an error when the magic is invalid or any header/class/code section cannot be parsed.
pub fn parse_dex(data: Vec<u8>) -> Result<DexFile> {
    let mut parser = DexParser::new(data);
    if !parser.check_magic() { bail!("Not a DEX file"); }
    let header = parser.parse_header()?;

    // Parse strings
    let mut strings = Vec::with_capacity(header.string_ids_size as usize);
    for i in 0..header.string_ids_size {
        strings.push(parser.read_string(header.string_ids_off, i));
    }

    // Parse types
    let mut types = Vec::with_capacity(header.type_ids_size as usize);
    for i in 0..header.type_ids_size {
        let off = header.type_ids_off + i * 4;
        let idx = u32::from_le_bytes(parser.data[off as usize..off as usize + 4].try_into().unwrap_or([0;4]));
        types.push(strings.get(idx as usize).cloned().unwrap_or_default());
    }

    Ok(DexFile { header, strings, types, methods: Vec::new(), classes: Vec::new() })
}
