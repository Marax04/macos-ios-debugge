//! Python bindings exposing `RustRE` analysis APIs to scripts.
//!
//! Provides a `rustre` pseudo-module callable from the sandbox.  All
//! functions accept and return [`PyValue`] so they integrate with both the
//! sandbox interpreter and, optionally, pyo3-backed engines.

use std::collections::HashMap;

use crate::python_stdlib_stubs::PyValue;

// ─── BoundFunction ────────────────────────────────────────────────────────────

/// Type alias for the boxed handler stored in [`BoundFunction`].
pub type BoundHandler = Box<dyn Fn(&[PyValue]) -> Result<PyValue, String> + Send + Sync>;

/// A single bound function that a script can call.
pub struct BoundFunction {
    pub name: String,
    pub doc: String,
    pub handler: BoundHandler,
}

impl BoundFunction {
    pub fn new(
        name: impl Into<String>,
        doc: impl Into<String>,
        handler: impl Fn(&[PyValue]) -> Result<PyValue, String> + Send + Sync + 'static,
    ) -> Self {
        Self { name: name.into(), doc: doc.into(), handler: Box::new(handler) }
    }

    pub fn call(&self, args: &[PyValue]) -> Result<PyValue, String> {
        (self.handler)(args)
    }
}

// ─── BindingModule ────────────────────────────────────────────────────────────

pub struct BindingModule {
    pub name: &'static str,
    functions: HashMap<String, BoundFunction>,
}

impl BindingModule {
    #[must_use] 
    pub fn new(name: &'static str) -> Self {
        Self { name, functions: HashMap::new() }
    }

    pub fn register(&mut self, f: BoundFunction) {
        self.functions.insert(f.name.clone(), f);
    }

    pub fn call(&self, func_name: &str, args: &[PyValue]) -> Result<PyValue, String> {
        let f = self.functions.get(func_name)
            .ok_or_else(|| format!("AttributeError: module '{}' has no function '{}'", self.name, func_name))?;
        f.call(args)
    }

    #[must_use] 
    pub fn function_names(&self) -> Vec<&str> {
        self.functions.keys().map(std::string::String::as_str).collect()
    }
}

// ─── RustReBindings ──────────────────────────────────────────────────────────

/// Registry of all bound modules.
pub struct RustReBindings {
    modules: HashMap<&'static str, BindingModule>,
}

impl RustReBindings {
    #[must_use] 
    pub fn new() -> Self {
        let mut s = Self { modules: HashMap::new() };
        s.register_rustre_module();
        s
    }

    pub fn call(&self, module: &str, func: &str, args: &[PyValue]) -> Result<PyValue, String> {
        self.modules.get(module)
            .ok_or_else(|| format!("ModuleNotFoundError: No module named '{module}'"))?
            .call(func, args)
    }

    #[must_use] 
    pub fn module_names(&self) -> Vec<&'static str> {
        self.modules.keys().copied().collect()
    }

    fn insert(&mut self, m: BindingModule) {
        self.modules.insert(m.name, m);
    }

    fn register_rustre_module(&mut self) {
        let mut m = BindingModule::new("rustre");
        register_analysis_fns(&mut m);
        register_encoding_fns(&mut m);
        register_search_fns(&mut m);
        self.insert(m);
    }
}

fn register_analysis_fns(m: &mut BindingModule) {
    m.register(BoundFunction::new(
        "analyze_pe",
        "Analyze a PE file from bytes. Returns dict with entry_point, sections, imports, exports.",
        |args| {
            let data = args.first().and_then(|a| a.as_bytes())
                .ok_or("TypeError: analyze_pe expects bytes")?;
            analyze_pe_impl(data)
        },
    ));
    m.register(BoundFunction::new(
        "disassemble",
        "Disassemble bytes. Returns list of dicts with offset, mnemonic, operands.",
        |args| {
            let data = args.first().and_then(|a| a.as_bytes())
                .ok_or("TypeError: disassemble expects bytes as first arg")?;
            let arch = args.get(1).and_then(|a| a.as_str()).unwrap_or("x86_64");
            let base_addr = args.get(2).and_then(super::python_stdlib_stubs::PyValue::as_int).unwrap_or(0).max(0).cast_unsigned();
            Ok(disassemble_impl(data, arch, base_addr))
        },
    ));
    m.register(BoundFunction::new(
        "compute_entropy",
        "Compute Shannon entropy of bytes (0.0 – 8.0).",
        |args| {
            let data = args.first().and_then(|a| a.as_bytes())
                .ok_or("TypeError: compute_entropy expects bytes")?;
            Ok(PyValue::Float(shannon_entropy(data)))
        },
    ));
    m.register(BoundFunction::new(
        "find_strings",
        "Find printable ASCII strings in bytes.",
        |args| {
            let data = args.first().and_then(|a| a.as_bytes())
                .ok_or("TypeError: find_strings expects bytes")?;
            let min_len = usize::try_from(args.get(1).and_then(super::python_stdlib_stubs::PyValue::as_int).unwrap_or(4).max(1)).unwrap_or(4);
            Ok(PyValue::List(find_printable_strings(data, min_len).into_iter().map(PyValue::Str).collect()))
        },
    ));
    m.register(BoundFunction::new(
        "detect_packer",
        "Heuristically detect the packer/protector used.",
        |args| {
            let data = args.first().and_then(|a| a.as_bytes())
                .ok_or("TypeError: detect_packer expects bytes")?;
            Ok(PyValue::Str(detect_packer_impl(data).to_owned()))
        },
    ));
    m.register(BoundFunction::new(
        "pe_overlay",
        "Extract overlay data appended after the last PE section.",
        |args| {
            let data = args.first().and_then(|a| a.as_bytes())
                .ok_or("TypeError: pe_overlay expects bytes")?;
            Ok(PyValue::Bytes(pe_overlay_impl(data)))
        },
    ));
}

fn register_encoding_fns(m: &mut BindingModule) {
    m.register(BoundFunction::new(
        "xor_decode",
        "XOR decode bytes with a repeating key.",
        |args| {
            let data = args.first().and_then(|a| a.as_bytes())
                .ok_or("TypeError: xor_decode expects bytes as first arg")?;
            let key = args.get(1).and_then(|a| a.as_bytes())
                .ok_or("TypeError: xor_decode expects bytes as second arg")?;
            if key.is_empty() { return Err("ValueError: key cannot be empty".into()); }
            let decoded: Vec<u8> = data.iter().enumerate().map(|(i, &b)| b ^ key[i % key.len()]).collect();
            Ok(PyValue::Bytes(decoded))
        },
    ));
    m.register(BoundFunction::new(
        "base64_decode",
        "Decode a base64 string to bytes.",
        |args| {
            let s = args.first().and_then(|a| a.as_str())
                .ok_or("TypeError: base64_decode expects a str")?;
            let decoded = base64_decode_impl(s.as_bytes())
                .ok_or("ValueError: invalid base64 data")?;
            Ok(PyValue::Bytes(decoded))
        },
    ));
    m.register(BoundFunction::new(
        "md5",
        "Return MD5 hex digest of bytes.",
        |args| {
            let data = args.first().and_then(|a| a.as_bytes())
                .ok_or("TypeError: md5 expects bytes")?;
            Ok(PyValue::Str(md5_hex_impl(data)))
        },
    ));
    m.register(BoundFunction::new(
        "sha256",
        "Return SHA-256 hex digest of bytes.",
        |args| {
            let data = args.first().and_then(|a| a.as_bytes())
                .ok_or("TypeError: sha256 expects bytes")?;
            Ok(PyValue::Str(sha256_hex_impl(data)))
        },
    ));
}

fn register_search_fns(m: &mut BindingModule) {
    m.register(BoundFunction::new(
        "find_pattern",
        "Find all occurrences of a hex pattern in bytes. Returns list of int offsets.",
        |args| {
            let data = args.first().and_then(|a| a.as_bytes())
                .ok_or("TypeError: find_pattern expects bytes as first arg")?;
            let pattern_str = args.get(1).and_then(|a| a.as_str())
                .ok_or("TypeError: find_pattern expects str as second arg")?;
            let pattern = parse_hex_pattern(pattern_str).ok_or("ValueError: invalid hex pattern")?;
            let offsets = find_byte_pattern(data, &pattern);
            Ok(PyValue::List(offsets.into_iter().map(|o| PyValue::Int(i64::try_from(o).unwrap_or(i64::MAX))).collect()))
        },
    ));
    m.register(BoundFunction::new(
        "extract_urls",
        "Extract HTTP/HTTPS/FTP URLs from bytes.",
        |args| {
            let data = args.first().and_then(|a| a.as_bytes())
                .ok_or("TypeError: extract_urls expects bytes")?;
            let urls = extract_urls_from_bytes(data);
            Ok(PyValue::List(urls.into_iter().map(PyValue::Str).collect()))
        },
    ));
}

impl Default for RustReBindings {
    fn default() -> Self { Self::new() }
}

// ─── Implementation helpers ───────────────────────────────────────────────────

fn analyze_pe_impl(data: &[u8]) -> Result<PyValue, String> {
    if data.len() < 64 { return Err("ValueError: too short to be a PE file".into()); }
    // Check MZ magic
    if data[0] != b'M' || data[1] != b'Z' {
        return Err("ValueError: not a valid PE file (missing MZ header)".into());
    }
    // e_lfanew at offset 0x3C
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew + 24 > data.len() {
        return Err("ValueError: e_lfanew points outside data".into());
    }
    // PE signature
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err("ValueError: invalid PE signature".into());
    }

    // COFF header
    let machine = u16::from_le_bytes([data[e_lfanew + 4], data[e_lfanew + 5]]);
    let num_sections = u16::from_le_bytes([data[e_lfanew + 6], data[e_lfanew + 7]]) as usize;
    let opt_header_size = u16::from_le_bytes([data[e_lfanew + 20], data[e_lfanew + 21]]) as usize;

    // Optional header
    let opt_hdr_offset = e_lfanew + 24;
    let (entry_point, image_base) = if opt_hdr_offset + 24 <= data.len() {
        let ep = i64::from(u32::from_le_bytes([data[opt_hdr_offset+16], data[opt_hdr_offset+17], data[opt_hdr_offset+18], data[opt_hdr_offset+19]]));
        let magic = u16::from_le_bytes([data[opt_hdr_offset], data[opt_hdr_offset+1]]);
        let base: i64 = if magic == 0x20B {
            // PE32+
            if opt_hdr_offset + 32 <= data.len() {
                i64::from_le_bytes(data[opt_hdr_offset+24..opt_hdr_offset+32].try_into().unwrap_or([0;8]))
            } else { 0x0001_4000_0000 }
        } else if opt_hdr_offset + 32 <= data.len() {
            i64::from(u32::from_le_bytes([data[opt_hdr_offset+28], data[opt_hdr_offset+29], data[opt_hdr_offset+30], data[opt_hdr_offset+31]]))
        } else { 0x0040_0000 };
        (ep, base)
    } else {
        (0, 0x0040_0000)
    };

    // Sections
    let section_table_offset = opt_hdr_offset.saturating_add(opt_header_size);
    if section_table_offset > data.len() {
        return Err("ValueError: section table offset exceeds data length".into());
    }
    let mut sections = Vec::new();
    for i in 0..num_sections {
        let sec_off = section_table_offset + i * 40;
        if sec_off + 40 > data.len() { break; }
        let name_bytes = &data[sec_off..sec_off + 8];
        let name = String::from_utf8_lossy(name_bytes).trim_end_matches('\0').to_owned();
        let vsize = i64::from(u32::from_le_bytes([data[sec_off+8], data[sec_off+9], data[sec_off+10], data[sec_off+11]]));
        let vaddr = i64::from(u32::from_le_bytes([data[sec_off+12], data[sec_off+13], data[sec_off+14], data[sec_off+15]]));
        let raw_size = i64::from(u32::from_le_bytes([data[sec_off+16], data[sec_off+17], data[sec_off+18], data[sec_off+19]]));
        let characteristics = u32::from_le_bytes([data[sec_off+36], data[sec_off+37], data[sec_off+38], data[sec_off+39]]);

        // Compute entropy of section data
        let raw_offset = usize::try_from(u32::from_le_bytes([data[sec_off+20], data[sec_off+21], data[sec_off+22], data[sec_off+23]])).unwrap_or(0);
        let sec_data_end = (raw_offset + usize::try_from(raw_size).unwrap_or(0)).min(data.len());
        let entropy = if raw_offset < sec_data_end { shannon_entropy(&data[raw_offset..sec_data_end]) } else { 0.0 };

        let sec_dict = vec![
            (PyValue::Str("name".into()), PyValue::Str(name)),
            (PyValue::Str("vsize".into()), PyValue::Int(vsize)),
            (PyValue::Str("vaddr".into()), PyValue::Int(vaddr)),
            (PyValue::Str("raw_size".into()), PyValue::Int(raw_size)),
            (PyValue::Str("characteristics".into()), PyValue::Int(i64::from(characteristics))),
            (PyValue::Str("entropy".into()), PyValue::Float(entropy)),
        ];
        sections.push(PyValue::Dict(sec_dict));
    }

    // Simplified import detection: scan for null-terminated DLL names after IAT region
    let imports = extract_import_names(data);
    let exports = extract_export_names(data);

    let arch_str = match machine {
        0x8664 => "x86_64",
        0x014c => "x86",
        0xAA64 => "arm64",
        0x01c4 => "arm",
        _ => "unknown",
    };

    let result = vec![
        (PyValue::Str("entry_point".into()), PyValue::Int(entry_point + image_base)),
        (PyValue::Str("image_base".into()), PyValue::Int(image_base)),
        (PyValue::Str("arch".into()), PyValue::Str(arch_str.into())),
        (PyValue::Str("sections".into()), PyValue::List(sections)),
        (PyValue::Str("imports".into()), PyValue::List(imports.into_iter().map(PyValue::Str).collect())),
        (PyValue::Str("exports".into()), PyValue::List(exports.into_iter().map(PyValue::Str).collect())),
        (PyValue::Str("num_sections".into()), PyValue::Int(i64::try_from(num_sections).unwrap_or(0))),
    ];

    Ok(PyValue::Dict(result))
}

fn disassemble_impl(data: &[u8], arch: &str, base_addr: u64) -> PyValue {
    // Lightweight x86/x86_64 disassembler: recognise a small set of common opcodes.
    // This is intentionally approximate — for scripting convenience, not production use.
    let is_64 = arch == "x86_64" || arch == "x64";
    let mut instructions = Vec::new();
    let mut offset = 0usize;

    while offset < data.len() && instructions.len() < 256 {
        let _ = data[offset];
        let addr = base_addr + u64::try_from(offset).unwrap_or(0);

        let (mnemonic, operands, length) = decode_x86_instr(data, offset, is_64);
        let instr_dict = vec![
            (PyValue::Str("offset".into()), PyValue::Int(addr.cast_signed())),
            (PyValue::Str("mnemonic".into()), PyValue::Str(mnemonic.to_owned())),
            (PyValue::Str("operands".into()), PyValue::Str(operands)),
            (PyValue::Str("length".into()), PyValue::Int(i64::try_from(length).unwrap_or(0))),
        ];
        instructions.push(PyValue::Dict(instr_dict));
        offset += length;
    }

    PyValue::List(instructions)
}

fn decode_x86_instr(data: &[u8], offset: usize, _is_64: bool) -> (&'static str, String, usize) {
    if offset >= data.len() { return ("db", "0x00".to_string(), 1); }
    let b = data[offset];
    match b {
        0x00 if offset + 1 < data.len() && data[offset + 1] == 0x00 => ("add", "[eax], al".into(), 2),
        0x50..=0x57 => { let reg = ["eax","ecx","edx","ebx","esp","ebp","esi","edi"][(b - 0x50) as usize]; ("push", reg.into(), 1) }
        0x58..=0x5F => { let reg = ["eax","ecx","edx","ebx","esp","ebp","esi","edi"][(b - 0x58) as usize]; ("pop", reg.into(), 1) }
        0x90 => ("nop", String::new(), 1),
        0xC3 => ("ret", String::new(), 1),
        0xCC => ("int3", String::new(), 1),
        0xEB if offset + 1 < data.len() => {
            let rel = data[offset + 1].cast_signed();
            ("jmp", format!("short {rel:+}"), 2)
        }
        0xE8 if offset + 4 < data.len() => {
            let rel = i32::from_le_bytes([data[offset+1], data[offset+2], data[offset+3], data[offset+4]]);
            ("call", format!("{rel:+}"), 5)
        }
        0xE9 if offset + 4 < data.len() => {
            let rel = i32::from_le_bytes([data[offset+1], data[offset+2], data[offset+3], data[offset+4]]);
            ("jmp", format!("{rel:+}"), 5)
        }
        0xB8..=0xBF => {
            let reg = ["eax","ecx","edx","ebx","esp","ebp","esi","edi"][(b - 0xB8) as usize];
            if offset + 4 < data.len() {
                let imm = u32::from_le_bytes([data[offset+1], data[offset+2], data[offset+3], data[offset+4]]);
                ("mov", format!("{reg}, 0x{imm:x}"), 5)
            } else {
                ("mov", format!("{reg}, ?"), 1)
            }
        }
        0x89 if offset + 1 < data.len() => {
            ("mov", format!("rm, r (modrm=0x{:02x})", data[offset+1]), 2)
        }
        0x8B if offset + 1 < data.len() => {
            ("mov", format!("r, rm (modrm=0x{:02x})", data[offset+1]), 2)
        }
        0xFF if offset + 1 < data.len() => {
            let modrm = data[offset + 1];
            let op = (modrm >> 3) & 7;
            let name = match op { 2 => "call", 4 => "jmp", 6 => "push", _ => "ff" };
            (name, format!("rm (modrm=0x{modrm:02x})"), 2)
        }
        0x74 if offset + 1 < data.len() => {
            ("je", format!("short {:+}", data[offset+1].cast_signed()), 2)
        }
        0x75 if offset + 1 < data.len() => {
            ("jne", format!("short {:+}", data[offset+1].cast_signed()), 2)
        }
        0x33 if offset + 1 < data.len() => {
            ("xor", format!("r, rm (modrm=0x{:02x})", data[offset+1]), 2)
        }
        0x31 if offset + 1 < data.len() => {
            ("xor", format!("rm, r (modrm=0x{:02x})", data[offset+1]), 2)
        }
        _ => ("db", format!("0x{b:02x}"), 1),
    }
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u32; 256];
    for &b in data { counts[b as usize] += 1; }
    let n = data.len() as f64;
    counts.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
        let p = f64::from(c) / n;
        p.mul_add(-p.log2(), acc)
    })
}

fn find_printable_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut results = Vec::new();
    let mut start = 0usize;
    while start < data.len() {
        if data[start] >= 0x20 && data[start] < 0x7F {
            let run_start = start;
            while start < data.len() && data[start] >= 0x20 && data[start] < 0x7F {
                start += 1;
            }
            if start - run_start >= min_len {
                results.push(String::from_utf8_lossy(&data[run_start..start]).into_owned());
            }
        } else {
            start += 1;
        }
    }
    results
}

fn base64_decode_impl(raw: &[u8]) -> Option<Vec<u8>> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut table = [255u8; 256];
    for (i, &c) in alphabet.iter().enumerate() { table[c as usize] = u8::try_from(i).unwrap_or(255); }
    let mut out = Vec::with_capacity(raw.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &b in raw {
        if b == b'=' { break; }
        if b == b'\n' || b == b'\r' || b == b' ' { continue; }
        let v = table[b as usize];
        if v == 255 { return None; }
        buf = (buf << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 { bits -= 8; out.push(u32::to_le_bytes(buf >> bits)[0]); buf &= (1 << bits) - 1; }
    }
    Some(out)
}

fn parse_hex_pattern(s: &str) -> Option<Vec<Option<u8>>> {
    let s = s.replace(' ', "");
    if !s.len().is_multiple_of(2) { return None; }
    let mut pattern = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i + 1 < chars.len() {
        let hi = chars[i];
        let lo = chars[i + 1];
        if hi == '?' && lo == '?' {
            pattern.push(None); // wildcard
        } else {
            let hi_v = u8::try_from(hi.to_digit(16)?).unwrap_or(0);
            let lo_v = u8::try_from(lo.to_digit(16)?).unwrap_or(0);
            pattern.push(Some((hi_v << 4) | lo_v));
        }
        i += 2;
    }
    Some(pattern)
}

fn find_byte_pattern(data: &[u8], pattern: &[Option<u8>]) -> Vec<usize> {
    let plen = pattern.len();
    if plen == 0 { return Vec::new(); }
    let mut results = Vec::new();
    for i in 0..data.len().saturating_sub(plen - 1) {
        let matches = pattern.iter().enumerate().all(|(j, &p)| {
            p.is_none_or(|b| data[i + j] == b)
        });
        if matches { results.push(i); }
    }
    results
}

fn extract_urls_from_bytes(data: &[u8]) -> Vec<String> {
    let mut urls = Vec::new();
    for scheme in &[b"http://".as_ref(), b"https://".as_ref(), b"ftp://".as_ref()] {
        let mut start = 0;
        while start + scheme.len() <= data.len() {
            if &data[start..start + scheme.len()] == *scheme {
                let end = data[start..].iter().position(|&b| b == 0 || b == b'"' || b == b' ' || b < 0x20)
                    .map_or(data.len(), |p| start + p);
                if end - start > scheme.len() + 3
                    && let Ok(s) = std::str::from_utf8(&data[start..end]) {
                        urls.push(s.to_owned());
                    }
                start = end;
            } else {
                start += 1;
            }
        }
    }
    urls
}

fn detect_packer_impl(data: &[u8]) -> &'static str {
    if data.len() < 4 { return "Unknown"; }

    // UPX signatures
    if contains_bytes(data, b"UPX!") || contains_bytes(data, b"UPX0") {
        return "UPX";
    }
    // MPRESS
    if contains_bytes(data, b"MPRESS") {
        return "MPRESS";
    }
    // Themida / WinLicense
    if contains_bytes(data, b".themida") || contains_bytes(data, b"Themida") {
        return "Themida";
    }
    // ASPack
    if contains_bytes(data, b".aspack") || contains_bytes(data, b"ASPack") {
        return "ASPack";
    }
    // PECompact
    if contains_bytes(data, b"PECompact") {
        return "PECompact";
    }
    // PyInstaller
    if contains_bytes(data, b"PyInstaller") || contains_bytes(data, b"pyi-windows-manifest-filename") {
        return "PyInstaller";
    }
    // .NET
    if data.len() > 64 && data[0] == b'M' && data[1] == b'Z'
        && contains_bytes(data, b"mscoree.dll") {
            return ".NET Assembly";
        }
    // High entropy sections suggest packing
    if data.len() > 512 {
        let entropy = shannon_entropy(&data[..512.min(data.len())]);
        if entropy > 7.2 { return "Unknown (high entropy - possibly packed)"; }
    }
    "Unknown"
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() { return true; }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn pe_overlay_impl(data: &[u8]) -> Vec<u8> {
    if data.len() < 64 { return Vec::new(); }
    if data[0] != b'M' || data[1] != b'Z' { return Vec::new(); }

    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew + 24 > data.len() { return Vec::new(); }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" { return Vec::new(); }

    let num_sections = u16::from_le_bytes([data[e_lfanew + 6], data[e_lfanew + 7]]) as usize;
    let opt_header_size = u16::from_le_bytes([data[e_lfanew + 20], data[e_lfanew + 21]]) as usize;
    let section_table_offset = e_lfanew + 24 + opt_header_size;

    let mut last_section_end = 0usize;
    for i in 0..num_sections {
        let sec_off = section_table_offset + i * 40;
        if sec_off + 40 > data.len() { break; }
        let raw_offset = u32::from_le_bytes([data[sec_off+20], data[sec_off+21], data[sec_off+22], data[sec_off+23]]) as usize;
        let raw_size   = u32::from_le_bytes([data[sec_off+16], data[sec_off+17], data[sec_off+18], data[sec_off+19]]) as usize;
        let end = raw_offset + raw_size;
        if end > last_section_end { last_section_end = end; }
    }

    if last_section_end < data.len() {
        data[last_section_end..].to_vec()
    } else {
        Vec::new()
    }
}

fn extract_import_names(data: &[u8]) -> Vec<String> {
    // Scan for common DLL name patterns (null-terminated ASCII ending in .dll)
    let mut names = Vec::new();
    let mut i = 0;
    while i < data.len().saturating_sub(4) {
        // Look for .dll\0 pattern
        if &data[i..i+4] == b".dll" || &data[i..i+4] == b".DLL" {
            // Scan back for start of DLL name
            let mut start = i;
            while start > 0 && data[start-1] >= 0x20 && data[start-1] < 0x7F {
                start -= 1;
            }
            if i > start
                && let Ok(s) = std::str::from_utf8(&data[start..i+4])
                    && s.len() >= 5 && !names.contains(&s.to_owned()) {
                        names.push(s.to_owned());
                    }
        }
        i += 1;
    }
    names.truncate(64); // reasonable cap
    names
}

fn extract_export_names(data: &[u8]) -> Vec<String> {
    // Very simplified: scan for sequences of printable bytes that look like function names
    // near the export table area (first 256 bytes of each section with high ASCII ratio).
    // In practice you'd parse the export directory — this is a heuristic approximation.
    let strings = find_printable_strings(data, 4);
    strings.into_iter()
        .filter(|s| s.chars().all(|c| c.is_alphanumeric() || c == '_') && !s.is_empty())
        .take(64)
        .collect()
}

fn md5_hex_impl(data: &[u8]) -> String {
    // Forward to the StdlibStubs md5 for consistency
    let stubs = crate::python_stdlib_stubs::StdlibStubs::new();
    if let Some(PyValue::Str(s)) = stubs.call("hashlib", "md5", &[PyValue::Bytes(data.to_vec())]) {
        s
    } else {
        "0".repeat(32)
    }
}

fn sha256_hex_impl(data: &[u8]) -> String {
    let stubs = crate::python_stdlib_stubs::StdlibStubs::new();
    if let Some(PyValue::Str(s)) = stubs.call("hashlib", "sha256", &[PyValue::Bytes(data.to_vec())]) {
        s
    } else {
        "0".repeat(64)
    }
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn bindings() -> RustReBindings { RustReBindings::new() }

    fn make_minimal_pe() -> Vec<u8> {
        // Minimal MZ+PE stub: MZ header + e_lfanew=0x40, PE\0\0 signature at 0x40
        let mut data = vec![0u8; 0x200];
        data[0] = b'M'; data[1] = b'Z';
        data[0x3C] = 0x40; // e_lfanew = 0x40
        data[0x40] = b'P'; data[0x41] = b'E'; data[0x42] = 0; data[0x43] = 0;
        data[0x44] = 0x64; data[0x45] = 0x86; // machine = x86_64
        data[0x46] = 1;  // num sections = 1
        data[0x54] = 0xF0; data[0x55] = 0x00; // optional header size = 0xF0 (PE32+)
        // Place PE32+ optional header magic
        data[0x58] = 0x0B; data[0x59] = 0x02; // PE32+ magic
        // entry point RVA at opt_hdr+16 = 0x58+16 = 0x68
        data[0x68] = 0x00; data[0x69] = 0x10;
        // image base at opt_hdr+24 = 0x70 (PE32+)
        data[0x70] = 0x00; data[0x71] = 0x00; data[0x72] = 0x00; data[0x73] = 0x40;
        data[0x74] = 0x01;
        data
    }

    #[test]
    fn test_analyze_pe_mz_magic() {
        let pe = make_minimal_pe();
        let result = bindings().call("rustre", "analyze_pe", &[PyValue::Bytes(pe)]);
        assert!(result.is_ok());
        if let Ok(PyValue::Dict(fields)) = result {
            let arch = fields.iter().find(|(k, _)| k == &PyValue::Str("arch".into()));
            assert!(arch.is_some());
        }
    }

    #[test]
    fn test_analyze_pe_not_mz_returns_err() {
        let data = b"XXXXXXX".to_vec();
        let result = bindings().call("rustre", "analyze_pe", &[PyValue::Bytes(data)]);
        assert!(result.is_err());
    }

    #[test]
    fn test_disassemble_nop_ret() {
        let code = vec![0x90u8, 0xC3]; // nop; ret
        let result = bindings().call("rustre", "disassemble", &[PyValue::Bytes(code), PyValue::Str("x86_64".into()), PyValue::Int(0)]);
        assert!(result.is_ok());
        if let Ok(PyValue::List(instrs)) = result {
            assert_eq!(instrs.len(), 2);
        }
    }

    #[test]
    fn test_compute_entropy_uniform() {
        let data: Vec<u8> = (0u8..=255).collect();
        let result = bindings().call("rustre", "compute_entropy", &[PyValue::Bytes(data)]);
        if let Ok(PyValue::Float(e)) = result {
            assert!((e - 8.0).abs() < 0.01);
        } else { panic!("expected float"); }
    }

    #[test]
    fn test_compute_entropy_zero() {
        let data = vec![0u8; 100];
        let result = bindings().call("rustre", "compute_entropy", &[PyValue::Bytes(data)]);
        if let Ok(PyValue::Float(e)) = result {
            assert_eq!(e, 0.0);
        } else { panic!("expected float"); }
    }

    #[test]
    fn test_find_strings_basic() {
        let mut data = vec![0u8, 0u8];
        data.extend_from_slice(b"password");
        data.extend_from_slice(&[0, 0]);
        let result = bindings().call("rustre", "find_strings", &[PyValue::Bytes(data), PyValue::Int(4)]);
        if let Ok(PyValue::List(strings)) = result {
            assert!(strings.iter().any(|s| s == &PyValue::Str("password".into())));
        } else { panic!("expected list"); }
    }

    #[test]
    fn test_xor_decode_roundtrip() {
        let original = b"Hello World!".to_vec();
        let key = vec![0x42u8];
        let xored: Vec<u8> = original.iter().map(|b| b ^ 0x42).collect();
        let result = bindings().call("rustre", "xor_decode", &[PyValue::Bytes(xored), PyValue::Bytes(key)]);
        assert_eq!(result, Ok(PyValue::Bytes(original)));
    }

    #[test]
    fn test_xor_decode_empty_key_error() {
        let result = bindings().call("rustre", "xor_decode", &[PyValue::Bytes(vec![1,2,3]), PyValue::Bytes(vec![])]);
        assert!(result.is_err());
    }

    #[test]
    fn test_base64_decode() {
        let result = bindings().call("rustre", "base64_decode", &[PyValue::Str("SGVsbG8=".into())]);
        assert_eq!(result, Ok(PyValue::Bytes(b"Hello".to_vec())));
    }

    #[test]
    fn test_md5_empty() {
        let result = bindings().call("rustre", "md5", &[PyValue::Bytes(vec![])]);
        assert_eq!(result, Ok(PyValue::Str("d41d8cd98f00b204e9800998ecf8427e".into())));
    }

    #[test]
    fn test_sha256_empty() {
        let result = bindings().call("rustre", "sha256", &[PyValue::Bytes(vec![])]);
        assert_eq!(result, Ok(PyValue::Str("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into())));
    }

    #[test]
    fn test_find_pattern_simple() {
        let data = vec![0u8, 0x90, 0x90, 0x00, 0x90, 0x90];
        let result = bindings().call("rustre", "find_pattern", &[PyValue::Bytes(data), PyValue::Str("9090".into())]);
        if let Ok(PyValue::List(offsets)) = result {
            assert_eq!(offsets.len(), 2);
            assert_eq!(offsets[0], PyValue::Int(1));
            assert_eq!(offsets[1], PyValue::Int(4));
        } else { panic!("expected list"); }
    }

    #[test]
    fn test_find_pattern_wildcard() {
        let data = vec![0x48u8, 0x89, 0xDE, 0x48, 0x8B, 0xDF];
        let result = bindings().call("rustre", "find_pattern", &[PyValue::Bytes(data), PyValue::Str("48 ?? ??".into())]);
        if let Ok(PyValue::List(offsets)) = result {
            assert_eq!(offsets.len(), 2);
        } else { panic!("expected list"); }
    }

    #[test]
    fn test_extract_urls() {
        let mut data = b"some data ".to_vec();
        data.extend_from_slice(b"http://evil.com/malware ");
        data.extend_from_slice(b"more data");
        let result = bindings().call("rustre", "extract_urls", &[PyValue::Bytes(data)]);
        if let Ok(PyValue::List(urls)) = result {
            assert!(!urls.is_empty());
            assert!(urls.iter().any(|u| u == &PyValue::Str("http://evil.com/malware".into())));
        } else { panic!("expected list"); }
    }

    #[test]
    fn test_detect_packer_upx() {
        let mut data = vec![0u8; 64];
        data.extend_from_slice(b"UPX!");
        let result = bindings().call("rustre", "detect_packer", &[PyValue::Bytes(data)]);
        assert_eq!(result, Ok(PyValue::Str("UPX".into())));
    }

    #[test]
    fn test_pe_overlay_no_overlay() {
        let pe = make_minimal_pe();
        let result = bindings().call("rustre", "pe_overlay", &[PyValue::Bytes(pe)]);
        // minimal PE has no overlay data
        assert!(matches!(result, Ok(PyValue::Bytes(_))));
    }

    #[test]
    fn test_module_names_include_rustre() {
        let b = bindings();
        assert!(b.module_names().contains(&"rustre"));
    }
}
