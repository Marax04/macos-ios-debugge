//! Python standard-library stubs for safe, sandboxed script execution.
//!
//! Provides a pure-Rust implementation of common Python stdlib functions so
//! that scripts can call e.g. `struct.pack`, `binascii.hexlify`, or
//! `hashlib.sha256` without requiring a full `CPython` interpreter.

use std::collections::HashMap;
use std::fmt;

// ─── PyValue ─────────────────────────────────────────────────────────────────

/// Runtime value type used by the stub interpreter.
#[derive(Debug, Clone, PartialEq)]
pub enum PyValue {
    None,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Bytes(Vec<u8>),
    List(Vec<Self>),
    Dict(Vec<(Self, Self)>),
    Tuple(Vec<Self>),
    Set(Vec<Self>),
}

impl PyValue {
    #[must_use] 
    pub fn is_truthy(&self) -> bool {
        match self {
            Self::None => false,
            Self::Bool(b) => *b,
            Self::Int(i) => *i != 0,
            Self::Float(f) => *f != 0.0,
            Self::Str(s) => !s.is_empty(),
            Self::Bytes(b) => !b.is_empty(),
            Self::Dict(v) => !v.is_empty(),
            Self::List(v) | Self::Tuple(v) | Self::Set(v) => !v.is_empty(),
        }
    }

    #[must_use] 
    pub const fn as_str(&self) -> Option<&str> {
        if let Self::Str(s) = self { Some(s.as_str()) } else { None }
    }

    #[must_use] 
    pub const fn as_bytes(&self) -> Option<&[u8]> {
        if let Self::Bytes(b) = self { Some(b.as_slice()) } else { None }
    }

    #[must_use] 
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(*i),
            Self::Bool(b) => Some(i64::from(*b)),
            _ => None,
        }
    }

    #[must_use] 
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::None => "NoneType",
            Self::Bool(_) => "bool",
            Self::Int(_) => "int",
            Self::Float(_) => "float",
            Self::Str(_) => "str",
            Self::Bytes(_) => "bytes",
            Self::List(_) => "list",
            Self::Dict(_) => "dict",
            Self::Tuple(_) => "tuple",
            Self::Set(_) => "set",
        }
    }
}

impl fmt::Display for PyValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Bool(b) => write!(f, "{}", if *b { "True" } else { "False" }),
            Self::Int(i) => write!(f, "{i}"),
            Self::Float(fl) => write!(f, "{fl}"),
            Self::Str(s) => write!(f, "{s}"),
            Self::Bytes(b) => {
                use std::fmt::Write as FmtWrite;
                let mut repr = String::with_capacity(b.len() * 4);
                for x in b { let _ = write!(repr, "\\x{x:02x}"); }
                write!(f, "b'{repr}'")
            }
            Self::List(v) => {
                let items: Vec<String> = v.iter().map(|x| format!("{x}")).collect();
                write!(f, "[{}]", items.join(", "))
            }
            Self::Tuple(v) => {
                let items: Vec<String> = v.iter().map(|x| format!("{x}")).collect();
                write!(f, "({})", items.join(", "))
            }
            Self::Dict(v) => {
                let items: Vec<String> = v.iter().map(|(k, val)| format!("{k}: {val}")).collect();
                write!(f, "{{{}}}", items.join(", "))
            }
            Self::Set(v) => {
                let items: Vec<String> = v.iter().map(|x| format!("{x}")).collect();
                write!(f, "{{{}}}", items.join(", "))
            }
        }
    }
}

// ─── Arity ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Arity {
    /// Exactly N positional arguments.
    Fixed(u8),
    /// Any number of positional arguments.
    Variadic,
    /// Positional + keyword arguments.
    VarKeyword,
}

// ─── StubFunction / StubModule ───────────────────────────────────────────────

/// Type alias for the boxed closure stored in [`StubFunction`].
pub type StubImplFn = Box<dyn Fn(&[PyValue]) -> PyValue + Send + Sync>;

pub struct StubFunction {
    pub name: String,
    pub arity: Arity,
    pub doc: String,
    pub impl_fn: StubImplFn,
}

impl StubFunction {
    pub fn new(name: impl Into<String>, arity: Arity, doc: impl Into<String>, f: impl Fn(&[PyValue]) -> PyValue + Send + Sync + 'static) -> Self {
        Self { name: name.into(), arity, doc: doc.into(), impl_fn: Box::new(f) }
    }

    #[must_use] 
    pub fn call(&self, args: &[PyValue]) -> PyValue {
        (self.impl_fn)(args)
    }
}

pub struct StubModule {
    pub name: &'static str,
    functions: HashMap<String, StubFunction>,
}

impl StubModule {
    #[must_use] 
    pub fn new(name: &'static str) -> Self {
        Self { name, functions: HashMap::new() }
    }

    pub fn register(&mut self, f: StubFunction) {
        self.functions.insert(f.name.clone(), f);
    }

    #[must_use] 
    pub fn call(&self, func_name: &str, args: &[PyValue]) -> Option<PyValue> {
        self.functions.get(func_name).map(|f| f.call(args))
    }

    #[must_use] 
    pub fn function_names(&self) -> Vec<&str> {
        self.functions.keys().map(std::string::String::as_str).collect()
    }
}

// ─── StdlibStubs ─────────────────────────────────────────────────────────────

/// Registry of all stub modules. Call [`call`] to dispatch.
pub struct StdlibStubs {
    modules: HashMap<&'static str, StubModule>,
}

impl StdlibStubs {
    #[must_use] 
    pub fn new() -> Self {
        let mut s = Self { modules: HashMap::new() };
        s.register_os_path();
        s.register_struct();
        s.register_binascii();
        s.register_hashlib();
        s.register_re();
        s.register_json();
        s.register_sys();
        s
    }

    #[must_use] 
    pub fn call(&self, module: &str, func: &str, args: &[PyValue]) -> Option<PyValue> {
        self.modules.get(module)?.call(func, args)
    }

    #[must_use] 
    pub fn module_names(&self) -> Vec<&'static str> {
        self.modules.keys().copied().collect()
    }

    fn insert(&mut self, module: StubModule) {
        self.modules.insert(module.name, module);
    }

    // ── os.path ─────────────────────────────────────────────────────────────

    fn register_os_path(&mut self) {
        let mut m = StubModule::new("os.path");

        m.register(StubFunction::new("join", Arity::Variadic, "Join path components", |args| {
            let parts: Vec<String> = args.iter().filter_map(|a| a.as_str().map(std::borrow::ToOwned::to_owned)).collect();
            PyValue::Str(parts.join("/"))
        }));

        m.register(StubFunction::new("basename", Arity::Fixed(1), "Return final component", |args| {
            let s = args.first().and_then(|a| a.as_str()).unwrap_or("");
            let base = s.rsplit('/').next().unwrap_or(s);
            let base = base.rsplit('\\').next().unwrap_or(base);
            PyValue::Str(base.to_owned())
        }));

        m.register(StubFunction::new("dirname", Arity::Fixed(1), "Return directory component", |args| {
            let s = args.first().and_then(|a| a.as_str()).unwrap_or("");
            let sep_pos = s.rfind('/').or_else(|| s.rfind('\\'));
            PyValue::Str(sep_pos.map_or("", |p| &s[..p]).to_owned())
        }));

        m.register(StubFunction::new("splitext", Arity::Fixed(1), "Split extension from path", |args| {
            let s = args.first().and_then(|a| a.as_str()).unwrap_or("");
            let dot_pos = s.rfind('.');
            match dot_pos {
                Some(p) if p > s.rfind('/').unwrap_or(0) => {
                    PyValue::Tuple(vec![PyValue::Str(s[..p].to_owned()), PyValue::Str(s[p..].to_owned())])
                }
                _ => PyValue::Tuple(vec![PyValue::Str(s.to_owned()), PyValue::Str(String::new())]),
            }
        }));

        m.register(StubFunction::new("exists", Arity::Fixed(1), "Stub: always returns False", |_args| {
            // In sandbox context we have no filesystem access
            PyValue::Bool(false)
        }));

        self.insert(m);
    }

    // ── struct ───────────────────────────────────────────────────────────────

    fn register_struct(&mut self) {
        let mut m = StubModule::new("struct");

        m.register(StubFunction::new("pack", Arity::Variadic, "Pack values to bytes", |args| {
            let fmt = args.first().and_then(|a| a.as_str()).unwrap_or("");
            let vals = if args.len() > 1 { &args[1..] } else { &[] };
            PyValue::Bytes(struct_pack(fmt, vals))
        }));

        m.register(StubFunction::new("unpack", Arity::Fixed(2), "Unpack bytes according to format", |args| {
            let fmt = args.first().and_then(|a| a.as_str()).unwrap_or("");
            let data = args.get(1).and_then(|a| a.as_bytes()).unwrap_or(&[]);
            PyValue::Tuple(struct_unpack(fmt, data))
        }));

        m.register(StubFunction::new("calcsize", Arity::Fixed(1), "Return size of format string", |args| {
            let fmt = args.first().and_then(|a| a.as_str()).unwrap_or("");
            PyValue::Int(i64::try_from(struct_calcsize(fmt)).unwrap_or(0))
        }));

        self.insert(m);
    }

    // ── binascii ─────────────────────────────────────────────────────────────

    fn register_binascii(&mut self) {
        use std::fmt::Write as FmtWrite;
        let mut m = StubModule::new("binascii");

        m.register(StubFunction::new("hexlify", Arity::Fixed(1), "Return hexadecimal representation", |args| {
            let data = args.first().and_then(|a| a.as_bytes()).unwrap_or(&[]);
            let mut hex = String::with_capacity(data.len() * 2);
            for b in data { let _ = write!(hex, "{b:02x}"); }
            PyValue::Bytes(hex.into_bytes())
        }));

        m.register(StubFunction::new("unhexlify", Arity::Fixed(1), "Decode hexadecimal string", |args| {
            let data = match args.first() {
                Some(PyValue::Bytes(b)) => b.clone(),
                Some(PyValue::Str(s)) => s.as_bytes().to_vec(),
                _ => return PyValue::Bytes(Vec::new()),
            };
            let decoded: Option<Vec<u8>> = data.chunks_exact(2).map(|pair| {
                let hi = hex_nibble(pair[0])?;
                let lo = hex_nibble(pair[1])?;
                Some((hi << 4) | lo)
            }).collect();
            PyValue::Bytes(decoded.unwrap_or_default())
        }));

        m.register(StubFunction::new("b2a_base64", Arity::Fixed(1), "Encode bytes as base64", |args| {
            let data = args.first().and_then(|a| a.as_bytes()).unwrap_or(&[]);
            let encoded = base64_encode(data);
            PyValue::Bytes((encoded + "\n").into_bytes())
        }));

        m.register(StubFunction::new("a2b_base64", Arity::Fixed(1), "Decode base64 bytes", |args| {
            let data = match args.first() {
                Some(PyValue::Bytes(b)) => b.clone(),
                Some(PyValue::Str(s)) => s.as_bytes().to_vec(),
                _ => return PyValue::Bytes(Vec::new()),
            };
            PyValue::Bytes(base64_decode_bytes(&data).unwrap_or_default())
        }));

        self.insert(m);
    }

    // ── hashlib ──────────────────────────────────────────────────────────────

    fn register_hashlib(&mut self) {
        let mut m = StubModule::new("hashlib");

        m.register(StubFunction::new("md5", Arity::Fixed(1), "Return MD5 hex digest", |args| {
            let data = args.first().and_then(|a| a.as_bytes()).unwrap_or(&[]);
            PyValue::Str(md5_hex(data))
        }));

        m.register(StubFunction::new("sha1", Arity::Fixed(1), "Return SHA-1 hex digest", |args| {
            let data = args.first().and_then(|a| a.as_bytes()).unwrap_or(&[]);
            PyValue::Str(sha1_hex(data))
        }));

        m.register(StubFunction::new("sha256", Arity::Fixed(1), "Return SHA-256 hex digest", |args| {
            let data = args.first().and_then(|a| a.as_bytes()).unwrap_or(&[]);
            PyValue::Str(sha256_hex(data))
        }));

        m.register(StubFunction::new("sha512", Arity::Fixed(1), "Return SHA-512 hex digest", |args| {
            let data = args.first().and_then(|a| a.as_bytes()).unwrap_or(&[]);
            PyValue::Str(sha512_hex(data))
        }));

        self.insert(m);
    }

    // ── re ───────────────────────────────────────────────────────────────────

    fn register_re(&mut self) {
        let mut m = StubModule::new("re");

        // Simplified: literal string search only (no full regex engine dependency)
        m.register(StubFunction::new("findall", Arity::Fixed(2), "Find all literal occurrences", |args| {
            let pattern = args.first().and_then(|a| a.as_str()).unwrap_or("");
            let text = args.get(1).and_then(|a| a.as_str()).unwrap_or("");
            let mut results = Vec::new();
            let mut start = 0;
            while let Some(pos) = text[start..].find(pattern) {
                results.push(PyValue::Str(pattern.to_owned()));
                start += pos + pattern.len().max(1);
                if start >= text.len() { break; }
            }
            PyValue::List(results)
        }));

        m.register(StubFunction::new("match", Arity::Fixed(2), "Match at start of string", |args| {
            let pattern = args.first().and_then(|a| a.as_str()).unwrap_or("");
            let text = args.get(1).and_then(|a| a.as_str()).unwrap_or("");
            if text.starts_with(pattern) {
                PyValue::Str(text[..pattern.len().min(text.len())].to_owned())
            } else {
                PyValue::None
            }
        }));

        m.register(StubFunction::new("search", Arity::Fixed(2), "Search for pattern in string", |args| {
            let pattern = args.first().and_then(|a| a.as_str()).unwrap_or("");
            let text = args.get(1).and_then(|a| a.as_str()).unwrap_or("");
            text.find(pattern).map_or(PyValue::None, |pos| PyValue::Str(text[pos..pos + pattern.len().min(text.len() - pos)].to_owned()))
        }));

        m.register(StubFunction::new("sub", Arity::Fixed(3), "Replace pattern occurrences", |args| {
            let pattern = args.first().and_then(|a| a.as_str()).unwrap_or("");
            let repl = args.get(1).and_then(|a| a.as_str()).unwrap_or("");
            let text = args.get(2).and_then(|a| a.as_str()).unwrap_or("");
            PyValue::Str(text.replace(pattern, repl))
        }));

        self.insert(m);
    }

    // ── json ─────────────────────────────────────────────────────────────────

    fn register_json(&mut self) {
        let mut m = StubModule::new("json");

        m.register(StubFunction::new("dumps", Arity::Fixed(1), "Serialize to JSON string", |args| {
            let val = args.first().unwrap_or(&PyValue::None);
            PyValue::Str(pyvalue_to_json(val))
        }));

        m.register(StubFunction::new("loads", Arity::Fixed(1), "Deserialize JSON string", |args| {
            let s = args.first().and_then(|a| a.as_str()).unwrap_or("");
            json_to_pyvalue(s)
        }));

        self.insert(m);
    }

    // ── sys ──────────────────────────────────────────────────────────────────

    fn register_sys(&mut self) {
        let mut m = StubModule::new("sys");

        m.register(StubFunction::new("version_info", Arity::Fixed(0), "Python version info tuple", |_args| {
            PyValue::Tuple(vec![PyValue::Int(3), PyValue::Int(11), PyValue::Int(0)])
        }));

        m.register(StubFunction::new("platform", Arity::Fixed(0), "Platform identifier", |_args| {
            PyValue::Str("rustre-sandbox".to_owned())
        }));

        self.insert(m);
    }
}

impl Default for StdlibStubs {
    fn default() -> Self { Self::new() }
}

// ─── struct pack/unpack helpers ──────────────────────────────────────────────

fn struct_calcsize(fmt: &str) -> usize {
    let fmt = fmt.trim_start_matches(['<', '>', '!', '=', '@']);
    let mut size = 0usize;
    let mut count_str = String::new();
    for ch in fmt.chars() {
        if ch.is_ascii_digit() { count_str.push(ch); continue; }
        let count: usize = if count_str.is_empty() { 1 } else { count_str.parse().unwrap_or(1) };
        count_str.clear();
        let element_size = match ch {
            'B' | 'b' | 'x' | 'c' => 1,
            'H' | 'h' => 2,
            'I' | 'i' | 'f' | 'L' | 'l' => 4,
            'Q' | 'q' | 'd' | 'P' => 8,
            's' => count, // fixed string: count is total bytes
            _ => 0,
        };
        if ch == 's' { size += element_size; count_str.clear(); continue; }
        size += element_size * count;
    }
    size
}

fn struct_pack(fmt: &str, vals: &[PyValue]) -> Vec<u8> {
    let little_endian = !fmt.starts_with('>') && !fmt.starts_with('!');
    let fmt_clean = fmt.trim_start_matches(['<', '>', '!', '=', '@']);
    let mut out = Vec::new();
    let mut val_idx = 0;
    for ch in fmt_clean.chars() {
        let val = vals.get(val_idx).unwrap_or(&PyValue::Int(0));
        val_idx += 1;
        let n = val.as_int().unwrap_or(0);
        let n_bytes = n.to_le_bytes(); // wrapping truncation via LE bytes
        match ch {
            'B' | 'b' => { out.push(n_bytes[0]); }
            'H' => {
                let v = u16::from_le_bytes([n_bytes[0], n_bytes[1]]);
                out.extend_from_slice(&if little_endian { v.to_le_bytes() } else { v.to_be_bytes() });
            }
            'h' => {
                let v = i16::from_le_bytes([n_bytes[0], n_bytes[1]]);
                out.extend_from_slice(&if little_endian { v.to_le_bytes() } else { v.to_be_bytes() });
            }
            'I' | 'L' => {
                let v = u32::from_le_bytes([n_bytes[0], n_bytes[1], n_bytes[2], n_bytes[3]]);
                out.extend_from_slice(&if little_endian { v.to_le_bytes() } else { v.to_be_bytes() });
            }
            'i' | 'l' => {
                let v = i32::from_le_bytes([n_bytes[0], n_bytes[1], n_bytes[2], n_bytes[3]]);
                out.extend_from_slice(&if little_endian { v.to_le_bytes() } else { v.to_be_bytes() });
            }
            'Q' => {
                let v = n.cast_unsigned();
                out.extend_from_slice(&if little_endian { v.to_le_bytes() } else { v.to_be_bytes() });
            }
            'q' => {
                out.extend_from_slice(&if little_endian { n.to_le_bytes() } else { n.to_be_bytes() });
            }
            'f' => {
                let f64_val = match val { PyValue::Float(f) => *f, PyValue::Int(i) => *i as f64, _ => 0.0 };
                let f32_bits = f64_to_f32_bits(f64_val);
                let v = f32::from_bits(f32_bits);
                out.extend_from_slice(&if little_endian { v.to_le_bytes() } else { v.to_be_bytes() });
            }
            'd' => {
                let v = match val { PyValue::Float(f) => *f, PyValue::Int(i) => *i as f64, _ => 0.0 };
                out.extend_from_slice(&if little_endian { v.to_le_bytes() } else { v.to_be_bytes() });
            }
            's' => {
                if let PyValue::Bytes(b) = val { out.extend_from_slice(b); }
                else if let PyValue::Str(s) = val { out.extend_from_slice(s.as_bytes()); }
            }
            'x' => { out.push(0); val_idx -= 1; } // padding byte, no value consumed
            _ => {}
        }
    }
    out
}

/// Convert `f64` to `f32` bit pattern using integer arithmetic (no `as f32`).
fn f64_to_f32_bits(v: f64) -> u32 {
    if v.is_nan() { return 0x7FC0_0000u32; }
    if v.is_infinite() {
        return if v.is_sign_positive() { 0x7F80_0000u32 } else { 0xFF80_0000u32 };
    }
    if v == 0.0 { return 0u32; }
    let bits64 = v.to_bits();
    let sign32 = u32::try_from(bits64 >> 63).unwrap_or(0) << 31;
    let exp64 = i32::try_from((bits64 >> 52) & 0x7FF).unwrap_or(0) - 1023;
    let mant64 = bits64 & 0x000F_FFFF_FFFF_FFFF_u64;
    let exp32 = exp64 + 127;
    if exp32 <= 0 { return sign32; }
    if exp32 >= 0xFF { return sign32 | 0x7F80_0000u32; }
    let mant32 = u32::try_from(mant64 >> 29).unwrap_or(0) & 0x007F_FFFFu32;
    sign32 | (u32::try_from(exp32).unwrap_or(0) << 23) | mant32
}

fn struct_unpack(fmt: &str, data: &[u8]) -> Vec<PyValue> {
    let little_endian = !fmt.starts_with('>') && !fmt.starts_with('!');
    let fmt_clean = fmt.trim_start_matches(['<', '>', '!', '=', '@']);
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut count_str = String::new();
    for ch in fmt_clean.chars() {
        if ch.is_ascii_digit() { count_str.push(ch); continue; }
        let count: usize = if count_str.is_empty() { 1 } else { count_str.parse().unwrap_or(1) };
        count_str.clear();
        for _ in 0..count {
            let val = match ch {
                'B' => { let v = data.get(pos).copied().unwrap_or(0); pos += 1; PyValue::Int(i64::from(v)) }
                'b' => { let v = data.get(pos).copied().unwrap_or(0).cast_signed(); pos += 1; PyValue::Int(i64::from(v)) }
                'H' => {
                    let bytes = get_bytes_fixed::<2>(data, pos);
                    pos += 2;
                    PyValue::Int(i64::from(if little_endian { u16::from_le_bytes(bytes) } else { u16::from_be_bytes(bytes) }))
                }
                'h' => {
                    let bytes = get_bytes_fixed::<2>(data, pos);
                    pos += 2;
                    PyValue::Int(i64::from(if little_endian { i16::from_le_bytes(bytes) } else { i16::from_be_bytes(bytes) }))
                }
                'I' | 'L' => {
                    let bytes = get_bytes_fixed::<4>(data, pos);
                    pos += 4;
                    PyValue::Int(i64::from(if little_endian { u32::from_le_bytes(bytes) } else { u32::from_be_bytes(bytes) }))
                }
                'i' | 'l' => {
                    let bytes = get_bytes_fixed::<4>(data, pos);
                    pos += 4;
                    PyValue::Int(i64::from(if little_endian { i32::from_le_bytes(bytes) } else { i32::from_be_bytes(bytes) }))
                }
                'Q' => {
                    let bytes = get_bytes_fixed::<8>(data, pos);
                    pos += 8;
                    PyValue::Int((if little_endian { u64::from_le_bytes(bytes) } else { u64::from_be_bytes(bytes) }).cast_signed())
                }
                'q' => {
                    let bytes = get_bytes_fixed::<8>(data, pos);
                    pos += 8;
                    PyValue::Int(if little_endian { i64::from_le_bytes(bytes) } else { i64::from_be_bytes(bytes) })
                }
                'f' => {
                    let bytes = get_bytes_fixed::<4>(data, pos);
                    pos += 4;
                    let v = if little_endian { f32::from_le_bytes(bytes) } else { f32::from_be_bytes(bytes) };
                    PyValue::Float(f64::from(v))
                }
                'd' => {
                    let bytes = get_bytes_fixed::<8>(data, pos);
                    pos += 8;
                    let v = if little_endian { f64::from_le_bytes(bytes) } else { f64::from_be_bytes(bytes) };
                    PyValue::Float(v)
                }
                's' => {
                    let end = (pos + count).min(data.len());
                    let b = data[pos..end].to_vec();
                    return vec![PyValue::Bytes(b)]; // 's' is treated as one item
                }
                'x' => { pos += 1; continue; }
                _ => PyValue::None,
            };
            out.push(val);
        }
    }
    out
}

fn get_bytes_fixed<const N: usize>(data: &[u8], pos: usize) -> [u8; N] {
    let mut arr = [0u8; N];
    let end = (pos + N).min(data.len());
    arr[..end - pos].copy_from_slice(&data[pos..end]);
    arr
}

// ─── Base64 helpers ──────────────────────────────────────────────────────────

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 { u32::from(chunk[1]) } else { 0 };
        let b2 = if chunk.len() > 2 { u32::from(chunk[2]) } else { 0 };
        let combined = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((combined >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((combined >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 { ALPHABET[((combined >> 6) & 0x3F) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[(combined & 0x3F) as usize] as char } else { '=' });
    }
    out
}

fn base64_decode_bytes(raw: &[u8]) -> Option<Vec<u8>> {
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

// ─── Minimal hash functions ──────────────────────────────────────────────────
// These implement the real algorithms without external crates.

fn bytes_to_hex<const N: usize>(digest: &[u8; N]) -> String {
    use std::fmt::Write as FmtWrite;
    let mut s = String::with_capacity(N * 2);
    for b in digest { let _ = write!(s, "{b:02x}"); }
    s
}

fn md5_hex(data: &[u8]) -> String {
    bytes_to_hex(&md5_digest(data))
}

fn sha1_hex(data: &[u8]) -> String {
    bytes_to_hex(&sha1_digest(data))
}

fn sha256_hex(data: &[u8]) -> String {
    bytes_to_hex(&sha256_digest(data))
}

fn sha512_hex(data: &[u8]) -> String {
    bytes_to_hex(&sha512_digest(data))
}

// MD5 implementation
fn md5_digest(data: &[u8]) -> [u8; 16] {
    // Per-round shift amounts
    const S: [u32; 64] = [
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
    ];
    const K: [u32; 64] = [
        0xd76a_a478,0xe8c7_b756,0x2420_70db,0xc1bd_ceee,0xf57c_0faf,0x4787_c62a,0xa830_4613,0xfd46_9501,
        0x6980_98d8,0x8b44_f7af,0xffff_5bb1,0x895c_d7be,0x6b90_1122,0xfd98_7193,0xa679_438e,0x49b4_0821,
        0xf61e_2562,0xc040_b340,0x265e_5a51,0xe9b6_c7aa,0xd62f_105d,0x0244_1453,0xd8a1_e681,0xe7d3_fbc8,
        0x21e1_cde6,0xc337_07d6,0xf4d5_0d87,0x455a_14ed,0xa9e3_e905,0xfcef_a3f8,0x676f_02d9,0x8d2a_4c8a,
        0xfffa_3942,0x8771_f681,0x6d9d_6122,0xfde5_380c,0xa4be_ea44,0x4bde_cfa9,0xf6bb_4b60,0xbebf_bc70,
        0x289b_7ec6,0xeaa1_27fa,0xd4ef_3085,0x0488_1d05,0xd9d4_d039,0xe6db_99e5,0x1fa2_7cf8,0xc4ac_5665,
        0xf429_2244,0x432a_ff97,0xab94_23a7,0xfc93_a039,0x655b_59c3,0x8f0c_cc92,0xffef_f47d,0x8584_5dd1,
        0x6fa8_7e4f,0xfe2c_e6e0,0xa301_4314,0x4e08_11a1,0xf753_7e82,0xbd3a_f235,0x2ad7_d2bb,0xeb86_d391,
    ];

    let msg_len = data.len();
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    let bit_len = (msg_len as u64).wrapping_mul(8);
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xefcd_ab89;
    let mut c0: u32 = 0x98ba_dcfe;
    let mut d0: u32 = 0x1032_5476;

    for chunk in msg.chunks_exact(64) {
        let mut block = [0u32; 16];
        for (idx, word) in block.iter_mut().enumerate() {
            let byte_pos = idx * 4;
            *word = u32::from_le_bytes([chunk[byte_pos], chunk[byte_pos+1], chunk[byte_pos+2], chunk[byte_pos+3]]);
        }
        let (mut aa, mut bb, mut cc, mut dd) = (a0, b0, c0, d0);
        for round in 0..64u32 {
            let (mix_val, word_idx) = match round {
                0..=15 => ((bb & cc) | (!bb & dd), round),
                16..=31 => ((dd & bb) | (!dd & cc), (5*round + 1) % 16),
                32..=47 => (bb ^ cc ^ dd, (3*round + 5) % 16),
                _ => (cc ^ (bb | !dd), (7*round) % 16),
            };
            let temp = dd;
            dd = cc;
            cc = bb;
            bb = bb.wrapping_add(aa.wrapping_add(mix_val).wrapping_add(K[round as usize]).wrapping_add(block[word_idx as usize]).rotate_left(S[round as usize]));
            aa = temp;
        }
        a0 = a0.wrapping_add(aa);
        b0 = b0.wrapping_add(bb);
        c0 = c0.wrapping_add(cc);
        d0 = d0.wrapping_add(dd);
    }

    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&a0.to_le_bytes());
    result[4..8].copy_from_slice(&b0.to_le_bytes());
    result[8..12].copy_from_slice(&c0.to_le_bytes());
    result[12..16].copy_from_slice(&d0.to_le_bytes());
    result
}

fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let msg_len = data.len();
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&((msg_len as u64) * 8).to_be_bytes());

    let mut state = [0x6745_2301_u32, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];

    for chunk in msg.chunks_exact(64) {
        let mut schedule = [0u32; 80];
        for (idx, item) in schedule[..16].iter_mut().enumerate() {
            let byte_pos = idx * 4;
            *item = u32::from_be_bytes([chunk[byte_pos], chunk[byte_pos+1], chunk[byte_pos+2], chunk[byte_pos+3]]);
        }
        let mut wi = 16usize;
        while wi < 80 { schedule[wi] = (schedule[wi-3] ^ schedule[wi-8] ^ schedule[wi-14] ^ schedule[wi-16]).rotate_left(1); wi += 1; }

        let (mut sa, mut sb, mut sc, mut sd, mut se) = (state[0], state[1], state[2], state[3], state[4]);
        let mut ri = 0usize;
        while ri < 80 {
            let (mix_val, round_const) = match ri {
                0..=19 => ((sb & sc) | (!sb & sd), 0x5A82_7999_u32),
                20..=39 => (sb ^ sc ^ sd, 0x6ED9_EBA1),
                40..=59 => ((sb & sc) | (sb & sd) | (sc & sd), 0x8F1B_BCDC),
                _ => (sb ^ sc ^ sd, 0xCA62_C1D6),
            };
            let temp = sa.rotate_left(5).wrapping_add(mix_val).wrapping_add(se).wrapping_add(round_const).wrapping_add(schedule[ri]);
            se = sd; sd = sc; sc = sb.rotate_left(30); sb = sa; sa = temp;
            ri += 1;
        }
        state[0] = state[0].wrapping_add(sa); state[1] = state[1].wrapping_add(sb);
        state[2] = state[2].wrapping_add(sc); state[3] = state[3].wrapping_add(sd);
        state[4] = state[4].wrapping_add(se);
    }

    let mut out = [0u8; 20];
    for (idx, &word) in state.iter().enumerate() { out[idx*4..idx*4+4].copy_from_slice(&word.to_be_bytes()); }
    out
}

fn sha256_digest(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a_2f98,0x7137_4491,0xb5c0_fbcf,0xe9b5_dba5,0x3956_c25b,0x59f1_11f1,0x923f_82a4,0xab1c_5ed5,
        0xd807_aa98,0x1283_5b01,0x2431_85be,0x550c_7dc3,0x72be_5d74,0x80de_b1fe,0x9bdc_06a7,0xc19b_f174,
        0xe49b_69c1,0xefbe_4786,0x0fc1_9dc6,0x240c_a1cc,0x2de9_2c6f,0x4a74_84aa,0x5cb0_a9dc,0x76f9_88da,
        0x983e_5152,0xa831_c66d,0xb003_27c8,0xbf59_7fc7,0xc6e0_0bf3,0xd5a7_9147,0x06ca_6351,0x1429_2967,
        0x27b7_0a85,0x2e1b_2138,0x4d2c_6dfc,0x5338_0d13,0x650a_7354,0x766a_0abb,0x81c2_c92e,0x9272_2c85,
        0xa2bf_e8a1,0xa81a_664b,0xc24b_8b70,0xc76c_51a3,0xd192_e819,0xd699_0624,0xf40e_3585,0x106a_a070,
        0x19a4_c116,0x1e37_6c08,0x2748_774c,0x34b0_bcb5,0x391c_0cb3,0x4ed8_aa4a,0x5b9c_ca4f,0x682e_6ff3,
        0x748f_82ee,0x78a5_636f,0x84c8_7814,0x8cc7_0208,0x90be_fffa,0xa450_6ceb,0xbef9_a3f7,0xc671_78f2,
    ];
    let msg_len = data.len();
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&((msg_len as u64) * 8).to_be_bytes());

    let mut state = [0x6a09_e667_u32, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19];

    for chunk in msg.chunks_exact(64) {
        let mut schedule = [0u32; 64];
        for (idx, item) in schedule[..16].iter_mut().enumerate() { let bp = idx*4; *item = u32::from_be_bytes([chunk[bp],chunk[bp+1],chunk[bp+2],chunk[bp+3]]); }
        let mut wi = 16usize;
        while wi < 64 {
            let sig0 = schedule[wi-15].rotate_right(7) ^ schedule[wi-15].rotate_right(18) ^ (schedule[wi-15] >> 3);
            let sig1 = schedule[wi-2].rotate_right(17) ^ schedule[wi-2].rotate_right(19) ^ (schedule[wi-2] >> 10);
            schedule[wi] = schedule[wi-16].wrapping_add(sig0).wrapping_add(schedule[wi-7]).wrapping_add(sig1);
            wi += 1;
        }
        let (mut sa,mut sb,mut sc,mut sd,mut se,mut mix_f,mut mix_g,mut hh) = (state[0],state[1],state[2],state[3],state[4],state[5],state[6],state[7]);
        let mut ri = 0usize;
        while ri < 64 {
            let ep1 = se.rotate_right(6) ^ se.rotate_right(11) ^ se.rotate_right(25);
            let ch = (se & mix_f) ^ (!se & mix_g);
            let t1 = hh.wrapping_add(ep1).wrapping_add(ch).wrapping_add(K[ri]).wrapping_add(schedule[ri]);
            let ep0 = sa.rotate_right(2) ^ sa.rotate_right(13) ^ sa.rotate_right(22);
            let maj = (sa & sb) ^ (sa & sc) ^ (sb & sc);
            let t2 = ep0.wrapping_add(maj);
            hh=mix_g; mix_g=mix_f; mix_f=se; se=sd.wrapping_add(t1); sd=sc; sc=sb; sb=sa; sa=t1.wrapping_add(t2);
            ri += 1;
        }
        state[0]=state[0].wrapping_add(sa); state[1]=state[1].wrapping_add(sb); state[2]=state[2].wrapping_add(sc); state[3]=state[3].wrapping_add(sd);
        state[4]=state[4].wrapping_add(se); state[5]=state[5].wrapping_add(mix_f); state[6]=state[6].wrapping_add(mix_g); state[7]=state[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (idx, &word) in state.iter().enumerate() { out[idx*4..idx*4+4].copy_from_slice(&word.to_be_bytes()); }
    out
}

fn sha512_digest(data: &[u8]) -> [u8; 64] {
    // SHA-512 round constants (must precede statements).
    const K: [u64; 80] = [
        0x428a_2f98_d728_ae22,0x7137_4491_23ef_65cd,0xb5c0_fbcf_ec4d_3b2f,0xe9b5_dba5_8189_dbbc,
        0x3956_c25b_f348_b538,0x59f1_11f1_b605_d019,0x923f_82a4_af19_4f9b,0xab1c_5ed5_da6d_8118,
        0xd807_aa98_a303_0242,0x1283_5b01_4570_6fbe,0x2431_85be_4ee4_b28c,0x550c_7dc3_d5ff_b4e2,
        0x72be_5d74_f27b_896f,0x80de_b1fe_3b16_96b1,0x9bdc_06a7_25c7_1235,0xc19b_f174_cf69_2694,
        0xe49b_69c1_9ef1_4ad2,0xefbe_4786_384f_25e3,0x0fc1_9dc6_8b8c_d5b5,0x240c_a1cc_77ac_9c65,
        0x2de9_2c6f_592b_0275,0x4a74_84aa_6ea6_e483,0x5cb0_a9dc_bd41_fbd4,0x76f9_88da_8311_53b5,
        0x983e_5152_ee66_dfab,0xa831_c66d_2db4_3210,0xb003_27c8_98fb_213f,0xbf59_7fc7_beef_0ee4,
        0xc6e0_0bf3_3da8_8fc2,0xd5a7_9147_930a_a725,0x06ca_6351_e003_826f,0x1429_2967_0a0e_6e70,
        0x27b7_0a85_46d2_2ffc,0x2e1b_2138_5c26_c926,0x4d2c_6dfc_5ac4_2aed,0x5338_0d13_9d95_b3df,
        0x650a_7354_8baf_63de,0x766a_0abb_3c77_b2a8,0x81c2_c92e_47ed_aee6,0x9272_2c85_1482_353b,
        0xa2bf_e8a1_4cf1_0364,0xa81a_664b_bc42_3001,0xc24b_8b70_d0f8_9791,0xc76c_51a3_0654_be30,
        0xd192_e819_d6ef_5218,0xd699_0624_5565_a910,0xf40e_3585_5771_202a,0x106a_a070_32bb_d1b8,
        0x19a4_c116_b8d2_d0c8,0x1e37_6c08_5141_ab53,0x2748_774c_df8e_eb99,0x34b0_bcb5_e19b_48a8,
        0x391c_0cb3_c5c9_5a63,0x4ed8_aa4a_e341_8acb,0x5b9c_ca4f_7763_e373,0x682e_6ff3_d6b2_b8a3,
        0x748f_82ee_5def_b2fc,0x78a5_636f_4317_2f60,0x84c8_7814_a1f0_ab72,0x8cc7_0208_1a64_39ec,
        0x90be_fffa_2363_1e28,0xa450_6ceb_de82_bde9,0xbef9_a3f7_b2c6_7915,0xc671_78f2_e372_532b,
        0xca27_3ece_ea26_619c,0xd186_b8c7_21c0_c207,0xeada_7dd6_cde0_eb1e,0xf57d_4f7f_ee6e_d178,
        0x06f0_67aa_7217_6fba,0x0a63_7dc5_a2c8_98a6,0x113f_9804_bef9_0dae,0x1b71_0b35_131c_471b,
        0x28db_77f5_2304_7d84,0x32ca_ab7b_40c7_2493,0x3c9e_be0a_15c9_bebc,0x431d_67c4_9c10_0d4c,
        0x4cc5_d4be_cb3e_42b6,0x597f_299c_fc65_7e2a,0x5fcb_6fab_3ad6_faec,0x6c44_198c_4a47_5817,
    ];
    // Initialise using SHA-512 IV (after const to avoid items-after-statements lint).
    let mut state: [u64; 8] = [
        0x6a09_e667_f3bc_c908, 0xbb67_ae85_84ca_a73b, 0x3c6e_f372_fe94_f82b, 0xa54f_f53a_5f1d_36f1,
        0x510e_527f_ade6_82d1, 0x9b05_688c_2b3e_6c1f, 0x1f83_d9ab_fb41_bd6b, 0x5be0_cd19_137e_2179,
    ];
    let msg_len = data.len();
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 128 != 112 { msg.push(0); }
    msg.extend_from_slice(&[0u8; 8]); // high 64 bits of 128-bit length
    msg.extend_from_slice(&((msg_len as u64) * 8).to_be_bytes());

    for chunk in msg.chunks_exact(128) {
        let mut schedule = [0u64; 80];
        for (idx, item) in schedule[..16].iter_mut().enumerate() { let bp=idx*8; *item=u64::from_be_bytes([chunk[bp],chunk[bp+1],chunk[bp+2],chunk[bp+3],chunk[bp+4],chunk[bp+5],chunk[bp+6],chunk[bp+7]]); }
        let mut wi = 16usize;
        while wi < 80 {
            let sig0=schedule[wi-15].rotate_right(1)^schedule[wi-15].rotate_right(8)^(schedule[wi-15]>>7);
            let sig1=schedule[wi-2].rotate_right(19)^schedule[wi-2].rotate_right(61)^(schedule[wi-2]>>6);
            schedule[wi]=schedule[wi-16].wrapping_add(sig0).wrapping_add(schedule[wi-7]).wrapping_add(sig1);
            wi += 1;
        }
        let (mut sa,mut sb,mut sc,mut sd,mut se,mut mix_f,mut mix_g,mut hh)=(state[0],state[1],state[2],state[3],state[4],state[5],state[6],state[7]);
        let mut ri = 0usize;
        while ri < 80 {
            let ep1=se.rotate_right(14)^se.rotate_right(18)^se.rotate_right(41);
            let ch=(se&mix_f)^(!se&mix_g);
            let t1=hh.wrapping_add(ep1).wrapping_add(ch).wrapping_add(K[ri]).wrapping_add(schedule[ri]);
            let ep0=sa.rotate_right(28)^sa.rotate_right(34)^sa.rotate_right(39);
            let maj=(sa&sb)^(sa&sc)^(sb&sc);
            let t2=ep0.wrapping_add(maj);
            hh=mix_g;mix_g=mix_f;mix_f=se;se=sd.wrapping_add(t1);sd=sc;sc=sb;sb=sa;sa=t1.wrapping_add(t2);
            ri += 1;
        }
        state[0]=state[0].wrapping_add(sa);state[1]=state[1].wrapping_add(sb);state[2]=state[2].wrapping_add(sc);state[3]=state[3].wrapping_add(sd);
        state[4]=state[4].wrapping_add(se);state[5]=state[5].wrapping_add(mix_f);state[6]=state[6].wrapping_add(mix_g);state[7]=state[7].wrapping_add(hh);
    }
    let mut out = [0u8; 64];
    for (idx, &word) in state.iter().enumerate() { out[idx*8..idx*8+8].copy_from_slice(&word.to_be_bytes()); }
    out
}

// ─── JSON helpers (minimal, for stub json module) ─────────────────────────────

fn pyvalue_to_json(v: &PyValue) -> String {
    match v {
        PyValue::None => "null".into(),
        PyValue::Bool(b) => if *b { "true".into() } else { "false".into() },
        PyValue::Int(i) => i.to_string(),
        PyValue::Float(f) => format!("{f}"),
        PyValue::Str(s) => format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")),
        PyValue::Bytes(b) => format!("\"{}\"", base64_encode(b)),
        PyValue::List(v) | PyValue::Tuple(v) | PyValue::Set(v) => {
            let items: Vec<String> = v.iter().map(pyvalue_to_json).collect();
            format!("[{}]", items.join(","))
        }
        PyValue::Dict(pairs) => {
            let items: Vec<String> = pairs.iter().map(|(k, val)| format!("{}:{}", pyvalue_to_json(k), pyvalue_to_json(val))).collect();
            format!("{{{}}}", items.join(","))
        }
        }
}

fn json_to_pyvalue(s: &str) -> PyValue {
    let s = s.trim();
    if s == "null" { return PyValue::None; }
    if s == "true" { return PyValue::Bool(true); }
    if s == "false" { return PyValue::Bool(false); }
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        return PyValue::Str(s[1..s.len()-1].replace("\\\"", "\"").replace("\\\\", "\\"));
    }
    if let Ok(i) = s.parse::<i64>() { return PyValue::Int(i); }
    if let Ok(f) = s.parse::<f64>() { return PyValue::Float(f); }
    if s.starts_with('[') && s.ends_with(']') {
        return PyValue::List(Vec::new()); // simplified: don't recurse
    }
    if s.starts_with('{') && s.ends_with('}') {
        return PyValue::Dict(Vec::new()); // simplified
    }
    PyValue::Str(s.to_owned())
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn stubs() -> StdlibStubs { StdlibStubs::new() }

    #[test]
    fn test_os_path_join() {
        let v = stubs().call("os.path", "join", &[PyValue::Str("a".into()), PyValue::Str("b".into())]);
        assert_eq!(v, Some(PyValue::Str("a/b".into())));
    }

    #[test]
    fn test_os_path_basename() {
        let v = stubs().call("os.path", "basename", &[PyValue::Str("/foo/bar/baz.txt".into())]);
        assert_eq!(v, Some(PyValue::Str("baz.txt".into())));
    }

    #[test]
    fn test_os_path_dirname() {
        let v = stubs().call("os.path", "dirname", &[PyValue::Str("/foo/bar/baz.txt".into())]);
        assert_eq!(v, Some(PyValue::Str("/foo/bar".into())));
    }

    #[test]
    fn test_os_path_splitext() {
        let v = stubs().call("os.path", "splitext", &[PyValue::Str("file.exe".into())]);
        assert_eq!(v, Some(PyValue::Tuple(vec![PyValue::Str("file".into()), PyValue::Str(".exe".into())])));
    }

    #[test]
    fn test_struct_pack_unpack_u32() {
        let args_pack = vec![PyValue::Str("<I".into()), PyValue::Int(0x1234_5678)];
        let packed = stubs().call("struct", "pack", &args_pack).unwrap();
        let bytes = if let PyValue::Bytes(b) = &packed { b.clone() } else { panic!("expected bytes") };
        assert_eq!(bytes, vec![0x78, 0x56, 0x34, 0x12]);

        let args_unpack = vec![PyValue::Str("<I".into()), PyValue::Bytes(bytes)];
        let unpacked = stubs().call("struct", "unpack", &args_unpack).unwrap();
        if let PyValue::Tuple(v) = unpacked {
            assert_eq!(v[0], PyValue::Int(0x1234_5678));
        } else { panic!("expected tuple"); }
    }

    #[test]
    fn test_struct_calcsize() {
        let v = stubs().call("struct", "calcsize", &[PyValue::Str("<IHB".into())]);
        assert_eq!(v, Some(PyValue::Int(7)));
    }

    #[test]
    fn test_binascii_hexlify() {
        let v = stubs().call("binascii", "hexlify", &[PyValue::Bytes(b"Hello".to_vec())]);
        if let Some(PyValue::Bytes(b)) = v {
            assert_eq!(String::from_utf8(b).unwrap(), "48656c6c6f");
        } else { panic!("expected bytes"); }
    }

    #[test]
    fn test_binascii_unhexlify() {
        let v = stubs().call("binascii", "unhexlify", &[PyValue::Str("48656c6c6f".into())]);
        assert_eq!(v, Some(PyValue::Bytes(b"Hello".to_vec())));
    }

    #[test]
    fn test_binascii_b2a_a2b_base64() {
        let data = b"Hello World".to_vec();
        let encoded = stubs().call("binascii", "b2a_base64", &[PyValue::Bytes(data.clone())]);
        if let Some(PyValue::Bytes(enc)) = encoded {
            let enc_str = String::from_utf8(enc).unwrap();
            let enc_trimmed = enc_str.trim();
            let decoded = stubs().call("binascii", "a2b_base64", &[PyValue::Bytes(enc_trimmed.as_bytes().to_vec())]);
            assert_eq!(decoded, Some(PyValue::Bytes(data)));
        } else { panic!("encode failed"); }
    }

    #[test]
    fn test_hashlib_md5() {
        let v = stubs().call("hashlib", "md5", &[PyValue::Bytes(b"".to_vec())]);
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        assert_eq!(v, Some(PyValue::Str("d41d8cd98f00b204e9800998ecf8427e".into())));
    }

    #[test]
    fn test_hashlib_sha1() {
        let v = stubs().call("hashlib", "sha1", &[PyValue::Bytes(b"".to_vec())]);
        // SHA1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        assert_eq!(v, Some(PyValue::Str("da39a3ee5e6b4b0d3255bfef95601890afd80709".into())));
    }

    #[test]
    fn test_hashlib_sha256() {
        let v = stubs().call("hashlib", "sha256", &[PyValue::Bytes(b"".to_vec())]);
        // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(v, Some(PyValue::Str("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into())));
    }

    #[test]
    fn test_re_findall() {
        let v = stubs().call("re", "findall", &[PyValue::Str("l".into()), PyValue::Str("hello world".into())]);
        if let Some(PyValue::List(items)) = v {
            assert_eq!(items.len(), 3);
        } else { panic!("expected list"); }
    }

    #[test]
    fn test_re_sub() {
        let v = stubs().call("re", "sub", &[PyValue::Str("o".into()), PyValue::Str("0".into()), PyValue::Str("hello world".into())]);
        assert_eq!(v, Some(PyValue::Str("hell0 w0rld".into())));
    }

    #[test]
    fn test_json_dumps_loads_int() {
        let v = stubs().call("json", "dumps", &[PyValue::Int(42)]);
        assert_eq!(v, Some(PyValue::Str("42".into())));
        let v2 = stubs().call("json", "loads", &[PyValue::Str("42".into())]);
        assert_eq!(v2, Some(PyValue::Int(42)));
    }

    #[test]
    fn test_sys_platform() {
        let v = stubs().call("sys", "platform", &[]);
        assert_eq!(v, Some(PyValue::Str("rustre-sandbox".into())));
    }

    #[test]
    fn test_pyvalue_truthy() {
        assert!(!PyValue::None.is_truthy());
        assert!(PyValue::Int(1).is_truthy());
        assert!(!PyValue::Int(0).is_truthy());
        assert!(PyValue::Str("hi".into()).is_truthy());
    }
}
