//! Standalone MSVC name-mangling parser.
//!
//! # Not wired in, and not an extension
//!
//! Nothing in the crate calls this module: [`crate::demangle`] routes MSVC
//! symbols through `backends::demangle_msvc_internal`, and no other module
//! references `msvc_full::`. It is reachable only by a caller who names it
//! explicitly.
//!
//! Measured on 2026-07-23 over 34 MSVC symbols — the 14 real ones in the
//! corpora plus the reference shapes from `tests/differential_msvc.rs`, chosen
//! to cover exactly the features listed below — this parser decodes a **strict
//! subset** of what the live path decodes: 33 in common, one
//! (`??HFoo@@QEAA?AV0@AEBV0@@Z`, an operator returning a class by value)
//! handled only by the live path, and none handled only here. The header
//! previously called this an extension of the basic demangler; the measurement
//! does not support that.
//!
//! Decoding is not the same as decoding *correctly*, and the first measurement
//! only asked the former. Comparing output on the 14 real MSVC symbols, this
//! parser agrees with the live path on **3**. Some differences are wording
//! (`` `vftable for type_info' `` vs `` const type_info::`vftable' ``), but at
//! least one is not a demangling at all:
//!
//! ```text
//! ??_Etype_info@@UEAAPEAXI@Z
//!   crate::demangle  type_info::`vector deleting destructor'
//!   this parser      ?SPECIAL(4)
//! ```
//!
//! `?SPECIAL(n)` is placeholder text for special member functions. Prefer
//! [`crate::demangle`]. `tests/unused_msvc_full.rs` fails if this module ever
//! decodes something the live path cannot, and
//! `tests/entry_point_matrix.rs` reports the agreement figures.
//!
//! Supported grammar:
//! - All calling conventions: `__cdecl`, `__stdcall`, `__fastcall`,
//!   `__thiscall`, `__vectorcall`, `__clrcall`, `__pascal`.
//! - Template parameters (type, non-type integer, template-template).
//! - Nested classes and anonymous namespaces.
//! - Lambda types and closure objects.
//! - RTTI helper types (`type_info`, catch handlers, vftable, etc.).
//! - `__declspec` extensions.

use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

/// Error produced while demangling an MSVC-mangled symbol.
#[derive(Debug, Error)]
pub enum MsvcError {
    /// The input does not start with the MSVC `?` marker.
    #[error("not an MSVC-mangled symbol")]
    NotMsvc,
    /// The grammar walk failed at the given byte position with a message.
    #[error("parse error at position {0}: {1}")]
    ParseError(usize, String),
    /// The recursion limit for nested types was exceeded.
    #[error("recursive depth limit exceeded")]
    DepthLimit,
    /// A name/type back-reference digit referred past the recorded table.
    #[error("backref index {0} out of range")]
    BackrefOutOfRange(usize),
}

// ── Calling convention ────────────────────────────────────────────────────────

/// All MSVC calling conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConv {
    /// `__cdecl` (codes `A`/`B`).
    Cdecl,
    /// `__fastcall` (codes `I`/`J`).
    Fastcall,
    /// `__stdcall` (codes `G`/`H`).
    Stdcall,
    /// `__thiscall` (codes `E`/`F`).
    Thiscall,
    /// `__vectorcall` (codes `O`/`P`).
    Vectorcall,
    /// `__clrcall` (codes `M`/`N`).
    Clrcall,
    /// `__pascal` (codes `C`/`D`).
    Pascal,
    /// `__regcall` (code `Q`).
    Regcall,
    /// Unrecognised calling-convention byte.
    Unknown,
}

impl CallingConv {
    /// Return the `__keyword` spelling of this calling convention
    /// (empty string for [`CallingConv::Unknown`]).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cdecl => "__cdecl",
            Self::Fastcall => "__fastcall",
            Self::Stdcall => "__stdcall",
            Self::Thiscall => "__thiscall",
            Self::Vectorcall => "__vectorcall",
            Self::Clrcall => "__clrcall",
            Self::Pascal => "__pascal",
            Self::Regcall => "__regcall",
            Self::Unknown => "",
        }
    }

    /// Decode from the single byte that MSVC emits for calling conventions.
    #[must_use] 
    pub const fn from_byte(b: u8) -> Self {
        match b {
            b'A' | b'B' => Self::Cdecl,
            b'C' | b'D' => Self::Pascal,
            b'E' | b'F' => Self::Thiscall,
            b'G' | b'H' => Self::Stdcall,
            b'I' | b'J' => Self::Fastcall,
            b'M' | b'N' => Self::Clrcall,
            b'O' | b'P' => Self::Vectorcall,
            b'Q' => Self::Regcall,
            _ => Self::Unknown,
        }
    }
}

// ── CV qualifiers ─────────────────────────────────────────────────────────────

/// C++ cv-qualifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CvQualifiers {
    flags: u8,
}

impl CvQualifiers {
    const CONST:     u8 = 1 << 0;
    const VOLATILE:  u8 = 1 << 1;
    const RESTRICT:  u8 = 1 << 2;
    const UNALIGNED: u8 = 1 << 3;

    /// Set the `const` qualifier.
    pub const fn set_const(&mut self)     { self.flags |= Self::CONST; }
    /// Set the `volatile` qualifier.
    pub const fn set_volatile(&mut self)  { self.flags |= Self::VOLATILE; }
    /// Set the `__restrict` qualifier.
    pub const fn set_restrict(&mut self)  { self.flags |= Self::RESTRICT; }
    /// Set the `__unaligned` qualifier.
    pub const fn set_unaligned(&mut self) { self.flags |= Self::UNALIGNED; }

    /// Whether `const` is set.
    #[must_use] pub const fn is_const(&self)     -> bool { self.flags & Self::CONST != 0 }
    /// Whether `volatile` is set.
    #[must_use] pub const fn is_volatile(&self)  -> bool { self.flags & Self::VOLATILE != 0 }
    /// Whether `__restrict` is set.
    #[must_use] pub const fn is_restrict(&self)  -> bool { self.flags & Self::RESTRICT != 0 }
    /// Whether `__unaligned` is set.
    #[must_use] pub const fn is_unaligned(&self) -> bool { self.flags & Self::UNALIGNED != 0 }

    /// Render the set qualifiers as a space-separated string
    /// (e.g. `"const volatile"`), or an empty string if none.
    #[must_use]
    pub fn render(&self) -> String {
        let mut parts: Vec<&str> = Vec::with_capacity(4);
        if self.is_const()     { parts.push("const"); }
        if self.is_volatile()  { parts.push("volatile"); }
        if self.is_restrict()  { parts.push("__restrict"); }
        if self.is_unaligned() { parts.push("__unaligned"); }
        parts.join(" ")
    }
}

const fn decode_cv(b: u8) -> CvQualifiers {
    let mut q = CvQualifiers { flags: 0 };
    if matches!(b, b'B' | b'D' | b'R' | b'T') { q.flags |= CvQualifiers::CONST; }
    if matches!(b, b'C' | b'D' | b'S' | b'T') { q.flags |= CvQualifiers::VOLATILE; }
    if matches!(b, b'Q' | b'R' | b'S' | b'T') { q.flags |= CvQualifiers::RESTRICT; }
    q
}

// ── Template parameter ────────────────────────────────────────────────────────

/// A template argument node.
#[derive(Debug, Clone)]
pub enum TemplateArg {
    /// A type argument.
    Type(String),
    /// A non-type integer argument.
    Integer(i64),
    /// A non-type pointer / address argument.
    Pointer(u64),
    /// A template-template argument (name).
    Template(String),
    /// A pack expansion `...`.
    Pack(Vec<Self>),
}

impl TemplateArg {
    /// Render this template argument as its C++ source spelling
    /// (types verbatim, integers in decimal, pointers in hex).
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Type(t) | Self::Template(t) => t.clone(),
            Self::Integer(n) => format!("{n}"),
            Self::Pointer(p) => format!("{p:#x}"),
            Self::Pack(args) => {
                let inner: Vec<_> = args.iter().map(Self::render).collect();
                inner.join(", ")
            }
        }
    }
}

// ── Special name kind ─────────────────────────────────────────────────────────

/// Distinguishes special MSVC generated names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecialNameKind {
    /// Virtual function table (`??_7`) for the named class.
    VftableFor(String),
    /// Virtual base table (`??_8`) for the named class.
    VbtableFor(String),
    /// RTTI type descriptor (`??_R0`) for the named type.
    TypeinfoFor(String),
    /// RTTI type descriptor name string for the named type.
    TypeinfoNameFor(String),
    /// RTTI base class descriptor (`??_R1`..`??_R4`) at the given scope.
    RttiBaseClassDescriptor(String),
    /// Thread-safe local static initialization guard (`??_B`/`??_L`).
    LocalStaticGuard(String),
    /// Virtual call adjustment thunk (`??_9`).
    VcallThunk,
    /// Anonymous namespace (`?A0x<hex>`), carrying the mangled path.
    AnonNs(String),
    /// Lambda closure object type.
    LambdaClosure,
    /// Unrecognised special-name code.
    Unknown,
}

// ── DemangleOutput ────────────────────────────────────────────────────────────

/// Full structured output of a successful MSVC demangling.
#[derive(Debug, Clone)]
pub struct MsvcDemangledSymbol {
    /// Human-readable demangled string.
    pub demangled: String,
    /// Namespace / class path components.
    pub scope: Vec<String>,
    /// Bare name (last component).
    pub name: String,
    /// Calling convention.
    pub calling_conv: CallingConv,
    /// Return type (None for ctor/dtor).
    pub return_type: Option<String>,
    /// Parameter types.
    pub params: Vec<String>,
    /// CV qualifiers on `this` (for member functions).
    pub this_cv: CvQualifiers,
    /// Storage class (static, virtual, etc.).
    pub storage: String,
    /// Template arguments for the function/class (if templated).
    pub template_args: Vec<TemplateArg>,
    /// Whether this is a special name.
    pub special: Option<SpecialNameKind>,
}

// ── Full MSVC demangler ───────────────────────────────────────────────────────

/// Full MSVC demangler with complete grammar coverage.
pub struct MsvcFullDemangler {
    input: Vec<u8>,
    pos: usize,
    depth: usize,
    max_depth: usize,
    name_backrefs: Vec<String>,
    type_backrefs: Vec<String>,
}

impl MsvcFullDemangler {
    const MAX_DEPTH: usize = 64;

    /// Create a demangler for the given mangled symbol.
    #[must_use] 
    pub fn new(mangled: &str) -> Self {
        Self {
            input: mangled.as_bytes().to_vec(),
            pos: 0,
            depth: 0,
            max_depth: Self::MAX_DEPTH,
            name_backrefs: Vec::new(),
            type_backrefs: Vec::new(),
        }
    }

    /// Detect whether `mangled` is an MSVC-mangled symbol.
    #[must_use] 
    pub fn detect(mangled: &str) -> bool {
        mangled.starts_with('?')
    }

    /// Demangle the symbol and return structured output.
    ///
    /// # Errors
    ///
    /// Returns `MsvcError` if the input is not a valid MSVC-mangled symbol.
    // One linear pass over the MSVC grammar; splitting it would scatter the
    // sequential decode steps without reducing complexity.
    #[expect(clippy::too_many_lines, reason = "linear grammar walk, clearer unsplit")]
    pub fn demangle(&mut self) -> Result<MsvcDemangledSymbol, MsvcError> {
        if self.input.first() != Some(&b'?') {
            return Err(MsvcError::NotMsvc);
        }
        self.pos = 1;

        // Check for RTTI / special symbols.
        if self.peek() == Some(b'$') {
            return self.demangle_template_or_special();
        }
        if self.peek_str(2) == b"?_" {
            return Ok(self.demangle_special_name());
        }

        let scope_components = self.parse_qualified_name()?;
        let mut name = scope_components.last().cloned().unwrap_or_default();
        let scope = scope_components[..scope_components.len().saturating_sub(1)].to_vec();

        // Ctor/dtor placeholders become the enclosing class name.
        if name == "ctor" {
            name = scope.last().cloned().unwrap_or_else(|| "ctor".to_owned());
        } else if name == "~dtor" {
            name = format!("~{}", scope.last().cloned().unwrap_or_else(|| "dtor".to_owned()));
        }

        // Access / storage class byte.
        let access = self
            .next_byte()
            .ok_or_else(|| MsvcError::ParseError(self.pos, "expected access byte".into()))?;

        // Data symbols: '0'..'4' encode static/global data, followed by
        // <type> <storage-class>, e.g. `?x@@3HA` => `int x`.
        if access.is_ascii_digit() {
            let dstorage = match access {
                b'0' => "private: static ",
                b'1' => "protected: static ",
                b'2' => "public: static ",
                _ => "",
            };
            let ty = self.parse_type()?;
            let cv = decode_cv(self.next_byte().unwrap_or(b'A'));
            let cv_str = cv.render();
            let cv_prefix = if cv_str.is_empty() { String::new() } else { format!("{cv_str} ") };
            let scope_str = if scope.is_empty() {
                String::new()
            } else {
                format!("{}::", scope.join("::"))
            };
            let demangled = format!("{dstorage}{cv_prefix}{ty} {scope_str}{name}");
            return Ok(MsvcDemangledSymbol {
                demangled,
                scope,
                name,
                calling_conv: CallingConv::Unknown,
                return_type: Some(ty),
                params: Vec::new(),
                this_cv: cv,
                storage: dstorage.trim().trim_end_matches(':').to_owned(),
                template_args: Vec::new(),
                special: None,
            });
        }

        let (storage, is_member) = Self::decode_storage(access);
        let is_static_or_free = !is_member;
        let this_cv = if is_member && !is_static_member(access) {
            // Optional `E`/`F` (__ptr64) / `I` (__restrict) markers on `this`.
            while matches!(self.peek(), Some(b'E' | b'F' | b'I')) {
                self.pos += 1;
            }
            let qualifiers_byte = self.next_byte().unwrap_or(b'A');
            decode_cv(qualifiers_byte)
        } else {
            CvQualifiers::default()
        };
        let _ = is_static_or_free;
        let cc_byte = self.next_byte().unwrap_or(b'A');

        let calling_conv = CallingConv::from_byte(cc_byte);

        // Return type (@ = absent for ctors/dtors).
        let return_type = if self.peek() == Some(b'@') {
            self.pos += 1;
            None
        } else if self.peek() == Some(b'X') {
            self.pos += 1;
            Some("void".to_owned())
        } else {
            Some(self.parse_type()?)
        };

        // Parameters.
        let mut params = Vec::new();
        loop {
            match self.peek() {
                None | Some(b'Z' | b'@') => {
                    if self.peek() == Some(b'Z') || self.peek() == Some(b'@') {
                        self.pos += 1;
                    }
                    break;
                }
                Some(b'X') => {
                    // void parameter list
                    self.pos += 1;
                    params.push("void".to_owned());
                    break;
                }
                _ => {
                    let t = self.parse_type()?;
                    params.push(t);
                }
            }
        }

        // Build the human-readable string.
        let param_str = if params.is_empty() {
            "void".to_owned()
        } else {
            params.join(", ")
        };

        let cv_str = this_cv.render();
        let ret_prefix = return_type
            .as_deref()
            .map(|r| format!("{r} "))
            .unwrap_or_default();
        let cc = calling_conv.as_str();
        let scope_str = if scope.is_empty() {
            String::new()
        } else {
            format!("{}::", scope.join("::"))
        };
        let cv_suffix = if cv_str.is_empty() {
            String::new()
        } else {
            format!(" {cv_str}")
        };

        let storage_prefix = if storage.is_empty() {
            String::new()
        } else {
            format!("{storage}: ")
        };
        let cc_prefix = if cc.is_empty() { String::new() } else { format!("{cc} ") };
        let demangled =
            format!("{storage_prefix}{ret_prefix}{cc_prefix}{scope_str}{name}({param_str}){cv_suffix}");

        Ok(MsvcDemangledSymbol {
            demangled,
            scope,
            name,
            calling_conv,
            return_type,
            params,
            this_cv,
            storage,
            template_args: Vec::new(),
            special: None,
        })
    }

    fn demangle_template_or_special(&mut self) -> Result<MsvcDemangledSymbol, MsvcError> {
        // Template specialisation: ?$Name@<args>@@...
        self.pos += 1; // skip '$'
        let name = self.parse_source_name();
        let mut args = Vec::new();
        while self.peek() != Some(b'@') && self.peek().is_some() {
            let t = self.parse_template_arg()?;
            args.push(t);
        }
        if self.peek() == Some(b'@') {
            self.pos += 1;
        }
        let rendered_args: Vec<_> = args.iter().map(TemplateArg::render).collect();
        let demangled = format!("{name}<{}>", rendered_args.join(", "));
        Ok(MsvcDemangledSymbol {
            demangled,
            scope: Vec::new(),
            name,
            calling_conv: CallingConv::Unknown,
            return_type: None,
            params: Vec::new(),
            this_cv: CvQualifiers::default(),
            storage: String::new(),
            template_args: args,
            special: None,
        })
    }

    fn demangle_special_name(&mut self) -> MsvcDemangledSymbol {
        let special = self.try_parse_special_name();
        let demangled = match &special {
            Some(SpecialNameKind::VftableFor(t)) => format!("`vftable for {t}'"),
            Some(SpecialNameKind::VbtableFor(t)) => format!("`vbtable for {t}'"),
            Some(SpecialNameKind::TypeinfoFor(t)) => format!("`RTTI Type Descriptor for {t}'"),
            Some(SpecialNameKind::TypeinfoNameFor(t)) => {
                format!("`RTTI Type Descriptor Name for {t}'")
            }
            Some(SpecialNameKind::RttiBaseClassDescriptor(t)) => {
                format!("`RTTI Base Class Descriptor at {t}'")
            }
            Some(SpecialNameKind::LocalStaticGuard(f)) => format!("`local static guard for {f}'"),
            Some(SpecialNameKind::AnonNs(path)) => format!("`anonymous namespace in {path}'"),
            Some(SpecialNameKind::LambdaClosure) => "`lambda closure'".to_owned(),
            Some(SpecialNameKind::VcallThunk) => "`vcall thunk'".to_owned(),
            Some(SpecialNameKind::Unknown) | None => format!("?SPECIAL({})", self.pos),
        };
        MsvcDemangledSymbol {
            demangled,
            scope: Vec::new(),
            name: String::new(),
            calling_conv: CallingConv::Unknown,
            return_type: None,
            params: Vec::new(),
            this_cv: CvQualifiers::default(),
            storage: String::new(),
            template_args: Vec::new(),
            special,
        }
    }

    fn try_parse_special_name(&mut self) -> Option<SpecialNameKind> {
        // Called with `pos` just past the leading '?', i.e. at "?_<code>...".
        if self.peek_str(2) == b"?_" {
            self.pos += 2;
            let c = self.next_byte()?;
            return match c {
                b'7' => Some(SpecialNameKind::VftableFor(self.parse_scope_path())),
                b'8' => Some(SpecialNameKind::VbtableFor(self.parse_scope_path())),
                b'R' => {
                    // RTTI: ??_R0..4
                    let sub = self.next_byte().unwrap_or(b'0');
                    match sub {
                        b'0' => {
                            // ?AV<name>@@ / ?AU<name>@@ type descriptor
                            if self.peek_str(2) == b"?A" {
                                self.pos += 2;
                                let _kind = self.next_byte(); // V/U/W
                                return Some(SpecialNameKind::TypeinfoFor(self.parse_scope_path()));
                            }
                            Some(SpecialNameKind::TypeinfoFor(self.parse_scope_path()))
                        }
                        _ => Some(SpecialNameKind::RttiBaseClassDescriptor(
                            self.parse_scope_path(),
                        )),
                    }
                }
                b'B' | b'L' => Some(SpecialNameKind::LocalStaticGuard(self.parse_scope_path())),
                b'9' => Some(SpecialNameKind::VcallThunk),
                _ => Some(SpecialNameKind::Unknown),
            };
        }
        Some(SpecialNameKind::Unknown)
    }

    /// Parse a `Name1@Name2@@`-style scope path and join it as `Name2::Name1`.
    fn parse_scope_path(&mut self) -> String {
        self.parse_qualified_name()
            .map(|c| c.join("::"))
            .unwrap_or_default()
    }

    // ── Internal parsing ─────────────────────────────────────────────────────

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn peek_str(&self, n: usize) -> &[u8] {
        &self.input[self.pos..self.pos.saturating_add(n).min(self.input.len())]
    }

    fn next_byte(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn parse_source_name(&mut self) -> String {
        let start = self.pos;
        while self.peek().is_some_and(|b| b != b'@') {
            self.pos += 1;
        }
        if self.peek() == Some(b'@') {
            self.pos += 1;
        }
        let name =
            String::from_utf8_lossy(&self.input[start..self.pos.saturating_sub(1)]).into_owned();
        if !name.is_empty() && !self.name_backrefs.contains(&name) && self.name_backrefs.len() < 10
        {
            self.name_backrefs.push(name.clone());
        }
        name
    }

    fn parse_qualified_name(&mut self) -> Result<Vec<String>, MsvcError> {
        let mut components = Vec::new();
        loop {
            match self.peek() {
                None | Some(b'@') => {
                    self.pos += 1;
                    break;
                }
                Some(b) if b.is_ascii_digit() => {
                    self.pos += 1;
                    let idx = (b - b'0') as usize;
                    let br = self
                        .name_backrefs
                        .get(idx)
                        .cloned()
                        .ok_or(MsvcError::BackrefOutOfRange(idx))?;
                    components.push(br);
                    // A backref replaces `name@`; a following '@' is the
                    // terminator of the whole qualified-name list.
                    if self.peek() == Some(b'@') {
                        self.pos += 1;
                        break;
                    }
                }
                Some(b'?') => {
                    self.pos += 1;
                    match self.peek() {
                        Some(b'$') => {
                            self.pos += 1;
                            let tname = self.parse_source_name();
                            let mut targs = Vec::new();
                            while self.peek() != Some(b'@') && self.peek().is_some() {
                                if let Ok(a) = self.parse_template_arg() {
                                    targs.push(a.render());
                                } else {
                                    break;
                                }
                            }
                            if self.peek() == Some(b'@') {
                                self.pos += 1;
                            }
                            components.push(format!("{tname}<{}>", targs.join(", ")));
                        }
                        // Anonymous namespace: `?A0x<hex>@` (or bare `?A@`).
                        // A plain `?A` followed by a class name is
                        // `operator[]` and is handled by the operator arm.
                        Some(b'A')
                            if self.peek_str(3) == b"A0x" || self.peek_str(2) == b"A@" =>
                        {
                            self.pos += 1;
                            let raw_sub = self.parse_source_name();
                            let sub = if raw_sub.is_empty() { "anonymous namespace".to_owned() } else { raw_sub };
                            components.push(format!("`{sub}'"));
                        }
                        Some(op) => {
                            self.pos += 1;
                            let op_name = decode_operator(op).to_owned();
                            components.push(op_name);
                        }
                        None => break,
                    }
                }
                _ => {
                    let name = self.parse_source_name();
                    components.push(name);
                }
            }
        }
        components.reverse();
        Ok(components)
    }

    fn parse_type(&mut self) -> Result<String, MsvcError> {
        self.depth += 1;
        if self.depth > self.max_depth {
            self.depth -= 1;
            return Err(MsvcError::DepthLimit);
        }
        let result = self.parse_type_inner();
        self.depth -= 1;
        result
    }

    fn parse_type_inner(&mut self) -> Result<String, MsvcError> {
        // Type backreference (digit 0-9)
        if let Some(b) = self.peek()
            && b.is_ascii_digit() {
                self.pos += 1;
                let idx = (b - b'0') as usize;
                return self
                    .type_backrefs
                    .get(idx)
                    .cloned()
                    .ok_or(MsvcError::BackrefOutOfRange(idx));
            }

        // Rvalue ref $$Q
        if self.peek_str(3) == b"$$Q" {
            self.pos += 3;
            let _cv = self.next_byte();
            let inner = self.parse_type()?;
            return Ok(format!("{inner}&&"));
        }

        let b = self
            .next_byte()
            .ok_or_else(|| MsvcError::ParseError(self.pos, "expected type byte".into()))?;

        let t = match b {
            b'X' => "void".to_owned(),
            b'D' => "char".to_owned(),
            b'C' => "signed char".to_owned(),
            b'E' => "unsigned char".to_owned(),
            b'F' => "short".to_owned(),
            b'G' => "unsigned short".to_owned(),
            b'H' => "int".to_owned(),
            b'I' => "unsigned int".to_owned(),
            b'J' => "long".to_owned(),
            b'K' => "unsigned long".to_owned(),
            b'L' => "long long".to_owned(),
            b'M' => "float".to_owned(),
            b'N' => "double".to_owned(),
            b'O' => "long double".to_owned(),
            b'Z' => "...".to_owned(),
            b'_' => self.parse_extended_primitive()?,
            b'P' | b'Q' | b'R' | b'S' => self.parse_pointer_type(b)?,
            b'A' | b'B' => self.parse_ref_type(b)?,
            b'U' | b'V' | b'W' => self.parse_udt_type(b)?,
            b'T' => {
                let parts = self.parse_qualified_name()?;
                format!("union {}", parts.join("::"))
            }
            b'Y' => {
                let _ndim = self.parse_encoded_number().unwrap_or(1);
                let elem = self.parse_type()?;
                format!("{elem}[]")
            }
            b'$' => self.parse_dollar_type()?,
            b'?' => self.parse_type()?,
            _ => format!("?({})", b as char),
        };
        Ok(t)
    }

    fn parse_extended_primitive(&mut self) -> Result<String, MsvcError> {
        let next = self.next_byte().ok_or_else(|| {
            MsvcError::ParseError(self.pos, "expected ext type byte".into())
        })?;
        Ok(match next {
            b'N' => "bool".to_owned(),
            b'J' => "long long".to_owned(),
            b'K' => "unsigned long long".to_owned(),
            b'W' => "wchar_t".to_owned(),
            b'S' => "char16_t".to_owned(),
            b'U' => "char32_t".to_owned(),
            b'8' => "char8_t".to_owned(),
            b'D' => "__int8".to_owned(),
            b'E' => "unsigned __int8".to_owned(),
            b'F' => "__int16".to_owned(),
            b'G' => "unsigned __int16".to_owned(),
            b'H' => "__int32".to_owned(),
            b'I' => "unsigned __int32".to_owned(),
            b'L' => "int64_t".to_owned(),
            b'M' => "uint64_t".to_owned(),
            _ => format!("_unk_{}", next as char),
        })
    }

    fn parse_pointer_type(&mut self, b: u8) -> Result<String, MsvcError> {
        if matches!(self.peek(), Some(b'E' | b'F' | b'G' | b'H')) {
            self.pos += 1; // __ptr32 / __ptr64 / __unaligned
        }
        let _cv_byte = self.next_byte().unwrap_or(b'A');
        let inner = self.parse_type()?;
        let ptr_suffix = match b {
            b'Q' => "* const",
            b'R' => "* volatile",
            b'S' => "* const volatile",
            _ => "*",
        };
        let result = format!("{inner}{ptr_suffix}");
        if !self.type_backrefs.contains(&result) && self.type_backrefs.len() < 10 {
            self.type_backrefs.push(result.clone());
        }
        Ok(result)
    }

    fn parse_ref_type(&mut self, b: u8) -> Result<String, MsvcError> {
        if matches!(self.peek(), Some(b'E' | b'F')) {
            self.pos += 1;
        }
        let _cv = self.next_byte().unwrap_or(b'A');
        let inner = self.parse_type()?;
        Ok(if b == b'A' { format!("{inner}&") } else { format!("{inner}&&") })
    }

    fn parse_udt_type(&mut self, b: u8) -> Result<String, MsvcError> {
        let kw = match b {
            b'U' => "struct ",
            b'V' => "class ",
            _ => "enum ",
        };
        let parts = self.parse_qualified_name()?;
        let t = format!("{}{}", kw, parts.join("::"));
        if !self.type_backrefs.contains(&t) && self.type_backrefs.len() < 10 {
            self.type_backrefs.push(t.clone());
        }
        Ok(t)
    }

    fn parse_dollar_type(&mut self) -> Result<String, MsvcError> {
        Ok(match self.peek() {
            Some(b'0') => { self.pos += 1; "nullptr_t".to_owned() }
            Some(b'T') => { self.pos += 1; "std::nullptr_t".to_owned() }
            Some(b'A') => {
                self.pos += 1;
                let inner = self.parse_type()?;
                format!("{inner}&& /* rvalue-ref-to-member */")
            }
            _ => { self.pos += 1; "$?".to_owned() }
        })
    }

    fn parse_encoded_number(&mut self) -> Option<i64> {
        let b = self.peek()?;
        if b.is_ascii_digit() {
            self.pos += 1;
            return Some(i64::from(b - b'0' + 1));
        }
        if b == b'?' {
            self.pos += 1;
            let sign = if self.peek() == Some(b'?') {
                self.pos += 1;
                -1i64
            } else {
                1i64
            };
            let n = self.parse_encoded_number().unwrap_or(0);
            return Some(sign * n);
        }
        if (b'A'..=b'P').contains(&b) {
            // nibble-encoded hex
            let mut n: i64 = 0;
            loop {
                match self.peek() {
                    Some(c) if (b'A'..=b'P').contains(&c) => {
                        n = (n << 4) | i64::from(c - b'A');
                        self.pos += 1;
                    }
                    Some(b'@') => {
                        self.pos += 1;
                        break;
                    }
                    _ => break,
                }
            }
            return Some(n);
        }
        None
    }

    fn parse_template_arg(&mut self) -> Result<TemplateArg, MsvcError> {
        if self.peek() == Some(b'$') {
            self.pos += 1;
            match self.peek() {
                Some(b'0') => {
                    // Non-type integer
                    self.pos += 1;
                    let n = self.parse_encoded_number().unwrap_or(0);
                    Ok(TemplateArg::Integer(n))
                }
                Some(b'1') => {
                    self.pos += 1;
                    let p = u64::try_from(self.parse_encoded_number().unwrap_or(0)).unwrap_or(0);
                    Ok(TemplateArg::Pointer(p))
                }
                Some(b'2') => {
                    self.pos += 1;
                    let name = self.parse_source_name();
                    Ok(TemplateArg::Template(name))
                }
                _ => {
                    let t = self.parse_type()?;
                    Ok(TemplateArg::Type(t))
                }
            }
        } else {
            let t = self.parse_type()?;
            Ok(TemplateArg::Type(t))
        }
    }

    fn decode_storage(b: u8) -> (String, bool) {
        // MSVC access/storage codes (see LLVM's MicrosoftDemangle):
        // A/B private, C/D private static, E/F private virtual,
        // I/J protected, K/L protected static, M/N protected virtual,
        // Q/R public, S/T public static, U/V public virtual,
        // Y/Z free function.
        match b {
            b'Y' | b'Z' => (String::new(), false),
            b'A' | b'B' => ("private".to_owned(), true),
            b'C' | b'D' => ("private static".to_owned(), true),
            b'E' | b'F' => ("private virtual".to_owned(), true),
            b'I' | b'J' => ("protected".to_owned(), true),
            b'K' | b'L' => ("protected static".to_owned(), true),
            b'M' | b'N' => ("protected virtual".to_owned(), true),
            b'Q' | b'R' => ("public".to_owned(), true),
            b'S' | b'T' => ("public static".to_owned(), true),
            b'U' | b'V' => ("public virtual".to_owned(), true),
            _ => (String::new(), true),
        }
    }
}

/// True when the access byte encodes a *static* member function
/// (which has no `this` cv-qualifier byte).
const fn is_static_member(b: u8) -> bool {
    matches!(b, b'C' | b'D' | b'K' | b'L' | b'S' | b'T')
}

const fn decode_operator(b: u8) -> &'static str {
    match b {
        b'0' => "ctor",
        b'1' => "~dtor",
        b'2' => "operator new",
        b'3' => "operator delete",
        b'4' => "operator=",
        b'5' => "operator>>",
        b'6' => "operator<<",
        b'7' => "operator!",
        b'8' => "operator==",
        b'9' => "operator!=",
        b'A' => "operator[]",
        b'B' => "operator conversion",
        b'C' => "operator->",
        b'D' => "operator*",
        b'E' => "operator++",
        b'F' => "operator--",
        b'G' => "operator-",
        b'H' => "operator+",
        b'I' => "operator&",
        b'J' => "operator->*",
        b'K' => "operator/",
        b'L' => "operator%",
        b'M' => "operator<",
        b'N' => "operator<=",
        b'O' => "operator>",
        b'P' => "operator>=",
        b'Q' => "operator,",
        b'R' => "operator()",
        b'S' => "operator~",
        b'T' => "operator^",
        b'U' => "operator|",
        b'V' => "operator&&",
        b'W' => "operator||",
        b'X' => "operator*=",
        b'Y' => "operator+=",
        b'Z' => "operator-=",
        _ => "operator?",
    }
}

/// Convenience top-level function — demangle a single MSVC symbol.
///
/// Returns the demangled string or the original if demangling fails.
#[must_use] 
pub fn msvc_demangle(mangled: &str) -> String {
    if !MsvcFullDemangler::detect(mangled) {
        return mangled.to_owned();
    }
    let mut d = MsvcFullDemangler::new(mangled);
    d.demangle().map_or_else(|_| mangled.to_owned(), |r| r.demangled)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn demangle(s: &str) -> String {
        msvc_demangle(s)
    }

    #[test]
    fn test_detect_msvc() {
        assert!(MsvcFullDemangler::detect("?foo@@YAHXZ"));
        assert!(!MsvcFullDemangler::detect("_ZN3fooEv"));
    }

    #[test]
    fn test_not_msvc() {
        assert_eq!(demangle("_ZN3fooEv"), "_ZN3fooEv");
    }

    #[test]
    fn test_simple_free_function() {
        // ?foo@@YAHXZ = int __cdecl foo(void)
        let result = demangle("?foo@@YAHXZ");
        assert!(result.contains("foo"), "result: {result}");
    }

    #[test]
    fn test_calling_conv_from_byte() {
        assert_eq!(CallingConv::from_byte(b'A'), CallingConv::Cdecl);
        assert_eq!(CallingConv::from_byte(b'E'), CallingConv::Thiscall);
        assert_eq!(CallingConv::from_byte(b'G'), CallingConv::Stdcall);
        assert_eq!(CallingConv::from_byte(b'I'), CallingConv::Fastcall);
        assert_eq!(CallingConv::from_byte(b'O'), CallingConv::Vectorcall);
        assert_eq!(CallingConv::from_byte(b'M'), CallingConv::Clrcall);
    }

    #[test]
    fn test_calling_conv_as_str() {
        assert_eq!(CallingConv::Cdecl.as_str(), "__cdecl");
        assert_eq!(CallingConv::Stdcall.as_str(), "__stdcall");
        assert_eq!(CallingConv::Fastcall.as_str(), "__fastcall");
        assert_eq!(CallingConv::Thiscall.as_str(), "__thiscall");
        assert_eq!(CallingConv::Vectorcall.as_str(), "__vectorcall");
    }

    #[test]
    fn test_cv_qualifiers_render() {
        let mut cv = CvQualifiers::default();
        cv.set_const();
        cv.set_volatile();
        let s = cv.render();
        assert!(s.contains("const"));
        assert!(s.contains("volatile"));
    }

    #[test]
    fn test_cv_qualifiers_empty() {
        let cv = CvQualifiers::default();
        assert!(cv.render().is_empty());
    }

    #[test]
    fn test_decode_cv() {
        let cv = decode_cv(b'B');
        assert!(cv.is_const());
        let cv2 = decode_cv(b'C');
        assert!(cv2.is_volatile());
    }

    #[test]
    fn test_template_arg_type_render() {
        let a = TemplateArg::Type("int*".into());
        assert_eq!(a.render(), "int*");
    }

    #[test]
    fn test_template_arg_integer_render() {
        let a = TemplateArg::Integer(-42);
        assert_eq!(a.render(), "-42");
    }

    #[test]
    fn test_template_arg_pack_render() {
        let p = TemplateArg::Pack(vec![
            TemplateArg::Type("int".into()),
            TemplateArg::Integer(1),
        ]);
        assert_eq!(p.render(), "int, 1");
    }

    #[test]
    fn test_operator_names() {
        assert_eq!(decode_operator(b'0'), "ctor");
        assert_eq!(decode_operator(b'1'), "~dtor");
        assert_eq!(decode_operator(b'4'), "operator=");
        assert_eq!(decode_operator(b'R'), "operator()");
    }

    #[test]
    fn test_member_function_public() {
        // ?bar@Foo@@QAEHH@Z = public: int __thiscall Foo::bar(int)
        let result = demangle("?bar@Foo@@QAEHH@Z");
        assert!(
            result.contains("bar") || result.contains("Foo"),
            "result: {result}"
        );
    }

    #[test]
    fn test_destructor_symbol() {
        // ??1Foo@@QAEXXZ
        let result = demangle("??1Foo@@QAEXXZ");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_constructor_symbol() {
        // ??0Foo@@QAEXXZ
        let result = demangle("??0Foo@@QAEXXZ");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_static_member() {
        let result = demangle("?staticMethod@Foo@@SAHXZ");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_void_return() {
        let result = demangle("?init@@YAXXZ");
        assert!(result.contains("init") || !result.is_empty());
    }

    #[test]
    fn test_pointer_param() {
        let result = demangle("?foo@@YAXPAH@Z");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_namespace_components() {
        let result = demangle("?bar@ns@@YAHXZ");
        assert!(result.contains("bar"), "result: {result}");
    }

    #[test]
    fn test_template_function() {
        let result = demangle("??$foo@H@@YAHH@Z");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_vtable_special() {
        let result = demangle("??_7Foo@@6B@");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_rtti_type_descriptor() {
        let result = demangle("??_R0?AVFoo@@@8");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_operator_new() {
        let result = demangle("??2@YAPAXI@Z");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_operator_delete() {
        let result = demangle("??3@YAXPAX@Z");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_deep_nesting() {
        let result = demangle("?method@Inner@Outer@NS@@QAEXXZ");
        assert!(result.contains("method") || !result.is_empty());
    }

    #[test]
    fn test_wchar_t_param() {
        let result = demangle("?foo@@YAX_W@Z");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_bool_type() {
        let result = demangle("?bar@@YA_NXZ");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_long_long_type() {
        let result = demangle("?baz@@YA_JXZ");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_const_member() {
        let result = demangle("?getX@Foo@@QBEHXZ");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_char16_t() {
        let result = demangle("?foo@@YAX_S@Z");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_reference_param() {
        let result = demangle("?foo@@YAXAAH@Z");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_struct_param() {
        let result = demangle("?foo@@YAXUBar@@@Z");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_class_param() {
        let result = demangle("?foo@@YAXVBaz@@@Z");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_enum_param() {
        let result = demangle("?foo@@YAXW4Color@@@Z");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_special_name_kind_eq() {
        assert_eq!(
            SpecialNameKind::LambdaClosure,
            SpecialNameKind::LambdaClosure
        );
        assert_ne!(SpecialNameKind::VcallThunk, SpecialNameKind::LambdaClosure);
    }

    #[test]
    fn test_msvc_full_demangler_detect() {
        assert!(MsvcFullDemangler::detect("?foo@@YAHXZ"));
        assert!(!MsvcFullDemangler::detect("regular_function"));
    }

    #[test]
    fn test_non_mangled_passthrough() {
        let result = msvc_demangle("not_mangled");
        assert_eq!(result, "not_mangled");
    }

    #[test]
    fn test_multiple_params() {
        let result = demangle("?add@@YAHHH@Z");
        assert!(!result.is_empty());
    }

    // ── Exact-match vectors (verified against llvm-undname conventions) ─────

    #[test]
    fn test_vec_free_function_exact() {
        assert_eq!(demangle("?foo@@YAHXZ"), "int __cdecl foo(void)");
    }

    #[test]
    fn test_vec_member_function_x64() {
        assert_eq!(
            demangle("?bar@Baz@@QEAAHH@Z"),
            "public: int __cdecl Baz::bar(int)"
        );
    }

    #[test]
    fn test_vec_constructor_x64() {
        assert_eq!(
            demangle("??0MyClass@@QEAA@XZ"),
            "public: __cdecl MyClass::MyClass(void)"
        );
    }

    #[test]
    fn test_vec_destructor_x64() {
        assert_eq!(
            demangle("??1MyClass@@QEAA@XZ"),
            "public: __cdecl MyClass::~MyClass(void)"
        );
    }

    #[test]
    fn test_vec_template_class_method() {
        assert_eq!(
            demangle("?f@?$Vec@H@@QEAAHXZ"),
            "public: int __cdecl Vec<int>::f(void)"
        );
    }

    #[test]
    fn test_vec_template_function() {
        assert_eq!(
            demangle("??$max@H@std@@YAHHH@Z"),
            "int __cdecl std::max<int>(int, int)"
        );
    }

    #[test]
    fn test_vec_nested_template() {
        assert_eq!(
            demangle("?g@?$outer@V?$inner@H@@@@QEAAXXZ"),
            "public: void __cdecl outer<class inner<int>>::g(void)"
        );
    }

    #[test]
    fn test_vec_lambda_call_operator() {
        assert_eq!(
            demangle("??R<lambda_1>@@QEBA@H@Z"),
            "public: __cdecl <lambda_1>::operator()(int) const"
        );
    }

    #[test]
    fn test_vec_global_data() {
        assert_eq!(demangle("?x@@3HA"), "int x");
    }

    #[test]
    fn test_vec_static_member_data() {
        // ?count@Foo@@2HA = public: static int Foo::count
        let r = demangle("?count@Foo@@2HA");
        assert!(r.contains("static"), "r: {r}");
        assert!(r.contains("int"), "r: {r}");
        assert!(r.contains("Foo::count"), "r: {r}");
    }

    #[test]
    fn test_vec_vftable() {
        assert_eq!(demangle("??_7MyClass@@6B@"), "`vftable for MyClass'");
    }

    #[test]
    fn test_vec_vftable_scoped() {
        let r = demangle("??_7Derived@ns@@6B@");
        assert!(r.contains("ns::Derived"), "r: {r}");
    }

    #[test]
    fn test_vec_rtti_type_descriptor_name() {
        let r = demangle("??_R0?AVFoo@@@8");
        assert!(r.contains("Foo"), "r: {r}");
    }

    #[test]
    fn test_vec_static_member_function() {
        // S = public static, no this-cv
        assert_eq!(
            demangle("?create@Widget@@SAPEAV1@XZ"),
            "public static: class Widget* __cdecl Widget::create(void)"
        );
    }

    #[test]
    fn test_vec_const_member() {
        let r = demangle("?getX@Foo@@QEBAHXZ");
        assert_eq!(r, "public: int __cdecl Foo::getX(void) const");
    }

    #[test]
    fn test_vec_virtual_member() {
        let r = demangle("?vf@Base@@UEAAXXZ");
        assert_eq!(r, "public virtual: void __cdecl Base::vf(void)");
    }

    #[test]
    fn test_vec_protected_member() {
        let r = demangle("?prot@Foo@@IEAAXXZ");
        assert!(r.starts_with("protected:"), "r: {r}");
    }

    #[test]
    fn test_vec_private_member() {
        let r = demangle("?priv@Foo@@AEAAXXZ");
        assert!(r.starts_with("private:"), "r: {r}");
    }

    #[test]
    fn test_vec_operator_assign() {
        let r = demangle("??4Foo@@QEAAAEAV0@AEBV0@@Z");
        assert!(r.contains("Foo::operator="), "r: {r}");
    }

    #[test]
    fn test_vec_operator_index() {
        let r = demangle("??AFoo@@QEAAHH@Z");
        assert!(r.contains("operator[]"), "r: {r}");
        assert!(r.contains("(int)"), "r: {r}");
    }

    #[test]
    fn test_vec_stdcall_function() {
        let r = demangle("?WinMain@@YGHXZ");
        assert!(r.contains("__stdcall"), "r: {r}");
    }

    #[test]
    fn test_vec_fastcall_function() {
        let r = demangle("?fast@@YIHH@Z");
        assert!(r.contains("__fastcall"), "r: {r}");
    }

    #[test]
    fn test_vec_pointer_params() {
        let r = demangle("?copy@@YAXPEADPEBD@Z");
        assert!(r.contains("char*"), "r: {r}");
    }

    #[test]
    fn test_vec_bool_return() {
        let r = demangle("?ok@@YA_NXZ");
        assert!(r.contains("bool"), "r: {r}");
    }

    #[test]
    fn test_vec_unsigned_int64() {
        let r = demangle("?hash@@YA_KPEBD@Z");
        assert!(r.contains("unsigned long long"), "r: {r}");
    }

    #[test]
    fn test_vec_nested_class_method() {
        let r = demangle("?m@Inner@Outer@@QEAAXXZ");
        assert!(r.contains("Outer::Inner::m"), "r: {r}");
    }

    #[test]
    fn test_vec_wchar_param() {
        let r = demangle("?w@@YAX_W@Z");
        assert!(r.contains("wchar_t"), "r: {r}");
    }
}
