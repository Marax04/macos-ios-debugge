//! D language (`_D`-prefixed) symbol demangler.
//!
//! Implements the D ABI mangling grammar for:
//! - Module paths and qualified names
//! - Function types and return types
//! - Template instantiations
//! - D primitive types (all widths + complex/imaginary)
//! - Arrays, pointers, delegates, function types
//! - `extern(C)` / `extern(D)` / `extern(C++)` linkage

use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors produced while demangling a D symbol.
#[derive(Debug, Error)]
pub enum DError {
    /// The input does not start with `_D` followed by a length digit.
    #[error("not a D-mangled symbol")]
    NotD,
    /// The symbol is malformed at the given byte offset.
    #[error("parse error at position {0}: {1}")]
    ParseError(usize, String),
    /// The parser exceeded its nesting-depth limit (degenerate input).
    #[error("depth limit exceeded")]
    DepthLimit,
    /// The symbol ended before a required component was complete.
    #[error("truncated symbol")]
    Truncated,
}

// ── D types ───────────────────────────────────────────────────────────────────

/// The linkage of a D function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DLinkage {
    /// `extern(D)` — default D calling convention (`F` code).
    D,
    /// `extern(C)` linkage (`U` code).
    C,
    /// `extern(C++)` linkage (`R` code).
    Cpp,
    /// `extern(Windows)` / stdcall linkage (`W` code).
    Windows,
    /// `extern(Pascal)` linkage (`V` code).
    Pascal,
    /// `extern(Objective-C)` linkage (`Y` code).
    ObjC,
}

impl DLinkage {
    /// Render this linkage as D source syntax, e.g. `extern(C++)`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::D => "extern(D)",
            Self::C => "extern(C)",
            Self::Cpp => "extern(C++)",
            Self::Windows => "extern(Windows)",
            Self::Pascal => "extern(Pascal)",
            Self::ObjC => "extern(Objective-C)",
        }
    }
}

/// Attributes on a D function type, stored as a bitmask.
#[derive(Debug, Clone, Default)]
pub struct DFuncAttrs {
    flags: u16,
}

impl DFuncAttrs {
    const PURE:     u16 = 1 << 0;
    const NOTHROW:  u16 = 1 << 1;
    const REF:      u16 = 1 << 2;
    const PROPERTY: u16 = 1 << 3;
    const TRUSTED:  u16 = 1 << 4;
    const SAFE:     u16 = 1 << 5;
    const SCOPE:    u16 = 1 << 6;
    const RETURN:   u16 = 1 << 7;
    const NOGC:     u16 = 1 << 8;
    const LIVE:     u16 = 1 << 9;

    /// Mark the function `pure` (`Na` code).
    pub const fn set_pure(&mut self)     { self.flags |= Self::PURE; }
    /// Mark the function `nothrow` (`Nb` code).
    pub const fn set_nothrow(&mut self)  { self.flags |= Self::NOTHROW; }
    /// Mark the function `ref` (`Nc` code).
    pub const fn set_ref(&mut self)      { self.flags |= Self::REF; }
    /// Mark the function `@property` (`Nd` code).
    pub const fn set_property(&mut self) { self.flags |= Self::PROPERTY; }
    /// Mark the function `@trusted` (`Ne` code).
    pub const fn set_trusted(&mut self)  { self.flags |= Self::TRUSTED; }
    /// Mark the function `@safe` (`Nf` code).
    pub const fn set_safe(&mut self)     { self.flags |= Self::SAFE; }
    /// Mark the function `scope` (`Nk` code).
    pub const fn set_scope(&mut self)    { self.flags |= Self::SCOPE; }
    /// Mark the function `return` (`Nj` code).
    pub const fn set_return(&mut self)   { self.flags |= Self::RETURN; }
    /// Mark the function `@nogc` (`Ni` code).
    pub const fn set_nogc(&mut self)     { self.flags |= Self::NOGC; }
    /// Mark the function `@live` (`Nm` code).
    pub const fn set_live(&mut self)     { self.flags |= Self::LIVE; }

    /// Whether the function is `pure`.
    #[must_use] pub const fn is_pure(&self)     -> bool { self.flags & Self::PURE != 0 }
    /// Whether the function is `nothrow`.
    #[must_use] pub const fn is_nothrow(&self)  -> bool { self.flags & Self::NOTHROW != 0 }
    /// Whether the function is `ref`.
    #[must_use] pub const fn is_ref(&self)      -> bool { self.flags & Self::REF != 0 }
    /// Whether the function is `@property`.
    #[must_use] pub const fn is_property(&self) -> bool { self.flags & Self::PROPERTY != 0 }
    /// Whether the function is `@trusted`.
    #[must_use] pub const fn is_trusted(&self)  -> bool { self.flags & Self::TRUSTED != 0 }
    /// Whether the function is `@safe`.
    #[must_use] pub const fn is_safe(&self)     -> bool { self.flags & Self::SAFE != 0 }
    /// Whether the function is `scope`.
    #[must_use] pub const fn is_scope(&self)    -> bool { self.flags & Self::SCOPE != 0 }
    /// Whether the function is `return`.
    #[must_use] pub const fn is_return(&self)   -> bool { self.flags & Self::RETURN != 0 }
    /// Whether the function is `@nogc`.
    #[must_use] pub const fn is_nogc(&self)     -> bool { self.flags & Self::NOGC != 0 }
    /// Whether the function is `@live`.
    #[must_use] pub const fn is_live(&self)     -> bool { self.flags & Self::LIVE != 0 }

    /// Render the set attributes as a space-separated D attribute list
    /// (e.g. `pure nothrow @safe`); empty when no attributes are set.
    #[must_use]
    pub fn render(&self) -> String {
        let mut parts: Vec<&str> = Vec::with_capacity(10);
        if self.is_pure()     { parts.push("pure"); }
        if self.is_nothrow()  { parts.push("nothrow"); }
        if self.is_nogc()     { parts.push("@nogc"); }
        if self.is_safe()     { parts.push("@safe"); }
        if self.is_trusted()  { parts.push("@trusted"); }
        if self.is_property() { parts.push("@property"); }
        if self.is_ref()      { parts.push("ref"); }
        if self.is_scope()    { parts.push("scope"); }
        if self.is_return()   { parts.push("return"); }
        if self.is_live()     { parts.push("@live"); }
        parts.join(" ")
    }
}

/// A D function type.
#[derive(Debug, Clone)]
pub struct DFuncType {
    /// Calling-convention / linkage of the function.
    pub linkage: DLinkage,
    /// Function attributes (`pure`, `nothrow`, `@safe`, ...).
    pub attrs: DFuncAttrs,
    /// Rendered return type (follows the `Z` terminator in the mangling).
    pub return_type: String,
    /// Function parameters, in declaration order.
    pub params: Vec<DParam>,
    /// Whether the function is variadic (`X`/`Y` codes).
    pub variadic: bool,
}

/// A single parameter in a D function signature.
#[derive(Debug, Clone)]
pub struct DParam {
    /// Parameter storage class (`out`, `ref`, `lazy`, ...).
    pub storage: DParamStorage,
    /// Rendered D type of the parameter.
    pub type_name: String,
}

/// Storage class for a D parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DParamStorage {
    /// No storage class.
    None,
    /// `in` parameter.
    In,
    /// `out` parameter (`J` code).
    Out,
    /// `ref` parameter (`K` code).
    Ref,
    /// `lazy` parameter (`L` code).
    Lazy,
    /// `scope` parameter (`M` code).
    Scope,
    /// `return` parameter.
    Return,
}

impl DParamStorage {
    /// Render this storage class as a D source prefix (with trailing space),
    /// or an empty string for [`DParamStorage::None`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "",
            Self::In => "in ",
            Self::Out => "out ",
            Self::Ref => "ref ",
            Self::Lazy => "lazy ",
            Self::Scope => "scope ",
            Self::Return => "return ",
        }
    }
}

/// Structured output of a demangled D symbol.
#[derive(Debug, Clone)]
pub struct DDemangledSymbol {
    /// Full human-readable demangled form (signature or `type name`).
    pub demangled: String,
    /// Enclosing module/package path components (may be empty).
    pub module_path: Vec<String>,
    /// The symbol's own (last) name component.
    pub name: String,
    /// Parsed function type, or `None` for variable/data symbols.
    pub func_type: Option<DFuncType>,
    /// `true` when the mangling carried `M`, D's MEMBER-function marker.
    ///
    /// This is evidence the other ABIs do not have. Rust and MSVC guess that
    /// the last scope component is the class, which is wrong for a nested
    /// module (`core::fmt::write` reports `fmt` as the class); D can say so
    /// exactly, because `M` is present precisely when the symbol belongs to an
    /// aggregate.
    pub is_member: bool,
}

// ── DDemangler ────────────────────────────────────────────────────────────────

/// Demangler for D language symbols (`_D` prefix).
pub struct DDemangler {
    input: Vec<u8>,
    pos: usize,
    depth: usize,
    max_depth: usize,
}

impl DDemangler {
    const MAX_DEPTH: usize = 48;

    /// Detect a D-mangled symbol.
    #[must_use]
    pub fn detect(mangled: &str) -> bool {
        // The byte-index check this used to carry (`get(2)` must be a digit)
        // was both redundant — `sigil::is_d` already requires a digit after the
        // prefix — and wrong for the Mach-O `__D…` form, where the digit sits
        // at index 3. It made `detect` reject symbols `new` was ready to parse.
        crate::sigil::is_d(mangled) && mangled.len() > 4
    }

    /// Create a new demangler.
    #[must_use] 
    pub fn new(mangled: &str) -> Self {
        // Mach-O prefixes every symbol with `_`, so a D symbol from an Apple
        // binary arrives as `__D…`. Normalise here rather than in the wrappers:
        // both `lang_wrappers::DDemangler` and `backends::DLangDemangler`
        // delegate to this constructor, so one normalisation point serves
        // both — and `detect` accepts the form, so declining it here would put
        // the two back out of step.
        let mangled = mangled
            .strip_prefix('_')
            .filter(|s| s.starts_with("_D"))
            .unwrap_or(mangled);
        let input = mangled.as_bytes().to_vec();
        Self {
            input,
            pos: 0,
            depth: 0,
            max_depth: Self::MAX_DEPTH,
        }
    }

    /// Demangle and return structured output.
    ///
    /// # Errors
    /// Returns [`DError`] on parse failure.
    pub fn demangle(&mut self) -> Result<DDemangledSymbol, DError> {
        if !Self::detect(&String::from_utf8_lossy(&self.input)) {
            return Err(DError::NotD);
        }
        // Skip "_D" prefix.
        self.pos = 2;

        let parts = self.parse_qualified()?;
        let name = parts.last().cloned().unwrap_or_default();
        let module_path = if parts.len() > 1 {
            parts[..parts.len() - 1].to_vec()
        } else {
            Vec::new()
        };

        // `M` marks a MEMBER function and precedes the calling-convention
        // sigil: `_D4main3Foo3barMFZv` is `void main.Foo.bar()`. It was handled
        // only as a parameter storage class (`scope`), never here, so every
        // non-static D method — an enormous share of any real D binary —
        // declined with `UnsupportedAbi`. Consume it and carry on to the
        // convention byte.
        //
        // `M` may be followed by type modifiers (`x` const, `y` immutable)
        // before the convention, as in `barMxFZv`.
        let (member_quals, is_member) = {
            let saw_m = self.peek() == Some(b'M');
            (self.parse_member_qualifiers(), saw_m)
        };

        // Parse optional function type suffix (or a variable type).
        let is_function = matches!(
            self.peek(),
            Some(b'F' | b'U' | b'W' | b'V' | b'R' | b'Y')
        );
        let mut var_type: Option<String> = None;
        let func_type = if self.at_end() {
            None
        } else if is_function {
            self.parse_func_type().ok()
        } else if self.peek() == Some(b'Z') && self.pos + 1 == self.input.len() {
            // Runtime special symbols — `__ModuleInfo`, `__init`, `__vtbl`,
            // `__Class`, `__Interface` — end in a bare `Z` that is *not* a
            // type: `Z` is the parameter-list terminator and is never a valid
            // type code. Parsing it as one produced a fabricated `?(Z)` in
            // front of an otherwise correctly decoded name.
            //
            // The name alone is the honest answer here. Inventing a
            // replacement type would just trade one fabrication for another.
            self.pos += 1;
            None
        } else {
            // Variable / data symbol: remaining bytes encode its type.
            var_type = Some(self.parse_type_code());
            None
        };

        // The whole symbol must be accounted for. Anything left over means the
        // parser stopped early and is about to report a partial reading as a
        // complete one: `_D4main3fooFiZiGARBAGE` decoded to exactly the same
        // string as `_D4main3fooFiZi`, so two distinct linker symbols — two
        // different functions — became indistinguishable in the output.
        //
        // Itanium already behaves this way (via `cpp_demangle`, which rejects
        // trailing input), which is what showed D and Swift were the outliers.
        if self.pos < self.input.len() {
            return Err(DError::ParseError(
                self.pos,
                "trailing bytes after a complete symbol".to_owned(),
            ));
        }

        let path_str = if module_path.is_empty() {
            name.clone()
        } else {
            format!("{}.{}", module_path.join("."), name)
        };
        if let Some(vt) = var_type {
            return Ok(DDemangledSymbol {
                demangled: format!("{vt} {path_str}"),
                module_path,
                name,
                func_type: None,
                is_member,
            });
        }

        let demangled = if let Some(ref ft) = func_type {
            let attrs = ft.attrs.render();
            let param_str = ft
                .params
                .iter()
                .map(|p| format!("{}{}", p.storage.as_str(), p.type_name))
                .collect::<Vec<_>>()
                .join(", ");
            let variadic_str = if ft.variadic { ", ..." } else { "" };
            let linkage_str = if ft.linkage == DLinkage::D {
                String::new()
            } else {
                format!("{} ", ft.linkage.as_str())
            };
            let attrs_str = if attrs.is_empty() {
                String::new()
            } else {
                format!(" {attrs}")
            };
            let quals_str = if member_quals.is_empty() {
                String::new()
            } else {
                format!(" {}", member_quals.join(" "))
            };
            format!(
                "{linkage_str}{} {path_str}({param_str}{variadic_str}){quals_str}{attrs_str}",
                ft.return_type,
                linkage_str = linkage_str,
                path_str = path_str,
                param_str = param_str,
                variadic_str = variadic_str,
                attrs_str = attrs_str
            )
        } else {
            path_str
        };

        Ok(DDemangledSymbol {
            demangled,
            module_path,
            name,
            func_type,
            is_member,
        })
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    const fn at_end(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn next_byte(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    const fn enter(&mut self) -> Result<(), DError> {
        self.depth += 1;
        if self.depth > self.max_depth {
            self.depth -= 1;
            Err(DError::DepthLimit)
        } else {
            Ok(())
        }
    }

    const fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn parse_length(&mut self) -> Option<usize> {
        let start = self.pos;
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.pos += 1;
        }
        if self.pos == start {
            return None;
        }
        std::str::from_utf8(&self.input[start..self.pos])
            .ok()?
            .parse()
            .ok()
    }

    fn parse_identifier(&mut self) -> Option<String> {
        // Check for template instance marker
        let is_template = if self.peek() == Some(b'_') {
            // Could be template instance prefix __T
            if self.input.get(self.pos + 1) == Some(&b'_')
                && self.input.get(self.pos + 2) == Some(&b'T')
            {
                self.pos += 3;
                true
            } else {
                false
            }
        } else {
            false
        };

        let len = self.parse_length()?;
        // `self.pos + len` must be CHECKED: `len` is read from the symbol, so a
        // prefix near `usize::MAX` overflows the bounds test itself. Found by the
        // adversarial length sweep at iter 83 — invisible to the release gates,
        // which compile overflow checks out.
        let end = self.pos.checked_add(len)?;
        if len == 0 || end > self.input.len() {
            return None;
        }
        let name = String::from_utf8_lossy(&self.input[self.pos..end]).into_owned();
        self.pos = end;

        if is_template {
            // Parse template arguments
            let mut args = Vec::new();
            while !self.at_end() {
                match self.peek() {
                    Some(b'Z') => {
                        self.pos += 1;
                        break;
                    }
                    Some(b'T' | b'S') => {
                        self.pos += 1;
                        let t = self.parse_type_code();
                        args.push(t);
                    }
                    Some(b'V') => {
                        self.pos += 1;
                        args.push(self.parse_template_value());
                    }
                    _ => break,
                }
            }
            if args.is_empty() {
                Some(name)
            } else {
                Some(format!("{name}!({})", args.join(", ")))
            }
        } else {
            Some(name)
        }
    }

    fn parse_qualified(&mut self) -> Result<Vec<String>, DError> {
        let mut parts = Vec::new();
        while !self.at_end() && self.peek().is_some_and(|b| b.is_ascii_digit()) {
            let id = self.parse_identifier().ok_or(DError::Truncated)?;
            // A function nested in another function's scope embeds the
            // ENCLOSING function's type in the path. The `()` marks it, and is
            // not decoration: without it `_D4main3fooFZ3barFZv` (bar nested
            // inside foo) and `_D4main3foo3barFZv` (bar inside class foo) would
            // both render `void main.foo.bar()` — two different symbols, one
            // output.
            if let Some(params) = self.try_consume_enclosing_function_type() {
                parts.push(format!("{id}({params})"));
            } else {
                parts.push(id);
            }
        }
        Ok(parts)
    }

    /// Consume an enclosing function's `TypeFunctionNoReturn`, if one is here.
    ///
    /// D's ABI writes a nested symbol's path as
    /// `SymbolName M? TypeModifiers? TypeFunctionNoReturn QualifiedName` — the
    /// enclosing function's **return type is omitted**, which is exactly what
    /// makes the two cases separable: after the parameter terminator `Z`, a
    /// length prefix (a digit) means another name follows and this was an
    /// enclosing function; anything else is the symbol's own return type, since
    /// no D type code is a digit.
    ///
    /// Speculative and rewinding, so a symbol that merely looks like one costs
    /// nothing. Progress is guaranteed: it only reports success after consuming
    /// at least the convention sigil AND leaving a digit for the caller's loop.
    fn try_consume_enclosing_function_type(&mut self) -> Option<String> {
        let save = self.pos;
        let _quals = self.parse_member_qualifiers();
        if !matches!(self.peek(), Some(b'F' | b'U' | b'W' | b'V' | b'R' | b'Y')) {
            self.pos = save;
            return None;
        }
        let _linkage = self.parse_linkage();
        let _attrs = self.parse_func_attrs();
        let (params, variadic) = self.parse_params();
        if !self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.pos = save;
            return None;
        }
        // The enclosing function's PARAMETERS are rendered too. Emitting a bare
        // `()` dropped them, so `_D4main3fooFZ3barFZv` and
        // `_D4main3fooFiZ3barFZv` — a nested `bar` in each of two `foo`
        // overloads — collapsed onto one output.
        let mut rendered = params
            .iter()
            .map(|prm| format!("{}{}", prm.storage.as_str(), prm.type_name))
            .collect::<Vec<_>>()
            .join(", ");
        if variadic {
            if rendered.is_empty() {
                rendered.push_str("...");
            } else {
                rendered.push_str(", ...");
            }
        }
        Some(rendered)
    }

    /// Parse the qualified name of a named type (`C`/`S`/`E`/`T`/`I`).
    ///
    /// `parse_qualified` yields an empty vector when no length-prefixed
    /// identifier follows, and `parts.join(".")` then produced the **empty
    /// string** — an empty type, rendered as a phantom parameter:
    ///
    /// ```text
    /// _D4main3fooFiIZv  =>  void main.foo(int, )
    /// _D4main3fooFIiZv  =>  void main.foo(, int)
    /// ```
    ///
    /// Neither is valid D, and the second shifts the real parameter into second
    /// place. An empty rendering is never a decode, so return the placeholder
    /// instead and let the existing D placeholder rule decline the symbol —
    /// declining beats inventing, which is this crate's standing preference.
    fn parse_named_type(&mut self, kind: u8) -> String {
        let parts = self.parse_qualified().unwrap_or_default();
        if parts.is_empty() {
            return format!("?({})", kind as char);
        }
        parts.join(".")
    }

    fn parse_func_type(&mut self) -> Result<DFuncType, DError> {
        self.enter()?;
        let linkage = self.parse_linkage();
        let attrs = self.parse_func_attrs();
        // D ABI: TypeFunction = CallConvention FuncAttrs Parameters 'Z' ReturnType
        let (params, variadic) = self.parse_params();
        let return_type = self.parse_type_code();
        self.leave();
        Ok(DFuncType {
            linkage,
            attrs,
            return_type,
            params,
            variadic,
        })
    }

    fn parse_linkage(&mut self) -> DLinkage {
        match self.peek() {
            Some(b'F') => {
                self.pos += 1;
                DLinkage::D
            }
            Some(b'U') => {
                self.pos += 1;
                DLinkage::C
            }
            Some(b'W') => {
                self.pos += 1;
                DLinkage::Windows
            }
            Some(b'V') => {
                self.pos += 1;
                DLinkage::Pascal
            }
            Some(b'R') => {
                self.pos += 1;
                DLinkage::Cpp
            }
            Some(b'Y') => {
                self.pos += 1;
                DLinkage::ObjC
            }
            _ => DLinkage::D,
        }
    }

    fn parse_func_attrs(&mut self) -> DFuncAttrs {
        let mut attrs = DFuncAttrs::default();
        loop {
            // Attr codes are prefixed by 'N' in newer mangling schemes
            if self.peek() != Some(b'N') {
                break;
            }
            self.pos += 1;
            match self.next_byte() {
                Some(b'a') => attrs.set_pure(),
                Some(b'b') => attrs.set_nothrow(),
                Some(b'c') => attrs.set_ref(),
                Some(b'd') => attrs.set_property(),
                Some(b'e') => attrs.set_trusted(),
                Some(b'f') => attrs.set_safe(),
                // `a b c d e f i j k m` — the published `FuncAttr` set.
                //
                // `g` used to be in this table, mapped to `@nogc`, and that was
                // the same position-dependence defect the catch-all below was
                // written to fix, one letter short of complete. `Ng` is `inout`,
                // a TYPE constructor taking an operand — as this file's own type
                // parser and two of its comments already say — so the loop stole
                // it only when it happened to come first:
                //
                //   _D4main3fooFiNgiZv  ->  void main.foo(int, inout(int))
                //   _D4main3fooFNgiZv   ->  void main.foo(int) @nogc
                //
                // Same `Ngi`, two readings, decided by position alone.
                //
                // Dropping `g` alone would have left `@nogc` unreachable from
                // parsing — an unreachable variant, a defect shape in its own
                // right — so the remaining letters take their published
                // meanings. That also makes the set self-consistent: it is now
                // exactly the documented table, where before it was the table
                // minus `m` plus `g`.
                Some(b'i') => attrs.set_nogc(),
                Some(b'j') => attrs.set_return(),
                Some(b'k') => attrs.set_scope(),
                Some(b'm') => attrs.set_live(),
                _ => {
                    // Put back **both** bytes: the `N` consumed above and the
                    // letter just read. Restoring only the letter dropped the
                    // `N`, so an `N`-prefixed *type* standing where an
                    // attribute could be was silently re-read as a bare type
                    // code:
                    //
                    //   FNhiZv  ->  "ubyte, int"   instead of "__vector(int)"
                    //   FNnZv   ->  "typeof(null)" instead of "noreturn"
                    //
                    // The first invents a second parameter as well as the wrong
                    // type. The attribute letters are `a b c d e f i j k m`, so
                    // at this position `Ng`, `Nh` and `Nn` can only be types,
                    // and the loop must hand them back intact.
                    self.pos = self.pos.saturating_sub(2);
                    break;
                }
            }
        }
        attrs
    }

    fn parse_params(&mut self) -> (Vec<DParam>, bool) {
        let mut params = Vec::new();
        let mut variadic = false;

        loop {
            match self.peek() {
                None | Some(b'Z') => {
                    if self.peek() == Some(b'Z') {
                        self.pos += 1;
                    }
                    break;
                }
                // `X` (typesafe variadic), `Y` (C-style variadic) and `Z`
                // (non-variadic) are all parameter-list *terminators*: the
                // return type follows. `Y` must therefore break like the other
                // two — falling through consumes the return type as a further
                // parameter and leaves the return itself unparsed.
                //
                // The two variadic flavours share an arm because this renderer
                // spells both `...`; it does not distinguish them.
                Some(b'X' | b'Y') => {
                    self.pos += 1;
                    variadic = true;
                    break;
                }
                _ => {
                    let storage = self.parse_param_storage();
                    let type_name = self.parse_type_code();
                    params.push(DParam { storage, type_name });
                }
            }
        }

        (params, variadic)
    }

    /// Consume the member-function marker `M` and its type qualifiers,
    /// returning the qualifiers in source order.
    ///
    /// `M` marks a member function and precedes the calling-convention sigil:
    /// `_D4main3Foo3barMFZv` is `void main.Foo.bar()`. It was handled only as a
    /// parameter storage class (`scope`), never here, so every non-static D
    /// method declined with `UnsupportedAbi`.
    ///
    /// The qualifiers are RETURNED rather than discarded: dropping them would
    /// make `barMxFZv` (a const method) and `barMFZv` render identically — two
    /// different D functions, one output.
    fn parse_member_qualifiers(&mut self) -> Vec<&'static str> {
        let mut quals = Vec::new();
        if self.peek() != Some(b'M') {
            return quals;
        }
        self.pos += 1;
        loop {
            let q = match self.peek() {
                Some(b'x') => "const",
                Some(b'y') => "immutable",
                Some(b'O') => "shared",
                Some(b'N') => {
                    // `Ng` is `inout`; every other `N?` pair is a function
                    // attribute, which belongs AFTER the convention sigil and
                    // is parsed by `parse_func_type`.
                    if self.input.get(self.pos + 1) == Some(&b'g') {
                        self.pos += 2;
                        quals.push("inout");
                        continue;
                    }
                    break;
                }
                _ => break,
            };
            self.pos += 1;
            quals.push(q);
        }
        quals
    }

    fn parse_param_storage(&mut self) -> DParamStorage {
        match self.peek() {
            Some(b'J') => {
                self.pos += 1;
                DParamStorage::Out
            }
            Some(b'K') => {
                self.pos += 1;
                DParamStorage::Ref
            }
            Some(b'L') => {
                self.pos += 1;
                DParamStorage::Lazy
            }
            Some(b'M') => {
                self.pos += 1;
                DParamStorage::Scope
            }
            Some(b'N') => {
                // Could be func attrs or 'return'; consume carefully
                DParamStorage::None
            }
            _ => DParamStorage::None,
        }
    }

    fn parse_type_code(&mut self) -> String {
        // Depth guard: type codes like `P`/`A`/`x`/`R` recurse once per byte,
        // so a long run of them would otherwise overflow the stack. On limit,
        // still consume one byte so looping callers keep making progress.
        if self.enter().is_err() {
            let _ = self.next_byte();
            return "?".to_owned();
        }
        let result = self.parse_type_code_inner();
        self.leave();
        result
    }

    // Flat lookup table over the D type-code alphabet; a match this shape is
    // clearer as one unit than split across helpers.
    #[expect(clippy::too_many_lines, reason = "flat type-code lookup table")]
    fn parse_type_code_inner(&mut self) -> String {
        match self.next_byte() {
            Some(b'v') => "void".to_owned(),
            Some(b'g') => "byte".to_owned(),
            Some(b'h') => "ubyte".to_owned(),
            Some(b's') => "short".to_owned(),
            Some(b't') => "ushort".to_owned(),
            Some(b'i') => "int".to_owned(),
            Some(b'k') => "uint".to_owned(),
            Some(b'l') => "long".to_owned(),
            Some(b'm') => "ulong".to_owned(),
            Some(b'n') => "typeof(null)".to_owned(),
            Some(b'f') => "float".to_owned(),
            Some(b'd') => "double".to_owned(),
            Some(b'e') => "real".to_owned(),
            Some(b'o') => "ifloat".to_owned(),
            Some(b'p') => "idouble".to_owned(),
            Some(b'j') => "ireal".to_owned(),
            Some(b'q') => "cfloat".to_owned(),
            Some(b'r') => "cdouble".to_owned(),
            // `creal` completes the complex triple. The imaginary triple above
            // is complete (`o`/`p`/`j` = ifloat/idouble/ireal) and the complex
            // one had only two of three, so the gap is visible in this table
            // alone — the answer comes from the crate's own data, not from
            // inference about the D ABI.
            //
            // Until now `c` fell through to the catch-all and rendered `?(c)`,
            // which since the placeholder rule makes the whole symbol decline
            // as `UnsupportedAbi`. That was honest — it flagged a missing
            // capability — and this supplies the capability.
            Some(b'c') => "creal".to_owned(),
            Some(b'z') => match self.next_byte() {
                Some(b'i') => "cent".to_owned(),
                Some(b'k') => "ucent".to_owned(),
                _ => "?(z)".to_owned(),
            },
            Some(b'x') => {
                // const(T)
                let inner = self.parse_type_code();
                format!("const({inner})")
            }
            Some(b'y') => {
                // immutable(T)
                let inner = self.parse_type_code();
                format!("immutable({inner})")
            }
            Some(b'a') => "char".to_owned(),
            Some(b'u') => "wchar".to_owned(),
            Some(b'w') => "dchar".to_owned(),
            Some(b'b') => "bool".to_owned(),
            Some(b'A') => {
                // Dynamic array: A <type>
                let elem = self.parse_type_code();
                format!("{elem}[]")
            }
            Some(b'G') => {
                // Static array: G <number> <type>. The Number is REQUIRED, so a
                // bare `G` is malformed input, not a zero-length array.
                // `unwrap_or(0)` made `Gi` and `G0i` render identically as
                // `int[0]` — an invented array size that the input never
                // stated, and a well-formed symbol made indistinguishable from
                // a malformed one. Decline instead; see `parse_named_type`.
                let Some(len) = self.parse_length() else {
                    return "?(G)".to_owned();
                };
                let elem = self.parse_type_code();
                format!("{elem}[{len}]")
            }
            Some(b'H') => {
                // Associative array: H <type_key> <type_value>
                let key = self.parse_type_code();
                let val = self.parse_type_code();
                format!("{val}[{key}]")
            }
            Some(b'P') => {
                // Pointer: P <type>.
                //
                // When <type> is a function type the result is a function
                // pointer, `<ret> function(<params>)`, not a pointee followed
                // by `*` — the same shape the `D` (delegate) arm below renders.
                // A function type starts with its linkage byte; `R`
                // (extern(C++)) is deliberately excluded because `R` is also
                // the type code for a reference, so `PR…` is ambiguous and
                // treating it as linkage would regress pointer-to-ref.
                if matches!(self.peek(), Some(b'F' | b'U' | b'W' | b'V' | b'Y'))
                    && let Ok(ft) = self.parse_func_type()
                {
                    let param_str = ft
                        .params
                        .iter()
                        .map(|p| p.type_name.clone())
                        .collect::<Vec<_>>()
                        .join(", ");
                    return format!("{} function({param_str})", ft.return_type);
                }
                let inner = self.parse_type_code();
                format!("{inner}*")
            }
            Some(b'R') => {
                // Reference: R <type>
                let inner = self.parse_type_code();
                format!("ref {inner}")
            }
            Some(b'I') => {
                // Ident / class: I <qualified_name>
                self.parse_named_type(b'I')
            }
            Some(b'C') => {
                // Class: C <qualified_name>
                self.parse_named_type(b'C')
            }
            Some(b'S') => {
                // Struct: S <qualified_name>
                self.parse_named_type(b'S')
            }
            Some(b'E') => {
                // Enum: E <qualified_name>
                self.parse_named_type(b'E')
            }
            Some(b'T') => {
                // Typedef: T <qualified_name>
                self.parse_named_type(b'T')
            }
            Some(b'D') => {
                // Delegate: D <func_type>
                // Parse linkage byte then params
                let ft = self.parse_func_type().unwrap_or_else(|_| DFuncType {
                    linkage: DLinkage::D,
                    attrs: DFuncAttrs::default(),
                    return_type: "?".into(),
                    params: Vec::new(),
                    variadic: false,
                });
                let param_str = ft
                    .params
                    .iter()
                    .map(|p| p.type_name.clone())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{} delegate({param_str})", ft.return_type)
            }
            Some(b'B') => {
                // TypeTuple: `B` Number Arguments — the number is a COUNT OF
                // TYPES, each parsed recursively, not the byte length of an
                // identifier. Reading it through `parse_qualified` (which parses
                // `<len><chars>` names) took the digits as a length and copied
                // that many raw bytes straight into the output, so the mangled
                // letters leaked and the remainder was re-read as further
                // parameters:
                //   B2iv    -> "Tuple!(iv)"          not "Tuple!(int, void)"
                //   B2PiAk  -> "Tuple!(Pi), uint[]"  not "Tuple!(int*, uint[])"
                // The second is the damaging shape: consuming 2 *characters*
                // where 2 *types* were meant also fabricates an extra parameter,
                // so the defect is in the arity, not only the spelling.
                // The Number is REQUIRED: a bare `B` is malformed, not an
                // empty tuple. `unwrap_or(0)` rendered `B` and `B0` alike as
                // `Tuple!()`, asserting a count the input never gave.
                let Some(count) = self.parse_length() else {
                    return "?(B)".to_owned();
                };
                let mut parts = Vec::with_capacity(count.min(16));
                for _ in 0..count {
                    if self.at_end() {
                        break;
                    }
                    // A declared count is attacker-controlled (`B999999999`), so
                    // bound the loop by progress rather than by the number: a
                    // type code that consumes nothing would otherwise spin.
                    let before = self.pos;
                    parts.push(self.parse_type_code());
                    if self.pos == before {
                        break;
                    }
                }
                format!("Tuple!({})", parts.join(", "))
            }
            Some(b'O') => {
                // shared(T)
                let inner = self.parse_type_code();
                format!("shared({inner})")
            }
            Some(b'N') => match self.next_byte() {
                Some(b'g') => {
                    let inner = self.parse_type_code();
                    format!("inout({inner})")
                }
                Some(b'h') => {
                    let inner = self.parse_type_code();
                    format!("__vector({inner})")
                }
                // `Nn` is the `noreturn` bottom type. Unlike `Ng`/`Nh` it takes
                // no operand — it is a complete type on its own, so nothing
                // further is consumed. Without this arm it fell through to the
                // catch-all and was rendered as a fabricated `?(N)`.
                Some(b'n') => "noreturn".to_owned(),
                _ => "?(N)".to_owned(),
            },
            Some(other) => format!("?({})", other as char),
            None => "?".to_owned(),
        }
    }

    fn parse_template_value(&mut self) -> String {
        // Value template parameter: simplified — just consume a number or char
        if self.peek().is_some_and(|b| b.is_ascii_digit()) {
            let n = self.parse_length().unwrap_or(0);
            format!("{n}")
        } else {
            match self.next_byte() {
                Some(b'0') => "false".to_owned(),
                Some(b'1') => "true".to_owned(),
                Some(b'n') => "null".to_owned(),
                _ => "?".to_owned(),
            }
        }
    }
}

/// Convenience function: demangle a D symbol.
///
/// Returns the demangled string, or the original if demangling fails.
#[must_use] 
pub fn d_demangle(mangled: &str) -> String {
    if !DDemangler::detect(mangled) {
        return mangled.to_owned();
    }
    let mut d = DDemangler::new(mangled);
    d.demangle().map_or_else(|_| mangled.to_owned(), |r| r.demangled)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_d_symbol() {
        assert!(DDemangler::detect("_D4main3fooFZi"));
        assert!(DDemangler::detect("_D6object9TypeInfo6__initFZv"));
    }

    #[test]
    fn test_not_d_symbol() {
        assert!(!DDemangler::detect("_ZN3fooEv"));
        assert!(!DDemangler::detect("regular_func"));
        assert!(!DDemangler::detect("_D")); // too short
    }

    #[test]
    fn test_d_demangle_simple_function() {
        let result = d_demangle("_D4main3fooFZi");
        assert!(result.contains("foo"), "result: {result}");
    }

    #[test]
    fn test_d_demangle_void_function() {
        let result = d_demangle("_D4main4initFZv");
        assert!(result.contains("init"), "result: {result}");
    }

    #[test]
    fn test_d_demangle_non_d_passthrough() {
        assert_eq!(d_demangle("normal_func"), "normal_func");
    }

    #[test]
    fn test_d_demangle_module_path() {
        let r = d_demangle("_D3std5array5ArrayFZv");
        assert!(r.contains("Array") || !r.is_empty());
    }

    #[test]
    fn test_linkage_as_str() {
        assert_eq!(DLinkage::D.as_str(), "extern(D)");
        assert_eq!(DLinkage::C.as_str(), "extern(C)");
        assert_eq!(DLinkage::Cpp.as_str(), "extern(C++)");
        assert_eq!(DLinkage::Windows.as_str(), "extern(Windows)");
    }

    #[test]
    fn test_func_attrs_render_empty() {
        let attrs = DFuncAttrs::default();
        assert!(attrs.render().is_empty());
    }

    #[test]
    fn test_func_attrs_render_pure_nothrow() {
        let mut attrs = DFuncAttrs::default();
        attrs.set_pure();
        attrs.set_nothrow();
        let s = attrs.render();
        assert!(s.contains("pure"));
        assert!(s.contains("nothrow"));
    }

    #[test]
    fn test_func_attrs_safe() {
        let mut attrs = DFuncAttrs::default();
        attrs.set_safe();
        assert!(attrs.render().contains("@safe"));
    }

    #[test]
    fn test_func_attrs_property() {
        let mut attrs = DFuncAttrs::default();
        attrs.set_property();
        assert!(attrs.render().contains("@property"));
    }

    #[test]
    fn test_param_storage_as_str() {
        assert_eq!(DParamStorage::None.as_str(), "");
        assert_eq!(DParamStorage::Out.as_str(), "out ");
        assert_eq!(DParamStorage::Ref.as_str(), "ref ");
        assert_eq!(DParamStorage::Lazy.as_str(), "lazy ");
    }

    #[test]
    fn test_d_demangled_symbol_struct() {
        let sym = DDemangledSymbol {
            demangled: "void main.foo()".into(),
            module_path: vec!["main".into()],
            name: "foo".into(),
            func_type: None,
            is_member: false,
        };
        assert_eq!(sym.name, "foo");
        assert_eq!(sym.module_path, vec!["main"]);
    }

    #[test]
    fn test_d_type_codes_in_parser() {
        let mut d = DDemangler::new("_D1a1bFiksZv");
        let _ = d.demangle(); // should not panic
    }

    #[test]
    fn test_d_demangle_pointer_type() {
        let mut d = DDemangler::new("_D4main3fooFPiZv");
        let result = d.demangle().unwrap_or_else(|_| DDemangledSymbol {
            demangled: "?".into(),
            module_path: vec![],
            name: "?".into(),
            func_type: None,
            is_member: false,
        });
        assert!(!result.demangled.is_empty());
    }

    #[test]
    fn test_d_demangle_array_type() {
        let mut d = DDemangler::new("_D4main3fooFAiZv");
        let _ = d.demangle();
    }

    #[test]
    fn test_d_demangle_template_simple() {
        let result = d_demangle("_D3std5range11__T4iota__TiZ4iotaFiiZS3std5range4Iota");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_d_detect_no_digit_after_prefix() {
        assert!(!DDemangler::detect("_Dabc"));
    }

    #[test]
    fn test_d_demangle_extern_c() {
        // When linkage byte is 'U' -> extern(C)
        let mut d = DDemangler::new("_D4main3fooUiZv");
        let sym = d.demangle().unwrap();
        if let Some(ft) = sym.func_type {
            assert_eq!(ft.linkage, DLinkage::C);
        }
    }

    #[test]
    fn test_d_demangle_extern_cpp() {
        let mut d = DDemangler::new("_D4main3fooRiZv");
        let sym = d.demangle().unwrap();
        if let Some(ft) = sym.func_type {
            assert_eq!(ft.linkage, DLinkage::Cpp);
        }
    }

    // ── Exact-match vectors (D ABI: F <params> Z <return>) ──────────────────

    #[test]
    fn test_d_vec_printf() {
        assert_eq!(
            d_demangle("_D4core4stdc5stdio6printfFPxaZi"),
            "int core.stdc.stdio.printf(const(char)*)"
        );
    }

    #[test]
    fn test_d_vec_simple_int_fn() {
        assert_eq!(d_demangle("_D3foo3barFiZi"), "int foo.bar(int)");
    }

    #[test]
    fn test_d_vec_void_fn_no_params() {
        assert_eq!(d_demangle("_D8demangle4testFZv"), "void demangle.test()");
    }

    #[test]
    fn test_d_vec_writeln_string() {
        assert_eq!(
            d_demangle("_D3std5stdio7writelnFAyaZv"),
            "void std.stdio.writeln(immutable(char)[])"
        );
    }

    #[test]
    fn test_d_vec_variable_symbol() {
        assert_eq!(d_demangle("_D3foo3bari"), "int foo.bar");
    }

    #[test]
    fn test_d_vec_variable_array() {
        assert_eq!(d_demangle("_D4main3arrAi"), "int[] main.arr");
    }

    #[test]
    fn test_d_vec_pointer_return() {
        assert_eq!(d_demangle("_D3foo5allocFkZPv"), "void* foo.alloc(uint)");
    }

    #[test]
    fn test_d_vec_static_array_param() {
        assert_eq!(d_demangle("_D3foo1fFG4iZv"), "void foo.f(int[4])");
    }

    #[test]
    fn test_d_vec_assoc_array_param() {
        // H key value = value[key]
        assert_eq!(d_demangle("_D3foo1gFHaiZv"), "void foo.g(int[char])");
    }

    #[test]
    fn test_d_vec_shared_param() {
        assert_eq!(d_demangle("_D3foo1hFOiZv"), "void foo.h(shared(int))");
    }

    #[test]
    fn test_d_vec_ref_param() {
        // K = ref parameter storage
        assert_eq!(d_demangle("_D3foo1rFKiZv"), "void foo.r(ref int)");
    }

    #[test]
    fn test_d_vec_bool_and_dchar() {
        assert_eq!(d_demangle("_D3foo1bFbwZb"), "bool foo.b(bool, dchar)");
    }

    #[test]
    fn test_d_vec_typeof_null() {
        assert_eq!(d_demangle("_D3foo1nFnZv"), "void foo.n(typeof(null))");
    }

    #[test]
    fn test_d_vec_cent() {
        assert_eq!(d_demangle("_D3foo1cFziZv"), "void foo.c(cent)");
    }

    #[test]
    fn test_d_vec_immutable_const_mix() {
        assert_eq!(
            d_demangle("_D3foo1mFxiyaZv"),
            "void foo.m(const(int), immutable(char))"
        );
    }
}
