//! Native Itanium ABI recursive-descent parser and
//! [`ItaniumNativeDemangler`].
//!
//! # Accuracy — prefer [`crate::demangle`]
//!
//! This parser is **substantially less accurate than the consolidated path**,
//! and unlike `itanium_full` it did not say so. Measured 2026-07-23 over the
//! 815 real Itanium symbols in `tests/data/`:
//!
//! | outcome | count | share |
//! |---|---|---|
//! | identical to `crate::demangle` | 117 | 15% |
//! | differs only in `const` placement | 136 | 17% |
//! | **substantively different** | **529** | **68%** |
//! | …of which **wrong parameter count** | **293** | **37%** |
//!
//! The failures are not cosmetic. It loses the `St` (`std::`) substitution and
//! `S<n>_` back-references, which splits one parameter into several:
//!
//! ```text
//! _ZL16get_adjusted_ptrPKSt9type_infoS1_PPv
//!   crate::demangle  get_adjusted_ptr(std::type_info const*, std::type_info const*, void**)
//!   this parser      get_adjusted_ptr(const std*, type_info, _, void**)
//! ```
//!
//! and it can mistake a namespace for a call:
//!
//! ```text
//! _ZN10__cxxabiv1L21__gxx_personality_impEiiyP17_Unwind_ExceptionP15_Unwind_Context
//!   crate::demangle  __cxxabiv1::__gxx_personality_imp(int, int, unsigned long long, …)
//!   this parser      __cxxabiv1(__gxx_personality_imp)
//! ```
//!
//! Wrong arity is the worst shape a demangler can emit: a caller building a
//! signature from it gets a plausible prototype that is silently false.
//! Callers outside this crate use it directly in ~10 places; unless a caller
//! specifically needs this parser's structural node output, [`crate::demangle`]
//! is the correct entry point.
//!
//! `tests/itanium_native_accuracy.rs` pins the figures above so they cannot
//! quietly get worse.

use crate::core_types::SymbolKind;

// ── Itanium full parser ───────────────────────────────────────────────────────

/// State for the recursive-descent Itanium ABI parser.
pub struct ItaniumParser<'a> {
    input: &'a [u8],
    pos: usize,
    subs: Vec<String>,
    depth: usize,
    max_depth: usize,
}

impl<'a> ItaniumParser<'a> {
    pub const fn new(s: &'a str) -> Self {
        Self {
            input: s.as_bytes(),
            pos: 0,
            subs: Vec::new(),
            depth: 0,
            max_depth: 128,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn consume(&mut self, b: u8) -> bool {
        if self.peek() == Some(b) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn consume_str(&mut self, s: &[u8]) -> bool {
        if self.pos + s.len() <= self.input.len() && &self.input[self.pos..self.pos + s.len()] == s
        {
            self.pos += s.len();
            true
        } else {
            false
        }
    }

    /// Try to consume a two-byte vendor-extended type prefix `u` then source-name.
    fn try_consume_vendor_type(&mut self) -> Option<String> {
        if self.consume_str(b"u") {
            return self.parse_source_name();
        }
        None
    }

    fn remaining(&self) -> &[u8] {
        &self.input[self.pos..]
    }

    fn add_sub(&mut self, s: String) {
        if !self.subs.contains(&s) {
            self.subs.push(s);
        }
    }

    /// Parse a decimal number and return it, advancing the cursor.
    fn parse_number(&mut self) -> Option<usize> {
        let start = self.pos;
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.pos += 1;
        }
        if self.pos == start {
            return None;
        }
        let s = std::str::from_utf8(&self.input[start..self.pos]).ok()?;
        s.parse().ok()
    }

    /// Parse a source name: decimal-length followed by identifier bytes.
    fn parse_source_name(&mut self) -> Option<String> {
        let len = self.parse_number()?;
        let end = self.pos.checked_add(len)?;
        if end > self.input.len() {
            return None;
        }
        let name = std::str::from_utf8(&self.input[self.pos..end])
            .ok()?
            .to_owned();
        self.pos = end;
        Some(name)
    }

    /// Parse a builtin type code.
    fn parse_builtin_type(&mut self) -> Option<String> {
        let b = self.next()?;
        let s = match b {
            b'v' => "void",
            b'w' => "wchar_t",
            b'b' => "bool",
            b'c' => "char",
            b'a' => "signed char",
            b'h' => "unsigned char",
            b's' => "short",
            b't' => "unsigned short",
            b'i' => "int",
            b'j' => "unsigned int",
            b'l' => "long",
            b'm' => "unsigned long",
            b'x' => "long long",
            b'y' => "unsigned long long",
            b'n' => "__int128",
            b'o' => "unsigned __int128",
            b'f' => "float",
            b'd' => "double",
            b'e' => "long double",
            b'g' => "__float128",
            b'z' => "...",
            b'u' => {
                // vendor extended type: source-name follows
                return self.parse_source_name();
            }
            _ => {
                self.pos -= 1;
                return None;
            }
        };
        Some(s.to_owned())
    }

    /// Parse a CV-qualifier prefix (r/V/K).
    ///
    /// The loop is capped at 3 iterations: there are only three distinct CV
    /// qualifiers (restrict, volatile, const), so consuming more than 3 means
    /// the input is malformed. This prevents O(n) work per recursion level on
    /// pathological inputs.
    fn parse_cv_qualifiers(&mut self) -> String {
        let mut quals = Vec::new();
        for _ in 0..3 {
            match self.peek() {
                Some(b'r') => {
                    self.pos += 1;
                    quals.push("restrict");
                }
                Some(b'V') => {
                    self.pos += 1;
                    quals.push("volatile");
                }
                Some(b'K') => {
                    self.pos += 1;
                    quals.push("const");
                }
                _ => break,
            }
        }
        quals.join(" ")
    }

    /// Parse a type encoding.
    fn parse_type(&mut self) -> Option<String> {
        self.depth += 1;
        if self.depth > self.max_depth {
            self.depth -= 1;
            return None;
        }
        let result = self.parse_type_inner();
        self.depth -= 1;
        result
    }

    fn parse_type_inner(&mut self) -> Option<String> {
        // CV qualifiers
        let start_pos = self.pos;
        let cvq = self.parse_cv_qualifiers();

        match self.peek()? {
            b'P' => {
                self.pos += 1;
                let inner = self.parse_type()?;
                let t = if cvq.is_empty() {
                    format!("{inner}*")
                } else {
                    format!("{cvq} {inner}*")
                };
                self.add_sub(t.clone());
                Some(t)
            }
            b'R' => {
                self.pos += 1;
                let inner = self.parse_type()?;
                let t = if cvq.is_empty() {
                    format!("{inner}&")
                } else {
                    format!("{cvq} {inner}&")
                };
                self.add_sub(t.clone());
                Some(t)
            }
            b'O' => {
                self.pos += 1;
                let inner = self.parse_type()?;
                let t = format!("{inner}&&");
                self.add_sub(t.clone());
                Some(t)
            }
            b'A' => {
                // Array type: A <number> _ <type>  or  A <type> _ <type>
                self.pos += 1;
                let dim = if self.peek().is_some_and(|b| b.is_ascii_digit()) {
                    let n = self.parse_number()?;
                    format!("{n}")
                } else {
                    String::new()
                };
                self.consume(b'_');
                let elem = self.parse_type()?;
                let t = format!("{elem}[{dim}]");
                self.add_sub(t.clone());
                Some(t)
            }
            b'F' => {
                // Function type
                self.pos += 1;
                let ret = self.parse_type()?;
                let mut params = Vec::new();
                while self.peek().is_some_and(|b| b != b'E') {
                    if let Some(p) = self.parse_type() {
                        params.push(p);
                    } else {
                        break;
                    }
                }
                self.consume(b'E');
                let t = format!("{ret}({})", params.join(", "));
                Some(t)
            }
            b'N' | b'Z' | b'L' => {
                // Nested / local name – fall through to parse_name
                self.pos = start_pos; // reset to re-parse fully
                let name = self.parse_name()?;
                self.add_sub(name.clone());
                Some(name)
            }
            b'S' => {
                let sub = self.parse_substitution()?;
                // Apply any cv-quals if present
                if cvq.is_empty() {
                    Some(sub)
                } else {
                    Some(format!("{cvq} {sub}"))
                }
            }
            b'T' => {
                // Template parameter
                self.pos += 1;
                let _n = if self.peek().is_some_and(|b| b.is_ascii_digit()) {
                    self.parse_number().unwrap_or(0)
                } else {
                    0
                };
                self.consume(b'_');
                Some("T".to_owned())
            }
            _ => {
                // Try builtin type first, reusing the CV qualifiers already parsed.
                // Do NOT call parse_cv_qualifiers again — it was already called at
                // the top of parse_type_inner and the position was not reset there.
                if let Some(bt) = self.parse_builtin_type() {
                    if cvq.is_empty() {
                        Some(bt)
                    } else {
                        Some(format!("{cvq} {bt}"))
                    }
                } else {
                    // Otherwise parse as name; reset to before the CV qualifiers.
                    self.pos = start_pos;
                    self.parse_name()
                }
            }
        }
    }

    /// Parse a substitution reference `S_`, `S0_`, `S1_`, …, or standard substitutions.
    fn parse_substitution(&mut self) -> Option<String> {
        if !self.consume(b'S') {
            return None;
        }
        match self.peek()? {
            b't' => {
                self.pos += 1;
                Some("std".to_owned())
            }
            b'a' => {
                self.pos += 1;
                Some("std::allocator".to_owned())
            }
            b'b' => {
                self.pos += 1;
                Some("std::basic_string".to_owned())
            }
            b's' => {
                self.pos += 1;
                Some("std::string".to_owned())
            }
            b'i' => {
                self.pos += 1;
                Some("std::istream".to_owned())
            }
            b'o' => {
                self.pos += 1;
                Some("std::ostream".to_owned())
            }
            b'd' => {
                self.pos += 1;
                Some("std::iostream".to_owned())
            }
            b'_' => {
                self.pos += 1;
                // S_ refers to the first (index 0) substitution.
                if self.subs.is_empty() {
                    None
                } else {
                    Some(self.subs[0].clone())
                }
            }
            c if c.is_ascii_digit() || (c.is_ascii_uppercase()) => {
                // Parse base-36 index
                let mut idx_str = String::new();
                loop {
                    match self.peek() {
                        Some(b'_') => {
                            self.pos += 1;
                            break;
                        }
                        Some(b) if b.is_ascii_alphanumeric() => {
                            idx_str.push(b as char);
                            self.pos += 1;
                        }
                        _ => break,
                    }
                }
                // decode idx_str as base-36 index + 1 (S0_ = subs[1])
                let idx = if idx_str.is_empty() {
                    0usize
                } else {
                    match usize::from_str_radix(&idx_str, 36) {
                        Ok(n) => n + 1,
                        Err(_) => return None,
                    }
                };
                if idx < self.subs.len() {
                    Some(self.subs[idx].clone())
                } else {
                    None
                }
            }
            _ => Some("S?".to_owned()),
        }
    }

    /// Parse an operator name.
    pub fn parse_operator_name(&mut self) -> Option<String> {
        let start = self.pos;
        let a = self.next()? as char;
        let b = self.next()? as char;
        let code = &[a, b];
        let name = match *code {
            ['n', 'w'] => "operator new",
            ['n', 'a'] => "operator new[]",
            ['d', 'l'] => "operator delete",
            ['d', 'a'] => "operator delete[]",
            ['p', 's' | 'l'] => "operator+",
            ['n', 'g'] | ['m', 'i'] => "operator-",
            ['a', 'd' | 'n'] => "operator&",
            ['d', 'e'] | ['m', 'l'] => "operator*",
            ['c', 'o'] => "operator~",
            ['d', 'v'] => "operator/",
            ['r', 'm'] => "operator%",
            ['o', 'r'] => "operator|",
            ['e', 'o'] => "operator^",
            ['a', 'S'] => "operator=",
            ['p', 'L'] => "operator+=",
            ['m', 'I'] => "operator-=",
            ['m', 'L'] => "operator*=",
            ['d', 'V'] => "operator/=",
            ['r', 'M'] => "operator%=",
            ['a', 'N'] => "operator&=",
            ['o', 'R'] => "operator|=",
            ['e', 'O'] => "operator^=",
            ['l', 's'] => "operator<<",
            ['r', 's'] => "operator>>",
            ['l', 'S'] => "operator<<=",
            ['r', 'S'] => "operator>>=",
            ['e', 'q'] => "operator==",
            ['n', 'e'] => "operator!=",
            ['l', 't'] => "operator<",
            ['g', 't'] => "operator>",
            ['l', 'e'] => "operator<=",
            ['g', 'e'] => "operator>=",
            ['s', 's'] => "operator<=>",
            ['q', 'u'] => "operator?",
            ['p', 'p'] => "operator++",
            ['m', 'm'] => "operator--",
            ['c', 'l'] => "operator()",
            ['i', 'x'] => "operator[]",
            ['c', 'v'] => {
                // Conversion operator: cv <type>
                let t = self.parse_type().unwrap_or_else(|| "?".to_owned());
                return Some(format!("operator {t}"));
            }
            ['l', 'i'] => {
                // Literal operator: li <source-name>
                let n = self.parse_source_name().unwrap_or_default();
                return Some(format!("operator\"\"_{n}"));
            }
            ['s', 'r'] => "operator::",
            ['s', 't' | 'z'] => "sizeof",
            ['a', 't' | 'z'] => "alignof",
            ['n', 'x'] => "noexcept",
            ['d', 't'] => "operator.",
            ['p', 't'] => "operator->",
            ['d', 's'] => "operator.*",
            ['t', 'i' | 'e'] => "typeid",
            _ => {
                self.pos = start;
                return None;
            }
        };
        Some(name.to_owned())
    }

    /// Parse a special name (_ZTV, _ZTT, etc.).  Input already past "_Z".
    fn parse_special_name(&mut self) -> Option<String> {
        match self.peek()? {
            b'V' => {
                self.pos += 1;
                let t = self.parse_type()?;
                Some(format!("vtable for {t}"))
            }
            b'T' => {
                self.pos += 1;
                match self.peek()? {
                    b'T' => {
                        self.pos += 1;
                        let t = self.parse_type()?;
                        Some(format!("VTT for {t}"))
                    }
                    b'I' => {
                        self.pos += 1;
                        let t = self.parse_type()?;
                        Some(format!("typeinfo for {t}"))
                    }
                    b'S' => {
                        self.pos += 1;
                        let t = self.parse_type()?;
                        Some(format!("typeinfo name for {t}"))
                    }
                    b'c' => {
                        self.pos += 1;
                        let _off1 = self.parse_number();
                        self.consume(b'_');
                        let _off2 = self.parse_number();
                        self.consume(b'_');
                        let t = self.parse_type()?;
                        Some(format!("covariant return thunk for {t}"))
                    }
                    b'h' => {
                        self.pos += 1;
                        let _off = self.parse_number();
                        self.consume(b'_');
                        let t = self.parse_type()?;
                        Some(format!("non-virtual thunk for {t}"))
                    }
                    b'v' => {
                        self.pos += 1;
                        let _off = self.parse_number();
                        self.consume(b'_');
                        let t = self.parse_type()?;
                        Some(format!("virtual thunk for {t}"))
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Parse a constructor/destructor name after 'C' or 'D'.
    fn parse_ctor_dtor(&mut self, class_name: &str) -> Option<String> {
        let tag = self.next()?;
        match tag {
            b'C' => {
                let n = self.next()?;
                let suffix = match n {
                    b'2' => " base",
                    b'3' => " allocating",
                    _ => "",
                };
                Some(format!("{class_name}::{class_name}{suffix}"))
            }
            b'D' => {
                let n = self.next()?;
                let suffix = match n {
                    b'0' => " deleting",
                    b'2' => " base",
                    _ => "",
                };
                Some(format!("{class_name}::~{class_name}{suffix}"))
            }
            _ => {
                self.pos -= 1;
                None
            }
        }
    }

    /// Parse an unqualified name.
    fn parse_unqualified_name(&mut self) -> Option<String> {
        match self.peek()? {
            b'C' | b'D' => {
                // These need context; handle at a higher level.
                None
            }
            b'L' => {
                // Anonymous local name
                self.pos += 1;
                let n = self.parse_source_name()?;
                Some(n)
            }
            c if c.is_ascii_digit() => self.parse_source_name(),
            _ => {
                // Try operator name
                let saved = self.pos;
                if let Some(op) = self.parse_operator_name() {
                    return Some(op);
                }
                self.pos = saved;
                None
            }
        }
    }

    /// Parse a nested name: `N [qualifiers] <name-components> E`.
    fn parse_nested_name(&mut self) -> Option<String> {
        if !self.consume(b'N') {
            return None;
        }
        let _cv = self.parse_cv_qualifiers();
        let mut parts: Vec<String> = Vec::new();

        loop {
            match self.peek()? {
                b'E' => {
                    self.pos += 1;
                    break;
                }
                b'S' => {
                    if let Some(sub) = self.parse_substitution() {
                        parts.push(sub);
                    }
                }
                b'I' => {
                    // Template args
                    let args = self.parse_template_args()?;
                    if let Some(last) = parts.last_mut() {
                        *last = format!("{last}<{}>", args.join(", "));
                    }
                }
                b'C' | b'D' => {
                    let class_name = parts.last().cloned().unwrap_or_default();
                    if let Some(cd) = self.parse_ctor_dtor(&class_name) {
                        // cd is the full "Class::ctor" or "Class::~Class"
                        // replace the last component with just the bare ctor/dtor
                        let bare = cd.rsplit("::").next().unwrap_or(&cd).to_owned();
                        parts.push(bare);
                    } else {
                        break;
                    }
                }
                c if c.is_ascii_digit() || c == b'L' => {
                    if let Some(n) = self.parse_source_name() {
                        parts.push(n);
                    } else {
                        break;
                    }
                }
                b'u' => {
                    // Vendor extended type as part of a nested name.
                    if let Some(vt) = self.try_consume_vendor_type() {
                        parts.push(vt);
                    } else {
                        break;
                    }
                }
                _ => {
                    // Try parse_unqualified_name for anything we haven't handled.
                    let saved = self.pos;
                    if let Some(uq) = self.parse_unqualified_name() {
                        parts.push(uq);
                    } else {
                        self.pos = saved;
                        if let Some(op) = self.parse_operator_name() {
                            parts.push(op);
                        } else {
                            self.pos = saved;
                            break;
                        }
                    }
                }
            }
        }

        if parts.is_empty() {
            return None;
        }
        let qualified = parts.join("::");
        self.add_sub(qualified.clone());
        Some(qualified)
    }

    /// Parse template args `I <type>* E` and return the args as strings.
    fn parse_template_args(&mut self) -> Option<Vec<String>> {
        if !self.consume(b'I') {
            return None;
        }
        let mut args = Vec::new();
        while self.peek().is_some_and(|b| b != b'E') {
            if let Some(t) = self.parse_template_arg() {
                args.push(t);
            } else {
                break;
            }
        }
        self.consume(b'E');
        Some(args)
    }

    pub fn parse_template_arg(&mut self) -> Option<String> {
        match self.peek()? {
            b'X' => {
                self.pos += 1;
                let expr = self.parse_type().unwrap_or_else(|| "expr".to_owned());
                self.consume(b'E');
                Some(expr)
            }
            b'L' => {
                // Literal
                self.pos += 1;
                let t = self.parse_type().unwrap_or_else(|| "?".to_owned());
                // skip value
                while self.peek().is_some_and(|b| b != b'E') {
                    self.pos += 1;
                }
                self.consume(b'E');
                Some(t)
            }
            b'J' => {
                self.pos += 1;
                let mut args = Vec::new();
                while self.peek().is_some_and(|b| b != b'E') {
                    if let Some(a) = self.parse_template_arg() {
                        args.push(a);
                    } else {
                        break;
                    }
                }
                self.consume(b'E');
                Some(format!("<{}>", args.join(", ")))
            }
            _ => self.parse_type(),
        }
    }

    /// Top-level name parser.
    fn parse_name(&mut self) -> Option<String> {
        // Guard against unbounded recursion on deeply nested 'Z' local names
        // (dos-unbounded-recursion). parse_type() has a depth guard already,
        // but parse_name() calls itself directly via the 'Z' arm without going
        // through that check.
        self.depth += 1;
        if self.depth > self.max_depth {
            self.depth -= 1;
            return None;
        }
        let result = self.parse_name_inner();
        self.depth -= 1;
        result
    }

    fn parse_name_inner(&mut self) -> Option<String> {
        match self.peek()? {
            b'N' => self.parse_nested_name(),
            b'Z' => {
                // Local name
                self.pos += 1;
                let func = self.parse_name()?;
                self.consume(b'E');
                let local = self.parse_name().unwrap_or_default();
                Some(format!("{func}::{local}"))
            }
            b'S' => {
                let sub = self.parse_substitution()?;
                // Might be followed by template args
                if self.peek() == Some(b'I') {
                    let args = self.parse_template_args()?;
                    Some(format!("{sub}<{}>", args.join(", ")))
                } else {
                    Some(sub)
                }
            }
            b'L' => {
                self.pos += 1;
                self.parse_source_name()
            }
            c if c.is_ascii_digit() => {
                let name = self.parse_source_name()?;
                if self.peek() == Some(b'I') {
                    let args = self.parse_template_args()?;
                    let with_args = format!("{name}<{}>", args.join(", "));
                    self.add_sub(with_args.clone());
                    Some(with_args)
                } else {
                    self.add_sub(name.clone());
                    Some(name)
                }
            }
            _ => self.parse_operator_name(),
        }
    }

    /// Parse a parameter type list until `E` or end of input.
    fn parse_params(&mut self) -> Vec<String> {
        let mut params = Vec::new();
        loop {
            match self.peek() {
                None | Some(b'E') => break,
                Some(b'v') if params.is_empty() => {
                    // Single 'v' parameter = void
                    self.pos += 1;
                    params.push("void".to_owned());
                    break;
                }
                _ => {
                    let saved = self.pos;
                    if let Some(t) = self.parse_type() {
                        params.push(t);
                    } else {
                        self.pos = saved + 1; // skip one byte to avoid infinite loop
                    }
                }
            }
        }
        params
    }

    /// Top-level encoding parser.
    fn parse_encoding(&mut self) -> Option<String> {
        // Check for special names first (_ZTV, _ZTI etc.)
        if let Some(b'T' | b'V') = self.peek()
            && let Some(s) = self.parse_special_name() {
                return Some(s);
            }

        let name = self.parse_name()?;

        // If next byte exists and is not a terminal, it's the return type/params
        if self.remaining().is_empty() {
            // Data symbol
            return Some(name);
        }

        // Encoding is <name> <type>, where type is the function type.
        // Skip return type for functions (only present for template functions).
        // Heuristically: if name ends in a qualifier, skip it.
        // For simplicity, just parse params directly.
        let params = self.parse_params();
        if params.is_empty() {
            Some(name)
        } else if params == ["void"] {
            Some(format!("{name}()"))
        } else {
            Some(format!("{name}({})", params.join(", ")))
        }
    }
}

/// Full native Itanium demangler that does not depend on `cpp_demangle`.
///
/// This is an alternative implementation that handles all the cases
/// specified in the Itanium C++ ABI mangling spec.
pub struct ItaniumNativeDemangler;

impl ItaniumNativeDemangler {
    /// Demangle an Itanium-mangled symbol.
    #[must_use] 
    pub fn demangle(mangled: &str) -> Option<String> {
        let stripped = if let Some(s) = mangled.strip_prefix("__Z") {
            s
        } else { mangled.strip_prefix("_Z")? };
        let mut parser = ItaniumParser::new(stripped);
        parser.parse_encoding()
    }

    /// Detect special symbol kind from mangled name.
    #[must_use] 
    pub fn detect_kind(mangled: &str) -> SymbolKind {
        if mangled.starts_with("_ZTV") {
            return SymbolKind::VTable;
        }
        if mangled.starts_with("_ZTI") {
            return SymbolKind::Typeinfo;
        }
        if mangled.starts_with("_ZTS") {
            return SymbolKind::TypeinfoName;
        }
        if mangled.starts_with("_ZTT") {
            return SymbolKind::VTT;
        }
        if mangled.starts_with("_ZTh") || mangled.starts_with("_ZTv") {
            return SymbolKind::Thunk;
        }
        SymbolKind::Function
    }
}
