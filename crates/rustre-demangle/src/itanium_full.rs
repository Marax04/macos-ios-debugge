//! Standalone Itanium C++ ABI name demangling.
//!
//! Implements the Itanium C++ ABI mangling specification
//! (<https://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangle>).
//!
//! # Accuracy
//!
//! This is a self-contained structural parser, **not** the crate's most
//! accurate demangler. Measured by `examples/itanium_compare.rs` against
//! `cpp_demangle` on a 28-symbol reference corpus it reproduces 6/28 exactly,
//! mainly failing on `std::` template substitutions, whereas the consolidated
//! path ([`crate::demangle`] and [`crate::cpp_demangler::demangle_itanium`])
//! reproduces 28/28.
//!
//! Prefer the consolidated path for demangling. Reach for this module only
//! when you specifically need its structural decomposition
//! ([`ItaniumSymbolInfo`], [`detect_kind`]-style classification) rather than
//! a faithful demangled string. Nothing inside the crate depends on it.
//!
//! Supported:
//! - `_Z`-prefixed symbols
//! - Nested names: `N ... E`
//! - Template arguments: `I ... E`
//! - Substitutions: `S_`, `S0_`, … `S<n>_`
//! - Built-in type abbreviations
//! - Operators: `nw`, `dl`, `pl`, `mi`, `ml`, `dv`, `rm`, `an`, `or`, `eo`, …
//! - Local names: `Z<func>E<name>`
//! - Lambda closures: `Ul<type>E_<n>`
//! - Unresolved names
//! - Cv-qualifiers, pointer/reference types

use std::collections::HashMap;
use std::fmt;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Error produced during Itanium demangling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItaniumError {
    /// Not an Itanium-mangled symbol.
    NotMangled,
    /// Unexpected end of input.
    UnexpectedEof {
        /// Byte position where input ended prematurely.
        at: usize,
    },
    /// Unexpected character at position.
    UnexpectedChar {
        /// Byte position of the offending character.
        pos: usize,
        /// The character that was found.
        ch: char,
    },
    /// Unknown substitution.
    UnknownSubstitution(String),
    /// Recursion depth exceeded.
    TooDeep,
}

impl fmt::Display for ItaniumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotMangled => write!(f, "not an Itanium-mangled symbol"),
            Self::UnexpectedEof { at } => write!(f, "unexpected end of input at {at}"),
            Self::UnexpectedChar { pos, ch } => write!(f, "unexpected '{ch}' at {pos}"),
            Self::UnknownSubstitution(s) => write!(f, "unknown substitution {s}"),
            Self::TooDeep => write!(f, "recursion depth exceeded"),
        }
    }
}

// ── ItaniumDemangler ──────────────────────────────────────────────────────────

/// Full Itanium C++ ABI demangler.
pub struct ItaniumDemangler {
    input: Vec<char>,
    pos: usize,
    depth: usize,
    substitutions: Vec<String>,
}

const MAX_DEPTH: usize = 64;

impl ItaniumDemangler {
    /// Demangle a `_Z`-prefixed symbol.
    ///
    /// # Errors
    ///
    /// Returns [`ItaniumError`] if the symbol is not Itanium-mangled or is malformed.
    pub fn demangle(symbol: &str) -> Result<String, ItaniumError> {
        let Some(sym) = symbol.strip_prefix("_Z") else {
            return Err(ItaniumError::NotMangled);
        };
        let mut d = Self {
            input: sym.chars().collect(),
            pos: 0,
            depth: 0,
            substitutions: Vec::new(),
        };
        d.parse_encoding()
    }

    fn peek(&self) -> Option<char> {
        self.input.get(self.pos).copied()
    }

    fn consume(&mut self) -> Result<char, ItaniumError> {
        if let Some(&c) = self.input.get(self.pos) {
            self.pos += 1;
            Ok(c)
        } else {
            Err(ItaniumError::UnexpectedEof { at: self.pos })
        }
    }

    fn expect(&mut self, ch: char) -> Result<(), ItaniumError> {
        let c = self.consume()?;
        if c == ch {
            Ok(())
        } else {
            Err(ItaniumError::UnexpectedChar {
                pos: self.pos - 1,
                ch: c,
            })
        }
    }

    const fn depth_check(&self) -> Result<(), ItaniumError> {
        if self.depth > MAX_DEPTH {
            Err(ItaniumError::TooDeep)
        } else {
            Ok(())
        }
    }

    // ── Top-level encoding ────────────────────────────────────────────────────

    fn parse_encoding(&mut self) -> Result<String, ItaniumError> {
        self.depth += 1;
        self.depth_check()?;
        let result = if self.peek() == Some('T') { self.parse_special_name() } else {
            let name = self.parse_name()?;
            if self.pos < self.input.len() {
                let bare_fn_type = self.parse_bare_function_type()?;
                Ok(format!("{name}({bare_fn_type})"))
            } else {
                Ok(name)
            }
        };
        self.depth -= 1;
        result
    }

    // ── Name ──────────────────────────────────────────────────────────────────

    fn parse_name(&mut self) -> Result<String, ItaniumError> {
        self.depth += 1;
        self.depth_check()?;
        let result = match self.peek() {
            Some('N') => self.parse_nested_name(),
            Some('Z') => self.parse_local_name(),
            Some('S') => self.parse_substitution_or_std(),
            _ => self.parse_unscoped_name(),
        };
        self.depth -= 1;
        result
    }

    // ── Nested name: N <qualifiers> <prefix> <unqualified-name> E ─────────────

    fn parse_nested_name(&mut self) -> Result<String, ItaniumError> {
        self.expect('N')?;
        let _cv = self.parse_cv_qualifiers();
        self.parse_ref_qualifier();
        let mut parts = Vec::new();
        while self.peek() != Some('E') {
            if self.pos >= self.input.len() {
                return Err(ItaniumError::UnexpectedEof { at: self.pos });
            }
            let part = self.parse_prefix_part()?;
            parts.push(part);
        }
        self.expect('E')?;
        let result = parts.join("::");
        self.substitutions.push(result.clone());
        Ok(result)
    }

    fn parse_prefix_part(&mut self) -> Result<String, ItaniumError> {
        match self.peek() {
            Some('I') => {
                let template_args = self.parse_template_args()?;
                let base = self.substitutions.last().cloned().unwrap_or_default();
                let s = format!("{base}<{template_args}>");
                self.substitutions.push(s.clone());
                Ok(s)
            }
            Some('S') => self.parse_substitution_or_std(),
            Some(c) if c.is_ascii_digit() => {
                let s = self.parse_source_name()?;
                self.substitutions.push(s.clone());
                Ok(s)
            }
            _ => self.parse_unqualified_name(),
        }
    }

    // ── Unscoped name ─────────────────────────────────────────────────────────

    fn parse_unscoped_name(&mut self) -> Result<String, ItaniumError> {
        if self.peek() == Some('L') {
            self.consume()?; // consume 'L'
            self.parse_unqualified_name()
        } else {
            let name = self.parse_unqualified_name()?;
            if self.peek() == Some('I') {
                let args = self.parse_template_args()?;
                Ok(format!("{name}<{args}>"))
            } else {
                Ok(name)
            }
        }
    }

    // ── Unqualified name ──────────────────────────────────────────────────────

    fn parse_unqualified_name(&mut self) -> Result<String, ItaniumError> {
        match self.peek() {
            Some(c) if c.is_ascii_digit() => self.parse_source_name(),
            Some('C' | 'D') => self.parse_ctor_dtor_name(),
            Some('o' | 'n' | 'p' | 'm' | 'd' | 'a' | 'e' | 'r' | 'l' | 'g' | 'i' | 's' |
'q' | 'c' | 'v') => self.parse_operator_name(),
            Some('U') => {
                // closure / unnamed type
                self.parse_unnamed_type()
            }
            Some(c) => Err(ItaniumError::UnexpectedChar {
                pos: self.pos,
                ch: c,
            }),
            None => Err(ItaniumError::UnexpectedEof { at: self.pos }),
        }
    }

    // ── Source name: <length> <identifier> ───────────────────────────────────

    fn parse_source_name(&mut self) -> Result<String, ItaniumError> {
        let len = self.parse_number()?;
        let s: String = (0..len).map(|_| self.consume()).collect::<Result<_, _>>()?;
        Ok(s)
    }

    fn parse_number(&mut self) -> Result<usize, ItaniumError> {
        let mut digits = String::new();
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                digits.push(c);
                self.consume()?;
            } else {
                break;
            }
        }
        digits
            .parse::<usize>()
            .map_err(|_| ItaniumError::UnexpectedEof { at: self.pos })
    }

    // ── Constructor / destructor names ────────────────────────────────────────

    fn parse_ctor_dtor_name(&mut self) -> Result<String, ItaniumError> {
        let c = self.consume()?;
        let n = self.consume()?;
        match (c, n) {
            ('C', '1' | '2' | '3') => Ok("<ctor>".to_string()),
            ('D', '0' | '1' | '2') => Ok("~<dtor>".to_string()),
            _ => Ok(format!("{c}{n}")),
        }
    }

    // ── Operator names ────────────────────────────────────────────────────────

    fn parse_operator_name(&mut self) -> Result<String, ItaniumError> {
        let c1 = self.consume()?;
        let c2 = self.consume()?;
        let op = match (c1, c2) {
            ('n', 'w') => "operator new",
            ('n', 'a') => "operator new[]",
            ('d', 'l') => "operator delete",
            ('d', 'a') => "operator delete[]",
            ('p', 's' | 'l') => "operator+",
            ('n', 'g') | ('m', 'i') => "operator-",
            ('a', 'd' | 'n') => "operator&",
            ('d', 'e') | ('m', 'l') => "operator*",
            ('c', 'o') => "operator~",
            ('d', 'v') => "operator/",
            ('r', 'm') => "operator%",
            ('o', 'r') => "operator|",
            ('e', 'o') => "operator^",
            ('a', 'S') => "operator=",
            ('p', 'L') => "operator+=",
            ('m', 'I') => "operator-=",
            ('m', 'L') => "operator*=",
            ('d', 'V') => "operator/=",
            ('r', 'M') => "operator%=",
            ('a', 'N') => "operator&=",
            ('o', 'R') => "operator|=",
            ('e', 'O') => "operator^=",
            ('l', 's') => "operator<<",
            ('r', 's') => "operator>>",
            ('l', 'S') => "operator<<=",
            ('r', 'S') => "operator>>=",
            ('e', 'q') => "operator==",
            ('n', 'e') => "operator!=",
            ('l', 't') => "operator<",
            ('g', 't') => "operator>",
            ('l', 'e') => "operator<=",
            ('g', 'e') => "operator>=",
            ('n', 't') => "operator!",
            ('a', 'a') => "operator&&",
            ('o', 'o') => "operator||",
            ('p', 'p') => "operator++",
            ('m', 'm') => "operator--",
            ('c', 'm') => "operator,",
            ('p', 'm') => "operator->*",
            ('p', 't') => "operator->",
            ('c', 'l') => "operator()",
            ('i', 'x') => "operator[]",
            ('q', 'u') => "operator?",
            ('c', 'v') => {
                let ty = self.parse_type().unwrap_or_default();
                return Ok(format!("operator {ty}"));
            }
            ('l', 'i') => {
                let lit = self.parse_source_name().unwrap_or_default();
                return Ok(format!("operator\"\" _{lit}"));
            }
            _ => return Ok(format!("operator_{c1}{c2}")),
        };
        Ok(op.to_string())
    }

    // ── Template arguments: I <type>+ E ──────────────────────────────────────

    fn parse_template_args(&mut self) -> Result<String, ItaniumError> {
        self.expect('I')?;
        let mut args = Vec::new();
        while self.peek() != Some('E') {
            if self.pos >= self.input.len() {
                return Err(ItaniumError::UnexpectedEof { at: self.pos });
            }
            let arg = self.parse_template_arg()?;
            args.push(arg);
        }
        self.expect('E')?;
        Ok(args.join(", "))
    }

    fn parse_template_arg(&mut self) -> Result<String, ItaniumError> {
        match self.peek() {
            Some('X') => {
                self.consume()?;
                let expr = self.parse_expression()?;
                self.expect('E')?;
                Ok(expr)
            }
            Some('L') => {
                self.consume()?;
                let ty = self.parse_type()?;
                let val = self.parse_expr_primary()?;
                Ok(format!("{val} /*{ty}*/"))
            }
            Some('J') => {
                self.consume()?;
                let mut args = Vec::new();
                while self.peek() != Some('E') {
                    args.push(self.parse_template_arg()?);
                }
                self.expect('E')?;
                Ok(format!("<{}>", args.join(", ")))
            }
            _ => self.parse_type(),
        }
    }

    // ── Type ──────────────────────────────────────────────────────────────────

    fn parse_type(&mut self) -> Result<String, ItaniumError> {
        self.depth += 1;
        self.depth_check()?;
        let result = self.parse_type_inner();
        self.depth -= 1;
        result
    }

    fn parse_type_inner(&mut self) -> Result<String, ItaniumError> {
        match self.peek() {
            Some('r') => {
                self.consume()?;
                Ok("restrict".to_string())
            }
            Some('V') => {
                self.consume()?;
                Ok("volatile".to_string())
            }
            Some('K') => {
                self.consume()?;
                let t = self.parse_type()?;
                Ok(format!("{t} const"))
            }
            Some('P') => {
                self.consume()?;
                let t = self.parse_type()?;
                Ok(format!("{t}*"))
            }
            Some('R') => {
                self.consume()?;
                let t = self.parse_type()?;
                Ok(format!("{t}&"))
            }
            Some('O') => {
                self.consume()?;
                let t = self.parse_type()?;
                Ok(format!("{t}&&"))
            }
            Some('C') => {
                self.consume()?;
                let t = self.parse_type()?;
                Ok(format!("{t} complex"))
            }
            Some('G') => {
                self.consume()?;
                let t = self.parse_type()?;
                Ok(format!("{t} imaginary"))
            }
            Some('U') => {
                // vendor-extended type qualifier
                self.consume()?;
                let _name = self.parse_source_name()?;
                self.parse_type()
            }
            Some('F') => self.parse_function_type(),
            Some('A') => self.parse_array_type(),
            Some('M') => self.parse_pointer_to_member_type(),
            Some('T') => self.parse_template_param(),
            Some('S') => self.parse_substitution_type(),
            Some('N') => self.parse_nested_name(),
            Some('D') => self.parse_d_type(),
            Some(c) if c.is_ascii_digit() => self.parse_source_name(),
            Some(c) if matches!(c, 'v' | 'w' | 'b' | 'c' | 'a' | 'h' | 's' | 't' | 'i' | 'j' | 'l' | 'm' | 'x' | 'y' | 'n' | 'o' | 'f' | 'd' | 'e' | 'g' | 'z') => {
                // builtin type abbreviation
                self.consume()?;
                Ok(builtin_type(c).to_string())
            }
            _ => Err(ItaniumError::UnexpectedEof { at: self.pos }),
        }
    }

    fn parse_function_type(&mut self) -> Result<String, ItaniumError> {
        self.expect('F')?;
        let mut types = Vec::new();
        while self.peek() != Some('E') {
            types.push(self.parse_type()?);
        }
        self.expect('E')?;
        let empty_string = String::new();
        let empty_slice: &[String] = &[];
        let (ret, params) = types.split_first().unwrap_or((&empty_string, empty_slice));
        Ok(format!("{ret}({})", params.join(", ")))
    }

    fn parse_array_type(&mut self) -> Result<String, ItaniumError> {
        self.expect('A')?;
        let dim = if self.peek() == Some('_') {
            String::new()
        } else {
            let mut s = String::new();
            while self.peek() != Some('_') {
                s.push(self.consume()?);
            }
            s
        };
        self.expect('_')?;
        let ty = self.parse_type()?;
        Ok(format!("{ty}[{dim}]"))
    }

    fn parse_pointer_to_member_type(&mut self) -> Result<String, ItaniumError> {
        self.expect('M')?;
        let cls = self.parse_type()?;
        let ty = self.parse_type()?;
        Ok(format!("{ty} {cls}::*"))
    }

    fn parse_template_param(&mut self) -> Result<String, ItaniumError> {
        self.expect('T')?;
        let idx = if self.peek() == Some('_') {
            self.consume()?;
            0usize
        } else {
            let n = self.parse_number()?;
            self.expect('_')?;
            n + 1
        };
        Ok(format!("T{idx}"))
    }

    fn parse_substitution_type(&mut self) -> Result<String, ItaniumError> {
        self.parse_substitution_or_std()
    }

    fn parse_d_type(&mut self) -> Result<String, ItaniumError> {
        self.consume()?; // 'D'
        let c = self.consume()?;
        match c {
            'e' => Ok("decimal128".to_string()),
            'd' => Ok("decimal64".to_string()),
            'f' => Ok("decimal32".to_string()),
            'h' => Ok("half".to_string()),
            's' => Ok("char16_t".to_string()),
            'i' => Ok("char32_t".to_string()),
            'n' => Ok("decltype(nullptr)".to_string()),
            'p' => {
                let t = self.parse_type()?;
                Ok(format!("auto... {t}"))
            }
            'T' => {
                // decltype
                let e = self.parse_expression()?;
                self.expect('E')?;
                Ok(format!("decltype({e})"))
            }
            'v' => {
                // parameter pack
                let n = self.parse_number()?;
                Ok(format!("<pack{n}>"))
            }
            _ => Ok(format!("D{c}")),
        }
    }

    // ── Substitution ─────────────────────────────────────────────────────────

    fn parse_substitution_or_std(&mut self) -> Result<String, ItaniumError> {
        self.expect('S')?;
        match self.peek() {
            Some('t') => {
                self.consume()?;
                Ok("std".to_string())
            }
            Some('a') => {
                self.consume()?;
                Ok("std::allocator".to_string())
            }
            Some('b') => {
                self.consume()?;
                Ok("std::basic_string".to_string())
            }
            Some('s') => {
                self.consume()?;
                Ok("std::string".to_string())
            }
            Some('i') => {
                self.consume()?;
                Ok("std::istream".to_string())
            }
            Some('o') => {
                self.consume()?;
                Ok("std::ostream".to_string())
            }
            Some('d') => {
                self.consume()?;
                Ok("std::iostream".to_string())
            }
            Some('_') => {
                self.consume()?;
                self.substitutions
                    .first()
                    .cloned()
                    .ok_or_else(|| ItaniumError::UnknownSubstitution("S_".to_string()))
            }
            Some(c) if c.is_ascii_alphanumeric() => {
                let mut s = String::new();
                s.push(self.consume()?);
                while let Some(cc) = self.peek() {
                    if cc == '_' {
                        self.consume()?;
                        break;
                    }
                    s.push(self.consume()?);
                }
                let idx = base36_decode(&s);
                self.substitutions
                    .get(idx)
                    .cloned()
                    .ok_or_else(|| ItaniumError::UnknownSubstitution(format!("S{s}_")))
            }
            _ => Ok("S?".to_string()),
        }
    }

    // ── Local name: Z <encoding> E <name> ─────────────────────────────────────

    fn parse_local_name(&mut self) -> Result<String, ItaniumError> {
        self.expect('Z')?;
        let func = self.parse_encoding()?;
        self.expect('E')?;
        let local = match self.peek() {
            Some('s') => {
                self.consume()?;
                "string_literal".to_string()
            }
            Some('d') => {
                self.consume()?;
                self.parse_discriminator();
                format!("{func}::<anon>")
            }
            _ => self.parse_name()?,
        };
        Ok(format!("{func}::{local}"))
    }

    fn parse_discriminator(&mut self) {
        if self.peek() == Some('_') {
            self.consume().ok();
            // Parse optional number
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.consume().ok();
            }
        }
    }

    // ── Unnamed type / lambda closure ─────────────────────────────────────────

    fn parse_unnamed_type(&mut self) -> Result<String, ItaniumError> {
        self.expect('U')?;
        match self.peek() {
            Some('t') => {
                self.consume()?;
                let n = if self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    
                    self.parse_number().unwrap_or(0)
                } else {
                    0
                };
                self.expect('_')?;
                Ok(format!("<unnamed type#{n}>"))
            }
            Some('l') => {
                self.consume()?;
                // Lambda: l <lambda-sig> E _ <n>
                let sig = self.parse_lambda_sig();
                self.expect('E')?;
                self.expect('_')?;
                let n = if self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    self.parse_number().unwrap_or(0)
                } else {
                    0
                };
                Ok(format!("<lambda({sig})#{n}>"))
            }
            _ => Ok("<unnamed>".to_string()),
        }
    }

    fn parse_lambda_sig(&mut self) -> String {
        let mut types = Vec::new();
        while self.peek() != Some('E') {
            if self.pos >= self.input.len() {
                break;
            }
            types.push(self.parse_type().unwrap_or_else(|_| "?".to_string()));
        }
        types.join(", ")
    }

    // ── Expression / expr-primary ─────────────────────────────────────────────

    fn parse_expression(&mut self) -> Result<String, ItaniumError> {
        match self.peek() {
            Some('L') => {
                self.consume()?;
                let t = self.parse_type()?;
                let v = self.parse_expr_primary()?;
                Ok(format!("{v} /*:{t}*/"))
            }
            Some('T') => self.parse_template_param(),
            _ => Ok("expr".to_string()),
        }
    }

    fn parse_expr_primary(&mut self) -> Result<String, ItaniumError> {
        // Simplified: read digits or 'n' (negative) until 'E'
        let mut s = String::new();
        loop {
            match self.peek() {
                Some('E') => {
                    self.consume()?;
                    break;
                }
                Some(c) => {
                    s.push(c);
                    self.consume()?;
                }
                None => break,
            }
        }
        Ok(s)
    }

    // ── Bare function type ────────────────────────────────────────────────────

    fn parse_bare_function_type(&mut self) -> Result<String, ItaniumError> {
        let mut types = Vec::new();
        while self.pos < self.input.len() && self.peek() != Some('E') {
            types.push(self.parse_type()?);
        }
        Ok(types.join(", "))
    }

    // ── CV qualifiers ─────────────────────────────────────────────────────────

    fn parse_cv_qualifiers(&mut self) -> String {
        let mut quals = Vec::new();
        while let Some(c) = self.peek() {
            match c {
                'r' => {
                    self.consume().ok();
                    quals.push("restrict");
                }
                'V' => {
                    self.consume().ok();
                    quals.push("volatile");
                }
                'K' => {
                    self.consume().ok();
                    quals.push("const");
                }
                _ => break,
            }
        }
        quals.join(" ")
    }

    fn parse_ref_qualifier(&mut self) {
        if let Some('R' | 'O') = self.peek() {
            self.consume().ok();
        }
    }

    // ── Special names ─────────────────────────────────────────────────────────

    fn parse_special_name(&mut self) -> Result<String, ItaniumError> {
        self.expect('T')?;
        let c = self.consume()?;
        match c {
            'V' => {
                let ty = self.parse_type()?;
                Ok(format!("vtable for {ty}"))
            }
            'T' => {
                let ty = self.parse_type()?;
                Ok(format!("VTT for {ty}"))
            }
            'I' => {
                let ty = self.parse_type()?;
                Ok(format!("typeinfo for {ty}"))
            }
            'S' => {
                let ty = self.parse_type()?;
                Ok(format!("typeinfo name for {ty}"))
            }
            'c' => {
                let ty = self.parse_type()?;
                Ok(format!("covariant thunk for {ty}"))
            }
            'h' => {
                let _adj = self.parse_type()?;
                let func = self.parse_encoding()?;
                Ok(format!("non-virtual thunk for {func}"))
            }
            'v' => {
                let _adj = self.parse_type()?;
                let _voff = self.parse_type()?;
                let func = self.parse_encoding()?;
                Ok(format!("virtual thunk for {func}"))
            }
            _ => Ok(format!("T{c}?")),
        }
    }
}

// ── ItaniumSymbolKind ─────────────────────────────────────────────────────────

/// The kind of an Itanium-mangled symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItaniumSymbolKind {
    /// Regular function or data symbol.
    Normal,
    /// `VTable`.
    VTable,
    /// VTT (virtual table table).
    Vtt,
    /// Type info structure.
    TypeInfo,
    /// Type info name string.
    TypeInfoName,
    /// Thunk (virtual or non-virtual).
    Thunk,
}

impl ItaniumSymbolKind {
    /// Classify an Itanium symbol by inspecting its mangled form.
    #[must_use]
    pub fn classify(mangled: &str) -> Self {
        let s = mangled.strip_prefix("_Z").unwrap_or(mangled);
        if s.starts_with("TV") {
            return Self::VTable;
        }
        if s.starts_with("TT") {
            return Self::Vtt;
        }
        if s.starts_with("TI") {
            return Self::TypeInfo;
        }
        if s.starts_with("TS") {
            return Self::TypeInfoName;
        }
        if s.starts_with("Th") || s.starts_with("Tv") || s.starts_with("Tc") {
            return Self::Thunk;
        }
        Self::Normal
    }

    /// Human-readable name for the symbol kind.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::VTable => "vtable",
            Self::Vtt => "vtt",
            Self::TypeInfo => "typeinfo",
            Self::TypeInfoName => "typeinfo_name",
            Self::Thunk => "thunk",
        }
    }
}

// ── ItaniumBatchDemangler ─────────────────────────────────────────────────────

/// Batch demangler with caching for repeated lookups.
#[derive(Debug, Default)]
pub struct ItaniumBatchDemangler {
    cache: HashMap<String, Option<String>>,
}

impl ItaniumBatchDemangler {
    /// Create a new batch demangler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Demangle a symbol, using the cache.
    #[must_use]
    pub fn demangle(&mut self, symbol: &str) -> Option<&str> {
        if !self.cache.contains_key(symbol) {
            let result = ItaniumDemangler::demangle(symbol).ok();
            self.cache.insert(symbol.to_string(), result);
        }
        self.cache.get(symbol)?.as_deref()
    }

    /// Demangle a batch of symbols.
    #[must_use]
    pub fn demangle_all(&mut self, symbols: &[&str]) -> Vec<Option<String>> {
        symbols
            .iter()
            .map(|&s| self.demangle(s).map(std::string::ToString::to_string))
            .collect()
    }

    /// Cache hit rate.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
}

// ── ItaniumNamespaceParser ────────────────────────────────────────────────────

/// Extracts the top-level namespace from a demangled symbol name.
#[must_use]
pub fn extract_namespace(demangled: &str) -> Option<&str> {
    let ns_end = demangled.find("::")?;
    Some(&demangled[..ns_end])
}

/// Check whether a demangled name belongs to the `std` namespace.
#[must_use]
pub fn is_std_symbol(demangled: &str) -> bool {
    demangled.starts_with("std::") || demangled.starts_with("std::<")
}

/// Attempt to detect if a symbol is a lambda from its demangled name.
#[must_use]
pub fn is_lambda(demangled: &str) -> bool {
    demangled.contains("<lambda")
}

/// Detect if the symbol is a constructor.
#[must_use]
pub fn is_constructor(demangled: &str) -> bool {
    demangled.contains("<ctor>")
}

/// Detect if the symbol is a destructor.
#[must_use]
pub fn is_destructor(demangled: &str) -> bool {
    demangled.contains("~<dtor>")
}

// ── ItaniumDemanglerOptions ───────────────────────────────────────────────────

/// Options controlling the demangling output style.
#[derive(Debug, Clone)]
pub struct DemanglerOptions {
    /// Include return types in function signatures.
    pub include_return_type: bool,
    /// Expand all template arguments.
    pub expand_templates: bool,
    /// Abbreviate standard-library types (`std::` → …).
    pub abbreviate_std: bool,
}

impl Default for DemanglerOptions {
    fn default() -> Self {
        Self {
            include_return_type: false,
            expand_templates: true,
            abbreviate_std: false,
        }
    }
}

/// Post-process a demangled string according to options.
#[must_use]
pub fn apply_options(demangled: &str, opts: &DemanglerOptions) -> String {
    let mut s = demangled.to_string();
    if opts.abbreviate_std {
        s = s.replace("std::", "…::");
    }
    s
}

// ── ItaniumMultiDemangler ─────────────────────────────────────────────────────

/// Tries multiple demangling strategies: Itanium, fallback prefix stripping.
pub struct ItaniumMultiDemangler;

impl ItaniumMultiDemangler {
    /// Demangle: try Itanium first, then strip leading `__` / `_`, return input on failure.
    #[must_use]
    pub fn demangle(symbol: &str) -> String {
        if let Some(d) = demangle_itanium(symbol) {
            return d;
        }
        // Try with stripped leading underscore
        if let Some(s) = symbol.strip_prefix('_')
            && let Some(d) = demangle_itanium(s) {
                return d;
            }
        symbol.to_string()
    }

    /// Demangle a list of symbols.
    #[must_use]
    pub fn demangle_list(symbols: &[&str]) -> Vec<String> {
        symbols.iter().map(|&s| Self::demangle(s)).collect()
    }

    /// Group symbols by namespace.
    #[must_use]
    pub fn group_by_namespace(symbols: &[&str]) -> HashMap<String, Vec<String>> {
        let mut groups: HashMap<String, Vec<String>> = HashMap::new();
        for &sym in symbols {
            let demangled = Self::demangle(sym);
            let ns = extract_namespace(&demangled)
                .unwrap_or("<global>")
                .to_string();
            groups.entry(ns).or_default().push(demangled);
        }
        groups
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const fn builtin_type(c: char) -> &'static str {
    match c {
        'v' => "void",
        'w' => "wchar_t",
        'b' => "bool",
        'c' => "char",
        'a' => "signed char",
        'h' => "unsigned char",
        's' => "short",
        't' => "unsigned short",
        'i' => "int",
        'j' => "unsigned int",
        'l' => "long",
        'm' => "unsigned long",
        'x' => "long long",
        'y' => "unsigned long long",
        'n' => "__int128",
        'o' => "unsigned __int128",
        'f' => "float",
        'd' => "double",
        'e' => "long double",
        'g' => "__float128",
        'z' => "...",
        _ => "?",
    }
}

fn base36_decode(s: &str) -> usize {
    let mut n = 0usize;
    for c in s.chars() {
        n *= 36;
        n += match c {
            '0'..='9' => (c as usize) - ('0' as usize),
            'A'..='Z' => (c as usize) - ('A' as usize) + 10,
            _ => 0,
        };
    }
    n + 1 // S_ = 0, S0_ = 1, ...
}

// ── ItaniumSubstitutionTable ──────────────────────────────────────────────────

/// Standard Itanium substitution abbreviations.
pub const STANDARD_SUBS: &[(&str, &str)] = &[
    ("St", "std"),
    ("Sa", "std::allocator"),
    ("Sb", "std::basic_string"),
    ("Ss", "std::string"),
    ("Si", "std::istream"),
    ("So", "std::ostream"),
    ("Sd", "std::iostream"),
];

/// Look up a standard substitution abbreviation.
#[must_use]
pub fn lookup_standard_sub(abbrev: &str) -> Option<&'static str> {
    STANDARD_SUBS
        .iter()
        .find(|(k, _)| *k == abbrev)
        .map(|(_, v)| *v)
}

// ── ItaniumSymbolInfo ─────────────────────────────────────────────────────────

/// Boolean classification flags extracted from a demangled Itanium symbol.
#[derive(Debug, Clone, Default)]
pub struct ItaniumSymbolFlags {
    flags: u8,
}

impl ItaniumSymbolFlags {
    const STD: u8         = 1 << 0;
    const LAMBDA: u8      = 1 << 1;
    const CONSTRUCTOR: u8 = 1 << 2;
    const DESTRUCTOR: u8  = 1 << 3;

    /// Mark this symbol as from `std::`.
    pub const fn set_std(&mut self)         { self.flags |= Self::STD; }
    /// Mark this symbol as a lambda.
    pub const fn set_lambda(&mut self)      { self.flags |= Self::LAMBDA; }
    /// Mark this symbol as a constructor.
    pub const fn set_constructor(&mut self) { self.flags |= Self::CONSTRUCTOR; }
    /// Mark this symbol as a destructor.
    pub const fn set_destructor(&mut self)  { self.flags |= Self::DESTRUCTOR; }

    /// Whether the `std::` flag is set.
    #[must_use] pub const fn is_std(&self)         -> bool { self.flags & Self::STD != 0 }
    /// Whether the lambda flag is set.
    #[must_use] pub const fn is_lambda(&self)      -> bool { self.flags & Self::LAMBDA != 0 }
    /// Whether the constructor flag is set.
    #[must_use] pub const fn is_constructor(&self) -> bool { self.flags & Self::CONSTRUCTOR != 0 }
    /// Whether the destructor flag is set.
    #[must_use] pub const fn is_destructor(&self)  -> bool { self.flags & Self::DESTRUCTOR != 0 }
}

/// Aggregated analysis of a single Itanium-mangled symbol: demangling result,
/// kind classification, boolean flags, and top-level namespace.
pub struct ItaniumSymbolInfo {
    /// The original mangled symbol.
    pub mangled: String,
    /// Demangled name, or `None` if demangling failed.
    pub demangled: Option<String>,
    /// Symbol kind (normal, vtable, typeinfo, thunk, …).
    pub kind: ItaniumSymbolKind,
    /// Classification flags (`std::`, lambda, ctor, dtor).
    pub flags: ItaniumSymbolFlags,
    /// Top-level namespace of the demangled name, if any.
    pub namespace: Option<String>,
}

impl ItaniumSymbolInfo {
    /// Whether this symbol is from the `std::` namespace.
    #[must_use] pub const fn is_std(&self) -> bool { self.flags.is_std() }
    /// Whether this symbol is a lambda.
    #[must_use] pub const fn is_lambda(&self) -> bool { self.flags.is_lambda() }
    /// Whether this symbol is a constructor.
    #[must_use] pub const fn is_constructor(&self) -> bool { self.flags.is_constructor() }
    /// Whether this symbol is a destructor.
    #[must_use] pub const fn is_destructor(&self) -> bool { self.flags.is_destructor() }
}

impl ItaniumSymbolInfo {
    /// Analyze a mangled symbol and extract all info.
    #[must_use]
    pub fn analyze(mangled: &str) -> Self {
        let demangled = ItaniumDemangler::demangle(mangled).ok();
        let kind = ItaniumSymbolKind::classify(mangled);
        let (is_std, is_lam, ctor_flag, dtor_flag, ns) = demangled.as_ref().map_or(
            (false, false, false, false, None),
            |d| {
                let std_sym = is_std_symbol(d);
                let lam = is_lambda(d);
                let ctor = is_constructor(d);
                let dtor = is_destructor(d);
                let namespace = extract_namespace(d).map(std::string::ToString::to_string);
                (std_sym, lam, ctor, dtor, namespace)
            },
        );
        Self {
            mangled: mangled.to_string(),
            demangled,
            kind,
            flags: {
                let mut f = ItaniumSymbolFlags::default();
                if is_std { f.set_std(); }
                if is_lam { f.set_lambda(); }
                if ctor_flag { f.set_constructor(); }
                if dtor_flag { f.set_destructor(); }
                f
            },
            namespace: ns,
        }
    }

    /// Whether the symbol was successfully demangled.
    #[must_use]
    pub const fn was_demangled(&self) -> bool {
        self.demangled.is_some()
    }

    /// Display name: demangled if available, else mangled.
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.demangled.as_deref().unwrap_or(&self.mangled)
    }
}

impl fmt::Display for ItaniumSymbolInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.display_name(), self.kind.name())
    }
}

// ── Public convenience function ───────────────────────────────────────────────

/// Attempt to demangle an Itanium C++ symbol.
///
/// Returns `None` if the symbol is not an Itanium-mangled symbol.
///
/// Uses this module's standalone parser. For faithful output prefer
/// [`crate::demangle`] or [`crate::cpp_demangler::demangle_itanium`] — see the
/// accuracy note in the module documentation.
#[must_use]
pub fn demangle_itanium(symbol: &str) -> Option<String> {
    ItaniumDemangler::demangle(symbol).ok()
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dem(s: &str) -> String {
        ItaniumDemangler::demangle(s).unwrap_or_else(|e| format!("ERR: {e}"))
    }

    fn ok(s: &str) -> bool {
        ItaniumDemangler::demangle(s).is_ok()
    }

    // --- Basic symbols ---

    #[test]
    fn test_not_mangled() {
        assert!(matches!(
            ItaniumDemangler::demangle("main"),
            Err(ItaniumError::NotMangled)
        ));
    }

    #[test]
    fn test_simple_function_int() {
        // _ZN3foo3barEi = foo::bar(int)
        let d = dem("_ZN3foo3barEi");
        assert!(d.contains("foo"), "got: {d}");
        assert!(d.contains("bar"), "got: {d}");
    }

    #[test]
    fn test_simple_free_function() {
        // _Z3fooi = foo(int)
        let d = dem("_Z3fooi");
        assert!(d.contains("foo"), "got: {d}");
    }

    #[test]
    fn test_nested_namespace() {
        // _ZN3foo3bar3bazEv = foo::bar::baz()
        let d = dem("_ZN3foo3bar3bazEv");
        assert!(d.contains("foo"), "got: {d}");
        assert!(d.contains("baz"), "got: {d}");
    }

    #[test]
    fn test_constructor() {
        // _ZN3FooC1Ev = Foo::Foo()
        let d = dem("_ZN3FooC1Ev");
        assert!(d.contains("Foo"), "got: {d}");
    }

    #[test]
    fn test_destructor() {
        // _ZN3FooD1Ev = Foo::~Foo()
        let d = dem("_ZN3FooD1Ev");
        assert!(d.contains("Foo"), "got: {d}");
    }

    #[test]
    fn test_operator_new() {
        // _ZnwPv — simplified; just check it doesn't error
        assert!(ok("_Znwm"));
    }

    #[test]
    fn test_operator_delete() {
        assert!(ok("_ZdlPv"));
    }

    #[test]
    fn test_operator_plus_equals() {
        let d = dem("_ZN3FoopLEi");
        assert!(d.contains("operator+=") || d.contains("Foo"), "got: {d}");
    }

    #[test]
    fn test_operator_call() {
        // _ZN3FooclEi = Foo::operator()(int)
        let d = dem("_ZN3FooclEi");
        assert!(ok("_ZN3FooclEi"), "got: {d}");
    }

    #[test]
    fn test_template_simple() {
        // _Z3fooIiEvi = foo<int>(int)
        let d = dem("_Z3fooIiEvi");
        assert!(d.contains("foo"), "got: {d}");
    }

    #[test]
    fn test_template_two_args() {
        let d = dem("_Z3fooIidEvi");
        assert!(d.contains("foo"), "got: {d}");
    }

    #[test]
    fn test_pointer_type() {
        let d = dem("_Z3fooPi");
        assert!(d.contains("foo"), "got: {d}");
    }

    #[test]
    fn test_const_ref_type() {
        let d = dem("_Z3fooRKi");
        assert!(d.contains("foo"), "got: {d}");
    }

    #[test]
    fn test_local_name() {
        // _ZZ3fooiE3bar = foo(int)::bar
        let d = dem("_ZZ3fooiE3bar");
        assert!(d.contains("foo"), "got: {d}");
        assert!(d.contains("bar"), "got: {d}");
    }

    #[test]
    fn test_vtable() {
        // _ZTV3Foo = vtable for Foo
        let d = dem("_ZTV3Foo");
        assert!(d.contains("Foo"), "got: {d}");
        assert!(d.contains("vtable"), "got: {d}");
    }

    #[test]
    fn test_typeinfo() {
        let d = dem("_ZTI3Foo");
        assert!(d.contains("Foo"), "got: {d}");
    }

    #[test]
    fn test_typeinfo_name() {
        let d = dem("_ZTS3Foo");
        assert!(d.contains("Foo"), "got: {d}");
    }

    #[test]
    fn test_std_string() {
        // _ZNSsC1Ev = std::string::string()
        let d = dem("_ZNSsC1Ev");
        assert!(ok("_ZNSsC1Ev"), "got: {d}");
    }

    #[test]
    fn test_void_return() {
        let d = dem("_Z3foov");
        assert!(d.contains("foo"), "got: {d}");
    }

    #[test]
    fn test_builtin_type_bool() {
        let d = dem("_Z3foob");
        assert!(d.contains("foo"), "got: {d}");
    }

    #[test]
    fn test_substitution_s_() {
        // _ZN3FooS_Ev — second arg is a substitution of Foo
        let _ = dem("_ZN3FooS_Ev"); // just don't panic
    }

    #[test]
    fn test_lambda_closure() {
        // _ZZ3fooiENUlvE_clEv — lambda in foo(int)
        let d = dem("_ZZ3fooiENUlvE_clEv");
        assert!(ok("_ZZ3fooiENUlvE_clEv"), "got: {d}");
    }

    #[test]
    fn test_array_type() {
        let d = dem("_Z3fooA5_i");
        assert!(d.contains("foo"), "got: {d}");
    }

    #[test]
    fn test_demangle_itanium_some() {
        assert!(demangle_itanium("_ZN3foo3barEi").is_some());
    }

    #[test]
    fn test_demangle_itanium_none() {
        assert!(demangle_itanium("main").is_none());
    }

    #[test]
    fn test_error_display() {
        let e = ItaniumError::NotMangled;
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn test_builtin_void() {
        assert_eq!(builtin_type('v'), "void");
    }

    #[test]
    fn test_builtin_long_long() {
        assert_eq!(builtin_type('x'), "long long");
    }

    #[test]
    fn test_base36_decode_0() {
        assert_eq!(base36_decode("_"), 1);
    }

    #[test]
    fn test_reference_rvalue() {
        let d = dem("_Z3fooOi");
        assert!(d.contains("foo"), "got: {d}");
    }

    #[test]
    fn test_operator_eq_eq() {
        let d = dem("_ZN3FooeqERKS_");
        assert!(ok("_ZN3FooeqERKS_"), "got: {d}");
    }

    #[test]
    fn test_cv_const_pointer() {
        let d = dem("_Z3fooPKi");
        assert!(d.contains("foo"), "got: {d}");
    }

    #[test]
    fn test_function_type() {
        let d = dem("_Z3fooFivE");
        assert!(d.contains("foo"), "got: {d}");
    }

    #[test]
    fn test_deeply_nested() {
        // _ZN1a1b1c3fooEv = a::b::c::foo()
        let d = dem("_ZN1a1b1c3fooEv");
        assert!(d.contains('a') && d.contains('c'), "got: {d}");
    }

    // --- ItaniumSymbolKind ---

    #[test]
    fn test_symbol_kind_normal() {
        assert_eq!(
            ItaniumSymbolKind::classify("_ZN3FooD1Ev"),
            ItaniumSymbolKind::Normal
        );
    }

    #[test]
    fn test_symbol_kind_vtable() {
        assert_eq!(
            ItaniumSymbolKind::classify("_ZTV3Foo"),
            ItaniumSymbolKind::VTable
        );
    }

    #[test]
    fn test_symbol_kind_typeinfo() {
        assert_eq!(
            ItaniumSymbolKind::classify("_ZTI3Foo"),
            ItaniumSymbolKind::TypeInfo
        );
    }

    #[test]
    fn test_symbol_kind_typeinfo_name() {
        assert_eq!(
            ItaniumSymbolKind::classify("_ZTS3Foo"),
            ItaniumSymbolKind::TypeInfoName
        );
    }

    #[test]
    fn test_symbol_kind_name() {
        assert_eq!(ItaniumSymbolKind::Normal.name(), "normal");
        assert_eq!(ItaniumSymbolKind::VTable.name(), "vtable");
        assert_eq!(ItaniumSymbolKind::Thunk.name(), "thunk");
    }

    // --- ItaniumBatchDemangler ---

    #[test]
    fn test_batch_demangler_cache() {
        let mut bd = ItaniumBatchDemangler::new();
        let _ = bd.demangle("_ZN3foo3barEi");
        assert_eq!(bd.cache_size(), 1);
        let _ = bd.demangle("_ZN3foo3barEi"); // cached
        assert_eq!(bd.cache_size(), 1);
    }

    #[test]
    fn test_batch_demangler_all() {
        let mut bd = ItaniumBatchDemangler::new();
        let symbols = vec!["_ZN3foo3barEi", "main"];
        let results = bd.demangle_all(&symbols);
        assert_eq!(results.len(), 2);
        assert!(results[0].is_some());
        assert!(results[1].is_none()); // "main" is not Itanium-mangled
    }

    // --- Utility functions ---

    #[test]
    fn test_extract_namespace_some() {
        assert_eq!(extract_namespace("foo::bar"), Some("foo"));
    }

    #[test]
    fn test_extract_namespace_none() {
        assert_eq!(extract_namespace("plain_func"), None);
    }

    #[test]
    fn test_is_std_symbol() {
        assert!(is_std_symbol("std::string"));
        assert!(!is_std_symbol("foo::bar"));
    }

    #[test]
    fn test_is_lambda() {
        assert!(is_lambda("foo::<lambda(int)>"));
        assert!(!is_lambda("foo::bar"));
    }

    #[test]
    fn test_standard_subs_count() {
        assert!(STANDARD_SUBS.len() >= 7);
    }

    #[test]
    fn test_lookup_standard_sub() {
        assert_eq!(lookup_standard_sub("Ss"), Some("std::string"));
    }

    #[test]
    fn test_apply_options_abbreviate_std() {
        let opts = DemanglerOptions {
            abbreviate_std: true,
            ..Default::default()
        };
        let result = apply_options("std::string::length()", &opts);
        assert!(result.contains("…::"));
    }

    // --- ItaniumSymbolInfo ---

    #[test]
    fn test_symbol_info_demangled() {
        let info = ItaniumSymbolInfo::analyze("_ZN3foo3barEi");
        assert!(info.was_demangled());
        assert!(!info.display_name().is_empty());
    }

    #[test]
    fn test_symbol_info_not_mangled() {
        let info = ItaniumSymbolInfo::analyze("main");
        assert!(!info.was_demangled());
        assert_eq!(info.display_name(), "main");
    }

    // --- ItaniumMultiDemangler ---

    #[test]
    fn test_multi_demangler_fallback() {
        let result = ItaniumMultiDemangler::demangle("main");
        assert_eq!(result, "main");
    }

    #[test]
    fn test_multi_demangler_list() {
        let results = ItaniumMultiDemangler::demangle_list(&["main", "_ZN3foo3barEi"]);
        assert_eq!(results.len(), 2);
    }
}
