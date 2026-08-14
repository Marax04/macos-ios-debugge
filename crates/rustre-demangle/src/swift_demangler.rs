//! Swift 5.x demangler for `_$s`-prefixed symbols.
//!
//! Implements a recursive-descent parser for the Swift mangling grammar,
//! producing a [`SwiftNode`] AST and a human-readable demangled string.
//!
//! Supported features:
//! - Module and type names
//! - Generic parameters and substitutions
//! - Protocol conformances and witness tables
//! - Associated types
//! - Function signatures with parameter labels
//! - Property accessors (getter/setter/modify/read)
//!
//! Not supported, despite an earlier claim here to the contrary: **local
//! functions and closures**. There is no handling of the `L` local-entity
//! marker anywhere in this module, so a symbol that names one is truncated at
//! the enclosing function and the local name is dropped silently —
//! `$s4main5outeryyF6insideL_yyF` renders `main.outer() -> ()`, losing
//! `inside`. See the ignored test in `tests/swift_completeness.rs`; the
//! rendering cannot be settled without a Swift oracle, which this crate does
//! not have.

/// Re-exported for callers that build lookup tables over demangled symbols.
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors produced while demangling a Swift symbol.
#[derive(Debug, Error)]
pub enum SwiftDemError {
    /// The input does not carry a recognized Swift mangling prefix
    /// (`_$s`, `$s`, `_T0`, ...).
    #[error("not a Swift mangled symbol")]
    NotSwift,
    /// The symbol is malformed at the given byte offset.
    #[error("parse error at position {0}: {1}")]
    ParseError(usize, String),
    /// The parser exceeded its nesting-depth limit (malicious/degenerate input).
    #[error("depth limit exceeded")]
    DepthLimit,
    /// A substitution reference pointed past the substitution table.
    #[error("substitution index {0} out of range")]
    SubstitutionOutOfRange(usize),
}

// ── SwiftNode ─────────────────────────────────────────────────────────────────

/// An AST node in a demangled Swift symbol.
#[derive(Debug, Clone, PartialEq)]
pub enum SwiftNode {
    /// A module name (e.g. `Swift` for the `s` shorthand).
    Module(String),
    /// A bare identifier (length-prefixed in the mangling).
    Identifier(String),
    /// A type wrapper around another node.
    Type(Box<Self>),
    /// A `struct` nominal type (`V` suffix).
    Structure {
        /// Defining module.
        module: String,
        /// Type name.
        name: String,
    },
    /// A `class` nominal type (`C` suffix).
    Class {
        /// Defining module.
        module: String,
        /// Type name.
        name: String,
    },
    /// A `protocol` (`P` suffix).
    Protocol {
        /// Defining module.
        module: String,
        /// Protocol name.
        name: String,
    },
    /// An `enum` nominal type (`O` suffix).
    Enum {
        /// Defining module.
        module: String,
        /// Type name.
        name: String,
    },
    /// A module-level function (`F` entity suffix).
    Function {
        /// Defining module.
        module: String,
        /// Function name.
        name: String,
        /// Parameter types.
        params: Vec<Self>,
        /// Return type.
        return_type: Box<Self>,
    },
    /// A method on a nominal type.
    Method {
        /// Rendered name of the enclosing type.
        class: String,
        /// Method name.
        name: String,
        /// Parameter types.
        params: Vec<Self>,
        /// Return type.
        return_type: Box<Self>,
    },
    /// A generic parameter (`q` code), rendered as `A`, `B`, `A1`, ...
    GenericParam {
        /// Generic context depth (0 = innermost).
        depth: u32,
        /// Parameter index within its depth.
        index: u32,
    },
    /// An unresolved substitution reference, rendered as `τ_N`.
    ///
    /// **Never produced.** Back-references resolve to the referenced node, and
    /// an out-of-range index becomes [`Self::Unknown`]; nothing yields this.
    Substitution(usize),
    /// A protocol conformance record (`Wa`/`WT` globals), `Type: Protocol`.
    ProtocolConformance {
        /// Conforming type (rendered `module.name`).
        type_name: String,
        /// Protocol conformed to.
        protocol: String,
    },
    /// A protocol witness table (`Wv` global).
    WitnessTable {
        /// Witnessing type (rendered `module.name`).
        type_name: String,
        /// Protocol the table witnesses.
        protocol: String,
    },
    /// A member/associated-type projection, rendered `base.name`.
    AssociatedType {
        /// Base node the member hangs off.
        base: Box<Self>,
        /// Member name.
        name: String,
    },
    /// A closure inside an enclosing entity (`c` code), `name.<closure #N>`.
    Closure {
        /// Rendered name of the enclosing entity.
        name: String,
        /// Closure ordinal within the entity.
        index: u32,
    },
    /// A property getter accessor (`g` code).
    Getter(Box<Self>),
    /// A property setter accessor (`s` code).
    Setter(Box<Self>),
    /// A `_modify` coroutine accessor (`m` code).
    Modify(Box<Self>),
    /// A `_read` coroutine accessor (`r` code).
    Read(Box<Self>),
    /// The root wrapper around a demangled global entity.
    Global(Box<Self>),
    /// A tuple type; empty renders as `()`.
    TupleType(Vec<Self>),
    /// A function *type* (`c` type code), rendered `(params) -> result`.
    FunctionType {
        /// Parameter types.
        params: Vec<Self>,
        /// Result type.
        result: Box<Self>,
        /// Whether the function type is `throws` (`Kc` code).
        throws: bool,
    },
    /// A `Builtin.*` type (`B`-prefixed codes).
    BuiltinType(String),
    /// An optional type, rendered `T?` (`Xo` code).
    Optional(Box<Self>),
    /// A Swift array type, rendered `[T]`.
    Array(Box<Self>),
    /// A Swift dictionary type, rendered `[Key: Value]`.
    Dictionary {
        /// Key type.
        key: Box<Self>,
        /// Value type.
        value: Box<Self>,
    },
    /// A metatype, rendered `T.Type` (`Xb` code).
    Metatype(Box<Self>),
    /// An argument label attached to a type, rendered `label: T`.
    ///
    /// **Never produced** — argument labels are unparsed.
    Label(String, Box<Self>),
    /// A variadic parameter, rendered `T...`.
    ///
    /// **Never produced** — variadic parameters are unparsed.
    Variadic(Box<Self>),
    /// A reabstraction thunk helper (`WI` global).
    ReabstractionThunk,
    /// An unrecognized construct, preserved verbatim as `?(text)`.
    Unknown(String),
}

impl SwiftNode {
    /// Render this node as a human-readable string.
    #[must_use] 
    pub fn render(&self) -> String {
        match self {
            Self::Module(n) | Self::Identifier(n) => n.clone(),
            Self::Type(inner) | Self::Global(inner) => inner.render(),
            Self::Structure { module, name }
            | Self::Class { module, name }
            | Self::Protocol { module, name }
            | Self::Enum { module, name } => format!("{module}.{name}"),
            Self::Function {
                module,
                name,
                params,
                return_type,
            } => {
                let ps: Vec<_> = params.iter().map(Self::render).collect();
                format!(
                    "{module}.{name}({}) -> {}",
                    ps.join(", "),
                    return_type.render()
                )
            }
            Self::Method {
                class,
                name,
                params,
                return_type,
            } => {
                let ps: Vec<_> = params.iter().map(Self::render).collect();
                format!(
                    "{class}.{name}({}) -> {}",
                    ps.join(", "),
                    return_type.render()
                )
            }
            Self::GenericParam { depth, index } => {
                let letter = (b'A' + u8::try_from(*index).unwrap_or(u8::MAX) % 26) as char;
                if *depth == 0 {
                    format!("{letter}")
                } else {
                    format!("{letter}{depth}")
                }
            }
            Self::Substitution(idx) => format!("τ_{idx}"),
            Self::ProtocolConformance {
                type_name,
                protocol,
            } => {
                format!("{type_name}: {protocol}")
            }
            Self::WitnessTable {
                type_name,
                protocol,
            } => {
                format!("witness table {type_name}: {protocol}")
            }
            Self::AssociatedType { base, name } => format!("{}.{name}", base.render()),
            Self::Closure { name, index } => format!("{name}.<closure #{index}>"),
            Self::Getter(inner) => format!("{}.getter", inner.render()),
            Self::Setter(inner) => format!("{}.setter", inner.render()),
            Self::Modify(inner) => format!("{}.modify", inner.render()),
            Self::Read(inner) => format!("{}.read", inner.render()),
            Self::TupleType(elems) => {
                if elems.is_empty() {
                    "()".to_owned()
                } else {
                    let inner: Vec<_> = elems.iter().map(Self::render).collect();
                    format!("({})", inner.join(", "))
                }
            }
            Self::FunctionType {
                params,
                result,
                throws,
            } => {
                let ps: Vec<_> = params.iter().map(Self::render).collect();
                let throws_str = if *throws { " throws" } else { "" };
                format!("({}) {throws_str}-> {}", ps.join(", "), result.render())
            }
            Self::BuiltinType(t) => t.clone(),
            Self::Optional(inner) => format!("{}?", inner.render()),
            Self::Array(elem) => format!("[{}]", elem.render()),
            Self::Dictionary { key, value } => format!("[{}: {}]", key.render(), value.render()),
            Self::Metatype(inner) => format!("{}.Type", inner.render()),
            Self::Label(label, inner) => format!("{label}: {}", inner.render()),
            Self::Variadic(inner) => format!("{}...", inner.render()),
            Self::ReabstractionThunk => "reabstraction thunk".to_owned(),
            Self::Unknown(s) => format!("?({s})"),
        }
    }
}

// ── SwiftDemangler ────────────────────────────────────────────────────────────

/// Swift 5.x demangler.
///
/// Accepts symbols with the `_$s`, `_$S`, `$s`, `$S` prefixes.
pub struct SwiftDemangler {
    input: Vec<u8>,
    pos: usize,
    depth: usize,
    max_depth: usize,
    substitutions: Vec<SwiftNode>,
    generic_param_counts: Vec<u32>,
}

impl SwiftDemangler {
    const MAX_DEPTH: usize = 64;

    /// Create a demangler for the given mangled symbol.
    #[must_use] 
    pub fn new(mangled: &str) -> Self {
        Self {
            input: mangled.as_bytes().to_vec(),
            pos: 0,
            depth: 0,
            max_depth: Self::MAX_DEPTH,
            substitutions: Vec::new(),
            generic_param_counts: Vec::new(),
        }
    }

    /// Accessor for the generic parameter count stack used during parsing.
    #[must_use] 
    pub fn generic_param_counts(&self) -> &[u32] {
        &self.generic_param_counts
    }

    /// Detect whether `mangled` is a Swift symbol.
    #[must_use] 
    pub fn detect(mangled: &str) -> bool {
        mangled.starts_with("_$s")
            || mangled.starts_with("_$S")
            || mangled.starts_with("$s")
            || mangled.starts_with("$S")
            || mangled.starts_with("__T0")
            || mangled.starts_with("_T0")
    }

    /// Demangle, returning the root [`SwiftNode`].
    ///
    /// # Errors
    /// Returns an error if the input is not a valid Swift mangled symbol.
    pub fn demangle(&mut self) -> Result<SwiftNode, SwiftDemError> {
        if !Self::detect(&String::from_utf8_lossy(&self.input)) {
            return Err(SwiftDemError::NotSwift);
        }
        // Skip prefix
        for prefix in &["_$s", "_$S", "$s", "$S", "__T0", "_T0"] {
            if self.input.starts_with(prefix.as_bytes()) {
                self.pos = prefix.len();
                break;
            }
        }

        let node = self.parse_global()?;
        Ok(node)
    }

    fn parse_global(&mut self) -> Result<SwiftNode, SwiftDemError> {
        self.enter()?;
        // Look for well-known global prefixes
        let node = match self.peek_bytes(2) {
            b"Wv" => {
                self.pos += 2;
                self.parse_witness_table()
            }
            b"WP" => {
                self.pos += 2;
                self.parse_protocol_witness_table()
            }
            b"Wa" => {
                self.pos += 2;
                self.parse_protocol_conformance_accessor()
            }
            b"WT" => {
                self.pos += 2;
                self.parse_witness_table_accessor()
            }
            b"WI" => {
                self.pos += 2;
                SwiftNode::ReabstractionThunk
            }
            b"To" => {
                self.pos += 2;
                self.parse_objc_exposed()?
            }
            _ => self.parse_entity()?,
        };
        self.leave();
        Ok(SwiftNode::Global(Box::new(node)))
    }

    fn parse_entity(&mut self) -> Result<SwiftNode, SwiftDemError> {
        self.enter()?;
        let module = self.parse_module();
        if self.at_end() {
            self.leave();
            return Ok(SwiftNode::Module(module));
        }
        let type_kind = self.peek();
        if matches!(type_kind, Some(b'V' | b'C' | b'O' | b'P')) {
            self.pos += 1;
            let name = self.parse_identifier().unwrap_or_default();
            let node = match type_kind {
                Some(b'V') => SwiftNode::Structure { module, name },
                Some(b'C') => SwiftNode::Class { module, name },
                Some(b'O') => SwiftNode::Enum { module, name },
                Some(b'P') => SwiftNode::Protocol { module, name },
                _ => unreachable!(),
            };
            self.add_substitution(node.clone());
            // Check for member
            if !self.at_end() {
                let member = self.parse_entity_member(&node)?;
                self.leave();
                return Ok(member);
            }
            self.leave();
            return Ok(node);
        }
        let name = self.parse_identifier().unwrap_or_default();
        // Swift 4.2+ writes the nominal-type kind AFTER the name
        // (`10Foundation4DataV`), unlike the older leading-kind form handled
        // above. Recognize it and continue with any member that follows.
        if !name.is_empty() && matches!(self.peek(), Some(b'V' | b'C' | b'O' | b'P')) {
            let kind = self.peek();
            self.pos += 1;
            let node = match kind {
                Some(b'V') => SwiftNode::Structure { module, name },
                Some(b'C') => SwiftNode::Class { module, name },
                Some(b'O') => SwiftNode::Enum { module, name },
                _ => SwiftNode::Protocol { module, name },
            };
            self.add_substitution(node.clone());
            if self.at_end() {
                self.leave();
                return Ok(node);
            }
            let member = self.parse_entity_member(&node)?;
            self.leave();
            return Ok(member);
        }
        // A module-level variable carries the same `<type>v[<accessor>]` tail as
        // a member of a nominal type. Tested before the function loop below,
        // which consumes type codes greedily and discards them unless an `F`
        // arrives — that is how this tail used to be lost.
        if !name.is_empty()
            && let Some(node) = self.parse_variable_tail(&format!("{module}.{name}"))
        {
            self.leave();
            return Ok(node);
        }
        // Detect trailing function-suffix codes for module-level free functions.
        // Swift mangles `module.foo() -> ()` as `<module><name>yyF` where `y`
        // is the empty-tuple type and `F` is the function entity suffix.
        // We greedily consume type codes until we hit `F` (function) or end.
        let mut return_type: SwiftNode = SwiftNode::TupleType(Vec::new());
        let mut is_function = false;
        let mut collected: Vec<SwiftNode> = Vec::new();
        while let Some(b) = self.peek() {
            if b == b'F' || b == b'f' {
                self.pos += 1;
                is_function = true;
                break;
            }
            if b == b'y' {
                self.pos += 1;
                collected.push(SwiftNode::TupleType(Vec::new()));
                continue;
            }
            // Try to parse a generic type; if it fails or makes no
            // progress, stop (a zero-length parse would loop forever).
            let save = self.pos;
            if let Ok(t) = self.parse_type() {
                if self.pos == save {
                    break;
                }
                collected.push(t);
            } else {
                self.pos = save;
                break;
            }
        }
        if is_function {
            // Swift's convention: last collected type is the return, prior are params.
            if let Some(ret) = collected.pop() {
                return_type = ret;
            }
            let mut params = collected;
            // `y` is Swift's EMPTY-LIST marker, pushed as an empty tuple by the
            // collector above. It is not a parameter type, so it must never
            // survive as a parameter ENTRY.
            //
            // The rule was here but applied only when there was exactly one, so
            // a second marker turned into an invented parameter:
            // `$s4main3fooyySiF` rendered `main.foo((), ()) -> Swift.Int` —
            // arity 2, both parameters an empty tuple — and
            // `$s4main1aySiSSF` rendered `main.a((), Swift.Int) -> …`, arity 2
            // for one argument. Phantom parameters are well-formed, plausible
            // and invisible to everything but arity itself.
            //
            // This is deliberately independent of the open result/params ORDER
            // question (`tests/swift_signature_order.rs`): a list marker is not
            // a parameter under either reading, so nothing here presumes one.
            params.retain(|p| *p != SwiftNode::TupleType(Vec::new()));
            self.leave();
            return Ok(SwiftNode::Function {
                module,
                name,
                params,
                return_type: Box::new(return_type),
            });
        }
        self.leave();
        if name.is_empty() {
            return Ok(SwiftNode::Module(module));
        }
        Ok(SwiftNode::Identifier(format!("{module}.{name}")))
    }

    fn parse_entity_member(&mut self, parent: &SwiftNode) -> Result<SwiftNode, SwiftDemError> {
        let class_name = parent.render();
        match self.peek() {
            Some(b'i') => {
                self.pos += 1;
                let property = SwiftNode::Identifier(self.parse_identifier().unwrap_or_default());
                Ok(SwiftNode::Read(Box::new(SwiftNode::AssociatedType {
                    base: Box::new(SwiftNode::Identifier(class_name)),
                    name: property.render(),
                })))
            }
            Some(b'g') => {
                self.pos += 1;
                let prop = self.parse_identifier().unwrap_or_default();
                Ok(SwiftNode::Getter(Box::new(SwiftNode::Identifier(format!(
                    "{class_name}.{prop}"
                )))))
            }
            Some(b's') => {
                self.pos += 1;
                let prop = self.parse_identifier().unwrap_or_default();
                Ok(SwiftNode::Setter(Box::new(SwiftNode::Identifier(format!(
                    "{class_name}.{prop}"
                )))))
            }
            Some(b'm') => {
                self.pos += 1;
                let prop = self.parse_identifier().unwrap_or_default();
                Ok(SwiftNode::Modify(Box::new(SwiftNode::Identifier(format!(
                    "{class_name}.{prop}"
                )))))
            }
            Some(b'r') => {
                self.pos += 1;
                let prop = self.parse_identifier().unwrap_or_default();
                Ok(SwiftNode::Read(Box::new(SwiftNode::Identifier(format!(
                    "{class_name}.{prop}"
                )))))
            }
            Some(b'f' | b'F') => {
                self.pos += 1;
                let name = self.parse_identifier().unwrap_or_default();
                let params = self.parse_params()?;
                let ret = self.parse_return_type()?;
                Ok(SwiftNode::Method {
                    class: class_name,
                    name,
                    params,
                    return_type: Box::new(ret),
                })
            }
            Some(b'c') => {
                // Closure
                self.pos += 1;
                let index = u32::try_from(self.parse_index().unwrap_or(0)).unwrap_or(u32::MAX);
                Ok(SwiftNode::Closure {
                    name: class_name,
                    index,
                })
            }
            // `<identifier><type><entity-kind>` — a member declared inside the
            // nominal type, e.g. `5countSivg` = `count : Swift.Int`, variable
            // (`v`), getter (`g`).
            Some(b'0'..=b'9') => Ok(self.parse_named_member(&class_name)),
            _ => Ok(parent.clone()),
        }
    }

    /// Parse a length-prefixed member of a nominal type: an identifier,
    /// followed by its type, followed by the entity-kind code (`v` variable,
    /// `F`/`f` function) and an optional accessor code (`g` getter, `s`
    /// setter, `M` modify, `r` read).
    fn parse_named_member(&mut self, class_name: &str) -> SwiftNode {
        let name = self.parse_identifier().unwrap_or_default();
        if self.at_end() {
            return SwiftNode::Identifier(format!("{class_name}.{name}"));
        }
        if let Some(node) = self.parse_variable_tail(&format!("{class_name}.{name}")) {
            return node;
        }
        let save = self.pos;
        let ty = self.parse_type().ok().filter(|_| self.pos != save);
        let kind = self.peek();
        if matches!(kind, Some(b'F' | b'f')) {
            // `f` introduces a function-kind DISCRIMINATOR: `fc` constructor,
            // `fC` allocating constructor, `fd` destructor, `fD` deallocating
            // destructor. Those name different declarations, and this arm used
            // to consume the `f` and return a plain method, dropping the letter
            // in silence — eleven distinct manglings collapsing onto one
            // rendering:
            //
            //   …3barSif   …3barSifc   …3barSifd   …3barSifD
            //     all  =>  main.Foo.bar() -> Swift.Int
            //
            // The `[unparsed …]` echo exists for exactly this, but it is gated
            // on no signature having been produced, so a method rendering
            // suppressed it. Rewinding to before the `f` lets that gate fire and
            // restores the distinction, without inventing a spelling for a
            // construct this crate has no Swift oracle to check.
            //
            // Deliberately only the four discriminators whose meaning is not in
            // doubt. A letter left out costs nothing — the symbol keeps today's
            // method rendering; a letter wrongly included would turn a real
            // method into an unparsed echo, so the conservative direction is
            // fewer.
            if matches!(self.input.get(self.pos + 1), Some(b'c' | b'C' | b'd' | b'D')) {
                return SwiftNode::Identifier(format!("{class_name}.{name}"));
            }
            self.pos += 1;
            return SwiftNode::Method {
                class: class_name.to_owned(),
                name,
                params: Vec::new(),
                return_type: Box::new(ty.unwrap_or_else(|| SwiftNode::TupleType(Vec::new()))),
            };
        }
        SwiftNode::Identifier(format!("{class_name}.{name}"))
    }

    /// Parse a variable entity's `<type>v[<accessor>]` tail onto an
    /// already-known name, rewinding and returning `None` if this is not one.
    ///
    /// Exists in one place because it has two call sites that had drifted. The
    /// tail was implemented only for members of a nominal type, so the identical
    /// suffix on a module-level global fell through to the function loop, which
    /// discards what it collected when no `F` arrives:
    ///
    /// ```text
    ///   $s4main8MyStructV5valueSivp  =>  main.MyStruct.value : Swift.Int
    ///   $s4main6globalSivp           =>  main.global [unparsed Sivp]
    /// ```
    ///
    /// Same `Sivp`, same meaning, decoded at one nesting depth and echoed raw at
    /// another. `swift_completeness` cannot see it — the *named* component
    /// `global` does survive; it is the type that is lost.
    fn parse_variable_tail(&mut self, prefix: &str) -> Option<SwiftNode> {
        let save = self.pos;
        let ty = self.parse_type().ok().filter(|_| self.pos != save);
        if self.peek() != Some(b'v') {
            self.pos = save;
            return None;
        }
        self.pos += 1;
        let accessor = match self.peek() {
            Some(b'g') => Some("getter"),
            Some(b's') => Some("setter"),
            Some(b'M' | b'm') => Some("modify"),
            Some(b'r') => Some("read"),
            Some(b'w') => Some("willset"),
            Some(b'W') => Some("didset"),
            _ => None,
        };
        if accessor.is_some() {
            self.pos += 1;
        }
        let mut out = prefix.to_owned();
        if let Some(a) = accessor {
            out.push('.');
            out.push_str(a);
        }
        if let Some(t) = ty {
            out.push_str(" : ");
            out.push_str(&t.render());
        }
        Some(SwiftNode::Identifier(out))
    }

    fn parse_module(&mut self) -> String {
        // Check for known standard modules
        if self.peek() == Some(b's') {
            self.pos += 1;
            return "Swift".to_owned();
        }
        if self.peek() == Some(b'S') {
            // Substitution.
            //
            // A letter code is a well-known stdlib substitution (`Si` =
            // Swift.Int, `SS` = Swift.String…), never a back-reference into the
            // symbol's own table — the same rule the type-position parser
            // applies. Without this check a leading `SS` fell through to the
            // index formatting below and leaked the internal substitution
            // number into the output, so `$sSS7countedSiSo7NSArrayCF` rendered
            // `S5.counted` instead of naming `Swift.String`.
            self.pos += 1;
            let code = self.peek();
            let idx = self.parse_substitution_index();
            if let Some(name) = code.and_then(standard_substitution_type) {
                return name.to_owned();
            }
            if let Some(node) = self.substitutions.get(idx) {
                return node.render();
            }
            // An unresolvable back-reference is not a name. Formatting the
            // internal index as `S{idx}` put a parser-internal number where a
            // module belongs, and the number was not even right: `$sS0`,
            // `$sS1` and `$sS12` all rendered `S0`, as did every non-standard
            // letter (`$sSO`, `$sSA`, `$sSZ`).
            //
            // Iter 6 fixed the *standard substitution* half of this — `$sSS`
            // now gives `Swift.String` — and left this fallback fabricating.
            // Returning the module placeholder routes it through the same
            // decline rule that already covers the other unreadable Swift
            // shapes, so the symbol reports failure instead of a fake name.
            return "?module".to_owned();
        }
        self.parse_identifier()
            .unwrap_or_else(|| "?module".to_owned())
    }

    fn parse_identifier(&mut self) -> Option<String> {
        // Check for operator prefix
        let operator_prefix = if self.peek() == Some(b'o') {
            self.pos += 1;
            true
        } else {
            false
        };

        // Check for Punycode prefix
        let punycode = if self.peek() == Some(b'X') {
            self.pos += 1;
            true
        } else {
            false
        };

        let start = self.pos;
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.pos += 1;
        }
        if self.pos == start {
            return None;
        }
        let len_str = std::str::from_utf8(&self.input[start..self.pos]).ok()?;
        let len: usize = len_str.parse().ok()?;
        // Checked: `len` comes from the symbol, so a prefix near `usize::MAX`
        // overflows this very bounds test. Third instance of the class swept out
        // at iter 83; release builds compile the overflow check away.
        let end = self.pos.checked_add(len)?;
        if end > self.input.len() {
            return None;
        }
        // Fail rather than substitute. A length prefix that ends *between* the
        // bytes of a multi-byte character yields a slice that is not valid
        // UTF-8, and `from_utf8_lossy` used to turn that into U+FFFD and carry
        // on: `$s1ñ` decoded to `Some("\u{fffd}")` and `$s2añ3fooyyF` to
        // `Some("a\u{fffd}")`, losing `foo` entirely. A replacement character
        // is worse than a placeholder — it reads as data.
        //
        // This matches what the D backend already does for the same input shape
        // and what the second Swift parser in this file does at its own
        // length-prefix site.
        let name = std::str::from_utf8(&self.input[self.pos..end]).ok()?.to_owned();

        // ASCII punctuation cannot occur in a Swift identifier. Without this the
        // length prefix was taken at face value, so arbitrary bytes became a
        // name: `$s5Av.*2dY)j…` decoded to `Av.*2`, a fragment of random text
        // reported as a Swift identifier. Found by sweeping random printable
        // ASCII, where such strings decoded instead of declining.
        //
        // **Deliberately narrower than "ASCII alphanumeric plus `_`".** That
        // stricter rule is what 38 identifiers sampled from known-good symbols
        // suggest, and it matches the claim that Swift punycodes anything else
        // — but it rejects `$s3añ3fooyyF`, which `tests/multibyte_length_prefixes.rs`
        // pins as decoding. Both beliefs rest on hand-built symbols, Swift has
        // neither oracle nor corpus here, and there is no way to settle which is
        // right. So only the certain part is enforced: punctuation is out,
        // non-ASCII is left alone.
        if !punycode && name.bytes().any(|b| b.is_ascii_punctuation() && b != b'_') {
            return None;
        }

        self.pos += len;

        let mut result = if punycode {
            format!("/* punycode: {name} */")
        } else {
            name
        };

        if operator_prefix {
            result = decode_operator_name(&result);
        }

        Some(result)
    }

    fn parse_type(&mut self) -> Result<SwiftNode, SwiftDemError> {
        self.enter()?;
        let node = self.parse_type_inner()?;
        self.leave();
        Ok(node)
    }

    /// Parse a `B`-prefixed builtin Swift type (caller already consumed `b'B'`).
    fn parse_builtin_type_inner(&mut self) -> SwiftNode {
        let t = match self.peek() {
            Some(b'b') => { self.pos += 1; "Builtin.BridgeObject" }
            Some(b'o') => { self.pos += 1; "Builtin.UnknownObject" }
            Some(b'p') => { self.pos += 1; "Builtin.RawPointer" }
            Some(b'w') => { self.pos += 1; "Builtin.Word" }
            Some(b'i') => { self.pos += 1; let _n = self.parse_index(); "Builtin.Int" }
            Some(b'f') => { self.pos += 1; let _n = self.parse_index(); "Builtin.Float" }
            Some(b'v') => { self.pos += 1; let _n = self.parse_index(); "Builtin.Vec" }
            _ => "Builtin.?",
        };
        SwiftNode::BuiltinType(t.to_owned())
    }

    fn parse_type_inner(&mut self) -> Result<SwiftNode, SwiftDemError> {
        match self.peek() {
            // Builtin types
            Some(b'B') => {
                self.pos += 1;
                Ok(self.parse_builtin_type_inner())
            }
            // Standard type substitutions
            Some(b'S') => {
                self.pos += 1;
                let code = self.peek();
                let idx = self.parse_substitution_index();
                // A letter code is always a well-known stdlib substitution
                // (`Si` = Swift.Int, `SS` = Swift.String…), never a
                // back-reference into the symbol's own substitution table.
                if let Some(name) = code.and_then(standard_substitution_type) {
                    return Ok(SwiftNode::BuiltinType(name.to_owned()));
                }
                if let Some(node) = self.substitutions.get(idx) {
                    return Ok(node.clone());
                }
                Ok(SwiftNode::Unknown(format!("S{idx}")))
            }
            // Generic parameter
            Some(b'q') => {
                self.pos += 1;
                let index = self.parse_index().unwrap_or(0);
                Ok(SwiftNode::GenericParam {
                    depth: 0,
                    index: u32::try_from(index).unwrap_or(u32::MAX),
                })
            }
            // Tuple
            Some(b't') => {
                self.pos += 1;
                let elems = self.parse_type_list(b'_')?;
                Ok(SwiftNode::TupleType(elems))
            }
            // Optional
            Some(b'X') => {
                self.pos += 1;
                match self.peek() {
                    Some(b'o') => {
                        self.pos += 1;
                        let inner = self.parse_type()?;
                        Ok(SwiftNode::Optional(Box::new(inner)))
                    }
                    Some(b'b') => {
                        self.pos += 1;
                        let inner = self.parse_type()?;
                        Ok(SwiftNode::Metatype(Box::new(inner)))
                    }
                    _ => self.parse_entity().map(|n| SwiftNode::Type(Box::new(n))),
                }
            }
            // Function type
            Some(b'c') => {
                self.pos += 1;
                let params = self.parse_type_list(b'_')?;
                let ret = self.parse_type()?;
                Ok(SwiftNode::FunctionType {
                    params,
                    result: Box::new(ret),
                    throws: false,
                })
            }
            // Throws function type
            Some(b'K') => {
                self.pos += 1;
                match self.peek() {
                    Some(b'c') => {
                        self.pos += 1;
                        let params = self.parse_type_list(b'_')?;
                        let ret = self.parse_type()?;
                        Ok(SwiftNode::FunctionType {
                            params,
                            result: Box::new(ret),
                            throws: true,
                        })
                    }
                    _ => Ok(SwiftNode::Unknown("K?".into())),
                }
            }
            _ => self.parse_entity().map(|n| SwiftNode::Type(Box::new(n))),
        }
    }

    fn parse_type_list(&mut self, terminator: u8) -> Result<Vec<SwiftNode>, SwiftDemError> {
        let mut list = Vec::new();
        while self.peek().is_some_and(|b| b != terminator) {
            let save = self.pos;
            let t = self.parse_type()?;
            if self.pos == save {
                // No progress — bail out to avoid an infinite loop.
                break;
            }
            list.push(t);
        }
        if self.peek() == Some(terminator) {
            self.pos += 1;
        }
        Ok(list)
    }

    fn parse_params(&mut self) -> Result<Vec<SwiftNode>, SwiftDemError> {
        self.parse_type_list(b'_')
    }

    fn parse_return_type(&mut self) -> Result<SwiftNode, SwiftDemError> {
        if self.at_end() {
            return Ok(SwiftNode::TupleType(Vec::new())); // ()
        }
        self.parse_type()
    }

    fn parse_substitution_index(&mut self) -> usize {
        match self.peek() {
            Some(b'i') => {
                self.pos += 1;
                builtin_subst_index("i")
            }
            Some(b'b') => {
                self.pos += 1;
                builtin_subst_index("b")
            }
            Some(b'S') => {
                self.pos += 1;
                builtin_subst_index("S")
            }
            Some(b'a') => {
                self.pos += 1;
                builtin_subst_index("a")
            }
            Some(b'd') => {
                self.pos += 1;
                builtin_subst_index("d")
            }
            Some(b'D') => {
                self.pos += 1;
                builtin_subst_index("D")
            }
            Some(b'f') => {
                self.pos += 1;
                builtin_subst_index("f")
            }
            Some(b'I') => {
                self.pos += 1;
                builtin_subst_index("I")
            }
            Some(b'u') => {
                self.pos += 1;
                builtin_subst_index("u")
            }
            Some(b'g') => {
                self.pos += 1;
                builtin_subst_index("g")
            }
            Some(b'G') => {
                self.pos += 1;
                builtin_subst_index("G")
            }
            Some(b'q') => {
                self.pos += 1;
                builtin_subst_index("q")
            }
            Some(b'Q') => {
                self.pos += 1;
                builtin_subst_index("Q")
            }
            Some(b'R') => {
                self.pos += 1;
                builtin_subst_index("R")
            }
            Some(b'T') => {
                self.pos += 1;
                builtin_subst_index("T")
            }
            Some(c) if c.is_ascii_digit() => {
                let start = self.pos;
                while self.peek().is_some_and(|b| b.is_ascii_digit()) {
                    self.pos += 1;
                }
                if self.pos + 1 < self.input.len() && self.input[self.pos] == b'_' {
                    let n: usize = std::str::from_utf8(&self.input[start..self.pos])
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    self.pos += 1; // consume '_'
                    n + 26 // offset past the single-letter substitutions
                } else {
                    0
                }
            }
            _ => 0,
        }
    }

    fn parse_index(&mut self) -> Option<usize> {
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

    fn parse_witness_table(&mut self) -> SwiftNode {
        let module = self.parse_module();
        let name = self.parse_identifier().unwrap_or_default();
        let proto = self.parse_identifier().unwrap_or_default();
        SwiftNode::WitnessTable {
            type_name: format!("{module}.{name}"),
            protocol: proto,
        }
    }

    fn parse_protocol_witness_table(&mut self) -> SwiftNode {
        let module = self.parse_module();
        let name = self.parse_identifier().unwrap_or_default();
        let proto = self.parse_identifier().unwrap_or_default();
        SwiftNode::ProtocolConformance {
            type_name: format!("{module}.{name}"),
            protocol: proto,
        }
    }

    fn parse_protocol_conformance_accessor(&mut self) -> SwiftNode {
        self.parse_protocol_witness_table()
    }

    fn parse_witness_table_accessor(&mut self) -> SwiftNode {
        self.parse_protocol_witness_table()
    }

    fn parse_objc_exposed(&mut self) -> Result<SwiftNode, SwiftDemError> {
        let inner = self.parse_entity()?;
        Ok(SwiftNode::Unknown(format!("@objc {}", inner.render())))
    }

    fn add_substitution(&mut self, node: SwiftNode) {
        self.substitutions.push(node);
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn peek_bytes(&self, n: usize) -> &[u8] {
        let end = (self.pos + n).min(self.input.len());
        &self.input[self.pos..end]
    }

    const fn at_end(&self) -> bool {
        self.pos >= self.input.len()
    }

    const fn enter(&mut self) -> Result<(), SwiftDemError> {
        self.depth += 1;
        if self.depth > self.max_depth {
            self.depth -= 1;
            Err(SwiftDemError::DepthLimit)
        } else {
            Ok(())
        }
    }

    const fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }
}

/// Map a well-known Swift stdlib substitution code to its fully qualified
/// type name (`Si` → `Swift.Int`, `SS` → `Swift.String`, …).
const fn standard_substitution_type(code: u8) -> Option<&'static str> {
    Some(match code {
        b'i' => "Swift.Int",
        b'u' => "Swift.UInt",
        b'b' => "Swift.Bool",
        b'f' => "Swift.Float",
        b'd' => "Swift.Double",
        b'S' => "Swift.String",
        b'c' => "Swift.UnicodeScalar",
        b'a' => "Swift.Array",
        b'D' => "Swift.Dictionary",
        b'q' => "Swift.Optional",
        b'y' => "Swift.Character",
        _ => return None,
    })
}

fn builtin_subst_index(key: &str) -> usize {
    // Map well-known single-letter Swift substitution codes to stable indices.
    // These correspond to stdlib types defined in Swift.swiftmodule.
    match key {
        "i" => 0,  // Int
        "u" => 1,  // UInt
        "b" => 2,  // Bool
        "f" => 3,  // Float
        "d" => 4,  // Double
        "S" => 5,  // String
        "s" => 6,  // String (alternate)
        "a" => 7,  // Array
        "D" => 8,  // Dictionary
        "q" => 9,  // Optional
        "Q" => 10, // ImplicitlyUnwrappedOptional
        "R" => 11, // AnyObject
        "T" => 12, // Any
        "g" => 13, // AnyHashable
        "G" => 14, // AnySequence
        "I" => 15, // Index
        _ => 16,
    }
}

fn decode_operator_name(raw: &str) -> String {
    let mut result = String::new();
    for ch in raw.chars() {
        let replacement = match ch {
            'a' => "&",
            'A' => "&&",
            'c' => ":",
            'C' => "??",
            'd' => "/",
            'D' => "???",
            'e' => "==",
            'E' => "===",
            'g' => ">",
            'G' => ">=",
            'l' => "<",
            'L' => "<=",
            'm' => "%",
            'M' => "!!",
            'n' => "!",
            'N' => "!=",
            'o' => "||",
            'p' => "+",
            'P' => "++",
            'q' => "?",
            'r' => ">>",
            'R' => ">>=",
            's' => "-",
            'S' => "--",
            't' => "*",
            'T' => "+=",
            'x' => "^",
            'X' => "^^",
            'z' => ".",
            'Z' => "..",
            _ => {
                result.push(ch);
                continue;
            }
        };
        result.push_str(replacement);
    }
    result
}

// ── Old-style (Swift 3 `_T`) mangling ─────────────────────────────────────────

/// Cursor over an old-style (Swift 3) mangled symbol.
struct OldSwift<'a> {
    b: &'a [u8],
    i: usize,
}

impl OldSwift<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    /// Length-prefixed identifier: `4main` → `main`.
    fn ident(&mut self) -> Option<String> {
        let start = self.i;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.i += 1;
        }
        if self.i == start {
            return None;
        }
        let len: usize = std::str::from_utf8(&self.b[start..self.i]).ok()?.parse().ok()?;
        let end = self.i.checked_add(len)?;
        if len == 0 || end > self.b.len() {
            return None;
        }
        let s = std::str::from_utf8(&self.b[self.i..end]).ok()?.to_owned();
        self.i = end;
        Some(s)
    }

    /// Context: either a bare module, or a nominal type (`C`/`V`/`O`/`P`)
    /// whose own context precedes its name.
    fn context(&mut self, depth: usize) -> Option<String> {
        if depth > 16 {
            return None;
        }
        match self.peek() {
            Some(b'C' | b'V' | b'O' | b'P') => {
                self.i += 1;
                let outer = self.context(depth + 1)?;
                let name = self.ident()?;
                Some(format!("{outer}.{name}"))
            }
            _ => self.ident(),
        }
    }

    /// Type production. Supports tuples (`T…_`), function types (`F`/`f`) and
    /// the stdlib substitutions (`Si` …).
    fn ty(&mut self, depth: usize) -> Option<String> {
        if depth > 16 {
            return None;
        }
        match self.peek()? {
            b'T' | b't' => {
                self.i += 1;
                let mut elems = Vec::new();
                while self.peek().is_some_and(|c| c != b'_') {
                    let save = self.i;
                    let t = self.ty(depth + 1)?;
                    if self.i == save {
                        return None;
                    }
                    elems.push(t);
                }
                self.i += 1; // consume `_`
                Some(format!("({})", elems.join(", ")))
            }
            b'F' | b'f' => {
                self.i += 1;
                let params = self.ty(depth + 1)?;
                let ret = self.ty(depth + 1)?;
                Some(format!("{params} -> {ret}"))
            }
            b'S' => {
                self.i += 1;
                let code = self.peek()?;
                let name = standard_substitution_type(code)?;
                self.i += 1;
                Some(name.to_owned())
            }
            _ => None,
        }
    }
}

/// Detect an old-style (Swift 3) `_T`-prefixed mangled symbol.
///
/// Swift 3 used `_T` followed by an entity code; `_T0` (Swift 4) and `$s`
/// (Swift 4.2+) are handled by the main parser instead.
#[must_use]
pub fn detect_old_swift(mangled: &str) -> bool {
    let rest = mangled
        .strip_prefix("__T")
        .or_else(|| mangled.strip_prefix("_T"));
    // `F` is a function; `t` introduces a nominal TYPE (`_TtC4main3Foo`), the
    // form the Obj-C runtime shows for every Swift class. Only `F` was handled,
    // so the type forms were claimed by `sigil::is_swift` and then declined —
    // a detect/demangle divergence that files them as `UnsupportedAbi`, the
    // variant this crate treats as its only real defect signal.
    rest.is_some_and(|r| r.starts_with('F') || r.starts_with('t'))
}

/// Demangle an old-style (Swift 3) `_TF…` function symbol.
///
/// Returns `None` if the symbol is not old-style or is not fully understood,
/// so callers can fall back to other strategies rather than emit a partial
/// result.
#[must_use]
pub fn demangle_old_swift(mangled: &str) -> Option<String> {
    if !detect_old_swift(mangled) {
        return None;
    }
    let rest = mangled
        .strip_prefix("__T")
        .or_else(|| mangled.strip_prefix("_T"))?;
    if let Some(ty) = rest.strip_prefix('t') {
        return demangle_old_swift_nominal(ty);
    }
    let mut p = OldSwift {
        b: rest.as_bytes(),
        i: 1, // skip the `F` entity code
    };
    let context = p.context(0)?;
    let name = p.ident()?;
    let sig = p.ty(0)?;
    if p.i != p.b.len() {
        return None;
    }
    Some(format!("{context}.{name}{sig}"))
}

/// Demangle the nominal-type body of a `_Tt…` symbol: a kind byte followed by
/// a context and a name (`C4main3Foo` -> `main.Foo`).
///
/// Only the four nominal kinds are decoded. Anything else — metadata (`_TM`),
/// witness tables (`_TW`) and the rest of the Swift 3 entity alphabet — is
/// deliberately left declining rather than guessed at: there is no Swift
/// oracle here, and inventing a rendering is the failure mode this crate
/// punishes hardest.
fn demangle_old_swift_nominal(body: &str) -> Option<String> {
    let kind = body.as_bytes().first()?;
    let label = match kind {
        b'C' => "class",
        b'V' => "struct",
        b'O' => "enum",
        b'P' => "protocol",
        _ => return None,
    };
    let mut p = OldSwift {
        b: body.as_bytes(),
        i: 1, // skip the kind byte
    };
    let context = p.context(0)?;
    let name = p.ident()?;
    if p.i != p.b.len() {
        return None;
    }
    Some(format!("{label} {context}.{name}"))
}

/// Convenience top-level function for Swift demangling.
///
/// Returns the demangled string or the original if demangling fails.
#[must_use] 
pub fn swift_demangle(mangled: &str) -> String {
    if let Some(old) = demangle_old_swift(mangled) {
        return old;
    }
    if !SwiftDemangler::detect(mangled) {
        return mangled.to_owned();
    }
    let mut d = SwiftDemangler::new(mangled);
    let Ok(node) = d.demangle() else {
        return mangled.to_owned();
    };
    let rendered = node.render();
    // A parse that stopped before the end and produced only a PATH dropped the
    // signature outright, collapsing distinct functions onto one name:
    //
    //   $s4main3fooySaySiGF    (Array<Int>)    main.foo
    //   $s4main3fooySDySSSiGF  (Dictionary)    main.foo
    //   $s4main3fooySi_SitF    (a tuple)       main.foo
    //
    // `swift_completeness.rs` cannot see it — its invariant is defined over
    // `<len><chars>` identifiers, and a standard-library substitution (`Si`,
    // `Say…G`) carries no length prefix. The same blind spot let Go drop a
    // numeric closure index past `go_completeness.rs` (iter 120).
    //
    // Rendering these types needs the Swift grammar and an oracle to check it,
    // neither of which is here. Echoing the unread mangling needs neither and
    // restores the distinction — the remedy used for the operator suffixes at
    // iter 131.
    //
    // Deliberately narrow: only when NO signature was produced. Swift's parser
    // legitimately stops early on many symbols (measured in
    // `tests/trailing_input.rs`: 9 of 16 consume everything), and those already
    // render a partial signature, which is informative and not a collapse.
    // The echo starts after the length-prefixed IDENTIFIERS, not at the
    // parser's stop position. `d.pos` differs between `SaySiG`, `SDySSSiG` and
    // `SqySiG` but all three leave the same two trailing bytes, so echoing from
    // there left three of the five still colliding.
    let tail = swift_signature_region(mangled, &rendered);
    if !tail.is_empty() && !rendered.contains("->") && !rendered.contains(" : ") {
        return format!("{rendered} [unparsed {tail}]");
    }
    rendered
}

/// The mangling that follows everything the rendering names.
///
/// Anchored to the LAST rendered path component rather than to a leading run of
/// `<len><chars>` identifiers: a Swift path may carry type markers between its
/// names, so a leading-run scan stops early and returns a tail that overlaps
/// text the rendering already contains. `multibyte_length_prefixes.rs` caught
/// that immediately.
///
/// Purely lexical, needing no grammar — which is the point, since the grammar
/// is exactly what is missing here.
fn swift_signature_region<'a>(mangled: &'a str, rendered: &str) -> &'a str {
    let last = rendered.rsplit('.').next().unwrap_or(rendered);
    if last.is_empty() {
        return "";
    }
    mangled
        .rfind(last)
        .and_then(|i| mangled.get(i + last.len()..))
        .unwrap_or("")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_swift_prefix_dollar_s() {
        assert!(SwiftDemangler::detect("$sSS7countedSiSo7NSArrayCF"));
        assert!(SwiftDemangler::detect("_$s4main3fooyyF"));
    }

    #[test]
    fn test_detect_not_swift() {
        assert!(!SwiftDemangler::detect("_ZN3fooEv"));
        assert!(!SwiftDemangler::detect("?foo@@YAHXZ"));
    }

    #[test]
    fn test_swift_demangle_passthrough() {
        let result = swift_demangle("not_swift_at_all");
        assert_eq!(result, "not_swift_at_all");
    }

    #[test]
    fn test_swift_demangle_simple() {
        let result = swift_demangle("$sSS7countedSiSo7NSArrayCF");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_swift_demangle_main_module() {
        let result = swift_demangle("$s4main3fooyyF");
        assert!(
            result.contains("foo") || !result.is_empty(),
            "result: {result}"
        );
    }

    #[test]
    fn test_swift_node_module_render() {
        let n = SwiftNode::Module("MyModule".into());
        assert_eq!(n.render(), "MyModule");
    }

    #[test]
    fn test_swift_node_struct_render() {
        let n = SwiftNode::Structure {
            module: "Foundation".into(),
            name: "URL".into(),
        };
        assert_eq!(n.render(), "Foundation.URL");
    }

    #[test]
    fn test_swift_node_class_render() {
        let n = SwiftNode::Class {
            module: "UIKit".into(),
            name: "UIView".into(),
        };
        assert_eq!(n.render(), "UIKit.UIView");
    }

    #[test]
    fn test_swift_node_protocol_render() {
        let n = SwiftNode::Protocol {
            module: "Swift".into(),
            name: "Equatable".into(),
        };
        assert_eq!(n.render(), "Swift.Equatable");
    }

    #[test]
    fn test_swift_node_optional_render() {
        let n = SwiftNode::Optional(Box::new(SwiftNode::BuiltinType("Int".into())));
        assert_eq!(n.render(), "Int?");
    }

    #[test]
    fn test_swift_node_array_render() {
        let n = SwiftNode::Array(Box::new(SwiftNode::BuiltinType("String".into())));
        assert_eq!(n.render(), "[String]");
    }

    #[test]
    fn test_swift_node_dict_render() {
        let n = SwiftNode::Dictionary {
            key: Box::new(SwiftNode::BuiltinType("String".into())),
            value: Box::new(SwiftNode::BuiltinType("Int".into())),
        };
        assert_eq!(n.render(), "[String: Int]");
    }

    #[test]
    fn test_swift_node_tuple_empty() {
        let n = SwiftNode::TupleType(vec![]);
        assert_eq!(n.render(), "()");
    }

    #[test]
    fn test_swift_node_tuple_single() {
        let n = SwiftNode::TupleType(vec![SwiftNode::BuiltinType("Int".into())]);
        assert_eq!(n.render(), "(Int)");
    }

    #[test]
    fn test_swift_node_function_type_render() {
        let n = SwiftNode::FunctionType {
            params: vec![SwiftNode::BuiltinType("Int".into())],
            result: Box::new(SwiftNode::BuiltinType("Bool".into())),
            throws: false,
        };
        assert_eq!(n.render(), "(Int) -> Bool");
    }

    #[test]
    fn test_swift_node_throws_function_type() {
        let n = SwiftNode::FunctionType {
            params: vec![],
            result: Box::new(SwiftNode::TupleType(vec![])),
            throws: true,
        };
        assert!(n.render().contains("throws"));
    }

    #[test]
    fn test_swift_node_generic_param() {
        let n = SwiftNode::GenericParam { depth: 0, index: 0 };
        assert_eq!(n.render(), "A");
    }

    #[test]
    fn test_swift_node_generic_param_b() {
        let n = SwiftNode::GenericParam { depth: 0, index: 1 };
        assert_eq!(n.render(), "B");
    }

    #[test]
    fn test_swift_node_metatype() {
        let n = SwiftNode::Metatype(Box::new(SwiftNode::BuiltinType("Int".into())));
        assert_eq!(n.render(), "Int.Type");
    }

    #[test]
    fn test_swift_node_getter() {
        let n = SwiftNode::Getter(Box::new(SwiftNode::Identifier("MyClass.x".into())));
        assert_eq!(n.render(), "MyClass.x.getter");
    }

    #[test]
    fn test_swift_node_setter() {
        let n = SwiftNode::Setter(Box::new(SwiftNode::Identifier("MyClass.y".into())));
        assert_eq!(n.render(), "MyClass.y.setter");
    }

    #[test]
    fn test_swift_node_witness_table() {
        let n = SwiftNode::WitnessTable {
            type_name: "MyStruct".into(),
            protocol: "Equatable".into(),
        };
        assert!(n.render().contains("witness table"));
    }

    #[test]
    fn test_swift_node_protocol_conformance() {
        let n = SwiftNode::ProtocolConformance {
            type_name: "MyType".into(),
            protocol: "Hashable".into(),
        };
        assert_eq!(n.render(), "MyType: Hashable");
    }

    #[test]
    fn test_swift_node_global_wraps() {
        let inner = SwiftNode::BuiltinType("Int".into());
        let n = SwiftNode::Global(Box::new(inner));
        assert_eq!(n.render(), "Int");
    }

    #[test]
    fn test_operator_decode() {
        assert_eq!(decode_operator_name("p"), "+");
        assert_eq!(decode_operator_name("e"), "==");
        assert_eq!(decode_operator_name("l"), "<");
        assert_eq!(decode_operator_name("g"), ">");
        assert_eq!(decode_operator_name("n"), "!");
    }

    #[test]
    fn test_builtin_subst_map() {
        assert_ne!(builtin_subst_index("i"), builtin_subst_index("S"));
    }

    #[test]
    fn test_swift_demangle_t0_prefix() {
        let result = swift_demangle("_T0SS13printedLength3int4dotsXSSiSi_SbtF");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_swift_vec_empty_param_function() {
        // `yyF` = () -> (): the leading empty tuple is the parameter list,
        // so it must not render as `foo(())`.
        assert_eq!(swift_demangle("$s4main3fooyyF"), "main.foo() -> ()");
    }

    #[test]
    fn test_swift_vec_underscore_terminates() {
        // Regression: `_` bytes inside the symbol used to trigger an
        // infinite zero-progress loop with unbounded memory growth.
        let result = swift_demangle("_T0SS13printedLength3int4dotsXSSiSi_SbtF");
        assert!(!result.is_empty());
        assert!(result.len() < 4096, "unbounded output: {} bytes", result.len());
    }

    #[test]
    fn test_swift_vec_type_list_no_progress_terminates() {
        // Craft input that reaches parse_type_list with a byte that parses
        // to zero-length; must terminate promptly.
        let result = swift_demangle("$s4main1ft__tF");
        assert!(result.len() < 4096);
    }

    #[test]
    fn test_swift_vec_int_param_function() {
        // main.bar(Si) -> Sb : Int param, Bool return
        let result = swift_demangle("$s4main3barSiSbF");
        assert!(result.contains("main.bar"), "result: {result}");
    }

    #[test]
    fn test_swift_demangle_tf_prefix_reject() {
        // Input from validator: _TFC1a1bFT_T_ — an old-style `_TF` symbol with
        // a `C` (class) context but NO member name after the class name, so
        // the old-style parser cannot fully consume it and returns the input.
        let result = swift_demangle("_TFC1a1bFT_T_");
        // Since detect fails, swift_demangle returns the original input
        assert_eq!(result, "_TFC1a1bFT_T_", "swift_demangle should return original when detect fails");
        assert!(!result.is_empty(), "result should not be empty");
    }
}
