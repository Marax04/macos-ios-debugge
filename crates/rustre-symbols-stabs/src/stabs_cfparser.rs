//! STABS control-flow parser.
//!
//! Builds a function→scope tree from STABS `N_FUN`, `N_LBRAC`, `N_RBRAC`,
//! `N_SOL`, `N_SLINE`, and `N_OPT` records.

use serde::{Deserialize, Serialize};
/// Re-export of [`HashMap`] for downstream callers that build STABS index maps.
pub use std::collections::HashMap;
/// Re-export of [`std::fmt`] for downstream callers that need formatter traits
/// when implementing custom display logic over the CF parser types.
pub use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Source line info
// ─────────────────────────────────────────────────────────────────────────────

/// A source line mapping entry (`N_SLINE` / `N_SOL`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLineEntry {
    /// Machine address.
    pub address: u64,
    /// 1-based source line number.
    pub line: u32,
    /// Source file (may be different from the compilation unit's main file).
    pub file: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Scope block
// ─────────────────────────────────────────────────────────────────────────────

/// A lexical scope block produced by `N_LBRAC` / `N_RBRAC`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeBlock {
    /// Start address of this scope.
    pub start_addr: u64,
    /// End address (exclusive).
    pub end_addr: u64,
    /// Nesting depth (0 = function body).
    pub depth: u32,
    /// Local variables declared in this scope.
    pub locals: Vec<ScopeLocal>,
    /// Child scopes.
    pub children: Vec<Self>,
}

impl ScopeBlock {
    /// Create an empty scope starting (and provisionally ending) at `start`.
    #[must_use] 
    pub const fn new(start: u64, depth: u32) -> Self {
        Self {
            start_addr: start,
            end_addr: start,
            depth,
            locals: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Whether `addr` is within this scope.
    #[must_use] 
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start_addr && addr < self.end_addr
    }

    /// Total number of bytes covered by this scope.
    #[must_use] 
    pub const fn size(&self) -> u64 {
        self.end_addr.saturating_sub(self.start_addr)
    }

    /// Flatten all locals including from nested scopes.
    #[must_use] 
    pub fn all_locals(&self) -> Vec<&ScopeLocal> {
        let mut v: Vec<&ScopeLocal> = self.locals.iter().collect();
        for child in &self.children {
            v.extend(child.all_locals());
        }
        v
    }

    /// Total child scope count (recursive).
    #[must_use] 
    pub fn child_count(&self) -> usize {
        self.children.iter().map(|c| 1 + c.child_count()).sum()
    }
}

/// A local variable within a scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeLocal {
    /// Variable name.
    pub name: String,
    /// Type reference (encoded as a string for now).
    pub type_str: String,
    /// Register or stack offset descriptor.
    pub location: LocalLocation,
}

/// Location of a local variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LocalLocation {
    /// In a CPU register.
    Register {
        /// Register number (`N_RSYM` value).
        reg_num: u8,
    },
    /// At a stack offset.
    Stack {
        /// Frame-pointer-relative offset.
        offset: i32,
    },
    /// Optimized out.
    Optimized,
    /// Unknown.
    Unknown,
}

// ─────────────────────────────────────────────────────────────────────────────
// StabsNFun — function entry record
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed `N_FUN` record (function start or end).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabsNFun {
    /// Function name (empty for function-end record).
    pub name: String,
    /// Type descriptor string.
    pub type_str: String,
    /// Start address.
    pub address: u64,
    /// True if this is a function-end record (name="").
    pub is_end: bool,
}

impl StabsNFun {
    /// Parse an `N_FUN` payload (`name:type_desc`, bare name, or empty end record).
    #[must_use] 
    pub fn parse(name_desc: &str, address: u64) -> Self {
        let is_end = name_desc.is_empty();
        if is_end {
            return Self {
                name: String::new(),
                type_str: String::new(),
                address,
                is_end: true,
            };
        }
        // Format: "name:type_desc" or just "name"
        let Some(colon) = name_desc.find(':') else {
            return Self {
                name: name_desc.to_string(),
                type_str: String::new(),
                address,
                is_end: false,
            };
        };
        let name = name_desc[..colon].to_string();
        let type_str = name_desc[colon + 1..].to_string();
        Self {
            name,
            type_str,
            address,
            is_end: false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StabsSOL — source file change record
// ─────────────────────────────────────────────────────────────────────────────

/// An `N_SOL` record: change of active source file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabsSOL {
    /// New active source file.
    pub file: String,
    /// Address at which the file change takes effect.
    pub address: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// StabsOpt — optimization info record (N_OPT)
// ─────────────────────────────────────────────────────────────────────────────

/// An `N_OPT` record: compiler optimization hint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabsOpt {
    /// Raw option string (e.g. `gcc2_compiled.`).
    pub option_string: String,
    /// Record value field.
    pub value: u32,
}

impl StabsOpt {
    /// Build from the record's string and value fields.
    #[must_use] 
    pub fn parse(s: &str, value: u32) -> Self {
        Self {
            option_string: s.to_string(),
            value,
        }
    }

    /// Returns true if this is a "`gcc2_compiled`" marker.
    #[must_use] 
    pub fn is_gcc2(&self) -> bool {
        self.option_string.contains("gcc2")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CfParseRecord — a single input record
// ─────────────────────────────────────────────────────────────────────────────

/// A STABS record fed to the [`StabsCfParser`].
#[derive(Debug, Clone)]
pub enum CfRecord {
    /// `N_FUN` — function start or end.
    NFun {
        /// Raw `name:type_desc` payload (empty for end records).
        name_desc: String,
        /// Function address.
        address: u64,
    },
    /// `N_LBRAC` — begin lexical block.
    LBrac {
        /// Block start address.
        address: u64,
    },
    /// `N_RBRAC` — end lexical block.
    RBrac {
        /// Block end address.
        address: u64,
    },
    /// `N_SLINE` — source line.
    Sline {
        /// Line number.
        line: u32,
        /// Code address.
        address: u64,
    },
    /// `N_SOL` — source file change.
    Sol {
        /// New active file.
        file: String,
        /// Address of the change.
        address: u64,
    },
    /// `N_OPT` — compiler option marker.
    Opt {
        /// Option string.
        opt: String,
        /// Record value field.
        value: u32,
    },
    /// `N_LSYM` — stack local variable.
    LSym {
        /// Variable name.
        name: String,
        /// Type descriptor string.
        type_str: String,
        /// Frame offset.
        value: i32,
    },
    /// `N_RSYM` — register variable.
    RSym {
        /// Variable name.
        name: String,
        /// Type descriptor string.
        type_str: String,
        /// Register number.
        reg: u8,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionScope — complete scope tree for one function
// ─────────────────────────────────────────────────────────────────────────────

/// The complete scope + line-number info for one function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionScope {
    /// The `N_FUN` record that opened this function.
    pub func: StabsNFun,
    /// Root scope block (the function body).
    pub body: ScopeBlock,
    /// Ordered source line entries.
    pub lines: Vec<SourceLineEntry>,
    /// Source file changes within this function.
    pub sol_changes: Vec<StabsSOL>,
    /// End address (set when we see the matching end `N_FUN`).
    pub end_addr: Option<u64>,
}

impl FunctionScope {
    /// Create a scope tree rooted at the given function record.
    #[must_use] 
    pub const fn new(func: StabsNFun) -> Self {
        let addr = func.address;
        Self {
            body: ScopeBlock::new(addr, 0),
            func,
            lines: Vec::new(),
            sol_changes: Vec::new(),
            end_addr: None,
        }
    }

    /// Number of source lines mapped.
    #[must_use] 
    pub const fn line_count(&self) -> usize {
        self.lines.len()
    }

    /// Deepest nesting level.
    #[must_use] 
    pub fn max_depth(&self) -> u32 {
        fn max_depth_block(b: &ScopeBlock) -> u32 {
            let child_max = b.children.iter().map(max_depth_block).max().unwrap_or(0);
            b.depth.max(child_max)
        }
        max_depth_block(&self.body)
    }

    /// Find which scope block contains `addr`.
    #[must_use] 
    pub fn scope_at(&self, addr: u64) -> Option<&ScopeBlock> {
        fn find_in(b: &ScopeBlock, addr: u64) -> Option<&ScopeBlock> {
            if !b.contains(addr) {
                return None;
            }
            for child in &b.children {
                if let Some(found) = find_in(child, addr) {
                    return Some(found);
                }
            }
            Some(b)
        }
        find_in(&self.body, addr)
    }

    /// All locals across all scopes.
    #[must_use] 
    pub fn all_locals(&self) -> Vec<&ScopeLocal> {
        self.body.all_locals()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StabsCfParser
// ─────────────────────────────────────────────────────────────────────────────

/// Incremental parser that builds a [`FunctionScope`] tree from STABS records.
#[derive(Default)]
pub struct StabsCfParser {
    /// Completed function scopes.
    pub functions: Vec<FunctionScope>,
    /// Currently open function scope, if any.
    current_func: Option<FunctionScope>,
    /// Stack of open scope blocks (deepest last).
    scope_stack: Vec<ScopeBlock>,
    /// Current source file.
    current_file: Option<String>,
    /// Optimization flags encountered.
    pub opts: Vec<StabsOpt>,
    /// Count of `N_LBRACs` dropped because [`MAX_SCOPE_DEPTH`] was reached; their
    /// matching `N_RBRACs` are swallowed so the stack stays balanced.
    suppressed_lbrac: usize,
}

/// Maximum lexical-scope nesting depth retained by the parser.
/// Far beyond any real compiler output; caps a crafted-input recursion bomb.
const MAX_SCOPE_DEPTH: usize = 256;

impl StabsCfParser {
    /// Create an empty parser.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed a single record into the parser.
    pub fn feed(&mut self, rec: CfRecord) {
        match rec {
            CfRecord::NFun { name_desc, address } => {
                let nfun = StabsNFun::parse(&name_desc, address);
                if nfun.is_end {
                    // Close the current function
                    if let Some(mut func) = self.current_func.take() {
                        // Flush remaining open scopes
                        while let Some(mut scope) = self.scope_stack.pop() {
                            scope.end_addr = address;
                            if let Some(parent) = self.scope_stack.last_mut() {
                                parent.children.push(scope);
                            } else {
                                func.body.children.push(scope);
                            }
                        }
                        func.end_addr = Some(address);
                        func.body.end_addr = address;
                        self.functions.push(func);
                    }
                } else {
                    // Close any open function first (shouldn't happen in well-formed STABS)
                    if let Some(f) = self.current_func.take() {
                        self.functions.push(f);
                    }
                    self.current_func = Some(FunctionScope::new(nfun));
                    self.scope_stack.clear();
                    self.suppressed_lbrac = 0;
                }
            }
            CfRecord::LBrac { address } => {
                // Depth is attacker-controlled (one N_LBRAC per 12 bytes), and
                // ScopeBlock is a recursive tree that is walked, dropped and
                // serialised recursively — so it must be capped at
                // construction, not merely at traversal time.
                if self.scope_stack.len() >= MAX_SCOPE_DEPTH {
                    // Attribute the range to the innermost open scope and
                    // remember to swallow the matching N_RBRAC so the stack
                    // stays balanced.
                    self.suppressed_lbrac = self.suppressed_lbrac.saturating_add(1);
                    return;
                }
                let depth = u32::try_from(self.scope_stack.len()).unwrap_or(u32::MAX).saturating_add(1);
                self.scope_stack.push(ScopeBlock::new(address, depth));
            }
            CfRecord::RBrac { address } => {
                if self.suppressed_lbrac > 0 {
                    self.suppressed_lbrac -= 1;
                    return;
                }
                if let Some(mut scope) = self.scope_stack.pop() {
                    scope.end_addr = address;
                    if let Some(parent) = self.scope_stack.last_mut() {
                        parent.children.push(scope);
                    } else if let Some(ref mut func) = self.current_func {
                        func.body.children.push(scope);
                    }
                }
            }
            CfRecord::Sline { line, address } => {
                if let Some(ref mut func) = self.current_func {
                    func.lines.push(SourceLineEntry {
                        address,
                        line,
                        file: self.current_file.clone(),
                    });
                }
            }
            CfRecord::Sol { file, address } => {
                self.current_file = Some(file.clone());
                if let Some(ref mut func) = self.current_func {
                    func.sol_changes.push(StabsSOL { file, address });
                }
            }
            CfRecord::Opt { opt, value } => {
                self.opts.push(StabsOpt::parse(&opt, value));
            }
            CfRecord::LSym {
                name,
                type_str,
                value,
            } => {
                let local = ScopeLocal {
                    name,
                    type_str,
                    location: LocalLocation::Stack { offset: value },
                };
                if let Some(scope) = self.scope_stack.last_mut() {
                    scope.locals.push(local);
                } else if let Some(ref mut func) = self.current_func {
                    func.body.locals.push(local);
                }
            }
            CfRecord::RSym {
                name,
                type_str,
                reg,
            } => {
                let local = ScopeLocal {
                    name,
                    type_str,
                    location: LocalLocation::Register { reg_num: reg },
                };
                if let Some(scope) = self.scope_stack.last_mut() {
                    scope.locals.push(local);
                } else if let Some(ref mut func) = self.current_func {
                    func.body.locals.push(local);
                }
            }
        }
    }

    /// Feed multiple records at once.
    pub fn feed_all(&mut self, records: Vec<CfRecord>) {
        for r in records {
            self.feed(r);
        }
    }

    /// Finalize any open function and return all parsed functions.
    #[must_use] 
    pub fn finish(mut self) -> Vec<FunctionScope> {
        if let Some(f) = self.current_func.take() {
            self.functions.push(f);
        }
        self.functions
    }

    /// Number of completed functions.
    #[must_use] 
    pub const fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Look up a function scope by name.
    #[must_use] 
    pub fn function_by_name(&self, name: &str) -> Option<&FunctionScope> {
        self.functions.iter().find(|f| f.func.name == name)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_function_records(addr: u64, name: &str) -> Vec<CfRecord> {
        vec![
            CfRecord::NFun {
                name_desc: format!("{name}:F-1"),
                address: addr,
            },
            CfRecord::Sline {
                line: 10,
                address: addr,
            },
            CfRecord::Sline {
                line: 11,
                address: addr + 4,
            },
            CfRecord::NFun {
                name_desc: String::new(),
                address: addr + 0x20,
            },
        ]
    }

    // --- StabsNFun::parse ---

    #[test]
    fn nfun_parse_with_type() {
        let f = StabsNFun::parse("main:F-1", 0x1000);
        assert_eq!(f.name, "main");
        assert_eq!(f.type_str, "F-1");
        assert_eq!(f.address, 0x1000);
        assert!(!f.is_end);
    }

    #[test]
    fn nfun_parse_end_record() {
        let f = StabsNFun::parse("", 0x1020);
        assert!(f.is_end);
        assert!(f.name.is_empty());
    }

    #[test]
    fn nfun_parse_no_colon() {
        let f = StabsNFun::parse("foo", 0x2000);
        assert_eq!(f.name, "foo");
        assert!(f.type_str.is_empty());
    }

    // --- ScopeBlock ---

    #[test]
    fn scope_block_contains() {
        let mut b = ScopeBlock::new(0x1000, 0);
        b.end_addr = 0x1020;
        assert!(b.contains(0x1000));
        assert!(b.contains(0x1019));
        assert!(!b.contains(0x1020));
    }

    #[test]
    fn scope_block_size() {
        let mut b = ScopeBlock::new(0x1000, 0);
        b.end_addr = 0x1040;
        assert_eq!(b.size(), 0x40);
    }

    #[test]
    fn scope_block_child_count() {
        let mut root = ScopeBlock::new(0x1000, 0);
        let mut child = ScopeBlock::new(0x1010, 1);
        child.children.push(ScopeBlock::new(0x1018, 2));
        root.children.push(child);
        assert_eq!(root.child_count(), 2);
    }

    #[test]
    fn scope_block_all_locals() {
        let mut root = ScopeBlock::new(0, 0);
        root.locals.push(ScopeLocal {
            name: "x".into(),
            type_str: "i32".into(),
            location: LocalLocation::Unknown,
        });
        let mut child = ScopeBlock::new(0, 1);
        child.locals.push(ScopeLocal {
            name: "y".into(),
            type_str: "i32".into(),
            location: LocalLocation::Unknown,
        });
        root.children.push(child);
        assert_eq!(root.all_locals().len(), 2);
    }

    // --- StabsOpt ---

    #[test]
    fn opt_parse() {
        let opt = StabsOpt::parse("gcc2_compiled.", 0);
        assert!(opt.is_gcc2());
    }

    #[test]
    fn opt_not_gcc2() {
        let opt = StabsOpt::parse("clang_compiled", 0);
        assert!(!opt.is_gcc2());
    }

    // --- StabsCfParser ---

    #[test]
    fn parser_parses_simple_function() {
        let mut p = StabsCfParser::new();
        p.feed_all(simple_function_records(0x1000, "main"));
        assert_eq!(p.function_count(), 1);
    }

    #[test]
    fn parser_function_name() {
        let mut p = StabsCfParser::new();
        p.feed_all(simple_function_records(0x1000, "main"));
        assert_eq!(p.functions[0].func.name, "main");
    }

    #[test]
    fn parser_line_count() {
        let mut p = StabsCfParser::new();
        p.feed_all(simple_function_records(0x1000, "foo"));
        assert_eq!(p.functions[0].line_count(), 2);
    }

    #[test]
    fn parser_function_end_addr() {
        let mut p = StabsCfParser::new();
        p.feed_all(simple_function_records(0x1000, "bar"));
        assert_eq!(p.functions[0].end_addr, Some(0x1020));
    }

    #[test]
    fn parser_scope_lbrac_rbrac() {
        let mut p = StabsCfParser::new();
        p.feed(CfRecord::NFun {
            name_desc: "f:F-1".into(),
            address: 0x1000,
        });
        p.feed(CfRecord::LBrac { address: 0x1004 });
        p.feed(CfRecord::RBrac { address: 0x1010 });
        p.feed(CfRecord::NFun {
            name_desc: String::new(),
            address: 0x1020,
        });
        assert_eq!(p.functions[0].body.children.len(), 1);
    }

    #[test]
    fn parser_nested_scopes() {
        let mut p = StabsCfParser::new();
        p.feed(CfRecord::NFun {
            name_desc: "g:F-1".into(),
            address: 0,
        });
        p.feed(CfRecord::LBrac { address: 4 });
        p.feed(CfRecord::LBrac { address: 8 });
        p.feed(CfRecord::RBrac { address: 12 });
        p.feed(CfRecord::RBrac { address: 16 });
        p.feed(CfRecord::NFun {
            name_desc: String::new(),
            address: 20,
        });
        // Outer scope has one child scope
        assert_eq!(p.functions[0].body.children.len(), 1);
        assert_eq!(p.functions[0].body.children[0].children.len(), 1);
    }

    #[test]
    fn parser_sol_change() {
        let mut p = StabsCfParser::new();
        p.feed(CfRecord::NFun {
            name_desc: "h:F-1".into(),
            address: 0,
        });
        p.feed(CfRecord::Sol {
            file: "header.h".into(),
            address: 4,
        });
        p.feed(CfRecord::NFun {
            name_desc: String::new(),
            address: 20,
        });
        assert_eq!(p.functions[0].sol_changes.len(), 1);
        assert_eq!(p.functions[0].sol_changes[0].file, "header.h");
    }

    #[test]
    fn parser_lsym_in_function() {
        let mut p = StabsCfParser::new();
        p.feed(CfRecord::NFun {
            name_desc: "k:F-1".into(),
            address: 0,
        });
        p.feed(CfRecord::LSym {
            name: "local_x".into(),
            type_str: "-1".into(),
            value: -8,
        });
        p.feed(CfRecord::NFun {
            name_desc: String::new(),
            address: 20,
        });
        let locals = p.functions[0].all_locals();
        assert_eq!(locals.len(), 1);
        assert_eq!(locals[0].name, "local_x");
    }

    #[test]
    fn parser_rsym_in_scope() {
        let mut p = StabsCfParser::new();
        p.feed(CfRecord::NFun {
            name_desc: "m:F-1".into(),
            address: 0,
        });
        p.feed(CfRecord::LBrac { address: 4 });
        p.feed(CfRecord::RSym {
            name: "reg_var".into(),
            type_str: "-1".into(),
            reg: 0,
        });
        p.feed(CfRecord::RBrac { address: 16 });
        p.feed(CfRecord::NFun {
            name_desc: String::new(),
            address: 20,
        });
        let all = p.functions[0].all_locals();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "reg_var");
    }

    #[test]
    fn parser_two_functions() {
        let mut p = StabsCfParser::new();
        p.feed_all(simple_function_records(0x1000, "alpha"));
        p.feed_all(simple_function_records(0x2000, "beta"));
        assert_eq!(p.function_count(), 2);
    }

    #[test]
    fn parser_function_by_name_found() {
        let mut p = StabsCfParser::new();
        p.feed_all(simple_function_records(0x1000, "needle"));
        assert!(p.function_by_name("needle").is_some());
    }

    #[test]
    fn parser_function_by_name_not_found() {
        let mut p = StabsCfParser::new();
        p.feed_all(simple_function_records(0x1000, "haystack"));
        assert!(p.function_by_name("needle").is_none());
    }

    #[test]
    fn parser_max_depth_nested() {
        let mut p = StabsCfParser::new();
        p.feed(CfRecord::NFun {
            name_desc: "deep:F-1".into(),
            address: 0,
        });
        p.feed(CfRecord::LBrac { address: 4 });
        p.feed(CfRecord::LBrac { address: 8 });
        p.feed(CfRecord::LBrac { address: 12 });
        p.feed(CfRecord::RBrac { address: 16 });
        p.feed(CfRecord::RBrac { address: 20 });
        p.feed(CfRecord::RBrac { address: 24 });
        p.feed(CfRecord::NFun {
            name_desc: String::new(),
            address: 28,
        });
        assert!(p.functions[0].max_depth() >= 3);
    }

    #[test]
    fn parser_finish_consumes_open_function() {
        let mut p = StabsCfParser::new();
        p.feed(CfRecord::NFun {
            name_desc: "open:F-1".into(),
            address: 0,
        });
        let funcs = p.finish();
        assert_eq!(funcs.len(), 1);
    }
}
