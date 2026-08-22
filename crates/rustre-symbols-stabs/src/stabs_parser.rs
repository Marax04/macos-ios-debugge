// stabs_parser.rs — Full STABS debug format parser
//
// Handles the following stab types:
//   N_GSYM  (0x20) — global symbol
//   N_FUN   (0x24) — function beginning / end
//   N_STSYM (0x26) — static symbol (file scope)
//   N_LCSYM (0x28) — BSS symbol
//   N_RSYM  (0x40) — register variable
//   N_SLINE (0x44) — source line within function
//   N_ENSYM (0x4E) — end of function (alt)
//   N_SO    (0x64) — source file name / directory
//   N_LSYM  (0x80) — local symbol (stack)
//   N_BINCL (0x82) — begin include file
//   N_SOL   (0x84) — #included source file name
//   N_PSYM  (0xA0) — parameter
//   N_EINCL (0xA2) — end include file
//   N_LBRAC (0xC0) — left brace (scope open)
//   N_RBRAC (0xE0) — right brace (scope close)
//   N_BCOMM (0xE2) — begin common block
//   N_ECOMM (0xE4) — end common block
//   N_FUN ending with empty string = end of function marker

use std::collections::HashMap;
use std::fmt;

// ── Raw stab entry ────────────────────────────────────────────────────────────

/// A single raw stab entry as loaded from .stab / .stabs sections
#[derive(Debug, Clone)]
pub struct RawStab {
    /// Offset into .stabstr for the name (or 0)
    pub string_offset: u32,
    /// Stab type byte (`N_FUN`, `N_SLINE`, etc.)
    pub stab_type: u8,
    /// Other field (misc; used differently per type)
    pub other: u8,
    /// Descriptor (line number for `N_SLINE`; type number for others)
    pub desc: u16,
    /// Value (address, register number, stack offset, etc.)
    pub value: u32,
}

impl fmt::Display for RawStab {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RawStab {{ type={:#04x} other={:#04x} desc={} value={:#x} stroff={} }}",
            self.stab_type, self.other, self.desc, self.value, self.string_offset
        )
    }
}

impl RawStab {
    /// Size in bytes of one on-disk stab entry (`n_strx` + `n_type` + `n_other` + `n_desc` + `n_value`).
    pub const ENTRY_SIZE: usize = 12;

    /// Parse from 12 raw bytes (ELF/Mach-O layout: stroff, type, other, desc, value)
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::ENTRY_SIZE { return None; }
        Some(Self {
            string_offset: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            stab_type: data[4],
            other: data[5],
            desc: u16::from_le_bytes([data[6], data[7]]),
            value: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
        })
    }

    /// Parse from big-endian bytes (PowerPC, SPARC)
    #[must_use]
    pub fn parse_be(data: &[u8]) -> Option<Self> {
        if data.len() < Self::ENTRY_SIZE { return None; }
        Some(Self {
            string_offset: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            stab_type: data[4],
            other: data[5],
            desc: u16::from_be_bytes([data[6], data[7]]),
            value: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
        })
    }
}

// ── Stab type constants ───────────────────────────────────────────────────────

/// Standard STABS `n_type` byte constants (N_* stab types).
pub mod stab_types {
    /// `N_GSYM` — global symbol.
    pub const N_GSYM: u8  = 0x20;
    /// `N_FUN` — function beginning (or end when the name is empty).
    pub const N_FUN: u8   = 0x24;
    /// `N_STSYM` — file-scope static symbol (data segment).
    pub const N_STSYM: u8 = 0x26;
    /// `N_LCSYM` — file-scope static symbol (BSS segment).
    pub const N_LCSYM: u8 = 0x28;
    /// `N_RSYM` — register variable.
    pub const N_RSYM: u8  = 0x40;
    /// `N_SLINE` — source line within the current function.
    pub const N_SLINE: u8 = 0x44;
    /// `N_ENSYM` — alternate end-of-function marker.
    pub const N_ENSYM: u8 = 0x4E;
    /// `N_SO` — source file name or directory (starts/ends a compilation unit).
    pub const N_SO: u8    = 0x64;
    /// `N_LSYM` — local (stack) symbol or type definition.
    pub const N_LSYM: u8  = 0x80;
    /// `N_BINCL` — begin include file.
    pub const N_BINCL: u8 = 0x82;
    /// `N_SOL` — name of a `#include`d source file.
    pub const N_SOL: u8   = 0x84;
    /// `N_PSYM` — function parameter.
    pub const N_PSYM: u8  = 0xA0;
    /// `N_EINCL` — end include file.
    pub const N_EINCL: u8 = 0xA2;
    /// `N_LBRAC` — left brace (lexical scope open).
    pub const N_LBRAC: u8 = 0xC0;
    /// `N_RBRAC` — right brace (lexical scope close).
    pub const N_RBRAC: u8 = 0xE0;
    /// `N_BCOMM` — begin Fortran common block.
    pub const N_BCOMM: u8 = 0xE2;
    /// `N_ECOMM` — end Fortran common block.
    pub const N_ECOMM: u8 = 0xE4;
}

use stab_types::{N_SO, N_SOL, N_FUN, N_SLINE, N_LSYM, N_PSYM, N_RSYM, N_GSYM, N_STSYM, N_LCSYM, N_LBRAC, N_RBRAC};

// ── Parsed stab items ─────────────────────────────────────────────────────────

/// A source line mapping entry (from `N_SLINE`)
#[derive(Debug, Clone, Copy)]
pub struct LineEntry {
    /// Absolute address of this source line
    pub address: u64,
    /// Line number within the source file
    pub line: u32,
    /// Source file index (into the source file list of the enclosing function)
    pub file_idx: usize,
}

/// A local variable on the stack (from `N_LSYM` with stack offset)
#[derive(Debug, Clone)]
pub struct LocalVar {
    /// Variable name (portion of the stab string before ':').
    pub name: String,
    /// Type string (e.g. "int", "(0,5)", "4:t(1,2)=*int")
    pub type_str: String,
    /// Frame offset (negative = below frame pointer on most ABIs)
    pub frame_offset: i32,
}

/// A function parameter (from `N_PSYM`)
#[derive(Debug, Clone)]
pub struct Parameter {
    /// Parameter name (portion of the stab string before ':').
    pub name: String,
    /// STABS type descriptor string (portion after ':').
    pub type_str: String,
    /// Stack offset of the parameter (positive above return address on x86)
    pub frame_offset: i32,
}

/// A register variable (from `N_RSYM`)
#[derive(Debug, Clone)]
pub struct RegisterVar {
    /// Variable name (portion of the stab string before ':').
    pub name: String,
    /// STABS type descriptor string (portion after ':').
    pub type_str: String,
    /// Register number (architecture-specific)
    pub reg: u32,
}

/// Scope bracket (from `N_LBRAC` / `N_RBRAC`)
#[derive(Debug, Clone, Copy)]
pub struct ScopeBracket {
    /// Whether this bracket opens (`N_LBRAC`) or closes (`N_RBRAC`) a scope.
    pub kind: BracketKind,
    /// Address offset relative to function start
    pub offset: u32,
    /// Nesting level (0 = function top-level scope)
    pub nesting_depth: u32,
}

/// Direction of a scope bracket: `Open` = `N_LBRAC`, `Close` = `N_RBRAC`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BracketKind {
    /// Scope opening (`N_LBRAC`).
    Open,
    /// Scope closing (`N_RBRAC`).
    Close,
}

/// A fully parsed function from STABS
#[derive(Debug, Clone)]
pub struct ParsedFunction {
    /// Function name (portion of the `N_FUN` string before ':').
    pub name: String,
    /// Type string (return type + args) — the part after the ':'
    pub type_str: String,
    /// Start address
    pub start_addr: u64,
    /// End address (0 if not yet known)
    pub end_addr: u64,
    /// Source file at function start
    pub source_file: String,
    /// Line number table entries
    pub lines: Vec<LineEntry>,
    /// Parameters in declaration order
    pub params: Vec<Parameter>,
    /// Local variables
    pub locals: Vec<LocalVar>,
    /// Register variables
    pub reg_vars: Vec<RegisterVar>,
    /// Scope brackets
    pub brackets: Vec<ScopeBracket>,
}

impl ParsedFunction {
    /// Byte size of the function (`end_addr - start_addr`, saturating).
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end_addr.saturating_sub(self.start_addr)
    }

    /// Find the source line for a given absolute address
    #[must_use]
    pub fn line_for_addr(&self, addr: u64) -> Option<&LineEntry> {
        if addr < self.start_addr { return None; }
        // Binary-search for the last line entry whose address <= addr
        let rel_u64 = addr - self.start_addr;
        // Clamp to u32::MAX — STABS N_SLINE offsets are 32-bit; any function
        // larger than 4 GiB is malformed input and we simply cap here.
        let rel = u32::try_from(rel_u64).unwrap_or(u32::MAX);
        // Sanity: the relative offset cannot exceed the function's size — but
        // only when the size is actually known. `end_addr == 0` is the
        // documented "function never closed by an empty-name N_FUN" case, which
        // find_function_at_addr deliberately matches, so asserting there would
        // abort debug builds on ordinary truncated input.
        debug_assert!(
            self.end_addr == 0 || u64::from(rel) <= self.size(),
            "line_for_addr: rel offset {rel} exceeds function size {}",
            self.size()
        );
        let mut best: Option<&LineEntry> = None;
        for le in &self.lines {
            if le.address <= addr {
                best = Some(le);
            } else {
                break;
            }
        }
        best
    }
}

/// A global symbol (from `N_GSYM`)
#[derive(Debug, Clone)]
pub struct GlobalSymbol {
    /// Symbol name (portion of the stab string before ':').
    pub name: String,
    /// STABS type descriptor string (portion after ':').
    pub type_str: String,
    /// Address (may be 0 for BSS / extern symbols)
    pub address: u64,
}

/// A static symbol (from `N_STSYM` / `N_LCSYM`)
#[derive(Debug, Clone)]
pub struct StaticSymbol {
    /// Symbol name (portion of the stab string before ':').
    pub name: String,
    /// STABS type descriptor string (portion after ':').
    pub type_str: String,
    /// Address of the symbol (`n_value`).
    pub address: u64,
    /// True for `N_LCSYM` (BSS), false for `N_STSYM` (data).
    pub is_bss: bool,
}

/// One compilation unit worth of parsed STABS data
#[derive(Debug, Clone)]
pub struct CompilationUnit {
    /// Directory component from `N_SO` with trailing slash
    pub directory: String,
    /// File name component from `N_SO`
    pub filename: String,
    /// Additional included files seen via `N_SOL`
    pub included_files: Vec<String>,
    /// All parsed functions
    pub functions: Vec<ParsedFunction>,
    /// Global symbols defined in this CU
    pub globals: Vec<GlobalSymbol>,
    /// Static symbols
    pub statics: Vec<StaticSymbol>,
}

impl CompilationUnit {
    /// Join the `N_SO` directory and file name into a full source path.
    #[must_use]
    pub fn full_path(&self) -> String {
        if self.directory.is_empty() {
            self.filename.clone()
        } else if self.directory.ends_with('/') || self.directory.ends_with('\\') {
            format!("{}{}", self.directory, self.filename)
        } else {
            format!("{}/{}", self.directory, self.filename)
        }
    }

    /// Number of parsed functions in this compilation unit.
    #[must_use]
    pub const fn function_count(&self) -> usize { self.functions.len() }

    /// Find a function by exact name.
    #[must_use]
    pub fn find_function_by_name(&self, name: &str) -> Option<&ParsedFunction> {
        self.functions.iter().find(|f| f.name == name)
    }

    /// Find the function containing `addr` (functions with unknown end match by start only).
    #[must_use]
    pub fn find_function_at_addr(&self, addr: u64) -> Option<&ParsedFunction> {
        self.functions.iter().find(|f| {
            addr >= f.start_addr && (f.end_addr == 0 || addr < f.end_addr)
        })
    }

    /// Total number of `N_SLINE` entries across all functions.
    #[must_use]
    pub fn total_lines(&self) -> usize {
        self.functions.iter().map(|f| f.lines.len()).sum()
    }
}

// ── String table ──────────────────────────────────────────────────────────────

/// Wraps the .stabstr section for efficient string lookup
#[derive(Debug, Clone)]
pub struct StabStringTable {
    data: Vec<u8>,
}

impl StabStringTable {
    /// Wrap raw `.stabstr` section bytes.
    #[must_use]
    pub const fn new(data: Vec<u8>) -> Self { Self { data } }

    /// Look up a string at an *absolute* `.stabstr` offset.
    #[must_use]
    pub fn get(&self, offset: u32) -> &str {
        crate::cu_strings::read_cstr(&self.data, offset as usize)
    }

    /// Look up a string at a CU-relative `n_strx`, honouring `N_UNDF` headers.
    ///
    /// `base` is the running per-CU base maintained by the record loop; it is
    /// advanced here when `n_type` is `N_UNDF`.
    pub fn get_with_base(
        &self,
        base: &mut crate::cu_strings::CuStringBase,
        n_type: u8,
        n_strx: u32,
        n_value: u32,
    ) -> &str {
        base.resolve(&self.data, n_type, n_strx, n_value)
    }

    /// Size of the string table in bytes.
    #[must_use]
    pub const fn len(&self) -> usize { self.data.len() }
    /// True if the string table has no data.
    #[must_use]
    pub const fn is_empty(&self) -> bool { self.data.is_empty() }
}

// ── Parser state machine ───────────────────────────────────────────────────────

enum ParserState {
    /// Not inside any compilation unit
    TopLevel,
    /// Inside a CU, not inside a function
    InCu { cu: CompilationUnit, current_file: String },
    /// Inside a function
    InFunction {
        cu: CompilationUnit,
        func: ParsedFunction,
        current_file: String,
        brace_depth: u32,
    },
}

/// Full STABS parser — converts raw stabs + string table into structured data
pub struct StabsParser {
    /// Parsed compilation units
    pub units: Vec<CompilationUnit>,
}

impl StabsParser {
    /// Create a parser with no compilation units.
    #[must_use]
    pub const fn new() -> Self { Self { units: Vec::new() } }

    /// Parse an entire .stab section using the provided string table.
    /// `big_endian` controls byte order.
    pub fn parse_stab_section(
        &mut self,
        stab_data: &[u8],
        str_table: &StabStringTable,
        big_endian: bool,
    ) {
        let count = stab_data.len() / RawStab::ENTRY_SIZE;
        let mut state = ParserState::TopLevel;
        let mut str_base = crate::cu_strings::CuStringBase::new();

        for i in 0..count {
            let base = i * RawStab::ENTRY_SIZE;
            let raw = if big_endian {
                RawStab::parse_be(&stab_data[base..])
            } else {
                RawStab::parse(&stab_data[base..])
            };
            let raw = match raw {
                Some(r) => r,
                None => continue,
            };

            let name_str = str_table.get_with_base(
                &mut str_base,
                raw.stab_type,
                raw.string_offset,
                raw.value,
            );
            state = self.process_stab(state, &raw, name_str);
        }

        // Flush any in-progress state
        state = self.flush_state(state);
        // state is now TopLevel (unused)
        let _ = state;
    }

    fn process_stab(&mut self, state: ParserState, raw: &RawStab, name: &str) -> ParserState {
        match raw.stab_type {
            N_SO => self.handle_so(state, raw, name),
            N_SOL => self.handle_sol(state, name),
            N_FUN => self.handle_fun(state, raw, name),
            N_SLINE => self.handle_sline(state, raw),
            N_LSYM => self.handle_lsym(state, raw, name),
            N_PSYM => self.handle_psym(state, raw, name),
            N_RSYM => self.handle_rsym(state, raw, name),
            N_GSYM => self.handle_gsym(state, raw, name),
            N_STSYM => self.handle_stsym(state, raw, name, false),
            N_LCSYM => self.handle_stsym(state, raw, name, true),
            N_LBRAC => self.handle_lbrac(state, raw),
            N_RBRAC => self.handle_rbrac(state, raw),
            _ => state,
        }
    }

    fn handle_so(&mut self, state: ParserState, raw: &RawStab, name: &str) -> ParserState {
        // N_SO with empty name = end of compilation unit
        if name.is_empty() {
            return self.flush_state(state);
        }

        // If name ends with '/' it's a directory; next N_SO will be the file name
        match state {
            ParserState::TopLevel => {
                if name.ends_with('/') || name.ends_with('\\') {
                    // Directory — start a new CU with just directory
                    let cu = CompilationUnit {
                        directory: name.to_string(),
                        filename: String::new(),
                        included_files: Vec::new(),
                        functions: Vec::new(),
                        globals: Vec::new(),
                        statics: Vec::new(),
                    };
                    ParserState::InCu { cu, current_file: name.to_string() }
                } else {
                    let cu = CompilationUnit {
                        directory: String::new(),
                        filename: name.to_string(),
                        included_files: Vec::new(),
                        functions: Vec::new(),
                        globals: Vec::new(),
                        statics: Vec::new(),
                    };
                    let cf = name.to_string();
                    ParserState::InCu { cu, current_file: cf }
                }
            }
            ParserState::InCu { mut cu, current_file } => {
                debug_assert!(
                    current_file.is_empty() || current_file == cu.directory || !cu.filename.is_empty(),
                    "current_file out of sync with CU state"
                );
                if cu.filename.is_empty() {
                    // This is the file name following the directory
                    cu.filename = name.to_string();
                    let cf = cu.full_path();
                    ParserState::InCu { cu, current_file: cf }
                } else {
                    // New CU begins — push current one
                    self.units.push(cu);
                    let new_cu = CompilationUnit {
                        directory: String::new(),
                        filename: name.to_string(),
                        included_files: Vec::new(),
                        functions: Vec::new(),
                        globals: Vec::new(),
                        statics: Vec::new(),
                    };
                    let cf = name.to_string();
                    ParserState::InCu { cu: new_cu, current_file: cf }
                }
            }
            other => {
                let flushed = self.flush_state(other);
                self.handle_so(flushed, raw, name)
            }
        }
    }

    fn handle_sol(&self, state: ParserState, name: &str) -> ParserState {
        match state {
            ParserState::InCu { mut cu, current_file } => {
                debug_assert!(!current_file.is_empty() || cu.filename.is_empty(),
                    "InCu state with no current_file but a known filename");
                let _prev_file = current_file;
                if !cu.included_files.contains(&name.to_string()) {
                    cu.included_files.push(name.to_string());
                }
                let cf = name.to_string();
                ParserState::InCu { cu, current_file: cf }
            }
            ParserState::InFunction { mut cu, func, current_file, brace_depth } => {
                debug_assert!(brace_depth < 1024, "implausible brace depth {brace_depth} in InFunction");
                let _prev_file = current_file;
                if !cu.included_files.contains(&name.to_string()) {
                    cu.included_files.push(name.to_string());
                }
                ParserState::InFunction { cu, func, current_file: name.to_string(), brace_depth }
            }
            other => other,
        }
    }

    fn handle_fun(&mut self, state: ParserState, raw: &RawStab, name: &str) -> ParserState {
        // N_FUN with empty name = end of current function
        if name.is_empty() {
            return match state {
                ParserState::InFunction { cu, mut func, current_file, brace_depth } => {
                    // NOTE: brace_depth != 0 here means unbalanced
                    // N_LBRAC/N_RBRAC, which is common in stripped and
                    // linker-mangled binaries. It is input-derived, not an
                    // internal invariant, so it must not be asserted.
                    let _unbalanced = brace_depth != 0;
                    func.end_addr = func.start_addr.saturating_add(u64::from(raw.value));
                    let mut cu2 = cu;
                    cu2.functions.push(func);
                    ParserState::InCu { cu: cu2, current_file }
                }
                other => other,
            };
        }

        // Split "name:type" at the first ':'
        let (func_name, type_str) = split_name_type(name);

        let cu = match state {
            ParserState::InCu { cu, current_file: _ } => {
                let cf = cu.full_path();
                let func = ParsedFunction {
                    name: func_name.to_string(),
                    type_str: type_str.to_string(),
                    start_addr: u64::from(raw.value),
                    end_addr: 0,
                    source_file: cf.clone(),
                    lines: Vec::new(),
                    params: Vec::new(),
                    locals: Vec::new(),
                    reg_vars: Vec::new(),
                    brackets: Vec::new(),
                };
                return ParserState::InFunction { cu, func, current_file: cf, brace_depth: 0 };
            }
            ParserState::TopLevel => {
                let cu = CompilationUnit {
                    directory: String::new(),
                    filename: String::new(),
                    included_files: Vec::new(),
                    functions: Vec::new(),
                    globals: Vec::new(),
                    statics: Vec::new(),
                };
                cu
            }
            ParserState::InFunction { cu, mut func, current_file, brace_depth } => {
                debug_assert!(brace_depth < 1024, "implausible brace depth {brace_depth} closing function");
                // Tag the closed function's source file from the live cursor
                // if it was not already recorded during InCu opening.
                if func.source_file.is_empty() {
                    func.source_file = current_file;
                }
                func.end_addr = u64::from(raw.value);
                let mut cu2 = cu;
                cu2.functions.push(func);
                cu2
            }
        };
        let cf = cu.full_path();
        let func = ParsedFunction {
            name: func_name.to_string(),
            type_str: type_str.to_string(),
            start_addr: u64::from(raw.value),
            end_addr: 0,
            source_file: cf.clone(),
            lines: Vec::new(),
            params: Vec::new(),
            locals: Vec::new(),
            reg_vars: Vec::new(),
            brackets: Vec::new(),
        };
        ParserState::InFunction { cu, func, current_file: cf, brace_depth: 0 }
    }

    fn handle_sline(&self, state: ParserState, raw: &RawStab) -> ParserState {
        match state {
            ParserState::InFunction { cu, mut func, current_file, brace_depth } => {
                let addr = func.start_addr.saturating_add(u64::from(raw.value));
                func.lines.push(LineEntry {
                    address: addr,
                    line: u32::from(raw.desc),
                    file_idx: 0,
                });
                ParserState::InFunction { cu, func, current_file, brace_depth }
            }
            other => other,
        }
    }

    fn handle_lsym(&self, state: ParserState, raw: &RawStab, name: &str) -> ParserState {
        // N_LSYM with stack offset → local variable
        let (var_name, type_str) = split_name_type(name);
        match state {
            ParserState::InFunction { cu, mut func, current_file, brace_depth } => {
                func.locals.push(LocalVar {
                    name: var_name.to_string(),
                    type_str: type_str.to_string(),
                    frame_offset: raw.value as i32,
                });
                ParserState::InFunction { cu, func, current_file, brace_depth }
            }
            other => other,
        }
    }

    fn handle_psym(&self, state: ParserState, raw: &RawStab, name: &str) -> ParserState {
        let (param_name, type_str) = split_name_type(name);
        match state {
            ParserState::InFunction { cu, mut func, current_file, brace_depth } => {
                func.params.push(Parameter {
                    name: param_name.to_string(),
                    type_str: type_str.to_string(),
                    frame_offset: raw.value as i32,
                });
                ParserState::InFunction { cu, func, current_file, brace_depth }
            }
            other => other,
        }
    }

    fn handle_rsym(&self, state: ParserState, raw: &RawStab, name: &str) -> ParserState {
        let (var_name, type_str) = split_name_type(name);
        match state {
            ParserState::InFunction { cu, mut func, current_file, brace_depth } => {
                func.reg_vars.push(RegisterVar {
                    name: var_name.to_string(),
                    type_str: type_str.to_string(),
                    reg: raw.value,
                });
                ParserState::InFunction { cu, func, current_file, brace_depth }
            }
            other => other,
        }
    }

    fn handle_gsym(&self, state: ParserState, raw: &RawStab, name: &str) -> ParserState {
        let (sym_name, type_str) = split_name_type(name);
        match state {
            ParserState::InCu { mut cu, current_file } => {
                cu.globals.push(GlobalSymbol {
                    name: sym_name.to_string(),
                    type_str: type_str.to_string(),
                    address: u64::from(raw.value),
                });
                ParserState::InCu { cu, current_file }
            }
            other => other,
        }
    }

    fn handle_stsym(&self, state: ParserState, raw: &RawStab, name: &str, is_bss: bool) -> ParserState {
        let (sym_name, type_str) = split_name_type(name);
        match state {
            ParserState::InCu { mut cu, current_file } => {
                cu.statics.push(StaticSymbol {
                    name: sym_name.to_string(),
                    type_str: type_str.to_string(),
                    address: u64::from(raw.value),
                    is_bss,
                });
                ParserState::InCu { cu, current_file }
            }
            other => other,
        }
    }

    fn handle_lbrac(&self, state: ParserState, raw: &RawStab) -> ParserState {
        match state {
            ParserState::InFunction { cu, mut func, current_file, brace_depth } => {
                func.brackets.push(ScopeBracket {
                    kind: BracketKind::Open,
                    offset: raw.value,
                    nesting_depth: brace_depth,
                });
                ParserState::InFunction { cu, func, current_file, brace_depth: brace_depth.saturating_add(1) }
            }
            other => other,
        }
    }

    fn handle_rbrac(&self, state: ParserState, raw: &RawStab) -> ParserState {
        match state {
            ParserState::InFunction { cu, mut func, current_file, brace_depth } => {
                let depth = brace_depth.saturating_sub(1);
                func.brackets.push(ScopeBracket {
                    kind: BracketKind::Close,
                    offset: raw.value,
                    nesting_depth: depth,
                });
                ParserState::InFunction { cu, func, current_file, brace_depth: depth }
            }
            other => other,
        }
    }

    fn flush_state(&mut self, state: ParserState) -> ParserState {
        match state {
            ParserState::InFunction { mut cu, func, .. } => {
                cu.functions.push(func);
                self.units.push(cu);
            }
            ParserState::InCu { cu, .. } => {
                if !cu.filename.is_empty() || !cu.functions.is_empty() {
                    self.units.push(cu);
                }
            }
            ParserState::TopLevel => {}
        }
        ParserState::TopLevel
    }

    // ── High-level query API ───────────────────────────────────────────────────

    /// Iterate over all parsed functions across every compilation unit.
    pub fn all_functions(&self) -> impl Iterator<Item = &ParsedFunction> {
        self.units.iter().flat_map(|cu| cu.functions.iter())
    }

    /// Find a function by exact name across all compilation units.
    #[must_use]
    pub fn find_function_by_name(&self, name: &str) -> Option<&ParsedFunction> {
        self.all_functions().find(|f| f.name == name)
    }

    /// Find the function containing `addr` across all compilation units.
    #[must_use]
    pub fn find_function_at_addr(&self, addr: u64) -> Option<&ParsedFunction> {
        self.all_functions().find(|f| {
            addr >= f.start_addr && (f.end_addr == 0 || addr < f.end_addr)
        })
    }

    /// Map an address to `(source_file, line)` using `N_SLINE` data.
    #[must_use]
    pub fn line_for_addr(&self, addr: u64) -> Option<(String, u32)> {
        let func = self.find_function_at_addr(addr)?;
        let le = func.line_for_addr(addr)?;
        Some((func.source_file.clone(), le.line))
    }

    /// Iterate over all global symbols across every compilation unit.
    pub fn all_globals(&self) -> impl Iterator<Item = &GlobalSymbol> {
        self.units.iter().flat_map(|cu| cu.globals.iter())
    }

    /// Number of parsed compilation units.
    #[must_use]
    pub const fn unit_count(&self) -> usize { self.units.len() }

    /// Total number of parsed functions across all compilation units.
    #[must_use]
    pub fn function_count(&self) -> usize { self.units.iter().map(|u| u.function_count()).sum() }

    /// Build address → function name map
    #[must_use]
    pub fn build_addr_map(&self) -> HashMap<u64, &str> {
        let mut map = HashMap::new();
        for func in self.all_functions() {
            map.insert(func.start_addr, func.name.as_str());
        }
        map
    }

    /// Find the CU that contains the given source file name
    #[must_use]
    pub fn cu_for_file(&self, filename: &str) -> Option<&CompilationUnit> {
        self.units.iter().find(|cu| {
            cu.filename == filename || cu.full_path() == filename
        })
    }
}

impl Default for StabsParser {
    fn default() -> Self { Self::new() }
}

// ── Helper: split "name:type" ──────────────────────────────────────────────────

/// Split a stab name string at the first ':' character.
/// Returns ("`name_part`", "`type_part`").
/// If no ':' is found, returns ("", `whole_string`).
#[must_use]
pub fn split_name_type(s: &str) -> (&str, &str) {
    // Delegates to the crate-wide `::`-aware splitter so C++ symbols such as
    // `Foo::bar:F(0,1)` are not truncated to `Foo`.
    if s.contains(':') {
        crate::split_stab_name(s)
    } else {
        ("", s)
    }
}

/// Return just the name portion (before ':')
#[must_use]
pub fn stab_name(s: &str) -> &str { split_name_type(s).0 }
/// Return just the type string (after ':')
#[must_use]
pub fn stab_type_str(s: &str) -> &str { split_name_type(s).1 }

// ── Continuation-string handling ──────────────────────────────────────────────

/// GCC sometimes splits long stab strings with a backslash at end.
/// This function joins continuation strings from a sequence of raw name strings.
pub fn join_continuations<'a>(parts: impl Iterator<Item = &'a str>) -> String {
    let mut result = String::new();
    for part in parts {
        if part.ends_with('\\') {
            result.push_str(&part[..part.len()-1]);
        } else {
            result.push_str(part);
            break;
        }
    }
    result
}

// ── Stab section loader ────────────────────────────────────────────────────────

/// Parse a .stab section (array of 12-byte entries) into raw stabs
#[must_use]
pub fn parse_stab_section_raw(data: &[u8], big_endian: bool) -> Vec<RawStab> {
    let count = data.len() / RawStab::ENTRY_SIZE;
    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        let base = i * RawStab::ENTRY_SIZE;
        let raw = if big_endian {
            RawStab::parse_be(&data[base..])
        } else {
            RawStab::parse(&data[base..])
        };
        if let Some(r) = raw { result.push(r); }
    }
    result
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_stab(str_off: u32, ty: u8, other: u8, desc: u16, value: u32) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[0..4].copy_from_slice(&str_off.to_le_bytes());
        b[4] = ty;
        b[5] = other;
        b[6..8].copy_from_slice(&desc.to_le_bytes());
        b[8..12].copy_from_slice(&value.to_le_bytes());
        b
    }

    fn build_stab_bytes(entries: &[(u32, u8, u8, u16, u32)]) -> Vec<u8> {
        entries.iter().flat_map(|&(a,b,c,d,e)| make_stab(a,b,c,d,e).to_vec()).collect()
    }

    fn build_stabstr(strings: &[&str]) -> Vec<u8> {
        let mut v = Vec::new();
        for s in strings {
            v.extend_from_slice(s.as_bytes());
            v.push(0);
        }
        v
    }

    #[test]
    fn test_raw_stab_parse() {
        let b = make_stab(0x10, N_FUN, 0, 5, 0x4000);
        let r = RawStab::parse(&b).unwrap();
        assert_eq!(r.string_offset, 0x10);
        assert_eq!(r.stab_type, N_FUN);
        assert_eq!(r.desc, 5);
        assert_eq!(r.value, 0x4000);
    }

    #[test]
    fn test_split_name_type() {
        assert_eq!(split_name_type("foo:int"), ("foo", "int"));
        assert_eq!(split_name_type(":int"), ("", "int"));
        assert_eq!(split_name_type("bare"), ("", "bare"));
    }

    #[test]
    fn test_string_table() {
        let data = build_stabstr(&["", "hello", "world"]);
        let st = StabStringTable::new(data);
        assert_eq!(st.get(0), "");
        assert_eq!(st.get(1), "hello");
        assert_eq!(st.get(7), "world");
    }

    #[test]
    fn test_parse_simple_function() {
        // Strings: 0="" 1="foo.c" 7="bar:F(0,1)" 17="" (fun end marker)
        let strs = build_stabstr(&["", "foo.c", "bar:F(0,1)", ""]);
        let offset_foo_c = 1u32;
        let offset_bar = 1 + "foo.c".len() as u32 + 1;
        let offset_empty_end = offset_bar + "bar:F(0,1)".len() as u32 + 1;

        let stab_entries = vec![
            (offset_foo_c, N_SO, 0, 0, 0u32),    // source file
            (offset_bar,   N_FUN, 0, 0, 0x1000u32), // function start
            (0,            N_SLINE, 0, 10, 0u32),  // line 10 at offset 0
            (0,            N_SLINE, 0, 11, 4u32),  // line 11 at offset 4
            (offset_empty_end, N_FUN, 0, 0, 0x40u32), // function end
        ];
        let stab_data = build_stab_bytes(&stab_entries);
        let str_table = StabStringTable::new(strs);

        let mut parser = StabsParser::new();
        parser.parse_stab_section(&stab_data, &str_table, false);

        assert_eq!(parser.unit_count(), 1);
        let cu = &parser.units[0];
        assert_eq!(cu.filename, "foo.c");
        assert_eq!(cu.functions.len(), 1);
        let f = &cu.functions[0];
        assert_eq!(f.name, "bar");
        assert_eq!(f.start_addr, 0x1000);
        assert_eq!(f.end_addr, 0x1040);
        assert_eq!(f.lines.len(), 2);
        assert_eq!(f.lines[0].line, 10);
        assert_eq!(f.lines[1].line, 11);
    }

    #[test]
    fn test_join_continuations() {
        let parts = vec!["foo\\", "bar\\", "baz"];
        let joined = join_continuations(parts.into_iter());
        assert_eq!(joined, "foobarbaz");
    }

    #[test]
    fn test_find_function_at_addr() {
        let f = ParsedFunction {
            name: "test".to_string(),
            type_str: String::new(),
            start_addr: 0x1000,
            end_addr: 0x1100,
            source_file: "f.c".to_string(),
            lines: vec![
                LineEntry { address: 0x1000, line: 5, file_idx: 0 },
                LineEntry { address: 0x1050, line: 6, file_idx: 0 },
            ],
            params: vec![],
            locals: vec![],
            reg_vars: vec![],
            brackets: vec![],
        };
        assert_eq!(f.line_for_addr(0x1000).map(|e| e.line), Some(5));
        assert_eq!(f.line_for_addr(0x1060).map(|e| e.line), Some(6));
        assert!(f.line_for_addr(0x0FFF).is_none());
    }
}
