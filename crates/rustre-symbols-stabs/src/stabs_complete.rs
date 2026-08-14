//! `stabs_complete` — Complete STABS debug format type system and parser.
//!
//! Provides:
//! * [`StabsComplete`] — top-level complete STABS parser
//! * All N_ type codes from the STABS format
//! * [`StabsScope`] — lexical scope (compilation unit / function / block)
//! * [`StabsVariable`] — variable with type, storage class, and location
//! * [`StabsLineNumber`] — source line number mapping
//! * [`StabsReport`] — aggregated analysis report

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::StabsError;

// ─── StabType ─────────────────────────────────────────────────────────────────

/// All STABS `N_*` type codes.
///
/// Values correspond to the `n_type` byte in ELF `.stab` entries.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StabType {
    /// Global symbol (`N_GSYM`).
    NSym = 0x20,
    /// Function name for BSD Fortran (`N_FNAME`).
    Fname = 0x22,
    /// Function name or text-segment variable (`N_FUN`).
    Fun = 0x24,
    /// Data-segment variable (`N_STSYM`).
    StSym = 0x26,
    /// BSS-segment variable (`N_LCSYM`).
    LcSym = 0x28,
    /// Name of main routine (`N_MAIN`).
    Main = 0x2A,
    /// Rosetta symbols (`N_ROSYM`).
    RoSym = 0x2C,
    /// PC/source-line (for `pc` table) (`N_PC`).
    Pc = 0x30,
    /// Symbol in `.o` file included in link (`N_NSYMS`).
    NSsyms = 0x32,
    /// No DST map for sym (`N_NOMAP`).
    NoMap = 0x34,
    /// Macro definition (`N_MAC_DEFINE`).
    MacDef = 0x36,
    /// Debugging symbol (`N_OBJ`).
    Obj = 0x38,
    /// Macro undef (`N_MAC_UNDEF`, binutils/gdb `stab.def`: 0x3A).
    MacUndef = 0x3A,
    /// Debugger options / compiler version string (`N_OPT`, 0x3C).
    ///
    /// GCC emits one of these (holding the gcc version string) in
    /// essentially every compilation unit.
    Opt = 0x3C,
    /// Register variable (`N_RSYM`).
    RSym = 0x40,
    /// Modula-2 compilation unit (`N_M2C`).
    M2C = 0x42,
    /// Line number in text segment (`N_SLINE`).
    SLine = 0x44,
    /// Line number in data segment (`N_DSLINE`).
    DSLine = 0x46,
    /// Line number in BSS segment (`N_BSLINE`).
    BSLine = 0x48,
    /// Sun source code browser (`N_SSYM`).
    SSym = 0x60,
    /// End of an include file (`N_SO`) — end variant.
    SoEnd = 0x62,
    /// Name of object file (`N_SO`).
    So = 0x64,
    /// Automatic variable (`N_LSYM`).
    LSym = 0x80,
    /// Beginning of an include file (`N_BINCL`).
    Bincl = 0x82,
    /// Name of include file (`N_SOL`).
    Sol = 0x84,
    /// Parameter variable (`N_PSYM`).
    PSym = 0xA0,
    /// End of an include file (`N_EINCL`).
    Eincl = 0xA2,
    /// Alternate entry point (`N_ENTRY`).
    Entry = 0xA4,
    /// Beginning of a lexical block (`N_LBRAC`).
    LBrac = 0xC0,
    /// Delete included file (`N_EXCL`).
    Excl = 0xC2,
    /// Scope information (`N_SCOPE`).
    Scope = 0xC4,
    /// End of a lexical block (`N_RBRAC`).
    RBrac = 0xE0,
    /// Begin common block (`N_BCOMM`).
    BComm = 0xE2,
    /// End common block (`N_ECOMM`).
    EComm = 0xE4,
    /// End common (local) (`N_ECOML`).
    EComL = 0xE8,
    /// New begin BSS segment (`N_NBBSS`, 0xF4 — matches `crate::StabType::NNbbss`).
    ///
    /// Historically mislabeled `Tls` here; 0xF4 is `N_NBBSS` in binutils
    /// `stab.def` and in this crate's own top-level `StabType`.
    Nbbss = 0xF4,
    /// Line number in text segment (alternate) (`N_LENG`).
    Leng = 0xFE,
    /// Undefined (`N_UNDF`).
    Undf = 0x00,
}

impl StabType {
    /// Decode a raw `n_type` byte into a `StabType`.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x20 => Some(Self::NSym),
            0x22 => Some(Self::Fname),
            0x24 => Some(Self::Fun),
            0x26 => Some(Self::StSym),
            0x28 => Some(Self::LcSym),
            0x2A => Some(Self::Main),
            0x2C => Some(Self::RoSym),
            0x30 => Some(Self::Pc),
            0x32 => Some(Self::NSsyms),
            0x34 => Some(Self::NoMap),
            0x36 => Some(Self::MacDef),
            0x38 => Some(Self::Obj),
            0x3A => Some(Self::MacUndef),
            0x3C => Some(Self::Opt),
            0x40 => Some(Self::RSym),
            0x42 => Some(Self::M2C),
            0x44 => Some(Self::SLine),
            0x46 => Some(Self::DSLine),
            0x48 => Some(Self::BSLine),
            0x60 => Some(Self::SSym),
            0x62 => Some(Self::SoEnd),
            0x64 => Some(Self::So),
            0x80 => Some(Self::LSym),
            0x82 => Some(Self::Bincl),
            0x84 => Some(Self::Sol),
            0xA0 => Some(Self::PSym),
            0xA2 => Some(Self::Eincl),
            0xA4 => Some(Self::Entry),
            0xC0 => Some(Self::LBrac),
            0xC2 => Some(Self::Excl),
            0xC4 => Some(Self::Scope),
            0xE0 => Some(Self::RBrac),
            0xE2 => Some(Self::BComm),
            0xE4 => Some(Self::EComm),
            0xE8 => Some(Self::EComL),
            0xF4 => Some(Self::Nbbss),
            0xFE => Some(Self::Leng),
            0x00 => Some(Self::Undf),
            _ => None,
        }
    }

    /// Returns `true` if this type represents a source file boundary.
    #[must_use]
    pub const fn is_source_file(&self) -> bool {
        matches!(self, Self::So | Self::Sol | Self::SoEnd)
    }

    /// Returns `true` if this type represents a variable or parameter.
    #[must_use]
    pub const fn is_variable(&self) -> bool {
        matches!(
            self,
            Self::NSym
                | Self::StSym
                | Self::LcSym
                | Self::LSym
                | Self::PSym
                | Self::RSym
        )
    }

    /// Returns `true` if this type represents a function.
    #[must_use]
    pub const fn is_function(&self) -> bool {
        matches!(self, Self::Fun | Self::Main | Self::Entry)
    }

    /// Returns `true` if this type represents a block boundary.
    #[must_use]
    pub const fn is_block_boundary(&self) -> bool {
        matches!(self, Self::LBrac | Self::RBrac)
    }
}

// ─── RawStab ──────────────────────────────────────────────────────────────────

/// A raw STABS entry read from the `.stab` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawStab {
    /// Index into `.stabstr` string table.
    pub str_index: u32,
    /// Entry type byte.
    pub n_type: u8,
    /// Other field (varies by type).
    pub n_other: u8,
    /// Description field (line number for `N_SLINE`, type number for vars, etc.).
    pub n_desc: u16,
    /// Value field (address or offset).
    pub n_value: u32,
}

impl RawStab {
    /// Decode the type from `n_type`.
    #[must_use]
    pub const fn stab_type(&self) -> Option<StabType> {
        StabType::from_byte(self.n_type)
    }
}

// ─── StabsTypeRef ─────────────────────────────────────────────────────────────

/// A reference to a STABS type descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StabsTypeRef {
    /// File number (0 = current file).
    pub file_no: u32,
    /// Type number within the file.
    pub type_no: u32,
}

impl StabsTypeRef {
    /// Create a new type reference.
    #[must_use]
    pub const fn new(file_no: u32, type_no: u32) -> Self {
        Self { file_no, type_no }
    }

    /// Returns `true` if this is a reference to the current file.
    #[must_use]
    pub const fn is_local(&self) -> bool {
        self.file_no == 0
    }
}

// ─── StabsBaseType ────────────────────────────────────────────────────────────

/// A decoded STABS primitive/composite type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StabsBaseType {
    /// Integer type (signed / unsigned, bit width).
    Int {
        /// Whether the type is signed.
        signed: bool,
        /// Width in bits.
        bits: u32,
    },
    /// Floating-point type.
    Float {
        /// Width in bits.
        bits: u32,
    },
    /// Void / no-type.
    Void,
    /// Pointer to another type.
    Pointer {
        /// Pointed-to type.
        target: Box<Self>,
    },
    /// Array type.
    Array {
        /// Element type.
        element: Box<Self>,
        /// Lower index bound.
        lower: i64,
        /// Upper index bound.
        upper: i64,
    },
    /// Structure type.
    Struct {
        /// Struct tag name.
        name: String,
        /// Member fields.
        fields: Vec<StabsField>,
    },
    /// Union type.
    Union {
        /// Union tag name.
        name: String,
        /// Member fields.
        fields: Vec<StabsField>,
    },
    /// Enum type.
    Enum {
        /// Enum tag name.
        name: String,
        /// `(name, value)` enumerator pairs.
        variants: Vec<(String, i64)>,
    },
    /// Type alias (typedef).
    Typedef {
        /// Typedef name.
        alias: String,
        /// Aliased type.
        target: Box<Self>,
    },
    /// Forward reference by type number.
    Ref(StabsTypeRef),
    /// Unknown or not yet parsed.
    Unknown(String),
}

impl StabsBaseType {
    /// Returns a short display string.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::Int { signed, bits } => {
                format!("{}{}", if *signed { "i" } else { "u" }, bits)
            }
            Self::Float { bits } => format!("f{bits}"),
            Self::Void => "void".to_string(),
            Self::Pointer { .. } => "ptr".to_string(),
            Self::Array { .. } => "array".to_string(),
            Self::Struct { name, .. } => format!("struct {name}"),
            Self::Union { name, .. } => format!("union {name}"),
            Self::Enum { name, .. } => format!("enum {name}"),
            Self::Typedef { alias, .. } => format!("typedef {alias}"),
            Self::Ref(r) => format!("ref({},{})", r.file_no, r.type_no),
            Self::Unknown(s) => format!("?({s})"),
        }
    }

    /// Returns `true` if this is a pointer type.
    #[must_use]
    pub const fn is_pointer(&self) -> bool {
        matches!(self, Self::Pointer { .. })
    }

    /// Returns `true` if this is a struct or union.
    #[must_use]
    pub const fn is_composite(&self) -> bool {
        matches!(self, Self::Struct { .. } | Self::Union { .. })
    }
}

// ─── StabsField ───────────────────────────────────────────────────────────────

/// A field in a STABS struct/union type descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabsField {
    /// Field name.
    pub name: String,
    /// Field type reference.
    pub field_type: StabsTypeRef,
    /// Bit offset within the aggregate.
    pub bit_offset: u32,
    /// Bit size (0 = natural size of the type).
    pub bit_size: u32,
}

// ─── StabsVariable ────────────────────────────────────────────────────────────

/// A variable, parameter, or register variable decoded from STABS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabsVariable {
    /// Variable name.
    pub name: String,
    /// STABS type reference.
    pub type_ref: StabsTypeRef,
    /// Storage class.
    pub storage: StabsStorage,
    /// Address or register number.
    pub value: i64,
    /// Source file where declared.
    pub source_file: String,
    /// Source line number.
    pub line: u32,
}

/// Storage class for a variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StabsStorage {
    /// Global symbol.
    Global,
    /// Static (file-scope).
    Static,
    /// BSS (zero-init static).
    Bss,
    /// Auto (stack-allocated local).
    Auto,
    /// Register variable.
    Register,
    /// Function parameter.
    Param,
    /// Thread-local.
    ThreadLocal,
}

// ─── StabsLineNumber ─────────────────────────────────────────────────────────

/// A source line number mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabsLineNumber {
    /// Source line number.
    pub line: u32,
    /// Text address corresponding to this line.
    pub address: u64,
    /// Source file (from the current `N_SO`/`N_SOL` context).
    pub file: String,
}

// ─── StabsScope ───────────────────────────────────────────────────────────────

/// A lexical scope (compilation unit, function, or anonymous block).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabsScope {
    /// Scope kind.
    pub kind: ScopeKind,
    /// Name (function name or file path for CU scopes).
    pub name: String,
    /// Start address.
    pub start: u64,
    /// End address (0 if unknown).
    pub end: u64,
    /// Variables declared in this scope.
    pub variables: Vec<StabsVariable>,
    /// Nested child scopes.
    pub children: Vec<Self>,
}

/// Kind of lexical scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeKind {
    /// Compilation unit (top-level `N_SO`).
    CompilationUnit,
    /// Function body (`N_FUN`).
    Function,
    /// Anonymous block (`N_LBRAC` / `N_RBRAC`).
    Block,
}

impl StabsScope {
    /// Returns `true` if `address` falls within this scope.
    #[must_use]
    pub const fn contains(&self, address: u64) -> bool {
        if self.end == 0 {
            address >= self.start
        } else {
            address >= self.start && address < self.end
        }
    }

    /// Recursively count all variables in this scope and children.
    #[must_use]
    pub fn total_variables(&self) -> usize {
        self.variables.len()
            + self
                .children
                .iter()
                .map(Self::total_variables)
                .sum::<usize>()
    }
}

// ─── StabsReport ──────────────────────────────────────────────────────────────

/// Aggregated report produced by [`StabsComplete`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabsReport {
    /// Source files found.
    pub source_files: Vec<String>,
    /// Top-level compilation unit scopes.
    pub compilation_units: Vec<StabsScope>,
    /// Line number table.
    pub line_numbers: Vec<StabsLineNumber>,
    /// Global variables.
    pub globals: Vec<StabsVariable>,
    /// Type definitions map: `type_no` → decoded type.
    pub types: HashMap<u32, StabsBaseType>,
    /// Total number of raw stab entries processed.
    pub raw_stab_count: usize,
    /// Number of unknown stab types encountered.
    pub unknown_count: usize,
}

impl StabsReport {
    /// Returns the total number of line number entries.
    #[must_use]
    pub const fn line_count(&self) -> usize {
        self.line_numbers.len()
    }

    /// Look up the source location for a given address.
    #[must_use]
    pub fn location_for(&self, address: u64) -> Option<&StabsLineNumber> {
        // Return the nearest line number entry ≤ address.
        self.line_numbers
            .iter()
            .filter(|l| l.address <= address)
            .max_by_key(|l| l.address)
    }

    /// Returns all global variable names.
    #[must_use]
    pub fn global_names(&self) -> Vec<&str> {
        self.globals.iter().map(|v| v.name.as_str()).collect()
    }

    /// Returns the number of compilation units.
    #[must_use]
    pub const fn cu_count(&self) -> usize {
        self.compilation_units.len()
    }
}

// ─── StabsComplete ────────────────────────────────────────────────────────────

/// Complete STABS debug information parser.
///
/// Parses a `.stab` section + `.stabstr` string table and produces a
/// comprehensive [`StabsReport`].
#[derive(Debug, Default, Clone)]
pub struct StabsComplete {
    /// Whether to include unknown/unsupported stab entries in the report.
    pub include_unknown: bool,
}

impl StabsComplete {
    /// Create a new parser.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Include unknown stab entries in the report.
    #[must_use]
    pub const fn with_unknown(mut self) -> Self {
        self.include_unknown = true;
        self
    }

    /// Parse raw stab entries with a string table.
    ///
    /// # Errors
    /// Returns [`StabsError`] if string table access fails.
    pub fn parse(&self, stabs: &[RawStab], stabstr: &[u8]) -> Result<StabsReport, StabsError> {
        let mut report = StabsReport {
            source_files: Vec::new(),
            compilation_units: Vec::new(),
            line_numbers: Vec::new(),
            globals: Vec::new(),
            types: HashMap::new(),
            raw_stab_count: stabs.len(),
            unknown_count: 0,
        };

        let mut current_file = String::new();
        let mut current_cu: Option<StabsScope> = None;
        let mut current_func: Option<StabsScope> = None;
        let mut type_counter = 1u32;

        let mut str_base = crate::cu_strings::CuStringBase::new();
        for stab in stabs {
            let name = Self::read_string_based(stabstr, &mut str_base, stab)?;
            Self::process_stab(
                stab,
                &name,
                &mut report,
                &mut current_file,
                &mut current_cu,
                &mut current_func,
                &mut type_counter,
            );
        }

        // Close any open function/CU.
        if let Some(func) = current_func
            && let Some(cu) = current_cu.as_mut() {
                cu.children.push(func);
        }
        if let Some(cu) = current_cu {
            report.compilation_units.push(cu);
        }

        Ok(report)
    }

    fn process_stab(
        stab: &RawStab,
        name: &str,
        report: &mut StabsReport,
        current_file: &mut String,
        current_cu: &mut Option<StabsScope>,
        current_func: &mut Option<StabsScope>,
        type_counter: &mut u32,
    ) {
        match stab.stab_type() {
            Some(StabType::So) => {
                if let Some(mut cu) = current_cu.take() {
                    cu.end = u64::from(stab.n_value);
                    report.compilation_units.push(cu);
                }
                if !name.is_empty() {
                    name.clone_into(current_file);
                    if !report.source_files.contains(current_file) {
                        report.source_files.push(current_file.clone());
                    }
                    *current_cu = Some(StabsScope {
                        kind: ScopeKind::CompilationUnit,
                        name: name.to_owned(),
                        start: u64::from(stab.n_value),
                        end: 0,
                        variables: Vec::new(),
                        children: Vec::new(),
                    });
                }
            }
            Some(StabType::Sol) => {
                name.clone_into(current_file);
                if !report.source_files.contains(current_file) {
                    report.source_files.push(current_file.clone());
                }
            }
            Some(StabType::Fun) => {
                // An empty-name N_FUN is the end-of-function marker, and its
                // n_value is the function *size*, not an address. Without this
                // branch every real function was followed by a phantom
                // empty-named scope and its `end` was left at 0 (which makes
                // StabsScope::contains treat it as unbounded).
                if name.is_empty() {
                    if let Some(mut func) = current_func.take() {
                        func.end = func.start.saturating_add(u64::from(stab.n_value));
                        if let Some(cu) = current_cu.as_mut() {
                            cu.children.push(func);
                        }
                    }
                    return;
                }
                if let Some(func) = current_func.take()
                    && let Some(cu) = current_cu.as_mut() {
                        cu.children.push(func);
                }
                *current_func = Some(StabsScope {
                    kind: ScopeKind::Function,
                    // Strip the `:F(0,1)` type descriptor: a real .stabstr
                    // holds `name:descriptor`, not a bare name.
                    name: crate::stab_name_of(name).to_owned(),
                    start: u64::from(stab.n_value),
                    end: 0,
                    variables: Vec::new(),
                    children: Vec::new(),
                });
            }
            Some(StabType::SLine) => {
                report.line_numbers.push(StabsLineNumber {
                    line: u32::from(stab.n_desc),
                    address: u64::from(stab.n_value),
                    file: current_file.clone(),
                });
            }
            Some(StabType::NSym) => {
                let type_ref = StabsTypeRef::new(0, *type_counter);
                report.globals.push(StabsVariable {
                    name: crate::stab_name_of(name).to_owned(),
                    type_ref,
                    storage: StabsStorage::Global,
                    value: i64::from(stab.n_value),
                    source_file: current_file.clone(),
                    line: u32::from(stab.n_desc),
                });
                *type_counter += 1;
            }
            Some(StabType::LSym) => {
                Self::push_local_var(stab, name, current_file, current_cu, current_func, type_counter, StabsStorage::Auto);
            }
            Some(StabType::PSym) => {
                let type_ref = StabsTypeRef::new(0, *type_counter);
                let var = StabsVariable {
                    name: crate::stab_name_of(name).to_owned(),
                    type_ref,
                    storage: StabsStorage::Param,
                    value: i64::from(stab.n_value),
                    source_file: current_file.clone(),
                    line: u32::from(stab.n_desc),
                };
                if let Some(func) = current_func.as_mut() {
                    func.variables.push(var);
                }
                *type_counter += 1;
            }
            Some(StabType::RSym) => {
                let type_ref = StabsTypeRef::new(0, *type_counter);
                let var = StabsVariable {
                    name: crate::stab_name_of(name).to_owned(),
                    type_ref,
                    storage: StabsStorage::Register,
                    value: i64::from(stab.n_value),
                    source_file: current_file.clone(),
                    line: u32::from(stab.n_desc),
                };
                if let Some(func) = current_func.as_mut() {
                    func.variables.push(var);
                }
                *type_counter += 1;
            }
            None => {
                report.unknown_count += 1;
            }
            _ => {}
        }
    }

    fn push_local_var(
        stab: &RawStab,
        name: &str,
        current_file: &str,
        current_cu: &mut Option<StabsScope>,
        current_func: &mut Option<StabsScope>,
        type_counter: &mut u32,
        storage: StabsStorage,
    ) {
        let type_ref = StabsTypeRef::new(0, *type_counter);
        let var = StabsVariable {
            name: crate::stab_name_of(name).to_owned(),
            type_ref,
            storage,
            value: i64::from(stab.n_value),
            source_file: current_file.to_owned(),
            line: u32::from(stab.n_desc),
        };
        if let Some(func) = current_func.as_mut() {
            func.variables.push(var);
        } else if let Some(cu) = current_cu.as_mut() {
            cu.variables.push(var);
        }
        *type_counter += 1;
    }

    /// Read a record's string at the running CU-relative base, advancing the
    /// base past an `N_UNDF` compilation-unit header.
    fn read_string_based(
        stabstr: &[u8],
        base: &mut crate::cu_strings::CuStringBase,
        stab: &RawStab,
    ) -> Result<String, StabsError> {
        base.observe(stab.n_type, stab.n_value, stabstr.len());
        match base.offset(stabstr.len(), stab.str_index) {
            Some(off) => Self::decode(crate::cu_strings::read_cstr_bytes(stabstr, off)),
            None if stab.str_index == 0 => Ok(String::new()),
            None => Err(StabsError::StringTable(format!(
                "offset {} out of range",
                stab.str_index
            ))),
        }
    }

    fn decode(bytes: &[u8]) -> Result<String, StabsError> {
        std::str::from_utf8(bytes)
            .map(std::string::ToString::to_string)
            .map_err(|e| StabsError::StringTable(e.to_string()))
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_stabstr(strings: &[&str]) -> Vec<u8> {
        let mut buf = Vec::new();
        for s in strings {
            buf.extend_from_slice(s.as_bytes());
            buf.push(0);
        }
        buf
    }

    fn stab(str_idx: u32, n_type: u8, n_desc: u16, n_value: u32) -> RawStab {
        RawStab {
            str_index: str_idx,
            n_type,
            n_other: 0,
            n_desc,
            n_value,
        }
    }

    // ── StabType ──────────────────────────────────────────────────────────────

    #[test]
    fn test_stab_type_from_byte_so() {
        assert_eq!(StabType::from_byte(0x64), Some(StabType::So));
    }
    #[test]
    fn test_stab_type_from_byte_fun() {
        assert_eq!(StabType::from_byte(0x24), Some(StabType::Fun));
    }
    #[test]
    fn test_stab_type_from_byte_sline() {
        assert_eq!(StabType::from_byte(0x44), Some(StabType::SLine));
    }
    #[test]
    fn test_stab_type_from_byte_lsym() {
        assert_eq!(StabType::from_byte(0x80), Some(StabType::LSym));
    }
    #[test]
    fn test_stab_type_from_byte_rsym() {
        assert_eq!(StabType::from_byte(0x40), Some(StabType::RSym));
    }
    #[test]
    fn test_stab_type_from_byte_psym() {
        assert_eq!(StabType::from_byte(0xA0), Some(StabType::PSym));
    }
    #[test]
    fn test_stab_type_from_byte_nsym() {
        assert_eq!(StabType::from_byte(0x20), Some(StabType::NSym));
    }
    #[test]
    fn test_stab_type_from_byte_unknown() {
        assert!(StabType::from_byte(0x01).is_none());
    }
    #[test]
    fn test_stab_type_is_source_file() {
        assert!(StabType::So.is_source_file());
        assert!(!StabType::Fun.is_source_file());
    }
    #[test]
    fn test_stab_type_is_variable() {
        assert!(StabType::LSym.is_variable());
        assert!(!StabType::So.is_variable());
    }
    #[test]
    fn test_stab_type_is_function() {
        assert!(StabType::Fun.is_function());
        assert!(!StabType::LSym.is_function());
    }
    #[test]
    fn test_stab_type_is_block_boundary() {
        assert!(StabType::LBrac.is_block_boundary());
        assert!(StabType::RBrac.is_block_boundary());
    }

    // ── StabsTypeRef ──────────────────────────────────────────────────────────

    #[test]
    fn test_type_ref_is_local() {
        let r = StabsTypeRef::new(0, 5);
        assert!(r.is_local());
    }
    #[test]
    fn test_type_ref_not_local() {
        let r = StabsTypeRef::new(1, 5);
        assert!(!r.is_local());
    }

    // ── StabsBaseType ─────────────────────────────────────────────────────────

    #[test]
    fn test_base_type_display_int() {
        assert_eq!(
            StabsBaseType::Int {
                signed: true,
                bits: 32
            }
            .display(),
            "i32"
        );
    }
    #[test]
    fn test_base_type_display_float() {
        assert_eq!(StabsBaseType::Float { bits: 64 }.display(), "f64");
    }
    #[test]
    fn test_base_type_display_void() {
        assert_eq!(StabsBaseType::Void.display(), "void");
    }
    #[test]
    fn test_base_type_is_pointer() {
        let t = StabsBaseType::Pointer {
            target: Box::new(StabsBaseType::Void),
        };
        assert!(t.is_pointer());
    }
    #[test]
    fn test_base_type_is_composite_struct() {
        let t = StabsBaseType::Struct {
            name: "Foo".into(),
            fields: vec![],
        };
        assert!(t.is_composite());
    }
    #[test]
    fn test_base_type_is_not_composite_int() {
        assert!(
            !StabsBaseType::Int {
                signed: false,
                bits: 8
            }
            .is_composite()
        );
    }

    // ── StabsScope ────────────────────────────────────────────────────────────

    #[test]
    fn test_scope_contains() {
        let s = StabsScope {
            kind: ScopeKind::Function,
            name: "foo".into(),
            start: 0x1000,
            end: 0x2000,
            variables: vec![],
            children: vec![],
        };
        assert!(s.contains(0x1500));
        assert!(!s.contains(0x500));
        assert!(!s.contains(0x2000));
    }
    #[test]
    fn test_scope_total_variables() {
        let child = StabsScope {
            kind: ScopeKind::Block,
            name: String::new(),
            start: 0x1100,
            end: 0x1200,
            variables: vec![StabsVariable {
                name: "x".into(),
                type_ref: StabsTypeRef::new(0, 1),
                storage: StabsStorage::Auto,
                value: 0,
                source_file: String::new(),
                line: 1,
            }],
            children: vec![],
        };
        let parent = StabsScope {
            kind: ScopeKind::Function,
            name: "foo".into(),
            start: 0x1000,
            end: 0x2000,
            variables: vec![StabsVariable {
                name: "a".into(),
                type_ref: StabsTypeRef::new(0, 2),
                storage: StabsStorage::Auto,
                value: 0,
                source_file: String::new(),
                line: 2,
            }],
            children: vec![child],
        };
        assert_eq!(parent.total_variables(), 2);
    }

    // ── StabsComplete (integration) ───────────────────────────────────────────

    fn simple_stabs_and_stabstr() -> (Vec<RawStab>, Vec<u8>) {
        let stabstr = make_stabstr(&["", "main.c", "foo", "argc", "argv", "result"]);
        // offsets: "" = 0, "main.c" = 1, "foo" = 8, "argc" = 12, "argv" = 17, "result" = 22
        let stabs = vec![
            stab(1, 0x64, 0, 0x1000),        // N_SO main.c
            stab(8, 0x24, 0, 0x1000),        // N_FUN foo
            stab(12, 0xA0, 1, 0),            // N_PSYM argc
            stab(17, 0xA0, 2, 4),            // N_PSYM argv
            stab(0, 0x44, 10, 0x1000),       // N_SLINE line 10
            stab(0, 0x44, 11, 0x1005),       // N_SLINE line 11
            stab(22, 0x80, 3, -4i32 as u32), // N_LSYM result
        ];
        (stabs, stabstr)
    }

    #[test]
    fn test_parse_source_file() {
        let (stabs, stabstr) = simple_stabs_and_stabstr();
        let parser = StabsComplete::new();
        let report = parser.parse(&stabs, &stabstr).unwrap();
        assert!(report.source_files.iter().any(|f| f.contains("main.c")));
    }

    #[test]
    fn test_parse_line_numbers() {
        let (stabs, stabstr) = simple_stabs_and_stabstr();
        let parser = StabsComplete::new();
        let report = parser.parse(&stabs, &stabstr).unwrap();
        assert!(!report.line_numbers.is_empty());
    }

    #[test]
    fn test_parse_raw_stab_count() {
        let (stabs, stabstr) = simple_stabs_and_stabstr();
        let parser = StabsComplete::new();
        let report = parser.parse(&stabs, &stabstr).unwrap();
        assert_eq!(report.raw_stab_count, stabs.len());
    }

    #[test]
    fn test_parse_compilation_unit() {
        let (stabs, stabstr) = simple_stabs_and_stabstr();
        let parser = StabsComplete::new();
        let report = parser.parse(&stabs, &stabstr).unwrap();
        assert!(!report.compilation_units.is_empty());
    }

    #[test]
    fn test_parse_function_scope_in_cu() {
        let (stabs, stabstr) = simple_stabs_and_stabstr();
        let parser = StabsComplete::new();
        let report = parser.parse(&stabs, &stabstr).unwrap();
        let cu = &report.compilation_units[0];
        assert!(!cu.children.is_empty());
    }

    #[test]
    fn test_parse_empty_stabs() {
        let parser = StabsComplete::new();
        let report = parser.parse(&[], b"\0").unwrap();
        assert_eq!(report.raw_stab_count, 0);
        assert!(report.source_files.is_empty());
    }

    #[test]
    fn test_location_for() {
        let (stabs, stabstr) = simple_stabs_and_stabstr();
        let parser = StabsComplete::new();
        let report = parser.parse(&stabs, &stabstr).unwrap();
        let loc = report.location_for(0x1004);
        assert!(loc.is_some());
    }

    #[test]
    fn test_global_names_empty() {
        let (stabs, stabstr) = simple_stabs_and_stabstr();
        let parser = StabsComplete::new();
        let report = parser.parse(&stabs, &stabstr).unwrap();
        let _names = report.global_names(); // no panic
    }

    #[test]
    fn test_report_serialization() {
        let (stabs, stabstr) = simple_stabs_and_stabstr();
        let parser = StabsComplete::new();
        let report = parser.parse(&stabs, &stabstr).unwrap();
        let j = serde_json::to_string(&report).unwrap();
        let d: StabsReport = serde_json::from_str(&j).unwrap();
        assert_eq!(d.raw_stab_count, report.raw_stab_count);
    }

    #[test]
    fn test_parse_global_variable() {
        let stabstr = make_stabstr(&["", "main.c", "gVar"]);
        let stabs = vec![
            stab(1, 0x64, 0, 0x1000), // N_SO
            stab(8, 0x20, 0, 0x4000), // N_GSYM gVar
        ];
        let parser = StabsComplete::new();
        let report = parser.parse(&stabs, &stabstr).unwrap();
        assert!(!report.globals.is_empty());
        assert_eq!(report.globals[0].name, "gVar");
        assert_eq!(report.globals[0].storage, StabsStorage::Global);
    }

    #[test]
    fn test_parse_register_variable() {
        let stabstr = make_stabstr(&["", "test.c", "foo", "reg_var"]);
        let stabs = vec![
            stab(1, 0x64, 0, 0x1000), // N_SO
            stab(8, 0x24, 0, 0x1000), // N_FUN foo
            stab(12, 0x40, 0, 3),     // N_RSYM reg_var in reg 3
        ];
        let parser = StabsComplete::new();
        let report = parser.parse(&stabs, &stabstr).unwrap();
        let cu = &report.compilation_units[0];
        let func = cu.children.first().unwrap();
        assert!(!func.variables.is_empty());
        assert_eq!(func.variables[0].storage, StabsStorage::Register);
    }

    #[test]
    fn test_stab_type_sol() {
        assert!(StabType::Sol.is_source_file());
    }

    #[test]
    fn test_stab_type_n_other_roundtrip() {
        let s = RawStab {
            str_index: 0,
            n_type: 0x64,
            n_other: 5,
            n_desc: 0,
            n_value: 0,
        };
        assert_eq!(s.n_other, 5);
    }

    #[test]
    fn test_cu_count() {
        let (stabs, stabstr) = simple_stabs_and_stabstr();
        let parser = StabsComplete::new();
        let report = parser.parse(&stabs, &stabstr).unwrap();
        assert_eq!(report.cu_count(), 1);
    }

    #[test]
    fn test_line_count() {
        let (stabs, stabstr) = simple_stabs_and_stabstr();
        let parser = StabsComplete::new();
        let report = parser.parse(&stabs, &stabstr).unwrap();
        assert_eq!(report.line_count(), 2);
    }
}
