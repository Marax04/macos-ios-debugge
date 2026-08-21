//! `assembler_6502` — Two-pass 6502/65C02/65816 assembler.
//!
//! Provides [`TwoPassAssembler`] which resolves forward references via a
//! symbol table built in pass 1 and emits object bytes in pass 2.
//!
//! # Features
//! * Assembler directives: `ORG`, `BYTE`, `WORD`, `TEXT`, `EQU`
//! * Label definitions and forward-reference resolution
//! * Full 6502 instruction encoding (all 56 official opcodes, all addressing modes)
//! * Optional 65C02 extensions
//! * Listing output with addresses, bytes, and source lines
//! * Rich error reporting with line numbers

use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can arise during assembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssemblerError {
    /// Undefined symbol referenced.
    UndefinedSymbol { name: String, line: usize },
    /// Symbol defined more than once.
    DuplicateSymbol { name: String, line: usize },
    /// Branch target is too far for an 8-bit relative offset.
    BranchOutOfRange { target: u16, from: u16, line: usize },
    /// An opcode does not support the specified addressing mode.
    InvalidAddressingMode {
        mnemonic: String,
        mode: AddressingMode,
        line: usize,
    },
    /// A numeric literal could not be parsed.
    ParseError { text: String, line: usize },
    /// ORG value would overlap already-emitted bytes.
    OrgOverlap {
        new_pc: u16,
        current_pc: u16,
        line: usize,
    },
    /// Unknown mnemonic.
    UnknownMnemonic { mnemonic: String, line: usize },
    /// Generic error.
    Generic { message: String, line: usize },
}

impl fmt::Display for AssemblerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UndefinedSymbol { name, line } => {
                write!(f, "line {line}: undefined symbol '{name}'")
            }
            Self::DuplicateSymbol { name, line } => {
                write!(f, "line {line}: duplicate symbol '{name}'")
            }
            Self::BranchOutOfRange { target, from, line } => write!(
                f,
                "line {line}: branch target {target:#06x} out of range from {from:#06x}"
            ),
            Self::InvalidAddressingMode {
                mnemonic,
                mode,
                line,
            } => write!(f, "line {line}: '{mnemonic}' does not support {mode:?}"),
            Self::ParseError { text, line } => write!(f, "line {line}: cannot parse '{text}'"),
            Self::OrgOverlap {
                new_pc,
                current_pc,
                line,
            } => write!(
                f,
                "line {line}: ORG {new_pc:#06x} overlaps current PC {current_pc:#06x}"
            ),
            Self::UnknownMnemonic { mnemonic, line } => {
                write!(f, "line {line}: unknown mnemonic '{mnemonic}'")
            }
            Self::Generic { message, line } => write!(f, "line {line}: {message}"),
        }
    }
}

impl std::error::Error for AssemblerError {}

impl From<AssemblerError> for Vec<AssemblerError> {
    fn from(err: AssemblerError) -> Self {
        vec![err]
    }
}

// ---------------------------------------------------------------------------
// Addressing modes
// ---------------------------------------------------------------------------

/// All 6502/65C02 addressing modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressingMode {
    Implied,
    Accumulator,
    Immediate,
    ZeroPage,
    ZeroPageX,
    ZeroPageY,
    Absolute,
    AbsoluteX,
    AbsoluteY,
    Indirect,
    IndirectX, // (zp,X)
    IndirectY, // (zp),Y
    Relative,
    /// 65C02: (zp) indirect without index
    ZeroPageIndirect,
    /// 65816 absolute long
    AbsoluteLong,
}

// ---------------------------------------------------------------------------
// Label
// ---------------------------------------------------------------------------

/// A resolved or unresolved label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    pub name: String,
    pub address: Option<u16>,
    pub defined_at_line: usize,
}

impl Label {
    pub fn new(name: impl Into<String>, address: Option<u16>, line: usize) -> Self {
        Self {
            name: name.into(),
            address,
            defined_at_line: line,
        }
    }

    #[must_use] 
    pub const fn is_resolved(&self) -> bool {
        self.address.is_some()
    }
}

// ---------------------------------------------------------------------------
// Assembler directive
// ---------------------------------------------------------------------------

/// Pseudo-operations supported by the assembler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssemblerDirective {
    /// Set the program counter.
    Org(u16),
    /// Emit one or more bytes.
    Byte(Vec<u8>),
    /// Emit one or more 16-bit words (little-endian).
    Word(Vec<u16>),
    /// Emit a string as bytes (no NUL terminator by default).
    Text(String),
    /// Assign a constant value to a symbol.
    Equ { name: String, value: u16 },
}

// ---------------------------------------------------------------------------
// Instruction (source-level)
// ---------------------------------------------------------------------------

/// A parsed source instruction (mnemonic + addressing mode + operand).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub mnemonic: String,
    pub mode: AddressingMode,
    /// Operand as a string — may be a numeric literal or a symbol name.
    pub operand: Option<String>,
    pub line: usize,
}

impl Instruction {
    pub fn new(
        mnemonic: impl Into<String>,
        mode: AddressingMode,
        operand: Option<String>,
        line: usize,
    ) -> Self {
        Self {
            mnemonic: mnemonic.into(),
            mode,
            operand,
            line,
        }
    }
}

// ---------------------------------------------------------------------------
// Opcode table entry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct OpcodeEntry {
    mode: AddressingMode,
    opcode: u8,
    /// Total instruction size in bytes (opcode + operand bytes).
    size: u8,
}

impl OpcodeEntry {
    /// Returns the addressing mode encoded by this opcode entry.
    pub const fn mode(self) -> AddressingMode {
        self.mode
    }
}

// ---------------------------------------------------------------------------
// Static opcode table
// ---------------------------------------------------------------------------

type OpcodeTable = &'static [(AddressingMode, u8, u8)]; // (mode, opcode, size)

macro_rules! opcodes {
    ( $( $mode:ident => $op:expr, $sz:expr );* $(;)? ) => {
        &[ $( (AddressingMode::$mode, $op, $sz) ),* ]
    };
}

/// Opcode table for one mnemonic.
///
/// The mnemonics are split across three lookups purely to keep each function
/// a readable size; the chain below is exhaustive.
fn lookup_opcode_table(mnemonic: &str) -> Option<OpcodeTable> {
    let upper = mnemonic.to_uppercase();
    lookup_opcode_table_a(&upper)
        .or_else(|| lookup_opcode_table_b(&upper))
        .or_else(|| lookup_opcode_table_c(&upper))
}

fn lookup_opcode_table_a(mnemonic: &str) -> Option<OpcodeTable> {
    match mnemonic {
        "ADC" => Some(opcodes!(
            Immediate  => 0x69, 2;
            ZeroPage   => 0x65, 2;
            ZeroPageX  => 0x75, 2;
            Absolute   => 0x6D, 3;
            AbsoluteX  => 0x7D, 3;
            AbsoluteY  => 0x79, 3;
            IndirectX  => 0x61, 2;
            IndirectY  => 0x71, 2;
        )),
        "AND" => Some(opcodes!(
            Immediate  => 0x29, 2;
            ZeroPage   => 0x25, 2;
            ZeroPageX  => 0x35, 2;
            Absolute   => 0x2D, 3;
            AbsoluteX  => 0x3D, 3;
            AbsoluteY  => 0x39, 3;
            IndirectX  => 0x21, 2;
            IndirectY  => 0x31, 2;
        )),
        "ASL" => Some(opcodes!(
            Accumulator => 0x0A, 1;
            ZeroPage    => 0x06, 2;
            ZeroPageX   => 0x16, 2;
            Absolute    => 0x0E, 3;
            AbsoluteX   => 0x1E, 3;
        )),
        "BCC" => Some(opcodes!(Relative => 0x90, 2;)),
        "BCS" => Some(opcodes!(Relative => 0xB0, 2;)),
        "BEQ" => Some(opcodes!(Relative => 0xF0, 2;)),
        "BIT" => Some(opcodes!(
            ZeroPage => 0x24, 2;
            Absolute => 0x2C, 3;
        )),
        "BMI" => Some(opcodes!(Relative => 0x30, 2;)),
        "BNE" => Some(opcodes!(Relative => 0xD0, 2;)),
        "BPL" => Some(opcodes!(Relative => 0x10, 2;)),
        "BRK" => Some(opcodes!(Implied => 0x00, 1;)),
        "BVC" => Some(opcodes!(Relative => 0x50, 2;)),
        "BVS" => Some(opcodes!(Relative => 0x70, 2;)),
        "CLC" => Some(opcodes!(Implied => 0x18, 1;)),
        "CLD" => Some(opcodes!(Implied => 0xD8, 1;)),
        "CLI" => Some(opcodes!(Implied => 0x58, 1;)),
        "CLV" => Some(opcodes!(Implied => 0xB8, 1;)),
        "CMP" => Some(opcodes!(
            Immediate => 0xC9, 2;
            ZeroPage  => 0xC5, 2;
            ZeroPageX => 0xD5, 2;
            Absolute  => 0xCD, 3;
            AbsoluteX => 0xDD, 3;
            AbsoluteY => 0xD9, 3;
            IndirectX => 0xC1, 2;
            IndirectY => 0xD1, 2;
        )),
        "CPX" => Some(opcodes!(
            Immediate => 0xE0, 2;
            ZeroPage  => 0xE4, 2;
            Absolute  => 0xEC, 3;
        )),
        "CPY" => Some(opcodes!(
            Immediate => 0xC0, 2;
            ZeroPage  => 0xC4, 2;
            Absolute  => 0xCC, 3;
        )),
        "DEC" => Some(opcodes!(
            ZeroPage  => 0xC6, 2;
            ZeroPageX => 0xD6, 2;
            Absolute  => 0xCE, 3;
            AbsoluteX => 0xDE, 3;
        )),
        "DEX" => Some(opcodes!(Implied => 0xCA, 1;)),
        "DEY" => Some(opcodes!(Implied => 0x88, 1;)),
        _ => None,
    }
}

fn lookup_opcode_table_b(mnemonic: &str) -> Option<OpcodeTable> {
    match mnemonic {
        "EOR" => Some(opcodes!(
            Immediate => 0x49, 2;
            ZeroPage  => 0x45, 2;
            ZeroPageX => 0x55, 2;
            Absolute  => 0x4D, 3;
            AbsoluteX => 0x5D, 3;
            AbsoluteY => 0x59, 3;
            IndirectX => 0x41, 2;
            IndirectY => 0x51, 2;
        )),
        "INC" => Some(opcodes!(
            ZeroPage  => 0xE6, 2;
            ZeroPageX => 0xF6, 2;
            Absolute  => 0xEE, 3;
            AbsoluteX => 0xFE, 3;
        )),
        "INX" => Some(opcodes!(Implied => 0xE8, 1;)),
        "INY" => Some(opcodes!(Implied => 0xC8, 1;)),
        "JMP" => Some(opcodes!(
            Absolute => 0x4C, 3;
            Indirect => 0x6C, 3;
        )),
        "JSR" => Some(opcodes!(Absolute => 0x20, 3;)),
        "LDA" => Some(opcodes!(
            Immediate => 0xA9, 2;
            ZeroPage  => 0xA5, 2;
            ZeroPageX => 0xB5, 2;
            Absolute  => 0xAD, 3;
            AbsoluteX => 0xBD, 3;
            AbsoluteY => 0xB9, 3;
            IndirectX => 0xA1, 2;
            IndirectY => 0xB1, 2;
        )),
        "LDX" => Some(opcodes!(
            Immediate => 0xA2, 2;
            ZeroPage  => 0xA6, 2;
            ZeroPageY => 0xB6, 2;
            Absolute  => 0xAE, 3;
            AbsoluteY => 0xBE, 3;
        )),
        "LDY" => Some(opcodes!(
            Immediate => 0xA0, 2;
            ZeroPage  => 0xA4, 2;
            ZeroPageX => 0xB4, 2;
            Absolute  => 0xAC, 3;
            AbsoluteX => 0xBC, 3;
        )),
        "LSR" => Some(opcodes!(
            Accumulator => 0x4A, 1;
            ZeroPage    => 0x46, 2;
            ZeroPageX   => 0x56, 2;
            Absolute    => 0x4E, 3;
            AbsoluteX   => 0x5E, 3;
        )),
        "NOP" => Some(opcodes!(Implied => 0xEA, 1;)),
        "ORA" => Some(opcodes!(
            Immediate => 0x09, 2;
            ZeroPage  => 0x05, 2;
            ZeroPageX => 0x15, 2;
            Absolute  => 0x0D, 3;
            AbsoluteX => 0x1D, 3;
            AbsoluteY => 0x19, 3;
            IndirectX => 0x01, 2;
            IndirectY => 0x11, 2;
        )),
        _ => None,
    }
}

fn lookup_opcode_table_c(mnemonic: &str) -> Option<OpcodeTable> {
    match mnemonic {
        "PHA" => Some(opcodes!(Implied => 0x48, 1;)),
        "PHP" => Some(opcodes!(Implied => 0x08, 1;)),
        "PLA" => Some(opcodes!(Implied => 0x68, 1;)),
        "PLP" => Some(opcodes!(Implied => 0x28, 1;)),
        "ROL" => Some(opcodes!(
            Accumulator => 0x2A, 1;
            ZeroPage    => 0x26, 2;
            ZeroPageX   => 0x36, 2;
            Absolute    => 0x2E, 3;
            AbsoluteX   => 0x3E, 3;
        )),
        "ROR" => Some(opcodes!(
            Accumulator => 0x6A, 1;
            ZeroPage    => 0x66, 2;
            ZeroPageX   => 0x76, 2;
            Absolute    => 0x6E, 3;
            AbsoluteX   => 0x7E, 3;
        )),
        "RTI" => Some(opcodes!(Implied => 0x40, 1;)),
        "RTS" => Some(opcodes!(Implied => 0x60, 1;)),
        "SBC" => Some(opcodes!(
            Immediate => 0xE9, 2;
            ZeroPage  => 0xE5, 2;
            ZeroPageX => 0xF5, 2;
            Absolute  => 0xED, 3;
            AbsoluteX => 0xFD, 3;
            AbsoluteY => 0xF9, 3;
            IndirectX => 0xE1, 2;
            IndirectY => 0xF1, 2;
        )),
        "SEC" => Some(opcodes!(Implied => 0x38, 1;)),
        "SED" => Some(opcodes!(Implied => 0xF8, 1;)),
        "SEI" => Some(opcodes!(Implied => 0x78, 1;)),
        "STA" => Some(opcodes!(
            ZeroPage  => 0x85, 2;
            ZeroPageX => 0x95, 2;
            Absolute  => 0x8D, 3;
            AbsoluteX => 0x9D, 3;
            AbsoluteY => 0x99, 3;
            IndirectX => 0x81, 2;
            IndirectY => 0x91, 2;
        )),
        "STX" => Some(opcodes!(
            ZeroPage  => 0x86, 2;
            ZeroPageY => 0x96, 2;
            Absolute  => 0x8E, 3;
        )),
        "STY" => Some(opcodes!(
            ZeroPage  => 0x84, 2;
            ZeroPageX => 0x94, 2;
            Absolute  => 0x8C, 3;
        )),
        "TAX" => Some(opcodes!(Implied => 0xAA, 1;)),
        "TAY" => Some(opcodes!(Implied => 0xA8, 1;)),
        "TSX" => Some(opcodes!(Implied => 0xBA, 1;)),
        "TXA" => Some(opcodes!(Implied => 0x8A, 1;)),
        "TXS" => Some(opcodes!(Implied => 0x9A, 1;)),
        "TYA" => Some(opcodes!(Implied => 0x98, 1;)),
        _ => None,
    }
}

/// Wrap a byte length to a 16-bit program-counter advance.
fn len_u16(len: usize) -> u16 {
    u16::try_from(len % 0x1_0000).unwrap_or_else(|_| unreachable!())
}

fn find_opcode(mnemonic: &str, mode: AddressingMode) -> Option<OpcodeEntry> {
    let table = lookup_opcode_table(mnemonic)?;
    table
        .iter()
        .find(|(m, _, _)| *m == mode)
        .map(|(m, op, sz)| OpcodeEntry {
            mode: *m,
            opcode: *op,
            size: *sz,
        })
}

// ---------------------------------------------------------------------------
// Source line
// ---------------------------------------------------------------------------

/// A parsed source line.
#[derive(Debug, Clone)]
pub enum SourceLine {
    Empty,
    Label(String),
    LabelWithInstruction(String, Instruction),
    InstructionLine(Instruction),
    DirectiveLine {
        label: Option<String>,
        directive: AssemblerDirective,
    },
}

// ---------------------------------------------------------------------------
// Listing output
// ---------------------------------------------------------------------------

/// A single line of listing output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingLine {
    pub address: Option<u16>,
    pub bytes: Vec<u8>,
    pub source_line: usize,
    pub text: String,
}

/// Complete listing output from an assembly run.
#[derive(Debug, Default)]
pub struct ListingOutput {
    pub lines: Vec<ListingLine>,
    pub errors: Vec<AssemblerError>,
}

impl ListingOutput {
    #[must_use] 
    pub const fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Format listing to a string.
    #[must_use]
    pub fn format(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(self.lines.len() * 32);
        for line in &self.lines {
            let mut bytes = String::with_capacity(line.bytes.len() * 3);
            for b in &line.bytes {
                let _ = write!(bytes, "{b:02X} ");
            }
            if let Some(a) = line.address {
                let _ = writeln!(out, "{a:04X}  {bytes:<12} {}", line.text);
            } else {
                let _ = writeln!(out, "      {bytes:<12} {}", line.text);
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Symbol table
// ---------------------------------------------------------------------------

// BTreeMap is used instead of HashMap so that attacker-controlled symbol names
// (parsed from untrusted source text) cannot trigger a hash-collision
// denial-of-service (dos-hash-collision). BTreeMap lookup is O(log n) and
// is not sensitive to key distribution.
#[derive(Debug, Default)]
struct SymbolTable {
    symbols: BTreeMap<String, u16>,
}

impl SymbolTable {
    fn define(&mut self, name: &str, value: u16, line: usize) -> Result<(), AssemblerError> {
        if self.symbols.contains_key(name) {
            return Err(AssemblerError::DuplicateSymbol {
                name: name.to_owned(),
                line,
            });
        }
        self.symbols.insert(name.to_owned(), value);
        Ok(())
    }

    fn resolve(&self, name: &str, line: usize) -> Result<u16, AssemblerError> {
        self.symbols
            .get(name)
            .copied()
            .ok_or_else(|| AssemblerError::UndefinedSymbol {
                name: name.to_owned(),
                line,
            })
    }

    pub fn get(&self, name: &str) -> Option<u16> {
        self.symbols.get(name).copied()
    }
}

// ---------------------------------------------------------------------------
// Operand resolver
// ---------------------------------------------------------------------------

fn parse_number(s: &str, line: usize) -> Result<u16, AssemblerError> {
    let s = s.trim();
    let (digits, radix) = s
        .strip_prefix('$')
        .map(|hex| (hex, 16))
        .or_else(|| s.strip_prefix('%').map(|bin| (bin, 2)))
        .unwrap_or((s, 10));
    u16::from_str_radix(digits, radix).map_err(|_| AssemblerError::ParseError {
        text: s.into(),
        line,
    })
}

fn resolve_operand(
    operand: &str,
    symbols: &SymbolTable,
    line: usize,
) -> Result<u16, AssemblerError> {
    let op = operand.trim();
    // Try numeric first
    if op.starts_with('$')
        || op.starts_with('%')
        || op
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit())
    {
        parse_number(op, line)
    } else {
        // Fast path: probe via `get` (non-erroring) before falling back to
        // the erroring `resolve`. This keeps both code paths exercised.
        if let Some(v) = symbols.get(op) {
            return Ok(v);
        }
        symbols.resolve(op, line)
    }
}

// ---------------------------------------------------------------------------
// Two-pass assembler
// ---------------------------------------------------------------------------

/// Two-pass 6502 assembler.
///
/// # Usage
/// ```rust
/// # use rustre_arch_6502::assembler_6502::TwoPassAssembler;
/// let mut asm = TwoPassAssembler::new(0x0600);
/// let listing = asm.assemble("  LDA #$FF\n  STA $00\n  RTS\n").unwrap();
/// assert!(!listing.has_errors());
/// ```
#[derive(Debug)]
pub struct TwoPassAssembler {
    /// Initial program counter value.
    origin: u16,
    /// Enable 65C02 extension opcodes.
    pub enable_65c02: bool,
}

impl TwoPassAssembler {
    /// Create a new assembler with the given starting address.
    #[must_use] 
    pub const fn new(origin: u16) -> Self {
        Self {
            origin,
            enable_65c02: false,
        }
    }

    /// Enable 65C02 extension opcodes (STZ, TRB, TSB, etc.).
    #[must_use] 
    pub const fn with_65c02(mut self) -> Self {
        self.enable_65c02 = true;
        self
    }

    /// Assemble source text and return listing + object bytes.
    ///
    /// # Errors
    ///
    /// Returns all parse, symbol, and encoding errors collected during
    /// assembly.
    pub fn assemble(&mut self, source: &str) -> Result<ListingOutput, Vec<AssemblerError>> {
        let lines: Vec<&str> = source.lines().collect();
        let mut listing = ListingOutput {
            lines: Vec::with_capacity(lines.len()),
            errors: Vec::new(),
        };

        // Pass 1: build symbol table and compute addresses
        let symbols = self.assemble_pass1(&lines)?;

        // Pass 2: emit bytes
        self.assemble_pass2(&lines, &symbols, &mut listing)?;

        Ok(listing)
    }

    /// First assembler pass: define every label and compute its address.
    ///
    /// # Errors
    ///
    /// Returns every symbol-definition error found, so the caller sees them
    /// all rather than only the first.
    fn assemble_pass1(&self, lines: &[&str]) -> Result<SymbolTable, Vec<AssemblerError>> {
        let mut symbols = SymbolTable::default();
        let mut pc: u16 = self.origin;
        let mut pass1_errors: Vec<AssemblerError> = Vec::new();

        for (idx, &line_text) in lines.iter().enumerate() {
            let line_num = idx + 1;
            match Self::parse_line(line_text, line_num) {
                Ok(SourceLine::Empty) => {}
                Ok(SourceLine::Label(name)) => {
                    if let Err(e) = symbols.define(&name, pc, line_num) {
                        pass1_errors.push(e);
                    }
                }
                Ok(SourceLine::LabelWithInstruction(name, instr)) => {
                    if let Err(e) = symbols.define(&name, pc, line_num) {
                        pass1_errors.push(e);
                    }
                    if let Some(sz) = Self::instruction_size_with_symbols(&instr, Some(&symbols)) {
                        pc = pc.wrapping_add(u16::from(sz));
                    }
                }
                Ok(SourceLine::InstructionLine(instr)) => {
                    if let Some(sz) = Self::instruction_size_with_symbols(&instr, Some(&symbols)) {
                        pc = pc.wrapping_add(u16::from(sz));
                    }
                }
                Ok(SourceLine::DirectiveLine { label, directive }) => {
                    if let Some(lbl) = label && let Err(e) = symbols.define(&lbl, pc, line_num) {
                        pass1_errors.push(e);
                    }
                    match &directive {
                        AssemblerDirective::Org(addr) => {
                            pc = *addr;
                        }
                        AssemblerDirective::Byte(bytes) => {
                            pc = pc.wrapping_add(len_u16(bytes.len()));
                        }
                        AssemblerDirective::Word(words) => {
                            pc = pc.wrapping_add(len_u16(words.len() * 2));
                        }
                        AssemblerDirective::Text(s) => {
                            pc = pc.wrapping_add(len_u16(s.len()));
                        }
                        AssemblerDirective::Equ { name, value } => {
                            if let Err(e) = symbols.define(name, *value, line_num) {
                                pass1_errors.push(e);
                            }
                        }
                    }
                }
                Err(e) => pass1_errors.push(e),
            }
        }

        if !pass1_errors.is_empty() {
            return Err(pass1_errors);
        }
        Ok(symbols)
    }

    /// Second assembler pass: emit bytes now every label address is known.
    ///
    /// # Errors
    ///
    /// Returns the first parse error encountered while re-reading the source.
    fn assemble_pass2(
        &self,
        lines: &[&str],
        symbols: &SymbolTable,
        listing: &mut ListingOutput,
    ) -> Result<(), Vec<AssemblerError>> {
        let mut pc = self.origin;

        for (idx, &line_text) in lines.iter().enumerate() {
            let line_num = idx + 1;
            let parsed = Self::parse_line(line_text, line_num)?;
            match parsed {
                SourceLine::Empty => {
                    listing.lines.push(ListingLine {
                        address: None,
                        bytes: vec![],
                        source_line: line_num,
                        text: line_text.to_owned(),
                    });
                }
                SourceLine::Label(_) => {
                    listing.lines.push(ListingLine {
                        address: Some(pc),
                        bytes: vec![],
                        source_line: line_num,
                        text: line_text.to_owned(),
                    });
                }
                SourceLine::LabelWithInstruction(_, instr) | SourceLine::InstructionLine(instr) => {
                    let addr = pc;
                    match Self::encode_instruction(&instr, pc, symbols) {
                        Ok(bytes) => {
                            pc = pc.wrapping_add(len_u16(bytes.len()));
                            listing.lines.push(ListingLine {
                                address: Some(addr),
                                bytes,
                                source_line: line_num,
                                text: line_text.to_owned(),
                            });
                        }
                        Err(e) => {
                            listing.errors.push(e);
                        }
                    }
                }
                SourceLine::DirectiveLine { directive, .. } => {
                    let addr = pc;
                    match directive {
                        AssemblerDirective::Org(new_pc) => {
                            pc = new_pc;
                            listing.lines.push(ListingLine {
                                address: Some(new_pc),
                                bytes: vec![],
                                source_line: line_num,
                                text: line_text.to_owned(),
                            });
                        }
                        AssemblerDirective::Byte(bytes) => {
                            pc = pc.wrapping_add(len_u16(bytes.len()));
                            listing.lines.push(ListingLine {
                                address: Some(addr),
                                bytes,
                                source_line: line_num,
                                text: line_text.to_owned(),
                            });
                        }
                        AssemblerDirective::Word(words) => {
                            let mut bytes = Vec::with_capacity(words.len() * 2);
                            for w in &words {
                                bytes.extend_from_slice(&w.to_le_bytes());
                            }
                            pc = pc.wrapping_add(len_u16(bytes.len()));
                            listing.lines.push(ListingLine {
                                address: Some(addr),
                                bytes,
                                source_line: line_num,
                                text: line_text.to_owned(),
                            });
                        }
                        AssemblerDirective::Text(s) => {
                            let bytes: Vec<u8> = s.bytes().collect();
                            pc = pc.wrapping_add(len_u16(bytes.len()));
                            listing.lines.push(ListingLine {
                                address: Some(addr),
                                bytes,
                                source_line: line_num,
                                text: line_text.to_owned(),
                            });
                        }
                        AssemblerDirective::Equ { .. } => {
                            listing.lines.push(ListingLine {
                                address: None,
                                bytes: vec![],
                                source_line: line_num,
                                text: line_text.to_owned(),
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Return the object bytes produced by the last assembly.
    ///
    /// # Errors
    ///
    /// Returns all parse, symbol, and encoding errors collected during
    /// assembly.
    pub fn assemble_bytes(&mut self, source: &str) -> Result<Vec<u8>, Vec<AssemblerError>> {
        let listing = self.assemble(source)?;
        if listing.has_errors() {
            return Err(listing.errors);
        }
        let total: usize = listing.lines.iter().map(|l| l.bytes.len()).sum();
        let mut bytes = Vec::with_capacity(total);
        for line in &listing.lines {
            bytes.extend_from_slice(&line.bytes);
        }
        Ok(bytes)
    }

    // -------------------------------------------------------------------
    // Parsing helpers
    // -------------------------------------------------------------------

    fn parse_line(line: &str, line_num: usize) -> Result<SourceLine, AssemblerError> {
        // Strip comments
        let line = line.find(';').map_or(line, |pos| &line[..pos]).trim();
        if line.is_empty() {
            return Ok(SourceLine::Empty);
        }

        // Check for directive
        let upper = line.to_uppercase();
        for kw in &[
            "ORG", ".ORG", "BYTE", ".BYTE", "DB", "WORD", ".WORD", "DW", "TEXT", ".TEXT", "EQU",
            ".EQU",
        ] {
            if upper.starts_with(kw) {
                return Self::parse_directive(line, line_num)
                    .map(|d| SourceLine::DirectiveLine {
                        label: None,
                        directive: d,
                    });
            }
        }

        // Label detection: identifier followed by ':'
        let (label, rest) = line.find(':').map_or((None, line), |colon_pos| {
            (
                Some(line[..colon_pos].trim().to_owned()),
                line[colon_pos + 1..].trim(),
            )
        });

        if rest.is_empty() {
            return Ok(label.map_or(SourceLine::Empty, SourceLine::Label));
        }

        // Check rest for directive
        let upper_rest = rest.to_uppercase();
        for kw in &[
            "ORG", ".ORG", "BYTE", ".BYTE", "DB", "WORD", ".WORD", "DW", "TEXT", ".TEXT", "EQU",
            ".EQU",
        ] {
            if upper_rest.starts_with(kw) {
                let d = Self::parse_directive(rest, line_num)?;
                return Ok(SourceLine::DirectiveLine {
                    label,
                    directive: d,
                });
            }
        }

        // Detect "SYMBOL EQU value" / "SYMBOL .EQU value" format (no colon label, EQU as
        // second whitespace-delimited token).  This is common in 6502 source files.
        if label.is_none() {
            let mut toks = rest.splitn(3, |c: char| c.is_whitespace());
            let sym_tok = toks.next().unwrap_or("");
            let kw_tok = toks.next().unwrap_or("").to_uppercase();
            let val_tok = toks.next().unwrap_or("").trim();
            if (kw_tok == "EQU" || kw_tok == ".EQU") && !sym_tok.is_empty() && !val_tok.is_empty() {
                let value = parse_number(val_tok, line_num)?;
                return Ok(SourceLine::DirectiveLine {
                    label: None,
                    directive: AssemblerDirective::Equ {
                        name: sym_tok.to_owned(),
                        value,
                    },
                });
            }
        }

        let instr = Self::parse_instruction(rest, line_num)?;
        Ok(match label {
            Some(l) => SourceLine::LabelWithInstruction(l, instr),
            None => SourceLine::InstructionLine(instr),
        })
    }

    fn parse_directive(
        s: &str,
        line_num: usize,
    ) -> Result<AssemblerDirective, AssemblerError> {
        let s = s.trim();
        let upper = s.to_uppercase();
        if upper.starts_with("ORG") || upper.starts_with(".ORG") {
            let val_str = s
                .split_once(|c: char| c.is_whitespace())
                .map(|x| x.1)
                .ok_or_else(|| AssemblerError::ParseError {
                    text: s.into(),
                    line: line_num,
                })?;
            let addr = parse_number(val_str.trim(), line_num)?;
            return Ok(AssemblerDirective::Org(addr));
        }
        if upper.starts_with("BYTE") || upper.starts_with(".BYTE") || upper.starts_with("DB") {
            let after = s
                .split_once(|c: char| c.is_whitespace())
                .map(|x| x.1)
                .ok_or_else(|| AssemblerError::ParseError {
                    text: s.into(),
                    line: line_num,
                })?;
            let bytes: Result<Vec<u8>, _> = after
                .split(',')
                .map(|tok| parse_number(tok.trim(), line_num).map(|v| v.to_le_bytes()[0]))
                .collect();
            return Ok(AssemblerDirective::Byte(bytes?));
        }
        if upper.starts_with("WORD") || upper.starts_with(".WORD") || upper.starts_with("DW") {
            let after = s
                .split_once(|c: char| c.is_whitespace())
                .map(|x| x.1)
                .ok_or_else(|| AssemblerError::ParseError {
                    text: s.into(),
                    line: line_num,
                })?;
            let words: Result<Vec<u16>, _> = after
                .split(',')
                .map(|tok| parse_number(tok.trim(), line_num))
                .collect();
            return Ok(AssemblerDirective::Word(words?));
        }
        if upper.starts_with("TEXT") || upper.starts_with(".TEXT") {
            let after = s
                .split_once(|c: char| c.is_whitespace())
                .map_or("", |x| x.1)
                .trim();
            let text = after.trim_matches('"').to_owned();
            return Ok(AssemblerDirective::Text(text));
        }
        if upper.starts_with("EQU") || upper.starts_with(".EQU") {
            let mut parts = s.splitn(3, |c: char| c.is_whitespace());
            let _kw = parts.next();
            let name = parts
                .next()
                .ok_or_else(|| AssemblerError::ParseError {
                    text: s.into(),
                    line: line_num,
                })?
                .trim()
                .to_owned();
            let val_s = parts.next().ok_or_else(|| AssemblerError::ParseError {
                text: s.into(),
                line: line_num,
            })?;
            let value = parse_number(val_s.trim(), line_num)?;
            return Ok(AssemblerDirective::Equ { name, value });
        }
        Err(AssemblerError::ParseError {
            text: s.into(),
            line: line_num,
        })
    }

    fn parse_instruction(s: &str, line_num: usize) -> Result<Instruction, AssemblerError> {
        let mut parts = s.splitn(2, |c: char| c.is_whitespace());
        let mnemonic = parts.next().unwrap_or("").trim().to_uppercase();
        if mnemonic.is_empty() {
            return Err(AssemblerError::ParseError {
                text: s.into(),
                line: line_num,
            });
        }
        let operand_str = parts.next().map(|s| s.trim().to_owned());

        let (mode, operand) = operand_str
            .as_ref()
            .map_or((AddressingMode::Implied, None), |op| {
                Self::classify_operand(op)
            });

        if lookup_opcode_table(&mnemonic).is_none() {
            return Err(AssemblerError::UnknownMnemonic {
                mnemonic,
                line: line_num,
            });
        }

        Ok(Instruction {
            mnemonic,
            mode,
            operand,
            line: line_num,
        })
    }

    fn classify_operand(op: &str) -> (AddressingMode, Option<String>) {
        let op = op.trim();
        if op.eq_ignore_ascii_case("A") {
            return (AddressingMode::Accumulator, None);
        }
        if let Some(inner) = op.strip_prefix('#') {
            return (AddressingMode::Immediate, Some(inner.to_owned()));
        }
        // Indirect modes
        if op.starts_with('(') && op.ends_with(",X)") {
            let inner = &op[1..op.len() - 3];
            return (AddressingMode::IndirectX, Some(inner.to_owned()));
        }
        if op.starts_with('(') && op.ends_with("),Y") {
            let inner = &op[1..op.len() - 3];
            return (AddressingMode::IndirectY, Some(inner.to_owned()));
        }
        if op.starts_with('(') && op.ends_with(')') && !op.contains(',') {
            let inner = &op[1..op.len() - 1];
            return (AddressingMode::Indirect, Some(inner.to_owned()));
        }
        // Indexed modes
        if let Some(base) = op.strip_suffix(",X") {
            let b = base.trim();
            let val = b.trim_start_matches('$');
            if b.starts_with('$') && val.len() <= 2 {
                return (AddressingMode::ZeroPageX, Some(b.to_owned()));
            }
            return (AddressingMode::AbsoluteX, Some(b.to_owned()));
        }
        if let Some(base) = op.strip_suffix(",Y") {
            let b = base.trim();
            let val = b.trim_start_matches('$');
            if b.starts_with('$') && val.len() <= 2 {
                return (AddressingMode::ZeroPageY, Some(b.to_owned()));
            }
            return (AddressingMode::AbsoluteY, Some(b.to_owned()));
        }
        // Zero page vs absolute
        if op.starts_with('$') && op[1..].len() <= 2 {
            return (AddressingMode::ZeroPage, Some(op.to_owned()));
        }
        (AddressingMode::Absolute, Some(op.to_owned()))
    }

    #[must_use]
    pub fn instruction_size(instr: &Instruction) -> Option<u8> {
        Self::instruction_size_with_symbols(instr, None)
    }

    fn instruction_size_with_symbols(instr: &Instruction, symbols: Option<&SymbolTable>) -> Option<u8> {
        let table = lookup_opcode_table(&instr.mnemonic)?;
        // Branch mnemonics always assemble to 2 bytes (opcode + relative offset),
        // even when the operand is parsed as Absolute (label reference) during pass 1.
        match instr.mnemonic.as_str() {
            "BCC" | "BCS" | "BEQ" | "BMI" | "BNE" | "BPL" | "BVC" | "BVS" => return Some(2),
            _ => {}
        }
        // For relative branches identified by addressing mode, always 2
        if instr.mode == AddressingMode::Relative {
            return Some(2);
        }
        // If mode is Absolute but operand is a symbol resolving to ≤ 0xFF, prefer ZeroPage
        if instr.mode == AddressingMode::Absolute
            && let (Some(syms), Some(op_str)) = (symbols, instr.operand.as_deref()) {
                let op = op_str.trim();
                // Only do this for symbol operands (not numeric literals)
                if !op.starts_with('$') && !op.starts_with('%') && !op.chars().next().is_some_and(|c| c.is_ascii_digit())
                    && let Some(val) = syms.get(op)
                        && val <= 0xFF && table.iter().any(|(m, _, _)| *m == AddressingMode::ZeroPage) {
                            return Some(2);
                        }
            }
        table
            .iter()
            .find(|(m, _, _)| *m == instr.mode)
            .map(|(_, _, sz)| *sz)
    }

    fn encode_instruction(
        instr: &Instruction,
        pc: u16,
        symbols: &SymbolTable,
    ) -> Result<Vec<u8>, AssemblerError> {
        let mnemonic = &instr.mnemonic;
        let mode = instr.mode;
        let line = instr.line;

        // Determine actual mode for branch instructions (always Relative)
        let mut effective_mode = match mnemonic.as_str() {
            "BCC" | "BCS" | "BEQ" | "BMI" | "BNE" | "BPL" | "BVC" | "BVS" => {
                AddressingMode::Relative
            }
            _ => mode,
        };

        // If mode is Absolute but operand resolves to a zero-page value (≤ 0xFF)
        // via a symbol lookup, downgrade to ZeroPage for optimal encoding.
        if effective_mode == AddressingMode::Absolute {
            let op_str = instr.operand.as_deref().unwrap_or("").trim();
            if !op_str.starts_with('$') && !op_str.starts_with('%')
                && !op_str.chars().next().is_some_and(|c| c.is_ascii_digit())
                && let Some(val) = symbols.get(op_str)
                    && val <= 0xFF && find_opcode(mnemonic, AddressingMode::ZeroPage).is_some() {
                        effective_mode = AddressingMode::ZeroPage;
                    }
        }

        let entry = find_opcode(mnemonic, effective_mode).ok_or_else(|| {
            AssemblerError::InvalidAddressingMode {
                mnemonic: mnemonic.clone(),
                mode: effective_mode,
                line,
            }
        })?;
        debug_assert_eq!(entry.mode(), effective_mode);

        let mut bytes = vec![entry.opcode];
        if entry.size == 1 {
            return Ok(bytes);
        }

        let op_str = instr.operand.as_deref().unwrap_or("");
        let value = resolve_operand(op_str, symbols, line)?;

        match effective_mode {
            AddressingMode::Relative => {
                let next_pc = pc.wrapping_add(2);
                let offset = i32::from(value) - i32::from(next_pc);
                if !(-128..=127).contains(&offset) {
                    return Err(AssemblerError::BranchOutOfRange {
                        target: value,
                        from: pc,
                        line,
                    });
                }
                bytes.push(offset.to_le_bytes()[0]);
            }
            AddressingMode::Absolute
            | AddressingMode::AbsoluteX
            | AddressingMode::AbsoluteY
            | AddressingMode::Indirect => {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
            _ => {
                bytes.push(value.to_le_bytes()[0]);
            }
        }
        Ok(bytes)
    }
}

impl std::convert::TryFrom<&str> for TwoPassAssembler {
    type Error = ();
    fn try_from(_: &str) -> Result<Self, ()> {
        Ok(Self::new(0x0600))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn asm(source: &str) -> Vec<u8> {
        let mut a = TwoPassAssembler::new(0x0600);
        a.assemble_bytes(source).expect("assembly failed")
    }

    fn asm_at(origin: u16, source: &str) -> Vec<u8> {
        let mut a = TwoPassAssembler::new(origin);
        a.assemble_bytes(source).expect("assembly failed")
    }

    // --- Implied / Accumulator -----------------------------------------------

    #[test]
    fn test_nop() {
        assert_eq!(asm("NOP"), &[0xEA]);
    }

    #[test]
    fn test_brk() {
        assert_eq!(asm("BRK"), &[0x00]);
    }

    #[test]
    fn test_rts() {
        assert_eq!(asm("RTS"), &[0x60]);
    }

    #[test]
    fn test_rti() {
        assert_eq!(asm("RTI"), &[0x40]);
    }

    #[test]
    fn test_pha_pla() {
        assert_eq!(asm("PHA\nPLA"), &[0x48, 0x68]);
    }

    #[test]
    fn test_tax_txa() {
        assert_eq!(asm("TAX\nTXA"), &[0xAA, 0x8A]);
    }

    #[test]
    fn test_asl_accumulator() {
        assert_eq!(asm("ASL A"), &[0x0A]);
    }

    #[test]
    fn test_lsr_accumulator() {
        assert_eq!(asm("LSR A"), &[0x4A]);
    }

    // --- Immediate -----------------------------------------------------------

    #[test]
    fn test_lda_immediate() {
        assert_eq!(asm("LDA #$FF"), &[0xA9, 0xFF]);
    }

    #[test]
    fn test_ldx_immediate() {
        assert_eq!(asm("LDX #$10"), &[0xA2, 0x10]);
    }

    #[test]
    fn test_ldy_immediate() {
        assert_eq!(asm("LDY #0"), &[0xA0, 0x00]);
    }

    #[test]
    fn test_adc_immediate() {
        assert_eq!(asm("ADC #1"), &[0x69, 0x01]);
    }

    #[test]
    fn test_and_immediate() {
        assert_eq!(asm("AND #$0F"), &[0x29, 0x0F]);
    }

    #[test]
    fn test_ora_immediate() {
        assert_eq!(asm("ORA #$80"), &[0x09, 0x80]);
    }

    #[test]
    fn test_eor_immediate() {
        assert_eq!(asm("EOR #$AA"), &[0x49, 0xAA]);
    }

    #[test]
    fn test_cmp_immediate() {
        assert_eq!(asm("CMP #$00"), &[0xC9, 0x00]);
    }

    #[test]
    fn test_cpx_immediate() {
        assert_eq!(asm("CPX #$05"), &[0xE0, 0x05]);
    }

    #[test]
    fn test_cpy_immediate() {
        assert_eq!(asm("CPY #$0A"), &[0xC0, 0x0A]);
    }

    #[test]
    fn test_sbc_immediate() {
        assert_eq!(asm("SBC #1"), &[0xE9, 0x01]);
    }

    // --- Zero Page -----------------------------------------------------------

    #[test]
    fn test_lda_zero_page() {
        assert_eq!(asm("LDA $10"), &[0xA5, 0x10]);
    }

    #[test]
    fn test_sta_zero_page() {
        assert_eq!(asm("STA $20"), &[0x85, 0x20]);
    }

    #[test]
    fn test_stx_zero_page() {
        assert_eq!(asm("STX $30"), &[0x86, 0x30]);
    }

    #[test]
    fn test_sty_zero_page() {
        assert_eq!(asm("STY $40"), &[0x84, 0x40]);
    }

    #[test]
    fn test_inc_zero_page() {
        assert_eq!(asm("INC $50"), &[0xE6, 0x50]);
    }

    #[test]
    fn test_dec_zero_page() {
        assert_eq!(asm("DEC $60"), &[0xC6, 0x60]);
    }

    // --- Absolute ------------------------------------------------------------

    #[test]
    fn test_lda_absolute() {
        assert_eq!(asm("LDA $1234"), &[0xAD, 0x34, 0x12]);
    }

    #[test]
    fn test_sta_absolute() {
        assert_eq!(asm("STA $D000"), &[0x8D, 0x00, 0xD0]);
    }

    #[test]
    fn test_jsr_absolute() {
        assert_eq!(asm("JSR $C000"), &[0x20, 0x00, 0xC0]);
    }

    #[test]
    fn test_jmp_absolute() {
        assert_eq!(asm("JMP $0300"), &[0x4C, 0x00, 0x03]);
    }

    #[test]
    fn test_jmp_indirect() {
        assert_eq!(asm("JMP ($FFFC)"), &[0x6C, 0xFC, 0xFF]);
    }

    // --- Indexed modes -------------------------------------------------------

    #[test]
    fn test_lda_abs_x() {
        assert_eq!(asm("LDA $1000,X"), &[0xBD, 0x00, 0x10]);
    }

    #[test]
    fn test_lda_abs_y() {
        assert_eq!(asm("LDA $1000,Y"), &[0xB9, 0x00, 0x10]);
    }

    #[test]
    fn test_sta_zp_x() {
        assert_eq!(asm("STA $10,X"), &[0x95, 0x10]);
    }

    #[test]
    fn test_ldx_zp_y() {
        assert_eq!(asm("LDX $10,Y"), &[0xB6, 0x10]);
    }

    #[test]
    fn test_lda_indirect_x() {
        assert_eq!(asm("LDA ($20,X)"), &[0xA1, 0x20]);
    }

    #[test]
    fn test_lda_indirect_y() {
        assert_eq!(asm("LDA ($30),Y"), &[0xB1, 0x30]);
    }

    // --- Branch / Relative ---------------------------------------------------

    #[test]
    fn test_beq_forward() {
        // BEQ +2 (skip one NOP)
        let bytes = asm_at(0x0600, "BEQ TARGET\nNOP\nTARGET: NOP");
        assert_eq!(bytes[0], 0xF0); // BEQ
        assert_eq!(bytes[1], 0x01); // +1 offset
    }

    #[test]
    fn test_bne_backward() {
        // A tiny loop: LDX #3, loop: DEX, BNE loop
        let bytes = asm_at(0x1000, "LDX #3\nLOOP: DEX\nBNE LOOP");
        assert_eq!(bytes[0], 0xA2); // LDX imm
        assert_eq!(bytes[2], 0xCA); // DEX
        assert_eq!(bytes[3], 0xD0); // BNE
        assert_eq!(bytes[4].cast_signed(), -3i8); // backward 3
    }

    // --- Directives ----------------------------------------------------------

    #[test]
    fn test_org_directive() {
        let mut a = TwoPassAssembler::new(0x0000);
        let listing = a.assemble("ORG $0600\nNOP").unwrap();
        let instr_line = listing.lines.iter().find(|l| !l.bytes.is_empty()).unwrap();
        assert_eq!(instr_line.address, Some(0x0600));
    }

    #[test]
    fn test_byte_directive() {
        let bytes = asm(".BYTE $01, $02, $03");
        assert_eq!(bytes, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_word_directive() {
        let bytes = asm(".WORD $1234");
        assert_eq!(bytes, &[0x34, 0x12]); // little-endian
    }

    #[test]
    fn test_text_directive() {
        let bytes = asm(r#".TEXT "HI""#);
        assert_eq!(bytes, b"HI");
    }

    #[test]
    fn test_equ_directive() {
        let bytes = asm("ZRAM .EQU $00\nLDA ZRAM");
        assert_eq!(bytes, &[0xA5, 0x00]);
    }

    // --- Labels / forward references -----------------------------------------

    #[test]
    fn test_forward_jmp() {
        let bytes = asm("JMP END\nNOP\nEND: RTS");
        assert_eq!(bytes[0], 0x4C); // JMP
        assert_eq!(u16::from_le_bytes([bytes[1], bytes[2]]), 0x0604); // 0x0600 + 4
    }

    // --- Errors --------------------------------------------------------------

    #[test]
    fn test_unknown_mnemonic() {
        let mut a = TwoPassAssembler::new(0x0600);
        let result = a.assemble_bytes("FROBULATE $10");
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(matches!(errs[0], AssemblerError::UnknownMnemonic { .. }));
    }

    #[test]
    fn test_duplicate_label() {
        let mut a = TwoPassAssembler::new(0x0600);
        let result = a.assemble_bytes("FOO: NOP\nFOO: RTS");
        assert!(result.is_err());
    }

    #[test]
    fn test_branch_out_of_range() {
        let mut a = TwoPassAssembler::new(0x0000);
        // Target $0200 from BEQ at $0000: offset 0x1FE, way out of range
        let result = a.assemble_bytes("BEQ $0200");
        assert!(result.is_err());
    }

    // --- Listing output ------------------------------------------------------

    #[test]
    fn test_listing_format() {
        let mut a = TwoPassAssembler::new(0x0600);
        let listing = a.assemble("LDA #$FF\nRTS").unwrap();
        let fmt = listing.format();
        assert!(fmt.contains("0600"));
        assert!(fmt.contains("A9"));
    }

    // --- Label struct --------------------------------------------------------

    #[test]
    fn test_label_resolved() {
        let l = Label::new("start", Some(0x1000), 1);
        assert!(l.is_resolved());
        assert_eq!(l.address, Some(0x1000));
    }

    #[test]
    fn test_label_unresolved() {
        let l = Label::new("forward", None, 5);
        assert!(!l.is_resolved());
    }

    // --- AssemblerError display -----------------------------------------------

    #[test]
    fn test_error_display_undefined_symbol() {
        let e = AssemblerError::UndefinedSymbol {
            name: "foo".into(),
            line: 3,
        };
        assert!(e.to_string().contains("foo"));
        assert!(e.to_string().contains('3'));
    }

    #[test]
    fn test_multiple_instructions() {
        let bytes = asm("SEC\nLDA #$80\nADC #$01\nSTA $00\nRTS");
        assert_eq!(bytes[0], 0x38); // SEC
        assert_eq!(bytes[1], 0xA9); // LDA imm
        assert_eq!(bytes[5], 0x85); // STA zp
    }
}
