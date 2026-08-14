//! Z80 platform-specific knowledge: ZX Spectrum, MSX, CP/M, Game Boy (GB-Z80).
//!
//! Covers port I/O semantics, memory banking, OS call patterns, and the
//! GB-Z80 ISA divergences (no IX/IY, no R, new SWAP/STOP/HALT behaviour).


// ── ZX Spectrum ───────────────────────────────────────────────────────────────

/// ULA port address on the ZX Spectrum (0xFE, lower 8 bits).
pub const SPECTRUM_ULA_PORT: u16 = 0x00FE;

/// Spectrum border colour codes (bits 2:0 of ULA output).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpectrumBorder {
    Black   = 0,
    Blue    = 1,
    Red     = 2,
    Magenta = 3,
    Green   = 4,
    Cyan    = 5,
    Yellow  = 6,
    White   = 7,
}

impl SpectrumBorder {
    #[must_use]
    pub fn from_bits(v: u8) -> Self {
        match v & 7 {
            0 => Self::Black,
            1 => Self::Blue,
            2 => Self::Red,
            3 => Self::Magenta,
            4 => Self::Green,
            5 => Self::Cyan,
            6 => Self::Yellow,
            _ => Self::White,
        }
    }
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Black   => "BLACK",
            Self::Blue    => "BLUE",
            Self::Red     => "RED",
            Self::Magenta => "MAGENTA",
            Self::Green   => "GREEN",
            Self::Cyan    => "CYAN",
            Self::Yellow  => "YELLOW",
            Self::White   => "WHITE",
        }
    }
}

/// ZX Spectrum ULA output byte layout (OUT 0xFE,A).
#[derive(Debug, Clone, Copy)]
pub struct UlaOutput(pub u8);

impl UlaOutput {
    /// Bits 2:0 — border colour.
    #[must_use]
    pub fn border(self) -> SpectrumBorder {
        SpectrumBorder::from_bits(self.0)
    }
    /// Bit 3 — MIC socket output (tape save).
    #[must_use]
    pub fn mic(self) -> bool {
        (self.0 >> 3) & 1 != 0
    }
    /// Bit 4 — EAR socket output (beeper).
    #[must_use]
    pub fn ear(self) -> bool {
        (self.0 >> 4) & 1 != 0
    }
}

/// ZX Spectrum ULA input byte layout (IN A,(0xFE)).
#[derive(Debug, Clone, Copy)]
pub struct UlaInput(pub u8);

impl UlaInput {
    /// Bits 4:0 — keyboard row (active-low).
    #[must_use]
    pub fn keyboard(self) -> u8 {
        self.0 & 0x1F
    }
    /// Bit 6 — EAR input (tape load).
    #[must_use]
    pub fn ear(self) -> bool {
        (self.0 >> 6) & 1 != 0
    }
}

/// ZX Spectrum keyboard row → half-row address mapping.
/// Address lines A8..A15 select the row (one bit low at a time).
pub const SPECTRUM_KEY_ROWS: &[(&str, &[&str])] = &[
    ("A8=0",  &["Shift","Z","X","C","V"]),
    ("A9=0",  &["A","S","D","F","G"]),
    ("A10=0", &["Q","W","E","R","T"]),
    ("A11=0", &["1","2","3","4","5"]),
    ("A12=0", &["0","9","8","7","6"]),
    ("A13=0", &["P","O","I","U","Y"]),
    ("A14=0", &["Enter","L","K","J","H"]),
    ("A15=0", &["Space","SymShift","M","N","B"]),
];

/// Spectrum 128k memory banking port (0x7FFD).
pub const SPECTRUM128_PAGING_PORT: u16 = 0x7FFD;

/// Decode a Spectrum 128k memory paging byte.
#[derive(Debug, Clone, Copy)]
pub struct Spectrum128Page(pub u8);

impl Spectrum128Page {
    /// Bits 2:0 — which RAM bank (0-7) is paged into 0xC000.
    #[must_use]
    pub fn ram_bank(self) -> u8 {
        self.0 & 7
    }
    /// Bit 3 — screen: 0 = normal (bank 5), 1 = shadow (bank 7).
    #[must_use]
    pub fn shadow_screen(self) -> bool {
        (self.0 >> 3) & 1 != 0
    }
    /// Bit 4 — ROM: 0 = 128k editor ROM, 1 = 48k BASIC ROM.
    #[must_use]
    pub fn rom_select(self) -> u8 {
        (self.0 >> 4) & 1
    }
    /// Bit 5 — paging lock: once set, further paging is disabled until reset.
    #[must_use]
    pub fn paging_locked(self) -> bool {
        (self.0 >> 5) & 1 != 0
    }
}

/// Spectrum memory map regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpectrumRegion {
    /// 0x0000–0x3FFF: ROM.
    Rom,
    /// 0x4000–0x5AFF: Display file (screen pixels).
    DisplayFile,
    /// 0x5800–0x5AFF: Attribute file (colour data).
    AttributeFile,
    /// 0x5B00–0x5BFF: Printer buffer / system vars.
    PrinterBuffer,
    /// 0x5C00–0x5CFF: System variables.
    SystemVars,
    /// 0x5D00–0xFFFF: User RAM (BASIC, machine code, etc.).
    UserRam,
}

impl SpectrumRegion {
    /// Classify an address into its Spectrum region.
    #[must_use]
    pub fn from_address(addr: u16) -> Self {
        match addr {
            0x0000..=0x3FFF => Self::Rom,
            0x4000..=0x57FF => Self::DisplayFile,
            0x5800..=0x5AFF => Self::AttributeFile,
            0x5B00..=0x5BFF => Self::PrinterBuffer,
            0x5C00..=0x5CFF => Self::SystemVars,
            _ => Self::UserRam,
        }
    }
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Rom           => "ROM",
            Self::DisplayFile   => "DISPLAY_FILE",
            Self::AttributeFile => "ATTRIBUTE_FILE",
            Self::PrinterBuffer => "PRINTER_BUFFER",
            Self::SystemVars    => "SYSTEM_VARS",
            Self::UserRam       => "USER_RAM",
        }
    }
}

/// Spectrum system variable addresses (partial — commonly used ones).
pub static SPECTRUM_SYSVARS: &[(&str, u16, &str)] = &[
    ("ERR_NR",  0x5C3A, "Last error number (255 = none)"),
    ("FLAGS",   0x5C3B, "Main flags"),
    ("TV_FLAG", 0x5C3C, "TV flag"),
    ("INT_MOD", 0x5C3D, "Interrupt mode"),
    ("BORDCR",  0x5C48, "Border colour (lower 3 bits)"),
    ("PPC",     0x5C45, "Line number of current BASIC statement"),
    ("E_PPC",   0x5C49, "Line number of cursor"),
    ("VARS",    0x5C4B, "Address of start of variables"),
    ("DEST",    0x5C4D, "Address of variable in assignment"),
    ("CHANS",   0x5C4F, "Address of channel data"),
    ("PROG",    0x5C53, "Address of BASIC program"),
    ("NXTLIN",  0x5C55, "Address of next program line to execute"),
    ("DATADD",  0x5C57, "Address of next DATA item"),
    ("E_LINE",  0x5C59, "Address of command being typed in"),
    ("K_CUR",   0x5C5B, "Address of cursor"),
    ("WORKSP",  0x5C61, "Address of temporary work space"),
    ("STKBOT",  0x5C63, "Address of bottom of calculator stack"),
    ("STKEND",  0x5C65, "Address of end of calculator stack"),
    ("BERG",    0x5C67, "Calculator memory register"),
    ("MEM",     0x5C68, "Address of base of calculator mem. area"),
    ("RAMTOP",  0x5CB2, "Address of last byte of BASIC system area"),
    ("P_RAMT",  0x5CB4, "Address of last byte of physical RAM"),
];

/// Look up a Spectrum system variable by address.
#[must_use]
pub fn spectrum_sysvar(addr: u16) -> Option<(&'static str, &'static str)> {
    SPECTRUM_SYSVARS
        .iter()
        .find(|e| e.1 == addr)
        .map(|e| (e.0, e.2))
}

// ── MSX ───────────────────────────────────────────────────────────────────────

/// MSX slot select port (primary slot register, written to port 0xA8).
pub const MSX_PRIMARY_SLOT_PORT: u16 = 0x00A8;

/// MSX secondary slot select (expanded slot, written to 0xFFFF in slot page 3).
pub const MSX_SECONDARY_SLOT_ADDR: u16 = 0xFFFF;

/// MSX slot configuration.
#[derive(Debug, Clone, Copy)]
pub struct MsxSlotSelect(pub u8);

impl MsxSlotSelect {
    /// Return the primary slot for the given page (0-3).
    #[must_use]
    pub fn slot_for_page(self, page: u8) -> u8 {
        (self.0 >> (page * 2)) & 3
    }
}

/// MSX memory mapper port (0xFC-0xFF).
pub const MSX_MAPPER_PORTS: &[(u16, &str)] = &[
    (0x00FC, "MAPPER_BANK_P0 — segment for page 0 (0x0000-0x3FFF)"),
    (0x00FD, "MAPPER_BANK_P1 — segment for page 1 (0x4000-0x7FFF)"),
    (0x00FE, "MAPPER_BANK_P2 — segment for page 2 (0x8000-0xBFFF)"),
    (0x00FF, "MAPPER_BANK_P3 — segment for page 3 (0xC000-0xFFFF)"),
];

/// MSX BIOS entry points (ROM 0, slot 0).
pub static MSX_BIOS_CALLS: &[(&str, u16, &str)] = &[
    ("CHKRAM",  0x0000, "Test RAM and set stack"),
    ("SYNCHR",  0x0008, "Check character against next in BASIC"),
    ("RDSLT",   0x000C, "Read byte from slot"),
    ("CHRGTR",  0x0010, "Get next character from BASIC"),
    ("WRSLT",   0x0014, "Write byte to slot"),
    ("OUTDO",   0x0018, "Output to current device"),
    ("CALSLT",  0x001C, "Inter-slot call"),
    ("DCOMPR",  0x0020, "Compare DE and HL"),
    ("ENASLT",  0x0024, "Enable slot for reading/writing"),
    ("GETYPR",  0x0028, "Get type of DAC value"),
    ("CALLF",   0x0030, "Inter-slot call with far call"),
    ("KEYINT",  0x0038, "Keyboard/timer interrupt handler"),
    ("INITIO",  0x003B, "Initialize I/O devices"),
    ("INIFNK",  0x003E, "Initialize function key strings"),
    ("DISSCR",  0x0041, "Disable screen"),
    ("ENASCR",  0x0044, "Enable screen"),
    ("WRTVDP",  0x0047, "Write to VDP register"),
    ("RDVRM",   0x004A, "Read VRAM byte"),
    ("WRTVRM",  0x004D, "Write VRAM byte"),
    ("SETRD",   0x0050, "Set up for VRAM read"),
    ("SETWRT",  0x0053, "Set up for VRAM write"),
    ("FILVRM",  0x0056, "Fill VRAM block"),
    ("LDIRMV",  0x0059, "Block move VRAM to RAM"),
    ("LDIRVM",  0x005C, "Block move RAM to VRAM"),
    ("CHGMOD",  0x005F, "Change screen mode"),
    ("CHGCLR",  0x0062, "Change screen colours"),
    ("CLRSPR",  0x0069, "Clear all sprites"),
    ("INITXT",  0x006C, "Initialize screen to TEXT1 mode"),
    ("INIT32",  0x006F, "Initialize screen to GRAPHIC1 mode"),
    ("INIGRP",  0x0072, "Initialize screen to GRAPHIC2 mode"),
    ("INIMLT",  0x0075, "Initialize screen to MULTICOLOR mode"),
    ("SETTXT",  0x0078, "Set VDP to TEXT1 mode"),
    ("SETT32",  0x007B, "Set VDP to GRAPHIC1 mode"),
    ("SETGRP",  0x007E, "Set VDP to GRAPHIC2 mode"),
    ("SETMLT",  0x0081, "Set VDP to MULTICOLOR mode"),
    ("LDCHR",   0x0084, "Load tile patterns into VRAM"),
    ("RDSPR",   0x0087, "Read sprite attr table"),
    ("WRSPR",   0x008A, "Write sprite attr table"),
    ("GTPATNAM", 0x008D, "Get pattern name address"),
    ("GTBATNM", 0x0090, "Get base of tile name table"),
    ("CHSNS",   0x009C, "Check keyboard buffer"),
    ("CHGET",   0x009F, "Get character from keyboard"),
    ("CHPUT",   0x00A2, "Print character"),
    ("LPTOUT",  0x00A5, "Output character to printer"),
    ("LPTSTT",  0x00A8, "Printer status check"),
    ("CNVCHR",  0x00AB, "Convert graphic character"),
    ("PINLIN",  0x00AE, "Get line from console"),
    ("INLIN",   0x00B1, "Get line (stop at Ctrl-STOP)"),
    ("QINLIN",  0x00B4, "Get line with prompt"),
    ("BREAKX",  0x00B7, "Check for Ctrl-STOP break"),
    ("ISCNTC",  0x00BA, "Check for Ctrl-C"),
    ("CKCNTC",  0x00BD, "Check Ctrl-C and force stop"),
    ("BEEP",    0x00C0, "Output beep sound"),
    ("CLS",     0x00C3, "Clear screen"),
    ("POSIT",   0x00C6, "Set cursor position"),
    ("FNKSB",   0x00C9, "Show/hide function key label row"),
    ("ERAFNK",  0x00CC, "Erase function key label"),
    ("DSPFNK",  0x00CF, "Display function key label"),
    ("TOTEXT",  0x00D2, "Force screen to text mode"),
    ("GTSTCK",  0x00D5, "Get joystick direction"),
    ("GTTRIG",  0x00D8, "Get trigger button state"),
    ("GTPAD",   0x00DB, "Get touch pad data"),
    ("GTPDL",   0x00DE, "Get paddle value"),
    ("TAPION",  0x00E1, "Open tape for reading"),
    ("TAPIN",   0x00E4, "Read byte from tape"),
    ("TAPIOF",  0x00E7, "Close tape for reading"),
    ("TAPOON",  0x00EA, "Open tape for writing"),
    ("TAPOUT",  0x00ED, "Write byte to tape"),
    ("TAPOOF",  0x00F0, "Close tape for writing"),
    ("STMOTR",  0x00F3, "Set motor state"),
    ("LFTQ",    0x00F6, "Get free space in queue"),
    ("PUTQ",    0x00F9, "Put byte in queue"),
    ("RIGHTC",  0x00FC, "Move current position one character right"),
    ("LEFTC",   0x00FF, "Move current position one character left"),
    ("UPC",     0x0102, "Move current position one line up"),
    ("TUPC",    0x0105, "Move current position one line up (conditional)"),
    ("DOWNC",   0x0108, "Move current position one line down"),
    ("TDOWNC",  0x010B, "Move current position one line down (conditional)"),
    ("SCALXY",  0x010E, "Scale x,y coordinates"),
    ("MAPXY",   0x0111, "Map x,y to physical coordinate"),
    ("FETCHC",  0x0114, "Fetch current position"),
    ("STOREC",  0x0117, "Store current position"),
    ("SETATR",  0x011A, "Set colour attribute"),
    ("READC",   0x011D, "Read colour attribute at current position"),
    ("SETC",    0x0120, "Set colour at current position"),
    ("NSETCX",  0x0123, "Set colours for multiple columns"),
    ("GTASPC",  0x0126, "Get aspect ratio"),
    ("PNTINI",  0x0129, "Initialise Paint command"),
    ("SCANR",   0x012C, "Scan boundary colour rightward"),
    ("SCANL",   0x012F, "Scan boundary colour leftward"),
];

/// Look up an MSX BIOS call by address.
#[must_use]
pub fn msx_bios_call(addr: u16) -> Option<(&'static str, &'static str)> {
    MSX_BIOS_CALLS
        .iter()
        .find(|e| e.1 == addr)
        .map(|e| (e.0, e.2))
}

// ── CP/M ─────────────────────────────────────────────────────────────────────

/// CP/M BDOS function codes (in register C when calling 0x0005).
pub static CPM_BDOS_FUNCTIONS: &[(u8, &str, &str)] = &[
    (0,  "P_TERMCPM",   "System reset"),
    (1,  "C_READ",      "Console input (A = char)"),
    (2,  "C_WRITE",     "Console output (E = char)"),
    (3,  "A_READ",      "Auxiliary input"),
    (4,  "A_WRITE",     "Auxiliary output"),
    (5,  "L_WRITE",     "Printer output"),
    (6,  "C_RAWIO",     "Direct console I/O"),
    (7,  "A_STATIN",    "Get auxiliary input status"),
    (8,  "A_STATOUT",   "Get auxiliary output status"),
    (9,  "C_WRITESTR",  "Print string (DE = $ terminated)"),
    (10, "C_READSTR",   "Buffered console input"),
    (11, "C_STAT",      "Get console status"),
    (12, "S_BDOSVER",   "Return BDOS version number"),
    (13, "DRV_ALLRESET","Reset disk system"),
    (14, "DRV_SET",     "Select drive (E = drive 0=A)"),
    (15, "F_OPEN",      "Open file (DE = FCB)"),
    (16, "F_CLOSE",     "Close file"),
    (17, "F_SFIRST",    "Search for first"),
    (18, "F_SNEXT",     "Search for next"),
    (19, "F_DELETE",    "Delete file"),
    (20, "F_READ",      "Read sequential"),
    (21, "F_WRITE",     "Write sequential"),
    (22, "F_MAKE",      "Create file"),
    (23, "F_RENAME",    "Rename file"),
    (24, "DRV_LOGINVEC","Return login vector"),
    (25, "DRV_GET",     "Return current drive"),
    (26, "F_DMAOFF",    "Set DMA address"),
    (27, "DRV_ALLOCVEC","Return address of alloc vector"),
    (28, "DRV_SETRO",   "Write protect disk"),
    (29, "DRV_ROVEC",   "Return R/O vector"),
    (30, "F_ATTRIB",    "Set file attributes"),
    (31, "DRV_DPB",     "Return address of DPB"),
    (32, "F_USERNUM",   "Get/set user number"),
    (33, "F_READRAND",  "Read random"),
    (34, "F_WRITERAND", "Write random"),
    (35, "F_SIZE",      "Compute file size"),
    (36, "F_RANDREC",   "Set random record"),
    (37, "DRV_RESET",   "Reset drive"),
    (40, "F_WRITEZF",   "Write random with zero fill"),
];

/// Decode a CP/M BDOS function code.
#[must_use]
pub fn cpm_bdos_name(func: u8) -> Option<(&'static str, &'static str)> {
    CPM_BDOS_FUNCTIONS
        .iter()
        .find(|e| e.0 == func)
        .map(|e| (e.1, e.2))
}

/// CP/M BIOS function offsets (jump table at BIOS base, 3 bytes per entry).
pub static CPM_BIOS_FUNCTIONS: &[(u8, &str)] = &[
    (0,  "BOOT"),
    (1,  "WBOOT"),
    (2,  "CONST"),
    (3,  "CONIN"),
    (4,  "CONOUT"),
    (5,  "LIST"),
    (6,  "PUNCH"),
    (7,  "READER"),
    (8,  "HOME"),
    (9,  "SELDSK"),
    (10, "SETTRK"),
    (11, "SETSEC"),
    (12, "SETDMA"),
    (13, "READ"),
    (14, "WRITE"),
    (15, "LISTST"),
    (16, "SECTRAN"),
];

// ── Game Boy (GB-Z80) ─────────────────────────────────────────────────────────

/// The Game Boy CPU is a modified Z80 (sometimes called SM83 / LR35902).
/// Differences from standard Z80:
/// - No IX, IY registers
/// - No R register (memory refresh)
/// - No I register
/// - No alternate register set (no EXX, no AF')
/// - No IN/OUT instructions
/// - No ED-prefix instructions
/// - New instructions: SWAP r, STOP, LDH, LD HL,SP+e, ADD SP,e, RLCA/RLA/RRCA/RRA only through CB
/// - CB prefix decodes differently (no undocumented SLL)
/// - Carry/half-carry semantics preserved, parity removed
/// - Separate HALT: CPU halts on next instruction if IME=0 and pending interrupt

/// GB-Z80 register IDs (data-model used in this crate).
pub mod gb_regs {
    pub const GB_REG_A:  u32 = 0;
    pub const GB_REG_F:  u32 = 1;
    pub const GB_REG_B:  u32 = 2;
    pub const GB_REG_C:  u32 = 3;
    pub const GB_REG_D:  u32 = 4;
    pub const GB_REG_E:  u32 = 5;
    pub const GB_REG_H:  u32 = 6;
    pub const GB_REG_L:  u32 = 7;
    pub const GB_REG_AF: u32 = 8;
    pub const GB_REG_BC: u32 = 9;
    pub const GB_REG_DE: u32 = 10;
    pub const GB_REG_HL: u32 = 11;
    pub const GB_REG_SP: u32 = 12;
    pub const GB_REG_PC: u32 = 13;
}

/// GB-Z80 flags (upper nibble of F, lower nibble always 0).
#[derive(Debug, Clone, Copy)]
pub struct GbFlags(pub u8);

impl GbFlags {
    pub const ZERO:       u8 = 0x80;
    pub const SUBTRACT:   u8 = 0x40;
    pub const HALF_CARRY: u8 = 0x20;
    pub const CARRY:      u8 = 0x10;

    #[must_use] pub fn zero(self)       -> bool { self.0 & Self::ZERO       != 0 }
    #[must_use] pub fn subtract(self)   -> bool { self.0 & Self::SUBTRACT   != 0 }
    #[must_use] pub fn half_carry(self) -> bool { self.0 & Self::HALF_CARRY != 0 }
    #[must_use] pub fn carry(self)      -> bool { self.0 & Self::CARRY      != 0 }
}

/// Decode a GB-Z80 CB-prefixed instruction (SWAP/bit ops).
/// On Game Boy the CB prefix always operates on 8-bit registers only.
#[must_use]
pub fn decode_gb_cb(op: u8) -> GbDecoded {
    let x = (op >> 6) & 3;
    let y = (op >> 3) & 7;
    let z = op & 7;
    let reg = GB_R8_NAMES[z as usize];

    let (mnemonic, operands) = match x {
        0 => {
            let mn = match y {
                0 => "RLC",
                1 => "RRC",
                2 => "RL",
                3 => "RR",
                4 => "SLA",
                5 => "SRA",
                6 => "SWAP",  // GB-Z80: bit 6 → SWAP (NOT SLL like standard Z80)
                _ => "SRL",
            };
            (mn, reg.to_string())
        }
        1 => ("BIT", format!("{y},{reg}")),
        2 => ("RES", format!("{y},{reg}")),
        _ => ("SET", format!("{y},{reg}")),
    };
    GbDecoded {
        mnemonic: mnemonic.to_string(),
        operands,
        size: 2,
    }
}

static GB_R8_NAMES: [&str; 8] = ["B", "C", "D", "E", "H", "L", "(HL)", "A"];

/// A decoded Game Boy instruction.
#[derive(Debug, Clone)]
pub struct GbDecoded {
    pub mnemonic: String,
    pub operands: String,
    pub size: usize,
}

/// Decode a Game Boy (GB-Z80 / SM83) instruction.
///
/// Only opcodes valid on Game Boy are handled.  Many Z80 opcodes are
/// undefined/illegal on Game Boy and will decode as "ILLEGAL".
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn decode_gb(bytes: &[u8], pc: u16) -> GbDecoded {
    if bytes.is_empty() {
        return GbDecoded {
            mnemonic: "ILLEGAL".to_string(),
            operands: String::new(),
            size: 1,
        };
    }
    let op = bytes[0];

    // CB prefix
    if op == 0xCB {
        let op2 = bytes.get(1).copied().unwrap_or(0);
        return decode_gb_cb(op2);
    }

    let x = (op >> 6) & 3;
    let y = (op >> 3) & 7;
    let z = op & 7;

    match op {
        0x00 => GbDecoded { mnemonic: "NOP".into(),  operands: String::new(), size: 1 },
        0x10 => GbDecoded { mnemonic: "STOP".into(), operands: "0".into(),    size: 2 },
        0x76 => GbDecoded { mnemonic: "HALT".into(), operands: String::new(), size: 1 },
        0xF3 => GbDecoded { mnemonic: "DI".into(),   operands: String::new(), size: 1 },
        0xFB => GbDecoded { mnemonic: "EI".into(),   operands: String::new(), size: 1 },
        0xC9 => GbDecoded { mnemonic: "RET".into(),  operands: String::new(), size: 1 },
        0xD9 => GbDecoded { mnemonic: "RETI".into(), operands: String::new(), size: 1 },
        0xE9 => GbDecoded { mnemonic: "JP".into(),   operands: "(HL)".into(), size: 1 },
        // LD (BC),A / LD (DE),A / LD (nn),A / LD A,(BC) / LD A,(DE) / LD A,(nn)
        0x02 => GbDecoded { mnemonic: "LD".into(), operands: "(BC),A".into(), size: 1 },
        0x12 => GbDecoded { mnemonic: "LD".into(), operands: "(DE),A".into(), size: 1 },
        0x0A => GbDecoded { mnemonic: "LD".into(), operands: "A,(BC)".into(), size: 1 },
        0x1A => GbDecoded { mnemonic: "LD".into(), operands: "A,(DE)".into(), size: 1 },
        // LDH (GB-specific) — 0xE0, 0xF0
        0xE0 => {
            let n = bytes.get(1).copied().unwrap_or(0);
            GbDecoded { mnemonic: "LDH".into(), operands: format!("($FF{n:02X}),A"), size: 2 }
        }
        0xF0 => {
            let n = bytes.get(1).copied().unwrap_or(0);
            GbDecoded { mnemonic: "LDH".into(), operands: format!("A,($FF{n:02X})"), size: 2 }
        }
        // LD (C),A / LD A,(C)  — 0xE2 / 0xF2
        0xE2 => GbDecoded { mnemonic: "LD".into(),  operands: "($FF00+C),A".into(), size: 1 },
        0xF2 => GbDecoded { mnemonic: "LD".into(),  operands: "A,($FF00+C)".into(), size: 1 },
        // LD HL,SP+e — 0xF8
        0xF8 => {
            let e = bytes.get(1).copied().unwrap_or(0) as i8;
            let sign = if e >= 0 { '+' } else { '-' };
            GbDecoded {
                mnemonic: "LD".into(),
                operands: format!("HL,SP{sign}{}", e.unsigned_abs()),
                size: 2,
            }
        }
        // ADD SP,e — 0xE8
        0xE8 => {
            let e = bytes.get(1).copied().unwrap_or(0) as i8;
            let sign = if e >= 0 { '+' } else { '-' };
            GbDecoded {
                mnemonic: "ADD".into(),
                operands: format!("SP,{sign}{}", e.unsigned_abs()),
                size: 2,
            }
        }
        // LD SP,HL — 0xF9
        0xF9 => GbDecoded { mnemonic: "LD".into(), operands: "SP,HL".into(), size: 1 },
        // LD (nn),SP — 0x08
        0x08 => {
            let nn = bytes.get(1..3).map(|b| u16::from_le_bytes([b[0], b[1]])).unwrap_or(0);
            GbDecoded { mnemonic: "LD".into(), operands: format!("(${nn:04X}),SP"), size: 3 }
        }
        // JP nn — 0xC3
        0xC3 => {
            let nn = bytes.get(1..3).map(|b| u16::from_le_bytes([b[0], b[1]])).unwrap_or(0);
            GbDecoded { mnemonic: "JP".into(), operands: format!("${nn:04X}"), size: 3 }
        }
        // CALL nn — 0xCD
        0xCD => {
            let nn = bytes.get(1..3).map(|b| u16::from_le_bytes([b[0], b[1]])).unwrap_or(0);
            GbDecoded { mnemonic: "CALL".into(), operands: format!("${nn:04X}"), size: 3 }
        }
        // JR e — 0x18
        0x18 => {
            let e = bytes.get(1).copied().unwrap_or(0) as i8;
            let target = (pc as i32 + 2 + e as i32) as u16;
            GbDecoded { mnemonic: "JR".into(), operands: format!("${target:04X}"), size: 2 }
        }
        // JR cc,e — 0x20/0x28/0x30/0x38
        0x20 | 0x28 | 0x30 | 0x38 => {
            let cc = match op {
                0x20 => "NZ", 0x28 => "Z", 0x30 => "NC", _ => "C",
            };
            let e = bytes.get(1).copied().unwrap_or(0) as i8;
            let target = (pc as i32 + 2 + e as i32) as u16;
            GbDecoded {
                mnemonic: "JR".into(),
                operands: format!("{cc},${target:04X}"),
                size: 2,
            }
        }
        // RLCA/RRCA/RLA/RRA — 0x07/0x0F/0x17/0x1F
        0x07 => GbDecoded { mnemonic: "RLCA".into(), operands: String::new(), size: 1 },
        0x0F => GbDecoded { mnemonic: "RRCA".into(), operands: String::new(), size: 1 },
        0x17 => GbDecoded { mnemonic: "RLA".into(),  operands: String::new(), size: 1 },
        0x1F => GbDecoded { mnemonic: "RRA".into(),  operands: String::new(), size: 1 },
        // DAA / CPL / SCF / CCF
        0x27 => GbDecoded { mnemonic: "DAA".into(), operands: String::new(), size: 1 },
        0x2F => GbDecoded { mnemonic: "CPL".into(), operands: String::new(), size: 1 },
        0x37 => GbDecoded { mnemonic: "SCF".into(), operands: String::new(), size: 1 },
        0x3F => GbDecoded { mnemonic: "CCF".into(), operands: String::new(), size: 1 },
        // RST p
        0xC7 | 0xCF | 0xD7 | 0xDF | 0xE7 | 0xEF | 0xF7 | 0xFF => {
            let p = ((op & 0x38) >> 3) * 8;
            GbDecoded { mnemonic: "RST".into(), operands: format!("${p:02X}H"), size: 1 }
        }
        // Illegal on GB: DD/ED/FD prefixes
        0xD3 | 0xDB | 0xDD | 0xE3 | 0xE4 | 0xEB | 0xEC | 0xED | 0xF4 | 0xFC | 0xFD => {
            GbDecoded { mnemonic: "ILLEGAL".into(), operands: format!("${op:02X}"), size: 1 }
        }
        // 8-bit register loads x=1
        op if x == 1 && op != 0x76 => {
            let dst = GB_R8_NAMES[y as usize];
            let src = GB_R8_NAMES[z as usize];
            GbDecoded { mnemonic: "LD".into(), operands: format!("{dst},{src}"), size: 1 }
        }
        // 16-bit register loads x=0, z=1, q=0
        op if x == 0 && z == 1 && (y & 1) == 0 => {
            let rp = match (op >> 4) & 0x03 {
                0 => "BC", 1 => "DE", 2 => "HL", _ => "SP",
            };
            let nn = bytes.get(1..3).map(|b| u16::from_le_bytes([b[0], b[1]])).unwrap_or(0);
            GbDecoded { mnemonic: "LD".into(), operands: format!("{rp},${nn:04X}"), size: 3 }
        }
        // ALU x=2
        op if x == 2 => {
            let mn = gb_alu_mnemonic((op >> 3) & 7);
            let src = GB_R8_NAMES[(op & 7) as usize];
            GbDecoded {
                mnemonic: mn.into(),
                operands: if matches!(mn, "ADD" | "ADC" | "SBC") {
                    format!("A,{src}")
                } else {
                    src.into()
                },
                size: 1,
            }
        }
        _ => GbDecoded {
            mnemonic: "DB".into(),
            operands: format!("${op:02X}"),
            size: 1,
        },
    }
}

fn gb_alu_mnemonic(y: u8) -> &'static str {
    match y {
        0 => "ADD", 1 => "ADC", 2 => "SUB", 3 => "SBC",
        4 => "AND", 5 => "XOR", 6 => "OR",  _ => "CP",
    }
}

/// Game Boy memory map regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GbRegion {
    /// 0x0000–0x00FF: Bootstrap ROM / RST/Interrupt vectors.
    BootOrVectors,
    /// 0x0100–0x014F: Cartridge header.
    CartHeader,
    /// 0x0150–0x3FFF: ROM bank 0.
    RomBank0,
    /// 0x4000–0x7FFF: ROM bank N (switchable via MBC).
    RomBankN,
    /// 0x8000–0x9FFF: VRAM.
    Vram,
    /// 0xA000–0xBFFF: External cartridge RAM.
    ExternalRam,
    /// 0xC000–0xCFFF: Work RAM bank 0.
    WRamBank0,
    /// 0xD000–0xDFFF: Work RAM bank 1 (GBC: switchable).
    WRamBank1,
    /// 0xE000–0xFDFF: Echo of 0xC000–0xDDFF.
    Echo,
    /// 0xFE00–0xFE9F: OAM (sprite attribute table).
    Oam,
    /// 0xFEA0–0xFEFF: Prohibited.
    Prohibited,
    /// 0xFF00–0xFF7F: I/O registers.
    IoRegs,
    /// 0xFF80–0xFFFE: High RAM (HRAM / zero page).
    Hram,
    /// 0xFFFF: Interrupt Enable register.
    Ie,
}

impl GbRegion {
    #[must_use]
    pub fn from_address(addr: u16) -> Self {
        match addr {
            0x0000..=0x00FF => Self::BootOrVectors,
            0x0100..=0x014F => Self::CartHeader,
            0x0150..=0x3FFF => Self::RomBank0,
            0x4000..=0x7FFF => Self::RomBankN,
            0x8000..=0x9FFF => Self::Vram,
            0xA000..=0xBFFF => Self::ExternalRam,
            0xC000..=0xCFFF => Self::WRamBank0,
            0xD000..=0xDFFF => Self::WRamBank1,
            0xE000..=0xFDFF => Self::Echo,
            0xFE00..=0xFE9F => Self::Oam,
            0xFEA0..=0xFEFF => Self::Prohibited,
            0xFF00..=0xFF7F => Self::IoRegs,
            0xFF80..=0xFFFE => Self::Hram,
            0xFFFF           => Self::Ie,
        }
    }
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::BootOrVectors => "BOOT/VECTORS",
            Self::CartHeader    => "CART_HEADER",
            Self::RomBank0      => "ROM_BANK_0",
            Self::RomBankN      => "ROM_BANK_N",
            Self::Vram          => "VRAM",
            Self::ExternalRam   => "EXT_RAM",
            Self::WRamBank0     => "WRAM_BANK_0",
            Self::WRamBank1     => "WRAM_BANK_1",
            Self::Echo          => "ECHO",
            Self::Oam           => "OAM",
            Self::Prohibited    => "PROHIBITED",
            Self::IoRegs        => "IO_REGS",
            Self::Hram          => "HRAM",
            Self::Ie            => "IE",
        }
    }
}

/// Game Boy I/O register names (0xFF00-0xFF7F partial).
pub static GB_IO_REGS: &[(u16, &str, &str)] = &[
    (0xFF00, "P1/JOYP",  "Joypad / P1"),
    (0xFF01, "SB",       "Serial transfer data"),
    (0xFF02, "SC",       "Serial transfer control"),
    (0xFF04, "DIV",      "Divider register"),
    (0xFF05, "TIMA",     "Timer counter"),
    (0xFF06, "TMA",      "Timer modulo"),
    (0xFF07, "TAC",      "Timer control"),
    (0xFF0F, "IF",       "Interrupt flag"),
    (0xFF10, "NR10",     "Channel 1 sweep"),
    (0xFF11, "NR11",     "Channel 1 sound length/wave duty"),
    (0xFF12, "NR12",     "Channel 1 volume envelope"),
    (0xFF13, "NR13",     "Channel 1 freq lo"),
    (0xFF14, "NR14",     "Channel 1 freq hi + trigger"),
    (0xFF16, "NR21",     "Channel 2 sound length/wave duty"),
    (0xFF17, "NR22",     "Channel 2 volume envelope"),
    (0xFF18, "NR23",     "Channel 2 freq lo"),
    (0xFF19, "NR24",     "Channel 2 freq hi + trigger"),
    (0xFF1A, "NR30",     "Channel 3 on/off"),
    (0xFF1B, "NR31",     "Channel 3 sound length"),
    (0xFF1C, "NR32",     "Channel 3 output level"),
    (0xFF1D, "NR33",     "Channel 3 freq lo"),
    (0xFF1E, "NR34",     "Channel 3 freq hi + trigger"),
    (0xFF20, "NR41",     "Channel 4 sound length"),
    (0xFF21, "NR42",     "Channel 4 volume envelope"),
    (0xFF22, "NR43",     "Channel 4 polynomial counter"),
    (0xFF23, "NR44",     "Channel 4 trigger/length enable"),
    (0xFF24, "NR50",     "Master volume / VIN panning"),
    (0xFF25, "NR51",     "Sound panning"),
    (0xFF26, "NR52",     "Sound on/off"),
    (0xFF40, "LCDC",     "LCD control"),
    (0xFF41, "STAT",     "LCD status"),
    (0xFF42, "SCY",      "BG scroll Y"),
    (0xFF43, "SCX",      "BG scroll X"),
    (0xFF44, "LY",       "LCD Y coordinate"),
    (0xFF45, "LYC",      "LY compare"),
    (0xFF46, "DMA",      "OAM DMA transfer and start"),
    (0xFF47, "BGP",      "BG palette data"),
    (0xFF48, "OBP0",     "Object palette 0"),
    (0xFF49, "OBP1",     "Object palette 1"),
    (0xFF4A, "WY",       "Window Y position"),
    (0xFF4B, "WX",       "Window X position"),
    (0xFFFF, "IE",       "Interrupt enable"),
];

/// Look up a Game Boy I/O register.
#[must_use]
pub fn gb_io_reg(addr: u16) -> Option<(&'static str, &'static str)> {
    GB_IO_REGS
        .iter()
        .find(|e| e.0 == addr)
        .map(|e| (e.1, e.2))
}

/// Game Boy interrupt vectors.
pub static GB_INTERRUPT_VECTORS: &[(u8, u16, &str)] = &[
    (0, 0x0040, "VBlank — LCD vertical blank period"),
    (1, 0x0048, "STAT — LCD status interrupt"),
    (2, 0x0050, "Timer — TIMA overflow"),
    (3, 0x0058, "Serial — serial transfer complete"),
    (4, 0x0060, "Joypad — P10-P13 input low"),
];

// ── Platform detector ──────────────────────────────────────────────────────────

/// High-level Z80 platform kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Z80Platform {
    ZxSpectrum48k,
    ZxSpectrum128k,
    Msx1,
    Msx2,
    Cpm22,
    GameBoy,
    Unknown,
}

impl Z80Platform {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::ZxSpectrum48k  => "ZX Spectrum 48K",
            Self::ZxSpectrum128k => "ZX Spectrum 128K",
            Self::Msx1           => "MSX 1",
            Self::Msx2           => "MSX 2",
            Self::Cpm22          => "CP/M 2.2",
            Self::GameBoy        => "Game Boy (SM83)",
            Self::Unknown        => "Unknown Z80 Platform",
        }
    }
}

/// Heuristic platform detection from a byte slice of code.
///
/// Looks for platform-specific call patterns:
/// - Spectrum ROM RST 0x10 / 0x28 / CALL 0x0056
/// - CP/M CALL 0x0005
/// - Game Boy: LDH (0xE0/0xF0) and absence of ED/DD prefixes
/// - MSX: CALL 0x00A2 (CHPUT) or 0x009F (CHGET)
#[must_use]
pub fn heuristic_platform(code: &[u8]) -> Z80Platform {
    let mut cpm_score     = 0i32;
    let mut spectrum_score = 0i32;
    let mut msx_score     = 0i32;
    let mut gb_score      = 0i32;
    let mut ix_iy_count   = 0i32;

    let mut i = 0usize;
    while i < code.len() {
        let b = code[i];
        match b {
            0xCD => {
                if i + 2 < code.len() {
                    let target = u16::from_le_bytes([code[i+1], code[i+2]]);
                    match target {
                        0x0005 => cpm_score += 10,
                        0x0056 | 0x0010 | 0x0028 => spectrum_score += 5,
                        0x00A2 | 0x009F | 0x001C  => msx_score += 5,
                        _ => {}
                    }
                }
                i += 3;
            }
            // RST 0x10 = 0xD7, RST 0x28 = 0xEF, RST 0x30 = 0xF7
            0xD7 | 0xEF | 0xF7 => { spectrum_score += 3; i += 1; }
            // IX/IY prefixes — not present on Game Boy
            0xDD | 0xFD => { ix_iy_count += 1; i += 1; }
            // ED prefix — not on Game Boy
            0xED => { gb_score -= 5; i += 1; }
            // LDH — Game Boy specific
            0xE0 | 0xF0 => { gb_score += 8; i += 2; }
            // STOP — Game Boy specific
            0x10 if i + 1 < code.len() && code[i+1] == 0x00 => {
                gb_score += 10; i += 2;
            }
            _ => { i += 1; }
        }
    }

    if ix_iy_count > 0 {
        gb_score -= ix_iy_count * 3;
    }

    let scores = [
        (cpm_score, Z80Platform::Cpm22),
        (spectrum_score, Z80Platform::ZxSpectrum48k),
        (msx_score, Z80Platform::Msx1),
        (gb_score, Z80Platform::GameBoy),
    ];

    let best = scores.iter().max_by_key(|s| s.0).copied();
    match best {
        Some((s, p)) if s > 0 => p,
        _ => Z80Platform::Unknown,
    }
}

// ── I/O port decoder ──────────────────────────────────────────────────────────

/// Decoded I/O port information.
#[derive(Debug, Clone)]
pub struct IoPortInfo {
    /// Port address.
    pub port: u16,
    /// Short name.
    pub name: String,
    /// Detailed description.
    pub description: String,
    /// Platform where this port is valid.
    pub platform: Z80Platform,
}

/// Decode an I/O port address to a human-readable name.
#[must_use]
pub fn decode_io_port(port: u16, platform: Z80Platform) -> IoPortInfo {
    let (name, desc) = match platform {
        Z80Platform::ZxSpectrum48k | Z80Platform::ZxSpectrum128k => {
            spectrum_port_name(port)
        }
        Z80Platform::Msx1 | Z80Platform::Msx2 => {
            msx_port_name(port)
        }
        _ => (format!("PORT_{port:04X}"), format!("Unknown port 0x{port:04X}")),
    };
    IoPortInfo { port, name, description: desc, platform }
}

fn spectrum_port_name(port: u16) -> (String, String) {
    match port & 0x00FF {
        0xFE => ("ULA".into(), "ULA — border/speaker/keyboard".into()),
        0xFD if (port & 0xFF00) == 0x7F00 => {
            ("PAGE128".into(), "Spectrum 128k memory paging register".into())
        }
        0xFD if (port & 0xFF00) == 0xFF00 => {
            ("AY_REG".into(), "AY-3-8912 register select".into())
        }
        0xBF if (port & 0xFF00) == 0xFF00 => {
            ("AY_DATA".into(), "AY-3-8912 data write".into())
        }
        _ => (format!("PORT_{port:04X}"), format!("Spectrum I/O 0x{port:04X}")),
    }
}

fn msx_port_name(port: u16) -> (String, String) {
    match port & 0x00FF {
        0xA8 => ("PPI_A".into(), "8255 PPI Port A — slot select".into()),
        0xA9 => ("PPI_B".into(), "8255 PPI Port B — keyboard row".into()),
        0xAA => ("PPI_C".into(), "8255 PPI Port C — keyboard/cassette/CapsLock".into()),
        0xAB => ("PPI_CTL".into(), "8255 PPI control".into()),
        0x98 => ("VDP_DATA".into(), "V9918 VRAM data".into()),
        0x99 => ("VDP_ADDR".into(), "V9918 address/register".into()),
        0xA0 => ("PSG_REG".into(), "AY-3-8910 register latch".into()),
        0xA1 => ("PSG_DATA".into(), "AY-3-8910 data write".into()),
        0xA2 => ("PSG_READ".into(), "AY-3-8910 data read".into()),
        0xFC..=0xFF => {
            let pg = port & 3;
            (
                format!("MAPPER_P{pg}"),
                format!("Memory mapper bank for page {pg}"),
            )
        }
        _ => (format!("PORT_{port:04X}"), format!("MSX I/O 0x{port:04X}")),
    }
}
