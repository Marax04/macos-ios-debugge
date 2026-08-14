//! Motorola 68000 platform-specific knowledge.
//!
//! Covers Amiga (custom chips, CIA, Paula, Denise), Sega Genesis/Mega Drive
//! (VDP, PSG/YM2612, memory map), Macintosh 68k (Toolbox traps, A-line),
//! and Sun-3 (SunOS syscalls, VME bus).

// ── Amiga ────────────────────────────────────────────────────────────────────

/// Amiga custom chip register map.
/// Registers are 16-bit, big-endian, mapped at 0xDFF000.
pub static AMIGA_CUSTOM_REGS: &[(u32, &str, &str, bool)] = &[
    // (offset, name, description, write_only)
    (0x000, "BLTDDAT",  "Blitter destination early read (dummy)",       false),
    (0x002, "DMACONR",  "DMA control and blitter status (read)",        false),
    (0x004, "VPOSR",    "Read vertical position (MSB) + VHPOSR",        false),
    (0x006, "VHPOSR",   "Read vertical and horizontal position",         false),
    (0x008, "DSKDATR",  "Disk data early read (dummy)",                 false),
    (0x00A, "JOY0DAT",  "Joystick/mouse 0 data (2 quadrature bits each)",false),
    (0x00C, "JOY1DAT",  "Joystick/mouse 1 data",                        false),
    (0x00E, "CLXDAT",   "Sprite/playfield collision data",               false),
    (0x010, "ADKCONR",  "Audio/disk control (read)",                    false),
    (0x012, "POT0DAT",  "Pot counter data left pair",                   false),
    (0x014, "POT1DAT",  "Pot counter data right pair",                  false),
    (0x016, "POTINP",   "Pot pin data read",                            false),
    (0x018, "SERDATR",  "Serial data and status read",                  false),
    (0x01A, "DSKBYTR",  "Disk data byte and status read",               false),
    (0x01C, "INTENAR",  "Interrupt enable bits (read)",                 false),
    (0x01E, "INTREQR",  "Interrupt request bits (read)",                false),
    (0x020, "DSKPTH",   "Disk pointer (high 3 bits)",                   true),
    (0x022, "DSKPTL",   "Disk pointer (low 15 bits)",                   true),
    (0x024, "DSKLEN",   "Disk length and DMA control",                  true),
    (0x026, "DSKDAT",   "Disk DMA data write (dummy)",                  true),
    (0x028, "REFPTR",   "Refresh pointer",                              true),
    (0x02A, "VPOSW",    "Write vertical position (MSB and LOF)",        true),
    (0x02C, "VHPOSW",   "Write vertical and horizontal position",        true),
    (0x02E, "COPCON",   "Coprocessor control register",                 true),
    (0x030, "SERDAT",   "Serial data and stop bits",                    true),
    (0x032, "SERPER",   "Serial period and control",                    true),
    (0x034, "POTGO",    "Pot count start and output data",              true),
    (0x036, "JOYTEST",  "Write to all four joystick/mouse counters",    true),
    (0x038, "STREQU",   "Strobe for horiz sync with VB and EQU",        true),
    (0x03A, "STRVBL",   "Strobe for horiz sync with VB",               true),
    (0x03C, "STRHOR",   "Strobe for horizontal sync",                   true),
    (0x03E, "STRLONG",  "Strobe for long horizontal line",              true),
    (0x040, "BLTCON0",  "Blitter control register 0",                   true),
    (0x042, "BLTCON1",  "Blitter control register 1",                   true),
    (0x044, "BLTAFWM",  "Blitter first word mask for source A",         true),
    (0x046, "BLTALWM",  "Blitter last word mask for source A",          true),
    (0x048, "BLTCPTH",  "Blitter source C pointer high",                true),
    (0x04A, "BLTCPTL",  "Blitter source C pointer low",                 true),
    (0x04C, "BLTBPTH",  "Blitter source B pointer high",                true),
    (0x04E, "BLTBPTL",  "Blitter source B pointer low",                 true),
    (0x050, "BLTAPTH",  "Blitter source A pointer high",                true),
    (0x052, "BLTAPTL",  "Blitter source A pointer low",                 true),
    (0x054, "BLTDPTH",  "Blitter destination D pointer high",           true),
    (0x056, "BLTDPTL",  "Blitter destination D pointer low",            true),
    (0x058, "BLTSIZE",  "Blitter start and size (w/h)",                 true),
    (0x060, "BLTCMOD",  "Blitter source C modulo",                      true),
    (0x062, "BLTBMOD",  "Blitter source B modulo",                      true),
    (0x064, "BLTAMOD",  "Blitter source A modulo",                      true),
    (0x066, "BLTDMOD",  "Blitter destination D modulo",                 true),
    (0x070, "BLTCDAT",  "Blitter source C data",                        true),
    (0x072, "BLTBDAT",  "Blitter source B data",                        true),
    (0x074, "BLTADAT",  "Blitter source A data",                        true),
    (0x078, "SPRHDAT",  "Sprite H data (ECS)",                          true),
    (0x07E, "CLXCON",   "Collision control",                            true),
    (0x080, "INTENA",   "Interrupt enable bits (write — bit 15 = set/clear)",true),
    (0x082, "INTREQ",   "Interrupt request bits (write)",               true),
    (0x084, "ADKCON",   "Audio/disk/UART control",                      true),
    (0x086, "DMACON",   "DMA control write (bit 15 = set/clear)",       true),
    (0x088, "COP1LCH",  "Copper first location pointer high",           true),
    (0x08A, "COP1LCL",  "Copper first location pointer low",            true),
    (0x08C, "COP2LCH",  "Copper second location pointer high",          true),
    (0x08E, "COP2LCL",  "Copper second location pointer low",           true),
    (0x090, "COPJMP1",  "Restart Copper at first location",             true),
    (0x092, "COPJMP2",  "Restart Copper at second location",            true),
    (0x094, "COPINS",   "Copper instruction fetch identity",            true),
    (0x096, "DIWSTRT",  "Display window start (upper left vert-horiz)", true),
    (0x098, "DIWSTOP",  "Display window stop (lower right -vert-horiz)",true),
    (0x09A, "DDFSTRT",  "Display bitplane data fetch start",            true),
    (0x09C, "DDFSTOP",  "Display bitplane data fetch stop",             true),
    (0x09E, "DMACON",   "DMA control (alt — duplicate)",                true),
    (0x100, "BPLCON0",  "Bitplane control (color depth, HAM, etc.)",    true),
    (0x102, "BPLCON1",  "Bitplane control (scroll values)",             true),
    (0x104, "BPLCON2",  "Bitplane control (priority, sprite)",          true),
    (0x106, "BPLCON3",  "Bitplane control (ECS/AGA)",                   true),
    (0x108, "BPL1MOD",  "Bitplane modulo (odd planes)",                 true),
    (0x10A, "BPL2MOD",  "Bitplane modulo (even planes)",                true),
    (0x180, "COLOR00",  "Color table 0 — background",                   true),
    (0x182, "COLOR01",  "Color table 1",                                true),
    // ... 32 color regs total; abbreviated here
];

/// Look up an Amiga custom chip register.
#[must_use]
pub fn amiga_custom_reg(offset: u32) -> Option<(&'static str, &'static str)> {
    AMIGA_CUSTOM_REGS
        .iter()
        .find(|e| e.0 == offset)
        .map(|e| (e.1, e.2))
}

/// Amiga CIA (Complex Interface Adapter) register offsets.
/// CIAA at 0xBFE001, CIAB at 0xBFD000 (byte-wide, odd addresses).
pub static CIA_REGS: &[(u8, &str, &str)] = &[
    (0x00, "PRA",  "Port A data (CIAA: FIR1/FIR0/RDY/TK0/WPRO/CHNG/LED/OVL)"),
    (0x01, "PRB",  "Port B data (CIAA: parallel port / CIAB: drive enables)"),
    (0x02, "DDRA", "Data direction register A"),
    (0x03, "DDRB", "Data direction register B"),
    (0x04, "TALO", "Timer A low byte"),
    (0x05, "TAHI", "Timer A high byte"),
    (0x06, "TBLO", "Timer B low byte"),
    (0x07, "TBHI", "Timer B high byte"),
    (0x08, "TODLO","Time-of-Day counter bits 7-0"),
    (0x09, "TODMID","TOD counter bits 15-8"),
    (0x0A, "TODHI","TOD counter bits 23-16"),
    (0x0C, "SDR",  "Serial data register"),
    (0x0D, "ICR",  "Interrupt control register"),
    (0x0E, "CRA",  "Control register A"),
    (0x0F, "CRB",  "Control register B"),
];

/// Amiga interrupt bits (INTENA/INTREQ).
pub static AMIGA_INT_BITS: &[(u8, &str, &str)] = &[
    (0,  "TBE",   "Serial transmit buffer empty"),
    (1,  "DSKBLK","Disk block finished"),
    (2,  "SOFT",  "Software interrupt"),
    (3,  "PORTS", "I/O ports & timers (CIA-A)"),
    (4,  "COPER", "Copper"),
    (5,  "VERTB", "Vertical blank"),
    (6,  "BLIT",  "Blitter done"),
    (7,  "AUD0",  "Audio channel 0 block finished"),
    (8,  "AUD1",  "Audio channel 1 block finished"),
    (9,  "AUD2",  "Audio channel 2 block finished"),
    (10, "AUD3",  "Audio channel 3 block finished"),
    (11, "RBF",   "Serial receive buffer full"),
    (12, "DSKSYN","Disk sync register match"),
    (13, "EXTER", "External interrupt (CIA-B)"),
    (14, "INTEN", "Master interrupt enable (bit 14 only in INTENA)"),
    (15, "SETCLR","Set (1) or clear (0) named bits (write only)"),
];

/// Amiga DMA channel bits (DMACON).
pub static AMIGA_DMA_BITS: &[(u8, &str)] = &[
    (0,  "AUD0EN  — audio channel 0 DMA enable"),
    (1,  "AUD1EN  — audio channel 1 DMA enable"),
    (2,  "AUD2EN  — audio channel 2 DMA enable"),
    (3,  "AUD3EN  — audio channel 3 DMA enable"),
    (4,  "DSKEN   — disk DMA enable"),
    (5,  "SPREN   — sprites DMA enable"),
    (6,  "BLTEN   — blitter DMA enable"),
    (7,  "COPEN   — copper DMA enable"),
    (8,  "BPLEN   — bitplanes DMA enable"),
    (9,  "DMAEN   — master DMA enable"),
    (10, "BLTPRI  — blitter DMA priority over CPU"),
    (14, "BZERO   — blitter zero flag (read only)"),
    (15, "SETCLR  — set (1) or clear (0) bits"),
];

// ── Sega Genesis / Mega Drive ─────────────────────────────────────────────────

/// Genesis memory map regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenesisRegion {
    /// 0x000000–0x3FFFFF: ROM / cartridge space.
    CartRom,
    /// 0x400000–0x7FFFFF: Reserved (or cart RAM on some mappers).
    Reserved,
    /// 0x800000–0x9FFFFF: Reserved.
    Reserved2,
    /// 0xA00000–0xA0FFFF: Z80 address space (68k views it through window).
    Z80Ram,
    /// 0xA10000–0xA1001F: I/O ports (version, controller 1/2, expansion).
    IoPorts,
    /// 0xA11000–0xA11100: Z80 BUSREQ/RESET control.
    Z80Control,
    /// 0xA13000–0xA13FFF: SRAM access enable / TMSS.
    SramControl,
    /// 0xC00000–0xC0001F: VDP registers/data/control.
    Vdp,
    /// 0xC00020–0xC0007F: VDP alias / PSG.
    VdpAlias,
    /// 0xE00000–0xFFFFFF: Work RAM (64 KB, mirrored).
    WorkRam,
}

impl GenesisRegion {
    #[must_use]
    pub const fn from_address(addr: u32) -> Self {
        match addr {
            0x0000_0000..=0x003F_FFFF => Self::CartRom,
            0x0080_0000..=0x009F_FFFF => Self::Reserved2,
            0x00A0_0000..=0x00A0_FFFF => Self::Z80Ram,
            0x00A1_0000..=0x00A1_001F => Self::IoPorts,
            0x00A1_1000..=0x00A1_10FF => Self::Z80Control,
            0x00A1_3000..=0x00A1_3FFF => Self::SramControl,
            0x00C0_0000..=0x00C0_001F => Self::Vdp,
            0x00C0_0020..=0x00C0_07FF => Self::VdpAlias,
            0x00E0_0000..=0x00FF_FFFF => Self::WorkRam,
            _ => Self::Reserved,
        }
    }
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CartRom     => "CART_ROM",
            Self::Reserved    => "RESERVED",
            Self::Reserved2   => "RESERVED2",
            Self::Z80Ram      => "Z80_RAM",
            Self::IoPorts     => "IO_PORTS",
            Self::Z80Control  => "Z80_CONTROL",
            Self::SramControl => "SRAM_CONTROL",
            Self::Vdp         => "VDP",
            Self::VdpAlias    => "VDP_ALIAS",
            Self::WorkRam     => "WORK_RAM",
        }
    }
}

/// Genesis VDP registers (write to control port 0xC00004 with command word).
pub static GENESIS_VDP_REGS: &[(u8, &str, &str)] = &[
    (0x00, "VDP_R0",  "Mode Set Register 1 — H-interrupt enable, counter stop"),
    (0x01, "VDP_R1",  "Mode Set Register 2 — display enable, V-interrupt, DMA, V28/30"),
    (0x02, "VDP_R2",  "Plane A name table address (bits 15:13 of VRAM addr >> 10)"),
    (0x03, "VDP_R3",  "Window name table address"),
    (0x04, "VDP_R4",  "Plane B name table address"),
    (0x05, "VDP_R5",  "Sprite attribute table address"),
    (0x06, "VDP_R6",  "Sprite pattern generator (always 0)"),
    (0x07, "VDP_R7",  "Background colour — palette/colour index"),
    (0x08, "VDP_R8",  "Horizontal scroll mode"),
    (0x09, "VDP_R9",  "(reserved, set 0)"),
    (0x0A, "VDP_RA",  "H-interrupt counter"),
    (0x0B, "VDP_RB",  "Mode Set Register 3 — ext interrupt, V-scroll, H-scroll"),
    (0x0C, "VDP_RC",  "Mode Set Register 4 — H40/H32, S/TE, SHI, LSM1/0"),
    (0x0D, "VDP_RD",  "Horizontal scroll data address"),
    (0x0E, "VDP_RE",  "(reserved, set 0)"),
    (0x0F, "VDP_RF",  "Auto-increment data"),
    (0x10, "VDP_R10", "Scroll size — V and H scroll plane dimensions"),
    (0x11, "VDP_R11", "Window plane H position"),
    (0x12, "VDP_R12", "Window plane V position"),
    (0x13, "VDP_R13", "DMA length low"),
    (0x14, "VDP_R14", "DMA length high"),
    (0x15, "VDP_R15", "DMA source low"),
    (0x16, "VDP_R16", "DMA source mid"),
    (0x17, "VDP_R17", "DMA source high + DMA type (fill/copy/68k)"),
];

/// Look up a Genesis VDP register.
#[must_use]
pub fn genesis_vdp_reg(reg: u8) -> Option<(&'static str, &'static str)> {
    GENESIS_VDP_REGS
        .iter()
        .find(|e| e.0 == reg)
        .map(|e| (e.1, e.2))
}

/// Genesis I/O port register offsets (base 0xA10000).
pub static GENESIS_IO_REGS: &[(u32, &str, &str)] = &[
    (0x00A1_0000, "VERSION", "Version register — region, model, revision"),
    (0x00A1_0002, "CTRL1",   "Controller 1 data register"),
    (0x00A1_0004, "CTRL2",   "Controller 2 data register"),
    (0x00A1_0006, "CTRLEXP", "Expansion port data"),
    (0x00A1_0008, "IOMODE1", "Controller 1 I/O direction"),
    (0x00A1_000A, "IOMODE2", "Controller 2 I/O direction"),
    (0x00A1_000C, "IOMODEEXP","Expansion I/O direction"),
    (0x00A1_000E, "TXDATA1", "Controller 1 TX data (serial)"),
    (0x00A1_0010, "RXDATA1", "Controller 1 RX data (serial)"),
    (0x00A1_0012, "SCTRL1",  "Controller 1 serial control"),
    (0x00A1_0014, "TXDATA2", "Controller 2 TX data"),
    (0x00A1_0016, "RXDATA2", "Controller 2 RX data"),
    (0x00A1_0018, "SCTRL2",  "Controller 2 serial control"),
    (0x00A1_1100, "BUSREQ",  "Z80 bus request (write 1 to request, read for ack)"),
    (0x00A1_100E, "ZRESET",  "Z80 reset control (write 0 to reset, 1 to run)"),
];

/// Look up a Genesis I/O register.
#[must_use]
pub fn genesis_io_reg(addr: u32) -> Option<(&'static str, &'static str)> {
    GENESIS_IO_REGS
        .iter()
        .find(|e| e.0 == addr)
        .map(|e| (e.1, e.2))
}

/// Genesis interrupt levels.
pub static GENESIS_IRQ_LEVELS: &[(u8, &str)] = &[
    (2, "H-BLANK — horizontal blank interrupt (VDP register RA counter)"),
    (4, "V-BLANK — vertical blank interrupt"),
    (6, "EXT — external interrupt from controller port"),
];

// ── Macintosh 68k ────────────────────────────────────────────────────────────

/// Macintosh A-line (LINEA) trap mechanism.
///
/// Instructions with opcode bits 15:12 = 1010 (0xA) trigger a software trap
/// through the Trap Dispatch Table.  The lower 12 bits encode the trap number.
/// Traps with bit 11 set are Toolbox calls; bit 11 clear are OS traps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacTrapType {
    /// Trap number < 0x800 — Operating System Trap (MOVEQ / register-based).
    OsTrap,
    /// Trap number >= 0x800 — Toolbox Trap (Pascal convention / stack-based).
    ToolboxTrap,
}

/// Decode a Macintosh A-line trap number into name + type.
#[must_use]
pub fn mac_trap_name(trap_num: u16) -> Option<(&'static str, MacTrapType)> {
    let trap = trap_num & 0x0FFF;
    MAC_TRAPS.iter().find(|e| e.0 == trap).map(|e| {
        let kind = if trap >= 0x800 { MacTrapType::ToolboxTrap } else { MacTrapType::OsTrap };
        (e.1, kind)
    })
}

/// Mac OS and Toolbox trap table (selected entries).
pub static MAC_TRAPS: &[(u16, &str)] = &[
    // OS traps (0x000 – 0x0FF)
    (0x000, "_Open"),
    (0x001, "_Close"),
    (0x002, "_Read"),
    (0x003, "_Write"),
    (0x004, "_Control"),
    (0x005, "_Status"),
    (0x006, "_KillIO"),
    (0x007, "_GetVolInfo"),
    (0x008, "_Create"),
    (0x009, "_Delete"),
    (0x00A, "_OpenRF"),
    (0x00B, "_RenameFile"),
    (0x00C, "_GetFileInfo"),
    (0x00D, "_SetFileInfo"),
    (0x00E, "_UnmountVol"),
    (0x00F, "_MountVol"),
    (0x010, "_Allocate"),
    (0x011, "_GetEOF"),
    (0x012, "_SetEOF"),
    (0x013, "_FlushVol"),
    (0x014, "_GetVol"),
    (0x015, "_SetVol"),
    (0x016, "_FInitQueue"),
    (0x017, "_Eject"),
    (0x018, "_GetFPos"),
    (0x019, "_InitZone"),
    (0x01B, "_SetZone"),
    (0x01C, "_FreeMem"),
    (0x01E, "_NewPtr"),
    (0x01F, "_DisposPtr"),
    (0x020, "_SetPtrSize"),
    (0x021, "_GetPtrSize"),
    (0x022, "_NewHandle"),
    (0x023, "_DisposHandle"),
    (0x024, "_SetHandleSize"),
    (0x025, "_GetHandleSize"),
    (0x026, "_HandleZone"),
    (0x027, "_ReallocHandle"),
    (0x028, "_RecoverHandle"),
    (0x029, "_HLock"),
    (0x02A, "_HUnlock"),
    (0x02B, "_EmptyHandle"),
    (0x02C, "_InitApplZone"),
    (0x02D, "_SetApplLimit"),
    (0x02E, "_BlockMove"),
    (0x02F, "_PostEvent"),
    (0x030, "_OSEventAvail"),
    (0x031, "_GetOSEvent"),
    (0x032, "_FlushEvents"),
    (0x033, "_VInstall"),
    (0x034, "_VRemove"),
    (0x035, "_OffLine"),
    (0x036, "_MoreMasters"),
    (0x037, "_ReadParam"),
    (0x038, "_WriteParam"),
    (0x039, "_ReadDateTime"),
    (0x03A, "_SetDateTime"),
    (0x03B, "_Delay"),
    (0x03C, "_CmpString"),
    (0x03D, "_DrvrInstall"),
    (0x03E, "_DrvrRemove"),
    (0x03F, "_InitUtil"),
    (0x040, "_ResrvMem"),
    (0x041, "_SetFilLock"),
    (0x042, "_RstFilLock"),
    (0x043, "_SetFilType"),
    (0x044, "_SetFPos"),
    (0x045, "_FlushFile"),
    (0x046, "_GetTrapAddress"),
    (0x047, "_SetTrapAddress"),
    (0x049, "_HPurge"),
    (0x04A, "_HNoPurge"),
    (0x04B, "_SetGrowZone"),
    (0x04C, "_CompactMem"),
    (0x04D, "_PurgeMem"),
    (0x04E, "_AddDrive"),
    (0x04F, "_RdVerify"),
    (0x050, "_SCSIDispatch"),
    // Toolbox traps (0x800+)
    (0x800, "_SoundDispatch"),
    (0x801, "_SoundBegin"),
    (0x802, "_SoundEnd"),
    (0x803, "_SetSoundVol"),
    (0x804, "_GetSoundVol"),
    (0x808, "_SysBeep"),
    (0x809, "_SysError"),
    (0x81E, "_InitGraf"),
    (0x81F, "_OpenPort"),
    (0x820, "_InitPort"),
    (0x821, "_ClosePort"),
    (0x822, "_SetPort"),
    (0x823, "_GetPort"),
    (0x824, "_GrafDevice"),
    (0x825, "_PortSize"),
    (0x826, "_MovePortTo"),
    (0x827, "_SetOrigin"),
    (0x828, "_SetClip"),
    (0x829, "_GetClip"),
    (0x82A, "_ClipRect"),
    (0x82B, "_BackPat"),
    (0x82C, "_CloseRgn"),
    (0x82D, "_BitMapRgn"),
    (0x82E, "_AddPt"),
    (0x82F, "_SubPt"),
    (0x830, "_SetPt"),
    (0x831, "_EqualPt"),
    (0x832, "_StdText"),
    (0x833, "_DrawChar"),
    (0x834, "_DrawString"),
    (0x835, "_DrawText"),
    (0x836, "_TextWidth"),
    (0x837, "_TextFace"),
    (0x838, "_TextMode"),
    (0x839, "_TextSize"),
    (0x83A, "_SetSpaceExtra"),
    (0x83B, "_CharWidth"),
    (0x83C, "_StringWidth"),
    (0x83D, "_TextFont"),
    (0x83E, "_ForeColor"),
    (0x83F, "_BackColor"),
    (0x840, "_ColorBit"),
    (0x841, "_GetFontInfo"),
    (0x87F, "_NewControl"),
    (0x880, "_DisposControl"),
    (0x881, "_KillControls"),
    (0x882, "_ShowControl"),
    (0x883, "_HideControl"),
    (0x884, "_MoveControl"),
    (0x885, "_GetCRefCon"),
    (0x886, "_SetCRefCon"),
    (0x887, "_SizeControl"),
    (0x888, "_HiliteControl"),
    (0x889, "_GetCTitle"),
    (0x88A, "_SetCTitle"),
    (0x88B, "_GetCtlValue"),
    (0x88C, "_GetMinCtl"),
    (0x88D, "_GetMaxCtl"),
    (0x88E, "_SetCtlValue"),
    (0x88F, "_SetMinCtl"),
    (0x890, "_SetMaxCtl"),
    (0x891, "_TestControl"),
    (0x892, "_DragControl"),
    (0x893, "_TrackControl"),
    (0x894, "_DrawControls"),
    (0x895, "_ScrollRect"),
    (0x896, "_GetNextEvent"),
    (0x897, "_EventAvail"),
    (0x898, "_GetMouse"),
    (0x899, "_StillDown"),
    (0x89A, "_Button"),
    (0x89B, "_TickCount"),
    (0x89C, "_GetKeys"),
    (0x8F4, "_NewMenu"),
    (0x8F5, "_DisposMenu"),
    (0x8F6, "_AppendMenu"),
    (0x8F7, "_ClearMenuBar"),
    (0x8F8, "_InsertMenu"),
    (0x8F9, "_DeleteMenu"),
    (0x8FA, "_DrawMenuBar"),
    (0x8FB, "_HiliteMenu"),
    (0x8FC, "_EnableItem"),
    (0x8FD, "_DisableItem"),
    (0x8FE, "_MenuSelect"),
    (0x8FF, "_MenuKey"),
    (0x9A0, "_LoadSeg"),
    (0x9A1, "_UnloadSeg"),
    (0x9A2, "_Launch"),
    (0x9A3, "_Chain"),
    (0x9A4, "_ExitToShell"),
    (0x9A5, "_GetAppParms"),
    (0x9A6, "_GetResInfo"),
    (0x9A7, "_GetSeg"),
    (0x9A8, "_SetResPurge"),
    (0x9A9, "_GetFileType"),
    (0x9AA, "_NewDialog"),
    (0x9AB, "_GetNewDialog"),
    (0x9AC, "_SelectWindow"),
    (0x9AD, "_HideWindow"),
    (0x9AE, "_ShowHide"),
    (0x9AF, "_TrackGoAway"),
    (0x9B0, "_DragWindow"),
    (0x9B1, "_GrowWindow"),
    (0x9B2, "_ZoomWindow"),
    (0x9B3, "_BeginUpdate"),
    (0x9B4, "_EndUpdate"),
    (0x9B5, "_InvalRgn"),
    (0x9B6, "_InvalRect"),
    (0x9B7, "_ValidRgn"),
    (0x9B8, "_ValidRect"),
    (0x9B9, "_PaintBehind"),
    (0x9BA, "_CalcVis"),
    (0x9BB, "_CalcVisBehind"),
    (0x9BC, "_ClipAbove"),
    (0x9BD, "_PaintOne"),
    (0x9BE, "_PaintAll"),
    (0x9BF, "_SetWinColor"),
    (0x9C0, "_GetWinColor"),
    (0x9C1, "_NewWindow"),
    (0x9C2, "_DisposWindow"),
    (0x9C3, "_ShowWindow"),
    (0x9C4, "_BringToFront"),
    (0x9C5, "_SendBehind"),
    (0x9C6, "_WindowSelect"),
    (0x9C7, "_FrontWindow"),
    (0x9C8, "_SetWTitle"),
    (0x9C9, "_GetWTitle"),
    (0x9CA, "_GetNewWindow"),
    (0x9CB, "_GetNewCWindow"),
    (0x9CC, "_SetWindowPic"),
    (0x9CD, "_GetWindowPic"),
    (0x9CE, "_ResizePalette"),
];

/// Detect whether a 68k A-line instruction is a Macintosh Toolbox trap.
#[must_use]
pub const fn is_mac_toolbox_call(word: u16) -> bool {
    (word >> 12) == 0xA
}

/// Extract trap number from a 68k A-line instruction word.
#[must_use]
pub const fn mac_trap_number(word: u16) -> u16 {
    word & 0x0FFF
}

// ── Sun-3 (SunOS) ─────────────────────────────────────────────────────────────

/// Sun-3 uses a 68020 with `SunOS` 4.x.  System calls are made via TRAP #0.
/// Register A0 holds the syscall number; arguments follow `SunOS` calling conv.
pub static SUNOS_SYSCALLS: &[(u16, &str, &str)] = &[
    (0,   "SYS_SYSCALL",  "Indirect system call"),
    (1,   "SYS_EXIT",     "Process exit"),
    (2,   "SYS_FORK",     "Create child process"),
    (3,   "SYS_READ",     "Read from file descriptor"),
    (4,   "SYS_WRITE",    "Write to file descriptor"),
    (5,   "SYS_OPEN",     "Open file"),
    (6,   "SYS_CLOSE",    "Close file descriptor"),
    (7,   "SYS_WAIT4",    "Wait for process"),
    (8,   "SYS_CREAT",    "Create file"),
    (9,   "SYS_LINK",     "Create hard link"),
    (10,  "SYS_UNLINK",   "Remove directory entry"),
    (11,  "SYS_EXECV",    "Execute file (no env)"),
    (12,  "SYS_CHDIR",    "Change working directory"),
    (13,  "SYS_FCHDIR",   "Change working directory (fd)"),
    (14,  "SYS_MKNOD",    "Create special file"),
    (15,  "SYS_CHMOD",    "Change file mode"),
    (16,  "SYS_CHOWN",    "Change file owner"),
    (17,  "SYS_BRK",      "Change data segment size"),
    (18,  "SYS_STAT",     "Get file status"),
    (19,  "SYS_LSEEK",    "Reposition read/write offset"),
    (20,  "SYS_GETPID",   "Get process ID"),
    (21,  "SYS_MOUNT",    "Mount file system"),
    (22,  "SYS_UMOUNT",   "Unmount file system"),
    (23,  "SYS_SETUID",   "Set user ID"),
    (24,  "SYS_GETUID",   "Get user ID"),
    (25,  "SYS_STIME",    "Set system time"),
    (26,  "SYS_PTRACE",   "Process trace"),
    (27,  "SYS_ALARM",    "Set alarm clock"),
    (28,  "SYS_FSTAT",    "Get file status by descriptor"),
    (29,  "SYS_PAUSE",    "Stop until signal"),
    (30,  "SYS_UTIME",    "Set file access and modification times"),
    (33,  "SYS_ACCESS",   "Check accessibility of file"),
    (34,  "SYS_NICE",     "Change process priority"),
    (36,  "SYS_SYNC",     "Sync file system"),
    (37,  "SYS_KILL",     "Send signal to process"),
    (38,  "SYS_STAT2",    "Get file status (SunOS 4)"),
    (41,  "SYS_DUP",      "Duplicate file descriptor"),
    (42,  "SYS_PIPE",     "Create pipe"),
    (43,  "SYS_TIMES",    "Get process times"),
    (44,  "SYS_PROFIL",   "Control profiling"),
    (46,  "SYS_SETGID",   "Set group ID"),
    (47,  "SYS_GETGID",   "Get group ID"),
    (48,  "SYS_SIGNAL",   "Set signal disposition"),
    (51,  "SYS_ACCT",     "Enable/disable accounting"),
    (54,  "SYS_IOCTL",    "Control device"),
    (56,  "SYS_REBOOT",   "Reboot system"),
    (57,  "SYS_SYMLINK",  "Create symbolic link"),
    (58,  "SYS_READLINK", "Read symbolic link"),
    (59,  "SYS_EXECVE",   "Execute file"),
    (60,  "SYS_UMASK",    "Set file creation mode mask"),
    (61,  "SYS_CHROOT",   "Change root directory"),
    (62,  "SYS_FSTAT2",   "Get file status by descriptor (SunOS 4)"),
    (63,  "SYS_GETPAGESIZE","Get page size"),
    (64,  "SYS_MREMAP",   "Remap memory"),
    (65,  "SYS_VFORK",    "Spawn child (shares address space)"),
    (73,  "SYS_MUNMAP",   "Remove a mapping"),
    (74,  "SYS_MPROTECT", "Change memory protection"),
    (75,  "SYS_MADVISE",  "Memory advice"),
    (77,  "SYS_VHANGUP",  "Virtually hangup terminal"),
    (82,  "SYS_SETGROUPS","Set supplementary group IDs"),
    (83,  "SYS_GETGROUPS","Get supplementary group IDs"),
    (84,  "SYS_SETPGRP",  "Set process group"),
    (85,  "SYS_GETPGRP",  "Get process group"),
    (86,  "SYS_SETITIMER","Set value of interval timer"),
    (87,  "SYS_WAIT3",    "Wait for child (3-arg)"),
    (88,  "SYS_SWAPON",   "Add swap device"),
    (89,  "SYS_GETITIMER","Get value of interval timer"),
    (90,  "SYS_GETHOSTNAME","Get hostname"),
    (91,  "SYS_SETHOSTNAME","Set hostname"),
    (92,  "SYS_GETDTABLESIZE","Get number of open files limit"),
    (93,  "SYS_DUP2",     "Duplicate file descriptor to given number"),
    (95,  "SYS_FCNTL",    "File control"),
    (96,  "SYS_SELECT",   "Synchronous I/O multiplexing"),
    (98,  "SYS_FSYNC",    "Synchronize file state"),
    (99,  "SYS_SETPRIORITY","Set process/group/user priority"),
    (100, "SYS_SOCKET",   "Create endpoint for communication"),
    (101, "SYS_CONNECT",  "Connect socket"),
    (102, "SYS_ACCEPT",   "Accept connection"),
    (103, "SYS_GETPRIORITY","Get process/group/user priority"),
    (104, "SYS_SEND",     "Send message on socket"),
    (105, "SYS_RECV",     "Receive message from socket"),
    (106, "SYS_SIGRETURN","Return from signal"),
    (107, "SYS_BIND",     "Bind name to socket"),
    (108, "SYS_SETSOCKOPT","Set socket options"),
    (109, "SYS_LISTEN",   "Listen for connections"),
    (110, "SYS_SIGVEC",   "Set signal disposition (BSD style)"),
    (111, "SYS_SIGBLOCK", "Block signals"),
    (112, "SYS_SIGSETMASK","Set signal mask"),
    (113, "SYS_SIGPAUSE", "Pause until signal received"),
    (114, "SYS_SIGSTACK", "Set and/or get signal stack context"),
    (115, "SYS_RECVMSG",  "Receive message from socket"),
    (116, "SYS_SENDMSG",  "Send message on socket"),
    (117, "SYS_VTRACE",   "SunOS trace facility"),
    (118, "SYS_GETTIMEOFDAY","Get date and time"),
    (119, "SYS_GETRUSAGE","Get resource usage"),
    (120, "SYS_GETSOCKOPT","Get socket options"),
    (121, "SYS_GETMSG",   "Get message from stream"),
    (122, "SYS_READV",    "Read from file descriptor into vector"),
    (123, "SYS_WRITEV",   "Write to file descriptor from vector"),
    (124, "SYS_SETTIMEOFDAY","Set date and time"),
    (125, "SYS_FCHOWN",   "Change owner and group of file by descriptor"),
    (126, "SYS_FCHMOD",   "Change mode of file by descriptor"),
    (127, "SYS_RECVFROM", "Receive data from socket"),
    (128, "SYS_SETREUID", "Set real and effective user ID"),
    (129, "SYS_SETREGID", "Set real and effective group ID"),
    (130, "SYS_RENAME",   "Rename file"),
    (131, "SYS_TRUNCATE", "Truncate file to specified length"),
    (132, "SYS_FTRUNCATE","Truncate file by descriptor"),
    (133, "SYS_FLOCK",    "Apply or remove file lock"),
    (134, "SYS_SENDTO",   "Send data from socket"),
    (135, "SYS_SHUTDOWN", "Shut down socket connection"),
    (136, "SYS_SOCKETPAIR","Create pair of connected sockets"),
    (137, "SYS_MKDIR",    "Create directory"),
    (138, "SYS_RMDIR",    "Remove directory"),
    (139, "SYS_UTIMES",   "Set file access and modification times"),
    (140, "SYS_SIGCLEANUP","Clean up after signal"),
    (141, "SYS_ADJTIME",  "Correct time to synchronize system clock"),
    (142, "SYS_GETPEERNAME","Get name of connected peer"),
    (143, "SYS_GETHOSTID","Get identifier of current host"),
    (144, "SYS_SETHOSTID","Set identifier of current host"),
    (145, "SYS_GETRLIMIT","Get maximum system resource consumption"),
    (146, "SYS_SETRLIMIT","Set maximum system resource consumption"),
    (147, "SYS_KILLPG",   "Send signal to process group"),
    (148, "SYS_SETSID",   "Create session and set process group"),
    (149, "SYS_QUOTACTL", "Manipulate disk quotas"),
    (150, "SYS_NFS_GETFH","Get NFS file handle"),
    (155, "SYS_ASYNCDAEMON","NFS async daemon"),
    (156, "SYS_GETDOMAINNAME","Get domain name"),
    (157, "SYS_SETDOMAINNAME","Set domain name"),
    (162, "SYS_EXPORTFS", "Export/unexport NFS directories"),
    (163, "SYS_MMAP",     "Map file or device into memory"),
    (165, "SYS_SYSCONF",  "Get configurable system variable"),
    (166, "SYS_WAIT",     "Wait for child"),
    (167, "SYS_MODULE",   "Load/unload kernel module"),
    (168, "SYS_AUDITSYS", "Auditing system call"),
];

/// Look up a SunOS/Sun-3 system call by number.
#[must_use]
pub fn sunos_syscall(num: u16) -> Option<(&'static str, &'static str)> {
    SUNOS_SYSCALLS
        .iter()
        .find(|e| e.0 == num)
        .map(|e| (e.1, e.2))
}

/// Detect the system call number from a TRAP #0 + instruction context.
///
/// On Sun-3/SunOS, the convention is:
///   MOVE.W #<`syscall_num`>, -(SP)   ; or via `D0`
///   TRAP   #0
///
/// Returns the syscall number from the 2-byte displacement word before TRAP,
/// if the bytes match the standard pattern.
#[must_use]
pub fn detect_sunos_syscall(bytes_before_trap: &[u8]) -> Option<u16> {
    // Pattern: MOVE.W #n,-(SP) = 0x3F3C nn nn (6 bytes before TRAP)
    if bytes_before_trap.len() >= 4
        && bytes_before_trap[0] == 0x3F
        && bytes_before_trap[1] == 0x3C
    {
        return Some(u16::from_be_bytes([bytes_before_trap[2], bytes_before_trap[3]]));
    }
    None
}

// ── Platform detector ──────────────────────────────────────────────────────────

/// High-level 68k platform kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum M68kPlatform {
    Amiga,
    SegaGenesis,
    Mac68k,
    Sun3,
    AtariST,
    Unknown,
}

impl M68kPlatform {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Amiga       => "Amiga (OCS/ECS/AGA)",
            Self::SegaGenesis => "Sega Genesis / Mega Drive",
            Self::Mac68k      => "Apple Macintosh (68k)",
            Self::Sun3        => "Sun-3 / SunOS 4",
            Self::AtariST     => "Atari ST",
            Self::Unknown     => "Unknown 68k Platform",
        }
    }
}

/// Heuristic platform detection for 68k code.
#[must_use]
pub fn heuristic_platform(code: &[u8]) -> M68kPlatform {
    let mut amiga_score   = 0i32;
    let mut genesis_score = 0i32;
    let mut mac_score     = 0i32;
    let mut sun_score     = 0i32;

    let mut i = 0usize;
    while i + 1 < code.len() {
        let word = u16::from_be_bytes([code[i], code[i+1]]);

        // A-line: Macintosh toolbox
        if (word >> 12) == 0xA {
            mac_score += 5;
            i += 2;
            continue;
        }
        // TRAP #0: SunOS syscall
        if word == 0x4E40 {
            sun_score += 3;
        }
        // TRAP #15 or #14: Amiga/Atari
        if word == 0x4E4F {
            amiga_score += 3;  // Amiga dos TRAP #15
        }
        // LEA $DFF000,A6 or similar: Amiga custom chip access
        if word == 0x4CDF || (i + 5 < code.len()
            && code[i] == 0x41 && code[i+1] == 0xF9)
        {
            let next_long = u32::from_be_bytes([
                code.get(i+2).copied().unwrap_or(0),
                code.get(i+3).copied().unwrap_or(0),
                code.get(i+4).copied().unwrap_or(0),
                code.get(i+5).copied().unwrap_or(0),
            ]);
            if next_long == 0x00DF_F000 {
                amiga_score += 20;
            }
            if next_long == 0x00C0_0000 || next_long == 0x00C0_0004 {
                genesis_score += 20;
            }
        }
        // Genesis VDP access pattern (MOVE to 0xC00004)
        if i + 5 < code.len() && code[i] == 0x33 && code[i+1] == 0xC0 {
            let addr = u32::from_be_bytes([0, 0, code[i+2], code[i+3]]);
            if addr == 0x00C0_0004 || addr == 0x00C0_0000 {
                genesis_score += 10;
            }
        }
        i += 2;
    }

    let scores = [
        (amiga_score,   M68kPlatform::Amiga),
        (genesis_score, M68kPlatform::SegaGenesis),
        (mac_score,     M68kPlatform::Mac68k),
        (sun_score,     M68kPlatform::Sun3),
    ];
    let best = scores.iter().max_by_key(|s| s.0).copied();
    match best {
        Some((s, p)) if s > 0 => p,
        _ => M68kPlatform::Unknown,
    }
}
