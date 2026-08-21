//! MOS 6502 addressing mode decoder and memory model — **low-level layer**.
//!
//! Provides `Mos6502MemoryModel` (a 64 KB address space with stack support),
//! `AddressingModeInfo` (static string metadata keyed by short mode name), and
//! raw effective-address calculation functions that operate on plain `&[u8]`
//! memory slices.
//!
//! **Intentionally distinct from [`crate::mos6502_address_modes`]**, which is
//! the high-level layer: a rich typed `Mos6502AddressMode` enum (carrying the
//! decoded operand bytes), `EffectiveAddress`, cycle-count helpers, and the
//! `AddressModeDecoder` helper — all integrated with the [`crate::AddrMode`]
//! tag enum and the opcode table.

use crate::mos6502_disassembler::Mos6502Operand;

// ── AddressingModeInfo ────────────────────────────────────────────────────────

/// Static metadata about a 6502 addressing mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressingModeInfo {
    /// Human-readable mode name.
    pub mode: &'static str,
    /// Number of instruction bytes (including opcode).
    pub byte_count: u8,
    /// Plain-English description.
    pub description: &'static str,
}

/// All addressing mode descriptors, keyed by mode name.
#[must_use]
pub fn addressing_mode_info(mode: &str) -> Option<AddressingModeInfo> {
    match mode {
        "IMP" => Some(AddressingModeInfo {
            mode: "IMP",
            byte_count: 1,
            description: "Implied — operand is implicit in the instruction",
        }),
        "ACC" => Some(AddressingModeInfo {
            mode: "ACC",
            byte_count: 1,
            description: "Accumulator — operand is the A register",
        }),
        "IMM" => Some(AddressingModeInfo {
            mode: "IMM",
            byte_count: 2,
            description: "Immediate — 1-byte literal value follows opcode",
        }),
        "ZPG" => Some(AddressingModeInfo {
            mode: "ZPG",
            byte_count: 2,
            description: "Zero-page — 1-byte address in page $00",
        }),
        "ZPX" => Some(AddressingModeInfo {
            mode: "ZPX",
            byte_count: 2,
            description: "Zero-page,X — zero-page address + X (wraps in page $00)",
        }),
        "ZPY" => Some(AddressingModeInfo {
            mode: "ZPY",
            byte_count: 2,
            description: "Zero-page,Y — zero-page address + Y (wraps in page $00)",
        }),
        "ABS" => Some(AddressingModeInfo {
            mode: "ABS",
            byte_count: 3,
            description: "Absolute — full 16-bit address follows opcode (little-endian)",
        }),
        "ABX" => Some(AddressingModeInfo {
            mode: "ABX",
            byte_count: 3,
            description: "Absolute,X — absolute address + X; +1 cycle on page-cross",
        }),
        "ABY" => Some(AddressingModeInfo {
            mode: "ABY",
            byte_count: 3,
            description: "Absolute,Y — absolute address + Y; +1 cycle on page-cross",
        }),
        "IND" => Some(AddressingModeInfo {
            mode: "IND",
            byte_count: 3,
            description: "Indirect — address of a pointer; JMP only; page-wrap bug on $xxFF",
        }),
        "INX" => Some(AddressingModeInfo {
            mode: "INX",
            byte_count: 2,
            description: "(Indirect,X) — zero-page ptr = (zp+X)&$FF; reads 16-bit target",
        }),
        "INY" => Some(AddressingModeInfo {
            mode: "INY",
            byte_count: 2,
            description: "(Indirect),Y — read 16-bit ptr from zero-page; add Y; +1 on page-cross",
        }),
        "REL" => Some(AddressingModeInfo {
            mode: "REL",
            byte_count: 2,
            description: "Relative — signed 8-bit offset from next PC; branch instructions only",
        }),
        _ => None,
    }
}

// ── Effective address calculation ─────────────────────────────────────────────

/// Zero-page addition with 8-bit wrap: `(base + index) & 0xFF`.
#[inline]
#[must_use]
pub const fn effective_address_zp_x(zp: u8, x: u8) -> u8 {
    zp.wrapping_add(x)
}

/// Zero-page,Y with 8-bit wrap.
#[inline]
#[must_use]
pub const fn effective_address_zp_y(zp: u8, y: u8) -> u8 {
    zp.wrapping_add(y)
}

/// `(Indirect,X)` — `ptr_addr = (zp + X) & 0xFF`, then read 16-bit LE from `ptr_addr`.
///
/// The two pointer bytes are both read from zero-page with 8-bit wrap.
#[must_use]
pub fn effective_address_ind_x(mem: &[u8], zp: u8, x: u8) -> u16 {
    let ptr = zp.wrapping_add(x) as usize;
    let lo = mem[ptr & 0xFF];
    let hi = mem[(ptr.wrapping_add(1)) & 0xFF];
    u16::from_le_bytes([lo, hi])
}

/// `(Indirect),Y` — read 16-bit LE from zero-page address `zp`, then add Y.
///
/// Both bytes of the pointer are read from zero-page with 8-bit wrap.
#[must_use]
pub fn effective_address_ind_y(mem: &[u8], zp: u8, y: u8) -> u16 {
    let lo = mem[zp as usize];
    let hi = mem[zp.wrapping_add(1) as usize];
    u16::from_le_bytes([lo, hi]).wrapping_add(u16::from(y))
}

/// Detect whether adding `index` to `base` crosses a 256-byte page boundary.
#[inline]
#[must_use]
pub const fn cross_page_check(base: u16, index: u8) -> bool {
    (base & 0xFF00) != (base.wrapping_add(index as u16) & 0xFF00)
}

/// Wrap a zero-page address to stay within page 0.
#[inline]
#[must_use]
pub const fn zero_page_wrap(addr: u8) -> u16 {
    addr as u16
}

/// Compute the effective address for any `Mos6502Operand` given CPU state.
///
/// `mem` must be a 64 KB slice; `x`, `y` are the respective index registers;
/// `pc` is the current program counter (used to compute branch targets).
#[must_use]
pub fn decode_address(
    operand: &Mos6502Operand,
    mem: &[u8],
    x: u8,
    y: u8,
    pc: u16,
) -> u16 {
    match *operand {
        Mos6502Operand::Implied | Mos6502Operand::Accumulator => 0,
        Mos6502Operand::Immediate(_) => pc.wrapping_add(1),
        Mos6502Operand::ZeroPage(zp) => zero_page_wrap(zp),
        Mos6502Operand::ZeroPageX(zp) => zero_page_wrap(effective_address_zp_x(zp, x)),
        Mos6502Operand::ZeroPageY(zp) => zero_page_wrap(effective_address_zp_y(zp, y)),
        Mos6502Operand::Absolute(a) => a,
        Mos6502Operand::AbsoluteX(a) => a.wrapping_add(u16::from(x)),
        Mos6502Operand::AbsoluteY(a) => a.wrapping_add(u16::from(y)),
        Mos6502Operand::Indirect(ptr) => {
            // 6502 page-wrap bug: if ptr == $xxFF, high byte is read from $xx00
            let lo = mem[ptr as usize];
            let hi_addr = (ptr & 0xFF00) | ((ptr.wrapping_add(1)) & 0x00FF);
            let hi = mem[hi_addr as usize];
            u16::from_le_bytes([lo, hi])
        }
        Mos6502Operand::IndirectX(zp) => effective_address_ind_x(mem, zp, x),
        Mos6502Operand::IndirectY(zp) => effective_address_ind_y(mem, zp, y),
        Mos6502Operand::Relative(off) => {
            // Branch offset is relative to next instruction (PC + 2).
            pc.wrapping_add(2).wrapping_add(i16::from(off).cast_unsigned())
        }
    }
}

// ── Mos6502MemoryModel ────────────────────────────────────────────────────────

/// Emulated 64 KB address space with hardware stack support.
///
/// The stack lives at $0100–$01FF. SP points to the next free slot and
/// decrements on push, increments on pop (standard 6502 convention).
pub struct Mos6502MemoryModel {
    /// Raw 64 KB memory.
    pub ram: Vec<u8>,
    /// Stack pointer (low byte of $01xx address).
    pub sp: u8,
}

impl Mos6502MemoryModel {
    /// Create a new model initialized with all zeros; SP = $FF (empty stack).
    #[must_use]
    pub fn new() -> Self {
        Self {
            ram: vec![0u8; 0x10000],
            sp: 0xFF,
        }
    }

    /// Create a model pre-loaded with `data` at address `load_addr`.
    #[must_use]
    pub fn with_data(data: &[u8], load_addr: u16) -> Self {
        let mut model = Self::new();
        let start = load_addr as usize;
        let end = (start + data.len()).min(0x10000);
        model.ram[start..end].copy_from_slice(&data[..end - start]);
        model
    }

    /// Read one byte from the bus.
    #[must_use]
    pub fn read(&self, addr: u16) -> u8 {
        self.ram[addr as usize]
    }

    /// Write one byte to the bus.
    pub fn write(&mut self, addr: u16, val: u8) {
        self.ram[addr as usize] = val;
    }

    /// Read a 16-bit little-endian word from `addr` (with 16-bit address wrap).
    #[must_use]
    pub fn read_u16(&self, addr: u16) -> u16 {
        let lo = self.read(addr);
        let hi = self.read(addr.wrapping_add(1));
        u16::from_le_bytes([lo, hi])
    }

    /// Write a 16-bit little-endian word.
    pub fn write_u16(&mut self, addr: u16, val: u16) {
        let [lo, hi] = val.to_le_bytes();
        self.write(addr, lo);
        self.write(addr.wrapping_add(1), hi);
    }

    /// Push a byte onto the hardware stack at $01xx; SP decrements.
    pub fn stack_push(&mut self, val: u8) {
        let addr = 0x0100u16 | u16::from(self.sp);
        self.write(addr, val);
        self.sp = self.sp.wrapping_sub(1);
    }

    /// Pop a byte from the hardware stack; SP increments first (pre-increment).
    pub fn stack_pop(&mut self) -> u8 {
        self.sp = self.sp.wrapping_add(1);
        let addr = 0x0100u16 | u16::from(self.sp);
        self.read(addr)
    }

    /// Push a 16-bit value (high byte first, then low byte).
    pub fn stack_push_u16(&mut self, val: u16) {
        let [lo, hi] = val.to_le_bytes();
        self.stack_push(hi);
        self.stack_push(lo);
    }

    /// Pop a 16-bit value (low byte first, then high byte).
    pub fn stack_pop_u16(&mut self) -> u16 {
        let lo = self.stack_pop();
        let hi = self.stack_pop();
        u16::from_le_bytes([lo, hi])
    }

    /// Return the current stack depth (number of bytes on the stack).
    #[must_use]
    pub const fn stack_depth(&self) -> u8 {
        0xFF_u8.wrapping_sub(self.sp)
    }

    /// Peek at the top-of-stack without changing SP.
    #[must_use]
    pub fn stack_peek(&self) -> u8 {
        let addr = 0x0100u16 | u16::from(self.sp.wrapping_add(1));
        self.read(addr)
    }

    /// Copy a slice of memory starting at `addr`.
    #[must_use]
    pub fn read_slice(&self, addr: u16, len: usize) -> Vec<u8> {
        let start = addr as usize;
        let end = (start + len).min(0x10000);
        self.ram[start..end].to_vec()
    }

    /// Fill a range with a constant byte.
    pub fn fill(&mut self, addr: u16, len: usize, val: u8) {
        let start = addr as usize;
        let end = (start + len).min(0x10000);
        for b in &mut self.ram[start..end] {
            *b = val;
        }
    }

    /// Read the NMI / RESET / IRQ vectors.
    #[must_use]
    pub fn read_vectors(&self) -> (u16, u16, u16) {
        let nmi   = self.read_u16(0xFFFA);
        let reset = self.read_u16(0xFFFC);
        let irq   = self.read_u16(0xFFFE);
        (nmi, reset, irq)
    }
}

impl Default for Mos6502MemoryModel {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_64k() -> Vec<u8> {
        vec![0u8; 0x10000]
    }

    #[test]
    fn zp_x_wrap() {
        assert_eq!(effective_address_zp_x(0xFE, 0x03), 0x01);
    }

    #[test]
    fn zp_y_wrap() {
        assert_eq!(effective_address_zp_y(0xFF, 0x01), 0x00);
    }

    #[test]
    fn ind_x_reads_from_zp() {
        let mut mem = make_64k();
        // zp = 0x20, x = 0x04 => ptr_addr = 0x24
        mem[0x24] = 0xCD;
        mem[0x25] = 0xAB;
        let ea = effective_address_ind_x(&mem, 0x20, 0x04);
        assert_eq!(ea, 0xABCD);
    }

    #[test]
    fn ind_x_ptr_wraps_in_page0() {
        let mut mem = make_64k();
        // zp + x = 0xFF + 0x01 = 0x00 (wrap)
        mem[0x00] = 0x34;
        mem[0x01] = 0x12;
        let ea = effective_address_ind_x(&mem, 0xFF, 0x01);
        assert_eq!(ea, 0x1234);
    }

    #[test]
    fn ind_y_adds_y() {
        let mut mem = make_64k();
        mem[0x10] = 0x00;
        mem[0x11] = 0x03; // base = $0300
        let ea = effective_address_ind_y(&mem, 0x10, 0x05);
        assert_eq!(ea, 0x0305);
    }

    #[test]
    fn cross_page_no_cross() {
        assert!(!cross_page_check(0x0200, 0x50));
    }

    #[test]
    fn cross_page_crosses() {
        assert!(cross_page_check(0x02D0, 0x40));
    }

    #[test]
    fn decode_address_absolute_x() {
        let mem = make_64k();
        let op = Mos6502Operand::AbsoluteX(0x0300);
        let ea = decode_address(&op, &mem, 0x10, 0x00, 0x8000);
        assert_eq!(ea, 0x0310);
    }

    #[test]
    fn decode_address_absolute_y() {
        let mem = make_64k();
        let op = Mos6502Operand::AbsoluteY(0x0300);
        let ea = decode_address(&op, &mem, 0x00, 0x20, 0x8000);
        assert_eq!(ea, 0x0320);
    }

    #[test]
    fn decode_address_relative_forward() {
        let mem = make_64k();
        let op = Mos6502Operand::Relative(10);
        // next PC = pc + 2 = 0x100 + 2; + 10 = 0x10C
        let ea = decode_address(&op, &mem, 0, 0, 0x100);
        assert_eq!(ea, 0x010C);
    }

    #[test]
    fn decode_address_relative_backward() {
        let mem = make_64k();
        let op = Mos6502Operand::Relative(-4i8);
        // next PC = 0x0200 + 2 = 0x0202; - 4 = 0x01FE
        let ea = decode_address(&op, &mem, 0, 0, 0x0200);
        assert_eq!(ea, 0x01FE);
    }

    #[test]
    fn indirect_page_bug() {
        let mut mem = make_64k();
        // JMP ($01FF) — lo from $01FF, hi from $0100 (not $0200)
        mem[0x01FF] = 0x40;
        mem[0x0100] = 0x02; // should be read for high byte
        mem[0x0200] = 0xFF; // should NOT be read
        let op = Mos6502Operand::Indirect(0x01FF);
        let ea = decode_address(&op, &mem, 0, 0, 0);
        assert_eq!(ea, 0x0240);
    }

    #[test]
    fn stack_push_pop() {
        let mut m = Mos6502MemoryModel::new();
        m.stack_push(0x42);
        assert_eq!(m.sp, 0xFE);
        assert_eq!(m.stack_pop(), 0x42);
        assert_eq!(m.sp, 0xFF);
    }

    #[test]
    fn stack_push_pop_u16() {
        let mut m = Mos6502MemoryModel::new();
        m.stack_push_u16(0xBEEF);
        let v = m.stack_pop_u16();
        assert_eq!(v, 0xBEEF);
    }

    #[test]
    fn stack_depth_counting() {
        let mut m = Mos6502MemoryModel::new();
        assert_eq!(m.stack_depth(), 0);
        m.stack_push(1);
        m.stack_push(2);
        assert_eq!(m.stack_depth(), 2);
    }

    #[test]
    fn read_write_vectors() {
        let mut m = Mos6502MemoryModel::new();
        m.write_u16(0xFFFA, 0x8000);
        m.write_u16(0xFFFC, 0xC000);
        m.write_u16(0xFFFE, 0xFF00);
        let (nmi, reset, irq) = m.read_vectors();
        assert_eq!(nmi, 0x8000);
        assert_eq!(reset, 0xC000);
        assert_eq!(irq, 0xFF00);
    }

    #[test]
    fn addressing_mode_info_zpg() {
        let info = addressing_mode_info("ZPG").unwrap();
        assert_eq!(info.byte_count, 2);
        assert_eq!(info.mode, "ZPG");
    }

    #[test]
    fn addressing_mode_info_abs() {
        let info = addressing_mode_info("ABS").unwrap();
        assert_eq!(info.byte_count, 3);
    }

    #[test]
    fn addressing_mode_info_unknown() {
        assert!(addressing_mode_info("XYZ").is_none());
    }

    #[test]
    fn zero_page_wrap_is_16bit() {
        assert_eq!(zero_page_wrap(0x80), 0x0080u16);
    }

    #[test]
    fn memory_fill_and_read_slice() {
        let mut m = Mos6502MemoryModel::new();
        m.fill(0x0200, 4, 0xAB);
        let sl = m.read_slice(0x0200, 4);
        assert_eq!(sl, vec![0xAB, 0xAB, 0xAB, 0xAB]);
    }
}
