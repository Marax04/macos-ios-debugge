//! AVR software emulator with full register set, memory model, timers, and interrupt support.

// ---------------------------------------------------------------------------
// SREG flag bit positions
// ---------------------------------------------------------------------------

/// Carry flag bit in SREG.
pub const SREG_C: u8 = 0x01;
/// Zero flag bit in SREG.
pub const SREG_Z: u8 = 0x02;
/// Negative flag bit in SREG.
pub const SREG_N: u8 = 0x04;
/// Overflow flag bit in SREG.
pub const SREG_V: u8 = 0x08;
/// Sign flag bit in SREG (= N XOR V).
pub const SREG_S: u8 = 0x10;
/// Half-carry flag bit in SREG.
pub const SREG_H: u8 = 0x20;
/// Bit-copy storage (T).
pub const SREG_T: u8 = 0x40;
/// Global Interrupt Enable (I).
pub const SREG_I: u8 = 0x80;

// ---------------------------------------------------------------------------
// Memory sizes
// ---------------------------------------------------------------------------

/// Flash/program memory size in bytes (128 KiB = 64 Ki words).
pub const FLASH_SIZE: usize = 0x2_0000;
/// SRAM size in bytes.
pub const SRAM_SIZE: usize = 0x1000; // 4 KiB (ATmega328P)
/// EEPROM size in bytes.
pub const EEPROM_SIZE: usize = 0x400; // 1 KiB

/// Number of interrupt vectors (`ATmega328P` has `26`).
pub const VECTOR_COUNT: usize = 26;

// ---------------------------------------------------------------------------
// Peripheral stubs
// ---------------------------------------------------------------------------

/// Timer0 peripheral registers.
#[derive(Debug, Clone, Default)]
pub struct Timer0 {
    pub tccr0a: u8,
    pub tccr0b: u8,
    pub tcnt0: u8,
    pub ocr0a: u8,
    pub ocr0b: u8,
    pub tifr0: u8,
    pub timsk0: u8,
    /// Cycle counter for this timer (accumulates from `step()`).
    pub cycles: u64,
}

impl Timer0 {
    /// Tick the timer by `cycles` CPU cycles.  Updates TCNT0 and sets overflow flag.
    pub fn tick(&mut self, cycles: u64) {
        if self.tccr0b.trailing_zeros() >= 3 {
            return; // timer stopped
        }
        self.cycles = self.cycles.wrapping_add(cycles);
        let overflow = self.cycles / 256;
        self.cycles %= 256;
        self.tcnt0 = self.tcnt0.wrapping_add(u8::try_from(overflow).unwrap_or(u8::MAX));
        if overflow > 0 {
            self.tifr0 |= 0x01; // TOV0 — set whenever at least one overflow occurred
        }
    }
}

/// Timer1 peripheral registers (16-bit).
#[derive(Debug, Clone, Default)]
pub struct Timer1 {
    pub tccr1a: u8,
    pub tccr1b: u8,
    pub tcnt1: u16,
    pub ocr1a: u16,
    pub ocr1b: u16,
    pub tifr1: u8,
    pub timsk1: u8,
    /// Accumulated cycle counter (u64) to detect multiple 16-bit overflows.
    pub cycles: u64,
}

impl Timer1 {
    /// Tick the timer by `cycles` CPU cycles.
    pub fn tick(&mut self, cycles: u64) {
        if self.tccr1b.trailing_zeros() >= 3 {
            return;
        }
        self.cycles = self.cycles.wrapping_add(cycles);
        let overflow_count = self.cycles / 65536;
        self.cycles %= 65536;
        self.tcnt1 = self.tcnt1.wrapping_add(u16::try_from(overflow_count).unwrap_or(u16::MAX));
        if overflow_count > 0 {
            self.tifr1 |= 0x01; // TOV1 — set whenever at least one overflow occurred
        }
    }
}

// ---------------------------------------------------------------------------
// Interrupt vector table
// ---------------------------------------------------------------------------

/// An entry in the AVR interrupt vector table.
#[derive(Debug, Clone, Copy)]
pub struct IntVector {
    /// Vector index (0 = RESET, 1 = INT0, etc.)
    pub index: usize,
    /// Name of the interrupt.
    pub name: &'static str,
    /// Handler address in flash (word address, in bytes = addr * 2).
    pub address: u32,
    /// Whether this vector has been initialised (address != 0).
    pub enabled: bool,
}

/// The complete interrupt vector table.
pub static INT_VECTOR_NAMES: [&str; VECTOR_COUNT] = [
    "RESET",
    "INT0",
    "INT1",
    "PCINT0",
    "PCINT1",
    "PCINT2",
    "WDT",
    "TIMER2_COMPA",
    "TIMER2_COMPB",
    "TIMER2_OVF",
    "TIMER1_CAPT",
    "TIMER1_COMPA",
    "TIMER1_COMPB",
    "TIMER1_OVF",
    "TIMER0_COMPA",
    "TIMER0_COMPB",
    "TIMER0_OVF",
    "SPI_STC",
    "USART_RX",
    "USART_UDRE",
    "USART_TX",
    "ADC",
    "EE_READY",
    "ANALOG_COMP",
    "TWI",
    "SPM_READY",
];

// ---------------------------------------------------------------------------
// Main CPU state
// ---------------------------------------------------------------------------

/// The complete AVR CPU state.
#[derive(Debug, Clone)]
pub struct AvrState {
    /// General-purpose registers R0–R31.
    pub regs: [u8; 32],
    /// Program Counter (byte address, always even).
    pub pc: u32,
    /// Stack Pointer (16-bit; SPH:SPL in IO space).
    pub sp: u16,
    /// Status Register.
    pub sreg: u8,

    // --- Memories ---
    /// Flash / program memory (byte-addressed, little-endian words).
    pub flash: Box<[u8; FLASH_SIZE]>,
    /// SRAM data memory (byte-addressed).
    pub sram: Box<[u8; SRAM_SIZE]>,
    /// EEPROM (byte-addressed).
    pub eeprom: Box<[u8; EEPROM_SIZE]>,

    // --- Peripherals ---
    pub timer0: Timer0,
    pub timer1: Timer1,

    // --- Interrupt state ---
    /// Handler addresses for each interrupt vector (byte address).
    pub int_vectors: [u32; VECTOR_COUNT],
    /// Whether a hardware interrupt is pending.
    pub int_pending: [bool; VECTOR_COUNT],

    /// Total cycles executed.
    pub cycle_count: u64,
}

impl Default for AvrState {
    fn default() -> Self {
        Self::new()
    }
}

impl AvrState {
    /// Create a new, reset-state AVR CPU.
    #[must_use]
    pub fn new() -> Self {
        Self {
            regs: [0u8; 32],
            pc: 0,
            sp: u16::try_from(SRAM_SIZE - 1).unwrap_or(u16::MAX), // reset SP = RAMEND (top of SRAM array)
            sreg: 0,
            flash: vec![0u8; FLASH_SIZE]
                .into_boxed_slice()
                .try_into()
                .expect("vec of FLASH_SIZE bytes converts to Box<[u8; FLASH_SIZE]>"),
            sram: Box::new([0u8; SRAM_SIZE]),
            eeprom: Box::new([0u8; EEPROM_SIZE]),
            timer0: Timer0::default(),
            timer1: Timer1::default(),
            int_vectors: [0u32; VECTOR_COUNT],
            int_pending: [false; VECTOR_COUNT],
            cycle_count: 0,
        }
    }

    /// Load a program image into flash at byte offset `base`.
    pub fn load_flash(&mut self, data: &[u8], base: usize) {
        if base >= FLASH_SIZE {
            return;
        }
        let end = (base + data.len()).min(FLASH_SIZE);
        self.flash[base..end].copy_from_slice(&data[..end - base]);
    }

    /// Read a 16-bit instruction word from flash at byte address `addr`.
    #[must_use]
    pub fn fetch_word(&self, addr: u32) -> u16 {
        let a = (addr as usize) & (FLASH_SIZE - 1);
        u16::from_le_bytes([
            self.flash[a],
            self.flash[a.wrapping_add(1) & (FLASH_SIZE - 1)],
        ])
    }

    /// Read a byte from SRAM (data memory).
    #[must_use]
    pub fn sram_read(&self, addr: u16) -> u8 {
        self.sram[(addr as usize).min(SRAM_SIZE - 1)]
    }

    /// Write a byte to SRAM.
    pub fn sram_write(&mut self, addr: u16, val: u8) {
        if (addr as usize) < SRAM_SIZE {
            self.sram[addr as usize] = val;
        }
    }

    // --- Register pair helpers ---

    /// Read the X register (R27:R26).
    #[must_use]
    pub fn x(&self) -> u16 {
        u16::from(self.regs[26]) | (u16::from(self.regs[27]) << 8)
    }
    /// Write the X register.
    pub const fn set_x(&mut self, v: u16) {
        let [lo, hi] = v.to_le_bytes();
        self.regs[26] = lo;
        self.regs[27] = hi;
    }

    /// Read the Y register (R29:R28).
    #[must_use]
    pub fn y(&self) -> u16 {
        u16::from(self.regs[28]) | (u16::from(self.regs[29]) << 8)
    }
    /// Write the Y register.
    pub const fn set_y(&mut self, v: u16) {
        let [lo, hi] = v.to_le_bytes();
        self.regs[28] = lo;
        self.regs[29] = hi;
    }

    /// Read the Z register (R31:R30).
    #[must_use]
    pub fn z(&self) -> u16 {
        u16::from(self.regs[30]) | (u16::from(self.regs[31]) << 8)
    }
    /// Write the Z register.
    pub const fn set_z(&mut self, v: u16) {
        let [lo, hi] = v.to_le_bytes();
        self.regs[30] = lo;
        self.regs[31] = hi;
    }

    // --- SREG helpers ---

    #[inline]
    const fn flag(&self, mask: u8) -> bool {
        self.sreg & mask != 0
    }
    #[inline]
    const fn set_flag(&mut self, mask: u8, v: bool) {
        if v {
            self.sreg |= mask;
        } else {
            self.sreg &= !mask;
        }
    }

    /// Set the SREG Zero flag.
    pub const fn update_z(&mut self, result: u8) {
        self.set_flag(SREG_Z, result == 0);
    }
    /// Set the SREG Negative flag.
    pub const fn update_n(&mut self, result: u8) {
        self.set_flag(SREG_N, result & 0x80 != 0);
    }
    /// Recompute Sign from N XOR V.
    pub const fn update_s(&mut self) {
        let n = self.flag(SREG_N);
        let v = self.flag(SREG_V);
        self.set_flag(SREG_S, n ^ v);
    }

    // --- Stack helpers ---

    /// Push a byte onto the hardware stack.
    pub fn push_byte(&mut self, val: u8) {
        let sp = self.sp;
        self.sram_write(sp, val);
        self.sp = self.sp.wrapping_sub(1);
    }

    /// Pop a byte from the hardware stack.
    pub fn pop_byte(&mut self) -> u8 {
        self.sp = self.sp.wrapping_add(1);
        self.sram_read(self.sp)
    }

    /// Push a 2-byte little-endian value (e.g. return address).
    pub fn push_u16(&mut self, val: u16) {
        let [lo, hi] = val.to_le_bytes();
        self.push_byte(hi);
        self.push_byte(lo);
    }

    /// Pop a 2-byte return address.
    pub fn pop_u16(&mut self) -> u16 {
        let lo = self.pop_byte();
        let hi = self.pop_byte();
        u16::from(lo) | (u16::from(hi) << 8)
    }

    // --- Interrupt handling ---

    /// Trigger a hardware interrupt at `vector_index` (sets pending flag).
    pub const fn trigger_interrupt(&mut self, vector_index: usize) {
        if vector_index < VECTOR_COUNT {
            self.int_pending[vector_index] = true;
        }
    }

    /// Service the highest-priority pending interrupt (if global IE is set).
    pub fn service_interrupt(&mut self) {
        if !self.flag(SREG_I) {
            return;
        }
        for i in 0..VECTOR_COUNT {
            if self.int_pending[i] {
                self.int_pending[i] = false;
                self.set_flag(SREG_I, false); // clear GIE while in ISR
                // Push return address (word address = PC / 2, then we store byte address)
                self.push_u16(u16::try_from(self.pc).unwrap_or(u16::MAX));
                self.pc = self.int_vectors[i];
                return;
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Single-step execution
    // ---------------------------------------------------------------------------

    /// Execute one instruction at the current PC.
    ///
    /// Returns the number of cycles consumed, or an error string.
    ///
    /// # Errors
    /// Returns `Err` with a descriptive string for unimplemented opcodes.
    pub fn step(&mut self) -> Result<u32, String> {
        // Service interrupts before executing; if an interrupt was taken,
        // count the interrupt latency (4 cycles) and return without executing
        // the first instruction at the vector address.
        let pc_before = self.pc;
        self.service_interrupt();
        if self.pc != pc_before {
            // Interrupt was serviced — charge interrupt latency cycles only.
            let latency: u32 = 4;
            self.cycle_count += u64::from(latency);
            self.timer0.tick(u64::from(latency));
            self.timer1.tick(u64::from(latency));
            return Ok(latency);
        }

        let word = self.fetch_word(self.pc);
        let pc_start = self.pc;

        let cycles = self.execute_word(word, pc_start)?;
        self.cycle_count += u64::from(cycles);
        self.timer0.tick(u64::from(cycles));
        self.timer1.tick(u64::from(cycles));
        Ok(cycles)
    }

    fn execute_word(&mut self, word: u16, pc: u32) -> Result<u32, String> {
        // NOP
        if word == 0x0000 {
            self.pc = pc + 2;
            return Ok(1);
        }
        // SLEEP
        if word == 0x9588 {
            self.pc = pc + 2;
            return Ok(1);
        }
        // WDR
        if word == 0x95A8 {
            self.pc = pc + 2;
            return Ok(1);
        }
        // BREAK
        if word == 0x9598 {
            self.pc = pc + 2;
            return Ok(1);
        }
        // RET
        if word == 0x9508 {
            let addr = self.pop_u16();
            self.pc = u32::from(addr);
            return Ok(4);
        }
        // RETI
        if word == 0x9518 {
            let addr = self.pop_u16();
            self.pc = u32::from(addr);
            self.set_flag(SREG_I, true);
            return Ok(4);
        }
        // IJMP
        if word == 0x9409 {
            self.pc = u32::from(self.z()) * 2;
            return Ok(2);
        }
        // ICALL
        if word == 0x9509 {
            self.push_u16(u16::try_from(pc / 2 + 1).unwrap_or(u16::MAX));
            self.pc = u32::from(self.z()) * 2;
            return Ok(3);
        }
        // SEI/CLI and other flag ops
        if (word & 0xFF8F) == 0x9408 {
            let s = ((word >> 4) & 7) as u8;
            self.sreg |= 1 << s;
            self.pc = pc + 2;
            return Ok(1);
        }
        if (word & 0xFF8F) == 0x9488 {
            let s = ((word >> 4) & 7) as u8;
            self.sreg &= !(1 << s);
            self.pc = pc + 2;
            return Ok(1);
        }

        // ADD Rd,Rr
        if (word & 0xFC00) == 0x0C00 {
            let d = ((word >> 4) & 0x1F) as usize;
            let r = (((word & 0x0200) >> 5) | (word & 0x0F)) as usize;
            let (result, carry) = self.regs[d].overflowing_add(self.regs[r]);
            let half = (self.regs[d] & 0x0F) + (self.regs[r] & 0x0F) > 0x0F;
            let ovf = (self.regs[d] ^ result) & (self.regs[r] ^ result) & 0x80 != 0;
            self.regs[d] = result;
            self.update_z(result);
            self.update_n(result);
            self.set_flag(SREG_C, carry);
            self.set_flag(SREG_H, half);
            self.set_flag(SREG_V, ovf);
            self.update_s();
            self.pc = pc + 2;
            return Ok(1);
        }
        // SUB Rd,Rr
        if (word & 0xFC00) == 0x1800 {
            let d = ((word >> 4) & 0x1F) as usize;
            let r = (((word & 0x0200) >> 5) | (word & 0x0F)) as usize;
            let (result, carry) = self.regs[d].overflowing_sub(self.regs[r]);
            let ovf = (self.regs[d] ^ self.regs[r]) & (self.regs[d] ^ result) & 0x80 != 0;
            self.regs[d] = result;
            self.update_z(result);
            self.update_n(result);
            self.set_flag(SREG_C, carry);
            self.set_flag(SREG_V, ovf);
            self.update_s();
            self.pc = pc + 2;
            return Ok(1);
        }
        // AND Rd,Rr
        if (word & 0xFC00) == 0x2000 {
            let d = ((word >> 4) & 0x1F) as usize;
            let r = (((word & 0x0200) >> 5) | (word & 0x0F)) as usize;
            let result = self.regs[d] & self.regs[r];
            self.regs[d] = result;
            self.update_z(result);
            self.update_n(result);
            self.set_flag(SREG_V, false);
            self.update_s();
            self.pc = pc + 2;
            return Ok(1);
        }
        // OR Rd,Rr
        if (word & 0xFC00) == 0x2800 {
            let d = ((word >> 4) & 0x1F) as usize;
            let r = (((word & 0x0200) >> 5) | (word & 0x0F)) as usize;
            let result = self.regs[d] | self.regs[r];
            self.regs[d] = result;
            self.update_z(result);
            self.update_n(result);
            self.set_flag(SREG_V, false);
            self.update_s();
            self.pc = pc + 2;
            return Ok(1);
        }
        // EOR Rd,Rr
        if (word & 0xFC00) == 0x2400 {
            let d = ((word >> 4) & 0x1F) as usize;
            let r = (((word & 0x0200) >> 5) | (word & 0x0F)) as usize;
            let result = self.regs[d] ^ self.regs[r];
            self.regs[d] = result;
            self.update_z(result);
            self.update_n(result);
            self.set_flag(SREG_V, false);
            self.update_s();
            self.pc = pc + 2;
            return Ok(1);
        }
        // MOV Rd,Rr
        if (word & 0xFC00) == 0x2C00 {
            let d = ((word >> 4) & 0x1F) as usize;
            let r = (((word & 0x0200) >> 5) | (word & 0x0F)) as usize;
            self.regs[d] = self.regs[r];
            self.pc = pc + 2;
            return Ok(1);
        }
        // LDI Rd,K  (d = 16..31)
        if (word & 0xF000) == 0xE000 {
            let d = (16 + ((word >> 4) & 0xF)) as usize;
            let k = u8::try_from((word & 0x0F00) >> 4 | (word & 0x0F)).unwrap_or(u8::MAX);
            self.regs[d] = k;
            self.pc = pc + 2;
            return Ok(1);
        }
        // SUBI Rd,K
        if (word & 0xF000) == 0x5000 {
            let d = (16 + ((word >> 4) & 0xF)) as usize;
            let k = u8::try_from((word & 0x0F00) >> 4 | (word & 0x0F)).unwrap_or(u8::MAX);
            let (result, carry) = self.regs[d].overflowing_sub(k);
            let ovf = (self.regs[d] ^ k) & (self.regs[d] ^ result) & 0x80 != 0;
            self.regs[d] = result;
            self.update_z(result);
            self.update_n(result);
            self.set_flag(SREG_C, carry);
            self.set_flag(SREG_V, ovf);
            self.update_s();
            self.pc = pc + 2;
            return Ok(1);
        }
        // CPI Rd,K
        if (word & 0xF000) == 0x3000 {
            let d = (16 + ((word >> 4) & 0xF)) as usize;
            let k = u8::try_from((word & 0x0F00) >> 4 | (word & 0x0F)).unwrap_or(u8::MAX);
            let result = self.regs[d].wrapping_sub(k);
            let carry = self.regs[d] < k;
            let ovf = (self.regs[d] ^ k) & (self.regs[d] ^ result) & 0x80 != 0;
            self.update_z(result);
            self.update_n(result);
            self.set_flag(SREG_C, carry);
            self.set_flag(SREG_V, ovf);
            self.update_s();
            self.pc = pc + 2;
            return Ok(1);
        }
        // CP Rd,Rr
        if (word & 0xFC00) == 0x1400 {
            let d = ((word >> 4) & 0x1F) as usize;
            let r = (((word & 0x0200) >> 5) | (word & 0x0F)) as usize;
            let result = self.regs[d].wrapping_sub(self.regs[r]);
            let carry = self.regs[d] < self.regs[r];
            let ovf = (self.regs[d] ^ self.regs[r]) & (self.regs[d] ^ result) & 0x80 != 0;
            self.update_z(result);
            self.update_n(result);
            self.set_flag(SREG_C, carry);
            self.set_flag(SREG_V, ovf);
            self.update_s();
            self.pc = pc + 2;
            return Ok(1);
        }
        // INC Rd
        if (word & 0xFE0F) == 0x9403 {
            let d = ((word >> 4) & 0x1F) as usize;
            let result = self.regs[d].wrapping_add(1);
            let ovf = self.regs[d] == 0x7F;
            self.regs[d] = result;
            self.update_z(result);
            self.update_n(result);
            self.set_flag(SREG_V, ovf);
            self.update_s();
            self.pc = pc + 2;
            return Ok(1);
        }
        // DEC Rd
        if (word & 0xFE0F) == 0x940A {
            let d = ((word >> 4) & 0x1F) as usize;
            let result = self.regs[d].wrapping_sub(1);
            let ovf = self.regs[d] == 0x80;
            self.regs[d] = result;
            self.update_z(result);
            self.update_n(result);
            self.set_flag(SREG_V, ovf);
            self.update_s();
            self.pc = pc + 2;
            return Ok(1);
        }
        // PUSH Rr
        if (word & 0xFE0F) == 0x920F {
            let r = ((word >> 4) & 0x1F) as usize;
            self.push_byte(self.regs[r]);
            self.pc = pc + 2;
            return Ok(2);
        }
        // POP Rd
        if (word & 0xFE0F) == 0x900F {
            let d = ((word >> 4) & 0x1F) as usize;
            self.regs[d] = self.pop_byte();
            self.pc = pc + 2;
            return Ok(2);
        }
        // LD Rd,X
        if (word & 0xFE0F) == 0x900C {
            let d = ((word >> 4) & 0x1F) as usize;
            self.regs[d] = self.sram_read(self.x());
            self.pc = pc + 2;
            return Ok(2);
        }
        // LD Rd,X+
        if (word & 0xFE0F) == 0x900D {
            let d = ((word >> 4) & 0x1F) as usize;
            let x = self.x();
            self.regs[d] = self.sram_read(x);
            self.set_x(x.wrapping_add(1));
            self.pc = pc + 2;
            return Ok(2);
        }
        // LD Rd,Z
        if (word & 0xFE0F) == 0x8000 {
            let d = ((word >> 4) & 0x1F) as usize;
            self.regs[d] = self.sram_read(self.z());
            self.pc = pc + 2;
            return Ok(2);
        }
        // ST X,Rr
        if (word & 0xFE0F) == 0x920C {
            let r = ((word >> 4) & 0x1F) as usize;
            let x = self.x();
            self.sram_write(x, self.regs[r]);
            self.pc = pc + 2;
            return Ok(2);
        }
        // RJMP k
        if (word & 0xF000) == 0xC000 {
            let k = sign_ext_12(word);
            self.pc = avr_branch_target(pc, 2, i64::from(k) * 2);
            return Ok(2);
        }
        // RCALL k
        if (word & 0xF000) == 0xD000 {
            let k = sign_ext_12(word);
            self.push_u16(u16::try_from(u32::midpoint(pc, 2)).unwrap_or(u16::MAX));
            self.pc = avr_branch_target(pc, 2, i64::from(k) * 2);
            return Ok(3);
        }
        // JMP (32-bit)
        if (word & 0xFE0E) == 0x940C {
            let next = self.fetch_word(pc + 2);
            let k_hi = u32::from((word & 0x01F0) >> 3) | u32::from(word & 1);
            let target = ((k_hi << 16) | u32::from(next)) * 2;
            self.pc = target & FLASH_MASK;
            return Ok(3);
        }
        // CALL (32-bit)
        if (word & 0xFE0E) == 0x940E {
            let next = self.fetch_word(pc + 2);
            let k_hi = u32::from((word & 0x01F0) >> 3) | u32::from(word & 1);
            let target = ((k_hi << 16) | u32::from(next)) * 2;
            self.push_u16(u16::try_from(u32::midpoint(pc, 4)).unwrap_or(u16::MAX));
            self.pc = target & FLASH_MASK;
            return Ok(4);
        }
        // BRBS / BRBC (conditional branches)
        if (word & 0xFC00) == 0xF000 {
            let k_raw = ((word >> 3) & 0x7F) as i8;
            let k = if k_raw & 0x40 != 0 {
                k_raw | -0x80_i8
            } else {
                k_raw
            };
            let s = (word & 7) as u8;
            let flag_set = self.sreg & (1 << s) != 0;
            if flag_set {
                self.pc = avr_branch_target(pc, 2, i64::from(k) * 2);
                return Ok(2);
            }
            self.pc = pc + 2;
            return Ok(1);
        }
        if (word & 0xFC00) == 0xF400 {
            let k_raw = ((word >> 3) & 0x7F) as i8;
            let k = if k_raw & 0x40 != 0 {
                k_raw | -0x80_i8
            } else {
                k_raw
            };
            let s = (word & 7) as u8;
            let flag_clear = self.sreg & (1 << s) == 0;
            if flag_clear {
                self.pc = avr_branch_target(pc, 2, i64::from(k) * 2);
                return Ok(2);
            }
            self.pc = pc + 2;
            return Ok(1);
        }
        // IN Rd,A
        if (word & 0xF800) == 0xB000 {
            let d = ((word >> 4) & 0x1F) as usize;
            let a = ((word & 0x0600) >> 5) | (word & 0x0F);
            // Map IO address to SRAM (IO base = 0x20)
            self.regs[d] = self.sram_read(a + 0x20);
            self.pc = pc + 2;
            return Ok(1);
        }
        // OUT A,Rr
        if (word & 0xF800) == 0xB800 {
            let r = ((word >> 4) & 0x1F) as usize;
            let a = ((word & 0x0600) >> 5) | (word & 0x0F);
            self.sram_write(a + 0x20, self.regs[r]);
            self.pc = pc + 2;
            return Ok(1);
        }
        // NEG Rd
        if (word & 0xFE0F) == 0x9401 {
            let d = ((word >> 4) & 0x1F) as usize;
            let result = self.regs[d].wrapping_neg();
            let carry = result != 0;
            let ovf = self.regs[d] == 0x80;
            self.regs[d] = result;
            self.update_z(result);
            self.update_n(result);
            self.set_flag(SREG_C, carry);
            self.set_flag(SREG_V, ovf);
            self.update_s();
            self.pc = pc + 2;
            return Ok(1);
        }
        // COM Rd
        if (word & 0xFE0F) == 0x9400 {
            let d = ((word >> 4) & 0x1F) as usize;
            let result = !self.regs[d];
            self.regs[d] = result;
            self.update_z(result);
            self.update_n(result);
            self.set_flag(SREG_V, false);
            self.set_flag(SREG_C, true);
            self.update_s();
            self.pc = pc + 2;
            return Ok(1);
        }
        // LSR Rd
        if (word & 0xFE0F) == 0x9406 {
            let d = ((word >> 4) & 0x1F) as usize;
            let carry = self.regs[d] & 1 != 0;
            let result = self.regs[d] >> 1;
            self.regs[d] = result;
            self.set_flag(SREG_C, carry);
            self.update_z(result);
            self.update_n(result);
            let n = self.flag(SREG_N);
            let c = self.flag(SREG_C);
            self.set_flag(SREG_V, n ^ c);
            self.update_s();
            self.pc = pc + 2;
            return Ok(1);
        }
        // ROR Rd
        if (word & 0xFE0F) == 0x9407 {
            let d = ((word >> 4) & 0x1F) as usize;
            let old_c = if self.flag(SREG_C) { 0x80u8 } else { 0 };
            let carry = self.regs[d] & 1 != 0;
            let result = (self.regs[d] >> 1) | old_c;
            self.regs[d] = result;
            self.set_flag(SREG_C, carry);
            self.update_z(result);
            self.update_n(result);
            let n = self.flag(SREG_N);
            let c = self.flag(SREG_C);
            self.set_flag(SREG_V, n ^ c);
            self.update_s();
            self.pc = pc + 2;
            return Ok(1);
        }
        // MOVW
        if (word & 0xFF00) == 0x0100 {
            let d = ((word >> 4) & 0xF) as usize * 2;
            let r = (word & 0xF) as usize * 2;
            self.regs[d] = self.regs[r];
            self.regs[d + 1] = self.regs[r + 1];
            self.pc = pc + 2;
            return Ok(1);
        }
        // LDS Rd,k (32-bit)
        if (word & 0xFE0F) == 0x9000 {
            let d = ((word >> 4) & 0x1F) as usize;
            let base = pc as usize;
            let (Some(&lo), Some(&hi)) = (self.flash.get(base + 2), self.flash.get(base + 3)) else {
                return Err(format!("LDS: PC {pc:#x} too close to flash end"));
            };
            let k = u16::from(lo) | (u16::from(hi) << 8);
            self.regs[d] = self.sram_read(k);
            self.pc = pc + 4;
            return Ok(2);
        }
        // STS k,Rr (32-bit)
        if (word & 0xFE0F) == 0x9200 {
            let r = ((word >> 4) & 0x1F) as usize;
            let base = pc as usize;
            let (Some(&lo), Some(&hi)) = (self.flash.get(base + 2), self.flash.get(base + 3)) else {
                return Err(format!("STS: PC {pc:#x} too close to flash end"));
            };
            let k = u16::from(lo) | (u16::from(hi) << 8);
            self.sram_write(k, self.regs[r]);
            self.pc = pc + 4;
            return Ok(2);
        }

        // Fallthrough: unknown instruction, advance PC
        self.pc = pc + 2;
        Err(format!("unimplemented AVR opcode 0x{word:04X}"))
    }
}

fn sign_ext_12(raw: u16) -> i32 {
    let v = i32::from(raw & 0x0FFF);
    if v & 0x0800 != 0 { v - 0x1000 } else { v }
}

/// Flash address mask — keeps PC within the 128 KiB flash window.
const FLASH_MASK: u32 = 0x1_FFFF; // FLASH_SIZE - 1

/// Compute a branch/jump target byte address, wrapping within flash.
fn avr_branch_target(pc: u32, fetch_advance: u32, offset_bytes: i64) -> u32 {
    let base = i64::from(pc.wrapping_add(fetch_advance));
    let target = base.wrapping_add(offset_bytes);
    u32::try_from(target & i64::from(FLASH_MASK)).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> AvrState {
        AvrState::new()
    }

    fn load_and_step(data: &[u8]) -> AvrState {
        let mut s = state();
        s.load_flash(data, 0);
        s.step().unwrap();
        s
    }

    #[test]
    fn test_nop() {
        let s = load_and_step(&[0x00, 0x00]);
        assert_eq!(s.pc, 2);
        assert_eq!(s.cycle_count, 1);
    }

    #[test]
    fn test_ldi() {
        // LDI R16, 0x42: word = 0xE402 LE = [0x02, 0xE4]
        let s = load_and_step(&[0x02, 0xE4]);
        assert_eq!(s.regs[16], 0x42);
    }

    #[test]
    fn test_add() {
        // ADD R0,R1 where R0=5, R1=3
        let mut s = state();
        s.regs[0] = 5;
        s.regs[1] = 3;
        let word = 0x0C01_u16.to_le_bytes();
        s.load_flash(&word, 0);
        s.step().unwrap();
        assert_eq!(s.regs[0], 8);
        assert!(!s.flag(SREG_Z));
        assert!(!s.flag(SREG_C));
    }

    #[test]
    fn test_add_carry() {
        let mut s = state();
        s.regs[0] = 0xFF;
        s.regs[1] = 0x01;
        s.load_flash(&0x0C01_u16.to_le_bytes(), 0);
        s.step().unwrap();
        assert_eq!(s.regs[0], 0);
        assert!(s.flag(SREG_Z));
        assert!(s.flag(SREG_C));
    }

    #[test]
    fn test_sub() {
        let mut s = state();
        s.regs[0] = 10;
        s.regs[1] = 3;
        s.load_flash(&0x1801_u16.to_le_bytes(), 0);
        s.step().unwrap();
        assert_eq!(s.regs[0], 7);
    }

    #[test]
    fn test_and_zero_result() {
        let mut s = state();
        s.regs[0] = 0xAA;
        s.regs[1] = 0x55;
        s.load_flash(&0x2001_u16.to_le_bytes(), 0); // AND R0,R1
        s.step().unwrap();
        assert_eq!(s.regs[0], 0);
        assert!(s.flag(SREG_Z));
    }

    #[test]
    fn test_or() {
        let mut s = state();
        s.regs[0] = 0xAA;
        s.regs[1] = 0x55;
        s.load_flash(&0x2801_u16.to_le_bytes(), 0);
        s.step().unwrap();
        assert_eq!(s.regs[0], 0xFF);
    }

    #[test]
    fn test_eor_clr() {
        let mut s = state();
        s.regs[0] = 0xAB;
        s.load_flash(&0x2400_u16.to_le_bytes(), 0); // EOR R0,R0
        s.step().unwrap();
        assert_eq!(s.regs[0], 0);
        assert!(s.flag(SREG_Z));
    }

    #[test]
    fn test_mov() {
        let mut s = state();
        s.regs[1] = 42;
        s.load_flash(&0x2C01_u16.to_le_bytes(), 0); // MOV R0,R1
        s.step().unwrap();
        assert_eq!(s.regs[0], 42);
    }

    #[test]
    fn test_push_pop() {
        let mut s = state();
        s.regs[16] = 0xAB;
        let sp_start = s.sp;
        // PUSH R16 = 0x930F LE=[0x0F,0x93]
        s.load_flash(&[0x0F, 0x93, 0x0F, 0x90], 0);
        s.step().unwrap(); // PUSH R16
        assert_eq!(s.sram_read(sp_start), 0xAB);
        assert_eq!(s.sp, sp_start - 1);
        s.step().unwrap(); // POP R16
        assert_eq!(s.regs[16], 0xAB);
    }

    #[test]
    fn test_rjmp() {
        // RJMP +2 from PC=0: k=1, target = 0 + 2 + 1*2 = 4
        let mut s = state();
        s.load_flash(&[0x01, 0xC0], 0);
        s.step().unwrap();
        assert_eq!(s.pc, 4);
    }

    #[test]
    fn test_inc_dec() {
        let mut s = state();
        s.regs[0] = 5;
        s.load_flash(&[0x03, 0x94, 0x0A, 0x94], 0); // INC R0, DEC R0
        s.step().unwrap();
        assert_eq!(s.regs[0], 6);
        s.step().unwrap();
        assert_eq!(s.regs[0], 5);
    }

    #[test]
    fn test_sei_cli() {
        let mut s = state();
        assert!(!s.flag(SREG_I));
        s.load_flash(&[0x78, 0x94, 0xF8, 0x94], 0); // SEI, CLI
        s.step().unwrap();
        assert!(s.flag(SREG_I));
        s.step().unwrap();
        assert!(!s.flag(SREG_I));
    }

    #[test]
    fn test_ret() {
        let mut s = state();
        // Put return address 0x0010 on stack
        s.push_u16(0x0010);
        s.load_flash(&[0x08, 0x95], 0); // RET
        s.step().unwrap();
        assert_eq!(s.pc, 0x0010);
    }

    #[test]
    fn test_brcc_not_taken() {
        // BRCC +2: s=0(Carry), if C=0 branch taken
        let mut s = state();
        s.set_flag(SREG_C, true); // set carry → branch NOT taken for BRCC
        // BRCC: F400 | (k<<3) | s=0 ; k=1 → 0xF408 LE=[0x08,0xF4]
        s.load_flash(&[0x08, 0xF4], 0);
        s.step().unwrap();
        assert_eq!(s.pc, 2); // not taken
    }

    #[test]
    fn test_brcc_taken() {
        let mut s = state();
        s.set_flag(SREG_C, false);
        s.load_flash(&[0x08, 0xF4], 0);
        s.step().unwrap();
        assert_eq!(s.pc, 4); // taken: 0+2+1*2=4
    }

    #[test]
    fn test_lsr() {
        let mut s = state();
        s.regs[0] = 0x02;
        s.load_flash(&[0x06, 0x94], 0);
        s.step().unwrap();
        assert_eq!(s.regs[0], 1);
        assert!(!s.flag(SREG_C));
    }

    #[test]
    fn test_com() {
        let mut s = state();
        s.regs[0] = 0xAA;
        s.load_flash(&[0x00, 0x94], 0);
        s.step().unwrap();
        assert_eq!(s.regs[0], 0x55);
    }

    #[test]
    fn test_ld_st_sram() {
        let mut s = state();
        s.sram_write(0x100, 0xBB);
        s.set_x(0x100);
        // LD R0,X: 0x900C LE=[0x0C,0x90]
        s.load_flash(&[0x0C, 0x90], 0);
        s.step().unwrap();
        assert_eq!(s.regs[0], 0xBB);
    }

    #[test]
    fn test_timer0_tick() {
        let mut s = state();
        s.timer0.tccr0b = 0x01; // prescaler /1
        s.load_flash(&[0x00, 0x00], 0); // NOP
        s.step().unwrap();
        assert_eq!(s.timer0.cycles, 1);
    }

    #[test]
    fn test_interrupt_service() {
        let mut s = state();
        // Set up INT0 handler at 0x0100
        s.int_vectors[1] = 0x0100;
        s.set_flag(SREG_I, true);
        s.trigger_interrupt(1);
        s.load_flash(&[0x00, 0x00], 0); // NOP
        s.step().unwrap();
        // Should have jumped to 0x0100
        assert_eq!(s.pc, 0x0100);
        assert!(!s.flag(SREG_I));
    }

    #[test]
    fn test_neg() {
        let mut s = state();
        s.regs[0] = 5;
        s.load_flash(&[0x01, 0x94], 0); // NEG R0
        s.step().unwrap();
        // NEG 5 = 256 - 5 = 251 = 0xFB.
        //
        // This used to read `0xFBu8.wrapping_neg().wrapping_add(0xFB)`, which
        // evaluates to 0 (neg(0xFB) = 5, then 5 + 251 wraps to 0) while its own
        // trailing comment stated 251 — the emulator was returning the correct
        // 251 and the test compared it against a nonsense expression. Note the
        // `s2` block at the end of this very test already asserted the right
        // value on an identical setup, so the file contained both the broken
        // and the correct expectation side by side.
        assert_eq!(s.regs[0], 0xFB);
        let mut s2 = state();
        s2.regs[0] = 5;
        s2.load_flash(&[0x01, 0x94], 0);
        s2.step().unwrap();
        assert_eq!(s2.regs[0], 251);
        assert!(s2.flag(SREG_C));
    }

    #[test]
    fn test_movw() {
        let mut s = state();
        s.regs[2] = 0x12;
        s.regs[3] = 0x34;
        // MOVW R0:R1, R2:R3: 0x0101 LE=[0x01,0x01]
        s.load_flash(&[0x01, 0x01], 0);
        s.step().unwrap();
        assert_eq!(s.regs[0], 0x12);
        assert_eq!(s.regs[1], 0x34);
    }

    #[test]
    fn test_cpi_zero() {
        let mut s = state();
        s.regs[16] = 5;
        // CPI R16,5: 0x3050 LE=[0x50,0x30]
        s.load_flash(&[0x50, 0x30], 0);
        s.step().unwrap();
        assert!(s.flag(SREG_Z));
        assert!(!s.flag(SREG_C));
    }

    #[test]
    fn test_initial_sp() {
        let s = state();
        // SP should be initialised to top of SRAM
        assert!(s.sp > 0);
    }

    #[test]
    fn test_x_y_z_helpers() {
        let mut s = state();
        s.set_x(0x1234);
        assert_eq!(s.x(), 0x1234);
        s.set_y(0xABCD);
        assert_eq!(s.y(), 0xABCD);
        s.set_z(0x0100);
        assert_eq!(s.z(), 0x0100);
    }
}
