//! Lightweight x86-64 single-step emulator for shellcode analysis.

use std::collections::HashMap;

// ── Register enum ─────────────────────────────────────────────────────────────

/// x86 / x86-64 register names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum X86Reg {
    Rax,
    Rbx,
    Rcx,
    Rdx,
    Rsi,
    Rdi,
    Rsp,
    Rbp,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    Rip,
    Eax,
    Ebx,
    Ecx,
    Edx,
    Esi,
    Edi,
    Esp,
    Ebp,
    R8d,
    R9d,
    R10d,
    R11d,
    R12d,
    R13d,
    R14d,
    R15d,
    Ax,
    Bx,
    Cx,
    Dx,
    Al,
    Ah,
    Bl,
    Bh,
    Cl,
    Ch,
    Dl,
    Dh,
}

// ── CPU state ─────────────────────────────────────────────────────────────────

/// Full x86-64 CPU register file.
#[derive(Debug, Clone)]
pub struct X86Cpu {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub cs: u16,
    pub ds: u16,
    pub ss: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
}

impl X86Cpu {
    /// Create a zeroed CPU with a default stack pointer.
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rsp: 0x7FFF_0000,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rflags: 0,
            cs: 0,
            ds: 0,
            ss: 0,
            es: 0,
            fs: 0,
            gs: 0,
        }
    }

    /// Read a register value.
    #[must_use] 
    pub const fn get(&self, reg: X86Reg) -> u64 {
        match reg {
            X86Reg::Rax => self.rax,
            X86Reg::Rbx => self.rbx,
            X86Reg::Rcx => self.rcx,
            X86Reg::Rdx => self.rdx,
            X86Reg::Rsi => self.rsi,
            X86Reg::Rdi => self.rdi,
            X86Reg::Rsp => self.rsp,
            X86Reg::Rbp => self.rbp,
            X86Reg::R8 => self.r8,
            X86Reg::R9 => self.r9,
            X86Reg::R10 => self.r10,
            X86Reg::R11 => self.r11,
            X86Reg::R12 => self.r12,
            X86Reg::R13 => self.r13,
            X86Reg::R14 => self.r14,
            X86Reg::R15 => self.r15,
            X86Reg::Rip => self.rip,
            X86Reg::Eax => self.rax & 0xFFFF_FFFF,
            X86Reg::Ebx => self.rbx & 0xFFFF_FFFF,
            X86Reg::Ecx => self.rcx & 0xFFFF_FFFF,
            X86Reg::Edx => self.rdx & 0xFFFF_FFFF,
            X86Reg::Esi => self.rsi & 0xFFFF_FFFF,
            X86Reg::Edi => self.rdi & 0xFFFF_FFFF,
            X86Reg::Esp => self.rsp & 0xFFFF_FFFF,
            X86Reg::Ebp => self.rbp & 0xFFFF_FFFF,
            X86Reg::R8d => self.r8 & 0xFFFF_FFFF,
            X86Reg::R9d => self.r9 & 0xFFFF_FFFF,
            X86Reg::R10d => self.r10 & 0xFFFF_FFFF,
            X86Reg::R11d => self.r11 & 0xFFFF_FFFF,
            X86Reg::R12d => self.r12 & 0xFFFF_FFFF,
            X86Reg::R13d => self.r13 & 0xFFFF_FFFF,
            X86Reg::R14d => self.r14 & 0xFFFF_FFFF,
            X86Reg::R15d => self.r15 & 0xFFFF_FFFF,
            X86Reg::Ax => self.rax & 0xFFFF,
            X86Reg::Bx => self.rbx & 0xFFFF,
            X86Reg::Cx => self.rcx & 0xFFFF,
            X86Reg::Dx => self.rdx & 0xFFFF,
            X86Reg::Al => self.rax & 0xFF,
            X86Reg::Ah => (self.rax >> 8) & 0xFF,
            X86Reg::Bl => self.rbx & 0xFF,
            X86Reg::Bh => (self.rbx >> 8) & 0xFF,
            X86Reg::Cl => self.rcx & 0xFF,
            X86Reg::Ch => (self.rcx >> 8) & 0xFF,
            X86Reg::Dl => self.rdx & 0xFF,
            X86Reg::Dh => (self.rdx >> 8) & 0xFF,
        }
    }

    /// Write a register value. 32-bit writes zero the upper 32 bits.
    pub const fn set(&mut self, reg: X86Reg, val: u64) {
        match reg {
            X86Reg::Rax => self.rax = val,
            X86Reg::Rbx => self.rbx = val,
            X86Reg::Rcx => self.rcx = val,
            X86Reg::Rdx => self.rdx = val,
            X86Reg::Rsi => self.rsi = val,
            X86Reg::Rdi => self.rdi = val,
            X86Reg::Rsp => self.rsp = val,
            X86Reg::Rbp => self.rbp = val,
            X86Reg::R8 => self.r8 = val,
            X86Reg::R9 => self.r9 = val,
            X86Reg::R10 => self.r10 = val,
            X86Reg::R11 => self.r11 = val,
            X86Reg::R12 => self.r12 = val,
            X86Reg::R13 => self.r13 = val,
            X86Reg::R14 => self.r14 = val,
            X86Reg::R15 => self.r15 = val,
            X86Reg::Rip => self.rip = val,
            // 32-bit: zero-extend into 64-bit register
            X86Reg::Eax => self.rax = val & 0xFFFF_FFFF,
            X86Reg::Ebx => self.rbx = val & 0xFFFF_FFFF,
            X86Reg::Ecx => self.rcx = val & 0xFFFF_FFFF,
            X86Reg::Edx => self.rdx = val & 0xFFFF_FFFF,
            X86Reg::Esi => self.rsi = val & 0xFFFF_FFFF,
            X86Reg::Edi => self.rdi = val & 0xFFFF_FFFF,
            X86Reg::Esp => self.rsp = val & 0xFFFF_FFFF,
            X86Reg::Ebp => self.rbp = val & 0xFFFF_FFFF,
            X86Reg::R8d => self.r8 = val & 0xFFFF_FFFF,
            X86Reg::R9d => self.r9 = val & 0xFFFF_FFFF,
            X86Reg::R10d => self.r10 = val & 0xFFFF_FFFF,
            X86Reg::R11d => self.r11 = val & 0xFFFF_FFFF,
            X86Reg::R12d => self.r12 = val & 0xFFFF_FFFF,
            X86Reg::R13d => self.r13 = val & 0xFFFF_FFFF,
            X86Reg::R14d => self.r14 = val & 0xFFFF_FFFF,
            X86Reg::R15d => self.r15 = val & 0xFFFF_FFFF,
            // 16-bit: merge low 16 bits
            X86Reg::Ax => self.rax = (self.rax & !0xFFFF) | (val & 0xFFFF),
            X86Reg::Bx => self.rbx = (self.rbx & !0xFFFF) | (val & 0xFFFF),
            X86Reg::Cx => self.rcx = (self.rcx & !0xFFFF) | (val & 0xFFFF),
            X86Reg::Dx => self.rdx = (self.rdx & !0xFFFF) | (val & 0xFFFF),
            // 8-bit low
            X86Reg::Al => self.rax = (self.rax & !0xFF) | (val & 0xFF),
            X86Reg::Bl => self.rbx = (self.rbx & !0xFF) | (val & 0xFF),
            X86Reg::Cl => self.rcx = (self.rcx & !0xFF) | (val & 0xFF),
            X86Reg::Dl => self.rdx = (self.rdx & !0xFF) | (val & 0xFF),
            // 8-bit high
            X86Reg::Ah => self.rax = (self.rax & !0xFF00) | ((val & 0xFF) << 8),
            X86Reg::Bh => self.rbx = (self.rbx & !0xFF00) | ((val & 0xFF) << 8),
            X86Reg::Ch => self.rcx = (self.rcx & !0xFF00) | ((val & 0xFF) << 8),
            X86Reg::Dh => self.rdx = (self.rdx & !0xFF00) | ((val & 0xFF) << 8),
        }
    }

    // ── Flag accessors ────────────────────────────────────────────────────────

    /// Zero flag (bit 6).
    #[must_use] 
    pub const fn flag_zero(&self) -> bool {
        (self.rflags >> 6) & 1 == 1
    }
    /// Sign flag (bit 7).
    #[must_use] 
    pub const fn flag_sign(&self) -> bool {
        (self.rflags >> 7) & 1 == 1
    }
    /// Carry flag (bit 0).
    #[must_use] 
    pub const fn flag_carry(&self) -> bool {
        self.rflags & 1 == 1
    }
    /// Overflow flag (bit 11).
    #[must_use] 
    pub const fn flag_overflow(&self) -> bool {
        (self.rflags >> 11) & 1 == 1
    }
    /// Parity flag (bit 2).
    #[must_use] 
    pub const fn flag_parity(&self) -> bool {
        (self.rflags >> 2) & 1 == 1
    }

    const fn set_flag_bit(&mut self, bit: u64, v: bool) {
        if v {
            self.rflags |= 1 << bit;
        } else {
            self.rflags &= !(1 << bit);
        }
    }
    pub const fn set_flag_zero(&mut self, b: bool) {
        self.set_flag_bit(6, b);
    }
    pub const fn set_flag_sign(&mut self, b: bool) {
        self.set_flag_bit(7, b);
    }
    pub const fn set_flag_carry(&mut self, b: bool) {
        self.set_flag_bit(0, b);
    }
    pub const fn set_flag_overflow(&mut self, b: bool) {
        self.set_flag_bit(11, b);
    }
    pub const fn set_flag_parity(&mut self, b: bool) {
        self.set_flag_bit(2, b);
    }

    // ── Flag update helpers ───────────────────────────────────────────────────

    /// Update flags after a subtraction: `result = a - b`.
    pub const fn update_flags_sub(&mut self, a: u64, b: u64, result: u64) {
        self.set_flag_zero(result == 0);
        self.set_flag_sign((result >> 63) & 1 == 1);
        self.set_flag_carry(b > a);
        // Overflow: sign(a) != sign(b) && sign(result) != sign(a)
        let ov = ((a ^ b) & (a ^ result)) >> 63 & 1 == 1;
        self.set_flag_overflow(ov);
    }

    /// Update flags after an addition: `result = a + b`.
    pub const fn update_flags_add(&mut self, a: u64, b: u64, result: u64) {
        self.set_flag_zero(result == 0);
        self.set_flag_sign((result >> 63) & 1 == 1);
        // Carry: unsigned overflow
        self.set_flag_carry(result < a);
        // Overflow: sign(a) == sign(b) && sign(result) != sign(a)
        let ov = (!(a ^ b) & (a ^ result)) >> 63 & 1 == 1;
        self.set_flag_overflow(ov);
    }

    /// Update flags after a logical operation (AND/OR/XOR). Clears CF and OF.
    pub const fn update_flags_logic(&mut self, result: u64) {
        self.set_flag_zero(result == 0);
        self.set_flag_sign((result >> 63) & 1 == 1);
        self.set_flag_carry(false);
        self.set_flag_overflow(false);
    }
}

impl Default for X86Cpu {
    fn default() -> Self {
        Self::new()
    }
}

// ── Memory ────────────────────────────────────────────────────────────────────

/// Page-granular memory map (4 KiB pages).
#[derive(Debug, Default)]
pub struct X86Mem {
    pub pages: HashMap<u64, Box<[u8; 4096]>>,
}

impl X86Mem {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    const fn page_base(addr: u64) -> u64 {
        addr & !0xFFF
    }
    const fn page_off(addr: u64) -> usize {
        (addr & 0xFFF) as usize
    }

    /// Read a single byte.
    #[must_use] 
    pub fn read_u8(&self, addr: u64) -> Option<u8> {
        let page = self.pages.get(&Self::page_base(addr))?;
        Some(page[Self::page_off(addr)])
    }

    /// Read a little-endian u16.
    #[must_use] 
    pub fn read_u16(&self, addr: u64) -> Option<u16> {
        let lo = u16::from(self.read_u8(addr)?);
        let hi = u16::from(self.read_u8(addr.wrapping_add(1))?);
        Some(lo | (hi << 8))
    }

    /// Read a little-endian u32.
    #[must_use] 
    pub fn read_u32(&self, addr: u64) -> Option<u32> {
        let lo = u32::from(self.read_u16(addr)?);
        let hi = u32::from(self.read_u16(addr.wrapping_add(2))?);
        Some(lo | (hi << 16))
    }

    /// Read a little-endian u64.
    #[must_use] 
    pub fn read_u64(&self, addr: u64) -> Option<u64> {
        let lo = u64::from(self.read_u32(addr)?);
        let hi = u64::from(self.read_u32(addr.wrapping_add(4))?);
        Some(lo | (hi << 32))
    }

    fn ensure_page(&mut self, addr: u64) -> &mut [u8; 4096] {
        self.pages
            .entry(Self::page_base(addr))
            .or_insert_with(|| Box::new([0u8; 4096]))
    }

    /// Write a single byte, allocating the page if necessary.
    pub fn write_u8(&mut self, addr: u64, val: u8) {
        let off = Self::page_off(addr);
        self.ensure_page(addr)[off] = val;
    }

    /// Write a little-endian u16.
    pub fn write_u16(&mut self, addr: u64, val: u16) {
        self.write_u8(addr, (val & 0xFF) as u8);
        self.write_u8(addr.wrapping_add(1), (val >> 8) as u8);
    }

    /// Write a little-endian u32.
    pub fn write_u32(&mut self, addr: u64, val: u32) {
        self.write_u16(addr, (val & 0xFFFF) as u16);
        self.write_u16(addr.wrapping_add(2), (val >> 16) as u16);
    }

    /// Write a little-endian u64.
    pub fn write_u64(&mut self, addr: u64, val: u64) {
        self.write_u32(addr, (val & 0xFFFF_FFFF) as u32);
        self.write_u32(addr.wrapping_add(4), (val >> 32) as u32);
    }

    /// Map a byte slice starting at `addr`.
    pub fn map_bytes(&mut self, addr: u64, data: &[u8]) {
        for (i, &b) in data.iter().enumerate() {
            self.write_u8(addr.wrapping_add(i as u64), b);
        }
    }

    /// Push a u64 onto the stack (rsp -= 8 first).
    pub fn stack_push(&mut self, cpu: &mut X86Cpu, val: u64) {
        cpu.rsp = cpu.rsp.wrapping_sub(8);
        self.write_u64(cpu.rsp, val);
    }

    /// Pop a u64 from the stack (rsp += 8 after).
    pub fn stack_pop(&mut self, cpu: &mut X86Cpu) -> Option<u64> {
        let val = self.read_u64(cpu.rsp)?;
        cpu.rsp = cpu.rsp.wrapping_add(8);
        Some(val)
    }
}

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors that can occur during emulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmulatorError {
    UnknownOpcode(u8, u64),
    MemFault(u64),
    MaxSteps,
    DivisionByZero,
    StackFault,
}

impl std::fmt::Display for EmulatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownOpcode(op, rip) => {
                write!(f, "unknown opcode {op:#04x} at rip={rip:#018x}")
            }
            Self::MemFault(addr) => write!(f, "memory fault at {addr:#018x}"),
            Self::MaxSteps => write!(f, "max steps reached"),
            Self::DivisionByZero => write!(f, "division by zero"),
            Self::StackFault => write!(f, "stack fault"),
        }
    }
}

impl std::error::Error for EmulatorError {}

// ── API call record ───────────────────────────────────────────────────────────

/// A recorded CALL instruction to a stub address.
#[derive(Debug, Clone)]
pub struct ApiCall {
    pub address: u64,
    pub name: Option<String>,
    pub rcx: u64,
    pub rdx: u64,
    pub r8: u64,
    pub r9: u64,
    pub retval: Option<u64>,
}

// ── Emulator ──────────────────────────────────────────────────────────────────

/// Lightweight x86-64 single-step emulator.
#[derive(Debug)]
pub struct X86Emulator {
    pub cpu: X86Cpu,
    pub mem: X86Mem,
    pub api_calls: Vec<ApiCall>,
    max_steps: usize,
    pub steps: usize,
    pub halted: bool,
}

impl X86Emulator {
    #[must_use] 
    pub fn new(max_steps: usize) -> Self {
        Self {
            cpu: X86Cpu::new(),
            mem: X86Mem::new(),
            api_calls: Vec::new(),
            max_steps,
            steps: 0,
            halted: false,
        }
    }

    /// Load shellcode into memory and point RIP at `base`.
    pub fn load_shellcode(&mut self, code: &[u8], base: u64) {
        self.mem.map_bytes(base, code);
        self.cpu.rip = base;
    }

    /// Execute a single instruction.
    pub fn step(&mut self) -> Result<(), EmulatorError> {
        if self.halted {
            return Ok(());
        }

        let rip = self.cpu.rip;

        // Fetch first byte — may be REX prefix.
        let first = self.mem.read_u8(rip).ok_or(EmulatorError::MemFault(rip))?;

        // Detect REX prefix (0x40–0x4F). When present, the opcode byte follows
        // the prefix, so decode it here and reuse it below.
        let (rex, op_rip, op) = if (0x40..=0x4F).contains(&first) {
            let op = self
                .mem
                .read_u8(rip + 1)
                .ok_or(EmulatorError::MemFault(rip + 1))?;
            (first, rip + 1, op)
        } else {
            (0u8, rip, first)
        };

        let rex_w = (rex >> 3) & 1 == 1; // 64-bit operand
        let rex_b = rex & 1 == 1; // extends ModRM rm / SIB base / opcode reg

        match op {
            // NOP
            0x90 => {
                self.cpu.rip = op_rip + 1;
            }

            // HLT
            0xF4 => {
                self.halted = true;
                self.cpu.rip = op_rip + 1;
            }

            // INT3
            0xCC => {
                // Breakpoint — just continue.
                self.cpu.rip = op_rip + 1;
            }

            // PUSH r64 (58–5F + REX.B)
            0x50..=0x57 => {
                let reg_idx = (op - 0x50) as usize + if rex_b { 8 } else { 0 };
                let val = self.cpu_get_gpr64(reg_idx);
                self.mem.stack_push(&mut self.cpu, val);
                self.cpu.rip = op_rip + 1;
            }

            // POP r64
            0x58..=0x5F => {
                let reg_idx = (op - 0x58) as usize + if rex_b { 8 } else { 0 };
                let val = self
                    .mem
                    .stack_pop(&mut self.cpu)
                    .ok_or(EmulatorError::StackFault)?;
                self.cpu_set_gpr64(reg_idx, val);
                self.cpu.rip = op_rip + 1;
            }

            // PUSH imm32 (sign-extended)
            0x68 => {
                let imm = i64::from(self.read_i32_at(op_rip + 1)?) as u64;
                self.mem.stack_push(&mut self.cpu, imm);
                self.cpu.rip = op_rip + 5;
            }

            // PUSH imm8 (sign-extended)
            0x6A => {
                let imm8 = i64::from(self
                    .mem
                    .read_u8(op_rip + 1)
                    .ok_or(EmulatorError::MemFault(op_rip + 1))? as i8) as u64;
                self.mem.stack_push(&mut self.cpu, imm8);
                self.cpu.rip = op_rip + 2;
            }

            // MOV r32/64, imm32/64  (B8–BF)
            0xB8..=0xBF => {
                let reg_idx = (op - 0xB8) as usize + if rex_b { 8 } else { 0 };
                if rex_w {
                    let imm = self.read_u64_at(op_rip + 1)?;
                    self.cpu_set_gpr64(reg_idx, imm);
                    self.cpu.rip = op_rip + 9;
                } else {
                    let imm = u64::from(self.read_u32_at(op_rip + 1)?);
                    // 32-bit write zero-extends
                    self.cpu_set_gpr64(reg_idx, imm);
                    self.cpu.rip = op_rip + 5;
                }
            }

            // JMP rel32
            0xE9 => {
                let rel = self.read_i32_at(op_rip + 1)?;
                self.cpu.rip = ((op_rip + 5) as i64).wrapping_add(i64::from(rel)) as u64;
            }

            // JMP rel8
            0xEB => {
                let rel = self
                    .mem
                    .read_u8(op_rip + 1)
                    .ok_or(EmulatorError::MemFault(op_rip + 1))? as i8;
                self.cpu.rip = ((op_rip + 2) as i64).wrapping_add(i64::from(rel)) as u64;
            }

            // CALL rel32
            0xE8 => {
                let rel = self.read_i32_at(op_rip + 1)?;
                let next_rip = op_rip + 5;
                let target = (next_rip as i64).wrapping_add(i64::from(rel)) as u64;
                self.mem.stack_push(&mut self.cpu, next_rip);
                self.api_calls.push(ApiCall {
                    address: target,
                    name: None,
                    rcx: self.cpu.rcx,
                    rdx: self.cpu.rdx,
                    r8: self.cpu.r8,
                    r9: self.cpu.r9,
                    retval: None,
                });
                self.cpu.rip = target;
            }

            // RET
            0xC3 => {
                let ret_addr = self
                    .mem
                    .stack_pop(&mut self.cpu)
                    .ok_or(EmulatorError::StackFault)?;
                self.cpu.rip = ret_addr;
            }

            // MOV r/m, r  (89)
            0x89 => {
                let modrm = self
                    .mem
                    .read_u8(op_rip + 1)
                    .ok_or(EmulatorError::MemFault(op_rip + 1))?;
                let (reg, rm) = decode_modrm_regs(modrm, rex);
                let val = self.cpu_get_gpr64(reg);
                if rex_w {
                    self.cpu_set_gpr64(rm, val);
                } else {
                    self.cpu_set_gpr64(rm, val & 0xFFFF_FFFF);
                }
                self.cpu.rip = op_rip + 2;
            }

            // MOV r, r/m  (8B)
            0x8B => {
                let modrm = self
                    .mem
                    .read_u8(op_rip + 1)
                    .ok_or(EmulatorError::MemFault(op_rip + 1))?;
                let (reg, rm) = decode_modrm_regs(modrm, rex);
                let val = self.cpu_get_gpr64(rm);
                if rex_w {
                    self.cpu_set_gpr64(reg, val);
                } else {
                    self.cpu_set_gpr64(reg, val & 0xFFFF_FFFF);
                }
                self.cpu.rip = op_rip + 2;
            }

            // XOR r/m32, r32  (31)
            0x31 => {
                let modrm = self
                    .mem
                    .read_u8(op_rip + 1)
                    .ok_or(EmulatorError::MemFault(op_rip + 1))?;
                let (reg, rm) = decode_modrm_regs(modrm, rex);
                let a = self.cpu_get_gpr64(rm);
                let b = self.cpu_get_gpr64(reg);
                let result = a ^ b;
                let result = if rex_w { result } else { result & 0xFFFF_FFFF };
                self.cpu_set_gpr64(rm, result);
                self.cpu.update_flags_logic(result);
                self.cpu.rip = op_rip + 2;
            }

            // XOR r32, r/m32  (33)
            0x33 => {
                let modrm = self
                    .mem
                    .read_u8(op_rip + 1)
                    .ok_or(EmulatorError::MemFault(op_rip + 1))?;
                let (reg, rm) = decode_modrm_regs(modrm, rex);
                let a = self.cpu_get_gpr64(reg);
                let b = self.cpu_get_gpr64(rm);
                let result = a ^ b;
                let result = if rex_w { result } else { result & 0xFFFF_FFFF };
                self.cpu_set_gpr64(reg, result);
                self.cpu.update_flags_logic(result);
                self.cpu.rip = op_rip + 2;
            }

            // ADD r/m, r  (01)
            0x01 => {
                let modrm = self
                    .mem
                    .read_u8(op_rip + 1)
                    .ok_or(EmulatorError::MemFault(op_rip + 1))?;
                let (reg, rm) = decode_modrm_regs(modrm, rex);
                let a = self.cpu_get_gpr64(rm);
                let b = self.cpu_get_gpr64(reg);
                let result = a.wrapping_add(b);
                self.cpu_set_gpr64(rm, if rex_w { result } else { result & 0xFFFF_FFFF });
                self.cpu.update_flags_add(a, b, result);
                self.cpu.rip = op_rip + 2;
            }

            // ADD r, r/m  (03)
            0x03 => {
                let modrm = self
                    .mem
                    .read_u8(op_rip + 1)
                    .ok_or(EmulatorError::MemFault(op_rip + 1))?;
                let (reg, rm) = decode_modrm_regs(modrm, rex);
                let a = self.cpu_get_gpr64(reg);
                let b = self.cpu_get_gpr64(rm);
                let result = a.wrapping_add(b);
                self.cpu_set_gpr64(reg, if rex_w { result } else { result & 0xFFFF_FFFF });
                self.cpu.update_flags_add(a, b, result);
                self.cpu.rip = op_rip + 2;
            }

            // SUB r/m, r  (29)
            0x29 => {
                let modrm = self
                    .mem
                    .read_u8(op_rip + 1)
                    .ok_or(EmulatorError::MemFault(op_rip + 1))?;
                let (reg, rm) = decode_modrm_regs(modrm, rex);
                let a = self.cpu_get_gpr64(rm);
                let b = self.cpu_get_gpr64(reg);
                let result = a.wrapping_sub(b);
                self.cpu_set_gpr64(rm, if rex_w { result } else { result & 0xFFFF_FFFF });
                self.cpu.update_flags_sub(a, b, result);
                self.cpu.rip = op_rip + 2;
            }

            // SUB r, r/m  (2B)
            0x2B => {
                let modrm = self
                    .mem
                    .read_u8(op_rip + 1)
                    .ok_or(EmulatorError::MemFault(op_rip + 1))?;
                let (reg, rm) = decode_modrm_regs(modrm, rex);
                let a = self.cpu_get_gpr64(reg);
                let b = self.cpu_get_gpr64(rm);
                let result = a.wrapping_sub(b);
                self.cpu_set_gpr64(reg, if rex_w { result } else { result & 0xFFFF_FFFF });
                self.cpu.update_flags_sub(a, b, result);
                self.cpu.rip = op_rip + 2;
            }

            // CMP r/m, r  (39)
            0x39 => {
                let modrm = self
                    .mem
                    .read_u8(op_rip + 1)
                    .ok_or(EmulatorError::MemFault(op_rip + 1))?;
                let (reg, rm) = decode_modrm_regs(modrm, rex);
                let a = self.cpu_get_gpr64(rm);
                let b = self.cpu_get_gpr64(reg);
                let result = a.wrapping_sub(b);
                self.cpu.update_flags_sub(a, b, result);
                self.cpu.rip = op_rip + 2;
            }

            // CMP r, r/m  (3B)
            0x3B => {
                let modrm = self
                    .mem
                    .read_u8(op_rip + 1)
                    .ok_or(EmulatorError::MemFault(op_rip + 1))?;
                let (reg, rm) = decode_modrm_regs(modrm, rex);
                let a = self.cpu_get_gpr64(reg);
                let b = self.cpu_get_gpr64(rm);
                let result = a.wrapping_sub(b);
                self.cpu.update_flags_sub(a, b, result);
                self.cpu.rip = op_rip + 2;
            }

            // TEST r/m, r  (85)
            0x85 => {
                let modrm = self
                    .mem
                    .read_u8(op_rip + 1)
                    .ok_or(EmulatorError::MemFault(op_rip + 1))?;
                let (reg, rm) = decode_modrm_regs(modrm, rex);
                let result = self.cpu_get_gpr64(rm) & self.cpu_get_gpr64(reg);
                self.cpu.update_flags_logic(result);
                self.cpu.rip = op_rip + 2;
            }

            // FF /4 JMP r/m64; /2 CALL r/m64; /0 INC r/m64; /1 DEC r/m64
            0xFF => {
                let modrm = self
                    .mem
                    .read_u8(op_rip + 1)
                    .ok_or(EmulatorError::MemFault(op_rip + 1))?;
                let slash = (modrm >> 3) & 7;
                let rm = (modrm & 7) as usize + if rex_b { 8 } else { 0 };
                match slash {
                    0 => {
                        // INC r/m
                        let a = self.cpu_get_gpr64(rm);
                        let result = a.wrapping_add(1);
                        self.cpu_set_gpr64(rm, result);
                        // INC does not affect CF
                        self.cpu.set_flag_zero(result == 0);
                        self.cpu.set_flag_sign((result >> 63) & 1 == 1);
                        self.cpu.rip = op_rip + 2;
                    }
                    1 => {
                        // DEC r/m
                        let a = self.cpu_get_gpr64(rm);
                        let result = a.wrapping_sub(1);
                        self.cpu_set_gpr64(rm, result);
                        self.cpu.set_flag_zero(result == 0);
                        self.cpu.set_flag_sign((result >> 63) & 1 == 1);
                        self.cpu.rip = op_rip + 2;
                    }
                    2 => {
                        // CALL r/m
                        let target = self.cpu_get_gpr64(rm);
                        let next = op_rip + 2;
                        self.mem.stack_push(&mut self.cpu, next);
                        self.api_calls.push(ApiCall {
                            address: target,
                            name: None,
                            rcx: self.cpu.rcx,
                            rdx: self.cpu.rdx,
                            r8: self.cpu.r8,
                            r9: self.cpu.r9,
                            retval: None,
                        });
                        self.cpu.rip = target;
                    }
                    4 => {
                        // JMP r/m
                        let target = self.cpu_get_gpr64(rm);
                        self.cpu.rip = target;
                    }
                    _ => return Err(EmulatorError::UnknownOpcode(op, rip)),
                }
            }

            // JZ rel8
            0x74 => {
                let rel = self
                    .mem
                    .read_u8(op_rip + 1)
                    .ok_or(EmulatorError::MemFault(op_rip + 1))? as i8;
                if self.cpu.flag_zero() {
                    self.cpu.rip = ((op_rip + 2) as i64).wrapping_add(i64::from(rel)) as u64;
                } else {
                    self.cpu.rip = op_rip + 2;
                }
            }

            // JNZ rel8
            0x75 => {
                let rel = self
                    .mem
                    .read_u8(op_rip + 1)
                    .ok_or(EmulatorError::MemFault(op_rip + 1))? as i8;
                if self.cpu.flag_zero() {
                    self.cpu.rip = op_rip + 2;
                } else {
                    self.cpu.rip = ((op_rip + 2) as i64).wrapping_add(i64::from(rel)) as u64;
                }
            }

            // JL rel8 (SF != OF)
            0x7C => {
                let rel = self
                    .mem
                    .read_u8(op_rip + 1)
                    .ok_or(EmulatorError::MemFault(op_rip + 1))? as i8;
                if self.cpu.flag_sign() != self.cpu.flag_overflow() {
                    self.cpu.rip = ((op_rip + 2) as i64).wrapping_add(i64::from(rel)) as u64;
                } else {
                    self.cpu.rip = op_rip + 2;
                }
            }

            // JGE rel8 (SF == OF)
            0x7D => {
                let rel = self
                    .mem
                    .read_u8(op_rip + 1)
                    .ok_or(EmulatorError::MemFault(op_rip + 1))? as i8;
                if self.cpu.flag_sign() == self.cpu.flag_overflow() {
                    self.cpu.rip = ((op_rip + 2) as i64).wrapping_add(i64::from(rel)) as u64;
                } else {
                    self.cpu.rip = op_rip + 2;
                }
            }

            // JLE rel8 (ZF=1 or SF != OF)
            0x7E => {
                let rel = self
                    .mem
                    .read_u8(op_rip + 1)
                    .ok_or(EmulatorError::MemFault(op_rip + 1))? as i8;
                if self.cpu.flag_zero() || (self.cpu.flag_sign() != self.cpu.flag_overflow()) {
                    self.cpu.rip = ((op_rip + 2) as i64).wrapping_add(i64::from(rel)) as u64;
                } else {
                    self.cpu.rip = op_rip + 2;
                }
            }

            // JG rel8 (ZF=0 and SF == OF)
            0x7F => {
                let rel = self
                    .mem
                    .read_u8(op_rip + 1)
                    .ok_or(EmulatorError::MemFault(op_rip + 1))? as i8;
                if !self.cpu.flag_zero() && (self.cpu.flag_sign() == self.cpu.flag_overflow()) {
                    self.cpu.rip = ((op_rip + 2) as i64).wrapping_add(i64::from(rel)) as u64;
                } else {
                    self.cpu.rip = op_rip + 2;
                }
            }

            // 2-byte escape: 0F xx
            0x0F => {
                let op2 = self
                    .mem
                    .read_u8(op_rip + 1)
                    .ok_or(EmulatorError::MemFault(op_rip + 1))?;
                match op2 {
                    // JZ rel32
                    0x84 => {
                        let rel = self.read_i32_at(op_rip + 2)?;
                        if self.cpu.flag_zero() {
                            self.cpu.rip = ((op_rip + 6) as i64).wrapping_add(i64::from(rel)) as u64;
                        } else {
                            self.cpu.rip = op_rip + 6;
                        }
                    }
                    // JNZ rel32
                    0x85 => {
                        let rel = self.read_i32_at(op_rip + 2)?;
                        if self.cpu.flag_zero() {
                            self.cpu.rip = op_rip + 6;
                        } else {
                            self.cpu.rip = ((op_rip + 6) as i64).wrapping_add(i64::from(rel)) as u64;
                        }
                    }
                    // JL rel32
                    0x8C => {
                        let rel = self.read_i32_at(op_rip + 2)?;
                        if self.cpu.flag_sign() == self.cpu.flag_overflow() {
                            self.cpu.rip = op_rip + 6;
                        } else {
                            self.cpu.rip = ((op_rip + 6) as i64).wrapping_add(i64::from(rel)) as u64;
                        }
                    }
                    // JGE rel32
                    0x8D => {
                        let rel = self.read_i32_at(op_rip + 2)?;
                        if self.cpu.flag_sign() == self.cpu.flag_overflow() {
                            self.cpu.rip = ((op_rip + 6) as i64).wrapping_add(i64::from(rel)) as u64;
                        } else {
                            self.cpu.rip = op_rip + 6;
                        }
                    }
                    // JLE rel32
                    0x8E => {
                        let rel = self.read_i32_at(op_rip + 2)?;
                        if self.cpu.flag_zero()
                            || (self.cpu.flag_sign() != self.cpu.flag_overflow())
                        {
                            self.cpu.rip = ((op_rip + 6) as i64).wrapping_add(i64::from(rel)) as u64;
                        } else {
                            self.cpu.rip = op_rip + 6;
                        }
                    }
                    // JG rel32
                    0x8F => {
                        let rel = self.read_i32_at(op_rip + 2)?;
                        if !self.cpu.flag_zero()
                            && (self.cpu.flag_sign() == self.cpu.flag_overflow())
                        {
                            self.cpu.rip = ((op_rip + 6) as i64).wrapping_add(i64::from(rel)) as u64;
                        } else {
                            self.cpu.rip = op_rip + 6;
                        }
                    }
                    _ => return Err(EmulatorError::UnknownOpcode(op2, rip)),
                }
            }

            _ => return Err(EmulatorError::UnknownOpcode(op, rip)),
        }

        self.steps += 1;
        Ok(())
    }

    /// Run until halted or `max_steps` reached. Returns total steps executed.
    pub fn run(&mut self) -> Result<usize, EmulatorError> {
        loop {
            if self.halted {
                break;
            }
            if self.steps >= self.max_steps {
                return Err(EmulatorError::MaxSteps);
            }
            self.step()?;
        }
        Ok(self.steps)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    const fn cpu_get_gpr64(&self, idx: usize) -> u64 {
        match idx & 15 {
            0 => self.cpu.rax,
            1 => self.cpu.rcx,
            2 => self.cpu.rdx,
            3 => self.cpu.rbx,
            4 => self.cpu.rsp,
            5 => self.cpu.rbp,
            6 => self.cpu.rsi,
            7 => self.cpu.rdi,
            8 => self.cpu.r8,
            9 => self.cpu.r9,
            10 => self.cpu.r10,
            11 => self.cpu.r11,
            12 => self.cpu.r12,
            13 => self.cpu.r13,
            14 => self.cpu.r14,
            _ => self.cpu.r15,
        }
    }

    const fn cpu_set_gpr64(&mut self, idx: usize, val: u64) {
        match idx & 15 {
            0 => self.cpu.rax = val,
            1 => self.cpu.rcx = val,
            2 => self.cpu.rdx = val,
            3 => self.cpu.rbx = val,
            4 => self.cpu.rsp = val,
            5 => self.cpu.rbp = val,
            6 => self.cpu.rsi = val,
            7 => self.cpu.rdi = val,
            8 => self.cpu.r8 = val,
            9 => self.cpu.r9 = val,
            10 => self.cpu.r10 = val,
            11 => self.cpu.r11 = val,
            12 => self.cpu.r12 = val,
            13 => self.cpu.r13 = val,
            14 => self.cpu.r14 = val,
            _ => self.cpu.r15 = val,
        }
    }

    fn read_i32_at(&self, addr: u64) -> Result<i32, EmulatorError> {
        let v = self
            .mem
            .read_u32(addr)
            .ok_or(EmulatorError::MemFault(addr))?;
        Ok(v as i32)
    }

    fn read_u32_at(&self, addr: u64) -> Result<u32, EmulatorError> {
        self.mem.read_u32(addr).ok_or(EmulatorError::MemFault(addr))
    }

    fn read_u64_at(&self, addr: u64) -> Result<u64, EmulatorError> {
        self.mem.read_u64(addr).ok_or(EmulatorError::MemFault(addr))
    }
}

// ── ModRM decoder (register–register only, mod=11) ────────────────────────────

/// Decode a `ModRM` byte assuming mod=11 (register operands only).
/// Returns (`reg_field`, `rm_field`) both adjusted for REX.R / REX.B.
#[must_use] 
pub const fn decode_modrm_regs(modrm: u8, rex: u8) -> (usize, usize) {
    let rex_r = (rex >> 2) & 1 == 1;
    let rex_b = rex & 1 == 1;
    let reg = ((modrm >> 3) & 7) as usize + if rex_r { 8 } else { 0 };
    let rm = (modrm & 7) as usize + if rex_b { 8 } else { 0 };
    (reg, rm)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn emu() -> X86Emulator {
        X86Emulator::new(100_000)
    }

    // ── X86Cpu ────────────────────────────────────────────────────────────────

    #[test]
    fn test_cpu_new_rsp() {
        let cpu = X86Cpu::new();
        assert_eq!(cpu.rsp, 0x7FFF_0000);
    }

    #[test]
    fn test_cpu_set_get_rax() {
        let mut cpu = X86Cpu::new();
        cpu.set(X86Reg::Rax, 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(cpu.get(X86Reg::Rax), 0xDEAD_BEEF_CAFE_BABE);
    }

    #[test]
    fn test_cpu_set_eax_zero_extends() {
        let mut cpu = X86Cpu::new();
        cpu.rax = 0xFFFF_FFFF_FFFF_FFFF;
        cpu.set(X86Reg::Eax, 0x1234_5678);
        assert_eq!(cpu.rax, 0x1234_5678); // upper 32 bits zeroed
    }

    #[test]
    fn test_cpu_set_al() {
        let mut cpu = X86Cpu::new();
        cpu.rax = 0xDEAD_BEEF_CAFE_0000;
        cpu.set(X86Reg::Al, 0x42);
        assert_eq!(cpu.rax & 0xFF, 0x42);
        assert_eq!((cpu.rax >> 8) & 0xFF, 0x00); // AH unchanged
    }

    #[test]
    fn test_cpu_set_ah() {
        let mut cpu = X86Cpu::new();
        cpu.set(X86Reg::Ah, 0xFF);
        assert_eq!((cpu.rax >> 8) & 0xFF, 0xFF);
    }

    #[test]
    fn test_cpu_flag_zero() {
        let mut cpu = X86Cpu::new();
        cpu.set_flag_zero(true);
        assert!(cpu.flag_zero());
        cpu.set_flag_zero(false);
        assert!(!cpu.flag_zero());
    }

    #[test]
    fn test_cpu_flag_carry() {
        let mut cpu = X86Cpu::new();
        cpu.set_flag_carry(true);
        assert!(cpu.flag_carry());
    }

    #[test]
    fn test_cpu_update_flags_sub_zero() {
        let mut cpu = X86Cpu::new();
        cpu.update_flags_sub(5, 5, 0);
        assert!(cpu.flag_zero());
    }

    #[test]
    fn test_cpu_update_flags_add_carry() {
        let mut cpu = X86Cpu::new();
        let a: u64 = u64::MAX;
        let b: u64 = 1;
        let result = a.wrapping_add(b);
        cpu.update_flags_add(a, b, result);
        assert!(cpu.flag_carry());
    }

    #[test]
    fn test_cpu_update_flags_logic_clears_cf_of() {
        let mut cpu = X86Cpu::new();
        cpu.set_flag_carry(true);
        cpu.set_flag_overflow(true);
        cpu.update_flags_logic(0);
        assert!(!cpu.flag_carry());
        assert!(!cpu.flag_overflow());
        assert!(cpu.flag_zero());
    }

    // ── X86Mem ────────────────────────────────────────────────────────────────

    #[test]
    fn test_mem_write_read_u8() {
        let mut mem = X86Mem::new();
        mem.write_u8(0x1000, 0xAB);
        assert_eq!(mem.read_u8(0x1000), Some(0xAB));
    }

    #[test]
    fn test_mem_write_read_u64() {
        let mut mem = X86Mem::new();
        mem.write_u64(0x2000, 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(mem.read_u64(0x2000), Some(0xDEAD_BEEF_CAFE_BABE));
    }

    #[test]
    fn test_mem_read_unmapped_none() {
        let mem = X86Mem::new();
        assert_eq!(mem.read_u8(0xDEAD_0000), None);
    }

    #[test]
    fn test_mem_map_bytes() {
        let mut mem = X86Mem::new();
        mem.map_bytes(0x3000, b"Hello");
        assert_eq!(mem.read_u8(0x3000), Some(b'H'));
        assert_eq!(mem.read_u8(0x3004), Some(b'o'));
    }

    #[test]
    fn test_mem_cross_page_read_u64() {
        let mut mem = X86Mem::new();
        mem.write_u64(0x0FFC, 0x0102030405060708);
        assert_eq!(mem.read_u64(0x0FFC), Some(0x0102030405060708));
    }

    // ── Emulator instructions ─────────────────────────────────────────────────

    #[test]
    fn test_nop() {
        let mut e = emu();
        e.load_shellcode(&[0x90, 0xF4], 0x1000);
        e.run().unwrap();
        assert!(e.halted);
    }

    #[test]
    fn test_push_pop() {
        let mut e = emu();
        // PUSH RAX (0x50); POP RCX (0x59); HLT
        e.cpu.rax = 0xCAFE;
        e.load_shellcode(&[0x50, 0x59, 0xF4], 0x1000);
        e.run().unwrap();
        assert_eq!(e.cpu.rcx, 0xCAFE);
    }

    #[test]
    fn test_push_imm32() {
        let mut e = emu();
        // PUSH imm32 (68 01 00 00 00); POP RCX; HLT
        e.load_shellcode(&[0x68, 0x01, 0x00, 0x00, 0x00, 0x59, 0xF4], 0x1000);
        e.run().unwrap();
        assert_eq!(e.cpu.rcx, 1);
    }

    #[test]
    fn test_push_imm8_sign_extended() {
        let mut e = emu();
        // PUSH imm8 -1 (6A FF); POP RCX; HLT
        e.load_shellcode(&[0x6A, 0xFF, 0x59, 0xF4], 0x1000);
        e.run().unwrap();
        assert_eq!(e.cpu.rcx as i64, -1);
    }

    #[test]
    fn test_mov_r32_imm() {
        let mut e = emu();
        // MOV EAX, 0x1234 (B8 34 12 00 00); HLT
        e.load_shellcode(&[0xB8, 0x34, 0x12, 0x00, 0x00, 0xF4], 0x1000);
        e.run().unwrap();
        assert_eq!(e.cpu.rax, 0x1234);
    }

    #[test]
    fn test_mov_r64_imm_rex_w() {
        let mut e = emu();
        // REX.W=48 MOV RAX, imm64
        let imm: u64 = 0xDEAD_BEEF_CAFE_BABE;
        let mut code = vec![0x48u8, 0xB8];
        code.extend_from_slice(&imm.to_le_bytes());
        code.push(0xF4);
        e.load_shellcode(&code, 0x1000);
        e.run().unwrap();
        assert_eq!(e.cpu.rax, imm);
    }

    #[test]
    fn test_jmp_rel8_backward() {
        let mut e = X86Emulator::new(10);
        // JMP -2 (EB FE) — infinite loop, should hit max_steps
        e.load_shellcode(&[0xEB, 0xFE], 0x1000);
        assert!(matches!(e.run(), Err(EmulatorError::MaxSteps)));
    }

    #[test]
    fn test_jz_taken() {
        let mut e = emu();
        // XOR EAX,EAX (31 C0) → ZF=1; JZ +2 (74 02); MOV ECX,1; HLT (F4)
        // Layout: [31 C0] [74 02] [B9 01 00 00 00] [F4]
        // JZ skips the MOV and lands on HLT
        let code = [0x31u8, 0xC0, 0x74, 0x05, 0xB9, 0x01, 0x00, 0x00, 0x00, 0xF4];
        e.load_shellcode(&code, 0x1000);
        e.run().unwrap();
        assert_eq!(e.cpu.rcx, 0, "JZ should skip MOV ECX,1");
    }

    #[test]
    fn test_xor_r_r() {
        let mut e = emu();
        e.cpu.rax = 0xF0F0;
        // XOR EAX,EAX (31 C0); HLT
        e.load_shellcode(&[0x31, 0xC0, 0xF4], 0x1000);
        e.run().unwrap();
        assert_eq!(e.cpu.rax, 0);
        assert!(e.cpu.flag_zero());
    }

    #[test]
    fn test_add_sub() {
        let mut e = emu();
        // MOV EAX,10; MOV ECX,3; ADD EAX,ECX (03 C1); SUB EAX,ECX (2B C1); HLT
        let code = [
            0xB8, 0x0A, 0x00, 0x00, 0x00, // MOV EAX, 10
            0xB9, 0x03, 0x00, 0x00, 0x00, // MOV ECX, 3
            0x03, 0xC1, // ADD EAX, ECX  (ModRM 11 000 001)
            0x2B, 0xC1, // SUB EAX, ECX
            0xF4,
        ];
        e.load_shellcode(&code, 0x1000);
        e.run().unwrap();
        assert_eq!(e.cpu.rax, 10);
    }

    #[test]
    fn test_call_records_api_call() {
        let mut e = emu();
        // CALL +0 (E8 00 00 00 00) then HLT at call target
        // CALL target = rip+5 + 0 = 0x1005
        // At 0x1005: HLT (F4)
        let code = [0xE8u8, 0x00, 0x00, 0x00, 0x00, 0xF4];
        e.load_shellcode(&code, 0x1000);
        e.step().unwrap(); // CALL
        assert_eq!(e.api_calls.len(), 1);
        assert_eq!(e.api_calls[0].address, 0x1005);
    }

    #[test]
    fn test_ret() {
        let mut e = emu();
        // Push a return address then RET
        e.mem.stack_push(&mut e.cpu, 0x5000);
        e.load_shellcode(&[0xC3u8], 0x1000);
        e.step().unwrap();
        assert_eq!(e.cpu.rip, 0x5000);
    }

    #[test]
    fn test_decode_modrm_regs() {
        // ModRM = 0b11_000_001 = 0xC1 — reg=0 (RAX), rm=1 (RCX)
        let (reg, rm) = decode_modrm_regs(0xC1, 0);
        assert_eq!(reg, 0);
        assert_eq!(rm, 1);
    }

    #[test]
    fn test_decode_modrm_rex_r() {
        // REX = 0x44 (REX.R set), ModRM = 0xC0 — reg=8 (R8), rm=0 (RAX)
        let (reg, rm) = decode_modrm_regs(0xC0, 0x44);
        assert_eq!(reg, 8);
        assert_eq!(rm, 0);
    }

    #[test]
    fn test_max_steps_error() {
        let mut e = X86Emulator::new(3);
        // Infinite NOP loop via JMP -1
        e.load_shellcode(&[0x90, 0xEB, 0xFD], 0x1000); // NOP; JMP -3
        assert!(matches!(e.run(), Err(EmulatorError::MaxSteps)));
    }

    #[test]
    fn test_unknown_opcode_error() {
        let mut e = emu();
        e.load_shellcode(&[0xD6u8], 0x1000); // undefined
        assert!(matches!(
            e.step(),
            Err(EmulatorError::UnknownOpcode(0xD6, _))
        ));
    }

    #[test]
    fn test_mem_fault_error() {
        let mut e = emu();
        e.cpu.rip = 0xDEAD_BEEF; // unmapped
        assert!(matches!(e.step(), Err(EmulatorError::MemFault(_))));
    }

    #[test]
    fn test_0f84_jz_rel32_taken() {
        let mut e = emu();
        // XOR EAX,EAX then 0F 84 rel32=3 (skip 3 bytes), then MOV ECX,1, then HLT
        let code = [
            0x31u8, 0xC0, // XOR EAX, EAX
            0x0F, 0x84, 0x05, 0x00, 0x00, 0x00, // JZ +5
            0xB9, 0x01, 0x00, 0x00, 0x00, // MOV ECX,1  (5 bytes)
            0xF4, // HLT
        ];
        e.load_shellcode(&code, 0x1000);
        e.run().unwrap();
        assert_eq!(e.cpu.rcx, 0, "JZ rel32 should skip MOV ECX,1");
    }
}
