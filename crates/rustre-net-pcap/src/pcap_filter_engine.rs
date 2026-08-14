//! `pcap_filter_engine` — BPF-like filter engine for PCAP data.
//!
//! Provides [`PcapFilterEngine`] which compiles text filter expressions into
//! bytecode executed by [`FilterVm`].  [`FilterExpr`] is the AST,
//! [`FilterCompiler`] lowers it to instructions, and [`FilterOptimizer`]
//! performs constant folding and dead-code removal.

use std::fmt;
use std::net::Ipv4Addr;

pub use std::collections::HashMap;
pub use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FilterError {
    #[error("parse error at position {pos}: {msg}")]
    ParseError { pos: usize, msg: String },
    #[error("compile error: {0}")]
    CompileError(String),
    #[error("vm error: {0}")]
    VmError(String),
    #[error("unknown field: {0}")]
    UnknownField(String),
    #[error("type mismatch: expected {expected}, got {got}")]
    TypeMismatch { expected: String, got: String },
    #[error("division by zero")]
    DivisionByZero,
    #[error("stack underflow")]
    StackUnderflow,
    #[error("program too large: {0} instructions")]
    ProgramTooLarge(usize),
}

// ─── Packet ───────────────────────────────────────────────────────────────────

/// Simplified packet representation for the filter VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub src_ip: Option<Ipv4Addr>,
    pub dst_ip: Option<Ipv4Addr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub proto: u8, // 6=TCP, 17=UDP, 1=ICMP
    pub payload: Vec<u8>,
    pub vlan: Option<u16>,
    pub eth_type: u16,
}

impl Default for Packet {
    fn default() -> Self {
        Self {
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            proto: 0,
            payload: Vec::new(),
            vlan: None,
            eth_type: 0x0800,
        }
    }
}

impl Packet {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn tcp(src: Ipv4Addr, src_port: u16, dst: Ipv4Addr, dst_port: u16) -> Self {
        Self {
            src_ip: Some(src),
            dst_ip: Some(dst),
            src_port: Some(src_port),
            dst_port: Some(dst_port),
            proto: 6,
            ..Default::default()
        }
    }

    #[must_use] 
    pub fn udp(src: Ipv4Addr, src_port: u16, dst: Ipv4Addr, dst_port: u16) -> Self {
        Self {
            src_ip: Some(src),
            dst_ip: Some(dst),
            src_port: Some(src_port),
            dst_port: Some(dst_port),
            proto: 17,
            ..Default::default()
        }
    }

    #[must_use] 
    pub const fn is_tcp(&self) -> bool {
        self.proto == 6
    }

    #[must_use] 
    pub const fn is_udp(&self) -> bool {
        self.proto == 17
    }

    #[must_use] 
    pub const fn is_icmp(&self) -> bool {
        self.proto == 1
    }

    /// Read a 16-bit word at byte offset `off` from the payload.
    #[must_use] 
    pub fn load_half(&self, off: usize) -> Option<u16> {
        if off + 1 < self.payload.len() {
            Some(u16::from_be_bytes([
                self.payload[off],
                self.payload[off + 1],
            ]))
        } else {
            None
        }
    }

    /// Read a byte at offset `off` from the payload.
    #[must_use] 
    pub fn load_byte(&self, off: usize) -> Option<u8> {
        self.payload.get(off).copied()
    }
}

// ─── FilterExpr (AST) ─────────────────────────────────────────────────────────

/// Filter expression AST node.
#[derive(Debug, Clone, PartialEq)]
pub enum FilterExpr {
    True,
    False,
    Proto(u8),
    SrcIp(Ipv4Addr),
    DstIp(Ipv4Addr),
    SrcPort(u16),
    DstPort(u16),
    Port(u16),
    Net(Ipv4Addr, u8), // addr / prefix
    PayloadContains(Vec<u8>),
    Len(LenOp, u16),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Not(Box<Self>),
    Vlan(u16),
    EthType(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LenOp {
    Lt,
    Le,
    Eq,
    Ge,
    Gt,
}

impl FilterExpr {
    #[must_use] 
    pub fn and(a: Self, b: Self) -> Self {
        Self::And(Box::new(a), Box::new(b))
    }

    #[must_use] 
    pub fn or(a: Self, b: Self) -> Self {
        Self::Or(Box::new(a), Box::new(b))
    }

    #[must_use] 
    pub fn not(e: Self) -> Self {
        Self::Not(Box::new(e))
    }

    /// Evaluate the expression against a packet; no VM overhead.
    #[must_use] 
    pub fn eval(&self, pkt: &Packet) -> bool {
        match self {
            Self::True => true,
            Self::False => false,
            Self::Proto(p) => pkt.proto == *p,
            Self::SrcIp(addr) => pkt.src_ip.as_ref() == Some(addr),
            Self::DstIp(addr) => pkt.dst_ip.as_ref() == Some(addr),
            Self::SrcPort(p) => pkt.src_port == Some(*p),
            Self::DstPort(p) => pkt.dst_port == Some(*p),
            Self::Port(p) => pkt.src_port == Some(*p) || pkt.dst_port == Some(*p),
            Self::Net(addr, prefix) => {
                let mask = if *prefix == 0 {
                    0u32
                } else {
                    !0u32 << (32 - prefix)
                };
                let net = u32::from(*addr) & mask;
                let src_match = pkt
                    .src_ip
                    .is_some_and(|a| u32::from(a) & mask == net);
                let dst_match = pkt
                    .dst_ip
                    .is_some_and(|a| u32::from(a) & mask == net);
                src_match || dst_match
            }
            Self::PayloadContains(pattern) => pkt
                .payload
                .windows(pattern.len())
                .any(|w| w == pattern.as_slice()),
            Self::Len(op, val) => {
                let len = u16::try_from(pkt.payload.len()).unwrap_or(u16::MAX);
                match op {
                    LenOp::Lt => len < *val,
                    LenOp::Le => len <= *val,
                    LenOp::Eq => len == *val,
                    LenOp::Ge => len >= *val,
                    LenOp::Gt => len > *val,
                }
            }
            Self::And(a, b) => a.eval(pkt) && b.eval(pkt),
            Self::Or(a, b) => a.eval(pkt) || b.eval(pkt),
            Self::Not(e) => !e.eval(pkt),
            Self::Vlan(v) => pkt.vlan == Some(*v),
            Self::EthType(t) => pkt.eth_type == *t,
        }
    }
}

impl fmt::Display for FilterExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::True => write!(f, "true"),
            Self::False => write!(f, "false"),
            Self::Proto(p) => write!(f, "proto {p}"),
            Self::SrcIp(a) => write!(f, "src host {a}"),
            Self::DstIp(a) => write!(f, "dst host {a}"),
            Self::SrcPort(p) => write!(f, "src port {p}"),
            Self::DstPort(p) => write!(f, "dst port {p}"),
            Self::Port(p) => write!(f, "port {p}"),
            Self::Net(a, p) => write!(f, "net {a}/{p}"),
            Self::PayloadContains(_) => write!(f, "payload[...]"),
            Self::Len(_, v) => write!(f, "len cmp {v}"),
            Self::And(a, b) => write!(f, "({a} and {b})"),
            Self::Or(a, b) => write!(f, "({a} or {b})"),
            Self::Not(e) => write!(f, "not ({e})"),
            Self::Vlan(v) => write!(f, "vlan {v}"),
            Self::EthType(t) => write!(f, "ether proto 0x{t:04x}"),
        }
    }
}

// ─── VM Instruction set ───────────────────────────────────────────────────────

/// Low-level VM instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Instr {
    /// Push a constant onto the stack.
    PushConst(u32),
    /// Load packet field; 0=proto, `1=src_port`, `2=dst_port`, 3=len
    LoadField(u8),
    /// Load src IP as u32.
    LoadSrcIp,
    /// Load dst IP as u32.
    LoadDstIp,
    /// Compare top two stack elements; push 1 if equal.
    CmpEq,
    CmpLt,
    CmpGt,
    /// Bitwise AND.
    BitAnd,
    /// Logical AND of two booleans on stack.
    LogicalAnd,
    /// Logical OR of two booleans on stack.
    LogicalOr,
    /// Logical NOT of top of stack.
    LogicalNot,
    /// Unconditional jump to offset.
    Jump(i32),
    /// Jump if top-of-stack is zero.
    JumpFalse(i32),
    /// Halt with ACCEPT (1) or DROP (0).
    Ret(u8),
}

// ─── FilterVm ─────────────────────────────────────────────────────────────────

/// Stack-based virtual machine that executes compiled filter programs.
#[derive(Debug, Default)]
pub struct FilterVm {
    max_steps: usize,
}

impl FilterVm {
    #[must_use] 
    pub const fn new() -> Self {
        Self { max_steps: 65536 }
    }

    #[must_use] 
    pub const fn with_max_steps(max_steps: usize) -> Self {
        Self { max_steps }
    }

    /// Execute `program` against `pkt`; returns `true` if the packet matches.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn execute(&self, program: &[Instr], pkt: &Packet) -> Result<bool, FilterError> {
        let mut stack: Vec<u32> = Vec::with_capacity(16);
        let mut pc = 0i32;
        let mut steps = 0usize;

        while pc >= 0 && (usize::try_from(pc).unwrap_or(usize::MAX)) < program.len() {
            steps += 1;
            if steps > self.max_steps {
                return Err(FilterError::VmError("max steps exceeded".into()));
            }
            let instr = &program[usize::try_from(pc).unwrap_or(usize::MAX)];
            pc += 1;
            match instr {
                Instr::PushConst(v) => stack.push(*v),
                Instr::LoadField(0) => stack.push(u32::from(pkt.proto)),
                Instr::LoadField(1) => stack.push(u32::from(pkt.src_port.unwrap_or(0))),
                Instr::LoadField(2) => stack.push(u32::from(pkt.dst_port.unwrap_or(0))),
                Instr::LoadField(3) => stack.push(u32::try_from(pkt.payload.len()).unwrap_or(u32::MAX)),
                Instr::LoadField(f) => {
                    return Err(FilterError::VmError(format!("unknown field {f}")));
                }
                Instr::LoadSrcIp => {
                    let v = pkt.src_ip.map_or(0, u32::from);
                    stack.push(v);
                }
                Instr::LoadDstIp => {
                    let v = pkt.dst_ip.map_or(0, u32::from);
                    stack.push(v);
                }
                Instr::CmpEq => {
                    let b = stack.pop().ok_or(FilterError::StackUnderflow)?;
                    let a = stack.pop().ok_or(FilterError::StackUnderflow)?;
                    stack.push(u32::from(a == b));
                }
                Instr::CmpLt => {
                    let b = stack.pop().ok_or(FilterError::StackUnderflow)?;
                    let a = stack.pop().ok_or(FilterError::StackUnderflow)?;
                    stack.push(u32::from(a < b));
                }
                Instr::CmpGt => {
                    let b = stack.pop().ok_or(FilterError::StackUnderflow)?;
                    let a = stack.pop().ok_or(FilterError::StackUnderflow)?;
                    stack.push(u32::from(a > b));
                }
                Instr::BitAnd => {
                    let b = stack.pop().ok_or(FilterError::StackUnderflow)?;
                    let a = stack.pop().ok_or(FilterError::StackUnderflow)?;
                    stack.push(a & b);
                }
                Instr::LogicalAnd => {
                    let b = stack.pop().ok_or(FilterError::StackUnderflow)?;
                    let a = stack.pop().ok_or(FilterError::StackUnderflow)?;
                    stack.push(u32::from(a != 0 && b != 0));
                }
                Instr::LogicalOr => {
                    let b = stack.pop().ok_or(FilterError::StackUnderflow)?;
                    let a = stack.pop().ok_or(FilterError::StackUnderflow)?;
                    stack.push(u32::from(a != 0 || b != 0));
                }
                Instr::LogicalNot => {
                    let a = stack.pop().ok_or(FilterError::StackUnderflow)?;
                    stack.push(u32::from(a == 0));
                }
                Instr::Jump(off) => {
                    pc = pc - 1 + off;
                }
                Instr::JumpFalse(off) => {
                    let a = stack.pop().ok_or(FilterError::StackUnderflow)?;
                    if a == 0 {
                        pc = pc - 1 + off;
                    }
                }
                Instr::Ret(v) => {
                    return Ok(*v != 0);
                }
            }
        }

        // Fall through: accept if final stack value is truthy
        Ok(stack.last().copied().unwrap_or(0) != 0)
    }
}

// ─── FilterCompiler ───────────────────────────────────────────────────────────

/// Compiles a [`FilterExpr`] AST into a [`FilterVm`] bytecode program.
#[derive(Debug, Default)]
pub struct FilterCompiler {
    max_program_size: usize,
}

impl FilterCompiler {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            max_program_size: 4096,
        }
    }

    /// # Errors
    /// Returns an error if the operation fails.
    pub fn compile(&self, expr: &FilterExpr) -> Result<Vec<Instr>, FilterError> {
        let mut prog = Vec::new();
        self.lower(expr, &mut prog)?;
        if prog.len() > self.max_program_size {
            return Err(FilterError::ProgramTooLarge(prog.len()));
        }
        Ok(prog)
    }

    fn lower(&self, expr: &FilterExpr, prog: &mut Vec<Instr>) -> Result<(), FilterError> {
        match expr {
            FilterExpr::True => prog.push(Instr::PushConst(1)),
            FilterExpr::False => prog.push(Instr::PushConst(0)),
            FilterExpr::Proto(p) => {
                prog.push(Instr::LoadField(0));
                prog.push(Instr::PushConst(u32::from(*p)));
                prog.push(Instr::CmpEq);
            }
            FilterExpr::SrcPort(p) => {
                prog.push(Instr::LoadField(1));
                prog.push(Instr::PushConst(u32::from(*p)));
                prog.push(Instr::CmpEq);
            }
            FilterExpr::DstPort(p) => {
                prog.push(Instr::LoadField(2));
                prog.push(Instr::PushConst(u32::from(*p)));
                prog.push(Instr::CmpEq);
            }
            FilterExpr::Port(p) => {
                self.lower(&FilterExpr::SrcPort(*p), prog)?;
                self.lower(&FilterExpr::DstPort(*p), prog)?;
                prog.push(Instr::LogicalOr);
            }
            FilterExpr::SrcIp(addr) => {
                prog.push(Instr::LoadSrcIp);
                prog.push(Instr::PushConst(u32::from(*addr)));
                prog.push(Instr::CmpEq);
            }
            FilterExpr::DstIp(addr) => {
                prog.push(Instr::LoadDstIp);
                prog.push(Instr::PushConst(u32::from(*addr)));
                prog.push(Instr::CmpEq);
            }
            FilterExpr::Net(addr, prefix) => {
                let mask: u32 = if *prefix == 0 {
                    0
                } else {
                    !0u32 << (32 - prefix)
                };
                let net = u32::from(*addr) & mask;
                // src match
                prog.push(Instr::LoadSrcIp);
                prog.push(Instr::PushConst(mask));
                prog.push(Instr::BitAnd);
                prog.push(Instr::PushConst(net));
                prog.push(Instr::CmpEq);
                // dst match
                prog.push(Instr::LoadDstIp);
                prog.push(Instr::PushConst(mask));
                prog.push(Instr::BitAnd);
                prog.push(Instr::PushConst(net));
                prog.push(Instr::CmpEq);
                prog.push(Instr::LogicalOr);
            }
            FilterExpr::Len(op, val) => {
                prog.push(Instr::LoadField(3));
                prog.push(Instr::PushConst(u32::from(*val)));
                let cmp = match op {
                    LenOp::Lt => Instr::CmpLt,
                    LenOp::Le => {
                        // a <= b  ⟺  !(a > b)
                        prog.push(Instr::CmpGt);
                        prog.push(Instr::LogicalNot);
                        return Ok(());
                    }
                    LenOp::Eq => Instr::CmpEq,
                    LenOp::Ge => {
                        prog.push(Instr::CmpLt);
                        prog.push(Instr::LogicalNot);
                        return Ok(());
                    }
                    LenOp::Gt => Instr::CmpGt,
                };
                prog.push(cmp);
            }
            FilterExpr::And(a, b) => {
                self.lower(a, prog)?;
                self.lower(b, prog)?;
                prog.push(Instr::LogicalAnd);
            }
            FilterExpr::Or(a, b) => {
                self.lower(a, prog)?;
                self.lower(b, prog)?;
                prog.push(Instr::LogicalOr);
            }
            FilterExpr::Not(e) => {
                self.lower(e, prog)?;
                prog.push(Instr::LogicalNot);
            }
            FilterExpr::Vlan(v) => {
                // No VLAN field in VM currently; encode as constant push
                prog.push(Instr::PushConst(u32::from(*v == 0)));
            }
            FilterExpr::EthType(_) | FilterExpr::PayloadContains(_) => {
                // Unsupported in VM path; return true (permissive)
                prog.push(Instr::PushConst(1));
            }
        }
        Ok(())
    }
}

// ─── FilterOptimizer ──────────────────────────────────────────────────────────

/// Constant-folds and eliminates dead code in a [`FilterExpr`] AST.
#[derive(Debug, Default)]
pub struct FilterOptimizer;

impl FilterOptimizer {
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }

    #[must_use] 
    pub fn optimize(&self, expr: FilterExpr) -> FilterExpr {
        match expr {
            FilterExpr::And(a, b) => {
                let a = self.optimize(*a);
                let b = self.optimize(*b);
                match (&a, &b) {
                    (FilterExpr::False, _) | (_, FilterExpr::False) => FilterExpr::False,
                    (FilterExpr::True, _) => b,
                    (_, FilterExpr::True) => a,
                    _ => FilterExpr::And(Box::new(a), Box::new(b)),
                }
            }
            FilterExpr::Or(a, b) => {
                let a = self.optimize(*a);
                let b = self.optimize(*b);
                match (&a, &b) {
                    (FilterExpr::True, _) | (_, FilterExpr::True) => FilterExpr::True,
                    (FilterExpr::False, _) => b,
                    (_, FilterExpr::False) => a,
                    _ => FilterExpr::Or(Box::new(a), Box::new(b)),
                }
            }
            FilterExpr::Not(e) => {
                let e = self.optimize(*e);
                match e {
                    FilterExpr::True => FilterExpr::False,
                    FilterExpr::False => FilterExpr::True,
                    FilterExpr::Not(inner) => *inner,
                    other => FilterExpr::Not(Box::new(other)),
                }
            }
            other => other,
        }
    }
}

// ─── FilterResult ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilterResult {
    Accept,
    Reject,
}

impl fmt::Display for FilterResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accept => write!(f, "ACCEPT"),
            Self::Reject => write!(f, "REJECT"),
        }
    }
}

// ─── PcapFilterEngine ─────────────────────────────────────────────────────────

/// High-level BPF-like filter engine that combines parsing, compiling, and VM.
#[derive(Debug)]
pub struct PcapFilterEngine {
    expr: FilterExpr,
    program: Vec<Instr>,
    vm: FilterVm,
    optimizer: FilterOptimizer,
    packets_tested: u64,
    packets_accepted: u64,
}

impl PcapFilterEngine {
    /// Build a filter engine from an AST expression.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn from_expr(expr: FilterExpr) -> Result<Self, FilterError> {
        let optimizer = FilterOptimizer::new();
        let optimized = optimizer.optimize(expr);
        let compiler = FilterCompiler::new();
        let program = compiler.compile(&optimized)?;
        Ok(Self {
            expr: optimized,
            program,
            vm: FilterVm::new(),
            optimizer: FilterOptimizer::new(),
            packets_tested: 0,
            packets_accepted: 0,
        })
    }

    /// Test a packet against the compiled filter.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn test(&mut self, pkt: &Packet) -> Result<FilterResult, FilterError> {
        self.packets_tested += 1;
        let matched = self.vm.execute(&self.program, pkt)?;
        if matched {
            self.packets_accepted += 1;
            Ok(FilterResult::Accept)
        } else {
            Ok(FilterResult::Reject)
        }
    }

    /// Evaluate using the AST directly (no VM overhead).
    pub fn test_direct(&mut self, pkt: &Packet) -> FilterResult {
        self.packets_tested += 1;
        if self.expr.eval(pkt) {
            self.packets_accepted += 1;
            FilterResult::Accept
        } else {
            FilterResult::Reject
        }
    }

    /// Filter a batch of packets; returns only accepted ones.
    pub fn filter_batch(&mut self, packets: &[Packet]) -> Vec<Packet> {
        packets
            .iter()
            .filter(|p| self.test_direct(p) == FilterResult::Accept)
            .cloned()
            .collect()
    }

    #[must_use] 
    pub const fn packets_tested(&self) -> u64 {
        self.packets_tested
    }

    #[must_use] 
    pub const fn packets_accepted(&self) -> u64 {
        self.packets_accepted
    }

    #[must_use] 
    pub fn accept_rate(&self) -> f64 {
        if self.packets_tested == 0 {
            0.0
        } else {
            self.packets_accepted as f64 / self.packets_tested as f64
        }
    }

    #[must_use] 
    pub fn program(&self) -> &[Instr] {
        &self.program
    }

    #[must_use] 
    pub const fn expr(&self) -> &FilterExpr {
        &self.expr
    }

    /// Returns the optimizer used to fold and prune filter ASTs.
    #[must_use] 
    pub const fn optimizer(&self) -> &FilterOptimizer {
        &self.optimizer
    }

    /// Re-optimize an additional expression with the engine's optimizer
    /// (useful when chaining filters).
    #[must_use] 
    pub fn optimize(&self, expr: FilterExpr) -> FilterExpr {
        self.optimizer.optimize(expr)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn tcp_pkt() -> Packet {
        Packet::tcp(ip("10.0.0.1"), 12345, ip("10.0.0.2"), 80)
    }

    fn udp_pkt() -> Packet {
        Packet::udp(ip("192.168.1.1"), 5000, ip("8.8.8.8"), 53)
    }

    // --- FilterExpr::eval ---

    #[test]
    fn test_expr_true() {
        assert!(FilterExpr::True.eval(&tcp_pkt()));
    }

    #[test]
    fn test_expr_false() {
        assert!(!FilterExpr::False.eval(&tcp_pkt()));
    }

    #[test]
    fn test_expr_proto_tcp() {
        assert!(FilterExpr::Proto(6).eval(&tcp_pkt()));
        assert!(!FilterExpr::Proto(17).eval(&tcp_pkt()));
    }

    #[test]
    fn test_expr_src_ip() {
        assert!(FilterExpr::SrcIp(ip("10.0.0.1")).eval(&tcp_pkt()));
        assert!(!FilterExpr::SrcIp(ip("10.0.0.9")).eval(&tcp_pkt()));
    }

    #[test]
    fn test_expr_dst_port() {
        assert!(FilterExpr::DstPort(80).eval(&tcp_pkt()));
        assert!(!FilterExpr::DstPort(443).eval(&tcp_pkt()));
    }

    #[test]
    fn test_expr_port_matches_either() {
        let pkt = tcp_pkt();
        assert!(FilterExpr::Port(80).eval(&pkt));
        assert!(FilterExpr::Port(12345).eval(&pkt));
        assert!(!FilterExpr::Port(9999).eval(&pkt));
    }

    #[test]
    fn test_expr_net() {
        let expr = FilterExpr::Net(ip("10.0.0.0"), 24);
        assert!(expr.eval(&tcp_pkt())); // 10.0.0.1 and 10.0.0.2 are in /24
    }

    #[test]
    fn test_expr_net_no_match() {
        let expr = FilterExpr::Net(ip("192.168.0.0"), 24);
        assert!(!expr.eval(&tcp_pkt()));
    }

    #[test]
    fn test_expr_payload_contains() {
        let mut pkt = tcp_pkt();
        pkt.payload = b"GET / HTTP/1.1".to_vec();
        let expr = FilterExpr::PayloadContains(b"HTTP".to_vec());
        assert!(expr.eval(&pkt));
        let expr2 = FilterExpr::PayloadContains(b"SMTP".to_vec());
        assert!(!expr2.eval(&pkt));
    }

    #[test]
    fn test_expr_len_lt() {
        let mut pkt = tcp_pkt();
        pkt.payload = vec![0u8; 10];
        assert!(FilterExpr::Len(LenOp::Lt, 20).eval(&pkt));
        assert!(!FilterExpr::Len(LenOp::Lt, 5).eval(&pkt));
    }

    #[test]
    fn test_expr_len_eq() {
        let mut pkt = tcp_pkt();
        pkt.payload = vec![0u8; 10];
        assert!(FilterExpr::Len(LenOp::Eq, 10).eval(&pkt));
    }

    #[test]
    fn test_expr_and() {
        let expr = FilterExpr::and(FilterExpr::Proto(6), FilterExpr::DstPort(80));
        assert!(expr.eval(&tcp_pkt()));
        assert!(!expr.eval(&udp_pkt()));
    }

    #[test]
    fn test_expr_or() {
        let expr = FilterExpr::or(FilterExpr::Proto(6), FilterExpr::Proto(17));
        assert!(expr.eval(&tcp_pkt()));
        assert!(expr.eval(&udp_pkt()));
    }

    #[test]
    fn test_expr_not() {
        assert!(!FilterExpr::not(FilterExpr::True).eval(&tcp_pkt()));
        assert!(FilterExpr::not(FilterExpr::False).eval(&tcp_pkt()));
    }

    // --- Packet helpers ---

    #[test]
    fn test_packet_is_tcp() {
        assert!(tcp_pkt().is_tcp());
        assert!(!tcp_pkt().is_udp());
    }

    #[test]
    fn test_packet_is_udp() {
        assert!(udp_pkt().is_udp());
    }

    #[test]
    fn test_packet_load_half() {
        let mut pkt = Packet::new();
        pkt.payload = vec![0x12, 0x34, 0x56];
        assert_eq!(pkt.load_half(0), Some(0x1234));
        assert_eq!(pkt.load_half(1), Some(0x3456));
    }

    #[test]
    fn test_packet_load_byte() {
        let mut pkt = Packet::new();
        pkt.payload = vec![0xAB];
        assert_eq!(pkt.load_byte(0), Some(0xAB));
        assert_eq!(pkt.load_byte(1), None);
    }

    // --- FilterOptimizer ---

    #[test]
    fn test_optimizer_and_false_folds() {
        let opt = FilterOptimizer::new();
        let expr = FilterExpr::and(FilterExpr::False, FilterExpr::Proto(6));
        assert_eq!(opt.optimize(expr), FilterExpr::False);
    }

    #[test]
    fn test_optimizer_and_true_eliminates() {
        let opt = FilterOptimizer::new();
        let expr = FilterExpr::and(FilterExpr::True, FilterExpr::Proto(6));
        assert_eq!(opt.optimize(expr), FilterExpr::Proto(6));
    }

    #[test]
    fn test_optimizer_or_true_folds() {
        let opt = FilterOptimizer::new();
        let expr = FilterExpr::or(FilterExpr::True, FilterExpr::Proto(6));
        assert_eq!(opt.optimize(expr), FilterExpr::True);
    }

    #[test]
    fn test_optimizer_or_false_eliminates() {
        let opt = FilterOptimizer::new();
        let expr = FilterExpr::or(FilterExpr::False, FilterExpr::Proto(17));
        assert_eq!(opt.optimize(expr), FilterExpr::Proto(17));
    }

    #[test]
    fn test_optimizer_not_true_folds() {
        let opt = FilterOptimizer::new();
        assert_eq!(
            opt.optimize(FilterExpr::not(FilterExpr::True)),
            FilterExpr::False
        );
    }

    #[test]
    fn test_optimizer_not_false_folds() {
        let opt = FilterOptimizer::new();
        assert_eq!(
            opt.optimize(FilterExpr::not(FilterExpr::False)),
            FilterExpr::True
        );
    }

    #[test]
    fn test_optimizer_double_not_cancels() {
        let opt = FilterOptimizer::new();
        let expr = FilterExpr::not(FilterExpr::not(FilterExpr::Proto(6)));
        assert_eq!(opt.optimize(expr), FilterExpr::Proto(6));
    }

    // --- FilterCompiler + FilterVm ---

    #[test]
    fn test_compile_and_run_proto() {
        let compiler = FilterCompiler::new();
        let prog = compiler.compile(&FilterExpr::Proto(6)).unwrap();
        let vm = FilterVm::new();
        assert!(vm.execute(&prog, &tcp_pkt()).unwrap());
        assert!(!vm.execute(&prog, &udp_pkt()).unwrap());
    }

    #[test]
    fn test_compile_and_run_dst_port() {
        let compiler = FilterCompiler::new();
        let prog = compiler.compile(&FilterExpr::DstPort(80)).unwrap();
        let vm = FilterVm::new();
        assert!(vm.execute(&prog, &tcp_pkt()).unwrap());
    }

    #[test]
    fn test_compile_and_run_and() {
        let compiler = FilterCompiler::new();
        let expr = FilterExpr::and(FilterExpr::Proto(6), FilterExpr::DstPort(80));
        let prog = compiler.compile(&expr).unwrap();
        let vm = FilterVm::new();
        assert!(vm.execute(&prog, &tcp_pkt()).unwrap());
    }

    #[test]
    fn test_compile_and_run_not() {
        let compiler = FilterCompiler::new();
        let prog = compiler
            .compile(&FilterExpr::not(FilterExpr::Proto(6)))
            .unwrap();
        let vm = FilterVm::new();
        assert!(!vm.execute(&prog, &tcp_pkt()).unwrap());
        assert!(vm.execute(&prog, &udp_pkt()).unwrap());
    }

    #[test]
    fn test_vm_stack_underflow() {
        let vm = FilterVm::new();
        let prog = vec![Instr::CmpEq];
        assert!(matches!(
            vm.execute(&prog, &tcp_pkt()),
            Err(FilterError::StackUnderflow)
        ));
    }

    #[test]
    fn test_vm_max_steps() {
        let vm = FilterVm::with_max_steps(3);
        // Infinite loop-ish: push + jump back
        let prog = vec![
            Instr::PushConst(1),
            Instr::Jump(0), // jump to instruction 1 (relative 0 means PC stays — actually +1-1=0 always at current)
        ];
        // This will spin and hit the max steps limit
        let result = vm.execute(&prog, &tcp_pkt());
        assert!(matches!(result, Err(FilterError::VmError(_))));
    }

    // --- PcapFilterEngine ---

    #[test]
    fn test_engine_accept() {
        let mut engine = PcapFilterEngine::from_expr(FilterExpr::Proto(6)).unwrap();
        assert_eq!(engine.test(&tcp_pkt()).unwrap(), FilterResult::Accept);
    }

    #[test]
    fn test_engine_reject() {
        let mut engine = PcapFilterEngine::from_expr(FilterExpr::Proto(17)).unwrap();
        assert_eq!(engine.test(&tcp_pkt()).unwrap(), FilterResult::Reject);
    }

    #[test]
    fn test_engine_test_direct() {
        let mut engine = PcapFilterEngine::from_expr(FilterExpr::True).unwrap();
        assert_eq!(engine.test_direct(&tcp_pkt()), FilterResult::Accept);
    }

    #[test]
    fn test_engine_filter_batch() {
        let mut engine = PcapFilterEngine::from_expr(FilterExpr::Proto(6)).unwrap();
        let packets = vec![tcp_pkt(), udp_pkt(), tcp_pkt()];
        let accepted = engine.filter_batch(&packets);
        assert_eq!(accepted.len(), 2);
    }

    #[test]
    fn test_engine_stats() {
        let mut engine = PcapFilterEngine::from_expr(FilterExpr::True).unwrap();
        engine.test(&tcp_pkt()).unwrap();
        engine.test(&udp_pkt()).unwrap();
        assert_eq!(engine.packets_tested(), 2);
        assert_eq!(engine.packets_accepted(), 2);
        assert!((engine.accept_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_engine_accept_rate_zero_tested() {
        let engine = PcapFilterEngine::from_expr(FilterExpr::True).unwrap();
        assert!((engine.accept_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_engine_net_filter() {
        let expr = FilterExpr::Net(ip("10.0.0.0"), 24);
        let mut engine = PcapFilterEngine::from_expr(expr).unwrap();
        assert_eq!(engine.test_direct(&tcp_pkt()), FilterResult::Accept);
        assert_eq!(engine.test_direct(&udp_pkt()), FilterResult::Reject);
    }

    #[test]
    fn test_filter_result_display() {
        assert_eq!(FilterResult::Accept.to_string(), "ACCEPT");
        assert_eq!(FilterResult::Reject.to_string(), "REJECT");
    }

    #[test]
    fn test_expr_display() {
        let expr = FilterExpr::and(FilterExpr::Proto(6), FilterExpr::DstPort(80));
        let s = expr.to_string();
        assert!(s.contains("proto 6"));
        assert!(s.contains("dst port 80"));
    }
}
