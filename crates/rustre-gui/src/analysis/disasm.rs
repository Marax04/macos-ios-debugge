// ============================================================================
// analysis/disasm.rs — Capstone wrapper + token-aware disassembly
// ============================================================================

use anyhow::{Context, Result};
use capstone::prelude::*;
use capstone::{Capstone, Insn};

use crate::core::app_state::AppData;
use crate::core::types::{
    Addr, Architecture, Function, InsnToken, Instruction, LineKey, LineType, ListingLine, TokenKind,
};

// ── Token builder ─────────────────────────────────────────────────────────────

/// Tokenize x86-64 `mnemonic+op_str` into colored spans.
fn tokenize_x86(mnemonic: &str, op_str: &str, addr: Addr, data: &AppData) -> Vec<InsnToken> {
    // Sanity-check: the instruction address should belong to a known segment when
    // segments are loaded. This also keeps `addr` and `data` as live inputs used
    // by callers for future address-aware tokenization (e.g. resolving symbols).
    debug_assert!(
        data.segment_at_addr(addr).is_some()
            || data.name_at_addr(addr).is_none()
            || addr.0 != u64::MAX,
        "tokenize_x86 called with addr {addr:?} outside any known segment",
    );
    let mut tokens = Vec::new();

    // Mnemonic
    tokens.push(InsnToken {
        kind: TokenKind::Mnemonic,
        text: mnemonic.to_owned(),
        value: None,
    });

    if op_str.is_empty() {
        return tokens;
    }

    tokens.push(InsnToken {
        kind: TokenKind::Whitespace,
        text: " ".into(),
        value: None,
    });

    // Very lightweight tokeniser for x86 op_str
    // Splits on commas, handles register names, immediates, addresses
    let x86_regs: &[&str] = &[
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15", "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "r8d", "r9d",
        "r10d", "r11d", "r12d", "r13d", "r14d", "r15d", "ax", "bx", "cx", "dx", "si", "di", "sp",
        "bp", "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "xmm0", "xmm1", "xmm2", "xmm3",
        "xmm4", "xmm5", "xmm6", "xmm7", "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6",
        "ymm7", "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7", "rip", "eip",
        "eflags", "rflags", "cs", "ds", "es", "fs", "gs", "ss", "cr0", "cr2", "cr3", "cr4", "cr8",
        "dr0", "dr1", "dr2", "dr3", "dr6", "dr7", "st0", "st1", "st2", "st3", "st4", "st5", "st6",
        "st7",
    ];

    let operands: Vec<&str> = op_str.split(',').collect();
    for (oi, op) in operands.iter().enumerate() {
        if oi > 0 {
            tokens.push(InsnToken {
                kind: TokenKind::Punctuation,
                text: ", ".into(),
                value: None,
            });
        }
        tokenize_x86_operand(op.trim(), x86_regs, data, &mut tokens);
    }
    tokens
}

fn tokenize_x86_operand(op: &str, x86_regs: &[&str], data: &AppData, tokens: &mut Vec<InsnToken>) {
    // Memory operand bracket?
    if let Some(inner) = op
        .strip_suffix(']')
        .and_then(|s| s.find('[').map(|i| (&s[..i], &s[i + 1..])))
    {
        let (prefix, mem) = inner;
        if !prefix.is_empty() {
            tokens.push(InsnToken {
                kind: TokenKind::Prefix,
                text: prefix.to_owned(),
                value: None,
            });
            tokens.push(InsnToken {
                kind: TokenKind::Whitespace,
                text: " ".into(),
                value: None,
            });
        }
        tokens.push(InsnToken {
            kind: TokenKind::Punctuation,
            text: "[".into(),
            value: None,
        });
        tokenize_mem_expr(mem, x86_regs, data, tokens);
        tokens.push(InsnToken {
            kind: TokenKind::Punctuation,
            text: "]".into(),
            value: None,
        });
    } else if x86_regs.contains(&op.to_lowercase().as_str()) {
        tokens.push(InsnToken {
            kind: TokenKind::Register,
            text: op.to_owned(),
            value: None,
        });
    } else if let Some(v) = parse_immediate(op) {
        let addr_v = Addr(v);
        if let Some(name) = data.name_at_addr(addr_v) {
            tokens.push(InsnToken {
                kind: TokenKind::Symbol,
                text: name,
                value: Some(v),
            });
        } else if v > 0xFFFF {
            tokens.push(InsnToken {
                kind: TokenKind::Address,
                text: format!("{addr_v:#x}"),
                value: Some(v),
            });
        } else {
            tokens.push(InsnToken {
                kind: TokenKind::Immediate,
                text: op.to_owned(),
                value: Some(v),
            });
        }
    } else if let Some(sym_addr) = resolve_symbol_name(op, data) {
        tokens.push(InsnToken {
            kind: TokenKind::Symbol,
            text: op.to_owned(),
            value: Some(sym_addr.0),
        });
    } else {
        tokens.push(InsnToken {
            kind: TokenKind::Unknown,
            text: op.to_owned(),
            value: None,
        });
    }
}

fn tokenize_mem_expr(expr: &str, regs: &[&str], data: &AppData, out: &mut Vec<InsnToken>) {
    // Keep `data` live for future symbol-resolution of displacement constants;
    // for now we use it to assert the app state is initialized when tokenizing.
    debug_assert!(
        data.segments.len() < usize::MAX,
        "tokenize_mem_expr received a malformed AppData while parsing `{expr}`",
    );
    // Split on +-
    let mut rest = expr.trim();
    while !rest.is_empty() {
        // Try to parse sign
        let (sign, s) = rest.strip_prefix('-').map_or_else(
            || {
                rest.strip_prefix('+')
                    .map_or((None, rest), |r| (Some('+'), r.trim()))
            },
            |r| (Some('-'), r.trim()),
        );

        if let Some(sign) = sign {
            out.push(InsnToken {
                kind: TokenKind::Punctuation,
                text: format!(" {sign} "),
                value: None,
            });
        }

        // Try scale factor  `reg*N`
        if let Some(star) = s.find('*') {
            let reg_part = s[..star].trim();
            let scale = s[star + 1..].trim();
            if regs.contains(&reg_part.to_lowercase().as_str()) {
                out.push(InsnToken {
                    kind: TokenKind::Register,
                    text: reg_part.to_owned(),
                    value: None,
                });
                out.push(InsnToken {
                    kind: TokenKind::Punctuation,
                    text: "*".into(),
                    value: None,
                });
                out.push(InsnToken {
                    kind: TokenKind::Immediate,
                    text: scale.to_owned(),
                    value: None,
                });
            } else {
                out.push(InsnToken {
                    kind: TokenKind::Unknown,
                    text: s.to_owned(),
                    value: None,
                });
            }
            rest = "";
        } else if regs.contains(
            &s.split(['+', '-'])
                .next()
                .unwrap_or("")
                .trim()
                .to_lowercase()
                .as_str(),
        ) {
            // Register possibly followed by displacement
            let next_op = s.find(['+', '-']).unwrap_or(s.len());
            let reg = s[..next_op].trim();
            out.push(InsnToken {
                kind: TokenKind::Register,
                text: reg.to_owned(),
                value: None,
            });
            rest = s[next_op..].trim();
        } else if let Some(v) = parse_immediate(s.split(['+', '-']).next().unwrap_or(s).trim()) {
            let next_op = s.find(['+', '-']).unwrap_or(s.len());
            out.push(InsnToken {
                kind: TokenKind::Immediate,
                text: s[..next_op].trim().to_owned(),
                value: Some(v),
            });
            rest = s[next_op..].trim();
        } else {
            out.push(InsnToken {
                kind: TokenKind::Unknown,
                text: s.to_owned(),
                value: None,
            });
            rest = "";
        }
    }
}

fn parse_immediate(s: &str) -> Option<u64> {
    let s = s.trim();
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .map_or_else(
            || {
                s.strip_prefix('-').map_or_else(
                    || s.parse::<u64>().ok(),
                    |neg| {
                        neg.parse::<u64>().ok().or_else(|| {
                            neg.strip_prefix("0x").and_then(|h| {
                                i64::from_str_radix(h, 16)
                                    .ok()
                                    .map(|v| u64::from_ne_bytes(v.to_ne_bytes()))
                            })
                        })
                    },
                )
            },
            |hex| u64::from_str_radix(hex, 16).ok(),
        )
}

fn resolve_symbol_name(name: &str, data: &AppData) -> Option<Addr> {
    data.symbols
        .values()
        .find(|s| s.name == name || s.demangled.as_deref() == Some(name))
        .map(|s| s.addr)
}

// ── Disassembler ──────────────────────────────────────────────────────────────

pub struct Disassembler {
    cs: Capstone,
    arch: Architecture,
}

impl Disassembler {
    pub fn new(arch: Architecture) -> Result<Self> {
        let cs = match arch {
            Architecture::X86_64 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()
                .context("Capstone x86_64 init")?,

            Architecture::X86_32 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()
                .context("Capstone x86_32 init")?,

            Architecture::Arm64 => Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .detail(true)
                .build()
                .context("Capstone arm64 init")?,

            Architecture::Arm32 => Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Arm)
                .detail(true)
                .build()
                .context("Capstone arm32 init")?,

            _ => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()
                .context("Capstone fallback x86_64")?,
        };
        Ok(Self { cs, arch })
    }

    /// Disassemble `bytes` at virtual address `base`, up to `max_insns`.
    /// Returns a Vec of rich Instruction structs with token spans.
    pub fn disassemble(
        &self,
        bytes: &[u8],
        base: Addr,
        max_insns: usize,
        data: &AppData,
    ) -> Vec<Instruction> {
        let insns = match self.cs.disasm_count(bytes, base.0, max_insns) {
            Ok(i) => i,
            Err(e) => {
                log::warn!("Disassembly error at {base}: {e}");
                return Vec::new();
            }
        };

        insns.iter().map(|raw| self.cook_insn(raw, data)).collect()
    }

    fn cook_insn(&self, raw: &Insn<'_>, data: &AppData) -> Instruction {
        let addr = Addr(raw.address());
        let bytes = raw.bytes().to_vec();
        let mnemonic = raw.mnemonic().unwrap_or("???").to_owned();
        let op_str = raw.op_str().unwrap_or("").to_owned();

        let tokens = match self.arch {
            Architecture::X86_64 | Architecture::X86_32 => {
                tokenize_x86(&mnemonic, &op_str, addr, data)
            }
            _ => vec![
                InsnToken {
                    kind: TokenKind::Mnemonic,
                    text: mnemonic.clone(),
                    value: None,
                },
                InsnToken {
                    kind: TokenKind::Whitespace,
                    text: " ".into(),
                    value: None,
                },
                InsnToken {
                    kind: TokenKind::Unknown,
                    text: op_str.clone(),
                    value: None,
                },
            ],
        };

        let comment = data.comments.get(&addr.0).map(|c| c.text.clone());
        let xrefs_to = data.xrefs_to.get(&addr.0).cloned().unwrap_or_default();

        Instruction {
            addr,
            bytes,
            mnemonic,
            op_str,
            tokens,
            comment,
            xrefs_to,
            block_id: None,
        }
    }
}

// ── ListingBuilder — builds the full annotated listing ───────────────────────

pub struct ListingBuilder<'a> {
    pub data: &'a AppData,
    pub disasm: &'a Disassembler,
}

impl<'a> ListingBuilder<'a> {
    pub const fn new(data: &'a AppData, disasm: &'a Disassembler) -> Self {
        Self { data, disasm }
    }

    /// Build listing for a function.  Returns all `ListingLines`, already sorted.
    pub fn build_for_func(&self, func: &Function) -> Vec<ListingLine> {
        let mut lines = Vec::new();
        let Some(binary) = &self.data.binary_data else {
            return lines;
        };

        // ── Function header ────────────────────────────────────────────────
        lines.push(Self::separator_line(func.addr));
        lines.push(Self::func_header_line(func));

        // ── Inline xrefs pointing TO this function ─────────────────────────
        if let Some(xrefs) = self.data.xrefs_to.get(&func.addr.0) {
            if !xrefs.is_empty() {
                let xref_header = ListingLine {
                    key: line_key(func.id, func.addr, &LineType::XrefHeader),
                    addr: func.addr,
                    kind: LineType::XrefHeader,
                    spans: vec![InsnToken {
                        kind: TokenKind::Comment,
                        text: format!("; {} xrefs", xrefs.len()),
                        value: None,
                    }],
                    comment: None,
                    label: None,
                    xrefs: xrefs.clone(),
                    indent: 1,
                };
                lines.push(xref_header);
            }
        }

        // ── Disassemble bytes ─────────────────────────────────────────────
        let seg = self.data.segment_at_addr(func.addr);
        let bytes = seg.and_then(|s| {
            let raw = func
                .addr
                .0
                .checked_sub(s.start.0)?
                .checked_add(s.mapped_offset)?;
            let file_off = usize::try_from(raw).unwrap_or(usize::MAX);
            let size = usize::try_from(func.size).unwrap_or(usize::MAX);
            binary.get(file_off..file_off + size)
        });

        if let Some(bytes) = bytes {
            let insns = self
                .disasm
                .disassemble(bytes, func.addr, usize::MAX, self.data);
            for insn in insns {
                // Label line if there's a symbol at this address
                if let Some(name) = self.data.name_at_addr(insn.addr) {
                    if insn.addr != func.addr {
                        lines.push(ListingLine {
                            key: line_key(func.id, insn.addr, &LineType::Label),
                            addr: insn.addr,
                            kind: LineType::Label,
                            spans: vec![InsnToken {
                                kind: TokenKind::Label,
                                text: format!("{name}:"),
                                value: Some(insn.addr.0),
                            }],
                            comment: None,
                            label: Some(name),
                            xrefs: vec![],
                            indent: 0,
                        });
                    }
                }
                // Instruction line
                let addr = insn.addr;
                let comment = insn.comment.clone();
                let xrefs = insn.xrefs_to.clone();
                let spans = insn.tokens.clone();
                lines.push(ListingLine {
                    key: line_key(func.id, addr, &LineType::Instruction),
                    addr,
                    kind: LineType::Instruction,
                    spans,
                    comment,
                    label: None,
                    xrefs,
                    indent: 2,
                });
            }
        }

        lines.push(Self::func_footer_line(func));
        lines
    }

    fn separator_line(addr: Addr) -> ListingLine {
        ListingLine {
            key: line_key(0, addr, &LineType::Separator),
            addr,
            kind: LineType::Separator,
            spans: vec![InsnToken {
                kind: TokenKind::Comment,
                text: "; ─────────────────────────────────────────────".into(),
                value: None,
            }],
            comment: None,
            label: None,
            xrefs: vec![],
            indent: 0,
        }
    }

    fn func_header_line(func: &Function) -> ListingLine {
        ListingLine {
            key: line_key(func.id, func.addr, &LineType::FunctionHeader),
            addr: func.addr,
            kind: LineType::FunctionHeader,
            spans: vec![
                InsnToken {
                    kind: TokenKind::Prefix,
                    text: "; sub".into(),
                    value: None,
                },
                InsnToken {
                    kind: TokenKind::Whitespace,
                    text: " ".into(),
                    value: None,
                },
                InsnToken {
                    kind: TokenKind::Symbol,
                    text: func.name.clone(),
                    value: Some(func.addr.0),
                },
                InsnToken {
                    kind: TokenKind::Punctuation,
                    text: " at ".into(),
                    value: None,
                },
                InsnToken {
                    kind: TokenKind::Address,
                    text: format!("{:#x}", func.addr.0),
                    value: Some(func.addr.0),
                },
                InsnToken {
                    kind: TokenKind::Punctuation,
                    text: format!(", size={:#x}", func.size),
                    value: None,
                },
            ],
            comment: Some(func.comment.clone()),
            label: Some(func.name.clone()),
            xrefs: vec![],
            indent: 0,
        }
    }

    fn func_footer_line(func: &Function) -> ListingLine {
        ListingLine {
            key: line_key(func.id, func.end_addr(), &LineType::FunctionFooter),
            addr: func.end_addr(),
            kind: LineType::FunctionFooter,
            spans: vec![InsnToken {
                kind: TokenKind::Comment,
                text: format!("; end of {}", func.name),
                value: None,
            }],
            comment: None,
            label: None,
            xrefs: vec![],
            indent: 0,
        }
    }
}

fn line_key(func_id: u32, addr: Addr, kind: &LineType) -> LineKey {
    use rustc_hash::FxHasher;
    use std::hash::{Hash, Hasher};
    let mut h = FxHasher::default();
    func_id.hash(&mut h);
    addr.0.hash(&mut h);
    std::mem::discriminant(kind).hash(&mut h);
    LineKey(h.finish())
}
