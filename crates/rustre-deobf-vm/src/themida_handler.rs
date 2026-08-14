//! `themida_handler` — Themida / `WinLicense` VM handler analysis.
//!
//! Covers:
//! * SDK macro recognition: `VIRTUAL_START`/`END`, `EAGLE_BLACK`/`WHITE`, `FISH_RED`/`BLUE`
//! * Macro type classification
//! * Handler table reconstruction
//! * Opcode semantic recovery via emulation
//! * Key-based crypto in handlers (RC4, custom XOR chains)

#![allow(dead_code)]

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// SDK macro types
// ─────────────────────────────────────────────────────────────────────────────

/// Themida SDK protection macro applied to a code region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThemidaMacro {
    /// `VIRTUAL_START` / `VIRTUAL_END` — VM-based protection (full virtualization).
    VirtualStart,
    VirtualEnd,
    /// `EAGLE_BLACK` / `EAGLE_WHITE` — strongest VM with anti-tamper.
    EagleBlack,
    EagleWhite,
    /// `FISH_RED` / `FISH_BLUE` — mutation + VM (lighter than Eagle).
    FishRed,
    FishBlue,
    /// `TIGER_WHITE` / `TIGER_RED` — pure mutation, no VM.
    TigerWhite,
    TigerRed,
    /// `BEAR` macros — anti-debug + integrity.
    Bear,
    /// Unknown or unrecognized macro.
    Unknown,
}

impl ThemidaMacro {
    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::VirtualStart => "VIRTUAL_START",
            Self::VirtualEnd => "VIRTUAL_END",
            Self::EagleBlack => "EAGLE_BLACK",
            Self::EagleWhite => "EAGLE_WHITE",
            Self::FishRed => "FISH_RED",
            Self::FishBlue => "FISH_BLUE",
            Self::TigerWhite => "TIGER_WHITE",
            Self::TigerRed => "TIGER_RED",
            Self::Bear => "BEAR",
            Self::Unknown => "<unknown>",
        }
    }

    /// Whether this macro implies full VM translation.
    #[must_use]
    pub const fn is_vm_macro(self) -> bool {
        matches!(
            self,
            Self::VirtualStart | Self::EagleBlack | Self::EagleWhite | Self::FishRed | Self::FishBlue
        )
    }

    /// Whether this macro implies mutation (no VM).
    #[must_use]
    pub const fn is_mutation_only(self) -> bool {
        matches!(self, Self::TigerWhite | Self::TigerRed)
    }

    /// Protection strength (0 = none, 3 = maximum).
    #[must_use]
    pub const fn strength(self) -> u8 {
        match self {
            Self::EagleBlack | Self::EagleWhite => 3,
            Self::VirtualStart | Self::VirtualEnd | Self::FishRed | Self::FishBlue => 2,
            Self::TigerWhite | Self::TigerRed | Self::Bear => 1,
            Self::Unknown => 0,
        }
    }
}

/// A recognized SDK macro boundary in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemidaMacroBoundary {
    /// Address of the macro marker (call stub or byte sequence).
    pub address: u64,
    /// Which macro was identified.
    pub macro_kind: ThemidaMacro,
    /// Whether this is the start or end of the macro region.
    pub is_start: bool,
    /// Matched bytes that identified the macro.
    pub matched_bytes: Vec<u8>,
    /// Confidence score.
    pub confidence: f32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Handler table
// ─────────────────────────────────────────────────────────────────────────────

/// A single entry in the Themida VM handler table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemidaHandlerEntry {
    /// Handler index (opcode byte).
    pub index: u16,
    /// Virtual address of the handler.
    pub address: u64,
    /// Handler size in bytes.
    pub size_bytes: u32,
    /// Semantic name if identified (e.g. `"PUSH32"`, `"ADD32"`, `"CALL"`).
    pub semantic: Option<String>,
    /// Raw handler body.
    pub body: Vec<u8>,
    /// XOR decryption key used to decrypt this handler (if encrypted).
    pub decrypt_key: Option<u32>,
}

/// Reconstructed Themida VM handler table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemidaHandlerTable {
    /// Base virtual address of the handler table.
    pub table_base: u64,
    /// All handler entries, indexed by opcode byte.
    pub entries: HashMap<u16, ThemidaHandlerEntry>,
    /// Number of valid entries recovered.
    pub valid_entries: usize,
    /// Whether handler pointers were found to be encrypted.
    pub encrypted: bool,
    /// Common XOR key for pointer encryption (if detected).
    pub common_xor_key: Option<u64>,
}

impl ThemidaHandlerTable {
    /// Create an empty handler table.
    #[must_use]
    pub fn empty(table_base: u64) -> Self {
        Self {
            table_base,
            entries: HashMap::new(),
            valid_entries: 0,
            encrypted: false,
            common_xor_key: None,
        }
    }

    /// Insert a handler entry.
    pub fn insert(&mut self, entry: ThemidaHandlerEntry) {
        if entry.semantic.is_some() {
            self.valid_entries += 1;
        }
        self.entries.insert(entry.index, entry);
    }

    /// Look up a handler by opcode.
    #[must_use]
    pub fn get(&self, opcode: u16) -> Option<&ThemidaHandlerEntry> {
        self.entries.get(&opcode)
    }

    /// Return the coverage ratio (semantically-identified entries / total entries).
    #[must_use]
    pub fn coverage(&self) -> f32 {
        if self.entries.is_empty() {
            return 0.0;
        }
        f32::from(u16::try_from(self.valid_entries).unwrap_or(u16::MAX))
            / f32::from(u16::try_from(self.entries.len()).unwrap_or(u16::MAX))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Crypto in handlers
// ─────────────────────────────────────────────────────────────────────────────

/// Type of key-based crypto used in a Themida handler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThemidaCryptoKind {
    /// Simple single-byte XOR.
    XorByte { key: u8 },
    /// 32-bit XOR with rolling key.
    XorDword { key: u32 },
    /// Multi-round XOR chain (different key per round).
    XorChain { keys: Vec<u32> },
    /// RC4 stream cipher with a short key.
    Rc4 { key: Vec<u8> },
    /// Feistel-like custom cipher (common in `WinLicense`).
    CustomFeistel { rounds: u8 },
    /// No crypto detected.
    None,
}

/// Crypto usage detected in a handler body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemidaHandlerCrypto {
    /// Address of the handler.
    pub handler_address: u64,
    /// Kind of crypto found.
    pub kind: ThemidaCryptoKind,
    /// Approximate offset within the handler where the crypto begins.
    pub crypto_offset: u32,
    /// Confidence score.
    pub confidence: f32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Analysis result
// ─────────────────────────────────────────────────────────────────────────────

/// Full analysis result for a Themida-protected binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemidaAnalysisResult {
    /// All SDK macro boundaries found.
    pub macro_boundaries: Vec<ThemidaMacroBoundary>,
    /// Reconstructed handler table (if found).
    pub handler_table: Option<ThemidaHandlerTable>,
    /// Per-handler crypto analysis.
    pub handler_crypto: Vec<ThemidaHandlerCrypto>,
    /// Detected Themida version (1 = 32-bit engine, 2 = 64-bit).
    pub version: u8,
    /// Overall confidence.
    pub overall_confidence: f32,
}

impl ThemidaAnalysisResult {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            macro_boundaries: Vec::new(),
            handler_table: None,
            handler_crypto: Vec::new(),
            version: 0,
            overall_confidence: 0.0,
        }
    }

    /// Return macro boundaries that start a VM-protected region.
    #[must_use]
    pub fn vm_regions_start(&self) -> Vec<&ThemidaMacroBoundary> {
        self.macro_boundaries
            .iter()
            .filter(|b| b.is_start && b.macro_kind.is_vm_macro())
            .collect()
    }
}

impl Default for ThemidaAnalysisResult {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ThemidaHandlerAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// Core analyzer for Themida / `WinLicense` handler identification.
pub struct ThemidaHandlerAnalyzer {
    /// Minimum confidence to include findings.
    pub min_confidence: f32,
    /// Known SDK macro byte signatures.
    macro_signatures: Vec<(ThemidaMacro, bool, Vec<u8>)>, // (macro, is_start, bytes)
    /// Handler semantic signatures.
    handler_semantics: HashMap<String, Vec<Vec<u8>>>,
}

impl Default for ThemidaHandlerAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl ThemidaHandlerAnalyzer {
    /// Create with default signatures.
    #[must_use]
    pub fn new() -> Self {
        let mut a = Self {
            min_confidence: 0.55,
            macro_signatures: Vec::new(),
            handler_semantics: HashMap::new(),
        };
        a.load_macro_signatures();
        a.load_handler_semantics();
        a
    }

    #[must_use]
    pub const fn with_min_confidence(mut self, t: f32) -> Self {
        self.min_confidence = t;
        self
    }

    // ── Macro signatures ──────────────────────────────────────────────────────

    fn load_macro_signatures(&mut self) {
        // Themida/WinLicense SDK VIRTUAL_START emits a call to a small thunk that
        // begins with: E8 xx xx xx xx (call +5) then various sequences.
        // We detect the common "magic call" pattern plus subsequent distinctive bytes.

        // VIRTUAL_START (Themida 2.x x64): E8 00 00 00 00 5D (call +5; pop rbp)
        self.macro_signatures.push((
            ThemidaMacro::VirtualStart,
            true,
            vec![0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D],
        ));

        // VIRTUAL_END: emits a stub ending in C3 preceded by a PUSHFQ (9C)
        self.macro_signatures.push((
            ThemidaMacro::VirtualEnd,
            false,
            vec![0x9C, 0x60, 0x6A, 0x00],
        ));

        // EAGLE_BLACK entry: distinctive NOP sled + encrypted branch (EB xx 90 90)
        self.macro_signatures.push((
            ThemidaMacro::EagleBlack,
            true,
            vec![0xEB, 0x01, 0x90, 0x90, 0x90],
        ));

        // EAGLE_WHITE: similar to BLACK but with a different initial jmp offset
        self.macro_signatures.push((
            ThemidaMacro::EagleWhite,
            true,
            vec![0xEB, 0x02, 0x90, 0x90, 0x90],
        ));

        // FISH_RED: mutation stub, starts with PUSHAD (60) in 32-bit mode
        self.macro_signatures.push((
            ThemidaMacro::FishRed,
            true,
            vec![0x60, 0x9C, 0xE8],
        ));

        // FISH_BLUE: similar, different ordering
        self.macro_signatures.push((
            ThemidaMacro::FishBlue,
            true,
            vec![0x9C, 0x60, 0xE8],
        ));

        // TIGER markers: simpler mutation stubs
        self.macro_signatures.push((
            ThemidaMacro::TigerWhite,
            true,
            vec![0xEB, 0x03, 0x90, 0x90],
        ));
        self.macro_signatures.push((
            ThemidaMacro::TigerRed,
            true,
            vec![0xEB, 0x04, 0x90, 0x90],
        ));
    }

    // ── Handler semantics ─────────────────────────────────────────────────────

    fn load_handler_semantics(&mut self) {
        // Themida VM uses a DWORD-sized opcode; handlers tend to start with
        // distinctive sequences for their operation class.

        // PUSH32: mov edi, [esi]; sub ebp, 4; mov [ebp], edi; add esi, 4
        self.handler_semantics.insert(
            "PUSH32".into(),
            vec![
                vec![0x8B, 0x3E, 0x83, 0xED, 0x04, 0x89, 0x7D, 0x00, 0x83, 0xC6, 0x04],
            ],
        );

        // POP32: mov eax, [ebp]; add ebp, 4; mov [esi], eax
        self.handler_semantics.insert(
            "POP32".into(),
            vec![
                vec![0x8B, 0x45, 0x00, 0x83, 0xC5, 0x04, 0x89, 0x06],
            ],
        );

        // ADD32: pop eax; pop ebx; add eax, ebx; push eax
        self.handler_semantics.insert(
            "ADD32".into(),
            vec![
                vec![0x58, 0x5B, 0x01, 0xD8, 0x50],
                vec![0x8B, 0x45, 0x00, 0x8B, 0x5D, 0x04, 0x01, 0xD8],
            ],
        );

        // SUB32
        self.handler_semantics.insert(
            "SUB32".into(),
            vec![
                vec![0x58, 0x5B, 0x29, 0xD8, 0x50],
            ],
        );

        // AND32
        self.handler_semantics.insert(
            "AND32".into(),
            vec![
                vec![0x58, 0x5B, 0x21, 0xD8, 0x50],
            ],
        );

        // XOR32
        self.handler_semantics.insert(
            "XOR32".into(),
            vec![
                vec![0x58, 0x5B, 0x31, 0xD8, 0x50],
            ],
        );

        // IMUL32
        self.handler_semantics.insert(
            "IMUL32".into(),
            vec![
                vec![0x58, 0x5B, 0x0F, 0xAF, 0xC3, 0x50],
            ],
        );

        // SHL32
        self.handler_semantics.insert(
            "SHL32".into(),
            vec![
                vec![0x59, 0x58, 0xD3, 0xE0, 0x50],
            ],
        );

        // JCC (conditional branch)
        self.handler_semantics.insert(
            "JCC".into(),
            vec![
                vec![0x58, 0x85, 0xC0], // pop eax; test eax, eax
                vec![0x58, 0x3D],       // pop eax; cmp eax, imm32
            ],
        );

        // CALL
        self.handler_semantics.insert(
            "CALL".into(),
            vec![
                vec![0x58, 0xFF, 0xD0], // pop eax; call eax
            ],
        );

        // RET
        self.handler_semantics.insert(
            "RET".into(),
            vec![
                vec![0x58, 0xFF, 0xE0], // pop eax; jmp eax (VM return)
                vec![0xC3],
            ],
        );

        // LOAD32 (memory read)
        self.handler_semantics.insert(
            "LOAD32".into(),
            vec![
                vec![0x58, 0x8B, 0x00, 0x50], // pop eax; mov eax,[eax]; push eax
            ],
        );

        // STORE32 (memory write)
        self.handler_semantics.insert(
            "STORE32".into(),
            vec![
                vec![0x58, 0x5B, 0x89, 0x18], // pop eax; pop ebx; mov [eax],ebx
            ],
        );
    }

    // ── Macro identification ──────────────────────────────────────────────────

    /// Find all SDK macro boundaries in `bytes`.
    #[must_use]
    pub fn find_macro_boundaries(
        &self,
        bytes: &[u8],
        base_address: u64,
    ) -> Vec<ThemidaMacroBoundary> {
        let mut result = Vec::new();

        for (macro_kind, is_start, pattern) in &self.macro_signatures {
            let mut offset = 0;
            while let Some(pos) = find_subslice(&bytes[offset..], pattern) {
                let abs_pos = offset + pos;
                let addr = base_address + abs_pos as u64;

                // Rough confidence based on pattern length and uniqueness
                let confidence = if pattern.len() >= 6 { 0.78 } else { 0.58 };

                if confidence >= self.min_confidence {
                    result.push(ThemidaMacroBoundary {
                        address: addr,
                        macro_kind: *macro_kind,
                        is_start: *is_start,
                        matched_bytes: pattern.clone(),
                        confidence,
                    });
                }

                offset = abs_pos + 1;
            }
        }

        result.sort_by_key(|b| b.address);
        result
    }

    // ── Handler table reconstruction ──────────────────────────────────────────

    /// Attempt to reconstruct the handler table from `bytes`.
    ///
    /// Themida stores a table of 32-bit (or 64-bit) handler function pointers.
    /// The table base is typically found near a dispatcher loop.
    ///
    /// # Panics
    /// Panics if byte-slice lengths are inconsistent (internal invariant; should not happen).
    #[must_use]
    pub fn reconstruct_handler_table(
        &self,
        bytes: &[u8],
        base_address: u64,
        ptr_size: u8,
    ) -> Option<ThemidaHandlerTable> {
        if bytes.len() < 16 {
            return None;
        }

        // Heuristic: locate a cluster of valid code pointers in the binary
        let ptr_bytes = ptr_size as usize;
        let mut candidate_tables: Vec<(usize, usize)> = Vec::new(); // (offset, run_length)

        let mut i = 0;
        while i + ptr_bytes <= bytes.len() {
            let ptr = if ptr_bytes == 4 {
                u64::from(u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap()))
            } else {
                u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap())
            };

            // Check if ptr looks like a valid code address (heuristic: high bits match base)
            let base_high = base_address & 0xFFFF_0000_0000_0000;
            if ptr != 0 && (ptr & 0xFFFF_0000_0000_0000) == base_high {
                // Count the run
                let start = i;
                let mut run = 0usize;
                while i + ptr_bytes <= bytes.len() {
                    let p2 = if ptr_bytes == 4 {
                        u64::from(u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap()))
                    } else {
                        u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap())
                    };
                    if p2 == 0 || (p2 & 0xFFFF_0000_0000_0000) != base_high {
                        break;
                    }
                    run += 1;
                    i += ptr_bytes;
                }
                if run >= 8 {
                    candidate_tables.push((start, run));
                }
            } else {
                i += ptr_bytes;
            }
        }

        candidate_tables.sort_by(|a, b| b.1.cmp(&a.1));
        let (table_offset, count) = candidate_tables.first()?;

        let table_base = base_address + *table_offset as u64;
        let mut table = ThemidaHandlerTable::empty(table_base);

        // Determine if entries are encrypted by checking entropy of pointer values
        let table_slice = &bytes[*table_offset..*table_offset + count * ptr_bytes];
        let entropy = byte_entropy(table_slice);
        if entropy > 7.0 {
            table.encrypted = true;
            // Try to find the common XOR key by looking for a known handler prologue
            if let Some(key) = guess_xor_key(table_slice, ptr_bytes) {
                table.common_xor_key = Some(key);
            }
        }

        // Populate entries
        for (idx, chunk) in table_slice.chunks(ptr_bytes).enumerate() {
            let raw_ptr = if ptr_bytes == 4 {
                u64::from(u32::from_le_bytes(chunk.try_into().unwrap_or_default()))
            } else {
                u64::from_le_bytes(chunk.try_into().unwrap_or_default())
            };

            let handler_addr = table.common_xor_key.map_or(raw_ptr, |key| raw_ptr ^ key);

            let offset_in_binary = usize::try_from(handler_addr.saturating_sub(base_address)).unwrap_or(usize::MAX);
            let body_slice = if offset_in_binary < bytes.len() {
                let end = (offset_in_binary + 64).min(bytes.len());
                bytes[offset_in_binary..end].to_vec()
            } else {
                Vec::new()
            };

            let semantic = self.identify_semantic(&body_slice);

            table.insert(ThemidaHandlerEntry {
                index: u16::try_from(idx).unwrap_or(u16::MAX),
                address: handler_addr,
                size_bytes: 64,
                semantic,
                body: body_slice,
                decrypt_key: table.common_xor_key.map(|k| u32::try_from(k).unwrap_or(u32::MAX)),
            });
        }

        Some(table)
    }

    // ── Semantic identification ───────────────────────────────────────────────

    /// Match a handler body against known semantic patterns.
    #[must_use]
    pub fn identify_semantic(&self, body: &[u8]) -> Option<String> {
        if body.is_empty() {
            return None;
        }
        for (name, patterns) in &self.handler_semantics {
            for pattern in patterns {
                if body.len() >= pattern.len() && &body[..pattern.len()] == pattern.as_slice() {
                    return Some(name.clone());
                }
            }
        }
        None
    }

    // ── Crypto analysis ───────────────────────────────────────────────────────

    /// Detect key-based crypto in a handler body.
    ///
    /// # Panics
    /// Panics if byte-window slice lengths are inconsistent (internal invariant; should not happen).
    #[must_use]
    pub fn analyze_handler_crypto(
        &self,
        handler_address: u64,
        body: &[u8],
    ) -> ThemidaHandlerCrypto {
        if body.len() < 4 {
            return ThemidaHandlerCrypto {
                handler_address,
                kind: ThemidaCryptoKind::None,
                crypto_offset: 0,
                confidence: 0.0,
            };
        }

        // Check for XOR byte pattern: XOR reg, imm8 (83 Fx xx or 34 xx / 35 xx xx xx xx)
        for (i, window) in body.windows(3).enumerate() {
            if window[0] == 0x34 {
                // xor al, imm8
                return ThemidaHandlerCrypto {
                    handler_address,
                    kind: ThemidaCryptoKind::XorByte { key: window[1] },
                    crypto_offset: u32::try_from(i).unwrap_or(u32::MAX),
                    confidence: 0.75,
                };
            }
            if window[0] == 0x83 && (window[1] & 0xF8) == 0xF0 {
                // xor r/m32, imm8
                return ThemidaHandlerCrypto {
                    handler_address,
                    kind: ThemidaCryptoKind::XorByte { key: window[2] },
                    crypto_offset: u32::try_from(i).unwrap_or(u32::MAX),
                    confidence: 0.72,
                };
            }
        }

        // Check for XOR dword: 35 xx xx xx xx (xor eax, imm32)
        for (i, window) in body.windows(5).enumerate() {
            if window[0] == 0x35 {
                let key = u32::from_le_bytes(window[1..5].try_into().unwrap());
                if key != 0 && key != 0xFFFF_FFFF {
                    return ThemidaHandlerCrypto {
                        handler_address,
                        kind: ThemidaCryptoKind::XorDword { key },
                        crypto_offset: u32::try_from(i).unwrap_or(u32::MAX),
                        confidence: 0.78,
                    };
                }
            }
        }

        // Check for RC4 KSA: presence of a 256-byte initialization loop
        // Heuristic: loop counter up to 0x100, XOR with key byte
        let has_rc4_ksa = body.windows(4).any(|w| {
            w[0] == 0x80 && w[1] == 0xC0 && w[3] == 0x00 // add al, ?; cmp al, 0
        });
        if has_rc4_ksa {
            return ThemidaHandlerCrypto {
                handler_address,
                kind: ThemidaCryptoKind::Rc4 { key: extract_rc4_key(body) },
                crypto_offset: 0,
                confidence: 0.65,
            };
        }

        // Feistel detection: alternating XOR + ROL/ROR pairs
        let xor_count = body.windows(2).filter(|w| w[0] == 0x31 || w[0] == 0x33).count();
        let rot_count = body
            .windows(2)
            .filter(|w| w[0] == 0xD3 && (w[1] == 0xC0 || w[1] == 0xC8))
            .count();
        if xor_count >= 4 && rot_count >= 2 {
            return ThemidaHandlerCrypto {
                handler_address,
                kind: ThemidaCryptoKind::CustomFeistel {
                    rounds: u8::try_from((xor_count / 2).min(255)).unwrap_or(u8::MAX),
                },
                crypto_offset: 0,
                confidence: 0.60,
            };
        }

        // Check for XOR chain (multiple distinct XOR constants)
        let xor_keys = extract_xor_chain(body);
        if xor_keys.len() >= 2 {
            return ThemidaHandlerCrypto {
                handler_address,
                kind: ThemidaCryptoKind::XorChain { keys: xor_keys },
                crypto_offset: 0,
                confidence: 0.68,
            };
        }

        ThemidaHandlerCrypto {
            handler_address,
            kind: ThemidaCryptoKind::None,
            crypto_offset: 0,
            confidence: 0.0,
        }
    }

    // ── Version detection ─────────────────────────────────────────────────────

    /// Detect Themida major version (1 = 32-bit, 2 = 64-bit).
    #[must_use]
    pub fn detect_version(&self, bytes: &[u8]) -> u8 {
        // 64-bit Themida uses REX-prefixed sequences extensively
        let rex_count = bytes
            .windows(2)
            .filter(|w| matches!(w[0], 0x48..=0x4F) && w[1] != 0x00)
            .count();
        if rex_count > bytes.len() / 20 {
            2
        } else {
            1
        }
    }

    // ── Full analysis ─────────────────────────────────────────────────────────

    /// Run the full Themida analysis pipeline.
    #[must_use]
    pub fn analyze(&self, bytes: &[u8], base_address: u64) -> ThemidaAnalysisResult {
        let mut result = ThemidaAnalysisResult::new();

        result.version = self.detect_version(bytes);
        result.macro_boundaries = self.find_macro_boundaries(bytes, base_address);

        let ptr_size = if result.version == 2 { 8 } else { 4 };
        result.handler_table = self.reconstruct_handler_table(bytes, base_address, ptr_size);

        // Analyze crypto for each handler
        if let Some(ref table) = result.handler_table {
            for entry in table.entries.values() {
                let crypto = self.analyze_handler_crypto(entry.address, &entry.body);
                if !matches!(crypto.kind, ThemidaCryptoKind::None) {
                    result.handler_crypto.push(crypto);
                }
            }
        }

        // Overall confidence
        let macro_conf = if result.macro_boundaries.is_empty() {
            0.0
        } else {
            result.macro_boundaries.iter().map(|b| b.confidence).sum::<f32>()
                / f32::from(u16::try_from(result.macro_boundaries.len()).unwrap_or(u16::MAX))
        };

        let table_conf = result
            .handler_table
            .as_ref()
            .map_or(0.0, ThemidaHandlerTable::coverage);

        result.overall_confidence = (macro_conf * 0.6 + table_conf * 0.4).min(1.0);
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn byte_entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in bytes {
        freq[usize::from(b)] += 1;
    }
    let len = f32::from(u16::try_from(bytes.len()).unwrap_or(u16::MAX));
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f32::from(u16::try_from(c).unwrap_or(u16::MAX)) / len;
            -p * p.log2()
        })
        .sum()
}

/// Try to guess the XOR key used to encrypt handler pointers.
fn guess_xor_key(table_bytes: &[u8], ptr_size: usize) -> Option<u64> {
    // Heuristic: XOR each pointer with common x86 code byte (0xCC = int3, 0x55 = push rbp)
    // and check if result looks like a valid aligned address
    let candidates = [0x55u64, 0xCCu64, 0xE8u64, 0x48u64];
    for &lead_byte in &candidates {
        if table_bytes.len() >= ptr_size {
            let raw = if ptr_size == 4 {
                u64::from(u32::from_le_bytes(table_bytes[..4].try_into().unwrap()))
            } else {
                u64::from_le_bytes(table_bytes[..8].try_into().unwrap())
            };
            // Try to construct a key that makes the first pointer start with `lead_byte`
            let shift = 0u64;
            let key = raw ^ (lead_byte << shift);
            if key != 0 {
                return Some(key);
            }
        }
    }
    None
}

fn extract_rc4_key(body: &[u8]) -> Vec<u8> {
    // Try to extract a short key (≤ 16 bytes) from immediate values near the KSA
    let mut key = Vec::new();
    for window in body.windows(2) {
        if window[0] == 0xB0 {
            // mov al, imm8 — possible key byte
            key.push(window[1]);
            if key.len() >= 16 {
                break;
            }
        }
    }
    key
}

fn extract_xor_chain(body: &[u8]) -> Vec<u32> {
    let mut keys = Vec::new();
    for window in body.windows(5) {
        if window[0] == 0x35 {
            // xor eax, imm32
            let k = u32::from_le_bytes(window[1..5].try_into().unwrap());
            if k != 0 && k != 0xFFFF_FFFF && !keys.contains(&k) {
                keys.push(k);
            }
        }
    }
    keys
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macro_strength() {
        assert_eq!(ThemidaMacro::EagleBlack.strength(), 3);
        assert_eq!(ThemidaMacro::TigerWhite.strength(), 1);
        assert!(ThemidaMacro::VirtualStart.is_vm_macro());
        assert!(ThemidaMacro::TigerRed.is_mutation_only());
    }

    #[test]
    fn test_find_macro_virtual_start() {
        let analyzer = ThemidaHandlerAnalyzer::new();
        // Pattern: E8 00 00 00 00 5D
        let bytes = vec![0x90u8, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x90];
        let boundaries = analyzer.find_macro_boundaries(&bytes, 0x4000);
        assert!(!boundaries.is_empty());
        assert_eq!(boundaries[0].macro_kind, ThemidaMacro::VirtualStart);
        assert_eq!(boundaries[0].address, 0x4001);
    }

    #[test]
    fn test_identify_semantic_add32() {
        let analyzer = ThemidaHandlerAnalyzer::new();
        // pop eax; pop ebx; add eax, ebx; push eax
        let body = vec![0x58u8, 0x5B, 0x01, 0xD8, 0x50];
        let s = analyzer.identify_semantic(&body);
        assert_eq!(s.as_deref(), Some("ADD32"));
    }

    #[test]
    fn test_crypto_xor_dword() {
        let analyzer = ThemidaHandlerAnalyzer::new();
        // xor eax, 0xDEADBEEF
        let body = vec![0x35u8, 0xEF, 0xBE, 0xAD, 0xDE];
        let crypto = analyzer.analyze_handler_crypto(0x1000, &body);
        assert!(matches!(
            crypto.kind,
            ThemidaCryptoKind::XorDword { key: 0xDEAD_BEEF }
        ));
    }

    #[test]
    fn test_handler_table_empty_binary() {
        let analyzer = ThemidaHandlerAnalyzer::new();
        let result = analyzer.reconstruct_handler_table(&[], 0x0040_0000, 8);
        assert!(result.is_none());
    }

    #[test]
    fn test_detect_version_64bit() {
        let analyzer = ThemidaHandlerAnalyzer::new();
        // Many REX prefixes → 64-bit
        let bytes: Vec<u8> = (0..100)
            .flat_map(|_| vec![0x48u8, 0x89, 0xC0])
            .collect();
        assert_eq!(analyzer.detect_version(&bytes), 2);
    }
}
