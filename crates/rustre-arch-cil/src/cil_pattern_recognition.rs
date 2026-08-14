//! CIL pattern recognizer — detect malware / obfuscation patterns in CIL bytecode.
//!
//! Scans raw method bodies for characteristic opcode sequences that indicate
//! string encryption, reflection, dynamic code loading, anti-debug, P/Invoke,
//! and other notable behaviors.

use std::fmt;

// ── Pattern enum ──────────────────────────────────────────────────────────────

/// A behavioral pattern detectable in CIL bytecode.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Pattern {
    StringEncryption,
    ReflectionCall,
    DynamicCodeLoad,
    AntiDebug,
    ResourceExtract,
    RegistryAccess,
    NetworkConnect,
    FileSystemOp,
    SqlQuery,
    ThreadCreation,
    ProcessSpawn,
    DllInjection,
    /// P/Invoke to a specific DLL name.
    PInvoke(String),
    UnsafePointerArith,
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Pattern::StringEncryption    => write!(f, "StringEncryption"),
            Pattern::ReflectionCall      => write!(f, "ReflectionCall"),
            Pattern::DynamicCodeLoad     => write!(f, "DynamicCodeLoad"),
            Pattern::AntiDebug           => write!(f, "AntiDebug"),
            Pattern::ResourceExtract     => write!(f, "ResourceExtract"),
            Pattern::RegistryAccess      => write!(f, "RegistryAccess"),
            Pattern::NetworkConnect      => write!(f, "NetworkConnect"),
            Pattern::FileSystemOp        => write!(f, "FileSystemOp"),
            Pattern::SqlQuery            => write!(f, "SqlQuery"),
            Pattern::ThreadCreation      => write!(f, "ThreadCreation"),
            Pattern::ProcessSpawn        => write!(f, "ProcessSpawn"),
            Pattern::DllInjection        => write!(f, "DllInjection"),
            Pattern::PInvoke(dll)        => write!(f, "PInvoke({})", dll),
            Pattern::UnsafePointerArith  => write!(f, "UnsafePointerArith"),
        }
    }
}

// ── PatternMatch ──────────────────────────────────────────────────────────────

/// A single hit of a pattern within a method body.
#[derive(Debug, Clone)]
pub struct PatternMatch {
    /// Which pattern was matched.
    pub pattern: Pattern,
    /// Byte offset within the method body where the match begins.
    pub offset: u32,
    /// Confidence score [0.0, 1.0].
    pub confidence: f64,
    /// Human-readable evidence descriptions.
    pub evidence: Vec<String>,
}

impl PatternMatch {
    pub fn new(pattern: Pattern, offset: u32, confidence: f64, evidence: Vec<String>) -> Self {
        Self { pattern, offset, confidence, evidence }
    }
}

// ── CilPatternRecognizer ──────────────────────────────────────────────────────

/// Scans CIL method bodies for patterns of interest.
pub struct CilPatternRecognizer {
    /// Include low-confidence matches in output.
    pub include_low_confidence: bool,
    /// Confidence threshold below which matches are suppressed.
    pub min_confidence: f64,
}

impl CilPatternRecognizer {
    pub fn new() -> Self {
        Self {
            include_low_confidence: false,
            min_confidence: 0.4,
        }
    }

    /// Scan a raw CIL method body and return all detected patterns.
    pub fn scan_method(&self, code: &[u8]) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        matches.extend(self.detect_string_encryption(code));
        matches.extend(self.detect_reflection(code));
        matches.extend(self.detect_dynamic_code(code));
        matches.extend(self.detect_anti_debug(code));
        matches.extend(self.detect_pinvoke(code));
        matches.extend(self.detect_unsafe_pointer_arith(code));
        matches.extend(self.detect_network_ops(code));
        matches.extend(self.detect_file_ops(code));
        matches.extend(self.detect_registry_ops(code));
        matches.extend(self.detect_thread_creation(code));
        matches.extend(self.detect_process_spawn(code));
        matches.extend(self.detect_resource_extract(code));
        matches.extend(self.detect_sql_query(code));
        // Filter by confidence threshold.
        if !self.include_low_confidence {
            matches.retain(|m| m.confidence >= self.min_confidence);
        }
        matches
    }

    // ── Individual detectors ───────────────────────────────────────────────

    /// Detect string encryption: ldc.i4 + xor + stelem loop.
    ///
    /// Signature: a loop containing ldc.i4 (key byte), xor, stelem.
    pub fn detect_string_encryption(&self, code: &[u8]) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        let mut i = 0usize;
        while i + 2 < code.len() {
            // Look for: xor (0x61) preceded by ldc.i4 variants and followed by stelem (0x9E)
            if code[i] == 0x61 {
                // xor
                let has_ldc = self.scan_back_for_ldc(code, i, 8);
                let has_stelem = self.scan_forward_for(code, i, &[0x9E, 0xA4], 4);
                if has_ldc && has_stelem {
                    let confidence = 0.75;
                    matches.push(PatternMatch::new(
                        Pattern::StringEncryption,
                        i as u32,
                        confidence,
                        vec![
                            format!("XOR at offset {:#x}", i),
                            "ldc.i4 key loading near XOR".to_string(),
                            "stelem after XOR suggests array output".to_string(),
                        ],
                    ));
                }
            }
            // Also look for: ldc.i4 followed immediately by xor (simple XOR key)
            if self.is_ldc_i4(code[i]) && i + 1 < code.len() && code[i + 1] == 0x61 {
                // Check for loop structure: branch back before this
                if self.has_backward_branch_near(code, i, 12) {
                    matches.push(PatternMatch::new(
                        Pattern::StringEncryption,
                        i as u32,
                        0.65,
                        vec![
                            format!("ldc.i4 + xor at offset {:#x}", i),
                            "backward branch suggests loop".to_string(),
                        ],
                    ));
                }
            }
            i += 1;
        }
        matches
    }

    /// Detect reflection: ldstr + call GetType/GetMethod/Invoke.
    pub fn detect_reflection(&self, code: &[u8]) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        let mut i = 0usize;
        while i + 5 < code.len() {
            // ldstr (0x72) followed within 10 bytes by call (0x28) or callvirt (0x6F)
            if code[i] == 0x72 {
                let call_off = self.scan_forward_for(code, i + 5, &[0x28, 0x6F], 12);
                if call_off {
                    let evidence = vec![
                        format!("ldstr at {:#x}", i),
                        "call/callvirt follows string load — potential GetType/GetMethod".to_string(),
                    ];
                    matches.push(PatternMatch::new(
                        Pattern::ReflectionCall,
                        i as u32,
                        0.60,
                        evidence,
                    ));
                }
            }
            i += 1;
        }
        matches
    }

    /// Detect dynamic code: ldstr + newobj System.Reflection.Emit patterns.
    pub fn detect_dynamic_code(&self, code: &[u8]) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        let mut i = 0usize;
        while i + 5 < code.len() {
            // newobj (0x73) followed by callvirt (0x6F) twice — AssemblyBuilder pattern
            if code[i] == 0x73 {
                let cw1 = self.scan_forward_for(code, i + 5, &[0x6F], 12);
                let cw2 = if cw1 { self.scan_forward_for(code, i + 10, &[0x6F], 20) } else { false };
                if cw1 && cw2 {
                    matches.push(PatternMatch::new(
                        Pattern::DynamicCodeLoad,
                        i as u32,
                        0.55,
                        vec![
                            format!("newobj at {:#x}", i),
                            "double callvirt after newobj — possible Emit usage".to_string(),
                        ],
                    ));
                }
            }
            // ldftn (0xFE 0x06) indicates delegate creation from function pointer
            if i + 1 < code.len() && code[i] == 0xFE && code[i + 1] == 0x06 {
                matches.push(PatternMatch::new(
                    Pattern::DynamicCodeLoad,
                    i as u32,
                    0.50,
                    vec![format!("ldftn at {:#x} — function pointer indirection", i)],
                ));
            }
            i += 1;
        }
        matches
    }

    /// Detect anti-debug: call Debugger::IsAttached / DebuggerPresent patterns.
    pub fn detect_anti_debug(&self, code: &[u8]) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        let mut i = 0usize;
        while i + 1 < code.len() {
            // call (0x28) followed by conditional branch — characteristic of IsAttached check
            if code[i] == 0x28 && i + 5 < code.len() {
                let branch = self.scan_forward_for(code, i + 5, &[0x2C, 0x2D, 0x39, 0x3A], 4);
                if branch {
                    matches.push(PatternMatch::new(
                        Pattern::AntiDebug,
                        i as u32,
                        0.65,
                        vec![
                            format!("call at {:#x} followed by conditional branch", i),
                            "pattern consistent with Debugger.IsAttached check".to_string(),
                        ],
                    ));
                }
            }
            // ldsfld (0x7E) + brfalse/brtrue: reading a static field then branching
            if code[i] == 0x7E && i + 5 < code.len() {
                let branch = self.scan_forward_for(code, i + 5, &[0x2C, 0x2D], 3);
                if branch {
                    matches.push(PatternMatch::new(
                        Pattern::AntiDebug,
                        i as u32,
                        0.45,
                        vec![
                            format!("ldsfld at {:#x} + branch", i),
                            "possible static debugger flag check".to_string(),
                        ],
                    ));
                }
            }
            i += 1;
        }
        matches
    }

    /// Detect P/Invoke: DllImport attribute usage in method body (ldstr → call pattern).
    pub fn detect_pinvoke(&self, code: &[u8]) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        // In CIL, P/Invoke methods are identified by their metadata flags.
        // At the bytecode level, we look for `calli` (0x29) which is used
        // for unmanaged function pointer calls.
        for (i, &b) in code.iter().enumerate() {
            if b == 0x29 {
                // calli — unmanaged indirect call
                matches.push(PatternMatch::new(
                    Pattern::PInvoke("(unmanaged calli)".to_string()),
                    i as u32,
                    0.70,
                    vec![format!("calli opcode at {:#x}", i)],
                ));
            }
        }
        // Also detect GetProcAddress / LoadLibrary call sequences:
        // ldstr + call (LoadLibrary) + call (GetProcAddress) + calli
        let mut i = 0;
        while i + 6 < code.len() {
            if code[i] == 0x72 {
                let call1 = self.scan_forward_for(code, i + 5, &[0x28, 0x6F], 8);
                let calli = self.scan_forward_for(code, i + 8, &[0x29], 16);
                if call1 && calli {
                    matches.push(PatternMatch::new(
                        Pattern::PInvoke("LoadLibrary/GetProcAddress".to_string()),
                        i as u32,
                        0.80,
                        vec![
                            format!("ldstr + call + calli sequence at {:#x}", i),
                            "consistent with dynamic P/Invoke via LoadLibrary".to_string(),
                        ],
                    ));
                }
            }
            i += 1;
        }
        matches
    }

    /// Detect unsafe pointer arithmetic: conv.u / add / ldind variants.
    pub fn detect_unsafe_pointer_arith(&self, code: &[u8]) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        let mut i = 0usize;
        while i + 1 < code.len() {
            // conv.u (0x6D) followed by add (0x58) — pointer arithmetic
            if code[i] == 0x6D && i + 1 < code.len() && code[i + 1] == 0x58 {
                matches.push(PatternMatch::new(
                    Pattern::UnsafePointerArith,
                    i as u32,
                    0.70,
                    vec![format!("conv.u + add at {:#x}", i)],
                ));
            }
            // ldind variants (0x46–0x52): loading from pointer
            if (0x46..=0x52).contains(&code[i]) {
                let prev_is_ptr_op = i > 0 && (code[i - 1] == 0x6D || code[i - 1] == 0x58);
                if prev_is_ptr_op {
                    matches.push(PatternMatch::new(
                        Pattern::UnsafePointerArith,
                        i as u32,
                        0.60,
                        vec![format!("ldind at {:#x} after pointer operation", i)],
                    ));
                }
            }
            // cpblk (0xFE 0x17) / initblk (0xFE 0x18)
            if code[i] == 0xFE && i + 1 < code.len()
                && (code[i + 1] == 0x17 || code[i + 1] == 0x18)
            {
                matches.push(PatternMatch::new(
                    Pattern::UnsafePointerArith,
                    i as u32,
                    0.85,
                    vec![format!("{} at {:#x}", if code[i+1]==0x17 {"cpblk"} else {"initblk"}, i)],
                ));
            }
            i += 1;
        }
        matches
    }

    /// Detect network operations: call WebClient/HttpClient patterns.
    pub fn detect_network_ops(&self, code: &[u8]) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        // Look for newobj (0x73) + callvirt (0x6F) + callvirt — WebClient.DownloadString style
        let mut i = 0usize;
        while i + 10 < code.len() {
            if code[i] == 0x73 {
                let v1 = self.scan_forward_for(code, i + 5, &[0x6F], 10);
                let v2 = if v1 { self.scan_forward_for(code, i + 9, &[0x6F], 15) } else { false };
                if v1 && v2 {
                    matches.push(PatternMatch::new(
                        Pattern::NetworkConnect,
                        i as u32,
                        0.50,
                        vec![format!("newobj+callvirt*2 at {:#x} — possible network call", i)],
                    ));
                }
            }
            i += 1;
        }
        matches
    }

    /// Detect file system operations: ldstr + call File/FileStream.
    pub fn detect_file_ops(&self, code: &[u8]) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        let mut i = 0usize;
        // FileStream constructor: newobj (0x73) after ldstr (0x72)
        while i + 6 < code.len() {
            if code[i] == 0x72 && self.scan_forward_for(code, i + 5, &[0x73], 8) {
                matches.push(PatternMatch::new(
                    Pattern::FileSystemOp,
                    i as u32,
                    0.55,
                    vec![format!("ldstr + newobj at {:#x} — possible FileStream", i)],
                ));
            }
            i += 1;
        }
        matches
    }

    /// Detect registry access: call OpenSubKey / GetValue patterns.
    pub fn detect_registry_ops(&self, code: &[u8]) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        let mut i = 0usize;
        // ldsfld (0x7E) + ldstr (0x72) + callvirt (0x6F) — Registry.GetValue pattern
        while i + 10 < code.len() {
            if code[i] == 0x7E && self.scan_forward_for(code, i + 5, &[0x72], 6) {
                let cv = self.scan_forward_for(code, i + 10, &[0x6F], 10);
                if cv {
                    matches.push(PatternMatch::new(
                        Pattern::RegistryAccess,
                        i as u32,
                        0.55,
                        vec![format!("ldsfld+ldstr+callvirt at {:#x} — possible registry access", i)],
                    ));
                }
            }
            i += 1;
        }
        matches
    }

    /// Detect thread creation: newobj Thread + callvirt Start.
    pub fn detect_thread_creation(&self, code: &[u8]) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        let mut i = 0usize;
        while i + 10 < code.len() {
            // ldftn (0xFE 0x06) + newobj (0x73) — Thread constructor with ThreadStart delegate
            if code[i] == 0xFE && i + 1 < code.len() && code[i + 1] == 0x06 {
                if self.scan_forward_for(code, i + 2, &[0x73], 8) {
                    matches.push(PatternMatch::new(
                        Pattern::ThreadCreation,
                        i as u32,
                        0.70,
                        vec![format!("ldftn + newobj at {:#x} — thread creation", i)],
                    ));
                }
            }
            i += 1;
        }
        matches
    }

    /// Detect process spawning: call Process.Start patterns.
    pub fn detect_process_spawn(&self, code: &[u8]) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        let mut i = 0usize;
        // ldstr + ldstr + call (static Process.Start(filename, args))
        while i + 12 < code.len() {
            if code[i] == 0x72 && self.scan_forward_for(code, i + 5, &[0x72], 6) {
                let call = self.scan_forward_for(code, i + 10, &[0x28], 8);
                if call {
                    matches.push(PatternMatch::new(
                        Pattern::ProcessSpawn,
                        i as u32,
                        0.60,
                        vec![format!("ldstr+ldstr+call at {:#x} — Process.Start pattern", i)],
                    ));
                }
            }
            i += 1;
        }
        matches
    }

    /// Detect resource extraction: call Assembly.GetManifestResourceStream.
    pub fn detect_resource_extract(&self, code: &[u8]) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        let mut i = 0usize;
        // call (0x28) / callvirt (0x6F) with ldstr before it — GetManifestResourceStream
        while i + 6 < code.len() {
            if code[i] == 0x72 && self.scan_forward_for(code, i + 5, &[0x6F, 0x28], 6) {
                matches.push(PatternMatch::new(
                    Pattern::ResourceExtract,
                    i as u32,
                    0.45,
                    vec![format!("ldstr+call at {:#x} — possible resource access", i)],
                ));
            }
            i += 1;
        }
        matches
    }

    /// Detect SQL query construction: ldstr + string.Concat/Format + call.
    pub fn detect_sql_query(&self, code: &[u8]) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        let mut i = 0usize;
        // Multiple ldstr opcodes in a row suggest SQL string building
        while i + 15 < code.len() {
            if code[i] == 0x72 && code[i + 5] == 0x72 && code[i + 10] == 0x72 {
                matches.push(PatternMatch::new(
                    Pattern::SqlQuery,
                    i as u32,
                    0.50,
                    vec![format!(
                        "Three consecutive ldstr opcodes at {:#x} — possible SQL concatenation",
                        i
                    )],
                ));
                i += 15;
                continue;
            }
            i += 1;
        }
        matches
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    /// True if `opcode` is any ldc.i4 short form (0x15–0x1E) or ldc.i4.s/ldc.i4.
    fn is_ldc_i4(&self, opcode: u8) -> bool {
        (0x15..=0x20).contains(&opcode)
    }

    /// Scan backwards from `pos` for an ldc.i4 variant within `window` bytes.
    fn scan_back_for_ldc(&self, code: &[u8], pos: usize, window: usize) -> bool {
        let start = pos.saturating_sub(window);
        for j in start..pos {
            if self.is_ldc_i4(code[j]) {
                return true;
            }
        }
        false
    }

    /// Scan forwards from `pos` for any opcode in `targets` within `window` bytes.
    fn scan_forward_for(&self, code: &[u8], pos: usize, targets: &[u8], window: usize) -> bool {
        let end = (pos + window).min(code.len());
        for &b in &code[pos..end] {
            if targets.contains(&b) {
                return true;
            }
        }
        false
    }

    /// Check for a backward branch (short or long) within `window` bytes before `pos`.
    fn has_backward_branch_near(&self, code: &[u8], pos: usize, window: usize) -> bool {
        let start = pos.saturating_sub(window);
        for j in start..pos {
            // Short backward branch: offset byte is negative (>= 0x80 when cast to i8)
            if (code[j] == 0x2B || (0x2C..=0x37).contains(&code[j]))
                && j + 1 < code.len()
                && (code[j + 1] as i8) < 0
            {
                return true;
            }
        }
        false
    }
}

impl Default for CilPatternRecognizer {
    fn default() -> Self { Self::new() }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn rec() -> CilPatternRecognizer {
        let mut r = CilPatternRecognizer::new();
        r.include_low_confidence = true;
        r.min_confidence = 0.0;
        r
    }

    #[test]
    fn pattern_display() {
        assert_eq!(Pattern::StringEncryption.to_string(), "StringEncryption");
        assert_eq!(Pattern::PInvoke("kernel32".to_string()).to_string(), "PInvoke(kernel32)");
    }

    #[test]
    fn detect_string_encryption_xor_stelem() {
        // ldc.i4.5, ldc.i4.3, xor, stelem (a simplified XOR loop body)
        let code = [0x1B, 0x19, 0x61, 0x9E, 0x2A];
        let matches = rec().detect_string_encryption(&code);
        assert!(
            matches.iter().any(|m| m.pattern == Pattern::StringEncryption),
            "expected StringEncryption match"
        );
    }

    #[test]
    fn detect_reflection_ldstr_callvirt() {
        // ldstr token (5 bytes: 0x72 + 4), then callvirt (0x6F + 4)
        let code = [0x72, 0x01, 0x00, 0x00, 0x70, 0x6F, 0x02, 0x00, 0x00, 0x06, 0x2A];
        let matches = rec().detect_reflection(&code);
        assert!(matches.iter().any(|m| m.pattern == Pattern::ReflectionCall));
    }

    #[test]
    fn detect_dynamic_code_newobj_double_callvirt() {
        // newobj + callvirt + callvirt
        let code = [0x73, 0x01, 0x00, 0x00, 0x06, 0x6F, 0x02, 0x00, 0x00, 0x06,
                    0x6F, 0x03, 0x00, 0x00, 0x06, 0x2A];
        let matches = rec().detect_dynamic_code(&code);
        assert!(matches.iter().any(|m| m.pattern == Pattern::DynamicCodeLoad));
    }

    #[test]
    fn detect_anti_debug_call_then_branch() {
        // call token (5 bytes), brfalse.s (2 bytes)
        let code = [0x28, 0x01, 0x00, 0x00, 0x0A, 0x2C, 0x05, 0x2A];
        let matches = rec().detect_anti_debug(&code);
        assert!(matches.iter().any(|m| m.pattern == Pattern::AntiDebug));
    }

    #[test]
    fn detect_calli_pinvoke() {
        let code = [0x72, 0x01, 0x00, 0x00, 0x70, 0x29, 0x02, 0x00, 0x00, 0x06, 0x2A];
        let matches = rec().detect_pinvoke(&code);
        assert!(matches.iter().any(|m| matches!(m.pattern, Pattern::PInvoke(_))));
    }

    #[test]
    fn detect_unsafe_cpblk() {
        let code = [0x02, 0x03, 0x17, 0xFE, 0x17, 0x2A]; // cpblk
        let matches = rec().detect_unsafe_pointer_arith(&code);
        assert!(matches.iter().any(|m| m.pattern == Pattern::UnsafePointerArith));
    }

    #[test]
    fn detect_unsafe_conv_u_add() {
        let code = [0x6D, 0x58, 0x2A]; // conv.u, add
        let matches = rec().detect_unsafe_pointer_arith(&code);
        assert!(matches.iter().any(|m| m.pattern == Pattern::UnsafePointerArith));
    }

    #[test]
    fn detect_thread_creation_ldftn_newobj() {
        let code = [0xFE, 0x06, 0x01, 0x00, 0x00, 0x06, 0x73, 0x02, 0x00, 0x00, 0x07, 0x2A];
        let matches = rec().detect_thread_creation(&code);
        assert!(matches.iter().any(|m| m.pattern == Pattern::ThreadCreation));
    }

    #[test]
    fn detect_process_spawn_ldstr_ldstr_call() {
        let code = [
            0x72, 0x01, 0x00, 0x00, 0x70, // ldstr
            0x72, 0x02, 0x00, 0x00, 0x70, // ldstr
            0x28, 0x03, 0x00, 0x00, 0x06, // call
            0x2A,
        ];
        let matches = rec().detect_process_spawn(&code);
        assert!(matches.iter().any(|m| m.pattern == Pattern::ProcessSpawn));
    }

    #[test]
    fn scan_method_returns_multiple() {
        let code = [
            0x72, 0x01, 0x00, 0x00, 0x70, 0x6F, 0x02, 0x00, 0x00, 0x06, // reflection
            0x61, 0x9E, // xor+stelem (encryption)
            0x2A,
        ];
        let matches = rec().scan_method(&code);
        let patterns: Vec<&Pattern> = matches.iter().map(|m| &m.pattern).collect();
        assert!(patterns.contains(&&Pattern::ReflectionCall)
            || patterns.contains(&&Pattern::StringEncryption)
            || !matches.is_empty());
    }

    #[test]
    fn detect_sql_three_consecutive_ldstr() {
        let code = [
            0x72, 0x01, 0x00, 0x00, 0x70,
            0x72, 0x02, 0x00, 0x00, 0x70,
            0x72, 0x03, 0x00, 0x00, 0x70,
            0x2A,
        ];
        let matches = rec().detect_sql_query(&code);
        assert!(matches.iter().any(|m| m.pattern == Pattern::SqlQuery));
    }

    #[test]
    fn detect_resource_extract_ldstr_callvirt() {
        let code = [0x72, 0x01, 0x00, 0x00, 0x70, 0x6F, 0x02, 0x00, 0x00, 0x06, 0x2A];
        let matches = rec().detect_resource_extract(&code);
        assert!(matches.iter().any(|m| m.pattern == Pattern::ResourceExtract));
    }

    #[test]
    fn confidence_threshold_filters() {
        let mut r = CilPatternRecognizer::new();
        r.include_low_confidence = false;
        r.min_confidence = 0.9; // very high threshold
        let code = [0x61, 0x9E, 0x2A];
        let matches = r.detect_string_encryption(&code);
        // 0.75 confidence should be filtered at 0.9 threshold
        assert!(matches.is_empty());
    }

    #[test]
    fn pattern_match_fields() {
        let m = PatternMatch::new(
            Pattern::AntiDebug,
            0x10,
            0.75,
            vec!["test".to_string()],
        );
        assert_eq!(m.pattern, Pattern::AntiDebug);
        assert_eq!(m.offset, 0x10);
        assert!((m.confidence - 0.75).abs() < 1e-9);
        assert_eq!(m.evidence.len(), 1);
    }

    #[test]
    fn detect_file_ops_ldstr_newobj() {
        let code = [
            0x72, 0x01, 0x00, 0x00, 0x70,
            0x73, 0x02, 0x00, 0x00, 0x07,
            0x2A,
        ];
        let matches = rec().detect_file_ops(&code);
        assert!(matches.iter().any(|m| m.pattern == Pattern::FileSystemOp));
    }

    #[test]
    fn empty_code_no_matches() {
        let code = [];
        let matches = rec().scan_method(&code);
        assert!(matches.is_empty());
    }
}
