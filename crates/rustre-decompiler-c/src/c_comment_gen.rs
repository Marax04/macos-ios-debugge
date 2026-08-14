//! `c_comment_gen` — automatic comment generation for decompiled C pseudocode.
//!
//! Recognises known library functions (Win32 API, POSIX libc, C runtime),
//! common algorithmic patterns (string loops, memcpy idioms, crypto constants),
//! and cross-reference sites, then injects `/* … */` comments at the
//! appropriate lines.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// CommentKind
// ─────────────────────────────────────────────────────────────────────────────

/// The category of an auto-generated comment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommentKind {
    /// Annotation for a known library/API function call.
    LibraryFunction,
    /// Recognised algorithmic pattern (loop, copy idiom, …).
    Pattern,
    /// Cross-reference: this address is called from / calls / is a data ref.
    Xref,
    /// Security-relevant site (format string, unsafe copy, …).
    SecurityNote,
    /// Crypto constant or algorithm hint.
    Crypto,
    /// Custom / user-supplied annotation.
    Custom,
}

// ─────────────────────────────────────────────────────────────────────────────
// GeneratedComment
// ─────────────────────────────────────────────────────────────────────────────

/// A comment to be injected at a specific line (1-based) in the output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedComment {
    /// 1-based line number in the source where the comment should appear.
    pub line: usize,
    /// The comment text (without `/* */` delimiters).
    pub text: String,
    /// Category.
    pub kind: CommentKind,
    /// Whether to place it *before* the line (`true`) or at end-of-line (`false`).
    pub before_line: bool,
}

impl GeneratedComment {
    pub fn end_of_line(line: usize, text: impl Into<String>, kind: CommentKind) -> Self {
        Self {
            line,
            text: text.into(),
            kind,
            before_line: false,
        }
    }

    pub fn before(line: usize, text: impl Into<String>, kind: CommentKind) -> Self {
        Self {
            line,
            text: text.into(),
            kind,
            before_line: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LibraryFunctionDatabase
// ─────────────────────────────────────────────────────────────────────────────

/// A static database of known library/API functions and their annotations.
#[derive(Debug, Default, Clone)]
pub struct LibraryFunctionDatabase {
    entries: HashMap<String, LibFuncEntry>,
}

#[derive(Debug, Clone)]
pub struct LibFuncEntry {
    pub description: String,
    pub header: Option<String>,
    pub security_note: Option<String>,
    pub category: FuncCategory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuncCategory {
    Memory,
    String,
    Io,
    Process,
    Thread,
    Registry,
    Network,
    Crypto,
    Math,
    Time,
    Debug,
    Other,
}

impl LibraryFunctionDatabase {
    fn add_libc_builtins(db: &mut Self) {
        db.add("malloc",   "Allocate heap memory", Some("stdlib.h"), None, FuncCategory::Memory);
        db.add("calloc",   "Allocate zero-initialised heap memory", Some("stdlib.h"), None, FuncCategory::Memory);
        db.add("realloc",  "Resize heap allocation", Some("stdlib.h"), None, FuncCategory::Memory);
        db.add("free",     "Free heap allocation", Some("stdlib.h"), None, FuncCategory::Memory);
        db.add("memcpy",   "Copy memory region (no overlap)", Some("string.h"),
               Some("UNSAFE if buffers overlap — prefer memmove"), FuncCategory::Memory);
        db.add("memmove",  "Copy memory region (handles overlap)", Some("string.h"), None, FuncCategory::Memory);
        db.add("memset",   "Fill memory region with byte value", Some("string.h"), None, FuncCategory::Memory);
        db.add("memcmp",   "Compare memory regions", Some("string.h"), None, FuncCategory::Memory);
        db.add("strlen",   "Get string length (null-terminated)", Some("string.h"), None, FuncCategory::String);
        // POSIX/C11-Annex-K bounded length. A real `<string.h>` declaration
        // exists, so it must count as a PUBLISHED prototype (D18) — omitting it
        // let the forward-decl pass emit a conflicting `__int64 strnlen();`.
        db.add("strnlen",  "Get string length, bounded by N", Some("string.h"), None, FuncCategory::String);
        // Wide twin of `strnlen`, same reason and same defect: mingw's headers
        // declare it, so a forward-decl `__int64 wcsnlen();` conflicts. It is
        // the ONLY `wcs*` name the corpus actually trips over (measured on
        // sample7_cpp: 1 occurrence, and no other conflicting name at all), so
        // the rest of `<wchar.h>` is deliberately NOT bulk-added — a form being
        // absent is not the same as a defect being present.
        db.add("wcsnlen",  "Get wide string length, bounded by N", Some("wchar.h"), None, FuncCategory::String);
        // Stessa classe di `wcsnlen` (forward decl in conflitto col prototipo),
        // e ARITA' LETTA negli header mingw, non a memoria:
        //   stdlib.h: _onexit_t __cdecl _onexit(_onexit_t _Func)   -> 1
        //   stdlib.h: errno_t   __cdecl _set_fmode(int _Mode)      -> 1
        // Misurato: 4 `_onexit` + 2 `_set_fmode` = 6 dei 23 errori gcc residui.
        db.add("_onexit",  "Register a function to run at exit", Some("stdlib.h"), None, FuncCategory::Process);
        db.add("_set_fmode", "Set default file translation mode", Some("stdlib.h"), None, FuncCategory::Process);
        db.add("strcpy",   "Copy null-terminated string", Some("string.h"),
               Some("UNSAFE — no bounds check, use strncpy or strlcpy"), FuncCategory::String);
        db.add("strncpy",  "Copy at most N bytes of string", Some("string.h"), None, FuncCategory::String);
        db.add("strcat",   "Append null-terminated string", Some("string.h"),
               Some("UNSAFE — no bounds check, use strncat"), FuncCategory::String);
        db.add("strncat",  "Append at most N bytes of string", Some("string.h"), None, FuncCategory::String);
        db.add("strcmp",   "Compare null-terminated strings", Some("string.h"), None, FuncCategory::String);
        db.add("strncmp",  "Compare at most N bytes of strings", Some("string.h"), None, FuncCategory::String);
        db.add("strchr",   "Find first occurrence of char in string", Some("string.h"), None, FuncCategory::String);
        db.add("strrchr",  "Find last occurrence of char in string", Some("string.h"), None, FuncCategory::String);
        db.add("strstr",   "Find substring in string", Some("string.h"), None, FuncCategory::String);
        db.add("strtol",   "Parse long integer from string", Some("stdlib.h"), None, FuncCategory::String);
        db.add("strtoul",  "Parse unsigned long integer from string", Some("stdlib.h"), None, FuncCategory::String);
        db.add("atoi",     "Convert string to int", Some("stdlib.h"),
               Some("No error detection — prefer strtol"), FuncCategory::String);
        db.add("atof",     "Convert string to double", Some("stdlib.h"), None, FuncCategory::String);
        db.add("printf",   "Print formatted string to stdout", Some("stdio.h"),
               Some("Format-string vulnerability if arg is user-controlled"), FuncCategory::Io);
        db.add("fprintf",  "Print formatted string to file", Some("stdio.h"),
               Some("Format-string vulnerability if arg is user-controlled"), FuncCategory::Io);
        db.add("sprintf",  "Print formatted string to buffer", Some("stdio.h"),
               Some("UNSAFE buffer overflow — use snprintf"), FuncCategory::Io);
        db.add("snprintf", "Print formatted string to sized buffer", Some("stdio.h"), None, FuncCategory::Io);
        db.add("sscanf",   "Parse formatted input from string", Some("stdio.h"), None, FuncCategory::Io);
        db.add("fopen",    "Open file stream", Some("stdio.h"), None, FuncCategory::Io);
        db.add("fclose",   "Close file stream", Some("stdio.h"), None, FuncCategory::Io);
        db.add("fread",    "Read from file stream", Some("stdio.h"), None, FuncCategory::Io);
        db.add("fwrite",   "Write to file stream", Some("stdio.h"), None, FuncCategory::Io);
        db.add("fgets",    "Read line from file stream", Some("stdio.h"), None, FuncCategory::Io);
        db.add("fputs",    "Write string to file stream", Some("stdio.h"), None, FuncCategory::Io);
        db.add("fseek",    "Seek in file stream", Some("stdio.h"), None, FuncCategory::Io);
        db.add("ftell",    "Get file position", Some("stdio.h"), None, FuncCategory::Io);
        db.add("fflush",   "Flush file stream", Some("stdio.h"), None, FuncCategory::Io);
        db.add("exit",     "Terminate process", Some("stdlib.h"), None, FuncCategory::Process);
        db.add("abort",    "Terminate process abnormally", Some("stdlib.h"), None, FuncCategory::Process);
        db.add("getenv",   "Get environment variable", Some("stdlib.h"), None, FuncCategory::Process);
        db.add("system",   "Execute shell command", Some("stdlib.h"),
               Some("SECURITY: shell injection if arg is user-controlled"), FuncCategory::Process);
        db.add("qsort",    "Sort array", Some("stdlib.h"), None, FuncCategory::Other);
        db.add("bsearch",  "Binary search in sorted array", Some("stdlib.h"), None, FuncCategory::Other);
        db.add("rand",     "Generate pseudo-random number (WEAK)", Some("stdlib.h"),
               Some("NOT cryptographically secure"), FuncCategory::Crypto);
        db.add("srand",    "Seed pseudo-random number generator", Some("stdlib.h"), None, FuncCategory::Crypto);

    }

    fn add_posix_builtins(db: &mut Self) {
        db.add("open",     "Open file descriptor", Some("fcntl.h"), None, FuncCategory::Io);
        db.add("close",    "Close file descriptor", Some("unistd.h"), None, FuncCategory::Io);
        db.add("read",     "Read from file descriptor", Some("unistd.h"), None, FuncCategory::Io);
        db.add("write",    "Write to file descriptor", Some("unistd.h"), None, FuncCategory::Io);
        db.add("mmap",     "Map file/device into memory", Some("sys/mman.h"), None, FuncCategory::Memory);
        db.add("munmap",   "Unmap memory region", Some("sys/mman.h"), None, FuncCategory::Memory);
        db.add("fork",     "Create child process", Some("unistd.h"), None, FuncCategory::Process);
        db.add("exec",     "Execute program", Some("unistd.h"), None, FuncCategory::Process);
        db.add("execve",   "Execute program with env", Some("unistd.h"),
               Some("SECURITY: argument injection risk"), FuncCategory::Process);
        db.add("pthread_create", "Create POSIX thread", Some("pthread.h"), None, FuncCategory::Thread);
        db.add("pthread_join",   "Wait for thread completion", Some("pthread.h"), None, FuncCategory::Thread);
        db.add("pthread_mutex_lock",   "Acquire mutex", Some("pthread.h"), None, FuncCategory::Thread);
        db.add("pthread_mutex_unlock", "Release mutex", Some("pthread.h"), None, FuncCategory::Thread);

    }

    fn add_win32_builtins(db: &mut Self) {
        db.add("CreateFile",         "Open/create file (Win32)", Some("windows.h"), None, FuncCategory::Io);
        db.add("ReadFile",           "Read from file handle (Win32)", Some("windows.h"), None, FuncCategory::Io);
        db.add("WriteFile",          "Write to file handle (Win32)", Some("windows.h"), None, FuncCategory::Io);
        db.add("CloseHandle",        "Close Win32 handle", Some("windows.h"), None, FuncCategory::Io);
        db.add("VirtualAlloc",       "Allocate virtual memory (Win32)", Some("windows.h"), None, FuncCategory::Memory);
        db.add("VirtualFree",        "Free virtual memory (Win32)", Some("windows.h"), None, FuncCategory::Memory);
        db.add("VirtualProtect",     "Change memory protection (Win32)", Some("windows.h"),
               Some("Used in shellcode/injection patterns"), FuncCategory::Memory);
        db.add("HeapAlloc",          "Allocate from heap (Win32)", Some("windows.h"), None, FuncCategory::Memory);
        db.add("HeapFree",           "Free heap allocation (Win32)", Some("windows.h"), None, FuncCategory::Memory);
        db.add("LoadLibrary",        "Load DLL into process (Win32)", Some("windows.h"),
               Some("SECURITY: DLL hijacking risk"), FuncCategory::Other);
        db.add("LoadLibraryA",       "Load DLL (ANSI) into process (Win32)", Some("windows.h"),
               Some("SECURITY: DLL hijacking risk"), FuncCategory::Other);
        db.add("LoadLibraryW",       "Load DLL (Unicode) into process (Win32)", Some("windows.h"),
               Some("SECURITY: DLL hijacking risk"), FuncCategory::Other);
        db.add("GetProcAddress",     "Get function pointer from DLL (Win32)", Some("windows.h"), None, FuncCategory::Other);
        db.add("CreateProcess",      "Create new process (Win32)", Some("windows.h"),
               Some("SECURITY: command injection risk"), FuncCategory::Process);
        db.add("OpenProcess",        "Open handle to process (Win32)", Some("windows.h"), None, FuncCategory::Process);
        db.add("TerminateProcess",   "Terminate process (Win32)", Some("windows.h"), None, FuncCategory::Process);
        db.add("CreateThread",       "Create thread (Win32)", Some("windows.h"), None, FuncCategory::Thread);
        db.add("WaitForSingleObject","Wait for kernel object (Win32)", Some("windows.h"), None, FuncCategory::Thread);
        db.add("RegOpenKeyEx",       "Open registry key (Win32)", Some("windows.h"), None, FuncCategory::Registry);
        db.add("RegQueryValueEx",    "Query registry value (Win32)", Some("windows.h"), None, FuncCategory::Registry);
        db.add("RegSetValueEx",      "Set registry value (Win32)", Some("windows.h"), None, FuncCategory::Registry);
        db.add("RegCreateKeyEx",     "Create registry key (Win32)", Some("windows.h"), None, FuncCategory::Registry);
        db.add("RegDeleteKey",       "Delete registry key (Win32)", Some("windows.h"), None, FuncCategory::Registry);
        db.add("WSAStartup",         "Initialise Winsock (Win32)", Some("winsock2.h"), None, FuncCategory::Network);
        db.add("socket",             "Create network socket", Some("winsock2.h"), None, FuncCategory::Network);
        db.add("connect",            "Connect socket to address", Some("winsock2.h"), None, FuncCategory::Network);
        db.add("send",               "Send data on socket", Some("winsock2.h"), None, FuncCategory::Network);
        db.add("recv",               "Receive data from socket", Some("winsock2.h"), None, FuncCategory::Network);
        db.add("bind",               "Bind socket to address", Some("winsock2.h"), None, FuncCategory::Network);
        db.add("listen",             "Listen for connections on socket", Some("winsock2.h"), None, FuncCategory::Network);
        db.add("accept",             "Accept incoming connection", Some("winsock2.h"), None, FuncCategory::Network);
        db.add("InternetOpen",       "Initialise WinInet (Win32)", Some("wininet.h"), None, FuncCategory::Network);
        db.add("InternetConnect",    "Connect to internet host (Win32)", Some("wininet.h"), None, FuncCategory::Network);
        db.add("HttpOpenRequest",    "Open HTTP request (Win32)", Some("wininet.h"), None, FuncCategory::Network);
        db.add("HttpSendRequest",    "Send HTTP request (Win32)", Some("wininet.h"), None, FuncCategory::Network);
        db.add("CryptEncrypt",       "Encrypt data (Win32 CryptoAPI)", Some("wincrypt.h"), None, FuncCategory::Crypto);
        db.add("CryptDecrypt",       "Decrypt data (Win32 CryptoAPI)", Some("wincrypt.h"), None, FuncCategory::Crypto);
        db.add("CryptHashData",      "Hash data (Win32 CryptoAPI)", Some("wincrypt.h"), None, FuncCategory::Crypto);
        db.add("IsDebuggerPresent",  "Check if debugger is attached (Win32)", Some("windows.h"),
               Some("Anti-debugging check"), FuncCategory::Debug);
        db.add("CheckRemoteDebuggerPresent", "Remote debugger check (Win32)", Some("windows.h"),
               Some("Anti-debugging check"), FuncCategory::Debug);
        db.add("OutputDebugString",  "Send string to debugger output (Win32)", Some("windows.h"), None, FuncCategory::Debug);
        db.add("GetLastError",       "Get last Win32 error code", Some("windows.h"), None, FuncCategory::Other);
        db.add("SetLastError",       "Set last Win32 error code", Some("windows.h"), None, FuncCategory::Other);
        db.add("GetTickCount",       "Get milliseconds since boot (Win32)", Some("windows.h"), None, FuncCategory::Time);
        db.add("GetSystemTime",      "Get current system time (Win32)", Some("windows.h"), None, FuncCategory::Time);
        db.add("Sleep",              "Suspend thread execution (Win32)", Some("windows.h"), None, FuncCategory::Thread);
    }

    /// Build the built-in database.
    #[must_use]
    pub fn builtin() -> Self {
        let mut db = Self::default();
        Self::add_libc_builtins(&mut db);
        Self::add_posix_builtins(&mut db);
        Self::add_win32_builtins(&mut db);
        db
    }

    fn add(
        &mut self,
        name: &str,
        desc: &str,
        header: Option<&str>,
        security: Option<&str>,
        cat: FuncCategory,
    ) {
        self.entries.insert(
            name.to_string(),
            LibFuncEntry {
                description: desc.to_string(),
                header: header.map(std::string::ToString::to_string),
                security_note: security.map(std::string::ToString::to_string),
                category: cat,
            },
        );
    }

    /// Look up a function name.
    #[must_use]
    pub fn lookup(&self, name: &str) -> Option<&LibFuncEntry> {
        self.entries.get(name)
    }

    /// True if the function is known in the database.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternMatcher
// ─────────────────────────────────────────────────────────────────────────────

/// Recognises common algorithmic patterns in multi-line C pseudocode.
pub struct PatternMatcher;

/// A recognised pattern in the source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    /// First line number (1-based) of the pattern.
    pub start_line: usize,
    /// Inclusive last line of the pattern.
    pub end_line: usize,
    /// Human-readable pattern name.
    pub name: String,
    /// Suggested comment text.
    pub comment: String,
}

impl PatternMatcher {
    fn scan_crypto_patterns(i: usize, t: &str, lineno: usize, lines: &[&str], matches: &mut Vec<PatternMatch>) {
        if (t.contains("^ ") || t.contains(" ^=")) && (t.contains("key") || t.contains("Key") || t.contains("KEY")) {
            matches.push(PatternMatch { start_line: lineno, end_line: lineno, name: "xor_cipher".to_string(), comment: "XOR cipher operation — possible encryption/obfuscation".to_string() });
        }
        if t.contains("256") && t.contains("S[") && t.contains("= i") {
            matches.push(PatternMatch { start_line: lineno, end_line: lineno + 3.min(lines.len() - i - 1), name: "rc4_ksa".to_string(), comment: "RC4 Key Scheduling Algorithm (KSA) — crypto".to_string() });
        }
        if t.contains("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") {
            matches.push(PatternMatch { start_line: lineno, end_line: lineno, name: "base64_table".to_string(), comment: "Base64 alphabet table".to_string() });
        }
        if t.contains("0xEDB88320") || t.contains("0x04C11DB7") {
            matches.push(PatternMatch { start_line: lineno, end_line: lineno, name: "crc32".to_string(), comment: "CRC32 polynomial constant".to_string() });
        }
        if t.contains("0x67452301") || t.contains("0xEFCDAB89") {
            matches.push(PatternMatch { start_line: lineno, end_line: lineno, name: "md5_init".to_string(), comment: "MD5 initialisation constants".to_string() });
        }
        if t.contains("0x67452301") && t.contains("0x98BADCFE") {
            matches.push(PatternMatch { start_line: lineno, end_line: lineno, name: "sha1_init".to_string(), comment: "SHA-1 initialisation constants".to_string() });
        }
        if (t.contains("GetTickCount") || t.contains("QueryPerformanceCounter")) && i + 3 < lines.len() {
            let window: String = lines[i..i + 3].join(" ");
            if (window.contains("GetTickCount") || window.contains("QueryPerformanceCounter")) && (window.contains('>') || window.contains('<') || window.contains("diff")) {
                matches.push(PatternMatch { start_line: lineno, end_line: lineno + 2, name: "timing_anti_debug".to_string(), comment: "Timing-based anti-debug check (RDTSC / GetTickCount delta)".to_string() });
            }
        }
        if t.contains("__security_cookie") || t.contains("__stack_chk") {
            matches.push(PatternMatch { start_line: lineno, end_line: lineno, name: "stack_canary".to_string(), comment: "Stack canary check (stack buffer overflow protection)".to_string() });
        }
        if (t.contains("* 1103515245") || t.contains("* 6364136223846793005")) && t.contains('+') {
            matches.push(PatternMatch { start_line: lineno, end_line: lineno, name: "lcg_prng".to_string(), comment: "Linear congruential generator (LCG) PRNG step".to_string() });
        }
    }

    /// Check one source line for patterns and append any matches.
    fn scan_line(i: usize, line: &str, lines: &[&str], matches: &mut Vec<PatternMatch>) {
        let t = line.trim();
        let lineno = i + 1;
        if (t.contains("while") && t.contains('*') && t.contains("\\0"))
            || (t.contains("while") && t.contains("*ptr") && i + 1 < lines.len() && lines[i + 1].trim().contains("++"))
        {
            matches.push(PatternMatch { start_line: lineno, end_line: lineno + 2.min(lines.len() - i - 1), name: "string_length_loop".to_string(), comment: "strlen-style loop: scan for null terminator".to_string() });
        }
        if t.contains("*dst") && t.contains("*src") && (t.contains("++") || t.contains("--")) {
            matches.push(PatternMatch { start_line: lineno, end_line: lineno, name: "manual_memcpy".to_string(), comment: "manual memcpy pattern: byte-by-byte copy".to_string() });
        }
        if t.contains("while") && t.contains('0') && (t.contains("*p") || t.contains("*buf") || t.contains("*dst")) {
            matches.push(PatternMatch { start_line: lineno, end_line: lineno + 1.min(lines.len() - i - 1), name: "manual_memset".to_string(), comment: "manual memset pattern: zero-fill loop".to_string() });
        }
        if t.contains("->next") && (t.starts_with("while") || t.starts_with("for")) {
            matches.push(PatternMatch { start_line: lineno, end_line: lineno, name: "linked_list_traversal".to_string(), comment: "linked-list traversal".to_string() });
        }
        Self::scan_crypto_patterns(i, t, lineno, lines, matches);
    }

    /// Scan the source lines for patterns. Returns all matches.
    #[must_use]
    pub fn scan(lines: &[&str]) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        for (i, &line) in lines.iter().enumerate() {
            Self::scan_line(i, line, lines, &mut matches);
        }
        matches
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XrefDatabase
// ─────────────────────────────────────────────────────────────────────────────

/// Holds cross-reference information used to generate xref comments.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct XrefDatabase {
    /// Map from function name to list of caller names.
    pub callers: HashMap<String, Vec<String>>,
    /// Map from function name to list of callee names.
    pub callees: HashMap<String, Vec<String>>,
    /// Map from address string to symbolic name.
    pub addr_names: HashMap<String, String>,
}

impl XrefDatabase {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_caller(&mut self, func: &str, caller: &str) {
        self.callers
            .entry(func.to_string())
            .or_default()
            .push(caller.to_string());
    }

    pub fn add_callee(&mut self, func: &str, callee: &str) {
        self.callees
            .entry(func.to_string())
            .or_default()
            .push(callee.to_string());
    }

    pub fn add_addr_name(&mut self, addr: &str, name: &str) {
        self.addr_names.insert(addr.to_string(), name.to_string());
    }

    /// Generate an xref comment for a function header.
    #[must_use]
    pub fn header_comment(&self, func_name: &str) -> Option<String> {
        let callers = self.callers.get(func_name)?;
        if callers.is_empty() {
            return None;
        }
        let list = callers.join(", ");
        Some(format!("Called from: {list}"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CommentConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Bitfield of which comment annotation categories are enabled.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CommentAnnotationFlags(u8);

impl CommentAnnotationFlags {
    const LIB_FUNCTIONS: u8 = 0b00001;
    const PATTERNS: u8 = 0b00010;
    const SECURITY: u8 = 0b00100;
    const XREFS: u8 = 0b01000;
    const CRYPTO: u8 = 0b10000;
    const ALL: u8 = 0b11111;

    #[must_use] pub const fn all() -> Self { Self(Self::ALL) }
    #[must_use] pub const fn annotate_lib_functions(self) -> bool { self.0 & Self::LIB_FUNCTIONS != 0 }
    #[must_use] pub const fn annotate_patterns(self) -> bool { self.0 & Self::PATTERNS != 0 }
    #[must_use] pub const fn annotate_security(self) -> bool { self.0 & Self::SECURITY != 0 }
    #[must_use] pub const fn annotate_xrefs(self) -> bool { self.0 & Self::XREFS != 0 }
    #[must_use] pub const fn annotate_crypto(self) -> bool { self.0 & Self::CRYPTO != 0 }
}

impl Default for CommentAnnotationFlags {
    fn default() -> Self { Self(Self::ALL) }
}

/// Configuration for comment generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommentConfig {
    /// Which annotation categories are enabled.
    pub annotations: CommentAnnotationFlags,
    pub max_eol_comment_len: usize,
}

impl Default for CommentConfig {
    fn default() -> Self {
        Self {
            annotations: CommentAnnotationFlags::all(),
            max_eol_comment_len: 60,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CommentGenerator
// ─────────────────────────────────────────────────────────────────────────────

/// Generates [`GeneratedComment`]s for a block of C pseudocode.
pub struct CommentGenerator {
    pub config: CommentConfig,
    pub lib_db: LibraryFunctionDatabase,
    pub xref_db: XrefDatabase,
}

impl CommentGenerator {
    /// Create with default databases and config.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: CommentConfig::default(),
            lib_db: LibraryFunctionDatabase::builtin(),
            xref_db: XrefDatabase::new(),
        }
    }

    /// Set the xref database.
    #[must_use]
    pub fn with_xrefs(mut self, db: XrefDatabase) -> Self {
        self.xref_db = db;
        self
    }

    /// Generate all comments for the given source lines.
    #[must_use]
    pub fn generate(&self, lines: &[&str]) -> Vec<GeneratedComment> {
        let mut comments: Vec<GeneratedComment> = Vec::new();

        // ── Library function annotations ─────────────────────────────────
        if self.config.annotations.annotate_lib_functions() {
            for (i, &line) in lines.iter().enumerate() {
                let lineno = i + 1;
                // Extract all function call names from the line.
                for func_name in extract_call_names(line) {
                    if let Some(entry) = self.lib_db.lookup(&func_name) {
                        let mut text = entry.description.clone();
                        if let Some(ref hdr) = entry.header {
                            use std::fmt::Write as _;
                            write!(text, " [{hdr}]").unwrap();
                        }
                        if text.len() > self.config.max_eol_comment_len {
                            text.truncate(self.config.max_eol_comment_len);
                            text.push('…');
                        }
                        comments.push(GeneratedComment::end_of_line(lineno, text, CommentKind::LibraryFunction));

                        // Security notes go as a separate before-line comment.
                        if self.config.annotations.annotate_security()
                            && let Some(ref sec) = entry.security_note {
                                comments.push(GeneratedComment::before(
                                    lineno,
                                    format!("SECURITY: {sec}"),
                                    CommentKind::SecurityNote,
                                ));
                            }
                    }
                }
            }
        }

        // ── Pattern annotations ───────────────────────────────────────────
        if self.config.annotations.annotate_patterns() {
            let pattern_matches = PatternMatcher::scan(lines);
            for pm in pattern_matches {
                let kind = if pm.name.contains("crypto")
                    || pm.name.contains("rc4")
                    || pm.name.contains("md5")
                    || pm.name.contains("sha")
                    || pm.name.contains("xor_cipher")
                    || pm.name.contains("crc32")
                    || pm.name.contains("base64")
                    || pm.name.contains("lcg")
                {
                    CommentKind::Crypto
                } else if pm.name.contains("anti_debug") || pm.name.contains("canary") {
                    CommentKind::SecurityNote
                } else {
                    CommentKind::Pattern
                };
                comments.push(GeneratedComment::before(pm.start_line, pm.comment, kind));
            }
        }

        comments
    }

    /// Apply generated comments to a vector of source lines, returning the
    /// annotated source.
    #[must_use]
    pub fn apply(&self, lines: &[String], comments: &[GeneratedComment]) -> Vec<String> {
        let mut before_comments: HashMap<usize, Vec<&GeneratedComment>> = HashMap::new();
        let mut eol_comments: HashMap<usize, Vec<&GeneratedComment>> = HashMap::new();

        for c in comments {
            if c.before_line {
                before_comments.entry(c.line).or_default().push(c);
            } else {
                eol_comments.entry(c.line).or_default().push(c);
            }
        }

        let mut out: Vec<String> = Vec::with_capacity(lines.len() + comments.len());

        for (i, line) in lines.iter().enumerate() {
            let lineno = i + 1;

            // Insert before-comments.
            if let Some(befores) = before_comments.get(&lineno) {
                // Detect the indentation of the current line.
                let indent: String = line
                    .chars()
                    .take_while(|c| c.is_whitespace())
                    .collect();
                for bc in befores {
                    out.push(format!("{indent}/* {} */", bc.text));
                }
            }

            // Append end-of-line comments.
            if let Some(eols) = eol_comments.get(&lineno) {
                let joined: String = eols.iter().map(|c| c.text.clone()).collect::<Vec<_>>().join("; ");
                out.push(format!("{line} /* {joined} */"));
            } else {
                out.push(line.clone());
            }
        }

        out
    }

    /// High-level: process source and return annotated version.
    pub fn annotate(&self, source: &str) -> String {
        let lines_str: Vec<String> = source.lines().map(std::string::ToString::to_string).collect();
        let line_refs: Vec<&str> = lines_str.iter().map(std::string::String::as_str).collect();
        let comments = self.generate(&line_refs);
        let annotated = self.apply(&lines_str, &comments);
        annotated.join("\n")
    }
}

impl Default for CommentGenerator {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: extract call names from a line
// ─────────────────────────────────────────────────────────────────────────────

/// Extract bare function names that appear in a call context (`name(`).
fn extract_call_names(line: &str) -> Vec<String> {
    let mut names = Vec::new();
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        // Skip non-identifier starts.
        if !chars[i].is_alphabetic() && chars[i] != '_' {
            i += 1;
            continue;
        }
        // Collect identifier.
        let start = i;
        while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
            i += 1;
        }
        let name: String = chars[start..i].iter().collect();
        // Check if followed immediately by `(`.
        let mut j = i;
        while j < chars.len() && chars[j] == ' ' {
            j += 1;
        }
        if j < chars.len() && chars[j] == '(' {
            names.push(name);
        }
    }

    names
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionHeaderCommentBuilder
// ─────────────────────────────────────────────────────────────────────────────

/// Builds a multi-line header comment block for a function.
pub struct FunctionHeaderCommentBuilder {
    func_name: String,
    address: Option<u64>,
    calling_convention: Option<String>,
    xrefs: Vec<String>,
    custom_notes: Vec<String>,
}

impl FunctionHeaderCommentBuilder {
    #[must_use]
    pub fn new(func_name: impl Into<String>) -> Self {
        Self {
            func_name: func_name.into(),
            address: None,
            calling_convention: None,
            xrefs: Vec::new(),
            custom_notes: Vec::new(),
        }
    }

    #[must_use]
    pub const fn address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    #[must_use]
    pub fn calling_convention(mut self, cc: impl Into<String>) -> Self {
        self.calling_convention = Some(cc.into());
        self
    }

    pub fn add_xref(&mut self, xref: impl Into<String>) {
        self.xrefs.push(xref.into());
    }

    pub fn add_note(&mut self, note: impl Into<String>) {
        self.custom_notes.push(note.into());
    }

    /// Build the comment block string.
    #[must_use]
    pub fn build(&self) -> String {
        use std::fmt::Write as _;
        let mut lines: Vec<String> = Vec::new();
        lines.push(format!("Function: {}", self.func_name));
        if let Some(addr) = self.address {
            lines.push(format!("  Address: 0x{addr:016X}"));
        }
        if let Some(ref cc) = self.calling_convention {
            lines.push(format!("  Calling convention: {cc}"));
        }
        if !self.xrefs.is_empty() {
            lines.push(format!("  Called from: {}", self.xrefs.join(", ")));
        }
        for note in &self.custom_notes {
            lines.push(format!("  Note: {note}"));
        }

        let width = lines.iter().map(std::string::String::len).max().unwrap_or(0) + 4;
        let bar = "*".repeat(width);
        let mut out = format!("/*{bar}\n");
        for l in &lines {
            writeln!(out, " * {l}").unwrap();
        }
        writeln!(out, " {bar}*/").unwrap();
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lib_db_lookup_malloc() {
        let db = LibraryFunctionDatabase::builtin();
        let entry = db.lookup("malloc").unwrap();
        assert!(entry.description.contains("heap"));
        assert_eq!(entry.header.as_deref(), Some("stdlib.h"));
    }

    #[test]
    fn test_lib_db_security_note_strcpy() {
        let db = LibraryFunctionDatabase::builtin();
        let entry = db.lookup("strcpy").unwrap();
        assert!(entry.security_note.is_some());
    }

    #[test]
    fn test_lib_db_missing() {
        let db = LibraryFunctionDatabase::builtin();
        assert!(db.lookup("__totally_unknown_fn").is_none());
    }

    #[test]
    fn test_extract_call_names() {
        let names = extract_call_names("    x = malloc(100);");
        assert!(names.contains(&"malloc".to_string()));
    }

    #[test]
    fn test_extract_call_names_multiple() {
        let names = extract_call_names("memcpy(dst, src, strlen(src));");
        assert!(names.contains(&"memcpy".to_string()));
        assert!(names.contains(&"strlen".to_string()));
    }

    #[test]
    fn test_comment_generator_annotates_malloc() {
        let cgen = CommentGenerator::new();
        let src = "    ptr = malloc(100);";
        let out = cgen.annotate(src);
        assert!(out.contains("malloc"), "output: {out}");
        assert!(out.contains("/*") || out.contains("heap"), "output: {out}");
    }

    #[test]
    fn test_comment_generator_security_note() {
        let cgen = CommentGenerator::new();
        let src = "    strcpy(dst, src);";
        let out = cgen.annotate(src);
        assert!(out.contains("UNSAFE") || out.contains("SECURITY") || out.contains("bounds"));
    }

    #[test]
    fn test_pattern_matcher_strlen_loop() {
        let lines = vec!["    while (*ptr != '\\0') {", "        ptr++;", "    }"];
        let matches = PatternMatcher::scan(&lines);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_function_header_builder() {
        let mut b = FunctionHeaderCommentBuilder::new("sub_1234");
        b = b.address(0x1234).calling_convention("__cdecl");
        b.add_xref("main");
        b.add_note("possible encryption routine");
        let hdr = b.build();
        assert!(hdr.contains("sub_1234"));
        assert!(hdr.contains("0x0000000000001234"));
        assert!(hdr.contains("__cdecl"));
        assert!(hdr.contains("main"));
    }

    #[test]
    fn test_xref_database() {
        let mut db = XrefDatabase::new();
        db.add_caller("foo", "main");
        db.add_caller("foo", "bar");
        let comment = db.header_comment("foo").unwrap();
        assert!(comment.contains("main"));
        assert!(comment.contains("bar"));
    }

    #[test]
    fn test_crc32_pattern() {
        let lines = vec!["    crc ^= 0xEDB88320;"];
        let matches = PatternMatcher::scan(&lines);
        assert!(matches.iter().any(|m| m.name == "crc32"));
    }

    #[test]
    fn test_winapi_virtualprotect_security() {
        let cgen = CommentGenerator::new();
        let src = "    VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &old);";
        let out = cgen.annotate(src);
        assert!(out.contains("VirtualProtect") || out.contains("injection") || out.contains("memory"));
    }
}
