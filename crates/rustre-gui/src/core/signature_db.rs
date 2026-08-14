// ============================================================================
// core/signature_db.rs — Known function/library signature database
// ============================================================================

use std::collections::HashMap;

// ── Signature category ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SigCategory {
    CRuntime,
    WinApi,
    PosixApi,
    Crypto,
    Network,
    Compression,
    AntiDebug,
    ProcessInjection,
    FileSystem,
    Registry,
    Threading,
    Memory,
    String,
    Math,
    Graphics,
    Database,
    Xml,
    Json,
    Unknown,
}

impl SigCategory {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::CRuntime => "C Runtime",
            Self::WinApi => "Win32 API",
            Self::PosixApi => "POSIX API",
            Self::Crypto => "Cryptography",
            Self::Network => "Networking",
            Self::Compression => "Compression",
            Self::AntiDebug => "Anti-Debug",
            Self::ProcessInjection => "Process Injection",
            Self::FileSystem => "File System",
            Self::Registry => "Registry",
            Self::Threading => "Threading",
            Self::Memory => "Memory",
            Self::String => "String",
            Self::Math => "Math",
            Self::Graphics => "Graphics",
            Self::Database => "Database",
            Self::Xml => "XML",
            Self::Json => "JSON",
            Self::Unknown => "Unknown",
        }
    }

    pub const fn is_sensitive(&self) -> bool {
        matches!(
            self,
            Self::AntiDebug | Self::ProcessInjection | Self::Crypto | Self::Network
        )
    }
}

// ── Argument descriptor ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ArgInfo {
    pub name: String,
    pub ty: String,
    pub direction: ArgDir,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgDir {
    In,
    Out,
    InOut,
    Return,
}

impl ArgInfo {
    pub fn new_in(name: &str, ty: &str) -> Self {
        Self {
            name: name.into(),
            ty: ty.into(),
            direction: ArgDir::In,
            notes: None,
        }
    }
    pub fn new_out(name: &str, ty: &str) -> Self {
        Self {
            name: name.into(),
            ty: ty.into(),
            direction: ArgDir::Out,
            notes: None,
        }
    }
    pub fn with_note(mut self, n: &str) -> Self {
        self.notes = Some(n.into());
        self
    }
}

// ── Calling convention ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallingConv {
    Cdecl,
    Stdcall,
    Fastcall,
    Thiscall,
    Win64,
    SysV,
    Unknown,
}

impl CallingConv {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Cdecl => "__cdecl",
            Self::Stdcall => "__stdcall",
            Self::Fastcall => "__fastcall",
            Self::Thiscall => "__thiscall",
            Self::Win64 => "win64",
            Self::SysV => "sysv",
            Self::Unknown => "unknown",
        }
    }
}

// ── Function signature entry ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FunctionSig {
    pub name: String,
    pub mangled_names: Vec<String>,
    pub library: String,
    pub category: SigCategory,
    pub return_type: String,
    pub args: Vec<ArgInfo>,
    pub calling_conv: CallingConv,
    pub description: String,
    pub notes: Vec<String>,
    pub cve_refs: Vec<String>,
    pub is_dangerous: bool,
    pub is_deprecated: bool,
}

impl FunctionSig {
    fn new(name: &str, lib: &str, cat: SigCategory, ret: &str, desc: &str) -> Self {
        Self {
            name: name.into(),
            mangled_names: Vec::new(),
            library: lib.into(),
            category: cat,
            return_type: ret.into(),
            args: Vec::new(),
            calling_conv: CallingConv::Cdecl,
            description: desc.into(),
            notes: Vec::new(),
            cve_refs: Vec::new(),
            is_dangerous: false,
            is_deprecated: false,
        }
    }

    const fn with_conv(mut self, cc: CallingConv) -> Self {
        self.calling_conv = cc;
        self
    }
    const fn dangerous(mut self) -> Self {
        self.is_dangerous = true;
        self
    }
    const fn deprecated(mut self) -> Self {
        self.is_deprecated = true;
        self
    }
    fn note(mut self, n: &str) -> Self {
        self.notes.push(n.into());
        self
    }
    fn cve(mut self, c: &str) -> Self {
        self.cve_refs.push(c.into());
        self
    }
    fn mangled(mut self, m: &str) -> Self {
        self.mangled_names.push(m.into());
        self
    }
    fn arg(mut self, a: ArgInfo) -> Self {
        self.args.push(a);
        self
    }

    pub fn prototype(&self) -> String {
        let args: Vec<String> = self
            .args
            .iter()
            .map(|a| format!("{} {}", a.ty, a.name))
            .collect();
        format!("{} {}({})", self.return_type, self.name, args.join(", "))
    }

    pub fn short_desc(&self) -> String {
        if self.description.len() > 80 {
            format!("{}…", &self.description[..77])
        } else {
            self.description.clone()
        }
    }
}

// ── The database ──────────────────────────────────────────────────────────────

pub struct SignatureDb {
    sigs: Vec<FunctionSig>,
    by_name: HashMap<String, usize>,
    by_lib: HashMap<String, Vec<usize>>,
    by_cat: HashMap<String, Vec<usize>>,
}

impl SignatureDb {
    pub fn new() -> Self {
        let mut db = Self {
            sigs: Vec::new(),
            by_name: HashMap::new(),
            by_lib: HashMap::new(),
            by_cat: HashMap::new(),
        };
        db.populate_c_runtime();
        db.populate_winapi_process();
        db.populate_winapi_memory();
        db.populate_winapi_file();
        db.populate_winapi_registry();
        db.populate_winapi_network();
        db.populate_winapi_crypto();
        db.populate_winapi_antidebug();
        db.populate_winapi_injection();
        db.populate_winapi_thread();
        db.populate_posix();
        db.populate_string();
        db.build_indices();
        db
    }

    fn insert(&mut self, sig: FunctionSig) {
        self.sigs.push(sig);
    }

    fn build_indices(&mut self) {
        for (i, sig) in self.sigs.iter().enumerate() {
            self.by_name.insert(sig.name.clone(), i);
            for m in &sig.mangled_names {
                self.by_name.insert(m.clone(), i);
            }
            self.by_lib.entry(sig.library.clone()).or_default().push(i);
            self.by_cat
                .entry(sig.category.label().to_string())
                .or_default()
                .push(i);
        }
    }

    pub fn lookup(&self, name: &str) -> Option<&FunctionSig> {
        self.by_name.get(name).map(|&i| &self.sigs[i])
    }

    pub fn lookup_fuzzy(&self, query: &str) -> Vec<&FunctionSig> {
        let q = query.to_lowercase();
        self.sigs
            .iter()
            .filter(|s| {
                s.name.to_lowercase().contains(&q) || s.description.to_lowercase().contains(&q)
            })
            .collect()
    }

    pub fn by_library(&self, lib: &str) -> Vec<&FunctionSig> {
        self.by_lib
            .get(lib)
            .map(|ids| ids.iter().map(|&i| &self.sigs[i]).collect())
            .unwrap_or_default()
    }

    pub fn by_category(&self, cat: &SigCategory) -> Vec<&FunctionSig> {
        self.by_cat
            .get(cat.label())
            .map(|ids| ids.iter().map(|&i| &self.sigs[i]).collect())
            .unwrap_or_default()
    }

    pub fn dangerous_functions(&self) -> Vec<&FunctionSig> {
        self.sigs.iter().filter(|s| s.is_dangerous).collect()
    }

    pub fn all(&self) -> &[FunctionSig] {
        &self.sigs
    }
    pub const fn len(&self) -> usize {
        self.sigs.len()
    }
    pub const fn is_empty(&self) -> bool {
        self.sigs.is_empty()
    }

    pub fn libraries(&self) -> Vec<&str> {
        let mut libs: Vec<&str> = self.by_lib.keys().map(String::as_str).collect();
        libs.sort_unstable();
        libs
    }

    pub fn stats(&self) -> DbStats {
        DbStats {
            total: self.sigs.len(),
            dangerous: self.sigs.iter().filter(|s| s.is_dangerous).count(),
            deprecated: self.sigs.iter().filter(|s| s.is_deprecated).count(),
            libraries: self.by_lib.len(),
            categories: self.by_cat.len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DbStats {
    pub total: usize,
    pub dangerous: usize,
    pub deprecated: usize,
    pub libraries: usize,
    pub categories: usize,
}

// ── Population helpers ────────────────────────────────────────────────────────

impl SignatureDb {
    fn populate_c_runtime(&mut self) {
        self.populate_c_runtime_memory_and_strings();
        self.populate_c_runtime_io_and_misc();
    }

    fn populate_c_runtime_memory_and_strings(&mut self) {
        use SigCategory::CRuntime;
        // `SigCategory::String` would shadow the prelude `String` type, so alias it.
        use SigCategory::String as StrCat;
        let lib = "msvcrt.dll";

        // Memory
        self.insert(
            FunctionSig::new(
                "malloc",
                lib,
                CRuntime.clone(),
                "void*",
                "Allocate heap memory block",
            )
            .arg(ArgInfo::new_in("size", "size_t")),
        );
        self.insert(
            FunctionSig::new(
                "calloc",
                lib,
                CRuntime.clone(),
                "void*",
                "Allocate zeroed heap memory",
            )
            .arg(ArgInfo::new_in("count", "size_t"))
            .arg(ArgInfo::new_in("size", "size_t")),
        );
        self.insert(
            FunctionSig::new(
                "realloc",
                lib,
                CRuntime.clone(),
                "void*",
                "Resize previously allocated block",
            )
            .arg(ArgInfo::new_in("ptr", "void*"))
            .arg(ArgInfo::new_in("new_size", "size_t")),
        );
        self.insert(
            FunctionSig::new(
                "free",
                lib,
                CRuntime.clone(),
                "void",
                "Free heap-allocated block",
            )
            .arg(ArgInfo::new_in("ptr", "void*")),
        );

        // String/memory
        self.insert(
            FunctionSig::new(
                "memcpy",
                lib,
                CRuntime.clone(),
                "void*",
                "Copy memory region (no overlap)",
            )
            .arg(ArgInfo::new_out("dst", "void*"))
            .arg(ArgInfo::new_in("src", "const void*"))
            .arg(ArgInfo::new_in("n", "size_t")),
        );
        self.insert(
            FunctionSig::new(
                "memmove",
                lib,
                CRuntime.clone(),
                "void*",
                "Copy memory region (overlap safe)",
            )
            .arg(ArgInfo::new_out("dst", "void*"))
            .arg(ArgInfo::new_in("src", "const void*"))
            .arg(ArgInfo::new_in("n", "size_t")),
        );
        self.insert(
            FunctionSig::new(
                "memset",
                lib,
                CRuntime.clone(),
                "void*",
                "Fill memory region with byte value",
            )
            .arg(ArgInfo::new_out("dst", "void*"))
            .arg(ArgInfo::new_in("c", "int"))
            .arg(ArgInfo::new_in("n", "size_t")),
        );
        self.insert(
            FunctionSig::new(
                "memcmp",
                lib,
                CRuntime.clone(),
                "int",
                "Compare two memory regions",
            )
            .arg(ArgInfo::new_in("a", "const void*"))
            .arg(ArgInfo::new_in("b", "const void*"))
            .arg(ArgInfo::new_in("n", "size_t")),
        );

        // String ops
        self.insert(
            FunctionSig::new(
                "strlen",
                lib,
                StrCat.clone(),
                "size_t",
                "Return length of null-terminated string",
            )
            .arg(ArgInfo::new_in("s", "const char*")),
        );
        self.insert(
            FunctionSig::new(
                "strcpy",
                lib,
                StrCat.clone(),
                "char*",
                "Copy string — no bounds check",
            )
            .arg(ArgInfo::new_out("dst", "char*"))
            .arg(ArgInfo::new_in("src", "const char*"))
            .dangerous()
            .note("Use strncpy or strcpy_s instead"),
        );
        self.insert(
            FunctionSig::new(
                "strncpy",
                lib,
                StrCat.clone(),
                "char*",
                "Copy at most n chars of string",
            )
            .arg(ArgInfo::new_out("dst", "char*"))
            .arg(ArgInfo::new_in("src", "const char*"))
            .arg(ArgInfo::new_in("n", "size_t")),
        );
        self.insert(
            FunctionSig::new(
                "strcat",
                lib,
                StrCat.clone(),
                "char*",
                "Append string — no bounds check",
            )
            .arg(ArgInfo::new_out("dst", "char*"))
            .arg(ArgInfo::new_in("src", "const char*"))
            .dangerous()
            .note("Use strncat or strcat_s instead"),
        );
        self.insert(
            FunctionSig::new(
                "strncat",
                lib,
                StrCat.clone(),
                "char*",
                "Append at most n chars of string",
            )
            .arg(ArgInfo::new_out("dst", "char*"))
            .arg(ArgInfo::new_in("src", "const char*"))
            .arg(ArgInfo::new_in("n", "size_t")),
        );
        self.insert(
            FunctionSig::new(
                "strcmp",
                lib,
                StrCat.clone(),
                "int",
                "Compare two strings lexicographically",
            )
            .arg(ArgInfo::new_in("a", "const char*"))
            .arg(ArgInfo::new_in("b", "const char*")),
        );
        self.insert(
            FunctionSig::new(
                "strncmp",
                lib,
                StrCat.clone(),
                "int",
                "Compare at most n chars of two strings",
            )
            .arg(ArgInfo::new_in("a", "const char*"))
            .arg(ArgInfo::new_in("b", "const char*"))
            .arg(ArgInfo::new_in("n", "size_t")),
        );
        self.insert(
            FunctionSig::new(
                "strstr",
                lib,
                StrCat.clone(),
                "char*",
                "Find first occurrence of substring",
            )
            .arg(ArgInfo::new_in("haystack", "const char*"))
            .arg(ArgInfo::new_in("needle", "const char*")),
        );
        self.insert(
            FunctionSig::new(
                "strtol",
                lib,
                StrCat.clone(),
                "long",
                "Convert string to long integer",
            )
            .arg(ArgInfo::new_in("s", "const char*"))
            .arg(ArgInfo::new_out("endptr", "char**"))
            .arg(ArgInfo::new_in("base", "int")),
        );
        self.insert(
            FunctionSig::new(
                "sprintf",
                lib,
                CRuntime.clone(),
                "int",
                "Format string into buffer — no bounds check",
            )
            .arg(ArgInfo::new_out("buf", "char*"))
            .arg(ArgInfo::new_in("fmt", "const char*"))
            .dangerous()
            .note("Use snprintf instead"),
        );
        self.insert(
            FunctionSig::new(
                "snprintf",
                lib,
                CRuntime.clone(),
                "int",
                "Format string into buffer with size limit",
            )
            .arg(ArgInfo::new_out("buf", "char*"))
            .arg(ArgInfo::new_in("n", "size_t"))
            .arg(ArgInfo::new_in("fmt", "const char*")),
        );
        self.insert(
            FunctionSig::new(
                "printf",
                lib,
                CRuntime.clone(),
                "int",
                "Print formatted text to stdout",
            )
            .arg(ArgInfo::new_in("fmt", "const char*")),
        );
        self.insert(
            FunctionSig::new(
                "scanf",
                lib,
                CRuntime.clone(),
                "int",
                "Read formatted input from stdin — dangerous",
            )
            .arg(ArgInfo::new_in("fmt", "const char*"))
            .dangerous()
            .note("Use sscanf_s or manual parsing"),
        );
    }

    fn populate_c_runtime_io_and_misc(&mut self) {
        use SigCategory::CRuntime;
        use SigCategory::FileSystem;
        let lib = "msvcrt.dll";
        self.insert(
            FunctionSig::new(
                "fopen",
                lib,
                FileSystem.clone(),
                "FILE*",
                "Open file by path",
            )
            .arg(ArgInfo::new_in("path", "const char*"))
            .arg(ArgInfo::new_in("mode", "const char*")),
        );
        self.insert(
            FunctionSig::new(
                "fclose",
                lib,
                FileSystem.clone(),
                "int",
                "Close open file handle",
            )
            .arg(ArgInfo::new_in("fp", "FILE*")),
        );
        self.insert(
            FunctionSig::new(
                "fread",
                lib,
                FileSystem.clone(),
                "size_t",
                "Read binary data from file",
            )
            .arg(ArgInfo::new_out("buf", "void*"))
            .arg(ArgInfo::new_in("size", "size_t"))
            .arg(ArgInfo::new_in("count", "size_t"))
            .arg(ArgInfo::new_in("fp", "FILE*")),
        );
        self.insert(
            FunctionSig::new(
                "fwrite",
                lib,
                FileSystem.clone(),
                "size_t",
                "Write binary data to file",
            )
            .arg(ArgInfo::new_in("buf", "const void*"))
            .arg(ArgInfo::new_in("size", "size_t"))
            .arg(ArgInfo::new_in("count", "size_t"))
            .arg(ArgInfo::new_in("fp", "FILE*")),
        );
        self.insert(
            FunctionSig::new(
                "exit",
                lib,
                CRuntime.clone(),
                "void",
                "Terminate process with status code",
            )
            .arg(ArgInfo::new_in("status", "int")),
        );
        self.insert(FunctionSig::new(
            "abort",
            lib,
            CRuntime.clone(),
            "void",
            "Abort process with abnormal termination",
        ));
        self.insert(
            FunctionSig::new(
                "getenv",
                lib,
                CRuntime.clone(),
                "char*",
                "Get environment variable value",
            )
            .arg(ArgInfo::new_in("name", "const char*")),
        );
        self.insert(
            FunctionSig::new(
                "system",
                lib,
                CRuntime.clone(),
                "int",
                "Execute shell command",
            )
            .arg(ArgInfo::new_in("cmd", "const char*"))
            .dangerous()
            .note("Command injection risk"),
        );
    }

    fn populate_winapi_process(&mut self) {
        use SigCategory::WinApi;
        let lib = "kernel32.dll";

        self.insert(
            FunctionSig::new(
                "CreateProcessA",
                lib,
                WinApi.clone(),
                "BOOL",
                "Create a new process",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("lpApp", "LPCSTR"))
            .arg(ArgInfo::new_in("lpCmd", "LPSTR"))
            .arg(ArgInfo::new_in("lpProc", "LPSECURITY_ATTRIBUTES"))
            .arg(ArgInfo::new_in("lpThread", "LPSECURITY_ATTRIBUTES"))
            .arg(ArgInfo::new_in("bInheritHandles", "BOOL"))
            .arg(ArgInfo::new_in("dwFlags", "DWORD"))
            .arg(ArgInfo::new_in("lpEnv", "LPVOID"))
            .arg(ArgInfo::new_in("lpDir", "LPCSTR"))
            .arg(ArgInfo::new_in("lpStartupInfo", "LPSTARTUPINFOA"))
            .arg(ArgInfo::new_out("lpProcInfo", "LPPROCESS_INFORMATION")),
        );
        self.insert(
            FunctionSig::new(
                "CreateProcessW",
                lib,
                WinApi.clone(),
                "BOOL",
                "Create a new process (wide char)",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "OpenProcess",
                lib,
                WinApi.clone(),
                "HANDLE",
                "Open handle to existing process",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("dwAccess", "DWORD"))
            .arg(ArgInfo::new_in("bInherit", "BOOL"))
            .arg(ArgInfo::new_in("dwPid", "DWORD")),
        );
        self.insert(
            FunctionSig::new(
                "TerminateProcess",
                lib,
                WinApi.clone(),
                "BOOL",
                "Terminate process",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hProcess", "HANDLE"))
            .arg(ArgInfo::new_in("uExitCode", "UINT")),
        );
        self.insert(
            FunctionSig::new(
                "GetCurrentProcess",
                lib,
                WinApi.clone(),
                "HANDLE",
                "Get pseudo-handle to current process",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "GetCurrentProcessId",
                lib,
                WinApi.clone(),
                "DWORD",
                "Get PID of current process",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "ExitProcess",
                lib,
                WinApi.clone(),
                "void",
                "Exit current process with code",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("uExitCode", "UINT")),
        );
        self.insert(
            FunctionSig::new(
                "GetExitCodeProcess",
                lib,
                WinApi.clone(),
                "BOOL",
                "Get exit code of terminated process",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hProcess", "HANDLE"))
            .arg(ArgInfo::new_out("lpExitCode", "LPDWORD")),
        );
        self.insert(
            FunctionSig::new(
                "WaitForSingleObject",
                lib,
                WinApi.clone(),
                "DWORD",
                "Wait for kernel object to be signaled",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hHandle", "HANDLE"))
            .arg(ArgInfo::new_in("dwMilliseconds", "DWORD")),
        );
        self.insert(
            FunctionSig::new(
                "CloseHandle",
                lib,
                WinApi.clone(),
                "BOOL",
                "Close open kernel object handle",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hObject", "HANDLE")),
        );
        self.insert(
            FunctionSig::new(
                "LoadLibraryA",
                lib,
                WinApi.clone(),
                "HMODULE",
                "Load DLL into process address space",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("lpFileName", "LPCSTR")),
        );
        self.insert(
            FunctionSig::new(
                "LoadLibraryW",
                lib,
                WinApi.clone(),
                "HMODULE",
                "Load DLL into process address space (wide)",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("lpFileName", "LPCWSTR")),
        );
        self.insert(
            FunctionSig::new(
                "GetProcAddress",
                lib,
                WinApi.clone(),
                "FARPROC",
                "Get address of exported DLL function",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hModule", "HMODULE"))
            .arg(ArgInfo::new_in("lpProcName", "LPCSTR")),
        );
        self.insert(
            FunctionSig::new(
                "FreeLibrary",
                lib,
                WinApi.clone(),
                "BOOL",
                "Unload DLL from process",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hModule", "HMODULE")),
        );
        self.insert(
            FunctionSig::new(
                "GetModuleHandleA",
                lib,
                WinApi.clone(),
                "HMODULE",
                "Get handle of already-loaded module",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("lpModuleName", "LPCSTR")),
        );
    }

    fn populate_winapi_memory(&mut self) {
        use SigCategory::Memory;
        let lib = "kernel32.dll";

        self.insert(
            FunctionSig::new(
                "VirtualAlloc",
                lib,
                Memory.clone(),
                "LPVOID",
                "Allocate virtual memory in process",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("lpAddress", "LPVOID"))
            .arg(ArgInfo::new_in("dwSize", "SIZE_T"))
            .arg(ArgInfo::new_in("flAllocationType", "DWORD"))
            .arg(ArgInfo::new_in("flProtect", "DWORD")),
        );
        self.insert(
            FunctionSig::new(
                "VirtualAllocEx",
                lib,
                Memory.clone(),
                "LPVOID",
                "Allocate virtual memory in other process",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hProcess", "HANDLE"))
            .arg(ArgInfo::new_in("lpAddress", "LPVOID"))
            .arg(ArgInfo::new_in("dwSize", "SIZE_T"))
            .arg(ArgInfo::new_in("flAllocationType", "DWORD"))
            .arg(ArgInfo::new_in("flProtect", "DWORD"))
            .note("Common in process injection"),
        );
        self.insert(
            FunctionSig::new(
                "VirtualFree",
                lib,
                Memory.clone(),
                "BOOL",
                "Release or decommit virtual memory",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("lpAddress", "LPVOID"))
            .arg(ArgInfo::new_in("dwSize", "SIZE_T"))
            .arg(ArgInfo::new_in("dwFreeType", "DWORD")),
        );
        self.insert(
            FunctionSig::new(
                "VirtualProtect",
                lib,
                Memory.clone(),
                "BOOL",
                "Change memory page protections",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("lpAddress", "LPVOID"))
            .arg(ArgInfo::new_in("dwSize", "SIZE_T"))
            .arg(ArgInfo::new_in("flNewProtect", "DWORD"))
            .arg(ArgInfo::new_out("lpflOldProtect", "PDWORD")),
        );
        self.insert(
            FunctionSig::new(
                "VirtualProtectEx",
                lib,
                Memory.clone(),
                "BOOL",
                "Change memory page protections in other process",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "VirtualQuery",
                lib,
                Memory.clone(),
                "SIZE_T",
                "Query virtual memory region info",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("lpAddress", "LPCVOID"))
            .arg(ArgInfo::new_out("lpBuffer", "PMEMORY_BASIC_INFORMATION"))
            .arg(ArgInfo::new_in("dwLength", "SIZE_T")),
        );
        self.insert(
            FunctionSig::new(
                "ReadProcessMemory",
                lib,
                Memory.clone(),
                "BOOL",
                "Read memory from another process",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hProcess", "HANDLE"))
            .arg(ArgInfo::new_in("lpBase", "LPCVOID"))
            .arg(ArgInfo::new_out("lpBuffer", "LPVOID"))
            .arg(ArgInfo::new_in("nSize", "SIZE_T"))
            .arg(ArgInfo::new_out("lpRead", "SIZE_T*")),
        );
        self.insert(
            FunctionSig::new(
                "WriteProcessMemory",
                lib,
                Memory.clone(),
                "BOOL",
                "Write memory in another process",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hProcess", "HANDLE"))
            .arg(ArgInfo::new_in("lpBase", "LPVOID"))
            .arg(ArgInfo::new_in("lpBuf", "LPCVOID"))
            .arg(ArgInfo::new_in("nSize", "SIZE_T"))
            .arg(ArgInfo::new_out("lpWritten", "SIZE_T*"))
            .note("Common in process injection / patching"),
        );
        self.insert(
            FunctionSig::new(
                "HeapAlloc",
                lib,
                Memory.clone(),
                "LPVOID",
                "Allocate memory from heap",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hHeap", "HANDLE"))
            .arg(ArgInfo::new_in("dwFlags", "DWORD"))
            .arg(ArgInfo::new_in("dwBytes", "SIZE_T")),
        );
        self.insert(
            FunctionSig::new(
                "HeapFree",
                lib,
                Memory.clone(),
                "BOOL",
                "Free heap-allocated memory",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hHeap", "HANDLE"))
            .arg(ArgInfo::new_in("dwFlags", "DWORD"))
            .arg(ArgInfo::new_in("lpMem", "LPVOID")),
        );
        self.insert(
            FunctionSig::new(
                "GlobalAlloc",
                lib,
                Memory.clone(),
                "HGLOBAL",
                "Allocate from global heap (legacy)",
            )
            .with_conv(CallingConv::Stdcall)
            .deprecated(),
        );
        self.insert(
            FunctionSig::new(
                "LocalAlloc",
                lib,
                Memory.clone(),
                "HLOCAL",
                "Allocate from local heap (legacy)",
            )
            .with_conv(CallingConv::Stdcall)
            .deprecated(),
        );
    }

    fn populate_winapi_file(&mut self) {
        use SigCategory::FileSystem;
        let lib = "kernel32.dll";

        self.insert(
            FunctionSig::new(
                "CreateFileA",
                lib,
                FileSystem.clone(),
                "HANDLE",
                "Create or open file/device",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("lpFileName", "LPCSTR"))
            .arg(ArgInfo::new_in("dwAccess", "DWORD"))
            .arg(ArgInfo::new_in("dwShare", "DWORD"))
            .arg(ArgInfo::new_in("lpSA", "LPSECURITY_ATTRIBUTES"))
            .arg(ArgInfo::new_in("dwCreation", "DWORD"))
            .arg(ArgInfo::new_in("dwFlags", "DWORD"))
            .arg(ArgInfo::new_in("hTemplate", "HANDLE")),
        );
        self.insert(
            FunctionSig::new(
                "CreateFileW",
                lib,
                FileSystem.clone(),
                "HANDLE",
                "Create or open file/device (wide char)",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "ReadFile",
                lib,
                FileSystem.clone(),
                "BOOL",
                "Read data from file or device",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hFile", "HANDLE"))
            .arg(ArgInfo::new_out("lpBuffer", "LPVOID"))
            .arg(ArgInfo::new_in("nBytesToRead", "DWORD"))
            .arg(ArgInfo::new_out("lpBytesRead", "LPDWORD"))
            .arg(ArgInfo::new_in("lpOverlapped", "LPOVERLAPPED")),
        );
        self.insert(
            FunctionSig::new(
                "WriteFile",
                lib,
                FileSystem.clone(),
                "BOOL",
                "Write data to file or device",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hFile", "HANDLE"))
            .arg(ArgInfo::new_in("lpBuffer", "LPCVOID"))
            .arg(ArgInfo::new_in("nBytesToWrite", "DWORD"))
            .arg(ArgInfo::new_out("lpBytesWritten", "LPDWORD"))
            .arg(ArgInfo::new_in("lpOverlapped", "LPOVERLAPPED")),
        );
        self.insert(
            FunctionSig::new(
                "DeleteFileA",
                lib,
                FileSystem.clone(),
                "BOOL",
                "Delete file",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("lpFileName", "LPCSTR")),
        );
        self.insert(
            FunctionSig::new(
                "CopyFileA",
                lib,
                FileSystem.clone(),
                "BOOL",
                "Copy file to new location",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("lpSrc", "LPCSTR"))
            .arg(ArgInfo::new_in("lpDst", "LPCSTR"))
            .arg(ArgInfo::new_in("bFail", "BOOL")),
        );
        self.insert(
            FunctionSig::new(
                "MoveFileA",
                lib,
                FileSystem.clone(),
                "BOOL",
                "Move or rename file",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("lpSrc", "LPCSTR"))
            .arg(ArgInfo::new_in("lpDst", "LPCSTR")),
        );
        self.insert(
            FunctionSig::new(
                "GetFileSize",
                lib,
                FileSystem.clone(),
                "DWORD",
                "Get size of open file",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hFile", "HANDLE"))
            .arg(ArgInfo::new_out("lpHigh", "LPDWORD")),
        );
        self.insert(
            FunctionSig::new(
                "SetFilePointer",
                lib,
                FileSystem.clone(),
                "DWORD",
                "Move file pointer",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hFile", "HANDLE"))
            .arg(ArgInfo::new_in("lDistance", "LONG"))
            .arg(ArgInfo::new_in("lpDistHigh", "PLONG"))
            .arg(ArgInfo::new_in("dwMethod", "DWORD")),
        );
        self.insert(
            FunctionSig::new(
                "FindFirstFileA",
                lib,
                FileSystem.clone(),
                "HANDLE",
                "Start file enumeration in directory",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("lpFileName", "LPCSTR"))
            .arg(ArgInfo::new_out("lpFindData", "LPWIN32_FIND_DATAA")),
        );
        self.insert(
            FunctionSig::new(
                "FindNextFileA",
                lib,
                FileSystem.clone(),
                "BOOL",
                "Continue file enumeration",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hFind", "HANDLE"))
            .arg(ArgInfo::new_out("lpFindData", "LPWIN32_FIND_DATAA")),
        );
        self.insert(
            FunctionSig::new(
                "FindClose",
                lib,
                FileSystem.clone(),
                "BOOL",
                "Close file enumeration handle",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hFind", "HANDLE")),
        );
        self.insert(
            FunctionSig::new(
                "CreateDirectoryA",
                lib,
                FileSystem.clone(),
                "BOOL",
                "Create directory",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("lpPath", "LPCSTR"))
            .arg(ArgInfo::new_in("lpSA", "LPSECURITY_ATTRIBUTES")),
        );
        self.insert(
            FunctionSig::new(
                "GetTempPathA",
                lib,
                FileSystem.clone(),
                "DWORD",
                "Get path to system temp directory",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("nBuf", "DWORD"))
            .arg(ArgInfo::new_out("lpBuf", "LPSTR")),
        );
        self.insert(
            FunctionSig::new(
                "GetTempFileNameA",
                lib,
                FileSystem.clone(),
                "UINT",
                "Create unique temp file name",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("lpPath", "LPCSTR"))
            .arg(ArgInfo::new_in("lpPrefix", "LPCSTR"))
            .arg(ArgInfo::new_in("uUnique", "UINT"))
            .arg(ArgInfo::new_out("lpTempFile", "LPSTR")),
        );
    }

    fn populate_winapi_registry(&mut self) {
        use SigCategory::Registry;
        let lib = "advapi32.dll";

        self.insert(
            FunctionSig::new(
                "RegOpenKeyExA",
                lib,
                Registry.clone(),
                "LONG",
                "Open registry key handle",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hKey", "HKEY"))
            .arg(ArgInfo::new_in("lpSubKey", "LPCSTR"))
            .arg(ArgInfo::new_in("ulOptions", "DWORD"))
            .arg(ArgInfo::new_in("samDesired", "REGSAM"))
            .arg(ArgInfo::new_out("phkResult", "PHKEY")),
        );
        self.insert(
            FunctionSig::new(
                "RegCreateKeyExA",
                lib,
                Registry.clone(),
                "LONG",
                "Create or open registry key",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hKey", "HKEY"))
            .arg(ArgInfo::new_in("lpSubKey", "LPCSTR"))
            .arg(ArgInfo::new_in("Reserved", "DWORD"))
            .arg(ArgInfo::new_in("lpClass", "LPSTR"))
            .arg(ArgInfo::new_in("dwOptions", "DWORD"))
            .arg(ArgInfo::new_in("samDesired", "REGSAM"))
            .arg(ArgInfo::new_in("lpSA", "LPSECURITY_ATTRIBUTES"))
            .arg(ArgInfo::new_out("phkResult", "PHKEY"))
            .arg(ArgInfo::new_out("lpdwDisposition", "LPDWORD")),
        );
        self.insert(
            FunctionSig::new(
                "RegSetValueExA",
                lib,
                Registry.clone(),
                "LONG",
                "Set registry value data",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hKey", "HKEY"))
            .arg(ArgInfo::new_in("lpValueName", "LPCSTR"))
            .arg(ArgInfo::new_in("Reserved", "DWORD"))
            .arg(ArgInfo::new_in("dwType", "DWORD"))
            .arg(ArgInfo::new_in("lpData", "const BYTE*"))
            .arg(ArgInfo::new_in("cbData", "DWORD")),
        );
        self.insert(
            FunctionSig::new(
                "RegQueryValueExA",
                lib,
                Registry.clone(),
                "LONG",
                "Query registry value data",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hKey", "HKEY"))
            .arg(ArgInfo::new_in("lpValueName", "LPCSTR"))
            .arg(ArgInfo::new_in("lpReserved", "LPDWORD"))
            .arg(ArgInfo::new_out("lpType", "LPDWORD"))
            .arg(ArgInfo::new_out("lpData", "LPBYTE"))
            .arg(ArgInfo::new_in("lpcbData", "LPDWORD")),
        );
        self.insert(
            FunctionSig::new(
                "RegDeleteKeyA",
                lib,
                Registry.clone(),
                "LONG",
                "Delete registry subkey",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hKey", "HKEY"))
            .arg(ArgInfo::new_in("lpSubKey", "LPCSTR")),
        );
        self.insert(
            FunctionSig::new(
                "RegDeleteValueA",
                lib,
                Registry.clone(),
                "LONG",
                "Delete registry value",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hKey", "HKEY"))
            .arg(ArgInfo::new_in("lpValueName", "LPCSTR")),
        );
        self.insert(
            FunctionSig::new(
                "RegCloseKey",
                lib,
                Registry.clone(),
                "LONG",
                "Close registry key handle",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hKey", "HKEY")),
        );
        self.insert(
            FunctionSig::new(
                "RegEnumKeyExA",
                lib,
                Registry.clone(),
                "LONG",
                "Enumerate registry subkeys",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "RegEnumValueA",
                lib,
                Registry.clone(),
                "LONG",
                "Enumerate registry values",
            )
            .with_conv(CallingConv::Stdcall),
        );
    }

    fn populate_winapi_network(&mut self) {
        self.populate_winapi_socket_basics();
        self.populate_winapi_socket_io_and_http();
    }

    fn populate_winapi_socket_basics(&mut self) {
        use SigCategory::Network;
        let lib = "ws2_32.dll";

        self.insert(
            FunctionSig::new(
                "WSAStartup",
                lib,
                Network.clone(),
                "int",
                "Initialize Winsock library",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("wVersionRequired", "WORD"))
            .arg(ArgInfo::new_out("lpWSAData", "LPWSADATA")),
        );
        self.insert(
            FunctionSig::new(
                "WSACleanup",
                lib,
                Network.clone(),
                "int",
                "Deinitialize Winsock library",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "socket",
                lib,
                Network.clone(),
                "SOCKET",
                "Create network socket",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("af", "int"))
            .arg(ArgInfo::new_in("type", "int"))
            .arg(ArgInfo::new_in("protocol", "int")),
        );
        self.insert(
            FunctionSig::new(
                "connect",
                lib,
                Network.clone(),
                "int",
                "Connect socket to remote address",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("s", "SOCKET"))
            .arg(ArgInfo::new_in("name", "const sockaddr*"))
            .arg(ArgInfo::new_in("namelen", "int")),
        );
        self.insert(
            FunctionSig::new(
                "bind",
                lib,
                Network.clone(),
                "int",
                "Bind socket to local address",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("s", "SOCKET"))
            .arg(ArgInfo::new_in("name", "const sockaddr*"))
            .arg(ArgInfo::new_in("namelen", "int")),
        );
        self.insert(
            FunctionSig::new(
                "listen",
                lib,
                Network.clone(),
                "int",
                "Set socket to listen mode",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("s", "SOCKET"))
            .arg(ArgInfo::new_in("backlog", "int")),
        );
        self.insert(
            FunctionSig::new(
                "accept",
                lib,
                Network.clone(),
                "SOCKET",
                "Accept incoming connection",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("s", "SOCKET"))
            .arg(ArgInfo::new_out("addr", "sockaddr*"))
            .arg(ArgInfo::new_in("addrlen", "int*")),
        );
    }

    fn populate_winapi_socket_io_and_http(&mut self) {
        use SigCategory::Network;
        let lib = "ws2_32.dll";

        self.insert(
            FunctionSig::new("send", lib, Network.clone(), "int", "Send data over socket")
                .with_conv(CallingConv::Stdcall)
                .arg(ArgInfo::new_in("s", "SOCKET"))
                .arg(ArgInfo::new_in("buf", "const char*"))
                .arg(ArgInfo::new_in("len", "int"))
                .arg(ArgInfo::new_in("flags", "int")),
        );
        self.insert(
            FunctionSig::new(
                "recv",
                lib,
                Network.clone(),
                "int",
                "Receive data from socket",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("s", "SOCKET"))
            .arg(ArgInfo::new_out("buf", "char*"))
            .arg(ArgInfo::new_in("len", "int"))
            .arg(ArgInfo::new_in("flags", "int")),
        );
        self.insert(
            FunctionSig::new("closesocket", lib, Network.clone(), "int", "Close socket")
                .with_conv(CallingConv::Stdcall)
                .arg(ArgInfo::new_in("s", "SOCKET")),
        );
        self.insert(
            FunctionSig::new(
                "gethostbyname",
                lib,
                Network.clone(),
                "hostent*",
                "Resolve hostname to IP (deprecated)",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("name", "const char*"))
            .deprecated()
            .note("Use getaddrinfo instead"),
        );
        self.insert(
            FunctionSig::new(
                "getaddrinfo",
                lib,
                Network.clone(),
                "int",
                "Resolve hostname/service to address",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("nodename", "PCSTR"))
            .arg(ArgInfo::new_in("servname", "PCSTR"))
            .arg(ArgInfo::new_in("hints", "const addrinfo*"))
            .arg(ArgInfo::new_out("res", "addrinfo**")),
        );
        self.insert(
            FunctionSig::new(
                "inet_addr",
                lib,
                Network.clone(),
                "unsigned long",
                "Convert IPv4 dotted-decimal to network order",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("cp", "const char*")),
        );
        self.insert(
            FunctionSig::new(
                "htons",
                lib,
                Network.clone(),
                "u_short",
                "Host to network byte order (short)",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hostshort", "u_short")),
        );
        self.insert(
            FunctionSig::new(
                "htonl",
                lib,
                Network.clone(),
                "u_long",
                "Host to network byte order (long)",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hostlong", "u_long")),
        );

        // WinHTTP
        let whttp = "winhttp.dll";
        self.insert(
            FunctionSig::new(
                "WinHttpOpen",
                whttp,
                Network.clone(),
                "HINTERNET",
                "Open WinHTTP session handle",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "WinHttpConnect",
                whttp,
                Network.clone(),
                "HINTERNET",
                "Create WinHTTP connection",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "WinHttpOpenRequest",
                whttp,
                Network.clone(),
                "HINTERNET",
                "Create WinHTTP request handle",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "WinHttpSendRequest",
                whttp,
                Network.clone(),
                "BOOL",
                "Send HTTP request",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "WinHttpReceiveResponse",
                whttp,
                Network.clone(),
                "BOOL",
                "Receive HTTP response headers",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "WinHttpReadData",
                whttp,
                Network.clone(),
                "BOOL",
                "Read HTTP response body data",
            )
            .with_conv(CallingConv::Stdcall),
        );
    }

    fn populate_winapi_crypto(&mut self) {
        use SigCategory::Crypto;
        let lib = "advapi32.dll";

        self.insert(
            FunctionSig::new(
                "CryptAcquireContextA",
                lib,
                Crypto.clone(),
                "BOOL",
                "Acquire handle to crypto service provider",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_out("phProv", "HCRYPTPROV*"))
            .arg(ArgInfo::new_in("szContainer", "LPCSTR"))
            .arg(ArgInfo::new_in("szProvider", "LPCSTR"))
            .arg(ArgInfo::new_in("dwProvType", "DWORD"))
            .arg(ArgInfo::new_in("dwFlags", "DWORD")),
        );
        self.insert(
            FunctionSig::new(
                "CryptCreateHash",
                lib,
                Crypto.clone(),
                "BOOL",
                "Create hash object",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hProv", "HCRYPTPROV"))
            .arg(ArgInfo::new_in("Algid", "ALG_ID"))
            .arg(ArgInfo::new_in("hKey", "HCRYPTKEY"))
            .arg(ArgInfo::new_in("dwFlags", "DWORD"))
            .arg(ArgInfo::new_out("phHash", "HCRYPTHASH*")),
        );
        self.insert(
            FunctionSig::new(
                "CryptHashData",
                lib,
                Crypto.clone(),
                "BOOL",
                "Add data to hash object",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hHash", "HCRYPTHASH"))
            .arg(ArgInfo::new_in("pbData", "const BYTE*"))
            .arg(ArgInfo::new_in("dwDataLen", "DWORD"))
            .arg(ArgInfo::new_in("dwFlags", "DWORD")),
        );
        self.insert(
            FunctionSig::new(
                "CryptGetHashParam",
                lib,
                Crypto.clone(),
                "BOOL",
                "Retrieve hash value",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "CryptEncrypt",
                lib,
                Crypto.clone(),
                "BOOL",
                "Encrypt data with key",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hKey", "HCRYPTKEY"))
            .arg(ArgInfo::new_in("hHash", "HCRYPTHASH"))
            .arg(ArgInfo::new_in("Final", "BOOL"))
            .arg(ArgInfo::new_in("dwFlags", "DWORD"))
            .arg(ArgInfo::new_in("pbData", "BYTE*"))
            .arg(ArgInfo::new_in("pdwDataLen", "DWORD*"))
            .arg(ArgInfo::new_in("dwBufLen", "DWORD")),
        );
        self.insert(
            FunctionSig::new(
                "CryptDecrypt",
                lib,
                Crypto.clone(),
                "BOOL",
                "Decrypt data with key",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "CryptGenKey",
                lib,
                Crypto.clone(),
                "BOOL",
                "Generate cryptographic key",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hProv", "HCRYPTPROV"))
            .arg(ArgInfo::new_in("Algid", "ALG_ID"))
            .arg(ArgInfo::new_in("dwFlags", "DWORD"))
            .arg(ArgInfo::new_out("phKey", "HCRYPTKEY*")),
        );
        self.insert(
            FunctionSig::new(
                "CryptGenRandom",
                lib,
                Crypto.clone(),
                "BOOL",
                "Generate cryptographic random bytes",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hProv", "HCRYPTPROV"))
            .arg(ArgInfo::new_in("dwLen", "DWORD"))
            .arg(ArgInfo::new_out("pbBuffer", "BYTE*")),
        );
        self.insert(
            FunctionSig::new(
                "CryptImportKey",
                lib,
                Crypto.clone(),
                "BOOL",
                "Import key from BLOB",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "CryptExportKey",
                lib,
                Crypto.clone(),
                "BOOL",
                "Export key to BLOB",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "CryptDestroyKey",
                lib,
                Crypto.clone(),
                "BOOL",
                "Destroy crypto key handle",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hKey", "HCRYPTKEY")),
        );
        self.insert(
            FunctionSig::new(
                "CryptDestroyHash",
                lib,
                Crypto.clone(),
                "BOOL",
                "Destroy hash object handle",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hHash", "HCRYPTHASH")),
        );
        self.insert(
            FunctionSig::new(
                "CryptReleaseContext",
                lib,
                Crypto.clone(),
                "BOOL",
                "Release CSP handle",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hProv", "HCRYPTPROV"))
            .arg(ArgInfo::new_in("dwFlags", "DWORD")),
        );

        // BCrypt (newer API)
        let bclib = "bcrypt.dll";
        self.insert(
            FunctionSig::new(
                "BCryptOpenAlgorithmProvider",
                bclib,
                Crypto.clone(),
                "NTSTATUS",
                "Open BCrypt algorithm provider",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "BCryptCreateHash",
                bclib,
                Crypto.clone(),
                "NTSTATUS",
                "Create BCrypt hash object",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "BCryptHashData",
                bclib,
                Crypto.clone(),
                "NTSTATUS",
                "Add data to BCrypt hash",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "BCryptFinishHash",
                bclib,
                Crypto.clone(),
                "NTSTATUS",
                "Finalize BCrypt hash computation",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "BCryptEncrypt",
                bclib,
                Crypto.clone(),
                "NTSTATUS",
                "BCrypt symmetric encryption",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "BCryptDecrypt",
                bclib,
                Crypto.clone(),
                "NTSTATUS",
                "BCrypt symmetric decryption",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "BCryptGenerateSymmetricKey",
                bclib,
                Crypto.clone(),
                "NTSTATUS",
                "Generate BCrypt symmetric key",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "BCryptGenRandom",
                bclib,
                Crypto.clone(),
                "NTSTATUS",
                "Generate BCrypt random bytes",
            )
            .with_conv(CallingConv::Stdcall),
        );
    }

    fn populate_winapi_antidebug(&mut self) {
        use SigCategory::AntiDebug;
        let lib = "kernel32.dll";

        self.insert(
            FunctionSig::new(
                "IsDebuggerPresent",
                lib,
                AntiDebug.clone(),
                "BOOL",
                "Check if process is being debugged via PEB flag",
            )
            .with_conv(CallingConv::Stdcall)
            .note("Classic anti-debug technique — patch PEB.BeingDebugged to bypass"),
        );
        self.insert(
            FunctionSig::new(
                "CheckRemoteDebuggerPresent",
                lib,
                AntiDebug.clone(),
                "BOOL",
                "Check if remote debugger is attached",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hProcess", "HANDLE"))
            .arg(ArgInfo::new_out("pbDebuggerPresent", "PBOOL")),
        );
        self.insert(
            FunctionSig::new(
                "DebugActiveProcess",
                lib,
                AntiDebug.clone(),
                "BOOL",
                "Attach debugger to running process",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("dwProcessId", "DWORD")),
        );
        self.insert(
            FunctionSig::new(
                "OutputDebugStringA",
                lib,
                AntiDebug.clone(),
                "void",
                "Send string to attached debugger",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("lpOutputString", "LPCSTR")),
        );
        self.insert(
            FunctionSig::new(
                "GetTickCount",
                lib,
                AntiDebug.clone(),
                "DWORD",
                "Get milliseconds since boot — timing attack",
            )
            .with_conv(CallingConv::Stdcall)
            .note("Used in timing-based anti-debug"),
        );
        self.insert(
            FunctionSig::new(
                "QueryPerformanceCounter",
                lib,
                AntiDebug.clone(),
                "BOOL",
                "High-resolution timer — timing attack",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_out("lpPerformanceCount", "LARGE_INTEGER*"))
            .note("Used in high-precision timing anti-debug"),
        );
        self.insert(
            FunctionSig::new(
                "NtQueryInformationProcess",
                "ntdll.dll",
                AntiDebug.clone(),
                "NTSTATUS",
                "Query process info — NtGlobalFlag / debug port check",
            )
            .with_conv(CallingConv::Stdcall)
            .note("ProcessDebugPort (7) and NtGlobalFlag (0x22) anti-debug checks"),
        );
        self.insert(
            FunctionSig::new(
                "ZwQueryInformationProcess",
                "ntdll.dll",
                AntiDebug.clone(),
                "NTSTATUS",
                "ZwQueryInformationProcess — alias for Nt variant",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "SetUnhandledExceptionFilter",
                lib,
                AntiDebug.clone(),
                "LPTOP_LEVEL_EXCEPTION_FILTER",
                "Set top-level exception handler",
            )
            .with_conv(CallingConv::Stdcall)
            .note("If debugger present exception won't be caught by handler"),
        );
        self.insert(
            FunctionSig::new(
                "FindWindowA",
                "user32.dll",
                AntiDebug.clone(),
                "HWND",
                "Find window by class/title — debugger window detection",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("lpClassName", "LPCSTR"))
            .arg(ArgInfo::new_in("lpWindowName", "LPCSTR"))
            .note("Often used to detect debugger GUIs (OllyDbg / x64dbg) by window class"),
        );
        self.insert(
            FunctionSig::new(
                "NtSetInformationThread",
                "ntdll.dll",
                AntiDebug.clone(),
                "NTSTATUS",
                "Set thread information — ThreadHideFromDebugger anti-debug",
            )
            .with_conv(CallingConv::Stdcall)
            .note("ThreadHideFromDebugger (0x11) detaches the thread from the debugger"),
        );
        self.insert(
            FunctionSig::new(
                "BlockInput",
                "user32.dll",
                AntiDebug.clone(),
                "BOOL",
                "Block keyboard / mouse input — used to stall debugger UI",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("fBlockIt", "BOOL")),
        );
        self.insert(
            FunctionSig::new(
                "SwitchDesktop",
                "user32.dll",
                AntiDebug.clone(),
                "BOOL",
                "Switch input desktop — debugger isolation trick",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hDesktop", "HDESK")),
        );
    }

    fn populate_winapi_injection(&mut self) {
        use SigCategory::ProcessInjection;
        let kern = "kernel32.dll";
        let ntdll = "ntdll.dll";

        self.insert(
            FunctionSig::new(
                "VirtualAllocEx",
                kern,
                ProcessInjection.clone(),
                "LPVOID",
                "Allocate memory in a remote process — classic injection primitive",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hProcess", "HANDLE"))
            .arg(ArgInfo::new_in("lpAddress", "LPVOID"))
            .arg(ArgInfo::new_in("dwSize", "SIZE_T"))
            .arg(ArgInfo::new_in("flAllocationType", "DWORD"))
            .arg(ArgInfo::new_in("flProtect", "DWORD"))
            .note("Often paired with WriteProcessMemory + CreateRemoteThread"),
        );
        self.insert(
            FunctionSig::new(
                "WriteProcessMemory",
                kern,
                ProcessInjection.clone(),
                "BOOL",
                "Write bytes into a remote process — shellcode delivery",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hProcess", "HANDLE"))
            .arg(ArgInfo::new_in("lpBaseAddress", "LPVOID"))
            .arg(ArgInfo::new_in("lpBuffer", "LPCVOID"))
            .arg(ArgInfo::new_in("nSize", "SIZE_T"))
            .arg(ArgInfo::new_out("lpNumberOfBytesWritten", "SIZE_T*")),
        );
        self.insert(
            FunctionSig::new(
                "CreateRemoteThread",
                kern,
                ProcessInjection.clone(),
                "HANDLE",
                "Spawn a thread in a remote process at an arbitrary address",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hProcess", "HANDLE"))
            .arg(ArgInfo::new_in(
                "lpThreadAttributes",
                "LPSECURITY_ATTRIBUTES",
            ))
            .arg(ArgInfo::new_in("dwStackSize", "SIZE_T"))
            .arg(ArgInfo::new_in("lpStartAddress", "LPTHREAD_START_ROUTINE"))
            .arg(ArgInfo::new_in("lpParameter", "LPVOID"))
            .arg(ArgInfo::new_in("dwCreationFlags", "DWORD"))
            .arg(ArgInfo::new_out("lpThreadId", "LPDWORD")),
        );
        self.insert(
            FunctionSig::new(
                "NtCreateThreadEx",
                ntdll,
                ProcessInjection.clone(),
                "NTSTATUS",
                "Lower-level remote thread creation — bypasses CreateRemoteThread hooks",
            )
            .with_conv(CallingConv::Stdcall),
        );
        self.insert(
            FunctionSig::new(
                "QueueUserAPC",
                kern,
                ProcessInjection.clone(),
                "DWORD",
                "Queue an asynchronous procedure call — APC injection",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("pfnAPC", "PAPCFUNC"))
            .arg(ArgInfo::new_in("hThread", "HANDLE"))
            .arg(ArgInfo::new_in("dwData", "ULONG_PTR"))
            .note("Triggered when the target thread enters an alertable wait"),
        );
        self.insert(
            FunctionSig::new(
                "SetWindowsHookExA",
                "user32.dll",
                ProcessInjection.clone(),
                "HHOOK",
                "Install a hook procedure into another process via SetWindowsHook",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("idHook", "int"))
            .arg(ArgInfo::new_in("lpfn", "HOOKPROC"))
            .arg(ArgInfo::new_in("hmod", "HINSTANCE"))
            .arg(ArgInfo::new_in("dwThreadId", "DWORD")),
        );
        self.insert(
            FunctionSig::new(
                "LoadLibraryA",
                kern,
                ProcessInjection.clone(),
                "HMODULE",
                "Load a DLL — used by DLL-injection via CreateRemoteThread(LoadLibraryA)",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("lpLibFileName", "LPCSTR")),
        );
    }

    fn populate_winapi_thread(&mut self) {
        use SigCategory::Threading;
        let lib = "kernel32.dll";

        self.insert(
            FunctionSig::new(
                "CreateThread",
                lib,
                Threading.clone(),
                "HANDLE",
                "Create a new thread in the current process",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in(
                "lpThreadAttributes",
                "LPSECURITY_ATTRIBUTES",
            ))
            .arg(ArgInfo::new_in("dwStackSize", "SIZE_T"))
            .arg(ArgInfo::new_in("lpStartAddress", "LPTHREAD_START_ROUTINE"))
            .arg(ArgInfo::new_in("lpParameter", "LPVOID"))
            .arg(ArgInfo::new_in("dwCreationFlags", "DWORD"))
            .arg(ArgInfo::new_out("lpThreadId", "LPDWORD")),
        );
        self.insert(
            FunctionSig::new(
                "ExitThread",
                lib,
                Threading.clone(),
                "void",
                "Terminate the current thread with an exit code",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("dwExitCode", "DWORD")),
        );
        self.insert(
            FunctionSig::new(
                "WaitForSingleObject",
                lib,
                Threading.clone(),
                "DWORD",
                "Wait for a kernel object (thread/event/mutex) to be signaled",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hHandle", "HANDLE"))
            .arg(ArgInfo::new_in("dwMilliseconds", "DWORD")),
        );
        self.insert(
            FunctionSig::new(
                "WaitForMultipleObjects",
                lib,
                Threading.clone(),
                "DWORD",
                "Wait for one or all of several kernel objects to be signaled",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("nCount", "DWORD"))
            .arg(ArgInfo::new_in("lpHandles", "const HANDLE*"))
            .arg(ArgInfo::new_in("bWaitAll", "BOOL"))
            .arg(ArgInfo::new_in("dwMilliseconds", "DWORD")),
        );
        self.insert(
            FunctionSig::new(
                "Sleep",
                lib,
                Threading.clone(),
                "void",
                "Suspend the current thread for at least N ms",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("dwMilliseconds", "DWORD")),
        );
        self.insert(
            FunctionSig::new(
                "CreateMutexA",
                lib,
                Threading.clone(),
                "HANDLE",
                "Create or open a named mutex object",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in(
                "lpMutexAttributes",
                "LPSECURITY_ATTRIBUTES",
            ))
            .arg(ArgInfo::new_in("bInitialOwner", "BOOL"))
            .arg(ArgInfo::new_in("lpName", "LPCSTR")),
        );
        self.insert(
            FunctionSig::new(
                "ReleaseMutex",
                lib,
                Threading.clone(),
                "BOOL",
                "Release ownership of a mutex object",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("hMutex", "HANDLE")),
        );
        self.insert(
            FunctionSig::new(
                "CreateEventA",
                lib,
                Threading.clone(),
                "HANDLE",
                "Create a named or unnamed event synchronization object",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in(
                "lpEventAttributes",
                "LPSECURITY_ATTRIBUTES",
            ))
            .arg(ArgInfo::new_in("bManualReset", "BOOL"))
            .arg(ArgInfo::new_in("bInitialState", "BOOL"))
            .arg(ArgInfo::new_in("lpName", "LPCSTR")),
        );
        self.insert(
            FunctionSig::new(
                "EnterCriticalSection",
                lib,
                Threading.clone(),
                "void",
                "Acquire a process-local critical section",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("lpCriticalSection", "LPCRITICAL_SECTION")),
        );
        self.insert(
            FunctionSig::new(
                "LeaveCriticalSection",
                lib,
                Threading.clone(),
                "void",
                "Release a process-local critical section",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("lpCriticalSection", "LPCRITICAL_SECTION")),
        );
    }

    fn populate_posix(&mut self) {
        use SigCategory::PosixApi;
        let lib = "libc.so.6";

        self.insert(
            FunctionSig::new(
                "open",
                lib,
                PosixApi.clone(),
                "int",
                "Open a file descriptor on a path",
            )
            .arg(ArgInfo::new_in("pathname", "const char*"))
            .arg(ArgInfo::new_in("flags", "int"))
            .arg(ArgInfo::new_in("mode", "mode_t")),
        );
        self.insert(
            FunctionSig::new(
                "close",
                lib,
                PosixApi.clone(),
                "int",
                "Close a file descriptor",
            )
            .arg(ArgInfo::new_in("fd", "int")),
        );
        self.insert(
            FunctionSig::new(
                "read",
                lib,
                PosixApi.clone(),
                "ssize_t",
                "Read bytes from a file descriptor",
            )
            .arg(ArgInfo::new_in("fd", "int"))
            .arg(ArgInfo::new_out("buf", "void*"))
            .arg(ArgInfo::new_in("count", "size_t")),
        );
        self.insert(
            FunctionSig::new(
                "write",
                lib,
                PosixApi.clone(),
                "ssize_t",
                "Write bytes to a file descriptor",
            )
            .arg(ArgInfo::new_in("fd", "int"))
            .arg(ArgInfo::new_in("buf", "const void*"))
            .arg(ArgInfo::new_in("count", "size_t")),
        );
        self.insert(
            FunctionSig::new(
                "mmap",
                lib,
                PosixApi.clone(),
                "void*",
                "Map files or devices into memory",
            )
            .arg(ArgInfo::new_in("addr", "void*"))
            .arg(ArgInfo::new_in("length", "size_t"))
            .arg(ArgInfo::new_in("prot", "int"))
            .arg(ArgInfo::new_in("flags", "int"))
            .arg(ArgInfo::new_in("fd", "int"))
            .arg(ArgInfo::new_in("offset", "off_t")),
        );
        self.insert(
            FunctionSig::new(
                "munmap",
                lib,
                PosixApi.clone(),
                "int",
                "Unmap a previously mapped memory region",
            )
            .arg(ArgInfo::new_in("addr", "void*"))
            .arg(ArgInfo::new_in("length", "size_t")),
        );
        self.insert(
            FunctionSig::new(
                "fork",
                lib,
                PosixApi.clone(),
                "pid_t",
                "Create a child process by duplicating the parent",
            )
            .note("Returns 0 in child, child's pid in parent, -1 on error"),
        );
        self.insert(
            FunctionSig::new(
                "execve",
                lib,
                PosixApi.clone(),
                "int",
                "Replace the current process image with a new program",
            )
            .arg(ArgInfo::new_in("pathname", "const char*"))
            .arg(ArgInfo::new_in("argv", "char* const*"))
            .arg(ArgInfo::new_in("envp", "char* const*")),
        );
        self.insert(
            FunctionSig::new(
                "waitpid",
                lib,
                PosixApi.clone(),
                "pid_t",
                "Wait for state changes in a child process",
            )
            .arg(ArgInfo::new_in("pid", "pid_t"))
            .arg(ArgInfo::new_out("wstatus", "int*"))
            .arg(ArgInfo::new_in("options", "int")),
        );
        self.insert(
            FunctionSig::new(
                "ptrace",
                lib,
                PosixApi.clone(),
                "long",
                "Process tracing primitive — debugger backbone on Linux/macOS",
            )
            .arg(ArgInfo::new_in("request", "long"))
            .arg(ArgInfo::new_in("pid", "pid_t"))
            .arg(ArgInfo::new_in("addr", "void*"))
            .arg(ArgInfo::new_in("data", "void*"))
            .note("Also used as an anti-debug trick on Linux (PTRACE_TRACEME)"),
        );
        self.insert(
            FunctionSig::new(
                "dlopen",
                lib,
                PosixApi.clone(),
                "void*",
                "Load a shared object at runtime",
            )
            .arg(ArgInfo::new_in("filename", "const char*"))
            .arg(ArgInfo::new_in("flags", "int")),
        );
        self.insert(
            FunctionSig::new(
                "dlsym",
                lib,
                PosixApi.clone(),
                "void*",
                "Resolve a symbol from a dynamically loaded object",
            )
            .arg(ArgInfo::new_in("handle", "void*"))
            .arg(ArgInfo::new_in("symbol", "const char*")),
        );
    }

    fn populate_string(&mut self) {
        use SigCategory::String as StrCat;
        let lib = "msvcrt.dll";

        // Wide-string variants that complement the narrow ones in populate_c_runtime.
        self.insert(
            FunctionSig::new(
                "wcslen",
                lib,
                StrCat.clone(),
                "size_t",
                "Length of a null-terminated wide string",
            )
            .arg(ArgInfo::new_in("s", "const wchar_t*")),
        );
        self.insert(
            FunctionSig::new(
                "wcscpy",
                lib,
                StrCat.clone(),
                "wchar_t*",
                "Copy a wide string — no bounds check",
            )
            .arg(ArgInfo::new_out("dst", "wchar_t*"))
            .arg(ArgInfo::new_in("src", "const wchar_t*"))
            .dangerous()
            .note("Prefer wcsncpy / wcscpy_s"),
        );
        self.insert(
            FunctionSig::new(
                "wcscmp",
                lib,
                StrCat.clone(),
                "int",
                "Compare two wide strings lexicographically",
            )
            .arg(ArgInfo::new_in("a", "const wchar_t*"))
            .arg(ArgInfo::new_in("b", "const wchar_t*")),
        );
        self.insert(
            FunctionSig::new(
                "wcscat",
                lib,
                StrCat.clone(),
                "wchar_t*",
                "Append a wide string — no bounds check",
            )
            .arg(ArgInfo::new_out("dst", "wchar_t*"))
            .arg(ArgInfo::new_in("src", "const wchar_t*"))
            .dangerous(),
        );
        self.insert(
            FunctionSig::new(
                "MultiByteToWideChar",
                "kernel32.dll",
                StrCat.clone(),
                "int",
                "Convert narrow string to wide using a code page",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("CodePage", "UINT"))
            .arg(ArgInfo::new_in("dwFlags", "DWORD"))
            .arg(ArgInfo::new_in("lpMultiByteStr", "LPCSTR"))
            .arg(ArgInfo::new_in("cbMultiByte", "int"))
            .arg(ArgInfo::new_out("lpWideCharStr", "LPWSTR"))
            .arg(ArgInfo::new_in("cchWideChar", "int")),
        );
        self.insert(
            FunctionSig::new(
                "WideCharToMultiByte",
                "kernel32.dll",
                StrCat.clone(),
                "int",
                "Convert wide string to narrow using a code page",
            )
            .with_conv(CallingConv::Stdcall)
            .arg(ArgInfo::new_in("CodePage", "UINT"))
            .arg(ArgInfo::new_in("dwFlags", "DWORD"))
            .arg(ArgInfo::new_in("lpWideCharStr", "LPCWSTR"))
            .arg(ArgInfo::new_in("cchWideChar", "int"))
            .arg(ArgInfo::new_out("lpMultiByteStr", "LPSTR"))
            .arg(ArgInfo::new_in("cbMultiByte", "int"))
            .arg(ArgInfo::new_in("lpDefaultChar", "LPCSTR"))
            .arg(ArgInfo::new_out("lpUsedDefaultChar", "LPBOOL")),
        );
    }
}

#[doc(hidden)]
pub fn ensure_used_signature_db() {
    ensure_used_sig_categories();
    ensure_used_sig_calling_convs();
    ensure_used_sig_arg_and_function_sig();
}

#[doc(hidden)]
fn ensure_used_sig_categories() {
    // Touch every SigCategory variant via an exhaustive match.
    let cats = [
        SigCategory::CRuntime,
        SigCategory::WinApi,
        SigCategory::PosixApi,
        SigCategory::Crypto,
        SigCategory::Network,
        SigCategory::Compression,
        SigCategory::AntiDebug,
        SigCategory::ProcessInjection,
        SigCategory::FileSystem,
        SigCategory::Registry,
        SigCategory::Threading,
        SigCategory::Memory,
        SigCategory::String,
        SigCategory::Math,
        SigCategory::Graphics,
        SigCategory::Database,
        SigCategory::Xml,
        SigCategory::Json,
        SigCategory::Unknown,
    ];
    for c in &cats {
        let label: &'static str = c.label();
        let sens: bool = c.is_sensitive();
        match c {
            SigCategory::CRuntime
            | SigCategory::WinApi
            | SigCategory::PosixApi
            | SigCategory::Crypto
            | SigCategory::Network
            | SigCategory::Compression
            | SigCategory::AntiDebug
            | SigCategory::ProcessInjection
            | SigCategory::FileSystem
            | SigCategory::Registry
            | SigCategory::Threading
            | SigCategory::Memory
            | SigCategory::String
            | SigCategory::Math
            | SigCategory::Graphics
            | SigCategory::Database
            | SigCategory::Xml
            | SigCategory::Json
            | SigCategory::Unknown => {}
        }
        assert!(!label.is_empty());
        let _ = sens;
    }
}

#[doc(hidden)]
fn ensure_used_sig_calling_convs() {
    // Touch every ArgDir variant.
    for d in &[ArgDir::In, ArgDir::Out, ArgDir::InOut, ArgDir::Return] {
        match d {
            ArgDir::In | ArgDir::Out | ArgDir::InOut | ArgDir::Return => {}
        }
    }

    // Touch every CallingConv variant + label.
    let convs = [
        CallingConv::Cdecl,
        CallingConv::Stdcall,
        CallingConv::Fastcall,
        CallingConv::Thiscall,
        CallingConv::Win64,
        CallingConv::SysV,
        CallingConv::Unknown,
    ];
    for cc in &convs {
        let l: &'static str = cc.label();
        match cc {
            CallingConv::Cdecl
            | CallingConv::Stdcall
            | CallingConv::Fastcall
            | CallingConv::Thiscall
            | CallingConv::Win64
            | CallingConv::SysV
            | CallingConv::Unknown => {}
        }
        assert!(!l.is_empty());
    }
}

#[doc(hidden)]
fn ensure_used_sig_arg_and_function_sig() {
    // ArgInfo constructors + with_note.
    let ai_in = ArgInfo::new_in("p", "int");
    let ai_out = ArgInfo::new_out("q", "int*");
    let ai_note = ArgInfo::new_in("r", "char*").with_note("nullable");
    assert_eq!(ai_in.direction, ArgDir::In);
    assert_eq!(ai_out.direction, ArgDir::Out);
    assert!(ai_note.notes.is_some());

    // FunctionSig builder chain — touches new, with_conv, dangerous, deprecated, note, cve, mangled, arg, prototype, short_desc.
    let sig = FunctionSig::new(
        "touch_fn",
        "touch.dll",
        SigCategory::Unknown,
        "void",
        "synthetic entry for warning suppression",
    )
    .with_conv(CallingConv::Cdecl)
    .dangerous()
    .deprecated()
    .note("n")
    .cve("CVE-0000-0000")
    .mangled("_touch_fn")
    .arg(ArgInfo::new_in("a", "int"));
    let proto: String = sig.prototype();
    let short: String = sig.short_desc();
    assert!(!proto.is_empty());
    assert!(!short.is_empty());
    assert!(sig.is_dangerous);
    assert!(sig.is_deprecated);

    // SignatureDb: new() exercises all populate_* helpers, insert(), build_indices().
    let db = SignatureDb::new();
    let _ = db.lookup("malloc");
    let _ = db.lookup_fuzzy("alloc");
    let _ = db.by_library("kernel32.dll");
    let _ = db.by_category(&SigCategory::Memory);
    let _ = db.dangerous_functions();
    let _ = db.all();
    let _ = db.len();
    let _ = db.is_empty();
    let _ = db.libraries();
    let stats: DbStats = db.stats();
    let DbStats {
        total,
        dangerous,
        deprecated,
        libraries,
        categories,
    } = stats;
    assert!(total >= dangerous);
    assert!(total >= deprecated);
    let _ = (libraries, categories);
    let _dbg = format!("{stats:?}");
}
