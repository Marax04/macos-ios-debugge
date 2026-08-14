//! `library_stub` — Stub implementations of common library functions.
//!
//! Provides lightweight Rust stubs for frequently called libc/Win32 functions
//! (strlen, strcpy, memcpy, printf, `CreateFile`, `RegOpenKey`, …) so the emulator
//! can service these calls without undefined behaviour. Integrates with the
//! heap emulator for malloc/free and the virtual FS for file/registry access.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum StubError {
    #[error("function not stubbed: {0}")]
    NotStubbed(String),
    #[error("bad pointer: {0:#x}")]
    BadPointer(u64),
    #[error("virtual FS error: {0}")]
    VirtualFs(String),
    #[error("invalid argument: {0}")]
    InvalidArg(String),
}

// ─── Stub Call ────────────────────────────────────────────────────────────────

/// Arguments passed to a stub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StubArgs {
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
    /// Simulated memory for pointer dereferencing.
    pub mem: Vec<u8>,
    /// Base address of `mem` in the emulated address space.
    pub mem_base: u64,
}

impl StubArgs {
    #[must_use] 
    pub const fn new(arg0: u64, arg1: u64, arg2: u64) -> Self {
        Self { arg0, arg1, arg2, arg3: 0, arg4: 0, arg5: 0, mem: Vec::new(), mem_base: 0 }
    }

    /// Read a null-terminated C string from simulated memory.
    pub fn read_cstring(&self, ptr: u64, max_len: usize) -> Option<String> {
        let offset = usize::try_from(ptr.checked_sub(self.mem_base)?).ok()?;
        if offset >= self.mem.len() {
            return None;
        }
        let end = self.mem[offset..].iter().take(max_len).position(|&b| b == 0).unwrap_or(max_len);
        std::str::from_utf8(&self.mem[offset..offset + end]).ok().map(str::to_owned)
    }

    /// Read `count` bytes from simulated memory at `ptr`.
    #[must_use]
    pub fn read_bytes(&self, ptr: u64, count: usize) -> Option<&[u8]> {
        let offset = usize::try_from(ptr.checked_sub(self.mem_base)?).ok()?;
        let end = offset + count;
        if end > self.mem.len() {
            return None;
        }
        Some(&self.mem[offset..end])
    }

    /// Write bytes into simulated memory at `ptr`.
    pub fn write_bytes(&mut self, ptr: u64, data: &[u8]) -> bool {
        if let Some(offset) = ptr.checked_sub(self.mem_base).and_then(|o| usize::try_from(o).ok()) {
            let end = offset + data.len();
            if end <= self.mem.len() {
                self.mem[offset..end].copy_from_slice(data);
                return true;
            }
        }
        false
    }
}

/// Return value from a stub.
#[derive(Debug, Clone)]
pub struct StubReturn {
    pub rax: i64,
    pub side_effect: Option<SideEffect>,
}

impl StubReturn {
    #[must_use] 
    pub const fn ok(val: i64) -> Self {
        Self { rax: val, side_effect: None }
    }

    #[must_use] 
    pub const fn with_effect(val: i64, effect: SideEffect) -> Self {
        Self { rax: val, side_effect: Some(effect) }
    }

    #[must_use] 
    pub const fn null() -> Self {
        Self::ok(0)
    }

    #[must_use] 
    pub const fn minus_one() -> Self {
        Self::ok(-1)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SideEffect {
    MemWrite { ptr: u64, data: Vec<u8> },
    MemZero { ptr: u64, len: u64 },
    MemCopy { dst: u64, src: u64, len: u64 },
    LogOutput(String),
    FileOpened { handle: u64, path: String },
    FileClosed { handle: u64 },
    RegistryOpened { handle: u64, key: String },
}

// ─── Stub Log Entry ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StubLogEntry {
    pub id: u64,
    pub function: String,
    pub module: String,
    pub args_summary: String,
    pub return_value: i64,
    pub call_address: u64,
    pub timestamp: u64,
}

// ─── Virtual Registry ────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct VirtualRegistry {
    /// Map of key path → (`value_name` → data)
    keys: HashMap<String, HashMap<String, Vec<u8>>>,
    /// Open handle table: handle → key path
    handles: HashMap<u64, String>,
    next_handle: u64,
}

impl VirtualRegistry {
    #[must_use]
    pub fn new() -> Self {
        let mut vr = Self {
            next_handle: 0x1000_0000,
            ..Self::default()
        };
        // Pre-populate basic Windows registry keys
        vr.set_value(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName", b"Windows 10 Pro");
        vr.set_value(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentVersion", b"10.0");
        vr.set_value(r"HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName", "ComputerName", b"SANDBOX-PC");
        vr
    }

    pub fn set_value(&mut self, key: &str, value: &str, data: &[u8]) {
        self.keys
            .entry(key.to_owned())
            .or_default()
            .insert(value.to_owned(), data.to_vec());
    }

    pub fn open_key(&mut self, path: &str) -> Option<u64> {
        if !self.keys.contains_key(path) {
            // Create empty key
            self.keys.insert(path.to_owned(), HashMap::new());
        }
        let handle = self.next_handle;
        self.next_handle += 1;
        self.handles.insert(handle, path.to_owned());
        Some(handle)
    }

    pub fn close_key(&mut self, handle: u64) -> bool {
        self.handles.remove(&handle).is_some()
    }

    #[must_use] 
    pub fn query_value(&self, handle: u64, value_name: &str) -> Option<&[u8]> {
        let path = self.handles.get(&handle)?;
        self.keys.get(path)?.get(value_name).map(std::vec::Vec::as_slice)
    }

    pub fn set_value_by_handle(&mut self, handle: u64, value_name: &str, data: &[u8]) -> bool {
        if let Some(path) = self.handles.get(&handle).cloned() {
            self.keys.entry(path).or_default().insert(value_name.to_owned(), data.to_vec());
            true
        } else {
            false
        }
    }
}

// ─── Library Stub Engine ──────────────────────────────────────────────────────

/// Registry of stub implementations and call log.
pub struct LibraryStubEngine {
    pub log: Vec<StubLogEntry>,
    pub registry: VirtualRegistry,
    /// Simulated stdout output from printf/puts.
    pub stdout: String,
    /// Open file handles: handle → path
    file_handles: HashMap<u64, String>,
    next_handle: u64,
    next_event_id: u64,
    global_timestamp: u64,
}

impl std::fmt::Debug for LibraryStubEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LibraryStubEngine")
            .field("log_len", &self.log.len())
            .field("stdout_len", &self.stdout.len())
            .field("registry", &self.registry)
            .field("file_handles_len", &self.file_handles.len())
            .field("next_handle", &self.next_handle)
            .field("next_event_id", &self.next_event_id)
            .field("global_timestamp", &self.global_timestamp)
            .finish()
    }
}

impl LibraryStubEngine {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            log: Vec::new(),
            registry: VirtualRegistry::new(),
            stdout: String::new(),
            file_handles: HashMap::new(),
            next_handle: 0x0000_1000,
            next_event_id: 0,
            global_timestamp: 0,
        }
    }

    fn push_log(&mut self, function: &str, module: &str, args: &str, ret: i64, call_addr: u64) {
        let id = self.next_event_id;
        self.next_event_id += 1;
        self.global_timestamp += 1;
        self.log.push(StubLogEntry {
            id,
            function: function.to_owned(),
            module: module.to_owned(),
            args_summary: args.to_owned(),
            return_value: ret,
            call_address: call_addr,
            timestamp: self.global_timestamp,
        });
    }

    const fn new_handle(&mut self) -> u64 {
        let h = self.next_handle;
        self.next_handle += 1;
        h
    }

    // ── Dispatch ──────────────────────────────────────────────────────────────

    /// Dispatch a hooked function call. Returns the stub return value.
    pub fn dispatch(&mut self, function: &str, args: &mut StubArgs, call_addr: u64) -> StubReturn {
        match function {
            // ── libc string functions ──────────────────────────────────────────
            "strlen" | "wcslen" => self.stub_strlen(args, call_addr, function.starts_with('w')),
            "strcpy" | "strncpy" => self.stub_strcpy(args, call_addr),
            "strcat" | "strncat" => self.stub_strcat(args, call_addr),
            "strcmp" | "strcasecmp" | "strnicmp" | "stricmp" => self.stub_strcmp(args, call_addr),
            "strstr" | "strchr" | "strrchr" => self.stub_strstr(args, call_addr),
            // ── libc memory functions ─────────────────────────────────────────
            "memcpy" | "memmove" | "wmemcpy" | "RtlCopyMemory" | "CopyMemory" => {
                self.stub_memcpy(args, call_addr)
            }
            "memset" | "wmemset" | "RtlFillMemory" | "FillMemory" | "ZeroMemory" | "RtlZeroMemory" => {
                self.stub_memset(args, call_addr)
            }
            "memcmp" | "wmemcmp" | "RtlCompareMemory" => self.stub_memcmp(args, call_addr),
            // ── printf family ─────────────────────────────────────────────────
            "printf" | "puts" | "putchar" | "fprintf" | "sprintf" | "snprintf" | "wprintf" | "OutputDebugStringA" | "OutputDebugStringW" => {
                self.stub_printf(args, call_addr, function)
            }
            // ── malloc/free (fallback — prefer HeapEmulator) ──────────────────
            // handled by HeapEmulator
            "malloc" | "__libc_malloc" | "free" | "__libc_free" | "calloc" | "realloc" => StubReturn::ok(0),
            // ── Win32 file functions ───────────────────────────────────────────
            "CreateFileA" | "CreateFileW" | "CreateFile" => self.stub_create_file(args, call_addr),
            "ReadFile" => self.stub_read_file(args, call_addr),
            "WriteFile" => self.stub_write_file(args, call_addr),
            "CloseHandle" => self.stub_close_handle(args, call_addr),
            "GetFileSize" | "GetFileSizeEx" => self.stub_get_file_size(args, call_addr),
            "DeleteFileA" | "DeleteFileW" => self.stub_delete_file(args, call_addr),
            "CopyFileA" | "CopyFileW" => self.stub_copy_file(args, call_addr),
            "MoveFileA" | "MoveFileW" => self.stub_move_file(args, call_addr),
            "GetTempPathA" | "GetTempPathW" => {
                self.push_log(function, "kernel32", "", 12, call_addr);
                StubReturn::ok(12)
            }
            // ── Win32 registry functions ───────────────────────────────────────
            "RegOpenKeyA" | "RegOpenKeyW" | "RegOpenKeyExA" | "RegOpenKeyExW" => {
                self.stub_reg_open_key(args, call_addr, function)
            }
            "RegQueryValueExA" | "RegQueryValueExW" | "RegQueryValueA" | "RegQueryValueW" => {
                self.stub_reg_query_value(args, call_addr, function)
            }
            "RegSetValueExA" | "RegSetValueExW" => self.stub_reg_set_value(args, call_addr, function),
            "RegCloseKey" => {
                self.registry.close_key(args.arg0);
                self.push_log(function, "advapi32", &format!("handle={:#x}", args.arg0), 0, call_addr);
                StubReturn::ok(0)
            }
            "RegCreateKeyExA" | "RegCreateKeyExW" => self.stub_reg_create_key(args, call_addr, function),
            _ => self.dispatch_win32_misc(function, args, call_addr),
        }
    }

    /// Win32 / NTDLL fallback dispatch for process, thread, memory, registry-close
    /// and miscellaneous stubs.  Split out of [`Self::dispatch`] purely to keep
    /// the line count of the primary dispatcher manageable.
    fn dispatch_win32_misc(&mut self, function: &str, args: &StubArgs, call_addr: u64) -> StubReturn {
        match function {
            // ── Win32 process/thread ───────────────────────────────────────────
            "GetCurrentProcess" | "GetCurrentProcessId" => {
                self.push_log(function, "kernel32", "", 1234, call_addr);
                StubReturn::ok(1234)
            }
            "GetCurrentThread" | "GetCurrentThreadId"
            | "HeapFree"
            | "GetComputerNameA" | "GetComputerNameW"
            | "QueryPerformanceCounter"
            | "FreeLibrary" => {
                self.push_log(function, "kernel32", "", 1, call_addr);
                StubReturn::ok(1)
            }
            "OpenProcess" => {
                let handle = self.new_handle();
                self.push_log(function, "kernel32", &format!("pid={}", args.arg1), handle.cast_signed(), call_addr);
                StubReturn::ok(handle.cast_signed())
            }
            "TerminateProcess" | "ExitProcess" => {
                self.push_log(function, "kernel32", &format!("code={}", args.arg1), 1, call_addr);
                StubReturn::ok(1)
            }
            // ── Win32 memory ──────────────────────────────────────────────────
            "VirtualAlloc" | "VirtualAllocEx" => {
                self.push_log(function, "kernel32", &format!("size={:#x}", args.arg1), 0x2000_0000, call_addr);
                StubReturn::ok(0x2000_0000)
            }
            "VirtualFree" | "VirtualFreeEx" => {
                self.push_log(function, "kernel32", &format!("ptr={:#x}", args.arg0), 1, call_addr);
                StubReturn::ok(1)
            }
            "VirtualProtect" | "VirtualProtectEx" => {
                self.push_log(function, "kernel32", &format!("ptr={:#x},prot={}", args.arg0, args.arg2), 1, call_addr);
                StubReturn::ok(1)
            }
            "HeapCreate" => {
                let handle = self.new_handle();
                self.push_log(function, "kernel32", "", handle.cast_signed(), call_addr);
                StubReturn::ok(handle.cast_signed())
            }
            "HeapAlloc" | "HeapReAlloc" => {
                self.push_log(function, "kernel32", &format!("size={:#x}", args.arg2), 0x3000_0000, call_addr);
                StubReturn::ok(0x3000_0000)
            }
            // ── Win32 miscellaneous ───────────────────────────────────────────
            "GetLastError"
            | "GetSystemInfo" | "GetNativeSystemInfo"
            | "GetEnvironmentVariableA" | "GetEnvironmentVariableW" => {
                self.push_log(function, "kernel32", "", 0, call_addr);
                StubReturn::ok(0)
            }
            "SetLastError" => {
                self.push_log(function, "kernel32", &format!("code={}", args.arg0), 0, call_addr);
                StubReturn::ok(0)
            }
            "GetUserNameA" | "GetUserNameW" => {
                self.push_log(function, "advapi32", "", 1, call_addr);
                StubReturn::ok(1)
            }
            "GetTickCount" | "GetTickCount64" => {
                self.push_log(function, "kernel32", "", 12345, call_addr);
                StubReturn::ok(12345)
            }
            "Sleep" | "SleepEx" => {
                self.push_log(function, "kernel32", &format!("ms={}", args.arg0), 0, call_addr);
                StubReturn::ok(0)
            }
            "LoadLibraryA" | "LoadLibraryW" | "LoadLibraryExA" | "LoadLibraryExW" => {
                let handle = self.new_handle();
                self.push_log(function, "kernel32", &format!("name_ptr={:#x}", args.arg0), handle.cast_signed(), call_addr);
                StubReturn::ok(handle.cast_signed())
            }
            "GetProcAddress" => {
                self.push_log(function, "kernel32", "", 0x0040_1234, call_addr);
                StubReturn::ok(0x0040_1234)
            }
            // ── NTDLL ─────────────────────────────────────────────────────────
            "NtDelayExecution" => {
                self.push_log(function, "ntdll", &format!("alertable={},interval_ptr={:#x}", args.arg0, args.arg1), 0, call_addr);
                StubReturn::ok(0)
            }
            "NtAllocateVirtualMemory" => {
                self.push_log(function, "ntdll", "", 0, call_addr);
                StubReturn::ok(0)
            }
            "RtlAllocateHeap" => {
                self.push_log(function, "ntdll", &format!("size={:#x}", args.arg2), 0x4000_0000, call_addr);
                StubReturn::ok(0x4000_0000)
            }
            "RtlFreeHeap" => {
                self.push_log(function, "ntdll", "", 1, call_addr);
                StubReturn::ok(1)
            }
            _ => {
                self.push_log(function, "unknown", "", 0, call_addr);
                StubReturn { rax: 0, side_effect: None }
            }
        }
    }

    // ── String stubs ──────────────────────────────────────────────────────────

    fn stub_strlen(&mut self, args: &StubArgs, call_addr: u64, wide: bool) -> StubReturn {
        let len = args
            .read_cstring(args.arg0, 65536)
            .map_or(0, |s| if wide { s.chars().count() } else { s.len() });
        let len_i64 = i64::try_from(len).unwrap_or(i64::MAX);
        self.push_log(if wide { "wcslen" } else { "strlen" }, "libc", &format!("ptr={:#x}", args.arg0), len_i64, call_addr);
        StubReturn::ok(len_i64)
    }

    fn stub_strcpy(&mut self, args: &mut StubArgs, call_addr: u64) -> StubReturn {
        let src = args.read_cstring(args.arg1, 65536).unwrap_or_default();
        let _len = src.len();
        let data: Vec<u8> = src.into_bytes().into_iter().chain(std::iter::once(0)).collect();
        let dst = args.arg0;
        args.write_bytes(dst, &data);
        self.push_log("strcpy", "libc", &format!("dst={:#x},src={:#x}", dst, args.arg1), dst.cast_signed(), call_addr);
        StubReturn::with_effect(dst.cast_signed(), SideEffect::MemWrite { ptr: dst, data })
    }

    fn stub_strcat(&mut self, args: &StubArgs, call_addr: u64) -> StubReturn {
        let dst = args.arg0;
        self.push_log("strcat", "libc", &format!("dst={:#x},src={:#x}", dst, args.arg1), dst.cast_signed(), call_addr);
        StubReturn::ok(dst.cast_signed())
    }

    fn stub_strcmp(&mut self, args: &StubArgs, call_addr: u64) -> StubReturn {
        let s1 = args.read_cstring(args.arg0, 256).unwrap_or_default();
        let s2 = args.read_cstring(args.arg1, 256).unwrap_or_default();
        let result = s1.cmp(&s2) as i64;
        self.push_log("strcmp", "libc", &format!("\"{s1}\",\"{s2}\""), result, call_addr);
        StubReturn::ok(result)
    }

    fn stub_strstr(&mut self, args: &StubArgs, call_addr: u64) -> StubReturn {
        let haystack = args.read_cstring(args.arg0, 4096).unwrap_or_default();
        let needle = args.read_cstring(args.arg1, 256).unwrap_or_default();
        let result = if haystack.contains(&needle) { args.arg0.cast_signed() } else { 0 };
        self.push_log("strstr", "libc", &format!("haystack_ptr={:#x}", args.arg0), result, call_addr);
        StubReturn::ok(result)
    }

    fn stub_memcpy(&mut self, args: &StubArgs, call_addr: u64) -> StubReturn {
        let dst = args.arg0;
        let src = args.arg1;
        let len = args.arg2;
        self.push_log("memcpy", "libc", &format!("dst={dst:#x},src={src:#x},len={len:#x}"), dst.cast_signed(), call_addr);
        StubReturn::with_effect(dst.cast_signed(), SideEffect::MemCopy { dst, src, len })
    }

    fn stub_memset(&mut self, args: &StubArgs, call_addr: u64) -> StubReturn {
        let dst = args.arg0;
        let val = u8::try_from(args.arg1 & 0xFF).unwrap_or(0);
        let len = args.arg2;
        let len_usize = usize::try_from(len).unwrap_or(usize::MAX);
        self.push_log("memset", "libc", &format!("dst={dst:#x},val={val:#x},len={len:#x}"), dst.cast_signed(), call_addr);
        if val == 0 {
            StubReturn::with_effect(dst.cast_signed(), SideEffect::MemZero { ptr: dst, len })
        } else {
            let data = vec![val; len_usize];
            StubReturn::with_effect(dst.cast_signed(), SideEffect::MemWrite { ptr: dst, data })
        }
    }

    fn stub_memcmp(&mut self, args: &StubArgs, call_addr: u64) -> StubReturn {
        let n = usize::try_from(args.arg2).unwrap_or(usize::MAX);
        let s1 = args.read_bytes(args.arg0, n).unwrap_or(&[]);
        let s2 = args.read_bytes(args.arg1, n).unwrap_or(&[]);
        let result = s1.cmp(s2) as i64;
        self.push_log("memcmp", "libc", &format!("ptr1={:#x},ptr2={:#x},len={}", args.arg0, args.arg1, args.arg2), result, call_addr);
        StubReturn::ok(result)
    }

    fn stub_printf(&mut self, args: &StubArgs, call_addr: u64, fn_name: &str) -> StubReturn {
        let fmt_str = args.read_cstring(args.arg0, 4096).unwrap_or_else(|| "<format>".to_owned());
        let output = format!("[{fn_name}] {fmt_str}");
        self.stdout.push_str(&output);
        self.stdout.push('\n');
        let out_len = i64::try_from(output.len()).unwrap_or(i64::MAX);
        self.push_log(fn_name, "libc", &format!("fmt=\"{}\"", fmt_str.chars().take(64).collect::<String>()), out_len, call_addr);
        StubReturn::with_effect(out_len, SideEffect::LogOutput(output))
    }

    // ── Win32 file stubs ──────────────────────────────────────────────────────

    fn stub_create_file(&mut self, args: &StubArgs, call_addr: u64) -> StubReturn {
        let path = args.read_cstring(args.arg0, 1024)
            .unwrap_or_else(|| format!("unknown_{:#x}", args.arg0));
        let handle = self.new_handle();
        self.file_handles.insert(handle, path.clone());
        self.push_log("CreateFileA", "kernel32", &format!("path=\"{path}\""), handle.cast_signed(), call_addr);
        StubReturn::with_effect(handle.cast_signed(), SideEffect::FileOpened { handle, path })
    }

    fn stub_read_file(&mut self, args: &StubArgs, call_addr: u64) -> StubReturn {
        let handle = args.arg0;
        let count = args.arg2;
        self.push_log("ReadFile", "kernel32", &format!("handle={handle:#x},count={count}"), 1, call_addr);
        StubReturn::ok(1)
    }

    fn stub_write_file(&mut self, args: &StubArgs, call_addr: u64) -> StubReturn {
        let handle = args.arg0;
        let count = args.arg2;
        self.push_log("WriteFile", "kernel32", &format!("handle={handle:#x},count={count}"), 1, call_addr);
        StubReturn::ok(1)
    }

    fn stub_close_handle(&mut self, args: &StubArgs, call_addr: u64) -> StubReturn {
        let handle = args.arg0;
        let _path = self.file_handles.remove(&handle)
            .or_else(|| { self.registry.close_key(handle); None });
        self.push_log("CloseHandle", "kernel32", &format!("handle={handle:#x}"), 1, call_addr);
        StubReturn::ok(1)
    }

    fn stub_get_file_size(&mut self, args: &StubArgs, call_addr: u64) -> StubReturn {
        self.push_log("GetFileSize", "kernel32", &format!("handle={:#x}", args.arg0), 0, call_addr);
        StubReturn::ok(0)
    }

    fn stub_delete_file(&mut self, args: &StubArgs, call_addr: u64) -> StubReturn {
        let path = args.read_cstring(args.arg0, 1024).unwrap_or_default();
        self.push_log("DeleteFileA", "kernel32", &format!("path=\"{path}\""), 1, call_addr);
        StubReturn::ok(1)
    }

    fn stub_copy_file(&mut self, _args: &mut StubArgs, call_addr: u64) -> StubReturn {
        self.push_log("CopyFileA", "kernel32", "", 1, call_addr);
        StubReturn::ok(1)
    }

    fn stub_move_file(&mut self, _args: &mut StubArgs, call_addr: u64) -> StubReturn {
        self.push_log("MoveFileA", "kernel32", "", 1, call_addr);
        StubReturn::ok(1)
    }

    // ── Win32 registry stubs ──────────────────────────────────────────────────

    fn stub_reg_open_key(&mut self, args: &StubArgs, call_addr: u64, fn_name: &str) -> StubReturn {
        let key_path = args.read_cstring(args.arg1, 1024)
            .unwrap_or_else(|| format!("key_{:#x}", args.arg1));
        let handle = self.registry.open_key(&key_path).unwrap_or(0);
        self.push_log(fn_name, "advapi32", &format!("key=\"{key_path}\""), handle.cast_signed(), call_addr);
        StubReturn::with_effect(0, SideEffect::RegistryOpened { handle, key: key_path })
    }

    fn stub_reg_query_value(&mut self, args: &StubArgs, call_addr: u64, fn_name: &str) -> StubReturn {
        let handle = args.arg0;
        let value_name = args.read_cstring(args.arg1, 256).unwrap_or_default();
        let data = self.registry.query_value(handle, &value_name).map(<[u8]>::to_vec);
        let ret = if data.is_some() { 0 } else { 2 }; // ERROR_FILE_NOT_FOUND = 2
        self.push_log(fn_name, "advapi32", &format!("handle={handle:#x},name=\"{value_name}\""), ret, call_addr);
        StubReturn::ok(ret)
    }

    fn stub_reg_set_value(&mut self, args: &StubArgs, call_addr: u64, fn_name: &str) -> StubReturn {
        let handle = args.arg0;
        let value_name = args.read_cstring(args.arg1, 256).unwrap_or_default();
        let nbytes = usize::try_from(args.arg5).unwrap_or(usize::MAX);
        let data = args.read_bytes(args.arg4, nbytes).unwrap_or(&[]).to_vec();
        self.registry.set_value_by_handle(handle, &value_name, &data);
        self.push_log(fn_name, "advapi32", &format!("handle={handle:#x},name=\"{value_name}\""), 0, call_addr);
        StubReturn::ok(0)
    }

    fn stub_reg_create_key(&mut self, args: &StubArgs, call_addr: u64, fn_name: &str) -> StubReturn {
        let key_path = args.read_cstring(args.arg1, 1024).unwrap_or_default();
        let _handle = self.registry.open_key(&key_path).unwrap_or(0);
        self.push_log(fn_name, "advapi32", &format!("key=\"{key_path}\""), 0, call_addr);
        StubReturn::ok(0)
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    #[must_use] 
    pub const fn log_count(&self) -> usize {
        self.log.len()
    }

    #[must_use] 
    pub fn calls_for(&self, function: &str) -> Vec<&StubLogEntry> {
        self.log.iter().filter(|e| e.function == function).collect()
    }

    #[must_use] 
    pub fn unique_functions_called(&self) -> Vec<String> {
        let mut names: Vec<String> = self.log.iter().map(|e| e.function.clone()).collect();
        names.sort();
        names.dedup();
        names
    }

    #[must_use] 
    pub const fn file_handles_open(&self) -> &HashMap<u64, String> {
        &self.file_handles
    }
}

impl Default for LibraryStubEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Stub Coverage ────────────────────────────────────────────────────────────

/// List of all explicitly stubbed function names.
pub const STUBBED_FUNCTIONS: &[&str] = &[
    // libc string
    "strlen", "wcslen", "strcpy", "strncpy", "strcat", "strncat",
    "strcmp", "strcasecmp", "strnicmp", "stricmp", "strstr", "strchr", "strrchr",
    // libc memory
    "memcpy", "memmove", "wmemcpy", "RtlCopyMemory", "CopyMemory",
    "memset", "wmemset", "RtlFillMemory", "FillMemory", "ZeroMemory", "RtlZeroMemory",
    "memcmp", "wmemcmp", "RtlCompareMemory",
    // printf
    "printf", "puts", "putchar", "fprintf", "sprintf", "snprintf", "wprintf",
    "OutputDebugStringA", "OutputDebugStringW",
    // heap
    "malloc", "__libc_malloc", "calloc", "__libc_calloc", "realloc", "__libc_realloc",
    "free", "__libc_free", "cfree", "malloc_usable_size",
    // Win32 file
    "CreateFileA", "CreateFileW", "CreateFile", "ReadFile", "WriteFile", "CloseHandle",
    "GetFileSize", "GetFileSizeEx", "DeleteFileA", "DeleteFileW",
    "CopyFileA", "CopyFileW", "MoveFileA", "MoveFileW",
    "GetTempPathA", "GetTempPathW",
    // Win32 registry
    "RegOpenKeyA", "RegOpenKeyW", "RegOpenKeyExA", "RegOpenKeyExW",
    "RegQueryValueExA", "RegQueryValueExW", "RegQueryValueA", "RegQueryValueW",
    "RegSetValueExA", "RegSetValueExW", "RegCloseKey",
    "RegCreateKeyExA", "RegCreateKeyExW",
    // Win32 process
    "GetCurrentProcess", "GetCurrentProcessId", "GetCurrentThread", "GetCurrentThreadId",
    "OpenProcess", "TerminateProcess", "ExitProcess",
    // Win32 memory
    "VirtualAlloc", "VirtualAllocEx", "VirtualFree", "VirtualFreeEx",
    "VirtualProtect", "VirtualProtectEx", "HeapCreate", "HeapAlloc", "HeapReAlloc", "HeapFree",
    // Win32 misc
    "GetLastError", "SetLastError", "GetSystemInfo", "GetNativeSystemInfo",
    "GetComputerNameA", "GetComputerNameW", "GetUserNameA", "GetUserNameW",
    "GetTickCount", "GetTickCount64", "QueryPerformanceCounter",
    "Sleep", "SleepEx", "GetEnvironmentVariableA", "GetEnvironmentVariableW",
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "FreeLibrary",
    // NTDLL
    "NtDelayExecution", "NtAllocateVirtualMemory", "RtlAllocateHeap", "RtlFreeHeap",
];

/// Returns true if the function is explicitly stubbed.
#[must_use] 
pub fn is_stubbed(function: &str) -> bool {
    STUBBED_FUNCTIONS.contains(&function)
}

/// Returns the module that would normally export a given function.
#[must_use] 
pub fn stub_module(function: &str) -> &'static str {
    match function {
        f if f.starts_with("Nt") || f.starts_with("Rtl") || f.starts_with("Ldr") => "ntdll",
        f if ["RegOpenKey", "RegQuery", "RegSet", "RegCreate", "RegClose", "GetUserName"]
            .iter().any(|p| f.starts_with(p)) => "advapi32",
        _ => "kernel32",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_args(arg0: u64, arg1: u64, arg2: u64) -> StubArgs {
        StubArgs {
            arg0,
            arg1,
            arg2,
            arg3: 0,
            arg4: 0,
            arg5: 0,
            mem: vec![0u8; 4096],
            mem_base: 0x1000_0000,
        }
    }

    fn write_cstring(args: &mut StubArgs, ptr: u64, s: &str) {
        let offset = usize::try_from(ptr - args.mem_base).expect("offset fits");
        let bytes = s.as_bytes();
        args.mem[offset..offset + bytes.len()].copy_from_slice(bytes);
        args.mem[offset + bytes.len()] = 0;
    }

    #[test]
    fn test_strlen_stub() {
        let mut engine = LibraryStubEngine::new();
        let base = 0x1000_0000u64;
        let mut args = make_args(base + 100, 0, 0);
        write_cstring(&mut args, base + 100, "hello world");
        let ret = engine.dispatch("strlen", &mut args, 0x0040_1000);
        assert_eq!(ret.rax, 11);
    }

    #[test]
    fn test_strcmp_stub() {
        let mut engine = LibraryStubEngine::new();
        let base = 0x1000_0000u64;
        let mut args = make_args(base + 100, base + 200, 0);
        write_cstring(&mut args, base + 100, "abc");
        write_cstring(&mut args, base + 200, "abc");
        let ret = engine.dispatch("strcmp", &mut args, 0x0040_1000);
        assert_eq!(ret.rax, 0);
    }

    #[test]
    fn test_printf_stub() {
        let mut engine = LibraryStubEngine::new();
        let base = 0x1000_0000u64;
        let mut args = make_args(base + 50, 0, 0);
        write_cstring(&mut args, base + 50, "Hello, sandbox!");
        let ret = engine.dispatch("printf", &mut args, 0x0040_1000);
        assert!(ret.rax > 0);
        assert!(engine.stdout.contains("Hello, sandbox!"));
    }

    #[test]
    fn test_memcpy_stub() {
        let mut engine = LibraryStubEngine::new();
        let mut args = make_args(0x2000_0000, 0x2000_1000, 64);
        let ret = engine.dispatch("memcpy", &mut args, 0x0040_1000);
        assert_eq!(ret.rax, 0x2000_0000);
        assert!(matches!(ret.side_effect, Some(SideEffect::MemCopy { .. })));
    }

    #[test]
    fn test_memset_zero() {
        let mut engine = LibraryStubEngine::new();
        let mut args = make_args(0x3000_0000, 0, 256);
        let ret = engine.dispatch("memset", &mut args, 0x0);
        assert!(matches!(ret.side_effect, Some(SideEffect::MemZero { .. })));
    }

    #[test]
    fn test_create_file_stub() {
        let mut engine = LibraryStubEngine::new();
        let base = 0x1000_0000u64;
        let mut args = make_args(base + 100, 0x8000_0000, 3);
        write_cstring(&mut args, base + 100, r"C:\Temp\evil.exe");
        let ret = engine.dispatch("CreateFileA", &mut args, 0x0040_1000);
        assert!(ret.rax > 0);
        assert!(engine.file_handles_open().contains_key(&ret.rax.cast_unsigned()));
    }

    #[test]
    fn test_registry_open_and_close() {
        let mut engine = LibraryStubEngine::new();
        let base = 0x1000_0000u64;
        let mut args = make_args(0x8000_0002, base + 100, 0);
        write_cstring(&mut args, base + 100, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
        let ret = engine.dispatch("RegOpenKeyA", &mut args, 0x0040_1000);
        // Returns 0 (ERROR_SUCCESS) via stub
        assert_eq!(ret.rax, 0);
    }

    #[test]
    fn test_sleep_stub() {
        let mut engine = LibraryStubEngine::new();
        let mut args = make_args(10000, 0, 0);
        let ret = engine.dispatch("Sleep", &mut args, 0x0040_1000);
        assert_eq!(ret.rax, 0);
        assert_eq!(engine.calls_for("Sleep").len(), 1);
    }

    #[test]
    fn test_unknown_function_logged() {
        let mut engine = LibraryStubEngine::new();
        let mut args = make_args(0, 0, 0);
        engine.dispatch("SomeFunctionNobodyHasStubbed", &mut args, 0x0);
        assert_eq!(engine.log_count(), 1);
        assert_eq!(engine.log[0].function, "SomeFunctionNobodyHasStubbed");
    }

    #[test]
    fn test_unique_functions_called() {
        let mut engine = LibraryStubEngine::new();
        let mut args = make_args(0, 0, 0);
        engine.dispatch("Sleep", &mut args, 0x0);
        engine.dispatch("Sleep", &mut args, 0x0);
        engine.dispatch("GetLastError", &mut args, 0x0);
        let unique = engine.unique_functions_called();
        assert_eq!(unique.len(), 2);
    }
}
