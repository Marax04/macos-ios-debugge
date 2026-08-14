//! Win32 API stub emulation for shellcode analysis.
//!
//! Provides a fake Win32 API dispatch table and per-API handlers that
//! log calls and supply plausible return values without needing a real OS.

use std::collections::HashMap;

use crate::x86_emulator::{X86Cpu, X86Mem};

// ── API table ─────────────────────────────────────────────────────────────────

/// A table mapping Win32 API names to stub addresses.
pub struct Win32ApiTable {
    pub entries: Vec<(String, u64)>,
}

impl Win32ApiTable {
    /// Build a table of ~30 common Win32 APIs with sequential stub addresses
    /// starting at `base`.
    #[must_use] 
    pub fn new(base: u64) -> Self {
        let names: &[&str] = &[
            "VirtualAlloc",
            "VirtualFree",
            "HeapAlloc",
            "HeapFree",
            "GetProcAddress",
            "LoadLibraryA",
            "LoadLibraryW",
            "GetLastError",
            "SetLastError",
            "Sleep",
            "ExitProcess",
            "CreateFileA",
            "ReadFile",
            "WriteFile",
            "CloseHandle",
            "CreateProcessA",
            "ShellExecuteA",
            "WinExec",
            "OutputDebugStringA",
            "MessageBoxA",
            "InternetOpenA",
            "InternetOpenUrlA",
            "HttpOpenRequestA",
            "send",
            "recv",
            "connect",
            "WSAStartup",
            "GetModuleHandleA",
            "GetModuleHandleW",
            "IsDebuggerPresent",
        ];
        let mut entries = Vec::with_capacity(names.len());
        for (i, &name) in names.iter().enumerate() {
            entries.push((name.to_string(), base + i as u64 * 0x10));
        }
        Self { entries }
    }

    /// Find an API by stub address.
    #[must_use] 
    pub fn find_by_address(&self, addr: u64) -> Option<&str> {
        self.entries
            .iter()
            .find(|(_, a)| *a == addr)
            .map(|(n, _)| n.as_str())
    }

    /// Find a stub address by API name.
    #[must_use] 
    pub fn find_by_name(&self, name: &str) -> Option<u64> {
        self.entries
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, a)| *a)
    }
}

// ── Call result ───────────────────────────────────────────────────────────────

/// Record of a single API call interception.
#[derive(Debug, Clone)]
pub struct ApiCallResult {
    pub api_name: String,
    pub args: Vec<u64>,
    pub retval: u64,
    pub side_effects: Vec<String>,
}

// ── Emulator ──────────────────────────────────────────────────────────────────

/// Handles Win32 API stub calls during shellcode emulation.
pub struct ApiEmulator {
    api_table: Win32ApiTable,
    heap_base: u64,
    next_alloc: u64,
    alloc_map: HashMap<u64, usize>,
    log: Vec<ApiCallResult>,
}

impl ApiEmulator {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            api_table: Win32ApiTable::new(0x7700_0000),
            heap_base: 0x0050_0000,
            next_alloc: 0x0050_0000,
            alloc_map: HashMap::new(),
            log: Vec::new(),
        }
    }

    /// Attempt to handle a CALL to `call_addr`.
    ///
    /// Returns `true` if the call was handled (known API), `false` otherwise.
    pub fn handle_call(&mut self, cpu: &mut X86Cpu, mem: &mut X86Mem, call_addr: u64) -> bool {
        let name = match self.api_table.find_by_address(call_addr) {
            Some(n) => n.to_string(),
            None => return false,
        };

        let rcx = cpu.rcx;
        let rdx = cpu.rdx;
        let r8 = cpu.r8;
        let _r9 = cpu.r9;

        let (retval, side_effects) = match name.as_str() {
            "VirtualAlloc" | "HeapAlloc" => {
                let size = rdx.max(1) as usize;
                let addr = self.next_alloc;
                self.next_alloc += (size as u64 + 0xFFF) & !0xFFF;
                self.alloc_map.insert(addr, size);
                let offset = addr - self.heap_base;
                (
                    addr,
                    vec![format!("alloc({size}) -> {addr:#x} (heap+{offset:#x})")],
                )
            }
            "VirtualFree" | "HeapFree" => {
                self.alloc_map.remove(&rcx);
                (1, vec![format!("free({rcx:#x})")])
            }
            "ExitProcess" => (0, vec![format!("exit({})", rcx)]),
            "OutputDebugStringA" => {
                let s = read_cstring(mem, rcx);
                (0, vec![format!("OutputDebugString: {s}")])
            }
            "LoadLibraryA" | "LoadLibraryW" => {
                let dll = read_cstring(mem, rcx);
                let fake_handle = 0x7800_0000_u64 + (dll.len() as u64 & 0xFFFF);
                (
                    fake_handle,
                    vec![format!("LoadLibrary({dll}) -> {fake_handle:#x}")],
                )
            }
            "GetProcAddress" => {
                let proc_name = read_cstring(mem, rdx);
                let retval = self.api_table.find_by_name(&proc_name).unwrap_or(0);
                (
                    retval,
                    vec![format!("GetProcAddress({proc_name}) -> {retval:#x}")],
                )
            }
            "WinExec" => {
                let cmdline = read_cstring(mem, rcx);
                (1, vec![format!("WinExec: {cmdline}")])
            }
            "Sleep" => (0, vec![format!("Sleep({}ms)", rcx)]),
            "GetLastError" => (0, vec![]),
            "SetLastError" => (0, vec![format!("SetLastError({})", rcx)]),
            "IsDebuggerPresent" => (0, vec![]), // return not-debugging
            "GetModuleHandleA" | "GetModuleHandleW" => {
                let name_str = read_cstring(mem, rcx);
                (0x0040_0000, vec![format!("GetModuleHandle({name_str})")])
            }
            "MessageBoxA" => {
                let text = read_cstring(mem, rdx);
                let caption = read_cstring(mem, r8);
                (1, vec![format!("MessageBox({caption}: {text})")])
            }
            "CreateFileA" => {
                let path = read_cstring(mem, rcx);
                let fake_handle = 0x0000_0100_u64;
                (fake_handle, vec![format!("CreateFile({path})")])
            }
            "CloseHandle" => (1, vec![format!("CloseHandle({rcx:#x})")]),
            "ReadFile" | "WriteFile" => (1, vec![format!("{name}(handle={rcx:#x})")]),
            _ => (1, vec![format!("{name}(rcx={rcx:#x}, rdx={rdx:#x})")]),
        };

        cpu.rax = retval;

        self.log.push(ApiCallResult {
            api_name: name,
            args: vec![cpu.rcx, cpu.rdx, cpu.r8, cpu.r9],
            retval,
            side_effects,
        });

        true
    }

    /// Access the call log.
    #[must_use] 
    pub fn call_log(&self) -> &[ApiCallResult] {
        &self.log
    }

    /// Return a reference to the API table.
    #[must_use] 
    pub const fn api_table(&self) -> &Win32ApiTable {
        &self.api_table
    }

    /// Base address of the emulated process heap.
    #[must_use] 
    pub const fn heap_base(&self) -> u64 {
        self.heap_base
    }

    /// Number of heap bytes handed out so far (current bump-pointer offset
    /// from [`heap_base`](Self::heap_base)).
    #[must_use] 
    pub const fn heap_used(&self) -> u64 {
        self.next_alloc - self.heap_base
    }
}

impl Default for ApiEmulator {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper ────────────────────────────────────────────────────────────────────

/// Read a NUL-terminated ASCII string from memory.
fn read_cstring(mem: &X86Mem, addr: u64) -> String {
    if addr == 0 {
        return String::new();
    }
    let mut out = Vec::new();
    let mut cur = addr;
    loop {
        match mem.read_u8(cur) {
            Some(0) | None => break,
            Some(b) => out.push(b),
        }
        cur = cur.wrapping_add(1);
        if out.len() > 256 {
            break;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (ApiEmulator, X86Cpu, X86Mem) {
        (ApiEmulator::new(), X86Cpu::new(), X86Mem::new())
    }

    // ── Win32ApiTable ─────────────────────────────────────────────────────────

    #[test]
    fn test_api_table_find_by_name() {
        let t = Win32ApiTable::new(0x7700_0000);
        assert!(t.find_by_name("VirtualAlloc").is_some());
    }

    #[test]
    fn test_api_table_find_by_name_case_insensitive() {
        let t = Win32ApiTable::new(0x7700_0000);
        assert_eq!(
            t.find_by_name("virtualalloc"),
            t.find_by_name("VirtualAlloc")
        );
    }

    #[test]
    fn test_api_table_find_by_address_roundtrip() {
        let t = Win32ApiTable::new(0x7700_0000);
        let addr = t.find_by_name("LoadLibraryA").unwrap();
        assert_eq!(t.find_by_address(addr), Some("LoadLibraryA"));
    }

    #[test]
    fn test_api_table_unknown_returns_none() {
        let t = Win32ApiTable::new(0x7700_0000);
        assert!(t.find_by_name("NonExistentFunction123").is_none());
        assert!(t.find_by_address(0xDEAD_BEEF).is_none());
    }

    #[test]
    fn test_api_table_has_30_entries() {
        let t = Win32ApiTable::new(0x7700_0000);
        assert_eq!(t.entries.len(), 30);
    }

    #[test]
    fn test_api_table_sequential_addresses() {
        let t = Win32ApiTable::new(0x1000);
        assert_eq!(t.entries[0].1, 0x1000);
        assert_eq!(t.entries[1].1, 0x1010);
    }

    // ── ApiEmulator.handle_call ───────────────────────────────────────────────

    #[test]
    fn test_handle_virtual_alloc() {
        let (mut emu, mut cpu, mut mem) = setup();
        let addr = emu.api_table.find_by_name("VirtualAlloc").unwrap();
        cpu.rdx = 0x1000; // size
        let handled = emu.handle_call(&mut cpu, &mut mem, addr);
        assert!(handled);
        assert_ne!(cpu.rax, 0);
        assert_eq!(emu.log.len(), 1);
        assert_eq!(emu.log[0].api_name, "VirtualAlloc");
    }

    #[test]
    fn test_heap_base_and_usage_tracking() {
        let (mut emu, mut cpu, mut mem) = setup();
        let base = emu.heap_base();
        assert_ne!(base, 0);
        // First allocation must come from the heap base.
        assert_eq!(emu.heap_used(), 0);

        let addr = emu.api_table.find_by_name("HeapAlloc").unwrap();
        cpu.rdx = 0x1000; // size
        assert!(emu.handle_call(&mut cpu, &mut mem, addr));
        assert_eq!(cpu.rax, base);

        // A 0x1000-byte request rounds up to one page beyond the base.
        assert_eq!(emu.heap_used(), 0x1000);
        assert!(emu.log[0].side_effects[0].contains("heap+0x0"));
    }

    #[test]
    fn test_handle_exit_process() {
        let (mut emu, mut cpu, mut mem) = setup();
        let addr = emu.api_table.find_by_name("ExitProcess").unwrap();
        cpu.rcx = 1;
        emu.handle_call(&mut cpu, &mut mem, addr);
        assert!(emu.log[0].side_effects.iter().any(|s| s.contains("exit")));
    }

    #[test]
    fn test_handle_load_library_returns_handle() {
        let (mut emu, mut cpu, mut mem) = setup();
        let dll = b"ntdll.dll\0";
        mem.map_bytes(0x4000, dll);
        cpu.rcx = 0x4000;
        let addr = emu.api_table.find_by_name("LoadLibraryA").unwrap();
        emu.handle_call(&mut cpu, &mut mem, addr);
        assert_ne!(cpu.rax, 0);
    }

    #[test]
    fn test_handle_get_proc_address_known() {
        let (mut emu, mut cpu, mut mem) = setup();
        let fn_name = b"VirtualAlloc\0";
        mem.map_bytes(0x5000, fn_name);
        cpu.rdx = 0x5000;
        let addr = emu.api_table.find_by_name("GetProcAddress").unwrap();
        emu.handle_call(&mut cpu, &mut mem, addr);
        // Should return the stub address of VirtualAlloc
        assert_ne!(cpu.rax, 0);
    }

    #[test]
    fn test_handle_output_debug_string() {
        let (mut emu, mut cpu, mut mem) = setup();
        mem.map_bytes(0x6000, b"hello world\0");
        cpu.rcx = 0x6000;
        let addr = emu.api_table.find_by_name("OutputDebugStringA").unwrap();
        emu.handle_call(&mut cpu, &mut mem, addr);
        assert!(
            emu.log[0]
                .side_effects
                .iter()
                .any(|s| s.contains("hello world"))
        );
    }

    #[test]
    fn test_handle_win_exec() {
        let (mut emu, mut cpu, mut mem) = setup();
        mem.map_bytes(0x7000, b"cmd.exe /c whoami\0");
        cpu.rcx = 0x7000;
        let addr = emu.api_table.find_by_name("WinExec").unwrap();
        emu.handle_call(&mut cpu, &mut mem, addr);
        assert!(
            emu.log[0]
                .side_effects
                .iter()
                .any(|s| s.contains("cmd.exe"))
        );
    }

    #[test]
    fn test_handle_unknown_address_returns_false() {
        let (mut emu, mut cpu, mut mem) = setup();
        assert!(!emu.handle_call(&mut cpu, &mut mem, 0xDEAD_BEEF));
    }

    #[test]
    fn test_call_log_accessor() {
        let (mut emu, mut cpu, mut mem) = setup();
        let addr = emu.api_table.find_by_name("Sleep").unwrap();
        cpu.rcx = 500;
        emu.handle_call(&mut cpu, &mut mem, addr);
        let log = emu.call_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].api_name, "Sleep");
    }

    #[test]
    fn test_is_debugger_present_returns_zero() {
        let (mut emu, mut cpu, mut mem) = setup();
        let addr = emu.api_table.find_by_name("IsDebuggerPresent").unwrap();
        emu.handle_call(&mut cpu, &mut mem, addr);
        assert_eq!(cpu.rax, 0);
    }

    #[test]
    fn test_virtual_free_removes_alloc() {
        let (mut emu, mut cpu, mut mem) = setup();
        let va_addr = emu.api_table.find_by_name("VirtualAlloc").unwrap();
        cpu.rdx = 0x1000;
        emu.handle_call(&mut cpu, &mut mem, va_addr);
        let alloc_addr = cpu.rax;

        let vf_addr = emu.api_table.find_by_name("VirtualFree").unwrap();
        cpu.rcx = alloc_addr;
        emu.handle_call(&mut cpu, &mut mem, vf_addr);
        assert_eq!(cpu.rax, 1);
    }

    #[test]
    fn test_message_box() {
        let (mut emu, mut cpu, mut mem) = setup();
        mem.map_bytes(0x8000, b"Error\0");
        mem.map_bytes(0x8100, b"Caption\0");
        cpu.rdx = 0x8000;
        cpu.r8 = 0x8100;
        let addr = emu.api_table.find_by_name("MessageBoxA").unwrap();
        emu.handle_call(&mut cpu, &mut mem, addr);
        assert_eq!(cpu.rax, 1);
        assert!(
            emu.log[0]
                .side_effects
                .iter()
                .any(|s| s.contains("Caption"))
        );
    }

    #[test]
    fn test_multiple_allocs_unique_addresses() {
        let (mut emu, mut cpu, mut mem) = setup();
        let va_addr = emu.api_table.find_by_name("VirtualAlloc").unwrap();
        cpu.rdx = 0x1000;
        emu.handle_call(&mut cpu, &mut mem, va_addr);
        let addr1 = cpu.rax;
        cpu.rdx = 0x1000;
        emu.handle_call(&mut cpu, &mut mem, va_addr);
        let addr2 = cpu.rax;
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_api_emulator_default() {
        let emu = ApiEmulator::default();
        assert!(emu.call_log().is_empty());
    }

    #[test]
    fn test_read_cstring_empty_on_null_addr() {
        let mem = X86Mem::new();
        assert_eq!(read_cstring(&mem, 0), String::new());
    }

    #[test]
    fn test_heap_alloc() {
        let (mut emu, mut cpu, mut mem) = setup();
        let addr = emu.api_table.find_by_name("HeapAlloc").unwrap();
        cpu.rdx = 64;
        emu.handle_call(&mut cpu, &mut mem, addr);
        assert_ne!(cpu.rax, 0);
    }

    #[test]
    fn test_close_handle() {
        let (mut emu, mut cpu, mut mem) = setup();
        let addr = emu.api_table.find_by_name("CloseHandle").unwrap();
        cpu.rcx = 0x100;
        emu.handle_call(&mut cpu, &mut mem, addr);
        assert_eq!(cpu.rax, 1);
    }

    #[test]
    fn test_create_file_a() {
        let (mut emu, mut cpu, mut mem) = setup();
        mem.map_bytes(0x9000, b"C:\\temp\\file.txt\0");
        cpu.rcx = 0x9000;
        let addr = emu.api_table.find_by_name("CreateFileA").unwrap();
        emu.handle_call(&mut cpu, &mut mem, addr);
        assert_ne!(cpu.rax, 0);
    }

    #[test]
    fn test_get_module_handle() {
        let (mut emu, mut cpu, mut mem) = setup();
        mem.map_bytes(0xA000, b"kernel32.dll\0");
        cpu.rcx = 0xA000;
        let addr = emu.api_table.find_by_name("GetModuleHandleA").unwrap();
        emu.handle_call(&mut cpu, &mut mem, addr);
        assert_ne!(cpu.rax, 0);
    }
}
