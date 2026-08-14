//! Built-in MCP tools: `disassemble_at`, `get_function`, `list_functions`, `search_string`,
//! `get_imports`, `get_exports`, `compute_hash`, `get_section`.
//!
//! Each tool is a struct implementing `ToolHandler` from the executor module.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::tool_executor::{
    ToolHandler, extract_bool_or, extract_opt_u64, extract_str, extract_u64,
    wrap_list, wrap_success,
};

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Shared utility: hex encode/decode â€” re-use crate-level helpers from lib.rs
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

use crate::hex_encode;

fn hex_decode_simple(s: &str) -> Result<Vec<u8>, String> {
    crate::hex_decode(s).map_err(|e| format!("{e:?}"))
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// 1. DisassembleAtTool
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Disassemble instructions at a given virtual address.
///
/// Parameters:
/// - `address` (required, integer): virtual address to disassemble at
/// - `count` (optional, integer, default 10): number of instructions
/// - `arch` (optional, string, default `"x86_64"`): architecture hint
pub struct DisassembleAtTool;

impl ToolHandler for DisassembleAtTool {
    fn name(&self) -> &'static str { "disassemble_at" }

    fn preprocess_params(&self, mut params: Value) -> Value {
        if params.get("count").is_none() {
            params["count"] = json!(10);
        }
        if params.get("arch").is_none() {
            params["arch"] = json!("x86_64");
        }
        params
    }

    fn execute(&self, params: &Value) -> Result<Value, String> {
        let address = extract_u64(params, "address")?;
        let count = usize::try_from(extract_opt_u64(params, "count").unwrap_or(10).min(1000)).unwrap_or(1000);
        let arch = params.get("arch").and_then(Value::as_str).unwrap_or("x86_64");

        // Synthetic disassembly output (placeholder for real disassembler call)
        let mut instructions = Vec::new();
        for i in 0..count {
            let addr = address + (i as u64) * 4;
            instructions.push(json!({
                "address": format!("{:#010x}", addr),
                "address_int": addr,
                "mnemonic": if i % 5 == 0 { "push" } else if i % 5 == 1 { "mov" } else if i % 5 == 2 { "lea" } else if i % 5 == 3 { "call" } else { "ret" },
                "operands": if i % 5 == 0 { "rbp" } else if i % 5 == 1 { "rax, rbx" } else if i % 5 == 2 { "rcx, [rsp+0x10]" } else if i % 5 == 3 { "0xdeadbeef" } else { "" },
                "bytes": format!("{:02x} {:02x}", (addr & 0xff) as u8, ((addr >> 8) & 0xff) as u8),
                "size": 4,
            }));
        }

        Ok(wrap_success(&json!({
            "address": format!("{address:#010x}"),
            "arch": arch,
            "count": count,
            "instructions": instructions,
        })))
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// 2. GetFunctionTool
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Get function information by name or address.
///
/// Parameters:
/// - `name` (required, string): function name or hex address
/// - `decompile` (optional, bool, default false): include decompiled pseudocode
/// - `disassemble` (optional, bool, default true): include disassembly
pub struct GetFunctionTool;

impl ToolHandler for GetFunctionTool {
    fn name(&self) -> &'static str { "get_function" }

    fn execute(&self, params: &Value) -> Result<Value, String> {
        let name = extract_str(params, "name")?;
        let decompile = extract_bool_or(params, "decompile", false);
        let disassemble = extract_bool_or(params, "disassemble", true);

        // Parse address if hex
        let address = if name.starts_with("0x") || name.starts_with("0X") {
            u64::from_str_radix(&name[2..], 16).ok()
        } else {
            None
        };

        let mut result = json!({
            "name": name,
            "address": address.map_or_else(|| "unknown".to_string(), |a| format!("{a:#010x}")),
            "size": 128,
            "basic_blocks": 4,
            "calls_to": 3,
            "calls_from": 5,
            "is_thunk": false,
            "is_library": false,
            "calling_convention": "fastcall",
        });

        if disassemble {
            result["disassembly"] = json!([
                {"addr": "0x00401000", "insn": "push rbp"},
                {"addr": "0x00401001", "insn": "mov rbp, rsp"},
                {"addr": "0x00401004", "insn": "sub rsp, 0x20"},
                {"addr": "0x00401008", "insn": "mov eax, 0"},
                {"addr": "0x0040100d", "insn": "pop rbp"},
                {"addr": "0x0040100e", "insn": "ret"},
            ]);
        }

        if decompile {
            result["pseudocode"] = json!(format!(
                "int {}(void) {{\n  // decompiled pseudocode\n  return 0;\n}}", name
            ));
        }

        Ok(wrap_success(&result))
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// 3. ListFunctionsTool
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// List all functions in the loaded binary.
///
/// Parameters:
/// - `filter` (optional, string): filter by name prefix/substring
/// - `limit` (optional, integer, default 100): max results
/// - `offset` (optional, integer, default 0): pagination offset
pub struct ListFunctionsTool;

impl ToolHandler for ListFunctionsTool {
    fn name(&self) -> &'static str { "list_functions" }

    fn execute(&self, params: &Value) -> Result<Value, String> {
        let filter = params.get("filter").and_then(Value::as_str).unwrap_or("").to_lowercase();
        let limit = usize::try_from(extract_opt_u64(params, "limit").unwrap_or(100).min(10000)).unwrap_or(10000);
        let offset = usize::try_from(extract_opt_u64(params, "offset").unwrap_or(0)).unwrap_or(0);

        // Synthetic function list
        let all_functions: Vec<Value> = [
            ("main", 0x0040_1000_u64, 256_usize, false),
            ("sub_401100", 0x0040_1100_u64, 64, false),
            ("__libc_start_main", 0x0040_1200_u64, 32, true),
            ("WinMain", 0x0040_1300_u64, 128, false),
            ("DllMain", 0x0040_1400_u64, 64, false),
            ("CreateFileA_stub", 0x0040_1500_u64, 16, true),
            ("WriteFile_stub", 0x0040_1510_u64, 16, true),
            ("ReadFile_stub", 0x0040_1520_u64, 16, true),
            ("VirtualAlloc_stub", 0x0040_1530_u64, 16, true),
            ("decrypt_payload", 0x0040_1600_u64, 512, false),
            ("inject_shellcode", 0x0040_1800_u64, 256, false),
            ("check_debugger", 0x0040_1a00_u64, 128, false),
            ("hash_string", 0x0040_1b00_u64, 64, false),
            ("connect_c2", 0x0040_1c00_u64, 256, false),
            ("exfiltrate_data", 0x0040_1e00_u64, 384, false),
        ]
        .iter()
        .filter(|(name, _, _, _)| {
            filter.is_empty() || name.to_lowercase().contains(&filter)
        })
        .map(|(name, addr, size, is_lib)| json!({
            "name": name,
            "address": format!("{addr:#010x}"),
            "address_int": addr,
            "size": size,
            "is_library": is_lib,
        }))
        .collect();

        let total = all_functions.len();
        let page: Vec<Value> = all_functions.into_iter().skip(offset).take(limit).collect();

        Ok(wrap_list(&Value::Array(page), total, offset, limit))
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// 4. SearchStringTool
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Search for strings in the binary.
///
/// Parameters:
/// - `pattern` (required, string): substring or regex to search for
/// - `case_sensitive` (optional, bool, default false)
/// - `regex` (optional, bool, default false)
/// - `min_length` (optional, integer, default 4)
/// - `limit` (optional, integer, default 200)
pub struct SearchStringTool;

impl ToolHandler for SearchStringTool {
    fn name(&self) -> &'static str { "search_string" }

    fn execute(&self, params: &Value) -> Result<Value, String> {
        let pattern = extract_str(params, "pattern")?;
        let case_sensitive = extract_bool_or(params, "case_sensitive", false);
        let is_regex = extract_bool_or(params, "regex", false);
        let min_len = usize::try_from(extract_opt_u64(params, "min_length").unwrap_or(4)).unwrap_or(4);
        let limit = usize::try_from(extract_opt_u64(params, "limit").unwrap_or(200).min(10000)).unwrap_or(200);

        let raw_strings: Vec<(&str, u64, &str)> = vec![
            ("C2 server connected", 0x0040_3010, ".rdata"),
            ("cmd.exe", 0x0040_3030, ".rdata"),
            ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0x0040_3050, ".rdata"),
            ("VirtualAlloc", 0x0040_3090, ".rdata"),
            ("CreateRemoteThread", 0x0040_30b0, ".rdata"),
            ("KERNEL32.DLL", 0x0040_30d0, ".rdata"),
            ("ntdll.dll", 0x0040_30f0, ".rdata"),
            ("http://c2.malware.example.com/beacon", 0x0040_3110, ".data"),
            ("\\Device\\Afd", 0x0040_3160, ".rdata"),
            ("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", 0x0040_3190, ".data"),
            ("password123", 0x0040_31e0, ".data"),
            ("HKEY_LOCAL_MACHINE", 0x0040_3200, ".rdata"),
            ("powershell.exe -enc", 0x0040_3220, ".data"),
            ("SeDebugPrivilege", 0x0040_3250, ".rdata"),
            ("IsDebuggerPresent", 0x0040_3270, ".rdata"),
        ];

        let compare_pattern = if case_sensitive { pattern.to_string() } else { pattern.to_lowercase() };

        let matches: Vec<Value> = raw_strings
            .iter()
            .filter(|(s, _, _)| {
                let haystack = if case_sensitive { s.to_string() } else { s.to_lowercase() };
                // When is_regex=true treat pattern as a literal word (full-string match);
                // when false use substring search.
                let hit = if is_regex {
                    haystack == compare_pattern
                } else {
                    haystack.contains(&compare_pattern)
                };
                hit && s.len() >= min_len
            })
            .take(limit)
            .map(|(s, addr, section)| json!({
                "string": s,
                "address": format!("{addr:#010x}"),
                "address_int": addr,
                "section": section,
                "length": s.len(),
                "encoding": "utf-8",
            }))
            .collect();

        let count = matches.len();
        Ok(wrap_list(&
            Value::Array(matches),
            count,
            0,
            limit,
        ))
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// 5. GetImportsTool
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Get imported symbols (IAT).
///
/// Parameters:
/// - `module` (optional, string): filter by DLL/module name
/// - `limit` (optional, integer, default 200)
pub struct GetImportsTool;

impl ToolHandler for GetImportsTool {
    fn name(&self) -> &'static str { "get_imports" }

    fn execute(&self, params: &Value) -> Result<Value, String> {
        let module_filter = params.get("module")
            .and_then(Value::as_str)
            .map(str::to_lowercase)
            .unwrap_or_default();
        let limit = usize::try_from(extract_opt_u64(params, "limit").unwrap_or(200)).unwrap_or(200);

        let all_imports: Vec<(&str, &str, u64)> = vec![
            ("KERNEL32.dll", "VirtualAlloc", 0x0040_1500),
            ("KERNEL32.dll", "VirtualFree", 0x0040_1504),
            ("KERNEL32.dll", "CreateFileA", 0x0040_1508),
            ("KERNEL32.dll", "WriteFile", 0x0040_150c),
            ("KERNEL32.dll", "ReadFile", 0x0040_1510),
            ("KERNEL32.dll", "CloseHandle", 0x0040_1514),
            ("KERNEL32.dll", "CreateRemoteThread", 0x0040_1518),
            ("KERNEL32.dll", "OpenProcess", 0x0040_151c),
            ("KERNEL32.dll", "IsDebuggerPresent", 0x0040_1520),
            ("KERNEL32.dll", "GetProcAddress", 0x0040_1524),
            ("KERNEL32.dll", "LoadLibraryA", 0x0040_1528),
            ("ntdll.dll", "NtAllocateVirtualMemory", 0x0040_1600),
            ("ntdll.dll", "NtCreateThread", 0x0040_1604),
            ("ntdll.dll", "NtWriteVirtualMemory", 0x0040_1608),
            ("ntdll.dll", "NtQueryInformationProcess", 0x0040_160c),
            ("WS2_32.dll", "connect", 0x0040_1700),
            ("WS2_32.dll", "send", 0x0040_1704),
            ("WS2_32.dll", "recv", 0x0040_1708),
            ("WS2_32.dll", "WSAStartup", 0x0040_170c),
            ("ADVAPI32.dll", "RegSetValueExA", 0x0040_1800),
            ("ADVAPI32.dll", "RegOpenKeyExA", 0x0040_1804),
        ];

        let filtered: Vec<Value> = all_imports
            .iter()
            .filter(|(dll, _, _)| {
                module_filter.is_empty() || dll.to_lowercase().contains(&module_filter)
            })
            .take(limit)
            .map(|(dll, name, addr)| json!({
                "module": dll,
                "name": name,
                "address": format!("{addr:#010x}"),
                "address_int": addr,
                "ordinal": null,
            }))
            .collect();

        let total = filtered.len();
        Ok(wrap_list(&Value::Array(filtered), total, 0, limit))
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// 6. GetExportsTool
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Get exported symbols (EAT).
///
/// Parameters:
/// - `filter` (optional, string): filter by name substring
/// - `limit` (optional, integer, default 200)
pub struct GetExportsTool;

impl ToolHandler for GetExportsTool {
    fn name(&self) -> &'static str { "get_exports" }

    fn execute(&self, params: &Value) -> Result<Value, String> {
        let filter = params.get("filter")
            .and_then(Value::as_str)
            .map(str::to_lowercase)
            .unwrap_or_default();
        let limit = usize::try_from(extract_opt_u64(params, "limit").unwrap_or(200)).unwrap_or(200);

        let exports: Vec<(&str, u64, u32)> = vec![
            ("DllMain", 0x0040_1400, 1),
            ("Initialize", 0x0040_1600, 2),
            ("Execute", 0x0040_1700, 3),
            ("Cleanup", 0x0040_1800, 4),
            ("GetVersion", 0x0040_1900, 5),
        ];

        let filtered: Vec<Value> = exports
            .iter()
            .filter(|(name, _, _)| {
                filter.is_empty() || name.to_lowercase().contains(&filter)
            })
            .take(limit)
            .map(|(name, addr, ordinal)| json!({
                "name": name,
                "address": format!("{addr:#010x}"),
                "address_int": addr,
                "ordinal": ordinal,
                "forwarded": null,
            }))
            .collect();

        let total = filtered.len();
        Ok(wrap_list(&Value::Array(filtered), total, 0, limit))
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// 7. ComputeHashTool
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Compute cryptographic hashes of binary data.
///
/// Parameters:
/// - `data` (required, string): hex-encoded bytes
/// - `algorithm` (optional, string, default "sha256"): md5|sha1|sha256|sha512|crc32
pub struct ComputeHashTool;

impl ComputeHashTool {
    /// Simple (non-cryptographic) DJB2 hash, used as placeholder for MD5/SHA.
    fn djb2(data: &[u8]) -> u64 {
        let mut hash: u64 = 5381;
        for &b in data {
            hash = hash.wrapping_mul(33).wrapping_add(u64::from(b));
        }
        hash
    }

    /// CRC-32 (Castagnoli polynomial, placeholder).
    fn crc32(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFF_FFFF;
        for &b in data {
            let mut byte = u32::from(b);
            for _ in 0..8 {
                if (crc ^ byte) & 1 == 1 {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                } else {
                    crc >>= 1;
                }
                byte >>= 1;
            }
        }
        !crc
    }
}

impl ToolHandler for ComputeHashTool {
    fn name(&self) -> &'static str { "compute_hash" }

    fn execute(&self, params: &Value) -> Result<Value, String> {
        let data_hex = extract_str(params, "data")?;
        let algorithm = params.get("algorithm").and_then(Value::as_str).unwrap_or("sha256");

        let bytes = hex_decode_simple(data_hex)?;

        let hash_value = match algorithm {
            "md5" => {
                // Placeholder: DJB2 as 16-byte LE
                let h = Self::djb2(&bytes);
                hex_encode(&h.to_le_bytes())
            }
            "sha1" => {
                let h = Self::djb2(&bytes);
                let mut buf = [0u8; 20];
                buf[..8].copy_from_slice(&h.to_le_bytes());
                hex_encode(&buf)
            }
            "sha256" => {
                let h = Self::djb2(&bytes);
                let mut buf = [0u8; 32];
                buf[..8].copy_from_slice(&h.to_le_bytes());
                buf[8..16].copy_from_slice(&(h ^ 0xDEAD_BEEF_CAFE_BABE).to_le_bytes());
                hex_encode(&buf)
            }
            "sha512" => {
                let h = Self::djb2(&bytes);
                let mut buf = [0u8; 64];
                for i in 0..8 {
                    let part = h.wrapping_add(i as u64 * 0x1234_5678);
                    buf[i * 8..(i + 1) * 8].copy_from_slice(&part.to_le_bytes());
                }
                hex_encode(&buf)
            }
            "crc32" => {
                format!("{:08x}", Self::crc32(&bytes))
            }
            other => return Err(format!("unknown algorithm: {other}")),
        };

        Ok(wrap_success(&json!({
            "algorithm": algorithm,
            "input_size": bytes.len(),
            "hash": hash_value,
        })))
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// 8. GetSectionTool
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Get binary section information.
///
/// Parameters:
/// - `name` (required, string): section name (e.g. ".text", ".data")
/// - `include_data` (optional, bool, default false): include hex dump of first 64 bytes
pub struct GetSectionTool;

impl ToolHandler for GetSectionTool {
    fn name(&self) -> &'static str { "get_section" }

    fn execute(&self, params: &Value) -> Result<Value, String> {
        let name = extract_str(params, "name")?;
        let include_data = extract_bool_or(params, "include_data", false);

        let sections: Vec<(&str, u64, u64, &str, bool, bool, bool)> = vec![
            (".text",  0x0040_1000, 0x10000, "r-x", true,  false, true),
            (".data",  0x0041_2000, 0x1000,  "rw-", false, true,  true),
            (".rdata", 0x0041_3000, 0x3000,  "r--", false, false, true),
            (".bss",   0x0041_6000, 0x500,   "rw-", false, true,  false),
            (".rsrc",  0x0041_7000, 0x800,   "r--", false, false, true),
            (".reloc", 0x0041_8000, 0x200,   "r--", false, false, true),
        ];

        if let Some((sec_name, addr, size, perm, exec, write, read)) =
            sections.iter().find(|(sn, _, _, _, _, _, _)| sn.eq_ignore_ascii_case(name))
        {
            let mut result = json!({
                "name": sec_name,
                "address": format!("{addr:#010x}"),
                "address_int": addr,
                "size": size,
                "permissions": perm,
                "executable": exec,
                "writable": write,
                "readable": read,
                "entropy": 5.7,
            });

            if include_data {
                // Synthetic first 64 bytes
                let addr_byte = u8::try_from(*addr & 0xFF).unwrap_or(0);
                let preview: Vec<String> = (0u8..64)
                    .map(|i| format!("{:02x}", i ^ addr_byte))
                    .collect();
                result["data_preview"] = json!(preview.join(" "));
            }

            Ok(wrap_success(&result))
        } else {
            Err(format!("section '{name}' not found"))
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// 9. StackFrameReportTool â€” Gap E
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

use rustre_decompiler::stack_locals::{AddressedInsn, build_report};
use rustre_decompiler::variable_recovery_engine::{CallingConvention, VariableRecoveryEngine};

/// Build a stack-frame report (locals as `var_N`, prologue/epilogue ranges,
/// struct-on-stack candidates) for a function.
///
/// Parameters:
/// - `function_addr` (required, integer or hex string): function entry address
/// - `instructions` (required, array): list of `{addr, mnemonic, operands,
///   stack_offset?, access_size?, is_def?}` records
/// - `arch` (optional, string, default `"x86_64"`): architecture hint for CC
pub struct StackFrameReportTool;

impl ToolHandler for StackFrameReportTool {
    fn name(&self) -> &'static str { "decompiler_stack_frame_report" }

    fn execute(&self, params: &Value) -> Result<Value, String> {
        let func_addr = extract_u64(params, "function_addr")?;
        let arch = params.get("arch").and_then(Value::as_str).unwrap_or("x86_64");
        let cc = match arch {
            a if a.contains("aarch64") || a.contains("arm64") => CallingConvention::Arm64,
            a if a.contains("win") || a.contains("msvc") => CallingConvention::WindowsX64,
            _ => CallingConvention::SysVAmd64,
        };
        let arr = params
            .get("instructions")
            .and_then(Value::as_array)
            .ok_or_else(|| "missing 'instructions' array".to_string())?;
        let mut insns: Vec<AddressedInsn> = Vec::with_capacity(arr.len());
        let mut engine = VariableRecoveryEngine::new(cc);
        for v in arr {
            let addr = v
                .get("addr")
                .and_then(Value::as_u64)
                .ok_or_else(|| "instruction missing 'addr'".to_string())?;
            let mnem = v
                .get("mnemonic")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let ops = v
                .get("operands")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if let Some(off) = v.get("stack_offset").and_then(Value::as_i64) {
                let sz = v
                    .get("access_size")
                    .and_then(Value::as_u64)
                    .map_or(8_u32, |v| u32::try_from(v).unwrap_or(8));
                let is_def = v.get("is_def").and_then(Value::as_bool).unwrap_or(false);
                engine.record_stack_access(off, sz.max(1), addr, is_def);
            }
            insns.push(AddressedInsn { addr, mnemonic: mnem, operands: ops });
        }
        let rep = build_report(&engine, &insns);

        let locals: Vec<Value> = rep
            .locals
            .iter()
            .map(|l| {
                json!({
                    "name": l.name,
                    "offset": l.offset,
                    "max_width": l.max_width,
                    "widths": l.observed_widths,
                    "kind": l.kind,
                })
            })
            .collect();
        let candidates: Vec<Value> = rep
            .struct_candidates
            .iter()
            .map(|c| {
                let fields: Vec<Value> = c
                    .fields
                    .iter()
                    .map(|(off, w)| json!({"offset": off, "width": w}))
                    .collect();
                json!({
                    "name": c.name,
                    "base_offset": c.base_offset,
                    "span": c.span,
                    "fields": fields,
                })
            })
            .collect();
        let prologue = rep.prologue.as_ref().map(|r| {
            json!({"start": format!("{:#x}", r.start), "end": format!("{:#x}", r.end)})
        });
        let epilogue = rep.epilogue.as_ref().map(|r| {
            json!({"start": format!("{:#x}", r.start), "end": format!("{:#x}", r.end)})
        });
        Ok(wrap_success(&json!({
            "function_addr": format!("{func_addr:#x}"),
            "frame_size": rep.frame_size,
            "saved_regs": rep.saved_regs,
            "prologue": prologue,
            "epilogue": epilogue,
            "locals": locals,
            "struct_candidates": candidates,
        })))
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Registry helper: register all built-in handlers
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Create a `Vec` of all built-in tool handlers.
#[must_use]
pub fn all_builtin_handlers() -> Vec<Arc<dyn ToolHandler>> {
    vec![
        Arc::new(DisassembleAtTool),
        Arc::new(GetFunctionTool),
        Arc::new(ListFunctionsTool),
        Arc::new(SearchStringTool),
        Arc::new(GetImportsTool),
        Arc::new(GetExportsTool),
        Arc::new(ComputeHashTool),
        Arc::new(GetSectionTool),
        Arc::new(StackFrameReportTool),
    ]
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tests
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_disassemble_at_basic() {
        let t = DisassembleAtTool;
        let params = json!({"address": 0x401000, "count": 5});
        let r = t.execute(&params).unwrap();
        assert_eq!(r["status"], "ok");
        let insns = r["data"]["instructions"].as_array().unwrap();
        assert_eq!(insns.len(), 5);
    }

    #[test]
    fn test_disassemble_at_default_count() {
        let t = DisassembleAtTool;
        let params = t.preprocess_params(json!({"address": 0x401000}));
        let r = t.execute(&params).unwrap();
        let insns = r["data"]["instructions"].as_array().unwrap();
        assert_eq!(insns.len(), 10);
    }

    #[test]
    fn test_disassemble_at_missing_address() {
        let t = DisassembleAtTool;
        assert!(t.execute(&json!({})).is_err());
    }

    #[test]
    fn test_get_function_basic() {
        let t = GetFunctionTool;
        let r = t.execute(&json!({"name": "main"})).unwrap();
        assert_eq!(r["status"], "ok");
        assert_eq!(r["data"]["name"], "main");
    }

    #[test]
    fn test_get_function_with_decompile() {
        let t = GetFunctionTool;
        let r = t.execute(&json!({"name": "main", "decompile": true})).unwrap();
        assert!(r["data"]["pseudocode"].is_string());
    }

    #[test]
    fn test_get_function_with_disassembly() {
        let t = GetFunctionTool;
        let r = t.execute(&json!({"name": "sub_401100", "disassemble": true})).unwrap();
        assert!(r["data"]["disassembly"].is_array());
    }

    #[test]
    fn test_list_functions_all() {
        let t = ListFunctionsTool;
        let r = t.execute(&json!({})).unwrap();
        assert_eq!(r["status"], "ok");
        assert!(!r["data"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_list_functions_filtered() {
        let t = ListFunctionsTool;
        let r = t.execute(&json!({"filter": "main"})).unwrap();
        let fns = r["data"].as_array().unwrap();
        assert!(!fns.is_empty());
        for f in fns {
            assert!(f["name"].as_str().unwrap().to_lowercase().contains("main"));
        }
    }

    #[test]
    fn test_search_string_found() {
        let t = SearchStringTool;
        let r = t.execute(&json!({"pattern": "cmd"})).unwrap();
        let results = r["data"].as_array().unwrap();
        assert!(!results.is_empty());
        assert!(results.iter().any(|x| x["string"].as_str().unwrap().to_lowercase().contains("cmd")));
    }

    #[test]
    fn test_search_string_not_found() {
        let t = SearchStringTool;
        let r = t.execute(&json!({"pattern": "zzznomatch_xyz999"})).unwrap();
        let results = r["data"].as_array().unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_get_imports_all() {
        let t = GetImportsTool;
        let r = t.execute(&json!({})).unwrap();
        assert!(!r["data"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_get_imports_filtered_by_module() {
        let t = GetImportsTool;
        let r = t.execute(&json!({"module": "ws2_32"})).unwrap();
        let imports = r["data"].as_array().unwrap();
        assert!(!imports.is_empty());
        for imp in imports {
            assert!(imp["module"].as_str().unwrap().to_lowercase().contains("ws2_32"));
        }
    }

    #[test]
    fn test_get_exports() {
        let t = GetExportsTool;
        let r = t.execute(&json!({})).unwrap();
        assert!(!r["data"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_get_exports_filtered() {
        let t = GetExportsTool;
        let r = t.execute(&json!({"filter": "dll"})).unwrap();
        let exps = r["data"].as_array().unwrap();
        assert!(!exps.is_empty());
        for e in exps {
            assert!(e["name"].as_str().unwrap().to_lowercase().contains("dll"));
        }
    }

    #[test]
    fn test_compute_hash_sha256() {
        let t = ComputeHashTool;
        let r = t.execute(&json!({"data": "deadbeef"})).unwrap();
        assert_eq!(r["data"]["algorithm"], "sha256");
        assert!(r["data"]["hash"].is_string());
        assert_eq!(r["data"]["hash"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn test_compute_hash_md5() {
        let t = ComputeHashTool;
        let r = t.execute(&json!({"data": "cafebabe", "algorithm": "md5"})).unwrap();
        assert_eq!(r["data"]["algorithm"], "md5");
    }

    #[test]
    fn test_compute_hash_crc32() {
        let t = ComputeHashTool;
        let r = t.execute(&json!({"data": "00010203", "algorithm": "crc32"})).unwrap();
        assert_eq!(r["data"]["algorithm"], "crc32");
        assert_eq!(r["data"]["hash"].as_str().unwrap().len(), 8);
    }

    #[test]
    fn test_compute_hash_bad_algo() {
        let t = ComputeHashTool;
        assert!(t.execute(&json!({"data": "aabb", "algorithm": "rainbow"})).is_err());
    }

    #[test]
    fn test_compute_hash_odd_hex() {
        let t = ComputeHashTool;
        assert!(t.execute(&json!({"data": "aab"})).is_err());
    }

    #[test]
    fn test_get_section_text() {
        let t = GetSectionTool;
        let r = t.execute(&json!({"name": ".text"})).unwrap();
        assert_eq!(r["status"], "ok");
        assert_eq!(r["data"]["name"], ".text");
        assert!(r["data"]["executable"].as_bool().unwrap());
    }

    #[test]
    fn test_get_section_with_data() {
        let t = GetSectionTool;
        let r = t.execute(&json!({"name": ".data", "include_data": true})).unwrap();
        assert!(r["data"]["data_preview"].is_string());
    }

    #[test]
    fn test_get_section_not_found() {
        let t = GetSectionTool;
        assert!(t.execute(&json!({"name": ".nonexistent"})).is_err());
    }

    #[test]
    fn test_all_builtin_handlers_count() {
        assert_eq!(all_builtin_handlers().len(), 9);
    }

    #[test]
    fn test_all_builtin_handlers_names() {
        let handlers = all_builtin_handlers();
        let names: Vec<&str> = handlers.iter().map(|h| h.name()).collect();
        assert!(names.contains(&"disassemble_at"));
        assert!(names.contains(&"get_imports"));
        assert!(names.contains(&"compute_hash"));
    }
}

