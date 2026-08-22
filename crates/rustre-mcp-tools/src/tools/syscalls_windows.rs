//! MCP wrappers for the rustre-syscalls_windows crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct SyscallsWindowsFormatNtstatusWireV2Tool;

pub struct SyscallsWindowsNtToWin32PathTool;

pub struct SyscallsWindowsLookupWin32ApiTool;

pub struct SyscallsWindowsApisByModuleTool;

pub struct SyscallsWindowsIsSystemPathTool;

pub struct SyscallsWindowsDecodeFileAccessTool;

pub struct SyscallsWindowsDecodeAllocTypeTool;

pub struct SyscallsWindowsIsCleanX64StubTool;

pub struct SyscallsWindowsIsCleanX86StubTool;

pub struct SyscallsWindowsDetectHookTypeTool;

pub struct SyscallsWindowsIsDangerousPrivilegeTool;

pub struct SyscallsWindowsNtToWin32RegPathTool;

pub struct SyscallsWindowsIsPersistenceRegistryKeyTool;

pub struct SyscallsWindowsBuildVersionSsnTableTool;

pub struct SyscallsWindowsIsCleanStubDualTool;

pub struct SyscallsWindowsArchListTool;

pub struct SyscallsWindowsVersionListTool;

pub struct SyscallsWindowsFormatNtstatusWireV3Tool;

pub struct SyscallsWindowsIsSystemPathWireV2Tool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (SyscallsWindowsFormatNtstatusWireV2Tool::definition(), Box::new(SyscallsWindowsFormatNtstatusWireV2Tool)),
        (SyscallsWindowsNtToWin32PathTool::definition(), Box::new(SyscallsWindowsNtToWin32PathTool)),
        (SyscallsWindowsLookupWin32ApiTool::definition(), Box::new(SyscallsWindowsLookupWin32ApiTool)),
        (SyscallsWindowsApisByModuleTool::definition(), Box::new(SyscallsWindowsApisByModuleTool)),
        (SyscallsWindowsIsSystemPathTool::definition(), Box::new(SyscallsWindowsIsSystemPathTool)),
        (SyscallsWindowsDecodeFileAccessTool::definition(), Box::new(SyscallsWindowsDecodeFileAccessTool)),
        (SyscallsWindowsDecodeAllocTypeTool::definition(), Box::new(SyscallsWindowsDecodeAllocTypeTool)),
        (SyscallsWindowsIsCleanX64StubTool::definition(), Box::new(SyscallsWindowsIsCleanX64StubTool)),
        (SyscallsWindowsIsCleanX86StubTool::definition(), Box::new(SyscallsWindowsIsCleanX86StubTool)),
        (SyscallsWindowsDetectHookTypeTool::definition(), Box::new(SyscallsWindowsDetectHookTypeTool)),
        (SyscallsWindowsIsDangerousPrivilegeTool::definition(), Box::new(SyscallsWindowsIsDangerousPrivilegeTool)),
        (SyscallsWindowsNtToWin32RegPathTool::definition(), Box::new(SyscallsWindowsNtToWin32RegPathTool)),
        (SyscallsWindowsIsPersistenceRegistryKeyTool::definition(), Box::new(SyscallsWindowsIsPersistenceRegistryKeyTool)),
        (SyscallsWindowsBuildVersionSsnTableTool::definition(), Box::new(SyscallsWindowsBuildVersionSsnTableTool)),
        (SyscallsWindowsIsCleanStubDualTool::definition(), Box::new(SyscallsWindowsIsCleanStubDualTool)),
        (SyscallsWindowsArchListTool::definition(), Box::new(SyscallsWindowsArchListTool)),
        (SyscallsWindowsVersionListTool::definition(), Box::new(SyscallsWindowsVersionListTool)),
        (SyscallsWindowsFormatNtstatusWireV3Tool::definition(), Box::new(SyscallsWindowsFormatNtstatusWireV3Tool)),
        (SyscallsWindowsIsSystemPathWireV2Tool::definition(), Box::new(SyscallsWindowsIsSystemPathWireV2Tool)),
    ]
}
