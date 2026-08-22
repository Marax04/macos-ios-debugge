//! MCP wrappers for the rustre-forensics_fs crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{artifact_to_json, read_path_or_data};

pub struct ForensicsFsPrefetchParseTool;

pub struct ForensicsFsPrefetchSummaryTool;

pub struct ForensicsFsLnkParseTool;

pub struct ForensicsFsMemFsNodeV2FileSizeTool;

pub struct ForensicsFsMemoryFsNewRootTool;

pub struct ForensicsFsMemFsNodeV2IsFileTool;
impl ForensicsFsMemFsNodeV2IsFileTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_memfs_node_v2_is_file".to_string(), description: "MemFsNodeV2::new_file then is_file/is_dir via rustre_forensics_fs::MemFsNodeV2.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"inode":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsMemFsNodeV2IsFileTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).unwrap_or("f.txt"); let inode = args.get("inode").and_then(Value::as_u64).unwrap_or(2); let n = rustre_forensics_fs::MemFsNodeV2::new_file(name, b"hello".to_vec(), inode); Ok(ToolResult::text(json!({"is_file":n.is_file(),"is_dir":n.is_dir(),"size":n.size(),"inode":n.inode,"source":"rustre_forensics_fs::MemFsNodeV2::is_file"}).to_string())) } }

pub struct ForensicsFsMemFsNodeV2IsDirCheckTool;
impl ForensicsFsMemFsNodeV2IsDirCheckTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_memfs_node_v2_is_dir_check".to_string(), description: "MemFsNodeV2::new_dir then is_dir/size via rustre_forensics_fs::MemFsNodeV2::new_dir.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"inode":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsMemFsNodeV2IsDirCheckTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).unwrap_or("d"); let inode = args.get("inode").and_then(Value::as_u64).unwrap_or(1); let n = rustre_forensics_fs::MemFsNodeV2::new_dir(name, inode); Ok(ToolResult::text(json!({"is_dir":n.is_dir(),"is_file":n.is_file(),"size":n.size(),"inode":n.inode,"source":"rustre_forensics_fs::MemFsNodeV2::new_dir"}).to_string())) } }

pub struct ForensicsFsMemFsNodeV2SizeFileTool;
impl ForensicsFsMemFsNodeV2SizeFileTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_memfs_node_v2_size_file".to_string(), description: "Return MemFsNodeV2::size for a file built from arbitrary bytes via rustre_forensics_fs::MemFsNodeV2::size.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsMemFsNodeV2SizeFileTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = crate::args_to_bytes(&args)?; let n = rustre_forensics_fs::MemFsNodeV2::new_file("f", data.clone(), 7); Ok(ToolResult::text(json!({"size":n.size(),"input_len":data.len(),"source":"rustre_forensics_fs::MemFsNodeV2::size"}).to_string())) } }

pub struct ForensicsFsMemFsNodeFileReadBytesTool;
impl ForensicsFsMemFsNodeFileReadBytesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_memfs_node_file_read_bytes".to_string(), description: "MemFsNode::File read_bytes roundtrip via rustre_forensics_fs::MemFsNode::read_bytes.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsMemFsNodeFileReadBytesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = crate::args_to_bytes(&args)?; let n = rustre_forensics_fs::MemFsNode::File(data.clone()); let r = n.read_bytes().unwrap_or_default(); Ok(ToolResult::text(json!({"is_file":n.is_file(),"is_dir":n.is_dir(),"out_hex":crate::hex_encode(&r),"len":r.len(),"source":"rustre_forensics_fs::MemFsNode::read_bytes"}).to_string())) } }

pub struct ForensicsFsMemFsNodeDirChildrenTool;
impl ForensicsFsMemFsNodeDirChildrenTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_memfs_node_dir_children".to_string(), description: "MemFsNode::Directory::children listing via rustre_forensics_fs::MemFsNode::children.".to_string(), input_schema: json!({"type":"object","properties":{"names":{"type":"array","items":{"type":"string"}}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsMemFsNodeDirChildrenTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let names: Vec<String> = args.get("names").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_else(|| vec!["a".into(),"b".into()]); let entries: Vec<(String, rustre_forensics_fs::MemFsNode)> = names.iter().map(|n| (n.clone(), rustre_forensics_fs::MemFsNode::File(vec![0]))).collect(); let d = rustre_forensics_fs::MemFsNode::Directory(entries); let children: Vec<String> = d.children().map(|v| v.into_iter().map(String::from).collect()).unwrap_or_default(); Ok(ToolResult::text(json!({"count":children.len(),"children":children,"source":"rustre_forensics_fs::MemFsNode::children"}).to_string())) } }

pub struct ForensicsFsMemFsNodeDirChildByNameTool;
impl ForensicsFsMemFsNodeDirChildByNameTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_memfs_node_dir_child_by_name".to_string(), description: "MemFsNode::Directory::child lookup by name via rustre_forensics_fs::MemFsNode::child.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"query":{"type":"string"}},"required":["name","query"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsMemFsNodeDirChildByNameTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("name".into()))?.to_string(); let query = args.get("query").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("query".into()))?; let d = rustre_forensics_fs::MemFsNode::Directory(vec![(name.clone(), rustre_forensics_fs::MemFsNode::File(vec![1,2,3]))]); let found = d.child(query).is_some(); Ok(ToolResult::text(json!({"found":found,"queried":query,"present":name,"source":"rustre_forensics_fs::MemFsNode::child"}).to_string())) } }

pub struct ForensicsFsMemFsNodeLazyFileReadTool;
impl ForensicsFsMemFsNodeLazyFileReadTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_memfs_node_lazy_file_read".to_string(), description: "MemFsNode::LazyFile invoked via rustre_forensics_fs::MemFsNode::read_bytes.".to_string(), input_schema: json!({"type":"object","properties":{"value":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsMemFsNodeLazyFileReadTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let v = args.get("value").and_then(Value::as_u64).unwrap_or(42) as u8; let n = rustre_forensics_fs::MemFsNode::LazyFile(Box::new(move || vec![v])); let r = n.read_bytes().unwrap_or_default(); Ok(ToolResult::text(json!({"out_hex":crate::hex_encode(&r),"len":r.len(),"is_file":n.is_file(),"source":"rustre_forensics_fs::MemFsNode::LazyFile"}).to_string())) } }

pub struct ForensicsFsMemFsNodeDirReadBytesNoneTool;
impl ForensicsFsMemFsNodeDirReadBytesNoneTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_memfs_node_dir_read_bytes_none".to_string(), description: "MemFsNode::Directory::read_bytes returns None via rustre_forensics_fs::MemFsNode::read_bytes.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsMemFsNodeDirReadBytesNoneTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let d = rustre_forensics_fs::MemFsNode::Directory(vec![]); Ok(ToolResult::text(json!({"read_bytes_is_none":d.read_bytes().is_none(),"is_dir":d.is_dir(),"source":"rustre_forensics_fs::MemFsNode::read_bytes"}).to_string())) } }

pub struct ForensicsFsMemoryFsRootInodeTool;
impl ForensicsFsMemoryFsRootInodeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_memory_fs_root_inode".to_string(), description: "MemoryFs::new + root().inode via rustre_forensics_fs::MemoryFs::root.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsMemoryFsRootInodeTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let fs = rustre_forensics_fs::MemoryFs::new(); let r = fs.root(); Ok(ToolResult::text(json!({"root_inode":r.inode,"is_dir":r.is_dir(),"name":r.name,"source":"rustre_forensics_fs::MemoryFs::root"}).to_string())) } }

pub struct ForensicsFsMemoryFsIntoRootTool;
impl ForensicsFsMemoryFsIntoRootTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_memory_fs_into_root".to_string(), description: "MemoryFs::into_root consumes fs via rustre_forensics_fs::MemoryFs::into_root.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsMemoryFsIntoRootTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let fs = rustre_forensics_fs::MemoryFs::new(); let root = fs.into_root(); Ok(ToolResult::text(json!({"inode":root.inode,"is_dir":root.is_dir(),"name":root.name,"source":"rustre_forensics_fs::MemoryFs::into_root"}).to_string())) } }

pub struct ForensicsFsMemFsV2WalkerRootTool;
impl ForensicsFsMemFsV2WalkerRootTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_memfs_v2_walker_root".to_string(), description: "MemFsV2Walker yields root first via rustre_forensics_fs::MemFsV2Walker::new.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsMemFsV2WalkerRootTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let fs = rustre_forensics_fs::MemoryFs::new(); let mut w = rustre_forensics_fs::MemFsV2Walker::new(&fs); let first = w.next(); Ok(ToolResult::text(json!({"first_path":first.as_ref().map(|(p,_)| p.clone()),"first_is_dir":first.as_ref().map(|(_,d)| *d),"source":"rustre_forensics_fs::MemFsV2Walker"}).to_string())) } }

pub struct ForensicsFsToExportDirSingleFileTool;
impl ForensicsFsToExportDirSingleFileTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_to_export_dir_single_file".to_string(), description: "Export a single MemFsNodeV2 file tree via rustre_forensics_fs::to_export_dir into a temp dir.".to_string(), input_schema: json!({"type":"object","properties":{"content":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsToExportDirSingleFileTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let content = args.get("content").and_then(Value::as_str).unwrap_or("hi").to_string(); let mut d = rustre_forensics_fs::MemFsNodeV2::new_dir("root", 1); d.add_child(rustre_forensics_fs::MemFsNodeV2::new_file("a.txt", content.into_bytes(), 2)); let tmp = std::env::temp_dir().join(format!("rustre_fs_wire_{}", std::process::id())); let _ = std::fs::remove_dir_all(&tmp); rustre_forensics_fs::to_export_dir(&d, &tmp).map_err(|e| McpError::InternalError(e.to_string()))?; let exists = tmp.join("a.txt").exists(); let _ = std::fs::remove_dir_all(&tmp); Ok(ToolResult::text(json!({"exported":exists,"source":"rustre_forensics_fs::to_export_dir"}).to_string())) } }

pub struct ForensicsFsInodeTableNewLenEmptyTool;
impl ForensicsFsInodeTableNewLenEmptyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_inode_table_new_len_empty".to_string(), description: "InodeTable::new + len + is_empty via rustre_forensics_fs::inode::InodeTable.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsInodeTableNewLenEmptyTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let t = rustre_forensics_fs::inode::InodeTable::new(); Ok(ToolResult::text(json!({"len":t.len(),"is_empty":t.is_empty(),"total_allocated":t.total_allocated_size(),"source":"rustre_forensics_fs::inode::InodeTable::new"}).to_string())) } }

pub struct ForensicsFsInodeTableInsertGetTool;
impl ForensicsFsInodeTableInsertGetTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_inode_table_insert_get".to_string(), description: "InodeTable::insert then get via rustre_forensics_fs::inode::InodeTable::insert.".to_string(), input_schema: json!({"type":"object","properties":{"inode_num":{"type":"integer"},"name":{"type":"string"},"size":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsInodeTableInsertGetTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_forensics_fs::inode::{Inode, InodeTable}; let n = args.get("inode_num").and_then(Value::as_u64).unwrap_or(42); let name = args.get("name").and_then(Value::as_str).unwrap_or("f.txt").to_string(); let size = args.get("size").and_then(Value::as_u64).unwrap_or(1024); let ino = Inode { inode_num:n, name:name.clone(), size, alloc_size:size, flags:0, link_count:1, uid:0, gid:0, mode:0o100644, atime:0, mtime:0, ctime:0, crtime:0, data_runs:vec![] }; let mut t = InodeTable::new(); t.insert(ino); let got = t.get(n).map(|i| i.name.clone()); Ok(ToolResult::text(json!({"got":got,"len":t.len(),"total_alloc":t.total_allocated_size(),"source":"rustre_forensics_fs::inode::InodeTable::insert"}).to_string())) } }

pub struct ForensicsFsInodeTableFindByNameTool;
impl ForensicsFsInodeTableFindByNameTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_inode_table_find_by_name".to_string(), description: "InodeTable::find_by_name via rustre_forensics_fs::inode::InodeTable::find_by_name.".to_string(), input_schema: json!({"type":"object","properties":{"query":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsInodeTableFindByNameTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_forensics_fs::inode::{Inode, InodeTable}; let q = args.get("query").and_then(Value::as_str).unwrap_or("evil"); let mut t = InodeTable::new(); for (i, n) in ["evil.exe","good.txt","EvIl2.dll"].iter().enumerate() { t.insert(Inode { inode_num:(i as u64)+1, name:(*n).into(), size:100, alloc_size:512, flags:0, link_count:1, uid:0, gid:0, mode:0o100644, atime:0, mtime:0, ctime:0, crtime:0, data_runs:vec![] }); } let found: Vec<String> = t.find_by_name(q).into_iter().map(|i| i.name.clone()).collect(); Ok(ToolResult::text(json!({"count":found.len(),"names":found,"source":"rustre_forensics_fs::inode::InodeTable::find_by_name"}).to_string())) } }

pub struct ForensicsFsInodeTableFindDeletedTool;
impl ForensicsFsInodeTableFindDeletedTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_inode_table_find_deleted".to_string(), description: "InodeTable::find_deleted via rustre_forensics_fs::inode::InodeTable::find_deleted.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsInodeTableFindDeletedTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_forensics_fs::inode::{Inode, InodeTable, InodeFlags}; let mut t = InodeTable::new(); t.insert(Inode { inode_num:1, name:"live.txt".into(), size:100, alloc_size:512, flags:0, link_count:1, uid:0, gid:0, mode:0o100644, atime:0, mtime:0, ctime:0, crtime:0, data_runs:vec![] }); t.insert(Inode { inode_num:2, name:"orphan".into(), size:200, alloc_size:512, flags:0, link_count:0, uid:0, gid:0, mode:0o100644, atime:0, mtime:0, ctime:0, crtime:0, data_runs:vec![] }); t.insert(Inode { inode_num:3, name:"flagged".into(), size:0, alloc_size:0, flags:InodeFlags::DELETED, link_count:1, uid:0, gid:0, mode:0, atime:0, mtime:0, ctime:0, crtime:0, data_runs:vec![] }); let dels: Vec<String> = t.find_deleted().into_iter().map(|i| i.name.clone()).collect(); Ok(ToolResult::text(json!({"count":dels.len(),"deleted":dels,"source":"rustre_forensics_fs::inode::InodeTable::find_deleted"}).to_string())) } }

pub struct ForensicsFsInodeIsDirectoryTool;
impl ForensicsFsInodeIsDirectoryTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_inode_is_directory".to_string(), description: "Inode::is_directory / is_encrypted / is_deleted via rustre_forensics_fs::inode::Inode.".to_string(), input_schema: json!({"type":"object","properties":{"flags":{"type":"integer"},"mode":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsInodeIsDirectoryTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_forensics_fs::inode::Inode; let flags = args.get("flags").and_then(Value::as_u64).unwrap_or(0) as u32; let mode = args.get("mode").and_then(Value::as_u64).unwrap_or(0o040755) as u32; let ino = Inode { inode_num:1, name:"d".into(), size:0, alloc_size:0, flags, link_count:1, uid:0, gid:0, mode, atime:0, mtime:0, ctime:0, crtime:0, data_runs:vec![] }; Ok(ToolResult::text(json!({"is_directory":ino.is_directory(),"is_encrypted":ino.is_encrypted(),"is_deleted":ino.is_deleted(),"source":"rustre_forensics_fs::inode::Inode::is_directory"}).to_string())) } }

pub struct ForensicsFsDataRunNewByteSizeTool;
impl ForensicsFsDataRunNewByteSizeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_data_run_new_byte_size".to_string(), description: "DataRun::new + sparse + byte_size via rustre_forensics_fs::inode::DataRun.".to_string(), input_schema: json!({"type":"object","properties":{"lcn":{"type":"integer"},"length":{"type":"integer"},"cluster_size":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsDataRunNewByteSizeTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_forensics_fs::inode::DataRun; let lcn = args.get("lcn").and_then(Value::as_u64).unwrap_or(1000); let length = args.get("length").and_then(Value::as_u64).unwrap_or(4); let cs = args.get("cluster_size").and_then(Value::as_u64).unwrap_or(4096); let r = DataRun::new(lcn, length); let s = DataRun::sparse(length); Ok(ToolResult::text(json!({"run_bytes":r.byte_size(cs),"sparse_bytes":s.byte_size(cs),"run_is_sparse":r.sparse,"sparse_is_sparse":s.sparse,"source":"rustre_forensics_fs::inode::DataRun::byte_size"}).to_string())) } }

pub struct ForensicsFsInodeTotalRunBytesTool;
impl ForensicsFsInodeTotalRunBytesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_inode_total_run_bytes".to_string(), description: "Inode::total_run_bytes via rustre_forensics_fs::inode::Inode::total_run_bytes.".to_string(), input_schema: json!({"type":"object","properties":{"cluster_size":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsInodeTotalRunBytesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_forensics_fs::inode::{Inode, DataRun}; let cs = args.get("cluster_size").and_then(Value::as_u64).unwrap_or(4096); let ino = Inode { inode_num:1, name:"f".into(), size:0, alloc_size:0, flags:0, link_count:1, uid:0, gid:0, mode:0, atime:0, mtime:0, ctime:0, crtime:0, data_runs:vec![DataRun::new(0,3), DataRun::new(10,2), DataRun::sparse(4)] }; Ok(ToolResult::text(json!({"total_bytes":ino.total_run_bytes(cs),"cluster_size":cs,"source":"rustre_forensics_fs::inode::Inode::total_run_bytes"}).to_string())) } }

pub struct ForensicsFsTimelineEventNewTool;
impl ForensicsFsTimelineEventNewTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_timeline_event_new".to_string(), description: "TimelineEvent::new + builders via rustre_forensics_fs::timeline::TimelineEvent::new.".to_string(), input_schema: json!({"type":"object","properties":{"ts":{"type":"integer"},"path":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsTimelineEventNewTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_forensics_fs::timeline::{TimelineEvent, TimelineEventType}; let ts = args.get("ts").and_then(Value::as_u64).unwrap_or(1_700_000_000); let path = args.get("path").and_then(Value::as_str).unwrap_or("/tmp/x").to_string(); let ev = TimelineEvent::new(ts, TimelineEventType::Create, path.clone()).with_process("proc", 42).with_size(1024).with_inode(7).with_extra("k","v"); Ok(ToolResult::text(json!({"type_name":ev.type_name(),"pid":ev.pid,"process":ev.process,"size":ev.size,"inode":ev.inode,"extra_len":ev.extra.len(),"source":"rustre_forensics_fs::timeline::TimelineEvent::new"}).to_string())) } }

pub struct ForensicsFsTimelineEventTypeKindNameTool;
impl ForensicsFsTimelineEventTypeKindNameTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_timeline_event_type_kind_name".to_string(), description: "TimelineEventType::kind_name for all variants via rustre_forensics_fs::timeline::TimelineEventType::kind_name.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsTimelineEventTypeKindNameTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_forensics_fs::timeline::TimelineEventType as T; let all = [T::Create, T::Modify, T::Access, T::Delete, T::Move { from: "/a".into() }, T::HardLink, T::SymLink, T::PermChange, T::OwnerChange, T::Mount, T::Unmount, T::Execute]; let names: Vec<String> = all.iter().map(|t| t.kind_name().to_string()).collect(); let displays: Vec<String> = all.iter().map(|t| t.to_string()).collect(); Ok(ToolResult::text(json!({"count":names.len(),"kind_names":names,"displays":displays,"source":"rustre_forensics_fs::timeline::TimelineEventType::kind_name"}).to_string())) } }

pub struct ForensicsFsTimelinePushSortTool;
impl ForensicsFsTimelinePushSortTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_timeline_push_sort".to_string(), description: "Timeline::push + sort_by_time via rustre_forensics_fs::timeline::Timeline.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsTimelinePushSortTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_forensics_fs::timeline::{Timeline, TimelineEvent, TimelineEventType}; let mut t = Timeline::new(); t.push(TimelineEvent::new(300, TimelineEventType::Create, "/c")); t.push(TimelineEvent::new(100, TimelineEventType::Modify, "/a")); t.push(TimelineEvent::new(200, TimelineEventType::Access, "/b")); t.sort_by_time(); let order: Vec<u64> = t.events().map(|e| e.timestamp).collect(); Ok(ToolResult::text(json!({"order":order,"source":"rustre_forensics_fs::timeline::Timeline::sort_by_time"}).to_string())) } }

pub struct ForensicsFsTimelineFilterByTypeTool;
impl ForensicsFsTimelineFilterByTypeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_timeline_filter_by_type".to_string(), description: "Timeline::filter_by_type via rustre_forensics_fs::timeline::Timeline::filter_by_type.".to_string(), input_schema: json!({"type":"object","properties":{"kind":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsTimelineFilterByTypeTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_forensics_fs::timeline::{Timeline, TimelineEvent, TimelineEventType}; let kind = args.get("kind").and_then(Value::as_str).unwrap_or("Create"); let mut t = Timeline::new(); t.push(TimelineEvent::new(1, TimelineEventType::Create, "/a")); t.push(TimelineEvent::new(2, TimelineEventType::Modify, "/b")); t.push(TimelineEvent::new(3, TimelineEventType::Create, "/c")); let hits = t.filter_by_type(kind).len(); Ok(ToolResult::text(json!({"kind":kind,"matches":hits,"source":"rustre_forensics_fs::timeline::Timeline::filter_by_type"}).to_string())) } }

pub struct ForensicsFsTimelineFilterByTimeTool;
impl ForensicsFsTimelineFilterByTimeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_timeline_filter_by_time".to_string(), description: "Timeline::filter_by_time window via rustre_forensics_fs::timeline::Timeline::filter_by_time.".to_string(), input_schema: json!({"type":"object","properties":{"start":{"type":"integer"},"end":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsTimelineFilterByTimeTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_forensics_fs::timeline::{Timeline, TimelineEvent, TimelineEventType}; let start = args.get("start").and_then(Value::as_u64).unwrap_or(10); let end = args.get("end").and_then(Value::as_u64).unwrap_or(30); let mut t = Timeline::new(); for ts in [5u64, 15, 20, 25, 40] { t.push(TimelineEvent::new(ts, TimelineEventType::Access, "/x")); } let n = t.filter_by_time(start, end).len(); Ok(ToolResult::text(json!({"start":start,"end":end,"in_window":n,"source":"rustre_forensics_fs::timeline::Timeline::filter_by_time"}).to_string())) } }

pub struct ForensicsFsTimelineHotPathsTool;
impl ForensicsFsTimelineHotPathsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_timeline_hot_paths".to_string(), description: "Timeline::hot_paths top-N via rustre_forensics_fs::timeline::Timeline::hot_paths.".to_string(), input_schema: json!({"type":"object","properties":{"top_n":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsTimelineHotPathsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_forensics_fs::timeline::{Timeline, TimelineEvent, TimelineEventType}; let n = args.get("top_n").and_then(Value::as_u64).unwrap_or(2) as usize; let mut t = Timeline::new(); for _ in 0..5 { t.push(TimelineEvent::new(1, TimelineEventType::Access, "/hot")); } for _ in 0..2 { t.push(TimelineEvent::new(1, TimelineEventType::Access, "/warm")); } t.push(TimelineEvent::new(1, TimelineEventType::Access, "/cold")); let hot = t.hot_paths(n); Ok(ToolResult::text(json!({"top_n":n,"hot":hot,"source":"rustre_forensics_fs::timeline::Timeline::hot_paths"}).to_string())) } }

pub struct ForensicsFsTimelineCsvRoundtripTool;
impl ForensicsFsTimelineCsvRoundtripTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_timeline_csv_roundtrip".to_string(), description: "Timeline::to_csv + from_csv roundtrip via rustre_forensics_fs::timeline::Timeline.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsTimelineCsvRoundtripTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_forensics_fs::timeline::{Timeline, TimelineEvent, TimelineEventType}; let mut t = Timeline::new(); t.push(TimelineEvent::new(100, TimelineEventType::Create, "/a")); t.push(TimelineEvent::new(200, TimelineEventType::Modify, "/b")); let csv = t.to_csv(); let round = Timeline::from_csv(&csv).map_err(|e| McpError::InternalError(e.to_string()))?; let cnt = round.events().count(); Ok(ToolResult::text(json!({"csv_bytes":csv.len(),"roundtrip_events":cnt,"source":"rustre_forensics_fs::timeline::Timeline::to_csv"}).to_string())) } }

pub struct ForensicsFsTimelineReportTool;
impl ForensicsFsTimelineReportTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_timeline_report".to_string(), description: "Timeline::report summary via rustre_forensics_fs::timeline::Timeline::report.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsTimelineReportTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_forensics_fs::timeline::{Timeline, TimelineEvent, TimelineEventType}; let mut t = Timeline::new(); t.push(TimelineEvent::new(1, TimelineEventType::Create, "/a")); t.push(TimelineEvent::new(2, TimelineEventType::Modify, "/a")); t.push(TimelineEvent::new(3, TimelineEventType::Delete, "/a")); let r = t.report(); Ok(ToolResult::text(json!({"report_debug":format!("{:?}", r),"source":"rustre_forensics_fs::timeline::Timeline::report"}).to_string())) } }

pub struct ForensicsFsDetectPrefetchTool;
impl ForensicsFsDetectPrefetchTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "forensics_fs_detect_prefetch".to_string(),
            description: "Detect Windows Prefetch (.pf/SCCA) artifact from a path and its bytes.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "data": {"description": "Optional byte array or hex string; if omitted, read from path"}
                },
                "required": ["path"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ForensicsFsDetectPrefetchTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let (path, data) = read_path_or_data(&args)?;
        let art = rustre_forensics_fs::artifacts::detect_prefetch(&path, &data);
        Ok(ToolResult::text(json!({
            "path": path,
            "detected": art.is_some(),
            "artifact": art.as_ref().map(artifact_to_json),
        }).to_string()))
    }
}

pub struct ForensicsFsDetectLnkTool;
impl ForensicsFsDetectLnkTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "forensics_fs_detect_lnk".to_string(),
            description: "Detect Windows LNK shortcut artifact from a path and its bytes.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "data": {"description": "Optional byte array or hex string; if omitted, read from path"}
                },
                "required": ["path"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ForensicsFsDetectLnkTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let (path, data) = read_path_or_data(&args)?;
        let art = rustre_forensics_fs::artifacts::detect_lnk(&path, &data);
        Ok(ToolResult::text(json!({
            "path": path,
            "detected": art.is_some(),
            "artifact": art.as_ref().map(artifact_to_json),
        }).to_string()))
    }
}

pub struct ForensicsFsDetectRegistryHiveTool;
impl ForensicsFsDetectRegistryHiveTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "forensics_fs_detect_registry_hive".to_string(),
            description: "Detect a Windows Registry hive (regf magic + known filename) from a path and its bytes.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "data": {"description": "Optional byte array or hex string; if omitted, read from path"}
                },
                "required": ["path"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ForensicsFsDetectRegistryHiveTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let (path, data) = read_path_or_data(&args)?;
        let art = rustre_forensics_fs::artifacts::detect_registry_hive(&path, &data);
        Ok(ToolResult::text(json!({
            "path": path,
            "detected": art.is_some(),
            "artifact": art.as_ref().map(artifact_to_json),
        }).to_string()))
    }
}

pub struct ForensicsFsDetectEvtxTool;
impl ForensicsFsDetectEvtxTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_detect_evtx".to_string(), description: "Detect Windows EVTX event log artifact from a path and its bytes.".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"data":{}},"required":["path"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsDetectEvtxTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let (path, data) = read_path_or_data(&args)?; let art = rustre_forensics_fs::artifacts::detect_evtx(&path, &data); Ok(ToolResult::text(json!({"path":path,"detected":art.is_some(),"artifact":art.as_ref().map(artifact_to_json),"source":"rustre_forensics_fs::artifacts::detect_evtx"}).to_string())) } }

pub struct ForensicsFsDetectBrowserDbTool;
impl ForensicsFsDetectBrowserDbTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_detect_browser_db".to_string(), description: "Detect a browser artifact database (History, Cookies, etc.) by path.".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsDetectBrowserDbTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let path = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?.to_string(); let art = rustre_forensics_fs::artifacts::detect_browser_db(&path); Ok(ToolResult::text(json!({"path":path,"detected":art.is_some(),"artifact":art.as_ref().map(artifact_to_json),"source":"rustre_forensics_fs::artifacts::detect_browser_db"}).to_string())) } }

pub struct ForensicsFsDetectMemoryDumpTool;
impl ForensicsFsDetectMemoryDumpTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_detect_memory_dump".to_string(), description: "Detect a memory-dump artifact (raw/lime/crash-dump) from a path and its bytes.".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"data":{}},"required":["path"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsDetectMemoryDumpTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let (path, data) = read_path_or_data(&args)?; let art = rustre_forensics_fs::artifacts::detect_memory_dump(&path, &data); Ok(ToolResult::text(json!({"path":path,"detected":art.is_some(),"artifact":art.as_ref().map(artifact_to_json),"source":"rustre_forensics_fs::artifacts::detect_memory_dump"}).to_string())) } }

pub struct ForensicsFsDetectDroppedPayloadTool;
impl ForensicsFsDetectDroppedPayloadTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_detect_dropped_payload".to_string(), description: "Detect a dropped payload (PE with anomalous location or attribs) by path and bytes.".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"data":{}},"required":["path"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsDetectDroppedPayloadTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let (path, data) = read_path_or_data(&args)?; let art = rustre_forensics_fs::artifacts::detect_dropped_payload(&path, &data); Ok(ToolResult::text(json!({"path":path,"detected":art.is_some(),"artifact":art.as_ref().map(artifact_to_json),"source":"rustre_forensics_fs::artifacts::detect_dropped_payload"}).to_string())) } }

pub struct ForensicsFsDetectPagefileTool;
impl ForensicsFsDetectPagefileTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_detect_pagefile".to_string(), description: "Detect a Windows pagefile/swapfile/hiberfil artifact by path.".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsDetectPagefileTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let path = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?.to_string(); let art = rustre_forensics_fs::artifacts::detect_pagefile(&path); Ok(ToolResult::text(json!({"path":path,"detected":art.is_some(),"artifact":art.as_ref().map(artifact_to_json),"source":"rustre_forensics_fs::artifacts::detect_pagefile"}).to_string())) } }

pub struct ForensicsFsDetectCertificateStoreTool;
impl ForensicsFsDetectCertificateStoreTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_detect_certificate_store".to_string(), description: "Detect a certificate store artifact by path.".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsDetectCertificateStoreTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let path = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?.to_string(); let art = rustre_forensics_fs::artifacts::detect_certificate_store(&path); Ok(ToolResult::text(json!({"path":path,"detected":art.is_some(),"artifact":art.as_ref().map(artifact_to_json),"source":"rustre_forensics_fs::artifacts::detect_certificate_store"}).to_string())) } }

pub struct ForensicsFsArtifactScannerScanPathTool;
impl ForensicsFsArtifactScannerScanPathTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_artifact_scanner_scan_path".to_string(), description: "Run ArtifactScanner::scan_path over one path+data pair and report totals + high-confidence hits.".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"data":{}},"required":["path"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsArtifactScannerScanPathTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let (path, data) = read_path_or_data(&args)?; let mut sc = rustre_forensics_fs::artifacts::ArtifactScanner::new(); sc.scan_path(&path, &data); let rep = sc.report(); let arts: Vec<Value> = sc.artifacts().iter().map(artifact_to_json).collect(); let hc: Vec<Value> = sc.high_confidence().iter().map(|a| artifact_to_json(*a)).collect(); Ok(ToolResult::text(json!({"path":path,"artifacts":arts,"high_confidence":hc,"total":rep.total,"critical":rep.critical,"high":rep.high,"source":"rustre_forensics_fs::artifacts::ArtifactScanner::scan_path"}).to_string())) } }

pub struct ForensicsFsLnkAnalyzerSummaryTool;
impl ForensicsFsLnkAnalyzerSummaryTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_lnk_analyzer_summary".to_string(), description: "Parse a LNK file and report LnkAnalyzer resolved path, suspicion flag, drive serial, and tracker GUIDs.".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"data":{}},"required":["path"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsLnkAnalyzerSummaryTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let (path, data) = read_path_or_data(&args)?; let an = rustre_forensics_fs::lnk_parser::LnkAnalyzer::from_bytes(&data).map_err(|e| McpError::InternalError(format!("lnk parse: {e}")))?; Ok(ToolResult::text(json!({"path":path,"resolved_path":an.resolved_path(),"is_suspicious":an.is_suspicious(),"drive_serial":an.drive_serial(),"tracker_guids":an.tracker_guids(),"source":"rustre_forensics_fs::lnk_parser::LnkAnalyzer"}).to_string())) } }

pub struct ForensicsFsLnkFileTargetPathTool;
impl ForensicsFsLnkFileTargetPathTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_lnk_file_target_path".to_string(), description: "Parse a LNK file and return LnkFile::target_path and summary text.".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"data":{}},"required":["path"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsLnkFileTargetPathTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let (path, data) = read_path_or_data(&args)?; let lnk = rustre_forensics_fs::lnk_parser::LnkFile::parse(&data).map_err(|e| McpError::InternalError(format!("lnk parse: {e}")))?; Ok(ToolResult::text(json!({"path":path,"target_path":lnk.target_path(),"summary":lnk.summary(),"source":"rustre_forensics_fs::lnk_parser::LnkFile::target_path"}).to_string())) } }

pub struct ForensicsFsPrefetchAnalyzerReportTool;
impl ForensicsFsPrefetchAnalyzerReportTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_prefetch_analyzer_report".to_string(), description: "Parse a Prefetch file and report PrefetchAnalyzer directories, modules, average run interval, and a CSV line.".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"data":{}},"required":["path"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsPrefetchAnalyzerReportTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let (path, data) = read_path_or_data(&args)?; let an = rustre_forensics_fs::prefetch_analyzer::PrefetchAnalyzer::from_bytes(&data).map_err(|e| McpError::InternalError(format!("prefetch parse: {e}")))?; Ok(ToolResult::text(json!({"path":path,"referenced_directories":an.referenced_directories(),"module_names":an.module_names(),"avg_run_interval_secs":an.avg_run_interval_secs(),"csv_line":an.to_csv_line(),"source":"rustre_forensics_fs::prefetch_analyzer::PrefetchAnalyzer"}).to_string())) } }

pub struct ForensicsFsPrefetchPatternMatcherRiskTool;
impl ForensicsFsPrefetchPatternMatcherRiskTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_prefetch_pattern_matcher_risk".to_string(), description: "Parse a Prefetch file and run PatternMatcher heuristics (loader/path suspicion + risk score).".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"data":{}},"required":["path"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsPrefetchPatternMatcherRiskTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let (path, data) = read_path_or_data(&args)?; let pf = rustre_forensics_fs::prefetch_analyzer::PrefetchFile::parse(&data).map_err(|e| McpError::InternalError(format!("prefetch parse: {e}")))?; let has_loader = rustre_forensics_fs::prefetch_analyzer::PatternMatcher::has_suspicious_loader(&pf); let has_path = rustre_forensics_fs::prefetch_analyzer::PatternMatcher::has_suspicious_path(&pf); let score = rustre_forensics_fs::prefetch_analyzer::PatternMatcher::risk_score(&pf); Ok(ToolResult::text(json!({"path":path,"has_suspicious_loader":has_loader,"has_suspicious_path":has_path,"risk_score":score,"source":"rustre_forensics_fs::prefetch_analyzer::PatternMatcher"}).to_string())) } }

pub struct ForensicsFsPrefetchFileLoadedModulesTool;
impl ForensicsFsPrefetchFileLoadedModulesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "forensics_fs_prefetch_file_loaded_modules".to_string(), description: "Parse a Prefetch file and return PrefetchFile::loaded_modules list plus summary text.".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"data":{}},"required":["path"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ForensicsFsPrefetchFileLoadedModulesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let (path, data) = read_path_or_data(&args)?; let pf = rustre_forensics_fs::prefetch_analyzer::PrefetchFile::parse(&data).map_err(|e| McpError::InternalError(format!("prefetch parse: {e}")))?; let mods: Vec<String> = pf.loaded_modules().into_iter().map(str::to_string).collect(); Ok(ToolResult::text(json!({"path":path,"loaded_modules":mods,"count":pf.file_metrics.len(),"summary":pf.summary(),"source":"rustre_forensics_fs::prefetch_analyzer::PrefetchFile::loaded_modules"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (ForensicsFsPrefetchParseTool::definition(), Box::new(ForensicsFsPrefetchParseTool)),
        (ForensicsFsPrefetchSummaryTool::definition(), Box::new(ForensicsFsPrefetchSummaryTool)),
        (ForensicsFsLnkParseTool::definition(), Box::new(ForensicsFsLnkParseTool)),
        (ForensicsFsMemFsNodeV2FileSizeTool::definition(), Box::new(ForensicsFsMemFsNodeV2FileSizeTool)),
        (ForensicsFsMemoryFsNewRootTool::definition(), Box::new(ForensicsFsMemoryFsNewRootTool)),
        (ForensicsFsMemFsNodeV2IsFileTool::definition(), Box::new(ForensicsFsMemFsNodeV2IsFileTool)),
        (ForensicsFsMemFsNodeV2IsDirCheckTool::definition(), Box::new(ForensicsFsMemFsNodeV2IsDirCheckTool)),
        (ForensicsFsMemFsNodeV2SizeFileTool::definition(), Box::new(ForensicsFsMemFsNodeV2SizeFileTool)),
        (ForensicsFsMemFsNodeFileReadBytesTool::definition(), Box::new(ForensicsFsMemFsNodeFileReadBytesTool)),
        (ForensicsFsMemFsNodeDirChildrenTool::definition(), Box::new(ForensicsFsMemFsNodeDirChildrenTool)),
        (ForensicsFsMemFsNodeDirChildByNameTool::definition(), Box::new(ForensicsFsMemFsNodeDirChildByNameTool)),
        (ForensicsFsMemFsNodeLazyFileReadTool::definition(), Box::new(ForensicsFsMemFsNodeLazyFileReadTool)),
        (ForensicsFsMemFsNodeDirReadBytesNoneTool::definition(), Box::new(ForensicsFsMemFsNodeDirReadBytesNoneTool)),
        (ForensicsFsMemoryFsRootInodeTool::definition(), Box::new(ForensicsFsMemoryFsRootInodeTool)),
        (ForensicsFsMemoryFsIntoRootTool::definition(), Box::new(ForensicsFsMemoryFsIntoRootTool)),
        (ForensicsFsMemFsV2WalkerRootTool::definition(), Box::new(ForensicsFsMemFsV2WalkerRootTool)),
        (ForensicsFsToExportDirSingleFileTool::definition(), Box::new(ForensicsFsToExportDirSingleFileTool)),
        (ForensicsFsInodeTableNewLenEmptyTool::definition(), Box::new(ForensicsFsInodeTableNewLenEmptyTool)),
        (ForensicsFsInodeTableInsertGetTool::definition(), Box::new(ForensicsFsInodeTableInsertGetTool)),
        (ForensicsFsInodeTableFindByNameTool::definition(), Box::new(ForensicsFsInodeTableFindByNameTool)),
        (ForensicsFsInodeTableFindDeletedTool::definition(), Box::new(ForensicsFsInodeTableFindDeletedTool)),
        (ForensicsFsInodeIsDirectoryTool::definition(), Box::new(ForensicsFsInodeIsDirectoryTool)),
        (ForensicsFsDataRunNewByteSizeTool::definition(), Box::new(ForensicsFsDataRunNewByteSizeTool)),
        (ForensicsFsInodeTotalRunBytesTool::definition(), Box::new(ForensicsFsInodeTotalRunBytesTool)),
        (ForensicsFsTimelineEventNewTool::definition(), Box::new(ForensicsFsTimelineEventNewTool)),
        (ForensicsFsTimelineEventTypeKindNameTool::definition(), Box::new(ForensicsFsTimelineEventTypeKindNameTool)),
        (ForensicsFsTimelinePushSortTool::definition(), Box::new(ForensicsFsTimelinePushSortTool)),
        (ForensicsFsTimelineFilterByTypeTool::definition(), Box::new(ForensicsFsTimelineFilterByTypeTool)),
        (ForensicsFsTimelineFilterByTimeTool::definition(), Box::new(ForensicsFsTimelineFilterByTimeTool)),
        (ForensicsFsTimelineHotPathsTool::definition(), Box::new(ForensicsFsTimelineHotPathsTool)),
        (ForensicsFsTimelineCsvRoundtripTool::definition(), Box::new(ForensicsFsTimelineCsvRoundtripTool)),
        (ForensicsFsTimelineReportTool::definition(), Box::new(ForensicsFsTimelineReportTool)),
        (ForensicsFsDetectPrefetchTool::definition(), Box::new(ForensicsFsDetectPrefetchTool)),
        (ForensicsFsDetectLnkTool::definition(), Box::new(ForensicsFsDetectLnkTool)),
        (ForensicsFsDetectRegistryHiveTool::definition(), Box::new(ForensicsFsDetectRegistryHiveTool)),
        (ForensicsFsDetectEvtxTool::definition(), Box::new(ForensicsFsDetectEvtxTool)),
        (ForensicsFsDetectBrowserDbTool::definition(), Box::new(ForensicsFsDetectBrowserDbTool)),
        (ForensicsFsDetectMemoryDumpTool::definition(), Box::new(ForensicsFsDetectMemoryDumpTool)),
        (ForensicsFsDetectDroppedPayloadTool::definition(), Box::new(ForensicsFsDetectDroppedPayloadTool)),
        (ForensicsFsDetectPagefileTool::definition(), Box::new(ForensicsFsDetectPagefileTool)),
        (ForensicsFsDetectCertificateStoreTool::definition(), Box::new(ForensicsFsDetectCertificateStoreTool)),
        (ForensicsFsArtifactScannerScanPathTool::definition(), Box::new(ForensicsFsArtifactScannerScanPathTool)),
        (ForensicsFsLnkAnalyzerSummaryTool::definition(), Box::new(ForensicsFsLnkAnalyzerSummaryTool)),
        (ForensicsFsLnkFileTargetPathTool::definition(), Box::new(ForensicsFsLnkFileTargetPathTool)),
        (ForensicsFsPrefetchAnalyzerReportTool::definition(), Box::new(ForensicsFsPrefetchAnalyzerReportTool)),
        (ForensicsFsPrefetchPatternMatcherRiskTool::definition(), Box::new(ForensicsFsPrefetchPatternMatcherRiskTool)),
        (ForensicsFsPrefetchFileLoadedModulesTool::definition(), Box::new(ForensicsFsPrefetchFileLoadedModulesTool)),
    ]
}
