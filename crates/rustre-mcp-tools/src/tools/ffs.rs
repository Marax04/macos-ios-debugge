//! MCP wrappers for the rustre-ffs crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct FfsNodeV2NewFileTool;
impl FfsNodeV2NewFileTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "forensics_fs_node_v2_new_file".to_string(),
            description: "Create a MemFsNodeV2 file and report name/inode/size/is_file.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"inode":{"type":"integer"},"len":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FfsNodeV2NewFileTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("f.bin").to_string();
        let inode = args.get("inode").and_then(Value::as_u64).unwrap_or(2);
        let len = args.get("len").and_then(Value::as_u64).unwrap_or(4) as usize;
        let n = rustre_forensics_fs::MemFsNodeV2::new_file(name, vec![0u8; len], inode);
        Ok(ToolResult::text(json!({"name":n.name,"inode":n.inode,"size":n.size(),"is_file":n.is_file(),"source":"MemFsNodeV2::new_file"}).to_string()))
    }
}

pub struct FfsNodeV2NewDirTool;
impl FfsNodeV2NewDirTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "forensics_fs_node_v2_new_dir".to_string(),
            description: "Create a MemFsNodeV2 directory and report is_dir/size.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"inode":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FfsNodeV2NewDirTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("d").to_string();
        let inode = args.get("inode").and_then(Value::as_u64).unwrap_or(1);
        let n = rustre_forensics_fs::MemFsNodeV2::new_dir(name, inode);
        Ok(ToolResult::text(json!({"name":n.name,"inode":n.inode,"is_dir":n.is_dir(),"size":n.size(),"source":"MemFsNodeV2::new_dir"}).to_string()))
    }
}

pub struct FfsNodeV2AddChildTool;
impl FfsNodeV2AddChildTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "forensics_fs_node_v2_add_child".to_string(),
            description: "Add N file children to a fresh directory node and count readdir entries.".to_string(),
            input_schema: json!({"type":"object","properties":{"count":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FfsNodeV2AddChildTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let count = args.get("count").and_then(Value::as_u64).unwrap_or(3);
        let mut d = rustre_forensics_fs::MemFsNodeV2::new_dir("root", 1);
        for i in 0..count {
            d.add_child(rustre_forensics_fs::MemFsNodeV2::new_file(format!("c{i}.txt"), vec![i as u8], 100 + i));
        }
        let entries = d.readdir_entries();
        Ok(ToolResult::text(json!({"children":entries.len(),"source":"MemFsNodeV2::add_child"}).to_string()))
    }
}

pub struct FfsNodeV2FindChildTool;
impl FfsNodeV2FindChildTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "forensics_fs_node_v2_find_child".to_string(),
            description: "Find a named child in a small directory.".to_string(),
            input_schema: json!({"type":"object","properties":{"target":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FfsNodeV2FindChildTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let target = args.get("target").and_then(Value::as_str).unwrap_or("a.txt").to_string();
        let mut d = rustre_forensics_fs::MemFsNodeV2::new_dir("d", 1);
        d.add_child(rustre_forensics_fs::MemFsNodeV2::new_file("a.txt", vec![1], 2));
        d.add_child(rustre_forensics_fs::MemFsNodeV2::new_file("b.txt", vec![2], 3));
        let found = d.find_child(&target).is_some();
        Ok(ToolResult::text(json!({"target":target,"found":found,"source":"MemFsNodeV2::find_child"}).to_string()))
    }
}

pub struct FfsNodeV2FindByInodeTool;
impl FfsNodeV2FindByInodeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "forensics_fs_node_v2_find_by_inode".to_string(),
            description: "Recursively look up a MemFsNodeV2 by inode number.".to_string(),
            input_schema: json!({"type":"object","properties":{"inode":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FfsNodeV2FindByInodeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let target = args.get("inode").and_then(Value::as_u64).unwrap_or(3);
        let mut root = rustre_forensics_fs::MemFsNodeV2::new_dir("r", 1);
        let mut sub = rustre_forensics_fs::MemFsNodeV2::new_dir("s", 2);
        sub.add_child(rustre_forensics_fs::MemFsNodeV2::new_file("x", vec![0], 3));
        root.add_child(sub);
        let found = root.find_by_inode(target).is_some();
        Ok(ToolResult::text(json!({"inode":target,"found":found,"source":"MemFsNodeV2::find_by_inode"}).to_string()))
    }
}

pub struct FfsNodeV2ReaddirTool;
impl FfsNodeV2ReaddirTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "forensics_fs_node_v2_readdir_entries".to_string(),
            description: "Return readdir_entries names for a small mixed dir.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FfsNodeV2ReaddirTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let mut d = rustre_forensics_fs::MemFsNodeV2::new_dir("d", 1);
        d.add_child(rustre_forensics_fs::MemFsNodeV2::new_file("a.txt", vec![], 2));
        d.add_child(rustre_forensics_fs::MemFsNodeV2::new_dir("sub", 3));
        let names: Vec<String> = d.readdir_entries().into_iter().map(|(_, n, _)| n).collect();
        Ok(ToolResult::text(json!({"names":names,"source":"MemFsNodeV2::readdir_entries"}).to_string()))
    }
}

pub struct FfsMemoryFsNewTool;
impl FfsMemoryFsNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "forensics_fs_memory_fs_new".to_string(),
            description: "Create a fresh MemoryFs and report root inode.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FfsMemoryFsNewTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let fs = rustre_forensics_fs::MemoryFs::new();
        Ok(ToolResult::text(json!({"root_inode":fs.root().inode,"is_dir":fs.root().is_dir(),"source":"MemoryFs::new"}).to_string()))
    }
}

pub struct FfsMemoryFsBuildEmptyTool;
impl FfsMemoryFsBuildEmptyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "forensics_fs_memory_fs_build_process_tree_empty".to_string(),
            description: "Build a MemoryFs process tree from empty slices; verify /processes dir exists.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FfsMemoryFsBuildEmptyTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let fs = rustre_forensics_fs::MemoryFs::build_process_tree(&[], &[]);
        let has_procs = fs.root().find_child("processes").is_some();
        Ok(ToolResult::text(json!({"has_processes_dir":has_procs,"source":"MemoryFs::build_process_tree"}).to_string()))
    }
}

pub struct FfsMemFsNodeFileTool;
impl FfsMemFsNodeFileTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "forensics_fs_memfs_node_file_probe".to_string(),
            description: "Construct MemFsNode::File and probe is_file/read_bytes.".to_string(),
            input_schema: json!({"type":"object","properties":{"len":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FfsMemFsNodeFileTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let len = args.get("len").and_then(Value::as_u64).unwrap_or(5) as usize;
        let n = rustre_forensics_fs::MemFsNode::File(vec![7u8; len]);
        let bytes = n.read_bytes().map(|b| b.len()).unwrap_or(0);
        Ok(ToolResult::text(json!({"is_file":n.is_file(),"is_dir":n.is_dir(),"read_bytes_len":bytes,"source":"MemFsNode::File"}).to_string()))
    }
}

pub struct FfsMemFsNodeDirTool;
impl FfsMemFsNodeDirTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "forensics_fs_memfs_node_dir_probe".to_string(),
            description: "Construct MemFsNode::Directory and report children names.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FfsMemFsNodeDirTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let n = rustre_forensics_fs::MemFsNode::Directory(vec![
            ("a".to_string(), rustre_forensics_fs::MemFsNode::File(vec![1])),
            ("b".to_string(), rustre_forensics_fs::MemFsNode::File(vec![2])),
        ]);
        let names: Vec<String> = n.children().map(|v| v.into_iter().map(|s| s.to_string()).collect()).unwrap_or_default();
        Ok(ToolResult::text(json!({"is_dir":n.is_dir(),"children":names,"source":"MemFsNode::children"}).to_string()))
    }
}

pub struct FfsMemFsNodeChildLookupTool;
impl FfsMemFsNodeChildLookupTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "forensics_fs_memfs_node_child_lookup".to_string(),
            description: "Look up a named child in a MemFsNode::Directory.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FfsMemFsNodeChildLookupTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let target = args.get("name").and_then(Value::as_str).unwrap_or("a").to_string();
        let n = rustre_forensics_fs::MemFsNode::Directory(vec![
            ("a".to_string(), rustre_forensics_fs::MemFsNode::File(vec![1])),
            ("b".to_string(), rustre_forensics_fs::MemFsNode::File(vec![2])),
        ]);
        let found = n.child(&target).is_some();
        Ok(ToolResult::text(json!({"target":target,"found":found,"source":"MemFsNode::child"}).to_string()))
    }
}

pub struct FfsNodeV2SizesTool;
impl FfsNodeV2SizesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "forensics_fs_node_v2_sizes".to_string(),
            description: "Report size() for a file and a dir MemFsNodeV2 (dir is 0).".to_string(),
            input_schema: json!({"type":"object","properties":{"len":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FfsNodeV2SizesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let len = args.get("len").and_then(Value::as_u64).unwrap_or(10) as usize;
        let f = rustre_forensics_fs::MemFsNodeV2::new_file("f", vec![0u8; len], 2);
        let d = rustre_forensics_fs::MemFsNodeV2::new_dir("d", 3);
        Ok(ToolResult::text(json!({"file_size":f.size(),"dir_size":d.size(),"source":"MemFsNodeV2::size"}).to_string()))
    }
}

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (FfsNodeV2NewFileTool::definition(), Box::new(FfsNodeV2NewFileTool)),
        (FfsNodeV2NewDirTool::definition(), Box::new(FfsNodeV2NewDirTool)),
        (FfsNodeV2AddChildTool::definition(), Box::new(FfsNodeV2AddChildTool)),
        (FfsNodeV2FindChildTool::definition(), Box::new(FfsNodeV2FindChildTool)),
        (FfsNodeV2FindByInodeTool::definition(), Box::new(FfsNodeV2FindByInodeTool)),
        (FfsNodeV2ReaddirTool::definition(), Box::new(FfsNodeV2ReaddirTool)),
        (FfsMemoryFsNewTool::definition(), Box::new(FfsMemoryFsNewTool)),
        (FfsMemoryFsBuildEmptyTool::definition(), Box::new(FfsMemoryFsBuildEmptyTool)),
        (FfsMemFsNodeFileTool::definition(), Box::new(FfsMemFsNodeFileTool)),
        (FfsMemFsNodeDirTool::definition(), Box::new(FfsMemFsNodeDirTool)),
        (FfsMemFsNodeChildLookupTool::definition(), Box::new(FfsMemFsNodeChildLookupTool)),
        (FfsNodeV2SizesTool::definition(), Box::new(FfsNodeV2SizesTool)),
    ]
}
