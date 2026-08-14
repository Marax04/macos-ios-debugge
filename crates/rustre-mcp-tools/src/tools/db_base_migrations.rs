//! MCP wrappers for the rustre-db_base_migrations crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};

pub struct DbBaseMigrationsCountTool;

pub struct DbBaseMigrationsListTool;

pub struct DbBaseMigrationsMaxVersionTool;

pub struct DbBaseMigrationsNamesTool;

pub struct DbBaseMigrationsFindByVersionTool;

pub struct DbBaseMigrationsVersionsTool;

pub struct DbBaseMigrationsMinVersionTool;

pub struct DbBaseMigrationsIsContiguousTool;

pub struct DbBaseMigrationsFirstVersionTool;

pub struct DbBaseMigrationsSummaryTool;

pub struct DbBaseMigrationsWithDownSqlTool;

pub struct DbBaseMigrationsUniqueVersionsTool;

pub struct DbBaseMigrationsTotalSqlBytesTool;

pub struct DbBaseMigrationsAvgSqlBytesTool;

pub struct DbBaseMigrationsLargestUpSqlTool;

pub struct DbBaseMigrationsHasVersionTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (DbBaseMigrationsCountTool::definition(), Box::new(DbBaseMigrationsCountTool)),
        (DbBaseMigrationsListTool::definition(), Box::new(DbBaseMigrationsListTool)),
        (DbBaseMigrationsMaxVersionTool::definition(), Box::new(DbBaseMigrationsMaxVersionTool)),
        (DbBaseMigrationsNamesTool::definition(), Box::new(DbBaseMigrationsNamesTool)),
        (DbBaseMigrationsFindByVersionTool::definition(), Box::new(DbBaseMigrationsFindByVersionTool)),
        (DbBaseMigrationsVersionsTool::definition(), Box::new(DbBaseMigrationsVersionsTool)),
        (DbBaseMigrationsMinVersionTool::definition(), Box::new(DbBaseMigrationsMinVersionTool)),
        (DbBaseMigrationsIsContiguousTool::definition(), Box::new(DbBaseMigrationsIsContiguousTool)),
        (DbBaseMigrationsFirstVersionTool::definition(), Box::new(DbBaseMigrationsFirstVersionTool)),
        (DbBaseMigrationsSummaryTool::definition(), Box::new(DbBaseMigrationsSummaryTool)),
        (DbBaseMigrationsWithDownSqlTool::definition(), Box::new(DbBaseMigrationsWithDownSqlTool)),
        (DbBaseMigrationsUniqueVersionsTool::definition(), Box::new(DbBaseMigrationsUniqueVersionsTool)),
        (DbBaseMigrationsTotalSqlBytesTool::definition(), Box::new(DbBaseMigrationsTotalSqlBytesTool)),
        (DbBaseMigrationsAvgSqlBytesTool::definition(), Box::new(DbBaseMigrationsAvgSqlBytesTool)),
        (DbBaseMigrationsLargestUpSqlTool::definition(), Box::new(DbBaseMigrationsLargestUpSqlTool)),
        (DbBaseMigrationsHasVersionTool::definition(), Box::new(DbBaseMigrationsHasVersionTool)),
    ]
}
