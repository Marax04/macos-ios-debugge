// ============================================================================
// core/mod.rs
// ============================================================================
pub mod app_state;
pub mod binary_buffer;
pub mod call_chain;
pub mod call_graph;
pub mod cfg_analysis;
pub mod commands;
pub mod cpu_pool;
pub mod data_layout;
pub mod debugger;
pub mod disasm_cache;
pub mod elf_parser;
pub mod entropy_analysis;
pub mod event_bus;
pub mod i18n;
pub mod ir_lifting;
pub mod keybindings;
pub mod macro_recorder;
pub mod navigation;
pub mod patch_manager;
pub mod pattern_matcher;
pub mod pe_parser;
pub mod project;
pub mod revision;
pub mod script_engine;
pub mod search;
pub mod selection;
pub mod signature_db;
pub mod string_extractor;
pub mod symbol_demangler;
pub mod taint;
pub mod task_system;
pub mod type_inference;
pub mod type_system;
pub mod types;
