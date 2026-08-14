//! `rustre-plugin-lua`
//!
//! Lua integration layer for `RustRE`: loads Lua plugin scripts, exposes the
//! platform API to Lua code, and manages a pool of Lua VM states.

pub mod lua_plugin_loader;
pub mod lua_api_provider;
pub mod lua_state_manager;

pub use lua_api_provider::{ApiFunction, ApiTable, LuaApiProvider};
pub use lua_plugin_loader::{LuaPlugin, LuaPluginLoader, PluginEntry};
pub use lua_state_manager::{LuaState, LuaStateManager, StatePool};
