//! `rustre-plugin-loader`
//!
//! Utilities for discovering, loading, and managing the lifecycle of RustRE
//! plugins, including dependency resolution, version compatibility checking,
//! and sandboxed execution.

pub mod plugin_dependency_resolver;
pub mod plugin_version_checker;
pub mod plugin_sandbox_runner;

pub use plugin_dependency_resolver::{DepGraph, Dependency, PluginDependencyResolver};
pub use plugin_sandbox_runner::{PluginSandboxRunner, RunResult, SandboxConfig};
pub use plugin_version_checker::{CompatResult, PluginVersionChecker, VersionSpec};
