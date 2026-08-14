//! Bridge between `rustre-sysinternals` and the forensics plugin framework.
//!
//! Re-exports the primary Sysinternals-style introspection types and provides
//! a `ForensicsPlugin` implementation that runs a system snapshot via the
//! `SystemMonitor` trait, surfacing processes/drivers/handles/network endpoints
//! as plugin rows.

use std::collections::HashMap;

pub use rustre_sysinternals::{
    AutorunScanner, FileSignatureChecker, InMemorySystemMonitor, NetworkMonitor, ProcessScanner,
    ProcessTree, SystemMonitor, SystemSnapshot,
};

use crate::{ForensicsError, ForensicsPlugin, MemoryImage, PluginArgs, PluginOutput};

/// Plugin that captures a `SystemSnapshot` via any `SystemMonitor` and
/// flattens it into plugin rows.
pub struct SysinternalsSnapshotPlugin<M: SystemMonitor + 'static> {
    monitor: M,
}

impl<M: SystemMonitor + 'static> SysinternalsSnapshotPlugin<M> {
    pub const fn new(monitor: M) -> Self {
        Self { monitor }
    }
}

impl Default for SysinternalsSnapshotPlugin<InMemorySystemMonitor> {
    fn default() -> Self {
        Self::new(InMemorySystemMonitor::new())
    }
}

impl<M: SystemMonitor + 'static> ForensicsPlugin for SysinternalsSnapshotPlugin<M> {
    fn name(&self) -> &'static str {
        "sysinternals.snapshot"
    }

    fn description(&self) -> &'static str {
        "Capture a Sysinternals-style system snapshot (processes, drivers, handles, network)"
    }

    fn run(
        &self,
        _image: &dyn MemoryImage,
        _args: &PluginArgs,
    ) -> Result<PluginOutput, ForensicsError> {
        let snap: SystemSnapshot = self
            .monitor
            .snapshot()
            .map_err(|e| ForensicsError::NotSupported(format!("sysinternals snapshot: {e}")))?;

        let mut out = PluginOutput::new();
        for p in &snap.processes {
            let mut row = HashMap::new();
            row.insert("kind".into(), "process".into());
            row.insert("pid".into(), p.pid.to_string());
            row.insert("ppid".into(), p.ppid.to_string());
            row.insert("name".into(), p.name.clone());
            row.insert("status".into(), p.status.to_string());
            out.add_row(row);
        }
        for d in &snap.drivers {
            let mut row = HashMap::new();
            row.insert("kind".into(), "driver".into());
            row.insert("name".into(), d.name.clone());
            row.insert("path".into(), d.path.clone());
            row.insert("base".into(), format!("0x{:016x}", d.base));
            out.add_row(row);
        }
        for h in &snap.handles {
            let mut row = HashMap::new();
            row.insert("kind".into(), "handle".into());
            row.insert("pid".into(), h.pid.to_string());
            row.insert("type".into(), h.type_name.clone());
            row.insert("handle".into(), format!("0x{:x}", h.handle));
            out.add_row(row);
        }
        for n in &snap.network {
            let mut row = HashMap::new();
            row.insert("kind".into(), "network".into());
            row.insert("pid".into(), n.pid.to_string());
            row.insert("protocol".into(), n.protocol.to_string());
            row.insert("local".into(), format!("{}:{}", n.local_addr, n.local_port));
            row.insert(
                "remote".into(),
                format!("{}:{}", n.remote_addr, n.remote_port),
            );
            row.insert("state".into(), n.state.to_string());
            out.add_row(row);
        }
        Ok(out)
    }
}
