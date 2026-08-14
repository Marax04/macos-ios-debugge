//! Sub-crate registry / dispatcher for the `rustre-net` hub.
//!
//! Each wired sub-crate is described by a [`NetComponent`] entry that names
//! the crate. The [`all`] function returns every wired component, providing a
//! single discovery point for downstream tooling (CLI, MCP, GUI).
//!
//! Cycle note: `rustre-net-pcap`, `rustre-net-proxy`, `rustre-net-dissect`,
//! and `rustre-net-rules` all depend on `rustre-net` themselves, so they
//! cannot be wired here as Cargo dependencies without producing a build
//! cycle. They participate in the platform by linking against this hub
//! rather than being re-exported from it. Downstream binaries that need
//! concrete analyzer/server instances should depend on the sub-crates
//! directly and use [`ComponentKind::crate_name`] to correlate registry
//! entries with their implementations.

use std::sync::Arc;

/// Identifier for a wired sub-crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComponentKind {
    /// `rustre-net-pcap` — PCAP/PCAPNG reading and writing.
    Pcap,
    /// `rustre-net-proxy` — Intercepting proxy / MITM engine.
    Proxy,
    /// `rustre-net-dissect` — Application-layer protocol dissection.
    Dissect,
    /// `rustre-net-rules` — Rule engine for traffic classification.
    Rules,
}

impl ComponentKind {
    /// Crate name as it appears in `Cargo.toml`.
    #[must_use]
    pub const fn crate_name(&self) -> &'static str {
        match self {
            Self::Pcap => "rustre-net-pcap",
            Self::Proxy => "rustre-net-proxy",
            Self::Dissect => "rustre-net-dissect",
            Self::Rules => "rustre-net-rules",
        }
    }
}

/// A wired sub-crate exposed through the hub.
pub struct NetComponent {
    pub kind: ComponentKind,
    pub description: &'static str,
}

/// Trait implemented by component factories registered from downstream crates.
///
/// Sub-crates such as `rustre-net-pcap` and `rustre-net-proxy` cannot be
/// imported here because they depend on `rustre-net`. Instead, a downstream
/// binary (CLI/MCP/GUI) that links both this hub and a sub-crate can register
/// a factory implementing this trait via [`ComponentRegistry::register`].
pub trait ComponentFactory: Send + Sync {
    /// The component this factory produces.
    fn kind(&self) -> ComponentKind;

    /// Construct an opaque instance of the sub-crate's primary type.
    ///
    /// The returned `Arc<dyn std::any::Any + Send + Sync>` is downcast by the
    /// caller, who knows the concrete type because they depend on the
    /// sub-crate directly.
    fn instantiate(&self) -> Arc<dyn std::any::Any + Send + Sync>;
}

/// A runtime registry of component factories supplied by downstream crates.
///
/// This inverts the dependency: instead of the hub importing sub-crates
/// (which would cycle), downstream code registers factories at startup.
pub struct ComponentRegistry {
    factories: parking_lot::RwLock<Vec<Arc<dyn ComponentFactory>>>,
}

impl ComponentRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            factories: parking_lot::RwLock::new(Vec::new()),
        }
    }

    /// Register a factory. Later lookups by `kind` will find it.
    pub fn register(&self, factory: Arc<dyn ComponentFactory>) {
        self.factories.write().push(factory);
    }

    /// Find a registered factory for the given component kind.
    #[must_use]
    pub fn factory(&self, kind: ComponentKind) -> Option<Arc<dyn ComponentFactory>> {
        self.factories
            .read()
            .iter()
            .find(|f| f.kind() == kind)
            .cloned()
    }

    /// Instantiate every registered factory.
    #[must_use]
    pub fn instantiate_all(&self) -> Vec<(ComponentKind, Arc<dyn std::any::Any + Send + Sync>)> {
        self.factories
            .read()
            .iter()
            .map(|f| (f.kind(), f.instantiate()))
            .collect()
    }

    /// Number of registered factories.
    #[must_use]
    pub fn len(&self) -> usize {
        self.factories.read().len()
    }

    /// Returns `true` if no factories are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.factories.read().is_empty()
    }
}

impl Default for ComponentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Return every wired sub-crate component.
#[must_use]
pub fn all() -> Vec<NetComponent> {
    vec![
        NetComponent {
            kind: ComponentKind::Pcap,
            description: "PCAP / PCAPNG reading and writing.",
        },
        NetComponent {
            kind: ComponentKind::Proxy,
            description: "Intercepting proxy and MITM engine.",
        },
        NetComponent {
            kind: ComponentKind::Dissect,
            description: "Application-layer protocol dissection.",
        },
        NetComponent {
            kind: ComponentKind::Rules,
            description: "Rule engine for traffic classification.",
        },
    ]
}
