//! Sub-crate registry / dispatcher for the `rustre-threatintel` hub.
//!
//! Each wired sub-crate is represented by a [`SubCrate`] entry pairing the
//! crate's canonical name with the principal exported type identifier. This
//! gives the hub a single point of truth from which every wired sub-crate is
//! discoverable, regardless of whether the caller wants to enumerate providers,
//! correlators, or platform integrations.

/// Descriptor for a wired sub-crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubCrate {
    /// Canonical crate name as it appears on crates.io / in `Cargo.toml`.
    pub name: &'static str,
    /// Name of the principal exported type of the sub-crate.
    pub primary_type: &'static str,
}

/// `rustre-ti-correlate` — `IoC` correlation engine.
pub const TI_CORRELATE: SubCrate = SubCrate {
    name: "rustre-ti-correlate",
    primary_type: "CampaignCorrelationEngine",
};

/// `rustre-ti-malpedia` — Malpedia malware knowledge base client.
pub const TI_MALPEDIA: SubCrate = SubCrate {
    name: "rustre-ti-malpedia",
    primary_type: "MalpediaClient",
};

/// `rustre-ti-misp` — MISP REST API client.
pub const TI_MISP: SubCrate = SubCrate {
    name: "rustre-ti-misp",
    primary_type: "MispClient",
};

/// `rustre-ti-opencti` — `OpenCTI` GraphQL integration.
pub const TI_OPENCTI: SubCrate = SubCrate {
    name: "rustre-ti-opencti",
    primary_type: "OpenCtiConfig",
};

/// `rustre-ti-otx` — `AlienVault` OTX integration.
pub const TI_OTX: SubCrate = SubCrate {
    name: "rustre-ti-otx",
    primary_type: "OtxConfig",
};

/// `rustre-ti-shodan` — Shodan host enrichment.
pub const TI_SHODAN: SubCrate = SubCrate {
    name: "rustre-ti-shodan",
    primary_type: "ShodanConfig",
};

/// `rustre-ti-vt` — `VirusTotal` API v3 client.
pub const TI_VT: SubCrate = SubCrate {
    name: "rustre-ti-vt",
    primary_type: "VtClient",
};

/// Re-exported principal types from each wired sub-crate.
///
/// Importing through the hub guarantees the sub-crate is reachable from any
/// caller that already depends on `rustre-threatintel`.
pub mod types {
    // Sub-crate re-exports are gated out to break the cycle: ti-* crates
    // now depend on rustre-threatintel for shared core types, so the hub
    // cannot re-export them back. Descriptors above remain as metadata.
}

/// Return every wired sub-crate descriptor.
#[must_use]
pub fn all() -> Vec<SubCrate> {
    vec![
        TI_CORRELATE,
        TI_MALPEDIA,
        TI_MISP,
        TI_OPENCTI,
        TI_OTX,
        TI_SHODAN,
        TI_VT,
    ]
}

/// Look up a wired sub-crate by canonical name.
#[must_use]
pub fn find(name: &str) -> Option<SubCrate> {
    all().into_iter().find(|s| s.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_seven_subcrates_registered() {
        assert_eq!(all().len(), 7);
    }

    #[test]
    fn find_known_subcrate() {
        assert_eq!(find("rustre-ti-vt"), Some(TI_VT));
        assert_eq!(find("rustre-ti-correlate"), Some(TI_CORRELATE));
    }

    #[test]
    fn find_unknown_returns_none() {
        assert!(find("does-not-exist").is_none());
    }
}
