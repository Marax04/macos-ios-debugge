//! Entitlement analysis for iOS binaries — re-export shim.
//!
//! This module re-exports the canonical implementation from
//! [`crate::ipa_entitlement_analyzer`], which supersedes the original
//! `entitlement_analyzer` module.  The unique types that were defined here
//! (`AppStoreComplianceChecker`, `ComplianceViolation`, `ViolationSeverity`,
//! `extract_entitlements_from_macho`) have been migrated into
//! `ipa_entitlement_analyzer` so that the two implementations do not diverge.
//!
//! # Migration guide
//! Replace any `use rustre_mobile_ipa::entitlement_analyzer::*` with
//! `use rustre_mobile_ipa::ipa_entitlement_analyzer::*`.

pub use crate::ipa_entitlement_analyzer::{
    AnalysisError,
    AnalysisResult,
    AppStoreComplianceChecker,
    ComplianceViolation,
    EntitlementKind,
    EntitlementRisk,
    IpaEntitlementAnalyzer,
    RiskLevel,
    ViolationSeverity,
    extract_entitlements_from_macho,
};
