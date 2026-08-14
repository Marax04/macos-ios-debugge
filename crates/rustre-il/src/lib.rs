//! `rustre-il` — foundational intermediate-language primitives shared by the
//! `RustRE` IL stack (`rustre-il-lift`, `rustre-il-llil`, `rustre-il-mlil`,
//! `rustre-il-hlil`, `rustre-il-passes`).
//!
//! Each tier of the IL pipeline depends on this crate so cross-cutting
//! definitions (tier tags, IL-wide errors, width tokens) live in a single
//! place instead of being duplicated across siblings. The sibling crates own
//! their own concrete instruction/expression types; this crate owns only the
//! glue that all tiers agree on.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// IL pipeline tier. Used by passes and adapters that need to reason about
/// where in the lifting pipeline a value originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IlTier {
    /// Architecture-specific lifted effects (`rustre-il-lift`).
    Lift,
    /// Low-level IL (`rustre-il-llil`).
    Llil,
    /// Medium-level IL (`rustre-il-mlil`).
    Mlil,
    /// High-level IL (`rustre-il-hlil`).
    Hlil,
}

impl IlTier {
    /// Human-readable short tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Lift => "lift",
            Self::Llil => "llil",
            Self::Mlil => "mlil",
            Self::Hlil => "hlil",
        }
    }

    /// Returns the next-higher tier in the lifting pipeline, if any.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Lift => Some(Self::Llil),
            Self::Llil => Some(Self::Mlil),
            Self::Mlil => Some(Self::Hlil),
            Self::Hlil => None,
        }
    }

    /// Returns the next-lower tier in the lifting pipeline, if any.
    #[must_use]
    pub const fn prev(self) -> Option<Self> {
        match self {
            Self::Lift => None,
            Self::Llil => Some(Self::Lift),
            Self::Mlil => Some(Self::Llil),
            Self::Hlil => Some(Self::Mlil),
        }
    }
}

/// Errors that can be raised by any IL tier when a cross-tier invariant is
/// violated. Tier-local errors continue to live in their own crates; this
/// enum is for things every tier can produce.
#[derive(Debug, Error)]
pub enum IlError {
    #[error("unsupported operation `{op}` at tier {}", tier.tag())]
    Unsupported { tier: IlTier, op: String },
    #[error("tier mismatch: expected {}, got {}", expected.tag(), actual.tag())]
    TierMismatch { expected: IlTier, actual: IlTier },
    #[error("invalid IL: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_ordering() {
        assert_eq!(IlTier::Lift.next(), Some(IlTier::Llil));
        assert_eq!(IlTier::Llil.next(), Some(IlTier::Mlil));
        assert_eq!(IlTier::Mlil.next(), Some(IlTier::Hlil));
        assert_eq!(IlTier::Hlil.next(), None);
    }

    #[test]
    fn tier_tags() {
        assert_eq!(IlTier::Lift.tag(), "lift");
        assert_eq!(IlTier::Hlil.tag(), "hlil");
    }

    #[test]
    fn tier_prev() {
        assert_eq!(IlTier::Lift.prev(), None);
        assert_eq!(IlTier::Llil.prev(), Some(IlTier::Lift));
        assert_eq!(IlTier::Mlil.prev(), Some(IlTier::Llil));
        assert_eq!(IlTier::Hlil.prev(), Some(IlTier::Mlil));
    }

    #[test]
    fn tier_ord() {
        assert!(IlTier::Lift < IlTier::Llil);
        assert!(IlTier::Llil < IlTier::Mlil);
        assert!(IlTier::Mlil < IlTier::Hlil);
        assert!(IlTier::Hlil > IlTier::Lift);
        assert_eq!(IlTier::Mlil.cmp(&IlTier::Mlil), std::cmp::Ordering::Equal);

        let mut tiers = vec![IlTier::Hlil, IlTier::Lift, IlTier::Mlil, IlTier::Llil];
        tiers.sort();
        assert_eq!(
            tiers,
            vec![IlTier::Lift, IlTier::Llil, IlTier::Mlil, IlTier::Hlil]
        );
    }

    #[test]
    fn tier_hash_and_eq() {
        use std::collections::HashMap;

        let mut map: HashMap<IlTier, &'static str> = HashMap::new();
        map.insert(IlTier::Lift, "lift-value");
        map.insert(IlTier::Hlil, "hlil-value");

        assert_eq!(map.get(&IlTier::Lift), Some(&"lift-value"));
        assert_eq!(map.get(&IlTier::Hlil), Some(&"hlil-value"));
        assert_eq!(map.get(&IlTier::Mlil), None);
        assert_eq!(IlTier::Lift, IlTier::Lift);
        assert_ne!(IlTier::Lift, IlTier::Llil);
    }

    #[test]
    fn il_error_display() {
        let err = IlError::Unsupported {
            tier: IlTier::Llil,
            op: "divmod".to_string(),
        };
        assert_eq!(err.to_string(), "unsupported operation `divmod` at tier llil");

        let err = IlError::TierMismatch {
            expected: IlTier::Mlil,
            actual: IlTier::Hlil,
        };
        assert_eq!(err.to_string(), "tier mismatch: expected mlil, got hlil");

        let err = IlError::Invalid("bad phi node".to_string());
        assert_eq!(err.to_string(), "invalid IL: bad phi node");
    }
}
