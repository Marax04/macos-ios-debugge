//! `rustre-mobile`
//!
//! Composition hub for all `rustre-mobile-*` sub-crates.
//!
//! Re-exports the primary types from each mobile analysis sub-crate and
//! provides a [`registry`] module with a convenience [`registry::all()`]
//! function that returns the short crate name of every wired backend.

// Re-export primary types from every sub-crate.
pub use rustre_mobile_android::AndroidManifest;
pub use rustre_mobile_apktool::ApktoolConfig;
pub use rustre_mobile_dyld::DyldHeader;
pub use rustre_mobile_ios::BundleInfo;
pub use rustre_mobile_ipa::IpaPackage;
pub use rustre_mobile_jadx::DecompiledProject;
pub use rustre_mobile_smali::SmaliClass;

// Make the full sub-crate namespaces available under this hub.
pub use rustre_mobile_android as android;
pub use rustre_mobile_apktool as apktool;
pub use rustre_mobile_dyld    as dyld;
pub use rustre_mobile_ios     as ios;
pub use rustre_mobile_ipa     as ipa;
pub use rustre_mobile_jadx    as jadx;
pub use rustre_mobile_smali   as smali;

/// Registry of all wired `rustre-mobile-*` backends.
pub mod registry {
    /// Returns the short names of every `rustre-mobile-*` backend wired into
    /// this hub crate.
    #[must_use]
    pub fn all() -> Vec<&'static str> {
        vec![
            "rustre-mobile-android",
            "rustre-mobile-apktool",
            "rustre-mobile-dyld",
            "rustre-mobile-ios",
            "rustre-mobile-ipa",
            "rustre-mobile-jadx",
            "rustre-mobile-smali",
        ]
    }
}
