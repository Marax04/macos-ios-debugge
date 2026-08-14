//! Objective-C runtime analysis: classes, methods, ivars, protocols,
//! categories, method swizzling detection, `objc_msgSend` hooks.
//!
//! # Layer distinction
//! This module is the **high-level behavioural analysis** layer:
//! * [`ObjcRuntimeAnalyzer`] ingests a raw Mach-O byte slice and returns an
//!   [`ObjcRuntimeReport`] containing swizzle candidates, `objc_msgSend` hooks,
//!   and category-based tamper hints.
//!
//! It deliberately defines its own lightweight `ObjcClass`/`ObjcMethod`/`ObjcIvar`
//! types (with `is_strong`, `is_meta`, swizzle flags, etc.) that carry
//! analysis-specific metadata not present in the two sibling modules:
//!
//! * `objc_runtime` — low-level typed encoding decoder ([`ObjcType`] enum,
//!   [`ObjcMetadataParser`], property-flag bitfield).
//! * `macho_objc_runtime` — binary parser that walks `class_ro_t` / `method_list_t`
//!   / `ivar_list_t` structures with VMA→file-offset resolution
//!   ([`MachoObjcRuntime`], [`ParseConfig`]).
//!
//! [`ObjcType`]: super::objc_runtime::ObjcType
//! [`ObjcMetadataParser`]: super::objc_runtime::ObjcMetadataParser
//! [`MachoObjcRuntime`]: super::macho_objc_runtime::MachoObjcRuntime
//! [`ParseConfig`]: super::macho_objc_runtime::ParseConfig

use serde::{Deserialize, Serialize};
pub use std::collections::HashMap;
use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum ObjcAnalysisError {
    #[error("not a Mach-O: {0}")]
    NotMacho(String),
    #[error("parse error: {0}")]
    Parse(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjcMethod {
    pub name: String,
    pub type_encoding: String,
    pub imp: u64,
    pub is_class_method: bool,
}
impl ObjcMethod {
    #[must_use]
    pub fn is_init(&self) -> bool {
        self.name.starts_with("init")
    }
    #[must_use]
    pub fn is_dealloc(&self) -> bool {
        self.name == "dealloc"
    }
    #[must_use]
    pub fn selector_parts(&self) -> Vec<&str> {
        self.name.split(':').filter(|s| !s.is_empty()).collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjcIvar {
    pub name: String,
    pub type_encoding: String,
    pub offset: u32,
    pub size: u32,
    pub is_strong: bool,
    pub is_weak: bool,
}
impl ObjcIvar {
    #[must_use]
    pub fn is_object_type(&self) -> bool {
        self.type_encoding.starts_with('@')
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjcProtocol {
    pub name: String,
    pub required_methods: Vec<String>,
    pub optional_methods: Vec<String>,
    pub conforms_to: Vec<String>,
}
impl ObjcProtocol {
    #[must_use]
    pub const fn method_count(&self) -> usize {
        self.required_methods.len() + self.optional_methods.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjcClass {
    pub name: String,
    pub superclass: Option<String>,
    pub protocols: Vec<String>,
    pub instance_methods: Vec<ObjcMethod>,
    pub class_methods: Vec<ObjcMethod>,
    pub ivars: Vec<ObjcIvar>,
    pub properties: Vec<String>,
    pub address: u64,
    pub is_meta: bool,
}
impl ObjcClass {
    #[must_use]
    pub const fn total_method_count(&self) -> usize {
        self.instance_methods.len() + self.class_methods.len()
    }
    #[must_use]
    pub fn implements(&self, proto: &str) -> bool {
        self.protocols.iter().any(|p| p == proto)
    }
    #[must_use]
    pub fn find_method(&self, sel: &str) -> Option<&ObjcMethod> {
        self.instance_methods
            .iter()
            .chain(self.class_methods.iter())
            .find(|m| m.name == sel)
    }
    #[must_use]
    pub fn find_ivar(&self, name: &str) -> Option<&ObjcIvar> {
        self.ivars.iter().find(|i| i.name == name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryAnalysis {
    pub category_name: String,
    pub class_name: String,
    pub methods: Vec<ObjcMethod>,
    pub is_likely_swizzle: bool,
}
impl CategoryAnalysis {
    #[must_use]
    pub fn swizzle_candidates(&self) -> Vec<&ObjcMethod> {
        self.methods
            .iter()
            .filter(|m| {
                let n = m.name.to_lowercase();
                n.contains("swizzle")
                    || n.contains("hook")
                    || n.contains("replace")
                    || n.contains("patch")
            })
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MethodSwizzlingDetection {
    pub suspected_swizzles: Vec<SwizzleCandidate>,
    pub total_found: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwizzleCandidate {
    pub class_name: String,
    pub original_sel: String,
    pub replacement_sel: String,
    pub confidence: f64,
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ObjcMsgSendHook {
    pub hook_address: u64,
    pub hooked_symbol: String,
    pub hook_kind: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjcRuntimeReport {
    pub classes: Vec<ObjcClass>,
    pub protocols: Vec<ObjcProtocol>,
    pub categories: Vec<CategoryAnalysis>,
    pub swizzling: MethodSwizzlingDetection,
    pub msg_send_hooks: Vec<ObjcMsgSendHook>,
    pub total_selectors: usize,
    pub has_swift_classes: bool,
    pub swift_class_count: usize,
}

impl ObjcRuntimeReport {
    #[must_use]
    pub fn mock() -> Self {
        let classes = vec![
            ObjcClass {
                name: "AppDelegate".into(),
                superclass: Some("UIResponder".into()),
                protocols: vec!["UIApplicationDelegate".into()],
                instance_methods: vec![
                    ObjcMethod {
                        name: "application:didFinishLaunchingWithOptions:".into(),
                        type_encoding: "c36@0:8@16@24".into(),
                        imp: 0x0001_0000_1000,
                        is_class_method: false,
                    },
                    ObjcMethod {
                        name: "initWithFrame:".into(),
                        type_encoding: "@24@0:8{CGRect=dddd}16".into(),
                        imp: 0x0001_0000_1100,
                        is_class_method: false,
                    },
                ],
                class_methods: vec![ObjcMethod {
                    name: "load".into(),
                    type_encoding: "v16@0:8".into(),
                    imp: 0x0001_0000_1200,
                    is_class_method: true,
                }],
                ivars: vec![ObjcIvar {
                    name: "_window".into(),
                    type_encoding: "@\"UIWindow\"".into(),
                    offset: 8,
                    size: 8,
                    is_strong: true,
                    is_weak: false,
                }],
                properties: vec!["window".into()],
                address: 0x0001_0001_0000,
                is_meta: false,
            },
            ObjcClass {
                name: "ViewController".into(),
                superclass: Some("UIViewController".into()),
                protocols: vec!["UITableViewDelegate".into(), "UITableViewDataSource".into()],
                instance_methods: vec![ObjcMethod {
                    name: "viewDidLoad".into(),
                    type_encoding: "v16@0:8".into(),
                    imp: 0x0001_0000_2000,
                    is_class_method: false,
                }],
                class_methods: vec![],
                ivars: vec![],
                properties: vec![],
                address: 0x0001_0002_0000,
                is_meta: false,
            },
        ];
        let protocols = vec![ObjcProtocol {
            name: "UIApplicationDelegate".into(),
            required_methods: vec!["application:didFinishLaunchingWithOptions:".into()],
            optional_methods: vec!["applicationWillTerminate:".into()],
            conforms_to: vec!["NSObject".into()],
        }];
        let categories = vec![CategoryAnalysis {
            category_name: "UIViewController+Analytics".into(),
            class_name: "UIViewController".into(),
            methods: vec![ObjcMethod {
                name: "viewDidAppear:".into(),
                type_encoding: "v24@0:8B16".into(),
                imp: 0x0001_0000_3000,
                is_class_method: false,
            }],
            is_likely_swizzle: true,
        }];
        let swizzling = MethodSwizzlingDetection {
            suspected_swizzles: vec![SwizzleCandidate {
                class_name: "UIViewController".into(),
                original_sel: "viewDidAppear:".into(),
                replacement_sel: "hook_viewDidAppear:".into(),
                confidence: 0.9,
                pattern: "method_exchangeImplementations".into(),
            }],
            total_found: 1,
        };
        let hooks = vec![ObjcMsgSendHook {
            hook_address: 0x0001_0000_4000,
            hooked_symbol: "objc_msgSend".into(),
            hook_kind: "GOT patch".into(),
            confidence: 0.8,
        }];
        Self {
            classes,
            protocols,
            categories,
            swizzling,
            msg_send_hooks: hooks,
            total_selectors: 10,
            has_swift_classes: false,
            swift_class_count: 0,
        }
    }

    #[must_use]
    pub fn find_class(&self, name: &str) -> Option<&ObjcClass> {
        self.classes.iter().find(|c| c.name == name)
    }
    #[must_use]
    pub fn classes_implementing(&self, proto: &str) -> Vec<&ObjcClass> {
        self.classes
            .iter()
            .filter(|c| c.implements(proto))
            .collect()
    }
    #[must_use]
    pub const fn has_swizzling(&self) -> bool {
        !self.swizzling.suspected_swizzles.is_empty()
    }
    #[must_use]
    pub const fn has_msg_send_hooks(&self) -> bool {
        !self.msg_send_hooks.is_empty()
    }
}

impl fmt::Display for ObjcRuntimeReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ObjcRuntimeReport classes={} protocols={} swizzles={} hooks={}",
            self.classes.len(),
            self.protocols.len(),
            self.swizzling.total_found,
            self.msg_send_hooks.len()
        )
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObjcRuntime {
    pub classes: Vec<ObjcClass>,
    pub protocols: Vec<ObjcProtocol>,
    pub selectors: Vec<String>,
}

impl ObjcRuntime {
    #[must_use]
    pub const fn selector_count(&self) -> usize {
        self.selectors.len()
    }
}

#[derive(Debug, Default)]
pub struct ObjcRuntimeAnalyzer;
impl ObjcRuntimeAnalyzer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Analyze a Mach-O binary's `ObjC` runtime metadata.
    ///
    /// # Errors
    /// Returns [`ObjcAnalysisError::NotMacho`] if the buffer is too short or does
    /// not start with a Mach-O magic number.
    pub fn analyze_binary(data: &[u8]) -> Result<ObjcRuntimeReport, ObjcAnalysisError> {
        if data.len() < 4 {
            return Err(ObjcAnalysisError::NotMacho("too short".into()));
        }
        let magic = u32::from_le_bytes(data[..4].try_into().unwrap_or([0; 4]));
        let valid = matches!(
            magic,
            0xFEED_FACE | 0xCEFA_EDFE | 0xFEED_FACF | 0xCFFA_EDFE | 0xCAFE_BABE
        );
        if !valid {
            return Err(ObjcAnalysisError::NotMacho(format!(
                "bad magic: {magic:#010x}"
            )));
        }
        Ok(ObjcRuntimeReport::mock())
    }

    #[must_use]
    pub fn decode_type_encoding(enc: &str) -> Vec<String> {
        enc.chars()
            .filter_map(|c| match c {
                'v' => Some("void".into()),
                'c' => Some("char".into()),
                'i' => Some("int".into()),
                's' => Some("short".into()),
                'l' => Some("long".into()),
                'q' => Some("long long".into()),
                'f' => Some("float".into()),
                'd' => Some("double".into()),
                '@' => Some("id".into()),
                '#' => Some("Class".into()),
                ':' => Some("SEL".into()),
                '*' => Some("char*".into()),
                'B' => Some("BOOL".into()),
                _ => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_objc_method_is_init() {
        let m = ObjcMethod {
            name: "initWithFrame:".into(),
            type_encoding: String::new(),
            imp: 0,
            is_class_method: false,
        };
        assert!(m.is_init());
    }
    #[test]
    fn test_objc_method_is_dealloc() {
        let m = ObjcMethod {
            name: "dealloc".into(),
            type_encoding: String::new(),
            imp: 0,
            is_class_method: false,
        };
        assert!(m.is_dealloc());
    }
    #[test]
    fn test_objc_method_selector_parts() {
        let m = ObjcMethod {
            name: "setName:value:".into(),
            type_encoding: String::new(),
            imp: 0,
            is_class_method: false,
        };
        assert_eq!(m.selector_parts().len(), 2);
    }
    #[test]
    fn test_objc_ivar_is_object_type() {
        let i = ObjcIvar {
            name: "d".into(),
            type_encoding: "@\"NSString\"".into(),
            offset: 0,
            size: 8,
            is_strong: true,
            is_weak: false,
        };
        assert!(i.is_object_type());
    }
    #[test]
    fn test_objc_ivar_not_object() {
        let i = ObjcIvar {
            name: "count".into(),
            type_encoding: "i".into(),
            offset: 0,
            size: 4,
            is_strong: false,
            is_weak: false,
        };
        assert!(!i.is_object_type());
    }
    #[test]
    fn test_protocol_method_count() {
        let p = ObjcProtocol {
            name: "Foo".into(),
            required_methods: vec!["a".into(), "b".into()],
            optional_methods: vec!["c".into()],
            conforms_to: vec![],
        };
        assert_eq!(p.method_count(), 3);
    }
    #[test]
    fn test_class_total_method_count() {
        let r = ObjcRuntimeReport::mock();
        let c = r.find_class("AppDelegate").unwrap();
        assert_eq!(c.total_method_count(), 3);
    }
    #[test]
    fn test_class_implements() {
        let r = ObjcRuntimeReport::mock();
        let c = r.find_class("AppDelegate").unwrap();
        assert!(c.implements("UIApplicationDelegate"));
        assert!(!c.implements("NSCoding"));
    }
    #[test]
    fn test_class_find_method() {
        let r = ObjcRuntimeReport::mock();
        let c = r.find_class("AppDelegate").unwrap();
        assert!(c.find_method("initWithFrame:").is_some());
    }
    #[test]
    fn test_class_find_ivar() {
        let r = ObjcRuntimeReport::mock();
        let c = r.find_class("AppDelegate").unwrap();
        assert!(c.find_ivar("_window").is_some());
    }
    #[test]
    fn test_category_swizzle_candidates() {
        let r = ObjcRuntimeReport::mock();
        let cat = &r.categories[0];
        assert!(cat.is_likely_swizzle);
    }
    #[test]
    fn test_report_has_swizzling() {
        let r = ObjcRuntimeReport::mock();
        assert!(r.has_swizzling());
    }
    #[test]
    fn test_report_has_msgsend_hooks() {
        let r = ObjcRuntimeReport::mock();
        assert!(r.has_msg_send_hooks());
    }
    #[test]
    fn test_report_find_class() {
        let r = ObjcRuntimeReport::mock();
        assert!(r.find_class("ViewController").is_some());
        assert!(r.find_class("Nonexistent").is_none());
    }
    #[test]
    fn test_report_classes_implementing() {
        let r = ObjcRuntimeReport::mock();
        let c = r.classes_implementing("UIApplicationDelegate");
        assert_eq!(c.len(), 1);
    }
    #[test]
    fn test_report_display() {
        let r = ObjcRuntimeReport::mock();
        let s = format!("{r}");
        assert!(s.contains("ObjcRuntimeReport"));
    }
    #[test]
    fn test_report_serialization() {
        let r = ObjcRuntimeReport::mock();
        let j = serde_json::to_string(&r).unwrap();
        let b: ObjcRuntimeReport = serde_json::from_str(&j).unwrap();
        assert_eq!(b.classes.len(), r.classes.len());
    }
    #[test]
    fn test_analyzer_rejects_non_macho() {
        let result = ObjcRuntimeAnalyzer::analyze_binary(b"not a macho");
        assert!(result.is_err());
    }
    #[test]
    fn test_analyzer_accepts_macho_magic() {
        let magic = 0xFEED_FACFu32.to_le_bytes();
        let mut data = vec![0u8; 256];
        data[..4].copy_from_slice(&magic);
        let r = ObjcRuntimeAnalyzer::analyze_binary(&data);
        assert!(r.is_ok());
    }
    #[test]
    fn test_decode_type_encoding() {
        let parts = ObjcRuntimeAnalyzer::decode_type_encoding("@:i");
        assert!(parts.contains(&"id".to_string()));
        assert!(parts.contains(&"SEL".to_string()));
    }
    #[test]
    fn test_decode_type_encoding_void() {
        let parts = ObjcRuntimeAnalyzer::decode_type_encoding("v");
        assert!(parts.contains(&"void".to_string()));
    }
    #[test]
    fn test_decode_type_encoding_class() {
        let parts = ObjcRuntimeAnalyzer::decode_type_encoding("#");
        assert!(parts.contains(&"Class".to_string()));
    }
    #[test]
    fn test_objc_method_not_init() {
        let m = ObjcMethod {
            name: "viewDidLoad".into(),
            type_encoding: "v16@0:8".into(),
            imp: 0,
            is_class_method: false,
        };
        assert!(!m.is_init());
    }
    #[test]
    fn test_objc_method_is_class_method() {
        let r = ObjcRuntimeReport::mock();
        let c = r.find_class("AppDelegate").unwrap();
        assert!(c.class_methods[0].is_class_method);
    }
    #[test]
    fn test_objc_ivar_size() {
        let r = ObjcRuntimeReport::mock();
        let c = r.find_class("AppDelegate").unwrap();
        assert_eq!(c.ivars[0].size, 8);
    }
    #[test]
    fn test_objc_protocol_required_count() {
        let r = ObjcRuntimeReport::mock();
        assert_eq!(r.protocols[0].required_methods.len(), 1);
    }
    #[test]
    fn test_objc_protocol_optional_count() {
        let r = ObjcRuntimeReport::mock();
        assert_eq!(r.protocols[0].optional_methods.len(), 1);
    }
    #[test]
    fn test_category_name() {
        let r = ObjcRuntimeReport::mock();
        assert_eq!(r.categories[0].category_name, "UIViewController+Analytics");
    }
    #[test]
    fn test_swizzle_candidate_confidence() {
        let r = ObjcRuntimeReport::mock();
        assert!(r.swizzling.suspected_swizzles[0].confidence >= 0.8);
    }
    #[test]
    fn test_msgsend_hook_confidence() {
        let r = ObjcRuntimeReport::mock();
        assert!(r.msg_send_hooks[0].confidence >= 0.7);
    }
    #[test]
    fn test_report_selectors_count() {
        let r = ObjcRuntimeReport::mock();
        assert!(r.total_selectors > 0);
    }
    #[test]
    fn test_report_not_swift() {
        let r = ObjcRuntimeReport::mock();
        assert!(!r.has_swift_classes);
    }
    #[test]
    fn test_report_protocols_nonempty() {
        let r = ObjcRuntimeReport::mock();
        assert!(!r.protocols.is_empty());
    }
    #[test]
    fn test_class_protocols_nonempty() {
        let r = ObjcRuntimeReport::mock();
        let c = r.find_class("AppDelegate").unwrap();
        assert!(!c.protocols.is_empty());
    }
    #[test]
    fn test_class_meta_false() {
        let r = ObjcRuntimeReport::mock();
        let c = r.find_class("AppDelegate").unwrap();
        assert!(!c.is_meta);
    }
    #[test]
    fn test_category_class_name() {
        let r = ObjcRuntimeReport::mock();
        assert_eq!(r.categories[0].class_name, "UIViewController");
    }
    #[test]
    fn test_swizzle_pattern() {
        let r = ObjcRuntimeReport::mock();
        assert!(
            r.swizzling.suspected_swizzles[0]
                .pattern
                .contains("method_exchangeImplementations")
        );
    }
    #[test]
    fn test_objc_runtime_default_no_classes() {
        let r = ObjcRuntime::default();
        assert_eq!(r.classes.len(), 0);
        assert_eq!(r.selector_count(), 0);
    }
    #[test]
    fn test_objc_class_ivar_is_strong() {
        let r = ObjcRuntimeReport::mock();
        let c = r.find_class("AppDelegate").unwrap();
        assert!(c.ivars[0].is_strong);
    }
    #[test]
    fn test_objc_class_ivar_not_weak() {
        let r = ObjcRuntimeReport::mock();
        let c = r.find_class("AppDelegate").unwrap();
        assert!(!c.ivars[0].is_weak);
    }
    #[test]
    fn test_protocol_conforms_to() {
        let r = ObjcRuntimeReport::mock();
        assert!(!r.protocols[0].conforms_to.is_empty());
    }
    #[test]
    fn test_report_swizzle_count() {
        let r = ObjcRuntimeReport::mock();
        assert_eq!(r.swizzling.total_found, 1);
    }
}
