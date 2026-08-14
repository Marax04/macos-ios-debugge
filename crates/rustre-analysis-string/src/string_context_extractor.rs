/// String-to-function context extraction and API proximity grouping.
///
/// Extracts context about where a string is used:
/// - Which function(s) reference it
/// - Which API calls appear nearby (within N instructions)
/// - Grouping of strings by API proximity and semantic category
/// - Cross-reference graphs from string to call site to API

use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// Address types (simple stand-ins for rustre_core::address)
// ---------------------------------------------------------------------------

/// A virtual address (64-bit).
pub type Va = u64;

/// An instruction offset (instruction index within a function).
pub type InsnOff = u32;

// ---------------------------------------------------------------------------
// StringRef — reference to a string at a specific call site
// ---------------------------------------------------------------------------

/// A reference from a string to a call site.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StringRef {
    /// The string contents.
    pub string: String,
    /// Address of the instruction that loads/references this string.
    pub load_va: Va,
    /// Address of the function containing the reference.
    pub function_va: Va,
    /// Instruction offset within the function.
    pub insn_offset: InsnOff,
}

// ---------------------------------------------------------------------------
// ApiCallSite — a nearby API/function call
// ---------------------------------------------------------------------------

/// A nearby function call.
#[derive(Debug, Clone)]
pub struct ApiCallSite {
    /// Address of the call instruction.
    pub call_va: Va,
    /// Name of the called function (if known).
    pub callee_name: Option<String>,
    /// Address of the callee.
    pub callee_va: Va,
    /// Instruction distance from the string load.
    pub distance: u32,
}

// ---------------------------------------------------------------------------
// StringContext — full context for one string occurrence
// ---------------------------------------------------------------------------

/// Full context for one occurrence of a string.
#[derive(Debug, Clone)]
pub struct StringContext {
    /// The string reference (load site).
    pub string_ref: StringRef,
    /// API calls found near this string reference.
    pub nearby_apis: Vec<ApiCallSite>,
    /// Names of APIs grouped within this context.
    pub api_names: Vec<String>,
    /// Any semantic tag inferred from nearby APIs.
    pub semantic_tag: Option<String>,
}

impl StringContext {
    #[must_use]
    pub fn closest_api(&self) -> Option<&ApiCallSite> {
        self.nearby_apis.iter().min_by_key(|a| a.distance)
    }

    #[must_use]
    pub fn api_count(&self) -> usize {
        self.nearby_apis.len()
    }

    #[must_use]
    pub fn has_api(&self, name: &str) -> bool {
        self.api_names.iter().any(|n| n.eq_ignore_ascii_case(name))
    }
}

// ---------------------------------------------------------------------------
// StringFunction — all strings + contexts within one function
// ---------------------------------------------------------------------------

/// All string references and their contexts within one function.
#[derive(Debug, Clone)]
pub struct StringFunction {
    pub function_va: Va,
    pub function_name: Option<String>,
    pub contexts: Vec<StringContext>,
}

impl StringFunction {
    #[must_use]
    pub fn string_count(&self) -> usize {
        self.contexts.len()
    }

    #[must_use]
    pub fn unique_strings(&self) -> Vec<&str> {
        let mut seen = HashSet::new();
        self.contexts.iter()
            .map(|c| c.string_ref.string.as_str())
            .filter(|s| seen.insert(*s))
            .collect()
    }

    #[must_use]
    pub fn all_api_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.contexts.iter()
            .flat_map(|c| c.api_names.iter().cloned())
            .collect();
        names.sort();
        names.dedup();
        names
    }
}

// ---------------------------------------------------------------------------
// ApiNearString — pairing of API name with string
// ---------------------------------------------------------------------------

/// Pairing of an API name with a string referenced nearby.
#[derive(Debug, Clone)]
pub struct ApiNearString {
    pub api_name: String,
    pub api_va: Va,
    pub string_value: String,
    pub string_va: Va,
    pub function_va: Va,
    pub distance: u32,
}

// ---------------------------------------------------------------------------
// StringGroup — cluster of strings sharing API proximity
// ---------------------------------------------------------------------------

/// A group of strings that share proximity to the same set of APIs.
#[derive(Debug, Clone)]
pub struct StringGroup {
    pub group_id: u32,
    /// The shared API names driving grouping.
    pub pivot_apis: Vec<String>,
    /// Strings in this group.
    pub strings: Vec<String>,
    /// Functions containing these strings.
    pub functions: Vec<Va>,
    /// Inferred category/tag.
    pub inferred_tag: Option<String>,
}

impl StringGroup {
    #[must_use]
    pub fn size(&self) -> usize {
        self.strings.len()
    }
}

// ---------------------------------------------------------------------------
// ContextExtractor — main extraction engine
// ---------------------------------------------------------------------------

/// Configuration for context extraction.
#[derive(Debug, Clone)]
pub struct ExtractorConfig {
    /// Maximum instruction distance to consider an API "nearby".
    pub api_proximity_window: u32,
    /// Minimum number of strings in a group.
    pub min_group_size: usize,
    /// Maximum groups to produce.
    pub max_groups: usize,
}

impl Default for ExtractorConfig {
    fn default() -> Self {
        Self {
            api_proximity_window: 10,
            min_group_size: 2,
            max_groups: 100,
        }
    }
}

/// Statistics about extraction runs.
#[derive(Debug, Default, Clone)]
pub struct ExtractorStats {
    pub functions_processed: u64,
    pub strings_extracted: u64,
    pub api_pairs_found: u64,
    pub groups_formed: u64,
}

/// The main context extractor.
pub struct ContextExtractor {
    config: ExtractorConfig,
    stats: ExtractorStats,
    /// function_va -> StringFunction
    functions: HashMap<Va, StringFunction>,
    /// All API-near-string pairs
    api_pairs: Vec<ApiNearString>,
}

impl ContextExtractor {
    pub fn new(config: ExtractorConfig) -> Self {
        Self {
            config,
            stats: ExtractorStats::default(),
            functions: HashMap::new(),
            api_pairs: Vec::new(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(ExtractorConfig::default())
    }

    /// Ingest a function's instruction-level data.
    ///
    /// `string_loads` = (insn_offset, string_value, load_va)
    /// `call_sites` = (insn_offset, callee_name, callee_va, call_va)
    pub fn ingest_function(
        &mut self,
        function_va: Va,
        function_name: Option<String>,
        string_loads: &[(InsnOff, String, Va)],
        call_sites: &[(InsnOff, Option<String>, Va, Va)],
    ) {
        self.stats.functions_processed += 1;

        let mut contexts = Vec::new();

        for (str_off, string, load_va) in string_loads {
            self.stats.strings_extracted += 1;

            let string_ref = StringRef {
                string: string.clone(),
                load_va: *load_va,
                function_va,
                insn_offset: *str_off,
            };

            // Find nearby calls
            let nearby_apis: Vec<ApiCallSite> = call_sites.iter()
                .filter_map(|(call_off, name, callee_va, call_va)| {
                    let dist = str_off.abs_diff(*call_off);
                    if dist <= self.config.api_proximity_window {
                        Some(ApiCallSite {
                            call_va: *call_va,
                            callee_name: name.clone(),
                            callee_va: *callee_va,
                            distance: dist,
                        })
                    } else {
                        None
                    }
                })
                .collect();

            let api_names: Vec<String> = nearby_apis.iter()
                .filter_map(|a| a.callee_name.clone())
                .collect();

            let semantic_tag = infer_semantic_tag(&api_names, string);

            // Record api-pair entries
            for api in &nearby_apis {
                if let Some(name) = &api.callee_name {
                    self.api_pairs.push(ApiNearString {
                        api_name: name.clone(),
                        api_va: api.callee_va,
                        string_value: string.clone(),
                        string_va: *load_va,
                        function_va,
                        distance: api.distance,
                    });
                    self.stats.api_pairs_found += 1;
                }
            }

            contexts.push(StringContext {
                string_ref,
                nearby_apis,
                api_names,
                semantic_tag,
            });
        }

        self.functions.insert(function_va, StringFunction {
            function_va,
            function_name,
            contexts,
        });
    }

    /// Return all string contexts across all functions.
    #[must_use]
    pub fn all_contexts(&self) -> Vec<&StringContext> {
        // Iterate functions in sorted-VA order so the output order is
        // deterministic (HashMap iteration order is random per process).
        let mut vas: Vec<Va> = self.functions.keys().copied().collect();
        vas.sort_unstable();
        vas.iter()
            .filter_map(|va| self.functions.get(va))
            .flat_map(|f| f.contexts.iter())
            .collect()
    }

    /// Return all API-near-string pairs.
    #[must_use]
    pub fn api_pairs(&self) -> &[ApiNearString] {
        &self.api_pairs
    }

    /// Return all strings that appear near a specific API.
    #[must_use]
    pub fn strings_near_api(&self, api_name: &str) -> Vec<&str> {
        let mut seen = std::collections::HashSet::new();
        self.api_pairs.iter()
            .filter(|p| p.api_name.eq_ignore_ascii_case(api_name))
            .map(|p| p.string_value.as_str())
            .filter(|&s| seen.insert(s))
            .collect()
    }

    /// Return the function containing the most strings.
    #[must_use]
    pub fn richest_function(&self) -> Option<&StringFunction> {
        // Deterministic tie-break: on equal string counts pick the lowest
        // function VA (HashMap iteration order is otherwise random).
        self.functions
            .values()
            .max_by_key(|f| (f.string_count(), std::cmp::Reverse(f.function_va)))
    }

    /// Group strings by shared API proximity.
    pub fn group_by_api(&self) -> Vec<StringGroup> {
        // Build: api_name -> set of (string, function_va)
        let mut api_to_strings: HashMap<String, Vec<(String, Va)>> = HashMap::new();
        for pair in &self.api_pairs {
            api_to_strings
                .entry(pair.api_name.clone())
                .or_default()
                .push((pair.string_value.clone(), pair.function_va));
        }

        let mut groups: Vec<StringGroup> = Vec::new();
        let mut group_id = 0u32;

        // Iterate APIs in sorted-name order: the max_groups cutoff and the
        // group_id assignment must not depend on HashMap iteration order.
        let mut api_names: Vec<&String> = api_to_strings.keys().collect();
        api_names.sort_unstable();
        for api_name in api_names {
            let entries = &api_to_strings[api_name];
            if entries.len() < self.config.min_group_size {
                continue;
            }

            let mut strings: Vec<String> = entries.iter().map(|(s, _)| s.clone()).collect();
            strings.sort();
            strings.dedup();

            let mut functions: Vec<Va> = entries.iter().map(|(_, f)| *f).collect();
            functions.sort();
            functions.dedup();

            let tag = api_semantic_tag(api_name);

            groups.push(StringGroup {
                group_id,
                pivot_apis: vec![api_name.clone()],
                strings,
                functions,
                inferred_tag: tag,
            });
            group_id += 1;

            if groups.len() >= self.config.max_groups {
                break;
            }
        }

        // Stable, deterministic order: size desc, then pivot API name.
        groups.sort_by(|a, b| {
            b.size()
                .cmp(&a.size())
                .then_with(|| a.pivot_apis.cmp(&b.pivot_apis))
        });
        groups
    }

    /// Find all strings with a given semantic tag.
    pub fn strings_by_tag(&self, tag: &str) -> Vec<&str> {
        // Deterministic output order: walk contexts in sorted-VA order.
        self.all_contexts()
            .into_iter()
            .filter(|c| c.semantic_tag.as_deref() == Some(tag))
            .map(|c| c.string_ref.string.as_str())
            .collect()
    }

    /// Return all functions that reference a given string value.
    pub fn functions_with_string(&self, s: &str) -> Vec<Va> {
        let mut out: Vec<Va> = self.functions.values()
            .filter(|f| f.contexts.iter().any(|c| c.string_ref.string == s))
            .map(|f| f.function_va)
            .collect();
        out.sort_unstable();
        out
    }

    #[must_use]
    pub fn stats(&self) -> &ExtractorStats {
        &self.stats
    }

    #[must_use]
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }
}

// ---------------------------------------------------------------------------
// Heuristics for semantic tag inference
// ---------------------------------------------------------------------------

/// Infer a semantic tag from nearby API names and the string itself.
#[must_use]
pub fn infer_semantic_tag(api_names: &[String], string: &str) -> Option<String> {
    let lower_string = string.to_lowercase();

    // Network APIs
    let net_apis = ["connect", "send", "recv", "socket", "WSAStartup", "getaddrinfo",
                    "InternetOpen", "HttpSendRequest", "URLDownloadToFile"];
    if api_names.iter().any(|n| net_apis.iter().any(|na| n.eq_ignore_ascii_case(na))) {
        return Some("network".to_owned());
    }

    // File system
    let file_apis = ["CreateFile", "ReadFile", "WriteFile", "DeleteFile",
                     "fopen", "fread", "fwrite", "rename", "unlink"];
    if api_names.iter().any(|n| file_apis.iter().any(|fa| n.eq_ignore_ascii_case(fa))) {
        return Some("filesystem".to_owned());
    }

    // Registry
    let reg_apis = ["RegOpenKey", "RegQueryValue", "RegSetValue", "RegCreateKey", "RegDeleteKey"];
    if api_names.iter().any(|n| reg_apis.iter().any(|ra| n.eq_ignore_ascii_case(ra))) {
        return Some("registry".to_owned());
    }

    // Process
    let proc_apis = ["CreateProcess", "OpenProcess", "TerminateProcess", "VirtualAlloc",
                     "WriteProcessMemory", "CreateThread"];
    if api_names.iter().any(|n| proc_apis.iter().any(|pa| n.eq_ignore_ascii_case(pa))) {
        return Some("process".to_owned());
    }

    // Crypto
    let crypto_apis = ["CryptEncrypt", "CryptDecrypt", "CryptHashData", "BCryptEncrypt",
                       "EVP_EncryptInit", "AES_set_encrypt_key"];
    if api_names.iter().any(|n| crypto_apis.iter().any(|ca| n.eq_ignore_ascii_case(ca))) {
        return Some("crypto".to_owned());
    }

    // Error/debug
    if lower_string.contains("error") || lower_string.contains("fail") || lower_string.contains("exception") {
        return Some("error_message".to_owned());
    }

    None
}

/// Infer a semantic tag for a group given an API pivot name.
#[must_use]
fn api_semantic_tag(api_name: &str) -> Option<String> {
    let lower = api_name.to_lowercase();
    if lower.contains("file") || lower.contains("open") || lower.contains("read") || lower.contains("write") {
        return Some("filesystem".to_owned());
    }
    if lower.contains("socket") || lower.contains("connect") || lower.contains("send") || lower.contains("recv") || lower.contains("internet") {
        return Some("network".to_owned());
    }
    if lower.contains("reg") {
        return Some("registry".to_owned());
    }
    if lower.contains("process") || lower.contains("thread") || lower.contains("alloc") {
        return Some("process".to_owned());
    }
    if lower.contains("crypt") || lower.contains("aes") || lower.contains("sha") || lower.contains("hash") {
        return Some("crypto".to_owned());
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_extractor() -> ContextExtractor {
        ContextExtractor::with_defaults()
    }

    #[test]
    fn test_ingest_function_basic() {
        let mut ext = make_extractor();
        let strings = vec![(0u32, "https://c2.example.com".to_owned(), 0x1000u64)];
        let calls: Vec<(u32, Option<String>, u64, u64)> = vec![
            (3, Some("connect".to_owned()), 0x2000, 0x1010),
        ];
        ext.ingest_function(0x4000, Some("connect_func".to_owned()), &strings, &calls);
        assert_eq!(ext.function_count(), 1);
        assert_eq!(ext.stats().strings_extracted, 1);
    }

    #[test]
    fn test_context_semantic_tag_network() {
        let mut ext = make_extractor();
        let strings = vec![(0u32, "http://malware.example/c2".to_owned(), 0x1000u64)];
        let calls: Vec<(u32, Option<String>, u64, u64)> = vec![
            (2, Some("connect".to_owned()), 0x2000, 0x1008),
        ];
        ext.ingest_function(0x4000, None, &strings, &calls);
        let ctxs = ext.all_contexts();
        assert_eq!(ctxs.len(), 1);
        assert_eq!(ctxs[0].semantic_tag, Some("network".to_owned()));
    }

    #[test]
    fn regress_richest_function_deterministic_on_ties() {
        // Two functions with the same string count: the lowest VA must win,
        // on every call (previously HashMap iteration order decided).
        let mut ext = make_extractor();
        for va in [0x9000u64, 0x4000, 0x7000] {
            let strings = vec![(0u32, format!("s_{va}"), va + 0x10)];
            let calls: Vec<(u32, Option<String>, u64, u64)> = vec![];
            ext.ingest_function(va, None, &strings, &calls);
        }
        for _ in 0..20 {
            assert_eq!(ext.richest_function().unwrap().function_va, 0x4000);
        }
    }

    #[test]
    fn regress_functions_with_string_sorted() {
        let mut ext = make_extractor();
        for va in [0x9000u64, 0x4000, 0x7000] {
            let strings = vec![(0u32, "shared".to_owned(), va + 0x10)];
            let calls: Vec<(u32, Option<String>, u64, u64)> = vec![];
            ext.ingest_function(va, None, &strings, &calls);
        }
        assert_eq!(ext.functions_with_string("shared"), vec![0x4000, 0x7000, 0x9000]);
    }

    #[test]
    fn test_strings_near_api() {
        let mut ext = make_extractor();
        let strings = vec![
            (0u32, "config.ini".to_owned(), 0x1000u64),
            (5, "data.bin".to_owned(), 0x1020),
        ];
        let calls: Vec<(u32, Option<String>, u64, u64)> = vec![
            (2, Some("CreateFile".to_owned()), 0x2000, 0x1008),
            (7, Some("CreateFile".to_owned()), 0x2000, 0x1028),
        ];
        ext.ingest_function(0x4000, None, &strings, &calls);
        let near = ext.strings_near_api("CreateFile");
        assert_eq!(near.len(), 2);
    }

    #[test]
    fn test_group_by_api() {
        let mut ext = make_extractor();
        for i in 0..3 {
            let strings = vec![(0u32, format!("url_{}", i), 0x1000 + i as u64 * 0x100)];
            let calls: Vec<(u32, Option<String>, u64, u64)> = vec![
                (2, Some("connect".to_owned()), 0x2000, 0x1008 + i as u64 * 0x100),
            ];
            ext.ingest_function(0x4000 + i as u64 * 0x100, None, &strings, &calls);
        }
        let groups = ext.group_by_api();
        assert!(!groups.is_empty());
        let connect_group = groups.iter().find(|g| g.pivot_apis.contains(&"connect".to_owned()));
        assert!(connect_group.is_some());
        assert_eq!(connect_group.unwrap().size(), 3);
    }

    #[test]
    fn test_strings_by_tag() {
        let mut ext = make_extractor();
        let strings = vec![(0u32, "fail: bad auth".to_owned(), 0x1000u64)];
        let calls: Vec<(u32, Option<String>, u64, u64)> = vec![];
        ext.ingest_function(0x4000, None, &strings, &calls);
        let tagged = ext.strings_by_tag("error_message");
        assert!(!tagged.is_empty());
    }

    #[test]
    fn test_functions_with_string() {
        let mut ext = make_extractor();
        let s = "TARGET_STRING".to_owned();
        ext.ingest_function(0x1000, None, &[(0, s.clone(), 0x1000)], &[]);
        ext.ingest_function(0x2000, None, &[(0, s.clone(), 0x2000)], &[]);
        let fns = ext.functions_with_string(&s);
        assert_eq!(fns.len(), 2);
    }

    #[test]
    fn test_richest_function() {
        let mut ext = make_extractor();
        ext.ingest_function(0x1000, None, &[(0, "a".to_owned(), 0x1000)], &[]);
        ext.ingest_function(0x2000, None, &[
            (0, "b".to_owned(), 0x2000),
            (5, "c".to_owned(), 0x2010),
        ], &[]);
        let richest = ext.richest_function().unwrap();
        assert_eq!(richest.function_va, 0x2000);
    }

    #[test]
    fn test_all_api_names_in_function() {
        let mut ext = make_extractor();
        ext.ingest_function(
            0x1000,
            Some("fn_test".to_owned()),
            &[(0, "test.txt".to_owned(), 0x1000)],
            &[
                (2, Some("CreateFile".to_owned()), 0x2000, 0x1008),
                (4, Some("ReadFile".to_owned()), 0x3000, 0x1010),
            ],
        );
        let func = ext.functions.get(&0x1000u64).unwrap();
        let apis = func.all_api_names();
        assert!(apis.contains(&"CreateFile".to_owned()));
        assert!(apis.contains(&"ReadFile".to_owned()));
    }

    #[test]
    fn test_infer_semantic_tag_registry() {
        let tag = infer_semantic_tag(&["RegOpenKey".to_owned()], "SOFTWARE\\Malware");
        assert_eq!(tag, Some("registry".to_owned()));
    }

    #[test]
    fn test_infer_semantic_tag_crypto() {
        let tag = infer_semantic_tag(&["CryptEncrypt".to_owned()], "encrypted_data");
        assert_eq!(tag, Some("crypto".to_owned()));
    }

    #[test]
    fn test_api_proximity_window() {
        let config = ExtractorConfig {
            api_proximity_window: 3,
            ..Default::default()
        };
        let mut ext = ContextExtractor::new(config);
        let strings = vec![(0u32, "test".to_owned(), 0x1000u64)];
        let calls: Vec<(u32, Option<String>, u64, u64)> = vec![
            (2, Some("close_api".to_owned()), 0x2000, 0x1008),  // within window
            (10, Some("far_api".to_owned()), 0x3000, 0x1028),   // outside window
        ];
        ext.ingest_function(0x4000, None, &strings, &calls);
        let ctx = &ext.all_contexts()[0];
        assert!(ctx.has_api("close_api"));
        assert!(!ctx.has_api("far_api"));
    }

    #[test]
    fn test_string_group_tag_network() {
        let tag = api_semantic_tag("connect");
        assert_eq!(tag, Some("network".to_owned()));
    }

    // Coverage-gap: closest_api / api_count had no direct test.
    #[test]
    fn test_closest_api_and_api_count() {
        let mut ext = make_extractor();
        let strings = vec![(5u32, "cfg".to_owned(), 0x1000u64)];
        let calls: Vec<(u32, Option<String>, u64, u64)> = vec![
            (9, Some("far_one".to_owned()), 0x2000, 0x1010),
            (6, Some("near_one".to_owned()), 0x3000, 0x1008),
        ];
        ext.ingest_function(0x4000, None, &strings, &calls);
        let ctx = &ext.all_contexts()[0];
        assert_eq!(ctx.api_count(), 2);
        assert_eq!(ctx.closest_api().unwrap().callee_name.as_deref(), Some("near_one"));
    }

    // Coverage-gap: closest_api on a context with no nearby APIs.
    #[test]
    fn test_closest_api_empty() {
        let mut ext = make_extractor();
        let strings = vec![(0u32, "lonely".to_owned(), 0x1000u64)];
        let calls: Vec<(u32, Option<String>, u64, u64)> = vec![];
        ext.ingest_function(0x4000, None, &strings, &calls);
        let ctx = &ext.all_contexts()[0];
        assert_eq!(ctx.api_count(), 0);
        assert!(ctx.closest_api().is_none());
    }

    // Coverage-gap: string_count / unique_strings had no direct test.
    #[test]
    fn test_string_count_and_unique_strings() {
        let mut ext = make_extractor();
        let strings = vec![
            (0u32, "dup".to_owned(), 0x1000u64),
            (2, "dup".to_owned(), 0x1010),
            (4, "other".to_owned(), 0x1020),
        ];
        let calls: Vec<(u32, Option<String>, u64, u64)> = vec![];
        ext.ingest_function(0x4000, None, &strings, &calls);
        let funcs = ext.all_contexts();
        assert_eq!(funcs.len(), 3);
        let f = ext.richest_function().unwrap();
        assert_eq!(f.string_count(), 3);
        // unique_strings dedups, preserving first-occurrence order.
        assert_eq!(f.unique_strings(), vec!["dup", "other"]);
    }

    // Coverage-gap: api_pairs accessor had no direct test.
    #[test]
    fn test_api_pairs_accessor() {
        let mut ext = make_extractor();
        assert!(ext.api_pairs().is_empty());
        let strings = vec![(0u32, "config.ini".to_owned(), 0x1000u64)];
        let calls: Vec<(u32, Option<String>, u64, u64)> = vec![
            (2, Some("CreateFile".to_owned()), 0x2000, 0x1008),
        ];
        ext.ingest_function(0x4000, None, &strings, &calls);
        let pairs = ext.api_pairs();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].api_name, "CreateFile");
        assert_eq!(pairs[0].string_value, "config.ini");
        assert_eq!(pairs[0].function_va, 0x4000);
    }
}
