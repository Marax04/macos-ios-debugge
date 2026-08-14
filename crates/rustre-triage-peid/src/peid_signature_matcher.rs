// peid_signature_matcher.rs — PEiD signature matcher for RustRE

use std::collections::HashMap;

// ─── PeidSignature ────────────────────────────────────────────────────────────

/// A PEiD signature: a sequence of bytes with optional wildcards (`None` = `??`).
#[derive(Debug, Clone)]
pub struct PeidSignature {
    pub name: String,
    /// `None` = wildcard, `Some(b)` = exact byte match.
    pub signature_bytes: Vec<Option<u8>>,
    /// Only match at the entry point if true.
    pub ep_only: bool,
}

impl PeidSignature {
    pub fn new(name: &str, sig: Vec<Option<u8>>, ep_only: bool) -> Self {
        Self {
            name: name.to_string(),
            signature_bytes: sig,
            ep_only,
        }
    }

    /// Return the index of the first non-wildcard byte, or None if all wildcards.
    pub fn first_concrete_byte(&self) -> Option<(usize, u8)> {
        self.signature_bytes.iter().enumerate().find_map(|(i, opt)| opt.map(|b| (i, b)))
    }

    pub fn len(&self) -> usize {
        self.signature_bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signature_bytes.is_empty()
    }
}

// ─── PEiD database parser ─────────────────────────────────────────────────────

/// Parse a PEiD `userdb.txt` format into signatures.
/// Format:
/// ```text
/// [Packer Name v1.0]
/// signature = XX XX ?? XX ...
/// ep_only = true
/// ```
pub fn parse_peid_database(text: &str) -> Vec<PeidSignature> {
    let mut sigs = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_sig: Option<Vec<Option<u8>>> = None;
    let mut ep_only = true;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            // Flush previous
            if let (Some(name), Some(sig)) = (current_name.take(), current_sig.take()) {
                sigs.push(PeidSignature::new(&name, sig, ep_only));
            }
            current_name = Some(line[1..line.len() - 1].to_string());
            ep_only = true;
            current_sig = None;
        } else if let Some(rest) = line.strip_prefix("signature = ") {
            match parse_signature_bytes(rest) {
                Ok(bytes) => current_sig = Some(bytes),
                Err(e) => {
                    // Skip this entry — a bad token in the database should not
                    // silently produce a weaker wildcard-filled signature.
                    eprintln!("rustre-triage-peid: skipping signature for '{:?}': {e}",
                        current_name);
                    current_name = None;
                    current_sig = None;
                }
            }
        } else if line.starts_with("ep_only = ") {
            let val = &line["ep_only = ".len()..];
            ep_only = val.trim().eq_ignore_ascii_case("true");
        }
    }
    // Flush last
    if let (Some(name), Some(sig)) = (current_name, current_sig) {
        sigs.push(PeidSignature::new(&name, sig, ep_only));
    }
    sigs
}

/// Parse a space-separated hex signature string ("XX ?? AB") into bytes.
///
/// Returns `Err` with a diagnostic message if any token is not a valid hex byte
/// or a wildcard (`??` / `?`). Unrecognised tokens are never silently treated
/// as wildcards — the caller decides how to handle the error.
///
/// # Errors
/// Returns `Err(String)` describing the first unrecognised token.
pub fn parse_signature_bytes(s: &str) -> Result<Vec<Option<u8>>, String> {
    let mut result = Vec::new();
    for tok in s.split_whitespace() {
        if tok == "??" || tok == "?" {
            result.push(None);
        } else {
            match u8::from_str_radix(tok, 16) {
                Ok(b) => result.push(Some(b)),
                Err(_) => {
                    return Err(format!(
                        "unrecognised token '{tok}' in signature string '{s}'"
                    ));
                }
            }
        }
    }
    Ok(result)
}

// ─── match_signature ─────────────────────────────────────────────────────────

/// Check if a signature matches at a specific offset in `pe_data`.
pub fn match_at_offset(sig: &PeidSignature, data: &[u8], offset: usize) -> bool {
    if offset + sig.len() > data.len() {
        return false;
    }
    for (i, &pattern_byte) in sig.signature_bytes.iter().enumerate() {
        if let Some(expected) = pattern_byte {
            if data[offset + i] != expected {
                return false;
            }
        }
        // None = wildcard, always matches
    }
    true
}

/// Match signature against PE data. If ep_only, only check at `ep_offset`.
pub fn match_signature(sig: &PeidSignature, pe_data: &[u8], ep_offset: usize) -> bool {
    if sig.is_empty() || pe_data.is_empty() {
        return false;
    }
    if sig.ep_only {
        match_at_offset(sig, pe_data, ep_offset)
    } else {
        // Scan entire file
        for offset in 0..pe_data.len().saturating_sub(sig.len().saturating_sub(1)) {
            if match_at_offset(sig, pe_data, offset) {
                return true;
            }
        }
        false
    }
}

// ─── PatternAccelerator ───────────────────────────────────────────────────────

/// Accelerates signature matching by indexing signatures by first concrete byte.
pub struct PatternAccelerator {
    /// Maps first_non_wildcard_byte → list of signature indices in the database.
    first_byte_table: HashMap<u8, Vec<usize>>,
    wildcard_only: Vec<usize>,
}

impl PatternAccelerator {
    pub fn new(sigs: &[PeidSignature]) -> Self {
        let mut first_byte_table: HashMap<u8, Vec<usize>> = HashMap::new();
        let mut wildcard_only = Vec::new();
        for (i, sig) in sigs.iter().enumerate() {
            match sig.first_concrete_byte() {
                Some((_, byte)) => {
                    first_byte_table.entry(byte).or_default().push(i);
                }
                None => wildcard_only.push(i),
            }
        }
        Self { first_byte_table, wildcard_only }
    }

    /// Return the indices of candidate signatures for the byte at `ep_offset`.
    pub fn candidates_for_ep(&self, data: &[u8], ep_offset: usize) -> Vec<usize> {
        let mut result = self.wildcard_only.clone();
        if let Some(&b) = data.get(ep_offset) {
            if let Some(indices) = self.first_byte_table.get(&b) {
                result.extend_from_slice(indices);
            }
        }
        result
    }
}

// ─── PeidMatcher ─────────────────────────────────────────────────────────────

pub struct PeidMatcher {
    pub signatures: Vec<PeidSignature>,
    pub accelerator: PatternAccelerator,
}

impl PeidMatcher {
    pub fn new(signatures: Vec<PeidSignature>) -> Self {
        let accelerator = PatternAccelerator::new(&signatures);
        Self { signatures, accelerator }
    }

    pub fn from_database(text: &str) -> Self {
        Self::new(parse_peid_database(text))
    }

    pub fn with_builtins() -> Self {
        Self::new(builtin_signatures())
    }

    pub fn match_all_signatures(&self, pe_data: &[u8], ep_offset: usize) -> Vec<String> {
        let candidates = self.accelerator.candidates_for_ep(pe_data, ep_offset);
        let mut matches = Vec::new();

        for &idx in &candidates {
            let sig = &self.signatures[idx];
            if sig.ep_only {
                if match_at_offset(sig, pe_data, ep_offset) {
                    matches.push(sig.name.clone());
                }
            } else if match_signature(sig, pe_data, ep_offset) {
                matches.push(sig.name.clone());
            }
        }

        // Also check non-EP-only sigs not in the candidate list (keyed by a non-EP byte)
        for (idx, sig) in self.signatures.iter().enumerate() {
            if !sig.ep_only && !candidates.contains(&idx) {
                if match_signature(sig, pe_data, ep_offset) {
                    matches.push(sig.name.clone());
                }
            }
        }

        matches.dedup();
        matches
    }

    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }
}

// ─── Built-in signatures ─────────────────────────────────────────────────────

/// A representative set of 30+ common packer/compiler signatures.
pub fn builtin_signatures() -> Vec<PeidSignature> {
    // Helper closures
    let sig = |name: &str, bytes: &[Option<u8>], ep_only: bool| {
        PeidSignature::new(name, bytes.to_vec(), ep_only)
    };
    let b = |v: u8| Some(v);
    let w = None::<u8>;

    vec![
        // UPX
        sig("UPX 0.x", &[b(0x60), b(0xBE), w, w, w, w, b(0x8D), b(0xBE)], true),
        sig("UPX 1.x", &[b(0x60), b(0xBE), w, w, w, w, b(0x8D), b(0xBE), w, w, w, w], true),
        sig("UPX 2.x", &[b(0x60), b(0xBE), w, w, w, w, b(0x8D), b(0xBE), w, w, w, w, b(0x57)], true),
        sig("UPX 3.x", &[b(0x53), b(0x55), b(0x57), b(0x56), b(0x52), b(0x51), b(0x41), b(0x50)], true),
        // ASPack
        sig("ASPack 1.x", &[b(0x60), b(0xE8), b(0x00), b(0x00), b(0x00), b(0x00), b(0x5D)], true),
        sig("ASPack 2.x", &[b(0x60), b(0xE8), b(0x03), b(0x00), b(0x00), b(0x00), b(0xE9), b(0xEB)], true),
        // PECompact
        sig("PECompact 1.x", &[b(0xEB), b(0x06), b(0x68), w, w, w, w, b(0xC3)], true),
        sig("PECompact 2.x", &[b(0xEB), b(0x06), b(0x68), w, w, w, w, b(0xC3), b(0x9C)], true),
        // MPRESS
        sig("MPRESS 1.x", &[b(0x60), b(0x68), w, w, w, w, b(0x68), w, w, w, w, b(0x68)], true),
        // NSIS
        sig("NSIS Installer", &[b(0xEF), b(0xBE), b(0xAD), b(0xDE), b(0x4E), b(0x75), b(0x6C), b(0x6C)], false),
        // FSG
        sig("FSG 1.0", &[b(0xBB), w, w, w, w, b(0xBF), w, w, w, w, b(0xBE), w, w, w, w, b(0x53)], true),
        sig("FSG 2.0", &[b(0x87), b(0x25), w, w, w, w, b(0x61), w, w, w, w, b(0x94)], true),
        // Themida
        sig("Themida", &[b(0xEB), b(0x0B), b(0x00), b(0x00), b(0x00), b(0x00), b(0x00), b(0x00), b(0x00), b(0x00), b(0x00), b(0x8B), b(0x45)], true),
        // VMProtect
        sig("VMProtect 1.x", &[b(0x9C), b(0x60), b(0xE8), b(0x00), b(0x00), b(0x00), b(0x00), b(0x5D)], true),
        sig("VMProtect 2.x", &[b(0xE9), w, w, w, w, b(0x00), b(0x00), b(0x00), b(0x00), b(0x00)], true),
        // Delphi
        sig("Borland Delphi", &[b(0x55), b(0x8B), b(0xEC), b(0x83), b(0xC4), w, b(0xBA), w, w, w, w, b(0xA1)], true),
        // MSVC
        sig("MSVC 6.0", &[b(0x55), b(0x8B), b(0xEC), b(0x6A), b(0xFF), b(0x68), w, w, w, w, b(0x68)], true),
        sig("MSVC 7.0+", &[b(0xE8), w, w, w, w, b(0xE9), w, w, w, w, b(0x00), b(0x00)], true),
        // MinGW
        sig("MinGW", &[b(0x55), b(0x89), b(0xE5), b(0x83), b(0xEC), w, b(0xC7), b(0x04), b(0x24)], true),
        // Go runtime
        sig("Go runtime", &[b(0x64), b(0x48), b(0x8B), b(0x0C), b(0x25), b(0xF8), b(0xFF), b(0xFF), b(0xFF)], false),
        // PyInstaller
        sig("PyInstaller", &[b(0x4D), b(0x45), b(0x49), b(0x01), b(0x00)], false),
        // InnoSetup
        sig("InnoSetup", &[b(0x55), b(0x8B), b(0xEC), b(0x83), b(0xC4), b(0xF0), b(0x53), b(0x56), b(0x57)], true),
        // PEX
        sig("PEX 0.99", &[b(0xEB), b(0x01), b(0xFF), b(0x53), b(0x60), b(0xE8), b(0x00), b(0x00), b(0x00), b(0x00), b(0x5D)], true),
        // ExeCryptor
        sig("ExeCryptor", &[b(0xEB), b(0x03), b(0xC7), b(0x83), b(0xEB), w, b(0x83), b(0xC3)], true),
        // Petite
        sig("Petite 2.x", &[b(0xB8), w, w, w, w, b(0x68), w, w, w, w, b(0x64), b(0xFF), b(0x35)], true),
        // yoda's crypter
        sig("yoda's Crypter 1.3", &[b(0xEB), b(0x20), b(0x59), b(0x6F), b(0x64), b(0x61), b(0x27), b(0x73)], true),
        // NsPack
        sig("NsPack 1.x", &[b(0x9C), b(0x60), b(0xE8), b(0x00), b(0x00), b(0x00), b(0x00), b(0x5D), b(0x81), b(0xED)], true),
        // Kkrunchy
        sig("kkrunchy", &[b(0x60), b(0xBE), w, w, w, w, b(0x8D), b(0xBE), w, w, w, w, b(0xC7), b(0x87)], true),
        // Armadillo
        sig("Armadillo v1.xx", &[b(0x55), b(0x8B), b(0xEC), b(0x6A), b(0xFF), b(0x68), w, w, w, w, b(0x68), w, w, w, w, b(0x64), b(0xA1)], true),
        // ACProtect
        sig("ACProtect 1.x", &[b(0xB8), w, w, w, w, b(0xEB), b(0x10), b(0x00), b(0x00), b(0x00), b(0x00), b(0x00), b(0x00), b(0x00), b(0x00), b(0x00), b(0x00)], true),
    ]
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn upx_data() -> Vec<u8> {
        // UPX 0.x EP pattern: 60 BE XX XX XX XX 8D BE
        let mut d = vec![0u8; 256];
        d[0] = 0x60; d[1] = 0xBE; d[2] = 0x00; d[3] = 0x10; d[4] = 0x40; d[5] = 0x00;
        d[6] = 0x8D; d[7] = 0xBE;
        d
    }

    #[test]
    fn test_parse_signature_bytes_wildcards() {
        let sig = parse_signature_bytes("60 BE ?? 8D").unwrap();
        assert_eq!(sig.len(), 4);
        assert_eq!(sig[0], Some(0x60));
        assert_eq!(sig[2], None);
    }

    #[test]
    fn test_parse_peid_database_basic() {
        let db = "[UPX Test]\nsignature = 60 BE ?? 8D\nep_only = true\n";
        let sigs = parse_peid_database(db);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].name, "UPX Test");
        assert!(sigs[0].ep_only);
    }

    #[test]
    fn test_parse_peid_database_multiple() {
        let db = "[Sig A]\nsignature = 60 BE\nep_only = true\n\n[Sig B]\nsignature = 55 8B\nep_only = false\n";
        let sigs = parse_peid_database(db);
        assert_eq!(sigs.len(), 2);
    }

    #[test]
    fn test_match_at_offset_exact() {
        let sig = PeidSignature::new("test", vec![Some(0x60), Some(0xBE)], true);
        let data = vec![0x60, 0xBE, 0x00];
        assert!(match_at_offset(&sig, &data, 0));
    }

    #[test]
    fn test_match_at_offset_wildcard() {
        let sig = PeidSignature::new("test", vec![Some(0x60), None, Some(0xBE)], true);
        let data = vec![0x60, 0xFF, 0xBE];
        assert!(match_at_offset(&sig, &data, 0));
    }

    #[test]
    fn test_match_at_offset_fail() {
        let sig = PeidSignature::new("test", vec![Some(0x60), Some(0x90)], true);
        let data = vec![0x60, 0xBE, 0x00];
        assert!(!match_at_offset(&sig, &data, 0));
    }

    #[test]
    fn test_match_signature_ep_only() {
        let sig = PeidSignature::new("upx", vec![Some(0x60), Some(0xBE)], true);
        let data = upx_data();
        assert!(match_signature(&sig, &data, 0));
        assert!(!match_signature(&sig, &data, 10));
    }

    #[test]
    fn test_match_signature_whole_file() {
        let sig = PeidSignature::new("marker", vec![Some(0xDE), Some(0xAD)], false);
        let mut data = vec![0u8; 64];
        data[30] = 0xDE;
        data[31] = 0xAD;
        assert!(match_signature(&sig, &data, 0));
    }

    #[test]
    fn test_peid_matcher_with_builtins_loads() {
        let m = PeidMatcher::with_builtins();
        assert!(m.signature_count() >= 30);
    }

    #[test]
    fn test_peid_matcher_detects_upx() {
        let m = PeidMatcher::with_builtins();
        let data = upx_data();
        let hits = m.match_all_signatures(&data, 0);
        assert!(hits.iter().any(|n| n.contains("UPX")));
    }

    #[test]
    fn test_peid_matcher_no_false_positive_empty() {
        let m = PeidMatcher::with_builtins();
        let data = vec![0u8; 256];
        let hits = m.match_all_signatures(&data, 0);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_pattern_accelerator_candidates_for_ep() {
        let sigs = vec![
            PeidSignature::new("a", vec![Some(0x60)], true),
            PeidSignature::new("b", vec![Some(0x90)], true),
        ];
        let accel = PatternAccelerator::new(&sigs);
        let data = vec![0x60u8; 4];
        let cands = accel.candidates_for_ep(&data, 0);
        assert!(cands.contains(&0));
        assert!(!cands.contains(&1));
    }

    #[test]
    fn test_signature_first_concrete_byte() {
        let sig = PeidSignature::new("t", vec![None, None, Some(0xAB)], true);
        assert_eq!(sig.first_concrete_byte(), Some((2, 0xAB)));
    }

    #[test]
    fn test_signature_all_wildcards() {
        let sig = PeidSignature::new("t", vec![None, None], true);
        assert_eq!(sig.first_concrete_byte(), None);
    }

    #[test]
    fn test_match_all_deduplication() {
        let sigs = vec![
            PeidSignature::new("dup", vec![Some(0x60)], true),
            PeidSignature::new("dup", vec![Some(0x60)], true),
        ];
        let m = PeidMatcher::new(sigs);
        let data = vec![0x60u8; 8];
        let hits = m.match_all_signatures(&data, 0);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_ep_only_false_not_at_ep() {
        let sig = PeidSignature::new("nep", vec![Some(0xCC)], false);
        let mut data = vec![0u8; 32];
        data[20] = 0xCC;
        // ep_offset = 0, but byte is at offset 20
        assert!(match_signature(&sig, &data, 0));
    }
}
