// compiler_detector.rs — Compiler/linker detector for RustRE

// ─── CompilerFamily ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompilerFamily {
    MSVC,
    GCC,
    Clang,
    MinGW,
    Delphi,
    FPC,
    Rust,
    Go,
    Swift,
    Unknown,
}

impl CompilerFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            CompilerFamily::MSVC => "MSVC",
            CompilerFamily::GCC => "GCC",
            CompilerFamily::Clang => "Clang",
            CompilerFamily::MinGW => "MinGW",
            CompilerFamily::Delphi => "Delphi",
            CompilerFamily::FPC => "FPC",
            CompilerFamily::Rust => "Rust",
            CompilerFamily::Go => "Go",
            CompilerFamily::Swift => "Swift",
            CompilerFamily::Unknown => "Unknown",
        }
    }
}

// ─── CompilerInfo ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CompilerInfo {
    pub name: String,
    pub version: Option<String>,
    pub confidence: f64,
    pub evidence: Vec<String>,
    pub family: CompilerFamily,
}

impl CompilerInfo {
    pub fn new(family: CompilerFamily, name: &str, confidence: f64) -> Self {
        Self {
            name: name.to_string(),
            version: None,
            confidence,
            evidence: Vec::new(),
            family,
        }
    }

    pub fn with_version(mut self, v: &str) -> Self {
        self.version = Some(v.to_string());
        self
    }

    pub fn add_evidence(&mut self, e: &str) {
        self.evidence.push(e.to_string());
    }

    pub fn summary(&self) -> String {
        match &self.version {
            Some(v) => format!("{} {} (conf: {:.2})", self.name, v, self.confidence),
            None => format!("{} (conf: {:.2})", self.name, self.confidence),
        }
    }
}

// ─── CompilerReport ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct CompilerReport {
    pub primary: CompilerInfo,
    pub secondary: Vec<CompilerInfo>,
}

impl CompilerReport {
    pub fn new(primary: CompilerInfo) -> Self {
        Self { primary, secondary: Vec::new() }
    }

    pub fn add_secondary(&mut self, info: CompilerInfo) {
        self.secondary.push(info);
    }

    pub fn all_families(&self) -> Vec<&CompilerFamily> {
        let mut v = vec![&self.primary.family];
        for s in &self.secondary {
            v.push(&s.family);
        }
        v
    }
}

// ─── Rich Header product IDs ─────────────────────────────────────────────────

/// Map a Visual Studio linker product ID to a version string.
fn vs_product_id_to_version(prod_id: u16) -> Option<&'static str> {
    match prod_id {
        0x0000..=0x0006 => Some("MSVC 6.0"),
        0x0007..=0x000C => Some("MSVC 2002/2003"),
        0x0019..=0x001C => Some("MSVC 2005"),
        0x001E..=0x0025 => Some("MSVC 2008"),
        0x0060..=0x006F => Some("MSVC 2010"),
        0x0070..=0x007F => Some("MSVC 2012"),
        0x0080..=0x008F => Some("MSVC 2013"),
        0x00C0..=0x00CF => Some("MSVC 2015"),
        0x00D0..=0x00DF => Some("MSVC 2017"),
        0x00E0..=0x00EF => Some("MSVC 2019"),
        0x00F0..=0x00FF => Some("MSVC 2022"),
        _ => None,
    }
}

// ─── Helper: search for ASCII string in binary data ──────────────────────────

fn find_string(data: &[u8], pattern: &[u8]) -> bool {
    data.windows(pattern.len()).any(|w| w == pattern)
}

fn find_icase(data: &[u8], pattern: &str) -> bool {
    let pat_lower: Vec<u8> = pattern.bytes().map(|b| b.to_ascii_lowercase()).collect();
    data.windows(pat_lower.len()).any(|w| {
        w.iter().zip(pat_lower.iter()).all(|(&a, &b)| a.to_ascii_lowercase() == b)
    })
}

fn extract_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut results = Vec::new();
    let mut buf = String::new();
    for &b in data {
        if b >= 0x20 && b < 0x7F {
            buf.push(b as char);
        } else {
            if buf.len() >= min_len {
                results.push(buf.clone());
            }
            buf.clear();
        }
    }
    if buf.len() >= min_len {
        results.push(buf);
    }
    results
}

// ─── CompilerDetector ─────────────────────────────────────────────────────────

pub struct CompilerDetector<'a> {
    data: &'a [u8],
}

impl<'a> CompilerDetector<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Detect compiler from the Rich Header (Visual Studio product IDs).
    pub fn detect_from_rich_header(&self) -> Option<CompilerInfo> {
        // Rich header is between DOS stub and PE header.
        // Marker: "Rich" XOR key followed by "DanS" XOR key.
        // Simplified: look for "Rich" marker
        let rich_marker = b"Rich";
        let dans_marker = b"DanS";
        if let Some(pos) = self.data.windows(4).position(|w| w == rich_marker) {
            // Extract XOR key (4 bytes after "Rich")
            if pos + 8 > self.data.len() {
                return None;
            }
            let key = u32::from_le_bytes([
                self.data[pos + 4], self.data[pos + 5],
                self.data[pos + 6], self.data[pos + 7],
            ]);
            // Look for DanS XOR key = key
            let dans_xored = dans_marker.iter().enumerate().map(|(i, &b)| b ^ ((key >> (i * 8)) as u8)).collect::<Vec<_>>();
            if let Some(start) = self.data.windows(4).position(|w| w == dans_xored.as_slice()) {
                // Entries are 8 bytes each starting at start+16 (skip DanS header)
                let entry_start = start + 16;
                let entry_end = pos;
                let mut best_version: Option<&'static str> = None;
                let mut i = entry_start;
                while i + 8 <= entry_end {
                    // Every DWORD between "DanS" and "Rich" is stored XORed with
                    // the key — which is why `dans_xored` above had to be built
                    // to find the start. The entries need the same treatment:
                    // reading them raw yields the encrypted value, so the
                    // product id was garbage and matched a real MSVC version
                    // only by accident.
                    let comp_id = u32::from_le_bytes([
                        self.data[i], self.data[i+1], self.data[i+2], self.data[i+3],
                    ]) ^ key;
                    let prod_id = (comp_id >> 16) as u16;
                    if let Some(v) = vs_product_id_to_version(prod_id) {
                        best_version = Some(v);
                    }
                    i += 8;
                }
                if let Some(v) = best_version {
                    let mut info = CompilerInfo::new(CompilerFamily::MSVC, "MSVC", 0.9);
                    info.version = Some(v.to_string());
                    info.add_evidence("Rich header product ID matched");
                    return Some(info);
                }
            }
        }
        None
    }

    /// Detect from section names (MinGW: .eh_frame, Delphi: CODE, Go: .gopclntab).
    pub fn detect_from_sections(&self) -> Vec<CompilerInfo> {
        let mut results = Vec::new();
        // Look for section name patterns in data
        if find_string(self.data, b".eh_frame") {
            let mut info = CompilerInfo::new(CompilerFamily::MinGW, "MinGW/GCC", 0.7);
            info.add_evidence(".eh_frame section found (GCC/MinGW)");
            results.push(info);
        }
        if find_string(self.data, b".gopclntab") {
            let mut info = CompilerInfo::new(CompilerFamily::Go, "Go", 0.95);
            info.add_evidence(".gopclntab section found");
            results.push(info);
        }
        if find_string(self.data, b"CODE\0\0\0\0") || find_string(self.data, b".code\0\0\0") {
            // Delphi uses CODE as primary code section
            let mut info = CompilerInfo::new(CompilerFamily::Delphi, "Borland Delphi", 0.5);
            info.add_evidence("CODE section name found");
            results.push(info);
        }
        if find_string(self.data, b".debug_info") {
            let mut info = CompilerInfo::new(CompilerFamily::GCC, "GCC/Clang", 0.6);
            info.add_evidence(".debug_info section (DWARF, likely GCC/Clang)");
            results.push(info);
        }
        if find_string(self.data, b".pdata") && find_string(self.data, b".xdata") {
            let mut info = CompilerInfo::new(CompilerFamily::MSVC, "MSVC", 0.5);
            info.add_evidence(".pdata/.xdata sections (MSVC x64 exception handling)");
            results.push(info);
        }
        results
    }

    /// Detect from embedded strings.
    pub fn detect_from_strings(&self) -> Vec<CompilerInfo> {
        let mut results = Vec::new();
        let strings = extract_strings(self.data, 6);

        for s in &strings {
            let sl = s.to_ascii_lowercase();
            if sl.contains("gcc: (gnu)") || sl.contains("gcc version") {
                let mut info = CompilerInfo::new(CompilerFamily::GCC, "GCC", 0.9);
                info.add_evidence(s.as_str());
                // Try to extract version
                if let Some(v) = extract_version_from_string(s) {
                    info.version = Some(v);
                }
                results.push(info);
            } else if sl.contains("microsoft visual c++") || sl.contains("msvcr") {
                let mut info = CompilerInfo::new(CompilerFamily::MSVC, "MSVC", 0.85);
                info.add_evidence(s.as_str());
                results.push(info);
            } else if sl.contains("rustc") || sl.contains("rust-") {
                let mut info = CompilerInfo::new(CompilerFamily::Rust, "rustc", 0.9);
                info.add_evidence(s.as_str());
                results.push(info);
            } else if sl.starts_with("go1.") || sl.contains("go build") {
                let mut info = CompilerInfo::new(CompilerFamily::Go, "Go", 0.9);
                info.add_evidence(s.as_str());
                if let Some(v) = extract_go_version(s) {
                    info.version = Some(v);
                }
                results.push(info);
            } else if sl.contains("clang version") || sl.contains("apple llvm") {
                let mut info = CompilerInfo::new(CompilerFamily::Clang, "Clang", 0.85);
                info.add_evidence(s.as_str());
                results.push(info);
            } else if sl.contains("free pascal") || sl.contains("fpc ") {
                let mut info = CompilerInfo::new(CompilerFamily::FPC, "Free Pascal", 0.85);
                info.add_evidence(s.as_str());
                results.push(info);
            } else if sl.contains("swift version") || sl.contains("swift-") {
                let mut info = CompilerInfo::new(CompilerFamily::Swift, "Swift", 0.85);
                info.add_evidence(s.as_str());
                results.push(info);
            }
        }
        results
    }

    /// Detect from entry point byte patterns.
    pub fn detect_from_entry_point(&self, ep_offset: usize) -> Option<CompilerInfo> {
        if ep_offset + 16 > self.data.len() {
            return None;
        }
        let ep = &self.data[ep_offset..ep_offset + 16.min(self.data.len() - ep_offset)];

        // Delphi EP: 55 8B EC 83 C4 XX BA XX XX XX XX A1
        if ep.len() >= 12
            && ep[0] == 0x55 && ep[1] == 0x8B && ep[2] == 0xEC
            && ep[3] == 0x83 && ep[4] == 0xC4
            && ep[7] == 0xBA
        {
            let mut info = CompilerInfo::new(CompilerFamily::Delphi, "Borland Delphi", 0.85);
            info.add_evidence("Delphi EP pattern: PUSH EBP / MOV EBP,ESP / ADD ESP,N / MOV EDX,X");
            return Some(info);
        }

        // MinGW CRT startup: 55 89 E5 83 EC XX C7 04 24
        if ep.len() >= 9
            && ep[0] == 0x55 && ep[1] == 0x89 && ep[2] == 0xE5
            && ep[3] == 0x83 && ep[4] == 0xEC
            && ep[6] == 0xC7 && ep[7] == 0x04 && ep[8] == 0x24
        {
            let mut info = CompilerInfo::new(CompilerFamily::MinGW, "MinGW", 0.8);
            info.add_evidence("MinGW CRT startup pattern");
            return Some(info);
        }

        // MSVC _mainCRTStartup: E8 XX XX XX XX E9 XX XX XX XX
        if ep.len() >= 10 && ep[0] == 0xE8 && ep[5] == 0xE9 {
            let mut info = CompilerInfo::new(CompilerFamily::MSVC, "MSVC", 0.6);
            info.add_evidence("MSVC CRT startup: CALL + JMP pattern");
            return Some(info);
        }

        // MSVC x64: 48 83 EC XX 48 8B 05 -- sub rsp,N; mov rax,[rip+X]
        if ep.len() >= 7 && ep[0] == 0x48 && ep[1] == 0x83 && ep[2] == 0xEC {
            let mut info = CompilerInfo::new(CompilerFamily::MSVC, "MSVC x64", 0.65);
            info.add_evidence("x64 prologue: SUB RSP,N");
            return Some(info);
        }

        None
    }

    /// Detect from debug information (PDB path → MSVC, .debug_abbrev → GCC/Clang).
    pub fn detect_from_debug_info(&self) -> Option<CompilerInfo> {
        if find_icase(self.data, ".pdb") {
            let mut info = CompilerInfo::new(CompilerFamily::MSVC, "MSVC", 0.8);
            info.add_evidence("PDB reference found in binary");
            return Some(info);
        }
        if find_string(self.data, b".debug_abbrev") || find_string(self.data, b".debug_line") {
            let is_clang = find_icase(self.data, "clang");
            let fam = if is_clang { CompilerFamily::Clang } else { CompilerFamily::GCC };
            let name = if is_clang { "Clang" } else { "GCC" };
            let mut info = CompilerInfo::new(fam, name, 0.75);
            info.add_evidence("DWARF debug sections found");
            return Some(info);
        }
        None
    }

    /// Run all detection methods and aggregate into a CompilerReport.
    pub fn detect(&self, ep_offset: usize) -> CompilerReport {
        let mut all: Vec<CompilerInfo> = Vec::new();

        if let Some(info) = self.detect_from_rich_header() {
            all.push(info);
        }
        all.extend(self.detect_from_sections());
        all.extend(self.detect_from_strings());
        if let Some(info) = self.detect_from_entry_point(ep_offset) {
            all.push(info);
        }
        if let Some(info) = self.detect_from_debug_info() {
            all.push(info);
        }

        if all.is_empty() {
            return CompilerReport::new(CompilerInfo::new(CompilerFamily::Unknown, "Unknown", 0.0));
        }

        // Sort by confidence descending
        all.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));

        let mut report = CompilerReport::new(all.remove(0));
        for info in all {
            report.add_secondary(info);
        }
        report
    }
}

fn extract_version_from_string(s: &str) -> Option<String> {
    // Look for patterns like "4.8.4" or "7.3.0"
    let chars: Vec<char> = s.chars().collect();
    for i in 0..chars.len() {
        if chars[i].is_ascii_digit() {
            let mut j = i;
            while j < chars.len() && (chars[j].is_ascii_digit() || chars[j] == '.') {
                j += 1;
            }
            let version: String = chars[i..j].iter().collect();
            if version.contains('.') && version.len() >= 3 {
                return Some(version);
            }
        }
    }
    None
}

fn extract_go_version(s: &str) -> Option<String> {
    if let Some(pos) = s.find("go1.") {
        let rest = &s[pos..];
        let end = rest.find(|c: char| c == ' ' || c == '\0' || c == '\n').unwrap_or(rest.len());
        return Some(rest[..end].to_string());
    }
    None
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a Rich header the way link.exe does: `DanS`, three padding
    /// DWORDs, the entries, then `Rich` followed by the plaintext key. Every
    /// DWORD from `DanS` up to (not including) `Rich` is XORed with the key.
    fn rich_header(key: u32, prod_id: u16, build_id: u16, count: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"MZ");
        out.extend_from_slice(&[0u8; 14]); // some DOS header padding
        let xored = |v: u32, out: &mut Vec<u8>| out.extend_from_slice(&(v ^ key).to_le_bytes());
        xored(u32::from_le_bytes(*b"DanS"), &mut out);
        for _ in 0..3 {
            xored(0, &mut out); // padding
        }
        let comp_id = (u32::from(prod_id) << 16) | u32::from(build_id);
        xored(comp_id, &mut out);
        xored(count, &mut out);
        out.extend_from_slice(b"Rich");
        out.extend_from_slice(&key.to_le_bytes());
        out
    }

    #[test]
    fn rich_header_entries_are_xor_decoded() {
        // prod_id 0x00D5 is in the MSVC 2017 range. Encrypted it is
        // 0x00D5 ^ (key >> 16), which lands outside every range in
        // `vs_product_id_to_version`, so reading the entry raw yields None —
        // and the version silently disappears rather than being reported wrong.
        let key = 0x1234_5678_u32;
        let data = rich_header(key, 0x00D5, 0x6110, 7);
        let info = CompilerDetector::new(&data)
            .detect_from_rich_header()
            .expect("Rich header should be recognised");
        assert_eq!(info.version.as_deref(), Some("MSVC 2017"));
        assert_eq!(info.family, CompilerFamily::MSVC);
    }

    #[test]
    fn rich_header_key_of_zero_still_decodes() {
        // A zero key is the degenerate case where encrypted and plaintext
        // coincide: it must keep working, or the fix would only move the bug.
        let data = rich_header(0, 0x00F2, 0x0001, 1);
        let info = CompilerDetector::new(&data)
            .detect_from_rich_header()
            .expect("Rich header should be recognised");
        assert_eq!(info.version.as_deref(), Some("MSVC 2022"));
    }

    #[test]
    fn test_compiler_family_as_str() {
        assert_eq!(CompilerFamily::MSVC.as_str(), "MSVC");
        assert_eq!(CompilerFamily::Go.as_str(), "Go");
    }

    #[test]
    fn test_compiler_info_summary_with_version() {
        let info = CompilerInfo::new(CompilerFamily::GCC, "GCC", 0.9).with_version("12.2.0");
        assert!(info.summary().contains("12.2.0"));
    }

    #[test]
    fn test_detect_from_strings_gcc() {
        let data = b"GCC: (GNU) 12.2.0 20220819".to_vec();
        let d = CompilerDetector::new(&data);
        let results = d.detect_from_strings();
        assert!(results.iter().any(|i| i.family == CompilerFamily::GCC));
    }

    #[test]
    fn test_detect_from_strings_rust() {
        let data = b"rustc 1.75.0 (82e1608df 2023-12-21)".to_vec();
        let d = CompilerDetector::new(&data);
        let results = d.detect_from_strings();
        assert!(results.iter().any(|i| i.family == CompilerFamily::Rust));
    }

    #[test]
    fn test_detect_from_strings_go() {
        let data = b"go1.21.0 linux/amd64".to_vec();
        let d = CompilerDetector::new(&data);
        let results = d.detect_from_strings();
        assert!(results.iter().any(|i| i.family == CompilerFamily::Go));
    }

    #[test]
    fn test_detect_from_strings_clang() {
        let data = b"clang version 16.0.0 (git)".to_vec();
        let d = CompilerDetector::new(&data);
        let results = d.detect_from_strings();
        assert!(results.iter().any(|i| i.family == CompilerFamily::Clang));
    }

    #[test]
    fn test_detect_from_sections_go() {
        let data = b".gopclntab\0rest".to_vec();
        let d = CompilerDetector::new(&data);
        let results = d.detect_from_sections();
        assert!(results.iter().any(|i| i.family == CompilerFamily::Go));
    }

    #[test]
    fn test_detect_from_sections_mingw() {
        let data = b".eh_frame\0rest".to_vec();
        let d = CompilerDetector::new(&data);
        let results = d.detect_from_sections();
        assert!(results.iter().any(|i| i.family == CompilerFamily::MinGW));
    }

    #[test]
    fn test_detect_from_ep_delphi() {
        // 55 8B EC 83 C4 XX BA XX XX XX XX XX
        let mut data = vec![0u8; 64];
        data[0] = 0x55; data[1] = 0x8B; data[2] = 0xEC;
        data[3] = 0x83; data[4] = 0xC4; data[5] = 0xF0;
        data[6] = 0x00; data[7] = 0xBA;
        let d = CompilerDetector::new(&data);
        let result = d.detect_from_entry_point(0);
        assert!(result.is_some());
        assert_eq!(result.unwrap().family, CompilerFamily::Delphi);
    }

    #[test]
    fn test_detect_from_ep_mingw() {
        // The MinGW CRT prologue is nine bytes with no filler:
        //   55           push ebp
        //   89 E5        mov  ebp, esp
        //   83 EC 10     sub  esp, 0x10      <- the 0x10 is the imm8 at index 5
        //   C7 04 24     mov  dword [esp], …  <- so this starts at index 6
        // The previous layout inserted an extra 0x00 at index 6, pushing
        // C7 04 24 to 7..9 where the detector — which follows the documented
        // pattern `55 89 E5 83 EC XX C7 04 24` — correctly did not look.
        let mut data = vec![0u8; 64];
        data[0] = 0x55; data[1] = 0x89; data[2] = 0xE5;
        data[3] = 0x83; data[4] = 0xEC; data[5] = 0x10;
        data[6] = 0xC7; data[7] = 0x04; data[8] = 0x24;
        let d = CompilerDetector::new(&data);
        let result = d.detect_from_entry_point(0);
        assert!(result.is_some());
        assert_eq!(result.unwrap().family, CompilerFamily::MinGW);
    }

    #[test]
    fn test_detect_from_debug_info_pdb() {
        let data = b"path\\to\\binary.pdb\0rest".to_vec();
        let d = CompilerDetector::new(&data);
        let result = d.detect_from_debug_info();
        assert!(result.is_some());
        assert_eq!(result.unwrap().family, CompilerFamily::MSVC);
    }

    #[test]
    fn test_detect_from_debug_info_dwarf() {
        let data = b".debug_abbrev\0.debug_line".to_vec();
        let d = CompilerDetector::new(&data);
        let result = d.detect_from_debug_info();
        assert!(result.is_some());
    }

    #[test]
    fn test_detect_unknown_empty() {
        let data = vec![0u8; 64];
        let d = CompilerDetector::new(&data);
        let report = d.detect(0);
        assert_eq!(report.primary.family, CompilerFamily::Unknown);
    }

    #[test]
    fn test_detect_aggregates_multiple() {
        let mut data = b"rustc 1.75.0\0".to_vec();
        data.extend_from_slice(b".gopclntab\0");
        let d = CompilerDetector::new(&data);
        let report = d.detect(0);
        let families = report.all_families();
        assert!(families.len() >= 2);
    }

    #[test]
    fn test_extract_version_from_string() {
        let v = extract_version_from_string("GCC 12.2.0 something");
        assert_eq!(v, Some("12.2.0".to_string()));
    }

    #[test]
    fn test_extract_go_version() {
        let v = extract_go_version("go1.21.5 linux/amd64");
        assert_eq!(v, Some("go1.21.5".to_string()));
    }

    #[test]
    fn test_vs_product_id_msvc2019() {
        assert_eq!(vs_product_id_to_version(0x00E0), Some("MSVC 2019"));
    }
}
