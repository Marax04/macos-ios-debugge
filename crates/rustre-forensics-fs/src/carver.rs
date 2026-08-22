use std::fmt::Write as _;
use std::collections::HashMap;

// ── File carver ───────────────────────────────────────────────────────────────
// Carves files from raw disk images by searching for known file headers/footers.

#[derive(Debug, Clone)]
pub struct FileSignature {
    pub name: &'static str,
    pub extension: &'static str,
    pub header: &'static [u8],
    pub footer: Option<&'static [u8]>,
    pub max_size: u64,
    pub mime_type: &'static str,
}

pub struct SignatureDatabase {
    signatures: Vec<FileSignature>,
}

impl SignatureDatabase {
    #[must_use] 
    pub fn default_db() -> Self {
        let sigs: Vec<FileSignature> = vec![
            FileSignature { name: "PE Executable", extension: "exe", header: b"MZ", footer: None, max_size: 256 * 1024 * 1024, mime_type: "application/x-msdownload" },
            FileSignature { name: "ELF Binary", extension: "elf", header: b"\x7fELF", footer: None, max_size: 256 * 1024 * 1024, mime_type: "application/x-elf" },
            FileSignature { name: "ZIP Archive", extension: "zip", header: b"PK\x03\x04", footer: Some(b"PK\x05\x06"), max_size: 2 * 1024 * 1024 * 1024, mime_type: "application/zip" },
            FileSignature { name: "PDF Document", extension: "pdf", header: b"%PDF-", footer: Some(b"%%EOF"), max_size: 100 * 1024 * 1024, mime_type: "application/pdf" },
            FileSignature { name: "JPEG Image", extension: "jpg", header: b"\xff\xd8\xff", footer: Some(b"\xff\xd9"), max_size: 50 * 1024 * 1024, mime_type: "image/jpeg" },
            FileSignature { name: "PNG Image", extension: "png", header: b"\x89PNG\r\n\x1a\n", footer: Some(b"IEND\xaeB`\x82"), max_size: 50 * 1024 * 1024, mime_type: "image/png" },
            FileSignature { name: "GIF Image", extension: "gif", header: b"GIF89a", footer: Some(b"\x00;"), max_size: 20 * 1024 * 1024, mime_type: "image/gif" },
            FileSignature { name: "SQLite Database", extension: "db", header: b"SQLite format 3\0", footer: None, max_size: 4 * 1024 * 1024 * 1024, mime_type: "application/x-sqlite3" },
            FileSignature { name: "RAR Archive", extension: "rar", header: b"Rar!\x1a\x07", footer: None, max_size: 4 * 1024 * 1024 * 1024, mime_type: "application/x-rar-compressed" },
            FileSignature { name: "7-Zip Archive", extension: "7z", header: b"7z\xbc\xaf'\x1c", footer: None, max_size: 4 * 1024 * 1024 * 1024, mime_type: "application/x-7z-compressed" },
            FileSignature { name: "Office DOCX", extension: "docx", header: b"PK\x03\x04", footer: None, max_size: 100 * 1024 * 1024, mime_type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document" },
            FileSignature { name: "OLE2 Document", extension: "doc", header: b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", footer: None, max_size: 100 * 1024 * 1024, mime_type: "application/msword" },
            FileSignature { name: "WebAssembly", extension: "wasm", header: b"\0asm", footer: None, max_size: 100 * 1024 * 1024, mime_type: "application/wasm" },
            FileSignature { name: "Mach-O Binary", extension: "macho", header: b"\xfe\xed\xfa\xce", footer: None, max_size: 256 * 1024 * 1024, mime_type: "application/x-mach-binary" },
            FileSignature { name: "Java Class", extension: "class", header: b"\xca\xfe\xba\xbe", footer: None, max_size: 10 * 1024 * 1024, mime_type: "application/java-vm" },
            FileSignature { name: "DEX Bytecode", extension: "dex", header: b"dex\n035\0", footer: None, max_size: 100 * 1024 * 1024, mime_type: "application/dalvik-executable" },
            FileSignature { name: "GZIP Archive", extension: "gz", header: b"\x1f\x8b", footer: None, max_size: 4 * 1024 * 1024 * 1024, mime_type: "application/gzip" },
            FileSignature { name: "XML Document", extension: "xml", header: b"<?xml", footer: Some(b">"), max_size: 100 * 1024 * 1024, mime_type: "application/xml" },
            FileSignature { name: "BMP Image", extension: "bmp", header: b"BM", footer: None, max_size: 50 * 1024 * 1024, mime_type: "image/bmp" },
            FileSignature { name: "PCAP Capture", extension: "pcap", header: b"\xd4\xc3\xb2\xa1", footer: None, max_size: 4 * 1024 * 1024 * 1024, mime_type: "application/vnd.tcpdump.pcap" },
        ];
        Self { signatures: sigs }
    }

    #[must_use] 
    pub fn find_by_header(&self, data: &[u8]) -> Vec<&FileSignature> {
        self.signatures.iter().filter(|sig| {
            data.len() >= sig.header.len() && data.starts_with(sig.header)
        }).collect()
    }

    pub fn add(&mut self, sig: FileSignature) {
        self.signatures.push(sig);
    }
}

// ── Carved file ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CarvedFile {
    pub offset: u64,
    pub size: u64,
    pub file_type: String,
    pub extension: String,
    pub confidence: CarveConfidence,
    pub has_footer: bool,
    pub data_range: (u64, u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CarveConfidence {
    High,
    Medium,
    Low,
}

impl CarvedFile {
    #[must_use] 
    pub fn name(&self, index: usize) -> String {
        format!("carved_{:08x}_{}.{}", self.offset, index, self.extension)
    }
}

// ── Carver ────────────────────────────────────────────────────────────────────

pub struct FileCarver {
    pub db: SignatureDatabase,
    pub config: CarverConfig,
}

#[derive(Debug, Clone)]
pub struct CarverConfig {
    pub scan_block_size: usize,
    pub max_file_size: u64,
    pub skip_overlapping: bool,
    pub validate_found: bool,
}

impl Default for CarverConfig {
    fn default() -> Self {
        Self {
            scan_block_size: 512,
            max_file_size: 512 * 1024 * 1024,
            skip_overlapping: true,
            validate_found: true,
        }
    }
}

impl FileCarver {
    #[must_use] 
    pub fn new() -> Self {
        Self { db: SignatureDatabase::default_db(), config: CarverConfig::default() }
    }

    #[must_use] 
    pub fn carve(&self, data: &[u8]) -> Vec<CarvedFile> {
        let mut carved = Vec::new();
        let mut offset = 0usize;
        let data_len = data.len();

        while offset < data_len {
            let chunk = &data[offset..];
            let matches = self.db.find_by_header(chunk);
            for sig in matches {
                let file_offset = offset as u64;
                let (size, has_footer) = if let Some(footer) = sig.footer {
                    self.find_footer(&data[offset..], footer, sig.max_size as usize).map_or_else(|| (self.estimate_size(sig, data, offset) as u64, false), |footer_end| (footer_end as u64, true))
                } else {
                    (self.estimate_size(sig, data, offset) as u64, false)
                };

                if size == 0 || size > sig.max_size { continue; }

                let confidence = if has_footer {
                    CarveConfidence::High
                } else if size < 64 {
                    CarveConfidence::Low
                } else {
                    CarveConfidence::Medium
                };

                carved.push(CarvedFile {
                    offset: file_offset,
                    size,
                    file_type: sig.name.to_string(),
                    extension: sig.extension.to_string(),
                    confidence,
                    has_footer,
                    data_range: (file_offset, file_offset.saturating_add(size)),
                });
            }
            offset += self.config.scan_block_size;
        }

        if self.config.skip_overlapping {
            self.remove_overlaps(carved)
        } else {
            carved
        }
    }

    fn find_footer(&self, data: &[u8], footer: &[u8], max_size: usize) -> Option<usize> {
        let search_end = data.len().min(max_size);
        let footer_len = footer.len();
        if footer_len == 0 || search_end < footer_len {
            return None;
        }
        for i in 0..=(search_end - footer_len) {
            if &data[i..i + footer_len] == footer {
                return Some(i + footer_len);
            }
        }
        None
    }

    fn estimate_size(&self, sig: &FileSignature, data: &[u8], offset: usize) -> usize {
        let remaining = data.len() - offset;
        match sig.extension {
            "exe" | "elf" => {
                let hdr = &data[offset..];
                if sig.extension == "exe" && hdr.len() >= 64 {
                    let e_lfanew = u32::from_le_bytes([hdr[60], hdr[61], hdr[62], hdr[63]]) as usize;
                    if e_lfanew + 4 < hdr.len() && &hdr[e_lfanew..e_lfanew+4] == b"PE\0\0" {
                        let opt_off = e_lfanew + 24;
                        if opt_off + 56 < hdr.len() {
                            let sz = u32::from_le_bytes([hdr[opt_off+56], hdr[opt_off+57], hdr[opt_off+58], hdr[opt_off+59]]) as usize;
                            if sz > 0 && sz < remaining { return sz; }
                        }
                    }
                }
                remaining.min(sig.max_size as usize)
            }
            _ => remaining.min(sig.max_size as usize),
        }
    }

    fn remove_overlaps(&self, mut carved: Vec<CarvedFile>) -> Vec<CarvedFile> {
        if carved.is_empty() { return carved; }
        carved.sort_by_key(|f| f.offset);
        let mut result = Vec::new();
        let mut last_end = 0u64;
        for file in carved {
            if file.offset >= last_end {
                last_end = file.offset + file.size;
                result.push(file);
            }
        }
        result
    }

    #[must_use] 
    pub fn carve_stats(&self, carved: &[CarvedFile]) -> CarveStats {
        let mut by_type: HashMap<String, usize> = HashMap::new();
        for f in carved {
            *by_type.entry(f.file_type.clone()).or_default() += 1;
        }
        let high = carved.iter().filter(|f| f.confidence == CarveConfidence::High).count();
        let medium = carved.iter().filter(|f| f.confidence == CarveConfidence::Medium).count();
        let low = carved.iter().filter(|f| f.confidence == CarveConfidence::Low).count();
        let total_bytes: u64 = carved.iter().map(|f| f.size).sum();
        CarveStats { total: carved.len(), high_confidence: high, medium_confidence: medium, low_confidence: low, total_bytes, by_type }
    }
}

impl Default for FileCarver {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, Clone)]
pub struct CarveStats {
    pub total: usize,
    pub high_confidence: usize,
    pub medium_confidence: usize,
    pub low_confidence: usize,
    pub total_bytes: u64,
    pub by_type: HashMap<String, usize>,
}

impl CarveStats {
    #[must_use] 
    pub fn report(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "Total files carved: {}", self.total);
        let _ = writeln!(s, "  High confidence: {}", self.high_confidence);
        let _ = writeln!(s, "  Medium confidence: {}", self.medium_confidence);
        let _ = writeln!(s, "  Low confidence: {}", self.low_confidence);
        let _ = writeln!(s, "Total bytes: {} MB", self.total_bytes / 1_048_576);
        s.push_str("By type:\n");
        let mut types: Vec<_> = self.by_type.iter().collect();
        types.sort_by(|a, b| b.1.cmp(a.1));
        for (t, c) in types {
            let _ = writeln!(s, "  {t}: {c}");
        }
        s
    }
}

// ── Entropy scanner ───────────────────────────────────────────────────────────

pub struct EntropyScanner {
    pub window_size: usize,
    pub stride: usize,
    pub high_entropy_threshold: f64,
    pub low_entropy_threshold: f64,
}

impl EntropyScanner {
    #[must_use] 
    pub const fn new() -> Self {
        Self { window_size: 4096, stride: 512, high_entropy_threshold: 7.0, low_entropy_threshold: 1.0 }
    }

    #[must_use] 
    pub fn scan(&self, data: &[u8]) -> Vec<EntropyRegion> {
        let mut regions: Vec<EntropyRegion> = Vec::new();
        let mut off = 0usize;
        while off + self.window_size <= data.len() {
            let window = &data[off..off + self.window_size];
            let entropy = compute_entropy(window);
            let kind = if entropy >= self.high_entropy_threshold {
                EntropyKind::High
            } else if entropy <= self.low_entropy_threshold {
                EntropyKind::Low
            } else {
                EntropyKind::Normal
            };
            if kind != EntropyKind::Normal {
                match regions.last_mut() {
                    Some(last) if last.kind == kind && last.end as usize == off => {
                        last.end = (off + self.window_size) as u64;
                        last.sample_entropy = f64::midpoint(last.sample_entropy, entropy);
                    }
                    _ => {
                        regions.push(EntropyRegion { start: off as u64, end: (off + self.window_size) as u64, sample_entropy: entropy, kind });
                    }
                }
            }
            off += self.stride;
        }
        regions
    }
}

impl Default for EntropyScanner {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, Clone)]
pub struct EntropyRegion {
    pub start: u64,
    pub end: u64,
    pub sample_entropy: f64,
    pub kind: EntropyKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntropyKind { High, Normal, Low }

fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u32; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = data.len() as f64;
    counts.iter().filter(|&&c| c > 0).map(|&c| {
        let p = f64::from(c) / len;
        -p * p.log2()
    }).sum()
}
