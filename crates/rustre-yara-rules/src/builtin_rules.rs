//! `builtin_rules` — Built-in YARA rule library:
//! - Shellcode detection (x86/x64/ARM)
//! - Packer families (UPX, Themida, `VMProtect`, MPRESS, `ASProtect`)
//! - Crypto constants (AES S-box, SHA-256 constants, RC4 table)
//! - Suspicious strings (base64-encoded PE, `PowerShell` encoded, C2 patterns)
//! - Document malware (macro patterns, OLE exploits)

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// ── Rule category ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleCategory {
    Shellcode,
    Packer,
    CryptoConstant,
    SuspiciousString,
    DocumentMalware,
    Ransomware,
    Backdoor,
}

impl std::fmt::Display for RuleCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shellcode        => write!(f, "shellcode"),
            Self::Packer           => write!(f, "packer"),
            Self::CryptoConstant   => write!(f, "crypto"),
            Self::SuspiciousString => write!(f, "suspicious_string"),
            Self::DocumentMalware  => write!(f, "document_malware"),
            Self::Ransomware       => write!(f, "ransomware"),
            Self::Backdoor         => write!(f, "backdoor"),
        }
    }
}

// ── Static rule definition ────────────────────────────────────────────────────

/// A built-in rule definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuiltinRule {
    pub name: String,
    pub category: RuleCategory,
    pub description: String,
    pub author: &'static str,
    pub severity: u8,
    /// The full YARA source text.
    pub source: String,
}

impl BuiltinRule {
    fn new(
        name: &'static str,
        cat: RuleCategory,
        desc: &'static str,
        sev: u8,
        source: String,
    ) -> Self {
        Self {
            name: name.to_string(),
            category: cat,
            description: desc.to_string(),
            author: "RustRE builtin",
            severity: sev,
            source,
        }
    }
}

// ── Built-in rule catalogue ───────────────────────────────────────────────────

/// Return all built-in rules.
#[must_use] 
pub fn all_builtin_rules() -> Vec<BuiltinRule> {
    let mut rules = Vec::new();
    rules.extend(shellcode_rules());
    rules.extend(packer_rules());
    rules.extend(crypto_constant_rules());
    rules.extend(suspicious_string_rules());
    rules.extend(document_malware_rules());
    rules
}

/// Return rules filtered by category.
#[must_use] 
pub fn rules_by_category(cat: RuleCategory) -> Vec<BuiltinRule> {
    all_builtin_rules().into_iter().filter(|r| r.category == cat).collect()
}

/// Return combined YARA source for all built-in rules.
#[must_use] 
pub fn builtin_source_all() -> String {
    all_builtin_rules().iter().map(|r| r.source.as_str()).collect::<Vec<_>>().join("\n\n")
}

/// Return combined YARA source for a specific category.
#[must_use] 
pub fn builtin_source_for_category(cat: RuleCategory) -> String {
    rules_by_category(cat).iter().map(|r| r.source.as_str()).collect::<Vec<_>>().join("\n\n")
}

// ── Shellcode rules ───────────────────────────────────────────────────────────

fn shellcode_rules() -> Vec<BuiltinRule> {
    vec![
        BuiltinRule::new(
            "Shellcode_x86_LoadLibrary",
            RuleCategory::Shellcode,
            "x86 shellcode using LoadLibraryA pattern",
            75,
            r#"rule Shellcode_x86_LoadLibrary {
    meta:
        author = "RustRE builtin"
        description = "x86 shellcode: LoadLibraryA hash lookup stub"
        severity = 75
        category = "shellcode"
    strings:
        // CALL $+5 / POP EBX pattern used to get EIP
        $call_pop = { E8 00 00 00 00 5? }
        // PEB traversal: MOV EAX, FS:[0x30]
        $peb_fs30 = { 64 A1 30 00 00 00 }
        // Hash-based API resolution stub
        $hash_api = { 60 89 E5 31 D2 64 8B 52 30 }
        // Egg hunter NOP sled
        $nop_sled = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
    condition:
        ($call_pop and $peb_fs30) or $hash_api
}"#.to_string(),
        ),
        BuiltinRule::new(
            "Shellcode_x64_syscall",
            RuleCategory::Shellcode,
            "x64 shellcode using direct syscall",
            80,
            r#"rule Shellcode_x64_syscall {
    meta:
        author = "RustRE builtin"
        description = "x64 shellcode: direct syscall stub"
        severity = 80
        category = "shellcode"
    strings:
        // syscall; ret sequence
        $syscall_ret = { 0F 05 C3 }
        // mov eax, <syscall_nr>; syscall
        $mov_syscall = { B8 ?? ?? 00 00 0F 05 }
        // Heaven's Gate (32→64 transition): far jmp to 0x33 segment
        $heavens_gate = { EA ?? ?? ?? ?? 33 00 }
        // NTDLL syscall stub: mov r10, rcx; mov eax, imm; syscall
        $ntdll_stub = { 4C 8B D1 B8 ?? 00 00 00 0F 05 }
    condition:
        2 of them
}"#.to_string(),
        ),
        BuiltinRule::new(
            "Shellcode_ARM_Thumb",
            RuleCategory::Shellcode,
            "ARM Thumb shellcode patterns",
            70,
            r#"rule Shellcode_ARM_Thumb {
    meta:
        author = "RustRE builtin"
        description = "ARM Thumb shellcode patterns"
        severity = 70
        category = "shellcode"
    strings:
        // PUSH {R4-R7,LR}; BLX label pattern
        $thumb_push_blx = { 2D E9 F0 4F }
        // LDR PC, [PC, #-4] — absolute jump via literal pool
        $ldr_pc = { 1F FF 2F E1 }
        // Linux ARM syscall: SWI 0 / SVC #0
        $arm_svc = { 00 00 00 EF }
        $thumb_svc = { 00 DF }
    condition:
        any of them
}"#.to_string(),
        ),
        BuiltinRule::new(
            "Shellcode_Egghunter",
            RuleCategory::Shellcode,
            "Egghunter shellcode (SEH/NtAccessCheckAndAuditAlarm method)",
            72,
            r#"rule Shellcode_Egghunter {
    meta:
        author = "RustRE builtin"
        description = "Egghunter shellcode patterns"
        severity = 72
        category = "shellcode"
    strings:
        // NtAccessCheckAndAuditAlarm egghunter: mov eax, 2; int 0x2e
        $seh_egg = { B8 02 00 00 00 CD 2E }
        // Common 8-byte egg markers
        $egg_w00t = "w00tw00t"
        $egg_haha = "hahahahahahaha" nocase
        // SEH-based egghunter: push 4; call <func>
        $seh_push = { 6A 04 54 }
    condition:
        ($seh_egg) or ($egg_w00t) or ($seh_push and 1 of ($egg_*))
}"#.to_string(),
        ),
    ]
}

// ── Packer rules ──────────────────────────────────────────────────────────────

fn packer_rules() -> Vec<BuiltinRule> {
    let mut v = packer_rules_part_a();
    v.extend(packer_rules_part_b());
    v
}

fn packer_rules_part_a() -> Vec<BuiltinRule> {
    vec![
        BuiltinRule::new(
            "Packer_UPX",
            RuleCategory::Packer,
            "UPX packed PE",
            40,
            r#"rule Packer_UPX {
    meta:
        author = "RustRE builtin"
        description = "UPX packer signature"
        severity = 40
        category = "packer"
        family = "UPX"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX2" ascii
        $upx_magic = { 55 50 58 21 }
        // UPX decompression stub entry point
        $stub = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 }
    condition:
        ($upx0 and $upx1) or ($upx_magic) or $stub
}"#.to_string(),
        ),
        BuiltinRule::new(
            "Packer_Themida",
            RuleCategory::Packer,
            "Themida / WinLicense protected executable",
            65,
            r#"rule Packer_Themida {
    meta:
        author = "RustRE builtin"
        description = "Themida/WinLicense protector"
        severity = 65
        category = "packer"
        family = "Themida"
    strings:
        $str1 = ".themida" ascii nocase
        $str2 = "This file is protected by Themida" ascii wide
        $str3 = "WinLicense" ascii wide nocase
        // Themida section header marker
        $sec_mark = { 2E 74 68 65 6D 69 64 61 }
        // Anti-debug VM entry stubs
        $vment = { EB 10 66 62 3A 79 6F 75 72 20 73 6F 66 74 77 61 72 65 }
    condition:
        any of them
}"#.to_string(),
        ),
    ]
}

fn packer_rules_part_b() -> Vec<BuiltinRule> {
    vec![
        BuiltinRule::new(
            "Packer_VMProtect",
            RuleCategory::Packer,
            "VMProtect protected executable",
            65,
            r#"rule Packer_VMProtect {
    meta:
        author = "RustRE builtin"
        description = "VMProtect protector"
        severity = 65
        category = "packer"
        family = "VMProtect"
    strings:
        $vmp0 = ".vmp0" ascii
        $vmp1 = ".vmp1" ascii
        $vmp_str = "VMProtect" ascii wide nocase
        // VMProtect 3.x VM dispatcher signature
        $vmp3_disp = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 }
        // VMProtect marker in overlay or resource
        $vmp_marker = { 56 4D 50 72 6F 74 65 63 74 }
    condition:
        ($vmp0 and $vmp1) or $vmp_str or $vmp3_disp or $vmp_marker
}"#.to_string(),
        ),
        BuiltinRule::new(
            "Packer_MPRESS",
            RuleCategory::Packer,
            "MPRESS packed PE",
            45,
            r#"rule Packer_MPRESS {
    meta:
        author = "RustRE builtin"
        description = "MPRESS packer"
        severity = 45
        category = "packer"
        family = "MPRESS"
    strings:
        $mpress_sec = ".MPRESS1" ascii
        $mpress_sec2 = ".MPRESS2" ascii
        // MPRESS decompressor stub
        $stub = { 60 E8 00 00 00 00 58 83 E8 ?? 8B ?? }
    condition:
        ($mpress_sec and $mpress_sec2) or $stub
}"#.to_string(),
        ),
        BuiltinRule::new(
            "Packer_ASProtect",
            RuleCategory::Packer,
            "ASProtect protected executable",
            60,
            r#"rule Packer_ASProtect {
    meta:
        author = "RustRE builtin"
        description = "ASProtect packer"
        severity = 60
        category = "packer"
        family = "ASProtect"
    strings:
        $asp1 = ".aspack" ascii nocase
        $asp2 = "ASProtect" ascii wide nocase
        $asp3 = { 60 E8 72 00 00 00 }
        $aspr_lic = "ASPr" ascii
    condition:
        any of them
}"#.to_string(),
        ),
    ]
}

// ── Crypto constant rules ─────────────────────────────────────────────────────

fn crypto_constant_rules() -> Vec<BuiltinRule> {
    vec![
        BuiltinRule::new(
            "Crypto_AES_SBox",
            RuleCategory::CryptoConstant,
            "AES S-box constant table",
            30,
            r#"rule Crypto_AES_SBox {
    meta:
        author = "RustRE builtin"
        description = "AES S-box lookup table"
        severity = 30
        category = "crypto"
    strings:
        // First 16 bytes of AES S-box
        $aes_sbox_start = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
        // AES Rcon (round constants)
        $aes_rcon = { 01 02 04 08 10 20 40 80 1B 36 }
        // AES MixColumns polynomial constant
        $aes_poly = { 63 7C 77 7B F2 6B 6F C5 }
    condition:
        any of them
}"#.to_string(),
        ),
        BuiltinRule::new(
            "Crypto_SHA256_Constants",
            RuleCategory::CryptoConstant,
            "SHA-256 K constants (first 8)",
            25,
            r#"rule Crypto_SHA256_Constants {
    meta:
        author = "RustRE builtin"
        description = "SHA-256 K-constant table"
        severity = 25
        category = "crypto"
    strings:
        // First 8 SHA-256 K constants in little-endian
        $sha256_k = {
            98 2F 8A 42 91 44 37 71 CF FB C0 B5 A5 DB B5 E9
            5B C2 56 39 F1 11 F1 59 A4 82 3F92 D5 5E 1C AB
        }
        // SHA-256 initial hash values H0..H7 (big-endian)
        $sha256_h0 = { 67 E6 09 6A 85 AE 67 BB 72 F3 6E 3C 3A F5 4F A5 }
        // SHA-256 magic bytes in source
        $sha256_magic = "6a09e667bb67ae853c6ef372a54ff53a"
    condition:
        any of them
}"#.to_string(),
        ),
        BuiltinRule::new(
            "Crypto_RC4_Table",
            RuleCategory::CryptoConstant,
            "RC4 key schedule / S-box initialisation",
            35,
            r#"rule Crypto_RC4_Table {
    meta:
        author = "RustRE builtin"
        description = "RC4 key-scheduling or stream cipher patterns"
        severity = 35
        category = "crypto"
    strings:
        // RC4 KSA initialisation loop pattern (x86 assembly)
        $rc4_ksa = { 31 C0 99 BF 00 01 00 00 F3 AA }
        // 256-byte incrementing S-box initializer: 00 01 02 03 ... FE FF
        $sbox_init = { 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
                       10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F }
        // String literal "RC4" in code
        $rc4_str = "RC4" ascii wide nocase
    condition:
        $rc4_ksa or ($sbox_init and filesize < 5MB)
}"#.to_string(),
        ),
        BuiltinRule::new(
            "Crypto_ChaCha20_Constant",
            RuleCategory::CryptoConstant,
            "ChaCha20 'expand 32-byte k' constant",
            30,
            r#"rule Crypto_ChaCha20_Constant {
    meta:
        author = "RustRE builtin"
        description = "ChaCha20 stream cipher constant"
        severity = 30
        category = "crypto"
    strings:
        $expand_32 = "expand 32-byte k" ascii
        $expand_16 = "expand 16-byte k" ascii
        // ChaCha20 constant as bytes
        $cc20_bytes = { 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B }
    condition:
        any of them
}"#.to_string(),
        ),
    ]
}

// ── Suspicious string rules ───────────────────────────────────────────────────

fn suspicious_string_rules() -> Vec<BuiltinRule> {
    let mut v = suspicious_string_rules_part_a();
    v.extend(suspicious_string_rules_part_b());
    v
}

fn suspicious_string_rules_part_a() -> Vec<BuiltinRule> {
    vec![
        BuiltinRule::new(
            "Susp_Base64EncodedPE",
            RuleCategory::SuspiciousString,
            "Base64-encoded PE header in memory or script",
            70,
            r#"rule Susp_Base64EncodedPE {
    meta:
        author = "RustRE builtin"
        description = "Base64-encoded PE (MZ header)"
        severity = 70
        category = "suspicious_string"
    strings:
        // "MZ" base64-encoded with various padding offsets
        $b64_mz1 = "TVqQAAMAAAAEAAAA" ascii wide
        $b64_mz2 = "TVoAAAAAAAAA" ascii wide
        $b64_mz3 = "TVpAAA" ascii wide
        $b64_mz4 = "0MZ" ascii wide
        // zlib-compressed PE base64
        $b64_zlib_pe = "eJzs" ascii wide
    condition:
        any of them
}"#.to_string(),
        ),
        BuiltinRule::new(
            "Susp_PowerShellEncoded",
            RuleCategory::SuspiciousString,
            "PowerShell -EncodedCommand execution",
            75,
            r#"rule Susp_PowerShellEncoded {
    meta:
        author = "RustRE builtin"
        description = "PowerShell encoded command execution"
        severity = 75
        category = "suspicious_string"
    strings:
        $enc1 = "-EncodedCommand" ascii wide nocase
        $enc2 = "-enc" ascii wide nocase
        $enc3 = "-e " ascii wide
        $iex1 = "IEX" ascii wide
        $iex2 = "Invoke-Expression" ascii wide nocase
        $iex3 = "iex(" ascii wide nocase
        $bypass = "-ExecutionPolicy Bypass" ascii wide nocase
        $bypass2 = "-ep bypass" ascii wide nocase
        $hidden = "-WindowStyle Hidden" ascii wide nocase
        $noprofile = "-NoProfile" ascii wide nocase
        $download = "DownloadString" ascii wide nocase
        $webclient = "New-Object Net.WebClient" ascii wide nocase
    condition:
        ($enc1 or $enc2) and ($iex1 or $iex2 or $iex3 or $download or $webclient)
        or ($bypass and $hidden and $noprofile)
}"#.to_string(),
        ),
    ]
}

fn suspicious_string_rules_part_b() -> Vec<BuiltinRule> {
    vec![
        BuiltinRule::new(
            "Susp_CommonC2Patterns",
            RuleCategory::SuspiciousString,
            "Common C2 communication patterns",
            65,
            r#"rule Susp_CommonC2Patterns {
    meta:
        author = "RustRE builtin"
        description = "Common C2 beacon/communication patterns"
        severity = 65
        category = "suspicious_string"
    strings:
        // Cobalt Strike default beacon strings
        $cs_beacon1 = "/dpixel" ascii
        $cs_beacon2 = "__cfduid" ascii
        $cs_ua = "Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5;" ascii
        // Metasploit Meterpreter
        $msfmeter = "METERPRETER" ascii wide nocase
        $msf_winhttp = "WinHttpSetDefaultProxyConfiguration" ascii
        // Generic C2 check-in
        $checkin = "/checkin" ascii
        $heartbeat = "/heartbeat" ascii
        // Common reverse shell patterns
        $rev_shell1 = "cmd.exe /c " ascii wide nocase
        $rev_shell2 = "bash -i >& /dev/tcp/" ascii
        $rev_shell3 = "/bin/sh -i" ascii
    condition:
        2 of them
}"#.to_string(),
        ),
        BuiltinRule::new(
            "Susp_MimikatzStrings",
            RuleCategory::SuspiciousString,
            "Mimikatz credential harvesting tool strings",
            90,
            r#"rule Susp_MimikatzStrings {
    meta:
        author = "RustRE builtin"
        description = "Mimikatz strings"
        severity = 90
        category = "suspicious_string"
        family = "Mimikatz"
    strings:
        $mimi1 = "mimikatz" ascii wide nocase
        $mimi2 = "mimilib" ascii wide nocase
        $mimi3 = "sekurlsa::" ascii wide nocase
        $mimi4 = "lsadump::" ascii wide nocase
        $mimi5 = "privilege::debug" ascii wide nocase
        $mimi6 = "SekurLSA" ascii wide nocase
        $mimi7 = "wdigest.dll" ascii wide nocase
        $mimi8 = "kerberos::golden" ascii wide nocase
    condition:
        3 of them
}"#.to_string(),
        ),
    ]
}

// ── Document malware rules ────────────────────────────────────────────────────

fn document_malware_rules() -> Vec<BuiltinRule> {
    let mut v = document_malware_rules_part_a();
    v.extend(document_malware_rules_part_b());
    v
}

fn document_malware_rules_part_a() -> Vec<BuiltinRule> {
    vec![
        BuiltinRule::new(
            "Doc_OfficeMacro_Suspicious",
            RuleCategory::DocumentMalware,
            "Office document with suspicious macro patterns",
            70,
            r#"rule Doc_OfficeMacro_Suspicious {
    meta:
        author = "RustRE builtin"
        description = "Office macro with suspicious API calls"
        severity = 70
        category = "document_malware"
    strings:
        $shell = "Shell" ascii wide nocase
        $wscript = "WScript.Shell" ascii wide nocase
        $createobj = "CreateObject" ascii wide nocase
        $environ = "Environ" ascii wide nocase
        $auto_open = "Auto_Open" ascii wide nocase
        $auto_close = "Auto_Close" ascii wide nocase
        $document_open = "Document_Open" ascii wide nocase
        $powershell = "powershell" ascii wide nocase
        $wmic = "wmic" ascii wide nocase
        $cmd_exec = "cmd /c" ascii wide nocase
        $download = "URLDownloadToFile" ascii wide nocase
        $http_req = "XMLHTTP" ascii wide nocase
        // OLE2 container magic
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }
    condition:
        $ole_magic and
        (($auto_open or $auto_close or $document_open) and
         2 of ($shell, $wscript, $createobj, $powershell, $wmic, $cmd_exec, $download, $http_req))
}"#.to_string(),
        ),
        BuiltinRule::new(
            "Doc_OLE_CVE2017_11882",
            RuleCategory::DocumentMalware,
            "CVE-2017-11882 Microsoft Equation Editor exploit",
            95,
            r#"rule Doc_OLE_CVE2017_11882 {
    meta:
        author = "RustRE builtin"
        description = "CVE-2017-11882 Equation Editor exploit"
        severity = 95
        category = "document_malware"
        family = "CVE-2017-11882"
        reference = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11882"
    strings:
        // Equation Editor CLSID in OLE stream
        $eqnedt32_clsid = { 02 CE 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
        // The specific shellcode payload header seen in-the-wild
        $payload_hdr = { 2C 00 1C 00 01 00 12 00 41 03 01 00 }
        // OLE magic
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }
        // Office open XML version with exploit
        $ooxml_eq = "word/embeddings" ascii
    condition:
        $ole_magic and ($eqnedt32_clsid or $payload_hdr)
        or ($ooxml_eq and $eqnedt32_clsid)
}"#.to_string(),
        ),
    ]
}

fn document_malware_rules_part_b() -> Vec<BuiltinRule> {
    vec![
        BuiltinRule::new(
            "Doc_RTF_MaliciousObject",
            RuleCategory::DocumentMalware,
            "RTF document with embedded OLE object (malware delivery)",
            65,
            r#"rule Doc_RTF_MaliciousObject {
    meta:
        author = "RustRE builtin"
        description = "RTF with embedded OLE/shellcode"
        severity = 65
        category = "document_malware"
    strings:
        $rtf_magic = { 7B 5C 72 74 66 }
        $objdata = "\\objdata" ascii nocase
        $object = "\\object" ascii nocase
        // Hex-encoded MZ header inside RTF object stream
        $mz_hex1 = "4d5a" ascii nocase
        $mz_hex2 = "4D5A" ascii
        // CVE-2010-3333 / CVE-2014-1761 pattern
        $pFragments = "\\pFragments" ascii
        // Large hex blob (>512 consecutive hex chars) = likely shellcode
        $hex_blob = /[0-9a-fA-F]{512,}/
    condition:
        $rtf_magic and
        (($objdata or $object) and ($mz_hex1 or $mz_hex2))
        or ($rtf_magic and $pFragments)
}"#.to_string(),
        ),
        BuiltinRule::new(
            "Doc_PDF_JavaScript",
            RuleCategory::DocumentMalware,
            "PDF with embedded JavaScript and suspicious actions",
            60,
            r#"rule Doc_PDF_JavaScript {
    meta:
        author = "RustRE builtin"
        description = "PDF containing JavaScript (potential exploit)"
        severity = 60
        category = "document_malware"
    strings:
        $pdf_magic = { 25 50 44 46 }
        $js1 = "/JavaScript" ascii
        $js2 = "/JS" ascii
        $js3 = "eval(" ascii wide nocase
        $js4 = "unescape(" ascii wide nocase
        $openaction = "/OpenAction" ascii
        $launch = "/Launch" ascii
        $submitform = "/SubmitForm" ascii
        $embedded_file = "/EmbeddedFile" ascii
        // Heap spray pattern
        $heap_spray = "%u0c0c%u0c0c" ascii
        $heap_spray2 = "\\u0c0c\\u0c0c" ascii
    condition:
        $pdf_magic and
        ($js1 or $js2) and
        (($openaction or $launch) or $heap_spray or $heap_spray2 or
         ($js3 and $js4))
}"#.to_string(),
        ),
    ]
}

// ── Rule index ────────────────────────────────────────────────────────────────

/// A searchable index of all built-in rules.
pub struct BuiltinRuleIndex {
    rules: Vec<BuiltinRule>,
    by_name: HashMap<String, usize>,
    by_category: HashMap<RuleCategory, Vec<usize>>,
}

impl BuiltinRuleIndex {
    #[must_use] 
    pub fn build() -> Self {
        let rules = all_builtin_rules();
        let mut by_name = HashMap::new();
        let mut by_category: HashMap<RuleCategory, Vec<usize>> = HashMap::new();
        for (i, r) in rules.iter().enumerate() {
            by_name.insert(r.name.clone(), i);
            by_category.entry(r.category).or_default().push(i);
        }
        Self { rules, by_name, by_category }
    }

    #[must_use] 
    pub fn get(&self, name: &str) -> Option<&BuiltinRule> {
        self.by_name.get(name).map(|&i| &self.rules[i])
    }

    #[must_use] 
    pub fn category(&self, cat: RuleCategory) -> Vec<&BuiltinRule> {
        self.by_category.get(&cat)
            .map(|ids| ids.iter().map(|&i| &self.rules[i]).collect())
            .unwrap_or_default()
    }

    #[must_use] 
    pub fn all(&self) -> &[BuiltinRule] {
        &self.rules
    }

    #[must_use] 
    pub fn by_min_severity(&self, min: u8) -> Vec<&BuiltinRule> {
        self.rules.iter().filter(|r| r.severity >= min).collect()
    }

    #[must_use] 
    pub fn search(&self, query: &str) -> Vec<&BuiltinRule> {
        let q = query.to_lowercase();
        self.rules.iter().filter(|r| {
            r.name.to_lowercase().contains(&q) ||
            r.description.to_lowercase().contains(&q)
        }).collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_rules_non_empty() {
        let rules = all_builtin_rules();
        assert!(!rules.is_empty());
        for r in &rules {
            assert!(!r.name.is_empty(), "rule has empty name");
            assert!(!r.source.is_empty(), "rule '{}' has empty source", r.name);
            assert!(r.source.contains("condition:"), "rule '{}' missing condition", r.name);
        }
    }

    #[test]
    fn test_shellcode_category() {
        let rules = rules_by_category(RuleCategory::Shellcode);
        assert!(!rules.is_empty());
    }

    #[test]
    fn test_packer_rules_have_family() {
        for r in rules_by_category(RuleCategory::Packer) {
            assert!(r.source.contains("family"), "packer rule '{}' missing family", r.name);
        }
    }

    #[test]
    fn test_index_search() {
        let idx = BuiltinRuleIndex::build();
        let results = idx.search("shellcode");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_index_by_severity() {
        let idx = BuiltinRuleIndex::build();
        let high = idx.by_min_severity(80);
        assert!(!high.is_empty());
        for r in &high {
            assert!(r.severity >= 80);
        }
    }

    #[test]
    fn test_builtin_source_all_contains_all_names() {
        let src = builtin_source_all();
        for r in all_builtin_rules() {
            assert!(src.contains(&r.name), "combined source missing rule '{}'", r.name);
        }
    }
}
