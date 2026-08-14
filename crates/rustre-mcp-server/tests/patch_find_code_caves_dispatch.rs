//! Integration test verifying that `patch_patch_find_code_caves` dispatches
//! through the rmcp surface and actually scans the file at `path`.
//!
//! Regression guard for FIX D: the tool must accept `path` directly (no
//! session required) so callers can invoke it without first loading a binary
//! into a session.

use rustre_mcp_server::RustREMcpServer;
use serde_json::{Value, json};

/// Build a minimal ELF64 with an executable `.text` section containing a 64-byte
/// 0xCC cave bracketed by non-cave bytes — same shape as the rustre-patch
/// fix-D fixture.
fn make_minimal_elf64_with_text(text: &[u8]) -> Vec<u8> {
    const SHENTSIZE: usize = 64;
    let ehsize: usize = 64;
    let text_off = ehsize + 3 * SHENTSIZE;
    let mut bin = vec![0u8; text_off + text.len()];
    bin[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    bin[4] = 2; // EI_CLASS = ELFCLASS64
    bin[5] = 1; // EI_DATA = ELFDATA2LSB
    bin[6] = 1; // EI_VERSION
    // e_type=ET_EXEC=2, e_machine=EM_X86_64=0x3e
    bin[16..18].copy_from_slice(&2u16.to_le_bytes());
    bin[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
    bin[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    // e_shoff = ehsize, e_shentsize, e_shnum=3, e_shstrndx=2
    bin[40..48].copy_from_slice(&(ehsize as u64).to_le_bytes());
    bin[52..54].copy_from_slice(&(ehsize as u16).to_le_bytes()); // e_ehsize
    bin[58..60].copy_from_slice(&(SHENTSIZE as u16).to_le_bytes());
    bin[60..62].copy_from_slice(&3u16.to_le_bytes());
    bin[62..64].copy_from_slice(&2u16.to_le_bytes());
    // shstrtab content: "\0.text\0.shstrtab\0"
    let shstr = b"\0.text\0.shstrtab\0";
    let shstr_off = text_off + text.len();
    bin.extend_from_slice(shstr);
    // sh[1] = .text
    let sh1 = ehsize + SHENTSIZE;
    bin[sh1..sh1 + 4].copy_from_slice(&1u32.to_le_bytes()); // sh_name -> ".text"
    bin[sh1 + 4..sh1 + 8].copy_from_slice(&1u32.to_le_bytes()); // SHT_PROGBITS
    bin[sh1 + 8..sh1 + 16].copy_from_slice(&0x6u64.to_le_bytes()); // SHF_ALLOC|SHF_EXECINSTR
    bin[sh1 + 24..sh1 + 32].copy_from_slice(&(text_off as u64).to_le_bytes()); // sh_offset
    bin[sh1 + 32..sh1 + 40].copy_from_slice(&(text.len() as u64).to_le_bytes()); // sh_size
    // sh[2] = .shstrtab
    let sh2 = ehsize + 2 * SHENTSIZE;
    bin[sh2..sh2 + 4].copy_from_slice(&7u32.to_le_bytes()); // sh_name -> ".shstrtab"
    bin[sh2 + 4..sh2 + 8].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB
    bin[sh2 + 24..sh2 + 32].copy_from_slice(&(shstr_off as u64).to_le_bytes());
    bin[sh2 + 32..sh2 + 40].copy_from_slice(&(shstr.len() as u64).to_le_bytes());
    // Write text payload
    bin[text_off..text_off + text.len()].copy_from_slice(text);
    bin
}

#[test]
fn patch_find_code_caves_dispatch_uses_path() {
    let mut text = vec![0x90u8; 8];
    text.extend(std::iter::repeat(0xCC).take(64));
    text.extend(std::iter::repeat(0x90).take(8));
    let bin = make_minimal_elf64_with_text(&text);

    let path = std::env::temp_dir().join("rustre_mcp_find_code_caves_dispatch.bin");
    std::fs::write(&path, &bin).expect("write elf");

    let srv = RustREMcpServer::new();
    let result = srv.dispatch_tool(
        "patch_patch_find_code_caves",
        json!({ "path": path.to_string_lossy(), "min_size": 16 }),
    );

    assert!(
        !result.is_error.unwrap_or(false),
        "dispatch returned error: {result:?}"
    );
    let text = result
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("no text content");

    let parsed: Value = serde_json::from_str(&text).expect("response is JSON");
    assert!(
        parsed.get("stub").is_none(),
        "dispatch returned stub instead of running analyzer: {parsed}"
    );
    assert!(
        parsed["count"].as_u64().unwrap_or(0) >= 1,
        "expected at least one cave, got: {parsed}"
    );

    let _ = std::fs::remove_file(&path);
}
