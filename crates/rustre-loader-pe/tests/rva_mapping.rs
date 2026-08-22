//! The invariant every RVA→file-offset translation must satisfy.
//!
//! A PE section is described twice: `virtual_size` bytes exist once loaded,
//! but only `raw_size` bytes exist *in the file*. When `virtual_size` exceeds
//! `raw_size` — ordinary for `.bss`-like padding, and trivially forged in a
//! hostile binary — the tail of the section has no file bytes behind it. A
//! translation that maps those RVAs anyway hands the caller an offset pointing
//! into the *next* section's data, or past the end of the file, and the parse
//! continues on bytes that were never part of the section.
//!
//! Nothing crashes; the import table is simply read from the wrong place. This
//! crate translates RVAs in four independent places, so the rule is asserted
//! here rather than trusted to stay consistent.

use rustre_loader_pe::imports::RvaSection;

const fn sec(virtual_address: u32, virtual_size: u32, raw_size: u32, raw_offset: u32) -> RvaSection {
    RvaSection { virtual_address, virtual_size, raw_size, raw_offset }
}

/// Sections whose virtual span exceeds their raw span, plus ordinary ones.
fn sections() -> Vec<RvaSection> {
    vec![
        // Ordinary: virtual == raw.
        sec(0x1000, 0x200, 0x200, 0x400),
        // Virtual tail with no file bytes behind it (the interesting case).
        sec(0x1000, 0x1000, 0x200, 0x400),
        // Entirely virtual (.bss): no raw data at all.
        sec(0x2000, 0x1000, 0, 0x600),
        // Raw larger than virtual (alignment padding in the file).
        sec(0x3000, 0x100, 0x200, 0x800),
    ]
}

/// If a translation succeeds, the offset must lie inside the section's *raw*
/// data — that is the only region the file actually provides.
#[test]
fn a_mapped_offset_stays_inside_the_sections_raw_data() {
    for s in sections() {
        let span = s.virtual_size.max(s.raw_size);
        for delta in 0..span.min(0x2000) {
            let rva = s.virtual_address + delta;
            let Some(off) = s.rva_to_offset(rva) else {
                continue;
            };
            let lo = s.raw_offset as usize;
            let hi = lo + s.raw_size as usize;
            assert!(
                off >= lo && off < hi,
                "rva {rva:#x} mapped to offset {off:#x}, outside this section's \
                 raw data [{lo:#x}, {hi:#x}) — section va={:#x} vsize={:#x} \
                 rawsize={:#x} rawoff={:#x}",
                s.virtual_address, s.virtual_size, s.raw_size, s.raw_offset,
            );
        }
    }
}

/// A section with no raw data can never yield a file offset.
#[test]
fn a_purely_virtual_section_maps_nothing() {
    let bss = sec(0x2000, 0x1000, 0, 0x600);
    for delta in 0..0x100 {
        assert_eq!(
            bss.rva_to_offset(0x2000 + delta),
            None,
            "a section with raw_size == 0 has no bytes in the file, \
             but rva {:#x} was mapped",
            0x2000 + delta
        );
    }
}

/// Guards the two tests above against passing vacuously: the generator must
/// actually produce RVAs that fall in a virtual-only tail, otherwise the rule
/// is never exercised.
#[test]
fn the_generator_reaches_the_virtual_only_tail() {
    let mut tail_rvas = 0;
    for s in sections() {
        if s.virtual_size <= s.raw_size {
            continue;
        }
        for delta in s.raw_size..s.virtual_size {
            let _ = s.rva_to_offset(s.virtual_address + delta);
            tail_rvas += 1;
        }
    }
    assert!(
        tail_rvas > 0,
        "no RVA in the fixtures lands past raw_size — the invariant above \
         would be passing without ever being tested"
    );
}
