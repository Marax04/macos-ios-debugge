use rustre_arch_arm64::Arm64LinearDisassembler;
use rustre_core::address::Address;

fn main() {
    let groups: &[&[u8]] = &[
        &[0x60, 0x00, 0x00, 0x10],
        &[0x01, 0x78, 0x61, 0xf8],
        &[0x20, 0x00, 0x1f, 0xd6],
        &[0x09, 0x00, 0x00, 0xb0],
        &[0x29, 0x41, 0x10, 0x91],
        &[0x2a, 0x69, 0x62, 0x38],
        &[0x2b, 0xc9, 0x6a, 0xf8],
        &[0x60, 0x01, 0x1f, 0xd6],
    ];
    for g in groups {
        for r in Arm64LinearDisassembler::new(g, Address::new(0x1000)) {
            match r {
                Ok(i) => println!("{:02x?} -> '{}' '{}'", g, i.mnemonic, i.operands),
                Err(e) => println!("{:02x?} -> ERR {:?}", g, e),
            }
        }
    }
}
