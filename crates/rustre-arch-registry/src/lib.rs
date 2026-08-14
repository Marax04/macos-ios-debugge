//! `rustre-arch-registry`
//!
//! Composition crate: wires every concrete `rustre-arch-*` sub-crate into the
//! [`rustre_arch::global_registry`].
//!
//! Each sub-crate exposes a primary type implementing [`Architecture`].
//! [`all`] returns a fresh `Vec<Arc<dyn Architecture>>` containing one
//! instance of every wired backend, and [`register_all`] installs them
//! into the process-wide [`rustre_arch::global_registry`], overwriting any
//! `PlaceholderArch` entries that were previously inserted by
//! [`rustre_arch::register_all_builtins`].
//!
//! This crate lives outside the `rustre-arch` hub so the hub can stay
//! free of path-deps on its sub-crates (each of which depends on the hub).

use std::sync::Arc;

use rustre_core::arch::Architecture;

use rustre_arch_6502::Cpu6502Arch;
use rustre_arch_68k::Mc68kArch;
use rustre_arch_arm::ArmArch;
use rustre_arch_arm64::Arm64Arch;
use rustre_arch_avr::AvrArch;
use rustre_arch_bpf::BpfArch;
use rustre_arch_cil::CilArch;
use rustre_arch_dex::DexArch;
use rustre_arch_jvm::JvmArch;
use rustre_arch_lua::LuaArch;
use rustre_arch_luajit::LuaJitArch;
use rustre_arch_mips::MipsArch;
use rustre_arch_msp430::Msp430Arch;
use rustre_arch_ppc::PpcArch;
use rustre_arch_riscv::RiscvArch;
use rustre_arch_sparc::SparcArch;
use rustre_arch_wasm::WasmArch;
use rustre_arch_x86::X86Arch;
use rustre_arch_z80::Z80Arch;

/// Return a fresh `Vec` containing one boxed instance of every wired
/// sub-crate architecture backend.
#[must_use]
pub fn all() -> Vec<Arc<dyn Architecture>> {
    vec![
        Arc::new(Cpu6502Arch::default()) as Arc<dyn Architecture>,
        Arc::new(Mc68kArch::default()),
        Arc::new(ArmArch::default()),
        Arc::new(Arm64Arch),
        Arc::new(AvrArch::default()),
        Arc::new(BpfArch::default()),
        Arc::new(CilArch::default()),
        Arc::new(DexArch::default()),
        Arc::new(JvmArch),
        Arc::new(LuaArch::default()),
        Arc::new(LuaJitArch),
        Arc::new(MipsArch::default()),
        Arc::new(Msp430Arch::default()),
        Arc::new(PpcArch::default()),
        Arc::new(RiscvArch::default()),
        Arc::new(SparcArch::default()),
        Arc::new(WasmArch),
        Arc::new(X86Arch::default()),
        Arc::new(Z80Arch::default()),
    ]
}

/// Register every wired sub-crate backend into the process-wide
/// [`rustre_arch::global_registry`].
///
/// Existing entries with matching names -- including `PlaceholderArch`
/// stubs from [`rustre_arch::register_all_builtins`] -- are overwritten.
pub fn register_all() {
    let reg = rustre_arch::global_registry();
    for arch in all() {
        reg.insert(arch.name().to_owned(), arch);
    }
}
