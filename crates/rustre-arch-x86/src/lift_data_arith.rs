//! `lift_data_arith` — shared re-exports for x86 category lifter sub-modules.
//!
//! The actual handlers live in this crate's other modules (lift.rs, sse.rs,
//! x87.rs, branch.rs).  This file exists as a stable import anchor so that
//! future category-specific files can use:
//!
//!   `use super::lift_data_arith::*;`
//!
//! and get the right types without chasing down scattered re-exports.

pub use iced_x86::Instruction as IcedInstruction;
pub use rustre_core::arch::Instruction as CoreInstruction;
pub use rustre_il_llil::{LlilAnnotatedInstr, LlilExpr, LlilInstruction, LlilRegister, Size};
