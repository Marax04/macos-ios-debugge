# rustre-il

## Overview
Foundational intermediate-language primitives shared by the RustRE IL stack
(`rustre-il-lift`, `rustre-il-llil`, `rustre-il-mlil`, `rustre-il-hlil`,
`rustre-il-passes`). Owns only cross-cutting definitions (tier tags, IL-wide
errors); concrete instruction/expression types live in the sibling crates.

## Cargo.toml
- name: `rustre-il`
- version: `0.1.0`
- edition: `2024`
- license/description/repository/readme/keywords/categories/authors: workspace
- dependencies: `serde` (workspace), `thiserror` (workspace)
- lints: workspace
- `#![forbid(unsafe_code)]`

## Public API

### `enum IlTier`
Derives: `Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize`.

Variants:
- `Lift` — architecture-specific lifted effects (`rustre-il-lift`)
- `Llil` — low-level IL (`rustre-il-llil`)
- `Mlil` — medium-level IL (`rustre-il-mlil`)
- `Hlil` — high-level IL (`rustre-il-hlil`)

Methods:
- `pub const fn tag(self) -> &'static str`
  - Input: tier value (by copy).
  - Output: short static tag (`"lift" | "llil" | "mlil" | "hlil"`).
  - Behavior: pure const match; total.
- `pub const fn next(self) -> Option<Self>`
  - Input: tier value.
  - Output: next-higher tier in the lifting pipeline, or `None` for `Hlil`.
  - Behavior: `Lift -> Llil -> Mlil -> Hlil -> None`. Pure, const, total.

### `enum IlError`
Derives: `Debug, Error` (`thiserror`). Cross-tier invariant violations.

Variants:
- `Unsupported { tier: IlTier, op: String }` — `"unsupported operation `{op}` at tier {tier:?}"`
- `TierMismatch { expected: IlTier, actual: IlTier }` — `"tier mismatch: expected {expected:?}, got {actual:?}"`
- `Invalid(String)` — `"invalid IL: {0}"`

## I/O
- No filesystem, network, or global state. All functions are pure const.
- Serde Serialize/Deserialize on `IlTier` enables JSON/bincode round-trip across
  tier boundaries.

## Behavior / Invariants
- Tier ordering forms a strict linear chain terminating at `Hlil`.
- `tag()` is stable and used as a short human-readable identifier.
- `IlError` is the canonical error vocabulary for any tier that needs to signal
  unsupported ops, tier mismatch, or generic invalid-IL conditions.

## Testability
Tests present in `src/lib.rs` (`tier_ordering`, `tier_tags`). Pure functions,
no I/O — trivially testable.

## Public fn count
2 public functions (`IlTier::tag`, `IlTier::next`). Plus 2 public enums
(`IlTier`, `IlError`) with public variants.
