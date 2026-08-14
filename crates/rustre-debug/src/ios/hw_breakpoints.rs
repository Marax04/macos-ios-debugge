//! ARM64 hardware breakpoints and watchpoints, end to end.
//!
//! Three things have to agree for a hardware breakpoint to work, and this
//! module is where they are made to agree:
//!
//! 1. **The debug registers.** [`crate::ios::arm64::hw`] builds the `DBGBVR`/`DBGBCR`
//!    and `DBGWVR`/`DBGWCR` words, including the `BAS` byte-address-select
//!    field that expresses a sub-doubleword watchpoint. That layer is pure
//!    arithmetic and rejects what the hardware cannot encode (unaligned
//!    watchpoints, sizes other than 1/2/4/8, ranges crossing the 8-byte
//!    granule).
//! 2. **The finite slot file.** A core implements a handful of `DBGBVR` pairs
//!    (6 on Apple arm64) and fewer `DBGWVR` pairs (4). Asking for a seventh is
//!    not a soft failure: it is [`HwError::BreakpointSlotsExhausted`]. A
//!    debugger that silently drops the request produces a session where a
//!    breakpoint the user set simply never fires, which is the single most
//!    expensive way to be wrong.
//! 3. **The wire.** `debugserver` is driven with `Z1`/`z1` for hardware
//!    breakpoints and `Z2`/`z2`, `Z3`/`z3`, `Z4`/`z4` for write, read and
//!    access watchpoints; the resulting stop is a `T05` carrying a
//!    `watch:`/`rwatch:`/`awatch:` key whose value is the watched address.
//!
//! The slot table and the stub are kept consistent by construction: a slot is
//! only committed after the stub answers `OK`, and a stub rejection rolls the
//! reservation back. Otherwise the table would drift from the target and every
//! later capacity decision would be made on a fiction.
//!
//! Nothing here is gated on the host OS — it is packet building, register
//! arithmetic and bookkeeping — so it is fully exercised against
//! [`crate::ios::mock_debugserver`] from Windows.

use crate::ios::arm64::{Arm64Error, hw};
use crate::ios::rsp::{RspClient, RspError, RspTransport, StopReply, commands::ZKind};

// ---------------------------------------------------------------------------
// kinds
// ---------------------------------------------------------------------------

/// The four hardware-assisted `Z` kinds. `Z0` (software breakpoint) is
/// deliberately absent: it consumes no debug register and is therefore not this
/// module's business.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HwKind {
    /// `Z1` — instruction breakpoint (`DBGBVR`/`DBGBCR`).
    Breakpoint,
    /// `Z2` — fires on stores.
    WriteWatch,
    /// `Z3` — fires on loads.
    ReadWatch,
    /// `Z4` — fires on either.
    AccessWatch,
}

impl HwKind {
    /// The `Z`/`z` packet kind.
    #[must_use]
    pub const fn z_kind(self) -> ZKind {
        match self {
            Self::Breakpoint => ZKind::Hardware,
            Self::WriteWatch => ZKind::WriteWatch,
            Self::ReadWatch => ZKind::ReadWatch,
            Self::AccessWatch => ZKind::AccessWatch,
        }
    }

    /// Does this kind occupy a watchpoint slot (rather than a breakpoint slot)?
    #[must_use]
    pub const fn is_watchpoint(self) -> bool {
        !matches!(self, Self::Breakpoint)
    }

    /// `DBGWCR.LSC` encoding, or `None` for an instruction breakpoint.
    #[must_use]
    pub const fn lsc(self) -> Option<hw::WatchKind> {
        match self {
            Self::Breakpoint => None,
            Self::WriteWatch => Some(hw::WatchKind::Store),
            Self::ReadWatch => Some(hw::WatchKind::Load),
            Self::AccessWatch => Some(hw::WatchKind::LoadStore),
        }
    }

    /// The stop-reply key `debugserver` uses to report a hit.
    #[must_use]
    pub const fn stop_key(self) -> Option<&'static str> {
        match self {
            Self::Breakpoint => None,
            Self::WriteWatch => Some("watch"),
            Self::ReadWatch => Some("rwatch"),
            Self::AccessWatch => Some("awatch"),
        }
    }

    /// Inverse of [`HwKind::stop_key`].
    #[must_use]
    pub fn from_stop_key(key: &str) -> Option<Self> {
        match key {
            "watch" => Some(Self::WriteWatch),
            "rwatch" => Some(Self::ReadWatch),
            "awatch" => Some(Self::AccessWatch),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// errors
// ---------------------------------------------------------------------------

/// A slot count together with WHERE it came from.
///
/// The target reports its capacity through `qHardwareBreakpointSupportInfo` /
/// `qWatchpointSupportInfo`, but not every stub answers, and then the Apple
/// arm64 constants are used instead. Those two are not the same claim: one is
/// measured, the other is a guess about a core nobody asked. Reporting both as
/// "N implemented" made a refusal state as fact a number that may be wrong in
/// either direction — denying a breakpoint the hardware would take, or
/// promising one it will not.
///
/// The number is unchanged; only the honesty of the sentence is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capacity {
    /// How many slots of this class.
    pub value: usize,
    /// `true` when the TARGET reported it, `false` when it was assumed.
    pub measured: bool,
}

impl core::fmt::Display for Capacity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.measured {
            write!(f, "{} implemented", self.value)
        } else {
            write!(
                f,
                "an assumed {} — the target did not report its capacity",
                self.value
            )
        }
    }
}

/// Why a hardware breakpoint or watchpoint could not be installed or removed.
///
/// Every variant names a *distinct* remedy, which is why none of them is a
/// generic "failed": exhaustion means "free a slot", an encoding error means
/// "ask for a legal address/size", and a stub rejection means "the target said
/// no" — conflating them would leave the caller unable to react.
#[derive(Debug, thiserror::Error)]
pub enum HwError {
    /// The address/size cannot be encoded into the debug registers.
    #[error("cannot encode hardware debug registers: {0}")]
    Encoding(#[from] Arm64Error),
    /// All `DBGBVR`/`DBGBCR` pairs are in use.
    #[error("no hardware breakpoint slot free ({capacity}, all in use)")]
    BreakpointSlotsExhausted { capacity: Capacity },
    /// All `DBGWVR`/`DBGWCR` pairs are in use.
    #[error("no hardware watchpoint slot free ({capacity}, all in use)")]
    WatchpointSlotsExhausted { capacity: Capacity },
    /// A breakpoint of that kind already covers that address.
    #[error("{kind:?} already set at {addr:#x} (slot {slot})")]
    Duplicate {
        kind: HwKind,
        addr: u64,
        slot: usize,
    },
    /// Removal asked for something that was never installed.
    #[error("no {kind:?} registered at {addr:#x}")]
    NotFound { kind: HwKind, addr: u64 },
    /// The stub refused the `Z`/`z` packet. Typically the target implements
    /// fewer slots than we were told, or the address is unmappable.
    #[error("target rejected {packet}: {source}")]
    Stub {
        packet: String,
        #[source]
        source: RspError,
    },
    /// Transport/protocol failure unrelated to the request's content.
    #[error(transparent)]
    Rsp(#[from] RspError),
}

// ---------------------------------------------------------------------------
// slot limits
// ---------------------------------------------------------------------------

/// How many hardware slots of each class the target implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HwSlotLimits {
    pub breakpoints: usize,
    pub watchpoints: usize,
    /// Whether `breakpoints` came from the target rather than the defaults.
    pub breakpoints_measured: bool,
    /// Whether `watchpoints` came from the target rather than the defaults.
    pub watchpoints_measured: bool,
}

impl Default for HwSlotLimits {
    /// The Apple arm64 counts. These are a *hint*: prefer
    /// [`HwSlotLimits::query`], because the authoritative number comes from the
    /// target and an over-estimate turns into a stub rejection at the worst
    /// possible moment.
    fn default() -> Self {
        Self {
            breakpoints: hw::APPLE_HW_BREAKPOINT_SLOTS,
            watchpoints: hw::APPLE_HW_WATCHPOINT_SLOTS,
            breakpoints_measured: false,
            watchpoints_measured: false,
        }
    }
}

impl HwSlotLimits {
    #[must_use]
    /// Counts supplied by the caller are treated as MEASURED: whoever calls
    /// this states the capacity, unlike [`Default`], which guesses it.
    pub const fn new(breakpoints: usize, watchpoints: usize) -> Self {
        Self {
            breakpoints,
            watchpoints,
            breakpoints_measured: true,
            watchpoints_measured: true,
        }
    }

    /// Parse the `num:<hex>;` reply to `qWatchpointSupportInfo` /
    /// `qHardwareBreakpointSupportInfo`.
    #[must_use]
    pub fn parse_num(reply: &str) -> Option<usize> {
        for field in reply.split(';') {
            if let Some(v) = field.trim().strip_prefix("num:") {
                return usize::from_str_radix(v.trim(), 16).ok();
            }
        }
        None
    }

    /// Ask the target how many slots it has, falling back to the Apple defaults
    /// for whichever query the stub does not implement.
    ///
    /// # Errors
    /// [`HwError::Rsp`] on a transport or framing failure. An `Exx` or empty
    /// reply is *not* an error — it means "unsupported", and the default is
    /// used.
    pub fn query<T: RspTransport>(client: &mut RspClient<T>) -> Result<Self, HwError> {
        let fallback = Self::default();
        let reported_w = Self::query_one(client, b"qWatchpointSupportInfo:")?;
        let reported_b = Self::query_one(client, b"qHardwareBreakpointSupportInfo")?;
        Ok(Self {
            breakpoints: reported_b.unwrap_or(fallback.breakpoints),
            watchpoints: reported_w.unwrap_or(fallback.watchpoints),
            breakpoints_measured: reported_b.is_some(),
            watchpoints_measured: reported_w.is_some(),
        })
    }

    fn query_one<T: RspTransport>(
        client: &mut RspClient<T>,
        packet: &[u8],
    ) -> Result<Option<usize>, HwError> {
        let reply = client.request(packet)?;
        if reply.data.is_empty() || reply.error_code().is_some() {
            return Ok(None);
        }
        Ok(Self::parse_num(&reply.as_str()))
    }

    /// Capacity for a given kind.
    #[must_use]
    pub const fn capacity(&self, kind: HwKind) -> Capacity {
        if kind.is_watchpoint() {
            Capacity { value: self.watchpoints, measured: self.watchpoints_measured }
        } else {
            Capacity { value: self.breakpoints, measured: self.breakpoints_measured }
        }
    }
}

// ---------------------------------------------------------------------------
// slot entries
// ---------------------------------------------------------------------------

/// A hardware breakpoint occupying slot `slot`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HwBreakpointEntry {
    pub slot: usize,
    pub addr: u64,
    pub regs: hw::HwBreakpoint,
}

/// A hardware watchpoint occupying slot `slot`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HwWatchpointEntry {
    pub slot: usize,
    pub kind: HwKind,
    /// The address the user asked to watch (not the 8-byte-aligned `DBGWVR`).
    pub addr: u64,
    pub size: usize,
    pub regs: hw::HwWatchpoint,
}

impl HwWatchpointEntry {
    /// Does this watchpoint cover `addr`?
    #[must_use]
    pub const fn covers(&self, addr: u64) -> bool {
        // Offset comparison, never a materialised end: `saturating_add` reports
        // `u64::MAX` for a region whose true exclusive end is `u64::MAX + 1`,
        // and the `<` then drops the last byte of memory. Same correction as
        // `Symbol::contains` and `MemoryAccess::overlaps` (iter 273).
        addr >= self.addr && addr - self.addr < self.size as u64
    }
}

// ---------------------------------------------------------------------------
// the slot table
// ---------------------------------------------------------------------------

/// The debug-register file as this debugger believes the target has programmed
/// it. Pure bookkeeping — no I/O — so the allocation policy is testable on its
/// own, separately from the packets it eventually produces.
#[derive(Debug, Clone)]
pub struct HwSlotTable {
    limits: HwSlotLimits,
    breakpoints: Vec<HwBreakpointEntry>,
    watchpoints: Vec<HwWatchpointEntry>,
}

impl HwSlotTable {
    #[must_use]
    pub const fn new(limits: HwSlotLimits) -> Self {
        Self {
            limits,
            breakpoints: Vec::new(),
            watchpoints: Vec::new(),
        }
    }

    #[must_use]
    pub const fn limits(&self) -> HwSlotLimits {
        self.limits
    }

    #[must_use]
    pub fn breakpoints(&self) -> &[HwBreakpointEntry] {
        &self.breakpoints
    }

    #[must_use]
    pub fn watchpoints(&self) -> &[HwWatchpointEntry] {
        &self.watchpoints
    }

    /// Slots still free for `kind`.
    #[must_use]
    pub fn free_slots(&self, kind: HwKind) -> usize {
        let used = if kind.is_watchpoint() {
            self.watchpoints.len()
        } else {
            self.breakpoints.len()
        };
        self.limits.capacity(kind).value.saturating_sub(used)
    }

    /// Lowest slot index not currently occupied, so slot numbers are reused
    /// after a removal instead of climbing until they exceed the register file.
    fn lowest_free(used: &mut dyn Iterator<Item = usize>, capacity: usize) -> Option<usize> {
        let taken: Vec<usize> = used.collect();
        (0..capacity).find(|i| !taken.contains(i))
    }

    /// Reserve a breakpoint slot for `addr`.
    ///
    /// # Errors
    /// [`HwError::Encoding`] if `addr` is not 4-byte aligned,
    /// [`HwError::Duplicate`] if one is already set there, and
    /// [`HwError::BreakpointSlotsExhausted`] when the register file is full.
    pub fn insert_breakpoint(&mut self, addr: u64) -> Result<HwBreakpointEntry, HwError> {
        if let Some(existing) = self.breakpoints.iter().find(|b| b.addr == addr) {
            return Err(HwError::Duplicate {
                kind: HwKind::Breakpoint,
                addr,
                slot: existing.slot,
            });
        }
        // Encode *before* taking a slot: a rejected encoding must not consume
        // capacity.
        let regs = hw::breakpoint(addr, hw::PrivilegeControl::El0)?;
        let slot = Self::lowest_free(
            &mut self.breakpoints.iter().map(|b| b.slot),
            self.limits.breakpoints,
        )
        .ok_or(HwError::BreakpointSlotsExhausted {
            capacity: self.limits.capacity(HwKind::Breakpoint),
        })?;
        let entry = HwBreakpointEntry { slot, addr, regs };
        self.breakpoints.push(entry);
        Ok(entry)
    }

    /// Release the breakpoint slot at `addr`.
    ///
    /// # Errors
    /// [`HwError::NotFound`] if nothing is registered there.
    pub fn remove_breakpoint(&mut self, addr: u64) -> Result<HwBreakpointEntry, HwError> {
        let idx = self
            .breakpoints
            .iter()
            .position(|b| b.addr == addr)
            .ok_or(HwError::NotFound {
                kind: HwKind::Breakpoint,
                addr,
            })?;
        Ok(self.breakpoints.remove(idx))
    }

    /// Reserve a watchpoint slot.
    ///
    /// # Errors
    /// [`HwError::Encoding`] for a size/alignment the `BAS` field cannot
    /// express, [`HwError::Duplicate`], or
    /// [`HwError::WatchpointSlotsExhausted`].
    pub fn insert_watchpoint(
        &mut self,
        kind: HwKind,
        addr: u64,
        size: usize,
    ) -> Result<HwWatchpointEntry, HwError> {
        debug_assert!(kind.is_watchpoint());
        if let Some(existing) = self
            .watchpoints
            .iter()
            .find(|w| w.addr == addr && w.kind == kind)
        {
            return Err(HwError::Duplicate {
                kind,
                addr,
                slot: existing.slot,
            });
        }
        let lsc = kind.lsc().ok_or(HwError::NotFound { kind, addr })?;
        let regs = hw::watchpoint(addr, size, lsc, hw::PrivilegeControl::El0)?;
        let slot = Self::lowest_free(
            &mut self.watchpoints.iter().map(|w| w.slot),
            self.limits.watchpoints,
        )
        .ok_or(HwError::WatchpointSlotsExhausted {
            capacity: self.limits.capacity(kind),
        })?;
        let entry = HwWatchpointEntry {
            slot,
            kind,
            addr,
            size,
            regs,
        };
        self.watchpoints.push(entry);
        Ok(entry)
    }

    /// Release a watchpoint slot.
    ///
    /// # Errors
    /// [`HwError::NotFound`].
    pub fn remove_watchpoint(
        &mut self,
        kind: HwKind,
        addr: u64,
    ) -> Result<HwWatchpointEntry, HwError> {
        let idx = self
            .watchpoints
            .iter()
            .position(|w| w.addr == addr && w.kind == kind)
            .ok_or(HwError::NotFound { kind, addr })?;
        Ok(self.watchpoints.remove(idx))
    }

    /// The watchpoint whose watched range contains `addr`, if any. Used to turn
    /// a `watch:ADDR` stop into the entry the user installed.
    #[must_use]
    pub fn watchpoint_covering(&self, addr: u64) -> Option<&HwWatchpointEntry> {
        self.watchpoints.iter().find(|w| w.covers(addr))
    }

    /// The breakpoint registered at `addr`, if any.
    #[must_use]
    pub fn breakpoint_at(&self, addr: u64) -> Option<&HwBreakpointEntry> {
        self.breakpoints.iter().find(|b| b.addr == addr)
    }

    /// Forget everything, e.g. after the target exits.
    pub fn clear(&mut self) {
        self.breakpoints.clear();
        self.watchpoints.clear();
    }
}

// ---------------------------------------------------------------------------
// stop-reply decoding
// ---------------------------------------------------------------------------

/// A stop attributable to a hardware debug resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwStop {
    /// A watchpoint fired on `addr`. `slot` is filled in when the address is
    /// recognised; a `None` slot means the target reported a watchpoint we do
    /// not have on file, which is worth surfacing rather than hiding.
    Watchpoint {
        kind: HwKind,
        addr: u64,
        slot: Option<usize>,
    },
    /// An instruction breakpoint fired at `pc`.
    Breakpoint { pc: u64, slot: Option<usize> },
}

/// Extract a watchpoint hit from a stop reply, without any table to match
/// against.
///
/// Handles both the explicit `watch:`/`rwatch:`/`awatch:` keys and the
/// `reason:watchpoint` form some `debugserver` builds emit, in which case the
/// address is taken from the second `medata` value.
#[must_use]
pub fn parse_watchpoint_stop(reply: &StopReply) -> Option<(HwKind, u64)> {
    let StopReply::SignalWithInfo { pairs, .. } = reply else {
        return None;
    };
    for (k, v) in pairs {
        if let Some(kind) = HwKind::from_stop_key(k)
            && let Ok(addr) = u64::from_str_radix(v.trim_start_matches("0x"), 16)
        {
            return Some((kind, addr));
        }
    }
    // Fallback: `reason:watchpoint` with the address in the trailing `medata`.
    if !pairs
        .iter()
        .any(|(k, v)| k == "reason" && v == "watchpoint")
    {
        return None;
    }
    let addr = pairs
        .iter()
        .filter(|(k, _)| k == "medata")
        .filter_map(|(_, v)| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        .next_back()?;
    // Without a key we cannot tell read from write; `AccessWatch` is the honest
    // answer because it is the only one that is not a claim about direction.
    Some((HwKind::AccessWatch, addr))
}

// ---------------------------------------------------------------------------
// the controller
// ---------------------------------------------------------------------------

/// Drives hardware breakpoints and watchpoints over RSP, keeping [`HwSlotTable`]
/// in step with what the stub actually accepted.
#[derive(Debug, Clone)]
pub struct HwBreakpointController {
    table: HwSlotTable,
}

impl HwBreakpointController {
    #[must_use]
    pub const fn new(limits: HwSlotLimits) -> Self {
        Self {
            table: HwSlotTable::new(limits),
        }
    }

    /// Build a controller with the limits the target reports.
    ///
    /// # Errors
    /// See [`HwSlotLimits::query`].
    pub fn from_target<T: RspTransport>(client: &mut RspClient<T>) -> Result<Self, HwError> {
        Ok(Self::new(HwSlotLimits::query(client)?))
    }

    #[must_use]
    pub const fn table(&self) -> &HwSlotTable {
        &self.table
    }

    #[must_use]
    pub const fn table_mut(&mut self) -> &mut HwSlotTable {
        &mut self.table
    }

    /// Install a hardware breakpoint at `addr`.
    ///
    /// # Errors
    /// Slot exhaustion, an unencodable address, a duplicate, or a stub refusal.
    /// On refusal the reservation is rolled back, so the table never claims a
    /// slot the target did not take.
    pub fn set_breakpoint<T: RspTransport>(
        &mut self,
        client: &mut RspClient<T>,
        addr: u64,
    ) -> Result<HwBreakpointEntry, HwError> {
        let entry = self.table.insert_breakpoint(addr)?;
        let size = u32::try_from(crate::ios::arm64::INSTRUCTION_SIZE).unwrap_or(4);
        if let Err(e) = client.insert_breakpoint(ZKind::Hardware, addr, size) {
            let _ = self.table.remove_breakpoint(addr);
            return Err(HwError::Stub {
                packet: format!("Z1,{addr:x},{size:x}"),
                source: e,
            });
        }
        Ok(entry)
    }

    /// Remove the hardware breakpoint at `addr`.
    ///
    /// # Errors
    /// [`HwError::NotFound`] or a stub refusal. A stub refusal restores the
    /// entry: the breakpoint is still armed on the target, and pretending
    /// otherwise would leak a slot on the next capacity check.
    pub fn clear_breakpoint<T: RspTransport>(
        &mut self,
        client: &mut RspClient<T>,
        addr: u64,
    ) -> Result<HwBreakpointEntry, HwError> {
        let entry = self.table.remove_breakpoint(addr)?;
        let size = u32::try_from(crate::ios::arm64::INSTRUCTION_SIZE).unwrap_or(4);
        if let Err(e) = client.remove_breakpoint(ZKind::Hardware, addr, size) {
            self.table.breakpoints.push(entry);
            return Err(HwError::Stub {
                packet: format!("z1,{addr:x},{size:x}"),
                source: e,
            });
        }
        Ok(entry)
    }

    /// Install a watchpoint of `kind` covering `size` bytes at `addr`.
    ///
    /// # Errors
    /// As [`HwSlotTable::insert_watchpoint`], plus a stub refusal (rolled back).
    pub fn set_watchpoint<T: RspTransport>(
        &mut self,
        client: &mut RspClient<T>,
        kind: HwKind,
        addr: u64,
        size: usize,
    ) -> Result<HwWatchpointEntry, HwError> {
        if !kind.is_watchpoint() {
            return Err(HwError::NotFound { kind, addr });
        }
        let entry = self.table.insert_watchpoint(kind, addr, size)?;
        let wire_size = u32::try_from(size).unwrap_or(u32::MAX);
        if let Err(e) = client.insert_breakpoint(kind.z_kind(), addr, wire_size) {
            let _ = self.table.remove_watchpoint(kind, addr);
            return Err(HwError::Stub {
                packet: format!("Z{},{addr:x},{wire_size:x}", kind.z_kind().code()),
                source: e,
            });
        }
        Ok(entry)
    }

    /// Remove the watchpoint of `kind` at `addr`.
    ///
    /// # Errors
    /// As [`HwSlotTable::remove_watchpoint`], plus a stub refusal (restored).
    pub fn clear_watchpoint<T: RspTransport>(
        &mut self,
        client: &mut RspClient<T>,
        kind: HwKind,
        addr: u64,
    ) -> Result<HwWatchpointEntry, HwError> {
        let entry = self.table.remove_watchpoint(kind, addr)?;
        let wire_size = u32::try_from(entry.size).unwrap_or(u32::MAX);
        if let Err(e) = client.remove_breakpoint(kind.z_kind(), addr, wire_size) {
            self.table.watchpoints.push(entry);
            return Err(HwError::Stub {
                packet: format!("z{},{addr:x},{wire_size:x}", kind.z_kind().code()),
                source: e,
            });
        }
        Ok(entry)
    }

    /// Remove every installed resource, best effort. Returns the errors that
    /// occurred rather than swallowing them; the table keeps whatever could not
    /// be removed.
    pub fn clear_all<T: RspTransport>(&mut self, client: &mut RspClient<T>) -> Vec<HwError> {
        let mut errors = Vec::new();
        let bps: Vec<u64> = self.table.breakpoints.iter().map(|b| b.addr).collect();
        for addr in bps {
            if let Err(e) = self.clear_breakpoint(client, addr) {
                errors.push(e);
            }
        }
        let wps: Vec<(HwKind, u64)> = self
            .table
            .watchpoints
            .iter()
            .map(|w| (w.kind, w.addr))
            .collect();
        for (kind, addr) in wps {
            if let Err(e) = self.clear_watchpoint(client, kind, addr) {
                errors.push(e);
            }
        }
        errors
    }

    /// Attribute a stop reply to one of our installed resources.
    ///
    /// A `pc` is needed to recognise a hardware *breakpoint* hit, because the
    /// stop reply says only "breakpoint" — the address that distinguishes a
    /// hardware breakpoint from a `BRK` is the program counter.
    #[must_use]
    pub fn classify_stop(&self, reply: &StopReply, pc: Option<u64>) -> Option<HwStop> {
        if let Some((kind, addr)) = parse_watchpoint_stop(reply) {
            let slot = self.table.watchpoint_covering(addr).map(|w| w.slot);
            // Trust the table's kind over the wire's when we recognise the
            // address: `Z4` hits are reported by some stubs with the generic
            // form, and the installed kind is the ground truth.
            let kind = self
                .table
                .watchpoint_covering(addr)
                .map_or(kind, |w| w.kind);
            return Some(HwStop::Watchpoint { kind, addr, slot });
        }
        let pc = pc?;
        let entry = self.table.breakpoint_at(pc)?;
        Some(HwStop::Breakpoint {
            pc,
            slot: Some(entry.slot),
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::ios::mock_client::LoopbackTransport;
    use crate::ios::mock_debugserver::{Arm64Interp, MemoryRegion, MockDebugserver, Perms};

    // -- pure slot bookkeeping ---------------------------------------------

    /// A hardware watchpoint on the last bytes of memory still covers them.
    ///
    /// `covers` built the exclusive end with `saturating_add`, so a region
    /// ending at `u64::MAX` claimed an end of `u64::MAX` instead of
    /// `u64::MAX + 1`, and the strict `<` dropped the final byte. The engine
    /// would then decide a genuine hit fell outside the watched range and
    /// resume the target — the watchpoint appears armed and silently never
    /// fires. Same shape swept in iters 273/310/311; this instance was missed.
    #[test]
    fn a_hardware_watchpoint_at_the_end_of_memory_covers_its_last_byte() {
        let mut table = HwSlotTable::new(HwSlotLimits::new(4, 4));
        let entry = table
            .insert_watchpoint(HwKind::WriteWatch, u64::MAX - 3, 4)
            .expect("a free slot");

        for probe in [u64::MAX - 3, u64::MAX - 1, u64::MAX] {
            assert!(
                entry.covers(probe),
                "{probe:#x} is inside the watched region and must be covered"
            );
        }
        assert!(!entry.covers(u64::MAX - 4), "one byte below the region");

        // An ordinary region is unchanged, end still exclusive.
        let ordinary = HwWatchpointEntry {
            slot: 0,
            kind: HwKind::WriteWatch,
            addr: 0x1000,
            size: 4,
            regs: entry.regs,
        };
        assert!(ordinary.covers(0x1000));
        assert!(ordinary.covers(0x1003));
        assert!(!ordinary.covers(0x1004), "end is exclusive");
        assert!(!ordinary.covers(0x0FFF));
    }

    #[test]
    fn kinds_map_to_the_right_z_packets_and_stop_keys() {
        assert_eq!(HwKind::Breakpoint.z_kind().code(), 1);
        assert_eq!(HwKind::WriteWatch.z_kind().code(), 2);
        assert_eq!(HwKind::ReadWatch.z_kind().code(), 3);
        assert_eq!(HwKind::AccessWatch.z_kind().code(), 4);
        for k in [HwKind::WriteWatch, HwKind::ReadWatch, HwKind::AccessWatch] {
            let key = k.stop_key().unwrap();
            assert_eq!(HwKind::from_stop_key(key), Some(k));
            assert!(k.is_watchpoint());
        }
        assert_eq!(HwKind::Breakpoint.stop_key(), None);
        assert!(!HwKind::Breakpoint.is_watchpoint());
        assert_eq!(HwKind::Breakpoint.lsc(), None);
        assert_eq!(HwKind::ReadWatch.lsc(), Some(hw::WatchKind::Load));
    }

    #[test]
    fn breakpoint_slots_are_finite_and_exhaustion_is_an_error() {
        let mut t = HwSlotTable::new(HwSlotLimits::new(2, 1));
        assert_eq!(t.free_slots(HwKind::Breakpoint), 2);
        assert_eq!(t.insert_breakpoint(0x1000).unwrap().slot, 0);
        assert_eq!(t.insert_breakpoint(0x1004).unwrap().slot, 1);
        assert_eq!(t.free_slots(HwKind::Breakpoint), 0);
        let err = t.insert_breakpoint(0x1008).unwrap_err();
        assert!(
            matches!(err, HwError::BreakpointSlotsExhausted { capacity: Capacity { value: 2, .. } }),
            "{err:?}"
        );
        assert_eq!(t.breakpoints().len(), 2);
    }

    #[test]
    fn freed_slots_are_reused_rather_than_climbing() {
        let mut t = HwSlotTable::new(HwSlotLimits::new(2, 2));
        t.insert_breakpoint(0x1000).unwrap();
        t.insert_breakpoint(0x1004).unwrap();
        t.remove_breakpoint(0x1000).unwrap();
        // Without slot reuse this would be slot 2, which does not exist.
        assert_eq!(t.insert_breakpoint(0x2000).unwrap().slot, 0);
    }

    #[test]
    fn watchpoint_slots_are_counted_apart_from_breakpoint_slots() {
        let mut t = HwSlotTable::new(HwSlotLimits::new(1, 2));
        t.insert_breakpoint(0x1000).unwrap();
        // A full breakpoint file must not block a watchpoint.
        t.insert_watchpoint(HwKind::WriteWatch, 0x2000, 8).unwrap();
        t.insert_watchpoint(HwKind::ReadWatch, 0x2008, 4).unwrap();
        let err = t
            .insert_watchpoint(HwKind::AccessWatch, 0x2010, 1)
            .unwrap_err();
        assert!(
            matches!(err, HwError::WatchpointSlotsExhausted { capacity: Capacity { value: 2, .. } }),
            "{err:?}"
        );
    }

    #[test]
    fn same_address_with_a_different_kind_takes_a_separate_slot() {
        let mut t = HwSlotTable::new(HwSlotLimits::new(2, 4));
        t.insert_watchpoint(HwKind::WriteWatch, 0x3000, 4).unwrap();
        // Read and write watchpoints on one address are two hardware resources.
        let r = t.insert_watchpoint(HwKind::ReadWatch, 0x3000, 4).unwrap();
        assert_eq!(r.slot, 1);
        let dup = t.insert_watchpoint(HwKind::ReadWatch, 0x3000, 4).unwrap_err();
        assert!(matches!(dup, HwError::Duplicate { slot: 1, .. }), "{dup:?}");
    }

    #[test]
    fn unencodable_watchpoints_are_rejected_before_a_slot_is_taken() {
        let mut t = HwSlotTable::new(HwSlotLimits::new(1, 1));
        // 3 bytes has no BAS encoding.
        assert!(matches!(
            t.insert_watchpoint(HwKind::WriteWatch, 0x1000, 3).unwrap_err(),
            HwError::Encoding(Arm64Error::UnsupportedWatchpointSize(3))
        ));
        assert!(matches!(
            t.insert_watchpoint(HwKind::WriteWatch, 0x1002, 4).unwrap_err(),
            HwError::Encoding(Arm64Error::UnalignedWatchpoint { .. })
        ));
        assert_eq!(t.free_slots(HwKind::WriteWatch), 1);
        assert!(matches!(
            t.insert_breakpoint(0x1002).unwrap_err(),
            HwError::Encoding(Arm64Error::UnalignedInstruction(0x1002))
        ));
        assert_eq!(t.free_slots(HwKind::Breakpoint), 1);
    }

    #[test]
    fn programmed_registers_round_trip_through_the_arm64_layer() {
        let mut t = HwSlotTable::new(HwSlotLimits::default());
        let w = t.insert_watchpoint(HwKind::WriteWatch, 0x1004, 4).unwrap();
        // DBGWVR is the 8-byte-aligned base; BAS selects the upper word.
        assert_eq!(w.regs.dbgwvr, 0x1000);
        assert_eq!(hw::watchpoint_range(&w.regs), Some((0x1004, 4)));
        assert!(hw::is_enabled(w.regs.dbgwcr));
        let b = t.insert_breakpoint(0x4000).unwrap();
        assert_eq!(b.regs.dbgbvr, 0x4000);
        assert!(hw::is_enabled(b.regs.dbgbcr));
    }

    #[test]
    fn removing_something_absent_is_an_explicit_error() {
        let mut t = HwSlotTable::new(HwSlotLimits::default());
        assert!(matches!(
            t.remove_breakpoint(0x1000).unwrap_err(),
            HwError::NotFound { .. }
        ));
        assert!(matches!(
            t.remove_watchpoint(HwKind::WriteWatch, 0x1000).unwrap_err(),
            HwError::NotFound { .. }
        ));
    }

    #[test]
    fn slot_limits_parse_from_the_stub_reply() {
        assert_eq!(HwSlotLimits::parse_num("num:4;"), Some(4));
        assert_eq!(HwSlotLimits::parse_num("num:10;other:1;"), Some(0x10));
        assert_eq!(HwSlotLimits::parse_num("nope"), None);
        assert_eq!(HwSlotLimits::parse_num(""), None);
    }

    // -- stop-reply decoding ------------------------------------------------

    fn stop(payload: &[u8]) -> StopReply {
        StopReply::parse(payload).unwrap()
    }

    #[test]
    fn each_watch_key_decodes_to_its_kind() {
        assert_eq!(
            parse_watchpoint_stop(&stop(b"T05thread:1;watch:100000;")),
            Some((HwKind::WriteWatch, 0x0010_0000))
        );
        assert_eq!(
            parse_watchpoint_stop(&stop(b"T05thread:1;rwatch:2000;")),
            Some((HwKind::ReadWatch, 0x2000))
        );
        assert_eq!(
            parse_watchpoint_stop(&stop(b"T05thread:1;awatch:3000;")),
            Some((HwKind::AccessWatch, 0x3000))
        );
        assert_eq!(
            parse_watchpoint_stop(&stop(b"T05thread:1;reason:breakpoint;")),
            None
        );
        assert_eq!(parse_watchpoint_stop(&stop(b"S05")), None);
    }

    #[test]
    fn reason_watchpoint_without_a_key_falls_back_to_medata() {
        let r = stop(b"T05thread:1;metype:6;mecount:2;medata:0;medata:4010;reason:watchpoint;");
        assert_eq!(
            parse_watchpoint_stop(&r),
            Some((HwKind::AccessWatch, 0x4010))
        );
    }

    #[test]
    fn classify_stop_resolves_the_slot_and_prefers_the_installed_kind() {
        let mut c = HwBreakpointController::new(HwSlotLimits::new(2, 2));
        c.table_mut()
            .insert_watchpoint(HwKind::AccessWatch, 0x4010, 4)
            .unwrap();
        c.table_mut().insert_breakpoint(0x8000).unwrap();
        // Generic form: the table says this address is an access watchpoint.
        let r = stop(b"T05thread:1;metype:6;medata:0;medata:4012;reason:watchpoint;");
        assert_eq!(
            c.classify_stop(&r, None),
            Some(HwStop::Watchpoint {
                kind: HwKind::AccessWatch,
                addr: 0x4012,
                slot: Some(0),
            })
        );
        // An address we never watched: reported, with no slot, not swallowed.
        let r2 = stop(b"T05thread:1;watch:9999;");
        assert_eq!(
            c.classify_stop(&r2, None),
            Some(HwStop::Watchpoint {
                kind: HwKind::WriteWatch,
                addr: 0x9999,
                slot: None,
            })
        );
        // Breakpoint attribution needs the PC.
        let r3 = stop(b"T05thread:1;reason:breakpoint;");
        assert_eq!(
            c.classify_stop(&r3, Some(0x8000)),
            Some(HwStop::Breakpoint {
                pc: 0x8000,
                slot: Some(0)
            })
        );
        assert_eq!(c.classify_stop(&r3, Some(0x9000)), None);
        assert_eq!(c.classify_stop(&r3, None), None);
    }

    // -- end to end against the mock debugserver ----------------------------

    const TEXT: u64 = 0x1_0000_4000;

    /// One store (`stp`) and one load (`ldp`) at a known stack address.
    fn program() -> Vec<u32> {
        vec![
            Arm64Interp::STP_FP_LR_PRE,
            Arm64Interp::MOV_FP_SP,
            Arm64Interp::NOP,
            Arm64Interp::LDP_FP_LR_POST,
            Arm64Interp::RET,
        ]
    }

    type Client = RspClient<LoopbackTransport>;

    fn client_for(srv: MockDebugserver) -> Client {
        // A 7-byte chunk so nothing here can accidentally depend on one `recv`
        // returning one whole packet.
        RspClient::new(LoopbackTransport::new(srv).with_chunk(7))
    }

    fn connected() -> Client {
        client_for(MockDebugserver::with_program(0x1234, TEXT, &program()))
    }

    /// Expedited register from a stop reply, by `qRegisterInfo` index.
    fn expedited(reply: &StopReply, key: &str) -> Option<u64> {
        let StopReply::SignalWithInfo { pairs, .. } = reply else {
            return None;
        };
        let hexle = pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v)?;
        let bytes: Vec<u8> = (0..hexle.len() / 2)
            .map(|i| u8::from_str_radix(&hexle[i * 2..i * 2 + 2], 16).unwrap_or(0))
            .collect();
        let mut buf = [0u8; 8];
        let n = bytes.len().min(8);
        buf[..n].copy_from_slice(&bytes[..n]);
        Some(u64::from_le_bytes(buf))
    }

    fn pc_of(reply: &StopReply) -> Option<u64> {
        expedited(reply, "20")
    }

    fn sp_of(reply: &StopReply) -> Option<u64> {
        expedited(reply, "1f")
    }

    fn sent(c: &Client) -> Vec<String> {
        c.transport().server().packet_log.clone()
    }

    #[test]
    fn slot_limits_are_read_from_the_target() {
        let mut c = connected();
        let limits = HwSlotLimits::query(&mut c).unwrap();
        assert_eq!(limits.watchpoints, hw::APPLE_HW_WATCHPOINT_SLOTS);
        assert_eq!(limits.breakpoints, hw::APPLE_HW_BREAKPOINT_SLOTS);
    }

    #[test]
    fn hardware_breakpoint_fires_and_sends_z1() {
        let mut c = connected();
        let mut ctl = HwBreakpointController::from_target(&mut c).unwrap();
        let target = TEXT + 3 * 4; // the LDP
        assert_eq!(ctl.set_breakpoint(&mut c, target).unwrap().slot, 0);
        let reply = c.vcont(&[("c", None)]).unwrap();
        let pc = pc_of(&reply).expect("expedited pc");
        assert_eq!(pc, target, "stopped at the wrong pc: {reply:?}");
        assert_eq!(
            ctl.classify_stop(&reply, Some(pc)),
            Some(HwStop::Breakpoint {
                pc: target,
                slot: Some(0)
            })
        );
        assert!(
            sent(&c).iter().any(|p| p.starts_with("Z1,")),
            "expected a Z1 packet, log: {:?}",
            sent(&c)
        );
        ctl.clear_breakpoint(&mut c, target).unwrap();
        assert!(sent(&c).iter().any(|p| p.starts_with("z1,")));
        assert_eq!(ctl.table().breakpoints().len(), 0);
    }

    #[test]
    fn write_watchpoint_fires_on_the_stack_store() {
        let mut c = connected();
        let sp = sp_of(&c.halt_reason().unwrap()).expect("expedited sp");
        // `stp x29, x30, [sp, #-16]!` writes 8 bytes at sp-16.
        let watched = sp - 16;
        let mut ctl = HwBreakpointController::new(HwSlotLimits::new(2, 2));
        ctl.set_watchpoint(&mut c, HwKind::WriteWatch, watched, 8)
            .unwrap();
        let reply = c.vcont(&[("c", None)]).unwrap();
        assert_eq!(
            ctl.classify_stop(&reply, None),
            Some(HwStop::Watchpoint {
                kind: HwKind::WriteWatch,
                addr: watched,
                slot: Some(0),
            })
        );
        // The store is the first instruction, so we stopped right after it.
        assert_eq!(pc_of(&reply), Some(TEXT + 4));
        assert!(sent(&c).iter().any(|p| p.starts_with("Z2,")));
    }

    #[test]
    fn read_watchpoint_ignores_the_store_and_fires_on_the_load() {
        let mut c = connected();
        let sp = sp_of(&c.halt_reason().unwrap()).unwrap();
        let watched = sp - 16;
        let mut ctl = HwBreakpointController::new(HwSlotLimits::new(2, 2));
        ctl.set_watchpoint(&mut c, HwKind::ReadWatch, watched, 8)
            .unwrap();
        let reply = c.vcont(&[("c", None)]).unwrap();
        assert_eq!(
            ctl.classify_stop(&reply, None),
            Some(HwStop::Watchpoint {
                kind: HwKind::ReadWatch,
                addr: watched,
                slot: Some(0),
            })
        );
        // The store happened first and must NOT have stopped us: a read
        // watchpoint that fires on a write is the classic false positive.
        assert_eq!(pc_of(&reply), Some(TEXT + 4 * 4));
    }

    #[test]
    fn access_watchpoint_fires_on_the_first_touch_of_either_direction() {
        let mut c = connected();
        let sp = sp_of(&c.halt_reason().unwrap()).unwrap();
        let watched = sp - 16;
        let mut ctl = HwBreakpointController::new(HwSlotLimits::new(2, 2));
        ctl.set_watchpoint(&mut c, HwKind::AccessWatch, watched, 8)
            .unwrap();
        let reply = c.vcont(&[("c", None)]).unwrap();
        assert_eq!(
            ctl.classify_stop(&reply, None),
            Some(HwStop::Watchpoint {
                kind: HwKind::AccessWatch,
                addr: watched,
                slot: Some(0),
            })
        );
        assert_eq!(pc_of(&reply), Some(TEXT + 4));
    }

    #[test]
    fn a_watchpoint_on_untouched_memory_never_fires() {
        let mut c = connected();
        let sp = sp_of(&c.halt_reason().unwrap()).unwrap();
        let mut ctl = HwBreakpointController::new(HwSlotLimits::new(2, 2));
        // Somewhere in the stack the program does not touch.
        ctl.set_watchpoint(&mut c, HwKind::AccessWatch, sp - 4096, 8)
            .unwrap();
        let reply = c.vcont(&[("c", None)]).unwrap();
        assert_eq!(ctl.classify_stop(&reply, None), None);
        assert!(reply.is_exit(), "program should have run to completion");
    }

    #[test]
    fn instruction_fetch_does_not_trip_a_read_watchpoint() {
        // A watchpoint over the instruction stream must stay silent: fetching
        // is not a data access, and conflating them would stop on every
        // instruction.
        let mut c = connected();
        let mut ctl = HwBreakpointController::new(HwSlotLimits::new(2, 2));
        ctl.set_watchpoint(&mut c, HwKind::ReadWatch, TEXT, 8).unwrap();
        let reply = c.vcont(&[("c", None)]).unwrap();
        assert!(reply.is_exit(), "unexpected stop: {reply:?}");
    }

    #[test]
    fn removing_a_watchpoint_stops_it_firing() {
        let mut c = connected();
        let sp = sp_of(&c.halt_reason().unwrap()).unwrap();
        let watched = sp - 16;
        let mut ctl = HwBreakpointController::new(HwSlotLimits::new(2, 2));
        ctl.set_watchpoint(&mut c, HwKind::WriteWatch, watched, 8)
            .unwrap();
        ctl.clear_watchpoint(&mut c, HwKind::WriteWatch, watched)
            .unwrap();
        assert!(sent(&c).iter().any(|p| p.starts_with("z2,")));
        let reply = c.vcont(&[("c", None)]).unwrap();
        assert!(reply.is_exit(), "unexpected stop: {reply:?}");
        assert_eq!(ctl.table().watchpoints().len(), 0);
    }

    #[test]
    fn exhausting_the_target_slots_is_an_explicit_error() {
        let mut srv = MockDebugserver::with_program(9, TEXT, &program());
        srv.set_hw_slots(1, 2);
        let mut c = client_for(srv);
        let mut ctl = HwBreakpointController::from_target(&mut c).unwrap();
        assert_eq!(ctl.table().limits(), HwSlotLimits::new(1, 2));

        ctl.set_watchpoint(&mut c, HwKind::WriteWatch, 0x2000, 8).unwrap();
        ctl.set_watchpoint(&mut c, HwKind::WriteWatch, 0x2008, 8).unwrap();
        let err = ctl
            .set_watchpoint(&mut c, HwKind::WriteWatch, 0x2010, 8)
            .unwrap_err();
        assert!(
            matches!(err, HwError::WatchpointSlotsExhausted { capacity: Capacity { value: 2, .. } }),
            "{err:?}"
        );
        // The third request must never have reached the wire.
        assert_eq!(sent(&c).iter().filter(|p| p.starts_with("Z2,")).count(), 2);

        ctl.set_breakpoint(&mut c, TEXT).unwrap();
        let err = ctl.set_breakpoint(&mut c, TEXT + 4).unwrap_err();
        assert!(
            matches!(err, HwError::BreakpointSlotsExhausted { capacity: Capacity { value: 1, .. } }),
            "{err:?}"
        );
    }

    #[test]
    fn a_stub_refusal_rolls_the_reservation_back() {
        // The client believes there are more slots than the target implements —
        // exactly what happens when the count is assumed instead of asked for.
        // The refusal must not leave a phantom entry behind.
        let mut srv = MockDebugserver::with_program(9, TEXT, &program());
        srv.set_hw_slots(6, 1);
        let mut c = client_for(srv);
        let mut ctl = HwBreakpointController::new(HwSlotLimits::new(6, 4));

        ctl.set_watchpoint(&mut c, HwKind::WriteWatch, 0x2000, 8).unwrap();
        let err = ctl
            .set_watchpoint(&mut c, HwKind::WriteWatch, 0x2008, 8)
            .unwrap_err();
        match &err {
            HwError::Stub { packet, source } => {
                assert!(packet.starts_with("Z2,"), "{packet}");
                assert!(matches!(source, RspError::Remote(_)), "{source:?}");
            }
            other => panic!("expected a stub refusal, got {other:?}"),
        }
        // One entry, not two: the table matches the target.
        assert_eq!(ctl.table().watchpoints().len(), 1);
        assert_eq!(ctl.table().free_slots(HwKind::WriteWatch), 3);
    }

    #[test]
    fn clear_all_releases_every_slot() {
        let mut c = connected();
        let mut ctl = HwBreakpointController::new(HwSlotLimits::new(4, 4));
        ctl.set_breakpoint(&mut c, TEXT).unwrap();
        ctl.set_breakpoint(&mut c, TEXT + 4).unwrap();
        ctl.set_watchpoint(&mut c, HwKind::WriteWatch, 0x3000, 8).unwrap();
        assert!(ctl.clear_all(&mut c).is_empty());
        assert_eq!(ctl.table().breakpoints().len(), 0);
        assert_eq!(ctl.table().watchpoints().len(), 0);
        assert_eq!(ctl.table().free_slots(HwKind::Breakpoint), 4);
    }

    /// A refusal must not state a guessed capacity as measured fact.
    ///
    /// The target reports its slot counts through
    /// `qHardwareBreakpointSupportInfo` / `qWatchpointSupportInfo`, but not
    /// every stub answers — and then the Apple arm64 constants are used
    /// instead. Both were rendered as "N implemented", so a refusal asserted a
    /// number nobody had asked the target for. That is wrong in both
    /// directions: it can deny a breakpoint the hardware would take, or
    /// promise one it will not, and the message gives the user no way to tell
    /// which case they are in.
    ///
    /// The count itself is unchanged — only the claim about where it came
    /// from. Nothing here asserts a specific number, so the constants may
    /// change without touching this test.
    #[test]
    fn an_exhaustion_message_says_whether_the_capacity_was_measured_or_assumed() {
        // Measured: the caller stated the capacity.
        let stated = HwSlotLimits::new(2, 2);
        let msg = HwError::BreakpointSlotsExhausted {
            capacity: stated.capacity(HwKind::Breakpoint),
        }
        .to_string();
        assert!(
            msg.contains("implemented"),
            "a measured capacity should be stated plainly, got: {msg}"
        );
        assert!(
            !msg.contains("assumed"),
            "a measured capacity must not be hedged as assumed, got: {msg}"
        );

        // Assumed: nobody asked the target, so the fallback constants are in
        // play and the sentence has to admit it.
        let guessed = HwSlotLimits::default();
        assert!(
            !guessed.breakpoints_measured && !guessed.watchpoints_measured,
            "the defaults are a guess by construction"
        );
        for kind in [HwKind::Breakpoint, HwKind::WriteWatch] {
            let msg = if kind.is_watchpoint() {
                HwError::WatchpointSlotsExhausted { capacity: guessed.capacity(kind) }.to_string()
            } else {
                HwError::BreakpointSlotsExhausted { capacity: guessed.capacity(kind) }.to_string()
            };
            assert!(
                msg.contains("assumed"),
                "{kind:?}: a guessed capacity is reported as fact, got: {msg}"
            );
            assert!(
                msg.contains("did not report"),
                "{kind:?}: the message should say WHY it is a guess, got: {msg}"
            );
        }

        // The number survives the change: this is about the claim, not the
        // count.
        assert_eq!(stated.capacity(HwKind::Breakpoint).value, 2);
        assert_eq!(guessed.capacity(HwKind::Breakpoint).value, guessed.breakpoints);
    }

    #[test]
    fn a_sub_doubleword_watchpoint_only_covers_its_own_bytes() {
        let mut srv = MockDebugserver::with_program(9, TEXT, &program());
        assert!(srv.memory.map(MemoryRegion::zeroed(
            0x5000_0000,
            0x1000,
            Perms::rw(),
            "Data"
        )));
        let mut c = client_for(srv);
        let mut ctl = HwBreakpointController::new(HwSlotLimits::new(2, 2));
        let w = ctl
            .set_watchpoint(&mut c, HwKind::WriteWatch, 0x5000_0004, 4)
            .unwrap();
        assert_eq!(w.regs.dbgwvr, 0x5000_0000);
        assert_eq!(hw::watchpoint_range(&w.regs), Some((0x5000_0004, 4)));
        assert!(w.covers(0x5000_0007));
        assert!(!w.covers(0x5000_0003));
        assert!(!w.covers(0x5000_0008));
        // Nothing in the program touches it.
        assert!(c.vcont(&[("c", None)]).unwrap().is_exit());
    }
}
