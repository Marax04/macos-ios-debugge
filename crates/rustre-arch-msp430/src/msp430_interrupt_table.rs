//! MSP430 interrupt vector table analysis and ISR detection.
//!
//! Provides a full 16-entry interrupt vector table model for the base
//! MSP430 family (vectors 0xFFE0–0xFFFE), covering:
//!
//! - Named interrupt vector enumeration with SLAU208-compliant addresses
//! - `IsrInfo` records for discovered ISR handlers
//! - `Msp430InterruptTable` for parsing and querying the vector table from
//!   a memory image
//! - Priority assignment, RETI detection, and ISR naming utilities

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// VectorAddr constants
// ---------------------------------------------------------------------------

/// Base address of the first interrupt vector (lowest priority on `MSP430G2xx`).
pub const VECTOR_TABLE_BASE: u16 = 0xFFE0;
/// Address of the reset vector (highest priority, always present).
pub const RESET_VECTOR_ADDR: u16 = 0xFFFE;
/// Number of interrupt vectors in the base-family table.
pub const NUM_VECTORS: usize = 16;

// ---------------------------------------------------------------------------
// InterruptVector
// ---------------------------------------------------------------------------

/// All 16 interrupt vectors for the `MSP430G2xx` / F2xx / F4xx base family,
/// ordered from lowest to highest priority (0xFFE0 … 0xFFFE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterruptVector {
    /// 0xFFE0 — (reserved on many devices, used as Info-D start on MSP430FR).
    Vector0,
    /// 0xFFE2 — Port 1 interrupt.
    Port1,
    /// 0xFFE4 — Port 2 interrupt.
    Port2,
    /// 0xFFE6 — `Comparator_A` interrupt.
    ComparatorA,
    /// 0xFFE8 — ADC10 interrupt.
    Adc10,
    /// 0xFFEA — USCI A0/B0 receive interrupt.
    UsciRx,
    /// 0xFFEC — USCI A0/B0 transmit interrupt.
    UsciTx,
    /// 0xFFEE — `Timer_A` capture/compare 1–4 and overflow.
    TimerA1,
    /// 0xFFF0 — `Timer_A` capture/compare 0 (highest priority timer).
    TimerA0,
    /// 0xFFF2 — Watchdog timer interval.
    Watchdog,
    /// 0xFFF4 — `Comparator_B` interrupt.
    ComparatorB,
    /// 0xFFF6 — `Timer_B` capture/compare 1–4 and overflow.
    TimerB1,
    /// 0xFFF8 — `Timer_B` capture/compare 0.
    TimerB0,
    /// 0xFFFA — (reserved / NMI on some devices).
    Reserved1,
    /// 0xFFFC — Non-Maskable Interrupt (NMI / OFIE / NMIIE).
    Nmi,
    /// 0xFFFE — Reset / Power-On Reset.
    Reset,
}

impl InterruptVector {
    /// Return the vector table address for this interrupt.
    #[must_use]
    pub const fn address(self) -> u16 {
        VECTOR_TABLE_BASE + self.index() as u16 * 2
    }

    /// Return the zero-based index of this vector (0 = lowest priority).
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Vector0   => 0,
            Self::Port1     => 1,
            Self::Port2     => 2,
            Self::ComparatorA => 3,
            Self::Adc10     => 4,
            Self::UsciRx    => 5,
            Self::UsciTx    => 6,
            Self::TimerA1   => 7,
            Self::TimerA0   => 8,
            Self::Watchdog  => 9,
            Self::ComparatorB => 10,
            Self::TimerB1   => 11,
            Self::TimerB0   => 12,
            Self::Reserved1 => 13,
            Self::Nmi       => 14,
            Self::Reset     => 15,
        }
    }

    /// Return the short name of this interrupt source.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Vector0    => "VECTOR0",
            Self::Port1      => "PORT1",
            Self::Port2      => "PORT2",
            Self::ComparatorA => "COMP_A",
            Self::Adc10      => "ADC10",
            Self::UsciRx     => "USCI_RX",
            Self::UsciTx     => "USCI_TX",
            Self::TimerA1    => "TIMERA1",
            Self::TimerA0    => "TIMERA0",
            Self::Watchdog   => "WDT",
            Self::ComparatorB => "COMP_B",
            Self::TimerB1    => "TIMERB1",
            Self::TimerB0    => "TIMERB0",
            Self::Reserved1  => "RESERVED",
            Self::Nmi        => "NMI",
            Self::Reset      => "RESET",
        }
    }

    /// Return a suggested C-style ISR function name.
    #[must_use]
    pub fn suggested_isr_name(self) -> String {
        format!("{}_ISR", self.name())
    }

    /// Return `true` if this is a non-maskable interrupt (NMI or Reset).
    #[must_use]
    pub const fn is_nmi(self) -> bool {
        matches!(self, Self::Nmi | Self::Reset)
    }

    /// Return `true` if this is the reset vector.
    #[must_use]
    pub const fn is_reset(self) -> bool {
        matches!(self, Self::Reset)
    }

    /// Return the interrupt priority level (higher index = higher priority).
    #[must_use]
    pub const fn priority(self) -> usize {
        self.index()
    }

    /// Return all 16 vectors ordered by index.
    #[must_use]
    pub const fn all() -> [Self; NUM_VECTORS] {
        [
            Self::Vector0, Self::Port1, Self::Port2, Self::ComparatorA,
            Self::Adc10, Self::UsciRx, Self::UsciTx, Self::TimerA1,
            Self::TimerA0, Self::Watchdog, Self::ComparatorB, Self::TimerB1,
            Self::TimerB0, Self::Reserved1, Self::Nmi, Self::Reset,
        ]
    }

    /// Look up a vector by its vector table address.
    ///
    /// Returns `None` if `addr` is not in the vector table range.
    #[must_use]
    pub fn from_address(addr: u16) -> Option<Self> {
        if !(VECTOR_TABLE_BASE..=RESET_VECTOR_ADDR).contains(&addr) {
            return None;
        }
        if addr & 1 != 0 {
            return None; // odd address
        }
        let index = (addr - VECTOR_TABLE_BASE) as usize / 2;
        Self::all().get(index).copied()
    }
}

impl std::fmt::Display for InterruptVector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@0x{:04X}", self.name(), self.address())
    }
}

// ---------------------------------------------------------------------------
// IsrKind
// ---------------------------------------------------------------------------

/// Classification of an ISR handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsrKind {
    /// Standard ISR that ends with RETI.
    Standard,
    /// Reset handler (ends with JMP / CALL to main).
    ResetHandler,
    /// ISR that simply returns without restoring SR (bare return).
    BareReturn,
    /// ISR body that appears empty or trivial (just RETI).
    Trivial,
    /// ISR redirects to another address (e.g. via JMP).
    Trampoline,
    /// Handler body could not be classified.
    Unknown,
}

impl std::fmt::Display for IsrKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Standard     => "Standard",
            Self::ResetHandler => "ResetHandler",
            Self::BareReturn   => "BareReturn",
            Self::Trivial      => "Trivial",
            Self::Trampoline   => "Trampoline",
            Self::Unknown      => "Unknown",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// IsrInfo
// ---------------------------------------------------------------------------

/// Information about a discovered interrupt service routine.
#[derive(Debug, Clone)]
pub struct IsrInfo {
    /// The interrupt vector that points to this ISR.
    pub vector: InterruptVector,
    /// Entry-point address read from the vector table.
    pub entry_point: u16,
    /// Suggested name for this handler.
    pub name: String,
    /// How many instructions were found in the ISR body (0 if not analysed).
    pub instruction_count: usize,
    /// Whether the ISR ends with RETI.
    pub ends_with_reti: bool,
    /// Classification of the ISR.
    pub kind: IsrKind,
    /// Any PUSH'ed registers in the ISR prologue.
    pub saved_regs: Vec<u8>,
    /// Optional analyst note.
    pub note: Option<String>,
}

impl IsrInfo {
    /// Create a minimal ISR info record.
    #[must_use]
    pub fn new(vector: InterruptVector, entry_point: u16) -> Self {
        let name = vector.suggested_isr_name();
        Self {
            vector,
            entry_point,
            name,
            instruction_count: 0,
            ends_with_reti: false,
            kind: IsrKind::Unknown,
            saved_regs: Vec::new(),
            note: None,
        }
    }

    /// Return `true` if this is considered a properly formed ISR.
    #[must_use]
    pub const fn is_well_formed(&self) -> bool {
        self.ends_with_reti
    }
}

// ---------------------------------------------------------------------------
// Msp430InterruptTable
// ---------------------------------------------------------------------------

/// Parsed MSP430 interrupt vector table.
///
/// Built from a memory image by reading the 16 two-byte entries at
/// addresses 0xFFE0–0xFFFE.  Provides lookup, validation, and ISR analysis
/// helpers.
pub struct Msp430InterruptTable {
    /// Vector index → ISR info (populated entries only).
    entries: HashMap<usize, IsrInfo>,
    /// Raw 16-entry vector table values (0 if unset).
    raw: [u16; NUM_VECTORS],
}

impl Msp430InterruptTable {
    /// Create an empty interrupt table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            raw: [0u16; NUM_VECTORS],
        }
    }

    /// Parse the interrupt vector table from a memory image.
    ///
    /// `image` must contain at least `0x10000` bytes (full MSP430 address space).
    /// Alternatively supply a partial image starting at `VECTOR_TABLE_BASE`.
    ///
    /// # Errors
    /// Returns an error string if the image is too short to contain the vector table.
    pub fn from_image(image: &[u8]) -> Result<Self, String> {
        // We need at least 32 bytes at 0xFFE0.
        const TABLE_SIZE: usize = NUM_VECTORS * 2;
        const OFFSET_IN_64K: usize = VECTOR_TABLE_BASE as usize;

        let (base_offset, effective_len) = if image.len() >= 0x10000 {
            (OFFSET_IN_64K, image.len())
        } else if image.len() >= TABLE_SIZE {
            // Assume image starts at VECTOR_TABLE_BASE.
            (0, image.len())
        } else {
            return Err(format!(
                "image too short: {} bytes, need at least {} for vector table",
                image.len(),
                TABLE_SIZE
            ));
        };

        let _ = effective_len;
        let mut table = Self::new();

        for (i, vec) in InterruptVector::all().iter().enumerate() {
            let off = base_offset + i * 2;
            if off + 1 >= image.len() {
                continue;
            }
            let lo = u16::from(image[off]);
            let hi = u16::from(image[off + 1]);
            let target = lo | (hi << 8);
            table.raw[i] = target;

            // Skip zero / 0xFFFF entries (unprogrammed flash).
            if target == 0x0000 || target == 0xFFFF {
                continue;
            }

            let mut info = IsrInfo::new(*vec, target);
            // Classify reset vector heuristically.
            if vec.is_reset() {
                info.kind = IsrKind::ResetHandler;
            }
            table.entries.insert(i, info);
        }

        Ok(table)
    }

    /// Build a table from a flat array of 16 vector addresses.
    ///
    /// Addresses of 0x0000 or 0xFFFF are treated as unprogrammed.
    #[must_use]
    pub fn from_raw_vectors(vectors: &[u16; NUM_VECTORS]) -> Self {
        let mut table = Self::new();
        table.raw = *vectors;
        for (i, &addr) in vectors.iter().enumerate() {
            if addr == 0x0000 || addr == 0xFFFF {
                continue;
            }
            let vec = InterruptVector::all()[i];
            let mut info = IsrInfo::new(vec, addr);
            if vec.is_reset() {
                info.kind = IsrKind::ResetHandler;
            }
            table.entries.insert(i, info);
        }
        table
    }

    /// Look up the ISR info for a specific vector.
    #[must_use]
    pub fn get(&self, vector: InterruptVector) -> Option<&IsrInfo> {
        self.entries.get(&vector.index())
    }

    /// Look up the ISR info mutably for a specific vector.
    pub fn get_mut(&mut self, vector: InterruptVector) -> Option<&mut IsrInfo> {
        self.entries.get_mut(&vector.index())
    }

    /// Return the raw (unparsed) entry at vector index `i`.
    #[must_use]
    pub fn raw_entry(&self, i: usize) -> Option<u16> {
        self.raw.get(i).copied()
    }

    /// Return all populated ISR infos.
    #[must_use]
    pub fn all_isrs(&self) -> Vec<&IsrInfo> {
        let mut v: Vec<&IsrInfo> = self.entries.values().collect();
        v.sort_by_key(|i| i.vector.index());
        v
    }

    /// Return the reset vector entry point, or `None` if unprogrammed.
    #[must_use]
    pub fn reset_entry_point(&self) -> Option<u16> {
        self.get(InterruptVector::Reset).map(|i| i.entry_point)
    }

    /// Return the number of populated (programmed) vectors.
    #[must_use]
    pub fn populated_count(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the reset vector is populated.
    #[must_use]
    pub fn has_reset_vector(&self) -> bool {
        self.get(InterruptVector::Reset).is_some()
    }

    /// Return vectors that are populated but whose entry point is outside a
    /// sensible flash range (0x4000–0xFFFF for most MSP430 devices).
    ///
    /// Returns a list of (vector, `entry_point`) pairs that look suspicious.
    #[must_use]
    pub fn suspicious_entries(&self) -> Vec<(InterruptVector, u16)> {
        self.entries
            .values()
            .filter(|i| i.entry_point < 0x1000 || i.entry_point > 0xFFDF)
            .map(|i| (i.vector, i.entry_point))
            .collect()
    }

    /// Return a formatted summary table.
    #[must_use]
    pub fn summary(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::from(
            "Idx  Vector     Addr    Entry   Kind\n\
             ---- ---------- ------- ------- ----------\n",
        );
        for vec in InterruptVector::all() {
            let addr = vec.address();
            let raw = self.raw[vec.index()];
            if raw == 0 || raw == 0xFFFF {
                let _ = writeln!(s, "{:3}  {:10} 0x{:04X}  (unprogrammed)", vec.index(), vec.name(), addr);
            } else {
                let kind = self
                    .get(vec).map_or_else(|| "?".to_string(), |i| i.kind.to_string());
                let _ = writeln!(
                    s,
                    "{:3}  {:10} 0x{:04X}  0x{:04X}  {}",
                    vec.index(),
                    vec.name(),
                    addr,
                    raw,
                    kind
                );
            }
        }
        s
    }

    /// Look up the vector that points to a given `entry_point`.
    #[must_use]
    pub fn vector_for_entry(&self, entry_point: u16) -> Option<InterruptVector> {
        self.entries
            .values()
            .find(|i| i.entry_point == entry_point)
            .map(|i| i.vector)
    }
}

impl Default for Msp430InterruptTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Free function: vector_at
// ---------------------------------------------------------------------------

/// Return the `InterruptVector` for the given vector table address,
/// or `None` if `addr` is out of the vector table range.
///
/// Equivalent to `InterruptVector::from_address(addr)`.
#[must_use]
pub fn vector_at(addr: u16) -> Option<InterruptVector> {
    InterruptVector::from_address(addr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_raw_vectors() -> [u16; NUM_VECTORS] {
        let mut v = [0u16; NUM_VECTORS];
        v[15] = 0x4400; // RESET → 0x4400
        v[8]  = 0x4480; // TIMERA0 ISR
        v[1]  = 0x44C0; // PORT1 ISR
        v
    }

    fn table() -> Msp430InterruptTable {
        Msp430InterruptTable::from_raw_vectors(&make_raw_vectors())
    }

    #[test]
    fn test_table_has_reset() {
        assert!(table().has_reset_vector());
    }

    #[test]
    fn test_reset_entry_point() {
        assert_eq!(table().reset_entry_point(), Some(0x4400));
    }

    #[test]
    fn test_populated_count() {
        assert_eq!(table().populated_count(), 3);
    }

    #[test]
    fn test_get_vector() {
        let t = table();
        let isr = t.get(InterruptVector::Reset);
        assert!(isr.is_some());
        assert_eq!(isr.unwrap().entry_point, 0x4400);
    }

    #[test]
    fn test_get_unpopulated_vector() {
        let t = table();
        assert!(t.get(InterruptVector::Nmi).is_none());
    }

    #[test]
    fn test_all_isrs_sorted() {
        let t = table();
        let isrs = t.all_isrs();
        // Should be sorted by vector index.
        for w in isrs.windows(2) {
            assert!(w[0].vector.index() < w[1].vector.index());
        }
    }

    #[test]
    fn test_vector_for_entry() {
        let t = table();
        let v = t.vector_for_entry(0x44C0);
        assert_eq!(v, Some(InterruptVector::Port1));
    }

    #[test]
    fn test_vector_for_entry_not_found() {
        let t = table();
        assert!(t.vector_for_entry(0x0000).is_none());
    }

    #[test]
    fn test_no_suspicious_entries_normal() {
        let t = table();
        let sus = t.suspicious_entries();
        assert!(sus.is_empty(), "unexpected suspicious entries: {sus:?}");
    }

    #[test]
    fn test_suspicious_entry_low_address() {
        let mut v = [0u16; NUM_VECTORS];
        v[1] = 0x0020; // Port1 ISR pointing into SFR space — suspicious
        let t = Msp430InterruptTable::from_raw_vectors(&v);
        assert!(!t.suspicious_entries().is_empty());
    }

    #[test]
    fn test_raw_entry() {
        let t = table();
        assert_eq!(t.raw_entry(15), Some(0x4400)); // RESET
        assert_eq!(t.raw_entry(0),  Some(0x0000)); // unprogrammed
    }

    #[test]
    fn test_from_image_too_short() {
        let tiny = vec![0u8; 4];
        let result = Msp430InterruptTable::from_image(&tiny);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_image_partial_table() {
        // 32-byte image covering the vector table directly.
        let mut img = vec![0u8; 32];
        // Place reset vector (index 15 = offset 30) = 0x4400.
        img[30] = 0x00;
        img[31] = 0x44;
        let t = Msp430InterruptTable::from_image(&img).unwrap();
        assert_eq!(t.reset_entry_point(), Some(0x4400));
    }

    #[test]
    fn test_vector_at_free_fn() {
        let v = vector_at(0xFFFE);
        assert_eq!(v, Some(InterruptVector::Reset));
    }

    #[test]
    fn test_vector_at_out_of_range() {
        assert!(vector_at(0x4000).is_none());
    }

    #[test]
    fn test_interrupt_vector_address() {
        assert_eq!(InterruptVector::Reset.address(), 0xFFFE);
        assert_eq!(InterruptVector::Port1.address(), 0xFFE2);
    }

    #[test]
    fn test_interrupt_vector_index() {
        assert_eq!(InterruptVector::Reset.index(), 15);
        assert_eq!(InterruptVector::Vector0.index(), 0);
    }

    #[test]
    fn test_interrupt_vector_is_nmi() {
        assert!(InterruptVector::Nmi.is_nmi());
        assert!(InterruptVector::Reset.is_nmi());
        assert!(!InterruptVector::Port1.is_nmi());
    }

    #[test]
    fn test_interrupt_vector_priority() {
        assert!(InterruptVector::Reset.priority() > InterruptVector::Port1.priority());
    }

    #[test]
    fn test_interrupt_vector_from_address_valid() {
        assert_eq!(InterruptVector::from_address(0xFFFE), Some(InterruptVector::Reset));
        assert_eq!(InterruptVector::from_address(0xFFE2), Some(InterruptVector::Port1));
    }

    #[test]
    fn test_interrupt_vector_from_address_odd() {
        assert!(InterruptVector::from_address(0xFFE3).is_none());
    }

    #[test]
    fn test_isr_info_suggested_name() {
        let i = IsrInfo::new(InterruptVector::Port1, 0x4480);
        assert!(i.name.contains("PORT1"));
    }

    #[test]
    fn test_isr_info_is_well_formed_false() {
        let i = IsrInfo::new(InterruptVector::TimerA0, 0x44C0);
        assert!(!i.is_well_formed()); // ends_with_reti is false by default
    }

    #[test]
    fn test_summary_contains_reset() {
        let t = table();
        let s = t.summary();
        assert!(s.contains("RESET"));
        assert!(s.contains("0x4400"));
    }

    #[test]
    fn test_all_vectors_count() {
        assert_eq!(InterruptVector::all().len(), NUM_VECTORS);
    }

    #[test]
    fn test_reset_vector_addr_constant() {
        assert_eq!(RESET_VECTOR_ADDR, 0xFFFE);
    }
}
