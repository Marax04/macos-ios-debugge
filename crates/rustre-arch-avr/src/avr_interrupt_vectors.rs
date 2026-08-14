//! `avr_interrupt_vectors` — AVR interrupt vector table database.
//!
//! Every AVR MCU has a fixed interrupt vector table at the beginning of flash.
//! Each vector occupies 2 bytes (classic AVR, ≤8 KiB flash) or 4 bytes (mega
//! AVR with >8 KiB flash) and contains a `RJMP` or `JMP` instruction pointing
//! to the ISR.  This module provides a typed database for common variants.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// InterruptSource
// ─────────────────────────────────────────────────────────────────────────────

/// The hardware source that triggers an interrupt.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InterruptSource {
    /// Power-on reset (not really an interrupt, but vector 0).
    Reset,
    /// External interrupt request on `INTn` pin.
    ExternalInt(u8),
    /// Pin-change interrupt on `PCINTn` group.
    PinChange(u8),
    /// Timer overflow.
    TimerOverflow(u8),
    /// Timer output compare match.
    TimerCompareMatch { timer: u8, channel: char },
    /// Timer input capture.
    TimerInputCapture(u8),
    /// SPI Serial Transfer Complete.
    SpiTransferComplete,
    /// USART Receive Complete.
    UsartRxComplete(u8),
    /// USART Data Register Empty.
    UsartDataEmpty(u8),
    /// USART Transmit Complete.
    UsartTxComplete(u8),
    /// ADC Conversion Complete.
    AdcComplete,
    /// EEPROM Ready.
    EepromReady,
    /// Analog Comparator.
    AnalogComparator,
    /// 2-wire Serial Interface (I2C/TWI).
    TwiComplete,
    /// Store Program Memory (SPM) Ready.
    SpmReady,
    /// Watchdog Timer Overflow.
    WatchdogTimeout,
    /// Any other interrupt.
    Other(String),
}

impl InterruptSource {
    /// Returns a short abbreviation suitable for assembly comments.
    #[must_use]
    pub fn abbrev(&self) -> String {
        match self {
            Self::Reset => "RESET".into(),
            Self::ExternalInt(n) => format!("INT{n}"),
            Self::PinChange(n) => format!("PCINT{n}"),
            Self::TimerOverflow(n) => format!("OVF{n}"),
            Self::TimerCompareMatch { timer, channel } => format!("OC{timer}{channel}"),
            Self::TimerInputCapture(n) => format!("ICU{n}"),
            Self::SpiTransferComplete => "SPI".into(),
            Self::UsartRxComplete(n) => format!("RXC{n}"),
            Self::UsartDataEmpty(n) => format!("UDRE{n}"),
            Self::UsartTxComplete(n) => format!("TXC{n}"),
            Self::AdcComplete => "ADC".into(),
            Self::EepromReady => "ERDY".into(),
            Self::AnalogComparator => "ACI".into(),
            Self::TwiComplete => "TWI".into(),
            Self::SpmReady => "SPMR".into(),
            Self::WatchdogTimeout => "WDT".into(),
            Self::Other(s) => s.clone(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VectorEntry — one row in the vector table
// ─────────────────────────────────────────────────────────────────────────────

/// A single entry in an AVR interrupt vector table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorEntry {
    /// 0-based vector number (0 = RESET, 1 = INT0, …).
    pub vector_num: u8,
    /// Byte address of this vector in flash (= `vector_num` × `vector_size`).
    pub byte_addr: u16,
    /// Canonical source name (e.g. `"INT0_vect"`).
    pub vector_name: String,
    /// Human-readable description.
    pub description: String,
    /// Hardware source category.
    pub source: InterruptSource,
    /// Suggested C/avr-libc ISR name (e.g. `"ISR(INT0_vect)"`).
    pub isr_name: String,
    /// Enable bit name (e.g. `"INT0"` in `EIMSK`).
    pub enable_bit: String,
    /// Flag bit name (e.g. `"INTF0"` in `EIFR`).
    pub flag_bit: String,
}

impl VectorEntry {
    /// Return the word address (for `RJMP`/`JMP` target calculation).
    #[must_use]
    pub const fn word_addr(&self) -> u16 {
        self.byte_addr / 2
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AvrInterruptVector — top-level type
// ─────────────────────────────────────────────────────────────────────────────

/// A rich representation of an AVR interrupt vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvrInterruptVector {
    pub entry: VectorEntry,
    /// Size of this vector slot in bytes (2 for classic, 4 for mega/xmega).
    pub slot_size: u8,
}

impl AvrInterruptVector {
    /// Byte address in flash.
    #[must_use]
    pub const fn byte_addr(&self) -> u16 {
        self.entry.byte_addr
    }

    /// Vector number.
    #[must_use]
    pub const fn number(&self) -> u8 {
        self.entry.vector_num
    }

    /// Canonical name (e.g. `"INT0_vect"`).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.entry.vector_name
    }

    /// Description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.entry.description
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Database builders
// ─────────────────────────────────────────────────────────────────────────────

fn v(num: u8, slot: u8, name: &str, desc: &str, source: InterruptSource, enable: &str, flag: &str) -> AvrInterruptVector {
    let byte_addr = u16::from(num) * u16::from(slot);
    let isr_name = format!("ISR({name})");
    AvrInterruptVector {
        entry: VectorEntry {
            vector_num: num,
            byte_addr,
            vector_name: name.to_owned(),
            description: desc.to_owned(),
            source,
            isr_name,
            enable_bit: enable.to_owned(),
            flag_bit: flag.to_owned(),
        },
        slot_size: slot,
    }
}

/// Build the `ATmega328P` interrupt vector table.
///
/// The `ATmega328P` uses 4-byte (2-word) vector slots for MCUs with more than
/// 8 KiB of flash.
#[must_use]
pub fn atmega328p_vectors() -> Vec<AvrInterruptVector> {
    use InterruptSource::{Reset, ExternalInt, PinChange, WatchdogTimeout, TimerCompareMatch, TimerOverflow, TimerInputCapture, SpiTransferComplete, UsartRxComplete, UsartDataEmpty, UsartTxComplete, AdcComplete, EepromReady, AnalogComparator, TwiComplete, SpmReady};
    let s = 4u8; // 4-byte slots
    vec![
        v(0,  s, "RESET_vect",        "External Pin/Power-on/Brown-out/Watchdog/JTAG Reset", Reset,                    "—",     "—"),
        v(1,  s, "INT0_vect",          "External Interrupt Request 0",  ExternalInt(0),        "INT0",  "INTF0"),
        v(2,  s, "INT1_vect",          "External Interrupt Request 1",  ExternalInt(1),        "INT1",  "INTF1"),
        v(3,  s, "PCINT0_vect",        "Pin Change Interrupt 0 (PCINT0..7)",  PinChange(0),   "PCIE0", "PCIF0"),
        v(4,  s, "PCINT1_vect",        "Pin Change Interrupt 1 (PCINT8..14)", PinChange(1),   "PCIE1", "PCIF1"),
        v(5,  s, "PCINT2_vect",        "Pin Change Interrupt 2 (PCINT16..23)",PinChange(2),   "PCIE2", "PCIF2"),
        v(6,  s, "WDT_vect",           "Watchdog Time-out Interrupt",   WatchdogTimeout,       "WDIE",  "WDIF"),
        v(7,  s, "TIMER2_COMPA_vect",  "Timer/Counter 2 Compare Match A",TimerCompareMatch { timer: 2, channel: 'A' }, "OCIE2A","OCF2A"),
        v(8,  s, "TIMER2_COMPB_vect",  "Timer/Counter 2 Compare Match B",TimerCompareMatch { timer: 2, channel: 'B' }, "OCIE2B","OCF2B"),
        v(9,  s, "TIMER2_OVF_vect",    "Timer/Counter 2 Overflow",      TimerOverflow(2),      "TOIE2", "TOV2"),
        v(10, s, "TIMER1_CAPT_vect",   "Timer/Counter 1 Capture Event", TimerInputCapture(1),  "ICIE1", "ICF1"),
        v(11, s, "TIMER1_COMPA_vect",  "Timer/Counter 1 Compare Match A",TimerCompareMatch { timer: 1, channel: 'A' }, "OCIE1A","OCF1A"),
        v(12, s, "TIMER1_COMPB_vect",  "Timer/Counter 1 Compare Match B",TimerCompareMatch { timer: 1, channel: 'B' }, "OCIE1B","OCF1B"),
        v(13, s, "TIMER1_OVF_vect",    "Timer/Counter 1 Overflow",      TimerOverflow(1),      "TOIE1", "TOV1"),
        v(14, s, "TIMER0_COMPA_vect",  "Timer/Counter 0 Compare Match A",TimerCompareMatch { timer: 0, channel: 'A' }, "OCIE0A","OCF0A"),
        v(15, s, "TIMER0_COMPB_vect",  "Timer/Counter 0 Compare Match B",TimerCompareMatch { timer: 0, channel: 'B' }, "OCIE0B","OCF0B"),
        v(16, s, "TIMER0_OVF_vect",    "Timer/Counter 0 Overflow",      TimerOverflow(0),      "TOIE0", "TOV0"),
        v(17, s, "SPI_STC_vect",       "SPI Serial Transfer Complete",  SpiTransferComplete,   "SPIE",  "SPIF"),
        v(18, s, "USART_RX_vect",      "USART Rx Complete",             UsartRxComplete(0),    "RXCIE0","RXC0"),
        v(19, s, "USART_UDRE_vect",    "USART Data Register Empty",     UsartDataEmpty(0),     "UDRIE0","UDRE0"),
        v(20, s, "USART_TX_vect",      "USART Tx Complete",             UsartTxComplete(0),    "TXCIE0","TXC0"),
        v(21, s, "ADC_vect",           "ADC Conversion Complete",       AdcComplete,           "ADIE",  "ADIF"),
        v(22, s, "EE_READY_vect",      "EEPROM Ready",                  EepromReady,           "EERIE", "EEPE"),
        v(23, s, "ANALOG_COMP_vect",   "Analog Comparator",             AnalogComparator,      "ACIE",  "ACI"),
        v(24, s, "TWI_vect",           "2-wire Serial Interface (I2C)",  TwiComplete,           "TWIE",  "TWINT"),
        v(25, s, "SPM_READY_vect",     "Store Program Memory Ready",    SpmReady,              "SPMIE", "RWWSB"),
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Public lookup API
// ─────────────────────────────────────────────────────────────────────────────

/// Return the canonical vector name for a given vector number in the
/// `ATmega328P` table.
///
/// Returns `None` if the number exceeds the table size.
#[must_use]
pub fn avr_vector_name(vector_num: u8) -> Option<String> {
    atmega328p_vectors()
        .into_iter()
        .find(|v| v.number() == vector_num)
        .map(|v| v.name().to_owned())
}

/// Build a map from vector number to [`AvrInterruptVector`].
#[must_use]
pub fn avr_vectors_by_number() -> HashMap<u8, AvrInterruptVector> {
    atmega328p_vectors()
        .into_iter()
        .map(|v| (v.number(), v))
        .collect()
}

/// Build a map from vector name to [`AvrInterruptVector`].
#[must_use]
pub fn avr_vectors_by_name() -> HashMap<String, AvrInterruptVector> {
    atmega328p_vectors()
        .into_iter()
        .map(|v| (v.name().to_owned(), v))
        .collect()
}

/// Given a byte address in flash, return the vector occupying that address
/// (if any).
#[must_use]
pub fn vector_at_address(byte_addr: u16) -> Option<AvrInterruptVector> {
    atmega328p_vectors()
        .into_iter()
        .find(|v| v.byte_addr() == byte_addr)
}

// ─────────────────────────────────────────────────────────────────────────────
// VectorTableAnalysis — heuristic analysis of a binary flash image
// ─────────────────────────────────────────────────────────────────────────────

/// Result of analysing the vector table area of a flash dump.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorTableAnalysis {
    /// Detected vector slot size in bytes.
    pub slot_size: u8,
    /// Number of non-reset-default vectors detected.
    pub non_default_count: usize,
    /// ISR target addresses, indexed by vector number.
    pub isr_targets: Vec<Option<u32>>,
}

impl VectorTableAnalysis {
    /// Analyse the beginning of a flash dump for the `ATmega328P` vector table.
    ///
    /// Assumes little-endian 16-bit instructions.
    ///
    /// # Arguments
    /// * `flash` – raw flash bytes starting at address 0.
    #[must_use]
    pub fn analyse(flash: &[u8]) -> Self {
        const VECTORS: usize = 26;
        const SLOT: usize = 4;
        let mut isr_targets: Vec<Option<u32>> = vec![None; VECTORS];
        let mut non_default_count = 0;

        for (i, target_slot) in isr_targets.iter_mut().enumerate() {
            let offset = i * SLOT;
            if offset + 4 > flash.len() { break; }
            let word0 = u16::from_le_bytes([flash[offset], flash[offset + 1]]);
            let word1 = u16::from_le_bytes([flash[offset + 2], flash[offset + 3]]);

            // JMP k: opcode = 0b1001010x_xxxk_110x; simplified: upper nibble 0x940C/0x940D
            let opcode = word0 & 0xFFFE;
            let target = if opcode == 0x940C || opcode == 0x940E {
                // JMP: target = word1 | ((word0 & 0x01F0) as u32 << 13) | ((word0 & 0x0001) as u32 << 22)
                let high = (u32::from(word0 & 0x01F0) << 13) | (u32::from(word0 & 0x0001) << 22);
                Some((high | u32::from(word1)) * 2)
            } else if word0 & 0xF000 == 0xC000 {
                // RJMP k: 12-bit signed offset
                let offset_val = i32::from(word0 & 0x0FFF);
                let signed = if offset_val & 0x0800 != 0 { offset_val | -0x1000i32 } else { offset_val };
                let target_word = i32::try_from(i).unwrap_or(i32::MAX) + 1 + signed;
                if target_word >= 0 { Some(target_word.cast_unsigned() * 2) } else { None }
            } else {
                None
            };
            if target.is_some_and(|t| t != (u32::try_from(i).unwrap_or(u32::MAX) * 2 + 4)) {
                non_default_count += 1;
            }
            *target_slot = target;
        }

        Self {
            slot_size: u8::try_from(SLOT).unwrap_or(u8::MAX),
            non_default_count,
            isr_targets,
        }
    }

    /// Return vector entries that have an ISR target set.
    #[must_use]
    pub fn active_vectors(&self) -> Vec<(u8, u32)> {
        self.isr_targets
            .iter()
            .enumerate()
            .filter_map(|(i, t)| t.map(|addr| (u8::try_from(i).unwrap_or(u8::MAX), addr)))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_length() {
        assert_eq!(atmega328p_vectors().len(), 26);
    }

    #[test]
    fn test_reset_vector() {
        let vecs = atmega328p_vectors();
        assert_eq!(vecs[0].number(), 0);
        assert_eq!(vecs[0].byte_addr(), 0x0000);
    }

    #[test]
    fn test_int0_vector() {
        let vecs = atmega328p_vectors();
        let int0 = &vecs[1];
        assert_eq!(int0.name(), "INT0_vect");
        assert_eq!(int0.byte_addr(), 0x0004);
    }

    #[test]
    fn test_vector_name_lookup() {
        assert_eq!(avr_vector_name(0).as_deref(), Some("RESET_vect"));
        assert_eq!(avr_vector_name(18).as_deref(), Some("USART_RX_vect"));
        assert_eq!(avr_vector_name(99), None);
    }

    #[test]
    fn test_by_name_map() {
        let m = avr_vectors_by_name();
        assert!(m.contains_key("INT0_vect"));
        assert!(m.contains_key("ADC_vect"));
    }

    #[test]
    fn test_by_number_map() {
        let m = avr_vectors_by_number();
        assert!(m.contains_key(&0));
        assert!(m.contains_key(&25));
    }

    #[test]
    fn test_vector_at_address_reset() {
        let v = vector_at_address(0x0000);
        assert!(v.is_some());
        assert_eq!(v.unwrap().name(), "RESET_vect");
    }

    #[test]
    fn test_vector_at_address_int0() {
        let v = vector_at_address(0x0004);
        assert!(v.is_some());
        assert_eq!(v.unwrap().name(), "INT0_vect");
    }

    #[test]
    fn test_vector_at_address_none() {
        assert!(vector_at_address(0x0001).is_none());
    }

    #[test]
    fn test_interrupt_source_abbrev() {
        assert_eq!(InterruptSource::ExternalInt(0).abbrev(), "INT0");
        assert_eq!(InterruptSource::TimerOverflow(2).abbrev(), "OVF2");
        assert_eq!(InterruptSource::SpiTransferComplete.abbrev(), "SPI");
        assert_eq!(InterruptSource::WatchdogTimeout.abbrev(), "WDT");
    }

    #[test]
    fn test_word_addr() {
        let vecs = atmega328p_vectors();
        // INT0_vect is at byte 0x0004, word 0x0002
        assert_eq!(vecs[1].entry.word_addr(), 0x0002);
    }

    #[test]
    fn test_vector_analysis_empty_flash() {
        let flash = vec![0xFF; 256];
        let a = VectorTableAnalysis::analyse(&flash);
        assert_eq!(a.slot_size, 4);
    }

    #[test]
    fn test_vector_analysis_rjmp() {
        // Build a small flash with RJMP 0x100 at offset 0
        // RJMP k: 1100 kkkk kkkk kkkk; k=0x07E (target = pc+1+126 = 128 words = 0x100 bytes)
        let mut flash = vec![0xFFu8; 256];
        // offset 0..4: slot 0 (RESET)
        // RJMP k: C000 | k; k = 0x07E (126 decimal)
        let rjmp: u16 = 0xC000 | 0x007E;
        let bytes = rjmp.to_le_bytes();
        flash[0] = bytes[0];
        flash[1] = bytes[1];
        let a = VectorTableAnalysis::analyse(&flash);
        assert!(!a.active_vectors().is_empty());
    }

    #[test]
    fn test_spi_vector_present() {
        let by_name = avr_vectors_by_name();
        assert!(by_name.contains_key("SPI_STC_vect"));
        let spi = &by_name["SPI_STC_vect"];
        assert!(matches!(spi.entry.source, InterruptSource::SpiTransferComplete));
    }

    #[test]
    fn test_usart_vector_isr_name() {
        let by_name = avr_vectors_by_name();
        let rxc = &by_name["USART_RX_vect"];
        assert_eq!(rxc.entry.isr_name, "ISR(USART_RX_vect)");
    }
}
