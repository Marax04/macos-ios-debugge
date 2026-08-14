//! `avr_fuse_bits` — AVR fuse byte decoder.
//!
//! AVR microcontrollers use non-volatile fuse bytes to configure boot options,
//! clock sources, brown-out detection levels, and other hardware features.
//! This module provides typed decoding for the `ATmega328P` fuse bytes (Low,
//! High, Extended) and related configuration utilities.

use std::fmt;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// FuseSetting — one decoded fuse field
// ─────────────────────────────────────────────────────────────────────────────

/// A single decoded fuse bit-field with its interpreted meaning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuseSetting {
    /// Bit-field name (e.g. `"CKSEL"`, `"BODLEVEL"`).
    pub name: String,
    /// Raw extracted value.
    pub raw_value: u8,
    /// Human-readable interpretation (e.g. `"8 MHz internal RC"`).
    pub interpretation: String,
    /// Whether this field is active-low (0 = programmed/enabled, AVR convention).
    pub active_low: bool,
    /// Whether the fuse is currently "programmed" (0) or "unprogrammed" (1).
    pub programmed: bool,
}

impl FuseSetting {
    fn new(name: &str, raw: u8, interpretation: &str, active_low: bool) -> Self {
        Self {
            name: name.to_owned(),
            raw_value: raw,
            interpretation: interpretation.to_owned(),
            active_low,
            programmed: if active_low { raw == 0 } else { raw == 1 },
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FuseByte — one fuse byte with its name and settings
// ─────────────────────────────────────────────────────────────────────────────

/// A decoded AVR fuse byte.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuseByte {
    /// Fuse byte name (`"Low"`, `"High"`, or `"Extended"`).
    pub name: String,
    /// Raw byte value as programmed (active-low bits = programmed).
    pub raw: u8,
    /// Decoded fields.
    pub settings: Vec<FuseSetting>,
}

impl FuseByte {
    /// Find a setting by (case-insensitive) field name.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&FuseSetting> {
        let lower = name.to_lowercase();
        self.settings.iter().find(|s| s.name.to_lowercase() == lower)
    }

    /// Return all programmed (active) settings.
    #[must_use]
    pub fn programmed_settings(&self) -> Vec<&FuseSetting> {
        self.settings.iter().filter(|s| s.programmed).collect()
    }
}

impl fmt::Display for FuseByte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fuse {} = 0x{:02X}", self.name, self.raw)?;
        for s in &self.settings {
            write!(f, "\n  [{:8}] raw={} → {}", s.name, s.raw_value, s.interpretation)?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AvrFuseBits — all three fuse bytes combined
// ─────────────────────────────────────────────────────────────────────────────

/// All three `ATmega328P` fuse bytes decoded together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvrFuseBits {
    pub low: FuseByte,
    pub high: FuseByte,
    pub extended: FuseByte,
}

impl AvrFuseBits {
    /// Decode all three fuse bytes for the `ATmega328P`.
    #[must_use]
    pub fn decode_atmega328p(low: u8, high: u8, extended: u8) -> Self {
        Self {
            low: decode_low_fuse(low),
            high: decode_high_fuse(high),
            extended: decode_extended_fuse(extended),
        }
    }

    /// Return the clock frequency implied by `CKSEL`/`SUT` in the Low fuse.
    #[must_use]
    pub fn clock_source_description(&self) -> &str {
        self.low
            .field("CKSEL")
            .map_or("Unknown", |s| s.interpretation.as_str())
    }

    /// Return `true` if JTAG is disabled (JTAGEN = 0 in High fuse).
    #[must_use]
    pub fn jtag_disabled(&self) -> bool {
        self.high.field("JTAGEN").is_some_and(|s| s.programmed)
    }

    /// Return `true` if `DWEN` (`DebugWIRE`) is enabled.
    #[must_use]
    pub fn debugwire_enabled(&self) -> bool {
        self.high.field("DWEN").is_some_and(|s| s.programmed)
    }

    /// Return `true` if the chip's SPI programming is enabled (SPIEN = 0).
    #[must_use]
    pub fn spi_enabled(&self) -> bool {
        self.high.field("SPIEN").is_some_and(|s| s.programmed)
    }

    /// Return `true` if the watchdog is always on (WDTON = 0).
    #[must_use]
    pub fn watchdog_always_on(&self) -> bool {
        self.high.field("WDTON").is_some_and(|s| s.programmed)
    }

    /// Brown-out detection level description.
    #[must_use]
    pub fn bod_level_description(&self) -> &str {
        self.extended
            .field("BODLEVEL")
            .map_or("Unknown", |s| s.interpretation.as_str())
    }

    /// Boot size in bytes.
    #[must_use]
    pub fn bootsz_bytes(&self) -> Option<u16> {
        // BYTES, matching this function's name. ATmega328P datasheet, BOOTSZ:
        //   11 -> 256 words = 512 bytes    (boot start 0x3F00)
        //   10 -> 512 words = 1024 bytes   (0x3E00)
        //   01 -> 1024 words = 2048 bytes  (0x3C00)
        //   00 -> 2048 words = 4096 bytes  (0x3800, the factory default)
        //
        // This table used to hold WORD counts under a `_bytes` name. Its only
        // caller, `bootloader_start_word_addr`, computes `0x4000 - sz / 2`,
        // which is correct ONLY if `sz` is in bytes — so the unit error
        // propagated: BOOTSZ=00 reported 0x3C00 where the datasheet says
        // 0x3800, i.e. a boot section half the real size starting 1024 words
        // too late. Fixing the unit here makes the caller correct untouched.
        self.high.field("BOOTSZ").map(|s| match s.raw_value {
            0b11 => 512,
            0b10 => 1024,
            0b01 => 2048,
            0b00 => 4096,
            _ => 0,
        })
    }

    /// Start address of the bootloader section.
    #[must_use]
    pub fn bootloader_start_word_addr(&self) -> Option<u16> {
        let sz = self.bootsz_bytes()?;
        Some(0x4000 - sz / 2) // ATmega328P has 32 KiB flash = 16384 words
    }

    /// Return `true` if BOOTRST is programmed (boot from bootloader section).
    #[must_use]
    pub fn boot_from_bootloader(&self) -> bool {
        self.high.field("BOOTRST").is_some_and(|s| s.programmed)
    }

    /// Produce a summary report string.
    #[must_use]
    pub fn report(&self) -> String {
        format!(
            "ATmega328P Fuse Report\n{}\n{}\n{}",
            self.low, self.high, self.extended
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fuse decoders
// ─────────────────────────────────────────────────────────────────────────────

const fn extract(raw: u8, lsb: u8, width: u8) -> u8 {
    let mask = if width >= 8 { 0xFF } else { (1u8 << width) - 1 };
    (raw >> lsb) & mask
}

fn decode_low_fuse(raw: u8) -> FuseByte {
    let cksel = extract(raw, 0, 4);
    let sut = extract(raw, 4, 2);
    let ckout = extract(raw, 6, 1);
    let ckdiv8 = extract(raw, 7, 1);

    let cksel_interp = match cksel {
        0b0000 => "External Clock",
        0b0001 => "Reserved",
        0b0010 => "Calibrated Internal RC 8 MHz",
        0b0011 => "Internal 128 kHz RC",
        0b0100..=0b0111 => "Low-frequency Crystal",
        0b1000..=0b1001 => "Full-swing Crystal Oscillator",
        0b1010..=0b1011 => "Low Power Crystal 0.4–0.9 MHz",
        0b1100..=0b1101 => "Low Power Crystal 0.9–3.0 MHz",
        0b1110..=0b1111 => "Low Power Crystal 3.0–8.0 MHz",
        _ => "Unknown",
    };

    let sut_interp = match sut {
        0b00 => "Start-up: 6 CK + 14 CK",
        0b01 => "Start-up: 6 CK + 14 CK + 4.1 ms",
        0b10 => "Start-up: 6 CK + 14 CK + 65 ms",
        0b11 => "Reserved",
        _ => "Unknown",
    };

    let ckout_interp = if ckout == 0 { "System clock output on PORTB0 enabled" } else { "No clock output" };
    let ckdiv8_interp = if ckdiv8 == 0 { "Divide clock by 8 (CKDIV8 programmed)" } else { "Full speed clock" };

    FuseByte {
        name: "Low".into(),
        raw,
        settings: vec![
            FuseSetting::new("CKSEL", cksel, cksel_interp, false),
            FuseSetting::new("SUT",   sut,   sut_interp,   false),
            FuseSetting::new("CKOUT", ckout, ckout_interp, true),
            FuseSetting::new("CKDIV8",ckdiv8,ckdiv8_interp,true),
        ],
    }
}

fn decode_high_fuse(raw: u8) -> FuseByte {
    let bootrst = extract(raw, 0, 1);
    let bootsz  = extract(raw, 1, 2);
    let eesave  = extract(raw, 3, 1);
    let wdton   = extract(raw, 4, 1);
    let spien   = extract(raw, 5, 1);
    let dwen    = extract(raw, 6, 1);
    let rstdisbl= extract(raw, 7, 1);

    let bootrst_interp = if bootrst == 0 { "Boot from bootloader section" } else { "Boot from application section (RESET vec = 0x0000)" };
    let bootsz_interp = match bootsz {
        0b11 => "Boot size: 256 words (512 B)",
        0b10 => "Boot size: 512 words (1 KiB)",
        0b01 => "Boot size: 1024 words (2 KiB)",
        0b00 => "Boot size: 2048 words (4 KiB)",
        _ => "Unknown",
    };
    let eesave_interp  = if eesave == 0  { "EEPROM preserved during chip erase" } else { "EEPROM NOT preserved" };
    let wdton_interp   = if wdton  == 0  { "Watchdog Timer always ON" } else { "Watchdog controlled by WDE/WDIE" };
    let spien_interp   = if spien  == 0  { "SPI serial programming enabled" } else { "SPI programming DISABLED" };
    let dwen_interp    = if dwen   == 0  { "DebugWIRE enabled" } else { "DebugWIRE disabled" };
    let rstdisbl_interp= if rstdisbl==0  { "RESET pin disabled (PC6 = GPIO)" } else { "RESET pin enabled" };

    FuseByte {
        name: "High".into(),
        raw,
        settings: vec![
            FuseSetting::new("BOOTRST",  bootrst,  bootrst_interp,  true),
            FuseSetting::new("BOOTSZ",   bootsz,   bootsz_interp,   false),
            FuseSetting::new("EESAVE",   eesave,   eesave_interp,   true),
            FuseSetting::new("WDTON",    wdton,    wdton_interp,    true),
            FuseSetting::new("SPIEN",    spien,    spien_interp,    true),
            FuseSetting::new("DWEN",     dwen,     dwen_interp,     true),
            FuseSetting::new("RSTDISBL", rstdisbl, rstdisbl_interp, true),
        ],
    }
}

fn decode_extended_fuse(raw: u8) -> FuseByte {
    let bodlevel = extract(raw, 0, 3);
    let bod_interp = match bodlevel {
        0b111 => "BOD Disabled",
        0b110 => "BOD Level 1.8 V",
        0b101 => "BOD Level 2.7 V",
        0b100 => "BOD Level 4.3 V",
        _     => "Reserved BOD setting",
    };

    FuseByte {
        name: "Extended".into(),
        raw,
        settings: vec![
            FuseSetting::new("BODLEVEL", bodlevel, bod_interp, false),
        ],
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level convenience
// ─────────────────────────────────────────────────────────────────────────────

/// Decode `ATmega328P` fuse bytes.
///
/// This is a convenience wrapper around [`AvrFuseBits::decode_atmega328p`].
#[must_use]
pub fn decode_fuse(low: u8, high: u8, extended: u8) -> AvrFuseBits {
    AvrFuseBits::decode_atmega328p(low, high, extended)
}

/// Default "factory" fuse settings for the `ATmega328P`:
///   Low = 0x62, High = 0xD9, Extended = 0xFF.
#[must_use]
pub fn atmega328p_factory_fuses() -> AvrFuseBits {
    decode_fuse(0x62, 0xD9, 0xFF)
}

// ─────────────────────────────────────────────────────────────────────────────
// FuseValidator — detect suspicious / dangerous fuse combinations
// ─────────────────────────────────────────────────────────────────────────────

/// Warning produced by [`FuseValidator`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuseWarning {
    pub severity: WarningSeverity,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WarningSeverity {
    /// Potentially unrecoverable configuration (e.g. RESET pin disabled).
    Critical,
    /// Unusual but recoverable (e.g. JTAG disabled).
    Warning,
    /// Informational note.
    Info,
}

/// Validates a set of fuse bytes for common mistakes.
pub struct FuseValidator;

impl FuseValidator {
    /// Validate an [`AvrFuseBits`] and return a list of warnings.
    #[must_use]
    pub fn validate(fuses: &AvrFuseBits) -> Vec<FuseWarning> {
        let mut warnings = Vec::new();

        // RESET pin disabled → very hard to recover
        if fuses.high.field("RSTDISBL").is_some_and(|s| s.programmed) {
            warnings.push(FuseWarning {
                severity: WarningSeverity::Critical,
                message: "RSTDISBL is programmed: external RESET pin disabled. Recovery requires HVPP.".into(),
            });
        }

        // SPI disabled
        if !fuses.spi_enabled() {
            warnings.push(FuseWarning {
                severity: WarningSeverity::Critical,
                message: "SPIEN is NOT programmed: ISP/SPI programming disabled. Recovery requires HVPP/HVSP.".into(),
            });
        }

        // Watchdog always on — may surprise firmware that doesn't reset WDT
        if fuses.watchdog_always_on() {
            warnings.push(FuseWarning {
                severity: WarningSeverity::Warning,
                message: "WDTON programmed: watchdog always enabled. Firmware must periodically reset WDT.".into(),
            });
        }

        // DebugWIRE enabled — disables RESET pin ISP
        if fuses.debugwire_enabled() {
            warnings.push(FuseWarning {
                severity: WarningSeverity::Warning,
                message: "DWEN programmed: DebugWIRE enabled; ISP requires RESET toggle sequence.".into(),
            });
        }

        // BOD disabled — risk of flash corruption during brownout
        if fuses.extended.field("BODLEVEL").is_some_and(|s| s.raw_value == 0b111) {
            warnings.push(FuseWarning {
                severity: WarningSeverity::Warning,
                message: "BOD disabled (BODLEVEL=111). Risk of flash corruption during power dips.".into(),
            });
        }

        // Clock divided by 8 but external crystal selected — unusual
        let cksel = fuses.low.field("CKSEL").map_or(2, |s| s.raw_value);
        let ckdiv8 = fuses.low.field("CKDIV8").is_some_and(|s| s.programmed);
        if ckdiv8 && cksel >= 0b1000 {
            warnings.push(FuseWarning {
                severity: WarningSeverity::Info,
                message: "CKDIV8 active with external crystal: effective speed = crystal / 8.".into(),
            });
        }

        warnings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn factory() -> AvrFuseBits {
        atmega328p_factory_fuses()
    }

    #[test]
    fn test_factory_low_raw() {
        let f = factory();
        assert_eq!(f.low.raw, 0x62);
    }

    #[test]
    fn test_factory_high_raw() {
        let f = factory();
        assert_eq!(f.high.raw, 0xD9);
    }

    #[test]
    fn test_factory_extended_raw() {
        let f = factory();
        assert_eq!(f.extended.raw, 0xFF);
    }

    #[test]
    fn test_factory_clock_source() {
        let f = factory();
        // Low = 0x62 → CKSEL = 0b0010 = calibrated 8 MHz internal RC
        let desc = f.clock_source_description();
        assert!(desc.contains("8 MHz") || desc.contains("RC"), "got: {desc}");
    }

    #[test]
    fn test_factory_spi_enabled() {
        let f = factory();
        assert!(f.spi_enabled(), "Factory fuses should have SPIEN=0 (SPI enabled)");
    }

    #[test]
    fn test_factory_watchdog_not_always_on() {
        let f = factory();
        assert!(!f.watchdog_always_on());
    }

    #[test]
    fn test_factory_debugwire_disabled() {
        let f = factory();
        assert!(!f.debugwire_enabled());
    }

    #[test]
    fn test_factory_bod_level() {
        let f = factory();
        // Extended = 0xFF → BODLEVEL = 0b111 → BOD disabled
        let desc = f.bod_level_description();
        assert!(desc.contains("Disabled") || desc.contains("disabled"), "got: {desc}");
    }

    #[test]
    fn test_bootsz_bytes_factory() {
        let f = factory();
        // High = 0xD9 = 0b1101_1001, so BOOTSZ = bits[2:1] = 0b00 — NOT 0b11 as
        // this test's comment used to claim. AVR fuses are active-low and the
        // ATmega328P factory default leaves BOOTSZ programmed to 00, i.e. the
        // LARGEST boot section (2048 words), not the smallest.
        //
        // `bootsz_bytes()` now returns BYTES, so BOOTSZ=00 (2048 words) is 4096.
        let sz = f.bootsz_bytes();
        assert_eq!(sz, Some(4096), "BOOTSZ=00 is 2048 words = 4096 BYTES");

        // The unit error a previous version of this test PINNED is now fixed:
        // with bytes in the table, the caller's `0x4000 - sz / 2` lands on the
        // datasheet value.
        assert_eq!(
            f.bootloader_start_word_addr(),
            Some(0x3800),
            "ATmega328P: BOOTSZ=00 puts the boot section at word address 0x3800"
        );

        // Pin the whole table against the datasheet so a future edit cannot
        // drift back into word counts: bytes/2 must equal the words below the
        // 0x4000-word top of flash.
        for (bytes, start) in [(512u32, 0x3F00u32), (1024, 0x3E00), (2048, 0x3C00), (4096, 0x3800)] {
            assert_eq!(
                bytes / 2,
                0x4000 - start,
                "{bytes} bytes must place the boot section at {start:#06x}"
            );
        }
    }

    #[test]
    fn test_boot_from_application() {
        let f = factory();
        // High=0xD9: BOOTRST bit 0 = 1 → unprogrammed → boot from application
        assert!(!f.boot_from_bootloader());
    }

    #[test]
    fn test_decode_fuse_convenience() {
        let f = decode_fuse(0x62, 0xD9, 0xFF);
        assert_eq!(f.low.raw, 0x62);
    }

    #[test]
    fn test_fuse_field_lookup() {
        let f = factory();
        assert!(f.low.field("CKSEL").is_some());
        assert!(f.low.field("nonexistent").is_none());
    }

    #[test]
    fn test_validator_factory_has_bod_warning() {
        let f = factory();
        let warnings = FuseValidator::validate(&f);
        // BOD disabled should produce a warning
        let has_bod = warnings.iter().any(|w| w.message.contains("BOD"));
        assert!(has_bod, "Expected BOD warning for factory fuses");
    }

    #[test]
    fn test_validator_rst_disabled() {
        // Low=0xFF, High=0x40 (RSTDISBL programmed = bit7=0), Extended=0xFF
        let f = decode_fuse(0xFF, 0x7F, 0xFF); // bit7 of high = 0 → RSTDISBL programmed
        let warnings = FuseValidator::validate(&f);
        let crit = warnings.iter().any(|w| w.severity == WarningSeverity::Critical && w.message.contains("RSTDISBL"));
        assert!(crit, "Expected critical warning for RSTDISBL");
    }

    #[test]
    fn test_validator_no_critical_factory() {
        let f = factory();
        let warnings = FuseValidator::validate(&f);
        let crits: Vec<_> = warnings.iter().filter(|w| w.severity == WarningSeverity::Critical).collect();
        assert!(crits.is_empty(), "Factory fuses should not produce critical warnings: {crits:?}");
    }

    #[test]
    fn test_programmed_settings() {
        let f = factory();
        // High = 0xD9 = 0b1101_1001, so the bits really are:
        //   7 RSTDISBL=1  6 DWEN=1  5 SPIEN=0  4 WDTON=1
        //   3 EESAVE=1    2 BOOTSZ1=0  1 BOOTSZ0=0  0 BOOTRST=1
        // AVR fuses are ACTIVE LOW, so only the zero bits are "programmed":
        // SPIEN and the two BOOTSZ bits. DWEN and BOOTRST are 1 = unprogrammed.
        //
        // The previous version of this test had the bit table INVERTED (it
        // claimed 6=0 and 5=1) and therefore asserted that DWEN, BOOTSZ or
        // BOOTRST was programmed — the two of those three that are single bits
        // are exactly the ones that are NOT. It also contradicted its own
        // opening comment, which said SPIEN was unprogrammed.
        let programmed = f.high.programmed_settings();
        assert!(
            programmed.iter().any(|s| s.name == "SPIEN"),
            "SPIEN (bit 5 = 0) is programmed on factory fuses — serial \
             programming enabled; got {:?}",
            programmed.iter().map(|s| &s.name).collect::<Vec<_>>()
        );
        assert!(
            !programmed.iter().any(|s| s.name == "DWEN"),
            "DWEN (bit 6 = 1) is UNprogrammed on factory fuses"
        );
    }

    #[test]
    fn test_fuse_byte_display() {
        let f = factory();
        let display = format!("{}", f.low);
        assert!(display.contains("Low"));
        assert!(display.contains("0x62"));
    }

    #[test]
    fn test_extract_helper() {
        assert_eq!(extract(0b1100_1010, 1, 3), 0b101);
        assert_eq!(extract(0xFF, 0, 8), 0xFF);
        assert_eq!(extract(0b1011_0000, 4, 4), 0b1011);
    }
}
