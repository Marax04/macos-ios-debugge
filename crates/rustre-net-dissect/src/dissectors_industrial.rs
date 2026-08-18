//! Industrial / ICS / `IoT` protocol dissectors.
//!
//! Covers:
//! - Modbus TCP — all standard function codes
//! - DNP3 — Application Layer PDU and Data Link Layer
//! - `BACnet` — BVLC / NPDU / APDU (confirmed + unconfirmed services)
//! - IEC 60870-5-104 — APDU I/S/U frames and ASDU
//! - PROFINET — RT frames, DCP, LLDP
//! - EtherNet/IP — CIP encapsulation


use serde::{Deserialize, Serialize};
use crate::DissectError;

// ─────────────────────────────────────────────────────────────────────────────
// Modbus TCP
// ─────────────────────────────────────────────────────────────────────────────

/// Modbus function codes (standard).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ModbusFc {
    ReadCoils                = 0x01,
    ReadDiscreteInputs       = 0x02,
    ReadHoldingRegisters     = 0x03,
    ReadInputRegisters       = 0x04,
    WriteSingleCoil          = 0x05,
    WriteSingleRegister      = 0x06,
    WriteMultipleCoils       = 0x0f,
    WriteMultipleRegisters   = 0x10,
    ReadWriteMultipleRegisters = 0x17,
    MaskWriteRegister        = 0x16,
    ReadFileRecord           = 0x14,
    WriteFileRecord          = 0x15,
    ReadExceptionStatus      = 0x07,
    Diagnostics              = 0x08,
    GetCommEventCounter      = 0x0b,
    GetCommEventLog          = 0x0c,
    ReportServerId           = 0x11,
    /// 0x2b — MEI Transport (covers both Read Device Identification sub-fn 0x0e
    /// and Encapsulated Interface Transport sub-fn 0x0d). Sub-function dispatch
    /// must be done by the caller after inspecting the next byte.
    MeiTransport             = 0x2b,
    Unknown(u8),
}

impl ModbusFc {
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0x01 => Self::ReadCoils,
            0x02 => Self::ReadDiscreteInputs,
            0x03 => Self::ReadHoldingRegisters,
            0x04 => Self::ReadInputRegisters,
            0x05 => Self::WriteSingleCoil,
            0x06 => Self::WriteSingleRegister,
            0x0f => Self::WriteMultipleCoils,
            0x10 => Self::WriteMultipleRegisters,
            0x17 => Self::ReadWriteMultipleRegisters,
            0x16 => Self::MaskWriteRegister,
            0x14 => Self::ReadFileRecord,
            0x15 => Self::WriteFileRecord,
            0x07 => Self::ReadExceptionStatus,
            0x08 => Self::Diagnostics,
            0x0b => Self::GetCommEventCounter,
            0x0c => Self::GetCommEventLog,
            0x11 => Self::ReportServerId,
            0x2b => Self::MeiTransport,
            other => Self::Unknown(other),
        }
    }
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ReadCoils                    => "Read Coils",
            Self::ReadDiscreteInputs           => "Read Discrete Inputs",
            Self::ReadHoldingRegisters         => "Read Holding Registers",
            Self::ReadInputRegisters           => "Read Input Registers",
            Self::WriteSingleCoil              => "Write Single Coil",
            Self::WriteSingleRegister          => "Write Single Register",
            Self::WriteMultipleCoils           => "Write Multiple Coils",
            Self::WriteMultipleRegisters       => "Write Multiple Registers",
            Self::ReadWriteMultipleRegisters   => "Read/Write Multiple Registers",
            Self::MaskWriteRegister            => "Mask Write Register",
            Self::ReadFileRecord               => "Read File Record",
            Self::WriteFileRecord              => "Write File Record",
            Self::ReadExceptionStatus          => "Read Exception Status",
            Self::Diagnostics                  => "Diagnostics",
            Self::GetCommEventCounter          => "Get Comm Event Counter",
            Self::GetCommEventLog              => "Get Comm Event Log",
            Self::ReportServerId               => "Report Server Id",
            Self::MeiTransport                 => "MEI Transport (0x2b)",
            Self::Unknown(_)                   => "Unknown",
        }
    }
    #[must_use]
    pub const fn is_error(self, raw: u8) -> bool { raw & 0x80 != 0 }
}

/// Modbus TCP Application Data Unit (MBAP + PDU).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModbusTcpAdu {
    pub transaction_id: u16,
    pub protocol_id:    u16, // always 0
    pub length:         u16,
    pub unit_id:        u8,
    pub function_code:  ModbusFc,
    pub is_exception:   bool,
    pub exception_code: Option<u8>,
    pub data:           Vec<u8>,
}

pub struct ModbusDissector;

impl ModbusDissector {
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn decode(buf: &[u8]) -> Result<(ModbusTcpAdu, usize), DissectError> {
        if buf.len() < 8 {
            return Err(DissectError::BufferTooShort { needed: 8, got: buf.len() });
        }
        let tid  = u16::from_be_bytes([buf[0], buf[1]]);
        let pid  = u16::from_be_bytes([buf[2], buf[3]]);
        let len  = u16::from_be_bytes([buf[4], buf[5]]);
        let uid  = buf[6];
        let fc_raw = buf[7];
        let is_exc = fc_raw & 0x80 != 0;
        let fc   = ModbusFc::from_byte(fc_raw & 0x7f);
        let total = 6 + len as usize;
        // MBAP Length counts the unit id plus the PDU, so it is at least 2 (unit
        // id + function code) and `total` at least 8 — the offset the PDU data is
        // sliced from below. A smaller declared length is expressible on the wire
        // and would make that slice start after it ends, which panics.
        if total < 8 {
            return Err(DissectError::BufferTooShort { needed: 8, got: total });
        }
        if buf.len() < total {
            return Err(DissectError::BufferTooShort { needed: total, got: buf.len() });
        }
        let (exc_code, data) = if is_exc && buf.len() > 8 && total >= 9 {
            (Some(buf[8]), buf[9..total].to_vec())
        } else {
            (None, buf[8..total].to_vec())
        };
        Ok((ModbusTcpAdu { transaction_id: tid, protocol_id: pid, length: len, unit_id: uid, function_code: fc, is_exception: is_exc, exception_code: exc_code, data }, total))
    }

    /// Parse register values from a Read Holding/Input Registers response.
    #[must_use]
    pub fn parse_register_response(data: &[u8]) -> Vec<u16> {
        if data.is_empty() { return Vec::new(); }
        let byte_count = data[0] as usize;
        let payload = &data[1..];
        if payload.len() < byte_count { return Vec::new(); }
        payload[..byte_count].chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect()
    }

    /// Parse coil/discrete input values from response byte.
    #[must_use]
    pub fn parse_coil_response(data: &[u8], count: u16) -> Vec<bool> {
        if data.is_empty() { return Vec::new(); }
        let mut out = Vec::new();
        for &byte in data.iter().skip(1) {
            for bit in 0..8 {
                if out.len() < count as usize {
                    out.push(byte & (1 << bit) != 0);
                }
            }
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DNP3
// ─────────────────────────────────────────────────────────────────────────────

/// DNP3 Application Layer Function Codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Dnp3AppFc {
    Confirm             = 0x00,
    Read                = 0x01,
    Write               = 0x02,
    Select              = 0x03,
    Operate             = 0x04,
    DirectOperate       = 0x05,
    DirectOperateNoAck  = 0x06,
    ImmediateFreeze     = 0x07,
    ImmediateFreezeNoAck = 0x08,
    FreezeClear         = 0x09,
    FreezeClearNoAck    = 0x0a,
    FreezeAtTime        = 0x0b,
    FreezeAtTimeNoAck   = 0x0c,
    ColdRestart         = 0x0d,
    WarmRestart         = 0x0e,
    InitializeData      = 0x0f,
    InitializeAppl      = 0x10,
    StartAppl           = 0x11,
    StopAppl            = 0x12,
    SaveConfig          = 0x13,
    EnableSpontaneous   = 0x14,
    DisableSpontaneous  = 0x15,
    AssignClass         = 0x16,
    DelayMeasure        = 0x17,
    RecordCurrentTime   = 0x18,
    OpenFile            = 0x19,
    CloseFile           = 0x1a,
    DeleteFile          = 0x1b,
    GetFileInfo         = 0x1c,
    AuthenticateFile    = 0x1d,
    AbortFile           = 0x1e,
    Response            = 0x81,
    UnsolicitedResponse = 0x82,
    Unknown(u8),
}

impl Dnp3AppFc {
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::Confirm,
            0x01 => Self::Read,
            0x02 => Self::Write,
            0x03 => Self::Select,
            0x04 => Self::Operate,
            0x05 => Self::DirectOperate,
            0x06 => Self::DirectOperateNoAck,
            0x07 => Self::ImmediateFreeze,
            0x08 => Self::ImmediateFreezeNoAck,
            0x09 => Self::FreezeClear,
            0x0a => Self::FreezeClearNoAck,
            0x0b => Self::FreezeAtTime,
            0x0c => Self::FreezeAtTimeNoAck,
            0x0d => Self::ColdRestart,
            0x0e => Self::WarmRestart,
            0x14 => Self::EnableSpontaneous,
            0x15 => Self::DisableSpontaneous,
            0x81 => Self::Response,
            0x82 => Self::UnsolicitedResponse,
            other => Self::Unknown(other),
        }
    }
}

/// DNP3 Data Link Layer frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dnp3DataLinkFrame {
    pub start:       u16, // always 0x0564
    pub length:      u8,
    pub control:     u8,
    pub destination: u16,
    pub source:      u16,
    pub crc_ok:      bool,
    pub payload:     Vec<u8>,
}

/// Packed application-layer control bits (FIN/FIR/CON/UNS).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dnp3AppBits(u8);

impl Dnp3AppBits {
    const fn new(ac: u8) -> Self { Self(ac) }
    /// Final frame bit.
    #[must_use] pub const fn fin(self) -> bool { self.0 & 0x80 != 0 }
    /// First frame bit.
    #[must_use] pub const fn fir(self) -> bool { self.0 & 0x40 != 0 }
    /// Confirmation requested.
    #[must_use] pub const fn con(self) -> bool { self.0 & 0x20 != 0 }
    /// Unsolicited response.
    #[must_use] pub const fn uns(self) -> bool { self.0 & 0x10 != 0 }
}

/// DNP3 Application Layer header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dnp3AppHeader {
    pub application_control: u8,
    pub function_code:       Dnp3AppFc,
    pub seq:                 u8,
    /// Packed FIN/FIR/CON/UNS bits.
    pub bits:                Dnp3AppBits,
}

pub struct Dnp3Dissector;

impl Dnp3Dissector {
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn decode_data_link(buf: &[u8]) -> Result<(Dnp3DataLinkFrame, usize), DissectError> {
        if buf.len() < 10 {
            return Err(DissectError::BufferTooShort { needed: 10, got: buf.len() });
        }
        let start = u16::from_le_bytes([buf[0], buf[1]]);
        if start != 0x0564 {
            return Err(DissectError::InvalidMagic(format!("DNP3 start: 0x{start:04x}")));
        }
        let length = buf[2];
        let control = buf[3];
        let dest = u16::from_le_bytes([buf[4], buf[5]]);
        let src  = u16::from_le_bytes([buf[6], buf[7]]);
        // CRC covers bytes 0..8
        let _crc = u16::from_le_bytes([buf[8], buf[9]]);
        let total = 2 + length as usize;
        // The payload is sliced from offset 10 (start, length, control, dest, src,
        // CRC), so `total` must reach it: a Length field small enough to put the
        // frame end before the header end would panic instead of erroring.
        if total < 10 { return Err(DissectError::BufferTooShort { needed: 10, got: total }); }
        if buf.len() < total { return Err(DissectError::BufferTooShort { needed: total, got: buf.len() }); }
        Ok((Dnp3DataLinkFrame { start, length, control, destination: dest, source: src, crc_ok: true, payload: buf[10..total].to_vec() }, total))
    }

    /// # Errors
    /// Returns an error if the operation fails.
    pub fn decode_app_header(buf: &[u8]) -> Result<Dnp3AppHeader, DissectError> {
        if buf.len() < 2 {
            return Err(DissectError::BufferTooShort { needed: 2, got: buf.len() });
        }
        let ac = buf[0];
        let fc = Dnp3AppFc::from_byte(buf[1]);
        Ok(Dnp3AppHeader {
            application_control: ac,
            function_code: fc,
            seq: ac & 0x0f,
            bits: Dnp3AppBits::new(ac),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BACnet
// ─────────────────────────────────────────────────────────────────────────────

/// `BACnet` Virtual Link Control message types (BVLC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum BvlcFunction {
    Result                      = 0x00,
    WriteBroadcastDistTable     = 0x01,
    ReadBroadcastDistTable      = 0x02,
    ReadBroadcastDistTableAck   = 0x03,
    ForwardedNpdu               = 0x04,
    RegisterForeignDevice       = 0x05,
    ReadForeignDeviceTable      = 0x06,
    ReadForeignDeviceTableAck   = 0x07,
    DeleteForeignDeviceEntry    = 0x08,
    DistributeBroadcastToNetwork = 0x09,
    OriginalUnicastNpdu         = 0x0a,
    OriginalBroadcastNpdu       = 0x0b,
    SecureBvll                  = 0x0c,
    Unknown(u8),
}

impl BvlcFunction {
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::Result,
            0x04 => Self::ForwardedNpdu,
            0x05 => Self::RegisterForeignDevice,
            0x0a => Self::OriginalUnicastNpdu,
            0x0b => Self::OriginalBroadcastNpdu,
            other => Self::Unknown(other),
        }
    }
}

/// `BACnet` NPDU.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BacnetNpdu {
    pub version:          u8,
    pub control:          u8,
    pub dest_net:         Option<u16>,
    pub dest_addr:        Option<Vec<u8>>,
    pub src_net:          Option<u16>,
    pub src_addr:         Option<Vec<u8>>,
    pub hop_count:        Option<u8>,
    pub apdu_data:        Vec<u8>,
}

/// `BACnet` APDU types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BacnetApduType {
    ConfirmedReq   = 0,
    UnconfirmedReq = 1,
    SimpleAck      = 2,
    ComplexAck     = 3,
    SegmentAck     = 4,
    Error          = 5,
    Reject         = 6,
    Abort          = 7,
    Unknown(u8),
}

impl BacnetApduType {
    #[must_use]
    pub const fn from_nibble(v: u8) -> Self {
        match v >> 4 {
            0 => Self::ConfirmedReq,
            1 => Self::UnconfirmedReq,
            2 => Self::SimpleAck,
            3 => Self::ComplexAck,
            4 => Self::SegmentAck,
            5 => Self::Error,
            6 => Self::Reject,
            7 => Self::Abort,
            o => Self::Unknown(o),
        }
    }
}

/// `BACnet` unconfirmed service choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BacnetUnconfirmedService {
    IAm              = 0,
    IHave            = 1,
    CovNotification  = 2,
    EventNotification = 3,
    PrivateTransfer  = 4,
    TextMessage      = 5,
    TimeSynchronization = 6,
    WhoHas           = 7,
    WhoIs            = 8,
    UtcTimeSynchronization = 9,
    WriteGroup       = 10,
    Unknown(u8),
}

impl BacnetUnconfirmedService {
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0  => Self::IAm,
            1  => Self::IHave,
            2  => Self::CovNotification,
            3  => Self::EventNotification,
            7  => Self::WhoHas,
            8  => Self::WhoIs,
            other => Self::Unknown(other),
        }
    }
}

pub struct BacnetDissector;

impl BacnetDissector {
    /// Decode BVLC header (4 bytes).
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn decode_bvlc(buf: &[u8]) -> Result<(BvlcFunction, u16, &[u8]), DissectError> {
        if buf.len() < 4 {
            return Err(DissectError::BufferTooShort { needed: 4, got: buf.len() });
        }
        if buf[0] != 0x81 {
            return Err(DissectError::InvalidMagic(format!("BACnet BVLC type: 0x{:02x}", buf[0])));
        }
        let func = BvlcFunction::from_byte(buf[1]);
        let len  = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        // The BVLC Length field counts the WHOLE BVLL message, header included
        // (ASHRAE 135 Annex J), so the payload is `buf[4..len]` — but a declared
        // length below the 4-byte header is expressible on the wire and would make
        // that slice start after it ends, which panics rather than erroring.
        if len < 4 { return Err(DissectError::BufferTooShort { needed: 4, got: len }); }
        if buf.len() < len { return Err(DissectError::BufferTooShort { needed: len, got: buf.len() }); }
        Ok((func, u16::try_from(len).unwrap_or(u16::MAX), &buf[4..len]))
    }

    /// Decode NPDU from payload slice.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn decode_npdu(buf: &[u8]) -> Result<BacnetNpdu, DissectError> {
        if buf.len() < 2 { return Err(DissectError::BufferTooShort { needed: 2, got: buf.len() }); }
        let version = buf[0];
        let control = buf[1];
        let mut pos = 2usize;
        let dest_net = if control & 0x20 != 0 {
            if buf.len() < pos + 3 { return Err(DissectError::BufferTooShort { needed: pos + 3, got: buf.len() }); }
            let net = u16::from_be_bytes([buf[pos], buf[pos+1]]); pos += 2;
            let alen = buf[pos] as usize; pos += 1;
            pos += alen;
            Some(net)
        } else { None };
        let src_net = if control & 0x08 != 0 {
            if buf.len() < pos + 3 { return Err(DissectError::BufferTooShort { needed: pos + 3, got: buf.len() }); }
            let net = u16::from_be_bytes([buf[pos], buf[pos+1]]); pos += 2;
            let alen = buf[pos] as usize; pos += 1;
            pos += alen;
            Some(net)
        } else { None };
        let hop_count = if control & 0x20 != 0 {
            let h = buf.get(pos).copied(); pos += 1; h
        } else { None };
        Ok(BacnetNpdu { version, control, dest_net, dest_addr: None, src_net, src_addr: None, hop_count, apdu_data: buf[pos..].to_vec() })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IEC 60870-5-104
// ─────────────────────────────────────────────────────────────────────────────

/// IEC 104 APDU format type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Iec104ApduFormat {
    I, // Information transfer
    S, // Supervisory
    U, // Unnumbered
}

/// IEC 104 U-frame types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Iec104Utype {
    Startdt,
    StartdtAct,
    StartdtCon,
    Stopdt,
    StopdtAct,
    StopdtCon,
    Testfr,
    TestfrAct,
    TestfrCon,
    Unknown(u8),
}

impl Iec104Utype {
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b >> 2 {
            1  => Self::StartdtAct,
            2  => Self::StartdtCon,
            4  => Self::StopdtAct,
            8  => Self::StopdtCon,
            16 => Self::TestfrAct,
            32 => Self::TestfrCon,
            other => Self::Unknown(other),
        }
    }
}

/// IEC 104 APDU header (6 bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iec104Apdu {
    pub apci_start:  u8,   // always 0x68
    pub apdu_length: u8,
    pub ctrl1:       u8,
    pub ctrl2:       u8,
    pub ctrl3:       u8,
    pub ctrl4:       u8,
    pub format:      Iec104ApduFormat,
    pub send_seq:    Option<u16>,
    pub recv_seq:    Option<u16>,
    pub utype:       Option<Iec104Utype>,
    pub asdu:        Vec<u8>,
}

/// IEC 104 Type Identification (TI) codes for ASDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Iec104Ti(pub u8);

impl Iec104Ti {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self.0 {
            1  => "M_SP_NA_1",  // Single-point information
            3  => "M_DP_NA_1",  // Double-point information
            5  => "M_ST_NA_1",  // Step position information
            7  => "M_BO_NA_1",  // Bitstring of 32 bit
            9  => "M_ME_NA_1",  // Measured value, normalised value
            11 => "M_ME_NB_1",  // Measured value, scaled value
            13 => "M_ME_NC_1",  // Measured value, short floating point
            15 => "M_IT_NA_1",  // Integrated totals
            30 => "M_SP_TB_1",  // Single-point with time tag CP56Time2a
            31 => "M_DP_TB_1",  // Double-point with time tag CP56Time2a
            34 => "M_ME_TD_1",  // Measured value normalised with time tag
            36 => "M_ME_TF_1",  // Measured value float with time tag
            45 => "C_SC_NA_1",  // Single command
            46 => "C_DC_NA_1",  // Double command
            50 => "C_SE_NA_1",  // Set-point command, normalised
            58 => "C_SC_TA_1",  // Single command with time tag
            70 => "M_EI_NA_1",  // End of initialisation
            100 => "C_IC_NA_1", // Interrogation command
            101 => "C_CI_NA_1", // Counter interrogation command
            103 => "C_CS_NA_1", // Clock synchronisation command
            _   => "UNKNOWN",
        }
    }
}

pub struct Iec104Dissector;

impl Iec104Dissector {
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn decode_apdu(buf: &[u8]) -> Result<(Iec104Apdu, usize), DissectError> {
        if buf.len() < 6 {
            return Err(DissectError::BufferTooShort { needed: 6, got: buf.len() });
        }
        if buf[0] != 0x68 {
            return Err(DissectError::InvalidMagic(format!("IEC104 APCI start: 0x{:02x}", buf[0])));
        }
        let apdu_len = buf[1] as usize;
        let total = 2 + apdu_len;
        // APDU length counts the four control octets, so it is never below 4 and
        // `total` never below 6 — the offset the ASDU is sliced from below.
        if total < 6 { return Err(DissectError::BufferTooShort { needed: 6, got: total }); }
        if buf.len() < total { return Err(DissectError::BufferTooShort { needed: total, got: buf.len() }); }
        let c1 = buf[2]; let c2 = buf[3]; let c3 = buf[4]; let c4 = buf[5];

        let (format, send_seq, recv_seq, utype) = if c1 & 0x01 == 0 {
            // I-frame
            let ssn = (((u16::from(c1)) | ((u16::from(c2)) << 8)) >> 1) & 0x7fff;
            let rsn = (((u16::from(c3)) | ((u16::from(c4)) << 8)) >> 1) & 0x7fff;
            (Iec104ApduFormat::I, Some(ssn), Some(rsn), None)
        } else if c1 & 0x03 == 0x01 {
            // S-frame
            let rsn = (((u16::from(c3)) | ((u16::from(c4)) << 8)) >> 1) & 0x7fff;
            (Iec104ApduFormat::S, None, Some(rsn), None)
        } else {
            // U-frame
            let ut = Iec104Utype::from_byte(c1);
            (Iec104ApduFormat::U, None, None, Some(ut))
        };

        let asdu = buf[6..total].to_vec();
        Ok((Iec104Apdu { apci_start: buf[0], apdu_length: buf[1], ctrl1: c1, ctrl2: c2, ctrl3: c3, ctrl4: c4, format, send_seq, recv_seq, utype, asdu }, total))
    }

    /// Decode ASDU type identification (first byte of ASDU).
    pub fn decode_asdu_ti(asdu: &[u8]) -> Option<Iec104Ti> {
        asdu.first().copied().map(Iec104Ti)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PROFINET
// ─────────────────────────────────────────────────────────────────────────────

/// PROFINET Ethertype.
pub const PROFINET_ETHERTYPE: u16 = 0x8892;

/// PROFINET frame IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProfinetFrameId(pub u16);

impl ProfinetFrameId {
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self.0 {
            0x0001..=0x001f => "RT_CLASS_3",
            0x0100..=0x07ff => "RT_CLASS_1",
            0x8000..=0xbfff => "RT_CLASS_UDP",
            0xc000..=0xfbff => "RT_CLASS_1_ISOCHRONOUS",
            0xfefc           => "PTCP_ANNOUNCE",
            0xfefe           => "PTCP_FOLLOW_UP",
            0xfeff           => "PTCP_DELAY_RESP",
            0xfc00..=0xfeff => "ALARMS",
            0xff00..=0xff01 => "DCP",
            0xff02..=0xff03 => "RPC",
            _                => "RESERVED",
        }
    }
}

/// PROFINET DCP service IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DcpServiceId {
    Get      = 3,
    Set      = 4,
    Identify = 5,
    Hello    = 6,
    Unknown(u8),
}

impl DcpServiceId {
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            3 => Self::Get,
            4 => Self::Set,
            5 => Self::Identify,
            6 => Self::Hello,
            o => Self::Unknown(o),
        }
    }
}

/// Decoded PROFINET RT frame header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfinetRtFrame {
    pub frame_id:       ProfinetFrameId,
    pub cycle_counter:  Option<u16>,
    pub data_status:    Option<u8>,
    pub transfer_status: Option<u8>,
    pub payload:        Vec<u8>,
}

pub struct ProfinetDissector;

impl ProfinetDissector {
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn decode_rt(buf: &[u8]) -> Result<ProfinetRtFrame, DissectError> {
        if buf.len() < 2 {
            return Err(DissectError::BufferTooShort { needed: 2, got: buf.len() });
        }
        let fid = ProfinetFrameId(u16::from_be_bytes([buf[0], buf[1]]));
        // RT frames >= 0x0100 have CycleCounter/DataStatus/TransferStatus at end
        let (payload, cc, ds, ts) = if buf.len() >= 6 {
            let n = buf.len();
            let ts = buf[n-1];
            let ds = buf[n-2];
            let cc = u16::from_be_bytes([buf[n-4], buf[n-3]]);
            (&buf[2..n-4], Some(cc), Some(ds), Some(ts))
        } else {
            (&buf[2..], None, None, None)
        };
        Ok(ProfinetRtFrame { frame_id: fid, cycle_counter: cc, data_status: ds, transfer_status: ts, payload: payload.to_vec() })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EtherNet/IP (CIP)
// ─────────────────────────────────────────────────────────────────────────────

/// EtherNet/IP encapsulation command codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum EnipCommand {
    Nop                 = 0x0000,
    ListServices        = 0x0004,
    ListIdentity        = 0x0063,
    ListInterfaces      = 0x0064,
    RegisterSession     = 0x0065,
    UnregisterSession   = 0x0066,
    SendRrData          = 0x006F,
    SendUnitData        = 0x0070,
    IndicateStatus      = 0x0072,
    Cancel              = 0x0073,
    Unknown(u16),
}

impl EnipCommand {
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            0x0000 => Self::Nop,
            0x0004 => Self::ListServices,
            0x0063 => Self::ListIdentity,
            0x0064 => Self::ListInterfaces,
            0x0065 => Self::RegisterSession,
            0x0066 => Self::UnregisterSession,
            0x006F => Self::SendRrData,
            0x0070 => Self::SendUnitData,
            0x0072 => Self::IndicateStatus,
            0x0073 => Self::Cancel,
            other  => Self::Unknown(other),
        }
    }
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Nop               => "NOP",
            Self::ListServices      => "ListServices",
            Self::ListIdentity      => "ListIdentity",
            Self::ListInterfaces    => "ListInterfaces",
            Self::RegisterSession   => "RegisterSession",
            Self::UnregisterSession => "UnregisterSession",
            Self::SendRrData        => "SendRRData",
            Self::SendUnitData      => "SendUnitData",
            Self::IndicateStatus    => "IndicateStatus",
            Self::Cancel            => "Cancel",
            Self::Unknown(_)        => "Unknown",
        }
    }
}

/// EtherNet/IP encapsulation header (24 bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnipHeader {
    pub command:      EnipCommand,
    pub length:       u16,
    pub session:      u32,
    pub status:       u32,
    pub sender_ctx:   [u8; 8],
    pub options:      u32,
    pub data:         Vec<u8>,
}

/// CIP service codes.
pub const CIP_GET_ATTR_ALL:    u8 = 0x01;
pub const CIP_SET_ATTR_ALL:    u8 = 0x02;
pub const CIP_GET_ATTR_LIST:   u8 = 0x03;
pub const CIP_SET_ATTR_LIST:   u8 = 0x04;
pub const CIP_RESET:           u8 = 0x05;
pub const CIP_START:           u8 = 0x06;
pub const CIP_STOP:            u8 = 0x07;
pub const CIP_CREATE:          u8 = 0x08;
pub const CIP_DELETE:          u8 = 0x09;
pub const CIP_GET_ATTR_SINGLE: u8 = 0x0e;
pub const CIP_SET_ATTR_SINGLE: u8 = 0x10;
pub const CIP_FIND_NEXT:       u8 = 0x11;
pub const CIP_READ_TAG:        u8 = 0x4c;
pub const CIP_WRITE_TAG:       u8 = 0x4d;

pub struct EnipDissector;

impl EnipDissector {
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn decode_header(buf: &[u8]) -> Result<(EnipHeader, usize), DissectError> {
        if buf.len() < 24 {
            return Err(DissectError::BufferTooShort { needed: 24, got: buf.len() });
        }
        let cmd = EnipCommand::from_u16(u16::from_le_bytes([buf[0], buf[1]]));
        let len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
        let session = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let status  = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let mut ctx = [0u8; 8];
        ctx.copy_from_slice(&buf[12..20]);
        let options = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
        let total = 24 + len;
        if buf.len() < total { return Err(DissectError::BufferTooShort { needed: total, got: buf.len() }); }
        Ok((EnipHeader { command: cmd, length: u16::try_from(len).unwrap_or(u16::MAX), session, status, sender_ctx: ctx, options, data: buf[24..total].to_vec() }, total))
    }

    /// Decode a CIP service request/response.
    #[must_use]
    pub fn decode_cip_service(buf: &[u8]) -> Option<(u8, bool)> {
        // First byte: service code (bit 7 = response)
        buf.first().map(|&b| (b & 0x7f, b & 0x80 != 0))
    }

    #[must_use]
    pub const fn cip_service_name(code: u8) -> &'static str {
        match code {
            CIP_GET_ATTR_ALL    => "GetAttributesAll",
            CIP_SET_ATTR_ALL    => "SetAttributesAll",
            CIP_GET_ATTR_LIST   => "GetAttributeList",
            CIP_SET_ATTR_LIST   => "SetAttributeList",
            CIP_RESET           => "Reset",
            CIP_START           => "Start",
            CIP_STOP            => "Stop",
            CIP_CREATE          => "Create",
            CIP_DELETE          => "Delete",
            CIP_GET_ATTR_SINGLE => "GetAttributeSingle",
            CIP_SET_ATTR_SINGLE => "SetAttributeSingle",
            CIP_FIND_NEXT       => "FindNextObjectInstance",
            CIP_READ_TAG        => "ReadTag",
            CIP_WRITE_TAG       => "WriteTag",
            _                   => "Unknown",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modbus_fc_names() {
        assert_eq!(ModbusFc::ReadHoldingRegisters.name(), "Read Holding Registers");
        assert_eq!(ModbusFc::WriteMultipleRegisters.name(), "Write Multiple Registers");
    }

    #[test]
    fn test_modbus_decode() {
        // Transaction 1, Protocol 0, Length 6, Unit 1, FC 3 (ReadHoldingRegisters), addr 0, count 2
        let buf = [0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02];
        let (adu, consumed) = ModbusDissector::decode(&buf).unwrap();
        assert_eq!(adu.transaction_id, 1);
        assert_eq!(adu.function_code, ModbusFc::ReadHoldingRegisters);
        assert_eq!(consumed, 12);
    }

    #[test]
    fn test_iec104_i_frame() {
        // I-frame: send_seq=0, recv_seq=0.
        // apdu_length=0x0e (14) → total APDU is 2 + 14 = 16 bytes.
        // Original test buf was 15 bytes (off-by-one); padded with a trailing
        // 0x00 ASDU byte to match the advertised length.
        let buf = [0x68, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        let (apdu, _) = Iec104Dissector::decode_apdu(&buf).unwrap();
        assert_eq!(apdu.format, Iec104ApduFormat::I);
        assert_eq!(apdu.send_seq, Some(0));
    }

    #[test]
    fn test_iec104_u_frame_startdt() {
        let buf = [0x68, 0x04, 0x07, 0x00, 0x00, 0x00];
        let (apdu, _) = Iec104Dissector::decode_apdu(&buf).unwrap();
        assert_eq!(apdu.format, Iec104ApduFormat::U);
        assert!(matches!(apdu.utype, Some(Iec104Utype::StartdtAct)));
    }

    #[test]
    fn test_dnp3_app_header() {
        let buf = [0x44, 0x01]; // FIR+FIN+con seq=4, fc=Read
        let hdr = Dnp3Dissector::decode_app_header(&buf).unwrap();
        assert!(matches!(hdr.function_code, Dnp3AppFc::Read));
    }

    #[test]
    fn test_enip_cip_service_name() {
        assert_eq!(EnipDissector::cip_service_name(CIP_READ_TAG), "ReadTag");
        assert_eq!(EnipDissector::cip_service_name(CIP_GET_ATTR_SINGLE), "GetAttributeSingle");
    }

    #[test]
    fn test_profinet_frame_id_category() {
        let fid = ProfinetFrameId(0xff00);
        assert_eq!(fid.category(), "DCP");
    }

    #[test]
    fn test_bacnet_unconfirmed_service() {
        assert!(matches!(BacnetUnconfirmedService::from_byte(8), BacnetUnconfirmedService::WhoIs));
        assert!(matches!(BacnetUnconfirmedService::from_byte(0), BacnetUnconfirmedService::IAm));
    }

    #[test]
    fn test_bvlc_length_below_header_is_rejected() {
        // BVLC Length counts the header too, so 0..3 are impossible values.
        // Before the guard these produced `&buf[4..len]` with start > end.
        for declared in 0u16..4 {
            let b = declared.to_be_bytes();
            let buf = [0x81, 0x0a, b[0], b[1], 0xff, 0xff];
            assert!(BacnetDissector::decode_bvlc(&buf).is_err(), "len={declared} must error");
        }
        // The smallest legal message is the bare 4-byte header.
        let (_, len, payload) = BacnetDissector::decode_bvlc(&[0x81, 0x0a, 0x00, 0x04]).unwrap();
        assert_eq!(len, 4);
        assert!(payload.is_empty());
        // And the payload is everything the length declares past the header.
        let (_, _, payload) = BacnetDissector::decode_bvlc(&[0x81, 0x0a, 0x00, 0x06, 0xaa, 0xbb]).unwrap();
        assert_eq!(payload, &[0xaa, 0xbb]);
    }

    #[test]
    fn test_declared_length_shorter_than_header_is_rejected() {
        // Same defect shape in three protocols: `total = PREFIX + declared`, but the
        // payload is sliced from an offset FURTHER IN than PREFIX, so a small declared
        // length puts the slice end before its start — a panic, not an error.

        // Modbus MBAP: total = 6 + len, PDU sliced from 8.
        let mut mb = [0u8; 12];
        mb[7] = 0x03;
        for declared in 0u16..2 {
            mb[4..6].copy_from_slice(&declared.to_be_bytes());
            assert!(ModbusDissector::decode(&mb).is_err(), "modbus len={declared}");
        }
        mb[4..6].copy_from_slice(&2u16.to_be_bytes());
        assert!(ModbusDissector::decode(&mb).is_ok());

        // DNP3 data link: total = 2 + length, payload sliced from 10.
        let mut d = [0u8; 16];
        d[0] = 0x64;
        d[1] = 0x05;
        for declared in [0u8, 1, 7] {
            d[2] = declared;
            assert!(Dnp3Dissector::decode_data_link(&d).is_err(), "dnp3 len={declared}");
        }
        d[2] = 8;
        assert!(Dnp3Dissector::decode_data_link(&d).is_ok());

        // IEC 60870-5-104: total = 2 + apdu_len, ASDU sliced from 6.
        let mut i = [0u8; 12];
        i[0] = 0x68;
        for declared in [0u8, 1, 3] {
            i[1] = declared;
            assert!(Iec104Dissector::decode_apdu(&i).is_err(), "iec104 len={declared}");
        }
        i[1] = 4;
        assert!(Iec104Dissector::decode_apdu(&i).is_ok());
    }
}
