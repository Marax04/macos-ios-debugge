//! LLDB/`debugserver` extensions to the GDB Remote Serial Protocol.
//!
//! These packets are what makes an Apple target usable at all, and none of them
//! exist anywhere in this workspace (the only active RSP client,
//! `rustre-debug/src/rr_backend.rs`, speaks base GDB and hard-codes an x86-64
//! register layout). Covered here:
//!
//! | packet | purpose |
//! |---|---|
//! | `qHostInfo` | CPU type/subtype, pointer size, endianness, OS version |
//! | `qProcessInfo` | pid/uid/gid and the *actual* arch of the inferior |
//! | `jThreadsInfo` | JSON thread list with stop reason and register snapshot |
//! | `qRegisterInfo<N>` | incremental register-set *discovery* |
//! | `A` | argv for `vRun`-style launch |
//! | `QLaunchArch` | slice selection for a universal binary |
//! | `qShlibInfoAddr` | address of dyld's all-image-infos |
//! | `qMemoryRegionInfo` | permissions/name of the region holding an address |
//! | `_M` / `_m` | allocate/deallocate memory inside the target |
//!
//! # Design
//! Everything here is a pure function over reply text. No transport, no
//! `cfg(target_os)`: the parsers are exercised on Windows against payloads
//! captured from a real `debugserver`.
//!
//! # Why discovery instead of a hard-coded table
//! `qRegisterInfo` exists precisely so the client never has to know the
//! target's register layout. arm64 vs arm64e vs x86-64 differ in count, order
//! *and* `g`-packet offsets; the `generic:` field is the only trustworthy way
//! to learn which register is the PC. Hard-coding that is the single defect
//! that makes `rr_backend` unusable off x86-64.

use std::collections::BTreeMap;

use crate::ios::rsp::RspPacket;

/// Errors raised while interpreting an lldb-extension reply.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LldbExtError {
    /// The stub answered `Exx`. `qRegisterInfo` uses this as a *terminator*,
    /// so callers enumerating registers must treat it as end-of-list, not
    /// as a failure — see [`parse_register_table`].
    #[error("{packet} returned error reply E{code:02x}")]
    ErrorReply { packet: &'static str, code: u8 },
    /// An empty reply is the RSP way of saying "packet not recognised".
    #[error("{0} unsupported by this stub (empty reply)")]
    Unsupported(&'static str),
    /// The reply parsed structurally but a required field was absent.
    #[error("{packet}: missing required field `{field}`")]
    MissingField {
        packet: &'static str,
        field: &'static str,
    },
    /// A field was present but not decodable.
    #[error("{packet}: field `{field}` has malformed value {value:?}")]
    BadField {
        packet: &'static str,
        field: &'static str,
        value: String,
    },
    /// `jThreadsInfo` did not return the documented JSON shape.
    #[error("{packet}: malformed JSON reply: {detail}")]
    BadJson {
        packet: &'static str,
        detail: String,
    },
}

type Result<T> = std::result::Result<T, LldbExtError>;

// ---------------------------------------------------------------------------
// Shared low-level helpers
// ---------------------------------------------------------------------------

/// Reject the two "no answer" shapes before any field parsing.
///
/// # Errors
/// [`LldbExtError::Unsupported`] for an empty reply, [`LldbExtError::ErrorReply`]
/// for `Exx`.
pub fn check_reply(packet: &'static str, reply: &str) -> Result<()> {
    if reply.is_empty() {
        return Err(LldbExtError::Unsupported(packet));
    }
    // `E` alone is not an error reply (e.g. a register named `E...` never
    // occurs, but a hex payload may legitimately start with 'e' lowercase).
    if let Some(rest) = reply.strip_prefix('E')
        && rest.len() == 2
        && rest.bytes().all(|b| b.is_ascii_hexdigit())
    {
        let code = u8::from_str_radix(rest, 16).unwrap_or(0);
        return Err(LldbExtError::ErrorReply { packet, code });
    }
    Ok(())
}

/// Split a `key:value;key:value;` reply. Values may themselves contain `:`
/// (register `set:General Purpose Registers`), so only the FIRST colon splits.
#[must_use]
pub fn parse_kv(reply: &str) -> BTreeMap<String, String> {
    reply
        .split(';')
        .filter(|f| !f.is_empty())
        .filter_map(|field| {
            field
                .split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.to_string()))
        })
        .collect()
}

/// Decode a hex-encoded ASCII string (debugserver hex-encodes `triple`,
/// `hostname` and region `name` so they cannot contain `;` or `:`).
#[must_use]
pub fn hex_to_ascii(hex: &str) -> Option<String> {
    if hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect();
    String::from_utf8(bytes).ok()
}

fn field<'a>(
    map: &'a BTreeMap<String, String>,
    packet: &'static str,
    name: &'static str,
) -> Result<&'a str> {
    map.get(name)
        .map(String::as_str)
        .ok_or(LldbExtError::MissingField {
            packet,
            field: name,
        })
}

fn hex_u64(packet: &'static str, name: &'static str, raw: &str) -> Result<u64> {
    u64::from_str_radix(raw.trim_start_matches("0x"), 16).map_err(|_| LldbExtError::BadField {
        packet,
        field: name,
        value: raw.to_string(),
    })
}

fn dec_u32(packet: &'static str, name: &'static str, raw: &str) -> Result<u32> {
    raw.parse().map_err(|_| LldbExtError::BadField {
        packet,
        field: name,
        value: raw.to_string(),
    })
}

// ---------------------------------------------------------------------------
// qHostInfo
// ---------------------------------------------------------------------------

/// Byte order reported by the stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

impl Endian {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "little" => Some(Self::Little),
            "big" => Some(Self::Big),
            _ => None,
        }
    }
}

/// Mach-O `cputype` values seen from `debugserver`, kept as constants rather
/// than magic numbers at the call sites.
pub mod cputype {
    /// `CPU_TYPE_X86_64` (`CPU_TYPE_X86 | CPU_ARCH_ABI64`).
    pub const X86_64: u32 = 0x0100_0007;
    /// `CPU_TYPE_ARM64`.
    pub const ARM64: u32 = 0x0100_000C;
    /// `CPU_TYPE_ARM64_32` (watchOS).
    pub const ARM64_32: u32 = 0x0200_000C;
    /// `CPU_TYPE_ARM` (32-bit iOS).
    pub const ARM: u32 = 0x0000_000C;
}

/// `CPU_SUBTYPE_ARM64E` — pointer authentication is in play, so code addresses
/// must be stripped before comparison. Callers use this to decide.
pub const CPU_SUBTYPE_ARM64E: u32 = 2;

/// Parsed `qHostInfo` reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostInfo {
    pub cputype: u32,
    pub cpusubtype: u32,
    pub ostype: String,
    pub vendor: Option<String>,
    pub endian: Endian,
    pub ptrsize: u8,
    pub os_version: Option<String>,
    /// Decoded from hex, e.g. `arm64e-apple-macosx`.
    pub triple: Option<String>,
    pub hostname: Option<String>,
    /// `before` or `after` — whether the stub reports a watchpoint hit before
    /// or after the access completes. Getting this wrong makes a watchpoint
    /// report the wrong instruction.
    pub watchpoint_exceptions_received: Option<String>,
    /// Number of hardware watchpoint slots, when advertised.
    pub num_watchpoints: Option<u32>,
    /// Fields present in the reply but not modelled above, kept verbatim so
    /// nothing is silently dropped.
    pub extra: BTreeMap<String, String>,
}

impl HostInfo {
    /// The command to send.
    pub const COMMAND: &'static str = "qHostInfo";

    /// Parse a `qHostInfo` reply payload.
    ///
    /// # Errors
    /// Missing/undecodable `cputype`, `ptrsize` or `endian`, or a non-reply.
    pub fn parse(reply: &str) -> Result<Self> {
        const P: &str = "qHostInfo";
        check_reply(P, reply)?;
        let mut kv = parse_kv(reply);
        if kv.is_empty() {
            return Err(LldbExtError::MissingField {
                packet: P,
                field: "cputype",
            });
        }

        // cputype/cpusubtype are DECIMAL in qHostInfo but HEX in qProcessInfo.
        // That asymmetry is real debugserver behaviour, not a typo.
        let cputype = dec_u32(P, "cputype", field(&kv, P, "cputype")?)?;
        let cpusubtype = kv
            .get("cpusubtype")
            .map_or(Ok(0), |v| dec_u32(P, "cpusubtype", v))?;
        let ptrsize_raw = field(&kv, P, "ptrsize")?;
        let ptrsize: u8 = ptrsize_raw.parse().map_err(|_| LldbExtError::BadField {
            packet: P,
            field: "ptrsize",
            value: ptrsize_raw.to_string(),
        })?;
        let endian_raw = field(&kv, P, "endian")?;
        let endian = Endian::parse(endian_raw).ok_or(LldbExtError::BadField {
            packet: P,
            field: "endian",
            value: endian_raw.to_string(),
        })?;
        let ostype = field(&kv, P, "ostype")?.to_string();

        let triple = kv.get("triple").and_then(|h| hex_to_ascii(h));
        let hostname = kv.get("hostname").and_then(|h| hex_to_ascii(h));
        let num_watchpoints = kv.get("num_wps").and_then(|v| v.parse().ok());
        let vendor = kv.get("vendor").cloned();
        let os_version = kv.get("os_version").cloned();
        let watchpoint_exceptions_received = kv.get("watchpoint_exceptions_received").cloned();

        // Everything consumed above is removed so `extra` holds exactly the
        // fields this struct does not model — a new debugserver key surfaces
        // there instead of vanishing.
        for k in [
            "cputype",
            "cpusubtype",
            "ptrsize",
            "endian",
            "ostype",
            "vendor",
            "os_version",
            "triple",
            "hostname",
            "watchpoint_exceptions_received",
            "num_wps",
        ] {
            kv.remove(k);
        }

        Ok(Self {
            cputype,
            cpusubtype,
            ostype,
            vendor,
            endian,
            ptrsize,
            os_version,
            triple,
            hostname,
            watchpoint_exceptions_received,
            num_watchpoints,
            extra: kv,
        })
    }

    /// True when the host is arm64e, i.e. return addresses carry a PAC that
    /// must be stripped before they can be matched against an image.
    #[must_use]
    pub const fn is_arm64e(&self) -> bool {
        self.cputype == cputype::ARM64 && self.cpusubtype == CPU_SUBTYPE_ARM64E
    }

    /// Whether a watchpoint stop is reported after the access completed.
    #[must_use]
    pub fn watchpoint_reported_after_access(&self) -> bool {
        self.watchpoint_exceptions_received.as_deref() == Some("after")
    }
}

// ---------------------------------------------------------------------------
// qProcessInfo
// ---------------------------------------------------------------------------

/// Parsed `qProcessInfo` reply. All numeric fields are hex here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u64,
    pub parent_pid: Option<u64>,
    pub real_uid: Option<u32>,
    pub real_gid: Option<u32>,
    pub effective_uid: Option<u32>,
    pub effective_gid: Option<u32>,
    pub cputype: u32,
    pub cpusubtype: u32,
    pub ptrsize: u8,
    pub ostype: Option<String>,
    pub vendor: Option<String>,
    pub endian: Option<Endian>,
    pub extra: BTreeMap<String, String>,
}

impl ProcessInfo {
    pub const COMMAND: &'static str = "qProcessInfo";

    /// Parse a `qProcessInfo` reply payload.
    ///
    /// # Errors
    /// Missing/undecodable `pid`, `cputype` or `ptrsize`, or a non-reply.
    pub fn parse(reply: &str) -> Result<Self> {
        const P: &str = "qProcessInfo";
        check_reply(P, reply)?;
        let kv = parse_kv(reply);
        let hexf = |name: &'static str| -> Result<u64> { hex_u64(P, name, field(&kv, P, name)?) };
        let opt_hex = |name: &str| -> Option<u64> {
            kv.get(name)
                .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        };

        let cputype = u32::try_from(hexf("cputype")?).map_err(|_| LldbExtError::BadField {
            packet: P,
            field: "cputype",
            value: kv.get("cputype").cloned().unwrap_or_default(),
        })?;
        let ptrsize_raw = field(&kv, P, "ptrsize")?;
        let ptrsize: u8 = ptrsize_raw.parse().map_err(|_| LldbExtError::BadField {
            packet: P,
            field: "ptrsize",
            value: ptrsize_raw.to_string(),
        })?;

        let mut extra = kv.clone();
        for k in [
            "pid",
            "parent-pid",
            "real-uid",
            "real-gid",
            "effective-uid",
            "effective-gid",
            "cputype",
            "cpusubtype",
            "ptrsize",
            "ostype",
            "vendor",
            "endian",
        ] {
            extra.remove(k);
        }

        Ok(Self {
            pid: hexf("pid")?,
            parent_pid: opt_hex("parent-pid"),
            real_uid: opt_hex("real-uid").and_then(|v| u32::try_from(v).ok()),
            real_gid: opt_hex("real-gid").and_then(|v| u32::try_from(v).ok()),
            effective_uid: opt_hex("effective-uid").and_then(|v| u32::try_from(v).ok()),
            effective_gid: opt_hex("effective-gid").and_then(|v| u32::try_from(v).ok()),
            cputype,
            cpusubtype: opt_hex("cpusubtype")
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(0),
            ptrsize,
            ostype: kv.get("ostype").cloned(),
            vendor: kv.get("vendor").cloned(),
            endian: kv.get("endian").and_then(|v| Endian::parse(v)),
            extra,
        })
    }
}

// ---------------------------------------------------------------------------
// qRegisterInfo<N>
// ---------------------------------------------------------------------------

/// The `generic:` role of a register. This is the ONLY portable way to find the
/// program counter: on arm64 it is `pc` (x32), on x86-64 `rip` (reg 16), and
/// nothing in the numbering tells you which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenericRole {
    Pc,
    Sp,
    Fp,
    /// Return address (`lr` on arm64).
    Ra,
    Flags,
    Arg(u8),
}

impl GenericRole {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "pc" => Some(Self::Pc),
            "sp" => Some(Self::Sp),
            "fp" => Some(Self::Fp),
            "ra" => Some(Self::Ra),
            "flags" => Some(Self::Flags),
            other => other
                .strip_prefix("arg")
                .and_then(|n| n.parse::<u8>().ok())
                .filter(|n| (1..=8).contains(n))
                .map(Self::Arg),
        }
    }
}

/// One register as described by `qRegisterInfo<N>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterInfo {
    /// Index in the enumeration; also the number to use with `p`/`P`.
    pub regnum: u32,
    pub name: String,
    pub alt_name: Option<String>,
    pub bitsize: u32,
    /// Byte offset in the `g`/`G` packet payload.
    pub offset: Option<u32>,
    pub encoding: String,
    pub format: String,
    /// Register set name, e.g. `General Purpose Registers` or
    /// `Exception State Registers` (where the arm64 debug registers live).
    pub set: String,
    pub dwarf_regnum: Option<u32>,
    pub gcc_regnum: Option<u32>,
    pub generic: Option<GenericRole>,
    /// Registers this one is a sub-field of (e.g. `w0` inside `x0`).
    pub container_regs: Vec<u32>,
    /// Registers invalidated by writing this one.
    pub invalidate_regs: Vec<u32>,
}

impl RegisterInfo {
    /// Build the query for register `n`.
    #[must_use]
    pub fn command(regnum: u32) -> String {
        format!("qRegisterInfo{regnum:x}")
    }

    /// Parse one `qRegisterInfo` reply.
    ///
    /// # Errors
    /// [`LldbExtError::ErrorReply`] when the stub signals end-of-list (`E45`),
    /// or a missing `name`/`bitsize`.
    pub fn parse(regnum: u32, reply: &str) -> Result<Self> {
        const P: &str = "qRegisterInfo";
        check_reply(P, reply)?;
        let kv = parse_kv(reply);
        let bitsize_raw = field(&kv, P, "bitsize")?;
        Ok(Self {
            regnum,
            name: field(&kv, P, "name")?.to_string(),
            alt_name: kv.get("alt-name").cloned(),
            bitsize: bitsize_raw.parse().map_err(|_| LldbExtError::BadField {
                packet: P,
                field: "bitsize",
                value: bitsize_raw.to_string(),
            })?,
            offset: kv.get("offset").and_then(|v| v.parse().ok()),
            encoding: kv.get("encoding").cloned().unwrap_or_default(),
            format: kv.get("format").cloned().unwrap_or_default(),
            set: kv.get("set").cloned().unwrap_or_default(),
            dwarf_regnum: kv.get("dwarf").and_then(|v| v.parse().ok()),
            gcc_regnum: kv.get("gcc").and_then(|v| v.parse().ok()),
            generic: kv.get("generic").and_then(|v| GenericRole::parse(v)),
            container_regs: parse_reg_list(kv.get("container-regs")),
            invalidate_regs: parse_reg_list(kv.get("invalidate-regs")),
        })
    }

    /// Size in bytes, rounded up (a 1-bit flag register still occupies a byte).
    #[must_use]
    pub const fn byte_size(&self) -> u32 {
        self.bitsize.div_ceil(8)
    }
}

fn parse_reg_list(raw: Option<&String>) -> Vec<u32> {
    raw.map(|s| {
        s.split(',')
            .filter_map(|n| u32::from_str_radix(n.trim(), 16).ok())
            .collect()
    })
    .unwrap_or_default()
}

/// Consume an enumeration of `qRegisterInfo` replies, stopping at the first
/// `Exx` terminator.
///
/// `debugserver` signals "no more registers" with `E45`, so an error reply here
/// is the documented end condition, NOT a failure. Any other malformed reply is
/// still surfaced — a silent truncation would produce a register map that is
/// quietly missing the flags register.
///
/// # Errors
/// Propagates a malformed (non-`Exx`) reply.
pub fn parse_register_table<S: AsRef<str>>(replies: &[S]) -> Result<Vec<RegisterInfo>> {
    let mut out = Vec::with_capacity(replies.len());
    for (i, reply) in replies.iter().enumerate() {
        let n = u32::try_from(i).unwrap_or(u32::MAX);
        match RegisterInfo::parse(n, reply.as_ref()) {
            Ok(info) => out.push(info),
            Err(LldbExtError::ErrorReply { .. } | LldbExtError::Unsupported(_)) => break,
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// Find the register carrying a given generic role in a discovered table.
#[must_use]
pub fn find_generic(table: &[RegisterInfo], role: GenericRole) -> Option<&RegisterInfo> {
    table.iter().find(|r| r.generic == Some(role))
}

// ---------------------------------------------------------------------------
// jThreadsInfo
// ---------------------------------------------------------------------------

/// One entry of the `jThreadsInfo` JSON array.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ThreadInfo {
    pub tid: u64,
    pub name: Option<String>,
    /// GCD queue name, when the thread is running a dispatch queue.
    pub queue: Option<String>,
    /// `breakpoint`, `exception`, `signal`, `trace`, …
    pub reason: Option<String>,
    /// Mach exception type (`EXC_BREAKPOINT` = 6) when `reason == "exception"`.
    pub metype: Option<u64>,
    pub medata: Vec<u64>,
    pub signo: Option<u32>,
    /// Register snapshot: register number → raw little-endian hex payload.
    /// Left as hex on purpose — decoding needs the width from `qRegisterInfo`,
    /// which this parser deliberately does not assume.
    pub registers: BTreeMap<u32, String>,
}

impl ThreadInfo {
    /// Decode a register value as a little-endian unsigned integer.
    ///
    /// Returns `None` when the register is absent or wider than 64 bits (a
    /// vector register), rather than silently truncating it.
    #[must_use]
    pub fn register_u64(&self, regnum: u32) -> Option<u64> {
        let hex = self.registers.get(&regnum)?;
        if hex.len() % 2 != 0 || hex.len() > 16 {
            return None;
        }
        let mut value = 0u64;
        for (i, chunk) in (0..hex.len()).step_by(2).enumerate() {
            let byte = u8::from_str_radix(&hex[chunk..chunk + 2], 16).ok()?;
            value |= u64::from(byte) << (8 * i);
        }
        Some(value)
    }
}

/// Parse a `jThreadsInfo` reply (a JSON array).
///
/// # Errors
/// [`LldbExtError::BadJson`] when the payload is not a JSON array of objects
/// carrying a numeric `tid`.
pub fn parse_threads_info(reply: &str) -> Result<Vec<ThreadInfo>> {
    const P: &str = "jThreadsInfo";
    check_reply(P, reply)?;
    let root: serde_json::Value =
        serde_json::from_str(reply).map_err(|e| LldbExtError::BadJson {
            packet: P,
            detail: e.to_string(),
        })?;
    let arr = root.as_array().ok_or(LldbExtError::BadJson {
        packet: P,
        detail: "top level is not an array".to_string(),
    })?;

    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        let obj = entry.as_object().ok_or(LldbExtError::BadJson {
            packet: P,
            detail: "array element is not an object".to_string(),
        })?;
        let tid = obj
            .get("tid")
            .and_then(serde_json::Value::as_u64)
            .ok_or(LldbExtError::BadJson {
                packet: P,
                detail: "thread entry has no numeric `tid`".to_string(),
            })?;

        let registers = obj
            .get("registers")
            .and_then(serde_json::Value::as_object)
            .map(|regs| {
                regs.iter()
                    .filter_map(|(k, v)| Some((k.parse::<u32>().ok()?, v.as_str()?.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        out.push(ThreadInfo {
            tid,
            name: obj
                .get("name")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            queue: obj
                .get("queue")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            reason: obj
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            metype: obj.get("metype").and_then(serde_json::Value::as_u64),
            medata: obj
                .get("medata")
                .and_then(serde_json::Value::as_array)
                .map(|a| a.iter().filter_map(serde_json::Value::as_u64).collect())
                .unwrap_or_default(),
            signo: obj
                .get("signo")
                .and_then(serde_json::Value::as_u64)
                .and_then(|v| u32::try_from(v).ok()),
            registers,
        })
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// A packet (argv) and QLaunchArch
// ---------------------------------------------------------------------------

/// Build the `A` packet carrying argv for a launch.
///
/// Format: `A<len>,<argnum>,<hex>` repeated, comma separated, where `len` is
/// the length of the HEX encoding (i.e. twice the byte length) — encoding it as
/// the byte length is the classic bug and makes debugserver reject the launch.
#[must_use]
pub fn build_a_packet<S: AsRef<str>>(argv: &[S]) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(argv.len());
    for (i, arg) in argv.iter().enumerate() {
        let hex: String = arg
            .as_ref()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        parts.push(format!("{},{},{}", hex.len(), i, hex));
    }
    format!("A{}", parts.join(","))
}

/// Hex-encode a string for the `Q` launch packets.
fn hex_of(text: &str) -> String {
    text.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// Build `QSetWorkingDir:<hex path>` — the working directory the inferior is
/// launched in. Hex-encoded so a path with spaces or `#`/`$` survives the RSP
/// framing.
#[must_use]
pub fn build_set_working_dir(dir: &str) -> String {
    format!("QSetWorkingDir:{}", hex_of(dir))
}

/// Build `QEnvironmentHexEncoded:<hex of KEY=VALUE>` — one variable to add to
/// the inferior's environment. The hex form is used unconditionally because the
/// plain `QEnvironment:` form cannot carry a value containing `#`, `$` or `*`.
#[must_use]
pub fn build_environment(key: &str, value: &str) -> String {
    format!("QEnvironmentHexEncoded:{}", hex_of(&format!("{key}={value}")))
}

/// Architecture slice to select before launching a universal binary.
#[must_use]
pub fn build_launch_arch(arch: &str) -> String {
    format!("QLaunchArch:{arch}")
}

// ---------------------------------------------------------------------------
// qShlibInfoAddr
// ---------------------------------------------------------------------------

/// Command for the address of dyld's `all_image_infos` structure.
pub const QSHLIB_INFO_ADDR: &str = "qShlibInfoAddr";

/// Parse the `qShlibInfoAddr` reply (a bare hex address).
///
/// # Errors
/// Empty reply (unsupported), `Exx`, or non-hex payload.
pub fn parse_shlib_info_addr(reply: &str) -> Result<u64> {
    const P: &str = "qShlibInfoAddr";
    check_reply(P, reply)?;
    hex_u64(P, "address", reply)
}

// ---------------------------------------------------------------------------
// qMemoryRegionInfo
// ---------------------------------------------------------------------------

/// Parsed `qMemoryRegionInfo:<addr>` reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRegionInfo {
    pub start: u64,
    pub size: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    /// Mapped file path, hex-decoded.
    pub name: Option<String>,
    /// Set when the stub answered `error:<hex message>` — the address is not
    /// mapped. Modelled as a value rather than an `Err` because "unmapped" is
    /// a legitimate answer a memory-map walker must be able to act on.
    pub error: Option<String>,
    pub extra: BTreeMap<String, String>,
}

impl MemoryRegionInfo {
    /// Build the query.
    #[must_use]
    pub fn command(addr: u64) -> String {
        format!("qMemoryRegionInfo:{addr:x}")
    }

    /// Parse a `qMemoryRegionInfo` reply.
    ///
    /// # Errors
    /// Non-reply, or a reply with neither `start`/`size` nor `error`.
    pub fn parse(reply: &str) -> Result<Self> {
        const P: &str = "qMemoryRegionInfo";
        check_reply(P, reply)?;
        let kv = parse_kv(reply);

        if let Some(err) = kv.get("error") {
            return Ok(Self {
                start: 0,
                size: 0,
                readable: false,
                writable: false,
                executable: false,
                name: None,
                error: Some(hex_to_ascii(err).unwrap_or_else(|| err.clone())),
                extra: BTreeMap::new(),
            });
        }

        let perms = kv.get("permissions").map(String::as_str).unwrap_or("");
        let mut extra = kv.clone();
        for k in ["start", "size", "permissions", "name", "error"] {
            extra.remove(k);
        }

        Ok(Self {
            start: hex_u64(P, "start", field(&kv, P, "start")?)?,
            size: hex_u64(P, "size", field(&kv, P, "size")?)?,
            readable: perms.contains('r'),
            writable: perms.contains('w'),
            executable: perms.contains('x'),
            name: kv.get("name").and_then(|h| hex_to_ascii(h)),
            error: None,
            extra,
        })
    }

    /// End address (exclusive).
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.start.saturating_add(self.size)
    }

    /// Whether the region is actually mapped.
    #[must_use]
    pub const fn is_mapped(&self) -> bool {
        self.error.is_none() && self.size > 0
    }
}

// ---------------------------------------------------------------------------
// _M / _m — allocate and deallocate memory in the target
// ---------------------------------------------------------------------------

/// Memory protection flags for [`build_alloc`]. Needed for trampolines: a page
/// written as data then executed must be requested `rx`/`rwx` up front, because
/// `_M` has no counterpart to `mprotect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AllocPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl AllocPermissions {
    #[must_use]
    pub const fn rw() -> Self {
        Self {
            read: true,
            write: true,
            execute: false,
        }
    }

    #[must_use]
    pub const fn rx() -> Self {
        Self {
            read: true,
            write: false,
            execute: true,
        }
    }

    #[must_use]
    pub const fn rwx() -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
        }
    }

    #[must_use]
    pub fn encode(self) -> String {
        let mut s = String::with_capacity(3);
        if self.read {
            s.push('r');
        }
        if self.write {
            s.push('w');
        }
        if self.execute {
            s.push('x');
        }
        s
    }
}

/// Build `_M<size>,<perms>`.
#[must_use]
pub fn build_alloc(size: u64, perms: AllocPermissions) -> String {
    format!("_M{:x},{}", size, perms.encode())
}

/// Build `_m<addr>`.
#[must_use]
pub fn build_dealloc(addr: u64) -> String {
    format!("_m{addr:x}")
}

/// Parse the `_M` reply — a bare hex address of the new allocation.
///
/// # Errors
/// Empty reply means the stub cannot allocate; `Exx` means it refused.
pub fn parse_alloc_reply(reply: &str) -> Result<u64> {
    const P: &str = "_M";
    check_reply(P, reply)?;
    hex_u64(P, "address", reply)
}

/// Parse the `_m` reply — `OK` on success.
///
/// # Errors
/// Anything other than `OK`.
pub fn parse_dealloc_reply(reply: &str) -> Result<()> {
    const P: &str = "_m";
    check_reply(P, reply)?;
    if reply == "OK" {
        Ok(())
    } else {
        Err(LldbExtError::BadField {
            packet: P,
            field: "status",
            value: reply.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Packet convenience
// ---------------------------------------------------------------------------

/// Parse directly from a decoded [`RspPacket`], for callers wiring the framer
/// straight into these parsers.
///
/// # Errors
/// Whatever `parse` returns.
pub fn from_packet<T, F>(packet: &RspPacket, parse: F) -> Result<T>
where
    F: FnOnce(&str) -> Result<T>,
{
    parse(&packet.as_str())
}

#[cfg(test)]
mod tests {

    /// Truncation + mutation sweep over every reply parser in this module.
    ///
    /// These consume text a REMOTE `debugserver` sends: `qHostInfo`,
    /// `qProcessInfo`, `qRegisterInfo`, `jThreadsInfo` (JSON),
    /// `qMemoryRegionInfo`, `_M`/`_m`. A malformed or hostile reply must
    /// produce `Err`, never a panic — the same bar the local-format parsers
    /// were held to in iters 235-236, applied to the remote surface.
    #[test]
    fn lldb_reply_parsers_never_panic_on_truncated_or_mutated_input() {
        let seeds: [&str; 6] = [
            "cputype:16777228;cpusubtype:2;ostype:ios;vendor:apple;endian:little;ptrsize:8;",
            "pid:1a2b;parent-pid:1;real-uid:1f5;cputype:16777228;ptrsize:8;",
            "name:x0;bitsize:64;offset:0;encoding:uint;format:hex;set:General Purpose Registers;",
            "[{\"tid\":6699,\"name\":\"main\",\"reason\":\"breakpoint\"},{\"tid\":6700}]",
            "start:100000000;size:4000;permissions:rx;name:5f5f54455854;",
            "OK",
        ];
        let probes: [char; 10] = ['\0', ':', ';', ',', '"', '{', '}', '[', 'x', '\u{7f}'];

        let hammer = |s: &str| {
            let _ = parse_kv(s);
            let _ = HostInfo::parse(s);
            let _ = ProcessInfo::parse(s);
            let _ = RegisterInfo::parse(0, s);
            let _ = parse_threads_info(s);
            let _ = parse_shlib_info_addr(s);
            let _ = MemoryRegionInfo::parse(s);
            let _ = parse_alloc_reply(s);
            let _ = parse_dealloc_reply(s);
        };

        for seed in seeds {
            for len in 0..=seed.len() {
                if seed.is_char_boundary(len) {
                    hammer(&seed[..len]);
                }
            }
            let chars: Vec<char> = seed.chars().collect();
            for i in 0..chars.len() {
                for probe in probes {
                    let mut m = chars.clone();
                    m[i] = probe;
                    hammer(&m.into_iter().collect::<String>());
                }
            }
        }

        // A register table is assembled from MANY replies: a hostile stub can
        // make them disagree, overlap or repeat, which no single reply shows.
        let _ = parse_register_table(&[
            "name:x0;bitsize:64;offset:0;",
            "name:x0;bitsize:64;offset:0;",              // duplicate name
            "name:x1;bitsize:ffffffff;offset:ffffffff;", // absurd geometry
            "name:;bitsize:0;offset:0;",                 // empty name, zero size
            "",
        ]);
    }
    use super::*;

    // Payloads below are real `debugserver` replies (macOS 13 / arm64e and
    // x86-64), transcribed from packet logs; they are the reason the decimal
    // vs hex asymmetry between qHostInfo and qProcessInfo is tested explicitly.

    const HOST_INFO_ARM64E: &str = "cputype:16777228;cpusubtype:2;ostype:macosx;watchpoint_exceptions_received:after;vendor:apple;os_version:13.4.1;endian:little;ptrsize:8;";
    const PROCESS_INFO: &str = "pid:d21c;parent-pid:d216;real-uid:1f5;real-gid:14;effective-uid:1f5;effective-gid:14;cputype:100000c;cpusubtype:2;ptrsize:8;ostype:macosx;vendor:apple;endian:little;";

    #[test]
    fn host_info_arm64e_is_detected() {
        let hi = HostInfo::parse(HOST_INFO_ARM64E).unwrap();
        assert_eq!(hi.cputype, cputype::ARM64);
        assert_eq!(hi.cpusubtype, CPU_SUBTYPE_ARM64E);
        assert_eq!(hi.ptrsize, 8);
        assert_eq!(hi.endian, Endian::Little);
        assert_eq!(hi.ostype, "macosx");
        assert_eq!(hi.vendor.as_deref(), Some("apple"));
        assert_eq!(hi.os_version.as_deref(), Some("13.4.1"));
        assert!(hi.is_arm64e());
        assert!(hi.watchpoint_reported_after_access());
    }

    #[test]
    fn host_info_decodes_hex_triple_and_hostname() {
        // triple = "arm64e-apple-macosx", hostname = "mac"
        let reply = "cputype:16777228;cpusubtype:2;ostype:macosx;endian:little;ptrsize:8;\
             triple:61726d3634652d6170706c652d6d61636f7378;hostname:6d6163;";
        let hi = HostInfo::parse(reply).unwrap();
        assert_eq!(hi.triple.as_deref(), Some("arm64e-apple-macosx"));
        assert_eq!(hi.hostname.as_deref(), Some("mac"));
    }

    #[test]
    fn host_info_x86_64_is_not_arm64e() {
        let reply =
            "cputype:16777223;cpusubtype:8;ostype:macosx;endian:little;ptrsize:8;vendor:apple;";
        let hi = HostInfo::parse(reply).unwrap();
        assert_eq!(hi.cputype, cputype::X86_64);
        assert!(!hi.is_arm64e());
    }

    #[test]
    fn host_info_rejects_missing_and_error_replies() {
        assert_eq!(
            HostInfo::parse(""),
            Err(LldbExtError::Unsupported("qHostInfo"))
        );
        assert_eq!(
            HostInfo::parse("E45"),
            Err(LldbExtError::ErrorReply {
                packet: "qHostInfo",
                code: 0x45
            })
        );
        assert!(matches!(
            HostInfo::parse("ostype:macosx;endian:little;ptrsize:8;"),
            Err(LldbExtError::MissingField {
                field: "cputype",
                ..
            })
        ));
        assert!(matches!(
            HostInfo::parse("cputype:zz;ostype:macosx;endian:little;ptrsize:8;"),
            Err(LldbExtError::BadField { field: "cputype", .. })
        ));
    }

    #[test]
    fn process_info_fields_are_hex_unlike_host_info() {
        let pi = ProcessInfo::parse(PROCESS_INFO).unwrap();
        assert_eq!(pi.pid, 0xd21c);
        assert_eq!(pi.parent_pid, Some(0xd216));
        assert_eq!(pi.real_uid, Some(0x1f5));
        assert_eq!(pi.effective_gid, Some(0x14));
        // Same CPU as the qHostInfo case above, but encoded in hex there.
        assert_eq!(pi.cputype, cputype::ARM64);
        assert_eq!(pi.ptrsize, 8);
        assert_eq!(pi.endian, Some(Endian::Little));
    }

    #[test]
    fn process_info_requires_pid() {
        assert!(matches!(
            ProcessInfo::parse("cputype:100000c;ptrsize:8;"),
            Err(LldbExtError::MissingField { field: "pid", .. })
        ));
    }

    #[test]
    fn register_info_arm64_pc_carries_generic_role() {
        let reply = "name:pc;alt-name:pc;bitsize:64;offset:256;encoding:uint;format:hex;\
             set:General Purpose Registers;gcc:32;dwarf:32;generic:pc;";
        let r = RegisterInfo::parse(32, reply).unwrap();
        assert_eq!(r.name, "pc");
        assert_eq!(r.bitsize, 64);
        assert_eq!(r.byte_size(), 8);
        assert_eq!(r.offset, Some(256));
        assert_eq!(r.generic, Some(GenericRole::Pc));
        assert_eq!(r.set, "General Purpose Registers");
        assert_eq!(r.dwarf_regnum, Some(32));
    }

    #[test]
    fn register_info_parses_container_and_invalidate_lists() {
        let reply = "name:w0;bitsize:32;offset:0;encoding:uint;format:hex;\
             set:General Purpose Registers;container-regs:0;invalidate-regs:0,1a;";
        let r = RegisterInfo::parse(1, reply).unwrap();
        assert_eq!(r.container_regs, vec![0]);
        assert_eq!(r.invalidate_regs, vec![0, 0x1a]);
    }

    #[test]
    fn register_info_command_is_hex() {
        assert_eq!(RegisterInfo::command(0), "qRegisterInfo0");
        assert_eq!(RegisterInfo::command(26), "qRegisterInfo1a");
    }

    #[test]
    fn register_table_stops_at_e45_terminator() {
        let replies = vec![
            "name:x0;bitsize:64;offset:0;encoding:uint;format:hex;set:General Purpose Registers;generic:arg1;"
                .to_string(),
            "name:sp;bitsize:64;offset:248;encoding:uint;format:hex;set:General Purpose Registers;generic:sp;"
                .to_string(),
            "E45".to_string(),
            // Never reached: proves the terminator really terminates.
            "name:ghost;bitsize:64;".to_string(),
        ];
        let table = parse_register_table(&replies).unwrap();
        assert_eq!(table.len(), 2);
        assert_eq!(table[0].generic, Some(GenericRole::Arg(1)));
        assert_eq!(find_generic(&table, GenericRole::Sp).unwrap().name, "sp");
        assert!(find_generic(&table, GenericRole::Pc).is_none());
    }

    #[test]
    fn register_table_propagates_real_malformation() {
        let replies = vec!["bitsize:64;offset:0;".to_string()];
        assert!(matches!(
            parse_register_table(&replies),
            Err(LldbExtError::MissingField { field: "name", .. })
        ));
    }

    #[test]
    fn threads_info_parses_stop_reason_and_registers() {
        // x0 = 1, pc = 0x0000000100003f44 (little-endian hex payloads).
        let reply = r#"[
            {"tid":1234,"name":"main","queue":"com.apple.main-thread","reason":"exception",
             "metype":6,"medata":[1,0],
             "registers":{"0":"0100000000000000","32":"443f000001000000"}},
            {"tid":5678,"reason":"signal","signo":17}
        ]"#;
        let threads = parse_threads_info(reply).unwrap();
        assert_eq!(threads.len(), 2);
        assert_eq!(threads[0].tid, 1234);
        assert_eq!(threads[0].name.as_deref(), Some("main"));
        assert_eq!(threads[0].queue.as_deref(), Some("com.apple.main-thread"));
        assert_eq!(threads[0].reason.as_deref(), Some("exception"));
        assert_eq!(threads[0].metype, Some(6)); // EXC_BREAKPOINT
        assert_eq!(threads[0].medata, vec![1, 0]);
        assert_eq!(threads[0].register_u64(0), Some(1));
        assert_eq!(threads[0].register_u64(32), Some(0x0000_0001_0000_3f44));
        assert_eq!(threads[0].register_u64(99), None);
        assert_eq!(threads[1].signo, Some(17));
        assert!(threads[1].registers.is_empty());
    }

    #[test]
    fn threads_info_refuses_vector_register_truncation() {
        let reply = r#"[{"tid":1,"registers":{"64":"000102030405060708090a0b0c0d0e0f"}}]"#;
        let t = parse_threads_info(reply).unwrap();
        // 128-bit value: returning its low half would be confidently wrong.
        assert_eq!(t[0].register_u64(64), None);
    }

    #[test]
    fn threads_info_rejects_non_array_and_bad_entries() {
        assert!(matches!(
            parse_threads_info("{\"tid\":1}"),
            Err(LldbExtError::BadJson { .. })
        ));
        assert!(matches!(
            parse_threads_info("[{\"name\":\"main\"}]"),
            Err(LldbExtError::BadJson { .. })
        ));
        assert!(matches!(
            parse_threads_info("not json"),
            Err(LldbExtError::BadJson { .. })
        ));
    }

    #[test]
    fn a_packet_encodes_hex_length_not_byte_length() {
        // "/bin/ls" is 7 bytes => 14 hex chars; the length field is 14.
        assert_eq!(
            build_a_packet(&["/bin/ls"]),
            "A14,0,2f62696e2f6c73"
        );
        assert_eq!(build_a_packet(&["a", "b"]), "A2,0,61,2,1,62");
        assert_eq!(build_a_packet::<&str>(&[]), "A");
    }

    #[test]
    fn launch_arch_command() {
        assert_eq!(build_launch_arch("arm64e"), "QLaunchArch:arm64e");
    }

    #[test]
    fn shlib_info_addr() {
        assert_eq!(parse_shlib_info_addr("7fff20010000").unwrap(), 0x7fff_2001_0000);
        assert_eq!(
            parse_shlib_info_addr(""),
            Err(LldbExtError::Unsupported("qShlibInfoAddr"))
        );
        assert!(matches!(
            parse_shlib_info_addr("nothex"),
            Err(LldbExtError::BadField { .. })
        ));
    }

    #[test]
    fn memory_region_info_decodes_permissions_and_path() {
        // name = "/usr/lib/dyld"
        let reply = "start:180000000;size:56000;permissions:rx;\
             name:2f7573722f6c69622f64796c64;";
        let r = MemoryRegionInfo::parse(reply).unwrap();
        assert_eq!(r.start, 0x1_8000_0000);
        assert_eq!(r.size, 0x56000);
        assert_eq!(r.end(), 0x1_8005_6000);
        assert!(r.readable && r.executable && !r.writable);
        assert_eq!(r.name.as_deref(), Some("/usr/lib/dyld"));
        assert!(r.is_mapped());
    }

    #[test]
    fn memory_region_info_unmapped_is_a_value_not_an_error() {
        // error = "invalid address"
        let reply = "error:696e76616c69642061646472657373;";
        let r = MemoryRegionInfo::parse(reply).unwrap();
        assert!(!r.is_mapped());
        assert_eq!(r.error.as_deref(), Some("invalid address"));
    }

    #[test]
    fn memory_region_command_is_hex() {
        assert_eq!(
            MemoryRegionInfo::command(0x1_0000_0000),
            "qMemoryRegionInfo:100000000"
        );
    }

    #[test]
    fn alloc_dealloc_roundtrip() {
        assert_eq!(build_alloc(0x1000, AllocPermissions::rx()), "_M1000,rx");
        assert_eq!(build_alloc(0x20, AllocPermissions::rwx()), "_M20,rwx");
        assert_eq!(build_alloc(8, AllocPermissions::rw()), "_M8,rw");
        assert_eq!(parse_alloc_reply("100010000").unwrap(), 0x1_0001_0000);
        assert_eq!(build_dealloc(0x1_0001_0000), "_m100010000");
        assert!(parse_dealloc_reply("OK").is_ok());
        assert!(parse_dealloc_reply("NO").is_err());
        assert_eq!(
            parse_alloc_reply("E53"),
            Err(LldbExtError::ErrorReply {
                packet: "_M",
                code: 0x53
            })
        );
    }

    #[test]
    fn kv_parser_keeps_colons_inside_values() {
        let kv = parse_kv("set:General Purpose Registers;name:x0;");
        assert_eq!(kv["set"], "General Purpose Registers");
        let kv2 = parse_kv("triple:a:b;");
        assert_eq!(kv2["triple"], "a:b");
    }

    #[test]
    fn hex_to_ascii_rejects_malformed() {
        assert_eq!(hex_to_ascii("6d6163").as_deref(), Some("mac"));
        assert_eq!(hex_to_ascii("6d616"), None); // odd length
        assert_eq!(hex_to_ascii("zzzz"), None);
    }

    #[test]
    fn from_packet_bridges_the_framer() {
        let pkt = RspPacket::new(HOST_INFO_ARM64E.as_bytes().to_vec());
        let hi = from_packet(&pkt, HostInfo::parse).unwrap();
        assert!(hi.is_arm64e());
    }

#[cfg(test)]
mod launch_env_packet_tests {
    use super::{build_environment, build_set_working_dir};

    #[test]
    fn working_dir_and_environment_are_hex_encoded() {
        assert_eq!(
            build_set_working_dir("/private/tmp"),
            "QSetWorkingDir:2f707269766174652f746d70"
        );
        // A value containing `#` — the RSP frame terminator — survives only
        // because the hex form is used; plain `QEnvironment:` would not.
        assert_eq!(build_environment("K", "a#b"), "QEnvironmentHexEncoded:4b3d612362");
    }
}
}
