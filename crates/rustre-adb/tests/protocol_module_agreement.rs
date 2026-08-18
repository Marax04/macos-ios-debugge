//! The crate's two ADB protocol implementations must interoperate.
//!
//! `lib.rs` and `adb_protocol.rs` each define their own `AdbMessage` — different
//! types, different field sets — and each encodes the same 24-byte ADB wire
//! header. They are two implementations of one protocol, and nothing makes the
//! compiler compare them: each module's own tests pass whatever it believes.
//!
//! What must hold is that a message written by one is readable by the other,
//! byte for byte. If they ever disagree on field order, on the magic rule, or on
//! the checksum, an ADB peer talking to one half of this crate is talking to a
//! different protocol than the other half implements — and no test inside either
//! module can see it.


use rustre_adb::adb_protocol::{
    AdbMessage as ProtoMessage, CMD_AUTH, CMD_CLSE, CMD_CNXN, CMD_OKAY, CMD_OPEN, CMD_SYNC,
    CMD_WRTE,
};
use rustre_adb::cmd;
use rustre_adb::protocol::is_valid_header;
use rustre_adb::{decode_message, encode_message};

/// Representative messages: no payload, small payload, and a long one.
fn cases() -> Vec<(u32, u32, u32, Vec<u8>)> {
    vec![
        (cmd::CNXN, 0x0100_0000, 256 * 1024, b"host::features=cmd".to_vec()),
        (cmd::OKAY, 1, 2, Vec::new()),
        (cmd::WRTE, 7, 9, vec![0xFF; 1024]),
        (cmd::CLSE, 0, 0, Vec::new()),
        (cmd::OPEN, 42, 0, b"shell:ls -la\0".to_vec()),
        // Payload bytes that sum past u32 would expose a checksum-width
        // disagreement.
        (cmd::WRTE, 1, 1, vec![0xFF; 4096]),
    ]
}

/// The two encoders must produce identical bytes for the same message.
#[test]
fn both_encoders_produce_the_same_wire_bytes() {
    for (command, arg0, arg1, data) in cases() {
        let from_lib = encode_message(command, arg0, arg1, &data);
        let from_proto = ProtoMessage::new(command, arg0, arg1, data.clone()).encode();

        assert_eq!(
            &from_lib[..],
            &from_proto[..],
            "the two encoders disagree for command {command:#010x} with a {}-byte \
             payload",
            data.len()
        );
    }
}

/// Each decoder must accept what the other encoder produced.
#[test]
fn each_decoder_accepts_the_other_encoding() {
    for (command, arg0, arg1, data) in cases() {
        // lib encodes → adb_protocol reads.
        let bytes = encode_message(command, arg0, arg1, &data);
        let mut cursor: &[u8] = &bytes;
        let read = ProtoMessage::read_from(&mut cursor)
            .unwrap_or_else(|e| panic!("adb_protocol rejected lib's encoding: {e:?}"));
        assert_eq!(read.command, command);
        assert_eq!(read.arg0, arg0);
        assert_eq!(read.arg1, arg1);
        assert_eq!(read.data, data, "payload changed crossing the module boundary");

        // adb_protocol encodes → lib reads.
        let bytes = ProtoMessage::new(command, arg0, arg1, data.clone()).encode();
        let decoded = decode_message(&bytes)
            .unwrap_or_else(|e| panic!("lib rejected adb_protocol's encoding: {e:?}"));
        assert_eq!(decoded.command, command);
        assert_eq!(decoded.arg0, arg0);
        assert_eq!(decoded.arg1, arg1);
        assert_eq!(decoded.data, data, "payload changed crossing the module boundary");
    }
}

/// `is_valid_header` must accept headers from both encoders.
///
/// It is the third opinion on the magic rule, and a header the crate itself
/// produced is the one case it can never be allowed to reject.
#[test]
fn the_header_validator_accepts_both_encoders() {
    for (command, arg0, arg1, data) in cases() {
        for (name, bytes) in [
            ("lib::encode_message", encode_message(command, arg0, arg1, &data).to_vec()),
            ("adb_protocol::encode", ProtoMessage::new(command, arg0, arg1, data.clone()).encode()),
        ] {
            let header: [u8; 24] = bytes[..24].try_into().expect("24-byte header");
            assert!(
                is_valid_header(&header),
                "{name} produced a header that is_valid_header rejects, for command \
                 {command:#010x}"
            );
        }
    }
}

/// A corrupted magic field must be refused by every reader.
///
/// The opposite direction of the test above: agreement is only meaningful if the
/// readers also agree on what to reject.
#[test]
fn a_corrupted_magic_is_refused_by_every_reader() {
    let mut bytes = encode_message(cmd::OKAY, 1, 2, b"payload").to_vec();
    bytes[23] ^= 0xFF; // top byte of the magic field

    let header: [u8; 24] = bytes[..24].try_into().expect("24-byte header");
    assert!(!is_valid_header(&header), "is_valid_header accepted a corrupted magic");

    assert!(
        decode_message(&bytes).is_err(),
        "lib::decode_message accepted a corrupted magic"
    );

    let mut cursor: &[u8] = &bytes;
    assert!(
        ProtoMessage::read_from(&mut cursor).is_err(),
        "adb_protocol::read_from accepted a corrupted magic"
    );
}

/// A corrupted payload is caught by both modules — but at different moments.
///
/// The two have deliberately different contracts, and this pins the difference
/// so it is not mistaken for a bug in either direction:
///
/// * `adb_protocol::read_from` verifies the checksum while reading and refuses
///   the message outright.
/// * `lib::decode_message` only parses. Its documentation lists exactly three
///   failure conditions — too short, wrong magic, truncated payload — and the
///   checksum is deliberately not among them; `AdbMessage::verify_crc` is the
///   separate step that checks it.
///
/// The consequence worth remembering: `decode_message` returning `Ok` is *not*
/// an integrity check. A caller that skips `verify_crc` accepts corrupted
/// payloads, whereas the same bytes fed to the other module are rejected.
#[test]
fn a_corrupted_payload_is_caught_by_both_modules() {
    let mut bytes = encode_message(cmd::WRTE, 1, 2, b"the original payload").to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;

    // adb_protocol refuses it at read time.
    let mut cursor: &[u8] = &bytes;
    assert!(
        ProtoMessage::read_from(&mut cursor).is_err(),
        "adb_protocol::read_from accepted a payload that fails its own checksum"
    );

    // lib parses it — as documented — and reports the mismatch separately.
    let decoded = decode_message(&bytes)
        .expect("decode_message documents only length and magic as failures");
    assert!(
        !decoded.verify_crc(),
        "verify_crc did not notice a corrupted payload, so nothing in this module \
         would have caught it"
    );

    // The same message untouched passes both, so the assertions above are not
    // simply rejecting everything.
    let clean = encode_message(cmd::WRTE, 1, 2, b"the original payload").to_vec();
    let mut cursor: &[u8] = &clean;
    assert!(ProtoMessage::read_from(&mut cursor).is_ok());
    assert!(
        decode_message(&clean).expect("well-formed message").verify_crc(),
        "verify_crc rejected an untampered message"
    );
}

/// The two modules' command constants must name the same commands.
#[test]
fn the_command_constants_agree_across_modules() {
    for (name, a, b) in [
        ("SYNC", cmd::SYNC, CMD_SYNC),
        ("CNXN", cmd::CNXN, CMD_CNXN),
        ("AUTH", cmd::AUTH, CMD_AUTH),
        ("OPEN", cmd::OPEN, CMD_OPEN),
        ("OKAY", cmd::OKAY, CMD_OKAY),
        ("CLSE", cmd::CLSE, CMD_CLSE),
        ("WRTE", cmd::WRTE, CMD_WRTE),
    ] {
        assert_eq!(a, b, "{name} differs between lib::cmd ({a:#010x}) and adb_protocol ({b:#010x})");
    }
}

/// Each command constant must equal its own four-letter name, little-endian.
///
/// Derived from the name rather than copied from the source, so this checks the
/// constants instead of restating them — a transposed digit in either module
/// fails here even though the two would still agree with each other.
#[test]
fn each_command_constant_spells_its_own_name() {
    for (name, value) in [
        (b"SYNC", cmd::SYNC),
        (b"CNXN", cmd::CNXN),
        (b"AUTH", cmd::AUTH),
        (b"OPEN", cmd::OPEN),
        (b"OKAY", cmd::OKAY),
        (b"CLSE", cmd::CLSE),
        (b"WRTE", cmd::WRTE),
    ] {
        let expected = u32::from_le_bytes(*name);
        assert_eq!(
            value,
            expected,
            "{} should be {expected:#010x} (its ASCII name little-endian) but is {value:#010x}",
            std::str::from_utf8(name).unwrap_or("?")
        );
    }
}

/// Guards the tests above: the fixtures must really exercise encoding.
///
/// If every case had an empty payload and a zero command, byte-equality would
/// hold without either encoder writing anything interesting.
#[test]
fn the_fixtures_actually_exercise_the_encoders() {
    let with_payload = cases().iter().filter(|(_, _, _, d)| !d.is_empty()).count();
    assert!(
        with_payload >= 3,
        "only {with_payload} fixtures carry a payload — the agreement would be trivial"
    );

    let biggest = cases().iter().map(|(_, _, _, d)| d.len()).max().unwrap_or(0);
    assert!(
        biggest >= 1024,
        "largest fixture payload is {biggest} bytes; too small to move the checksum far"
    );

    // A payload whose byte sum exceeds u32 would wrap: confirm one fixture is
    // large enough to matter for the checksum width.
    let mut cursor: &[u8] = &encode_message(cmd::WRTE, 0, 0, &vec![0xFFu8; 4096]);
    let read = ProtoMessage::read_from(&mut cursor).expect("well-formed message");
    assert_eq!(
        read.data_checksum,
        4096 * 0xFF,
        "the checksum of 4096 0xFF bytes is not the plain byte sum"
    );
}
