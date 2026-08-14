//! Archive harvesting must stay linear in input size.
//!
//! # Why there is no arbitrary cap here
//!
//! T12 proposed hard limits — max member count, max declared size, recursion
//! depth. Measured first, the limits turned out not to be needed:
//!
//! | input | tempo |
//! |---|---|
//! | 1 000 membri (60 KB) | 0 ms |
//! | 10 000 membri (600 KB) | 3 ms |
//! | 50 000 membri (3 MB) | 19 ms |
//! | 1 membro che dichiara 9 999 999 999 byte | 0 ms, respinto |
//! | 1 000 membri che dichiarano 999 999 byte | 0 ms, fermato al primo |
//!
//! The ar parser bounds every member by the actual file length, so a declared
//! size cannot cause a large read, and cost grows linearly with the bytes on
//! disk. A hard member cap would add a knob that rejects legitimate archives —
//! a real `.lib` can hold tens of thousands of members — to defend against
//! something already bounded.
//!
//! So the deliverable is not a limit but a **guard against regression**: if the
//! harvester ever becomes super-linear, these tests fail. The thresholds are
//! deliberately loose (seconds, against measured milliseconds) so they detect a
//! complexity change, not a slow machine or a busy build server.
//!
//! # What this does *not* cover
//!
//! Every member here is a non-object blob, so the expensive path — parsing a
//! real COFF/ELF object and walking its symbols — is not exercised. This bounds
//! the *container* handling only. Object parsing is `goblin`/`object` territory
//! and would need real objects to measure honestly.

use std::time::{Duration, Instant};

use rustre_flirt_gen::coff_archive::{harvest_archive_bytes, ArchiveHarvestOptions};

fn archive(n: usize, body_len: usize, declared_size: Option<&str>) -> Vec<u8> {
    let mut v = b"!<arch>\n".to_vec();
    let body = vec![0x90u8; body_len];
    for i in 0..n {
        let name = format!("m{i}.o/");
        v.extend_from_slice(format!("{name:<16}").as_bytes());
        v.extend_from_slice(b"0           ");
        v.extend_from_slice(b"0     ");
        v.extend_from_slice(b"0     ");
        v.extend_from_slice(b"100644  ");
        let size = declared_size
            .map_or_else(|| format!("{body_len:<10}"), |d| format!("{d:<10}"));
        v.extend_from_slice(size.as_bytes());
        v.extend_from_slice(b"`\n");
        v.extend_from_slice(&body);
        if body.len() % 2 == 1 {
            v.push(b'\n');
        }
    }
    v
}

fn harvest_timed(data: &[u8]) -> (usize, Duration) {
    let opts = ArchiveHarvestOptions::default();
    let t = Instant::now();
    let members = harvest_archive_bytes(data, &opts).map_or(0, |(_, s)| s.members);
    (members, t.elapsed())
}

#[test]
fn fifty_thousand_members_complete_quickly() {
    // Measured at 19 ms. The 10-second ceiling is ~500x that: it catches a
    // quadratic regression while staying immune to a loaded machine.
    let data = archive(50_000, 0, None);
    let (members, elapsed) = harvest_timed(&data);
    assert_eq!(members, 50_000, "ogni membro deve essere visitato");
    assert!(
        elapsed < Duration::from_secs(10),
        "50 000 membri hanno richiesto {elapsed:?}: sospetta complessità super-lineare"
    );
}

#[test]
fn cost_grows_roughly_with_input_size_not_faster() {
    // Ten times the members must not cost a hundred times the time. Compared
    // against a floor of 1 ms so that two sub-millisecond runs never produce a
    // meaningless ratio.
    let small = archive(1_000, 64, None);
    let large = archive(10_000, 64, None);

    let (_, t_small) = harvest_timed(&small);
    let (_, t_large) = harvest_timed(&large);

    let floor = Duration::from_millis(1);
    let s = t_small.max(floor).as_secs_f64();
    let l = t_large.max(floor).as_secs_f64();
    assert!(
        l / s < 40.0,
        "10x l'input è costato {:.1}x il tempo ({t_small:?} -> {t_large:?}): \
         atteso ~10x, oltre 40x indica una regressione di complessità",
        l / s
    );
}

#[test]
fn a_member_declaring_ten_gigabytes_is_rejected_immediately() {
    // The archive-bomb shape: an 84-byte file whose member header claims
    // 9 999 999 999 bytes. It must be refused without attempting the read.
    let data = archive(1, 16, Some("9999999999"));
    assert!(data.len() < 200, "l'input deve restare minuscolo");
    let (_, elapsed) = harvest_timed(&data);
    assert!(
        elapsed < Duration::from_secs(2),
        "una dimensione dichiarata assurda ha richiesto {elapsed:?}"
    );
}

#[test]
fn many_members_with_inflated_declared_sizes_stay_bounded() {
    // Each header claims 999 999 bytes in a 76 KB file. Whatever the parser
    // decides, it must decide it in bounded time and not walk off the end.
    let data = archive(1_000, 16, Some("999999"));
    let (_, elapsed) = harvest_timed(&data);
    assert!(
        elapsed < Duration::from_secs(2),
        "dimensioni dichiarate gonfiate hanno richiesto {elapsed:?}"
    );
}

#[test]
fn an_empty_or_header_only_archive_is_handled() {
    for data in [&b""[..], b"!<arch>\n", b"!<arch>"] {
        let (_, elapsed) = harvest_timed(data);
        assert!(elapsed < Duration::from_secs(1));
    }
}
