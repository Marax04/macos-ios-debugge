//! Smoke tests — link and trait-bound coverage only.
use rustre_deobf_mba as _;

#[test]
fn smoke_link() {
    // If this test binary builds and runs, the crate links cleanly into a test target.
}

#[test]
fn smoke_send_sync_marker() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<()>();
    assert_sync::<()>();
}
