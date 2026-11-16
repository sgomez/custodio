use super::*;

#[test]
fn the_entry_point_of_the_fuzz_target_says_whether_the_journal_is_persistent() {
    assert!(fuzz_journald_conf(b"[Journal]\nStorage=persistent\n"));
    assert!(!fuzz_journald_conf(b"[Journal]\nStorage=volatile\n"));
}
