use super::*;

#[test]
fn the_entry_point_of_the_fuzz_target_says_whether_the_journal_is_persistent() {
    assert!(fuzz_journald_conf(b"[Journal]\nStorage=persistent\n"));
    assert!(!fuzz_journald_conf(b"[Journal]\nStorage=volatile\n"));
}

#[test]
fn auto_without_the_directory_names_the_line_only_when_it_is_set() {
    let verdict = |text: &str| {
        let files = Files {
            main: Some(File {
                name: "/etc/systemd/journald.conf".into(),
                text: text.into(),
            }),
            drop_ins: Vec::new(),
        };
        evaluate(&files, &JournalDir::Missing)
    };
    assert!(matches!(
        verdict("[Journal]\nStorage=auto\n"),
        Verdict::NotPersistent(Cause::AutoWithoutDirectory(Some(_)))
    ));
    assert_eq!(
        verdict("[Journal]\n#Storage=auto\n"),
        Verdict::NotPersistent(Cause::AutoWithoutDirectory(None))
    );
}
