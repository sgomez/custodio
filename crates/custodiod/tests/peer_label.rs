//! The peer label parser: the accepted label and every refusal class, each with its own reason.

use custodiod::peer_label::{MAX_LABEL_LEN, Refusal, check};

#[test]
fn accepts_only_the_browser_app_in_enforce_mode() {
    assert_eq!(check(b"snap.firefox.firefox (enforce)"), Ok(()));
}

#[test]
fn every_label_case_has_its_own_reason() {
    use Refusal::*;
    let selinux_inside = b"system_u:snap.firefox.firefox (enforce):s0";
    let cases: Vec<(&[u8], Refusal)> = vec![
        // Another app or hook of the snap (F171: only the browser app).
        (b"snap.firefox.geckodriver (enforce)", OtherApp),
        (b"snap.firefox.hook.install (enforce)", OtherApp),
        (b"snap.firefox.hook.configure (enforce)", OtherApp),
        (b"snap.firefox.firefoxx (enforce)", OtherApp),
        (b"snap.firefox.irefox (enforce)", OtherApp),
        (b"snap.firefox. (enforce)", OtherApp),
        // Another snap, a prefix or suffix, case changes.
        (b"snap.chromium.chromium (enforce)", OtherSnap),
        (b"snap.firefoxx.firefox (enforce)", OtherSnap),
        (b"snap.firefox (enforce)", OtherSnap),
        (b"snap.fire.firefox (enforce)", OtherSnap),
        (b"xsnap.firefox.firefox (enforce)", OtherSnap),
        (b"Snap.firefox.firefox (enforce)", OtherSnap),
        (b"snap.Firefox.firefox (enforce)", OtherSnap),
        (b"snap.firefox.Firefox (enforce)", OtherApp),
        (b"/usr/bin/firefox (enforce)", OtherSnap),
        // Stacked and child profiles are different reasons.
        (b"snap.firefox.firefox//&unconfined (enforce)", Stacked),
        (
            b"snap.firefox.firefox//&snap.firefox.firefox (enforce)",
            Stacked,
        ),
        (b"//& (enforce)", Stacked),
        (b"snap.firefox.firefox//child (enforce)", ChildProfile),
        (b"snap.firefox.firefox// (enforce)", ChildProfile),
        // Mode.
        (b"snap.firefox.firefox (complain)", Complain),
        (b"unconfined", Unconfined),
        (b"snap.firefox.firefox (unconfined)", Unconfined),
        (b"snap.firefox.firefox", MissingMode),
        (b"snap.firefox.firefox (ENFORCE)", BadMode),
        (b"snap.firefox.firefox (Enforce)", BadMode),
        (b"snap.firefox.firefox ( enforce)", BadMode),
        (b"snap.firefox.firefox (enforce", BadMode),
        (b"snap.firefox.firefox (kill)", BadMode),
        (b"snap.firefox.firefox ()", BadMode),
        // Extra text.
        (b" snap.firefox.firefox (enforce)", ExtraText),
        (b"snap.firefox.firefox (enforce) ", ExtraText),
        (b"snap.firefox.firefox (enforce)\n", ExtraText),
        (b"\nsnap.firefox.firefox (enforce)", ExtraText),
        (b"snap.firefox.firefox\n(enforce)", ExtraText),
        (b"snap.firefox.firefox\t(enforce)", ExtraText),
        (b"snap.firefox.firefox  (enforce)", ExtraText),
        (b"snap.firefox.firefox (enforce)x", ExtraText),
        (b"snap.firefox.firefox (enforce) (enforce)", ExtraText),
        (
            b"snap.firefox.firefox (enforce) snap.firefox.firefox (enforce)",
            ExtraText,
        ),
        (b"snap.firefox.firefox x (enforce)", ExtraText),
        (b"snap.firefox.firefox\x01 (enforce)", ExtraText),
        // NUL: anywhere, trailing included (the kernel leaves it out of the length).
        (b"\0snap.firefox.firefox (enforce)", EmbeddedNul),
        (b"snap.firefox\0.firefox (enforce)", EmbeddedNul),
        (b"snap.firefox.firefox\0(enforce)", EmbeddedNul),
        (b"snap.firefox.firefox (enforce)\0", EmbeddedNul),
        (b"snap.firefox.firefox (enforce)\0\0", EmbeddedNul),
        (b"\0", EmbeddedNul),
        (b"", Empty),
        // SELinux contexts are not snap labels, never parsed as one.
        (b"unconfined_u:unconfined_r:unconfined_t:s0", NotSnapLabel),
        (
            b"unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
            NotSnapLabel,
        ),
        (b"system_u:system_r:snappy_t:s0", NotSnapLabel),
        (selinux_inside, NotSnapLabel),
        (b"snap.firefox.firefox:s0 (enforce)", NotSnapLabel),
        // Not UTF-8.
        (b"snap.firefox.firefox (enforce)\xff", NotUtf8),
        (b"\xff", NotUtf8),
        (b"snap.firefox.firefox (enforc\xc3)", NotUtf8),
    ];
    for (label, want) in cases {
        assert_eq!(
            check(label),
            Err(want),
            "{:?}",
            String::from_utf8_lossy(label)
        );
    }
}

#[test]
fn long_input_is_refused_without_its_bytes_in_the_reason() {
    let at_limit = format!(
        "snap.firefox.firefox (enforce){}",
        "a".repeat(MAX_LABEL_LEN - 30)
    );
    assert_eq!(at_limit.len(), MAX_LABEL_LEN);
    assert_eq!(check(at_limit.as_bytes()), Err(Refusal::ExtraText));
    let over = vec![b'a'; MAX_LABEL_LEN + 1];
    assert_eq!(check(&over), Err(Refusal::TooLong));
    let huge = vec![b'a'; 1 << 20];
    assert_eq!(check(&huge), Err(Refusal::TooLong));
}

#[test]
fn reasons_have_fixed_distinct_text_without_label_bytes() {
    use Refusal::*;
    let all = [
        Empty,
        EmbeddedNul,
        NotUtf8,
        TooLong,
        NotSnapLabel,
        Stacked,
        ChildProfile,
        Unconfined,
        Complain,
        MissingMode,
        BadMode,
        OtherSnap,
        OtherApp,
        ExtraText,
    ];
    let texts: std::collections::HashSet<String> = all.iter().map(ToString::to_string).collect();
    assert_eq!(texts.len(), all.len());
    assert!(all.iter().all(|r| r.to_string().len() < 64));
}
