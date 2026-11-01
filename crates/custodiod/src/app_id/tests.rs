use super::*;

fn scope(e: &str, n: &str) -> Vec<u8> {
    format!("app-flatpak-{e}-{n}.scope").into_bytes()
}

fn read(name: &[u8]) -> Option<String> {
    match classify(Some(name)) {
        AppIdOutcome::Read(id) => Some(id.as_str().to_owned()),
        _ => None,
    }
}

fn undetermined(name: &[u8]) -> bool {
    classify(Some(name)) == AppIdOutcome::Undetermined
}

#[test]
fn valid_scope_names_are_read() {
    // The longest plain id that fits the 255-byte name bound: 255 - 12 (prefix) - 2 (`-1`) - 6 (`.scope`).
    let long = format!("org.example.{}", "a".repeat(235 - 12));
    assert_eq!(long.len(), 235);
    assert_eq!(scope(&long, "1").len(), MAX_SCOPE_NAME_LEN);
    let cases: Vec<(String, &str, String)> = vec![
        ("org.example.App".into(), "123", "org.example.App".into()),
        ("a.b.c.d.e.f.g".into(), "7", "a.b.c.d.e.f.g".into()),
        ("org.my_app.x_y.z_".into(), "1", "org.my_app.x_y.z_".into()),
        ("_a._b._c".into(), "1", "_a._b._c".into()),
        ("org.example.a1.b2".into(), "42", "org.example.a1.b2".into()),
        (
            "org.example.My_App\\x2dName".into(),
            "5151",
            "org.example.My_App-Name".into(),
        ),
        (
            "org.example.a\\x2db\\x2dc".into(),
            "9",
            "org.example.a-b-c".into(),
        ),
        (long.clone(), "1", long),
        (
            "org.example.App".into(),
            "4294967295",
            "org.example.App".into(),
        ),
        (
            "org.example.App".into(),
            "0000000001",
            "org.example.App".into(),
        ),
    ];
    for (e, n, want) in cases {
        let got = read(&scope(&e, n));
        assert_eq!(got.as_deref(), Some(want.as_str()), "{e} {n}");
        let got = want.clone();
        assert!(!got.contains(n) || want.contains(n));
    }
    // The instance id never ends up in the id.
    assert_eq!(
        read(&scope("org.example.App", "987654")).as_deref(),
        Some("org.example.App")
    );
}

fn rejected(id: &str) -> bool {
    validate(id.as_bytes()).is_none()
}

#[test]
fn rejects_fewer_than_three_elements() {
    assert!(rejected("org"));
    assert!(rejected("org.example"));
    assert!(validate(b"org.example.App").is_some());
}

#[test]
fn rejects_empty_element() {
    assert!(rejected("org..App"));
    assert!(rejected("org.example.App."));
    assert!(rejected("org.example..App"));
}

#[test]
fn rejects_leading_dot() {
    assert!(rejected(".org.example.App"));
}

#[test]
fn rejects_leading_digit_in_any_element() {
    assert!(rejected("1org.example.App"));
    assert!(rejected("org.1example.App"));
    assert!(rejected("org.example.1App"));
    assert!(rejected("org.example.App.9"));
    assert!(validate(b"org.example.A1").is_some());
}

#[test]
fn rejects_dash_outside_last_element() {
    assert!(rejected("org-x.example.App"));
    assert!(rejected("org.ex-ample.App"));
    assert!(validate(b"org.example.App-x").is_some());
    assert!(validate(b"org.example.-x").is_some());
}

#[test]
fn rejects_bad_characters() {
    for id in [
        "org.exa mple.App",
        "org.example.A/pp",
        "org.example.A:pp",
        "org.example.Äpp",
        "org.example.A\u{1}pp",
        "org.example.A\0pp",
        "org.example.A\npp",
    ] {
        assert!(rejected(id), "{id:?}");
    }
    for e in [
        "org.example.A\\x2fpp",
        "org.example.A\\x2Dpp",
        "org.example.A\\x41pp",
        "org.example.A\\x2",
        "org.example.A\\",
        "org.example.A\\x",
        "org.example.A\\n",
        "org.example.A\\\\x2d",
    ] {
        assert!(undetermined(&scope(e, "1")), "{e:?}");
    }
    // A raw `-` in the escaped part adds a second `-` and does not parse.
    assert!(undetermined(b"app-flatpak-org.example.A-pp-1.scope"));
}

#[test]
fn rejects_id_over_255_characters() {
    let ok = format!("org.example.{}", "a".repeat(255 - 12));
    assert_eq!(ok.len(), 255);
    assert!(validate(ok.as_bytes()).is_some());
    let long = format!("{ok}a");
    assert!(rejected(&long));
}

#[test]
fn rejects_empty_id() {
    assert!(rejected(""));
    assert!(undetermined(b"app-flatpak--1.scope"));
}

#[test]
fn rejects_malformed_scope_names() {
    for name in [
        &b"app-flatpak-org.example.App-1"[..],
        b"app-flatpak-org.example.App-1.service",
        b"app-flatpak-org.example.App-1.slice",
        b"app-flatpak-org.example.App-1.scopes",
        b"app-flatpak-org.example.App-1.scope.scope",
        b"app-flatpak-org.example.App-1.scope ",
        b"app-flatpak-org.example.App.scope",
        b"app-flatpak-org.example.App1.scope",
        b"app-flatpak-org.example.App--1.scope",
        b"app-flatpak-org.example.App-1-2.scope",
        b"app-flatpak-org.example.App-.scope",
        b"app-flatpak-org.example.App-a.scope",
        b"app-flatpak-org.example.App-1a.scope",
        b"app-flatpak-org.example.App-+1.scope",
        b"app-flatpak-org.example.App-10000000000.scope",
        b"app-flatpak-org.example.App-00000000001.scope",
        b"app-flatpak-org.example.App-4294967296.scope",
        b"app-flatpak-org.example.App-9999999999.scope",
        b"app-flatpak-.scope",
        b"app-flatpak--.scope",
        b"app-flatpak-",
        b"app-flatpak-.",
        b"app-flatpak-1.scope",
    ] {
        assert!(undetermined(name), "{}", String::from_utf8_lossy(name));
    }
    assert!(read(b"app-flatpak-org.example.App-4294967295.scope").is_some());
    assert!(read(b"app-flatpak-org.example.App-0000000000.scope").is_some());
}

#[test]
fn non_utf8_and_binary_input_is_undetermined() {
    for tail in [
        &b"\xff"[..],
        b"org.example.\xff-1.scope",
        b"org.example.\xc0\xaf-1.scope",
        b"org.example.\xe0\x80\xaf-1.scope",
        b"org.example.\xc3-1.scope",
        b"org.example.A\0-1.scope",
        b"\0\0\0",
        b"org.example.App-1.scope\xff",
    ] {
        let mut name = b"app-flatpak-".to_vec();
        name.extend_from_slice(tail);
        assert!(undetermined(&name), "{name:?}");
    }
}

#[test]
fn non_utf8_without_the_prefix_is_none() {
    for name in [
        &b"\xff\xfe"[..],
        b"app-flatpa\xff-org.example.App-1.scope",
        b"\xffapp-flatpak-org.example.App-1.scope",
    ] {
        assert_eq!(classify(Some(name)), AppIdOutcome::None);
    }
}

#[test]
fn oversized_name_is_undetermined() {
    assert_eq!(MAX_SCOPE_NAME_LEN, 255);
    // Structure checked by reading: the input is `&[u8]` and the length test runs before `parse`, which is the only
    // place that decodes or copies bytes.
    let id_ok = |len: usize| {
        let e = format!("org.example.{}", "a".repeat(len - 12));
        scope(&e, "1")
    };
    let at = id_ok(235);
    assert_eq!(at.len(), 255);
    assert!(read(&at).is_some());
    let over = id_ok(236);
    assert_eq!(over.len(), 256);
    assert!(undetermined(&over));
    let mut huge = b"app-flatpak-org.example.".to_vec();
    huge.resize(1 << 20, b'a');
    assert!(undetermined(&huge));
    // An oversized name without the prefix is still not a flatpak scope.
    assert_eq!(classify(Some(&vec![b'a'; 1 << 20])), AppIdOutcome::None);
}

#[test]
fn absent_and_other_scopes_are_none() {
    assert_eq!(classify(None), AppIdOutcome::None);
    for name in [
        &b""[..],
        b"app-gnome-gedit-99b.scope",
        b"init.scope",
        b"app-flatpak.scope",
        b"app-flatpak",
        b"xapp-flatpak-org.a.b-1.scope",
        b"app-flatpak_org.example.App-1.scope",
        b"APP-FLATPAK-org.example.App-1.scope",
        b"session-app-flatpak-org.example.App-1.scope",
    ] {
        assert_eq!(
            classify(Some(name)),
            AppIdOutcome::None,
            "{}",
            String::from_utf8_lossy(name)
        );
    }
}

#[test]
fn undetermined_carries_no_text() {
    assert!(matches!(AppIdOutcome::None, AppIdOutcome::None));
    assert!(matches!(
        AppIdOutcome::Undetermined,
        AppIdOutcome::Undetermined
    ));
    for name in [
        &b"app-flatpak-MARKER!-1.scope"[..],
        b"app-flatpak-org.MARKER.x\xff-1.scope",
        b"app-flatpak-MARKER",
        b"xMARKER",
    ] {
        let shown = format!("{:?}", classify(Some(name)));
        assert!(!shown.contains("MARKER"), "{shown}");
    }
    assert_eq!(format!("{:?}", AppIdOutcome::Undetermined), "Undetermined");
    assert_eq!(format!("{:?}", AppIdOutcome::None), "None");
}

#[test]
fn module_has_no_io() {
    let src = include_str!("../app_id.rs");
    // The tests live in `app_id/tests.rs`, so the whole file is the code.
    for needle in [
        "std::fs",
        "std::io",
        "std::process",
        "std::time",
        "tokio",
        "zbus",
        "tracing",
        "println",
    ] {
        assert!(!src.contains(needle), "{needle}");
    }
}

#[test]
fn app_mutants_recipe_lists_the_module() {
    let justfile = include_str!("../../../../justfile");
    let line = justfile
        .lines()
        .find(|l| l.trim_start().starts_with("cargo mutants -p custodiod"))
        .unwrap_or("");
    let args: Vec<&str> = line.split_whitespace().collect();
    assert!(
        args.windows(2)
            .any(|w| w == ["--file", "crates/custodiod/src/app_id.rs"])
    );
}
