//! The decisions of `custodio fingerprint enable` and `disable`, from observed values only: no
//! file system, no bus, no temporary directory.

use custodio_cli::fingerprint_decide::{
    DisableDecision, EnableDecision, Family, FileState, Observed, VendorState,
    authselect_has_fingerprint, decide_disable, decide_enable, family_from_os_release, file_bytes,
    first_fprintd_auth_line, is_custodios, lock_note_shown, pam_has_fprintd,
};

const DESIGN_LINES: [&str; 5] = [
    "#%PAM-1.0",
    "auth     [success=done default=ignore] pam_fprintd.so max-tries=1 timeout=10",
    "auth     include /usr/lib/pam.d/polkit-1",
    "account  include /usr/lib/pam.d/polkit-1",
    "password include /usr/lib/pam.d/polkit-1",
];
const SESSION: &str = "session  include /usr/lib/pam.d/polkit-1";

fn base(family: Family) -> Observed {
    Observed {
        euid: 0,
        family,
        polkit_file: FileState::Missing,
        vendor: VendorState::Regular,
        module_present: true,
        fprintd_present: true,
        reader_present: true,
        common_auth: None,
        authselect: None,
        system_auth: None,
        sudo: None,
        gnome_login_schema: false,
        dconf_disables_login_fingerprint: false,
    }
}

fn two_lines(text: &str) {
    assert_eq!(text.lines().count(), 2, "not two lines: {text:?}");
    assert!(!text.ends_with('\n'));
}

fn refusal(d: EnableDecision) -> String {
    match d {
        EnableDecision::Refuse(r) => {
            let m = r.message();
            two_lines(&m);
            m
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn the_file_is_the_five_lines_and_comments_hide_nothing() {
    let text = String::from_utf8(file_bytes().to_vec()).unwrap();
    let active: Vec<&str> = text
        .lines()
        .filter(|l| !l.starts_with('#') || l.starts_with("#%PAM"))
        .collect();
    let mut want: Vec<&str> = DESIGN_LINES.to_vec();
    want.push(SESSION);
    assert_eq!(active, want);
    assert!(text.ends_with('\n'));
    assert_eq!(first_fprintd_auth_line(&text), Some(DESIGN_LINES[1]));
    for c in text.lines().filter(|l| l.starts_with("# ")) {
        assert!(!c.contains("pam_fprintd"), "{c}");
    }
    assert!(
        text.lines().any(|l| l.starts_with("# ")),
        "comments say who wrote it"
    );
}

#[test]
fn a_comment_is_not_an_active_line() {
    let t = "#%PAM-1.0\n# auth sufficient pam_fprintd.so\nauth include x\n";
    assert_eq!(first_fprintd_auth_line(t), None);
    assert!(!pam_has_fprintd(t));
}

#[test]
fn whose_file_it_is() {
    let own = file_bytes();
    assert!(is_custodios(own));
    for i in 0..own.len() {
        let mut b = own.to_vec();
        b[i] ^= 1;
        assert!(!is_custodios(&b), "byte {i}");
    }
    let mut longer = own.to_vec();
    longer.push(b'\n');
    assert!(!is_custodios(&longer));
    assert!(!is_custodios(&own[..own.len() - 1]));
    let crlf = String::from_utf8(own.to_vec())
        .unwrap()
        .replace('\n', "\r\n");
    assert!(!is_custodios(crlf.as_bytes()));
    assert!(!is_custodios(b""));
    assert!(!is_custodios(b"auth sufficient pam_fprintd.so\n"));
}

#[test]
fn pam_detection_forms() {
    for (text, want) in [
        ("auth sufficient pam_fprintd.so\n", true),
        ("auth\tsufficient\tpam_fprintd.so\n", true),
        ("-auth sufficient pam_fprintd.so\n", true),
        (
            "auth [success=done default=ignore] pam_fprintd.so max-tries=1\n",
            true,
        ),
        ("auth sufficient /usr/lib/security/pam_fprintd.so\n", true),
        ("auth required pam_fprintd.so\n", true),
        ("# auth sufficient pam_fprintd.so\n", false),
        ("   # auth sufficient pam_fprintd.so\n", false),
        ("auth sufficient pam_unix.so # pam_fprintd.so\n", false),
        ("account required pam_fprintd.so\n", false),
        ("auth include system-auth\n", false),
        ("auth sufficient pam_fprintd_grosshack.so\n", false),
        ("", false),
    ] {
        assert_eq!(pam_has_fprintd(text), want, "{text:?}");
    }
}

#[test]
fn authselect_features() {
    for (text, want) in [
        ("sssd\nwith-fingerprint\nwith-mkhomedir\n", true),
        ("sssd\nwith-mkhomedir\n", false),
        ("sssd\nwith-fingerprint-extra\n", false),
        ("sssd\n# with-fingerprint\n", false),
        (
            "Profile ID: sssd\nEnabled features:\n- with-fingerprint\n",
            true,
        ),
        ("sssd\r\nwith-fingerprint\r\n", true),
        ("", false),
    ] {
        assert_eq!(authselect_has_fingerprint(text), want, "{text:?}");
    }
}

#[test]
fn the_family_comes_from_os_release() {
    for (text, want) in [
        ("ID=ubuntu\nID_LIKE=debian\n", Family::Debian),
        ("ID=debian\n", Family::Debian),
        ("ID=\"fedora\"\n", Family::Fedora),
        (
            "ID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\n",
            Family::Fedora,
        ),
        ("ID=bazzite\nID_LIKE=\"fedora\"\n", Family::Fedora),
        ("ID=arch\n", Family::Arch),
        ("ID=omarchy\nID_LIKE=arch\n", Family::Arch),
        ("ID=nixos\n", Family::Unknown),
        ("", Family::Unknown),
    ] {
        assert_eq!(family_from_os_release(text), want, "{text:?}");
    }
}

#[test]
fn enable_success_and_already_enabled() {
    let d = decide_enable(&base(Family::Debian));
    assert_eq!(
        d,
        EnableDecision::Write {
            warn_no_reader: false,
            lock_note: false
        }
    );
    let mut o = base(Family::Debian);
    o.polkit_file = FileState::Regular(file_bytes().to_vec());
    assert_eq!(decide_enable(&o), EnableDecision::AlreadyEnabled);
    // Already Custodio's wins over a global switch: nothing to write, success.
    o.common_auth = Some("auth sufficient pam_fprintd.so\n".into());
    assert_eq!(decide_enable(&o), EnableDecision::AlreadyEnabled);
}

#[test]
fn no_reader_is_a_warning() {
    let mut o = base(Family::Debian);
    o.reader_present = false;
    assert_eq!(
        decide_enable(&o),
        EnableDecision::Write {
            warn_no_reader: true,
            lock_note: false
        }
    );
    let w = custodio_cli::fingerprint_decide::NO_READER_WARNING;
    assert!(w.contains("custodio doctor") && w.contains("password"));
}

#[test]
fn not_root() {
    let mut o = base(Family::Debian);
    o.euid = 1000;
    let m = refusal(decide_enable(&o));
    assert!(m.contains("root") && m.contains("sudo custodio fingerprint enable"));
    // Not root comes first, before any other state.
    o.vendor = VendorState::Missing;
    assert!(refusal(decide_enable(&o)).contains("root"));
    assert_eq!(
        decide_disable(&o).refusal_text().map(|m| {
            two_lines(&m);
            m.contains("root")
        }),
        Some(true)
    );
}

#[test]
fn foreign_files() {
    let omarchy = b"#%PAM-1.0\nauth sufficient pam_fprintd.so\nauth include system-auth\n".to_vec();
    let mut changed = file_bytes().to_vec();
    changed[12] ^= 1;
    for f in [
        FileState::Regular(omarchy),
        FileState::Regular(b"auth include x\n".to_vec()),
        FileState::Regular(changed),
        FileState::Regular(Vec::new()),
        FileState::NotRegular,
    ] {
        let mut o = base(Family::Debian);
        o.polkit_file = f;
        let m = refusal(decide_enable(&o));
        assert!(m.contains("/etc/pam.d/polkit-1"), "{m}");
        assert!(
            m.contains("custodio fingerprint disable") || m.contains("not Custodio"),
            "{m}"
        );
    }
}

#[test]
fn vendor_module_and_fprintd() {
    for v in [VendorState::Missing, VendorState::NotRegular] {
        let mut o = base(Family::Fedora);
        o.vendor = v;
        let m = refusal(decide_enable(&o));
        assert!(m.contains("/usr/lib/pam.d/polkit-1"), "{m}");
    }
    for (family, names) in [
        (Family::Debian, vec!["libpam-fprintd", "fprintd"]),
        (Family::Fedora, vec!["fprintd-pam", "fprintd"]),
        (Family::Arch, vec!["fprintd"]),
        (
            Family::Unknown,
            vec!["libpam-fprintd", "fprintd-pam", "fprintd"],
        ),
    ] {
        let mut o = base(family);
        o.module_present = false;
        let m = refusal(decide_enable(&o));
        assert!(m.contains("pam_fprintd.so"), "{m}");
        for n in &names {
            assert!(m.contains(n), "{family:?}: {m}");
        }
        if family == Family::Arch {
            assert!(!m.contains("libpam-fprintd") && !m.contains("fprintd-pam"));
        }
        let mut o = base(family);
        o.fprintd_present = false;
        let m = refusal(decide_enable(&o));
        for n in &names {
            assert!(m.contains(n), "{family:?}: {m}");
        }
    }
}

#[derive(Clone, Copy)]
enum Place {
    CommonAuth,
    Authselect,
    SystemAuth,
    Sudo,
}

const ON: &str = "auth sufficient pam_fprintd.so\n";
const OFF: &str = "auth sufficient pam_unix.so\n";
const FEATURE: &str = "sssd\nwith-fingerprint\n";

#[test]
fn global_fingerprint_is_refused_per_family() {
    use Family::{Arch, Debian, Fedora, Unknown};
    use Place::{Authselect, CommonAuth, Sudo, SystemAuth};
    let cases = [
        (Debian, CommonAuth, ON, true),
        (Debian, CommonAuth, OFF, false),
        (Debian, Sudo, ON, false),
        (Debian, Authselect, FEATURE, false),
        (Fedora, Authselect, FEATURE, true),
        (Fedora, Authselect, "sssd\n", false),
        (Fedora, CommonAuth, ON, false),
        (Arch, SystemAuth, ON, true),
        (Arch, Sudo, ON, true),
        (Arch, Sudo, OFF, false),
        (Arch, CommonAuth, ON, false),
        (Unknown, CommonAuth, ON, true),
        (Unknown, SystemAuth, ON, true),
        (Unknown, Sudo, ON, true),
        (Unknown, Authselect, FEATURE, true),
        (Unknown, Authselect, "sssd\n", false),
    ];
    for (i, (family, place, text, refused)) in cases.into_iter().enumerate() {
        let mut o = base(family);
        let slot = match place {
            CommonAuth => &mut o.common_auth,
            Authselect => &mut o.authselect,
            SystemAuth => &mut o.system_auth,
            Sudo => &mut o.sudo,
        };
        *slot = Some(text.to_owned());
        let d = decide_enable(&o);
        if refused {
            let m = refusal(d);
            assert!(m.contains("redundant"), "case {i}: {m}");
            assert!(m.contains("again"), "case {i}: {m}");
        } else {
            assert!(matches!(d, EnableDecision::Write { .. }), "case {i}: {d:?}");
        }
    }
    // Nothing anywhere, unknown family: no refusal.
    assert!(matches!(
        decide_enable(&base(Unknown)),
        EnableDecision::Write { .. }
    ));
}

#[test]
fn disable_decisions() {
    let mut o = base(Family::Debian);
    assert_eq!(decide_disable(&o), DisableDecision::NothingToDisable);
    o.polkit_file = FileState::Regular(file_bytes().to_vec());
    assert_eq!(decide_disable(&o), DisableDecision::Remove);
    for f in [
        FileState::Regular(b"auth include x\n".to_vec()),
        FileState::NotRegular,
    ] {
        o.polkit_file = f;
        let m = decide_disable(&o).refusal_text().expect("refused");
        two_lines(&m);
        assert!(
            m.contains("not Custodio")
                && m.contains("pacman -Qo")
                && m.contains("dpkg -S")
                && m.contains("rpm -qf"),
            "{m}"
        );
    }
    // Disable needs neither the vendor file nor the module.
    o.polkit_file = FileState::Regular(file_bytes().to_vec());
    o.vendor = VendorState::Missing;
    o.module_present = false;
    assert_eq!(decide_disable(&o), DisableDecision::Remove);
}

#[test]
fn the_lock_screen_note() {
    // (schema present, key set false, family) -> shown
    for (schema, off, family, shown) in [
        (false, false, Family::Debian, false),
        (true, false, Family::Debian, true),
        (true, true, Family::Debian, false),
        (true, false, Family::Fedora, false),
        (true, false, Family::Arch, true),
        // Unknown family: the conservative choice is to show it.
        (true, false, Family::Unknown, true),
        (false, false, Family::Unknown, false),
    ] {
        assert_eq!(
            lock_note_shown(schema, off, family),
            shown,
            "{schema} {off} {family:?}"
        );
    }
    let mut o = base(Family::Debian);
    o.gnome_login_schema = true;
    assert_eq!(
        decide_enable(&o),
        EnableDecision::Write {
            warn_no_reader: false,
            lock_note: true
        }
    );
    o.dconf_disables_login_fingerprint = true;
    assert_eq!(
        decide_enable(&o),
        EnableDecision::Write {
            warn_no_reader: false,
            lock_note: false
        }
    );
}

#[test]
fn dconf_key_detection() {
    use custodio_cli::fingerprint_decide::dconf_disables_fingerprint;
    assert!(dconf_disables_fingerprint(
        "[org/gnome/login-screen]\nenable-fingerprint-authentication=false\n"
    ));
    assert!(dconf_disables_fingerprint(
        "[org/gnome/login-screen]\nenable-fingerprint-authentication = false\n"
    ));
    assert!(!dconf_disables_fingerprint(
        "[org/gnome/login-screen]\nenable-fingerprint-authentication=true\n"
    ));
    assert!(!dconf_disables_fingerprint(
        "#enable-fingerprint-authentication=false\n"
    ));
    assert!(!dconf_disables_fingerprint(""));
}

#[test]
fn the_fuzz_entry_reports_an_active_fingerprint_line() {
    assert!(custodio_cli::fingerprint_decide::fuzz_pam_file(
        b"auth sufficient pam_fprintd.so\n"
    ));
    assert!(!custodio_cli::fingerprint_decide::fuzz_pam_file(
        b"# auth sufficient pam_fprintd.so\n"
    ));
}

#[test]
fn a_refusal_prints_its_two_lines() {
    let mut o = base(Family::Debian);
    o.euid = 1000;
    let EnableDecision::Refuse(r) = decide_enable(&o) else {
        panic!("not a refusal");
    };
    assert_eq!(r.to_string(), r.message());
    assert_eq!(r.to_string().lines().count(), 2);
}
