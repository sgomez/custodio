//! When a key expires and how times and the header row look.

use super::*;

#[test]
fn expiry_is_judged_at_the_boundaries() {
    let end = now();
    assert_eq!(Expiry::of(None, end), None);
    assert_eq!(Expiry::of(Some(end), end), Some(Expiry::Expired));
    assert_eq!(
        Expiry::of(Some(end), end + Duration::from_secs(1)),
        Some(Expiry::Expired)
    );
    assert_eq!(Expiry::of(Some(end), end - SOON), Some(Expiry::Soon));
    assert_eq!(
        Expiry::of(Some(end), end - SOON - Duration::from_secs(1)),
        Some(Expiry::Valid)
    );
}

#[test]
fn soon_is_thirty_days() {
    let end = now();
    let day = Duration::from_hours(24);
    assert_eq!(Expiry::of(Some(end), end - 30 * day), Some(Expiry::Soon));
    assert_eq!(Expiry::of(Some(end), end - 31 * day), Some(Expiry::Valid));
}

#[test]
fn times_not_in_the_certificate_form_are_shown_unchanged() {
    assert_eq!(
        readable_time("2030-01-02T03:04:05Z"),
        "2030-01-02 03:04:05 UTC"
    );
    assert_eq!(readable_time("2030-01-02T03:04Z"), "2030-01-02T03:04Z");
    assert_eq!(day("2030-01-02T03:04:05Z"), "2030-01-02");
    assert_eq!(day("30-01-02T03:04:05Z"), "30-01-02T03:04:05Z");
}

#[test]
fn only_the_header_row_is_bold() {
    let keys = vec![key("bb", "rsa2048", RSA), key("a", "ecdsa-p256", P256)];
    for terminal in [false, true] {
        let look = Look {
            terminal,
            colour: true,
            ..Look::plain(now())
        };
        let out = table(&keys, look);
        let bold: Vec<bool> = out.lines().map(|l| l.starts_with("\x1b[1m")).collect();
        let want = if terminal {
            vec![true, false, false]
        } else {
            vec![false, false]
        };
        assert_eq!(bold, want, "{out:?}");
    }
}
