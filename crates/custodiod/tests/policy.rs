//! The polkit policy file: every signature must ask, so no default may be a `_keep` variant.

use std::error::Error;

use custodiod::polkit::ACTION_ID;

type TestResult = Result<(), Box<dyn Error>>;

fn policy() -> Result<String, Box<dyn Error>> {
    Ok(std::fs::read_to_string(format!(
        "{}/../../data/com.rfirma.custodio.policy",
        env!("CARGO_MANIFEST_DIR")
    ))?)
}

/// Text between `<tag>` and `</tag>`, for tags that appear once and hold plain text.
fn tag<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let rest = xml.split(&format!("<{name}>")).nth(1)?;
    Some(rest.split(&format!("</{name}>")).next()?.trim())
}

/// The XML with comments removed, so a commented-out `_keep` cannot hide or fake a value.
fn without_comments(xml: &str) -> String {
    let mut out = String::new();
    let mut rest = xml;
    while let Some((before, after)) = rest.split_once("<!--") {
        out.push_str(before);
        rest = after.split_once("-->").map_or("", |(_, tail)| tail);
    }
    out.push_str(rest);
    out
}

#[test]
fn defaults_are_auth_self_for_active_inactive_and_any() -> TestResult {
    let xml = without_comments(&policy()?);
    for name in ["allow_any", "allow_inactive", "allow_active"] {
        assert_eq!(tag(&xml, name), Some("auth_self"), "{name}");
    }
    Ok(())
}

#[test]
fn no_keep_variant_anywhere() -> TestResult {
    let xml = without_comments(&policy()?);
    assert!(
        !xml.contains("_keep"),
        "a _keep variant would cache an authorization"
    );
    Ok(())
}

#[test]
fn defines_exactly_the_sign_action() -> TestResult {
    let xml = without_comments(&policy()?);
    assert_eq!(xml.matches("<action ").count(), 1);
    assert!(xml.contains(&format!("<action id=\"{ACTION_ID}\">")));
    assert_eq!(xml.matches("<allow_").count(), 3);
    Ok(())
}

#[test]
fn comment_stripping_works() {
    assert_eq!(without_comments("a<!-- x -->b<!-- y"), "ab");
}

/// polkit only lets an unprivileged caller check another user's subject if it owns the action.
#[test]
fn the_service_user_owns_the_action() -> TestResult {
    let xml = without_comments(&policy()?);
    assert!(xml.contains(
        "<annotate key=\"org.freedesktop.policykit.owner\">unix-user:custodio</annotate>"
    ));
    Ok(())
}
