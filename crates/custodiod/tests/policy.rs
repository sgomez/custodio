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

const IMPORT_ID: &str = "com.rfirma.custodio.import-certificate";
const DELETE_ID: &str = "com.rfirma.custodio.delete-certificate";
const REPLACE_ID: &str = "com.rfirma.custodio.replace-certificate";
const OWNER: &str =
    "<annotate key=\"org.freedesktop.policykit.owner\">unix-user:custodio</annotate>";

/// `(id, body)` of every `<action>` element in comment-free XML.
fn actions(xml: &str) -> Vec<(String, String)> {
    xml.split("<action ")
        .skip(1)
        .map(|chunk| {
            let id = chunk
                .split("id=\"")
                .nth(1)
                .and_then(|r| r.split('"').next())
                .unwrap_or_default()
                .to_owned();
            let body = chunk
                .split("</action>")
                .next()
                .unwrap_or_default()
                .to_owned();
            (id, body)
        })
        .collect()
}

/// Exactly one of each `allow_*` tag, all `auth_self`.
fn check_defaults(body: &str) -> Result<(), String> {
    for name in ["allow_any", "allow_inactive", "allow_active"] {
        if body.matches(&format!("<{name}>")).count() != 1 {
            return Err(format!("{name} must appear exactly once"));
        }
        if tag(body, name) != Some("auth_self") {
            return Err(format!("{name} is not auth_self"));
        }
    }
    Ok(())
}

fn check_owner(body: &str) -> Result<(), String> {
    if body.contains(OWNER) {
        Ok(())
    } else {
        Err("owner annotation missing".into())
    }
}

/// Non-empty messages, pairwise distinct.
fn check_messages(messages: &[&str]) -> Result<(), String> {
    for (i, m) in messages.iter().enumerate() {
        if m.is_empty() {
            return Err("empty message".into());
        }
        if messages.iter().take(i).any(|p| p == m) {
            return Err(format!("duplicate message: {m}"));
        }
    }
    Ok(())
}

fn parsed() -> Result<Vec<(String, String)>, Box<dyn Error>> {
    Ok(actions(&without_comments(&policy()?)))
}

#[test]
fn defaults_are_auth_self_for_every_action() -> TestResult {
    for (id, body) in parsed()? {
        check_defaults(&body).map_err(|e| format!("{id}: {e}"))?;
    }
    Ok(())
}

#[test]
fn default_check_rejects_bad_blocks() {
    let good = "<allow_any>auth_self</allow_any><allow_inactive>auth_self</allow_inactive><allow_active>auth_self</allow_active>";
    assert!(check_defaults(good).is_ok());
    assert!(
        check_defaults(&good.replace("<allow_active>auth_self", "<allow_active>auth_admin"))
            .is_err()
    );
    assert!(check_defaults(&good.replace("<allow_active>auth_self</allow_active>", "")).is_err());
    assert!(check_defaults(&format!("{good}{good}")).is_err());
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
fn defines_exactly_the_four_actions() -> TestResult {
    let xml = without_comments(&policy()?);
    let mut ids: Vec<String> = actions(&xml).into_iter().map(|(id, _)| id).collect();
    ids.sort();
    let mut want = vec![ACTION_ID, IMPORT_ID, DELETE_ID, REPLACE_ID];
    want.sort_unstable();
    assert_eq!(ids, want);
    assert_eq!(xml.matches("<allow_").count(), 12);
    Ok(())
}

#[test]
fn messages_are_distinct_and_non_empty() -> TestResult {
    let all = parsed()?;
    let messages: Vec<&str> = all
        .iter()
        .map(|(_, b)| tag(b, "message").unwrap_or(""))
        .collect();
    check_messages(&messages)?;
    for (id, word) in [
        (IMPORT_ID, "import"),
        (DELETE_ID, "delete"),
        (REPLACE_ID, "replace"),
    ] {
        let body = &all.iter().find(|(i, _)| i == id).ok_or(id)?.1;
        let msg = tag(body, "message").unwrap_or("").to_lowercase();
        assert!(msg.contains(word), "{id}: message must name the operation");
    }
    Ok(())
}

#[test]
fn message_check_rejects_equal_and_empty() {
    assert!(check_messages(&["a", "b"]).is_ok());
    assert!(check_messages(&["a", "a"]).is_err());
    assert!(check_messages(&["a", ""]).is_err());
}

#[test]
fn signing_text_is_unchanged() -> TestResult {
    let all = parsed()?;
    let body = &all.iter().find(|(i, _)| i == ACTION_ID).ok_or("sign")?.1;
    assert_eq!(tag(body, "description"), Some("Sign with a custodied key"));
    assert_eq!(
        tag(body, "message"),
        Some("Authentication is required to sign with a key held by Custodio")
    );
    Ok(())
}

#[test]
fn comment_stripping_works() {
    assert_eq!(without_comments("a<!-- x -->b<!-- y"), "ab");
}

/// polkit only lets an unprivileged caller check another user's subject if it owns the action.
#[test]
fn every_action_is_owned_by_the_service_user() -> TestResult {
    for (id, body) in parsed()? {
        check_owner(&body).map_err(|e| format!("{id}: {e}"))?;
    }
    Ok(())
}

#[test]
fn owner_check_rejects_a_block_without_it() {
    assert!(check_owner(OWNER).is_ok());
    assert!(check_owner("<defaults/>").is_err());
}
