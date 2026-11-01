//! The client document `docs/api.md` against its three sources: the live introspection data of the
//! service (interface `com.rfirma.Custodio1` only), `ServiceError::ALL` and the shipped `.policy` file.
//! An item in a source missing from the document fails, and so does an item in the document missing
//! from its source. Bounds other than the `.p12` size are only checked for being present.
//!
//! Document format (prose around it is free), one item per line:
//!
//! ```text
//! ### Method `Name`           starts a method; below it, in order:
//! - in `name`: `sig`          one line per input argument
//! - out: `sig`                one line per result
//! - bounds: ...               required in every method section
//! - p12 size: `N` bytes       the `.p12` bound, in `ImportP12`
//! - certificate size: `N` bytes   the certificate bound, in `ReplaceCertificate`
//! - property `Name`: `sig`, `access`
//! - error `com.rfirma.Custodio1.Error.Name`
//! - action `com.rfirma.custodio.name`
//! ```

// The shared helpers are used in full by other tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "audit/bus.rs"]
mod bus;
#[allow(dead_code, unused_imports)]
#[path = "audit/common.rs"]
mod common;

use std::collections::BTreeSet;
use std::error::Error;
use std::sync::Arc;

use custodio_client::{BUS_NAME, MAX_CERT_LEN, MAX_P12_LEN, OBJECT_PATH};
use custodiod::audit::MemorySink;
use custodiod::error::ServiceError;

const INTERFACE: &str = "com.rfirma.Custodio1";
const SOURCE_MISSING: &str = "source item missing from document";
const DOC_MISSING: &str = "document item missing from source";

type Items = BTreeSet<String>;

fn manifest(path: &str) -> String {
    format!("{}/{path}", env!("CARGO_MANIFEST_DIR"))
}

/// Attribute `key` of the tag text `tag`.
fn attr(tag: &str, key: &str) -> Option<String> {
    let pat = format!(" {key}=\"");
    let start = tag.find(&pat)? + pat.len();
    let len = tag.get(start..)?.find('"')?;
    Some(tag.get(start..start + len)?.to_owned())
}

/// Items of the interface `INTERFACE` in an introspection XML: methods with their arguments (name,
/// direction, signature, position) and properties (signature, access).
fn introspection_items(xml: &str) -> Items {
    let mut items = Items::new();
    let mut rest = xml;
    let mut in_interface = false;
    let mut method = String::new();
    let mut out_index = 0;
    while let Some(open) = rest.find('<') {
        let after = rest.get(open..).unwrap_or_default();
        if let Some(body) = after.strip_prefix("<!--") {
            rest = body.split_once("-->").map_or("", |(_, r)| r);
            continue;
        }
        let Some(close) = after.find('>') else { break };
        let tag = after.get(1..close).unwrap_or_default();
        rest = after.get(close + 1..).unwrap_or_default();
        if tag.starts_with("interface ") {
            in_interface = attr(tag, "name").as_deref() == Some(INTERFACE);
        } else if tag == "/interface" {
            in_interface = false;
        } else if !in_interface {
        } else if tag.starts_with("method ") {
            method = attr(tag, "name").unwrap_or_default();
            out_index = 0;
            items.insert(format!("method {method}"));
        } else if tag == "/method" {
            method.clear();
        } else if tag.starts_with("arg ") && !method.is_empty() {
            let dir = attr(tag, "direction").unwrap_or_default();
            let sig = attr(tag, "type").unwrap_or_default();
            if dir == "out" {
                out_index += 1;
                items.insert(format!("method {method} out #{out_index} {sig}"));
            } else {
                let name = attr(tag, "name").unwrap_or_default();
                items.insert(format!("method {method} in {name} {sig}"));
            }
        } else if tag.starts_with("property ") {
            let name = attr(tag, "name").unwrap_or_default();
            let sig = attr(tag, "type").unwrap_or_default();
            let access = attr(tag, "access").unwrap_or_default();
            items.insert(format!("property {name} {sig} {access}"));
        }
    }
    items
}

fn backticked(line: &str) -> Vec<&str> {
    line.split('`').skip(1).step_by(2).collect()
}

/// What the document lists, in the same key format as the sources, plus the `.p12` bound and the
/// methods with no bounds line.
struct Doc {
    methods: Items,
    errors: Items,
    actions: Items,
    p12_size: Option<String>,
    cert_size: Option<String>,
    without_bounds: Vec<String>,
}

fn parse_doc(text: &str) -> Doc {
    let mut doc = Doc {
        methods: Items::new(),
        errors: Items::new(),
        actions: Items::new(),
        p12_size: None,
        cert_size: None,
        without_bounds: Vec::new(),
    };
    let mut method = String::new();
    let mut out_index = 0;
    let mut has_bounds = true;
    let finish = |doc: &mut Doc, method: &str, has_bounds: bool| {
        if !method.is_empty() && !has_bounds {
            doc.without_bounds.push(method.to_owned());
        }
    };
    for line in text.lines() {
        let ticks = backticked(line);
        if line.starts_with('#') {
            finish(&mut doc, &method, has_bounds);
            method.clear();
        }
        if let Some(h) = line.strip_prefix("### Method ") {
            backticked(h)
                .first()
                .copied()
                .unwrap_or_default()
                .clone_into(&mut method);
            out_index = 0;
            has_bounds = false;
            doc.methods.insert(format!("method {method}"));
        } else if line.starts_with("- in ") && !method.is_empty() {
            if let [name, sig] = ticks[..] {
                doc.methods
                    .insert(format!("method {method} in {name} {sig}"));
            }
        } else if line.starts_with("- out") && !method.is_empty() {
            if let [sig] = ticks[..] {
                out_index += 1;
                doc.methods
                    .insert(format!("method {method} out #{out_index} {sig}"));
            }
        } else if line.starts_with("- bounds:") {
            has_bounds = true;
        } else if line.starts_with("- p12 size:") {
            doc.p12_size = ticks.first().map(|s| (*s).to_owned());
        } else if line.starts_with("- certificate size:") {
            doc.cert_size = ticks.first().map(|s| (*s).to_owned());
        } else if line.starts_with("- property ") {
            if let [name, sig, access] = ticks[..] {
                doc.methods
                    .insert(format!("property {name} {sig} {access}"));
            }
        } else if line.starts_with("- error ") {
            doc.errors.extend(ticks.first().map(|s| (*s).to_owned()));
        } else if line.starts_with("- action ") {
            doc.actions.extend(ticks.first().map(|s| (*s).to_owned()));
        }
    }
    finish(&mut doc, &method, has_bounds);
    doc
}

fn policy_actions(policy: &str) -> Items {
    policy
        .lines()
        .filter(|l| l.trim_start().starts_with("<action "))
        .filter_map(|l| attr(l, "id"))
        .collect()
}

fn diff(kind: &str, source: &Items, doc: &Items, out: &mut Vec<String>) {
    out.extend(
        source
            .difference(doc)
            .map(|i| format!("{SOURCE_MISSING}: {kind} {i}")),
    );
    out.extend(
        doc.difference(source)
            .map(|i| format!("{DOC_MISSING}: {kind} {i}")),
    );
}

/// The three sources, read once.
struct Sources {
    introspection: Items,
    errors: Items,
    actions: Items,
}

/// Every difference between the document text and the sources.
fn differences(text: &str, sources: &Sources) -> Vec<String> {
    let doc = parse_doc(text);
    let mut out = Vec::new();
    diff("interface", &sources.introspection, &doc.methods, &mut out);
    diff("error", &sources.errors, &doc.errors, &mut out);
    diff("action", &sources.actions, &doc.actions, &mut out);
    for m in &doc.without_bounds {
        out.push(format!("method {m} has no bounds entry"));
    }
    let want = MAX_P12_LEN.to_string();
    if doc.p12_size.as_deref() != Some(want.as_str()) {
        out.push(format!(
            ".p12 size bound is {:?}, the code enforces {want}",
            doc.p12_size
        ));
    }
    let want = MAX_CERT_LEN.to_string();
    if doc.cert_size.as_deref() != Some(want.as_str()) {
        out.push(format!(
            "certificate size bound is {:?}, the code enforces {want}",
            doc.cert_size
        ));
    }
    out
}

fn sources() -> Result<Sources, Box<dyn Error>> {
    let xml = zbus::block_on(async {
        let f = common::fixture(bus::Answer::Yes, &Arc::new(MemorySink::default())).await?;
        let m = f
            .client
            .call_method(
                Some(BUS_NAME),
                OBJECT_PATH,
                Some("org.freedesktop.DBus.Introspectable"),
                "Introspect",
                &(),
            )
            .await?;
        let xml: String = m.body().deserialize()?;
        Ok::<_, Box<dyn Error>>(xml)
    })?;
    let introspection = introspection_items(&xml);
    assert!(
        introspection.contains("method Sign"),
        "introspection read nothing useful: {introspection:?}"
    );
    Ok(Sources {
        introspection,
        errors: ServiceError::ALL
            .iter()
            .map(|e| e.error_name().to_owned())
            .collect(),
        actions: policy_actions(&std::fs::read_to_string(manifest(
            "../../data/com.rfirma.custodio.policy",
        ))?),
    })
}

fn expect_fail(text: &str, sources: &Sources, needle: &str, kind: &str) {
    let found = differences(text, sources);
    assert!(
        found.iter().any(|d| d.contains(needle) && d.contains(kind)),
        "expected a difference with {kind:?} naming {needle:?}, got {found:#?}"
    );
}

/// The document `text` with the first `from` replaced by `to`, asserted to differ.
fn edited(text: &str, from: &str, to: &str) -> String {
    assert!(text.contains(from), "the document has no {from:?} to edit");
    text.replacen(from, to, 1)
}

#[test]
fn api_document_matches_its_sources() -> Result<(), Box<dyn Error>> {
    let text = std::fs::read_to_string(manifest("../../docs/api.md")).unwrap_or_default();
    let sources = sources()?;
    let found = differences(&text, &sources);
    assert!(
        found.is_empty(),
        "docs/api.md differs from its sources:\n{}",
        found.join("\n")
    );
    Ok(())
}

#[test]
fn edited_copies_of_the_document_fail() -> Result<(), Box<dyn Error>> {
    let text = std::fs::read_to_string(manifest("../../docs/api.md"))?;
    let sources = sources()?;
    assert_eq!(differences(&text, &sources), Vec::<String>::new());

    // A method removed: its heading and arguments vanish from the document.
    let start = text
        .find("### Method `ImportP12`")
        .ok_or("no ImportP12 section")?;
    let end = text[start + 1..]
        .find("\n### ")
        .map_or(text.len(), |e| start + 1 + e);
    let removed = format!("{}{}", &text[..start], &text[end..]);
    expect_fail(&removed, &sources, "method ImportP12", SOURCE_MISSING);

    // A method that does not exist.
    let extra_method = format!("{text}\n### Method `Bogus`\n- bounds: none\n");
    expect_fail(&extra_method, &sources, "method Bogus", DOC_MISSING);

    // A wrong argument signature: `Sign`'s data `ay` written as `s`.
    let wrong = edited(&text, "- in `data`: `ay`", "- in `data`: `s`");
    expect_fail(&wrong, &sources, "method Sign in data ay", SOURCE_MISSING);
    expect_fail(&wrong, &sources, "method Sign in data s", DOC_MISSING);

    // An extra error name, and one removed.
    let extra_error = format!("{text}\n- error `com.rfirma.Custodio1.Error.Bogus`\n");
    expect_fail(&extra_error, &sources, "Error.Bogus", DOC_MISSING);
    let first = ServiceError::ALL[0].error_name();
    let no_error = edited(&text, &format!("- error `{first}`"), "- gone");
    expect_fail(&no_error, &sources, first, SOURCE_MISSING);

    // An extra action, and the real one removed.
    let extra_action = format!("{text}\n- action `com.rfirma.custodio.bogus`\n");
    expect_fail(
        &extra_action,
        &sources,
        "com.rfirma.custodio.bogus",
        DOC_MISSING,
    );
    let no_action = edited(&text, "- action `com.rfirma.custodio.sign`", "- gone");
    expect_fail(
        &no_action,
        &sources,
        "com.rfirma.custodio.sign",
        SOURCE_MISSING,
    );

    // A wrong `.p12` bound.
    let bound = format!("`{MAX_P12_LEN}`");
    let wrong_bound = edited(&text, &bound, "`1`");
    expect_fail(&wrong_bound, &sources, ".p12 size bound", "");

    // A wrong certificate bound.
    let wrong_cert = edited(&text, &format!("`{MAX_CERT_LEN}`"), "`1`");
    expect_fail(&wrong_cert, &sources, "certificate size bound", "");

    // A method without a bounds entry.
    let no_bounds = edited(&text, "- bounds:", "- limits:");
    expect_fail(&no_bounds, &sources, "has no bounds entry", "");
    Ok(())
}
