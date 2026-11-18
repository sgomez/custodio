//! What a successful `custodio import` printed, read back by its layout, not by its wording.
//! Shared with custodio-it by `#[path]`.

#![allow(
    dead_code,
    reason = "each test crate that includes this uses only part of it"
)]

/// The parts of the output.
#[derive(Debug)]
pub struct Imported {
    /// `ok` or `warn`.
    pub word: String,
    /// Key id, key type, storage kind.
    pub cells: Vec<String>,
    /// The lines under the first one, before the next steps.
    pub notes: Vec<String>,
    /// Each next step: the command, and why.
    pub next: Vec<(String, String)>,
}

fn cells(line: &str) -> Vec<String> {
    line.split("  ")
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Panics, naming the output, if it does not have the layout: the key line, indented notes, a
/// blank line, a heading, then two-column rows whose second columns line up.
#[must_use]
pub fn parse(out: &str) -> Imported {
    let mut lines = out.lines();
    let mut first = cells(lines.next().unwrap_or_else(|| panic!("empty: {out:?}")));
    assert!(!first.is_empty(), "{out}");
    let word = first.remove(0);
    let mut notes = Vec::new();
    for line in lines.by_ref() {
        if line.is_empty() {
            break;
        }
        assert!(
            line.starts_with("      "),
            "a note not under the key: {out}"
        );
        notes.push(line.trim().to_owned());
    }
    let heading = lines
        .next()
        .unwrap_or_else(|| panic!("no next steps: {out}"));
    assert!(!heading.starts_with(' ') && heading.ends_with(':'), "{out}");
    let mut next = Vec::new();
    let mut column = None;
    for line in lines {
        assert!(line.starts_with("  "), "a step not indented: {out}");
        let (command, why) = line[2..]
            .split_once("  ")
            .unwrap_or_else(|| panic!("one column: {out}"));
        let at = line.len() - why.trim_start().len();
        assert_eq!(
            *column.get_or_insert(at),
            at,
            "the reasons do not line up: {out}"
        );
        next.push((command.to_owned(), why.trim().to_owned()));
    }
    Imported {
        word,
        cells: first,
        notes,
        next,
    }
}
