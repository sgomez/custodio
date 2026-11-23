//! What a command printed in the shared line format (`report.rs`), read back by its layout, not
//! by its wording: a line that starts at the margin with a state word, then the indented lines
//! under it. Shared with custodio-it by `#[path]`.

#![allow(
    dead_code,
    reason = "each test crate that includes this uses only part of it"
)]

/// One line and what is under it.
#[derive(Debug, Clone)]
pub struct Imported {
    /// `ok`, `FAIL`, `warn` or `?`.
    pub word: String,
    /// The name, then each cell of the text.
    pub cells: Vec<String>,
    /// The lines under it, in order.
    pub under: Vec<String>,
}

const WORDS: [&str; 4] = ["ok", "FAIL", "warn", "?"];
/// Under-lines start below the name: the word column (4) and two spaces.
const UNDER: &str = "      ";

fn cells(line: &str) -> Vec<String> {
    line.split("  ")
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Every line of `out`. Panics, naming the output, on a line that is neither a state line at the
/// margin, nor under one at the name column, nor blank.
#[must_use]
pub fn parse_all(out: &str) -> Vec<Imported> {
    let mut all: Vec<Imported> = Vec::new();
    for line in out.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix(UNDER) {
            assert!(!rest.starts_with(' '), "not at the name column: {out}");
            let last = all
                .last_mut()
                .unwrap_or_else(|| panic!("an indented line first: {out}"));
            last.under.push(rest.to_owned());
            continue;
        }
        let mut c = cells(line);
        let word = c.remove(0);
        assert!(
            WORDS.contains(&word.as_str()),
            "no state word: {line:?} in {out}"
        );
        let after = &line[word.len()..];
        assert_eq!(
            word.len() + after.len() - after.trim_start().len(),
            UNDER.len(),
            "the name is not at its column: {out}"
        );
        all.push(Imported {
            word,
            cells: c,
            under: Vec::new(),
        });
    }
    all
}

/// The one line `out` holds.
#[must_use]
pub fn parse(out: &str) -> Imported {
    let mut all = parse_all(out);
    assert_eq!(all.len(), 1, "not one line: {out}");
    all.remove(0)
}

/// The command after `shred -u ` in an under-line, if there is one.
#[must_use]
pub fn shred_target(line: &Imported) -> Option<String> {
    line.under
        .iter()
        .find_map(|u| u.split_once("shred -u ").map(|(_, t)| t.to_owned()))
}
