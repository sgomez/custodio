//! Output in the shared line format (`custodio_cli::report`), read back by its layout: a state
//! word, a name, a text, and the lines under the name.

#![allow(
    dead_code,
    reason = "each test crate that includes this uses only part of it"
)]

use custodio_cli::report::{State, WORD_WIDTH};

/// One line and what is under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub state: State,
    pub name: String,
    pub text: String,
    pub under: Vec<String>,
}

impl Row {
    /// The `Fix:` lines under it, without the label.
    #[must_use]
    pub fn fixes(&self) -> Vec<&str> {
        self.under
            .iter()
            .filter_map(|u| u.strip_prefix("Fix: "))
            .collect()
    }
}

const STATES: [State; 4] = [State::Ok, State::NotOk, State::Warn, State::CouldNotCheck];

/// Panics, naming the output, on a line that is neither a row nor under one, or on names that do
/// not line up.
#[must_use]
pub fn rows(out: &str) -> Vec<Row> {
    let under = " ".repeat(WORD_WIDTH + 2);
    let mut rows: Vec<Row> = Vec::new();
    let mut column = None;
    for line in out.lines().filter(|l| !l.trim().is_empty()) {
        if let Some(rest) = line.strip_prefix(&under) {
            let last = rows
                .last_mut()
                .unwrap_or_else(|| panic!("a line under nothing: {out}"));
            assert!(!rest.starts_with(' '), "misaligned: {line:?} in {out}");
            last.under.push(rest.to_owned());
            continue;
        }
        let state = STATES
            .into_iter()
            .find(|s| {
                line.strip_prefix(s.word()).is_some_and(|r| {
                    r.len() > WORD_WIDTH + 2 - s.word().len() && r.starts_with(' ')
                })
            })
            .unwrap_or_else(|| panic!("no state word: {line:?} in {out}"));
        let rest = &line[WORD_WIDTH + 2..];
        let (name, text) = rest.split_once("  ").unwrap_or((rest, ""));
        let text = text.trim_start();
        if !text.is_empty() {
            let at = line.len() - text.len();
            assert_eq!(*column.get_or_insert(at), at, "texts do not line up: {out}");
        }
        rows.push(Row {
            state,
            name: name.to_owned(),
            text: text.to_owned(),
            under: Vec::new(),
        });
    }
    rows
}
