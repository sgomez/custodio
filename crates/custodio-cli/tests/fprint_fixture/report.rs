//! The reading of a `custodio doctor` report: the one place the tests know its format.

/// One check of a `custodio doctor` report, as the report prints it. The format is known here only:
/// the tests read these fields, never the lines.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Line {
    /// `ok`, `not ok`, `warn` or `could not check`, whatever word or mark the report uses for it.
    pub state: &'static str,
    pub section: String,
    pub name: String,
    pub text: String,
    pub notes: Vec<String>,
    pub warnings: Vec<String>,
    pub fixes: Vec<String>,
}

/// The checks of a report, in order. Panics on a line it cannot place, so a change of format
/// fails here once instead of in every test.
pub fn report(text: &str) -> Vec<Line> {
    let mut checks: Vec<Line> = Vec::new();
    let mut section = String::new();
    for raw in text.lines() {
        if raw.is_empty()
            || (raw.ends_with(" problem.") || raw.ends_with(" problems.")) && !raw.starts_with(' ')
        {
            continue;
        }
        if !raw.starts_with(' ') {
            raw.clone_into(&mut section);
            continue;
        }
        let body = raw.trim_start();
        let indent = raw.len() - body.len();
        if indent == 2 {
            let (word, rest) = body
                .split_once(' ')
                .unwrap_or_else(|| panic!("no state: {raw:?}"));
            let state = match word {
                "ok" => "ok",
                "FAIL" => "not ok",
                "warn" => "warn",
                "?" => "could not check",
                _ => panic!("unknown state {word:?} in {raw:?}"),
            };
            let rest = rest.trim_start();
            let (name, text) = rest.split_once("  ").unwrap_or((rest, ""));
            checks.push(Line {
                state,
                section: section.clone(),
                name: name.to_owned(),
                text: text.trim_start().to_owned(),
                ..Line::default()
            });
            continue;
        }
        let last = checks
            .last_mut()
            .unwrap_or_else(|| panic!("indented line first: {raw:?}"));
        if let Some(fix) = body.strip_prefix("Fix: ") {
            last.fixes.push(fix.to_owned());
        } else if let Some(w) = body.strip_prefix("Warning: ") {
            last.warnings.push(w.to_owned());
        } else {
            last.notes.push(body.to_owned());
        }
    }
    checks
}

/// Every check with that name (one per profile for a browser), in order.
pub fn checks(text: &str, name: &str) -> Vec<Line> {
    report(text)
        .into_iter()
        .filter(|l| l.name == name)
        .collect()
}

/// The first check with that name; a default (state `none`) when there is none.
pub fn check(text: &str, name: &str) -> Line {
    checks(text, name).into_iter().next().unwrap_or(Line {
        state: "none",
        ..Line::default()
    })
}

/// The state of the first check with that name.
pub fn state(text: &str, name: &str) -> String {
    check(text, name).state.to_owned()
}

/// The fixes of the first check with that name.
pub fn fixes(text: &str, name: &str) -> Vec<String> {
    check(text, name).fixes
}

pub const READER: &str = custodio_cli::doctor_decide::READER;
pub const FINGER: &str = custodio_cli::doctor_decide::FINGER;
pub const POLKIT_CHECK: &str = custodio_cli::doctor_decide::POLKIT;
