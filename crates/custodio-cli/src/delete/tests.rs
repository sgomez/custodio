use std::cell::RefCell;

use super::*;

struct Says(Option<&'static str>);

impl Confirmation for Says {
    fn answer(&mut self, _: &str) -> io::Result<String> {
        self.0
            .map(str::to_owned)
            .ok_or_else(|| io::Error::other("no terminal"))
    }
}

#[derive(Default)]
struct Recorder {
    calls: RefCell<Vec<String>>,
    reply: Option<ServiceFailure>,
}

impl KeyDeleter for Recorder {
    fn delete_key(&self, id: &str) -> Result<(), ServiceFailure> {
        self.calls.borrow_mut().push(id.to_owned());
        self.reply.clone().map_or(Ok(()), Err)
    }
}

fn run(answer: Option<&'static str>, rec: &Recorder) -> (Result<(), DeleteFailure>, String) {
    let mut out = Vec::new();
    let result = run_delete("my-key", &mut Says(answer), rec, &mut out);
    (result, String::from_utf8_lossy(&out).into_owned())
}

#[test]
fn the_accepted_words_are_exactly_these() {
    assert_eq!(ACCEPTED, ["y", "yes"]);
    for word in ACCEPTED {
        assert!(is_yes(word));
        assert!(is_yes(&format!("{word}\n")));
        assert!(is_yes(&format!("{word}\r\n")));
    }
}

#[test]
fn everything_else_declines() {
    for word in [
        "",
        "\n",
        "n",
        "no",
        "Y",
        "YES",
        "Yes",
        "y ",
        " y",
        "yes please",
        "yess",
        "ye",
        "yes\n\n",
        "1",
        "true",
        "\u{0}",
    ] {
        assert!(!is_yes(word), "{word:?}");
    }
}

#[test]
fn a_yes_makes_one_call_with_the_id_and_prints_the_line() {
    let rec = Recorder::default();
    let (result, out) = run(Some("yes\n"), &rec);
    assert!(result.is_ok());
    assert_eq!(*rec.calls.borrow(), ["my-key"]);
    assert_eq!(out, "Deleted key 'my-key'.\n");
}

#[test]
fn any_other_answer_calls_nothing() {
    for answer in ["n\n", "\n", "", "yes please\n", "Y \n", "no\n", "Yes\n"] {
        let rec = Recorder::default();
        let (result, out) = run(Some(answer), &rec);
        assert!(matches!(result, Err(DeleteFailure::Declined)), "{answer:?}");
        assert!(rec.calls.borrow().is_empty(), "{answer:?}");
        assert_eq!(out, "");
    }
}

#[test]
fn no_terminal_calls_nothing() {
    let rec = Recorder::default();
    let (result, out) = run(None, &rec);
    assert!(matches!(result, Err(DeleteFailure::NoTerminal)));
    assert!(rec.calls.borrow().is_empty());
    assert_eq!(out, "");
}

#[test]
fn a_service_failure_is_passed_on_and_nothing_is_printed() {
    let rec = Recorder {
        reply: Some(ServiceFailure::PolkitDenied),
        ..Recorder::default()
    };
    let (result, out) = run(Some("y\n"), &rec);
    assert!(matches!(
        result,
        Err(DeleteFailure::Service(ServiceFailure::PolkitDenied))
    ));
    assert_eq!(out, "");
}

#[test]
fn the_question_names_the_key_and_says_it_cannot_be_recovered() {
    let q = question("my-key");
    assert!(q.contains("'my-key'"));
    assert!(q.contains("cannot be recovered"));
    assert!(!question("a\u{1b}[2Jb").contains('\u{1b}'));
}

#[test]
fn the_messages_are_fixed() {
    assert_eq!(
        DeleteFailure::Declined.to_string(),
        "not confirmed; nothing was deleted"
    );
    assert!(DeleteFailure::NoTerminal.to_string().contains("terminal"));
}

fn parse(args: &[&str]) -> Result<crate::Command, crate::ArgError> {
    crate::parse_command(args.iter().map(|s| (*s).to_owned()))
}

#[test]
fn delete_takes_exactly_one_id() {
    assert_eq!(
        parse(&["delete", "my-key"]),
        Ok(crate::Command::Delete("my-key".into()))
    );
    for args in [
        &["delete"][..],
        &["delete", "a", "b"],
        &["delete", "--yes", "a"],
        &["delete", "-y", "a"],
        &["delete", "--force", "a"],
        &["delete", "a", "--yes"],
        &["delete", "-"],
        &["delete", "--"],
    ] {
        assert_eq!(parse(args), Err(crate::ArgError::Usage), "{args:?}");
    }
}

#[test]
fn the_usage_text_names_delete() {
    assert!(crate::USAGE.contains("custodio delete <key id>"));
}
