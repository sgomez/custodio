//! The manual page documents `custodio list`: fails if any of the facts is removed.

use std::error::Error;

fn page() -> Result<String, Box<dyn Error>> {
    Ok(std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../packaging/custodio.1"
    ))?)
}

fn section<'a>(page: &'a str, name: &str) -> Result<&'a str, Box<dyn Error>> {
    let head = format!(".SH {name}\n");
    let start = page.find(&head).ok_or(format!("no section {name}"))? + head.len();
    let rest = &page[start..];
    Ok(rest.find("\n.SH ").map_or(rest, |end| &rest[..end]))
}

#[test]
fn the_synopsis_has_custodio_list() -> Result<(), Box<dyn Error>> {
    let page = page()?;
    assert!(section(&page, "SYNOPSIS")?.contains(".B custodio list"));
    Ok(())
}

#[test]
fn the_description_names_the_fields_the_none_case_and_polkit() -> Result<(), Box<dyn Error>> {
    let page = page()?;
    let text = section(&page, "DESCRIPTION")?;
    for fact in [
        ".B list\n",
        ".I id\n",
        ".I type\n",
        "rsa2048",
        "ecdsa\\-p256",
        ".I subject\n",
        "valid until",
        "notAfter",
        "If you have none, it prints a sentence saying so and exits with status 0",
        "does not ask for authorization: it never calls polkit",
        "certificate unreadable",
        "Only your own keys",
    ] {
        assert!(text.contains(fact), "DESCRIPTION lacks: {fact}");
    }
    Ok(())
}

#[test]
fn the_exit_status_section_has_all_three_codes() -> Result<(), Box<dyn Error>> {
    let page = page()?;
    let text = section(&page, "EXIT STATUS")?;
    for fact in [".B 0\n", ".B 1\n", ".B 2\n", "no keys", "wrong"] {
        assert!(text.contains(fact), "EXIT STATUS lacks: {fact}");
    }
    Ok(())
}

#[test]
fn the_synopsis_has_custodio_delete() -> Result<(), Box<dyn Error>> {
    let page = page()?;
    assert!(section(&page, "SYNOPSIS")?.contains(".B custodio delete\n.I key id"));
    Ok(())
}

#[test]
fn delete_is_documented_with_its_confirmation_terminal_and_polkit() -> Result<(), Box<dyn Error>> {
    let page = page()?;
    let text = section(&page, "DESCRIPTION")?;
    for fact in [
        ".B delete\n",
        "asks on the terminal",
        "cannot be recovered",
        "\\fBy\\fR or \\fByes\\fR",
        "There is no option, environment variable or configuration that skips the confirmation",
        "never from standard input",
        "without a terminal",
        "refuses and deletes nothing",
        "polkit asks for authorization as well",
        "takes exactly one argument",
        "starts with a dash, write\n.B \\-\\-\nbefore it",
    ] {
        assert!(text.contains(fact), "DESCRIPTION lacks: {fact}");
    }
    Ok(())
}

#[test]
fn the_exit_status_section_covers_delete() -> Result<(), Box<dyn Error>> {
    let page = page()?;
    let text = section(&page, "EXIT STATUS")?;
    for fact in ["you did not confirm", "no terminal to confirm it on"] {
        assert!(text.contains(fact), "EXIT STATUS lacks: {fact}");
    }
    Ok(())
}
