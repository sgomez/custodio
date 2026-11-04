//! The manual page's synopsis lists the subcommands.

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
fn the_synopsis_has_custodio_delete() -> Result<(), Box<dyn Error>> {
    let page = page()?;
    assert!(section(&page, "SYNOPSIS")?.contains(".B custodio delete\n.I key id"));
    Ok(())
}
