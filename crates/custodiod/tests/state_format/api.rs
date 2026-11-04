//! The write API takes only protected types.

use std::fs;
use std::path::Path;

const ALLOWED: [(&str, &str); 4] = [
    ("new", "certificate"),
    ("with_certificate", "certificate"),
    ("replace_certificate", "certificate"),
    ("decode", "bytes"),
];
const RAW: [&str; 3] = ["SecretSlice", "[u8]", "Vec<u8>"];

/// The signatures of the public functions of `src` that take raw bytes, and the public fields of `Sealed`.
fn violations(src: &str) -> Vec<String> {
    let mut out = raw_params(src);
    out.extend(sealed_fields(src));
    out
}

fn raw_params(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(i) = rest.find("pub fn ") {
        let sig = &rest[i + "pub fn ".len()..];
        let end = sig.find(['{', ';']).unwrap_or(sig.len());
        rest = &sig[end..];
        let sig = sig[..end].replace("->", "to");
        let name = sig.split('(').next().unwrap_or("").trim();
        let Some(open) = sig.find('(') else { continue };
        let (mut depth, mut params, mut cur) = (0_i32, Vec::new(), String::new());
        for c in sig[open + 1..].chars() {
            match c {
                '(' | '<' | '[' => depth += 1,
                ')' | '>' | ']' if depth == 0 => break,
                ')' | '>' | ']' => depth -= 1,
                ',' if depth == 0 => {
                    params.push(std::mem::take(&mut cur));
                    continue;
                }
                _ => {}
            }
            cur.push(c);
        }
        params.push(cur);
        for p in params {
            let Some((pname, ty)) = p.split_once(':') else {
                continue;
            };
            let pname = pname.trim();
            if RAW.iter().any(|r| ty.contains(r)) && !ALLOWED.contains(&(name, pname)) {
                out.push(format!("{name}({pname}:{ty})"));
            }
        }
    }
    out
}

fn sealed_fields(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(i) = src.find("pub struct Sealed") {
        let body = src[i..].split("\n}").next().unwrap_or("");
        for line in body.lines().skip(1) {
            if line.trim_start().starts_with("pub ") {
                out.push(format!("public field: {}", line.trim()));
            }
        }
    }
    out
}

fn read(file: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file);
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.len() > 200, "{file} was not read");
    text
}

#[test]
fn the_check_fails_on_a_seeded_raw_parameter() {
    assert_ne!(
        violations("pub fn put(&self, key: &[u8]) -> Result<(), E> {"),
        Vec::<String>::new()
    );
    assert_ne!(
        violations("pub fn put(&self, key: SecretSlice<u8>) {"),
        Vec::<String>::new()
    );
    assert_ne!(
        violations("pub fn put(&self, owner: u32, key: Vec<u8>);"),
        Vec::<String>::new()
    );
    assert_ne!(
        violations("pub struct Sealed {\n    pub credential: Vec<u8>,\n}"),
        Vec::<String>::new()
    );
    assert_eq!(
        violations("pub struct Sealed {\n    credential: Vec<u8>,\n}"),
        Vec::<String>::new()
    );
    assert_eq!(
        violations("pub fn put(&self, record: &Record) -> Result<(), E> {"),
        Vec::<String>::new()
    );
}

#[test]
fn write_api_takes_only_protected_types() {
    let store = read("store.rs");
    assert!(store.contains("pub fn put(&self, record: &Record)"));
    for file in [
        "store.rs",
        "store/record.rs",
        "store/kind.rs",
        "store/legacy.rs",
    ] {
        assert_eq!(violations(&read(file)), Vec::<String>::new(), "{file}");
    }
    // `creds` is where plaintext goes in and a credential comes out; what must hold there is that a
    // `Sealed` cannot be built outside it.
    assert_eq!(sealed_fields(&read("creds.rs")), Vec::<String>::new());
    let record = read("store/record.rs");
    assert!(record.contains("pub fn from_imported(imported: &Imported)"));
    assert!(record.contains("pub fn from_sealed(sealed: &Sealed)"));
    assert!(read("creds.rs").contains("pub struct Sealed"));
}
