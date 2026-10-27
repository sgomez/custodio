//! The `crap` binary on a small crate and a hand-written coverage export.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

/// A crate with a complex function (`complex`, complexity 6) and a simple one.
const SOURCE: &str = "pub fn complex(x: i32) -> i32 {\n    if x == 0 { return 0; }\n    if x == 1 { return 1; }\n    if x == 2 { return 2; }\n    if x == 3 { return 3; }\n    if x == 4 { return 4; }\n    5\n}\n\npub fn simple() {}\n";

fn export(file: &Path, complex_covered: u32) -> String {
    let f = file.display();
    format!(
        r#"{{"data":[{{"functions":[
        {{"name":"complex","count":1,"filenames":["{f}"],"regions":[[1,1,8,2,1,0,0,0],[2,5,2,6,{complex_covered},0,0,0]]}},
        {{"name":"simple","count":1,"filenames":["{f}"],"regions":[[10,1,10,18,1,0,0,0]]}}]}}]}}"#
    )
}

fn run(dir: &Path, covered: u32, threshold: &str, extra: &[&str]) -> Output {
    let src = dir.join("krate/src");
    fs::create_dir_all(&src).unwrap();
    let file = src.join("lib.rs");
    fs::write(&file, SOURCE).unwrap();
    let json = dir.join("coverage.json");
    fs::write(&json, export(&fs::canonicalize(&file).unwrap(), covered)).unwrap();
    Command::new(env!("CARGO_BIN_EXE_crap"))
        .arg(&json)
        .arg(threshold)
        .args(extra)
        .arg(dir.join("krate"))
        .output()
        .unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn passes_when_every_score_is_within_the_threshold() {
    let dir = tempfile::tempdir().unwrap();
    // Half the regions covered: 6² × 0.5³ + 6 = 10.5.
    let out = run(dir.path(), 0, "10.5", &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("2 functions, worst CRAP 10.5"));
}

#[test]
fn fails_and_names_the_function_above_the_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let out = run(dir.path(), 0, "10.4", &[]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(
        err.contains("complex complexity 6 coverage 50% CRAP 10.5"),
        "{err}"
    );
    assert!(!err.contains("simple"), "{err}");
}

#[test]
fn full_coverage_scores_the_complexity() {
    let dir = tempfile::tempdir().unwrap();
    let out = run(dir.path(), 1, "6", &[]);
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn excluded_files_are_not_scored() {
    let dir = tempfile::tempdir().unwrap();
    let out = run(dir.path(), 0, "1", &[]);
    assert!(!out.status.success());
    let lib = dir.path().join("krate/src/lib.rs");
    let out = run(dir.path(), 0, "1", &["--exclude", lib.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("0 functions"));
}

#[test]
fn bad_invocations_fail_with_a_message() {
    let bin = env!("CARGO_BIN_EXE_crap");
    for args in [
        &[][..],
        &["x.json"],
        &["x.json", "abc", "dir"],
        &["x.json", "30"],
        &["x.json", "30", "--exclude"],
    ] {
        let out = Command::new(bin).args(args).output().unwrap();
        assert!(!out.status.success(), "{args:?}");
        assert!(
            stderr(&out).starts_with("crap: "),
            "{args:?}: {}",
            stderr(&out)
        );
    }
    let out = Command::new(bin)
        .args(["missing.json", "30", "dir"])
        .output()
        .unwrap();
    assert!(stderr(&out).contains("just coverage"));
}
