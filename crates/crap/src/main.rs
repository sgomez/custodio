#![forbid(unsafe_code)]

//! `crap <coverage.json> <threshold> [--exclude <file>]... <crate-dir>...`: fails when the CRAP
//! score of a function in the `src` of a crate is above the threshold. The JSON is the output of
//! `cargo llvm-cov report --json`. Excluded files are not scored.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::{env, fs};

const USAGE: &str = "usage: crap <coverage.json> <threshold> [--exclude <file>]... <crate-dir>...";

struct Args {
    json: String,
    threshold: f64,
    exclude: Vec<PathBuf>,
    crates: Vec<String>,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let [json, threshold, rest @ ..] = args else {
        return Err(USAGE.into());
    };
    let threshold = threshold
        .parse()
        .map_err(|e| format!("bad threshold {threshold:?}: {e}"))?;
    let mut parsed = Args {
        json: json.clone(),
        threshold,
        exclude: Vec::new(),
        crates: Vec::new(),
    };
    let mut rest = rest.iter();
    while let Some(arg) = rest.next() {
        if arg == "--exclude" {
            let file = rest.next().ok_or(USAGE)?;
            parsed
                .exclude
                .push(fs::canonicalize(file).map_err(|e| format!("{file}: {e}"))?);
        } else {
            parsed.crates.push(arg.clone());
        }
    }
    if parsed.crates.is_empty() {
        return Err(USAGE.into());
    }
    Ok(parsed)
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            rust_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(fs::canonicalize(path)?);
        }
    }
    Ok(())
}

fn functions(args: &Args) -> Result<Vec<crap::Function>, String> {
    let mut functions = Vec::new();
    for krate in &args.crates {
        let mut files = Vec::new();
        rust_files(&Path::new(krate).join("src"), &mut files)
            .map_err(|e| format!("{krate}: {e}"))?;
        for file in files.iter().filter(|f| !args.exclude.contains(f)) {
            let source =
                fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
            functions.extend(
                crap::functions_in(file, &source)
                    .map_err(|e| format!("{}: {e}", file.display()))?,
            );
        }
    }
    Ok(functions)
}

fn run(args: &[String]) -> Result<bool, String> {
    let args = parse_args(args)?;
    let export = fs::read_to_string(&args.json)
        .map_err(|e| format!("{}: {e} (run `just coverage` first)", args.json))?;
    let scored = crap::score(functions(&args)?, &crap::instances(&export)?);
    let bad = crap::offenders(&scored, args.threshold);
    for s in &bad {
        eprintln!("{s}");
    }
    let worst = scored.iter().map(|s| s.crap).fold(0.0, f64::max);
    println!(
        "{} functions, worst CRAP {worst:.1}, threshold {}",
        scored.len(),
        args.threshold
    );
    Ok(bad.is_empty())
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => {
            eprintln!("CRAP gate failed: add tests or simplify the functions above");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("crap: {e}");
            ExitCode::FAILURE
        }
    }
}
