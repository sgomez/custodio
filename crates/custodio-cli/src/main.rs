//! Custodio import tool.
#![forbid(unsafe_code)]

use std::io;
use std::process::ExitCode;

use custodio_cli::bus::DbusImporter;
use custodio_cli::tty::Terminal;
use custodio_cli::{parse_args, run_import};

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let importer = match DbusImporter::system() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("custodio: cannot reach the system bus: {e}");
            return ExitCode::FAILURE;
        }
    };
    match run_import(&args, &mut Terminal, &importer, &mut io::stdout()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("custodio: {e}");
            ExitCode::FAILURE
        }
    }
}
