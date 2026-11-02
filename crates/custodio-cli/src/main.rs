//! Custodio import tool.
#![forbid(unsafe_code)]

use std::io;
use std::process::ExitCode;

use custodio_cli::bus::DbusImporter;
use custodio_cli::tty::Terminal;
use custodio_cli::{CliError, finish, parse_args, run_import};

fn run() -> Result<(), CliError> {
    let args = parse_args(std::env::args().skip(1)).map_err(CliError::Args)?;
    let importer = DbusImporter::system().map_err(|e| CliError::SystemBus(e.to_string()))?;
    run_import(&args, &mut Terminal, &importer, &mut io::stdout()).map_err(CliError::Import)
}

fn main() -> ExitCode {
    ExitCode::from(finish(&run(), &mut io::stderr()))
}
