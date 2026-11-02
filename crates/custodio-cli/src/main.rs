//! Custodio import tool.
#![forbid(unsafe_code)]

use std::io;
use std::process::ExitCode;

use custodio_cli::bus::DbusImporter;
use custodio_cli::tty::Terminal;
use custodio_cli::{CliError, Command, finish, parse_command, run_delete, run_import, run_list};

fn run() -> Result<(), CliError> {
    let command = parse_command(std::env::args().skip(1)).map_err(CliError::Args)?;
    let bus = DbusImporter::system().map_err(|e| CliError::SystemBus(e.to_string()))?;
    match command {
        Command::Import(args) => {
            run_import(&args, &mut Terminal, &bus, &mut io::stdout()).map_err(CliError::Import)
        }
        Command::Delete(id) => {
            run_delete(&id, &mut Terminal, &bus, &mut io::stdout()).map_err(CliError::Delete)
        }
        Command::List => run_list(&bus, &mut io::stdout()).map_err(CliError::List),
    }
}

fn main() -> ExitCode {
    ExitCode::from(finish(&run(), &mut io::stderr()))
}
