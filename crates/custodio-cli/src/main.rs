//! Custodio import tool.
#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use custodio_cli::agent::process::Pkttyagent;
use custodio_cli::agent::{Process, WithAgent};
use custodio_cli::browser_files::local_address;
use custodio_cli::bus::DbusImporter;
use custodio_cli::register_discover::Environment;
use custodio_cli::register_native::{
    RegisterArgs, RegisterError, RunError, default_journal_socket, refresh_only_command,
    register_command,
};
use custodio_cli::tty::Terminal;
use custodio_cli::{
    CliError, Command, finish, import_command, list_command, parse_command, run_delete,
};

/// `register` edits files only: it needs no bus.
fn run_register(args: &RegisterArgs) -> Result<(), CliError> {
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .ok_or(CliError::Register(RegisterError::Run(RunError::NoHome)))?;
    let env = Environment {
        home: home.into(),
        xdg_config_home: std::env::var_os("XDG_CONFIG_HOME"),
        local_address: local_address(),
    };
    let euid = rustix::process::geteuid().as_raw();
    let var = |name: &str| std::env::var_os(name);
    if args.refresh_only {
        return refresh_only_command(
            args,
            &env,
            euid,
            var,
            Path::new(default_journal_socket()),
            &mut io::stdout(),
            &mut io::stderr(),
        )
        .map_err(CliError::Register);
    }
    register_command(args, &env, euid, var, &mut io::stdout(), &mut io::stderr())
        .map_err(CliError::Register)
}

fn run() -> Result<(), CliError> {
    let command = parse_command(std::env::args().skip(1)).map_err(CliError::Args)?;
    if let Command::Register(args) = &command {
        return run_register(args);
    }
    if let Command::Help(topic) = &command {
        // A closed standard output is not a failure of the tool.
        let out_tty = rustix::termios::isatty(io::stdout());
        let on = colour_on(out_tty);
        let text = custodio_cli::colour::headings(&custodio_cli::help::text(*topic), on);
        let _ = io::stdout().write_all(text.as_bytes());
        return Ok(());
    }
    let bus = DbusImporter::system().map_err(|e| CliError::SystemBus(e.to_string()))?;
    // Only `import` and `delete` make the service ask polkit, so only they may need an agent. The
    // agent is started on the main thread (its parent-death signal follows that thread).
    let on_terminal = rustix::termios::isatty(io::stdin());
    let with_agent =
        |inner| WithAgent::new(inner, Pkttyagent, on_terminal, Process::current().ok());
    let storage = bus.clone();
    match command {
        Command::Import(args) => import_command(
            &args,
            &mut Terminal,
            &with_agent(bus),
            &storage,
            &mut io::stdout(),
            &mut io::stderr(),
        )
        .map_err(CliError::Import),
        Command::Delete(id) => run_delete(&id, &mut Terminal, &with_agent(bus), &mut io::stdout())
            .map_err(CliError::Delete),
        Command::Register(_) | Command::Help(_) => unreachable!("handled before the bus is opened"),
        Command::List => list_command(&bus, &storage, &mut io::stdout(), &mut io::stderr())
            .map_err(CliError::List),
    }
}

/// Whether a stream that is (or is not) a terminal gets colour: see `custodio_cli::colour`.
fn colour_on(stream_is_terminal: bool) -> bool {
    custodio_cli::colour::enabled(
        stream_is_terminal,
        rustix::termios::isatty(io::stdout()),
        std::env::var_os("NO_COLOR")
            .map(|v| v.to_string_lossy().into_owned())
            .as_deref(),
    )
}

fn main() -> ExitCode {
    let result = run();
    let on = colour_on(rustix::termios::isatty(io::stderr()));
    ExitCode::from(finish(&result, &mut io::stderr(), on))
}
