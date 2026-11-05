use std::cell::RefCell;
use std::rc::Rc;

use super::*;

type Log = Rc<RefCell<Vec<String>>>;

struct Fake {
    log: Log,
    fail: bool,
}

struct Handle(Log);

impl Stop for Handle {
    fn stop(&mut self) {
        self.0.borrow_mut().push("stop".to_owned());
    }
}

impl AgentSpawner for Fake {
    fn spawn(&self, args: &[String]) -> io::Result<Box<dyn Stop>> {
        self.log
            .borrow_mut()
            .push(format!("spawn {}", args.join(" ")));
        if self.fail {
            return Err(io::Error::other("no agent"));
        }
        Ok(Box::new(Handle(self.log.clone())))
    }
}

struct Inner(Log);

impl KeyDeleter for Inner {
    fn delete_key(&self, id: &str) -> Result<(), ServiceFailure> {
        self.0.borrow_mut().push(format!("call {id}"));
        Err(ServiceFailure::Transport)
    }
}

impl Importer for Inner {
    fn import_p12(
        &self,
        id: &str,
        _: &[u8],
        _: &SecretString,
    ) -> Result<(String, Kind), ServiceFailure> {
        self.0.borrow_mut().push(format!("call {id}"));
        Ok(("ec".to_owned(), Kind::Tpm))
    }
}

const ME: Process = Process {
    pid: 4242,
    start_time: 987_654,
};

fn setup(terminal: bool, process: Option<Process>, fail: bool) -> (WithAgent<Inner, Fake>, Log) {
    let log = Log::default();
    let with = WithAgent::new(
        Inner(log.clone()),
        Fake {
            log: log.clone(),
            fail,
        },
        terminal,
        process,
    );
    (with, log)
}

#[test]
fn the_arguments_name_only_the_given_process() {
    for (pid, start) in [(1, 2), (4242, 987_654), (u32::MAX, u64::MAX)] {
        let args = agent_args(Process {
            pid,
            start_time: start,
        });
        assert_eq!(
            args,
            [
                "--fallback".to_owned(),
                "--notify-fd=1".to_owned(),
                format!("--process={pid},{start}")
            ]
        );
        assert!(!args.iter().any(|a| a.contains("bus-name") || a == "-s"));
    }
}

#[test]
fn the_start_time_is_field_22_even_with_a_strange_command_name() {
    let tail = "S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 777 20 21";
    assert_eq!(start_time_of(&format!("55 (custodio) {tail}")), Some(777));
    assert_eq!(start_time_of(&format!("55 (a b) c) ({tail}")), Some(777));
    assert_eq!(start_time_of("55 (x) S 1 2"), None);
    assert_eq!(start_time_of("garbage"), None);
}

#[test]
fn this_process_has_a_start_time_that_matches_proc() {
    let me = Process::current().unwrap_or(Process {
        pid: 0,
        start_time: 0,
    });
    assert_eq!(me.pid, std::process::id());
    assert!(me.start_time > 0);
}

#[test]
fn on_a_terminal_the_agent_runs_exactly_around_the_call() {
    let (with, log) = setup(true, Some(ME), false);
    assert!(with.delete_key("k").is_err());
    assert_eq!(
        *log.borrow(),
        [
            "spawn --fallback --notify-fd=1 --process=4242,987654",
            "call k",
            "stop"
        ]
    );
    let (with, log) = setup(true, Some(ME), false);
    let secret = SecretString::from("x");
    assert!(with.import_p12("k", b"", &secret).is_ok());
    assert_eq!(log.borrow().len(), 3);
    assert_eq!(log.borrow().last().map(String::as_str), Some("stop"));
}

#[test]
fn without_a_terminal_or_a_process_no_agent_is_started() {
    for (terminal, process) in [(false, Some(ME)), (true, None), (false, None)] {
        let (with, log) = setup(terminal, process, false);
        assert!(with.delete_key("k").is_err());
        assert_eq!(*log.borrow(), ["call k"]);
    }
}

#[test]
fn an_agent_that_cannot_start_leaves_the_call_to_go_on() {
    let (with, log) = setup(true, Some(ME), true);
    assert!(with.delete_key("k").is_err());
    assert_eq!(log.borrow().len(), 2);
    assert!(log.borrow()[1].starts_with("call"));
    assert!(!with.guard().running());
}
